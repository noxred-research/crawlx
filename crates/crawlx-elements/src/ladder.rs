//! Candidate discovery ladder.
//!
//! Each rung adds evidence to the same candidate; nothing found at a lower
//! rung is discarded. Rungs (rungs 0–3; the visual rung is out of
//! scope and canvas-like surfaces are reported by
//! [`crate::unsupported_surface`] instead of becoming candidates):
//!
//! | [`Rung`] | evidence |
//! |---|---|
//! | `Ax` | AX widget role, expandable / has-popup state |
//! | `Native` | native HTML interactive tag or ARIA widget role from the DOM supplement |
//! | `FocusCursor` | focusable (AX or `tabindex ≥ 0`) or an action cursor on an outermost node |
//! | `Listener` | click-class or hover-class event listeners (`DomSupplement::listener_candidates`) |

use std::collections::{BTreeMap, BTreeSet};

use crawlx_core::observation::{AxNode, DomNodeSupplement, ObservationBundle, ObservedDescriptor};

use crate::descriptor::{assign_instance_ordinals, DescriptorBuilder};
use crate::index::BundleIndex;
use crate::normalize::collapse_ws;
use crate::unsupported_surface::{detect, is_surface_tag, UnsupportedSurface};

/// Where a candidate was first found. Ordered from strongest to weakest evidence.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Rung {
    /// AX widget role, or expandable / has-popup state.
    Ax,
    /// Native interactive HTML tag or ARIA widget role in the DOM supplement.
    Native,
    /// Focusable node, or outermost node with an action cursor.
    FocusCursor,
    /// Click-class or hover-class event listener, within the probe budget.
    Listener,
}

impl Rung {
    /// Plan numbering: AX is rung 0, listeners rung 3.
    #[must_use]
    pub const fn index(self) -> u8 {
        match self {
            Self::Ax => 0,
            Self::Native => 1,
            Self::FocusCursor => 2,
            Self::Listener => 3,
        }
    }
}

/// Discovery knobs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiscoveryConfig {
    /// Highest rung consulted.
    pub max_rung: Rung,
    /// Nodes newly added by listener evidence per observation (planning default 64).
    pub listener_probe_budget: u16,
    /// Keep disabled controls (`evidence.enabled == false`).
    pub include_disabled: bool,
    /// Keep nodes known to be hidden or zero-sized (`evidence.visible == false`).
    pub include_hidden: bool,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            max_rung: Rung::Listener,
            listener_probe_budget: 64,
            include_disabled: false,
            include_hidden: false,
        }
    }
}

/// Accumulated evidence for one candidate.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct CandidateEvidence {
    /// Lowercase AX role when it is a widget role or expandable.
    pub ax_widget_role: Option<String>,
    /// Native interactive HTML element (`a[href]`, `button`, `input`, …).
    pub native_semantics: bool,
    /// ARIA widget role or interactive ARIA state in the DOM.
    pub aria_semantics: bool,
    /// AX `focusable` or `tabindex ≥ 0`.
    pub focusable: bool,
    /// A click-class listener was observed on the node itself.
    pub direct_listener: bool,
    /// A hover-class listener (`mouseenter`, `mouseover`, `pointerenter`, `pointerover`) was
    /// observed on the node itself; the node is a `Hover` target.
    pub hover_listener: bool,
    /// Likelihood (0..=1) that the node handles clicks via a delegated
    /// listener: cursor, tabindex and short-text signals. 0 for nodes with
    /// native or ARIA semantics, where delegation is irrelevant.
    pub delegated_likelihood: f32,
    /// Computed cursor is an action cursor (`pointer`, `grab`).
    pub action_cursor: bool,
    /// The node is a drag source: `draggable="true"`, `aria-grabbed`, a `grab` cursor or a
    /// `dragstart` listener; it supports `Drag`.
    pub draggable: bool,
    /// The node is a drop zone: a `drop`/`dragover`/`dragenter` listener or
    /// `aria-dropeffect`; it is a drag destination, never a target of its own.
    pub drop_zone: bool,
    /// Not known to be hidden or zero-sized.
    pub visible: bool,
    /// Not disabled by AX, `disabled` or `aria-disabled`.
    pub enabled: bool,
}

/// One interactive candidate.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct Candidate {
    /// Evidence-complete descriptor of the node, with `instance_ordinal` filled.
    pub descriptor: ObservedDescriptor,
    /// Why the node was judged a candidate.
    pub evidence: CandidateEvidence,
    /// Lowest (strongest) rung that found it.
    pub rung: Rung,
}

/// Candidates plus surfaces that are never candidates.
#[derive(Clone, PartialEq, Debug, Default)]
#[non_exhaustive]
pub struct Discovery {
    /// Candidates in AX pre-order, then DOM-only nodes by backend id.
    pub candidates: Vec<Candidate>,
    /// Canvas, WebGL, embed and object nodes, reported but never candidates.
    pub unsupported: Vec<UnsupportedSurface>,
}

/// The ladder.
pub struct CandidateDiscovery;

/// AX / ARIA widget roles that make a node a candidate (`menuitem*` handled separately).
const WIDGET_ROLES: [&str; 20] = [
    "button",
    "link",
    "textbox",
    "searchbox",
    "combobox",
    "listbox",
    "option",
    "checkbox",
    "radio",
    "switch",
    "slider",
    "spinbutton",
    "tab",
    "treeitem",
    "disclosure",
    "disclosuretriangle",
    "popupbutton",
    "comboboxselect",
    "comboboxmenubutton",
    "gridcell",
];

/// Event types that count as a click-class listener (rung 3 of the candidate ladder).
pub const CLICK_LISTENERS: [&str; 7] = [
    "click",
    "mousedown",
    "mouseup",
    "pointerdown",
    "pointerup",
    "touchstart",
    "keydown",
];

/// Event types that count as a hover-class listener (menus revealed on pointer hover).
pub const HOVER_LISTENERS: [&str; 4] = ["mouseenter", "mouseover", "pointerenter", "pointerover"];

/// Event types that make a node a drag source (native HTML5 drag and drop).
pub const DRAG_LISTENERS: [&str; 2] = ["dragstart", "drag"];

/// Event types that make a node a drop zone (native HTML5 drag and drop).
pub const DROP_LISTENERS: [&str; 3] = ["drop", "dragover", "dragenter"];

/// Cursor values of a drag handle.
#[must_use]
pub fn is_drag_cursor(cursor: &str) -> bool {
    matches!(cursor.trim().to_ascii_lowercase().as_str(), "grab" | "grabbing")
}

/// Is `role` an interactive widget role?
#[must_use]
pub fn is_widget_role(role: &str) -> bool {
    let r = role.trim().to_ascii_lowercase();
    r.starts_with("menuitem") || WIDGET_ROLES.contains(&r.as_str())
}

/// Cursor values that signal an action.
#[must_use]
pub fn is_action_cursor(cursor: &str) -> bool {
    matches!(
        cursor.trim().to_ascii_lowercase().as_str(),
        "pointer" | "grab" | "grabbing"
    )
}

#[derive(Default)]
struct Acc {
    rung: Option<Rung>,
    ax_widget_role: Option<String>,
    native: bool,
    aria: bool,
    focusable: bool,
    direct_listener: bool,
    hover_listener: bool,
    action_cursor: bool,
    draggable: bool,
    drop_zone: bool,
}

impl Acc {
    fn found(&mut self, rung: Rung) {
        self.rung = Some(self.rung.map_or(rung, |r| r.min(rung)));
    }
}

impl CandidateDiscovery {
    /// Candidates of `bundle`, in AX pre-order followed by DOM-only nodes in
    /// backend-id order.
    #[must_use]
    pub fn discover(bundle: &ObservationBundle, config: &DiscoveryConfig) -> Vec<Candidate> {
        Self::discover_report(bundle, config).candidates
    }

    /// Candidates and unsupported surfaces.
    #[must_use]
    pub fn discover_report(bundle: &ObservationBundle, config: &DiscoveryConfig) -> Discovery {
        let index = BundleIndex::new(bundle);
        let unsupported = detect(bundle);
        let excluded: BTreeSet<i64> = unsupported.iter().map(|s| s.locator.backend_node_id.0).collect();
        let dom = &bundle.dom_supplement.nodes;

        let mut order: Vec<i64> = Vec::new();
        let mut acc: BTreeMap<i64, Acc> = BTreeMap::new();
        let touch = |id: i64, order: &mut Vec<i64>, acc: &mut BTreeMap<i64, Acc>| -> bool {
            if excluded.contains(&id) {
                return false;
            }
            if let std::collections::btree_map::Entry::Vacant(e) = acc.entry(id) {
                e.insert(Acc::default());
                order.push(id);
            }
            true
        };

        // Rung Ax: widget roles and expandable / has-popup state.
        for n in &bundle.ax.nodes {
            let id = n.locator.backend_node_id.0;
            if n.ignored || !ax_candidate(n) || !touch(id, &mut order, &mut acc) {
                continue;
            }
            if let Some(a) = acc.get_mut(&id) {
                a.found(Rung::Ax);
                a.ax_widget_role = Some(n.role.trim().to_ascii_lowercase());
            }
        }

        // Rung Native: interactive tags, ARIA widget roles and native drag-and-drop
        // semantics (`draggable`, `aria-grabbed`, `aria-dropeffect`) in the DOM supplement.
        if config.max_rung >= Rung::Native {
            for (&id, d) in dom {
                let (native, aria) = (native_semantics(d), aria_semantics(d));
                let (drag, drop) = (drag_attribute(d), drop_attribute(d));
                if !(native || aria || drag || drop) || !touch(id, &mut order, &mut acc) {
                    continue;
                }
                if let Some(a) = acc.get_mut(&id) {
                    a.found(Rung::Native);
                    a.native |= native;
                    a.aria |= aria;
                    a.draggable |= drag;
                    a.drop_zone |= drop;
                }
            }
        }

        // Rung FocusCursor, pass 1: focusable nodes. Pass 2 (below): outermost action cursors.
        if config.max_rung >= Rung::FocusCursor {
            let mut ids: BTreeSet<i64> = dom.keys().copied().collect();
            ids.extend(
                bundle
                    .ax
                    .nodes
                    .iter()
                    .filter(|n| !n.ignored)
                    .map(|n| n.locator.backend_node_id.0),
            );
            for id in ids {
                let ax = index.ax_by_backend(id).filter(|n| !n.ignored);
                let focusable =
                    ax.is_some_and(|n| n.focusable) || dom.get(&id).is_some_and(tabindex_focusable);
                if focusable && !is_non_target(ax, dom.get(&id)) && touch(id, &mut order, &mut acc) {
                    if let Some(a) = acc.get_mut(&id) {
                        a.found(Rung::FocusCursor);
                    }
                }
                if let Some(a) = acc.get_mut(&id) {
                    a.focusable |= focusable;
                }
            }
        }

        // Rung Listener evidence (flag only on nodes already known).
        let listener_ids: Vec<i64> = if config.max_rung >= Rung::Listener {
            let mut ids: Vec<i64> = Vec::new();
            let mut seen = BTreeSet::new();
            for b in &bundle.dom_supplement.listener_candidates {
                if seen.insert(b.0) {
                    ids.push(b.0);
                }
            }
            for (&id, d) in dom {
                if (has_click_listener(d)
                    || has_hover_listener(d)
                    || has_drag_listener(d)
                    || has_drop_listener(d))
                    && seen.insert(id)
                {
                    ids.push(id);
                }
            }
            ids
        } else {
            Vec::new()
        };
        for &id in &listener_ids {
            if let (Some(a), Some(d)) = (acc.get_mut(&id), dom.get(&id)) {
                a.direct_listener |= has_click_listener(d);
                a.hover_listener |= has_hover_listener(d);
                a.draggable |= has_drag_listener(d);
                a.drop_zone |= has_drop_listener(d);
            }
        }

        // Rung FocusCursor, pass 2: cursor-only nodes, outermost per chain.
        if config.max_rung >= Rung::FocusCursor {
            let mut accepted: BTreeSet<i64> = BTreeSet::new();
            let mut cursor_ids: Vec<i64> = Vec::new();
            let mut seen_ids: BTreeSet<i64> = BTreeSet::new();
            for id in bundle
                .ax
                .nodes
                .iter()
                .map(|n| n.locator.backend_node_id.0)
                .chain(dom.keys().copied())
            {
                if seen_ids.insert(id) {
                    cursor_ids.push(id);
                }
            }
            for id in cursor_ids {
                let Some(d) = dom.get(&id) else { continue };
                if !d.cursor.as_deref().is_some_and(is_action_cursor) {
                    continue;
                }
                if let Some(a) = acc.get_mut(&id) {
                    a.action_cursor = true;
                    a.draggable |= d.cursor.as_deref().is_some_and(is_drag_cursor);
                }
                let ax = index.ax_by_backend(id).filter(|n| !n.ignored);
                if excluded.contains(&id) || acc.contains_key(&id) || is_non_target(ax, Some(d)) {
                    continue;
                }
                if !(has_text(ax, d)
                    && d.bbox
                        .or_else(|| ax.and_then(|n| n.bbox))
                        .is_some_and(|b| b.area() > 0.0))
                {
                    continue;
                }
                let covered = ax.is_some_and(|n| {
                    index.ancestors(n).iter().any(|anc| {
                        let b = anc.locator.backend_node_id.0;
                        acc.contains_key(&b) || accepted.contains(&b)
                    })
                });
                if covered {
                    continue;
                }
                accepted.insert(id);
                touch(id, &mut order, &mut acc);
                if let Some(a) = acc.get_mut(&id) {
                    a.found(Rung::FocusCursor);
                    a.action_cursor = true;
                    a.draggable |= d.cursor.as_deref().is_some_and(is_drag_cursor);
                }
            }
        }

        // Rung Listener: new nodes, within the probe budget.
        if config.max_rung >= Rung::Listener {
            let mut budget = usize::from(config.listener_probe_budget);
            for &id in &listener_ids {
                let Some(d) = dom.get(&id) else { continue };
                if let Some(a) = acc.get_mut(&id) {
                    a.direct_listener |= has_click_listener(d);
                    a.hover_listener |= has_hover_listener(d);
                    a.draggable |= has_drag_listener(d);
                    a.drop_zone |= has_drop_listener(d);
                    if a.rung.is_some() {
                        continue;
                    }
                }
                if budget == 0 || excluded.contains(&id) {
                    continue;
                }
                let ax = index.ax_by_backend(id).filter(|n| !n.ignored);
                if is_non_target(ax, Some(d)) || !touch(id, &mut order, &mut acc) {
                    continue;
                }
                budget -= 1;
                if let Some(a) = acc.get_mut(&id) {
                    a.found(Rung::Listener);
                    a.direct_listener |= has_click_listener(d);
                    a.hover_listener |= has_hover_listener(d);
                    a.draggable |= has_drag_listener(d) || d.cursor.as_deref().is_some_and(is_drag_cursor);
                    a.drop_zone |= has_drop_listener(d);
                    a.action_cursor |= d.cursor.as_deref().is_some_and(is_action_cursor);
                    a.focusable |= ax.is_some_and(|n| n.focusable) || tabindex_focusable(d);
                }
            }
        }

        // Materialise in AX pre-order, then DOM-only nodes by backend id.
        let mut ax_pos: BTreeMap<i64, usize> = BTreeMap::new();
        for (i, n) in bundle.ax.nodes.iter().enumerate() {
            ax_pos.entry(n.locator.backend_node_id.0).or_insert(i);
        }
        order.sort_by_key(|id| (ax_pos.get(id).copied().unwrap_or(usize::MAX), *id));
        let builder = DescriptorBuilder::new(&index);
        let mut candidates = Vec::new();
        for id in order {
            let Some(a) = acc.get(&id) else { continue };
            let Some(rung) = a.rung else { continue };
            let ax = index.ax_by_backend(id);
            let descriptor = builder.build(ax, dom.get(&id), id);
            let evidence = evidence_for(a, &descriptor);
            if (!config.include_disabled && !evidence.enabled)
                || (!config.include_hidden && !evidence.visible)
            {
                continue;
            }
            candidates.push(Candidate {
                descriptor,
                evidence,
                rung,
            });
        }
        assign_instance_ordinals(candidates.iter_mut().map(|c| &mut c.descriptor));
        Discovery {
            candidates,
            unsupported,
        }
    }
}

fn evidence_for(a: &Acc, d: &ObservedDescriptor) -> CandidateEvidence {
    let delegated = if a.native || a.aria || a.ax_widget_role.is_some() {
        0.0
    } else {
        delegated_likelihood(a.action_cursor, a.focusable, d)
    };
    CandidateEvidence {
        ax_widget_role: a.ax_widget_role.clone(),
        native_semantics: a.native,
        aria_semantics: a.aria,
        focusable: a.focusable || d.focusable,
        direct_listener: a.direct_listener,
        hover_listener: a.hover_listener,
        delegated_likelihood: delegated,
        action_cursor: a.action_cursor,
        draggable: a.draggable
            || d.attributes
                .get("draggable")
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
            || d.cursor.as_deref().is_some_and(is_drag_cursor),
        drop_zone: a.drop_zone,
        visible: d.visible,
        enabled: !d.disabled,
    }
}

/// Weak-evidence estimate for delegated handlers (frameworks attach at the
/// root, so a missing direct listener says little): cursor, `tabindex`, short
/// label text and a role hint, capped at 0.9.
fn delegated_likelihood(cursor: bool, focusable: bool, d: &ObservedDescriptor) -> f32 {
    let mut p = 0.0_f32;
    if cursor {
        p += 0.45;
    }
    if focusable {
        p += 0.25;
    }
    let label_len = d
        .accessible_name
        .as_deref()
        .or(d.text.as_deref())
        .map(|t| collapse_ws(t).chars().count())
        .unwrap_or(0);
    if (1..=40).contains(&label_len) {
        p += 0.15;
    }
    if d.attributes.contains_key("aria-haspopup") || d.attributes.contains_key("aria-expanded") {
        p += 0.15;
    }
    p.min(0.9)
}

/// Rung-Ax test: widget role (gridcell only with actions) or expandable/has-popup state.
fn ax_candidate(n: &AxNode) -> bool {
    let role = n.role.trim().to_ascii_lowercase();
    if is_surface_tag(&role) {
        return false;
    }
    if role == "gridcell" {
        return n.focusable || n.expanded.is_some() || has_popup(n);
    }
    is_widget_role(&role) || n.expanded.is_some() || has_popup(n)
}

fn has_popup(n: &AxNode) -> bool {
    n.properties
        .get("haspopup")
        .is_some_and(|v| !v.trim().is_empty() && !v.trim().eq_ignore_ascii_case("false"))
}

fn native_semantics(d: &DomNodeSupplement) -> bool {
    let tag = d.tag.trim().to_ascii_lowercase();
    match tag.as_str() {
        "a" | "area" => d.attributes.contains_key("href"),
        "button" | "select" | "textarea" | "summary" => true,
        "input" => !d
            .attributes
            .get("type")
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("hidden")),
        _ => d
            .attributes
            .get("contenteditable")
            .is_some_and(|v| !v.trim().eq_ignore_ascii_case("false")),
    }
}

fn aria_semantics(d: &DomNodeSupplement) -> bool {
    let role_widget = d
        .attributes
        .get("role")
        .and_then(|r| r.split_whitespace().next())
        .is_some_and(is_widget_role);
    role_widget
        || d.attributes.contains_key("aria-expanded")
        || d.attributes.contains_key("aria-pressed")
        || d.attributes
            .get("aria-haspopup")
            .is_some_and(|v| !v.trim().eq_ignore_ascii_case("false"))
}

fn tabindex_focusable(d: &DomNodeSupplement) -> bool {
    d.attributes
        .get("tabindex")
        .and_then(|t| t.trim().parse::<i32>().ok())
        .is_some_and(|t| t >= 0)
}

fn has_click_listener(d: &DomNodeSupplement) -> bool {
    d.listeners
        .iter()
        .any(|l| CLICK_LISTENERS.contains(&l.trim().to_ascii_lowercase().as_str()))
}

fn has_hover_listener(d: &DomNodeSupplement) -> bool {
    d.listeners
        .iter()
        .any(|l| HOVER_LISTENERS.contains(&l.trim().to_ascii_lowercase().as_str()))
}

fn has_drag_listener(d: &DomNodeSupplement) -> bool {
    d.listeners
        .iter()
        .any(|l| DRAG_LISTENERS.contains(&l.trim().to_ascii_lowercase().as_str()))
}

fn has_drop_listener(d: &DomNodeSupplement) -> bool {
    d.listeners
        .iter()
        .any(|l| DROP_LISTENERS.contains(&l.trim().to_ascii_lowercase().as_str()))
}

/// `draggable="true"` or `aria-grabbed` (either value: the attribute marks a drag source).
fn drag_attribute(d: &DomNodeSupplement) -> bool {
    d.attributes
        .get("draggable")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
        || d.attributes.contains_key("aria-grabbed")
}

/// `aria-dropeffect` with any effect other than `none`.
fn drop_attribute(d: &DomNodeSupplement) -> bool {
    d.attributes
        .get("aria-dropeffect")
        .is_some_and(|v| !v.trim().is_empty() && !v.trim().eq_ignore_ascii_case("none"))
}

fn has_text(ax: Option<&AxNode>, d: &DomNodeSupplement) -> bool {
    d.text.as_deref().is_some_and(|t| !t.trim().is_empty())
        || ax
            .and_then(|n| n.name.as_deref())
            .is_some_and(|t| !t.trim().is_empty())
        || d.attributes
            .get("aria-label")
            .is_some_and(|t| !t.trim().is_empty())
}

/// Nodes that are never an action target at rungs 2–3: document roots and
/// text leaves inherit cursor and focus from their parents.
fn is_non_target(ax: Option<&AxNode>, d: Option<&DomNodeSupplement>) -> bool {
    if let Some(n) = ax {
        let r = n.role.trim().to_ascii_lowercase();
        if matches!(
            r.as_str(),
            "rootwebarea" | "webarea" | "statictext" | "inlinetextbox" | "linebreak" | "document"
        ) {
            return true;
        }
    }
    d.is_some_and(|d| matches!(d.tag.trim().to_ascii_lowercase().as_str(), "html" | "body"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{bbox, Page};
    use crate::unsupported_surface::SurfaceKind;

    /// root(1) > main(2) > { button(3), listener div(4), focusable span(5),
    /// pointer div(6) > pointer span(7), canvas(8), ignored link(9), disabled button(10) }
    fn page() -> Page {
        let mut p = Page::new();
        p.ax(1, None, "RootWebArea", "Home");
        p.ax(2, Some(1), "main", "");
        p.ax(3, Some(2), "button", "Save").bbox = Some(bbox(10.0, 10.0, 80.0, 30.0));
        p.dom(3, "button", &[]).bbox = Some(bbox(10.0, 10.0, 80.0, 30.0));

        // div with a click listener, found only through listener inspection
        p.ax(4, Some(2), "generic", "");
        let d = p.dom(4, "div", &[]);
        d.listeners = vec!["click".into()];
        d.text = Some("Open menu".into());
        d.bbox = Some(bbox(10.0, 50.0, 90.0, 20.0));
        p.bundle
            .dom_supplement
            .listener_candidates
            .push(crawlx_core::ids::BackendNodeId(4));

        // focusable span with pointer cursor
        let s = p.ax(5, Some(2), "generic", "Filters");
        s.focusable = true;
        let d = p.dom(5, "span", &[]);
        d.cursor = Some("pointer".into());
        d.text = Some("Filters".into());
        d.bbox = Some(bbox(10.0, 80.0, 60.0, 20.0));

        // pointer-cursor div with a pointer-cursor child: only the outer survives
        p.ax(6, Some(2), "generic", "Card");
        let d = p.dom(6, "div", &[]);
        d.cursor = Some("pointer".into());
        d.text = Some("Card".into());
        d.bbox = Some(bbox(10.0, 110.0, 200.0, 60.0));
        p.ax(7, Some(6), "generic", "Card title");
        let d = p.dom(7, "span", &[]);
        d.cursor = Some("pointer".into());
        d.text = Some("Card title".into());
        d.bbox = Some(bbox(12.0, 112.0, 100.0, 20.0));

        // canvas never becomes a candidate even with a listener and pointer cursor
        p.ax(8, Some(2), "Canvas", "");
        let d = p.dom(8, "canvas", &[]);
        d.listeners = vec!["click".into()];
        d.cursor = Some("pointer".into());
        d.bbox = Some(bbox(0.0, 200.0, 300.0, 200.0));

        // AX-ignored anchor with native semantics
        p.ax(9, Some(2), "none", "").ignored = true;
        let d = p.dom(9, "a", &[("href", "/about")]);
        d.text = Some("About".into());
        d.bbox = Some(bbox(10.0, 420.0, 50.0, 20.0));

        // disabled button
        let b = p.ax(10, Some(2), "button", "Delete");
        b.disabled = true;
        b.bbox = Some(bbox(10.0, 450.0, 50.0, 20.0));
        p
    }

    fn find(c: &[Candidate], backend: i64) -> Option<&Candidate> {
        c.iter()
            .find(|c| c.descriptor.locator.backend_node_id.0 == backend)
    }

    #[test]
    fn ladder_finds_each_rung_and_reports_canvas() {
        let p = page();
        let report = CandidateDiscovery::discover_report(&p.bundle, &DiscoveryConfig::default());
        let c = &report.candidates;
        let ids: Vec<i64> = c.iter().map(|c| c.descriptor.locator.backend_node_id.0).collect();
        assert_eq!(
            ids,
            vec![3, 4, 5, 6, 9],
            "AX pre-order, canvas/disabled/child excluded"
        );

        let button = find(c, 3).unwrap();
        assert_eq!(button.rung, Rung::Ax);
        assert_eq!(button.evidence.ax_widget_role.as_deref(), Some("button"));
        assert!(
            button.evidence.native_semantics,
            "rung Ax evidence accumulates native semantics"
        );
        assert_eq!(button.evidence.delegated_likelihood, 0.0);

        let listener = find(c, 4).unwrap();
        assert_eq!(listener.rung, Rung::Listener);
        assert!(listener.evidence.direct_listener);
        assert!(!listener.evidence.native_semantics && listener.evidence.ax_widget_role.is_none());
        assert_eq!(listener.descriptor.role, "generic");

        let focus = find(c, 5).unwrap();
        assert_eq!(focus.rung, Rung::FocusCursor);
        assert!(focus.evidence.focusable && focus.evidence.action_cursor);
        assert!(
            focus.evidence.delegated_likelihood > 0.5,
            "{}",
            focus.evidence.delegated_likelihood
        );

        let card = find(c, 6).unwrap();
        assert_eq!(card.rung, Rung::FocusCursor);
        assert!(card.evidence.action_cursor && !card.evidence.focusable);
        assert!(
            find(c, 7).is_none(),
            "inner pointer node covered by outer candidate"
        );

        let anchor = find(c, 9).unwrap();
        assert_eq!(anchor.rung, Rung::Native);
        assert_eq!(anchor.descriptor.role, "link");
        assert_eq!(anchor.descriptor.href.as_deref(), Some("/about"));
        assert!(anchor.evidence.native_semantics && anchor.evidence.ax_widget_role.is_none());

        assert!(find(c, 8).is_none());
        assert_eq!(report.unsupported.len(), 1);
        assert_eq!(report.unsupported[0].kind, SurfaceKind::Canvas);
        assert_eq!(report.unsupported[0].locator.backend_node_id.0, 8);
    }

    #[test]
    fn disabled_and_hidden_are_opt_in() {
        let p = page();
        let cfg = DiscoveryConfig {
            include_disabled: true,
            ..DiscoveryConfig::default()
        };
        let c = CandidateDiscovery::discover(&p.bundle, &cfg);
        let del = find(&c, 10).unwrap();
        assert!(!del.evidence.enabled);

        let mut hidden = Page::new();
        hidden.ax(1, None, "RootWebArea", "");
        hidden.ax(2, Some(1), "button", "Ghost").bbox = Some(bbox(0.0, 0.0, 0.0, 0.0));
        assert!(CandidateDiscovery::discover(&hidden.bundle, &DiscoveryConfig::default()).is_empty());
        let cfg = DiscoveryConfig {
            include_hidden: true,
            ..DiscoveryConfig::default()
        };
        let c = CandidateDiscovery::discover(&hidden.bundle, &cfg);
        assert_eq!(c.len(), 1);
        assert!(!c[0].evidence.visible);
    }

    #[test]
    fn max_rung_limits_escalation() {
        let p = page();
        let ax_only = DiscoveryConfig {
            max_rung: Rung::Ax,
            ..DiscoveryConfig::default()
        };
        let ids: Vec<i64> = CandidateDiscovery::discover(&p.bundle, &ax_only)
            .iter()
            .map(|c| c.descriptor.locator.backend_node_id.0)
            .collect();
        assert_eq!(ids, vec![3]);
        let no_listener = DiscoveryConfig {
            max_rung: Rung::FocusCursor,
            ..DiscoveryConfig::default()
        };
        let c = CandidateDiscovery::discover(&p.bundle, &no_listener);
        assert!(find(&c, 4).is_none());
        assert!(find(&c, 5).is_some());
    }

    #[test]
    fn listener_budget_caps_new_candidates_only() {
        let mut p = Page::new();
        p.ax(1, None, "RootWebArea", "");
        for i in 0..5 {
            let id = 10 + i;
            p.ax(id, Some(1), "generic", "");
            let d = p.dom(id, "div", &[]);
            d.listeners = vec!["mousedown".into()];
            d.text = Some(format!("tile {i}"));
            d.bbox = Some(bbox(0.0, 30.0 * i as f64, 20.0, 20.0));
            p.bundle
                .dom_supplement
                .listener_candidates
                .push(crawlx_core::ids::BackendNodeId(id));
        }
        let cfg = DiscoveryConfig {
            listener_probe_budget: 3,
            ..DiscoveryConfig::default()
        };
        let c = CandidateDiscovery::discover(&p.bundle, &cfg);
        assert_eq!(c.len(), 3);
        assert!(c.iter().all(|c| c.rung == Rung::Listener));
        assert_eq!(Rung::Listener.index(), 3);
    }

    #[test]
    fn widget_role_table() {
        for r in [
            "button",
            "link",
            "textbox",
            "searchbox",
            "combobox",
            "listbox",
            "option",
            "checkbox",
            "radio",
            "switch",
            "slider",
            "spinbutton",
            "tab",
            "treeitem",
            "menuitem",
            "menuitemcheckbox",
            "menuitemradio",
            "DisclosureTriangle",
        ] {
            assert!(is_widget_role(r), "{r}");
        }
        for r in ["generic", "heading", "main", "img", "StaticText"] {
            assert!(!is_widget_role(r), "{r}");
        }
    }

    #[test]
    fn expandable_and_gridcell_rules() {
        let mut p = Page::new();
        p.ax(1, None, "RootWebArea", "");
        p.ax(2, Some(1), "generic", "More").expanded = Some(false);
        p.ax(3, Some(1), "gridcell", "plain");
        p.ax(4, Some(1), "gridcell", "editable").focusable = true;
        p.ax(5, Some(1), "generic", "Menu")
            .properties
            .insert("haspopup".into(), "menu".into());
        let c = CandidateDiscovery::discover(&p.bundle, &DiscoveryConfig::default());
        let ids: Vec<i64> = c.iter().map(|c| c.descriptor.locator.backend_node_id.0).collect();
        assert_eq!(ids, vec![2, 4, 5]);
        assert_eq!(
            c[0].descriptor
                .attributes
                .get("aria-expanded")
                .map(String::as_str),
            Some("false")
        );
        assert_eq!(
            c[2].descriptor
                .attributes
                .get("aria-haspopup")
                .map(String::as_str),
            Some("menu")
        );
    }

    /// A hover menu: a generic wrapper with only a `mouseenter` listener is a
    /// `Listener`-rung candidate with `hover_listener` evidence and a `Hover` vocabulary; the
    /// click-less listener never counts as `direct_listener`.
    #[test]
    fn hover_listener_makes_a_generic_node_a_hover_candidate() {
        use crate::vocabulary::ActionVocabulary;
        use crawlx_core::identity::ActionKind;
        let mut p = Page::new();
        p.ax(1, None, "RootWebArea", "");
        p.ax(2, Some(1), "generic", "");
        let d = p.dom(2, "div", &[("class", "hm")]);
        d.listeners = vec!["mouseenter".into()];
        d.text = Some("File".into());
        d.bbox = Some(bbox(10.0, 10.0, 80.0, 30.0));
        // a click-and-hover node keeps both evidences
        p.ax(3, Some(1), "generic", "");
        let d = p.dom(3, "div", &[]);
        d.listeners = vec!["click".into(), "pointerover".into()];
        d.text = Some("Edit".into());
        d.bbox = Some(bbox(100.0, 10.0, 80.0, 30.0));
        p.bundle
            .dom_supplement
            .listener_candidates
            .push(crawlx_core::ids::BackendNodeId(3));
        let c = CandidateDiscovery::discover(&p.bundle, &DiscoveryConfig::default());
        let ids: Vec<i64> = c.iter().map(|c| c.descriptor.locator.backend_node_id.0).collect();
        assert_eq!(ids, vec![2, 3]);
        assert_eq!(c[0].rung, Rung::Listener);
        assert!(c[0].evidence.hover_listener && !c[0].evidence.direct_listener);
        assert_eq!(ActionVocabulary::for_candidate(&c[0]), vec![ActionKind::Hover]);
        assert!(c[1].evidence.hover_listener && c[1].evidence.direct_listener);
        assert_eq!(
            ActionVocabulary::for_candidate(&c[1]),
            vec![ActionKind::Click, ActionKind::Hover]
        );
        // below the listener rung the node is not a candidate at all
        let cfg = DiscoveryConfig {
            max_rung: Rung::FocusCursor,
            ..DiscoveryConfig::default()
        };
        assert!(CandidateDiscovery::discover(&p.bundle, &cfg).is_empty());
    }

    /// Drag and drop: a grab-cursor card, a `draggable` source and an
    /// `aria-grabbed` source are drag candidates with a `Drag` vocabulary; a node with only
    /// `drop`/`dragover` listeners is a drop zone, a destination with no `Drag` of its own.
    #[test]
    fn drag_sources_and_drop_zones_are_rungs() {
        use crate::vocabulary::ActionVocabulary;
        use crawlx_core::identity::ActionKind;
        let mut p = Page::new();
        p.ax(1, None, "RootWebArea", "");
        type Node<'a> = (i64, &'a [(&'a str, &'a str)], Option<&'a str>, &'a [&'a str]);
        let nodes: [Node<'_>; 4] = [
            (2, &[], Some("grab"), &[]),
            (3, &[("draggable", "true")], None, &[]),
            (4, &[("aria-grabbed", "false")], None, &[]),
            (5, &[], None, &["dragover", "drop"]),
        ];
        for (i, (id, kv, cursor, listeners)) in nodes.into_iter().enumerate() {
            p.ax(id, Some(1), "generic", "");
            let d = p.dom(id, "div", kv);
            d.text = Some(format!("item {id}"));
            d.bbox = Some(bbox(10.0 + 100.0 * i as f64, 10.0, 80.0, 30.0));
            d.cursor = cursor.map(str::to_owned);
            d.listeners = listeners.iter().map(|l| (*l).to_owned()).collect();
        }
        let c = CandidateDiscovery::discover(&p.bundle, &DiscoveryConfig::default());
        let by_id = |id: i64| {
            c.iter()
                .find(|c| c.descriptor.locator.backend_node_id.0 == id)
                .unwrap_or_else(|| panic!("{id} is a candidate"))
        };
        for id in [2, 3, 4] {
            let cand = by_id(id);
            assert!(cand.evidence.draggable, "{id}");
            assert!(
                ActionVocabulary::for_candidate(cand).contains(&ActionKind::Drag),
                "{id}"
            );
        }
        let zone = by_id(5);
        assert!(zone.evidence.drop_zone && !zone.evidence.draggable);
        assert!(!ActionVocabulary::for_candidate(zone).contains(&ActionKind::Drag));
    }

    #[test]
    fn native_and_aria_dom_only_candidates() {
        let mut p = Page::new();
        p.ax(1, None, "RootWebArea", "");
        p.dom(20, "input", &[("type", "hidden")]);
        p.dom(21, "input", &[("type", "email"), ("name", "email")]).bbox = Some(bbox(0.0, 0.0, 100.0, 20.0));
        p.dom(22, "div", &[("role", "tab")]).bbox = Some(bbox(0.0, 30.0, 100.0, 20.0));
        p.dom(23, "div", &[("contenteditable", "true")]).bbox = Some(bbox(0.0, 60.0, 100.0, 20.0));
        p.dom(24, "a", &[]).bbox = Some(bbox(0.0, 90.0, 100.0, 20.0));
        let c = CandidateDiscovery::discover(&p.bundle, &DiscoveryConfig::default());
        let ids: Vec<i64> = c.iter().map(|c| c.descriptor.locator.backend_node_id.0).collect();
        assert_eq!(ids, vec![21, 22, 23]);
        assert!(
            c[0].evidence.native_semantics && c[1].evidence.aria_semantics && c[2].evidence.native_semantics
        );
        assert_eq!(c[1].descriptor.role, "tab");
        assert_eq!(c[0].descriptor.role, "textbox");
        assert!(c.iter().all(|c| c.rung == Rung::Native));
    }

    #[test]
    fn webgl_canvas_embed_object_are_unsupported() {
        let mut p = Page::new();
        p.ax(1, None, "RootWebArea", "");
        p.dom(2, "canvas", &[("data-crawlx-context", "webgl2")]);
        p.dom(3, "embed", &[]);
        p.dom(4, "object", &[]);
        p.dom(5, "canvas", &[]);
        let r = CandidateDiscovery::discover_report(&p.bundle, &DiscoveryConfig::default());
        assert!(r.candidates.is_empty());
        let kinds: Vec<(i64, SurfaceKind)> = r
            .unsupported
            .iter()
            .map(|s| (s.locator.backend_node_id.0, s.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                (2, SurfaceKind::WebGl),
                (3, SurfaceKind::Embed),
                (4, SurfaceKind::Object),
                (5, SurfaceKind::Canvas)
            ]
        );
    }
}
