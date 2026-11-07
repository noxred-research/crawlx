//! Pure conversions from raw CDP payloads (AX tree, `DOMSnapshot`) to crawlx observation
//! types. Nothing here performs I/O, so it is unit-tested against hand-built payloads.

use crate::cdp::{ax_value_text, RawAxNode, Rect};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, TabId};
use crawlx_core::observation::{AxNode, BoundingBox, DomNodeSupplement, RuntimeLocator};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// AX roles that make a node an interaction candidate.
const CANDIDATE_ROLES: [&str; 17] = [
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
    "menuitem",
    "menuitemcheckbox",
];

/// Cap on supplement entries per observation.
pub const MAX_SUPPLEMENT_NODES: usize = 2000;

/// `listener_probe_budget`: nodes inspected for listeners per observation.
pub const LISTENER_PROBE_BUDGET: usize = 64;

/// Event types that make a generic node clickable.
pub const INTERACTION_EVENTS: [&str; 7] = [
    "click",
    "mousedown",
    "mouseup",
    "pointerdown",
    "pointerup",
    "touchstart",
    "keydown",
];

/// Event types that make a generic node hoverable (menus revealed on pointer hover).
pub const HOVER_EVENTS: [&str; 4] = ["mouseenter", "mouseover", "pointerenter", "pointerover"];

/// Event types of native drag and drop: sources (`dragstart`, `drag`) and drop zones
/// (`drop`, `dragover`, `dragenter`); the ladder keeps both.
pub const DRAG_EVENTS: [&str; 5] = ["dragstart", "drag", "drop", "dragover", "dragenter"];

/// Every listener event type the ladder keeps: [`INTERACTION_EVENTS`], [`HOVER_EVENTS`] then
/// [`DRAG_EVENTS`].
pub const LISTENER_EVENTS: [&str; 16] = [
    "click",
    "mousedown",
    "mouseup",
    "pointerdown",
    "pointerup",
    "touchstart",
    "keydown",
    "mouseenter",
    "mouseover",
    "pointerenter",
    "pointerover",
    "dragstart",
    "drag",
    "drop",
    "dragover",
    "dragenter",
];

/// Is `role` one of the interaction roles (or a `menuitem*` variant)?
#[must_use]
pub fn is_candidate_role(role: &str) -> bool {
    CANDIDATE_ROLES.contains(&role) || role.starts_with("menuitem")
}

/// One DOM node of the snapshot, keyed by backend node id.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct SnapNode {
    /// Lower-case tag name (`#text`, `#document` and friends for non-elements).
    pub tag: String,
    /// DOM `nodeType` (1 element, 3 text, 9 document, 11 document fragment).
    pub node_type: i64,
    /// Attributes in source order collapsed into a map (a repeated name keeps the last value).
    pub attrs: BTreeMap<String, String>,
    /// Viewport-relative border box; `None` when the node has no layout (not rendered).
    pub bounds: Option<Rect>,
    /// Computed `cursor` value (`pointer` marks hand-cursor affordances); `None` when not laid out.
    pub cursor: Option<String>,
    /// Computed `pointer-events` value; `None` when not laid out.
    pub pointer_events: Option<String>,
    /// Computed `display` value; `None` when not laid out.
    pub display: Option<String>,
    /// Computed `visibility` value; `None` when not laid out.
    pub visibility: Option<String>,
    /// The snapshot flags the node as having a click listener (`isClickable`).
    pub clickable: bool,
    /// Backend node id of the DOM parent; `None` for roots.
    pub parent: Option<i64>,
    /// Concatenated descendant text (whitespace-collapsed, truncated).
    pub text: String,
    /// `Some("open" | "closed" | "user-agent")` when this node is a shadow root.
    pub shadow_root_type: Option<String>,
    /// The node lives under a shadow root (open, closed or user-agent).
    pub in_shadow_root: bool,
    /// The nearest enclosing shadow root is closed (not reachable from page script).
    pub in_closed_shadow_root: bool,
    /// Frame whose document contains the node; `None` when the snapshot gave no frame id.
    pub frame_id: Option<String>,
}

impl SnapNode {
    /// Rendered, not hidden, and non-empty.
    #[must_use]
    pub fn visible(&self) -> bool {
        self.bounds.is_some_and(|b| b.w > 0.0 && b.h > 0.0)
            && self.display.as_deref() != Some("none")
            && !matches!(self.visibility.as_deref(), Some("hidden" | "collapse"))
    }

    /// Computed cursor is `pointer`.
    #[must_use]
    pub fn pointer_cursor(&self) -> bool {
        self.cursor.as_deref() == Some("pointer")
    }

    /// Computed cursor is a drag handle (`grab`, `grabbing`).
    #[must_use]
    pub fn drag_cursor(&self) -> bool {
        matches!(self.cursor.as_deref(), Some("grab" | "grabbing"))
    }

    /// Computed cursor signals an action (`pointer_cursor` or `drag_cursor`).
    #[must_use]
    pub fn action_cursor(&self) -> bool {
        self.pointer_cursor() || self.drag_cursor()
    }

    /// Declared drag source: `draggable="true"` or `aria-grabbed`.
    #[must_use]
    pub fn drag_source(&self) -> bool {
        self.attrs
            .get("draggable")
            .is_some_and(|v| v.eq_ignore_ascii_case("true"))
            || self.attrs.contains_key("aria-grabbed")
    }

    /// Native interactive element?
    #[must_use]
    pub fn natively_interactive(&self) -> bool {
        match self.tag.as_str() {
            "a" | "area" => self.attrs.contains_key("href"),
            "button" | "select" | "textarea" | "summary" => true,
            "input" => self.attrs.get("type").is_none_or(|t| t != "hidden"),
            _ => false,
        }
    }

    /// ARIA/focus/editable semantics beyond the tag.
    #[must_use]
    pub fn semantic_hint(&self) -> bool {
        self.attrs.contains_key("role")
            || self.attrs.contains_key("tabindex")
            || self
                .attrs
                .get("contenteditable")
                .is_some_and(|v| v.is_empty() || v == "true")
    }
}

/// Parsed `DOMSnapshot.captureSnapshot`.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct SnapshotIndex {
    /// Every node of every captured document, keyed by backend node id.
    pub nodes: BTreeMap<i64, SnapNode>,
    /// Document-order backend ids (parents before children), for deterministic iteration.
    pub order: Vec<i64>,
    /// Backend id of each document's root node, in `documents` order.
    pub document_roots: Vec<i64>,
}

impl SnapshotIndex {
    /// Move the index into another node-id space and viewport: every backend id (keys,
    /// `order`, `document_roots`, parents) gains `id_base`; every box moves by `(dx, dy)`.
    /// Used for an out-of-process iframe whose snapshot was captured on its own session
    /// (ids numbered by its renderer, boxes relative to its own viewport).
    pub fn relocate(&mut self, id_base: i64, dx: f64, dy: f64) {
        let nodes = std::mem::take(&mut self.nodes);
        self.nodes = nodes
            .into_iter()
            .map(|(id, mut n)| {
                n.parent = n.parent.map(|p| p + id_base);
                if let Some(b) = &mut n.bounds {
                    b.x += dx;
                    b.y += dy;
                }
                (id + id_base, n)
            })
            .collect();
        for id in self.order.iter_mut().chain(self.document_roots.iter_mut()) {
            *id += id_base;
        }
    }

    /// Append another (already relocated) index: its documents follow this one's.
    pub fn merge(&mut self, other: Self) {
        self.nodes.extend(other.nodes);
        self.order.extend(other.order);
        self.document_roots.extend(other.document_roots);
    }

    /// Project native form ownership and actual control destinations before arbitration.
    pub(crate) fn project_form_attributes(&self, id: i64, attributes: &mut BTreeMap<String, String>) {
        let Some(node) = self.nodes.get(&id) else { return };
        // These keys are observer evidence, never author-provided attributes.
        attributes.remove("crawlx:form");
        attributes.remove("crawlx:frame");
        attributes.remove("form-action");
        attributes.remove("form-method");
        if let Some(frame) = &node.frame_id {
            attributes.insert("crawlx:frame".to_owned(), frame.clone());
        }
        let submit = match node.tag.as_str() {
            "button" => node
                .attrs
                .get("type")
                .is_none_or(|kind| kind.eq_ignore_ascii_case("submit")),
            "input" => node.attrs.get("type").is_some_and(|kind| {
                kind.eq_ignore_ascii_case("submit") || kind.eq_ignore_ascii_case("image")
            }),
            _ => false,
        };
        let owner = if node.tag == "form" {
            Some((id, node))
        } else if let Some(owner) = node.attrs.get("form") {
            self.nodes.iter().find_map(|(&id, form)| {
                (form.tag == "form" && form.frame_id == node.frame_id && form.attrs.get("id") == Some(owner))
                    .then_some((id, form))
            })
        } else {
            let mut parent = node.parent;
            let mut owner = None;
            for _ in 0..self.nodes.len() {
                let Some((ancestor_id, ancestor)) =
                    parent.and_then(|id| self.nodes.get(&id).map(|node| (id, node)))
                else {
                    break;
                };
                if ancestor.shadow_root_type.is_some() || ancestor.frame_id != node.frame_id {
                    break;
                }
                if ancestor.tag == "form" {
                    owner = Some((ancestor_id, ancestor));
                    break;
                }
                parent = ancestor.parent;
            }
            owner
        };
        let Some((owner_id, owner)) = owner else { return };
        attributes.insert("crawlx:form".to_owned(), owner_id.to_string());
        let field = matches!(node.tag.as_str(), "form" | "select" | "textarea")
            || (node.tag == "input"
                && !node.attrs.get("type").is_some_and(|kind| {
                    kind.eq_ignore_ascii_case("button") || kind.eq_ignore_ascii_case("reset")
                }));
        if !submit && !field {
            return;
        }
        // An empty native action targets the current document; absence of this
        // projected attribute, unlike its empty value, means no known destination.
        let action = if submit {
            node.attrs.get("formaction").or_else(|| owner.attrs.get("action"))
        } else {
            owner.attrs.get("action")
        };
        attributes.insert("form-action".to_owned(), action.cloned().unwrap_or_default());
        let method = if submit {
            node.attrs.get("formmethod").or_else(|| owner.attrs.get("method"))
        } else {
            owner.attrs.get("method")
        };
        let method = match method.map(String::as_str) {
            Some(value) if value.eq_ignore_ascii_case("post") => "post",
            Some(value) if value.eq_ignore_ascii_case("dialog") => "dialog",
            _ => "get",
        };
        attributes.insert("form-method".to_owned(), method.to_owned());
    }
}

fn ints(v: Option<&Value>) -> Vec<i64> {
    v.and_then(Value::as_array)
        .map(|a| a.iter().map(|x| x.as_i64().unwrap_or(-1)).collect())
        .unwrap_or_default()
}

fn rare_ints(v: Option<&Value>) -> BTreeMap<usize, i64> {
    let idx = ints(v.and_then(|r| r.get("index")));
    let val = ints(v.and_then(|r| r.get("value")));
    idx.into_iter()
        .zip(val)
        .filter_map(|(i, v)| usize::try_from(i).ok().map(|i| (i, v)))
        .collect()
}

fn collapse_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(s: &mut String, max: usize) {
    if s.chars().count() > max {
        *s = s.chars().take(max).collect();
    }
}

/// Parse a `DOMSnapshot.captureSnapshot` result. Bounds are translated into
/// main-frame viewport coordinates (scroll offsets subtracted, iframe offsets added).
#[must_use]
pub fn parse_snapshot(v: &Value) -> SnapshotIndex {
    let strings: Vec<&str> = v
        .get("strings")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|s| s.as_str().unwrap_or_default()).collect())
        .unwrap_or_default();
    let s = |i: i64| -> Option<&str> { usize::try_from(i).ok().and_then(|i| strings.get(i).copied()) };
    let docs = v
        .get("documents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    // First pass: per-document node arrays and document-to-document links.
    struct DocParse {
        backend: Vec<i64>,
        owner_to_doc: BTreeMap<usize, i64>,
    }
    let mut parsed: Vec<DocParse> = Vec::with_capacity(docs.len());
    for d in &docs {
        let nodes = d.get("nodes").unwrap_or(&Value::Null);
        parsed.push(DocParse {
            backend: ints(nodes.get("backendNodeId")),
            owner_to_doc: rare_ints(nodes.get("contentDocumentIndex")),
        });
    }
    // origin of each document in main-frame viewport coordinates
    let mut origin: Vec<Option<(f64, f64)>> = vec![None; docs.len()];
    let scroll = |d: &Value| -> (f64, f64) {
        (
            d.get("scrollOffsetX").and_then(Value::as_f64).unwrap_or_default(),
            d.get("scrollOffsetY").and_then(Value::as_f64).unwrap_or_default(),
        )
    };
    if let Some(first) = docs.first() {
        let (sx, sy) = scroll(first);
        origin[0] = Some((-sx, -sy));
    }

    let mut out = SnapshotIndex::default();
    // bounds in document coordinates, resolved in a second sweep once origins are known
    let mut doc_node_bounds: Vec<BTreeMap<usize, Rect>> = vec![BTreeMap::new(); docs.len()];
    for (di, d) in docs.iter().enumerate() {
        let layout = d.get("layout").unwrap_or(&Value::Null);
        let node_index = ints(layout.get("nodeIndex"));
        if let Some(bounds) = layout.get("bounds").and_then(Value::as_array) {
            for (li, b) in bounds.iter().enumerate() {
                let (Some(ni), Some(arr)) = (node_index.get(li), b.as_array()) else {
                    continue;
                };
                let f: Vec<f64> = arr.iter().filter_map(Value::as_f64).collect();
                if let (Ok(ni), [x, y, w, h]) = (usize::try_from(*ni), f.as_slice()) {
                    doc_node_bounds[di].insert(
                        ni,
                        Rect {
                            x: *x,
                            y: *y,
                            w: *w,
                            h: *h,
                        },
                    );
                }
            }
        }
    }
    // resolve child-document origins from their owner nodes (parents precede children in practice;
    // iterate to a fixed point to be safe)
    for _ in 0..docs.len().max(1) {
        let mut changed = false;
        for pi in 0..docs.len() {
            let Some((ox, oy)) = origin[pi] else { continue };
            for (owner_idx, child_doc) in &parsed[pi].owner_to_doc {
                let Ok(ci) = usize::try_from(*child_doc) else {
                    continue;
                };
                if ci >= docs.len() || origin[ci].is_some() {
                    continue;
                }
                if let Some(b) = doc_node_bounds[pi].get(owner_idx) {
                    let (sx, sy) = scroll(&docs[ci]);
                    origin[ci] = Some((ox + b.x - sx, oy + b.y - sy));
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }

    for (di, d) in docs.iter().enumerate() {
        let (ox, oy) = origin[di].unwrap_or((0.0, 0.0));
        let nodes = d.get("nodes").unwrap_or(&Value::Null);
        let layout = d.get("layout").unwrap_or(&Value::Null);
        let backend = &parsed[di].backend;
        let parent = ints(nodes.get("parentIndex"));
        let ntype = ints(nodes.get("nodeType"));
        let nname = ints(nodes.get("nodeName"));
        let nvalue = ints(nodes.get("nodeValue"));
        let attrs = nodes
            .get("attributes")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let shadow = rare_ints(nodes.get("shadowRootType"));
        let clickable: BTreeSet<usize> = ints(nodes.get("isClickable").and_then(|r| r.get("index")))
            .into_iter()
            .filter_map(|i| usize::try_from(i).ok())
            .collect();
        let frame_id = d
            .get("frameId")
            .and_then(Value::as_i64)
            .and_then(s)
            .map(str::to_owned);

        // computed styles per node index
        let node_index = ints(layout.get("nodeIndex"));
        let styles = layout
            .get("styles")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut style_of: BTreeMap<usize, [Option<String>; 4]> = BTreeMap::new();
        for (li, st) in styles.iter().enumerate() {
            let (Some(ni), Some(arr)) = (node_index.get(li), st.as_array()) else {
                continue;
            };
            let Ok(ni) = usize::try_from(*ni) else { continue };
            let get = |k: usize| arr.get(k).and_then(Value::as_i64).and_then(s).map(str::to_owned);
            style_of.insert(ni, [get(0), get(1), get(2), get(3)]);
        }

        let n = backend.len();
        let mut nodes_out: Vec<SnapNode> = Vec::with_capacity(n);
        for i in 0..n {
            let mut a = BTreeMap::new();
            if let Some(pairs) = attrs.get(i).and_then(Value::as_array) {
                for kv in pairs.chunks(2) {
                    if let [k, val] = kv {
                        let k = k.as_i64().and_then(s).unwrap_or_default().to_ascii_lowercase();
                        let val = val.as_i64().and_then(s).unwrap_or_default();
                        let mut val = val.to_owned();
                        truncate_chars(&mut val, 256);
                        if !k.is_empty() {
                            a.insert(k, val);
                        }
                    }
                }
            }
            let st = style_of.get(&i).cloned().unwrap_or_default();
            let [cursor, pointer_events, display, visibility] = st;
            let tag = nname
                .get(i)
                .and_then(|x| s(*x))
                .unwrap_or_default()
                .to_ascii_lowercase();
            let pidx = parent
                .get(i)
                .copied()
                .filter(|p| *p >= 0)
                .and_then(|p| usize::try_from(p).ok());
            let shadow_root_type = shadow.get(&i).and_then(|t| s(*t)).map(str::to_owned);
            nodes_out.push(SnapNode {
                tag,
                node_type: ntype.get(i).copied().unwrap_or_default(),
                attrs: a,
                bounds: doc_node_bounds[di].get(&i).map(|r| Rect {
                    x: r.x + ox,
                    y: r.y + oy,
                    w: r.w,
                    h: r.h,
                }),
                cursor,
                pointer_events,
                display,
                visibility,
                clickable: clickable.contains(&i),
                parent: pidx.and_then(|p| backend.get(p).copied()),
                text: String::new(),
                shadow_root_type,
                in_shadow_root: false,
                in_closed_shadow_root: false,
                frame_id: frame_id.clone(),
            });
            let _ = pidx;
        }
        // shadow flags (parents precede children in document order)
        for i in 0..n {
            let pidx = parent
                .get(i)
                .copied()
                .filter(|p| *p >= 0)
                .and_then(|p| usize::try_from(p).ok());
            if let Some(p) = pidx.filter(|p| *p < n) {
                let (p_is_shadow, p_in, p_closed, p_closed_root) = {
                    let pn = &nodes_out[p];
                    (
                        pn.shadow_root_type.is_some(),
                        pn.in_shadow_root,
                        pn.in_closed_shadow_root,
                        pn.shadow_root_type.as_deref() == Some("closed"),
                    )
                };
                let me = &mut nodes_out[i];
                me.in_shadow_root = p_is_shadow || p_in;
                me.in_closed_shadow_root = p_closed || p_closed_root;
            }
        }
        // text accumulation: text nodes feed their nearest ancestors
        for i in 0..n {
            if nodes_out[i].node_type != 3 {
                continue;
            }
            let Some(t) = nvalue.get(i).and_then(|x| s(*x)) else {
                continue;
            };
            let t = collapse_ws(t);
            if t.is_empty() {
                continue;
            }
            let mut cur = parent
                .get(i)
                .copied()
                .filter(|p| *p >= 0)
                .and_then(|p| usize::try_from(p).ok());
            let mut depth = 0;
            while let Some(p) = cur.filter(|p| *p < n) {
                if depth >= 6 {
                    break;
                }
                let node = &mut nodes_out[p];
                if node.text.chars().count() < 200 {
                    if !node.text.is_empty() {
                        node.text.push(' ');
                    }
                    node.text.push_str(&t);
                    truncate_chars(&mut node.text, 200);
                }
                cur = parent
                    .get(p)
                    .copied()
                    .filter(|q| *q >= 0)
                    .and_then(|q| usize::try_from(q).ok());
                depth += 1;
            }
        }
        if let Some(root) = backend.first() {
            out.document_roots.push(*root);
        }
        for (i, node) in nodes_out.into_iter().enumerate() {
            let id = backend[i];
            out.order.push(id);
            out.nodes.insert(id, node);
        }
    }
    out
}

/// Convert one frame's raw AX nodes into crawlx `AxNode`s (pre-order). Nodes without a
/// backend DOM node are dropped and their children re-parented to the nearest kept ancestor.
#[must_use]
pub fn ax_nodes(
    raw: &[RawAxNode],
    tab: &TabId,
    frame: &FrameId,
    main_frame: bool,
    epoch: ObservationEpoch,
    bbox_of: &dyn Fn(i64) -> Option<BoundingBox>,
) -> Vec<AxNode> {
    let id_of = |raw_id: &str| -> AxNodeId {
        if main_frame {
            AxNodeId(raw_id.to_owned())
        } else {
            AxNodeId(format!("{}:{raw_id}", frame.0))
        }
    };
    let by_id: BTreeMap<&str, &RawAxNode> = raw.iter().map(|n| (n.node_id.as_str(), n)).collect();
    // parent per node from childIds (parentId is optional in the protocol)
    let mut parent_of: BTreeMap<&str, &str> = BTreeMap::new();
    for n in raw {
        for c in &n.child_ids {
            parent_of.insert(c.as_str(), n.node_id.as_str());
        }
        if let Some(p) = &n.parent_id {
            parent_of.entry(n.node_id.as_str()).or_insert(p.as_str());
        }
    }
    let kept = |n: &RawAxNode| n.backend_dom_node_id.is_some_and(|b| b > 0);
    let nearest_kept_parent = |id: &str| -> Option<&str> {
        let mut cur = parent_of.get(id).copied();
        let mut guard = 0;
        while let Some(p) = cur {
            if by_id.get(p).is_some_and(|n| kept(n)) {
                return Some(p);
            }
            cur = parent_of.get(p).copied();
            guard += 1;
            if guard > raw.len() {
                break;
            }
        }
        None
    };

    let mut children_of: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut roots: Vec<&str> = Vec::new();
    for n in raw.iter().filter(|n| kept(n)) {
        match nearest_kept_parent(&n.node_id) {
            Some(p) => children_of.entry(p).or_default().push(n.node_id.as_str()),
            None => roots.push(n.node_id.as_str()),
        }
    }

    // pre-order walk
    let mut order: Vec<&str> = Vec::with_capacity(raw.len());
    let mut stack: Vec<&str> = roots.into_iter().rev().collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        order.push(id);
        if let Some(ch) = children_of.get(id) {
            for c in ch.iter().rev() {
                stack.push(c);
            }
        }
    }

    order
        .into_iter()
        .filter_map(|id| by_id.get(id).copied())
        .map(|n| {
            let backend = n.backend_dom_node_id.unwrap_or_default();
            // CDP spells property names in camelCase (`hasPopup`, `autocomplete`, ...);
            // consumers (`ax_is_candidate`, the elements ladder, descriptor mirroring)
            // key on lower-case names.
            let mut properties = BTreeMap::new();
            let (mut focusable, mut disabled, mut expanded, mut checked) = (false, false, None, None);
            for p in &n.properties {
                let text = ax_value_text(Some(&p.value)).unwrap_or_default();
                let name = p.name.to_ascii_lowercase();
                match name.as_str() {
                    "focusable" => focusable = text == "true",
                    "disabled" => disabled = text == "true",
                    "expanded" => expanded = Some(text == "true"),
                    "checked" => checked = Some(text.clone()),
                    _ => {}
                }
                properties.insert(name, text);
            }
            AxNode {
                locator: RuntimeLocator {
                    tab: tab.clone(),
                    frame: frame.clone(),
                    backend_node_id: BackendNodeId(backend),
                    object_id: None,
                    ax_node_id: Some(id_of(&n.node_id)),
                    epoch,
                },
                role: ax_value_text(n.role.as_ref()).unwrap_or_default(),
                name: ax_value_text(n.name.as_ref()).filter(|s| !s.is_empty()),
                description: ax_value_text(n.description.as_ref()).filter(|s| !s.is_empty()),
                value: ax_value_text(n.value.as_ref()),
                ignored: n.ignored,
                focusable,
                disabled,
                expanded,
                checked,
                properties,
                parent: nearest_kept_parent(&n.node_id).map(id_of),
                children: children_of
                    .get(n.node_id.as_str())
                    .map(|c| c.iter().map(|c| id_of(c)).collect())
                    .unwrap_or_default(),
                bbox: bbox_of(backend),
            }
        })
        .collect()
}

/// Is this AX node a candidate (not ignored/disabled; interaction role or focus/expand semantics)?
#[must_use]
pub fn ax_is_candidate(n: &AxNode) -> bool {
    !n.ignored
        && !n.disabled
        && (is_candidate_role(&n.role)
            || n.focusable
            || n.expanded.is_some()
            || n.properties.contains_key("haspopup")
            || n.properties.contains_key("editable"))
}

/// Nodes the snapshot flags as likely interactive but AX does not cover (rungs 1–2),
/// outermost action-cursor nodes only, plus declared drag sources, in document order.
#[must_use]
pub fn snapshot_only_candidates(snap: &SnapshotIndex, ax_candidates: &BTreeSet<i64>) -> Vec<i64> {
    let mut out = Vec::new();
    for id in &snap.order {
        let Some(n) = snap.nodes.get(id) else { continue };
        if n.node_type != 1 || ax_candidates.contains(id) || !n.visible() {
            continue;
        }
        let parent_cursor = n
            .parent
            .and_then(|p| snap.nodes.get(&p))
            .is_some_and(SnapNode::action_cursor);
        let cursor_root = n.action_cursor() && !parent_cursor;
        if n.natively_interactive() || n.semantic_hint() || n.clickable || cursor_root || n.drag_source() {
            out.push(*id);
        }
    }
    out
}

/// Drop-zone probes for a page with drag sources (`draggable`, `aria-grabbed` or a grab
/// cursor): the sources' ancestors (two levels) and their siblings, plus every node with
/// `aria-dropeffect`, in document order. Drop listeners sit on containers that carry no
/// cursor or role hint, so they are only probed when something could be dragged into them;
/// the caller bounds the list with the listener budget. Empty without drag sources.
#[must_use]
pub fn drop_zone_probes(snap: &SnapshotIndex, sources: &[i64]) -> Vec<i64> {
    if sources.is_empty() {
        return Vec::new();
    }
    let source_set: BTreeSet<i64> = sources.iter().copied().collect();
    let mut wanted: BTreeSet<i64> = BTreeSet::new();
    for id in sources {
        let mut cur = snap.nodes.get(id).and_then(|n| n.parent);
        for _ in 0..2 {
            let Some(p) = cur else { break };
            wanted.insert(p);
            cur = snap.nodes.get(&p).and_then(|n| n.parent);
        }
    }
    let parents: BTreeSet<i64> = sources
        .iter()
        .filter_map(|id| snap.nodes.get(id).and_then(|n| n.parent))
        .collect();
    let mut out = Vec::new();
    for id in &snap.order {
        let Some(n) = snap.nodes.get(id) else { continue };
        if n.node_type != 1 || source_set.contains(id) || !n.visible() {
            continue;
        }
        let sibling = n.parent.is_some_and(|p| parents.contains(&p));
        let declared = n
            .attrs
            .get("aria-dropeffect")
            .is_some_and(|v| !v.is_empty() && !v.eq_ignore_ascii_case("none"));
        if wanted.contains(id) || sibling || declared {
            out.push(*id);
        }
    }
    out
}

/// Does `id` have an interactive ancestor (native interactive tag or AX candidate)?
#[must_use]
pub fn has_interactive_ancestor(snap: &SnapshotIndex, id: i64, ax_candidates: &BTreeSet<i64>) -> bool {
    let mut cur = snap.nodes.get(&id).and_then(|n| n.parent);
    let mut guard = 0;
    while let Some(p) = cur {
        if ax_candidates.contains(&p) || snap.nodes.get(&p).is_some_and(SnapNode::natively_interactive) {
            return true;
        }
        cur = snap.nodes.get(&p).and_then(|n| n.parent);
        guard += 1;
        if guard > 256 {
            break;
        }
    }
    false
}

/// Supplement entry for one snapshot node.
#[must_use]
pub fn supplement_for(n: &SnapNode, name_hint: Option<&str>) -> DomNodeSupplement {
    let text = if n.text.is_empty() {
        name_hint.map(str::to_owned)
    } else {
        Some(n.text.clone())
    };
    DomNodeSupplement {
        tag: n.tag.clone(),
        attributes: n.attrs.clone(),
        cursor: n.cursor.clone(),
        listeners: Vec::new(),
        text,
        bbox: n.bounds.map(Rect::to_bbox),
        in_shadow_root: n.in_shadow_root,
        shadow_root_closed: n.in_closed_shadow_root,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::cdp::RawAxValue;
    use serde_json::json;

    fn val(v: Value) -> Option<RawAxValue> {
        Some(RawAxValue { value: Some(v) })
    }

    fn ax(id: &str, role: &str, name: &str, backend: Option<i64>, children: &[&str]) -> RawAxNode {
        RawAxNode {
            node_id: id.to_owned(),
            role: val(json!(role)),
            name: val(json!(name)),
            backend_dom_node_id: backend,
            child_ids: children.iter().map(|s| (*s).to_owned()).collect(),
            ..RawAxNode::default()
        }
    }

    #[test]
    fn ax_tree_is_preorder_and_reparents_over_dropped_nodes() {
        let raw = vec![
            ax("1", "RootWebArea", "t", Some(1), &["2"]),
            ax("2", "generic", "", None, &["3", "4"]),
            ax("3", "button", "Save", Some(5), &[]),
            ax("4", "link", "Home", Some(6), &[]),
        ];
        let nodes = ax_nodes(
            &raw,
            &TabId("t".into()),
            &FrameId("f".into()),
            true,
            ObservationEpoch::default(),
            &|_| None,
        );
        let roles: Vec<_> = nodes.iter().map(|n| n.role.as_str()).collect();
        assert_eq!(roles, ["RootWebArea", "button", "link"]);
        assert_eq!(nodes[1].parent, Some(AxNodeId("1".into())));
        assert_eq!(
            nodes[0].children,
            vec![AxNodeId("3".into()), AxNodeId("4".into())]
        );
        assert_eq!(nodes[1].name.as_deref(), Some("Save"));
        assert_eq!(nodes[1].locator.backend_node_id, BackendNodeId(5));
    }

    #[test]
    fn ax_properties_map_to_fields() {
        let mut n = ax("1", "checkbox", "Agree", Some(9), &[]);
        n.properties = vec![
            crate::cdp::RawAxProperty {
                name: "focusable".into(),
                value: RawAxValue {
                    value: Some(json!(true)),
                },
            },
            crate::cdp::RawAxProperty {
                name: "checked".into(),
                value: RawAxValue {
                    value: Some(json!("mixed")),
                },
            },
            crate::cdp::RawAxProperty {
                name: "disabled".into(),
                value: RawAxValue {
                    value: Some(json!(true)),
                },
            },
        ];
        let nodes = ax_nodes(
            &[n],
            &TabId("t".into()),
            &FrameId("sub".into()),
            false,
            ObservationEpoch::default(),
            &|_| Some(BoundingBox::default()),
        );
        let n = &nodes[0];
        assert!(n.focusable && n.disabled);
        assert_eq!(n.checked.as_deref(), Some("mixed"));
        assert_eq!(n.locator.ax_node_id, Some(AxNodeId("sub:1".into())));
        assert!(n.bbox.is_some());
        assert!(!ax_is_candidate(n), "disabled nodes are not candidates");
    }

    /// CDP spells `hasPopup` in camelCase; consumers key on lower-case names.
    #[test]
    fn ax_property_names_are_lower_cased() {
        let mut n = ax("1", "generic", "File", Some(9), &[]);
        n.properties = vec![crate::cdp::RawAxProperty {
            name: "hasPopup".into(),
            value: RawAxValue {
                value: Some(json!("menu")),
            },
        }];
        let nodes = ax_nodes(
            &[n],
            &TabId("t".into()),
            &FrameId("main".into()),
            true,
            ObservationEpoch::default(),
            &|_| None,
        );
        let n = &nodes[0];
        assert_eq!(n.properties.get("haspopup").map(String::as_str), Some("menu"));
        assert!(!n.properties.contains_key("hasPopup"));
        assert!(ax_is_candidate(n), "a has-popup generic is a rung-0 candidate");
    }

    fn snapshot() -> Value {
        // strings: 0 html,1 body,2 button,3 id,4 b1,5 div,6 pointer,7 block,8 visible,9 Hello,10 #text,11 none
        json!({
            "strings": ["html","body","button","id","b1","div","pointer","block","visible","Hello world","#text","default","role","link"],
            "documents": [{
                "frameId": 0,
                "scrollOffsetX": 0.0,
                "scrollOffsetY": 10.0,
                "nodes": {
                    "parentIndex": [-1, 0, 1, 2, 1, 1],
                    "nodeType": [9, 1, 1, 3, 1, 1],
                    "nodeName": [0, 1, 2, 10, 5, 5],
                    "nodeValue": [-1, -1, -1, 9, -1, -1],
                    "backendNodeId": [10, 11, 12, 13, 14, 15],
                    "attributes": [[], [], [3, 4], [], [12, 13], []],
                    "isClickable": {"index": [4]},
                    "shadowRootType": {"index": [], "value": []},
                    "contentDocumentIndex": {"index": [], "value": []}
                },
                "layout": {
                    "nodeIndex": [1, 2, 4, 5],
                    "bounds": [[0,0,800,600],[10,110,80,30],[10,200,50,20],[10,300,50,20]],
                    "styles": [[11,7,7,8],[6,7,7,8],[6,7,7,8],[11,7,7,8]]
                }
            }]
        })
    }

    #[test]
    fn snapshot_parsing_translates_bounds_and_text() {
        let snap = parse_snapshot(&snapshot());
        let b = &snap.nodes[&12];
        assert_eq!(b.tag, "button");
        assert_eq!(b.attrs.get("id").map(String::as_str), Some("b1"));
        // scrollY 10 is subtracted: document y 110 -> viewport y 100
        let r = b.bounds.unwrap();
        assert_eq!((r.x, r.y, r.w, r.h), (10.0, 100.0, 80.0, 30.0));
        assert_eq!(b.text, "Hello world");
        assert!(b.visible() && b.pointer_cursor() && b.natively_interactive());
        assert_eq!(snap.document_roots, vec![10]);
        assert!(snap.nodes[&10].bounds.is_none());
    }

    #[test]
    fn snapshot_only_candidates_follow_rungs() {
        let snap = parse_snapshot(&snapshot());
        let covered: BTreeSet<i64> = BTreeSet::new();
        let got = snapshot_only_candidates(&snap, &covered);
        // button (native), div role=link (hint + clickable + pointer); plain div (15) is not a candidate
        assert_eq!(got, vec![12, 14]);
        let covered: BTreeSet<i64> = [12].into_iter().collect();
        assert_eq!(snapshot_only_candidates(&snap, &covered), vec![14]);
        assert!(!has_interactive_ancestor(&snap, 14, &covered));
        assert!(has_interactive_ancestor(&snap, 13, &covered));
    }

    #[test]
    fn iframe_documents_are_offset_by_their_owner() {
        let snap = json!({
            "strings": ["html","iframe","button","body"],
            "documents": [
                {"frameId": -1, "scrollOffsetX": 0.0, "scrollOffsetY": 0.0,
                 "nodes": {"parentIndex": [-1, 0], "nodeType": [9, 1], "nodeName": [0, 1], "nodeValue": [-1,-1],
                           "backendNodeId": [1, 2], "attributes": [[], []],
                           "contentDocumentIndex": {"index": [1], "value": [1]}},
                 "layout": {"nodeIndex": [1], "bounds": [[100, 50, 300, 200]], "styles": [[0,0,0,0]]}},
                {"frameId": -1, "scrollOffsetX": 0.0, "scrollOffsetY": 0.0,
                 "nodes": {"parentIndex": [-1, 0], "nodeType": [9, 1], "nodeName": [0, 2], "nodeValue": [-1,-1],
                           "backendNodeId": [3, 4], "attributes": [[], []]},
                 "layout": {"nodeIndex": [1], "bounds": [[5, 6, 40, 20]], "styles": [[0,0,0,0]]}}
            ]
        });
        let idx = parse_snapshot(&snap);
        let b = idx.nodes[&4].bounds.unwrap();
        assert_eq!((b.x, b.y), (105.0, 56.0));
        assert_eq!(idx.document_roots, vec![1, 3]);
    }

    #[test]
    fn relocate_moves_ids_and_boxes_and_merge_appends() {
        let mut page = parse_snapshot(&snapshot());
        let mut frame = parse_snapshot(&snapshot());
        let before = frame.nodes[&12].clone();
        frame.relocate(1 << 32, 100.0, 50.0);
        let moved = &frame.nodes[&(12 + (1 << 32))];
        assert_eq!(moved.parent, before.parent.map(|p| p + (1 << 32)));
        let (b0, b1) = (before.bounds.unwrap(), moved.bounds.unwrap());
        assert_eq!((b1.x, b1.y, b1.w, b1.h), (b0.x + 100.0, b0.y + 50.0, b0.w, b0.h));
        assert!(frame
            .order
            .iter()
            .chain(&frame.document_roots)
            .all(|id| *id >= (1 << 32)));
        let (n, o, r) = (page.nodes.len(), page.order.len(), page.document_roots.len());
        page.merge(frame);
        assert_eq!(
            (page.nodes.len(), page.order.len(), page.document_roots.len()),
            (2 * n, 2 * o, 2 * r)
        );
        assert!(page.nodes.contains_key(&12) && page.nodes.contains_key(&(12 + (1 << 32))));
    }

    #[test]
    fn supplement_prefers_text_then_name() {
        let snap = parse_snapshot(&snapshot());
        let s = supplement_for(&snap.nodes[&12], Some("Save"));
        assert_eq!(s.text.as_deref(), Some("Hello world"));
        assert_eq!(s.cursor.as_deref(), Some("pointer"));
        let s = supplement_for(&snap.nodes[&15], Some("Save"));
        assert_eq!(s.text.as_deref(), Some("Save"));
    }

    #[test]
    fn native_submit_destination_is_projected_with_owner_and_submitter_overrides() {
        let mut snap = SnapshotIndex::default();
        snap.nodes.insert(
            1,
            SnapNode {
                tag: "form".into(),
                attrs: [
                    ("id".into(), "mail".into()),
                    ("action".into(), "/sink".into()),
                    ("method".into(), "POST".into()),
                ]
                .into(),
                ..SnapNode::default()
            },
        );
        snap.nodes.insert(
            2,
            SnapNode {
                tag: "button".into(),
                parent: Some(1),
                ..SnapNode::default()
            },
        );
        let mut attributes = BTreeMap::new();
        snap.project_form_attributes(2, &mut attributes);
        assert_eq!(attributes.get("form-action").map(String::as_str), Some("/sink"));
        assert_eq!(attributes.get("crawlx:form").map(String::as_str), Some("1"));
        let mut declaration = BTreeMap::new();
        snap.project_form_attributes(1, &mut declaration);
        assert_eq!(declaration.get("crawlx:form"), attributes.get("crawlx:form"));
        snap.nodes.insert(
            3,
            SnapNode {
                tag: "input".into(),
                attrs: [
                    ("form".into(), "mail".into()),
                    ("formaction".into(), "/not-a-submitter".into()),
                    ("formmethod".into(), "get".into()),
                ]
                .into(),
                ..SnapNode::default()
            },
        );
        let mut field = BTreeMap::new();
        snap.project_form_attributes(3, &mut field);
        assert_eq!(field.get("crawlx:form"), declaration.get("crawlx:form"));
        assert_eq!(field.get("form-action").map(String::as_str), Some("/sink"));
        assert_eq!(field.get("form-method").map(String::as_str), Some("post"));
        snap.nodes
            .get_mut(&2)
            .unwrap()
            .attrs
            .insert("formaction".into(), "/override".into());
        snap.project_form_attributes(2, &mut attributes);
        assert_eq!(
            attributes.get("form-action").map(String::as_str),
            Some("/override")
        );
        let button = snap.nodes.get_mut(&2).unwrap();
        button.parent = None;
        button.attrs.insert("form".into(), "mail".into());
        attributes.clear();
        snap.project_form_attributes(2, &mut attributes);
        assert_eq!(
            attributes.get("form-action").map(String::as_str),
            Some("/override")
        );
        snap.nodes
            .get_mut(&2)
            .unwrap()
            .attrs
            .insert("type".into(), "button".into());
        attributes.clear();
        snap.project_form_attributes(2, &mut attributes);
        assert!(!attributes.contains_key("form-action"));
        snap.nodes.get_mut(&2).unwrap().attrs.remove("type");
        snap.nodes.get_mut(&2).unwrap().frame_id = Some("other-frame".into());
        snap.project_form_attributes(2, &mut attributes);
        assert!(!attributes.contains_key("form-action"));
        assert!(!attributes.contains_key("crawlx:form"));
        assert_eq!(
            attributes.get("crawlx:frame").map(String::as_str),
            Some("other-frame")
        );
        // An identical author id in another frame owns only that frame's controls.
        snap.nodes.insert(
            4,
            SnapNode {
                tag: "form".into(),
                frame_id: Some("other-frame".into()),
                attrs: [("id".into(), "mail".into()), ("action".into(), "/other".into())].into(),
                ..SnapNode::default()
            },
        );
        attributes.insert("crawlx:form".into(), "forged".into());
        snap.project_form_attributes(2, &mut attributes);
        assert_eq!(attributes.get("crawlx:form").map(String::as_str), Some("4"));
        // The submitter override still wins; ownership does not replace destinations.
        assert_eq!(
            attributes.get("form-action").map(String::as_str),
            Some("/override")
        );
    }
}
