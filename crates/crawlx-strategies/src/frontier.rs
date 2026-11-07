//! Frontier statistics, candidate → action-key enumeration, template/group
//! dedupe and the paper's layered queue.
//!
//! Everything here is a pure function of its inputs plus [`FrontierStats`],
//! which is updated only through [`crate::ExplorationState`]. All maps are
//! `BTreeMap`s so ordering never depends on hash-map iteration.

use crawlx_core::action::{BrowserAction, KeyChord, Modifiers, OptionKey, PointerButton, ScrollDelta};
use crawlx_core::hash::Digest;
use crawlx_core::observation::{LiveTargetFacts, ObservationBundle};
use crawlx_core::safety::RiskClass;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{
    ActionContextId, ActionContextKey, ActionKind, ElementIdentityHash, ElementIdentityV1, InputClass,
    PrincipalId, ResourceContext, RouteTemplate, SafetyProfile, StateClusterId, Timestamp,
};
use crawlx_elements::{ActionVocabulary, BundleIndex, Candidate, ResolvedElement};
use crawlx_forms::{
    partitions_for, ConfiguredValues, FormGrouper, InputClassifier, InputConstraints, InputKind, Partition,
    ValueContext, ValuePartitions, GENERATOR_VERSION,
};
use rand::seq::SliceRandom;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Variant of the paper's enablement bonus `E(e)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum EVariant {
    /// `−0.8 · min(R, 5)` with `R` novel-reveal episodes (default).
    #[default]
    NovelEpisode,
    /// `−0.8` per revealed identity.
    PerElement,
    /// `−0.8` once ever revealed.
    Flag,
}

/// Paper constants (starting references for sensitivity analysis, not truths).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct QueueCfg {
    /// Magnitude of the enablement bonus `E(e)` subtracted from the score (paper: 0.8).
    pub reveal_bonus: f32,
    /// Cap on the novel-reveal episode count `R` in the `NovelEpisode` variant (paper: 5).
    pub reveal_cap: u32,
    /// Weight of the family-repetition term `Z(e)` (paper: 0.3).
    pub z_weight: f32,
    /// Which enablement-bonus variant is applied.
    pub e_variant: EVariant,
    /// Use `w_element` (paper-compatible) instead of `w_key`.
    pub paper_compat: bool,
    /// Same `(cluster, key)` executed this many times triggers a cooldown.
    pub cycle_threshold: u32,
    /// Interactions a cycling key stays blacklisted.
    pub blacklist_len: u64,
    /// Soft-block window of recently exercised element signatures.
    pub recent_window: usize,
}

impl Default for QueueCfg {
    fn default() -> Self {
        Self {
            reveal_bonus: 0.8,
            reveal_cap: 5,
            z_weight: 0.3,
            e_variant: EVariant::NovelEpisode,
            paper_compat: false,
            cycle_threshold: 3,
            blacklist_len: 5,
            recent_window: 8,
        }
    }
}

/// `BLAKE3(role ‖ stable_ancestor_role_path)` — the family signature behind `Z(e)`.
#[must_use]
pub fn stable_path_sig(identity: &ElementIdentityV1) -> Digest {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(identity.role.as_bytes());
    for part in &identity.stable_ancestor_role_path {
        buf.push(0);
        buf.extend_from_slice(part.as_bytes());
    }
    Digest::of("crawlx/stable-path-sig/v1", &buf)
}

/// Signature of "an element with the same normalized name and stable path".
#[must_use]
pub fn name_path_sig(identity: &ElementIdentityV1) -> Digest {
    let mut buf = Vec::with_capacity(96);
    buf.extend_from_slice(stable_path_sig(identity).0.as_slice());
    buf.push(0);
    buf.extend_from_slice(identity.normalized_accessible_name.as_bytes());
    Digest::of("crawlx/name-path-sig/v1", &buf)
}

/// Synthetic element identity of "the page at this route" for `Navigate` keys
/// that have no link behind them (reset-to-known-route steps).
#[must_use]
pub fn route_element(route: &RouteTemplate) -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("crawlx/route-nav/v1", route.0.as_bytes()))
}

/// Action-context key of a reset `Navigate` to `target_route`.
#[must_use]
pub fn route_nav_key(
    principal: &PrincipalId,
    from_route: &RouteTemplate,
    cluster: StateClusterId,
    target_route: &RouteTemplate,
) -> ActionContextKey {
    ActionContextKey {
        principal: principal.clone(),
        route_template: from_route.clone(),
        element: route_element(target_route),
        action_kind: ActionKind::Navigate,
        input_class: InputClass::none(),
        resource_context: ResourceContext::None,
        state_cluster: cluster,
    }
}

/// Stable id of the navigation to `route` used by path search (cluster-independent).
#[must_use]
pub fn route_nav_action_id(principal: &PrincipalId, route: &RouteTemplate) -> ActionContextId {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(principal.0.as_bytes());
    buf.push(0);
    buf.extend_from_slice(route.0.as_bytes());
    ActionContextId(Digest::of("crawlx/route-nav-action/v1", &buf).truncate16())
}

/// A known route the strategies may reset to with `Navigate`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RouteEntry {
    /// Fetchable URL of the first observation of this route.
    pub url: String,
    /// Cluster that observation landed in.
    pub cluster: StateClusterId,
    /// Number of observations of this route so far.
    pub visits: u32,
}

/// What a keyed action does, without runtime handles or generated values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Intent {
    /// Click the target.
    Click,
    /// Activate the focused target with the keyboard (Enter/Space).
    KeyboardActivate,
    /// Hover the target.
    Hover,
    /// Scroll the target (or the page) into motion.
    Scroll,
    /// Desired checked state.
    SetChecked(bool),
    /// Set a range input (slider) value.
    SetRange,
    /// Choose an option of a select control.
    Select,
    /// Type text drawn from the value partition.
    Type(Partition),
    /// Upload a file drawn from the value partition.
    Upload(Partition),
    /// Press a keyboard chord; has no target element.
    Keys,
    /// Drag the target onto the candidate at this index (drag evidence).
    Drag(usize),
    /// Dismiss the open modal dialog with `Escape` (escape policy); keyed on
    /// the dialog's first control (or the first candidate when the dialog has none).
    Dismiss,
}

/// Accessible names of controls that close a dialog without committing anything
/// (normalized: lower case, trimmed, trailing punctuation removed).
const DISMISS_NAMES: [&str; 11] = [
    "close",
    "cancel",
    "dismiss",
    "close dialog",
    "no thanks",
    "not now",
    "later",
    "maybe later",
    "skip",
    "×",
    "x",
];

/// The open modal dialog of an observation: which candidates live inside it and which of
/// them dismiss it. While a modal is open only its own controls are reachable
/// (crawlx never clicks through an obstructor), so enumeration is restricted to `inside`;
/// the dismiss controls (or `Escape` when there is none) are the escape policy.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ModalScope {
    /// Candidate indices inside the dialog.
    pub inside: BTreeSet<usize>,
    /// Candidate indices of the dialog's close/cancel controls (subset of `inside`).
    pub dismiss: BTreeSet<usize>,
}

impl ModalScope {
    /// Does `ka` dismiss the dialog (a close control's activation, or `Escape`)?
    #[must_use]
    pub fn dismisses(&self, ka: &KeyedAction) -> bool {
        match ka.intent {
            Intent::Dismiss => true,
            Intent::Click | Intent::KeyboardActivate => self.dismiss.contains(&ka.candidate),
            _ => false,
        }
    }
}

fn is_dialog_role(role: &str) -> bool {
    matches!(
        role.trim().to_ascii_lowercase().as_str(),
        "dialog" | "alertdialog"
    )
}

fn dismiss_name(name: &str) -> bool {
    let n = name.trim().trim_end_matches(['.', '!', '…']).to_ascii_lowercase();
    DISMISS_NAMES.contains(&n.as_str())
}

/// The modal scope of `bundle`, if a modal dialog (`role=dialog|alertdialog` with the
/// `modal` AX property, rendered) is open. Candidates are inside when a dialog role is among
/// their ancestors.
#[must_use]
pub fn modal_scope(bundle: &ObservationBundle, candidates: &[Candidate]) -> Option<ModalScope> {
    let open = bundle.ax.nodes.iter().any(|n| {
        !n.ignored
            && is_dialog_role(&n.role)
            && n.properties.get("modal").is_some_and(|v| v == "true")
            && n.bbox.is_some_and(|b| b.area() > 0.0)
    });
    if !open {
        return None;
    }
    let mut scope = ModalScope::default();
    for (i, c) in candidates.iter().enumerate() {
        let d = &c.descriptor;
        if !d.ancestor_roles.iter().any(|r| is_dialog_role(r)) {
            continue;
        }
        scope.inside.insert(i);
        let named = d
            .accessible_name
            .as_deref()
            .or(d.attributes.get("aria-label").map(String::as_str))
            .or(d.text.as_deref())
            .is_some_and(dismiss_name);
        if named
            && matches!(
                d.role.to_ascii_lowercase().as_str(),
                "button" | "link" | "menuitem"
            )
        {
            scope.dismiss.insert(i);
        }
    }
    Some(scope)
}

/// Destination of a drag from candidate `i`: a native (`draggable`) source
/// prefers a drop zone (a node with `drop`/`dragover` listeners or `aria-dropeffect`); every
/// source then falls back to the nearest other drag source of the same tag and role, in
/// another container first (kanban columns), then in the same one (sortable lists).
#[must_use]
pub fn drag_destination(candidates: &[Candidate], i: usize) -> Option<usize> {
    let src = candidates.get(i)?;
    let native = src
        .descriptor
        .attributes
        .get("draggable")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    if native {
        if let Some(zone) = candidates.iter().position(|c| c.evidence.drop_zone) {
            return Some(zone);
        }
    }
    let centre = |c: &Candidate| {
        c.descriptor
            .bbox
            .map(|b| (b.x + b.width / 2.0, b.y + b.height / 2.0))
    };
    let (sx, sy) = centre(src)?;
    let same_family = |c: &Candidate| {
        c.evidence.draggable
            && c.descriptor.tag == src.descriptor.tag
            && c.descriptor.role.eq_ignore_ascii_case(&src.descriptor.role)
    };
    let mut best: Option<(bool, i64, usize)> = None;
    for (j, c) in candidates.iter().enumerate() {
        if j == i || !same_family(c) {
            continue;
        }
        let Some((x, y)) = centre(c) else { continue };
        let same_container = c.descriptor.container_text == src.descriptor.container_text;
        let distance = crate::utility::micros_f64((x - sx).hypot(y - sy));
        let rank = (same_container, distance, j);
        if best.is_none_or(|b| rank < b) {
            best = Some(rank);
        }
    }
    best.map(|(_, _, j)| j)
}

/// One executable idea over a current candidate: the coverage key plus how to build the action.
#[derive(Clone, PartialEq, Debug)]
pub struct KeyedAction {
    /// Coverage key of the action.
    pub key: ActionContextKey,
    /// Index into the context's `candidates`/`resolved`.
    pub candidate: usize,
    /// What the action does, without runtime handles or generated values.
    pub intent: Intent,
    /// Template group (§4.4): role ‖ stable path ‖ normalized name ‖ action kind.
    pub group: Digest,
    /// Stable-path family signature (`Z`).
    pub family: Digest,
}

/// Inputs of [`enumerate_actions`].
#[derive(Clone, Copy, Debug)]
pub struct EnumInput<'a> {
    /// Principal the keys are issued for.
    pub principal: &'a PrincipalId,
    /// Route template of the observed page.
    pub route: &'a RouteTemplate,
    /// State cluster of the observed page.
    pub cluster: StateClusterId,
    /// Safety profile that bounds which value partitions are enumerated.
    pub profile: SafetyProfile,
    /// Candidates of the observation.
    pub candidates: &'a [Candidate],
    /// Resolved identities, parallel to `candidates`.
    pub resolved: &'a [ResolvedElement],
    /// Include `Keys` chords for tab/menu items (off by default: Keys has no target).
    pub include_keys: bool,
    /// The open modal dialog, if any ([`modal_scope`]): only its controls are enumerated.
    pub modal: Option<&'a ModalScope>,
}

fn attr_lower(c: &Candidate, k: &str) -> Option<String> {
    c.descriptor
        .attributes
        .get(k)
        .map(|v| v.trim().to_ascii_lowercase())
}

/// Is the checkable control on `c` currently checked (`aria-checked` / `checked`)?
fn is_checked(c: &Candidate) -> bool {
    attr_lower(c, "aria-checked")
        .or_else(|| attr_lower(c, "checked"))
        .is_some_and(|v| v == "true" || v.is_empty() || v == "checked")
}

/// Every `(candidate, action kind, input class)` the vocabulary supports,
/// deduplicated by key (route, element identity, kind, input class), in
/// candidate order then kind order. `Drag` goes to [`drag_destination`]; `Upload`
/// and `Type` use the profile's value partitions. Under an open modal only the
/// dialog's controls are enumerated, plus an `Escape` chord when none of them
/// dismisses it (escape policy).
#[must_use]
pub fn enumerate_actions(inp: &EnumInput<'_>) -> Vec<KeyedAction> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<ActionContextId> = BTreeSet::new();
    let classifier = InputClassifier::new();
    for (i, (cand, res)) in inp.candidates.iter().zip(inp.resolved).enumerate() {
        if !cand.evidence.visible || !cand.evidence.enabled {
            continue;
        }
        if inp.modal.is_some_and(|m| !m.inside.contains(&i)) {
            continue;
        }
        let family = stable_path_sig(&res.identity);
        let mut push = |kind: ActionKind, input_class: InputClass, intent: Intent| {
            let key = ActionContextKey {
                principal: inp.principal.clone(),
                route_template: inp.route.clone(),
                element: res.hash,
                action_kind: kind,
                input_class,
                resource_context: ResourceContext::None,
                state_cluster: inp.cluster,
            };
            if !seen.insert(key.id()) {
                return;
            }
            let mut g = Vec::with_capacity(96);
            g.extend_from_slice(family.0.as_slice());
            g.push(0);
            g.extend_from_slice(res.identity.normalized_accessible_name.as_bytes());
            g.push(0);
            g.extend_from_slice(kind.as_str().as_bytes());
            out.push(KeyedAction {
                key,
                candidate: i,
                intent,
                group: Digest::of("crawlx/template-group/v1", &g),
                family,
            });
        };
        for kind in ActionVocabulary::for_candidate(cand) {
            match kind {
                ActionKind::Click => push(kind, InputClass::none(), Intent::Click),
                ActionKind::KeyboardActivate => push(kind, InputClass::none(), Intent::KeyboardActivate),
                ActionKind::Hover => push(kind, InputClass::none(), Intent::Hover),
                ActionKind::Scroll => push(kind, InputClass::none(), Intent::Scroll),
                ActionKind::Select => push(kind, InputClass::new("select", "alt"), Intent::Select),
                ActionKind::SetRange => push(kind, InputClass::new("range", "max"), Intent::SetRange),
                ActionKind::SetChecked => {
                    push(
                        kind,
                        InputClass::new("bool", "toggle"),
                        Intent::SetChecked(!is_checked(cand)),
                    );
                }
                ActionKind::Keys if inp.include_keys => {
                    push(kind, InputClass::new("keys", "enter"), Intent::Keys);
                }
                ActionKind::Type => {
                    let class = classifier.classify(&cand.descriptor);
                    for p in partitions_for(class.kind, inp.profile) {
                        if p.is_generated() {
                            push(kind, p.input_class(), Intent::Type(p));
                        }
                    }
                }
                ActionKind::Upload => {
                    for p in partitions_for(InputKind::File, inp.profile) {
                        if crawlx_forms::FixtureFiles::id_for(p).is_some() {
                            push(kind, p.input_class(), Intent::Upload(p));
                        }
                    }
                }
                ActionKind::Drag => {
                    if let Some(dest) = drag_destination(inp.candidates, i) {
                        push(kind, InputClass::none(), Intent::Drag(dest));
                    }
                }
                // Keys disabled, Navigate / tab actions are proposed by other strategies,
                // never from a single candidate.
                ActionKind::Keys
                | ActionKind::Navigate
                | ActionKind::SwitchTab
                | ActionKind::CloseTab
                | ActionKind::SolveCaptcha
                | ActionKind::SyntheticClick => {}
            }
        }
    }
    // escape policy: a modal without a close control is dismissed with `Escape`, keyed on
    // its first control (or the first candidate when it has none)
    if let Some(modal) = inp.modal.filter(|m| m.dismiss.is_empty()) {
        let anchor = modal
            .inside
            .iter()
            .next()
            .copied()
            .or_else(|| (!inp.candidates.is_empty()).then_some(0));
        if let Some(i) = anchor {
            if let (Some(res), Some(_)) = (inp.resolved.get(i), inp.candidates.get(i)) {
                let family = stable_path_sig(&res.identity);
                let key = ActionContextKey {
                    principal: inp.principal.clone(),
                    route_template: inp.route.clone(),
                    element: res.hash,
                    action_kind: ActionKind::Keys,
                    input_class: InputClass::new("keys", "escape"),
                    resource_context: ResourceContext::None,
                    state_cluster: inp.cluster,
                };
                if seen.insert(key.id()) {
                    out.push(KeyedAction {
                        key,
                        candidate: i,
                        intent: Intent::Dismiss,
                        group: Digest::of("crawlx/template-group/v1", b"keys:escape"),
                        family,
                    });
                }
            }
        }
    }
    out
}

/// Build the browser action for `ka` over `candidates[ka.candidate]`. `attempts` is the
/// key's trusted-attempt count (the ordinal of `unique_per_use` partitions). `configured` are
/// the operator's `-form-config` values: a text field whose baseline partition has one takes
/// it instead of the seeded value. Returns `None` when a value cannot be generated or the
/// candidate (or a drag destination) is out of range.
#[must_use]
pub fn build_action(
    ka: &KeyedAction,
    candidates: &[Candidate],
    bundle: &ObservationBundle,
    seed: CrawlSeed,
    attempts: u32,
    today: Timestamp,
    configured: &ConfiguredValues,
) -> Option<BrowserAction> {
    let values = ValueContext::new(today.date_naive())
        .with_attempt(attempts)
        .with_configured(configured.clone());
    build_for_intent(ka.intent, &ka.key, ka.candidate, candidates, bundle, seed, values)
}

/// The [`Intent`] a recorded coverage `key` stands for over `candidates[candidate]`: the
/// inverse of the `(kind, input class)` pairs [`enumerate_actions`] issues. Parameters the key
/// does not carry (the checked state a toggle moves to, a drag destination) are re-derived from
/// the candidates exactly as enumeration derives them. `None` when the key's parameters live
/// elsewhere (`Navigate`, tab actions, `SyntheticClick` are proposed outside the frontier) or
/// its input class is not one this build issues (a model-chosen option or chord).
#[must_use]
pub fn intent_for_key(key: &ActionContextKey, candidates: &[Candidate], candidate: usize) -> Option<Intent> {
    let cand = candidates.get(candidate)?;
    Some(match key.action_kind {
        ActionKind::Click => Intent::Click,
        ActionKind::KeyboardActivate => Intent::KeyboardActivate,
        ActionKind::Hover => Intent::Hover,
        ActionKind::Scroll => Intent::Scroll,
        ActionKind::Select if key.input_class == InputClass::new("select", "alt") => Intent::Select,
        ActionKind::SetRange => Intent::SetRange,
        ActionKind::SetChecked => Intent::SetChecked(!is_checked(cand)),
        ActionKind::Keys if key.input_class == InputClass::new("keys", "enter") => Intent::Keys,
        ActionKind::Keys if key.input_class == InputClass::new("keys", "escape") => Intent::Dismiss,
        ActionKind::Type => Intent::Type(key.input_class.0.parse().ok()?),
        ActionKind::Upload => Intent::Upload(key.input_class.0.parse().ok()?),
        ActionKind::Drag => Intent::Drag(drag_destination(candidates, candidate)?),
        ActionKind::Select
        | ActionKind::Keys
        | ActionKind::Navigate
        | ActionKind::SwitchTab
        | ActionKind::CloseTab
        | ActionKind::SolveCaptcha
        | ActionKind::SyntheticClick => return None,
    })
}

/// Rebuild the browser action a recorded `key` performed over `candidates[candidate]`, the way
/// [`build_action`] built it: same intent, same generated values (`seed`, `key`, partition at
/// ordinal 0, `configured` values), same constraints, scroll distance and option index. `today`
/// is the instant the action was proposed at. `None` when [`intent_for_key`] has no intent for
/// the key, a value cannot be generated, or the candidate (or a drag destination) is out of
/// range.
#[must_use]
pub fn rebuild_action(
    key: &ActionContextKey,
    candidate: usize,
    candidates: &[Candidate],
    bundle: &ObservationBundle,
    seed: CrawlSeed,
    today: Timestamp,
    configured: &ConfiguredValues,
) -> Option<BrowserAction> {
    let intent = intent_for_key(key, candidates, candidate)?;
    let values = ValueContext::new(today.date_naive()).with_configured(configured.clone());
    build_for_intent(intent, key, candidate, candidates, bundle, seed, values)
}

fn build_for_intent(
    intent: Intent,
    key: &ActionContextKey,
    candidate: usize,
    candidates: &[Candidate],
    bundle: &ObservationBundle,
    seed: CrawlSeed,
    values: ValueContext,
) -> Option<BrowserAction> {
    let cand = candidates.get(candidate)?;
    let target = cand.descriptor.locator.clone();
    Some(match intent {
        Intent::Click => BrowserAction::Click {
            target,
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        },
        Intent::KeyboardActivate => BrowserAction::KeyboardActivate { target },
        Intent::Hover => BrowserAction::Hover { target },
        Intent::Scroll => BrowserAction::Scroll {
            container: Some(target),
            delta: ScrollDelta {
                dx: 0.0,
                dy: f64::from(bundle.viewport.height) * 0.8,
            },
        },
        Intent::SetChecked(checked) => BrowserAction::SetChecked { target, checked },
        Intent::SetRange => {
            let max = attr_lower(cand, "max")
                .or_else(|| attr_lower(cand, "aria-valuemax"))
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(100.0);
            BrowserAction::SetRange { target, value: max }
        }
        Intent::Select => BrowserAction::Select {
            target,
            options: vec![OptionKey::Index(1)],
        },
        Intent::Keys => BrowserAction::Keys {
            sequence: vec![KeyChord {
                key: "Enter".to_owned(),
                modifiers: Modifiers::default(),
            }],
        },
        Intent::Dismiss => BrowserAction::Keys {
            sequence: vec![KeyChord {
                key: "Escape".to_owned(),
                modifiers: Modifiers::default(),
            }],
        },
        Intent::Drag(dest) => BrowserAction::Drag {
            source: target,
            destination: candidates.get(dest)?.descriptor.locator.clone(),
        },
        Intent::Type(p) => {
            let attempts = values.attempt;
            let ctx = values.with_constraints(InputConstraints::from_descriptor(&cand.descriptor));
            let value = ValuePartitions::value(seed, key, p, attempts, GENERATOR_VERSION, &ctx);
            BrowserAction::Type {
                target,
                value,
                clear_first: true,
            }
        }
        Intent::Upload(p) => BrowserAction::Upload {
            target,
            fixture: crawlx_forms::FixtureFiles::id_for(p)?,
        },
    })
}

/// The absolute http(s) URL (fragment stripped) a link candidate points at,
/// resolved against the observed page. `None` for fragment-only, `javascript:`,
/// `mailto:` and other non-navigational hrefs.
#[must_use]
pub fn resolve_href(bundle: &ObservationBundle, href: &str) -> Option<url::Url> {
    let href = href.trim();
    if href.is_empty() || href.starts_with('#') {
        return None;
    }
    let mut u = bundle.url.url.join(href).ok()?;
    if !matches!(u.scheme(), "http" | "https") {
        return None;
    }
    u.set_fragment(None);
    Some(u)
}

/// Structural facts about a candidate in the shape the safety kernel
/// classifies on (`LiveTargetFacts`), taken from the proposal-time observation.
#[must_use]
pub fn target_facts(cand: &Candidate, bundle: &ObservationBundle) -> LiveTargetFacts {
    let d = &cand.descriptor;
    let mut attributes = BTreeMap::new();
    for (k, v) in &d.attributes {
        attributes.insert(k.to_ascii_lowercase(), v.clone());
    }
    LiveTargetFacts {
        role: Some(d.role.clone()),
        name: d.accessible_name.clone().or_else(|| d.text.clone()),
        tag: d.tag.clone(),
        href: d.href.clone(),
        bbox: d.bbox.unwrap_or_default(),
        hit_points: Vec::new(),
        frame_url: None,
        current_url: bundle.url.url.to_string(),
        attributes,
        observed_form_hint: None,
    }
}

/// Form semantics keyed by public backend node id, from this observation only.
///
/// Group all structural descriptors, not just actionable candidates: native form
/// declarations are evidence, never extra frontier actions. Group each frame
/// separately so identical form ids or landmark paths cannot cross frame boundaries.
#[must_use]
pub fn observed_form_hints(bundle: &ObservationBundle) -> BTreeMap<i64, String> {
    let index = BundleIndex::new(bundle);
    let builder = crawlx_elements::descriptor::DescriptorBuilder::new(&index);
    let mut frames: BTreeMap<&str, Vec<crawlx_core::observation::ObservedDescriptor>> = BTreeMap::new();
    let ids: BTreeSet<i64> = bundle
        .dom_supplement
        .nodes
        .keys()
        .copied()
        .chain(bundle.ax.nodes.iter().map(|n| n.locator.backend_node_id.0))
        .collect();
    for id in ids {
        let dom = bundle.dom_supplement.nodes.get(&id);
        let ax = index.ax_by_backend(id);
        let native = dom.is_some_and(|d| {
            matches!(
                d.tag.as_str(),
                "form" | "input" | "select" | "textarea" | "button"
            )
        });
        let widget = ax.is_some_and(|n| {
            matches!(
                n.role.as_str(),
                "form"
                    | "button"
                    | "textbox"
                    | "searchbox"
                    | "combobox"
                    | "listbox"
                    | "checkbox"
                    | "radio"
                    | "switch"
                    | "slider"
                    | "spinbutton"
            )
        });
        if !native && !widget {
            continue;
        }
        let mut descriptor = builder.build(ax, dom, id);
        if let Some(frame) = descriptor.attributes.get("crawlx:frame") {
            descriptor.locator.frame = crawlx_core::FrameId(frame.clone());
            descriptor.frame_lineage = index.lineage(&descriptor.locator.frame);
        }
        let frame = dom
            .and_then(|d| d.attributes.get("crawlx:frame").map(String::as_str))
            .or_else(|| ax.map(|n| n.locator.frame.0.as_str()))
            .unwrap_or_default();
        frames.entry(frame).or_default().push(descriptor);
    }
    let mut hints = BTreeMap::new();
    for descriptors in frames.values() {
        for group in FormGrouper::new().group(descriptors) {
            let Some(hint) = group.form_hint() else { continue };
            for i in group
                .inputs
                .iter()
                .map(|input| input.index)
                .chain(group.form_index)
                .chain(group.submit_index)
                .chain(group.alt_submit_indices.iter().copied())
            {
                hints.insert(descriptors[i].locator.backend_node_id.0, hint.clone());
            }
        }
    }
    hints
}

/// Result of [`dedupe_groups`]: indices into the input slice.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct Deduped {
    /// Indices of the instances to explore now, ascending.
    pub sampled: Vec<usize>,
    /// Indices of the instances postponed (still distinct keys), ascending.
    pub deferred: Vec<usize>,
}

/// Template/group dedupe. For a group of `m` instances sample
/// `s = min(m, 2 + ⌈log₂ m⌉)`: the first, the last and seeded-random others;
/// the rest are `deferred` (never merged: keys stay distinct). A group for
/// which `promote` returns `true` (a sampled instance diverged) is explored in full.
#[must_use]
pub fn dedupe_groups(items: &[KeyedAction], seed: CrawlSeed, promote: &dyn Fn(&Digest) -> bool) -> Deduped {
    let mut groups: BTreeMap<Digest, Vec<usize>> = BTreeMap::new();
    for (i, it) in items.iter().enumerate() {
        groups.entry(it.group).or_default().push(i);
    }
    let mut out = Deduped::default();
    for (group, idxs) in groups {
        let m = idxs.len();
        if m <= 1 || promote(&group) {
            out.sampled.extend(idxs);
            continue;
        }
        let ceil_log2 = (usize::BITS - (m - 1).leading_zeros()) as usize;
        let s = m.min(2 + ceil_log2);
        let mut chosen: Vec<usize> = vec![idxs[0], idxs[m - 1]];
        let mut middle: Vec<usize> = idxs[1..m - 1].to_vec();
        let mut rng = seed.rng("dedupe", &[group.0.as_slice()]);
        middle.shuffle(&mut rng);
        chosen.extend(middle.iter().copied().take(s.saturating_sub(2)));
        let chosen_set: BTreeSet<usize> = chosen.iter().copied().collect();
        for i in idxs {
            if chosen_set.contains(&i) {
                out.sampled.push(i);
            } else {
                out.deferred.push(i);
            }
        }
    }
    out.sampled.sort_unstable();
    out.deferred.sort_unstable();
    out
}

/// Statistics behind the layered queue and the repetition penalty. Updated by
/// [`crate::ExplorationState`]; read through [`crate::DecisionContext::frontier`].
#[derive(Clone, Debug, Default)]
pub struct FrontierStats {
    pub(crate) cfg: QueueCfg,
    /// Configured text values (`-form-config`), applied by `DecisionContext::action_for`.
    pub(crate) form_values: ConfiguredValues,
    /// `w_key`: trusted executions per action-context key.
    pub(crate) w_key: BTreeMap<ActionContextId, u32>,
    /// `w_element`: trusted executions per element identity (paper-compatible).
    pub(crate) w_element: BTreeMap<ElementIdentityHash, u32>,
    /// `Z`: trusted interactions per stable-path family.
    pub(crate) family: BTreeMap<Digest, u32>,
    /// `R(e)`: novel-reveal episodes per element.
    pub(crate) reveal_episodes: BTreeMap<ElementIdentityHash, u32>,
    /// Revealed identities credited to an element (`per_element` variant).
    pub(crate) reveal_elements: BTreeMap<ElementIdentityHash, u32>,
    pub(crate) cooldown_until: BTreeMap<ActionContextId, u64>,
    pub(crate) interactions: u64,
    pub(crate) recent_keys: VecDeque<ActionContextId>,
    pub(crate) recent_sigs: VecDeque<Digest>,
    pub(crate) cluster_visits: BTreeMap<StateClusterId, u32>,
    /// After-clusters each key led to, with counts.
    pub(crate) key_after: BTreeMap<ActionContextId, BTreeMap<StateClusterId, u32>>,
    /// Last observed `StateDiff` novelty after executing the key.
    pub(crate) key_diff: BTreeMap<ActionContextId, f32>,
    pub(crate) visited_urls: BTreeSet<String>,
    pub(crate) routes: BTreeMap<RouteTemplate, RouteEntry>,
    pub(crate) risk: BTreeMap<ActionContextId, RiskClass>,
    pub(crate) group_outcomes: BTreeMap<Digest, BTreeSet<StateClusterId>>,
    /// Keys the kernel denied or parked for approval (excluded from `Q0`).
    pub(crate) blocked: BTreeSet<ActionContextId>,
    /// Keys the actor dropped (stale epoch, not actionable, identity changed), cooling down
    /// until the decision round in the value; strategies skip them until then.
    pub(crate) dropped_until: BTreeMap<ActionContextId, u64>,
    /// Decision round the current `DecisionContext` belongs to (`begin_round`).
    pub(crate) round: u64,
    /// Identities each `(element, action kind)`'s trusted executions revealed, in any
    /// cluster: the element-level evidence scoring and `enablement` use once an element is
    /// known (the key-level graph edges are cluster-specific).
    pub(crate) revealed_by: BTreeMap<(ElementIdentityHash, ActionKind), BTreeSet<ElementIdentityHash>>,
    /// Kernel class of each `(element, action kind)`, from its most recent key the kernel
    /// classified (any cluster).
    pub(crate) element_risk: BTreeMap<(ElementIdentityHash, ActionKind), RiskClass>,
}

impl FrontierStats {
    /// Create empty statistics under `cfg`.
    #[must_use]
    pub fn new(cfg: QueueCfg) -> Self {
        Self {
            cfg,
            ..Self::default()
        }
    }

    /// Queue constants the statistics were created with.
    #[must_use]
    pub const fn cfg(&self) -> &QueueCfg {
        &self.cfg
    }

    /// The operator's `-form-config` values typed into matching text fields
    /// ([`build_action`]); empty unless set with [`Self::with_form_values`].
    #[must_use]
    pub const fn form_values(&self) -> &ConfiguredValues {
        &self.form_values
    }

    /// Same statistics with `form_values` as the configured field values.
    #[must_use]
    pub fn with_form_values(mut self, form_values: ConfiguredValues) -> Self {
        self.form_values = form_values;
        self
    }

    /// `W(e)`: the layer (`w_key` by default, `w_element` under `paper_compat`).
    #[must_use]
    pub fn layer(&self, key: &ActionContextKey) -> u32 {
        if self.cfg.paper_compat {
            self.w_element.get(&key.element).copied().unwrap_or(0)
        } else {
            self.w_key.get(&key.id()).copied().unwrap_or(0)
        }
    }

    /// `Z(e)`: trusted interactions with the element's stable-path family.
    #[must_use]
    pub fn family_count(&self, family: &Digest) -> u32 {
        self.family.get(family).copied().unwrap_or(0)
    }

    /// `R(e)`: novel-reveal episodes of an element.
    #[must_use]
    pub fn novel_reveals(&self, element: &ElementIdentityHash) -> u32 {
        self.reveal_episodes.get(element).copied().unwrap_or(0)
    }

    /// `E(e)` (non-positive).
    #[must_use]
    pub fn enablement_bonus(&self, element: &ElementIdentityHash) -> f32 {
        let c = &self.cfg;
        let n = match c.e_variant {
            EVariant::NovelEpisode => self.novel_reveals(element).min(c.reveal_cap),
            EVariant::PerElement => self.reveal_elements.get(element).copied().unwrap_or(0),
            EVariant::Flag => u32::from(self.novel_reveals(element) > 0),
        };
        -c.reveal_bonus * n as f32
    }

    /// The paper's `Score(e) = W + 0.3·Z + E` over the key (lower is better).
    #[must_use]
    pub fn queue_score(&self, key: &ActionContextKey, family: &Digest) -> f32 {
        self.layer(key) as f32
            + self.cfg.z_weight * self.family_count(family) as f32
            + self.enablement_bonus(&key.element)
    }

    /// Is the key blacklisted after cycling (`cycle(k) = 1`)?
    #[must_use]
    pub fn in_cooldown(&self, key: &ActionContextKey) -> bool {
        self.cooldown_until
            .get(&key.id())
            .is_some_and(|until| self.interactions < *until)
    }

    /// Was the key dropped by the actor and is it still cooling down this round?
    #[must_use]
    pub fn is_dropped(&self, id: ActionContextId) -> bool {
        self.dropped_until
            .get(&id)
            .is_some_and(|until| self.round < *until)
    }

    /// Identities `kind` on `element` revealed in its trusted executions so far, in any
    /// cluster; `None` when that pair never ran on the trusted lane.
    #[must_use]
    pub fn revealed_by(
        &self,
        element: &ElementIdentityHash,
        kind: ActionKind,
    ) -> Option<&BTreeSet<ElementIdentityHash>> {
        self.revealed_by.get(&(*element, kind))
    }

    /// `(element, kind)` pairs whose trusted executions revealed `target`, in key order.
    pub fn revealers_of<'s>(
        &'s self,
        target: &'s ElementIdentityHash,
    ) -> impl Iterator<Item = (ElementIdentityHash, ActionKind)> + 's {
        self.revealed_by
            .iter()
            .filter(move |(_, revealed)| revealed.contains(target))
            .map(|(pair, _)| *pair)
    }

    /// `recent(k)`: an element with the same normalized name and stable path
    /// was exercised within the soft-block window.
    #[must_use]
    pub fn recent_contains(&self, identity: &ElementIdentityV1) -> bool {
        let sig = name_path_sig(identity);
        self.recent_sigs.contains(&sig)
    }

    /// `repetition_penalty(k) = min(1, 0.3·Z/(Z+5) + 0.5·cycle(k) + 0.2·recent(k))` (§4.3).
    #[must_use]
    pub fn repetition_penalty(&self, key: &ActionContextKey, identity: Option<&ElementIdentityV1>) -> f32 {
        let z = identity.map_or(0, |i| self.family_count(&stable_path_sig(i))) as f32;
        let cycle = f32::from(u8::from(self.in_cooldown(key)));
        let recent = identity.map_or(0.0, |i| f32::from(u8::from(self.recent_contains(i))));
        (0.3 * z / (z + 5.0) + 0.5 * cycle + 0.2 * recent).min(1.0)
    }

    /// Times an observation landed in `cluster`.
    #[must_use]
    pub fn cluster_visits(&self, cluster: StateClusterId) -> u32 {
        self.cluster_visits.get(&cluster).copied().unwrap_or(0)
    }

    /// After-clusters the key led to, with counts, in cluster-id order.
    #[must_use]
    pub fn after_clusters(&self, key: &ActionContextKey) -> Vec<(StateClusterId, u32)> {
        self.key_after
            .get(&key.id())
            .map(|m| m.iter().map(|(c, n)| (*c, *n)).collect())
            .unwrap_or_default()
    }

    /// Last `StateDiff` novelty after the key, if it ran.
    #[must_use]
    pub fn last_diff(&self, key: &ActionContextKey) -> Option<f32> {
        self.key_diff.get(&key.id()).copied()
    }

    /// Has the URL (fragment stripped) been observed?
    #[must_use]
    pub fn url_visited(&self, url: &str) -> bool {
        self.visited_urls.contains(url)
    }

    /// Known routes with the URL of their first observation.
    #[must_use]
    pub fn routes(&self) -> &BTreeMap<RouteTemplate, RouteEntry> {
        &self.routes
    }

    /// Kernel risk class last recorded for a key id (`None` = never classified).
    #[must_use]
    pub fn risk_of(&self, id: ActionContextId) -> Option<RiskClass> {
        self.risk.get(&id).copied()
    }

    /// Path-safe: only reveal, navigation and reversible UI actions the kernel has classified.
    #[must_use]
    pub fn is_path_safe(&self, id: ActionContextId) -> bool {
        matches!(
            self.risk.get(&id),
            Some(RiskClass::NavigationReveal | RiskClass::ReversibleLocalPreference)
        )
    }

    /// Path-safe at element level: the kernel's most recent class for `kind` on `element`
    /// (in any cluster) is a reveal, navigation or reversible UI class.
    #[must_use]
    pub fn is_path_safe_element(&self, element: &ElementIdentityHash, kind: ActionKind) -> bool {
        matches!(
            self.element_risk.get(&(*element, kind)),
            Some(RiskClass::NavigationReveal | RiskClass::ReversibleLocalPreference)
        )
    }

    /// Did the kernel deny the key or park it for approval?
    #[must_use]
    pub fn is_blocked(&self, id: ActionContextId) -> bool {
        self.blocked.contains(&id)
    }

    /// Can a strategy propose the key now: not kernel-blocked, not cooling down after
    /// cycling and not cooling down after a drop?
    #[must_use]
    pub fn is_proposable(&self, key: &ActionContextKey) -> bool {
        !self.is_blocked(key.id()) && !self.in_cooldown(key) && !self.is_dropped(key.id())
    }

    /// A sampled member of the group led to different after-clusters.
    #[must_use]
    pub fn group_diverged(&self, group: &Digest) -> bool {
        self.group_outcomes.get(group).is_some_and(|s| s.len() > 1)
    }

    pub(crate) fn push_recent(&mut self, key: ActionContextId, sig: Option<Digest>) {
        self.recent_keys.push_back(key);
        while self.recent_keys.len() > self.cfg.recent_window {
            self.recent_keys.pop_front();
        }
        if let Some(s) = sig {
            self.recent_sigs.push_back(s);
            while self.recent_sigs.len() > self.cfg.recent_window {
                self.recent_sigs.pop_front();
            }
        }
    }

    /// Recently executed key ids, oldest first.
    #[must_use]
    pub fn recent_keys(&self) -> &VecDeque<ActionContextId> {
        &self.recent_keys
    }

    pub(crate) fn note_trusted_execution(
        &mut self,
        key: &ActionContextKey,
        identity: Option<&ElementIdentityV1>,
        group: Option<Digest>,
        after: StateClusterId,
    ) {
        let id = key.id();
        self.interactions += 1;
        let n = self.w_key.entry(id).or_default();
        *n += 1;
        let executed = *n;
        *self.w_element.entry(key.element).or_default() += 1;
        if let Some(i) = identity {
            *self.family.entry(stable_path_sig(i)).or_default() += 1;
        }
        self.push_recent(id, identity.map(name_path_sig));
        if self.cfg.cycle_threshold > 0 && executed.is_multiple_of(self.cfg.cycle_threshold) {
            self.cooldown_until
                .insert(id, self.interactions + self.cfg.blacklist_len);
        }
        *self.key_after.entry(id).or_default().entry(after).or_default() += 1;
        if let Some(g) = group {
            self.group_outcomes.entry(g).or_default().insert(after);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{Fixture, Spec};

    #[test]
    fn enumeration_respects_the_role_vocabulary() {
        let f = Fixture::new(&[
            Spec::button("Save"),
            Spec::textbox("Email", &[("type", "email")]),
            Spec::checkbox("Remember"),
            Spec::link("Docs", "/docs"),
            Spec::button("Hidden").hidden(),
        ]);
        let acts = f.actions();
        let kinds = |name: &str| -> Vec<ActionKind> {
            let idx = f.index_of(name);
            acts.iter()
                .filter(|a| a.candidate == idx)
                .map(|a| a.key.action_kind)
                .collect()
        };
        assert_eq!(
            kinds("Save"),
            vec![ActionKind::Click, ActionKind::KeyboardActivate]
        );
        assert_eq!(kinds("Email"), vec![ActionKind::Type]);
        assert_eq!(kinds("Remember"), vec![ActionKind::SetChecked]);
        assert_eq!(
            kinds("Docs"),
            vec![ActionKind::Click, ActionKind::KeyboardActivate]
        );
        assert!(
            f.candidates
                .iter()
                .all(|c| c.descriptor.accessible_name.as_deref() != Some("Hidden")),
            "discovery drops known-hidden controls"
        );
        // and enumeration itself skips candidates whose evidence says invisible
        let mut g = Fixture::new(&[Spec::button("Save"), Spec::button("Other")]);
        let save = g.index_of("Save");
        g.candidates[save].evidence.visible = false;
        assert!(g.actions().iter().all(|a| a.candidate != save));
        assert!(!g.actions().is_empty());
        assert!(acts.iter().all(|a| a.key.action_kind != ActionKind::Navigate));
        let email = acts
            .iter()
            .find(|a| a.key.action_kind == ActionKind::Type)
            .unwrap();
        assert_eq!(email.key.input_class.0, "email:valid_new_user");
    }

    #[test]
    fn duplicate_identities_collapse_to_one_key() {
        let f = Fixture::new(&[Spec::button("Delete"), Spec::button("Delete")]);
        let acts = f.actions();
        let ids: BTreeSet<_> = acts.iter().map(|a| a.key.id()).collect();
        assert_eq!(ids.len(), acts.len());
        assert!(
            acts.iter().all(|a| a.candidate == 0),
            "the first instance represents the identity"
        );
    }

    #[test]
    fn dedupe_samples_log_many_and_is_seeded() {
        // same name/role/path, different destinations: distinct identities, one template group
        let specs: Vec<Spec> = (0..16)
            .map(|i| Spec::link("View details", &format!("/items/{}", crate::testutil::letters(i))))
            .collect();
        let f = Fixture::new(&specs);
        let acts: Vec<KeyedAction> = f
            .actions()
            .into_iter()
            .filter(|a| a.key.action_kind == ActionKind::Click)
            .collect();
        assert_eq!(acts.len(), 16);
        let d1 = dedupe_groups(&acts, CrawlSeed(1), &|_| false);
        let d1b = dedupe_groups(&acts, CrawlSeed(1), &|_| false);
        assert_eq!(d1, d1b);
        assert_eq!(d1.sampled.len(), 2 + 4, "s = min(m, 2 + ceil(log2 16))");
        assert!(
            d1.sampled.contains(&0) && d1.sampled.contains(&15),
            "first and last are always sampled"
        );
        assert_eq!(d1.sampled.len() + d1.deferred.len(), 16);
        let d2 = dedupe_groups(&acts, CrawlSeed(2), &|_| false);
        assert_eq!(d2.sampled.len(), d1.sampled.len());
        // divergence promotes the whole group
        let all = dedupe_groups(&acts, CrawlSeed(1), &|_| true);
        assert_eq!(all.sampled.len(), 16);
        assert!(all.deferred.is_empty());
    }

    #[test]
    fn queue_score_is_w_plus_z_plus_e() {
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Close")]);
        let acts = f.actions();
        let open = acts
            .iter()
            .find(|a| a.candidate == 0 && a.key.action_kind == ActionKind::Click)
            .unwrap();
        let mut stats = FrontierStats::new(QueueCfg::default());
        assert!((stats.queue_score(&open.key, &open.family) - 0.0).abs() < 1e-6);
        let ident = &f.resolved[0].identity;
        stats.note_trusted_execution(&open.key, Some(ident), Some(open.group), open.key.state_cluster);
        // W = 1, Z = 1 (shared family), E = 0
        assert!((stats.queue_score(&open.key, &open.family) - (1.0 + 0.3)).abs() < 1e-6);
        stats.reveal_episodes.insert(open.key.element, 9);
        // E capped at 5 episodes
        assert!((stats.queue_score(&open.key, &open.family) - (1.0 + 0.3 - 4.0)).abs() < 1e-5);
        stats.cfg.e_variant = EVariant::Flag;
        assert!((stats.queue_score(&open.key, &open.family) - (1.0 + 0.3 - 0.8)).abs() < 1e-5);
    }

    #[test]
    fn repetition_penalty_components() {
        let f = Fixture::new(&[Spec::button("Open")]);
        let acts = f.actions();
        let k = &acts[0];
        let mut stats = FrontierStats::new(QueueCfg::default());
        let ident = &f.resolved[0].identity;
        assert_eq!(stats.repetition_penalty(&k.key, Some(ident)), 0.0);
        stats.note_trusted_execution(&k.key, Some(ident), None, k.key.state_cluster);
        // Z = 1 -> 0.3/6 = 0.05; recent -> +0.2
        let p = stats.repetition_penalty(&k.key, Some(ident));
        assert!((p - (0.05 + 0.2)).abs() < 1e-5, "{p}");
        // third execution triggers the cycle cooldown (+0.5), capped at 1
        stats.note_trusted_execution(&k.key, Some(ident), None, k.key.state_cluster);
        stats.note_trusted_execution(&k.key, Some(ident), None, k.key.state_cluster);
        assert!(stats.in_cooldown(&k.key));
        assert!(stats.repetition_penalty(&k.key, Some(ident)) <= 1.0);
        // the cooldown lasts blacklist_len interactions
        for _ in 0..5 {
            stats.interactions += 1;
        }
        assert!(!stats.in_cooldown(&k.key));
    }

    #[test]
    fn build_action_generates_deterministic_values() {
        let f = Fixture::new(&[Spec::textbox("Email", &[("type", "email")])]);
        let acts = f.actions();
        let a = &acts[0];
        let none = ConfiguredValues::default();
        let b1 = build_action(
            a,
            &f.candidates,
            &f.bundle,
            CrawlSeed(5),
            0,
            Timestamp::default(),
            &none,
        )
        .unwrap();
        let b2 = build_action(
            a,
            &f.candidates,
            &f.bundle,
            CrawlSeed(5),
            0,
            Timestamp::default(),
            &none,
        )
        .unwrap();
        let (BrowserAction::Type { value: v1, .. }, BrowserAction::Type { value: v2, .. }) = (b1, b2) else {
            panic!("expected Type");
        };
        assert_eq!(v1.expose(), v2.expose());
        assert!(v1.expose().contains('@'));
    }

    #[test]
    fn configured_values_replace_the_baseline_values_of_matching_fields_only() {
        let f = Fixture::new(&[
            Spec::textbox("Email", &[("type", "email")]),
            Spec::textbox("Phone", &[("type", "tel")]),
            Spec::textbox("Secret", &[("type", "password")]),
            Spec::textbox("Nickname", &[("type", "text")]),
            Spec::textbox("Quantity", &[("type", "number")]),
        ]);
        let configured = ConfiguredValues {
            email: Some("fc@example.org".to_owned()),
            phone: Some("5551234".to_owned()),
            password: Some("hunter2!".to_owned()),
            placeholder: Some("Alice".to_owned()),
        };
        let typed = |configured: &ConfiguredValues| -> BTreeMap<String, (String, bool)> {
            f.actions()
                .iter()
                .filter_map(|a| {
                    let built = build_action(
                        a,
                        &f.candidates,
                        &f.bundle,
                        CrawlSeed(5),
                        0,
                        Timestamp::default(),
                        configured,
                    )?;
                    let BrowserAction::Type { value, .. } = built else {
                        return None;
                    };
                    let secret = matches!(value, crawlx_core::secret::SecretOr::Secret(_));
                    Some((f.name_of(&a.key.element), (value.expose().clone(), secret)))
                })
                .collect()
        };
        let seeded = typed(&ConfiguredValues::default());
        let replaced = typed(&configured);
        assert_eq!(replaced.len(), 5, "{replaced:?}");
        assert_eq!(replaced["Email"].0, "fc@example.org");
        assert_eq!(replaced["Phone"].0, "5551234");
        assert_eq!(
            replaced["Secret"],
            ("hunter2!".to_owned(), true),
            "a configured password stays a secret"
        );
        assert_eq!(replaced["Nickname"].0, "Alice");
        assert_eq!(
            replaced["Quantity"], seeded["Quantity"],
            "a number has no configured class"
        );
        for name in ["Email", "Phone", "Secret", "Nickname"] {
            assert_ne!(seeded[name].0, replaced[name].0, "{name}");
        }
    }

    fn names_and_kinds(f: &Fixture, acts: &[KeyedAction]) -> Vec<(String, ActionKind)> {
        acts.iter()
            .map(|a| (f.name_of(&a.key.element), a.key.action_kind))
            .collect()
    }

    #[test]
    fn an_open_modal_restricts_enumeration_to_its_controls() {
        let f = Fixture::new(&[
            Spec::button("Open"),
            Spec::button("Save").in_dialog(),
            Spec::button("Cancel").in_dialog(),
        ]);
        let modal = modal_scope(&f.bundle, &f.candidates).expect("modal is open");
        assert_eq!(modal.inside.len(), 2);
        assert_eq!(modal.dismiss.len(), 1, "Cancel dismisses the dialog");
        let acts = f.actions();
        let got = names_and_kinds(&f, &acts);
        assert!(got.iter().all(|(n, _)| n != "Open"), "{got:?}");
        assert!(got.iter().any(|(n, _)| n == "Save"), "{got:?}");
        // a close control exists: no Escape chord
        assert!(acts.iter().all(|a| a.intent != Intent::Dismiss));
    }

    #[test]
    fn a_modal_without_a_close_control_is_dismissed_with_escape() {
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Save").in_dialog()]);
        let acts = f.actions();
        let esc = acts
            .iter()
            .find(|a| a.intent == Intent::Dismiss)
            .expect("escape policy");
        assert_eq!(esc.key.action_kind, ActionKind::Keys);
        assert_eq!(esc.key.input_class, InputClass::new("keys", "escape"));
        let action = build_action(
            esc,
            &f.candidates,
            &f.bundle,
            CrawlSeed(1),
            0,
            Timestamp::default(),
            &ConfiguredValues::default(),
        )
        .unwrap();
        let BrowserAction::Keys { sequence } = action else {
            panic!("expected Keys");
        };
        assert_eq!(sequence[0].key, "Escape");
    }

    #[test]
    fn no_modal_means_no_restriction_and_no_escape() {
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Save")]);
        assert!(modal_scope(&f.bundle, &f.candidates).is_none());
        assert!(f.actions().iter().all(|a| a.intent != Intent::Dismiss));
    }

    #[test]
    fn drag_sources_get_a_destination_in_another_container_first() {
        let f = Fixture::new(&[
            Spec::card("Write spec").in_container("To do"),
            Spec::card("Review").in_container("To do"),
            Spec::card("Build").in_container("Doing"),
        ]);
        let acts = f.actions();
        let drag = acts
            .iter()
            .find(|a| a.key.action_kind == ActionKind::Drag && f.name_of(&a.key.element) == "Write spec")
            .expect("a grab-cursor card is a drag source");
        let Intent::Drag(dest) = drag.intent else {
            panic!("expected a drag intent");
        };
        assert_eq!(
            f.candidates[dest].descriptor.accessible_name.as_deref(),
            Some("Build")
        );
        let action = build_action(
            drag,
            &f.candidates,
            &f.bundle,
            CrawlSeed(1),
            0,
            Timestamp::default(),
            &ConfiguredValues::default(),
        )
        .unwrap();
        assert!(matches!(action, BrowserAction::Drag { .. }));
    }

    #[test]
    fn a_native_drag_source_prefers_a_drop_zone() {
        let f = Fixture::new(&[
            Spec::card("Draft").attr("draggable", "true"),
            Spec::card("Invoice").attr("draggable", "true"),
            Spec::drop_zone("Trash"),
        ]);
        let i = f.index_of("Draft");
        let dest = drag_destination(&f.candidates, i).unwrap();
        assert_eq!(
            f.candidates[dest].descriptor.accessible_name.as_deref(),
            Some("Trash")
        );
        // the drop zone itself is not dragged anywhere
        let zone = f.index_of("Trash");
        assert!(f
            .actions()
            .iter()
            .all(|a| !(a.candidate == zone && a.key.action_kind == ActionKind::Drag)));
    }

    #[test]
    fn target_facts_carry_href_role_and_attributes() {
        let f = Fixture::new(&[Spec::link("Docs", "/docs")]);
        let facts = target_facts(&f.candidates[0], &f.bundle);
        assert_eq!(facts.role.as_deref(), Some("link"));
        assert_eq!(facts.href.as_deref(), Some("/docs"));
        assert_eq!(facts.name.as_deref(), Some("Docs"));
        assert!(facts.current_url.starts_with("https://app.example/"));
    }

    /// Replay rebuilds an action from its recorded key alone: for every key enumeration issues,
    /// the inverse yields the same intent and the same browser action `build_action` built.
    #[test]
    fn every_enumerated_key_rebuilds_to_the_action_it_built() {
        let pages: [Vec<Spec>; 2] = [
            vec![
                Spec::button("Save"),
                Spec::textbox("Email", &[("type", "email")]),
                Spec::textbox("Avatar", &[("type", "file")]),
                Spec::checkbox("Remember"),
                Spec::widget("combobox", "Fruit", "div", &[]),
                Spec::widget("slider", "Volume", "input", &[("type", "range"), ("max", "11")]),
                Spec::widget("feed", "News", "div", &[]),
                Spec::widget("menu", "Actions", "div", &[]),
                Spec::card("Write spec").in_container("To do"),
                Spec::card("Build").in_container("Doing"),
            ],
            vec![Spec::button("Open"), Spec::button("Save").in_dialog()],
        ];
        let mut seen = BTreeSet::new();
        for specs in &pages {
            let f = Fixture::new(specs);
            for ka in f.actions() {
                assert_eq!(
                    intent_for_key(&ka.key, &f.candidates, ka.candidate),
                    Some(ka.intent),
                    "{:?}",
                    ka.key
                );
                let built = build_action(
                    &ka,
                    &f.candidates,
                    &f.bundle,
                    CrawlSeed(9),
                    0,
                    Timestamp::default(),
                    &ConfiguredValues::default(),
                )
                .unwrap();
                let rebuilt = rebuild_action(
                    &ka.key,
                    ka.candidate,
                    &f.candidates,
                    &f.bundle,
                    CrawlSeed(9),
                    Timestamp::default(),
                    &ConfiguredValues::default(),
                )
                .unwrap();
                assert_eq!(format!("{built:?}"), format!("{rebuilt:?}"), "{:?}", ka.key);
                seen.insert(ka.key.action_kind);
            }
        }
        for kind in [
            ActionKind::Click,
            ActionKind::KeyboardActivate,
            ActionKind::Hover,
            ActionKind::Scroll,
            ActionKind::Select,
            ActionKind::SetRange,
            ActionKind::SetChecked,
            ActionKind::Type,
            ActionKind::Upload,
            ActionKind::Drag,
            ActionKind::Keys,
        ] {
            assert!(seen.contains(&kind), "{kind:?} was not exercised: {seen:?}");
        }
    }

    #[test]
    fn keys_with_parameters_the_frontier_never_issues_have_no_intent() {
        let f = Fixture::new(&[Spec::widget("combobox", "Fruit", "div", &[])]);
        let mut key = f.key("Fruit", ActionKind::Select);
        assert_eq!(intent_for_key(&key, &f.candidates, 0), Some(Intent::Select));
        // a model-chosen option is not derivable from the build's own vocabulary
        key.input_class = InputClass::new("select", "option_3");
        assert_eq!(intent_for_key(&key, &f.candidates, 0), None);
        for kind in [
            ActionKind::Navigate,
            ActionKind::SwitchTab,
            ActionKind::CloseTab,
            ActionKind::SyntheticClick,
        ] {
            key.action_kind = kind;
            assert_eq!(intent_for_key(&key, &f.candidates, 0), None, "{kind:?}");
        }
        // a candidate index out of range never panics
        assert_eq!(intent_for_key(&key, &f.candidates, 7), None);
    }
}
