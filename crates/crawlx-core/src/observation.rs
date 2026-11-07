//! Observation types shared between the browser, observe, elements, state
//! and strategy crates. `RuntimeLocator` is never persisted.

use crate::epoch::ObservationEpoch;
use crate::ids::{
    ArtifactRef, AxNodeId, BackendNodeId, FrameId, NetworkEpochId, RemoteObjectId, SessionId, TabId,
};
use crate::time::Timestamp;
use crate::url::{CanonicalUrl, RouteKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Runtime handle for one node; valid for one `(navigation_seq, document_seq)`.
/// Deliberately not `Serialize`: it is never persisted, hashed or logged.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RuntimeLocator {
    /// Tab that owns the node.
    pub tab: TabId,
    /// Frame that contains the node.
    pub frame: FrameId,
    /// CDP backend node id; stable for the node's lifetime within one document.
    pub backend_node_id: BackendNodeId,
    /// CDP remote object handle for script calls; `None` when never resolved.
    pub object_id: Option<RemoteObjectId>,
    /// Accessibility node id; `None` when the node has no AX counterpart.
    pub ax_node_id: Option<AxNodeId>,
    /// Observation epoch in which this locator was captured; stale after the epoch moves on.
    pub epoch: ObservationEpoch,
}

/// Bounding box in CSS pixels relative to the main-frame viewport.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct BoundingBox {
    /// Left edge in CSS pixels, relative to the main-frame viewport origin.
    pub x: f64,
    /// Top edge in CSS pixels, relative to the main-frame viewport origin.
    pub y: f64,
    /// Width in CSS pixels; zero or negative means no visible area.
    pub width: f64,
    /// Height in CSS pixels; zero or negative means no visible area.
    pub height: f64,
}

impl BoundingBox {
    /// Visible area in square CSS pixels; negative extents count as zero.
    #[must_use]
    pub fn area(&self) -> f64 {
        self.width.max(0.0) * self.height.max(0.0)
    }
    /// Midpoint `(x, y)` of the box in CSS pixels.
    #[must_use]
    pub fn center(&self) -> (f64, f64) {
        (self.x + self.width / 2.0, self.y + self.height / 2.0)
    }
}

/// Viewport size.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Viewport {
    /// Viewport width in CSS pixels.
    pub width: u32,
    /// Viewport height in CSS pixels.
    pub height: u32,
}

impl Default for Viewport {
    fn default() -> Self {
        Self {
            width: 1280,
            height: 800,
        }
    }
}

/// One frame in the tab.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FrameInfo {
    /// Frame id, unique within the tab.
    pub id: FrameId,
    /// Parent frame; `None` for the main frame.
    pub parent: Option<FrameId>,
    /// Document URL of the frame as reported by the browser, uncanonicalized.
    pub url: String,
    /// `true` when the frame shares its origin with the main frame.
    pub same_origin: bool,
    /// Digest-based lineage used by `ElementIdentityV1.frame_lineage`.
    pub lineage: Vec<String>,
}

/// One accessibility node as observed.
#[derive(Clone, PartialEq, Debug)]
pub struct AxNode {
    /// Runtime handle for the node; valid only within its observation epoch.
    pub locator: RuntimeLocator,
    /// ARIA role of the node as the browser computes it.
    pub role: String,
    /// Computed accessible name; `None` when the node has no name.
    pub name: Option<String>,
    /// Computed accessible description; `None` when absent.
    pub description: Option<String>,
    /// Current accessible value (inputs, sliders); `None` when the node has no value.
    pub value: Option<String>,
    /// `true` when the browser marks the node as ignored for assistive technology.
    pub ignored: bool,
    /// `true` when the node can receive keyboard focus.
    pub focusable: bool,
    /// `true` when the node is disabled and cannot be activated.
    pub disabled: bool,
    /// `aria-expanded` state; `None` when the node is not expandable.
    pub expanded: Option<bool>,
    /// Checked state as the browser reports it (`"true"`, `"false"`, `"mixed"`); `None` when not checkable.
    pub checked: Option<String>,
    /// Remaining AX properties as name → value strings, in sorted key order.
    pub properties: BTreeMap<String, String>,
    /// Parent AX node; `None` for a root.
    pub parent: Option<AxNodeId>,
    /// Child AX nodes in document order.
    pub children: Vec<AxNodeId>,
    /// Bounding box in CSS pixels; `None` when the node has no layout box.
    pub bbox: Option<BoundingBox>,
}

/// Accessibility snapshot (all frames, pre-order).
#[derive(Clone, PartialEq, Debug, Default)]
pub struct AxSnapshot {
    /// Accessibility nodes of every frame in pre-order.
    pub nodes: Vec<AxNode>,
}

/// DOM evidence gathered for escalated nodes only.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct DomNodeSupplement {
    /// Lower-case HTML tag name.
    pub tag: String,
    /// HTML attributes as name → value pairs in sorted key order.
    pub attributes: BTreeMap<String, String>,
    /// Computed CSS `cursor` value; `None` when not read.
    pub cursor: Option<String>,
    /// Names of event listeners attached to the node (e.g. `"click"`).
    pub listeners: Vec<String>,
    /// Visible text content; `None` when the node has none.
    pub text: Option<String>,
    /// Bounding box in CSS pixels; `None` when the node has no layout box.
    pub bbox: Option<BoundingBox>,
    /// `true` when the node lives inside a shadow root.
    pub in_shadow_root: bool,
    /// `true` when that shadow root is closed (not reachable through script).
    pub shadow_root_closed: bool,
}

/// Supplement keyed by backend node id.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct DomSupplement {
    /// Supplements keyed by CDP backend node id.
    pub nodes: BTreeMap<i64, DomNodeSupplement>,
    /// Backend node ids of generic elements found by targeted listener inspection.
    pub listener_candidates: Vec<BackendNodeId>,
}

/// Mutation counts since the previous bundle, from the isolated-world observer.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct MutationStats {
    /// Number of mutation records observed.
    pub records: u64,
    /// Number of nodes added to the DOM.
    pub added_nodes: u64,
    /// Number of nodes removed from the DOM.
    pub removed_nodes: u64,
    /// Number of attribute changes.
    pub attribute_changes: u64,
    /// Number of text (character-data) changes.
    pub text_changes: u64,
    /// Share of mutations in regions already masked as volatile (0..=1000).
    pub volatile_permille: u16,
}

/// Network activity during an epoch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct NetworkEpochSummary {
    /// Id of the network epoch this summary covers; `None` when no epoch was open.
    pub epoch_id: Option<NetworkEpochId>,
    /// Requests started during the epoch.
    pub requests: u32,
    /// Requests still in flight at capture time, excluding long-lived ones.
    pub in_flight_at_capture: u32,
    /// URLs of long-lived requests (streams, long polls) excluded from the idle check.
    pub long_lived: Vec<String>,
    /// Requests that finished after their network epoch had already closed.
    pub late: u32,
    /// Distinct `(method, route template)` pairs.
    pub operations: Vec<String>,
}

/// Result of waiting for quiescence (`QuiescencePolicy`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct SettleReport {
    /// Milliseconds the settle wait lasted before it returned.
    pub waited_ms: u64,
    /// `true` when no blocking network requests remained in flight for the idle window.
    pub network_idle: bool,
    /// `true` when no DOM mutations occurred for the idle window.
    pub mutation_idle: bool,
    /// `true` when any triggered navigation had finished loading.
    pub navigation_settled: bool,
    /// `true` when the hard timeout ended the wait before the page went idle.
    pub settle_timeout: bool,
    /// Whether the caller's postcondition held after settling; `None` when none was checked.
    pub postcondition: Option<bool>,
    /// Number of DOM mutation targets the mutation-idle criterion ignored as volatile
    /// (periodic tickers, `aria-live` regions) while waiting.
    #[serde(default)]
    pub excluded_volatile_targets: u32,
}

/// Quiescence policy with its default settings.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct QuiescencePolicy {
    /// Milliseconds without blocking network activity that count as network-idle.
    pub network_idle_window_ms: u64,
    /// Milliseconds without DOM mutations that count as mutation-idle.
    pub mutation_idle_window_ms: u64,
    /// Whether to also wait for an in-progress navigation to finish.
    pub navigation_settled: bool,
    /// Hard upper bound in milliseconds for the idle wait (after `fixed_wait_ms`).
    pub hard_timeout_ms: u64,
    /// Unconditional wait in milliseconds before the idle criteria are evaluated
    /// (`dynamic.pageLoadStrategy: domcontentloaded` → `dynamic.domWaitMs`); `0` for the
    /// heuristic presets. Counted in `SettleReport::waited_ms`.
    #[serde(default)]
    pub fixed_wait_ms: u64,
}

impl Default for QuiescencePolicy {
    fn default() -> Self {
        Self {
            network_idle_window_ms: 500,
            mutation_idle_window_ms: 300,
            navigation_settled: true,
            hard_timeout_ms: 8_000,
            fixed_wait_ms: 0,
        }
    }
}

impl QuiescencePolicy {
    /// The policy behind `dynamic.pageLoadStrategy`: `heuristic` is the
    /// Default; `load` waits for the navigation only (no idle windows);
    /// `domcontentloaded` waits for the navigation plus a fixed `dom_wait_ms`
    /// (`dynamic.domWaitMs`); `networkidle` waits for the network window only; `none`
    /// waits for nothing.
    #[must_use]
    pub fn preset(strategy: crate::config::PageLoadStrategy, dom_wait_ms: u64) -> Self {
        use crate::config::PageLoadStrategy as S;
        let base = Self::default();
        match strategy {
            S::Heuristic => base,
            S::Load => Self {
                network_idle_window_ms: 0,
                mutation_idle_window_ms: 0,
                navigation_settled: true,
                ..base
            },
            S::DomContentLoaded => Self {
                network_idle_window_ms: 0,
                mutation_idle_window_ms: 0,
                navigation_settled: true,
                fixed_wait_ms: dom_wait_ms,
                ..base
            },
            S::NetworkIdle => Self {
                mutation_idle_window_ms: 0,
                navigation_settled: false,
                ..base
            },
            S::None => Self {
                network_idle_window_ms: 0,
                mutation_idle_window_ms: 0,
                navigation_settled: false,
                hard_timeout_ms: 0,
                fixed_wait_ms: 0,
            },
        }
    }

    /// [`Self::preset`] for the request's `dynamic` block, with `dynamic.timeStableMs`
    /// applied through [`Self::with_time_stable`].
    #[must_use]
    pub fn for_dynamic(dynamic: &crate::config::Dynamic) -> Self {
        Self::preset(dynamic.page_load_strategy, u64::from(dynamic.dom_wait_ms))
            .with_time_stable(u64::from(dynamic.time_stable_ms))
    }

    /// Require the page to stay quiet for `stable_ms` before it counts as settled (katana
    /// `-time-stable`, `dynamic.timeStableMs`): both idle windows become at least `stable_ms` and
    /// the hard timeout at least twice that, so the window can elapse (katana caps the stable
    /// time at half of the timeout). `0` keeps `self` unchanged; an explicit request overrides a
    /// preset that waits for nothing.
    #[must_use]
    pub const fn with_time_stable(self, stable_ms: u64) -> Self {
        if stable_ms == 0 {
            return self;
        }
        let doubled = stable_ms.saturating_mul(2);
        Self {
            network_idle_window_ms: max_u64(self.network_idle_window_ms, stable_ms),
            mutation_idle_window_ms: max_u64(self.mutation_idle_window_ms, stable_ms),
            hard_timeout_ms: max_u64(self.hard_timeout_ms, doubled),
            ..self
        }
    }

    /// `true` when the policy waits for nothing at all (`none`).
    #[must_use]
    pub const fn is_no_wait(&self) -> bool {
        self.hard_timeout_ms == 0 && self.fixed_wait_ms == 0
    }
}

const fn max_u64(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

/// How a [`DomSelector`] expression is interpreted (the recorded-flow selector vocabulary of
/// `crawlx_forms::SelectorKind` is the forms-side twin).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DomSelectorKind {
    /// A CSS selector.
    Css,
    /// An XPath expression.
    XPath,
    /// An accessible name, matched against the AX tree (`aria/Name` in Recorder exports; an
    /// optional `[role="x"]` suffix narrows the role).
    Aria,
    /// Visible text contained in an element (`text/Some text` in Recorder exports).
    Text,
}

/// A control reference a browser context resolves into a [`RuntimeLocator`]
/// ([`crate::BrowserContext::resolve_selector`]).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct DomSelector {
    /// How `expr` is interpreted.
    pub kind: DomSelectorKind,
    /// The selector expression without its kind prefix.
    pub expr: String,
}

impl DomSelector {
    /// A CSS selector.
    #[must_use]
    pub fn css(expr: impl Into<String>) -> Self {
        Self {
            kind: DomSelectorKind::Css,
            expr: expr.into(),
        }
    }
}

/// A dialog that appeared during the epoch.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct DialogEvent {
    /// Dialog type as reported by CDP (`"alert"`, `"confirm"`, `"prompt"`, `"beforeunload"`).
    pub kind: String,
    /// Message text the page showed in the dialog.
    pub message: String,
    /// `true` when the browser layer already accepted or dismissed the dialog.
    pub handled: bool,
}

/// A tab in the session's bounded tab graph.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TabInfo {
    /// Tab id, unique within the session.
    pub id: TabId,
    /// Current URL of the tab, uncanonicalized.
    pub url: String,
    /// Tab that opened this one; `None` for tabs not opened by another tab.
    pub opener: Option<TabId>,
    /// `true` for the tab the session currently drives.
    pub active: bool,
    /// Awaiting admission because the attached-tab budget is full.
    pub pending: bool,
    /// A download was recorded for this window; close it rather than explore it.
    pub download: bool,
}

/// All evidence seen for one candidate element in one observation.
/// Identity resolution consumes this; it is never a persistent key itself.
#[derive(Clone, PartialEq, Debug)]
pub struct ObservedDescriptor {
    /// Runtime handle for the candidate node.
    pub locator: RuntimeLocator,
    /// ARIA role of the node as the browser computes it.
    pub role: String,
    /// Computed accessible name; `None` when absent.
    pub accessible_name: Option<String>,
    /// Computed accessible description; `None` when absent.
    pub description: Option<String>,
    /// Lower-case HTML tag name; `None` when no DOM evidence was gathered.
    pub tag: Option<String>,
    /// HTML attributes as name → value pairs in sorted key order.
    pub attributes: BTreeMap<String, String>,
    /// Visible text of the node; `None` when empty or not gathered.
    pub text: Option<String>,
    /// `href` attribute as written; `None` when the node has none.
    pub href: Option<String>,
    /// Bounding box in CSS pixels; `None` when the node has no layout box.
    pub bbox: Option<BoundingBox>,
    /// Digests of the enclosing frames' identities, outermost first (empty for the main frame).
    pub frame_lineage: Vec<String>,
    /// Ancestor roles, outermost first, unfiltered.
    pub ancestor_roles: Vec<String>,
    /// Text of the enclosing container (e.g. a row or card); `None` when there is none.
    pub container_text: Option<String>,
    /// `true` when the node can receive keyboard focus.
    pub focusable: bool,
    /// `true` when the node is disabled.
    pub disabled: bool,
    /// `true` when the node is rendered and visible.
    pub visible: bool,
    /// Names of event listeners attached to the node (e.g. `"click"`).
    pub listeners: Vec<String>,
    /// Computed CSS `cursor` value; `None` when not read.
    pub cursor: Option<String>,
    /// `true` when the node sits inside a closed shadow root.
    pub in_closed_shadow_root: bool,
    /// Index among siblings sharing the same container template (not part of identity).
    pub instance_ordinal: u32,
}

/// What an observation cost.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct ObservationCost {
    /// Number of CDP calls the observation issued.
    pub cdp_calls: u32,
    /// Bytes captured (HTML plus raw artifacts).
    pub bytes: u64,
    /// Wall-clock milliseconds the observation took.
    pub wall_ms: u64,
}

/// What to capture.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ObservationSpec {
    /// Capture the accessibility tree.
    pub ax: bool,
    /// Gather DOM evidence for escalated nodes.
    pub dom_supplement: bool,
    /// Capture a full DOM snapshot as a raw artifact.
    pub dom_snapshot: bool,
    /// Capture a screenshot as a raw artifact.
    pub screenshot: bool,
    /// Capture fresh structure without consuming ordinary observation buffers or baselines.
    /// Used only by the actor's final safety revalidation; never published as a decision round.
    #[serde(default)]
    pub revalidation_only: bool,
}

impl Default for ObservationSpec {
    fn default() -> Self {
        Self {
            ax: true,
            dom_supplement: true,
            dom_snapshot: false,
            screenshot: false,
            revalidation_only: false,
        }
    }
}

/// The immutable product of one observation.
#[derive(Clone, PartialEq, Debug)]
pub struct ObservationBundle {
    /// Session the observation belongs to.
    pub session_id: SessionId,
    /// Per-session observation sequence number.
    pub seq: u64,
    /// Observation epoch this bundle was captured in.
    pub epoch: ObservationEpoch,
    /// Time of capture.
    pub captured_at: Timestamp,
    /// Tab that was observed.
    pub tab: TabId,
    /// Canonical URL of the main document.
    pub url: CanonicalUrl,
    /// Route (origin, template, query schema) derived from `url`.
    pub route: RouteKey,
    /// Viewport size at capture time.
    pub viewport: Viewport,
    /// All frames of the tab, main frame first.
    pub frames: Vec<FrameInfo>,
    /// Accessibility snapshot across all frames.
    pub ax: AxSnapshot,
    /// DOM evidence for escalated nodes only.
    pub dom_supplement: DomSupplement,
    /// Stored DOM snapshot; `None` when the spec did not ask for one or it is not yet stored.
    pub dom_snapshot: Option<ArtifactRef>,
    /// Mutation counts since the previous bundle.
    pub mutation: MutationStats,
    /// Network activity of the current network epoch.
    pub network: NetworkEpochSummary,
    /// Stored screenshot; `None` when the spec did not ask for one or it is not yet stored.
    pub screenshot: Option<ArtifactRef>,
    /// Result of the last settle wait; `None` when no settle ran before capture.
    pub settle: Option<SettleReport>,
    /// Dialogs that appeared during the epoch.
    pub dialogs: Vec<DialogEvent>,
    /// Tabs open in the session at capture time.
    pub tabs: Vec<TabInfo>,
    /// Cost of producing this bundle.
    pub cost: ObservationCost,
    /// Raw HTML of the main document when captured (static-plane parity, extraction).
    pub html: Option<String>,
    /// Document title; `None` when the page has none.
    pub title: Option<String>,
    /// Blobs captured while observing (`"dom_snapshot"`, `"screenshot"`), keyed by
    /// artifact kind, for the caller to put in the object store and reference through
    /// `dom_snapshot` / `screenshot`. Empty unless the spec asked for them.
    pub raw_artifacts: Vec<(String, Vec<u8>)>,
    /// URLs the page-hooks discovery sink captured since the previous observation, as
    /// `(url, source)` with `source` one of `history.pushState`, `history.replaceState`,
    /// `window.open`, `hashchange`, `websocket`, `eventsource`, `fetch`, `xhr`.
    /// Empty unless `ContextConfig::page_hooks` is on. The URL is as the
    /// page passed it, not canonicalized.
    pub discovered_urls: Vec<(String, String)>,
}

impl ObservationBundle {
    /// An empty bundle (no AX nodes, no frames, default epoch, `captured_at` at the
    /// Unix epoch) for `url`; the constructor tests and replay harnesses start from.
    #[must_use]
    pub fn empty(session_id: SessionId, tab: TabId, url: CanonicalUrl) -> Self {
        let route = url.route_key();
        Self {
            session_id,
            seq: 0,
            epoch: ObservationEpoch::default(),
            captured_at: Timestamp::default(),
            tab,
            url,
            route,
            viewport: Viewport::default(),
            frames: Vec::new(),
            ax: AxSnapshot::default(),
            dom_supplement: DomSupplement::default(),
            dom_snapshot: None,
            mutation: MutationStats::default(),
            network: NetworkEpochSummary::default(),
            screenshot: None,
            settle: None,
            dialogs: Vec::new(),
            tabs: Vec::new(),
            cost: ObservationCost::default(),
            html: None,
            title: None,
            raw_artifacts: Vec::new(),
            discovered_urls: Vec::new(),
        }
    }

    /// The captured blob for artifact `kind` (`"dom_snapshot"`, `"screenshot"`), if any.
    #[must_use]
    pub fn raw_artifact(&self, kind: &str) -> Option<&[u8]> {
        self.raw_artifacts
            .iter()
            .find(|(k, _)| k == kind)
            .map(|(_, bytes)| bytes.as_slice())
    }

    /// Attach a captured blob for artifact `kind`, replacing any earlier one.
    #[must_use]
    pub fn with_raw_artifact(mut self, kind: impl Into<String>, bytes: Vec<u8>) -> Self {
        let kind = kind.into();
        self.raw_artifacts.retain(|(k, _)| *k != kind);
        self.raw_artifacts.push((kind, bytes));
        self
    }
}

/// Persisted form of everything [`StateSignature`](crate::state::StateSignature) is
/// computed from.
/// Stored as the `ax_tree` state artifact. Runtime handles are replaced by node
/// indices: `parent`/`children` index into `nodes`, and `supplement` is keyed by the
/// same index, so no `RuntimeLocator` ever reaches the object store.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct FingerprintInput {
    /// Record format version ([`Self::VERSION`]).
    pub version: u16,
    /// Canonical URL of the main document; the route key is derived from it.
    pub url: CanonicalUrl,
    /// Observation epoch the bundle was captured in.
    pub epoch: ObservationEpoch,
    /// Document title.
    pub title: Option<String>,
    /// Frame document URLs, main frame first (only the URL enters the signature).
    pub frame_urls: Vec<String>,
    /// Accessibility nodes in snapshot order.
    pub nodes: Vec<FingerprintNode>,
    /// DOM supplement per node index (escalated nodes only).
    pub supplement: BTreeMap<u32, DomNodeSupplement>,
    /// Network operations (`METHOD /route/:template`) of the bundle's epoch, sorted.
    pub network_operations: Vec<String>,
}

/// One accessibility node of a [`FingerprintInput`]: [`AxNode`] without its runtime
/// locator, with index-based tree links.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct FingerprintNode {
    /// ARIA role as the browser computed it.
    pub role: String,
    /// Computed accessible name.
    pub name: Option<String>,
    /// Computed accessible description.
    pub description: Option<String>,
    /// Current accessible value.
    pub value: Option<String>,
    /// Ignored for assistive technology.
    pub ignored: bool,
    /// Can receive keyboard focus.
    pub focusable: bool,
    /// Disabled.
    pub disabled: bool,
    /// `aria-expanded` state.
    pub expanded: Option<bool>,
    /// Checked state (`"true"`, `"false"`, `"mixed"`).
    pub checked: Option<String>,
    /// Remaining AX properties in sorted key order.
    pub properties: BTreeMap<String, String>,
    /// Index of the parent node in `nodes`; `None` for a root.
    pub parent: Option<u32>,
    /// Indices of the child nodes in document order.
    pub children: Vec<u32>,
    /// Bounding box in CSS pixels.
    pub bbox: Option<BoundingBox>,
}

impl FingerprintInput {
    /// Current record format version.
    pub const VERSION: u16 = 1;

    /// Capture the signature inputs of `bundle`. Nodes whose AX id cannot be resolved
    /// to an index keep no parent (the tree builder re-roots them the same way).
    #[must_use]
    pub fn from_bundle(bundle: &ObservationBundle) -> Self {
        let nodes = &bundle.ax.nodes;
        let index_of = |id: &AxNodeId| -> Option<u32> {
            nodes
                .iter()
                .position(|n| n.locator.ax_node_id.as_ref() == Some(id))
                .and_then(|i| u32::try_from(i).ok())
        };
        let mut supplement = BTreeMap::new();
        // true when `id` or any ancestor (bounded walk) is an editable control
        let under_editable = |start: Option<&AxNodeId>| -> bool {
            let mut id: Option<&AxNodeId> = start;
            for _ in 0..64 {
                let Some(cur) = id else { return false };
                let Some(node) = nodes.iter().find(|n| n.locator.ax_node_id.as_ref() == Some(cur)) else {
                    return false;
                };
                if is_editable_role(&node.role) {
                    return true;
                }
                id = node.parent.as_ref();
            }
            false
        };
        let out_nodes = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| {
                if let (Ok(i), Some(s)) = (
                    u32::try_from(i),
                    bundle.dom_supplement.nodes.get(&n.locator.backend_node_id.0),
                ) {
                    // Snapshot ancestor text can include scripts, credentials and profile data.
                    // Fingerprinting reads the AX name and listener evidence, never this text.
                    supplement.insert(
                        i,
                        DomNodeSupplement {
                            tag: s.tag.clone(),
                            attributes: s.attributes.clone(),
                            cursor: s.cursor.clone(),
                            listeners: s.listeners.clone(),
                            text: None,
                            bbox: s.bbox,
                            in_shadow_root: s.in_shadow_root,
                            shadow_root_closed: s.shadow_root_closed,
                        },
                    );
                }
                FingerprintNode {
                    role: n.role.clone(),
                    // the browser also exposes typed text as the StaticText child of the control
                    name: if matches!(n.role.as_str(), "StaticText" | "InlineTextBox")
                        && under_editable(n.parent.as_ref())
                    {
                        None
                    } else {
                        n.name.clone()
                    },
                    description: n.description.clone(),
                    // The value of an editable control is
                    // what was typed into it (a credential, a session token) and never enters
                    // the object store; the signature does not read it.
                    value: if is_editable_role(&n.role) {
                        None
                    } else {
                        n.value.clone()
                    },
                    ignored: n.ignored,
                    focusable: n.focusable,
                    disabled: n.disabled,
                    expanded: n.expanded,
                    checked: n.checked.clone(),
                    properties: n.properties.clone(),
                    parent: n.parent.as_ref().and_then(index_of),
                    children: n.children.iter().filter_map(index_of).collect(),
                    bbox: n.bbox,
                }
            })
            .collect();
        Self {
            version: Self::VERSION,
            url: bundle.url.clone(),
            epoch: bundle.epoch,
            title: bundle.title.clone(),
            frame_urls: bundle.frames.iter().map(|f| f.url.clone()).collect(),
            nodes: out_nodes,
            supplement,
            network_operations: bundle.network.operations.clone(),
        }
    }

    /// Rebuild a bundle that fingerprints identically to the one this record was
    /// taken from. Locators are synthetic (`backend_node_id` = node index, AX id =
    /// decimal index); frames carry only their URL.
    #[must_use]
    pub fn to_bundle(&self) -> ObservationBundle {
        let tab = TabId("fingerprint-input".to_owned());
        let frame = FrameId("main".to_owned());
        let mut bundle =
            ObservationBundle::empty(SessionId(uuid::Uuid::nil()), tab.clone(), self.url.clone());
        bundle.epoch = self.epoch;
        bundle.title.clone_from(&self.title);
        bundle.network.operations.clone_from(&self.network_operations);
        bundle.frames = self
            .frame_urls
            .iter()
            .enumerate()
            .map(|(i, url)| FrameInfo {
                id: FrameId(i.to_string()),
                parent: (i > 0).then(|| FrameId("0".to_owned())),
                url: url.clone(),
                same_origin: true,
                lineage: Vec::new(),
            })
            .collect();
        bundle.ax.nodes = self
            .nodes
            .iter()
            .enumerate()
            .map(|(i, n)| AxNode {
                locator: RuntimeLocator {
                    tab: tab.clone(),
                    frame: frame.clone(),
                    backend_node_id: BackendNodeId(i64::try_from(i).unwrap_or(i64::MAX)),
                    object_id: None,
                    ax_node_id: Some(AxNodeId(i.to_string())),
                    epoch: self.epoch,
                },
                role: n.role.clone(),
                name: n.name.clone(),
                description: n.description.clone(),
                value: n.value.clone(),
                ignored: n.ignored,
                focusable: n.focusable,
                disabled: n.disabled,
                expanded: n.expanded,
                checked: n.checked.clone(),
                properties: n.properties.clone(),
                parent: n.parent.map(|p| AxNodeId(p.to_string())),
                children: n.children.iter().map(|c| AxNodeId(c.to_string())).collect(),
                bbox: n.bbox,
            })
            .collect();
        bundle.dom_supplement.nodes = self
            .supplement
            .iter()
            .map(|(i, s)| (i64::from(*i), s.clone()))
            .collect();
        bundle
    }
}

/// AX roles whose `value` is user-typed text (dropped from stored snapshots).
#[must_use]
pub fn is_editable_role(role: &str) -> bool {
    matches!(
        role.to_ascii_lowercase().as_str(),
        "textbox" | "searchbox" | "combobox" | "spinbutton" | "textarea" | "input"
    )
}

/// Result of `BrowserContext::revalidate`.
// Actionable is the common hot-path result. Keep its owned evidence inline rather
// than adding a heap allocation to every successful target revalidation.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Debug)]
pub enum Revalidation {
    /// The target is present and ready; `live` holds the facts seen just now.
    Actionable {
        /// Facts observed on the live target.
        live: LiveTargetFacts,
    },
    /// The node is no longer attached to the document.
    Detached,
    /// The node exists but no longer matches its recorded identity.
    IdentityChanged,
    /// The node has no visible area or is hidden.
    NotVisible,
    /// The node is disabled.
    Disabled,
    /// Another element covers the node's hit points.
    Obscured {
        /// Backend node id of the covering element; `None` when it cannot be resolved.
        by_backend_node_id: Option<BackendNodeId>,
    },
    /// The node's position or state kept changing, so no stable target was found.
    Unstable,
    /// The locator's observation epoch is no longer current.
    StaleEpoch {
        /// Epoch that is current now.
        current: ObservationEpoch,
    },
}

/// Facts observed at revalidation time; the kernel re-confirms against these.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct LiveTargetFacts {
    /// ARIA role; `None` when the node has none.
    pub role: Option<String>,
    /// Accessible name; `None` when absent.
    pub name: Option<String>,
    /// Lower-case HTML tag name; `None` when unknown.
    pub tag: Option<String>,
    /// `href` attribute as written; `None` when the node has none.
    pub href: Option<String>,
    /// Bounding box in CSS pixels at revalidation time.
    pub bbox: BoundingBox,
    /// Candidate click points `(x, y)` in CSS pixels inside the box, most central first.
    pub hit_points: Vec<(f64, f64)>,
    /// URL of the containing frame; `None` for the main frame.
    pub frame_url: Option<String>,
    /// URL of the tab at revalidation time, uncanonicalized.
    pub current_url: String,
    /// Structural attributes the safety kernel classifies on (lower-case keys):
    /// `aria-expanded`, `aria-haspopup`, `aria-pressed`, `type` (input type),
    /// `form-method`, `form-action`, `confirm-dialog` (`true`), `observed-methods`
    /// (comma-separated HTTP methods seen for this action context). Revalidation
    /// MUST fill the same keys the proposal-time observation did.
    #[serde(default)]
    pub attributes: std::collections::BTreeMap<String, String>,
    /// Enclosing form semantics derived from structural observation and form grouping.
    /// Rebuilt for each target observation; never copied from proposal or model text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_form_hint: Option<String>,
}

/// Receipt returned by `BrowserContext::perform`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ActionReceipt {
    /// Network epoch opened for the action; traffic during it belongs to the action.
    pub network_epoch: NetworkEpochId,
    /// Fidelity with which the action ran.
    pub fidelity: crate::traffic::Fidelity,
    /// Trust lane the action ran in.
    pub lane: crate::traffic::TrustLane,
    /// Time the action started.
    pub started_at: Timestamp,
    /// Time the action finished.
    pub finished_at: Timestamp,
}

/// Result of a navigation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct NavigationResult {
    /// URL the navigation ended on after redirects, uncanonicalized.
    pub final_url: String,
    /// HTTP status of the final document; `None` when none was observed.
    pub status: Option<u16>,
    /// Epoch the page is in after navigating.
    pub epoch: ObservationEpoch,
    /// Network epoch opened for the navigation.
    pub network_epoch: NetworkEpochId,
    /// URLs passed through during redirects, in order.
    pub redirects: Vec<String>,
    /// URLs the egress policy blocked during the navigation.
    pub blocked_by_egress: Vec<String>,
}

/// Browser build recorded on every session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct BrowserBuildInfo {
    /// Chromium version string of the running browser.
    pub chromium_version: String,
    /// CDP protocol revision in use.
    pub cdp_revision: String,
    /// User-Agent string the browser sends.
    pub user_agent: String,
    /// `true` when the running build matches the pinned Chromium version.
    pub pinned: bool,
    /// Launch profile the browser started with.
    pub launch_profile: crate::config::LaunchProfile,
    /// `true` when console messages are captured.
    pub console_capture: bool,
    /// `true` when the backend attached to a browser it did not launch
    /// (`LaunchConfig::cdp_ws_url`); such a session is never `pinned`.
    #[serde(default)]
    pub attached: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::QuiescencePolicy;
    use crate::config::{Dynamic, PageLoadStrategy};

    #[test]
    fn page_load_strategy_presets_table() {
        // (strategy, net window, mutation window, navigation settled, hard timeout, fixed wait)
        let table = [
            (PageLoadStrategy::Heuristic, 500, 300, true, 8_000, 0),
            (PageLoadStrategy::Load, 0, 0, true, 8_000, 0),
            (PageLoadStrategy::DomContentLoaded, 0, 0, true, 8_000, 5_000),
            (PageLoadStrategy::NetworkIdle, 500, 0, false, 8_000, 0),
            (PageLoadStrategy::None, 0, 0, false, 0, 0),
        ];
        for (strategy, net, mutation, nav, hard, fixed) in table {
            let p = QuiescencePolicy::preset(strategy, 5_000);
            assert_eq!(p.network_idle_window_ms, net, "{strategy:?}");
            assert_eq!(p.mutation_idle_window_ms, mutation, "{strategy:?}");
            assert_eq!(p.navigation_settled, nav, "{strategy:?}");
            assert_eq!(p.hard_timeout_ms, hard, "{strategy:?}");
            assert_eq!(p.fixed_wait_ms, fixed, "{strategy:?}");
            assert_eq!(p.is_no_wait(), strategy == PageLoadStrategy::None);
        }
        assert_eq!(
            QuiescencePolicy::preset(PageLoadStrategy::Heuristic, 5_000),
            QuiescencePolicy::default()
        );
        assert_eq!(
            QuiescencePolicy::preset(PageLoadStrategy::DomContentLoaded, 250).fixed_wait_ms,
            250
        );
        let d = Dynamic::default();
        assert_eq!(QuiescencePolicy::for_dynamic(&d), QuiescencePolicy::default());
        let legacy: QuiescencePolicy = serde_json::from_str(
            r#"{"network_idle_window_ms":1,"mutation_idle_window_ms":2,"navigation_settled":true,"hard_timeout_ms":3}"#,
        )
        .unwrap();
        assert_eq!(legacy.fixed_wait_ms, 0);
    }

    #[test]
    fn time_stable_raises_both_windows_and_the_hard_timeout() {
        let mut d = Dynamic {
            time_stable_ms: 2_000,
            ..Dynamic::default()
        };
        let p = QuiescencePolicy::for_dynamic(&d);
        assert_eq!(p.network_idle_window_ms, 2_000);
        assert_eq!(p.mutation_idle_window_ms, 2_000);
        assert_eq!(p.hard_timeout_ms, 8_000, "the preset's larger timeout stays");
        assert!(p.navigation_settled);
        d.time_stable_ms = 10_000;
        let p = QuiescencePolicy::for_dynamic(&d);
        assert_eq!(
            p.hard_timeout_ms, 20_000,
            "katana: stable time is at most half the timeout"
        );
        // a request for stability overrides a preset that would wait for nothing
        d.page_load_strategy = PageLoadStrategy::None;
        d.time_stable_ms = 500;
        let none = QuiescencePolicy::for_dynamic(&d);
        assert!(!none.is_no_wait());
        assert_eq!(
            (none.network_idle_window_ms, none.mutation_idle_window_ms),
            (500, 500)
        );
        // zero keeps every preset as it is, and a longer preset window is never shortened
        d.time_stable_ms = 0;
        assert_eq!(
            QuiescencePolicy::for_dynamic(&d),
            QuiescencePolicy::preset(PageLoadStrategy::None, 5_000)
        );
        let long = QuiescencePolicy {
            network_idle_window_ms: 4_000,
            ..QuiescencePolicy::default()
        };
        assert_eq!(long.with_time_stable(1_000).network_idle_window_ms, 4_000);
    }
}
