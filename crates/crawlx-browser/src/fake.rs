//! Scripted in-memory [`BrowserBackend`] / [`BrowserContext`] for downstream tests.
//!
//! A [`FakeScript`] describes a tiny website: pages ([`FakePage`]) with
//! accessibility nodes ([`FakeAxSpec`]) and per-action transitions
//! ([`FakeEffect`]), plus fault flags (stale, obscured, crashing, ...). Every
//! context created by a [`FakeBackend`] shares the backend's script handle but
//! owns its page state (tabs, live nodes, epochs, performed log).
//!
//! Everything is deterministic: no wall clock (a [`SteppingClock`] advancing
//! 1 ms per call by default), no randomness (ids derive from counters),
//! ordered maps only.
//!
//! Notes on fidelity to the real backend:
//! * Text typed with a secret `SecretOr` is never stored in clear: the node's
//!   AX `value` shows one bullet per character, and the typed-input log keeps
//!   only the length. Plain text is stored verbatim.
//! * `mutation_seq` resets with every document (navigation), exactly like the
//!   real observer.
//! * Selector waits use the existing fake CSS subset. Visibility models `hidden` and
//!   positive box dimensions only, not a CSS engine. Unsupported selectors fail explicitly.

use crate::context::{count_crash, record_settle};
use crate::pin::{parse_version, repository_pin};
use async_trait::async_trait;
use crawlx_core::action::BrowserAction;
use crawlx_core::dom_ops::{CssFilter, LazyScrollReport, LazyScrollSpec, XhrRecord, MAX_LAZY_SCROLL_STEPS};
use crawlx_core::identity::ActionKind;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, NetworkEpochId, TabId};
use crawlx_core::observation::{
    ActionReceipt, AxNode, AxSnapshot, BoundingBox, BrowserBuildInfo, DomNodeSupplement, DomSelector,
    DomSelectorKind, DomSupplement, FrameInfo, LiveTargetFacts, MutationStats, NavigationResult,
    NetworkEpochSummary, ObservationBundle, ObservationCost, ObservationSpec, QuiescencePolicy, Revalidation,
    RuntimeLocator, SettleReport, TabInfo,
};
use crawlx_core::page_op::{PageOp, PageOpResult, SelectorState};
use crawlx_core::traffic::{TrafficEvent, TrafficOrigin};
use crawlx_core::{
    BlockedNavigation, BrowserBackend, BrowserContext, BrowserError, CanonicalUrl, Clock, ContextConfig,
    LaunchProfile, NavigationGuard, ObservationEpoch, OptionKey, Timestamp,
};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use url::Url;

/// `2026-01-01T00:00:00Z` in Unix milliseconds.
const DEFAULT_START_MS: i64 = 1_767_225_600_000;
/// Backend node ids at or above this value name synthetic overlay elements
/// reported by `Revalidation::Obscured`.
const OBSCURER_BASE: i64 = 900_000;
/// Name of the single frame of every fake page.
const MAIN_FRAME: &str = "main";

/// Minimal valid 1x1 transparent PNG (signature, IHDR, IDAT, IEND).
pub const PLACEHOLDER_PNG: [u8; 67] = [
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00,
    0x00, 0x00, 0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05, 0x00, 0x01,
    0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
];

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// Deterministic clock that returns the current instant and then advances by a
/// fixed step on every `now()` call.
#[derive(Debug)]
pub struct SteppingClock {
    millis: AtomicI64,
    step_ms: i64,
}

impl SteppingClock {
    /// Start at `start`, advancing `step_ms` per call.
    #[must_use]
    pub fn new(start: Timestamp, step_ms: i64) -> Self {
        Self {
            millis: AtomicI64::new(start.timestamp_millis()),
            step_ms,
        }
    }
}

impl Default for SteppingClock {
    /// `2026-01-01T00:00:00Z`, 1 ms per call.
    fn default() -> Self {
        Self {
            millis: AtomicI64::new(DEFAULT_START_MS),
            step_ms: 1,
        }
    }
}

impl Clock for SteppingClock {
    fn now(&self) -> Timestamp {
        let ms = self.millis.fetch_add(self.step_ms, Ordering::SeqCst);
        Timestamp::from_timestamp_millis(ms).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Script model
// ---------------------------------------------------------------------------

/// One scripted accessibility node.
#[derive(Clone, Debug, PartialEq)]
pub struct FakeAxSpec {
    /// Stable node key, unique within a page (e.g. `"btn-save"`).
    pub key: String,
    /// ARIA role reported in the AX tree (e.g. `"button"`, `"textbox"`); also
    /// selects the default DOM tag when `tag` is `None`.
    pub role: String,
    /// Accessible name; also reported as the node's DOM text.
    pub name: Option<String>,
    /// Current value (typed text for inputs); updated by type/set-value actions.
    pub value: Option<String>,
    /// Accessible description.
    pub description: Option<String>,
    /// AX `disabled` flag; `revalidate` reports `Disabled` for such nodes.
    pub disabled: bool,
    /// AX `focusable` flag.
    pub focusable: bool,
    /// AX checked state as a string (`"true"`, `"false"`, `"mixed"`); `None` when not checkable.
    pub checked: Option<String>,
    /// AX expanded state; `None` when the node is not expandable.
    pub expanded: Option<bool>,
    /// DOM tag name; `None` derives one from `role` (e.g. `button` -> `button`, unknown -> `div`).
    pub tag: Option<String>,
    /// `href` attribute, reported as an AX property, a DOM attribute and in the action target.
    pub href: Option<String>,
    /// Extra DOM attributes reported in the DOM supplement and the action target.
    pub attributes: BTreeMap<String, String>,
    /// `None`: the page assigns a distinct default box from the node's index.
    pub bbox: Option<BoundingBox>,
    /// Key of the parent node (AX tree nesting).
    pub parent: Option<String>,
    /// In the AX tree but not visible: `revalidate` reports `NotVisible`.
    pub hidden: bool,
    /// Attributes only the live target reports (what Chromium derives at revalidation:
    /// `form-method`, `form-action`, `observed-methods`), absent from the observation.
    pub live_attributes: BTreeMap<String, String>,
}

impl FakeAxSpec {
    /// Bare node with `key` and `role`.
    #[must_use]
    pub fn new(key: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            role: role.into(),
            name: None,
            value: None,
            description: None,
            disabled: false,
            focusable: false,
            checked: None,
            expanded: None,
            tag: None,
            href: None,
            attributes: BTreeMap::new(),
            bbox: None,
            parent: None,
            hidden: false,
            live_attributes: BTreeMap::new(),
        }
    }

    /// `<button>` named `name`.
    #[must_use]
    pub fn button(key: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(key, "button").name(name).tag("button").focusable()
    }

    /// `<a href>` named `name`.
    #[must_use]
    pub fn link(key: impl Into<String>, name: impl Into<String>, href: impl Into<String>) -> Self {
        Self::new(key, "link").name(name).href(href).tag("a").focusable()
    }

    /// `<input type=text>` labelled `name`.
    #[must_use]
    pub fn textbox(key: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(key, "textbox")
            .name(name)
            .tag("input")
            .attr("type", "text")
            .focusable()
    }

    /// Unchecked `<input type=checkbox>` labelled `name`.
    #[must_use]
    pub fn checkbox(key: impl Into<String>, name: impl Into<String>) -> Self {
        Self::new(key, "checkbox")
            .name(name)
            .tag("input")
            .attr("type", "checkbox")
            .checked("false")
            .focusable()
    }

    /// Set the accessible name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the current value.
    #[must_use]
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Set the accessible description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the `href` attribute.
    #[must_use]
    pub fn href(mut self, href: impl Into<String>) -> Self {
        self.href = Some(href.into());
        self
    }

    /// Set the DOM tag name, overriding the role-derived default.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Add (or replace) one DOM attribute.
    #[must_use]
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Add one attribute that only the live target reports (see `live_attributes`).
    #[must_use]
    pub fn live_attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.live_attributes.insert(key.into(), value.into());
        self
    }

    /// Pin the bounding box (CSS pixels, page coordinates) instead of the index-derived default.
    #[must_use]
    pub fn bbox(mut self, x: f64, y: f64, width: f64, height: f64) -> Self {
        self.bbox = Some(BoundingBox { x, y, width, height });
        self
    }

    /// Mark the node disabled.
    #[must_use]
    pub fn disabled(mut self) -> Self {
        self.disabled = true;
        self
    }

    /// Mark the node hidden (in the AX tree but not visible).
    #[must_use]
    pub fn hidden(mut self) -> Self {
        self.hidden = true;
        self
    }

    /// Mark the node focusable.
    #[must_use]
    pub fn focusable(mut self) -> Self {
        self.focusable = true;
        self
    }

    /// Nest the node under the node whose key is `parent`.
    #[must_use]
    pub fn parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Set the checked state string (`"true"`, `"false"` or `"mixed"`).
    #[must_use]
    pub fn checked(mut self, checked: impl Into<String>) -> Self {
        self.checked = Some(checked.into());
        self
    }

    /// Set the expanded state.
    #[must_use]
    pub fn expanded(mut self, expanded: bool) -> Self {
        self.expanded = Some(expanded);
        self
    }
}

/// What an action does to the page it is performed on.
#[derive(Clone, Debug, PartialEq)]
pub enum FakeEffect {
    /// Navigate to another scripted page (absolute, or relative to the current
    /// URL); bumps `navigation_seq` and `document_seq`.
    Navigate(String),
    /// Add nodes to the current page (menu, dialog); bumps `mutation_seq` by the node count.
    Reveal(Vec<FakeAxSpec>),
    /// Remove nodes (and their descendants) by key; bumps `mutation_seq` by the removed count.
    Remove(Vec<String>),
    /// Change a node's accessible name; bumps `mutation_seq` by 1.
    SetName {
        /// Key of the node to rename.
        key: String,
        /// New accessible name.
        name: String,
    },
    /// Open a popup tab at `url` (opener = the acting tab).
    OpenTab(String),
    /// Open an initially blank popup whose first navigation commits after `delay_ms`.
    OpenBlankThenNavigate {
        /// Absolute destination URL.
        url: String,
        /// Delay measured by Tokio's monotonic test clock.
        delay_ms: u64,
    },
    /// Open a download window, recording its URL before policy closes it.
    OpenDownload(String),
    /// Replace the cookie/storage map `export_storage` reports (a login that sets a session
    /// cookie); no mutation counter moves.
    SetStorage(BTreeMap<String, String>),
    /// Nothing happens; `mutation_seq` is not bumped.
    Nothing,
}

/// Action key used by `transitions`, `fail_actions` and `crash_on_action`:
/// `"<ActionKind::as_str()>:<node key>"`.
///
/// Actions without a node target use an empty node key (`"keys:"`,
/// `"switch_tab:"`, `"close_tab:"`, `"scroll:"` without a container); `Navigate`
/// uses the URL (`"navigate:<url>"`).
#[must_use]
pub fn action_key(kind: ActionKind, node_key: &str) -> String {
    format!("{}:{node_key}", kind.as_str())
}

/// One scripted page.
#[derive(Clone, Debug, PartialEq)]
pub struct FakePage {
    /// Absolute, normalized URL; the key under which the page is stored in [`FakeScript::pages`].
    pub url: String,
    /// Document title; `None` reports no title.
    pub title: Option<String>,
    /// HTTP status code reported for the navigation (default 200).
    pub status: u16,
    /// Raw HTML body captured in the observation bundle.
    pub html: String,
    /// Outgoing links for tests that compare against the static plane; not
    /// part of an observation.
    pub links: Vec<String>,
    /// Scripted AX nodes, in document order.
    pub ax: Vec<FakeAxSpec>,
    /// Action key -> effects applied in order.
    pub transitions: BTreeMap<String, Vec<FakeEffect>>,
    /// Redirect hops reported by `NavigationResult::redirects`.
    pub redirect_chain: Vec<String>,
    /// URLs the egress proxy blocked while loading.
    pub blocked_by_egress: Vec<String>,
    /// `(url, source)` pairs the page-hooks discovery sink reports, e.g.
    /// `("/api/items", "fetch")`; surfaced in `ObservationBundle::discovered_urls` on the
    /// first observation after each load of the page, and only when the context was created
    /// with `ContextConfig::page_hooks`.
    pub discovered_urls: Vec<(String, String)>,
    /// Nodes that appear lazily, one list per scroll step: the n-th step of a
    /// [`BrowserContext::lazy_scroll`] reveals the n-th list (infinite scroll / sentinel
    /// stand-in). Steps beyond the list reveal nothing and the page counts as at its bottom.
    pub lazy_steps: Vec<Vec<FakeAxSpec>>,
    /// XHR/`fetch()` requests the page issues when it loads; `page_url` is filled with the page's
    /// URL. They come out of [`BrowserContext::drain_xhr`] after each load of the page.
    pub xhr: Vec<XhrRecord>,
}

impl FakePage {
    /// Page at `url` (normalized through `url::Url` when parseable), status 200.
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            url: normalize_url(url),
            title: None,
            status: 200,
            html: String::new(),
            links: Vec::new(),
            ax: Vec::new(),
            transitions: BTreeMap::new(),
            redirect_chain: Vec::new(),
            blocked_by_egress: Vec::new(),
            discovered_urls: Vec::new(),
            lazy_steps: Vec::new(),
            xhr: Vec::new(),
        }
    }

    /// Set the document title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the HTML body.
    #[must_use]
    pub fn html(mut self, html: impl Into<String>) -> Self {
        self.html = html.into();
        self
    }

    /// Add an outgoing link URL (for static-plane comparisons).
    #[must_use]
    pub fn link(mut self, url: impl Into<String>) -> Self {
        self.links.push(url.into());
        self
    }

    /// Append one AX node.
    #[must_use]
    pub fn node(mut self, node: FakeAxSpec) -> Self {
        self.ax.push(node);
        self
    }

    /// Append several AX nodes in order.
    #[must_use]
    pub fn nodes(mut self, nodes: impl IntoIterator<Item = FakeAxSpec>) -> Self {
        self.ax.extend(nodes);
        self
    }

    /// Script the effects of `kind` on `node_key` (see [`action_key`]).
    #[must_use]
    pub fn on(mut self, kind: ActionKind, node_key: &str, effects: Vec<FakeEffect>) -> Self {
        self.transitions.insert(action_key(kind, node_key), effects);
        self
    }

    /// Shorthand for `on(ActionKind::Click, node_key, effects)`.
    #[must_use]
    pub fn on_click(self, node_key: &str, effects: Vec<FakeEffect>) -> Self {
        self.on(ActionKind::Click, node_key, effects)
    }

    /// Redirect hops that led to this page.
    #[must_use]
    pub fn redirect_from(mut self, chain: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.redirect_chain = chain.into_iter().map(Into::into).collect();
        self
    }

    /// Record a URL blocked by the egress proxy while loading this page.
    #[must_use]
    pub fn blocked(mut self, url: impl Into<String>) -> Self {
        self.blocked_by_egress.push(url.into());
        self
    }

    /// Set the HTTP status code reported on navigation.
    #[must_use]
    pub fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Add a URL the page-hooks sink reports under `source` (`pushState`, `fetch`, ...).
    #[must_use]
    pub fn discovered(mut self, url: impl Into<String>, source: impl Into<String>) -> Self {
        self.discovered_urls.push((url.into(), source.into()));
        self
    }

    /// Reveal `nodes` on the next unused lazy scroll step.
    #[must_use]
    pub fn lazy_step(mut self, nodes: impl IntoIterator<Item = FakeAxSpec>) -> Self {
        self.lazy_steps.push(nodes.into_iter().collect());
        self
    }

    /// The page issues an XHR (`resource_type` `xhr`) `method url` answered with `status` when
    /// it loads.
    #[must_use]
    pub fn xhr(mut self, method: &str, url: &str, status: u16) -> Self {
        self.xhr.push(XhrRecord {
            page_url: String::new(),
            method: method.to_owned(),
            url: url.to_owned(),
            status: Some(status),
            resource_type: "xhr".to_owned(),
            content_type: Some("application/json".to_owned()),
        });
        self
    }
}

/// The whole scripted world shared by a backend's contexts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FakeScript {
    /// Pages by normalized URL.
    pub pages: BTreeMap<String, FakePage>,
    /// Node keys whose `revalidate` returns `StaleEpoch`.
    pub stale: BTreeSet<String>,
    /// Node keys reported `Obscured`.
    pub obscured: BTreeSet<String>,
    /// Node keys reported `Unstable`.
    pub unstable: BTreeSet<String>,
    /// Node keys reported `IdentityChanged`.
    pub identity_changed: BTreeSet<String>,
    /// Node keys reported `Detached`.
    pub detached: BTreeSet<String>,
    /// Action key -> `BrowserError::Script` message.
    pub fail_actions: BTreeMap<String, String>,
    /// Action key -> `BrowserError::Script` message returned after the action's effects were
    /// applied: a browser that errors out halfway, with the page already changed (a custom
    /// combobox the action toggled shut before it found no option to click).
    pub fail_after_effects: BTreeMap<String, String>,
    /// Action key that makes `perform` return `BrowserError::TargetCrashed`.
    pub crash_on_action: Option<String>,
    /// `settle` reports a timeout (`settle_timeout: true`, nothing idle).
    pub settle_timeout: bool,
    /// `waited_ms` reported by a successful `settle`.
    pub settle_waited_ms: u64,
}

impl FakeScript {
    /// Empty script: no pages, no injected faults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `page`, keyed by its URL.
    #[must_use]
    pub fn page(mut self, page: FakePage) -> Self {
        self.pages.insert(page.url.clone(), page);
        self
    }

    /// Make `revalidate` of node `key` return `StaleEpoch`.
    #[must_use]
    pub fn stale(mut self, key: impl Into<String>) -> Self {
        self.stale.insert(key.into());
        self
    }

    /// Report node `key` as `Obscured`.
    #[must_use]
    pub fn obscured(mut self, key: impl Into<String>) -> Self {
        self.obscured.insert(key.into());
        self
    }

    /// Report node `key` as `Unstable`.
    #[must_use]
    pub fn unstable(mut self, key: impl Into<String>) -> Self {
        self.unstable.insert(key.into());
        self
    }

    /// Report node `key` as `IdentityChanged`.
    #[must_use]
    pub fn identity_changed(mut self, key: impl Into<String>) -> Self {
        self.identity_changed.insert(key.into());
        self
    }

    /// Report node `key` as `Detached`.
    #[must_use]
    pub fn detached(mut self, key: impl Into<String>) -> Self {
        self.detached.insert(key.into());
        self
    }

    /// `perform` of `action_key` fails with `BrowserError::Script(message)`.
    #[must_use]
    pub fn fail_action(mut self, action_key: impl Into<String>, message: impl Into<String>) -> Self {
        self.fail_actions.insert(action_key.into(), message.into());
        self
    }

    /// `perform` of `action_key` applies its effects, then fails with
    /// `BrowserError::Script(message)`.
    #[must_use]
    pub fn fail_action_after_effects(
        mut self,
        action_key: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        self.fail_after_effects.insert(action_key.into(), message.into());
        self
    }

    /// `perform` of `action_key` fails with `BrowserError::TargetCrashed`.
    #[must_use]
    pub fn crash_on(mut self, action_key: impl Into<String>) -> Self {
        self.crash_on_action = Some(action_key.into());
        self
    }

    /// `settle` reports a timeout.
    #[must_use]
    pub fn settle_timeout(mut self) -> Self {
        self.settle_timeout = true;
        self
    }

    /// `settle` reports `waited_ms` on success.
    #[must_use]
    pub fn settle_waited_ms(mut self, waited_ms: u64) -> Self {
        self.settle_waited_ms = waited_ms;
        self
    }
}

fn normalize_url(raw: &str) -> String {
    Url::parse(raw).map_or_else(|_| raw.to_owned(), |u| u.to_string())
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

/// Find the script key of the page for `raw` (exact, normalized, without
/// fragment, trailing-slash toggled, or relative to `base`).
fn find_page_key(script: &FakeScript, raw: &str, base: Option<&str>) -> Option<String> {
    let mut candidates = vec![raw.to_owned()];
    if let Some(stripped) = raw.split('#').next() {
        push_unique(&mut candidates, stripped.to_owned());
    }
    match Url::parse(raw) {
        Ok(mut u) => {
            u.set_fragment(None);
            push_unique(&mut candidates, u.to_string());
        }
        Err(_) => {
            if let Some(Ok(mut joined)) = base.and_then(|b| Url::parse(b).ok()).map(|b| b.join(raw)) {
                joined.set_fragment(None);
                push_unique(&mut candidates, joined.to_string());
            }
        }
    }
    let toggled: Vec<String> = candidates
        .iter()
        .map(|c| c.strip_suffix('/').map_or_else(|| format!("{c}/"), str::to_owned))
        .collect();
    for t in toggled {
        push_unique(&mut candidates, t);
    }
    candidates.into_iter().find(|c| script.pages.contains_key(c))
}

// ---------------------------------------------------------------------------
// Per-context state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct LiveNode {
    /// Stable backend node id within the document.
    id: i64,
    spec: FakeAxSpec,
}

#[derive(Clone, Debug)]
struct TabState {
    id: TabId,
    opener: Option<TabId>,
    admission_pending: bool,
    download: bool,
    created: Option<tokio::time::Instant>,
    first_navigation: Option<(tokio::time::Instant, String)>,
    /// Script key of the loaded page, `None` before any scripted page loaded.
    page_key: Option<String>,
    url: String,
    status: u16,
    title: Option<String>,
    html: String,
    nodes: Vec<LiveNode>,
    next_id: i64,
    epoch: ObservationEpoch,
    /// Mutations since the last observation of this tab.
    pending: MutationStats,
    /// Page-hooks sink contents not yet reported by an observation.
    hooks_sink: Vec<(String, String)>,
    /// Lazy scroll steps already performed on the current document.
    scrolled: usize,
}

impl TabState {
    fn blank(id: TabId, opener: Option<TabId>, url: String) -> Self {
        Self {
            id,
            opener,
            admission_pending: false,
            download: false,
            created: None,
            first_navigation: None,
            page_key: None,
            url,
            status: 200,
            title: None,
            html: String::new(),
            nodes: Vec::new(),
            next_id: 1,
            epoch: ObservationEpoch::default(),
            pending: MutationStats::default(),
            hooks_sink: Vec::new(),
            scrolled: 0,
        }
    }

    fn node(&self, key: &str) -> Option<&LiveNode> {
        self.nodes.iter().find(|n| n.spec.key == key)
    }

    fn node_mut(&mut self, key: &str) -> Option<&mut LiveNode> {
        self.nodes.iter_mut().find(|n| n.spec.key == key)
    }

    fn bump_mutation(&mut self, n: u64) {
        self.epoch.mutation_seq += n;
    }

    /// Add or replace a node; returns nothing, counts as one added node.
    fn reveal(&mut self, mut spec: FakeAxSpec) {
        if let Some(existing) = self.node_mut(&spec.key) {
            if spec.bbox.is_none() {
                spec.bbox = existing.spec.bbox;
            }
            existing.spec = spec;
        } else {
            let id = self.next_id;
            self.next_id += 1;
            if spec.bbox.is_none() {
                spec.bbox = Some(default_bbox(id));
            }
            self.nodes.push(LiveNode { id, spec });
        }
        self.pending.added_nodes += 1;
        self.pending.records += 1;
        self.bump_mutation(1);
    }

    /// Remove `key` and its descendants; returns the removed count.
    fn remove(&mut self, key: &str) -> u64 {
        let mut doomed: BTreeSet<String> = BTreeSet::new();
        if self.node(key).is_some() {
            doomed.insert(key.to_owned());
        }
        loop {
            let before = doomed.len();
            for n in &self.nodes {
                if n.spec.parent.as_ref().is_some_and(|p| doomed.contains(p)) {
                    doomed.insert(n.spec.key.clone());
                }
            }
            if doomed.len() == before {
                break;
            }
        }
        let before = self.nodes.len();
        self.nodes.retain(|n| !doomed.contains(&n.spec.key));
        let removed = u64::try_from(before - self.nodes.len()).unwrap_or(0);
        self.pending.removed_nodes += removed;
        self.pending.records += removed;
        self.bump_mutation(removed);
        removed
    }

    /// Indices of `nodes` in AX pre-order (roots in spec order, then children).
    fn preorder(&self) -> Vec<usize> {
        let mut index: BTreeMap<&str, usize> = BTreeMap::new();
        for (i, n) in self.nodes.iter().enumerate() {
            index.entry(n.spec.key.as_str()).or_insert(i);
        }
        let mut kids: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        let mut roots: Vec<usize> = Vec::new();
        for (i, n) in self.nodes.iter().enumerate() {
            match n.spec.parent.as_deref() {
                Some(p) if index.contains_key(p) => kids.entry(p).or_default().push(i),
                _ => roots.push(i),
            }
        }
        let mut seen = vec![false; self.nodes.len()];
        let mut out = Vec::with_capacity(self.nodes.len());
        let mut stack: Vec<usize> = roots.into_iter().rev().collect();
        while let Some(i) = stack.pop() {
            match seen.get_mut(i) {
                Some(flag) if !*flag => *flag = true,
                _ => continue,
            }
            let Some(node) = self.nodes.get(i) else { continue };
            out.push(i);
            if let Some(children) = kids.get(node.spec.key.as_str()) {
                stack.extend(children.iter().rev());
            }
        }
        out
    }
}

fn default_bbox(id: i64) -> BoundingBox {
    let row = f64::from(i32::try_from(id.saturating_sub(1)).unwrap_or(0));
    BoundingBox {
        x: 8.0,
        y: row.mul_add(40.0, 8.0),
        width: 120.0,
        height: 32.0,
    }
}

/// Does the scripted node match `selector`? The fake knows the subset `#key`, `key`, `tag`,
/// `.class`, `[attr]` and `[attr=value]` (`name` matches the node key); anything else matches
/// nothing, like an invalid selector in the real browser.
fn css_subset_matches(selector: &str, node: &LiveNode) -> bool {
    let sel = selector.trim();
    if sel.is_empty() {
        return false;
    }
    let spec = &node.spec;
    if let Some(key) = sel.strip_prefix('#') {
        return key == spec.key || spec.attributes.get("id").is_some_and(|id| id == key);
    }
    if let Some(class) = sel.strip_prefix('.') {
        return spec
            .attributes
            .get("class")
            .is_some_and(|c| c.split_whitespace().any(|t| t == class));
    }
    if let Some(inner) = sel.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        return match inner.split_once('=') {
            None => spec.attributes.contains_key(inner.trim()),
            Some((k, v)) => {
                let (k, v) = (k.trim(), v.trim().trim_matches(|c| c == '"' || c == '\''));
                (k == "name" && v == spec.key) || spec.attributes.get(k).is_some_and(|a| a == v)
            }
        };
    }
    sel == spec.key || sel.eq_ignore_ascii_case(&effective_tag(spec))
}

fn effective_tag(spec: &FakeAxSpec) -> String {
    spec.tag.clone().unwrap_or_else(|| {
        match spec.role.as_str() {
            "button" => "button",
            "link" => "a",
            "textbox" | "checkbox" | "radio" | "slider" | "spinbutton" | "searchbox" => "input",
            "combobox" | "listbox" => "select",
            "heading" => "h1",
            _ => "div",
        }
        .to_owned()
    })
}

fn epoch_id(n: u64) -> NetworkEpochId {
    format!("{n:032x}").parse().unwrap_or_default()
}

/// A snapshot of a scripted page taken at navigation time.
struct PageSnapshot {
    key: String,
    url: String,
    status: u16,
    title: Option<String>,
    html: String,
    ax: Vec<FakeAxSpec>,
    redirect_chain: Vec<String>,
    blocked: Vec<String>,
    discovered: Vec<(String, String)>,
    xhr: Vec<XhrRecord>,
}

enum StateChange {
    Type { text: String, clear_first: bool },
    Checked(bool),
    Value(String),
}

/// One recorded text input. Secret text is never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedInput {
    /// Node key the text went to.
    pub key: String,
    /// Number of characters typed.
    pub chars: usize,
    /// The text was secret (`SecretOr::Secret`).
    pub secret: bool,
    /// The text, only for non-secret input.
    pub text: Option<String>,
}

/// URLs (absolute) of the documents an action would load that the guard refused, with the
/// reason, decided before the action runs.
type Refusals = BTreeMap<String, &'static str>;

struct Inner {
    config: ContextConfig,
    clock: Arc<dyn Clock>,
    script: Arc<Mutex<FakeScript>>,
    network_counter: Arc<AtomicU64>,
    tabs: Vec<TabState>,
    current: TabId,
    tab_counter: u64,
    obs_seq: u64,
    net_epoch: Option<NetworkEpochId>,
    net_requests: u32,
    net_operation: Option<String>,
    traffic: Vec<TrafficEvent>,
    traffic_seq: u64,
    traffic_drained: usize,
    last_settle: Option<SettleReport>,
    performed: Vec<(ActionKind, String)>,
    navigations: Vec<String>,
    typed: Vec<TypedInput>,
    storage: BTreeMap<String, serde_json::Value>,
    canon: BTreeMap<String, CanonicalUrl>,
    closed: bool,
    blocked_urls: Vec<String>,
    xhr_queue: Vec<XhrRecord>,
    lazy_scrolls: Vec<LazyScrollSpec>,
    settle_policies: Vec<QuiescencePolicy>,
    css_filters: Vec<CssFilter>,
    /// Every navigation the guard refused, including the ones `navigate` and a `Navigate`
    /// action returned as errors.
    refused_all: Vec<BlockedNavigation>,
    /// The refusals of navigations a page triggered itself (an effect of an action), until
    /// `drain_blocked_navigations` hands them out.
    refused_pending: Vec<BlockedNavigation>,
}

impl Inner {
    fn new(
        config: ContextConfig,
        clock: Arc<dyn Clock>,
        script: Arc<Mutex<FakeScript>>,
        network_counter: Arc<AtomicU64>,
    ) -> Self {
        let first = TabId("tab-1".to_owned());
        Self {
            config,
            clock,
            script,
            network_counter,
            tabs: vec![TabState::blank(first.clone(), None, "about:blank".to_owned())],
            current: first,
            tab_counter: 1,
            obs_seq: 0,
            net_epoch: None,
            net_requests: 0,
            net_operation: None,
            traffic: Vec::new(),
            traffic_seq: 0,
            traffic_drained: 0,
            last_settle: None,
            performed: Vec::new(),
            navigations: Vec::new(),
            typed: Vec::new(),
            storage: BTreeMap::new(),
            canon: BTreeMap::new(),
            closed: false,
            blocked_urls: Vec::new(),
            xhr_queue: Vec::new(),
            lazy_scrolls: Vec::new(),
            settle_policies: Vec::new(),
            css_filters: Vec::new(),
            refused_all: Vec::new(),
            refused_pending: Vec::new(),
        }
    }

    fn tab(&self, id: &TabId) -> Result<&TabState, BrowserError> {
        self.tabs
            .iter()
            .find(|t| &t.id == id)
            .ok_or(BrowserError::TargetClosed)
    }

    fn tab_mut(&mut self, id: &TabId) -> Result<&mut TabState, BrowserError> {
        self.tabs
            .iter_mut()
            .find(|t| &t.id == id)
            .ok_or(BrowserError::TargetClosed)
    }

    fn current_epoch(&self) -> ObservationEpoch {
        self.tab(&self.current).map(|t| t.epoch).unwrap_or_default()
    }

    fn open_epoch(&mut self) -> NetworkEpochId {
        let n = self.network_counter.fetch_add(1, Ordering::SeqCst) + 1;
        let id = epoch_id(n);
        self.net_epoch = Some(id);
        self.net_requests = 0;
        self.net_operation = None;
        id
    }

    fn record_traffic(&mut self, method: &str, url: &str, status: Option<u16>, started_at: Timestamp) {
        self.traffic_seq += 1;
        self.net_requests += 1;
        let route = Url::parse(url).map_or_else(|_| url.to_owned(), |u| u.path().to_owned());
        self.net_operation = Some(format!("{method} {route}"));
        let finished_at = self.clock.now();
        self.traffic.push(TrafficEvent {
            seq: self.traffic_seq,
            epoch_id: self.net_epoch,
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: method.to_owned(),
            url: url.to_owned(),
            status,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: None,
            started_at,
            finished_at: Some(finished_at),
        });
    }

    fn lookup_page(&self, raw: &str, tab: &TabId) -> Result<PageSnapshot, BrowserError> {
        let base = self.tab(tab).ok().map(|t| t.url.clone());
        let script = self.script.lock();
        let key = find_page_key(&script, raw, base.as_deref())
            .ok_or_else(|| BrowserError::Navigation(format!("no scripted page for {raw}")))?;
        let page = script
            .pages
            .get(&key)
            .ok_or_else(|| BrowserError::Navigation(format!("no scripted page for {raw}")))?;
        Ok(PageSnapshot {
            key,
            url: page.url.clone(),
            status: page.status,
            title: page.title.clone(),
            html: page.html.clone(),
            ax: page.ax.clone(),
            redirect_chain: page.redirect_chain.clone(),
            blocked: page.blocked_by_egress.clone(),
            discovered: page.discovered_urls.clone(),
            xhr: page.xhr.clone(),
        })
    }

    /// Replace the document of `tab` with `snap`: nodes reset, nav+doc bumped,
    /// mutation counter reset.
    fn load_page(
        &mut self,
        tab: &TabId,
        snap: &PageSnapshot,
        requested: &str,
    ) -> Result<ObservationEpoch, BrowserError> {
        let t = self.tab_mut(tab)?;
        t.page_key = Some(snap.key.clone());
        t.url.clone_from(&snap.url);
        t.status = snap.status;
        t.title.clone_from(&snap.title);
        t.html.clone_from(&snap.html);
        t.nodes = snap
            .ax
            .iter()
            .enumerate()
            .map(|(i, spec)| {
                let id = i64::try_from(i).unwrap_or(0) + 1;
                let mut spec = spec.clone();
                if spec.bbox.is_none() {
                    spec.bbox = Some(default_bbox(id));
                }
                LiveNode { id, spec }
            })
            .collect();
        t.next_id = i64::try_from(t.nodes.len()).unwrap_or(0) + 1;
        t.epoch = ObservationEpoch {
            navigation_seq: t.epoch.navigation_seq + 1,
            document_seq: t.epoch.document_seq + 1,
            mutation_seq: 0,
        };
        t.pending = MutationStats::default();
        t.hooks_sink.clone_from(&snap.discovered);
        t.scrolled = 0;
        let epoch = t.epoch;
        self.xhr_queue.extend(snap.xhr.iter().cloned().map(|mut x| {
            x.page_url.clone_from(&snap.url);
            x
        }));
        self.navigations.push(requested.to_owned());
        Ok(epoch)
    }

    fn canonical(&mut self, url: &str) -> Result<CanonicalUrl, BrowserError> {
        if let Some(c) = self.canon.get(url) {
            return Ok(c.clone());
        }
        let parsed =
            Url::parse(url).map_err(|e| BrowserError::Navigation(format!("bad page url {url}: {e}")))?;
        let canonical = Canonicalizer::canonicalize_url(&parsed, &CanonicalizeOptions::default())
            .map_err(|e| BrowserError::Navigation(format!("cannot canonicalize {url}: {e}")))?;
        self.canon.insert(url.to_owned(), canonical.clone());
        Ok(canonical)
    }

    // ---- BrowserContext operations -------------------------------------

    fn navigate(&mut self, raw: &str) -> Result<NavigationResult, BrowserError> {
        let started_at = self.clock.now();
        let cur = self.current.clone();
        let snap = self.lookup_page(raw, &cur)?;
        let epoch = self.load_page(&cur, &snap, raw)?;
        let network_epoch = self.open_epoch();
        self.record_traffic("GET", &snap.url, Some(snap.status), started_at);
        Ok(NavigationResult {
            final_url: snap.url,
            status: Some(snap.status),
            epoch,
            network_epoch,
            redirects: snap.redirect_chain,
            blocked_by_egress: snap.blocked,
        })
    }

    fn prepare_popups(&mut self) -> Result<Option<tokio::time::Instant>, BrowserError> {
        let now = tokio::time::Instant::now();
        let ready: Vec<_> = self
            .tabs
            .iter_mut()
            .filter_map(|t| {
                if t.first_navigation.as_ref().is_some_and(|(at, _)| *at <= now) {
                    t.first_navigation.take().map(|(_, url)| (t.id.clone(), url))
                } else {
                    None
                }
            })
            .collect();
        for (tab, url) in ready {
            if let Ok(snapshot) = self.lookup_page(&url, &tab) {
                self.load_page(&tab, &snapshot, &url)?;
            } else {
                self.tab_mut(&tab)?.url = url;
            }
        }
        Ok(self
            .tabs
            .iter()
            .filter_map(|t| {
                let deadline = t.created? + crate::target::FIRST_NAVIGATION_WAIT;
                if t.url != "about:blank" || t.download || now >= deadline {
                    return None;
                }
                Some(
                    t.first_navigation
                        .as_ref()
                        .map_or(deadline, |(at, _)| (*at).min(deadline)),
                )
            })
            .min())
    }

    fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        let cur = self.current.clone();
        let url_str = {
            let tab = self.tab(&cur)?;
            if tab.page_key.is_none() {
                return Err(BrowserError::Navigation(format!(
                    "no document loaded in {}",
                    tab.id.0
                )));
            }
            tab.url.clone()
        };
        let canonical = self.canonical(&url_str)?;
        if !spec.revalidation_only {
            self.obs_seq += 1;
        }
        let seq = self.obs_seq;
        let captured_at = self.clock.now();
        let pending = if spec.revalidation_only {
            self.tab(&cur)?.pending
        } else {
            std::mem::take(&mut self.tab_mut(&cur)?.pending)
        };
        // Safety-only snapshots must not consume the next ordinary observation's hooks.
        let discovered_urls = if self.config.page_hooks && !spec.revalidation_only {
            std::mem::take(&mut self.tab_mut(&cur)?.hooks_sink)
        } else {
            Vec::new()
        };
        let settle = self.last_settle.clone();

        let tab = self.tab(&cur)?;
        let order = tab.preorder();
        let present: BTreeSet<&str> = tab.nodes.iter().map(|n| n.spec.key.as_str()).collect();
        let mut children: BTreeMap<&str, Vec<AxNodeId>> = BTreeMap::new();
        for n in order.iter().filter_map(|&i| tab.nodes.get(i)) {
            if let Some(p) = n.spec.parent.as_deref().filter(|p| present.contains(p)) {
                children.entry(p).or_default().push(AxNodeId(n.spec.key.clone()));
            }
        }
        let locator_of = |n: &LiveNode| RuntimeLocator {
            tab: tab.id.clone(),
            frame: FrameId(MAIN_FRAME.to_owned()),
            backend_node_id: BackendNodeId(n.id),
            object_id: None,
            ax_node_id: Some(AxNodeId(n.spec.key.clone())),
            epoch: tab.epoch,
        };

        let mut ax = AxSnapshot::default();
        if spec.ax {
            for n in order.iter().filter_map(|&i| tab.nodes.get(i)) {
                let mut properties = BTreeMap::new();
                if let Some(href) = &n.spec.href {
                    properties.insert("href".to_owned(), href.clone());
                }
                ax.nodes.push(AxNode {
                    locator: locator_of(n),
                    role: n.spec.role.clone(),
                    name: n.spec.name.clone(),
                    description: n.spec.description.clone(),
                    value: n.spec.value.clone(),
                    ignored: false,
                    focusable: n.spec.focusable,
                    disabled: n.spec.disabled,
                    expanded: n.spec.expanded,
                    checked: n.spec.checked.clone(),
                    properties,
                    parent: n
                        .spec
                        .parent
                        .as_deref()
                        .filter(|p| present.contains(p))
                        .map(|p| AxNodeId(p.to_owned())),
                    children: children.get(n.spec.key.as_str()).cloned().unwrap_or_default(),
                    bbox: n.spec.bbox,
                });
            }
        }

        let mut dom_supplement = DomSupplement::default();
        if spec.dom_supplement {
            for n in order.iter().filter_map(|&i| tab.nodes.get(i)) {
                let mut attributes = n.spec.attributes.clone();
                if let Some(href) = &n.spec.href {
                    attributes.insert("href".to_owned(), href.clone());
                }
                dom_supplement.nodes.insert(
                    n.id,
                    DomNodeSupplement {
                        tag: effective_tag(&n.spec),
                        attributes,
                        text: n.spec.name.clone(),
                        bbox: n.spec.bbox,
                        ..DomNodeSupplement::default()
                    },
                );
            }
        }

        let mut bundle = ObservationBundle::empty(self.config.session_id, tab.id.clone(), canonical);
        bundle.seq = seq;
        bundle.epoch = tab.epoch;
        bundle.captured_at = captured_at;
        bundle.viewport = self.config.viewport;
        bundle.frames = vec![FrameInfo {
            id: FrameId(MAIN_FRAME.to_owned()),
            parent: None,
            url: tab.url.clone(),
            same_origin: true,
            lineage: Vec::new(),
        }];
        bundle.ax = ax;
        bundle.dom_supplement = dom_supplement;
        bundle.mutation = MutationStats {
            records: pending.added_nodes
                + pending.removed_nodes
                + pending.attribute_changes
                + pending.text_changes,
            ..pending
        };
        bundle.network = NetworkEpochSummary {
            epoch_id: self.net_epoch,
            requests: self.net_requests,
            in_flight_at_capture: 0,
            long_lived: Vec::new(),
            late: 0,
            operations: self.net_operation.iter().cloned().collect(),
        };
        bundle.settle = settle;
        bundle.tabs = self
            .tabs
            .iter()
            .map(|t| TabInfo {
                id: t.id.clone(),
                url: t.url.clone(),
                opener: t.opener.clone(),
                active: t.id == self.current,
                pending: t.admission_pending,
                download: t.download,
            })
            .collect();
        bundle.html = Some(tab.html.clone());
        bundle.title = tab.title.clone();
        bundle.discovered_urls = discovered_urls;

        let mut bytes = u64::try_from(tab.html.len()).unwrap_or(0);
        if spec.dom_snapshot {
            let snapshot = serde_json::json!({
                "fake": true,
                "url": tab.url,
                "nodes": tab.nodes.len(),
            });
            let blob = serde_json::to_vec(&snapshot).map_err(|e| BrowserError::Io(e.to_string()))?;
            bytes += u64::try_from(blob.len()).unwrap_or(0);
            bundle = bundle.with_raw_artifact("dom_snapshot", blob);
        }
        if spec.screenshot {
            bytes += u64::try_from(PLACEHOLDER_PNG.len()).unwrap_or(0);
            bundle = bundle.with_raw_artifact("screenshot", PLACEHOLDER_PNG.to_vec());
        }
        bundle.cost = ObservationCost {
            cdp_calls: 1
                + u32::from(spec.ax)
                + u32::from(spec.dom_supplement)
                + u32::from(spec.dom_snapshot)
                + u32::from(spec.screenshot),
            bytes,
            wall_ms: 0,
        };
        Ok(bundle)
    }

    fn locator_key(&self, loc: &RuntimeLocator) -> String {
        if let Some(a) = &loc.ax_node_id {
            return a.0.clone();
        }
        self.tab(&loc.tab)
            .ok()
            .and_then(|t| t.nodes.iter().find(|n| n.id == loc.backend_node_id.0))
            .map_or_else(|| format!("#{}", loc.backend_node_id.0), |n| n.spec.key.clone())
    }

    /// Resolve a recorded-flow selector against the active tab's live nodes, in document
    /// order. Matching rule: `css` and `xpath` match a node whose key equals the expression
    /// (`#key` and `[name="key"]` forms are accepted for CSS) or whose `attributes` map
    /// contains an attribute selector `[attr="value"]` the expression consists of; `aria`
    /// matches the accessible name (an optional `[role="x"]` suffix must match the role);
    /// `text` matches a node whose name contains the expression. Hidden nodes are still
    /// returned (visibility is `revalidate`'s job, as in the real adapter).
    fn resolve_selector(&self, selector: &DomSelector) -> Option<RuntimeLocator> {
        let tab = self.tab(&self.current).ok()?;
        let expr = selector.expr.trim();
        if expr.is_empty() {
            return None;
        }
        let attr_selector = |e: &str| -> Option<(String, String)> {
            let inner = e.strip_prefix('[')?.strip_suffix(']')?;
            let (k, v) = inner.split_once('=')?;
            Some((
                k.trim().to_owned(),
                v.trim().trim_matches(|c| c == '"' || c == '\'').to_owned(),
            ))
        };
        let matches = |n: &LiveNode| -> bool {
            match selector.kind {
                DomSelectorKind::Css | DomSelectorKind::XPath => {
                    let key = n.spec.key.as_str();
                    expr == key
                        || expr.strip_prefix('#') == Some(key)
                        || attr_selector(expr).is_some_and(|(k, v)| {
                            (k == "name" && v == key) || n.spec.attributes.get(&k) == Some(&v)
                        })
                }
                DomSelectorKind::Aria => {
                    let (name, role) = match expr.rfind("[role=") {
                        Some(at) if expr.ends_with(']') => (
                            expr[..at].trim(),
                            Some(
                                expr[at + "[role=".len()..expr.len() - 1]
                                    .trim()
                                    .trim_matches(|c| c == '"' || c == '\''),
                            ),
                        ),
                        _ => (expr, None),
                    };
                    n.spec
                        .name
                        .as_deref()
                        .is_some_and(|live| live.eq_ignore_ascii_case(name))
                        && role.is_none_or(|r| n.spec.role.eq_ignore_ascii_case(r))
                }
                DomSelectorKind::Text => n.spec.name.as_deref().is_some_and(|live| live.contains(expr)),
                _ => false,
            }
        };
        let order = tab.preorder();
        order
            .iter()
            .filter_map(|&i| tab.nodes.get(i))
            .find(|n| matches(n))
            .map(|n| RuntimeLocator {
                tab: tab.id.clone(),
                frame: FrameId(MAIN_FRAME.to_owned()),
                backend_node_id: BackendNodeId(n.id),
                object_id: None,
                ax_node_id: Some(AxNodeId(n.spec.key.clone())),
                epoch: tab.epoch,
            })
    }

    fn revalidate(&self, locator: &RuntimeLocator, expected: ObservationEpoch) -> Revalidation {
        let Ok(tab) = self.tab(&locator.tab) else {
            return Revalidation::Detached;
        };
        let current = tab.epoch;
        let mismatch = |e: &ObservationEpoch| {
            e.navigation_seq != current.navigation_seq || e.document_seq != current.document_seq
        };
        if mismatch(&locator.epoch) || mismatch(&expected) {
            return Revalidation::StaleEpoch { current };
        }
        let key = self.locator_key(locator);
        let script = self.script.lock();
        let node = tab.node(&key);
        let Some(node) = node.filter(|_| !script.detached.contains(&key)) else {
            return Revalidation::Detached;
        };
        if script.stale.contains(&key) {
            return Revalidation::StaleEpoch { current };
        }
        if script.identity_changed.contains(&key) {
            return Revalidation::IdentityChanged;
        }
        if node.spec.hidden {
            return Revalidation::NotVisible;
        }
        if node.spec.disabled {
            return Revalidation::Disabled;
        }
        if script.obscured.contains(&key) {
            return Revalidation::Obscured {
                by_backend_node_id: Some(BackendNodeId(OBSCURER_BASE + node.id)),
            };
        }
        if script.unstable.contains(&key) {
            return Revalidation::Unstable;
        }
        let bbox = node.spec.bbox.unwrap_or_default();
        let (x, y, w, h) = (bbox.x, bbox.y, bbox.width, bbox.height);
        let hit_points = vec![
            (w.mul_add(0.5, x), h.mul_add(0.5, y)),
            (w.mul_add(0.25, x), h.mul_add(0.25, y)),
            (w.mul_add(0.75, x), h.mul_add(0.25, y)),
            (w.mul_add(0.25, x), h.mul_add(0.75, y)),
            (w.mul_add(0.75, x), h.mul_add(0.75, y)),
        ];
        let mut attributes = node.spec.attributes.clone();
        attributes.extend(
            node.spec
                .live_attributes
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        Revalidation::Actionable {
            live: LiveTargetFacts {
                role: Some(node.spec.role.clone()),
                name: node.spec.name.clone(),
                tag: node.spec.tag.clone(),
                href: node.spec.href.clone(),
                bbox,
                hit_points,
                frame_url: None,
                current_url: tab.url.clone(),
                attributes,
                observed_form_hint: None,
            },
        }
    }

    fn action_key(&self, action: &BrowserAction) -> String {
        let kind = action.kind();
        match action {
            BrowserAction::Keys { .. } | BrowserAction::SwitchTab { .. } | BrowserAction::CloseTab { .. } => {
                action_key(kind, "")
            }
            BrowserAction::Navigate { url } => action_key(kind, url.as_str()),
            BrowserAction::Scroll { container, .. } => action_key(
                kind,
                &container
                    .as_ref()
                    .map(|c| self.locator_key(c))
                    .unwrap_or_default(),
            ),
            other => action_key(
                kind,
                &other.target().map(|t| self.locator_key(t)).unwrap_or_default(),
            ),
        }
    }

    /// `raw`, a link or popup target of a scripted effect, as an absolute URL relative to the
    /// page `tab` shows; `None` when it parses neither way (the navigation fails on its own).
    fn absolute(&self, raw: &str, tab: &TabId) -> Option<Url> {
        let base = self.tab(tab).ok().and_then(|t| Url::parse(&t.url).ok());
        base.and_then(|b| b.join(raw).ok())
            .or_else(|| Url::parse(raw).ok())
    }

    /// The documents `action` would load: its own `Navigate` target and the navigations and
    /// tabs its scripted effects open, as absolute URLs. The guard is asked about each of them
    /// before the action runs.
    fn navigation_targets(&self, action: &BrowserAction) -> Vec<Url> {
        let key = self.action_key(action);
        let acting = action
            .target()
            .map_or_else(|| self.current.clone(), |t| t.tab.clone());
        let mut targets = Vec::new();
        if let BrowserAction::Navigate { url } = action {
            targets.push(url.clone());
        }
        let effects: Vec<FakeEffect> = self
            .tab(&acting)
            .ok()
            .and_then(|t| t.page_key.clone())
            .and_then(|page| {
                let script = self.script.lock();
                script
                    .pages
                    .get(&page)
                    .and_then(|p| p.transitions.get(&key))
                    .cloned()
            })
            .unwrap_or_default();
        for effect in effects {
            match effect {
                FakeEffect::Navigate(raw)
                | FakeEffect::OpenTab(raw)
                | FakeEffect::OpenDownload(raw)
                | FakeEffect::OpenBlankThenNavigate { url: raw, .. } => {
                    targets.extend(self.absolute(&raw, &acting));
                }
                _ => {}
            }
        }
        targets
    }

    /// Whether the guard refused the navigation to `raw` before the action ran; records it.
    fn refuse(&mut self, raw: &str, tab: &TabId, refused: &Refusals) -> bool {
        let Some(url) = self.absolute(raw, tab) else {
            return false;
        };
        let Some(reason) = refused.get(url.as_str()).copied() else {
            return false;
        };
        let blocked = BlockedNavigation::new(crate::context::guard::loggable(&url), reason);
        self.refused_all.push(blocked.clone());
        self.refused_pending.push(blocked);
        true
    }

    fn perform(&mut self, action: BrowserAction, refused: &Refusals) -> Result<ActionReceipt, BrowserError> {
        let started_at = self.clock.now();
        let kind = action.kind();
        let key = self.action_key(&action);
        self.performed.push((kind, key.clone()));

        {
            let script = self.script.lock();
            if script.crash_on_action.as_deref() == Some(key.as_str()) {
                count_crash("action");
                return Err(BrowserError::TargetCrashed);
            }
            if let Some(msg) = script.fail_actions.get(&key) {
                return Err(BrowserError::Script(msg.clone()));
            }
        }
        if matches!(action, BrowserAction::SyntheticClick { .. }) && !self.config.synthetic_click_allowed {
            return Err(BrowserError::Unsupported(
                "synthetic click is disabled for this context".to_owned(),
            ));
        }

        let locators: Vec<&RuntimeLocator> = match &action {
            BrowserAction::Drag { source, destination } => vec![source, destination],
            other => other.target().into_iter().collect(),
        };
        for loc in locators {
            let current = match self.tab(&loc.tab) {
                Ok(t) => t.epoch,
                Err(_) => return Err(BrowserError::StaleLocator(self.current_epoch())),
            };
            if loc.epoch.navigation_seq != current.navigation_seq
                || loc.epoch.document_seq != current.document_seq
            {
                return Err(BrowserError::StaleLocator(current));
            }
        }

        let acting_tab = action
            .target()
            .map_or_else(|| self.current.clone(), |t| t.tab.clone());
        let effects: Vec<FakeEffect> = {
            let page_key = self.tab(&acting_tab)?.page_key.clone();
            let script = self.script.lock();
            page_key
                .and_then(|k| script.pages.get(&k))
                .and_then(|p| p.transitions.get(&key))
                .cloned()
                .unwrap_or_default()
        };

        let change = match &action {
            BrowserAction::Type {
                value, clear_first, ..
            } => {
                let secret = value.is_secret();
                let raw = value.expose();
                let text = if secret {
                    "\u{2022}".repeat(raw.chars().count())
                } else {
                    raw.clone()
                };
                self.typed.push(TypedInput {
                    key: self.action_target_key(&action),
                    chars: raw.chars().count(),
                    secret,
                    text: (!secret).then(|| raw.clone()),
                });
                Some(StateChange::Type {
                    text,
                    clear_first: *clear_first,
                })
            }
            BrowserAction::SetChecked { checked, .. } => Some(StateChange::Checked(*checked)),
            BrowserAction::Select { options, .. } => Some(StateChange::Value(
                options
                    .iter()
                    .map(|o| match o {
                        OptionKey::Value(s) | OptionKey::Label(s) => s.clone(),
                        OptionKey::Index(i) => i.to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(","),
            )),
            BrowserAction::SetRange { value, .. } => Some(StateChange::Value(value.to_string())),
            _ => None,
        };
        if let Some(change) = change {
            let node_key = self.action_target_key(&action);
            self.apply_state_change(&acting_tab, &node_key, change)?;
        }

        match &action {
            BrowserAction::Navigate { url } => {
                if let Some(reason) = refused.get(url.as_str()).copied() {
                    let blocked = BlockedNavigation::new(crate::context::guard::loggable(url), reason);
                    self.refused_all.push(blocked.clone());
                    return Err(blocked.into_error());
                }
                let cur = self.current.clone();
                let snap = self.lookup_page(url.as_str(), &cur)?;
                self.load_page(&cur, &snap, url.as_str())?;
            }
            BrowserAction::SwitchTab { tab } => {
                if self.tab(tab)?.admission_pending {
                    if self.tabs.iter().filter(|t| !t.admission_pending).count()
                        >= usize::from(self.config.max_tabs.max(1))
                    {
                        return Err(BrowserError::TabLimit(self.config.max_tabs));
                    }
                    self.tab_mut(tab)?.admission_pending = false;
                }
                self.current = tab.clone();
            }
            BrowserAction::CloseTab { tab } => {
                self.close_tab(tab)?;
            }
            _ => {}
        }

        if self.tab(&acting_tab).is_ok() {
            self.apply_effects(&acting_tab, effects, refused)?;
        }
        if let Some(msg) = self.script.lock().fail_after_effects.get(&key) {
            return Err(BrowserError::Script(msg.clone()));
        }

        let network_epoch = self.open_epoch();
        let method = match kind {
            ActionKind::Click
            | ActionKind::KeyboardActivate
            | ActionKind::SyntheticClick
            | ActionKind::Upload => "POST",
            _ => "GET",
        };
        let (url, status) = self
            .tab(&self.current)
            .map(|t| (t.url.clone(), t.status))
            .unwrap_or_else(|_| ("about:blank".to_owned(), 200));
        self.record_traffic(method, &url, Some(status), started_at);
        let fidelity = action.fidelity();
        Ok(ActionReceipt {
            network_epoch,
            fidelity,
            lane: fidelity.lane(),
            started_at,
            finished_at: self.clock.now(),
        })
    }

    fn action_target_key(&self, action: &BrowserAction) -> String {
        action.target().map(|t| self.locator_key(t)).unwrap_or_default()
    }

    fn apply_state_change(
        &mut self,
        tab: &TabId,
        key: &str,
        change: StateChange,
    ) -> Result<(), BrowserError> {
        let t = self.tab_mut(tab)?;
        let node = t.node_mut(key).ok_or_else(|| BrowserError::Protocol {
            method: "DOM.resolveNode".to_owned(),
            message: format!("no live node {key}"),
        })?;
        match change {
            StateChange::Type {
                text, clear_first, ..
            } => {
                node.spec.value = Some(if clear_first {
                    text
                } else {
                    format!("{}{text}", node.spec.value.as_deref().unwrap_or_default())
                });
            }
            StateChange::Checked(checked) => {
                node.spec.checked = Some(if checked { "true" } else { "false" }.to_owned());
            }
            StateChange::Value(v) => node.spec.value = Some(v),
        }
        t.pending.attribute_changes += 1;
        t.pending.records += 1;
        t.bump_mutation(1);
        Ok(())
    }

    fn close_tab(&mut self, tab: &TabId) -> Result<(), BrowserError> {
        let pos = self
            .tabs
            .iter()
            .position(|t| &t.id == tab)
            .ok_or(BrowserError::TargetClosed)?;
        if self.tabs.len() == 1 {
            return Err(BrowserError::Unsupported("cannot close the last tab".to_owned()));
        }
        let closed = self.tabs.remove(pos);
        if &self.current == tab {
            let fallback = closed
                .opener
                .filter(|o| self.tabs.iter().any(|t| &t.id == o))
                .or_else(|| self.tabs.first().map(|t| t.id.clone()));
            if let Some(next) = fallback {
                self.current = next;
            }
        }
        Ok(())
    }

    fn apply_effects(
        &mut self,
        tab: &TabId,
        effects: Vec<FakeEffect>,
        refused: &Refusals,
    ) -> Result<(), BrowserError> {
        for effect in effects {
            match effect {
                FakeEffect::Nothing => {}
                FakeEffect::Navigate(raw) => {
                    if self.refuse(&raw, tab, refused) {
                        continue;
                    }
                    let snap = self.lookup_page(&raw, tab)?;
                    self.load_page(tab, &snap, &raw)?;
                }
                FakeEffect::Reveal(specs) => {
                    let t = self.tab_mut(tab)?;
                    for spec in specs {
                        t.reveal(spec);
                    }
                }
                FakeEffect::Remove(keys) => {
                    let t = self.tab_mut(tab)?;
                    for key in keys {
                        t.remove(&key);
                    }
                }
                FakeEffect::SetName { key, name } => {
                    let t = self.tab_mut(tab)?;
                    let node = t
                        .node_mut(&key)
                        .ok_or_else(|| BrowserError::Script(format!("SetName: no live node {key}")))?;
                    node.spec.name = Some(name);
                    t.pending.text_changes += 1;
                    t.pending.records += 1;
                    t.bump_mutation(1);
                }
                FakeEffect::OpenTab(raw) => {
                    if self.refuse(&raw, tab, refused) {
                        continue;
                    }
                    let pending = self.tabs.iter().filter(|t| !t.admission_pending).count()
                        >= usize::from(self.config.max_tabs.max(1));
                    self.tab_counter += 1;
                    let id = TabId(format!("tab-{}", self.tab_counter));
                    let mut popup = TabState::blank(id.clone(), Some(tab.clone()), raw.clone());
                    popup.admission_pending = pending;
                    popup.created = Some(tokio::time::Instant::now());
                    self.tabs.push(popup);
                    // A popup to an unscripted URL stays an empty tab at that URL.
                    if let Ok(snap) = self.lookup_page(&raw, tab) {
                        self.load_page(&id, &snap, &raw)?;
                    }
                }
                FakeEffect::OpenBlankThenNavigate { url, delay_ms } => {
                    let first_refused = self.refuse(&url, tab, refused);
                    self.apply_effects(tab, vec![FakeEffect::OpenTab("about:blank".to_owned())], refused)?;
                    if let (false, Some(popup)) = (first_refused, self.tabs.last_mut()) {
                        popup.first_navigation = Some((
                            tokio::time::Instant::now() + std::time::Duration::from_millis(delay_ms),
                            url,
                        ));
                    }
                }
                FakeEffect::OpenDownload(url) => {
                    if self.refuse(&url, tab, refused) {
                        continue;
                    }
                    self.apply_effects(tab, vec![FakeEffect::OpenTab(url)], refused)?;
                    if let Some(popup) = self.tabs.last_mut() {
                        popup.download = true;
                    }
                }
                FakeEffect::SetStorage(map) => {
                    self.storage = map
                        .into_iter()
                        .map(|(k, v)| (k, serde_json::Value::String(v)))
                        .collect();
                }
            }
        }
        Ok(())
    }

    fn settle(&mut self, policy: QuiescencePolicy) -> SettleReport {
        self.settle_policies.push(policy);
        let (timeout, waited) = {
            let script = self.script.lock();
            (script.settle_timeout, script.settle_waited_ms)
        };
        let report = if timeout {
            SettleReport {
                waited_ms: policy.hard_timeout_ms,
                network_idle: false,
                mutation_idle: false,
                navigation_settled: false,
                settle_timeout: true,
                postcondition: None,
                excluded_volatile_targets: 0,
            }
        } else {
            SettleReport {
                waited_ms: waited,
                network_idle: true,
                mutation_idle: true,
                navigation_settled: true,
                settle_timeout: false,
                postcondition: None,
                excluded_volatile_targets: 0,
            }
        };
        record_settle(&report);
        self.last_settle = Some(report.clone());
        report
    }

    /// Reveal the scripted lazy steps of the current page, at most `spec.max_steps`.
    fn lazy_scroll(&mut self, spec: LazyScrollSpec) -> Result<LazyScrollReport, BrowserError> {
        self.lazy_scrolls.push(spec);
        let cur = self.current.clone();
        let steps: Vec<Vec<FakeAxSpec>> = {
            let key = self.tab(&cur)?.page_key.clone();
            let script = self.script.lock();
            key.and_then(|k| script.pages.get(&k))
                .map(|p| p.lazy_steps.clone())
                .unwrap_or_default()
        };
        let max = usize::from(spec.max_steps.min(MAX_LAZY_SCROLL_STEPS));
        let tab = self.tab_mut(&cur)?;
        let mut done = 0_u8;
        while usize::from(done) < max && tab.scrolled < steps.len() {
            for node in steps[tab.scrolled].clone() {
                tab.reveal(node);
            }
            tab.scrolled += 1;
            done += 1;
        }
        Ok(LazyScrollReport {
            steps: done,
            reached_bottom: tab.scrolled >= steps.len(),
            document_height: 0,
        })
    }

    /// Evaluate `filter` against the scripted nodes with the CSS subset [`css_subset_matches`]
    /// understands.
    fn css_filter(
        &mut self,
        filter: &CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, BrowserError> {
        self.css_filters.push(filter.clone());
        let mut out = Vec::with_capacity(targets.len());
        for loc in targets {
            let Ok(tab) = self.tab(&loc.tab) else {
                out.push(false);
                continue;
            };
            let Some(node) = tab.nodes.iter().find(|n| n.id == loc.backend_node_id.0) else {
                out.push(false);
                continue;
            };
            let included =
                filter.include.is_empty() || filter.include.iter().any(|sel| css_subset_matches(sel, node));
            // the node and every ancestor (`Element.closest`)
            let mut excluded = false;
            let mut cursor = Some(node);
            while let Some(n) = cursor {
                if filter.exclude.iter().any(|sel| css_subset_matches(sel, n)) {
                    excluded = true;
                    break;
                }
                cursor = n
                    .spec
                    .parent
                    .as_deref()
                    .and_then(|p| tab.nodes.iter().find(|x| x.spec.key == p));
            }
            out.push(included && !excluded);
        }
        Ok(out)
    }

    /// Sample a selector wait against live nodes without changing the fake clock or page.
    fn selector_state(&self, selector: &str, state: SelectorState) -> Result<bool, BrowserError> {
        if self.closed {
            return Err(BrowserError::TargetClosed);
        }
        let selector = selector.trim();
        let identifier = |text: &str| {
            !text.is_empty() && text.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        };
        if selector.is_empty()
            || selector.chars().filter(|&c| c == '[').count()
                != selector.chars().filter(|&c| c == ']').count()
        {
            return Err(BrowserError::Script("invalid CSS selector".to_owned()));
        }
        let supported = if let Some(inner) = selector.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            match inner.split_once('=') {
                None => identifier(inner.trim()),
                Some((key, value)) => {
                    let value = value.trim();
                    identifier(key.trim())
                        && (identifier(value)
                            || (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
                            || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2))
                }
            }
        } else {
            identifier(selector.strip_prefix(['#', '.']).unwrap_or(selector))
        };
        if !supported {
            return Err(BrowserError::Unsupported(
                "selector outside fake CSS subset".to_owned(),
            ));
        }
        let tab = self.tab(&self.current)?;
        let script = self.script.lock();
        let order = tab.preorder();
        let first = order
            .iter()
            .filter_map(|&index| tab.nodes.get(index))
            .filter(|node| !script.detached.contains(&node.spec.key))
            .find(|node| css_subset_matches(selector, node));
        let visible = first.is_some_and(|node| {
            !node.spec.hidden
                && node
                    .spec
                    .bbox
                    .is_some_and(|bbox| bbox.width > 0.0 && bbox.height > 0.0)
        });
        match state {
            SelectorState::Attached => Ok(first.is_some()),
            SelectorState::Visible => Ok(visible),
            SelectorState::Hidden => Ok(!visible),
            SelectorState::Detached => Ok(first.is_none()),
            _ => Err(BrowserError::Unsupported("selector wait state".to_owned())),
        }
    }

    fn block_urls(&mut self, patterns: Vec<String>) {
        self.blocked_urls = patterns;
    }

    fn import_storage(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        let parsed: BTreeMap<String, serde_json::Value> = serde_json::from_slice(blob)
            .map_err(|e| BrowserError::Io(format!("invalid storage blob: {e}")))?;
        self.storage = parsed;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public context / handle
// ---------------------------------------------------------------------------

/// Entries in progress and their high-water mark (single-writer checks).
#[derive(Default)]
struct InFlight {
    current: AtomicUsize,
    max: AtomicUsize,
}

impl InFlight {
    fn enter(&self) -> InFlightGuard<'_> {
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.max.fetch_max(now, Ordering::SeqCst);
        InFlightGuard(self)
    }

    fn current(&self) -> usize {
        self.current.load(Ordering::SeqCst)
    }

    fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }
}

/// Decrements the entry count when the method returns, on every path.
struct InFlightGuard<'a>(&'a InFlight);

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.0.current.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Scripted browser context. Create via [`FakeBackend::new_fake_context`] or
/// the boxed [`BrowserBackend::new_context`].
pub struct FakeContext {
    inner: Arc<Mutex<Inner>>,
    /// Entries into this context's action/navigation methods.
    in_flight: Arc<InFlight>,
    /// Entries across every context of the backend that created this one.
    backend_in_flight: Arc<InFlight>,
    /// Open contexts of the backend; decremented once, on `close` or drop.
    open: Arc<AtomicUsize>,
    /// `perform` waits here while the backend holds performs (`false`).
    performs_open: tokio::sync::watch::Receiver<bool>,
    /// Performs of the backend parked on the hold right now.
    held: Arc<InFlight>,
    /// Consulted before every document navigation (`ContextConfig::navigation_guard`).
    guard: Option<Arc<dyn NavigationGuard>>,
}

impl Drop for FakeContext {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if !inner.closed {
            inner.closed = true;
            self.open.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl FakeContext {
    /// The reason code when the guard refuses `url`; `None` without a guard and for URLs that
    /// are not `http(s)` (they load no remote document).
    async fn refusal(&self, url: &Url) -> Option<&'static str> {
        let guard = self.guard.as_ref()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        crate::context::guard::refusal(guard.as_ref(), url).await
    }

    /// What the guard refuses among the documents `action` would load. Decided before the
    /// action touches the page, so a refused navigation is never half applied.
    async fn refusals_for(&self, action: &BrowserAction) -> Refusals {
        let mut refused = Refusals::new();
        if self.guard.is_none() {
            return refused;
        }
        let targets = self.inner.lock().navigation_targets(action);
        for url in targets {
            if let Some(reason) = self.refusal(&url).await {
                refused.insert(url.to_string(), reason);
            }
        }
        refused
    }
}

impl fmt::Debug for FakeContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeContext")
            .field("handle", &self.handle())
            .finish()
    }
}

impl FakeContext {
    /// Cloneable observer sharing this context's state; stays valid after the
    /// context is boxed, moved into an actor, or closed.
    #[must_use]
    pub fn handle(&self) -> FakeContextHandle {
        FakeContextHandle {
            inner: Arc::clone(&self.inner),
            in_flight: Arc::clone(&self.in_flight),
        }
    }

    /// Kinds of the actions performed so far (including failed ones).
    #[must_use]
    pub fn performed(&self) -> Vec<ActionKind> {
        self.handle().performed()
    }

    /// Count this entry on the context and its backend until the guards drop.
    fn enter(&self) -> (InFlightGuard<'_>, InFlightGuard<'_>) {
        (self.in_flight.enter(), self.backend_in_flight.enter())
    }

    /// Park until the backend releases performs (returns at once when none are held).
    async fn wait_performs_open(&self) {
        let mut rx = self.performs_open.clone();
        if *rx.borrow_and_update() {
            return;
        }
        let _parked = self.held.enter();
        // a closed sender (backend dropped) opens the gate: nothing can release it later
        let _ = rx.wait_for(|open| *open).await;
    }
}

/// Cloneable view onto a [`FakeContext`]'s state, for assertions after the
/// context moved elsewhere.
#[derive(Clone)]
pub struct FakeContextHandle {
    inner: Arc<Mutex<Inner>>,
    in_flight: Arc<InFlight>,
}

impl fmt::Debug for FakeContextHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("FakeContextHandle")
            .field("epoch", &inner.current_epoch())
            .field("tabs", &inner.tabs.len())
            .field("performed", &inner.performed.len())
            .field("closed", &inner.closed)
            .finish()
    }
}

impl FakeContextHandle {
    /// Kinds of the actions performed so far, in order (failed ones included).
    #[must_use]
    pub fn performed(&self) -> Vec<ActionKind> {
        self.inner.lock().performed.iter().map(|(k, _)| *k).collect()
    }

    /// Action keys (see [`action_key`]) of the actions performed so far.
    #[must_use]
    pub fn performed_keys(&self) -> Vec<String> {
        self.inner
            .lock()
            .performed
            .iter()
            .map(|(_, k)| k.clone())
            .collect()
    }

    /// URLs requested through `navigate`, `Navigate` actions/effects and popup loads.
    #[must_use]
    pub fn navigations(&self) -> Vec<String> {
        self.inner.lock().navigations.clone()
    }

    /// Every navigation the guard refused, oldest first: the ones `navigate` and a `Navigate`
    /// action returned as [`BrowserError::RobotsBlocked`] and the ones an action's effect
    /// triggered (a link, a popup). None of them loaded anything: they are in neither
    /// [`Self::navigations`] nor the traffic.
    #[must_use]
    pub fn refused_navigations(&self) -> Vec<BlockedNavigation> {
        self.inner.lock().refused_all.clone()
    }

    /// Epoch of the current tab.
    #[must_use]
    pub fn epoch(&self) -> ObservationEpoch {
        self.inner.lock().current_epoch()
    }

    /// Total number of traffic events handed out by `drain_traffic`.
    #[must_use]
    pub fn traffic_drained(&self) -> usize {
        self.inner.lock().traffic_drained
    }

    /// Has the context been closed?
    #[must_use]
    pub fn closed(&self) -> bool {
        self.inner.lock().closed
    }

    /// Action/navigation methods of this context in progress right now.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.current()
    }

    /// High-water mark of [`Self::in_flight`] since the context was created; `1` means no
    /// two entries ever overlapped (single writer).
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.in_flight.max()
    }

    /// Seed the cookie/storage map returned by `export_storage`.
    pub fn set_storage(&self, map: BTreeMap<String, String>) {
        self.inner.lock().storage = map
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
    }

    /// Current storage map (seeded or imported).
    #[must_use]
    pub fn storage(&self) -> BTreeMap<String, serde_json::Value> {
        self.inner.lock().storage.clone()
    }

    /// Ids of all open tabs, in opening order.
    #[must_use]
    pub fn tab_ids(&self) -> Vec<TabId> {
        self.inner.lock().tabs.iter().map(|t| t.id.clone()).collect()
    }

    /// Id of the current tab.
    #[must_use]
    pub fn current_tab(&self) -> TabId {
        self.inner.lock().current.clone()
    }

    /// URL of the current tab.
    #[must_use]
    pub fn current_url(&self) -> String {
        let inner = self.inner.lock();
        inner
            .tab(&inner.current)
            .map(|t| t.url.clone())
            .unwrap_or_default()
    }

    /// Keys of the live nodes of the current tab, in insertion order.
    #[must_use]
    pub fn live_keys(&self) -> Vec<String> {
        let inner = self.inner.lock();
        inner
            .tab(&inner.current)
            .map(|t| t.nodes.iter().map(|n| n.spec.key.clone()).collect())
            .unwrap_or_default()
    }

    /// Text inputs recorded so far (secret text is never stored).
    #[must_use]
    pub fn typed_inputs(&self) -> Vec<TypedInput> {
        self.inner.lock().typed.clone()
    }

    /// Patterns of the last `PageOp::BlockUrls` the context executed (empty: none, or cleared).
    #[must_use]
    pub fn blocked_url_patterns(&self) -> Vec<String> {
        self.inner.lock().blocked_urls.clone()
    }

    /// Every [`BrowserContext::lazy_scroll`] request received, in order.
    #[must_use]
    pub fn lazy_scrolls(&self) -> Vec<LazyScrollSpec> {
        self.inner.lock().lazy_scrolls.clone()
    }

    /// The policy of every [`BrowserContext::settle`] call, in order.
    #[must_use]
    pub fn settle_policies(&self) -> Vec<QuiescencePolicy> {
        self.inner.lock().settle_policies.clone()
    }

    /// Every [`BrowserContext::css_filter`] request received, in order.
    #[must_use]
    pub fn css_filters(&self) -> Vec<CssFilter> {
        self.inner.lock().css_filters.clone()
    }
}

#[async_trait]
impl BrowserContext for FakeContext {
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        let _entered = self.enter();
        if let Some(reason) = self.refusal(&url.url).await {
            let blocked = BlockedNavigation::new(crate::context::guard::loggable(&url.url), reason);
            self.inner.lock().refused_all.push(blocked.clone());
            return Err(blocked.into_error());
        }
        self.inner.lock().navigate(url.url.as_str())
    }

    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        let _entered = self.enter();
        loop {
            let deadline = self.inner.lock().prepare_popups()?;
            let Some(deadline) = deadline else { break };
            tokio::time::sleep_until(deadline).await;
        }
        self.inner.lock().observe(spec)
    }

    async fn revalidate(
        &mut self,
        locator: &RuntimeLocator,
        expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        let _entered = self.enter();
        Ok(self.inner.lock().revalidate(locator, expected))
    }

    async fn resolve_selector(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, BrowserError> {
        let _entered = self.enter();
        Ok(self.inner.lock().resolve_selector(selector))
    }

    async fn perform(&mut self, action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        if matches!(&action, BrowserAction::SolveCaptcha) {
            return Err(crawlx_core::captcha::CaptchaError::UnsupportedChallenge.into());
        }
        let _entered = self.enter();
        self.wait_performs_open().await;
        let refused = self.refusals_for(&action).await;
        self.inner.lock().perform(action, &refused)
    }

    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        let _entered = self.enter();
        Ok(self.inner.lock().settle(policy))
    }

    fn current_epoch(&self) -> ObservationEpoch {
        self.inner.lock().current_epoch()
    }

    fn drain_xhr(&mut self) -> Vec<XhrRecord> {
        std::mem::take(&mut self.inner.lock().xhr_queue)
    }

    fn drain_blocked_navigations(&mut self) -> Vec<BlockedNavigation> {
        std::mem::take(&mut self.inner.lock().refused_pending)
    }

    fn drain_traffic(&mut self) -> Vec<TrafficEvent> {
        let mut inner = self.inner.lock();
        let drained = std::mem::take(&mut inner.traffic);
        inner.traffic_drained += drained.len();
        drained
    }

    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError> {
        let _entered = self.enter();
        let inner = self.inner.lock();
        serde_json::to_vec(&inner.storage).map_err(|e| BrowserError::Io(e.to_string()))
    }

    async fn import_storage(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        let _entered = self.enter();
        self.inner.lock().import_storage(blob)
    }

    async fn page_op(&mut self, op: PageOp) -> Result<PageOpResult, BrowserError> {
        let _entered = self.enter();
        match op {
            PageOp::BlockUrls(patterns) => {
                self.inner.lock().block_urls(patterns);
                Ok(PageOpResult::Done)
            }
            PageOp::WaitForSelector {
                selector,
                state,
                timeout_ms,
            } => {
                let deadline =
                    tokio::time::Instant::now() + std::time::Duration::from_millis(u64::from(timeout_ms));
                loop {
                    if self.inner.lock().selector_state(&selector, state)? {
                        return Ok(PageOpResult::Found(true));
                    }
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        return Ok(PageOpResult::Found(false));
                    }
                    tokio::time::sleep(remaining.min(std::time::Duration::from_millis(100))).await;
                }
            }
            other => Err(BrowserError::Unsupported(format!(
                "page operation {}",
                other.name()
            ))),
        }
    }

    async fn lazy_scroll(&mut self, spec: LazyScrollSpec) -> Result<LazyScrollReport, BrowserError> {
        let _entered = self.enter();
        self.inner.lock().lazy_scroll(spec)
    }

    async fn css_filter(
        &mut self,
        filter: &CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, BrowserError> {
        let _entered = self.enter();
        self.inner.lock().css_filter(filter, targets)
    }

    async fn close(self: Box<Self>) -> Result<(), BrowserError> {
        {
            let mut inner = self.inner.lock();
            if !inner.closed {
                inner.closed = true;
                self.open.fetch_sub(1, Ordering::SeqCst);
            }
        }
        // `Drop` sees `closed` and does not decrement again
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Builder for [`FakeBackend`].
#[derive(Default)]
pub struct FakeBackendBuilder {
    script: FakeScript,
    clock: Option<Arc<dyn Clock>>,
    info: Option<BrowserBuildInfo>,
    epoch_base: u64,
    honours_guard: bool,
}

impl FakeBackendBuilder {
    /// Set the script served by the backend (default: empty).
    #[must_use]
    pub fn script(mut self, script: FakeScript) -> Self {
        self.script = script;
        self
    }

    /// Clock for timestamps; default [`SteppingClock`] (2026-01-01T00:00:00Z, +1 ms per call).
    #[must_use]
    pub fn clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Override the reported [`BrowserBuildInfo`]; default is a pinned fake Chromium 154 standard profile.
    #[must_use]
    pub fn build_info(mut self, info: BrowserBuildInfo) -> Self {
        self.info = Some(info);
        self
    }

    /// First network epoch id is `epoch_base + 1` (default `0`: ids `1, 2, ...`, so two
    /// identical runs produce identical bundles). Several fakes writing one database (the
    /// soak harness runs parallel worker loops over one PostgreSQL schema) need disjoint ids:
    /// give each a distinct base, e.g. `cycle << 32`.
    #[must_use]
    pub fn epoch_base(mut self, base: u64) -> Self {
        self.epoch_base = base;
        self
    }

    /// Make the contexts consult `ContextConfig::navigation_guard` before every document they
    /// load, as a real browser does, and report so through
    /// [`BrowserBackend::honours_navigation_guard`]. Off by default: scripted sites on made-up
    /// hosts have no `robots.txt` for the worker's gate to read, so the worker leaves the guard
    /// off for a backend that does not honour it.
    #[must_use]
    pub fn honour_navigation_guard(mut self) -> Self {
        self.honours_guard = true;
        self
    }

    /// Build the [`FakeBackend`], filling unset clock and build info with their defaults.
    #[must_use]
    pub fn build(self) -> FakeBackend {
        let (performs_open, _) = tokio::sync::watch::channel(true);
        FakeBackend {
            script: Arc::new(Mutex::new(self.script)),
            clock: self.clock.unwrap_or_else(|| Arc::new(SteppingClock::default())),
            info: self.info.unwrap_or_else(default_build_info),
            network_counter: Arc::new(AtomicU64::new(self.epoch_base)),
            contexts: Arc::new(AtomicUsize::new(0)),
            open: Arc::new(AtomicUsize::new(0)),
            in_flight: Arc::new(InFlight::default()),
            performs_open,
            held: Arc::new(InFlight::default()),
            handles: Arc::new(Mutex::new(Vec::new())),
            honours_guard: self.honours_guard,
        }
    }
}

/// Build info of the fake: the version and CDP revision of the workspace `chromium-pin.toml`
/// (embedded at build time), so the fake stays in step with the real pin. A malformed pin is
/// reported as an unpinned build rather than a panic in library code; `pin::tests` fail on it.
fn default_build_info() -> BrowserBuildInfo {
    let pin = repository_pin().ok();
    let chromium_version = pin
        .as_ref()
        .map_or_else(|| "0.0.0.0".to_owned(), |p| p.version.clone());
    let cdp_revision = pin.as_ref().map_or_else(
        || "fake-cdp".to_owned(),
        |p| format!("fake-cdp-{}", p.cdp_revision),
    );
    let major = parse_version(&chromium_version).map_or(0, |v| v[0]);
    BrowserBuildInfo {
        chromium_version,
        cdp_revision,
        user_agent: format!(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36" // wire-compat: standard user-agent token
        ),
        pinned: pin.is_some(),
        launch_profile: LaunchProfile::Standard,
        console_capture: true,
        attached: false,
    }
}

/// Scripted [`BrowserBackend`].
pub struct FakeBackend {
    script: Arc<Mutex<FakeScript>>,
    clock: Arc<dyn Clock>,
    info: BrowserBuildInfo,
    network_counter: Arc<AtomicU64>,
    contexts: Arc<AtomicUsize>,
    /// Contexts created and not yet closed or dropped.
    open: Arc<AtomicUsize>,
    /// Entries into action/navigation methods across every context of this backend.
    in_flight: Arc<InFlight>,
    /// `false` while [`FakeBackend::hold_performs`] parks every `perform`.
    performs_open: tokio::sync::watch::Sender<bool>,
    /// Performs parked on the hold right now.
    held: Arc<InFlight>,
    handles: Arc<Mutex<Vec<FakeContextHandle>>>,
    /// Contexts consult `ContextConfig::navigation_guard`
    /// ([`FakeBackendBuilder::honour_navigation_guard`]).
    honours_guard: bool,
}

impl fmt::Debug for FakeBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FakeBackend")
            .field("pages", &self.script.lock().pages.len())
            .field("contexts_created", &self.contexts_created())
            .finish()
    }
}

impl FakeBackend {
    /// Start a [`FakeBackendBuilder`] with an empty script, default clock and default build info.
    #[must_use]
    pub fn builder() -> FakeBackendBuilder {
        FakeBackendBuilder::default()
    }

    /// Backend with defaults and `script`.
    #[must_use]
    pub fn new(script: FakeScript) -> Self {
        Self::builder().script(script).build()
    }

    /// Shared script; mutate it while contexts are alive (changes apply to
    /// later navigations, revalidations and actions).
    #[must_use]
    pub fn script_handle(&self) -> Arc<Mutex<FakeScript>> {
        Arc::clone(&self.script)
    }

    /// Number of contexts created so far.
    #[must_use]
    pub fn contexts_created(&self) -> usize {
        self.contexts.load(Ordering::SeqCst)
    }

    /// Handles of all contexts created so far, in creation order (reachable
    /// even when the context was created through the boxed trait method).
    #[must_use]
    pub fn context_handles(&self) -> Vec<FakeContextHandle> {
        self.handles.lock().clone()
    }

    /// Contexts created and neither closed nor dropped.
    #[must_use]
    pub fn open_contexts(&self) -> usize {
        self.open.load(Ordering::SeqCst)
    }

    /// Action/navigation methods in progress right now across all contexts.
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight.current()
    }

    /// High-water mark of [`Self::in_flight`] since the backend was built; `1` means no two
    /// entries ever overlapped, on any context (single writer).
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.in_flight.max()
    }

    /// Park every `perform` of every context (after it counted as in flight) until
    /// [`Self::release_performs`]; a backpressure stand-in for a slow browser step.
    pub fn hold_performs(&self) {
        self.performs_open.send_replace(false);
    }

    /// Let held and future `perform`s run.
    pub fn release_performs(&self) {
        self.performs_open.send_replace(true);
    }

    /// Performs parked on [`Self::hold_performs`] right now.
    #[must_use]
    pub fn performs_held(&self) -> usize {
        self.held.current()
    }

    /// Concrete-typed context.
    #[must_use]
    pub fn new_fake_context(&self, config: ContextConfig) -> FakeContext {
        self.contexts.fetch_add(1, Ordering::SeqCst);
        self.open.fetch_add(1, Ordering::SeqCst);
        // a scripted site on a made-up host cannot answer the `robots.txt` lookups a guard
        // triggers: unless the test opted in, the context navigates unchecked
        let guard = self
            .honours_guard
            .then(|| config.navigation_guard.clone())
            .flatten();
        let ctx = FakeContext {
            guard,
            inner: Arc::new(Mutex::new(Inner::new(
                config,
                Arc::clone(&self.clock),
                Arc::clone(&self.script),
                Arc::clone(&self.network_counter),
            ))),
            in_flight: Arc::new(InFlight::default()),
            backend_in_flight: Arc::clone(&self.in_flight),
            open: Arc::clone(&self.open),
            performs_open: self.performs_open.subscribe(),
            held: Arc::clone(&self.held),
        };
        self.handles.lock().push(ctx.handle());
        ctx
    }
}

#[async_trait]
impl BrowserBackend for FakeBackend {
    async fn new_context(&self, config: ContextConfig) -> Result<Box<dyn BrowserContext>, BrowserError> {
        if config.captcha.is_some() {
            return Err(crawlx_core::captcha::CaptchaError::UnsupportedChallenge.into());
        }
        if config.response_bodies != crawlx_core::config::ResponseBodies::MetadataOnly {
            return Err(BrowserError::Unsupported(
                "fake browser cannot capture retained response bodies".to_owned(),
            ));
        }
        Ok(Box::new(self.new_fake_context(config)))
    }

    fn build_info(&self) -> &BrowserBuildInfo {
        &self.info
    }

    fn honours_navigation_guard(&self) -> bool {
        self.honours_guard
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::ids::SessionId;
    use crawlx_core::traffic::{Fidelity, TrustLane};
    use crawlx_core::{Modifiers, PointerButton, ScrollDelta, SecretOr};

    fn canon(s: &str) -> CanonicalUrl {
        Canonicalizer::canonicalize_url(&Url::parse(s).unwrap(), &CanonicalizeOptions::default()).unwrap()
    }

    fn site() -> FakeScript {
        FakeScript::new()
            .page(
                FakePage::new("https://example.test/")
                    .title("Home")
                    .html("<html>home</html>")
                    .link("/about")
                    .node(FakeAxSpec::new("nav", "navigation").name("Main"))
                    .node(FakeAxSpec::link("lnk-about", "About", "/about").parent("nav"))
                    .node(FakeAxSpec::button("btn-menu", "Menu"))
                    .node(FakeAxSpec::button("btn-popup", "Popup"))
                    .node(FakeAxSpec::button("btn-rename", "Rename"))
                    .node(FakeAxSpec::new("banner", "banner").name("Cookies"))
                    .node(FakeAxSpec::button("banner-ok", "OK").parent("banner"))
                    .node(FakeAxSpec::button("btn-dismiss", "Dismiss"))
                    .node(FakeAxSpec::textbox("txt-user", "User"))
                    .node(FakeAxSpec::checkbox("chk-tos", "Terms"))
                    .node(FakeAxSpec::new("sel-country", "combobox").name("Country"))
                    .node(FakeAxSpec::new("rng-vol", "slider").name("Volume"))
                    .on_click(
                        "lnk-about",
                        vec![FakeEffect::Navigate("https://example.test/about".to_owned())],
                    )
                    .on_click(
                        "btn-menu",
                        vec![FakeEffect::Reveal(vec![
                            FakeAxSpec::new("menu", "menu").name("Items"),
                            FakeAxSpec::button("mi-1", "Item 1").parent("menu"),
                        ])],
                    )
                    .on_click(
                        "btn-popup",
                        vec![FakeEffect::OpenTab("https://example.test/about".to_owned())],
                    )
                    .on_click(
                        "btn-rename",
                        vec![FakeEffect::SetName {
                            key: "btn-rename".to_owned(),
                            name: "Renamed".to_owned(),
                        }],
                    )
                    .on_click("btn-dismiss", vec![FakeEffect::Remove(vec!["banner".to_owned()])]),
            )
            .page(
                FakePage::new("https://example.test/about")
                    .title("About")
                    .html("<html>about</html>")
                    .node(FakeAxSpec::button("btn-back", "Back"))
                    .on_click("btn-back", vec![FakeEffect::Navigate("/".to_owned())]),
            )
    }

    struct Rig {
        backend: FakeBackend,
        ctx: FakeContext,
        handle: FakeContextHandle,
    }

    fn rig_with(script: FakeScript, config: ContextConfig) -> Rig {
        let backend = FakeBackend::new(script);
        let ctx = backend.new_fake_context(config);
        let handle = ctx.handle();
        Rig { backend, ctx, handle }
    }

    fn rig() -> Rig {
        rig_with(site(), ContextConfig::new(SessionId::new()))
    }

    async fn home(rig: &mut Rig) -> ObservationBundle {
        rig.ctx.navigate(&canon("https://example.test/")).await.unwrap();
        rig.ctx.observe(ObservationSpec::default()).await.unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn selector_waits_use_first_live_match_visibility_and_bounded_timeout() {
        let script = FakeScript::new().page(
            FakePage::new("https://example.test/")
                .node(FakeAxSpec::button("visible", "Visible").disabled())
                .node(
                    FakeAxSpec::button("hidden", "Hidden")
                        .hidden()
                        .attr("class", "same"),
                )
                .node(FakeAxSpec::button("second", "Second").attr("class", "same"))
                .node(FakeAxSpec::button("zero-width", "Zero").bbox(0.0, 0.0, 0.0, 10.0))
                .node(FakeAxSpec::button("zero-height", "Zero").bbox(0.0, 0.0, 10.0, 0.0)),
        );
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        home(&mut rig).await;
        let wait = |selector: &str, state, timeout_ms| PageOp::WaitForSelector {
            selector: selector.to_owned(),
            state,
            timeout_ms,
        };
        for (selector, state, expected) in [
            ("#hidden", SelectorState::Attached, true),
            ("#visible", SelectorState::Visible, true),
            ("#hidden", SelectorState::Visible, false),
            ("#zero-width", SelectorState::Visible, false),
            ("#zero-height", SelectorState::Visible, false),
            (".same", SelectorState::Visible, false),
            (".same", SelectorState::Hidden, true),
            ("#missing", SelectorState::Hidden, true),
            ("#missing", SelectorState::Detached, true),
            ("#hidden", SelectorState::Detached, false),
            ("#visible", SelectorState::Hidden, false),
        ] {
            assert_eq!(
                rig.ctx.page_op(wait(selector, state, 0)).await.unwrap(),
                PageOpResult::Found(expected),
                "{selector}: {state:?}"
            );
        }
        for state in [
            SelectorState::Attached,
            SelectorState::Visible,
            SelectorState::Hidden,
            SelectorState::Detached,
        ] {
            assert!(matches!(
                rig.ctx.page_op(wait("div[", state, 100)).await,
                Err(BrowserError::Script(_))
            ));
        }
        let started = tokio::time::Instant::now();
        assert_eq!(
            rig.ctx
                .page_op(wait("#missing", SelectorState::Visible, 300))
                .await
                .unwrap(),
            PageOpResult::Found(false)
        );
        assert_eq!(started.elapsed(), std::time::Duration::from_millis(300));
        rig.backend
            .script_handle()
            .lock()
            .detached
            .insert("visible".to_owned());
        assert_eq!(
            rig.ctx
                .page_op(wait("#visible", SelectorState::Detached, 0))
                .await
                .unwrap(),
            PageOpResult::Found(true)
        );
    }

    fn node<'a>(b: &'a ObservationBundle, key: &str) -> &'a AxNode {
        b.ax.nodes
            .iter()
            .find(|n| n.locator.ax_node_id.as_ref().is_some_and(|a| a.0 == key))
            .unwrap()
    }

    fn loc(b: &ObservationBundle, key: &str) -> RuntimeLocator {
        node(b, key).locator.clone()
    }

    #[tokio::test]
    async fn selectors_resolve_by_key_name_text_and_attribute() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        let resolve = |kind, expr: &str| DomSelector {
            kind,
            expr: expr.to_owned(),
        };
        let css = rig
            .ctx
            .resolve_selector(&resolve(DomSelectorKind::Css, "#txt-user"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(css, loc(&b, "txt-user"));
        let aria = rig
            .ctx
            .resolve_selector(&resolve(DomSelectorKind::Aria, "menu[role=\"button\"]"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(aria, loc(&b, "btn-menu"));
        assert!(rig
            .ctx
            .resolve_selector(&resolve(DomSelectorKind::Aria, "Menu[role=\"link\"]"))
            .await
            .unwrap()
            .is_none());
        let text = rig
            .ctx
            .resolve_selector(&resolve(DomSelectorKind::Text, "Rena"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(text, loc(&b, "btn-rename"));
        assert!(rig
            .ctx
            .resolve_selector(&resolve(DomSelectorKind::XPath, "//nope"))
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn hooks_feed_is_reported_once_per_load_and_only_with_hooks_on() {
        let script = FakeScript::new().page(
            FakePage::new("https://example.test/")
                .discovered("/api/items", "fetch")
                .discovered("/next", "pushState"),
        );
        let mut off = rig_with(script.clone(), ContextConfig::new(SessionId::new()));
        assert!(home(&mut off).await.discovered_urls.is_empty());
        let mut cfg = ContextConfig::new(SessionId::new());
        cfg.page_hooks = true;
        let mut on = rig_with(script, cfg);
        on.ctx.navigate(&canon("https://example.test/")).await.unwrap();
        let safety = on
            .ctx
            .observe(ObservationSpec {
                revalidation_only: true,
                ..ObservationSpec::default()
            })
            .await
            .unwrap();
        assert!(safety.discovered_urls.is_empty());
        let first = on.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(first.seq, safety.seq + 1);
        assert_eq!(
            first.discovered_urls,
            vec![
                ("/api/items".to_owned(), "fetch".to_owned()),
                ("/next".to_owned(), "pushState".to_owned())
            ]
        );
        let second = on.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert!(second.discovered_urls.is_empty());
        assert!(!home(&mut on).await.discovered_urls.is_empty());
    }

    #[tokio::test]
    async fn set_storage_effect_changes_the_exported_blob() {
        let script = FakeScript::new().page(
            FakePage::new("https://example.test/")
                .node(FakeAxSpec::button("go", "Go"))
                .on_click(
                    "go",
                    vec![FakeEffect::SetStorage(BTreeMap::from([(
                        "sid".to_owned(),
                        "abc".to_owned(),
                    )]))],
                ),
        );
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        let b = home(&mut rig).await;
        let before = rig.ctx.export_storage().await.unwrap();
        rig.ctx.perform(click(loc(&b, "go"))).await.unwrap();
        let after = rig.ctx.export_storage().await.unwrap();
        assert_ne!(before, after);
        assert_eq!(String::from_utf8(after).unwrap(), "{\"sid\":\"abc\"}");
    }

    fn click(target: RuntimeLocator) -> BrowserAction {
        BrowserAction::Click {
            target,
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        }
    }

    fn ep(n: u64, d: u64, m: u64) -> ObservationEpoch {
        ObservationEpoch {
            navigation_seq: n,
            document_seq: d,
            mutation_seq: m,
        }
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in data {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        !c
    }

    #[tokio::test]
    async fn navigate_observe_round_trip() {
        let mut rig = rig();
        let nav = rig.ctx.navigate(&canon("https://example.test/")).await.unwrap();
        assert_eq!(nav.final_url, "https://example.test/");
        assert_eq!(nav.status, Some(200));
        assert_eq!(nav.epoch, ep(1, 1, 0));
        assert!(nav.redirects.is_empty() && nav.blocked_by_egress.is_empty());

        let b = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(b.epoch, ep(1, 1, 0));
        assert_eq!(b.seq, 1);
        assert_eq!(b.html.as_deref(), Some("<html>home</html>"));
        assert_eq!(b.title.as_deref(), Some("Home"));
        assert_eq!(b.url.url.as_str(), "https://example.test/");
        assert_eq!(b.viewport, ContextConfig::new(SessionId::new()).viewport);
        assert_eq!(b.frames.len(), 1);
        assert_eq!(b.frames[0].id.0, "main");
        assert!(b.frames[0].lineage.is_empty());
        assert_eq!(b.tabs.len(), 1);
        assert!(b.tabs[0].active && b.tabs[0].opener.is_none());
        assert!(b.captured_at >= Timestamp::from_timestamp_millis(DEFAULT_START_MS).unwrap());

        assert_eq!(node(&b, "btn-menu").name.as_deref(), Some("Menu"));
        assert_eq!(node(&b, "btn-menu").role, "button");
        // pre-order: the link follows its parent navigation node directly
        let keys: Vec<&str> =
            b.ax.nodes
                .iter()
                .filter_map(|n| n.locator.ax_node_id.as_ref().map(|a| a.0.as_str()))
                .collect();
        assert_eq!(&keys[..3], ["nav", "lnk-about", "btn-menu"]);
        assert_eq!(node(&b, "lnk-about").parent, Some(AxNodeId("nav".to_owned())));
        assert_eq!(node(&b, "nav").children, vec![AxNodeId("lnk-about".to_owned())]);
        assert_eq!(
            node(&b, "banner").children,
            vec![AxNodeId("banner-ok".to_owned())]
        );
        // only href leaks into properties
        assert_eq!(
            node(&b, "lnk-about").properties.get("href").map(String::as_str),
            Some("/about")
        );
        assert!(node(&b, "btn-menu").properties.is_empty());
        for n in &b.ax.nodes {
            assert_eq!(n.locator.epoch, b.epoch);
            assert_eq!(n.locator.frame.0, "main");
            assert_eq!(n.locator.tab, b.tab);
            assert!(n.locator.object_id.is_none());
        }
        let second = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(second.seq, 2);
        assert!(second.captured_at > b.captured_at);
    }

    #[tokio::test]
    async fn backend_node_ids_are_stable_and_index_derived() {
        let mut rig = rig();
        let first = home(&mut rig).await;
        let second = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(loc(&first, "nav").backend_node_id, BackendNodeId(1));
        assert_eq!(loc(&first, "lnk-about").backend_node_id, BackendNodeId(2));
        assert_eq!(loc(&first, "btn-menu").backend_node_id, BackendNodeId(3));
        for n in &first.ax.nodes {
            let key = n.locator.ax_node_id.as_ref().unwrap().0.clone();
            assert_eq!(n.locator.backend_node_id, loc(&second, &key).backend_node_id);
        }
        // distinct default boxes
        let boxes: BTreeSet<String> = first
            .ax
            .nodes
            .iter()
            .map(|n| format!("{:?}", n.bbox.unwrap()))
            .collect();
        assert_eq!(boxes.len(), first.ax.nodes.len());
        // reveals get fresh ids after the existing ones
        let n = i64::try_from(first.ax.nodes.len()).unwrap();
        rig.ctx.perform(click(loc(&first, "btn-menu"))).await.unwrap();
        let third = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(loc(&third, "menu").backend_node_id, BackendNodeId(n + 1));
        assert_eq!(loc(&third, "mi-1").backend_node_id, BackendNodeId(n + 2));
        assert_eq!(loc(&third, "btn-menu").backend_node_id, BackendNodeId(3));
    }

    #[tokio::test]
    async fn epoch_bump_rules() {
        let mut rig = rig();
        assert_eq!(rig.ctx.current_epoch(), ep(0, 0, 0));
        let b = home(&mut rig).await;
        assert_eq!(rig.ctx.current_epoch(), ep(1, 1, 0));
        // reveal bumps mutation only, by the number of nodes added
        rig.ctx.perform(click(loc(&b, "btn-menu"))).await.unwrap();
        assert_eq!(rig.ctx.current_epoch(), ep(1, 1, 2));
        // a scripted no-op changes nothing
        rig.ctx
            .perform(BrowserAction::Keys { sequence: vec![] })
            .await
            .unwrap();
        assert_eq!(rig.ctx.current_epoch(), ep(1, 1, 2));
        // navigation bumps nav+doc and resets mutation
        rig.ctx.perform(click(loc(&b, "lnk-about"))).await.unwrap();
        assert_eq!(rig.ctx.current_epoch(), ep(2, 2, 0));
        assert_eq!(rig.handle.epoch(), ep(2, 2, 0));
        rig.ctx.navigate(&canon("https://example.test/")).await.unwrap();
        assert_eq!(rig.ctx.current_epoch(), ep(3, 3, 0));
    }

    #[tokio::test]
    async fn click_navigate_transition() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        rig.ctx.perform(click(loc(&b, "lnk-about"))).await.unwrap();
        let about = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(about.url.url.as_str(), "https://example.test/about");
        assert_eq!(about.title.as_deref(), Some("About"));
        assert_eq!(about.html.as_deref(), Some("<html>about</html>"));
        assert_eq!(about.ax.nodes.len(), 1);
        // relative Navigate effect resolves against the current URL
        rig.ctx.perform(click(loc(&about, "btn-back"))).await.unwrap();
        assert_eq!(rig.handle.current_url(), "https://example.test/");
        assert_eq!(
            rig.handle.navigations(),
            vec!["https://example.test/", "https://example.test/about", "/"]
        );
    }

    #[tokio::test]
    async fn click_reveal_and_remove_transitions() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        rig.ctx.perform(click(loc(&b, "btn-menu"))).await.unwrap();
        let safety = rig
            .ctx
            .observe(ObservationSpec {
                revalidation_only: true,
                ..ObservationSpec::default()
            })
            .await
            .unwrap();
        assert_eq!(safety.seq, b.seq);
        let after_reveal = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(after_reveal.ax.nodes.len(), b.ax.nodes.len() + 2);
        assert_eq!(
            node(&after_reveal, "mi-1").parent,
            Some(AxNodeId("menu".to_owned()))
        );
        assert_eq!(
            node(&after_reveal, "menu").children,
            vec![AxNodeId("mi-1".to_owned())]
        );
        assert_eq!(after_reveal.mutation.added_nodes, 2);
        assert_eq!(after_reveal.mutation.added_nodes, safety.mutation.added_nodes);
        assert_eq!(after_reveal.mutation.records, 2);

        rig.ctx.perform(click(loc(&b, "btn-dismiss"))).await.unwrap();
        // removing a parent removes its descendants: banner + banner-ok
        assert_eq!(rig.handle.epoch(), ep(1, 1, 4));
        assert!(!rig
            .handle
            .live_keys()
            .iter()
            .any(|k| k == "banner" || k == "banner-ok"));
        let after_remove = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(after_remove.mutation.removed_nodes, 2);
        assert_eq!(after_remove.mutation.records, 2);
        // the delta resets with each observation
        let quiet = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(quiet.mutation, MutationStats::default());
    }

    #[tokio::test]
    async fn set_name_effect_changes_observed_name() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        rig.ctx.perform(click(loc(&b, "btn-rename"))).await.unwrap();
        let after = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(node(&after, "btn-rename").name.as_deref(), Some("Renamed"));
        assert_eq!(after.epoch, ep(1, 1, 1));
        assert_eq!(after.mutation.text_changes, 1);
    }

    #[tokio::test]
    async fn revalidate_script_flags() {
        let script = FakeScript::new()
            .page(
                FakePage::new("https://example.test/")
                    .node(
                        FakeAxSpec::button("ok", "Ok")
                            .attr("aria-pressed", "false")
                            .bbox(10.0, 20.0, 100.0, 40.0),
                    )
                    .node(FakeAxSpec::button("stale", "S"))
                    .node(FakeAxSpec::button("obscured", "O"))
                    .node(FakeAxSpec::button("unstable", "U"))
                    .node(FakeAxSpec::button("idchg", "I"))
                    .node(FakeAxSpec::button("detached", "D"))
                    .node(FakeAxSpec::button("hidden", "H").hidden())
                    .node(FakeAxSpec::button("disabled", "X").disabled())
                    .node(FakeAxSpec::button("both", "B").hidden().disabled())
                    .node(FakeAxSpec::button("gone", "G"))
                    .node(FakeAxSpec::button("remover", "R"))
                    .on_click("remover", vec![FakeEffect::Remove(vec!["gone".to_owned()])]),
            )
            .stale("stale")
            .obscured("obscured")
            .unstable("unstable")
            .identity_changed("idchg")
            .detached("detached")
            .stale("detached");
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        let b = home(&mut rig).await;
        let e = b.epoch;

        let r = rig.ctx.revalidate(&loc(&b, "stale"), e).await.unwrap();
        assert_eq!(r, Revalidation::StaleEpoch { current: e });
        let r = rig.ctx.revalidate(&loc(&b, "obscured"), e).await.unwrap();
        assert!(matches!(
            r,
            Revalidation::Obscured {
                by_backend_node_id: Some(_)
            }
        ));
        assert_eq!(
            rig.ctx.revalidate(&loc(&b, "unstable"), e).await.unwrap(),
            Revalidation::Unstable
        );
        assert_eq!(
            rig.ctx.revalidate(&loc(&b, "idchg"), e).await.unwrap(),
            Revalidation::IdentityChanged
        );
        // detached wins over stale
        assert_eq!(
            rig.ctx.revalidate(&loc(&b, "detached"), e).await.unwrap(),
            Revalidation::Detached
        );
        assert_eq!(
            rig.ctx.revalidate(&loc(&b, "hidden"), e).await.unwrap(),
            Revalidation::NotVisible
        );
        assert_eq!(
            rig.ctx.revalidate(&loc(&b, "disabled"), e).await.unwrap(),
            Revalidation::Disabled
        );
        // hidden wins over disabled
        assert_eq!(
            rig.ctx.revalidate(&loc(&b, "both"), e).await.unwrap(),
            Revalidation::NotVisible
        );
        // a node removed from the live page is detached; mutation drift alone is not stale
        rig.ctx.perform(click(loc(&b, "remover"))).await.unwrap();
        assert_eq!(
            rig.ctx.revalidate(&loc(&b, "gone"), e).await.unwrap(),
            Revalidation::Detached
        );
        let ok = rig.ctx.revalidate(&loc(&b, "ok"), e).await.unwrap();
        assert!(matches!(ok, Revalidation::Actionable { .. }));
    }

    #[tokio::test]
    async fn revalidate_actionable_reports_live_facts() {
        let script = FakeScript::new().page(
            FakePage::new("https://example.test/").node(
                FakeAxSpec::link("l", "Docs", "https://example.test/docs")
                    .attr("aria-haspopup", "menu")
                    .bbox(10.0, 20.0, 100.0, 40.0),
            ),
        );
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        let b = home(&mut rig).await;
        let Revalidation::Actionable { live } = rig.ctx.revalidate(&loc(&b, "l"), b.epoch).await.unwrap()
        else {
            panic!("expected actionable");
        };
        assert_eq!(live.role.as_deref(), Some("link"));
        assert_eq!(live.name.as_deref(), Some("Docs"));
        assert_eq!(live.tag.as_deref(), Some("a"));
        assert_eq!(live.href.as_deref(), Some("https://example.test/docs"));
        assert_eq!(live.current_url, "https://example.test/");
        assert!(live.frame_url.is_none());
        assert_eq!(
            live.bbox,
            BoundingBox {
                x: 10.0,
                y: 20.0,
                width: 100.0,
                height: 40.0
            }
        );
        assert_eq!(live.hit_points.len(), 5);
        for (x, y) in &live.hit_points {
            assert!(*x > 10.0 && *x < 110.0 && *y > 20.0 && *y < 60.0);
        }
        assert_eq!(live.hit_points[0], (60.0, 40.0));
        assert_eq!(live.attributes.len(), 1);
        assert_eq!(
            live.attributes.get("aria-haspopup").map(String::as_str),
            Some("menu")
        );
    }

    #[tokio::test]
    async fn stale_locator_after_navigation() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        let old = loc(&b, "btn-menu");
        rig.ctx.perform(click(loc(&b, "lnk-about"))).await.unwrap();
        let current = ep(2, 2, 0);

        let r = rig.ctx.revalidate(&old, b.epoch).await.unwrap();
        assert_eq!(r, Revalidation::StaleEpoch { current });
        // a fresh locator with a stale `expected` is stale too
        let about = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        let r = rig
            .ctx
            .revalidate(&loc(&about, "btn-back"), b.epoch)
            .await
            .unwrap();
        assert_eq!(r, Revalidation::StaleEpoch { current });
        let r = rig
            .ctx
            .revalidate(&loc(&about, "btn-back"), about.epoch)
            .await
            .unwrap();
        assert!(matches!(r, Revalidation::Actionable { .. }));

        let err = rig.ctx.perform(click(old)).await.unwrap_err();
        assert!(matches!(err, BrowserError::StaleLocator(e) if e == current));
        // the failed attempt is still logged
        assert_eq!(rig.handle.performed(), vec![ActionKind::Click, ActionKind::Click]);
    }

    #[tokio::test]
    async fn performed_log_records_kinds_and_keys() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        rig.ctx.perform(click(loc(&b, "btn-rename"))).await.unwrap();
        rig.ctx
            .perform(BrowserAction::Hover {
                target: loc(&b, "btn-menu"),
            })
            .await
            .unwrap();
        rig.ctx
            .perform(BrowserAction::Scroll {
                container: None,
                delta: ScrollDelta { dx: 0.0, dy: 100.0 },
            })
            .await
            .unwrap();
        rig.ctx
            .perform(BrowserAction::Keys { sequence: vec![] })
            .await
            .unwrap();
        let expected = vec![
            ActionKind::Click,
            ActionKind::Hover,
            ActionKind::Scroll,
            ActionKind::Keys,
        ];
        assert_eq!(rig.ctx.performed(), expected);
        assert_eq!(rig.handle.performed(), expected);
        assert_eq!(
            rig.handle.performed_keys(),
            vec!["click:btn-rename", "hover:btn-menu", "scroll:", "keys:"]
        );
        assert_eq!(action_key(ActionKind::Click, "x"), "click:x");
    }

    #[tokio::test]
    async fn synthetic_click_needs_permission() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        let err = rig
            .ctx
            .perform(BrowserAction::SyntheticClick {
                target: loc(&b, "btn-menu"),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, BrowserError::Unsupported(_)));
        assert_eq!(rig.handle.epoch(), b.epoch);

        let mut config = ContextConfig::new(SessionId::new());
        config.synthetic_click_allowed = true;
        let mut allowed = rig_with(site(), config);
        let b = home(&mut allowed).await;
        let receipt = allowed
            .ctx
            .perform(BrowserAction::SyntheticClick {
                target: loc(&b, "btn-menu"),
            })
            .await
            .unwrap();
        assert_eq!(receipt.fidelity, Fidelity::SyntheticDomEvent);
        assert_eq!(receipt.lane, TrustLane::Diagnostic);
        assert_eq!(allowed.handle.performed(), vec![ActionKind::SyntheticClick]);
        // transitions are keyed by action kind: no `synthetic_click:btn-menu` script, no effect
        assert_eq!(allowed.handle.epoch(), ep(1, 1, 0));
    }

    #[tokio::test]
    async fn fail_actions_and_crash_on() {
        let script = site()
            .fail_action(action_key(ActionKind::Click, "btn-menu"), "boom")
            .crash_on(action_key(ActionKind::Click, "btn-rename"));
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        let b = home(&mut rig).await;
        let err = rig.ctx.perform(click(loc(&b, "btn-menu"))).await.unwrap_err();
        assert!(matches!(&err, BrowserError::Script(m) if m == "boom"));
        assert!(!err.is_target_crash());
        let err = rig.ctx.perform(click(loc(&b, "btn-rename"))).await.unwrap_err();
        assert!(matches!(err, BrowserError::TargetCrashed));
        assert!(err.is_target_crash());
        // untouched keys still work and the failed actions had no effect
        assert_eq!(rig.handle.epoch(), b.epoch);
        rig.ctx.perform(click(loc(&b, "btn-dismiss"))).await.unwrap();
        assert_eq!(rig.handle.performed().len(), 3);
    }

    #[tokio::test]
    async fn popup_tab_switch_and_close() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        let first_tab = rig.handle.current_tab();
        rig.ctx.perform(click(loc(&b, "btn-popup"))).await.unwrap();
        // popup opens in the background; the current tab and its epoch are untouched
        assert_eq!(rig.handle.tab_ids().len(), 2);
        assert_eq!(rig.handle.current_tab(), first_tab);
        assert_eq!(rig.handle.epoch(), b.epoch);
        let seen = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(seen.tabs.len(), 2);
        let popup = seen.tabs.iter().find(|t| t.id != first_tab).unwrap().clone();
        assert_eq!(popup.opener, Some(first_tab.clone()));
        assert_eq!(popup.url, "https://example.test/about");
        assert!(!popup.active);

        rig.ctx
            .perform(BrowserAction::SwitchTab {
                tab: popup.id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(rig.handle.current_tab(), popup.id);
        let on_popup = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(on_popup.tab, popup.id);
        assert_eq!(on_popup.title.as_deref(), Some("About"));
        assert_eq!(on_popup.epoch, ep(1, 1, 0));
        assert!(on_popup.tabs.iter().any(|t| t.id == popup.id && t.active));
        // a locator from the first tab is still valid against that tab's own epoch
        let r = rig.ctx.revalidate(&loc(&b, "btn-menu"), b.epoch).await.unwrap();
        assert!(matches!(r, Revalidation::Actionable { .. }));

        rig.ctx
            .perform(BrowserAction::CloseTab {
                tab: popup.id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(rig.handle.current_tab(), first_tab);
        assert_eq!(rig.handle.tab_ids(), vec![first_tab.clone()]);
        let err = rig
            .ctx
            .perform(BrowserAction::CloseTab {
                tab: first_tab.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, BrowserError::Unsupported(_)));
        let err = rig
            .ctx
            .perform(BrowserAction::SwitchTab { tab: popup.id })
            .await
            .unwrap_err();
        assert!(matches!(err, BrowserError::TargetClosed));
        assert_eq!(
            rig.handle
                .performed_keys()
                .iter()
                .filter(|k| *k == "switch_tab:" || *k == "close_tab:")
                .count(),
            4
        );
    }

    #[tokio::test]
    async fn popup_respects_tab_limit_and_unscripted_url() {
        let mut config = ContextConfig::new(SessionId::new());
        config.max_tabs = 1;
        let mut limited = rig_with(site(), config);
        let b = home(&mut limited).await;
        limited.ctx.perform(click(loc(&b, "btn-popup"))).await.unwrap();
        let seen = limited.ctx.observe(ObservationSpec::default()).await.unwrap();
        let pending = seen.tabs.iter().find(|t| t.pending).unwrap();
        let err = limited
            .ctx
            .perform(BrowserAction::SwitchTab {
                tab: pending.id.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, BrowserError::TabLimit(1)));

        let script = FakeScript::new().page(
            FakePage::new("https://example.test/")
                .node(FakeAxSpec::button("p", "P"))
                .on_click("p", vec![FakeEffect::OpenTab("https://other.test/x".to_owned())]),
        );
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        let b = home(&mut rig).await;
        rig.ctx.perform(click(loc(&b, "p"))).await.unwrap();
        let seen = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert!(seen.tabs.iter().any(|t| t.url == "https://other.test/x"));
        // switching to an unloaded popup works, observing it does not
        let popup = seen.tabs.iter().find(|t| !t.active).unwrap().id.clone();
        rig.ctx
            .perform(BrowserAction::SwitchTab { tab: popup })
            .await
            .unwrap();
        assert!(matches!(
            rig.ctx.observe(ObservationSpec::default()).await,
            Err(BrowserError::Navigation(_))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn blank_popup_waits_for_first_navigation_but_never_more_than_two_seconds() {
        for (delay_ms, expected, elapsed) in [
            (500, "https://example.test/child", 500),
            (2500, "about:blank", 2000),
        ] {
            let script = FakeScript::new()
                .page(
                    FakePage::new("https://example.test/")
                        .node(FakeAxSpec::button("open", "Open"))
                        .on_click(
                            "open",
                            vec![FakeEffect::OpenBlankThenNavigate {
                                url: "https://example.test/child".to_owned(),
                                delay_ms,
                            }],
                        ),
                )
                .page(FakePage::new("https://example.test/child"));
            let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
            let b = home(&mut rig).await;
            rig.ctx.perform(click(loc(&b, "open"))).await.unwrap();
            let started = tokio::time::Instant::now();
            let seen = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
            assert_eq!(started.elapsed(), std::time::Duration::from_millis(elapsed));
            assert_eq!(seen.tabs.iter().find(|t| !t.active).unwrap().url, expected);
            // An unchanged blank URL does not get a fresh two-second wait each round.
            if delay_ms > 2000 {
                let again = tokio::time::Instant::now();
                rig.ctx.observe(ObservationSpec::default()).await.unwrap();
                assert_eq!(again.elapsed(), std::time::Duration::ZERO);
            }
        }
    }

    #[tokio::test]
    async fn pending_popup_admits_only_after_diagnostic_close_frees_capacity() {
        let script = FakeScript::new().page(
            FakePage::new("https://example.test/")
                .node(FakeAxSpec::button("open", "Open"))
                .on_click(
                    "open",
                    vec![
                        FakeEffect::OpenTab("https://example.test/old".to_owned()),
                        FakeEffect::OpenTab("https://example.test/new".to_owned()),
                    ],
                ),
        );
        let mut config = ContextConfig::new(SessionId::new());
        config.max_tabs = 2;
        let mut rig = rig_with(script, config);
        let b = home(&mut rig).await;
        rig.ctx.perform(click(loc(&b, "open"))).await.unwrap();
        let seen = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        let victim = seen.tabs.iter().find(|t| t.url.ends_with("/old")).unwrap();
        let pending = seen.tabs.iter().find(|t| t.pending).unwrap();
        assert!(matches!(
            rig.ctx
                .perform(BrowserAction::SwitchTab {
                    tab: pending.id.clone()
                })
                .await,
            Err(BrowserError::TabLimit(2))
        ));
        let receipt = rig
            .ctx
            .perform(BrowserAction::CloseTab {
                tab: victim.id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(receipt.lane, TrustLane::Diagnostic);
        rig.ctx
            .perform(BrowserAction::SwitchTab {
                tab: pending.id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(rig.handle.current_tab(), pending.id);
    }

    #[tokio::test]
    async fn download_and_external_windows_are_recorded_before_closing() {
        let script = FakeScript::new().page(
            FakePage::new("https://example.test/")
                .node(FakeAxSpec::button("open", "Open"))
                .on_click(
                    "open",
                    vec![
                        FakeEffect::OpenDownload("https://example.test/report.csv".to_owned()),
                        FakeEffect::OpenTab("https://external.test/window".to_owned()),
                    ],
                ),
        );
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        let b = home(&mut rig).await;
        rig.ctx.perform(click(loc(&b, "open"))).await.unwrap();
        let seen = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert!(seen
            .tabs
            .iter()
            .any(|t| t.download && t.url.ends_with("/report.csv")));
        assert!(seen.tabs.iter().any(|t| t.url == "https://external.test/window"));
        for popup in seen.tabs.iter().filter(|t| !t.active) {
            let receipt = rig
                .ctx
                .perform(BrowserAction::CloseTab {
                    tab: popup.id.clone(),
                })
                .await
                .unwrap();
            assert_eq!(receipt.lane, TrustLane::Diagnostic);
        }
        let after = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(after.tabs.len(), 1);
        assert_eq!(after.tab, b.tab);
    }

    #[tokio::test]
    async fn typed_secret_never_leaks() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        let target = loc(&b, "txt-user");
        let secret = SecretOr::secret("hunter2".to_owned());
        let action = BrowserAction::Type {
            target: target.clone(),
            value: secret,
            clear_first: true,
        };
        assert!(!format!("{action:?}").contains("hunter2"));
        let receipt = rig.ctx.perform(action).await.unwrap();
        assert_eq!(receipt.fidelity, Fidelity::NativeTextInput);
        assert_eq!(receipt.lane, TrustLane::TrustedUi);

        let after = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        let rendered = [
            format!("{receipt:?}"),
            format!("{after:?}"),
            format!("{:?}", rig.handle),
            format!("{:?}", rig.ctx),
            format!("{:?}", rig.handle.performed_keys()),
            format!("{:?}", rig.handle.typed_inputs()),
            format!("{:?}", rig.backend),
            format!("{:?}", rig.ctx.drain_traffic()),
        ]
        .join("\n");
        assert!(!rendered.contains("hunter2"));
        assert_eq!(
            node(&after, "txt-user").value.as_deref(),
            Some("\u{2022}".repeat(7).as_str())
        );
        assert_eq!(after.epoch, ep(1, 1, 1));
        let typed = rig.handle.typed_inputs();
        assert_eq!(
            typed,
            vec![TypedInput {
                key: "txt-user".to_owned(),
                chars: 7,
                secret: true,
                text: None
            }]
        );

        // plain text is stored; clear_first=false appends, true replaces
        for (text, clear) in [("ab", true), ("cd", false)] {
            let value = SecretOr::Plain(text.to_owned());
            rig.ctx
                .perform(BrowserAction::Type {
                    target: target.clone(),
                    value,
                    clear_first: clear,
                })
                .await
                .unwrap();
        }
        let after = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(node(&after, "txt-user").value.as_deref(), Some("abcd"));
        assert_eq!(
            rig.handle.typed_inputs().last().unwrap().text.as_deref(),
            Some("cd")
        );
    }

    #[tokio::test]
    async fn state_changing_actions_update_live_nodes() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        assert_eq!(node(&b, "chk-tos").checked.as_deref(), Some("false"));
        rig.ctx
            .perform(BrowserAction::SetChecked {
                target: loc(&b, "chk-tos"),
                checked: true,
            })
            .await
            .unwrap();
        rig.ctx
            .perform(BrowserAction::Select {
                target: loc(&b, "sel-country"),
                options: vec![OptionKey::Value("nl".to_owned())],
            })
            .await
            .unwrap();
        rig.ctx
            .perform(BrowserAction::SetRange {
                target: loc(&b, "rng-vol"),
                value: 7.0,
            })
            .await
            .unwrap();
        let after = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(node(&after, "chk-tos").checked.as_deref(), Some("true"));
        assert_eq!(node(&after, "sel-country").value.as_deref(), Some("nl"));
        assert_eq!(node(&after, "rng-vol").value.as_deref(), Some("7"));
        assert_eq!(after.epoch, ep(1, 1, 3));
        assert_eq!(after.mutation.attribute_changes, 3);
        assert_eq!(after.mutation.records, 3);
        // the state change is per document: navigating resets it
        rig.ctx.navigate(&canon("https://example.test/")).await.unwrap();
        let fresh = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(node(&fresh, "chk-tos").checked.as_deref(), Some("false"));
        // a state change on a node that is gone is a protocol error, not silent
        let err = rig
            .ctx
            .perform(BrowserAction::SetChecked {
                target: RuntimeLocator {
                    ax_node_id: Some(AxNodeId("missing".to_owned())),
                    ..loc(&fresh, "chk-tos")
                },
                checked: true,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, BrowserError::Protocol { .. }));
    }

    #[tokio::test]
    async fn storage_export_import_round_trip() {
        let mut rig = rig();
        assert_eq!(rig.ctx.export_storage().await.unwrap(), b"{}");
        let mut map = BTreeMap::new();
        map.insert("sid".to_owned(), "abc".to_owned());
        map.insert("theme".to_owned(), "dark".to_owned());
        rig.handle.set_storage(map);
        let blob = rig.ctx.export_storage().await.unwrap();
        assert_eq!(
            String::from_utf8(blob.clone()).unwrap(),
            r#"{"sid":"abc","theme":"dark"}"#
        );

        let mut other = rig.backend.new_fake_context(ContextConfig::new(SessionId::new()));
        assert_eq!(other.export_storage().await.unwrap(), b"{}");
        other.import_storage(&blob).await.unwrap();
        assert_eq!(other.export_storage().await.unwrap(), blob);
        assert_eq!(other.handle().storage().len(), 2);
        assert!(matches!(
            other.import_storage(b"not json").await,
            Err(BrowserError::Io(_))
        ));
        assert_eq!(other.export_storage().await.unwrap(), blob);
    }

    #[tokio::test]
    async fn two_identical_runs_are_equal() {
        async fn run(
            session: SessionId,
        ) -> (
            Vec<ObservationBundle>,
            Vec<ActionReceipt>,
            Vec<TrafficEvent>,
            Vec<String>,
        ) {
            let backend = FakeBackend::new(site());
            let mut ctx = backend.new_context(ContextConfig::new(session)).await.unwrap();
            ctx.navigate(&canon("https://example.test/")).await.unwrap();
            let mut bundles = vec![ctx
                .observe(ObservationSpec {
                    dom_snapshot: true,
                    screenshot: true,
                    ..ObservationSpec::default()
                })
                .await
                .unwrap()];
            let mut receipts = Vec::new();
            let b = bundles[0].clone();
            receipts.push(ctx.perform(click(loc(&b, "btn-menu"))).await.unwrap());
            bundles.push(ctx.observe(ObservationSpec::default()).await.unwrap());
            receipts.push(ctx.perform(click(loc(&b, "btn-popup"))).await.unwrap());
            ctx.settle(QuiescencePolicy::default()).await.unwrap();
            bundles.push(ctx.observe(ObservationSpec::default()).await.unwrap());
            let traffic = ctx.drain_traffic();
            let handle = backend.context_handles().remove(0);
            (bundles, receipts, traffic, handle.performed_keys())
        }
        let session = SessionId::new();
        let a = run(session).await;
        let b = run(session).await;
        assert_eq!(a, b);
        assert_eq!(a.0.len(), 3);
    }

    #[tokio::test]
    async fn unknown_url_and_fragment_fallback() {
        let mut rig = rig();
        let err = rig
            .ctx
            .navigate(&canon("https://example.test/nope"))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, BrowserError::Navigation(m) if m == "no scripted page for https://example.test/nope")
        );
        assert_eq!(rig.handle.epoch(), ep(0, 0, 0));
        assert!(matches!(
            rig.ctx.observe(ObservationSpec::default()).await,
            Err(BrowserError::Navigation(_))
        ));
        let mut with_fragment = canon("https://example.test/about");
        with_fragment.url.set_fragment(Some("top"));
        let nav = rig.ctx.navigate(&with_fragment).await.unwrap();
        assert_eq!(nav.final_url, "https://example.test/about");
        // BrowserAction::Navigate goes through the same lookup
        let url = Url::parse("https://example.test/").unwrap();
        rig.ctx.perform(BrowserAction::Navigate { url }).await.unwrap();
        assert_eq!(rig.handle.epoch(), ep(2, 2, 0));
        assert_eq!(
            rig.handle.performed_keys(),
            vec!["navigate:https://example.test/"]
        );
        let url = Url::parse("https://example.test/nope").unwrap();
        assert!(matches!(
            rig.ctx.perform(BrowserAction::Navigate { url }).await,
            Err(BrowserError::Navigation(_))
        ));
    }

    #[tokio::test]
    async fn navigation_result_carries_page_metadata() {
        let script = FakeScript::new().page(
            FakePage::new("https://example.test/gone")
                .status(404)
                .redirect_from(["http://example.test/old", "https://example.test/older"])
                .blocked("https://ads.test/pixel"),
        );
        let mut rig = rig_with(script, ContextConfig::new(SessionId::new()));
        let nav = rig
            .ctx
            .navigate(&canon("https://example.test/gone"))
            .await
            .unwrap();
        assert_eq!(nav.status, Some(404));
        assert_eq!(
            nav.redirects,
            vec!["http://example.test/old", "https://example.test/older"]
        );
        assert_eq!(nav.blocked_by_egress, vec!["https://ads.test/pixel"]);
        let b = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(b.network.epoch_id, Some(nav.network_epoch));
        assert_eq!(b.network.requests, 1);
        assert_eq!(b.network.operations, vec!["GET /gone"]);
    }

    #[tokio::test]
    async fn settle_reports_and_timeout_flag() {
        let mut rig = rig();
        let _ = home(&mut rig).await;
        let ok = rig.ctx.settle(QuiescencePolicy::default()).await.unwrap();
        assert_eq!(
            ok,
            SettleReport {
                waited_ms: 0,
                network_idle: true,
                mutation_idle: true,
                navigation_settled: true,
                settle_timeout: false,
                postcondition: None,
                excluded_volatile_targets: 0,
            }
        );
        let b = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(b.settle, Some(ok));

        rig.backend.script_handle().lock().settle_timeout = true;
        let policy = QuiescencePolicy::default();
        let metrics = crawlx_telemetry::Metrics::global();
        let timeouts = metrics.counter(crawlx_telemetry::metrics::names::SETTLE_TIMEOUTS);
        let durations = metrics.histogram(crawlx_telemetry::metrics::names::SETTLE_DURATION);
        let timeouts_before = timeouts.get(&[]);
        let count_before = durations.snapshot(&[]).map_or(0, |s| s.count);
        let timed_out = rig.ctx.settle(policy).await.unwrap();
        assert!(timed_out.settle_timeout && !timed_out.network_idle && !timed_out.mutation_idle);
        assert_eq!(timed_out.waited_ms, policy.hard_timeout_ms);
        // metrics are process-global; sibling tests settle concurrently, so assert lower bounds
        assert!(timeouts.get(&[]) > timeouts_before, "settle timeout counted");
        assert!(
            durations.snapshot(&[]).map_or(0, |s| s.count) > count_before,
            "settle duration observed"
        );

        let waiting = FakeBackend::new(FakeScript::new().settle_waited_ms(120));
        let mut ctx = waiting.new_fake_context(ContextConfig::new(SessionId::new()));
        assert_eq!(ctx.settle(policy).await.unwrap().waited_ms, 120);
    }

    #[tokio::test]
    async fn artifacts_are_deterministic_and_optional() {
        let mut rig = rig();
        let plain = home(&mut rig).await;
        assert!(plain.raw_artifacts.is_empty());
        let spec = ObservationSpec {
            ax: true,
            dom_supplement: false,
            dom_snapshot: true,
            screenshot: true,
            revalidation_only: false,
        };
        let b = rig.ctx.observe(spec).await.unwrap();
        assert!(b.dom_supplement.nodes.is_empty());
        let snap: serde_json::Value =
            serde_json::from_slice(b.raw_artifact("dom_snapshot").unwrap()).unwrap();
        assert_eq!(snap["fake"], true);
        assert_eq!(snap["url"], "https://example.test/");
        let png = b.raw_artifact("screenshot").unwrap();
        assert_eq!(png, PLACEHOLDER_PNG);
        // verify the placeholder is a well-formed PNG: signature + chunks with valid CRCs
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
        let mut off = 8;
        let mut kinds = Vec::new();
        while off < png.len() {
            let len = usize::try_from(u32::from_be_bytes(png[off..off + 4].try_into().unwrap())).unwrap();
            let body = &png[off + 4..off + 8 + len];
            let crc = u32::from_be_bytes(png[off + 8 + len..off + 12 + len].try_into().unwrap());
            assert_eq!(crc32(body), crc);
            kinds.push(String::from_utf8(body[..4].to_vec()).unwrap());
            off += 12 + len;
        }
        assert_eq!(kinds, ["IHDR", "IDAT", "IEND"]);
        assert_eq!(&png[16..24], &[0, 0, 0, 1, 0, 0, 0, 1]);
    }

    #[tokio::test]
    async fn dom_supplement_mirrors_nodes() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        let link = loc(&b, "lnk-about");
        let s = b.dom_supplement.nodes.get(&link.backend_node_id.0).unwrap();
        assert_eq!(s.tag, "a");
        assert_eq!(s.text.as_deref(), Some("About"));
        assert_eq!(s.bbox, node(&b, "lnk-about").bbox);
        assert_eq!(s.attributes.get("href").map(String::as_str), Some("/about"));
        let user = b
            .dom_supplement
            .nodes
            .get(&loc(&b, "txt-user").backend_node_id.0)
            .unwrap();
        assert_eq!(user.tag, "input");
        assert_eq!(user.attributes.get("type").map(String::as_str), Some("text"));
        assert_eq!(b.dom_supplement.nodes.len(), b.ax.nodes.len());
        let ax_off = rig
            .ctx
            .observe(ObservationSpec {
                ax: false,
                ..ObservationSpec::default()
            })
            .await
            .unwrap();
        assert!(ax_off.ax.nodes.is_empty());
    }

    #[tokio::test]
    async fn receipts_traffic_and_network_epochs() {
        let mut rig = rig();
        let b = home(&mut rig).await;
        let r1 = rig.ctx.perform(click(loc(&b, "btn-menu"))).await.unwrap();
        let r2 = rig
            .ctx
            .perform(BrowserAction::Hover {
                target: loc(&b, "btn-menu"),
            })
            .await
            .unwrap();
        assert_ne!(r1.network_epoch, r2.network_epoch);
        assert_eq!(r1.fidelity, Fidelity::NativePointer);
        assert_eq!(r1.lane, TrustLane::TrustedUi);
        assert!(r1.finished_at > r1.started_at && r2.started_at > r1.finished_at);
        let seen = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(seen.network.epoch_id, Some(r2.network_epoch));

        let nav = rig
            .ctx
            .perform(BrowserAction::SwitchTab {
                tab: rig.handle.current_tab(),
            })
            .await
            .unwrap();
        assert_eq!(nav.fidelity, Fidelity::ScriptedNavigation);
        assert_eq!(nav.lane, TrustLane::Diagnostic);

        let events = rig.ctx.drain_traffic();
        // navigate + click + hover + switch_tab
        assert_eq!(events.len(), 4);
        assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
        assert_eq!(
            events.iter().map(|e| e.method.as_str()).collect::<Vec<_>>(),
            vec!["GET", "POST", "GET", "GET"]
        );
        assert!(events
            .iter()
            .all(|e| e.origin == TrafficOrigin::Page && e.url == "https://example.test/"));
        assert_eq!(events[1].epoch_id, Some(r1.network_epoch));
        assert_eq!(events[0].status, Some(200));
        assert!(rig.ctx.drain_traffic().is_empty());
        assert_eq!(rig.handle.traffic_drained(), 4);
    }

    #[tokio::test]
    async fn backend_boxes_contexts_and_close_is_observable() {
        let backend = FakeBackend::builder().script(site()).build();
        assert_eq!(
            backend.build_info().chromium_version,
            repository_pin().unwrap().version
        );
        assert!(backend.build_info().pinned);
        assert_eq!(backend.contexts_created(), 0);
        let mut boxed = backend
            .new_context(ContextConfig::new(SessionId::new()))
            .await
            .unwrap();
        let _second = backend
            .new_context(ContextConfig::new(SessionId::new()))
            .await
            .unwrap();
        assert_eq!(backend.contexts_created(), 2);
        let handles = backend.context_handles();
        assert_eq!(handles.len(), 2);

        boxed.navigate(&canon("https://example.test/")).await.unwrap();
        assert_eq!(handles[0].epoch(), ep(1, 1, 0));
        assert_eq!(handles[1].epoch(), ep(0, 0, 0));
        // network epoch ids are distinct across contexts of one backend
        let b0 = boxed.observe(ObservationSpec::default()).await.unwrap();
        assert!(!handles[0].closed());
        boxed.close().await.unwrap();
        assert!(handles[0].closed() && !handles[1].closed());
        assert_eq!(b0.network.epoch_id.map(|e| e.as_uuid().as_u128()), Some(1));
    }

    #[tokio::test]
    async fn open_contexts_in_flight_and_held_performs_are_observable() {
        let backend = Arc::new(FakeBackend::builder().script(site()).build());
        assert_eq!((backend.open_contexts(), backend.max_in_flight()), (0, 0));
        let mut a = backend.new_fake_context(ContextConfig::new(SessionId::new()));
        let b = backend
            .new_context(ContextConfig::new(SessionId::new()))
            .await
            .unwrap();
        assert_eq!(backend.open_contexts(), 2);
        let ha = a.handle();
        a.navigate(&canon("https://example.test/")).await.unwrap();
        let bundle = a.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!((ha.in_flight(), ha.max_in_flight()), (0, 1));
        assert_eq!((backend.in_flight(), backend.max_in_flight()), (0, 1));

        // a held perform counts as in flight while parked and completes on release
        backend.hold_performs();
        let action = click(loc(&bundle, "lnk-about"));
        let parked = tokio::spawn(async move { a.perform(action).await.map(|_| a) });
        while backend.performs_held() == 0 {
            tokio::task::yield_now().await;
        }
        assert_eq!((ha.in_flight(), backend.in_flight()), (1, 1));
        assert!(!parked.is_finished(), "parked until released");
        backend.release_performs();
        let a = parked.await.unwrap().unwrap();
        assert_eq!((ha.in_flight(), backend.performs_held()), (0, 0));
        assert_eq!(ha.current_url(), "https://example.test/about");
        assert_eq!(backend.max_in_flight(), 1, "contexts ran one at a time");

        // close and drop each release the context exactly once
        b.close().await.unwrap();
        assert_eq!(backend.open_contexts(), 1);
        drop(a);
        assert_eq!(backend.open_contexts(), 0);
    }

    #[tokio::test]
    async fn script_can_change_while_contexts_live() {
        let backend = FakeBackend::new(FakeScript::new());
        let mut ctx = backend.new_fake_context(ContextConfig::new(SessionId::new()));
        assert!(ctx.navigate(&canon("https://late.test/")).await.is_err());
        {
            let handle = backend.script_handle();
            let mut script = handle.lock();
            script.pages.insert(
                "https://late.test/".to_owned(),
                FakePage::new("https://late.test/").node(FakeAxSpec::button("b", "B")),
            );
        }
        ctx.navigate(&canon("https://late.test/")).await.unwrap();
        let b = ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(b.ax.nodes.len(), 1);
        backend.script_handle().lock().stale.insert("b".to_owned());
        let r = ctx.revalidate(&loc(&b, "b"), b.epoch).await.unwrap();
        assert_eq!(r, Revalidation::StaleEpoch { current: b.epoch });
    }

    #[test]
    fn stepping_clock_starts_2026_and_ticks_one_ms() {
        let clock = SteppingClock::default();
        let a = clock.now();
        let b = clock.now();
        assert_eq!(a, "2026-01-01T00:00:00Z".parse::<Timestamp>().unwrap());
        assert_eq!((b - a).num_milliseconds(), 1);
    }

    #[tokio::test]
    async fn custom_clock_and_build_info() {
        let at: Timestamp = "2030-05-05T10:00:00Z".parse().unwrap();
        let clock = Arc::new(crawlx_core::time::ManualClock::new(at));
        let mut info = default_build_info();
        info.pinned = false;
        let backend = FakeBackend::builder()
            .script(site())
            .clock(clock.clone())
            .build_info(info.clone())
            .build();
        assert_eq!(backend.build_info(), &info);
        let mut ctx = backend.new_fake_context(ContextConfig::new(SessionId::new()));
        ctx.navigate(&canon("https://example.test/")).await.unwrap();
        let b = ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(b.captured_at, at);
        clock.advance_ms(5);
        let b2 = ctx.observe(ObservationSpec::default()).await.unwrap();
        assert_eq!(b2.captured_at, at + chrono::Duration::milliseconds(5));
    }

    #[test]
    fn page_lookup_normalizes_urls() {
        let script = FakeScript::new().page(FakePage::new("https://example.test"));
        assert!(script.pages.contains_key("https://example.test/"));
        assert_eq!(
            find_page_key(&script, "https://example.test/#x", None).as_deref(),
            Some("https://example.test/")
        );
        assert_eq!(
            find_page_key(&script, "/", Some("https://example.test/a")).as_deref(),
            Some("https://example.test/")
        );
        assert!(find_page_key(&script, "https://other.test/", None).is_none());
    }
}
