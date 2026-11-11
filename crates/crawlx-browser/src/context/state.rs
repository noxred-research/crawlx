//! Per-context state updated by the event pump: tab epochs, in-flight network tracking,
//! redacted traffic capture, dialogs and the tab graph. Pure (no I/O, no clock reads
//! beyond the `Instant`/`Timestamp` arguments), so the epoch and quiescence bookkeeping
//! is unit-tested with synthetic CDP events.

use super::xhr::XhrTracker;
use crate::cdp::CdpEvent;
use crate::egress;
use crate::target::{TabDecision, TabGraph};
use crawlx_core::browser::BlockedNavigation;
use crawlx_core::dom_ops::XhrRecord;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::ids::NetworkEpochId;
use crawlx_core::observation::{DialogEvent, NetworkEpochSummary};
use crawlx_core::page_op::Emulation;
use crawlx_core::request_controls::RequestControls;
use crawlx_core::time::Timestamp;
use crawlx_core::traffic::{Protocol, TrafficEvent, TrafficOrigin, UnattributedReason};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Requests older than this are excluded from the network-idle criterion.
pub const LONG_LIVED_AFTER: Duration = Duration::from_secs(10);
/// Captured traffic is bounded; the oldest events are dropped first.
pub const MAX_TRAFFIC_EVENTS: usize = 5000;
const MAX_CONSOLE: usize = 500;
/// Per-message retained console bytes; a page cannot fill the ring with unbounded strings.
const MAX_CONSOLE_BYTES: usize = 4096;
/// Refused navigations kept for the next drain; the oldest are dropped first.
pub const MAX_BLOCKED_NAVIGATIONS: usize = 256;

/// Cumulative mutation counters read from the isolated-world observer.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Counters {
    /// Mutation records delivered by the `MutationObserver`, volatile targets included.
    pub records: u64,
    /// Nodes added by `childList` records.
    pub added: u64,
    /// Nodes removed by `childList` records.
    pub removed: u64,
    /// `attributes` records.
    pub attrs: u64,
    /// `characterData` records.
    pub text: u64,
    /// Records on targets not classified volatile; only these restart the mutation-idle window.
    pub stable: u64,
    /// Records on volatile targets (`aria-live` regions, near-periodic mutators).
    pub volatile: u64,
    /// Volatile targets that mutated within the observer's recency window (two seconds).
    pub volatile_recent: u32,
    /// Milliseconds between the last stable record and this read; `None` before the first one.
    pub stable_age_ms: Option<u64>,
}

/// A request that has started and not yet finished, failed or been served from cache.
#[derive(Clone, Debug)]
pub struct InFlight {
    /// When `Network.requestWillBeSent` was seen (monotonic clock).
    pub started: Instant,
    /// Excluded from the network-idle criterion (WebSocket, SSE, long poll).
    pub long_lived: bool,
}

#[derive(Clone, Debug)]
struct Pending {
    epoch_id: NetworkEpochId,
    origin: TrafficOrigin,
    method: String,
    url: String,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
    status: Option<u16>,
    third_party: bool,
    started_at: Timestamp,
    protocol: Option<Protocol>,
    prefix_capture: bool,
}

/// One bounded text-prefix job; completion may precede its request's final traffic event.
#[derive(Debug, Default)]
pub struct PrefixCapture {
    /// Completed request event, once Chromium reports loading finished.
    pub seq: Option<u64>,
    /// Policy decision, which never contains raw body bytes.
    pub result: Option<Result<crawlx_core::ArtifactRef, &'static str>>,
}
/// Backend node ids of a child-frame session are offset by `index * NODE_ID_SPAN` in every
/// observation (locators, supplement keys, obstructor ids): each renderer process numbers
/// its nodes from 1, so ids of an out-of-process iframe collide with the page's.
/// [`split_node_id`] recovers the session index and the raw id.
pub const NODE_ID_SPAN: i64 = 1 << 32;

/// `(session index, raw backend id)` of a public backend node id; index 0 is the tab's own
/// session.
#[must_use]
pub fn split_node_id(id: i64) -> (u32, i64) {
    let index = u32::try_from(id.div_euclid(NODE_ID_SPAN)).unwrap_or(u32::MAX);
    (index, id.rem_euclid(NODE_ID_SPAN))
}

/// Public backend node id of raw id `raw` in session `index`.
#[must_use]
pub fn join_node_id(index: u32, raw: i64) -> i64 {
    i64::from(index).saturating_mul(NODE_ID_SPAN).saturating_add(raw)
}

/// An out-of-process iframe of a tab, auto-attached as its own flattened session
/// (`Target.setAutoAttach`). Its target id is the id of its root frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChildFrame {
    /// Flattened CDP session of the frame target.
    pub session: String,
    /// Frame id of the parent frame (in the page or in another child session).
    pub parent_frame: String,
    /// Node-id space of the session (`join_node_id(index, raw)`); never 0, never reused.
    pub index: u32,
    /// Domains enabled and the frame resumed; observations skip frames still being set up.
    pub ready: bool,
    /// Isolated-world execution context in the frame's root; `None` until created.
    pub world_ctx: Option<i64>,
}

/// One tab (CDP target) of the context.
#[derive(Debug)]
pub struct Tab {
    /// CDP target id of the tab.
    pub target_id: String,
    /// Flattened CDP session id commands for this tab go through.
    pub session: String,
    /// Network-only service-worker target, never part of trusted action attribution.
    pub service_worker: bool,
    /// Frame id of the tab's main frame.
    pub main_frame: String,
    /// Current URL of the main frame.
    pub url: String,
    /// Observation epoch of the current document (navigation, document and mutation counters).
    pub epoch: ObservationEpoch,
    /// A frame navigation is in progress (`Page.frameStartedLoading` without a matching stop).
    pub loading: bool,
    /// Loader ids whose `load` lifecycle event fired.
    pub loaded: BTreeSet<String>,
    /// Redirect hops of the most recent main-frame navigation, in order.
    pub nav_redirects: Vec<String>,
    /// HTTP status of the most recent main-frame document response.
    pub nav_status: Option<u16>,
    /// Response of the most recent main-frame document navigation (`PageOp::DocumentResponse`);
    /// reset with `nav_status` when a navigation starts.
    pub nav_response: Option<DocumentResponse>,
    /// Requests started and not yet finished, keyed by CDP request id.
    pub inflight: BTreeMap<String, InFlight>,
    /// Last network start/finish event (monotonic clock); the network-idle window runs from here.
    pub last_net: Instant,
    /// Last mutation of any kind, volatile targets included.
    pub last_mut: Instant,
    /// Last instant a mutation on a non-volatile target was seen (the settle criterion).
    pub last_stable_mut: Instant,
    /// When the last `perform` finished; settle windows start here, not at zero, so that fetches
    /// scheduled with `setTimeout(0)` by the action are caught.
    pub perform_done_at: Instant,
    /// Execution context id of the isolated world in the main frame; `None` until created.
    pub world_ctx: Option<i64>,
    /// Id of the network epoch requests are currently attributed to.
    pub net_epoch: NetworkEpochId,
    /// Requests started in the current network epoch.
    pub epoch_requests: u32,
    /// Requests that started in an earlier network epoch and finished in the current one.
    pub epoch_late: u32,
    /// Distinct operations (`METHOD /path/:id`) seen in the current network epoch.
    pub epoch_ops: BTreeSet<String>,
    /// Redacted URLs of long-lived connections seen in the current network epoch.
    pub long_lived_urls: BTreeSet<String>,
    pending: BTreeMap<String, Pending>,
    ws_urls: BTreeMap<String, String>,
    /// XHR and `fetch()` requests of the tab (`extract.xhr`).
    pub(crate) xhr: XhrTracker,
    /// JavaScript dialogs opened since the last observation, in order.
    pub dialogs: Vec<DialogEvent>,
    /// The renderer crashed (`Inspector.targetCrashed`); every further command fails.
    pub crashed: bool,
    /// Console messages captured so far (bounded; `Standard` profile only).
    pub console: Vec<String>,
    /// Messages evicted from the bounded console window.
    pub console_dropped: u64,
    /// At least one message was clipped before retention.
    pub console_truncated: bool,
    /// Counters at the previous `observe` (for per-bundle deltas).
    pub counters_at_observe: Counters,
    /// Counters from the most recent read of the observer.
    pub counters: Counters,
    /// Drag payload the browser intercepted (`Input.dragIntercepted`) during a drag action.
    pub drag_data: Option<Value>,
    /// Role/name seen at observation time, by backend node id.
    pub identity: BTreeMap<i64, (String, Option<String>)>,
    /// Backend nodes whose activation raised a confirm/beforeunload dialog.
    pub confirm_nodes: BTreeSet<i64>,
    /// Backend nodes brought into view by a forced scroll (wheel input could not reveal them)
    /// since their last action; the next action on them is reported as `ScriptedScroll`.
    pub forced_scroll_nodes: BTreeSet<i64>,
    /// HTTP methods observed while acting on a backend node.
    pub observed_methods: BTreeMap<i64, BTreeSet<String>>,
    /// JavaScript dialogs opened on this tab since it was attached (never reset).
    pub dialogs_total: u64,
    /// Backend node of the most recent `perform` target.
    pub last_action_node: Option<i64>,
    /// Out-of-process iframes attached under this tab, keyed by frame target id.
    pub frames: BTreeMap<String, ChildFrame>,
    /// The main-frame navigation the guard refused since the last `navigate`, if any: the
    /// navigation in flight ended without loading (`NavigationGuard`).
    pub nav_blocked: Option<BlockedNavigation>,
    /// Index handed to the next child frame (`ChildFrame::index`).
    next_frame_index: u32,
}

impl Tab {
    /// A tab for `target_id` reached through `session`, with all timers started at `now`.
    #[must_use]
    pub fn new(target_id: &str, session: &str, main_frame: &str, url: &str, now: Instant) -> Self {
        Self {
            target_id: target_id.to_owned(),
            session: session.to_owned(),
            service_worker: false,
            main_frame: main_frame.to_owned(),
            url: url.to_owned(),
            epoch: ObservationEpoch::default(),
            loading: false,
            loaded: BTreeSet::new(),
            nav_redirects: Vec::new(),
            nav_status: None,
            nav_response: None,
            inflight: BTreeMap::new(),
            last_net: now,
            last_mut: now,
            last_stable_mut: now,
            perform_done_at: now,
            world_ctx: None,
            net_epoch: NetworkEpochId::new(),
            epoch_requests: 0,
            epoch_late: 0,
            epoch_ops: BTreeSet::new(),
            long_lived_urls: BTreeSet::new(),
            pending: BTreeMap::new(),
            ws_urls: BTreeMap::new(),
            xhr: XhrTracker::default(),
            dialogs: Vec::new(),
            crashed: false,
            console: Vec::new(),
            console_dropped: 0,
            console_truncated: false,
            counters_at_observe: Counters::default(),
            counters: Counters::default(),
            drag_data: None,
            identity: BTreeMap::new(),
            confirm_nodes: BTreeSet::new(),
            forced_scroll_nodes: BTreeSet::new(),
            observed_methods: BTreeMap::new(),
            dialogs_total: 0,
            last_action_node: None,
            frames: BTreeMap::new(),
            nav_blocked: None,
            next_frame_index: 1,
        }
    }

    /// Open a fresh network epoch (every `perform` and navigation does).
    pub fn open_network_epoch(&mut self) -> NetworkEpochId {
        let id = NetworkEpochId::new();
        self.net_epoch = id;
        self.epoch_requests = 0;
        self.epoch_late = 0;
        self.epoch_ops.clear();
        self.long_lived_urls.clear();
        id
    }

    /// Fold the HTTP methods seen in the current network epoch into the node last acted on.
    pub fn merge_observed_methods(&mut self) {
        if let Some(node) = self.last_action_node {
            let methods: BTreeSet<String> = self
                .epoch_ops
                .iter()
                .filter_map(|op| op.split(' ').next().map(str::to_owned))
                .collect();
            self.observed_methods.entry(node).or_default().extend(methods);
        }
    }

    /// Child frame reached through `session`, if any.
    #[must_use]
    pub fn child_by_session(&self, session: &str) -> Option<&ChildFrame> {
        self.frames.values().find(|f| f.session == session)
    }

    /// Child frame of node-id space `index`.
    #[must_use]
    pub fn child_by_index(&self, index: u32) -> Option<&ChildFrame> {
        self.frames.values().find(|f| f.index == index)
    }

    /// Record an auto-attached frame target; returns `false` when it is already known.
    pub fn attach_child(&mut self, target_id: &str, session: &str, parent_frame: &str) -> bool {
        if self.frames.contains_key(target_id) {
            return false;
        }
        let index = self.next_frame_index;
        self.next_frame_index = self.next_frame_index.saturating_add(1);
        self.frames.insert(
            target_id.to_owned(),
            ChildFrame {
                session: session.to_owned(),
                parent_frame: parent_frame.to_owned(),
                index,
                ready: false,
                world_ctx: None,
            },
        );
        true
    }

    /// A new document replaced the main one: counters and the isolated world restart.
    fn document_replaced(&mut self, navigation: bool, now: Instant) {
        if navigation {
            self.epoch.navigation_seq += 1;
            self.epoch.mutation_seq = 0;
            self.counters = Counters::default();
            self.counters_at_observe = Counters::default();
            self.world_ctx = None;
            self.frames.clear();
            self.identity.clear();
            self.confirm_nodes.clear();
            self.forced_scroll_nodes.clear();
        }
        self.epoch.document_seq += 1;
        self.last_mut = now;
        self.last_stable_mut = now;
    }

    /// Apply counters read from the observer; `mutation_seq` follows the record count.
    pub fn apply_counters(&mut self, c: Counters, now: Instant) {
        if c.records > self.counters.records {
            self.last_mut = now;
        }
        // the observer's own clock dates the last stable mutation; a poll only reads it late
        if let Some(age) = c.stable_age_ms {
            let at = now.checked_sub(Duration::from_millis(age)).unwrap_or(now);
            self.last_stable_mut = self.last_stable_mut.max(at);
        }
        self.counters = c;
        if c.records > self.epoch.mutation_seq {
            self.epoch.mutation_seq = c.records;
        }
    }

    /// Requests in flight that count toward the idle criterion.
    #[must_use]
    pub fn blocking_inflight(&self, now: Instant) -> usize {
        self.inflight
            .values()
            .filter(|r| !r.long_lived && now.saturating_duration_since(r.started) < LONG_LIVED_AFTER)
            .count()
    }

    /// Summary for `ObservationBundle.network`.
    #[must_use]
    pub fn network_summary(&self, now: Instant) -> NetworkEpochSummary {
        NetworkEpochSummary {
            epoch_id: Some(self.net_epoch),
            requests: self.epoch_requests,
            in_flight_at_capture: u32::try_from(self.blocking_inflight(now)).unwrap_or(u32::MAX),
            long_lived: self.long_lived_urls.iter().cloned().collect(),
            late: self.epoch_late,
            operations: self.epoch_ops.iter().cloned().collect(),
        }
    }
}

/// Work the pump must do after a state update (it needs I/O).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Followup {
    /// Attach to a popup target the tab graph accepted.
    AttachPopup {
        /// CDP target id of the popup.
        target_id: String,
    },
    /// Close a popup target the graph rejected as part of a popup storm.
    CloseTarget {
        /// CDP target id to close.
        target_id: String,
    },
    /// Answer a JavaScript dialog that is blocking the page.
    HandleDialog {
        /// Flattened CDP session of the tab showing the dialog.
        session: String,
        /// `true` to accept (OK), `false` to dismiss.
        accept: bool,
    },
    /// Enable the domains of an auto-attached child frame and resume it.
    SetupFrame {
        /// Tab the frame belongs to.
        target_id: String,
        /// Flattened CDP session of the frame target.
        session: String,
    },
    /// Resume an auto-attached target the context does not drive (a worker): it started paused.
    ResumeTarget {
        /// Flattened CDP session of the target.
        session: String,
    },
    /// Enable network capture before an auto-attached service worker starts.
    SetupWorker {
        /// Flattened CDP worker session.
        session: String,
    },
    /// Retrieve a bounded response body without holding the state lock.
    CaptureBody {
        /// Actual CDP session and request identifiers.
        session: String,
        /// CDP request identifier.
        request_id: String,
        /// Event awaiting body retention.
        seq: u64,
        /// Reported response MIME type.
        content_type: String,
    },
    /// Stream only a bounded same-origin JSON/HTML prefix.
    CapturePrefix {
        /// Actual flattened CDP session.
        session: String,
        /// Actual CDP request identifier.
        request_id: String,
        /// Reported MIME type.
        content_type: String,
    },
}

/// Main-frame document response facts kept beside `Tab::nav_status`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DocumentResponse {
    /// HTTP status.
    pub status: Option<u16>,
    /// Response headers: lower-case names, credential headers redacted like captured traffic.
    pub headers: Vec<(String, String)>,
    /// `Response.mimeType`.
    pub content_type: Option<String>,
}

/// Context-wide page operations (`PageOp::BlockUrls`, `PageOp::Emulate`): applied to every
/// open tab and frame session and re-applied by `setup_tab` / `setup_frame` to tabs and
/// frames attached later (popups, new iframes).
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Overrides {
    /// Blocked URL patterns (`Network.setBlockedURLs`); empty blocks nothing.
    pub block_urls: Vec<String>,
    /// The emulation in effect; `None` keeps the context configuration.
    pub emulation: Option<Emulation>,
}

/// All mutable state of one browser context.
#[derive(Debug)]
pub struct State {
    /// CDP browser-context id this state belongs to (the isolated profile of one session).
    pub browser_context_id: String,
    /// Open tabs keyed by CDP target id.
    pub tabs: BTreeMap<String, Tab>,
    /// Network-only service-worker targets, keyed by target id.
    pub workers: BTreeMap<String, Tab>,
    /// Opener relations between tabs and the popup limit.
    pub graph: TabGraph,
    /// Target id of the active tab; empty before the first tab attaches.
    pub active: String,
    /// Captured traffic, oldest first, bounded by `MAX_TRAFFIC_EVENTS`.
    pub traffic: Vec<TrafficEvent>,
    traffic_seq: u64,
    /// Retain source response identities only when a capture policy sink is configured.
    pub(super) capture_sources: bool,
    /// Original response identities indexed by frame then URL, independent of traffic
    /// drains. At most 128 entries; `None` means an ambiguous same-document response.
    /// Present values contain `(session, request_id)`, never response bodies.
    pub resource_requests: BTreeMap<String, BTreeMap<String, Option<(String, String)>>>,
    /// Body jobs whose events cannot be drained until the policy decision completes.
    pub pending_bodies: BTreeSet<u64>,
    /// Full capture was explicitly requested and has a policy sink.
    pub capture_full: bool,
    /// Same-origin JSON/HTML prefix capture was requested.
    pub capture_text: bool,
    /// At most eight active streaming-prefix decisions.
    pub text_prefixes: BTreeMap<(String, String), PrefixCapture>,
    /// The context was closed; no further commands are sent.
    pub closed: bool,
    /// Console capture enabled (`Standard` only).
    pub console_capture: bool,
    /// Egress denials observed since the last navigation start.
    pub blocked_by_egress: Vec<String>,
    /// Document navigations the guard refused and nobody collected yet, oldest first.
    pub blocked_navigations: Vec<BlockedNavigation>,
    /// Popup targets accepted by the graph but not yet attached.
    pub attaching: BTreeSet<String>,
    /// Configured request headers and cookies: their values never enter captured traffic.
    controls: RequestControls,
    /// Page operations applied to every tab and frame session of the context.
    pub overrides: Overrides,
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn headers_of(v: Option<&Value>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = v
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_owned)))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// Captured headers: credential headers by name ([`egress::redact_headers`]), then every
/// configured request header and every header echoing a configured value.
fn redact_headers(controls: &RequestControls, headers: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = egress::redact_headers(headers);
    controls.mask_headers(&mut out);
    // These names carry observer facts, never server-controlled attribution.
    out.retain(|(name, _)| {
        !name
            .as_bytes()
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"x-crawlx-"))
    });
    out
}

fn merge_headers(target: &mut Vec<(String, String)>, incoming: Vec<(String, String)>) {
    for header in incoming {
        if let Some(existing) = target
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(&header.0))
        {
            *existing = header;
        } else {
            target.push(header);
        }
    }
}

/// The HTTP status of a CDP `Response`; CDP sends an integer, a whole-number float is tolerated.
fn status_of(v: &Value) -> Option<u16> {
    let status = v.get("status")?;
    if let Some(n) = status.as_u64() {
        return u16::try_from(n).ok();
    }
    let f = status.as_f64()?.round();
    if !(0.0..=f64::from(u16::MAX)).contains(&f) {
        return None;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "range-checked to 0..=u16::MAX just above"
    )]
    let n = f as u16;
    Some(n)
}

/// `METHOD path` with id-like segments collapsed to `:id`.
#[must_use]
pub fn operation_of(method: &str, url: &str) -> String {
    let path = url::Url::parse(url).map_or_else(|_| "/".to_owned(), |u| u.path().to_owned());
    let templ: Vec<String> = path
        .split('/')
        .map(|seg| {
            let numeric = !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit());
            let hexy = seg.len() >= 8 && seg.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
            if numeric || hexy {
                ":id".to_owned()
            } else {
                seg.to_owned()
            }
        })
        .collect();
    format!("{method} {}", templ.join("/"))
}

fn body_policy_denied(pending: &Pending) -> bool {
    pending.third_party
        || url::Url::parse(&pending.url).is_ok_and(|url| {
            let path = url.path().as_bytes();
            ["login", "logout", "signin", "auth", "token", "session"]
                .iter()
                .any(|part| {
                    path.windows(part.len())
                        .any(|window| window.eq_ignore_ascii_case(part.as_bytes()))
                })
        })
        || pending
            .response_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
}

impl State {
    /// Apply a streamed-prefix result once both the job and the request have finished.
    pub fn finish_prefix(&mut self, key: &(String, String)) {
        let ready = self
            .text_prefixes
            .get(key)
            .is_some_and(|prefix| prefix.seq.is_some() && prefix.result.is_some());
        if !ready {
            return;
        }
        let Some(prefix) = self.text_prefixes.remove(key) else {
            return;
        };
        let (Some(seq), Some(result)) = (prefix.seq, prefix.result) else {
            return;
        };
        if let Some(event) = self.traffic.iter_mut().find(|event| event.seq == seq) {
            let status = match result {
                Ok(artifact) => {
                    event.response_body = Some(artifact);
                    "stored_prefix"
                }
                Err(status) => status,
            };
            if let Some((_, value)) = event
                .response_headers
                .iter_mut()
                .find(|(name, _)| name == "x-crawlx-body-state")
            {
                *value = status.to_owned();
            }
            event
                .response_headers
                .push(("x-crawlx-body-prefix-limit".to_owned(), "65536".to_owned()));
        }
        self.pending_bodies.remove(&seq);
    }

    /// An empty state for `browser_context_id`; `console_capture` follows the launch profile.
    #[must_use]
    pub fn new(browser_context_id: &str, graph: TabGraph, console_capture: bool) -> Self {
        Self {
            browser_context_id: browser_context_id.to_owned(),
            tabs: BTreeMap::new(),
            workers: BTreeMap::new(),
            graph,
            active: String::new(),
            traffic: Vec::new(),
            traffic_seq: 0,
            capture_sources: false,
            resource_requests: BTreeMap::new(),
            pending_bodies: BTreeSet::new(),
            capture_full: false,
            capture_text: false,
            text_prefixes: BTreeMap::new(),
            closed: false,
            console_capture,
            blocked_by_egress: Vec::new(),
            blocked_navigations: Vec::new(),
            attaching: BTreeSet::new(),
            controls: RequestControls::default(),
            overrides: Overrides::default(),
        }
    }

    /// Same state masking the values of `controls` (and every header that echoes one) in
    /// captured traffic, on top of the credential-header redaction.
    #[must_use]
    pub fn with_controls(mut self, controls: RequestControls) -> Self {
        self.controls = controls;
        self
    }

    /// The active tab.
    #[must_use]
    pub fn active_tab(&self) -> Option<&Tab> {
        self.tabs.get(&self.active)
    }

    /// The active tab, mutably.
    pub fn active_tab_mut(&mut self) -> Option<&mut Tab> {
        self.tabs.get_mut(&self.active)
    }

    fn push_traffic(&mut self, p: Pending, status: Option<u16>, now_wall: Timestamp, late: bool) {
        self.traffic_seq += 1;
        let ev = TrafficEvent {
            seq: self.traffic_seq,
            epoch_id: (p.origin != TrafficOrigin::ServiceWorker).then_some(p.epoch_id),
            unattributed_reason: (p.origin == TrafficOrigin::ServiceWorker)
                .then_some(UnattributedReason::NotApplicable),
            origin: p.origin,
            method: p.method,
            url: p.url,
            status: status.or(p.status),
            request_headers: p.request_headers,
            response_headers: p.response_headers,
            request_body: None,
            response_body: None,
            third_party: p.third_party,
            late,
            protocol: p.protocol,
            started_at: p.started_at,
            finished_at: Some(now_wall),
        };
        self.traffic.push(ev);
        if self.traffic.len() > MAX_TRAFFIC_EVENTS {
            let drop = self.traffic.len() - MAX_TRAFFIC_EVENTS;
            self.traffic.drain(..drop);
        }
    }

    /// Finished XHR and `fetch()` requests of every tab since the last call
    /// ([`crawlx_core::BrowserContext::drain_xhr`]).
    pub fn drain_xhr(&mut self) -> Vec<XhrRecord> {
        self.tabs.values_mut().flat_map(|t| t.xhr.take()).collect()
    }

    /// Record a main-frame navigation of `target_id` the guard refused: the tab's navigation in
    /// flight ends, and the refusal waits for [`Self::take_blocked_navigations`] unless the
    /// navigation that caused it returns it as an error ([`Self::take_nav_blocked`]).
    pub fn record_blocked_navigation(&mut self, target_id: &str, blocked: BlockedNavigation) {
        if let Some(tab) = self.tabs.get_mut(target_id) {
            tab.nav_blocked = Some(blocked.clone());
        }
        self.blocked_navigations.push(blocked);
        if self.blocked_navigations.len() > MAX_BLOCKED_NAVIGATIONS {
            let excess = self.blocked_navigations.len() - MAX_BLOCKED_NAVIGATIONS;
            self.blocked_navigations.drain(..excess);
        }
    }

    /// The refusal that ended the navigation in flight on `target_id`, removed from the list
    /// [`Self::take_blocked_navigations`] returns: the caller reports it itself.
    pub fn take_nav_blocked(&mut self, target_id: &str) -> Option<BlockedNavigation> {
        let blocked = self.tabs.get_mut(target_id)?.nav_blocked.take()?;
        if let Some(at) = self.blocked_navigations.iter().rposition(|b| *b == blocked) {
            self.blocked_navigations.remove(at);
        }
        Some(blocked)
    }

    /// Every refusal nobody collected yet, oldest first.
    pub fn take_blocked_navigations(&mut self) -> Vec<BlockedNavigation> {
        std::mem::take(&mut self.blocked_navigations)
    }

    /// Fold one CDP event into the state.
    pub fn handle_event(&mut self, ev: &CdpEvent, now: Instant, wall: Timestamp) -> Vec<Followup> {
        let mut follow = Vec::new();
        match ev.session_id.as_deref() {
            Some(session) => self.handle_session_event(session, ev, now, wall, &mut follow),
            None => self.handle_browser_event(ev, now, &mut follow),
        }
        follow
    }

    fn handle_browser_event(&mut self, ev: &CdpEvent, now: Instant, follow: &mut Vec<Followup>) {
        let p = &ev.params;
        match ev.method.as_str() {
            "Target.attachedToTarget" => {
                let info = p.get("targetInfo").unwrap_or(&Value::Null);
                if str_of(info, "type") == "service_worker"
                    && str_of(info, "browserContextId") == self.browser_context_id
                {
                    self.attach_worker(info, str_of(p, "sessionId"), now, follow);
                }
            }
            "Target.targetCreated" => {
                let info = p.get("targetInfo").unwrap_or(&Value::Null);
                if str_of(info, "type") != "page"
                    || str_of(info, "browserContextId") != self.browser_context_id
                {
                    return;
                }
                let id = str_of(info, "targetId");
                let Some(opener) = info.get("openerId").and_then(Value::as_str) else {
                    return;
                };
                if self.graph.contains(id) || self.attaching.contains(id) || !self.graph.contains(opener) {
                    return;
                }
                match self
                    .graph
                    .on_target_created(id, Some(opener), str_of(info, "url"), now)
                {
                    TabDecision::Attach => {
                        self.attaching.insert(id.to_owned());
                        follow.push(Followup::AttachPopup {
                            target_id: id.to_owned(),
                        });
                    }
                    TabDecision::Pending => {}
                    TabDecision::Reject(_) => follow.push(Followup::CloseTarget {
                        target_id: id.to_owned(),
                    }),
                }
            }
            "Target.targetInfoChanged" => {
                let info = p.get("targetInfo").unwrap_or(&Value::Null);
                let id = str_of(info, "targetId");
                if self.graph.contains(id) {
                    self.graph.set_url(id, str_of(info, "url"));
                }
            }
            "Browser.downloadWillBegin" => {
                let frame = str_of(p, "frameId");
                let target = self
                    .tabs
                    .values()
                    .find(|tab| tab.main_frame == frame)
                    .map_or(frame, |tab| tab.target_id.as_str());
                self.graph.record_download(target, str_of(p, "url"));
            }
            "Target.targetDestroyed" => {
                let id = str_of(p, "targetId").to_owned();
                self.workers.remove(&id);
                self.drop_tab(&id, true);
            }
            "Target.targetCrashed" => {
                let id = str_of(p, "targetId");
                if let Some(t) = self.tabs.get_mut(id) {
                    t.crashed = true;
                }
            }
            "Target.detachedFromTarget" => {
                let session = str_of(p, "sessionId").to_owned();
                if let Some(id) = self
                    .tabs
                    .values()
                    .find(|t| t.session == session)
                    .map(|t| t.target_id.clone())
                {
                    self.drop_tab(&id, true);
                }
            }
            _ => {}
        }
    }

    /// Drop a tab; if it was active, fall back to its opener, then any remaining tab.
    pub fn remove_tab(&mut self, target_id: &str) {
        self.drop_tab(target_id, false);
    }

    fn drop_tab(&mut self, target_id: &str, browser_closed: bool) {
        let opener = if browser_closed && self.graph.record_closed_download(target_id) {
            self.graph.opener_of(target_id).map(str::to_owned)
        } else {
            self.graph.remove(target_id)
        };
        self.attaching.remove(target_id);
        self.tabs.remove(target_id);
        if self.active == target_id {
            let next = opener
                .filter(|o| self.tabs.contains_key(o))
                .or_else(|| self.tabs.keys().next().cloned());
            self.active = next.unwrap_or_default();
        }
    }

    fn attach_worker(&mut self, info: &Value, session: &str, now: Instant, follow: &mut Vec<Followup>) {
        if session.is_empty() || self.workers.values().any(|worker| worker.session == session) {
            return;
        }
        let target = str_of(info, "targetId");
        let mut worker = Tab::new(target, session, "", str_of(info, "url"), now);
        worker.service_worker = true;
        self.workers.insert(target.to_owned(), worker);
        follow.push(Followup::SetupWorker {
            session: session.to_owned(),
        });
    }

    fn handle_session_event(
        &mut self,
        session: &str,
        ev: &CdpEvent,
        now: Instant,
        wall: Timestamp,
        follow: &mut Vec<Followup>,
    ) {
        if ev.method == "Target.attachedToTarget"
            && self
                .tabs
                .values()
                .any(|tab| tab.session == session || tab.child_by_session(session).is_some())
        {
            let info = ev.params.get("targetInfo").unwrap_or(&Value::Null);
            if str_of(info, "type") == "service_worker" {
                self.attach_worker(info, str_of(&ev.params, "sessionId"), now, follow);
                return;
            }
        }
        let console_capture = self.console_capture;
        let blocked = &mut self.blocked_by_egress;
        let controls = &self.controls;
        let capture_text = self.capture_text;
        let text_prefixes = &mut self.text_prefixes;
        let capture_full = self.capture_full;
        let body_slots = 8usize.saturating_sub(self.pending_bodies.len());
        let traffic_out: &mut Vec<(Pending, Option<u16>, bool)> = &mut Vec::new();
        let Some(tab) = self
            .tabs
            .values_mut()
            .chain(self.workers.values_mut())
            .find(|t| t.session == session || t.child_by_session(session).is_some())
        else {
            return;
        };
        // events of a child-frame session: only the main frame's lifecycle is the tab's
        let is_child = tab.session != session;
        let p = &ev.params;
        if ev.method == "Page.downloadWillBegin" {
            self.graph.record_download(&tab.target_id, str_of(p, "url"));
            return;
        }
        match ev.method.as_str() {
            "Target.attachedToTarget" => {
                let info = p.get("targetInfo").unwrap_or(&Value::Null);
                let child_session = str_of(p, "sessionId");
                if child_session.is_empty() {
                    return;
                }
                if str_of(info, "type") != "iframe" {
                    follow.push(Followup::ResumeTarget {
                        session: child_session.to_owned(),
                    });
                    return;
                }
                let id = str_of(info, "targetId");
                if tab.attach_child(id, child_session, str_of(info, "parentFrameId")) {
                    follow.push(Followup::SetupFrame {
                        target_id: tab.target_id.clone(),
                        session: child_session.to_owned(),
                    });
                }
            }
            "Target.detachedFromTarget" => {
                let gone = str_of(p, "sessionId");
                tab.frames.retain(|_, f| f.session != gone);
            }
            "Page.frameNavigated" if is_child => {
                if let Some(f) = tab.frames.values_mut().find(|f| f.session == session) {
                    f.world_ctx = None;
                }
            }
            "Page.frameNavigated" => {
                let frame = p.get("frame").unwrap_or(&Value::Null);
                if frame.get("parentId").and_then(Value::as_str).is_none() {
                    tab.main_frame = str_of(frame, "id").to_owned();
                    tab.url = str_of(frame, "url").to_owned();
                    tab.document_replaced(true, now);
                    self.graph.set_url(&tab.target_id, &tab.url);
                }
            }
            "Page.navigatedWithinDocument" => {
                if str_of(p, "frameId") == tab.main_frame {
                    tab.url = str_of(p, "url").to_owned();
                    tab.document_replaced(false, now);
                    self.graph.set_url(&tab.target_id, &tab.url);
                }
            }
            "Page.frameStartedLoading" => {
                if str_of(p, "frameId") == tab.main_frame {
                    tab.loading = true;
                }
            }
            "Page.frameStoppedLoading" => {
                if str_of(p, "frameId") == tab.main_frame {
                    tab.loading = false;
                }
            }
            "Page.lifecycleEvent" => {
                if str_of(p, "name") == "load" && str_of(p, "frameId") == tab.main_frame {
                    tab.loaded.insert(str_of(p, "loaderId").to_owned());
                }
            }
            "Page.javascriptDialogOpening" => {
                let kind = str_of(p, "type").to_owned();
                tab.dialogs_total += 1;
                tab.dialogs.push(DialogEvent {
                    kind: kind.clone(),
                    message: str_of(p, "message").to_owned(),
                    handled: true,
                });
                follow.push(Followup::HandleDialog {
                    session: session.to_owned(),
                    accept: matches!(kind.as_str(), "alert" | "beforeunload"),
                });
            }
            "Inspector.targetCrashed" if !is_child => tab.crashed = true,
            "Input.dragIntercepted" => tab.drag_data = p.get("data").cloned(),
            "Runtime.consoleAPICalled" if console_capture => {
                let (line, truncated) = console_line(p);
                tab.console_truncated |= truncated;
                tab.console.push(line);
                if tab.console.len() > MAX_CONSOLE {
                    tab.console.remove(0);
                    tab.console_dropped = tab.console_dropped.saturating_add(1);
                }
            }
            "Network.requestWillBeSent" => {
                let id = str_of(p, "requestId").to_owned();
                let req = p.get("request").unwrap_or(&Value::Null);
                // Network response buffers survive ordinary HTTP no-store directives;
                // page resource caches need not. Retain identities only, never bodies.
                let source_url = str_of(req, "url");
                let source_frame = str_of(p, "frameId");
                if self.capture_sources && !source_frame.is_empty() && source_frame.len() <= 1024 {
                    if str_of(p, "type") == "Document" {
                        // A new document owns a fresh response set for this frame only.
                        self.resource_requests.remove(source_frame);
                    }
                    for (frame, requests) in &mut self.resource_requests {
                        requests.retain(|url, identity| {
                            identity.as_ref().is_none_or(|(owner, request)| {
                                owner != session
                                    || request != &id
                                    || (frame == source_frame && url == source_url)
                            })
                        });
                    }
                    self.resource_requests.retain(|_, requests| !requests.is_empty());
                    if !source_url.is_empty() && source_url.len() <= 8192 {
                        let known = self
                            .resource_requests
                            .get(source_frame)
                            .is_some_and(|requests| requests.contains_key(source_url));
                        let count: usize = self.resource_requests.values().map(BTreeMap::len).sum();
                        if count >= 128 && !known {
                            if let Some(mut frame) = self.resource_requests.first_entry() {
                                frame.get_mut().pop_first();
                                if frame.get().is_empty() {
                                    frame.remove();
                                }
                            }
                        }
                        let identity = if !id.is_empty() && id.len() <= 1024 && session.len() <= 1024 {
                            Some((session.to_owned(), id.clone()))
                        } else {
                            None
                        };
                        let requests = self.resource_requests.entry(source_frame.to_owned()).or_default();
                        match requests.entry(source_url.to_owned()) {
                            std::collections::btree_map::Entry::Vacant(entry) => {
                                entry.insert(identity);
                            }
                            std::collections::btree_map::Entry::Occupied(mut entry) => {
                                // Two responses for one displayed resource cannot be
                                // disambiguated by its URL. Keep refusing until navigation.
                                if entry.get() != &identity {
                                    entry.insert(None);
                                }
                            }
                        }
                    }
                }
                if let Some(redirect) = p.get("redirectResponse") {
                    // the previous hop of this request id ended with a redirect
                    if let Some(prev) = tab.pending.remove(&id) {
                        let mut prev = prev;
                        merge_headers(
                            &mut prev.response_headers,
                            redact_headers(controls, &headers_of(redirect.get("headers"))),
                        );
                        prev.protocol = match str_of(redirect, "protocol") {
                            "http/1.0" | "http/1.1" => Some(Protocol::Http11),
                            "h2" | "h2c" => Some(Protocol::H2),
                            "h3" | "http/3" => Some(Protocol::H3),
                            _ => None,
                        };
                        prev.response_headers.push((
                            "x-crawlx-body-state".to_owned(),
                            if capture_full {
                                "unavailable"
                            } else {
                                "metadata_only"
                            }
                            .to_owned(),
                        ));
                        traffic_out.push((prev, status_of(redirect), false));
                    }
                    tab.inflight.remove(&id);
                    tab.xhr.response_received(&id, status_of(redirect), None);
                    tab.xhr.request_finished(&id);
                    if str_of(p, "type") == "Document" && str_of(p, "frameId") == tab.main_frame {
                        tab.nav_redirects.push(str_of(redirect, "url").to_owned());
                    }
                }
                let url = str_of(req, "url").to_owned();
                let method = str_of(req, "method").to_owned();
                let rtype = str_of(p, "type");
                let long_lived = matches!(rtype, "WebSocket" | "EventSource");
                let origin = if tab.service_worker {
                    TrafficOrigin::ServiceWorker
                } else {
                    match rtype {
                        "WebSocket" => TrafficOrigin::WebSocket,
                        "EventSource" => TrafficOrigin::EventSource,
                        _ => TrafficOrigin::Page,
                    }
                };
                tab.inflight.insert(
                    id.clone(),
                    InFlight {
                        started: now,
                        long_lived,
                    },
                );
                if !long_lived {
                    tab.last_net = now;
                } else {
                    tab.long_lived_urls.insert(egress::redact_url(&url));
                }
                tab.epoch_requests += 1;
                tab.epoch_ops.insert(operation_of(&method, &url));
                tab.xhr
                    .request_started(&id, rtype, &method, &egress::redact_url(&url), &tab.url);
                tab.pending.insert(
                    id,
                    Pending {
                        epoch_id: tab.net_epoch,
                        origin,
                        method,
                        third_party: !(rtype == "Document" && str_of(p, "frameId") == tab.main_frame)
                            && egress::is_third_party(&tab.url, &url),
                        url: egress::redact_url(&url),
                        request_headers: {
                            let mut headers = redact_headers(controls, &headers_of(req.get("headers")));
                            headers.push(("x-crawlx-target-session".to_owned(), session.to_owned()));
                            headers.push(("x-crawlx-resource-type".to_owned(), rtype.to_ascii_lowercase()));
                            headers.push(("x-crawlx-page-url".to_owned(), egress::redact_url(&tab.url)));
                            let frame = str_of(p, "frameId");
                            if !frame.is_empty() {
                                headers.push(("x-crawlx-frame-id".to_owned(), frame.to_owned()));
                            }
                            headers
                        },
                        response_headers: Vec::new(),
                        status: None,
                        started_at: wall,
                        protocol: None,
                        prefix_capture: false,
                    },
                );
            }
            "Network.responseReceivedExtraInfo" => {
                if let Some(pending) = tab.pending.get_mut(str_of(p, "requestId")) {
                    merge_headers(
                        &mut pending.response_headers,
                        redact_headers(controls, &headers_of(p.get("headers"))),
                    );
                }
            }
            "Network.responseReceived" => {
                let id = str_of(p, "requestId");
                let resp = p.get("response").unwrap_or(&Value::Null);
                let headers = headers_of(resp.get("headers"));
                let status = status_of(resp);
                if str_of(resp, "mimeType").eq_ignore_ascii_case("text/event-stream") {
                    if let Some(r) = tab.inflight.get_mut(id) {
                        r.long_lived = true;
                    }
                    tab.long_lived_urls
                        .insert(egress::redact_url(str_of(resp, "url")));
                }
                if let Some(s) = status {
                    if egress::is_egress_denied(s, &headers) {
                        blocked.push(str_of(resp, "url").to_owned());
                    }
                    if str_of(p, "type") == "Document" && str_of(p, "frameId") == tab.main_frame {
                        tab.nav_status = Some(s);
                    }
                }
                if str_of(p, "type") == "Document" && str_of(p, "frameId") == tab.main_frame {
                    let mut lowered = redact_headers(controls, &headers);
                    for (name, _) in &mut lowered {
                        name.make_ascii_lowercase();
                    }
                    let mime = str_of(resp, "mimeType");
                    tab.nav_response = Some(DocumentResponse {
                        status,
                        headers: lowered,
                        content_type: (!mime.is_empty()).then(|| mime.to_owned()),
                    });
                }
                tab.xhr
                    .response_received(id, status, Some(str_of(resp, "mimeType")));
                if let Some(pend) = tab.pending.get_mut(id) {
                    pend.status = status;
                    merge_headers(&mut pend.response_headers, redact_headers(controls, &headers));
                    pend.protocol = match str_of(resp, "protocol") {
                        "http/1.0" | "http/1.1" => Some(Protocol::Http11),
                        "h2" | "h2c" => Some(Protocol::H2),
                        "h3" | "http/3" => Some(Protocol::H3),
                        _ => None,
                    };
                    pend.response_headers.push((
                        "x-crawlx-content-type".to_owned(),
                        str_of(resp, "mimeType").to_owned(),
                    ));
                    let mime = str_of(resp, "mimeType");
                    let text_like = mime.eq_ignore_ascii_case("text/html")
                        || mime.eq_ignore_ascii_case("application/json")
                        || mime.ends_with("+json");
                    if capture_text && text_like && !body_policy_denied(pend) && text_prefixes.len() < 8 {
                        pend.prefix_capture = true;
                        text_prefixes.insert((session.to_owned(), id.to_owned()), PrefixCapture::default());
                        follow.push(Followup::CapturePrefix {
                            session: session.to_owned(),
                            request_id: id.to_owned(),
                            content_type: mime.to_owned(),
                        });
                    }
                }
            }
            "Network.loadingFinished" | "Network.loadingFailed" => {
                let id = str_of(p, "requestId");
                tab.xhr.request_finished(id);
                let was = tab.inflight.remove(id);
                if was.is_some_and(|w| !w.long_lived) {
                    tab.last_net = now;
                }
                if let Some(mut pend) = tab.pending.remove(id) {
                    let late = pend.epoch_id != tab.net_epoch;
                    if late {
                        tab.epoch_late += 1;
                    }
                    let encoded = p
                        .get("encodedDataLength")
                        .and_then(Value::as_f64)
                        .unwrap_or_default();
                    let denied = body_policy_denied(&pend);
                    let body_state = if !capture_full && !capture_text {
                        "metadata_only"
                    } else if denied {
                        "policy_denied"
                    } else if ev.method == "Network.loadingFailed" {
                        "unavailable"
                    } else if capture_text && !pend.prefix_capture {
                        "policy_denied"
                    } else if capture_full && encoded > 1_048_576.0 {
                        "oversized"
                    } else if capture_full && body_slots == 0 {
                        "capacity_exceeded"
                    } else {
                        "pending"
                    };
                    pend.response_headers
                        .push(("x-crawlx-body-state".to_owned(), body_state.to_owned()));
                    pend.response_headers
                        .push(("x-crawlx-body-bytes".to_owned(), encoded.to_string()));
                    traffic_out.push((pend, None, late));
                }
            }
            "Network.webSocketCreated" => {
                let id = str_of(p, "requestId").to_owned();
                let url = str_of(p, "url").to_owned();
                if let Some(r) = tab.inflight.get_mut(&id) {
                    r.long_lived = true;
                }
                tab.long_lived_urls.insert(egress::redact_url(&url));
                tab.ws_urls.insert(id, url);
            }
            "Network.webSocketFrameSent" | "Network.webSocketFrameReceived" => {
                let id = str_of(p, "requestId");
                let url = tab.ws_urls.get(id).cloned().unwrap_or_default();
                let sent = ev.method.ends_with("Sent");
                let resp = p.get("response").unwrap_or(&Value::Null);
                let opcode = resp.get("opcode").and_then(Value::as_i64).unwrap_or_default();
                let payload = str_of(resp, "payloadData");
                let len = if opcode == 1 {
                    payload.len()
                } else {
                    payload
                        .len()
                        .div_euclid(4)
                        .saturating_mul(3)
                        .saturating_sub(payload.bytes().rev().take_while(|byte| *byte == b'=').count())
                };
                traffic_out.push((
                    Pending {
                        epoch_id: tab.net_epoch,
                        origin: if tab.service_worker {
                            TrafficOrigin::ServiceWorker
                        } else {
                            TrafficOrigin::WebSocket
                        },
                        method: if sent { "WS_SEND" } else { "WS_RECV" }.to_owned(),
                        third_party: egress::is_third_party(&tab.url, &url),
                        prefix_capture: false,
                        url: egress::redact_url(&url),
                        request_headers: vec![
                            ("x-ws-opcode".to_owned(), opcode.to_string()),
                            ("x-ws-payload-bytes".to_owned(), len.to_string()),
                            ("x-crawlx-target-session".to_owned(), session.to_owned()),
                        ],
                        response_headers: vec![(
                            "x-crawlx-body-state".to_owned(),
                            "stream_metadata_only".to_owned(),
                        )],
                        status: None,
                        protocol: None,
                        started_at: wall,
                    },
                    None,
                    false,
                ));
            }
            "Network.webSocketClosed" => {
                tab.ws_urls.remove(str_of(p, "requestId"));
                tab.inflight.remove(str_of(p, "requestId"));
            }
            "Network.eventSourceMessageReceived" => {
                let id = str_of(p, "requestId");
                if let Some(r) = tab.inflight.get_mut(id) {
                    r.long_lived = true;
                }
                if let Some(connection) = tab.pending.get(id) {
                    let mut frame = connection.clone();
                    frame.origin = if tab.service_worker {
                        TrafficOrigin::ServiceWorker
                    } else {
                        TrafficOrigin::EventSource
                    };
                    frame.method = "SSE_RECV".to_owned();
                    frame.epoch_id = tab.net_epoch;
                    frame.started_at = wall;
                    frame.request_headers.retain(|(name, _)| {
                        matches!(name.as_str(), "x-crawlx-frame-id" | "x-crawlx-target-session")
                    });
                    frame.response_headers = vec![
                        (
                            "x-crawlx-stream-payload-bytes".to_owned(),
                            str_of(p, "data").len().to_string(),
                        ),
                        ("x-crawlx-stream-kind".to_owned(), "sse".to_owned()),
                        (
                            "x-crawlx-body-state".to_owned(),
                            "stream_metadata_only".to_owned(),
                        ),
                    ];
                    traffic_out.push((frame, None, false));
                }
            }
            _ => {}
        }
        for (mut pend, status, late) in traffic_out.drain(..) {
            pend.response_headers
                .push(("x-crawlx-capture-source".to_owned(), "cdp".to_owned()));
            let capture_body = pend
                .response_headers
                .iter()
                .any(|(name, value)| name == "x-crawlx-body-state" && value == "pending");
            let content_type = pend
                .response_headers
                .iter()
                .find(|(name, _)| name == "x-crawlx-content-type")
                .map_or_else(String::new, |(_, value)| value.clone());
            let prefix_capture = pend.prefix_capture;
            self.push_traffic(pend, status, wall, late);
            if prefix_capture {
                self.pending_bodies.insert(self.traffic_seq);
                let key = (session.to_owned(), str_of(p, "requestId").to_owned());
                if let Some(prefix) = self.text_prefixes.get_mut(&key) {
                    prefix.seq = Some(self.traffic_seq);
                }
                self.finish_prefix(&key);
                continue;
            }
            if capture_body {
                self.pending_bodies.insert(self.traffic_seq);
                follow.push(Followup::CaptureBody {
                    session: session.to_owned(),
                    request_id: str_of(p, "requestId").to_owned(),
                    seq: self.traffic_seq,
                    content_type,
                });
            }
        }
    }
}

fn append_console(output: &mut String, text: &str) -> bool {
    let mut end = text.len().min(MAX_CONSOLE_BYTES.saturating_sub(output.len()));
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    output.push_str(&text[..end]);
    end < text.len()
}

fn console_line(parameters: &Value) -> (String, bool) {
    let mut line = String::with_capacity(128);
    let mut truncated = append_console(&mut line, str_of(parameters, "type"));
    truncated |= append_console(&mut line, ": ");
    if let Some(args) = parameters.get("args").and_then(Value::as_array) {
        for (index, arg) in args.iter().enumerate() {
            if line.len() == MAX_CONSOLE_BYTES {
                truncated = true;
                break;
            }
            if index != 0 {
                truncated |= append_console(&mut line, " ");
            }
            if let Some(text) = arg
                .get("value")
                .and_then(Value::as_str)
                .or_else(|| arg.get("description").and_then(Value::as_str))
            {
                truncated |= append_console(&mut line, text);
            } else if let Some(value) = arg.get("value") {
                // Scalar previews only; objects can carry arbitrarily large payloads.
                if value.is_number() || value.is_boolean() || value.is_null() {
                    truncated |= append_console(&mut line, &value.to_string());
                }
            }
        }
    }
    (line, truncated)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn ev(session: Option<&str>, method: &str, params: Value) -> CdpEvent {
        CdpEvent {
            method: method.to_owned(),
            session_id: session.map(str::to_owned),
            params,
        }
    }

    fn state() -> (State, Instant) {
        let now = Instant::now();
        let mut g = TabGraph::new(3);
        g.add_home("T1", "about:blank");
        let mut s = State::new("CTX", g, true);
        s.tabs
            .insert("T1".to_owned(), Tab::new("T1", "S1", "F1", "about:blank", now));
        s.active = "T1".to_owned();
        (s, now)
    }

    fn feed(s: &mut State, now: Instant, session: &str, method: &str, params: Value) -> Vec<Followup> {
        s.handle_event(&ev(Some(session), method, params), now, Timestamp::default())
    }

    #[test]
    fn node_ids_split_and_join_per_session_index() {
        assert_eq!(split_node_id(17), (0, 17));
        assert_eq!(join_node_id(2, 17), 2 * NODE_ID_SPAN + 17);
        assert_eq!(split_node_id(join_node_id(2, 17)), (2, 17));
    }

    #[test]
    fn child_frames_attach_resume_and_detach_through_their_sessions() {
        let (mut s, now) = state();
        // an iframe target auto-attached under the tab's session: set up, keyed by index
        let f = feed(
            &mut s,
            now,
            "S1",
            "Target.attachedToTarget",
            json!({ "sessionId": "C1", "targetInfo": { "type": "iframe", "targetId": "FX", "parentFrameId": "F1" } }),
        );
        assert_eq!(
            f,
            vec![Followup::SetupFrame {
                target_id: "T1".to_owned(),
                session: "C1".to_owned()
            }]
        );
        let child = s.tabs["T1"].frames["FX"].clone();
        assert_eq!(
            (child.index, child.session.as_str(), child.parent_frame.as_str()),
            (1, "C1", "F1")
        );
        assert!(!child.ready);
        assert!(s.tabs["T1"].child_by_session("C1").is_some() && s.tabs["T1"].child_by_index(1).is_some());
        // a repeat attach is not set up twice; a worker is only resumed
        assert!(feed(
            &mut s,
            now,
            "S1",
            "Target.attachedToTarget",
            json!({ "sessionId": "C1", "targetInfo": { "type": "iframe", "targetId": "FX", "parentFrameId": "F1" } }),
        )
        .is_empty());
        assert_eq!(
            feed(
                &mut s,
                now,
                "S1",
                "Target.attachedToTarget",
                json!({ "sessionId": "W1", "targetInfo": { "type": "worker", "targetId": "WX" } }),
            ),
            vec![Followup::ResumeTarget {
                session: "W1".to_owned()
            }]
        );
        // a nested frame attaches under the child's session and gets the next index
        feed(
            &mut s,
            now,
            "C1",
            "Target.attachedToTarget",
            json!({ "sessionId": "C2", "targetInfo": { "type": "iframe", "targetId": "FY", "parentFrameId": "FX" } }),
        );
        assert_eq!(s.tabs["T1"].frames["FY"].index, 2);
        // the child's own navigation drops its world but leaves the tab's epoch alone
        s.tabs
            .get_mut("T1")
            .unwrap()
            .frames
            .get_mut("FX")
            .unwrap()
            .world_ctx = Some(9);
        let epoch = s.tabs["T1"].epoch;
        feed(
            &mut s,
            now,
            "C1",
            "Page.frameNavigated",
            json!({ "frame": { "id": "FX", "url": "http://other/f" } }),
        );
        assert_eq!(s.tabs["T1"].frames["FX"].world_ctx, None);
        assert_eq!(s.tabs["T1"].epoch, epoch);
        assert_eq!(s.tabs["T1"].main_frame, "F1");
        // a child crash does not crash the tab; a detach removes the frame
        feed(&mut s, now, "C1", "Inspector.targetCrashed", json!({}));
        assert!(!s.tabs["T1"].crashed);
        feed(
            &mut s,
            now,
            "S1",
            "Target.detachedFromTarget",
            json!({ "sessionId": "C1", "targetId": "FX" }),
        );
        assert!(!s.tabs["T1"].frames.contains_key("FX"));
        assert!(s.tabs["T1"].frames.contains_key("FY"));
        // a main-frame navigation discards every child frame
        feed(
            &mut s,
            now,
            "S1",
            "Page.frameNavigated",
            json!({ "frame": { "id": "F1", "url": "http://h/next" } }),
        );
        assert!(s.tabs["T1"].frames.is_empty());
        // indexes are never reused after a detach
        feed(
            &mut s,
            now,
            "S1",
            "Target.attachedToTarget",
            json!({ "sessionId": "C3", "targetInfo": { "type": "iframe", "targetId": "FZ", "parentFrameId": "F1" } }),
        );
        assert_eq!(s.tabs["T1"].frames["FZ"].index, 3);
    }

    #[test]
    fn main_frame_navigation_bumps_navigation_and_document_and_resets_mutations() {
        let (mut s, now) = state();
        s.tabs.get_mut("T1").unwrap().apply_counters(
            Counters {
                records: 7,
                ..Counters::default()
            },
            now,
        );
        assert_eq!(s.tabs["T1"].epoch.mutation_seq, 7);
        feed(
            &mut s,
            now,
            "S1",
            "Page.frameNavigated",
            json!({"frame": {"id": "F1", "url": "http://a.test/"}}),
        );
        let e = s.tabs["T1"].epoch;
        assert_eq!((e.navigation_seq, e.document_seq, e.mutation_seq), (1, 1, 0));
        assert_eq!(s.tabs["T1"].url, "http://a.test/");
    }

    #[test]
    fn same_document_navigation_bumps_document_only() {
        let (mut s, now) = state();
        feed(
            &mut s,
            now,
            "S1",
            "Page.navigatedWithinDocument",
            json!({"frameId": "F1", "url": "http://a.test/#x"}),
        );
        let e = s.tabs["T1"].epoch;
        assert_eq!((e.navigation_seq, e.document_seq), (0, 1));
    }

    #[test]
    fn subframe_navigation_does_not_bump_epoch() {
        let (mut s, now) = state();
        feed(
            &mut s,
            now,
            "S1",
            "Page.frameNavigated",
            json!({"frame": {"id": "F2", "parentId": "F1", "url": "http://a.test/frame"}}),
        );
        assert_eq!(s.tabs["T1"].epoch, ObservationEpoch::default());
        assert_eq!(s.tabs["T1"].url, "about:blank");
    }

    #[test]
    fn mutation_counters_only_move_forward() {
        let (mut s, now) = state();
        let t = s.tabs.get_mut("T1").unwrap();
        t.apply_counters(
            Counters {
                records: 3,
                ..Counters::default()
            },
            now,
        );
        t.apply_counters(
            Counters {
                records: 2,
                ..Counters::default()
            },
            now,
        );
        assert_eq!(t.epoch.mutation_seq, 3);
    }

    #[test]
    fn volatile_mutations_do_not_restart_the_stable_clock() {
        let (mut s, now) = state();
        let t = s.tabs.get_mut("T1").unwrap();
        let before = t.last_stable_mut;
        // 40 volatile records (a ticker): the record count moves, the stable clock does not
        let later = now + Duration::from_secs(5);
        t.apply_counters(
            Counters {
                records: 40,
                volatile: 40,
                volatile_recent: 1,
                ..Counters::default()
            },
            later,
        );
        assert_eq!(t.last_stable_mut, before);
        assert_eq!(t.last_mut, later);
        // a stable record dated 300 ms before the read restarts it at that instant
        let read_at = later + Duration::from_secs(1);
        t.apply_counters(
            Counters {
                records: 41,
                stable: 1,
                volatile: 40,
                stable_age_ms: Some(300),
                ..Counters::default()
            },
            read_at,
        );
        assert_eq!(t.last_stable_mut, read_at - Duration::from_millis(300));
        // an older stable record read later never moves the clock backwards
        t.apply_counters(
            Counters {
                records: 41,
                stable: 1,
                stable_age_ms: Some(9_000),
                ..Counters::default()
            },
            read_at + Duration::from_secs(1),
        );
        assert_eq!(t.last_stable_mut, read_at - Duration::from_millis(300));
    }

    #[test]
    fn long_lived_requests_do_not_block_idle() {
        let (mut s, now) = state();
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "1", "type": "XHR", "request": {"url": "http://a.test/api/1", "method": "GET", "headers": {}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "2", "type": "WebSocket", "request": {"url": "ws://a.test/sock", "method": "GET", "headers": {}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "3", "type": "Fetch", "request": {"url": "http://a.test/stream", "method": "GET", "headers": {}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "3", "type": "Fetch", "response": {"url": "http://a.test/stream", "status": 200, "mimeType": "text/event-stream", "headers": {}}}),
        );
        let t = &s.tabs["T1"];
        assert_eq!(t.blocking_inflight(now), 1, "only the XHR blocks");
        // a request older than 10 s stops blocking
        assert_eq!(
            t.blocking_inflight(now + LONG_LIVED_AFTER + Duration::from_millis(1)),
            0
        );
        assert_eq!(t.long_lived_urls.len(), 2);
        feed(
            &mut s,
            now,
            "S1",
            "Network.loadingFinished",
            json!({"requestId": "1"}),
        );
        assert_eq!(s.tabs["T1"].blocking_inflight(now), 0);
    }

    #[test]
    fn traffic_is_redacted_and_marks_third_party() {
        let (mut s, now) = state();
        s.tabs.get_mut("T1").unwrap().url = "http://a.test/".to_owned();
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "9", "type": "XHR", "request": {
                "url": "http://cdn.test/x?token=abc&page=2",
                "method": "POST",
                "headers": {"Authorization": "Bearer s3cret", "Cookie": "sid=1", "Accept": "*/*"}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "9", "type": "XHR", "response": {
                "url": "http://cdn.test/x", "status": 201, "mimeType": "application/json",
                "headers": {"Set-Cookie": "sid=2", "Content-Type": "application/json"}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.loadingFinished",
            json!({"requestId": "9"}),
        );
        assert_eq!(s.traffic.len(), 1);
        let t = &s.traffic[0];
        assert_eq!(t.url, "http://cdn.test/x?token=[redacted]&page=2");
        assert_eq!(t.status, Some(201));
        assert!(t.third_party);
        assert_eq!(t.method, "POST");
        let auth = t
            .request_headers
            .iter()
            .find(|(k, _)| k == "Authorization")
            .unwrap();
        assert_eq!(auth.1, egress::REDACTED);
        let cookie = t.request_headers.iter().find(|(k, _)| k == "Cookie").unwrap();
        assert_eq!(cookie.1, egress::REDACTED);
        let setc = t
            .response_headers
            .iter()
            .find(|(k, _)| k == "Set-Cookie")
            .unwrap();
        assert_eq!(setc.1, egress::REDACTED);
        let accept = t.request_headers.iter().find(|(k, _)| k == "Accept").unwrap();
        assert_eq!(accept.1, "*/*");
        let rendered = format!("{:?}", s.traffic);
        assert!(!rendered.contains("s3cret") && !rendered.contains("sid=1") && !rendered.contains("sid=2"));
    }

    #[tokio::test]
    async fn configured_request_controls_are_masked_in_traffic() {
        use crawlx_core::config::Fetch;
        let mut fetch = Fetch::default();
        fetch.extra_headers.insert("x-tenant", "t-12345678");
        fetch
            .cookies
            .push(crawlx_core::request_controls::FetchCookie::new(
                "sid",
                "c-87654321",
            ));
        let controls = RequestControls::resolve(&fetch, "a.test", None).await.unwrap();
        let (s, now) = state();
        let mut s = s.with_controls(controls);
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "5", "type": "XHR", "request": {
                "url": "http://a.test/x", "method": "GET",
                "headers": {"X-Tenant": "t-12345678", "Accept": "*/*", "X-Forwarded": "via t-12345678"}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "5", "type": "XHR", "response": {
                "url": "http://a.test/x", "status": 200, "mimeType": "text/plain",
                "headers": {"X-Echo": "c-87654321", "Content-Type": "text/plain"}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.loadingFinished",
            json!({"requestId": "5"}),
        );
        let t = &s.traffic[0];
        let value =
            |hs: &[(String, String)], name: &str| hs.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
        assert_eq!(
            value(&t.request_headers, "X-Tenant").as_deref(),
            Some(egress::REDACTED)
        );
        assert_eq!(
            value(&t.request_headers, "X-Forwarded").as_deref(),
            Some(egress::REDACTED)
        );
        assert_eq!(value(&t.request_headers, "Accept").as_deref(), Some("*/*"));
        assert_eq!(
            value(&t.response_headers, "X-Echo").as_deref(),
            Some(egress::REDACTED)
        );
        assert_eq!(
            value(&t.response_headers, "Content-Type").as_deref(),
            Some("text/plain")
        );
        let rendered = format!("{:?}", s.traffic);
        assert!(
            !rendered.contains("t-12345678") && !rendered.contains("c-87654321"),
            "{rendered}"
        );
    }

    #[test]
    fn websocket_frames_are_metadata_only() {
        let (mut s, now) = state();
        feed(
            &mut s,
            now,
            "S1",
            "Network.webSocketCreated",
            json!({"requestId": "w", "url": "ws://a.test/s?auth=abc"}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.webSocketFrameSent",
            json!({"requestId": "w", "response": {"opcode": 1, "payloadData": "super secret payload"}}),
        );
        assert_eq!(s.traffic.len(), 1);
        let t = &s.traffic[0];
        assert_eq!(t.origin, TrafficOrigin::WebSocket);
        assert_eq!(t.method, "WS_SEND");
        assert!(!format!("{t:?}").contains("super secret"));
        assert_eq!(t.url, "ws://a.test/s?auth=[redacted]");
    }

    #[test]
    fn egress_denials_and_redirects_are_tracked() {
        let (mut s, now) = state();
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "r", "type": "Document", "frameId": "F1", "request": {"url": "http://a.test/old", "method": "GET", "headers": {}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "r", "type": "Document", "frameId": "F1",
                   "redirectResponse": {"url": "http://a.test/old", "status": 302, "headers": {}},
                   "request": {"url": "http://a.test/new", "method": "GET", "headers": {}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "r", "type": "Document", "frameId": "F1",
                   "response": {"url": "http://a.test/new", "status": 403, "mimeType": "text/plain",
                                "headers": {"X-Crawlx-Egress-Denied": "private-range"}}}),
        );
        let t = &s.tabs["T1"];
        assert_eq!(t.nav_redirects, vec!["http://a.test/old"]);
        assert_eq!(t.nav_status, Some(403));
        assert_eq!(s.blocked_by_egress, vec!["http://a.test/new"]);
        assert_eq!(s.traffic.len(), 1, "the redirect hop was finalized");
        assert_eq!(s.traffic[0].status, Some(302));
    }

    #[test]
    fn main_document_response_keeps_lowercase_redacted_headers_of_the_last_hop() {
        let (mut s, now) = state();
        assert_eq!(s.tabs["T1"].nav_response, None);
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "i", "type": "Image", "frameId": "F1",
                   "response": {"url": "http://a.test/i.png", "status": 200, "mimeType": "image/png",
                                "headers": {"X-Image": "1"}}}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "f", "type": "Document", "frameId": "OTHER",
                   "response": {"url": "http://a.test/frame", "status": 200, "mimeType": "text/html",
                                "headers": {"X-Frame": "1"}}}),
        );
        assert_eq!(
            s.tabs["T1"].nav_response, None,
            "subresources and subframes are not the document"
        );
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "d", "type": "Document", "frameId": "F1",
                   "response": {"url": "http://a.test/", "status": 200, "mimeType": "text/html",
                                "headers": {"Content-Type": "text/html; charset=utf-8",
                                            "X-Custom": "hello", "Set-Cookie": "sid=abc123"}}}),
        );
        let first = s.tabs["T1"].nav_response.clone().unwrap();
        assert_eq!(first.status, Some(200));
        assert_eq!(first.content_type.as_deref(), Some("text/html"));
        assert!(first
            .headers
            .contains(&("x-custom".to_owned(), "hello".to_owned())));
        assert!(first
            .headers
            .contains(&("set-cookie".to_owned(), egress::REDACTED.to_owned())));
        assert!(first.headers.iter().all(|(k, _)| *k == k.to_ascii_lowercase()));
        assert!(!format!("{first:?}").contains("abc123"));
        // a later navigation's document replaces it
        feed(
            &mut s,
            now,
            "S1",
            "Network.responseReceived",
            json!({"requestId": "e", "type": "Document", "frameId": "F1",
                   "response": {"url": "http://a.test/next", "status": 404, "mimeType": "",
                                "headers": {}}}),
        );
        let last = s.tabs["T1"].nav_response.clone().unwrap();
        assert_eq!(last.status, Some(404));
        assert_eq!(last.content_type, None);
        assert!(last.headers.is_empty());
    }

    #[test]
    fn load_event_records_loader_and_dialogs_are_handled() {
        let (mut s, now) = state();
        feed(
            &mut s,
            now,
            "S1",
            "Page.frameStartedLoading",
            json!({"frameId": "F1"}),
        );
        assert!(s.tabs["T1"].loading);
        feed(
            &mut s,
            now,
            "S1",
            "Page.lifecycleEvent",
            json!({"frameId": "F1", "loaderId": "L1", "name": "load"}),
        );
        feed(
            &mut s,
            now,
            "S1",
            "Page.frameStoppedLoading",
            json!({"frameId": "F1"}),
        );
        assert!(s.tabs["T1"].loaded.contains("L1"));
        assert!(!s.tabs["T1"].loading);
        let f = feed(
            &mut s,
            now,
            "S1",
            "Page.javascriptDialogOpening",
            json!({"type": "confirm", "message": "Sure?"}),
        );
        assert_eq!(
            f,
            vec![Followup::HandleDialog {
                session: "S1".to_owned(),
                accept: false
            }]
        );
        assert_eq!(s.tabs["T1"].dialogs[0].kind, "confirm");
        let f = feed(
            &mut s,
            now,
            "S1",
            "Page.javascriptDialogOpening",
            json!({"type": "alert", "message": "hi"}),
        );
        assert_eq!(
            f,
            vec![Followup::HandleDialog {
                session: "S1".to_owned(),
                accept: true
            }]
        );
    }

    #[test]
    fn excess_popups_wait_for_worker_policy_without_attaching() {
        let (mut s, now) = state();
        let created = |id: &str| {
            ev(
                None,
                "Target.targetCreated",
                json!({"targetInfo": {"targetId": id, "type": "page", "url": "http://p/", "openerId": "T1", "browserContextId": "CTX"}}),
            )
        };
        let w = Timestamp::default();
        assert_eq!(
            s.handle_event(&created("P1"), now, w),
            vec![Followup::AttachPopup {
                target_id: "P1".into()
            }]
        );
        assert_eq!(
            s.handle_event(&created("P2"), now, w),
            vec![Followup::AttachPopup {
                target_id: "P2".into()
            }]
        );
        assert!(s.handle_event(&created("P3"), now, w).is_empty());
        assert!(s.graph.infos("T1").iter().any(|t| t.id.0 == "P3" && t.pending));
        // other contexts' targets and opener-less targets are ignored
        let foreign = ev(
            None,
            "Target.targetCreated",
            json!({"targetInfo": {"targetId": "X", "type": "page", "openerId": "T1", "browserContextId": "OTHER"}}),
        );
        assert!(s.handle_event(&foreign, now, w).is_empty());
    }

    #[test]
    fn browser_closed_download_survives_inflight_popup_setup_failure_until_policy_acknowledges_it() {
        for attached in [false, true] {
            let (mut state, now) = state();
            let wall = Timestamp::default();
            let url = "http://p/report.csv";
            state.graph.on_target_created("same-url", Some("T1"), url, now);
            state.handle_event(
                &ev(
                    None,
                    "Target.targetCreated",
                    json!({"targetInfo": {"targetId": "download", "type": "page", "url": "",
                        "openerId": "T1", "browserContextId": "CTX"}}),
                ),
                now,
                wall,
            );
            let frame = if attached { "download-frame" } else { "download" };
            if attached {
                state
                    .tabs
                    .insert("download".into(), Tab::new("download", "S2", frame, "", now));
            }
            // Chromium identifies the owning target before popup setup finishes, then
            // detaches and destroys it while a setup command is still in flight.
            state.handle_event(
                &ev(
                    None,
                    "Browser.downloadWillBegin",
                    json!({"frameId": frame, "url": url}),
                ),
                now,
                wall,
            );
            for event in [
                ev(
                    None,
                    "Target.detachedFromTarget",
                    json!({"sessionId": "S2", "targetId": "download"}),
                ),
                ev(None, "Target.targetDestroyed", json!({"targetId": "download"})),
            ] {
                state.handle_event(&event, now, wall);
            }
            assert!(state.graph.closed_download("download"));
            assert!(!state.attaching.contains("download"));
            assert!(!state.tabs.contains_key("download"));
            let tabs = state.graph.infos("T1");
            assert!(tabs
                .iter()
                .any(|tab| tab.id.0 == "download" && tab.download && tab.url == url));
            assert!(tabs.iter().any(|tab| tab.id.0 == "same-url" && !tab.download));
            state.handle_event(
                &ev(None, "Target.targetDestroyed", json!({"targetId": "same-url"})),
                now,
                wall,
            );
            assert!(!state.graph.contains("same-url"));
            state.remove_tab("download");
            assert!(!state.graph.contains("download"));
        }
    }

    #[test]
    fn destroying_the_active_tab_falls_back_to_the_opener() {
        let (mut s, now) = state();
        s.graph.on_target_created("P1", Some("T1"), "http://p/", now);
        s.tabs
            .insert("P1".into(), Tab::new("P1", "S2", "F9", "http://p/", now));
        s.active = "P1".into();
        s.handle_event(
            &ev(None, "Target.targetDestroyed", json!({"targetId": "P1"})),
            now,
            Timestamp::default(),
        );
        assert_eq!(s.active, "T1");
        assert!(!s.graph.contains("P1"));
    }

    #[test]
    fn network_epoch_opens_fresh_counters() {
        let (mut s, now) = state();
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({"requestId": "1", "type": "XHR", "request": {"url": "http://a.test/items/42", "method": "GET", "headers": {}}}),
        );
        let t = s.tabs.get_mut("T1").unwrap();
        let first = t.net_epoch;
        let summary = t.network_summary(now);
        assert_eq!(summary.requests, 1);
        assert_eq!(summary.operations, vec!["GET /items/:id"]);
        let second = t.open_network_epoch();
        assert_ne!(first, second);
        assert_eq!(t.network_summary(now).requests, 0);
        // the in-flight request finishes in the new epoch: late
        feed(
            &mut s,
            now,
            "S1",
            "Network.loadingFinished",
            json!({"requestId": "1"}),
        );
        assert!(s.traffic[0].late);
        assert_eq!(s.tabs["T1"].epoch_late, 1);
    }

    #[test]
    fn cdp_protocols_and_frame_metadata_are_reported_without_body_retention() {
        for (reported, expected) in [
            ("http/1.1", Some(Protocol::Http11)),
            ("h2", Some(Protocol::H2)),
            ("h3", Some(Protocol::H3)),
            ("future-protocol", None),
        ] {
            let (mut s, now) = state();
            s.tabs.get_mut("T1").unwrap().url = "http://a.test/".to_owned();
            feed(
                &mut s,
                now,
                "S1",
                "Network.requestWillBeSent",
                json!({
                    "requestId": "r", "frameId": "F1", "type": "Fetch",
                    "request": {"url": "http://a.test/data", "method": "GET", "headers": {}}
                }),
            );
            feed(
                &mut s,
                now,
                "S1",
                "Network.responseReceived",
                json!({
                    "requestId": "r", "response": {"protocol": reported, "status": 200,
                    "mimeType": "application/json", "headers": {"x-crawlx-body-state": "forged"}}
                }),
            );
            let jobs = feed(
                &mut s,
                now,
                "S1",
                "Network.loadingFinished",
                json!({
                    "requestId": "r", "encodedDataLength": 42
                }),
            );
            assert!(jobs.is_empty());
            let event = &s.traffic[0];
            assert_eq!(event.protocol, expected);
            assert!(event.response_body.is_none());
            assert!(event
                .request_headers
                .contains(&("x-crawlx-frame-id".into(), "F1".into())));
            assert_eq!(
                event
                    .response_headers
                    .iter()
                    .filter(|(name, _)| name == "x-crawlx-body-state")
                    .map(|(_, value)| value.as_str())
                    .collect::<Vec<_>>(),
                vec!["metadata_only"]
            );
        }
    }

    #[test]
    fn browser_level_worker_attachment_is_scoped_and_not_registered_twice() {
        let (mut s, now) = state();
        let attached = |context: &str| {
            ev(
                None,
                "Target.attachedToTarget",
                json!({
                    "sessionId": "SW", "targetInfo": {"type": "service_worker", "targetId": "W",
                    "browserContextId": context, "url": "http://a.test/worker.js"}
                }),
            )
        };
        assert!(s
            .handle_event(&attached("OTHER"), now, Timestamp::default())
            .is_empty());
        assert!(s.workers.is_empty());
        assert_eq!(
            s.handle_event(&attached("CTX"), now, Timestamp::default()),
            vec![Followup::SetupWorker { session: "SW".into() }]
        );
        assert!(s
            .handle_event(&attached("CTX"), now, Timestamp::default())
            .is_empty());
        assert_eq!(s.workers.len(), 1);
        assert!(s.workers["W"].service_worker);
        assert_eq!(s.tabs.len(), 1, "workers never become user-action tabs");
    }

    #[test]
    fn service_worker_and_sse_events_have_explicit_attribution_and_no_payload() {
        let (mut s, now) = state();
        let attached = feed(
            &mut s,
            now,
            "S1",
            "Target.attachedToTarget",
            json!({
                "sessionId": "SW", "targetInfo": {"type": "service_worker", "targetId": "W",
                "url": "http://a.test/sw.js"}
            }),
        );
        assert_eq!(attached, vec![Followup::SetupWorker { session: "SW".into() }]);
        feed(
            &mut s,
            now,
            "SW",
            "Network.requestWillBeSent",
            json!({
                "requestId": "worker-r", "type": "Fetch",
                "request": {"url": "http://a.test/background", "method": "GET", "headers": {}}
            }),
        );
        feed(
            &mut s,
            now,
            "SW",
            "Network.loadingFinished",
            json!({"requestId": "worker-r"}),
        );
        let event = &s.traffic[0];
        assert_eq!(event.origin, TrafficOrigin::ServiceWorker);
        assert_eq!(event.epoch_id, None);
        assert_eq!(event.unattributed_reason, Some(UnattributedReason::NotApplicable));
        feed(
            &mut s,
            now,
            "S1",
            "Network.requestWillBeSent",
            json!({
                "requestId": "sse", "frameId": "F1", "type": "EventSource",
                "request": {"url": "http://a.test/events", "method": "GET", "headers": {}}
            }),
        );
        let epoch = s.tabs["T1"].net_epoch;
        feed(
            &mut s,
            now,
            "S1",
            "Network.eventSourceMessageReceived",
            json!({
                "requestId": "sse", "eventName": "arbitrary-sensitive-event",
                "eventId": "sensitive-id", "data": "secret payload"
            }),
        );
        let frame = &s.traffic[1];
        assert_eq!(frame.origin, TrafficOrigin::EventSource);
        assert_eq!(frame.method, "SSE_RECV");
        assert_eq!(frame.epoch_id, Some(epoch));
        assert_eq!(s.tabs["T1"].blocking_inflight(now), 0);
        let encoded = serde_json::to_string(frame).unwrap();
        assert!(!encoded.contains("secret payload"));
        assert!(!encoded.contains("sensitive"));
    }

    #[test]
    fn capped_prefix_decision_can_finish_before_or_after_request_without_duplicate_events() {
        for early in [false, true] {
            let (mut s, now) = state();
            s.capture_text = true;
            s.tabs.get_mut("T1").unwrap().url = "http://a.test/".into();
            feed(
                &mut s,
                now,
                "S1",
                "Network.requestWillBeSent",
                json!({
                    "requestId": "r", "type": "Fetch",
                    "request": {"url": "http://a.test/large", "method": "GET", "headers": {}}
                }),
            );
            let jobs = feed(
                &mut s,
                now,
                "S1",
                "Network.responseReceived",
                json!({
                    "requestId": "r", "response": {"status": 200, "mimeType": "text/html", "headers": {}}
                }),
            );
            assert_eq!(
                jobs,
                vec![Followup::CapturePrefix {
                    session: "S1".into(),
                    request_id: "r".into(),
                    content_type: "text/html".into(),
                }]
            );
            let key = ("S1".to_owned(), "r".to_owned());
            let artifact = crawlx_core::ArtifactRef {
                id: crawlx_core::ArtifactId::new(),
                digest: crawlx_core::hash::Digest::of("capture-prefix-test", b"public-prefix"),
            };
            if early {
                s.text_prefixes.get_mut(&key).unwrap().result = Some(Ok(artifact.clone()));
                s.finish_prefix(&key);
                assert!(s.traffic.is_empty());
            }
            let jobs = feed(
                &mut s,
                now,
                "S1",
                "Network.loadingFinished",
                json!({"requestId": "r", "encodedDataLength": 2_000_000}),
            );
            assert!(jobs.is_empty(), "prefix job already owns this request");
            if !early {
                assert_eq!(s.pending_bodies.len(), 1);
                s.text_prefixes.get_mut(&key).unwrap().result = Some(Ok(artifact.clone()));
                s.finish_prefix(&key);
            }
            assert_eq!(s.traffic.len(), 1);
            assert_eq!(s.traffic[0].response_body, Some(artifact));
            assert!(s.traffic[0]
                .response_headers
                .contains(&("x-crawlx-body-state".into(), "stored_prefix".into())));
            assert!(s.pending_bodies.is_empty());
            assert!(s.text_prefixes.is_empty());
        }
    }

    #[test]
    fn full_response_capture_has_explicit_policy_size_and_capacity_limits() {
        for (url, headers, size, slots, expected) in [
            ("http://a.test/data", json!({}), 42, 0, "pending"),
            ("http://other.test/data", json!({}), 42, 0, "policy_denied"),
            ("http://a.test/token", json!({}), 42, 0, "policy_denied"),
            (
                "http://a.test/data",
                json!({"Set-Cookie": "secret"}),
                42,
                0,
                "policy_denied",
            ),
            ("http://a.test/data", json!({}), 1_048_577, 0, "oversized"),
            ("http://a.test/data", json!({}), 42, 8, "capacity_exceeded"),
        ] {
            let (mut s, now) = state();
            s.capture_full = true;
            s.tabs.get_mut("T1").unwrap().url = "http://a.test/".into();
            s.pending_bodies.extend(100..100 + slots);
            feed(
                &mut s,
                now,
                "S1",
                "Network.requestWillBeSent",
                json!({
                    "requestId": "r", "type": "Fetch",
                    "request": {"url": url, "method": "GET", "headers": {}}
                }),
            );
            feed(
                &mut s,
                now,
                "S1",
                "Network.responseReceived",
                json!({
                    "requestId": "r", "response": {"status": 200, "mimeType": "application/json",
                    "headers": headers}
                }),
            );
            let jobs = feed(
                &mut s,
                now,
                "S1",
                "Network.loadingFinished",
                json!({"requestId": "r", "encodedDataLength": size}),
            );
            assert_eq!(jobs.len(), usize::from(expected == "pending"));
            assert!(s.traffic[0]
                .response_headers
                .contains(&("x-crawlx-body-state".into(), expected.into())));
        }
    }

    #[test]
    fn crash_events_mark_tabs() {
        let (mut s, now) = state();
        feed(&mut s, now, "S1", "Inspector.targetCrashed", json!({}));
        assert!(s.tabs["T1"].crashed);
    }

    #[test]
    fn refused_navigations_are_queued_unless_the_navigation_that_waits_returns_them() {
        let (mut s, _) = state();
        let link = BlockedNavigation::new("http://a.test/private/x", "robots_disallow");
        // a page's own navigation: queued for the next drain, and the tab remembers it
        s.record_blocked_navigation("T1", link.clone());
        assert_eq!(s.tabs["T1"].nav_blocked.as_ref(), Some(&link));
        assert_eq!(s.take_blocked_navigations(), vec![link.clone()]);
        assert!(s.take_blocked_navigations().is_empty());

        // a navigation the context itself waits on reports the refusal as its own error: it is
        // not queued a second time
        let hop = BlockedNavigation::new("http://a.test/private/hop", "robots_unavailable");
        s.record_blocked_navigation("T1", link.clone());
        s.record_blocked_navigation("T1", hop.clone());
        assert_eq!(s.take_nav_blocked("T1"), Some(hop));
        assert_eq!(s.take_nav_blocked("T1"), None, "taken once");
        assert_eq!(s.take_blocked_navigations(), vec![link]);
    }

    #[test]
    fn the_refusal_queue_is_bounded() {
        let (mut s, _) = state();
        for i in 0..MAX_BLOCKED_NAVIGATIONS + 10 {
            s.record_blocked_navigation(
                "T1",
                BlockedNavigation::new(format!("http://a.test/p/{i}"), "robots_disallow"),
            );
        }
        let kept = s.take_blocked_navigations();
        assert_eq!(kept.len(), MAX_BLOCKED_NAVIGATIONS);
        assert_eq!(kept[0].url, "http://a.test/p/10", "the oldest were dropped first");
    }

    #[test]
    fn console_preview_bounds_utf8_and_ignores_object_payloads() {
        let parameters = serde_json::json!({
            "type": "log",
            "args": [{"value": true}, {"value": {"oversized": "not serialized"}},
                     {"value": "界".repeat(MAX_CONSOLE_BYTES)}],
        });
        let (line, truncated) = console_line(&parameters);
        assert!(truncated);
        assert!(line.starts_with("log: true  "));
        assert!(line.len() <= MAX_CONSOLE_BYTES);
        assert!(line.is_char_boundary(line.len()));
        assert!(!line.contains("oversized"));
    }
}
