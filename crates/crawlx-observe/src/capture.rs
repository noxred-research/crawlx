//! Capture backends: the [`TrafficSource`] contract both backends
//! implement, [`CdpTraffic`] over the browser context's own (already attributed)
//! events, and [`ProxyTraffic`] over the flows of the loopback egress proxy.
//!
//! The proxy sees wire traffic without any notion of the action that caused it, so
//! `ProxyTraffic` attributes each flow itself, in this order:
//!
//! 1. **CDP correlation.** The session's CDP events (fed through
//!    [`ProxyTraffic::observe_cdp`]) are the authority for attribution. A flow with
//!    the same method and redacted URL that started within
//!    [`CDP_MATCH_TOLERANCE_MS`] of a CDP event inherits that event's epoch, `late`
//!    flag and session. Each CDP event matches at most one flow, so repeated identical
//!    requests stay distinct (raw stream, never deduplicated).
//! 2. **Epoch windows.** Otherwise the flow is attributed to the epoch of the session
//!    whose latest window started at or before the flow; a flow that started after that
//!    window settled is `late`. When windows of several
//!    sessions qualify the flow is ambiguous and treated as unmatched.
//! 3. **Unmatched.** No window at all, or an ambiguous one: `epoch_id = None`,
//!    `unattributed_reason = UnmatchedProxyFlow`, counted in
//!    [`ProxyCaptureStats::unmatched`]; the event is kept, never dropped.
//!
//! Fetch-plane flows carry `origin = fetch_plane`, no epoch and
//! `unattributed_reason = NotApplicable`. A proxy cannot
//! identify service workers itself; a matched CDP event is authoritative for origin.
//! CDP supplements retain decrypted HTTPS, stream metadata and body artifact references
//! separately from opaque proxy CONNECT events. Reserved `x-crawlx-capture-source`
//! response metadata identifies `cdp`, `proxy` and `cdp_supplement`; raw events are never
//! deduplicated. Only derived operation views exclude proxy tunnels and collapse repeats.
//! Redaction: the proxy task already replaced credential header values; the
//! [`Redactor`] then handles the URL (session-class query parameters, userinfo), the
//! wider header list and `third_party` before the event leaves this module.
//!
//! This module reads no clock: every flow and window carries its timestamp.

use crate::error::CaptureError;
use crate::traffic::Redactor;
use async_trait::async_trait;
use chrono::Duration;
use crawlx_core::config::CaptureBackend;
use crawlx_core::ids::{NetworkEpochId, SessionId};
use crawlx_core::time::Timestamp;
use crawlx_core::traffic::{
    Protocol, ProxyFlow, ProxyFlowSource, TrafficEvent, TrafficOrigin, UnattributedReason,
};
use std::collections::{BTreeMap, VecDeque};
use tokio::sync::mpsc;

/// How far apart (ms) a proxy flow and a CDP event of the same method and URL may start
/// and still be the same request.
pub const CDP_MATCH_TOLERANCE_MS: i64 = 5_000;

/// Epoch windows kept per session; older ones are forgotten.
const MAX_WINDOWS_PER_SESSION: usize = 64;
/// CDP candidates kept for correlation across all sessions.
const MAX_CDP_CANDIDATES: usize = 4096;

/// Protocols the proxy backend cannot observe (Chromium runs with QUIC disabled).
const PROXY_PROTOCOLS_DISABLED: &[Protocol] = &[Protocol::H3];

/// Reserved response metadata identifying the observer, not an upstream HTTP header.
const CAPTURE_SOURCE: &str = "x-crawlx-capture-source";

fn mark_source(event: &mut TrafficEvent, source: &str) {
    // An upstream response cannot impersonate capture provenance.
    event
        .request_headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(CAPTURE_SOURCE));
    event
        .response_headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(CAPTURE_SOURCE));
    event
        .response_headers
        .push((CAPTURE_SOURCE.to_owned(), source.to_owned()));
}

fn capture_source(event: &TrafficEvent) -> Option<&str> {
    event
        .response_headers
        .iter()
        .find(|(name, _)| name == CAPTURE_SOURCE)
        .map(|(_, value)| value.as_str())
}

/// One chronological, never deduplicated stream of redacted traffic events.
#[async_trait]
pub trait TrafficSource: Send {
    /// The next event in capture order; `None` when the source is exhausted.
    ///
    /// # Errors
    /// [`CaptureError`] when the backend fails; a closed proxy channel is `Ok(None)`.
    async fn next_event(&mut self) -> Result<Option<TrafficEvent>, CaptureError>;
    /// Which backend produced the stream.
    fn backend(&self) -> CaptureBackend;
    /// Protocols the backend disabled in the browser to be able to observe traffic
    /// (recorded on the session).
    fn protocols_disabled(&self) -> &[Protocol];
}

/// The default backend: events the browser context already attributed and redacted,
/// fed from `BrowserContext::drain_traffic`.
///
/// The browser marks `late` only when a request *finishes* in a later epoch; the
/// contract also makes a request that *starts* after its epoch
/// settled `late`. With the epoch windows fed through [`CdpTraffic::open_epoch`] /
/// [`CdpTraffic::close_epoch`] the source applies that rule on every pushed batch; without
/// windows the events pass through unchanged.
#[derive(Debug, Default)]
pub struct CdpTraffic {
    queue: VecDeque<TrafficEvent>,
    settled: BTreeMap<NetworkEpochId, Option<Timestamp>>,
    /// Events re-tagged `late` by the window rule.
    retagged_late: u64,
}

impl CdpTraffic {
    /// Empty source.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// An epoch opened (the action's receipt time); its settle time is unknown yet.
    pub fn open_epoch(&mut self, epoch: NetworkEpochId) {
        self.settled.insert(epoch, None);
        while self.settled.len() > MAX_WINDOWS_PER_SESSION {
            // ids are UUIDv7: the smallest is the oldest
            let Some(oldest) = self.settled.keys().next().copied() else {
                break;
            };
            self.settled.remove(&oldest);
        }
    }

    /// The epoch settled at `settled_at`.
    pub fn close_epoch(&mut self, epoch: NetworkEpochId, settled_at: Timestamp) {
        if let Some(s) = self.settled.get_mut(&epoch) {
            *s = Some(settled_at);
        }
    }

    /// Append a drained batch in its original order, applying the window rule.
    pub fn push_drained(&mut self, events: Vec<TrafficEvent>) {
        for mut ev in events {
            let after_settle = ev
                .epoch_id
                .and_then(|e| self.settled.get(&e).copied().flatten())
                .is_some_and(|s| ev.started_at > s);
            if after_settle && !ev.late {
                ev.late = true;
                self.retagged_late += 1;
            }
            mark_source(&mut ev, "cdp");
            self.queue.push_back(ev);
        }
    }

    /// Yield everything waiting, in order.
    pub fn drain(&mut self) -> Vec<TrafficEvent> {
        self.queue.drain(..).collect()
    }

    /// Events the window rule marked `late` that the browser had not.
    #[must_use]
    pub const fn retagged_late(&self) -> u64 {
        self.retagged_late
    }

    /// Events not yet yielded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// No event is waiting.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[async_trait]
impl TrafficSource for CdpTraffic {
    async fn next_event(&mut self) -> Result<Option<TrafficEvent>, CaptureError> {
        Ok(self.queue.pop_front())
    }

    fn backend(&self) -> CaptureBackend {
        CaptureBackend::Cdp
    }

    fn protocols_disabled(&self) -> &[Protocol] {
        &[]
    }
}

/// Counters of the proxy backend (`traffic_unattributed_total`,
/// `unmatched_proxy_flows_total`, `traffic_late_ratio = late / flows`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct ProxyCaptureStats {
    /// Flows received from the proxy and the fetch plane.
    pub flows: u64,
    /// Flows attributed through a CDP event.
    pub cdp_matched: u64,
    /// Flows attributed through an epoch window only.
    pub window_matched: u64,
    /// Attributed flows tagged `late`.
    pub late: u64,
    /// Browser flows that matched no CDP event and no unambiguous window.
    pub unmatched: u64,
    /// Every event without an epoch (unmatched plus fetch-plane).
    pub unattributed: u64,
}

#[derive(Clone, Copy, Debug)]
struct Window {
    session: SessionId,
    started_at: Timestamp,
    settled_at: Option<Timestamp>,
}

#[derive(Clone, Copy, Debug)]
struct CdpCandidate {
    session: SessionId,
    epoch: Option<NetworkEpochId>,
    origin: TrafficOrigin,
    reason: Option<UnattributedReason>,
    started_at: Timestamp,
    late: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Attribution {
    session: Option<SessionId>,
    epoch: Option<NetworkEpochId>,
    late: bool,
    reason: Option<UnattributedReason>,
}

/// The proxy backend: flows from [`crawlx_core::traffic::ProxyFlow`] producers,
/// attributed to epochs as described in the module documentation.
#[derive(Debug)]
pub struct ProxyTraffic {
    rx: mpsc::Receiver<ProxyFlow>,
    redactor: Redactor,
    windows: BTreeMap<NetworkEpochId, Window>,
    /// `(method, redacted url)` to CDP events not yet claimed by a flow.
    cdp: BTreeMap<(String, String), VecDeque<CdpCandidate>>,
    cdp_len: usize,
    ready: VecDeque<(Option<SessionId>, TrafficEvent)>,
    seq: u64,
    stats: ProxyCaptureStats,
}

impl ProxyTraffic {
    /// Source over `rx`; `redactor` carries the run's correlation key and classifier.
    #[must_use]
    pub fn new(rx: mpsc::Receiver<ProxyFlow>, redactor: Redactor) -> Self {
        Self {
            rx,
            redactor,
            windows: BTreeMap::new(),
            cdp: BTreeMap::new(),
            cdp_len: 0,
            ready: VecDeque::new(),
            seq: 0,
            stats: ProxyCaptureStats::default(),
        }
    }

    /// Origin of the page the traffic belongs to, for `third_party` marking.
    pub fn set_page_origin(&mut self, origin: impl Into<String>) {
        self.redactor.set_page_origin(origin);
    }

    /// Counters so far.
    #[must_use]
    pub const fn stats(&self) -> ProxyCaptureStats {
        self.stats
    }

    /// An epoch of `session` opened at `started_at` (the action's intent / receipt time).
    pub fn open_epoch(&mut self, epoch: NetworkEpochId, session: SessionId, started_at: Timestamp) {
        self.windows.insert(
            epoch,
            Window {
                session,
                started_at,
                settled_at: None,
            },
        );
        let mine: Vec<(Timestamp, NetworkEpochId)> = self
            .windows
            .iter()
            .filter(|(_, w)| w.session == session)
            .map(|(id, w)| (w.started_at, *id))
            .collect();
        if mine.len() > MAX_WINDOWS_PER_SESSION {
            let mut sorted = mine;
            sorted.sort();
            for (_, id) in sorted.iter().take(sorted.len() - MAX_WINDOWS_PER_SESSION) {
                self.windows.remove(id);
            }
        }
    }

    /// The epoch settled at `settled_at`; later flows attributed to it are `late`.
    pub fn close_epoch(&mut self, epoch: NetworkEpochId, settled_at: Timestamp) {
        if let Some(w) = self.windows.get_mut(&epoch) {
            w.settled_at = Some(settled_at);
        }
    }

    /// Feed the CDP events `session`'s browser context drained, so flows can be
    /// correlated to the backend that knows the action.
    pub fn observe_cdp(&mut self, session: SessionId, events: &[TrafficEvent]) {
        for ev in events {
            // Background service-worker events remain epochless even inside a page window.
            let key = (ev.method.to_ascii_uppercase(), ev.url.clone());
            self.cdp.entry(key).or_default().push_back(CdpCandidate {
                session,
                epoch: ev.epoch_id,
                origin: ev.origin,
                reason: ev.unattributed_reason,
                started_at: ev.started_at,
                late: ev.late,
            });
            self.cdp_len += 1;
        }
        while self.cdp_len > MAX_CDP_CANDIDATES {
            // forget the oldest candidate of the oldest key
            let Some(key) = self
                .cdp
                .iter()
                .filter_map(|(k, q)| q.front().map(|c| (c.started_at, k.clone())))
                .min()
                .map(|(_, k)| k)
            else {
                break;
            };
            if let Some(q) = self.cdp.get_mut(&key) {
                q.pop_front();
                self.cdp_len -= 1;
                if q.is_empty() {
                    self.cdp.remove(&key);
                }
            }
        }
        self.correlate_waiting();
    }

    /// Retain every browser event as an explicitly identified CDP supplement.
    ///
    /// The proxy cannot decrypt CONNECT tunnels or retain browser response artifacts.
    /// Supplements therefore remain separate raw events, including matching HTTP
    /// requests. Consumers deduplicate only derived views.
    pub fn push_cdp(&mut self, session: SessionId, events: Vec<TrafficEvent>) {
        self.observe_cdp(session, &events);
        for mut event in events {
            event.late |= event
                .epoch_id
                .and_then(|epoch| self.windows.get(&epoch))
                .and_then(|window| window.settled_at)
                .is_some_and(|settled| event.started_at > settled);
            mark_source(&mut event, "cdp_supplement");
            self.ready.push_back((Some(session), event));
        }
    }

    /// Take every flow waiting on the channel without blocking and attribute it.
    /// Returns how many flows were taken.
    pub fn pump(&mut self) -> usize {
        let mut n = 0;
        while let Ok(flow) = self.rx.try_recv() {
            let (owner, ev) = self.attribute(flow);
            self.ready.push_back((owner, ev));
            n += 1;
        }
        n
    }

    /// Attributed events of `session`'s epochs plus every unattributed event not yet
    /// handed out, in capture order. Unattributed events go to whichever session drains
    /// first so they are journaled (with their reason) rather than lost.
    pub fn take_for(&mut self, session: SessionId) -> Vec<TrafficEvent> {
        let mut out = Vec::new();
        let mut keep = VecDeque::with_capacity(self.ready.len());
        for (owner, ev) in self.ready.drain(..) {
            if owner.is_none_or(|s| s == session) {
                out.push(ev);
            } else {
                keep.push_back((owner, ev));
            }
        }
        self.ready = keep;
        // Stable sorting preserves source order when timestamps tie. Events arriving
        // after an earlier drain keep arrival order across drains; seq never rewinds.
        out.sort_by_key(|event| event.started_at);
        for event in &mut out {
            self.seq = self.seq.saturating_add(1);
            event.seq = self.seq;
        }
        out
    }

    /// Events waiting to be taken.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.ready.len()
    }

    fn match_cdp(&mut self, method: &str, url: &str, at: Timestamp) -> Option<CdpCandidate> {
        let key = (method.to_ascii_uppercase(), url.to_owned());
        let queue = self.cdp.get_mut(&key)?;
        let tolerance = Duration::milliseconds(CDP_MATCH_TOLERANCE_MS);
        let best = queue
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                let delta = if c.started_at > at {
                    c.started_at - at
                } else {
                    at - c.started_at
                };
                delta <= tolerance
            })
            .min_by_key(|(_, c)| {
                if c.started_at > at {
                    c.started_at - at
                } else {
                    at - c.started_at
                }
            })
            .map(|(i, _)| i)?;
        let found = queue.remove(best);
        self.cdp_len = self.cdp_len.saturating_sub(1);
        if queue.is_empty() {
            self.cdp.remove(&key);
        }
        found
    }

    /// Latest window per session that started at or before `at`.
    fn window_at(&self, at: Timestamp) -> Result<Option<(NetworkEpochId, Window)>, ()> {
        let mut latest: BTreeMap<SessionId, (NetworkEpochId, Window)> = BTreeMap::new();
        for (id, w) in &self.windows {
            if w.started_at > at {
                continue;
            }
            match latest.get(&w.session) {
                Some((_, cur)) if cur.started_at >= w.started_at => {}
                _ => {
                    latest.insert(w.session, (*id, *w));
                }
            }
        }
        match latest.len() {
            0 => Ok(None),
            1 => Ok(latest.into_values().next()),
            _ => Err(()),
        }
    }

    fn cdp_attribution(&mut self, event: &mut TrafficEvent) -> Option<Attribution> {
        let candidate = self.match_cdp(&event.method, &event.url, event.started_at)?;
        self.stats.cdp_matched += 1;
        event.origin = candidate.origin;
        event
            .response_headers
            .push(("x-crawlx-stream-cdp-correlated".to_owned(), "true".to_owned()));
        let after_settle = candidate
            .epoch
            .and_then(|epoch| self.windows.get(&epoch))
            .and_then(|window| window.settled_at)
            .is_some_and(|settled| candidate.started_at > settled);
        Some(Attribution {
            session: Some(candidate.session),
            epoch: candidate.epoch,
            late: candidate.late || after_settle,
            reason: candidate.reason,
        })
    }

    fn correlate_waiting(&mut self) {
        // Summary counters may pump the proxy before the browser drains CDP.
        // Reconcile only raw, unclaimed browser flows; never steal another match.
        let mut ready = std::mem::take(&mut self.ready);
        for (owner, event) in &mut ready {
            if capture_source(event) != Some("proxy")
                || event.origin == TrafficOrigin::FetchPlane
                || event
                    .response_headers
                    .iter()
                    .any(|(name, _)| name == "x-crawlx-stream-cdp-correlated")
            {
                continue;
            }
            let Some(attribution) = self.cdp_attribution(event) else {
                continue;
            };
            if event.epoch_id.is_some() {
                self.stats.window_matched = self.stats.window_matched.saturating_sub(1);
            } else {
                self.stats.unattributed = self.stats.unattributed.saturating_sub(1);
                self.stats.unmatched = self.stats.unmatched.saturating_sub(1);
            }
            self.stats.late = self.stats.late.saturating_sub(u64::from(event.late));
            *owner = attribution.session;
            event.epoch_id = attribution.epoch;
            event.unattributed_reason = attribution.reason;
            event.late = attribution.late;
            self.stats.unattributed += u64::from(event.epoch_id.is_none());
            self.stats.late += u64::from(event.late);
        }
        self.ready = ready;
    }

    fn attribute(&mut self, flow: ProxyFlow) -> (Option<SessionId>, TrafficEvent) {
        self.stats.flows += 1;
        // Sequence numbers are assigned when the combined stream is emitted.
        let origin = match flow.source {
            ProxyFlowSource::Browser => TrafficOrigin::Page,
            ProxyFlowSource::FetchPlane => TrafficOrigin::FetchPlane,
        };
        let draft = TrafficEvent {
            seq: 0,
            epoch_id: None,
            unattributed_reason: None,
            origin,
            method: flow.method,
            url: flow.url,
            status: flow.status,
            request_headers: flow.request_headers,
            response_headers: flow.response_headers,
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: Some(flow.protocol),
            started_at: flow.started_at,
            finished_at: Some(flow.finished_at),
        };
        let mut ev = self.redactor.redact(draft);
        // Preserve tunnel visibility without claiming decrypted headers or bodies.
        // Upstream headers cannot impersonate this reserved metadata namespace.
        let wire_header = |(name, _): &(String, String)| {
            !name
                .as_bytes()
                .get(..16)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"x-crawlx-stream-"))
        };
        ev.request_headers.retain(wire_header);
        ev.response_headers.retain(|header| {
            wire_header(header)
                || (origin == TrafficOrigin::FetchPlane
                    && matches!(
                        header.0.as_str(),
                        "x-crawlx-stream-body-mode"
                            | "x-crawlx-stream-body-capture"
                            | "x-crawlx-stream-body-truncated"
                            | "x-crawlx-stream-body-limit"
                            | "x-crawlx-stream-response-artifact-id"
                            | "x-crawlx-stream-response-artifact-digest"
                    ))
        });
        if origin == TrafficOrigin::FetchPlane {
            // Only the fetch producer may attach stored artifact references.
            // It strips this reserved namespace from wire headers before injection.
            let value = |name: &str| {
                ev.response_headers
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.as_str())
            };
            ev.response_body = value("x-crawlx-stream-response-artifact-id")
                .and_then(|id| id.parse::<crawlx_core::ArtifactId>().ok())
                .zip(
                    value("x-crawlx-stream-response-artifact-digest")
                        .and_then(|digest| crawlx_core::hash::Digest::from_hex(digest).ok()),
                )
                .map(|(id, digest)| crawlx_core::ArtifactRef { id, digest });
        }
        if let Some(tunnel) = flow.tunnel {
            ev.response_headers.extend([
                ("x-crawlx-stream-opaque".to_owned(), "true".to_owned()),
                ("x-crawlx-stream-bytes-up".to_owned(), tunnel.bytes_up.to_string()),
                (
                    "x-crawlx-stream-bytes-down".to_owned(),
                    tunnel.bytes_down.to_string(),
                ),
            ]);
        }
        for (side, body) in [("request", flow.request_body), ("response", flow.response_body)] {
            if let Some(body) = body {
                // A wire digest is metadata, never a fabricated stored artifact.
                ev.response_headers.extend([
                    (
                        format!("x-crawlx-stream-{side}-body-digest"),
                        body.digest.to_hex(),
                    ),
                    (
                        format!("x-crawlx-stream-{side}-body-length"),
                        body.len.to_string(),
                    ),
                    (
                        format!("x-crawlx-stream-{side}-body-truncated"),
                        body.truncated.to_string(),
                    ),
                ]);
            }
        }
        mark_source(&mut ev, "proxy");
        let at = ev.started_at;
        let a = if origin == TrafficOrigin::FetchPlane {
            Attribution {
                session: None,
                epoch: None,
                late: false,
                reason: Some(UnattributedReason::NotApplicable),
            }
        } else if let Some(attribution) = self.cdp_attribution(&mut ev) {
            attribution
        } else {
            match self.window_at(at) {
                Ok(Some((epoch, w))) => {
                    self.stats.window_matched += 1;
                    Attribution {
                        session: Some(w.session),
                        epoch: Some(epoch),
                        late: w.settled_at.is_some_and(|s| at > s),
                        reason: None,
                    }
                }
                Ok(None) | Err(()) => {
                    self.stats.unmatched += 1;
                    Attribution {
                        session: None,
                        epoch: None,
                        late: false,
                        reason: Some(UnattributedReason::UnmatchedProxyFlow),
                    }
                }
            }
        };
        if a.epoch.is_none() {
            self.stats.unattributed += 1;
        }
        if a.late {
            self.stats.late += 1;
        }
        ev.epoch_id = a.epoch;
        ev.unattributed_reason = a.reason;
        ev.late = a.late;
        (a.session, ev)
    }
}

#[async_trait]
impl TrafficSource for ProxyTraffic {
    async fn next_event(&mut self) -> Result<Option<TrafficEvent>, CaptureError> {
        self.pump();
        self.ready
            .make_contiguous()
            .sort_by_key(|(_, event)| event.started_at);
        let event = if let Some((_, event)) = self.ready.pop_front() {
            Some(event)
        } else {
            self.rx.recv().await.map(|flow| self.attribute(flow).1)
        };
        Ok(event.map(|mut event| {
            self.seq = self.seq.saturating_add(1);
            event.seq = self.seq;
            event
        }))
    }

    fn backend(&self) -> CaptureBackend {
        CaptureBackend::Proxy
    }

    fn protocols_disabled(&self) -> &[Protocol] {
        PROXY_PROTOCOLS_DISABLED
    }
}

/// Derived, deduplicated operation view of a raw stream (`METHOD url`), in first-seen
/// order: what `network_epochs` stores, while `traffic_events` keeps every event.
/// Explicitly identified proxy CONNECT events are transport metadata, not operations.
#[must_use]
pub fn operations(events: &[TrafficEvent]) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for ev in events {
        if capture_source(ev) == Some("proxy") && ev.method.eq_ignore_ascii_case("CONNECT") {
            continue;
        }
        let op = format!("{} {}", ev.method.to_ascii_uppercase(), ev.url);
        if seen.insert(op.clone()) {
            out.push(op);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::{DateTime, Utc};
    use crawlx_core::traffic::{Protocol, REDACTED_PLACEHOLDER};

    fn t(ms: i64) -> Timestamp {
        DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000 + ms).unwrap()
    }

    fn flow(method: &str, url: &str, at_ms: i64) -> ProxyFlow {
        ProxyFlow {
            source: ProxyFlowSource::Browser,
            method: method.to_owned(),
            url: url.to_owned(),
            status: Some(200),
            protocol: Protocol::Http11,
            request_headers: vec![
                ("authorization".to_owned(), REDACTED_PLACEHOLDER.to_owned()),
                ("x-api-key".to_owned(), "k-123".to_owned()),
            ],
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            tunnel: None,
            peer: Some("127.0.0.1:40000".parse().unwrap()),
            started_at: t(at_ms),
            finished_at: t(at_ms + 10),
        }
    }

    fn source() -> (mpsc::Sender<ProxyFlow>, ProxyTraffic) {
        let (tx, rx) = mpsc::channel(64);
        (tx, ProxyTraffic::new(rx, Redactor::new([7u8; 32])))
    }

    #[test]
    fn raw_stream_keeps_repeats_in_order_and_the_operation_view_dedupes() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let epoch = NetworkEpochId::new();
        src.open_epoch(epoch, session, t(0));
        for i in 0..3 {
            tx.try_send(flow("GET", "http://a.test/poll", 100 + i)).unwrap();
        }
        assert_eq!(src.pump(), 3);
        let events = src.take_for(session);
        assert_eq!(events.len(), 3);
        assert_eq!(events.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert!(events.iter().all(|e| e.epoch_id == Some(epoch) && !e.late));
        assert!(events.windows(2).all(|w| w[0].started_at <= w[1].started_at));
        assert_eq!(operations(&events), vec!["GET http://a.test/poll".to_owned()]);
        assert_eq!(src.stats().flows, 3);
        assert_eq!(src.stats().window_matched, 3);
    }

    #[test]
    fn window_attribution_tags_flows_after_settle_as_late() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let first = NetworkEpochId::new();
        let second = NetworkEpochId::new();
        src.open_epoch(first, session, t(0));
        src.close_epoch(first, t(500));
        src.open_epoch(second, session, t(2_000));
        tx.try_send(flow("GET", "http://a.test/in", 200)).unwrap();
        tx.try_send(flow("GET", "http://a.test/late", 900)).unwrap();
        tx.try_send(flow("GET", "http://a.test/next", 2_100)).unwrap();
        src.pump();
        let events = src.take_for(session);
        assert_eq!(events.len(), 3);
        assert_eq!((events[0].epoch_id, events[0].late), (Some(first), false));
        assert_eq!((events[1].epoch_id, events[1].late), (Some(first), true));
        assert_eq!((events[2].epoch_id, events[2].late), (Some(second), false));
        assert_eq!(src.stats().late, 1);
    }

    #[test]
    fn cdp_correlation_wins_over_the_window_and_is_consumed_once() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let window_epoch = NetworkEpochId::new();
        let cdp_epoch = NetworkEpochId::new();
        src.open_epoch(window_epoch, session, t(0));
        let cdp = TrafficEvent {
            seq: 9,
            epoch_id: Some(cdp_epoch),
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "get".to_owned(),
            url: "http://a.test/x".to_owned(),
            status: Some(200),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            third_party: false,
            late: true,
            protocol: None,
            started_at: t(1_000),
            finished_at: None,
        };
        src.observe_cdp(session, &[cdp]);
        tx.try_send(flow("GET", "http://a.test/x", 1_200)).unwrap();
        tx.try_send(flow("GET", "http://a.test/x", 1_300)).unwrap();
        src.pump();
        let events = src.take_for(session);
        assert_eq!((events[0].epoch_id, events[0].late), (Some(cdp_epoch), true));
        assert_eq!((events[1].epoch_id, events[1].late), (Some(window_epoch), false));
        assert_eq!(src.stats().cdp_matched, 1);
        assert_eq!(src.stats().window_matched, 1);
    }

    #[test]
    fn flows_outside_every_window_are_unmatched_but_kept() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        tx.try_send(flow("GET", "http://a.test/early", 100)).unwrap();
        src.open_epoch(NetworkEpochId::new(), session, t(1_000));
        src.pump();
        let events = src.take_for(session);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].epoch_id, None);
        assert_eq!(
            events[0].unattributed_reason,
            Some(UnattributedReason::UnmatchedProxyFlow)
        );
        assert_eq!(src.stats().unmatched, 1);
        assert_eq!(src.stats().unattributed, 1);
    }

    #[test]
    fn overlapping_windows_of_two_sessions_are_ambiguous_without_cdp() {
        let (tx, mut src) = source();
        let (a, b) = (SessionId::new(), SessionId::new());
        let (ea, eb) = (NetworkEpochId::new(), NetworkEpochId::new());
        src.open_epoch(ea, a, t(0));
        src.open_epoch(eb, b, t(10));
        tx.try_send(flow("GET", "http://a.test/who", 50)).unwrap();
        src.pump();
        let events = src.take_for(a);
        assert_eq!(
            events[0].unattributed_reason,
            Some(UnattributedReason::UnmatchedProxyFlow)
        );
        // a CDP event from session b resolves the same situation
        let cdp = TrafficEvent {
            seq: 1,
            epoch_id: Some(eb),
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "GET".to_owned(),
            url: "http://a.test/who".to_owned(),
            status: None,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: None,
            started_at: t(60),
            finished_at: None,
        };
        src.observe_cdp(b, &[cdp]);
        tx.try_send(flow("GET", "http://a.test/who", 70)).unwrap();
        src.pump();
        assert!(src.take_for(a).is_empty(), "owned by b, not handed to a");
        let for_b = src.take_for(b);
        assert_eq!(for_b[0].epoch_id, Some(eb));
    }

    #[test]
    fn fetch_plane_flows_are_not_applicable_and_proxy_flows_are_page_origin() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        src.open_epoch(NetworkEpochId::new(), session, t(0));
        let mut f = flow("GET", "http://a.test/static", 100);
        f.source = ProxyFlowSource::FetchPlane;
        tx.try_send(f).unwrap();
        tx.try_send(flow("GET", "http://a.test/page", 100)).unwrap();
        src.pump();
        let events = src.take_for(session);
        assert_eq!(events[0].origin, TrafficOrigin::FetchPlane);
        assert_eq!(events[0].epoch_id, None);
        assert_eq!(
            events[0].unattributed_reason,
            Some(UnattributedReason::NotApplicable)
        );
        assert_eq!(events[1].origin, TrafficOrigin::Page);
        assert!(events[1].epoch_id.is_some());
        assert_eq!(events[1].protocol, Some(Protocol::Http11));
    }

    #[test]
    fn redaction_covers_headers_the_proxy_left_and_session_query_parameters() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        src.set_page_origin("http://a.test");
        src.open_epoch(NetworkEpochId::new(), session, t(0));
        tx.try_send(flow("GET", "http://other.test/p?sessionid=abc&page=2", 100))
            .unwrap();
        src.pump();
        let ev = src.take_for(session).remove(0);
        let value = |n: &str| {
            ev.request_headers
                .iter()
                .find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(value("authorization").as_deref(), Some(REDACTED_PLACEHOLDER));
        assert!(value("x-api-key").unwrap().starts_with("[redacted:"));
        assert!(!ev.url.contains("abc"), "{}", ev.url);
        assert!(ev.url.contains("page=2"), "{}", ev.url);
        assert!(ev.third_party);
    }

    #[tokio::test]
    async fn next_event_yields_in_order_and_ends_when_the_channel_closes() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        src.open_epoch(NetworkEpochId::new(), session, t(0));
        tx.try_send(flow("GET", "http://a.test/1", 10)).unwrap();
        tx.try_send(flow("GET", "http://a.test/2", 20)).unwrap();
        drop(tx);
        assert_eq!(src.backend(), CaptureBackend::Proxy);
        assert_eq!(src.protocols_disabled(), &[Protocol::H3]);
        let a = src.next_event().await.unwrap().unwrap();
        let b = src.next_event().await.unwrap().unwrap();
        assert_eq!((a.seq, b.seq), (1, 2));
        assert!(src.next_event().await.unwrap().is_none());
    }

    #[test]
    fn cdp_source_marks_requests_started_after_settle_late() {
        let mut src = CdpTraffic::new();
        let epoch = NetworkEpochId::new();
        src.open_epoch(epoch);
        src.close_epoch(epoch, t(500));
        let mk = |at: i64| TrafficEvent {
            seq: 1,
            epoch_id: Some(epoch),
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "GET".to_owned(),
            url: "http://a.test/".to_owned(),
            status: Some(200),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: None,
            started_at: t(at),
            finished_at: None,
        };
        src.push_drained(vec![mk(100), mk(900)]);
        let out = src.drain();
        assert!(!out[0].late);
        assert!(out[1].late);
        assert_eq!(src.retagged_late(), 1);
    }

    #[tokio::test]
    async fn cdp_source_adds_provenance_without_changing_payloads_or_repeats() {
        let mut src = CdpTraffic::new();
        assert_eq!(src.backend(), CaptureBackend::Cdp);
        assert!(src.protocols_disabled().is_empty());
        assert!(src.is_empty());
        let ev = TrafficEvent {
            seq: 1,
            epoch_id: Some(NetworkEpochId::new()),
            unattributed_reason: None,
            origin: TrafficOrigin::Page,
            method: "GET".to_owned(),
            url: "http://a.test/".to_owned(),
            status: Some(200),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: Some(Protocol::H3),
            started_at: t(0),
            finished_at: None,
        };
        src.push_drained(vec![ev.clone(), ev.clone()]);
        assert_eq!(src.len(), 2);
        let mut ev = ev;
        mark_source(&mut ev, "cdp");
        assert_eq!(src.next_event().await.unwrap(), Some(ev.clone()));
        assert_eq!(src.next_event().await.unwrap(), Some(ev));
        assert_eq!(src.next_event().await.unwrap(), None);
    }

    fn cdp_event(epoch: Option<NetworkEpochId>, url: &str, at: i64) -> TrafficEvent {
        TrafficEvent {
            seq: 99,
            epoch_id: epoch,
            unattributed_reason: epoch.is_none().then_some(UnattributedReason::BeforeFirstEpoch),
            origin: TrafficOrigin::Page,
            method: "GET".to_owned(),
            url: url.to_owned(),
            status: Some(200),
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            third_party: false,
            late: false,
            protocol: Some(Protocol::H2),
            started_at: t(at),
            finished_at: Some(t(at + 10)),
        }
    }

    #[test]
    fn opaque_connect_and_https_supplements_remain_separate_chronological_raw_events() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let epoch = NetworkEpochId::new();
        src.open_epoch(epoch, session, t(0));
        let mut tunnel = flow("CONNECT", "a.test:443", 10);
        tunnel.status = None;
        tunnel.request_headers.clear();
        tunnel.tunnel = Some(crawlx_core::traffic::TunnelStats {
            bytes_up: 321,
            bytes_down: 654,
        });
        tx.try_send(tunnel).unwrap();
        let request = cdp_event(Some(epoch), "https://a.test/api", 20);
        src.push_cdp(session, vec![request.clone(), request]);
        src.pump();
        let events = src.take_for(session);
        assert_eq!(events.len(), 3);
        assert_eq!(
            events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert!(events
            .windows(2)
            .all(|pair| pair[0].started_at <= pair[1].started_at));
        assert_eq!(capture_source(&events[0]), Some("proxy"));
        assert_eq!(events[0].method, "CONNECT");
        assert_eq!(events[0].url, "a.test:443");
        assert_eq!(events[0].status, None);
        assert_eq!(events[0].request_body, None);
        assert_eq!(events[0].response_body, None);
        for (name, value) in [
            ("x-crawlx-stream-opaque", "true"),
            ("x-crawlx-stream-bytes-up", "321"),
            ("x-crawlx-stream-bytes-down", "654"),
        ] {
            assert!(events[0]
                .response_headers
                .iter()
                .any(|(key, val)| key == name && val == value));
        }
        assert!(events[1..]
            .iter()
            .all(|event| capture_source(event) == Some("cdp_supplement")));
        assert_eq!(operations(&events), ["GET https://a.test/api"]);
        assert_eq!(src.stats().flows, 1, "supplements are not invented proxy flows");
    }

    #[test]
    fn websocket_sse_and_service_worker_metadata_survive_without_any_proxy_flow() {
        let (_tx, mut src) = source();
        let session = SessionId::new();
        let epoch = NetworkEpochId::new();
        src.open_epoch(epoch, session, t(0));
        let kinds = [
            (TrafficOrigin::WebSocket, "wss://a.test/ws", "websocket"),
            (TrafficOrigin::EventSource, "https://a.test/sse", "sse"),
            (
                TrafficOrigin::ServiceWorker,
                "https://a.test/sw",
                "service_worker",
            ),
        ];
        let events = kinds
            .iter()
            .enumerate()
            .map(|(index, (origin, url, kind))| {
                let mut event = cdp_event(Some(epoch), url, i64::try_from(index).unwrap() + 10);
                event.origin = *origin;
                event
                    .response_headers
                    .push(("x-crawlx-stream-kind".to_owned(), (*kind).to_owned()));
                event
                    .response_headers
                    .push(("x-crawlx-stream-data".to_owned(), "retained".to_owned()));
                event
            })
            .collect();
        src.push_cdp(session, events);
        let out = src.take_for(session);
        assert_eq!(out.len(), kinds.len());
        for (event, (origin, url, kind)) in out.iter().zip(kinds) {
            assert_eq!(event.origin, origin);
            assert_eq!(event.url, url);
            assert_eq!(event.epoch_id, Some(epoch));
            assert_eq!(capture_source(event), Some("cdp_supplement"));
            assert!(event
                .response_headers
                .contains(&("x-crawlx-stream-kind".to_owned(), kind.to_owned())));
            assert!(event
                .response_headers
                .contains(&("x-crawlx-stream-data".to_owned(), "retained".to_owned())));
        }
        assert_eq!(src.stats().flows, 0);
    }

    #[test]
    fn full_http_artifact_refs_survive_even_when_proxy_matches_the_request() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let epoch = NetworkEpochId::new();
        src.open_epoch(epoch, session, t(0));
        let request = crawlx_core::ArtifactRef {
            id: crawlx_core::ArtifactId::new(),
            digest: crawlx_core::hash::Digest::of("capture-test", b"request"),
        };
        let response = crawlx_core::ArtifactRef {
            id: crawlx_core::ArtifactId::new(),
            digest: crawlx_core::hash::Digest::of("capture-test", b"response"),
        };
        let mut event = cdp_event(Some(epoch), "http://a.test/api", 100);
        event.request_body = Some(request.clone());
        event.response_body = Some(response.clone());
        src.push_cdp(session, vec![event]);
        tx.try_send(flow("GET", "http://a.test/api", 101)).unwrap();
        src.pump();
        let out = src.take_for(session);
        assert_eq!(out.len(), 2, "raw HTTP matches must not discard either observer");
        let supplement = out
            .iter()
            .find(|event| capture_source(event) == Some("cdp_supplement"))
            .unwrap();
        assert_eq!(supplement.request_body.as_ref(), Some(&request));
        assert_eq!(supplement.response_body.as_ref(), Some(&response));
        assert_eq!(operations(&out), ["GET http://a.test/api"]);
        assert_eq!(src.stats().cdp_matched, 1);
    }

    #[test]
    fn matched_service_worker_is_authoritative_even_after_proxy_was_pumped() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let epoch = NetworkEpochId::new();
        src.open_epoch(epoch, session, t(0));
        src.close_epoch(epoch, t(500));
        tx.try_send(flow("GET", "http://a.test/sw", 510)).unwrap();
        src.pump();
        let mut event = cdp_event(Some(epoch), "http://a.test/sw", 490);
        event.origin = TrafficOrigin::ServiceWorker;
        src.push_cdp(session, vec![event]);
        let out = src.take_for(session);
        assert_eq!(out.len(), 2);
        assert!(out
            .iter()
            .all(|event| event.origin == TrafficOrigin::ServiceWorker));
        assert!(out
            .iter()
            .all(|event| event.epoch_id == Some(epoch) && !event.late));
        assert_eq!(src.stats().window_matched, 0);
        assert_eq!(src.stats().cdp_matched, 1);
        assert_eq!(src.stats().late, 0);
    }

    #[test]
    fn background_service_worker_cannot_inherit_an_active_page_epoch() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        src.open_epoch(NetworkEpochId::new(), session, t(0));
        let mut event = cdp_event(None, "http://a.test/background", 100);
        event.origin = TrafficOrigin::ServiceWorker;
        src.push_cdp(session, vec![event]);
        tx.try_send(flow("GET", "http://a.test/background", 101)).unwrap();
        src.pump();
        let out = src.take_for(session);
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|event| event.epoch_id.is_none()));
        assert!(out
            .iter()
            .all(|event| event.origin == TrafficOrigin::ServiceWorker));
        assert!(out
            .iter()
            .all(|event| event.unattributed_reason == Some(UnattributedReason::BeforeFirstEpoch)));
        assert_eq!(src.stats().window_matched, 0);
    }

    #[test]
    fn cdp_supplement_late_rule_preserves_boundary_and_sequence_across_drains() {
        let (_tx, mut src) = source();
        let session = SessionId::new();
        let epoch = NetworkEpochId::new();
        src.open_epoch(epoch, session, t(0));
        src.close_epoch(epoch, t(500));
        let mut already_late = cdp_event(Some(epoch), "https://a.test/earlier", 100);
        already_late.late = true;
        src.push_cdp(
            session,
            vec![
                already_late,
                cdp_event(Some(epoch), "https://a.test/boundary", 500),
            ],
        );
        let first = src.take_for(session);
        assert!(first[0].late);
        assert!(!first[1].late);
        src.push_cdp(session, vec![cdp_event(Some(epoch), "https://a.test/late", 501)]);
        let next = src.take_for(session);
        assert!(next[0].late);
        assert_eq!(first.iter().map(|event| event.seq).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(next[0].seq, 3);
    }

    #[test]
    fn upstream_cannot_spoof_capture_provenance_or_hide_raw_proxy_operations() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let mut raw = flow("GET", "http://a.test/api", 100);
        raw.request_headers
            .push(("X-Crawlx-Capture-Source".to_owned(), "cdp".to_owned()));
        raw.response_headers
            .push((CAPTURE_SOURCE.to_owned(), "cdp_supplement".to_owned()));
        raw.response_headers
            .push(("x-crawlx-stream-cdp-correlated".to_owned(), "true".to_owned()));
        tx.try_send(raw).unwrap();
        src.pump();
        let events = src.take_for(session);
        assert_eq!(capture_source(&events[0]), Some("proxy"));
        assert!(!events[0]
            .request_headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(CAPTURE_SOURCE)));
        assert!(!events[0]
            .response_headers
            .iter()
            .any(|(name, _)| name == "x-crawlx-stream-cdp-correlated"));
        assert_eq!(operations(&events), ["GET http://a.test/api"]);
    }

    #[test]
    fn wire_body_digests_survive_as_metadata_without_fabricating_artifact_refs() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let request = crawlx_core::traffic::BodyDigest::of_prefix(b"request", 7);
        let response = crawlx_core::traffic::BodyDigest::of_prefix(
            b"response-prefix",
            u64::try_from(crawlx_core::traffic::BODY_DIGEST_PREFIX).unwrap() + 1,
        );
        let mut raw = flow("POST", "http://a.test/api", 100);
        raw.request_body = Some(request);
        raw.response_body = Some(response);
        tx.try_send(raw).unwrap();
        src.pump();
        let events = src.take_for(session);
        let event = &events[0];
        assert_eq!(event.request_body, None);
        assert_eq!(event.response_body, None);
        for (name, value) in [
            ("x-crawlx-stream-request-body-digest", request.digest.to_hex()),
            ("x-crawlx-stream-request-body-length", request.len.to_string()),
            ("x-crawlx-stream-request-body-truncated", "false".to_owned()),
            ("x-crawlx-stream-response-body-digest", response.digest.to_hex()),
            ("x-crawlx-stream-response-body-length", response.len.to_string()),
            ("x-crawlx-stream-response-body-truncated", "true".to_owned()),
        ] {
            assert!(event
                .response_headers
                .iter()
                .any(|(key, val)| key == name && val == &value));
        }
    }

    #[test]
    fn operation_view_excludes_connect_only_when_explicitly_identified_as_proxy() {
        let mut cdp = cdp_event(None, "a.test:443", 100);
        cdp.method = "CONNECT".to_owned();
        mark_source(&mut cdp, "cdp_supplement");
        let mut proxy = cdp.clone();
        mark_source(&mut proxy, "proxy");
        assert!(operations(&[proxy.clone()]).is_empty());
        assert_eq!(operations(&[proxy, cdp]), ["CONNECT a.test:443"]);
    }

    #[test]
    fn fetch_plane_stored_body_refs_survive_while_browser_wire_headers_cannot_spoof_them() {
        let (tx, mut src) = source();
        let session = SessionId::new();
        let artifact = crawlx_core::ArtifactRef {
            id: crawlx_core::ArtifactId::new(),
            digest: crawlx_core::hash::Digest::of("capture-test", b"stored prefix"),
        };
        let mut fetched = flow("GET", "http://a.test/static", 100);
        fetched.source = ProxyFlowSource::FetchPlane;
        fetched.response_headers = vec![
            (
                "x-crawlx-stream-response-artifact-id".to_owned(),
                artifact.id.to_string(),
            ),
            (
                "x-crawlx-stream-response-artifact-digest".to_owned(),
                artifact.digest.to_hex(),
            ),
            ("x-crawlx-stream-body-mode".to_owned(), "text_capped".to_owned()),
            (
                "x-crawlx-stream-body-capture".to_owned(),
                "stored_prefix".to_owned(),
            ),
            ("x-crawlx-stream-body-truncated".to_owned(), "true".to_owned()),
        ];
        let mut spoof = fetched.clone();
        spoof.source = ProxyFlowSource::Browser;
        tx.try_send(fetched).unwrap();
        tx.try_send(spoof).unwrap();
        src.pump();
        let events = src.take_for(session);
        assert_eq!(events[0].response_body.as_ref(), Some(&artifact));
        assert_eq!(
            events[0].unattributed_reason,
            Some(UnattributedReason::NotApplicable)
        );
        assert!(events[0]
            .response_headers
            .iter()
            .any(|(name, value)| { name == "x-crawlx-stream-body-capture" && value == "stored_prefix" }));
        assert!(events[1].response_body.is_none());
        assert!(!events[1]
            .response_headers
            .iter()
            .any(|(name, _)| { name == "x-crawlx-stream-response-artifact-id" }));
    }
}
