//! Pure model of network epochs and the
//! endpoint classifier.
//!
//! Each `perform` opens an epoch. Requests are tagged with the epoch open at
//! event time; events that arrive after the epoch settled and before the next
//! one opens are `late`: they stay attributed to the previous action with
//! [`Confidence::Low`] and are kept out of that epoch's operations. Long-lived
//! traffic (WebSocket, EventSource / `text/event-stream`, requests pending for
//! more than ten seconds, polling) is listed separately and never counts as
//! in flight. Service-worker and fetch-plane traffic is never attributed to
//! the trusted lane.
//!
//! The tracker reads no clock: every event carries its timestamp, and the
//! tracker's "now" is the latest timestamp it has seen.
//!
//! [`classify_endpoint`] is ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md.
//! The upstream's "skip" outcome is [`EndpointClass::Static`].

use chrono::Duration;
use crawlx_core::ids::{ActionId, NetworkEpochId};
use crawlx_core::observation::NetworkEpochSummary;
use crawlx_core::time::Timestamp;
use crawlx_core::traffic::{TrafficEvent, TrafficOrigin};
use crawlx_url::RouteTemplater;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// A request pending longer than this is long-lived.
pub const LONG_LIVED_AGE_MS: i64 = 10_000;
/// Window in which repeated requests to one URL count as polling.
pub const POLLING_WINDOW_MS: i64 = 30_000;
/// Repetitions inside the window that make a URL a polling target.
pub const POLLING_MIN_REPEATS: usize = 3;

const MAX_TRACKED_REQUESTS: usize = 4096;
const MAX_TRACKED_URLS: usize = 1024;

/// How far an attribution can be trusted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Confidence {
    /// The event arrived while its epoch was open (or before any epoch): the attribution is reliable.
    High,
    /// Late events: probably caused by the previous action, possibly by a timer.
    Low,
}

/// Why a request is excluded from in-flight accounting.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[non_exhaustive]
pub enum LongLivedReason {
    /// The request is a WebSocket connection.
    WebSocket,
    /// The request is an `EventSource` connection.
    EventSource,
    /// The response `Content-Type` is `text/event-stream`.
    EventStream,
    /// The request has been pending for longer than [`LONG_LIVED_AGE_MS`].
    Age,
    /// The same URL was requested at least [`POLLING_MIN_REPEATS`] times within [`POLLING_WINDOW_MS`].
    Polling,
}

/// Family of a captured request.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum EndpointClass {
    /// JSON/XML or form submission to an API-looking path or with a mutating verb.
    Rest,
    /// `graphql` path segment, `application/graphql`, or a GraphQL operation body.
    GraphQl,
    /// SOAP envelope or `soap+xml` content type.
    Soap,
    /// JSON `GET` to a non-API path (AJAX data load).
    Xhr,
    /// Everything else: documents, assets, unknown.
    Static,
}

impl EndpointClass {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rest => "rest",
            Self::GraphQl => "graphql",
            Self::Soap => "soap",
            Self::Xhr => "xhr",
            Self::Static => "static",
        }
    }
}

/// Path substrings that suggest an API endpoint (the upstream's `apiPathSegments` list).
const API_PATH_SEGMENTS: &[&str] = &[
    "/api/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/rest/",
    "/rpc/",
    "/jsonrpc",
    "/.well-known/",
    "/oauth/",
    "/openapi",
];

fn is_mutating(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}

/// Classify a request from its method, URL, (request or response)
/// content type and a prefix of its body. Decision order, first match wins:
/// SOAP, GraphQL, REST (structured body + mutating verb or API path), XHR
/// (JSON `GET` elsewhere), REST (form body on a mutating verb), else static.
#[must_use]
pub fn classify_endpoint(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    body_prefix: &[u8],
) -> EndpointClass {
    let method = method.trim().to_ascii_uppercase();
    let path =
        url::Url::parse(url).map_or_else(|_| url.to_ascii_lowercase(), |u| u.path().to_ascii_lowercase());
    let ct = content_type
        .map(|c| c.split(';').next().unwrap_or(c).trim().to_ascii_lowercase())
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&body_prefix[..body_prefix.len().min(512)]);
    let body = body.trim_start();
    let body_lower = body.to_ascii_lowercase();

    if ct.contains("soap+xml")
        || body_lower.contains("soap:envelope")
        || body_lower.contains("soapenv:envelope")
        || body_lower.contains("schemas.xmlsoap.org/soap/envelope")
    {
        return EndpointClass::Soap;
    }
    let graphql_body = (body.starts_with('{') && body_lower.contains("\"query\""))
        || body_lower.starts_with("query")
        || body_lower.starts_with("mutation")
        || body_lower.starts_with("subscription");
    if path.split('/').any(|seg| seg == "graphql") || ct.contains("application/graphql") || graphql_body {
        return EndpointClass::GraphQl;
    }

    let is_json = ct.contains("application/json")
        || ct.ends_with("+json")
        || body.starts_with('{')
        || body.starts_with('[');
    let is_xml = ct.contains("application/xml") || ct.ends_with("+xml") || ct == "text/xml";
    let is_form = ct.contains("application/x-www-form-urlencoded") || ct.contains("multipart/form-data");
    let api_path = API_PATH_SEGMENTS.iter().any(|seg| path.contains(seg));
    let mutating = is_mutating(&method);

    if (is_json || is_xml) && (mutating || api_path) {
        return EndpointClass::Rest;
    }
    if is_json && method == "GET" {
        return EndpointClass::Xhr;
    }
    if is_form && mutating {
        return EndpointClass::Rest;
    }
    EndpointClass::Static
}

/// Epoch attribution of one event.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EventTag {
    /// `None` before the first epoch opened.
    pub epoch_id: Option<NetworkEpochId>,
    /// The event arrived after its epoch settled and before the next one opened.
    pub late: bool,
    /// [`Confidence::Low`] exactly when `late` is set.
    pub confidence: Confidence,
}

/// `Network.requestWillBeSent` / WebSocket / EventSource creation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RequestEvent {
    /// Identifier of the request, unique among the requests tracked at once; later response and finish events refer to it.
    pub request_id: String,
    /// HTTP method as sent (any case; operations upper-case it).
    pub method: String,
    /// Absolute request URL; the fragment is ignored for polling detection.
    pub url: String,
    /// Which plane issued the request; service-worker and fetch-plane traffic is never attributed to an epoch.
    pub origin: TrafficOrigin,
    /// Event timestamp; the tracker reads no clock of its own.
    pub at: Timestamp,
}

impl RequestEvent {
    /// Build from a captured traffic event (`seq` doubles as request id).
    #[must_use]
    pub fn from_traffic(ev: &TrafficEvent) -> Self {
        Self {
            request_id: ev.seq.to_string(),
            method: ev.method.clone(),
            url: ev.url.clone(),
            origin: ev.origin,
            at: ev.started_at,
        }
    }
}

/// `Network.responseReceived`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ResponseEvent {
    /// Identifier of the request this response belongs to (see [`RequestEvent::request_id`]).
    pub request_id: String,
    /// HTTP status code, when the backend reported one.
    pub status: Option<u16>,
    /// Response MIME type; `text/event-stream` marks the request long-lived.
    pub mime_type: Option<String>,
    /// Event timestamp; the tracker reads no clock of its own.
    pub at: Timestamp,
}

#[derive(Clone, Debug)]
struct Req {
    url: String,
    method: String,
    origin: TrafficOrigin,
    /// `METHOD /route/:template`.
    operation: String,
    started_at: Timestamp,
    finished_at: Option<Timestamp>,
    mime: Option<String>,
    class: EndpointClass,
    epoch: Option<NetworkEpochId>,
    late: bool,
}

impl Req {
    fn attributed(&self) -> bool {
        !matches!(
            self.origin,
            TrafficOrigin::ServiceWorker | TrafficOrigin::FetchPlane
        )
    }
    fn pending(&self) -> bool {
        self.finished_at.is_none()
    }
}

#[derive(Clone, Debug)]
struct EpochState {
    id: NetworkEpochId,
    action: Option<ActionId>,
    settled_at: Option<Timestamp>,
    requests: u32,
    late: u32,
}

/// Tracks the traffic of the current network epoch.
#[derive(Clone, Debug)]
pub struct NetworkEpochTracker {
    templater: RouteTemplater,
    current: Option<EpochState>,
    reqs: BTreeMap<String, Req>,
    url_history: BTreeMap<String, VecDeque<Timestamp>>,
    polling_urls: BTreeSet<String>,
    now: Option<Timestamp>,
}

impl Default for NetworkEpochTracker {
    fn default() -> Self {
        Self::new(RouteTemplater::new())
    }
}

impl NetworkEpochTracker {
    /// `templater` renders request paths into route templates for operations.
    #[must_use]
    pub fn new(templater: RouteTemplater) -> Self {
        Self {
            templater,
            current: None,
            reqs: BTreeMap::new(),
            url_history: BTreeMap::new(),
            polling_urls: BTreeSet::new(),
            now: None,
        }
    }

    fn touch(&mut self, at: Timestamp) {
        if self.now.is_none_or(|n| at > n) {
            self.now = Some(at);
        }
    }

    /// Id of the open (or most recently closed) epoch.
    #[must_use]
    pub fn current_epoch_id(&self) -> Option<NetworkEpochId> {
        self.current.as_ref().map(|e| e.id)
    }

    /// The action the current epoch belongs to.
    #[must_use]
    pub fn current_action(&self) -> Option<ActionId> {
        self.current.as_ref().and_then(|e| e.action)
    }

    /// Is the current epoch still open (not yet settled)?
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.current.as_ref().is_some_and(|e| e.settled_at.is_none())
    }

    /// Open an epoch for `action` (`None` for navigations and probes). Requests
    /// still pending from earlier epochs stay tracked for in-flight accounting;
    /// everything finished is forgotten.
    pub fn open_epoch(&mut self, action: Option<ActionId>, at: Timestamp) -> NetworkEpochId {
        self.touch(at);
        self.reqs.retain(|_, r| r.pending());
        let horizon = at - Duration::milliseconds(POLLING_WINDOW_MS);
        self.url_history.retain(|_, h| {
            while h.front().is_some_and(|t| *t < horizon) {
                h.pop_front();
            }
            !h.is_empty()
        });
        let id = NetworkEpochId::new();
        self.current = Some(EpochState {
            id,
            action,
            settled_at: None,
            requests: 0,
            late: 0,
        });
        id
    }

    fn tag_for_new(&self, at: Timestamp) -> EventTag {
        match &self.current {
            None => EventTag {
                epoch_id: None,
                late: false,
                confidence: Confidence::High,
            },
            Some(e) => {
                let late = e.settled_at.is_some_and(|s| at > s);
                EventTag {
                    epoch_id: Some(e.id),
                    late,
                    confidence: if late { Confidence::Low } else { Confidence::High },
                }
            }
        }
    }

    fn operation_of(&self, method: &str, url: &str) -> String {
        let path = url::Url::parse(url).map_or_else(|_| url.to_owned(), |u| u.path().to_owned());
        format!(
            "{} {}",
            method.to_ascii_uppercase(),
            self.templater.template(&path).0
        )
    }

    fn record_url(&mut self, url: &str, at: Timestamp) {
        let key = url.split('#').next().unwrap_or(url).to_owned();
        if !self.url_history.contains_key(&key) && self.url_history.len() >= MAX_TRACKED_URLS {
            if let Some(first) = self.url_history.keys().next().cloned() {
                self.url_history.remove(&first);
            }
        }
        let hist = self.url_history.entry(key.clone()).or_default();
        while hist
            .front()
            .is_some_and(|t| (at - *t).num_milliseconds() > POLLING_WINDOW_MS)
        {
            hist.pop_front();
        }
        hist.push_back(at);
        if hist.len() >= POLLING_MIN_REPEATS && self.polling_urls.len() < MAX_TRACKED_URLS {
            self.polling_urls.insert(key);
        }
    }

    /// A request started. Returns its attribution.
    pub fn on_request(&mut self, ev: RequestEvent) -> EventTag {
        self.touch(ev.at);
        let tag = self.tag_for_new(ev.at);
        self.record_url(&ev.url, ev.at);
        let req = Req {
            operation: self.operation_of(&ev.method, &ev.url),
            class: classify_endpoint(&ev.method, &ev.url, None, &[]),
            method: ev.method,
            url: ev.url,
            origin: ev.origin,
            started_at: ev.at,
            finished_at: None,
            mime: None,
            epoch: tag.epoch_id,
            late: tag.late,
        };
        if req.attributed() {
            if let Some(e) = self.current.as_mut() {
                if tag.late {
                    e.late = e.late.saturating_add(1);
                } else {
                    e.requests = e.requests.saturating_add(1);
                }
            }
        }
        if self.reqs.len() >= MAX_TRACKED_REQUESTS && !self.reqs.contains_key(&ev.request_id) {
            let victim = self
                .reqs
                .iter()
                .min_by_key(|(_, r)| (!r.pending(), r.started_at))
                .map(|(k, _)| k.clone());
            if let Some(v) = victim {
                self.reqs.remove(&v);
            }
        }
        self.reqs.insert(ev.request_id, req);
        tag
    }

    fn tag_of(r: &Req) -> EventTag {
        EventTag {
            epoch_id: r.epoch,
            late: r.late,
            confidence: if r.late { Confidence::Low } else { Confidence::High },
        }
    }

    /// Response headers arrived. `None` for an unknown request id. The
    /// endpoint class is refined with the response MIME type.
    pub fn on_response(&mut self, ev: ResponseEvent) -> Option<EventTag> {
        self.touch(ev.at);
        let r = self.reqs.get_mut(&ev.request_id)?;
        r.class = classify_endpoint(&r.method, &r.url, ev.mime_type.as_deref(), &[]);
        r.mime = ev.mime_type;
        Some(Self::tag_of(r))
    }

    /// `loadingFinished`, `loadingFailed`, `servedFromCache`, WebSocket close.
    /// `None` for an unknown request id.
    pub fn on_finished(&mut self, request_id: &str, at: Timestamp) -> Option<EventTag> {
        self.touch(at);
        let r = self.reqs.get_mut(request_id)?;
        if r.finished_at.is_none() {
            r.finished_at = Some(at);
        }
        Some(Self::tag_of(r))
    }

    /// The action settled at `settled_at`: later events are `late`. Returns the
    /// epoch's summary at close. No-op without an open epoch.
    pub fn close_epoch(&mut self, settled_at: Timestamp) -> NetworkEpochSummary {
        self.touch(settled_at);
        if let Some(e) = self.current.as_mut() {
            if e.settled_at.is_none() {
                e.settled_at = Some(settled_at);
            }
        }
        self.summary()
    }

    fn long_lived_reason(&self, r: &Req, now: Timestamp) -> Option<LongLivedReason> {
        match r.origin {
            TrafficOrigin::WebSocket => return Some(LongLivedReason::WebSocket),
            TrafficOrigin::EventSource => return Some(LongLivedReason::EventSource),
            _ => {}
        }
        if r.mime
            .as_deref()
            .is_some_and(|m| m.trim().to_ascii_lowercase().starts_with("text/event-stream"))
        {
            return Some(LongLivedReason::EventStream);
        }
        if r.pending() && (now - r.started_at).num_milliseconds() > LONG_LIVED_AGE_MS {
            return Some(LongLivedReason::Age);
        }
        let key = r.url.split('#').next().unwrap_or(&r.url);
        if self.polling_urls.contains(key) {
            return Some(LongLivedReason::Polling);
        }
        None
    }

    /// Long-lived requests currently tracked: `(operation, reason)`, sorted, deduplicated.
    #[must_use]
    pub fn long_lived(&self) -> Vec<(String, LongLivedReason)> {
        let now = self.now.unwrap_or_default();
        let mut out: Vec<(String, LongLivedReason)> = self
            .reqs
            .values()
            .filter(|r| r.attributed())
            .filter_map(|r| {
                self.long_lived_reason(r, now)
                    .map(|why| (r.operation.clone(), why))
            })
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Number of requests pending right now that count toward network idle
    /// (long-lived and unattributed traffic excluded).
    #[must_use]
    pub fn in_flight(&self) -> u32 {
        let now = self.now.unwrap_or_default();
        let n = self
            .reqs
            .values()
            .filter(|r| r.pending() && r.attributed() && self.long_lived_reason(r, now).is_none())
            .count();
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    /// Summary of the current epoch as of the latest event timestamp.
    ///
    /// `requests` counts on-time attributed requests, `late` the late ones;
    /// `operations` are the distinct `METHOD /route/:template` pairs of
    /// on-time, non-long-lived requests, sorted.
    #[must_use]
    pub fn summary(&self) -> NetworkEpochSummary {
        let Some(e) = &self.current else {
            return NetworkEpochSummary::default();
        };
        let now = self.now.unwrap_or_default();
        let mut operations: BTreeSet<&str> = BTreeSet::new();
        for r in self.reqs.values() {
            if r.epoch == Some(e.id) && !r.late && r.attributed() && self.long_lived_reason(r, now).is_none()
            {
                operations.insert(&r.operation);
            }
        }
        let mut long_lived: Vec<String> = self.long_lived().into_iter().map(|(op, _)| op).collect();
        long_lived.dedup();
        NetworkEpochSummary {
            epoch_id: Some(e.id),
            requests: e.requests,
            in_flight_at_capture: self.in_flight(),
            long_lived,
            late: e.late,
            operations: operations.into_iter().map(str::to_owned).collect(),
        }
    }

    /// Endpoint class of every operation of the current epoch (same filter as
    /// [`NetworkEpochTracker::summary`] `operations`): `(operation, class)`,
    /// sorted and deduplicated. A parallel view so `NetworkEpochSummary` in
    /// `crawlx-core` stays unchanged.
    #[must_use]
    pub fn operation_classes(&self) -> Vec<(String, EndpointClass)> {
        let Some(e) = &self.current else {
            return Vec::new();
        };
        let now = self.now.unwrap_or_default();
        let mut out: BTreeSet<(String, EndpointClass)> = BTreeSet::new();
        for r in self.reqs.values() {
            if r.epoch == Some(e.id) && !r.late && r.attributed() && self.long_lived_reason(r, now).is_none()
            {
                out.insert((r.operation.clone(), r.class));
            }
        }
        out.into_iter().collect()
    }

    /// Number of requests currently tracked (bounded).
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.reqs.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::{DateTime, Utc};
    use proptest::prelude::*;

    fn t(ms: i64) -> Timestamp {
        DateTime::<Utc>::from_timestamp_millis(1_700_000_000_000 + ms).unwrap()
    }

    fn req(id: &str, method: &str, url: &str, at: i64) -> RequestEvent {
        RequestEvent {
            request_id: id.to_owned(),
            method: method.to_owned(),
            url: url.to_owned(),
            origin: TrafficOrigin::Page,
            at: t(at),
        }
    }

    type ClassCase = (
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static [u8],
        EndpointClass,
    );

    #[test]
    fn endpoint_classifier_table() {
        let cases: &[ClassCase] = &[
            ("POST", "https://a.test/ws/Order", Some("application/soap+xml"), b"", EndpointClass::Soap),
            (
                "POST",
                "https://a.test/svc",
                Some("text/xml"),
                b"<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">",
                EndpointClass::Soap,
            ),
            ("POST", "https://a.test/graphql", Some("application/json"), b"", EndpointClass::GraphQl),
            ("POST", "https://a.test/api/graphql?op=x", None, b"", EndpointClass::GraphQl),
            ("POST", "https://a.test/q", Some("application/graphql"), b"", EndpointClass::GraphQl),
            ("POST", "https://a.test/data", Some("application/json"), br#"{"query":"{ me { id } }"}"#, EndpointClass::GraphQl),
            ("GET", "https://a.test/notgraphql/blob", Some("application/json"), b"", EndpointClass::Xhr),
            ("POST", "https://a.test/items", Some("application/json"), b"", EndpointClass::Rest),
            ("GET", "https://a.test/api/v1/items", Some("application/json"), b"", EndpointClass::Rest),
            ("GET", "https://a.test/.well-known/openid-configuration", Some("application/json"), b"", EndpointClass::Rest),
            ("PUT", "https://a.test/thing", Some("application/xml"), b"", EndpointClass::Rest),
            ("DELETE", "https://a.test/thing/1", Some("application/x-www-form-urlencoded"), b"", EndpointClass::Rest),
            ("POST", "https://a.test/upload", Some("multipart/form-data; boundary=x"), b"", EndpointClass::Rest),
            ("POST", "https://a.test/x", None, br#"{"a":1}"#, EndpointClass::Rest),
            ("GET", "https://a.test/feed", Some("application/json; charset=utf-8"), b"", EndpointClass::Xhr),
            ("GET", "https://a.test/x", None, br#"[{"a":1}]"#, EndpointClass::Xhr),
            ("GET", "https://a.test/index.html", Some("text/html"), b"<html>", EndpointClass::Static),
            ("GET", "https://a.test/app.js", Some("application/javascript"), b"", EndpointClass::Static),
            ("GET", "https://a.test/api/page", Some("text/html"), b"", EndpointClass::Static),
            ("POST", "https://a.test/form", Some("text/html"), b"", EndpointClass::Static),
            ("get", "not a url", None, b"", EndpointClass::Static),
        ];
        for (method, url, ct, body, want) in cases {
            assert_eq!(
                classify_endpoint(method, url, *ct, body),
                *want,
                "{method} {url} {ct:?}"
            );
        }
        assert_eq!(EndpointClass::GraphQl.as_str(), "graphql");
    }

    #[test]
    fn operation_classes_follow_operations_and_refine_on_response() {
        let mut n = NetworkEpochTracker::default();
        n.open_epoch(Some(ActionId::new()), t(0));
        n.on_request(req("1", "GET", "https://a.test/api/users/42", 10));
        n.on_request(req("2", "GET", "https://a.test/page", 11));
        n.on_request(req("3", "POST", "https://a.test/graphql", 12));
        n.on_request(req("4", "GET", "https://a.test/data", 13));
        assert_eq!(
            n.operation_classes().iter().map(|(_, c)| *c).collect::<Vec<_>>(),
            vec![
                EndpointClass::Static,
                EndpointClass::Static,
                EndpointClass::Static,
                EndpointClass::GraphQl
            ],
            "before responses only the path decides"
        );
        n.on_response(ResponseEvent {
            request_id: "1".into(),
            status: Some(200),
            mime_type: Some("application/json".into()),
            at: t(20),
        });
        n.on_response(ResponseEvent {
            request_id: "4".into(),
            status: Some(200),
            mime_type: Some("application/json".into()),
            at: t(21),
        });
        let classes = n.operation_classes();
        let ops: Vec<String> = classes.iter().map(|(op, _)| op.clone()).collect();
        assert_eq!(ops, n.summary().operations, "same operations as the summary");
        let class_of = |op: &str| classes.iter().find(|(o, _)| o == op).map(|(_, c)| *c);
        assert_eq!(class_of("GET /api/users/:id"), Some(EndpointClass::Rest));
        assert_eq!(class_of("GET /data"), Some(EndpointClass::Xhr));
        assert_eq!(class_of("GET /page"), Some(EndpointClass::Static));
        assert_eq!(class_of("POST /graphql"), Some(EndpointClass::GraphQl));
        assert!(NetworkEpochTracker::default().operation_classes().is_empty());
    }

    #[test]
    fn events_after_settle_are_late_with_low_confidence() {
        let mut n = NetworkEpochTracker::default();
        let id = n.open_epoch(Some(ActionId::new()), t(0));
        let on_time = n.on_request(req("1", "GET", "https://a.test/api/x", 10));
        assert_eq!(on_time.epoch_id, Some(id));
        assert!(!on_time.late);
        assert_eq!(on_time.confidence, Confidence::High);
        n.on_finished("1", t(50));
        n.close_epoch(t(100));

        let late = n.on_request(req("2", "POST", "https://a.test/api/track", 250));
        assert_eq!(late.epoch_id, Some(id), "attributed to the previous action");
        assert!(late.late);
        assert_eq!(late.confidence, Confidence::Low);
        assert_eq!(n.on_finished("2", t(260)), Some(late));

        let s = n.summary();
        assert_eq!((s.requests, s.late), (1, 1));
        assert_eq!(
            s.operations,
            vec!["GET /api/x".to_owned()],
            "late traffic is not an operation"
        );

        // a request stamped at or before the settle instant is an ordering race, not late
        let mut n2 = NetworkEpochTracker::default();
        n2.open_epoch(None, t(0));
        n2.close_epoch(t(100));
        assert!(!n2.on_request(req("1", "GET", "https://a.test/", 100)).late);
        assert!(n2.on_request(req("2", "GET", "https://a.test/", 101)).late);

        // the next epoch starts clean
        let id2 = n.open_epoch(None, t(300));
        assert_ne!(id, id2);
        let tag = n.on_request(req("3", "GET", "https://a.test/api/y", 310));
        assert_eq!((tag.epoch_id, tag.late), (Some(id2), false));
        assert_eq!(n.summary().late, 0);
    }

    #[test]
    fn long_lived_traffic_is_excluded_from_in_flight() {
        let mut n = NetworkEpochTracker::default();
        n.open_epoch(None, t(0));
        let mut ws = req("ws", "GET", "wss://a.test/socket", 1);
        ws.origin = TrafficOrigin::WebSocket;
        let mut es = req("es", "GET", "https://a.test/events", 2);
        es.origin = TrafficOrigin::EventSource;
        n.on_request(ws);
        n.on_request(es);
        n.on_request(req("sse", "GET", "https://a.test/stream", 3));
        n.on_response(ResponseEvent {
            request_id: "sse".to_owned(),
            status: Some(200),
            mime_type: Some("text/event-stream; charset=utf-8".to_owned()),
            at: t(4),
        });
        n.on_request(req("slow", "GET", "https://a.test/api/report", 5));
        n.on_request(req("quick", "GET", "https://a.test/api/me", 6));
        n.on_request(req("sw", "GET", "https://a.test/sw-fetch", 7));
        // service workers are never attributed to the action
        let mut sw = req("sw2", "GET", "https://a.test/precache", 7);
        sw.origin = TrafficOrigin::ServiceWorker;
        n.on_request(sw);

        // slow + quick + sw pending, 3 streaming connections excluded, sw2 unattributed
        assert_eq!(n.in_flight(), 3);
        // 11 s later the unfinished `slow` and `quick`, and `sw`, count as long-lived (age)
        n.on_finished("quick", t(100));
        n.on_finished("sw", t(120));
        n.on_request(req("late-probe", "GET", "https://a.test/api/me", 11_000));
        let s = n.summary();
        assert_eq!(s.in_flight_at_capture, 1, "only the fresh probe is in flight");
        assert!(s.long_lived.contains(&"GET /api/report".to_owned()));
        assert!(s.long_lived.contains(&"GET /socket".to_owned()));
        assert!(s.long_lived.contains(&"GET /events".to_owned()));
        assert!(s.long_lived.contains(&"GET /stream".to_owned()));
        assert!(!s.operations.contains(&"GET /socket".to_owned()));
        assert!(!s.operations.contains(&"GET /api/report".to_owned()));
        assert!(!s.operations.contains(&"GET /precache".to_owned()));
        assert!(s.operations.contains(&"GET /api/me".to_owned()));
        let reasons: Vec<_> = n.long_lived().into_iter().map(|(_, r)| r).collect();
        assert!(reasons.contains(&LongLivedReason::Age));
        assert!(reasons.contains(&LongLivedReason::WebSocket));
        assert!(reasons.contains(&LongLivedReason::EventStream));
    }

    #[test]
    fn polling_pattern_becomes_long_lived() {
        let mut n = NetworkEpochTracker::default();
        n.open_epoch(None, t(0));
        for (i, at) in [1_000, 6_000].into_iter().enumerate() {
            n.on_request(req(&format!("p{i}"), "GET", "https://a.test/api/poll", at));
            n.on_finished(&format!("p{i}"), t(at + 50));
        }
        assert!(n.long_lived().is_empty(), "two repeats are not polling yet");
        assert_eq!(n.summary().operations, vec!["GET /api/poll".to_owned()]);

        n.on_request(req("p2", "GET", "https://a.test/api/poll", 11_000));
        assert_eq!(n.in_flight(), 0, "the third request is polling, not in flight");
        let s = n.summary();
        assert_eq!(s.long_lived, vec!["GET /api/poll".to_owned()]);
        assert!(
            s.operations.is_empty(),
            "polling is retroactively removed from operations"
        );

        // slow repeats outside the window do not qualify
        let mut m = NetworkEpochTracker::default();
        m.open_epoch(None, t(0));
        for (i, at) in [0, 20_000, 40_000, 60_000].into_iter().enumerate() {
            m.on_request(req(&format!("s{i}"), "GET", "https://a.test/api/slow", at));
            m.on_finished(&format!("s{i}"), t(at + 10));
        }
        assert!(m.long_lived().is_empty());
    }

    #[test]
    fn operations_are_distinct_method_route_templates() {
        let mut n = NetworkEpochTracker::default();
        n.open_epoch(None, t(0));
        for (i, (m, u)) in [
            ("GET", "https://a.test/invoice/8472"),
            ("GET", "https://a.test/invoice/9911?x=1"),
            ("get", "https://a.test/invoice/12"),
            ("POST", "https://a.test/invoice/8472"),
            ("GET", "https://a.test/health"),
        ]
        .into_iter()
        .enumerate()
        {
            let at = i64::try_from(i).unwrap();
            n.on_request(req(&i.to_string(), m, u, at));
            n.on_finished(&i.to_string(), t(at + 1));
        }
        let s = n.summary();
        assert_eq!(s.requests, 5);
        assert_eq!(
            s.operations,
            vec![
                "GET /health".to_owned(),
                "GET /invoice/:id".to_owned(),
                "POST /invoice/:id".to_owned()
            ]
        );
        assert_eq!(s.in_flight_at_capture, 0);
        assert_eq!(s.epoch_id, n.current_epoch_id());
    }

    #[test]
    fn pending_requests_carry_over_to_the_next_epoch() {
        let mut n = NetworkEpochTracker::default();
        n.open_epoch(None, t(0));
        n.on_request(req("a", "GET", "https://a.test/api/a", 1));
        n.on_request(req("b", "GET", "https://a.test/api/b", 2));
        n.on_finished("b", t(3));
        n.close_epoch(t(10));
        n.open_epoch(None, t(20));
        assert_eq!(n.tracked(), 1);
        assert_eq!(n.in_flight(), 1);
        let s = n.summary();
        assert_eq!(s.requests, 0);
        assert!(
            s.operations.is_empty(),
            "the carried request belongs to the old epoch"
        );
        assert!(n.on_finished("a", t(30)).is_some());
        assert_eq!(n.in_flight(), 0);
        assert!(n.on_finished("nope", t(31)).is_none());
    }

    #[test]
    fn events_before_the_first_epoch_are_unattributed() {
        let mut n = NetworkEpochTracker::default();
        let tag = n.on_request(req("1", "GET", "https://a.test/", 0));
        assert_eq!(tag.epoch_id, None);
        assert_eq!(n.summary(), NetworkEpochSummary::default());
        assert_eq!(n.in_flight(), 1);
    }

    proptest! {
        #[test]
        fn arbitrary_interleavings_keep_invariants(
            ops in proptest::collection::vec((0u8..5, 0u8..6, 0i64..40_000), 0..120)
        ) {
            let mut n = NetworkEpochTracker::default();
            let mut clock = 0i64;
            for (kind, id, dt) in ops {
                clock += dt % 3_000;
                let rid = id.to_string();
                match kind {
                    0 => { n.open_epoch(None, t(clock)); }
                    1 => { n.on_request(req(&rid, "GET", &format!("https://a.test/r/{id}"), clock)); }
                    2 => { n.on_finished(&rid, t(clock)); }
                    3 => { n.close_epoch(t(clock)); }
                    _ => { n.on_response(ResponseEvent { request_id: rid, status: Some(200), mime_type: None, at: t(clock) }); }
                }
                let s = n.summary();
                let mut sorted = s.operations.clone();
                sorted.sort();
                sorted.dedup();
                prop_assert_eq!(&sorted, &s.operations);
                prop_assert!(s.in_flight_at_capture as usize <= n.tracked());
            }
        }
    }
}
