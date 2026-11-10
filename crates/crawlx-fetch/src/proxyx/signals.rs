//! Block-signal feedback to the ProxyX control API (`POST /v1/block-signals`).
//!
//! A crawl that is blocked tells the gateway which exit IP was blocked for which target, so
//! the pool can cool or retire that address. Reporting never slows the crawl:
//!
//! * events enter a bounded queue with `try_send`; a full queue drops the event and counts it;
//! * one background task batches (at most 500 events, the gateway's limit) and posts;
//! * `429` pauses the task for the `Retry-After` the gateway sent (capped), during which new
//!   events keep filling, and overflowing, the bounded queue;
//! * `5xx` and transport failures are retried a few times with backoff (a retried batch is
//!   idempotent on the gateway), everything else drops the batch and counts it;
//! * the control host is held to the egress policy exactly like the gateway host: it is
//!   resolved through the run's resolver, every address is checked and the connection is
//!   pinned to the checked addresses.

use crate::resolver::{parse_ip_literal, Resolver};
use crate::retry::parse_retry_after;
use crawlx_core::secret::SecretOr;
use crawlx_policy::egress::EgressPolicy;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use http::HeaderMap;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use url::Url;

/// Events the queue holds before it drops.
pub const QUEUE_CAPACITY: usize = 1024;
/// The gateway refuses batches over 500 events.
const MAX_BATCH: usize = 500;
/// How long the task gathers events before it posts a short batch.
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
/// The gateway gives up after 15 seconds.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Longest `Retry-After` honored in one pause.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);
/// Pause when a `429` carries no usable `Retry-After`.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(5);
/// Attempts per batch, the first included.
const MAX_ATTEMPTS: u32 = 3;
/// First backoff after a transient failure; doubles per attempt.
const BACKOFF: Duration = Duration::from_secs(1);
/// Largest reply body read.
const MAX_REPLY_BYTES: usize = 4096;
/// Username sent with the org key; only the password is checked.
const BASIC_USER: &str = "px";
/// Path of the endpoint.
const SIGNALS_PATH: &str = "/v1/block-signals";

/// What blocked the request, in the gateway's vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum SignalKind {
    /// HTTP 429.
    RateLimited,
    /// 403 or 503 with a challenge or captcha marker, or a `/sorry/` redirect.
    Challenge,
    /// Repeated plain 403 on one target.
    Forbidden,
    /// Reset or TLS failure after a successful tunnel.
    Reset,
}

impl SignalKind {
    /// The wire value.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::RateLimited => "rate_limited",
            Self::Challenge => "challenge",
            Self::Forbidden => "forbidden",
            Self::Reset => "reset",
        }
    }
}

/// One event of a batch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlockSignal {
    /// `X-ProxyX-Pool-Session` of the tunnel.
    pub session: String,
    /// `X-ProxyX-Exit-IP` of the tunnel; the gateway requires an exact match.
    pub exit_ip: IpAddr,
    /// `host:port`, lower-cased, IPv6 bracketed.
    pub target: String,
    /// What blocked the request.
    pub kind: SignalKind,
    /// Unix seconds; the gateway ignores events older than an hour.
    pub time: i64,
}

#[derive(Serialize)]
struct WireEvent<'a> {
    session: &'a str,
    exit_ip: String,
    target: &'a str,
    #[serde(rename = "type")]
    ty: &'static str,
    time: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Reply {
    accepted: u64,
    ignored: u64,
}

/// `host:port` the way the gateway parses a target: lower-cased, IPv6 bracketed.
#[must_use]
pub fn target_of(host: &str, port: u16) -> String {
    let host = host.to_ascii_lowercase();
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Counters of one reporter.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[non_exhaustive]
pub struct SignalStats {
    /// Events the gateway accepted.
    pub accepted: u64,
    /// Events the gateway ignored (stale, unknown session or exit IP mismatch).
    pub ignored: u64,
    /// Events dropped because the queue was full.
    pub dropped: u64,
    /// Events lost to a failed or refused delivery.
    pub failed: u64,
}

#[derive(Default)]
struct Counters {
    accepted: AtomicU64,
    ignored: AtomicU64,
    dropped: AtomicU64,
    failed: AtomicU64,
}

impl Counters {
    fn add(&self, which: &AtomicU64, outcome: &'static str, n: u64) {
        which.fetch_add(n, Ordering::Relaxed);
        Metrics::global()
            .counter(names::PROXYX_BLOCK_SIGNALS)
            .inc_by(n, &[("outcome", outcome)]);
    }
}

/// Where and how to report.
pub(crate) struct ReportTarget {
    /// Control API base URL (`http://host:8081`).
    pub control: Url,
    /// The org key, sent as the Basic password.
    pub org_key: SecretOr<String>,
    /// Run egress policy; the control host is held to it.
    pub policy: Arc<EgressPolicy>,
    /// Resolver for the control host.
    pub resolver: Arc<dyn Resolver>,
}

/// Queue and background task. Dropping it closes the queue; the task drains what is left,
/// posts it and ends.
pub struct BlockReporter {
    tx: mpsc::Sender<BlockSignal>,
    counters: Arc<Counters>,
}

impl std::fmt::Debug for BlockReporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockReporter")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl BlockReporter {
    /// Start the background task. Needs a running tokio runtime.
    pub(crate) fn start(target: ReportTarget) -> Self {
        let (tx, rx) = mpsc::channel(QUEUE_CAPACITY);
        let counters = Arc::new(Counters::default());
        tokio::spawn(run(rx, target, Arc::clone(&counters)));
        Self { tx, counters }
    }

    /// Queue `signal`; never blocks. A full queue drops it and counts the drop.
    pub fn report(&self, signal: BlockSignal) {
        if self.tx.try_send(signal).is_err() {
            self.counters.add(&self.counters.dropped, "dropped", 1);
        }
    }

    /// Counters since start.
    #[must_use]
    pub fn stats(&self) -> SignalStats {
        SignalStats {
            accepted: self.counters.accepted.load(Ordering::Relaxed),
            ignored: self.counters.ignored.load(Ordering::Relaxed),
            dropped: self.counters.dropped.load(Ordering::Relaxed),
            failed: self.counters.failed.load(Ordering::Relaxed),
        }
    }
}

/// How one post ended.
enum Outcome {
    Delivered(Reply),
    /// `429`: wait this long, then send the same batch again.
    Throttled(Duration),
    /// `5xx` or transport failure: back off and send again.
    Transient,
    /// Any other answer, or the egress policy refused the control host: do not resend.
    Rejected,
}

async fn run(mut rx: mpsc::Receiver<BlockSignal>, target: ReportTarget, counters: Arc<Counters>) {
    while let Some(first) = rx.recv().await {
        let mut batch = vec![first];
        let deadline = Instant::now() + FLUSH_INTERVAL;
        while batch.len() < MAX_BATCH {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(signal)) => batch.push(signal),
                Ok(None) | Err(_) => break,
            }
        }
        deliver(&target, &batch, &counters).await;
    }
}

async fn deliver(target: &ReportTarget, batch: &[BlockSignal], counters: &Counters) {
    let n = u64::try_from(batch.len()).unwrap_or(u64::MAX);
    for attempt in 0..MAX_ATTEMPTS {
        match post(target, batch).await {
            Outcome::Delivered(reply) => {
                counters.add(&counters.accepted, "sent", reply.accepted);
                counters.add(&counters.ignored, "ignored", reply.ignored);
                return;
            }
            Outcome::Throttled(wait) => tokio::time::sleep(wait.min(MAX_RETRY_AFTER)).await,
            Outcome::Transient => tokio::time::sleep(BACKOFF * 2u32.pow(attempt)).await,
            Outcome::Rejected => break,
        }
    }
    counters.add(&counters.failed, "failed", n);
}

/// The control host's checked, pinned addresses.
async fn vet(target: &ReportTarget, host: &str, port: u16) -> Result<Vec<SocketAddr>, ()> {
    if target.policy.check_host(host).is_err() {
        tracing::warn!(host, "the ProxyX control host is refused by the egress policy");
        return Err(());
    }
    let addrs = match parse_ip_literal(host) {
        Some(ip) => vec![ip],
        None => target.resolver.resolve(host).await.map_err(|_| ())?,
    };
    if addrs.is_empty() || target.policy.check_all(host, &addrs).is_err() {
        tracing::warn!(host, "the ProxyX control host is refused by the egress policy");
        return Err(());
    }
    Ok(addrs.into_iter().map(|ip| SocketAddr::new(ip, port)).collect())
}

async fn post(target: &ReportTarget, batch: &[BlockSignal]) -> Outcome {
    let Some(host) = target.control.host_str() else {
        return Outcome::Rejected;
    };
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    let port = target.control.port_or_known_default().unwrap_or(80);
    let Ok(addrs) = vet(target, &host, port).await else {
        // an egress refusal is a configuration problem; a DNS failure may pass
        return if target.policy.check_host(&host).is_err() {
            Outcome::Rejected
        } else {
            Outcome::Transient
        };
    };
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_TIMEOUT)
        .use_rustls_tls();
    if parse_ip_literal(&host).is_none() {
        builder = builder.resolve_to_addrs(&host, &addrs);
    }
    let Ok(client) = builder.build() else {
        return Outcome::Rejected;
    };
    let mut url = target.control.clone();
    url.set_path(SIGNALS_PATH);
    url.set_query(None);
    let events: Vec<WireEvent<'_>> = batch
        .iter()
        .map(|s| WireEvent {
            session: &s.session,
            exit_ip: s.exit_ip.to_string(),
            target: &s.target,
            ty: s.kind.wire(),
            time: s.time,
        })
        .collect();
    let response = match client
        .post(url)
        .basic_auth(BASIC_USER, Some(target.org_key.expose()))
        .json(&events)
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => return Outcome::Transient,
    };
    let status = response.status();
    if status.is_success() {
        let reply = read_reply(response).await;
        return Outcome::Delivered(reply);
    }
    if status.as_u16() == 429 {
        return Outcome::Throttled(retry_after(response.headers()));
    }
    if status.is_server_error() {
        return Outcome::Transient;
    }
    tracing::warn!(
        status = status.as_u16(),
        "the ProxyX control API refused a block-signal batch"
    );
    Outcome::Rejected
}

fn retry_after(headers: &HeaderMap) -> Duration {
    parse_retry_after(headers, chrono::Utc::now())
        .unwrap_or(DEFAULT_RETRY_AFTER)
        .max(Duration::from_secs(1))
}

async fn read_reply(mut response: reqwest::Response) -> Reply {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        body.extend_from_slice(&chunk);
        if body.len() > MAX_REPLY_BYTES {
            return Reply::default();
        }
    }
    serde_json::from_slice(&body).unwrap_or_default()
}

/// Does a response carry the marker of an anti-bot challenge page?
///
/// Looked at only for `403`/`503` answers: a CDN's `cf-mitigated: challenge` header, a
/// `/sorry/` redirect, or well-known challenge phrases in the first bytes of the body. The marker
/// strings are exact page tokens the challenge vendors emit (detection-data).
#[must_use]
pub fn is_challenge(headers: &HeaderMap, body: &[u8]) -> bool {
    const PREFIX: usize = 16 * 1024;
    if headers
        .get("cf-mitigated")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("challenge"))
    {
        return true;
    }
    if headers
        .get(http::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("/sorry/"))
    {
        return true;
    }
    let head = &body[..body.len().min(PREFIX)];
    const MARKERS: [&[u8]; 9] = [
        b"cf-chl-",
        b"challenge-platform",
        b"just a moment...",
        b"g-recaptcha", // detection-data
        b"h-captcha",
        b"hcaptcha.com", // detection-data
        b"cf-turnstile", // detection-data
        b"px-captcha",
        b"/cdn-cgi/challenge",
    ];
    MARKERS.iter().any(|marker| {
        head.windows(marker.len())
            .any(|window| window.eq_ignore_ascii_case(marker))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use http::HeaderValue;

    #[test]
    fn targets_are_lowercased_and_ipv6_is_bracketed() {
        assert_eq!(target_of("Example.COM", 443), "example.com:443");
        assert_eq!(target_of("2001:DB8::1", 8443), "[2001:db8::1]:8443");
        assert_eq!(target_of("203.0.113.7", 80), "203.0.113.7:80");
    }

    #[test]
    fn signal_kinds_use_the_gateway_vocabulary() {
        assert_eq!(SignalKind::RateLimited.wire(), "rate_limited");
        assert_eq!(SignalKind::Challenge.wire(), "challenge");
        assert_eq!(SignalKind::Forbidden.wire(), "forbidden");
        assert_eq!(SignalKind::Reset.wire(), "reset");
    }

    #[test]
    fn challenge_markers_in_headers_and_body() {
        let mut headers = HeaderMap::new();
        assert!(!is_challenge(&headers, b"<html>plain forbidden</html>"));
        headers.insert("cf-mitigated", HeaderValue::from_static("Challenge"));
        assert!(is_challenge(&headers, b""));
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::LOCATION,
            HeaderValue::from_static("https://www.google.com/sorry/index?continue=x"),
        );
        assert!(is_challenge(&headers, b""));
        let none = HeaderMap::new();
        assert!(is_challenge(&none, b"<title>Just a moment...</title>"));
        assert!(is_challenge(&none, b"<div class=\"G-Recaptcha\"></div>")); // detection-data
        assert!(!is_challenge(&none, b"Access denied by policy"));
        // a marker beyond the inspected prefix is not seen
        let mut late = vec![b'x'; 20 * 1024];
        late.extend_from_slice(b"g-recaptcha"); // detection-data
        assert!(!is_challenge(&none, &late));
    }

    #[test]
    fn retry_after_defaults_and_floors() {
        let mut headers = HeaderMap::new();
        assert_eq!(retry_after(&headers), DEFAULT_RETRY_AFTER);
        headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("0"));
        assert_eq!(retry_after(&headers), Duration::from_secs(1));
        headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("42"));
        assert_eq!(retry_after(&headers), Duration::from_secs(42));
    }
}
