//! Recording reverse proxy: the server-side vantage point of `crawl-bench`.
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md. The idea: every target sits
//! behind a proxy, the crawler is pointed at the proxy, and what the target received is
//! measured from the server side instead of from the crawler's own report. The recorder
//! forwards the incoming `Host` header, so absolute links, sitemap URLs and redirects a target
//! builds from it point back through the proxy, and it turns an absolute same-origin
//! `Location` into a relative one for the same reason.
//!
//! Each request is recorded with its method, path, status and latency, measured from the
//! moment the request reached the proxy to the last byte of the upstream response.

use crate::error::BenchError;
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::{ACCEPT_ENCODING, CONTENT_LENGTH, HOST, LOCATION};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Largest request body the proxy forwards.
const MAX_REQUEST_BODY: usize = 8 * 1024 * 1024;
/// Time the upstream gets to answer one request.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);
/// Time the proxy gets to drain its connections on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Headers that describe one connection, not the message (RFC 9110 §7.6.1).
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// One request as the target received it.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct Hit {
    /// Upper-case HTTP method.
    pub method: String,
    /// Request path without the query string.
    pub path: String,
    /// Status the proxy answered with: the upstream's, `502` when the upstream failed and
    /// `413` when the request body was over the forwarding limit.
    pub status: u16,
    /// Time from the request reaching the proxy to the last upstream response byte.
    pub latency: Duration,
}

impl Hit {
    /// A hit from its parts (the recorder builds them itself; tests and callers that replay
    /// recorded traffic through [`crate::crawl_bench::summarize`] use this).
    #[must_use]
    pub fn new(method: impl Into<String>, path: impl Into<String>, status: u16, latency: Duration) -> Self {
        Self {
            method: method.into(),
            path: path.into(),
            status,
            latency,
        }
    }

    /// A successful (`2xx`) `GET`: what counts as a served page.
    #[must_use]
    pub fn is_page(&self) -> bool {
        self.method == "GET" && (200..300).contains(&self.status)
    }

    /// A `5xx` answer.
    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.status >= 500
    }
}

#[derive(Debug)]
struct ProxyState {
    upstream: Url,
    origin: String,
    client: reqwest::Client,
    hits: Mutex<Vec<Hit>>,
}

/// A running recording proxy in front of one upstream origin.
///
/// Dropping it aborts the server task; prefer [`Recorder::shutdown`].
#[derive(Debug)]
pub struct Recorder {
    addr: SocketAddr,
    state: Arc<ProxyState>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl Recorder {
    /// Listen on a free loopback port and forward to the origin of `upstream` (scheme, host and
    /// port; its path is ignored, requests keep their own).
    ///
    /// # Errors
    /// [`BenchError::Bind`] when the loopback listener cannot bind, [`BenchError::LocalAddr`]
    /// when its address is unreadable, [`BenchError::CrawlBench`] when `upstream` is not an
    /// `http(s)` URL with a host or the upstream client cannot be built.
    pub async fn start(upstream: &Url) -> Result<Self, BenchError> {
        if !matches!(upstream.scheme(), "http" | "https") || upstream.host_str().is_none() {
            return Err(BenchError::CrawlBench(format!(
                "recorder upstream `{upstream}` must be an http(s) URL with a host"
            )));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            // The crawler negotiates compression with the target itself; the proxy relays bytes.
            .no_gzip()
            .no_brotli()
            .no_proxy()
            .timeout(UPSTREAM_TIMEOUT)
            .build()
            .map_err(|e| BenchError::CrawlBench(format!("recorder upstream client: {e}")))?;
        let bind = SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = tokio::net::TcpListener::bind(bind)
            .await
            .map_err(|source| BenchError::Bind { addr: bind, source })?;
        let addr = listener.local_addr().map_err(BenchError::LocalAddr)?;
        let state = Arc::new(ProxyState {
            origin: upstream.origin().ascii_serialization(),
            upstream: upstream.clone(),
            client,
            hits: Mutex::new(Vec::new()),
        });
        let app = Router::new().fallback(forward).with_state(Arc::clone(&state));
        let stop = CancellationToken::new();
        let task = tokio::spawn({
            let stop = stop.clone();
            async move {
                let served = axum::serve(listener, app)
                    .with_graceful_shutdown(stop.cancelled_owned())
                    .await;
                if let Err(error) = served {
                    tracing::error!(%error, %addr, "crawl-bench recorder stopped with an error");
                }
            }
        });
        Ok(Self {
            addr,
            state,
            stop,
            task: Some(task),
        })
    }

    /// `http://127.0.0.1:PORT`, the origin the crawler must be pointed at.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Every request recorded so far, in arrival order.
    #[must_use]
    pub fn hits(&self) -> Vec<Hit> {
        self.state.hits.lock().clone()
    }

    /// Stop serving; connections get a short grace period before the task is aborted.
    pub async fn shutdown(mut self) {
        self.stop.cancel();
        if let Some(mut task) = self.task.take() {
            if tokio::time::timeout(SHUTDOWN_GRACE, &mut task).await.is_err() {
                task.abort();
            }
        }
    }
}

impl Drop for Recorder {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    HOP_BY_HOP.contains(&name.as_str())
}

async fn forward(State(state): State<Arc<ProxyState>>, req: Request) -> Response {
    let started = Instant::now();
    let (parts, body) = req.into_parts();
    let response = match relay(&state, &parts, body).await {
        Ok(response) => response,
        Err(status) => status.into_response(),
    };
    state.hits.lock().push(Hit {
        method: parts.method.as_str().to_owned(),
        path: parts.uri.path().to_owned(),
        status: response.status().as_u16(),
        latency: started.elapsed(),
    });
    response
}

/// Send one request upstream and read the whole answer.
async fn relay(state: &ProxyState, parts: &Parts, body: Body) -> Result<Response, StatusCode> {
    let body = to_bytes(body, MAX_REQUEST_BODY)
        .await
        .map_err(|_| StatusCode::PAYLOAD_TOO_LARGE)?;
    let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
    let url = format!("{}{path_and_query}", state.origin);

    let mut headers = HeaderMap::with_capacity(parts.headers.len());
    for (name, value) in &parts.headers {
        if !is_hop_by_hop(name) && name != HOST && name != ACCEPT_ENCODING && name != CONTENT_LENGTH {
            headers.append(name.clone(), value.clone());
        }
    }
    // Keep the proxy host so absolute links and redirects the target builds point back here.
    if let Some(host) = parts.headers.get(HOST) {
        headers.insert(HOST, host.clone());
    }

    let upstream = state
        .client
        .request(parts.method.clone(), &url)
        .headers(headers)
        .body(body)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let status = upstream.status();
    let mut out = HeaderMap::with_capacity(upstream.headers().len());
    for (name, value) in upstream.headers() {
        if !is_hop_by_hop(name) && name != CONTENT_LENGTH {
            out.append(name.clone(), value.clone());
        }
    }
    relativize_location(&mut out, &state.upstream);
    let bytes = upstream.bytes().await.map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    *response.headers_mut() = out;
    Ok(response)
}

/// Rewrite an absolute `Location` back to the upstream origin into a relative one, so the
/// crawler follows the redirect through the recorder.
fn relativize_location(headers: &mut HeaderMap, upstream: &Url) {
    let Some(location) = headers.get(LOCATION).and_then(|v| v.to_str().ok()) else {
        return;
    };
    let Ok(target) = Url::parse(location) else {
        return;
    };
    if target.origin() != upstream.origin() {
        return;
    }
    let mut relative = target.path().to_owned();
    if let Some(query) = target.query() {
        relative.push('?');
        relative.push_str(query);
    }
    if let Some(fragment) = target.fragment() {
        relative.push('#');
        relative.push_str(fragment);
    }
    if let Ok(value) = HeaderValue::from_str(&relative) {
        headers.insert(LOCATION, value);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn headers(location: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(LOCATION, HeaderValue::from_str(location).unwrap());
        h
    }

    #[test]
    fn same_origin_location_becomes_relative() {
        let upstream = Url::parse("http://127.0.0.1:3000/").unwrap();
        let mut h = headers("http://127.0.0.1:3000/login?next=%2Fhome#top");
        relativize_location(&mut h, &upstream);
        assert_eq!(h.get(LOCATION).unwrap(), "/login?next=%2Fhome#top");
    }

    #[test]
    fn foreign_and_relative_locations_are_untouched() {
        let upstream = Url::parse("http://127.0.0.1:3000/").unwrap();
        for loc in [
            "http://127.0.0.1:3001/x",
            "https://127.0.0.1:3000/x",
            "/already/relative",
            "next",
        ] {
            let mut h = headers(loc);
            relativize_location(&mut h, &upstream);
            assert_eq!(h.get(LOCATION).unwrap(), loc);
        }
    }

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        assert!(is_hop_by_hop(&HeaderName::from_static("connection")));
        assert!(is_hop_by_hop(&HeaderName::from_static("transfer-encoding")));
        assert!(!is_hop_by_hop(&HeaderName::from_static("content-type")));
    }

    #[test]
    fn page_and_error_classification() {
        let hit = |method: &str, status: u16| Hit {
            method: method.to_owned(),
            path: "/".to_owned(),
            status,
            latency: Duration::ZERO,
        };
        assert!(hit("GET", 200).is_page());
        assert!(!hit("GET", 404).is_page());
        assert!(!hit("POST", 200).is_page());
        assert!(hit("GET", 502).is_error());
        assert!(!hit("GET", 404).is_error());
    }
}
