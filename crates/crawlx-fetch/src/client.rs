//! The fetcher: resolve, check every address, pin, politeness, send, retry,
//! redirect, cap the body.
//!
//! Pinning works through a `reqwest::dns::Resolve` implementation that only
//! knows the addresses `Fetcher::fetch` has already checked for a host. The
//! connector therefore cannot dial anything the policy has not approved, and
//! there is no second DNS lookup between check and connect (defeats rebinding).
//! `Host` and SNI keep the original name because the URL is unchanged. After
//! the response the connected peer is asserted against the checked set.

use crate::body_limits::{read_capped, DEFAULT_MAX_BODY_BYTES};
use crate::conditional::Validators;
use crate::egress::{capture_headers, protocol_of};
use crate::error::FetchError;
use crate::governor::{GlobalOriginCap, GovernorConfig, Origin, OriginGovernor};
use crate::redirect::{is_redirect, location, strip_credentials, DEFAULT_MAX_REDIRECTS};
use crate::resolver::Resolver;
use crate::retry::{is_retryable_status, parse_retry_after, RetryPolicy};
use crate::tls::HttpClient;
use bytes::Bytes;
use crawlx_core::browser::ResponseBodySink;
use crawlx_core::config::{Fetch, ResponseBodies};
use crawlx_core::hash::Digest;
use crawlx_core::request_controls::RequestControls;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::tls::TlsImpersonation;
use crawlx_core::traffic::{BodyDigest, ProxyFlow, ProxyFlowSource};
use crawlx_core::{ArtifactId, ArtifactRef};
use crawlx_policy::egress::{DenyRule, EgressPolicy};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use parking_lot::Mutex;
use rand_chacha::ChaCha8Rng;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use url::{Host, Url};

/// Fetcher construction parameters.
#[derive(Clone)]
pub struct FetchConfig {
    /// Contact appended to the User-Agent: `crawlx/<version> (+<contact>)`.
    /// Empty means no contact suffix.
    pub contact: String,
    /// Default body cap in bytes (8 MiB; `fetch.maxResponseBytes`).
    pub max_body_bytes: usize,
    /// Default redirect hop limit (10).
    pub max_redirects: usize,
    /// Maximum time to establish the TCP and TLS connection of one request.
    pub connect_timeout: Duration,
    /// Whole-request timeout including the body (`fetch.timeoutMs`).
    pub request_timeout: Duration,
    /// Retry budget and backoff curve for transient failures (`fetch.retries`).
    pub retry: RetryPolicy,
    /// Per-origin pacing. Its `seed` is overridden by `FetchConfig::seed`.
    pub governor: GovernorConfig,
    /// Seed of the retry and pacing jitter.
    pub seed: CrawlSeed,
    /// Synthetic seeded ClientHello randomization; off keeps the rustls transport.
    pub tls_impersonation: TlsImpersonation,
    /// Follow `3xx` answers (`fetch.followRedirects`, default true). When false every
    /// redirect is returned as the final response, whatever the per-request option says.
    pub follow_redirects: bool,
    /// Upstream proxy for every request (`fetch.proxy`; `http`, `https`, `socks5` or
    /// `socks5h`). The egress policy is still applied to the *target* host of every hop
    /// before the request is sent, and to the proxy host itself: a proxy on a denied
    /// address fails with [`FetchError::EgressDenied`].
    pub proxy: Option<Url>,
    /// Process-wide per-origin connection cap shared with every other fetcher of the
    /// process. `None` gives this fetcher a private cap of
    /// `governor.global_per_origin_cap`.
    pub shared_origin_cap: Option<Arc<GlobalOriginCap>>,
    /// Complete per-run governor shared with browser actors and auxiliary fetchers.
    /// Takes precedence over `governor` and `shared_origin_cap` when present.
    pub shared_governor: Option<Arc<OriginGovernor>>,
    /// Custom headers, cookies, `User-Agent` and TLS verification (`fetch.extraHeaders`,
    /// `fetch.cookies`, `fetch.userAgent`, `fetch.skipTlsVerification`), resolved by
    /// `RequestControls::resolve`. Header values are sent only to the controls' scope domain
    /// (the seed's registrable domain); cookies only to hosts matching their own domain.
    pub controls: RequestControls,
}

impl std::fmt::Debug for FetchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FetchConfig")
            .field("max_body_bytes", &self.max_body_bytes)
            .field("request_timeout", &self.request_timeout)
            .field("proxy", &self.proxy.as_ref().map(|_| "[configured]"))
            .finish_non_exhaustive()
    }
}

impl Default for FetchConfig {
    fn default() -> Self {
        Self {
            contact: String::new(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            retry: RetryPolicy::default(),
            governor: GovernorConfig::default(),
            seed: CrawlSeed(0),
            tls_impersonation: TlsImpersonation::Off,
            follow_redirects: true,
            proxy: None,
            shared_origin_cap: None,
            shared_governor: None,
            controls: RequestControls::default(),
        }
    }
}

impl FetchConfig {
    /// The `User-Agent` of every request: `fetch.userAgent` verbatim, else
    /// `crawlx/<version> (+<contact>)`.
    #[must_use]
    pub fn user_agent(&self) -> String {
        if let Some(ua) = self.controls.user_agent() {
            return ua.to_owned();
        }
        let version = env!("CARGO_PKG_VERSION");
        if self.contact.trim().is_empty() {
            format!("crawlx/{version}")
        } else {
            format!("crawlx/{version} (+{})", self.contact.trim())
        }
    }

    /// The user agent robots.txt groups are matched with: `fetch.robotsUserAgent`, else
    /// `fetch.userAgent`, else [`Self::user_agent`] (its product token selects the group).
    #[must_use]
    pub fn robots_user_agent(&self) -> String {
        self.controls
            .robots_user_agent()
            .map_or_else(|| self.user_agent(), str::to_owned)
    }

    /// Same configuration with `controls` (see [`Self::controls`]).
    #[must_use]
    pub fn with_controls(mut self, controls: RequestControls) -> Self {
        self.controls = controls;
        self
    }

    /// Apply the request's `fetch` block: body cap, request timeout, retry
    /// budget, redirect following and upstream proxy. The connect timeout is bounded by the
    /// request timeout; every other field keeps its current value.
    #[must_use]
    pub fn with_fetch(mut self, fetch: &Fetch) -> Self {
        self.max_body_bytes = usize::try_from(fetch.max_response_bytes).unwrap_or(usize::MAX);
        self.request_timeout = Duration::from_millis(u64::from(fetch.timeout_ms));
        self.connect_timeout = self.connect_timeout.min(self.request_timeout);
        self.retry.max_retries = u32::from(fetch.retries);
        self.follow_redirects = fetch.follow_redirects;
        self.proxy.clone_from(&fetch.proxy);
        self.tls_impersonation = fetch.tls_impersonation;
        self
    }

    /// Defaults plus the request's `fetch` block ([`Self::with_fetch`]).
    #[must_use]
    pub fn from_request(fetch: &Fetch) -> Self {
        Self::default().with_fetch(fetch)
    }

    /// Scheme check of `proxy` (`http`, `https`, `socks5`, `socks5h`; no userinfo-free
    /// requirement: proxy credentials are allowed) and its host.
    fn proxy_target(&self) -> Result<Option<ProxyTarget>, FetchError> {
        let Some(p) = &self.proxy else { return Ok(None) };
        crate::UpstreamProxy::from_url(p)?;
        let (host, literal) = host_of(p)?;
        Ok(Some(ProxyTarget { host, literal }))
    }
}

/// The proxy host the client dials instead of the target.
#[derive(Clone, Debug)]
struct ProxyTarget {
    host: String,
    literal: Option<IpAddr>,
}

/// Lower-cased host of `url` and, for an IP literal, the address.
fn host_of(url: &Url) -> Result<(String, Option<IpAddr>), FetchError> {
    match url.host() {
        Some(Host::Domain(d)) => Ok((d.to_ascii_lowercase(), None)),
        Some(Host::Ipv4(ip)) => Ok((ip.to_string(), Some(IpAddr::V4(ip)))),
        Some(Host::Ipv6(ip)) => Ok((ip.to_string(), Some(IpAddr::V6(ip)))),
        None => Err(FetchError::InvalidUrl {
            url: url.to_string(),
            reason: "no host",
        }),
    }
}

/// Per-request options.
#[derive(Clone, Debug)]
pub struct FetchOptions {
    /// `GET` (default) or `HEAD`.
    pub method: Method,
    /// Extra request headers. `Authorization`, `Cookie` and
    /// `Proxy-Authorization` are dropped when a redirect leaves the origin.
    pub headers: HeaderMap,
    /// Validators for a conditional request; sent on the first hop only.
    pub validators: Option<Validators>,
    /// Overrides `FetchConfig::max_body_bytes`.
    pub max_body_bytes: Option<usize>,
    /// Overrides `FetchConfig::max_redirects`.
    pub max_redirects: Option<usize>,
    /// When `false` a `3xx` answer is returned as is.
    pub follow_redirects: bool,
    /// Report the request on the fetcher's capture channel (default `true`). `false` for
    /// requests whose URL or headers carry a secret, which must reach no other plane.
    pub capture: bool,
    /// Shared remaining network requests of the parent acquisition, charged before every hop.
    /// A redirect or fallback never gets a fresh allowance.
    pub request_allowance: Option<Arc<std::sync::atomic::AtomicU32>>,
    /// Skip Scrapy latency adjustment for this request; throttle cooldowns still apply.
    pub dont_adjust_delay: bool,
    /// Permanently suppress origin-bound credentials after a caller-managed origin change.
    pub suppress_credentials: bool,
    /// Suppress all conditional validators after a caller-managed transition.
    pub suppress_validators: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            method: Method::GET,
            headers: HeaderMap::new(),
            validators: None,
            max_body_bytes: None,
            max_redirects: None,
            follow_redirects: true,
            capture: true,
            request_allowance: None,
            dont_adjust_delay: false,
            suppress_credentials: false,
            suppress_validators: false,
        }
    }
}

/// One redirect answer of a fetch: the URL that was requested and what it answered with.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct FetchHop {
    /// URL that answered with the redirect.
    pub url: Url,
    /// The redirect status (`301`, `302`, ...).
    pub status: StatusCode,
    /// Headers of the redirect answer (including `Location`).
    pub headers: HeaderMap,
}
impl FetchHop {
    /// Record an observed redirect from a caller-managed checked hop.
    #[must_use]
    pub fn observed(url: Url, status: StatusCode, headers: HeaderMap) -> Self {
        Self { url, status, headers }
    }
}

/// A completed fetch.
#[derive(Clone, Debug)]
pub struct FetchResponse {
    /// URL that produced this response (after redirects).
    pub final_url: Url,
    /// Status of the final (non-redirect) response.
    pub status: StatusCode,
    /// Headers of the final response.
    pub headers: HeaderMap,
    /// Decoded body, at most the cap.
    pub body: Bytes,
    /// The body was cut at the cap.
    pub truncated: bool,
    /// URLs that answered with a redirect, in order. The full chain is
    /// `redirects` followed by `final_url`; empty when nothing redirected.
    pub redirects: Vec<String>,
    /// The redirect answers behind `redirects`, one per entry and in the same order.
    pub hops: Vec<FetchHop>,
    /// Address the final connection was made to.
    pub resolved_ip: IpAddr,
    /// The transport reported an actual peer address (rather than only a checked candidate).
    pub peer_observed: bool,
    /// `Content-Type` header value, if present and valid text.
    pub content_type: Option<String>,
    /// Requests sent in total, retries and redirects included.
    pub attempts: u32,
    /// Wall time of the whole fetch including politeness and backoff waits.
    pub duration: Duration,
}

impl FetchResponse {
    /// Artifact retained by the trusted fetch producer, if policy permitted body storage.
    #[must_use]
    pub fn retained_response_body(&self) -> Option<ArtifactRef> {
        let id = self
            .headers
            .get("x-crawlx-stream-response-artifact-id")?
            .to_str()
            .ok()?;
        let digest = self
            .headers
            .get("x-crawlx-stream-response-artifact-digest")?
            .to_str()
            .ok()?;
        Some(ArtifactRef {
            id: id.parse::<ArtifactId>().ok()?,
            digest: Digest::from_hex(digest).ok()?,
        })
    }

    /// `304 Not Modified`: the caller's stored copy is still valid.
    #[must_use]
    pub fn not_modified(&self) -> bool {
        self.status == StatusCode::NOT_MODIFIED
    }

    /// Validators this response offers for the next conditional request.
    #[must_use]
    pub fn validators(&self) -> Validators {
        Validators::from_headers(&self.headers)
    }
}

// ---------------------------------------------------------------------------
// Address pinning
// ---------------------------------------------------------------------------

struct PinEntry {
    ips: Vec<IpAddr>,
    refs: usize,
}

/// Host -> checked addresses, alive only while a request to the host is in flight.
#[derive(Default)]
struct PinTable {
    map: Mutex<HashMap<String, PinEntry>>,
}

struct PinGuard {
    table: Arc<PinTable>,
    host: String,
}

impl PinTable {
    fn pin(self: &Arc<Self>, host: &str, ips: &[IpAddr]) -> PinGuard {
        let host = host.to_ascii_lowercase();
        let mut map = self.map.lock();
        let entry = map.entry(host.clone()).or_insert_with(|| PinEntry {
            ips: Vec::new(),
            refs: 0,
        });
        entry.refs += 1;
        for ip in ips {
            if !entry.ips.contains(ip) {
                entry.ips.push(*ip);
            }
        }
        drop(map);
        PinGuard {
            table: Arc::clone(self),
            host,
        }
    }
}

impl PinGuard {
    /// Every address in the entry passed the egress check (it is the union of
    /// the checked sets of concurrent requests to this host).
    fn contains(&self, ip: IpAddr) -> bool {
        self.table
            .map
            .lock()
            .get(&self.host)
            .is_some_and(|e| e.ips.contains(&ip))
    }
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        let mut map = self.table.map.lock();
        if let Some(e) = map.get_mut(&self.host) {
            e.refs = e.refs.saturating_sub(1);
            if e.refs == 0 {
                map.remove(&self.host);
            }
        }
    }
}

impl PinTable {
    fn resolve_name(&self, name: &str) -> Resolving {
        let found: Option<Vec<IpAddr>> = self
            .map
            .lock()
            .get(&name.to_ascii_lowercase())
            .map(|e| e.ips.clone());
        Box::pin(async move {
            match found {
                Some(ips) => Ok(Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0))) as Addrs),
                None => Err(Box::<dyn std::error::Error + Send + Sync>::from(
                    "host has no pinned, policy-checked address",
                )),
            }
        })
    }
}

impl Resolve for PinTable {
    fn resolve(&self, name: Name) -> Resolving {
        self.resolve_name(name.as_str())
    }
}

impl wreq::dns::Resolve for PinTable {
    fn resolve(&self, name: wreq::dns::Name) -> wreq::dns::Resolving {
        self.resolve_name(name.as_str())
    }
}

// ---------------------------------------------------------------------------
// Fetcher
// ---------------------------------------------------------------------------

/// Result of one hop (one URL, after retries).
enum Hop {
    /// A redirect to follow; its body was not read.
    Redirect { status: StatusCode, headers: HeaderMap },
    Final {
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        truncated: bool,
        peer: IpAddr,
        peer_observed: bool,
    },
}

/// The HTTP plane.
pub struct Fetcher {
    cfg: FetchConfig,
    client: HttpClient,
    pins: Arc<PinTable>,
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolver>,
    governor: Arc<OriginGovernor>,
    /// Host the client dials when an upstream proxy is configured.
    proxy: Option<ProxyTarget>,
    /// Unified capture: one `ProxyFlow { source: FetchPlane }` per response.
    capture: Option<mpsc::Sender<ProxyFlow>>,
    response_bodies: ResponseBodies,
    response_body_sink: Option<Arc<dyn ResponseBodySink>>,
    response_body_origin: Option<Url>,
    /// `fetch.extraHeaders` as wire headers (values marked sensitive), sent to hosts in
    /// the controls' scope.
    control_headers: Vec<(HeaderName, HeaderValue)>,
    /// Alternate deployment route, used only by GET scrape escalation.
    enhanced: Option<Box<Fetcher>>,
}

impl std::fmt::Debug for Fetcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fetcher")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl Fetcher {
    /// Build a fetcher. The client ignores proxy environment variables (only
    /// `FetchConfig::proxy` is used), never follows redirects itself and only dials
    /// pinned addresses.
    ///
    /// # Errors
    /// [`FetchError::ClientBuild`] when the TLS backend or HTTP client cannot be
    /// initialised; [`FetchError::InvalidUrl`] when `cfg.proxy` has an unsupported scheme
    /// or no host.
    pub fn new(
        cfg: FetchConfig,
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self, FetchError> {
        let pins = Arc::new(PinTable::default());
        let proxy = cfg.proxy_target()?;
        let control_headers = control_headers(&cfg.controls)?;
        let client = if cfg.tls_impersonation == TlsImpersonation::Randomized {
            HttpClient::randomized(
                &cfg,
                Arc::clone(&pins),
                Arc::clone(&policy),
                Arc::clone(&resolver),
            )?
        } else {
            let mut builder = reqwest::Client::builder()
                .user_agent(cfg.user_agent())
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .use_rustls_tls()
                .dns_resolver(Arc::clone(&pins))
                .connect_timeout(cfg.connect_timeout)
                .timeout(cfg.request_timeout)
                .gzip(true)
                .brotli(true)
                .danger_accept_invalid_certs(cfg.controls.skip_tls_verification());
            if let Some(p) = &cfg.proxy {
                // Environment proxies stay disabled; only the checked proxy is used.
                builder = builder.proxy(
                    reqwest::Proxy::all(p.clone()).map_err(|error| FetchError::ClientBuild(error.into()))?,
                );
            }
            HttpClient::Rustls(
                builder
                    .build()
                    .map_err(|error| FetchError::ClientBuild(error.into()))?,
            )
        };
        let governor = match &cfg.shared_governor {
            Some(governor) => Arc::clone(governor),
            None => {
                let governor_cfg = GovernorConfig {
                    seed: cfg.seed,
                    ..cfg.governor.clone()
                };
                Arc::new(match &cfg.shared_origin_cap {
                    Some(cap) => OriginGovernor::with_global_cap(governor_cfg, Arc::clone(cap)),
                    None => OriginGovernor::new(governor_cfg),
                })
            }
        };
        Ok(Self {
            cfg,
            client,
            pins,
            policy,
            resolver,
            governor,
            proxy,
            control_headers,
            capture: None,
            response_bodies: ResponseBodies::MetadataOnly,
            response_body_sink: None,
            response_body_origin: None,
            enhanced: None,
        })
    }

    /// Configure an alternate upstream while retaining policy, credentials, pacing and capture.
    ///
    /// # Errors
    /// Returns the same construction failures as [`Self::new`].
    pub fn with_enhanced_proxy(mut self, proxy: &Url) -> Result<Self, FetchError> {
        let mut cfg = self.cfg.clone();
        cfg.proxy = Some(proxy.clone());
        let mut enhanced = Self::new(cfg, Arc::clone(&self.policy), Arc::clone(&self.resolver))?;
        enhanced.governor = Arc::clone(&self.governor);
        enhanced.capture.clone_from(&self.capture);
        enhanced.response_bodies = self.response_bodies;
        enhanced.response_body_sink.clone_from(&self.response_body_sink);
        enhanced
            .response_body_origin
            .clone_from(&self.response_body_origin);
        self.enhanced = Some(Box::new(enhanced));
        Ok(self)
    }

    /// The configured enhanced route, never an implicit fallback to the basic route.
    #[must_use]
    pub fn enhanced(&self) -> Option<&Self> {
        self.enhanced.as_deref()
    }

    /// Report every response as a [`ProxyFlow`] with `source = FetchPlane` on `capture`.
    /// Flows are `try_send`-ed; a full channel
    /// drops the flow. Credential header values are replaced before the flow is sent.
    #[must_use]
    pub fn with_capture(mut self, capture: mpsc::Sender<ProxyFlow>) -> Self {
        self.capture = Some(capture);
        self
    }

    /// Retain fetched bodies through the run's sensitivity and artifact policy boundary.
    /// Metadata-only mode never calls the sink. Text-capped mode supplies at most 64 KiB
    /// of JSON/HTML. All retained modes require the seed origin and deny auth routes
    /// and Set-Cookie.
    #[must_use]
    pub fn with_response_body_sink(
        mut self,
        mode: ResponseBodies,
        sink: Arc<dyn ResponseBodySink>,
        origin: Url,
    ) -> Self {
        if let Some(enhanced) = self.enhanced.take() {
            self.enhanced = Some(Box::new((*enhanced).with_response_body_sink(
                mode,
                Arc::clone(&sink),
                origin.clone(),
            )));
        }
        self.response_bodies = mode;
        self.response_body_sink = Some(sink);
        self.response_body_origin = Some(origin);
        self
    }

    async fn retain_response_body(
        &self,
        url: &Url,
        headers: &mut HeaderMap,
        body: &[u8],
        truncated: bool,
    ) -> Result<(), FetchError> {
        let prefix = self.response_bodies == ResponseBodies::TextCapped;
        let mode = if prefix {
            "text_capped"
        } else if self.response_bodies == ResponseBodies::Full {
            "full"
        } else {
            "metadata_only"
        };
        let limit = if prefix {
            64 * 1024
        } else {
            self.cfg.max_body_bytes
        };
        let policy_denied = self.response_bodies != ResponseBodies::MetadataOnly
            && !self.body_policy_permits(url, headers, prefix);
        let mut end = body.len().min(limit);
        if prefix && !policy_denied {
            if let Err(error) = std::str::from_utf8(&body[..end]) {
                if error.error_len().is_none() {
                    end = error.valid_up_to();
                }
            }
        }
        let cut = truncated || end < body.len();
        let (outcome, artifact) = if self.response_bodies == ResponseBodies::MetadataOnly {
            ("metadata_only", None)
        } else if policy_denied {
            ("policy_denied", None)
        } else if body.is_empty() {
            ("empty", None)
        } else if !prefix && cut {
            ("oversized", None)
        } else if let Some(sink) = &self.response_body_sink {
            let content_type = headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            match sink.store(content_type, &body[..end], prefix).await {
                Ok(Some(artifact)) => (if prefix { "stored_prefix" } else { "stored" }, Some(artifact)),
                Ok(None) => ("policy_denied", None),
                Err(_) => ("storage_error", None),
            }
        } else {
            ("sink_unavailable", None)
        };
        headers.insert("x-crawlx-stream-body-mode", HeaderValue::from_static(mode));
        headers.insert("x-crawlx-stream-body-capture", HeaderValue::from_static(outcome));
        headers.insert(
            "x-crawlx-stream-body-truncated",
            HeaderValue::from_static(if cut { "true" } else { "false" }),
        );
        headers.insert("x-crawlx-stream-body-limit", HeaderValue::from(limit));
        if let Some(artifact) = artifact {
            for (name, value) in [
                ("x-crawlx-stream-response-artifact-id", artifact.id.to_string()),
                (
                    "x-crawlx-stream-response-artifact-digest",
                    artifact.digest.to_hex(),
                ),
            ] {
                headers.insert(
                    HeaderName::from_static(name),
                    HeaderValue::from_str(&value).map_err(|_| FetchError::InvalidHeader {
                        name: name.to_owned(),
                    })?,
                );
            }
        }
        Ok(())
    }

    fn body_policy_permits(&self, url: &Url, headers: &HeaderMap, prefix: bool) -> bool {
        let Some(origin) = &self.response_body_origin else {
            return false;
        };
        if url.scheme() != origin.scheme()
            || url.host_str() != origin.host_str()
            || url.port_or_known_default() != origin.port_or_known_default()
            || headers.contains_key(header::SET_COOKIE)
        {
            return false;
        }
        let path = url.path().as_bytes();
        if ["login", "logout", "signin", "auth", "token", "session"]
            .iter()
            .any(|part| {
                path.windows(part.len())
                    .any(|window| window.eq_ignore_ascii_case(part.as_bytes()))
            })
        {
            return false;
        }
        if !prefix {
            return true;
        }
        let mime = headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .unwrap_or("")
            .trim();
        mime.eq_ignore_ascii_case("text/html")
            || mime.eq_ignore_ascii_case("application/json")
            || mime
                .as_bytes()
                .get(mime.len().saturating_sub(5)..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(b"+json"))
    }

    /// Headers of one hop: the configured extra headers when `url`'s host is in the controls'
    /// scope, the cookies whose domain and path match, then the per-request `headers`, which
    /// replace a configured header of the same name.
    fn request_headers(&self, url: &Url, headers: &HeaderMap) -> Result<HeaderMap, FetchError> {
        let mut out = HeaderMap::new();
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        if !self.control_headers.is_empty() && self.cfg.controls.applies_to(&host) {
            for (name, value) in &self.control_headers {
                out.insert(name.clone(), value.clone());
            }
        }
        if let Some(cookie) = self.cfg.controls.cookie_header(&host, url.path()) {
            let mut value =
                HeaderValue::from_bytes(cookie.as_bytes()).map_err(|_| FetchError::InvalidHeader {
                    name: "cookie".to_owned(),
                })?;
            value.set_sensitive(true);
            out.insert(header::COOKIE, value);
        }
        if out.is_empty() {
            return Ok(headers.clone());
        }
        let mut previous: Option<&HeaderName> = None;
        for (name, value) in headers {
            if previous != Some(name) {
                out.remove(name);
                previous = Some(name);
            }
            out.append(name.clone(), value.clone());
        }
        Ok(out)
    }

    /// Capture-channel copy of `headers` with every configured header and every header that
    /// echoes a configured value replaced by `[redacted]` ([`RequestControls::mask_headers`]).
    fn redact_flow_headers(&self, mut headers: Vec<(String, String)>) -> Vec<(String, String)> {
        self.cfg.controls.mask_headers(&mut headers);
        headers
    }

    fn emit_flow(&self, flow: Option<ProxyFlow>, body: Option<&Bytes>) {
        if let (Some(tx), Some(mut flow)) = (&self.capture, flow) {
            flow.response_body = body
                .filter(|b| !b.is_empty())
                .map(|b| BodyDigest::of_prefix(b, u64::try_from(b.len()).unwrap_or(u64::MAX)));
            flow.finished_at = chrono::Utc::now();
            if tx.try_send(flow).is_err() {
                tracing::debug!("fetch-plane capture channel full; flow dropped");
            }
        }
    }

    /// The politeness governor, shared so the browser plane can charge navigations to it.
    #[must_use]
    pub fn governor(&self) -> &Arc<OriginGovernor> {
        &self.governor
    }

    /// The configuration this fetcher was built with.
    #[must_use]
    pub const fn config(&self) -> &FetchConfig {
        &self.cfg
    }

    /// Fetch `url`, following redirects manually with a full egress re-check per hop.
    ///
    /// # Errors
    /// [`FetchError::UnsupportedMethod`] for methods other than `GET`/`HEAD`;
    /// [`FetchError::EgressDenied`], [`FetchError::InvalidUrl`] or
    /// [`FetchError::Resolve`] when a hop fails the egress or DNS checks;
    /// [`FetchError::PeerNotPinned`] when the connection reaches an unchecked address;
    /// [`FetchError::TooManyRedirects`] or [`FetchError::InvalidRedirect`] on bad
    /// redirect chains; [`FetchError::Timeout`] and [`FetchError::Transport`] on
    /// network failures once retries are exhausted.
    pub async fn fetch(&self, url: &Url, opts: &FetchOptions) -> Result<FetchResponse, FetchError> {
        self.fetch_with_retry_budget(url, opts, self.cfg.retry.max_retries, &|| {
            std::future::ready(Ok(()))
        })
        .await
    }

    /// Fetch with the configured retry budget and recheck borrowed authority before every send.
    ///
    /// The caller keeps the original authority alive across redirects and retries.
    /// This does not change request headers, cookies, or retry policy.
    ///
    /// # Errors
    /// Returns the failures of [`Self::fetch`] or the authority check unchanged.
    pub fn fetch_with_authority<'a, F, Fut>(
        &'a self,
        url: &'a Url,
        opts: &'a FetchOptions,
        check_authority: &'a F,
    ) -> impl Future<Output = Result<FetchResponse, FetchError>> + Send + 'a
    where
        F: Fn() -> Fut + Sync + 'a,
        Fut: Future<Output = Result<(), FetchError>> + Send + 'a,
    {
        self.fetch_with_retry_budget(url, opts, self.cfg.retry.max_retries, check_authority)
    }

    /// Fetch once per redirect hop, without status retries. GET/HEAD only, like [`Self::fetch`].
    /// Used for bounded scrape proxy escalation; robots and other fetches retain their budgets.
    ///
    /// # Errors
    /// Returns the same URL, policy, method and transport failures as [`Self::fetch`].
    pub async fn fetch_once(&self, url: &Url, opts: &FetchOptions) -> Result<FetchResponse, FetchError> {
        self.fetch_with_retry_budget(url, opts, 0, &|| std::future::ready(Ok(())))
            .await
    }

    /// Fetch once per hop, rechecking borrowed authority at each dispatch boundary.
    ///
    /// The check runs after DNS and governor waits, immediately before transport
    /// dispatch. Redirect hops retain the same check. The caller must keep its
    /// original authority pinned and bound pending checks with its deadline and
    /// cancellation policy; this method never replaces or refreshes that authority.
    ///
    /// # Errors
    /// Returns the failures of [`Self::fetch_once`] or the authority check unchanged.
    pub async fn fetch_once_with_authority<F, Fut>(
        &self,
        url: &Url,
        opts: &FetchOptions,
        check_authority: &F,
    ) -> Result<FetchResponse, FetchError>
    where
        F: Fn() -> Fut + Sync,
        Fut: Future<Output = Result<(), FetchError>> + Send,
    {
        // Bound the future stored by deeply composed worker acquisition/robots
        // paths. Ordinary fetches retain their allocation-free direct path.
        Box::pin(self.fetch_with_retry_budget(url, opts, 0, check_authority)).await
    }

    async fn fetch_with_retry_budget<F, Fut>(
        &self,
        url: &Url,
        opts: &FetchOptions,
        max_retries: u32,
        check_authority: &F,
    ) -> Result<FetchResponse, FetchError>
    where
        F: Fn() -> Fut + Sync,
        Fut: Future<Output = Result<(), FetchError>> + Send,
    {
        if opts.method != Method::GET && opts.method != Method::HEAD {
            return Err(FetchError::UnsupportedMethod(opts.method.to_string()));
        }
        let result = self.fetch_inner(url, opts, max_retries, check_authority).await;
        let outcome = match &result {
            Ok(r) => status_class(r.status),
            Err(_) => "error",
        };
        Metrics::global()
            .counter(names::FETCH_RESPONSES)
            .inc_by(1, &[("outcome", outcome)]);
        result
    }

    async fn fetch_inner<F, Fut>(
        &self,
        url: &Url,
        opts: &FetchOptions,
        max_retries: u32,
        check_authority: &F,
    ) -> Result<FetchResponse, FetchError>
    where
        F: Fn() -> Fut + Sync,
        Fut: Future<Output = Result<(), FetchError>> + Send,
    {
        let started = Instant::now();
        let max_body = opts.max_body_bytes.unwrap_or(self.cfg.max_body_bytes);
        let max_redirects = opts.max_redirects.unwrap_or(self.cfg.max_redirects);
        let mut rng = self.cfg.seed.rng("fetch/retry", &[url.as_str().as_bytes()]);
        let mut headers = opts.headers.clone();
        let mut current = url.clone();
        let mut redirects: Vec<String> = Vec::new();
        let mut attempts: u32 = 0;
        let mut hops: Vec<FetchHop> = Vec::new();

        loop {
            if let Some(allowance) = &opts.request_allowance {
                allowance
                    .try_update(
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                        |remaining| remaining.checked_sub(1),
                    )
                    .map_err(|_| FetchError::AcquisitionAllowance)?;
            }
            let validators = if redirects.is_empty() {
                opts.validators.as_ref()
            } else {
                None
            };
            let hop = self
                .fetch_hop(
                    &current,
                    &opts.method,
                    &headers,
                    validators,
                    max_body,
                    opts.follow_redirects && self.cfg.follow_redirects,
                    opts.capture,
                    opts.dont_adjust_delay,
                    opts.suppress_credentials,
                    opts.suppress_validators || !redirects.is_empty(),
                    &mut rng,
                    &mut attempts,
                    max_retries,
                    check_authority,
                )
                .await?;
            match hop {
                Hop::Redirect { status, headers: rh } => {
                    if redirects.len() >= max_redirects {
                        return Err(FetchError::TooManyRedirects { limit: max_redirects });
                    }
                    let next = location(&current, &rh)?;
                    if Origin::from_url(&next) != Origin::from_url(&current) {
                        strip_credentials(&mut headers);
                    }
                    redirects.push(current.to_string());
                    hops.push(FetchHop {
                        url: current.clone(),
                        status,
                        headers: rh,
                    });
                    current = next;
                }
                Hop::Final {
                    status,
                    headers: rh,
                    body,
                    truncated,
                    peer,
                    peer_observed,
                } => {
                    let content_type = rh
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    return Ok(FetchResponse {
                        final_url: current,
                        status,
                        headers: rh,
                        body,
                        truncated,
                        redirects,
                        hops,
                        resolved_ip: peer,
                        peer_observed,
                        content_type,
                        attempts,
                        duration: started.elapsed(),
                    });
                }
            }
        }
    }

    /// Resolve and check `url`'s host; every address must pass.
    async fn resolve_checked(&self, url: &Url) -> Result<(String, Vec<IpAddr>), FetchError> {
        if let Err(denied) = self.policy.check_url(url) {
            count_egress_denial(denied.rule);
            return Err(denied.into());
        }
        let (host, literal) = host_of(url)?;
        self.resolve_host_checked(host, literal).await
    }

    /// Resolve `host` (or take the literal) and check the name and every address.
    async fn resolve_host_checked(
        &self,
        host: String,
        literal: Option<IpAddr>,
    ) -> Result<(String, Vec<IpAddr>), FetchError> {
        let addrs = match literal {
            Some(ip) => vec![ip],
            None => self.resolver.resolve(&host).await?,
        };
        if addrs.is_empty() {
            return Err(FetchError::Resolve {
                host,
                reason: "no addresses".to_owned(),
            });
        }
        if let Err(denied) = self.policy.check_all(&host, &addrs) {
            tracing::warn!(%host, rule = denied.rule.as_str(), "egress denied (http plane)");
            count_egress_denial(denied.rule);
            return Err(denied.into());
        }
        Ok((host, addrs))
    }

    /// The addresses the connector may dial for this hop: the proxy's when one is
    /// configured (checked against the policy like any target), else the target's.
    async fn dial_checked(&self, url: &Url) -> Result<(String, Vec<IpAddr>, bool), FetchError> {
        // The target is checked first on every hop, proxy or not.
        let (host, addrs) = self.resolve_checked(url).await?;
        match &self.proxy {
            None => Ok((host, addrs, matches!(url.host(), Some(Host::Domain(_))))),
            Some(p) => {
                let (phost, paddrs) = self.resolve_host_checked(p.host.clone(), p.literal).await?;
                Ok((phost, paddrs, p.literal.is_none()))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn fetch_hop<F, Fut>(
        &self,
        url: &Url,
        method: &Method,
        headers: &HeaderMap,
        validators: Option<&Validators>,
        max_body: usize,
        follow_redirects: bool,
        capture: bool,
        dont_adjust_delay: bool,
        suppress_credentials: bool,
        suppress_validators: bool,
        rng: &mut ChaCha8Rng,
        attempts: &mut u32,
        max_retries: u32,
        check_authority: &F,
    ) -> Result<Hop, FetchError>
    where
        F: Fn() -> Fut + Sync,
        Fut: Future<Output = Result<(), FetchError>> + Send,
    {
        let origin = Origin::from_url(url);
        let mut attempt: u32 = 0;
        loop {
            // Re-resolve and re-check on every attempt: the pin is only as fresh as the check.
            let (host, addrs, by_name) = self.dial_checked(url).await?;
            let guard = by_name.then(|| self.pins.pin(&host, &addrs));
            let permit = self.governor.acquire(&origin).await?;

            let mut req_headers = self.request_headers(url, headers)?;
            if suppress_credentials {
                strip_credentials(&mut req_headers);
            }
            if let Some(v) = validators {
                v.apply(&mut req_headers);
            }
            if suppress_validators {
                req_headers.remove(header::IF_NONE_MATCH);
                req_headers.remove(header::IF_MODIFIED_SINCE);
            }
            *attempts += 1;
            let started_at = chrono::Utc::now();
            let captured_request = self
                .capture
                .as_ref()
                .filter(|_| capture)
                .map(|_| self.redact_flow_headers(capture_headers(&req_headers)));
            // Pending DNS and politeness waits must not carry stale caller authority
            // across the transport boundary, including subsequent send attempts.
            check_authority().await?;
            let request_started = tokio::time::Instant::now();
            let resp = self.client.send(method.clone(), url.clone(), req_headers).await?;

            let peer_address = resp.remote_addr();
            let peer_observed = peer_address.is_some();
            let peer = peer_address.map_or(addrs[0], |address| address.ip());
            let pinned = guard
                .as_ref()
                .map_or_else(|| addrs.contains(&peer), |g| g.contains(peer));
            if !pinned {
                return Err(FetchError::PeerNotPinned { host, peer });
            }

            let status = resp.status();
            let mut resp_headers = resp.headers().clone();
            let reserved: Vec<_> = resp_headers
                .keys()
                .filter(|name| reserved_capture_header(name.as_str()))
                .cloned()
                .collect();
            for name in reserved {
                resp_headers.remove(name);
            }
            let mut flow = captured_request.map(|request_headers| ProxyFlow {
                source: ProxyFlowSource::FetchPlane,
                method: method.to_string(),
                url: url.to_string(),
                status: Some(status.as_u16()),
                protocol: protocol_of(resp.version()),
                request_headers,
                response_headers: self.redact_flow_headers(capture_headers(&resp_headers)),
                request_body: None,
                response_body: None,
                tunnel: None,
                peer: None,
                started_at,
                finished_at: started_at,
            });
            let retry_after = parse_retry_after(&resp_headers, chrono::Utc::now());
            self.governor
                .on_response_with_latency(
                    &origin,
                    status.as_u16(),
                    retry_after,
                    Some(request_started.elapsed()),
                    dont_adjust_delay,
                )
                .await?;
            if let Some(reason) = throttle_reason(status) {
                Metrics::global()
                    .counter(names::FETCH_THROTTLES)
                    .inc_by(1, &[("reason", reason)]);
            }

            if is_retryable_status(status.as_u16())
                && attempt < max_retries
                && !(status.as_u16() == 429 && self.governor.defers_source_throttle())
            {
                if let Some(wait) = self.cfg.retry.delay(attempt, retry_after, rng) {
                    self.emit_flow(flow, None);
                    drop(resp);
                    drop(permit);
                    drop(guard);
                    attempt += 1;
                    tokio::time::sleep(wait).await;
                    continue;
                }
            }
            if follow_redirects && is_redirect(status.as_u16()) {
                self.emit_flow(flow, None);
                return Ok(Hop::Redirect {
                    status,
                    headers: resp_headers,
                });
            }
            let (body, truncated) = if method == Method::HEAD {
                (Bytes::new(), false)
            } else {
                read_capped(resp, max_body).await?
            };
            if capture {
                self.retain_response_body(url, &mut resp_headers, &body, truncated)
                    .await?;
                if let Some(flow) = &mut flow {
                    flow.response_headers.extend(
                        resp_headers
                            .iter()
                            .filter(|(name, _)| reserved_capture_header(name.as_str()))
                            .map(|(name, value)| {
                                (name.as_str().to_owned(), value.to_str().unwrap_or("").to_owned())
                            }),
                    );
                }
            }
            self.emit_flow(flow, Some(&body));
            return Ok(Hop::Final {
                status,
                headers: resp_headers,
                body,
                truncated,
                peer,
                peer_observed,
            });
        }
    }
}

fn reserved_capture_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-crawlx-capture-source")
        || name
            .as_bytes()
            .get(..16)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"x-crawlx-stream-"))
}

/// Wire form of `fetch.extraHeaders`: values are marked sensitive so no `Debug` of a request
/// prints them.
fn control_headers(controls: &RequestControls) -> Result<Vec<(HeaderName, HeaderValue)>, FetchError> {
    controls
        .headers()
        .iter()
        .map(|(name, value)| {
            let invalid = || FetchError::InvalidHeader { name: name.clone() };
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?;
            let mut header_value =
                HeaderValue::from_bytes(value.expose().as_bytes()).map_err(|_| invalid())?;
            header_value.set_sensitive(true);
            Ok((header_name, header_value))
        })
        .collect()
}

/// Bounded `outcome` label of a final response.
fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() {
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "error",
    }
}

/// `reason` label of `crawlx.fetch.throttles` for a throttling status.
fn throttle_reason(status: StatusCode) -> Option<&'static str> {
    match status {
        StatusCode::TOO_MANY_REQUESTS => Some("429"),
        StatusCode::SERVICE_UNAVAILABLE => Some("503"),
        _ => None,
    }
}

/// Count one http-plane egress denial under its rule.
fn count_egress_denial(rule: DenyRule) {
    Metrics::global()
        .counter(names::EGRESS_DENIALS)
        .inc_by(1, &[("plane", "http"), ("reason", rule.as_str())]);
}

#[cfg(test)]
mod capture_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use async_trait::async_trait;
    use crawlx_core::StoreError;

    #[derive(Debug, Default)]
    struct StoredBodies {
        bodies: Mutex<Vec<(Vec<u8>, bool)>>,
        deny: bool,
        fail: bool,
    }

    #[async_trait]
    impl ResponseBodySink for StoredBodies {
        async fn store(
            &self,
            _content_type: &str,
            body: &[u8],
            truncated: bool,
        ) -> Result<Option<ArtifactRef>, StoreError> {
            if self.fail {
                return Err(StoreError::NotFound {
                    entity: "artifact_store",
                    id: "unavailable".to_owned(),
                });
            }
            if self.deny {
                return Ok(None);
            }
            self.bodies.lock().push((body.to_vec(), truncated));
            Ok(Some(ArtifactRef {
                id: ArtifactId::new(),
                digest: Digest::of("capture-test", body),
            }))
        }
    }

    fn fetcher(mode: ResponseBodies, sink: &Arc<StoredBodies>) -> Fetcher {
        Fetcher::new(
            FetchConfig::default(),
            Arc::new(EgressPolicy::new(false)),
            Arc::new(crate::resolver::StaticResolver::new()),
        )
        .unwrap()
        .with_response_body_sink(
            mode,
            Arc::clone(sink) as Arc<dyn ResponseBodySink>,
            Url::parse("https://example.test/").unwrap(),
        )
    }

    fn page_url() -> Url {
        Url::parse("https://example.test/static").unwrap()
    }

    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers
    }

    #[tokio::test]
    async fn metadata_only_capture_never_sends_body_bytes_to_storage() {
        let sink = Arc::new(StoredBodies::default());
        let fetcher = fetcher(ResponseBodies::MetadataOnly, &sink);
        let mut headers = headers();
        fetcher
            .retain_response_body(&page_url(), &mut headers, b"not retained", false)
            .await
            .unwrap();
        assert!(sink.bodies.lock().is_empty());
        assert_eq!(headers["x-crawlx-stream-body-capture"], "metadata_only");
        assert!(headers.get("x-crawlx-stream-response-artifact-id").is_none());
    }

    #[tokio::test]
    async fn full_capture_preserves_real_artifact_refs_and_existing_fetch_body_limit() {
        let sink = Arc::new(StoredBodies::default());
        let (tx, mut rx) = mpsc::channel(8);
        let fetcher = fetcher(ResponseBodies::Full, &sink).with_capture(tx);
        let body = Bytes::from(vec![b'x'; 1024 * 1024 + 1]);
        let mut headers = headers();
        fetcher
            .retain_response_body(&page_url(), &mut headers, &body, false)
            .await
            .unwrap();
        assert_eq!(headers["x-crawlx-stream-body-capture"], "stored");
        let stored = sink.bodies.lock();
        assert_eq!(stored[0].0.as_slice(), body.as_ref());
        assert!(!stored[0].1);
        drop(stored);
        let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        fetcher.emit_flow(
            Some(ProxyFlow {
                source: ProxyFlowSource::FetchPlane,
                method: "GET".to_owned(),
                url: "https://example.test/static".to_owned(),
                status: Some(200),
                protocol: crawlx_core::traffic::Protocol::H2,
                request_headers: Vec::new(),
                response_headers: capture_headers(&headers),
                request_body: None,
                response_body: None,
                tunnel: None,
                peer: None,
                started_at: at,
                finished_at: at,
            }),
            Some(&body),
        );
        let flow = rx.try_recv().unwrap();
        let artifact_digest = flow
            .response_headers
            .iter()
            .find_map(|(name, value)| (name == "x-crawlx-stream-response-artifact-digest").then_some(value))
            .unwrap();
        assert_eq!(
            Digest::from_hex(artifact_digest).unwrap(),
            Digest::of("capture-test", &body)
        );
        assert_eq!(
            flow.response_body.unwrap().len,
            u64::try_from(body.len()).unwrap()
        );
    }

    #[tokio::test]
    async fn text_capped_capture_stores_only_utf8_prefix_and_records_truncation() {
        let sink = Arc::new(StoredBodies::default());
        let fetcher = fetcher(ResponseBodies::TextCapped, &sink);
        let mut body = vec![b'x'; 64 * 1024 - 1];
        body.extend_from_slice("€".as_bytes());
        body.extend_from_slice(b"not retained");
        let mut headers = headers();
        fetcher
            .retain_response_body(&page_url(), &mut headers, &body, false)
            .await
            .unwrap();
        let stored = sink.bodies.lock();
        assert_eq!(stored[0].0.len(), 64 * 1024 - 1);
        assert!(std::str::from_utf8(&stored[0].0).is_ok());
        assert!(stored[0].1);
        assert_eq!(headers["x-crawlx-stream-body-capture"], "stored_prefix");
        assert_eq!(headers["x-crawlx-stream-body-truncated"], "true");
        assert_eq!(headers["x-crawlx-stream-body-limit"], "65536");
    }

    #[tokio::test]
    async fn incomplete_full_body_and_policy_storage_refusals_remain_explicit() {
        let sink = Arc::new(StoredBodies::default());
        let full = fetcher(ResponseBodies::Full, &sink);
        let mut truncated = headers();
        full.retain_response_body(&page_url(), &mut truncated, b"partial", true)
            .await
            .unwrap();
        assert_eq!(truncated["x-crawlx-stream-body-capture"], "oversized");
        assert!(sink.bodies.lock().is_empty());
        for (deny, fail, outcome) in [(true, false, "policy_denied"), (false, true, "storage_error")] {
            let sink = Arc::new(StoredBodies {
                deny,
                fail,
                ..StoredBodies::default()
            });
            let fetcher = fetcher(ResponseBodies::TextCapped, &sink);
            let mut headers = headers();
            fetcher
                .retain_response_body(&page_url(), &mut headers, b"public text", false)
                .await
                .unwrap();
            assert_eq!(headers["x-crawlx-stream-body-capture"], outcome);
            assert!(headers.get("x-crawlx-stream-response-artifact-id").is_none());
        }
    }

    #[test]
    fn wire_headers_cannot_claim_reserved_capture_metadata() {
        assert!(reserved_capture_header("X-Crawlx-Stream-Response-Artifact-Id"));
        assert!(reserved_capture_header("X-Crawlx-Capture-Source"));
        assert!(!reserved_capture_header("content-type"));
        assert!(!reserved_capture_header("x-application-field"));
    }

    #[tokio::test]
    async fn auth_routes_and_set_cookie_are_denied_before_every_retained_mode_reaches_sink() {
        for mode in [ResponseBodies::Full, ResponseBodies::TextCapped] {
            let sink = Arc::new(StoredBodies::default());
            let fetcher = fetcher(mode, &sink);
            for path in [
                "/api/login/result",
                "/logout",
                "/signIn/finish",
                "/oauth/callback",
                "/api/token",
                "/api/session",
                "/v1/LOGIN/status",
            ] {
                let url = Url::parse(&format!("https://example.test{path}")).unwrap();
                let mut headers = headers();
                fetcher
                    .retain_response_body(&url, &mut headers, b"public content", false)
                    .await
                    .unwrap();
                assert_eq!(headers["x-crawlx-stream-body-capture"], "policy_denied");
                assert!(headers.get("x-crawlx-stream-response-artifact-id").is_none());
            }
            let mut headers = headers();
            headers.insert(header::SET_COOKIE, HeaderValue::from_static("sid=canary-session"));
            fetcher
                .retain_response_body(&page_url(), &mut headers, b"public content", false)
                .await
                .unwrap();
            assert_eq!(headers["x-crawlx-stream-body-capture"], "policy_denied");
            assert!(sink.bodies.lock().is_empty());
        }
    }

    #[tokio::test]
    async fn final_third_party_origins_are_denied_before_full_or_prefix_storage() {
        for mode in [ResponseBodies::Full, ResponseBodies::TextCapped] {
            let sink = Arc::new(StoredBodies::default());
            let fetcher = fetcher(mode, &sink);
            for target in [
                "https://cdn.test/static",
                "http://example.test/static",
                "https://example.test:8443/static",
            ] {
                let mut headers = headers();
                fetcher
                    .retain_response_body(
                        &Url::parse(target).unwrap(),
                        &mut headers,
                        b"public content",
                        false,
                    )
                    .await
                    .unwrap();
                assert_eq!(headers["x-crawlx-stream-body-capture"], "policy_denied");
                assert!(headers.get("x-crawlx-stream-response-artifact-id").is_none());
            }
            assert!(sink.bodies.lock().is_empty());
            let mut headers = headers();
            fetcher
                .retain_response_body(
                    &Url::parse("https://example.test:443/static").unwrap(),
                    &mut headers,
                    b"public content",
                    false,
                )
                .await
                .unwrap();
            assert_eq!(
                sink.bodies.lock().len(),
                1,
                "the default HTTPS port is the same origin"
            );
        }
    }

    #[tokio::test]
    async fn text_capped_requires_json_or_html_mime_while_full_keeps_text_policy() {
        let sink = Arc::new(StoredBodies::default());
        let prefix = fetcher(ResponseBodies::TextCapped, &sink);
        for mime in [
            "text/plain",
            "application/javascript",
            "image/svg+xml",
            "application/xml",
            "application/octet-stream",
            "text/json",
            "",
        ] {
            let mut headers = headers();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(mime).unwrap());
            prefix
                .retain_response_body(&page_url(), &mut headers, br#"{"value":"public"}"#, false)
                .await
                .unwrap();
            assert_eq!(headers["x-crawlx-stream-body-capture"], "policy_denied");
        }
        assert!(sink.bodies.lock().is_empty());
        for mime in [
            "application/json",
            "text/html; charset=utf-8",
            "application/problem+json",
            "Application/LD+JSON; charset=UTF-8",
        ] {
            let mut headers = headers();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(mime).unwrap());
            prefix
                .retain_response_body(&page_url(), &mut headers, br#"{"value":"public"}"#, false)
                .await
                .unwrap();
            assert_eq!(headers["x-crawlx-stream-body-capture"], "stored_prefix");
        }
        assert_eq!(sink.bodies.lock().len(), 4);
        let full = fetcher(ResponseBodies::Full, &sink);
        let mut headers = headers();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        full.retain_response_body(&page_url(), &mut headers, b"public text", false)
            .await
            .unwrap();
        assert_eq!(headers["x-crawlx-stream-body-capture"], "stored");
        assert_eq!(sink.bodies.lock().len(), 5);
    }
}
