//! Loopback egress proxy for the browser plane.
//!
//! Chromium is pointed at this proxy and resolves nothing itself. For every
//! request the proxy applies the egress policy to the host name and to *all*
//! resolved addresses, then connects to a checked address (resolve once, no
//! second lookup). Denied targets get `403` with `X-Crawlx-Egress-Denied`.
//! `CONNECT` tunnels are plain byte pipes: TLS stays end-to-end, nothing is
//! intercepted. Absolute-URI `http://` requests are forwarded over a fresh
//! connection to the pinned address: HTTP/1.1 upstream for an HTTP/1.x client,
//! HTTP/2 with prior knowledge upstream when the client itself spoke HTTP/2
//! (the listener accepts both).
//! Visible HTTP requests retain the authorization record's exact origins, prefixes and excluded
//! paths. Opaque CONNECT tunnels check the exact HTTPS origin and port; encrypted paths still
//! require the browser's full navigation scope guard and are not inspected by this proxy.
//!
//! With [`EgressProxy::serve_with_capture`] every forwarded request and every
//! tunnel produces exactly one [`ProxyFlow`] (the proxy capture backend). Credential
//! header values are replaced in this task before the flow enters the channel;
//! the flow is `try_send`-ed so the data path never blocks, and a
//! full channel drops the flow and counts it.

use crate::error::FetchError;
use crate::governor::{GlobalOriginCap, Origin, PhysicalPermit};
use crate::resolver::{parse_ip_literal, CheckedResolution, Resolver};
use crate::upstream::{BoxIo, UpstreamProxy};
use bytes::Bytes;
use crawlx_core::request_controls::RequestControls;
use crawlx_core::time::{Clock, SystemClock, Timestamp};
use crawlx_core::traffic::{
    BodyDigest, Protocol, ProxyFlow, ProxyFlowSource, TunnelStats, BODY_DIGEST_PREFIX, PROXY_DENIED_HEADERS,
    REDACTED_PLACEHOLDER,
};
use crawlx_policy::egress::EgressPolicy;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use http::{header, HeaderMap, HeaderName, Method, StatusCode, Version};
#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
use http::{Request, Response};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
use hyper::body::Incoming;
use hyper::body::{Body, Frame, SizeHint};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use std::collections::{BTreeSet, VecDeque};
use std::convert::Infallible;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Response header naming the deny rule.
pub const DENIED_HEADER: &str = "x-crawlx-egress-denied";
/// Response header on the proxy's own `502` answers for a failed upstream connect or exchange.
/// Never forwarded from an origin: the proxy removes it from origin responses.
pub const PROXY_ERROR_HEADER: &str = "x-crawlx-proxy-error";

/// Denial log is bounded; the counter is not.
const MAX_LOGGED_DENIALS: usize = 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Retain physical capacity through response completion, error or early drop,
/// independently of whether flow capture is enabled.
struct AdmittedBody {
    #[allow(
        clippy::disallowed_types,
        reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
    )]
    inner: ProxyBody,
    physical: Option<PhysicalPermit>,
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
impl Body for AdmittedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None | Some(Err(_)))) {
            self.physical = None;
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// One refused request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeniedEvent {
    /// When the request was refused.
    pub at: Timestamp,
    /// `CONNECT` or the HTTP method of a forwarded request.
    pub method: String,
    /// Target host name or IP literal, lowercased, without brackets.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// The offending address when the denial came from a resolved address.
    pub ip: Option<IpAddr>,
    /// `DenyRule::as_str()` of the policy rule.
    pub rule: String,
}

/// Flow capture: a bounded channel plus the count of flows it refused.
struct Capture {
    tx: mpsc::Sender<ProxyFlow>,
    dropped: AtomicU64,
}

impl Capture {
    fn send(&self, flow: ProxyFlow) {
        if self.tx.try_send(flow).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct Shared {
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolver>,
    denials: AtomicU64,
    events: Mutex<VecDeque<DeniedEvent>>,
    /// Every `(host, port)` the policy admitted (the egress capture).
    dialed: Mutex<BTreeSet<(String, u16)>>,
    capture: Option<Capture>,
    /// Configured headers and cookies: masked in every captured flow, whatever header carries them.
    controls: RequestControls,
    /// The operator's proxy every admitted request is chained to (`fetch.proxy`).
    upstream: Option<UpstreamProxy>,
    cancel: CancellationToken,
    physical_cap: Option<Arc<GlobalOriginCap>>,
}

/// Protocol of a request as hyper reports its version.
pub(crate) const fn protocol_of(v: Version) -> Protocol {
    if matches!(v, Version::HTTP_2) {
        Protocol::H2
    } else {
        Protocol::Http11
    }
}

/// Headers in wire order; credential values replaced by [`REDACTED_PLACEHOLDER`] so no
/// secret enters the capture channel.
#[must_use]
pub fn capture_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let name = name.as_str().to_owned();
            let value = if PROXY_DENIED_HEADERS.contains(&name.as_str()) {
                REDACTED_PLACEHOLDER.to_owned()
            } else {
                String::from_utf8_lossy(value.as_bytes()).into_owned()
            };
            (name, value)
        })
        .collect()
}

/// Flow under construction, shared by the request- and response-body observers.
struct FlowBuilder {
    flow: ProxyFlow,
    req_prefix: Vec<u8>,
    req_len: u64,
    resp_prefix: Vec<u8>,
    resp_len: u64,
    sent: bool,
}

impl FlowBuilder {
    fn new(flow: ProxyFlow) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            flow,
            req_prefix: Vec::new(),
            req_len: 0,
            resp_prefix: Vec::new(),
            resp_len: 0,
            sent: false,
        }))
    }

    fn observe(&mut self, side: Side, data: &[u8]) {
        let (prefix, len) = match side {
            Side::Request => (&mut self.req_prefix, &mut self.req_len),
            Side::Response => (&mut self.resp_prefix, &mut self.resp_len),
        };
        *len = len.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        let room = BODY_DIGEST_PREFIX.saturating_sub(prefix.len());
        prefix.extend_from_slice(&data[..data.len().min(room)]);
    }

    /// Complete the flow and hand it to the capture channel; idempotent.
    fn finish(&mut self, capture: &Capture) {
        if self.sent {
            return;
        }
        self.sent = true;
        let mut flow = self.flow.clone();
        flow.request_body = (self.req_len > 0).then(|| BodyDigest::of_prefix(&self.req_prefix, self.req_len));
        flow.response_body =
            (self.resp_len > 0).then(|| BodyDigest::of_prefix(&self.resp_prefix, self.resp_len));
        flow.finished_at = SystemClock.now();
        capture.send(flow);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Request,
    Response,
}

/// Body pass-through that hashes the first [`BODY_DIGEST_PREFIX`] bytes and, on the
/// response side, finishes the flow when the stream ends or the body is dropped.
struct CapturedBody<B> {
    inner: Pin<Box<B>>,
    builder: Arc<Mutex<FlowBuilder>>,
    capture: Arc<Shared>,
    side: Side,
}

impl<B> CapturedBody<B> {
    fn new(inner: B, builder: Arc<Mutex<FlowBuilder>>, capture: Arc<Shared>, side: Side) -> Self {
        Self {
            inner: Box::pin(inner),
            builder,
            capture,
            side,
        }
    }

    fn finish(&self) {
        if let Some(c) = &self.capture.capture {
            self.builder.lock().finish(c);
        }
    }
}

impl<B> Body for CapturedBody<B>
where
    B: Body<Data = Bytes>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = self.inner.as_mut().poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.builder.lock().observe(self.side, data);
                }
            }
            Poll::Ready(None | Some(Err(_))) => {
                if self.side == Side::Response {
                    self.finish();
                }
            }
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl<B> Drop for CapturedBody<B> {
    fn drop(&mut self) {
        if self.side == Side::Response {
            self.finish();
        }
    }
}

/// Skeleton of a flow for a request that just arrived; configured header and cookie values
/// are masked ([`RequestControls::mask_headers`]).
#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
fn flow_for(
    req: &Request<Incoming>,
    url: String,
    peer: SocketAddr,
    started_at: Timestamp,
    controls: &RequestControls,
) -> ProxyFlow {
    let mut request_headers = capture_headers(req.headers());
    controls.mask_headers(&mut request_headers);
    ProxyFlow {
        source: ProxyFlowSource::Browser,
        method: req.method().to_string(),
        url,
        status: None,
        protocol: protocol_of(req.version()),
        request_headers,
        response_headers: Vec::new(),
        request_body: None,
        response_body: None,
        tunnel: None,
        peer: Some(peer),
        started_at,
        finished_at: started_at,
    }
}

/// Why a target was not admitted.
enum Reject {
    Denied { rule: String },
    Unresolvable(String),
}

impl Shared {
    fn record_denial(&self, method: &str, host: &str, port: u16, ip: Option<IpAddr>, rule: &str) {
        self.denials.fetch_add(1, Ordering::Relaxed);
        Metrics::global()
            .counter(names::EGRESS_DENIALS)
            .inc_by(1, &[("plane", "browser"), ("reason", rule)]);
        tracing::warn!(%host, port, rule, method, "egress denied (browser plane)");
        let mut ev = self.events.lock();
        if ev.len() >= MAX_LOGGED_DENIALS {
            ev.pop_front();
        }
        ev.push_back(DeniedEvent {
            at: SystemClock.now(),
            method: method.to_owned(),
            host: host.to_owned(),
            port,
            ip,
            rule: rule.to_owned(),
        });
    }

    /// Host check, resolve, check every address. Returns the checked addresses; nothing is
    /// recorded as dialed (the upstream proxy's own host goes through here too).
    async fn vet(
        &self,
        method: &str,
        host: &str,
        port: u16,
    ) -> Result<(Vec<SocketAddr>, CheckedResolution), Reject> {
        if self.policy.fixture_scope.is_some() {
            if let Err(denied) = self.policy.check_port(port) {
                self.record_denial(method, host, port, parse_ip_literal(host), denied.rule.as_str());
                return Err(Reject::Denied {
                    rule: denied.rule.as_str().to_owned(),
                });
            }
        }
        let target = CheckedResolution::resolve_host(
            self.resolver.as_ref(),
            &self.policy,
            Origin::new(&format!("https://{host}:{port}")),
            host.to_owned(),
            parse_ip_literal(host),
        )
        .await
        .map_err(|error| match error {
            FetchError::EgressDenied(denied) => {
                let ip = denied.subject.parse().ok();
                self.record_denial(method, host, port, ip, denied.rule.as_str());
                Reject::Denied {
                    rule: denied.rule.as_str().to_owned(),
                }
            }
            other => Reject::Unresolvable(other.to_string()),
        })?;
        let addrs = target
            .addresses()
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        Ok((addrs, target))
    }

    /// [`Self::vet`] a target and record it as dialed.
    async fn authorize(
        &self,
        method: &str,
        host: &str,
        port: u16,
    ) -> Result<(Vec<SocketAddr>, Option<PhysicalPermit>), Reject> {
        let (addrs, target) = self.vet(method, host, port).await?;
        let physical = match &self.physical_cap {
            Some(cap) => {
                tokio::select! {
                    () = self.cancel.cancelled() => {
                        return Err(Reject::Unresolvable("proxy stopped during target admission".to_owned()));
                    }
                    permit = cap.acquire_physical(&target) => Some(permit),
                }
            }
            None => None,
        };
        self.dialed.lock().insert((host.to_owned(), port));
        Ok((addrs, physical))
    }

    /// The checked addresses of the upstream proxy `up` (its host is held to the egress
    /// policy like any target).
    async fn vet_upstream(&self, method: &str, up: &UpstreamProxy) -> Result<Vec<SocketAddr>, Refusal> {
        self.vet(method, up.host(), up.port())
            .await
            .map(|(addrs, _)| addrs)
            .map_err(|r| {
                tracing::warn!(
                    proxy = up.host(),
                    "the upstream proxy host is refused by the egress policy"
                );
                Box::new(reject_response(&r))
            })
    }

    /// A byte pipe to the admitted target `host:port`: direct to one of its pinned `addrs`, or
    /// through the upstream proxy (`CONNECT` / SOCKS5).
    async fn open_tunnel(
        &self,
        method: &str,
        host: &str,
        port: u16,
        addrs: &[SocketAddr],
    ) -> Result<BoxIo, Refusal> {
        let Some(up) = &self.upstream else {
            return match connect_any(addrs).await {
                Ok(stream) => {
                    let peer = stream.peer_addr().map_err(|error| {
                        Box::new(upstream_failure(&format!(
                            "cannot inspect upstream peer: {error}\n"
                        )))
                    })?;
                    if !addrs.contains(&peer) {
                        return Err(Box::new(upstream_failure("upstream peer was not pinned\n")));
                    }
                    if let Err(denied) = self.policy.check_all(host, &[peer.ip()]) {
                        self.record_denial(method, host, port, Some(peer.ip()), denied.rule.as_str());
                        return Err(Box::new(reject_response(&Reject::Denied {
                            rule: denied.rule.as_str().to_owned(),
                        })));
                    }
                    Ok(Box::new(stream))
                }
                Err(e) => Err(Box::new(upstream_failure(&format!(
                    "upstream connect failed: {e}\n"
                )))),
            };
        };
        let proxy_addrs = self.vet_upstream(method, up).await?;
        up.tunnel(&proxy_addrs, host, port, addrs)
            .await
            .map_err(|e| Box::new(upstream_failure(&format!("upstream proxy failed: {e}\n"))))
    }

    /// A connection for forwarding one plain-HTTP request to the admitted target. The flag is
    /// `true` when it leads to an HTTP(S) upstream proxy, which takes the request in absolute
    /// form with `Proxy-Authorization`; otherwise the request goes out in origin form.
    async fn open_forward(
        &self,
        method: &str,
        host: &str,
        port: u16,
        addrs: &[SocketAddr],
    ) -> Result<(BoxIo, bool), Refusal> {
        match &self.upstream {
            Some(up) if up.speaks_http() => {
                let proxy_addrs = self.vet_upstream(method, up).await?;
                let io = up
                    .connect_for_forward(&proxy_addrs)
                    .await
                    .map_err(|e| Box::new(upstream_failure(&format!("upstream proxy failed: {e}\n"))))?;
                Ok((io, true))
            }
            _ => Ok((self.open_tunnel(method, host, port, addrs).await?, false)),
        }
    }
}

/// An answer of the proxy itself for a failed upstream connect, handshake or exchange. It is
/// marked with [`PROXY_ERROR_HEADER`] so a client that routes through this proxy can tell it
/// from a `502` the origin sent.
#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
fn upstream_failure(msg: &str) -> Response<ProxyBody> {
    let mut resp = text_response(StatusCode::BAD_GATEWAY, msg);
    resp.headers_mut().insert(
        HeaderName::from_static(PROXY_ERROR_HEADER),
        header::HeaderValue::from_static("upstream"),
    );
    resp
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
fn text_response(status: StatusCode, msg: &str) -> Response<ProxyBody> {
    let body = Full::new(Bytes::from(msg.to_owned()))
        .map_err(|never| match never {})
        .boxed();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
fn reject_response(r: &Reject) -> Response<ProxyBody> {
    match r {
        Reject::Denied { rule } => {
            let mut resp = text_response(StatusCode::FORBIDDEN, &format!("egress denied: {rule}\n"));
            if let Ok(v) = header::HeaderValue::from_str(rule) {
                resp.headers_mut()
                    .insert(HeaderName::from_static(DENIED_HEADER), v);
            }
            resp
        }
        Reject::Unresolvable(why) => text_response(
            StatusCode::BAD_GATEWAY,
            &format!("cannot resolve target: {why}\n"),
        ),
    }
}

/// An answer the proxy gives instead of forwarding (boxed: it is the `Err` of the dial helpers).
#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
type Refusal = Box<Response<ProxyBody>>;

/// Connect to the first reachable pinned address.
pub(crate) async fn connect_any(addrs: &[SocketAddr]) -> Result<TcpStream, String> {
    let mut last = "no address".to_owned();
    for a in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                // Nagle only adds latency to a pass-through pipe.
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = format!("{a}: {e}"),
            Err(_) => last = format!("{a}: connect timed out"),
        }
    }
    Err(last)
}

fn strip_brackets(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for n in named {
        headers.remove(n);
    }
    for n in HOP_BY_HOP {
        headers.remove(n);
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
async fn handle(
    shared: Arc<Shared>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<ProxyBody>, Infallible> {
    Ok(if req.method() == Method::CONNECT {
        handle_connect(&shared, peer, req).await
    } else {
        handle_forward(&shared, peer, req).await
    })
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
async fn handle_connect(
    shared: &Arc<Shared>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    if shared.policy.fixture_scope.is_some() {
        let authority = req.uri().authority();
        let host = authority
            .map(|value| strip_brackets(value.host()).to_ascii_lowercase())
            .unwrap_or_default();
        let port = authority
            .map(|value| value.port_u16().unwrap_or(443))
            .unwrap_or(0);
        shared.record_denial(
            "CONNECT",
            &host,
            port,
            parse_ip_literal(&host),
            "authorization_scope",
        );
        return text_response(
            StatusCode::FORBIDDEN,
            "fixture evaluation does not permit CONNECT tunnels\n",
        );
    }
    let started_at = SystemClock.now();
    let Some(authority) = req.uri().authority().cloned() else {
        return text_response(StatusCode::BAD_REQUEST, "CONNECT requires host:port\n");
    };
    let host = strip_brackets(authority.host()).to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(443);
    let target = match url::Url::parse(&format!("https://{authority}/")) {
        Ok(target) => target,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid CONNECT authority\n"),
    };
    if let Err(denied) = shared.policy.check_connect_authority(&target) {
        shared.record_denial(
            "CONNECT",
            &host,
            port,
            parse_ip_literal(&host),
            denied.rule.as_str(),
        );
        return reject_response(&Reject::Denied {
            rule: denied.rule.as_str().to_owned(),
        });
    }
    let (addrs, physical) = match shared.authorize("CONNECT", &host, port).await {
        Ok(a) => a,
        Err(r) => return reject_response(&r),
    };
    let mut upstream = match shared.open_tunnel("CONNECT", &host, port, &addrs).await {
        Ok(io) => io,
        Err(refusal) => return *refusal,
    };
    let mut flow = shared.capture.as_ref().map(|_| {
        flow_for(
            &req,
            authority.as_str().to_owned(),
            peer,
            started_at,
            &shared.controls,
        )
    });
    if let Some(f) = flow.as_mut() {
        // a tunnel is opaque: no status, no headers, only its byte counts
        f.request_headers.clear();
    }
    let upgrade = hyper::upgrade::on(req);
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        let _physical = physical;
        let mut stats = TunnelStats::default();
        match upgrade.await {
            Ok(up) => {
                let mut client = TokioIo::new(up);
                tokio::select! {
                    () = shared.cancel.cancelled() => {}
                    r = tokio::io::copy_bidirectional(&mut client, &mut upstream) => match r {
                        Ok((up, down)) => stats = TunnelStats { bytes_up: up, bytes_down: down },
                        Err(e) => tracing::debug!(error = %e, "connect tunnel ended with error"),
                    }
                }
            }
            Err(e) => tracing::debug!(error = %e, "connect upgrade failed"),
        }
        if let (Some(c), Some(mut f)) = (&shared.capture, flow) {
            f.tunnel = Some(stats);
            f.finished_at = SystemClock.now();
            c.send(f);
        }
    });
    Response::new(Full::new(Bytes::new()).map_err(|never| match never {}).boxed())
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
type UpstreamBody = BoxBody<Bytes, hyper::Error>;

/// Drive an upstream connection until it ends or the proxy shuts down.
#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
fn spawn_conn(cancel: CancellationToken, conn: impl Future<Output = hyper::Result<()>> + Send + 'static) {
    tokio::spawn(async move {
        tokio::select! {
            () = cancel.cancelled() => {}
            r = conn => {
                if let Err(e) = r {
                    tracing::debug!(error = %e, "upstream connection ended with error");
                }
            }
        }
    });
}

/// One request over a fresh upstream connection: HTTP/2 with prior knowledge when the
/// client spoke HTTP/2, HTTP/1.1 otherwise.
#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
async fn send_upstream(
    shared: &Arc<Shared>,
    upstream: BoxIo,
    out: Request<UpstreamBody>,
) -> Result<Response<Incoming>, String> {
    let io = TokioIo::new(upstream);
    if out.version() == Version::HTTP_2 {
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .map_err(|e| format!("upstream handshake failed: {e}"))?;
        spawn_conn(shared.cancel.clone(), conn);
        sender
            .send_request(out)
            .await
            .map_err(|e| format!("upstream request failed: {e}"))
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|e| format!("upstream handshake failed: {e}"))?;
        spawn_conn(shared.cancel.clone(), conn);
        sender
            .send_request(out)
            .await
            .map_err(|e| format!("upstream request failed: {e}"))
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
async fn handle_forward(
    shared: &Arc<Shared>,
    peer: SocketAddr,
    req: Request<Incoming>,
) -> Response<ProxyBody> {
    let started_at = SystemClock.now();
    let method_name = req.method().to_string();
    let uri = req.uri().clone();
    let (Some("http"), Some(authority)) = (uri.scheme_str(), uri.authority()) else {
        return text_response(
            StatusCode::BAD_REQUEST,
            "proxy accepts absolute-form http:// requests and CONNECT only\n",
        );
    };
    let host = strip_brackets(authority.host()).to_ascii_lowercase();
    let port = authority.port_u16().unwrap_or(80);
    let url = match url::Url::parse(&uri.to_string()) {
        Ok(url) => url,
        Err(_) => return text_response(StatusCode::BAD_REQUEST, "invalid resource URL\n"),
    };
    if let Err(denied) = shared.policy.check_url(&url) {
        shared.record_denial(
            &method_name,
            &host,
            port,
            parse_ip_literal(&host),
            denied.rule.as_str(),
        );
        return reject_response(&Reject::Denied {
            rule: denied.rule.as_str().to_owned(),
        });
    }
    let (addrs, physical) = match shared.authorize(&method_name, &host, port).await {
        Ok(a) => a,
        Err(r) => return reject_response(&r),
    };
    let (upstream, via_http_proxy) = match shared.open_forward(&method_name, &host, port, &addrs).await {
        Ok(opened) => opened,
        Err(refusal) => return *refusal,
    };

    let builder = shared.capture.as_ref().map(|_| {
        FlowBuilder::new(flow_for(
            &req,
            uri.to_string(),
            peer,
            started_at,
            &shared.controls,
        ))
    });
    // an HTTP(S) upstream proxy is spoken to in HTTP/1.1 absolute form, whatever the client spoke
    let h2 = req.version() == Version::HTTP_2 && !via_http_proxy;
    let (mut parts, body) = req.into_parts();
    strip_hop_by_hop(&mut parts.headers);
    if h2 {
        // prior-knowledge h2 upstream: absolute URI carries `:scheme`/`:authority`
        parts.uri = uri.clone();
        parts.version = Version::HTTP_2;
        parts.headers.remove(header::HOST);
    } else if via_http_proxy {
        // the upstream proxy takes the request as the browser sent it, plus its own credentials
        parts.uri = uri.clone();
        parts.version = Version::HTTP_11;
        if !parts.headers.contains_key(header::HOST) {
            if let Ok(v) = header::HeaderValue::from_str(authority.as_str()) {
                parts.headers.insert(header::HOST, v);
            }
        }
        if let Some(auth) = shared.upstream.as_ref().and_then(UpstreamProxy::authorization) {
            parts.headers.insert(header::PROXY_AUTHORIZATION, auth.clone());
        }
        parts
            .headers
            .insert(header::CONNECTION, header::HeaderValue::from_static("close"));
    } else {
        let path = uri.path_and_query().map_or("/", http::uri::PathAndQuery::as_str);
        let Ok(origin_form) = path.parse::<http::Uri>() else {
            return text_response(StatusCode::BAD_REQUEST, "invalid request target\n");
        };
        parts.uri = origin_form;
        parts.version = Version::HTTP_11;
        if !parts.headers.contains_key(header::HOST) {
            if let Ok(v) = header::HeaderValue::from_str(authority.as_str()) {
                parts.headers.insert(header::HOST, v);
            }
        }
        parts
            .headers
            .insert(header::CONNECTION, header::HeaderValue::from_static("close"));
    }
    let body: UpstreamBody = match &builder {
        Some(b) => CapturedBody::new(body, Arc::clone(b), Arc::clone(shared), Side::Request).boxed(),
        None => body.boxed(),
    };
    let out = Request::from_parts(parts, body);

    match send_upstream(shared, upstream, out).await {
        Ok(resp) => {
            let (mut p, b) = resp.into_parts();
            let b: ProxyBody = match builder {
                Some(builder) => {
                    {
                        let mut fb = builder.lock();
                        fb.flow.status = Some(p.status.as_u16());
                        let mut headers = capture_headers(&p.headers);
                        shared.controls.mask_headers(&mut headers);
                        fb.flow.response_headers = headers;
                    }
                    CapturedBody::new(b, builder, Arc::clone(shared), Side::Response).boxed()
                }
                None => b.boxed(),
            };
            strip_hop_by_hop(&mut p.headers);
            // only this proxy may say it failed: never pass the marker on from an origin
            p.headers.remove(PROXY_ERROR_HEADER);
            let b = AdmittedBody { inner: b, physical }.boxed();
            Response::from_parts(p, b)
        }
        Err(e) => {
            if let (Some(c), Some(b)) = (&shared.capture, builder) {
                b.lock().finish(c);
            }
            upstream_failure(&format!("{e}\n"))
        }
    }
}

/// Optional parts of an [`EgressProxy`]: flow capture, request controls and an upstream proxy.
#[derive(Debug)]
#[must_use]
pub struct EgressOptions {
    capture: Option<mpsc::Sender<ProxyFlow>>,
    controls: RequestControls,
    upstream: Option<UpstreamProxy>,
    physical_cap: Option<Arc<GlobalOriginCap>>,
}

impl Default for EgressOptions {
    fn default() -> Self {
        Self {
            capture: None,
            controls: RequestControls::default(),
            upstream: None,
            physical_cap: Some(Arc::new(GlobalOriginCap::default())),
        }
    }
}

impl EgressOptions {
    /// No capture, no request controls, no upstream proxy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Share physical-target capacity with HTTP and every browser proxy in the process.
    pub fn with_global_cap(mut self, cap: Arc<GlobalOriginCap>) -> Self {
        self.physical_cap = Some(cap);
        self
    }

    /// HTTP-owned adapters already retain their caller's checked physical permit.
    pub(crate) fn http_adapter() -> Self {
        Self {
            capture: None,
            controls: RequestControls::default(),
            upstream: None,
            physical_cap: None,
        }
    }

    /// Report every flow on `capture` (see [`EgressProxy::serve_with_capture`]).
    pub fn with_capture(mut self, capture: mpsc::Sender<ProxyFlow>) -> Self {
        self.capture = Some(capture);
        self
    }

    /// Mask the configured headers and cookies in captured flows (see
    /// [`EgressProxy::serve_with_capture_and_controls`]).
    pub fn with_controls(mut self, controls: RequestControls) -> Self {
        self.controls = controls;
        self
    }

    /// Chain every admitted request to `upstream` (`fetch.proxy`). The egress policy still
    /// judges the target first and the proxy host after it; see [`crate::upstream`].
    pub fn with_upstream(mut self, upstream: UpstreamProxy) -> Self {
        self.upstream = Some(upstream);
        self
    }
}

/// Entry point: `EgressProxy::serve(policy, resolver)` or
/// [`EgressProxy::serve_with_capture`].
#[derive(Debug)]
pub struct EgressProxy;

impl EgressProxy {
    /// Bind `127.0.0.1:0` and serve until the handle is shut down or dropped.
    ///
    /// # Errors
    /// [`FetchError::Io`] when the loopback listener cannot be bound.
    pub async fn serve(
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
    ) -> Result<EgressProxyHandle, FetchError> {
        Self::start(policy, resolver, EgressOptions::new()).await
    }

    /// [`Self::serve`] with flow capture (the proxy capture backend): one [`ProxyFlow`] per
    /// forwarded request and per `CONNECT` tunnel is `try_send`-ed on `capture`; when the
    /// channel is full the flow is dropped and [`EgressProxyHandle::capture_dropped`] grows.
    ///
    /// # Errors
    /// [`FetchError::Io`] when the loopback listener cannot be bound.
    pub async fn serve_with_capture(
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
        capture: mpsc::Sender<ProxyFlow>,
    ) -> Result<EgressProxyHandle, FetchError> {
        Self::start(policy, resolver, EgressOptions::new().with_capture(capture)).await
    }

    /// [`Self::serve_with_capture`] for a run with request controls: every configured
    /// header and cookie value, and every header that echoes one, is replaced by
    /// `[redacted]` in the captured flows ([`RequestControls::mask_headers`]). Forwarded
    /// traffic itself is untouched.
    ///
    /// # Errors
    /// [`FetchError::Io`] when the loopback listener cannot be bound.
    pub async fn serve_with_capture_and_controls(
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
        capture: mpsc::Sender<ProxyFlow>,
        controls: RequestControls,
    ) -> Result<EgressProxyHandle, FetchError> {
        Self::start(
            policy,
            resolver,
            EgressOptions::new().with_capture(capture).with_controls(controls),
        )
        .await
    }

    /// [`Self::serve`] with every optional part of [`EgressOptions`]: flow capture, request
    /// controls and the upstream proxy the admitted requests are chained to.
    ///
    /// # Errors
    /// [`FetchError::Io`] when the loopback listener cannot be bound.
    pub async fn serve_with(
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
        options: EgressOptions,
    ) -> Result<EgressProxyHandle, FetchError> {
        Self::start(policy, resolver, options).await
    }

    /// [`Self::serve_with`] for a caller that is not `async` but runs inside a tokio runtime:
    /// the loopback listener is bound synchronously. Used by a [`crate::Fetcher`] that owns its
    /// adapter for the whole run.
    ///
    /// # Errors
    /// [`FetchError::Io`] when no tokio runtime is running or the loopback listener cannot be
    /// bound.
    pub fn serve_in_runtime(
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
        options: EgressOptions,
    ) -> Result<EgressProxyHandle, FetchError> {
        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|e| FetchError::Io(std::io::Error::other(e.to_string())))?;
        let std_listener = std::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        std_listener.set_nonblocking(true)?;
        let _entered = runtime.enter();
        let listener = TcpListener::from_std(std_listener)?;
        Self::launch(listener, policy, resolver, options)
    }

    async fn start(
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
        options: EgressOptions,
    ) -> Result<EgressProxyHandle, FetchError> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
        Self::launch(listener, policy, resolver, options)
    }

    /// Start serving on a bound listener; must run inside a tokio runtime.
    fn launch(
        listener: TcpListener,
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
        options: EgressOptions,
    ) -> Result<EgressProxyHandle, FetchError> {
        let EgressOptions {
            capture,
            controls,
            upstream,
            physical_cap,
        } = options;
        let addr = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let shared = Arc::new(Shared {
            policy,
            resolver,
            denials: AtomicU64::new(0),
            events: Mutex::new(VecDeque::new()),
            dialed: Mutex::new(BTreeSet::new()),
            capture: capture.map(|tx| Capture {
                tx,
                dropped: AtomicU64::new(0),
            }),
            controls,
            upstream,
            physical_cap,
            cancel: cancel.clone(),
        });
        let task = tokio::spawn(accept_loop(listener, Arc::clone(&shared)));
        Ok(EgressProxyHandle { addr, shared, task })
    }
}

#[allow(
    clippy::disallowed_types,
    reason = "reviewed policy-pinned proxy transport owns raw messages and translates bounded domain results"
)]
async fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        tokio::select! {
            () = shared.cancel.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let shared = Arc::clone(&shared);
                    tokio::spawn(async move {
                        let cancel = shared.cancel.clone();
                        let svc = service_fn(move |req| handle(Arc::clone(&shared), peer, req));
                        // HTTP/1.x (Chromium's proxy dialect) and prior-knowledge HTTP/2 clients
                        let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                        let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), svc);
                        tokio::select! {
                            () = cancel.cancelled() => {}
                            r = conn => {
                                if let Err(e) = r {
                                    tracing::debug!(error = %e, "proxy client connection ended with error");
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, "egress proxy accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }
}

/// Running proxy. Dropping it stops the listener and open tunnels.
#[derive(Debug)]
pub struct EgressProxyHandle {
    addr: SocketAddr,
    shared: Arc<Shared>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("denials", &self.denials.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl EgressProxyHandle {
    /// Bound loopback port, for `--proxy-server=http://127.0.0.1:<port>`.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.addr.port()
    }

    /// Bound loopback socket address of the proxy.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Total refused requests since start.
    #[must_use]
    pub fn denials(&self) -> u64 {
        self.shared.denials.load(Ordering::Relaxed)
    }

    /// The most recent refusals (bounded log, oldest first).
    #[must_use]
    pub fn denied_events(&self) -> Vec<DeniedEvent> {
        self.shared.events.lock().iter().cloned().collect()
    }

    /// Distinct `(host, port)` targets the policy admitted, sorted. An admitted target may
    /// still have failed to connect; a target never listed here was never dialed.
    #[must_use]
    pub fn dialed_hosts(&self) -> Vec<(String, u16)> {
        self.shared.dialed.lock().iter().cloned().collect()
    }

    /// Flows the capture channel refused because it was full (`proxy_capture_dropped_total`);
    /// `0` without capture.
    #[must_use]
    pub fn capture_dropped(&self) -> u64 {
        self.shared
            .capture
            .as_ref()
            .map_or(0, |c| c.dropped.load(Ordering::Relaxed))
    }

    /// Stop accepting, close open tunnels and wait for the accept loop.
    pub async fn shutdown(mut self) {
        self.shared.cancel.cancel();
        // The loop only exits on cancel, so a join error means it already panicked or was aborted.
        let _ = (&mut self.task).await;
    }
}

impl Drop for EgressProxyHandle {
    fn drop(&mut self) {
        self.shared.cancel.cancel();
    }
}
