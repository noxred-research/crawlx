//! Native client of the ProxyX pool gateway, an optional upstream for the `basic` and
//! `enhanced` proxy tiers (<https://github.com/noxred-research/proxyx>).
//!
//! The pool gateway is an HTTP `CONNECT` proxy with a typed username. Everything here is
//! implemented against its wire contract; crawlx has no dependency on the ProxyX code.
//!
//! * [`PoolSelector`] is the typed form of the username grammar (kind, country, city,
//!   provider, ttl, rotation) and validates locally; the gateway refuses anything outside the
//!   grammar and never repairs it.
//! * [`ProxyxRoute`] is the operator's configuration of one tier: gateway URL, optional control
//!   URL, the org key as a secret and a selector. [`ProxyxRoute::bind`] derives the sticky
//!   identity of one crawl and returns a [`PoolBinding`].
//! * A [`PoolBinding`] is the upstream of one crawl and tier. Its upstream speaks `CONNECT`
//!   only, because the gateway answers an absolute-form request with `405`: plain `http://`
//!   targets are tunneled too. The connector reads `X-ProxyX-Pool-Session` and
//!   `X-ProxyX-Exit-IP` from the `CONNECT` answer into a bounded [`TunnelLog`] and records a
//!   refusal by its [`PoolCause`].
//! * Block feedback: when the control URL is configured, a `429`, a challenge, a repeated plain
//!   `403` or a reset after the tunnel opened is queued for `POST /v1/block-signals`
//!   ([`BlockReporter`]); the queue is bounded, delivery never blocks a fetch.
//!
//! The gateway and control hosts stay subject to the egress policy: the loopback adapter the
//! fetcher uses vets the gateway host like any other upstream proxy, and the reporter vets the
//! control host. A gateway on a private address needs `egress.deployment_allowlist`.

mod cause;
mod log;
mod selector;
mod signals;

pub use cause::{PoolCause, Retryability};
pub use log::{PoolRefusal, PoolTunnel, TunnelLog};
pub use selector::{PoolKind, PoolRotation, PoolSelector, PoolTtl, MAX_USERNAME_LEN, USERNAME_PREFIX};
pub use signals::{
    is_challenge, target_of, BlockReporter, BlockSignal, SignalKind, SignalStats, QUEUE_CAPACITY,
};

use crate::resolver::Resolver;
use crate::upstream::UpstreamProxy;
use crawlx_core::secret::SecretOr;
use crawlx_policy::egress::EgressPolicy;
use http::{HeaderMap, StatusCode};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// Port of the gateway's `CONNECT` listener when the URL names none.
pub const DEFAULT_GATEWAY_PORT: u16 = 8080;
/// Port of the control API when the URL names none.
pub const DEFAULT_CONTROL_PORT: u16 = 8081;
/// Plain `403`s on one target before the repeat is reported as `forbidden`.
const FORBIDDEN_REPEATS: u8 = 2;
/// Targets whose `403` streak is tracked.
const MAX_STREAK_TARGETS: usize = 256;
/// A refusal older than this does not explain a transport failure.
pub(crate) const REFUSAL_WINDOW: Duration = Duration::from_secs(10);
/// Longest org key accepted.
const MAX_ORG_KEY_LEN: usize = 256;

/// Which proxy tier a pool serves.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PoolTier {
    /// The `basic` tier.
    Basic,
    /// The `enhanced` tier.
    Enhanced,
}

impl PoolTier {
    /// One letter that keeps the two tiers of a crawl on separate leases.
    pub(crate) const fn tag(self) -> char {
        match self {
            Self::Basic => 'b',
            Self::Enhanced => 'e',
        }
    }
}

/// A pool route or selection that cannot be used. Messages never contain the org key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyxError {
    /// A selector field is outside the gateway's grammar.
    #[error("invalid pool selector `{field}`: {reason}")]
    Selector {
        /// The offending field.
        field: &'static str,
        /// What is wrong.
        reason: &'static str,
    },
    /// The username would exceed the gateway's limit.
    #[error("the pool username would be {len} bytes; the gateway accepts at most {MAX_USERNAME_LEN}")]
    UsernameTooLong {
        /// Length of the rejected username.
        len: usize,
    },
    /// The gateway URL is unusable.
    #[error("invalid pool gateway URL: {0}")]
    Gateway(&'static str),
    /// The control URL is unusable.
    #[error("invalid pool control URL: {0}")]
    Control(&'static str),
    /// The org key is unusable.
    #[error("invalid pool org key: {0}")]
    OrgKey(&'static str),
}

impl ProxyxError {
    pub(crate) const fn selector(field: &'static str, reason: &'static str) -> Self {
        Self::Selector { field, reason }
    }
}

/// `scheme://host:port/` of `raw` with the default `port` filled in; no credentials, path,
/// query or fragment.
fn endpoint(raw: &Url, default_port: u16, err: fn(&'static str) -> ProxyxError) -> Result<Url, ProxyxError> {
    if !matches!(raw.scheme(), "http" | "https") {
        return Err(err("the scheme must be http or https"));
    }
    if raw.host_str().is_none() {
        return Err(err("the URL has no host"));
    }
    if !raw.username().is_empty() || raw.password().is_some() {
        return Err(err(
            "the URL must not carry credentials; the org key is configured separately",
        ));
    }
    if raw.query().is_some() || raw.fragment().is_some() {
        return Err(err("the URL must not have a query or fragment"));
    }
    let mut url = raw.clone();
    url.set_path("/");
    if url.port().is_none() {
        url.set_port(Some(default_port))
            .map_err(|()| err("the URL cannot carry a port"))?;
    }
    Ok(url)
}

/// The operator's configuration of one tier. Cheap to clone; holds the org key as a secret.
#[derive(Clone)]
pub struct ProxyxRoute {
    gateway: Url,
    control: Option<Url>,
    org_key: SecretOr<String>,
    selector: PoolSelector,
}

impl fmt::Debug for ProxyxRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyxRoute")
            .field("gateway", &self.gateway.host_str())
            .field("control", &self.control.as_ref().and_then(Url::host_str))
            .field("org_key", &"[configured]")
            .field("selector", &self.selector.to_string())
            .finish()
    }
}

impl ProxyxRoute {
    /// A route to `gateway` (`http://host[:8080]`) with an optional `control` API
    /// (`http://host[:8081]`) for block feedback, the org key and a selector.
    ///
    /// # Errors
    /// [`ProxyxError`] for a URL that is not `http(s)://host[:port]` without credentials, a key
    /// that is empty, too long or not printable ASCII, or an invalid selector.
    pub fn new(
        gateway: &Url,
        control: Option<&Url>,
        org_key: SecretOr<String>,
        selector: PoolSelector,
    ) -> Result<Self, ProxyxError> {
        let key = org_key.expose();
        if key.is_empty() {
            return Err(ProxyxError::OrgKey("the key is empty"));
        }
        if key.len() > MAX_ORG_KEY_LEN || !key.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(ProxyxError::OrgKey(
                "the key must be printable ASCII without spaces",
            ));
        }
        selector.validate()?;
        Ok(Self {
            gateway: endpoint(gateway, DEFAULT_GATEWAY_PORT, ProxyxError::Gateway)?,
            control: control
                .map(|url| endpoint(url, DEFAULT_CONTROL_PORT, ProxyxError::Control))
                .transpose()?,
            org_key,
            selector,
        })
    }

    /// The gateway's `CONNECT` endpoint, without credentials.
    #[must_use]
    pub const fn gateway(&self) -> &Url {
        &self.gateway
    }

    /// The control API, when block feedback is configured.
    #[must_use]
    pub const fn control(&self) -> Option<&Url> {
        self.control.as_ref()
    }

    /// The selector of the tier.
    #[must_use]
    pub const fn selector(&self) -> &PoolSelector {
        &self.selector
    }

    /// A stable, credential-free name of the route (gateway authority and selector) for
    /// identities and logs.
    #[must_use]
    pub fn identity(&self) -> String {
        format!(
            "proxyx://{}:{}?{}",
            self.gateway.host_str().unwrap_or_default(),
            self.gateway.port().unwrap_or(DEFAULT_GATEWAY_PORT),
            self.selector
        )
    }

    /// The upstream of `crawl` (a crawl id or any stable key) on `tier`.
    ///
    /// With `report = Some((policy, resolver))`, a control URL and a running tokio runtime,
    /// the binding also reports block signals; the policy and resolver are the run's and hold
    /// the control host to the egress rules. `None` binds the tunnel side only (the browser
    /// plane).
    ///
    /// # Errors
    /// [`ProxyxError`] when the selector and the crawl's sticky id do not fit the username.
    pub fn bind(
        &self,
        tier: PoolTier,
        crawl: &str,
        report: Option<(Arc<EgressPolicy>, Arc<dyn Resolver>)>,
    ) -> Result<Arc<PoolBinding>, ProxyxError> {
        let sid = self.selector.sticky_id(tier, crawl)?;
        let username = self.selector.username(sid.as_deref())?;
        let log = Arc::new(TunnelLog::default());
        let upstream = UpstreamProxy::pool(&self.gateway, &username, self.org_key.expose(), Arc::clone(&log))
            .map_err(|_| ProxyxError::Gateway("the gateway URL cannot be used as a CONNECT proxy"))?;
        let reporter = match (&self.control, report, tokio::runtime::Handle::try_current()) {
            (Some(control), Some((policy, resolver)), Ok(_)) => {
                Some(BlockReporter::start(signals::ReportTarget {
                    control: control.clone(),
                    org_key: self.org_key.clone(),
                    policy,
                    resolver,
                }))
            }
            _ => None,
        };
        Ok(Arc::new(PoolBinding {
            gateway: self.gateway.clone(),
            upstream,
            log,
            reporter,
            sid,
            rotates_each: self.selector.rotates_each(),
            forbidden: Mutex::new(BTreeMap::new()),
        }))
    }
}

/// The upstream of one crawl and tier.
pub struct PoolBinding {
    gateway: Url,
    upstream: UpstreamProxy,
    log: Arc<TunnelLog>,
    reporter: Option<BlockReporter>,
    sid: Option<String>,
    rotates_each: bool,
    /// Consecutive plain `403`s per target.
    forbidden: Mutex<BTreeMap<String, u8>>,
}

impl fmt::Debug for PoolBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolBinding")
            .field("gateway", &self.gateway.host_str())
            .field("sid", &self.sid)
            .field("rotates_each", &self.rotates_each)
            .field("reports", &self.reporter.is_some())
            .finish_non_exhaustive()
    }
}

impl PoolBinding {
    /// The gateway endpoint, without credentials.
    #[must_use]
    pub const fn gateway(&self) -> &Url {
        &self.gateway
    }

    /// The `CONNECT`-only upstream proxy carrying the typed username and the org key.
    #[must_use]
    pub const fn upstream(&self) -> &UpstreamProxy {
        &self.upstream
    }

    /// The sticky key this crawl sends, `None` with `rotation = each`.
    #[must_use]
    pub fn sid(&self) -> Option<&str> {
        self.sid.as_deref()
    }

    /// Does every tunnel get its own identity (connection reuse must then be off)?
    #[must_use]
    pub const fn rotates_each(&self) -> bool {
        self.rotates_each
    }

    /// The tunnels and refusals the gateway reported to this binding.
    #[must_use]
    pub fn log(&self) -> &Arc<TunnelLog> {
        &self.log
    }

    /// Block-signal counters; `None` when feedback is not configured.
    #[must_use]
    pub fn signal_stats(&self) -> Option<SignalStats> {
        self.reporter.as_ref().map(BlockReporter::stats)
    }

    /// The most recent tunnel the gateway opened to `host:port`.
    #[must_use]
    pub fn tunnel_for(&self, host: &str, port: u16) -> Option<PoolTunnel> {
        self.log.latest(host, port)
    }

    /// A refusal of `host:port` since `since`, if the gateway refused the tunnel.
    #[must_use]
    pub fn refusal_since(&self, host: &str, port: u16, since: Instant) -> Option<PoolRefusal> {
        self.log
            .recent_refusal(host, port, REFUSAL_WINDOW)
            .filter(|refusal| refusal.at >= since)
    }

    /// Look at a response of the pool-routed fetch and queue a block signal when it is one.
    ///
    /// `body` is the response body prefix when it has been read, empty otherwise (redirects and
    /// retried answers). The decision follows the gateway's vocabulary: `429` is
    /// `rate_limited`; a `403`/`503` with a challenge marker, or a redirect to a `/sorry/`
    /// page, is `challenge`; the second consecutive plain `403` on a target is `forbidden`.
    /// Never blocks.
    pub fn observe(&self, host: &str, port: u16, status: StatusCode, headers: &HeaderMap, body: &[u8]) {
        let Some(reporter) = &self.reporter else {
            return;
        };
        let target = target_of(host, port);
        let kind = self.classify(&target, status, headers, body);
        let Some(kind) = kind else {
            return;
        };
        self.report(reporter, host, port, target, kind);
    }

    /// A transport failure after the tunnel to `host:port` had opened since `since` (reset or
    /// TLS failure through the tunnel): queue a `reset` signal.
    pub fn observe_reset(&self, host: &str, port: u16, since: Instant) {
        let Some(reporter) = &self.reporter else {
            return;
        };
        if self.log.latest(host, port).is_some_and(|t| t.opened_at >= since) {
            self.report(reporter, host, port, target_of(host, port), SignalKind::Reset);
        }
    }

    fn classify(
        &self,
        target: &str,
        status: StatusCode,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Option<SignalKind> {
        let code = status.as_u16();
        let kind = if code == 429 {
            Some(SignalKind::RateLimited)
        } else if (status.is_redirection() || matches!(code, 403 | 503)) && is_challenge(headers, body) {
            Some(SignalKind::Challenge)
        } else {
            None
        };
        let mut streaks = self.forbidden.lock();
        if code != 403 {
            streaks.remove(target);
            return kind;
        }
        if kind.is_some() {
            streaks.remove(target);
            return kind;
        }
        if streaks.len() >= MAX_STREAK_TARGETS && !streaks.contains_key(target) {
            streaks.clear();
        }
        let streak = streaks.entry(target.to_owned()).or_insert(0);
        *streak = streak.saturating_add(1);
        (*streak >= FORBIDDEN_REPEATS).then_some(SignalKind::Forbidden)
    }

    fn report(&self, reporter: &BlockReporter, host: &str, port: u16, target: String, kind: SignalKind) {
        // without a recorded tunnel the signal cannot name a session and exit IP
        let Some(tunnel) = self.log.latest(host, port) else {
            return;
        };
        reporter.report(BlockSignal {
            session: tunnel.session,
            exit_ip: tunnel.exit_ip,
            target,
            kind,
            time: chrono::Utc::now().timestamp(),
        });
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const KEY: &str = "ak_secret-key-value_0123456789abcdefghijklmnopqrstuv";

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    fn route(gateway: &str, selector: &str) -> Result<ProxyxRoute, ProxyxError> {
        ProxyxRoute::new(
            &url(gateway),
            None,
            SecretOr::secret(KEY.to_owned()),
            PoolSelector::from_spec(selector).unwrap(),
        )
    }

    #[test]
    fn gateway_defaults_to_the_connect_port_and_is_credential_free() {
        let r = route("http://pool.internal", "").unwrap();
        assert_eq!(r.gateway().as_str(), "http://pool.internal:8080/");
        let r = route("https://pool.internal:9443/ignored/path", "").unwrap();
        assert_eq!(r.gateway().as_str(), "https://pool.internal:9443/");
        for bad in [
            "socks5://pool.internal:1080",
            "http://user:pw@pool.internal",
            "http://user@pool.internal",
            "http://pool.internal/?q=1",
            "http://pool.internal/#frag",
        ] {
            assert!(matches!(route(bad, ""), Err(ProxyxError::Gateway(_))), "{bad}");
        }
    }

    #[test]
    fn control_defaults_to_its_port_and_is_validated() {
        let r = ProxyxRoute::new(
            &url("http://pool.internal:8080"),
            Some(&url("http://pool.internal")),
            SecretOr::secret(KEY.to_owned()),
            PoolSelector::default(),
        )
        .unwrap();
        assert_eq!(r.control().unwrap().as_str(), "http://pool.internal:8081/");
        let bad = ProxyxRoute::new(
            &url("http://pool.internal:8080"),
            Some(&url("ftp://pool.internal")),
            SecretOr::secret(KEY.to_owned()),
            PoolSelector::default(),
        );
        assert!(matches!(bad, Err(ProxyxError::Control(_))));
    }

    #[test]
    fn org_key_is_validated_and_never_printed() {
        for bad in ["", "has space", "tab\tkey", "né", &"a".repeat(257)] {
            let r = ProxyxRoute::new(
                &url("http://pool.internal"),
                None,
                SecretOr::secret(bad.to_owned()),
                PoolSelector::default(),
            );
            assert!(matches!(r, Err(ProxyxError::OrgKey(_))), "{bad:?}");
        }
        let r = route("http://pool.internal", "cc=fr").unwrap();
        let rendered = format!("{r:?} {}", ProxyxError::OrgKey("x"));
        assert!(!rendered.contains(KEY), "{rendered}");
        assert!(rendered.contains("[configured]"));
        assert!(!r.identity().contains("ak_"));
        assert_eq!(r.identity(), "proxyx://pool.internal:8080?cc=fr");
    }

    #[tokio::test]
    async fn binding_derives_a_sticky_username_per_crawl_and_tier() {
        let r = route("http://pool.internal", "kind=rotating,cc=fr").unwrap();
        let a = r.bind(PoolTier::Basic, "run-1", None).unwrap();
        let again = r.bind(PoolTier::Basic, "run-1", None).unwrap();
        let other = r.bind(PoolTier::Basic, "run-2", None).unwrap();
        let enhanced = r.bind(PoolTier::Enhanced, "run-1", None).unwrap();
        assert_eq!(a.sid(), Some("cx_b_run_1"));
        assert_eq!(a.sid(), again.sid());
        assert_ne!(a.sid(), other.sid());
        assert_eq!(enhanced.sid(), Some("cx_e_run_1"));
        assert!(!a.rotates_each());
        let each = route("http://pool.internal", "rot=each").unwrap();
        let b = each.bind(PoolTier::Basic, "run-1", None).unwrap();
        assert_eq!(b.sid(), None);
        assert!(b.rotates_each());
        assert!(a.signal_stats().is_none());
    }

    #[test]
    fn debug_never_prints_the_key_or_the_username() {
        let r = route("http://pool.internal", "kind=rotating").unwrap();
        let b = r.bind(PoolTier::Basic, "run-1", None).unwrap();
        let rendered = format!("{b:?} {:?}", b.upstream());
        assert!(!rendered.contains(KEY));
        assert!(!rendered.contains("px-kind"));
    }

    fn binding_with_tunnel(control: bool) -> (Arc<PoolBinding>, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let r = ProxyxRoute::new(
            &url("http://pool.internal"),
            control.then(|| url("http://127.0.0.1:1")).as_ref(),
            SecretOr::secret(KEY.to_owned()),
            PoolSelector::default(),
        )
        .unwrap();
        let resolver: Arc<dyn Resolver> = Arc::new(crate::resolver::StaticResolver::new());
        let binding = r
            .bind(
                PoolTier::Basic,
                "run-1",
                Some((Arc::new(EgressPolicy::new(false)), resolver)),
            )
            .unwrap();
        binding
            .log
            .opened("t.test", 443, Some(&"ab".repeat(16)), Some("203.0.113.9"));
        (binding, rt)
    }

    #[test]
    fn classification_follows_the_gateway_vocabulary() {
        let (b, _rt) = binding_with_tunnel(true);
        let none = HeaderMap::new();
        let t = "t.test:443";
        assert_eq!(
            b.classify(t, StatusCode::TOO_MANY_REQUESTS, &none, b""),
            Some(SignalKind::RateLimited)
        );
        assert_eq!(
            b.classify(
                t,
                StatusCode::FORBIDDEN,
                &none,
                b"<title>Just a moment...</title>"
            ),
            Some(SignalKind::Challenge)
        );
        assert_eq!(
            b.classify(t, StatusCode::SERVICE_UNAVAILABLE, &none, b"cf-chl-bypass"),
            Some(SignalKind::Challenge)
        );
        // a plain 503 is a throttle of the origin, not a block of the exit IP
        assert_eq!(
            b.classify(t, StatusCode::SERVICE_UNAVAILABLE, &none, b"down"),
            None
        );
        assert_eq!(b.classify(t, StatusCode::OK, &none, b"fine"), None);
        let mut sorry = HeaderMap::new();
        sorry.insert(
            http::header::LOCATION,
            "https://x.test/sorry/index".parse().unwrap(),
        );
        assert_eq!(
            b.classify(t, StatusCode::FOUND, &sorry, b""),
            Some(SignalKind::Challenge)
        );
    }

    #[test]
    fn a_plain_403_is_forbidden_only_when_it_repeats_on_the_target() {
        let (b, _rt) = binding_with_tunnel(true);
        let none = HeaderMap::new();
        assert_eq!(b.classify("a:443", StatusCode::FORBIDDEN, &none, b"no"), None);
        assert_eq!(
            b.classify("a:443", StatusCode::FORBIDDEN, &none, b"no"),
            Some(SignalKind::Forbidden)
        );
        // another target has its own streak, and any other answer resets it
        assert_eq!(b.classify("b:443", StatusCode::FORBIDDEN, &none, b"no"), None);
        assert_eq!(b.classify("a:443", StatusCode::OK, &none, b""), None);
        assert_eq!(b.classify("a:443", StatusCode::FORBIDDEN, &none, b"no"), None);
    }

    #[test]
    fn signals_need_a_recorded_tunnel_and_a_control_url() {
        let (b, _rt) = binding_with_tunnel(true);
        let none = HeaderMap::new();
        b.observe("t.test", 443, StatusCode::TOO_MANY_REQUESTS, &none, b"");
        // an unknown target has no session to name, so nothing is queued for it
        b.observe("unknown.test", 443, StatusCode::TOO_MANY_REQUESTS, &none, b"");
        assert_eq!(b.signal_stats().unwrap().dropped, 0);
        let (quiet, _rt2) = binding_with_tunnel(false);
        quiet.observe("t.test", 443, StatusCode::TOO_MANY_REQUESTS, &none, b"");
        assert!(quiet.signal_stats().is_none());
    }

    #[test]
    fn refusals_are_scoped_to_the_attempt() {
        let (b, _rt) = binding_with_tunnel(false);
        let before = Instant::now();
        std::thread::sleep(Duration::from_millis(2));
        b.log.refused("t.test", 443, 403, "option_denied");
        let refusal = b.refusal_since("t.test", 443, before).unwrap();
        assert_eq!(refusal.cause, Some(PoolCause::OptionDenied));
        assert!(b
            .refusal_since("t.test", 443, Instant::now() + Duration::from_secs(1))
            .is_none());
        assert!(b.refusal_since("other.test", 443, before).is_none());
    }
}
