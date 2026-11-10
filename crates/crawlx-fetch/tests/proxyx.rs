//! The ProxyX pool route end to end against an in-process fake gateway: `CONNECT`-only
//! tunnels (plain `http://` targets included), the typed username with a per-crawl sticky id,
//! the session and exit IP read from the `CONNECT` answer, typed refusals, the egress policy
//! over the gateway and control hosts, and bounded block-signal feedback.
//!
//! The gateway here speaks the wire contract only: Basic auth on `CONNECT`, a `200` carrying
//! `X-ProxyX-Pool-Session` and `X-ProxyX-Exit-IP`, or `HTTP/1.1 <status> <cause_code>`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use base64::Engine as _;
use common::{allow_private_policy, fast_config, url, LOOPBACK};
use crawlx_core::secret::SecretOr;
use crawlx_fetch::proxyx::{PoolCause, PoolSelector, PoolTier, ProxyxRoute, Retryability};
use crawlx_fetch::{FetchConfig, FetchError, FetchOptions, Fetcher, Resolver, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "ak_fixture-org-key_0123456789abcdefghijklmnopqrstuv";

/// What the gateway saw on one `CONNECT`.
#[derive(Clone, Debug)]
struct Seen {
    target: String,
    username: String,
    password: String,
    first_line: String,
}

#[derive(Clone)]
enum Mode {
    Accept,
    /// `HTTP/1.1 <status> <reason>`, then close.
    Refuse(u16, &'static str),
}

struct Gateway {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    mode: Arc<Mutex<Mode>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Gateway {
    /// `routes`: where the gateway "resolves" a target host.
    async fn start(routes: Vec<(String, SocketAddr)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mode = Arc::new(Mutex::new(Mode::Accept));
        let counter = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn({
            let (seen, mode) = (Arc::clone(&seen), Arc::clone(&mode));
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve(
                        stream,
                        routes.clone(),
                        Arc::clone(&seen),
                        Arc::clone(&mode),
                        counter.fetch_add(1, Ordering::Relaxed),
                    ));
                }
            }
        });
        Self {
            addr,
            seen,
            mode,
            task,
        }
    }

    fn url(&self) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:{}", self.addr.port())).unwrap()
    }

    fn set_mode(&self, mode: Mode) {
        *self.mode.lock() = mode;
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().clone()
    }
}

async fn serve(
    mut stream: TcpStream,
    routes: Vec<(String, SocketAddr)>,
    seen: Arc<Mutex<Vec<Seen>>>,
    mode: Arc<Mutex<Mode>>,
    n: u64,
) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await.unwrap_or(0) == 0 {
            return;
        }
        head.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n");
    let first_line = lines.next().unwrap_or_default().to_owned();
    let mut parts = first_line.split(' ');
    let (verb, target) = (parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
    let auth = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
        .map(|(_, v)| v.trim().to_owned())
        .unwrap_or_default();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth.trim_start_matches("Basic "))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let (username, password) = decoded.split_once(':').unwrap_or(("", ""));
    seen.lock().push(Seen {
        target: target.to_owned(),
        username: username.to_owned(),
        password: password.to_owned(),
        first_line: first_line.clone(),
    });
    if verb != "CONNECT" {
        // the real gateway answers an absolute-form request with 405
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }
    let current = mode.lock().clone();
    if let Mode::Refuse(status, reason) = current {
        let _ = stream
            .write_all(format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes())
            .await;
        return;
    }
    if password != KEY {
        let _ = stream
            .write_all(b"HTTP/1.1 407 auth_required\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    }
    let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
    let upstream = match routes.iter().find(|(h, _)| h == host) {
        Some((_, addr)) => TcpStream::connect(addr).await,
        None => TcpStream::connect(target).await,
    };
    let Ok(mut upstream) = upstream else {
        let _ = stream
            .write_all(b"HTTP/1.1 502 upstream_error\r\nContent-Length: 0\r\n\r\n")
            .await;
        return;
    };
    let reply = format!(
        "HTTP/1.1 200 Connection established\r\nX-ProxyX-Pool-Session: {:032x}\r\nX-ProxyX-Exit-IP: 203.0.113.{}\r\n\r\n",
        0xabc0_0000_u128 + u128::from(n),
        n % 200 + 1
    );
    if stream.write_all(reply.as_bytes()).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
}

fn resolver() -> Arc<StaticResolver> {
    let r = StaticResolver::new();
    r.set("pub.test", [LOOPBACK]);
    Arc::new(r)
}

struct Rig {
    origin: MockServer,
    gateway: Gateway,
}

impl Rig {
    async fn start() -> Self {
        let origin = MockServer::start().await;
        let gateway = Gateway::start(vec![("pub.test".to_owned(), *origin.address())]).await;
        Self { origin, gateway }
    }

    fn url(&self, path: &str) -> url::Url {
        url("pub.test", &self.origin, path)
    }

    fn route(&self, selector: &str, control: Option<&url::Url>) -> ProxyxRoute {
        ProxyxRoute::new(
            &self.gateway.url(),
            control,
            SecretOr::secret(KEY.to_owned()),
            PoolSelector::from_spec(selector).unwrap(),
        )
        .unwrap()
    }

    fn policy(&self) -> Arc<EgressPolicy> {
        Arc::new(allow_private_policy(&self.origin))
    }

    fn fetcher(&self, route: &ProxyxRoute, crawl: &str, retries: u32) -> Fetcher {
        let resolver: Arc<dyn Resolver> = resolver();
        let binding = route
            .bind(
                PoolTier::Basic,
                crawl,
                Some((self.policy(), Arc::clone(&resolver))),
            )
            .unwrap();
        let mut cfg: FetchConfig = fast_config();
        cfg.retry.max_retries = retries;
        cfg.pool = Some(binding);
        Fetcher::new(cfg, self.policy(), resolver).unwrap()
    }

    async fn ok(&self, p: &'static str) {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ResponseTemplate::new(200).set_body_raw("hi there", "text/plain"))
            .mount(&self.origin)
            .await;
    }
}

#[tokio::test]
async fn a_plain_http_target_is_tunneled_with_the_typed_username_and_the_org_key() {
    let rig = Rig::start().await;
    rig.ok("/hello").await;
    let route = rig.route("kind=rotating,cc=fr", None);
    let f = rig.fetcher(&route, "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b", 0);
    let u = rig.url("/hello");
    let resp = f.fetch(&u, &FetchOptions::default()).await.unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body[..], b"hi there");
    // the gateway's own address is not the network peer: it is never reported as one
    assert!(!resp.peer_observed);

    let seen = rig.gateway.seen();
    assert_eq!(seen.len(), 1);
    // CONNECT, never an absolute-form request, even for a plain http:// target
    assert_eq!(
        seen[0].first_line,
        format!("CONNECT pub.test:{} HTTP/1.1", rig.origin.address().port())
    );
    assert_eq!(
        seen[0].target,
        format!("pub.test:{}", rig.origin.address().port())
    );
    assert_eq!(
        seen[0].username,
        "px-kind-rotating-cc-fr-sid-cx_b_0190a1b2_c3d4_7e5f_8a9b_0c1d2e3f4a5b"
    );
    assert_eq!(seen[0].password, KEY);

    // the origin saw an origin-form request and no proxy credentials
    let reqs = rig.origin.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].url.path(), "/hello");
    assert!(reqs[0].headers.get("proxy-authorization").is_none());

    // session and exit IP come from the CONNECT answer
    let tunnel = f.pool_tunnel(&u).unwrap();
    assert_eq!(tunnel.session, format!("{:032x}", 0xabc0_0000_u128));
    assert_eq!(tunnel.exit_ip.to_string(), "203.0.113.1");
}

#[tokio::test]
async fn one_crawl_keeps_one_identity_and_two_crawls_get_two() {
    let rig = Rig::start().await;
    rig.ok("/a").await;
    rig.ok("/b").await;
    let route = rig.route("", None);
    let one = rig.fetcher(&route, "crawl-one", 0);
    let two = rig.fetcher(&route, "crawl-two", 0);
    for f in [&one, &two] {
        for p in ["/a", "/b"] {
            f.fetch(&rig.url(p), &FetchOptions::default()).await.unwrap();
        }
    }
    let usernames: Vec<_> = rig.gateway.seen().into_iter().map(|s| s.username).collect();
    assert!(
        usernames.iter().all(|u| u.starts_with("px-sid-cx_b_crawl_")),
        "{usernames:?}"
    );
    let distinct: std::collections::BTreeSet<_> = usernames.iter().collect();
    assert_eq!(distinct.len(), 2, "{usernames:?}");
    // plain `http://` targets are sent in origin form over one tunnel each: four requests, four
    // tunnels, two identities
    assert_eq!(usernames.len(), 4, "{usernames:?}");
}

#[tokio::test]
async fn rot_each_opens_a_tunnel_and_an_identity_per_request() {
    let rig = Rig::start().await;
    rig.ok("/a").await;
    let route = rig.route("cc=de,rot=each", None);
    let f = rig.fetcher(&route, "crawl-each", 0);
    let mut sessions = Vec::new();
    for _ in 0..3 {
        let u = rig.url("/a");
        f.fetch(&u, &FetchOptions::default()).await.unwrap();
        sessions.push(f.pool_tunnel(&u).unwrap().session);
    }
    let seen = rig.gateway.seen();
    assert_eq!(seen.len(), 3);
    assert!(seen.iter().all(|s| s.username == "px-cc-de-rot-each"), "{seen:?}");
    let distinct: std::collections::BTreeSet<_> = sessions.iter().collect();
    assert_eq!(distinct.len(), 3);
}

#[tokio::test]
async fn gateway_refusals_become_typed_errors_with_retry_guidance() {
    let rig = Rig::start().await;
    rig.ok("/a").await;
    let route = rig.route("", None);
    for (status, reason, cause, retryability) in [
        (
            407,
            "auth_required",
            PoolCause::AuthRequired,
            Retryability::Terminal,
        ),
        (
            403,
            "option_denied",
            PoolCause::OptionDenied,
            Retryability::Terminal,
        ),
        (
            403,
            "destination_denied",
            PoolCause::DestinationDenied,
            Retryability::Terminal,
        ),
        (503, "org_budget", PoolCause::OrgBudget, Retryability::Terminal),
        (503, "org_capacity", PoolCause::OrgCapacity, Retryability::Backoff),
        (
            503,
            "no_healthy_ip",
            PoolCause::NoHealthyIp,
            Retryability::Backoff,
        ),
        (504, "lease_timeout", PoolCause::LeaseTimeout, Retryability::Retry),
        (
            502,
            "provider_unavailable",
            PoolCause::ProviderUnavailable,
            Retryability::Retry,
        ),
    ] {
        rig.gateway.set_mode(Mode::Refuse(status, reason));
        let f = rig.fetcher(&route, "refused", 0);
        let error = f
            .fetch(&rig.url("/a"), &FetchOptions::default())
            .await
            .unwrap_err();
        match error {
            FetchError::PoolRefused {
                cause: got,
                status: s,
            } => {
                assert_eq!((got, s), (Some(cause), status), "{reason}");
                assert_eq!(cause.retryability(), retryability);
            }
            other => panic!("{reason}: {other}"),
        }
    }
    // a reason phrase the gateway does not send is still a refusal, with no named cause
    rig.gateway.set_mode(Mode::Refuse(502, "teapot"));
    let f = rig.fetcher(&route, "refused", 0);
    let error = f
        .fetch(&rig.url("/a"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            FetchError::PoolRefused {
                cause: None,
                status: 502
            }
        ),
        "{error}"
    );
    assert!(!error.to_string().contains(KEY));
    // and nothing reached the origin
    assert!(rig.origin.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_wrong_org_key_is_a_terminal_auth_refusal() {
    let rig = Rig::start().await;
    rig.ok("/a").await;
    let route = ProxyxRoute::new(
        &rig.gateway.url(),
        None,
        SecretOr::secret("ak_wrong".to_owned()),
        PoolSelector::default(),
    )
    .unwrap();
    let f = rig.fetcher(&route, "x", 0);
    let error = f
        .fetch(&rig.url("/a"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            FetchError::PoolRefused {
                cause: Some(PoolCause::AuthRequired),
                status: 407
            }
        ),
        "{error}"
    );
}

#[tokio::test]
async fn the_gateway_host_stays_under_the_egress_policy() {
    let rig = Rig::start().await;
    rig.ok("/a").await;
    let route = rig.route("", None);
    // a policy that denies loopback: the target is public, the gateway is not
    let r = StaticResolver::new();
    r.set("pub.test", ["93.184.216.34".parse().unwrap()]);
    let resolver: Arc<dyn Resolver> = Arc::new(r);
    let policy = Arc::new(EgressPolicy::new(false));
    let binding = route.bind(PoolTier::Basic, "x", None).unwrap();
    let mut cfg = fast_config();
    cfg.retry.max_retries = 0;
    cfg.pool = Some(binding);
    let f = Fetcher::new(cfg, policy, resolver).unwrap();
    let error = f
        .fetch(
            &url::Url::parse("http://pub.test/a").unwrap(),
            &FetchOptions::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::EgressDenied(_)), "{error}");
    assert!(rig.gateway.seen().is_empty(), "the gateway was dialed");
}

#[tokio::test]
async fn the_target_is_still_checked_before_the_gateway_is_asked() {
    let rig = Rig::start().await;
    let route = rig.route("", None);
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
    let resolver: Arc<dyn Resolver> = resolver();
    let binding = route.bind(PoolTier::Basic, "x", None).unwrap();
    let mut cfg = fast_config();
    cfg.retry.max_retries = 0;
    cfg.pool = Some(binding);
    let f = Fetcher::new(cfg, Arc::new(policy), resolver).unwrap();
    // the gateway is reachable, the private target is not
    let error = f
        .fetch(
            &url::Url::parse("http://10.0.0.1/a").unwrap(),
            &FetchOptions::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::EgressDenied(_)), "{error}");
    assert!(rig.gateway.seen().is_empty());
}

#[tokio::test]
async fn debug_output_and_errors_never_carry_the_key() {
    let rig = Rig::start().await;
    let route = rig.route("kind=rotating", None);
    let binding = route.bind(PoolTier::Basic, "x", None).unwrap();
    let mut cfg = fast_config();
    cfg.pool = Some(Arc::clone(&binding));
    let rendered = format!("{route:?} {binding:?} {:?} {cfg:?}", binding.upstream());
    assert!(!rendered.contains(KEY), "{rendered}");
    assert!(!rendered.contains("px-kind"), "{rendered}");
}

#[tokio::test]
async fn a_refused_tunnel_to_an_https_target_is_typed_too() {
    let rig = Rig::start().await;
    let route = rig.route("", None);
    rig.gateway.set_mode(Mode::Refuse(403, "destination_denied"));
    let f = rig.fetcher(&route, "tls-target", 0);
    let u = url::Url::parse(&format!("https://pub.test:{}/a", rig.origin.address().port())).unwrap();
    let error = f.fetch(&u, &FetchOptions::default()).await.unwrap_err();
    assert!(
        matches!(
            error,
            FetchError::PoolRefused {
                cause: Some(PoolCause::DestinationDenied),
                status: 403
            }
        ),
        "{error}"
    );
    let seen = rig.gateway.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].first_line,
        format!("CONNECT pub.test:{} HTTP/1.1", rig.origin.address().port())
    );
}

#[tokio::test]
async fn an_origin_cannot_forge_the_proxy_error_marker() {
    let rig = Rig::start().await;
    Mock::given(method("GET"))
        .and(path("/forged"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("x-crawlx-proxy-error", "upstream")
                .set_body_raw("origin body", "text/plain"),
        )
        .mount(&rig.origin)
        .await;
    let route = rig.route("", None);
    let f = rig.fetcher(&route, "forged", 0);
    let resp = f
        .fetch(&rig.url("/forged"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 200);
    assert_eq!(&resp.body[..], b"origin body");
    assert!(resp.headers.get("x-crawlx-proxy-error").is_none());
}

#[tokio::test]
async fn an_origins_own_502_is_the_origins_answer() {
    let rig = Rig::start().await;
    Mock::given(method("GET"))
        .and(path("/bad"))
        .respond_with(ResponseTemplate::new(502).set_body_raw("origin says no", "text/plain"))
        .mount(&rig.origin)
        .await;
    let route = rig.route("", None);
    let f = rig.fetcher(&route, "origin-502", 0);
    let resp = f
        .fetch_once(&rig.url("/bad"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(resp.status.as_u16(), 502);
    assert_eq!(&resp.body[..], b"origin says no");
}

mod signals {
    use super::*;
    use crawlx_fetch::proxyx::SignalStats;
    use serde_json::Value;

    async fn control() -> MockServer {
        let control = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/block-signals"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"accepted": 1, "ignored": 0})),
            )
            .mount(&control)
            .await;
        control
    }

    fn control_url(server: &MockServer) -> url::Url {
        url::Url::parse(&format!("http://127.0.0.1:{}", server.address().port())).unwrap()
    }

    async fn batches(server: &MockServer, at_least: usize) -> Vec<(Value, String)> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let requests = server.received_requests().await.unwrap();
            if requests.len() >= at_least || Instant::now() > deadline {
                return requests
                    .iter()
                    .map(|r| {
                        (
                            serde_json::from_slice(&r.body).unwrap(),
                            r.headers
                                .get("authorization")
                                .unwrap()
                                .to_str()
                                .unwrap()
                                .to_owned(),
                        )
                    })
                    .collect();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn stats(f: &Fetcher, wanted: impl Fn(&SignalStats) -> bool) -> SignalStats {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let s = f.pool().unwrap().signal_stats().unwrap();
            if wanted(&s) || Instant::now() > deadline {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn a_429_is_reported_with_the_session_and_exit_ip_of_its_tunnel() {
        let rig = Rig::start().await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&rig.origin)
            .await;
        let control = control().await;
        let route = rig.route("cc=fr", Some(&control_url(&control)));
        let f = rig.fetcher(&route, "crawl-signals", 0);
        let u = rig.url("/limited");
        let resp = f.fetch_once(&u, &FetchOptions::default()).await.unwrap();
        assert_eq!(resp.status.as_u16(), 429);
        let tunnel = f.pool_tunnel(&u).unwrap();

        let sent = batches(&control, 1).await;
        assert_eq!(sent.len(), 1);
        let (body, auth) = &sent[0];
        let events = body.as_array().unwrap();
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert_eq!(event["session"], tunnel.session);
        assert_eq!(event["exit_ip"], tunnel.exit_ip.to_string());
        assert_eq!(
            event["target"],
            format!("pub.test:{}", rig.origin.address().port())
        );
        assert_eq!(event["type"], "rate_limited");
        assert!(event["time"].as_i64().unwrap() > 1_700_000_000);
        // Basic auth with the org key as the password
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(auth.trim_start_matches("Basic "))
            .unwrap();
        assert!(String::from_utf8(decoded).unwrap().ends_with(&format!(":{KEY}")));
        let s = stats(&f, |s| s.accepted >= 1).await;
        assert_eq!((s.accepted, s.dropped, s.failed), (1, 0, 0));
    }

    #[tokio::test]
    async fn challenges_and_repeated_403s_are_reported_but_a_single_403_is_not() {
        let rig = Rig::start().await;
        Mock::given(method("GET"))
            .and(path("/challenge"))
            .respond_with(
                ResponseTemplate::new(403).set_body_raw("<title>Just a moment...</title>", "text/html"),
            )
            .mount(&rig.origin)
            .await;
        Mock::given(method("GET"))
            .and(path("/plain"))
            .respond_with(ResponseTemplate::new(403).set_body_raw("denied", "text/plain"))
            .mount(&rig.origin)
            .await;
        let control = control().await;
        let route = rig.route("", Some(&control_url(&control)));
        let f = rig.fetcher(&route, "crawl-403", 0);
        f.fetch_once(&rig.url("/challenge"), &FetchOptions::default())
            .await
            .unwrap();
        f.fetch_once(&rig.url("/plain"), &FetchOptions::default())
            .await
            .unwrap();
        // one plain 403 is not a signal; the second in a row on the target is
        f.fetch_once(&rig.url("/plain"), &FetchOptions::default())
            .await
            .unwrap();
        let s = stats(&f, |s| s.accepted + s.ignored + s.failed >= 2).await;
        assert_eq!(s.failed, 0);
        let sent = batches(&control, 1).await;
        let kinds: Vec<String> = sent
            .iter()
            .flat_map(|(body, _)| {
                body.as_array()
                    .unwrap()
                    .iter()
                    .map(|e| e["type"].as_str().unwrap().to_owned())
            })
            .collect();
        assert_eq!(kinds, ["challenge", "forbidden"], "{kinds:?}");
    }

    #[tokio::test]
    async fn retry_after_pauses_delivery_and_the_batch_is_sent_again() {
        let rig = Rig::start().await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&rig.origin)
            .await;
        let control = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/block-signals"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "2"))
            .up_to_n_times(1)
            .mount(&control)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/block-signals"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"accepted": 1, "ignored": 0})),
            )
            .mount(&control)
            .await;
        let route = rig.route("", Some(&control_url(&control)));
        let f = rig.fetcher(&route, "crawl-retry-after", 0);
        f.fetch_once(&rig.url("/limited"), &FetchOptions::default())
            .await
            .unwrap();
        let first = Instant::now();
        let sent = batches(&control, 2).await;
        assert_eq!(sent.len(), 2, "the batch was not sent again");
        assert!(
            first.elapsed() >= Duration::from_millis(1500),
            "Retry-After was not honored"
        );
        assert_eq!(sent[0].0, sent[1].0, "a retried batch is the same batch");
        let s = stats(&f, |s| s.accepted >= 1).await;
        assert_eq!((s.accepted, s.failed), (1, 0));
    }

    #[tokio::test]
    async fn rejected_batches_are_dropped_and_counted_not_retried() {
        let rig = Rig::start().await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&rig.origin)
            .await;
        let control = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/block-signals"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&control)
            .await;
        let route = rig.route("", Some(&control_url(&control)));
        let f = rig.fetcher(&route, "crawl-401", 0);
        f.fetch_once(&rig.url("/limited"), &FetchOptions::default())
            .await
            .unwrap();
        let s = stats(&f, |s| s.failed >= 1).await;
        assert_eq!((s.accepted, s.failed), (0, 1));
        assert_eq!(control.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_stalled_control_api_never_blocks_the_crawl_and_overflow_is_dropped_and_counted() {
        let rig = Rig::start().await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&rig.origin)
            .await;
        let control = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/block-signals"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(60)))
            .mount(&control)
            .await;
        let route = rig.route("", Some(&control_url(&control)));
        let f = rig.fetcher(&route, "crawl-stalled", 0);
        let u = rig.url("/limited");
        f.fetch_once(&u, &FetchOptions::default()).await.unwrap();
        let pool = f.pool().unwrap();
        let started = Instant::now();
        let headers = http::HeaderMap::new();
        let port = rig.origin.address().port();
        for _ in 0..4000 {
            pool.observe(
                "pub.test",
                port,
                http::StatusCode::TOO_MANY_REQUESTS,
                &headers,
                b"",
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "observing blocked the caller"
        );
        let dropped = pool.signal_stats().unwrap().dropped;
        assert!(dropped >= 1000, "dropped {dropped}");
        // the crawl itself is unaffected
        let resp = f.fetch_once(&u, &FetchOptions::default()).await.unwrap();
        assert_eq!(resp.status.as_u16(), 429);
    }

    #[tokio::test]
    async fn the_control_host_is_held_to_the_egress_policy() {
        let rig = Rig::start().await;
        Mock::given(method("GET"))
            .and(path("/limited"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&rig.origin)
            .await;
        let control = control().await;
        let resolver: Arc<dyn Resolver> = resolver();
        // the gateway and the origin are allowed, the control host is not: it lives on a
        // different loopback address no allow-rule covers
        let mut policy = EgressPolicy::new(false);
        policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
        policy.extra_ports.push(rig.origin.address().port());
        let policy = Arc::new(policy);
        let denied_control = ProxyxRoute::new(
            &rig.gateway.url(),
            Some(&url::Url::parse("http://127.0.0.2:8081").unwrap()),
            SecretOr::secret(KEY.to_owned()),
            PoolSelector::default(),
        )
        .unwrap();
        let binding = denied_control
            .bind(
                PoolTier::Basic,
                "x",
                Some((Arc::clone(&policy), Arc::clone(&resolver))),
            )
            .unwrap();
        let mut cfg = fast_config();
        cfg.retry.max_retries = 0;
        cfg.pool = Some(binding);
        let f = Fetcher::new(cfg, policy, resolver).unwrap();
        f.fetch_once(&rig.url("/limited"), &FetchOptions::default())
            .await
            .unwrap();
        let s = stats(&f, |s| s.failed >= 1).await;
        assert_eq!((s.accepted, s.failed), (0, 1));
        assert!(control.received_requests().await.unwrap().is_empty());
        // control URL and key never leak through the binding's Debug
        assert!(!format!("{:?}", f.pool().unwrap()).contains("127.0.0.2"));
        assert!(control.received_requests().await.unwrap().is_empty());
    }
}
