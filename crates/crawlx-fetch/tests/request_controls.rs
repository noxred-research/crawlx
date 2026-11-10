//! Request controls of the fetch plane: custom headers, cookies, `User-Agent`
//! and TLS verification (`fetch.extraHeaders`, `fetch.cookies`, `fetch.userAgent`,
//! `fetch.skipTlsVerification`) against in-process servers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use common::{allow_private_policy, fast_config, fetcher, url, LOOPBACK};
use crawlx_core::config::Fetch;
use crawlx_core::request_controls::{FetchCookie, RequestControls};
use crawlx_core::traffic::REDACTED_PLACEHOLDER;
use crawlx_fetch::{FetchConfig, FetchError, FetchOptions, Fetcher, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use http::{header, HeaderValue};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "k-1234567";
const SID: &str = "s-7654321";

fn resolver(hosts: &[&str]) -> Arc<StaticResolver> {
    let r = StaticResolver::new();
    for h in hosts {
        r.set(h, [LOOPBACK]);
    }
    Arc::new(r)
}

/// Controls scoped to `a.test`: header `x-api-key`, cookie `sid`, UA `crawlx-test-ua/1`.
async fn controls(edit: impl FnOnce(&mut Fetch)) -> RequestControls {
    let mut fetch = Fetch::default();
    fetch.extra_headers.insert("x-api-key", KEY);
    fetch.cookies.push(FetchCookie::new("sid", SID));
    fetch.user_agent = Some("crawlx-test-ua/1".to_owned());
    edit(&mut fetch);
    RequestControls::resolve(&fetch, "a.test", None).await.unwrap()
}

async fn ok_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("ok", "text/plain"))
        .mount(&server)
        .await;
    server
}

fn header_of(req: &wiremock::Request, name: &str) -> Option<String> {
    req.headers.get(name).map(|v| v.to_str().unwrap().to_owned())
}

#[tokio::test]
async fn headers_cookies_and_user_agent_arrive_on_every_request() {
    let server = ok_server().await;
    let cfg = fast_config().with_controls(controls(|_| {}).await);
    let f = fetcher(
        cfg,
        allow_private_policy(&server),
        resolver(&["a.test", "www.a.test"]),
    );
    for host in ["a.test", "www.a.test"] {
        let r = f
            .fetch(&url(host, &server, "/page"), &FetchOptions::default())
            .await
            .unwrap();
        assert_eq!(r.status.as_u16(), 200);
    }
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    for req in &reqs {
        assert_eq!(header_of(req, "x-api-key").as_deref(), Some(KEY));
        assert_eq!(header_of(req, "cookie").as_deref(), Some(&*format!("sid={SID}")));
        assert_eq!(header_of(req, "user-agent").as_deref(), Some("crawlx-test-ua/1"));
    }
}

#[tokio::test]
async fn default_user_agent_is_unchanged_without_controls() {
    let server = ok_server().await;
    let f = fetcher(
        fast_config(),
        allow_private_policy(&server),
        resolver(&["a.test"]),
    );
    f.fetch(&url("a.test", &server, "/page"), &FetchOptions::default())
        .await
        .unwrap();
    let req = &server.received_requests().await.unwrap()[0];
    assert_eq!(
        header_of(req, "user-agent").unwrap(),
        format!("crawlx/{} (+ops@example.test)", env!("CARGO_PKG_VERSION"))
    );
    assert!(req.headers.get("cookie").is_none() && req.headers.get("x-api-key").is_none());
}

#[tokio::test]
async fn secrets_stay_inside_the_scope_domain() {
    let server = ok_server().await;
    Mock::given(method("GET"))
        .and(path("/away"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            format!("http://other.test:{}/page", server.address().port()),
        ))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/sub"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "Location",
            format!("http://www.a.test:{}/page", server.address().port()),
        ))
        .mount(&server)
        .await;
    let cfg = fast_config().with_controls(controls(|_| {}).await);
    let f = fetcher(
        cfg,
        allow_private_policy(&server),
        resolver(&["a.test", "www.a.test", "other.test"]),
    );

    // a redirect to another registrable domain carries the UA but neither header nor cookie
    let r = f
        .fetch(&url("a.test", &server, "/away"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(r.final_url.host_str(), Some("other.test"));
    // a redirect to a subdomain keeps them
    let r = f
        .fetch(&url("a.test", &server, "/sub"), &FetchOptions::default())
        .await
        .unwrap();
    assert_eq!(r.final_url.host_str(), Some("www.a.test"));
    // a direct fetch of another domain gets none either
    f.fetch(&url("other.test", &server, "/page"), &FetchOptions::default())
        .await
        .unwrap();

    let reqs = server.received_requests().await.unwrap();
    let by_host_path: Vec<(String, String, bool, bool, String)> = reqs
        .iter()
        .map(|r| {
            (
                header_of(r, "host")
                    .unwrap()
                    .split(':')
                    .next()
                    .unwrap()
                    .to_owned(),
                r.url.path().to_owned(),
                r.headers.get("x-api-key").is_some(),
                r.headers.get("cookie").is_some(),
                header_of(r, "user-agent").unwrap(),
            )
        })
        .collect();
    let expected = [
        ("a.test", "/away", true, true),
        ("other.test", "/page", false, false),
        ("a.test", "/sub", true, true),
        ("www.a.test", "/page", true, true),
        ("other.test", "/page", false, false),
    ];
    assert_eq!(by_host_path.len(), expected.len(), "{by_host_path:?}");
    for ((host, p, key, cookie, ua), (eh, ep, ek, ec)) in by_host_path.iter().zip(expected) {
        assert_eq!(
            (host.as_str(), p.as_str(), *key, *cookie),
            (eh, ep, ek, ec),
            "{by_host_path:?}"
        );
        assert_eq!(ua, "crawlx-test-ua/1");
    }
}

#[tokio::test]
async fn cookies_honour_their_domain_and_path() {
    let server = ok_server().await;
    Mock::given(method("GET"))
        .and(path("/app/x"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let c = controls(|f| {
        f.extra_headers = Default::default();
        f.cookies = vec![
            FetchCookie {
                path: Some("/app".to_owned()),
                ..FetchCookie::new("scoped", "1")
            },
            FetchCookie {
                domain: Some("other.test".to_owned()),
                ..FetchCookie::new("foreign", "2")
            },
            FetchCookie::new("everywhere", "3"),
        ];
    })
    .await;
    let f = fetcher(
        fast_config().with_controls(c),
        allow_private_policy(&server),
        resolver(&["a.test", "other.test"]),
    );
    f.fetch(&url("a.test", &server, "/page"), &FetchOptions::default())
        .await
        .unwrap();
    f.fetch(&url("a.test", &server, "/app/x"), &FetchOptions::default())
        .await
        .unwrap();
    f.fetch(&url("other.test", &server, "/page"), &FetchOptions::default())
        .await
        .unwrap();
    let cookies: Vec<Option<String>> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| header_of(r, "cookie"))
        .collect();
    assert_eq!(
        cookies,
        [
            Some("everywhere=3".to_owned()),
            Some("scoped=1; everywhere=3".to_owned()),
            Some("foreign=2".to_owned()),
        ]
    );
}

#[tokio::test]
async fn per_request_headers_override_configured_ones() {
    let server = ok_server().await;
    let cfg = fast_config().with_controls(controls(|_| {}).await);
    let f = fetcher(cfg, allow_private_policy(&server), resolver(&["a.test"]));
    let mut opts = FetchOptions::default();
    opts.headers
        .insert("x-api-key", HeaderValue::from_static("per-request"));
    opts.headers
        .insert(header::COOKIE, HeaderValue::from_static("explicit=1"));
    opts.headers.insert("x-extra", HeaderValue::from_static("e"));
    f.fetch(&url("a.test", &server, "/page"), &opts).await.unwrap();
    let req = &server.received_requests().await.unwrap()[0];
    assert_eq!(header_of(req, "x-api-key").as_deref(), Some("per-request"));
    assert_eq!(header_of(req, "cookie").as_deref(), Some("explicit=1"));
    assert_eq!(header_of(req, "x-extra").as_deref(), Some("e"));
    assert_eq!(req.headers.get_all("x-api-key").iter().count(), 1);
}

#[tokio::test]
async fn capture_channel_never_sees_a_configured_value() {
    use crawlx_core::traffic::ProxyFlow;
    let server = MockServer::start().await;
    // a server that echoes the key back in a response header must not leak it either
    Mock::given(method("GET"))
        .and(path("/page"))
        .respond_with(ResponseTemplate::new(200).insert_header("x-echo", format!("seen {KEY}")))
        .mount(&server)
        .await;
    let cfg = fast_config().with_controls(controls(|_| {}).await);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProxyFlow>(8);
    let f = fetcher(cfg, allow_private_policy(&server), resolver(&["a.test"])).with_capture(tx);
    f.fetch(&url("a.test", &server, "/page"), &FetchOptions::default())
        .await
        .unwrap();
    let flow = rx.recv().await.unwrap();
    let text = format!("{flow:?}");
    assert!(!text.contains(KEY) && !text.contains(SID), "{text}");
    let find = |hs: &[(String, String)], n: &str| hs.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
        find(&flow.request_headers, "x-api-key").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    assert_eq!(
        find(&flow.request_headers, "cookie").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    assert_eq!(
        find(&flow.response_headers, "x-echo").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
}

#[tokio::test]
async fn fetcher_and_config_debug_never_print_values() {
    let server = ok_server().await;
    let cfg = fast_config().with_controls(controls(|_| {}).await);
    let text = format!("{cfg:?}");
    assert!(!text.contains(KEY) && !text.contains(SID), "{text}");
    let f = fetcher(cfg, allow_private_policy(&server), resolver(&["a.test"]));
    let text = format!("{f:?}");
    assert!(!text.contains(KEY) && !text.contains(SID), "{text}");
}

#[tokio::test]
async fn an_invalid_header_name_is_rejected_when_the_fetcher_is_built() {
    let mut fetch = Fetch::default();
    fetch.extra_headers.insert("bad name", "v");
    let c = RequestControls::resolve(&fetch, "a.test", None).await.unwrap();
    let err = Fetcher::new(
        FetchConfig::default().with_controls(c),
        Arc::new(EgressPolicy::new(true)),
        resolver(&[]),
    )
    .unwrap_err();
    assert!(
        matches!(&err, FetchError::InvalidHeader { name } if name == "bad name"),
        "{err}"
    );
    assert_eq!(err.code(), "invalid_header");
}

#[test]
fn robots_user_agent_precedence() {
    let version = env!("CARGO_PKG_VERSION");
    let base = FetchConfig::default();
    assert_eq!(base.robots_user_agent(), format!("crawlx/{version}"));
    let mut fetch = Fetch {
        user_agent: Some("Agent/5.0 custom".to_owned()),
        ..Fetch::default()
    };
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    let with_ua = FetchConfig::default().with_controls(
        rt.block_on(RequestControls::resolve(&fetch, "a.test", None))
            .unwrap(),
    );
    assert_eq!(with_ua.user_agent(), "Agent/5.0 custom");
    assert_eq!(with_ua.robots_user_agent(), "Agent/5.0 custom");
    fetch.robots_user_agent = Some("crawlx-bot".to_owned());
    let with_robots = FetchConfig::default().with_controls(
        rt.block_on(RequestControls::resolve(&fetch, "a.test", None))
            .unwrap(),
    );
    assert_eq!(with_robots.user_agent(), "Agent/5.0 custom");
    assert_eq!(with_robots.robots_user_agent(), "crawlx-bot");
}

/// HTTPS server presenting the self-signed fixture certificate (SAN `localhost`, `127.0.0.1`).
async fn tls_server() -> (u16, tokio::task::JoinHandle<()>) {
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;

    let certs: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(include_bytes!("fixtures/selfsigned.crt"))
            .collect::<Result<_, _>>()
            .unwrap();
    let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/selfsigned.key")).unwrap();
    let config =
        ServerConfig::builder_with_provider(Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let svc = service_fn(|req: hyper::Request<hyper::body::Incoming>| async move {
                    let ua = req
                        .headers()
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Full::new(
                        bytes::Bytes::from(format!("secure {ua}")),
                    )))
                });
                let _ = Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), svc)
                    .await;
            });
        }
    });
    (port, task)
}

#[tokio::test]
async fn tls_verification_is_enforced_unless_skipped() {
    let (port, task) = tls_server().await;
    let target = url::Url::parse(&format!("https://localhost:{port}/")).unwrap();
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.push(port);
    let policy = Arc::new(policy);

    let strict = Fetcher::new(fast_config(), Arc::clone(&policy), resolver(&["localhost"])).unwrap();
    let err = strict.fetch(&target, &FetchOptions::default()).await.unwrap_err();
    assert!(matches!(err, FetchError::Transport(_)), "{err}");
    assert!(err.to_string().to_ascii_lowercase().contains("cert"), "{err}");

    let fetch = Fetch {
        skip_tls_verification: true,
        ..Fetch::default()
    };
    let controls = RequestControls::resolve(&fetch, "localhost", None).await.unwrap();
    let lax = Fetcher::new(
        fast_config().with_controls(controls),
        Arc::clone(&policy),
        resolver(&["localhost"]),
    )
    .unwrap();
    let r = lax.fetch(&target, &FetchOptions::default()).await.unwrap();
    assert_eq!(r.status.as_u16(), 200);
    assert!(String::from_utf8_lossy(&r.body).starts_with("secure crawlx/"));
    task.abort();
}

/// The browser plane's egress proxy forwards the real values and masks them (configured
/// header names, and any header echoing a configured value, in either direction) in the
/// flows it reports.
#[tokio::test]
async fn egress_proxy_capture_masks_configured_values() {
    use crawlx_core::traffic::ProxyFlow;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).insert_header("x-echo", format!("seen {KEY}")))
        .mount(&server)
        .await;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ProxyFlow>(8);
    let proxy = crawlx_fetch::EgressProxy::serve_with_capture_and_controls(
        Arc::new(EgressPolicy::new(true)),
        resolver(&["pub.test"]),
        tx,
        controls(|_| {}).await,
    )
    .await
    .unwrap();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy.port())).unwrap())
        .build()
        .unwrap();
    let port = server.address().port();
    let resp = client
        .get(format!("http://pub.test:{port}/x"))
        .header("x-api-key", KEY)
        .header("x-via", format!("hop {SID}"))
        .header("x-keep", "keep-me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    // forwarded traffic is untouched
    let upstream = &server.received_requests().await.unwrap()[0];
    assert_eq!(header_of(upstream, "x-api-key").as_deref(), Some(KEY));
    assert_eq!(
        header_of(upstream, "x-via").as_deref(),
        Some(&*format!("hop {SID}"))
    );

    let flow = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("a flow within 5 s")
        .expect("capture channel open");
    let text = format!("{flow:?}");
    assert!(!text.contains(KEY) && !text.contains(SID), "{text}");
    let find = |hs: &[(String, String)], n: &str| hs.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
        find(&flow.request_headers, "x-api-key").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    assert_eq!(
        find(&flow.request_headers, "x-via").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    assert_eq!(find(&flow.request_headers, "x-keep").as_deref(), Some("keep-me"));
    assert_eq!(
        find(&flow.response_headers, "x-echo").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
}
