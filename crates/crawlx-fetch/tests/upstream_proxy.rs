//! The egress proxy chained to an operator proxy (`fetch.proxy`): the request still passes the
//! egress policy and then reaches the target through the upstream proxy with its credentials.
//! The upstream proxies here are in-process: a hyper HTTP proxy and a SOCKS5 server.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use bytes::Bytes;
use common::LOOPBACK;
use crawlx_fetch::{
    EgressOptions, EgressProxy, EgressProxyHandle, StaticResolver, UpstreamProxy, DENIED_HEADER,
};
use crawlx_policy::egress::{DenyRule, EgressPolicy};
use http::{header, Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `Basic base64("operator:p@ss word")`, the credentials every upstream below demands.
const OPERATOR_AUTH: &str = "Basic b3BlcmF0b3I6cEBzcyB3b3Jk";
const OPERATOR_URL_USERINFO: &str = "operator:p%40ss%20word";

/// What an upstream proxy saw.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    /// Request target as sent (absolute-form for plain HTTP, `host:port` for `CONNECT`).
    target: String,
    method: String,
    proxy_authorization: Option<String>,
    host: Option<String>,
}

/// Host names the "operator's network" resolves; the egress proxy's own resolver is separate.
type Routes = Arc<BTreeMap<String, SocketAddr>>;

struct HttpUpstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
}

/// An HTTP proxy that requires [`OPERATOR_AUTH`]: plain requests are answered itself
/// (`via upstream: <uri>`), `CONNECT` tunnels to the routed address.
async fn http_upstream(routes: Routes) -> HttpUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let (log, routes) = (Arc::clone(&log), Arc::clone(&routes));
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let (log, routes) = (Arc::clone(&log), Arc::clone(&routes));
                    async move { Ok::<_, Infallible>(upstream_answer(req, &log, &routes)) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });
    HttpUpstream { addr, seen }
}

fn upstream_answer(req: Request<Incoming>, log: &Mutex<Vec<Seen>>, routes: &Routes) -> Response<Full<Bytes>> {
    let header_of = |name: header::HeaderName| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let seen = Seen {
        target: req.uri().to_string(),
        method: req.method().to_string(),
        proxy_authorization: header_of(header::PROXY_AUTHORIZATION),
        host: header_of(header::HOST),
    };
    let authorized = seen.proxy_authorization.as_deref() == Some(OPERATOR_AUTH);
    log.lock().push(seen.clone());
    let mut resp = Response::new(Full::new(Bytes::new()));
    if !authorized {
        *resp.status_mut() = StatusCode::PROXY_AUTHENTICATION_REQUIRED;
        resp.headers_mut().insert(
            header::PROXY_AUTHENTICATE,
            "Basic realm=\"upstream\"".parse().unwrap(),
        );
        return resp;
    }
    if req.method() == Method::CONNECT {
        let target = req.uri().authority().map(ToString::to_string).unwrap_or_default();
        let Some(dest) = routes.get(target.rsplit_once(':').map_or(target.as_str(), |(h, _)| h)) else {
            *resp.status_mut() = StatusCode::BAD_GATEWAY;
            return resp;
        };
        let dest = *dest;
        tokio::spawn(async move {
            if let Ok(upgraded) = hyper::upgrade::on(req).await {
                if let Ok(mut out) = TcpStream::connect(dest).await {
                    let mut client = TokioIo::new(upgraded);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut out).await;
                }
            }
        });
        return resp;
    }
    *resp.body_mut() = Full::new(Bytes::from(format!("via upstream: {}", seen.target)));
    resp
}

/// What a SOCKS5 upstream saw.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SocksSeen {
    credentials: Option<(String, String)>,
    /// `domain:<name>` or `ip:<addr>`.
    destination: String,
    port: u16,
}

struct SocksUpstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<SocksSeen>>>,
}

/// A SOCKS5 server that requires user/password `operator` / `p@ss word` and tunnels to the
/// routed address (by name or by IP).
async fn socks_upstream(routes: Routes, by_ip: Arc<BTreeMap<IpAddr, SocketAddr>>) -> SocksUpstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let (log, routes, by_ip) = (Arc::clone(&log), Arc::clone(&routes), Arc::clone(&by_ip));
            tokio::spawn(async move {
                let _ = socks_session(&mut s, &log, &routes, &by_ip).await;
            });
        }
    });
    SocksUpstream { addr, seen }
}

async fn socks_session(
    s: &mut TcpStream,
    log: &Mutex<Vec<SocksSeen>>,
    routes: &Routes,
    by_ip: &BTreeMap<IpAddr, SocketAddr>,
) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0x02) {
        s.write_all(&[0x05, 0xFF]).await?;
        return Ok(());
    }
    s.write_all(&[0x05, 0x02]).await?;
    let mut v = [0u8; 2];
    s.read_exact(&mut v).await?;
    let mut user = vec![0u8; usize::from(v[1])];
    s.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    s.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; usize::from(plen[0])];
    s.read_exact(&mut pass).await?;
    let credentials = (String::from_utf8(user).unwrap(), String::from_utf8(pass).unwrap());
    let ok = credentials == ("operator".to_owned(), "p@ss word".to_owned());
    s.write_all(&[0x01, u8::from(!ok)]).await?;
    if !ok {
        return Ok(());
    }
    let mut req = [0u8; 4];
    s.read_exact(&mut req).await?;
    let (destination, dest) = match req[3] {
        0x01 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            let ip = IpAddr::from(b);
            (format!("ip:{ip}"), by_ip.get(&ip).copied())
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            s.read_exact(&mut name).await?;
            let name = String::from_utf8(name).unwrap();
            let dest = routes.get(&name).copied();
            (format!("domain:{name}"), dest)
        }
        other => panic!("unexpected address type {other}"),
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    log.lock().push(SocksSeen {
        credentials: Some(credentials),
        destination,
        port,
    });
    let Some(dest) = dest else {
        s.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Ok(());
    };
    let mut out = TcpStream::connect(dest).await?;
    s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    let _ = tokio::io::copy_bidirectional(s, &mut out).await;
    Ok(())
}

fn resolver() -> Arc<StaticResolver> {
    Arc::new(
        StaticResolver::new()
            .with("pub.test", [LOOPBACK])
            .with("internal.test", [IpAddr::from([10, 0, 0, 7])])
            .with("target.test", [IpAddr::from([93, 184, 216, 34])]),
    )
}

/// Loopback is allowed (the upstream proxies and the mock target live there); every other
/// private range is not.
fn loopback_policy() -> EgressPolicy {
    let mut p = EgressPolicy::new(false);
    p.extra_allow.push("127.0.0.1/32".parse().unwrap());
    p
}

async fn chained_proxy(policy: EgressPolicy, upstream: &str) -> EgressProxyHandle {
    let upstream = UpstreamProxy::from_url(&Url::parse(upstream).unwrap()).unwrap();
    EgressProxy::serve_with(
        Arc::new(policy),
        resolver(),
        EgressOptions::new().with_upstream(upstream),
    )
    .await
    .unwrap()
}

/// A browser-like client of the egress proxy that also sends its own `Proxy-Authorization`.
fn browser(proxy: &EgressProxyHandle) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy.port()))
                .unwrap()
                .basic_auth("browser", "never-forwarded"),
        )
        .build()
        .unwrap()
}

/// `CONNECT authority` through the egress proxy; returns the answer head and the open stream.
async fn connect_through(proxy: &EgressProxyHandle, authority: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy.port())).await.unwrap();
    s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        assert!(s.read(&mut byte).await.unwrap() > 0, "closed: {buf:?}");
        buf.push(byte[0]);
    }
    (String::from_utf8(buf).unwrap(), s)
}

async fn get_over(mut tunnel: TcpStream, host: &str, path: &str) -> String {
    tunnel
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    tunnel.read_to_end(&mut out).await.unwrap();
    String::from_utf8(out).unwrap()
}

async fn target_server() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("from the target"))
        .mount(&server)
        .await;
    server
}

fn routes_to(server: &MockServer) -> Routes {
    Arc::new(BTreeMap::from([("pub.test".to_owned(), *server.address())]))
}

#[tokio::test]
async fn plain_http_is_forwarded_to_the_upstream_in_absolute_form_with_its_credentials() {
    let target = target_server().await;
    let upstream = http_upstream(routes_to(&target)).await;
    let proxy = chained_proxy(
        loopback_policy(),
        &format!(
            "http://{OPERATOR_URL_USERINFO}@127.0.0.1:{}",
            upstream.addr.port()
        ),
    )
    .await;

    let resp = browser(&proxy)
        .get("http://target.test/hello?x=1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.text().await.unwrap(),
        "via upstream: http://target.test/hello?x=1"
    );

    let seen = upstream.seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].target, "http://target.test/hello?x=1");
    assert_eq!(seen[0].host.as_deref(), Some("target.test"));
    assert_eq!(
        seen[0].proxy_authorization.as_deref(),
        Some(OPERATOR_AUTH),
        "the operator's credentials, not the browser's"
    );
    assert_eq!(proxy.denials(), 0);
    assert_eq!(proxy.dialed_hosts(), vec![("target.test".to_owned(), 80)]);
    assert!(
        target.received_requests().await.unwrap().is_empty(),
        "the egress proxy never dialed the target itself"
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn connect_tunnels_through_the_upstream_with_its_credentials() {
    let target = target_server().await;
    let upstream = http_upstream(routes_to(&target)).await;
    let proxy = chained_proxy(
        loopback_policy(),
        &format!(
            "http://{OPERATOR_URL_USERINFO}@127.0.0.1:{}",
            upstream.addr.port()
        ),
    )
    .await;
    let port = target.address().port();

    let (head, tunnel) = connect_through(&proxy, &format!("pub.test:{port}")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let answer = get_over(tunnel, "pub.test", "/x").await;
    assert!(answer.ends_with("from the target"), "{answer}");

    let seen = upstream.seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].method, "CONNECT");
    assert_eq!(seen[0].target, format!("pub.test:{port}"));
    assert_eq!(seen[0].proxy_authorization.as_deref(), Some(OPERATOR_AUTH));
    assert_eq!(proxy.dialed_hosts(), vec![("pub.test".to_owned(), port)]);
    proxy.shutdown().await;
}

#[tokio::test]
async fn the_policy_still_refuses_private_targets_before_the_upstream_sees_anything() {
    let target = target_server().await;
    let upstream = http_upstream(routes_to(&target)).await;
    let proxy = chained_proxy(
        loopback_policy(),
        &format!(
            "http://{OPERATOR_URL_USERINFO}@127.0.0.1:{}",
            upstream.addr.port()
        ),
    )
    .await;

    let resp = browser(&proxy)
        .get("http://internal.test/admin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.headers().get(DENIED_HEADER).unwrap(),
        DenyRule::Private.as_str()
    );
    let (head, _) = connect_through(&proxy, "internal.test:443").await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("x-crawlx-egress-denied: private"),
        "{head}"
    );

    assert!(
        upstream.seen.lock().is_empty(),
        "a refused target never reaches the upstream"
    );
    assert_eq!(proxy.denials(), 2);
    assert!(proxy.dialed_hosts().is_empty());
    proxy.shutdown().await;
}

#[tokio::test]
async fn an_upstream_proxy_on_a_denied_address_is_refused_like_any_target() {
    let target = target_server().await;
    let upstream = http_upstream(routes_to(&target)).await;
    // loopback is NOT exempt here: the proxy host itself is judged
    let proxy = chained_proxy(
        EgressPolicy::new(false),
        &format!(
            "http://{OPERATOR_URL_USERINFO}@127.0.0.1:{}",
            upstream.addr.port()
        ),
    )
    .await;

    let resp = browser(&proxy)
        .get("http://target.test/hello")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.headers().get(DENIED_HEADER).unwrap(),
        DenyRule::Loopback.as_str()
    );
    let (head, _) = connect_through(&proxy, "target.test:443").await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");

    assert!(upstream.seen.lock().is_empty());
    let events = proxy.denied_events();
    assert_eq!(events.len(), 2, "{events:?}");
    assert!(
        events
            .iter()
            .all(|e| e.host == "127.0.0.1" && e.rule == "loopback"),
        "{events:?}"
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn an_upstream_that_demands_other_credentials_fails_the_tunnel_with_a_bad_gateway() {
    let target = target_server().await;
    let upstream = http_upstream(routes_to(&target)).await;
    let proxy = chained_proxy(
        loopback_policy(),
        &format!("http://wrong:secret@127.0.0.1:{}", upstream.addr.port()),
    )
    .await;

    let (head, _) = connect_through(&proxy, &format!("pub.test:{}", target.address().port())).await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(upstream.seen.lock().len(), 1);
    assert!(
        !head.contains("secret") && !head.contains("d3Jvbmc6c2VjcmV0"),
        "credentials must not leak into the answer: {head}"
    );
    proxy.shutdown().await;
}

async fn socks_fixture() -> (MockServer, SocksUpstream) {
    let target = target_server().await;
    let by_ip = Arc::new(BTreeMap::from([(LOOPBACK, *target.address())]));
    let upstream = socks_upstream(routes_to(&target), by_ip).await;
    (target, upstream)
}

#[tokio::test]
async fn socks5h_sends_the_host_name_and_the_credentials() {
    let (target, upstream) = socks_fixture().await;
    let proxy = chained_proxy(
        loopback_policy(),
        &format!(
            "socks5h://{OPERATOR_URL_USERINFO}@127.0.0.1:{}",
            upstream.addr.port()
        ),
    )
    .await;
    let port = target.address().port();

    // CONNECT tunnel
    let (head, tunnel) = connect_through(&proxy, &format!("pub.test:{port}")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(get_over(tunnel, "pub.test", "/x")
        .await
        .ends_with("from the target"));
    // plain HTTP goes out in origin form over the SOCKS tunnel
    let resp = browser(&proxy)
        .get(format!("http://pub.test:{port}/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "from the target");
    let reqs = target.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    assert!(
        reqs.iter()
            .all(|r| !r.headers.contains_key("proxy-authorization")),
        "the browser's proxy credentials must not reach the target"
    );

    let seen = upstream.seen.lock().clone();
    assert_eq!(seen.len(), 2, "{seen:?}");
    for s in &seen {
        assert_eq!(s.destination, "domain:pub.test");
        assert_eq!(s.port, port);
        assert_eq!(
            s.credentials,
            Some(("operator".to_owned(), "p@ss word".to_owned()))
        );
    }
    proxy.shutdown().await;
}

#[tokio::test]
async fn socks5_sends_the_address_the_policy_checked() {
    let (target, upstream) = socks_fixture().await;
    let proxy = chained_proxy(
        loopback_policy(),
        &format!(
            "socks5://{OPERATOR_URL_USERINFO}@127.0.0.1:{}",
            upstream.addr.port()
        ),
    )
    .await;
    let port = target.address().port();

    let (head, tunnel) = connect_through(&proxy, &format!("pub.test:{port}")).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(get_over(tunnel, "pub.test", "/x")
        .await
        .ends_with("from the target"));

    let seen = upstream.seen.lock().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(
        seen[0].destination, "ip:127.0.0.1",
        "the resolved, policy-checked address"
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn a_socks5_proxy_that_cannot_reach_the_target_is_a_bad_gateway() {
    let (_target, upstream) = socks_fixture().await;
    let proxy = chained_proxy(
        loopback_policy(),
        &format!(
            "socks5h://{OPERATOR_URL_USERINFO}@127.0.0.1:{}",
            upstream.addr.port()
        ),
    )
    .await;
    // `target.test` is public for the policy but unknown to the SOCKS server's network
    let (head, _) = connect_through(&proxy, "target.test:443").await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    proxy.shutdown().await;
}
