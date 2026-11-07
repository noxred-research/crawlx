//! Integration tests of the egress proxy used by the browser plane.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use bytes::Bytes;
use common::LOOPBACK;
use crawlx_core::traffic::{BodyDigest, Protocol, ProxyFlow, ProxyFlowSource, REDACTED_PLACEHOLDER};
use crawlx_fetch::{EgressProxy, EgressProxyHandle, StaticResolver, DENIED_HEADER};
use crawlx_policy::egress::{DenyRule, EgressPolicy};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use wiremock::matchers::{body_string, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn resolver() -> StaticResolver {
    StaticResolver::new()
        .with("pub.test", [LOOPBACK])
        .with("h2.test", [LOOPBACK])
        .with("mixed.test", [IpAddr::from([93, 184, 216, 34]), LOOPBACK])
}

async fn start_proxy_with_capture(allow_private: bool) -> (EgressProxyHandle, mpsc::Receiver<ProxyFlow>) {
    let (tx, rx) = mpsc::channel(64);
    let proxy = EgressProxy::serve_with_capture(
        Arc::new(EgressPolicy::new(allow_private)),
        Arc::new(resolver()),
        tx,
    )
    .await
    .unwrap();
    (proxy, rx)
}

async fn next_flow(rx: &mut mpsc::Receiver<ProxyFlow>) -> ProxyFlow {
    tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .expect("a flow within 5 s")
        .expect("capture channel open")
}

async fn start_proxy(allow_private: bool) -> EgressProxyHandle {
    let resolver = StaticResolver::new()
        .with("pub.test", [LOOPBACK])
        .with("mixed.test", [IpAddr::from([93, 184, 216, 34]), LOOPBACK]);
    EgressProxy::serve(Arc::new(EgressPolicy::new(allow_private)), Arc::new(resolver))
        .await
        .unwrap()
}

fn proxied_client(proxy: &EgressProxyHandle) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy.port())).unwrap())
        .build()
        .unwrap()
}

/// Send raw bytes to the proxy and read until the header block ends.
async fn raw_head(proxy: &EgressProxyHandle, request: &str) -> (String, TcpStream) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy.port())).await.unwrap();
    s.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut byte).await.unwrap();
        assert!(
            n > 0,
            "connection closed before end of headers: {:?}",
            String::from_utf8_lossy(&buf)
        );
        buf.push(byte[0]);
    }
    (String::from_utf8(buf).unwrap(), s)
}

#[tokio::test]
async fn forwards_http_to_pinned_address_when_private_allowed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("via proxy"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/post"))
        .and(body_string("payload"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;
    let proxy = start_proxy(true).await;
    let client = proxied_client(&proxy);
    let port = server.address().port();

    let resp = client
        .get(format!("http://pub.test:{port}/x?q=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.text().await.unwrap(), "via proxy");

    let resp = client
        .post(format!("http://pub.test:{port}/post"))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);

    assert_eq!(proxy.denials(), 0);
    assert_eq!(proxy.dialed_hosts(), vec![("pub.test".to_owned(), port)]);
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(
        reqs[0].headers.get("host").unwrap().to_str().unwrap(),
        format!("pub.test:{port}")
    );
    assert_eq!(reqs[0].url.query(), Some("q=1"));
    assert!(!reqs[0].headers.contains_key("proxy-connection"));
    proxy.shutdown().await;
}

#[tokio::test]
async fn refuses_http_to_private_address_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let proxy = start_proxy(false).await;
    let client = proxied_client(&proxy);
    let port = server.address().port();

    let resp = client
        .get(format!("http://pub.test:{port}/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(
        resp.headers().get(DENIED_HEADER).unwrap(),
        DenyRule::Loopback.as_str()
    );
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "denied request must not reach the target"
    );

    assert_eq!(proxy.denials(), 1);
    let events = proxy.denied_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].host, "pub.test");
    assert_eq!(events[0].port, port);
    assert_eq!(events[0].ip, Some(LOOPBACK));
    assert_eq!(events[0].rule, "loopback");
    assert_eq!(events[0].method, "GET");
    assert!(proxy.dialed_hosts().is_empty(), "a denied target is never dialed");
    proxy.shutdown().await;
}

#[tokio::test]
async fn mixed_answer_is_denied_for_the_whole_name() {
    let proxy = start_proxy(false).await;
    let (head, _s) = raw_head(
        &proxy,
        "CONNECT mixed.test:443 HTTP/1.1\r\nHost: mixed.test:443\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(proxy.denied_events()[0].ip, Some(LOOPBACK));
}

#[tokio::test]
async fn connect_to_denied_hosts_returns_403() {
    let proxy = start_proxy(false).await;
    let denials = Metrics::global().counter(names::EGRESS_DENIALS);
    let metadata = [("plane", "browser"), ("reason", "metadata")];
    let metadata_before = denials.get(&metadata);
    for (target, rule) in [
        ("pub.test:443", "loopback"),
        ("169.254.169.254:80", "metadata"),
        ("localhost:8080", "hostname"),
        ("metadata.google.internal:80", "metadata"),
        ("[::1]:443", "loopback"),
    ] {
        let (head, _s) = raw_head(
            &proxy,
            &format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"),
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 403"), "{target}: {head}");
        let lower = head.to_ascii_lowercase();
        assert!(
            lower.contains(&format!("{DENIED_HEADER}: {rule}")),
            "{target}: {head}"
        );
    }
    assert_eq!(proxy.denials(), 5);
    assert_eq!(proxy.denied_events().len(), 5);
    assert!(proxy.denied_events().iter().all(|e| e.method == "CONNECT"));
    // metrics are process-global; sibling tests deny concurrently, so assert a lower bound
    assert!(
        denials.get(&metadata) >= metadata_before + 2,
        "browser-plane metadata denials counted"
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn connect_tunnels_bytes_to_pinned_address_when_allowed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/t"))
        .respond_with(ResponseTemplate::new(200).set_body_string("tunnelled"))
        .mount(&server)
        .await;
    let proxy = start_proxy(true).await;
    let port = server.address().port();
    let (head, mut s) = raw_head(
        &proxy,
        &format!("CONNECT pub.test:{port} HTTP/1.1\r\nHost: pub.test:{port}\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    s.write_all(format!("GET /t HTTP/1.1\r\nHost: pub.test:{port}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("tunnelled"), "{text}");
    assert_eq!(proxy.denials(), 0);
    assert_eq!(proxy.dialed_hosts(), vec![("pub.test".to_owned(), port)]);
    proxy.shutdown().await;
}

#[tokio::test]
async fn unresolvable_target_is_bad_gateway_not_a_denial() {
    let proxy = start_proxy(true).await;
    let (head, _s) = raw_head(
        &proxy,
        "CONNECT nowhere.test:443 HTTP/1.1\r\nHost: nowhere.test:443\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(proxy.denials(), 0);
}

#[tokio::test]
async fn origin_form_and_https_absolute_requests_are_rejected() {
    let proxy = start_proxy(true).await;
    let (head, _s) = raw_head(&proxy, "GET /plain HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    let (head, _s) = raw_head(&proxy, "GET https://pub.test/ HTTP/1.1\r\nHost: pub.test\r\n\r\n").await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
}

#[tokio::test]
async fn binds_loopback_only_and_stops_on_shutdown() {
    let proxy = start_proxy(false).await;
    assert!(proxy.addr().ip().is_loopback());
    assert_ne!(proxy.port(), 0);
    let port = proxy.port();
    proxy.shutdown().await;
    assert!(TcpStream::connect(("127.0.0.1", port)).await.is_err());
}

#[tokio::test]
async fn capture_reports_one_flow_per_forwarded_request_and_per_tunnel() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/x"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("set-cookie", "sid=server-secret")
                .set_body_string("via proxy"),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/post"))
        .and(body_string("payload"))
        .respond_with(ResponseTemplate::new(201))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/t"))
        .respond_with(ResponseTemplate::new(200).set_body_string("tunnelled"))
        .mount(&server)
        .await;
    let (proxy, mut rx) = start_proxy_with_capture(true).await;
    let client = proxied_client(&proxy);
    let port = server.address().port();

    let before = chrono::Utc::now();
    let resp = client
        .get(format!("http://pub.test:{port}/x?q=1"))
        .header("authorization", "Bearer client-secret")
        .header("cookie", "a=client-secret")
        .header("x-trace", "keep-me")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "via proxy");
    let get = next_flow(&mut rx).await;
    assert_eq!(get.source, ProxyFlowSource::Browser);
    assert_eq!(get.method, "GET");
    assert_eq!(get.url, format!("http://pub.test:{port}/x?q=1"));
    assert_eq!(get.status, Some(200));
    assert_eq!(get.protocol, Protocol::Http11);
    assert!(get.tunnel.is_none());
    assert!(get.peer.unwrap().ip().is_loopback());
    assert!(get.started_at >= before && get.finished_at >= get.started_at);
    let header = |h: &[(String, String)], n: &str| h.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone());
    assert_eq!(
        header(&get.request_headers, "authorization").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    assert_eq!(
        header(&get.request_headers, "cookie").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    assert_eq!(
        header(&get.request_headers, "x-trace").as_deref(),
        Some("keep-me")
    );
    assert_eq!(
        header(&get.response_headers, "set-cookie").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    assert!(!format!("{get:?}").contains("secret"), "{get:?}");
    assert_eq!(get.request_body, None);
    assert_eq!(get.response_body, Some(BodyDigest::of_prefix(b"via proxy", 9)));

    let resp = client
        .post(format!("http://pub.test:{port}/post"))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201);
    let post = next_flow(&mut rx).await;
    assert_eq!(post.method, "POST");
    assert_eq!(post.status, Some(201));
    assert_eq!(post.request_body, Some(BodyDigest::of_prefix(b"payload", 7)));
    assert_eq!(post.response_body, None);

    let (head, mut s) = raw_head(
        &proxy,
        &format!("CONNECT pub.test:{port} HTTP/1.1\r\nHost: pub.test:{port}\r\n\r\n"),
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    s.write_all(format!("GET /t HTTP/1.1\r\nHost: pub.test:{port}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.unwrap();
    drop(s);
    let tunnel = next_flow(&mut rx).await;
    assert_eq!(tunnel.method, "CONNECT");
    assert_eq!(tunnel.url, format!("pub.test:{port}"));
    assert_eq!(tunnel.status, None);
    assert!(tunnel.request_headers.is_empty() && tunnel.response_headers.is_empty());
    let stats = tunnel.tunnel.expect("tunnel stats");
    assert!(stats.bytes_up > 0 && stats.bytes_down > 0, "{stats:?}");
    assert!(stats.bytes_down >= u64::try_from(out.len()).unwrap());

    assert!(rx.try_recv().is_err(), "exactly one flow per request");
    assert_eq!(proxy.capture_dropped(), 0);
    proxy.shutdown().await;
}

#[tokio::test]
async fn full_capture_channel_drops_flows_and_counts_them_without_blocking() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let (tx, _rx) = mpsc::channel(1);
    let proxy = EgressProxy::serve_with_capture(Arc::new(EgressPolicy::new(true)), Arc::new(resolver()), tx)
        .await
        .unwrap();
    let client = proxied_client(&proxy);
    let port = server.address().port();
    for i in 0..3 {
        let r = client
            .get(format!("http://pub.test:{port}/{i}"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200);
        let _ = r.bytes().await.unwrap();
    }
    assert_eq!(proxy.capture_dropped(), 2);
    proxy.shutdown().await;
}

/// Prior-knowledge HTTP/2 origin on loopback; returns its port.
async fn h2_origin() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc =
                    hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| async move {
                        let body = format!("{:?} {}", req.version(), req.uri().path());
                        Ok::<_, Infallible>(http::Response::new(Full::new(Bytes::from(body))))
                    });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    port
}

#[tokio::test]
async fn h2_client_is_forwarded_to_an_h2_origin_and_the_flow_records_h2() {
    let origin = h2_origin().await;
    let (proxy, mut rx) = start_proxy_with_capture(true).await;
    let stream = TcpStream::connect(("127.0.0.1", proxy.port())).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
        TokioExecutor::new(),
        TokioIo::new(stream),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    let req = http::Request::builder()
        .method("GET")
        .uri(format!("http://h2.test:{origin}/h2"))
        .version(http::Version::HTTP_2)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(resp.version(), http::Version::HTTP_2);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"HTTP/2.0 /h2", "the origin saw an HTTP/2 request");

    let flow = next_flow(&mut rx).await;
    assert_eq!(flow.protocol, Protocol::H2);
    assert_eq!(flow.url, format!("http://h2.test:{origin}/h2"));
    assert_eq!(flow.status, Some(200));
    assert_eq!(
        flow.response_body,
        Some(BodyDigest::of_prefix(b"HTTP/2.0 /h2", 12))
    );
    proxy.shutdown().await;
}
