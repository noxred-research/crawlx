//! Local proxy fixtures exercise exact signed targets and private-host exclusions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_fetch::{EgressProxy, EgressProxyHandle, StaticResolver, DENIED_HEADER};
use crawlx_policy::egress::PrivateHostScope;
use crawlx_policy::{AuthorizationRecord, DenyRule, EgressPolicy, ExcludeHosts};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const HOST: &str = "staging.example.test";

fn record(target: &Url) -> AuthorizationRecord {
    let mut record = crawlx_policy::testkit::sample_record(
        "00000000-0000-0000-0000-000000000001".parse().unwrap(),
        "2026-01-01T00:00:00Z".parse().unwrap(),
        &[&target.origin().ascii_serialization()],
    );
    record.id = "00000000-0000-0000-0000-000000000002".parse().unwrap();
    record.authorized_networks = vec!["127.0.0.1/32".parse().unwrap()];
    record
}

async fn proxy(policy: EgressPolicy) -> EgressProxyHandle {
    EgressProxy::serve(
        Arc::new(policy),
        Arc::new(StaticResolver::new().with(HOST, [IpAddr::from([127, 0, 0, 1])])),
    )
    .await
    .unwrap()
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: a raw reqwest client plays the browser against the egress proxy and never crosses a typed fetch boundary"
)]
fn client(proxy: &EgressProxyHandle) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy.port())).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn connect(proxy: &EgressProxyHandle, port: u16) -> (String, TcpStream) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port())).await.unwrap();
    stream
        .write_all(format!("CONNECT {HOST}:{port} HTTP/1.1\r\nHost: {HOST}:{port}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let header = tokio::time::timeout(Duration::from_secs(5), async {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 4096);
            header.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(header).unwrap()
    })
    .await
    .unwrap();
    (header, stream)
}

#[tokio::test]
async fn real_forward_proxy_preserves_prefix_path_and_hostname_denials() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let target = Url::parse(&format!("http://{HOST}:{}/app/page", server.address().port())).unwrap();
    let mut record = record(&target);
    record.origins.clear();
    record.url_prefixes = vec![format!("{}/app/", target.origin().ascii_serialization())];
    record.excluded_paths = vec!["/app/secret/*".to_owned()];
    let policy = EgressPolicy::new(false)
        .with_seed_port(&target)
        .with_private_host_scope(PrivateHostScope::new(&record));
    let allowed_proxy = proxy(policy.clone()).await;
    let proxied = client(&allowed_proxy);
    assert_eq!(
        proxied
            .get(target.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    for path in ["/other/page", "/app/secret/token"] {
        let denied = proxied.get(target.join(path).unwrap()).send().await.unwrap();
        assert_eq!(denied.status().as_u16(), 403);
        assert_eq!(
            denied.headers()[DENIED_HEADER],
            DenyRule::AuthorizationScope.as_str()
        );
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    allowed_proxy.shutdown().await;

    let policy =
        policy.with_host_exclusions(ExcludeHosts::new(&["^staging\\.example\\.test$".to_owned()]).unwrap());
    let denied_proxy = proxy(policy).await;
    let denied = client(&denied_proxy).get(target).send().await.unwrap();
    assert_eq!(denied.status().as_u16(), 403);
    assert_eq!(denied.headers()[DENIED_HEADER], DenyRule::HostExcluded.as_str());
    assert!(denied_proxy.dialed_hosts().is_empty());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    denied_proxy.shutdown().await;
}

#[tokio::test]
async fn connect_checks_exact_https_origin_and_pinned_direct_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let target = Url::parse(&format!("https://{HOST}:{port}/app/page")).unwrap();
    let mut record = record(&target);
    record.origins.clear();
    record.url_prefixes = vec![format!("{}/app/", target.origin().ascii_serialization())];
    let mut policy = EgressPolicy::new(false)
        .with_seed_port(&target)
        .with_private_host_scope(PrivateHostScope::new(&record));
    let wrong_port = if port == 8443 { 8444 } else { 8443 };
    policy.extra_ports.push(wrong_port);
    let origin = target.join("/").unwrap();
    assert!(policy.check_connect_authority(&origin).is_ok());
    assert_eq!(
        policy.check_url(&origin).unwrap_err().rule,
        DenyRule::AuthorizationScope
    );
    let proxy = proxy(policy).await;
    let (header, _) = connect(&proxy, wrong_port).await;
    assert!(header.starts_with("HTTP/1.1 403"), "{header}");
    assert!(header.contains(DenyRule::AuthorizationScope.as_str()));
    assert!(proxy.dialed_hosts().is_empty());

    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut marker = [0u8; 4];
        stream.read_exact(&mut marker).await.unwrap();
        stream.write_all(&marker).await.unwrap();
    });
    let (header, mut stream) = connect(&proxy, port).await;
    assert!(header.starts_with("HTTP/1.1 200"), "{header}");
    stream.write_all(b"ping").await.unwrap();
    let mut marker = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut marker))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&marker, b"ping");
    echo.await.unwrap();
    proxy.shutdown().await;
}
