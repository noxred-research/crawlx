//! The browser plane's egress proxy under an authorization record and the deployment lists:
//! a CONNECT or proxied request to a host outside the record's target, or
//! on the operator blocklist, is refused before any dial, and a reload of the blocklist reaches
//! a proxy that is already serving.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use common::LOOPBACK;
use crawlx_fetch::{EgressProxy, EgressProxyHandle, StaticResolver, DENIED_HEADER};
use crawlx_policy::egress::{DenyRule, EgressPolicy};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::{EgressLists, SharedEgressLists};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn resolver() -> StaticResolver {
    StaticResolver::new()
        .with("in.test", [LOOPBACK])
        .with("out.test", [LOOPBACK])
        .with("takedown.test", [LOOPBACK])
}

/// Policy for a run whose record covers `in.test` only, on the mock server's port.
fn scoped_policy(server: &MockServer) -> EgressPolicy {
    let port = server.address().port();
    let record = sample_record(
        crawlx_core::TenantId::new(),
        chrono::Utc::now(),
        &[format!("http://in.test:{port}").as_str()],
    );
    let mut policy = EgressPolicy::new(true).with_record_scope(record.scope());
    policy.extra_allow = vec!["127.0.0.0/8".parse().unwrap()];
    policy.extra_ports.push(port);
    policy
}

async fn start(policy: EgressPolicy) -> EgressProxyHandle {
    EgressProxy::serve(Arc::new(policy), Arc::new(resolver()))
        .await
        .unwrap()
}

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: a raw reqwest client plays the browser against the egress proxy and never crosses a typed fetch boundary"
)]
fn proxied_client(proxy: &EgressProxyHandle) -> reqwest::Client {
    reqwest::Client::builder()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy.port())).unwrap())
        .build()
        .unwrap()
}

async fn connect_status(proxy: &EgressProxyHandle, authority: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", proxy.port())).await.unwrap();
    s.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut byte).await.unwrap() == 0 {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8(buf).unwrap()
}

#[tokio::test]
async fn a_host_outside_the_records_target_is_refused_before_any_dial() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let proxy = start(scoped_policy(&server)).await;
    let client = proxied_client(&proxy);
    let port = server.address().port();

    let ok = client
        .get(format!("http://in.test:{port}/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200);

    let denied = client
        .get(format!("http://out.test:{port}/x"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status().as_u16(), 403);
    assert_eq!(
        denied.headers().get(DENIED_HEADER).unwrap(),
        DenyRule::AuthorizationScope.as_str()
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "only the in-scope request arrived"
    );
    assert_eq!(proxy.dialed_hosts(), vec![("in.test".to_owned(), port)]);
    assert_eq!(proxy.denials(), 1);
    assert_eq!(proxy.denied_events()[0].rule, "authorization_scope");

    // a tunnel to a third-party host (a CDN, say) is outside the record too
    let head = connect_status(&proxy, &format!("out.test:{port}")).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("authorization_scope"),
        "{head}"
    );
    assert_eq!(proxy.dialed_hosts().len(), 1);
    proxy.shutdown().await;
}

#[tokio::test]
async fn an_operator_blocklist_reload_reaches_a_serving_proxy() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let lists = SharedEgressLists::new(EgressLists::default());
    let mut policy = EgressPolicy::new(true).with_lists(lists.clone());
    policy.extra_ports.push(server.address().port());
    let proxy = start(policy).await;
    let client = proxied_client(&proxy);
    let port = server.address().port();

    let before = client
        .get(format!("http://takedown.test:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(before.status().as_u16(), 200);

    // RB-10 step 5: the owner asked for the host to be taken off the list of targets
    lists.replace(EgressLists::new(None, ["takedown.test"]).unwrap());
    let after = client
        .get(format!("http://www.takedown.test:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(after.status().as_u16(), 403);
    assert_eq!(
        after.headers().get(DENIED_HEADER).unwrap(),
        DenyRule::Blocklist.as_str()
    );
    let again = client
        .get(format!("http://takedown.test:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(again.status().as_u16(), 403);
    assert_eq!(server.received_requests().await.unwrap().len(), 1);

    lists.replace(EgressLists::default());
    let lifted = client
        .get(format!("http://takedown.test:{port}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(lifted.status().as_u16(), 200);
    proxy.shutdown().await;
}
