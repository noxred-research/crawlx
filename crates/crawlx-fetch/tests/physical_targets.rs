//! Checked physical-target admission across native HTTP and browser proxy routes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_fetch::resolver::CheckedResolution;
use crawlx_fetch::{
    EgressOptions, EgressProxy, FetchConfig, FetchOptions, Fetcher, GlobalOriginCap, GovernorConfig,
    StaticResolver,
};
use crawlx_policy::EgressPolicy;
use std::future::{poll_fn, Future};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use url::Url;

const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
const PUBLIC: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34));

struct BodyGate {
    addr: SocketAddr,
    request: oneshot::Receiver<String>,
    release: oneshot::Sender<()>,
    tasks: JoinSet<()>,
}

async fn body_gate() -> BodyGate {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request) = oneshot::channel();
    let (release, release_rx) = oneshot::channel();
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        request_tx.send(String::from_utf8(bytes).unwrap()).unwrap();
        let _ = release_rx.await;
        let _ = stream.write_all(b"ok").await;
    });
    BodyGate {
        addr,
        request,
        release,
        tasks,
    }
}

async fn checked_alias(ip: IpAddr) -> CheckedResolution {
    CheckedResolution::resolve(
        &StaticResolver::new().with("alias.test", [ip]),
        &EgressPolicy::new(true),
        &Url::parse("http://alias.test/").unwrap(),
    )
    .await
    .unwrap()
}

async fn assert_occupied(cap: &GlobalOriginCap, target: &CheckedResolution) {
    let waiting = cap.acquire_physical(target);
    tokio::pin!(waiting);
    assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
}

#[tokio::test]
async fn http_checks_target_capacity_on_direct_and_distinct_proxy_routes() {
    for proxied in [false, true] {
        let gate = body_gate().await;
        let cap = Arc::new(GlobalOriginCap::new(1));
        let target_ip = if proxied { PUBLIC } else { LOOPBACK };
        let target_port = if proxied { 80 } else { gate.addr.port() };
        let mut policy = EgressPolicy::new(true);
        policy.extra_ports.push(gate.addr.port());
        let resolver = Arc::new(StaticResolver::new().with("target.test", [target_ip]));
        let mut config = FetchConfig {
            shared_origin_cap: Some(Arc::clone(&cap)),
            governor: GovernorConfig {
                base_delay: Duration::ZERO,
                ..GovernorConfig::default()
            },
            proxy: proxied.then(|| Url::parse(&format!("http://{}/", gate.addr)).unwrap()),
            ..FetchConfig::default()
        };
        config.retry.max_retries = 0;
        let fetcher = Fetcher::new(config, Arc::new(policy), resolver).unwrap();
        let url = Url::parse(&format!("http://target.test:{target_port}/held")).unwrap();
        let mut requests = JoinSet::new();
        requests.spawn(async move {
            let response = fetcher.fetch(&url, &FetchOptions::default()).await.unwrap();
            assert_eq!(response.status.as_u16(), 200);
        });
        let seen = gate.request.await.unwrap();
        assert!(seen.contains("/held"));
        let alias = checked_alias(target_ip).await;
        assert_occupied(&cap, &alias).await;
        if proxied {
            // The proxy endpoint is not the physical target's identity.
            let endpoint = checked_alias(LOOPBACK).await;
            let free = cap.acquire_physical(&endpoint);
            tokio::pin!(free);
            assert!(poll_fn(|cx| Poll::Ready(free.as_mut().poll(cx).is_ready())).await);
        }
        gate.release.send(()).unwrap();
        requests.join_next().await.unwrap().unwrap();
        let mut server_tasks = gate.tasks;
        server_tasks.join_next().await.unwrap().unwrap();
        drop(cap.acquire_physical(&alias).await);
    }
}

#[tokio::test]
#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary: a raw reqwest client plays the browser against the egress proxy and never crosses a typed fetch boundary"
)]
async fn browser_forward_holds_capacity_without_capture_and_ignores_source_host_header() {
    let gate = body_gate().await;
    let cap = Arc::new(GlobalOriginCap::new(1));
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.push(gate.addr.port());
    let proxy = EgressProxy::serve_with(
        Arc::new(policy),
        Arc::new(StaticResolver::new().with("target.test", [LOOPBACK])),
        EgressOptions::new().with_global_cap(Arc::clone(&cap)),
    )
    .await
    .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::http(format!("http://127.0.0.1:{}", proxy.port())).unwrap())
        .build()
        .unwrap();
    let response = client
        .get(format!("http://target.test:{}/held", gate.addr.port()))
        .header("host", "unrelated.test")
        .send()
        .await
        .unwrap();
    // A refusal answers immediately with a status; the gate would never see a request.
    assert_eq!(response.status().as_u16(), 200);
    let _ = gate.request.await.unwrap();
    let alias = checked_alias(LOOPBACK).await;
    assert_occupied(&cap, &alias).await;
    gate.release.send(()).unwrap();
    assert_eq!(response.text().await.unwrap(), "ok");
    drop(cap.acquire_physical(&alias).await);
    let mut tasks = gate.tasks;
    tasks.join_next().await.unwrap().unwrap();
    proxy.shutdown().await;
}

#[tokio::test]
async fn browser_tunnel_retains_checked_alias_capacity_until_connection_closes() {
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = destination.local_addr().unwrap().port();
    let cap = Arc::new(GlobalOriginCap::new(1));
    let mut policy = EgressPolicy::new(true);
    policy.extra_ports.push(port);
    let proxy = EgressProxy::serve_with(
        Arc::new(policy),
        Arc::new(StaticResolver::new().with("tunnel.test", [LOOPBACK])),
        EgressOptions::new().with_global_cap(Arc::clone(&cap)),
    )
    .await
    .unwrap();
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port())).await.unwrap();
    stream
        .write_all(format!("CONNECT tunnel.test:{port} HTTP/1.1\r\nHost: forged.test\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await.unwrap());
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "tunnel refused: {}",
        String::from_utf8_lossy(&head)
    );
    let alias = checked_alias(LOOPBACK).await;
    assert_occupied(&cap, &alias).await;
    let (upstream, _) = destination.accept().await.unwrap();
    drop(stream);
    drop(upstream);
    drop(
        tokio::time::timeout(Duration::from_secs(5), cap.acquire_physical(&alias))
            .await
            .unwrap(),
    );
    proxy.shutdown().await;
}

#[tokio::test]
async fn mapped_ipv4_candidates_share_one_physical_slot_without_self_deadlock() {
    let ip = IpAddr::from([10, 1, 1, 1]);
    let mapped: IpAddr = "::ffff:10.1.1.1".parse().unwrap();
    let mut policy = EgressPolicy::new(false);
    policy.extra_allow.push("10.0.0.0/8".parse().unwrap());
    let resolver = StaticResolver::new().with("dual.test", [mapped, ip]);
    let target = CheckedResolution::resolve(&resolver, &policy, &Url::parse("http://dual.test/").unwrap())
        .await
        .unwrap();
    let cap = GlobalOriginCap::new(1);
    let acquiring = cap.acquire_physical(&target);
    tokio::pin!(acquiring);
    let Poll::Ready(held) = poll_fn(|cx| Poll::Ready(acquiring.as_mut().poll(cx))).await else {
        panic!("equivalent address forms must not consume two slots");
    };
    let alias = checked_alias(ip).await;
    assert_occupied(&cap, &alias).await;
    drop(held);
    drop(cap.acquire_physical(&alias).await);
}
