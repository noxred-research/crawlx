#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Real local HTTP isolation of the pre-promotion fixture path; no Chromium or external network needed.

use axum::routing::get;
use axum::Router;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_core::config::{CrawlMode, StrategyName, System1Mode};
use crawlx_core::{Clock, CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::{EgressProxy, StaticResolver};
use crawlx_policy::EgressPolicy;
use crawlx_worker::fixture_evaluation::FixtureEvaluationHost;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn every_resource_and_redirect_stays_on_the_retained_fixture_listener() {
    let outside_hits = Arc::new(AtomicU64::new(0));
    let outside = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outside_addr = outside.local_addr().unwrap();
    let count = Arc::clone(&outside_hits);
    let outside_app = Router::new().fallback(move || {
        let count = Arc::clone(&count);
        async move {
            count.fetch_add(1, Ordering::Relaxed);
            "outside"
        }
    });
    let outside_stop = CancellationToken::new();
    let stop = outside_stop.clone();
    let outside_task = tokio::spawn(async move {
        axum::serve(outside, outside_app)
            .with_graceful_shutdown(stop.cancelled_owned())
            .await
            .unwrap();
    });

    let owner = FixtureEvaluationHost::bind().unwrap();
    let scope = owner.scope();
    let origin = owner.origin().to_string();
    let destination = format!("http://{outside_addr}/must-not-receive");
    let jump = destination.clone();
    let app = Router::new()
        .route("/allowed", get(|| async { "controlled fixture" }))
        .route(
            "/jump",
            get(move || {
                let jump = jump.clone();
                async move { axum::response::Redirect::temporary(&jump) }
            }),
        );
    let listener = tokio::net::TcpListener::from_std(owner.listener().unwrap()).unwrap();
    let fixture_stop = CancellationToken::new();
    let stop = fixture_stop.clone();
    let fixture_task = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(stop.cancelled_owned())
            .await
            .unwrap();
    });

    let mut policy = EgressPolicy::new(true);
    policy.extra_allow = vec!["127.0.0.0/8".parse().unwrap()];
    // Even explicit wider deployment settings cannot widen the fixture capability.
    policy.extra_ports = vec![owner.origin().port().unwrap(), outside_addr.port()];
    policy.fixture_scope = Some(scope.clone());
    let proxy = EgressProxy::serve(Arc::new(policy), Arc::new(StaticResolver::new()))
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", proxy.addr())).unwrap())
        .redirect(reqwest::redirect::Policy::limited(5))
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(
        client
            .get(format!("{origin}allowed"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        client
            .get(format!("{origin}jump"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    for destination_kind in ["iframe", "script", "image", "empty"] {
        let response = client
            .get(&destination)
            .header("Sec-Fetch-Dest", destination_kind)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 403, "{destination_kind}");
    }
    assert_eq!(outside_hits.load(Ordering::Relaxed), 0);
    assert!(!proxy
        .dialed_hosts()
        .contains(&("127.0.0.1".to_owned(), outside_addr.port())));

    for authority in [
        outside_addr.to_string(),
        format!("127.0.0.1:{}", owner.origin().port().unwrap()),
    ] {
        let mut tunnel = tokio::net::TcpStream::connect(proxy.addr()).await.unwrap();
        tunnel
            .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut status = String::new();
        BufReader::new(tunnel).read_line(&mut status).await.unwrap();
        assert!(status.contains("403"), "{authority}: {status}");
    }

    scope.revoke();
    assert_eq!(
        client
            .get(format!("{origin}allowed"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        403
    );
    assert_eq!(outside_hits.load(Ordering::Relaxed), 0);
    drop(client);
    proxy.shutdown().await;
    fixture_stop.cancel();
    outside_stop.cancel();
    fixture_task.await.unwrap();
    outside_task.await.unwrap();
}

#[tokio::test]
async fn mutable_gym_display_url_cannot_mint_authority_for_another_service() {
    let outside_hits = Arc::new(AtomicU64::new(0));
    let outside = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outside_addr = outside.local_addr().unwrap();
    let count = Arc::clone(&outside_hits);
    let outside_app = Router::new().fallback(move || {
        let count = Arc::clone(&count);
        async move {
            count.fetch_add(1, Ordering::Relaxed);
            "outside"
        }
    });
    let outside_stop = CancellationToken::new();
    let stop = outside_stop.clone();
    let outside_task = tokio::spawn(async move {
        axum::serve(outside, outside_app)
            .with_graceful_shutdown(stop.cancelled_owned())
            .await
            .unwrap();
    });
    let mut gym = GymServer::start_evaluation().await.unwrap();
    let actual = gym.evaluation_origin().unwrap().clone();
    let now = SystemClock.now();
    let origin = actual.origin().ascii_serialization();
    let mut record = crawlx_policy::testkit::sample_record(TenantId::new(), now, &[&origin]);
    record.verified_at = Some(now);
    record.authorized_networks = vec!["127.0.0.1/32".parse().unwrap()];
    let manifest = FixtureManifest::embedded("g01").unwrap();
    let mut crawl = CreateCrawl::new(actual.join("g01/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::System1];
    crawl.dynamic.system1_mode = System1Mode::Advisory;
    crawl.safety.authorization_record_ref = Some(record.id);
    crawl.safety.allow_private_networks = true;
    crawl.limits.duration_seconds = 30;
    crawl.normalize().unwrap();
    gym.base_url = format!("http://{outside_addr}");
    gym.port = outside_addr.port();
    let mut redirected = crawl.clone();
    redirected.seed_url = url::Url::parse(&format!("{}/g01/", gym.base_url)).unwrap();
    assert!(gym.evaluation_permit(&manifest, &redirected, &record).is_err());
    let permit = gym.evaluation_permit(&manifest, &crawl, &record).unwrap();
    assert_eq!(gym.evaluation_origin(), Some(&actual));
    // The public scope accessor must retain the actual listener even after both display fields
    // point at a real foreign HTTP service. Wider deployment settings cannot widen this lease.
    let scope = gym.evaluation_scope().unwrap();
    assert_eq!(scope.origin(), &actual);
    let mut policy = EgressPolicy::new(true);
    policy.extra_allow = vec!["127.0.0.0/8".parse().unwrap()];
    policy.extra_ports = vec![actual.port().unwrap(), outside_addr.port()];
    policy.fixture_scope = Some(scope.clone());
    let proxy = EgressProxy::serve(Arc::new(policy), Arc::new(StaticResolver::new()))
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", proxy.addr())).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let actual_url = actual.join("g01/").unwrap();
    assert_eq!(
        client
            .get(actual_url.clone())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    assert_eq!(
        client.get(&gym.base_url).send().await.unwrap().status().as_u16(),
        403
    );
    assert_eq!(outside_hits.load(Ordering::Relaxed), 0);
    assert_eq!(
        proxy.dialed_hosts(),
        vec![("127.0.0.1".to_owned(), actual.port().unwrap())]
    );
    gym.shutdown().await;
    assert!(permit.check_request(&crawl, &record).is_err());
    assert!(!scope.is_live());
    assert_eq!(
        client.get(actual_url).send().await.unwrap().status().as_u16(),
        403
    );
    assert_eq!(outside_hits.load(Ordering::Relaxed), 0);
    drop(client);
    proxy.shutdown().await;
    outside_stop.cancel();
    outside_task.await.unwrap();
}
