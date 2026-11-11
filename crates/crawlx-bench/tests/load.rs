//! `crawlx_bench::load` against the API served in-process over a real socket (in-memory
//! repositories, `crawlx_api::run_until`): 200 rps for 20 s over the default route mix, every
//! route's p99 below the metadata-API target (150 ms, defined as a p95
//! alert; asserted at p99 here) with no errors.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_api::auth::generate_key;
use crawlx_api::{run_until, ApiConfig, ApiKeyBootstrap};
use crawlx_bench::load::{self, LoadConfig, Mix};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Metadata-API latency target (ms).
const SLO_MS: f64 = 150.0;

#[allow(
    clippy::disallowed_types,
    reason = "owned loopback fixture transport boundary"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hundred_rps_for_twenty_seconds_stays_under_the_latency_target() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let dir = tempfile::tempdir().unwrap();
    let key = generate_key();
    let cfg = ApiConfig {
        bind: ([127, 0, 0, 1], port).into(),
        database_url: None,
        artifacts_dir: dir.path().to_path_buf(),
        api_keys: vec![ApiKeyBootstrap::new("acme", &key)],
        rate_limit_per_minute: 0,
        webhook_secret: "whsec_x".to_owned(),
        metrics_bind: None,
        ..ApiConfig::default()
    };
    let stop = CancellationToken::new();
    let server = tokio::spawn(run_until(cfg, stop.clone()));
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::new();
    let mut up = false;
    for _ in 0..100 {
        if client.get(format!("{base}/v1/openapi.json")).send().await.is_ok() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(up, "server did not come up");

    let report = load::run(&LoadConfig {
        base_url: base,
        api_key: key,
        rps: 200.0,
        duration: Duration::from_secs(20),
        mix: Mix::default(),
        runs: 5,
        seed: 7,
        ..LoadConfig::default()
    })
    .await
    .unwrap();
    eprintln!("{}", report.markdown());
    stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(10), server).await;

    let total: u64 = report.routes.values().map(|r| r.requests).sum();
    assert!(total >= 3_800, "about 4000 samples expected, got {total}");
    assert_eq!(report.dropped, 0);
    for route in [
        "GET /v1/crawls/{id}",
        "GET /v1/crawls/{id}/pages",
        "GET /v1/crawls/{id}/coverage",
        "POST /v1/crawls",
    ] {
        assert!(report.routes.contains_key(route), "{route} was driven");
    }
    for (route, r) in &report.routes {
        assert_eq!(r.error_rate(), 0.0, "{route}: {r:?}");
        assert!(
            r.p99_ms < SLO_MS,
            "{route}: p99 {:.1} ms >= {SLO_MS} ms",
            r.p99_ms
        );
    }
    assert!(report.max_p99_ms() < SLO_MS);
    assert!(report.error_rate() == 0.0);
}
