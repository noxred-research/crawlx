//! Capture metrics of the proxy backend, asserted as deltas on the process-global registry:
//! a hybrid run whose URL plane fetches through the capture channel reports the fetch-plane
//! flows as unattributed (`crawlx.traffic.unattributed{reason}`), sets
//! `crawlx.traffic.late_ratio` from the run's own flows and leaves
//! `crawlx.traffic.unmatched_proxy_flows` alone when no browser flow went unclaimed. The
//! tests in this binary are serialized.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_browser::fake::{FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CaptureBackend, CrawlMode};
use crawlx_core::counters::RunStatus;
use crawlx_core::{CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

/// Serializes the tests: every one asserts exact deltas.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn counter(name: &str, labels: &[(&str, &str)]) -> u64 {
    Metrics::global().counter(name).get(labels)
}

fn config(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

/// A hybrid run of the fixture site over the proxy capture backend; the browser plane is the
/// fake backend, which never dials the egress proxy.
async fn proxy_capture_run(base: &str) -> crawlx_worker::RunReport {
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Hybrid;
    crawl.seed = Some(20_261_110);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.limits.interactions = 4;
    crawl.capture.backend = CaptureBackend::Proxy;
    let backend = Arc::new(
        FakeBackend::builder()
            .script(FakeScript::new().page(FakePage::new(&format!("{base}/")).title("Home")))
            .clock(Arc::new(SystemClock))
            .build(),
    );
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let stores = Stores::open(&cfg).await.unwrap();
    run_local_with(
        LocalRun::new(crawl, cfg)
            .with_stores(stores)
            .with_backend(backend),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn a_proxy_capture_run_reports_its_flows_to_the_traffic_metrics() {
    let _serial = SERIAL.lock().await;
    let site = common::site::start().await;
    let fetch_plane = &[("reason", "fetch_plane")];
    let unmatched = &[("reason", "unmatched_proxy_flow")];
    let before = (
        counter(names::TRAFFIC_UNATTRIBUTED, fetch_plane),
        counter(names::TRAFFIC_UNATTRIBUTED, unmatched),
        counter(names::TRAFFIC_UNMATCHED_PROXY_FLOWS, &[]),
    );
    // a stale reading the run must overwrite with its own ratio
    let late_ratio = Metrics::global().gauge(names::TRAFFIC_LATE_RATIO);
    late_ratio.set(0.75, &[]);

    let report = proxy_capture_run(&site.base).await;
    assert_eq!(report.status, RunStatus::Completed);
    let stats = report.capture.proxy.expect("proxy capture statistics");
    assert!(
        stats.flows >= 4,
        "the URL plane fetched the fixture pages through the capture channel: {stats:?}"
    );
    assert!(stats.unattributed >= stats.unmatched, "{stats:?}");

    assert_eq!(
        counter(names::TRAFFIC_UNATTRIBUTED, fetch_plane),
        before.0 + (stats.unattributed - stats.unmatched),
        "{stats:?}"
    );
    assert!(
        stats.unattributed > stats.unmatched,
        "fetch-plane flows carry no epoch: {stats:?}"
    );
    assert_eq!(
        counter(names::TRAFFIC_UNATTRIBUTED, unmatched),
        before.1 + stats.unmatched
    );
    assert_eq!(
        counter(names::TRAFFIC_UNMATCHED_PROXY_FLOWS, &[]),
        before.2 + stats.unmatched
    );
    #[allow(clippy::cast_precision_loss)]
    let ratio = stats.late as f64 / stats.flows as f64;
    let reported = late_ratio.get(&[]).unwrap();
    assert!(
        (reported - ratio).abs() < 1e-9,
        "late_ratio {reported} vs late/flows {ratio}"
    );
}

#[tokio::test]
async fn a_default_capture_backend_leaves_the_traffic_metrics_alone() {
    let _serial = SERIAL.lock().await;
    let site = common::site::start().await;
    let before = (
        crawlx_telemetry::Metrics::global()
            .counter(names::TRAFFIC_UNATTRIBUTED)
            .get(&[("reason", "fetch_plane")]),
        counter(names::TRAFFIC_UNMATCHED_PROXY_FLOWS, &[]),
    );
    let late_ratio = Metrics::global().gauge(names::TRAFFIC_LATE_RATIO);
    late_ratio.set(0.75, &[]);

    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Hybrid;
    crawl.seed = Some(20_261_110);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.limits.interactions = 4;
    crawl.capture.backend = CaptureBackend::Cdp;
    let backend = Arc::new(
        FakeBackend::builder()
            .script(FakeScript::new().page(FakePage::new(&format!("{}/", site.base)).title("Home")))
            .clock(Arc::new(SystemClock))
            .build(),
    );
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let stores = Stores::open(&cfg).await.unwrap();
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_stores(stores)
            .with_backend(backend),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert!(report.capture.proxy.is_none());
    assert_eq!(
        Metrics::global()
            .counter(names::TRAFFIC_UNATTRIBUTED)
            .get(&[("reason", "fetch_plane")]),
        before.0
    );
    assert_eq!(counter(names::TRAFFIC_UNMATCHED_PROXY_FLOWS, &[]), before.1);
    assert_eq!(late_ratio.get(&[]), Some(0.75));
}
