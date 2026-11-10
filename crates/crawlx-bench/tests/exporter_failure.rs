//! Crawl-level OTLP exporter failure: a real static crawl over the gym with trace and metric
//! export pointed at a collector that cannot answer (nothing listening, or a socket that
//! accepts and never replies) completes with the same result as a crawl without export,
//! stays within a bounded time, and the failure is observable.
//!
//! `crawlx-telemetry` registers no export-failure counter: the exporter failure signal is the
//! OpenTelemetry SDK's own internal error event (`opentelemetry_sdk` target, event names
//! `BatchSpanProcessor.ExportError` and `PeriodicReader.ExportError`), emitted on the
//! exporter's background threads. The test installs a process-global subscriber that records
//! those events; the crawl itself runs under a thread-scoped subscriber that carries the
//! export layer. No Chromium and no network beyond loopback.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_telemetry::otlp::{self, OtlpConfig};
use crawlx_telemetry::{build_subscriber, LogFormat, TelemetryConfig};
use crawlx_worker::{run_local_with, LocalRun};
use parking_lot::Mutex;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};

/// Allowed extra wall time of a crawl whose collector is down, over the same crawl without export.
const CRAWL_SLACK: Duration = Duration::from_secs(15);

/// Wall time within which the exporters must shut down after a crawl against a dead collector.
const SHUTDOWN_BOUND: Duration = Duration::from_secs(45);

/// Names of the SDK's internal error events recorded on any thread, in arrival order.
static EXPORT_ERRORS: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[derive(Default)]
struct EventName(Option<String>);

impl Visit for EventName {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "name" {
            self.0 = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "name" && self.0.is_none() {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

/// Records the OpenTelemetry SDK's internal error events.
struct SdkErrors;

impl<S: Subscriber> Layer<S> for SdkErrors {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let meta = event.metadata();
        if *meta.level() != Level::ERROR || !meta.target().starts_with("opentelemetry") {
            return;
        }
        let mut name = EventName::default();
        event.record(&mut name);
        EXPORT_ERRORS
            .lock()
            .push(name.0.unwrap_or_else(|| meta.name().to_owned()));
    }
}

/// The exporters' background threads have no thread-scoped subscriber, so the recorder
/// is the process-global default (installed once for this test binary).
static SDK_ERROR_RECORDER: LazyLock<()> = LazyLock::new(|| {
    let subscriber = tracing_subscriber::registry().with(SdkErrors);
    tracing::subscriber::set_global_default(subscriber)
        .expect("no other global subscriber in this test binary");
});

fn install_sdk_error_recorder() {
    LazyLock::force(&SDK_ERROR_RECORDER);
}

fn export_errors() -> Vec<String> {
    EXPORT_ERRORS.lock().clone()
}

/// Both tests read the process-wide failure record; they run one after the other.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Path and query of a fetched page: the gym's port changes from run to run.
fn page_key(url: &url::Url) -> String {
    match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_owned(),
    }
}

/// What a crawl produced that must not depend on telemetry.
#[derive(PartialEq, Eq, Debug)]
struct Outcome {
    status: String,
    terminal_reason: String,
    counters: String,
    pages: Vec<(String, u16)>,
}

struct Crawl {
    outcome: Outcome,
    elapsed: Duration,
}

/// A static crawl of the `s1` fixture over a fresh gym.
async fn crawl_s1() -> Crawl {
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded("s1").unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, 20_261_019, SafetyProfile::ReadOnly).unwrap();
    req.mode = CrawlMode::Static;
    req.dynamic.enabled = false;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let started = Instant::now();
    let report = run_local_with(authorize_fixture(LocalRun::new(req, cfg)))
        .await
        .unwrap();
    let elapsed = started.elapsed();
    gym.shutdown().await;
    assert!(
        report.counters.urls.invariants_hold(),
        "{:?}",
        report.counters.urls
    );
    let mut pages: Vec<_> = report
        .pages
        .iter()
        .map(|p| (page_key(&p.url.url), p.status))
        .collect();
    pages.sort();
    Crawl {
        outcome: Outcome {
            status: format!("{:?}", report.status),
            terminal_reason: format!("{:?}", report.terminal_reason),
            counters: serde_json::to_string(&report.counters).unwrap(),
            pages,
        },
        elapsed,
    }
}

fn telemetry() -> TelemetryConfig {
    TelemetryConfig {
        format: LogFormat::Json,
        filter: Some("info,crawlx_worker=debug".to_owned()),
        ..TelemetryConfig::default()
    }
}

/// Run the `s1` crawl with trace and metric export to `endpoint`, then shut the exporters down.
async fn crawl_with_export(endpoint: String) -> (Crawl, Duration) {
    let handle = otlp::install(&OtlpConfig {
        endpoint,
        service_name: "crawlx-exporter-failure".to_owned(),
        resource: vec![("workload".to_owned(), "static-s1".to_owned())],
    })
    .unwrap()
    .expect("the otlp feature is enabled for this test");
    let subscriber = build_subscriber(&telemetry(), std::io::sink)
        .unwrap()
        .with(handle.layer());
    let guard = tracing::subscriber::set_default(subscriber);
    let crawl = crawl_s1().await;
    drop(guard);
    // Dropping the handle flushes the batch span processor and runs a final metrics collect:
    // the export attempt against the dead collector happens here at the latest.
    let shutdown_started = Instant::now();
    tokio::task::spawn_blocking(move || drop(handle)).await.unwrap();
    (crawl, shutdown_started.elapsed())
}

#[tokio::test]
async fn unreachable_collector_leaves_the_static_crawl_unchanged_and_reports_the_export_failure() {
    let _serial = SERIAL.lock().await;
    install_sdk_error_recorder();
    let baseline = crawl_s1().await;
    assert!(!baseline.outcome.pages.is_empty(), "the crawl fetched pages");
    assert!(
        baseline.outcome.pages.iter().any(|(_, status)| *status == 200),
        "{:?}",
        baseline.outcome.pages
    );

    // Reserve a TCP port without listening: connecting is refused and no other process
    // can become the collector.
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    reserved.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = reserved.local_addr().unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());

    let before = export_errors().len();
    let (outage, shutdown) = tokio::time::timeout(
        SHUTDOWN_BOUND + CRAWL_SLACK + baseline.elapsed,
        crawl_with_export(format!("http://{address}")),
    )
    .await
    .expect("an unreachable collector must not stall the crawl or exporter shutdown");
    drop(reserved);

    assert_eq!(
        outage.outcome, baseline.outcome,
        "an unreachable collector changed the crawl result"
    );
    assert!(
        outage.elapsed <= baseline.elapsed + CRAWL_SLACK,
        "crawl took {:?} against a dead collector, {:?} without export",
        outage.elapsed,
        baseline.elapsed
    );
    assert!(shutdown <= SHUTDOWN_BOUND, "exporter shutdown took {shutdown:?}");
    let errors = export_errors();
    let new: Vec<_> = errors[before..].to_vec();
    assert!(
        new.iter().any(|name| name.ends_with("ExportError")),
        "no export-failure event was observable after exporting to a dead collector: {new:?}"
    );
}

#[tokio::test]
async fn collector_that_accepts_and_never_answers_does_not_block_the_crawl() {
    let _serial = SERIAL.lock().await;
    install_sdk_error_recorder();
    let baseline = crawl_s1().await;

    // A collector that completes the TCP handshake and then says nothing: every export
    // runs into the exporter's own timeout instead of an immediate refusal.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let blackhole = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });

    let (outage, shutdown) = tokio::time::timeout(
        SHUTDOWN_BOUND + CRAWL_SLACK + baseline.elapsed,
        crawl_with_export(format!("http://{address}")),
    )
    .await
    .expect("a silent collector must not stall the crawl or exporter shutdown");
    blackhole.abort();

    assert_eq!(
        outage.outcome, baseline.outcome,
        "a silent collector changed the crawl result"
    );
    assert!(
        outage.elapsed <= baseline.elapsed + CRAWL_SLACK,
        "crawl took {:?} against a silent collector, {:?} without export",
        outage.elapsed,
        baseline.elapsed
    );
    assert!(shutdown <= SHUTDOWN_BOUND, "exporter shutdown took {shutdown:?}");
}
