//! Observability: the span-to-row join (`crawl_runs.trace_id`,
//! `actions.trace_id`) and the OTLP resource attributes a dedicated worker exports.
//!
//! Tests explore a small scripted site through `run_local_with` over `FakeBackend` and
//! `MemoryStore`, each under its own `tracing` subscriber installed with
//! `tracing::subscriber::set_default`, so tests never share a subscriber and none
//! touches the process-global default. That default is thread-local, which is why the tests
//! run on tokio's `current_thread` flavor: on a multi-thread runtime the worker's spawned
//! tasks would run on threads that never saw the scoped subscriber and every span created
//! there would be disabled.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use bytes::Bytes;
use crawlx_bench::worker_exec::authorize_fixture;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::repo::{ActionJournal, RunRepo};
use crawlx_core::{CreateCrawl, TraceId};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_telemetry::otlp::{self, OtlpConfig};
use crawlx_telemetry::{build_subscriber, LogFormat, TelemetryConfig};
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{any_value, KeyValue};
use parking_lot::Mutex;
use prost::Message as _;
use std::collections::BTreeSet;
use std::sync::Arc;
use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;

const TRACE_EXPORT: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";
const METRICS_EXPORT: &str = "/opentelemetry.proto.collector.metrics.v1.MetricsService/Export";

/// Four pages, three of them reachable by a click from the home page, each linking back.
fn four_page_site() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("about", "About", "/about"))
                .node(FakeAxSpec::link("products", "Products", "/products"))
                .node(FakeAxSpec::link("contact", "Contact", "/contact"))
                .on_click("about", vec![FakeEffect::Navigate("/about".into())])
                .on_click("products", vec![FakeEffect::Navigate("/products".into())])
                .on_click("contact", vec![FakeEffect::Navigate("/contact".into())]),
        )
        .page(
            FakePage::new("https://example.test/about")
                .title("About")
                .node(FakeAxSpec::link("home", "Home", "/"))
                .on_click("home", vec![FakeEffect::Navigate("/".into())]),
        )
        .page(
            FakePage::new("https://example.test/products")
                .title("Products")
                .node(FakeAxSpec::link("home", "Home", "/"))
                .on_click("home", vec![FakeEffect::Navigate("/".into())]),
        )
        .page(
            FakePage::new("https://example.test/contact")
                .title("Contact")
                .node(FakeAxSpec::link("home", "Home", "/"))
                .on_click("home", vec![FakeEffect::Navigate("/".into())]),
        )
}

fn telemetry() -> TelemetryConfig {
    TelemetryConfig {
        format: LogFormat::Json,
        filter: Some("info,crawlx_worker=debug".to_owned()),
        ..TelemetryConfig::default()
    }
}

/// Explore `four_page_site` end to end over `stores` (a dynamic crawl, ten interactions).
async fn explore(stores: Stores, artifacts_dir: &std::path::Path) -> RunReport {
    let backend = Arc::new(FakeBackend::new(four_page_site()));
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(20_261_020);
    crawl.limits.interactions = 10;
    crawl.limits.states = 20;
    let cfg = WorkerConfig {
        artifacts_dir: artifacts_dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    run_local_with(authorize_fixture(
        LocalRun::new(crawl, cfg)
            .with_backend(backend)
            .with_stores(stores),
    ))
    .await
    .unwrap()
}

// ---- span recorder ------------------------------------------------------------------------------

/// `(span name, trace id)` of one span the subscriber created, read from the span's
/// extensions where `TraceIdLayer` (inside `build_subscriber`) put it.
type RecordedSpan = (String, Option<TraceId>);

/// Every span the subscriber created, in creation order.
#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<RecordedSpan>>>);

impl<S> Layer<S> for Recorder
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let trace = ctx
            .span(id)
            .and_then(|span| span.extensions().get::<TraceId>().copied());
        self.0.lock().push((attrs.metadata().name().to_owned(), trace));
    }
}

#[tokio::test]
async fn every_journal_row_joins_a_recorded_span_trace() {
    let recorder = Recorder::default();
    let subscriber = build_subscriber(&telemetry(), std::io::sink)
        .unwrap()
        .with(recorder.clone());
    let _guard = tracing::subscriber::set_default(subscriber);

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(Arc::clone(&store), dir.path()).await.unwrap();
    let report = explore(stores, dir.path()).await;

    let rows = ActionJournal::list(&*store, report.run_id, None).await.unwrap();
    assert!(!rows.is_empty(), "the crawl journaled at least one action");
    let run_trace = RunRepo::get(&*store, report.run_id)
        .await
        .unwrap()
        .trace_id
        .expect("the worker recorded the trace id of its crawl span on the run");

    let recorded = recorder.0.lock().clone();
    let crawl_traces: BTreeSet<TraceId> = recorded
        .iter()
        .filter(|(name, _)| name == "crawl")
        .filter_map(|(_, trace)| *trace)
        .collect();
    assert!(
        crawl_traces.contains(&run_trace),
        "the run's trace id {run_trace} is one of the recorded crawl spans {crawl_traces:?}"
    );
    for row in &rows {
        assert_eq!(
            row.trace_id,
            Some(run_trace),
            "action {} (seq {}) joins the crawl span's trace",
            row.id,
            row.seq
        );
    }
    let count = |name: &str| {
        recorded
            .iter()
            .filter(|(n, trace)| n == name && *trace == Some(run_trace))
            .count()
    };
    let (run_spans, action_spans) = (count("run"), count("action"));
    assert!(run_spans >= 1, "a run span carries the crawl's trace id");
    assert!(action_spans >= 1, "an action span carries the crawl's trace id");
    println!(
        "journal rows: {}, spans recorded: {}, crawl spans: {}, run spans on the run's trace: {run_spans}, \
         action spans on the run's trace: {action_spans}, trace id: {run_trace}",
        rows.len(),
        recorded.len(),
        crawl_traces.len()
    );
}

// ---- OTLP stub collector ------------------------------------------------------------------------

/// `(grpc path, request bytes)` per export call.
type OtlpLog = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// An HTTP/2 server that records every gRPC request body and answers `grpc-status: 0` with an
/// empty response message, which is what `ExportTraceServiceResponse` / `ExportMetricsServiceResponse`
/// encode to.
async fn otlp_stub() -> (String, OtlpLog) {
    let log: OtlpLog = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let served = Arc::clone(&log);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let log = Arc::clone(&served);
            tokio::spawn(async move {
                let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let log = Arc::clone(&log);
                    async move {
                        let path = req.uri().path().to_owned();
                        let body = req.into_body().collect().await.map(|c| c.to_bytes().to_vec());
                        log.lock().push((path, body.unwrap_or_default()));
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                        let frames = vec![
                            Ok::<_, std::convert::Infallible>(Frame::data(Bytes::from_static(&[
                                0, 0, 0, 0, 0,
                            ]))),
                            Ok(Frame::trailers(trailers)),
                        ];
                        let body = StreamBody::new(futures::stream::iter(frames));
                        Ok::<_, std::convert::Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .header("content-type", "application/grpc")
                                .body(body)
                                .unwrap(),
                        )
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (format!("http://{addr}"), log)
}

/// The protobuf messages of a gRPC request body: each frame is one byte "compressed" flag,
/// a 4-byte big-endian length and the message.
fn grpc_messages(body: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        assert!(rest.len() >= 5, "truncated gRPC frame header");
        assert_eq!(rest[0], 0, "uncompressed gRPC frame");
        let len = usize::try_from(u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]])).unwrap();
        let (message, tail) = rest[5..].split_at(len);
        out.push(message);
        rest = tail;
    }
    out
}

fn string_attr<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|kv| kv.key == key)
        .and_then(|kv| kv.value.as_ref())
        .and_then(|v| match &v.value {
            Some(any_value::Value::StringValue(s)) => Some(s.as_str()),
            _ => None,
        })
}

fn has_resource(attrs: &[KeyValue], tenant: &str, run: &str) -> bool {
    string_attr(attrs, "tenant_id") == Some(tenant) && string_attr(attrs, "run_id") == Some(run)
}

/// Configured `run_id` resource attribute. The worker assigns the run id inside
/// `run_local_with`, after the exporter is installed, so the attribute carries a fixed value
/// and the test checks that it arrives verbatim.
const RUN_TAG: &str = "0192f3a0-7c1e-7d4b-9a2e-5f6e1c2b3a40";

#[tokio::test]
async fn otlp_export_carries_tenant_and_run_resource_attributes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(Arc::clone(&store), dir.path()).await.unwrap();
    let tenant = stores.tenant.to_string();

    let (endpoint, otlp_log) = otlp_stub().await;
    let handle = otlp::install(&OtlpConfig {
        endpoint,
        service_name: "crawlx-test".to_owned(),
        resource: vec![
            ("tenant_id".to_owned(), tenant.clone()),
            ("run_id".to_owned(), RUN_TAG.to_owned()),
        ],
    })
    .unwrap()
    .expect("the otlp feature is enabled for this test");
    let subscriber = build_subscriber(&telemetry(), std::io::sink)
        .unwrap()
        .with(handle.layer());
    let _guard = tracing::subscriber::set_default(subscriber);

    let report = explore(stores, dir.path()).await;
    assert!(
        !report.actions.is_empty(),
        "the crawl executed at least one action"
    );

    // Dropping the handle shuts both providers down: the batch span processor exports what
    // is pending and the periodic reader runs a final collect (`SdkMeterProvider::shutdown`).
    tokio::task::spawn_blocking(move || drop(handle)).await.unwrap();

    let exports = otlp_log.lock().clone();
    let mut trace_exports = 0usize;
    let mut metric_exports = 0usize;
    let mut tagged_trace_exports = 0usize;
    let mut tagged_metric_exports = 0usize;
    let mut span_names: BTreeSet<String> = BTreeSet::new();
    let mut metric_names: BTreeSet<String> = BTreeSet::new();
    let mut spans = 0usize;
    for (path, body) in &exports {
        for message in grpc_messages(body) {
            match path.as_str() {
                TRACE_EXPORT => {
                    trace_exports += 1;
                    let req = ExportTraceServiceRequest::decode(message).unwrap();
                    for rs in &req.resource_spans {
                        let attrs = rs
                            .resource
                            .as_ref()
                            .map(|r| r.attributes.as_slice())
                            .unwrap_or_default();
                        assert!(
                            has_resource(attrs, &tenant, RUN_TAG),
                            "trace export resource carries tenant_id and run_id: {attrs:?}"
                        );
                        tagged_trace_exports += 1;
                        for ss in &rs.scope_spans {
                            spans += ss.spans.len();
                            span_names.extend(ss.spans.iter().map(|s| s.name.clone()));
                        }
                    }
                }
                METRICS_EXPORT => {
                    metric_exports += 1;
                    let req = ExportMetricsServiceRequest::decode(message).unwrap();
                    for rm in &req.resource_metrics {
                        let attrs = rm
                            .resource
                            .as_ref()
                            .map(|r| r.attributes.as_slice())
                            .unwrap_or_default();
                        assert!(
                            has_resource(attrs, &tenant, RUN_TAG),
                            "metrics export resource carries tenant_id and run_id: {attrs:?}"
                        );
                        tagged_metric_exports += 1;
                        for sm in &rm.scope_metrics {
                            metric_names.extend(sm.metrics.iter().map(|m| m.name.clone()));
                        }
                    }
                }
                other => panic!("unexpected gRPC path {other}"),
            }
        }
    }
    assert!(trace_exports >= 1, "at least one trace export: {exports:?}");
    assert!(
        tagged_trace_exports >= 1,
        "a trace export with the configured resource"
    );
    assert!(
        span_names.contains("crawl"),
        "a crawl span was exported: {span_names:?}"
    );
    assert!(
        span_names.contains("action"),
        "an action span was exported: {span_names:?}"
    );
    assert!(metric_exports >= 1, "at least one metrics export");
    assert!(
        tagged_metric_exports >= 1,
        "a metrics export with the configured resource"
    );
    assert!(
        metric_names.iter().any(|n| n.starts_with("crawlx.")),
        "the catalog was exported: {metric_names:?}"
    );
    println!(
        "trace exports: {trace_exports} (tagged {tagged_trace_exports}), spans: {spans}, distinct span names: {}, \
         metrics exports: {metric_exports} (tagged {tagged_metric_exports}), metric names: {}",
        span_names.len(),
        metric_names.len()
    );
}

/// Compare correctness data, not generated ids, timestamps, trace ids or exporter defaults.
fn correctness_result(
    report: &RunReport,
    journal: &[crawlx_core::repo::ActionRecord],
    ledger: &[crawlx_core::repo::LedgerRow],
) -> serde_json::Value {
    let key = |key: &crawlx_core::identity::ActionContextKey| {
        let state = report
            .states
            .iter()
            .find(|state| state.cluster == key.state_cluster);
        serde_json::json!({
            "principal": key.principal,
            "route": key.route_template,
            "element": key.element,
            "kind": key.action_kind,
            "input": key.input_class,
            "resource": key.resource_context,
            "cluster_signature": state.map(|state| &state.signature),
        })
    };
    let mut actions: Vec<_> = journal
        .iter()
        .map(|row| {
            serde_json::json!({
                "seq": row.seq,
                "key": key(&row.key),
                "status": row.status,
                "attempt": row.attempt,
                "strategy": row.strategy,
                "strategy_version": row.strategy_version,
                "epoch": row.epoch,
                "lane": row.lane,
                "fidelity": row.fidelity,
                "resolution": row.reconcile_resolution,
            })
        })
        .collect();
    let mut ledger: Vec<_> = ledger
        .iter()
        .map(|row| {
            serde_json::json!({
                "key": key(&row.key),
                "trusted": row.trusted_exercised,
                "diagnostic": row.diagnostic_exercised,
                "failures": row.failures,
            })
        })
        .collect();
    let mut states: Vec<_> = report.states.iter().map(|state| &state.signature).collect();
    let mut pages: Vec<_> = report
        .pages
        .iter()
        .map(|page| (&page.url.url, page.status))
        .collect();
    actions.sort_by_cached_key(serde_json::Value::to_string);
    ledger.sort_by_cached_key(serde_json::Value::to_string);
    states.sort_by_cached_key(|signature| serde_json::to_string(signature).unwrap());
    pages.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()).then(a.1.cmp(&b.1)));
    serde_json::json!({
        "status": report.status,
        "terminal_reason": report.terminal_reason,
        "counters": report.counters,
        "actions": actions,
        "ledger": ledger,
        "states": states,
        "pages": pages,
    })
}

async fn explore_with_collector(endpoint: String) -> serde_json::Value {
    use crawlx_bench::trail::{verify_trail, TrailStore};
    let handle = otlp::install(&OtlpConfig {
        endpoint,
        service_name: "crawlx-outage-contract".to_owned(),
        resource: vec![("workload".to_owned(), "deterministic-fake".to_owned())],
    })
    .unwrap()
    .expect("the otlp feature is enabled for this test");
    let subscriber = build_subscriber(&telemetry(), std::io::sink)
        .unwrap()
        .with(handle.layer());
    let guard = tracing::subscriber::set_default(subscriber);
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(Arc::clone(&store), dir.path()).await.unwrap();
    let artifacts = Arc::clone(&stores.artifacts);
    let report = explore(stores, dir.path()).await;
    let journal = ActionJournal::list(store.as_ref(), report.run_id, None)
        .await
        .unwrap();
    let ledger = crawlx_core::repo::LedgerRepo::list(store.as_ref(), report.run_id)
        .await
        .unwrap();
    assert!(
        !journal.is_empty(),
        "workload must exercise the durable action journal"
    );
    assert!(!ledger.is_empty(), "workload must exercise the coverage ledger");
    assert_eq!(journal, report.actions, "report must reflect stored journal");
    assert_eq!(ledger, report.ledger, "report must reflect stored ledger");
    let trail = verify_trail(
        report.run_id,
        TrailStore::Memory {
            store: store.as_ref(),
            artifacts: Some(artifacts.as_ref()),
        },
    )
    .await
    .unwrap();
    assert!(trail.is_clean(), "{trail}");
    let result = correctness_result(&report, &journal, &ledger);
    drop(guard);
    // Force a real export attempt for both endpoints, rather than depending on tick defaults.
    tokio::task::spawn_blocking(move || drop(handle)).await.unwrap();
    result
}

#[tokio::test]
async fn unavailable_otlp_collector_does_not_change_crawl_or_ledger_results() {
    let (reachable, received) = otlp_stub().await;
    let baseline = explore_with_collector(reachable).await;
    {
        let exports = received.lock();
        assert!(exports.iter().any(|(path, _)| path == TRACE_EXPORT));
        assert!(exports.iter().any(|(path, _)| path == METRICS_EXPORT));
    }

    // Reserve a TCP port without listening, so no other process can become its collector.
    let unavailable = tokio::net::TcpSocket::new_v4().unwrap();
    unavailable.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let address = unavailable.local_addr().unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    let outage = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        explore_with_collector(format!("http://{address}")),
    )
    .await
    .expect("collector outage must not prevent crawl completion or exporter shutdown");
    assert_eq!(
        outage, baseline,
        "OTLP availability must not change correctness data"
    );
    drop(unavailable);
}
