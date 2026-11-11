//! Projection events from the normal worker driver, real Chromium, and checked loopback egress.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with;
use crawlx_core::browser_capture::BrowserEvidenceConfig;
use crawlx_core::browser_projection::{BrowserProjection, CaptureAvailability};
use crawlx_core::config::CrawlMode;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;
use std::time::Duration;

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn run(enabled: bool) -> Option<(tempfile::TempDir, Vec<crawlx_core::repo::RunEvent>)> {
    let executable = std::env::var_os("CRAWLX_CHROMIUM_PATH")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap());
    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(|| async {
                axum::response::Html(
                    r#"<!doctype html><html><head><title>Projection worker fixture</title></head>
            <body><h1>Projection worker fixture</h1><p id="state">Loading</p><script>
            (async () => {
              await (await fetch('/api/one')).text();
              await (await fetch('/api/two')).text();
              await (await fetch('/excluded')).text();
              document.querySelector('#state').textContent = 'Ready';
              console.log('public worker projection diagnostic');
            })();</script></body></html>"#,
                )
            }),
        )
        .route(
            "/api/one",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"message":"public one"})) }),
        )
        .route(
            "/api/two",
            axum::routing::get(|| async { axum::Json(serde_json::json!({"message":"public two"})) }),
        )
        .route("/excluded", axum::routing::get(|| async { "excluded" }));
    let _server = Server(tokio::spawn(
        async move { axum::serve(listener, app).await.unwrap() },
    ));
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(base.parse().unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.dynamic.observe_only = true;
    crawl.seed = Some(26_111_102);
    crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.limits.states = 1;
    crawl.limits.duration_seconds = 30;
    if enabled {
        crawl.capture.response_bodies = crawlx_core::config::ResponseBodies::Full;
        crawl.capture.browser = serde_json::from_value::<BrowserEvidenceConfig>(serde_json::json!({
            "xhr": {"urlPatterns": ["*/api/*"], "maxRecords": 2, "maxBytes": 65536},
            "diagnostics": {"maxRecords": 10, "maxBytes": 65536}
        }))
        .unwrap();
    }
    let mut config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            extra_allow: vec!["127.0.0.1/32".parse().unwrap()],
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    config.launch.executable = executable.into();
    config.launch.allow_unpinned = true;
    let report = tokio::time::timeout(
        Duration::from_secs(60),
        run_authorized_local_with(LocalRun::new(crawl, config).with_stores(stores.clone())),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!report.states.is_empty());
    let mut events = Vec::new();
    let mut after = 0;
    loop {
        let batch = stores.events.list_after(report.run_id, after, 64).await.unwrap();
        if batch.is_empty() {
            break;
        }
        after = batch.last().unwrap().seq;
        events.extend(
            batch
                .into_iter()
                .filter(|event| event.kind == "browser.projection"),
        );
    }
    Some((dir, events))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn normal_worker_observation_persists_bounded_projection_event() {
    let Some((_dir, events)) = run(true).await else {
        return;
    };
    assert!(!events.is_empty(), "normal driver must emit browser.projection");
    let mut saw_both = false;
    for event in events {
        assert!(event.payload["sessionId"].is_string());
        assert!(event.payload["observationSeq"].is_u64());
        let projection: BrowserProjection =
            serde_json::from_value(event.payload["projection"].clone()).unwrap();
        assert_eq!(projection.capture_source, "cdp");
        assert_eq!(
            projection.service_worker_bootstrap,
            CaptureAvailability::UnavailableBeforeTargetAttachment
        );
        let xhr = projection.xhr.unwrap();
        assert!(xhr.records.len() <= 2);
        assert!(xhr.metadata_bytes <= 65536);
        assert!(xhr
            .records
            .iter()
            .all(|record| record.url.contains("/api/") && record.status == Some(200)));
        assert!(xhr.records.windows(2).all(|pair| pair[0].seq < pair[1].seq));
        if xhr.records.len() == 2 {
            assert!(xhr.records[0].url.ends_with("/api/one"));
            assert!(xhr.records[1].url.ends_with("/api/two"));
            assert!(xhr.records.iter().all(
                |record| record.response_body.is_some() && record.body_state.as_deref() == Some("stored")
            ));
            saw_both = true;
        }
        let diagnostics = projection.diagnostics.unwrap();
        assert!(diagnostics.network.metadata_bytes + diagnostics.console.metadata_bytes <= 65536);
    }
    assert!(saw_both, "settled worker observation must include both APIs");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disabled_projection_records_no_projection_event() {
    let Some((_dir, events)) = run(false).await else {
        return;
    };
    assert!(events.is_empty());
}
