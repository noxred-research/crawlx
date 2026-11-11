//! End-to-end browser evidence; real Chromium runs only with explicit operator opt-in.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::run_authorized_local_with;
use crawlx_core::archive::ArchiveConfigV1;
use crawlx_core::archive_catalog::{ArchiveExportState, ArchiveReadV1, ArchiveRecordV1};
use crawlx_core::browser_capture::{BrowserEvidenceConfig, CaptureArtifact, CaptureKind};
use crawlx_core::config::{CrawlMode, RetentionMode};
use crawlx_core::{ArtifactRef, Clock, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

struct EvidenceFixture {
    _dir: tempfile::TempDir,
    stores: Stores,
    events: Vec<crawlx_core::repo::RunEvent>,
    records: Vec<ArchiveRecordV1>,
    run: crawlx_core::repo::CrawlRun,
}

async fn fixture(retention: RetentionMode, mut evidence: BrowserEvidenceConfig) -> Option<EvidenceFixture> {
    let executable = std::env::var_os("CRAWLX_CHROMIUM_PATH")?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    if evidence.durable() {
        evidence
            .downloads
            .push(crawlx_core::browser_download::DownloadSpec::new(
                format!("http://127.0.0.1:{port}/attachment").parse().unwrap(),
                1024,
                10_000,
            ));
    }
    let app = axum::Router::new().route("/", axum::routing::get(|| async {
        axum::response::Html(r#"<!doctype html><title>Evidence fixture</title>
        <style>body{background:white;color:black;font:40px sans-serif}</style>
        <h1 id="value">INITIAL EVIDENCE</h1>
        <button onclick="document.querySelector('#value').textContent='FINAL EVIDENCE';document.body.style.background='yellow';this.remove()">Change</button>"#)
    })).route("/attachment", axum::routing::get(|| async {
        (
            [
                ("content-type", "text/csv"),
                ("content-disposition", "attachment; filename=evidence.csv"),
            ],
            "id,value\n1,download evidence\n",
        )
    }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(format!("http://127.0.0.1:{port}/").parse().unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(26_111_101);
    if evidence.durable() {
        crawl.output.archive = Some(ArchiveConfigV1::default());
    }
    crawl.capture.browser = evidence;
    crawl.retention.mode = retention;
    crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.limits.states = 2;
    crawl.limits.interactions = 1;
    crawl.limits.duration_seconds = 30;
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
    let report = run_authorized_local_with(LocalRun::new(crawl, config).with_stores(stores.clone()))
        .await
        .unwrap();
    server.abort();
    let mut events = Vec::new();
    let mut after = 0;
    loop {
        let batch = stores.events.list_after(report.run_id, after, 64).await.unwrap();
        if batch.is_empty() {
            break;
        }
        after = batch.last().unwrap().seq;
        events.extend(batch.into_iter().filter(|event| event.kind == "browser.evidence"));
    }
    let mut records = Vec::new();
    let run = stores.runs.get(report.run_id).await.unwrap();
    if run.config.capture.browser.durable() {
        let ArchiveReadV1::Available(export) = stores
            .archives
            .get(run.tenant, run.id.0, SystemClock.now())
            .await
            .unwrap()
        else {
            panic!("browser evidence archive unavailable");
        };
        assert_eq!(export.state, ArchiveExportState::Published);
        records = stores
            .archives
            .records(run.tenant, export.id, None, 64, SystemClock.now())
            .await
            .unwrap();
    }
    Some(EvidenceFixture {
        _dir: dir,
        stores,
        events,
        records,
        run,
    })
}

fn requested() -> BrowserEvidenceConfig {
    let mut config = BrowserEvidenceConfig::default();
    config.phase_resources = true;
    config.mhtml = true;
    config.pdf = true;
    config
}

fn retained(events: &[crawlx_core::repo::RunEvent], phase: &str, kind: CaptureKind) -> CaptureArtifact {
    events
        .iter()
        .filter(|event| event.payload["phase"] == phase)
        .filter_map(|event| serde_json::from_value::<CaptureArtifact>(event.payload["capture"].clone()).ok())
        .find(|capture| capture.descriptor.kind == kind)
        .unwrap_or_else(|| panic!("missing {phase} {kind:?}: {events:?}"))
}

async fn bytes(stores: &Stores, artifact: &ArtifactRef) -> Vec<u8> {
    stores.artifacts.get(artifact).await.unwrap().to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mutation_retains_distinct_phases_and_real_mhtml_pdf() {
    let Some(fixture) = fixture(RetentionMode::Standard, requested()).await else {
        return;
    };
    let EvidenceFixture {
        _dir,
        stores,
        events,
        records,
        run,
    } = fixture;
    let initial_text = retained(&events, "initial", CaptureKind::Text);
    let final_text = retained(&events, "final", CaptureKind::Text);
    let initial = bytes(&stores, &initial_text.artifact).await;
    let final_body = bytes(&stores, &final_text.artifact).await;
    assert!(String::from_utf8_lossy(&initial).contains("INITIAL EVIDENCE"));
    assert!(String::from_utf8_lossy(&final_body).contains("FINAL EVIDENCE"));
    assert_ne!(initial, final_body);
    let initial_shot = retained(&events, "initial", CaptureKind::Screenshot);
    let final_shot = retained(&events, "final", CaptureKind::Screenshot);
    let initial = bytes(&stores, &initial_shot.artifact).await;
    let final_body = bytes(&stores, &final_shot.artifact).await;
    assert!(initial.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert!(final_body.starts_with(b"\x89PNG\r\n\x1a\n"));
    assert_ne!(initial, final_body);
    for phase in ["initial", "final"] {
        let mhtml = retained(&events, phase, CaptureKind::Mhtml);
        assert_eq!(mhtml.descriptor.content_type, "multipart/related");
        let body = bytes(&stores, &mhtml.artifact).await;
        assert!(String::from_utf8_lossy(&body).contains("multipart/related"));
        let pdf = retained(&events, phase, CaptureKind::Pdf);
        assert!(bytes(&stores, &pdf.artifact).await.starts_with(b"%PDF-"));
    }
    let attachment = retained(&events, "final", CaptureKind::Download);
    assert_eq!(attachment.descriptor.filename.as_deref(), Some("evidence.csv"));
    assert_eq!(attachment.descriptor.content_type, "text/csv");
    assert!(attachment.descriptor.source_url.ends_with("/attachment"));
    assert_eq!(
        bytes(&stores, &attachment.artifact).await,
        b"id,value\n1,download evidence\n"
    );
    assert!(events.iter().all(|event| {
        event.payload["phase"] != "initial" || event.payload["requestedKind"] != "download"
    }));
    assert!(!serde_json::to_string(&events)
        .unwrap()
        .contains(_dir.path().to_str().unwrap()));
    for event in &events {
        assert_eq!(event.payload["version"], 1);
        assert!(event.payload["epoch"]["navigation_seq"].is_u64());
        assert!(event.payload["observation"].is_u64());
        let capture: CaptureArtifact = serde_json::from_value(event.payload["capture"].clone()).unwrap();
        assert!(capture.bytes <= 16 * 1024 * 1024);
        assert!(event.payload["unavailable"].is_null());
    }
    for kind in [CaptureKind::Text, CaptureKind::Screenshot] {
        let mut digests = Vec::new();
        for phase in ["initial", "final"] {
            let capture = retained(&events, phase, kind);
            let record = records
                .iter()
                .find(|record| {
                    record.facts.capture_source == format!("browser_evidence_{phase}")
                        && record.mime == capture.descriptor.content_type
                })
                .unwrap_or_else(|| panic!("missing archived {phase} {kind:?}: {records:?}"));
            assert!(record
                .facts
                .transformations
                .iter()
                .any(|fact| fact.starts_with("epoch:")));
            let member = if kind == CaptureKind::Screenshot {
                assert_eq!(
                    record.custody.sensitivity,
                    crawlx_core::repo::Sensitivity::Sensitive
                );
                let source_custody = stores
                    .artifacts
                    .archive_custody(run.tenant, run.id, &capture.artifact, 16_908_288)
                    .await
                    .unwrap();
                assert!(record.custody.expires_at.unwrap() <= source_custody.expires_at.unwrap());
                stores
                    .artifacts
                    .read_archive_sensitive(run.tenant, run.id, &record.artifact, &record.custody, 16_908_288)
                    .await
                    .unwrap()
            } else {
                stores
                    .artifacts
                    .read_archive_content(run.tenant, run.id, &record.artifact, 16_908_288)
                    .await
                    .unwrap()
            };
            let (summary, payload) = crawlx_storage::archive::warc::read_member(
                std::io::Cursor::new(member),
                crawlx_storage::archive::Limits::default(),
            )
            .unwrap();
            assert_eq!(summary.payload_digest, record.payload_digest);
            assert_eq!(payload, bytes(&stores, &capture.artifact).await);
            digests.push(record.payload_digest.clone());
        }
        assert_ne!(digests[0], digests[1], "archive lost phase mutation for {kind:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_opt_in_records_no_browser_evidence() {
    let Some(fixture) = fixture(RetentionMode::Standard, BrowserEvidenceConfig::default()).await else {
        return;
    };
    assert!(fixture.events.is_empty());
}

#[test]
fn zdr_rejects_durable_browser_evidence_before_launch() {
    let mut crawl = CreateCrawl::new("https://example.test/".parse().unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.capture.browser = requested();
    crawl.retention.mode = RetentionMode::Zdr;
    let errors = crawl.normalize().unwrap_err();
    assert!(errors.iter().any(|error| matches!(
        error,
        crawlx_core::CoreError::Conflict {
            a: "capture.browser",
            b: "retention.mode",
            ..
        }
    )));
}
