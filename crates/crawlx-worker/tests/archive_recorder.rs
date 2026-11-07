//! A real owned HTTP crawl must publish a readable retained archive, not codec-only scaffolding.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use crawlx_core::archive::{ArchiveCapture, ArchiveConfigV1};
use crawlx_core::archive_catalog::{ArchiveExportState, ArchiveReadV1};
use crawlx_core::config::{CrawlMode, RetentionMode};
use crawlx_core::counters::RunStatus;
use crawlx_core::{Clock, CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_storage::archive::{wacz, Limits};
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, Stores, WorkerConfig, WorkerError};
use std::fs::File;
use std::sync::Arc;

fn worker(root: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: root.into(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}
fn crawl(base: &str) -> CreateCrawl {
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_105);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.output.archive = Some(ArchiveConfigV1::default());
    crawl
}

#[tokio::test]
async fn owned_fixture_crawl_publishes_catalog_artifact_and_inspectable_wacz() {
    let site = common::site::start().await;
    let root = tempfile::tempdir().unwrap();
    let cfg = worker(root.path());
    let stores = Stores::open(&cfg).await.unwrap();
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl(&site.base), cfg).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    let run = stores.runs.get(report.run_id).await.unwrap();
    let ArchiveReadV1::Available(export) = stores
        .archives
        .get(run.tenant, run.id.0, SystemClock.now())
        .await
        .unwrap()
    else {
        panic!("fixture crawl did not publish an archive catalog row");
    };
    assert_eq!(export.state, ArchiveExportState::Published);
    let manifest = export.manifest.as_ref().unwrap();
    assert!(
        !manifest.complete,
        "retained DOM/text is not complete original wire capture"
    );
    assert!(manifest.records > 0);
    assert!(manifest
        .omissions
        .iter()
        .any(|omission| omission.reason.contains("original_wire")));
    assert!(matches!(
        stores
            .archives
            .get(TenantId::new(), export.id, SystemClock.now())
            .await
            .unwrap(),
        ArchiveReadV1::Missing
    ));
    let package = root.path().join("download.wacz");
    stores
        .artifacts
        .copy_archive_content(
            run.tenant,
            run.id,
            export.artifact.as_ref().unwrap(),
            &package,
            export.config.max_bytes,
        )
        .await
        .unwrap();
    let inspection = wacz::inspect(File::open(&package).unwrap(), Limits::default()).unwrap();
    assert_eq!(inspection.indexed, manifest.records);
    assert_eq!(
        inspection
            .records
            .values()
            .map(|records| u64::try_from(records.len()).unwrap())
            .sum::<u64>(),
        manifest.records
    );
    assert!(inspection
        .resources
        .iter()
        .any(|resource| resource.path == "metadata/crawlx-manifest.json"));
    // Every exposed catalog member refers to an actual separately committed artifact.
    let rows = stores
        .archives
        .records(run.tenant, export.id, None, 64, SystemClock.now())
        .await
        .unwrap();
    assert!(!rows.is_empty());
    for record in rows {
        let bytes = stores
            .artifacts
            .read_archive_content(run.tenant, run.id, &record.artifact, 16_908_288)
            .await
            .unwrap();
        let (summary, _) =
            crawlx_storage::archive::warc::read_member(std::io::Cursor::new(bytes), Limits::default())
                .unwrap();
        assert_eq!(summary.id, record.record_id);
        assert_eq!(summary.length, record.length);
        assert_eq!(summary.payload_digest, record.payload_digest);
    }
}

#[tokio::test]
async fn zdr_and_unavailable_complete_capture_fail_admission_before_artifact_io() {
    let site = common::site::start().await;
    let root = tempfile::tempdir().unwrap();
    let artifacts = root.path().join("must-not-be-created");
    let mut zdr = crawl(&site.base);
    zdr.retention.mode = RetentionMode::Zdr;
    // Supply authorization without opening stores: this assertion covers admission before artifact I/O.
    let authorization = common::authorization::verified_record(&zdr, TenantId::new());
    let error = run_local_with(LocalRun::new(zdr, worker(&artifacts)).with_authorization(authorization))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        WorkerError::Config(reason)
            if reason.contains("durable archives are forbidden for zero-data-retention runs")
    ));
    assert!(!artifacts.exists());
    let mut complete = crawl(&site.base);
    complete.output.archive.as_mut().unwrap().capture = ArchiveCapture::RequireComplete;
    let authorization = common::authorization::verified_record(&complete, TenantId::new());
    let error = run_local_with(LocalRun::new(complete, worker(&artifacts)).with_authorization(authorization))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        WorkerError::Config(reason)
            if reason.contains("complete original response and subresource capture is unavailable")
    ));
    assert!(!artifacts.exists());
}

#[tokio::test]
async fn registered_canary_cannot_enter_any_published_archive_member() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let canary = "archive-recorder-owned-secret-canary";
    assert!(crawlx_telemetry::redact::register_secret(canary));
    let site = MockServer::start().await;
    Mock::given(method("GET")).and(path("/")).respond_with(ResponseTemplate::new(200)
        .set_body_raw(format!("<html><body><main><p>Owned retained fixture article.</p><p>Authorization: Bearer {canary}</p></main></body></html>"), "text/html"))
        .mount(&site).await;
    let root = tempfile::tempdir().unwrap();
    let cfg = worker(root.path());
    let stores = Stores::open(&cfg).await.unwrap();
    let mut request = crawl(&site.uri());
    request.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(request, cfg).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let run = stores.runs.get(report.run_id).await.unwrap();
    let ArchiveReadV1::Available(export) = stores
        .archives
        .get(run.tenant, run.id.0, SystemClock.now())
        .await
        .unwrap()
    else {
        panic!("archive finalization outcome missing");
    };
    assert!(!serde_json::to_string(export.as_ref()).unwrap().contains(canary));
    if export.state == ArchiveExportState::Published {
        for record in stores
            .archives
            .records(run.tenant, export.id, None, 64, SystemClock.now())
            .await
            .unwrap()
        {
            let bytes = stores
                .artifacts
                .read_archive_content(run.tenant, run.id, &record.artifact, 16_908_288)
                .await
                .unwrap();
            let (_, body) =
                crawlx_storage::archive::warc::read_member(std::io::Cursor::new(bytes), Limits::default())
                    .unwrap();
            assert!(!std::str::from_utf8(&body).unwrap().contains(canary));
        }
    } else {
        assert_eq!(export.state, ArchiveExportState::Failed);
        assert!(export.artifact.is_none());
    }
}

#[tokio::test]
async fn recrawl_uses_only_published_compatible_body_and_keeps_actual_304_status() {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let site = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .and(header("if-none-match", "\"fixture-v1\""))
        .respond_with(ResponseTemplate::new(304).insert_header("etag", "\"fixture-v1\""))
        .with_priority(1)
        .mount(&site)
        .await;
    Mock::given(method("GET")).and(path("/")).respond_with(ResponseTemplate::new(200)
        .insert_header("etag", "\"fixture-v1\"")
        .insert_header("vary", "Accept-Encoding")
        .set_body_raw("<html><body><main><h1>Owned conditional fixture</h1><p>Retained complete decoded response.</p></main></body></html>", "text/html"))
        .with_priority(5).mount(&site).await;
    let root = tempfile::tempdir().unwrap();
    let cfg = worker(root.path());
    let stores = Stores::open(&cfg).await.unwrap();
    let mut first = crawl(&site.uri());
    first.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    first.scope.disable_unique_filter = true;
    first.capture.response_bodies = crawlx_core::config::ResponseBodies::Full;
    let initial = common::authorization::run_authorized_local_with(
        LocalRun::new(first.clone(), cfg.clone()).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(initial.status, RunStatus::Completed);
    let source = stores.runs.get(initial.run_id).await.unwrap();
    let ArchiveReadV1::Available(published) = stores
        .archives
        .get(source.tenant, source.id.0, SystemClock.now())
        .await
        .unwrap()
    else {
        panic!("initial full retained baseline missing");
    };
    assert_eq!(published.state, ArchiveExportState::Published);
    let mut orchestration = crawlx_core::orchestration::OrchestrationConfigV1::default();
    orchestration.recrawl = Some(
        serde_json::from_value(serde_json::json!({
            "version":1,"minIntervalMs":50,"maxIntervalMs":50,"maxVisits":2,
            "endAt":SystemClock.now() + chrono::Duration::minutes(1),"validatorMode":"require_history"
        }))
        .unwrap(),
    );
    first.orchestration = Some(orchestration);
    let result = common::authorization::run_authorized_local_with(
        LocalRun::new(first, cfg).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let requests = site.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .any(|request| request.headers.get("if-none-match").is_some()));
    let pages = stores.pages.list(result.run_id).await.unwrap();
    let page = pages.iter().find(|page| page.url.url.path() == "/").unwrap();
    assert_eq!(page.status, 304);
    assert_eq!(
        page.metadata
            .pointer("/acquisition/targetStatus")
            .and_then(serde_json::Value::as_u64),
        Some(304)
    );
    assert_eq!(
        page.metadata
            .pointer("/acquisition/representation")
            .and_then(serde_json::Value::as_str),
        Some("retained_response")
    );
    assert!(page.metadata.pointer("/acquisition/retainedBaseline").is_some());
    assert!(
        page.html.is_some() || page.markdown.is_some(),
        "retained body produced no rendition: content_type={:?}, extraction_succeeded={}, validation={}, word_count={}",
        page.content_type,
        page.metadata["acquisition"]["extractionSucceeded"],
        page.metadata["acquisition"]["validation"],
        page.metadata["word_count"],
    );
    let retained = stores
        .artifacts
        .read_archive_content(
            source.tenant,
            result.run_id,
            page.markdown.as_ref().or(page.html.as_ref()).unwrap(),
            4096,
        )
        .await
        .unwrap();
    assert!(std::str::from_utf8(&retained)
        .unwrap()
        .contains("Retained complete decoded response."));
}
