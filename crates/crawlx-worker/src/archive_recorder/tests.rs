//! Real recorder and codec regression: immutable generation sources survive publication recovery.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::counters::TerminalReason;
use crawlx_core::orchestration::{OrchestrationConfigV1, RequestBatchV1, RequestCommitV1};
use crawlx_core::repo::{FrontierStatus, PageRecord, Sensitivity};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::secret::{ArtifactSink, Redactor as ArtifactRedactor};
use crawlx_core::time::ManualClock;
use crawlx_core::traffic::TrustLane;
use crawlx_core::{TenantId, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, StoreConfig};
use std::fs::File;
use std::path::Path;

async fn generations(
    stores: &Stores,
    clock: &ManualClock,
    rollover_bytes: Option<u64>,
) -> (CrawlRun, Vec<PageRecord>) {
    let mut config = create_crawl("https://generation.example.test/article", &[], 1);
    config.retention.days = 1;
    config.output.archive = Some(crawlx_core::archive::ArchiveConfigV1::default());
    config.output.archive.as_mut().unwrap().rollover_bytes = rollover_bytes;
    config.output.archive.as_mut().unwrap().max_records = 2;
    let mut policy = OrchestrationConfigV1::default();
    policy.recrawl = Some(
        serde_json::from_value(serde_json::json!({
            "version":1,"minIntervalMs":1000,"maxIntervalMs":1000,"maxVisits":2,
            "endAt":clock.now()+chrono::Duration::minutes(1)
        }))
        .unwrap(),
    );
    config.orchestration = Some(policy);
    let mut run = crawl_run(stores.tenant, config);
    run.created_at = clock.now();
    stores.runs.create(&run, None).await.unwrap();
    let url = canonical_url("https://generation.example.test/article");
    stores
        .frontier
        .append_batch(RequestBatchV1::new(
            run.tenant,
            run.id,
            "anonymous".into(),
            Digest::of("test/archive", b"generations"),
            vec![RequestEnvelopeV1::get(url.clone(), 0, None)],
        ))
        .await
        .unwrap();
    let mut pages = Vec::new();
    for body in [
        b"first immutable retained body".as_slice(),
        b"second immutable retained body".as_slice(),
    ] {
        let (entry, fence) = stores
            .frontier
            .lease_batch_fenced(run.id, WorkerId::new(), 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let source = ArtifactSink::over(stores.artifacts.as_ref())
            .put_page(
                run.id,
                entry.id,
                Sensitivity::Content,
                "text/markdown",
                &ArtifactRedactor::new().redact_artifact(body).unwrap(),
            )
            .await
            .unwrap();
        let page = PageRecord {
            run: run.id,
            frontier_id: entry.id,
            url: url.clone(),
            status: 200,
            content_type: Some("text/markdown".into()),
            content_digest: Digest::of("test/body", body),
            title: None,
            markdown: Some(source),
            html: None,
            metadata: serde_json::json!({}),
            links: Vec::new(),
            fetched_at: clock.now(),
            lane: TrustLane::Diagnostic,
        };
        let mut commit =
            RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
        commit.page = Some(page.clone());
        stores.request_commits.commit_fenced(commit).await.unwrap();
        pages.push(page);
        if pages.len() == 1 {
            if stores.durable.is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }
            clock.advance_ms(1000);
        }
    }
    let latest = stores.pages.list(run.id).await.unwrap();
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].markdown, pages[1].markdown);
    (run, pages)
}

async fn recovery(stores: &Stores, clock: Arc<ManualClock>, root: &Path) -> crawlx_core::CrawlRunId {
    // Cold publication must discover both sources itself. A latest-URL-only keyset loses the first.
    let (cold, sources) = generations(stores, clock.as_ref(), None).await;
    let cancel = CancellationToken::new();
    assert_eq!(
        finalize(
            stores,
            &cold,
            clock.clone(),
            &cancel,
            TerminalReason::FrontierExhausted
        )
        .await
        .unwrap(),
        Finalization::Ready,
    );
    let rows = stores
        .archives
        .records(cold.tenant, cold.id.0, None, 64, clock.now())
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    for (row, page) in rows.iter().zip(&sources) {
        assert_eq!(row.ordinal, u64::try_from(page.frontier_id).unwrap() * 8 + 2);
        assert_eq!(
            row.facts.source_event,
            format!("page:{}:markdown", page.frontier_id)
        );
        let shard = stores
            .artifacts
            .read_archive_content(cold.tenant, cold.id, &row.artifact, 1_048_576)
            .await
            .unwrap();
        let (_, body) = warc::read_member(std::io::Cursor::new(shard), Limits::default()).unwrap();
        let source = stores
            .artifacts
            .read_archive_content(cold.tenant, cold.id, page.markdown.as_ref().unwrap(), 1_048_576)
            .await
            .unwrap();
        assert_eq!(body, source);
    }
    // Allow UUID compression variation while forcing each resource into its own bounded file.
    let rollover_cap = rows.iter().map(|row| row.length).max().unwrap() + 64;
    let (run, pages) = generations(stores, clock.as_ref(), Some(rollover_cap)).await;
    let config = run.config.output.archive.as_ref().unwrap();
    let pending = ArchiveExportV1::pending(
        run.tenant,
        run.id,
        config.clone(),
        run.created_at,
        Some(run.created_at + chrono::Duration::days(1)),
        TerminalReason::FrontierExhausted,
    );
    stores.archives.begin(&pending).await.unwrap();
    let export = stores
        .archives
        .claim(run.tenant, pending.id, clock.now())
        .await
        .unwrap()
        .unwrap();
    let cancel = CancellationToken::new();
    let mut recorder = resource::Recorder {
        stores,
        run: &run,
        export: &export,
        clock: clock.as_ref(),
        cancel: &cancel,
        committed_bytes: 0,
    };
    // Commit both actual recorder shards, then lose the process before manifest publication.
    for page in &pages {
        let request = stores
            .frontier
            .get_request(run.id, page.frontier_id)
            .await
            .unwrap();
        let outcome = recorder
            .record(resource::ResourceInput {
                ordinal: u64::try_from(page.frontier_id).unwrap() * 8 + 2,
                source: page.markdown.as_ref(),
                capture: None,
                target: page.url.url.as_str(),
                mime: "text/markdown",
                facts: ArchiveCaptureFactsV1::retained(
                    format!("page:{}:markdown", page.frontier_id),
                    page.fetched_at,
                    ArchiveRepresentation::ExtractedText,
                    "retained_page_markdown",
                ),
                history_source: Some((&request, page)),
            })
            .await
            .unwrap();
        assert!(matches!(outcome, resource::RecordOutcome::Committed));
    }
    let before = stores
        .archives
        .records(run.tenant, export.id, None, 64, clock.now())
        .await
        .unwrap();
    assert_eq!(before.len(), 2);
    // Exercise the package-object-before-catalog-publication crash boundary without a mock.
    let mut writer = PackageWriter::open(config.rollover_bytes, limits(&export)).unwrap();
    for row in &before {
        let shard = StagedFile::new().unwrap();
        stores
            .artifacts
            .copy_archive_content(run.tenant, run.id, &row.artifact, shard.path(), config.max_bytes)
            .await
            .unwrap();
        writer.append(&shard, row, limits(&export)).unwrap();
    }
    let mut manifest = ArchiveManifestV1::available(run.tenant, run.id, run.created_at);
    manifest.records = 2;
    let orphan = writer.finish(&manifest, config.format, limits(&export)).unwrap();
    stores
        .artifacts
        .put_archive_file(
            run.id,
            "application/wacz+zip",
            orphan.archive.path(),
            config.max_bytes,
        )
        .await
        .unwrap();
    clock.advance_ms(301_000);
    assert_eq!(
        finalize(
            stores,
            &run,
            clock.clone(),
            &cancel,
            TerminalReason::FrontierExhausted
        )
        .await
        .unwrap(),
        Finalization::Ready
    );
    let ArchiveReadV1::Available(published) = stores
        .archives
        .get(run.tenant, run.id.0, clock.now())
        .await
        .unwrap()
    else {
        panic!("published export missing");
    };
    assert_eq!(published.state, ArchiveExportState::Published);
    assert_eq!(published.manifest.as_ref().unwrap().records, 2);
    assert!(!published
        .manifest
        .as_ref()
        .unwrap()
        .omissions
        .iter()
        .any(|omission| omission.reason == "remaining_retained_resources_not_evaluated_record_budget"));
    assert!(!published
        .manifest
        .as_ref()
        .unwrap()
        .omissions
        .iter()
        .any(|omission| omission.reason.contains("latest_committed_page")));
    let after = stores
        .archives
        .records(run.tenant, export.id, None, 64, clock.now())
        .await
        .unwrap();
    assert_eq!(after.len(), before.len());
    for ((row, previous), page) in after.iter().zip(&before).zip(&pages) {
        assert_eq!(row.ordinal, u64::try_from(page.frontier_id).unwrap() * 8 + 2);
        assert_eq!(row.record_id, previous.record_id);
        assert_eq!(row.artifact, previous.artifact);
        assert_eq!(
            row.facts.source_event,
            format!("page:{}:markdown", page.frontier_id)
        );
        let bytes = stores
            .artifacts
            .read_archive_content(run.tenant, run.id, &row.artifact, config.max_bytes)
            .await
            .unwrap();
        let (_, archived) = warc::read_member(std::io::Cursor::new(bytes), limits(&export)).unwrap();
        let retained = stores
            .artifacts
            .read_archive_content(
                run.tenant,
                run.id,
                page.markdown.as_ref().unwrap(),
                config.max_bytes,
            )
            .await
            .unwrap();
        assert_eq!(archived, retained);
    }
    let downloaded = root.join("published.wacz");
    stores
        .artifacts
        .copy_archive_content(
            run.tenant,
            run.id,
            published.artifact.as_ref().unwrap(),
            &downloaded,
            config.max_bytes,
        )
        .await
        .unwrap();
    let inspection = wacz::inspect(File::open(&downloaded).unwrap(), limits(&export)).unwrap();
    assert_eq!(inspection.indexed, 2);
    assert_eq!(inspection.records.len(), 2);
    for (filename, records) in &inspection.records {
        assert_eq!(records.len(), 1);
        let fixity = inspection
            .resources
            .iter()
            .find(|resource| &resource.path == filename)
            .unwrap();
        assert!(fixity.bytes <= rollover_cap);
        assert_eq!(records[0].offset, 0);
        assert_eq!(records[0].length, fixity.bytes);
        let body = wacz::payload(
            File::open(&downloaded).unwrap(),
            filename,
            &records[0],
            limits(&export),
        )
        .unwrap();
        let catalog = after.iter().find(|row| row.record_id == records[0].id).unwrap();
        let page = pages
            .iter()
            .find(|page| catalog.facts.source_event == format!("page:{}:markdown", page.frontier_id))
            .unwrap();
        let retained = stores
            .artifacts
            .read_archive_content(
                run.tenant,
                run.id,
                page.markdown.as_ref().unwrap(),
                config.max_bytes,
            )
            .await
            .unwrap();
        assert_eq!(body, retained);
    }
    // Re-enter after a publication acknowledgement is lost: same package, same two logical rows.
    assert_eq!(
        finalize(
            stores,
            &run,
            clock.clone(),
            &cancel,
            TerminalReason::FrontierExhausted
        )
        .await
        .unwrap(),
        Finalization::Ready
    );
    let ArchiveReadV1::Available(replayed) = stores
        .archives
        .get(run.tenant, run.id.0, clock.now())
        .await
        .unwrap()
    else {
        panic!("replayed export missing");
    };
    assert_eq!(replayed.artifact, published.artifact);
    assert_eq!(
        stores
            .archives
            .records(run.tenant, export.id, None, 64, clock.now())
            .await
            .unwrap()
            .len(),
        2
    );
    run.id
}

#[tokio::test]
async fn memory_archive_recorder_keeps_all_generations_through_publication_recovery() {
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
    let mut stores = Stores::over_memory(memory.clone(), root.path()).await.unwrap();
    stores.artifacts = Arc::new(
        FsArtifactStore::open(root.path(), memory.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(memory.clone()),
    );
    let run = recovery(&stores, clock, root.path()).await;
    assert!(memory.purge_run(run).await.unwrap() > 0);
    assert!(stores.pages.committed_page_keyset(run, 0, 64).await.is_err());
}

#[tokio::test]
async fn postgres_archive_recorder_keeps_all_generations_through_publication_recovery() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("archive_generations_{}", uuid::Uuid::now_v7().simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "archive-generations").await.unwrap();
    let artifacts = Arc::new(
        FsArtifactStore::open(root.path(), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    let stores = Stores::over_durable(
        crate::durable::DurableStore::Postgres(pg.clone()),
        artifacts.clone(),
        tenant,
    );
    let run = recovery(&stores, clock, root.path()).await;
    crawlx_storage::retention::RetentionSweeper::new(pg.clone())
        .with_artifacts(artifacts)
        .purge_run(run)
        .await
        .unwrap();
    assert!(stores.pages.committed_page_keyset(run, 0, 64).await.is_err());
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn live_wacz_rollover_refuses_oversized_member_without_publication() {
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    ));
    let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
    let mut stores = Stores::over_memory(memory.clone(), root.path()).await.unwrap();
    stores.artifacts = Arc::new(
        FsArtifactStore::open(root.path(), memory.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(memory),
    );
    let (run, _) = generations(&stores, clock.as_ref(), Some(1)).await;
    assert_eq!(
        finalize(
            &stores,
            &run,
            clock.clone(),
            &CancellationToken::new(),
            TerminalReason::FrontierExhausted
        )
        .await
        .unwrap(),
        Finalization::Failed,
    );
    let ArchiveReadV1::Available(export) = stores
        .archives
        .get(run.tenant, run.id.0, clock.now())
        .await
        .unwrap()
    else {
        panic!("failed export missing");
    };
    assert_eq!(export.state, ArchiveExportState::Failed);
    assert_eq!(
        export.failure,
        Some(crawlx_core::archive_catalog::ArchiveFailureV1::LimitExceeded)
    );
    assert!(export.artifact.is_none());
    assert!(export.manifest.is_none());
}

#[tokio::test]
async fn conditional_history_rejects_partial_bodies_and_checks_every_vary_field() {
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    ));
    let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
    let stores = Stores::over_memory(memory, root.path()).await.unwrap();
    let (run, mut pages) = generations(&stores, clock.as_ref(), None).await;
    let mut page = pages.remove(0);
    let request = stores
        .frontier
        .get_request(run.id, page.frontier_id)
        .await
        .unwrap();
    page.metadata = serde_json::json!({
        "response_headers": {"etag": "\"version-one\"", "vary": "accept, accept-language"}
    });
    let mut facts = ArchiveCaptureFactsV1::retained(
        "page:response",
        page.fetched_at,
        ArchiveRepresentation::ProtocolResource,
        "retained_native_decoded_response_body",
    );
    facts.body_state = "complete".into();
    let record = ArchiveRecordV1::resource(
        run.id.0,
        1,
        format!("<urn:uuid:{}>", run.id.0),
        page.markdown.as_ref().unwrap().clone(),
        0,
        1,
        warc::digest(b"retained body"),
        page.url.url.as_str().into(),
        facts,
        "text/plain".into(),
    );
    assert!(history::captured_history(&run, &request, &page, &record)
        .unwrap()
        .is_some());
    page.status = 206;
    assert!(history::captured_history(&run, &request, &page, &record)
        .unwrap()
        .is_none());
    page.status = 200;
    page.metadata["response_headers"]["content-range"] = "bytes 0-12/100".into();
    assert!(history::captured_history(&run, &request, &page, &record)
        .unwrap()
        .is_none());

    let baseline = ArchiveBaseline {
        validators: crawlx_fetch::conditional::Validators {
            etag: Some("\"version-one\"".into()),
            last_modified: None,
        },
        body: Vec::new(),
        record,
        vary: vec!["accept".into(), "accept-language".into()],
    };
    let mut headers = http::HeaderMap::new();
    headers.append(http::header::VARY, http::HeaderValue::from_static("accept"));
    headers.append(
        http::header::VARY,
        http::HeaderValue::from_static("accept-language"),
    );
    assert!(baseline.matches_response(&headers));
    headers.append(http::header::VARY, http::HeaderValue::from_static("*"));
    assert!(!baseline.matches_response(&headers));
    headers.remove(http::header::VARY);
    headers.append(
        http::header::ETAG,
        http::HeaderValue::from_static("\"version-one\""),
    );
    headers.append(
        http::header::ETAG,
        http::HeaderValue::from_static("\"version-two\""),
    );
    assert!(!baseline.matches_response(&headers));
}

#[cfg(all(feature = "chaos", target_os = "linux"))]
mod crash;

mod dedupe;

#[cfg(target_os = "linux")]
#[test]
fn anonymous_warc_package_retains_exact_member_and_adjacent_index() {
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read as _};
    use std::os::unix::fs::MetadataExt as _;

    let header = warc::RecordHeader {
        payload_offset: 0,
        fields: BTreeMap::from([
            ("WARC-Type".into(), "resource".into()),
            (
                "WARC-Record-ID".into(),
                "<urn:uuid:00000000-0000-8000-8000-000000000001>".into(),
            ),
            ("WARC-Date".into(), "2026-11-06T00:00:00Z".into()),
            ("WARC-Target-URI".into(), "https://package.example.test/".into()),
            ("Content-Type".into(), "text/plain".into()),
        ]),
    };
    let mut shard = StagedFile::new().unwrap();
    let summary = warc::write_record(
        shard.file_mut(),
        &header,
        &mut Cursor::new(b"exact retained bytes"),
        20,
        Limits::default(),
    )
    .unwrap();
    let at = chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let manifest = ArchiveManifestV1::available(TenantId::new(), crawlx_core::CrawlRunId::new(), at);
    let record = ArchiveRecordV1::resource(
        uuid::Uuid::now_v7(),
        8,
        summary.id.clone(),
        ArtifactRef {
            id: crawlx_core::ArtifactId::new(),
            digest: Digest::of("test/archive", b"fixture"),
        },
        summary.offset,
        summary.length,
        summary.payload_digest.clone(),
        summary.target.clone().unwrap(),
        ArchiveCaptureFactsV1::retained(
            "page:1:markdown",
            at,
            ArchiveRepresentation::ExtractedText,
            "retained_page_markdown",
        ),
        "text/plain".into(),
    );
    let mut writer = PackageWriter::open(None, Limits::default()).unwrap();
    writer.append(&shard, &record, Limits::default()).unwrap();
    let package = writer
        .finish(&manifest, ArchiveFormat::Warc, Limits::default())
        .unwrap();
    let index = package.index.as_ref().unwrap();
    assert_eq!(package.archive.file().metadata().unwrap().nlink(), 0);
    assert_eq!(index.file().metadata().unwrap().nlink(), 0);
    let mut expected = Vec::new();
    shard.reader().unwrap().read_to_end(&mut expected).unwrap();
    let mut actual = Vec::new();
    package
        .archive
        .reader()
        .unwrap()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, expected);
    let mut actual_index = String::new();
    index.reader().unwrap().read_to_string(&mut actual_index).unwrap();
    assert_eq!(
        actual_index,
        cdxj::Entry::from_record(&summary, "data.warc.gz")
            .unwrap()
            .line(&summary)
            .unwrap()
    );
}
