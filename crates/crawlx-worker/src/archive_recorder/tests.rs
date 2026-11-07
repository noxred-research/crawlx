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
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, PgConfig};

async fn generations(stores: &Stores, clock: &ManualClock) -> (CrawlRun, Vec<PageRecord>) {
    let mut config = create_crawl("https://generation.example.test/article", &[], 1);
    config.retention.days = 1;
    config.output.archive = Some(crawlx_core::archive::ArchiveConfigV1::default());
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
            if stores.pg.is_some() {
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
    let (cold, sources) = generations(stores, clock.as_ref()).await;
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
    let (run, pages) = generations(stores, clock.as_ref()).await;
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
        root,
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
    let mut writer = PackageWriter::open(root).unwrap();
    for row in &before {
        let shard = root.join("recover-shard.warc.gz");
        stores
            .artifacts
            .copy_archive_content(run.tenant, run.id, &row.artifact, &shard, config.max_bytes)
            .await
            .unwrap();
        writer.append(&shard, row, limits(&export)).unwrap();
    }
    let mut manifest = ArchiveManifestV1::available(run.tenant, run.id, run.created_at);
    manifest.records = 2;
    let orphan = writer
        .finish(root, &manifest, config.format, limits(&export))
        .unwrap();
    stores
        .artifacts
        .put_archive_file(run.id, "application/wacz+zip", &orphan, config.max_bytes)
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
    assert_eq!(
        wacz::inspect(File::open(downloaded).unwrap(), limits(&export))
            .unwrap()
            .indexed,
        2
    );
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
    assert!(memory.purge_run(run) > 0);
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
        PgConfig {
            schema: Some(format!("archive_generations_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
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
    let stores = Stores::over_pg(pg.clone(), artifacts.clone(), tenant);
    let run = recovery(&stores, clock, root.path()).await;
    crawlx_storage::retention::RetentionSweeper::new(pg.clone())
        .with_artifacts(artifacts)
        .purge_run(run)
        .await
        .unwrap();
    assert!(stores.pages.committed_page_keyset(run, 0, 64).await.is_err());
    pg.drop_schema().await.unwrap();
}
