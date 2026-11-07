//! Consumer-visible archive custody, fencing, dependency and validator history regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::archive::{
    ArchiveCaptureFactsV1, ArchiveConfigV1, ArchiveFormat, ArchiveManifestV1, ArchiveRepresentation,
};
use crawlx_core::archive_catalog::{
    ArchiveDependencyV1, ArchiveExportV1, ArchiveHistoryKeyV1, ArchiveHistoryV1, ArchiveReadV1,
    ArchiveRecordV1, ArchiveRepo,
};
use crawlx_core::counters::TerminalReason;
use crawlx_core::repo::{ArtifactStore, RunRepo};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, StoreError, TenantId};
use crawlx_storage::archive::{cdxj, warc, Limits};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, PgConfig};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::Arc;

fn at() -> crawlx_core::Timestamp {
    static START: std::sync::LazyLock<crawlx_core::Timestamp> = std::sync::LazyLock::new(|| {
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap()
    });
    *START
}
fn config() -> ArchiveConfigV1 {
    let mut config = ArchiveConfigV1::default();
    config.format = ArchiveFormat::Warc;
    config
}
async fn source(runs: &dyn RunRepo, tenant: TenantId) -> crawlx_core::repo::CrawlRun {
    let mut cfg = create_crawl("https://archive.example.test/data", &[], 1);
    cfg.retention.days = 7;
    cfg.output.archive = Some(config());
    let mut run = crawl_run(tenant, cfg);
    run.created_at = at();
    runs.create(&run, None).await.unwrap();
    run
}
async fn member(
    artifacts: &dyn ArtifactStore,
    run: &crawlx_core::repo::CrawlRun,
    ordinal: u64,
) -> (ArchiveRecordV1, crawlx_core::ArtifactRef) {
    let id = format!("<urn:uuid:{}>", uuid::Uuid::now_v7());
    let header = warc::RecordHeader {
        fields: BTreeMap::from([
            ("WARC-Type".into(), "resource".into()),
            ("WARC-Record-ID".into(), id),
            ("WARC-Date".into(), warc::date(at())),
            (
                "WARC-Target-URI".into(),
                "https://archive.example.test/data".into(),
            ),
            ("Content-Type".into(), "text/plain".into()),
        ]),
        payload_offset: 0,
    };
    let mut encoded = Cursor::new(Vec::new());
    let summary = warc::write_record(
        &mut encoded,
        &header,
        &mut Cursor::new(b"owned retained body"),
        19,
        Limits::default(),
    )
    .unwrap();
    let shard = artifacts
        .put(
            run.id,
            crawlx_core::repo::Sensitivity::Content,
            "application/warc",
            encoded.get_ref(),
        )
        .await
        .unwrap();
    let index = cdxj::Entry::from_record(&summary, "data.warc.gz")
        .unwrap()
        .line(&summary)
        .unwrap();
    let index = artifacts
        .put(
            run.id,
            crawlx_core::repo::Sensitivity::Content,
            "application/cdxj",
            index.as_bytes(),
        )
        .await
        .unwrap();
    let facts = ArchiveCaptureFactsV1::retained(
        format!("event:{ordinal}"),
        at(),
        ArchiveRepresentation::ProtocolResource,
        "retained_native_decoded_response_body",
    );
    (
        ArchiveRecordV1::resource(
            run.id.0,
            ordinal,
            summary.id,
            shard,
            summary.offset,
            summary.length,
            summary.payload_digest,
            "https://archive.example.test/data".into(),
            facts,
            "text/plain".into(),
        ),
        index,
    )
}
async fn exercise(
    runs: &dyn RunRepo,
    repo: &dyn ArchiveRepo,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
) -> Vec<crawlx_core::ArtifactRef> {
    let first = source(runs, tenant).await;
    let pending = ArchiveExportV1::pending(
        tenant,
        first.id,
        config(),
        at(),
        Some(at() + chrono::Duration::days(7)),
        TerminalReason::FrontierExhausted,
    );
    repo.begin(&pending).await.unwrap();
    let first_claim = repo.claim(tenant, pending.id, at()).await.unwrap().unwrap();
    let (record, index) = member(artifacts, &first, 1).await;
    let mut missing = record.clone();
    missing.artifact.id = crawlx_core::ArtifactId::new();
    assert!(repo
        .commit_record(tenant, first_claim.fence, &missing, None, at())
        .await
        .is_err());
    // Object committed, writer died before the catalog row. Recovery owns a newer fence.
    let recovery_time = at() + chrono::Duration::seconds(121);
    let recovered = repo
        .claim(tenant, pending.id, recovery_time)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        repo.commit_record(tenant, first_claim.fence, &record, None, recovery_time)
            .await,
        Err(StoreError::LeaseLost)
    ));
    let key = ArchiveHistoryKeyV1::new(
        record.target.clone(),
        "GET".into(),
        "anonymous".into(),
        "variant-v1".into(),
        "redaction-v1".into(),
    );
    let history = ArchiveHistoryV1::new(
        key.clone(),
        ArchiveDependencyV1::new(record.export, 1),
        Some("\"baseline-v1\"".into()),
        None,
        at(),
    );
    repo.commit_record(tenant, recovered.fence, &record, Some(&history), recovery_time)
        .await
        .unwrap();
    assert!(
        repo.history(tenant, &key, recovery_time).await.unwrap().is_none(),
        "unpublished baseline must not escape"
    );
    // Record row committed, writer died before publishing the final manifest.
    let publish_time = recovery_time + chrono::Duration::seconds(121);
    let publisher = repo
        .claim(tenant, pending.id, publish_time)
        .await
        .unwrap()
        .unwrap();
    repo.commit_record(tenant, publisher.fence, &record, Some(&history), publish_time)
        .await
        .unwrap();
    assert_eq!(
        repo.records(tenant, pending.id, None, 64, publish_time)
            .await
            .unwrap()
            .len(),
        1
    );
    let mut manifest = ArchiveManifestV1::available(tenant, first.id, at());
    manifest.records = 1;
    let mut forged = manifest.clone();
    forged.complete = true;
    assert!(repo
        .publish(
            tenant,
            pending.id,
            publisher.fence,
            &record.artifact,
            Some(&index),
            &forged,
            publish_time
        )
        .await
        .is_err());
    repo.publish(
        tenant,
        pending.id,
        publisher.fence,
        &record.artifact,
        Some(&index),
        &manifest,
        publish_time,
    )
    .await
    .unwrap();
    let Some(found) = repo.history(tenant, &key, publish_time).await.unwrap() else {
        panic!("published baseline missing");
    };
    assert_eq!(found.source, history.source);
    let mut other_principal = key.clone();
    other_principal.principal = "admin".into();
    let mut other_variant = key.clone();
    other_variant.variant = "other-vary-context".into();
    assert!(repo
        .history(tenant, &other_principal, publish_time)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .history(tenant, &other_variant, publish_time)
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        repo.get(TenantId::new(), pending.id, publish_time).await.unwrap(),
        ArchiveReadV1::Missing
    ));
    let second = source(runs, tenant).await;
    let second_pending = ArchiveExportV1::pending(
        tenant,
        second.id,
        config(),
        at(),
        Some(at() + chrono::Duration::days(7)),
        TerminalReason::FrontierExhausted,
    );
    repo.begin(&second_pending).await.unwrap();
    let second_claim = repo
        .claim(tenant, second_pending.id, publish_time)
        .await
        .unwrap()
        .unwrap();
    let (mut dependent, second_index) = member(artifacts, &second, 2).await;
    dependent.dependency = Some(history.source.clone());
    let dependent_history = ArchiveHistoryV1::new(
        key.clone(),
        ArchiveDependencyV1::new(dependent.export, 2),
        history.etag.clone(),
        None,
        at(),
    );
    repo.commit_record(
        tenant,
        second_claim.fence,
        &dependent,
        Some(&dependent_history),
        publish_time,
    )
    .await
    .unwrap();
    let mut second_manifest = ArchiveManifestV1::available(tenant, second.id, at());
    second_manifest.records = 1;
    repo.publish(
        tenant,
        second_pending.id,
        second_claim.fence,
        &dependent.artifact,
        Some(&second_index),
        &second_manifest,
        publish_time,
    )
    .await
    .unwrap();
    repo.erase(tenant, pending.id).await.unwrap();
    assert!(matches!(
        repo.get(tenant, second_pending.id, publish_time).await.unwrap(),
        ArchiveReadV1::Missing
    ));
    assert!(!repo
        .artifact_visible(tenant, &dependent.artifact, publish_time)
        .await
        .unwrap());
    assert!(repo.history(tenant, &key, publish_time).await.unwrap().is_none());
    assert!(!repo.erased_artifacts(tenant, 64).await.unwrap().is_empty());
    vec![record.artifact, index, dependent.artifact, second_index]
}

#[tokio::test]
async fn memory_catalog_tracks_actual_artifacts_fences_and_dependency_erasure() {
    let clock = Arc::new(ManualClock::new(at()));
    let store = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), store.clone(), clock)
        .await
        .unwrap()
        .with_index(store.clone());
    let erased = exercise(store.as_ref(), store.as_ref(), &artifacts, TenantId::new()).await;
    assert_eq!(erased.len(), 4);
}

#[tokio::test]
async fn postgres_catalog_matches_memory_custody_and_tenant_scope() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("archive_catalog_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "archive-catalog-fixture").await.unwrap();
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = Arc::new(
        FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock)
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    let erased = exercise(&pg, &pg, artifacts.as_ref(), tenant).await;
    // A failed DELETE may leave tombstones. The ordinary sweeper must resume physical
    // dependency cleanup even before source TTL, without reopening catalog visibility.
    let report = crawlx_storage::retention::RetentionSweeper::new(pg.clone())
        .with_artifacts(artifacts.clone())
        .sweep(at())
        .await
        .unwrap();
    assert_eq!(report.artifacts_deleted, 4);
    assert!(pg.erased_artifacts(tenant, 64).await.unwrap().is_empty());
    for artifact in erased {
        assert!(artifacts
            .read_content_limited(&artifact, 16 * 1024 * 1024)
            .await
            .is_err());
        assert_eq!(artifacts.erase_artifact(&artifact).await.unwrap(), 0);
    }
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn expiry_and_zdr_are_typed_without_returning_content_metadata() {
    let clock = Arc::new(ManualClock::new(at()));
    let store = MemoryStore::with_clock(clock.clone());
    let tenant = TenantId::new();
    let mut config = create_crawl("https://archive.example.test/", &[], 1);
    config.retention.days = 1;
    config.output.archive = Some(crate::config());
    let mut run = crawl_run(tenant, config.clone());
    run.created_at = at();
    RunRepo::create(&store, &run, None).await.unwrap();
    let expiry = at() + chrono::Duration::days(1);
    let pending = ArchiveExportV1::pending(
        tenant,
        run.id,
        crate::config(),
        at(),
        Some(expiry),
        TerminalReason::FrontierExhausted,
    );
    store.begin(&pending).await.unwrap();
    assert!(matches!(
        ArchiveRepo::get(&store, tenant, pending.id, expiry)
            .await
            .unwrap(),
        ArchiveReadV1::Expired
    ));
    config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    let mut zdr = crawl_run(tenant, config);
    zdr.created_at = at();
    RunRepo::create(&store, &zdr, None).await.unwrap();
    let forbidden = ArchiveExportV1::pending(
        tenant,
        zdr.id,
        crate::config(),
        at(),
        Some(expiry),
        TerminalReason::FrontierExhausted,
    );
    assert!(matches!(
        store.begin(&forbidden).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(store.list(tenant, zdr.id, clock.now()).await.unwrap().is_empty());
}
