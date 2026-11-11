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
    // A lost acknowledgement permits only the same immutable descriptor and history.
    // Matching ID/digest/length alone must not conceal changed custody or dependencies.
    let mut changed = record.clone();
    changed.artifact.id = crawlx_core::ArtifactId::new();
    let mut shifted = record.clone();
    shifted.offset = shifted.offset.saturating_add(1);
    let mut relinked = record.clone();
    relinked.dependency = Some(ArchiveDependencyV1::new(uuid::Uuid::nil(), 0));
    let mut relabeled = record.clone();
    relabeled.facts.body_state = "different".into();
    for conflict in [&changed, &shifted, &relinked, &relabeled] {
        assert!(matches!(
            repo.commit_record(tenant, recovered.fence, conflict, Some(&history), recovery_time)
                .await,
            Err(StoreError::Conflict(_))
        ));
    }
    let mut changed_history = history.clone();
    changed_history.etag = Some("\"different-validator\"".into());
    for conflict in [None, Some(&changed_history)] {
        assert!(matches!(
            repo.commit_record(tenant, recovered.fence, &record, conflict, recovery_time)
                .await,
            Err(StoreError::Conflict(_))
        ));
    }
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

#[tokio::test]
async fn sensitive_archive_capability_rejects_changed_authority_and_expiry_during_stream() {
    use crawlx_core::archive_catalog::ArchiveCustodyV1;
    use crawlx_core::repo::Sensitivity;
    use futures::TryStreamExt as _;
    let now: crawlx_core::Timestamp = "2026-11-11T00:00:00Z".parse().unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let store = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), store.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(store.clone());
    let tenant = TenantId::new();
    let mut cfg = create_crawl("https://archive.example.test/data", &[], 1);
    cfg.retention.days = 7;
    cfg.output.archive = Some(config());
    let mut run = crawl_run(tenant, cfg);
    run.created_at = now;
    RunRepo::create(store.as_ref(), &run, None).await.unwrap();
    let deadline = now + chrono::Duration::minutes(10);
    let body = vec![b'x'; 65_536];
    let source = artifacts
        .put_until(run.id, Sensitivity::Sensitive, "text/plain", &body, deadline)
        .await
        .unwrap();
    let custody = artifacts
        .archive_custody(tenant, run.id, &source, 65_536)
        .await
        .unwrap();
    assert_eq!(custody, ArchiveCustodyV1::sensitive(deadline));
    assert!(artifacts
        .read_archive_content(tenant, run.id, &source, 65_536)
        .await
        .is_err());
    assert!(artifacts
        .archive_custody(TenantId::new(), run.id, &source, 65_536)
        .await
        .is_err());
    assert!(artifacts
        .archive_custody(tenant, run.id, &source, 65_535)
        .await
        .is_err());
    assert!(artifacts
        .read_archive_sensitive(
            tenant,
            run.id,
            &source,
            &ArchiveCustodyV1::sensitive(deadline + chrono::Duration::seconds(1)),
            65_536,
        )
        .await
        .is_err());
    let spool = dir.path().join("copy.warc.gz");
    assert!(artifacts
        .copy_archive_with_custody(
            tenant,
            run.id,
            &source,
            &ArchiveCustodyV1::content(Some(deadline)),
            &spool,
            65_536,
        )
        .await
        .is_err());
    assert!(!spool.exists());
    artifacts
        .copy_archive_with_custody(tenant, run.id, &source, &custody, &spool, 65_536)
        .await
        .unwrap();
    let shard = artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &spool, 65_536, &custody)
        .await
        .unwrap();
    let row = artifacts.row(shard.id).await.unwrap().unwrap();
    assert_eq!(row.sensitivity, Sensitivity::Sensitive);
    assert_eq!(row.expires_at, Some(deadline));
    let unbounded: ArchiveCustodyV1 = serde_json::from_value(serde_json::json!({
        "sensitivity":"sensitive", "expiresAt":null,
    }))
    .unwrap();
    assert!(artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &spool, 65_536, &unbounded,)
        .await
        .is_err());
    let mut stream = artifacts
        .stream_archive_with_custody(&shard, 65_536, &custody)
        .await
        .unwrap();
    clock.advance_ms(600_001);
    assert!(stream.try_next().await.is_err());
    assert!(artifacts
        .read_archive_sensitive(tenant, run.id, &source, &custody, 65_536)
        .await
        .is_err());
    assert!(artifacts
        .put_archive_file_with_custody(run.id, "application/warc", &spool, 65_536, &custody,)
        .await
        .is_err());
}

#[tokio::test]
async fn sensitive_source_shortening_or_revocation_between_read_and_publish_fails_closed() {
    use crawlx_core::repo::Sensitivity;
    use crawlx_storage::ArtifactIndex as _;
    for change in ["shorten", "revoke", "class", "digest"] {
        let clock = Arc::new(ManualClock::new(at()));
        let store = Arc::new(MemoryStore::with_clock(clock.clone()));
        let dir = tempfile::tempdir().unwrap();
        let artifacts = FsArtifactStore::open(dir.path(), store.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(store.clone());
        let tenant = TenantId::new();
        let run = source(store.as_ref(), tenant).await;
        let pending = ArchiveExportV1::pending(
            tenant,
            run.id,
            config(),
            at(),
            Some(at() + chrono::Duration::days(7)),
            TerminalReason::FrontierExhausted,
        );
        store.begin(&pending).await.unwrap();
        let claim = store
            .claim(tenant, pending.id, clock.now())
            .await
            .unwrap()
            .unwrap();
        let deadline = at() + chrono::Duration::minutes(10);
        let source = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "text/plain",
                b"owned retained body",
                deadline,
            )
            .await
            .unwrap();
        let custody = artifacts
            .archive_custody(tenant, run.id, &source, 1024)
            .await
            .unwrap();
        artifacts
            .read_archive_sensitive(tenant, run.id, &source, &custody, 1024)
            .await
            .unwrap();
        store
            .narrow_custody(tenant, pending.id, claim.fence, &custody, clock.now())
            .await
            .unwrap();
        let (mut record, ordinary_index) = member(&artifacts, &run, 1).await;
        let shard_bytes = artifacts.get(&record.artifact).await.unwrap();
        record.artifact = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/warc",
                &shard_bytes,
                deadline,
            )
            .await
            .unwrap();
        let index_bytes = artifacts.get(&ordinary_index).await.unwrap();
        let index = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/cdxj",
                &index_bytes,
                deadline,
            )
            .await
            .unwrap();
        record.custody = custody;
        record.source_artifact = Some(source.clone());
        store
            .commit_record(tenant, claim.fence, &record, None, clock.now())
            .await
            .unwrap();
        if change == "revoke" {
            store.mark_deleted(&[source.id]).await.unwrap();
        } else {
            let mut row = artifacts.row(source.id).await.unwrap().unwrap();
            match change {
                "shorten" => row.expires_at = Some(deadline - chrono::Duration::seconds(1)),
                "class" => row.sensitivity = Sensitivity::Content,
                "digest" => row.digest = crawlx_core::hash::Digest::of("crawlx/test/source", b"changed"),
                _ => unreachable!(),
            }
            store.record(&row).await.unwrap();
        }
        let mut manifest = ArchiveManifestV1::available(tenant, run.id, at());
        manifest.records = 1;
        manifest.custody = custody;
        assert!(store
            .publish(
                tenant,
                pending.id,
                claim.fence,
                &record.artifact,
                Some(&index),
                &manifest,
                clock.now(),
            )
            .await
            .is_err());
        assert!(!store
            .artifact_visible(tenant, &record.artifact, clock.now())
            .await
            .unwrap());
        assert!(store
            .commit_record(tenant, claim.fence, &record, None, clock.now())
            .await
            .is_err());
    }
}

#[tokio::test]
async fn postgres_sweeper_erases_sensitive_archive_objects_when_source_authority_changes() {
    use crawlx_core::repo::Sensitivity;
    use crawlx_storage::ArtifactIndex as _;
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!(
                "archive_source_retention_{}",
                uuid::Uuid::now_v7().simple()
            )),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "archive-source-retention-fixture")
        .await
        .unwrap();
    let clock = Arc::new(ManualClock::new(at()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = Arc::new(
        FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    for revoke in [false, true] {
        let run = source(&pg, tenant).await;
        let pending = ArchiveExportV1::pending(
            tenant,
            run.id,
            config(),
            at(),
            Some(at() + chrono::Duration::days(7)),
            TerminalReason::FrontierExhausted,
        );
        pg.begin(&pending).await.unwrap();
        let claim = pg.claim(tenant, pending.id, clock.now()).await.unwrap().unwrap();
        let deadline = at() + chrono::Duration::minutes(10) + chrono::Duration::nanoseconds(123_456_789);
        let evidence = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "text/plain",
                b"owned retained body",
                deadline,
            )
            .await
            .unwrap();
        let custody = artifacts
            .archive_custody(tenant, run.id, &evidence, 1024)
            .await
            .unwrap();
        pg.narrow_custody(tenant, pending.id, claim.fence, &custody, clock.now())
            .await
            .unwrap();
        let physical: Option<crawlx_core::Timestamp> =
            sqlx::query_scalar("SELECT expires_at FROM archive_exports WHERE tenant_id=$1 AND export_id=$2")
                .bind(tenant.0)
                .bind(pending.id)
                .fetch_one(pg.pool())
                .await
                .unwrap();
        let ArchiveReadV1::Available(persisted) = ArchiveRepo::get(&pg, tenant, pending.id, clock.now())
            .await
            .unwrap()
        else {
            panic!("narrowed archive missing");
        };
        assert_eq!(persisted.expires_at, physical);
        assert_eq!(persisted.custody.expires_at, physical);
        assert_eq!(physical, custody.expires_at);
        let physical = physical.unwrap();
        assert!(physical <= deadline);
        assert_eq!(physical.timestamp_subsec_nanos() % 1_000, 0);
        assert_ne!(deadline.timestamp_subsec_nanos() % 1_000, 0);
        let (mut record, ordinary_index) = member(artifacts.as_ref(), &run, 1).await;
        let shard_bytes = artifacts.get(&record.artifact).await.unwrap();
        record.artifact = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/warc",
                &shard_bytes,
                deadline,
            )
            .await
            .unwrap();
        let package = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/warc",
                &shard_bytes,
                deadline,
            )
            .await
            .unwrap();
        let index_bytes = artifacts.get(&ordinary_index).await.unwrap();
        let index = artifacts
            .put_until(
                run.id,
                Sensitivity::Sensitive,
                "application/cdxj",
                &index_bytes,
                deadline,
            )
            .await
            .unwrap();
        record.custody = custody;
        record.source_artifact = Some(evidence.clone());
        pg.commit_record(tenant, claim.fence, &record, None, clock.now())
            .await
            .unwrap();
        let mut manifest = ArchiveManifestV1::available(tenant, run.id, at());
        manifest.records = 1;
        manifest.custody = custody;
        pg.publish(
            tenant,
            pending.id,
            claim.fence,
            &package,
            Some(&index),
            &manifest,
            clock.now(),
        )
        .await
        .unwrap();
        if revoke {
            pg.mark_deleted(&[evidence.id]).await.unwrap();
        } else {
            sqlx::query("UPDATE artifacts SET expires_at=$2 WHERE artifact_id=$1")
                .bind(evidence.id.0)
                .bind(deadline - chrono::Duration::seconds(1))
                .execute(pg.pool())
                .await
                .unwrap();
        }
        assert!(!pg.artifact_visible(tenant, &package, clock.now()).await.unwrap());
        let report = crawlx_storage::retention::RetentionSweeper::new(pg.clone())
            .with_artifacts(artifacts.clone())
            .sweep(clock.now())
            .await
            .unwrap();
        assert!(report.artifacts_deleted >= 3);
        assert!(matches!(
            ArchiveRepo::get(&pg, tenant, pending.id, clock.now())
                .await
                .unwrap(),
            ArchiveReadV1::Missing
        ));
        assert!(pg.erased_artifacts(tenant, 64).await.unwrap().is_empty());
        for artifact in [&record.artifact, &package, &index] {
            assert!(artifacts.row(artifact.id).await.unwrap().is_none());
            assert!(artifacts.get(artifact).await.is_err());
        }
    }
    pg.drop_schema().await.unwrap();
}
