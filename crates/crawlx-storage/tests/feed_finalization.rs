//! Terminal feed intents and run status share one transaction, including a one-connection pool.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::dataset::{DeliveryBatchV1, DeliveryOutboxRepo, DeliveryRangeV1};
use crawlx_core::orchestration::RequestCommitRepo;
use crawlx_core::repo::{ArtifactStore, RunRepo};
use crawlx_core::secret::{ArtifactSink, Redactor};
use crawlx_core::{CrawlRunId, TenantId, WorkerId};
use crawlx_storage::artifacts::FsArtifactStore;
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{Pg, PgConfig, WorkerRegistry};
use std::sync::Arc;

#[tokio::test]
async fn postgres_terminal_empty_source_commits_with_status_and_rolls_back_invalid_feed() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            max_connections: 1,
            schema: Some(format!("feed_finalization_{}", CrawlRunId::new().0.simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "feed-fixture").await.unwrap();
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.mode = crawlx_core::config::RetentionMode::Standard;
    config.retention.days = 1;
    config.datasets = serde_json::from_value(serde_json::json!({"stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":4096}],
        "feeds":[{"id":"empty","source":"items","serializer":"json","serializerVersion":1,"destination":"fixture","maxBatchItems":2,"maxBatchBytes":4096,"emptyPolicy":"emit"}]})).unwrap();
    let run = crawl_run(tenant, config);
    pg.create(&run, None).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(
        directory.path(),
        Arc::new(pg.clone()),
        Arc::new(crawlx_core::SystemClock),
    )
    .await
    .unwrap()
    .with_index(Arc::new(pg.clone()));
    let approved = Redactor::new().verify_canonical(b"[]\n").unwrap();
    let reference = ArtifactSink::over(&artifacts)
        .put_dataset(run.id, -100, "empty", "application/json", &approved)
        .await
        .unwrap();
    let content = artifacts
        .dataset_content(run.id, -100, &reference, 3)
        .await
        .unwrap();
    let deadline = run.created_at + chrono::Duration::days(1);
    let mut batch = DeliveryBatchV1::for_request(
        "empty".into(),
        "terminal.empty.empty".into(),
        content,
        3,
        deadline,
    );
    batch.range = DeliveryRangeV1::Empty;
    let mut invalid = batch.clone();
    invalid.feed = "undeclared".into();
    assert!(pg
        .finalize_run_feeds(
            run.id,
            RunStatus::Completed,
            TerminalReason::FrontierExhausted,
            &[batch.clone(), invalid]
        )
        .await
        .is_err());
    assert!(!pg.get(run.id).await.unwrap().status.is_terminal());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dataset_delivery_outbox WHERE run_id=$1")
        .bind(run.id.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    pg.finalize_run_feeds(
        run.id,
        RunStatus::Completed,
        TerminalReason::FrontierExhausted,
        &[batch.clone()],
    )
    .await
    .unwrap();
    assert_eq!(pg.get(run.id).await.unwrap().status, RunStatus::Completed);
    let source:(bool,Option<i64>,Option<uuid::Uuid>) = sqlx::query_as("SELECT terminal_source,source_request_id,source_action_id FROM dataset_delivery_outbox WHERE run_id=$1")
        .bind(run.id.0).fetch_one(pg.pool()).await.unwrap();
    assert_eq!(source, (true, None, None));
    pg.finalize_run_feeds(
        run.id,
        RunStatus::Completed,
        TerminalReason::FrontierExhausted,
        &[],
    )
    .await
    .unwrap();
    let worker = WorkerId::new();
    pg.register_worker(worker, "feed-fixture", "1").await.unwrap();
    let claims = pg.claim(run.id, worker, 10, 60).await.unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].batch, batch);
    let foreign = TenantId::new();
    assert!(crawlx_storage::tenant::scope(
        foreign,
        pg.finalize_run_feeds(
            run.id,
            RunStatus::Completed,
            TerminalReason::FrontierExhausted,
            &[]
        )
    )
    .await
    .is_err());
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn postgres_recovers_seal_without_outbox_and_api_terminal_run_metadata() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            max_connections: 1,
            schema: Some(format!("feed_recovery_{}", CrawlRunId::new().0.simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "feed-fixture").await.unwrap();
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.datasets = serde_json::from_value(serde_json::json!({"stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":4096}],
        "feeds":[{"id":"feed","source":"items","serializer":"json","serializerVersion":1,"destination":"fixture","maxBatchItems":2,"maxBatchBytes":4096,"emptyPolicy":"emit"}]})).unwrap();
    let sealed = crawl_run(tenant, config.clone());
    let cancelled = crawl_run(tenant, config);
    pg.create(&sealed, None).await.unwrap();
    pg.create(&cancelled, None).await.unwrap();
    assert_eq!(
        pg.begin_feed_finalization(sealed.id, Some(TerminalReason::FatalError))
            .await
            .unwrap(),
        Some(TerminalReason::FatalError)
    );
    pg.set_status(
        cancelled.id,
        RunStatus::Cancelled,
        Some(TerminalReason::Cancelled),
    )
    .await
    .unwrap();
    let pending = pg.ready_runs(None, 10).await.unwrap();
    assert!(pending.contains(&sealed.id));
    assert!(pending.contains(&cancelled.id));
    assert_eq!(
        pg.begin_feed_finalization(sealed.id, None).await.unwrap(),
        Some(TerminalReason::FatalError)
    );
    assert_eq!(
        pg.begin_feed_finalization(cancelled.id, None).await.unwrap(),
        Some(TerminalReason::Cancelled)
    );
    let outbox: i64 = sqlx::query_scalar("SELECT count(*) FROM dataset_delivery_outbox")
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(outbox, 0);
    assert!(pg
        .finalize_run_feeds(sealed.id, RunStatus::Failed, TerminalReason::FatalError, &[])
        .await
        .is_err());
    assert!(!pg.get(sealed.id).await.unwrap().status.is_terminal());
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn postgres_missing_volatile_config_retires_pending_feeds_without_reading_source() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let clock = Arc::new(crawlx_core::time::ManualClock::new(chrono::Utc::now()));
    let buffer = Arc::new(crawlx_storage::DeliveryBuffer::new(
        clock,
        crawlx_storage::BufferLimits::default(),
    ));
    let pg = Pg::connect(
        &url,
        PgConfig {
            max_connections: 1,
            schema: Some(format!("feed_expiry_{}", CrawlRunId::new().0.simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap()
    .with_delivery_buffer(buffer.clone());
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "feed-fixture").await.unwrap();
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    config.retention.days = 0;
    config.datasets = serde_json::from_value(serde_json::json!({"stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":4096}],
        "feeds":[{"id":"feed","source":"items","serializer":"json","serializerVersion":1,"destination":"fixture","maxBatchItems":2,"maxBatchBytes":4096,"emptyPolicy":"emit"}]})).unwrap();
    let run = crawl_run(tenant, config);
    pg.create(&run, None).await.unwrap();
    pg.begin_feed_finalization(run.id, Some(TerminalReason::FatalError))
        .await
        .unwrap();
    buffer.ack(tenant, run.id, i64::MIN).await.unwrap();
    assert!(
        matches!(pg.maintain(run.id).await,Err(crawlx_core::StoreError::RetentionDenied(message)) if message=="feed content_expired")
    );
    assert!(!pg.ready_runs(None, 10).await.unwrap().contains(&run.id));
    assert_eq!(pg.begin_feed_finalization(run.id, None).await.unwrap(), None);
    let (status, outcome): (String, String) =
        sqlx::query_as("SELECT status::text,feed_finalization_outcome FROM crawl_runs WHERE run_id=$1")
            .bind(run.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert_eq!(status, "failed");
    let outcome: crawlx_core::dataset::FeedFinalizationOutcomeV1 =
        serde_json::from_value(serde_json::json!(outcome)).unwrap();
    assert_eq!(
        outcome,
        crawlx_core::dataset::FeedFinalizationOutcomeV1::ContentExpired
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dataset_delivery_outbox WHERE run_id=$1")
        .bind(run.id.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    pg.drop_schema().await.unwrap();
}

async fn staged_manifest_contract<R>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: crawlx_core::Timestamp,
) -> (crawlx_core::repo::CrawlRun, DeliveryBatchV1)
where
    R: RunRepo + RequestCommitRepo + crawlx_core::repo::FrontierRepo + WorkerRegistry,
{
    use crawlx_core::dataset::{AcceptedBatchV1, AcceptedItemV1};
    use crawlx_core::orchestration::{RequestBatchV1, RequestCommitV1};
    use crawlx_core::repo::FrontierStatus;
    use crawlx_core::request::RequestEnvelopeV1;
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.days = 1;
    config.datasets = serde_json::from_value(serde_json::json!({
        "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":4096}],
        "feeds":[{"id":"feed","source":"items","serializer":"jsonl","serializerVersion":1,
        "destination":"fixture","maxBatchItems":2,"maxBatchBytes":4096,"batching":"terminal"}]
    }))
    .unwrap();
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    repo.create(&run, None).await.unwrap();
    let worker = WorkerId::new();
    repo.register_worker(worker, "feed-fixture", "1").await.unwrap();
    repo.publish_acquisition_capabilities(
        worker,
        &[crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
            "fixture", "1",
        )],
    )
    .await
    .unwrap();
    let mut facts = crawlx_core::data_capabilities::WorkerDataCapabilitiesV1::default();
    facts.destinations.insert("fixture".into(), true);
    repo.publish_data_capabilities(worker, &facts).await.unwrap();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        crawlx_core::hash::Digest::of("feed/fixture", b"one"),
        vec![RequestEnvelopeV1::get(
            crawlx_storage::testkit::canonical_url("https://fixture.test/one"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let (entry, fence) = repo
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let approved = Redactor::new().verify_canonical(b"{\"value\":1}\n").unwrap();
    let reference = ArtifactSink::over(artifacts)
        .put_dataset(run.id, entry.id, "feed", "application/x-ndjson", &approved)
        .await
        .unwrap();
    let content = artifacts
        .dataset_content(run.id, entry.id, &reference, 12)
        .await
        .unwrap();
    let mut commit = RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
    let mut item = AcceptedItemV1::new(
        "one".into(),
        "fixture_v1".into(),
        "document_item_v1".into(),
        "fixture_v1".into(),
        content.clone(),
        12,
    );
    item.expires_at = Some(now + chrono::Duration::days(1));
    commit
        .accepted
        .push(AcceptedBatchV1::new("items".into(), vec![item]));
    repo.commit_fenced(commit).await.unwrap();
    assert!(repo
        .staged_feed_batch(run.id, "feed", "terminal.feed.1.1")
        .await
        .is_err());
    repo.begin_feed_finalization(run.id, Some(TerminalReason::FrontierExhausted))
        .await
        .unwrap();
    assert!(repo
        .staged_feed_batch(run.id, "feed", "terminal.feed.1.1")
        .await
        .unwrap()
        .is_none());
    let mut batch = DeliveryBatchV1::for_request(
        "feed".into(),
        "terminal.feed.1.1".into(),
        content,
        12,
        now + chrono::Duration::days(1),
    );
    batch.range = DeliveryRangeV1::Committed { first: 1, last: 1 };
    repo.stage_feed_batches(run.id, std::slice::from_ref(&batch))
        .await
        .unwrap();
    for _ in 0..2 {
        assert_eq!(
            repo.staged_feed_batch(run.id, "feed", &batch.idempotency_key)
                .await
                .unwrap(),
            Some(batch.clone())
        );
    }
    assert!(repo
        .staged_feed_batch(run.id, "feed", "terminal.feed.2.2")
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .staged_feed_batch(run.id, "unknown", &batch.idempotency_key)
        .await
        .is_err());
    assert!(crawlx_storage::tenant::scope(
        TenantId::new(),
        repo.staged_feed_batch(run.id, "feed", &batch.idempotency_key)
    )
    .await
    .is_err());
    (run, batch)
}

#[tokio::test]
async fn memory_staged_feed_lookup_preserves_identity_and_denies_revoked_or_expired_content() {
    use crawlx_core::Clock;
    use crawlx_storage::ArtifactIndex;
    let clock = Arc::new(crawlx_core::time::ManualClock::new(chrono::Utc::now()));
    let repo = Arc::new(crawlx_storage::MemoryStore::with_clock(clock.clone()));
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(directory.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone());
    let (run, batch) =
        staged_manifest_contract(repo.as_ref(), &artifacts, TenantId::new(), clock.now()).await;
    repo.mark_deleted(&[batch.content.artifact().id]).await.unwrap();
    assert!(matches!(
        repo.staged_feed_batch(run.id, "feed", &batch.idempotency_key)
            .await,
        Err(crawlx_core::StoreError::RetentionDenied(_))
    ));
    let (expired_run, expired_batch) =
        staged_manifest_contract(repo.as_ref(), &artifacts, TenantId::new(), clock.now()).await;
    clock.advance_ms(86_400_001);
    assert!(matches!(
        repo.staged_feed_batch(expired_run.id, "feed", &expired_batch.idempotency_key)
            .await,
        Err(crawlx_core::StoreError::RetentionDenied(_))
    ));
}

#[tokio::test]
async fn postgres_staged_feed_lookup_preserves_identity_and_denies_missing_sources_or_revoked_content() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("feed_lookup_{}", CrawlRunId::new().0.simple())),
            max_connections: 1,
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "feed-fixture").await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(
        directory.path(),
        Arc::new(pg.clone()),
        Arc::new(crawlx_core::SystemClock),
    )
    .await
    .unwrap()
    .with_index(Arc::new(pg.clone()));
    let (run, batch) = staged_manifest_contract(&pg, &artifacts, tenant, pg.db_now().await.unwrap()).await;
    sqlx::query("DELETE FROM dataset_items WHERE run_id=$1")
        .bind(run.id.0)
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        pg.staged_feed_batch(run.id, "feed", &batch.idempotency_key).await,
        Err(crawlx_core::StoreError::Conflict(_))
    ));
    sqlx::query("UPDATE artifacts SET deleted_at=clock_timestamp() WHERE artifact_id=$1")
        .bind(batch.content.artifact().id.0)
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(matches!(
        pg.staged_feed_batch(run.id, "feed", &batch.idempotency_key).await,
        Err(crawlx_core::StoreError::RetentionDenied(_))
    ));
    sqlx::query(
        "UPDATE dataset_delivery_outbox SET expires_at=clock_timestamp()-interval '1 second' WHERE run_id=$1",
    )
    .bind(run.id.0)
    .execute(pg.pool())
    .await
    .unwrap();
    assert!(matches!(
        pg.staged_feed_batch(run.id, "feed", &batch.idempotency_key).await,
        Err(crawlx_core::StoreError::RetentionDenied(_))
    ));
    pg.drop_schema().await.unwrap();
}
