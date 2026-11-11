//! Dataset/KV/outbox consumer regressions. PostgreSQL cases require CRAWLX_TEST_DATABASE_URL.
//! These tests exercise real repositories and retention-aware artifacts, not source-text wiring.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use chrono::{Duration, Utc};
use crawlx_core::acquisition::BackendCapabilitiesV1;
use crawlx_core::config::RetentionMode;
use crawlx_core::data_capabilities::WorkerDataCapabilitiesV1;
use crawlx_core::dataset::{
    AcceptedBatchV1, AcceptedItemV1, DatasetContentV1, DatasetRepo, DeliveryBatchV1, DeliveryOutboxRepo,
    DurableDeliveryOutboxV1, KvCasV1, KvRepo,
};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{RequestBatchV1, RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{ArtifactStore, CrawlRun, FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::secret::ArtifactSink;
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, CrawlRunId, StoreError, TenantId, WorkerId};
use crawlx_storage::artifacts::FsArtifactStore;
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{BufferLimits, DeliveryBuffer, MemoryStore, Pg, StoreConfig, WorkerRegistry};
use std::sync::Arc;

const CANARY: &[u8] = b"{\"value\":\"dataset-private-canary-73d28\"}\n";

fn run(tenant: TenantId, now: crawlx_core::Timestamp) -> CrawlRun {
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    config.datasets=serde_json::from_value(serde_json::json!({"version":1,
        "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":20,"maxBytes":1048576}],
        "kvStores":[{"name":"state","maxKeys":20,"maxValueBytes":1048576,"maxBytes":1048576},
            {"name":"drop","maxKeys":20,"maxValueBytes":1048576,"maxBytes":1048576}],
        "feeds":[{"id":"first","source":"items","serializer":"jsonl","serializerVersion":1,"destination":"fixture","maxBatchItems":10,"maxBatchBytes":1048576},
            {"id":"second","source":"items","serializer":"jsonl","serializerVersion":1,"destination":"fixture","maxBatchItems":10,"maxBatchBytes":1048576}]})).unwrap();
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    run
}

fn delta(content: &DatasetContentV1, store: &str, expected: u64) -> KvCasV1 {
    serde_json::from_value(serde_json::json!({"store":store,"key":"checkpoint","expectedVersion":expected,
        "content":content,"contentType":"application/json","sizeBytes":CANARY.len(),"expiresAt":content.expires_at()})).unwrap()
}
fn commit(
    run: &CrawlRun,
    request: i64,
    fence: i64,
    content: &DatasetContentV1,
    key: &str,
) -> RequestCommitV1 {
    let mut commit = RequestCommitV1::terminal(run.id, request, fence, 1, FrontierStatus::Succeeded, None);
    let item = AcceptedItemV1::new(
        key.into(),
        "fixture_v1".into(),
        "document_item_v1".into(),
        "fixture_v1".into(),
        content.clone(),
        u64::try_from(CANARY.len()).unwrap(),
    );
    commit
        .accepted
        .push(AcceptedBatchV1::new("items".into(), vec![item]));
    commit.state_deltas.push(delta(content, "state", 0));
    for feed in ["first", "second"] {
        commit.outbox.push(DeliveryBatchV1::for_request(
            feed.into(),
            format!("request.{request}.{feed}"),
            content.clone(),
            u64::try_from(CANARY.len()).unwrap(),
            content.expires_at().unwrap(),
        ));
    }
    commit
}
async fn worker<R: WorkerRegistry>(repo: &R) -> WorkerId {
    let worker = WorkerId::new();
    repo.register_worker(worker, "dataset-fixture", "1")
        .await
        .unwrap();
    repo.publish_acquisition_capabilities(worker, &[BackendCapabilitiesV1::native_http("fixture", "1")])
        .await
        .unwrap();
    let mut facts = WorkerDataCapabilitiesV1::default();
    facts.destinations.insert("fixture".into(), true);
    repo.publish_data_capabilities(worker, &facts).await.unwrap();
    worker
}

struct Pending {
    run: CrawlRun,
    content: DatasetContentV1,
    receipt: DurableDeliveryOutboxV1,
    worker: WorkerId,
}

async fn transactional_contract<R>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: crawlx_core::Timestamp,
) -> Pending
where
    R: RunRepo
        + FrontierRepo
        + RequestCommitRepo
        + DatasetRepo
        + KvRepo
        + DeliveryOutboxRepo
        + WorkerRegistry,
{
    let run = run(tenant, now);
    repo.create(&run, None).await.unwrap();
    let worker = worker(repo).await;
    let requests = ["one", "two"]
        .into_iter()
        .map(|name| RequestEnvelopeV1::get(canonical_url(&format!("https://example.test/{name}")), 0, None))
        .collect();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("dataset/batch", b"one"),
        requests,
    ))
    .await
    .unwrap();
    let leased = repo.lease_batch_fenced(run.id, worker, 2).await.unwrap();
    assert_eq!(leased.len(), 2);
    let page = leased[0].0.id;
    let approved = crawlx_core::secret::Redactor::new()
        .verify_canonical(CANARY)
        .unwrap();
    assert_eq!(approved.as_ref(), CANARY);
    let reference = ArtifactSink::over(artifacts)
        .put_dataset(run.id, page, "fixture", "application/json", &approved)
        .await
        .unwrap();
    let content = artifacts
        .dataset_content(run.id, page, &reference, u64::try_from(CANARY.len()).unwrap())
        .await
        .unwrap();
    let one = commit(&run, page, leased[0].1, &content, "one");
    let duplicate = commit(&run, page, leased[0].1, &content, "one");
    let (a, b) = tokio::join!(repo.commit_fenced(one), repo.commit_fenced(duplicate));
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "only one worker may commit the same request fence"
    );
    assert!(matches!(
        a.as_ref().err().or(b.as_ref().err()),
        Some(StoreError::LeaseLost)
    ));
    assert_eq!(repo.items(run.id, "items", 0, 100).await.unwrap().len(), 1);
    assert!(repo.items(run.id, "items", 1, 1).await.unwrap().is_empty());
    assert_eq!(
        repo.value(run.id, "state", "checkpoint")
            .await
            .unwrap()
            .unwrap()
            .version,
        1
    );
    let failed = commit(&run, leased[1].0.id, leased[1].1, &content, "rollback");
    assert!(
        matches!(repo.commit_fenced(failed).await, Err(StoreError::Conflict(_))),
        "CAS collision must roll back request/item/outbox together"
    );
    assert_eq!(repo.items(run.id, "items", 0, 100).await.unwrap().len(), 1);
    assert_eq!(
        repo.get_request(run.id, leased[1].0.id)
            .await
            .unwrap()
            .state_version,
        1
    );
    // Fail after accepted rows, state CAS and the first outbox row have been staged.
    let mut late = commit(&run, leased[1].0.id, leased[1].1, &content, "late_rollback");
    late.state_deltas[0].expected_version = 1;
    late.outbox[1].feed = "undeclared".into();
    assert!(matches!(
        repo.commit_fenced(late).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(repo.items(run.id, "items", 0, 100).await.unwrap().len(), 1);
    assert_eq!(
        repo.value(run.id, "state", "checkpoint")
            .await
            .unwrap()
            .unwrap()
            .version,
        1,
        "late outbox failure must roll back an otherwise valid CAS"
    );
    assert_eq!(
        repo.get_request(run.id, leased[1].0.id)
            .await
            .unwrap()
            .state_version,
        1
    );
    assert!(matches!(
        repo.compare_and_set(run.id, delta(&content, "state", 0)).await,
        Err(StoreError::Conflict(_))
    ));
    assert!(
        crawlx_storage::tenant::scope(TenantId::new(), repo.items(run.id, "items", 0, 10))
            .await
            .is_err()
    );
    assert!(
        crawlx_storage::tenant::scope(TenantId::new(), repo.value(run.id, "state", "checkpoint"))
            .await
            .is_err()
    );
    repo.compare_and_set(run.id, delta(&content, "drop", 0))
        .await
        .unwrap();
    repo.drop_store(run.id, "drop").await.unwrap();
    repo.drop_store(run.id, "drop").await.unwrap();
    assert!(repo.keys(run.id, "drop", "", 10).await.is_err());
    assert!(
        repo.compare_and_set(run.id, delta(&content, "drop", 0))
            .await
            .is_err(),
        "drop cannot recreate version zero"
    );
    let other = WorkerId::new();
    let (a, b) = tokio::join!(
        repo.claim(run.id, worker, 1, 60),
        repo.claim(run.id, other, 1, 60)
    );
    let a = a.unwrap().pop().unwrap();
    let b = b.unwrap().pop().unwrap();
    assert_ne!(a.id, b.id, "two workers must not claim the same live delivery");
    assert!(
        repo.claim(run.id, other, 10, 60).await.unwrap().is_empty(),
        "failed commit must leave no extra delivery"
    );
    assert!(matches!(
        repo.acknowledge(run.id, a.id, a.fence + 1).await,
        Err(StoreError::LeaseLost)
    ));
    repo.retry(run.id, a.id, a.fence, Utc::now() + Duration::seconds(10))
        .await
        .unwrap();
    assert!(repo.claim(run.id, other, 10, 60).await.unwrap().is_empty());
    repo.acknowledge(run.id, b.id, b.fence).await.unwrap();
    assert_eq!(
        artifacts.get(&reference).await.unwrap(),
        CANARY,
        "first receipt cannot erase another pending feed's bytes"
    );
    Pending {
        run,
        content,
        receipt: a,
        worker,
    }
}

async fn finish<R: DeliveryOutboxRepo + DatasetRepo + KvRepo>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    buffer: &DeliveryBuffer,
    pending: &Pending,
) {
    let current = repo
        .claim(pending.run.id, pending.worker, 1, 60)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(current.id, pending.receipt.id);
    assert!(current.fence > pending.receipt.fence);
    assert!(matches!(
        repo.acknowledge(pending.run.id, current.id, pending.receipt.fence)
            .await,
        Err(StoreError::LeaseLost)
    ));
    repo.acknowledge(pending.run.id, current.id, current.fence)
        .await
        .unwrap();
    repo.acknowledge(pending.run.id, current.id, current.fence)
        .await
        .unwrap();
    assert!(artifacts.get(pending.content.artifact()).await.is_err());
    if let DatasetContentV1::Volatile { page, .. } = pending.content {
        assert!(
            buffer
                .content_metadata(
                    pending.run.tenant,
                    pending.run.id,
                    page,
                    pending.content.artifact()
                )
                .await
                .unwrap()
                .is_none(),
            "ack must physically erase, not merely hide content"
        );
    }
    assert!(matches!(
        repo.items(pending.run.id, "items", 0, 10).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        repo.value(pending.run.id, "state", "checkpoint").await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(repo.ready_runs(None, 100).await.unwrap().is_empty());
}

#[tokio::test]
async fn memory_transactional_append_cas_fencing_retry_isolation_and_physical_ack() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    repo.set_dataset_delivery(buffer.clone());
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_zdr_buffer(buffer.clone());
    let pending = transactional_contract(repo.as_ref(), &artifacts, TenantId::new(), clock.now()).await;
    clock.advance_ms(11_000);
    finish(repo.as_ref(), &artifacts, &buffer, &pending).await;
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "ZDR must not create object/index/spool files"
    );
}

#[tokio::test]
async fn postgres_transactional_append_cas_fencing_retry_isolation_and_physical_ack() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("dataset_{}", CrawlRunId::new().0.simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap()
    .with_delivery_buffer(buffer.clone());
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "dataset-fixture").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()))
        .with_zdr_buffer(buffer.clone());
    let pending = transactional_contract(&pg, &artifacts, tenant, clock.now()).await;
    for table in [
        "crawl_runs",
        "url_frontier",
        "dataset_items",
        "dataset_kv",
        "dataset_delivery_outbox",
        "artifacts",
    ] {
        let rows: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT row_to_json(t)::text FROM {table} t WHERE run_id=$1"
        )))
        .bind(pending.run.id.0)
        .fetch_all(pg.pool())
        .await
        .unwrap();
        assert!(
            rows.iter()
                .all(|row| !row.contains("dataset-private-canary-73d28")),
            "canary leaked into {table}"
        );
    }
    let durable_payload: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM dataset_items WHERE run_id=$1 AND (payload IS NOT NULL OR volatile_page IS NULL)
            UNION ALL
            SELECT 1 FROM dataset_kv WHERE run_id=$1 AND (payload IS NOT NULL OR volatile_page IS NULL)
            UNION ALL
            SELECT 1 FROM dataset_delivery_outbox WHERE run_id=$1 AND (payload IS NOT NULL OR volatile_page IS NULL)
        )",
    )
    .bind(pending.run.id.0)
    .fetch_one(pg.pool())
    .await
    .unwrap();
    assert!(
        !durable_payload,
        "ZDR item/KV/outbox metadata must remain volatile, not merely omit the byte canary"
    );
    sqlx::query("UPDATE dataset_delivery_outbox SET not_before=now() WHERE run_id=$1 AND delivery_id=$2")
        .bind(pending.run.id.0)
        .bind(pending.receipt.id)
        .execute(pg.pool())
        .await
        .unwrap();
    finish(&pg, &artifacts, &buffer, &pending).await;
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn memory_expired_values_never_resurrect_and_maintenance_erases_without_send() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    repo.set_dataset_delivery(buffer.clone());
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_zdr_buffer(buffer.clone());
    let pending = transactional_contract(repo.as_ref(), &artifacts, TenantId::new(), clock.now()).await;
    clock.advance_ms(7_200_000);
    repo.maintain(pending.run.id).await.unwrap();
    assert!(repo
        .claim(pending.run.id, pending.worker, 10, 60)
        .await
        .unwrap()
        .is_empty());
    assert!(repo
        .compare_and_set(pending.run.id, delta(&pending.content, "state", 0))
        .await
        .is_err());
    assert!(repo
        .compare_and_set(pending.run.id, delta(&pending.content, "state", 1))
        .await
        .is_err());
    assert!(artifacts.get(pending.content.artifact()).await.is_err());
    assert!(repo.ready_runs(None, 100).await.unwrap().is_empty());
}

#[tokio::test]
async fn postgres_expired_rows_retire_and_physically_erase_even_with_expired_operational_config() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("dataset_expiry_{}", CrawlRunId::new().0.simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap()
    .with_delivery_buffer(buffer.clone());
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "dataset-expiry").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()))
        .with_zdr_buffer(buffer.clone());
    let pending = transactional_contract(&pg, &artifacts, tenant, clock.now()).await;
    sqlx::query("UPDATE dataset_delivery_outbox SET expires_at=now()-interval '1 second' WHERE run_id=$1 AND state='pending'")
        .bind(pending.run.id.0).execute(pg.pool()).await.unwrap();
    sqlx::query(
        "UPDATE dataset_kv SET expires_at=now()-interval '1 second' WHERE run_id=$1 AND store='state'",
    )
    .bind(pending.run.id.0)
    .execute(pg.pool())
    .await
    .unwrap();
    assert!(pg
        .compare_and_set(pending.run.id, delta(&pending.content, "state", 0))
        .await
        .is_err());
    assert!(pg
        .compare_and_set(pending.run.id, delta(&pending.content, "state", 1))
        .await
        .is_err());
    buffer.ack(tenant, pending.run.id, i64::MIN).await.unwrap();
    assert!(pg.get(pending.run.id).await.is_err());
    pg.maintain(pending.run.id).await.unwrap();
    assert!(buffer
        .content_metadata(
            tenant,
            pending.run.id,
            match pending.content {
                DatasetContentV1::Volatile { page, .. } => page,
                _ => unreachable!(),
            },
            pending.content.artifact()
        )
        .await
        .unwrap()
        .is_none());
    let receipt: (String, Option<chrono::DateTime<Utc>>) =
        sqlx::query_as("SELECT state,erased_at FROM dataset_delivery_outbox WHERE delivery_id=$1")
            .bind(pending.receipt.id)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert_eq!(receipt.0, "content_expired");
    assert!(receipt.1.is_some());
    assert!(pg.ready_runs(None, 100).await.unwrap().is_empty());
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn postgres_restart_after_commit_and_after_send_preserves_items_and_batch_identity() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("dataset_crash_{}", CrawlRunId::new().0.simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "dataset-crash").await.unwrap();
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let mut run = run(tenant, clock.now());
    run.config.retention.mode = RetentionMode::Standard;
    run.config.retention.days = 1;
    pg.create(&run, None).await.unwrap();
    let worker = worker(&pg).await;
    let request = RequestEnvelopeV1::get(canonical_url("https://example.test/crash"), 0, None);
    pg.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("dataset/crash", b"one"),
        vec![request],
    ))
    .await
    .unwrap();
    let lease = pg
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let deadline = clock.now() + Duration::days(1);
    let approved = crawlx_core::secret::Redactor::new()
        .verify_canonical(CANARY)
        .unwrap();
    assert_eq!(approved.as_ref(), CANARY);
    let reference = ArtifactSink::over(&artifacts)
        .put_dataset_until(
            run.id,
            lease.0.id,
            "durable",
            "application/json",
            &approved,
            deadline,
        )
        .await
        .unwrap();
    let content = artifacts
        .dataset_content(
            run.id,
            lease.0.id,
            &reference,
            u64::try_from(CANARY.len()).unwrap(),
        )
        .await
        .unwrap();
    let mut item = AcceptedItemV1::new(
        "durable".into(),
        "fixture_v1".into(),
        "document_item_v1".into(),
        "fixture_v1".into(),
        content.clone(),
        u64::try_from(CANARY.len()).unwrap(),
    );
    item.expires_at = Some(deadline);
    let mut commit =
        RequestCommitV1::terminal(run.id, lease.0.id, lease.1, 1, FrontierStatus::Succeeded, None);
    commit
        .accepted
        .push(AcceptedBatchV1::new("items".into(), vec![item]));
    commit.outbox.push(DeliveryBatchV1::for_request(
        "first".into(),
        "crash_batch".into(),
        content,
        u64::try_from(CANARY.len()).unwrap(),
        deadline,
    ));
    pg.commit_fenced(commit).await.unwrap();
    // Reconnect without any in-process outbox or serializer state.
    let observer = Pg::connect(&url, pg.config().clone()).await.unwrap();
    let reopened = FsArtifactStore::open(dir.path(), Arc::new(observer.clone()), clock)
        .await
        .unwrap()
        .with_index(Arc::new(observer.clone()));
    assert_eq!(observer.items(run.id, "items", 0, 10).await.unwrap().len(), 1);
    assert_eq!(reopened.get(&reference).await.unwrap(), CANARY);
    let first = observer
        .claim(run.id, WorkerId::new(), 1, 60)
        .await
        .unwrap()
        .pop()
        .unwrap();
    // The destination received these bytes, then the worker died before receipt commit.
    assert_eq!(
        reopened.get(first.batch.content.artifact()).await.unwrap(),
        CANARY
    );
    sqlx::query(
        "UPDATE dataset_delivery_outbox SET lease_expires_at=now()-interval '1 second' WHERE delivery_id=$1",
    )
    .bind(first.id)
    .execute(pg.pool())
    .await
    .unwrap();
    let next = pg
        .claim(run.id, WorkerId::new(), 1, 60)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(next.id, first.id);
    assert_eq!(next.batch, first.batch);
    assert!(next.fence > first.fence);
    assert!(matches!(
        pg.acknowledge(run.id, next.id, first.fence).await,
        Err(StoreError::LeaseLost)
    ));
    pg.acknowledge(run.id, next.id, next.fence).await.unwrap();
    assert_eq!(observer.items(run.id, "items", 0, 10).await.unwrap().len(), 1);
    assert_eq!(
        reopened.get(&reference).await.unwrap(),
        CANARY,
        "durable acknowledgement must not erase accepted item storage"
    );
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn memory_recovery_keysets_reach_runs_beyond_unavailable_first_page() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    repo.set_dataset_delivery(buffer.clone());
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_zdr_buffer(buffer);
    for _ in 0..17 {
        transactional_contract(repo.as_ref(), &artifacts, TenantId::new(), clock.now()).await;
    }
    clock.advance_ms(11_000);
    let first = repo.ready_runs(None, 16).await.unwrap();
    assert_eq!(first.len(), 16);
    let last = repo.ready_runs(first.last().copied(), 16).await.unwrap();
    assert_eq!(last.len(), 1);
    assert!(!first.contains(&last[0]));
    assert!(repo
        .ready_runs(last.last().copied(), 16)
        .await
        .unwrap()
        .is_empty());
}

#[path = "dataset/acceptance.rs"]
mod acceptance;

#[path = "dataset/digest_registry.rs"]
mod digest_registry;
