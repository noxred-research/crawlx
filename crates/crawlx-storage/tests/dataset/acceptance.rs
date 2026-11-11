//! Scale and metadata contracts share the real repository/artifact fixtures in the parent harness.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::dataset::{DatasetConfigV1, MAX_BATCH_ITEMS};

const ITEM_COUNT: u64 = 100_000;
// Reserve one slot for a repeated identity in every transaction.
const UNIQUE_BATCH: u64 = 999;

fn retained_run(tenant: TenantId, now: crawlx_core::Timestamp) -> CrawlRun {
    let mut config = run(tenant, now).config;
    config.retention.mode = RetentionMode::Standard;
    config.retention.days = 1;
    config.datasets.feeds.clear();
    let mut owner = crawl_run(tenant, config);
    owner.created_at = now;
    owner
}

async fn source_content<R>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    owner: &CrawlRun,
    worker: WorkerId,
) -> DatasetContentV1
where
    R: FrontierRepo + RequestCommitRepo,
{
    repo.append_batch(RequestBatchV1::new(
        owner.tenant,
        owner.id,
        "anonymous".into(),
        Digest::of("dataset/source", b"one"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://example.test/artifact-source"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let (request, fence) = repo
        .lease_batch_fenced(owner.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let approved = crawlx_core::secret::Redactor::new()
        .verify_canonical(CANARY)
        .unwrap();
    let reference = ArtifactSink::over(artifacts)
        .put_dataset_until(
            owner.id,
            request.id,
            "acceptance",
            "application/json",
            &approved,
            owner.created_at + Duration::days(1),
        )
        .await
        .unwrap();
    let content = artifacts
        .dataset_content(
            owner.id,
            request.id,
            &reference,
            u64::try_from(CANARY.len()).unwrap(),
        )
        .await
        .unwrap();
    repo.commit_fenced(RequestCommitV1::terminal(
        owner.id,
        request.id,
        fence,
        1,
        FrontierStatus::Succeeded,
        None,
    ))
    .await
    .unwrap();
    content
}

async fn seed_scale<R>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: crawlx_core::Timestamp,
) -> (CrawlRun, DatasetContentV1)
where
    R: RunRepo + FrontierRepo + RequestCommitRepo + WorkerRegistry,
{
    let mut owner = retained_run(tenant, now);
    owner.config.datasets.stores[0].max_items = ITEM_COUNT;
    owner.config.datasets.stores[0].max_bytes = ITEM_COUNT
        .checked_mul(u64::try_from(CANARY.len()).unwrap())
        .unwrap();
    owner.config_digest = owner.config.digest().unwrap();
    repo.create(&owner, None).await.unwrap();
    let worker = worker(repo).await;
    // One authorized blob backs all items; neither backend creates 100k physical artifacts.
    let content = source_content(repo, artifacts, &owner, worker).await;
    let batch_count = ITEM_COUNT.div_ceil(UNIQUE_BATCH);
    let requests: Vec<_> = (0..batch_count)
        .rev()
        .map(|index| {
            RequestEnvelopeV1::get(
                canonical_url(&format!("https://example.test/scale/{index}")),
                0,
                None,
            )
        })
        .collect();
    assert!(requests.len() <= MAX_BATCH_ITEMS);
    repo.append_batch(RequestBatchV1::new(
        tenant,
        owner.id,
        "anonymous".into(),
        Digest::of("dataset/scale", b"100000"),
        requests,
    ))
    .await
    .unwrap();
    let mut ordinal = 1;
    while ordinal <= ITEM_COUNT {
        // Lease only the request being committed; slow databases cannot expire future batches.
        let (request, fence) = repo
            .lease_batch_fenced(owner.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let end = ordinal.saturating_add(UNIQUE_BATCH - 1).min(ITEM_COUNT);
        let mut items = Vec::with_capacity(MAX_BATCH_ITEMS);
        for index in ordinal..=end {
            let mut item = AcceptedItemV1::new(
                format!("item.{index:06}"),
                format!("transform_v{}", index % 2 + 1),
                "document_item_v1".into(),
                format!("extractor_v{}", index % 3 + 1),
                content.clone(),
                u64::try_from(CANARY.len()).unwrap(),
            );
            item.expires_at = Some(now + Duration::days(1));
            items.push(item);
        }
        items.push(items[0].clone());
        assert!(items.len() <= MAX_BATCH_ITEMS);
        if ordinal == 1 {
            let mut rejected =
                RequestCommitV1::terminal(owner.id, request.id, fence, 1, FrontierStatus::Succeeded, None);
            let mut invalid = items[0].clone();
            invalid.schema_version = "undeclared_schema_v1".into();
            rejected.accepted.push(AcceptedBatchV1::new(
                "items".into(),
                vec![items[1].clone(), invalid],
            ));
            assert!(matches!(
                repo.commit_fenced(rejected).await,
                Err(StoreError::Conflict(_))
            ));
        }
        let mut commit =
            RequestCommitV1::terminal(owner.id, request.id, fence, 1, FrontierStatus::Succeeded, None);
        commit.accepted.push(AcceptedBatchV1::new("items".into(), items));
        repo.commit_fenced(commit).await.unwrap();
        assert!(matches!(
            repo.commit_fenced(RequestCommitV1::terminal(
                owner.id,
                request.id,
                fence,
                1,
                FrontierStatus::Succeeded,
                None,
            ))
            .await,
            Err(StoreError::LeaseLost)
        ));
        ordinal = end.checked_add(1).unwrap();
    }
    (owner, content)
}

async fn exact_page_range<R: DatasetRepo>(
    repo: &R,
    owner: &CrawlRun,
    content: &DatasetContentV1,
    mut after: u64,
    through: u64,
    limit: u16,
) -> u64 {
    while after < through {
        let bound = u16::try_from((through - after).min(u64::from(limit))).unwrap();
        let page = repo.items(owner.id, "items", after, bound).await.unwrap();
        assert_eq!(page.len(), usize::from(bound));
        assert!(page.capacity() <= MAX_BATCH_ITEMS);
        for row in page {
            after = after.checked_add(1).unwrap();
            assert_eq!(row.ordinal, after);
            assert_eq!(row.item.item_key, format!("item.{after:06}"));
            assert_eq!(
                row.item.transform_version,
                format!("transform_v{}", after % 2 + 1)
            );
            assert_eq!(
                row.item.extractor_version,
                format!("extractor_v{}", after % 3 + 1)
            );
            assert_eq!(row.item.schema_version, "document_item_v1");
            assert_eq!(&row.item.content, content);
            assert!(row.source_request > 0);
            assert!(row.source_action.is_none());
        }
    }
    after
}

#[tokio::test]
async fn memory_100k_committed_items_have_bounded_exact_repeatable_keysets() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone());
    let (owner, content) = seed_scale(repo.as_ref(), &artifacts, TenantId::new(), clock.now()).await;
    for limit in [137, 1000] {
        assert_eq!(
            exact_page_range(repo.as_ref(), &owner, &content, 0, ITEM_COUNT, limit).await,
            ITEM_COUNT
        );
        assert!(repo
            .items(owner.id, "items", ITEM_COUNT, limit)
            .await
            .unwrap()
            .is_empty());
    }
    assert!(repo.items(owner.id, "items", 0, 0).await.is_err());
    assert!(repo.items(owner.id, "items", 0, 1001).await.is_err());
    assert_eq!(artifacts.get(content.artifact()).await.unwrap(), CANARY);
}

#[tokio::test]
async fn postgres_100k_keyset_resumes_after_reconnect_without_loss_or_duplicate() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("dataset_scale_{}", CrawlRunId::new().0.simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "dataset-scale").await.unwrap();
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let (owner, content) = seed_scale(&pg, &artifacts, tenant, clock.now()).await;
    let after = exact_page_range(&pg, &owner, &content, 0, ITEM_COUNT / 2, 137).await;
    let config = pg.config().clone();
    drop(artifacts);
    pg.pool().close().await;
    drop(pg);
    // No producer repository, pool, artifact index or in-process cursor collection survives.
    let reopened = Pg::connect(&url, config).await.unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(reopened.clone()), clock)
        .await
        .unwrap()
        .with_index(Arc::new(reopened.clone()));
    assert_eq!(
        exact_page_range(&reopened, &owner, &content, after, ITEM_COUNT, 137).await,
        ITEM_COUNT
    );
    assert_eq!(
        exact_page_range(&reopened, &owner, &content, 0, ITEM_COUNT, 1000).await,
        ITEM_COUNT
    );
    assert!(reopened
        .items(owner.id, "items", ITEM_COUNT, 137)
        .await
        .unwrap()
        .is_empty());
    assert!(reopened.items(owner.id, "items", 0, 0).await.is_err());
    assert!(reopened.items(owner.id, "items", 0, 1001).await.is_err());
    let artifacts_count: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE run_id=$1")
        .bind(owner.id.0)
        .fetch_one(reopened.pool())
        .await
        .unwrap();
    assert_eq!(artifacts_count, 1);
    assert_eq!(artifacts.get(content.artifact()).await.unwrap(), CANARY);
    reopened.drop_schema().await.unwrap();
}

fn kv_change(content: &DatasetContentV1, store: &str, key: &str, expires: crawlx_core::Timestamp) -> KvCasV1 {
    let mut change = delta(content, store, 0);
    change.key = key.into();
    change.expires_at = Some(expires);
    change
}

async fn kv_contract<R>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: crawlx_core::Timestamp,
) -> CrawlRun
where
    R: RunRepo + FrontierRepo + RequestCommitRepo + KvRepo + WorkerRegistry,
{
    let size = u64::try_from(CANARY.len()).unwrap();
    let mut owner = retained_run(tenant, now);
    let config: DatasetConfigV1 = serde_json::from_value(serde_json::json!({
        "version": 1,
        "kvStores": [
            {"name":"state","maxKeys":20,"maxValueBytes":size,"maxBytes":size * 20},
            {"name":"keys","maxKeys":2,"maxValueBytes":size,"maxBytes":size * 10},
            {"name":"bytes","maxKeys":10,"maxValueBytes":size,"maxBytes":size * 2},
            {"name":"value","maxKeys":10,"maxValueBytes":size - 1,"maxBytes":size * 10}
        ]
    }))
    .unwrap();
    owner.config.datasets = config;
    owner.config_digest = owner.config.digest().unwrap();
    repo.create(&owner, None).await.unwrap();
    let worker = worker(repo).await;
    let content = source_content(repo, artifacts, &owner, worker).await;
    let deadline = now + Duration::days(1);
    // All malformed values must fail without inserting a key or allocating a CAS version.
    for invalid in [
        "",
        "not-a-mime",
        "/json",
        "text/",
        "text/plain/extra",
        "text plain/json",
        "text/plain; charset",
        "text/plain; charset=",
        "text/plain; charset=\"unterminated",
        "text/plain; =utf-8",
        "text/plain; charset=a b",
        "text/plain\r\nx:value",
        "text/*",
        "*/*",
        "text/plain; charset=\"dangling\\",
        "text/plain;\tcharset=utf-8",
        "text/pl\u{e9}ain",
        " text/plain",
    ] {
        let mut change = kv_change(&content, "state", "invalid", deadline);
        change.content_type = invalid.into();
        assert!(
            matches!(
                repo.compare_and_set(owner.id, change).await,
                Err(StoreError::Conflict(_))
            ),
            "invalid MIME accepted: {invalid:?}"
        );
        assert!(repo.value(owner.id, "state", "invalid").await.unwrap().is_none());
    }
    for (key, mime) in [
        ("mime1", "application/json; charset=utf-8"),
        ("mime2", "text/plain; charset=\"utf-8\""),
        ("mime3", "application/vnd.fixture+json; note=\"a;b\\\"c\""),
        ("mime4", "TEXT/PLAIN ; charset=\"\"; mode=flowed"),
        ("mime5", "application/octet-stream; title=\"caf\u{e9}\""),
    ] {
        let mut change = kv_change(&content, "state", key, deadline);
        change.content_type = mime.into();
        let value = repo.compare_and_set(owner.id, change).await.unwrap();
        assert_eq!(value.version, 1);
        assert_eq!(value.value.content_type, mime);
    }
    for store in ["keys", "bytes"] {
        for key in ["a", "b"] {
            repo.compare_and_set(owner.id, kv_change(&content, store, key, deadline))
                .await
                .unwrap();
        }
        assert!(matches!(
            repo.compare_and_set(owner.id, kv_change(&content, store, "c", deadline))
                .await,
            Err(StoreError::Conflict(_))
        ));
        assert!(repo.value(owner.id, store, "c").await.unwrap().is_none());
        assert_eq!(repo.keys(owner.id, store, "", 10).await.unwrap().len(), 2);
        let mut replacement = kv_change(&content, store, "a", deadline);
        replacement.expected_version = 1;
        assert_eq!(
            repo.compare_and_set(owner.id, replacement).await.unwrap().version,
            2
        );
    }
    let mut tombstone = kv_change(&content, "bytes", "a", deadline);
    tombstone.expected_version = 2;
    tombstone.content = None;
    tombstone.size_bytes = 0;
    assert_eq!(
        repo.compare_and_set(owner.id, tombstone).await.unwrap().version,
        3
    );
    assert_eq!(
        repo.compare_and_set(owner.id, kv_change(&content, "bytes", "c", deadline))
            .await
            .unwrap()
            .version,
        1,
        "rejected quota writes must not consume a version or retain a byte charge"
    );
    assert!(matches!(
        repo.compare_and_set(owner.id, kv_change(&content, "value", "too_big", deadline))
            .await,
        Err(StoreError::Conflict(_))
    ));
    assert!(repo.keys(owner.id, "value", "", 10).await.unwrap().is_empty());
    // Distinct namespace/run declarations never alias the same key.
    assert!(repo.value(owner.id, "state", "a").await.unwrap().is_none());
    let other = retained_run(tenant, now);
    repo.create(&other, None).await.unwrap();
    assert!(repo.keys(other.id, "state", "", 10).await.unwrap().is_empty());
    assert!(repo.value(other.id, "state", "mime1").await.unwrap().is_none());
    assert!(
        crawlx_storage::tenant::scope(TenantId::new(), repo.keys(owner.id, "state", "", 10))
            .await
            .is_err()
    );
    assert!(repo.keys(owner.id, "state", "", 0).await.is_err());
    assert!(repo.keys(owner.id, "state", "", 1001).await.is_err());
    // Expire keys on both sides of the saved cursor; an offset continuation would skip live keys.
    for key in ["a", "b", "c", "d", "e"] {
        let expiry = if key <= "c" {
            now + Duration::hours(12)
        } else {
            deadline
        };
        repo.compare_and_set(owner.id, kv_change(&content, "state", key, expiry))
            .await
            .unwrap();
    }
    let mut extension = kv_change(&content, "state", "b", deadline);
    extension.expected_version = 1;
    assert!(matches!(
        repo.compare_and_set(owner.id, extension).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        repo.value(owner.id, "state", "b")
            .await
            .unwrap()
            .unwrap()
            .value
            .expires_at,
        Some(now + Duration::hours(12))
    );
    let first = repo.keys(owner.id, "state", "", 2).await.unwrap();
    assert_eq!(
        first.iter().map(|v| v.value.key.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
    let encoded = serde_json::to_string(&first).unwrap();
    assert!(!encoded.contains("dataset-private-canary-73d28"));
    assert!(first
        .iter()
        .all(|value| value.value.size_bytes == size && value.version == 1));
    owner
}

async fn expired_continuation<R: KvRepo>(repo: &R, owner: &CrawlRun) {
    assert!(matches!(
        repo.value(owner.id, "state", "a").await,
        Err(StoreError::RetentionDenied(_))
    ));
    let next = repo.keys(owner.id, "state", "b", 2).await.unwrap();
    assert_eq!(
        next.iter().map(|v| v.value.key.as_str()).collect::<Vec<_>>(),
        ["d", "e"]
    );
    assert!(!serde_json::to_string(&next)
        .unwrap()
        .contains("dataset-private-canary-73d28"));
    let repeated = repo.keys(owner.id, "state", "b", 2).await.unwrap();
    assert_eq!(repeated, next, "expiry must not mutate the continuation token");
    let tail = repo.keys(owner.id, "state", "e", 2).await.unwrap();
    assert_eq!(
        tail.iter().map(|v| v.value.key.as_str()).collect::<Vec<_>>(),
        ["mime1", "mime2"]
    );
}

#[tokio::test]
async fn memory_kv_metadata_continuation_exact_expiry_mime_and_quotas() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone());
    let owner = kv_contract(repo.as_ref(), &artifacts, TenantId::new(), clock.now()).await;
    clock.advance_ms(43_199_999);
    assert_eq!(
        repo.keys(owner.id, "state", "b", 1).await.unwrap()[0].value.key,
        "c"
    );
    clock.advance_ms(1);
    expired_continuation(repo.as_ref(), &owner).await;
}

#[tokio::test]
async fn postgres_kv_metadata_continuation_expiry_mime_and_quotas() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("dataset_kv_contract_{}", CrawlRunId::new().0.simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "dataset-kv-contract").await.unwrap();
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let owner = kv_contract(&pg, &artifacts, tenant, clock.now()).await;
    // Advance the database boundary explicitly, without sleeping or changing the host clock.
    sqlx::query(
        "UPDATE dataset_kv SET expires_at=now() WHERE run_id=$1 AND store='state' AND key IN ('a','b','c')",
    )
    .bind(owner.id.0)
    .execute(pg.pool())
    .await
    .unwrap();
    let reopened = Pg::connect(&url, pg.config().clone()).await.unwrap();
    expired_continuation(&reopened, &owner).await;
    pg.drop_schema().await.unwrap();
}
