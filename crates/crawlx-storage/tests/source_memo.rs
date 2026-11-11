//! Scoped seen/cache contracts. Optional PostgreSQL cases exercise restart and durable-ZDR denial.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use chrono::Duration;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::memo::{CategoryCacheEntryV1, MemoScopeV1, SourceMemoRepo};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ArtifactStore, CrawlRun, RunRepo};
use crawlx_core::secret::{ArtifactSink, Redactor};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, CrawlRunId, TenantId, Timestamp};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{BufferLimits, DeliveryBuffer, FsArtifactStore, MemoryStore, Pg, PgConfig};
use std::sync::Arc;

fn instant() -> Timestamp {
    "2026-11-10T00:00:00Z".parse().unwrap()
}
fn digest(value: &[u8]) -> Digest {
    Digest::of("source-memo-test/v1", value)
}
fn run(tenant: TenantId, now: Timestamp, zdr: bool) -> CrawlRun {
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.mode = if zdr {
        RetentionMode::Zdr
    } else {
        RetentionMode::Standard
    };
    config.retention.days = if zdr { 0 } else { 2 };
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    run
}
fn memo_scope(run: &CrawlRun) -> MemoScopeV1 {
    MemoScopeV1::new(
        run.tenant,
        run.id,
        digest(b"source"),
        digest(b"role"),
        digest(b"policy"),
    )
}
async fn seen_contract(repo: &dyn SourceMemoRepo, first: &CrawlRun, other: &CrawlRun, now: Timestamp) {
    let scope = memo_scope(first);
    let article = digest(b"article");
    assert!(!repo.seen(&scope, article, now).await.unwrap());
    repo.record_seen(&scope, &[article], 2, now).await.unwrap();
    assert!(repo.seen(&scope, article, now).await.unwrap());
    assert!(!repo.seen(&memo_scope(other), article, now).await.unwrap());
    for boundary in 0..3 {
        let mut isolated = scope;
        match boundary {
            0 => isolated.source = digest(b"other"),
            1 => isolated.role = digest(b"other"),
            _ => isolated.policy = digest(b"other"),
        }
        assert!(!repo.seen(&isolated, article, now).await.unwrap());
    }
    let mut foreign = scope;
    foreign.tenant = other.tenant;
    assert!(repo.seen(&foreign, article, now).await.is_err());
    assert!(repo.reset(other.tenant, first.id).await.is_err());
    let b = digest(b"b");
    let c = digest(b"c");
    repo.record_seen(&scope, &[b], 2, now + Duration::milliseconds(1))
        .await
        .unwrap();
    repo.record_seen(&scope, &[c], 2, now + Duration::milliseconds(2))
        .await
        .unwrap();
    assert!(!repo.seen(&scope, article, now).await.unwrap());
    assert!(repo.seen(&scope, b, now).await.unwrap());
    assert!(repo.seen(&scope, c, now).await.unwrap());
    let mut other_role = scope;
    other_role.role = digest(b"bounded-other-role");
    repo.record_seen(&other_role, &[article], 2, now + Duration::milliseconds(3))
        .await
        .unwrap();
    assert!(
        !repo.seen(&scope, b, now).await.unwrap(),
        "capacity spans every role and source scope"
    );
    assert!(repo.record_seen(&scope, &[article], 0, now).await.is_err());
    repo.reset(first.tenant, first.id).await.unwrap();
    assert!(!repo.seen(&scope, b, now).await.unwrap());
    repo.record_seen(&scope, &[article], 2, now).await.unwrap();
    assert!(
        repo.seen(&scope, article, now).await.unwrap(),
        "reset must permit re-admission"
    );
}
async fn cache_entry(
    artifacts: &dyn ArtifactStore,
    run: &CrawlRun,
    deadline: Timestamp,
) -> CategoryCacheEntryV1 {
    let bytes = br#"["https://fixture.test/category/science"]"#;
    let approved = Redactor::new().verify_canonical(bytes).unwrap();
    let reference = ArtifactSink::over(artifacts)
        .put_dataset_until(
            run.id,
            41,
            "source_categories",
            "application/json",
            &approved,
            deadline,
        )
        .await
        .unwrap();
    let size = u64::try_from(bytes.len()).unwrap();
    let content = artifacts
        .dataset_content(run.id, 41, &reference, size)
        .await
        .unwrap();
    let source_expiry = match &content {
        crawlx_core::dataset::DatasetContentV1::Durable { artifact } => {
            let custody = artifacts
                .archive_custody(run.tenant, run.id, artifact, size)
                .await
                .unwrap();
            assert_eq!(custody.sensitivity, crawlx_core::repo::Sensitivity::Content);
            custody.expires_at
        }
        _ => content.expires_at(),
    };
    let expiry = source_expiry.map_or(deadline, |original| deadline.min(original));
    CategoryCacheEntryV1::new(content, size, expiry)
}
async fn cache_contract(
    repo: &dyn SourceMemoRepo,
    run: &CrawlRun,
    other: &CrawlRun,
    entry: CategoryCacheEntryV1,
    now: Timestamp,
) {
    let scope = memo_scope(run);
    let representation = digest(b"representation");
    let expiry = entry.expires_at;
    repo.cache_category(&scope, representation, entry, now)
        .await
        .unwrap();
    assert!(repo
        .category(&scope, representation, expiry - Duration::milliseconds(1))
        .await
        .unwrap()
        .is_some());
    assert!(
        repo.category(&scope, representation, expiry)
            .await
            .unwrap()
            .is_none(),
        "expiry is exclusive, not one tick late"
    );
    assert!(repo
        .category(&scope, digest(b"new bytes"), now)
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .category(&memo_scope(other), representation, now)
        .await
        .unwrap()
        .is_none());
    for boundary in 0..3 {
        let mut isolated = scope;
        match boundary {
            0 => isolated.source = digest(b"other"),
            1 => isolated.role = digest(b"other"),
            _ => isolated.policy = digest(b"other"),
        }
        assert!(repo
            .category(&isolated, representation, now)
            .await
            .unwrap()
            .is_none());
    }
    repo.reset(run.tenant, run.id).await.unwrap();
    assert!(repo
        .category(&scope, representation, now)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn memory_scopes_capacity_reset_and_exact_worker_clock_expiry() {
    let now = instant();
    let clock = Arc::new(ManualClock::new(now));
    let store = Arc::new(MemoryStore::with_clock(clock.clone()));
    let a = run(TenantId::new(), now, false);
    let b = run(TenantId::new(), now, false);
    store.create(&a, None).await.unwrap();
    store.create(&b, None).await.unwrap();
    seen_contract(store.as_ref(), &a, &b, now).await;
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), store.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(store.clone());
    let entry = cache_entry(&artifacts, &a, now + Duration::hours(24)).await;
    assert_eq!(entry.expires_at, now + Duration::hours(24));
    cache_contract(store.as_ref(), &a, &b, entry.clone(), now).await;
    store
        .cache_category(&memo_scope(&a), digest(b"frozen"), entry, now)
        .await
        .unwrap();
    clock.advance_ms(86_399_999);
    assert!(store
        .category(&memo_scope(&a), digest(b"frozen"), clock.now())
        .await
        .unwrap()
        .is_some());
    clock.advance_ms(1);
    assert!(store
        .category(&memo_scope(&a), digest(b"frozen"), clock.now())
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn memory_zdr_seen_and_category_metadata_create_no_files() {
    let now = instant();
    let clock = Arc::new(ManualClock::new(now));
    let store = Arc::new(MemoryStore::with_clock(clock.clone()));
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    store.set_dataset_delivery(buffer.clone());
    let a = run(TenantId::new(), now, true);
    let b = run(TenantId::new(), now, true);
    store.create(&a, None).await.unwrap();
    store.create(&b, None).await.unwrap();
    seen_contract(store.as_ref(), &a, &b, now).await;
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), store.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(store.clone())
        .with_zdr_buffer(buffer);
    let entry = cache_entry(&artifacts, &a, now + Duration::minutes(10)).await;
    let mut durable = entry.clone();
    durable.content = crawlx_core::dataset::DatasetContentV1::Durable {
        artifact: entry.content.artifact().clone(),
    };
    assert!(store
        .cache_category(&memo_scope(&a), digest(b"durable-forbidden"), durable, now)
        .await
        .is_err());
    assert!(store
        .cache_category(&memo_scope(&b), digest(b"foreign-artifact"), entry.clone(), now)
        .await
        .is_err());
    cache_contract(store.as_ref(), &a, &b, entry, now).await;
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn postgres_restart_retains_scopes_and_shared_zdr_reset_never_writes_durable_metadata() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let now = chrono::Utc::now();
    let now = chrono::DateTime::from_timestamp(now.timestamp(), 123_456_789).unwrap();
    let clock = Arc::new(ManualClock::new(now));
    let config = PgConfig {
        schema: Some(format!("source_memo_{}", CrawlRunId::new().0.simple())),
        ..PgConfig::default()
    };
    let buffer = Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default()));
    let pg = Pg::connect(&url, config.clone())
        .await
        .unwrap()
        .with_delivery_buffer(buffer.clone());
    pg.migrate().await.unwrap();
    let a = run(TenantId::new(), now, false);
    let b = run(TenantId::new(), now, false);
    for tenant in [a.tenant, b.tenant] {
        pg.ensure_tenant(tenant, "memo-fixture").await.unwrap();
    }
    pg.create(&a, None).await.unwrap();
    pg.create(&b, None).await.unwrap();
    seen_contract(&pg, &a, &b, now).await;
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), clock.clone())
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let entry = cache_entry(&artifacts, &a, now + Duration::hours(24)).await;
    assert!(entry.expires_at <= now + Duration::hours(24));
    assert_eq!(entry.expires_at.timestamp_subsec_nanos() % 1000, 0);
    assert_ne!(
        entry.expires_at,
        now + Duration::hours(24),
        "committed precision must bound the requested expiry"
    );
    cache_contract(&pg, &a, &b, entry.clone(), now).await;
    pg.record_seen(&memo_scope(&a), &[digest(b"persisted")], 20_000, now)
        .await
        .unwrap();
    pg.cache_category(&memo_scope(&a), digest(b"persisted"), entry, now)
        .await
        .unwrap();
    let restarted = Pg::connect(&url, config)
        .await
        .unwrap()
        .with_delivery_buffer(buffer.clone());
    assert!(restarted
        .seen(&memo_scope(&a), digest(b"persisted"), now)
        .await
        .unwrap());
    assert!(restarted
        .category(&memo_scope(&a), digest(b"persisted"), now)
        .await
        .unwrap()
        .is_some());
    let zdr = run(a.tenant, now, true);
    pg.create(&zdr, None).await.unwrap();
    pg.record_seen(&memo_scope(&zdr), &[digest(b"private")], 20_000, now)
        .await
        .unwrap();
    assert!(restarted
        .seen(&memo_scope(&zdr), digest(b"private"), now)
        .await
        .unwrap());
    let zdr_dir = tempfile::tempdir().unwrap();
    let zdr_artifacts = FsArtifactStore::open(zdr_dir.path(), Arc::new(pg.clone()), clock)
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()))
        .with_zdr_buffer(buffer.clone());
    let entry = cache_entry(&zdr_artifacts, &zdr, now + Duration::minutes(10)).await;
    pg.cache_category(&memo_scope(&zdr), digest(b"private representation"), entry, now)
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT (SELECT count(*) FROM source_memo_seen WHERE run_id=$1)+(SELECT count(*) FROM source_category_cache WHERE run_id=$1)")
        .bind(zdr.id.0).fetch_one(pg.pool()).await.unwrap();
    assert_eq!(
        count, 0,
        "ZDR hashes and category references must not enter durable tables"
    );
    let stale_page = buffer
        .get(zdr.tenant, zdr.id, i64::MIN + 50)
        .await
        .unwrap()
        .unwrap();
    let stale_bytes = &stale_page.blobs["source_memo_v1.0"].bytes;
    restarted.reset(zdr.tenant, zdr.id).await.unwrap();
    // Model a cancelled remote write completing after the database reset releases its lock.
    buffer
        .insert_until(
            zdr.tenant,
            zdr.id,
            i64::MIN + 50,
            "source_memo_v1.0",
            "application/json",
            stale_bytes,
            stale_page.expires_at,
        )
        .await
        .unwrap();
    assert!(!pg.seen(&memo_scope(&zdr), digest(b"private"), now).await.unwrap());
    assert!(pg
        .category(&memo_scope(&zdr), digest(b"private representation"), now)
        .await
        .unwrap()
        .is_none());
    assert_eq!(std::fs::read_dir(zdr_dir.path()).unwrap().count(), 0);
    let denied = sqlx::query(
        "INSERT INTO source_memo_seen(tenant_id,run_id,lookup_key,recorded_at) VALUES($1,$2,$3,$4)",
    )
    .bind(zdr.tenant.0)
    .bind(zdr.id.0)
    .bind(digest(b"private").to_hex())
    .bind(now)
    .execute(pg.pool())
    .await;
    assert!(
        denied.is_err(),
        "database guard must reject direct durable ZDR memo writes"
    );
}

#[tokio::test]
async fn category_representation_count_stays_bounded_across_scopes() {
    let now = instant();
    let clock = Arc::new(ManualClock::new(now));
    let store = Arc::new(MemoryStore::with_clock(clock.clone()));
    let run = run(TenantId::new(), now, false);
    store.create(&run, None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(dir.path(), store.clone(), clock)
        .await
        .unwrap()
        .with_index(store.clone());
    let entry = cache_entry(&artifacts, &run, now + Duration::hours(24)).await;
    for ordinal in 0u8..65 {
        let mut scope = memo_scope(&run);
        scope.role = digest(&[ordinal]);
        store
            .cache_category(&scope, digest(&[ordinal]), entry.clone(), now)
            .await
            .unwrap();
    }
    let mut retained = 0usize;
    for ordinal in 0u8..65 {
        let mut scope = memo_scope(&run);
        scope.role = digest(&[ordinal]);
        retained += usize::from(
            store
                .category(&scope, digest(&[ordinal]), now)
                .await
                .unwrap()
                .is_some(),
        );
    }
    assert_eq!(retained, crawlx_core::dataset::memo::MAX_CATEGORY_CACHE_ENTRIES);
}
