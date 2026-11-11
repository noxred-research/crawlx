//! Conformance cases (datasets): accepted items, versioned KV, the delivery outbox, terminal
//! feed finalization and the source memo.
//!
//! Every case is written once against the repository traits. Fixtures that need a run, frontier
//! rows, request commits and workers use `RunRepo`, `FrontierRepo`, `RequestCommitRepo` and
//! `WorkerRegistry`. Time moves differently per engine: the in-memory store follows a manual
//! clock, the databases follow their own clock, so a case that needs "later" asks `Env` (memory)
//! or edits the stored deadline with raw SQL (databases), the way the PostgreSQL regression
//! tests always did.

use crate::rig::Rig;
use chrono::{Duration, Utc};
use crawlx_core::acquisition::BackendCapabilitiesV1;
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::custody::CustodySource;
use crawlx_core::data_capabilities::WorkerDataCapabilitiesV1;
use crawlx_core::data_capabilities::WorkerDataRequirementsV1;
use crawlx_core::dataset::memo::{
    CategoryCacheEntryV1, MemoScopeV1, SourceMemoRepo, MAX_CATEGORY_CACHE_ENTRIES,
};
use crawlx_core::dataset::{
    AcceptedBatchV1, AcceptedItemV1, DatasetConfigV1, DatasetContentV1, DatasetRepo, DeliveryBatchV1,
    DeliveryOutboxRepo, DeliveryRangeV1, DurableDeliveryOutboxV1, KvCasV1, KvRepo, MAX_BATCH_ITEMS,
};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{RequestBatchV1, RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{ArtifactStore, CrawlRun, FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::secret::{ArtifactSink, Redactor};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, StoreError, TenantId, Timestamp, WorkerId};
use crawlx_storage::artifacts::FsArtifactStore;
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl, Engine};
use crawlx_storage::{ArtifactIndex, BufferLimits, DeliveryBuffer, MemoryStore, WorkerRegistry};
use sqlx::Row as _;
use std::sync::Arc;

conformance! { all:
    transactional_append_cas_fencing_retry_isolation_and_physical_ack,
    expired_rows_retire_and_physically_erase_even_with_expired_operational_config,
    keyset_resumes_exactly_over_many_committed_items,
    kv_metadata_continuation_exact_expiry_mime_and_quotas,
    terminal_empty_source_commits_with_status_and_rolls_back_invalid_feed,
    seal_without_outbox_recovers_and_keeps_terminal_run_metadata,
    missing_volatile_config_retires_pending_feeds_without_reading_source,
    staged_feed_lookup_preserves_identity_and_denies_revoked_or_expired_content,
    source_memo_scopes_capacity_and_reset,
    source_memo_zdr_creates_no_files_and_refuses_durable_content,
    source_memo_category_count_stays_bounded_across_scopes,
    outbox_claims_in_id_order_and_bounds_leases_acks_and_retries,
    outbox_expiry_retires_expired_rows,
    kv_compare_and_set_collision_quota_and_drop_store,
    recovery_keysets_reach_runs_beyond_the_first_page,
    feed_finalizer_claim_is_exclusive_fenced_expiring_and_ends_with_finalization,
    compressed_feed_runs_are_only_eligible_where_compressed_bytes_are_published,
}

conformance! { databases:
    restart_after_commit_and_after_send_preserves_items_and_batch_identity,
    source_memo_restart_retains_scopes_and_zdr_never_writes_durable_metadata,
}

const CANARY: &[u8] = b"{\"value\":\"dataset-private-canary-73d28\"}\n";
const ITEM_CEILING: u64 = 100_000;
// Reserve one slot for a repeated identity in every transaction.
const UNIQUE_BATCH: u64 = 999;

/// A new handle over the same stored state with nothing else carried along: the database
/// engines hand out another `Store` over the same pool (no cursor, outbox or serializer state
/// lives in a handle); the in-memory store has no storage apart from itself.
trait Fresh: Sized {
    fn fresh(this: &Arc<Self>) -> Arc<Self>;
}

impl Fresh for MemoryStore {
    fn fresh(this: &Arc<Self>) -> Arc<Self> {
        this.clone()
    }
}

impl<B: crawlx_storage::Backend> Fresh for crawlx_storage::Store<B> {
    fn fresh(this: &Arc<Self>) -> Arc<Self> {
        Arc::new(this.as_ref().clone())
    }
}

/// Everything of a repository a case may touch.
trait Repo:
    RunRepo
    + FrontierRepo
    + RequestCommitRepo
    + DatasetRepo
    + KvRepo
    + DeliveryOutboxRepo
    + SourceMemoRepo
    + WorkerRegistry
    + ArtifactIndex
    + Fresh
    + Send
    + Sync
    + 'static
{
}

impl<T> Repo for T where
    T: RunRepo
        + FrontierRepo
        + RequestCommitRepo
        + DatasetRepo
        + KvRepo
        + DeliveryOutboxRepo
        + SourceMemoRepo
        + WorkerRegistry
        + ArtifactIndex
        + Fresh
        + Send
        + Sync
        + 'static
{
}

/// The clock, volatile delivery buffer and scratch directory of one case.
struct Env {
    clock: Arc<ManualClock>,
    buffer: Arc<DeliveryBuffer>,
    dir: tempfile::TempDir,
}

impl Env {
    fn new() -> Self {
        let clock = Arc::new(ManualClock::new(Utc::now()));
        Self {
            buffer: Arc::new(DeliveryBuffer::new(clock.clone(), BufferLimits::default())),
            clock,
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Files under the scratch directory (a ZDR run must never create one).
    fn files(&self) -> usize {
        std::fs::read_dir(self.dir.path()).unwrap().count()
    }
}

/// Run `$body` with `$repo` bound to a shared handle of the engine's repository: the in-memory
/// store on the case's manual clock, or a handle of the database store; both carry the case's
/// delivery buffer.
macro_rules! on_env {
    ($rig:expr, $env:expr, |$repo:ident| $body:expr) => {{
        match $rig.engine() {
            Engine::Memory => {
                let owned = Arc::new(MemoryStore::with_clock($env.clock.clone()));
                owned.set_dataset_delivery($env.buffer.clone());
                let $repo = &owned;
                Box::pin(async { $body }).await
            }
            Engine::Sqlite => {
                let owned = Arc::new(
                    $rig.database()
                        .sqlite_store()
                        .expect("a sqlite rig has a store")
                        .clone()
                        .with_delivery_buffer($env.buffer.clone()),
                );
                let $repo = &owned;
                Box::pin(async { $body }).await
            }
            Engine::MariaDb => {
                let owned = Arc::new(
                    $rig.database()
                        .mariadb_store()
                        .expect("a mariadb rig has a store")
                        .clone()
                        .with_delivery_buffer($env.buffer.clone()),
                );
                let $repo = &owned;
                Box::pin(async { $body }).await
            }
            Engine::Postgres => {
                let owned = Arc::new(
                    $rig.database()
                        .postgres()
                        .expect("a postgres rig has a store")
                        .clone()
                        .with_delivery_buffer($env.buffer.clone()),
                );
                let $repo = &owned;
                Box::pin(async { $body }).await
            }
            _ => panic!("every engine of the suite is handled above"),
        }
    }};
}

/// A tenant the engine accepts rows for.
async fn tenant_of(rig: &Rig) -> TenantId {
    let tenant = TenantId::new();
    if rig.engine() != Engine::Memory {
        rig.insert_tenant(tenant.0).await.unwrap();
    }
    tenant
}

/// Migrate a database rig.
async fn ready(rig: &Rig) {
    if rig.engine() != Engine::Memory {
        rig.migrate().await;
    }
}

// ---------------------------------------------------------------------------------------
// Raw SQL on the engine's own pool (state the repositories do not expose).
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Bind<'a> {
    Uuid(uuid::Uuid),
    I64(i64),
    Text(&'a str),
}

/// The statement of `template` for `engine`: `$n` placeholders in the engine's spelling and
/// `{now}`, `{past}` (one second ago) and `{key}` (the reserved `key` column) spliced in.
/// Returns the text and, for MariaDB, the bind order (placeholders are positional there).
fn expand(engine: Engine, template: &str) -> (String, Vec<usize>) {
    let (now, past) = match engine {
        Engine::Postgres => ("now()", "(now() - interval '1 second')"),
        Engine::MariaDb => ("NOW(6)", "(NOW(6) - INTERVAL 1 SECOND)"),
        _ => (
            "CAST(unixepoch('subsec') * 1000000 AS INTEGER)",
            "(CAST(unixepoch('subsec') * 1000000 AS INTEGER) - 1000000)",
        ),
    };
    let key = if engine == Engine::MariaDb { "`key`" } else { "key" };
    let text = template
        .replace("{now}", now)
        .replace("{past}", past)
        .replace("{key}", key);
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut order = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'$' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            let mut j = i + 1;
            let mut n = 0usize;
            while let Some(d) = bytes.get(j).filter(|c| c.is_ascii_digit()) {
                n = n * 10 + usize::from(d - b'0');
                j += 1;
            }
            match engine {
                Engine::Sqlite => out.push_str(&format!("?{n}")),
                Engine::MariaDb => {
                    out.push('?');
                    order.push(n);
                }
                _ => out.push_str(&format!("${n}")),
            }
            i = j;
        } else {
            out.push(char::from(bytes[i]));
            i += 1;
        }
    }
    (out, order)
}

macro_rules! bound {
    ($sql:expr, $binds:expr) => {{
        let mut query = sqlx::query(sqlx::AssertSqlSafe($sql));
        for bind in $binds {
            query = match bind {
                Bind::Uuid(value) => query.bind(*value),
                Bind::I64(value) => query.bind(*value),
                Bind::Text(value) => query.bind((*value).to_owned()),
            };
        }
        query
    }};
}

fn ordered<'a>(engine: Engine, order: &[usize], binds: &[Bind<'a>]) -> Vec<Bind<'a>> {
    if engine == Engine::MariaDb {
        order.iter().map(|n| binds[n - 1]).collect()
    } else {
        binds.to_vec()
    }
}

/// Run a statement; the engine's refusal comes back as an error.
async fn try_exec(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> Result<u64, sqlx::Error> {
    let engine = rig.engine();
    let (sql, order) = expand(engine, template);
    let binds = ordered(engine, &order, binds);
    let database = rig.database();
    match engine {
        Engine::Sqlite => bound!(sql, &binds)
            .execute(database.sqlite_pool().unwrap())
            .await
            .map(|done| done.rows_affected()),
        Engine::MariaDb => bound!(sql, &binds)
            .execute(database.mariadb_pool().unwrap())
            .await
            .map(|done| done.rows_affected()),
        _ => bound!(sql, &binds)
            .execute(database.postgres().unwrap().pool())
            .await
            .map(|done| done.rows_affected()),
    }
}

async fn exec(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> u64 {
    try_exec(rig, template, binds).await.unwrap()
}

/// The first column of the first row as an integer.
async fn scalar(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> i64 {
    let engine = rig.engine();
    let (sql, order) = expand(engine, template);
    let binds = ordered(engine, &order, binds);
    let database = rig.database();
    match engine {
        Engine::Sqlite => bound!(sql, &binds)
            .fetch_one(database.sqlite_pool().unwrap())
            .await
            .unwrap()
            .get::<i64, _>(0),
        Engine::MariaDb => bound!(sql, &binds)
            .fetch_one(database.mariadb_pool().unwrap())
            .await
            .unwrap()
            .get::<i64, _>(0),
        _ => bound!(sql, &binds)
            .fetch_one(database.postgres().unwrap().pool())
            .await
            .unwrap()
            .get::<i64, _>(0),
    }
}

/// The first column of the first row as text.
async fn scalar_text(rig: &Rig, template: &str, binds: &[Bind<'_>]) -> String {
    let engine = rig.engine();
    let (sql, order) = expand(engine, template);
    let binds = ordered(engine, &order, binds);
    let database = rig.database();
    match engine {
        Engine::Sqlite => bound!(sql, &binds)
            .fetch_one(database.sqlite_pool().unwrap())
            .await
            .unwrap()
            .get::<String, _>(0),
        Engine::MariaDb => bound!(sql, &binds)
            .fetch_one(database.mariadb_pool().unwrap())
            .await
            .unwrap()
            .get::<String, _>(0),
        _ => bound!(sql, &binds)
            .fetch_one(database.postgres().unwrap().pool())
            .await
            .unwrap()
            .get::<String, _>(0),
    }
}

// ---------------------------------------------------------------------------------------
// Fixtures shared by the cases.
// ---------------------------------------------------------------------------------------

/// A zero-retention run with two stores, two KV namespaces and two feeds.
fn zdr_run(tenant: TenantId, now: Timestamp) -> CrawlRun {
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    config.datasets = serde_json::from_value(serde_json::json!({"version":1,
        "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":20,"maxBytes":1048576}],
        "kvStores":[{"name":"state","maxKeys":20,"maxValueBytes":1048576,"maxBytes":1048576},
            {"name":"drop","maxKeys":20,"maxValueBytes":1048576,"maxBytes":1048576}],
        "feeds":[{"id":"first","source":"items","serializer":"jsonl","serializerVersion":1,"destination":"fixture","maxBatchItems":10,"maxBatchBytes":1048576},
            {"id":"second","source":"items","serializer":"jsonl","serializerVersion":1,"destination":"fixture","maxBatchItems":10,"maxBatchBytes":1048576}]})).unwrap();
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    run
}

/// A retained run (one day) with the scale/KV dataset declarations and no feeds.
fn retained_run(tenant: TenantId, now: Timestamp) -> CrawlRun {
    let mut config = zdr_run(tenant, now).config;
    config.retention.mode = RetentionMode::Standard;
    config.retention.days = 1;
    config.datasets.feeds.clear();
    let mut owner = crawl_run(tenant, config);
    owner.created_at = now;
    owner
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

/// The artifact store of a case over `repo`; zero-retention content goes to the buffer.
async fn artifact_store<R: Repo>(repo: &Arc<R>, env: &Env, zdr: bool) -> FsArtifactStore {
    let store = FsArtifactStore::open(env.dir.path(), repo.clone(), env.clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone());
    if zdr {
        store.with_zdr_buffer(env.buffer.clone())
    } else {
        store
    }
}

/// Volatile content parked in the delivery buffer under `page`, valid for an hour.
async fn volatile_content(env: &Env, run: &CrawlRun, page: i64, bytes: &[u8]) -> DatasetContentV1 {
    let deadline = env.now() + Duration::hours(1);
    let artifact = env
        .buffer
        .insert_until(
            run.tenant,
            run.id,
            page,
            "dataset.fixture",
            "application/json",
            bytes,
            deadline,
        )
        .await
        .unwrap();
    let (expires_at, size) = env
        .buffer
        .content_metadata(run.tenant, run.id, page, &artifact)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(size, u64::try_from(bytes.len()).unwrap());
    DatasetContentV1::Volatile {
        page,
        artifact,
        expires_at,
    }
}

// ---------------------------------------------------------------------------------------
// Transactional contract: items, CAS, outbox, fencing, retry, isolation and physical ack.
// ---------------------------------------------------------------------------------------

struct Pending {
    run: CrawlRun,
    content: DatasetContentV1,
    receipt: DurableDeliveryOutboxV1,
    worker: WorkerId,
}

async fn transactional_contract<R: Repo>(
    repo: &Arc<R>,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: Timestamp,
) -> Pending {
    let repo = repo.as_ref();
    let run = zdr_run(tenant, now);
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
    let approved = Redactor::new().verify_canonical(CANARY).unwrap();
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

async fn transactional_append_cas_fencing_retry_isolation_and_physical_ack(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| {
        async {
        let artifacts = artifact_store(repo, &env, true).await;
        let pending = transactional_contract(repo, &artifacts, tenant, env.now()).await;
        let run = Bind::Uuid(pending.run.id.0);
        if rig.engine() == Engine::Memory {
            env.clock.advance_ms(11_000);
        } else {
            // zero-retention rows hold no content, only volatile metadata
            for table in ["dataset_items", "dataset_kv", "dataset_delivery_outbox"] {
                let durable = scalar(
                    rig,
                    &format!("SELECT count(*) FROM {table} WHERE run_id = $1 AND (payload IS NOT NULL OR volatile_page IS NULL)"),
                    &[run],
                )
                .await;
                assert_eq!(
                    durable, 0,
                    "ZDR {table} metadata must remain volatile, not merely omit the byte canary"
                );
            }
            // the retry moved `not_before` ahead; make the delivery due again
            exec(
                rig,
                "UPDATE dataset_delivery_outbox SET not_before = {now} WHERE run_id = $1 AND delivery_id = $2",
                &[run, Bind::I64(pending.receipt.id)],
            )
            .await;
        }
        finish(repo.as_ref(), &artifacts, &env.buffer, &pending).await;
        assert_eq!(env.files(), 0, "ZDR must not create object, index or spool files");
    }
    .await
    });
}

// ---------------------------------------------------------------------------------------
// Expiry: rows retire and content is erased even when operational configuration expired.
// ---------------------------------------------------------------------------------------

async fn expired_rows_retire_and_physically_erase_even_with_expired_operational_config(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| {
        async {
        let artifacts = artifact_store(repo, &env, true).await;
        let pending = transactional_contract(repo, &artifacts, tenant, env.now()).await;
        let run = pending.run.id;
        let repo = repo.as_ref();
        if rig.engine() == Engine::Memory {
            env.clock.advance_ms(7_200_000);
        } else {
            let id = Bind::Uuid(run.0);
            exec(
                rig,
                "UPDATE dataset_delivery_outbox SET expires_at = {past} WHERE run_id = $1 AND state = 'pending'",
                &[id],
            )
            .await;
            exec(
                rig,
                "UPDATE dataset_kv SET expires_at = {past} WHERE run_id = $1 AND store = 'state'",
                &[id],
            )
            .await;
        }
        assert!(repo
            .compare_and_set(run, delta(&pending.content, "state", 0))
            .await
            .is_err());
        assert!(repo
            .compare_and_set(run, delta(&pending.content, "state", 1))
            .await
            .is_err());
        if rig.engine() != Engine::Memory {
            // the volatile run configuration is gone too: the run can no longer be read
            env.buffer.ack(tenant, run, i64::MIN).await.unwrap();
            assert!(repo.get(run).await.is_err());
        }
        repo.maintain(run).await.unwrap();
        assert!(repo.claim(run, pending.worker, 10, 60).await.unwrap().is_empty());
        assert!(artifacts.get(pending.content.artifact()).await.is_err());
        assert!(repo.ready_runs(None, 100).await.unwrap().is_empty());
        if rig.engine() != Engine::Memory {
            let DatasetContentV1::Volatile { page, .. } = pending.content else {
                unreachable!("the fixture run is zero-retention")
            };
            assert!(env
                .buffer
                .content_metadata(tenant, run, page, pending.content.artifact())
                .await
                .unwrap()
                .is_none());
            let id = [Bind::I64(pending.receipt.id)];
            assert_eq!(
                scalar_text(rig, "SELECT state FROM dataset_delivery_outbox WHERE delivery_id = $1", &id).await,
                "content_expired"
            );
            assert_eq!(
                scalar(
                    rig,
                    "SELECT count(*) FROM dataset_delivery_outbox WHERE delivery_id = $1 AND erased_at IS NOT NULL",
                    &id,
                )
                .await,
                1
            );
        }
    }
    .await
    });
}

// ---------------------------------------------------------------------------------------
// Restart: no in-process state carries items, receipts or batch identity.
// ---------------------------------------------------------------------------------------

async fn restart_after_commit_and_after_send_preserves_items_and_batch_identity(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let mut run = zdr_run(tenant, env.now());
        run.config.retention.mode = RetentionMode::Standard;
        run.config.retention.days = 1;
        store.create(&run, None).await.unwrap();
        let worker = worker(store).await;
        let request = RequestEnvelopeV1::get(canonical_url("https://example.test/crash"), 0, None);
        store
            .append_batch(RequestBatchV1::new(
                tenant,
                run.id,
                "anonymous".into(),
                Digest::of("dataset/crash", b"one"),
                vec![request],
            ))
            .await
            .unwrap();
        let lease = store
            .lease_batch_fenced(run.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let artifacts = artifact_store(repo, &env, false).await;
        let deadline = env.now() + Duration::days(1);
        let approved = Redactor::new().verify_canonical(CANARY).unwrap();
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
        store.commit_fenced(commit).await.unwrap();
        // A restart keeps no outbox, serializer or cursor state: every repository and artifact
        // object below is a new value over the same database.
        drop(artifacts);
        let observer = Fresh::fresh(repo);
        let reopened = artifact_store(&observer, &env, false).await;
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
        exec(
            rig,
            "UPDATE dataset_delivery_outbox SET lease_expires_at = {past} WHERE delivery_id = $1",
            &[Bind::I64(first.id)],
        )
        .await;
        let next = store
            .claim(run.id, WorkerId::new(), 1, 60)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(next.id, first.id);
        assert_eq!(next.batch, first.batch);
        assert!(next.fence > first.fence);
        assert!(matches!(
            store.acknowledge(run.id, next.id, first.fence).await,
            Err(StoreError::LeaseLost)
        ));
        store.acknowledge(run.id, next.id, next.fence).await.unwrap();
        assert_eq!(observer.items(run.id, "items", 0, 10).await.unwrap().len(), 1);
        assert_eq!(
            reopened.get(&reference).await.unwrap(),
            CANARY,
            "durable acknowledgement must not erase accepted item storage"
        );
    }
    .await);
}

// ---------------------------------------------------------------------------------------
// Scale: committed items page exactly, repeatably and across a restart.
// ---------------------------------------------------------------------------------------

async fn source_content<R: Repo>(
    repo: &R,
    artifacts: &dyn ArtifactStore,
    owner: &CrawlRun,
    worker: WorkerId,
) -> DatasetContentV1 {
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
    let approved = Redactor::new().verify_canonical(CANARY).unwrap();
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

async fn seed_scale<R: Repo>(
    repo: &Arc<R>,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: Timestamp,
    total: u64,
) -> (CrawlRun, DatasetContentV1) {
    let repo = repo.as_ref();
    let mut owner = retained_run(tenant, now);
    owner.config.datasets.stores[0].max_items = total;
    owner.config.datasets.stores[0].max_bytes =
        total.checked_mul(u64::try_from(CANARY.len()).unwrap()).unwrap();
    owner.config_digest = owner.config.digest().unwrap();
    repo.create(&owner, None).await.unwrap();
    let worker = worker(repo).await;
    // One authorized blob backs all items; no engine creates one physical artifact per item.
    let content = source_content(repo, artifacts, &owner, worker).await;
    let batch_count = total.div_ceil(UNIQUE_BATCH);
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
        Digest::of("dataset/scale", total.to_string().as_bytes()),
        requests,
    ))
    .await
    .unwrap();
    let mut ordinal = 1;
    while ordinal <= total {
        // Lease only the request being committed; slow databases cannot expire future batches.
        let (request, fence) = repo
            .lease_batch_fenced(owner.id, worker, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let end = ordinal.saturating_add(UNIQUE_BATCH - 1).min(total);
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

async fn keyset_resumes_exactly_over_many_committed_items(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    let total = ITEM_CEILING;
    on_env!(rig, env, |repo| async {
        let artifacts = artifact_store(repo, &env, false).await;
        let (owner, content) = seed_scale(repo, &artifacts, tenant, env.now(), total).await;
        let after = exact_page_range(repo.as_ref(), &owner, &content, 0, total / 2, 137).await;
        // No producer repository, artifact index or in-process cursor survives a restart.
        drop(artifacts);
        let reopened = Fresh::fresh(repo);
        let artifacts = artifact_store(&reopened, &env, false).await;
        assert_eq!(
            exact_page_range(reopened.as_ref(), &owner, &content, after, total, 137).await,
            total
        );
        for limit in [137, 1000] {
            assert_eq!(
                exact_page_range(reopened.as_ref(), &owner, &content, 0, total, limit).await,
                total
            );
            assert!(reopened
                .items(owner.id, "items", total, limit)
                .await
                .unwrap()
                .is_empty());
        }
        assert!(reopened.items(owner.id, "items", 0, 0).await.is_err());
        assert!(reopened.items(owner.id, "items", 0, 1001).await.is_err());
        if rig.engine() != Engine::Memory {
            let artifact_rows = scalar(
                rig,
                "SELECT count(*) FROM artifacts WHERE run_id = $1",
                &[Bind::Uuid(owner.id.0)],
            )
            .await;
            assert_eq!(artifact_rows, 1, "one authorized blob backs every item");
        }
        assert_eq!(artifacts.get(content.artifact()).await.unwrap(), CANARY);
    }
    .await);
}

// ---------------------------------------------------------------------------------------
// KV: MIME syntax, quotas, tombstones, continuation across expired keys.
// ---------------------------------------------------------------------------------------

fn kv_change(content: &DatasetContentV1, store: &str, key: &str, expires: Timestamp) -> KvCasV1 {
    let mut change = delta(content, store, 0);
    change.key = key.into();
    change.expires_at = Some(expires);
    change
}

async fn kv_contract<R: Repo>(
    repo: &Arc<R>,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: Timestamp,
) -> CrawlRun {
    let repo = repo.as_ref();
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

async fn kv_metadata_continuation_exact_expiry_mime_and_quotas(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| {
        async {
        let artifacts = artifact_store(repo, &env, false).await;
        let owner = kv_contract(repo, &artifacts, tenant, env.now()).await;
        if rig.engine() == Engine::Memory {
            env.clock.advance_ms(43_199_999);
            assert_eq!(
                repo.keys(owner.id, "state", "b", 1).await.unwrap()[0].value.key,
                "c"
            );
            env.clock.advance_ms(1);
        } else {
            // Advance the database boundary explicitly, without sleeping or touching the host clock.
            exec(
                rig,
                "UPDATE dataset_kv SET expires_at = {now} WHERE run_id = $1 AND store = 'state' AND {key} IN ('a', 'b', 'c')",
                &[Bind::Uuid(owner.id.0)],
            )
            .await;
        }
        let reopened = Fresh::fresh(repo);
        expired_continuation(reopened.as_ref(), &owner).await;
    }
    .await
    });
}

// ---------------------------------------------------------------------------------------
// Terminal feed finalization.
// ---------------------------------------------------------------------------------------

fn feed_config(policy: &str) -> crawlx_core::dataset::DatasetConfigV1 {
    serde_json::from_value(serde_json::json!({
        "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":4096}],
        "feeds":[{"id":"feed","source":"items","serializer":"json","serializerVersion":1,"destination":"fixture",
            "maxBatchItems":2,"maxBatchBytes":4096,"emptyPolicy":policy}]
    }))
    .unwrap()
}

async fn terminal_empty_source_commits_with_status_and_rolls_back_invalid_feed(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let mut config = create_crawl("https://fixture.test/", &[], 1);
        config.retention.mode = RetentionMode::Standard;
        config.retention.days = 1;
        config.datasets = feed_config("emit");
        config.datasets.feeds[0].id = "empty".into();
        let run = crawl_run(tenant, config);
        store.create(&run, None).await.unwrap();
        let artifacts = artifact_store(repo, &env, false).await;
        let approved = Redactor::new().verify_canonical(b"[]\n").unwrap();
        let reference = ArtifactSink::over(&artifacts)
            .put_dataset(run.id, -100, "empty", "application/json", &approved)
            .await
            .unwrap();
        let content = artifacts
            .dataset_content(run.id, -100, &reference, 3)
            .await
            .unwrap();
        // The artifact expires one day after the case clock (an exact instant); a database
        // keeps microseconds. A deadline of whole milliseconds never exceeds the stored expiry.
        let deadline = chrono::DateTime::from_timestamp_millis(env.now().timestamp_millis()).unwrap()
            + Duration::days(1);
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
        assert!(store
            .finalize_run_feeds(
                run.id,
                RunStatus::Completed,
                TerminalReason::FrontierExhausted,
                &[batch.clone(), invalid]
            )
            .await
            .is_err());
        assert!(!store.get(run.id).await.unwrap().status.is_terminal());
        if rig.engine() != Engine::Memory {
            let rows = scalar(
                rig,
                "SELECT count(*) FROM dataset_delivery_outbox WHERE run_id = $1",
                &[Bind::Uuid(run.id.0)],
            )
            .await;
            assert_eq!(
                rows, 0,
                "an invalid feed must roll back the whole terminal transaction"
            );
        }
        store
            .finalize_run_feeds(
                run.id,
                RunStatus::Completed,
                TerminalReason::FrontierExhausted,
                &[batch.clone()],
            )
            .await
            .unwrap();
        assert_eq!(store.get(run.id).await.unwrap().status, RunStatus::Completed);
        if rig.engine() != Engine::Memory {
            let run_id = [Bind::Uuid(run.id.0)];
            assert_eq!(
                scalar(
                    rig,
                    "SELECT count(*) FROM dataset_delivery_outbox WHERE run_id = $1 AND terminal_source \
                     AND source_request_id IS NULL AND source_action_id IS NULL",
                    &run_id,
                )
                .await,
                1,
                "a terminal empty feed is a terminal source: no request, no action"
            );
        }
        store
            .finalize_run_feeds(
                run.id,
                RunStatus::Completed,
                TerminalReason::FrontierExhausted,
                &[],
            )
            .await
            .unwrap();
        let worker = WorkerId::new();
        store.register_worker(worker, "feed-fixture", "1").await.unwrap();
        let claims = store.claim(run.id, worker, 10, 60).await.unwrap();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].batch, batch);
        assert!(crawlx_storage::tenant::scope(
            TenantId::new(),
            store.finalize_run_feeds(
                run.id,
                RunStatus::Completed,
                TerminalReason::FrontierExhausted,
                &[]
            )
        )
        .await
        .is_err());
    }
    .await);
}

async fn seal_without_outbox_recovers_and_keeps_terminal_run_metadata(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let mut config = create_crawl("https://fixture.test/", &[], 1);
        config.datasets = feed_config("emit");
        let sealed = crawl_run(tenant, config.clone());
        let cancelled = crawl_run(tenant, config);
        store.create(&sealed, None).await.unwrap();
        store.create(&cancelled, None).await.unwrap();
        assert_eq!(
            store
                .begin_feed_finalization(sealed.id, Some(TerminalReason::FatalError))
                .await
                .unwrap(),
            Some(TerminalReason::FatalError)
        );
        store
            .set_status(
                cancelled.id,
                RunStatus::Cancelled,
                Some(TerminalReason::Cancelled),
            )
            .await
            .unwrap();
        let pending = store.ready_runs(None, 10).await.unwrap();
        assert!(pending.contains(&sealed.id));
        assert!(pending.contains(&cancelled.id));
        assert_eq!(
            store.begin_feed_finalization(sealed.id, None).await.unwrap(),
            Some(TerminalReason::FatalError)
        );
        assert_eq!(
            store.begin_feed_finalization(cancelled.id, None).await.unwrap(),
            Some(TerminalReason::Cancelled)
        );
        if rig.engine() != Engine::Memory {
            assert_eq!(
                scalar(rig, "SELECT count(*) FROM dataset_delivery_outbox", &[]).await,
                0
            );
        }
        assert!(store
            .finalize_run_feeds(sealed.id, RunStatus::Failed, TerminalReason::FatalError, &[])
            .await
            .is_err());
        assert!(!store.get(sealed.id).await.unwrap().status.is_terminal());
    }
    .await);
}

async fn missing_volatile_config_retires_pending_feeds_without_reading_source(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| {
        async {
        let store = repo.as_ref();
        let mut config = create_crawl("https://fixture.test/", &[], 1);
        config.retention.mode = RetentionMode::Zdr;
        config.retention.days = 0;
        config.datasets = feed_config("emit");
        config.datasets.feeds[0].id = "feed".into();
        let run = crawl_run(tenant, config);
        store.create(&run, None).await.unwrap();
        store
            .begin_feed_finalization(run.id, Some(TerminalReason::FatalError))
            .await
            .unwrap();
        env.buffer.ack(tenant, run.id, i64::MIN).await.unwrap();
        assert!(
            matches!(store.maintain(run.id).await, Err(StoreError::RetentionDenied(message)) if message == "feed content_expired")
        );
        assert!(!store.ready_runs(None, 10).await.unwrap().contains(&run.id));
        assert_eq!(store.begin_feed_finalization(run.id, None).await.unwrap(), None);
        assert_eq!(store.get_metadata(run.id).await.unwrap().status, RunStatus::Failed);
        if rig.engine() != Engine::Memory {
            let run_id = [Bind::Uuid(run.id.0)];
            let outcome =
                scalar_text(rig, "SELECT feed_finalization_outcome FROM crawl_runs WHERE run_id = $1", &run_id).await;
            let outcome: crawlx_core::dataset::FeedFinalizationOutcomeV1 =
                serde_json::from_value(serde_json::json!(outcome)).unwrap();
            assert_eq!(outcome, crawlx_core::dataset::FeedFinalizationOutcomeV1::ContentExpired);
            assert_eq!(
                scalar(rig, "SELECT count(*) FROM dataset_delivery_outbox WHERE run_id = $1", &run_id).await,
                0
            );
        }
    }
    .await
    });
}

async fn staged_manifest_contract<R: Repo>(
    repo: &Arc<R>,
    artifacts: &dyn ArtifactStore,
    tenant: TenantId,
    now: Timestamp,
) -> (CrawlRun, DeliveryBatchV1) {
    let repo = repo.as_ref();
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
    let worker = worker(repo).await;
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("feed/fixture", b"one"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://fixture.test/one"),
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
    item.expires_at = Some(now + Duration::days(1));
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
        now + Duration::days(1),
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

async fn staged_feed_lookup_preserves_identity_and_denies_revoked_or_expired_content(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| async {
        let artifacts = artifact_store(repo, &env, false).await;
        let (run, batch) = staged_manifest_contract(repo, &artifacts, tenant, env.now()).await;
        if rig.engine() != Engine::Memory {
            // a feed whose accepted items vanished is a conflict, not a missing source
            exec(
                rig,
                "DELETE FROM dataset_items WHERE run_id = $1",
                &[Bind::Uuid(run.id.0)],
            )
            .await;
            assert!(matches!(
                repo.staged_feed_batch(run.id, "feed", &batch.idempotency_key)
                    .await,
                Err(StoreError::Conflict(_))
            ));
        }
        repo.mark_deleted(&[batch.content.artifact().id]).await.unwrap();
        assert!(matches!(
            repo.staged_feed_batch(run.id, "feed", &batch.idempotency_key)
                .await,
            Err(StoreError::RetentionDenied(_))
        ));
        let expired_tenant = tenant_of(rig).await;
        let (expired_run, expired_batch) =
            staged_manifest_contract(repo, &artifacts, expired_tenant, env.now()).await;
        if rig.engine() == Engine::Memory {
            env.clock.advance_ms(86_400_001);
        } else {
            exec(
                rig,
                "UPDATE dataset_delivery_outbox SET expires_at = {past} WHERE run_id = $1",
                &[Bind::Uuid(expired_run.id.0)],
            )
            .await;
        }
        assert!(matches!(
            repo.staged_feed_batch(expired_run.id, "feed", &expired_batch.idempotency_key)
                .await,
            Err(StoreError::RetentionDenied(_))
        ));
    }
    .await);
}

// ---------------------------------------------------------------------------------------
// Source memo.
// ---------------------------------------------------------------------------------------

/// The instant the source-memo cases start at: the real clock at first use (whole milliseconds).
/// The stores compare artifact and category deadlines with the database `now()`, so a fixture
/// instant fixed in the past (or future) makes every deadline already expired (or never due);
/// fixture instants must be relative to the same clock the engine reads.
fn instant() -> Timestamp {
    static START: std::sync::LazyLock<Timestamp> = std::sync::LazyLock::new(|| {
        chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).unwrap()
    });
    *START
}

fn digest(value: &[u8]) -> Digest {
    Digest::of("source-memo-test/v1", value)
}

fn memo_run(tenant: TenantId, now: Timestamp, zdr: bool) -> CrawlRun {
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
        DatasetContentV1::Durable { artifact } => {
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

async fn source_memo_scopes_capacity_and_reset(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let now = instant();
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let a = memo_run(tenant_of(rig).await, now, false);
        let b = memo_run(tenant_of(rig).await, now, false);
        store.create(&a, None).await.unwrap();
        store.create(&b, None).await.unwrap();
        seen_contract(store, &a, &b, now).await;
        let artifacts = artifact_store(repo, &env, false).await;
        let entry = cache_entry(&artifacts, &a, now + Duration::hours(24)).await;
        assert!(entry.expires_at <= now + Duration::hours(24));
        cache_contract(store, &a, &b, entry.clone(), now).await;
        store
            .cache_category(&memo_scope(&a), digest(b"frozen"), entry.clone(), now)
            .await
            .unwrap();
        // the worker clock is the caller's `now`: expiry is exact to the tick
        let last = entry.expires_at - Duration::milliseconds(1);
        assert!(store
            .category(&memo_scope(&a), digest(b"frozen"), last)
            .await
            .unwrap()
            .is_some());
        assert!(store
            .category(&memo_scope(&a), digest(b"frozen"), entry.expires_at)
            .await
            .unwrap()
            .is_none());
    }
    .await);
}

async fn source_memo_zdr_creates_no_files_and_refuses_durable_content(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let now = instant();
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let a = memo_run(tenant_of(rig).await, now, true);
        let b = memo_run(tenant_of(rig).await, now, true);
        store.create(&a, None).await.unwrap();
        store.create(&b, None).await.unwrap();
        seen_contract(store, &a, &b, now).await;
        let artifacts = artifact_store(repo, &env, true).await;
        let entry = cache_entry(&artifacts, &a, now + Duration::minutes(10)).await;
        let mut durable = entry.clone();
        durable.content = DatasetContentV1::Durable {
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
        cache_contract(store, &a, &b, entry, now).await;
        assert_eq!(env.files(), 0);
    }
    .await);
}

async fn source_memo_category_count_stays_bounded_across_scopes(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let now = instant();
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let run = memo_run(tenant_of(rig).await, now, false);
        store.create(&run, None).await.unwrap();
        let artifacts = artifact_store(repo, &env, false).await;
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
        assert_eq!(retained, MAX_CATEGORY_CACHE_ENTRIES);
    }
    .await);
}

async fn source_memo_restart_retains_scopes_and_zdr_never_writes_durable_metadata(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    // sub-microsecond digits: the committed precision must bound a requested expiry
    let now = chrono::DateTime::from_timestamp(Utc::now().timestamp(), 123_456_789).unwrap();
    on_env!(rig, env, |repo| {
        async {
        let store = repo.as_ref();
        let a = memo_run(tenant_of(rig).await, now, false);
        let b = memo_run(tenant_of(rig).await, now, false);
        store.create(&a, None).await.unwrap();
        store.create(&b, None).await.unwrap();
        seen_contract(store, &a, &b, now).await;
        let artifacts = artifact_store(repo, &env, false).await;
        let entry = cache_entry(&artifacts, &a, now + Duration::hours(24)).await;
        assert!(entry.expires_at <= now + Duration::hours(24));
        assert_eq!(entry.expires_at.timestamp_subsec_nanos() % 1000, 0);
        assert_ne!(
            entry.expires_at,
            now + Duration::hours(24),
            "committed precision must bound the requested expiry"
        );
        cache_contract(store, &a, &b, entry.clone(), now).await;
        store
            .record_seen(&memo_scope(&a), &[digest(b"persisted")], 20_000, now)
            .await
            .unwrap();
        store
            .cache_category(&memo_scope(&a), digest(b"persisted"), entry, now)
            .await
            .unwrap();
        let restarted = Fresh::fresh(repo);
        assert!(restarted
            .seen(&memo_scope(&a), digest(b"persisted"), now)
            .await
            .unwrap());
        assert!(restarted
            .category(&memo_scope(&a), digest(b"persisted"), now)
            .await
            .unwrap()
            .is_some());
        let zdr = memo_run(a.tenant, now, true);
        store.create(&zdr, None).await.unwrap();
        store
            .record_seen(&memo_scope(&zdr), &[digest(b"private")], 20_000, now)
            .await
            .unwrap();
        assert!(restarted
            .seen(&memo_scope(&zdr), digest(b"private"), now)
            .await
            .unwrap());
        let zdr_env = Env::new();
        let zdr_artifacts = FsArtifactStore::open(zdr_env.dir.path(), repo.clone(), env.clock.clone())
            .await
            .unwrap()
            .with_index(repo.clone())
            .with_zdr_buffer(env.buffer.clone());
        let entry = cache_entry(&zdr_artifacts, &zdr, now + Duration::minutes(10)).await;
        store
            .cache_category(&memo_scope(&zdr), digest(b"private representation"), entry, now)
            .await
            .unwrap();
        let zdr_id = [Bind::Uuid(zdr.id.0)];
        let durable = scalar(
            rig,
            "SELECT (SELECT count(*) FROM source_memo_seen WHERE run_id = $1) \
             + (SELECT count(*) FROM source_category_cache WHERE run_id = $2)",
            &[zdr_id[0], zdr_id[0]],
        )
        .await;
        assert_eq!(
            durable, 0,
            "ZDR hashes and category references must not enter durable tables"
        );
        let stale_page = env.buffer.get(zdr.tenant, zdr.id, i64::MIN + 50).await.unwrap().unwrap();
        let stale_bytes = &stale_page.blobs["source_memo_v1.0"].bytes;
        restarted.reset(zdr.tenant, zdr.id).await.unwrap();
        // Model a cancelled remote write completing after the database reset releases its lock.
        env.buffer
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
        assert!(!store.seen(&memo_scope(&zdr), digest(b"private"), now).await.unwrap());
        assert!(store
            .category(&memo_scope(&zdr), digest(b"private representation"), now)
            .await
            .unwrap()
            .is_none());
        assert_eq!(zdr_env.files(), 0);
        let denied = try_exec(
            rig,
            "INSERT INTO source_memo_seen (tenant_id, run_id, lookup_key, recorded_at) VALUES ($1, $2, $3, {now})",
            &[
                Bind::Uuid(zdr.tenant.0),
                zdr_id[0],
                Bind::Text(&digest(b"private").to_hex()),
            ],
        )
        .await;
        assert!(
            denied.is_err(),
            "database guard must reject direct durable ZDR memo writes"
        );
    }
    .await
    });
}

// ---------------------------------------------------------------------------------------
// Explicit outbox, expiry and KV contracts on the smallest fixtures: a zero-retention run with
// volatile content parked straight in the delivery buffer.
// ---------------------------------------------------------------------------------------

/// A zero-retention run whose three feeds each emit an empty terminal batch.
fn outbox_run(tenant: TenantId, now: Timestamp) -> CrawlRun {
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    config.datasets = serde_json::from_value(serde_json::json!({
        "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":4096}],
        "feeds":[
            {"id":"alpha","source":"items","serializer":"json","serializerVersion":1,"destination":"fixture",
             "maxBatchItems":2,"maxBatchBytes":4096,"emptyPolicy":"emit"},
            {"id":"beta","source":"items","serializer":"json","serializerVersion":1,"destination":"fixture",
             "maxBatchItems":2,"maxBatchBytes":4096,"emptyPolicy":"emit"},
            {"id":"gamma","source":"items","serializer":"json","serializerVersion":1,"destination":"fixture",
             "maxBatchItems":2,"maxBatchBytes":4096,"emptyPolicy":"emit"}]
    }))
    .unwrap();
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    run
}

/// Finalize `run` with one empty terminal batch per feed, in `order`; the outbox ids follow it.
async fn seal_with_empty_feeds<R: Repo>(repo: &R, env: &Env, run: &CrawlRun, order: &[&str]) {
    repo.create(run, None).await.unwrap();
    let mut batches = Vec::new();
    for (position, feed) in order.iter().enumerate() {
        let page = -100 - i64::try_from(position).unwrap();
        let content = volatile_content(env, run, page, b"[]\n").await;
        let expires_at = content.expires_at().unwrap();
        let mut batch = DeliveryBatchV1::for_request(
            (*feed).into(),
            format!("terminal.empty.{feed}"),
            content,
            3,
            expires_at,
        );
        batch.range = DeliveryRangeV1::Empty;
        batches.push(batch);
    }
    repo.finalize_run_feeds(
        run.id,
        RunStatus::Completed,
        TerminalReason::FrontierExhausted,
        &batches,
    )
    .await
    .unwrap();
}

async fn outbox_claims_in_id_order_and_bounds_leases_acks_and_retries(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let run = outbox_run(tenant, env.now());
        // not alphabetical: the ids follow the order the batches were staged in
        seal_with_empty_feeds(store, &env, &run, &["gamma", "alpha", "beta"]).await;
        let worker = WorkerId::new();
        let rival = WorkerId::new();
        // bounds of the claim itself
        assert!(store.claim(run.id, worker, 0, 60).await.is_err());
        assert!(store.claim(run.id, worker, 1001, 60).await.is_err());
        assert!(store.claim(run.id, worker, 1, 0).await.is_err());
        assert!(store.claim(run.id, worker, 1, 301).await.is_err());
        let claimed = store.claim(run.id, worker, 10, 60).await.unwrap();
        assert_eq!(
            claimed
                .iter()
                .map(|claim| claim.batch.feed.as_str())
                .collect::<Vec<_>>(),
            ["gamma", "alpha", "beta"],
            "deliveries come back in staging (ascending id) order"
        );
        assert!(claimed.windows(2).all(|pair| pair[0].id < pair[1].id));
        assert!(claimed
            .iter()
            .all(|claim| claim.attempts == 1 && claim.fence >= 1));
        assert!(
            store.claim(run.id, rival, 10, 60).await.unwrap().is_empty(),
            "a live lease keeps a second claimer out"
        );
        assert!(!store.ready_runs(None, 10).await.unwrap().contains(&run.id));
        // fences guard the receipt
        let first = &claimed[0];
        assert!(matches!(
            store.acknowledge(run.id, first.id, first.fence + 1).await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(
            store.acknowledge(run.id, first.id + 1000, first.fence).await,
            Err(StoreError::LeaseLost)
        ));
        // retry bounds: not in the past, not beyond a day, not beyond the delivery's own deadline
        let second = &claimed[1];
        assert!(matches!(
            store
                .retry(run.id, second.id, second.fence, env.now() - Duration::minutes(5))
                .await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(
            store
                .retry(run.id, second.id, second.fence, Utc::now() + Duration::days(2))
                .await,
            Err(StoreError::LeaseLost)
        ));
        assert!(matches!(
            store
                .retry(
                    run.id,
                    second.id,
                    second.fence + 1,
                    env.now() + Duration::seconds(90)
                )
                .await,
            Err(StoreError::LeaseLost)
        ));
        store
            .retry(run.id, second.id, second.fence, env.now() + Duration::seconds(90))
            .await
            .unwrap();
        assert!(
            matches!(
                store
                    .retry(run.id, second.id, second.fence, env.now() + Duration::seconds(90))
                    .await,
                Err(StoreError::LeaseLost)
            ),
            "a delivery that is no longer leased cannot be retried again"
        );
        store.acknowledge(run.id, first.id, first.fence).await.unwrap();
        store.acknowledge(run.id, first.id, first.fence).await.unwrap();
        // the lease of the third delivery runs out; the next claim fences the old holder
        let third = claimed[2].clone();
        if rig.engine() == Engine::Memory {
            env.clock.advance_ms(61_000);
        } else {
            exec(
                rig,
                "UPDATE dataset_delivery_outbox SET lease_expires_at = {past} WHERE delivery_id = $1",
                &[Bind::I64(third.id)],
            )
            .await;
        }
        let reclaimed = store.claim(run.id, rival, 10, 60).await.unwrap();
        assert_eq!(
            reclaimed.len(),
            1,
            "only the expired lease and no pending retry is claimable"
        );
        assert_eq!(reclaimed[0].id, third.id);
        assert_eq!(
            reclaimed[0].fence,
            third.fence + 1,
            "the fence increments on every claim"
        );
        assert_eq!(reclaimed[0].attempts, third.attempts + 1);
        assert!(matches!(
            store.acknowledge(run.id, third.id, third.fence).await,
            Err(StoreError::LeaseLost)
        ));
        store
            .acknowledge(run.id, reclaimed[0].id, reclaimed[0].fence)
            .await
            .unwrap();
    }
    .await);
}

async fn outbox_expiry_retires_expired_rows(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| {
        async {
        let store = repo.as_ref();
        let run = outbox_run(tenant, env.now());
        seal_with_empty_feeds(store, &env, &run, &["alpha", "beta", "gamma"]).await;
        let worker = WorkerId::new();
        let claimed = store.claim(run.id, worker, 2, 60).await.unwrap();
        assert_eq!(claimed.len(), 2);
        let (leased, pending_id) = (&claimed[0], {
            // the third delivery stays pending: it is the one `expire` must refuse to touch early
            let rest = store.claim(run.id, WorkerId::new(), 10, 60).await.unwrap();
            assert_eq!(rest.len(), 1);
            rest[0].id
        });
        // nothing has expired yet: neither the explicit expiry nor the sweep retires a live row
        assert!(matches!(
            store.expire(run.id, leased.id, leased.fence).await,
            Err(StoreError::LeaseLost)
        ));
        store.maintain(run.id).await.unwrap();
        // time passes beyond every delivery deadline
        if rig.engine() == Engine::Memory {
            env.clock.advance_ms(7_200_000);
        } else {
            exec(
                rig,
                "UPDATE dataset_delivery_outbox SET expires_at = {past} WHERE run_id = $1",
                &[Bind::Uuid(run.id.0)],
            )
            .await;
        }
        assert!(matches!(
            store.expire(run.id, leased.id, leased.fence + 1).await,
            Err(StoreError::LeaseLost)
        ));
        store.expire(run.id, leased.id, leased.fence).await.unwrap();
        // the sweep retires what is left
        store.maintain(run.id).await.unwrap();
        assert!(store.claim(run.id, WorkerId::new(), 10, 60).await.unwrap().is_empty());
        for claim in &claimed {
            assert!(matches!(
                store.acknowledge(run.id, claim.id, claim.fence).await,
                Err(StoreError::LeaseLost)
            ));
        }
        assert!(matches!(
            store.acknowledge(run.id, pending_id, 1).await,
            Err(StoreError::LeaseLost)
        ));
        if rig.engine() != Engine::Memory {
            let run_id = [Bind::Uuid(run.id.0)];
            assert_eq!(
                scalar(
                    rig,
                    "SELECT count(*) FROM dataset_delivery_outbox WHERE run_id = $1 AND state = 'content_expired'",
                    &run_id,
                )
                .await,
                3,
                "every expired delivery is retired"
            );
            assert_eq!(
                scalar(
                    rig,
                    "SELECT count(*) FROM dataset_delivery_outbox WHERE run_id = $1 AND lease_owner IS NOT NULL",
                    &run_id,
                )
                .await,
                0,
                "a retired delivery holds no lease"
            );
        }
        assert!(!store.ready_runs(None, 10).await.unwrap().contains(&run.id));
    }
    .await
    });
}

async fn kv_compare_and_set_collision_quota_and_drop_store(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let mut run = zdr_run(tenant, env.now());
        run.config.datasets = serde_json::from_value(serde_json::json!({
            "version": 1,
            "kvStores": [
                {"name":"state","maxKeys":2,"maxValueBytes":1048576,"maxBytes":1048576},
                {"name":"small","maxKeys":20,"maxValueBytes":1048576,"maxBytes":100},
                {"name":"drop","maxKeys":20,"maxValueBytes":1048576,"maxBytes":1048576}
            ]
        }))
        .unwrap();
        run.config_digest = run.config.digest().unwrap();
        store.create(&run, None).await.unwrap();
        let size = u64::try_from(CANARY.len()).unwrap();
        let content = volatile_content(&env, &run, -200, CANARY).await;
        let change = |store: &str, key: &str, expected: u64| {
            let mut change = delta(&content, store, expected);
            change.key = key.into();
            change
        };
        // compare-and-set: version zero creates, the next version needs the current one
        let created = store
            .compare_and_set(run.id, change("state", "a", 0))
            .await
            .unwrap();
        assert_eq!(created.version, 1);
        assert!(matches!(
            store.compare_and_set(run.id, change("state", "a", 0)).await,
            Err(StoreError::Conflict(_))
        ));
        assert!(matches!(
            store.compare_and_set(run.id, change("state", "a", 5)).await,
            Err(StoreError::Conflict(_))
        ));
        // two writers race for version 1: exactly one wins
        let (left, right) = tokio::join!(
            store.compare_and_set(run.id, change("state", "a", 1)),
            store.compare_and_set(run.id, change("state", "a", 1)),
        );
        assert_ne!(left.is_ok(), right.is_ok(), "{left:?} / {right:?}");
        assert!(matches!(
            left.as_ref().err().or(right.as_ref().err()),
            Some(StoreError::Conflict(_))
        ));
        assert_eq!(
            store.value(run.id, "state", "a").await.unwrap().unwrap().version,
            2
        );
        // key quota: two keys fit, the third does not, and the failure charges nothing
        store
            .compare_and_set(run.id, change("state", "b", 0))
            .await
            .unwrap();
        assert!(matches!(
            store.compare_and_set(run.id, change("state", "c", 0)).await,
            Err(StoreError::Conflict(_))
        ));
        assert!(store.value(run.id, "state", "c").await.unwrap().is_none());
        assert_eq!(store.keys(run.id, "state", "", 10).await.unwrap().len(), 2);
        // byte quota: the namespace holds two values of this size, not three
        assert!(size > 33 && size <= 50, "fixture sizes the byte quota: {size}");
        store
            .compare_and_set(run.id, change("small", "a", 0))
            .await
            .unwrap();
        store
            .compare_and_set(run.id, change("small", "b", 0))
            .await
            .unwrap();
        assert!(matches!(
            store.compare_and_set(run.id, change("small", "c", 0)).await,
            Err(StoreError::Conflict(_))
        ));
        // undeclared namespace
        assert!(matches!(
            store.compare_and_set(run.id, change("nowhere", "a", 0)).await,
            Err(StoreError::Conflict(_))
        ));
        // every zero-retention write owns a volatile page of its own
        if rig.engine() != Engine::Memory {
            let run_id = [Bind::Uuid(run.id.0)];
            let rows = scalar(rig, "SELECT count(*) FROM dataset_kv WHERE run_id = $1", &run_id).await;
            let pages = scalar(
                rig,
                "SELECT count(DISTINCT volatile_page) FROM dataset_kv WHERE run_id = $1",
                &run_id,
            )
            .await;
            assert_eq!(rows, 4);
            assert_eq!(pages, rows, "volatile pages never repeat across writes");
            assert_eq!(
                scalar(
                    rig,
                    "SELECT count(*) FROM dataset_kv WHERE run_id = $1 AND payload IS NOT NULL",
                    &run_id,
                )
                .await,
                0
            );
        }
        // drop: idempotent, hides the namespace and never lets version zero come back
        store
            .compare_and_set(run.id, change("drop", "x", 0))
            .await
            .unwrap();
        store.drop_store(run.id, "drop").await.unwrap();
        store.drop_store(run.id, "drop").await.unwrap();
        assert!(store.keys(run.id, "drop", "", 10).await.is_err());
        assert!(store.value(run.id, "drop", "x").await.is_err());
        assert!(store
            .compare_and_set(run.id, change("drop", "x", 0))
            .await
            .is_err());
        assert!(store.drop_store(run.id, "nowhere").await.is_err());
        assert_eq!(
            store.keys(run.id, "state", "", 10).await.unwrap().len(),
            2,
            "dropping one namespace leaves the others"
        );
    }
    .await);
}

async fn recovery_keysets_reach_runs_beyond_the_first_page(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    on_env!(rig, env, |repo| async {
        let artifacts = artifact_store(repo, &env, true).await;
        for _ in 0..17 {
            let tenant = tenant_of(rig).await;
            transactional_contract(repo, &artifacts, tenant, env.now()).await;
        }
        if rig.engine() == Engine::Memory {
            env.clock.advance_ms(11_000);
        } else {
            // every retried delivery is due again
            exec(
                rig,
                "UPDATE dataset_delivery_outbox SET not_before = {now} WHERE state = 'pending'",
                &[],
            )
            .await;
        }
        let store = repo.as_ref();
        let first = store.ready_runs(None, 16).await.unwrap();
        assert_eq!(first.len(), 16);
        let last = store.ready_runs(first.last().copied(), 16).await.unwrap();
        assert_eq!(last.len(), 1);
        assert!(!first.contains(&last[0]));
        assert!(store
            .ready_runs(last.last().copied(), 16)
            .await
            .unwrap()
            .is_empty());
    }
    .await);
}

// ---------------------------------------------------------------------------------------
// Terminal feed finalization as a fenced custody producer.
// ---------------------------------------------------------------------------------------

/// Move past the end of every finalizer lease the case took (60 s each).
async fn expire_finalizer(rig: &Rig, env: &Env, run: crawlx_core::CrawlRunId) {
    if rig.engine() == Engine::Memory {
        env.clock.advance_ms(61_000);
    } else {
        let rows = exec(
            rig,
            "UPDATE crawl_runs SET feed_finalizer_expires_at={past} WHERE run_id=$1",
            &[Bind::Uuid(run.0)],
        )
        .await;
        assert_eq!(rows, 1);
    }
}

async fn feed_finalizer_claim_is_exclusive_fenced_expiring_and_ends_with_finalization(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    let tenant = tenant_of(rig).await;
    let ttl = std::time::Duration::from_secs(60);
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let run = crawl_run(tenant, create_crawl("https://fixture.test/", &[], 1));
        store.create(&run, None).await.unwrap();
        store.set_status(run.id, RunStatus::Running, None).await.unwrap();
        let (first_worker, second_worker) = (WorkerId::new(), WorkerId::new());
        // Nothing to finalize yet: no claim exists to hold.
        let early = store.claim_feed_finalizer(run.id, first_worker, ttl).await;
        assert!(matches!(early, Err(StoreError::LeaseLost)), "{early:?}");
        store
            .begin_feed_finalization(run.id, Some(TerminalReason::FrontierExhausted))
            .await
            .unwrap();
        // Lease durations are bounded on both sides.
        for bad in [std::time::Duration::ZERO, std::time::Duration::from_secs(301)] {
            let refused = store.claim_feed_finalizer(run.id, first_worker, bad).await;
            assert!(matches!(refused, Err(StoreError::Conflict(_))), "{refused:?}");
        }

        let first = store
            .claim_feed_finalizer(run.id, first_worker, ttl)
            .await
            .unwrap();
        assert_eq!(
            (first.tenant, first.run, first.worker),
            (tenant, run.id, first_worker)
        );
        assert!(first.fence > 0);
        let CustodySource::FeedFinalization(first_id) = first.source else {
            panic!("unexpected producer source {:?}", first.source);
        };
        // One live claim excludes every other claimant, including its own owner.
        for claimant in [second_worker, first_worker] {
            let busy = store.claim_feed_finalizer(run.id, claimant, ttl).await;
            assert!(matches!(busy, Err(StoreError::Conflict(_))), "{busy:?}");
        }
        store.renew_feed_finalizer(&first, ttl).await.unwrap();
        // A forged fence, owner or claim id renews nothing.
        let mut forged = first.clone();
        forged.fence += 1;
        let refused = store.renew_feed_finalizer(&forged, ttl).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        let mut forged = first.clone();
        forged.worker = second_worker;
        let refused = store.renew_feed_finalizer(&forged, ttl).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        let mut forged = first.clone();
        forged.source = CustodySource::FeedFinalization(uuid::Uuid::now_v7());
        let refused = store.renew_feed_finalizer(&forged, ttl).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
        // A lease of another producer kind is no finalizer.
        let mut other = first.clone();
        other.source = CustodySource::Url(7);
        let refused = store.renew_feed_finalizer(&other, ttl).await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");

        // Release hands over at once; releasing twice is harmless; the old fence is dead and
        // the new one is higher.
        store.release_feed_finalizer(&first).await.unwrap();
        store.release_feed_finalizer(&first).await.unwrap();
        let renewed = store.renew_feed_finalizer(&first, ttl).await;
        assert!(matches!(renewed, Err(StoreError::LeaseLost)), "{renewed:?}");
        let second = store
            .claim_feed_finalizer(run.id, second_worker, ttl)
            .await
            .unwrap();
        assert!(second.fence > first.fence);
        assert_ne!(second.source, CustodySource::FeedFinalization(first_id));
        store.renew_feed_finalizer(&second, ttl).await.unwrap();
        // A stale holder cannot release its successor's claim.
        store.release_feed_finalizer(&first).await.unwrap();
        store.renew_feed_finalizer(&second, ttl).await.unwrap();

        // An expired claim renews nothing; takeover raises the fence again.
        expire_finalizer(rig, &env, run.id).await;
        let renewed = store.renew_feed_finalizer(&second, ttl).await;
        assert!(matches!(renewed, Err(StoreError::LeaseLost)), "{renewed:?}");
        let third = store
            .claim_feed_finalizer(run.id, first_worker, ttl)
            .await
            .unwrap();
        assert!(third.fence > second.fence);
        store.renew_feed_finalizer(&third, ttl).await.unwrap();

        // Completing the finalization ends the claim for good.
        store
            .finalize_run_feeds(
                run.id,
                RunStatus::Completed,
                TerminalReason::FrontierExhausted,
                &[],
            )
            .await
            .unwrap();
        let renewed = store.renew_feed_finalizer(&third, ttl).await;
        assert!(matches!(renewed, Err(StoreError::LeaseLost)), "{renewed:?}");
        let again = store.claim_feed_finalizer(run.id, second_worker, ttl).await;
        assert!(matches!(again, Err(StoreError::LeaseLost)), "{again:?}");
        // Another tenant's scope cannot claim, renew or release it; an unknown run is not found.
        let foreign = crawlx_storage::tenant::scope(
            TenantId::new(),
            store.claim_feed_finalizer(run.id, second_worker, ttl),
        )
        .await;
        assert!(matches!(foreign, Err(StoreError::AccessDenied(_))), "{foreign:?}");
        let foreign =
            crawlx_storage::tenant::scope(TenantId::new(), store.renew_feed_finalizer(&third, ttl)).await;
        assert!(matches!(foreign, Err(StoreError::AccessDenied(_))), "{foreign:?}");
        let foreign =
            crawlx_storage::tenant::scope(TenantId::new(), store.release_feed_finalizer(&third)).await;
        assert!(matches!(foreign, Err(StoreError::AccessDenied(_))), "{foreign:?}");
        let missing = store
            .claim_feed_finalizer(crawlx_core::CrawlRunId::new(), first_worker, ttl)
            .await;
        assert!(matches!(missing, Err(StoreError::NotFound { .. })), "{missing:?}");
    }
    .await);
}

async fn compressed_feed_runs_are_only_eligible_where_compressed_bytes_are_published(rig: &Rig) {
    ready(rig).await;
    let env = Env::new();
    on_env!(rig, env, |repo| async {
        let store = repo.as_ref();
        let worker = WorkerId::new();
        store.register_worker(worker, "eligibility", "1").await.unwrap();
        store
            .publish_acquisition_capabilities(worker, &[BackendCapabilitiesV1::native_http("fixture", "1")])
            .await
            .unwrap();
        let mut facts = WorkerDataCapabilitiesV1::default();
        facts.destinations.insert("loc".into(), false);
        facts.destinations.insert("queue".into(), false);
        facts.compressed_destinations.insert("loc".into());
        store.publish_data_capabilities(worker, &facts).await.unwrap();
        let requirements = |destinations: &[&str], compressed: &[&str]| {
            let mut required = WorkerDataRequirementsV1::default();
            for id in destinations {
                required.destinations.insert((*id).into(), false);
            }
            for id in compressed {
                required.compressed_destinations.insert((*id).into());
            }
            required
        };
        let eligible = |required: WorkerDataRequirementsV1| async move {
            store
                .eligible_data_worker(&[], &required, std::time::Duration::from_secs(60))
                .await
                .unwrap()
                .is_some()
        };
        assert!(eligible(requirements(&["loc"], &["loc"])).await);
        assert!(!eligible(requirements(&["queue"], &["queue"])).await);
        assert!(!eligible(requirements(&["loc", "queue"], &["loc", "queue"])).await);
        // Uncompressed feeds keep their meaning on the same worker.
        assert!(eligible(requirements(&["queue"], &[])).await);
        assert!(eligible(requirements(&["loc", "queue"], &["loc"])).await);
        // A worker that published no compressed support serves no compressed feed.
        let legacy = WorkerId::new();
        store.register_worker(legacy, "legacy", "1").await.unwrap();
        store
            .publish_acquisition_capabilities(legacy, &[BackendCapabilitiesV1::native_http("fixture", "1")])
            .await
            .unwrap();
        let mut old = WorkerDataCapabilitiesV1::default();
        old.destinations.insert("queue".into(), false);
        store.publish_data_capabilities(legacy, &old).await.unwrap();
        store
            .publish_data_capabilities(worker, &WorkerDataCapabilitiesV1::default())
            .await
            .unwrap();
        assert!(!eligible(requirements(&["queue"], &["queue"])).await);
        assert!(eligible(requirements(&["queue"], &[])).await);
    }
    .await);
}
