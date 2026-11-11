//! Persistent extension callback trails share the fenced request transaction on memory and
//! PostgreSQL. PostgreSQL cases require `CRAWLX_TEST_DATABASE_URL`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, Utc};
use crawlx_core::acquisition::BackendCapabilitiesV1;
use crawlx_core::custody::CustodyLease;
use crawlx_core::data_capabilities::WorkerDataCapabilitiesV1;
use crawlx_core::dataset::{AcceptedBatchV1, AcceptedItemV1, DatasetContentV1, DatasetRepo};
use crawlx_core::extensions::{
    ExtensionCallbackReceiptV1, ExtensionEventV1, ExtensionReasonV1, ExtensionReceiptV1, ExtensionResultV1,
    ExtensionTerminalV1,
};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{RequestBatchV1, RequestCommitRepo, RequestCommitV1};
use crawlx_core::repo::{
    ArtifactStore, CrawlRun, EventRepo, FrontierEntry, FrontierRepo, FrontierStatus, RunRepo,
};
use crawlx_core::report_history::{
    ReportDataV1, ReportFactV1, ReportHistoryRepo, ReportKindV1, ReportQueryV1,
};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::secret::{ArtifactSink, Redactor};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, CrawlRunId, StoreError, TenantId, WorkerId};
use crawlx_storage::artifacts::{ArtifactIndex, FsArtifactStore};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{MemoryStore, Pg, StoreConfig, WorkerRegistry};
use std::sync::Arc;

fn step(sequence: u64, event: ExtensionEventV1, result: ExtensionResultV1) -> ExtensionReceiptV1 {
    ExtensionReceiptV1::new(
        sequence,
        event,
        vec![ExtensionCallbackReceiptV1::new(
            0,
            Digest::of("wave3/extension-attempts", b"config"),
            result.clone(),
        )],
        result,
    )
}

fn completed_trail() -> Vec<ExtensionReceiptV1> {
    let go = || ExtensionResultV1::Continue;
    vec![
        step(1, ExtensionEventV1::Configure, go()),
        step(
            2,
            ExtensionEventV1::Terminal(ExtensionTerminalV1::Completed),
            go(),
        ),
        step(3, ExtensionEventV1::Checkpoint, go()),
        step(4, ExtensionEventV1::Close, go()),
    ]
}

fn failed_trail() -> Vec<ExtensionReceiptV1> {
    let go = || ExtensionResultV1::Continue;
    let reason = ExtensionReasonV1::HandlerFailed;
    // A receipt's result is the dispatcher's sticky result: once the error is recorded,
    // every later receipt carries the failure.
    let sticky = || ExtensionResultV1::Fail(reason);
    vec![
        step(1, ExtensionEventV1::Configure, go()),
        step(2, ExtensionEventV1::Error(reason), sticky()),
        step(3, ExtensionEventV1::Failed(reason), sticky()),
        step(
            4,
            ExtensionEventV1::Terminal(ExtensionTerminalV1::Failed(reason)),
            sticky(),
        ),
        step(5, ExtensionEventV1::Checkpoint, sticky()),
        step(6, ExtensionEventV1::Close, sticky()),
    ]
}

async fn trails<R: EventRepo>(repo: &R, run: CrawlRunId) -> Vec<serde_json::Value> {
    repo.list_metadata_after(run, 0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "extension_attempt")
        .map(|event| event.payload)
        .collect()
}

fn kinds(payload: &serde_json::Value) -> Vec<String> {
    payload["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|receipt| receipt["event"]["kind"].as_str().unwrap().to_owned())
        .collect()
}

async fn attempt<R: FrontierRepo>(repo: &R, run: CrawlRunId, id: i64) -> u32 {
    u32::from(repo.get_request(run, id).await.unwrap().entry.attempts)
}

struct Fixture {
    run: CrawlRun,
    tenant: TenantId,
    worker: WorkerId,
    leased: Vec<(FrontierEntry, i64)>,
    content: DatasetContentV1,
    _root: tempfile::TempDir,
}

async fn fixture<R>(repo: &Arc<R>, clock: &Arc<ManualClock>, tenant: TenantId) -> Fixture
where
    R: RunRepo + FrontierRepo + RequestCommitRepo + WorkerRegistry + ArtifactIndex + 'static,
{
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.days = 1;
    config.datasets = serde_json::from_value(serde_json::json!({
        "stores":[{"name":"items","schemaVersion":"document_item_v1","maxItems":10,"maxBytes":4096}],
        "feeds":[{"id":"feed","source":"items","serializer":"jsonl","serializerVersion":1,
        "destination":"fixture","maxBatchItems":2,"maxBatchBytes":4096,"batching":"terminal"}]
    }))
    .unwrap();
    let mut run = crawl_run(tenant, config);
    run.created_at = clock.now();
    repo.create(&run, None).await.unwrap();
    let worker = WorkerId::new();
    repo.register_worker(worker, "extension-fixture", "1")
        .await
        .unwrap();
    repo.publish_acquisition_capabilities(worker, &[BackendCapabilitiesV1::native_http("fixture", "1")])
        .await
        .unwrap();
    let mut facts = WorkerDataCapabilitiesV1::default();
    facts.destinations.insert("fixture".into(), true);
    repo.publish_data_capabilities(worker, &facts).await.unwrap();
    let requests = ["one", "two", "three"]
        .into_iter()
        .map(|name| RequestEnvelopeV1::get(canonical_url(&format!("https://fixture.test/{name}")), 0, None))
        .collect();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("wave3/extension-attempts", b"batch"),
        requests,
    ))
    .await
    .unwrap();
    let leased = repo.lease_batch_fenced(run.id, worker, 3).await.unwrap();
    assert_eq!(leased.len(), 3);
    let root = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(root.path(), repo.clone(), clock.clone())
        .await
        .unwrap()
        .with_index(repo.clone());
    let approved = Redactor::new().verify_canonical(b"{\"value\":1}\n").unwrap();
    let reference = ArtifactSink::over(&artifacts)
        .put_dataset(run.id, leased[1].0.id, "feed", "application/x-ndjson", &approved)
        .await
        .unwrap();
    let content = artifacts
        .dataset_content(run.id, leased[1].0.id, &reference, 12)
        .await
        .unwrap();
    Fixture {
        run,
        tenant,
        worker,
        leased,
        content,
        _root: root,
    }
}

fn commit(
    fx: &Fixture,
    index: usize,
    status: FrontierStatus,
    extensions: Vec<ExtensionReceiptV1>,
) -> RequestCommitV1 {
    let (entry, fence) = &fx.leased[index];
    let mut commit = RequestCommitV1::terminal(fx.run.id, entry.id, *fence, 1, status, None);
    commit.extensions = extensions;
    commit
}

fn with_item(fx: &Fixture, mut commit: RequestCommitV1, dataset: &str) -> RequestCommitV1 {
    let mut item = AcceptedItemV1::new(
        "one".into(),
        "fixture_v1".into(),
        "document_item_v1".into(),
        "fixture_v1".into(),
        fx.content.clone(),
        12,
    );
    item.expires_at = Some(fx.run.created_at + Duration::days(1));
    commit
        .accepted
        .push(AcceptedBatchV1::new(dataset.into(), vec![item]));
    commit
}

fn loss_fact(fx: &Fixture, index: usize, fence_offset: i64) -> ReportFactV1 {
    let (entry, fence) = &fx.leased[index];
    let lease = CustodyLease::for_url(fx.tenant, fx.run.id, entry.id, fx.worker, fence + fence_offset);
    let mut fact = ReportFactV1::new(
        &lease,
        Digest::of("wave3/extension-attempts", b"loss"),
        fx.run.created_at,
        ReportDataV1::Loss { dropped: 3 },
    );
    fact.request_id = Some(entry.id);
    fact
}

async fn loss_count<R: ReportHistoryRepo>(repo: &R, fx: &Fixture) -> usize {
    let mut query = ReportQueryV1::default();
    query.kind = Some(ReportKindV1::Loss);
    repo.query_facts(fx.tenant, Some(fx.run.id), &query)
        .await
        .unwrap()
        .entries
        .len()
}

async fn contract<R>(repo: Arc<R>, clock: Arc<ManualClock>, pg: Option<&Pg>, tenant: TenantId)
where
    R: RunRepo
        + FrontierRepo
        + RequestCommitRepo
        + EventRepo
        + DatasetRepo
        + ReportHistoryRepo
        + WorkerRegistry
        + ArtifactIndex
        + 'static,
{
    let fx = fixture(&repo, &clock, tenant).await;
    let run = fx.run.id;

    // Nonterminal retry: the complete trail is durable before the fence is handed back.
    let (one, fence_one) = (fx.leased[0].0.id, fx.leased[0].1);
    let first_attempt = attempt(repo.as_ref(), run, one).await;
    assert_eq!(first_attempt, 1);
    repo.record_extension_attempt(run, one, fence_one, first_attempt, &[])
        .await
        .unwrap();
    assert!(
        trails(repo.as_ref(), run).await.is_empty(),
        "no extensions leaves no trail"
    );
    let incomplete = completed_trail()[..2].to_vec();
    assert!(matches!(
        repo.record_extension_attempt(run, one, fence_one, first_attempt, &incomplete)
            .await,
        Err(StoreError::Conflict(_))
    ));
    repo.record_extension_attempt(run, one, fence_one, first_attempt, &completed_trail())
        .await
        .unwrap();
    // A lost acknowledgement may replay the identical trail without a second event.
    repo.record_extension_attempt(run, one, fence_one, first_attempt, &completed_trail())
        .await
        .unwrap();
    let stored = trails(repo.as_ref(), run).await;
    assert_eq!(stored.len(), 1);
    assert_eq!(
        kinds(&stored[0]),
        ["configure", "terminal", "checkpoint", "close"]
    );
    assert_eq!(stored[0]["requestId"], one);
    assert_eq!(stored[0]["fence"], fence_one);
    assert_eq!(stored[0]["attempt"], first_attempt);
    // Changed, stale, foreign and wrong-attempt callers cannot alter or add history.
    assert!(matches!(
        repo.record_extension_attempt(run, one, fence_one, first_attempt, &failed_trail())
            .await,
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        repo.record_extension_attempt(run, one, fence_one + 1, first_attempt, &failed_trail())
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        repo.record_extension_attempt(run, one, fence_one, first_attempt + 1, &failed_trail())
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        repo.record_extension_attempt(run, fx.leased[1].0.id, fence_one, first_attempt, &failed_trail())
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(repo
        .record_extension_attempt(CrawlRunId::new(), one, fence_one, first_attempt, &failed_trail())
        .await
        .is_err());
    assert!(crawlx_storage::tenant::scope(
        TenantId::new(),
        repo.record_extension_attempt(run, one, fence_one, first_attempt, &failed_trail())
    )
    .await
    .is_err());
    assert_eq!(trails(repo.as_ref(), run).await.len(), 1);
    // The trail is recorded first; only then is the lease handed back for another attempt.
    assert!(repo
        .retry_fenced(one, fence_one, Utc::now() - Duration::seconds(1))
        .await
        .unwrap());
    assert!(matches!(
        repo.record_extension_attempt(run, one, fence_one, first_attempt, &completed_trail())
            .await,
        Err(StoreError::LeaseLost)
    ));
    let (again, fence_again) = repo
        .lease_batch_fenced(run, fx.worker, 3)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(again.id, one);
    assert_ne!(fence_again, fence_one);
    let second_attempt = attempt(repo.as_ref(), run, one).await;
    assert_eq!(second_attempt, 2);
    assert!(matches!(
        repo.record_extension_attempt(run, one, fence_one, second_attempt, &failed_trail())
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert!(matches!(
        repo.record_extension_attempt(run, one, fence_again, first_attempt, &failed_trail())
            .await,
        Err(StoreError::LeaseLost)
    ));
    repo.record_extension_attempt(run, one, fence_again, second_attempt, &failed_trail())
        .await
        .unwrap();
    let stored = trails(repo.as_ref(), run).await;
    assert_eq!(stored.len(), 2);
    assert_eq!(
        kinds(&stored[1]),
        ["configure", "error", "failed", "terminal", "checkpoint", "close"]
    );
    assert_eq!(
        kinds(&stored[0]),
        ["configure", "terminal", "checkpoint", "close"]
    );

    // Terminal success: trail, accepted items and report facts are all-or-nothing.
    let (two, fence_two) = (fx.leased[1].0.id, fx.leased[1].1);
    let mut stale = with_item(
        &fx,
        commit(&fx, 1, FrontierStatus::Succeeded, completed_trail()),
        "items",
    );
    stale.fence += 1;
    assert!(matches!(
        repo.commit_fenced(stale).await,
        Err(StoreError::LeaseLost)
    ));
    let malformed = with_item(
        &fx,
        commit(&fx, 1, FrontierStatus::Succeeded, incomplete.clone()),
        "items",
    );
    assert!(matches!(
        repo.commit_fenced(malformed).await,
        Err(StoreError::Conflict(_))
    ));
    let mut foreign_fact = with_item(
        &fx,
        commit(&fx, 1, FrontierStatus::Succeeded, completed_trail()),
        "items",
    );
    foreign_fact.report_facts.push(loss_fact(&fx, 1, 1));
    assert!(matches!(
        repo.commit_fenced(foreign_fact).await,
        Err(StoreError::LeaseLost)
    ));
    let undeclared = with_item(
        &fx,
        commit(&fx, 1, FrontierStatus::Succeeded, completed_trail()),
        "undeclared",
    );
    assert!(repo.commit_fenced(undeclared).await.is_err());
    if let Some(pg) = pg {
        // Abort at the final frontier update, after the trail and every other row were staged.
        sqlx::query("CREATE FUNCTION reject_extension_result() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned result abort'; END $$")
            .execute(pg.pool()).await.unwrap();
        sqlx::query("CREATE TRIGGER reject_extension_result BEFORE UPDATE OF status ON url_frontier FOR EACH ROW WHEN (NEW.status='succeeded') EXECUTE FUNCTION reject_extension_result()")
            .execute(pg.pool()).await.unwrap();
        let mut staged = with_item(
            &fx,
            commit(&fx, 1, FrontierStatus::Succeeded, completed_trail()),
            "items",
        );
        staged.report_facts.push(loss_fact(&fx, 1, 0));
        assert!(repo.commit_fenced(staged).await.is_err());
        sqlx::query("DROP TRIGGER reject_extension_result ON url_frontier")
            .execute(pg.pool())
            .await
            .unwrap();
        sqlx::query("DROP FUNCTION reject_extension_result()")
            .execute(pg.pool())
            .await
            .unwrap();
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM extension_attempts WHERE request_id=$1")
            .bind(two)
            .fetch_one(pg.pool())
            .await
            .unwrap();
        assert_eq!(rows, 0);
    }
    assert_eq!(
        trails(repo.as_ref(), run).await.len(),
        2,
        "failed commits leave no trail"
    );
    assert!(repo.items(run, "items", 0, 10).await.unwrap().is_empty());
    assert_eq!(
        loss_count(repo.as_ref(), &fx).await,
        0,
        "failed commits leave no facts"
    );
    assert_eq!(repo.get_request(run, two).await.unwrap().state_version, 1);

    let mut success = with_item(
        &fx,
        commit(&fx, 1, FrontierStatus::Succeeded, completed_trail()),
        "items",
    );
    success.report_facts.push(loss_fact(&fx, 1, 0));
    repo.commit_fenced(success.clone()).await.unwrap();
    let stored = trails(repo.as_ref(), run).await;
    assert_eq!(stored.len(), 3);
    assert_eq!(stored[2]["requestId"], two);
    assert_eq!(stored[2]["fence"], fence_two);
    assert_eq!(stored[2]["attempt"], 1);
    assert_eq!(
        kinds(&stored[2]),
        ["configure", "terminal", "checkpoint", "close"]
    );
    assert_eq!(repo.items(run, "items", 0, 10).await.unwrap().len(), 1);
    assert_eq!(loss_count(repo.as_ref(), &fx).await, 1);
    // A duplicate result cannot append a second trail or fact.
    assert!(matches!(
        repo.commit_fenced(success).await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(trails(repo.as_ref(), run).await.len(), 3);
    assert_eq!(loss_count(repo.as_ref(), &fx).await, 1);

    // Terminal failure persists the typed failed-callback ordering under its own attempt.
    let (three, fence_three) = (fx.leased[2].0.id, fx.leased[2].1);
    let mut failed = commit(&fx, 2, FrontierStatus::Failed, failed_trail());
    failed.reason = Some("handler_failed".into());
    repo.commit_fenced(failed).await.unwrap();
    let stored = trails(repo.as_ref(), run).await;
    assert_eq!(stored.len(), 4);
    assert_eq!(stored[3]["requestId"], three);
    assert_eq!(stored[3]["fence"], fence_three);
    assert_eq!(
        kinds(&stored[3]),
        ["configure", "error", "failed", "terminal", "checkpoint", "close"]
    );
    if let Some(pg) = pg {
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM extension_attempts WHERE run_id=$1")
            .bind(run.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
        // Distinct trails: request one at attempts 1 and 2 (two fences), request two, request three.
        assert_eq!(rows, 4, "one digest row per distinct request, fence and attempt");
    }
}

#[tokio::test]
async fn memory_extension_attempts_are_ordered_idempotent_and_atomic() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    contract(repo, clock, None, TenantId::new()).await;
}

#[tokio::test]
async fn postgres_extension_attempts_are_ordered_idempotent_and_atomic() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("extension_attempts_{}", CrawlRunId::new().0.simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "extension-attempts").await.unwrap();
    let clock = Arc::new(ManualClock::new(Utc::now()));
    contract(Arc::new(pg.clone()), clock, Some(&pg), tenant).await;
    pg.drop_schema().await.unwrap();
}

async fn failed_recrawl<R>(repo: Arc<R>, clock: Arc<ManualClock>, tenant: TenantId)
where
    R: RunRepo + FrontierRepo + RequestCommitRepo,
{
    let mut config = create_crawl("https://fixture.test/recrawl", &[], 1);
    config.retention.days = 1;
    let mut policy = crawlx_core::orchestration::OrchestrationConfigV1::default();
    policy.recrawl = Some(
        serde_json::from_value(serde_json::json!({
            "version":1,"minIntervalMs":1000,"maxIntervalMs":1000,"maxVisits":2,"adaptive":{},
            "endAt":clock.now()+Duration::minutes(1)
        }))
        .unwrap(),
    );
    config.orchestration = Some(policy);
    let mut run = crawl_run(tenant, config);
    run.created_at = clock.now();
    repo.create(&run, None).await.unwrap();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest::of("wave3/extension-attempts", b"recrawl"),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://fixture.test/recrawl"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let (entry, fence) = repo
        .lease_batch_fenced(run.id, WorkerId::new(), 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let mut failed = RequestCommitV1::terminal(
        run.id,
        entry.id,
        fence,
        1,
        FrontierStatus::Failed,
        Some("fetch_failed".into()),
    );
    failed.extensions = failed_trail();
    repo.commit_fenced(failed).await.unwrap();
    // Failure is scheduled from real commit facts, never as an unchanged success.
    let next = repo
        .metadata_page(run.id, entry.id, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(
        repo.get_request(run.id, next.id)
            .await
            .unwrap()
            .envelope
            .revisit_generation,
        1
    );
}

#[tokio::test]
async fn memory_failed_result_schedules_adaptive_revisit() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    failed_recrawl(
        Arc::new(MemoryStore::with_clock(clock.clone())),
        clock,
        TenantId::new(),
    )
    .await;
}

#[tokio::test]
async fn postgres_failed_result_schedules_adaptive_revisit() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("extension_recrawl_{}", CrawlRunId::new().0.simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "extension-recrawl").await.unwrap();
    let clock = Arc::new(ManualClock::new(Utc::now()));
    failed_recrawl(Arc::new(pg.clone()), clock, tenant).await;
    pg.drop_schema().await.unwrap();
}
