//! Request frontier parity sources. Optional PostgreSQL tests require CRAWLX_TEST_DATABASE_URL.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{
    FrontierActivityV1, LoaderCursorV1, OrchestrationConfigV1, ProducerModeV1, RequestBatchV1,
    RequestCommitRepo, RequestCommitV1,
};
use crawlx_core::repo::{CrawlRun, FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, StoreError, TenantId, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{LeaseRepo, MemoryStore, Pg, PgConfig};
use std::sync::Arc;

fn run(tenant: TenantId, now: crawlx_core::Timestamp) -> CrawlRun {
    let mut config = create_crawl("https://example.test/", &[], 1);
    let mut policy = OrchestrationConfigV1::default();
    policy.queue.producer_mode = ProducerModeV1::Continuous;
    policy.queue.max_pending_entries = 2;
    config.orchestration = Some(policy);
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    run
}
fn batch(run: &CrawlRun, name: &str, paths: &[&str]) -> RequestBatchV1 {
    RequestBatchV1::new(
        run.tenant,
        run.id,
        "anonymous".into(),
        Digest::of("test/batch", name.as_bytes()),
        paths
            .iter()
            .map(|path| {
                RequestEnvelopeV1::get(canonical_url(&format!("https://example.test/{path}")), 0, None)
            })
            .collect(),
    )
}

async fn shared_contract<R: FrontierRepo + RunRepo + RequestCommitRepo>(repo: &R, tenant: TenantId) {
    let run = run(tenant, Utc::now());
    repo.create(&run, None).await.unwrap();
    assert_eq!(
        repo.activity(run.id).await.unwrap(),
        FrontierActivityV1::WaitingProducer
    );
    let mut input = batch(&run, "one", &["low", "high"]);
    input.requests[1].priority = 12;
    let cursor = LoaderCursorV1::new("fixture".into(), Digest::of("test/source", b"v1"), 2);
    input.next_cursor = Some(cursor.clone());
    let first = repo.append_batch(input.clone()).await.unwrap();
    assert_eq!(first.inserted.len(), 2);
    assert_eq!(repo.append_batch(input.clone()).await.unwrap(), first);
    assert_eq!(repo.loader_cursor(run.id, "fixture").await.unwrap(), Some(cursor));
    let mut changed = input.clone();
    changed.requests.pop();
    assert!(matches!(
        repo.append_batch(changed).await,
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        repo.append_batch(batch(&run, "overflow", &["third"])).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(repo.metadata_page(run.id, 0, 1).await.unwrap().len(), 1);
    let worker = WorkerId::new();
    let leased = repo.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    assert_eq!(leased[0].0.url.url.path(), "/high");
    assert!(matches!(
        repo.complete_fenced(leased[0].0.id, leased[0].1 + 1, FrontierStatus::Succeeded, None)
            .await,
        Err(StoreError::LeaseLost)
    ));
    repo.commit_fenced(RequestCommitV1::terminal(
        run.id,
        leased[0].0.id,
        leased[0].1,
        1,
        FrontierStatus::Succeeded,
        None,
    ))
    .await
    .unwrap();
    assert!(matches!(
        repo.commit_fenced(RequestCommitV1::terminal(
            run.id,
            leased[0].0.id,
            leased[0].1,
            1,
            FrontierStatus::Succeeded,
            None
        ))
        .await,
        Err(StoreError::LeaseLost)
    ));
    let rest = repo.lease_batch_fenced(run.id, worker, 2).await.unwrap();
    repo.defer_fenced(rest[0].0.id, rest[0].1, Utc::now() + Duration::minutes(1))
        .await
        .unwrap();
    assert_eq!(
        repo.activity(run.id).await.unwrap(),
        FrontierActivityV1::WaitingCooldown
    );
    assert!(repo
        .lease_batch_fenced(run.id, worker, 2)
        .await
        .unwrap()
        .is_empty());
    assert!(repo.seal(run.id, 2).await.is_err());
    repo.seal(run.id, 1).await.unwrap();
    assert!(repo
        .append_batch(batch(&run, "sealed", &["later"]))
        .await
        .is_err());
    assert_eq!(
        repo.activity(run.id).await.unwrap(),
        FrontierActivityV1::WaitingCooldown
    );
}

#[tokio::test]
async fn memory_request_frontier_contract() {
    shared_contract(&MemoryStore::new(), TenantId::new()).await;
}
#[tokio::test]
async fn postgres_request_frontier_contract() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("request_{}", crawlx_core::CrawlRunId::new().0.simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "request-tests").await.unwrap();
    shared_contract(&pg, tenant).await;
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn expiry_cannot_be_renewed_completed_or_used_to_append_children() {
    let now = Utc::now();
    let clock = Arc::new(ManualClock::new(now));
    let store = MemoryStore::with_clock(clock.clone());
    let run = run(TenantId::new(), clock.now());
    store.create(&run, None).await.unwrap();
    let id = store
        .append_batch(batch(&run, "parent", &["parent"]))
        .await
        .unwrap()
        .inserted[0];
    let worker = WorkerId::new();
    let lease = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    clock.advance_ms(61_000);
    assert!(store
        .heartbeat_frontier(worker, &[(id, lease[0].1)])
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        store
            .complete_fenced(id, lease[0].1, FrontierStatus::Succeeded, None)
            .await,
        Err(StoreError::LeaseLost)
    ));
    let mut child = batch(&run, "child", &["child"]);
    child.parent_fence = Some((id, lease[0].1));
    child.requests[0].parent = Some(id);
    child.next_cursor = Some(LoaderCursorV1::new(
        "children".into(),
        Digest::of("test", b"v1"),
        1,
    ));
    assert!(matches!(
        store.append_batch(child).await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(store.loader_cursor(run.id, "children").await.unwrap(), None);
    assert_eq!(store.metadata_page(run.id, 0, 1000).await.unwrap().len(), 1);
}

#[tokio::test]
async fn request_reservations_survive_retry_and_do_not_extend_elapsed_deadline() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let store = MemoryStore::with_clock(clock.clone());
    let mut run = run(TenantId::new(), clock.now());
    run.config
        .orchestration
        .as_mut()
        .unwrap()
        .attempts
        .max_total_effects = 2;
    store.create(&run, None).await.unwrap();
    let id = store
        .append_batch(batch(&run, "effects", &["one"]))
        .await
        .unwrap()
        .inserted[0];
    let worker = WorkerId::new();
    let one = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    store
        .reserve_effects_fenced(run.id, id, one[0].1, 1)
        .await
        .unwrap();
    assert!(store.retry_fenced(id, one[0].1, clock.now()).await.unwrap());
    let two = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    store
        .reserve_effects_fenced(run.id, id, two[0].1, 1)
        .await
        .unwrap();
    assert!(!store.retry_fenced(id, two[0].1, clock.now()).await.unwrap());
    assert!(store
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        store.metadata_page(run.id, 0, 1).await.unwrap()[0].status,
        FrontierStatus::Failed
    );
}

#[tokio::test]
async fn loader_checkpoint_rejects_changed_source_without_advancing_or_inserting() {
    let store = MemoryStore::new();
    let run = run(TenantId::new(), Utc::now());
    store.create(&run, None).await.unwrap();
    let mut first = batch(&run, "initial", &["first"]);
    let old = LoaderCursorV1::new("source".into(), Digest::of("test", b"one"), 1);
    first.next_cursor = Some(old.clone());
    store.append_batch(first).await.unwrap();
    let mut changed = batch(&run, "changed", &["second"]);
    changed.expected_cursor = Some(old.clone());
    changed.next_cursor = Some(LoaderCursorV1::new(
        "source".into(),
        Digest::of("test", b"two"),
        2,
    ));
    assert!(changed.validate().is_err());
    assert!(store.append_batch(changed).await.is_err());
    assert_eq!(store.loader_cursor(run.id, "source").await.unwrap(), Some(old));
    assert_eq!(store.metadata_page(run.id, 0, 1000).await.unwrap().len(), 1);
}

#[tokio::test]
async fn hundred_thousand_rows_keep_claim_population_and_keysets_bounded() {
    let store = MemoryStore::new();
    let mut run = run(TenantId::new(), Utc::now());
    let policy = run.config.orchestration.as_mut().unwrap();
    policy.queue.max_pending_entries = 100_000;
    policy.queue.max_pending_envelope_bytes = 128 * 1024 * 1024;
    policy.queue.batch_size = 1000;
    store.create(&run, None).await.unwrap();
    for page in 0..100_u32 {
        let requests = (0..1000_u32)
            .map(|offset| {
                RequestEnvelopeV1::get(
                    canonical_url(&format!("https://example.test/row/{}", page * 1000 + offset)),
                    0,
                    None,
                )
            })
            .collect();
        store
            .append_batch(RequestBatchV1::new(
                run.tenant,
                run.id,
                "anonymous".into(),
                Digest::of("test/page", &page.to_be_bytes()),
                requests,
            ))
            .await
            .unwrap();
    }
    assert_eq!(store.open_count(run.id).await.unwrap(), 100_000);
    let mut previous = 0;
    for _ in 0..64 {
        let claimed = store
            .lease_batch_fenced(run.id, WorkerId::new(), 16)
            .await
            .unwrap();
        assert_eq!(claimed.len(), 16);
        for (entry, _) in claimed {
            assert!(entry.id > previous);
            previous = entry.id;
        }
    }
    assert_eq!(store.metadata_page(run.id, 0, 1000).await.unwrap().len(), 1000);
    assert!(store.metadata_page(run.id, 0, 1001).await.is_err());
}

#[tokio::test]
async fn recrawl_allocates_delayed_generations_without_reopening_terminal_rows() {
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let store = MemoryStore::with_clock(clock.clone());
    let mut run = run(TenantId::new(), clock.now());
    run.config.orchestration.as_mut().unwrap().recrawl = Some(
        serde_json::from_value(serde_json::json!({
            "version":1,"minIntervalMs":1000,"maxIntervalMs":2000,"maxVisits":2,
            "endAt":clock.now()+Duration::minutes(1)
        }))
        .unwrap(),
    );
    store.create(&run, None).await.unwrap();
    store
        .append_batch(batch(&run, "recrawl", &["article"]))
        .await
        .unwrap();
    store.seal(run.id, 1).await.unwrap();
    let worker = WorkerId::new();
    let first = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    store
        .commit_fenced(RequestCommitV1::terminal(
            run.id,
            first[0].0.id,
            first[0].1,
            1,
            FrontierStatus::Succeeded,
            None,
        ))
        .await
        .unwrap();
    let rows = store.metadata_page(run.id, 0, 1000).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].status, FrontierStatus::Succeeded);
    assert_eq!(rows[1].revisit_generation, 1);
    assert_eq!(
        store.activity(run.id).await.unwrap(),
        FrontierActivityV1::WaitingCooldown
    );
    clock.advance_ms(1000);
    let second = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    assert_ne!(first[0].0.id, second[0].0.id);
    store
        .commit_fenced(RequestCommitV1::terminal(
            run.id,
            second[0].0.id,
            second[0].1,
            1,
            FrontierStatus::Succeeded,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(store.metadata_page(run.id, 0, 1000).await.unwrap().len(), 2);
    assert_eq!(
        store.activity(run.id).await.unwrap(),
        FrontierActivityV1::Terminal
    );
}

#[tokio::test]
async fn direct_import_cannot_mint_recrawl_generation_authority() {
    let store = MemoryStore::new();
    let run = run(TenantId::new(), Utc::now());
    store.create(&run, None).await.unwrap();
    let mut forged = batch(&run, "forged", &["article"]);
    forged.requests[0].revisit_generation = 1;
    assert!(matches!(
        store.append_batch(forged).await,
        Err(StoreError::AccessDenied(_))
    ));
    assert!(store.metadata_page(run.id, 0, 1000).await.unwrap().is_empty());
}

#[tokio::test]
async fn native_escrow_settles_known_usage_but_lost_lease_forfeits_unused_capacity() {
    use crawlx_core::acquisition::{AcquisitionPolicyV1, AcquisitionUsageV1};
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let store = MemoryStore::with_clock(clock.clone());
    let mut run = run(TenantId::new(), clock.now());
    let mut acquisition = AcquisitionPolicyV1::default();
    acquisition.max_attempts = 3;
    acquisition.max_network_requests = 6;
    acquisition.max_elapsed_ms = 300_000;
    run.config.acquisition = Some(acquisition);
    store.create(&run, None).await.unwrap();
    let id = store
        .append_batch(batch(&run, "escrow", &["article"]))
        .await
        .unwrap()
        .inserted[0];
    let worker = WorkerId::new();
    assert!(store
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .is_empty());
    crawlx_storage::WorkerRegistry::register_worker(&store, worker, "fixture", "1")
        .await
        .unwrap();
    crawlx_storage::WorkerRegistry::publish_acquisition_capabilities(
        &store,
        worker,
        &[crawlx_core::acquisition::BackendCapabilitiesV1::native_http(
            "fixture", "1",
        )],
    )
    .await
    .unwrap();
    let first = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    let receipt = store
        .reserve_acquisition_fenced(run.id, id, first[0].1)
        .await
        .unwrap();
    assert_eq!(receipt.remaining_attempts, 3);
    let usage = AcquisitionUsageV1::new(1, 1, 10, 10, false);
    store
        .settle_acquisition_fenced(run.id, id, first[0].1, &usage)
        .await
        .unwrap();
    store
        .settle_acquisition_fenced(run.id, id, first[0].1, &usage)
        .await
        .unwrap();
    assert!(store.retry_fenced(id, first[0].1, clock.now()).await.unwrap());
    let next = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    let remaining = store
        .reserve_acquisition_fenced(run.id, id, next[0].1)
        .await
        .unwrap();
    assert_eq!(remaining.remaining_attempts, 2);
    assert_eq!(remaining.remaining_network_requests, 5);
    assert_eq!(remaining.previous_usage, usage);
    clock.advance_ms(61_000);
    assert!(matches!(
        store
            .settle_acquisition_fenced(run.id, id, next[0].1, &usage)
            .await,
        Err(StoreError::LeaseLost)
    ));
    store.reap_frontier(clock.now(), 10).await.unwrap();
    let reclaimed = store.lease_batch_fenced(run.id, worker, 1).await.unwrap();
    assert!(store
        .reserve_acquisition_fenced(run.id, id, reclaimed[0].1)
        .await
        .is_err());
}

#[tokio::test]
async fn session_and_url_claims_require_all_backends_on_the_claiming_worker() {
    use crawlx_core::acquisition::{AcquisitionPolicyV1, BackendCapabilitiesV1};
    use crawlx_storage::WorkerRegistry;
    let clock = Arc::new(ManualClock::new(Utc::now()));
    let store = MemoryStore::with_clock(clock.clone());
    let mut run = run(TenantId::new(), clock.now());
    let mut policy = AcquisitionPolicyV1::default();
    policy.backend_ids = vec!["native_http".into(), "native_browser".into()];
    run.config.acquisition = Some(policy);
    store.create(&run, None).await.unwrap();
    store
        .create_sessions(&crawlx_storage::testkit::sessions(run.id, 1, 1))
        .await
        .unwrap();
    store
        .append_batch(batch(&run, "backend", &["article"]))
        .await
        .unwrap();
    let http_worker = WorkerId::new();
    let browser_worker = WorkerId::new();
    store
        .register_worker(http_worker, "http-fixture", "1")
        .await
        .unwrap();
    store
        .register_worker(browser_worker, "browser-fixture", "1")
        .await
        .unwrap();
    let http = BackendCapabilitiesV1::native_http("fixture", "1");
    let browser =
        BackendCapabilitiesV1::native_browser(crawlx_storage::testkit::browser_build("155.0.8059.84", "1.3"));
    store
        .publish_acquisition_capabilities(http_worker, std::slice::from_ref(&http))
        .await
        .unwrap();
    store
        .publish_acquisition_capabilities(browser_worker, std::slice::from_ref(&browser))
        .await
        .unwrap();
    assert!(store
        .claim_session(run.id, http_worker, false)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .claim_session(run.id, browser_worker, false)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .lease_batch_fenced(run.id, http_worker, 1)
        .await
        .unwrap()
        .is_empty());
    store
        .publish_acquisition_capabilities(http_worker, &[http, browser])
        .await
        .unwrap();
    assert!(store
        .claim_session(run.id, http_worker, false)
        .await
        .unwrap()
        .is_some());
    assert_eq!(
        store
            .lease_batch_fenced(run.id, http_worker, 1)
            .await
            .unwrap()
            .len(),
        1
    );
}

async fn legacy_strategy_fixture<R: FrontierRepo + RunRepo>(
    repo: &R,
    tenant: TenantId,
) -> (CrawlRun, Vec<i64>) {
    let mut run = run(tenant, Utc::now());
    run.config.scope.strategy = crawlx_core::config::CrawlStrategy::Priority;
    run.config
        .orchestration
        .as_mut()
        .unwrap()
        .queue
        .max_pending_entries = 128;
    repo.create(&run, None).await.unwrap();
    let mut ids = Vec::new();
    for index in 0..33 {
        let (path, depth) = if index == 32 {
            ("admin/late".to_owned(), 2)
        } else {
            (format!("plain/{index}"), 1)
        };
        ids.push(
            repo.discover(
                run.id,
                &canonical_url(&format!("https://example.test/{path}")),
                depth,
                None,
                None,
            )
            .await
            .unwrap()
            .1
            .unwrap(),
        );
    }
    ids.rotate_right(1);
    (run, ids)
}

#[tokio::test]
async fn memory_legacy_priority_discovery_selects_late_surface_before_first_batch() {
    let store = MemoryStore::new();
    let (run, expected) = legacy_strategy_fixture(&store, TenantId::new()).await;
    drain_strategy(&store, &run, &expected, &[]).await;
}

async fn strategy_fixture<R: FrontierRepo + RunRepo>(
    repo: &R,
    tenant: TenantId,
    strategy: crawlx_core::config::CrawlStrategy,
) -> (CrawlRun, Vec<i64>) {
    use crawlx_core::config::CrawlStrategy;

    let mut run = run(tenant, Utc::now());
    run.config.scope.strategy = strategy;
    let queue = &mut run.config.orchestration.as_mut().unwrap().queue;
    queue.max_pending_entries = 128;
    queue.batch_size = 16;
    repo.create(&run, None).await.unwrap();
    let requests: Vec<_> = (0..48)
        .map(|index| {
            let (path, depth) = match index {
                0..16 => (format!("plain/{index}"), 2),
                16..32 => (format!("plain/{index}"), 1),
                _ => (format!("admin/{index}?q=1"), 3),
            };
            let mut request = RequestEnvelopeV1::get(
                canonical_url(&format!("https://example.test/{path}")),
                depth,
                None,
            );
            request.priority = match index {
                0 => 10,
                47 => -10,
                _ => 0,
            };
            if index == 46 {
                request.method = "POST".into();
            }
            request
        })
        .collect();
    let mut ids = Vec::new();
    for (index, chunk) in requests.chunks(16).enumerate() {
        ids.extend(
            repo.append_batch(RequestBatchV1::new(
                run.tenant,
                run.id,
                "anonymous".into(),
                Digest::of("test/strategy-batch", &index.to_be_bytes()),
                chunk.to_vec(),
            ))
            .await
            .unwrap()
            .inserted,
        );
    }
    // Expected permutations are independent of the production score/comparator.
    let mut indices = vec![0];
    match strategy {
        CrawlStrategy::BreadthFirst => {
            indices.extend(16..32);
            indices.extend(1..16);
            indices.extend(32..47);
        }
        CrawlStrategy::DepthFirst => {
            indices.extend((32..47).rev());
            indices.extend((1..16).rev());
            indices.extend((16..32).rev());
        }
        CrawlStrategy::Priority => {
            indices.push(46);
            indices.extend(32..46);
            indices.extend(16..32);
            indices.extend(1..16);
        }
    }
    indices.push(47);
    (run, indices.into_iter().map(|index| ids[index]).collect())
}

async fn drain_strategy<R: FrontierRepo + RequestCommitRepo>(
    repo: &R,
    run: &CrawlRun,
    expected: &[i64],
    stale: &[(crawlx_core::repo::FrontierEntry, i64)],
) {
    for chunk in expected.chunks(16) {
        let claimed = repo
            .lease_batch_fenced(run.id, WorkerId::new(), 16)
            .await
            .unwrap();
        assert_eq!(
            claimed.iter().map(|(entry, _)| entry.id).collect::<Vec<_>>(),
            chunk,
            "strategy {:?} must choose globally before LIMIT",
            run.config.scope.strategy,
        );
        for (entry, fence) in claimed {
            if let Some((previous, old)) = stale.iter().find(|(old, _)| old.id == entry.id) {
                assert!(fence > *old);
                assert_eq!(entry.attempts, previous.attempts + 1);
                assert!(matches!(
                    repo.complete_fenced(entry.id, *old, FrontierStatus::Succeeded, None)
                        .await,
                    Err(StoreError::LeaseLost)
                ));
                assert!(matches!(
                    repo.give_back(entry.id, *old).await,
                    Err(StoreError::LeaseLost)
                ));
                assert!(matches!(
                    repo.retry_fenced(entry.id, *old, Utc::now()).await,
                    Err(StoreError::LeaseLost)
                ));
                assert!(matches!(
                    repo.reserve_effects_fenced(run.id, entry.id, *old, 1).await,
                    Err(StoreError::LeaseLost)
                ));
                let mut children = batch(run, &format!("stale-child-{}", entry.id), &["stale-child"]);
                children.parent_fence = Some((entry.id, *old));
                children.requests[0].parent = Some(entry.id);
                assert!(matches!(
                    repo.append_batch(children.clone()).await,
                    Err(StoreError::LeaseLost)
                ));
                let mut commit =
                    RequestCommitV1::terminal(run.id, entry.id, *old, 1, FrontierStatus::Succeeded, None);
                commit.children = Some(children);
                assert!(matches!(
                    repo.commit_fenced(commit).await,
                    Err(StoreError::LeaseLost)
                ));
            }
            repo.complete_fenced(entry.id, fence, FrontierStatus::Succeeded, None)
                .await
                .unwrap();
        }
    }
    assert!(repo
        .lease_batch_fenced(run.id, WorkerId::new(), 16)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        repo.metadata_page(run.id, 0, 1000).await.unwrap().len(),
        expected.len()
    );
}

#[tokio::test]
async fn memory_strategies_choose_globally_across_batches_and_reaped_fences() {
    use crawlx_core::config::CrawlStrategy;

    let store = MemoryStore::new();
    for strategy in [
        CrawlStrategy::BreadthFirst,
        CrawlStrategy::DepthFirst,
        CrawlStrategy::Priority,
    ] {
        let (run, expected) = strategy_fixture(&store, TenantId::new(), strategy).await;
        let mut first = store
            .lease_batch_fenced(run.id, WorkerId::new(), 16)
            .await
            .unwrap();
        assert_eq!(
            first.iter().map(|(entry, _)| entry.id).collect::<Vec<_>>(),
            expected[..16],
        );
        // Giving a row back must not change discovery order or explicit priority.
        store.give_back(first[0].0.id, first[0].1).await.unwrap();
        let replacement = store
            .lease_batch_fenced(run.id, WorkerId::new(), 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(replacement.0.id, first[0].0.id);
        assert_eq!(replacement.0.attempts, 1);
        assert!(replacement.1 > first[0].1);
        first[0] = replacement;
        assert_eq!(
            store
                .reap_frontier(Utc::now() + Duration::minutes(2), 10)
                .await
                .unwrap()
                .requeued,
            16,
        );
        drain_strategy(&store, &run, &expected, &first).await;
    }
}

#[tokio::test]
async fn postgres_strategies_survive_restart_and_backfill_without_changing_priorities_or_fences() {
    use crawlx_core::config::CrawlStrategy;

    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let config = PgConfig {
        schema: Some(format!("strategy_{}", crawlx_core::CrawlRunId::new().0.simple())),
        ..PgConfig::default()
    };
    let pg = Pg::connect(&url, config.clone()).await.unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "strategy-tests").await.unwrap();
    let mut fixtures = Vec::new();
    for strategy in [
        CrawlStrategy::BreadthFirst,
        CrawlStrategy::DepthFirst,
        CrawlStrategy::Priority,
    ] {
        let (run, expected) = strategy_fixture(&pg, tenant, strategy).await;
        let first = pg.lease_batch_fenced(run.id, WorkerId::new(), 16).await.unwrap();
        assert_eq!(
            first.iter().map(|(entry, _)| entry.id).collect::<Vec<_>>(),
            expected[..16],
        );
        // Simulate rows admitted before the nullable derived-score migration.
        sqlx::query("UPDATE url_frontier SET strategy_score=NULL WHERE run_id=$1")
            .bind(run.id.0)
            .execute(pg.pool())
            .await
            .unwrap();
        fixtures.push((run, expected, first));
    }
    let (legacy, expected) = legacy_strategy_fixture(&pg, tenant).await;
    sqlx::query(
        "UPDATE url_frontier SET strategy_score=NULL,request_envelope=NULL,envelope_bytes=0 WHERE run_id=$1",
    )
    .bind(legacy.id.0)
    .execute(pg.pool())
    .await
    .unwrap();
    fixtures.push((legacy, expected, Vec::new()));
    pg.pool().close().await;
    drop(pg);
    let restarted = Pg::connect_existing(&url, config).await.unwrap();
    assert_eq!(
        restarted
            .reap_frontier(Utc::now() + Duration::minutes(2), 10)
            .await
            .unwrap()
            .requeued,
        48,
    );
    for (run, expected, stale) in fixtures {
        drain_strategy(&restarted, &run, &expected, &stale).await;
        if run.config.scope.strategy == CrawlStrategy::Priority {
            let missing: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM url_frontier WHERE run_id=$1 AND strategy_score IS NULL",
            )
            .bind(run.id.0)
            .fetch_one(restarted.pool())
            .await
            .unwrap();
            assert_eq!(
                missing, 0,
                "all pre-cutover candidates must be scored before LIMIT"
            );
        }
    }
    restarted.drop_schema().await.unwrap();
}

#[tokio::test]
async fn postgres_priority_backfill_reads_volatile_original_method_and_fails_closed_after_expiry() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let buffer = Arc::new(crawlx_storage::DeliveryBuffer::with_defaults(Arc::new(
        crawlx_core::SystemClock,
    )));
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!(
                "strategy_zdr_{}",
                crawlx_core::CrawlRunId::new().0.simple()
            )),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap()
    .with_delivery_buffer(buffer.clone());
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "strategy-zdr-tests").await.unwrap();
    let mut run = run(tenant, Utc::now());
    run.config.scope.strategy = crawlx_core::config::CrawlStrategy::Priority;
    run.config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
    run.config.retention.days = 0;
    run.config
        .orchestration
        .as_mut()
        .unwrap()
        .queue
        .max_pending_entries = 128;
    pg.create(&run, None).await.unwrap();
    let mut input = batch(&run, "volatile-strategy", &[]);
    input.requests = (0..33)
        .map(|index| {
            let mut request = RequestEnvelopeV1::get(
                canonical_url(&format!(
                    "https://example.test/plain/{index}?private=strategy-backfill-canary"
                )),
                1,
                None,
            );
            if index == 32 {
                request.url =
                    canonical_url("https://example.test/admin/private?private=strategy-backfill-canary");
                request.depth = 2;
                request.method = "POST".into();
            }
            request
        })
        .collect();
    let ids = pg.append_batch(input).await.unwrap().inserted;
    sqlx::query("UPDATE url_frontier SET strategy_score=NULL WHERE run_id=$1")
        .bind(run.id.0)
        .execute(pg.pool())
        .await
        .unwrap();
    let claimed = pg.lease_batch_fenced(run.id, WorkerId::new(), 1).await.unwrap();
    assert_eq!(claimed[0].0.id, ids[32]);
    let score: i32 = sqlx::query_scalar("SELECT strategy_score FROM url_frontier WHERE frontier_id=$1")
        .bind(ids[32])
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(score, 2, "backfill must retain the original POST method");
    let missing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM url_frontier WHERE run_id=$1 AND strategy_score IS NULL")
            .bind(run.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert_eq!(missing, 0, "score every candidate before LIMIT");
    for table in ["crawl_runs", "url_frontier", "frontier_batch_receipts"] {
        let rows: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT row_to_json(t)::text FROM {table} t WHERE run_id=$1"
        )))
        .bind(run.id.0)
        .fetch_all(pg.pool())
        .await
        .unwrap();
        assert!(rows.iter().all(|row| !row.contains("strategy-backfill-canary")));
        assert!(rows.iter().all(|row| !row.contains("https://example.test")));
    }
    pg.give_back(claimed[0].0.id, claimed[0].1).await.unwrap();
    sqlx::query("UPDATE url_frontier SET strategy_score=NULL WHERE run_id=$1")
        .bind(run.id.0)
        .execute(pg.pool())
        .await
        .unwrap();
    // Expire only an original request, not the run config. No durable URL fallback may appear.
    assert!(buffer.ack(tenant, run.id, -ids[0]).await.unwrap());
    assert!(matches!(
        pg.lease_batch_fenced(run.id, WorkerId::new(), 16).await,
        Err(StoreError::RetentionDenied(_))
    ));
    let untouched: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM url_frontier WHERE run_id=$1 AND strategy_score IS NULL \
         AND status='pending' AND attempts=0",
    )
    .bind(run.id.0)
    .fetch_one(pg.pool())
    .await
    .unwrap();
    assert_eq!(
        untouched, 33,
        "failed backfill must not consume leases or attempts"
    );
    pg.drop_schema().await.unwrap();
}
