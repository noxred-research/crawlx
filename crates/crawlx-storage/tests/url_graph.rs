//! URL graph persistence, exact fencing, explicit invalidation and restart contracts.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::RetentionMode;
use crawlx_core::custody::CustodyLease;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{OrchestrationConfigV1, ProducerModeV1, RequestBatchV1};
use crawlx_core::repo::{CrawlRun, FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::time::ManualClock;
use crawlx_core::url_graph::*;
use crawlx_core::{Clock, CrawlRunId, TenantId, Timestamp, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{BufferLimits, DeliveryBuffer, MemoryStore, Pg, PgConfig};
use std::sync::Arc;

fn fixed() -> Timestamp {
    "2026-11-11T00:00:00Z".parse().unwrap()
}
fn tenant(value: u128) -> TenantId {
    TenantId(uuid::Uuid::from_u128(value))
}
fn node(value: u8) -> UrlHandleV1 {
    UrlHandleV1(Digest([value; 32]))
}
fn policy() -> UrlGraphPolicyV1 {
    UrlGraphPolicyV1::new(Digest([4; 32]), Digest([5; 32]), 2, 8500)
}
fn batch() -> UrlGraphBatchV1 {
    UrlGraphBatchV1::new(
        node(1),
        vec![UrlGraphEdgeV1::new(node(1), node(2), Some(Digest([9; 32])), 3)],
    )
    .unwrap()
}

async fn fixture<R: RunRepo + FrontierRepo>(
    repo: &R,
    tenant: TenantId,
    now: Timestamp,
    zdr: bool,
) -> (CrawlRun, CustodyLease) {
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.mode = if zdr {
        RetentionMode::Zdr
    } else {
        RetentionMode::Standard
    };
    config.retention.days = if zdr { 0 } else { 2 };
    let mut orchestration = OrchestrationConfigV1::default();
    orchestration.queue.producer_mode = ProducerModeV1::Continuous;
    config.orchestration = Some(orchestration);
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    repo.create(&run, None).await.unwrap();
    repo.append_batch(RequestBatchV1::new(
        tenant,
        run.id,
        "anonymous".into(),
        Digest([7; 32]),
        vec![RequestEnvelopeV1::get(
            canonical_url("https://fixture.test/"),
            0,
            None,
        )],
    ))
    .await
    .unwrap();
    let worker = WorkerId(uuid::Uuid::from_u128(33));
    let (entry, fence) = repo
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let lease = CustodyLease::for_url(tenant, run.id, entry.id, worker, fence);
    (run, lease)
}

async fn contract<R: UrlGraphRepo + FrontierRepo>(repo: &R, lease: &CustodyLease) {
    let policy = policy();
    repo.configure(lease, &policy).await.unwrap();
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Invalidated
    );
    let revision = repo.replace_source(lease, &batch(), &policy).await.unwrap();
    assert_eq!(revision, 1);
    assert_eq!(
        repo.replace_source(lease, &batch(), &policy).await.unwrap(),
        revision
    );
    let graph = repo.snapshot(lease.tenant, lease.run).await.unwrap();
    assert_eq!(graph.nodes, [node(1), node(2)]);
    assert_eq!(graph.edges, batch().edges);
    let ranks = graph.rank().unwrap();
    repo.store_ranks(lease, &ranks).await.unwrap();
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Current(ranks.clone())
    );
    repo.configure(lease, &policy).await.unwrap();
    assert!(matches!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Current(_)
    ));
    let mut model_changed = policy.clone();
    model_changed.model = Digest([6; 32]);
    repo.configure(lease, &model_changed).await.unwrap();
    assert!(repo.replace_source(lease, &batch(), &policy).await.is_err());
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Invalidated
    );
    assert!(repo.store_ranks(lease, &ranks).await.is_err());
    let current = repo
        .snapshot(lease.tenant, lease.run)
        .await
        .unwrap()
        .rank()
        .unwrap();
    repo.store_ranks(lease, &current).await.unwrap();
    let mut policy_changed = model_changed.clone();
    policy_changed.policy = Digest([8; 32]);
    repo.configure(lease, &policy_changed).await.unwrap();
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Invalidated
    );
    let current = repo
        .snapshot(lease.tenant, lease.run)
        .await
        .unwrap()
        .rank()
        .unwrap();
    repo.store_ranks(lease, &current).await.unwrap();
    repo.replace_source(
        lease,
        &UrlGraphBatchV1::new(node(1), vec![]).unwrap(),
        &policy_changed,
    )
    .await
    .unwrap();
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Invalidated
    );
    assert!(repo.store_ranks(lease, &current).await.is_err());
    let before = repo.snapshot(lease.tenant, lease.run).await.unwrap();
    let mut stale = lease.clone();
    stale.fence = stale.fence.checked_add(1).unwrap();
    assert!(repo
        .replace_source(&stale, &batch(), &policy_changed)
        .await
        .is_err());
    assert!(repo.configure(&stale, &policy).await.is_err());
    let mut foreign = lease.clone();
    foreign.tenant = tenant(999);
    assert!(repo.configure(&foreign, &policy).await.is_err());
    assert!(repo
        .replace_source(&foreign, &batch(), &policy_changed)
        .await
        .is_err());
    assert!(repo.snapshot(foreign.tenant, lease.run).await.is_err());
    assert!(repo.ranks(foreign.tenant, lease.run).await.is_err());
    assert_eq!(repo.snapshot(lease.tenant, lease.run).await.unwrap(), before);
}

#[tokio::test]
async fn memory_graph_reuses_actual_lease_authority_and_invalidates_exactly() {
    let clock = Arc::new(ManualClock::new(fixed()));
    let store = MemoryStore::with_clock(clock.clone());
    let (_, lease) = fixture(&store, tenant(1), clock.now(), false).await;
    contract(&store, &lease).await;
    store
        .complete_fenced(
            match lease.source {
                crawlx_core::custody::CustodySource::Url(id) => id,
                _ => unreachable!(),
            },
            lease.fence,
            FrontierStatus::Succeeded,
            None,
        )
        .await
        .unwrap();
    assert!(store.replace_source(&lease, &batch(), &policy()).await.is_err());
    assert!(store.configure(&lease, &policy()).await.is_err());
}

#[tokio::test]
async fn memory_retention_is_fixed_and_zdr_never_creates_graph() {
    let clock = Arc::new(ManualClock::new(fixed()));
    let store = MemoryStore::with_clock(clock.clone());
    let (_, lease) = fixture(&store, tenant(1), clock.now(), false).await;
    store.configure(&lease, &policy()).await.unwrap();
    store.replace_source(&lease, &batch(), &policy()).await.unwrap();
    clock.advance_ms(2 * 24 * 60 * 60 * 1000);
    assert!(store.snapshot(lease.tenant, lease.run).await.is_err());
    assert!(store.ranks(lease.tenant, lease.run).await.is_err());
    assert!(store.configure(&lease, &policy()).await.is_err());
    assert_eq!(store.purge_expired_url_graph().await.unwrap(), 1);
    assert_eq!(store.purge_expired_url_graph().await.unwrap(), 0);
    assert!(store.snapshot(lease.tenant, lease.run).await.is_err());
    let (_, zdr) = fixture(&store, tenant(2), clock.now(), true).await;
    assert!(store.configure(&zdr, &policy()).await.is_err());
    assert!(store.snapshot(zdr.tenant, zdr.run).await.is_err());
}

#[tokio::test]
async fn memory_cancelled_producer_cannot_change_graph_or_rank() {
    let store = MemoryStore::with_clock(Arc::new(ManualClock::new(fixed())));
    let (_, lease) = fixture(&store, tenant(1), fixed(), false).await;
    store.configure(&lease, &policy()).await.unwrap();
    let ranks = store
        .snapshot(lease.tenant, lease.run)
        .await
        .unwrap()
        .rank()
        .unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    let cancelled = lease.clone().with_cancellation(token);
    assert!(store
        .replace_source(&cancelled, &batch(), &policy())
        .await
        .is_err());
    assert!(store.store_ranks(&cancelled, &ranks).await.is_err());
}

#[tokio::test]
async fn postgres_graph_restart_preserves_edges_ranks_and_tenant_isolation() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let config = PgConfig {
        schema: Some(format!("url_graph_{}", CrawlRunId::new().0.simple())),
        ..PgConfig::default()
    };
    // ZDR fixture runs keep their configuration only in the volatile delivery buffer.
    let buffer = Arc::new(DeliveryBuffer::new(
        Arc::new(crawlx_core::SystemClock),
        BufferLimits::default(),
    ));
    let pg = Pg::connect(&url, config.clone())
        .await
        .unwrap()
        .with_delivery_buffer(buffer);
    pg.migrate().await.unwrap();
    pg.ensure_tenant(tenant(1), "graph-fixture").await.unwrap();
    pg.ensure_tenant(tenant(2), "graph-fixture").await.unwrap();
    let (_, lease) = fixture(&pg, tenant(1), chrono::Utc::now(), false).await;
    contract(&pg, &lease).await;
    let current_policy = pg.snapshot(lease.tenant, lease.run).await.unwrap().policy;
    pg.replace_source(&lease, &batch(), &current_policy)
        .await
        .unwrap();
    let graph = pg.snapshot(lease.tenant, lease.run).await.unwrap();
    let ranks = graph.rank().unwrap();
    pg.store_ranks(&lease, &ranks).await.unwrap();
    let restarted = Pg::connect_existing(&url, config).await.unwrap();
    assert_eq!(restarted.snapshot(lease.tenant, lease.run).await.unwrap(), graph);
    assert_eq!(
        restarted.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Current(ranks)
    );
    assert!(restarted.snapshot(tenant(2), lease.run).await.is_err());
    let bytes: String = sqlx::query_scalar("SELECT policy::text FROM url_graph_runs WHERE run_id=$1")
        .bind(lease.run.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert!(!bytes.contains("fixture.test"));
    assert!(!bytes.contains("anchor-text"));
    let (_, zdr) = fixture(&pg, tenant(2), chrono::Utc::now(), true).await;
    assert!(pg.configure(&zdr, &policy()).await.is_err());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM url_graph_runs WHERE run_id=$1")
        .bind(zdr.run.0)
        .fetch_one(pg.pool())
        .await
        .unwrap();
    assert_eq!(count, 0);
    let expired: Timestamp = "2000-01-01T00:00:00Z".parse().unwrap();
    sqlx::query("UPDATE url_graph_runs SET expires_at=$2 WHERE run_id=$1")
        .bind(lease.run.0)
        .bind(expired)
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(restarted.snapshot(lease.tenant, lease.run).await.is_err());
    assert_eq!(pg.purge_expired_url_graph().await.unwrap(), 1);
    assert_eq!(pg.purge_expired_url_graph().await.unwrap(), 0);
    let children: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM url_graph_nodes WHERE run_id=$1) + \
         (SELECT count(*) FROM url_graph_edges WHERE run_id=$1) + \
         (SELECT count(*) FROM url_graph_ranks WHERE run_id=$1)",
    )
    .bind(lease.run.0)
    .fetch_one(pg.pool())
    .await
    .unwrap();
    assert_eq!(children, 0);
    pg.drop_schema().await.unwrap();
}
