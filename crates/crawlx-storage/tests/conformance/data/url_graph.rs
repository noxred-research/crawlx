//! Conformance cases (URL graph): persistence over the producer's custody lease, exact
//! fencing and invalidation, restart, retention, ZDR and tenant isolation.

use super::reports::{exec, on_zdr_db, on_zdr_repo, scalar_i64, scalar_text, tenant_of, Bind};
use crate::rig::Rig;
use crawlx_core::config::RetentionMode;
use crawlx_core::custody::{CustodyLease, CustodySource};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{OrchestrationConfigV1, ProducerModeV1, RequestBatchV1};
use crawlx_core::repo::{CrawlRun, FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::time::ManualClock;
use crawlx_core::url_graph::{
    UrlGraphBatchV1, UrlGraphEdgeV1, UrlGraphPolicyV1, UrlGraphRankStateV1, UrlGraphRepo, UrlGraphSnapshotV1,
    UrlHandleV1,
};
use crawlx_core::{Clock, StoreError, TenantId, Timestamp, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::MemoryStore;
use std::sync::Arc;

conformance! { all:
    graph_reuses_actual_lease_authority_and_invalidates_exactly,
    zdr_never_creates_a_graph,
    cancelled_producer_cannot_change_graph_or_rank,
}

conformance! { databases:
    restart_preserves_edges_ranks_and_tenant_isolation,
    retention_ends_expired_graphs_and_purge_erases_children,
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

fn request_of(lease: &CustodyLease) -> i64 {
    match lease.source {
        CustodySource::Url(id) => id,
        _ => unreachable!("url fixture"),
    }
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
    let worker = WorkerId::new();
    let (entry, fence) = repo
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    let lease = CustodyLease::for_url(tenant, run.id, entry.id, worker, fence);
    (run, lease)
}

async fn graph_reuses_actual_lease_authority_and_invalidates_exactly(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_repo!(rig, |repo| authority(repo, tenant).await);
}

async fn authority<R: UrlGraphRepo + FrontierRepo + RunRepo>(repo: &R, tenant: TenantId) {
    let (_, lease) = fixture(repo, tenant, chrono::Utc::now(), false).await;
    contract(repo, &lease).await;
    // The producer lease is the only write authority: once its request completes, the fence
    // no longer holds.
    repo.complete_fenced(request_of(&lease), lease.fence, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    assert!(repo.replace_source(&lease, &batch(), &policy()).await.is_err());
    assert!(repo.configure(&lease, &policy()).await.is_err());
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
    foreign.tenant = TenantId::new();
    assert!(repo.configure(&foreign, &policy).await.is_err());
    assert!(repo
        .replace_source(&foreign, &batch(), &policy_changed)
        .await
        .is_err());
    assert!(repo.snapshot(foreign.tenant, lease.run).await.is_err());
    assert!(repo.ranks(foreign.tenant, lease.run).await.is_err());
    assert_eq!(repo.snapshot(lease.tenant, lease.run).await.unwrap(), before);
}

async fn zdr_never_creates_a_graph(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_repo!(rig, |repo| zdr(repo, tenant).await);
}

async fn zdr<R: UrlGraphRepo + FrontierRepo + RunRepo>(repo: &R, tenant: TenantId) {
    let (_, lease) = fixture(repo, tenant, chrono::Utc::now(), true).await;
    assert!(repo.configure(&lease, &policy()).await.is_err());
    assert!(repo.replace_source(&lease, &batch(), &policy()).await.is_err());
    assert!(repo.snapshot(lease.tenant, lease.run).await.is_err());
    assert!(repo.ranks(lease.tenant, lease.run).await.is_err());
}

async fn cancelled_producer_cannot_change_graph_or_rank(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_repo!(rig, |repo| cancelled(repo, tenant).await);
}

async fn cancelled<R: UrlGraphRepo + FrontierRepo + RunRepo>(repo: &R, tenant: TenantId) {
    let (_, lease) = fixture(repo, tenant, chrono::Utc::now(), false).await;
    repo.configure(&lease, &policy()).await.unwrap();
    let ranks = repo
        .snapshot(lease.tenant, lease.run)
        .await
        .unwrap()
        .rank()
        .unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    let cancelled = lease.clone().with_cancellation(token);
    assert!(repo
        .replace_source(&cancelled, &batch(), &policy())
        .await
        .is_err());
    assert!(repo.store_ranks(&cancelled, &ranks).await.is_err());
    // Nothing the cancelled producer attempted is visible afterwards.
    let graph = repo.snapshot(lease.tenant, lease.run).await.unwrap();
    assert!(graph.nodes.is_empty() && graph.edges.is_empty());
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Invalidated
    );
}

async fn restart_preserves_edges_ranks_and_tenant_isolation(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    let other = tenant_of(rig).await;
    let (lease, graph, ranks) = on_zdr_db!(rig, |repo| written(rig, repo, tenant, other).await);
    on_zdr_db!(rig, |repo| read_back(repo, &lease, &graph, &ranks, other).await);
    let database = super::reports::reopen(rig).await;
    super::reports::on_database!(database, |repo| read_back(repo, &lease, &graph, &ranks, other)
        .await);
    database.close().await;
}

async fn written<R: UrlGraphRepo + FrontierRepo + RunRepo>(
    rig: &Rig,
    repo: &R,
    tenant: TenantId,
    other: TenantId,
) -> (
    CustodyLease,
    UrlGraphSnapshotV1,
    crawlx_core::url_graph::UrlGraphRanksV1,
) {
    let (_, lease) = fixture(repo, tenant, chrono::Utc::now(), false).await;
    contract(repo, &lease).await;
    let current_policy = repo.snapshot(lease.tenant, lease.run).await.unwrap().policy;
    repo.replace_source(&lease, &batch(), &current_policy)
        .await
        .unwrap();
    let graph = repo.snapshot(lease.tenant, lease.run).await.unwrap();
    let ranks = graph.rank().unwrap();
    repo.store_ranks(&lease, &ranks).await.unwrap();
    // Opaque handles only: no URL, no anchor text reaches the stored policy.
    let stored = scalar_text(
        rig,
        "SELECT policy::text FROM url_graph_runs WHERE run_id=$1",
        &[Bind::Uuid(lease.run.0)],
    )
    .await;
    assert!(!stored.contains("fixture.test"));
    assert!(!stored.contains("anchor-text"));
    // A ZDR run of another tenant never creates a graph row.
    let (_, zdr) = fixture(repo, other, chrono::Utc::now(), true).await;
    assert!(repo.configure(&zdr, &policy()).await.is_err());
    assert_eq!(
        scalar_i64(
            rig,
            "SELECT count(*) FROM url_graph_runs WHERE run_id=$1",
            &[Bind::Uuid(zdr.run.0)]
        )
        .await,
        0
    );
    (lease, graph, ranks)
}

async fn read_back<R: UrlGraphRepo>(
    repo: &R,
    lease: &CustodyLease,
    graph: &UrlGraphSnapshotV1,
    ranks: &crawlx_core::url_graph::UrlGraphRanksV1,
    other: TenantId,
) {
    assert_eq!(&repo.snapshot(lease.tenant, lease.run).await.unwrap(), graph);
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Current(ranks.clone())
    );
    assert!(repo.snapshot(other, lease.run).await.is_err());
    assert!(repo.ranks(other, lease.run).await.is_err());
}

async fn retention_ends_expired_graphs_and_purge_erases_children(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_zdr_db!(rig, |repo| retention(rig, repo, tenant).await);
}

async fn retention<R: UrlGraphRepo + FrontierRepo + RunRepo + Purge>(rig: &Rig, repo: &R, tenant: TenantId) {
    let (_, lease) = fixture(repo, tenant, chrono::Utc::now(), false).await;
    repo.configure(&lease, &policy()).await.unwrap();
    repo.replace_source(&lease, &batch(), &policy()).await.unwrap();
    let ranks = repo
        .snapshot(lease.tenant, lease.run)
        .await
        .unwrap()
        .rank()
        .unwrap();
    repo.store_ranks(&lease, &ranks).await.unwrap();
    // Not due yet.
    assert_eq!(repo.purge_expired_url_graph().await.unwrap(), 0);
    let run = [Bind::Uuid(lease.run.0)];
    for table in ["url_graph_nodes", "url_graph_edges", "url_graph_ranks"] {
        assert!(
            scalar_i64(
                rig,
                &format!("SELECT count(*) FROM {table} WHERE run_id=$1"),
                &run
            )
            .await
                > 0,
            "{table}"
        );
    }
    let expired = chrono::Utc::now() - chrono::Duration::days(1);
    exec(
        rig,
        "UPDATE url_graph_runs SET expires_at=$1 WHERE run_id=$2",
        &[Bind::Ts(expired), Bind::Uuid(lease.run.0)],
    )
    .await;
    assert!(repo.snapshot(lease.tenant, lease.run).await.is_err());
    assert!(repo.ranks(lease.tenant, lease.run).await.is_err());
    assert!(repo.configure(&lease, &policy()).await.is_err());
    assert_eq!(repo.purge_expired_url_graph().await.unwrap(), 1);
    assert_eq!(repo.purge_expired_url_graph().await.unwrap(), 0);
    assert!(repo.snapshot(lease.tenant, lease.run).await.is_err());
    for table in [
        "url_graph_runs",
        "url_graph_nodes",
        "url_graph_edges",
        "url_graph_ranks",
    ] {
        assert_eq!(
            scalar_i64(
                rig,
                &format!("SELECT count(*) FROM {table} WHERE run_id=$1"),
                &run
            )
            .await,
            0,
            "{table}"
        );
    }
}

/// The retention sweep of URL graphs, an inherent method of each database store.
trait Purge {
    async fn purge_expired_url_graph(&self) -> Result<u64, StoreError>;
}

macro_rules! impl_purge {
    ($($store:ty),+) => {$(
        impl Purge for $store {
            async fn purge_expired_url_graph(&self) -> Result<u64, StoreError> {
                <$store>::purge_expired_url_graph(self).await
            }
        }
    )+};
}
impl_purge!(
    crawlx_storage::Store<crawlx_storage::backend::SqliteBackend>,
    crawlx_storage::Store<crawlx_storage::backend::MariaBackend>,
    crawlx_storage::Pg
);

/// The memory specification keeps its clock-driven checks: retention is fixed by the run's
/// creation, never moved by a later read or write.
#[tokio::test]
async fn memory_retention_is_fixed_and_expired_graphs_are_purged() {
    let clock = Arc::new(ManualClock::new("2026-11-11T00:00:00Z".parse().unwrap()));
    let store = MemoryStore::with_clock(clock.clone());
    let tenant = TenantId(uuid::Uuid::from_u128(1));
    let (_, lease) = fixture(&store, tenant, clock.now(), false).await;
    store.configure(&lease, &policy()).await.unwrap();
    store.replace_source(&lease, &batch(), &policy()).await.unwrap();
    clock.advance_ms(2 * 24 * 60 * 60 * 1000);
    assert!(store.snapshot(lease.tenant, lease.run).await.is_err());
    assert!(store.ranks(lease.tenant, lease.run).await.is_err());
    assert!(store.configure(&lease, &policy()).await.is_err());
    assert_eq!(store.purge_expired_url_graph().await.unwrap(), 1);
    assert_eq!(store.purge_expired_url_graph().await.unwrap(), 0);
    assert!(store.snapshot(lease.tenant, lease.run).await.is_err());
}
