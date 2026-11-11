//! URL graph producer projects admitted links without retaining URL or anchor bytes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::custody::CustodyLease;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{OrchestrationConfigV1, ProducerModeV1, RequestBatchV1};
use crawlx_core::repo::{FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::time::ManualClock;
use crawlx_core::url_graph::{UrlGraphPolicyV1, UrlGraphRankStateV1, UrlGraphRepo, MAX_URL_GRAPH_BATCH};
use crawlx_core::{TenantId, Timestamp, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::MemoryStore;
use crawlx_worker::url_graph::{UrlGraphLink, UrlGraphProducer};
use std::sync::Arc;

async fn fixture() -> (Arc<MemoryStore>, CustodyLease) {
    let now: Timestamp = "2026-11-11T00:00:00Z".parse().unwrap();
    let store = Arc::new(MemoryStore::with_clock(Arc::new(ManualClock::new(now))));
    let tenant = TenantId(uuid::Uuid::from_u128(1));
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    config.retention.days = 2;
    let mut queue = OrchestrationConfigV1::default();
    queue.queue.producer_mode = ProducerModeV1::Continuous;
    config.orchestration = Some(queue);
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    store.create(&run, None).await.unwrap();
    store
        .append_batch(RequestBatchV1::new(
            tenant,
            run.id,
            "anonymous".into(),
            Digest([1; 32]),
            vec![RequestEnvelopeV1::get(
                canonical_url("https://fixture.test/"),
                0,
                None,
            )],
        ))
        .await
        .unwrap();
    let worker = WorkerId(uuid::Uuid::from_u128(2));
    let (entry, fence) = store
        .lease_batch_fenced(run.id, worker, 1)
        .await
        .unwrap()
        .pop()
        .unwrap();
    (
        store,
        CustodyLease::for_url(tenant, run.id, entry.id, worker, fence),
    )
}
fn policy() -> UrlGraphPolicyV1 {
    UrlGraphPolicyV1::new(Digest([2; 32]), Digest([3; 32]), 4, 8500)
}

#[tokio::test]
async fn admitted_outlinks_hash_before_storage_and_restart_keeps_revision() {
    let (store, lease) = fixture().await;
    let repo: Arc<dyn UrlGraphRepo> = store.clone();
    let source = canonical_url("https://fixture.test/source?resource=private-canary");
    let target = canonical_url("https://fixture.test/target");
    let links = [UrlGraphLink::new(&target, Some("private-anchor-canary"), 2)];
    let producer = UrlGraphProducer::new(repo.clone(), &[7; 32]);
    assert_eq!(
        producer.record(&lease, &policy(), &source, &links).await.unwrap(),
        1
    );
    let ranks = producer.refresh_ranks(&lease).await.unwrap();
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Current(ranks)
    );
    let snapshot = repo.snapshot(lease.tenant, lease.run).await.unwrap();
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains("fixture.test"));
    assert!(!encoded.contains("private-canary"));
    assert!(!encoded.contains("private-anchor-canary"));
    let restarted = UrlGraphProducer::new(repo.clone(), &[7; 32]);
    assert_eq!(
        restarted
            .record(&lease, &policy(), &source, &links)
            .await
            .unwrap(),
        1
    );
    assert_eq!(repo.snapshot(lease.tenant, lease.run).await.unwrap(), snapshot);
    let mut changed = policy();
    changed.model = Digest([4; 32]);
    restarted.record(&lease, &changed, &source, &links).await.unwrap();
    assert_eq!(
        repo.ranks(lease.tenant, lease.run).await.unwrap(),
        UrlGraphRankStateV1::Invalidated
    );
}

#[tokio::test]
async fn oversized_invalid_and_settled_sources_do_not_publish() {
    let (store, lease) = fixture().await;
    let repo: Arc<dyn UrlGraphRepo> = store.clone();
    let producer = UrlGraphProducer::new(repo.clone(), &[7; 32]);
    let source = canonical_url("https://fixture.test/source");
    let target = canonical_url("https://fixture.test/target");
    let oversized: Vec<_> = (0..=MAX_URL_GRAPH_BATCH)
        .map(|_| UrlGraphLink::new(&target, None, 1))
        .collect();
    assert!(producer
        .record(&lease, &policy(), &source, &oversized)
        .await
        .is_err());
    assert!(repo.snapshot(lease.tenant, lease.run).await.is_err());
    assert!(producer
        .record(&lease, &policy(), &source, &[UrlGraphLink::new(&target, None, 0)])
        .await
        .is_err());
    assert!(repo.snapshot(lease.tenant, lease.run).await.is_err());
    producer.record(&lease, &policy(), &source, &[]).await.unwrap();
    let before = repo.snapshot(lease.tenant, lease.run).await.unwrap();
    let id = match lease.source {
        crawlx_core::custody::CustodySource::Url(id) => id,
        _ => unreachable!(),
    };
    store
        .complete_fenced(id, lease.fence, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    assert!(producer
        .record(&lease, &policy(), &source, &[UrlGraphLink::new(&target, None, 1)])
        .await
        .is_err());
    assert_eq!(repo.snapshot(lease.tenant, lease.run).await.unwrap(), before);
}
