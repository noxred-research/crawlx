//! Offline checkpoint compilation through the existing transactional frontier.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{OrchestrationConfigV1, ProducerModeV1};
use crawlx_core::repo::{FrontierRepo, FrontierStatus, RunRepo};
use crawlx_core::request::import::{decode_checkpoint_export, ImportAdmissionV1, SOURCE_PINS};
use crawlx_core::{CrawlRunId, TenantId, WorkerId};
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::{MemoryStore, Pg, StoreConfig};
use serde_json::json;

async fn checkpoint_contract<R: FrontierRepo + RunRepo>(repo: &R, reopened: &R, tenant: TenantId) {
    let mut config = create_crawl("https://fixture.test/", &[], 1);
    let mut policy = OrchestrationConfigV1::default();
    policy.queue.producer_mode = ProducerModeV1::Continuous;
    config.orchestration = Some(policy);
    let run = crawl_run(tenant, config);
    repo.create(&run, None).await.unwrap();
    let pin = SOURCE_PINS[2];
    let mut source = json!({
        "version":1,"source":"fixture","producerEpoch":1,
        "expectedCursor":null,"endPosition":1,
        "export":{"version":1,"source":{"dialect":pin.0,"release":pin.1,"commit":pin.2},
            "requests":[
                {"url":"https://fixture.test/a?resource=1","sourceKey":"private-checkpoint-one"},
                {"url":"https://fixture.test/b?resource=2","sourceKey":"private-checkpoint-two","method":"HEAD"}
            ]}
    });
    let authority = |name: &str| {
        ImportAdmissionV1::new(
            tenant,
            run.id,
            "anonymous".into(),
            Digest::keyed(&[7; 32], "test/checkpoint-batch", name.as_bytes()),
            1,
        )
    };
    let decode = |value: &serde_json::Value,
                  name: &str,
                  current: Option<&crawlx_core::orchestration::LoaderCursorV1>| {
        decode_checkpoint_export(
            &serde_json::to_vec(value).unwrap(),
            &[7; 32],
            authority(name),
            current,
            |url| Ok(canonical_url(url.as_str())),
        )
        .unwrap()
    };
    let first = decode(&source, "first", None);
    let receipt = repo.append_batch(first.clone()).await.unwrap();
    assert_eq!(receipt.inserted.len(), 1);
    // A fresh caller reconstructs only persisted cursor authority after restart.
    let repo = reopened;
    let current = repo.loader_cursor(run.id, "fixture").await.unwrap().unwrap();
    assert_eq!(current.position, 1);
    let retry = decode(&source, "first", Some(&current));
    assert_eq!(retry, first);
    assert_eq!(repo.append_batch(retry).await.unwrap(), receipt);
    let stale_identity = decode(&source, "different-retry", Some(&current));
    assert!(repo.append_batch(stale_identity).await.is_err());
    assert_eq!(repo.metadata_page(run.id, 0, 10).await.unwrap().len(), 1);
    let mut foreign = first.clone();
    foreign.tenant = TenantId::new();
    assert!(repo.append_batch(foreign).await.is_err());
    source["expectedCursor"] = serde_json::to_value(&current).unwrap();
    source["endPosition"] = json!(2);
    let second = decode(&source, "second", Some(&current));
    assert_eq!(second.requests.len(), 1);
    assert_eq!(second.requests[0].method, "HEAD");
    assert_eq!(second.requests[0].url.url.query(), Some("resource=2"));
    let mut stale_epoch = second.clone();
    stale_epoch.producer_epoch = 2;
    assert!(repo.append_batch(stale_epoch).await.is_err());
    assert_eq!(
        repo.loader_cursor(run.id, "fixture").await.unwrap(),
        Some(current.clone())
    );
    repo.append_batch(second).await.unwrap();
    let queued = repo.lease_batch_fenced(run.id, WorkerId::new(), 2).await.unwrap();
    assert_eq!(queued.len(), 2);
    assert!(repo
        .complete_fenced(queued[0].0.id, queued[0].1 + 1, FrontierStatus::Succeeded, None)
        .await
        .is_err());
    repo.complete_fenced(queued[0].0.id, queued[0].1, FrontierStatus::Succeeded, None)
        .await
        .unwrap();
    assert_eq!(
        repo.loader_cursor(run.id, "fixture")
            .await
            .unwrap()
            .unwrap()
            .position,
        2
    );
    let stored = serde_json::to_string(&repo.metadata_page(run.id, 0, 10).await.unwrap()).unwrap();
    assert!(!stored.contains("private-checkpoint"));
}

#[tokio::test]
async fn memory_checkpoint_restart_epoch_and_cursor_are_fenced() {
    let store = MemoryStore::new();
    checkpoint_contract(&store, &store, TenantId::new()).await;
}

#[tokio::test]
async fn postgres_checkpoint_restart_epoch_and_cursor_are_fenced() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let schema = format!("checkpoint_{}", CrawlRunId::new().0.simple());
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(schema.clone()),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "checkpoint-tests").await.unwrap();
    let reopened = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(schema),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    checkpoint_contract(&pg, &reopened, tenant).await;
    pg.drop_schema().await.unwrap();
}
