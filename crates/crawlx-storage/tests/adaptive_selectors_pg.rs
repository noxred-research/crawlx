//! Real PostgreSQL selector scope, retention and ZDR durable-payload regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::cache::{AdaptiveSelectorRecordV1, AdaptiveSelectorRepo};
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::RunRepo;
use crawlx_core::selectors::{AdaptiveSelectorSpecV1, SelectorScopeV1, StructuralDescriptorV1};
use crawlx_core::time::ManualClock;
use crawlx_core::TenantId;
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{BufferLimits, DeliveryBuffer, Pg, PgConfig};
use std::sync::Arc;

#[tokio::test]
async fn pg_descriptor_scope_retention_and_zdr_payload_gate_use_real_rows() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(format!("selectors_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    let foreign = TenantId::new();
    pg.ensure_tenant(tenant, "selector-owner").await.unwrap();
    pg.ensure_tenant(foreign, "selector-other").await.unwrap();
    let now = chrono::Utc::now();
    let buffer = Arc::new(DeliveryBuffer::new(
        Arc::new(ManualClock::new(now)),
        BufferLimits::default(),
    ));
    let pg = pg.with_delivery_buffer(buffer.clone());
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    pg.create(&run, None).await.unwrap();
    let scope = SelectorScopeV1::new(
        tenant.to_string(),
        "principal-a".into(),
        "https://example.test".into(),
        "news".into(),
        "article/v1".into(),
    );
    let spec = AdaptiveSelectorSpecV1::new(
        "body".into(),
        scope.clone(),
        StructuralDescriptorV1::new(
            "p".into(),
            Some("article".into()),
            None,
            vec!["zdr-descriptor-canary".into()],
            0,
        ),
    );
    let record = AdaptiveSelectorRecordV1::new(run.id, spec, now + chrono::Duration::minutes(10));
    crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::put(&pg, &record))
        .await
        .unwrap();
    let found = crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::get(&pg, &scope, "body", now))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.spec, record.spec);
    let durable: (Option<serde_json::Value>, Option<i64>) =
        sqlx::query_as("SELECT payload,volatile_page FROM adaptive_selectors WHERE run_id=$1")
            .bind(run.id.0)
            .fetch_one(pg.pool())
            .await
            .unwrap();
    assert!(
        durable.0.is_none(),
        "ZDR descriptor canary must not enter durable JSON"
    );
    assert!(durable.1.is_some_and(|page| page < 0));
    assert!(buffer.bytes().await.unwrap() > 0);
    let mut other = scope.clone();
    other.principal = "principal-b".into();
    assert!(
        crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::get(&pg, &other, "body", now))
            .await
            .unwrap()
            .is_none()
    );
    other = scope.clone();
    other.tenant = foreign.to_string();
    assert!(
        crawlx_storage::tenant::scope(foreign, AdaptiveSelectorRepo::get(&pg, &other, "body", now))
            .await
            .unwrap()
            .is_none()
    );
    let denied = sqlx::query("UPDATE adaptive_selectors SET payload=$1,volatile_page=NULL WHERE run_id=$2")
        .bind(serde_json::to_value(&record).unwrap())
        .bind(run.id.0)
        .execute(pg.pool())
        .await;
    assert!(
        denied.is_err(),
        "database trigger must reject direct-SQL ZDR descriptor payloads"
    );
    let mut invalid = record.clone();
    invalid.expires_at = now + chrono::Duration::hours(2);
    assert!(
        crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::put(&pg, &invalid))
            .await
            .is_err()
    );
    pg.drop_schema().await.unwrap();
}
