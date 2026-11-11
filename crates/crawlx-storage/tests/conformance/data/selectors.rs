//! Conformance cases (selectors): descriptor scope, fixed retention, the ZDR payload gate,
//! replacement keeping the earlier expiry, the expiry sweep and run deletion.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::rig::Rig;
use chrono::Duration;
use crawlx_core::cache::{AdaptiveSelectorRecordV1, AdaptiveSelectorRepo};
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::RunRepo;
use crawlx_core::selectors::{AdaptiveSelectorSpecV1, SelectorScopeV1, StructuralDescriptorV1};
use crawlx_core::time::ManualClock;
use crawlx_core::{StoreError, TenantId, Timestamp};
use crawlx_storage::testkit::{crawl_run, create_crawl, Engine};
use crawlx_storage::{BufferLimits, DeliveryBuffer};
use std::sync::Arc;

conformance! { all:
    descriptor_scope_retention_and_zdr_payload_gate_use_real_rows,
    replacement_keeps_the_earlier_expiry,
    sweep_deletes_only_expired_descriptors,
    delete_run_removes_its_descriptors,
}

/// Run `$body` with `$repo` bound to the engine's repository, a delivery buffer attached.
macro_rules! with_buffer {
    ($rig:expr, $buffer:expr, |$repo:ident| $body:expr) => {{
        match $rig.engine() {
            Engine::Memory => {
                let $repo = $rig.store().as_ref();
                $repo.set_dataset_delivery($buffer.clone());
                $body
            }
            Engine::Sqlite => {
                let owned = $rig
                    .database()
                    .sqlite_store()
                    .expect("a sqlite rig has a store")
                    .clone()
                    .with_delivery_buffer($buffer.clone());
                let $repo = &owned;
                $body
            }
            Engine::MariaDb => {
                let owned = $rig
                    .database()
                    .mariadb_store()
                    .expect("a mariadb rig has a store")
                    .clone()
                    .with_delivery_buffer($buffer.clone());
                let $repo = &owned;
                $body
            }
            Engine::Postgres => {
                let owned = $rig
                    .database()
                    .postgres()
                    .expect("a postgres rig has a store")
                    .clone()
                    .with_delivery_buffer($buffer.clone());
                let $repo = &owned;
                $body
            }
            _ => panic!("every engine of the suite is handled above"),
        }
    }};
}

fn scope_of(tenant: TenantId) -> SelectorScopeV1 {
    SelectorScopeV1::new(
        tenant.to_string(),
        "principal-a".into(),
        "https://example.test".into(),
        "news".into(),
        "article/v1".into(),
    )
}

fn spec(scope: SelectorScopeV1, canary: &str) -> AdaptiveSelectorSpecV1 {
    AdaptiveSelectorSpecV1::new(
        "body".into(),
        scope,
        StructuralDescriptorV1::new("p".into(), Some("article".into()), None, vec![canary.into()], 0),
    )
}

async fn tenant_of(rig: &Rig) -> TenantId {
    let tenant = TenantId::new();
    if rig.engine() != Engine::Memory {
        rig.migrate().await;
        rig.insert_tenant(tenant.0).await.unwrap();
    }
    tenant
}

fn buffer(now: Timestamp) -> Arc<DeliveryBuffer> {
    Arc::new(DeliveryBuffer::new(
        Arc::new(ManualClock::new(now)),
        BufferLimits::default(),
    ))
}

/// A retained run created now.
async fn retained_run<R: RunRepo>(repo: &R, tenant: TenantId, now: Timestamp) -> crawlx_core::repo::CrawlRun {
    let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
    run.created_at = now;
    repo.create(&run, None).await.unwrap();
    run
}

/// Raw view of the durable selector row of `run`: whether its payload is empty and its
/// volatile page.
async fn durable_row(rig: &Rig, run: uuid::Uuid) -> (bool, Option<i64>) {
    use sqlx::Row as _;
    let database = rig.database();
    match rig.engine() {
        Engine::Sqlite => {
            let row = sqlx::query(
                "SELECT payload IS NULL AS empty, volatile_page FROM adaptive_selectors WHERE run_id=?1",
            )
            .bind(run)
            .fetch_one(database.sqlite_pool().unwrap())
            .await
            .unwrap();
            (row.get::<i64, _>("empty") != 0, row.get("volatile_page"))
        }
        Engine::MariaDb => {
            let row = sqlx::query(
                "SELECT payload IS NULL AS empty, volatile_page FROM adaptive_selectors WHERE run_id=?",
            )
            .bind(run)
            .fetch_one(database.mariadb_pool().unwrap())
            .await
            .unwrap();
            (row.get::<i64, _>("empty") != 0, row.get("volatile_page"))
        }
        _ => {
            let row = sqlx::query(
                "SELECT payload IS NULL AS empty, volatile_page FROM adaptive_selectors WHERE run_id=$1",
            )
            .bind(run)
            .fetch_one(database.postgres().unwrap().pool())
            .await
            .unwrap();
            (row.get::<bool, _>("empty"), row.get("volatile_page"))
        }
    }
}

/// Direct SQL that would put descriptor content into a ZDR row; the database must refuse it.
async fn direct_payload_write_is_refused(
    rig: &Rig,
    run: uuid::Uuid,
    record: &AdaptiveSelectorRecordV1,
) -> bool {
    let database = rig.database();
    let text = serde_json::to_string(record).unwrap();
    match rig.engine() {
        Engine::Sqlite => {
            sqlx::query("UPDATE adaptive_selectors SET payload=?1,volatile_page=NULL WHERE run_id=?2")
                .bind(text)
                .bind(run)
                .execute(database.sqlite_pool().unwrap())
                .await
                .is_err()
        }
        Engine::MariaDb => {
            sqlx::query("UPDATE adaptive_selectors SET payload=?,volatile_page=NULL WHERE run_id=?")
                .bind(text)
                .bind(run)
                .execute(database.mariadb_pool().unwrap())
                .await
                .is_err()
        }
        _ => sqlx::query("UPDATE adaptive_selectors SET payload=$1,volatile_page=NULL WHERE run_id=$2")
            .bind(serde_json::to_value(record).unwrap())
            .bind(run)
            .execute(database.postgres().unwrap().pool())
            .await
            .is_err(),
    }
}

async fn descriptor_scope_retention_and_zdr_payload_gate_use_real_rows(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    let foreign = TenantId::new();
    if rig.engine() != Engine::Memory {
        rig.insert_tenant(foreign.0).await.unwrap();
    }
    let now = Timestamp::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let buffer = buffer(now);
    with_buffer!(rig, buffer, |repo| zdr_contract(
        rig, repo, &buffer, tenant, foreign, now
    )
    .await);
}

async fn zdr_contract<R: RunRepo + AdaptiveSelectorRepo>(
    rig: &Rig,
    repo: &R,
    buffer: &DeliveryBuffer,
    tenant: TenantId,
    foreign: TenantId,
    now: Timestamp,
) {
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Zdr;
    config.retention.days = 0;
    let mut run = crawl_run(tenant, config);
    run.created_at = now;
    repo.create(&run, None).await.unwrap();
    let scope = scope_of(tenant);
    let record = AdaptiveSelectorRecordV1::new(
        run.id,
        spec(scope.clone(), "zdr-descriptor-canary"),
        now + Duration::minutes(10),
    );
    crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::put(repo, &record))
        .await
        .unwrap();
    let found = crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::get(repo, &scope, "body", now))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.spec, record.spec);
    assert!(buffer.bytes().await.unwrap() > 0);
    if rig.engine() != Engine::Memory {
        let (empty, page) = durable_row(rig, run.id.0).await;
        assert!(empty, "ZDR descriptor canary must not enter durable JSON");
        assert!(page.is_some_and(|page| page < 0));
    }
    let mut other = scope.clone();
    other.principal = "principal-b".into();
    assert!(
        crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::get(repo, &other, "body", now))
            .await
            .unwrap()
            .is_none()
    );
    other = scope.clone();
    other.tenant = foreign.to_string();
    assert!(
        crawlx_storage::tenant::scope(foreign, AdaptiveSelectorRepo::get(repo, &other, "body", now))
            .await
            .unwrap()
            .is_none()
    );
    if rig.engine() != Engine::Memory {
        assert!(
            direct_payload_write_is_refused(rig, run.id.0, &record).await,
            "the database must reject direct-SQL ZDR descriptor payloads"
        );
    }
    let mut invalid = record.clone();
    invalid.expires_at = now + Duration::hours(2);
    assert!(
        crawlx_storage::tenant::scope(tenant, AdaptiveSelectorRepo::put(repo, &invalid))
            .await
            .is_err()
    );
}

async fn replacement_keeps_the_earlier_expiry(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_repo!(rig, |repo| replacement_contract(repo, tenant).await);
}

async fn replacement_contract<R: RunRepo + AdaptiveSelectorRepo>(repo: &R, tenant: TenantId) {
    let now = Timestamp::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let run = retained_run(repo, tenant, now).await;
    let scope = scope_of(tenant);
    let first = AdaptiveSelectorRecordV1::new(run.id, spec(scope.clone(), "a"), now + Duration::minutes(10));
    AdaptiveSelectorRepo::put(repo, &first).await.unwrap();
    let mut later = first.clone();
    later.expires_at += Duration::minutes(5);
    AdaptiveSelectorRepo::put(repo, &later).await.unwrap();
    let stored = AdaptiveSelectorRepo::get(repo, &scope, "body", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.expires_at, first.expires_at,
        "a replacement never extends the expiry"
    );
    let mut sooner = first.clone();
    sooner.expires_at -= Duration::minutes(4);
    AdaptiveSelectorRepo::put(repo, &sooner).await.unwrap();
    let stored = AdaptiveSelectorRepo::get(repo, &scope, "body", now)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.expires_at, sooner.expires_at,
        "a shorter replacement shortens it"
    );
    // beyond the source run's retention
    let mut beyond = first.clone();
    beyond.expires_at = run.created_at + Duration::days(8);
    assert!(matches!(
        AdaptiveSelectorRepo::put(repo, &beyond).await,
        Err(StoreError::RetentionDenied(_))
    ));
    // another principal's scope and a missing source run
    let mut foreign = scope.clone();
    foreign.principal = "principal-b".into();
    assert!(AdaptiveSelectorRepo::get(repo, &foreign, "body", now)
        .await
        .unwrap()
        .is_none());
    let mut orphan = first.clone();
    orphan.run = crawlx_core::CrawlRunId::new();
    assert!(AdaptiveSelectorRepo::put(repo, &orphan).await.is_err());
}

async fn sweep_deletes_only_expired_descriptors(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_repo!(rig, |repo| sweep_contract(repo, tenant).await);
}

async fn sweep_contract<R: RunRepo + AdaptiveSelectorRepo>(repo: &R, tenant: TenantId) {
    let now = Timestamp::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let run = retained_run(repo, tenant, now).await;
    let scope = scope_of(tenant);
    let record = AdaptiveSelectorRecordV1::new(run.id, spec(scope.clone(), "a"), now + Duration::minutes(10));
    AdaptiveSelectorRepo::put(repo, &record).await.unwrap();
    assert_eq!(AdaptiveSelectorRepo::sweep(repo, now).await.unwrap(), 0);
    let later = now + Duration::minutes(11);
    // an expired descriptor is invisible before the sweep removes it
    assert!(AdaptiveSelectorRepo::get(repo, &scope, "body", later)
        .await
        .unwrap()
        .is_none());
    assert_eq!(AdaptiveSelectorRepo::sweep(repo, later).await.unwrap(), 1);
    assert!(AdaptiveSelectorRepo::get(repo, &scope, "body", now)
        .await
        .unwrap()
        .is_none());
    assert_eq!(AdaptiveSelectorRepo::sweep(repo, later).await.unwrap(), 0);
}

async fn delete_run_removes_its_descriptors(rig: &Rig) {
    let tenant = tenant_of(rig).await;
    on_repo!(rig, |repo| delete_run_contract(repo, tenant).await);
}

async fn delete_run_contract<R: RunRepo + AdaptiveSelectorRepo>(repo: &R, tenant: TenantId) {
    let now = Timestamp::from_timestamp_micros(chrono::Utc::now().timestamp_micros()).unwrap();
    let run = retained_run(repo, tenant, now).await;
    let kept = retained_run(repo, tenant, now).await;
    let scope = scope_of(tenant);
    let doomed = AdaptiveSelectorRecordV1::new(run.id, spec(scope.clone(), "a"), now + Duration::minutes(10));
    AdaptiveSelectorRepo::put(repo, &doomed).await.unwrap();
    let mut other_scope = scope.clone();
    other_scope.principal = "principal-b".into();
    let survivor = AdaptiveSelectorRecordV1::new(
        kept.id,
        spec(other_scope.clone(), "b"),
        now + Duration::minutes(10),
    );
    AdaptiveSelectorRepo::put(repo, &survivor).await.unwrap();
    AdaptiveSelectorRepo::delete_run(repo, run.id).await.unwrap();
    assert!(AdaptiveSelectorRepo::get(repo, &scope, "body", now)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        AdaptiveSelectorRepo::get(repo, &other_scope, "body", now)
            .await
            .unwrap()
            .unwrap()
            .spec,
        survivor.spec
    );
}
