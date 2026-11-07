//! Deployment/run origin capacity and real database-clock pacing.
//! Tests skip when `CRAWLX_TEST_DATABASE_URL` is absent; PostgreSQL 14+ is required.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::origin::OriginAdmission;
use crawlx_core::repo::RunRepo;
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{tenant, Pg, PgConfig, PgOriginAdmission};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const DEADLINE: Duration = Duration::from_secs(10);

struct Env {
    first: Pg,
    second: Pg,
    tenants: [TenantId; 2],
    origin: String,
}

async fn setup(connections: u32) -> Option<Env> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let schema = format!("t_{}", CrawlRunId::new().0.simple());
    let config = PgConfig {
        schema: Some(schema.clone()),
        max_connections: connections,
        ..PgConfig::default()
    };
    let first = Pg::connect(&url, config.clone())
        .await
        .expect("first database handle");
    first.migrate().await.expect("migrate");
    let second = Pg::connect(&url, config)
        .await
        .expect("second independent database handle");
    let tenants = [TenantId::new(), TenantId::new()];
    for tenant in tenants {
        first.ensure_tenant(tenant, "origin-test").await.expect("tenant");
    }
    Some(Env {
        first,
        second,
        tenants,
        origin: format!("https://{schema}.test"),
    })
}

fn slot_digest(origin: &str, ticket: i64) -> Digest {
    let origin = Digest::of("crawlx/origin-admission/origin/v1", origin.as_bytes());
    Digest::keyed(
        &origin.0,
        "crawlx/origin-admission/slot/v1",
        &ticket.to_be_bytes(),
    )
}

async fn waiters(pg: &Pg, origin: &str, ticket: i64, expected: i64) {
    let digest = slot_digest(origin, ticket);
    let high = i64::from(u32::from_be_bytes(digest.0[..4].try_into().unwrap()));
    let low = i64::from(u32::from_be_bytes(digest.0[4..8].try_into().unwrap()));
    timeout(DEADLINE, async {
        loop {
            let count: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' \
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database()) \
                 AND classid::bigint = $1 AND objid::bigint = $2 AND objsubid = 1 AND NOT granted",
            )
            .bind(high)
            .bind(low)
            .fetch_one(pg.pool())
            .await
            .expect("advisory waiters");
            if count == expected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("advisory waiter count reached");
}

async fn start(pg: &Pg, origin: &str) -> DateTime<Utc> {
    sqlx::query_scalar(
        "SELECT next_allowed_at - last_spacing_us * INTERVAL '1 microsecond' \
         FROM origin_admission WHERE origin = $1",
    )
    .bind(origin)
    .fetch_one(pg.pool())
    .await
    .expect("database admission start")
}

#[tokio::test]
async fn shared_feedback_coalesces_waves_and_start_checks_other_workers_cooldown() {
    let Some(env) = setup(4).await else { return };
    let first = PgOriginAdmission::new(env.first.clone(), 2);
    let second = PgOriginAdmission::new(env.second.clone(), 2);
    first.cooldown(&env.origin, Duration::ZERO, true).await.unwrap();
    second.cooldown(&env.origin, Duration::ZERO, true).await.unwrap();
    let backoff: i64 = sqlx::query_scalar("SELECT throttle_delay_us FROM origin_admission WHERE origin=$1")
        .bind(&env.origin)
        .fetch_one(env.first.pool())
        .await
        .unwrap();
    assert_eq!(backoff, 2_000_000, "concurrent wave doubles only once");
    // Expire the fixture's wave without sleeping two seconds. The next committed
    // feedback must double the persisted baseline, not a worker-local counter.
    sqlx::query(
        "UPDATE origin_admission SET cooldown_until=clock_timestamp()-INTERVAL '1 second' WHERE origin=$1",
    )
    .bind(&env.origin)
    .execute(env.first.pool())
    .await
    .unwrap();
    second.cooldown(&env.origin, Duration::ZERO, true).await.unwrap();
    let backoff: i64 = sqlx::query_scalar("SELECT throttle_delay_us FROM origin_admission WHERE origin=$1")
        .bind(&env.origin)
        .fetch_one(env.first.pool())
        .await
        .unwrap();
    assert_eq!(backoff, 4_000_000);
    sqlx::query(
        "UPDATE origin_admission SET cooldown_until=clock_timestamp()-INTERVAL '1 second', \
         throttle_decays_at=clock_timestamp()-INTERVAL '1 second' WHERE origin=$1",
    )
    .bind(&env.origin)
    .execute(env.first.pool())
    .await
    .unwrap();
    first.cooldown(&env.origin, Duration::ZERO, true).await.unwrap();
    let backoff: i64 = sqlx::query_scalar("SELECT throttle_delay_us FROM origin_admission WHERE origin=$1")
        .bind(&env.origin)
        .fetch_one(env.first.pool())
        .await
        .unwrap();
    assert_eq!(backoff, 2_000_000, "a quiet window resets the persisted baseline");
    first
        .cooldown(&env.origin, Duration::from_secs(120), false)
        .await
        .unwrap();
    second
        .cooldown(&env.origin, Duration::from_millis(1), false)
        .await
        .unwrap();
    let remaining: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM (cooldown_until-clock_timestamp()))::float8 FROM origin_admission WHERE origin=$1",
    ).bind(&env.origin).fetch_one(env.first.pool()).await.unwrap();
    assert!(
        remaining > 110.0,
        "Retry-After is not capped or shortened by another worker"
    );
    assert!(second.cooldown_remaining(&env.origin).await.unwrap() > Duration::from_secs(110));
    assert!(timeout(
        Duration::from_millis(30),
        second.acquire(&env.origin, Duration::ZERO)
    )
    .await
    .is_err());
    let other = format!("{}-independent", env.origin);
    drop(
        timeout(DEADLINE, second.acquire(&other, Duration::ZERO))
            .await
            .unwrap()
            .unwrap(),
    );
    drop(first);
    drop(second);
    env.second.pool().close().await;
    env.first.drop_schema().await.expect("drop schema");
}

#[tokio::test]
async fn two_database_handles_and_tenants_share_capacity_but_origins_do_not() {
    let Some(env) = setup(4).await else { return };
    let first = PgOriginAdmission::new(env.first.clone(), 2);
    let second = Arc::new(PgOriginAdmission::new(env.second.clone(), 2));
    let held_a = tenant::scope(env.tenants[0], first.acquire(&env.origin, Duration::ZERO))
        .await
        .expect("tenant A slot");
    let held_b = tenant::scope(env.tenants[1], second.acquire(&env.origin, Duration::ZERO))
        .await
        .expect("tenant B slot");
    let waiter = {
        let admission = second.clone();
        let origin = env.origin.clone();
        let tenant = env.tenants[1];
        tokio::spawn(async move { tenant::scope(tenant, admission.acquire(&origin, Duration::ZERO)).await })
    };
    waiters(&env.first, &env.origin, 0, 1).await;
    assert!(!waiter.is_finished(), "deployment cap includes both tenants");
    let independent_origin = env.origin.replacen("https://", "https://independent-", 1);
    let other = timeout(DEADLINE, second.acquire(&independent_origin, Duration::ZERO))
        .await
        .expect("independent origin is not blocked")
        .expect("independent origin permit");
    drop(other);
    drop(held_a);
    let next = timeout(DEADLINE, waiter).await.unwrap().unwrap().unwrap();
    drop(next);
    drop(held_b);
    drop(first);
    drop(second);
    env.second.pool().close().await;
    env.first.drop_schema().await.expect("drop schema");
}

#[tokio::test]
async fn cancellation_removes_database_waiter_without_releasing_current_permit() {
    let Some(env) = setup(4).await else { return };
    let admission = Arc::new(PgOriginAdmission::new(env.first.clone(), 1));
    let held = admission.acquire(&env.origin, Duration::ZERO).await.unwrap();
    let canceled = {
        let admission = admission.clone();
        let origin = env.origin.clone();
        tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
    };
    waiters(&env.first, &env.origin, 0, 1).await;
    canceled.abort();
    assert!(canceled.await.unwrap_err().is_cancelled());
    // The live predecessor stays held. Client disconnect detection must remove
    // the canceled backend without waiting for that predecessor to finish.
    waiters(&env.first, &env.origin, 0, 0).await;
    let survivor = {
        let admission = admission.clone();
        let origin = env.origin.clone();
        tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
    };
    waiters(&env.first, &env.origin, 0, 1).await;
    assert!(!survivor.is_finished());
    drop(held);
    drop(timeout(DEADLINE, survivor).await.unwrap().unwrap().unwrap());
    drop(admission);
    env.second.pool().close().await;
    env.first.drop_schema().await.expect("drop schema");
}

#[tokio::test]
async fn advisory_waiters_are_fifo_and_cannot_exhaust_normal_storage_writes() {
    let Some(env) = setup(2).await else { return };
    let admission = Arc::new(PgOriginAdmission::new(env.first.clone(), 1));
    let held = admission.acquire(&env.origin, Duration::ZERO).await.unwrap();
    let first_waiter = {
        let admission = admission.clone();
        let origin = env.origin.clone();
        tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
    };
    waiters(&env.first, &env.origin, 0, 1).await;
    let second_service = Arc::new(PgOriginAdmission::new(env.second.clone(), 1));
    let second_waiter = {
        let admission = second_service.clone();
        let origin = env.origin.clone();
        tokio::spawn(async move { admission.acquire(&origin, Duration::ZERO).await })
    };
    waiters(&env.first, &env.origin, 0, 2).await;
    // A further caller waits before opening any additional capacity connection.
    assert!(timeout(
        Duration::from_millis(30),
        admission.acquire(&env.origin, Duration::ZERO),
    )
    .await
    .is_err());
    waiters(&env.first, &env.origin, 0, 2).await;
    // Capacity pool A is full (holder + waiter); ordinary pooled writes still run.
    timeout(
        DEADLINE,
        env.first.ensure_tenant(TenantId::new(), "ordinary-write"),
    )
    .await
    .expect("normal pool remains available")
    .expect("ordinary write");
    drop(held);
    let first_permit = timeout(DEADLINE, first_waiter).await.unwrap().unwrap().unwrap();
    assert!(!second_waiter.is_finished(), "first queued permit remains held");
    drop(first_permit);
    drop(timeout(DEADLINE, second_waiter).await.unwrap().unwrap().unwrap());
    drop(admission);
    drop(second_service);
    env.second.pool().close().await;
    env.first.drop_schema().await.expect("drop schema");
}

#[tokio::test]
async fn database_clock_spacing_uses_maximum_of_previous_and_current_operation() {
    let Some(env) = setup(4).await else { return };
    let first = PgOriginAdmission::new(env.first.clone(), 2);
    let second = PgOriginAdmission::new(env.second.clone(), 2);
    let http = Duration::from_millis(250);
    let browser = Duration::from_millis(500);
    let held = first.acquire(&env.origin, http).await.unwrap();
    let a = start(&env.first, &env.origin).await;
    drop(held);
    let held = second.acquire(&env.origin, browser).await.unwrap();
    let b = start(&env.first, &env.origin).await;
    drop(held);
    let held = first.acquire(&env.origin, http).await.unwrap();
    let c = start(&env.first, &env.origin).await;
    drop(held);
    assert!((b - a).num_microseconds().unwrap() >= 500_000, "HTTP to browser");
    assert!((c - b).num_microseconds().unwrap() >= 500_000, "browser to HTTP");
    // A canceled pacing wait must not advance a future reservation.
    assert!(
        timeout(Duration::from_millis(20), second.acquire(&env.origin, browser))
            .await
            .is_err()
    );
    assert_eq!(start(&env.first, &env.origin).await, c);
    let held = second.acquire(&env.origin, browser).await.unwrap();
    let d = start(&env.first, &env.origin).await;
    assert!((d - c).num_microseconds().unwrap() >= 500_000);
    drop(held);
    drop(first);
    drop(second);
    env.second.pool().close().await;
    env.first.drop_schema().await.expect("drop schema");
}

#[tokio::test]
async fn run_origin_limit_is_shared_across_workers_and_fences_admitted_starts() {
    let Some(env) = setup(4).await else { return };
    let run = crawl_run(env.tenants[0], create_crawl(&env.origin, &["anon"], 1));
    env.first.create(&run, None).await.expect("run");
    let first = PgOriginAdmission::new(env.first.clone(), 3).for_run(run.id, 1);
    let second = PgOriginAdmission::new(env.second.clone(), 3).for_run(run.id, 1);
    let held = first.acquire(&env.origin, Duration::ZERO).await.unwrap();
    let fence: i64 =
        sqlx::query_scalar("SELECT fencing_token FROM origin_leases WHERE run_id = $1 AND origin = $2")
            .bind(run.id.0)
            .bind(&env.origin)
            .fetch_one(env.first.pool())
            .await
            .unwrap();
    assert!(timeout(
        Duration::from_millis(100),
        second.acquire(&env.origin, Duration::ZERO)
    )
    .await
    .is_err());
    // A canceled run-slot wait does not consume a global slot or change its fence.
    let unchanged: i64 =
        sqlx::query_scalar("SELECT fencing_token FROM origin_leases WHERE run_id = $1 AND origin = $2")
            .bind(run.id.0)
            .bind(&env.origin)
            .fetch_one(env.first.pool())
            .await
            .unwrap();
    assert_eq!(fence, unchanged);
    drop(held);
    let held = timeout(DEADLINE, second.acquire(&env.origin, Duration::ZERO))
        .await
        .unwrap()
        .unwrap();
    let next: i64 =
        sqlx::query_scalar("SELECT fencing_token FROM origin_leases WHERE run_id = $1 AND origin = $2")
            .bind(run.id.0)
            .bind(&env.origin)
            .fetch_one(env.first.pool())
            .await
            .unwrap();
    assert!(next > fence);
    drop(held);
    let mismatch = PgOriginAdmission::new(env.first.clone(), 4);
    assert!(matches!(
        mismatch.acquire(&env.origin, Duration::ZERO).await,
        Err(StoreError::Conflict(_))
    ));
    drop(mismatch);
    drop(first);
    drop(second);
    env.second.pool().close().await;
    env.first.drop_schema().await.expect("drop schema");
}

#[tokio::test]
async fn reserved_capacity_paces_actual_start_instead_of_reservation_time() {
    let Some(env) = setup(4).await else { return };
    let admission = PgOriginAdmission::new(env.first.clone(), 2);
    let mut reserved = admission.reserve(&env.origin).await.unwrap();
    let started: bool =
        sqlx::query_scalar("SELECT isfinite(next_allowed_at) FROM origin_admission WHERE origin = $1")
            .bind(&env.origin)
            .fetch_one(env.first.pool())
            .await
            .unwrap();
    assert!(!started, "capacity reservation must not reserve a future start");
    let browser = admission
        .acquire(&env.origin, Duration::from_millis(500))
        .await
        .unwrap();
    let first = start(&env.first, &env.origin).await;
    drop(browser);
    reserved.start(Duration::from_millis(250)).await.unwrap();
    let second = start(&env.first, &env.origin).await;
    assert!((second - first).num_microseconds().unwrap() >= 500_000);
    drop(reserved);
    drop(admission);
    env.second.pool().close().await;
    env.first.drop_schema().await.expect("drop schema");
}
