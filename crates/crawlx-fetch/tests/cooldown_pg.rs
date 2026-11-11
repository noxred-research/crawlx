//! A `429`/`503` cooldown published by one worker holds back every worker on that origin.
//!
//! Two governors, each with its own database handle and process-local queues, share one
//! PostgreSQL origin admission store (the deployment authority). Skipped without
//! `CRAWLX_TEST_DATABASE_URL`; PostgreSQL 14+ is required.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::CrawlRunId;
use crawlx_fetch::{GlobalOriginCap, GovernorConfig, Origin, OriginGovernor};
use crawlx_storage::{Pg, PgOriginAdmission, StoreConfig};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn config() -> GovernorConfig {
    GovernorConfig {
        // A `503` without `Retry-After` doubles the spacing; it must be long enough to observe.
        base_delay: Duration::from_millis(300),
        ..GovernorConfig::default()
    }
}

/// One worker: its own database handle, admission pools and governor.
async fn worker(url: &str, schema: &str) -> Arc<OriginGovernor> {
    let pg = Pg::connect(
        url,
        StoreConfig {
            schema: Some(schema.to_owned()),
            max_connections: 4,
            ..StoreConfig::default()
        },
    )
    .await
    .expect("database handle");
    let admission = Arc::new(PgOriginAdmission::new(pg, GlobalOriginCap::DEFAULT_LIMIT));
    let cap = Arc::new(GlobalOriginCap::with_admission(
        GlobalOriginCap::DEFAULT_LIMIT,
        admission,
    ));
    Arc::new(OriginGovernor::with_global_cap(config(), cap))
}

async fn two_workers() -> Option<(Arc<OriginGovernor>, Arc<OriginGovernor>, String)> {
    let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
    let schema = format!("t_{}", CrawlRunId::new().0.simple());
    let admin = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(schema.clone()),
            max_connections: 2,
            ..StoreConfig::default()
        },
    )
    .await
    .expect("admin handle");
    admin.migrate().await.expect("migrate");
    let a = worker(&url, &schema).await;
    let b = worker(&url, &schema).await;
    Some((a, b, schema))
}

#[tokio::test]
async fn a_429_published_by_one_worker_holds_back_the_other_worker_and_only_that_origin() {
    let Some((a, b, schema)) = two_workers().await else {
        return;
    };
    let hot = Origin::new(&format!("https://{schema}-hot.test"));
    let other = Origin::new(&format!("https://{schema}-other.test"));

    // Both workers have used the origin, so neither is waiting on a first-start condition.
    drop(a.acquire(&hot).await.unwrap());
    drop(b.acquire(&hot).await.unwrap());

    a.on_response_with_latency(&hot, 429, Some(Duration::from_millis(1200)), None, false)
        .await
        .unwrap();

    // Worker B has seen no response from the origin, yet the committed cooldown is visible
    // before it leases work and it cannot start a request until the cooldown has passed.
    let visible = b.shared_cooldown_remaining(&hot).await.unwrap();
    assert!(
        visible > Duration::from_millis(500) && visible <= Duration::from_millis(1250),
        "{visible:?}"
    );
    let started = Instant::now();
    let permit = b.acquire(&hot).await.unwrap();
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_millis(900),
        "worker B started after only {waited:?}"
    );
    assert!(waited < Duration::from_secs(10), "{waited:?}");
    drop(permit);

    // The cooldown is per origin: another origin is not held back by it.
    let started = Instant::now();
    drop(b.acquire(&other).await.unwrap());
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_503_without_retry_after_still_holds_every_worker_and_the_cooldown_expires() {
    let Some((a, b, schema)) = two_workers().await else {
        return;
    };
    let origin = Origin::new(&format!("https://{schema}-503.test"));
    drop(a.acquire(&origin).await.unwrap());

    a.on_response_with_latency(&origin, 503, None, None, false)
        .await
        .unwrap();
    let remaining = b.shared_cooldown_remaining(&origin).await.unwrap();
    assert!(remaining > Duration::ZERO, "no cooldown reached the other worker");

    let started = Instant::now();
    drop(b.acquire(&origin).await.unwrap());
    assert!(started.elapsed() >= remaining.saturating_sub(Duration::from_millis(150)));

    // After the wait the origin is open again for both workers.
    assert_eq!(
        b.shared_cooldown_remaining(&origin).await.unwrap(),
        Duration::ZERO
    );
    let started = Instant::now();
    drop(a.acquire(&origin).await.unwrap());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn a_waiting_worker_does_not_hold_run_global_capacity_during_the_cooldown() {
    let Some((a, b, schema)) = two_workers().await else {
        return;
    };
    let hot = Origin::new(&format!("https://{schema}-queued.test"));
    let free = Origin::new(&format!("https://{schema}-free.test"));
    drop(a.acquire(&hot).await.unwrap());
    a.on_response_with_latency(&hot, 429, Some(Duration::from_millis(1500)), None, false)
        .await
        .unwrap();

    let waiting = {
        let b = Arc::clone(&b);
        let hot = hot.clone();
        tokio::spawn(async move { b.acquire(&hot).await.map(drop) })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = Instant::now();
    drop(b.acquire(&free).await.unwrap());
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "{:?}",
        started.elapsed()
    );
    waiting.await.unwrap().unwrap();
}
