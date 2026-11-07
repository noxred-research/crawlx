//! Existing worker registry capability publication, bounded snapshots and same-worker admission.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::acquisition::{BackendCapabilitiesV1, WORKER_CAPABILITY_SNAPSHOT_LIMIT};
use crawlx_core::config::LaunchProfile;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::time::ManualClock;
use crawlx_core::{CrawlRunId, WorkerId};
use crawlx_storage::{AdminOps, MemoryStore, Pg, PgConfig, WorkerRegistry};
use std::sync::Arc;
use std::time::Duration;

fn browser() -> BackendCapabilitiesV1 {
    BackendCapabilitiesV1::native_browser(BrowserBuildInfo {
        chromium_version: "registry-fixture-observed-build".into(),
        cdp_revision: "1.3".into(),
        user_agent: "registry-fixture".into(),
        pinned: false,
        launch_profile: LaunchProfile::Standard,
        console_capture: false,
        attached: false,
    })
}

#[tokio::test]
async fn memory_registry_never_unions_workers_or_hides_eligible_worker_beyond_snapshot() {
    let clock = Arc::new(ManualClock::new("2026-11-04T00:00:00Z".parse().unwrap()));
    let store = MemoryStore::with_clock(clock.clone());
    let required = vec!["native_http".to_owned(), "native_browser".to_owned()];
    assert!(store
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .is_none());
    let http = BackendCapabilitiesV1::native_http("crawlx-fetch/fixture", "1");
    for index in 1..=300u32 {
        let worker: WorkerId = format!("00000000-0000-0000-0000-{index:012x}").parse().unwrap();
        store.register_worker(worker, "fixture", "1").await.unwrap();
        let capabilities = if index == 300 {
            vec![http.clone(), browser()]
        } else {
            vec![http.clone()]
        };
        store
            .publish_acquisition_capabilities(worker, &capabilities)
            .await
            .unwrap();
    }
    let snapshot = store
        .live_acquisition_workers(Duration::from_secs(90))
        .await
        .unwrap();
    assert_eq!(snapshot.len(), WORKER_CAPABILITY_SNAPSHOT_LIMIT + 1);
    assert!(!snapshot.iter().any(|worker| worker.supports(&required)));
    let eligible = store
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        eligible.worker.to_string(),
        "00000000-0000-0000-0000-00000000012c"
    );
    clock.advance_ms(90_001);
    assert!(store
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .is_none());
    store.worker_heartbeat(eligible.worker).await.unwrap();
    assert!(store
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .is_some());
    store
        .register_worker(eligible.worker, "restarted", "2")
        .await
        .unwrap();
    assert!(
        store
            .eligible_acquisition_worker(&required, Duration::from_secs(90))
            .await
            .unwrap()
            .is_none(),
        "restart must clear old build claims"
    );
}

#[tokio::test]
async fn memory_registry_rejects_unobserved_browser_and_cross_worker_capability_union() {
    let store = MemoryStore::new();
    let http_worker = WorkerId::new();
    let browser_worker = WorkerId::new();
    store.register_worker(http_worker, "http", "1").await.unwrap();
    store
        .register_worker(browser_worker, "browser", "1")
        .await
        .unwrap();
    store
        .publish_acquisition_capabilities(http_worker, &[BackendCapabilitiesV1::native_http("fixture", "1")])
        .await
        .unwrap();
    store
        .publish_acquisition_capabilities(browser_worker, &[browser()])
        .await
        .unwrap();
    let required = vec!["native_http".into(), "native_browser".into()];
    assert!(store
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .is_none());
    let mut unobserved = BackendCapabilitiesV1::native_browser_unavailable("not_observed");
    unobserved.available = true;
    assert!(store
        .publish_acquisition_capabilities(http_worker, &[unobserved])
        .await
        .is_err());
}

#[tokio::test]
async fn local_executor_never_satisfies_queued_capability_admission() {
    let store = MemoryStore::new();
    let worker = WorkerId::new();
    let required = vec!["native_http".to_owned()];
    let capabilities = [BackendCapabilitiesV1::native_http("fixture", "1")];
    store.register_worker(worker, "local", "1").await.unwrap();
    store
        .publish_local_acquisition_capabilities(worker, CrawlRunId::new(), &capabilities)
        .await
        .unwrap();
    assert!(store
        .live_acquisition_workers(Duration::from_secs(90))
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .is_none());
    store
        .publish_acquisition_capabilities(worker, &capabilities)
        .await
        .unwrap();
    assert_eq!(
        store
            .eligible_acquisition_worker(&required, Duration::from_secs(90))
            .await
            .unwrap()
            .unwrap()
            .worker,
        worker
    );
}

#[tokio::test]
async fn postgres_registry_projection_excludes_stale_draining_and_restarted_workers() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let schema = format!("t_acquisition_{}", CrawlRunId::new().0.simple());
    let pg = Pg::connect(
        &url,
        PgConfig {
            schema: Some(schema),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let worker = WorkerId::new();
    let required = vec!["native_http".into(), "native_browser".into()];
    pg.register_worker(worker, "fixture", "1").await.unwrap();
    pg.publish_acquisition_capabilities(
        worker,
        &[BackendCapabilitiesV1::native_http("fixture", "1"), browser()],
    )
    .await
    .unwrap();
    assert_eq!(
        pg.eligible_acquisition_worker(&required, Duration::from_secs(90))
            .await
            .unwrap()
            .unwrap()
            .worker,
        worker
    );
    AdminOps::new(&pg, "fixture").drain_worker(worker).await.unwrap();
    assert!(pg
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .is_none());
    pg.register_worker(worker, "fixture", "2").await.unwrap();
    assert!(pg
        .live_acquisition_workers(Duration::from_secs(90))
        .await
        .unwrap()
        .is_empty());
    pg.publish_acquisition_capabilities(
        worker,
        &[BackendCapabilitiesV1::native_http("fixture", "2"), browser()],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE workers SET last_heartbeat_at = now() - interval '91 seconds' WHERE worker_id=$1")
        .bind(worker.0)
        .execute(pg.pool())
        .await
        .unwrap();
    assert!(pg
        .eligible_acquisition_worker(&required, Duration::from_secs(90))
        .await
        .unwrap()
        .is_none());
    pg.drop_schema().await.unwrap();
}
