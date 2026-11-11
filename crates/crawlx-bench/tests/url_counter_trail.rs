//! `verify_trail` holds the URL counters of a run to its `url_frontier` rows (the stored
//! `crawl_runs.counters` are a snapshot, the rows are the source): a worker
//! killed after it finished rows and before it flushed leaves `urls.succeeded` behind the rows,
//! the trail reports a `counter_mismatch`, and the worker that takes the run over re-derives the
//! counters (`RunCounters::recover_from_frontier`) so the trail is clean again.
//!
//! The crash is simulated on a finished static crawl of the `s1` gym slice (robots blocks,
//! excludes, a sitemap, duplicates): the stored counters are rewound by two finished pages, which
//! is exactly the state a kill between the second-last flush and the last leaves. The same on
//! the in-memory store and on PostgreSQL (skipped without `CRAWLX_TEST_DATABASE_URL`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "support/authorization.rs"]
mod authorization;

use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::trail::{verify_trail, TrailReport, TrailStore, TrailViolation};
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_core::counters::PlaneCounters;
use crawlx_core::repo::{FrontierStatus, RunRepo};
use crawlx_core::{Clock, CrawlRunId, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use crawlx_storage::{FsArtifactStore, Pg, StoreConfig};
use crawlx_worker::{run_local_with, LocalRun, RunCounters, Stores};
use std::path::Path;
use std::sync::Arc;

/// Pages lost from the stored counters.
const LOST: u64 = 2;

/// A record admitting the loopback gym (PostgreSQL holds a foreign key to it).
fn loopback_record(tenant: TenantId) -> AuthorizationRecord {
    let now = SystemClock.now();
    AuthorizationRecord {
        verified_at: Some(now),
        url_prefixes: vec!["http://127.0.0.1".to_owned()],
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        valid_from: now - chrono::Duration::days(1),
        valid_to: now + chrono::Duration::days(1),
        ..sample_record(tenant, now, &[])
    }
}

async fn trail(stores: &Stores, _pg: Option<&Pg>, run: CrawlRunId) -> TrailReport {
    let artifacts = Some(stores.artifacts.as_ref());
    let store = match (stores.durable.as_ref(), stores.memory.as_ref()) {
        (Some(store), _) => TrailStore::Database { store, artifacts },
        (None, Some(store)) => TrailStore::Memory { store, artifacts },
        (None, None) => panic!("neither store"),
    };
    verify_trail(run, store).await.unwrap()
}

async fn stored(stores: &Stores, run: CrawlRunId) -> PlaneCounters {
    stores.runs.get(run).await.unwrap().counters
}

async fn lost_flush_is_reported_then_repaired(
    pg: Option<Pg>,
    stores: Stores,
    dir: &Path,
    record: Option<AuthorizationRecord>,
) {
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded("s1").unwrap();
    let mut req = crawl_request(&manifest, &gym.base_url, 20_261_028, SafetyProfile::ReadOnly).unwrap();
    req.mode = CrawlMode::Static;
    req.dynamic.enabled = false;
    let cfg = worker_config(&manifest, dir).unwrap();
    let mut local = LocalRun::new(req, cfg).with_stores(stores.clone());
    if let Some(record) = record {
        local.crawl.safety.authorization_record_ref = Some(record.id);
        local = local.with_authorization(record);
    }
    let local = authorize_fixture(local);
    if let Some(pg) = pg.as_ref() {
        authorization::register_verified_record(pg, local.authorization.as_ref().unwrap()).await;
    }
    let report = run_local_with(local).await.unwrap();
    let run = report.run_id;
    let finished = stored(&stores, run).await;
    assert!(finished.urls.succeeded > LOST, "{:?}", finished.urls);
    let clean = trail(&stores, pg.as_ref(), run).await;
    assert!(clean.is_clean(), "{clean}");

    // the kill: the last two pages were finished on the frontier, never flushed to the counters
    let mut behind = finished;
    behind.urls.succeeded -= LOST;
    behind.urls.attempted -= LOST;
    stores.runs.update_counters(run, behind).await.unwrap();
    let dirty = trail(&stores, pg.as_ref(), run).await;
    assert_eq!(
        dirty.violations,
        vec![TrailViolation::CounterMismatch {
            counter: "urls.succeeded",
            stored: finished.urls.succeeded - LOST,
            derived: finished.urls.succeeded,
        }],
        "{dirty}"
    );

    // the worker that takes the run over re-derives the counters from the rows and flushes
    let counters = RunCounters::from_snapshot(stored(&stores, run).await);
    let repaired = counters
        .recover_from_frontier(stores.frontier.as_ref(), stores.runs.as_ref(), run)
        .await
        .unwrap();
    assert_eq!(repaired, LOST, "{:?}", counters.snapshot().urls);
    assert_eq!(
        stored(&stores, run).await,
        finished,
        "the counters of the uninterrupted run"
    );
    let repaired = trail(&stores, pg.as_ref(), run).await;
    assert!(repaired.is_clean(), "{repaired}");
    assert!(
        stores
            .frontier
            .list(run)
            .await
            .unwrap()
            .iter()
            .all(|r| r.status != FrontierStatus::Leased),
        "the run is over"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_counter_flush_is_reported_then_repaired_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::open(&worker_config(&FixtureManifest::embedded("s1").unwrap(), dir.path()).unwrap())
        .await
        .unwrap();
    assert!(stores.memory.is_some(), "the default stores are in memory");
    lost_flush_is_reported_then_repaired(None, stores, dir.path(), None).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_counter_flush_is_reported_then_repaired_on_postgres() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("t_urltrail_{}", uuid::Uuid::now_v7().simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "url-counter-trail").await.unwrap();
    let mut stores = Stores::over_durable(
        crawlx_worker::DurableStore::Postgres(pg.clone()),
        Arc::new(artifacts),
        tenant,
    );
    stores.checkpoint_keys =
        Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    lost_flush_is_reported_then_repaired(
        Some(pg.clone()),
        stores,
        dir.path(),
        Some(loopback_record(tenant)),
    )
    .await;
    pg.drop_schema().await.unwrap();
}
