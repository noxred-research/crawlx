//! G1 lane regressions through real Chromium: a default worker run of the link fixtures G06 (cards
//! with `open-N` links) and G07 (the self-filling feed with header links) executes every action on
//! the trusted lane. Skipped (with a message) without a Chromium
//! executable; set `CRAWLX_CHROMIUM_PATH`.
//!
//! Two defects put scripted `Navigate` actions on the diagnostic lane here: the live `href` of an
//! anchor was its resolved URL while the observed descriptor carried it as written, so the kernel
//! dropped the first click on every relative link (`confirm.identity_changed`) and the lane-blind
//! arbiter then picked the `url_plane` navigation to the same destination; and `url_plane` raced
//! the trusted click in the greedy phase. Both are asserted away below.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::ablation;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_bench::scorecard::Scorecard;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, rows_from_report, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::ActionStatus;
use crawlx_core::traffic::TrustLane;
use crawlx_storage::MemoryStore;
use crawlx_worker::{run_local_with, DriverConfig, LocalRun, RunReport, Stores};
use std::sync::Arc;

const SEED: u64 = 7;
const VARIANT: &str = "A4";

async fn crawl(gym: &GymHandle, id: &str) -> (FixtureManifest, RunReport) {
    let manifest = FixtureManifest::embedded(id).unwrap();
    let variant = ablation::find(VARIANT).unwrap();
    gym.reset(SEED);
    let mut req = crawl_request(&manifest, &gym.base_url, SEED, SafetyProfile::TestEnvironment).unwrap();
    variant.apply(&mut req);
    req.limits.interactions = 40;
    req.limits.urls = 200;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut driver = DriverConfig::default();
    driver.exploration.queue = variant.queue_cfg();
    let report = run_local_with(authorize_fixture(
        LocalRun::new(req, cfg).with_driver(driver).with_stores(stores),
    ))
    .await
    .unwrap();
    (manifest, report)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn link_fixtures_run_entirely_on_the_trusted_lane() {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    }
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    for id in ["g06", "g07"] {
        let (manifest, report) = crawl(&gym, id).await;
        assert!(!report.actions.is_empty(), "{id}: the run executed nothing");
        let detail = || {
            report
                .actions
                .iter()
                .map(|a| format!("{} {:?} {:?} {:?}", a.seq, a.strategy, a.status, a.fidelity))
                .collect::<Vec<_>>()
        };
        // a click dropped at confirmation never ran: a relative link must confirm like any other
        assert!(
            report.actions.iter().all(|a| a.status != ActionStatus::Proposed),
            "{id}: an admitted action was dropped before it ran: {:#?}",
            detail()
        );
        assert!(
            report
                .actions
                .iter()
                .all(|a| a.lane == Some(TrustLane::TrustedUi)),
            "{id}: an action ran on the diagnostic lane: {:#?}",
            detail()
        );
        let rows = rows_from_report(
            &report,
            &manifest,
            SEED,
            VARIANT,
            SafetyProfile::TestEnvironment,
            &gym,
        );
        let card = Scorecard::compute(&manifest, &rows, &gym.ledger());
        let lanes = card.lanes.expect("the run recorded lanes");
        assert_eq!(lanes.diagnostic, 0, "{id}: {lanes:?}");
        assert!(
            (lanes.trusted_share - 1.0).abs() < f64::EPSILON,
            "{id}: {lanes:?}"
        );
    }
    gym.shutdown().await;
}
