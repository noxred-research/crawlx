#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Replay of recorded paths on real Chromium (the G1 gate's `replay_match_rate`).
//!
//! The first local G1 run replayed 0/10 paths on every fixture. The regressions it found: a
//! form submit control classifies stricter from its live facts than from its descriptor, a
//! page with a third-party beacon never finishes loading in a replay browser that runs without
//! the egress proxy, and a `Select` could not be rebuilt from the journal (G02). Each
//! fixture replays the complete path to the source run's last succeeded action. Recorded
//! failures that changed the page have deterministic coverage in `replay_kinds`.

use crawlx_bench::ablation;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::GymServer;
use crawlx_bench::worker_exec::{authorize_fixture, crawl_request, worker_config};
use crawlx_browser::launch::find_executable;
use crawlx_browser::network_guard::GUARD_PLANE;
use crawlx_core::config::SafetyProfile;
use crawlx_core::counters::ActionStatus;
use crawlx_policy::egress::DenyRule;
use crawlx_storage::MemoryStore;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::replay::{ReplayMode, ReplayPlan, ReplayRunner, StepVerdict};
use crawlx_worker::{run_local_with, DriverConfig, LocalRun, StaticAuthorizationSource, Stores};
use std::sync::Arc;

/// Crawl `fixture` with the G1 configuration (variant `A4`, `test_environment`, 40
/// interactions) and replay the complete path to its last succeeded action in `verify` mode.
async fn crawl_then_replay(fixture: &str) -> Option<crawlx_worker::replay::ReplayReport> {
    crawl_then_replay_counting_guard_denials(fixture)
        .await
        .map(|(out, _)| out)
}

/// [`crawl_then_replay`], also returning how many metadata-service requests the browser
/// network guard refused while the replay itself ran (the source crawl is not counted).
async fn crawl_then_replay_counting_guard_denials(
    fixture: &str,
) -> Option<(crawlx_worker::replay::ReplayReport, u64)> {
    if find_executable().is_none() {
        eprintln!("SKIP: no Chromium (set CRAWLX_CHROMIUM_PATH)");
        return None;
    }
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded(fixture).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let variant = ablation::find("A4").unwrap();
    gym.reset(7);
    let mut req = crawl_request(&manifest, &gym.base_url, 7, SafetyProfile::TestEnvironment).unwrap();
    variant.apply(&mut req);
    req.limits.interactions = 40;
    // Match the G1 reporter's action-budget workload, not its 20-second smoke clock:
    // forty browser effects alone require twenty seconds of mandatory pacing.
    req.limits.duration_seconds = req.limits.interactions.saturating_mul(10).saturating_add(30);
    req.limits.urls = 200;
    let mut cfg = worker_config(&manifest, dir.path()).unwrap();
    cfg.gates = crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL);
    let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut driver = DriverConfig::default();
    driver.exploration.queue = variant.queue_cfg();
    let local = authorize_fixture(
        LocalRun::new(req, cfg.clone())
            .with_driver(driver)
            .with_stores(stores.clone()),
    );
    let source = Arc::new(StaticAuthorizationSource::new(
        local.authorization.as_ref().unwrap().clone(),
    ));
    stores.authorization = Some(source.clone());
    let report = run_local_with(local.with_authorization_source(source))
        .await
        .unwrap();
    let last = report
        .actions
        .iter()
        .rfind(|a| a.status == ActionStatus::Succeeded)
        .expect("the crawl recorded a succeeded action");
    let plan = ReplayPlan::load(&stores, report.run_id, last.id).await.unwrap();
    let expected_steps = plan.steps.len();
    let denials = Metrics::global().counter(names::EGRESS_DENIALS);
    let labels = [("plane", GUARD_PLANE), ("reason", DenyRule::Metadata.as_str())];
    let before_replay = denials.get(&labels);
    let out = ReplayRunner::run(cfg, plan, ReplayMode::Verify, None, None)
        .await
        .unwrap();
    let guard_denials = denials.get(&labels).saturating_sub(before_replay);
    gym.shutdown().await;
    assert_eq!(out.steps.len(), expected_steps, "{:#?}", out.steps);
    assert_eq!(out.steps.last().map(|step| step.action), Some(last.id));
    Some((out, guard_denials))
}

/// G01: forty recorded steps through submit controls inside forms replay and match. Before
/// the replay re-admitted on live facts every path stopped at the first such control with
/// `confirm_denied`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g01_recorded_path_replays_and_matches_on_chromium() {
    let Some(out) = crawl_then_replay("g01").await else {
        return;
    };
    assert!(out.ok, "{:#?}", out.steps);
    assert!(out
        .steps
        .iter()
        .all(|s| matches!(s.verdict, StepVerdict::Matched { .. })));
}

/// D1 embeds a link-local metadata-service image. The replay browser's network guard refuses
/// that request before the browser dispatches it, so the replay's egress proxy never sees it;
/// without the guard and proxy the navigation waited on the link-local address until the 30 s
/// timeout and no step ran. The refusal is evidenced by the guard's own denial counter, and
/// the proxy must not have dialed the metadata host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn d1_replay_runs_behind_the_egress_policy_and_matches() {
    let Some((out, guard_denials)) = crawl_then_replay_counting_guard_denials("d1").await else {
        return;
    };
    assert!(out.ok, "{:#?}", out.steps);
    assert!(
        guard_denials > 0,
        "the metadata-service beacon was refused by the replay browser's network guard"
    );
    assert!(
        !out.egress
            .dialed_hosts
            .iter()
            .any(|(host, _)| host.contains("169.254.169.254")),
        "the replay's egress proxy dialed the metadata service: {:?}",
        out.egress.dialed_hosts
    );
}

/// G02 records a `Select` (ARIA combobox/listbox widgets). The journal keeps the key of the
/// action, not the option it picked; the replay rebuilt only click, keyboard, hover,
/// navigation and typing, so every path stopped at `step 8 select -> NotReproducible`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g02_recorded_path_through_a_select_replays_and_matches_on_chromium() {
    let Some(out) = crawl_then_replay("g02").await else {
        return;
    };
    assert!(out.ok, "{:#?}", out.steps);
    assert!(
        out.steps.iter().any(|s| s.kind == "select"),
        "the recorded path selects an option: {:#?}",
        out.steps
    );
    assert!(out.steps.iter().all(|s| matches!(
        s.verdict,
        StepVerdict::Matched { .. } | StepVerdict::FailedAsRecorded { .. }
    )));
}

/// G03 replays the complete recorded path through its custom widgets, without requiring
/// a particular crawl ordering or assuming that a select attempt must fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn g03_recorded_widget_path_replays_and_matches_on_chromium() {
    let Some(out) = crawl_then_replay("g03").await else {
        return;
    };
    assert!(out.ok, "{:#?}", out.steps);
    assert!(out.steps.iter().all(|s| matches!(
        s.verdict,
        StepVerdict::Matched { .. } | StepVerdict::FailedAsRecorded { .. }
    )));
}
