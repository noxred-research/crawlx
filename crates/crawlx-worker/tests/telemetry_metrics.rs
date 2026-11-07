//! The catalog metrics the Session Actor emits, asserted as deltas because the
//! registry is process-global. Tests are serialized so no delta is shared.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{canonical, rig, rig_with, Rig};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::repo::StateRepo;
use crawlx_core::{CreateCrawl, SafetyProfile};
use crawlx_fetch::StaticResolver;
use crawlx_observe::spec;
use crawlx_storage::MemoryStore;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::actor::DropReason;
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, SessionError, Stores, WorkerConfig};
use std::sync::atomic::Ordering;
use std::sync::Arc;

/// Serializes the tests: the registry is process-global and every test asserts exact deltas.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn two_page_site() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("about", "About", "/about"))
                .on_click("about", vec![FakeEffect::Navigate("/about".into())]),
        )
        .page(
            FakePage::new("https://example.test/about")
                .title("About")
                .node(FakeAxSpec::link("home", "Home", "/")),
        )
}

async fn observe_cluster(
    r: &Rig,
) -> (
    Arc<crawlx_core::observation::ObservationBundle>,
    crawlx_core::StateClusterId,
) {
    let bundle = r.handle.observe(spec::after_action()).await.unwrap();
    let state = crawlx_worker::StateAnalyzer::new(
        r.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    )
    .analyze(&bundle)
    .await
    .state;
    r.store.put_state(&state).await.unwrap();
    (bundle, state.cluster)
}

fn hist_count(name: &str) -> u64 {
    hist_count_with(name, &[])
}

fn hist_count_with(name: &str, labels: &[(&str, &str)]) -> u64 {
    Metrics::global()
        .histogram(name)
        .snapshot(labels)
        .map_or(0, |s| s.count)
}

fn counter(name: &str, labels: &[(&str, &str)]) -> u64 {
    Metrics::global().counter(name).get(labels)
}

fn gauge(name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    Metrics::global().gauge(name).get(labels)
}

/// Explore `script` end to end through the driver (the rig drives the actor by hand).
async fn explore(script: FakeScript) -> crawlx_worker::RunReport {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(FakeBackend::new(script));
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(20_261_020);
    crawl.limits.interactions = 20;
    crawl.limits.states = 20;
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    run_local_with(
        LocalRun::new(crawl, cfg)
            .with_backend(backend)
            .with_stores(stores),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn an_executed_action_counts_once_and_times_both_journal_transactions() {
    let _serial = SERIAL.lock().await;
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let observations = hist_count(names::OBSERVATION_DURATION);
    let fingerprints = hist_count(names::FINGERPRINT_DURATION);
    let cluster_decisions = hist_count(names::CLUSTER_DECISION_DURATION);
    let (bundle, cluster) = observe_cluster(&r).await;
    assert_eq!(
        hist_count(names::OBSERVATION_DURATION),
        observations + 1,
        "an observe command is timed"
    );
    assert_eq!(
        hist_count(names::FINGERPRINT_DURATION),
        fingerprints + 1,
        "the fingerprint of the analyzed bundle is timed"
    );
    assert_eq!(
        hist_count(names::CLUSTER_DECISION_DURATION),
        cluster_decisions + 1
    );
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let admitted = r.admit(p, &c);
    let role = r.principal.0.as_str();
    let executed = &[("lane", "trusted_ui"), ("kind", "click")];
    let interactions = &[
        ("role", role),
        ("lane", "trusted_ui"),
        ("strategy", "test"),
        ("kind", "click"),
    ];
    let revalidated = &[("outcome", "actionable")];
    let synthetic = &[("kind", "click")];
    let invariant = &[("reason", "performed_without_allow")];
    let hard_deny = &[("reason", "navigation_reveal")];
    let duration = Metrics::global().histogram(names::ACTION_DURATION);
    let duration_labels = &[
        ("lane", "trusted_ui"),
        ("kind", "click"),
        ("outcome", "succeeded"),
    ];
    let before = (
        counter(names::ACTIONS_EXECUTED, executed),
        hist_count(names::JOURNAL_T1_DURATION),
        hist_count(names::JOURNAL_T2_DURATION),
        duration.snapshot(duration_labels).map_or(0, |s| s.count),
        counter(names::INTERACTIONS_EXECUTED, interactions),
        hist_count_with(names::REVALIDATE_LATENCY, revalidated),
        hist_count(names::FINGERPRINT_DURATION),
        counter(names::TRUSTED_LANE_SYNTHETIC_ACTIONS, synthetic),
        counter(names::SAFETY_INVARIANT_VIOLATIONS, invariant),
        counter(names::SAFETY_HARD_DENY_VIOLATIONS, hard_deny),
    );

    let out = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.status, ActionStatus::Succeeded);
    assert_eq!(out.receipt.as_ref().unwrap().lane.as_str(), "trusted_ui");

    assert_eq!(counter(names::ACTIONS_EXECUTED, executed), before.0 + 1);
    assert_eq!(hist_count(names::JOURNAL_T1_DURATION), before.1 + 1);
    assert_eq!(hist_count(names::JOURNAL_T2_DURATION), before.2 + 1);
    assert_eq!(
        duration.snapshot(duration_labels).map_or(0, |s| s.count),
        before.3 + 1
    );
    assert_eq!(
        counter(names::INTERACTIONS_EXECUTED, interactions),
        before.4 + 1,
        "the executed interaction is counted per role, lane, strategy and kind"
    );
    assert_eq!(
        hist_count_with(names::REVALIDATE_LATENCY, revalidated),
        before.5 + 1,
        "the pre-action revalidation is timed by outcome"
    );
    assert_eq!(
        hist_count(names::FINGERPRINT_DURATION),
        before.6 + 1,
        "the after-observation is fingerprinted once"
    );
    // the after-state was clustered with the role at hand: Home and About are two clusters
    assert_eq!(
        gauge(names::STATES_CLUSTERS, &[("role", role)]),
        Some(2.0),
        "clusters: {}",
        r.rc.clusters.len()
    );
    // guards that must stay at zero
    assert_eq!(
        counter(names::TRUSTED_LANE_SYNTHETIC_ACTIONS, synthetic),
        before.7
    );
    assert_eq!(counter(names::SAFETY_INVARIANT_VIOLATIONS, invariant), before.8);
    assert_eq!(counter(names::SAFETY_HARD_DENY_VIOLATIONS, hard_deny), before.9);
}

#[tokio::test]
async fn a_driven_exploration_reports_proposals_and_per_role_coverage() {
    let _serial = SERIAL.lock().await;
    let role = "anonymous";
    let by_role = &[("role", role)];
    let proposed = &[
        ("role", role),
        ("lane", "trusted_ui"),
        ("strategy", "interaction_bfs"),
        ("kind", "click"),
    ];
    let before = (
        counter(names::INTERACTIONS_PROPOSED, proposed),
        counter(names::STATES_FALSE_MERGE_SUSPECTS, by_role),
    );
    let report = explore(two_page_site()).await;
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert_eq!(report.sessions[0].role.0, role);
    assert!(
        counter(names::INTERACTIONS_PROPOSED, proposed) > before.0,
        "the BFS strategy proposed clicks on the trusted lane"
    );
    // two pages, two clusters, no review flag on a clean attachment
    assert_eq!(gauge(names::STATES_CLUSTERS, by_role), Some(2.0));
    assert_eq!(counter(names::STATES_FALSE_MERGE_SUSPECTS, by_role), before.1);
    // the ledger gauges follow the run's coverage claim
    let cov = &report.coverage;
    assert!(cov.keys_total > 0 && cov.keys_exercised_trusted > 0, "{cov:?}");
    // The gauge is the driver's view of its own ledger, which also holds keys that were proposed
    // but never attempted (the exploration frontier); the report's ledger is read back from the
    // journal and holds attempted keys only. The gauge's denominator is therefore at least the
    // report's, and its ratio never exceeds the report's.
    let reported = f64::from(cov.keys_exercised_trusted) / f64::from(cov.keys_total);
    let actual = gauge(names::COVERAGE_ACTION_CONTEXT, by_role).unwrap();
    assert!(
        actual > 0.0 && actual <= reported + f64::EPSILON,
        "{actual} vs {reported}"
    );
    assert_eq!(
        gauge(names::COVERAGE_DIAGNOSTIC_ONLY_KEYS, by_role),
        Some(f64::from(cov.keys_diagnostic_only))
    );
    // no cross-principal context exists for the anonymous role: the rate is 1.0 by definition
    assert_eq!(
        gauge(names::SESSION_CROSS_PRINCIPAL_ATTRIBUTION_RATE, by_role),
        Some(1.0)
    );
}

#[tokio::test]
async fn a_stale_epoch_drop_counts_as_stale_for_its_strategy() {
    let _serial = SERIAL.lock().await;
    let r = rig(two_page_site(), SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let admitted = r.admit(p, &c);
    let stale = &[("strategy", "test"), ("reason", "stale_epoch")];
    let by_role = &[
        ("role", r.principal.0.as_str()),
        ("lane", "trusted_ui"),
        ("reason", "stale_epoch"),
    ];
    let before = (
        counter(names::PROPOSALS_STALE, stale),
        counter(names::INTERACTIONS_DROPPED_STALE, by_role),
    );
    // the page navigates away after the proposal was derived
    r.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical("https://example.test/about"),
            0,
            None,
        ))
        .await
        .unwrap();
    let out = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.dropped, Some(DropReason::StaleEpoch));
    assert_eq!(counter(names::PROPOSALS_STALE, stale), before.0 + 1);
    assert_eq!(counter(names::INTERACTIONS_DROPPED_STALE, by_role), before.1 + 1);
}

#[tokio::test]
async fn a_detached_target_counts_as_not_actionable() {
    let _serial = SERIAL.lock().await;
    let r = rig(two_page_site().detached("about"), SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let stale = &[("strategy", "test"), ("reason", "not_actionable")];
    let by_role = &[
        ("role", r.principal.0.as_str()),
        ("lane", "trusted_ui"),
        ("reason", "not_actionable"),
    ];
    let before = (
        counter(names::PROPOSALS_STALE, stale),
        counter(names::INTERACTIONS_DROPPED_UNACTIONABLE, by_role),
    );
    let out = r
        .handle
        .execute(r.admit(p, &c), QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.dropped, Some(DropReason::NotActionable));
    assert_eq!(counter(names::PROPOSALS_STALE, stale), before.0 + 1);
    assert_eq!(
        counter(names::INTERACTIONS_DROPPED_UNACTIONABLE, by_role),
        before.1 + 1
    );
}

#[tokio::test]
async fn a_crash_after_intent_counts_an_unknown_outcome_until_reconciled() {
    let _serial = SERIAL.lock().await;
    let script = two_page_site().crash_on(crawlx_browser::fake::action_key(ActionKind::Click, "about"));
    let fake = Arc::new(FakeBackend::new(script));
    let r = rig_with(fake.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let by_role = &[("role", r.principal.0.as_str()), ("lane", "trusted_ui")];
    let gauge = Metrics::global().gauge(names::INTERACTIONS_UNKNOWN_UNRECONCILED);
    let before = (
        counter(names::UNKNOWN_OUTCOME, &[]),
        counter(names::INTERACTIONS_UNKNOWN_OUTCOME, by_role),
        gauge.get(&[]).unwrap_or(0.0),
    );
    let err = r
        .handle
        .execute(r.admit(p, &c), QuiescencePolicy::default())
        .await
        .unwrap_err();
    let SessionError::CrashedDuringAction(id) = err else {
        panic!("{err:?}")
    };
    assert_eq!(counter(names::UNKNOWN_OUTCOME, &[]), before.0 + 1);
    assert_eq!(
        counter(names::INTERACTIONS_UNKNOWN_OUTCOME, by_role),
        before.1 + 1
    );
    assert!((gauge.get(&[]).unwrap_or(0.0) - (before.2 + 1.0)).abs() < f64::EPSILON);

    fake.script_handle().lock().crash_on_action = None;
    r.handle.reconcile(id).await.unwrap();
    assert!((gauge.get(&[]).unwrap_or(0.0) - before.2).abs() < f64::EPSILON);
}

#[tokio::test]
async fn a_t1_failure_counts_a_journal_halt() {
    let _serial = SERIAL.lock().await;
    let fake = Arc::new(FakeBackend::new(two_page_site()));
    let r = rig_with(fake.clone(), fake, true, SafetyProfile::ReadOnly).await;
    let flaky = r.flaky.clone().unwrap();
    let (bundle, cluster) = observe_cluster(&r).await;
    let (p, c) = r.proposal(&bundle, "About", cluster);
    let admitted = r.admit(p, &c);
    let before = (
        counter(names::JOURNAL_HALTS, &[]),
        hist_count(names::JOURNAL_T1_DURATION),
    );
    flaky.fail_intend.store(true, Ordering::SeqCst);
    let err = r
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::HaltedStorage(_)), "{err:?}");
    assert_eq!(counter(names::JOURNAL_HALTS, &[]), before.0 + 1);
    assert_eq!(
        hist_count(names::JOURNAL_T1_DURATION),
        before.1 + 1,
        "the failed intent is timed too"
    );
}
