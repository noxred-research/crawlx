//! Ablation matrix, the exploration driver and trace replay over `FakeBackend` (no network, no
//! browser): the fake is scripted from the gym manifests and its performed-click log feeds a
//! simulated ledger.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_bench::ablation::{self, AblationRunner, FakeExecutor};
use crawlx_bench::driver::{self, DriverConfig};
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::replay::{ReplayHarness, StrategyConfig, Trace};
use crawlx_bench::scorecard::Scorecard;
use crawlx_browser::fake::FakeBackend;
use std::path::PathBuf;

const BASE: &str = "http://gym.test";

fn executor(max_actions: usize) -> FakeExecutor {
    FakeExecutor {
        base_url: BASE.to_owned(),
        config: DriverConfig {
            max_actions,
            ..DriverConfig::default()
        },
    }
}

#[tokio::test]
async fn matrix_a0_to_a7_runs_against_g21_and_scores_enablement() {
    let manifest = FixtureManifest::embedded("g21").unwrap();
    let ex = executor(40);
    let runner = AblationRunner::new(&ex);
    let variants: Vec<_> = ablation::matrix().into_iter().take(8).collect();
    let report = runner.run(&variants, &manifest, &[1, 2]).await.unwrap();
    assert_eq!(report.outcomes.len(), 16);

    for o in &report.outcomes {
        let sc = &o.scorecard;
        assert_eq!(sc.fixture, "g21");
        assert_eq!(sc.safety.unauthorized, 0);
        if o.variant == "A0" {
            // URL plane only: nothing interactive is ever exercised.
            assert!(sc.coverage.trusted.abs() < 1e-12);
            continue;
        }
        // All six controls of g21 (x1, x2, y, a, b, z) are exercised once each.
        assert!(
            (sc.coverage.trusted - 1.0).abs() < 1e-12,
            "{} seed {}: {}",
            o.variant,
            o.seed,
            sc.render_markdown()
        );
        assert!((sc.targets.overall.recall - 1.0).abs() < 1e-12, "{}", o.variant);
        assert!(sc.targets.overall.precision > 0.99, "{}", o.variant);
        assert!(sc.lanes.unwrap().trusted_share > 0.999);
        assert!(sc.quiescence_timeout_rate.unwrap().abs() < 1e-12);
        assert!(sc.stale_proposal_rate.unwrap().abs() < 1e-12);
        let e = sc.enablement.as_ref().unwrap();
        // The fake reveals y after its last prerequisite (x2) and b after a: both recorded, none spurious.
        assert_eq!(e.spurious, 0, "{}", o.variant);
        assert!(e.recorded >= 2, "{}", o.variant);
        assert!(e.recall.unwrap() > 0.6, "{}", o.variant);
    }
    let means = report.means();
    assert_eq!(means.len(), 8);
    assert!(means
        .iter()
        .skip(1)
        .all(|(_, cov, auc)| (*cov - 1.0).abs() < 1e-12 && *auc > 0.0));
    let md = report.render_markdown();
    assert!(md.contains("| A4 |") && md.contains("# Ablation: g21"));

    // The matrix has 13 rows; A8..A12 need the worker and are refused, not silently weakened.
    let a8 = ablation::find("A8").unwrap();
    let err = runner.run(&[a8], &manifest, &[1]).await.unwrap_err().to_string();
    assert!(
        err.contains("phase-2 pathfinding") && err.contains("crawlx_worker"),
        "{err}"
    );
}

#[tokio::test]
async fn paired_runs_compare_variants_seed_by_seed() {
    let manifest = FixtureManifest::embedded("g21").unwrap();
    let ex = executor(40);
    let runner = AblationRunner::new(&ex);
    let (a0, a1) = (ablation::find("A0").unwrap(), ablation::find("A1").unwrap());
    let seeds = crawlx_bench::stats::SeedSets::committed().unwrap();
    let nightly = seeds.seeds("nightly").unwrap();
    let (report, paired) = runner.run_paired(&a0, &a1, &manifest, nightly).await.unwrap();
    // A then B per seed: outcomes interleave in seed order.
    let order: Vec<(&str, u64)> = report.outcomes.iter().map(|o| (o.variant, o.seed)).collect();
    assert_eq!(order[0], ("A0", nightly[0]));
    assert_eq!(order[1], ("A1", nightly[0]));
    assert_eq!(order.len(), nightly.len() * 2);
    assert_eq!(paired.seeds, nightly);
    // Browser plane on g21 covers everything, URL plane nothing: a constant +1.0 difference.
    assert!((paired.coverage.bootstrap.mean_diff - 1.0).abs() < 1e-12);
    assert!(paired.is_improvement());
    assert!(paired.auc.is_improvement());
    assert!(paired.t80.is_none(), "A0 never reaches 80%, so T80 has no pairs");
    let p = paired.coverage.wilcoxon.as_ref().unwrap().p_two_sided;
    // n all-positive pairs: the exact two-sided signed-rank p is 2 / 2^n
    let n = u32::try_from(nightly.len()).unwrap();
    let expected = 2.0 / f64::from(1u32 << n);
    assert!(
        (p - expected).abs() < 1e-12,
        "{n} all-positive pairs: p = 2/2^{n}, got {p}"
    );
    let md = paired.render_markdown();
    assert!(
        md.contains(&format!("# Paired: A1 vs A0 on g21 ({n} seeds)")) && md.contains("coverage.trusted")
    );

    // Same variant twice: every pair ties, nothing is "better".
    let same = report.compare_paired("A1", "A1").unwrap();
    assert!(!same.is_improvement());
    assert!(same.coverage.wilcoxon.is_none());
    assert!(same.t80.is_some(), "A1 reaches 80% under every seed");
    assert!(!same.t80.unwrap().is_improvement());

    assert!(report.compare_paired("A0", "A9").is_err());
}

/// Every outcome carries actions per hidden target reached.
/// On the simulated gym every variant with a browser reaches the hidden controls of G11
/// (`g21`: `y`, `b`) and G13 (18 menu items), so the metric is defined and bounded by the
/// budget; the URL-plane row reaches none. A8 needs the worker (see the private authored
/// efficiency experiment in `worker_exec`'s unit tests for the comparison on real Chromium).
#[tokio::test]
async fn efficiency_reports_actions_per_hidden_target_on_g21_and_g13() {
    let ex = executor(60);
    let runner = AblationRunner::new(&ex);
    let variants: Vec<_> = ablation::matrix().into_iter().take(8).collect();
    for (fixture, hidden) in [("g21", 2u64), ("g13", 18u64)] {
        let manifest = FixtureManifest::embedded(fixture).unwrap();
        let report = runner.run(&variants, &manifest, &[1, 2]).await.unwrap();
        for o in &report.outcomes {
            let e = &o.efficiency;
            assert_eq!(e.hidden_total, hidden, "{fixture} {}", o.variant);
            // The fake executes every journaled action, so the executed count is the row count.
            assert_eq!(
                e.actions,
                o.scorecard.lanes.map_or(0, |l| l.trusted + l.diagnostic)
            );
            if o.variant == "A0" {
                assert_eq!(e.hidden_reached, 0);
                assert!(e.actions_per_hidden_target.is_none() && e.hidden_recall == Some(0.0));
                continue;
            }
            assert_eq!(
                e.hidden_reached, hidden,
                "{fixture} {} seed {}",
                o.variant, o.seed
            );
            assert!((e.hidden_recall.unwrap() - 1.0).abs() < 1e-12);
            let per = e.actions_per_hidden_target.unwrap();
            // Every hidden target costs at least its own action; the budget bounds the rest.
            assert!(
                per >= 1.0 && per <= 60.0 / hidden as f64,
                "{fixture} {}: {per}",
                o.variant
            );
        }
        let means = report.efficiency_means();
        assert_eq!(means.len(), 8);
        assert_eq!(means[0], ("A0", Some(0.0), None));
        assert!(means[1..].iter().all(|(_, r, a)| *r == Some(1.0) && a.is_some()));
        // The graph row (A7) spends no more actions per hidden target than the reveal-bonus row (A6).
        let per = |id: &str| means.iter().find(|(v, _, _)| *v == id).unwrap().2.unwrap();
        assert!(
            per("A7") <= per("A6") + 1e-9,
            "{fixture}: A7 {} vs A6 {}",
            per("A7"),
            per("A6")
        );
        let md = report.render_markdown();
        assert!(md.contains("| Hidden recall | Actions/hidden |"), "{md}");
        eprintln!("{fixture} efficiency: {means:?}");
    }
}

#[tokio::test]
async fn queue_order_is_seeded_document_order_is_not() {
    let manifest = FixtureManifest::embedded("g01").unwrap();
    let ex = executor(60);
    let click_order = |variant: &'static str, seed: u64| {
        let ex = &ex;
        let manifest = &manifest;
        async move {
            let v = ablation::find(variant).unwrap();
            use crawlx_bench::ablation::VariantExecutor as _;
            let run = ex.execute(&v, manifest, seed).await.unwrap();
            run.ledger
                .clicks("g01")
                .into_iter()
                .map(|(c, _)| c)
                .collect::<Vec<_>>()
        }
    };
    // Document order (A2): identical for every seed and in manifest order.
    let a = click_order("A2", 1).await;
    let b = click_order("A2", 2).await;
    assert_eq!(a, b);
    assert_eq!(a.len(), 40);
    assert_eq!(a[0], "c01");
    assert_eq!(a[39], "c40");
    // Queue with seeded tie-breaks (A4): same seed identical, different seed different order, same set.
    let q1 = click_order("A4", 1).await;
    let q1_again = click_order("A4", 1).await;
    let q2 = click_order("A4", 2).await;
    assert_eq!(
        q1, q1_again,
        "same seed must reproduce the run (Jaccard 1.0, same order)"
    );
    assert_ne!(q1, q2, "tie-breaks derive from the seed");
    let mut s1 = q1.clone();
    let mut s2 = q2;
    s1.sort();
    s2.sort();
    assert_eq!(s1, s2);
    assert_eq!(s1.len(), 40);
}

#[tokio::test]
async fn run_to_run_jaccard_is_one_for_equal_seeds_and_budget_limits_coverage() {
    let manifest = FixtureManifest::embedded("g01").unwrap();
    let ex = executor(10);
    let runner = AblationRunner::new(&ex);
    let v = [ablation::find("A4").unwrap()];
    let same = runner.run(&v, &manifest, &[5, 5]).await.unwrap();
    let a = &same.outcomes[0].scorecard;
    let b = &same.outcomes[1].scorecard;
    assert!((a.clone().with_run_to_run(b).run_to_run_jaccard.unwrap() - 1.0).abs() < 1e-12);
    // 10 actions of 40 controls: partial coverage, T50 never reached, AUC in (0, 1].
    assert!(
        (a.coverage.trusted - 0.25).abs() < 1e-12,
        "{}",
        a.coverage.trusted
    );
    assert_eq!(a.coverage.t50, None);
    assert!(a.coverage.auc > 0.0 && a.coverage.auc <= 1.0);
    // Different seeds pick different controls first, so the exercised sets differ.
    let other = runner.run(&v, &manifest, &[6]).await.unwrap();
    let j = a
        .clone()
        .with_run_to_run(&other.outcomes[0].scorecard)
        .run_to_run_jaccard
        .unwrap();
    assert!((0.0..1.0).contains(&j), "{j}");
}

#[tokio::test]
async fn driver_refuses_fixtures_with_forbidden_effects() {
    let manifest = FixtureManifest::embedded("g25").unwrap();
    let ex = executor(10);
    let v = ablation::find("A4").unwrap();
    use crawlx_bench::ablation::VariantExecutor as _;
    let err = ex
        .execute(&v, &manifest, 1)
        .await
        .err()
        .expect("must refuse")
        .to_string();
    assert!(err.contains("forbidden backend effects"), "{err}");
}

fn traces_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/traces")
}

/// Record the golden traces. Run with `CRAWLX_BLESS_TRACES=1 cargo test -p crawlx-bench --test ablation bless -- --ignored`.
#[tokio::test]
#[ignore = "writes fixtures/traces; run explicitly to re-bless"]
async fn bless_golden_traces() {
    if std::env::var_os("CRAWLX_BLESS_TRACES").is_none() {
        return;
    }
    std::fs::create_dir_all(traces_dir()).unwrap();
    for (fixture, variant, seed) in [("g21", "A6", 11u64), ("g03", "A4", 3)] {
        let trace = record(fixture, variant, seed).await;
        std::fs::write(
            traces_dir().join(format!("{fixture}-{}.json", variant.to_lowercase())),
            trace.to_json().unwrap(),
        )
        .unwrap();
    }
}

async fn record(fixture: &str, variant: &str, seed: u64) -> Trace {
    let manifest = FixtureManifest::embedded(fixture).unwrap();
    let v = ablation::find(variant).unwrap();
    let script = ablation::script_from_manifest(&manifest, BASE).unwrap();
    let backend = FakeBackend::new(script);
    let cfg = DriverConfig::default();
    driver::run_variant_traced(&backend, &v, &manifest, BASE, seed, &cfg)
        .await
        .unwrap()
        .1
}

#[tokio::test]
async fn recorded_trace_replays_identically_under_the_same_configuration() {
    for (fixture, variant, seed) in [("g21", "A6", 11u64), ("g03", "A4", 3), ("g01", "A5", 9)] {
        let trace = record(fixture, variant, seed).await;
        assert!(!trace.steps.is_empty(), "{fixture}");
        let v = ablation::find(variant).unwrap();
        let r = ReplayHarness::replay(&trace, StrategyConfig::from_variant(&v, seed, 1));
        assert!(r.identical(), "{fixture} {variant}: {:?}", r.first_divergence());
        assert!((r.agreement - 1.0).abs() < 1e-12 && (r.top3 - 1.0).abs() < 1e-12);
        assert!((r.coverage_curve.last().copied().unwrap() - 1.0).abs() < 1e-9 || trace.steps.len() < 100);
        // JSON round trip keeps replay identical
        let back = Trace::from_json(&trace.to_json().unwrap()).unwrap();
        assert_eq!(back, trace);
    }
}

#[tokio::test]
async fn a_different_seed_or_policy_diverges_from_the_recorded_trace() {
    let trace = record("g01", "A4", 9).await;
    let a4 = ablation::find("A4").unwrap();
    let other_seed = ReplayHarness::replay(&trace, StrategyConfig::from_variant(&a4, 10, 1));
    assert!(!other_seed.identical());
    assert!(other_seed.agreement < 1.0);
    assert!(other_seed.top3 >= other_seed.agreement);
    let doc_order = ablation::find("A2").unwrap();
    let r = ReplayHarness::replay(&trace, StrategyConfig::from_variant(&doc_order, 9, 1));
    assert!(!r.identical());
    assert!(r.first_divergence().is_some());
}

#[tokio::test]
async fn golden_traces_on_disk_match_a_fresh_recording() {
    let dir = traces_dir();
    let mut checked = 0;
    for (fixture, variant, seed) in [("g21", "A6", 11u64), ("g03", "A4", 3)] {
        let path = dir.join(format!("{fixture}-{}.json", variant.to_lowercase()));
        if !path.exists() {
            panic!(
                "golden trace {} missing; re-bless with CRAWLX_BLESS_TRACES=1",
                path.display()
            );
        }
        let golden = Trace::load(&path).unwrap();
        let fresh = record(fixture, variant, seed).await;
        assert_eq!(
            golden,
            fresh,
            "{}: recording drifted from the golden trace",
            path.display()
        );
        let v = ablation::find(variant).unwrap();
        let r = ReplayHarness::replay(&golden, StrategyConfig::from_variant(&v, seed, 1));
        assert!(r.identical(), "{}", path.display());
        checked += 1;
    }
    assert_eq!(checked, 2);
}

#[tokio::test]
async fn scorecard_from_a_driver_run_reports_identity_rates() {
    // g06 template identity: all `Like` buttons are one logical control; `Open` links differ by destination.
    let manifest = FixtureManifest::embedded("g03").unwrap();
    let ex = executor(40);
    use crawlx_bench::ablation::VariantExecutor as _;
    let v = ablation::find("A3").unwrap();
    let run = ex.execute(&v, &manifest, 1).await.unwrap();
    let sc = Scorecard::compute(&manifest, &run.rows, &run.ledger);
    let id = sc.identity.expect("labelled observations produce identity rates");
    assert!((0.0..=1.0).contains(&id.collision_rate) && (0.0..=1.0).contains(&id.split_rate));
    assert!(
        id.split_rate.abs() < 1e-12,
        "static fake page: identities never split"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn golden_traces_replay_through_the_production_strategies_arbiter_and_kernel() {
    use crawlx_bench::strategy_replay::StrategiesDecision;
    use crawlx_core::config::SafetyProfile;
    for (fixture, variant, seed) in [("g21", "A6", 11u64), ("g03", "A4", 3)] {
        let path = traces_dir().join(format!("{fixture}-{}.json", variant.to_lowercase()));
        let golden = Trace::load(&path).unwrap();
        let v = ablation::find("A7").unwrap();
        let mut production = StrategiesDecision::new(&v, seed, SafetyProfile::TestEnvironment).unwrap();
        let r = ReplayHarness::replay_with(&mut production, &golden);
        assert_eq!(r.steps.len(), golden.steps.len(), "{fixture}");
        assert!(r.decision_fn.contains("A7"), "{}", r.decision_fn);
        // The production path decides on the recorded snapshots: every step produced a ranking
        // that contains snapshot controls only, and the recorded choice is among the ranked ones
        // for most steps (the queue baseline and the arbiter agree on candidates, not on order).
        assert_eq!(
            r.undecided,
            0,
            "{fixture}: {:?}",
            r.steps.iter().filter(|s| s.decided.is_none()).collect::<Vec<_>>()
        );
        for (s, step) in r.steps.iter().zip(&golden.steps) {
            let decided = s.decided.as_ref().unwrap();
            assert!(
                step.snapshot.controls.iter().any(|c| &c.context_id == decided),
                "{fixture}: {decided}"
            );
        }
        // g21 is simple enough that the recorded choice is nearly always among production's top three; g03's
        // tabs and menu items are ranked differently (and some are never proposed), which is exactly
        // the kind of divergence the harness exists to expose.
        if fixture == "g21" {
            assert!(
                r.agreement > 0.0 && r.top3 >= 0.8,
                "{fixture}: agreement {} top3 {}",
                r.agreement,
                r.top3
            );
        }
        assert!(r.top3 >= r.agreement);
        assert!((0.0..=1.0).contains(&r.agreement));
        // Deterministic: the same production configuration replays to the same decisions.
        let mut again = StrategiesDecision::new(&v, seed, SafetyProfile::TestEnvironment).unwrap();
        let r2 = ReplayHarness::replay_with(&mut again, &golden);
        assert_eq!(
            r.steps.iter().map(|s| s.decided.clone()).collect::<Vec<_>>(),
            r2.steps.iter().map(|s| s.decided.clone()).collect::<Vec<_>>(),
            "{fixture}"
        );
    }
}
