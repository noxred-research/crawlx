//! False-causality simulation: 1,000 synthetic transitions in
//! which timers, polling and pushes reveal controls regardless of the action.
//! The attribution filter (baseline control, trusted lane, confounder
//! down-weighting) plus replay failures must keep timer-revealed targets from
//! becoming confident edges while true edges converge.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Duration, TimeZone, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::repo::EdgeRecord;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{ActionContextId, CrawlRunId, StateClusterId, TrustLane};
use crawlx_graph::{Confounders, EdgeTarget, EnablementGraph, TransitionObservation};
use rand::RngExt as _;
use std::collections::BTreeSet;
use uuid::Uuid;

const ACTIONS: u8 = 10;
const TIMERS: u8 = 3;
const TRANSITIONS: i64 = 1000;
/// Probability each timer target appears in any window, independent of the action.
const TIMER_RATE: f64 = 0.5;
/// Probability a true action reveals its target.
const TRUE_RATE: f64 = 0.95;
/// Probability the no-action control run also sees a timer that fired.
const BASELINE_CATCH: f64 = 0.6;
/// Probability the settle window shows polling/push traffic when a timer fired.
const CONFOUNDER_WHEN_TIMER: f64 = 0.5;

fn t0() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 1, 9, 0, 0).unwrap()
}
fn action(i: u8) -> ActionContextId {
    ActionContextId([i + 1; 16])
}
fn cluster(i: u8) -> StateClusterId {
    StateClusterId(Uuid::from_u128(u128::from(i) + 1))
}
fn true_target(i: u8) -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("sim/true", &[i]))
}
fn timer_target(j: u8) -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("sim/timer", &[j]))
}

struct SimResult {
    graph: EnablementGraph,
    /// `(p_success before the attempt, conclusive outcome)` for every transition
    /// that re-ran an action with a known exact edge in that cluster. The outcome
    /// follows the graph's own replay semantics: the target followed and the
    /// no-action baseline did not show it (success), or the target did not
    /// follow at all (failure); a target the baseline also revealed is
    /// inconclusive and is not a pair.
    pairs: Vec<(f64, bool)>,
}

fn simulate(seed: u64, filtered: bool) -> SimResult {
    let mut rng = CrawlSeed(seed).rng("graph-sim", &[]);
    let mut g = EnablementGraph::new(CrawlRunId(Uuid::from_u128(7)));
    let mut pairs = Vec::new();
    for i in 0..TRANSITIONS {
        let a = rng.random_range(0..ACTIONS);
        let mut revealed: Vec<ElementIdentityHash> = Vec::new();
        let mut baseline: Vec<ElementIdentityHash> = Vec::new();
        let mut timer_fired = false;
        if rng.random_bool(TRUE_RATE) {
            revealed.push(true_target(a));
        }
        for j in 0..TIMERS {
            if rng.random_bool(TIMER_RATE) {
                timer_fired = true;
                revealed.push(timer_target(j));
                if filtered && rng.random_bool(BASELINE_CATCH) {
                    baseline.push(timer_target(j));
                }
            }
        }
        let busy = rng.random_bool(if timer_fired { CONFOUNDER_WHEN_TIMER } else { 0.05 });
        let confounders = if filtered && busy {
            Confounders {
                ws_frames: 0,
                polling: 2,
                mutation_volatile_ratio: 0.1,
            }
        } else {
            Confounders::default()
        };
        let now = t0() + Duration::seconds(i);
        for e in g.edges_in(&crawlx_graph::EdgeContext::Cluster(cluster(a))) {
            if e.source != action(a) {
                continue;
            }
            let EdgeTarget::Identity(h) = e.target else {
                continue;
            };
            let followed = revealed.contains(&h);
            let ambient = baseline.contains(&h);
            if followed && ambient {
                continue;
            }
            pairs.push((e.p_success(now), followed));
        }
        g.observe_transition(&TransitionObservation {
            source: action(a),
            family: None,
            before_cluster: cluster(a),
            after_cluster: cluster(a),
            revealed,
            baseline_revealed: baseline,
            confounders,
            latency_ms: Some(120),
            lane: TrustLane::TrustedUi,
            now,
        });
    }
    SimResult { graph: g, pairs }
}

fn end() -> DateTime<Utc> {
    t0() + Duration::seconds(TRANSITIONS)
}

/// `(false edges with p >= 0.6, edges to timer targets)`.
fn false_causality(g: &EnablementGraph) -> (usize, usize) {
    let timers: BTreeSet<ElementIdentityHash> = (0..TIMERS).map(timer_target).collect();
    let mut total = 0;
    let mut confident = 0;
    for e in g.edges() {
        if let EdgeTarget::Identity(h) = e.target {
            if timers.contains(&h) {
                total += 1;
                if e.p_success(end()) >= 0.6 {
                    confident += 1;
                }
            }
        }
    }
    (confident, total)
}

#[test]
fn timer_revealed_targets_do_not_become_confident_edges() {
    let g = simulate(42, true).graph;
    let (confident, total) = false_causality(&g);
    assert!(total >= 20, "timer edges were created and exercised: {total}");
    let rate = confident as f64 / total as f64;
    assert!(rate < 0.05, "false-causality rate {rate} ({confident}/{total})");
}

#[test]
fn true_edges_converge_above_point_eight() {
    let g = simulate(42, true).graph;
    for a in 0..ACTIONS {
        let e = g
            .find(
                &crawlx_graph::EdgeContext::Cluster(cluster(a)),
                action(a),
                &EdgeTarget::Identity(true_target(a)),
            )
            .unwrap();
        let p = e.p_success(end());
        assert!(
            p >= 0.8,
            "action {a}: p = {p} (support {}, failures {})",
            e.support,
            e.failures
        );
    }
}

#[test]
fn without_the_filters_timers_would_look_causal() {
    // Control experiment: with no baseline run and no confounder flags, timer
    // edges track the raw coincidence rate (~0.5), far above the filtered value.
    let filtered = simulate(42, true).graph;
    let naive = simulate(42, false).graph;
    let mean_p = |g: &EnablementGraph| {
        let timers: BTreeSet<ElementIdentityHash> = (0..TIMERS).map(timer_target).collect();
        let ps: Vec<f64> = g
            .edges()
            .filter(|e| matches!(e.target, EdgeTarget::Identity(h) if timers.contains(&h)))
            .map(|e| e.p_success(end()))
            .collect();
        ps.iter().sum::<f64>() / ps.len() as f64
    };
    assert!(
        mean_p(&naive) > mean_p(&filtered) + 0.15,
        "{} vs {}",
        mean_p(&naive),
        mean_p(&filtered)
    );
}

#[test]
fn rate_holds_across_seeds() {
    for seed in 1..=5 {
        let g = simulate(seed, true).graph;
        let (confident, total) = false_causality(&g);
        assert!((confident as f64) / (total as f64) < 0.05, "seed {seed}");
    }
}

#[test]
fn simulation_is_deterministic_and_dump_round_trips() {
    let a = simulate(9, true).graph;
    let b = simulate(9, true).graph;
    let ra: Vec<EdgeRecord> = a.dump();
    assert_eq!(ra, b.dump());
    let mut c = EnablementGraph::new(a.run());
    c.load(ra.clone());
    assert_eq!(c.dump(), ra);
}

/// Calibration check: bucket `p_success` predictions
/// against replay outcomes; expected calibration error at most 0.10. The
/// corpus is the filtered simulation over several seeds (true edges and
/// timer-revealed decoys alike); the ECE is reported over 10 equal-width bins
/// (the gate) and over 15 equal-mass bins.
#[test]
fn p_success_is_calibrated_within_point_one_on_the_simulation_corpus() {
    use crawlx_graph::{
        calibration_bins, calibration_bins_equal_mass, expected_calibration_error,
        expected_calibration_error_equal_mass,
    };
    let mut pairs: Vec<(f64, bool)> = Vec::new();
    for seed in [1, 2, 3, 5, 8, 13, 42] {
        pairs.extend(simulate(seed, true).pairs);
    }
    assert!(pairs.len() >= 5_000, "replayed edges: {}", pairs.len());
    assert!(pairs.iter().all(|(p, _)| *p > 0.0 && *p < 1.0));

    let ece = expected_calibration_error(&pairs, 10);
    let ece_mass = expected_calibration_error_equal_mass(&pairs, 15);
    eprintln!(
        "calibration: {} pairs, ECE(10 equal-width) = {ece:.4}, ECE(15 equal-mass) = {ece_mass:.4}",
        pairs.len()
    );
    for b in calibration_bins(&pairs, 10) {
        eprintln!(
            "  width [{:.1}, {:.1}) n={:5} predicted={:.3} observed={:.3} gap={:.3}",
            b.lo,
            b.hi,
            b.count,
            b.mean_predicted,
            b.observed_rate,
            b.gap()
        );
    }
    for b in calibration_bins_equal_mass(&pairs, 15) {
        eprintln!(
            "  mass  [{:.3}, {:.3}] n={:5} predicted={:.3} observed={:.3} gap={:.3}",
            b.lo,
            b.hi,
            b.count,
            b.mean_predicted,
            b.observed_rate,
            b.gap()
        );
    }
    assert!(ece <= 0.10, "ECE over 10 equal-width bins = {ece}");
    assert!(ece_mass <= 0.10, "ECE over 15 equal-mass bins = {ece_mass}");
}
