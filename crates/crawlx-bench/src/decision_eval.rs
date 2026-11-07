//! Evaluation of a trained System 1 model against the gym.
//!
//! * [`MeteredEngine`]: wraps any `DecisionEngine` and counts calls, abstentions and errors and
//!   keeps the end-to-end latency of every call (what the worker waits for, queueing and
//!   tokenization included).
//! * [`pooled_comparison`]: the paired A9-vs-A10 comparison pooled over fixtures and seeds, the
//!   source of the G3 `coverage_gain_ci_low`.
//! * [`ece_equal_mass`]: expected calibration error over equal-mass bins.
//! * [`analyze_shadow`]: the shadow-comparison job over recorded
//!   `model_decisions` joined with the run's shortlist events: agreement with the arbiter,
//!   counterfactual coverage by hindsight replay, top-k recall of novel actions, and the
//!   calibration of the model's confidence on the outcomes the live crawls produced.
//! * [`assemble_g3`]: the `G3Report` of [`crate::gates`] from the measured pieces.

use crate::decision_dataset::{Hindsight, Outcome};
use crate::error::BenchError;
use crate::gates::G3Report;
use crate::stats::{Direction, PairedComparison, DEFAULT_LEVEL, DEFAULT_RESAMPLES};
use async_trait::async_trait;
use crawlx_model::breaker::BreakerState;
use crawlx_model::{DecisionEngine, ModelError, ModelId, TypedDecision, TypedDecisionRequest};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Nearest-rank percentile `q` in `[0, 1]` of `sorted` (ascending); `0.0` when empty.
#[must_use]
pub fn percentile(sorted: &[f64], q: f64) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    // nearest rank: the smallest index whose cumulative share reaches `q`
    let at = (0..n)
        .find(|i| {
            let share = f64::from(u32::try_from(i + 1).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(n).unwrap_or(u32::MAX));
            share >= q
        })
        .unwrap_or(n - 1);
    sorted[at]
}

/// Call counts and latency of a [`MeteredEngine`].
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct EngineStats {
    /// Calls made.
    pub calls: u64,
    /// Calls that returned an error (breaker open, timeout, malformed output, ...).
    pub errors: u64,
    /// Answered calls whose choice question abstained.
    pub abstained: u64,
    /// Answered calls whose choice question selected a candidate.
    pub selected: u64,
    /// Median end-to-end latency in milliseconds.
    pub p50_ms: f64,
    /// 95th percentile latency in milliseconds (nearest rank).
    pub p95_ms: f64,
    /// Slowest call in milliseconds.
    pub max_ms: f64,
}

/// A [`DecisionEngine`] that forwards to `inner` and measures every call.
pub struct MeteredEngine {
    inner: Arc<dyn DecisionEngine>,
    calls: AtomicU64,
    errors: AtomicU64,
    abstained: AtomicU64,
    selected: AtomicU64,
    latencies_ms: Mutex<Vec<f64>>,
}

impl MeteredEngine {
    /// Meter `inner`.
    #[must_use]
    pub fn new(inner: Arc<dyn DecisionEngine>) -> Self {
        Self {
            inner,
            calls: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            abstained: AtomicU64::new(0),
            selected: AtomicU64::new(0),
            latencies_ms: Mutex::new(Vec::new()),
        }
    }

    /// The counters and latency percentiles so far.
    #[must_use]
    pub fn stats(&self) -> EngineStats {
        let mut lat = self.latencies_ms.lock().clone();
        lat.sort_by(f64::total_cmp);
        EngineStats {
            calls: self.calls.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            abstained: self.abstained.load(Ordering::Relaxed),
            selected: self.selected.load(Ordering::Relaxed),
            p50_ms: percentile(&lat, 0.5),
            p95_ms: percentile(&lat, 0.95),
            max_ms: lat.last().copied().unwrap_or(0.0),
        }
    }
}

#[async_trait]
impl DecisionEngine for MeteredEngine {
    async fn decide(&self, req: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
        let started = Instant::now();
        let result = self.inner.decide(req).await;
        self.latencies_ms
            .lock()
            .push(started.elapsed().as_secs_f64() * 1000.0);
        self.calls.fetch_add(1, Ordering::Relaxed);
        match &result {
            Ok(d) => {
                self.abstained.fetch_add(
                    u64::try_from(d.abstained.len()).unwrap_or(u64::MAX),
                    Ordering::Relaxed,
                );
                if d.answers.iter().any(|a| {
                    matches!(
                        a,
                        crawlx_model::TypedAnswer::Choice {
                            selected: Some(_),
                            ..
                        }
                    )
                }) {
                    self.selected.fetch_add(1, Ordering::Relaxed);
                }
            }
            Err(_) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }

    fn id(&self) -> &ModelId {
        self.inner.id()
    }

    fn breaker_state(&self) -> Option<BreakerState> {
        self.inner.breaker_state()
    }
}

/// One expected-calibration-error bin.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct EceBin {
    /// Predictions in the bin.
    pub n: usize,
    /// Mean confidence.
    pub confidence: f64,
    /// Fraction correct.
    pub accuracy: f64,
}

/// ECE over `bins` equal-mass bins of `(confidence, correct)` pairs: sort by confidence, cut
/// into near-equal counts, `Σ n_b/N · |accuracy_b − confidence_b|`. `None` for no samples.
#[must_use]
pub fn ece_equal_mass(samples: &[(f64, bool)], bins: usize) -> Option<(f64, Vec<EceBin>)> {
    if samples.is_empty() || bins == 0 {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    let n = sorted.len();
    let bins = bins.min(n);
    let mut out = Vec::with_capacity(bins);
    let mut ece = 0.0;
    for b in 0..bins {
        let (lo, hi) = (b * n / bins, (b + 1) * n / bins);
        let chunk = &sorted[lo..hi];
        let count = chunk.len() as f64;
        let conf = chunk.iter().map(|s| s.0).sum::<f64>() / count;
        let acc = chunk.iter().filter(|s| s.1).count() as f64 / count;
        ece += count / n as f64 * (acc - conf).abs();
        out.push(EceBin {
            n: chunk.len(),
            confidence: conf,
            accuracy: acc,
        });
    }
    Some((ece, out))
}

/// Trusted coverage of one fixture and seed under the baseline and the candidate variant.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PairedRun {
    /// Fixture id.
    pub fixture: String,
    /// Seed both variants ran with.
    pub seed: u64,
    /// Trusted coverage of the baseline variant.
    pub baseline: f64,
    /// Trusted coverage of the candidate variant.
    pub candidate: f64,
    /// Interaction-weighted coverage AUC of the baseline.
    pub baseline_auc: f64,
    /// Interaction-weighted coverage AUC of the candidate.
    pub candidate_auc: f64,
    /// Executed actions of the candidate run (journal rows past `proposed`).
    pub candidate_executed: u64,
    /// Executed mutating effects the manifest forbids under the profile, candidate run.
    pub candidate_unauthorized: u64,
    /// Executed actions counted by the safety metrics, candidate run.
    pub candidate_safety_executed: u64,
}

/// Paired comparison of trusted coverage over all `runs` (candidate minus baseline).
///
/// # Errors
/// [`BenchError::Stats`] with fewer than two runs.
pub fn pooled_comparison(
    metric: &str,
    runs: &[PairedRun],
    auc: bool,
) -> Result<PairedComparison, BenchError> {
    let labels: Vec<u64> = (0..runs.len() as u64).collect();
    let (b, c): (Vec<f64>, Vec<f64>) = runs
        .iter()
        .map(|r| {
            if auc {
                (r.baseline_auc, r.candidate_auc)
            } else {
                (r.baseline, r.candidate)
            }
        })
        .unzip();
    Ok(PairedComparison::compute(
        metric,
        &labels,
        &b,
        &c,
        Direction::HigherIsBetter,
        DEFAULT_RESAMPLES,
        DEFAULT_LEVEL,
    )?)
}

// ---- shadow comparison ---------------------------------------------------------------------

/// One recorded System 1 decision joined with its run's events.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ShadowDecision {
    /// Fixture the run crawled.
    pub fixture: String,
    /// Run id (the unit of the bootstrap).
    pub run: String,
    /// Calibrated probability per shortlist entry (all of them, abstained or not).
    pub probs: Vec<f32>,
    /// Calibrated `none of these` mass.
    pub none_p: f32,
    /// Index the confidence gate accepted.
    pub selected: Option<usize>,
    /// Index of the deterministic pre-score leader.
    pub deterministic_top: usize,
    /// Index of the action the arbiter executed, when it was on the shortlist.
    pub executed: Option<usize>,
    /// Hindsight outcome of every candidate (first execution at or after the decision).
    pub hindsight: Vec<Option<Hindsight>>,
    /// Outcome of the executed action.
    pub outcome: Option<Outcome>,
    /// Engine latency of the call in milliseconds.
    pub latency_ms: Option<u32>,
    /// Calibration version recorded on the row.
    pub calibration_version: Option<String>,
    /// Circuit breaker state recorded on the row.
    pub breaker_state: Option<String>,
}

impl ShadowDecision {
    /// Index of the highest probability (ties: the lowest index).
    #[must_use]
    pub fn top(&self) -> Option<usize> {
        let mut best: Option<(usize, f32)> = None;
        for (i, p) in self.probs.iter().enumerate() {
            if best.is_none_or(|(_, b)| *p > b) {
                best = Some((i, *p));
            }
        }
        best.map(|(i, _)| i)
    }

    fn novel(&self, i: usize) -> Option<bool> {
        self.hindsight.get(i).copied().flatten().map(|h| h.gain > 0)
    }

    fn gain(&self, i: usize) -> Option<u64> {
        self.hindsight.get(i).copied().flatten().map(|h| h.gain)
    }
}

/// Agreement of the model with the arbiter and the deterministic ranker.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct Agreement {
    /// Decisions where the executed action was on the shortlist.
    pub with_executed: u64,
    /// Model top-1 (ungated argmax) equals the executed action.
    pub top1_equals_executed: u64,
    /// Model top-1 equals the deterministic leader.
    pub top1_equals_deterministic: u64,
    /// Decisions the confidence gate accepted.
    pub gated: u64,
    /// Gated picks equal to the executed action.
    pub gated_equals_executed: u64,
    /// Gated picks equal to the deterministic leader.
    pub gated_equals_deterministic: u64,
    /// Share of decisions the gate abstained on.
    pub abstain_rate: f64,
}

/// Top-k recall of novel actions: over decisions with at least one novel labelled candidate, the
/// share where a novel candidate is among the top `k` of the ranking.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct TopKRecall {
    /// `k`.
    pub k: usize,
    /// Decisions with a novel labelled candidate.
    pub n: u64,
    /// Model ranking (by probability).
    pub model: f64,
    /// Deterministic ranking (shortlist order).
    pub deterministic: f64,
}

/// Counterfactual coverage by hindsight replay.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct Counterfactual {
    /// Decisions where both the model's pick and the executed action have a known gain.
    pub pairs: u64,
    /// Runs contributing at least one pair.
    pub runs: u64,
    /// Share of the model's picks that produced novelty (gain > 0).
    pub novel_rate_model: f64,
    /// Share of the executed actions that produced novelty.
    pub novel_rate_executed: f64,
    /// Mean novelty gain of the model's picks.
    pub mean_gain_model: f64,
    /// Mean novelty gain of the executed actions.
    pub mean_gain_executed: f64,
    /// Mean per-run difference model − executed of the mean gain, with its bootstrap interval.
    pub gain_diff: Option<(f64, f64, f64)>,
}

/// Calibration of the model's confidence on the outcomes of the live crawls.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct LiveCalibration {
    /// Decisions whose top-1 pick has a hindsight label.
    pub n: u64,
    /// ECE over 15 equal-mass bins of top-1 confidence versus "the top-1 pick produced novelty".
    pub ece: Option<f64>,
    /// Mean squared error of the top-1 confidence against that outcome.
    pub brier: Option<f64>,
    /// Reliability bins.
    pub bins: Vec<EceBin>,
}

/// The shadow-comparison report.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ShadowReport {
    /// Decisions analysed.
    pub decisions: u64,
    /// Distinct fixtures.
    pub fixtures: usize,
    /// Distinct runs.
    pub runs: usize,
    /// Decisions per fixture.
    pub per_fixture: BTreeMap<String, u64>,
    /// Rows without a calibration version (must be 0).
    pub calibration_version_missing: u64,
    /// Distinct calibration versions seen.
    pub calibration_versions: BTreeSet<String>,
    /// Rows recorded while the circuit breaker was not closed.
    pub breaker_not_closed: u64,
    /// Model call latency in milliseconds.
    pub latency_p50_ms: f64,
    /// 95th percentile of the model call latency in milliseconds.
    pub latency_p95_ms: f64,
    /// Agreement with the arbiter and the deterministic ranker.
    pub agreement: Agreement,
    /// Top-k recall of novel actions (k = 1, 3, 5).
    pub recall: Vec<TopKRecall>,
    /// Counterfactual coverage by hindsight replay.
    pub counterfactual: Counterfactual,
    /// Calibration on live outcomes.
    pub calibration: LiveCalibration,
}

fn rate(num: u64, den: u64) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64
    }
}

/// Compute the shadow report of `decisions`.
///
/// # Errors
/// [`BenchError::Stats`] only from the bootstrap of the counterfactual gain.
pub fn analyze_shadow(decisions: &[ShadowDecision]) -> Result<ShadowReport, BenchError> {
    let mut per_fixture: BTreeMap<String, u64> = BTreeMap::new();
    let mut runs: BTreeSet<&str> = BTreeSet::new();
    let mut versions = BTreeSet::new();
    let mut missing = 0;
    let mut not_closed = 0;
    let mut latencies: Vec<f64> = Vec::new();
    let mut agreement = Agreement::default();
    let mut abstained = 0_u64;
    for d in decisions {
        *per_fixture.entry(d.fixture.clone()).or_default() += 1;
        runs.insert(d.run.as_str());
        match &d.calibration_version {
            Some(v) => {
                versions.insert(v.clone());
            }
            None => missing += 1,
        }
        if d.breaker_state.as_deref().is_some_and(|s| s != "closed") {
            not_closed += 1;
        }
        if let Some(ms) = d.latency_ms {
            latencies.push(f64::from(ms));
        }
        let top = d.top();
        if let Some(e) = d.executed {
            agreement.with_executed += 1;
            agreement.top1_equals_executed += u64::from(top == Some(e));
        }
        agreement.top1_equals_deterministic += u64::from(top == Some(d.deterministic_top));
        match d.selected {
            Some(s) => {
                agreement.gated += 1;
                agreement.gated_equals_executed += u64::from(d.executed == Some(s));
                agreement.gated_equals_deterministic += u64::from(s == d.deterministic_top);
            }
            None => abstained += 1,
        }
    }
    let total = decisions.len() as u64;
    agreement.abstain_rate = rate(abstained, total);
    latencies.sort_by(f64::total_cmp);

    let mut recall = Vec::new();
    for k in [1_usize, 3, 5] {
        let (mut n, mut model, mut det) = (0_u64, 0_u64, 0_u64);
        for d in decisions {
            let positives: Vec<usize> = (0..d.hindsight.len())
                .filter(|i| d.novel(*i) == Some(true))
                .collect();
            if positives.is_empty() {
                continue;
            }
            n += 1;
            let mut order: Vec<usize> = (0..d.probs.len()).collect();
            order.sort_by(|a, b| d.probs[*b].total_cmp(&d.probs[*a]).then(a.cmp(b)));
            model += u64::from(order.iter().take(k).any(|i| positives.contains(i)));
            det += u64::from((0..d.probs.len().min(k)).any(|i| positives.contains(&i)));
        }
        recall.push(TopKRecall {
            k,
            n,
            model: rate(model, n),
            deterministic: rate(det, n),
        });
    }

    let counterfactual = counterfactual(decisions)?;

    let mut samples: Vec<(f64, bool)> = Vec::new();
    for d in decisions {
        let Some(top) = d.top() else { continue };
        let Some(novel) = d.novel(top) else { continue };
        samples.push((f64::from(d.probs[top]).clamp(0.0, 1.0), novel));
    }
    let brier = (!samples.is_empty()).then(|| {
        samples
            .iter()
            .map(|(p, y)| (p - f64::from(u8::from(*y))).powi(2))
            .sum::<f64>()
            / samples.len() as f64
    });
    let (ece, bins) = ece_equal_mass(&samples, 15).map_or((None, Vec::new()), |(e, b)| (Some(e), b));
    Ok(ShadowReport {
        decisions: total,
        fixtures: per_fixture.len(),
        runs: runs.len(),
        per_fixture,
        calibration_version_missing: missing,
        calibration_versions: versions,
        breaker_not_closed: not_closed,
        latency_p50_ms: percentile(&latencies, 0.5),
        latency_p95_ms: percentile(&latencies, 0.95),
        agreement,
        recall,
        counterfactual,
        calibration: LiveCalibration {
            n: samples.len() as u64,
            ece,
            brier,
            bins,
        },
    })
}

fn counterfactual(decisions: &[ShadowDecision]) -> Result<Counterfactual, BenchError> {
    // per run: (model gains, executed gains) over decisions where both are known
    let mut by_run: BTreeMap<&str, (Vec<u64>, Vec<u64>)> = BTreeMap::new();
    for d in decisions {
        let (Some(top), Some(e)) = (d.top(), d.executed) else {
            continue;
        };
        let (Some(model_gain), Some(executed_gain)) =
            (d.gain(top), d.outcome.map(|o| o.gain).or_else(|| d.gain(e)))
        else {
            continue;
        };
        let entry = by_run.entry(d.run.as_str()).or_default();
        entry.0.push(model_gain);
        entry.1.push(executed_gain);
    }
    let pairs: u64 = by_run.values().map(|(m, _)| m.len() as u64).sum();
    if pairs == 0 {
        return Ok(Counterfactual::default());
    }
    let all_model: Vec<u64> = by_run.values().flat_map(|(m, _)| m.iter().copied()).collect();
    let all_exec: Vec<u64> = by_run.values().flat_map(|(_, e)| e.iter().copied()).collect();
    let mean = |v: &[u64]| v.iter().sum::<u64>() as f64 / v.len() as f64;
    let novel = |v: &[u64]| v.iter().filter(|g| **g > 0).count() as f64 / v.len() as f64;
    let (run_model, run_exec): (Vec<f64>, Vec<f64>) =
        by_run.values().map(|(m, e)| (mean(m), mean(e))).unzip();
    let gain_diff = if run_model.len() >= 2 {
        let labels: Vec<u64> = (0..run_model.len() as u64).collect();
        let c = PairedComparison::compute(
            "counterfactual.gain",
            &labels,
            &run_exec,
            &run_model,
            Direction::HigherIsBetter,
            DEFAULT_RESAMPLES,
            DEFAULT_LEVEL,
        )?;
        Some((c.bootstrap.mean_diff, c.bootstrap.lo, c.bootstrap.hi))
    } else {
        None
    };
    Ok(Counterfactual {
        pairs,
        runs: by_run.len() as u64,
        novel_rate_model: novel(&all_model),
        novel_rate_executed: novel(&all_exec),
        mean_gain_model: mean(&all_model),
        mean_gain_executed: mean(&all_exec),
        gain_diff,
    })
}

// ---- G3 assembly ---------------------------------------------------------------------------

/// What `assemble_g3` takes from the measured pieces.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct G3Inputs<'a> {
    /// Held-out labelled decisions behind the calibration.
    pub calibration_samples: u64,
    /// ECE on the held-out families.
    pub ece: f64,
    /// Warm inference p95 in milliseconds.
    pub warm_p95_ms: f64,
    /// Paired runs of the nights, in order: one slice per night (seeds of the suite).
    pub nights: &'a [&'a [PairedRun]],
    /// Unauthorized actions and executed actions of the model-in-the-loop safety runs.
    pub safety: (u64, u64),
}

/// The [`G3Report`] for `inputs`: `seeds` and `coverage_gain_ci_low` come from the first night's
/// pooled paired comparison; `consecutive_nightly_improvements` counts the trailing nights whose
/// pooled interval excludes zero on the improving side with no unauthorized action.
///
/// # Errors
/// [`BenchError::Stats`] when a night has fewer than two paired runs.
pub fn assemble_g3(inputs: &G3Inputs<'_>) -> Result<G3Report, BenchError> {
    let mut consecutive = 0_u32;
    let mut first: Option<(u32, f64)> = None;
    for night in inputs.nights {
        let cmp = pooled_comparison("coverage.trusted", night, false)?;
        let seeds: BTreeSet<u64> = night.iter().map(|r| r.seed).collect();
        if first.is_none() {
            first = Some((u32::try_from(seeds.len()).unwrap_or(u32::MAX), cmp.bootstrap.lo));
        }
        let safe = night.iter().all(|r| r.candidate_unauthorized == 0);
        if cmp.is_improvement() && safe {
            consecutive += 1;
        } else {
            consecutive = 0;
        }
    }
    let (seeds, ci_low) = first.unwrap_or((0, f64::NEG_INFINITY));
    let (unauthorized, executed) = inputs.safety;
    Ok(G3Report {
        calibration_samples: inputs.calibration_samples,
        ece: inputs.ece,
        seeds,
        coverage_gain_ci_low: ci_low,
        unauthorized_action_rate: if executed == 0 {
            // nothing executed means nothing was measured: never report a clean zero for it
            1.0
        } else {
            unauthorized as f64 / executed as f64
        },
        warm_p95_ms: inputs.warm_p95_ms,
        consecutive_nightly_improvements: consecutive,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn percentile_is_nearest_rank() {
        let v: Vec<f64> = (1..=20).map(f64::from).collect();
        assert_eq!(percentile(&v, 0.5), 10.0);
        assert_eq!(percentile(&v, 0.95), 19.0);
        assert_eq!(percentile(&v, 1.0), 20.0);
        assert_eq!(percentile(&[], 0.95), 0.0);
        assert_eq!(percentile(&[7.0], 0.5), 7.0);
    }

    #[test]
    fn ece_equal_mass_matches_a_hand_computation() {
        // 4 samples, 2 bins: low bin conf 0.2/0.4 acc 0.0, high bin conf 0.8/0.9 acc 1.0
        let s = [(0.2, false), (0.4, false), (0.8, true), (0.9, true)];
        let (ece, bins) = ece_equal_mass(&s, 2).unwrap();
        assert_eq!(bins.len(), 2);
        assert!((ece - (0.5 * 0.3 + 0.5 * 0.15)).abs() < 1e-12);
        assert!(ece_equal_mass(&[], 15).is_none());
        // fewer samples than bins: one bin per sample
        let (_, b) = ece_equal_mass(&s[..3], 15).unwrap();
        assert_eq!(b.len(), 3);
        // a perfectly calibrated constant predictor has zero error (one bin: tied confidences
        // are cut by position, so several bins would split them arbitrarily)
        let calibrated: Vec<(f64, bool)> = (0..100).map(|i| (0.3, i < 30)).collect();
        assert!(ece_equal_mass(&calibrated, 1).unwrap().0 < 1e-9);
    }

    fn decision(run: &str, probs: &[f32], hind: &[Option<u64>], executed: Option<usize>) -> ShadowDecision {
        ShadowDecision {
            fixture: "g01".to_owned(),
            run: run.to_owned(),
            probs: probs.to_vec(),
            none_p: 0.1,
            selected: None,
            deterministic_top: 0,
            executed,
            hindsight: hind
                .iter()
                .map(|g| g.map(|gain| Hindsight { decision: 1, gain }))
                .collect(),
            outcome: executed.and_then(|e| {
                hind.get(e).copied().flatten().map(|gain| Outcome {
                    succeeded: true,
                    new_cluster: false,
                    new_operation: false,
                    new_keys: gain,
                    first_trusted: None,
                    gain,
                })
            }),
            latency_ms: Some(10),
            calibration_version: Some("cal-1".to_owned()),
            breaker_state: Some("closed".to_owned()),
        }
    }

    #[test]
    fn shadow_report_computes_agreement_recall_counterfactual_and_calibration() {
        let mut ds = Vec::new();
        for r in 0..4 {
            let run = format!("run{r}");
            // the model prefers candidate 2, which is novel (gain 3); the arbiter ran 0 (gain 0)
            let mut a = decision(&run, &[0.1, 0.2, 0.6], &[Some(0), None, Some(3)], Some(0));
            a.selected = Some(2);
            ds.push(a);
            // the model prefers candidate 0 like the arbiter; novel gain 1
            ds.push(decision(
                &run,
                &[0.7, 0.1, 0.1],
                &[Some(1), Some(0), None],
                Some(0),
            ));
        }
        let rep = analyze_shadow(&ds).unwrap();
        assert_eq!((rep.decisions, rep.fixtures, rep.runs), (8, 1, 4));
        assert_eq!(rep.calibration_version_missing, 0);
        assert_eq!(rep.agreement.with_executed, 8);
        assert_eq!(rep.agreement.top1_equals_executed, 4);
        assert_eq!(rep.agreement.top1_equals_deterministic, 4);
        assert_eq!((rep.agreement.gated, rep.agreement.gated_equals_executed), (4, 0));
        assert!((rep.agreement.abstain_rate - 0.5).abs() < 1e-12);
        let k1 = &rep.recall[0];
        assert_eq!((k1.k, k1.n), (1, 8));
        // top-1 hit: first kind (model picks 2, novel) yes; second (model picks 0, novel) yes
        assert!((k1.model - 1.0).abs() < 1e-12);
        // deterministic top-1 is candidate 0: novel only in the second kind
        assert!((k1.deterministic - 0.5).abs() < 1e-12);
        let cf = &rep.counterfactual;
        assert_eq!((cf.pairs, cf.runs), (8, 4));
        assert!((cf.mean_gain_model - 2.0).abs() < 1e-12);
        assert!((cf.mean_gain_executed - 0.5).abs() < 1e-12);
        assert!((cf.novel_rate_model - 1.0).abs() < 1e-12);
        let (mean, lo, _) = cf.gain_diff.unwrap();
        assert!((mean - 1.5).abs() < 1e-12 && lo > 0.0);
        // live calibration: confidences 0.6 and 0.7, both pick novel candidates
        assert_eq!(rep.calibration.n, 8);
        assert!((rep.calibration.brier.unwrap() - (0.16 + 0.09) / 2.0).abs() < 1e-6);
        assert_eq!(rep.latency_p95_ms, 10.0);
    }

    #[test]
    fn missing_calibration_versions_and_open_breakers_are_counted() {
        let mut d = decision("r", &[0.5, 0.5], &[None, None], None);
        d.calibration_version = None;
        d.breaker_state = Some("open".to_owned());
        let rep = analyze_shadow(&[d]).unwrap();
        assert_eq!((rep.calibration_version_missing, rep.breaker_not_closed), (1, 1));
        assert_eq!(rep.counterfactual, Counterfactual::default());
        assert_eq!(rep.calibration.n, 0);
    }

    fn night(gain: f64, seeds: &[u64], unauthorized: u64) -> Vec<PairedRun> {
        seeds
            .iter()
            .map(|s| PairedRun {
                fixture: "g01".to_owned(),
                seed: *s,
                baseline: 0.5 + (*s as f64) * 0.001,
                candidate: 0.5 + (*s as f64) * 0.001 + gain,
                baseline_auc: 0.4,
                candidate_auc: 0.4 + gain,
                candidate_executed: 50,
                candidate_unauthorized: unauthorized,
                candidate_safety_executed: 50,
            })
            .collect()
    }

    #[test]
    fn g3_report_counts_trailing_improving_nights_without_safety_regressions() {
        let seeds = [1, 2, 3, 5, 8];
        let good = night(0.05, &seeds, 0);
        let flat = night(0.0, &seeds, 0);
        let unsafe_night = night(0.05, &seeds, 1);
        let mk = |nights: &[&[PairedRun]]| {
            assemble_g3(&G3Inputs {
                calibration_samples: 12_000,
                ece: 0.03,
                warm_p95_ms: 12.0,
                nights,
                safety: (0, 400),
            })
            .unwrap()
        };
        let r = mk(&[&good, &good]);
        assert_eq!((r.seeds, r.consecutive_nightly_improvements), (5, 2));
        assert!(r.coverage_gain_ci_low > 0.0 && r.unauthorized_action_rate == 0.0);
        assert_eq!(mk(&[&good, &flat]).consecutive_nightly_improvements, 0);
        assert_eq!(mk(&[&flat, &good, &good]).consecutive_nightly_improvements, 2);
        assert_eq!(mk(&[&good, &unsafe_night]).consecutive_nightly_improvements, 0);
        // no executed actions means the rate was not measured: it must not read as zero
        let none = assemble_g3(&G3Inputs {
            calibration_samples: 1,
            ece: 0.0,
            warm_p95_ms: 1.0,
            nights: &[&good],
            safety: (0, 0),
        })
        .unwrap();
        assert_eq!(none.unauthorized_action_rate, 1.0);
    }
}
