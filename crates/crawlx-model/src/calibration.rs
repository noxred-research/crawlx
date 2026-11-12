//! Calibration and the confidence gate.
//!
//! * [`fit`] fits one temperature per model version by minimizing the negative
//!   log-likelihood of held-out logits; NLL is convex in `β = 1/T`, so a
//!   bisection on its derivative converges to the global optimum
//!   deterministically.
//! * [`expected_calibration_error`], [`brier_score`] and [`CalibrationReport`]
//!   implement the release gate (ECE ≤ 0.05, Brier recorded).
//! * [`Gate`] accepts the top option only if `p_top ≥ 0.70`,
//!   `p_top − p_second ≥ 0.15` and the abstain mass is ≤ 0.30 (planning
//!   defaults, re-derived per model version). Isotonic fallback is not
//!   implemented; it was only ever a fallback option.

use crate::error::ModelError;
use serde::{Deserialize, Serialize};

/// Lowest temperature a fit may return.
pub const MIN_TEMPERATURE: f32 = 0.05;
/// Highest temperature a fit may return.
pub const MAX_TEMPERATURE: f32 = 20.0;
/// ECE release threshold.
pub const ECE_RELEASE_MAX: f64 = 0.05;
/// Default number of equal-width confidence bins for ECE.
pub const DEFAULT_ECE_BINS: usize = 10;

fn cal(msg: impl Into<String>) -> ModelError {
    ModelError::Calibration(msg.into())
}

/// Numerically stable softmax of `logits / temperature`.
///
/// Returns an empty vector for empty input. Non-finite logits yield NaN
/// probabilities, which the gate treats as abstention.
#[must_use]
pub fn softmax(logits: &[f32], temperature: f32) -> Vec<f32> {
    if logits.is_empty() {
        return Vec::new();
    }
    let t = f64::from(temperature.max(f32::MIN_POSITIVE));
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f64> = logits
        .iter()
        .map(|&z| ((f64::from(z) - f64::from(max)) / t).exp())
        .collect();
    let sum: f64 = exps.iter().sum();
    #[allow(clippy::cast_possible_truncation)]
    exps.iter().map(|e| (e / sum) as f32).collect()
}

/// Temperature scaling parameter of one model version.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct TemperatureScaler {
    /// Divisor applied to logits before the softmax; above 1 softens, below 1 sharpens.
    /// Within [`MIN_TEMPERATURE`]..=[`MAX_TEMPERATURE`].
    pub temperature: f32,
}

impl Default for TemperatureScaler {
    /// Identity calibration (`T = 1`).
    fn default() -> Self {
        Self { temperature: 1.0 }
    }
}

impl TemperatureScaler {
    /// A scaler with an explicit temperature.
    ///
    /// # Errors
    /// [`ModelError::Calibration`] unless `temperature` is finite and positive.
    pub fn new(temperature: f32) -> Result<Self, ModelError> {
        if temperature.is_finite() && temperature > 0.0 {
            Ok(Self { temperature })
        } else {
            Err(cal(format!(
                "temperature must be finite and > 0, got {temperature}"
            )))
        }
    }

    /// Calibrated probabilities for one row of logits.
    #[must_use]
    pub fn apply(&self, logits: &[f32]) -> Vec<f32> {
        softmax(logits, self.temperature)
    }
}

fn validate_batch(logits: &[Vec<f32>], labels: &[usize]) -> Result<(), ModelError> {
    if logits.is_empty() {
        return Err(cal("empty calibration set"));
    }
    if logits.len() != labels.len() {
        return Err(cal(format!(
            "{} logit rows but {} labels",
            logits.len(),
            labels.len()
        )));
    }
    for (row, &y) in logits.iter().zip(labels) {
        if row.len() < 2 {
            return Err(cal("each logit row needs at least two classes"));
        }
        if y >= row.len() {
            return Err(cal(format!("label {y} outside {} classes", row.len())));
        }
        if row.iter().any(|z| !z.is_finite()) {
            return Err(cal("non-finite logit"));
        }
    }
    Ok(())
}

/// Mean negative log-likelihood of `labels` under `softmax(logits / temperature)`.
///
/// # Errors
/// [`ModelError::Calibration`] for empty, ragged or non-finite input.
pub fn nll(logits: &[Vec<f32>], labels: &[usize], temperature: f32) -> Result<f64, ModelError> {
    validate_batch(logits, labels)?;
    let beta = 1.0 / f64::from(temperature);
    let mut total = 0.0;
    for (row, &y) in logits.iter().zip(labels) {
        let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let lse = f64::from(max) * beta
            + row
                .iter()
                .map(|&z| ((f64::from(z) - f64::from(max)) * beta).exp())
                .sum::<f64>()
                .ln();
        total += lse - f64::from(row[y]) * beta;
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(total / logits.len() as f64)
}

/// d NLL / d β at `beta` (monotone increasing in β).
fn nll_derivative(logits: &[Vec<f32>], labels: &[usize], beta: f64) -> f64 {
    let mut total = 0.0;
    for (row, &y) in logits.iter().zip(labels) {
        let max = row.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let weights: Vec<f64> = row
            .iter()
            .map(|&z| ((f64::from(z) - f64::from(max)) * beta).exp())
            .collect();
        let sum: f64 = weights.iter().sum();
        let expected: f64 = row
            .iter()
            .zip(&weights)
            .map(|(&z, w)| f64::from(z) * w / sum)
            .sum();
        total += expected - f64::from(row[y]);
    }
    total
}

/// Fit the temperature that minimizes NLL on `(logits, labels)`, clamped to
/// [`MIN_TEMPERATURE`]..=[`MAX_TEMPERATURE`].
///
/// # Errors
/// [`ModelError::Calibration`] for empty, ragged, or non-finite input.
pub fn fit(logits: &[Vec<f32>], labels: &[usize]) -> Result<TemperatureScaler, ModelError> {
    validate_batch(logits, labels)?;
    let mut lo = 1.0 / f64::from(MAX_TEMPERATURE);
    let mut hi = 1.0 / f64::from(MIN_TEMPERATURE);
    let beta = if nll_derivative(logits, labels, lo) >= 0.0 {
        lo
    } else if nll_derivative(logits, labels, hi) <= 0.0 {
        hi
    } else {
        for _ in 0..200 {
            let mid = 0.5 * (lo + hi);
            if nll_derivative(logits, labels, mid) < 0.0 {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        0.5 * (lo + hi)
    };
    #[allow(clippy::cast_possible_truncation)]
    let t = (1.0 / beta) as f32;
    TemperatureScaler::new(t.clamp(MIN_TEMPERATURE, MAX_TEMPERATURE))
}

/// Index and value of the largest probability (first on ties).
fn argmax(p: &[f32]) -> Option<(usize, f32)> {
    let mut best: Option<(usize, f32)> = None;
    for (i, &v) in p.iter().enumerate() {
        if best.is_none_or(|(_, b)| v > b) {
            best = Some((i, v));
        }
    }
    best
}

fn validate_probs(probs: &[Vec<f32>], labels: &[usize]) -> Result<(), ModelError> {
    if probs.is_empty() {
        return Err(cal("empty evaluation set"));
    }
    if probs.len() != labels.len() {
        return Err(cal(format!(
            "{} probability rows but {} labels",
            probs.len(),
            labels.len()
        )));
    }
    for (row, &y) in probs.iter().zip(labels) {
        if row.is_empty() || y >= row.len() {
            return Err(cal("label outside the probability row"));
        }
        if row.iter().any(|p| !p.is_finite() || *p < 0.0) {
            return Err(cal("probabilities must be finite and non-negative"));
        }
    }
    Ok(())
}

/// One bin of the reliability diagram.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ReliabilityBin {
    /// Inclusive lower confidence bound of the bin.
    pub lower: f64,
    /// Upper confidence bound of the bin.
    pub upper: f64,
    /// Number of predictions whose confidence falls in the bin.
    pub count: usize,
    /// Mean predicted confidence of those predictions.
    pub mean_confidence: f64,
    /// Fraction of those predictions that were correct.
    pub accuracy: f64,
}

/// Reliability bins over top-1 confidence with `bins` equal-width bins on `[0, 1]`.
///
/// # Errors
/// [`ModelError::Calibration`] for invalid input or `bins == 0`.
pub fn reliability_bins(
    probs: &[Vec<f32>],
    labels: &[usize],
    bins: usize,
) -> Result<Vec<ReliabilityBin>, ModelError> {
    validate_probs(probs, labels)?;
    if bins == 0 {
        return Err(cal("bins must be > 0"));
    }
    #[allow(clippy::cast_precision_loss)]
    let width = 1.0 / bins as f64;
    let mut conf_sum = vec![0.0_f64; bins];
    let mut hits = vec![0_usize; bins];
    let mut counts = vec![0_usize; bins];
    for (row, &y) in probs.iter().zip(labels) {
        let (pred, conf) = argmax(row).unwrap_or((0, 0.0));
        let conf = f64::from(conf).clamp(0.0, 1.0);
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let b = ((conf / width) as usize).min(bins - 1);
        conf_sum[b] += conf;
        counts[b] += 1;
        hits[b] += usize::from(pred == y);
    }
    Ok((0..bins)
        .map(|b| {
            #[allow(clippy::cast_precision_loss)]
            let (n, lower) = (counts[b] as f64, b as f64 * width);
            ReliabilityBin {
                lower,
                upper: lower + width,
                count: counts[b],
                mean_confidence: if counts[b] == 0 { 0.0 } else { conf_sum[b] / n },
                #[allow(clippy::cast_precision_loss)]
                accuracy: if counts[b] == 0 { 0.0 } else { hits[b] as f64 / n },
            }
        })
        .collect())
}

/// Expected calibration error of top-1 confidence with `bins` equal-width bins.
///
/// # Errors
/// [`ModelError::Calibration`] for invalid input or `bins == 0`.
pub fn expected_calibration_error(
    probs: &[Vec<f32>],
    labels: &[usize],
    bins: usize,
) -> Result<f64, ModelError> {
    let table = reliability_bins(probs, labels, bins)?;
    #[allow(clippy::cast_precision_loss)]
    let n = probs.len() as f64;
    #[allow(clippy::cast_precision_loss)]
    Ok(table
        .iter()
        .map(|b| (b.count as f64 / n) * (b.accuracy - b.mean_confidence).abs())
        .sum())
}

/// Multi-class Brier score: mean over samples of `Σ_k (p_k − 1[k = y])²`.
///
/// # Errors
/// [`ModelError::Calibration`] for invalid input.
pub fn brier_score(probs: &[Vec<f32>], labels: &[usize]) -> Result<f64, ModelError> {
    validate_probs(probs, labels)?;
    let mut total = 0.0;
    for (row, &y) in probs.iter().zip(labels) {
        for (k, &p) in row.iter().enumerate() {
            let target = if k == y { 1.0 } else { 0.0 };
            total += (f64::from(p) - target).powi(2);
        }
    }
    #[allow(clippy::cast_precision_loss)]
    Ok(total / probs.len() as f64)
}

/// Calibration quality of one model version on a held-out set.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct CalibrationReport {
    /// Number of held-out examples evaluated.
    pub samples: usize,
    /// Expected calibration error; gated by [`ECE_RELEASE_MAX`].
    pub ece: f64,
    /// Mean squared error between the probability vector and the one-hot label.
    pub brier: f64,
    /// Mean negative log-likelihood of the true label.
    pub nll: f64,
}

impl CalibrationReport {
    /// Evaluate `scaler` on held-out `(logits, labels)`.
    ///
    /// # Errors
    /// [`ModelError::Calibration`] for invalid input.
    pub fn evaluate(
        scaler: &TemperatureScaler,
        logits: &[Vec<f32>],
        labels: &[usize],
    ) -> Result<Self, ModelError> {
        validate_batch(logits, labels)?;
        let probs: Vec<Vec<f32>> = logits.iter().map(|r| scaler.apply(r)).collect();
        Ok(Self {
            samples: logits.len(),
            ece: expected_calibration_error(&probs, labels, DEFAULT_ECE_BINS)?,
            brier: brier_score(&probs, labels)?,
            nll: nll(logits, labels, scaler.temperature)?,
        })
    }

    /// The release gate: ECE ≤ 0.05.
    #[must_use]
    pub fn passes_release_gate(&self) -> bool {
        self.ece <= ECE_RELEASE_MAX
    }
}

/// Graded outcomes and decisions a [`DriftMonitor`] keeps by default.
pub const DRIFT_WINDOW: usize = 1000;
/// Graded outcomes a window needs before its ECE is trusted; fewer report `None`.
pub const DRIFT_MIN_SAMPLES: usize = 200;

/// Rolling-window calibration drift monitor of one model version.
///
/// The release gate judges a held-out set once. This watches the model in service: every graded
/// outcome (the confidence the model gave its top option and whether that option turned out
/// right) enters a bounded window, and the window's expected calibration error is compared with
/// the same [`ECE_RELEASE_MAX`] ceiling. A second window counts decisions and abstentions, so a
/// shift in how often the gate abstains is visible too. Old entries fall out; nothing is stored
/// beyond the two windows and the monitor never reads a clock.
#[derive(Clone, Debug)]
pub struct DriftMonitor {
    capacity: usize,
    min_samples: usize,
    graded: std::collections::VecDeque<(f64, bool)>,
    decisions: std::collections::VecDeque<bool>,
}

/// What a [`DriftMonitor`] currently shows.
#[derive(Clone, Copy, PartialEq, Debug)]
#[non_exhaustive]
pub struct DriftReading {
    /// Graded outcomes in the window.
    pub graded: usize,
    /// Expected calibration error of the graded window; `None` until it holds
    /// [`DriftMonitor::min_samples`] outcomes.
    pub ece: Option<f64>,
    /// Decisions in the abstention window.
    pub decisions: usize,
    /// Share of those decisions on which the gate abstained; `None` before the first.
    pub abstention_rate: Option<f64>,
}

impl DriftReading {
    /// Whether the window is mature and its ECE exceeds [`ECE_RELEASE_MAX`].
    #[must_use]
    pub fn drifted(&self) -> bool {
        self.ece.is_some_and(|ece| ece > ECE_RELEASE_MAX)
    }
}

impl Default for DriftMonitor {
    fn default() -> Self {
        Self {
            capacity: DRIFT_WINDOW,
            min_samples: DRIFT_MIN_SAMPLES,
            graded: std::collections::VecDeque::new(),
            decisions: std::collections::VecDeque::new(),
        }
    }
}

impl DriftMonitor {
    /// A monitor over windows of `capacity` entries that trusts an ECE from `min_samples` outcomes.
    ///
    /// # Errors
    /// [`ModelError::Calibration`] unless `0 < min_samples <= capacity`.
    pub fn new(capacity: usize, min_samples: usize) -> Result<Self, ModelError> {
        if min_samples == 0 || min_samples > capacity {
            return Err(cal("drift window needs 0 < min_samples <= capacity"));
        }
        Ok(Self {
            capacity,
            min_samples,
            graded: std::collections::VecDeque::with_capacity(capacity),
            decisions: std::collections::VecDeque::with_capacity(capacity),
        })
    }

    /// Outcomes a window needs before its ECE is reported.
    #[must_use]
    pub const fn min_samples(&self) -> usize {
        self.min_samples
    }

    /// Record one graded outcome: the top option's calibrated probability and whether it was right.
    ///
    /// # Errors
    /// [`ModelError::Calibration`] for a confidence that is not a probability; the window is unchanged.
    pub fn observe_outcome(&mut self, confidence: f32, correct: bool) -> Result<(), ModelError> {
        if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
            return Err(cal(format!("confidence {confidence} is not a probability")));
        }
        if self.graded.len() == self.capacity {
            self.graded.pop_front();
        }
        self.graded.push_back((f64::from(confidence), correct));
        Ok(())
    }

    /// Record that the gate accepted (`false`) or abstained (`true`) on one decision.
    pub fn observe_decision(&mut self, abstained: bool) {
        if self.decisions.len() == self.capacity {
            self.decisions.pop_front();
        }
        self.decisions.push_back(abstained);
    }

    /// The current window readings.
    #[must_use]
    pub fn reading(&self) -> DriftReading {
        let abstentions = self.decisions.iter().filter(|abstained| **abstained).count();
        #[allow(clippy::cast_precision_loss)]
        let abstention_rate =
            (!self.decisions.is_empty()).then(|| abstentions as f64 / self.decisions.len() as f64);
        DriftReading {
            graded: self.graded.len(),
            ece: (self.graded.len() >= self.min_samples).then(|| window_ece(&self.graded)),
            decisions: self.decisions.len(),
            abstention_rate,
        }
    }
}

/// Expected calibration error of `(confidence, correct)` pairs with [`DEFAULT_ECE_BINS`] bins,
/// the same binning as [`expected_calibration_error`].
fn window_ece(samples: &std::collections::VecDeque<(f64, bool)>) -> f64 {
    let mut conf_sum = [0.0_f64; DEFAULT_ECE_BINS];
    let mut hits = [0_usize; DEFAULT_ECE_BINS];
    let mut counts = [0_usize; DEFAULT_ECE_BINS];
    for &(confidence, correct) in samples {
        #[allow(clippy::cast_precision_loss)]
        let width = 1.0 / DEFAULT_ECE_BINS as f64;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let bin = ((confidence / width) as usize).min(DEFAULT_ECE_BINS - 1);
        conf_sum[bin] += confidence;
        counts[bin] += 1;
        hits[bin] += usize::from(correct);
    }
    #[allow(clippy::cast_precision_loss)]
    let total = samples.len() as f64;
    let mut ece = 0.0;
    for bin in 0..DEFAULT_ECE_BINS {
        if counts[bin] == 0 {
            continue;
        }
        #[allow(clippy::cast_precision_loss)]
        let n = counts[bin] as f64;
        #[allow(clippy::cast_precision_loss)]
        let accuracy = hits[bin] as f64 / n;
        ece += (n / total) * (accuracy - conf_sum[bin] / n).abs();
    }
    ece
}
/// Outcome of the confidence gate.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GateDecision {
    /// Index (into the probability slice) of the accepted option.
    Accept(usize),
    /// Confidence too low or margin too small: use the deterministic ranking.
    Abstain,
}

/// Confidence gate. Thresholds are per model version.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct Gate {
    /// Minimum top probability.
    pub p_top_min: f32,
    /// Minimum `p_top − p_second`.
    pub margin_min: f32,
    /// Abstain outright when the best probability is below this floor.
    pub abstain_floor: f32,
    /// Maximum probability mass on `none of these` / abstain.
    pub max_abstain_p: f32,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            p_top_min: 0.70,
            margin_min: 0.15,
            abstain_floor: 0.30,
            max_abstain_p: 0.30,
        }
    }
}

impl Gate {
    /// Gate over option probabilities only.
    #[must_use]
    pub fn decide(&self, probs: &[f32]) -> GateDecision {
        self.decide_with_abstain(probs, 0.0)
    }

    /// Gate over option probabilities plus the `none of these` mass, which
    /// also competes as a runner-up for the margin test.
    #[must_use]
    pub fn decide_with_abstain(&self, probs: &[f32], abstain_p: f32) -> GateDecision {
        if probs.iter().any(|p| !p.is_finite()) || !abstain_p.is_finite() {
            return GateDecision::Abstain;
        }
        let Some((top, p_top)) = argmax(probs) else {
            return GateDecision::Abstain;
        };
        let second_option = probs
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != top)
            .map(|(_, p)| *p)
            .fold(0.0, f32::max);
        let p_second = second_option.max(abstain_p);
        let accepted = p_top >= self.abstain_floor
            && p_top >= self.p_top_min
            && p_top - p_second >= self.margin_min
            && abstain_p <= self.max_abstain_p;
        if accepted {
            GateDecision::Accept(top)
        } else {
            GateDecision::Abstain
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn close(a: f64, b: f64, eps: f64) {
        assert!((a - b).abs() < eps, "{a} vs {b}");
    }

    #[test]
    fn softmax_matches_hand_computation() {
        let p = softmax(&[0.0, 0.0], 1.0);
        close(f64::from(p[0]), 0.5, 1e-7);
        let p = softmax(&[1.0, 2.0, 3.0], 1.0);
        close(f64::from(p[0]), 0.090_030_57, 1e-6);
        close(f64::from(p[1]), 0.244_728_47, 1e-6);
        close(f64::from(p[2]), 0.665_240_96, 1e-6);
        // Large logits do not overflow.
        let p = softmax(&[1000.0, 999.0], 1.0);
        close(f64::from(p[0]), 0.731_058_6, 1e-6);
        // Higher temperature flattens.
        let hot = softmax(&[1.0, 2.0, 3.0], 10.0);
        assert!(hot[2] < p_third_at_t1());
        assert!(softmax(&[], 1.0).is_empty());
    }

    fn p_third_at_t1() -> f32 {
        softmax(&[1.0, 2.0, 3.0], 1.0)[2]
    }

    #[test]
    fn nll_matches_hand_computation() {
        // softmax([0,0]) = [0.5, 0.5] -> NLL = ln 2.
        let v = nll(&[vec![0.0, 0.0]], &[0], 1.0).unwrap();
        close(v, std::f64::consts::LN_2, 1e-9);
        // Confident and right at T=1: logits [4,0] label 0 -> ln(1+e^-4).
        let v = nll(&[vec![4.0, 0.0]], &[0], 1.0).unwrap();
        close(v, (1.0 + (-4.0_f64).exp()).ln(), 1e-9);
    }

    #[test]
    fn fit_recovers_known_temperature() {
        // Two-class rows with logit gap g. Under T = 2 the probability of class 0
        // is sigmoid(g / 2); label exactly that fraction of each group as class 0,
        // so the NLL minimum sits at T = 2 up to rounding.
        let total = 1000;
        let mut logits = Vec::new();
        let mut labels = Vec::new();
        for gap in [2.0_f32, 4.0, 6.0] {
            let zeros = zeros_of(gap, total);
            for i in 0..total {
                logits.push(vec![gap, 0.0]);
                labels.push(usize::from(i >= zeros));
            }
        }
        let t = fit(&logits, &labels).unwrap().temperature;
        assert!((t - 2.0).abs() < 0.05, "fitted T = {t}");
    }

    fn zeros_of(gap: f32, total: usize) -> usize {
        let p0 = 1.0 / (1.0 + (-f64::from(gap) / 2.0).exp());
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        let z = (p0 * total as f64).round() as usize;
        z
    }

    #[test]
    fn fit_shrinks_overconfident_and_sharpens_underconfident_logits() {
        // Overconfident: huge margins but 30% wrong -> T > 1.
        let mut logits = Vec::new();
        let mut labels = Vec::new();
        for i in 0..100 {
            logits.push(vec![8.0, 0.0]);
            labels.push(usize::from(i % 10 < 3));
        }
        assert!(fit(&logits, &labels).unwrap().temperature > 1.5);

        // Underconfident: small margins but always right -> T < 1 (clamped at the minimum).
        let logits: Vec<Vec<f32>> = (0..50).map(|_| vec![1.0, 0.0]).collect();
        let labels = vec![0; 50];
        let t = fit(&logits, &labels).unwrap().temperature;
        assert!((t - MIN_TEMPERATURE).abs() < 1e-6, "{t}");
    }

    #[test]
    fn fitted_temperature_does_not_increase_nll() {
        let logits: Vec<Vec<f32>> = (0..60)
            .map(|i| vec![(i % 7) as f32, ((i * 3) % 5) as f32, 1.0])
            .collect();
        let labels: Vec<usize> = (0..60).map(|i| (i * 7 + 1) % 3).collect();
        let t = fit(&logits, &labels).unwrap().temperature;
        let fitted = nll(&logits, &labels, t).unwrap();
        for probe in [0.3_f32, 0.7, 1.0, 1.5, 3.0, 8.0] {
            assert!(
                fitted <= nll(&logits, &labels, probe).unwrap() + 1e-6,
                "T={t} vs {probe}"
            );
        }
    }

    #[test]
    fn fit_rejects_bad_input() {
        assert!(fit(&[], &[]).is_err());
        assert!(fit(&[vec![1.0, 2.0]], &[0, 1]).is_err());
        assert!(fit(&[vec![1.0, 2.0]], &[2]).is_err());
        assert!(fit(&[vec![f32::NAN, 2.0]], &[0]).is_err());
        assert!(fit(&[vec![1.0]], &[0]).is_err());
        assert!(TemperatureScaler::new(0.0).is_err());
        assert!(TemperatureScaler::new(f32::NAN).is_err());
    }

    #[test]
    fn ece_known_values() {
        // Perfectly calibrated: confidence 0.8, 8 of 10 right -> ECE 0.
        let mut probs = Vec::new();
        let mut labels = Vec::new();
        for i in 0..10 {
            probs.push(vec![0.8, 0.2]);
            labels.push(usize::from(i >= 8));
        }
        close(
            expected_calibration_error(&probs, &labels, 10).unwrap(),
            0.0,
            1e-6,
        );

        // Always confident 0.9 but only half right -> ECE 0.4.
        let probs = vec![vec![0.9, 0.1]; 10];
        let labels: Vec<usize> = (0..10).map(|i| usize::from(i >= 5)).collect();
        close(
            expected_calibration_error(&probs, &labels, 10).unwrap(),
            0.4,
            1e-6,
        );

        // Two bins mixed: 4 samples at 0.6 (2 right), 4 at 0.95 (4 right):
        // |0.5-0.6|*0.5 + |1-0.95|*0.5 = 0.075.
        let mut probs = vec![vec![0.6, 0.4]; 4];
        probs.extend(vec![vec![0.95, 0.05]; 4]);
        let labels = vec![0, 0, 1, 1, 0, 0, 0, 0];
        close(
            expected_calibration_error(&probs, &labels, 10).unwrap(),
            0.075,
            1e-6,
        );
        assert!(expected_calibration_error(&probs, &labels, 0).is_err());
    }

    #[test]
    fn brier_known_values() {
        // Perfect prediction.
        close(brier_score(&[vec![1.0, 0.0]], &[0]).unwrap(), 0.0, 1e-12);
        // Worst case for two classes: (1)^2 + (1)^2 = 2.
        close(brier_score(&[vec![0.0, 1.0]], &[0]).unwrap(), 2.0, 1e-12);
        // Uniform over 4 classes: (0.75)^2 + 3 * (0.25)^2 = 0.75.
        close(brier_score(&[vec![0.25; 4]], &[2]).unwrap(), 0.75, 1e-9);
        // Mean over samples.
        close(
            brier_score(&[vec![1.0, 0.0], vec![0.0, 1.0]], &[0, 0]).unwrap(),
            1.0,
            1e-12,
        );
        assert!(brier_score(&[vec![0.5, -0.1]], &[0]).is_err());
    }

    #[test]
    fn report_gate_accepts_calibrated_and_rejects_overconfident() {
        let logits: Vec<Vec<f32>> = (0..100).map(|_| vec![8.0, 0.0]).collect();
        let labels: Vec<usize> = (0..100).map(|i| usize::from(i % 10 < 3)).collect();
        let raw = CalibrationReport::evaluate(&TemperatureScaler::default(), &logits, &labels).unwrap();
        assert!(!raw.passes_release_gate(), "{raw:?}");
        let fitted = fit(&logits, &labels).unwrap();
        let after = CalibrationReport::evaluate(&fitted, &logits, &labels).unwrap();
        assert!(after.passes_release_gate(), "{after:?}");
        assert!(after.nll < raw.nll && after.brier < raw.brier);
        assert_eq!(after.samples, 100);
    }

    #[test]
    fn gate_defaults_match_the_plan() {
        let g = Gate::default();
        assert_eq!(
            (g.p_top_min, g.margin_min, g.abstain_floor, g.max_abstain_p),
            (0.70, 0.15, 0.30, 0.30)
        );
    }

    #[test]
    fn gate_decisions() {
        let g = Gate::default();
        assert_eq!(g.decide(&[0.05, 0.85, 0.10]), GateDecision::Accept(1));
        assert_eq!(
            g.decide(&[0.70, 0.15, 0.15]),
            GateDecision::Accept(0),
            "boundary p_top = 0.70, margin 0.55"
        );
        assert_eq!(
            g.decide(&[0.69, 0.01, 0.30]),
            GateDecision::Abstain,
            "p_top below 0.70"
        );
        assert_eq!(
            g.decide(&[0.75, 0.70, 0.0]),
            GateDecision::Abstain,
            "margin below 0.15 (p_top high)"
        );
        assert_eq!(g.decide(&[0.40, 0.35, 0.25]), GateDecision::Abstain);
        assert_eq!(
            g.decide(&[0.25, 0.25, 0.25, 0.25]),
            GateDecision::Abstain,
            "max < 0.30"
        );
        assert_eq!(g.decide(&[]), GateDecision::Abstain);
        assert_eq!(g.decide(&[1.0]), GateDecision::Accept(0));
        assert_eq!(g.decide(&[f32::NAN, 0.9]), GateDecision::Abstain);
    }

    #[test]
    fn gate_exact_margin_boundary() {
        let g = Gate::default();
        // 0.85 - 0.70 = 0.15 exactly in f32 arithmetic is fragile; use values with a clear side.
        assert_eq!(g.decide(&[0.86, 0.70]), GateDecision::Accept(0));
        assert_eq!(g.decide(&[0.84, 0.70]), GateDecision::Abstain);
    }

    #[test]
    fn none_option_competes_and_can_veto() {
        let g = Gate::default();
        assert_eq!(
            g.decide_with_abstain(&[0.80, 0.05], 0.15),
            GateDecision::Accept(0)
        );
        // Abstain mass above 0.30 vetoes even a high p_top.
        assert_eq!(g.decide_with_abstain(&[0.70, 0.0], 0.31), GateDecision::Abstain);
        // `none` as runner-up shrinks the margin: 0.72 - 0.28 = 0.44 fine, but 0.72 vs none 0.28 ok;
        // p_top 0.72 with none 0.28 passes, p_top 0.72 with none 0.30 passes, 0.31 vetoes.
        assert_eq!(g.decide_with_abstain(&[0.72, 0.0], 0.28), GateDecision::Accept(0));
        // Looser gate: margin must still clear against `none`.
        let loose = Gate {
            p_top_min: 0.40,
            margin_min: 0.15,
            abstain_floor: 0.30,
            max_abstain_p: 0.9,
        };
        assert_eq!(
            loose.decide_with_abstain(&[0.45, 0.0], 0.40),
            GateDecision::Abstain
        );
    }

    #[test]
    fn calibrated_probabilities_sum_to_one() {
        let s = TemperatureScaler::new(1.7).unwrap();
        let p = s.apply(&[3.0, -1.0, 0.5, 2.2]);
        let sum: f32 = p.iter().sum();
        assert!((sum - 1.0).abs() < 1e-6);
    }

    /// Graded outcomes whose accuracy matches their confidence: for each bucket confidence `c`
    /// (tenths), exactly `c * 10` of every ten outcomes are right.
    fn calibrated(monitor: &mut DriftMonitor, rounds: usize) {
        for round in 0..rounds {
            for tenths in [6_usize, 8, 10] {
                #[allow(clippy::cast_precision_loss)]
                let confidence = tenths as f32 / 10.0;
                monitor.observe_outcome(confidence, round % 10 < tenths).unwrap();
            }
        }
    }

    #[test]
    fn drift_window_stays_below_the_ceiling_while_calibrated() {
        let mut monitor = DriftMonitor::new(300, 100).unwrap();
        calibrated(&mut monitor, 100);
        let reading = monitor.reading();
        assert_eq!(reading.graded, 300);
        assert!(reading.ece.unwrap() < 0.01, "{reading:?}");
        assert!(!reading.drifted());
    }

    #[test]
    fn overconfident_outcomes_push_the_window_ece_above_the_ceiling() {
        let mut monitor = DriftMonitor::new(300, 100).unwrap();
        calibrated(&mut monitor, 100);
        // the model keeps answering at 0.9 but is right only six times in ten
        for i in 0..300 {
            monitor.observe_outcome(0.9, i % 10 < 6).unwrap();
        }
        let reading = monitor.reading();
        assert_eq!(reading.graded, 300, "old outcomes fell out of the window");
        let ece = reading.ece.unwrap();
        assert!((ece - 0.3).abs() < 1e-6, "{ece}");
        assert!(reading.drifted());
        // recovery: the window forgets the bad stretch
        calibrated(&mut monitor, 100);
        assert!(!monitor.reading().drifted());
    }

    #[test]
    fn ece_is_withheld_until_the_window_is_mature_and_bad_input_is_refused() {
        let mut monitor = DriftMonitor::new(300, 100).unwrap();
        for _ in 0..99 {
            monitor.observe_outcome(0.99, false).unwrap();
        }
        assert_eq!(monitor.reading().ece, None, "99 outcomes are not a reading");
        assert!(!monitor.reading().drifted());
        monitor.observe_outcome(0.99, false).unwrap();
        assert!(monitor.reading().drifted());
        for bad in [f32::NAN, f32::INFINITY, -0.1, 1.1] {
            assert!(monitor.observe_outcome(bad, true).is_err());
        }
        assert_eq!(monitor.reading().graded, 100);
        assert!(DriftMonitor::new(10, 0).is_err());
        assert!(DriftMonitor::new(10, 11).is_err());
    }

    #[test]
    fn abstention_window_reports_the_share_of_recent_decisions() {
        let mut monitor = DriftMonitor::new(10, 5).unwrap();
        assert_eq!(monitor.reading().abstention_rate, None);
        for abstained in [true, false, false, false] {
            monitor.observe_decision(abstained);
        }
        assert_eq!(monitor.reading().abstention_rate, Some(0.25));
        for _ in 0..10 {
            monitor.observe_decision(true);
        }
        let reading = monitor.reading();
        assert_eq!(reading.decisions, 10);
        assert_eq!(reading.abstention_rate, Some(1.0));
    }
}
