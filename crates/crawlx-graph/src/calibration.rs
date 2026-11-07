//! Calibration of `p_success` against replay outcomes (calibration check: expected
//! calibration error at most 0.10).
//!
//! A prediction is the edge's `p_success` *before* an attempt; the outcome is
//! whether the attempt succeeded. Predictions are bucketed and the ECE is the
//! count-weighted mean gap between each bucket's mean prediction and its
//! observed success rate. Two bucketings are offered: equal-width (the gate's
//! "bucket `p_success` predictions") and equal-mass (which
//! scores the model tier with 15 equal-mass bins).

/// One calibration bucket.
#[derive(Clone, Copy, PartialEq, Debug)]
#[non_exhaustive]
pub struct CalibrationBin {
    /// Lowest prediction the bucket covers (inclusive).
    pub lo: f64,
    /// Highest prediction the bucket covers (inclusive for the last bucket).
    pub hi: f64,
    /// Number of `(prediction, outcome)` pairs in the bucket.
    pub count: usize,
    /// Mean prediction of the bucket; `0` when empty.
    pub mean_predicted: f64,
    /// Share of successful outcomes in the bucket; `0` when empty.
    pub observed_rate: f64,
}

impl CalibrationBin {
    /// `|observed_rate - mean_predicted|`; `0` for an empty bucket.
    #[must_use]
    pub fn gap(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            (self.observed_rate - self.mean_predicted).abs()
        }
    }
}

fn summarize(lo: f64, hi: f64, members: &[(f64, bool)]) -> CalibrationBin {
    if members.is_empty() {
        return CalibrationBin {
            lo,
            hi,
            count: 0,
            mean_predicted: 0.0,
            observed_rate: 0.0,
        };
    }
    // Pair counts are far below 2^53; the casts are exact.
    let n = members.len() as f64;
    let sum_p: f64 = members.iter().map(|(p, _)| *p).sum();
    let hits = members.iter().filter(|(_, ok)| *ok).count() as f64;
    CalibrationBin {
        lo,
        hi,
        count: members.len(),
        mean_predicted: sum_p / n,
        observed_rate: hits / n,
    }
}

/// Bucket `pairs` into `bins` equal-width intervals of `[0, 1]`; a prediction
/// of exactly `1` lands in the last bucket. Predictions outside `[0, 1]` are
/// clamped. `bins == 0` yields no buckets.
#[must_use]
pub fn calibration_bins(pairs: &[(f64, bool)], bins: usize) -> Vec<CalibrationBin> {
    if bins == 0 {
        return Vec::new();
    }
    let mut buckets: Vec<Vec<(f64, bool)>> = vec![Vec::new(); bins];
    let width = 1.0 / bins as f64;
    for &(p, ok) in pairs {
        let p = if p.is_nan() { 0.0 } else { p.clamp(0.0, 1.0) };
        // `p / width` is in `[0, bins]`; truncation picks the bucket and the
        // `min` folds `p == 1` into the last one.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let idx = ((p / width) as usize).min(bins - 1);
        buckets[idx].push((p, ok));
    }
    buckets
        .iter()
        .enumerate()
        .map(|(i, members)| {
            let lo = i as f64 * width;
            let hi = (i + 1) as f64 * width;
            summarize(lo, hi.min(1.0), members)
        })
        .collect()
}

/// Bucket `pairs` into `bins` buckets of (as near as possible) equal size by
/// ascending prediction. Ties are kept in
/// input order, so the result is deterministic. `bins == 0` or no pairs
/// yields no buckets; with fewer pairs than bins the trailing buckets are empty.
#[must_use]
pub fn calibration_bins_equal_mass(pairs: &[(f64, bool)], bins: usize) -> Vec<CalibrationBin> {
    if bins == 0 || pairs.is_empty() {
        return Vec::new();
    }
    let mut sorted: Vec<(f64, bool)> = pairs
        .iter()
        .map(|&(p, ok)| (if p.is_nan() { 0.0 } else { p.clamp(0.0, 1.0) }, ok))
        .collect();
    sorted.sort_by(|a, b| a.0.total_cmp(&b.0));
    let base = sorted.len() / bins;
    let extra = sorted.len() % bins;
    let mut out = Vec::with_capacity(bins);
    let mut start = 0;
    for i in 0..bins {
        let len = base + usize::from(i < extra);
        let members = &sorted[start..start + len];
        let (lo, hi) = match (members.first(), members.last()) {
            (Some(first), Some(last)) => (first.0, last.0),
            _ => (1.0, 1.0),
        };
        out.push(summarize(lo, hi, members));
        start += len;
    }
    out
}

fn weighted_gap(bins: &[CalibrationBin]) -> f64 {
    let total: usize = bins.iter().map(|b| b.count).sum();
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    bins.iter()
        .map(|b| {
            let w = b.count as f64 / total;
            w * b.gap()
        })
        .sum()
}

/// Expected calibration error over `bins` equal-width buckets:
/// `Σ_b (n_b / N) · |observed_rate_b − mean_predicted_b|`. Empty input (or
/// `bins == 0`) is `0`.
#[must_use]
pub fn expected_calibration_error(pairs: &[(f64, bool)], bins: usize) -> f64 {
    weighted_gap(&calibration_bins(pairs, bins))
}

/// [`expected_calibration_error`] over `bins` equal-mass buckets
/// ([`calibration_bins_equal_mass`]).
#[must_use]
pub fn expected_calibration_error_equal_mass(pairs: &[(f64, bool)], bins: usize) -> f64 {
    weighted_gap(&calibration_bins_equal_mass(pairs, bins))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-12
    }

    #[test]
    fn ece_hand_computed_equal_width() {
        // Two buckets of width 0.5.
        // Low bucket: predictions 0.2, 0.4 (mean 0.3), outcomes 1 hit of 2 (0.5): gap 0.2.
        // High bucket: predictions 0.9, 0.7 (mean 0.8), outcomes 2 hits of 2 (1.0): gap 0.2.
        // ECE = 0.5 * 0.2 + 0.5 * 0.2 = 0.2.
        let pairs = [(0.2, true), (0.4, false), (0.9, true), (0.7, true)];
        assert!(close(expected_calibration_error(&pairs, 2), 0.2));

        // Unequal masses: 3 pairs low (mean 0.3, rate 1/3) and 1 pair high (0.8, hit): gap 0 and 0.2.
        // ECE = 0.75 * |1/3 - 0.3| + 0.25 * 0.2 = 0.025 + 0.05 = 0.075.
        let pairs = [(0.3, true), (0.3, false), (0.3, false), (0.8, true)];
        assert!(close(expected_calibration_error(&pairs, 2), 0.075));
    }

    #[test]
    fn perfectly_calibrated_input_scores_zero() {
        // Bucket mean 0.75 with 3 of 4 hits.
        let pairs = [(0.75, true), (0.75, true), (0.75, true), (0.75, false)];
        assert!(close(expected_calibration_error(&pairs, 10), 0.0));
        assert!(close(expected_calibration_error_equal_mass(&pairs, 1), 0.0));
    }

    #[test]
    fn bins_report_counts_and_edges() {
        let pairs = [
            (0.0, false),
            (0.05, true),
            (0.5, true),
            (1.0, true),
            (0.999, false),
        ];
        let bins = calibration_bins(&pairs, 10);
        assert_eq!(bins.len(), 10);
        assert_eq!(bins[0].count, 2);
        assert!(close(bins[0].lo, 0.0) && close(bins[0].hi, 0.1));
        assert_eq!(bins[5].count, 1);
        // p == 1 folds into the last bucket together with 0.999.
        assert_eq!(bins[9].count, 2);
        assert!(close(bins[9].observed_rate, 0.5));
        assert!(close(bins[9].mean_predicted, 0.9995));
        assert_eq!(bins[1].count, 0);
        assert!(close(bins[1].gap(), 0.0));
        let total: usize = bins.iter().map(|b| b.count).sum();
        assert_eq!(total, pairs.len());
    }

    #[test]
    fn equal_mass_bins_split_by_rank() {
        // 7 pairs into 3 bins: sizes 3, 2, 2 by ascending prediction.
        let pairs = [
            (0.9, true),
            (0.1, false),
            (0.5, true),
            (0.3, false),
            (0.7, true),
            (0.2, false),
            (0.8, false),
        ];
        let bins = calibration_bins_equal_mass(&pairs, 3);
        let counts: Vec<usize> = bins.iter().map(|b| b.count).collect();
        assert_eq!(counts, vec![3, 2, 2]);
        assert!(close(bins[0].lo, 0.1) && close(bins[0].hi, 0.3));
        assert!(close(bins[0].observed_rate, 0.0));
        assert!(close(bins[0].mean_predicted, 0.2));
        assert!(close(bins[1].lo, 0.5) && close(bins[1].hi, 0.7));
        assert!(close(bins[1].observed_rate, 1.0));
        assert!(close(bins[2].observed_rate, 0.5));
        // ECE = 3/7 * 0.2 + 2/7 * 0.4 + 2/7 * |0.5 - 0.85|.
        let want = 3.0 / 7.0 * 0.2 + 2.0 / 7.0 * 0.4 + 2.0 / 7.0 * 0.35;
        assert!(close(expected_calibration_error_equal_mass(&pairs, 3), want));
    }

    #[test]
    fn degenerate_inputs() {
        assert!(close(expected_calibration_error(&[], 10), 0.0));
        assert!(close(expected_calibration_error(&[(0.5, true)], 0), 0.0));
        assert!(calibration_bins(&[(0.5, true)], 0).is_empty());
        assert!(calibration_bins_equal_mass(&[], 5).is_empty());
        // Out-of-range and NaN predictions clamp instead of panicking.
        let bins = calibration_bins(&[(1.5, true), (-0.2, false), (f64::NAN, false)], 2);
        assert_eq!(bins[0].count, 2);
        assert_eq!(bins[1].count, 1);
        // Fewer pairs than bins: trailing equal-mass buckets are empty.
        let bins = calibration_bins_equal_mass(&[(0.4, true)], 3);
        assert_eq!(bins.iter().map(|b| b.count).collect::<Vec<_>>(), vec![1, 0, 0]);
    }
}
