//! Evidence decay and Laplace smoothing.
//!
//! Effective success/failure counts are multiplied by `0.5^(age_days / 14)`
//! before the Laplace estimate `(s + 1) / (s + f + 2)`. The cost-side
//! staleness term `min(1, age_days / 30)` is separate.

use crawlx_core::Timestamp;

/// Half-life of edge evidence, in days (planning default).
pub const HALF_LIFE_DAYS: f64 = 14.0;
/// Age, in days, at which the cost-side staleness term saturates at 1.
pub const STALE_HORIZON_DAYS: f64 = 30.0;

const MS_PER_DAY: f64 = 86_400_000.0;

/// Whole-and-fractional days from `last_seen` to `now`; never negative.
#[must_use]
pub fn age_days(last_seen: Timestamp, now: Timestamp) -> f64 {
    let ms = now.signed_duration_since(last_seen).num_milliseconds();
    if ms <= 0 {
        0.0
    } else {
        ms as f64 / MS_PER_DAY
    }
}

/// `0.5^(age_days / 14)`.
#[must_use]
pub fn decay_factor(age_days: f64) -> f64 {
    0.5_f64.powf(age_days.max(0.0) / HALF_LIFE_DAYS)
}

/// `min(1, age_days / 30)`, the cost-side staleness.
#[must_use]
pub fn staleness(age_days: f64) -> f64 {
    (age_days.max(0.0) / STALE_HORIZON_DAYS).min(1.0)
}

/// Laplace-smoothed success probability `(s + 1) / (s + f + 2)`.
#[must_use]
pub fn laplace(s: f64, f: f64) -> f64 {
    (s + 1.0) / (s + f + 2.0)
}

/// Decayed Laplace probability for raw counts `s`, `f` observed `age_days` ago.
#[must_use]
pub fn decayed_p(s: f64, f: f64, age_days: f64) -> f64 {
    let k = decay_factor(age_days);
    laplace(s * k, f * k)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn laplace_hand_computed() {
        assert!((laplace(0.0, 0.0) - 0.5).abs() < 1e-12);
        assert!((laplace(3.0, 0.0) - 0.8).abs() < 1e-12);
        assert!((laplace(2.0, 2.0) - 0.5).abs() < 1e-12);
        assert!((laplace(0.0, 5.0) - 1.0 / 7.0).abs() < 1e-12);
    }

    #[test]
    fn one_half_life_halves_counts() {
        // s=4 -> 2 after 14 d; p = 3/4.
        assert!((decayed_p(4.0, 0.0, 14.0) - 0.75).abs() < 1e-12);
        // s=4, f=2 -> 2, 1 after 14 d; p = 3/5.
        assert!((decayed_p(4.0, 2.0, 14.0) - 0.6).abs() < 1e-12);
        // two half-lives: s=8 -> 2; p = 3/4.
        assert!((decayed_p(8.0, 0.0, 28.0) - 0.75).abs() < 1e-12);
    }

    #[test]
    fn staleness_saturates() {
        assert!((staleness(15.0) - 0.5).abs() < 1e-12);
        assert!((staleness(90.0) - 1.0).abs() < 1e-12);
        assert!(staleness(-3.0).abs() < 1e-12);
    }
}
