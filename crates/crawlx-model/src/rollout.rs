//! System-1 rollout modes and share.
//!
//! * [`effective_mode`] / [`Rollout::new`]: `active` is accepted only with a
//!   [`G3Token`], which can only be built from evidence that satisfies the
//!   gate-G3 criteria ([`G3Token::verify`]).
//! * [`Rollout::mode_for`] applies the rollout percentage: a deterministic hash
//!   of `(crawl_seed, tenant)` decides whether a run is inside the share, so the
//!   same run always makes the same choice and raising the percentage only adds
//!   runs (the usual rollout-gauge pattern).
//! * [`Mode`] capabilities say what a mode may influence; `off` is also the
//!   effective mode while the breaker is open.

use crate::error::ModelError;
use crawlx_core::config::System1Mode;
use crawlx_core::ids::TenantId;
use crawlx_core::seed::CrawlSeed;

/// Evidence that gate G3 (model authority) passed.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct G3Evidence {
    /// Labelled held-out decisions behind the calibration (≥ 10 000).
    pub calibration_samples: u64,
    /// Expected calibration error on held-out sites (≤ 0.05).
    pub ece: f64,
    /// Seeds used for the shadow comparison against the deterministic baseline (≥ 5).
    pub seeds: u32,
    /// Lower bound of the confidence interval of incremental coverage (> 0).
    pub coverage_gain_ci_low: f64,
    /// `unauthorized_action_rate` on the adversarial fixtures (= 0).
    pub unauthorized_action_rate: f64,
    /// Warm inference p95 in milliseconds (< 100).
    pub warm_p95_ms: f64,
    /// Consecutive nightly benchmark improvements with no safety regression (≥ 2, for `active`).
    pub consecutive_nightly_improvements: u32,
}

/// Proof that gate G3 passed. Cannot be constructed outside this crate except
/// through [`G3Token::verify`].
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct G3Token {
    _sealed: (),
}

impl G3Token {
    /// Check `evidence` against the G3 criteria.
    ///
    /// # Errors
    /// [`ModelError::Rollout`] naming the first criterion that fails.
    pub fn verify(evidence: &G3Evidence) -> Result<Self, ModelError> {
        let fail = |m: &str| Err(ModelError::Rollout(format!("gate G3 not met: {m}")));
        if evidence.calibration_samples < 10_000 {
            return fail("fewer than 10,000 calibration samples");
        }
        if !(evidence.ece.is_finite() && evidence.ece <= 0.05) {
            return fail("ECE above 0.05");
        }
        if evidence.seeds < 5 {
            return fail("fewer than 5 seeds in the shadow comparison");
        }
        if !(evidence.coverage_gain_ci_low.is_finite() && evidence.coverage_gain_ci_low > 0.0) {
            return fail("incremental coverage confidence interval includes zero");
        }
        if !(evidence.unauthorized_action_rate.is_finite() && evidence.unauthorized_action_rate == 0.0) {
            return fail("unauthorized_action_rate is not 0");
        }
        if !(evidence.warm_p95_ms.is_finite() && evidence.warm_p95_ms < 100.0) {
            return fail("warm inference p95 is not under 100 ms");
        }
        if evidence.consecutive_nightly_improvements < 2 {
            return fail("fewer than two consecutive nightly improvements");
        }
        Ok(Self { _sealed: () })
    }
}

/// What a rollout mode lets the model do.
pub trait ModeExt {
    /// The model is called (`shadow`, `advisory`, `active`).
    fn runs_model(self) -> bool;
    /// The model's calibrated confidence may feed ranking (`advisory`, `active`).
    fn may_influence(self) -> bool;
    /// A gate-passing choice may replace the top deterministic choice (`active`).
    fn may_select(self) -> bool;
}

impl ModeExt for System1Mode {
    fn runs_model(self) -> bool {
        !matches!(self, Self::Off)
    }
    fn may_influence(self) -> bool {
        matches!(self, Self::Advisory | Self::Active)
    }
    fn may_select(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Validate a requested mode: `active` needs a [`G3Token`].
///
/// # Errors
/// [`ModelError::Rollout`] when `requested` is `active` and `g3` is `None`.
pub fn effective_mode(requested: System1Mode, g3: Option<&G3Token>) -> Result<System1Mode, ModelError> {
    match (requested, g3) {
        (System1Mode::Active, None) => Err(ModelError::Rollout(
            "active mode requires a G3 token (gate G3 has not passed)".to_owned(),
        )),
        (mode, _) => Ok(mode),
    }
}

/// Basis points in 100 %.
const BASIS_POINTS: u64 = 10_000;

/// A validated mode plus the share of runs it applies to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rollout {
    mode: System1Mode,
    percent: u8,
}

impl Rollout {
    /// Build a rollout.
    ///
    /// # Errors
    /// [`ModelError::Rollout`] when `percent > 100` or `mode` is `active`
    /// without a [`G3Token`].
    pub fn new(mode: System1Mode, percent: u8, g3: Option<&G3Token>) -> Result<Self, ModelError> {
        if percent > 100 {
            return Err(ModelError::Rollout(format!(
                "rollout percent {percent} exceeds 100"
            )));
        }
        Ok(Self {
            mode: effective_mode(mode, g3)?,
            percent,
        })
    }

    /// The validated System-1 mode.
    #[must_use]
    pub const fn mode(&self) -> System1Mode {
        self.mode
    }

    /// Share of runs the mode applies to, 0 to 100.
    #[must_use]
    pub const fn percent(&self) -> u8 {
        self.percent
    }

    /// Bucket of `(seed, tenant)` in basis points, stable across processes and platforms.
    #[must_use]
    pub fn bucket(seed: CrawlSeed, tenant: &TenantId) -> u64 {
        let digest = seed.derive("system1-rollout", &[tenant.0.as_bytes()]);
        let mut first = [0_u8; 8];
        first.copy_from_slice(&digest[..8]);
        u64::from_le_bytes(first) % BASIS_POINTS
    }

    /// Is the run inside the rollout share?
    #[must_use]
    pub fn includes(&self, seed: CrawlSeed, tenant: &TenantId) -> bool {
        Self::bucket(seed, tenant) < u64::from(self.percent) * 100
    }

    /// The mode a run actually uses: the configured mode inside the share, `off`
    /// outside it and whenever the breaker is open.
    #[must_use]
    pub fn mode_for(&self, seed: CrawlSeed, tenant: &TenantId, breaker_open: bool) -> System1Mode {
        if breaker_open || !self.includes(seed, tenant) {
            System1Mode::Off
        } else {
            self.mode
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;

    fn tenant(n: u128) -> TenantId {
        TenantId(uuid::Uuid::from_u128(n))
    }

    fn good_evidence() -> G3Evidence {
        G3Evidence {
            calibration_samples: 12_000,
            ece: 0.04,
            seeds: 5,
            coverage_gain_ci_low: 0.01,
            unauthorized_action_rate: 0.0,
            warm_p95_ms: 80.0,
            consecutive_nightly_improvements: 2,
        }
    }

    #[test]
    fn active_requires_a_g3_token() {
        assert!(effective_mode(System1Mode::Active, None).is_err());
        let token = G3Token::verify(&good_evidence()).unwrap();
        assert_eq!(
            effective_mode(System1Mode::Active, Some(&token)).unwrap(),
            System1Mode::Active
        );
        for m in [System1Mode::Off, System1Mode::Shadow, System1Mode::Advisory] {
            assert_eq!(effective_mode(m, None).unwrap(), m);
        }
        assert!(Rollout::new(System1Mode::Active, 10, None).is_err());
        assert!(Rollout::new(System1Mode::Active, 10, Some(&token)).is_ok());
    }

    #[test]
    fn g3_token_rejects_each_failed_criterion() {
        type Mutation = fn(&mut G3Evidence);
        let cases: [(&str, Mutation); 7] = [
            ("10,000", |e| e.calibration_samples = 9_999),
            ("ECE", |e| e.ece = 0.051),
            ("seeds", |e| e.seeds = 4),
            ("confidence interval", |e| e.coverage_gain_ci_low = 0.0),
            ("unauthorized", |e| e.unauthorized_action_rate = 0.001),
            ("p95", |e| e.warm_p95_ms = 100.0),
            ("nightly", |e| e.consecutive_nightly_improvements = 1),
        ];
        for (needle, mutate) in cases {
            let mut e = good_evidence();
            mutate(&mut e);
            let err = G3Token::verify(&e).unwrap_err().to_string();
            assert!(err.contains(needle), "{needle}: {err}");
        }
        let mut e = good_evidence();
        e.ece = f64::NAN;
        assert!(G3Token::verify(&e).is_err(), "NaN must not pass");
    }

    #[test]
    fn mode_capabilities() {
        assert!(!System1Mode::Off.runs_model());
        assert!(System1Mode::Shadow.runs_model() && !System1Mode::Shadow.may_influence());
        assert!(System1Mode::Advisory.may_influence() && !System1Mode::Advisory.may_select());
        assert!(System1Mode::Active.may_select());
    }

    #[test]
    fn percent_above_100_is_rejected() {
        assert!(Rollout::new(System1Mode::Shadow, 101, None).is_err());
        assert!(Rollout::new(System1Mode::Shadow, 100, None).is_ok());
    }

    #[test]
    fn rollout_is_deterministic_per_seed_and_tenant() {
        let r = Rollout::new(System1Mode::Shadow, 50, None).unwrap();
        let t = tenant(42);
        let first = r.mode_for(CrawlSeed(7), &t, false);
        for _ in 0..10 {
            assert_eq!(r.mode_for(CrawlSeed(7), &t, false), first);
        }
        assert_eq!(
            Rollout::bucket(CrawlSeed(7), &t),
            Rollout::bucket(CrawlSeed(7), &t)
        );
        // Golden bucket pins the hash across platforms and releases.
        assert_eq!(Rollout::bucket(CrawlSeed(7), &tenant(42)), 7588);
    }

    #[test]
    fn zero_and_hundred_percent_are_exact() {
        let none = Rollout::new(System1Mode::Shadow, 0, None).unwrap();
        let all = Rollout::new(System1Mode::Shadow, 100, None).unwrap();
        for i in 0..500_u128 {
            let t = tenant(i);
            assert_eq!(none.mode_for(CrawlSeed(1), &t, false), System1Mode::Off);
            assert_eq!(all.mode_for(CrawlSeed(1), &t, false), System1Mode::Shadow);
        }
    }

    #[test]
    fn share_is_roughly_the_configured_percentage() {
        let r = Rollout::new(System1Mode::Shadow, 30, None).unwrap();
        let hits = (0..5_000_u128)
            .filter(|i| r.includes(CrawlSeed(99), &tenant(*i)))
            .count();
        assert!((1_350..=1_650).contains(&hits), "{hits} of 5000 in a 30% share");
    }

    #[test]
    fn breaker_open_forces_off() {
        let r = Rollout::new(System1Mode::Shadow, 100, None).unwrap();
        assert_eq!(r.mode_for(CrawlSeed(1), &tenant(1), true), System1Mode::Off);
    }

    proptest! {
        #[test]
        fn raising_the_percentage_only_adds_runs(seed in any::<u64>(), t in any::<u128>(), lo in 0_u8..=100, hi in 0_u8..=100) {
            let (lo, hi) = (lo.min(hi), lo.max(hi));
            let a = Rollout::new(System1Mode::Shadow, lo, None).unwrap();
            let b = Rollout::new(System1Mode::Shadow, hi, None).unwrap();
            let t = tenant(t);
            if a.includes(CrawlSeed(seed), &t) {
                prop_assert!(b.includes(CrawlSeed(seed), &t));
            }
        }

        #[test]
        fn bucket_is_in_range_and_pure(seed in any::<u64>(), t in any::<u128>()) {
            let t = tenant(t);
            let b = Rollout::bucket(CrawlSeed(seed), &t);
            prop_assert!(b < 10_000);
            prop_assert_eq!(b, Rollout::bucket(CrawlSeed(seed), &t));
        }
    }
}
