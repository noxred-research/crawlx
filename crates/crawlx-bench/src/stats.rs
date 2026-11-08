//! Benchmark statistics: paired bootstrap confidence intervals, the Wilcoxon
//! signed-rank test, the pilot variance analysis that sizes seed sets, and the committed seed
//! sets themselves (`bench/seeds.toml`).
//!
//! Everything here is deterministic: the bootstrap resampler is seeded through
//! [`CrawlSeed`], there is no wall-clock input, and the Wilcoxon statistic uses an exact
//! enumeration for small samples (no approximation noise).

use crawlx_core::seed::CrawlSeed;
use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Resamples the planning default uses.
pub const DEFAULT_RESAMPLES: usize = 10_000;
/// Confidence level the planning default uses.
pub const DEFAULT_LEVEL: f64 = 0.95;
/// Coverage half-width target the pilot sizes seeds for.
pub const DEFAULT_HALF_WIDTH: f64 = 0.02;

/// A statistic could not be computed from the data it was given.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatsError {
    /// Baseline and candidate have different lengths: they are not paired.
    #[error("paired samples differ in length: baseline {baseline}, candidate {candidate}")]
    Unpaired {
        /// Baseline length.
        baseline: usize,
        /// Candidate length.
        candidate: usize,
    },
    /// Fewer samples than the statistic needs.
    #[error("need at least {needed} samples, got {got}")]
    TooFew {
        /// Minimum.
        needed: usize,
        /// Provided.
        got: usize,
    },
    /// A sample is NaN or infinite.
    #[error("sample {index} is not finite")]
    NotFinite {
        /// Position of the offending sample.
        index: usize,
    },
    /// A level, half-width or resample count is outside its domain.
    #[error("{what} must satisfy {constraint}")]
    Domain {
        /// Parameter name.
        what: &'static str,
        /// Human-readable constraint.
        constraint: &'static str,
    },
    /// A seed set file did not parse or did not validate.
    #[error("seed set: {0}")]
    Seeds(String),
}

/// Which direction of a paired difference counts as "better".
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Candidate minus baseline should be positive (coverage, recall, AUC).
    HigherIsBetter,
    /// Candidate minus baseline should be negative (`T80`, actions per target, cost).
    LowerIsBetter,
}

/// Paired bootstrap of the mean difference `candidate - baseline` over per-seed pairs.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PairedBootstrap {
    /// Number of pairs.
    pub pairs: usize,
    /// Mean of the paired differences.
    pub mean_diff: f64,
    /// Lower end of the percentile interval.
    pub lo: f64,
    /// Upper end of the percentile interval.
    pub hi: f64,
    /// Confidence level the interval was computed at.
    pub level: f64,
    /// Bootstrap resamples drawn.
    pub resamples: usize,
}

impl PairedBootstrap {
    /// `true` when the whole interval lies on the "better" side of zero.
    #[must_use]
    pub fn is_improvement(&self, direction: Direction) -> bool {
        match direction {
            Direction::HigherIsBetter => self.lo > 0.0,
            Direction::LowerIsBetter => self.hi < 0.0,
        }
    }

    /// `true` when the interval excludes zero in either direction.
    #[must_use]
    pub fn excludes_zero(&self) -> bool {
        self.lo > 0.0 || self.hi < 0.0
    }
}

fn check_pairs(baseline: &[f64], candidate: &[f64], needed: usize) -> Result<Vec<f64>, StatsError> {
    if baseline.len() != candidate.len() {
        return Err(StatsError::Unpaired {
            baseline: baseline.len(),
            candidate: candidate.len(),
        });
    }
    if baseline.len() < needed {
        return Err(StatsError::TooFew {
            needed,
            got: baseline.len(),
        });
    }
    for (index, v) in baseline.iter().chain(candidate.iter()).enumerate() {
        if !v.is_finite() {
            return Err(StatsError::NotFinite {
                index: index % baseline.len(),
            });
        }
    }
    Ok(baseline.iter().zip(candidate).map(|(b, c)| c - b).collect())
}

fn check_level(level: f64) -> Result<(), StatsError> {
    if level.is_finite() && level > 0.0 && level < 1.0 {
        Ok(())
    } else {
        Err(StatsError::Domain {
            what: "level",
            constraint: "0 < level < 1",
        })
    }
}

fn mean(xs: &[f64]) -> f64 {
    // Lengths are checked non-zero by the callers; the cast is exact for any realistic sample.
    xs.iter().sum::<f64>() / f64::from(u32::try_from(xs.len()).unwrap_or(u32::MAX))
}

/// Sample variance (`n - 1` denominator).
fn sample_variance(xs: &[f64]) -> f64 {
    let m = mean(xs);
    let n = f64::from(u32::try_from(xs.len()).unwrap_or(u32::MAX));
    xs.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (n - 1.0)
}

/// Value at quantile `q` of a sorted slice (nearest-rank, inclusive).
fn sorted_quantile(sorted: &[f64], q: f64) -> f64 {
    let n = sorted.len();
    // `q * (n - 1)` is in `[0, n - 1]`; rounding then truncating cannot leave that range.
    let n_minus_one = f64::from(u32::try_from(n - 1).unwrap_or(u32::MAX));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let idx = ((q * n_minus_one).round() as usize).min(n - 1);
    sorted[idx]
}

/// Value at quantile `q` of an ascending slice (nearest-rank, inclusive); `None` when empty.
#[must_use]
pub fn quantile(sorted: &[f64], q: f64) -> Option<f64> {
    (!sorted.is_empty()).then(|| sorted_quantile(sorted, q.clamp(0.0, 1.0)))
}

/// Percentile bootstrap interval of the mean paired difference.
///
/// Resampling draws `resamples` samples of size `n` with replacement from the per-seed
/// differences, using an RNG derived from `seed` so a report is reproducible.
///
/// # Errors
/// [`StatsError::Unpaired`] when the slices differ in length, [`StatsError::TooFew`] below two
/// pairs, [`StatsError::NotFinite`] on NaN/inf, [`StatsError::Domain`] for a level outside
/// `(0, 1)` or zero resamples.
pub fn paired_bootstrap(
    baseline: &[f64],
    candidate: &[f64],
    resamples: usize,
    level: f64,
    seed: CrawlSeed,
) -> Result<PairedBootstrap, StatsError> {
    let diffs = check_pairs(baseline, candidate, 2)?;
    check_level(level)?;
    if resamples == 0 {
        return Err(StatsError::Domain {
            what: "resamples",
            constraint: "resamples >= 1",
        });
    }
    let n = diffs.len();
    let mut rng = seed.rng("bench/paired-bootstrap", &[&(n as u64).to_le_bytes()]);
    let mut means = Vec::with_capacity(resamples);
    for _ in 0..resamples {
        let mut acc = 0.0;
        for _ in 0..n {
            acc += diffs[rng.random_range(0..n)];
        }
        means.push(acc / f64::from(u32::try_from(n).unwrap_or(u32::MAX)));
    }
    means.sort_by(f64::total_cmp);
    let alpha = 1.0 - level;
    Ok(PairedBootstrap {
        pairs: n,
        mean_diff: mean(&diffs),
        lo: sorted_quantile(&means, alpha / 2.0),
        hi: sorted_quantile(&means, 1.0 - alpha / 2.0),
        level,
        resamples,
    })
}

/// How the Wilcoxon p-value was obtained.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WilcoxonMethod {
    /// Exact enumeration of the rank-sum distribution (ties handled by doubled mid-ranks).
    Exact,
    /// Normal approximation with tie and continuity corrections.
    Normal,
}

/// Wilcoxon signed-rank test over paired differences.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Wilcoxon {
    /// Non-zero differences that entered the test (zeros are discarded, Wilcoxon 1945).
    pub n: usize,
    /// Sum of ranks of positive differences (`candidate > baseline`).
    pub w_plus: f64,
    /// Sum of ranks of negative differences.
    pub w_minus: f64,
    /// Two-sided p-value.
    pub p_two_sided: f64,
    /// How the p-value was computed.
    pub method: WilcoxonMethod,
}

/// Largest `n` the exact enumeration is used for.
const WILCOXON_EXACT_MAX_N: usize = 50;

/// Mid-ranks of `|d|`, doubled so ties keep them integral.
fn doubled_mid_ranks(abs: &[f64]) -> Vec<u64> {
    let mut order: Vec<usize> = (0..abs.len()).collect();
    order.sort_by(|a, b| abs[*a].total_cmp(&abs[*b]));
    let mut ranks = vec![0u64; abs.len()];
    let mut i = 0;
    while i < order.len() {
        let mut j = i;
        while j + 1 < order.len() && abs[order[j + 1]] == abs[order[i]] {
            j += 1;
        }
        // Positions i..=j (1-based ranks i+1..=j+1) share mid-rank (i+1 + j+1)/2; doubled: i+j+2.
        let doubled = (i + j + 2) as u64;
        for &k in &order[i..=j] {
            ranks[k] = doubled;
        }
        i = j + 1;
    }
    ranks
}

/// Exact two-sided p-value: `P(W <= w_min)` doubled, with `W` the rank-sum of a random
/// sign assignment. Ranks are doubled mid-ranks, so sums are integers.
fn wilcoxon_exact_p(doubled_ranks: &[u64], doubled_w_min: u64) -> f64 {
    let total: u64 = doubled_ranks.iter().sum();
    // `counts[s]` = number of sign assignments whose doubled rank sum is `s`.
    let total_usize = usize::try_from(total).unwrap_or(usize::MAX);
    let mut counts = vec![0.0f64; total_usize + 1];
    counts[0] = 1.0;
    for &r in doubled_ranks {
        let r = usize::try_from(r).unwrap_or(usize::MAX);
        for s in (r..=total_usize).rev() {
            counts[s] += counts[s - r];
        }
    }
    let w = usize::try_from(doubled_w_min)
        .unwrap_or(usize::MAX)
        .min(total_usize);
    let le: f64 = counts[..=w].iter().sum();
    let all = 2f64.powi(i32::try_from(doubled_ranks.len()).unwrap_or(i32::MAX));
    (2.0 * le / all).min(1.0)
}

/// Standard normal CDF (Abramowitz & Stegun 26.2.17, |error| < 7.5e-8).
fn normal_cdf(x: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.2316419 * x.abs());
    let poly =
        t * (0.319381530 + t * (-0.356563782 + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
    let pdf = (-0.5 * x * x).exp() / (2.0 * std::f64::consts::PI).sqrt();
    let upper = pdf * poly;
    if x >= 0.0 {
        1.0 - upper
    } else {
        upper
    }
}

/// Inverse of the standard normal CDF (Acklam's algorithm, relative error < 1.15e-9).
fn normal_quantile(p: f64) -> f64 {
    const A: [f64; 6] = [
        -3.969_683_028_665_376e1,
        2.209_460_984_245_205e2,
        -2.759_285_104_469_687e2,
        1.383_577_518_672_69e2,
        -3.066_479_806_614_716e1,
        2.506_628_277_459_239,
    ];
    const B: [f64; 5] = [
        -5.447_609_879_822_406e1,
        1.615_858_368_580_409e2,
        -1.556_989_798_598_866e2,
        6.680_131_188_771_972e1,
        -1.328_068_155_288_572e1,
    ];
    const C: [f64; 6] = [
        -7.784_894_002_430_293e-3,
        -3.223_964_580_411_365e-1,
        -2.400_758_277_161_838,
        -2.549_732_539_343_734,
        4.374_664_141_464_968,
        2.938_163_982_698_783,
    ];
    const D: [f64; 4] = [
        7.784_695_709_041_462e-3,
        3.224_671_290_700_398e-1,
        2.445_134_137_142_996,
        3.754_408_661_907_416,
    ];
    const P_LOW: f64 = 0.02425;
    if p < P_LOW {
        let q = (-2.0 * p.ln()).sqrt();
        (((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    } else if p <= 1.0 - P_LOW {
        let q = p - 0.5;
        let r = q * q;
        (((((A[0] * r + A[1]) * r + A[2]) * r + A[3]) * r + A[4]) * r + A[5]) * q
            / (((((B[0] * r + B[1]) * r + B[2]) * r + B[3]) * r + B[4]) * r + 1.0)
    } else {
        let q = (-2.0 * (1.0 - p).ln()).sqrt();
        -(((((C[0] * q + C[1]) * q + C[2]) * q + C[3]) * q + C[4]) * q + C[5])
            / ((((D[0] * q + D[1]) * q + D[2]) * q + D[3]) * q + 1.0)
    }
}

/// Two-sided Wilcoxon signed-rank test of `candidate - baseline` (robustness
/// check). Zero differences are dropped; ties among `|d|` get mid-ranks. Exact for up to
/// [`WILCOXON_EXACT_MAX_N`] non-zero pairs, normal approximation beyond.
///
/// # Errors
/// [`StatsError::Unpaired`], [`StatsError::NotFinite`], or [`StatsError::TooFew`] when fewer
/// than one non-zero difference remains.
pub fn wilcoxon_signed_rank(baseline: &[f64], candidate: &[f64]) -> Result<Wilcoxon, StatsError> {
    let diffs = check_pairs(baseline, candidate, 1)?;
    let nonzero: Vec<f64> = diffs.into_iter().filter(|d| *d != 0.0).collect();
    if nonzero.is_empty() {
        return Err(StatsError::TooFew { needed: 1, got: 0 });
    }
    let abs: Vec<f64> = nonzero.iter().map(|d| d.abs()).collect();
    let doubled = doubled_mid_ranks(&abs);
    let (mut dw_plus, mut dw_minus) = (0u64, 0u64);
    for (d, r) in nonzero.iter().zip(&doubled) {
        if *d > 0.0 {
            dw_plus += r;
        } else {
            dw_minus += r;
        }
    }
    let n = nonzero.len();
    let w_plus = dw_plus as f64 / 2.0;
    let w_minus = dw_minus as f64 / 2.0;
    let (p, method) = if n <= WILCOXON_EXACT_MAX_N {
        (
            wilcoxon_exact_p(&doubled, dw_plus.min(dw_minus)),
            WilcoxonMethod::Exact,
        )
    } else {
        let nf = n as f64;
        let mean = nf * (nf + 1.0) / 4.0;
        // Tie correction: sum over tie groups of (t^3 - t) / 48.
        let mut groups: BTreeMap<u64, f64> = BTreeMap::new();
        for r in &doubled {
            *groups.entry(*r).or_insert(0.0) += 1.0;
        }
        let tie: f64 = groups.values().map(|t| (t * t * t - t) / 48.0).sum();
        let var = nf * (nf + 1.0) * (2.0 * nf + 1.0) / 24.0 - tie;
        let w_min = w_plus.min(w_minus);
        let z = (w_min - mean + 0.5) / var.sqrt();
        ((2.0 * normal_cdf(z)).min(1.0), WilcoxonMethod::Normal)
    };
    Ok(Wilcoxon {
        n,
        w_plus,
        w_minus,
        p_two_sided: p,
        method,
    })
}

/// Pilot variance analysis: how many seeds a configuration needs so the
/// confidence-interval half-width of its mean is at most `half_width`.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PilotAnalysis {
    /// Pilot sample size.
    pub pilot_seeds: usize,
    /// Pilot mean.
    pub mean: f64,
    /// Pilot sample variance (`n - 1`).
    pub variance: f64,
    /// Half-width of the pilot's own interval at `level`.
    pub pilot_half_width: f64,
    /// Target half-width.
    pub target_half_width: f64,
    /// Seeds needed for the target half-width, never below two.
    pub seeds_needed: usize,
    /// Confidence level.
    pub level: f64,
}

/// Sizes a seed set from a pilot: `n = ceil((z * s / h)^2)`, with `z` the
/// two-sided normal quantile at `level`, `s` the pilot standard deviation and `h` the
/// target half-width. A zero-variance pilot (deterministic metric) needs two seeds: the
/// second run is the determinism check.
///
/// # Errors
/// [`StatsError::TooFew`] below two samples, [`StatsError::NotFinite`], or
/// [`StatsError::Domain`] for a non-positive half-width or a level outside `(0, 1)`.
pub fn pilot_variance(samples: &[f64], half_width: f64, level: f64) -> Result<PilotAnalysis, StatsError> {
    if samples.len() < 2 {
        return Err(StatsError::TooFew {
            needed: 2,
            got: samples.len(),
        });
    }
    if let Some(index) = samples.iter().position(|v| !v.is_finite()) {
        return Err(StatsError::NotFinite { index });
    }
    if !(half_width.is_finite() && half_width > 0.0) {
        return Err(StatsError::Domain {
            what: "half_width",
            constraint: "half_width > 0",
        });
    }
    check_level(level)?;
    let z = normal_quantile(1.0 - (1.0 - level) / 2.0);
    let variance = sample_variance(samples);
    let sd = variance.sqrt();
    let n_pilot = f64::from(u32::try_from(samples.len()).unwrap_or(u32::MAX));
    let needed = (z * sd / half_width).powi(2).ceil();
    // `needed` is finite and non-negative; saturate rather than wrap on absurd variances.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let seeds_needed = if needed > u32::MAX.into() {
        usize::MAX
    } else {
        (needed as usize).max(2)
    };
    Ok(PilotAnalysis {
        pilot_seeds: samples.len(),
        mean: mean(samples),
        variance,
        pilot_half_width: z * sd / n_pilot.sqrt(),
        target_half_width: half_width,
        seeds_needed,
        level,
    })
}

/// Full paired comparison of one metric between a baseline and a candidate configuration.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PairedComparison {
    /// Metric name (`coverage.trusted`, `coverage.auc`, `t80`).
    pub metric: String,
    /// Seeds, in pair order.
    pub seeds: Vec<u64>,
    /// Baseline values per seed.
    pub baseline: Vec<f64>,
    /// Candidate values per seed.
    pub candidate: Vec<f64>,
    /// Direction that counts as better.
    pub direction: Direction,
    /// Bootstrap interval of the mean difference.
    pub bootstrap: PairedBootstrap,
    /// Wilcoxon signed-rank robustness check, `None` when every pair is tied.
    pub wilcoxon: Option<Wilcoxon>,
}

impl PairedComparison {
    /// Computes both statistics for one metric.
    ///
    /// # Errors
    /// Propagates [`paired_bootstrap`] errors; a Wilcoxon with no non-zero pair yields `None`.
    pub fn compute(
        metric: impl Into<String>,
        seeds: &[u64],
        baseline: &[f64],
        candidate: &[f64],
        direction: Direction,
        resamples: usize,
        level: f64,
    ) -> Result<Self, StatsError> {
        if seeds.len() != baseline.len() {
            return Err(StatsError::Unpaired {
                baseline: baseline.len(),
                candidate: seeds.len(),
            });
        }
        let Some(first) = seeds.first() else {
            return Err(StatsError::TooFew { needed: 2, got: 0 });
        };
        let bootstrap = paired_bootstrap(baseline, candidate, resamples, level, CrawlSeed(*first))?;
        let wilcoxon = match wilcoxon_signed_rank(baseline, candidate) {
            Ok(w) => Some(w),
            Err(StatsError::TooFew { .. }) => None,
            Err(e) => return Err(e),
        };
        Ok(Self {
            metric: metric.into(),
            seeds: seeds.to_vec(),
            baseline: baseline.to_vec(),
            candidate: candidate.to_vec(),
            direction,
            bootstrap,
            wilcoxon,
        })
    }

    /// The verdict: the interval excludes zero in the intended direction.
    #[must_use]
    pub fn is_improvement(&self) -> bool {
        self.bootstrap.is_improvement(self.direction)
    }

    /// One Markdown line per comparison.
    #[must_use]
    pub fn render_markdown_row(&self) -> String {
        let w = self.wilcoxon.as_ref().map_or("tied".to_owned(), |w| {
            format!("{:.4} ({:?})", w.p_two_sided, w.method)
        });
        format!(
            "| {} | {} | {:+.4} | [{:+.4}, {:+.4}] | {} | {} |",
            self.metric,
            self.seeds.len(),
            self.bootstrap.mean_diff,
            self.bootstrap.lo,
            self.bootstrap.hi,
            w,
            if self.is_improvement() {
                "better"
            } else {
                "not shown"
            }
        )
    }
}

/// Seed sets per suite, as committed in `bench/seeds.toml`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedSets {
    /// Schema version of the file.
    pub version: u32,
    /// Suite name → seed list.
    pub suite: BTreeMap<String, SeedSuite>,
}

/// One suite's seeds.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedSuite {
    /// Why this many seeds (planning default, pilot result, ...).
    pub rationale: String,
    /// Fixed seed list, in run order.
    pub seeds: Vec<u64>,
}

/// The committed seed file.
pub const SEEDS_TOML: &str = include_str!("../../../bench/seeds.toml");

impl SeedSets {
    /// Parses and validates a `seeds.toml` document.
    ///
    /// # Errors
    /// [`StatsError::Seeds`] when the document does not parse, a suite is empty, a seed
    /// repeats inside a suite, or `pr`/`nightly`/`release` is missing.
    pub fn parse(text: &str) -> Result<Self, StatsError> {
        let sets: Self = toml::from_str(text).map_err(|e| StatsError::Seeds(e.to_string()))?;
        for required in ["pr", "nightly", "release", "pilot"] {
            if !sets.suite.contains_key(required) {
                return Err(StatsError::Seeds(format!("suite `{required}` is missing")));
            }
        }
        for (name, suite) in &sets.suite {
            if suite.seeds.is_empty() {
                return Err(StatsError::Seeds(format!("suite `{name}` has no seeds")));
            }
            let mut sorted = suite.seeds.clone();
            sorted.sort_unstable();
            if sorted.windows(2).any(|w| w[0] == w[1]) {
                return Err(StatsError::Seeds(format!("suite `{name}` repeats a seed")));
            }
        }
        Ok(sets)
    }

    /// The committed seed sets.
    ///
    /// # Errors
    /// Only if the committed file is invalid, which the unit tests prevent.
    pub fn committed() -> Result<Self, StatsError> {
        Self::parse(SEEDS_TOML)
    }

    /// Seeds of `suite`, if present.
    #[must_use]
    pub fn seeds(&self, suite: &str) -> Option<&[u64]> {
        self.suite.get(suite).map(|s| s.seeds.as_slice())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn seed() -> CrawlSeed {
        CrawlSeed(42)
    }

    #[test]
    fn bootstrap_of_a_constant_shift_is_that_shift() {
        let b = [0.50, 0.55, 0.60, 0.52, 0.58, 0.61];
        let c: Vec<f64> = b.iter().map(|x| x + 0.1).collect();
        let r = paired_bootstrap(&b, &c, 2_000, 0.95, seed()).unwrap();
        assert!((r.mean_diff - 0.1).abs() < 1e-12);
        assert!((r.lo - 0.1).abs() < 1e-12 && (r.hi - 0.1).abs() < 1e-12);
        assert!(r.is_improvement(Direction::HigherIsBetter));
        assert!(!r.is_improvement(Direction::LowerIsBetter));
    }

    #[test]
    fn bootstrap_interval_covers_the_true_difference_and_is_reproducible() {
        // Differences 0.05 ± noise: the interval must contain 0.05 and exclude zero.
        let b: Vec<f64> = (0..20).map(|i| 0.5 + f64::from(i % 5) * 0.01).collect();
        let noise = [
            0.01, -0.012, 0.008, -0.005, 0.015, -0.009, 0.004, -0.011, 0.007, -0.003,
        ];
        let c: Vec<f64> = b
            .iter()
            .enumerate()
            .map(|(i, x)| x + 0.05 + noise[i % 10])
            .collect();
        let r1 = paired_bootstrap(&b, &c, DEFAULT_RESAMPLES, DEFAULT_LEVEL, seed()).unwrap();
        let r2 = paired_bootstrap(&b, &c, DEFAULT_RESAMPLES, DEFAULT_LEVEL, seed()).unwrap();
        assert_eq!(r1, r2);
        assert!(r1.lo <= 0.05 && 0.05 <= r1.hi, "{r1:?}");
        assert!(r1.excludes_zero());
        assert!(r1.hi - r1.lo < 0.02, "{r1:?}");
        let other = paired_bootstrap(&b, &c, DEFAULT_RESAMPLES, DEFAULT_LEVEL, CrawlSeed(7)).unwrap();
        assert!((other.mean_diff - r1.mean_diff).abs() < 1e-12);
        assert!((other.lo - r1.lo).abs() < 0.005);
    }

    #[test]
    fn bootstrap_of_pure_noise_includes_zero() {
        let b: Vec<f64> = (0..12).map(|i| 0.5 + f64::from(i % 4) * 0.02).collect();
        let noise = [0.01, -0.01, 0.02, -0.02, 0.005, -0.005];
        let c: Vec<f64> = b.iter().enumerate().map(|(i, x)| x + noise[i % 6]).collect();
        let r = paired_bootstrap(&b, &c, 5_000, 0.95, seed()).unwrap();
        assert!(!r.excludes_zero(), "{r:?}");
    }

    #[test]
    fn bootstrap_rejects_bad_input() {
        assert_eq!(
            paired_bootstrap(&[1.0, 2.0], &[1.0], 10, 0.95, seed()),
            Err(StatsError::Unpaired {
                baseline: 2,
                candidate: 1
            })
        );
        assert_eq!(
            paired_bootstrap(&[1.0], &[1.0], 10, 0.95, seed()),
            Err(StatsError::TooFew { needed: 2, got: 1 })
        );
        assert!(matches!(
            paired_bootstrap(&[1.0, f64::NAN], &[1.0, 2.0], 10, 0.95, seed()),
            Err(StatsError::NotFinite { index: 1 })
        ));
        assert!(matches!(
            paired_bootstrap(&[1.0, 2.0], &[1.0, 2.0], 10, 1.0, seed()),
            Err(StatsError::Domain { what: "level", .. })
        ));
        assert!(matches!(
            paired_bootstrap(&[1.0, 2.0], &[1.0, 2.0], 0, 0.9, seed()),
            Err(StatsError::Domain {
                what: "resamples",
                ..
            })
        ));
    }

    #[test]
    fn wilcoxon_textbook_example_matches_the_known_answer() {
        // Classic 10-pair example (Wilcoxon 1945 / Siegel): W+ = 40, W- = 15, n = 10.
        let before = [
            125.0, 115.0, 130.0, 140.0, 140.0, 115.0, 140.0, 125.0, 140.0, 135.0,
        ];
        let after = [
            110.0, 122.0, 125.0, 120.0, 140.0, 124.0, 123.0, 137.0, 135.0, 145.0,
        ];
        let w = wilcoxon_signed_rank(&before, &after).unwrap();
        assert_eq!(w.n, 9, "one zero difference dropped");
        assert_eq!(w.method, WilcoxonMethod::Exact);
        assert!((w.w_plus + w.w_minus - 45.0).abs() < 1e-12);
        assert!((w.w_plus - 18.0).abs() < 1e-12 && (w.w_minus - 27.0).abs() < 1e-12);
        // Doubled mid-ranks {3,3,6,8,10,12,14,16,18}: 162 of 512 sign assignments have a rank
        // sum <= 18 (enumerated independently), so p = 2 * 162 / 512.
        assert!((w.p_two_sided - 2.0 * 162.0 / 512.0).abs() < 1e-12, "{w:?}");
    }

    #[test]
    fn wilcoxon_all_positive_small_sample_is_the_minimum_p() {
        // n = 6, all differences positive: p = 2 * (1/64) = 0.03125.
        let b = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let c = [2.0, 4.0, 6.0, 8.0, 10.0, 12.0];
        let w = wilcoxon_signed_rank(&b, &c).unwrap();
        assert!((w.w_plus - 21.0).abs() < 1e-12);
        assert!((w.w_minus).abs() < 1e-12);
        assert!((w.p_two_sided - 0.03125).abs() < 1e-12, "{w:?}");
    }

    #[test]
    fn wilcoxon_ties_use_mid_ranks() {
        // |d| = 1, 1, 2 → ranks 1.5, 1.5, 3.
        let b = [0.0, 0.0, 0.0];
        let c = [1.0, -1.0, 2.0];
        let w = wilcoxon_signed_rank(&b, &c).unwrap();
        assert!((w.w_plus - 4.5).abs() < 1e-12);
        assert!((w.w_minus - 1.5).abs() < 1e-12);
        assert!(w.p_two_sided <= 1.0 && w.p_two_sided > 0.0);
    }

    #[test]
    fn wilcoxon_large_sample_uses_the_normal_approximation_and_agrees_with_exact_on_the_edge() {
        let n = WILCOXON_EXACT_MAX_N;
        let b: Vec<f64> = (0..n).map(|i| i as f64).collect();
        let c: Vec<f64> = b
            .iter()
            .enumerate()
            .map(|(i, x)| x + if i % 3 == 0 { -1.0 } else { 2.0 } * (1.0 + (i % 7) as f64))
            .collect();
        let exact = wilcoxon_signed_rank(&b, &c).unwrap();
        assert_eq!(exact.method, WilcoxonMethod::Exact);
        let mut b2 = b.clone();
        let mut c2 = c.clone();
        b2.push(1000.0);
        c2.push(1000.5);
        let approx = wilcoxon_signed_rank(&b2, &c2).unwrap();
        assert_eq!(approx.method, WilcoxonMethod::Normal);
        assert_eq!(approx.n, n + 1);
        assert!(approx.p_two_sided < 0.01, "{approx:?}");
        assert!(exact.p_two_sided < 0.01, "{exact:?}");
    }

    #[test]
    fn wilcoxon_all_ties_is_too_few() {
        assert_eq!(
            wilcoxon_signed_rank(&[1.0, 2.0], &[1.0, 2.0]),
            Err(StatsError::TooFew { needed: 1, got: 0 })
        );
    }

    #[test]
    fn normal_functions_match_tables() {
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-7);
        assert!((normal_cdf(1.96) - 0.975_002).abs() < 1e-5);
        assert!((normal_cdf(-1.0) - 0.158_655).abs() < 1e-5);
        assert!((normal_quantile(0.975) - 1.959_964).abs() < 1e-5);
        assert!((normal_quantile(0.5)).abs() < 1e-9);
        assert!((normal_quantile(0.01) + 2.326_348).abs() < 1e-5);
    }

    #[test]
    fn pilot_sizes_seeds_from_a_known_variance() {
        // ±0.05 around 0.5 with n = 4: sample variance = 4 * 0.0025 / 3, sd = 0.057735;
        // (1.959964 * 0.057735 / 0.02)^2 = 32.02 → 33 seeds.
        let samples = [0.5 - 0.05, 0.5 + 0.05, 0.5 - 0.05, 0.5 + 0.05];
        let p = pilot_variance(&samples, DEFAULT_HALF_WIDTH, DEFAULT_LEVEL).unwrap();
        // Sample variance of ±0.05 with n = 4 is 0.0025 * 4 / 3.
        assert!((p.variance - 0.0025 * 4.0 / 3.0).abs() < 1e-12);
        let expected = ((1.959_964 * p.variance.sqrt()) / 0.02_f64).powi(2).ceil();
        assert!((expected - 33.0).abs() < f64::EPSILON, "{expected}");
        assert_eq!(p.seeds_needed, 33);
        assert!((p.mean - 0.5).abs() < 1e-12);
        assert!(p.pilot_half_width > 0.0);
    }

    #[test]
    fn pilot_with_exact_variance_gives_the_textbook_count() {
        // Eight samples with sample variance exactly 0.0025 (sd 0.05) → 25 seeds.
        let d = (0.0025_f64 * 7.0 / 8.0).sqrt();
        let samples: Vec<f64> = (0..8)
            .map(|i| if i % 2 == 0 { 0.5 - d } else { 0.5 + d })
            .collect();
        let p = pilot_variance(&samples, 0.02, 0.95).unwrap();
        assert!((p.variance - 0.0025).abs() < 1e-12, "{}", p.variance);
        assert_eq!(p.seeds_needed, 25);
    }

    #[test]
    fn pilot_of_a_deterministic_metric_needs_two_seeds() {
        let p = pilot_variance(&[0.7, 0.7, 0.7, 0.7, 0.7], 0.02, 0.95).unwrap();
        assert!(p.variance.abs() < 1e-18);
        assert_eq!(p.seeds_needed, 2);
        assert!(p.pilot_half_width.abs() < 1e-18);
    }

    #[test]
    fn pilot_rejects_bad_input() {
        assert_eq!(
            pilot_variance(&[1.0], 0.02, 0.95),
            Err(StatsError::TooFew { needed: 2, got: 1 })
        );
        assert!(matches!(
            pilot_variance(&[1.0, 2.0], 0.0, 0.95),
            Err(StatsError::Domain {
                what: "half_width",
                ..
            })
        ));
        assert!(matches!(
            pilot_variance(&[1.0, f64::INFINITY], 0.02, 0.95),
            Err(StatsError::NotFinite { index: 1 })
        ));
    }

    #[test]
    fn paired_comparison_reports_the_verdict() {
        let seeds = [1u64, 2, 3, 4, 5, 6];
        let b = [0.60, 0.62, 0.58, 0.61, 0.59, 0.63];
        let c = [0.70, 0.71, 0.69, 0.72, 0.70, 0.73];
        let cmp = PairedComparison::compute(
            "coverage.trusted",
            &seeds,
            &b,
            &c,
            Direction::HigherIsBetter,
            2_000,
            0.95,
        )
        .unwrap();
        assert!(cmp.is_improvement());
        assert!(cmp.wilcoxon.as_ref().unwrap().p_two_sided <= 0.0313);
        assert!(cmp.render_markdown_row().contains("better"));

        let tied =
            PairedComparison::compute("t80", &seeds, &b, &b, Direction::LowerIsBetter, 100, 0.95).unwrap();
        assert!(tied.wilcoxon.is_none());
        assert!(!tied.is_improvement());
        assert!(tied.render_markdown_row().contains("tied"));
    }

    #[test]
    fn committed_seed_sets_validate_and_match_the_plan() {
        let sets = SeedSets::committed().unwrap();
        assert_eq!(sets.version, 1);
        assert_eq!(sets.seeds("pr").unwrap().len(), 1);
        assert_eq!(sets.seeds("nightly").unwrap().len(), 8);
        assert_eq!(sets.seeds("release").unwrap().len(), 21);
        assert_eq!(sets.seeds("pilot").unwrap().len(), 30);
        // Nested: every nightly seed is a release seed, every PR seed a nightly seed (paired runs
        // across suites stay comparable).
        let release = sets.seeds("release").unwrap();
        let nightly = sets.seeds("nightly").unwrap();
        assert!(nightly.iter().all(|s| release.contains(s)));
        assert!(sets.seeds("pr").unwrap().iter().all(|s| nightly.contains(s)));
    }

    #[test]
    fn seed_sets_reject_duplicates_and_missing_suites() {
        let dup = "version = 1\n[suite.pr]\nrationale = \"x\"\nseeds = [1, 1]\n[suite.nightly]\nrationale = \"x\"\nseeds = [1]\n[suite.release]\nrationale = \"x\"\nseeds = [1]\n[suite.pilot]\nrationale = \"x\"\nseeds = [1]\n";
        assert!(matches!(SeedSets::parse(dup), Err(StatsError::Seeds(m)) if m.contains("repeats")));
        let missing = "version = 1\n[suite.pr]\nrationale = \"x\"\nseeds = [1]\n";
        assert!(matches!(SeedSets::parse(missing), Err(StatsError::Seeds(m)) if m.contains("missing")));
        let unknown = "version = 1\nextra = 1\n";
        assert!(matches!(SeedSets::parse(unknown), Err(StatsError::Seeds(_))));
    }
}
