//! Bounded exponential backoff (URL rows retry up to 5 attempts;
//! the outcome transaction T2 retries 3 times).

use crawlx_core::seed::CrawlSeed;
use crawlx_core::StoreError;
use rand::RngExt as _;
use std::future::Future;
use std::time::Duration;

/// What to do after a failed attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RetryDecision {
    /// Try again after waiting `after`.
    Retry {
        /// How long to wait before the next attempt.
        after: Duration,
    },
    /// Stop retrying and surface the error.
    GiveUp,
}

/// `delay(n) = min(base * factor^(n-1), max_delay)` with optional seeded jitter.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RetryPolicy {
    /// Total attempts including the first.
    pub max_attempts: u32,
    /// Delay before the second attempt.
    pub base: Duration,
    /// Multiplier applied to the delay after every failed attempt (values below 1 act as 1).
    pub factor: u32,
    /// Upper bound of every delay, jitter included.
    pub max_delay: Duration,
    /// Jitter as a share of the delay in ‰ (250 = ±25 %). Deterministic: derived from `CrawlSeed`.
    pub jitter_permille: u16,
}

impl Default for RetryPolicy {
    /// URL fetch retries: 5 attempts, 1 s doubling up to 5 min, ±25 % jitter.
    fn default() -> Self {
        Self {
            max_attempts: 5,
            base: Duration::from_secs(1),
            factor: 2,
            max_delay: Duration::from_secs(300),
            jitter_permille: 250,
        }
    }
}

impl RetryPolicy {
    /// Journal T2 retries: 3 attempts, short, no jitter.
    #[must_use]
    pub const fn journal() -> Self {
        Self {
            max_attempts: 3,
            base: Duration::from_millis(100),
            factor: 2,
            max_delay: Duration::from_secs(2),
            jitter_permille: 0,
        }
    }

    /// Backoff before attempt `attempt + 1`, where `attempt` (>= 1) attempts have already failed. No jitter.
    #[must_use]
    pub fn backoff(&self, attempt: u32) -> Duration {
        let exp = attempt.saturating_sub(1);
        let mut d = self.base;
        for _ in 0..exp {
            d = d.saturating_mul(self.factor.max(1));
            if d >= self.max_delay {
                return self.max_delay;
            }
        }
        d.min(self.max_delay)
    }

    /// [`Self::backoff`] with jitter derived from `(seed, key, attempt)`; never exceeds `max_delay`.
    #[must_use]
    pub fn delay(&self, attempt: u32, seed: &CrawlSeed, key: &[u8]) -> Duration {
        let base = self.backoff(attempt);
        if self.jitter_permille == 0 {
            return base;
        }
        let mut rng = seed.rng("retry-jitter", &[key, &attempt.to_le_bytes()]);
        let span = u64::from(self.jitter_permille);
        let permille = 1000 - span + rng.random_range(0..=2 * span);
        let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(millis.saturating_mul(permille) / 1000).min(self.max_delay)
    }

    /// Decide after `attempts_made` failed attempts (>= 1).
    #[must_use]
    pub fn decide(&self, attempts_made: u32, retryable: bool) -> RetryDecision {
        if !retryable || attempts_made >= self.max_attempts {
            RetryDecision::GiveUp
        } else {
            RetryDecision::Retry {
                after: self.backoff(attempts_made),
            }
        }
    }

    /// Run `op` (given the 1-based attempt number), retrying retryable `StoreError`s with backoff.
    /// Non-retryable errors and the last error are returned unchanged.
    ///
    /// # Errors
    ///
    /// Returns the first non-retryable [`StoreError`], or the last error once `max_attempts`
    /// attempts have failed.
    pub async fn run<T, F, Fut>(&self, mut op: F) -> Result<T, StoreError>
    where
        F: FnMut(u32) -> Fut,
        Fut: Future<Output = Result<T, StoreError>>,
    {
        let mut attempt = 1;
        loop {
            match op(attempt).await {
                Ok(v) => return Ok(v),
                Err(e) => match self.decide(attempt, e.is_retryable()) {
                    RetryDecision::GiveUp => return Err(e),
                    RetryDecision::Retry { after } => {
                        tracing::debug!(attempt, ?after, retryable = true, "retrying storage operation");
                        tokio::time::sleep(after).await;
                        attempt += 1;
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn backoff_doubles_and_caps() {
        let p = RetryPolicy::default();
        let secs: Vec<u64> = (1..=10).map(|n| p.backoff(n).as_secs()).collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 16, 32, 64, 128, 256, 300]);
    }

    #[test]
    fn decide_is_bounded() {
        let p = RetryPolicy::default();
        assert_eq!(
            p.decide(1, true),
            RetryDecision::Retry {
                after: Duration::from_secs(1)
            }
        );
        assert_eq!(p.decide(5, true), RetryDecision::GiveUp);
        assert_eq!(p.decide(1, false), RetryDecision::GiveUp);
    }

    #[test]
    fn jitter_is_deterministic_per_seed_and_key() {
        let p = RetryPolicy::default();
        let a = p.delay(3, &CrawlSeed(7), b"https://example.test/a");
        assert_eq!(a, p.delay(3, &CrawlSeed(7), b"https://example.test/a"));
        assert_ne!(
            a,
            p.delay(3, &CrawlSeed(8), b"https://example.test/a"),
            "different seeds differ (for this input)"
        );
    }

    proptest! {
        #[test]
        fn delay_stays_within_jitter_band_and_cap(attempt in 1u32..40, seed in any::<u64>(), key in proptest::collection::vec(any::<u8>(), 0..16)) {
            let p = RetryPolicy::default();
            let d = p.delay(attempt, &CrawlSeed(seed), &key);
            let base = p.backoff(attempt);
            prop_assert!(d <= p.max_delay);
            prop_assert!(d >= base.mul_f64(0.75).min(p.max_delay) - Duration::from_millis(1));
            prop_assert!(d <= base.mul_f64(1.25) + Duration::from_millis(1));
        }
    }

    #[tokio::test]
    async fn run_retries_only_retryable_errors() {
        let p = RetryPolicy {
            max_attempts: 3,
            base: Duration::ZERO,
            factor: 2,
            max_delay: Duration::ZERO,
            jitter_permille: 0,
        };
        let calls = AtomicU32::new(0);
        let v = p
            .run(|n| {
                calls.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 3 {
                        Err(StoreError::Unavailable("down".to_owned()))
                    } else {
                        Ok(n)
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!((v, calls.load(Ordering::SeqCst)), (3, 3));

        calls.store(0, Ordering::SeqCst);
        let e = p
            .run(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(StoreError::LeaseLost) }
            })
            .await
            .unwrap_err();
        assert!(matches!(e, StoreError::LeaseLost));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "non-retryable errors are not retried"
        );

        calls.store(0, Ordering::SeqCst);
        let e = p
            .run(|_| {
                calls.fetch_add(1, Ordering::SeqCst);
                async { Err::<(), _>(StoreError::Backend("x".to_owned())) }
            })
            .await
            .unwrap_err();
        assert!(matches!(e, StoreError::Backend(_)));
        assert_eq!(calls.load(Ordering::SeqCst), 3, "bounded by max_attempts");
    }
}
