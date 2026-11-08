//! Bounded retry with exponential backoff for `429`/`503`, honoring
//! `Retry-After` (delta-seconds or HTTP-date). Jitter comes from a seeded RNG
//! passed in by the caller.

use chrono::{DateTime, Utc};
use http::{header, HeaderMap};
use rand::{Rng, RngExt as _};
use std::time::Duration;

/// Retry budget and backoff curve.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    /// Retries after the first attempt (`0` disables retrying).
    pub max_retries: u32,
    /// Backoff before retry `n` is `base_backoff * 2^n` (before jitter).
    pub base_backoff: Duration,
    /// Upper bound for the computed backoff.
    pub max_backoff: Duration,
    /// A `Retry-After` above this is not waited out: the response is returned as is.
    pub max_retry_after: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            max_retry_after: Duration::from_secs(60),
        }
    }
}

/// Statuses that signal "come back later".
#[must_use]
pub const fn is_retryable_status(status: u16) -> bool {
    matches!(status, 429 | 503)
}

impl RetryPolicy {
    /// Delay before retry number `attempt` (0-based), or `None` when the
    /// server asked for longer than `max_retry_after` and retrying is pointless.
    ///
    /// `delay = max(jittered_backoff, retry_after)`, jitter ±20%.
    pub fn delay<R: Rng>(
        &self,
        attempt: u32,
        retry_after: Option<Duration>,
        rng: &mut R,
    ) -> Option<Duration> {
        if let Some(ra) = retry_after {
            if ra > self.max_retry_after {
                return None;
            }
        }
        let factor = 2u32.saturating_pow(attempt.min(20));
        let backoff = self.base_backoff.saturating_mul(factor).min(self.max_backoff);
        let jitter: f64 = rng.random_range(0.8..1.2);
        let jittered = backoff.mul_f64(jitter).min(self.max_backoff);
        Some(retry_after.map_or(jittered, |ra| ra.max(jittered)))
    }
}

/// Parse `Retry-After`: non-negative delta-seconds or an HTTP-date relative to `now`.
#[must_use]
pub fn parse_retry_after(headers: &HeaderMap, now: DateTime<Utc>) -> Option<Duration> {
    let raw = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs));
    }
    let when = DateTime::parse_from_rfc2822(raw).ok()?.with_timezone(&Utc);
    Some((when - now).to_std().unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::seed::CrawlSeed;
    use http::HeaderValue;

    fn hm(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::RETRY_AFTER, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn parses_delta_seconds_and_http_date() {
        let now = DateTime::parse_from_rfc3339("1994-11-06T08:49:07Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parse_retry_after(&hm("120"), now), Some(Duration::from_secs(120)));
        assert_eq!(
            parse_retry_after(&hm("Sun, 06 Nov 1994 08:49:37 GMT"), now),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            parse_retry_after(&hm("Sun, 06 Nov 1994 08:00:00 GMT"), now),
            Some(Duration::ZERO)
        );
        assert_eq!(parse_retry_after(&hm("soon"), now), None);
        assert_eq!(parse_retry_after(&HeaderMap::new(), now), None);
    }

    #[test]
    fn backoff_grows_and_honors_retry_after() {
        let p = RetryPolicy::default();
        let mut rng = CrawlSeed(1).rng("t", &[]);
        let d0 = p.delay(0, None, &mut rng).unwrap();
        let d3 = p.delay(3, None, &mut rng).unwrap();
        assert!(
            d0 >= Duration::from_millis(400) && d0 <= Duration::from_millis(600),
            "{d0:?}"
        );
        assert!(
            d3 >= Duration::from_millis(3200) && d3 <= Duration::from_millis(4800),
            "{d3:?}"
        );
        let d = p.delay(0, Some(Duration::from_secs(7)), &mut rng).unwrap();
        assert_eq!(d, Duration::from_secs(7));
        assert_eq!(p.delay(0, Some(Duration::from_secs(61)), &mut rng), None);
    }

    #[test]
    fn backoff_is_capped_and_deterministic() {
        let p = RetryPolicy {
            max_backoff: Duration::from_secs(2),
            ..RetryPolicy::default()
        };
        let a = p.delay(30, None, &mut CrawlSeed(5).rng("t", &[])).unwrap();
        let b = p.delay(30, None, &mut CrawlSeed(5).rng("t", &[])).unwrap();
        assert_eq!(a, b);
        assert!(a <= Duration::from_secs(2));
    }
}
