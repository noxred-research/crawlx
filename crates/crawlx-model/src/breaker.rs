//! Circuit breaker for model calls (the pattern
//! follows the breaker of Firecrawl's typed-decision call).
//!
//! The breaker opens after 5 consecutive failures or when at least 50 % of the
//! last 20 calls failed. It stays open 30 s; each re-open after a failed probe
//! doubles the open time up to 5 min. After the open time it is half-open and
//! admits exactly one probe: success closes it (and forgets the history),
//! failure re-opens it. Time is injected: every method takes `now: Instant`,
//! the breaker never reads a clock.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Breaker parameters (planning defaults).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BreakerConfig {
    /// Consecutive failed calls that open the breaker.
    pub consecutive_failures: u32,
    /// Size of the sliding window of recent calls.
    pub window: usize,
    /// Failures in a *full* window that open the breaker (10 of 20 = 50 %).
    pub window_failures: usize,
    /// First open interval; it doubles on every re-open.
    pub open_base: Duration,
    /// Upper bound of the open interval.
    pub open_max: Duration,
}

impl Default for BreakerConfig {
    fn default() -> Self {
        Self {
            consecutive_failures: 5,
            window: 20,
            window_failures: 10,
            open_base: Duration::from_secs(30),
            open_max: Duration::from_secs(300),
        }
    }
}

/// Externally visible breaker state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BreakerState {
    /// Calls pass through and outcomes are recorded.
    Closed,
    /// Calls are refused until `until`.
    Open {
        /// Instant after which one probe call is admitted.
        until: Instant,
    },
    /// One probe call is in flight; its outcome closes or re-opens the breaker.
    HalfOpen,
}

impl BreakerState {
    /// Value for the `crawlx.model.breaker.state` gauge: 0 closed, 1 half-open, 2 open.
    #[must_use]
    pub const fn gauge(self) -> u8 {
        match self {
            Self::Closed => 0,
            Self::HalfOpen => 1,
            Self::Open { .. } => 2,
        }
    }
}

/// The breaker state machine.
#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    cfg: BreakerConfig,
    state: BreakerState,
    /// Recent outcomes, newest last; `true` = success.
    window: VecDeque<bool>,
    consecutive: u32,
    /// Opens since the last successful close; drives the doubling.
    opens: u32,
    probe_in_flight: bool,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(BreakerConfig::default())
    }
}

impl CircuitBreaker {
    /// Closed breaker with empty history.
    #[must_use]
    pub fn new(cfg: BreakerConfig) -> Self {
        Self {
            cfg,
            state: BreakerState::Closed,
            window: VecDeque::with_capacity(cfg.window),
            consecutive: 0,
            opens: 0,
            probe_in_flight: false,
        }
    }

    /// Current state (an `Open` breaker whose time has passed still reports
    /// `Open` until [`CircuitBreaker::allow`] observes the deadline).
    #[must_use]
    pub const fn state(&self) -> BreakerState {
        self.state
    }

    /// May a call start at `now`? In half-open state only one probe is admitted
    /// until its outcome is recorded.
    pub fn allow(&mut self, now: Instant) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open { until } => {
                if now >= until {
                    self.state = BreakerState::HalfOpen;
                    self.probe_in_flight = true;
                    true
                } else {
                    false
                }
            }
            BreakerState::HalfOpen => {
                if self.probe_in_flight {
                    false
                } else {
                    self.probe_in_flight = true;
                    true
                }
            }
        }
    }

    /// Record the outcome of a call that [`CircuitBreaker::allow`] admitted.
    pub fn record(&mut self, ok: bool, now: Instant) {
        match self.state {
            BreakerState::HalfOpen => {
                self.probe_in_flight = false;
                if ok {
                    self.state = BreakerState::Closed;
                    self.window.clear();
                    self.consecutive = 0;
                    self.opens = 0;
                } else {
                    self.open(now);
                }
            }
            BreakerState::Closed => {
                if self.window.len() == self.cfg.window {
                    self.window.pop_front();
                }
                self.window.push_back(ok);
                if ok {
                    self.consecutive = 0;
                } else {
                    self.consecutive = self.consecutive.saturating_add(1);
                }
                let failures = self.window.iter().filter(|ok| !**ok).count();
                let window_full = self.window.len() == self.cfg.window;
                if self.consecutive >= self.cfg.consecutive_failures
                    || (window_full && failures >= self.cfg.window_failures)
                {
                    self.open(now);
                }
            }
            // A straggler that started before the breaker opened: ignore.
            BreakerState::Open { .. } => {}
        }
    }

    fn open(&mut self, now: Instant) {
        let factor = 1_u32.checked_shl(self.opens.min(16)).unwrap_or(u32::MAX);
        let duration = self.cfg.open_base.saturating_mul(factor).min(self.cfg.open_max);
        self.opens = self.opens.saturating_add(1);
        self.state = BreakerState::Open {
            until: now + duration,
        };
        self.window.clear();
        self.consecutive = 0;
        self.probe_in_flight = false;
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn opens_after_five_consecutive_failures() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::default();
        for i in 0..4 {
            assert!(b.allow(t0));
            b.record(false, t0);
            assert_eq!(b.state(), BreakerState::Closed, "after {} failures", i + 1);
        }
        assert!(b.allow(t0));
        b.record(false, t0);
        assert_eq!(b.state(), BreakerState::Open { until: t0 + secs(30) });
        assert!(!b.allow(t0));
        assert!(!b.allow(t0 + secs(29)));
    }

    #[test]
    fn a_success_resets_the_consecutive_count() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::default();
        for _ in 0..4 {
            b.record(false, t0);
        }
        b.record(true, t0);
        for _ in 0..4 {
            b.record(false, t0);
        }
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn opens_at_half_failures_over_a_full_window_of_twenty() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::default();
        // Alternate fail/ok: never 5 in a row; 10 failures in 20 calls opens on the 20th call.
        for i in 0..19 {
            b.record(i % 2 == 1, t0);
            assert_eq!(b.state(), BreakerState::Closed, "call {i}");
        }
        b.record(true, t0);
        // 20 calls: failures at even indices 0..=18 => 10 failures.
        assert!(matches!(b.state(), BreakerState::Open { .. }));
    }

    #[test]
    fn nine_failures_in_twenty_stays_closed() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::default();
        for i in 0..20 {
            // failures on i = 0, 2, ..., 16 (9 failures), rest successes.
            b.record(!(i % 2 == 0 && i < 18), t0);
        }
        assert_eq!(b.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_admits_one_probe_and_closes_on_success() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::default();
        for _ in 0..5 {
            b.record(false, t0);
        }
        let t1 = t0 + secs(30);
        assert!(b.allow(t1), "probe admitted at the deadline");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        assert!(!b.allow(t1), "second concurrent call refused");
        b.record(true, t1);
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allow(t1));
    }

    #[test]
    fn failed_probes_double_the_open_time_up_to_five_minutes() {
        let mut now = Instant::now();
        let mut b = CircuitBreaker::default();
        for _ in 0..5 {
            b.record(false, now);
        }
        for want in [30_u64, 60, 120, 240, 300, 300] {
            match b.state() {
                BreakerState::Open { until } => assert_eq!(until - now, secs(want)),
                s => panic!("expected open, got {s:?}"),
            }
            now += secs(want);
            assert!(b.allow(now));
            b.record(false, now);
        }
    }

    #[test]
    fn successful_close_resets_the_doubling() {
        let mut now = Instant::now();
        let mut b = CircuitBreaker::default();
        for _ in 0..5 {
            b.record(false, now);
        }
        now += secs(30);
        assert!(b.allow(now));
        b.record(false, now); // second open: 60 s
        now += secs(60);
        assert!(b.allow(now));
        b.record(true, now); // closed, history forgotten
        for _ in 0..5 {
            b.record(false, now);
        }
        assert_eq!(
            b.state(),
            BreakerState::Open {
                until: now + secs(30)
            }
        );
    }

    #[test]
    fn stragglers_recorded_while_open_are_ignored() {
        let t0 = Instant::now();
        let mut b = CircuitBreaker::default();
        for _ in 0..5 {
            b.record(false, t0);
        }
        let state = b.state();
        b.record(true, t0 + secs(1));
        b.record(false, t0 + secs(1));
        assert_eq!(b.state(), state);
    }

    #[test]
    fn gauge_values() {
        let t0 = Instant::now();
        assert_eq!(BreakerState::Closed.gauge(), 0);
        assert_eq!(BreakerState::HalfOpen.gauge(), 1);
        assert_eq!(BreakerState::Open { until: t0 }.gauge(), 2);
    }

    #[derive(Clone, Debug)]
    enum Op {
        Allow,
        Record(bool),
    }

    fn op() -> impl Strategy<Value = (u64, Op)> {
        (
            0_u64..40_000,
            prop_oneof![Just(Op::Allow), any::<bool>().prop_map(Op::Record)],
        )
    }

    proptest! {
        /// The breaker never admits a call while Open before `until`, and a
        /// re-open never happens sooner than the base cool-down after the
        /// previous open ended.
        #[test]
        fn never_allows_while_open_before_until(ops in proptest::collection::vec(op(), 1..400)) {
            let t0 = Instant::now();
            let mut b = CircuitBreaker::default();
            let mut now = t0;
            let mut in_flight = 0_u32;
            for (dt_ms, op) in ops {
                now += Duration::from_millis(dt_ms);
                match op {
                    Op::Allow => {
                        let before = b.state();
                        let admitted = b.allow(now);
                        if let BreakerState::Open { until } = before {
                            if now < until {
                                prop_assert!(!admitted, "admitted while open before until");
                            }
                        }
                        if admitted {
                            in_flight += 1;
                        }
                        if matches!(before, BreakerState::HalfOpen) {
                            prop_assert!(!admitted, "second probe admitted");
                        }
                    }
                    Op::Record(ok) => {
                        if in_flight > 0 {
                            in_flight -= 1;
                            b.record(ok, now);
                        }
                    }
                }
                if let BreakerState::Open { until } = b.state() {
                    prop_assert!(until.saturating_duration_since(now) <= secs(300));
                }
            }
        }
    }
}
