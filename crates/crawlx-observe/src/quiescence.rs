//! Quiescence waiting. The backend implements the event-driven
//! settle loop (`BrowserContext::settle`); this waiter adds the optional domain
//! postcondition on top of it.

use crate::error::ObserveError;
use crate::spec;
use crawlx_core::browser::BrowserContext;
use crawlx_core::observation::{ObservationBundle, QuiescencePolicy, SettleReport};
use std::time::Duration;
use tokio::time::Instant;

/// Defaults: poll every 100 ms, at most 64 postcondition observations.
const DEFAULT_POLL_INTERVAL_MS: u64 = 100;
const DEFAULT_MAX_OBSERVATIONS: u32 = 64;

/// Waits for the page to settle, optionally until a postcondition holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct QuiescenceWaiter {
    /// Pause between postcondition observations.
    pub poll_interval_ms: u64,
    /// Upper bound on postcondition observations, whatever the clock says.
    pub max_observations: u32,
}

impl Default for QuiescenceWaiter {
    fn default() -> Self {
        Self {
            poll_interval_ms: DEFAULT_POLL_INTERVAL_MS,
            max_observations: DEFAULT_MAX_OBSERVATIONS,
        }
    }
}

impl QuiescenceWaiter {
    /// Waiter polling every `poll_interval_ms` for at most `max_observations`
    /// observations (raised to 1 when zero).
    #[must_use]
    pub fn new(poll_interval_ms: u64, max_observations: u32) -> Self {
        Self {
            poll_interval_ms,
            max_observations: max_observations.max(1),
        }
    }

    /// [`Self::wait`] without a postcondition: one backend settle. Unlike `wait`, whose
    /// `&dyn Fn` parameter is not `Sync`, this future is `Send`, so Session Actors can run it
    /// on any runtime thread.
    ///
    /// # Errors
    /// [`ObserveError::Browser`] when the backend's settle fails.
    pub async fn settle(
        &self,
        ctx: &mut dyn BrowserContext,
        policy: &QuiescencePolicy,
    ) -> Result<SettleReport, ObserveError> {
        Ok(ctx.settle(*policy).await?)
    }

    /// Run `ctx.settle(policy)`. With a `postcondition`, additionally observe
    /// (AX only) until it holds, bounded by `policy.hard_timeout_ms` measured
    /// from the call and by `max_observations`. The report then carries
    /// `postcondition: Some(holds)`; when the postcondition never held,
    /// `settle_timeout` is set and the crawl continues.
    ///
    /// # Errors
    /// [`ObserveError::Browser`] when the backend's settle or an AX observation fails.
    pub async fn wait(
        &self,
        ctx: &mut dyn BrowserContext,
        policy: &QuiescencePolicy,
        postcondition: Option<&dyn Fn(&ObservationBundle) -> bool>,
    ) -> Result<SettleReport, ObserveError> {
        let started = Instant::now();
        let mut report = ctx.settle(*policy).await?;
        let Some(check) = postcondition else {
            return Ok(report);
        };
        let budget = Duration::from_millis(policy.hard_timeout_ms);
        let mut observations = 0u32;
        loop {
            let bundle = ctx.observe(spec::cheap()).await?;
            observations += 1;
            if check(&bundle) {
                report.postcondition = Some(true);
                break;
            }
            let elapsed = started.elapsed();
            if elapsed >= budget || observations >= self.max_observations {
                report.postcondition = Some(false);
                report.settle_timeout = true;
                break;
            }
            let pause = Duration::from_millis(self.poll_interval_ms).min(budget - elapsed);
            tokio::time::sleep(pause).await;
        }
        report.waited_ms = report
            .waited_ms
            .max(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::ScriptedContext;
    use std::cell::Cell;

    fn policy(hard_timeout_ms: u64) -> QuiescencePolicy {
        QuiescencePolicy {
            hard_timeout_ms,
            ..QuiescencePolicy::default()
        }
    }

    #[tokio::test]
    async fn no_postcondition_is_plain_settle() {
        let mut ctx = ScriptedContext::new();
        let report = QuiescenceWaiter::default()
            .wait(&mut ctx, &policy(1_000), None)
            .await
            .unwrap();
        assert_eq!(ctx.settles, 1);
        assert_eq!(ctx.observes, 0);
        assert_eq!(report.postcondition, None);
        assert!(!report.settle_timeout);
    }

    #[tokio::test]
    async fn postcondition_becomes_true_after_n_observations() {
        let mut ctx = ScriptedContext::new();
        let seen = Cell::new(0u32);
        let check = |_: &ObservationBundle| {
            seen.set(seen.get() + 1);
            seen.get() >= 3
        };
        let report = QuiescenceWaiter::new(1, 50)
            .wait(&mut ctx, &policy(5_000), Some(&check))
            .await
            .unwrap();
        assert_eq!(report.postcondition, Some(true));
        assert!(!report.settle_timeout);
        assert_eq!(ctx.observes, 3);
        assert_eq!(ctx.settles, 1);
    }

    #[tokio::test]
    async fn unmet_postcondition_times_out_with_bounded_calls() {
        let mut ctx = ScriptedContext::new();
        let check = |_: &ObservationBundle| false;
        // observation bound
        let report = QuiescenceWaiter::new(0, 5)
            .wait(&mut ctx, &policy(60_000), Some(&check))
            .await
            .unwrap();
        assert_eq!(report.postcondition, Some(false));
        assert!(report.settle_timeout);
        assert_eq!(ctx.observes, 5);

        // clock bound
        let mut ctx = ScriptedContext::new();
        let report = QuiescenceWaiter::new(5, 1_000_000)
            .wait(&mut ctx, &policy(40), Some(&check))
            .await
            .unwrap();
        assert_eq!(report.postcondition, Some(false));
        assert!(report.settle_timeout);
        assert!(
            ctx.observes >= 2 && ctx.observes <= 41,
            "observes = {}",
            ctx.observes
        );
        assert!(report.waited_ms >= 40);
        assert_eq!(ctx.settles, 1);

        // a zero budget still evaluates the postcondition once
        let mut ctx = ScriptedContext::new();
        let report = QuiescenceWaiter::default()
            .wait(&mut ctx, &policy(0), Some(&check))
            .await
            .unwrap();
        assert_eq!(ctx.observes, 1);
        assert!(report.settle_timeout);
    }

    #[tokio::test]
    async fn backend_failure_propagates() {
        let mut ctx = ScriptedContext::new();
        ctx.fail_observe = true;
        let check = |_: &ObservationBundle| true;
        let err = QuiescenceWaiter::default()
            .wait(&mut ctx, &policy(100), Some(&check))
            .await
            .unwrap_err();
        assert!(err.is_target_crash());
    }
}
