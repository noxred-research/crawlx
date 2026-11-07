//! Per-engine call guard: circuit breaker, concurrency cap and time budget.
//!
//! Every remote or local model call goes through [`CallGuard::run`]: the
//! breaker is consulted first (open breaker → [`ModelError::BreakerOpen`] with
//! no call made), the call waits for one of `max_concurrent` permits inside
//! its time budget, and the outcome is recorded once. Failures are recorded,
//! never retried.

use crate::breaker::{BreakerConfig, BreakerState, CircuitBreaker};
use crate::error::ModelError;
use parking_lot::Mutex;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Per-call time budget for a remote endpoint (planning default).
pub const REMOTE_TIMEOUT: Duration = Duration::from_millis(1500);
/// Per-call time budget for local ONNX inference (planning default).
pub const LOCAL_TIMEOUT: Duration = Duration::from_millis(300);

/// Guard parameters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GuardConfig {
    /// Per-call time budget; see [`REMOTE_TIMEOUT`] and [`LOCAL_TIMEOUT`].
    pub timeout: Duration,
    /// Concurrent judgments per engine.
    pub max_concurrent: usize,
    /// Circuit-breaker parameters shared by all calls of the engine.
    pub breaker: BreakerConfig,
}

impl GuardConfig {
    /// Defaults for a remote endpoint.
    #[must_use]
    pub fn remote() -> Self {
        Self {
            timeout: REMOTE_TIMEOUT,
            max_concurrent: 4,
            breaker: BreakerConfig::default(),
        }
    }

    /// Defaults for a local ONNX session.
    #[must_use]
    pub fn local() -> Self {
        Self {
            timeout: LOCAL_TIMEOUT,
            max_concurrent: 2,
            breaker: BreakerConfig::default(),
        }
    }
}

/// Breaker + semaphore + timeout around one engine.
#[derive(Debug)]
pub struct CallGuard {
    breaker: Mutex<CircuitBreaker>,
    permits: Arc<Semaphore>,
    timeout: Duration,
}

impl CallGuard {
    /// Guard with a closed breaker and `cfg.max_concurrent` permits.
    #[must_use]
    pub fn new(cfg: GuardConfig) -> Self {
        Self {
            breaker: Mutex::new(CircuitBreaker::new(cfg.breaker)),
            permits: Arc::new(Semaphore::new(cfg.max_concurrent.max(1))),
            timeout: cfg.timeout,
        }
    }

    /// Current breaker state, e.g. for the `crawlx.model.breaker.state` gauge.
    #[must_use]
    pub fn breaker_state(&self) -> BreakerState {
        self.breaker.lock().state()
    }

    /// Is the breaker refusing calls right now? Use to force rollout mode `off`.
    #[must_use]
    pub fn is_open(&self, now: Instant) -> bool {
        match self.breaker.lock().state() {
            BreakerState::Open { until } => now < until,
            BreakerState::Closed | BreakerState::HalfOpen => false,
        }
    }

    /// Run one async call. The concurrency permit is held until the future completes.
    ///
    /// # Errors
    /// [`ModelError::BreakerOpen`] without calling `make`; [`ModelError::Timeout`]
    /// when the budget (including waiting for a permit) elapses; otherwise the
    /// call's own error. Every `Err` counts as a breaker failure.
    pub async fn run<T, Fut>(&self, make: impl FnOnce() -> Fut) -> Result<T, ModelError>
    where
        Fut: Future<Output = Result<T, ModelError>>,
    {
        self.run_with_permit(|permit| async move {
            let _permit = permit;
            make().await
        })
        .await
    }

    /// Run blocking work (ONNX inference) on tokio's blocking pool. The permit
    /// moves into the blocking task, so a call that timed out keeps its slot
    /// until the thread really finishes.
    ///
    /// # Errors
    /// As [`CallGuard::run`], plus [`ModelError::Transport`] if the task panics.
    pub async fn run_blocking<T>(
        &self,
        work: impl FnOnce() -> Result<T, ModelError> + Send + 'static,
    ) -> Result<T, ModelError>
    where
        T: Send + 'static,
    {
        self.run_with_permit(|permit| async move {
            let joined = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                work()
            })
            .await;
            joined.map_err(|e| ModelError::Transport(format!("inference task failed: {e}")))?
        })
        .await
    }

    async fn run_with_permit<T, Fut>(
        &self,
        make: impl FnOnce(OwnedSemaphorePermit) -> Fut,
    ) -> Result<T, ModelError>
    where
        Fut: Future<Output = Result<T, ModelError>>,
    {
        let admitted = {
            let mut breaker = self.breaker.lock();
            breaker.allow(Instant::now())
        };
        if !admitted {
            return Err(ModelError::BreakerOpen);
        }
        let permits = Arc::clone(&self.permits);
        let budget = self.timeout;
        let outcome = tokio::time::timeout(budget, async move {
            let permit = permits
                .acquire_owned()
                .await
                .map_err(|_| ModelError::Transport("concurrency limiter closed".to_owned()))?;
            make(permit).await
        })
        .await;
        let result = outcome.unwrap_or_else(|_| {
            Err(ModelError::Timeout {
                after_ms: u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
            })
        });
        {
            let mut breaker = self.breaker.lock();
            breaker.record(result.is_ok(), Instant::now());
        }
        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cfg(timeout_ms: u64, concurrent: usize) -> GuardConfig {
        GuardConfig {
            timeout: Duration::from_millis(timeout_ms),
            max_concurrent: concurrent,
            breaker: BreakerConfig::default(),
        }
    }

    #[tokio::test]
    async fn opens_after_five_failures_without_further_calls() {
        let g = CallGuard::new(cfg(500, 2));
        let calls = Arc::new(AtomicUsize::new(0));
        for _ in 0..5 {
            let c = Arc::clone(&calls);
            let r: Result<(), _> = g
                .run(move || async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Err(ModelError::Http { status: 500 })
                })
                .await;
            assert_eq!(r.unwrap_err(), ModelError::Http { status: 500 });
        }
        let c = Arc::clone(&calls);
        let r: Result<(), _> = g
            .run(move || async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await;
        assert_eq!(r.unwrap_err(), ModelError::BreakerOpen);
        assert_eq!(calls.load(Ordering::SeqCst), 5);
        assert!(g.is_open(Instant::now()));
        assert_eq!(g.breaker_state().gauge(), 2);
    }

    #[tokio::test]
    async fn slow_calls_time_out_and_count_as_failures() {
        let g = CallGuard::new(cfg(20, 1));
        let r: Result<(), _> = g
            .run(|| async {
                tokio::time::sleep(Duration::from_millis(500)).await;
                Ok(())
            })
            .await;
        assert_eq!(r.unwrap_err(), ModelError::Timeout { after_ms: 20 });
    }

    #[tokio::test]
    async fn concurrency_is_capped() {
        let g = Arc::new(CallGuard::new(cfg(2_000, 2)));
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..8 {
            let (g, active, peak) = (Arc::clone(&g), Arc::clone(&active), Arc::clone(&peak));
            tasks.push(tokio::spawn(async move {
                g.run(move || async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert!(peak.load(Ordering::SeqCst) >= 1);
    }
}
