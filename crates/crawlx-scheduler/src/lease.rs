//! `Scheduler`: session leasing over a `LeaseRepo`.

use crate::error::SchedulerError;
use crawlx_core::repo::SessionStatus;
use crawlx_core::{CrawlRunId, SessionId, StoreError, Timestamp, WorkerId};
use crawlx_storage::{LeaseRepo, SessionLease};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Holder heartbeat period (10 s against a 30 s TTL).
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

/// Grants session leases. The round-robin barrier is enforced by the repository
/// in the claim statement itself, so the grant order is independent of how many
/// schedulers or workers race.
#[derive(Clone)]
pub struct Scheduler {
    leases: Arc<dyn LeaseRepo>,
    cursor: Arc<AtomicUsize>,
    /// Monotonic grant instant per leased session, for `crawlx.scheduler.lease.duration`.
    /// Inserted on grant, removed on `release`; a lease that is fenced instead of released
    /// is dropped from the map on the first failing holder call. The scheduler never reads
    /// wall time, so the hold time is measured with `Instant` rather than the repository clock.
    granted: Arc<Mutex<BTreeMap<SessionId, Instant>>>,
}

/// Time `fut` into `crawlx.scheduler.op.duration{op}`.
async fn timed<T>(op: &'static str, fut: impl Future<Output = T>) -> T {
    let start = Instant::now();
    let out = fut.await;
    Metrics::global()
        .histogram(names::SCHEDULER_OP_DURATION)
        .observe_duration(start.elapsed(), &[("op", op)]);
    out
}

/// Count a holder call refused because the lease was fenced.
fn count_fenced<T>(result: &Result<T, SchedulerError>) {
    if result.as_ref().is_err_and(SchedulerError::is_lease_lost) {
        Metrics::global().counter(names::LEASE_FENCED).inc();
    }
}

impl Scheduler {
    /// A scheduler over `leases` with its round-robin cursor at the first active run.
    #[must_use]
    pub fn new(leases: Arc<dyn LeaseRepo>) -> Self {
        Self {
            leases,
            cursor: Arc::new(AtomicUsize::new(0)),
            granted: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Remember when `lease` was granted so `release` can observe the hold time.
    fn note_granted(&self, lease: &SessionLease) {
        self.granted.lock().insert(lease.session.id, Instant::now());
    }

    /// Forget the grant instant of `lease` and observe its hold time, if it was granted here.
    fn note_released(&self, lease: &SessionLease) {
        let granted = self.granted.lock().remove(&lease.session.id);
        if let Some(at) = granted {
            Metrics::global()
                .histogram(names::SCHEDULER_LEASE_DURATION)
                .observe_duration(at.elapsed(), &[]);
        }
    }

    /// Lease the next eligible session across all active runs. Runs are tried round-robin
    /// from a rotating cursor so a busy run cannot starve the others.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::Store`] if listing active runs or claiming a session fails.
    pub async fn lease_next(&self, worker: WorkerId) -> Result<Option<SessionLease>, SchedulerError> {
        let lease = timed("lease_next", self.lease_next_inner(worker)).await?;
        if let Some(lease) = &lease {
            self.note_granted(lease);
        }
        Ok(lease)
    }

    async fn lease_next_inner(&self, worker: WorkerId) -> Result<Option<SessionLease>, SchedulerError> {
        // `scheduler.admission`: `drain` and `frozen` grant nothing (RB-04, RB-11)
        if !self.leases.admission().await?.grants_leases() {
            return Ok(None);
        }
        let runs = self.leases.active_runs().await?;
        if runs.is_empty() {
            return Ok(None);
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % runs.len();
        for offset in 0..runs.len() {
            let run = runs[(start + offset) % runs.len()];
            if let Some(lease) = self
                .leases
                .claim_session(run.run, worker, run.parallel_roles_allowed)
                .await?
            {
                return Ok(Some(lease));
            }
        }
        Ok(None)
    }

    /// Lease the next eligible session of one run.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::Store`] if the repository fails to claim a session.
    pub async fn lease_in_run(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, SchedulerError> {
        let lease = timed(
            "lease_in_run",
            self.leases.claim_session(run, worker, parallel_roles_allowed),
        )
        .await?;
        if let Some(lease) = &lease {
            self.note_granted(lease);
        }
        Ok(lease)
    }

    /// Extend the lease and return the new expiry as seen by the repository clock;
    /// `SchedulerError::is_lease_lost` means the holder must stop writing.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::Store`] if the repository fails or the lease was fenced.
    pub async fn heartbeat(&self, lease: &SessionLease) -> Result<Timestamp, SchedulerError> {
        let result = timed("heartbeat", self.leases.heartbeat(lease))
            .await
            .map_err(SchedulerError::from);
        count_fenced(&result);
        if result.as_ref().is_err_and(SchedulerError::is_lease_lost) {
            self.granted.lock().remove(&lease.session.id);
        }
        result
    }

    /// End the lease in `to` (`Completed | Failed | Cancelled`, or `Recovering` for a graceful hand-over).
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::Store`] if the repository fails; `StoreError::LeaseLost`
    /// means the lease was already fenced.
    pub async fn release(&self, lease: &SessionLease, to: SessionStatus) -> Result<(), SchedulerError> {
        let result = timed("release", self.leases.release(lease, to))
            .await
            .map_err(SchedulerError::from);
        count_fenced(&result);
        match &result {
            Ok(()) => self.note_released(lease),
            Err(_) => {
                self.granted.lock().remove(&lease.session.id);
            }
        }
        result
    }

    /// The session finished its run: `completed`, which opens the next turn of the barrier.
    ///
    /// # Errors
    ///
    /// Same as [`Self::release`].
    pub async fn complete(&self, lease: &SessionLease) -> Result<(), SchedulerError> {
        self.release(lease, SessionStatus::Completed).await
    }

    /// The session ended unsuccessfully: `failed`. Failed is terminal, so later turns proceed.
    ///
    /// # Errors
    ///
    /// Same as [`Self::release`].
    pub async fn fail(&self, lease: &SessionLease) -> Result<(), SchedulerError> {
        self.release(lease, SessionStatus::Failed).await
    }

    /// Keep `lease` alive every `interval` until `cancel` fires. Returns `Ok(())` on cancellation
    /// and the error (`LeaseLost` when fenced) if a heartbeat fails, after which the owner
    /// must stop acting on the session.
    ///
    /// Dropping the returned handle detaches the task; cancel `cancel` to stop it.
    #[must_use]
    pub fn keep_alive(
        &self,
        lease: SessionLease,
        interval: Duration,
        cancel: CancellationToken,
    ) -> JoinHandle<Result<(), SchedulerError>> {
        let leases = self.leases.clone();
        let granted = self.granted.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // first tick is immediate
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return Ok(()),
                    _ = ticker.tick() => {
                        if let Err(e) = timed("heartbeat", leases.heartbeat(&lease)).await {
                            if matches!(e, StoreError::LeaseLost) {
                                Metrics::global().counter(names::LEASE_FENCED).inc();
                                granted.lock().remove(&lease.session.id);
                            } else {
                                tracing::warn!(
                                    session = %lease.session.id,
                                    retryable = e.is_retryable(),
                                    "session heartbeat failed"
                                );
                            }
                            return Err(SchedulerError::Store(e));
                        }
                    }
                }
            }
        })
    }
}
