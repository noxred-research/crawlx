//! The stale-lease reaper: every 15 s expired
//! session leases become `recovering` and their `intended` actions `unknown`;
//! expired URL leases return to `pending` (over 5 attempts → `failed`).

use crate::error::SchedulerError;
use crawlx_core::repo::ActionJournal;
use crawlx_core::{ActionId, SessionId, StoreError};
use crawlx_storage::LeaseRepo;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// Reaper period.
pub const DEFAULT_REAP_INTERVAL: Duration = Duration::from_secs(15);
/// URL rows over this many attempts fail instead of re-queueing.
pub const DEFAULT_MAX_URL_ATTEMPTS: u16 = 5;

/// Reaper settings. Lease TTLs (30 s sessions, 60 s URL batches) are properties of the
/// repository that grants the leases (`PgConfig::session_ttl`, `url_batch_ttl`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ReaperConfig {
    /// Period between sweeps.
    pub interval: Duration,
    /// URL rows over this many attempts fail instead of re-queueing.
    pub max_url_attempts: u16,
}

impl Default for ReaperConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_REAP_INTERVAL,
            max_url_attempts: DEFAULT_MAX_URL_ATTEMPTS,
        }
    }
}

/// What one pass changed.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct ReapSummary {
    /// Sessions whose expired lease moved them to `recovering`.
    pub sessions_recovering: Vec<SessionId>,
    /// Actions flipped `intended → unknown` (by the session sweep or the journal sweep).
    pub actions_unknown: Vec<ActionId>,
    /// URL rows whose expired lease returned them to `pending`.
    pub urls_requeued: u64,
    /// URL rows that exceeded the attempt limit and became `failed`.
    pub urls_failed: u64,
}

impl ReapSummary {
    /// Did the pass change nothing?
    fn is_empty(&self) -> bool {
        self.sessions_recovering.is_empty()
            && self.actions_unknown.is_empty()
            && self.urls_requeued == 0
            && self.urls_failed == 0
    }
}

/// Periodic stale-lease sweep.
pub struct Reaper {
    leases: Arc<dyn LeaseRepo>,
    journal: Arc<dyn ActionJournal>,
    cfg: ReaperConfig,
}

impl Reaper {
    /// A reaper sweeping `leases` and `journal` with settings `cfg`.
    #[must_use]
    pub fn new(leases: Arc<dyn LeaseRepo>, journal: Arc<dyn ActionJournal>, cfg: ReaperConfig) -> Self {
        Self { leases, journal, cfg }
    }

    /// One pass using the repository clock (database `now()` for PostgreSQL).
    ///
    /// The pass is a sequence of independent repository calls and is not interrupted by
    /// cancellation: [`Self::spawn`] lets a started pass finish before it observes `cancel`.
    ///
    /// Telemetry: the whole pass is timed into `crawlx.scheduler.op.duration{op="reap"}`;
    /// `crawlx.lease.expired` grows by the sessions moved to `recovering`;
    /// `crawlx.lease.reconcile.duration` is observed only for passes that reaped at least one
    /// session or action; `crawlx.lease.stale_unreconciled` is set to the number of actions
    /// this pass flipped `intended → unknown`, i.e. the stale work still awaiting reconciliation
    /// by the recovering holder (a pass that flips nothing resets it to 0).
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::Store`] if the clock read, the session sweep, the journal
    /// sweep or the frontier sweep fails; later steps of the pass are skipped.
    pub async fn run_once(&self) -> Result<ReapSummary, SchedulerError> {
        let start = Instant::now();
        let result = self.sweep().await;
        let elapsed = start.elapsed();
        let metrics = Metrics::global();
        metrics
            .histogram(names::SCHEDULER_OP_DURATION)
            .observe_duration(elapsed, &[("op", "reap")]);
        if let Ok(summary) = &result {
            let expired = u64::try_from(summary.sessions_recovering.len()).unwrap_or(u64::MAX);
            metrics.counter(names::LEASE_EXPIRED).inc_by(expired, &[]);
            if !summary.sessions_recovering.is_empty() || !summary.actions_unknown.is_empty() {
                metrics
                    .histogram(names::LEASE_RECONCILE_DURATION)
                    .observe_duration(elapsed, &[]);
            }
            // precision loss above 2^53 actions per tick is not a concern
            #[allow(clippy::cast_precision_loss)]
            let unreconciled = summary.actions_unknown.len() as f64;
            metrics
                .gauge(names::LEASE_STALE_UNRECONCILED)
                .set(unreconciled, &[]);
        }
        result
    }

    async fn sweep(&self) -> Result<ReapSummary, SchedulerError> {
        let now = self.leases.now().await?;
        let sessions = self.leases.reap(now).await?;
        // actions of sessions whose lease expired but which were not moved by `reap`
        // (e.g. already `recovering`) still must not stay `intended`
        let swept = self.journal.mark_unknown(now).await?;
        let urls = self.leases.reap_frontier(now, self.cfg.max_url_attempts).await?;
        let mut actions_unknown = sessions.actions_unknown;
        actions_unknown.extend(swept);
        Ok(ReapSummary {
            sessions_recovering: sessions.sessions_recovering,
            actions_unknown,
            urls_requeued: urls.requeued,
            urls_failed: urls.failed,
        })
    }

    /// Run [`Self::run_once`] every `cfg.interval` until `cancel` fires. Failures are logged and
    /// the next tick tries again; the sweep is idempotent.
    ///
    /// Cancellation is observed between passes: a pass that has started runs to completion
    /// so the session, journal and frontier sweeps are never split by a dropped future.
    #[must_use]
    pub fn spawn(self: Arc<Self>, cancel: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(self.cfg.interval);
            loop {
                tokio::select! {
                    biased;
                    () = cancel.cancelled() => return,
                    _ = ticker.tick() => match self.run_once().await {
                        Ok(s) if s.is_empty() => {}
                        Ok(s) => tracing::info!(
                            sessions = s.sessions_recovering.len(),
                            actions_unknown = s.actions_unknown.len(),
                            urls_requeued = s.urls_requeued,
                            urls_failed = s.urls_failed,
                            "reaped stale leases"
                        ),
                        Err(SchedulerError::Store(e)) => tracing::warn!(
                            retryable = e.is_retryable(),
                            lease_lost = matches!(e, StoreError::LeaseLost),
                            "reaper pass failed"
                        ),
                    },
                }
            }
        })
    }
}
