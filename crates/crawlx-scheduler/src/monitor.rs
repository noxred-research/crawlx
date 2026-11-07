//! The monitor ticker: claims due monitors from the [`IntelRepo`], runs each through a
//! [`MonitorRunner`] with bounded concurrency, then reschedules it at the next occurrence of its
//! [`Schedule`].
//!
//! # Exactly-once per due time
//!
//! [`IntelRepo::monitor_claim_due`] sets a lease (`claimed_until`) on every monitor it returns;
//! while the lease holds, no other ticker (another task of this process or another replica
//! against the same database) claims the monitor. The lease is released by
//! [`IntelRepo::monitor_finish_run`], which also moves `next_run_at` to the next occurrence
//! computed *after the run finished*, so a slow check never causes a burst of catch-up runs: due
//! times missed while it ran are skipped. A runner that fails without producing a check leaves the
//! lease to expire, after which the monitor is claimed again.
//!
//! All times come from the injected [`Clock`] (or the `now` argument of [`MonitorScheduler::tick`]).
//! A started tick always runs to completion; [`MonitorScheduler::run_forever`] observes its
//! cancellation token between ticks, so runners that can run long must watch their own shutdown
//! signal.

use crate::error::SchedulerError;
use crate::schedule::Schedule;
use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use crawlx_core::{Clock, Timestamp};
use crawlx_storage::{IntelRepo, MonitorRecord};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Period of [`MonitorScheduler::run_forever`] used by the API.
pub const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(15);
/// How long a claim holds a monitor before another ticker may take it.
pub const DEFAULT_LEASE: Duration = Duration::from_secs(15 * 60);
/// Monitors claimed per tick.
pub const DEFAULT_CLAIM_BATCH: u32 = 32;
/// Checks running at once within one tick.
pub const DEFAULT_CONCURRENCY: usize = 4;

/// Runs one check of a monitor. Implemented by the API's monitor engine.
#[async_trait]
pub trait MonitorRunner: Send + Sync {
    /// Run a check of `monitor` to completion and return its check id. `trigger` is `scheduled`
    /// for the ticker.
    ///
    /// # Errors
    /// A message when no check could be recorded at all (the store is unavailable). A check that
    /// ran and found failures is not an error: it is recorded as a failed or partial check and its
    /// id returned.
    async fn run(&self, monitor: &MonitorRecord, trigger: &str) -> Result<Uuid, String>;
}

/// Settings of a [`MonitorScheduler`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MonitorSchedulerConfig {
    /// Monitors claimed per tick.
    pub claim_batch: u32,
    /// Checks run at once within a tick (at least 1).
    pub concurrency: usize,
    /// Claim lease; must outlast the longest check.
    pub lease: Duration,
}

impl Default for MonitorSchedulerConfig {
    fn default() -> Self {
        Self {
            claim_batch: DEFAULT_CLAIM_BATCH,
            concurrency: DEFAULT_CONCURRENCY,
            lease: DEFAULT_LEASE,
        }
    }
}

/// What one tick did. Lists are sorted by monitor id.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
#[non_exhaustive]
pub struct TickReport {
    /// Monitors the tick claimed.
    pub claimed: usize,
    /// `(monitor, check)` for every monitor that ran and was rescheduled.
    pub ran: Vec<(Uuid, Uuid)>,
    /// `(monitor, reason)` for runs that produced no check or whose reschedule failed; the lease
    /// of these monitors expires instead of being released.
    pub failed: Vec<(Uuid, String)>,
    /// Monitors that ran but whose stored schedule no longer parses; their `next_run_at` is
    /// cleared so they stop ticking.
    pub unschedulable: Vec<Uuid>,
}

/// Claims and runs due monitors.
pub struct MonitorScheduler {
    repo: Arc<dyn IntelRepo>,
    runner: Arc<dyn MonitorRunner>,
    clock: Arc<dyn Clock>,
    cfg: MonitorSchedulerConfig,
}

impl std::fmt::Debug for MonitorScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorScheduler")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

enum Outcome {
    Ran(Uuid, Uuid),
    Failed(Uuid, String),
    Unschedulable(Uuid),
}

impl MonitorScheduler {
    /// A scheduler over `repo` that runs checks through `runner` and reads time from `clock`.
    #[must_use]
    pub fn new(
        repo: Arc<dyn IntelRepo>,
        runner: Arc<dyn MonitorRunner>,
        clock: Arc<dyn Clock>,
        cfg: MonitorSchedulerConfig,
    ) -> Self {
        Self {
            repo,
            runner,
            clock,
            cfg,
        }
    }

    /// Claim the monitors due at `now` and run them. Returns when every claimed monitor has been
    /// run and rescheduled.
    ///
    /// # Errors
    /// [`SchedulerError::Store`] when claiming fails; per-monitor failures are reported in the
    /// [`TickReport`].
    pub async fn tick(&self, now: Timestamp) -> Result<TickReport, SchedulerError> {
        let lease = ChronoDuration::from_std(self.cfg.lease).unwrap_or_else(|_| ChronoDuration::minutes(15));
        let claimed = self
            .repo
            .monitor_claim_due(now, now + lease, self.cfg.claim_batch)
            .await?;
        let mut report = TickReport {
            claimed: claimed.len(),
            ..TickReport::default()
        };
        let permits = Arc::new(Semaphore::new(self.cfg.concurrency.max(1)));
        let mut tasks: JoinSet<Outcome> = JoinSet::new();
        let mut owners: Vec<(tokio::task::Id, Uuid)> = Vec::with_capacity(claimed.len());
        for monitor in claimed {
            let id = monitor.id;
            let handle = tasks.spawn(run_one(
                monitor,
                now,
                Arc::clone(&permits),
                Arc::clone(&self.runner),
                Arc::clone(&self.repo),
                Arc::clone(&self.clock),
            ));
            owners.push((handle.id(), id));
        }
        while let Some(joined) = tasks.join_next_with_id().await {
            match joined {
                Ok((_, Outcome::Ran(monitor, check))) => report.ran.push((monitor, check)),
                Ok((_, Outcome::Failed(monitor, reason))) => report.failed.push((monitor, reason)),
                Ok((_, Outcome::Unschedulable(monitor))) => report.unschedulable.push(monitor),
                Err(e) => {
                    let monitor = owners.iter().find(|(task, _)| *task == e.id()).map(|(_, m)| *m);
                    if let Some(monitor) = monitor {
                        tracing::error!(%monitor, "monitor runner task ended abnormally");
                        report
                            .failed
                            .push((monitor, "the check task panicked or was aborted".to_owned()));
                    }
                }
            }
        }
        report.ran.sort_unstable();
        report.failed.sort_unstable();
        report.unschedulable.sort_unstable();
        Ok(report)
    }

    /// Tick every `interval` until `cancel` fires. Store failures are logged and retried at the
    /// next tick.
    pub async fn run_forever(&self, interval: Duration, cancel: CancellationToken) {
        let mut ticker = tokio::time::interval(interval.max(Duration::from_millis(1)));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = cancel.cancelled() => break,
                _ = ticker.tick() => {}
            }
            match self.tick(self.clock.now()).await {
                Ok(report) if report.claimed > 0 => {
                    tracing::debug!(
                        claimed = report.claimed,
                        ran = report.ran.len(),
                        failed = report.failed.len(),
                        "monitor tick"
                    );
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "monitor tick failed"),
            }
        }
    }
}

async fn run_one(
    monitor: MonitorRecord,
    now: Timestamp,
    permits: Arc<Semaphore>,
    runner: Arc<dyn MonitorRunner>,
    repo: Arc<dyn IntelRepo>,
    clock: Arc<dyn Clock>,
) -> Outcome {
    let Ok(_permit) = permits.acquire_owned().await else {
        return Outcome::Failed(monitor.id, "the tick was shut down".to_owned());
    };
    let check = match runner.run(&monitor, "scheduled").await {
        Ok(check) => check,
        Err(reason) => {
            tracing::warn!(monitor = %monitor.id, %reason, "monitor run failed; the claim will expire");
            return Outcome::Failed(monitor.id, reason);
        }
    };
    let finished = clock.now().max(now);
    let (next, schedulable) = match Schedule::from_stored(&monitor.cron, &monitor.timezone) {
        Ok(schedule) => (schedule.next_after(finished), true),
        Err(e) => {
            tracing::error!(monitor = %monitor.id, error = %e, "stored monitor schedule no longer parses");
            (None, false)
        }
    };
    if let Err(e) = repo
        .monitor_finish_run(monitor.tenant, monitor.id, now, check, next)
        .await
    {
        tracing::warn!(monitor = %monitor.id, error = %e, "rescheduling a monitor failed; the claim will expire");
        return Outcome::Failed(monitor.id, format!("reschedule failed: {e}"));
    }
    if schedulable {
        Outcome::Ran(monitor.id, check)
    } else {
        Outcome::Unschedulable(monitor.id)
    }
}
