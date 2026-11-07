//! Firecrawl monitors: scheduled checks that scrape a set of targets, compare every
//! page with its stored baseline and report `new`, `same`, `changed`, `removed` or `error` pages.
//!
//! * [`model`] validates the create and update requests.
//! * [`engine`] runs one check: scraping, change detection, JSON-mode extraction, goal judging,
//!   persistence, usage and webhooks.
//! * [`diff`] renders the unified diff and its `parse-diff` AST.
//! * [`view`] renders the stored rows as the API objects.
//! * [`MonitorEngine`] adapts the engine to the scheduler's [`MonitorRunner`];
//!   [`spawn_monitor_loop`] starts the ticker that claims due monitors (15 s period) and an
//!   hourly retention sweep.

pub mod diff;
pub mod engine;
pub mod model;
pub mod view;

use crate::state::AppState;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use crawlx_scheduler::monitor::{
    MonitorRunner, MonitorScheduler, MonitorSchedulerConfig, DEFAULT_TICK_INTERVAL,
};
use crawlx_storage::MonitorRecord;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Period between ticks of the monitor ticker.
pub const TICK_INTERVAL: Duration = DEFAULT_TICK_INTERVAL;
/// Period between retention sweeps (`IntelRepo::purge_expired`).
pub const PURGE_INTERVAL: Duration = Duration::from_secs(3_600);

/// Claim lease of the ticker: a check is cut at [`engine::CHECK_DEADLINE`], so the lease outlasts
/// it and a live check is never claimed twice.
const CLAIM_LEASE: Duration = Duration::from_secs(engine::CHECK_DEADLINE.as_secs() + 300);

/// Runs scheduled checks for the [`MonitorScheduler`].
#[derive(Clone)]
pub struct MonitorEngine {
    state: AppState,
}

impl std::fmt::Debug for MonitorEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MonitorEngine").finish_non_exhaustive()
    }
}

impl MonitorEngine {
    /// An engine running checks against `state`.
    #[must_use]
    pub const fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl MonitorRunner for MonitorEngine {
    async fn run(&self, monitor: &MonitorRecord, trigger: &str) -> Result<Uuid, String> {
        engine::run_check(&self.state, monitor, trigger).await
    }
}

/// The scheduler the ticker runs: claims through `state.repos.intel`, time from `state.clock`.
#[must_use]
pub fn scheduler(state: &AppState) -> MonitorScheduler {
    MonitorScheduler::new(
        Arc::clone(&state.repos.intel),
        Arc::new(MonitorEngine::new(state.clone())),
        Arc::clone(&state.clock),
        MonitorSchedulerConfig {
            lease: CLAIM_LEASE,
            ..MonitorSchedulerConfig::default()
        },
    )
}

/// Start the monitor ticker and the retention sweep. Both stop when `state.shutdown` is
/// cancelled; await the handle to wait for them.
#[must_use = "await the handle once `state.shutdown` is cancelled"]
pub fn spawn_monitor_loop(state: AppState) -> JoinHandle<()> {
    spawn_monitor_loop_every(state, TICK_INTERVAL)
}

/// As [`spawn_monitor_loop`] with a custom tick period (tests).
#[must_use = "await the handle once `state.shutdown` is cancelled"]
pub fn spawn_monitor_loop_every(state: AppState, interval: Duration) -> JoinHandle<()> {
    let stop = state.shutdown.child_token();
    tokio::spawn(async move {
        let sched = scheduler(&state);
        tokio::join!(
            sched.run_forever(interval, stop.clone()),
            purge_loop(&state, stop)
        );
    })
}

/// Delete expired checks (and the other expiring intel rows) every [`PURGE_INTERVAL`].
async fn purge_loop(state: &AppState, stop: CancellationToken) {
    // the ledger is kept: only rows older than the epoch would go
    let keep_ledger: DateTime<Utc> = DateTime::UNIX_EPOCH;
    loop {
        tokio::select! {
            biased;
            () = stop.cancelled() => return,
            () = tokio::time::sleep(PURGE_INTERVAL) => {}
        }
        match state
            .repos
            .intel
            .purge_expired(state.clock.now(), keep_ledger)
            .await
        {
            Ok(report) => tracing::debug!(?report, "intel retention sweep"),
            Err(e) => tracing::warn!(error = %e, "intel retention sweep failed"),
        }
    }
}
