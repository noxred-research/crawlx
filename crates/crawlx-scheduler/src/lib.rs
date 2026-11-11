//! crawlx-scheduler: leases, retries, checkpoints, round-robin turns and the
//! stale-lease reaper.
//!
//! * [`plan`] – [`RunPlanner`] expands `roles[] × runsPerRole` into [`RunSlot`]s.
//! * [`turns`] – [`TurnBarrier`], the pure model of the round-robin rule that the
//!   repositories enforce in SQL (and in memory) on `crawl_sessions.schedule_slot`.
//! * [`lease`] – [`Scheduler`]: `lease_next`, `heartbeat`, `release`, `complete`
//!   over any `crawlx_storage::LeaseRepo`.
//! * [`retry`] – [`RetryPolicy`]: bounded exponential backoff with seeded jitter.
//! * [`checkpointing`] – [`CheckpointCadence`]: every 50 actions, every 120 s,
//!   before risky actions, on pause/approval wait/shutdown.
//! * [`reaper`] – [`Reaper`]: every 15 s expire stale leases and mark orphaned
//!   `intended` actions `unknown`.
//! * [`schedule`] – [`Schedule`]: compatibility-API monitor schedules (cron or natural text, IANA zone,
//!   5-minute floor, DST-aware next run).
//! * [`monitor`] – [`MonitorScheduler`]: claims due monitors with a lease, runs them through a
//!   [`MonitorRunner`] with bounded concurrency and reschedules them.
//!
//! All lease arithmetic uses the repository's clock (the database `now()` for
//! PostgreSQL), never the process clock, so worker clock skew cannot reassign live leases.

mod checkpointing;
mod error;
pub mod frontier;
mod lease;
pub mod monitor;
mod plan;
mod reaper;
mod retry;
pub mod schedule;
mod turns;

pub use checkpointing::{CheckpointCadence, CheckpointReason, CheckpointTracker};
pub use error::SchedulerError;
pub use lease::{Scheduler, HEARTBEAT_INTERVAL};
pub use monitor::{
    MonitorRunner, MonitorScheduler, MonitorSchedulerConfig, TickReport, DEFAULT_TICK_INTERVAL,
};
pub use plan::{RunPlanner, RunSlot};
pub use reaper::{ReapSummary, Reaper, ReaperConfig, DEFAULT_MAX_URL_ATTEMPTS, DEFAULT_REAP_INTERVAL};
pub use retry::{RetryDecision, RetryPolicy};
pub use schedule::{Schedule, ScheduleError, ScheduleSpec, MIN_INTERVAL_SECS};
pub use turns::TurnBarrier;
