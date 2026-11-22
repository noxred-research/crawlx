//! Injected clock (deterministic crates never read wall time) and the workspace time facade.
//!
//! Every crate reads and writes instants, durations and calendar dates through the types here.

mod civil;
#[cfg(feature = "sqlx")]
mod database;
mod error;
mod instant;
mod scan;
mod span;

pub use civil::{Days, IsoWeek, NaiveDate, NaiveDateTime, NaiveTime};
pub use error::{OutOfRangeError, ParseError, ParseErrorKind};
pub use instant::{FixedDateTime, SecondsFormat, Timestamp};
pub use span::Duration;
pub use ::time::Weekday;

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// Source of time for deterministic crates.
pub trait Clock: Send + Sync {
    /// Current instant according to this clock.
    fn now(&self) -> Timestamp;
}

/// Wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        Timestamp::now()
    }
}

/// Manually advanced clock for tests and replay.
#[derive(Debug, Clone)]
pub struct ManualClock {
    millis: Arc<AtomicI64>,
}

impl ManualClock {
    /// Start at `at`.
    #[must_use]
    pub fn new(at: Timestamp) -> Self {
        Self {
            millis: Arc::new(AtomicI64::new(at.timestamp_millis())),
        }
    }

    /// Advance by `ms` milliseconds.
    pub fn advance_ms(&self, ms: i64) {
        self.millis.fetch_add(ms, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_timestamp_millis(self.millis.load(Ordering::SeqCst)).unwrap_or_default()
    }
}
