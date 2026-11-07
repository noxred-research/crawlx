//! Injected clock (deterministic crates never read wall time).

use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

/// RFC 3339 UTC timestamp with millisecond precision.
pub type Timestamp = DateTime<Utc>;

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
        Utc::now()
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
        DateTime::<Utc>::from_timestamp_millis(self.millis.load(Ordering::SeqCst)).unwrap_or_default()
    }
}
