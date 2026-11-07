//! Statement-level failpoints in the outcome transaction T2 (the atomic outcome
//! test, `chaos` cargo feature).
//!
//! `ActionJournal::finish` reaches one failpoint before each of its statements and one
//! before `COMMIT`; [`T2_FAILPOINTS`] lists them in execution order. With the `chaos`
//! feature an armed failpoint fires once and returns `StoreError::Database` whose source is
//! [`ChaosFault`]: for the caller it is indistinguishable from a driver failure of that
//! statement, which is the point of the drill. Without the feature every [`fail`] compiles
//! to `Ok(())`.
//!
//! The table is process-global; tests that arm failpoints run one at a time (one test
//! owns the table per binary).

/// Failpoints of T2 (`ActionJournal::finish` in `repos/journal.rs`) in execution order.
///
/// `t2.insert_state` and `t2.append_event` guard helpers that run more than one statement
/// (`insert_state`: `states`, `state_clusters`, `state_cluster_membership`; `append_event`:
/// `crawl_runs.event_seq` bump and the `crawl_events` row); the failure is injected before
/// the helper's first statement. `t2.insert_network_epoch`, `t2.insert_state`,
/// `t2.insert_traffic` and `t2.insert_transition` are reached only when the outcome
/// carries a receipt, an after-state, traffic, and the action has a before-state.
pub const T2_FAILPOINTS: &[&str] = &[
    "t2.select_action",
    "t2.update_action",
    "t2.insert_network_epoch",
    "t2.insert_state",
    "t2.insert_traffic",
    "t2.insert_transition",
    "t2.update_action_context",
    "t2.append_event",
    "t2.commit",
];

/// Pause a chaos-enabled process at a durable boundary for an external SIGKILL drill.
///
/// `CRAWLX_STORAGE_PAUSE_AT` selects one exact boundary. The fixed 60-second pause lets
/// the parent observe the emitted marker before killing the process. Normal builds do
/// not read the environment or wait.
pub async fn pause(name: &'static str) {
    #[cfg(feature = "chaos")]
    if std::env::var("CRAWLX_STORAGE_PAUSE_AT").is_ok_and(|selected| selected == name) {
        tracing::warn!(failpoint = name, "failpoint: sleeping");
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    }
    #[cfg(not(feature = "chaos"))]
    let _ = name;
}

#[cfg(feature = "chaos")]
pub use enabled::{arm, fail, hits, reset, ChaosFault};

#[cfg(feature = "chaos")]
mod enabled {
    use crawlx_core::StoreError;
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use std::sync::LazyLock;

    /// The injected failure; the `source` of the `StoreError::Database` a fired failpoint returns.
    #[derive(Debug, thiserror::Error)]
    #[error("chaos failpoint {0} fired")]
    pub struct ChaosFault(pub &'static str);

    #[derive(Default)]
    struct Table {
        /// Remaining failures per failpoint.
        armed: BTreeMap<&'static str, u32>,
        /// Times each failpoint was reached since the last [`reset`].
        hits: BTreeMap<&'static str, u64>,
    }

    static TABLE: LazyLock<Mutex<Table>> = LazyLock::new(|| Mutex::new(Table::default()));

    /// Make `name` fail the next `times` times it is reached.
    pub fn arm(name: &'static str, times: u32) {
        TABLE.lock().armed.insert(name, times);
    }

    /// Disarm every failpoint and clear the hit counters.
    pub fn reset() {
        *TABLE.lock() = Table::default();
    }

    /// How many times `name` was reached since the last [`reset`].
    #[must_use]
    pub fn hits(name: &str) -> u64 {
        TABLE.lock().hits.get(name).copied().unwrap_or(0)
    }

    /// Reach failpoint `name`.
    ///
    /// # Errors
    /// Returns `StoreError::Database { retryable: true }` with a [`ChaosFault`] source while
    /// `name` is armed; each failure consumes one armed count.
    pub fn fail(name: &'static str) -> Result<(), StoreError> {
        let mut t = TABLE.lock();
        *t.hits.entry(name).or_insert(0) += 1;
        let fire = match t.armed.get_mut(name) {
            Some(left) if *left > 0 => {
                *left -= 1;
                true
            }
            _ => false,
        };
        drop(t);
        if fire {
            tracing::warn!(failpoint = name, "failpoint: injecting a statement failure");
            return Err(StoreError::Database {
                source: Box::new(ChaosFault(name)),
                retryable: true,
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
        use super::*;
        use std::error::Error;

        #[test]
        fn armed_failpoint_fires_once_and_counts_hits() {
            reset();
            arm("t2.commit", 1);
            let err = fail("t2.commit").unwrap_err();
            assert!(matches!(err, StoreError::Database { retryable: true, .. }));
            assert!(err.source().unwrap().is::<ChaosFault>());
            fail("t2.commit").unwrap();
            assert_eq!(hits("t2.commit"), 2);
            reset();
            assert_eq!(hits("t2.commit"), 0);
        }
    }
}

/// Without the `chaos` feature a failpoint never fires.
///
/// # Errors
/// Never fails.
#[cfg(not(feature = "chaos"))]
#[inline]
pub const fn fail(_name: &'static str) -> Result<(), crawlx_core::StoreError> {
    Ok(())
}
