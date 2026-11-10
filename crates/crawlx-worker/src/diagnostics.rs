//! Per-session driver diagnostics (`dynamic.enableDiagnostics`, the `-enable-diagnostics` compatibility flag).
//!
//! The reference headless crawler logs every page state it explores to a diagnostics directory.
//! crawlx keeps the equivalent in the run report instead: one [`SessionDiagnostics`] per
//! browser-plane session, summarizing what the exploration driver did (rounds that executed an
//! action, dropped actions, recovery ladder runs, popup-tab evictions, states persisted, why and
//! after how long the session stopped). The values are counts and one wall-clock duration; the
//! counts do not depend on timing, so two replays of a deterministic run agree on everything but
//! [`SessionDiagnostics::wall_ms`].

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// What one browser-plane session did, recorded when `dynamic.enableDiagnostics` is on.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionDiagnostics {
    /// Role (principal) the session acted as.
    pub role: String,
    /// 1-based repetition of the role within the run (`(role, run_index)` is unique per run).
    pub run_index: u16,
    /// Exploration steps: rounds whose chosen action reached the browser (executed, dropped
    /// before running, or crashed mid-action).
    pub steps: u64,
    /// Actions that reached a terminal journal state (succeeded or failed).
    pub actions: u64,
    /// Steps whose action the actor dropped before it ran (stale epoch, not actionable,
    /// identity changed, confirmation refused).
    pub drops: u64,
    /// Times the session actor ran its recovery ladder after a browser crash or a lost target.
    pub recoveries: u64,
    /// Popup tabs closed to stay within `dynamic.maxTabs` (least useful tab first).
    pub tab_evictions: u64,
    /// States the session persisted (initial observations plus action outcomes).
    pub states: u64,
    /// Scroll steps `dynamic.maxScrollSteps` performed across the session's pages.
    pub scroll_steps: u64,
    /// Why the session stopped: a `TerminalReason` name, or `error` when the driver failed.
    pub stop_reason: String,
    /// Wall-clock duration of the exploration in milliseconds.
    pub wall_ms: u64,
}

/// Collects the [`SessionDiagnostics`] of a run; cloned into every session of the run.
///
/// Sessions [`push`](Self::push) one record when they end; the run report drains the sink with
/// [`take`](Self::take).
#[derive(Clone, Default)]
pub struct DiagnosticsSink {
    sessions: Arc<Mutex<Vec<SessionDiagnostics>>>,
}

impl std::fmt::Debug for DiagnosticsSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiagnosticsSink")
            .field("sessions", &self.sessions.lock().len())
            .finish()
    }
}

impl DiagnosticsSink {
    /// Record one finished session.
    pub fn push(&self, diagnostics: SessionDiagnostics) {
        self.sessions.lock().push(diagnostics);
    }

    /// Drain every recorded session, ordered by `(role, run_index)` so the report does not
    /// depend on the order sessions happened to finish in.
    #[must_use]
    pub fn take(&self) -> Vec<SessionDiagnostics> {
        let mut all = std::mem::take(&mut *self.sessions.lock());
        all.sort_by(|a, b| (&a.role, a.run_index).cmp(&(&b.role, b.run_index)));
        all
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn record(role: &str, run_index: u16, steps: u64) -> SessionDiagnostics {
        SessionDiagnostics {
            role: role.to_owned(),
            run_index,
            steps,
            ..SessionDiagnostics::default()
        }
    }

    #[test]
    fn take_orders_by_role_then_run_index_and_drains() {
        let sink = DiagnosticsSink::default();
        let clone = sink.clone();
        clone.push(record("user", 2, 5));
        sink.push(record("admin", 1, 3));
        clone.push(record("user", 1, 4));
        let taken = sink.take();
        let order: Vec<_> = taken.iter().map(|d| (d.role.as_str(), d.run_index)).collect();
        assert_eq!(order, [("admin", 1), ("user", 1), ("user", 2)]);
        assert!(clone.take().is_empty(), "take drains the shared sink");
    }

    #[test]
    fn serializes_with_stable_snake_case_keys() {
        let mut d = record("user", 1, 2);
        d.stop_reason = "frontier_exhausted".to_owned();
        let json = serde_json::to_value(&d).unwrap();
        let keys: Vec<_> = json.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            [
                "actions",
                "drops",
                "recoveries",
                "role",
                "run_index",
                "scroll_steps",
                "states",
                "steps",
                "stop_reason",
                "tab_evictions",
                "wall_ms"
            ]
        );
        let back: SessionDiagnostics = serde_json::from_value(json).unwrap();
        assert_eq!(back, d);
    }
}
