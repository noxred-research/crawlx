//! Checkpoint cadence: every 50 committed actions, every 120 s of
//! session time, immediately before any action riskier than a local UI preference,
//! on pause, while waiting for an approval and on graceful shutdown. The newest
//! three checkpoints per session are kept.
//!
//! This is the decision helper only; the Session Actor writes the checkpoint
//! (encrypted storage-state artifact + `checkpoints` row).

use crawlx_core::safety::RiskClass;
use crawlx_core::Timestamp;
use std::time::Duration;

/// Why a checkpoint is taken; `as_str` matches `checkpoints.reason`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum CheckpointReason {
    /// The action-count cadence elapsed.
    CadenceActions,
    /// The time cadence elapsed.
    CadenceTime,
    /// Immediately before an action riskier than a local UI preference.
    PreMutation,
    /// The session is pausing.
    Pause,
    /// The session waits for an approval.
    ApprovalWait,
    /// Graceful shutdown.
    Shutdown,
}

impl CheckpointReason {
    /// The `checkpoints.reason` value for this reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CadenceActions => "cadence_actions",
            Self::CadenceTime => "cadence_time",
            Self::PreMutation => "pre_mutation",
            Self::Pause => "pause",
            Self::ApprovalWait => "approval_wait",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Cadence settings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CheckpointCadence {
    /// Committed actions between two cadence checkpoints.
    pub every_actions: u32,
    /// Session time between two cadence checkpoints (only when an action happened since).
    pub every: Duration,
    /// Newest checkpoints kept per session.
    pub keep: usize,
}

impl Default for CheckpointCadence {
    fn default() -> Self {
        Self {
            every_actions: 50,
            every: Duration::from_secs(120),
            keep: 3,
        }
    }
}

impl CheckpointCadence {
    /// Checkpoint required *before* performing an action of `risk`?
    /// True for every class above `ReversibleLocalPreference` (`Unclassified` counts as a write).
    #[must_use]
    pub fn before_action(&self, risk: RiskClass) -> Option<CheckpointReason> {
        (risk > RiskClass::ReversibleLocalPreference).then_some(CheckpointReason::PreMutation)
    }

    /// Fresh tracker starting at `now`.
    #[must_use]
    pub fn tracker(&self, now: Timestamp) -> CheckpointTracker {
        CheckpointTracker {
            cadence: *self,
            actions_since: 0,
            last_at: now,
        }
    }
}

/// Counts committed actions and elapsed session time since the last checkpoint.
#[derive(Clone, Copy, Debug)]
pub struct CheckpointTracker {
    cadence: CheckpointCadence,
    actions_since: u32,
    last_at: Timestamp,
}

impl CheckpointTracker {
    /// One action reached `succeeded`/`failed`.
    pub fn record_action(&mut self) {
        self.actions_since = self.actions_since.saturating_add(1);
    }

    /// Cadence-driven reason due at `now`, if any (actions take precedence over time).
    #[must_use]
    pub fn due(&self, now: Timestamp) -> Option<CheckpointReason> {
        if self.actions_since >= self.cadence.every_actions {
            return Some(CheckpointReason::CadenceActions);
        }
        let elapsed = now
            .signed_duration_since(self.last_at)
            .to_std()
            .unwrap_or(Duration::ZERO);
        (self.actions_since > 0 && elapsed >= self.cadence.every).then_some(CheckpointReason::CadenceTime)
    }

    /// A checkpoint was written at `now`; reset both counters.
    pub fn checkpointed(&mut self, now: Timestamp) {
        self.actions_since = 0;
        self.last_at = now;
    }

    /// Actions committed since the last checkpoint.
    #[must_use]
    pub const fn actions_since(&self) -> u32 {
        self.actions_since
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::{Duration as D, TimeZone, Utc};

    fn t0() -> Timestamp {
        Utc.with_ymd_and_hms(2026, 10, 16, 12, 0, 0).unwrap()
    }

    #[test]
    fn fires_every_fifty_actions() {
        let c = CheckpointCadence::default();
        let mut t = c.tracker(t0());
        for i in 1..=120u32 {
            t.record_action();
            let due = t.due(t0());
            if i % 50 == 0 {
                assert_eq!(due, Some(CheckpointReason::CadenceActions), "action {i}");
                t.checkpointed(t0());
            } else {
                assert_eq!(due, None, "action {i}");
            }
        }
    }

    #[test]
    fn fires_after_120_seconds_only_if_something_happened() {
        let c = CheckpointCadence::default();
        let mut t = c.tracker(t0());
        assert_eq!(
            t.due(t0() + D::seconds(500)),
            None,
            "idle sessions need no checkpoint"
        );
        t.record_action();
        assert_eq!(t.due(t0() + D::seconds(119)), None);
        assert_eq!(t.due(t0() + D::seconds(120)), Some(CheckpointReason::CadenceTime));
        t.checkpointed(t0() + D::seconds(120));
        assert_eq!(t.due(t0() + D::seconds(121)), None);
    }

    #[test]
    fn risky_actions_checkpoint_first() {
        let c = CheckpointCadence::default();
        assert_eq!(c.before_action(RiskClass::NavigationReveal), None);
        assert_eq!(c.before_action(RiskClass::ReversibleLocalPreference), None);
        for r in [
            RiskClass::PersistentWriteOwn,
            RiskClass::Destructive,
            RiskClass::FileUpload,
            RiskClass::Unclassified,
        ] {
            assert_eq!(c.before_action(r), Some(CheckpointReason::PreMutation), "{r:?}");
        }
        assert_eq!(CheckpointReason::PreMutation.as_str(), "pre_mutation");
        assert_eq!(c.keep, 3);
    }
}
