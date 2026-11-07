//! `TurnBarrier`: the round-robin rule as a pure function.
//!
//! The repositories enforce the rule on `crawl_sessions.schedule_slot` in a single
//! `UPDATE ... WHERE NOT EXISTS (lower non-terminal slot)`; this type is the executable
//! specification the property tests compare them against. `tests/loom_turns.rs` runs one
//! thread per role over this rule under `loom` (every interleaving: one turn at a time
//! unless parallel roles are allowed, slot order, every role runs, no deadlock):
//! `cargo test -p crawlx-scheduler --features loom --test loom_turns --release`.

use crawlx_core::repo::{CrawlSession, SessionStatus};
use crawlx_core::SessionId;

/// Barrier configuration for one run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TurnBarrier {
    parallel_roles_allowed: bool,
}

impl TurnBarrier {
    /// `parallel_roles_allowed` is `CreateCrawl::parallel_roles_allowed()`: true only for
    /// `targetIsolation = per_role_replica` or `crossPrincipalAttribution = false`.
    #[must_use]
    pub const fn new(parallel_roles_allowed: bool) -> Self {
        Self {
            parallel_roles_allowed,
        }
    }

    /// May a session at `slot` be granted, given the `(slot, status)` of every session of the run?
    /// Only `pending` sessions (and `recovering` ones, which re-enter the queue) are candidates;
    /// the barrier requires every lower slot to be terminal.
    #[must_use]
    pub fn grantable(&self, slot: u32, sessions: impl IntoIterator<Item = (u32, SessionStatus)>) -> bool {
        self.parallel_roles_allowed
            || sessions
                .into_iter()
                .all(|(s, status)| s >= slot || status.is_terminal())
    }

    /// The session the barrier would grant next among `sessions` (lowest eligible slot), if any.
    #[must_use]
    pub fn next(&self, sessions: &[CrawlSession]) -> Option<SessionId> {
        sessions
            .iter()
            .filter(|s| matches!(s.status, SessionStatus::Pending | SessionStatus::Recovering))
            .filter(|s| {
                self.grantable(
                    s.schedule_slot,
                    sessions.iter().map(|o| (o.schedule_slot, o.status)),
                )
            })
            .min_by_key(|s| s.schedule_slot)
            .map(|s| s.id)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::CrawlRunId;
    use crawlx_storage::testkit::sessions;

    #[test]
    fn higher_slots_wait_for_every_lower_slot() {
        use SessionStatus::{Completed, Pending, Running};
        let b = TurnBarrier::new(false);
        assert!(b.grantable(0, [(0, Pending), (1, Pending)]));
        assert!(!b.grantable(1, [(0, Running), (1, Pending)]));
        assert!(!b.grantable(2, [(0, Completed), (1, Pending), (2, Pending)]));
        assert!(b.grantable(2, [(0, Completed), (1, Completed), (2, Pending)]));
    }

    #[test]
    fn parallel_roles_lift_the_barrier() {
        use SessionStatus::{Pending, Running};
        assert!(TurnBarrier::new(true).grantable(3, [(0, Running), (3, Pending)]));
    }

    #[test]
    fn next_picks_lowest_slot_only_when_unblocked() {
        let mut s = sessions(CrawlRunId::new(), 2, 2);
        let b = TurnBarrier::new(false);
        assert_eq!(b.next(&s), Some(s[0].id));
        s[0].status = SessionStatus::Running;
        assert_eq!(b.next(&s), None, "slot 1 waits for running slot 0");
        s[0].status = SessionStatus::Recovering;
        assert_eq!(
            b.next(&s),
            Some(s[0].id),
            "a recovering session is re-granted before anything higher"
        );
    }
}
