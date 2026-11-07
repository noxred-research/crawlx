//! Durable round-robin session slices. Unused quota returns to the run when a turn ends;
//! the next turn divides the actual remainder among all nonterminal sessions. Recovery
//! reuses the original allocation and absolute deadline, never a fresh slice.

use crate::error::WorkerError;
use crate::run::RunContext;
use crawlx_core::repo::CrawlSession;
use crawlx_core::{SessionId, Timestamp};
use crawlx_policy::{BudgetKind, Remaining};
use serde::{Deserialize, Serialize};

const ALLOCATION_EVENT: &str = "session.budget";

/// Apply an absolute durable clock snapshot while holding the shared budget lock.
/// Re-reading a credit (or an older concurrent snapshot) never adds it twice.
fn reconcile_login_clock(budget: &mut crawlx_policy::Budget, deadline: Timestamp) {
    let missing = deadline.signed_duration_since(budget.deadline());
    budget.credit_time(missing);
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct Allocation {
    session_id: SessionId,
    interactions: Option<u32>,
    states: Option<u32>,
    deadline: Timestamp,
    #[serde(default)]
    login_credit_ms: u64,
    #[serde(default)]
    login_allowance_ms: u64,
}

impl Allocation {
    fn new(
        session_id: SessionId,
        limits: &crawlx_core::config::Limits,
        remaining: Remaining,
        count: u32,
        now: Timestamp,
    ) -> Self {
        let count = count.max(1);
        let millis = u64::try_from(remaining.time.as_millis()).unwrap_or(u64::MAX);
        let slice_millis = millis.div_ceil(u64::from(count));
        let deadline = now
            .checked_add_signed(chrono::Duration::milliseconds(
                i64::try_from(slice_millis).unwrap_or(i64::MAX),
            ))
            .unwrap_or(now);
        Self {
            session_id,
            interactions: (limits.interactions > 0).then(|| remaining.interactions.div_ceil(count)),
            states: (limits.states > 0).then(|| remaining.states.div_ceil(count)),
            deadline,
            login_credit_ms: 0,
            login_allowance_ms: 0,
        }
    }
}

/// One session's durable allocation and recovered usage, excluding recorded login actions.
pub(crate) struct RoleBudget {
    allocation: Allocation,
    interactions_used: u32,
    states_used: u32,
}

impl RoleBudget {
    /// Persist the slice before exploration, or recover it from the append-only run log.
    pub(crate) async fn load(rc: &RunContext, session: &CrawlSession) -> Result<Self, WorkerError> {
        let actions = rc.stores.journal.list(rc.run, None).await?;
        let states = rc.stores.states.list_states(rc.run).await?;
        let interaction_units = |session_id: Option<SessionId>| {
            actions
                .iter()
                .filter(|a| {
                    session_id.is_none_or(|id| a.session == id)
                        && a.strategy != crate::login::LOGIN_STRATEGY
                        && a.intended_at.is_some()
                })
                .fold(0_u32, |n, a| n.saturating_add(u32::from(a.attempt.max(1))))
        };
        let state_units = |session_id: Option<SessionId>| {
            states
                .iter()
                .filter(|s| s.cluster_is_new && session_id.is_none_or(|id| s.session == id))
                .fold(0_u32, |n, _| n.saturating_add(1))
        };
        // Journal/state rows win over a counter snapshot lost between T2 and its flush.
        // Raising only the missing amount also preserves in-flight charges in this process.
        {
            let mut budget = rc.budget.lock();
            for (kind, used) in [
                (BudgetKind::Interactions, interaction_units(None)),
                (BudgetKind::States, state_units(None)),
            ] {
                let missing = used.saturating_sub(budget.used(kind));
                let remaining = budget.remaining(rc.clock.now());
                let available = match kind {
                    BudgetKind::Interactions => remaining.interactions,
                    BudgetKind::States => remaining.states,
                    _ => 0,
                };
                let _ = budget.try_consume(kind, missing.min(available));
            }
        }
        let mut allocation = None;
        let mut after = 0;
        let mut login_credits = std::collections::BTreeMap::new();
        loop {
            let page = rc.stores.events.list_after(rc.run, after, 512).await?;
            let Some(last) = page.last() else { break };
            after = last.seq;
            for event in page.iter().filter(|e| e.kind == ALLOCATION_EVENT) {
                let value: Allocation = serde_json::from_value(event.payload.clone())
                    .map_err(|e| WorkerError::Other(format!("invalid session budget event: {e}")))?;
                login_credits.insert(value.session_id, value.login_credit_ms);
                if value.session_id == session.id {
                    allocation = Some(value);
                }
            }
        }
        let credit_ms = login_credits.values().fold(0_u64, |n, ms| n.saturating_add(*ms));
        if credit_ms > 0 {
            let run = rc.stores.runs.get(rc.run).await?;
            let started = run.started_at.unwrap_or(run.created_at);
            let credited_deadline = started
                .checked_add_signed(chrono::Duration::seconds(i64::from(
                    rc.crawl.limits.duration_seconds,
                )))
                .and_then(|deadline| {
                    deadline.checked_add_signed(chrono::Duration::milliseconds(
                        i64::try_from(credit_ms).unwrap_or(i64::MAX),
                    ))
                })
                .unwrap_or(started);
            let mut budget = rc.budget.lock();
            reconcile_login_clock(&mut budget, credited_deadline);
        }
        let allocation = match allocation {
            Some(value) => value,
            None => {
                let sessions = rc.stores.runs.list_sessions(rc.run).await?;
                let remaining_sessions = sessions.iter().filter(|s| !s.status.is_terminal()).count();
                let count = u32::try_from(remaining_sessions).unwrap_or(u32::MAX).max(1);
                let now = rc.clock.now();
                let remaining = rc.budget.lock().remaining(now);
                let value = Allocation::new(session.id, &rc.crawl.limits, remaining, count, now);
                rc.stores
                    .events
                    .append(
                        rc.run,
                        ALLOCATION_EVENT,
                        serde_json::to_value(value).map_err(|e| WorkerError::Other(e.to_string()))?,
                    )
                    .await?;
                value
            }
        };
        Ok(Self {
            allocation,
            interactions_used: interaction_units(Some(session.id)),
            states_used: state_units(Some(session.id)),
        })
    }

    /// Persist the bounded login envelope before binding a browser to it.
    pub(crate) async fn reserve_login(
        &mut self,
        rc: &RunContext,
        allowance: chrono::Duration,
    ) -> Result<(), WorkerError> {
        let millis = u64::try_from(allowance.num_milliseconds()).unwrap_or(0);
        if millis > crawlx_storage::session_binding::MAX_LOGIN_RESERVATION_MS {
            return Err(WorkerError::Config("login reservation exceeds its bound".into()));
        }
        let mut allocation = self.allocation;
        allocation.login_allowance_ms = millis;
        rc.stores
            .events
            .append(
                rc.run,
                ALLOCATION_EVENT,
                serde_json::to_value(allocation).map_err(|e| WorkerError::Other(e.to_string()))?,
            )
            .await?;
        self.allocation = allocation;
        Ok(())
    }

    /// Credit only time actually spent logging in, keeping the extension durable.
    pub(crate) async fn credit_login(
        &mut self,
        rc: &RunContext,
        spent: chrono::Duration,
    ) -> Result<(), WorkerError> {
        let millis = u64::try_from(spent.num_milliseconds()).unwrap_or(0);
        if millis == 0 {
            return Ok(());
        }
        let mut allocation = self.allocation;
        allocation.login_credit_ms = allocation.login_credit_ms.saturating_add(millis);
        allocation.login_allowance_ms = 0;
        allocation.deadline = allocation
            .deadline
            .checked_add_signed(spent)
            .unwrap_or(allocation.deadline);
        rc.stores
            .events
            .append(
                rc.run,
                ALLOCATION_EVENT,
                serde_json::to_value(allocation).map_err(|e| WorkerError::Other(e.to_string()))?,
            )
            .await?;
        self.allocation = allocation;
        Ok(())
    }

    /// Absolute durable execution ceiling, including only persisted login credit.
    pub(crate) fn deadline(&self) -> Timestamp {
        self.allocation.deadline
    }

    pub(crate) fn exhausted(&self, now: Timestamp) -> Option<crawlx_core::counters::TerminalReason> {
        use crawlx_core::counters::TerminalReason;
        if now >= self.allocation.deadline {
            Some(TerminalReason::DeadlineReached)
        } else if self
            .allocation
            .interactions
            .is_some_and(|n| self.interactions_used >= n)
            || self.allocation.states.is_some_and(|n| self.states_used >= n)
        {
            Some(TerminalReason::LimitReached)
        } else {
            None
        }
    }

    pub(crate) fn interactions_remaining(&self) -> Option<u32> {
        self.allocation
            .interactions
            .map(|n| n.saturating_sub(self.interactions_used))
    }

    pub(crate) fn charge(&mut self, kind: BudgetKind) {
        match kind {
            BudgetKind::Interactions => self.interactions_used = self.interactions_used.saturating_add(1),
            BudgetKind::States => self.states_used = self.states_used.saturating_add(1),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn parallel_credit_snapshots_are_idempotent_and_stale_reads_do_not_roll_back() {
        let started = chrono::DateTime::from_timestamp(1_000, 0).unwrap();
        let limits = crawlx_core::config::Limits::default();
        let shared = parking_lot::Mutex::new(crawlx_policy::Budget::new(&limits, started));
        let raw = shared.lock().deadline();
        let a_persisted = raw + chrono::Duration::seconds(25);
        // A persisted its login. B loads that durable credit before A resumes.
        reconcile_login_clock(&mut shared.lock(), a_persisted);
        // A's own post-login reload observes exactly the same credit, not an increment.
        reconcile_login_clock(&mut shared.lock(), a_persisted);
        assert_eq!(shared.lock().deadline(), a_persisted);
        let both_persisted = a_persisted + chrono::Duration::seconds(10);
        reconcile_login_clock(&mut shared.lock(), both_persisted);
        reconcile_login_clock(&mut shared.lock(), a_persisted);
        assert_eq!(shared.lock().deadline(), both_persisted);
    }

    #[test]
    fn uneven_demand_returns_unused_slices_to_later_turns() {
        let now = chrono::DateTime::from_timestamp(1_000, 0).unwrap();
        let limits = crawlx_core::config::Limits {
            interactions: 23,
            states: 23,
            ..crawlx_core::config::Limits::default()
        };
        let mut remaining = Remaining {
            urls: 0,
            interactions: 23,
            states: 23,
            time: std::time::Duration::from_millis(23),
        };
        let demands = [1_u32, 20, 2, 20, 20, 20];
        let mut spent = Vec::new();
        for (index, demand) in demands.into_iter().enumerate() {
            let sessions = u32::try_from(demands.len() - index).unwrap();
            let allocation = Allocation::new(SessionId::new(), &limits, remaining, sessions, now);
            let allowance = allocation.interactions.unwrap();
            assert_eq!(allocation.states, Some(allowance));
            assert_eq!(
                allocation.deadline - now,
                chrono::Duration::milliseconds(i64::from(allowance))
            );
            let used = demand.min(allowance);
            spent.push(used);
            remaining.interactions -= used;
            remaining.states -= used;
            remaining.time -= std::time::Duration::from_millis(u64::from(used));
        }
        assert_eq!(spent, [1, 5, 2, 5, 5, 5]);
        assert_eq!(remaining.interactions, 0);
        assert_eq!(remaining.states, 0);
        assert_eq!(remaining.time, std::time::Duration::ZERO);
    }

    #[test]
    fn recovered_usage_and_original_deadline_do_not_reset() {
        let now = chrono::DateTime::from_timestamp(1_000, 0).unwrap();
        let allocation = Allocation {
            session_id: SessionId::new(),
            interactions: Some(5),
            states: Some(3),
            deadline: now + chrono::Duration::seconds(10),
            login_credit_ms: 0,
            login_allowance_ms: 0,
        };
        let bytes = serde_json::to_vec(&allocation).unwrap();
        let mut recovered = RoleBudget {
            allocation: serde_json::from_slice(&bytes).unwrap(),
            interactions_used: 4,
            states_used: 2,
        };
        assert_eq!(recovered.interactions_remaining(), Some(1));
        recovered.charge(BudgetKind::Interactions);
        assert_eq!(
            recovered.exhausted(now),
            Some(crawlx_core::counters::TerminalReason::LimitReached)
        );
        assert_eq!(
            recovered.exhausted(now + chrono::Duration::seconds(10)),
            Some(crawlx_core::counters::TerminalReason::DeadlineReached)
        );
    }
}
