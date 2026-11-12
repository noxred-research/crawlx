//! Run budget tracking (`limits.urls|interactions|states|durationSeconds`)
//! plus the per-host page budget (`scope.maxPagesPerHost`).
//! Pure counters plus an absolute deadline; the caller passes
//! the current time so the type never reads a clock.
//!
//! A budget whose configured limit is `0` is *disabled*: it can never be
//! consumed and never counts as exhausted (a static crawl has
//! `interactions: 0`). The deadline always applies. The per-host budget
//! refuses pages for a saturated host but never ends the run.

use crawlx_core::config::Limits;
use crawlx_core::counters::TerminalReason;
use crawlx_core::time::Timestamp;
use std::collections::BTreeMap;
use std::time::Duration;

/// Which budget a unit is charged to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BudgetKind {
    /// Pages admitted to the crawl (`limits.urls`).
    Urls,
    /// Browser interactions performed (`limits.interactions`).
    Interactions,
    /// Distinct browser states recorded (`limits.states`).
    States,
    /// Pages admitted for one host (`scope.maxPagesPerHost`).
    HostPages,
}

impl BudgetKind {
    /// Field name as in the API.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Urls => "urls",
            Self::Interactions => "interactions",
            Self::States => "states",
            Self::HostPages => "maxPagesPerHost",
        }
    }
}

/// Remaining budget at a point in time.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Remaining {
    /// Pages that may still be admitted.
    pub urls: u32,
    /// Browser interactions that may still be performed.
    pub interactions: u32,
    /// Distinct browser states that may still be recorded.
    pub states: u32,
    /// Time until the deadline (zero once passed).
    pub time: Duration,
}

/// Charging a unit failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
#[error("{} budget exhausted", kind.as_str())]
pub struct BudgetExhausted {
    /// The budget that ran out.
    pub kind: BudgetKind,
}

/// Budget for one crawl run.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Budget {
    limit_urls: u32,
    limit_interactions: u32,
    limit_states: u32,
    used_urls: u32,
    used_interactions: u32,
    used_states: u32,
    deadline: Timestamp,
    /// `scope.maxPagesPerHost`; `None` is unlimited.
    limit_host_pages: Option<u32>,
    /// lowercase host → pages charged
    host_pages: BTreeMap<String, u32>,
}

impl Budget {
    /// Budget for `limits` starting at `started_at`, without a per-host limit.
    #[must_use]
    pub fn new(limits: &Limits, started_at: Timestamp) -> Self {
        let deadline = started_at
            .checked_add_signed(chrono::Duration::seconds(i64::from(limits.duration_seconds)))
            .unwrap_or(started_at);
        Self {
            limit_urls: limits.urls,
            limit_interactions: limits.interactions,
            limit_states: limits.states,
            used_urls: 0,
            used_interactions: 0,
            used_states: 0,
            deadline,
            limit_host_pages: None,
            host_pages: BTreeMap::new(),
        }
    }

    /// Charge at most `max` pages per host (`scope.maxPagesPerHost`); `None`
    /// is unlimited. The per-host budget never ends the run.
    #[must_use]
    pub fn with_max_pages_per_host(mut self, max: Option<u32>) -> Self {
        self.limit_host_pages = max;
        self
    }

    /// The per-host page limit.
    #[must_use]
    pub const fn max_pages_per_host(&self) -> Option<u32> {
        self.limit_host_pages
    }

    /// Pages charged to `host` so far.
    #[must_use]
    pub fn host_used(&self, host: &str) -> u32 {
        self.host_pages
            .get(&host.to_ascii_lowercase())
            .copied()
            .unwrap_or(0)
    }

    /// Charge one page to `host`.
    ///
    /// # Errors
    /// [`BudgetExhausted`] with [`BudgetKind::HostPages`] once the host is at its limit.
    pub fn try_consume_host(&mut self, host: &str) -> Result<(), BudgetExhausted> {
        let key = host.to_ascii_lowercase();
        let used = self.host_pages.get(&key).copied().unwrap_or(0);
        if self.limit_host_pages.is_some_and(|limit| used >= limit) {
            return Err(BudgetExhausted {
                kind: BudgetKind::HostPages,
            });
        }
        self.host_pages.insert(key, used + 1);
        Ok(())
    }

    /// The absolute deadline.
    #[must_use]
    pub const fn deadline(&self) -> Timestamp {
        self.deadline
    }

    /// Move the deadline out by `spent`: wall time that is not charged to
    /// `limits.durationSeconds` (compatibility flag `-crawl-duration` excludes login time). A negative
    /// `spent` is ignored.
    pub fn credit_time(&mut self, spent: chrono::Duration) {
        if spent > chrono::Duration::zero() {
            self.deadline = self.deadline.checked_add_signed(spent).unwrap_or(self.deadline);
        }
    }

    /// `(limit, used)` of a run-wide budget; the per-host budget has no
    /// single slot and reads as disabled here (see [`Self::try_consume_host`]).
    const fn slot(&self, kind: BudgetKind) -> (u32, u32) {
        match kind {
            BudgetKind::Urls => (self.limit_urls, self.used_urls),
            BudgetKind::Interactions => (self.limit_interactions, self.used_interactions),
            BudgetKind::States => (self.limit_states, self.used_states),
            BudgetKind::HostPages => (0, 0),
        }
    }

    /// Units used so far for `kind` (`0` for [`BudgetKind::HostPages`]; use
    /// [`Self::host_used`]).
    #[must_use]
    pub const fn used(&self, kind: BudgetKind) -> u32 {
        self.slot(kind).1
    }

    /// Charge `n` units; refuses (charging nothing) when fewer than `n` remain
    /// or the budget is disabled. [`BudgetKind::HostPages`] is always refused
    /// here: charge hosts through [`Self::try_consume_host`].
    ///
    /// # Errors
    /// [`BudgetExhausted`] naming the budget.
    pub fn try_consume(&mut self, kind: BudgetKind, n: u32) -> Result<(), BudgetExhausted> {
        let (limit, used) = self.slot(kind);
        if limit.saturating_sub(used) < n {
            return Err(BudgetExhausted { kind });
        }
        let used = used + n;
        match kind {
            BudgetKind::Urls => self.used_urls = used,
            BudgetKind::Interactions => self.used_interactions = used,
            BudgetKind::States => self.used_states = used,
            BudgetKind::HostPages => return Err(BudgetExhausted { kind }),
        }
        Ok(())
    }

    /// Remaining units and time at `now`.
    #[must_use]
    pub fn remaining(&self, now: Timestamp) -> Remaining {
        Remaining {
            urls: self.limit_urls.saturating_sub(self.used_urls),
            interactions: self.limit_interactions.saturating_sub(self.used_interactions),
            states: self.limit_states.saturating_sub(self.used_states),
            time: self
                .deadline
                .signed_duration_since(now)
                .to_std()
                .unwrap_or(Duration::ZERO),
        }
    }

    /// First exhausted enabled budget, if any.
    #[must_use]
    pub fn exhausted_kind(&self) -> Option<BudgetKind> {
        [BudgetKind::Urls, BudgetKind::Interactions, BudgetKind::States]
            .into_iter()
            .find(|k| {
                let (limit, used) = self.slot(*k);
                limit > 0 && used >= limit
            })
    }

    /// Terminal reason when the run must stop: the deadline has passed
    /// (`deadline_reached`) or an enabled budget is spent (`limit_reached`).
    #[must_use]
    pub fn exhausted(&self, now: Timestamp) -> Option<TerminalReason> {
        if now >= self.deadline {
            Some(TerminalReason::DeadlineReached)
        } else if self.exhausted_kind().is_some() {
            Some(TerminalReason::LimitReached)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::TimeZone;

    fn t0() -> Timestamp {
        chrono::Utc.with_ymd_and_hms(2026, 10, 20, 0, 0, 0).unwrap()
    }

    fn limits(urls: u32, interactions: u32, states: u32, secs: u32) -> Limits {
        Limits {
            urls,
            interactions,
            states,
            duration_seconds: secs,
            ..Limits::default()
        }
    }

    #[test]
    fn url_budget_exhausts_at_limit() {
        let mut b = Budget::new(&limits(3, 0, 0, 100), t0());
        for _ in 0..3 {
            assert_eq!(b.exhausted(t0()), None);
            b.try_consume(BudgetKind::Urls, 1).unwrap();
        }
        assert_eq!(b.exhausted(t0()), Some(TerminalReason::LimitReached));
        assert_eq!(b.exhausted_kind(), Some(BudgetKind::Urls));
        assert_eq!(
            b.try_consume(BudgetKind::Urls, 1),
            Err(BudgetExhausted {
                kind: BudgetKind::Urls
            })
        );
        assert_eq!(b.used(BudgetKind::Urls), 3);
    }

    #[test]
    fn partial_charge_is_refused_atomically() {
        let mut b = Budget::new(&limits(10, 5, 5, 100), t0());
        b.try_consume(BudgetKind::Interactions, 4).unwrap();
        assert!(b.try_consume(BudgetKind::Interactions, 2).is_err());
        assert_eq!(b.used(BudgetKind::Interactions), 4);
        assert_eq!(b.remaining(t0()).interactions, 1);
    }

    #[test]
    fn disabled_budgets_never_exhaust_and_cannot_be_charged() {
        let mut b = Budget::new(&limits(10, 0, 0, 100), t0());
        assert_eq!(b.exhausted(t0()), None);
        assert!(b.try_consume(BudgetKind::States, 1).is_err());
        assert_eq!(b.exhausted(t0()), None);
    }

    #[test]
    fn deadline_reached_wins_over_limit() {
        let mut b = Budget::new(&limits(1, 0, 0, 60), t0());
        b.try_consume(BudgetKind::Urls, 1).unwrap();
        let late = t0() + chrono::Duration::seconds(60);
        assert_eq!(b.exhausted(late), Some(TerminalReason::DeadlineReached));
        assert_eq!(
            b.exhausted(t0() + chrono::Duration::seconds(59)),
            Some(TerminalReason::LimitReached)
        );
    }

    #[test]
    fn credited_time_moves_the_deadline_out_and_negative_credit_is_ignored() {
        let mut b = Budget::new(&limits(0, 0, 0, 60), t0());
        let at_deadline = t0() + chrono::Duration::seconds(60);
        assert_eq!(b.exhausted(at_deadline), Some(TerminalReason::DeadlineReached));
        b.credit_time(chrono::Duration::seconds(30));
        assert_eq!(b.deadline(), t0() + chrono::Duration::seconds(90));
        assert_eq!(b.exhausted(at_deadline), None);
        assert_eq!(
            b.exhausted(t0() + chrono::Duration::seconds(90)),
            Some(TerminalReason::DeadlineReached)
        );
        b.credit_time(chrono::Duration::seconds(-500));
        assert_eq!(b.deadline(), t0() + chrono::Duration::seconds(90));
    }

    #[test]
    fn remaining_reports_time_and_saturates() {
        let b = Budget::new(&limits(5, 6, 7, 120), t0());
        let r = b.remaining(t0() + chrono::Duration::seconds(20));
        assert_eq!(
            r,
            Remaining {
                urls: 5,
                interactions: 6,
                states: 7,
                time: Duration::from_secs(100)
            }
        );
        assert_eq!(
            b.remaining(t0() + chrono::Duration::seconds(500)).time,
            Duration::ZERO
        );
    }

    #[test]
    fn states_and_interactions_exhaust_independently() {
        let mut b = Budget::new(&limits(100, 2, 1, 100), t0());
        b.try_consume(BudgetKind::States, 1).unwrap();
        assert_eq!(b.exhausted_kind(), Some(BudgetKind::States));
        let mut c = Budget::new(&limits(100, 2, 100, 100), t0());
        c.try_consume(BudgetKind::Interactions, 2).unwrap();
        assert_eq!(c.exhausted(t0()), Some(TerminalReason::LimitReached));
    }

    #[test]
    fn host_page_budget_is_per_host_and_never_ends_the_run() {
        let mut b = Budget::new(&limits(10, 0, 0, 100), t0()).with_max_pages_per_host(Some(2));
        assert_eq!(b.max_pages_per_host(), Some(2));
        b.try_consume_host("A.example").unwrap();
        b.try_consume_host("a.example").unwrap();
        assert_eq!(
            b.try_consume_host("a.example"),
            Err(BudgetExhausted {
                kind: BudgetKind::HostPages
            })
        );
        assert_eq!(b.host_used("a.example"), 2);
        b.try_consume_host("b.example").unwrap();
        assert_eq!(b.host_used("b.example"), 1);
        assert_eq!(b.exhausted(t0()), None);
        assert_eq!(b.exhausted_kind(), None);
        assert_eq!(BudgetKind::HostPages.as_str(), "maxPagesPerHost");
        // unlimited by default
        let mut u = Budget::new(&limits(10, 0, 0, 100), t0());
        for _ in 0..100 {
            u.try_consume_host("a.example").unwrap();
        }
        assert_eq!(u.max_pages_per_host(), None);
    }
}
