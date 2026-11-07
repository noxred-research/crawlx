//! Run-wide counters (`crawlx_core::counters`): one writer per plane, snapshotted into
//! `crawl_runs.counters` after every batch, round and at the end. The same calls feed the
//! `crawlx.urls.*` metrics, so the persisted counters and the Prometheus
//! series are produced from one place. The stored snapshot is derived state: the
//! journal and frontier rows win, and the worker that recovers a session re-derives the
//! interaction counters from the journal ([`RunCounters::recover_from_journal`]) and the worker
//! that takes a URL run over re-derives the URL counters from `url_frontier`
//! ([`RunCounters::recover_from_frontier`]).

use crawlx_core::counters::{Counters, PlaneCounters};
use crawlx_core::repo::{
    ActionJournal, DiscoveryOutcome, FrontierRepo, FrontierStateCounts, JournalOutcomes, RunRepo,
};
use crawlx_core::{CrawlRunId, StoreError};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::sync::Arc;

/// `reason` label of a policy-blocked discovery or a failed, abandoned or unreachable attempt
/// recorded without a more specific code.
pub const UNSPECIFIED_REASON: &str = "unspecified";

/// Which plane a counter update belongs to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Plane {
    /// Urls.
    Urls,
    /// Interactions.
    Interactions,
    /// States.
    States,
}

impl Plane {
    /// The `plane` label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Urls => "urls",
            Self::Interactions => "interactions",
            Self::States => "states",
        }
    }
}

/// Terminal status of one attempted unit of work.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Attempt {
    /// Succeeded.
    Succeeded,
    /// Failed.
    Failed,
    /// Abandoned.
    Abandoned,
    /// Unreachable.
    Unreachable,
    /// Unknown outcome.
    UnknownOutcome,
}

/// Count a discovery. `discovered = admitted + deduplicated + policy_blocked + robots_blocked`.
pub fn record_discovery(c: &mut Counters, outcome: DiscoveryOutcome) {
    record_discoveries(c, outcome, 1);
}

fn record_discoveries(c: &mut Counters, outcome: DiscoveryOutcome, n: u64) {
    c.discovered += n;
    match outcome {
        DiscoveryOutcome::Admitted => c.admitted += n,
        DiscoveryOutcome::Duplicate => c.deduplicated += n,
        DiscoveryOutcome::PolicyBlocked => c.policy_blocked += n,
        DiscoveryOutcome::RobotsBlocked => c.robots_blocked += n,
    }
}

/// Count an attempt and its outcome.
/// `attempted = succeeded + failed + abandoned + unreachable + unknown_outcome`.
pub fn record_attempt(c: &mut Counters, outcome: Attempt) {
    record_attempts(c, outcome, 1);
}

fn record_attempts(c: &mut Counters, outcome: Attempt, n: u64) {
    c.attempted += n;
    match outcome {
        Attempt::Succeeded => c.succeeded += n,
        Attempt::Failed => c.failed += n,
        Attempt::Abandoned => c.abandoned += n,
        Attempt::Unreachable => c.unreachable += n,
        Attempt::UnknownOutcome => c.unknown_outcome += n,
    }
}

/// Shared, cloneable counter set of one run.
#[derive(Clone, Default)]
pub struct RunCounters {
    inner: Arc<Mutex<PlaneCounters>>,
}

impl RunCounters {
    #[must_use]
    /// New.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from persisted counters (resumed run).
    #[must_use]
    pub fn from_snapshot(c: PlaneCounters) -> Self {
        Self {
            inner: Arc::new(Mutex::new(c)),
        }
    }

    #[must_use]
    /// Snapshot.
    pub fn snapshot(&self) -> PlaneCounters {
        *self.inner.lock()
    }

    /// Count a discovery and emit `crawlx.urls.discovered` plus the outcome's series; a
    /// policy block is labelled [`UNSPECIFIED_REASON`]. Prefer
    /// [`Self::discovery_with_reason`] when a bounded denial code is at hand.
    pub fn discovery(&self, plane: Plane, outcome: DiscoveryOutcome) {
        self.discovery_with_reason(plane, outcome, UNSPECIFIED_REASON);
    }

    /// [`Self::discovery`] with the `reason` label of a policy block (a bounded code such as
    /// `DenialReason::as_str()`, never a URL or pattern). Ignored for the other outcomes.
    pub fn discovery_with_reason(&self, plane: Plane, outcome: DiscoveryOutcome, reason: &str) {
        self.with(plane, |c| record_discovery(c, outcome));
        let m = Metrics::global();
        let by_plane = [("plane", plane.as_str())];
        m.counter(names::URLS_DISCOVERED).inc_by(1, &by_plane);
        match outcome {
            DiscoveryOutcome::Admitted => m.counter(names::URLS_ADMITTED).inc_by(1, &by_plane),
            DiscoveryOutcome::Duplicate => m.counter(names::URLS_DEDUPLICATED).inc_by(1, &by_plane),
            DiscoveryOutcome::PolicyBlocked => m
                .counter(names::URLS_POLICY_BLOCKED)
                .inc_by(1, &[("plane", plane.as_str()), ("reason", reason)]),
            DiscoveryOutcome::RobotsBlocked => m.counter(names::URLS_ROBOTS_BLOCKED).inc_by(1, &by_plane),
        }
    }

    /// Count an attempt and emit `crawlx.urls.attempted` plus the outcome's series; a failed,
    /// abandoned or unreachable attempt is labelled [`UNSPECIFIED_REASON`]. Prefer
    /// [`Self::attempt_with_reason`] when a bounded failure code is at hand.
    pub fn attempt(&self, plane: Plane, outcome: Attempt) {
        self.attempt_with_reason(plane, outcome, UNSPECIFIED_REASON);
    }

    /// [`Self::attempt`] with the `reason` label of a failed, abandoned or unreachable attempt
    /// (a bounded code such as `FetchError::code()`, never a URL). Ignored for the other
    /// outcomes; an unknown outcome has its own `crawlx.interactions.unknown_outcome` series.
    pub fn attempt_with_reason(&self, plane: Plane, outcome: Attempt, reason: &str) {
        self.with(plane, |c| record_attempt(c, outcome));
        let m = Metrics::global();
        let by_plane = [("plane", plane.as_str())];
        let with_reason = [("plane", plane.as_str()), ("reason", reason)];
        m.counter(names::URLS_ATTEMPTED).inc_by(1, &by_plane);
        match outcome {
            Attempt::Succeeded => m.counter(names::URLS_SUCCEEDED).inc_by(1, &by_plane),
            Attempt::Failed => m.counter(names::URLS_FAILED).inc_by(1, &with_reason),
            Attempt::Abandoned => m.counter(names::URLS_ABANDONED).inc_by(1, &with_reason),
            Attempt::Unreachable => m.counter(names::URLS_UNREACHABLE).inc_by(1, &with_reason),
            Attempt::UnknownOutcome => {}
        }
    }

    /// Move one already-admitted discovery to `deduplicated` or `policy_blocked` (a page whose
    /// body turned out to be a duplicate, a host that reached its page limit after admission).
    /// The persisted `admitted` count goes down by one; the monotonic
    /// `crawlx.urls.admitted` series cannot, so only the destination series grows.
    pub fn reclassify_admitted(&self, plane: Plane, outcome: DiscoveryOutcome, reason: &str) {
        let m = Metrics::global();
        match outcome {
            DiscoveryOutcome::Duplicate => {
                self.with(plane, |c| {
                    c.admitted = c.admitted.saturating_sub(1);
                    c.deduplicated += 1;
                });
                m.counter(names::URLS_DEDUPLICATED)
                    .inc_by(1, &[("plane", plane.as_str())]);
            }
            DiscoveryOutcome::PolicyBlocked => {
                self.with(plane, |c| {
                    c.admitted = c.admitted.saturating_sub(1);
                    c.policy_blocked += 1;
                });
                m.counter(names::URLS_POLICY_BLOCKED)
                    .inc_by(1, &[("plane", plane.as_str()), ("reason", reason)]);
            }
            DiscoveryOutcome::Admitted | DiscoveryOutcome::RobotsBlocked => {}
        }
    }

    /// With.
    pub fn with(&self, plane: Plane, f: impl FnOnce(&mut Counters)) {
        let mut g = self.inner.lock();
        match plane {
            Plane::Urls => f(&mut g.urls),
            Plane::Interactions => f(&mut g.interactions),
            Plane::States => f(&mut g.states),
        }
    }

    /// Persist the current snapshot to `crawl_runs.counters`.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn persist(&self, runs: &dyn RunRepo, run: CrawlRunId) -> Result<(), StoreError> {
        runs.update_counters(run, self.snapshot()).await
    }

    /// Raise the interaction counters that lag behind `journal` and return how many outcomes
    /// were missing. Each missing outcome is counted the way the live path counts it: one
    /// admitted action and one attempt of that outcome, so `discovered == admitted` and the
    /// plane invariants keep holding.
    ///
    /// The journal rows are the authoritative values and the counters only a snapshot of them:
    /// a worker killed between the T2 commit of an action and the flush of the
    /// counters leaves the stored snapshot one outcome (or more) behind. The repair is one-sided:
    /// a counter above the journal count is left alone, so `verify_trail` still reports an
    /// over-count (and `interactions.unknown_outcome` legitimately exceeds the journal when a
    /// halted T1 counted an unknown outcome without leaving a row).
    ///
    /// Exact while no sibling session of the run sits between its T2 commit and its in-memory
    /// count; the round-robin barrier (default) runs one session of a run at a time.
    #[must_use = "the number of outcomes that were missing"]
    pub fn align_interactions(&self, journal: JournalOutcomes) -> u64 {
        let mut repaired = 0_u64;
        self.with(Plane::Interactions, |c| {
            for (outcome, missing) in [
                (Attempt::Succeeded, journal.succeeded.saturating_sub(c.succeeded)),
                (Attempt::Failed, journal.failed.saturating_sub(c.failed)),
                (
                    Attempt::UnknownOutcome,
                    journal.unknown.saturating_sub(c.unknown_outcome),
                ),
            ] {
                if missing > 0 {
                    record_discoveries(c, DiscoveryOutcome::Admitted, missing);
                    record_attempts(c, outcome, missing);
                    repaired = repaired.saturating_add(missing);
                }
            }
        });
        repaired
    }

    /// Recovery of a run's counters (counters are derived state): re-derive the
    /// interaction counters from the journal rows of `run` ([`Self::align_interactions`]) and,
    /// when anything was missing, flush the repaired snapshot before the session resumes.
    /// Returns how many outcomes were missing.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn recover_from_journal(
        &self,
        journal: &dyn ActionJournal,
        runs: &dyn RunRepo,
        run: CrawlRunId,
    ) -> Result<u64, StoreError> {
        let repaired = self.align_interactions(journal.outcome_counts(run).await?);
        if repaired > 0 {
            self.persist(runs, run).await?;
        }
        Ok(repaired)
    }

    /// Re-derive the URL counters from the frontier rows of the run and return how many counter
    /// units changed. Everything a row proves is taken from the rows: `succeeded`, `failed`,
    /// `unreachable` and `abandoned` (and `attempted` with them), `admitted`, `policy_blocked`
    /// and `robots_blocked` (and `discovered` with them). A worker killed after it finished
    /// rows and before it flushed its counters leaves them out of the stored snapshot, and a
    /// page that turned out a duplicate after the last flush is still counted `admitted`.
    ///
    /// What no row proves stays as stored, never lowered: a link to a URL the run already knew
    /// leaves no row, so `deduplicated` only rises to the rows that carry a `dedupe:` reason
    /// (and the sightings a killed worker made after its last flush are lost), and
    /// `unknown_outcome` is not a frontier outcome. The plane identities hold afterwards.
    ///
    /// For the URL plane of a run that has one (`static`, `hybrid`); a `dynamic` run counts
    /// robots blocks of its browser sessions without a row.
    #[must_use = "the number of counter units that changed"]
    pub fn align_urls(&self, rows: FrontierStateCounts) -> u64 {
        let mut repaired = 0_u64;
        self.with(Plane::Urls, |c| {
            let mut derived = Counters {
                admitted: rows.admitted(),
                deduplicated: c.deduplicated.max(rows.deduplicated()),
                policy_blocked: rows.blocked_by_policy(),
                robots_blocked: rows.robots_blocked,
                succeeded: rows.succeeded,
                failed: rows.failed,
                abandoned: rows.abandoned,
                unreachable: rows.unreachable,
                unknown_outcome: c.unknown_outcome,
                ..Counters::default()
            };
            derived.discovered = [
                derived.admitted,
                derived.deduplicated,
                derived.policy_blocked,
                derived.robots_blocked,
            ]
            .iter()
            .fold(0_u64, |sum, &n| sum.saturating_add(n));
            derived.attempted = [
                derived.succeeded,
                derived.failed,
                derived.abandoned,
                derived.unreachable,
                derived.unknown_outcome,
            ]
            .iter()
            .fold(0_u64, |sum, &n| sum.saturating_add(n));
            repaired = [
                (c.admitted, derived.admitted),
                (c.deduplicated, derived.deduplicated),
                (c.policy_blocked, derived.policy_blocked),
                (c.robots_blocked, derived.robots_blocked),
                (c.succeeded, derived.succeeded),
                (c.failed, derived.failed),
                (c.abandoned, derived.abandoned),
                (c.unreachable, derived.unreachable),
            ]
            .iter()
            .fold(0_u64, |sum, &(stored, now)| {
                sum.saturating_add(stored.abs_diff(now))
            });
            *c = derived;
        });
        repaired
    }

    /// Recovery of the URL counters of a run a worker takes over: re-derive them from
    /// the frontier rows of `run` ([`Self::align_urls`]) and, when anything changed, flush the
    /// repaired snapshot before the plane leases its first batch. Returns how many counter
    /// units changed.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn recover_from_frontier(
        &self,
        frontier: &dyn FrontierRepo,
        runs: &dyn RunRepo,
        run: CrawlRunId,
    ) -> Result<u64, StoreError> {
        let repaired = self.align_urls(frontier.state_counts(run).await?);
        if repaired > 0 {
            self.persist(runs, run).await?;
        }
        Ok(repaired)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn helpers_preserve_the_invariants() {
        let c = RunCounters::new();
        for o in [
            DiscoveryOutcome::Admitted,
            DiscoveryOutcome::Admitted,
            DiscoveryOutcome::Duplicate,
            DiscoveryOutcome::PolicyBlocked,
            DiscoveryOutcome::RobotsBlocked,
        ] {
            c.discovery(Plane::Urls, o);
        }
        for a in [Attempt::Succeeded, Attempt::Failed] {
            c.attempt(Plane::Urls, a);
        }
        let s = c.snapshot();
        assert_eq!((s.urls.discovered, s.urls.admitted, s.urls.attempted), (5, 2, 2));
        assert!(s.urls.invariants_hold());
        assert!(s.interactions.invariants_hold());
    }

    #[test]
    fn align_counts_what_the_journal_has_beyond_the_counters() {
        let c = RunCounters::new();
        c.discovery(Plane::Interactions, DiscoveryOutcome::Admitted);
        c.attempt(Plane::Interactions, Attempt::Succeeded);
        c.discovery(Plane::Interactions, DiscoveryOutcome::Admitted);
        c.attempt(Plane::Interactions, Attempt::Abandoned);
        let journal = JournalOutcomes::new(3, 1, 2);
        assert_eq!(c.align_interactions(journal), 2 + 1 + 2);
        let i = c.snapshot().interactions;
        assert_eq!(
            (i.succeeded, i.failed, i.unknown_outcome, i.abandoned),
            (3, 1, 2, 1)
        );
        assert_eq!((i.discovered, i.admitted, i.attempted), (7, 7, 7));
        assert!(i.invariants_hold());
        assert_eq!(
            c.align_interactions(journal),
            0,
            "a second pass finds nothing missing"
        );
        assert_eq!(c.snapshot().urls, PlaneCounters::default().urls);
    }

    #[test]
    fn align_never_lowers_a_counter() {
        // three halted T1s count an unknown outcome without leaving a journal row, and two
        // successes are counted ahead of a journal that shows one: over-counts stay visible
        let c = RunCounters::new();
        for _ in 0..3 {
            c.attempt(Plane::Interactions, Attempt::UnknownOutcome);
        }
        for _ in 0..2 {
            c.attempt(Plane::Interactions, Attempt::Succeeded);
        }
        let before = c.snapshot();
        assert_eq!(c.align_interactions(JournalOutcomes::new(1, 0, 1)), 0);
        assert_eq!(c.snapshot(), before);
    }

    /// A run that discovered `admitted` URLs and finished `succeeded` of them.
    fn counted(admitted: u64, succeeded: u64) -> RunCounters {
        let c = RunCounters::new();
        for _ in 0..admitted {
            c.discovery(Plane::Urls, DiscoveryOutcome::Admitted);
        }
        for _ in 0..succeeded {
            c.attempt(Plane::Urls, Attempt::Succeeded);
        }
        c
    }

    #[test]
    fn align_urls_counts_the_rows_a_killed_worker_finished_after_its_last_flush() {
        // flushed after the second batch: 41 admitted, 17 finished; three rows more finished
        let c = counted(41, 17);
        let rows = FrontierStateCounts {
            pending: 21,
            succeeded: 20,
            ..FrontierStateCounts::default()
        };
        assert_eq!(c.align_urls(rows), 3);
        let u = c.snapshot().urls;
        assert_eq!(
            (u.discovered, u.admitted, u.attempted, u.succeeded),
            (41, 41, 20, 20)
        );
        assert!(u.invariants_hold(), "{u:?}");
        assert_eq!(c.align_urls(rows), 0, "a second pass finds nothing to repair");
    }

    #[test]
    fn align_urls_counts_the_rows_discovered_and_blocked_after_the_last_flush() {
        let c = counted(1, 1);
        let rows = FrontierStateCounts {
            succeeded: 5,
            failed: 1,
            unreachable: 1,
            abandoned: 1,
            pending: 3,
            leased: 2,
            policy_blocked: 4,
            robots_blocked: 2,
            ..FrontierStateCounts::default()
        };
        let repaired = c.align_urls(rows);
        let u = c.snapshot().urls;
        assert_eq!(repaired, (12 + 4 + 2) + (4 + 1 + 1 + 1));
        assert_eq!((u.admitted, u.policy_blocked, u.robots_blocked), (13, 4, 2));
        assert_eq!((u.succeeded, u.failed, u.unreachable, u.abandoned), (5, 1, 1, 1));
        assert_eq!((u.discovered, u.attempted), (19, 8));
        assert!(u.invariants_hold(), "{u:?}");
    }

    #[test]
    fn align_urls_moves_a_duplicate_page_out_of_admitted_and_keeps_the_sightings_no_row_proves() {
        // three duplicate links were counted, then a page turned out a duplicate of another
        // (admitted -> deduplicated) after the last flush, and a fingerprint block was found
        let c = counted(3, 0);
        for _ in 0..3 {
            c.discovery(Plane::Urls, DiscoveryOutcome::Duplicate);
        }
        let rows = FrontierStateCounts {
            succeeded: 2,
            succeeded_duplicate: 1,
            policy_blocked: 1,
            policy_blocked_duplicate: 1,
            ..FrontierStateCounts::default()
        };
        let _ = c.align_urls(rows);
        let u = c.snapshot().urls;
        assert_eq!(u.admitted, 1, "the duplicate page is not admitted any more");
        assert_eq!(
            u.policy_blocked, 0,
            "a fingerprint block is a duplicate, not a policy block"
        );
        assert_eq!(
            u.deduplicated, 3,
            "the stored value stays: the sightings no row proves are not lost with it"
        );
        assert_eq!((u.succeeded, u.attempted), (2, 2));
        assert!(u.invariants_hold(), "{u:?}");

        // rows that prove more duplicates than the snapshot knows raise it
        let rows = FrontierStateCounts {
            succeeded: 5,
            succeeded_duplicate: 4,
            ..FrontierStateCounts::default()
        };
        let _ = c.align_urls(rows);
        assert_eq!(c.snapshot().urls.deduplicated, 4);
        assert!(c.snapshot().urls.invariants_hold());
    }

    #[test]
    fn align_urls_leaves_the_other_planes_and_the_unknown_outcomes_alone() {
        let c = RunCounters::new();
        c.discovery(Plane::Interactions, DiscoveryOutcome::Admitted);
        c.attempt(Plane::Interactions, Attempt::Succeeded);
        c.attempt(Plane::Urls, Attempt::UnknownOutcome);
        let before = c.snapshot();
        let _ = c.align_urls(FrontierStateCounts::default());
        let after = c.snapshot();
        assert_eq!(after.interactions, before.interactions);
        assert_eq!(after.states, before.states);
        assert_eq!(after.urls.unknown_outcome, 1);
        assert!(after.urls.invariants_hold());
    }
}
