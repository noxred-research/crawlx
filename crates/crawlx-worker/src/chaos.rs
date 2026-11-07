//! Failpoints for the crash drills (`chaos` cargo feature).
//!
//! A failpoint is a named place in the per-action protocol. With the `chaos` feature the
//! action configured for it runs when the code reaches it; without the feature every
//! [`hit`] compiles to nothing. Configuration comes from `CRAWLX_FAILPOINTS`
//! (`name=action;name=action`) or from [`configure`] in-process:
//!
//! | action | effect |
//! |---|---|
//! | `off` | nothing |
//! | `panic` | panic the current task; the `Supervisor` turns it into a typed failure and the Session Actor dies with its action left `intended` |
//! | `abort` | `std::process::abort()`: the whole process dies at once (the in-process stand-in for `kill -9`) |
//! | `sleep(ms)` | wait `ms` milliseconds; lets an external harness kill the process while an action is `intended` |
//!
//! Points: [`AFTER_INTENT_BEFORE_PERFORM`], [`AFTER_PERFORM_BEFORE_OUTCOME`],
//! [`DURING_OUTCOME_TX`], [`AFTER_OUTCOME_BEFORE_NEXT_PROPOSAL`],
//! [`AFTER_OUTCOME_BEFORE_COUNTER_FLUSH`].
//!
//! `during_outcome_tx` is reached inside [`FailingJournal::finish`], the decorator every
//! worker store wraps its journal in under the `chaos` feature: the inner journal's T2 future
//! has been polled once (for PostgreSQL the connection acquire or the transaction's first
//! statement is in flight, nothing committed) and the failpoint fires while that future is
//! held, so a panic or abort drops it uncommitted. A journal that commits T2 in one
//! synchronous step (the in-memory store) has already committed when the failpoint fires.
//! Either way nothing partial can be observed, which is what the drills assert; a failure
//! between two statements of the PostgreSQL transaction would need a hook inside
//! `crawlx-storage` and is not simulated.

/// After T1 (`intended` durable), before `perform` reaches the browser.
pub const AFTER_INTENT_BEFORE_PERFORM: &str = "after_intent_before_perform";
/// After `perform` returned, before T2 (`succeeded`/`failed`) is written.
pub const AFTER_PERFORM_BEFORE_OUTCOME: &str = "after_perform_before_outcome";
/// Inside T2: the outcome transaction has started on the journal and is not committed.
pub const DURING_OUTCOME_TX: &str = "during_outcome_tx";
/// After T2 committed, before the actor returns the outcome and can take the next proposal.
pub const AFTER_OUTCOME_BEFORE_NEXT_PROPOSAL: &str = "after_outcome_before_next_proposal";
/// After T2 committed and the driver counted the action in memory, before the run counters
/// are flushed to `crawl_runs.counters`: the stored snapshot lags the journal until
/// recovery re-derives it.
pub const AFTER_OUTCOME_BEFORE_COUNTER_FLUSH: &str = "after_outcome_before_counter_flush";
/// Environment variable holding the failpoint spec.
pub const FAILPOINTS_ENV: &str = "CRAWLX_FAILPOINTS";

#[cfg(feature = "chaos")]
pub use enabled::{configure, hit, hits, reset, FailAction, FailingJournal};

#[cfg(feature = "chaos")]
mod enabled {
    use async_trait::async_trait;
    use crawlx_core::counters::ActionStatus;
    use crawlx_core::proposal::ActionProposal;
    use crawlx_core::repo::{ActionJournal, ActionRecord, JournalOutcomes, OutcomeRecord, Reconciliation};
    use crawlx_core::safety::SafetyVerdict;
    use crawlx_core::{ActionId, CrawlRunId, ObservationEpoch, SessionId, StoreError, Timestamp};
    use parking_lot::Mutex;
    use std::collections::BTreeMap;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, LazyLock};
    use std::task::Poll;
    use std::time::Duration;

    /// What a failpoint does when reached.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum FailAction {
        /// Nothing.
        Off,
        /// Panic the current task.
        Panic,
        /// Abort the process.
        Abort,
        /// Sleep this long, then continue.
        Sleep(Duration),
    }

    impl FailAction {
        fn parse(s: &str) -> Option<Self> {
            let s = s.trim();
            if s.eq_ignore_ascii_case("off") {
                return Some(Self::Off);
            }
            if s.eq_ignore_ascii_case("panic") {
                return Some(Self::Panic);
            }
            if s.eq_ignore_ascii_case("abort") {
                return Some(Self::Abort);
            }
            let ms = s
                .strip_prefix("sleep(")?
                .strip_suffix(')')?
                .trim()
                .parse::<u64>()
                .ok()?;
            Some(Self::Sleep(Duration::from_millis(ms)))
        }
    }

    struct Table {
        actions: BTreeMap<String, FailAction>,
        hits: BTreeMap<String, Arc<AtomicU64>>,
    }

    static TABLE: LazyLock<Mutex<Table>> = LazyLock::new(|| {
        let spec = std::env::var(super::FAILPOINTS_ENV).unwrap_or_default();
        Mutex::new(Table {
            actions: parse(&spec),
            hits: BTreeMap::new(),
        })
    });

    fn table() -> &'static Mutex<Table> {
        &TABLE
    }

    fn parse(spec: &str) -> BTreeMap<String, FailAction> {
        spec.split(';')
            .filter_map(|entry| {
                let (name, action) = entry.split_once('=')?;
                let action = FailAction::parse(action)?;
                Some((name.trim().to_owned(), action))
            })
            .collect()
    }

    /// Replace the whole failpoint table with `spec` (same syntax as `CRAWLX_FAILPOINTS`);
    /// hit counters are kept.
    pub fn configure(spec: &str) {
        table().lock().actions = parse(spec);
    }

    /// Disable every failpoint and clear the hit counters.
    pub fn reset() {
        let mut t = table().lock();
        t.actions.clear();
        t.hits.clear();
    }

    /// How many times `name` was reached since the last [`reset`].
    #[must_use]
    pub fn hits(name: &str) -> u64 {
        table()
            .lock()
            .hits
            .get(name)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Reach failpoint `name` and run its configured action.
    #[allow(
        clippy::panic,
        reason = "the `panic` action exists to exercise the Supervisor's panic path"
    )]
    pub async fn hit(name: &'static str) {
        let action = {
            let mut t = table().lock();
            t.hits
                .entry(name.to_owned())
                .or_insert_with(|| Arc::new(AtomicU64::new(0)))
                .fetch_add(1, Ordering::Relaxed);
            t.actions.get(name).copied().unwrap_or(FailAction::Off)
        };
        match action {
            FailAction::Off => {}
            FailAction::Panic => panic!("failpoint {name}: panic"),
            FailAction::Abort => {
                tracing::error!(failpoint = name, "failpoint: aborting the process");
                std::process::abort()
            }
            FailAction::Sleep(d) => {
                tracing::warn!(failpoint = name, ms = d.as_millis(), "failpoint: sleeping");
                tokio::time::sleep(d).await;
            }
        }
    }

    /// Journal decorator that reaches [`super::DURING_OUTCOME_TX`] inside `finish` (T2).
    ///
    /// `finish` polls the inner journal's T2 future once, reaches the failpoint while that
    /// future is held, then completes it. For the PostgreSQL journal nothing is committed at
    /// the failpoint: a `panic` drops the future (an open transaction is rolled back by
    /// `sqlx`), an `abort` or `kill -9` drops the connection and the server rolls back. The
    /// in-memory journal commits in one synchronous step and has finished when the failpoint
    /// fires. Every other method delegates unchanged.
    pub struct FailingJournal<J: ActionJournal + ?Sized> {
        inner: Arc<J>,
    }

    impl<J: ActionJournal + ?Sized> FailingJournal<J> {
        /// Wrap `inner`.
        #[must_use]
        pub const fn new(inner: Arc<J>) -> Self {
            Self { inner }
        }

        /// The wrapped journal.
        #[must_use]
        pub const fn inner(&self) -> &Arc<J> {
            &self.inner
        }
    }

    #[async_trait]
    impl<J: ActionJournal + ?Sized> ActionJournal for FailingJournal<J> {
        async fn propose(
            &self,
            run: CrawlRunId,
            session: SessionId,
            p: &ActionProposal,
            v: &SafetyVerdict,
        ) -> Result<ActionId, StoreError> {
            self.inner.propose(run, session, p, v).await
        }
        async fn intend(
            &self,
            id: ActionId,
            session: SessionId,
            epoch: ObservationEpoch,
        ) -> Result<(), StoreError> {
            self.inner.intend(id, session, epoch).await
        }
        async fn finish(&self, id: ActionId, outcome: OutcomeRecord) -> Result<(), StoreError> {
            let mut t2 = pin!(self.inner.finish(id, outcome));
            let first = std::future::poll_fn(|cx| Poll::Ready(t2.as_mut().poll(cx))).await;
            hit(super::DURING_OUTCOME_TX).await;
            match first {
                Poll::Ready(done) => done,
                Poll::Pending => t2.await,
            }
        }
        async fn dataset_page(&self, id: ActionId) -> Result<i64, StoreError> {
            self.inner.dataset_page(id).await
        }
        async fn finish_with_accepted(
            &self,
            id: ActionId,
            outcome: OutcomeRecord,
            session_fence: i64,
            accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
            state_deltas: Vec<crawlx_core::dataset::KvCasV1>,
            outbox: Vec<crawlx_core::dataset::DeliveryBatchV1>,
        ) -> Result<(), StoreError> {
            let mut t2 = pin!(self.inner.finish_with_accepted(
                id,
                outcome,
                session_fence,
                accepted,
                state_deltas,
                outbox
            ));
            let first = std::future::poll_fn(|cx| Poll::Ready(t2.as_mut().poll(cx))).await;
            hit(super::DURING_OUTCOME_TX).await;
            match first {
                Poll::Ready(done) => done,
                Poll::Pending => t2.await,
            }
        }
        async fn mark_unknown(&self, before: Timestamp) -> Result<Vec<ActionId>, StoreError> {
            self.inner.mark_unknown(before).await
        }
        async fn reconcile(&self, id: ActionId, r: Reconciliation) -> Result<(), StoreError> {
            self.inner.reconcile(id, r).await
        }
        async fn reconcile_with_accepted(
            &self,
            id: ActionId,
            r: Reconciliation,
            session_fence: i64,
            accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
            state_deltas: Vec<crawlx_core::dataset::KvCasV1>,
            outbox: Vec<crawlx_core::dataset::DeliveryBatchV1>,
        ) -> Result<(), StoreError> {
            self.inner
                .reconcile_with_accepted(id, r, session_fence, accepted, state_deltas, outbox)
                .await
        }
        async fn get(&self, id: ActionId) -> Result<ActionRecord, StoreError> {
            self.inner.get(id).await
        }
        async fn list(
            &self,
            run: CrawlRunId,
            status: Option<ActionStatus>,
        ) -> Result<Vec<ActionRecord>, StoreError> {
            self.inner.list(run, status).await
        }
        async fn outcome_counts(&self, run: CrawlRunId) -> Result<JournalOutcomes, StoreError> {
            self.inner.outcome_counts(run).await
        }
    }

    #[cfg(test)]
    mod tests {
        #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
        use super::*;

        #[test]
        fn spec_parsing() {
            let t = parse("a=panic; b = sleep(250);c=abort;d=off;bad;e=nope");
            assert_eq!(t.get("a"), Some(&FailAction::Panic));
            assert_eq!(t.get("b"), Some(&FailAction::Sleep(Duration::from_millis(250))));
            assert_eq!(t.get("c"), Some(&FailAction::Abort));
            assert_eq!(t.get("d"), Some(&FailAction::Off));
            assert_eq!(t.len(), 4);
        }
    }
}

/// Without the `chaos` feature a failpoint is a no-op.
#[cfg(not(feature = "chaos"))]
#[inline]
pub async fn hit(_name: &'static str) {}
