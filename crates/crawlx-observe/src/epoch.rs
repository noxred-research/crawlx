//! Pure state machine for `ObservationEpoch`.
//!
//! Counters never decrease and never reset within a session: a navigation
//! only moves them forward.

use crawlx_core::epoch::ObservationEpoch;

/// Browser-level events that move the epoch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum EpochEvent {
    /// `Page.frameNavigated` on the main frame (or a history navigation that
    /// loads a document): a new document replaces the old one.
    MainFrameNavigated,
    /// `Page.navigatedWithinDocument`; only a route change replaces the
    /// logical document.
    SameDocumentNavigation {
        /// The URL's route (origin and route template) differs from the previous one.
        route_changed: bool,
    },
    /// The main document was replaced without a navigation (`document.open`,
    /// a framework swapping the root).
    DocumentReplaced,
    /// `n` mutation records from the isolated-world `MutationObserver`.
    Mutations(u64),
}

/// Tracks the epoch of one tab/session.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct EpochTracker {
    epoch: ObservationEpoch,
}

impl EpochTracker {
    /// Start at epoch zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Start from a known epoch (session restore).
    #[must_use]
    pub fn starting_at(epoch: ObservationEpoch) -> Self {
        Self { epoch }
    }

    /// Current epoch.
    #[must_use]
    pub fn current(&self) -> ObservationEpoch {
        self.epoch
    }

    /// Apply one event and return the new epoch.
    ///
    /// * `MainFrameNavigated`: `navigation_seq + 1` and `document_seq + 1`
    ///   (a navigation always loads a new document); `mutation_seq` is kept.
    /// * `SameDocumentNavigation { route_changed: true }`: `document_seq + 1`.
    ///   Without a route change nothing moves.
    /// * `DocumentReplaced`: `document_seq + 1`.
    /// * `Mutations(n)`: `mutation_seq + n`.
    pub fn apply(&mut self, event: EpochEvent) -> ObservationEpoch {
        let e = &mut self.epoch;
        match event {
            EpochEvent::MainFrameNavigated => {
                e.navigation_seq = e.navigation_seq.saturating_add(1);
                e.document_seq = e.document_seq.saturating_add(1);
            }
            EpochEvent::SameDocumentNavigation { route_changed } => {
                if route_changed {
                    e.document_seq = e.document_seq.saturating_add(1);
                }
            }
            EpochEvent::DocumentReplaced => e.document_seq = e.document_seq.saturating_add(1),
            EpochEvent::Mutations(n) => e.mutation_seq = e.mutation_seq.saturating_add(n),
        }
        self.epoch
    }

    /// Merge an epoch reported by the backend (e.g. read back with
    /// `Runtime.callFunctionOn`): component-wise maximum, so the tracker stays
    /// monotone even if events and reads race.
    pub fn merge(&mut self, reported: ObservationEpoch) -> ObservationEpoch {
        let e = &mut self.epoch;
        e.navigation_seq = e.navigation_seq.max(reported.navigation_seq);
        e.document_seq = e.document_seq.max(reported.document_seq);
        e.mutation_seq = e.mutation_seq.max(reported.mutation_seq);
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;

    fn event() -> impl Strategy<Value = EpochEvent> {
        prop_oneof![
            Just(EpochEvent::MainFrameNavigated),
            any::<bool>().prop_map(|route_changed| EpochEvent::SameDocumentNavigation { route_changed }),
            Just(EpochEvent::DocumentReplaced),
            (0u64..1_000).prop_map(EpochEvent::Mutations),
        ]
    }

    proptest! {
        #[test]
        fn monotone_under_any_interleaving(events in proptest::collection::vec(event(), 0..200)) {
            let mut t = EpochTracker::new();
            let mut prev = t.current();
            for ev in events {
                let next = t.apply(ev);
                prop_assert!(next.navigation_seq >= prev.navigation_seq);
                prop_assert!(next.document_seq >= prev.document_seq);
                prop_assert!(next.mutation_seq >= prev.mutation_seq);
                prop_assert!(next >= prev);
                match ev {
                    EpochEvent::MainFrameNavigated => prop_assert_eq!(next.mutation_seq, prev.mutation_seq),
                    EpochEvent::Mutations(_) => {
                        prop_assert_eq!(next.navigation_seq, prev.navigation_seq);
                        prop_assert_eq!(next.document_seq, prev.document_seq);
                    }
                    _ => {}
                }
                prev = next;
            }
        }

        #[test]
        fn counters_equal_event_tallies(events in proptest::collection::vec(event(), 0..200)) {
            let mut t = EpochTracker::new();
            let (mut navs, mut docs, mut muts) = (0u64, 0u64, 0u64);
            for ev in &events {
                match ev {
                    EpochEvent::MainFrameNavigated => { navs += 1; docs += 1; }
                    EpochEvent::SameDocumentNavigation { route_changed: true } | EpochEvent::DocumentReplaced => docs += 1,
                    EpochEvent::SameDocumentNavigation { route_changed: false } => {}
                    EpochEvent::Mutations(n) => muts += n,
                }
                t.apply(*ev);
            }
            let e = t.current();
            prop_assert_eq!((e.navigation_seq, e.document_seq, e.mutation_seq), (navs, docs, muts));
        }

        #[test]
        fn merge_never_decreases(
            events in proptest::collection::vec(event(), 0..50),
            n in 0u64..100, d in 0u64..100, m in 0u64..100,
        ) {
            let mut t = EpochTracker::new();
            for ev in events { t.apply(ev); }
            let before = t.current();
            let after = t.merge(ObservationEpoch { navigation_seq: n, document_seq: d, mutation_seq: m });
            prop_assert!(after >= before);
            prop_assert!(after.navigation_seq >= n && after.document_seq >= d && after.mutation_seq >= m);
        }
    }

    #[test]
    fn navigation_resets_nothing() {
        let mut t = EpochTracker::new();
        t.apply(EpochEvent::Mutations(7));
        let e = t.apply(EpochEvent::MainFrameNavigated);
        assert_eq!((e.navigation_seq, e.document_seq, e.mutation_seq), (1, 1, 7));
        let e = t.apply(EpochEvent::SameDocumentNavigation { route_changed: false });
        assert_eq!((e.navigation_seq, e.document_seq, e.mutation_seq), (1, 1, 7));
    }
}
