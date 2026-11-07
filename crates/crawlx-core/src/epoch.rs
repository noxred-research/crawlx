//! Observation epochs. Monotonic per-tab counters bumped by the
//! observer; every proposal carries the epoch it was generated from.

use serde::{Deserialize, Serialize};

/// `navigation_seq` increments on main-frame navigation; `document_seq` when
/// the main document is replaced or a same-document navigation changes the
/// route; `mutation_seq` by the isolated-world `MutationObserver` record count.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize, Debug)]
pub struct ObservationEpoch {
    /// Counts main-frame navigations in the tab.
    pub navigation_seq: u64,
    /// Counts main-document replacements and same-document route changes.
    pub document_seq: u64,
    /// Running count of DOM mutation records seen by the isolated-world observer.
    pub mutation_seq: u64,
}

/// How much `mutation_seq` drift a proposal class tolerates before it is
/// dropped as stale (planning default 8, 0 under
/// `authorized_security_test`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochPolicy {
    /// Allowed `mutation_seq` drift for non-idempotent proposals; 0 tolerates none (default 8).
    pub mutation_slack_non_idempotent: u64,
}

impl Default for EpochPolicy {
    fn default() -> Self {
        Self {
            mutation_slack_non_idempotent: 8,
        }
    }
}

impl EpochPolicy {
    /// Strict policy: no mutation drift tolerated for non-idempotent classes.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            mutation_slack_non_idempotent: 0,
        }
    }

    /// Is a proposal generated at `proposal` still executable at `current`?
    /// Navigation and document counters must match exactly; mutation drift is
    /// tolerated for idempotent classes and bounded for non-idempotent ones.
    #[must_use]
    pub fn compatible(
        &self,
        proposal: ObservationEpoch,
        current: ObservationEpoch,
        idempotent: bool,
    ) -> bool {
        if proposal.navigation_seq != current.navigation_seq || proposal.document_seq != current.document_seq
        {
            return false;
        }
        if current.mutation_seq < proposal.mutation_seq {
            // counters never go backwards; a smaller value means a different tab/document
            return false;
        }
        idempotent || current.mutation_seq - proposal.mutation_seq <= self.mutation_slack_non_idempotent
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn e(n: u64, d: u64, m: u64) -> ObservationEpoch {
        ObservationEpoch {
            navigation_seq: n,
            document_seq: d,
            mutation_seq: m,
        }
    }

    #[test]
    fn navigation_change_is_stale() {
        let p = EpochPolicy::default();
        assert!(!p.compatible(e(1, 1, 0), e(2, 1, 0), true));
        assert!(!p.compatible(e(1, 1, 0), e(1, 2, 0), true));
    }

    #[test]
    fn mutation_slack_applies_to_non_idempotent_only() {
        let p = EpochPolicy::default();
        assert!(p.compatible(e(1, 1, 0), e(1, 1, 100), true));
        assert!(p.compatible(e(1, 1, 0), e(1, 1, 8), false));
        assert!(!p.compatible(e(1, 1, 0), e(1, 1, 9), false));
        assert!(!EpochPolicy::strict().compatible(e(1, 1, 0), e(1, 1, 1), false));
    }
}
