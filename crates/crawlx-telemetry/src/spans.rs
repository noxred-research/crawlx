//! Span-name constants and constructors for the span hierarchy.
//!
//! ```text
//! crawl
//! └── run
//!     └── phase
//!         ├── observation (accessibility_snapshot, dom_supplement, identity_resolution, state_abstraction)
//!         ├── policy_round (deterministic_proposals, model_proposal, safety_classification, arbitration)
//!         └── action (epoch_check, revalidation, safety_confirm, journal_intent, browser_mutation,
//!                     quiescence, traffic_correlation, journal_outcome, graph_update)
//! ```
//!
//! Every span carries `crawl_id`; deeper spans add their own fields.
//! Child spans have no dedicated constructor: create them with
//! `tracing::info_span!(spans::QUIESCENCE, ...)` inside the parent.

use std::fmt::Display;
use tracing::Span;

/// Root span of one crawl.
pub const CRAWL: &str = "crawl";
/// One run (a role/index pair) inside a crawl.
pub const RUN: &str = "run";
/// One strategy phase of a run; see [`PHASES`].
pub const PHASE: &str = "phase";
/// Capturing and abstracting the current page state.
pub const OBSERVATION: &str = "observation";
/// Fetching the accessibility tree during an observation.
pub const ACCESSIBILITY_SNAPSHOT: &str = "accessibility_snapshot";
/// Fetching DOM details the accessibility tree lacks.
pub const DOM_SUPPLEMENT: &str = "dom_supplement";
/// Mapping observed elements to stable element identities.
pub const IDENTITY_RESOLUTION: &str = "identity_resolution";
/// Reducing an observation to its abstract state key.
pub const STATE_ABSTRACTION: &str = "state_abstraction";
/// One round of proposing and arbitrating actions.
pub const POLICY_ROUND: &str = "policy_round";
/// Rule-based action proposals of a policy round.
pub const DETERMINISTIC_PROPOSALS: &str = "deterministic_proposals";
/// Model-generated action proposals of a policy round.
pub const MODEL_PROPOSAL: &str = "model_proposal";
/// Safety classification of candidate actions.
pub const SAFETY_CLASSIFICATION: &str = "safety_classification";
/// Choosing the action to execute among proposals.
pub const ARBITRATION: &str = "arbitration";
/// Execution of one chosen action.
pub const ACTION: &str = "action";
/// Verifying the page epochs still match the observation.
pub const EPOCH_CHECK: &str = "epoch_check";
/// Re-checking the target element before acting.
pub const REVALIDATION: &str = "revalidation";
/// Final safety confirmation before mutation.
pub const SAFETY_CONFIRM: &str = "safety_confirm";
/// Writing the intent record to the action journal.
pub const JOURNAL_INTENT: &str = "journal_intent";
/// The browser input that performs the action.
pub const BROWSER_MUTATION: &str = "browser_mutation";
/// Waiting for the page to settle after the action.
pub const QUIESCENCE: &str = "quiescence";
/// Attributing network traffic to the action.
pub const TRAFFIC_CORRELATION: &str = "traffic_correlation";
/// Writing the outcome record to the action journal.
pub const JOURNAL_OUTCOME: &str = "journal_outcome";
/// Applying the action result to the state graph.
pub const GRAPH_UPDATE: &str = "graph_update";

/// Values of the `phase` field on [`PHASE`] spans.
pub const PHASES: &[&str] = &["url_plane", "greedy", "recovery", "planner", "login"];

/// Every span name with its parent (`None` for the root), parents before children.
pub const HIERARCHY: &[(&str, Option<&str>)] = &[
    (CRAWL, None),
    (RUN, Some(CRAWL)),
    (PHASE, Some(RUN)),
    (OBSERVATION, Some(PHASE)),
    (ACCESSIBILITY_SNAPSHOT, Some(OBSERVATION)),
    (DOM_SUPPLEMENT, Some(OBSERVATION)),
    (IDENTITY_RESOLUTION, Some(OBSERVATION)),
    (STATE_ABSTRACTION, Some(OBSERVATION)),
    (POLICY_ROUND, Some(PHASE)),
    (DETERMINISTIC_PROPOSALS, Some(POLICY_ROUND)),
    (MODEL_PROPOSAL, Some(POLICY_ROUND)),
    (SAFETY_CLASSIFICATION, Some(POLICY_ROUND)),
    (ARBITRATION, Some(POLICY_ROUND)),
    (ACTION, Some(PHASE)),
    (EPOCH_CHECK, Some(ACTION)),
    (REVALIDATION, Some(ACTION)),
    (SAFETY_CONFIRM, Some(ACTION)),
    (JOURNAL_INTENT, Some(ACTION)),
    (BROWSER_MUTATION, Some(ACTION)),
    (QUIESCENCE, Some(ACTION)),
    (TRAFFIC_CORRELATION, Some(ACTION)),
    (JOURNAL_OUTCOME, Some(ACTION)),
    (GRAPH_UPDATE, Some(ACTION)),
];

/// `crawl` span: `crawl_id`, `mode`, `profile`.
#[must_use]
pub fn crawl_span(crawl_id: &dyn Display, mode: &str, profile: &str) -> Span {
    tracing::info_span!("crawl", crawl_id = %crawl_id, mode, profile)
}

/// `run` span: `crawl_id`, `run_id`, `role`, `run_index`, `seed`.
#[must_use]
pub fn run_span(crawl_id: &dyn Display, run_id: &dyn Display, role: &str, run_index: u32, seed: u64) -> Span {
    tracing::info_span!("run", crawl_id = %crawl_id, run_id = %run_id, role, run_index, seed)
}

/// `phase` span: `crawl_id`, `phase` (one of [`PHASES`]).
#[must_use]
pub fn phase_span(crawl_id: &dyn Display, phase: &str) -> Span {
    tracing::info_span!("phase", crawl_id = %crawl_id, phase)
}

/// `observation` span: `crawl_id`, `session_id`, epoch counters, `spec`.
#[must_use]
pub fn observation_span(
    crawl_id: &dyn Display,
    session_id: &dyn Display,
    epoch_nav: u64,
    epoch_doc: u64,
    epoch_mut: u64,
    spec: &str,
) -> Span {
    tracing::info_span!(
        "observation",
        crawl_id = %crawl_id,
        session_id = %session_id,
        epoch.nav = epoch_nav,
        epoch.doc = epoch_doc,
        epoch.mut = epoch_mut,
        spec,
    )
}

/// `policy_round` span: `crawl_id`, `decision_index`.
#[must_use]
pub fn policy_round_span(crawl_id: &dyn Display, decision_index: u64) -> Span {
    tracing::info_span!("policy_round", crawl_id = %crawl_id, decision_index)
}

/// `action` span: `crawl_id`, `action_id`, `key_id`, `kind`, `lane`, `fidelity`.
#[must_use]
pub fn action_span(
    crawl_id: &dyn Display,
    action_id: &dyn Display,
    key_id: &dyn Display,
    kind: &str,
    lane: &str,
    fidelity: &str,
) -> Span {
    tracing::info_span!(
        "action",
        crawl_id = %crawl_id,
        action_id = %action_id,
        key_id = %key_id,
        kind,
        lane,
        fidelity,
    )
}

/// Child spans of `observation`, `policy_round` and `action`. Each is created
/// inside its parent (the current span); fields that are only known when the
/// step finishes are declared `Empty` and filled with [`Span::record`].
pub mod child {
    use tracing::field::Empty;
    use tracing::Span;

    /// `accessibility_snapshot` (observation).
    #[must_use]
    pub fn accessibility_snapshot() -> Span {
        tracing::info_span!("accessibility_snapshot")
    }
    /// `dom_supplement` (observation).
    #[must_use]
    pub fn dom_supplement() -> Span {
        tracing::info_span!("dom_supplement")
    }
    /// `identity_resolution` (observation): `candidates`, `collisions` recorded later.
    #[must_use]
    pub fn identity_resolution() -> Span {
        tracing::info_span!("identity_resolution", candidates = Empty, collisions = Empty)
    }
    /// `state_abstraction` (observation): `state_id`, `cluster_id`, `decision` recorded later.
    #[must_use]
    pub fn state_abstraction() -> Span {
        tracing::info_span!(
            "state_abstraction",
            state_id = Empty,
            cluster_id = Empty,
            decision = Empty
        )
    }
    /// `deterministic_proposals` (policy round): `strategy`, `version`.
    #[must_use]
    pub fn deterministic_proposals(strategy: &str, version: u32) -> Span {
        tracing::info_span!("deterministic_proposals", strategy, version)
    }
    /// `model_proposal` (policy round): `model_id`, `mode`, `outcome` recorded later.
    #[must_use]
    pub fn model_proposal() -> Span {
        tracing::info_span!("model_proposal", model_id = Empty, mode = Empty, outcome = Empty)
    }
    /// `safety_classification` (policy round): verdict counts recorded later.
    #[must_use]
    pub fn safety_classification() -> Span {
        tracing::info_span!(
            "safety_classification",
            allow = Empty,
            deny = Empty,
            approval = Empty
        )
    }
    /// `arbitration` (policy round): chosen `key_id` and `utility` recorded later.
    #[must_use]
    pub fn arbitration() -> Span {
        tracing::info_span!("arbitration", key_id = Empty, utility = Empty)
    }
    /// `epoch_check` (action).
    #[must_use]
    pub fn epoch_check() -> Span {
        tracing::info_span!("epoch_check")
    }
    /// `revalidation` (action): `result` recorded later.
    #[must_use]
    pub fn revalidation() -> Span {
        tracing::info_span!("revalidation", result = Empty)
    }
    /// `safety_confirm` (action): `safety.verdict` recorded later.
    #[must_use]
    pub fn safety_confirm() -> Span {
        tracing::info_span!("safety_confirm", safety.verdict = Empty)
    }
    /// `journal_intent` (action, journal T1).
    #[must_use]
    pub fn journal_intent() -> Span {
        tracing::info_span!("journal_intent")
    }
    /// `browser_mutation` (action).
    #[must_use]
    pub fn browser_mutation() -> Span {
        tracing::info_span!("browser_mutation")
    }
    /// `quiescence` (action): `settle_timeout` recorded later.
    #[must_use]
    pub fn quiescence() -> Span {
        tracing::info_span!("quiescence", settle_timeout = Empty)
    }
    /// `traffic_correlation` (action): `epoch_id`, `late_count` recorded later.
    #[must_use]
    pub fn traffic_correlation() -> Span {
        tracing::info_span!("traffic_correlation", epoch_id = Empty, late_count = Empty)
    }
    /// `journal_outcome` (action, journal T2): `status` recorded later.
    #[must_use]
    pub fn journal_outcome() -> Span {
        tracing::info_span!("journal_outcome", status = Empty)
    }
    /// `graph_update` (action): `edges_touched` recorded later.
    #[must_use]
    pub fn graph_update() -> Span {
        tracing::info_span!("graph_update", edges_touched = Empty)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn hierarchy_is_a_tree_rooted_at_crawl() {
        assert_eq!(HIERARCHY[0], (CRAWL, None));
        for (i, (name, parent)) in HIERARCHY.iter().enumerate() {
            if let Some(p) = parent {
                assert!(
                    HIERARCHY[..i].iter().any(|(n, _)| n == p),
                    "{name} parent {p} must come first"
                );
            }
        }
        let mut names: Vec<_> = HIERARCHY.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), HIERARCHY.len());
    }

    #[test]
    fn names_are_snake_case_and_match_constants() {
        for (name, _) in HIERARCHY {
            assert!(name.chars().all(|c| c.is_ascii_lowercase() || c == '_'), "{name}");
        }
        assert_eq!(HIERARCHY.len(), 23);
    }
}
