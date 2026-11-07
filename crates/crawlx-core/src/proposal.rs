//! Strategy proposals. Proposals are advisory: the arbiter scores,
//! the safety kernel filters, the Session Actor revalidates.

use crate::action::BrowserAction;
use crate::epoch::ObservationEpoch;
use crate::identity::ActionContextKey;
use crate::identity::ElementIdentityHash;
use crate::ids::ModelDecisionId;
use crate::safety::RiskClass;
use serde::{Deserialize, Serialize};

/// Idempotency class used by the epoch policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProposalClass {
    /// The action tolerates retry after reconciliation and mutation drift (hover, scroll, navigate, tab switch/close, keys).
    Idempotent,
    /// The action may change server or page state; it is never blindly retried.
    NonIdempotent,
}

/// What the strategy expects the action to do (used by reconciliation and
/// the enablement graph).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct ExpectedEffect {
    /// Identities of elements the action is expected to make appear.
    pub reveals: Vec<ElementIdentityHash>,
    /// URL the action is expected to navigate to; `None` when no navigation is expected.
    pub navigates_to: Option<String>,
    /// `true` when the action is expected to change state (the action kind is not idempotent).
    pub mutates_state: bool,
}

/// A proposed action, bound to the observation epoch it was derived from.
#[derive(Clone, Debug)]
pub struct ActionProposal {
    /// Action-context key the proposal is for; the unit of coverage and dedupe.
    pub key: ActionContextKey,
    /// Concrete browser action to perform.
    pub action: BrowserAction,
    /// Observation epoch the proposal was derived from; stale when the epoch moves on.
    pub epoch: ObservationEpoch,
    /// Name of the proposing strategy.
    pub strategy: &'static str,
    /// Version of the proposing strategy; the arbiter prefers the higher version on ties.
    pub strategy_version: u32,
    /// Calibrated confidence in [0, 1].
    pub confidence: f32,
    /// Effect the strategy expects, used by reconciliation and the enablement graph.
    pub expected: ExpectedEffect,
    /// Risk class the proposer believes applies (the kernel decides).
    pub hinted_risk: Option<RiskClass>,
    /// Model decision that produced the proposal; `None` for non-model strategies.
    pub model_decision: Option<ModelDecisionId>,
    /// Human-readable summary for audit rows; never page text verbatim.
    pub summary: String,
}

impl ActionProposal {
    /// Epoch policy class derived from the action kind.
    #[must_use]
    pub const fn class(&self) -> ProposalClass {
        if self.key.action_kind.is_idempotent() {
            ProposalClass::Idempotent
        } else {
            ProposalClass::NonIdempotent
        }
    }
}
