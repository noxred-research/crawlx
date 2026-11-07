//! crawlx-graph: probabilistic enablement graph and path search.
//!
//! An edge says: in context `C`, action pattern `X` revealed target `T` with
//! probability `p`. The graph is in-memory and deterministic (`BTreeMap`s,
//! derived edge ids, no wall-clock reads: every update takes `now`).
//!
//! * [`edge`] — [`EnablementEdge`], [`EdgeContext`], [`EdgeTarget`], cost function.
//! * [`decay`] — Laplace probability and 14-day half-life decay.
//! * [`calibration`] — expected calibration error of `p_success` vs outcomes.
//! * [`context`] — [`EnablementGraph`], lookup order, route generalization,
//!   `EdgeRecord` dump/load and lossless snapshots.
//! * [`update`] — `observe_transition` attribution filter, replay credit,
//!   build change, retirement.
//! * [`search`] — [`best_path`] Dijkstra over clusters.
//! * [`hyperedge`] — conjunctive-precondition mining.
//! * [`replay`] — [`ReplayValidator`].

// No hash-ordered containers on decision or hashing paths (`clippy.toml`).
#![deny(clippy::disallowed_types)]

pub mod calibration;
pub mod context;
pub mod decay;
pub mod edge;
pub mod hyperedge;
pub mod replay;
pub mod search;
pub mod update;

pub use calibration::{
    calibration_bins, calibration_bins_equal_mass, expected_calibration_error,
    expected_calibration_error_equal_mass, CalibrationBin,
};
pub use context::{EnablementGraph, GraphSnapshot};
pub use edge::{derive_edge_id, CostParams, EdgeContext, EdgeTarget, EnablementEdge};
pub use hyperedge::{Episode, Hyperedge, HyperedgeMiner, MiningParams};
pub use replay::{ReplayReport, ReplayValidator, StepOutcome};
pub use search::{best_path, KnownRoute, PathGoal, PathPlan, PathStep, SearchParams};
pub use update::{Confounders, GraphParams, TransitionObservation, TransitionOutcome};

use crawlx_core::EdgeId;

/// Graph errors.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GraphError {
    /// The edge is not in the graph (never existed or was pruned).
    #[error("unknown edge {0}")]
    UnknownEdge(EdgeId),
    /// More outcomes were supplied than the plan has steps.
    #[error("{outcomes} outcomes for a plan of {steps} steps")]
    OutcomeCount {
        /// Number of steps in the plan being validated.
        steps: usize,
        /// Number of step outcomes supplied; always greater than `steps`.
        outcomes: usize,
    },
}

#[cfg(test)]
mod testutil;
