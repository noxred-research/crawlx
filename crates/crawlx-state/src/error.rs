//! Crate error type.

use crawlx_core::StateClusterId;

/// Failures of cluster-index mutations.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// A split plan names a source cluster the index does not hold.
    #[error("unknown cluster {0}")]
    UnknownCluster(StateClusterId),
    /// The split source was already replaced by an earlier split.
    #[error("cluster {0} is already superseded")]
    AlreadySuperseded(StateClusterId),
    /// The plan was computed against an older cluster version than the index now holds.
    #[error("split plan for cluster {cluster} targets version {plan_version}, cluster is at version {current_version}")]
    StaleSplitPlan {
        /// Source cluster of the plan.
        cluster: StateClusterId,
        /// Cluster version the plan was computed against.
        plan_version: u32,
        /// Version the cluster has now.
        current_version: u32,
    },
}
