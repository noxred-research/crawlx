//! Typed strategy errors. A failing strategy contributes nothing to
//! its round; it never fails the round.

use crawlx_core::error::{Classify, ErrorClass};
use crawlx_model::ModelError;
use std::time::Duration;

/// Why a strategy produced no proposals.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StrategyError {
    /// The per-strategy deadline elapsed.
    #[error("strategy timed out after {0:?}")]
    Timeout(Duration),
    /// The model provider is unavailable (breaker open, transport failure,
    /// malformed or disabled engine). Retryable on a later round.
    #[error("model provider unavailable: {0}")]
    ModelUnavailable(String),
    /// The `DecisionContext` is inconsistent (crawler bug, terminal for the round).
    #[error("invalid decision context: {0}")]
    InvalidContext(String),
    /// A milestone gate the strategy needs has not passed for this build.
    #[error("strategy {strategy} needs gate {gate}: {reason}")]
    Gated {
        /// Strategy name as recorded in proposal attribution.
        strategy: &'static str,
        /// Gate id, e.g. `G1`.
        gate: &'static str,
        /// Why the gate is not satisfied (missing, invalid, produced for another build).
        reason: String,
    },
    /// A requested version has no implementation registered in this build.
    #[error("strategy {strategy} version {version} is unavailable in this build")]
    UnavailableVersion {
        /// Strategy's proposal-attribution name.
        strategy: &'static str,
        /// Requested implementation version.
        version: u32,
    },
    /// Anything else (configuration rejected, internal invariant).
    #[error("internal strategy failure: {0}")]
    Internal(String),
}

impl Classify for StrategyError {
    fn class(&self) -> ErrorClass {
        match self {
            Self::Timeout(_) | Self::ModelUnavailable(_) => ErrorClass::Retryable,
            Self::InvalidContext(_) | Self::Internal(_) | Self::UnavailableVersion { .. } => {
                ErrorClass::Terminal
            }
            Self::Gated { .. } => ErrorClass::PolicyDenied,
        }
    }
}

impl From<ModelError> for StrategyError {
    fn from(e: ModelError) -> Self {
        match e {
            ModelError::Timeout { after_ms } => Self::Timeout(Duration::from_millis(after_ms)),
            ModelError::InvalidRequest(m) => Self::InvalidContext(m),
            ModelError::Rollout(m) | ModelError::Calibration(m) => Self::Internal(m),
            other @ (ModelError::BreakerOpen
            | ModelError::Transport(_)
            | ModelError::Http { .. }
            | ModelError::Malformed(_)
            | ModelError::RuntimeUnavailable(_)
            | ModelError::Disabled) => Self::ModelUnavailable(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn model_errors_map_to_typed_strategy_errors() {
        assert_eq!(
            StrategyError::from(ModelError::Timeout { after_ms: 300 }),
            StrategyError::Timeout(Duration::from_millis(300))
        );
        assert!(matches!(
            StrategyError::from(ModelError::BreakerOpen),
            StrategyError::ModelUnavailable(_)
        ));
        assert!(matches!(
            StrategyError::from(ModelError::InvalidRequest("x".into())),
            StrategyError::InvalidContext(_)
        ));
        assert!(matches!(
            StrategyError::from(ModelError::Rollout("x".into())),
            StrategyError::Internal(_)
        ));
    }

    #[test]
    fn every_variant_maps_to_a_class() {
        let table = [
            (
                StrategyError::Timeout(Duration::from_secs(1)),
                ErrorClass::Retryable,
            ),
            (StrategyError::ModelUnavailable("m".into()), ErrorClass::Retryable),
            (StrategyError::InvalidContext("c".into()), ErrorClass::Terminal),
            (
                StrategyError::Gated {
                    strategy: "state_novelty",
                    gate: "G1",
                    reason: "missing".into(),
                },
                ErrorClass::PolicyDenied,
            ),
            (StrategyError::Internal("i".into()), ErrorClass::Terminal),
            (
                StrategyError::UnavailableVersion {
                    strategy: "interaction_bfs",
                    version: 99,
                },
                ErrorClass::Terminal,
            ),
        ];
        for (e, want) in &table {
            assert_eq!(e.class(), *want, "{e}");
        }
    }
}
