//! Typed errors of `crawlx-model`.
//!
//! Every failure mode of an engine is an `Err`; callers fall back to the
//! deterministic ranking and never retry in a storm.

use thiserror::Error;

/// Errors returned by [`crate::DecisionEngine`] implementations and helpers.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ModelError {
    /// The circuit breaker is open: no call was made.
    #[error("circuit breaker open; falling back to deterministic ranking")]
    BreakerOpen,
    /// The per-call time budget elapsed.
    #[error("model call timed out after {after_ms} ms")]
    Timeout {
        /// Budget that elapsed, in milliseconds.
        after_ms: u64,
    },
    /// The request is not a legal typed-decision request (crawler bug, not a model failure).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The remote endpoint could not be reached or the connection failed.
    #[error("transport error: {0}")]
    Transport(String),
    /// The remote endpoint answered with a non-success HTTP status.
    #[error("model endpoint returned HTTP {status}")]
    Http {
        /// The HTTP status code received.
        status: u16,
    },
    /// The model output failed schema or semantic validation and was discarded.
    #[error("malformed model output: {0}")]
    Malformed(String),
    /// Calibration or gate parameters were unusable.
    #[error("calibration error: {0}")]
    Calibration(String),
    /// The inference runtime is not linked into this build.
    #[error("inference runtime unavailable: {0}")]
    RuntimeUnavailable(String),
    /// The engine is switched off by the rollout mode.
    #[error("model engine disabled by rollout mode")]
    Disabled,
    /// A rollout configuration was rejected.
    #[error("rollout rejected: {0}")]
    Rollout(String),
}
