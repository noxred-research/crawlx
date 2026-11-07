//! Errors of the observation layer.

use crawlx_core::BrowserError;
use thiserror::Error;

/// Failure while observing or waiting for quiescence.
#[derive(Debug, Error)]
pub enum ObserveError {
    /// The browser backend failed; `BrowserError::is_target_crash` still applies.
    #[error("browser error: {0}")]
    Browser(#[from] BrowserError),
}

impl ObserveError {
    /// Did the browser target die (the session's recovery ladder applies)?
    #[must_use]
    pub fn is_target_crash(&self) -> bool {
        match self {
            Self::Browser(e) => e.is_target_crash(),
        }
    }
}

/// Failure of a [`crate::capture::TrafficSource`]. The proxy source never
/// fails: a closed capture channel is the end of its stream.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// The CDP backend failed while draining traffic.
    #[error("browser error: {0}")]
    Browser(#[from] BrowserError),
}
