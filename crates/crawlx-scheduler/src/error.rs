//! Scheduler errors.

use crawlx_core::StoreError;
use thiserror::Error;

/// Failures of scheduler operations.
#[derive(Debug, Error)]
pub enum SchedulerError {
    /// The repository failed; `StoreError::LeaseLost` means the holder was fenced.
    #[error("storage error: {0}")]
    Store(#[from] StoreError),
}

impl SchedulerError {
    /// Was the lease lost or fenced (the holder must stop writing)?
    #[must_use]
    pub fn is_lease_lost(&self) -> bool {
        matches!(self, Self::Store(StoreError::LeaseLost))
    }
}
