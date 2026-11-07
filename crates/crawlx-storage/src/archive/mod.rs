//! Native offline WARC 1.1 / CDXJ 0.1.0 / WACZ 1.1.1 codecs.
//!
//! Clean-room implementation from versioned normative standards, not upstream crawler code.
//! Inputs are retained approved resources. No network or archived-code execution exists here.

pub mod cdxj;
pub mod collection;
pub mod recorded;
pub mod resolver;
pub mod retained;
pub mod wacz;
pub mod warc;
mod zip_bounds;

use std::io;

/// Hard limits for hostile archive readers and streaming writers.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Limits {
    /// Maximum bytes in one WARC content block or metadata resource.
    pub record_bytes: u64,
    /// Maximum WARC/HTTP header bytes.
    pub header_bytes: u64,
    /// Maximum encoded input/output bytes.
    pub total_bytes: u64,
    /// Maximum cumulative uncompressed bytes.
    pub expanded_bytes: u64,
    /// Maximum record count.
    pub records: u32,
    /// Maximum ZIP resource count.
    pub resources: usize,
    /// Maximum relationship chain depth.
    pub dependency_depth: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            record_bytes: 16_777_216,
            header_bytes: 65_536,
            total_bytes: 1_073_741_824,
            expanded_bytes: 1_073_741_824,
            records: 10_000,
            resources: 128,
            dependency_depth: 32,
        }
    }
}

/// Archive validation or staging failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArchiveError {
    /// File or stream I/O failure, with source chain preserved.
    #[error("archive I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Invalid JSON metadata, with source chain preserved.
    #[error("archive JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Invalid ZIP framing, with source chain preserved.
    #[error("archive ZIP failed: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// Bounded parser refused further work.
    #[error("archive limit exceeded: {0}")]
    Limit(&'static str),
    /// Format or relationship violation. Details intentionally exclude untrusted content.
    #[error("invalid archive: {0}")]
    Invalid(&'static str),
    /// An explicit content capability is absent; callers must disclose the omitted representation.
    #[error("archive capability unavailable: {0}")]
    CapabilityUnavailable(&'static str),
}

/// Reject unsafe ZIP/resource names, including alternate-platform paths.
///
/// # Errors
/// Returns an error for traversal, absolute, control-bearing, or noncanonical paths.
pub fn validate_path(path: &str) -> Result<(), ArchiveError> {
    if path.is_empty()
        || path.len() > 1024
        || path.starts_with('/')
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path.split('/').any(|part| matches!(part, "" | "." | ".."))
    {
        return Err(ArchiveError::Invalid("unsafe resource path"));
    }
    Ok(())
}
