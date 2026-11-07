//! Operator-controlled protocols. No automatic native-network fallback exists.

pub mod file;
pub mod service;
pub mod whois;

use bytes::Bytes;
use url::Url;

/// A protocol resource, not a synthetic HTTP response. Bytes remain retention scoped by the caller.
#[non_exhaustive]
pub struct ProtocolResource {
    /// Actual resource address, if authenticated evidence supplied it.
    pub final_url: Option<Url>,
    /// Actual target status, never the service gateway status.
    pub target_status: Option<u16>,
    /// Optional gateway response status.
    pub gateway_status: Option<u16>,
    /// Ordered authenticated redirect observations, never synthesized.
    pub redirects: Vec<crawlx_core::acquisition::AcquisitionRedirectV1>,
    /// Media type of returned representation.
    pub media_type: Option<String>,
    /// Bounded returned bytes; never serialized into durable metadata.
    pub body: Bytes,
    /// Decoded bytes consumed before mandatory secret removal.
    pub decoded_bytes: usize,
    /// Authorized bounded child resources.
    pub children: Vec<Url>,
    /// Classified local entries refused as resources; not authorized discovery targets.
    pub denied_children: Vec<Url>,
    /// Actual target requests consumed, not the control-plane service request.
    pub network_requests: u32,
    /// Operator-registered immutable build.
    pub build_digest: String,
}
impl std::fmt::Debug for ProtocolResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolResource")
            .field("target_status", &self.target_status)
            .field("gateway_status", &self.gateway_status)
            .field("decoded_bytes", &self.decoded_bytes)
            .field("network_requests", &self.network_requests)
            .finish_non_exhaustive()
    }
}

/// Closed protocol failure, with no secret-bearing response or URLs in messages.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// Missing approved capability or incompatible request.
    #[error("protocol capability unavailable: {0}")]
    CapabilityUnavailable(&'static str),
    /// Boundary validation failed.
    #[error("protocol boundary refused: {0}")]
    Refused(&'static str),
    /// Explicit caller cancellation.
    #[error("protocol acquisition cancelled")]
    Cancelled,
    /// Finite deadline exhausted.
    #[error("protocol acquisition deadline exhausted")]
    Deadline,
    /// Finite byte or discovery budget exhausted.
    #[error("protocol resource limit exceeded")]
    Limit,
    /// Filesystem or socket error.
    #[error("protocol I/O failed")]
    Io(#[from] std::io::Error),
    /// Checked transport failure.
    #[error("protocol transport failed")]
    Fetch(#[from] crate::FetchError),
    /// Service HTTPS or response stream failure.
    #[error("protocol service transport failed")]
    Service(#[source] reqwest::Error),
    /// Malformed bounded service message.
    #[error("protocol service schema failed")]
    Schema(#[source] serde_json::Error),
}
