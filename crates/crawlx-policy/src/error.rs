//! Crate error type.

use thiserror::Error;

/// Errors from policy construction and record validation. Policy *decisions*
/// are values ([`crate::ScopeVerdict`], [`crate::EgressDenied`],
/// [`crate::AdmissionError`]), not errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// Scope construction failed (bad include/exclude pattern, no seed host).
    #[error("scope: {0}")]
    Scope(#[from] crawlx_url::UrlError),
    /// An authorization record failed structural validation.
    #[error("invalid authorization record: {0}")]
    InvalidAuthorization(String),
    /// A CIDR string could not be parsed.
    #[error("invalid network {0:?}")]
    InvalidNetwork(String),
    /// The bundled public suffix list could not be loaded (`scope.hostScope: rdn|dn`).
    #[error("public suffix list: {0}")]
    PublicSuffixList(String),
    /// The normalized request could not be digested.
    #[error("digest: {0}")]
    Digest(#[from] crawlx_core::CoreError),
}
