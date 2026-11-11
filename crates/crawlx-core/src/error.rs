//! Typed errors shared by several crates. Library crates never use `anyhow`.
//!
//! Every public error enum of the workspace implements [`Classify`] so schedulers and
//! supervisors branch on an [`ErrorClass`] instead of matching message text.

use thiserror::Error;

/// How a caller may react to an error.
///
/// `OutcomeUnknown` exists so a timeout or transport loss while an effect may already have
/// landed (a CDP command during `perform`, a database statement after intent) is never
/// mapped to `Retryable`; the outcome is recorded as unknown instead.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum ErrorClass {
    /// Transient; a bounded retry of the same operation may succeed.
    Retryable,
    /// Permanent for this input; retrying the same operation cannot succeed.
    Terminal,
    /// The operation may or may not have taken effect; reconcile before retrying.
    OutcomeUnknown,
    /// A policy, profile or safety rule refused the operation; retrying is pointless and
    /// the refusal is itself the result.
    PolicyDenied,
    /// The caller's view (locator, epoch, lease) is out of date; re-observe, then decide.
    Stale,
}

/// Exposes the [`ErrorClass`] of an error value.
pub trait Classify {
    /// The class a scheduler or supervisor should branch on.
    fn class(&self) -> ErrorClass;
}

impl Classify for std::io::Error {
    fn class(&self) -> ErrorClass {
        use std::io::ErrorKind;
        match self.kind() {
            ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionRefused
            | ErrorKind::NotConnected
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof => ErrorClass::Retryable,
            _ => ErrorClass::Terminal,
        }
    }
}

/// Errors from core value-type operations and validation.
#[derive(Debug, Error)]
pub enum CoreError {
    /// A string did not match any variant of an enum when parsing a stored or wire value.
    #[error("unknown {kind} value {value:?}")]
    UnknownEnum {
        /// Name of the enum type being parsed, e.g. `RunStatus`.
        kind: &'static str,
        /// The unrecognised input text.
        value: String,
    },
    /// A field failed validation.
    #[error("invalid {field}: {reason}")]
    Invalid {
        /// Name of the offending field.
        field: &'static str,
        /// Human-readable explanation of why the value is rejected.
        reason: String,
    },
    /// A field that is optional in general is mandatory in a particular context.
    #[error("{field} is required for {context}")]
    Required {
        /// Name of the missing field.
        field: &'static str,
        /// The mode or feature that makes the field mandatory.
        context: &'static str,
    },
    /// Two settings cannot be combined.
    #[error("{a} conflicts with {b}: {reason}")]
    Conflict {
        /// Name of the first setting.
        a: &'static str,
        /// Name of the second setting.
        b: &'static str,
        /// Why the two cannot coexist.
        reason: String,
    },
    /// A credential reference could not be turned into a secret value; carries the reference or cause.
    #[error("credential reference could not be resolved: {0}")]
    CredentialUnavailable(String),
    /// Encoding or decoding a value (JSON, CBOR) failed; carries the underlying error text.
    #[error("serialization failed: {0}")]
    Serialization(String),
}

impl CoreError {
    /// Stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownEnum { .. } => "unknown_enum",
            Self::Invalid { .. } => "invalid_pattern",
            Self::Required { .. } => "required",
            Self::Conflict { .. } => "profile_conflict",
            Self::CredentialUnavailable(_) => "credential_unavailable",
            Self::Serialization(_) => "serialization",
        }
    }
}

impl Classify for CoreError {
    fn class(&self) -> ErrorClass {
        match self {
            Self::UnknownEnum { .. }
            | Self::Invalid { .. }
            | Self::Required { .. }
            | Self::Conflict { .. }
            | Self::Serialization(_) => ErrorClass::Terminal,
            Self::CredentialUnavailable(_) => ErrorClass::PolicyDenied,
        }
    }
}

/// Errors from repositories (implemented by `crawlx-storage`).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// No row exists for the requested entity.
    #[error("not found: {entity} {id}")]
    NotFound {
        /// Kind of entity looked up, e.g. `crawl_run`.
        entity: &'static str,
        /// Identifier that was looked up.
        id: String,
    },
    /// The write conflicts with existing state (duplicate key, concurrent update); carries the detail.
    #[error("conflict: {0}")]
    Conflict(String),
    /// A status change is not allowed by the status state machine.
    #[error("illegal status transition {from} -> {to}")]
    IllegalTransition {
        /// Current status, as its stored string.
        from: String,
        /// Requested status, as its stored string.
        to: String,
    },
    /// The caller's lease expired or was taken over by a newer holder, so its write was fenced off.
    #[error("lease lost or fenced")]
    LeaseLost,
    /// The storage backend cannot be reached right now; carries the cause. Retryable.
    #[error("storage unavailable: {0}")]
    Unavailable(String),
    /// A shared byte reservation or fallible output allocation cannot admit more data.
    #[error("resource exhausted: {resource} ({requested} bytes requested, {available} available)")]
    ResourceExhausted {
        /// Stable resource name, never document content or a URL.
        resource: &'static str,
        /// Requested reservation or allocation size.
        requested: usize,
        /// Remaining reservation bytes or current output capacity.
        available: usize,
        /// Original allocation failure, absent for admission pressure.
        #[source]
        source: Option<std::collections::TryReserveError>,
    },
    /// The retention policy forbids storing this data; carries what was refused.
    #[error("retention policy forbids this write: {0}")]
    RetentionDenied(String),
    /// The access rule for this data forbids the requested read path (e.g. a presigned URL for a
    /// `sensitive` artifact); carries what was refused.
    #[error("access denied: {0}")]
    AccessDenied(String),
    /// The run's fixed deadline closed request admission during an in-flight acquisition.
    #[error("run deadline reached")]
    RunDeadlineReached,
    /// Encoding or decoding a stored value failed; carries the underlying error text.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// The storage backend reported an error not covered by the other variants; carries its text. Retryable.
    #[error("storage backend error: {0}")]
    Backend(String),
    /// A database driver failure, retaining its original error chain.
    #[error("database operation failed")]
    Database {
        /// Original driver error, available for diagnostics through `Error::source`.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// Whether a bounded retry may resolve this failure.
        retryable: bool,
    },
}

impl StoreError {
    /// Transient failures that a bounded retry may resolve.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Unavailable(_)
                | Self::ResourceExhausted { .. }
                | Self::Backend(_)
                | Self::Database { retryable: true, .. }
        )
    }
}

impl Classify for StoreError {
    fn class(&self) -> ErrorClass {
        match self {
            Self::NotFound { .. }
            | Self::IllegalTransition { .. }
            | Self::Serialization(_)
            | Self::Database { retryable: false, .. } => ErrorClass::Terminal,
            Self::Conflict(_) | Self::LeaseLost => ErrorClass::Stale,
            Self::Unavailable(_)
            | Self::ResourceExhausted { .. }
            | Self::Backend(_)
            | Self::Database { retryable: true, .. } => ErrorClass::Retryable,
            Self::RetentionDenied(_) | Self::AccessDenied(_) | Self::RunDeadlineReached => {
                ErrorClass::PolicyDenied
            }
        }
    }
}

impl From<ciborium::ser::Error<std::io::Error>> for CoreError {
    fn from(e: ciborium::ser::Error<std::io::Error>) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for CoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn io(kind: std::io::ErrorKind) -> std::io::Error {
        std::io::Error::new(kind, "x")
    }

    /// Every variant of every error enum defined here maps to a class.
    #[test]
    fn every_core_and_store_variant_maps_to_a_class() {
        let core: Vec<(CoreError, ErrorClass)> = vec![
            (
                CoreError::UnknownEnum {
                    kind: "k",
                    value: "v".to_owned(),
                },
                ErrorClass::Terminal,
            ),
            (
                CoreError::Invalid {
                    field: "f",
                    reason: "r".to_owned(),
                },
                ErrorClass::Terminal,
            ),
            (
                CoreError::Required {
                    field: "f",
                    context: "c",
                },
                ErrorClass::Terminal,
            ),
            (
                CoreError::Conflict {
                    a: "a",
                    b: "b",
                    reason: "r".to_owned(),
                },
                ErrorClass::Terminal,
            ),
            (
                CoreError::CredentialUnavailable("c".to_owned()),
                ErrorClass::PolicyDenied,
            ),
            (CoreError::Serialization("s".to_owned()), ErrorClass::Terminal),
        ];
        for (e, want) in &core {
            assert_eq!(e.class(), *want, "{e}");
        }
        let store: Vec<(StoreError, ErrorClass)> = vec![
            (
                StoreError::NotFound {
                    entity: "e",
                    id: "i".to_owned(),
                },
                ErrorClass::Terminal,
            ),
            (StoreError::Conflict("c".to_owned()), ErrorClass::Stale),
            (
                StoreError::IllegalTransition {
                    from: "a".to_owned(),
                    to: "b".to_owned(),
                },
                ErrorClass::Terminal,
            ),
            (StoreError::LeaseLost, ErrorClass::Stale),
            (StoreError::Unavailable("u".to_owned()), ErrorClass::Retryable),
            (
                StoreError::ResourceExhausted {
                    resource: "article_output_reservation",
                    requested: 16,
                    available: 8,
                    source: None,
                },
                ErrorClass::Retryable,
            ),
            (
                StoreError::RetentionDenied("r".to_owned()),
                ErrorClass::PolicyDenied,
            ),
            (StoreError::AccessDenied("a".to_owned()), ErrorClass::PolicyDenied),
            (StoreError::Serialization("s".to_owned()), ErrorClass::Terminal),
            (StoreError::Backend("b".to_owned()), ErrorClass::Retryable),
            (
                StoreError::Database {
                    source: Box::new(io(std::io::ErrorKind::Other)),
                    retryable: true,
                },
                ErrorClass::Retryable,
            ),
            (
                StoreError::Database {
                    source: Box::new(io(std::io::ErrorKind::Other)),
                    retryable: false,
                },
                ErrorClass::Terminal,
            ),
        ];
        for (e, want) in &store {
            assert_eq!(e.class(), *want, "{e}");
            assert_eq!(e.is_retryable(), *want == ErrorClass::Retryable, "{e}");
        }
        assert_eq!(io(std::io::ErrorKind::TimedOut).class(), ErrorClass::Retryable);
        assert_eq!(io(std::io::ErrorKind::NotFound).class(), ErrorClass::Terminal);
    }

    /// CDP timeouts and transport loss are `OutcomeUnknown`, never `Retryable`.
    #[test]
    fn every_browser_variant_maps_to_a_class() {
        use crate::browser::BrowserError as B;
        let table: Vec<(B, ErrorClass)> = vec![
            (B::Launch("l".to_owned()), ErrorClass::Retryable),
            (
                B::PinMismatch {
                    expected: "a".to_owned(),
                    actual: "b".to_owned(),
                },
                ErrorClass::Terminal,
            ),
            (B::Transport("t".to_owned()), ErrorClass::OutcomeUnknown),
            (
                B::Protocol {
                    method: "m".to_owned(),
                    message: "x".to_owned(),
                },
                ErrorClass::Terminal,
            ),
            (B::TargetCrashed, ErrorClass::Retryable),
            (B::TargetClosed, ErrorClass::Retryable),
            (B::Navigation("n".to_owned()), ErrorClass::Retryable),
            (B::EgressDenied("e".to_owned()), ErrorClass::PolicyDenied),
            (
                B::StaleLocator(crate::epoch::ObservationEpoch::default()),
                ErrorClass::Stale,
            ),
            (B::Unsupported("u".to_owned()), ErrorClass::PolicyDenied),
            (B::Timeout(30_000), ErrorClass::OutcomeUnknown),
            (B::TabLimit(3), ErrorClass::PolicyDenied),
            (B::Script("s".to_owned()), ErrorClass::Terminal),
            (B::Io("i".to_owned()), ErrorClass::Terminal),
        ];
        for (e, want) in &table {
            assert_eq!(e.class(), *want, "{e}");
        }
        assert_ne!(B::Timeout(1).class(), ErrorClass::Retryable);
    }
}
