//! Typed identifiers. All persisted IDs are UUIDv7; runtime
//! handles (`TabId`, `FrameId`, `BackendNodeId`, ...) are never persisted.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

macro_rules! uuid_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// New time-ordered (v7) identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
            /// The wrapped UUID by value.
            #[must_use]
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
        impl From<Uuid> for $name {
            fn from(u: Uuid) -> Self {
                Self(u)
            }
        }
        impl std::str::FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
    };
}

uuid_id!(/// A tenant. 
    TenantId);
uuid_id!(/// An accepted crawl run (`crawl_runs`).
    CrawlRunId);
uuid_id!(/// A role/browser session slot (`crawl_sessions`).
    SessionId);
uuid_id!(/// An executed or proposed browser action (`actions`); the idempotency boundary.
    ActionId);
uuid_id!(/// An immutable observation (`states`).
    StateId);
uuid_id!(/// A derived state cluster (`state_clusters`).
    StateClusterId);
uuid_id!(/// A `transitions` row.
    TransitionId);
uuid_id!(/// A `network_epochs` row.
    NetworkEpochId);
uuid_id!(/// A `safety_decisions` row.
    SafetyDecisionId);
uuid_id!(/// A `model_decisions` row.
    ModelDecisionId);
uuid_id!(/// An `approvals` row.
    ApprovalId);
uuid_id!(/// A `checkpoints` row.
    CheckpointId);
uuid_id!(/// An `artifacts` row.
    ArtifactId);
uuid_id!(/// A `workflow_runs` row.
    WorkflowRunId);
uuid_id!(/// An `enablement_edges` row.
    EdgeId);
uuid_id!(/// A worker process.
    WorkerId);
uuid_id!(/// An authorization record (`authorization_records`).
    AuthorizationRecordId);

/// A 128-bit trace identifier in W3C `trace-id` form (32 lowercase hex digits).
///
/// Minted once per span tree by `crawlx-telemetry`'s trace layer and copied onto the
/// `crawl_runs` and `actions` rows written under that tree (the span-to-row join).
/// A trace id is never all zeros (the W3C invalid value).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TraceId(pub [u8; 16]);

impl TraceId {
    /// A fresh trace id: the bytes of a time-ordered UUIDv7 (48-bit timestamp plus 74 random
    /// bits), so trace ids sort by creation time like every other persisted id.
    #[must_use]
    pub fn new() -> Self {
        Self(*Uuid::now_v7().as_bytes())
    }

    /// Lowercase 32-hex-digit form.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl Default for TraceId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TraceId({})", self.to_hex())
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<TraceId> for String {
    fn from(id: TraceId) -> Self {
        id.to_hex()
    }
}

/// Why a string is not a trace id.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum TraceIdError {
    /// Not exactly 32 hex digits.
    #[error("trace id must be 32 hex digits, got {0:?}")]
    Malformed(String),
    /// The all-zero value, which W3C defines as invalid.
    #[error("trace id must not be all zeros")]
    Zero,
}

impl std::str::FromStr for TraceId {
    type Err = TraceIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TraceIdError::Malformed(s.to_owned()));
        }
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| TraceIdError::Malformed(s.to_owned()))?;
        }
        if out == [0u8; 16] {
            return Err(TraceIdError::Zero);
        }
        Ok(Self(out))
    }
}

impl TryFrom<String> for TraceId {
    type Error = TraceIdError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

/// A principal (role) running a session. Stored as the declared role name.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    /// The unauthenticated principal.
    #[must_use]
    pub fn anonymous() -> Self {
        Self("anonymous".to_owned())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Runtime handle for a browser tab (target). Never persisted.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TabId(pub String);

/// Runtime handle for a frame. Never persisted.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct FrameId(pub String);

/// CDP `DOM.BackendNodeId`. Never persisted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BackendNodeId(pub i64);

/// CDP `Runtime.RemoteObjectId`. Never persisted.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RemoteObjectId(pub String);

/// CDP `Accessibility.AXNodeId`. Never persisted.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AxNodeId(pub String);

/// Reference to an object-store artifact: `(artifact id, blake3 digest)`.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct ArtifactRef {
    /// Artifact identifier in the object store.
    pub id: ArtifactId,
    /// BLAKE3 digest of the artifact bytes, for integrity checks.
    pub digest: crate::hash::Digest,
}

/// Identifier of a fixture file that may be uploaded through a file input.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct FixtureFileId(pub String);

/// A deterministic 8-byte id for an `ActionContextKey`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionContextId(pub [u8; 16]);

impl fmt::Debug for ActionContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActionContextId({})", self)
    }
}

impl fmt::Display for ActionContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
