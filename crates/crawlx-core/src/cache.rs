//! Principal-scoped response caching, offline development replay and selector retention.

use crate::hash::Digest;
use crate::selectors::{AdaptiveSelectorSpecV1, SelectorScopeV1};
use crate::{CoreError, CrawlRunId, StoreError, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Explicit native cache behavior. Bypass permits writes; disabled permits neither.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheModeV1 {
    /// Read matching fresh entries and write successful acquisitions.
    #[default]
    ReadWrite,
    /// Never read; permit successful acquisition writes.
    Bypass,
    /// Neither read nor write reusable entries.
    Disabled,
    /// Read only. A miss never dispatches a network request.
    ReadOnly,
    /// Never read; write successful acquisitions.
    WriteOnly,
}

/// Optional validator exchange under the parent acquisition allowance.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacheFreshnessV1 {
    /// Use age and retained-body checks without network I/O.
    #[default]
    Retained,
    /// HEAD must repeat a matching ETag or Last-Modified value.
    Head,
    /// Conditional GET must return 304 for the matching retained body.
    ConditionalGet,
}

/// Native cache controls. Absence preserves facade cache semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct CachePolicyV1 {
    /// Supported layout, exactly one.
    pub schema_version: u8,
    /// Explicit read/write behavior.
    pub mode: CacheModeV1,
    /// Maximum retained response age in milliseconds.
    pub max_age_ms: u64,
    /// Offline artifact replay, distinct from action replay; never fetches or writes.
    pub development_replay: bool,
    /// Optional live validation. Read-only and replay never dispatch these exchanges.
    pub freshness: CacheFreshnessV1,
}
impl Default for CachePolicyV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: CacheModeV1::ReadWrite,
            max_age_ms: 172_800_000,
            development_replay: false,
            freshness: CacheFreshnessV1::Retained,
        }
    }
}
impl CachePolicyV1 {
    /// Validate schema and finite retention-age bounds at admission.
    /// # Errors
    /// Returns invalid cache policy for unsupported versions or ages beyond one year.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.schema_version != 1 || self.max_age_ms > 31_536_000_000 {
            return Err(CoreError::Invalid {
                field: "cache",
                reason: "unsupported schema or cache age exceeds one year".into(),
            });
        }
        Ok(())
    }
    /// Whether this policy permits a stored response read.
    #[must_use]
    pub fn reads(&self) -> bool {
        self.schema_version == 1
            && (self.development_replay
                || matches!(self.mode, CacheModeV1::ReadWrite | CacheModeV1::ReadOnly))
    }
    /// Whether this policy permits a reusable response write.
    #[must_use]
    pub fn writes(&self) -> bool {
        self.schema_version == 1
            && !self.development_replay
            && matches!(
                self.mode,
                CacheModeV1::ReadWrite | CacheModeV1::Bypass | CacheModeV1::WriteOnly
            )
    }
    /// Whether a miss must stop before network I/O.
    #[must_use]
    pub fn cache_only(&self) -> bool {
        self.development_replay || self.mode == CacheModeV1::ReadOnly
    }
}

/// Versioned identity of bytes reusable by a single authenticated principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CacheKeyV1 {
    /// Trusted API-key principal, or an isolated local run identifier.
    pub principal: String,
    /// Full acquisition and validation policy digest.
    pub acquisition_profile: Digest,
    /// Actual registered implementation revision, not a user-supplied version.
    pub backend_capability: String,
    /// Validation rule-set revision.
    pub validator_version: u8,
    /// Wire response versus rendered DOM.
    pub representation: String,
    /// Request options, including headers and session/profile identity.
    pub request_identity: Digest,
}
impl CacheKeyV1 {
    /// Construct a key from trusted execution facts.
    #[must_use]
    pub fn new(
        principal: String,
        acquisition_profile: Digest,
        backend_capability: String,
        validator_version: u8,
        representation: String,
        request_identity: Digest,
    ) -> Self {
        Self {
            principal,
            acquisition_profile,
            backend_capability,
            validator_version,
            representation,
            request_identity,
        }
    }
    /// Domain-separated digest; serialization consists only of infallible primitive fields.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let encoded = serde_json::to_vec(self).unwrap_or_default();
        Digest::of("crawlx/response-cache/v1", &encoded)
    }
}

/// Tenant-keyed correlation over resolved credential controls. Raw values never leave this helper.
///
/// # Errors
/// Returns serialization errors without including credential bytes.
pub fn credential_digest(
    root: &[u8; 32],
    tenant: crate::TenantId,
    controls: &crate::request_controls::RequestControls,
) -> Result<Digest, CoreError> {
    use zeroize::Zeroize;
    let mut tenant_key = Digest::keyed(root, "crawlx/tenant-request-key/v1", tenant.0.as_bytes()).0;
    let headers: Vec<_> = controls
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str(), value.expose().as_str()))
        .collect();
    let mut cookies: Vec<_> = controls
        .cookies()
        .iter()
        .map(|c| {
            (
                c.domain.as_str(),
                c.path.as_str(),
                c.name.as_str(),
                c.value.expose().as_str(),
            )
        })
        .collect();
    cookies.sort_unstable();
    let mut encoded = serde_json::to_vec(&(1u8, headers, cookies))
        .map_err(|_| CoreError::Serialization("credential identity serialization failed".into()))?;
    let digest = Digest::keyed(&tenant_key, "crawlx/credential-request-identity/v1", &encoded);
    encoded.zeroize();
    tenant_key.zeroize();
    Ok(digest)
}

/// A sanitized selector descriptor tied to a retained source run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdaptiveSelectorRecordV1 {
    /// Source run, used for authorization, retention and purge.
    pub run: CrawlRunId,
    /// Pure descriptor and caller-owned authority namespace.
    pub spec: AdaptiveSelectorSpecV1,
    /// Fixed expiry, never later than source run retention.
    pub expires_at: Timestamp,
}
impl AdaptiveSelectorRecordV1 {
    /// Construct a descriptor record; the repository enforces ownership and retention.
    #[must_use]
    pub fn new(run: CrawlRunId, spec: AdaptiveSelectorSpecV1, expires_at: Timestamp) -> Self {
        Self {
            run,
            spec,
            expires_at,
        }
    }
}

/// Scoped descriptor persistence. ZDR implementations use only shared volatile delivery.
#[async_trait]
pub trait AdaptiveSelectorRepo: Send + Sync {
    /// Save a bounded descriptor under its authenticated scope.
    /// # Errors
    /// Returns invalid descriptor, ownership, retention or storage errors.
    async fn put(&self, record: &AdaptiveSelectorRecordV1) -> Result<(), StoreError>;
    /// Read one exact scope and identifier, excluding expired or purged source runs.
    /// # Errors
    /// Returns ownership or storage errors; absence is not a relocation success.
    async fn get(
        &self,
        scope: &SelectorScopeV1,
        selector_id: &str,
        now: Timestamp,
    ) -> Result<Option<AdaptiveSelectorRecordV1>, StoreError>;
    /// Delete all descriptors of a purged run.
    /// # Errors
    /// Returns storage failures.
    async fn delete_run(&self, run: CrawlRunId) -> Result<(), StoreError>;
    /// Delete expired descriptors.
    /// # Errors
    /// Returns storage failures.
    async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn modes_have_explicit_read_write_and_offline_semantics() {
        for (mode, reads, writes, offline) in [
            (CacheModeV1::ReadWrite, true, true, false),
            (CacheModeV1::Bypass, false, true, false),
            (CacheModeV1::Disabled, false, false, false),
            (CacheModeV1::ReadOnly, true, false, true),
            (CacheModeV1::WriteOnly, false, true, false),
        ] {
            let p = CachePolicyV1 {
                mode,
                ..CachePolicyV1::default()
            };
            assert_eq!((p.reads(), p.writes(), p.cache_only()), (reads, writes, offline));
        }
        let p = CachePolicyV1 {
            development_replay: true,
            ..CachePolicyV1::default()
        };
        assert!(p.reads() && p.cache_only() && !p.writes());
    }
    #[test]
    fn principal_backend_validator_and_representation_never_share_keys() {
        let key = CacheKeyV1::new(
            "alice".into(),
            Digest::of("test", b"profile"),
            "http-1".into(),
            1,
            "wire_response".into(),
            Digest::of("test", b"request"),
        );
        let mut changed = key.clone();
        changed.principal = "bob".into();
        assert_ne!(key.digest(), changed.digest());
        changed = key.clone();
        changed.backend_capability = "http-2".into();
        assert_ne!(key.digest(), changed.digest());
        changed = key.clone();
        changed.validator_version = 2;
        assert_ne!(key.digest(), changed.digest());
        changed = key.clone();
        changed.representation = "rendered_dom".into();
        assert_ne!(key.digest(), changed.digest());
    }
    #[tokio::test]
    async fn resolved_credentials_are_tenant_keyed_and_order_stable() {
        let tenant = crate::TenantId(uuid::Uuid::from_u128(1));
        let other = crate::TenantId(uuid::Uuid::from_u128(2));
        let mut fetch = crate::config::Fetch::default();
        fetch.extra_headers.insert("x-token", "credential-canary-value");
        fetch.extra_headers.insert("authorization", "Bearer example");
        let controls = crate::request_controls::RequestControls::resolve(&fetch, "example.test", None)
            .await
            .unwrap();
        let digest = credential_digest(&[7; 32], tenant, &controls).unwrap();
        assert_ne!(digest, credential_digest(&[7; 32], other, &controls).unwrap());
        assert_ne!(digest, credential_digest(&[8; 32], tenant, &controls).unwrap());
        let mut reordered = crate::config::Fetch::default();
        reordered.extra_headers.insert("authorization", "Bearer example");
        reordered
            .extra_headers
            .insert("x-token", "credential-canary-value");
        let controls = crate::request_controls::RequestControls::resolve(&reordered, "example.test", None)
            .await
            .unwrap();
        assert_eq!(digest, credential_digest(&[7; 32], tenant, &controls).unwrap());
        let mut changed = reordered;
        changed.extra_headers.insert("x-token", "changed-credential");
        let controls = crate::request_controls::RequestControls::resolve(&changed, "example.test", None)
            .await
            .unwrap();
        assert_ne!(digest, credential_digest(&[7; 32], tenant, &controls).unwrap());
    }
}
