//! Bounded source memoization. Hashes are content-derived metadata, not authorization.
//!
//! Callers check current admission before lookup and record only after frontier append succeeds.
//! A crash between append and recording may repeat a proposal; frontier identity remains authoritative.
use super::DatasetContentV1;
use crate::hash::Digest;
use crate::{CrawlRunId, StoreError, TenantId, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Hard per-run seen-record ceiling, including every source/role/policy scope.
pub const MAX_MEMO_ENTRIES: u32 = 100_000;
/// Hard per-run category representation ceiling.
pub const MAX_CATEGORY_CACHE_ENTRIES: usize = 64;
/// Largest serialized category list; candidates still require current admission.
pub const MAX_CATEGORY_CACHE_BYTES: u64 = 1_048_576;

/// Explicit opt-in article seen ledger. Zero capacity is invalid even when disabled.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArticleMemoPolicyV1 {
    /// Enable repeat suppression after current authorization.
    pub enabled: bool,
    /// Total retained hash-only records per run, across all scopes.
    pub max_entries: u32,
}
impl Default for ArticleMemoPolicyV1 {
    fn default() -> Self {
        Self {
            enabled: false,
            max_entries: 20_000,
        }
    }
}

/// Category caching never grants authority and never extends source retention.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct CategoryCachePolicyV1 {
    /// False bypasses both reads and writes.
    pub enabled: bool,
    /// Worker-clock lifetime in seconds; entries expire exactly at their deadline.
    pub ttl_seconds: u32,
}
impl Default for CategoryCachePolicyV1 {
    fn default() -> Self {
        Self {
            enabled: true,
            ttl_seconds: 86_400,
        }
    }
}

/// Tenant/run/source/role/policy identity. Source and role text never enter durable memo rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct MemoScopeV1 {
    /// Owning tenant, checked against the stored run.
    pub tenant: TenantId,
    /// Run-local purpose; cross-run reuse requires a separate explicit contract.
    pub run: CrawlRunId,
    /// Domain-separated source digest.
    pub source: Digest,
    /// Role/session/request representation digest.
    pub role: Digest,
    /// Complete effective discovery/extraction policy digest.
    pub policy: Digest,
}
impl MemoScopeV1 {
    /// Construct an opaque, explicitly scoped identity.
    #[must_use]
    pub fn new(tenant: TenantId, run: CrawlRunId, source: Digest, role: Digest, policy: Digest) -> Self {
        Self {
            tenant,
            run,
            source,
            role,
            policy,
        }
    }
}

/// Already privacy-approved category list, stored through existing artifact custody.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct CategoryCacheEntryV1 {
    /// Retention-typed artifact reference, never inline category URLs.
    pub content: DatasetContentV1,
    /// Exact serialized length, bounded before allocation.
    pub size_bytes: u64,
    /// Exclusive worker-clock expiry, bounded by the source artifact's deadline.
    pub expires_at: Timestamp,
}
impl CategoryCacheEntryV1 {
    /// Construct a retention-typed reference.
    #[must_use]
    pub fn new(content: DatasetContentV1, size_bytes: u64, expires_at: Timestamp) -> Self {
        Self {
            content,
            size_bytes,
            expires_at,
        }
    }
}

/// Run-scoped memo authority. Implementations store ZDR metadata only in volatile custody.
// async_trait preserves the object-safe repository boundary used by worker and API.
#[async_trait]
pub trait SourceMemoRepo: Send + Sync {
    /// Test an opaque article key after current destination admission.
    ///
    /// # Errors
    /// Returns tenant, run-retention or storage errors.
    async fn seen(&self, scope: &MemoScopeV1, article: Digest, now: Timestamp) -> Result<bool, StoreError>;
    /// Record a successfully appended bounded chunk; evict oldest entries deterministically.
    ///
    /// # Errors
    /// Returns invalid capacity/batch, tenant, retention or storage errors.
    async fn record_seen(
        &self,
        scope: &MemoScopeV1,
        articles: &[Digest],
        max_entries: u32,
        now: Timestamp,
    ) -> Result<(), StoreError>;
    /// Read only the exact source representation under the supplied scope.
    ///
    /// # Errors
    /// Returns tenant, retention or storage errors; elapsed entries return `None`.
    async fn category(
        &self,
        scope: &MemoScopeV1,
        representation: Digest,
        now: Timestamp,
    ) -> Result<Option<CategoryCacheEntryV1>, StoreError>;
    /// Publish an already approved artifact reference without renewing an existing deadline.
    ///
    /// # Errors
    /// Returns invalid size/expiry, artifact ownership, tenant or storage errors.
    async fn cache_category(
        &self,
        scope: &MemoScopeV1,
        representation: Digest,
        entry: CategoryCacheEntryV1,
        now: Timestamp,
    ) -> Result<(), StoreError>;
    /// Explicitly clear every seen/category scope of a tenant-owned run.
    /// This does not remove queued or completed frontier requests or reset their identities.
    ///
    /// # Errors
    /// Returns tenant, retention or storage errors.
    async fn reset(&self, tenant: TenantId, run: CrawlRunId) -> Result<(), StoreError>;
}
