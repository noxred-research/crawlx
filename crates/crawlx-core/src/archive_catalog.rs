//! Tenant-scoped durable archive catalog and validator-compatible payload history.
//!
//! Catalog rows contain content-bearing metadata and inherit source retention. A published
//! manifest is the commit point; records are indexed only after their shard objects commit.

use crate::archive::{ArchiveCaptureFactsV1, ArchiveConfigV1, ArchiveManifestV1};
use crate::{ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One persisted chronological traffic descriptor, without body bytes or reconstructed headers.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ArchiveTrafficV1 {
    /// Stable persisted event ordinal.
    pub event_id: u64,
    /// Retained sanitized target, if present.
    pub url: Option<String>,
    /// Actual recorded request start time.
    pub captured_at: Timestamp,
    /// Approved retained request body, if present.
    pub request_body: Option<ArtifactRef>,
    /// Approved retained response body, if present.
    pub response_body: Option<ArtifactRef>,
}
impl ArchiveTrafficV1 {
    /// Project existing persisted capture custody; absent evidence remains absent.
    #[must_use]
    pub fn new(
        event_id: u64,
        url: Option<String>,
        captured_at: Timestamp,
        request_body: Option<ArtifactRef>,
        response_body: Option<ArtifactRef>,
    ) -> Self {
        Self {
            event_id,
            url,
            captured_at,
            request_body,
            response_body,
        }
    }
}

/// Durable export lifecycle. Deletion is a permanent tombstone, never a resumable job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveExportState {
    /// Committed intent, eligible for fenced recovery.
    Recording,
    /// Final object and manifest committed, readable.
    Published,
    /// A permanent capture/codec limit prevented publication; no download is available.
    Failed,
    /// Explicitly erased together with dependent exports.
    Deleted,
}

/// Privacy-safe terminal export failure, never a raw backend error message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArchiveFailureV1 {
    /// No approved resource survived capture/retention policy.
    CaptureUnavailable,
    /// A configured resource, record or encoded-package bound was exceeded.
    LimitExceeded,
    /// Capture, framing or integrity failed validation.
    InvalidCapture,
}

/// One logical export per tenant/run. IDs remain stable across worker recovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveExportV1 {
    /// Stable export identity.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Retained source run.
    pub run: CrawlRunId,
    /// Bounded codec settings persisted at admission.
    pub config: ArchiveConfigV1,
    /// Current durable state.
    pub state: ArchiveExportState,
    /// Actual source creation time.
    pub created_at: Timestamp,
    /// Source expiry, never extended by packaging or recovery.
    pub expires_at: Option<Timestamp>,
    /// Monotonically increasing writer fence.
    pub fence: i64,
    /// Writer lease deadline; renewed by every record commit.
    pub lease_until: Timestamp,
    /// Count of committed logical resource records.
    pub records: u64,
    /// Total committed compressed shard bytes.
    pub bytes: u64,
    /// Final artifact; absent until publication.
    pub artifact: Option<ArtifactRef>,
    /// Adjacent CDXJ for a WARC export; WACZ stores its index inside the package.
    pub index: Option<ArtifactRef>,
    /// Truthful final capture manifest; absent until publication.
    pub manifest: Option<ArchiveManifestV1>,
    /// Persisted terminal decision; recovery cannot infer completion from missing sessions.
    pub terminal_reason: crate::counters::TerminalReason,
    /// Terminal failure detail; never includes source URLs, payload or credentials.
    pub failure: Option<ArchiveFailureV1>,
}

impl ArchiveExportV1 {
    /// Construct a persisted finalization intent. The run UUID provides its stable identity.
    #[must_use]
    pub fn pending(
        tenant: TenantId,
        run: CrawlRunId,
        config: ArchiveConfigV1,
        created_at: Timestamp,
        expires_at: Option<Timestamp>,
        terminal_reason: crate::counters::TerminalReason,
    ) -> Self {
        Self {
            id: run.0,
            tenant,
            run,
            config,
            state: ArchiveExportState::Recording,
            created_at,
            expires_at,
            fence: 0,
            lease_until: created_at,
            records: 0,
            bytes: 0,
            artifact: None,
            index: None,
            manifest: None,
            terminal_reason,
            failure: None,
        }
    }
}

/// Committed gzip member and the exact retained representation it contains.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveRecordV1 {
    /// Export owning the record.
    pub export: Uuid,
    /// Persisted event ordinal; idempotency key, not a payload-deduplication key.
    pub ordinal: u64,
    /// WARC record ID, stable across retries.
    pub record_id: String,
    /// Actual committed shard artifact.
    pub artifact: ArtifactRef,
    /// Actual member offset inside that shard.
    pub offset: u64,
    /// Actual compressed gzip member length.
    pub length: u64,
    /// SHA-256 of the approved stored representation, not original wire bytes.
    pub payload_digest: String,
    /// Sanitized searchable target, under content retention.
    pub target: String,
    /// Persisted capture owner facts.
    pub facts: ArchiveCaptureFactsV1,
    /// MIME type of approved bytes.
    pub mime: String,
    /// Optional resolvable revisit dependency.
    pub dependency: Option<ArchiveDependencyV1>,
}

impl ArchiveRecordV1 {
    /// Construct a committed standalone resource. Revisit dependencies require explicit opt-in.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn resource(
        export: Uuid,
        ordinal: u64,
        record_id: String,
        artifact: ArtifactRef,
        offset: u64,
        length: u64,
        payload_digest: String,
        target: String,
        facts: ArchiveCaptureFactsV1,
        mime: String,
    ) -> Self {
        Self {
            export,
            ordinal,
            record_id,
            artifact,
            offset,
            length,
            payload_digest,
            target,
            facts,
            mime,
            dependency: None,
        }
    }
}

/// Reference to a committed source record; never crosses a tenant or retention domain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveDependencyV1 {
    /// Published source export.
    pub export: Uuid,
    /// Source record ordinal.
    pub ordinal: u64,
}

impl ArchiveDependencyV1 {
    /// Point to one committed source record.
    #[must_use]
    pub const fn new(export: Uuid, ordinal: u64) -> Self {
        Self { export, ordinal }
    }
}

/// Exact conditional-fetch identity. Unknown principals/variants must not use history.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveHistoryKeyV1 {
    /// Sanitized canonical target.
    pub target: String,
    /// Original request method.
    pub method: String,
    /// Scheduler-owned principal identity, not page metadata.
    pub principal: String,
    /// Authorization and Vary representation digest.
    pub variant: String,
    /// Redaction/retention policy revision.
    pub policy: String,
}

impl ArchiveHistoryKeyV1 {
    /// Construct an exact identity; callers must preserve authorization and Vary context.
    #[must_use]
    pub fn new(target: String, method: String, principal: String, variant: String, policy: String) -> Self {
        Self {
            target,
            method,
            principal,
            variant,
            policy,
        }
    }
}

/// Validator facts only become eligible after the referenced export publishes.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveHistoryV1 {
    /// Exact identity under which validators were captured.
    pub key: ArchiveHistoryKeyV1,
    /// Committed baseline record.
    pub source: ArchiveDependencyV1,
    /// Captured ETag, if any.
    pub etag: Option<String>,
    /// Captured Last-Modified, if any.
    pub last_modified: Option<String>,
    /// Actual capture time.
    pub captured_at: Timestamp,
    /// Sorted captured Vary names. Wildcard or unknown contexts are never eligible.
    #[serde(default)]
    pub vary: Vec<String>,
}

impl ArchiveHistoryV1 {
    /// Construct captured history without inferring absent validators.
    #[must_use]
    pub fn new(
        key: ArchiveHistoryKeyV1,
        source: ArchiveDependencyV1,
        etag: Option<String>,
        last_modified: Option<String>,
        captured_at: Timestamp,
    ) -> Self {
        Self {
            key,
            source,
            etag,
            last_modified,
            captured_at,
            vary: Vec::new(),
        }
    }
}

/// Expiry remains distinguishable from an unknown or foreign export.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ArchiveReadV1 {
    /// Unknown, deleted or foreign identity.
    Missing,
    /// Source retention elapsed; no content-bearing row is returned.
    Expired,
    /// Visible retained export.
    Available(Box<ArchiveExportV1>),
}

/// Tenant-scoped archive operations. All writes reject ZDR and expired source runs.
///
/// Implementations serialize claims, commits, publication and cascading erasure. A fence
/// expires after 120 seconds; a paused writer cannot mutate a recovered/deleted export.
#[async_trait]
pub trait ArchiveRepo: Send + Sync {
    /// Persist finalization intent idempotently. Refuse policy changes on recovery.
    async fn begin(&self, export: &ArchiveExportV1) -> Result<(), StoreError>;
    /// Claim or recover an expired writer lease. Returns no claim if published or held.
    async fn claim(
        &self,
        tenant: TenantId,
        export: Uuid,
        now: Timestamp,
    ) -> Result<Option<ArchiveExportV1>, StoreError>;
    /// Tenant-scoped typed read, preserving expired versus missing semantics.
    async fn get(&self, tenant: TenantId, export: Uuid, now: Timestamp) -> Result<ArchiveReadV1, StoreError>;
    /// At most 100 exports of a run, newest first. Expired rows are excluded.
    async fn list(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        now: Timestamp,
    ) -> Result<Vec<ArchiveExportV1>, StoreError>;
    /// Commit one actual shard descriptor, atomically advancing counters. Same ordinal is idempotent.
    async fn commit_record(
        &self,
        tenant: TenantId,
        fence: i64,
        record: &ArchiveRecordV1,
        history: Option<&ArchiveHistoryV1>,
        now: Timestamp,
    ) -> Result<(), StoreError>;
    /// Bounded keyset projection, limited to 64 descriptors. Deleted exports have no records.
    async fn records(
        &self,
        tenant: TenantId,
        export: Uuid,
        after: Option<u64>,
        limit: u32,
        now: Timestamp,
    ) -> Result<Vec<ArchiveRecordV1>, StoreError>;
    /// Publish manifest last after all referenced artifact objects commit.
    #[allow(
        clippy::too_many_arguments,
        reason = "publication requires distinct fencing, artifact, and manifest inputs"
    )]
    async fn publish(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        artifact: &ArtifactRef,
        index: Option<&ArtifactRef>,
        manifest: &ArchiveManifestV1,
        now: Timestamp,
    ) -> Result<(), StoreError>;
    /// Match only a live published baseline with exact method/principal/variant/policy and validators.
    async fn history(
        &self,
        tenant: TenantId,
        key: &ArchiveHistoryKeyV1,
        now: Timestamp,
    ) -> Result<Option<ArchiveHistoryV1>, StoreError>;
    /// Permanently tombstone this export and all transitive dependents before object erasure.
    async fn erase(&self, tenant: TenantId, export: Uuid) -> Result<(), StoreError>;
    /// Renew the current writer without changing logical record counts.
    async fn renew(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        now: Timestamp,
    ) -> Result<(), StoreError>;
    /// Whether an archive artifact belongs to a retained published export.
    async fn artifact_visible(
        &self,
        tenant: TenantId,
        artifact: &ArtifactRef,
        now: Timestamp,
    ) -> Result<bool, StoreError>;
    /// At most 64 artifact uses awaiting physical erasure after cascading tombstones.
    async fn erased_artifacts(&self, tenant: TenantId, limit: u32) -> Result<Vec<ArtifactRef>, StoreError>;
    /// Remove a tombstoned reference only after the object sink acknowledges erasure.
    async fn acknowledge_erased(&self, tenant: TenantId, artifact: &ArtifactRef) -> Result<(), StoreError>;
    /// Worker-authority recovery scan, at most 64 finalization intents whose run is not terminal.
    /// Authenticated tenant-scoped callers cannot use this cross-tenant maintenance operation.
    async fn recoverable(&self, now: Timestamp, limit: u32) -> Result<Vec<ArchiveExportV1>, StoreError>;
    /// Fail the current writer permanently without publishing a partial package.
    async fn fail(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        failure: ArchiveFailureV1,
        now: Timestamp,
    ) -> Result<(), StoreError>;
    /// At most 64 retained traffic descriptors, ordered by their actual persisted event ID.
    async fn traffic_keyset(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        after: u64,
        limit: u32,
    ) -> Result<Vec<ArchiveTrafficV1>, StoreError>;
}
