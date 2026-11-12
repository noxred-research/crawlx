//! Tenant-scoped durable archive catalog and validator-compatible payload history.
//!
//! Catalog rows contain content-bearing metadata and inherit source retention. A published
//! manifest is the commit point; records are indexed only after their shard objects commit.

use crate::archive::{ArchiveCaptureFactsV1, ArchiveConfigV1, ArchiveManifestV1};
use crate::hash::Digest;
use crate::{ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One persisted chronological traffic descriptor, without body bytes. Request headers and the
/// observed protocol are present only when the persisted source recorded them; nothing is
/// reconstructed.
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
    /// HTTP method the capture recorded; `None` when the source did not persist it.
    pub method: Option<String>,
    /// Request headers as recorded (name, value) in capture order, already redacted by the
    /// capture plane; `None` when the source did not persist headers, `Some(vec![])` for a
    /// request that really carried none.
    pub request_headers: Option<Vec<(String, String)>>,
    /// Application protocol the capture backend observed; `None` when it was not persisted.
    pub protocol: Option<crate::traffic::Protocol>,
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
            method: None,
            request_headers: None,
            protocol: None,
        }
    }

    /// Attach the wire facts the persisted event recorded.
    #[must_use]
    pub fn with_wire(
        mut self,
        method: Option<String>,
        request_headers: Option<Vec<(String, String)>>,
        protocol: Option<crate::traffic::Protocol>,
    ) -> Self {
        self.method = method;
        self.request_headers = request_headers;
        self.protocol = protocol;
        self
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

/// Retained byte authority inherited by every archive representation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveCustodyV1 {
    /// Content stays ordinary; Sensitive never becomes ordinary archive content.
    pub sensitivity: crate::repo::Sensitivity,
    /// Earliest approved source deadline; packaging cannot extend it.
    pub expires_at: Option<Timestamp>,
}

impl Default for ArchiveCustodyV1 {
    fn default() -> Self {
        Self::content(None)
    }
}

impl ArchiveCustodyV1 {
    /// Validate retained byte authority loaded from an artifact index.
    ///
    /// # Errors
    /// Refuses unsupported classes, expired deadlines and unbounded sensitive evidence.
    pub fn new(
        sensitivity: crate::repo::Sensitivity,
        expires_at: Option<Timestamp>,
        now: Timestamp,
    ) -> Result<Self, StoreError> {
        let custody = Self {
            sensitivity,
            expires_at,
        };
        custody.validate(now)?;
        Ok(custody)
    }

    /// Ordinary retained content with an optional source deadline.
    #[must_use]
    pub const fn content(expires_at: Option<Timestamp>) -> Self {
        Self {
            sensitivity: crate::repo::Sensitivity::Content,
            expires_at,
        }
    }

    /// Sensitive retained evidence always has a finite source deadline.
    #[must_use]
    pub const fn sensitive(expires_at: Timestamp) -> Self {
        Self {
            sensitivity: crate::repo::Sensitivity::Sensitive,
            expires_at: Some(expires_at),
        }
    }

    /// Reject unsupported classes and expired or unbounded sensitive authority.
    ///
    /// # Errors
    /// Returns a retention refusal for an invalid class or deadline.
    pub fn validate(self, now: Timestamp) -> Result<(), StoreError> {
        if !matches!(
            self.sensitivity,
            crate::repo::Sensitivity::Content | crate::repo::Sensitivity::Sensitive
        ) || (self.sensitivity == crate::repo::Sensitivity::Sensitive && self.expires_at.is_none())
            || self.expires_at.is_some_and(|expiry| expiry <= now)
        {
            return Err(StoreError::RetentionDenied(
                "archive custody is invalid or expired".into(),
            ));
        }
        Ok(())
    }

    /// Join sources without weakening sensitivity or extending either deadline.
    ///
    /// # Errors
    /// Returns a retention refusal when either source authority is invalid.
    pub fn narrow(self, source: Self, now: Timestamp) -> Result<Self, StoreError> {
        self.validate(now)?;
        source.validate(now)?;
        let expires_at = match (self.expires_at, source.expires_at) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        let sensitivity = if self.sensitivity == crate::repo::Sensitivity::Sensitive
            || source.sensitivity == crate::repo::Sensitivity::Sensitive
        {
            crate::repo::Sensitivity::Sensitive
        } else {
            crate::repo::Sensitivity::Content
        };
        Ok(Self {
            sensitivity,
            expires_at,
        })
    }
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
    /// Aggregate byte authority, persisted before sensitive shards become catalog-visible.
    #[serde(default)]
    pub custody: ArchiveCustodyV1,
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
            custody: ArchiveCustodyV1::content(expires_at),
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Original retained evidence authority; mandatory for Sensitive records.
    /// Revocation or deadline changes invalidate publication and subsequent byte access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_artifact: Option<ArtifactRef>,
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
    /// Exact retained authority of this shard and its approved source.
    #[serde(default)]
    pub custody: ArchiveCustodyV1,
    /// Exact approved payload reuse domain. Legacy rows without a key are never reuse sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_key: Option<ArchivePayloadKeyV1>,
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
            source_artifact: None,
            offset,
            length,
            payload_digest,
            target,
            facts,
            mime,
            dependency: None,
            custody: ArchiveCustodyV1::default(),
            payload_key: None,
        }
    }
}

/// Content reuse identity, distinct from target-bound conditional validator history.
///
/// `variant` binds method, immutable request headers/session, policy, retention,
/// representation provenance and Vary context. Retained DOM/text contexts are run-bound.
/// This descriptor never grants authority to fetch bytes or establishes wire completeness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchivePayloadKeyV1 {
    /// Exact principal whose approved representation is reused.
    pub principal: String,
    /// Deterministic complete request/security/policy context.
    pub variant: Digest,
    /// Meaning of the approved stored bytes.
    pub representation: crate::archive::ArchiveRepresentation,
    /// Required privacy revision.
    pub redaction_revision: String,
    /// Exact representation media type.
    pub mime: String,
}

impl ArchivePayloadKeyV1 {
    /// Bind an approved stored representation to its principal and immutable context.
    #[must_use]
    pub fn new(principal: String, variant: Digest, facts: &ArchiveCaptureFactsV1, mime: String) -> Self {
        Self {
            principal,
            variant,
            representation: facts.representation,
            redaction_revision: facts.redaction_revision.clone(),
            mime,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

/// Result of [`ArchiveRepo::cancel`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveCancelV1 {
    /// The recording export was abandoned by this call.
    Cancelled,
    /// The export is not recording and was left untouched.
    Refused(ArchiveExportState),
    /// Unknown, expired or foreign export.
    Missing,
}

/// What a completion callback may say about an export: identity, hash and size of a package that
/// is already durably committed, and nothing else. It is constructible only from a published
/// export, so no callback can ever announce an export that failed, is still recording, was
/// erased or has no package object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArchiveCompletionV1 {
    /// Contract version.
    pub schema_version: u8,
    /// Always `committed`.
    pub state: String,
    /// Committed export identity.
    pub export: Uuid,
    /// Source run.
    pub run: CrawlRunId,
    /// Package container.
    pub format: crate::archive::ArchiveFormat,
    /// Committed package object: identity and content digest.
    pub package: ArtifactRef,
    /// Exact byte length of the package object.
    pub package_bytes: u64,
    /// Committed resource records in the package.
    pub records: u64,
    /// Original wire and subresource completeness, exactly as the manifest states it.
    pub complete: bool,
}

impl ArchiveCompletionV1 {
    /// Describe a committed export.
    ///
    /// # Errors
    /// Returns a conflict unless the export is published with its package object and a
    /// manifest that recorded the package size.
    pub fn committed(export: &ArchiveExportV1) -> Result<Self, StoreError> {
        let (Some(package), Some(manifest)) = (&export.artifact, &export.manifest) else {
            return Err(StoreError::Conflict("archive export is not committed".into()));
        };
        if export.state != ArchiveExportState::Published || manifest.package_bytes == 0 {
            return Err(StoreError::Conflict("archive export is not committed".into()));
        }
        Ok(Self {
            schema_version: 1,
            state: "committed".into(),
            export: export.id,
            run: export.run,
            format: export.config.format,
            package: package.clone(),
            package_bytes: manifest.package_bytes,
            records: manifest.records,
            complete: manifest.complete,
        })
    }

    /// Stable delivery identity: the same committed package always maps to the same key, so a
    /// retried or re-derived callback never creates a second row.
    #[must_use]
    pub fn idempotency_key(&self) -> String {
        format!(
            "archive-complete.{}.{}",
            self.export.simple(),
            self.package.digest.to_hex()
        )
    }

    /// Canonical callback body.
    ///
    /// # Errors
    /// Returns a serialization failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(self).map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

/// Tenant-scoped archive operations. All writes reject ZDR and expired source runs.
///
/// Implementations serialize claims, commits, publication and cascading erasure. A fence
/// expires after 120 seconds; a paused writer cannot mutate a recovered/deleted export.
#[async_trait]
pub trait ArchiveRepo: Send + Sync {
    /// Persist finalization intent idempotently. Refuse policy changes on recovery.
    async fn begin(&self, export: &ArchiveExportV1) -> Result<(), StoreError>;
    /// Narrow byte authority under the current writer fence before committing a source.
    /// A sensitive class can never return to Content and expiry can only move earlier.
    ///
    /// # Errors
    /// Returns scope, lease, retention or backend errors without weakening existing authority.
    async fn narrow_custody(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        custody: &ArchiveCustodyV1,
        now: Timestamp,
    ) -> Result<(), StoreError>;
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
    /// Select one committed standalone payload in the configured reuse scope.
    /// Foreign, expired, failed and unpublished external exports are never eligible.
    async fn payload_source(
        &self,
        tenant: TenantId,
        export: Uuid,
        key: &ArchivePayloadKeyV1,
        payload_digest: &str,
        now: Timestamp,
    ) -> Result<Option<ArchiveRecordV1>, StoreError>;
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
    /// Every export that transitively depends on `export` through revisit records, excluding
    /// `export` itself, in ascending identity order. Empty for an unknown or foreign export.
    ///
    /// This is exactly the closure [`Self::erase`] tombstones, so a caller can refuse or
    /// confirm a removal before it happens.
    async fn dependents(&self, tenant: TenantId, export: Uuid) -> Result<Vec<Uuid>, StoreError>;
    /// Atomically abandon an export that is still recording: its writer fence is invalidated,
    /// it becomes a permanent tombstone and its committed shards are queued for physical
    /// erasure. A published, failed or already deleted export is never changed; the outcome
    /// names its state instead.
    async fn cancel(
        &self,
        tenant: TenantId,
        export: Uuid,
        now: Timestamp,
    ) -> Result<ArchiveCancelV1, StoreError>;
}
