//! Persistence the API needs beyond the `crawlx_core::repo` traits: API keys,
//! idempotency records, approvals, transitions, traffic, webhook deliveries,
//! audit events, authorization records and replay tagging.
//!
//! [`ApiStore`] has two implementations: [`crate::memory::MemoryApiStore`]
//! (tests, development, `database_url = None`) and [`crate::pg::PgApiStore`],
//! which holds no SQL of its own: it delegates to
//! [`crawlx_storage::PgApiRepo`] (the `api_keys`, `idempotency_keys`,
//! `approvals`, `transitions`, `webhook_deliveries` and `authorization_records`
//! tables), [`crawlx_storage::TrustedCorpus`] (traffic, coverage) and
//! [`crawlx_storage::retention::append_audit`].
//!
//! The row types shared with the repository (`ApprovalRecord`, `TransitionRecord`,
//! `WebhookDelivery`, their enums and filters) are defined in `crawlx-storage` and
//! re-exported here; the API-level types (`Scope`, `KeyRecord`, `IdemBegin`,
//! `TrafficRecord`) live in this module.

use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::traffic::{TrafficOrigin, TrustLane};
use crawlx_core::{
    ActionId, ApprovalId, ArtifactRef, AuthorizationRecordId, CrawlRunId, NetworkEpochId, StoreError,
    TenantId, Timestamp,
};
use crawlx_policy::AuthorizationRecord;
use crawlx_storage::{CoverageRow, TenantEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

pub use crawlx_storage::{
    ActionSummary, ApprovalDecision, ApprovalRecord, AuthorizationInsert, DecideOutcome, DeliveryResult,
    DeliveryStatus, TransitionFilter, TransitionRecord, WebhookDelivery,
};

/// A stored authorization record with what the store knows about it besides the record itself.
#[derive(Clone, PartialEq, Debug)]
pub struct AuthorizationEntry {
    /// The record as it stands now: lifecycle state (`verifiedAt`, `revokedAt`, `revokedReason`) merged in.
    pub record: AuthorizationRecord,
    /// `AuthorizationRecord::body_digest` as stored at creation.
    pub body_digest: Digest,
    /// How the ownership proof was checked (`{kind, checkedAt, hosts|keyId}`); `None` for a
    /// record that was registered locally and never verified.
    pub verification: Option<Value>,
}

/// Outcome of [`ApiStore::authorization_revoke`].
#[derive(Clone, PartialEq, Debug)]
pub struct AuthorizationRevoked {
    /// The record after the call; the revocation it carries is the first one.
    pub entry: AuthorizationEntry,
    /// `true` when this call revoked the record, `false` when it was already revoked.
    pub first: bool,
}

/// `authorization_records` without the lifecycle state, which the store keeps beside the body.
pub(crate) fn without_lifecycle(record: &AuthorizationRecord) -> AuthorizationRecord {
    AuthorizationRecord {
        verified_at: None,
        revoked_at: None,
        revoked_reason: None,
        ..record.clone()
    }
}

/// Result of an [`ApiStore`] operation; failures are [`StoreError`]s from `crawlx-core`.
pub type StoreResult<T> = Result<T, StoreError>;

/// API key scope.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub enum Scope {
    #[serde(rename = "crawls:read")]
    /// `crawls:read`: read runs, pages, graphs, transitions and traffic.
    CrawlsRead,
    #[serde(rename = "crawls:write")]
    /// `crawls:write`: create, pause, resume, cancel and erase runs.
    CrawlsWrite,
    #[serde(rename = "approvals:decide")]
    /// `approvals:decide`: approve or deny held actions.
    ApprovalsDecide,
    #[serde(rename = "artifacts:read_sensitive")]
    /// `artifacts:read_sensitive`: read artifacts the sensitivity policy withholds by default.
    ArtifactsReadSensitive,
    #[serde(rename = "replays:write")]
    /// `replays:write`: start replay runs from a finished run.
    ReplaysWrite,
    #[serde(rename = "authorizations:write")]
    /// `authorizations:write`: create, re-verify and revoke authorization records.
    AuthorizationsWrite,
    #[serde(rename = "authorizations:read")]
    /// `authorizations:read`: read authorization records.
    AuthorizationsRead,
    #[serde(rename = "metrics:read")]
    /// `metrics:read`: scrape the Prometheus exposition at `GET /metrics`.
    MetricsRead,
}

impl Scope {
    /// Every scope.
    pub const ALL: [Self; 8] = [
        Self::CrawlsRead,
        Self::CrawlsWrite,
        Self::ApprovalsDecide,
        Self::ArtifactsReadSensitive,
        Self::ReplaysWrite,
        Self::AuthorizationsWrite,
        Self::AuthorizationsRead,
        Self::MetricsRead,
    ];

    /// The wire form of the scope (the string stored in `api_keys.scopes`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CrawlsRead => "crawls:read",
            Self::CrawlsWrite => "crawls:write",
            Self::ApprovalsDecide => "approvals:decide",
            Self::ArtifactsReadSensitive => "artifacts:read_sensitive",
            Self::ReplaysWrite => "replays:write",
            Self::AuthorizationsWrite => "authorizations:write",
            Self::AuthorizationsRead => "authorizations:read",
            Self::MetricsRead => "metrics:read",
        }
    }

    /// Parse the wire form; unknown scopes are `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// All scopes as a set.
    #[must_use]
    pub fn all_set() -> BTreeSet<Self> {
        Self::ALL.into_iter().collect()
    }
}

/// One stored API key (`api_keys`). `hash` is BLAKE3-256 of the full key string.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KeyRecord {
    /// `api_keys.key_id`, the stable identifier of the key (not derived from the secret).
    pub key_id: Uuid,
    /// Tenant that owns the key; every request authenticated by it acts for this tenant.
    pub tenant: TenantId,
    /// First 8 characters of the secret part (after `cx_live_`).
    pub prefix: String,
    /// BLAKE3-256 digest of the full key string; compared in constant time on authentication.
    pub hash: [u8; 32],
    /// Scopes the key grants; a request needs the scope its route requires.
    pub scopes: BTreeSet<Scope>,
    /// Instant after which the key is rejected; `None` = never expires.
    pub expires_at: Option<Timestamp>,
    /// `true` once `api_keys.revoked_at` is set; a revoked key is always rejected.
    pub revoked: bool,
}

/// What a stored idempotent response looks like.
#[derive(Clone, PartialEq, Debug)]
pub struct StoredResponse {
    /// HTTP status code of the original response.
    pub status: u16,
    /// JSON body of the original response, returned verbatim on replay.
    pub body: Value,
    /// Run the original request created, when it created one.
    pub run_id: Option<CrawlRunId>,
}

/// Outcome of claiming an idempotency key.
#[derive(Clone, PartialEq, Debug)]
pub enum IdemBegin {
    /// First use: the caller executes and then `complete`s (or `release`s) the key.
    Started,
    /// Same key, same request hash, finished: return the stored response.
    Replay(StoredResponse),
    /// Same key, same request, still executing.
    InProgress,
    /// Same key with a different request hash.
    Mismatch,
}

/// One persisted traffic event.
#[derive(Clone, PartialEq, Debug)]
pub struct TrafficRecord {
    /// Sort key within a run: `(epoch, seq)` order as persisted.
    pub id: String,
    /// Network epoch the event belongs to; `None` for events outside any epoch.
    pub epoch_id: Option<NetworkEpochId>,
    /// Action that caused the request; `None` when the event is not attributed to an action.
    pub action: Option<ActionId>,
    /// Trust lane the request was observed in.
    pub lane: TrustLane,
    /// Role of the session that issued the request; `None` when unknown.
    pub role: Option<String>,
    /// Plane that produced the request (page, service worker, websocket, event source or fetch plane).
    pub origin: TrafficOrigin,
    /// HTTP method; `None` for events that have none (for example websocket frames).
    pub method: Option<String>,
    /// Redacted request URL; empty when none was recorded.
    pub url: String,
    /// HTTP response status; `None` when no response was observed.
    pub status: Option<u16>,
    /// `true` when the request went to a host outside the target site's party.
    pub third_party: bool,
    /// `true` when the request arrived after its epoch settled.
    pub late: bool,
    /// Redacted request headers as a JSON object; empty object when none were stored.
    pub request_headers: Value,
    /// Redacted response headers as a JSON object; empty object when none were stored.
    pub response_headers: Value,
    /// Artifact holding the response body; `None` when the body was not captured or not linkable.
    pub response_body: Option<ArtifactRef>,
    /// When the event occurred.
    pub occurred_at: Timestamp,
}

/// Optional equality filters for listing traffic; unset fields match everything.
#[derive(Clone, Default, Debug)]
pub struct TrafficFilter {
    /// `None` = both lanes.
    pub lane: Option<TrustLane>,
    /// Only events attributed to this role.
    pub role: Option<String>,
    /// Only events in this network epoch.
    pub epoch: Option<NetworkEpochId>,
    /// Only events from this origin plane.
    pub origin: Option<TrafficOrigin>,
}

/// Everything the API persists itself.
#[async_trait]
pub trait ApiStore: Send + Sync {
    // ---- API keys -------------------------------------------------------
    /// Look up a key by the first characters of its secret; `None` when absent.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn key_by_prefix(&self, prefix: &str) -> StoreResult<Option<KeyRecord>>;
    /// Insert a key (and ensure its tenant exists). Idempotent on `prefix`.
    async fn key_insert(&self, key: &KeyRecord, tenant_name: &str) -> StoreResult<()>;
    /// Record that `key_id` was used at `at` (`api_keys.last_used_at`).
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn key_touch(&self, key_id: Uuid, at: Timestamp) -> StoreResult<()>;

    // ---- idempotency (24 h retention) ----------------------------------
    /// Claim `key` for `tenant`. Keys are retained for 24 hours; `request_hash` pins the key to one request body.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn idem_begin(
        &self,
        tenant: TenantId,
        key: &str,
        request_hash: Digest,
        now: Timestamp,
    ) -> StoreResult<IdemBegin>;
    /// Store `response` against the claimed key so later repeats replay it.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn idem_complete(&self, tenant: TenantId, key: &str, response: &StoredResponse) -> StoreResult<()>;
    /// Drop an `in_progress` claim (5xx / error paths).
    async fn idem_release(&self, tenant: TenantId, key: &str) -> StoreResult<()>;
    /// Record `run` as the run the in-progress claim on `key` is about to create, so a repeat
    /// that arrives before the claim completes can name it ([`ApiStore::idem_run`]).
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn idem_link_run(&self, tenant: TenantId, key: &str, run: CrawlRunId) -> StoreResult<()>;
    /// The run linked to `key`: announced by an in-progress claim or created by a completed
    /// one; `None` when the key is unknown or carries no run.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn idem_run(&self, tenant: TenantId, key: &str) -> StoreResult<Option<CrawlRunId>>;

    // ---- approvals ------------------------------------------------------
    /// Every approval of `run`, ordered by approval id.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn approvals_list(&self, run: CrawlRunId) -> StoreResult<Vec<ApprovalRecord>>;
    /// One approval of `run`; `None` when the id is unknown or belongs to another run.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn approval_get(&self, run: CrawlRunId, id: ApprovalId) -> StoreResult<Option<ApprovalRecord>>;
    /// Apply `Approved` or `Denied`. Approving also releases the held action.
    async fn approval_decide(
        &self,
        run: CrawlRunId,
        id: ApprovalId,
        decision: ApprovalDecision,
        decided_by: Uuid,
        reason: Option<&str>,
        now: Timestamp,
    ) -> StoreResult<DecideOutcome>;

    // ---- transitions, traffic, coverage ---------------------------------
    /// Transitions of `run` matching `filter`, ordered by transition id.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn transitions_list(
        &self,
        run: CrawlRunId,
        filter: &TransitionFilter,
    ) -> StoreResult<Vec<TransitionRecord>>;
    /// Traffic events of `run` matching `filter`, in `(epoch, seq)` order. The lane predicate
    /// is always applied: `filter.lane = None` is the explicit `lane=all`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn traffic_list(&self, run: CrawlRunId, filter: &TrafficFilter) -> StoreResult<Vec<TrafficRecord>>;
    /// Coverage rows of `run` with the lane predicate applied (`TrustedCorpus`):
    /// trusted counts only include trusted-lane successes from trusted-reachable states.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn coverage(&self, run: CrawlRunId) -> StoreResult<Vec<CoverageRow>>;

    // ---- runs -------------------------------------------------------------
    /// Runs in `queued|running|pausing|paused` owned by `tenant`.
    async fn active_run_count(&self, tenant: TenantId) -> StoreResult<u64>;
    /// Ids of the runs of `tenant` in `queued|running|pausing|paused`, oldest first.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn active_runs(&self, tenant: TenantId) -> StoreResult<Vec<CrawlRunId>>;
    /// Called after run persistence (`RunRepo::create` or `RunRepo::create_replay`) to index memory-backed runs.
    async fn run_created(&self, tenant: TenantId, run: CrawlRunId) -> StoreResult<()>;
    /// Mark `run` as `run_kind = 'shadow'` (a mirrored crawl).
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails or the run is unknown.
    async fn shadow_tag(&self, run: CrawlRunId) -> StoreResult<()>;
    /// `tenants.engine` of `tenant`; `Crawlx` when the tenant has no row yet.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn tenant_engine(&self, tenant: TenantId) -> StoreResult<TenantEngine>;
    /// The authorization record `id` of `tenant`, with version, validity window, verification and revocation merged in; `None` when absent.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails or the stored record is malformed.
    async fn authorization_get(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> StoreResult<Option<AuthorizationRecord>>;
    /// The authorization record `id` of `tenant` with the digest it was stored under and the
    /// evidence of its ownership check; `None` when absent or owned by another tenant.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails or the stored record is malformed.
    async fn authorization_entry(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> StoreResult<Option<AuthorizationEntry>>;
    /// Store `record` as a new immutable authorization record, verified at `verified_at` by
    /// `verification` (`{kind, checkedAt, hosts|keyId}`) and created by the API key `created_by`.
    /// The record's lifecycle fields (`verifiedAt`, `revokedAt`, `revokedReason`) are ignored.
    /// Idempotent on `(id, body digest)`: see [`AuthorizationInsert`].
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn authorization_create(
        &self,
        tenant: TenantId,
        created_by: Uuid,
        record: &AuthorizationRecord,
        verification: &Value,
        verified_at: Timestamp,
    ) -> StoreResult<AuthorizationInsert>;
    /// Revoke the record at `now` (`revoked_at`, `revoked_reason`, `revoked_by`). Idempotent: an
    /// already revoked record keeps its first revocation. `None` when the record is absent or
    /// owned by another tenant.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn authorization_revoke(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        by: Uuid,
        reason: Option<&str>,
        now: Timestamp,
    ) -> StoreResult<Option<AuthorizationRevoked>>;
    /// Record a fresh successful ownership check (`verified_at`, `verification`); the body is
    /// untouched. `None` when the record is absent or owned by another tenant.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn authorization_mark_verified(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        verification: &Value,
        now: Timestamp,
    ) -> StoreResult<Option<AuthorizationEntry>>;
    /// Bind `run` to the body digest of the record it was admitted under.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown run and other [`StoreError`]s when the
    /// backing store fails.
    async fn authorization_bind_run(&self, run: CrawlRunId, body_digest: Digest) -> StoreResult<()>;
    /// The record body digest `run` was bound to; `None` when it references no record.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown run and other [`StoreError`]s when the
    /// backing store fails.
    async fn authorization_run_digest(&self, run: CrawlRunId) -> StoreResult<Option<Digest>>;

    // ---- audit ------------------------------------------------------------
    /// Append an audit event. `actor` identifies who acted, `event` names what happened, `subject` carries details.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn audit_append(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        actor: &str,
        event: &str,
        subject: Value,
    ) -> StoreResult<()>;

    // ---- webhook outbox ---------------------------------------------------
    /// Runs whose configuration has a webhook (all statuses; the dispatcher stops when drained).
    async fn webhook_runs(&self) -> StoreResult<Vec<CrawlRunId>>;
    /// Remember `run` as a webhook source (memory stores need this; SQL stores derive it).
    async fn webhook_watch(&self, run: CrawlRunId) -> StoreResult<()>;
    /// Highest event seq already queued for `run`.
    async fn webhook_cursor(&self, run: CrawlRunId) -> StoreResult<u64>;
    /// Queue a delivery; `false` when `(run, event_seq, url)` is already queued.
    async fn webhook_enqueue(&self, delivery: &WebhookDelivery) -> StoreResult<bool>;
    /// Claim up to `limit` pending deliveries due at `now`; each claim defers the row by `lease_secs`.
    async fn webhook_claim_due(
        &self,
        now: Timestamp,
        limit: u32,
        lease_secs: u32,
    ) -> StoreResult<Vec<WebhookDelivery>>;
    /// Apply the outcome of one delivery attempt to the delivery `id`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails or `id` is unknown.
    async fn webhook_record(&self, id: Uuid, result: &DeliveryResult) -> StoreResult<()>;
    /// Number of deliveries of `run` that ended `dead`.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn webhook_dead_count(&self, run: CrawlRunId) -> StoreResult<u64>;
    /// Every delivery of `run`, ordered by event sequence.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn webhook_list(&self, run: CrawlRunId) -> StoreResult<Vec<WebhookDelivery>>;
}

/// Object bytes and rows for the artifacts endpoint and page content.
#[async_trait]
pub trait ArtifactSource: Send + Sync {
    /// Artifact row for `id`; `None` when it does not exist.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the backing store fails.
    async fn row(&self, id: crawlx_core::ArtifactId) -> StoreResult<Option<crawlx_storage::ArtifactRow>>;
    /// Bytes of `artifact` from object storage.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the object is missing or unreadable.
    async fn read(&self, artifact: &ArtifactRef) -> StoreResult<Vec<u8>>;
    /// Read content with byte bound checked before allocation and fixity checked before return.
    ///
    /// # Errors
    /// Returns scope, retention, bound or unavailable streaming capability errors.
    async fn read_limited(&self, artifact: &ArtifactRef, max_bytes: u64) -> StoreResult<Vec<u8>> {
        let _ = (artifact, max_bytes);
        Err(StoreError::Unavailable("bounded content read unavailable".into()))
    }
    /// Stream retained content without collection-sized buffers.
    ///
    /// # Errors
    /// Returns scope, retention, bound, fixity or unsupported capability errors.
    async fn stream(
        &self,
        artifact: &ArtifactRef,
        max_bytes: u64,
    ) -> StoreResult<futures::stream::BoxStream<'static, StoreResult<bytes::Bytes>>> {
        let _ = (artifact, max_bytes);
        Err(StoreError::Unavailable("content streaming unavailable".into()))
    }
    /// Erase one content artifact use after catalog visibility is revoked.
    ///
    /// # Errors
    /// Returns scope or backend erasure errors.
    async fn erase_artifact(&self, artifact: &ArtifactRef) -> StoreResult<()> {
        let _ = artifact;
        Err(StoreError::Unavailable("artifact erasure unavailable".into()))
    }
    /// Store a UTF-8 authorization document on its tenant-owned run.
    ///
    /// # Errors
    /// Returns an error if retention forbids the write or storage fails.
    async fn put_evidence(&self, run: CrawlRunId, bytes: &[u8]) -> StoreResult<ArtifactRef>;
    /// Store an approved recorded login flow, bounded by its source run's original expiry.
    ///
    /// # Errors
    /// Returns retention denial or a storage error; implementations must preserve the deadline.
    async fn put_login_flow(
        &self,
        run: CrawlRunId,
        bytes: &crawlx_core::secret::Redacted<Vec<u8>>,
        deadline: Timestamp,
    ) -> StoreResult<ArtifactRef>;
    /// Delete every artifact use of `run` (erasure).
    async fn purge_run(&self, run: CrawlRunId) -> StoreResult<u64>;
    /// A presigned object-store URL for `artifact`, valid for at most `ttl`;
    /// `None` when the backend cannot presign, in which case the bytes are served by the API.
    ///
    /// # Errors
    /// Returns a [`StoreError`] when the artifact is unknown, not of the `content` class, or
    /// signing fails.
    async fn presign(
        &self,
        artifact: &ArtifactRef,
        ttl: std::time::Duration,
    ) -> StoreResult<Option<url::Url>> {
        let _ = (artifact, ttl);
        Ok(None)
    }
}

/// Erasure of a whole run (`DELETE /v1/crawls/{id}`).
#[async_trait]
pub trait Eraser: Send + Sync {
    /// Remove every row and object of `run`; returns the number of rows deleted.
    async fn erase(&self, run: CrawlRunId) -> StoreResult<u64>;
}

/// Revoke archive dependency closure before any run/artifact erasure, resuming cleanup in bounded batches.
pub(crate) async fn erase_archives(
    repo: &dyn crawlx_core::archive_catalog::ArchiveRepo,
    artifacts: &dyn ArtifactSource,
    tenant: TenantId,
    export: uuid::Uuid,
) -> StoreResult<()> {
    repo.erase(tenant, export).await?;
    loop {
        let pending = repo.erased_artifacts(tenant, 64).await?;
        if pending.is_empty() {
            return Ok(());
        }
        for artifact in pending {
            artifacts.erase_artifact(&artifact).await?;
            repo.acknowledge_erased(tenant, &artifact).await?;
        }
    }
}
