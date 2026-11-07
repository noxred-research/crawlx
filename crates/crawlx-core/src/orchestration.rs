//! Bounded frontier transactions, producer cursors and revisit scheduling.

use crate::hash::Digest;
use crate::repo::{FrontierEntry, FrontierStatus};
use crate::request::{RequestEnvelopeV1, RequestIdentityV1, MAX_REQUEST_BATCH, MAX_REQUEST_BATCH_BYTES};
use crate::{CrawlRunId, StoreError, TenantId, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Immutable native queue policy. Other runtime/session controls retain their existing owners.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct OrchestrationConfigV1 {
    /// Exactly one.
    pub version: u16,
    /// Pending-entry and metadata quotas.
    pub queue: QueueConfigV1,
    /// Independent whole-request ceilings across transport and cooldown retries.
    #[serde(default)]
    pub attempts: AttemptLimitsV1,
    /// Worker-local fixed/adaptive admission; never widens hard limits.
    #[serde(default)]
    pub admission: crate::runtime_admission::RuntimeAdmissionV1,
    /// Feedback recurrence within the existing origin governor.
    #[serde(default)]
    pub pacing_dialect: crate::runtime_admission::PacingDialectV1,
    /// Optional bounded revisits.
    pub recrawl: Option<RecrawlPolicyV1>,
}
impl Default for OrchestrationConfigV1 {
    fn default() -> Self {
        Self {
            version: 1,
            queue: QueueConfigV1::default(),
            recrawl: None,
            attempts: AttemptLimitsV1::default(),
            admission: crate::runtime_admission::RuntimeAdmissionV1::default(),
            pacing_dialect: crate::runtime_admission::PacingDialectV1::default(),
        }
    }
}
impl OrchestrationConfigV1 {
    /// Validate immutable policy against hard deployment ceilings.
    /// # Errors
    /// Returns a conflict for unsupported versions or unbounded configuration.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != 1
            || self.queue.batch_size == 0
            || self.queue.batch_size > 1000
            || self.queue.max_pending_entries == 0
            || self.queue.max_pending_entries > 1_000_000
            || self.queue.max_pending_envelope_bytes == 0
            || self.queue.max_pending_envelope_bytes > 1_073_741_824
        {
            return Err(StoreError::Conflict("invalid orchestration bounds".into()));
        }
        if let Some(policy) = &self.recrawl {
            policy.validate()?;
        }
        self.admission.validate()?;
        self.attempts.validate()?;
        Ok(())
    }
}
/// Independent ceilings; granting a budget never grants permission for an effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AttemptLimitsV1 {
    /// All reserved target effects, including redirects/helper/retry work.
    pub max_total_effects: u32,
    /// Maximum admitted session rotations; pinned native GET performs none.
    pub max_session_rotations: u32,
    /// Maximum processing retries, independently bounded by total effects.
    pub max_processing_retries: u32,
    /// Whole request elapsed deadline, including cooldown.
    pub max_elapsed_ms: u64,
}
impl Default for AttemptLimitsV1 {
    fn default() -> Self {
        Self {
            max_total_effects: 64,
            max_session_rotations: 0,
            max_processing_retries: 0,
            max_elapsed_ms: 600_000,
        }
    }
}
impl AttemptLimitsV1 {
    /// Validate finite deployment-bounded effect and elapsed ceilings.
    /// # Errors
    /// Rejects unlimited, overflowing or contradictory limits.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.max_total_effects == 0
            || self.max_total_effects > u32::from(u16::MAX)
            || self.max_session_rotations > self.max_total_effects
            || self.max_processing_retries > self.max_total_effects
            || self.max_elapsed_ms == 0
            || self.max_elapsed_ms > 31_536_000_000
        {
            return Err(StoreError::Conflict("invalid request attempt bounds".into()));
        }
        Ok(())
    }
}

/// Finite producer closes once input ends; continuous producer requires explicit sealing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProducerModeV1 {
    /// Seed producer is finite; discovery remains allowed while its parent fence is live.
    #[default]
    Finite,
    /// Empty queue waits for further authenticated input.
    Continuous,
}
/// Queue reservations count pending and leased rows until terminal completion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct QueueConfigV1 {
    /// Maximum pending plus leased rows.
    pub max_pending_entries: u64,
    /// Maximum serialized envelopes held by open rows.
    pub max_pending_envelope_bytes: u64,
    /// Maximum append/claim transaction entries.
    pub batch_size: u32,
    /// Producer lifecycle.
    pub producer_mode: ProducerModeV1,
}
impl Default for QueueConfigV1 {
    fn default() -> Self {
        Self {
            max_pending_entries: 100_000,
            max_pending_envelope_bytes: 64 * 1024 * 1024,
            batch_size: 256,
            producer_mode: ProducerModeV1::Finite,
        }
    }
}
/// Loader checkpoint committed atomically with its request batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct LoaderCursorV1 {
    /// Declarative source identifier.
    pub source: String,
    /// Digest of source bytes and pinned parser configuration.
    pub source_digest: Digest,
    /// Last committed input position.
    pub position: u64,
}
impl LoaderCursorV1 {
    /// Checkpoint for immutable source bytes and parser configuration.
    #[must_use]
    pub fn new(source: String, source_digest: Digest, position: u64) -> Self {
        Self {
            source,
            source_digest,
            position,
        }
    }
}
/// Authenticated append transaction. Authority fields must be assigned server-side.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RequestBatchV1 {
    /// Owning tenant, assigned by admission.
    pub tenant: TenantId,
    /// Existing admitted run.
    pub run: CrawlRunId,
    /// Existing principal name; not a page-supplied role grant.
    pub principal: String,
    /// Stable retry receipt key, privacy-safe and bounded.
    pub batch_id: Digest,
    /// Producer epoch checked before accepting new work.
    pub producer_epoch: u64,
    /// Cursor state expected before the append.
    pub expected_cursor: Option<LoaderCursorV1>,
    /// Cursor state after append.
    pub next_cursor: Option<LoaderCursorV1>,
    /// Live parent lease required for action/discovery-derived child batches.
    pub parent_fence: Option<(i64, i64)>,
    /// Initial policy/robots denial for an audited rejected discovery; never executable.
    #[serde(default)]
    pub initial_denial: Option<(FrontierStatus, String)>,
    /// Validated, bounded proposals.
    pub requests: Vec<RequestEnvelopeV1>,
}
impl RequestBatchV1 {
    /// New authenticated finite batch. Importers may set cursor and parent fence before admission.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        principal: String,
        batch_id: Digest,
        requests: Vec<RequestEnvelopeV1>,
    ) -> Self {
        Self {
            tenant,
            run,
            principal,
            batch_id,
            producer_epoch: 1,
            expected_cursor: None,
            next_cursor: None,
            parent_fence: None,
            initial_denial: None,
            requests,
        }
    }
}
impl RequestBatchV1 {
    /// Validate the full batch before mutations and return its serialized size.
    /// # Errors
    /// Returns a conflict for malformed envelopes, cursors or transaction bounds.
    pub fn validate(&self) -> Result<usize, StoreError> {
        if self.requests.len() > MAX_REQUEST_BATCH
            || !crate::request::safe_id(&self.principal)
            || self.producer_epoch == 0
        {
            return Err(StoreError::Conflict("invalid request batch".into()));
        }
        if self.initial_denial.as_ref().is_some_and(|(status, reason)| {
            !matches!(
                status,
                FrontierStatus::PolicyBlocked | FrontierStatus::RobotsBlocked
            ) || reason.is_empty()
                || reason.len() > 256
                || reason.bytes().any(|byte| byte.is_ascii_control())
        }) {
            return Err(StoreError::Conflict("invalid initial request denial".into()));
        }
        for request in &self.requests {
            request
                .validate()
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            if request.parent != self.parent_fence.map(|(id, _)| id) {
                return Err(StoreError::Conflict(
                    "request parent requires matching fence".into(),
                ));
            }
        }
        if let Some(next) = &self.next_cursor {
            if !crate::request::safe_id(&next.source)
                || self.expected_cursor.as_ref().is_some_and(|old| {
                    old.source != next.source
                        || old.source_digest != next.source_digest
                        || old.position > next.position
                })
            {
                return Err(StoreError::Conflict("incompatible loader cursor".into()));
            }
        } else if self.expected_cursor.is_some() {
            return Err(StoreError::Conflict("loader cursor cannot be removed".into()));
        }
        let bytes = serde_json::to_vec(self)
            .map_err(|error| StoreError::Serialization(error.to_string()))?
            .len();
        if bytes > MAX_REQUEST_BATCH_BYTES {
            return Err(StoreError::Conflict("request batch byte limit".into()));
        }
        Ok(bytes)
    }
}
/// Stable append receipt, replayed exactly for a duplicate batch id and digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RequestBatchReceiptV1 {
    /// Created frontier ids, in input order; duplicates are absent.
    pub inserted: Vec<i64>,
    /// Input rows already present.
    pub duplicates: u32,
    /// Committed cursor.
    pub cursor: Option<LoaderCursorV1>,
}
impl RequestBatchReceiptV1 {
    /// Empty transaction receipt.
    #[must_use]
    pub fn empty(cursor: Option<LoaderCursorV1>) -> Self {
        Self {
            inserted: Vec::new(),
            duplicates: 0,
            cursor,
        }
    }
}
/// Distinguish exhausted frontier from open producer, cooldown and remote leases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FrontierActivityV1 {
    /// Eligible rows exist.
    Ready,
    /// All remaining pending rows have future eligibility.
    WaitingCooldown,
    /// Another holder is draining leased work.
    Draining,
    /// No row remains, but producer accepts input.
    WaitingProducer,
    /// No rows and all producers sealed.
    Terminal,
}
/// Privacy-safe queue metadata; available even after volatile request content expires.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RequestMetadataV1 {
    /// Stable queue row id.
    pub id: i64,
    /// Current disposition.
    pub status: FrontierStatus,
    /// Discovery depth.
    pub depth: u16,
    /// Conservative lease-attempt count.
    pub attempts: u16,
    /// Immutable revisit generation.
    pub revisit_generation: u32,
}
impl RequestMetadataV1 {
    /// Construct a metadata-only row without URL, body, cookies or metadata values.
    #[must_use]
    pub const fn new(
        id: i64,
        status: FrontierStatus,
        depth: u16,
        attempts: u16,
        revisit_generation: u32,
    ) -> Self {
        Self {
            id,
            status,
            depth,
            attempts,
            revisit_generation,
        }
    }
}

/// Native fairness partition derived from the actual URL, never a source Host header.
/// It is advisory: resolver pinning and shared origin/IP limits remain authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FrontierPartitionV1 {
    /// Scheme, host and effective port used by the existing origin governor.
    pub origin: String,
}
impl FrontierPartitionV1 {
    /// Derive the native partition from parsed destination semantics, not imported metadata.
    #[must_use]
    pub fn from_url(url: &crate::url::CanonicalUrl) -> Self {
        Self {
            origin: url.url.origin().ascii_serialization(),
        }
    }
}

/// Stored request projection; legacy GET rows synthesize their native envelope.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct QueuedRequestV1 {
    /// Existing frontier row.
    pub entry: FrontierEntry,
    /// Authoritative principal assigned by the admitted run, never page metadata.
    pub principal: String,
    /// Immutable envelope.
    pub envelope: RequestEnvelopeV1,
    /// Identity and generation.
    pub identity: RequestIdentityV1,
    /// State CAS version; starts at one.
    pub state_version: u64,
    /// Checked native origin partition used by dispatch fairness/cooldown lookup.
    pub partition: FrontierPartitionV1,
}
impl QueuedRequestV1 {
    /// Rehydrate a validated stored queue projection.
    #[must_use]
    pub fn stored(
        entry: FrontierEntry,
        envelope: RequestEnvelopeV1,
        identity: RequestIdentityV1,
        state_version: u64,
        principal: String,
    ) -> Self {
        let partition = FrontierPartitionV1::from_url(&entry.url);
        Self {
            entry,
            envelope,
            identity,
            state_version,
            principal,
            partition,
        }
    }
}
/// Recrawl validators never substitute an unavailable body with fabricated content.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecrawlValidatorModeV1 {
    /// Always acquire a new representation.
    #[default]
    Disabled,
    /// Use exact retained history when available; otherwise acquire normally.
    IfAvailable,
    /// Refuse before dispatch when exact retained history is unavailable.
    RequireHistory,
}

/// Explicit bounded generation policy; authorization is checked separately on every revisit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RecrawlPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Minimum eligible interval.
    pub min_interval_ms: u64,
    /// Maximum eligible interval.
    pub max_interval_ms: u64,
    /// Includes original acquisition.
    pub max_visits: u32,
    /// Absolute end, never extending admitted run deadline.
    pub end_at: Timestamp,
    /// Conditional fetch behavior; only exact retained published history may supply validators.
    #[serde(default)]
    pub validator_mode: RecrawlValidatorModeV1,
}
impl RecrawlPolicyV1 {
    /// Allocate next immutable visit within policy and admitted run deadline.
    /// This pure calculation never grants authorization; callers must recheck live authority.
    /// # Errors
    /// Rejects invalid policy bounds or arithmetic overflow.
    pub fn next_visit(
        &self,
        current: &RequestEnvelopeV1,
        parent: i64,
        committed_at: Timestamp,
        run_deadline: Timestamp,
    ) -> Result<Option<RequestEnvelopeV1>, StoreError> {
        self.validate()?;
        let generation = current
            .revisit_generation
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("revisit generation overflow".into()))?;
        if generation >= self.max_visits {
            return Ok(None);
        }
        let delay = chrono::Duration::milliseconds(
            i64::try_from(self.min_interval_ms)
                .map_err(|_| StoreError::Conflict("revisit interval overflow".into()))?,
        );
        let eligible = committed_at
            .checked_add_signed(delay)
            .ok_or_else(|| StoreError::Conflict("revisit deadline overflow".into()))?;
        if eligible >= self.end_at || eligible >= run_deadline {
            return Ok(None);
        }
        let mut next = current.clone();
        next.revisit_generation = generation;
        next.not_before = Some(eligible);
        next.parent = Some(parent);
        Ok(Some(next))
    }
    /// Validate finite positive bounds.
    /// # Errors
    /// Returns a conflict for invalid or overflowing intervals.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != 1
            || self.min_interval_ms == 0
            || self.max_interval_ms < self.min_interval_ms
            || self.max_interval_ms > 31_536_000_000
            || self.max_visits < 2
            || self.max_visits > 10_000
        {
            return Err(StoreError::Conflict("invalid recrawl bounds".into()));
        }
        Ok(())
    }
}
/// Atomic request result, including an optional owned retained page descriptor.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RequestCommitV1 {
    /// Admitted run.
    pub run: CrawlRunId,
    /// Leased request.
    pub request_id: i64,
    /// Current unexpired frontier fence.
    pub fence: i64,
    /// Expected immutable result-state version.
    pub expected_state_version: u64,
    /// Terminal acquisition/processing disposition.
    pub status: FrontierStatus,
    /// Bounded privacy-safe reason code.
    pub reason: Option<String>,
    /// Digest of approved acquisition metadata, not an arbitrary artifact address.
    pub acquisition_ref: Option<Digest>,
    /// Digest of approved document metadata.
    pub document_ref: Option<Digest>,
    /// Page projection and immutable capture committed only with a successful live fence.
    /// Artifact bytes already have approved custody; this descriptor never stages visibility.
    pub page: Option<crate::repo::PageRecord>,
    /// Child requests applied in this transaction.
    pub children: Option<RequestBatchV1>,
    /// Accepted items committed under the same live request fence.
    pub accepted: Vec<crate::dataset::AcceptedBatchV1>,
    /// Extension/loader state deltas checked atomically with accepted items.
    pub state_deltas: Vec<crate::dataset::KvCasV1>,
    /// Immutable delivery intents; transport acknowledgement happens separately.
    pub outbox: Vec<crate::dataset::DeliveryBatchV1>,
}
impl RequestCommitV1 {
    /// Terminal result with no page, item, state, delivery or child deltas.
    #[must_use]
    pub fn terminal(
        run: CrawlRunId,
        request_id: i64,
        fence: i64,
        expected_state_version: u64,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Self {
        Self {
            run,
            request_id,
            fence,
            expected_state_version,
            status,
            reason,
            acquisition_ref: None,
            document_ref: None,
            page: None,
            children: None,
            accepted: Vec::new(),
            state_deltas: Vec::new(),
            outbox: Vec::new(),
        }
    }
}
/// Result transaction owner; dataset/outbox composition must use this same transaction.
#[async_trait]
pub trait RequestCommitRepo: Send + Sync {
    /// Validate live fence and state version, then persist result, page and children atomically.
    /// # Errors
    /// Returns lease loss, state conflict, quota or storage errors without partial writes.
    async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError>;
}

impl crate::acquisition::AcquisitionAllowanceV1 {
    /// Calculate remaining parent allowance without reading a clock in pure code.
    /// # Errors
    /// Returns a conflict when a deadline or any parent capacity is exhausted.
    pub fn remaining(
        policy: &crate::acquisition::AcquisitionPolicyV1,
        previous: crate::acquisition::AcquisitionUsageV1,
        deadline: Timestamp,
        now: Timestamp,
    ) -> Result<Self, StoreError> {
        let attempts = policy.max_attempts.saturating_sub(previous.attempts_reserved);
        let requests = policy
            .max_network_requests
            .saturating_sub(previous.network_requests_reserved);
        let bytes = policy
            .max_decoded_bytes
            .saturating_sub(previous.decoded_bytes_reserved);
        let elapsed = u32::try_from((deadline - now).num_milliseconds()).unwrap_or(0);
        if attempts == 0 || requests == 0 || bytes == 0 || elapsed == 0 {
            return Err(StoreError::Conflict(
                "parent acquisition allowance exhausted".into(),
            ));
        }
        Ok(Self::new(attempts, requests, bytes, elapsed, previous))
    }
    /// Conservatively hold the entire receipt while acquisition is in flight.
    #[must_use]
    pub fn held_usage(&self) -> crate::acquisition::AcquisitionUsageV1 {
        crate::acquisition::AcquisitionUsageV1::new(
            self.previous_usage
                .attempts_reserved
                .saturating_add(self.remaining_attempts),
            self.previous_usage
                .network_requests_reserved
                .saturating_add(self.remaining_network_requests),
            self.previous_usage
                .decoded_bytes_reserved
                .saturating_add(self.remaining_decoded_bytes),
            self.previous_usage.decoded_bytes_observed,
            true,
        )
    }
    /// Settle only per-lease evidence bounded by this receipt.
    /// # Errors
    /// Rejects claims exceeding escrow or impossible observed-byte evidence.
    pub fn checked_settlement(
        &self,
        usage: &crate::acquisition::AcquisitionUsageV1,
    ) -> Result<crate::acquisition::AcquisitionUsageV1, StoreError> {
        if usage.attempts_reserved > self.remaining_attempts
            || usage.network_requests_reserved > self.remaining_network_requests
            || usage.decoded_bytes_reserved > self.remaining_decoded_bytes
            || usage.decoded_bytes_observed > usage.decoded_bytes_reserved
        {
            return Err(StoreError::Conflict(
                "acquisition settlement exceeds escrow".into(),
            ));
        }
        Ok(crate::acquisition::AcquisitionUsageV1::new(
            self.previous_usage
                .attempts_reserved
                .saturating_add(usage.attempts_reserved),
            self.previous_usage
                .network_requests_reserved
                .saturating_add(usage.network_requests_reserved),
            self.previous_usage
                .decoded_bytes_reserved
                .saturating_add(usage.decoded_bytes_reserved),
            self.previous_usage
                .decoded_bytes_observed
                .saturating_add(usage.decoded_bytes_observed),
            self.previous_usage.evidence_incomplete || usage.evidence_incomplete,
        ))
    }
}
