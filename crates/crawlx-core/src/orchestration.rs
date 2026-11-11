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
    /// Optional deterministic change/error feedback; absent preserves fixed scheduling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive: Option<AdaptiveRecrawlV1>,
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
        if let Some(adaptive) = &self.adaptive {
            adaptive.validate()?;
        }
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

/// Integer-only versioned recurrence. Factors are thousandths of the previous interval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdaptiveRecrawlV1 {
    /// Exactly one.
    pub version: u16,
    /// Modified content shortens the interval.
    pub changed_permille: u16,
    /// Unmodified content lengthens the interval.
    pub unchanged_permille: u16,
    /// Failed acquisitions lengthen the interval.
    pub error_permille: u16,
    /// Typed status/change eligibility and deterministic ranking expression.
    pub ranking: crate::priority::EligibilityRankingV1,
}

impl Default for AdaptiveRecrawlV1 {
    fn default() -> Self {
        Self {
            version: 1,
            changed_permille: 500,
            unchanged_permille: 2000,
            error_permille: 4000,
            ranking: crate::priority::EligibilityRankingV1::default(),
        }
    }
}

impl AdaptiveRecrawlV1 {
    /// Check bounded, monotone factors.
    ///
    /// # Errors
    /// Rejects unknown versions, zero factors, or factors that reverse feedback.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != 1
            || !(1..=1000).contains(&self.changed_permille)
            || !(1000..=16_000).contains(&self.unchanged_permille)
            || !(1000..=16_000).contains(&self.error_permille)
        {
            return Err(StoreError::Conflict("invalid adaptive recrawl policy".into()));
        }
        self.ranking.validate()
    }
}

/// Actual acquisition comparison; unavailable evidence stays unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecrawlChangeV1 {
    /// Both approved content digests exist and differ.
    Changed,
    /// Both approved content digests exist and match.
    Unchanged,
    /// Terminal acquisition failed.
    Error,
    /// No comparable approved representation exists.
    Unknown,
}

/// Injected approved archive/history baseline. This value grants no byte-read authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RecrawlBaselineV1 {
    /// Last measured representation, absent when no body was acquired.
    pub content_digest: Option<Digest>,
    /// Injected transaction/capture time.
    pub observed_at: Timestamp,
    /// Previous bounded interval.
    pub interval_ms: u64,
    /// Smoothed measured change frequency in thousandths.
    pub change_rate_permille: u16,
    /// Consecutive actual failed acquisitions; unknown responses do not imply failure.
    #[serde(default)]
    pub consecutive_errors: u32,
}

impl RecrawlBaselineV1 {
    /// Construct a baseline from approved history, without opening archive bytes.
    #[must_use]
    pub fn new(content_digest: Option<Digest>, observed_at: Timestamp, interval_ms: u64) -> Self {
        Self {
            content_digest,
            observed_at,
            interval_ms,
            change_rate_permille: 500,
            consecutive_errors: 0,
        }
    }
}

/// Pure schedule result; durable append still requires the original live request fence.
#[derive(Clone, Debug)]
#[non_exhaustive]
#[must_use]
pub struct RecrawlDecisionV1 {
    /// Fresh immutable generation proposed for re-admission.
    pub request: RequestEnvelopeV1,
    /// Actual comparison used by this decision.
    pub change: RecrawlChangeV1,
    /// Clamped recurrence interval.
    pub interval_ms: u64,
    /// Smoothed change frequency; errors do not masquerade as unchanged.
    pub change_rate_permille: u16,
    /// Ascending scheduling key; the durable row ID remains the final dispatch tie-break.
    pub rank_key: (i64, i64),
}

const RECRAWL_BASELINE_KEY: &str = "crawlx_recrawl_baseline_v1";

impl RecrawlPolicyV1 {
    /// Schedule using real terminal commit facts and the prior committed baseline.
    /// A supplied archive baseline overrides queue history only after its caller checks custody.
    ///
    /// # Errors
    /// Rejects malformed history, policy bounds, future baselines, or arithmetic overflow.
    pub fn next_visit_after_commit(
        &self,
        current: &RequestEnvelopeV1,
        commit: &RequestCommitV1,
        committed_at: Timestamp,
        run_deadline: Timestamp,
        archive_baseline: Option<&RecrawlBaselineV1>,
    ) -> Result<Option<RecrawlDecisionV1>, StoreError> {
        self.validate()?;
        if !matches!(
            commit.status,
            FrontierStatus::Succeeded | FrontierStatus::Failed | FrontierStatus::Unreachable
        ) || (self.adaptive.is_none() && commit.status != FrontierStatus::Succeeded)
        {
            return Ok(None);
        }
        let queued = current
            .metadata
            .get(RECRAWL_BASELINE_KEY)
            .map(RecrawlBaselineV1::deserialize)
            .transpose()
            .map_err(|_| StoreError::Conflict("invalid recrawl baseline".into()))?;
        let baseline = archive_baseline.or(queued.as_ref());
        if baseline.is_some_and(|value| {
            value.observed_at > committed_at
                || value.change_rate_permille > 1000
                || value.interval_ms < self.min_interval_ms
                || value.interval_ms > self.max_interval_ms
        }) {
            return Err(StoreError::Conflict("invalid recrawl baseline bounds".into()));
        }
        let digest = commit.page.as_ref().map(|page| page.content_digest);
        let change = if matches!(
            commit.status,
            FrontierStatus::Failed | FrontierStatus::Unreachable
        ) || commit.page.as_ref().is_some_and(|page| page.status >= 400)
        {
            RecrawlChangeV1::Error
        } else if commit.status == FrontierStatus::Succeeded {
            match (baseline.and_then(|value| value.content_digest), digest) {
                (Some(previous), Some(current)) if previous == current => RecrawlChangeV1::Unchanged,
                (Some(_), Some(_)) => RecrawlChangeV1::Changed,
                _ => RecrawlChangeV1::Unknown,
            }
        } else {
            return Ok(None);
        };
        let previous_interval = if self.adaptive.is_some() {
            baseline.map_or(self.min_interval_ms, |value| value.interval_ms)
        } else {
            self.min_interval_ms
        };
        let previous_rate = baseline.map_or(500, |value| value.change_rate_permille);
        let rate = match change {
            RecrawlChangeV1::Changed => (u32::from(previous_rate) * 3 + 1000) / 4,
            RecrawlChangeV1::Unchanged => u32::from(previous_rate) * 3 / 4,
            RecrawlChangeV1::Error | RecrawlChangeV1::Unknown => u32::from(previous_rate),
        };
        let factor = self.adaptive.as_ref().map_or(1000, |policy| match change {
            RecrawlChangeV1::Changed => policy.changed_permille,
            RecrawlChangeV1::Unchanged => policy.unchanged_permille,
            RecrawlChangeV1::Error => policy.error_permille,
            RecrawlChangeV1::Unknown => 1000,
        });
        let interval_ms = previous_interval
            .checked_mul(u64::from(factor))
            .ok_or_else(|| StoreError::Conflict("recrawl recurrence overflow".into()))?
            .checked_div(1000)
            .ok_or_else(|| StoreError::Conflict("recrawl divisor is zero".into()))?
            .clamp(self.min_interval_ms, self.max_interval_ms);
        // Reuse generation/deadline checks without mutating the admitted policy.
        let mut bounded = self.clone();
        bounded.min_interval_ms = interval_ms;
        let Some(mut request) = bounded.next_visit(current, commit.request_id, committed_at, run_deadline)?
        else {
            return Ok(None);
        };
        let change_rate_permille =
            u16::try_from(rate).map_err(|_| StoreError::Conflict("recrawl change rate overflow".into()))?;
        let consecutive_errors = if change == RecrawlChangeV1::Error {
            baseline
                .map_or(0, |value| value.consecutive_errors)
                .saturating_add(1)
        } else {
            0
        };
        let default_ranking = crate::priority::EligibilityRankingV1::default();
        let ranking = self
            .adaptive
            .as_ref()
            .map_or(&default_ranking, |policy| &policy.ranking);
        let Some(rank_key) = ranking.key(
            committed_at,
            None,
            commit.page.as_ref().map(|page| page.status),
            current.priority,
            change_rate_permille,
            consecutive_errors,
            commit.request_id,
        )?
        else {
            return Ok(None);
        };
        let next_baseline = RecrawlBaselineV1 {
            // Errors preserve the most recent measured representation, not a fabricated body.
            content_digest: if change == RecrawlChangeV1::Error {
                baseline.and_then(|value| value.content_digest)
            } else {
                digest.or_else(|| baseline.and_then(|value| value.content_digest))
            },
            observed_at: committed_at,
            interval_ms,
            change_rate_permille,
            consecutive_errors,
        };
        request.metadata.insert(
            RECRAWL_BASELINE_KEY.into(),
            serde_json::to_value(next_baseline)
                .map_err(|_| StoreError::Conflict("recrawl baseline encoding failed".into()))?,
        );
        request
            .metadata
            .insert("crawlx_recrawl_rank_v1".into(), serde_json::json!(rank_key.0));
        request
            .validate()
            .map_err(|_| StoreError::Conflict("recrawl metadata limit exceeded".into()))?;
        Ok(Some(RecrawlDecisionV1 {
            request,
            change,
            interval_ms,
            change_rate_permille,
            rank_key,
        }))
    }
}
/// A settled rendition proposed under a real browser session lease.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ObservedRequestV1 {
    /// Session authority; URL and bootstrap leases are not accepted.
    pub lease: crate::custody::CustodyLease,
    /// Exact settled observation identity within that session.
    pub epoch: crate::ObservationEpoch,
    /// Original settled capture time, bound to the immutable observation marker.
    pub acquired_at: Timestamp,
    /// GET proposal; storage assigns the bounded revisit generation.
    pub envelope: RequestEnvelopeV1,
}
impl ObservedRequestV1 {
    /// Construct a rendition proposal without granting append authority.
    #[must_use]
    pub fn new(
        lease: crate::custody::CustodyLease,
        epoch: crate::ObservationEpoch,
        envelope: RequestEnvelopeV1,
        acquired_at: Timestamp,
    ) -> Self {
        Self {
            lease,
            epoch,
            acquired_at,
            envelope,
        }
    }
    /// Rebuild a staged observation without changing its original capture time.
    ///
    /// # Errors
    /// Rejects missing or malformed acquisition-time evidence.
    pub fn from_staged(
        lease: crate::custody::CustodyLease,
        epoch: crate::ObservationEpoch,
        envelope: RequestEnvelopeV1,
    ) -> Result<Self, StoreError> {
        let acquired_at = envelope
            .metadata
            .get("observed_acquired_at")
            .ok_or(StoreError::LeaseLost)?;
        let acquired_at = serde_json::from_value(acquired_at.clone())
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(Self::new(lease, epoch, envelope, acquired_at))
    }
    /// Opaque identity shared by append replay and result publication.
    ///
    /// # Errors
    /// Rejects non-session authority or serialization failures.
    pub fn batch_id(&self, principal: &str) -> Result<Digest, StoreError> {
        let crate::custody::CustodySource::Session(session) = self.lease.source else {
            return Err(StoreError::AccessDenied(
                "observation requires session authority".into(),
            ));
        };
        Digest::of_value(
            "crawlx/observed-request/v1",
            &(
                self.lease.tenant,
                self.lease.run,
                principal,
                self.envelope.url.key,
                session,
                self.lease.worker,
                self.lease.fence,
                self.epoch,
                self.acquired_at,
            ),
        )
        .map_err(|error| StoreError::Serialization(error.to_string()))
    }
    /// Normalize a trusted observed GET and bind its opaque marker to the session epoch.
    ///
    /// # Errors
    /// Rejects malformed or body-bearing proposals and non-session authority.
    pub fn prepare(&mut self, principal: &str) -> Result<(Digest, Digest), StoreError> {
        self.envelope
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        if self.envelope.method != "GET"
            || self.envelope.body.is_some()
            || self.envelope.header_control.is_some()
        {
            return Err(StoreError::AccessDenied(
                "observation requires a body-free GET".into(),
            ));
        }
        let batch = self.batch_id(principal)?;
        let scope = Digest::of_value(
            "crawlx/observed-scope/v1",
            &(
                self.lease.tenant,
                self.lease.run,
                principal,
                self.envelope.url.key,
            ),
        )
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
        self.envelope.parent = None;
        self.envelope.not_before = None;
        self.envelope.revisit_generation = 0;
        self.envelope.session_generation = None;
        self.envelope.dialect = crate::request::IdentityDialectV1::NativeV1;
        self.envelope.source_key = Some(scope);
        self.envelope.metadata.insert(
            "observed_acquired_at".into(),
            serde_json::to_value(self.acquired_at)?,
        );
        self.envelope
            .metadata
            .insert("observed_epoch".into(), serde_json::to_value(batch)?);
        let identity = self
            .envelope
            .identity(
                self.lease.tenant,
                self.lease.run,
                principal,
                &std::collections::BTreeMap::new(),
                1,
            )
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        Ok((batch, identity.key))
    }
}

/// Bounded, explicit rendition admission result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
#[must_use]
pub enum ObservedAppendV1 {
    /// New immutable frontier row.
    Appended {
        /// Exact row to lease.
        request_id: i64,
        /// Storage-assigned rendition generation.
        revisit_generation: u32,
    },
    /// Same session epoch already has a row; no new capacity was consumed.
    Duplicate {
        /// Existing immutable row.
        request_id: i64,
        /// Original storage-assigned generation.
        revisit_generation: u32,
    },
    /// Stored per-role, per-URL revisit limit has been reached.
    #[serde(rename = "revisit_cap_reached")]
    CapReached,
}

/// Atomic observed publication outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum ObservedCommitV1 {
    /// Session and URL fences authorized the complete result transaction.
    Committed,
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
    /// Worker-approved, body-free HEAD observation, published as a fixed `head_response` event.
    /// Storage validates its shape and queued method; this field grants no content approval authority.
    pub head_response: Option<serde_json::Value>,
    /// Opt-in hash-only arbitration, atomic with page, dataset and delivery publication.
    pub content_dedupe: Option<crate::digest_registry::ContentDedupeClaimV1>,
    /// Child requests applied in this transaction.
    pub children: Option<RequestBatchV1>,
    /// Accepted items committed under the same live request fence.
    pub accepted: Vec<crate::dataset::AcceptedBatchV1>,
    /// Extension/loader state deltas checked atomically with accepted items.
    pub state_deltas: Vec<crate::dataset::KvCasV1>,
    /// Complete bounded callback trail committed under the same request fence.
    pub extensions: Vec<crate::extensions::ExtensionReceiptV1>,
    /// Measured privacy-safe facts committed with this processing result.
    pub report_facts: Vec<crate::report_history::ReportFactV1>,
    /// Immutable delivery intents; transport acknowledgement happens separately.
    pub outbox: Vec<crate::dataset::DeliveryBatchV1>,
    /// Session and epoch checked by observed-capable stores in the result transaction.
    pub observation: Option<(crate::custody::CustodyLease, crate::ObservationEpoch)>,
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
            head_response: None,
            content_dedupe: None,
            children: None,
            accepted: Vec::new(),
            state_deltas: Vec::new(),
            extensions: Vec::new(),
            report_facts: Vec::new(),
            outbox: Vec::new(),
            observation: None,
        }
    }
    /// Validate bounded callback and report evidence before a result transaction.
    ///
    /// # Errors
    /// Rejects malformed callback sequences, foreign report scope and excessive facts.
    pub fn validate_processing_evidence(&self) -> Result<(), StoreError> {
        crate::extensions::validate_extension_receipts(&self.extensions)
            .map_err(|_| StoreError::Conflict("invalid extension attempt receipts".into()))?;
        if self.report_facts.len() > 64 {
            return Err(StoreError::Conflict("request report fact limit exceeded".into()));
        }
        for fact in &self.report_facts {
            fact.validate()?;
            let source_matches = match &self.observation {
                Some((lease, _)) => {
                    fact.tenant == lease.tenant && fact.source == lease.source && fact.fence == lease.fence
                }
                None => {
                    fact.fence == self.fence
                        && fact.source == crate::custody::CustodySource::Url(self.request_id)
                }
            };
            if fact.run != self.run || fact.request_id != Some(self.request_id) || !source_matches {
                return Err(StoreError::LeaseLost);
            }
        }
        Ok(())
    }
    /// Validate a closed, body-free acquisition observation and hash the immutable result receipt.
    /// Storage must separately check the queued HEAD method and bind `acquisition.tenant` to the
    /// admitted run's tenant. Workers must approve observation bytes before submitting them.
    /// `bodyBytes` describes only the final HEAD response. Acquisition byte counters may also
    /// include auxiliary HTTP work and are preserved unchanged.
    ///
    /// # Errors
    /// Returns a conflict for incompatible results, malformed observations or observations over 64 KiB.
    pub fn head_response_receipt(&self) -> Result<Option<Digest>, StoreError> {
        let Some(observation) = &self.head_response else {
            return Ok(None);
        };
        let bytes = serde_json::to_vec(observation)?;
        if bytes.len() > crate::acquisition::MAX_METADATA_BYTES {
            return Err(StoreError::Conflict(
                "HEAD response observation exceeds 64 KiB".into(),
            ));
        }
        let acquisition = observation
            .get("acquisition")
            .filter(|value| closed_head_acquisition(value))
            .and_then(|value| crate::acquisition::AcquisitionResultV1::deserialize(value).ok());
        let valid = matches!(self.status, FrontierStatus::Succeeded | FrontierStatus::Failed)
            && self.page.is_none()
            && self.content_dedupe.is_none()
            && self.document_ref.is_none()
            && self.children.is_none()
            && self.accepted.is_empty()
            && self.state_deltas.is_empty()
            && self.outbox.is_empty()
            && observation.as_object().is_some_and(|object| {
                object.len() == 6
                    && object.get("requestId").and_then(serde_json::Value::as_i64) == Some(self.request_id)
                    && object.get("method").and_then(serde_json::Value::as_str) == Some("HEAD")
                    && object.get("bodyBytes").and_then(serde_json::Value::as_u64) == Some(0)
                    && object
                        .get("status")
                        .and_then(serde_json::Value::as_u64)
                        .is_some_and(|status| {
                            (100..=599).contains(&status)
                                && (self.status != FrontierStatus::Succeeded
                                    || (200..=299).contains(&status)
                                    || status == 304)
                                && acquisition.as_ref().is_some_and(|acquisition| {
                                    acquisition.schema_version == 1
                                        && acquisition.run == self.run
                                        && acquisition.target_status.map(u64::from) == Some(status)
                                        && acquisition.wire_body.is_none()
                                        && acquisition.rendered_dom.is_none()
                                        && acquisition.retained_baseline.is_none()
                                        && acquisition.meta_refresh.is_none()
                                        && acquisition.extraction_succeeded != Some(true)
                                        && acquisition.representation
                                            == crate::acquisition::RepresentationV1::WireResponse
                                })
                        })
                    && object
                        .get("response_headers")
                        .and_then(serde_json::Value::as_object)
                        .is_some_and(|headers| {
                            headers.len() <= 128
                                && headers.iter().all(|(name, value)| {
                                    !name.is_empty()
                                        && name.len() <= 256
                                        && value.as_str().is_some_and(|value| value.len() <= 8192)
                                })
                        })
            });
        if !valid {
            return Err(StoreError::Conflict("invalid HEAD response observation".into()));
        }
        Ok(Some(
            Digest::of_value(
                "crawlx/head-response-receipt/v1",
                &(
                    self.run,
                    self.request_id,
                    self.fence,
                    self.expected_state_version,
                    self.status,
                    &self.reason,
                    self.acquisition_ref,
                    self.document_ref,
                    bytes.as_slice(),
                ),
            )
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
        ))
    }
}

// Ordinary acquisition DTOs allow forward-compatible keys. HEAD publication does not:
// ignoring a new body-bearing key here would persist its original, unparsed value in the event.
fn closed_head_acquisition(value: &serde_json::Value) -> bool {
    if !closed_head_object(
        value,
        &[
            "schemaVersion",
            "requestDigest",
            "run",
            "tenant",
            "session",
            "sessionGeneration",
            "requestedUrl",
            "finalUrl",
            "finalUrlEvidence",
            "redirects",
            "metaRefresh",
            "metaRefreshPolicy",
            "metaRefreshRevision",
            "targetStatus",
            "gatewayStatus",
            "contentType",
            "contentEncoding",
            "transportSucceeded",
            "extractionSucceeded",
            "representation",
            "wireBody",
            "retainedBaseline",
            "renderedDom",
            "decodedBytes",
            "wireBytes",
            "truncated",
            "backend",
            "connection",
            "dnsReport",
            "validation",
            "attempts",
            "attemptSummaries",
            "networkRequests",
            "networkRequestsObserved",
            "allowanceUsage",
            "elapsedMs",
            "elapsedScope",
            "evidenceTruncated",
        ],
    ) {
        return false;
    }
    let nested: &[(&str, &[&str])] = &[
        (
            "backend",
            &[
                "backendId",
                "implementation",
                "version",
                "buildDigest",
                "browser",
                "available",
                "limitations",
                "identityProfile",
            ],
        ),
        (
            "connection",
            &[
                "checkedOrigin",
                "peer",
                "peerChecked",
                "proxyRoute",
                "tlsVerification",
                "certificateObserved",
                "poolSession",
                "poolExitIp",
                "negotiatedProtocol",
            ],
        ),
        (
            "validation",
            &[
                "ruleSetVersion",
                "category",
                "signals",
                "retryDisposition",
                "contentAccepted",
            ],
        ),
        (
            "allowanceUsage",
            &[
                "attemptsReserved",
                "networkRequestsReserved",
                "decodedBytesReserved",
                "decodedBytesObserved",
                "evidenceIncomplete",
            ],
        ),
        ("metaRefreshPolicy", &["schemaVersion", "maxParserBytes"]),
    ];
    if !nested.iter().all(|(field, fields)| {
        value.get(*field).is_none_or(|value| {
            // Optional evidence may explicitly be null; typed parsing still rejects null
            // for required nested DTOs rather than replacing it with a default.
            value.is_null() || closed_head_object(value, fields)
        })
    }) {
        return false;
    }
    if let Some(policy) = value.get("metaRefreshPolicy").filter(|value| !value.is_null()) {
        // This policy's general DTO has serde defaults. Publication must not fill in
        // malformed partial evidence on the producer's behalf.
        if policy.get("schemaVersion").is_none() || policy.get("maxParserBytes").is_none() {
            return false;
        }
    }
    if let Some(browser) = value.get("backend").and_then(|backend| backend.get("browser")) {
        if !browser.is_null()
            && !closed_head_object(
                browser,
                &[
                    "chromium_version",
                    "cdp_revision",
                    "user_agent",
                    "pinned",
                    "launch_profile",
                    "console_capture",
                    "attached",
                ],
            )
        {
            return false;
        }
    }
    [
        ("redirects", &["url", "status"][..]),
        (
            "attemptSummaries",
            &["ordinal", "backendId", "targetStatus", "category"][..],
        ),
    ]
    .iter()
    .all(|(field, fields)| {
        value
            .get(*field)
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| values.iter().all(|value| closed_head_object(value, fields)))
    })
}

fn closed_head_object(value: &serde_json::Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|key| fields.contains(&key.as_str())))
}
/// Result transaction owner; dataset/outbox composition must use this same transaction.
#[async_trait]
pub trait RequestCommitRepo: Send + Sync + crate::digest_registry::DigestRegistryRepo {
    /// Seal accepted-item sources and retain the first terminal reason across crashes.
    /// `None` resumes pending work only; `Some` starts finalization. A terminal run's reason wins.
    /// Returns `None` when no recovery is pending or finalization already completed.
    /// # Errors
    /// Returns scope, reason or storage failures without partially sealing sources.
    async fn begin_feed_finalization(
        &self,
        run: CrawlRunId,
        reason: Option<crate::counters::TerminalReason>,
    ) -> Result<Option<crate::counters::TerminalReason>, StoreError>;
    /// Stage bounded immutable terminal-feed batches using committed source ranges.
    /// # Errors
    /// Returns scope, source, retention, identity or storage failures without partial writes.
    async fn stage_feed_batches(
        &self,
        run: CrawlRunId,
        batches: &[crate::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError>;

    /// Read an exact immutable terminal-feed manifest while its source is sealed.
    /// Returns `None` only when no batch with this run/feed/idempotency key was staged.
    ///
    /// # Errors
    /// Returns scope, finalization, source or retention failures without publishing a batch.
    async fn staged_feed_batch(
        &self,
        run: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<crate::dataset::DeliveryBatchV1>, StoreError>;

    /// Atomically publish eligible empty feed intents and seal the terminal run.
    /// # Errors
    /// Returns invalid status, producer, retention or storage failures without partial writes.
    async fn finalize_run_feeds(
        &self,
        run: CrawlRunId,
        status: crate::counters::RunStatus,
        reason: crate::counters::TerminalReason,
        empty_batches: &[crate::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError>;
    /// Claim the run's unfinished feed finalization as a fenced custody producer.
    ///
    /// The returned lease is the only authority under which terminal feed artifacts may be
    /// sealed. It lasts `ttl` and must be renewed through [`Self::renew_feed_finalizer`]; an
    /// unexpired claim by any worker makes this fail, and an expired one is taken over with a
    /// higher fence. Finalization completing ([`Self::finalize_run_feeds`]) ends the lease.
    ///
    /// # Errors
    /// Returns scope, `Conflict` while another claim is live, or `LeaseLost` when the run has no
    /// unfinished finalization.
    async fn claim_feed_finalizer(
        &self,
        run: CrawlRunId,
        worker: crate::WorkerId,
        ttl: std::time::Duration,
    ) -> Result<crate::custody::CustodyLease, StoreError>;
    /// Extend a live finalizer lease to `ttl` from now.
    ///
    /// # Errors
    /// Returns `LeaseLost` when the lease expired, was taken over or the finalization ended.
    async fn renew_feed_finalizer(
        &self,
        lease: &crate::custody::CustodyLease,
        ttl: std::time::Duration,
    ) -> Result<(), StoreError>;
    /// Give up a finalizer lease so another worker may claim it at once. Idempotent.
    ///
    /// # Errors
    /// Returns scope or storage failures.
    async fn release_feed_finalizer(&self, lease: &crate::custody::CustodyLease) -> Result<(), StoreError>;
    /// Append one settled rendition under live session authority and stored revisit limits.
    ///
    /// # Errors
    /// Returns lease loss, scope, quota or storage errors without frontier side effects.
    async fn append_observed_fenced(
        &self,
        _request: ObservedRequestV1,
    ) -> Result<ObservedAppendV1, StoreError> {
        Err(StoreError::AccessDenied("observed append unsupported".into()))
    }
    /// Lease only an already-acquired rendition receipt under its originating session.
    /// Worker drain does not discard this effect; this method never authorizes new dispatch.
    ///
    /// # Errors
    /// Returns cancellation, stale session authority, mismatched observation or storage errors.
    async fn lease_observed_fenced(
        &self,
        lease: &crate::custody::CustodyLease,
        epoch: crate::ObservationEpoch,
        request_id: i64,
    ) -> Result<Option<(crate::repo::FrontierEntry, i64)>, StoreError>;
    /// Publish a rendition under both its exact URL fence and its originating session fence.
    ///
    /// # Errors
    /// Returns lease loss, scope, state, retention or storage errors without publication.
    async fn commit_observed_fenced(
        &self,
        _commit: RequestCommitV1,
        _lease: crate::custody::CustodyLease,
        _epoch: crate::ObservationEpoch,
    ) -> Result<ObservedCommitV1, StoreError> {
        Err(StoreError::AccessDenied("observed commit unsupported".into()))
    }
    /// Validate live fence and state version, then persist result, page and children atomically.
    /// # Errors
    /// Returns lease loss, state conflict, quota or storage errors without partial writes.
    async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError>;
    /// Persist a complete nonterminal attempt trail before handing back its live fence.
    ///
    /// # Errors
    /// Rejects stale leases, malformed receipts and changed replay content.
    async fn record_extension_attempt(
        &self,
        _run: CrawlRunId,
        _request_id: i64,
        _fence: i64,
        _attempt: u32,
        _receipts: &[crate::extensions::ExtensionReceiptV1],
    ) -> Result<(), StoreError> {
        Err(StoreError::AccessDenied(
            "extension attempt persistence unsupported".into(),
        ))
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::acquisition::{
        AcquisitionAttemptV1, AcquisitionRedirectV1, AcquisitionResultV1, BackendCapabilitiesV1,
        UrlEvidenceV1, ValidationCategoryV1,
    };
    use serde_json::json;
    use uuid::Uuid;

    fn head_commit(status: u16) -> RequestCommitV1 {
        let run = CrawlRunId(Uuid::from_u128(1));
        let tenant = TenantId(Uuid::from_u128(2));
        let url = url::Url::parse("https://example.com/head").unwrap();
        let mut acquisition = AcquisitionResultV1::new(
            run,
            tenant,
            url.clone(),
            Digest::of("head-test", b"request"),
            BackendCapabilitiesV1::native_http("crawlx-fetch", "test"),
        );
        acquisition.target_status = Some(status);
        acquisition.transport_succeeded = true;
        acquisition.final_url = Some(url.clone());
        acquisition.final_url_evidence = UrlEvidenceV1::Observed;
        acquisition.redirects = vec![AcquisitionRedirectV1::observed(url, Some(302))];
        acquisition.attempts = 1;
        acquisition.network_requests = 2;
        acquisition.network_requests_observed = Some(2);
        acquisition.attempt_summaries = vec![AcquisitionAttemptV1::new(
            1,
            "native_http",
            Some(status),
            ValidationCategoryV1::Valid,
        )];
        acquisition.validation.category = ValidationCategoryV1::Valid;
        acquisition.validation.content_accepted = true;
        let mut commit = RequestCommitV1::terminal(run, 7, 3, 1, FrontierStatus::Succeeded, None);
        commit.head_response = Some(json!({
            "requestId": 7,
            "method": "HEAD",
            "status": status,
            "bodyBytes": 0,
            "response_headers": {"content-type": "text/html"},
            "acquisition": acquisition,
        }));
        commit
    }

    #[test]
    fn real_head_acquisition_preserves_nullable_evidence_and_actual_304() {
        for status in [200, 204, 304] {
            let mut commit = head_commit(status);
            let observation = commit.head_response.as_mut().unwrap();
            for key in [
                "metaRefresh",
                "metaRefreshPolicy",
                "metaRefreshRevision",
                "retainedBaseline",
                "elapsedScope",
            ] {
                observation["acquisition"][key] = serde_json::Value::Null;
            }
            let acquisition = AcquisitionResultV1::deserialize(&observation["acquisition"]).unwrap();
            assert_eq!(acquisition.target_status, Some(status));
            assert_eq!(acquisition.connection.peer_checked, None);
            assert_eq!(acquisition.extraction_succeeded, None);
            assert!(commit.head_response_receipt().unwrap().is_some());
        }
    }

    #[test]
    fn head_receipt_preserves_auxiliary_byte_accounting_and_unobserved_body_checks() {
        let mut commit = head_commit(200);
        let acquisition = &mut commit.head_response.as_mut().unwrap()["acquisition"];
        acquisition["decodedBytes"] = json!(512);
        acquisition["wireBytes"] = json!(1024);
        acquisition["allowanceUsage"] = json!({
            "attemptsReserved": 1,
            "networkRequestsReserved": 2,
            "decodedBytesReserved": 4096,
            "decodedBytesObserved": 512,
            "evidenceIncomplete": false,
        });
        acquisition["validation"]["signals"] = json!(["body_expectations_unobserved_head"]);
        assert!(commit.head_response_receipt().unwrap().is_some());
        commit.head_response.as_mut().unwrap()["bodyBytes"] = json!(1);
        assert!(commit.head_response_receipt().is_err());
    }

    #[test]
    fn head_receipt_rejects_unknown_keys_at_every_evidence_boundary() {
        for path in [
            "",
            "/acquisition",
            "/acquisition/backend",
            "/acquisition/connection",
            "/acquisition/validation",
            "/acquisition/redirects/0",
            "/acquisition/attemptSummaries/0",
            "/acquisition/allowanceUsage",
        ] {
            for payload in [serde_json::Value::Null, json!("hidden response body")] {
                let mut commit = head_commit(200);
                commit
                    .head_response
                    .as_mut()
                    .unwrap()
                    .pointer_mut(path)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("body".into(), payload);
                assert!(commit.head_response_receipt().is_err(), "{path}");
            }
        }
        for field in ["body", "html", "text", "document", "payload", "bodyRef"] {
            let mut commit = head_commit(200);
            commit.head_response.as_mut().unwrap()["acquisition"][field] = json!("hidden response body");
            assert!(commit.head_response_receipt().is_err(), "{field}");
        }
    }

    #[test]
    fn head_receipt_closes_optional_browser_and_policy_evidence() {
        let mut commit = head_commit(200);
        commit.head_response.as_mut().unwrap()["acquisition"]["backend"]["browser"] =
            json!(crate::observation::BrowserBuildInfo {
                chromium_version: "test".into(),
                cdp_revision: "test".into(),
                user_agent: "test".into(),
                pinned: false,
                launch_profile: crate::config::LaunchProfile::Standard,
                console_capture: false,
                attached: false,
            });
        commit.head_response.as_mut().unwrap()["acquisition"]["metaRefreshPolicy"] =
            json!(crate::acquisition::MetaRefreshPolicyV1::default());
        assert!(commit.head_response_receipt().unwrap().is_some());
        for path in ["/acquisition/backend/browser", "/acquisition/metaRefreshPolicy"] {
            let mut changed = commit.clone();
            changed.head_response.as_mut().unwrap().pointer_mut(path).unwrap()["body"] = json!("hidden body");
            // The ordinary DTO may ignore unknown evidence keys. The publication boundary cannot.
            assert!(changed.head_response_receipt().is_err(), "{path}");
        }
    }

    #[test]
    fn head_receipt_rejects_body_artifacts_extraction_and_document_results() {
        let artifact = crate::ArtifactRef {
            id: crate::ArtifactId(Uuid::from_u128(9)),
            digest: Digest::of("head-test", b"body"),
        };
        for field in ["wireBody", "renderedDom"] {
            let mut commit = head_commit(200);
            commit.head_response.as_mut().unwrap()["acquisition"][field] = json!(artifact);
            assert!(commit.head_response_receipt().is_err(), "{field}");
        }
        for (field, value) in [
            ("retainedBaseline", json!({})),
            ("extractionSucceeded", json!(true)),
            ("representation", json!("parsed_document")),
            ("metaRefresh", json!({})),
        ] {
            let mut commit = head_commit(200);
            commit.head_response.as_mut().unwrap()["acquisition"][field] = value;
            assert!(commit.head_response_receipt().is_err(), "{field}");
        }
        let mut commit = head_commit(200);
        commit.document_ref = Some(Digest::of("head-test", b"document"));
        assert!(commit.head_response_receipt().is_err());
    }

    #[test]
    fn head_receipt_rejects_foreign_run_status_mismatch_and_malformed_acquisition() {
        for (path, value) in [
            ("/acquisition/run", json!(CrawlRunId(Uuid::from_u128(99)))),
            ("/acquisition/tenant", json!("not-a-tenant")),
            ("/acquisition/targetStatus", json!(201)),
            ("/acquisition/targetStatus", serde_json::Value::Null),
            ("/acquisition/decodedBytes", json!("0")),
            ("/acquisition/connection", serde_json::Value::Null),
            ("/acquisition/schemaVersion", json!(2)),
            ("/acquisition/metaRefreshPolicy", json!({})),
            ("/acquisition", json!({})),
            ("/method", json!("GET")),
            ("/requestId", json!(8)),
            ("/status", json!(600)),
            ("/bodyBytes", json!("0")),
            ("/bodyBytes", json!(1)),
        ] {
            let mut commit = head_commit(200);
            let (parent, key) = path.rsplit_once('/').unwrap();
            commit
                .head_response
                .as_mut()
                .unwrap()
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), value);
            assert!(commit.head_response_receipt().is_err(), "{path}");
        }
        let mut commit = head_commit(200);
        commit
            .head_response
            .as_mut()
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("bodyBytes");
        assert!(commit.head_response_receipt().is_err());
    }

    #[test]
    fn head_receipt_bounds_headers_and_complete_encoded_observation() {
        let mut too_many = serde_json::Map::new();
        for index in 0..129 {
            too_many.insert(format!("x-{index}"), json!("value"));
        }
        for headers in [
            json!({"x": 1}),
            json!({"": "value"}),
            json!({ ("x".repeat(257)): "value" }),
            json!({"x": "v".repeat(8193)}),
            serde_json::Value::Object(too_many),
        ] {
            let mut commit = head_commit(200);
            commit.head_response.as_mut().unwrap()["response_headers"] = headers;
            assert!(commit.head_response_receipt().is_err());
        }
        let mut commit = head_commit(200);
        let mut headers = serde_json::Map::new();
        for index in 0..8 {
            headers.insert(format!("x-{index}"), json!("v".repeat(8192)));
        }
        commit.head_response.as_mut().unwrap()["response_headers"] = serde_json::Value::Object(headers);
        assert!(matches!(
            commit.head_response_receipt(),
            Err(StoreError::Conflict(reason)) if reason == "HEAD response observation exceeds 64 KiB"
        ));
    }

    #[test]
    fn head_receipt_hashes_complete_approved_observation_and_result_contract() {
        let commit = head_commit(200);
        let original = commit.head_response_receipt().unwrap().unwrap();
        assert_eq!(commit.head_response_receipt().unwrap(), Some(original));
        let mut changed = commit.clone();
        changed.head_response.as_mut().unwrap()["acquisition"]["elapsedMs"] = json!(9);
        assert_ne!(changed.head_response_receipt().unwrap(), Some(original));
        let mut changed = commit.clone();
        changed.reason = Some("metadata_only".into());
        assert_ne!(changed.head_response_receipt().unwrap(), Some(original));
        let mut changed = commit.clone();
        changed.acquisition_ref = Some(Digest::of("head-test", b"acquisition"));
        assert_ne!(changed.head_response_receipt().unwrap(), Some(original));
        let mut changed = commit.clone();
        changed.expected_state_version = 2;
        assert_ne!(changed.head_response_receipt().unwrap(), Some(original));
        let mut changed = commit;
        changed.fence = 4;
        assert_ne!(changed.head_response_receipt().unwrap(), Some(original));
    }
}

#[cfg(test)]
mod adaptive_schedule_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn now() -> Timestamp {
        "2026-01-01T00:00:00Z".parse().unwrap()
    }

    fn request() -> RequestEnvelopeV1 {
        let url = url::Url::parse("https://schedule.test/page").unwrap();
        RequestEnvelopeV1::get(
            crate::url::CanonicalUrl {
                key: Digest::of("schedule-test", b"url"),
                origin: url.origin().ascii_serialization(),
                route_template: crate::url::RouteTemplate(url.path().into()),
                params: Vec::new(),
                url,
            },
            0,
            None,
        )
    }

    fn policy() -> RecrawlPolicyV1 {
        RecrawlPolicyV1 {
            version: 1,
            min_interval_ms: 100,
            max_interval_ms: 10_000,
            max_visits: 10,
            end_at: now() + chrono::Duration::hours(1),
            validator_mode: RecrawlValidatorModeV1::Disabled,
            adaptive: Some(AdaptiveRecrawlV1::default()),
        }
    }

    fn commit(status: FrontierStatus, digest: Option<Digest>) -> RequestCommitV1 {
        let mut commit =
            RequestCommitV1::terminal(CrawlRunId(uuid::Uuid::from_u128(1)), 9, 7, 1, status, None);
        if let Some(content_digest) = digest {
            commit.page = Some(crate::repo::PageRecord {
                run: commit.run,
                frontier_id: commit.request_id,
                url: request().url,
                status: 200,
                content_type: None,
                content_digest,
                title: None,
                markdown: None,
                html: None,
                metadata: serde_json::json!({}),
                links: Vec::new(),
                fetched_at: now(),
                lane: crate::traffic::TrustLane::Diagnostic,
            });
        }
        commit
    }

    #[test]
    fn hand_computed_changed_unchanged_and_error_intervals() {
        let old = Digest::of("schedule-test", b"old");
        let new = Digest::of("schedule-test", b"new");
        let baseline = RecrawlBaselineV1::new(Some(old), now(), 1000);
        for (status, digest, expected_change, interval, rate) in [
            (
                FrontierStatus::Succeeded,
                Some(new),
                RecrawlChangeV1::Changed,
                500,
                625,
            ),
            (
                FrontierStatus::Succeeded,
                Some(old),
                RecrawlChangeV1::Unchanged,
                2000,
                375,
            ),
            (FrontierStatus::Failed, None, RecrawlChangeV1::Error, 4000, 500),
            (
                FrontierStatus::Succeeded,
                None,
                RecrawlChangeV1::Unknown,
                1000,
                500,
            ),
        ] {
            let decision = policy()
                .next_visit_after_commit(
                    &request(),
                    &commit(status, digest),
                    now(),
                    policy().end_at,
                    Some(&baseline),
                )
                .unwrap()
                .unwrap();
            assert_eq!(decision.change, expected_change);
            assert_eq!(decision.interval_ms, interval);
            assert_eq!(decision.change_rate_permille, rate);
            assert_eq!(decision.request.revisit_generation, 1);
            assert_eq!(decision.request.parent, Some(9));
            assert_eq!(
                decision.request.not_before,
                Some(now() + chrono::Duration::milliseconds(i64::try_from(interval).unwrap()))
            );
        }
    }

    #[test]
    fn bounds_deadline_generation_and_denial_are_not_overridden() {
        let old = Digest::of("schedule-test", b"old");
        let baseline = RecrawlBaselineV1::new(Some(old), now(), 9000);
        let failed = commit(FrontierStatus::Failed, None);
        let decision = policy()
            .next_visit_after_commit(&request(), &failed, now(), policy().end_at, Some(&baseline))
            .unwrap()
            .unwrap();
        assert_eq!(decision.interval_ms, 10_000);
        assert!(policy()
            .next_visit_after_commit(
                &request(),
                &failed,
                now(),
                now() + chrono::Duration::seconds(10),
                Some(&baseline),
            )
            .unwrap()
            .is_none());
        let mut exhausted = request();
        exhausted.revisit_generation = 9;
        assert!(policy()
            .next_visit_after_commit(&exhausted, &failed, now(), policy().end_at, None,)
            .unwrap()
            .is_none());
        for denied in [
            FrontierStatus::PolicyBlocked,
            FrontierStatus::RobotsBlocked,
            FrontierStatus::Abandoned,
        ] {
            assert!(policy()
                .next_visit_after_commit(&request(), &commit(denied, None), now(), policy().end_at, None,)
                .unwrap()
                .is_none());
        }
        let mut invalid_rate = RecrawlBaselineV1::new(Some(old), now(), 1000);
        invalid_rate.change_rate_permille = 1001;
        assert!(policy()
            .next_visit_after_commit(&request(), &failed, now(), policy().end_at, Some(&invalid_rate),)
            .is_err());
        let minimum = RecrawlBaselineV1::new(Some(old), now(), 100);
        let modified = commit(
            FrontierStatus::Succeeded,
            Some(Digest::of("schedule-test", b"new")),
        );
        assert_eq!(
            policy()
                .next_visit_after_commit(&request(), &modified, now(), policy().end_at, Some(&minimum),)
                .unwrap()
                .unwrap()
                .interval_ms,
            100
        );
        let future = RecrawlBaselineV1::new(Some(old), now() + chrono::Duration::seconds(1), 1000);
        assert!(policy()
            .next_visit_after_commit(&request(), &failed, now(), policy().end_at, Some(&future),)
            .is_err());
    }

    #[test]
    fn typed_status_eligibility_executes_in_native_commit_schedule() {
        let digest = Digest::of("schedule-test", b"body");
        let mut policy = policy();
        policy.adaptive.as_mut().unwrap().ranking.status_range = Some((200, 299));
        assert!(policy
            .next_visit_after_commit(
                &request(),
                &commit(FrontierStatus::Failed, None),
                now(),
                policy.end_at,
                None,
            )
            .unwrap()
            .is_none());
        let accepted = policy
            .next_visit_after_commit(
                &request(),
                &commit(FrontierStatus::Succeeded, Some(digest)),
                now(),
                policy.end_at,
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(accepted.request.metadata["crawlx_recrawl_rank_v1"], 0);
        policy.adaptive.as_mut().unwrap().ranking.version = 2;
        assert!(policy.validate().is_err());
    }

    #[test]
    fn immutable_generation_history_survives_restart() {
        let old = Digest::of("schedule-test", b"old");
        let baseline = RecrawlBaselineV1::new(Some(old), now(), 1000);
        let first = policy()
            .next_visit_after_commit(
                &request(),
                &commit(FrontierStatus::Succeeded, Some(old)),
                now(),
                policy().end_at,
                Some(&baseline),
            )
            .unwrap()
            .unwrap();
        let restored: RequestEnvelopeV1 =
            serde_json::from_slice(&serde_json::to_vec(&first.request).unwrap()).unwrap();
        let at = now() + chrono::Duration::seconds(2);
        let second = policy()
            .next_visit_after_commit(
                &restored,
                &commit(FrontierStatus::Succeeded, Some(old)),
                at,
                policy().end_at,
                None,
            )
            .unwrap()
            .unwrap();
        assert_eq!(second.interval_ms, 4000);
        assert_eq!(second.change_rate_permille, 281);
        assert_eq!(second.request.revisit_generation, 2);
        assert_eq!(request().revisit_generation, 0);
    }
}
