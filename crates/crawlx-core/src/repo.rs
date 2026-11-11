//! Repository and service traits. `crawlx-storage`
//! implements the repositories; `crawlx-safety` implements `SafetyGate`.

use crate::config::CreateCrawl;
use crate::counters::{ActionStatus, PlaneCounters, ReconcileResolution, RunStatus, TerminalReason};
use crate::epoch::ObservationEpoch;
use crate::error::StoreError;
use crate::identity::{ActionContextKey, ElementIdentityHash};
use crate::ids::*;
use crate::observation::{ActionReceipt, BrowserBuildInfo, SettleReport};
use crate::proposal::ActionProposal;
use crate::safety::SafetyVerdict;
use crate::seed::CrawlSeed;
use crate::state::{MaskSet, StateSignature};
use crate::time::Timestamp;
use crate::traffic::{TrafficEvent, TrustLane};
use crate::url::CanonicalUrl;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A run as stored.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct CrawlRun {
    /// Run identifier, assigned at creation and stable for the run's lifetime.
    pub id: CrawlRunId,
    /// Tenant that owns the run; scopes access and idempotency keys.
    pub tenant: TenantId,
    /// Current lifecycle status of the run.
    pub status: RunStatus,
    /// Why the run ended; `Some` exactly when `status` is terminal.
    pub terminal_reason: Option<TerminalReason>,
    /// Crawl request the run was created from.
    pub config: CreateCrawl,
    /// Content digest of `config`, identifying the exact configuration the run started with.
    pub config_digest: crate::hash::Digest,
    /// Seed URLs the crawl starts from.
    pub seed: CrawlSeed,
    /// Policy rule-set version in force for the run, recorded on every safety audit row.
    pub policy_version: u32,
    /// Progress counters per plane (URLs, interactions, states).
    pub counters: PlaneCounters,
    /// When the run was created.
    pub created_at: Timestamp,
    /// When the run first entered `running`; `None` until then.
    pub started_at: Option<Timestamp>,
    /// When the run reached a terminal status; `None` while it is still active.
    pub finished_at: Option<Timestamp>,
    /// Trace id of the worker's `crawl` span; `None` until a
    /// worker started the run.
    #[serde(default)]
    pub trace_id: Option<TraceId>,
}

/// Durable run view that never requires a retained seed URL or operational configuration.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct RunMetadata {
    /// Stable run identifier.
    pub id: CrawlRunId,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Current lifecycle state.
    pub status: RunStatus,
    /// Terminal reason, present only for terminal states.
    pub terminal_reason: Option<TerminalReason>,
    /// Hash of the original operational configuration.
    pub config_digest: crate::hash::Digest,
    /// Deterministic seed.
    pub seed: CrawlSeed,
    /// Safety policy version.
    pub policy_version: u32,
    /// Progress counters.
    pub counters: PlaneCounters,
    /// Creation time.
    pub created_at: Timestamp,
    /// Execution start time.
    pub started_at: Option<Timestamp>,
    /// Execution finish time.
    pub finished_at: Option<Timestamp>,
    /// Worker trace identifier.
    pub trace_id: Option<TraceId>,
    /// Retention policy without operational content.
    pub retention: crate::config::Retention,
    /// Safety profile.
    pub safety_profile: crate::config::SafetyProfile,
    /// Enabled crawl planes.
    pub mode: crate::config::CrawlMode,
    /// Configured execution time budget.
    pub duration_seconds: u32,
    /// Query canonicalization policy.
    pub query_policy: crate::config::QueryPolicy,
    /// Requested output representations.
    pub output_formats: Vec<crate::config::OutputFormat>,
    /// Whether a webhook was configured; its URL is never included.
    pub webhook_configured: bool,
    /// Scrape job kind, if configured.
    pub scrape_kind: Option<crate::scrape::JobKind>,
    /// Number of requested input pages, without their URLs.
    pub batch_total: usize,
}

impl From<&CrawlRun> for RunMetadata {
    fn from(run: &CrawlRun) -> Self {
        Self {
            id: run.id,
            tenant: run.tenant,
            status: run.status,
            terminal_reason: run.terminal_reason,
            config_digest: run.config_digest,
            seed: run.seed,
            policy_version: run.policy_version,
            counters: run.counters,
            created_at: run.created_at,
            started_at: run.started_at,
            finished_at: run.finished_at,
            trace_id: run.trace_id,
            retention: run.config.retention.clone(),
            safety_profile: run.config.safety.profile,
            mode: run.config.mode,
            duration_seconds: run.config.limits.duration_seconds,
            query_policy: run.config.scope.query_policy,
            output_formats: run.config.output.formats.clone(),
            webhook_configured: run.config.output.webhook.is_some(),
            scrape_kind: run.config.scrape.as_ref().map(|job| job.kind),
            batch_total: 1_usize.saturating_add(run.config.scrape.as_ref().map_or(0, |job| job.urls.len())),
        }
    }
}

/// A leased browser execution slot or HTTP coordinator.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct CrawlSession {
    /// Session identifier.
    pub id: SessionId,
    /// Run this session belongs to.
    pub run: CrawlRunId,
    /// Execution responsibility, independent of whether a browser has launched.
    #[serde(default)]
    pub kind: SessionKind,
    /// Principal (role) the session acts as.
    pub role: PrincipalId,
    /// 1-based repetition of the role within the run; `(run, role, run_index)` is unique.
    pub run_index: u16,
    /// Position in the run's round-robin order, `(run_index - 1) * n_roles + role_ordinal`; a session starts only after every lower slot is terminal.
    pub schedule_slot: u32,
    /// Current lifecycle status of the session.
    pub status: SessionStatus,
    /// Browser build the session runs on; `None` until a browser is launched for it.
    pub browser: Option<BrowserBuildInfo>,
    /// Number of actions proposed so far in this session; the last assigned `ActionRecord::seq`.
    pub action_seq: u64,
}

/// Execution responsibility of a [`CrawlSession`].
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SessionKind {
    /// Browser actor execution, including sessions cancelled before browser launch.
    #[default]
    Browser,
    /// HTTP-only coordinator owning a real scheduler lease and session binding.
    HttpCoordinator,
}

impl SessionKind {
    /// Stable storage label, identical to the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::HttpCoordinator => "http_coordinator",
        }
    }
}

/// Lifecycle status of a [`CrawlSession`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Created and waiting for its schedule slot.
    Pending,
    /// Leased by a worker and executing.
    Running,
    /// Handed over after a graceful stop; awaits a new lease and in-flight actions are reconciled.
    Recovering,
    /// Finished all its work (terminal).
    Completed,
    /// Ended with an unrecoverable error (terminal).
    Failed,
    /// Stopped by cancellation (terminal).
    Cancelled,
}

impl SessionStatus {
    /// Stable snake_case name, identical to the serde representation and the storage value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Recovering => "recovering",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
    /// `true` for `Completed`, `Failed` and `Cancelled`; a terminal session never changes status again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Frontier row status.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum FrontierStatus {
    /// Waiting to be leased.
    Pending,
    /// Leased to a worker that is fetching it.
    Leased,
    /// Fetched and processed successfully.
    Succeeded,
    /// Fetch failed after the allowed attempts.
    Failed,
    /// Leased but not fetched because the run was cancelled or its budget exhausted.
    Abandoned,
    /// Host or resource could not be reached.
    Unreachable,
    /// Refused by the crawl scope or safety policy; `denial_reason` says which rule.
    PolicyBlocked,
    /// Refused by the site's robots.txt.
    RobotsBlocked,
}

impl FrontierStatus {
    /// Stable snake_case name, identical to the serde representation and the storage value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Abandoned => "abandoned",
            Self::Unreachable => "unreachable",
            Self::PolicyBlocked => "policy_blocked",
            Self::RobotsBlocked => "robots_blocked",
        }
    }
}

/// A URL-work frontier row or a fenced session-observation custody record.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct FrontierEntry {
    /// Frontier row identifier, unique across runs and increasing in discovery order.
    pub id: i64,
    /// Run the URL was discovered in.
    pub run: CrawlRunId,
    /// Canonical form of the URL.
    pub url: CanonicalUrl,
    /// Link distance from a seed; `0` for seeds.
    pub depth: u16,
    /// Current status of the row.
    pub status: FrontierStatus,
    /// Reason text for a policy or robots block, or the last error code; `None` otherwise.
    pub denial_reason: Option<String>,
    /// Number of times the row has been leased.
    pub attempts: u16,
    /// Frontier row of the page this URL was found on; `None` for seeds.
    pub discovered_from: Option<i64>,
}

/// Prefix of the reason of a frontier row the URL plane counted as `deduplicated`: a
/// `policy_blocked` row the URL-shape fingerprint filtered (`dedupe:fingerprint`) or a
/// `succeeded` page whose body duplicated another (`dedupe:content_exact`,
/// `dedupe:content_similar`).
pub const DEDUPE_REASON_PREFIX: &str = "dedupe:";

/// The URL-work rows of one run counted by status: the values the URL-plane counters are
/// re-derived from when a worker takes a run over (the stored counters are a snapshot,
/// the rows are the source). Of the discoveries, only those that left a row are here: a link to
/// a URL the run already knew leaves none, so `deduplicated` is not derivable and a recovered
/// run keeps the stored value ([`Self::deduplicated`] is its floor).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FrontierStateCounts {
    /// Rows in status `pending`.
    pub pending: u64,
    /// Rows in status `leased`, whether their holder is alive or not.
    pub leased: u64,
    /// Rows in status `succeeded`.
    pub succeeded: u64,
    /// Rows in status `failed`.
    pub failed: u64,
    /// Rows in status `unreachable`.
    pub unreachable: u64,
    /// Rows in status `abandoned`.
    pub abandoned: u64,
    /// Rows in status `policy_blocked`.
    pub policy_blocked: u64,
    /// Rows in status `robots_blocked`.
    pub robots_blocked: u64,
    /// Of `succeeded`: pages whose body duplicated another (reason [`DEDUPE_REASON_PREFIX`]);
    /// they were admitted, then moved to `deduplicated`.
    pub succeeded_duplicate: u64,
    /// Of `policy_blocked`: URLs the fingerprint filter refused (reason
    /// [`DEDUPE_REASON_PREFIX`]); they were counted `deduplicated` when discovered.
    pub policy_blocked_duplicate: u64,
}

impl FrontierStateCounts {
    /// Count `rows` (the frontier rows of one run); the in-memory store's definition, which the
    /// PostgreSQL `state_counts` query mirrors.
    #[must_use]
    pub fn tally<'a>(rows: impl IntoIterator<Item = &'a FrontierEntry>) -> Self {
        let mut out = Self::default();
        for r in rows {
            let duplicate = r
                .denial_reason
                .as_deref()
                .is_some_and(|reason| reason.starts_with(DEDUPE_REASON_PREFIX));
            match r.status {
                FrontierStatus::Pending => out.pending += 1,
                FrontierStatus::Leased => out.leased += 1,
                FrontierStatus::Succeeded => {
                    out.succeeded += 1;
                    out.succeeded_duplicate += u64::from(duplicate);
                }
                FrontierStatus::Failed => out.failed += 1,
                FrontierStatus::Unreachable => out.unreachable += 1,
                FrontierStatus::Abandoned => out.abandoned += 1,
                FrontierStatus::PolicyBlocked => {
                    out.policy_blocked += 1;
                    out.policy_blocked_duplicate += u64::from(duplicate);
                }
                FrontierStatus::RobotsBlocked => out.robots_blocked += 1,
            }
        }
        out
    }

    /// Rows the counters hold as `admitted`: discovered into the frontier and neither blocked
    /// nor reclassified as duplicates (`admitted` goes down when a page turns out a duplicate or
    /// a host reached its limit after admission).
    #[must_use]
    pub const fn admitted(&self) -> u64 {
        self.pending
            .saturating_add(self.leased)
            .saturating_add(self.succeeded.saturating_sub(self.succeeded_duplicate))
            .saturating_add(self.failed)
            .saturating_add(self.unreachable)
            .saturating_add(self.abandoned)
    }

    /// Rows the counters hold as `policy_blocked`: a block by scope, limits or safety, not a
    /// fingerprint duplicate.
    #[must_use]
    pub const fn blocked_by_policy(&self) -> u64 {
        self.policy_blocked.saturating_sub(self.policy_blocked_duplicate)
    }

    /// Rows the counters hold as `deduplicated`: the part of that counter a row proves.
    #[must_use]
    pub const fn deduplicated(&self) -> u64 {
        self.succeeded_duplicate
            .saturating_add(self.policy_blocked_duplicate)
    }
}

/// Result of discovering a URL.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryOutcome {
    /// Newly inserted as a pending frontier row.
    Admitted,
    /// Canonical URL already known in this run; nothing was inserted.
    Duplicate,
    /// Recorded as blocked by scope or safety policy.
    PolicyBlocked,
    /// Recorded as blocked by robots.txt.
    RobotsBlocked,
}

/// An extracted page (`pages`).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PageRecord {
    /// Run the page belongs to.
    pub run: CrawlRunId,
    /// Frontier row that was fetched to produce the page; `0` when unknown.
    pub frontier_id: i64,
    /// Canonical URL of the page.
    pub url: CanonicalUrl,
    /// HTTP status code of the response; `0` when none was recorded.
    pub status: u16,
    /// Response `Content-Type`; `None` when the response had none.
    pub content_type: Option<String>,
    /// Digest of the response content, for change detection and dedupe.
    pub content_digest: crate::hash::Digest,
    /// Document title; `None` when the page has none.
    pub title: Option<String>,
    /// Stored Markdown rendition of the content; `None` when not produced or not retained.
    pub markdown: Option<ArtifactRef>,
    /// Stored HTML snapshot; `None` when not produced or not retained.
    pub html: Option<ArtifactRef>,
    /// Extracted structured metadata (JSON object; empty when none was found).
    pub metadata: serde_json::Value,
    /// Outgoing link URLs found on the page, in document order.
    pub links: Vec<String>,
    /// When the page was fetched.
    pub fetched_at: Timestamp,
    /// Trust lane the page was obtained through; fetch-plane pages are diagnostic.
    pub lane: TrustLane,
}

/// Path in [`PageRecord::metadata`] of the flag a stored scrape carries when it must not be
/// served from the cache or listed in a URL map (`ScrapeDocument::not_cacheable`: `storeInCache:
/// false`, a zero-data-retention run or a non-2xx answer).
pub const NOT_CACHEABLE_PATH: [&str; 2] = [crate::scrape::ScrapeDocument::METADATA_KEY, "notCacheable"];

impl PageRecord {
    /// Mark a read projection whose immutable epoch has no attributable late-XHR receipt.
    /// Initial capture-time `xhr_requests` remain unchanged; URL-wide late aggregates must
    /// not be merged into this rendition or written back as a replacement capture.
    pub fn mark_late_xhr_unattributed(&mut self) {
        if !self.metadata.is_object() {
            self.metadata = serde_json::json!({"capture_metadata": std::mem::take(&mut self.metadata)});
        }
        self.metadata["late_xhr_attribution"] =
            serde_json::Value::String("late_xhr_not_epoch_attributed".into());
    }
    /// Does the page's metadata flag it as not cacheable ([`NOT_CACHEABLE_PATH`])?
    #[must_use]
    pub fn is_not_cacheable(&self) -> bool {
        NOT_CACHEABLE_PATH
            .iter()
            .try_fold(&self.metadata, |value, key| value.get(*key))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }
}

/// What a stored page tells a URL listing: its own URL and the links found on it
/// ([`PageRepo::known_pages`]).
#[derive(Clone, PartialEq, Debug)]
pub struct KnownPage {
    /// Canonical URL of the page.
    pub url: CanonicalUrl,
    /// Document title; `None` when the page has none.
    pub title: Option<String>,
    /// `description` of the page's extracted metadata; `None` when it has none.
    pub description: Option<String>,
    /// Outgoing link URLs found on the page, in document order.
    pub links: Vec<String>,
}

/// An `actions` row as stored.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ActionRecord {
    /// Action identifier.
    pub id: ActionId,
    /// Run the action belongs to.
    pub run: CrawlRunId,
    /// Session that performs the action.
    pub session: SessionId,
    /// Per-session sequence number, assigned at proposal and strictly increasing.
    pub seq: u64,
    /// Action context (principal, route, element, kind, input class, resource, cluster) the action ran in.
    pub key: ActionContextKey,
    /// Current journal status of the action.
    pub status: ActionStatus,
    /// Execution attempt number; incremented when a reconciled `not_applied` action is re-intended.
    pub attempt: u16,
    /// Name of the strategy that proposed the action.
    pub strategy: String,
    /// Version of the proposing strategy.
    pub strategy_version: u32,
    /// Observation epoch the action was proposed or intended against.
    pub epoch: ObservationEpoch,
    /// Trust lane of the action, derived from its fidelity; `None` when not recorded.
    pub lane: Option<TrustLane>,
    /// How the action reaches the page; `None` when not recorded.
    pub fidelity: Option<crate::traffic::Fidelity>,
    /// Safety verdict that admitted (or held) the action.
    pub safety_decision: SafetyDecisionId,
    /// Model decision that influenced the proposal; `None` when no model was involved.
    pub model_decision: Option<ModelDecisionId>,
    /// State observed immediately before the action; `None` until it is intended.
    pub before_state: Option<StateId>,
    /// Outcome of reconciliation; `Some` only for actions that went through `unknown`.
    pub reconcile_resolution: Option<ReconcileResolution>,
    /// When the action was proposed.
    pub proposed_at: Timestamp,
    /// When the intent was made durable (T1); `None` while only proposed.
    pub intended_at: Option<Timestamp>,
    /// When the action reached a final status; `None` while it is still open.
    pub finished_at: Option<Timestamp>,
    /// Trace id of the span tree the proposal was journaled under (span-to-row
    /// join); `None` when the row was written outside a span.
    pub trace_id: Option<TraceId>,
}

/// The rows of one run's journal counted by the outcome they carry: the authoritative values
/// behind `interactions.succeeded`, `interactions.failed` and `interactions.unknown_outcome`
/// (the stored run counters are a snapshot, the journal rows are the source).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[non_exhaustive]
pub struct JournalOutcomes {
    /// Rows in status `succeeded`.
    pub succeeded: u64,
    /// Rows in status `failed`.
    pub failed: u64,
    /// Rows whose outcome was ever `unknown`: still `unknown`, `reconciled`, or re-intended
    /// after a `not_applied` verdict (the row then carries a reconcile resolution).
    pub unknown: u64,
}

impl JournalOutcomes {
    /// The counts of `succeeded`, `failed` and ever-`unknown` rows.
    #[must_use]
    pub const fn new(succeeded: u64, failed: u64, unknown: u64) -> Self {
        Self {
            succeeded,
            failed,
            unknown,
        }
    }

    /// Count `rows` (the journal rows of one run) by outcome; the in-memory store's
    /// definition, which the PostgreSQL `outcome_counts` query mirrors.
    #[must_use]
    pub fn tally<'a>(rows: impl IntoIterator<Item = &'a ActionRecord>) -> Self {
        let mut out = Self::default();
        for r in rows {
            match r.status {
                ActionStatus::Succeeded => out.succeeded += 1,
                ActionStatus::Failed => out.failed += 1,
                _ => {}
            }
            if matches!(r.status, ActionStatus::Unknown | ActionStatus::Reconciled)
                || r.reconcile_resolution.is_some()
            {
                out.unknown += 1;
            }
        }
        out
    }
}

/// Everything T2 writes atomically.
#[derive(Clone, Debug)]
pub struct OutcomeRecord {
    /// Final status to record for the action.
    pub status: ActionStatus,
    /// Receipt of the dispatched action; `None` when it was never dispatched.
    pub receipt: Option<ActionReceipt>,
    /// Report of the post-action settle wait; `None` when no settle was performed.
    pub settle: Option<SettleReport>,
    /// State observed after the action; `None` when no observation was taken.
    pub after_state: Option<NewState>,
    /// Network traffic captured during the action's network epoch.
    pub traffic: Vec<TrafficEvent>,
    /// Failure description; `None` on success.
    pub error: Option<String>,
    /// When the action finished.
    pub finished_at: Timestamp,
}

/// A new immutable observation to persist.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct NewState {
    /// State identifier.
    pub id: StateId,
    /// Session that made the observation.
    pub session: SessionId,
    /// Observation epoch the state was captured at.
    pub epoch: ObservationEpoch,
    /// Canonical URL of the observed document.
    pub url: CanonicalUrl,
    /// Fingerprint of the observation.
    pub signature: StateSignature,
    /// Volatile regions excluded when the signature was computed.
    pub masks: MaskSet,
    /// Cluster the state was assigned to.
    pub cluster: StateClusterId,
    /// Similarity in `[0.0, 1.0]` between the state and its cluster prototype.
    pub cluster_similarity: f32,
    /// `true` when the state founded `cluster` (it is the cluster prototype).
    pub cluster_is_new: bool,
    /// Stored artifacts as `(kind, reference)` pairs, e.g. `("manifest", ..)`.
    pub artifacts: Vec<(String, ArtifactRef)>,
    /// When the observation was made.
    pub observed_at: Timestamp,
}

/// Reconciliation result for an `unknown` action.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct Reconciliation {
    /// How the unknown action turned out (applied, not applied, ...).
    pub resolution: ReconcileResolution,
    /// Evidence supporting the resolution (JSON; shape depends on the reconciler).
    pub evidence: serde_json::Value,
    /// When the reconciliation was decided.
    pub reconciled_at: Timestamp,
}

/// T1/T2 journal. Implemented by `crawlx-storage` and by an
/// in-memory fake for tests.
#[async_trait]
pub trait ActionJournal: Send + Sync {
    /// Record a proposal (status `proposed`) with its safety decision.
    async fn propose(
        &self,
        run: CrawlRunId,
        session: SessionId,
        p: &ActionProposal,
        v: &SafetyVerdict,
    ) -> Result<ActionId, StoreError>;
    /// T1: `proposed → intended`. Durable before returning.
    async fn intend(
        &self,
        id: ActionId,
        session: SessionId,
        epoch: ObservationEpoch,
    ) -> Result<(), StoreError>;
    /// T2: outcome + transition + traffic + ledger, atomically.
    async fn finish(&self, id: ActionId, outcome: OutcomeRecord) -> Result<(), StoreError>;
    /// Resolve a full action UUID to its collision-free allocated volatile content namespace.
    ///
    /// # Errors
    /// Returns missing, retention or unsupported capability errors.
    async fn dataset_page(&self, id: ActionId) -> Result<i64, StoreError> {
        let _ = id;
        Err(StoreError::Unavailable(
            "action dataset namespace unavailable".into(),
        ))
    }
    /// T2 with accepted items, extension CAS and outbox under the same live session fence.
    ///
    /// # Errors
    /// Returns lease loss, CAS/quota errors or unsupported capability without partial writes.
    async fn finish_with_accepted(
        &self,
        id: ActionId,
        outcome: OutcomeRecord,
        session_fence: i64,
        accepted: Vec<crate::dataset::AcceptedBatchV1>,
        state_deltas: Vec<crate::dataset::KvCasV1>,
        outbox: Vec<crate::dataset::DeliveryBatchV1>,
    ) -> Result<(), StoreError> {
        let _ = session_fence;
        if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            return Err(StoreError::Unavailable(
                "atomic browser accepted-item commit unavailable".into(),
            ));
        }
        self.finish(id, outcome).await
    }
    /// Reaper: `intended → unknown` for actions whose lease expired before `expired_before`.
    async fn mark_unknown(&self, expired_before: Timestamp) -> Result<Vec<ActionId>, StoreError>;
    /// `unknown → reconciled`.
    async fn reconcile(&self, id: ActionId, r: Reconciliation) -> Result<(), StoreError>;
    /// Reconcile a known applied effect and commit its accepted projection in that transaction.
    ///
    /// # Errors
    /// Returns lease loss, unsupported capability or state/CAS/quota errors without partial writes.
    async fn reconcile_with_accepted(
        &self,
        id: ActionId,
        r: Reconciliation,
        session_fence: i64,
        accepted: Vec<crate::dataset::AcceptedBatchV1>,
        state_deltas: Vec<crate::dataset::KvCasV1>,
        outbox: Vec<crate::dataset::DeliveryBatchV1>,
    ) -> Result<(), StoreError> {
        let _ = session_fence;
        if !accepted.is_empty() || !state_deltas.is_empty() || !outbox.is_empty() {
            return Err(StoreError::Unavailable(
                "atomic reconciliation accepted-item commit unavailable".into(),
            ));
        }
        self.reconcile(id, r).await
    }
    /// Load one action by id.
    async fn get(&self, id: ActionId) -> Result<ActionRecord, StoreError>;
    /// Actions of `run`, optionally only those in `status`, ordered by proposal time then sequence.
    async fn list(
        &self,
        run: CrawlRunId,
        status: Option<ActionStatus>,
    ) -> Result<Vec<ActionRecord>, StoreError>;
    /// The rows of `run` counted by outcome ([`JournalOutcomes`]); recovery re-derives the
    /// run's interaction counters from it instead of trusting the stored snapshot.
    async fn outcome_counts(&self, run: CrawlRunId) -> Result<JournalOutcomes, StoreError>;
}

/// Runs and sessions.
#[async_trait]
pub trait RunRepo: Send + Sync {
    /// Insert a new run; with an idempotency key, record it so a repeated create can be recognised.
    async fn create(&self, run: &CrawlRun, idempotency_key: Option<&str>) -> Result<(), StoreError>;
    /// Atomically insert a replay run, its sessions, and its immutable execution specification.
    ///
    /// `spec.sourceRunId` must identify an existing run owned by the same tenant.
    /// No session may become leaseable before its replay specification is durable.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an absent or foreign source, and a conflict
    /// for an existing run or invalid session slots. Failed inserts leave no rows behind.
    async fn create_replay(
        &self,
        run: &CrawlRun,
        sessions: &[CrawlSession],
        spec: &serde_json::Value,
    ) -> Result<(), StoreError>;
    /// Load a replay's execution specification; ordinary runs return `None`.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an absent run, or a storage/decoding error.
    async fn replay_spec(&self, run: CrawlRunId) -> Result<Option<serde_json::Value>, StoreError>;
    /// Load one run by id, excluding literal header and cookie secrets.
    async fn get(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError>;
    /// Load a run for execution, recovering literal request controls from volatile storage.
    ///
    /// Metadata and API consumers must use [`Self::get`] instead.
    ///
    /// # Errors
    /// Fails closed when literal request controls expired or this adapter cannot recover them.
    async fn get_for_execution(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let run = self.get(id).await?;
        if run.config.fetch.has_literal_secrets() {
            return Err(StoreError::RetentionDenied(
                "literal request controls require volatile execution storage".to_owned(),
            ));
        }
        Ok(run)
    }
    /// Load durable status and policy metadata without requiring ephemeral operational values.
    ///
    /// # Errors
    /// Returns a storage error for an absent or malformed run.
    async fn get_metadata(&self, id: CrawlRunId) -> Result<RunMetadata, StoreError> {
        Ok(RunMetadata::from(&self.get(id).await?))
    }
    /// Move the run to `status`; `reason` must be `Some` exactly when `status` is terminal, and a terminal run cannot change.
    async fn set_status(
        &self,
        id: CrawlRunId,
        status: RunStatus,
        reason: Option<TerminalReason>,
    ) -> Result<(), StoreError>;
    /// Overwrite the run's progress counters.
    async fn update_counters(&self, id: CrawlRunId, counters: PlaneCounters) -> Result<(), StoreError>;
    /// Insert the sessions of a run in one transaction.
    async fn create_sessions(&self, sessions: &[CrawlSession]) -> Result<(), StoreError>;
    /// Sessions of `run` ordered by `schedule_slot`.
    async fn list_sessions(&self, run: CrawlRunId) -> Result<Vec<CrawlSession>, StoreError>;
    /// Move a session to `status`; a terminal session cannot change.
    async fn set_session_status(&self, id: SessionId, status: SessionStatus) -> Result<(), StoreError>;
    /// Record the browser build a session launched with.
    async fn set_session_browser(&self, id: SessionId, info: &BrowserBuildInfo) -> Result<(), StoreError>;
    /// Record the trace id of the `crawl` span that executes the run. Idempotent; the last
    /// write wins.
    async fn set_trace_id(&self, run: CrawlRunId, trace_id: TraceId) -> Result<(), StoreError>;
}

/// URL-plane frontier.
#[async_trait]
pub trait FrontierRepo: Send + Sync {
    /// Atomically append bounded proposals and advance their loader cursor.
    /// Authority must come from the authenticated run, never page content.
    async fn append_batch(
        &self,
        batch: crate::orchestration::RequestBatchV1,
    ) -> Result<crate::orchestration::RequestBatchReceiptV1, StoreError>;
    /// Redacted queue metadata keyset page; limit must be between one and 1000.
    async fn page(&self, run: CrawlRunId, after: i64, limit: u32) -> Result<Vec<FrontierEntry>, StoreError>;
    /// Content-free keyset projection; volatile request expiry cannot hide queue state.
    async fn metadata_page(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<crate::orchestration::RequestMetadataV1>, StoreError>;
    /// Resolve a request in its owning run; legacy rows become native anonymous GET.
    async fn get_request(
        &self,
        run: CrawlRunId,
        id: i64,
    ) -> Result<crate::orchestration::QueuedRequestV1, StoreError>;
    /// Resolve exact queued methods for at most 1000 request ids in their owning run.
    /// Only true legacy rows imply GET; lost volatile envelopes remain typed errors.
    ///
    /// # Errors
    /// Returns invalid bounds, missing or foreign ids, malformed envelopes, or volatile custody loss.
    async fn request_methods(
        &self,
        run: CrawlRunId,
        ids: &[i64],
    ) -> Result<std::collections::BTreeMap<i64, String>, StoreError>;
    /// Close authenticated input using the current producer epoch.
    async fn seal(&self, run: CrawlRunId, expected_epoch: u64) -> Result<(), StoreError>;
    /// Report producer, cooldown and live-work state without loading the queue.
    async fn activity(&self, run: CrawlRunId)
        -> Result<crate::orchestration::FrontierActivityV1, StoreError>;
    /// Read committed loader checkpoint without scanning request content.
    async fn loader_cursor(
        &self,
        run: CrawlRunId,
        source: &str,
    ) -> Result<Option<crate::orchestration::LoaderCursorV1>, StoreError>;
    /// Record `url` at `depth` (found on frontier row `from`), returning the outcome and the new row id (`None` for a duplicate); `denial` stores it blocked instead of pending and must be a policy or robots status.
    async fn discover(
        &self,
        run: CrawlRunId,
        url: &CanonicalUrl,
        depth: u16,
        from: Option<i64>,
        denial: Option<(FrontierStatus, String)>,
    ) -> Result<(DiscoveryOutcome, Option<i64>), StoreError>;
    /// Lease up to `limit` pending URL-work rows of `run`, highest priority first, incrementing their `attempts`.
    /// Session-observation custody rows are never URL work, including after hand-back or expiry.
    /// Dynamic runs never grant ordinary URL-work leases, even for legacy rows without source proof.
    /// The lease ends when it expires and the reaper returns the row to `pending`, or when the
    /// holder finishes it; a holder that stays alive renews it (`LeaseRepo::heartbeat_frontier`).
    async fn lease_batch(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        limit: u32,
    ) -> Result<Vec<FrontierEntry>, StoreError> {
        Ok(self
            .lease_batch_fenced(run, worker, limit)
            .await?
            .into_iter()
            .map(|(entry, _)| entry)
            .collect())
    }
    /// [`Self::lease_batch`] that also returns each row's fencing token: the holder presents it
    /// to renew, complete or hand back the row, so a holder that was paused past its lease
    /// cannot touch a row the reaper returned and another worker leased since.
    async fn lease_batch_fenced(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        limit: u32,
    ) -> Result<Vec<(FrontierEntry, i64)>, StoreError>;
    /// Lease only `id` in `run`, with the same fencing, attempt charge and TTL as batch leasing.
    /// Returns `None` unless the row is pending URL work, eligible and belongs to a live run.
    /// Never leases or changes another row, even when the requested row is unavailable.
    ///
    /// # Errors
    /// Returns backend errors, or [`StoreError::Unavailable`] if exact-row leasing is unsupported.
    async fn lease_one_fenced(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        id: i64,
    ) -> Result<Option<(FrontierEntry, i64)>, StoreError> {
        let _ = (run, worker, id);
        Err(StoreError::Unavailable("exact frontier lease unavailable".into()))
    }
    /// Finish a leased row with a final `status`; `reason` is stored as the denial reason or error code.
    async fn complete(
        &self,
        id: i64,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError>;
    /// [`Self::complete`] for the holder of the lease `fence` ([`Self::lease_batch_fenced`]).
    ///
    /// # Errors
    /// [`StoreError::LeaseLost`] when the row is no longer leased under `fence` (its lease
    /// expired and the reaper returned it, or another worker leased it since),
    /// [`StoreError::IllegalTransition`] for a `status` a leased row cannot take,
    /// [`StoreError::NotFound`] for a missing row.
    async fn complete_fenced(
        &self,
        id: i64,
        fence: i64,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError>;
    /// Hand a leased row back unfetched, for a worker that drains in the middle of its batch: the
    /// row returns to `pending` at once and the lease does not count as an attempt, so the next
    /// worker attempts it as if it had never been leased. Only the holder of the lease `fence`
    /// can.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for a missing row, [`StoreError::LeaseLost`] when the row is no
    /// longer leased under `fence`.
    async fn give_back(&self, id: i64, fence: i64) -> Result<(), StoreError>;
    /// Return unfetched work to pending with durable future eligibility.
    /// Requires the same unexpired fence as completion and does not consume an attempt.
    async fn defer_fenced(&self, id: i64, fence: i64, not_before: Timestamp) -> Result<(), StoreError>;
    /// Return after an actual target attempt, retaining its charge; false means exhausted.
    async fn retry_fenced(&self, id: i64, fence: i64, not_before: Timestamp) -> Result<bool, StoreError>;
    /// Atomically reserve a conservative bound on all effects before acquisition dispatch.
    async fn reserve_effects_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        effects: u32,
    ) -> Result<(), StoreError>;
    /// Refund proven unused read-only effect escrow; identical settlement is idempotent.
    async fn settle_effects_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        reserved: u32,
        actual: u32,
    ) -> Result<(), StoreError>;
    /// Escrow all remaining native acquisition capacity under the current lease.
    /// A lost or unknown lease forfeits its escrow instead of resetting retry budgets.
    async fn reserve_acquisition_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
    ) -> Result<crate::acquisition::AcquisitionAllowanceV1, StoreError>;
    /// Refund only known unused native allowance, under the same unexpired lease.
    /// Repeating the identical settlement is idempotent; conflicting settlements fail.
    async fn settle_acquisition_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        usage: &crate::acquisition::AcquisitionUsageV1,
    ) -> Result<(), StoreError>;
    /// Number of URL-work rows of `run` still pending; excludes session-observation custody records.
    async fn pending_count(&self, run: CrawlRunId) -> Result<u64, StoreError>;
    /// Number of URL-work rows of `run` that are not finished: pending (retries waiting out their backoff
    /// included) or leased to a worker, alive or dead. A run's frontier is exhausted only when
    /// this is `0`; a row leased by a worker that died stays counted until its lease expires and
    /// the reaper returns it to `pending`.
    async fn open_count(&self, run: CrawlRunId) -> Result<u64, StoreError>;
    /// The rows of `run` counted by status ([`FrontierStateCounts`]); a worker that takes a run
    /// over re-derives the URL-plane counters from it instead of trusting the stored snapshot.
    /// Session-observation custody rows are excluded, regardless of their lifecycle status.
    /// Dynamic runs have no URL-work rows, including when historical observation provenance has expired.
    async fn state_counts(&self, run: CrawlRunId) -> Result<FrontierStateCounts, StoreError>;
    /// All frontier rows of `run` in discovery order, including session-observation custody records.
    async fn list(&self, run: CrawlRunId) -> Result<Vec<FrontierEntry>, StoreError>;
}

/// Numeric billing metadata that survives ZDR page delivery without retaining document content.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct PageBilling {
    /// Credits consumed by the stored pages.
    pub credits: u64,
    /// LLM tokens consumed by the stored pages.
    pub llm_tokens: u64,
    /// Number of stored pages, independent of acknowledgement or content expiry.
    pub pages: u64,
}

impl PageBilling {
    /// The exact numeric totals derived before content redaction.
    #[must_use]
    pub const fn new(credits: u64, llm_tokens: u64, pages: u64) -> Self {
        Self {
            credits,
            llm_tokens,
            pages,
        }
    }
}

/// Extracted pages.
#[async_trait]
pub trait PageRepo: Send + Sync {
    /// Insert or replace the latest page for the same run and URL.
    /// This projection write never creates committed capture evidence; use `RequestCommitRepo`.
    async fn put(&self, page: &PageRecord) -> Result<(), StoreError>;
    /// Pages of `run`; dynamic runs expose all immutable committed renditions in frontier-ID order.
    /// URL lookup projections keep the first observed rendition for each role.
    ///
    /// # Errors
    /// Returns scope, retention or storage errors when committed custody cannot be proved.
    async fn list(&self, run: CrawlRunId) -> Result<Vec<PageRecord>, StoreError>;
    /// At most 64 immutable committed captures, ordered by frontier ID, strictly after `after`.
    /// Every retained successful generation qualifies, independent of the latest URL projection.
    ///
    /// # Errors
    /// Returns an error if the backend cannot prove committed page custody.
    async fn committed_page_keyset(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<PageRecord>, StoreError> {
        let _ = (run, after, limit);
        Err(StoreError::Unavailable(
            "committed page keyset unavailable".into(),
        ))
    }
    /// Fetch one immutable committed generation by frontier identity, not its latest URL rendition.
    ///
    /// # Errors
    /// Returns a backend error or a committed-page capability error.
    async fn get_committed(&self, run: CrawlRunId, frontier: i64) -> Result<Option<PageRecord>, StoreError> {
        let mut rows = self
            .committed_page_keyset(run, frontier.saturating_sub(1), 1)
            .await?;
        Ok(rows.pop().filter(|row| row.frontier_id == frontier))
    }
    /// A metadata-only billing projection, if the backend stores one.
    /// `None` asks the caller to calculate from its live run configuration and full pages.
    ///
    /// # Errors
    /// Returns a storage error when the numeric projection cannot be read.
    async fn billing(&self, _run: CrawlRunId) -> Result<Option<PageBilling>, StoreError> {
        Ok(None)
    }
    /// The most recent pages of `tenant` whose canonical URL key equals `url`'s, newest first,
    /// across every run of the tenant, at most `limit`. Backs `maxAge`, `minAge`, `lockdown` and
    /// `changeTracking` of the scrape engine.
    async fn recent_for_url(
        &self,
        tenant: TenantId,
        url: &CanonicalUrl,
        limit: u32,
    ) -> Result<Vec<PageRecord>, StoreError>;
    /// The pages `tenant`'s earlier runs stored for one site, newest first, at most `limit`:
    /// those whose host is `domain` (case-insensitive, a trailing dot ignored) or, with
    /// `subdomains`, a subdomain of it. Only pages that may be listed are returned: an HTTP status
    /// below 400 (`0`, none recorded, counts), not [`PageRecord::is_not_cacheable`], of a run that
    /// is not a zero-data-retention run and has not expired at `now` (`created_at` plus
    /// `retention.days`, `0` days never). Backs the stored-URL sources of `POST /v2/map`.
    async fn known_pages(
        &self,
        tenant: TenantId,
        domain: &str,
        subdomains: bool,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<KnownPage>, StoreError>;
}

/// One state moved by a cluster split.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct SplitMember {
    /// The moved state.
    pub state: StateId,
    /// Similarity in `[0.0, 1.0]` between the state and the successor's recomputed prototype.
    pub similarity: f32,
}

/// A successor cluster version minted by a split.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct SplitSuccessor {
    /// Fresh cluster id (a split never reuses the source id).
    pub cluster: StateClusterId,
    /// Cluster version (`source_version + 1`).
    pub version: u32,
    /// Member elected prototype of the successor; must be one of `members`.
    pub prototype: StateId,
    /// Signature of `prototype`, what `StateRepo::list_clusters` reports for the successor.
    pub signature: StateSignature,
    /// Members taken over from the source, in decision order; never empty.
    pub members: Vec<SplitMember>,
}

/// A cluster split to persist: the source cluster is superseded, every active
/// member moves to exactly one successor, and `action_contexts` rows keyed to the source are
/// re-keyed to a successor so coverage totals are conserved. `crawlx_state::SplitResult` is
/// the in-memory product this record is built from.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ClusterSplitRecord {
    /// Run the clusters belong to.
    pub run: CrawlRunId,
    /// Cluster being superseded.
    pub source: StateClusterId,
    /// Version of `source` the split was computed against; a stale version is rejected.
    pub source_version: u32,
    /// Successor versions in group order; the first is the dominant-outcome group and takes
    /// over every `action_contexts` row with no action evidence of its own.
    pub successors: Vec<SplitSuccessor>,
    /// Caller-supplied decision time.
    pub decided_at: Timestamp,
}

/// What applying a [`ClusterSplitRecord`] changed.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct SplitApplied {
    /// Memberships superseded and re-created under a successor.
    pub memberships_moved: u32,
    /// `action_contexts` rows whose `state_cluster_id` now names a successor.
    pub action_contexts_rekeyed: u32,
}

/// States and clusters.
#[async_trait]
pub trait StateRepo: Send + Sync {
    /// Persist an observation together with its cluster assignment.
    async fn put_state(&self, state: &NewState) -> Result<(), StoreError>;
    /// All states of `run` with their active cluster assignment.
    async fn list_states(&self, run: CrawlRunId) -> Result<Vec<NewState>, StoreError>;
    /// Active clusters of `run` as `(cluster, prototype signature, member count)`.
    async fn list_clusters(
        &self,
        run: CrawlRunId,
    ) -> Result<Vec<(StateClusterId, StateSignature, u32)>, StoreError>;
    /// Apply a split atomically: supersede the source cluster, create the successors, move
    /// every active membership, and re-key each `action_contexts` row of the source to the
    /// successor its actions' `before_state`s fall in (ties and rows without actions go to
    /// the first successor). A `state_cluster_split` run event records the supersession.
    ///
    /// # Errors
    /// `NotFound` when the source cluster is not in `run`; `Conflict` when the source is
    /// already superseded, `source_version` is stale, a successor id already exists, a member
    /// is not an active member of the source, or the successors do not partition the source's
    /// active members exactly.
    async fn apply_split(&self, split: &ClusterSplitRecord) -> Result<SplitApplied, StoreError>;
}

/// A persisted enablement edge.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct EdgeRecord {
    /// Edge identifier, derived from source, context and target.
    pub id: EdgeId,
    /// Run the edge was learned in.
    pub run: CrawlRunId,
    /// Action context whose execution enables the target.
    pub source: ActionContextId,
    /// State cluster the edge holds in; `None` when it applies regardless of cluster.
    pub context_cluster: Option<StateClusterId>,
    /// Element that becomes available after the source action.
    pub target: crate::identity::ElementIdentityHash,
    /// Strong credits: observations with no confounder in the settle window.
    pub support: u32,
    /// Confounded credits; each counts as half a strong credit.
    pub weak_support: u32,
    /// Observations where the source action did not enable the target.
    pub failures: u32,
    /// Typical latency in milliseconds from the source action until the target appears.
    pub latency_ms_ewma: f32,
    /// Risk of following the edge; `0.0` for reveal, navigation and reversible actions.
    pub risk: f32,
    /// When the edge was last observed.
    pub last_observed_at: Timestamp,
    /// Browser build the edge was last verified against; `None` if never verified.
    pub last_verified_build: Option<String>,
}

/// Enablement graph persistence.
#[async_trait]
pub trait EdgeStore: Send + Sync {
    /// Insert the edge or overwrite its counters (absolute upsert keyed by run, source, cluster and target).
    async fn upsert(&self, edge: &EdgeRecord) -> Result<(), StoreError>;
    /// All edges of `run`.
    async fn list(&self, run: CrawlRunId) -> Result<Vec<EdgeRecord>, StoreError>;
}

/// Coverage ledger row.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct LedgerRow {
    /// Action context the counts belong to.
    pub key: ActionContextKey,
    /// Successful executions on the trusted lane.
    pub trusted_exercised: u32,
    /// Successful executions on diagnostic lanes.
    pub diagnostic_exercised: u32,
    /// Failed executions.
    pub failures: u32,
    /// When the context was first seen.
    pub first_seen: Timestamp,
    /// When the context was last executed; `None` if never.
    pub last_exercised: Option<Timestamp>,
}

/// Privacy-safe aggregate coverage counts, without action-context labels or input values.
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct LedgerSummary {
    /// Number of discovered action contexts.
    pub discovered: u64,
    /// Number of contexts exercised successfully on the trusted lane.
    pub exercised_trusted: u64,
}

impl LedgerSummary {
    /// Aggregate counts without action-context labels or input values.
    #[must_use]
    pub const fn new(discovered: u64, exercised_trusted: u64) -> Self {
        Self {
            discovered,
            exercised_trusted,
        }
    }
}

/// `action_contexts` persistence.
#[async_trait]
pub trait LedgerRepo: Send + Sync {
    /// Write the row's counters for `run` (absolute: counters overwrite, `first_seen` keeps the earliest value).
    async fn upsert(&self, run: CrawlRunId, row: &LedgerRow) -> Result<(), StoreError>;
    /// All ledger rows of `run`.
    async fn list(&self, run: CrawlRunId) -> Result<Vec<LedgerRow>, StoreError>;
    /// Coverage counts that remain readable after transient ZDR context details expire.
    ///
    /// # Errors
    /// Returns a storage error when the aggregate cannot be read.
    async fn summary(&self, run: CrawlRunId) -> Result<LedgerSummary, StoreError> {
        let mut summary = LedgerSummary::default();
        for row in self.list(run).await? {
            summary.discovered = summary.discovered.saturating_add(1);
            if row.trusted_exercised > 0 {
                summary.exercised_trusted = summary.exercised_trusted.saturating_add(1);
            }
        }
        Ok(summary)
    }
}

/// Object-store artifacts (content-addressed).
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    /// Actual upload-spool occupancy in permille. Unknown backends return `None`.
    /// This diagnostic must never substitute an invented idle measurement.
    fn spool_pressure_permille(&self) -> Option<u16> {
        None
    }
    /// Store `bytes` for `run` under `class`, returning a content-addressed reference.
    async fn put(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError>;
    /// Store bytes with a deadline that can only shorten the normal retention window.
    ///
    /// # Errors
    /// Returns retention or backend errors; unsupported stores must not discard the deadline.
    async fn put_until(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
        deadline: Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        let _ = (run, class, content_type, bytes, deadline);
        Err(StoreError::RetentionDenied(
            "bounded artifact sink unavailable".into(),
        ))
    }
    /// Erase credential-bearing objects after the run becomes terminal, preserving audit rows.
    ///
    /// # Errors
    /// Returns scope, nonterminal-run or backend errors. Failed erasure must remain retryable.
    async fn erase_run_credentials(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let _ = run;
        Err(StoreError::RetentionDenied(
            "credential erasure unavailable".into(),
        ))
    }
    /// As [`Self::put`] for content belonging to page `page` ([`PageRecord::frontier_id`]).
    /// Stores with a zero-data-retention delivery buffer keep `content` of ZDR
    /// runs there instead of refusing it; by default this is exactly [`Self::put`].
    async fn put_page(
        &self,
        run: CrawlRunId,
        page: i64,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        let _ = page;
        self.put(run, class, content_type, bytes).await
    }
    /// Store a separately named dataset/feed rendition without overwriting page HTML.
    ///
    /// # Errors
    /// Returns retention, quota or backend errors.
    async fn put_dataset(
        &self,
        run: CrawlRunId,
        page: i64,
        rendition: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        let _ = (run, page, rendition, content_type, bytes);
        Err(StoreError::RetentionDenied(
            "dataset artifact sink unavailable".into(),
        ))
    }
    /// Store approved dataset bytes with an explicit deadline that can only shorten retention.
    ///
    /// # Errors
    /// Returns unsupported, expired, quota or backend errors.
    async fn put_dataset_until(
        &self,
        run: CrawlRunId,
        page: i64,
        rendition: &str,
        content_type: &str,
        bytes: &[u8],
        deadline: Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        let _ = (run, page, rendition, content_type, bytes, deadline);
        Err(StoreError::RetentionDenied(
            "bounded dataset artifact sink unavailable".into(),
        ))
    }
    /// Describe an already approved content reference without copying its body.
    ///
    /// # Errors
    /// Returns retention or unavailable errors if ownership, size or expiry cannot be proven.
    async fn dataset_content(
        &self,
        run: CrawlRunId,
        page: i64,
        artifact: &ArtifactRef,
        size_bytes: u64,
    ) -> Result<crate::dataset::DatasetContentV1, StoreError> {
        let _ = (run, page, artifact, size_bytes);
        Err(StoreError::RetentionDenied(
            "dataset content metadata unavailable".into(),
        ))
    }
    /// Fetch the bytes of an artifact.
    async fn get(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError>;
    /// Describe retained Content or Sensitive authority without reading body bytes.
    ///
    /// # Errors
    /// Refuses unsupported, foreign, expired, corrupt or oversized source references.
    async fn archive_custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        max_bytes: u64,
    ) -> Result<crate::archive_catalog::ArchiveCustodyV1, StoreError> {
        let _ = (tenant, run, artifact, max_bytes);
        Err(StoreError::RetentionDenied("archive custody unavailable".into()))
    }
    /// Read approved Sensitive evidence under its exact retained byte authority.
    ///
    /// # Errors
    /// Refuses classification, ownership, expiry, fixity or byte-bound mismatches.
    async fn read_archive_sensitive(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        custody: &crate::archive_catalog::ArchiveCustodyV1,
        max_bytes: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let _ = (tenant, run, artifact, custody, max_bytes);
        Err(StoreError::RetentionDenied(
            "sensitive archive read unavailable".into(),
        ))
    }
    /// Stream an archive file while retaining its explicit source classification and deadline.
    ///
    /// # Errors
    /// Unsupported stores must refuse rather than discard byte authority.
    async fn put_archive_file_with_custody(
        &self,
        run: CrawlRunId,
        content_type: &str,
        file: &std::path::Path,
        max_bytes: u64,
        custody: &crate::archive_catalog::ArchiveCustodyV1,
    ) -> Result<ArtifactRef, StoreError> {
        let _ = (run, content_type, file, max_bytes, custody);
        Err(StoreError::RetentionDenied(
            "typed archive sink unavailable".into(),
        ))
    }
    /// Copy one retained shard under exact classification and source deadline.
    ///
    /// # Errors
    /// Refuses mismatched, expired, oversized or corrupt shard authority.
    async fn copy_archive_with_custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        custody: &crate::archive_catalog::ArchiveCustodyV1,
        file: &std::path::Path,
        max_bytes: u64,
    ) -> Result<u64, StoreError> {
        let _ = (tenant, run, artifact, custody, file, max_bytes);
        Err(StoreError::RetentionDenied(
            "typed archive copy unavailable".into(),
        ))
    }
    /// Stream a bounded approved archive file through the same retention-aware object sink.
    /// Implementations must not collect file contents or permit ZDR durable writes.
    ///
    /// # Errors
    /// Returns an explicit capability error for stores without bounded file upload.
    async fn put_archive_file(
        &self,
        run: CrawlRunId,
        content_type: &str,
        file: &std::path::Path,
        max_bytes: u64,
    ) -> Result<ArtifactRef, StoreError> {
        let _ = (run, content_type, file, max_bytes);
        Err(StoreError::Unavailable(
            "streaming archive artifact sink unavailable".into(),
        ))
    }
    /// Copy approved retained content into a bounded local spool without body-sized buffers.
    ///
    /// # Errors
    /// Refuses foreign, expired, sensitive, oversized or corrupt artifacts.
    async fn copy_archive_content(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        file: &std::path::Path,
        max_bytes: u64,
    ) -> Result<u64, StoreError> {
        let _ = (tenant, run, artifact, file, max_bytes);
        Err(StoreError::Unavailable(
            "streaming archive artifact read unavailable".into(),
        ))
    }
    /// Read one retained content body with ownership and size checked before allocation.
    ///
    /// # Errors
    /// Refuses foreign, expired, sensitive, oversized or corrupt artifacts.
    async fn read_archive_content(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        max_bytes: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let _ = (tenant, run, artifact, max_bytes);
        Err(StoreError::Unavailable(
            "bounded archive content read unavailable".into(),
        ))
    }
    /// A time-limited URL that serves `artifact` straight from the object store, valid for at
    /// most `ttl` (`content` artifacts only, 60 s). `Ok(None)` when the backend
    /// cannot presign (directory and in-memory stores); callers then serve the bytes themselves.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] for an unknown or purged artifact, [`StoreError::AccessDenied`]
    /// for any class other than `content`, or a backend error from signing.
    async fn presign(
        &self,
        artifact: &ArtifactRef,
        ttl: std::time::Duration,
    ) -> Result<Option<url::Url>, StoreError> {
        let _ = (artifact, ttl);
        Ok(None)
    }
}

/// Artifact sensitivity class.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    /// Structural facts about a run (e.g. manifests); readable with ordinary artifact access.
    Metadata,
    /// Page content (e.g. HTML, Markdown); readable with ordinary artifact access.
    Content,
    /// Captured data that may hold secrets (e.g. DOM snapshots); reading needs the sensitive-artifacts scope.
    Sensitive,
    /// Holds credentials or session secrets (cookies, tokens, storage state).
    CredentialBearing,
}

impl Sensitivity {
    /// Stable snake_case name, identical to the serde representation and the storage value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::Content => "content",
            Self::Sensitive => "sensitive",
            Self::CredentialBearing => "credential_bearing",
        }
    }
}

/// Safety audit persistence.
#[async_trait]
pub trait SafetyAudit: Send + Sync {
    /// Persist the verdict for an action of `session` with a human-readable `summary` of the action.
    async fn record(
        &self,
        run: CrawlRunId,
        session: SessionId,
        v: &SafetyVerdict,
        summary: &str,
    ) -> Result<(), StoreError>;
}

/// Run events for SSE/webhooks (`crawl_events`).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct RunEvent {
    /// Per-run sequence number, starting at 1 and gapless; use it as the SSE cursor.
    pub seq: u64,
    /// Event type name, e.g. an action status change.
    pub kind: String,
    /// Event body (JSON).
    pub payload: serde_json::Value,
    /// When the event was appended.
    pub at: Timestamp,
}

/// Append-only run event log (`crawl_events`), the outbox behind SSE and webhooks.
#[async_trait]
pub trait EventRepo: Send + Sync {
    /// Append an event to `run` and return its sequence number.
    async fn append(
        &self,
        run: CrawlRunId,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StoreError>;
    /// Up to `limit` events of `run` with `seq > after_seq`, ascending.
    async fn list_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError>;
    /// Privacy-safe event history, including after ephemeral ZDR payloads expire.
    ///
    /// # Errors
    /// Returns a storage error when event metadata cannot be read.
    async fn list_metadata_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        self.list_after(run, after_seq, limit).await
    }
}

/// What a recorded model call was asked (`model_decisions.kind`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ModelDecisionKind {
    /// Rank a shortlist of candidate actions (System 1).
    Rank,
    /// Classify an input field.
    ClassifyInput,
    /// Classify a form.
    ClassifyForm,
    /// Plan a multi-step sequence (LLM planner).
    Plan,
    /// Hint at the risk of an action.
    RiskHint,
}

impl ModelDecisionKind {
    /// The label stored in `model_decisions.kind`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rank => "rank",
            Self::ClassifyInput => "classify_input",
            Self::ClassifyForm => "classify_form",
            Self::Plan => "plan",
            Self::RiskHint => "risk_hint",
        }
    }
}

/// One model call kept for audit and offline shadow comparison (`model_decisions`:
/// replay consumes these rows and never asks the model again).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct ModelDecisionRecord {
    /// Identifier referenced by `actions.model_decision_id` when the decision influenced an action.
    pub id: ModelDecisionId,
    /// Run the call belongs to.
    pub run: CrawlRunId,
    /// Session that made the call.
    pub session: Option<SessionId>,
    /// What the model was asked.
    pub kind: ModelDecisionKind,
    /// How much the answer was allowed to influence the crawl.
    pub mode: crate::config::System1Mode,
    /// Serving backend of the model (`decision-http`, `onnx-ranker`, ...).
    pub provider: String,
    /// Model name at the provider.
    pub model: String,
    /// Checkpoint digest or version of the model; empty when the provider reports none.
    pub model_version: String,
    /// Version of the calibration applied to the probabilities.
    pub calibration_version: Option<String>,
    /// Calibrated probability of the model's top answer, in `[0, 1]`.
    pub confidence: Option<f32>,
    /// The decision as JSON: shortlist, probabilities, selection (never page text).
    pub output: serde_json::Value,
    /// Digest of the exact request sent, so a replay can prove it asked the same question.
    pub prompt_digest: crate::hash::Digest,
    /// Wall time of the call in milliseconds.
    pub latency_ms: Option<u32>,
    /// State of the engine's circuit breaker when the call ran, if it has one.
    pub breaker_state: Option<String>,
    /// When the decision was recorded.
    pub created_at: Timestamp,
}

/// Append-only store of model calls (`model_decisions`).
#[async_trait]
pub trait ModelDecisionRepo: Send + Sync {
    /// Record one decision. Recording the same `id` again is a no-op.
    ///
    /// # Errors
    /// [`StoreError`] when the run or session does not exist or the store fails.
    async fn record(&self, decision: &ModelDecisionRecord) -> Result<(), StoreError>;

    /// Every decision of `run` in recording order.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn list(&self, run: CrawlRunId) -> Result<Vec<ModelDecisionRecord>, StoreError>;
}

/// The safety gate the arbiter consults before scoring.
pub trait SafetyGate: Send + Sync {
    /// Classify the proposal `p` in context `c` and return the verdict.
    fn classify(&self, p: &ActionProposal, c: &SafetyContext) -> SafetyVerdict;
}

/// Facts the kernel needs besides the proposal.
#[derive(Clone, Debug)]
pub struct SafetyContext {
    /// Safety profile of the run.
    pub profile: crate::config::SafetyProfile,
    /// Tenant has verified test sinks and the run opted in to using them.
    pub has_test_sinks: bool,
    /// Configuration allows destructive actions once approved.
    pub destructive_approval_allowed: bool,
    /// Principal the action runs as.
    pub principal: PrincipalId,
    /// Origin of the seed URL (scope root), e.g. `https://app.example.com`.
    pub seed_origin: String,
    /// Whether the action's target lies inside the run's scope.
    pub in_scope: bool,
    /// Observed facts about the target: role, name, href, text, form hints.
    pub target: crate::observation::LiveTargetFacts,
    /// Free-text hint about the enclosing form (e.g. its purpose or action); `None` when not in a form.
    pub form_hint: Option<String>,
}

/// A restore point of one session (`checkpoints`). The storage state
/// (cookies, local/session storage, URL) lives in a `CredentialBearing` artifact.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct CheckpointRecord {
    /// Checkpoint identifier.
    pub id: CheckpointId,
    /// Run the session belongs to.
    pub run: CrawlRunId,
    /// Session the checkpoint restores.
    pub session: SessionId,
    /// Observation epoch at the time of the checkpoint.
    pub epoch: ObservationEpoch,
    /// `crawl_sessions.action_seq` at the time of the checkpoint.
    pub action_seq: u64,
    /// `crawlx_scheduler::CheckpointReason::as_str()`.
    pub reason: String,
    /// Credential-bearing artifact holding the session's storage state.
    pub storage: ArtifactRef,
    /// Digest of the URL at checkpoint time (the URL itself is in the artifact).
    pub url_hash: Option<crate::hash::Digest>,
    /// When the checkpoint was taken.
    pub created_at: Timestamp,
    /// When the checkpoint, and its storage artifact, may be deleted.
    pub expires_at: Timestamp,
}

/// Checkpoint persistence. Implementations keep the newest three per session.
#[async_trait]
pub trait CheckpointRepo: Send + Sync {
    /// Store a checkpoint, evicting the session's oldest beyond the newest three.
    async fn put(&self, checkpoint: &CheckpointRecord) -> Result<(), StoreError>;
    /// The checkpoint with the highest `action_seq` (ties: newest) of `session`.
    async fn latest(&self, session: SessionId) -> Result<Option<CheckpointRecord>, StoreError>;
    /// Newest first.
    async fn list(&self, session: SessionId) -> Result<Vec<CheckpointRecord>, StoreError>;
}

/// An identity alias: `alias` is a hash that
/// resolved *toward* `canonical` without merging into it. Two producers: the weighted
/// matcher's ambiguous band (`0.60 <= score < 0.80` mints `alias` with `canonical` as its
/// `alias_candidate_of`), and a dual-compute release that records `(v1_hash, v2_hash)`.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct IdentityAlias {
    /// The newly minted (or newer-version) identity hash.
    pub alias: ElementIdentityHash,
    /// The known identity the alias points at.
    pub canonical: ElementIdentityHash,
    /// Identity version of `alias` (the source of the alias edge).
    pub from_version: u16,
    /// Identity version of `canonical` (the target of the alias edge).
    pub to_version: u16,
    /// Matcher score that put the pair in the ambiguity band, in `[0, 1]`.
    pub score: f32,
}

/// `identity_aliases` persistence.
#[async_trait]
pub trait IdentityAliasRepo: Send + Sync {
    /// Record an alias of `run`. Recording the same hashes and version pair again keeps
    /// the first row's score (idempotent). Registers both identities in the element registry.
    ///
    /// # Errors
    /// [`StoreError`] when the run does not exist or the store fails.
    async fn record_alias(&self, run: CrawlRunId, alias: &IdentityAlias) -> Result<(), StoreError>;

    /// Every alias of `run` pointing at `canonical`, ordered by alias hash.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn aliases_of(
        &self,
        run: CrawlRunId,
        canonical: ElementIdentityHash,
    ) -> Result<Vec<IdentityAlias>, StoreError>;
}
