//! Persistence for the Firecrawl-parity LLM products: asynchronous `extract` and
//! `agent` jobs with their trace, snapshots and conversation threads, scheduled monitors with
//! their checks and per-page baselines, the usage ledger behind `/team/*`, and per-tenant
//! settings (`threat-protection`).
//!
//! [`IntelRepo`] is implemented by [`crate::Pg`] (tables of migration `0016_intel.sql`) and by
//! [`MemoryIntel`] for tests and the in-memory API. Every method that takes a tenant filters by
//! it: a row of another tenant is indistinguishable from an absent row. Timestamps are passed in
//! by the caller (the API clock); the repository never reads wall time.
//!
//! Row payloads that the API shapes itself (`request`, `result`, `targets`, `summary`, ...) are
//! opaque JSON here; columns exist only for what the repository filters or orders by.

use async_trait::async_trait;
use crawlx_core::{StoreError, TenantId, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

pub use crate::intel_memory::MemoryIntel;

/// Result alias of this module.
pub type IntelResult<T> = Result<T, StoreError>;

/// Which product a job row belongs to.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// `POST /extract`.
    Extract,
    /// `POST /agent`.
    Agent,
}

impl JobKind {
    /// Stored label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Extract => "extract",
            Self::Agent => "agent",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "extract" => Some(Self::Extract),
            "agent" => Some(Self::Agent),
            _ => None,
        }
    }
}

/// Lifecycle of a job.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    /// Accepted and not finished.
    Processing,
    /// Finished with a result.
    Completed,
    /// Finished with an error.
    Failed,
    /// Cancelled by the caller.
    Cancelled,
}

impl JobStatus {
    /// Stored label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "processing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "processing" => Some(Self::Processing),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// No further transition is possible.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Processing)
    }
}

/// One `extract` or `agent` job.
#[derive(Clone, PartialEq, Debug)]
pub struct JobRecord {
    /// Job identifier (the `id` / `jobId` of the API).
    pub id: Uuid,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Product.
    pub kind: JobKind,
    /// Lifecycle state.
    pub status: JobStatus,
    /// The request body as admitted.
    pub request: Value,
    /// Final data once completed.
    pub result: Option<Value>,
    /// Failure text once failed.
    pub error: Option<String>,
    /// Why the job stopped when that is not plain completion (`credit_limit_reached`, ...).
    pub stop_reason: Option<String>,
    /// LLM tokens consumed so far.
    pub tokens_used: u64,
    /// Credits consumed so far (crawlx reports its own counters).
    pub credits_used: u64,
    /// Agent conversation thread the job belongs to.
    pub thread_id: Option<Uuid>,
    /// Admission time.
    pub created_at: Timestamp,
    /// Last write.
    pub updated_at: Timestamp,
    /// Time the job reached a terminal status.
    pub finished_at: Option<Timestamp>,
    /// The row may be purged after this instant.
    pub expires_at: Timestamp,
}

/// Fields of a job that change after admission. `None` leaves the column as is. Once a job is
/// terminal, `status`, `result`, `error`, `stop_reason` and `finished_at` are ignored, so a late
/// worker write cannot overwrite a cancellation.
#[derive(Clone, PartialEq, Debug)]
pub struct JobPatch {
    /// Write time (becomes `updated_at`).
    pub at: Timestamp,
    /// New status.
    pub status: Option<JobStatus>,
    /// Final data.
    pub result: Option<Value>,
    /// Failure text.
    pub error: Option<String>,
    /// Stop reason.
    pub stop_reason: Option<String>,
    /// Absolute token counter.
    pub tokens_used: Option<u64>,
    /// Absolute credit counter.
    pub credits_used: Option<u64>,
    /// Terminal time; set together with a terminal `status`.
    pub finished_at: Option<Timestamp>,
}

impl JobPatch {
    /// A patch that only touches `updated_at`.
    #[must_use]
    pub const fn at(at: Timestamp) -> Self {
        Self {
            at,
            status: None,
            result: None,
            error: None,
            stop_reason: None,
            tokens_used: None,
            credits_used: None,
            finished_at: None,
        }
    }
}

/// One step of an agent run (`GET /agent/{id}/trace`).
#[derive(Clone, PartialEq, Debug)]
pub struct TraceEvent {
    /// Job the event belongs to.
    pub job: Uuid,
    /// 1-based position within the job.
    pub seq: u64,
    /// Event kind (`tool_call`, `tool_result`, `message`, ...).
    pub kind: String,
    /// Event body.
    pub data: Value,
    /// Time of the event.
    pub at: Timestamp,
}

/// An intermediate document an agent saved (`GET /agent/{id}/snapshots/{snapshotId}`).
#[derive(Clone, PartialEq, Debug)]
pub struct Snapshot {
    /// Job the snapshot belongs to.
    pub job: Uuid,
    /// Snapshot identifier, unique within the job.
    pub id: String,
    /// Snapshot body.
    pub data: Value,
    /// Time it was taken.
    pub created_at: Timestamp,
}

/// A stored agent conversation (`threadId`).
#[derive(Clone, PartialEq, Debug)]
pub struct ThreadRecord {
    /// Thread identifier.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Messages and tool results the next turn continues from.
    pub state: Value,
    /// First write.
    pub created_at: Timestamp,
    /// Last write.
    pub updated_at: Timestamp,
}

/// Whether a monitor runs on schedule.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorStatus {
    /// Ticks run it.
    Active,
    /// Ticks skip it; `POST .../run` still works.
    Paused,
}

impl MonitorStatus {
    /// Stored label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "paused" => Some(Self::Paused),
            _ => None,
        }
    }
}

/// A scheduled monitor.
#[derive(Clone, PartialEq, Debug)]
pub struct MonitorRecord {
    /// Monitor identifier.
    pub id: Uuid,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Display name.
    pub name: Option<String>,
    /// Scheduling state.
    pub status: MonitorStatus,
    /// The schedule object as the caller sent it (`{cron|text, timezone}`).
    pub schedule: Value,
    /// Normalized five-field cron expression derived from `schedule`.
    pub cron: String,
    /// IANA timezone the cron is evaluated in.
    pub timezone: String,
    /// Natural-language goal the LLM judges changes against.
    pub goal: Option<String>,
    /// 1-50 targets (`scrape`, `crawl`, `search`), each with a stable `id`.
    pub targets: Value,
    /// How long checks and pages are kept (1-365).
    pub retention_days: u32,
    /// Webhook destination (`url`, `headers`, `metadata`, `events`).
    pub webhook: Option<Value>,
    /// Notification settings (`email`).
    pub notification: Value,
    /// Next scheduled run; `None` while paused.
    pub next_run_at: Option<Timestamp>,
    /// Start of the most recent check.
    pub last_run_at: Option<Timestamp>,
    /// Most recent check.
    pub last_check_id: Option<Uuid>,
    /// A ticker claimed the monitor until this instant (lease against double runs).
    pub claimed_until: Option<Timestamp>,
    /// Creation time.
    pub created_at: Timestamp,
    /// Last write.
    pub updated_at: Timestamp,
}

/// Lifecycle of a monitor check.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    /// Targets are being scraped.
    Running,
    /// Finished; `status` holds the aggregate outcome.
    Completed,
    /// The check itself failed.
    Failed,
}

impl CheckState {
    /// Stored label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    /// Inverse of [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

/// One execution of a monitor.
#[derive(Clone, PartialEq, Debug)]
pub struct CheckRecord {
    /// Check identifier.
    pub id: Uuid,
    /// Monitor it belongs to.
    pub monitor: Uuid,
    /// Owning tenant.
    pub tenant: TenantId,
    /// `scheduled` or `manual`.
    pub trigger: String,
    /// Lifecycle.
    pub state: CheckState,
    /// Aggregate page status once completed: `same`, `new`, `changed`, `removed` or `error`.
    pub status: Option<String>,
    /// Counts per page status, the LLM judgement and the goal verdict.
    pub summary: Value,
    /// Failure text when `state` is `failed`.
    pub error: Option<String>,
    /// Start.
    pub started_at: Timestamp,
    /// End.
    pub finished_at: Option<Timestamp>,
    /// The check and its pages may be purged after this instant.
    pub expires_at: Timestamp,
}

/// One page observed by a check.
#[derive(Clone, PartialEq, Debug)]
pub struct CheckPage {
    /// Check it belongs to.
    pub check: Uuid,
    /// Target that produced the page.
    pub target_id: String,
    /// Page URL.
    pub url: String,
    /// `same`, `new`, `changed`, `removed` or `error`.
    pub status: String,
    /// Diff, document metadata and judgement of the page.
    pub data: Value,
}

/// The last content seen at one URL of one monitor, the baseline the next check diffs against.
#[derive(Clone, PartialEq, Debug)]
pub struct Baseline {
    /// Monitor.
    pub monitor: Uuid,
    /// Page URL.
    pub url: String,
    /// Content digest (hex).
    pub digest: String,
    /// Markdown of the last observation.
    pub markdown: String,
    /// Time of the observation.
    pub seen_at: Timestamp,
}

/// A row of the usage ledger behind `/team/credit-usage`, `/token-usage` and `/activity`.
#[derive(Clone, PartialEq, Debug)]
pub struct UsageEvent {
    /// Tenant charged.
    pub tenant: TenantId,
    /// Time of the event.
    pub at: Timestamp,
    /// Endpoint family: `scrape`, `crawl`, `search`, `extract`, `agent`, `parse`, `monitor`, ...
    pub endpoint: String,
    /// Job, run or check the event belongs to.
    pub ref_id: Option<Uuid>,
    /// Final status of the unit of work.
    pub status: String,
    /// Credits attributed.
    pub credits: u64,
    /// LLM prompt tokens.
    pub prompt_tokens: u64,
    /// LLM completion tokens.
    pub completion_tokens: u64,
}

/// Sums over a window of the usage ledger.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct UsageTotals {
    /// Credits.
    pub credits: u64,
    /// Prompt tokens.
    pub prompt_tokens: u64,
    /// Completion tokens.
    pub completion_tokens: u64,
    /// Number of ledger rows.
    pub events: u64,
}

/// One UTC calendar-day bucket of the usage ledger.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UsageDay {
    /// `YYYY-MM-DD` (UTC).
    pub day: String,
    /// Sums for that day.
    pub totals: UsageTotals,
}

/// Counts of jobs by kind and status, for `/team/queue-status`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct JobCount {
    /// Product.
    pub kind: JobKind,
    /// Status.
    pub status: JobStatus,
    /// Number of jobs.
    pub count: u64,
}

/// Rows removed by [`IntelRepo::purge_expired`].
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct PurgeReport {
    /// Expired jobs with their trace, snapshots.
    pub jobs: u64,
    /// Expired monitor checks with their pages.
    pub checks: u64,
}

/// Persistence of the LLM products. See the module docs for the tenant rule.
#[async_trait]
pub trait IntelRepo: Send + Sync {
    // ---- jobs -----------------------------------------------------------------------------
    /// Insert a job; `Conflict` when the id exists.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] on a duplicate id, other [`StoreError`]s when the store fails.
    async fn job_insert(&self, job: &JobRecord) -> IntelResult<()>;

    /// Fetch a job of `tenant`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn job_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<JobRecord>>;

    /// Apply `patch` (see [`JobPatch`] for the terminal rule) and return the stored row after
    /// the write; `None` when the job does not exist for `tenant`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn job_update(
        &self,
        tenant: TenantId,
        id: Uuid,
        patch: &JobPatch,
    ) -> IntelResult<Option<JobRecord>>;

    /// Jobs of `tenant` (optionally one `kind`), newest first (`created_at`, then `id`
    /// descending), at most `limit`, starting after the `(created_at, id)` cursor when given.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn job_list(
        &self,
        tenant: TenantId,
        kind: Option<JobKind>,
        limit: u32,
        after: Option<(Timestamp, Uuid)>,
    ) -> IntelResult<Vec<JobRecord>>;

    /// Counts of the tenant's jobs grouped by kind and status.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn job_counts(&self, tenant: TenantId) -> IntelResult<Vec<JobCount>>;

    // ---- agent trace, snapshots, threads -------------------------------------------------------
    /// Append an event to a job's trace and return its 1-based sequence number.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when the job does not exist, other [`StoreError`]s when the store fails.
    async fn trace_append(&self, job: Uuid, kind: &str, data: Value, at: Timestamp) -> IntelResult<u64>;

    /// Events with `seq > after` in sequence order, at most `limit`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn trace_list(&self, job: Uuid, after: u64, limit: u32) -> IntelResult<Vec<TraceEvent>>;

    /// Store (or replace) snapshot `id` of `job`.
    ///
    /// # Errors
    /// [`StoreError::NotFound`] when the job does not exist, other [`StoreError`]s when the store fails.
    async fn snapshot_put(&self, job: Uuid, id: &str, data: Value, at: Timestamp) -> IntelResult<()>;

    /// Snapshot `id` of `job`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn snapshot_get(&self, job: Uuid, id: &str) -> IntelResult<Option<Snapshot>>;

    /// Ids of a job's snapshots in creation order.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn snapshot_ids(&self, job: Uuid) -> IntelResult<Vec<String>>;

    /// A conversation thread of `tenant`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn thread_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<ThreadRecord>>;

    /// Create or replace a thread's state. A thread owned by another tenant is `Conflict`.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] when the id belongs to another tenant, other [`StoreError`]s when the store fails.
    async fn thread_put(&self, tenant: TenantId, id: Uuid, state: Value, at: Timestamp) -> IntelResult<()>;

    // ---- monitors -------------------------------------------------------------------------
    /// Insert a monitor; `Conflict` when the id exists.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] on a duplicate id, other [`StoreError`]s when the store fails.
    async fn monitor_insert(&self, m: &MonitorRecord) -> IntelResult<()>;

    /// Replace every mutable field of a monitor (`PATCH` is get, modify, put). Returns `false`
    /// when the monitor does not exist for its tenant.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn monitor_update(&self, m: &MonitorRecord) -> IntelResult<bool>;

    /// Fetch a monitor of `tenant`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn monitor_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<MonitorRecord>>;

    /// Monitors of `tenant`, newest first, `limit` rows after `offset`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn monitor_list(
        &self,
        tenant: TenantId,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<MonitorRecord>>;

    /// Number of monitors of `tenant`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn monitor_count(&self, tenant: TenantId) -> IntelResult<u64>;

    /// Delete a monitor with its checks, pages and baselines; `false` when absent.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn monitor_delete(&self, tenant: TenantId, id: Uuid) -> IntelResult<bool>;

    /// Claim up to `limit` active monitors of every tenant whose `next_run_at <= now` and that
    /// no ticker holds (`claimed_until` null or `<= now`), setting `claimed_until = lease_until`.
    /// Oldest `next_run_at` first.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn monitor_claim_due(
        &self,
        now: Timestamp,
        lease_until: Timestamp,
        limit: u32,
    ) -> IntelResult<Vec<MonitorRecord>>;

    /// Record that a run started or finished: set `last_run_at`, `last_check_id`, `next_run_at`
    /// (`None` keeps the stored value cleared only for paused monitors; pass the computed next
    /// instant for active ones) and clear the claim.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn monitor_finish_run(
        &self,
        tenant: TenantId,
        id: Uuid,
        last_run_at: Timestamp,
        last_check_id: Uuid,
        next_run_at: Option<Timestamp>,
    ) -> IntelResult<()>;

    // ---- monitor checks -----------------------------------------------------------------------
    /// Insert a check; `Conflict` when the id exists.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] on a duplicate id, other [`StoreError`]s when the store fails.
    async fn check_insert(&self, c: &CheckRecord) -> IntelResult<()>;

    /// Replace the mutable fields of a check (`state`, `status`, `summary`, `error`,
    /// `finished_at`). Returns `false` when absent.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn check_update(&self, c: &CheckRecord) -> IntelResult<bool>;

    /// A check of `tenant`'s monitor.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn check_get(&self, tenant: TenantId, monitor: Uuid, id: Uuid) -> IntelResult<Option<CheckRecord>>;

    /// Checks of a monitor, newest first, `limit` rows after `offset`, optionally only those whose
    /// aggregate `status` equals the filter.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn check_list(
        &self,
        tenant: TenantId,
        monitor: Uuid,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<CheckRecord>>;

    /// Store the pages of a check (replacing rows with the same `(target_id, url)`).
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn check_pages_put(&self, pages: &[CheckPage]) -> IntelResult<()>;

    /// Pages of a check ordered by `(target_id, url)`, optionally one `status`, `limit` rows after `offset`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn check_pages(
        &self,
        check: Uuid,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<CheckPage>>;

    /// Baselines of a monitor.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn baselines(&self, monitor: Uuid) -> IntelResult<Vec<Baseline>>;

    /// Insert or replace baselines (key `(monitor, url)`).
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn baselines_put(&self, rows: &[Baseline]) -> IntelResult<()>;

    /// Remove the baselines of `monitor` whose URL is in `urls` (pages that disappeared).
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn baselines_remove(&self, monitor: Uuid, urls: &[String]) -> IntelResult<()>;

    // ---- usage ledger and settings -----------------------------------------------------------------
    /// Append a ledger row.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn usage_record(&self, e: &UsageEvent) -> IntelResult<()>;

    /// Sums of the tenant's ledger rows with `from <= at < to`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn usage_totals(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<UsageTotals>;

    /// Per-UTC-day sums of the tenant's ledger rows with `from <= at < to`, days ascending, days
    /// without rows omitted.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn usage_by_day(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<Vec<UsageDay>>;

    /// Newest ledger rows of the tenant, at most `limit`, starting at `offset`, optionally one `endpoint`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn usage_recent(
        &self,
        tenant: TenantId,
        endpoint: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<UsageEvent>>;

    /// The newest ledger row of the tenant that references `ref_id` (a job, search or monitor id).
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn usage_by_ref(&self, tenant: TenantId, ref_id: Uuid) -> IntelResult<Option<UsageEvent>>;

    /// A tenant setting (`threat-protection`, ...).
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn setting_get(&self, tenant: TenantId, key: &str) -> IntelResult<Option<Value>>;

    /// Create or replace a tenant setting.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn setting_put(&self, tenant: TenantId, key: &str, value: Value, at: Timestamp) -> IntelResult<()>;

    // ---- retention --------------------------------------------------------------------------------
    /// Delete jobs (with trace and snapshots) and checks (with pages) whose `expires_at <= now`,
    /// and ledger rows older than `usage_before`.
    ///
    /// # Errors
    /// [`StoreError`] when the store fails.
    async fn purge_expired(&self, now: Timestamp, usage_before: Timestamp) -> IntelResult<PurgeReport>;
}
