//! Operator controls behind `crawlx admin` (`scheduler.admission`, RB-11,
//! `verify-artifacts`; tenant engine flag).
//!
//! Every operation here is the SQL the runbooks name, wrapped so the CLI never runs its own
//! statements, and every mutation appends to the hash-chained `audit_events` log
//! (`actor = "admin:<operator>"`). Containment (`pause`, `freeze`, `drain`) stays expressible
//! in plain SQL (RB-11) because an emergency stop must not depend on this binary.

use crate::artifacts::ArtifactBlobs;
use crate::codec::get;
use crate::error::db;
use crate::pg::Pg;
use crate::retention::append_audit;
use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::{ActionId, CrawlRunId, SessionId, StoreError, TenantId, Timestamp, WorkerId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// `scheduler.admission`: what the scheduler grants.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionMode {
    /// Leases are granted normally.
    #[default]
    Open,
    /// No new leases; running sessions finish their work (RB-04, RB-07, rollout drain).
    Drain,
    /// No new leases **and** every Session Actor halts at its next action boundary (RB-11).
    Frozen,
}

impl AdmissionMode {
    /// The stored/CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Drain => "drain",
            Self::Frozen => "frozen",
        }
    }

    /// Parse the stored spelling.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] for anything but `open`, `drain`, `frozen`.
    pub fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "open" => Ok(Self::Open),
            "drain" => Ok(Self::Drain),
            "frozen" => Ok(Self::Frozen),
            other => Err(StoreError::Serialization(format!(
                "unknown admission mode {other:?}"
            ))),
        }
    }

    /// Whether new leases may be granted.
    #[must_use]
    pub const fn grants_leases(self) -> bool {
        matches!(self, Self::Open)
    }
}

impl fmt::Display for AdmissionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `tenants.engine`: which engine serves a tenant's compat requests.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum TenantEngine {
    /// crawlx serves the tenant (default).
    #[default]
    Crawlx,
    /// The upstream service serves the tenant; the facade refuses non-shadow creates.
    Upstream,
    /// Only mirrored (`X-Crawlx-Shadow: 1`) requests are accepted.
    Shadow,
}

impl TenantEngine {
    /// The stored/CLI spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Crawlx => "crawlx",
            Self::Upstream => "upstream",
            Self::Shadow => "shadow",
        }
    }

    /// Parse the stored spelling.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] for anything but `crawlx`, `upstream`, `shadow`.
    pub fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "crawlx" => Ok(Self::Crawlx),
            "upstream" => Ok(Self::Upstream),
            "shadow" => Ok(Self::Shadow),
            other => Err(StoreError::Serialization(format!("unknown engine {other:?}"))),
        }
    }
}

impl fmt::Display for TenantEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which runs an operator command targets (`--crawl`, `--tenant`, `--all`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunSelector {
    /// One run.
    Crawl(CrawlRunId),
    /// Every run of one tenant.
    Tenant(TenantId),
    /// Every run.
    All,
}

/// `$head` + the selector's predicate + `$tail` as a compile-time `&'static str`.
/// The predicate is one of three constants, so no SQL text is ever built at runtime.
macro_rules! selected_sql {
    ($sel:expr, $head:literal, $tail:literal) => {
        match $sel {
            RunSelector::Crawl(_) => concat!($head, "run_id = $1", $tail),
            RunSelector::Tenant(_) => concat!($head, "tenant_id = $1", $tail),
            RunSelector::All => concat!($head, "$1::uuid IS NULL", $tail),
        }
    };
}

impl RunSelector {
    /// The value bound to `$1` of [`selected_sql!`].
    fn arg(self) -> Option<uuid::Uuid> {
        match self {
            Self::Crawl(id) => Some(id.0),
            Self::Tenant(t) => Some(t.0),
            Self::All => None,
        }
    }

    fn describe(self) -> serde_json::Value {
        match self {
            Self::Crawl(id) => serde_json::json!({ "crawl": id }),
            Self::Tenant(t) => serde_json::json!({ "tenant": t }),
            Self::All => serde_json::json!({ "all": true }),
        }
    }
}

/// A `workers` row.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WorkerRow {
    /// Worker id (`WorkerConfig::worker_id`).
    pub id: WorkerId,
    /// Host the worker reported at registration.
    pub hostname: String,
    /// Binary version.
    pub version: String,
    /// `crawlx admin drain --worker` was applied; the worker stops taking leases.
    pub draining: bool,
    /// Registration time.
    pub started_at: Timestamp,
    /// Last heartbeat.
    pub last_heartbeat_at: Timestamp,
    /// Worker-published bounded capability manifest, never requested configuration or secrets.
    pub capacity: serde_json::Value,
    /// Session leases currently held by this worker.
    pub leases_held: u64,
}

/// An `actions` row in `intended` or `unknown` (RB-02 listing).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpenAction {
    /// Action id.
    pub id: ActionId,
    /// Run.
    pub run: CrawlRunId,
    /// Session.
    pub session: SessionId,
    /// `intended` or `unknown`.
    pub status: String,
    /// Session status (`running`, `recovering`, ...).
    pub session_status: String,
    /// When the intent became durable.
    pub intended_at: Option<Timestamp>,
}

/// One `artifacts` row whose object is missing or whose bytes no longer hash to `digest`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ArtifactDefect {
    /// `artifacts.artifact_id`.
    pub artifact_id: uuid::Uuid,
    /// Owning run.
    pub run: CrawlRunId,
    /// Object key.
    pub object_key: String,
    /// `missing`, `digest_mismatch` or (encrypted artifacts) `decrypt_failed`.
    pub defect: &'static str,
}

/// Result of [`AdminOps::verify_artifacts`].
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct ArtifactVerification {
    /// Rows examined.
    pub checked: u64,
    /// Rows with a missing object or a digest mismatch.
    pub defects: Vec<ArtifactDefect>,
    /// Objects in the store (under the standard prefixes) with no live row, when listing was possible.
    pub orphans: u64,
}

/// Result of [`AdminOps::durability_audit`]: SLO = `1 − missing / checked`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[must_use]
pub struct DurabilityAudit {
    /// `crawl.accepted` accept-log rows examined.
    pub checked: u64,
    /// Accepted runs with no `crawl_runs` row (any entry is SEV-1), sorted by id.
    pub missing: Vec<CrawlRunId>,
}

/// Worker registration seen by the lease loop.
#[async_trait]
pub trait WorkerRegistry: Send + Sync {
    /// Insert or refresh this worker's row.
    ///
    /// # Errors
    /// Returns an error if the row cannot be written.
    async fn register_worker(&self, id: WorkerId, hostname: &str, version: &str) -> Result<(), StoreError>;
    /// Record a heartbeat and return whether the operator asked this worker to drain.
    ///
    /// # Errors
    /// Returns an error if the row cannot be updated.
    async fn worker_heartbeat(&self, id: WorkerId) -> Result<bool, StoreError>;
    /// Publish bounded backend/build facts in the existing worker capacity JSON.
    ///
    /// # Errors
    /// Rejects oversized/unobserved capability evidence, unknown workers, or storage failures.
    async fn publish_acquisition_capabilities(
        &self,
        id: WorkerId,
        capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
    ) -> Result<(), StoreError>;
    /// Publish a one-shot local executor, scoped to one run and never eligible for queued work.
    ///
    /// # Errors
    /// Same validation and storage errors as [`Self::publish_acquisition_capabilities`].
    async fn publish_local_acquisition_capabilities(
        &self,
        id: WorkerId,
        run: CrawlRunId,
        capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
    ) -> Result<(), StoreError>;
    /// Publish bounded operator-observed delivery/language facts, never endpoint or secret config.
    ///
    /// # Errors
    /// Returns malformed evidence, missing worker or storage errors.
    async fn publish_data_capabilities(
        &self,
        id: WorkerId,
        facts: &crawlx_core::data_capabilities::WorkerDataCapabilitiesV1,
    ) -> Result<(), StoreError>;
    /// Select one fresh queued worker satisfying every backend and data requirement together.
    ///
    /// # Errors
    /// Returns invalid requirements, malformed evidence or storage errors.
    async fn eligible_data_worker(
        &self,
        required_ids: &[String],
        data: &crawlx_core::data_capabilities::WorkerDataRequirementsV1,
        max_age: std::time::Duration,
    ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError>;
    /// Read only the fresh, non-draining worker capability projection.
    /// API requests execute this through their restricted tenant pool.
    ///
    /// # Errors
    /// Returns malformed capability evidence or storage failures; no availability is fabricated.
    async fn live_acquisition_workers(
        &self,
        max_age: std::time::Duration,
    ) -> Result<Vec<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError>;
    /// Find one eligible worker after checking every required backend on that same fresh worker.
    ///
    /// # Errors
    /// Rejects invalid required IDs or malformed evidence, or returns storage failures.
    async fn eligible_acquisition_worker(
        &self,
        required_ids: &[String],
        max_age: std::time::Duration,
    ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError>;
}

#[async_trait]
impl WorkerRegistry for Pg {
    async fn register_worker(&self, id: WorkerId, hostname: &str, version: &str) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO workers (worker_id, hostname, version, capacity, last_heartbeat_at) \
             VALUES ($1, $2, $3, '{}', now()) \
             ON CONFLICT (worker_id) DO UPDATE SET hostname = EXCLUDED.hostname, version = EXCLUDED.version, \
               capacity = '{}', draining = false, started_at = now(), last_heartbeat_at = now()",
        )
        .bind(id.0)
        .bind(hostname)
        .bind(version)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn worker_heartbeat(&self, id: WorkerId) -> Result<bool, StoreError> {
        let draining: Option<bool> = sqlx::query_scalar(
            "UPDATE workers SET last_heartbeat_at = now() WHERE worker_id = $1 RETURNING draining",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        Ok(draining.unwrap_or(false))
    }

    async fn publish_acquisition_capabilities(
        &self,
        id: WorkerId,
        capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
    ) -> Result<(), StoreError> {
        let capacity = acquisition_capacity(capabilities)?;
        let result = sqlx::query(
            "UPDATE workers SET capacity = (capacity - 'localRun') || jsonb_build_object('acquisition',$2::jsonb,'acceptsQueued',true), last_heartbeat_at = now() WHERE worker_id = $1",
        ).bind(id.0).bind(capacity).execute(&self.pool).await.map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::NotFound {
                entity: "worker",
                id: id.to_string(),
            });
        }
        Ok(())
    }
    async fn publish_local_acquisition_capabilities(
        &self,
        id: WorkerId,
        run: CrawlRunId,
        capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
    ) -> Result<(), StoreError> {
        let capacity = acquisition_capacity(capabilities)?;
        let result = sqlx::query(
            "UPDATE workers SET capacity = capacity || jsonb_build_object('acquisition',$2::jsonb,'acceptsQueued',false,'localRun',$3::text), last_heartbeat_at = now() WHERE worker_id=$1",
        ).bind(id.0).bind(capacity).bind(run.to_string()).execute(&self.pool).await.map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::NotFound {
                entity: "worker",
                id: id.to_string(),
            });
        }
        Ok(())
    }
    async fn publish_data_capabilities(
        &self,
        id: WorkerId,
        facts: &crawlx_core::data_capabilities::WorkerDataCapabilitiesV1,
    ) -> Result<(), StoreError> {
        facts.validate()?;
        let value =
            serde_json::to_value(facts).map_err(|error| StoreError::Serialization(error.to_string()))?;
        let result = sqlx::query("UPDATE workers SET capacity=jsonb_set(capacity,'{data}',$2),last_heartbeat_at=now() WHERE worker_id=$1")
            .bind(id.0).bind(value).execute(&self.pool).await.map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::NotFound {
                entity: "worker",
                id: id.to_string(),
            });
        }
        Ok(())
    }
    async fn eligible_data_worker(
        &self,
        required_ids: &[String],
        data: &crawlx_core::data_capabilities::WorkerDataRequirementsV1,
        max_age: std::time::Duration,
    ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
        if !required_ids.is_empty() {
            validate_required_backends(required_ids)?;
        }
        data.validate()?;
        let age = i64::try_from(max_age.as_millis().min(90_000)).unwrap_or(90_000);
        let requirements =
            serde_json::to_value(data).map_err(|error| StoreError::Serialization(error.to_string()))?;
        let row = sqlx::query("SELECT worker_id,last_heartbeat_at,capabilities,data_capabilities FROM crawlx_eligible_data_worker($1,$2,$3)")
            .bind(required_ids).bind(requirements).bind(age).fetch_optional(&self.pool).await.map_err(db)?;
        row.as_ref().map(data_worker_row).transpose()
    }

    async fn live_acquisition_workers(
        &self,
        max_age: std::time::Duration,
    ) -> Result<Vec<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
        let milliseconds = i64::try_from(max_age.as_millis().min(90_000)).unwrap_or(90_000);
        if milliseconds == 0 {
            return Ok(Vec::new());
        }
        let rows = sqlx::query("SELECT worker_id,last_heartbeat_at,capabilities,data_capabilities FROM crawlx_live_data_workers($1)")
            .bind(milliseconds).fetch_all(&self.pool).await.map_err(db)?;
        rows.iter().map(data_worker_row).collect()
    }

    async fn eligible_acquisition_worker(
        &self,
        required_ids: &[String],
        max_age: std::time::Duration,
    ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
        validate_required_backends(required_ids)?;
        self.eligible_data_worker(required_ids, &Default::default(), max_age)
            .await
    }
}

fn data_worker_row(
    row: &sqlx::postgres::PgRow,
) -> Result<crawlx_core::acquisition::WorkerCapabilitiesV1, StoreError> {
    let backends = serde_json::from_value(get(row, "capabilities")?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let mut worker = crawlx_core::acquisition::WorkerCapabilitiesV1::new(
        WorkerId(get(row, "worker_id")?),
        get(row, "last_heartbeat_at")?,
        backends,
    )
    .map_err(|error| StoreError::Serialization(error.to_string()))?;
    worker.data = serde_json::from_value(get(row, "data_capabilities")?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    worker.data.validate()?;
    Ok(worker)
}

fn validate_required_backends(required: &[String]) -> Result<(), StoreError> {
    if required.is_empty()
        || required.len() > 4
        || required
            .iter()
            .any(|id| !matches!(id.as_str(), "native_http" | "native_browser"))
    {
        return Err(StoreError::Serialization(
            "invalid required acquisition backend IDs".to_owned(),
        ));
    }
    Ok(())
}

fn acquisition_capacity(
    capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
) -> Result<serde_json::Value, StoreError> {
    if capabilities.len() > 4 {
        return Err(StoreError::Serialization(
            "worker capability count exceeds four".to_owned(),
        ));
    }
    for capability in capabilities {
        capability
            .validate_evidence()
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
    }
    let value =
        serde_json::to_value(capabilities).map_err(|error| StoreError::Serialization(error.to_string()))?;
    if serde_json::to_vec(&value)
        .map_err(|error| StoreError::Serialization(error.to_string()))?
        .len()
        > crawlx_core::acquisition::MAX_METADATA_BYTES
    {
        return Err(StoreError::Serialization(
            "worker capability metadata exceeds byte cap".to_owned(),
        ));
    }
    Ok(value)
}

#[derive(Default)]
pub(crate) struct WorkerRegistryState {
    pub(crate) rows: std::collections::BTreeMap<
        WorkerId,
        (WorkerRow, Vec<crawlx_core::acquisition::BackendCapabilitiesV1>),
    >,
    data: std::collections::BTreeMap<WorkerId, crawlx_core::data_capabilities::WorkerDataCapabilitiesV1>,
}

#[async_trait]
impl WorkerRegistry for crate::MemoryStore {
    async fn register_worker(&self, id: WorkerId, hostname: &str, version: &str) -> Result<(), StoreError> {
        let now = self.worker_registry_now();
        let mut registry = self.worker_registry.lock();
        registry.data.remove(&id);
        registry.rows.insert(
            id,
            (
                WorkerRow {
                    id,
                    hostname: hostname.to_owned(),
                    version: version.to_owned(),
                    draining: false,
                    started_at: now,
                    last_heartbeat_at: now,
                    leases_held: 0,
                    capacity: serde_json::json!({}),
                },
                Vec::new(),
            ),
        );
        Ok(())
    }
    async fn worker_heartbeat(&self, id: WorkerId) -> Result<bool, StoreError> {
        let mut registry = self.worker_registry.lock();
        let (row, _) = registry.rows.get_mut(&id).ok_or_else(|| StoreError::NotFound {
            entity: "worker",
            id: id.to_string(),
        })?;
        row.last_heartbeat_at = self.worker_registry_now();
        Ok(row.draining)
    }
    async fn publish_acquisition_capabilities(
        &self,
        id: WorkerId,
        capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
    ) -> Result<(), StoreError> {
        let capacity = acquisition_capacity(capabilities)?;
        let mut registry = self.worker_registry.lock();
        let (row, backends) = registry.rows.get_mut(&id).ok_or_else(|| StoreError::NotFound {
            entity: "worker",
            id: id.to_string(),
        })?;
        row.capacity["acquisition"] = capacity;
        row.capacity["acceptsQueued"] = serde_json::json!(true);
        row.capacity
            .as_object_mut()
            .map(|object| object.remove("localRun"));
        row.last_heartbeat_at = self.worker_registry_now();
        backends.clear();
        backends.extend_from_slice(capabilities);
        Ok(())
    }
    async fn publish_local_acquisition_capabilities(
        &self,
        id: WorkerId,
        run: CrawlRunId,
        capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
    ) -> Result<(), StoreError> {
        let capacity = acquisition_capacity(capabilities)?;
        let mut registry = self.worker_registry.lock();
        let (row, backends) = registry.rows.get_mut(&id).ok_or_else(|| StoreError::NotFound {
            entity: "worker",
            id: id.to_string(),
        })?;
        row.capacity["acquisition"] = capacity;
        row.capacity["acceptsQueued"] = serde_json::json!(false);
        row.capacity["localRun"] = serde_json::json!(run);
        row.last_heartbeat_at = self.worker_registry_now();
        backends.clear();
        backends.extend_from_slice(capabilities);
        Ok(())
    }
    async fn publish_data_capabilities(
        &self,
        id: WorkerId,
        facts: &crawlx_core::data_capabilities::WorkerDataCapabilitiesV1,
    ) -> Result<(), StoreError> {
        facts.validate()?;
        let mut registry = self.worker_registry.lock();
        let (row, _) = registry.rows.get_mut(&id).ok_or_else(|| StoreError::NotFound {
            entity: "worker",
            id: id.to_string(),
        })?;
        row.capacity["data"] =
            serde_json::to_value(facts).map_err(|error| StoreError::Serialization(error.to_string()))?;
        row.last_heartbeat_at = self.worker_registry_now();
        registry.data.insert(id, facts.clone());
        Ok(())
    }
    async fn eligible_data_worker(
        &self,
        required_ids: &[String],
        data: &crawlx_core::data_capabilities::WorkerDataRequirementsV1,
        max_age: std::time::Duration,
    ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
        if !required_ids.is_empty() {
            validate_required_backends(required_ids)?;
        }
        data.validate()?;
        if max_age.is_zero() {
            return Ok(None);
        }
        let now = self.worker_registry_now();
        let cutoff = now
            - chrono::Duration::milliseconds(
                i64::try_from(max_age.as_millis().min(90_000)).unwrap_or(90_000),
            );
        let registry = self.worker_registry.lock();
        for (row, backends) in registry.rows.values() {
            let facts = registry.data.get(&row.id).cloned().unwrap_or_default();
            if row.draining
                || row.capacity["acceptsQueued"] != true
                || row.last_heartbeat_at < cutoff
                || row.last_heartbeat_at > now
                || !facts.supports(data)
                || !required_ids.iter().all(|id| {
                    backends
                        .iter()
                        .any(|backend| backend.available && backend.backend_id == *id)
                })
            {
                continue;
            }
            let mut worker = crawlx_core::acquisition::WorkerCapabilitiesV1::new(
                row.id,
                row.last_heartbeat_at,
                backends.clone(),
            )
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
            worker.data = facts;
            return Ok(Some(worker));
        }
        Ok(None)
    }
    async fn live_acquisition_workers(
        &self,
        max_age: std::time::Duration,
    ) -> Result<Vec<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
        if max_age.is_zero() {
            return Ok(Vec::new());
        }
        let now = self.worker_registry_now();
        let age =
            chrono::Duration::milliseconds(i64::try_from(max_age.as_millis().min(90_000)).unwrap_or(90_000));
        let cutoff = now - age;
        let registry = self.worker_registry.lock();
        registry
            .rows
            .values()
            .filter(|(row, backends)| {
                !row.draining
                    && row.capacity["acceptsQueued"] == true
                    && !backends.is_empty()
                    && row.last_heartbeat_at >= cutoff
                    && row.last_heartbeat_at <= now
            })
            .take(crawlx_core::acquisition::WORKER_CAPABILITY_SNAPSHOT_LIMIT.saturating_add(1))
            .map(|(row, backends)| {
                let mut worker = crawlx_core::acquisition::WorkerCapabilitiesV1::new(
                    row.id,
                    row.last_heartbeat_at,
                    backends.clone(),
                )
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
                worker.data = registry.data.get(&row.id).cloned().unwrap_or_default();
                Ok(worker)
            })
            .collect()
    }
    async fn eligible_acquisition_worker(
        &self,
        required_ids: &[String],
        max_age: std::time::Duration,
    ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
        validate_required_backends(required_ids)?;
        self.eligible_data_worker(required_ids, &Default::default(), max_age)
            .await
    }
}

impl crate::MemoryStore {
    /// Check data requirements while holding only the separate worker-registry authority.
    pub(crate) fn worker_data_ready(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        config: &crawlx_core::config::CreateCrawl,
        now: crawlx_core::Timestamp,
    ) -> Result<bool, StoreError> {
        let required = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(config)?;
        if required.destinations.is_empty() && required.language_bundle.is_none() {
            return Ok(true);
        }
        let registry = self.worker_registry.lock();
        let Some((row, _)) = registry.rows.get(&worker) else {
            return Ok(false);
        };
        let in_scope =
            row.capacity["acceptsQueued"] == true || row.capacity["localRun"] == serde_json::json!(run);
        Ok(in_scope
            && !row.draining
            && row.last_heartbeat_at >= now - chrono::Duration::seconds(90)
            && row.last_heartbeat_at <= now
            && registry
                .data
                .get(&worker)
                .is_some_and(|facts| facts.supports(&required)))
    }
}

/// The admin operations over PostgreSQL.
pub struct AdminOps<'a> {
    pg: &'a Pg,
    actor: String,
}

impl<'a> AdminOps<'a> {
    /// Operations recorded in the audit log as `admin:<operator>`.
    #[must_use]
    pub fn new(pg: &'a Pg, operator: &str) -> Self {
        Self {
            pg,
            actor: format!("admin:{operator}"),
        }
    }

    async fn audit(
        &self,
        tenant: Option<TenantId>,
        run: Option<CrawlRunId>,
        event: &str,
        subject: serde_json::Value,
    ) -> Result<(), StoreError> {
        append_audit(
            self.pg,
            tenant.map(|t| t.0),
            run.map(|r| r.0),
            &self.actor,
            event,
            subject,
        )
        .await
    }

    /// Current `scheduler.admission`.
    ///
    /// # Errors
    /// Returns an error if the setting cannot be read or holds an unknown value.
    pub async fn admission(&self) -> Result<AdmissionMode, StoreError> {
        admission_of(self.pg).await
    }

    /// Set `scheduler.admission` (`freeze` = `Frozen`, `resume` = `Open`).
    ///
    /// # Errors
    /// Returns an error if the update or the audit append fails.
    pub async fn set_admission(&self, mode: AdmissionMode) -> Result<AdmissionMode, StoreError> {
        let before = self.admission().await?;
        sqlx::query(
            "UPDATE cluster_settings SET value = $1, updated_at = now(), updated_by = $2 WHERE key = 'scheduler.admission'",
        )
        .bind(mode.as_str())
        .bind(&self.actor)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?;
        self.audit(
            None,
            None,
            "admin.admission",
            serde_json::json!({ "from": before.as_str(), "to": mode.as_str() }),
        )
        .await?;
        Ok(before)
    }

    /// Pause every `running` run selected (`pause_requested_at = now()`, `status = paused`); the
    /// Session Actors stop at their next action boundary. Returns the runs paused.
    ///
    /// # Errors
    /// Returns an error if the update, the event append or the audit append fails.
    pub async fn pause(&self, sel: RunSelector) -> Result<Vec<CrawlRunId>, StoreError> {
        let sql = selected_sql!(
            sel,
            "UPDATE crawl_runs SET status = 'paused', pause_requested_at = now() \
             WHERE status = 'running' AND ",
            " RETURNING run_id, tenant_id"
        );
        let rows = sqlx::query(sql)
            .bind(sel.arg())
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let run = CrawlRunId(get(r, "run_id")?);
            let tenant = TenantId(get(r, "tenant_id")?);
            self.append_event(run, "paused", serde_json::json!({ "by": self.actor }))
                .await?;
            self.audit(Some(tenant), Some(run), "admin.pause", sel.describe())
                .await?;
            out.push(run);
        }
        Ok(out)
    }

    /// Resume every `paused` run selected. Returns the runs resumed.
    ///
    /// # Errors
    /// Returns an error if the update, the event append or the audit append fails.
    pub async fn resume(&self, sel: RunSelector) -> Result<Vec<CrawlRunId>, StoreError> {
        let sql = selected_sql!(
            sel,
            "UPDATE crawl_runs SET status = 'running', pause_requested_at = NULL \
             WHERE status = 'paused' AND ",
            " RETURNING run_id, tenant_id"
        );
        let rows = sqlx::query(sql)
            .bind(sel.arg())
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let run = CrawlRunId(get(r, "run_id")?);
            let tenant = TenantId(get(r, "tenant_id")?);
            self.append_event(run, "resumed", serde_json::json!({ "by": self.actor }))
                .await?;
            self.audit(Some(tenant), Some(run), "admin.resume", sel.describe())
                .await?;
            out.push(run);
        }
        Ok(out)
    }

    /// Cancel every non-terminal run selected (`terminal_reason = cancelled`, or
    /// `policy_stopped` for safety-related stops); pending sessions become `cancelled`.
    ///
    /// # Errors
    /// Returns an error if the update, the event append or the audit append fails.
    pub async fn cancel(&self, sel: RunSelector, reason: &str) -> Result<Vec<CrawlRunId>, StoreError> {
        if !matches!(reason, "cancelled" | "policy_stopped") {
            return Err(StoreError::Conflict(format!(
                "cancel reason must be `cancelled` or `policy_stopped`, got {reason:?}"
            )));
        }
        let sql = selected_sql!(
            sel,
            "UPDATE crawl_runs SET status = 'cancelled', terminal_reason = $2::text::terminal_reason, \
               cancel_requested_at = now(), finished_at = now() \
             WHERE status::text IN ('queued','running','pausing','paused','cancelling') AND ",
            " RETURNING run_id, tenant_id"
        );
        let rows = sqlx::query(sql)
            .bind(sel.arg())
            .bind(reason)
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let run = CrawlRunId(get(r, "run_id")?);
            let tenant = TenantId(get(r, "tenant_id")?);
            sqlx::query("UPDATE crawl_sessions SET status = 'cancelled', finished_at = now() WHERE run_id = $1 AND status = 'pending'")
                .bind(run.0)
                .execute(&self.pg.pool)
                .await
                .map_err(db)?;
            self.append_event(
                run,
                "status",
                serde_json::json!({ "status": "cancelled", "terminalReason": reason }),
            )
            .await?;
            self.append_event(
                run,
                "completed",
                serde_json::json!({ "status": "cancelled", "terminalReason": reason, "by": self.actor }),
            )
            .await?;
            self.audit(
                Some(tenant),
                Some(run),
                "admin.cancel",
                serde_json::json!({ "selector": sel.describe(), "reason": reason }),
            )
            .await?;
            out.push(run);
        }
        Ok(out)
    }

    /// Mark `worker` draining: it stops taking leases at its next heartbeat and hands its
    /// sessions over at their next action boundary. Returns the number of leases it holds now.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] if the worker never registered, or an error if the
    /// update or the audit append fails.
    pub async fn drain_worker(&self, worker: WorkerId) -> Result<u64, StoreError> {
        let n = sqlx::query("UPDATE workers SET draining = true WHERE worker_id = $1")
            .bind(worker.0)
            .execute(&self.pg.pool)
            .await
            .map_err(db)?
            .rows_affected();
        if n == 0 {
            return Err(crate::error::not_found("worker", worker));
        }
        let held: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM crawl_sessions WHERE lease_owner = $1 AND status IN ('running','recovering')",
        )
        .bind(worker.0)
        .fetch_one(&self.pg.pool)
        .await
        .map_err(db)?;
        self.audit(
            None,
            None,
            "admin.drain",
            serde_json::json!({ "worker": worker, "leases_held": held }),
        )
        .await?;
        Ok(u64::try_from(held).unwrap_or(0))
    }

    /// Registered workers with their held leases.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub async fn workers(&self) -> Result<Vec<WorkerRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT w.worker_id, w.hostname, w.version, w.capacity, w.draining, w.started_at, w.last_heartbeat_at, \
                    (SELECT count(*) FROM crawl_sessions s WHERE s.lease_owner = w.worker_id AND s.status IN ('running','recovering')) AS held \
             FROM workers w ORDER BY w.started_at, w.worker_id",
        )
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                let held: i64 = get(r, "held")?;
                Ok(WorkerRow {
                    id: WorkerId(get(r, "worker_id")?),
                    hostname: get(r, "hostname")?,
                    version: get(r, "version")?,
                    draining: get(r, "draining")?,
                    started_at: get(r, "started_at")?,
                    last_heartbeat_at: get(r, "last_heartbeat_at")?,
                    capacity: get(r, "capacity")?,
                    leases_held: u64::try_from(held).unwrap_or(0),
                })
            })
            .collect()
    }

    /// Actions in `intended` or `unknown` (RB-02 step 1), oldest first; `action` narrows to one.
    ///
    /// # Errors
    /// Returns an error if the query fails.
    pub async fn open_actions(&self, action: Option<ActionId>) -> Result<Vec<OpenAction>, StoreError> {
        let rows = sqlx::query(
            "SELECT a.action_id, a.run_id, a.session_id, a.status::text AS status, s.status AS session_status, a.intended_at \
             FROM actions a JOIN crawl_sessions s ON s.session_id = a.session_id \
             WHERE a.status::text IN ('intended','unknown') AND ($1::uuid IS NULL OR a.action_id = $1) \
             ORDER BY a.intended_at NULLS LAST, a.action_id",
        )
        .bind(action.map(|a| a.0))
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(OpenAction {
                    id: ActionId(get(r, "action_id")?),
                    run: CrawlRunId(get(r, "run_id")?),
                    session: SessionId(get(r, "session_id")?),
                    status: get(r, "status")?,
                    session_status: get(r, "session_status")?,
                    intended_at: get(r, "intended_at")?,
                })
            })
            .collect()
    }

    /// Hand an `unknown` action's session to the reconciler: a `running` session whose lease is
    /// not held becomes `recovering` so the next worker claims it, restores the checkpoint and
    /// runs reconciliation (RB-02 step 3). Returns the session's status afterwards.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown action, [`StoreError::Conflict`] when the
    /// action is not `unknown` or its session is terminal, or an error if the update fails.
    pub async fn request_reconcile(&self, action: ActionId) -> Result<String, StoreError> {
        let Some(open) = self.open_actions(Some(action)).await?.into_iter().next() else {
            return Err(crate::error::not_found("action", action));
        };
        if open.status != "unknown" {
            return Err(StoreError::Conflict(format!(
                "action {action} is `{}`; only `unknown` actions are reconciled (an `intended` row \
                 becomes `unknown` when its lease expires)",
                open.status
            )));
        }
        let status: String = sqlx::query_scalar(
            "UPDATE crawl_sessions SET status = CASE WHEN status = 'running' AND (lease_expires_at IS NULL OR lease_expires_at < now()) \
                                               THEN 'recovering' ELSE status END \
             WHERE session_id = $1 RETURNING status",
        )
        .bind(open.session.0)
        .fetch_one(&self.pg.pool)
        .await
        .map_err(db)?;
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return Err(StoreError::Conflict(format!(
                "session {} is terminal ({status}); restore it from a checkpoint before reconciling",
                open.session
            )));
        }
        self.audit(
            None,
            Some(open.run),
            "admin.reconcile",
            serde_json::json!({ "action": action, "session": open.session, "session_status": status }),
        )
        .await?;
        Ok(status)
    }

    /// Set `tenants.engine` (the rollback flag). Returns the previous value.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for an unknown tenant, or an error if the update or the
    /// audit append fails.
    pub async fn set_tenant_engine(
        &self,
        tenant: TenantId,
        engine: TenantEngine,
    ) -> Result<TenantEngine, StoreError> {
        let before: Option<String> = sqlx::query_scalar("SELECT engine FROM tenants WHERE tenant_id = $1")
            .bind(tenant.0)
            .fetch_optional(&self.pg.pool)
            .await
            .map_err(db)?;
        let before = TenantEngine::parse(&before.ok_or_else(|| crate::error::not_found("tenant", tenant))?)?;
        sqlx::query("UPDATE tenants SET engine = $2 WHERE tenant_id = $1")
            .bind(tenant.0)
            .bind(engine.as_str())
            .execute(&self.pg.pool)
            .await
            .map_err(db)?;
        self.audit(
            Some(tenant),
            None,
            "admin.engine",
            serde_json::json!({ "from": before.as_str(), "to": engine.as_str() }),
        )
        .await?;
        Ok(before)
    }

    /// Check every live `artifacts` row created at or after `since` against `blobs`: the object
    /// must exist and its bytes must hash to the recorded digest (RB-06 step 6, `verify-artifacts`).
    /// Objects under the class prefixes and the encrypted-object prefix with no live row
    /// are counted as orphans.
    ///
    /// Encrypted artifacts are checked against their ciphertext identity only; use
    /// [`Self::verify_artifacts_with_keys`] to authenticate and decrypt them as well.
    ///
    /// # Errors
    /// Returns an error if the rows cannot be read or the store cannot be queried.
    pub async fn verify_artifacts(
        &self,
        blobs: &dyn ArtifactBlobs,
        since: Option<Timestamp>,
    ) -> Result<ArtifactVerification, StoreError> {
        self.verify_artifacts_with_keys(blobs, None, since).await
    }

    /// [`Self::verify_artifacts`] that also unwraps each encrypted artifact's key through
    /// `keys`, authenticates every ciphertext frame and checks the plaintext digest and size
    /// against the catalog row. Encrypted artifacts whose ciphertext identity or plaintext
    /// does not verify are reported as `digest_mismatch`; failures to authenticate or unwrap
    /// are reported as `decrypt_failed`. Without `keys` only the ciphertext identity is checked.
    ///
    /// # Errors
    /// Returns an error if the rows cannot be read or the store cannot be queried.
    pub async fn verify_artifacts_with_keys(
        &self,
        blobs: &dyn ArtifactBlobs,
        keys: Option<&dyn crate::artifact_key_crypto::ArtifactKeys>,
        since: Option<Timestamp>,
    ) -> Result<ArtifactVerification, StoreError> {
        let rows = sqlx::query(
            "SELECT a.artifact_id, a.run_id, a.object_key, a.content_digest, \
                    c.envelope, c.artifact_payload, c.ciphertext_digest, c.ciphertext_size \
             FROM artifacts a LEFT JOIN artifact_key_custody c ON c.artifact_id = a.artifact_id \
             WHERE a.deleted_at IS NULL AND ($1::timestamptz IS NULL OR a.created_at >= $1) \
             ORDER BY a.artifact_id",
        )
        .bind(since)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        let mut out = ArtifactVerification::default();
        let mut live_keys = std::collections::BTreeSet::new();
        for r in &rows {
            let artifact_id: uuid::Uuid = get(r, "artifact_id")?;
            let run = CrawlRunId(get(r, "run_id")?);
            let object_key: String = get(r, "object_key")?;
            let digest: Vec<u8> = get(r, "content_digest")?;
            let sealed: Option<serde_json::Value> = get(r, "envelope")?;
            out.checked += 1;
            live_keys.insert(object_key.clone());
            let defect = match blobs.get(&object_key).await? {
                None => Some("missing"),
                Some(bytes) => match sealed {
                    None => {
                        let actual = Digest::of(crate::artifacts::DIGEST_DOMAIN, &bytes);
                        (actual.0.as_slice() != digest.as_slice()).then_some("digest_mismatch")
                    }
                    Some(envelope) => Self::verify_sealed(keys, r, envelope, bytes).await?,
                },
            };
            if let Some(defect) = defect {
                out.defects.push(ArtifactDefect {
                    artifact_id,
                    run,
                    object_key,
                    defect,
                });
            }
        }
        if since.is_none() {
            // only a full pass can call an object an orphan
            for class in [
                "metadata",
                "content",
                "sensitive",
                "credential_bearing",
                "encrypted",
            ] {
                for entry in blobs.list(&format!("{class}/")).await? {
                    if !live_keys.contains(&entry.key) {
                        out.orphans += 1;
                    }
                }
            }
        }
        self.audit(
            None,
            None,
            "admin.verify_artifacts",
            serde_json::json!({ "since": since, "checked": out.checked, "defects": out.defects.len(), "orphans": out.orphans }),
        )
        .await?;
        Ok(out)
    }

    async fn verify_sealed(
        keys: Option<&dyn crate::artifact_key_crypto::ArtifactKeys>,
        r: &sqlx::postgres::PgRow,
        envelope: serde_json::Value,
        bytes: Vec<u8>,
    ) -> Result<Option<&'static str>, StoreError> {
        let ciphertext_digest: Vec<u8> = get(r, "ciphertext_digest")?;
        let ciphertext_size: i64 = get(r, "ciphertext_size")?;
        let actual = Digest::of(crate::custody::CIPHERTEXT_DIGEST_DOMAIN, &bytes);
        if actual.0.as_slice() != ciphertext_digest.as_slice()
            || i64::try_from(bytes.len()).ok() != Some(ciphertext_size)
        {
            return Ok(Some("digest_mismatch"));
        }
        let Some(keys) = keys else {
            return Ok(None);
        };
        let payload: serde_json::Value = get(r, "artifact_payload")?;
        let (Ok(row), Ok(envelope), Ok(ciphertext)) = (
            serde_json::from_value::<crate::ArtifactRow>(payload),
            serde_json::from_value::<crate::custody::ArtifactKeyEnvelope>(envelope),
            <[u8; 32]>::try_from(ciphertext_digest).map(|digest| {
                crate::custody::CiphertextIdentity::new(
                    Digest(digest),
                    u64::try_from(ciphertext_size).unwrap_or(0),
                )
            }),
        ) else {
            return Ok(Some("decrypt_failed"));
        };
        let Ok(ciphertext) = ciphertext else {
            return Ok(Some("decrypt_failed"));
        };
        let custody = crate::custody::ArtifactKeyCustody { envelope, ciphertext };
        Ok(
            crate::artifact_custody::open_sealed_bytes(keys, bytes, &row, &custody)
                .await
                .err()
                .map(|error| match error {
                    StoreError::Conflict(detail) if detail.contains("plaintext verification") => {
                        "digest_mismatch"
                    }
                    _ => "decrypt_failed",
                }),
        )
    }

    /// Accepted crawl-job durability: compare the append-only accept log
    /// (`audit_events` rows with `event = 'crawl.accepted'`, written by the API before it
    /// acknowledges a job) against `crawl_runs`. Every accepted run must still have its
    /// row; `since` restricts the accept log to rows at or after that instant. The audit
    /// itself is recorded as `admin.durability_audit`.
    ///
    /// # Errors
    /// Returns an error if a query or the audit append fails.
    pub async fn durability_audit(&self, since: Option<Timestamp>) -> Result<DurabilityAudit, StoreError> {
        let checked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_events e \
             WHERE e.event = 'crawl.accepted' AND e.run_id IS NOT NULL \
               AND ($1::timestamptz IS NULL OR e.occurred_at >= $1)",
        )
        .bind(since)
        .fetch_one(&self.pg.pool)
        .await
        .map_err(db)?;
        let rows = sqlx::query(
            "SELECT DISTINCT e.run_id FROM audit_events e \
             LEFT JOIN crawl_runs r ON r.run_id = e.run_id \
             WHERE e.event = 'crawl.accepted' AND e.run_id IS NOT NULL \
               AND ($1::timestamptz IS NULL OR e.occurred_at >= $1) \
               AND r.run_id IS NULL \
             ORDER BY e.run_id",
        )
        .bind(since)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        let missing = rows
            .iter()
            .map(|r| get(r, "run_id").map(CrawlRunId))
            .collect::<Result<Vec<_>, _>>()?;
        let out = DurabilityAudit {
            checked: u64::try_from(checked).unwrap_or(0),
            missing,
        };
        self.audit(
            None,
            None,
            "admin.durability_audit",
            serde_json::json!({ "since": since, "checked": out.checked, "missing": out.missing.len() }),
        )
        .await?;
        Ok(out)
    }

    async fn append_event(
        &self,
        run: CrawlRunId,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<(), StoreError> {
        crawlx_core::repo::EventRepo::append(self.pg, run, kind, payload)
            .await
            .map(|_| ())
    }
}

/// Runs in `queued|running|pausing|paused` (the `crawlx admin status` headline).
///
/// # Errors
/// Returns an error if the query fails.
pub async fn active_run_count(pg: &Pg) -> Result<i64, StoreError> {
    sqlx::query_scalar(
        "SELECT count(*) FROM crawl_runs WHERE status::text IN ('queued','running','pausing','paused')",
    )
    .fetch_one(&pg.pool)
    .await
    .map_err(db)
}

/// RB-08 step 3 (`crawlx admin sweep-retention --mode zdr --force`): for every run with
/// `retention_mode = zdr`, delete its artifact objects **first**, mark the `artifacts` rows
/// deleted, delete its `pages` rows, and keep the structural trail (`actions`, `transitions`,
/// `network_epochs`, `states`). Deleted keys (never contents) are written to the audit log.
/// Returns the runs touched.
///
/// # Errors
/// Returns an error if a query, the object deletion or the audit append fails.
pub async fn force_zdr_sweep(
    pg: &Pg,
    sweeper: &crate::retention::RetentionSweeper,
    actor: &str,
) -> Result<Vec<CrawlRunId>, StoreError> {
    let rows =
        sqlx::query("SELECT run_id, tenant_id FROM crawl_runs WHERE retention_mode = 'zdr' ORDER BY run_id")
            .fetch_all(&pg.pool)
            .await
            .map_err(db)?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let run = CrawlRunId(get(r, "run_id")?);
        let tenant: uuid::Uuid = get(r, "tenant_id")?;
        let keys: Vec<String> = sqlx::query_scalar(
            "SELECT object_key FROM artifacts WHERE run_id = $1 AND deleted_at IS NULL ORDER BY object_key",
        )
        .bind(run.0)
        .fetch_all(&pg.pool)
        .await
        .map_err(db)?;
        let objects = sweeper.purge_run_objects(run).await?;
        sqlx::query("UPDATE artifacts SET deleted_at = now() WHERE run_id = $1 AND deleted_at IS NULL")
            .bind(run.0)
            .execute(&pg.pool)
            .await
            .map_err(db)?;
        let pages = sqlx::query("DELETE FROM pages WHERE run_id = $1")
            .bind(run.0)
            .execute(&pg.pool)
            .await
            .map_err(db)?
            .rows_affected();
        append_audit(
            pg,
            Some(tenant),
            Some(run.0),
            actor,
            "admin.zdr_force_sweep",
            serde_json::json!({ "objects_deleted": objects, "pages_deleted": pages, "object_keys": keys }),
        )
        .await?;
        out.push(run);
    }
    Ok(out)
}

/// `scheduler.admission` as stored, for the scheduler and the workers.
///
/// # Errors
/// Returns an error if the row cannot be read or holds an unknown value.
pub async fn admission_of(pg: &Pg) -> Result<AdmissionMode, StoreError> {
    let value: Option<String> =
        sqlx::query_scalar("SELECT value FROM cluster_settings WHERE key = 'scheduler.admission'")
            .fetch_optional(&pg.pool)
            .await
            .map_err(db)?;
    value
        .as_deref()
        .map_or(Ok(AdmissionMode::Open), AdmissionMode::parse)
}

/// `tenants.engine` of `tenant`; `None` when the tenant row does not exist.
///
/// # Errors
/// Returns an error if the query fails or the stored value is unknown.
pub async fn tenant_engine_of(pg: &Pg, tenant: TenantId) -> Result<Option<TenantEngine>, StoreError> {
    let value: Option<String> = sqlx::query_scalar("SELECT engine FROM tenants WHERE tenant_id = $1")
        .bind(tenant.0)
        .fetch_optional(&pg.pool)
        .await
        .map_err(db)?;
    value.as_deref().map(TenantEngine::parse).transpose()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn admission_round_trips() {
        for m in [AdmissionMode::Open, AdmissionMode::Drain, AdmissionMode::Frozen] {
            assert_eq!(AdmissionMode::parse(m.as_str()).unwrap(), m);
        }
        assert!(AdmissionMode::parse("closed").is_err());
        assert!(AdmissionMode::Open.grants_leases());
        assert!(!AdmissionMode::Drain.grants_leases());
        assert!(!AdmissionMode::Frozen.grants_leases());
    }

    #[test]
    fn engine_round_trips() {
        for e in [TenantEngine::Crawlx, TenantEngine::Upstream, TenantEngine::Shadow] {
            assert_eq!(TenantEngine::parse(e.as_str()).unwrap(), e);
        }
        assert!(TenantEngine::parse("unknown").is_err());
    }

    #[test]
    fn selector_clauses_bind_one_argument() {
        assert_eq!(selected_sql!(RunSelector::All, "", ""), "$1::uuid IS NULL");
        assert_eq!(RunSelector::All.arg(), None);
        let id = CrawlRunId::new();
        assert_eq!(selected_sql!(RunSelector::Crawl(id), "", ""), "run_id = $1");
        assert_eq!(RunSelector::Crawl(id).arg(), Some(id.0));
    }
}
