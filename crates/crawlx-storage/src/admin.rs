//! Operator controls behind `crawlx admin` (`scheduler.admission`, RB-11,
//! `verify-artifacts`; tenant engine flag).
//!
//! Every operation here is the SQL the runbooks name, wrapped so the CLI never runs its own
//! statements, and every mutation appends to the hash-chained `audit_events` log
//! (`actor = "admin:<operator>"`). Containment (`pause`, `freeze`, `drain`) stays expressible
//! in plain SQL (RB-11) because an emergency stop must not depend on this binary.

use crate::artifacts::ArtifactBlobs;
use crate::backend::{Backend, BackendKind, Dialect, MariaBackend, PgBackend, RowLock, SqliteBackend};
use crate::codec::get;
use crate::error::db;
use crate::repos::effects::settle_run;
use crate::retention::append_audit;
use crate::sql::{stmt, Sql, SqlRow, Stmt};
use crate::store::{Pg, Store};
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

impl RunSelector {
    /// The predicate selecting the runs, over the one value [`RunSelector::arg`] binds to `$1`.
    const fn predicate(self) -> &'static str {
        match self {
            Self::Crawl(_) => "run_id = $1",
            Self::Tenant(_) => "tenant_id = $1",
            Self::All => "$1::uuid IS NULL",
        }
    }

    /// The value bound to `$1` of [`RunSelector::predicate`].
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
        || required.iter().any(|id| {
            !matches!(
                id.as_str(),
                "native_http" | "native_browser" | "acquisition_service"
            )
        })
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

/// The worker registry of the engines without the PostgreSQL SQL functions (MariaDB, SQLite):
/// capability JSON is merged and judged in Rust, with one shared eligibility rule.
mod registry {
    use super::{acquisition_capacity, validate_required_backends};
    use crate::backend::{Dialect, RowLock};
    use crate::sql::{stmt, Sql, SqlRow, Stmt};
    use crate::store::Store;
    use crate::worker_eligibility::{claim_eligible, WorkerFacts};
    use crawlx_core::acquisition::{BackendCapabilitiesV1, WorkerCapabilitiesV1};
    use crawlx_core::data_capabilities::{WorkerDataCapabilitiesV1, WorkerDataRequirementsV1};
    use crawlx_core::{CrawlRunId, StoreError, Timestamp, WorkerId};
    use serde_json::{Map, Value};
    use std::time::Duration;

    /// Largest `workers.capacity` document an eligibility read accepts.
    const MAX_CAPACITY_BYTES: usize = 98_304;

    fn not_found(id: WorkerId) -> StoreError {
        StoreError::NotFound {
            entity: "worker",
            id: id.to_string(),
        }
    }

    pub(super) async fn register<B: Sql>(
        store: &Store<B>,
        id: WorkerId,
        hostname: &str,
        version: &str,
    ) -> Result<(), StoreError> {
        let now = <B::Dialect as Dialect>::now();
        let update = <B::Dialect as Dialect>::upsert_update(&["worker_id"], &["hostname", "version"], None);
        Stmt::<B>::dynamic(&format!(
            "INSERT INTO workers (worker_id, hostname, version, capacity, last_heartbeat_at) \
             VALUES ($1, $2, $3, '{{}}', {now}) \
             {update}, capacity = '{{}}', draining = false, started_at = {now}, last_heartbeat_at = {now}"
        ))
        .uuid(id.0)
        .text(hostname)
        .text(version)
        .execute_write(&store.pool)
        .await?;
        Ok(())
    }

    pub(super) async fn heartbeat<B: Sql>(store: &Store<B>, id: WorkerId) -> Result<bool, StoreError> {
        let update = format!(
            "UPDATE workers SET last_heartbeat_at = {} WHERE worker_id = $1",
            <B::Dialect as Dialect>::now()
        );
        let draining = if <B::Dialect as Dialect>::UPDATE_RETURNING {
            Stmt::<B>::dynamic(&format!("{update} RETURNING draining"))
                .uuid(id.0)
                .fetch_optional_write(&store.pool)
                .await?
                .map(|row| row.bool("draining"))
                .transpose()?
        } else {
            let mut tx = store.begin_write().await?;
            let matched = Stmt::<B>::dynamic(&update).uuid(id.0).execute(tx.conn()).await?;
            let draining = if matched == 0 {
                None
            } else {
                stmt!(B, "SELECT draining FROM workers WHERE worker_id = $1")
                    .uuid(id.0)
                    .fetch_optional(tx.conn())
                    .await?
                    .map(|row| row.bool("draining"))
                    .transpose()?
            };
            tx.commit().await?;
            draining
        };
        Ok(draining.unwrap_or(false))
    }

    /// Read `workers.capacity` of `id` under the row lock, let `edit` change it and write it
    /// back with a fresh heartbeat, all in one write transaction.
    async fn edit_capacity<B: Sql>(
        store: &Store<B>,
        id: WorkerId,
        edit: impl FnOnce(&mut Map<String, Value>),
    ) -> Result<(), StoreError> {
        let lock = <B::Dialect as Dialect>::row_lock(RowLock::Update);
        let now = <B::Dialect as Dialect>::now();
        let mut tx = store.begin_write().await?;
        let row = Stmt::<B>::dynamic(&format!(
            "SELECT capacity FROM workers WHERE worker_id = $1{lock}"
        ))
        .uuid(id.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or_else(|| not_found(id))?;
        let mut capacity = row.json("capacity")?;
        edit(
            capacity
                .as_object_mut()
                .ok_or_else(|| StoreError::Serialization("worker capacity is not an object".to_owned()))?,
        );
        Stmt::<B>::dynamic(&format!(
            "UPDATE workers SET capacity = $2, last_heartbeat_at = {now} WHERE worker_id = $1"
        ))
        .uuid(id.0)
        .json(&capacity)
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }

    pub(super) async fn publish_acquisition<B: Sql>(
        store: &Store<B>,
        id: WorkerId,
        capabilities: &[BackendCapabilitiesV1],
    ) -> Result<(), StoreError> {
        let capacity = acquisition_capacity(capabilities)?;
        edit_capacity(store, id, |object| {
            object.remove("localRun");
            object.insert("acquisition".to_owned(), capacity);
            object.insert("acceptsQueued".to_owned(), Value::Bool(true));
        })
        .await
    }

    pub(super) async fn publish_local_acquisition<B: Sql>(
        store: &Store<B>,
        id: WorkerId,
        run: CrawlRunId,
        capabilities: &[BackendCapabilitiesV1],
    ) -> Result<(), StoreError> {
        let capacity = acquisition_capacity(capabilities)?;
        edit_capacity(store, id, |object| {
            object.insert("acquisition".to_owned(), capacity);
            object.insert("acceptsQueued".to_owned(), Value::Bool(false));
            object.insert("localRun".to_owned(), Value::String(run.to_string()));
        })
        .await
    }

    pub(super) async fn publish_data<B: Sql>(
        store: &Store<B>,
        id: WorkerId,
        facts: &WorkerDataCapabilitiesV1,
    ) -> Result<(), StoreError> {
        facts.validate()?;
        let value =
            serde_json::to_value(facts).map_err(|error| StoreError::Serialization(error.to_string()))?;
        edit_capacity(store, id, |object| {
            object.insert("data".to_owned(), value);
        })
        .await
    }

    /// Candidate rows: workers not draining whose last heartbeat is within `max_age` of now.
    async fn fresh_workers<B: Sql>(
        store: &Store<B>,
        max_age: Duration,
    ) -> Result<Vec<(WorkerId, Timestamp, Value, bool)>, StoreError> {
        let milliseconds = i64::try_from(max_age.as_millis().min(90_000)).unwrap_or(90_000);
        let now = super::db_now_of(store).await?;
        let since = now - chrono::Duration::milliseconds(milliseconds);
        let rows = stmt!(
            B,
            "SELECT worker_id, last_heartbeat_at, capacity, draining FROM workers \
             WHERE draining = false AND last_heartbeat_at >= $1 AND last_heartbeat_at <= $2 \
             ORDER BY worker_id"
        )
        .ts(since)
        .ts(now)
        .fetch_all_pool(&store.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    WorkerId(row.uuid("worker_id")?),
                    row.ts("last_heartbeat_at")?,
                    row.json("capacity")?,
                    row.bool("draining")?,
                ))
            })
            .collect()
    }

    fn queued(capacity: &Value) -> bool {
        capacity.get("acceptsQueued") == Some(&Value::Bool(true))
            && capacity.to_string().len() <= MAX_CAPACITY_BYTES
    }

    fn worker_of(
        id: WorkerId,
        heartbeat: Timestamp,
        capacity: &Value,
    ) -> Result<WorkerCapabilitiesV1, StoreError> {
        let backends = serde_json::from_value(capacity.get("acquisition").cloned().unwrap_or(Value::Null))
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let mut worker = WorkerCapabilitiesV1::new(id, heartbeat, backends)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        worker.data = serde_json::from_value(
            capacity
                .get("data")
                .cloned()
                .unwrap_or_else(|| Value::Object(Map::new())),
        )
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
        worker.data.validate()?;
        Ok(worker)
    }

    pub(super) async fn eligible_data_worker<B: Sql>(
        store: &Store<B>,
        required_ids: &[String],
        data: &WorkerDataRequirementsV1,
        max_age: Duration,
    ) -> Result<Option<WorkerCapabilitiesV1>, StoreError> {
        if !required_ids.is_empty() {
            validate_required_backends(required_ids)?;
        }
        data.validate()?;
        if max_age.is_zero() {
            return Ok(None);
        }
        let requirements =
            serde_json::to_value(data).map_err(|error| StoreError::Serialization(error.to_string()))?;
        let now = super::db_now_of(store).await?;
        for (id, heartbeat, capacity, draining) in fresh_workers(store, max_age).await? {
            let facts = WorkerFacts {
                capacity,
                draining,
                last_heartbeat_at: heartbeat,
            };
            if queued(&facts.capacity)
                && claim_eligible(
                    Some(&facts),
                    uuid::Uuid::nil(),
                    now,
                    required_ids,
                    false,
                    &requirements,
                )
            {
                return worker_of(id, heartbeat, &facts.capacity).map(Some);
            }
        }
        Ok(None)
    }

    pub(super) async fn live_acquisition_workers<B: Sql>(
        store: &Store<B>,
        max_age: Duration,
    ) -> Result<Vec<WorkerCapabilitiesV1>, StoreError> {
        if max_age.is_zero() {
            return Ok(Vec::new());
        }
        let limit = crawlx_core::acquisition::WORKER_CAPABILITY_SNAPSHOT_LIMIT.saturating_add(1);
        let mut out = Vec::new();
        for (id, heartbeat, capacity, _) in fresh_workers(store, max_age).await? {
            let backends = capacity
                .get("acquisition")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if queued(&capacity) && (1..=4).contains(&backends) {
                out.push(worker_of(id, heartbeat, &capacity)?);
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }
}

/// The engine's own clock for registry freshness.
async fn db_now_of<B: Sql>(store: &Store<B>) -> Result<Timestamp, StoreError> {
    stmt!(B, format!("SELECT {} AS v", <B::Dialect as Dialect>::now()))
        .fetch_one_pool(&store.pool)
        .await?
        .ts("v")
}

macro_rules! worker_registry_impl {
    ($($backend:ty),+) => {$(
        #[async_trait]
        impl WorkerRegistry for Store<$backend> {
            async fn register_worker(&self, id: WorkerId, hostname: &str, version: &str) -> Result<(), StoreError> {
                registry::register(self, id, hostname, version).await
            }

            async fn worker_heartbeat(&self, id: WorkerId) -> Result<bool, StoreError> {
                registry::heartbeat(self, id).await
            }

            async fn publish_acquisition_capabilities(
                &self,
                id: WorkerId,
                capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
            ) -> Result<(), StoreError> {
                registry::publish_acquisition(self, id, capabilities).await
            }

            async fn publish_local_acquisition_capabilities(
                &self,
                id: WorkerId,
                run: CrawlRunId,
                capabilities: &[crawlx_core::acquisition::BackendCapabilitiesV1],
            ) -> Result<(), StoreError> {
                registry::publish_local_acquisition(self, id, run, capabilities).await
            }

            async fn publish_data_capabilities(
                &self,
                id: WorkerId,
                facts: &crawlx_core::data_capabilities::WorkerDataCapabilitiesV1,
            ) -> Result<(), StoreError> {
                registry::publish_data(self, id, facts).await
            }

            async fn eligible_data_worker(
                &self,
                required_ids: &[String],
                data: &crawlx_core::data_capabilities::WorkerDataRequirementsV1,
                max_age: std::time::Duration,
            ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
                registry::eligible_data_worker(self, required_ids, data, max_age).await
            }

            async fn live_acquisition_workers(
                &self,
                max_age: std::time::Duration,
            ) -> Result<Vec<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
                registry::live_acquisition_workers(self, max_age).await
            }

            async fn eligible_acquisition_worker(
                &self,
                required_ids: &[String],
                max_age: std::time::Duration,
            ) -> Result<Option<crawlx_core::acquisition::WorkerCapabilitiesV1>, StoreError> {
                validate_required_backends(required_ids)?;
                registry::eligible_data_worker(self, required_ids, &Default::default(), max_age).await
            }
        }
    )+};
}

worker_registry_impl!(SqliteBackend, MariaBackend);

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

/// `ORDER BY` term putting rows with a `NULL` `col` last.
fn nulls_last<B: Backend>(col: &str) -> String {
    if B::KIND == BackendKind::MariaDb {
        format!("({col} IS NULL), {col}")
    } else {
        format!("{col} NULLS LAST")
    }
}

/// The admin operations over any engine.
pub struct AdminOps<'a, B: Sql = PgBackend> {
    store: &'a Store<B>,
    actor: String,
}

impl<'a, B: Sql> AdminOps<'a, B> {
    /// Operations recorded in the audit log as `admin:<operator>`.
    #[must_use]
    pub fn new(store: &'a Store<B>, operator: &str) -> Self {
        Self {
            store,
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
            self.store,
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
        admission_of(self.store).await
    }

    /// Set `scheduler.admission` (`freeze` = `Frozen`, `resume` = `Open`).
    ///
    /// # Errors
    /// Returns an error if the update or the audit append fails.
    pub async fn set_admission(&self, mode: AdmissionMode) -> Result<AdmissionMode, StoreError> {
        let before = self.admission().await?;
        let now = <B::Dialect as Dialect>::now();
        let key = <B::Dialect as Dialect>::reserved_ident("key");
        Stmt::<B>::dynamic(&format!(
            "UPDATE cluster_settings SET value = $1, updated_at = {now}, updated_by = $2 WHERE {key} = 'scheduler.admission'"
        ))
        .text(mode.as_str())
        .text(&self.actor)
        .execute_write(&self.store.pool)
        .await?;
        self.audit(
            None,
            None,
            "admin.admission",
            serde_json::json!({ "from": before.as_str(), "to": mode.as_str() }),
        )
        .await?;
        Ok(before)
    }

    /// Change the runs `sel` selects that satisfy `condition`: `assignments` is the `SET` list
    /// (it may use `$2` for `reason`). Returns the runs changed with their tenants, in id order.
    ///
    /// `condition` and `assignments` are compile-time literals.
    async fn update_runs(
        &self,
        sel: RunSelector,
        assignments: &str,
        condition: &str,
        reason: Option<&str>,
        settle: bool,
    ) -> Result<Vec<(CrawlRunId, TenantId)>, StoreError> {
        let predicate = sel.predicate();
        let mut changed: Vec<(CrawlRunId, TenantId)> = if <B::Dialect as Dialect>::UPDATE_RETURNING {
            let mut statement = Stmt::<B>::dynamic(&format!(
                "UPDATE crawl_runs SET {assignments} WHERE {condition} AND {predicate} RETURNING run_id, tenant_id"
            ))
            .opt_uuid(sel.arg());
            if let Some(reason) = reason {
                statement = statement.text(reason);
            }
            let mut tx = self.store.begin_write().await?;
            let rows = statement.fetch_all(tx.conn()).await?;
            let changed: Vec<(CrawlRunId, TenantId)> = rows
                .iter()
                .map(|r| Ok((CrawlRunId(r.uuid("run_id")?), TenantId(r.uuid("tenant_id")?))))
                .collect::<Result<_, StoreError>>()?;
            if settle {
                for (run, _) in &changed {
                    settle_run::<B>(tx.conn(), *run).await?;
                }
            }
            tx.commit().await?;
            changed
        } else {
            // no `UPDATE .. RETURNING`: lock the selected rows, then change them one by one
            let lock = <B::Dialect as Dialect>::row_lock(RowLock::Update);
            let mut tx = self.store.begin_write().await?;
            let rows = Stmt::<B>::dynamic(&format!(
                "SELECT run_id, tenant_id FROM crawl_runs WHERE {condition} AND {predicate}{lock}"
            ))
            .opt_uuid(sel.arg())
            .fetch_all(tx.conn())
            .await?;
            let mut changed = Vec::with_capacity(rows.len());
            for r in &rows {
                let run = r.uuid("run_id")?;
                let mut statement =
                    Stmt::<B>::dynamic(&format!("UPDATE crawl_runs SET {assignments} WHERE run_id = $1"))
                        .uuid(run);
                if let Some(reason) = reason {
                    statement = statement.text(reason);
                }
                statement.execute(tx.conn()).await?;
                if settle {
                    settle_run::<B>(tx.conn(), CrawlRunId(run)).await?;
                }
                changed.push((CrawlRunId(run), TenantId(r.uuid("tenant_id")?)));
            }
            tx.commit().await?;
            changed
        };
        changed.sort_by_key(|(run, _)| run.0);
        Ok(changed)
    }

    /// Mark `worker` draining: it stops taking leases at its next heartbeat and hands its
    /// sessions over at their next action boundary. Returns the number of leases it holds now.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] if the worker never registered, or an error if the
    /// update or the audit append fails.
    pub async fn drain_worker(&self, worker: WorkerId) -> Result<u64, StoreError> {
        let n = stmt!(B, "UPDATE workers SET draining = true WHERE worker_id = $1")
            .uuid(worker.0)
            .execute_write(&self.store.pool)
            .await?;
        if n == 0 {
            return Err(crate::error::not_found("worker", worker));
        }
        let held = stmt!(
            B,
            "SELECT count(*) AS held FROM crawl_sessions WHERE lease_owner = $1 AND status IN ('running','recovering')"
        )
        .uuid(worker.0)
        .fetch_one_pool(&self.store.pool)
        .await?
        .i64("held")?;
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
        let rows = stmt!(
            B,
            "SELECT w.worker_id, w.hostname, w.version, w.capacity, w.draining, w.started_at, w.last_heartbeat_at, \
                    (SELECT count(*) FROM crawl_sessions s WHERE s.lease_owner = w.worker_id AND s.status IN ('running','recovering')) AS held \
             FROM workers w ORDER BY w.started_at, w.worker_id"
        )
        .fetch_all_pool(&self.store.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let held = r.i64("held")?;
                Ok(WorkerRow {
                    id: WorkerId(r.uuid("worker_id")?),
                    hostname: r.text("hostname")?,
                    version: r.text("version")?,
                    draining: r.bool("draining")?,
                    started_at: r.ts("started_at")?,
                    last_heartbeat_at: r.ts("last_heartbeat_at")?,
                    capacity: r.json("capacity")?,
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
        let order = nulls_last::<B>("a.intended_at");
        let rows = Stmt::<B>::dynamic(&format!(
            "SELECT a.action_id, a.run_id, a.session_id, a.status::text AS status, s.status AS session_status, a.intended_at \
             FROM actions a JOIN crawl_sessions s ON s.session_id = a.session_id \
             WHERE a.status::text IN ('intended','unknown') AND ($1::uuid IS NULL OR a.action_id = $1) \
             ORDER BY {order}, a.action_id"
        ))
        .opt_uuid(action.map(|a| a.0))
        .fetch_all_pool(&self.store.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok(OpenAction {
                    id: ActionId(r.uuid("action_id")?),
                    run: CrawlRunId(r.uuid("run_id")?),
                    session: SessionId(r.uuid("session_id")?),
                    status: r.text("status")?,
                    session_status: r.text("session_status")?,
                    intended_at: r.opt_ts("intended_at")?,
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
        let now = <B::Dialect as Dialect>::now();
        let update = format!(
            "UPDATE crawl_sessions SET status = CASE WHEN status = 'running' AND (lease_expires_at IS NULL OR lease_expires_at < {now}) \
                                               THEN 'recovering' ELSE status END \
             WHERE session_id = $1"
        );
        let status = if <B::Dialect as Dialect>::UPDATE_RETURNING {
            Stmt::<B>::dynamic(&format!("{update} RETURNING status"))
                .uuid(open.session.0)
                .fetch_optional_write(&self.store.pool)
                .await?
                .ok_or(StoreError::NotFound {
                    entity: "row",
                    id: String::new(),
                })?
                .text("status")?
        } else {
            let mut tx = self.store.begin_write().await?;
            Stmt::<B>::dynamic(&update)
                .uuid(open.session.0)
                .execute(tx.conn())
                .await?;
            let status = stmt!(B, "SELECT status FROM crawl_sessions WHERE session_id = $1")
                .uuid(open.session.0)
                .fetch_one(tx.conn())
                .await?
                .text("status")?;
            tx.commit().await?;
            status
        };
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
        let before = stmt!(B, "SELECT engine FROM tenants WHERE tenant_id = $1")
            .uuid(tenant.0)
            .fetch_optional_pool(&self.store.pool)
            .await?
            .map(|r| r.text("engine"))
            .transpose()?;
        let before = TenantEngine::parse(&before.ok_or_else(|| crate::error::not_found("tenant", tenant))?)?;
        stmt!(B, "UPDATE tenants SET engine = $2 WHERE tenant_id = $1")
            .uuid(tenant.0)
            .text(engine.as_str())
            .execute_write(&self.store.pool)
            .await?;
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
        let rows = stmt!(
            B,
            "SELECT a.artifact_id, a.run_id, a.object_key, a.content_digest, \
                    c.envelope, c.artifact_payload, c.ciphertext_digest, c.ciphertext_size \
             FROM artifacts a LEFT JOIN artifact_key_custody c ON c.artifact_id = a.artifact_id \
             WHERE a.deleted_at IS NULL AND ($1::timestamptz IS NULL OR a.created_at >= $1) \
             ORDER BY a.artifact_id"
        )
        .opt_ts(since)
        .fetch_all_pool(&self.store.pool)
        .await?;
        let mut out = ArtifactVerification::default();
        let mut live_keys = std::collections::BTreeSet::new();
        for r in &rows {
            let artifact_id = r.uuid("artifact_id")?;
            let run = CrawlRunId(r.uuid("run_id")?);
            let object_key = r.text("object_key")?;
            let digest = r.bytes("content_digest")?;
            let sealed = r.opt_json("envelope")?;
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
        r: &B::Row,
        envelope: serde_json::Value,
        bytes: Vec<u8>,
    ) -> Result<Option<&'static str>, StoreError> {
        let ciphertext_digest = r.bytes("ciphertext_digest")?;
        let ciphertext_size = r.i64("ciphertext_size")?;
        let actual = Digest::of(crate::custody::CIPHERTEXT_DIGEST_DOMAIN, &bytes);
        if actual.0.as_slice() != ciphertext_digest.as_slice()
            || i64::try_from(bytes.len()).ok() != Some(ciphertext_size)
        {
            return Ok(Some("digest_mismatch"));
        }
        let Some(keys) = keys else {
            return Ok(None);
        };
        let payload = r.json("artifact_payload")?;
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
        let checked = stmt!(
            B,
            "SELECT count(*) AS checked FROM audit_events e \
             WHERE e.event = 'crawl.accepted' AND e.run_id IS NOT NULL \
               AND ($1::timestamptz IS NULL OR e.occurred_at >= $1)"
        )
        .opt_ts(since)
        .fetch_one_pool(&self.store.pool)
        .await?
        .i64("checked")?;
        let rows = stmt!(
            B,
            "SELECT DISTINCT e.run_id FROM audit_events e \
             LEFT JOIN crawl_runs r ON r.run_id = e.run_id \
             WHERE e.event = 'crawl.accepted' AND e.run_id IS NOT NULL \
               AND ($1::timestamptz IS NULL OR e.occurred_at >= $1) \
               AND r.run_id IS NULL \
             ORDER BY e.run_id"
        )
        .opt_ts(since)
        .fetch_all_pool(&self.store.pool)
        .await?;
        let missing = rows
            .iter()
            .map(|r| r.uuid("run_id").map(CrawlRunId))
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
}

impl<B: Sql> AdminOps<'_, B>
where
    Store<B>: crawlx_core::repo::EventRepo,
{
    async fn append_event(
        &self,
        run: CrawlRunId,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<(), StoreError> {
        crawlx_core::repo::EventRepo::append(self.store, run, kind, payload)
            .await
            .map(|_| ())
    }

    /// Pause every `running` run selected (`pause_requested_at = now()`, `status = paused`); the
    /// Session Actors stop at their next action boundary. Returns the runs paused.
    ///
    /// # Errors
    /// Returns an error if the update, the event append or the audit append fails.
    pub async fn pause(&self, sel: RunSelector) -> Result<Vec<CrawlRunId>, StoreError> {
        let now = <B::Dialect as Dialect>::now();
        let runs = self
            .update_runs(
                sel,
                &format!("status = 'paused', pause_requested_at = {now}"),
                "status = 'running'",
                None,
                false,
            )
            .await?;
        let mut out = Vec::with_capacity(runs.len());
        for (run, tenant) in runs {
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
        let runs = self
            .update_runs(
                sel,
                "status = 'running', pause_requested_at = NULL",
                "status = 'paused'",
                None,
                false,
            )
            .await?;
        let mut out = Vec::with_capacity(runs.len());
        for (run, tenant) in runs {
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
        let now = <B::Dialect as Dialect>::now();
        let runs = self
            .update_runs(
                sel,
                &format!(
                    "status = 'cancelled', terminal_reason = $2::text::terminal_reason, cancel_requested_at = {now}, finished_at = {now}"
                ),
                "status::text IN ('queued','running','pausing','paused','cancelling')",
                Some(reason),
                true,
            )
            .await?;
        let mut out = Vec::with_capacity(runs.len());
        for (run, tenant) in runs {
            Stmt::<B>::dynamic(&format!(
                "UPDATE crawl_sessions SET status = 'cancelled', finished_at = {now} WHERE run_id = $1 AND status = 'pending'"
            ))
            .uuid(run.0)
            .execute_write(&self.store.pool)
            .await?;
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
}

/// Runs in `queued|running|pausing|paused` (the `crawlx admin status` headline).
///
/// # Errors
/// Returns an error if the query fails.
pub async fn active_run_count<B: Sql>(store: &Store<B>) -> Result<i64, StoreError> {
    stmt!(
        B,
        "SELECT count(*) AS active FROM crawl_runs WHERE status::text IN ('queued','running','pausing','paused')"
    )
    .fetch_one_pool(&store.pool)
    .await?
    .i64("active")
}

/// RB-08 step 3 (`crawlx admin sweep-retention --mode zdr --force`): for every run with
/// `retention_mode = zdr`, delete its artifact objects **first**, mark the `artifacts` rows
/// deleted, delete its `pages` rows, and keep the structural trail (`actions`, `transitions`,
/// `network_epochs`, `states`). Deleted keys (never contents) are written to the audit log.
/// Returns the runs touched.
///
/// # Errors
/// Returns an error if a query, the object deletion or the audit append fails.
pub async fn force_zdr_sweep<B: Sql>(
    store: &Store<B>,
    sweeper: &crate::retention::RetentionSweeper<B>,
    actor: &str,
) -> Result<Vec<CrawlRunId>, StoreError> {
    let rows = stmt!(
        B,
        "SELECT run_id, tenant_id FROM crawl_runs WHERE retention_mode = 'zdr' ORDER BY run_id"
    )
    .fetch_all_pool(&store.pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let run = CrawlRunId(r.uuid("run_id")?);
        let tenant = r.uuid("tenant_id")?;
        let keys = stmt!(
            B,
            "SELECT object_key FROM artifacts WHERE run_id = $1 AND deleted_at IS NULL ORDER BY object_key"
        )
        .uuid(run.0)
        .fetch_all_pool(&store.pool)
        .await?
        .iter()
        .map(|row| row.text("object_key"))
        .collect::<Result<Vec<String>, _>>()?;
        let objects = sweeper.purge_run_objects(run).await?;
        let now = <B::Dialect as Dialect>::now();
        Stmt::<B>::dynamic(&format!(
            "UPDATE artifacts SET deleted_at = {now} WHERE run_id = $1 AND deleted_at IS NULL"
        ))
        .uuid(run.0)
        .execute_write(&store.pool)
        .await?;
        let pages = stmt!(B, "DELETE FROM pages WHERE run_id = $1")
            .uuid(run.0)
            .execute_write(&store.pool)
            .await?;
        append_audit(
            store,
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
pub async fn admission_of<B: Sql>(store: &Store<B>) -> Result<AdmissionMode, StoreError> {
    let key = <B::Dialect as Dialect>::reserved_ident("key");
    let value = Stmt::<B>::dynamic(&format!(
        "SELECT value FROM cluster_settings WHERE {key} = 'scheduler.admission'"
    ))
    .fetch_optional_pool(&store.pool)
    .await?
    .map(|row| row.text("value"))
    .transpose()?;
    value
        .as_deref()
        .map_or(Ok(AdmissionMode::Open), AdmissionMode::parse)
}

/// `tenants.engine` of `tenant`; `None` when the tenant row does not exist.
///
/// # Errors
/// Returns an error if the query fails or the stored value is unknown.
pub async fn tenant_engine_of<B: Sql>(
    store: &Store<B>,
    tenant: TenantId,
) -> Result<Option<TenantEngine>, StoreError> {
    let value = stmt!(B, "SELECT engine FROM tenants WHERE tenant_id = $1")
        .uuid(tenant.0)
        .fetch_optional_pool(&store.pool)
        .await?
        .map(|row| row.text("engine"))
        .transpose()?;
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
        assert_eq!(RunSelector::All.predicate(), "$1::uuid IS NULL");
        assert_eq!(RunSelector::All.arg(), None);
        let id = CrawlRunId::new();
        assert_eq!(RunSelector::Crawl(id).predicate(), "run_id = $1");
        assert_eq!(RunSelector::Crawl(id).arg(), Some(id.0));
        let tenant = TenantId::new();
        assert_eq!(RunSelector::Tenant(tenant).predicate(), "tenant_id = $1");
    }
}
