//! Row leases with fencing tokens, the round-robin turn barrier and the
//! stale-lease reaper primitives.
//!
//! Every lease carries a token from `lease_fence_seq`; writes by the holder
//! (`heartbeat`, `release`) include `fencing_token = $token`, so a worker that was
//! paused past expiry cannot touch a session that was reassigned. All lease
//! arithmetic uses the database clock (`now()`), never the caller's.

use crate::admin::AdmissionMode;
use crate::backend::strategy::{FenceSeq, SessionClaim};
use crate::backend::{Dialect, RowLock};
use crate::codec::{conv, from_json};
use crate::repos::{flip_intended_to_unknown, session_from_row, SESSION_COLS};
use crate::sql::{in_ids, returning, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use crate::worker_eligibility::{claim_eligible, WorkerFacts};
use async_trait::async_trait;
use crawlx_core::repo::{CrawlSession, RunRepo, SessionStatus};
use crawlx_core::{ActionId, CrawlRunId, CreateCrawl, SessionId, StoreError, Timestamp, WorkerId};
use std::sync::LazyLock;
use std::time::Duration;
use uuid::Uuid;

/// Session lease TTL.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(30);
/// URL batch lease TTL.
pub const DEFAULT_URL_BATCH_TTL: Duration = Duration::from_secs(60);
/// Reserved namespace of diagnostic render children; ordinary role slots remain below it.
pub const RENDER_SESSION_SLOT_BASE: u32 = 1_000_000;

pub(crate) fn validate_render_session(session: &CrawlSession) -> Result<(), StoreError> {
    if session.role.0 != "scrape"
        || session.kind != crawlx_core::repo::SessionKind::Browser
        || session.schedule_slot < RENDER_SESSION_SLOT_BASE
        || session.run_index == 0
        || session.status != SessionStatus::Pending
        || session.browser.is_some()
        || session.action_seq != 0
    {
        return Err(StoreError::Conflict(
            "invalid fresh internal render session".into(),
        ));
    }
    Ok(())
}

/// A granted session lease. `fencing_token` must accompany every holder write.
#[derive(Clone, PartialEq, Debug)]
pub struct SessionLease {
    /// Persisted session state at the time the lease was granted.
    pub session: CrawlSession,
    /// Worker that owns this lease and must identify itself on holder writes.
    pub worker: WorkerId,
    /// Monotonically increasing database token that fences out previous holders.
    pub fencing_token: i64,
    /// Lease deadline according to the repository clock.
    pub expires_at: Timestamp,
}

/// A run that may have claimable sessions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ActiveRun {
    /// Identifier of the run with potentially eligible sessions.
    pub run: CrawlRunId,
    /// `CreateCrawl::parallel_roles_allowed()` for this run (barrier lifted).
    pub parallel_roles_allowed: bool,
}

/// What one reaper pass changed.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct ReapReport {
    /// Sessions moved `running → recovering`.
    pub sessions_recovering: Vec<SessionId>,
    /// `intended` actions of those sessions flipped to `unknown`.
    pub actions_unknown: Vec<ActionId>,
}

/// Outcome of re-queueing expired URL leases.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FrontierReap {
    /// Number of expired URL rows returned to the pending queue.
    pub requeued: u64,
    /// Number of expired URL rows failed after exhausting their attempt budget.
    pub failed: u64,
}

/// Generic lease operations used by `crawlx-scheduler`.
#[async_trait]
pub trait LeaseRepo: Send + Sync {
    /// Lease clock (database `now()` for PostgreSQL).
    ///
    /// # Errors
    /// Returns an error if the repository clock cannot be read.
    async fn now(&self) -> Result<Timestamp, StoreError>;

    /// Runs with `pending`/`recovering` sessions, oldest first.
    ///
    /// # Errors
    /// Returns an error if the run query fails or stored configuration is invalid.
    async fn active_runs(&self) -> Result<Vec<ActiveRun>, StoreError>;

    /// Claim the lowest eligible session slot of `run`. Round-robin barrier:
    /// unless `parallel_roles_allowed`, a session is granted only when
    /// every lower `schedule_slot` of the run is `completed | failed | cancelled`.
    /// A `recovering` session whose previous lease expired is re-claimed and stays
    /// `recovering` until the worker finishes reconciliation.
    ///
    /// # Errors
    /// Returns an error if the claim transaction fails or the session cannot be decoded.
    async fn claim_session(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError>;

    /// Claim only the requested eligible slot, preserving the normal role barrier and fence.
    ///
    /// # Errors
    /// Returns a backend error or explicit unavailable when a custom repository lacks exact claims.
    async fn claim_session_exact(
        &self,
        _run: CrawlRunId,
        _session: SessionId,
        _worker: WorkerId,
        _parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError> {
        Err(StoreError::Unavailable(
            "exact session claims are unsupported by this repository".into(),
        ))
    }

    /// Atomically create and lease a fresh internal render child, never publishing a Pending row.
    /// This does not grant an exploration role turn or weaken the parent's safety/pacing bounds.
    ///
    /// # Errors
    /// Returns conflict, closed admission, missing live run or unsupported repository.
    async fn create_render_session(
        &self,
        _session: &CrawlSession,
        _worker: WorkerId,
    ) -> Result<SessionLease, StoreError> {
        Err(StoreError::Unavailable(
            "atomic render session leases are unsupported by this repository".into(),
        ))
    }

    /// Extend the lease; `LeaseLost` if the token or owner no longer matches.
    ///
    /// # Errors
    /// Returns [`StoreError::LeaseLost`] on owner or token mismatch, or a backend error.
    async fn heartbeat(&self, lease: &SessionLease) -> Result<Timestamp, StoreError>;

    /// End the lease. `to` must be terminal (`Completed | Failed | Cancelled`) or
    /// `Recovering` (graceful hand-over; the session's `intended` actions become
    /// `unknown`). `LeaseLost` on token mismatch.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] for an invalid target status,
    /// [`StoreError::LeaseLost`] on token mismatch, or a backend error.
    async fn release(&self, lease: &SessionLease, to: SessionStatus) -> Result<(), StoreError>;

    /// Reaper pass over sessions: expired `running` leases (`lease_expires_at < now`)
    /// become `recovering` (never `pending`) and their `intended` actions `unknown`.
    ///
    /// # Errors
    /// Returns an error if the session sweep or action status updates fail.
    async fn reap(&self, now: Timestamp) -> Result<ReapReport, StoreError>;

    /// Return expired URL leases to `pending`; rows with `attempts >= max_attempts`
    /// become `failed`.
    ///
    /// # Errors
    /// Returns an error if the sweep fails or `max_attempts` exceeds the SQL column range.
    async fn reap_frontier(&self, now: Timestamp, max_attempts: u16) -> Result<FrontierReap, StoreError>;

    /// Extend the leases of URL rows held by `worker`. `leases` pairs each row id with the
    /// fencing token of the holder's lease ([`FrontierRepo::lease_batch_fenced`]); returns the
    /// ids of the rows extended. A row missing from the result is no longer the holder's: its
    /// lease expired and the reaper returned it, it was finished, or another worker leased it
    /// since.
    ///
    /// [`FrontierRepo::lease_batch_fenced`]: crawlx_core::repo::FrontierRepo::lease_batch_fenced
    ///
    /// # Errors
    /// Returns an error if the URL lease update fails.
    async fn heartbeat_frontier(
        &self,
        worker: WorkerId,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError>;

    /// Time a URL row stays leased without a heartbeat (60 s). A holder renews
    /// more often than this.
    fn url_batch_ttl(&self) -> Duration;

    /// `scheduler.admission`: `Open` grants leases; `Drain` and `Frozen` do not.
    /// Stores without the setting report `Open`.
    ///
    /// # Errors
    /// Returns an error if the setting cannot be read.
    async fn admission(&self) -> Result<AdmissionMode, StoreError> {
        Ok(AdmissionMode::Open)
    }
}

pub(crate) fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

/// The columns a claimed session row carries: the session plus its fence and expiry.
static CLAIM_COLUMNS: LazyLock<String> =
    LazyLock::new(|| format!("{SESSION_COLS},s.fencing_token,s.lease_expires_at"));

/// `scheduler.admission` of the cluster; `Open` when the setting is absent.
pub(crate) async fn admission<B: Sql>(store: &Store<B>) -> Result<AdmissionMode, StoreError> {
    let key = B::Dialect::reserved_ident("key");
    let row = Stmt::<B>::dynamic(&format!(
        "SELECT value FROM cluster_settings WHERE {key} = 'scheduler.admission'"
    ))
    .fetch_optional_pool(&store.pool)
    .await?;
    row.map(|row| row.text("value"))
        .transpose()?
        .as_deref()
        .map_or(Ok(AdmissionMode::Open), AdmissionMode::parse)
}

/// What a claim needs from the worker: the acquisition backends and data capabilities the
/// run's admitted configuration asks for.
struct ClaimNeeds {
    required: Vec<String>,
    data_required: bool,
}

fn claim_needs(config: &CreateCrawl) -> Result<ClaimNeeds, StoreError> {
    let data = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(config)?;
    let data_required = !data.destinations.is_empty() || data.language_bundle.is_some();
    let required = if let Some(policy) = &config.acquisition {
        policy
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        policy.backend_ids.clone()
    } else {
        Vec::new()
    };
    Ok(ClaimNeeds {
        required,
        data_required,
    })
}

fn lease_from_row<R: SqlRow>(row: &R, worker: WorkerId) -> Result<SessionLease, StoreError> {
    Ok(SessionLease {
        session: session_from_row(row)?,
        worker,
        fencing_token: row.i64("fencing_token")?,
        expires_at: row.ts("lease_expires_at")?,
    })
}

async fn claim_inner<B: Sql>(
    store: &Store<B>,
    run: CrawlRunId,
    worker: WorkerId,
    parallel_roles_allowed: bool,
    requested: Option<SessionId>,
) -> Result<Option<SessionLease>, StoreError>
where
    Store<B>: RunRepo,
{
    if !admission(store).await?.grants_leases() {
        return Ok(None);
    }
    let admitted = RunRepo::get(store, run).await?;
    let needs = claim_needs(&admitted.config)?;
    let _timer = store.query_timer("leases.claim_session");
    let row = B::claim_sessions(
        &store.pool,
        SessionClaim {
            run: run.0,
            worker: worker.0,
            ttl_secs: secs(store.cfg.session_ttl),
            parallel_roles: parallel_roles_allowed,
            requested: requested.map(|session| session.0),
            required_backends: &needs.required,
            data_required: needs.data_required,
            columns: CLAIM_COLUMNS.as_str(),
        },
    )
    .await?;
    row.map(|row| lease_from_row(&row, worker)).transpose()
}

/// The `workers` row a claim judges eligibility on.
async fn worker_facts<B: Sql>(
    conn: &mut crate::backend::strategy::Conn<B>,
    worker: Uuid,
) -> Result<Option<WorkerFacts>, StoreError> {
    let row = stmt!(
        B,
        "SELECT capacity, draining, last_heartbeat_at FROM workers WHERE worker_id = $1"
    )
    .uuid(worker)
    .fetch_optional(conn)
    .await?;
    row.map(|row| {
        Ok(WorkerFacts {
            capacity: row.json("capacity")?,
            draining: row.bool("draining")?,
            last_heartbeat_at: row.ts("last_heartbeat_at")?,
        })
    })
    .transpose()
}

/// Atomically create and lease a render child where the engine cannot do it in one
/// statement: eligibility is evaluated in Rust inside one write transaction.
async fn create_render_portable<B: Sql>(
    store: &Store<B>,
    session: &CrawlSession,
    worker: WorkerId,
    needs: &ClaimNeeds,
) -> Result<SessionLease, StoreError> {
    let unavailable =
        || StoreError::Unavailable("render parent run or assigned worker is unavailable".into());
    let slot = i32::try_from(session.schedule_slot)
        .map_err(|_| StoreError::Conflict("render slot overflow".into()))?;
    let mut tx = store.begin_write().await?;
    let now = B::db_now(&store.pool).await?;
    let run = stmt!(
        B,
        "SELECT config, data_requirements FROM crawl_runs r WHERE r.run_id = $1 AND r.status IN ('queued','running') \
         AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL"
    )
    .uuid(session.run.0)
    .fetch_optional(tx.conn())
    .await?
    .ok_or_else(unavailable)?;
    let config = run.json("config")?;
    let facts = worker_facts::<B>(tx.conn(), worker.0).await?;
    if !claim_eligible(
        facts.as_ref(),
        session.run.0,
        now,
        &needs.required,
        needs.data_required,
        &run.json("data_requirements")?,
    ) {
        return Err(unavailable());
    }
    let profile = config
        .get("dynamic")
        .and_then(|dynamic| dynamic.get("launchProfile"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("standard");
    let fence = B::next_fence(tx.conn(), FenceSeq::Lease).await?;
    let clock = <B::Dialect as Dialect>::clock_timestamp();
    let expires = <B::Dialect as Dialect>::add_seconds(clock, "$9");
    Stmt::<B>::dynamic(&format!(
        "INSERT INTO crawl_sessions (session_id,run_id,role,run_index,schedule_slot,status,action_seq,launch_profile, \
           console_capture,lease_kind,lease_owner,lease_expires_at,fencing_token,last_heartbeat_at,started_at) \
         VALUES ($1,$2,$3,$4,$5,'running',0,$6,$7,'render',$8,{expires},$10,{clock},{clock})"
    ))
    .uuid(session.id.0)
    .uuid(session.run.0)
    .text(&session.role.0)
    .i32(i32::from(session.run_index))
    .i32(slot)
    .text(profile)
    .bool(profile != "stealth")
    .uuid(worker.0)
    .f64(secs(store.cfg.session_ttl))
    .i64(fence)
    .execute(tx.conn())
    .await?;
    let row = Stmt::<B>::dynamic(&format!(
        "SELECT {} FROM crawl_sessions s WHERE s.session_id = $1",
        CLAIM_COLUMNS.as_str()
    ))
    .uuid(session.id.0)
    .fetch_one(tx.conn())
    .await?;
    tx.commit().await?;
    lease_from_row(&row, worker)
}

/// The PostgreSQL render-session statement: insert, eligibility and the lease in one.
fn render_statement() -> String {
    format!("INSERT INTO crawl_sessions AS s \
        (session_id,run_id,role,run_index,schedule_slot,status,action_seq,launch_profile,console_capture,lease_kind, \
         lease_owner,lease_expires_at,fencing_token,last_heartbeat_at,started_at) \
        SELECT $1,r.run_id,$3,$4,$5,'running',0,COALESCE(r.config->'dynamic'->>'launchProfile','standard'), \
         COALESCE(r.config->'dynamic'->>'launchProfile','standard')<>'stealth','render', \
         $6,clock_timestamp()+make_interval(secs=>$7),nextval('lease_fence_seq'),clock_timestamp(),clock_timestamp() \
        FROM crawl_runs r WHERE r.run_id=$2 AND r.status IN ('queued','running') \
          AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
          AND ((cardinality($8::text[])=0 AND NOT $9::boolean) OR EXISTS(SELECT 1 FROM workers w \
            WHERE w.worker_id=$6 AND NOT w.draining AND w.last_heartbeat_at<=clock_timestamp() \
              AND w.last_heartbeat_at>=clock_timestamp()-interval '90 seconds' \
              AND (w.capacity->'acceptsQueued'='true'::jsonb OR w.capacity->>'localRun'=$2::text) \
              AND NOT EXISTS(SELECT 1 FROM unnest($8::text[]) required(backend_id) \
                WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(w.capacity->'acquisition','[]'::jsonb)) fact \
                  WHERE fact->>'backendId'=required.backend_id AND fact->'available'='true'::jsonb)))) \
          AND crawlx_worker_data_eligible($6,r.data_requirements) \
        RETURNING {SESSION_COLS},s.fencing_token,s.lease_expires_at")
}

#[async_trait]
impl<B: Sql> LeaseRepo for Store<B>
where
    Store<B>: RunRepo,
{
    async fn now(&self) -> Result<Timestamp, StoreError> {
        B::db_now(&self.pool).await
    }

    async fn admission(&self) -> Result<AdmissionMode, StoreError> {
        admission(self).await
    }

    async fn active_runs(&self) -> Result<Vec<ActiveRun>, StoreError> {
        let _timer = self.query_timer("leases.active_runs");
        let rows = stmt!(
            B,
            "SELECT run_id, config FROM crawl_runs r WHERE r.status IN ('queued','running') \
             AND EXISTS (SELECT 1 FROM crawl_sessions s WHERE s.run_id = r.run_id AND s.lease_kind='role' AND s.status IN ('pending','recovering')) \
             ORDER BY r.run_id"
        )
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                let value = r.json("config")?;
                let parallel_roles_allowed =
                    if value.get("privacy").and_then(serde_json::Value::as_str) == Some("zdr") {
                        value
                            .get("parallelRolesAllowed")
                            .and_then(serde_json::Value::as_bool)
                            .ok_or_else(|| {
                                StoreError::Serialization("missing zdr scheduling metadata".to_owned())
                            })?
                    } else {
                        let cfg: CreateCrawl = from_json(value)?;
                        cfg.parallel_roles_allowed()
                    };
                Ok(ActiveRun {
                    run: CrawlRunId(r.uuid("run_id")?),
                    parallel_roles_allowed,
                })
            })
            .collect()
    }

    async fn claim_session(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError> {
        claim_inner(self, run, worker, parallel_roles_allowed, None).await
    }

    async fn claim_session_exact(
        &self,
        run: CrawlRunId,
        session: SessionId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError> {
        claim_inner(self, run, worker, parallel_roles_allowed, Some(session)).await
    }

    async fn create_render_session(
        &self,
        session: &CrawlSession,
        worker: WorkerId,
    ) -> Result<SessionLease, StoreError> {
        validate_render_session(session)?;
        if !LeaseRepo::admission(self).await?.grants_leases() {
            return Err(StoreError::Unavailable("session admission is closed".into()));
        }
        let admitted = RunRepo::get(self, session.run).await?;
        let needs = claim_needs(&admitted.config)?;
        if B::KIND != crate::backend::BackendKind::Postgres {
            return create_render_portable(self, session, worker, &needs).await;
        }
        let slot = i32::try_from(session.schedule_slot)
            .map_err(|_| StoreError::Conflict("render slot overflow".into()))?;
        let row = stmt!(B, render_statement())
            .uuid(session.id.0)
            .uuid(session.run.0)
            .text(&session.role.0)
            .i32(i32::from(session.run_index))
            .i32(slot)
            .uuid(worker.0)
            .f64(secs(self.cfg.session_ttl))
            .text_list(&needs.required)
            .bool(needs.data_required)
            .fetch_optional_write(&self.pool)
            .await?
            .ok_or_else(|| {
                StoreError::Unavailable("render parent run or assigned worker is unavailable".into())
            })?;
        lease_from_row(&row, worker)
    }

    async fn heartbeat(&self, lease: &SessionLease) -> Result<Timestamp, StoreError> {
        let _timer = self.query_timer("leases.heartbeat");
        let ttl = secs(self.cfg.session_ttl);
        if B::KIND == crate::backend::BackendKind::Postgres {
            let row = stmt!(B, heartbeat_sql::<B>(" RETURNING lease_expires_at"))
                .uuid(lease.session.id.0)
                .uuid(lease.worker.0)
                .i64(lease.fencing_token)
                .f64(ttl)
                .fetch_optional_write(&self.pool)
                .await?;
            return row.ok_or(StoreError::LeaseLost)?.ts("lease_expires_at");
        }
        // no `UPDATE .. RETURNING` shared by every other engine: update and read the row
        // back in one transaction
        let mut tx = self.begin_write().await?;
        let matched = stmt!(B, heartbeat_sql::<B>(""))
            .uuid(lease.session.id.0)
            .uuid(lease.worker.0)
            .i64(lease.fencing_token)
            .f64(ttl)
            .execute(tx.conn())
            .await?;
        if matched == 0 {
            return Err(StoreError::LeaseLost);
        }
        let row = stmt!(
            B,
            "SELECT lease_expires_at FROM crawl_sessions WHERE session_id = $1"
        )
        .uuid(lease.session.id.0)
        .fetch_one(tx.conn())
        .await?;
        tx.commit().await?;
        row.ts("lease_expires_at")
    }

    async fn release(&self, lease: &SessionLease, to: SessionStatus) -> Result<(), StoreError> {
        let _timer = self.query_timer("leases.release");
        if !(to.is_terminal() || to == SessionStatus::Recovering) {
            return Err(StoreError::Conflict(format!(
                "cannot release a session into {}",
                to.as_str()
            )));
        }
        let mut tx = self.begin_write().await?;
        let released = stmt!(
            B,
            format!(
                "UPDATE crawl_sessions SET status = $4, lease_owner = NULL, lease_expires_at = NULL, \
                   finished_at = CASE WHEN $5 THEN {now} ELSE finished_at END \
                 WHERE session_id = $1 AND lease_owner = $2 AND fencing_token = $3 AND status IN ('running','recovering') AND lease_expires_at > {clock}{ret}",
                now = <B::Dialect as Dialect>::now(),
                clock = <B::Dialect as Dialect>::clock_timestamp(),
                ret = returning::<B>("session_id"),
            )
        )
        .uuid(lease.session.id.0)
        .uuid(lease.worker.0)
        .i64(lease.fencing_token)
        .text(to.as_str())
        .bool(to.is_terminal())
        .matched(tx.conn())
        .await?;
        if !released {
            return Err(StoreError::LeaseLost);
        }
        if to == SessionStatus::Recovering {
            flip_intended_to_unknown::<B>(tx.conn(), &[lease.session.id.0]).await?;
        }
        tx.commit().await
    }

    async fn reap(&self, now: Timestamp) -> Result<ReapReport, StoreError> {
        let _timer = self.query_timer("leases.reap");
        let mut tx = self.begin_write().await?;
        let ids: Vec<Uuid> = if B::KIND == crate::backend::BackendKind::Postgres {
            stmt!(
                B,
                "UPDATE crawl_sessions SET status = 'recovering', lease_owner = NULL, lease_expires_at = NULL \
                 WHERE status = 'running' AND lease_expires_at < $1 RETURNING session_id"
            )
            .ts(now)
            .fetch_all(tx.conn())
            .await?
            .iter()
            .map(|r| r.uuid("session_id"))
            .collect::<Result<_, _>>()?
        } else {
            // lock the expired holders, then move exactly those rows
            let lock = <B::Dialect as Dialect>::row_lock(RowLock::Update);
            let ids: Vec<Uuid> = Stmt::<B>::dynamic(&format!(
                "SELECT session_id FROM crawl_sessions WHERE status = 'running' AND lease_expires_at < $1{lock}"
            ))
            .ts(now)
            .fetch_all(tx.conn())
            .await?
            .iter()
            .map(|r| r.uuid("session_id"))
            .collect::<Result<_, _>>()?;
            for chunk in ids.chunks(chunk_size::<B>()) {
                Stmt::<B>::dynamic(&format!(
                    "UPDATE crawl_sessions SET status = 'recovering', lease_owner = NULL, lease_expires_at = NULL \
                     WHERE session_id {}",
                    in_ids::<B>(1, chunk.len())
                ))
                .uuid_list(chunk)
                .execute(tx.conn())
                .await?;
            }
            ids
        };
        let actions = flip_intended_to_unknown::<B>(tx.conn(), &ids).await?;
        tx.commit().await?;
        Ok(ReapReport {
            sessions_recovering: ids.into_iter().map(SessionId).collect(),
            actions_unknown: actions,
        })
    }

    async fn reap_frontier(&self, now: Timestamp, max_attempts: u16) -> Result<FrontierReap, StoreError> {
        let _timer = self.query_timer("leases.reap_frontier");
        let max = conv::<u16, i16>(max_attempts, "max_attempts")?;
        if B::KIND == crate::backend::BackendKind::Postgres {
            let rows = stmt!(
                B,
                "UPDATE url_frontier SET \
                   status = CASE WHEN attempts >= $2 THEN 'failed' ELSE 'pending' END, \
                   error_code = CASE WHEN attempts >= $2 THEN 'lease_expired' ELSE error_code END, \
                   finished_at = CASE WHEN attempts >= $2 THEN now() ELSE NULL END, \
                   lease_owner = NULL, lease_expires_at = NULL \
                 WHERE status = 'leased' AND lease_expires_at < $1 RETURNING status,via"
            )
            .ts(now)
            .i16(max)
            .fetch_all_pool(&self.pool)
            .await?;
            let mut out = FrontierReap::default();
            for r in &rows {
                if r.text("via")? == "interaction" {
                    continue;
                }
                if r.text("status")? == "failed" {
                    out.failed += 1;
                } else {
                    out.requeued += 1;
                }
            }
            return Ok(out);
        }
        let mut tx = self.begin_write().await?;
        let lock = <B::Dialect as Dialect>::row_lock(RowLock::Update);
        let rows = Stmt::<B>::dynamic(&format!(
            "SELECT frontier_id, attempts, via FROM url_frontier WHERE status = 'leased' AND lease_expires_at < $1{lock}"
        ))
        .ts(now)
        .fetch_all(tx.conn())
        .await?;
        let mut out = FrontierReap::default();
        let mut failed = Vec::new();
        let mut requeued = Vec::new();
        for r in &rows {
            let id = r.i64("frontier_id")?;
            let exhausted = r.i32("attempts")? >= i32::from(max);
            if exhausted {
                failed.push(id);
            } else {
                requeued.push(id);
            }
            if r.text("via")? != "interaction" {
                if exhausted {
                    out.failed += 1;
                } else {
                    out.requeued += 1;
                }
            }
        }
        let clock = <B::Dialect as Dialect>::now();
        for chunk in failed.chunks(chunk_size::<B>()) {
            let mut statement = Stmt::<B>::dynamic(&format!(
                "UPDATE url_frontier SET status = 'failed', error_code = 'lease_expired', finished_at = {clock}, \
                   lease_owner = NULL, lease_expires_at = NULL WHERE frontier_id {}",
                in_ids::<B>(1, chunk.len())
            ));
            for id in chunk {
                statement = statement.i64(*id);
            }
            statement.execute(tx.conn()).await?;
        }
        for chunk in requeued.chunks(chunk_size::<B>()) {
            let mut statement = Stmt::<B>::dynamic(&format!(
                "UPDATE url_frontier SET status = 'pending', finished_at = NULL, lease_owner = NULL, lease_expires_at = NULL \
                 WHERE frontier_id {}",
                in_ids::<B>(1, chunk.len())
            ));
            for id in chunk {
                statement = statement.i64(*id);
            }
            statement.execute(tx.conn()).await?;
        }
        tx.commit().await?;
        Ok(out)
    }

    async fn heartbeat_frontier(
        &self,
        worker: WorkerId,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError> {
        let _timer = self.query_timer("leases.heartbeat_frontier");
        B::heartbeat_frontier(&self.pool, worker.0, secs(self.cfg.url_batch_ttl), leases).await
    }

    fn url_batch_ttl(&self) -> Duration {
        self.cfg.url_batch_ttl
    }
}

/// The fenced heartbeat update; `suffix` is ` RETURNING ..` where the engine has it.
fn heartbeat_sql<B: Sql>(suffix: &str) -> String {
    let clock = <B::Dialect as Dialect>::clock_timestamp();
    let expires = <B::Dialect as Dialect>::add_seconds(clock, "$4");
    format!(
        "UPDATE crawl_sessions SET lease_expires_at = {expires}, last_heartbeat_at = {clock} \
         WHERE session_id = $1 AND lease_owner = $2 AND fencing_token = $3 AND status IN ('running','recovering') AND lease_expires_at > {clock}{suffix}"
    )
}

/// Most ids one `IN` list carries: the engine's placeholder cap minus the fixed parameters.
fn chunk_size<B: Sql>() -> usize {
    <B::Dialect as Dialect>::MAX_BIND_PARAMS.saturating_sub(8).max(1)
}
