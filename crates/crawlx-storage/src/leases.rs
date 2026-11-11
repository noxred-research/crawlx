//! Row leases with fencing tokens, the round-robin turn barrier and the
//! stale-lease reaper primitives.
//!
//! Every lease carries a token from `lease_fence_seq`; writes by the holder
//! (`heartbeat`, `release`) include `fencing_token = $token`, so a worker that was
//! paused past expiry cannot touch a session that was reassigned. All lease
//! arithmetic uses the database clock (`now()`), never the caller's.

use crate::admin::AdmissionMode;
use crate::codec::{from_json, get};
use crate::error::db;
use crate::pg::Pg;
use crate::repos::{flip_intended_to_unknown, SESSION_COLS};
use async_trait::async_trait;
use crawlx_core::repo::{CrawlSession, SessionStatus};
use crawlx_core::{ActionId, CrawlRunId, CreateCrawl, SessionId, StoreError, Timestamp, WorkerId};
use std::time::Duration;

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

async fn claim_pg(
    pg: &Pg,
    run: CrawlRunId,
    worker: WorkerId,
    parallel_roles_allowed: bool,
    requested: Option<SessionId>,
) -> Result<Option<SessionLease>, StoreError> {
    if !crate::admin::admission_of(pg).await?.grants_leases() {
        return Ok(None);
    }
    let admitted = <Pg as crawlx_core::repo::RunRepo>::get(pg, run).await?;
    let data = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(&admitted.config)?;
    let data_required = !data.destinations.is_empty() || data.language_bundle.is_some();
    let required = if let Some(policy) = admitted.config.acquisition {
        policy
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        policy.backend_ids
    } else {
        Vec::new()
    };
    let _timer = pg.query_timer("leases.claim_session");
    // Parallel runs probe only claimable states and an indexed availability range.
    // Recovering holders retain their state, so live recovery leases must also leave
    // the searchable range. Serial runs inspect exactly the first unfinished slot;
    // skipping a locked head must never grant its successor.
    let candidate = if parallel_roles_allowed {
        "SELECT c.session_id FROM crawl_sessions c \
         WHERE c.run_id=$2 AND c.lease_kind='role' AND c.status IN ('pending','recovering') \
           AND ($4::uuid IS NULL OR c.session_id=$4) \
           AND COALESCE(c.lease_expires_at,'-infinity'::timestamptz)<clock_timestamp() \
         ORDER BY COALESCE(c.lease_expires_at,'-infinity'::timestamptz),c.schedule_slot \
         LIMIT 1 FOR UPDATE SKIP LOCKED"
    } else {
        "SELECT c.session_id FROM crawl_sessions c \
         WHERE c.session_id=(SELECT p.session_id FROM crawl_sessions p WHERE p.run_id=$2 \
           AND p.lease_kind='role' AND p.status NOT IN ('completed','failed','cancelled') ORDER BY p.schedule_slot LIMIT 1) \
           AND ($4::uuid IS NULL OR c.session_id=$4) AND c.status IN ('pending','recovering') \
           AND COALESCE(c.lease_expires_at,'-infinity'::timestamptz)<clock_timestamp() \
         FOR UPDATE SKIP LOCKED"
    };
    let sql = format!(
        "UPDATE crawl_sessions s SET status=CASE WHEN s.status='pending' THEN 'running' ELSE s.status END, \
         lease_owner=$1,lease_expires_at=clock_timestamp()+make_interval(secs=>$3), \
         fencing_token=nextval('lease_fence_seq'),last_heartbeat_at=clock_timestamp(), \
         started_at=COALESCE(s.started_at,clock_timestamp()) \
         WHERE EXISTS(SELECT 1 FROM crawl_runs r WHERE r.run_id=$2 AND r.status IN ('queued','running') \
           AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL) \
           AND ((cardinality($5::text[])=0 AND NOT $6::boolean) OR EXISTS(SELECT 1 FROM workers w \
             WHERE w.worker_id=$1 AND NOT w.draining AND w.last_heartbeat_at<=clock_timestamp() \
               AND w.last_heartbeat_at>=clock_timestamp()-interval '90 seconds' \
               AND (w.capacity->'acceptsQueued'='true'::jsonb OR w.capacity->>'localRun'=$2::text) \
               AND NOT EXISTS(SELECT 1 FROM unnest($5::text[]) required(backend_id) \
                 WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(w.capacity->'acquisition','[]'::jsonb)) fact \
                   WHERE fact->>'backendId'=required.backend_id AND fact->'available'='true'::jsonb)))) \
           AND crawlx_worker_data_eligible($1,(SELECT data_requirements FROM crawl_runs WHERE run_id=$2)) \
           AND s.session_id=({candidate}) RETURNING {SESSION_COLS},s.fencing_token,s.lease_expires_at");
    let row = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(worker.0)
        .bind(run.0)
        .bind(secs(pg.cfg.session_ttl))
        .bind(requested.map(|session| session.0))
        .bind(required)
        .bind(data_required)
        .fetch_optional(&pg.pool)
        .await
        .map_err(db)?;
    row.map(|row| {
        Ok(SessionLease {
            session: crate::repos::session_from_row(&row)?,
            worker,
            fencing_token: get(&row, "fencing_token")?,
            expires_at: get(&row, "lease_expires_at")?,
        })
    })
    .transpose()
}

#[async_trait]
impl LeaseRepo for Pg {
    async fn now(&self) -> Result<Timestamp, StoreError> {
        self.db_now().await
    }

    async fn admission(&self) -> Result<AdmissionMode, StoreError> {
        crate::admin::admission_of(self).await
    }

    async fn active_runs(&self) -> Result<Vec<ActiveRun>, StoreError> {
        let _timer = self.query_timer("leases.active_runs");
        let rows = sqlx::query(
            "SELECT run_id, config FROM crawl_runs r WHERE r.status IN ('queued','running') \
             AND EXISTS (SELECT 1 FROM crawl_sessions s WHERE s.run_id = r.run_id AND s.lease_kind='role' AND s.status IN ('pending','recovering')) \
             ORDER BY r.run_id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                let value: serde_json::Value = get(r, "config")?;
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
                    run: CrawlRunId(get(r, "run_id")?),
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
        claim_pg(self, run, worker, parallel_roles_allowed, None).await
    }

    async fn claim_session_exact(
        &self,
        run: CrawlRunId,
        session: SessionId,
        worker: WorkerId,
        parallel_roles_allowed: bool,
    ) -> Result<Option<SessionLease>, StoreError> {
        claim_pg(self, run, worker, parallel_roles_allowed, Some(session)).await
    }

    async fn create_render_session(
        &self,
        session: &CrawlSession,
        worker: WorkerId,
    ) -> Result<SessionLease, StoreError> {
        validate_render_session(session)?;
        if !self.admission().await?.grants_leases() {
            return Err(StoreError::Unavailable("session admission is closed".into()));
        }
        let admitted = <Pg as crawlx_core::repo::RunRepo>::get(self, session.run).await?;
        let data = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(&admitted.config)?;
        let data_required = !data.destinations.is_empty() || data.language_bundle.is_some();
        let required = if let Some(policy) = admitted.config.acquisition {
            policy
                .validate()
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            policy.backend_ids
        } else {
            Vec::new()
        };
        let sql = format!("INSERT INTO crawl_sessions AS s \
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
            RETURNING {SESSION_COLS},s.fencing_token,s.lease_expires_at");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(session.id.0)
            .bind(session.run.0)
            .bind(&session.role.0)
            .bind(i32::from(session.run_index))
            .bind(
                i32::try_from(session.schedule_slot)
                    .map_err(|_| StoreError::Conflict("render slot overflow".into()))?,
            )
            .bind(worker.0)
            .bind(secs(self.cfg.session_ttl))
            .bind(required)
            .bind(data_required)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| {
                StoreError::Unavailable("render parent run or assigned worker is unavailable".into())
            })?;
        Ok(SessionLease {
            session: crate::repos::session_from_row(&row)?,
            worker,
            fencing_token: get(&row, "fencing_token")?,
            expires_at: get(&row, "lease_expires_at")?,
        })
    }

    async fn heartbeat(&self, lease: &SessionLease) -> Result<Timestamp, StoreError> {
        let _timer = self.query_timer("leases.heartbeat");
        let row = sqlx::query(
            "UPDATE crawl_sessions SET lease_expires_at = clock_timestamp() + make_interval(secs => $4), last_heartbeat_at = clock_timestamp() \
             WHERE session_id = $1 AND lease_owner = $2 AND fencing_token = $3 AND status IN ('running','recovering') AND lease_expires_at > clock_timestamp() \
             RETURNING lease_expires_at",
        )
        .bind(lease.session.id.0)
        .bind(lease.worker.0)
        .bind(lease.fencing_token)
        .bind(secs(self.cfg.session_ttl))
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        match row {
            Some(r) => get(&r, "lease_expires_at"),
            None => Err(StoreError::LeaseLost),
        }
    }

    async fn release(&self, lease: &SessionLease, to: SessionStatus) -> Result<(), StoreError> {
        let _timer = self.query_timer("leases.release");
        if !(to.is_terminal() || to == SessionStatus::Recovering) {
            return Err(StoreError::Conflict(format!(
                "cannot release a session into {}",
                to.as_str()
            )));
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row = sqlx::query(
            "UPDATE crawl_sessions SET status = $4, lease_owner = NULL, lease_expires_at = NULL, \
               finished_at = CASE WHEN $5 THEN now() ELSE finished_at END \
             WHERE session_id = $1 AND lease_owner = $2 AND fencing_token = $3 AND status IN ('running','recovering') AND lease_expires_at > clock_timestamp() \
             RETURNING session_id",
        )
        .bind(lease.session.id.0)
        .bind(lease.worker.0)
        .bind(lease.fencing_token)
        .bind(to.as_str())
        .bind(to.is_terminal())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if row.is_none() {
            return Err(StoreError::LeaseLost);
        }
        if to == SessionStatus::Recovering {
            flip_intended_to_unknown(&mut tx, &[lease.session.id.0]).await?;
        }
        tx.commit().await.map_err(db)
    }

    async fn reap(&self, now: Timestamp) -> Result<ReapReport, StoreError> {
        let _timer = self.query_timer("leases.reap");
        let mut tx = self.pool.begin().await.map_err(db)?;
        let rows = sqlx::query(
            "UPDATE crawl_sessions SET status = 'recovering', lease_owner = NULL, lease_expires_at = NULL \
             WHERE status = 'running' AND lease_expires_at < $1 RETURNING session_id",
        )
        .bind(now)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let ids = rows
            .iter()
            .map(|r| get::<uuid::Uuid>(r, "session_id"))
            .collect::<Result<Vec<_>, _>>()?;
        let actions = flip_intended_to_unknown(&mut tx, &ids).await?;
        tx.commit().await.map_err(db)?;
        Ok(ReapReport {
            sessions_recovering: ids.into_iter().map(SessionId).collect(),
            actions_unknown: actions,
        })
    }

    async fn reap_frontier(&self, now: Timestamp, max_attempts: u16) -> Result<FrontierReap, StoreError> {
        let _timer = self.query_timer("leases.reap_frontier");
        let rows = sqlx::query(
            "UPDATE url_frontier SET \
               status = CASE WHEN attempts >= $2 THEN 'failed' ELSE 'pending' END, \
               error_code = CASE WHEN attempts >= $2 THEN 'lease_expired' ELSE error_code END, \
               finished_at = CASE WHEN attempts >= $2 THEN now() ELSE NULL END, \
               lease_owner = NULL, lease_expires_at = NULL \
             WHERE status = 'leased' AND lease_expires_at < $1 RETURNING status,via",
        )
        .bind(now)
        .bind(crate::codec::conv::<u16, i16>(max_attempts, "max_attempts")?)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut out = FrontierReap::default();
        for r in &rows {
            if get::<String>(r, "via")? == "interaction" {
                continue;
            }
            if get::<String>(r, "status")? == "failed" {
                out.failed += 1;
            } else {
                out.requeued += 1;
            }
        }
        Ok(out)
    }

    async fn heartbeat_frontier(
        &self,
        worker: WorkerId,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, StoreError> {
        let _timer = self.query_timer("leases.heartbeat_frontier");
        let (ids, fences): (Vec<i64>, Vec<i64>) = leases.iter().copied().unzip();
        let rows = sqlx::query(
            "UPDATE url_frontier f SET lease_expires_at = now() + make_interval(secs => $4) \
             FROM unnest($1::bigint[], $2::bigint[]) AS held(frontier_id, fencing_token) \
             WHERE f.frontier_id = held.frontier_id AND f.fencing_token = held.fencing_token \
               AND f.lease_owner = $3 AND f.status = 'leased' AND f.lease_expires_at > now() RETURNING f.frontier_id",
        )
        .bind(ids)
        .bind(fences)
        .bind(worker.0)
        .bind(secs(self.cfg.url_batch_ttl))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(|r| get::<i64>(r, "frontier_id")).collect()
    }

    fn url_batch_ttl(&self) -> Duration {
        self.cfg.url_batch_ttl
    }
}
