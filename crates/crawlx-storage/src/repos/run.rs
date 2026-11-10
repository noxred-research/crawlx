//! `RunRepo` (`crawl_sessions`, `idempotency_keys`).

use super::{session_from_row, SESSION_COLS};
use crate::codec::{conv, expiry, from_json, get, label, parse_label, signed_bits, to_json, unsigned_bits};
use crate::error::{db, not_found};
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::{CrawlRun, CrawlSession, RunMetadata, RunRepo, SessionStatus};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::state::StateSignature;
use crawlx_core::{CrawlRunId, SessionId, StoreError, TenantId, TraceId};
use sqlx::postgres::PgRow;
use std::str::FromStr;

const QUERY_CLASSIFIER_VERSION: i16 = 1;

fn run_status(s: &str) -> Result<RunStatus, StoreError> {
    // `pausing` and `cancelling` are transient database-only states: the run still executes.
    match s {
        "pausing" | "cancelling" => Ok(RunStatus::Running),
        other => parse_label(other),
    }
}

async fn run_from_row(pg: &Pg, r: &PgRow) -> Result<CrawlRun, StoreError> {
    let mut run = CrawlRun {
        id: CrawlRunId(get(r, "run_id")?),
        tenant: TenantId(get(r, "tenant_id")?),
        status: run_status(&get::<String>(r, "status")?)?,
        terminal_reason: get::<Option<String>>(r, "terminal_reason")?
            .map(|s| parse_label::<TerminalReason>(&s))
            .transpose()?,
        config: if get::<String>(r, "retention_mode")? == "zdr" {
            pg.ephemeral_get(
                TenantId(get(r, "tenant_id")?),
                CrawlRunId(get(r, "run_id")?),
                i64::MIN,
                "run_config",
            )
            .await?
        } else {
            let config = get::<serde_json::Value>(r, "config")?;
            // Decode on an independent stack rather than the nested metadata future's stack.
            tokio::task::spawn_blocking(move || from_json(config))
                .await
                .map_err(|error| StoreError::Backend(format!("run config decode task failed: {error}")))??
        },
        config_digest: crate::codec::digest(&get::<Vec<u8>>(r, "config_digest")?)?,
        seed: CrawlSeed(unsigned_bits(get(r, "seed")?)?),
        policy_version: conv(get::<i32>(r, "policy_version")?, "policy_version")?,
        counters: from_json(get::<serde_json::Value>(r, "counters")?)?,
        created_at: get(r, "created_at")?,
        started_at: get(r, "started_at")?,
        finished_at: get(r, "finished_at")?,
        trace_id: get::<Option<String>>(r, "trace_id")?
            .map(|s| TraceId::from_str(&s).map_err(|e| StoreError::Serialization(e.to_string())))
            .transpose()?,
    };
    run.config.fetch = run.config.fetch.durable();
    Ok(run)
}

const RUN_COLS: &str = "run_id, tenant_id, status::text AS status, terminal_reason::text AS terminal_reason, config, config_digest, \
    seed, policy_version, counters, created_at, started_at, finished_at, trace_id, retention_mode::text AS retention_mode";

impl Pg {
    async fn prepare_config(&self, run: &CrawlRun) -> Result<serde_json::Value, StoreError> {
        if run.config.fetch.has_literal_secrets() {
            self.ephemeral_put(
                run.tenant,
                run.id,
                i64::MIN,
                &format!("_fetch_controls:{}", run.config_digest.to_hex()),
                &run.config.fetch,
            )
            .await?;
        }
        let mut config = run.config.clone();
        config.fetch = config.fetch.durable();
        if run.config.retention.mode != RetentionMode::Zdr {
            return to_json(&config);
        }
        self.ephemeral_put(run.tenant, run.id, i64::MIN, "run_config", &config)
            .await?;
        Ok(durable_zdr_config(run))
    }

    /// The run created under `(tenant, idempotency key)` and the request digest it was created with.
    ///
    /// # Errors
    /// Returns an error if the database query fails, the stored digest is malformed,
    /// or the idempotency record does not reference a run.
    pub async fn lookup_idempotency(
        &self,
        tenant: TenantId,
        key: &str,
    ) -> Result<Option<(CrawlRunId, Digest)>, StoreError> {
        let _timer = self.query_timer("run.lookup_idempotency");
        let row = sqlx::query("SELECT run_id, request_hash FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2 AND expires_at > now()")
            .bind(tenant.0)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        row.map(|r| {
            let run: Option<uuid::Uuid> = get(&r, "run_id")?;
            let run = run.ok_or_else(|| StoreError::Conflict("idempotency key has no run".to_owned()))?;
            Ok((
                CrawlRunId(run),
                crate::codec::digest(&get::<Vec<u8>>(&r, "request_hash")?)?,
            ))
        })
        .transpose()
    }
}

async fn insert_run(
    tx: &mut sqlx::PgConnection,
    run: &CrawlRun,
    durable_config: &serde_json::Value,
    replay: Option<(CrawlRunId, &serde_json::Value)>,
) -> Result<(), StoreError> {
    let cfg = &run.config;
    sqlx::query(
        "INSERT INTO crawl_runs (run_id, tenant_id, status, terminal_reason, mode, seed, safety_profile, authorization_record_id, \
           policy_version, identity_version, state_algo_version, query_classifier_version, config, config_digest, counters, \
           retention_mode, retention_days, expires_at, created_at, started_at, finished_at, trace_id, run_kind, replay_of, replay_spec, data_requirements) \
         VALUES ($1, $2, $3::text::run_status, $4::text::terminal_reason, $5::text::crawl_mode, $6, $7::text::safety_profile, $8, \
           $9, $10, $11, $12, $13, $14, $15, $16::text::retention_mode, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)",
    )
    .bind(run.id.0)
    .bind(run.tenant.0)
    .bind(run.status.as_str())
    .bind(run.terminal_reason.map(TerminalReason::as_str))
    .bind(label(&cfg.mode)?)
    .bind(signed_bits(run.seed.0)?)
    .bind(cfg.safety.profile.as_str())
    .bind(cfg.safety.authorization_record_ref.map(|a| a.0))
    .bind(conv::<u32, i32>(run.policy_version, "policy_version")?)
    .bind(conv::<u16, i16>(cfg.crawl.identity.version.decision_version(), "identity_version")?)
    .bind(conv::<u16, i16>(StateSignature::VERSION, "state_algo_version")?)
    .bind(QUERY_CLASSIFIER_VERSION)
    .bind(durable_config)
    .bind(run.config_digest.0.to_vec())
    .bind(to_json(&run.counters)?)
    .bind(label(&cfg.retention.mode)?)
    .bind(i32::from(cfg.retention.days))
    .bind(expiry(run.created_at, u32::from(cfg.retention.days)))
    .bind(run.created_at)
    .bind(run.started_at)
    .bind(run.finished_at)
    .bind(run.trace_id.map(|t| t.to_string()))
    .bind(if replay.is_some() { "replay" } else { "crawl" })
    .bind(replay.map(|(source, _)| source.0))
    .bind(replay.map(|(_, spec)| if cfg.retention.mode == RetentionMode::Zdr {
        serde_json::json!({ "sourceRunId": spec.get("sourceRunId") })
    } else {
        spec.clone()
    }))
    .bind(to_json(&crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(cfg)?)?)
    .execute(tx)
    .await
    .map_err(db)?;
    Ok(())
}

async fn insert_sessions(tx: &mut sqlx::PgConnection, sessions: &[CrawlSession]) -> Result<(), StoreError> {
    for s in sessions {
        // Launch profile and console capture follow the run's dynamic.launchProfile.
        let inserted = sqlx::query(
            "INSERT INTO crawl_sessions (session_id, run_id, role, run_index, schedule_slot, status, action_seq, launch_profile, console_capture) \
             SELECT $1::uuid, r.run_id, $3::text, $4::int, $5::int, $6::text, $7::bigint, \
                    COALESCE(r.config->'dynamic'->>'launchProfile', 'standard'), \
                    COALESCE(r.config->'dynamic'->>'launchProfile', 'standard') <> 'stealth' \
             FROM crawl_runs r WHERE r.run_id = $2",
        )
        .bind(s.id.0)
        .bind(s.run.0)
        .bind(&s.role.0)
        .bind(i32::from(s.run_index))
        .bind(conv::<u32, i32>(s.schedule_slot, "schedule_slot")?)
        .bind(s.status.as_str())
        .bind(conv::<u64, i64>(s.action_seq, "action_seq")?)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if inserted.rows_affected() == 0 {
            return Err(not_found("crawl_run", s.run));
        }
        if let Some(b) = &s.browser {
            write_browser(&mut *tx, s.id, b).await?;
        }
    }
    Ok(())
}

#[async_trait]
impl RunRepo for Pg {
    async fn create(&self, run: &CrawlRun, idempotency_key: Option<&str>) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.create");
        let durable_config = self.prepare_config(run).await?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        insert_run(&mut tx, run, &durable_config, None).await?;
        if let Some(key) = idempotency_key {
            sqlx::query(
                "INSERT INTO idempotency_keys (tenant_id, idem_key, request_hash, state, run_id, expires_at) \
                 VALUES ($1, $2, $3, 'done', $4, now() + interval '24 hours')",
            )
            .bind(run.tenant.0)
            .bind(key)
            .bind(run.config_digest.0.to_vec())
            .bind(run.id.0)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)
    }

    async fn create_replay(
        &self,
        run: &CrawlRun,
        sessions: &[CrawlSession],
        spec: &serde_json::Value,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.create_replay");
        let durable_config = self.prepare_config(run).await?;
        if run.config.retention.mode == RetentionMode::Zdr {
            self.ephemeral_put(run.tenant, run.id, i64::MIN, "replay_spec", spec)
                .await?;
        }
        let source: CrawlRunId = serde_json::from_value(
            spec.get("sourceRunId")
                .cloned()
                .ok_or_else(|| StoreError::Conflict("replay sourceRunId is required".to_owned()))?,
        )
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
        if sessions.iter().any(|session| session.run != run.id) {
            return Err(StoreError::Conflict(
                "replay session belongs to another run".to_owned(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let owned: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT run_id FROM crawl_runs WHERE run_id = $1 AND tenant_id = $2 FOR KEY SHARE",
        )
        .bind(source.0)
        .bind(run.tenant.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if owned.is_none() {
            return Err(not_found("crawl_run", source));
        }
        insert_run(&mut tx, run, &durable_config, Some((source, spec))).await?;
        insert_sessions(&mut tx, sessions).await?;
        tx.commit().await.map_err(db)
    }

    async fn replay_spec(&self, run: CrawlRunId) -> Result<Option<serde_json::Value>, StoreError> {
        let _timer = self.query_timer("run.replay_spec");
        let (tenant, zdr) = self.privacy_scope(run).await?;
        if zdr {
            let stored: Option<serde_json::Value> =
                sqlx::query_scalar("SELECT replay_spec FROM crawl_runs WHERE run_id = $1")
                    .bind(run.0)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(db)?;
            return if stored.is_some() {
                self.ephemeral_get(tenant, run, i64::MIN, "replay_spec")
                    .await
                    .map(Some)
            } else {
                Ok(None)
            };
        }
        let spec: Option<Option<serde_json::Value>> =
            sqlx::query_scalar("SELECT replay_spec FROM crawl_runs WHERE run_id = $1")
                .bind(run.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        spec.ok_or_else(|| not_found("crawl_run", run))
    }

    async fn get(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let _timer = self.query_timer("run.get");
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {RUN_COLS} FROM crawl_runs WHERE run_id = $1"
        )))
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("crawl_run", id))?;
        run_from_row(self, &row).await
    }

    async fn get_for_execution(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let mut run = RunRepo::get(self, id).await?;
        if run.config.fetch.has_literal_secrets() {
            run.config.fetch = self
                .ephemeral_get(
                    run.tenant,
                    id,
                    i64::MIN,
                    &format!("_fetch_controls:{}", run.config_digest.to_hex()),
                )
                .await?;
        }
        Ok(run)
    }

    async fn get_metadata(&self, id: CrawlRunId) -> Result<RunMetadata, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {RUN_COLS} FROM crawl_runs WHERE run_id = $1"
        )))
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("crawl_run", id))?;
        if get::<String>(&row, "retention_mode")? != "zdr" {
            return Ok(RunMetadata::from(&run_from_row(self, &row).await?));
        }
        let config: serde_json::Value = get(&row, "config")?;
        let mut metadata: RunMetadata = from_json(
            config
                .get("metadata")
                .cloned()
                .ok_or_else(|| StoreError::Serialization("missing durable zdr run metadata".to_owned()))?,
        )?;
        metadata.id = id;
        metadata.tenant = TenantId(get(&row, "tenant_id")?);
        metadata.status = run_status(&get::<String>(&row, "status")?)?;
        metadata.terminal_reason = get::<Option<String>>(&row, "terminal_reason")?
            .map(|reason| parse_label(&reason))
            .transpose()?;
        metadata.counters = from_json(get::<serde_json::Value>(&row, "counters")?)?;
        metadata.started_at = get(&row, "started_at")?;
        metadata.finished_at = get(&row, "finished_at")?;
        metadata.trace_id = get::<Option<String>>(&row, "trace_id")?
            .map(|trace| {
                TraceId::from_str(&trace).map_err(|error| StoreError::Serialization(error.to_string()))
            })
            .transpose()?;
        Ok(metadata)
    }

    async fn set_status(
        &self,
        id: CrawlRunId,
        status: RunStatus,
        reason: Option<TerminalReason>,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.set_status");
        if status.is_terminal() != reason.is_some() {
            return Err(StoreError::Conflict(format!(
                "terminal_reason must be set exactly for terminal statuses (status {}, reason {:?})",
                status.as_str(),
                reason
            )));
        }
        let updated = sqlx::query(
            "UPDATE crawl_runs SET status = $2::text::run_status, terminal_reason = $3::text::terminal_reason, \
               started_at = CASE WHEN $2 = 'running' THEN COALESCE(started_at, now()) ELSE started_at END, \
               finished_at = CASE WHEN $4 THEN now() ELSE finished_at END \
             WHERE run_id = $1 AND status::text NOT IN ('completed','failed','cancelled') RETURNING run_id",
        )
        .bind(id.0)
        .bind(status.as_str())
        .bind(reason.map(TerminalReason::as_str))
        .bind(status.is_terminal())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        if updated.is_some() {
            return Ok(());
        }
        let current: Option<String> =
            sqlx::query_scalar("SELECT status::text FROM crawl_runs WHERE run_id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        match current {
            Some(from) => Err(StoreError::IllegalTransition {
                from,
                to: status.as_str().to_owned(),
            }),
            None => Err(not_found("crawl_run", id)),
        }
    }

    async fn update_counters(&self, id: CrawlRunId, counters: PlaneCounters) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.update_counters");
        let r = sqlx::query("UPDATE crawl_runs SET counters = $2 WHERE run_id = $1")
            .bind(id.0)
            .bind(to_json(&counters)?)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        if r.rows_affected() == 0 {
            return Err(not_found("crawl_run", id));
        }
        Ok(())
    }

    async fn set_trace_id(&self, run: CrawlRunId, trace_id: TraceId) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.set_trace_id");
        let r = sqlx::query("UPDATE crawl_runs SET trace_id = $2 WHERE run_id = $1")
            .bind(run.0)
            .bind(trace_id.to_string())
            .execute(&self.pool)
            .await
            .map_err(db)?;
        if r.rows_affected() == 0 {
            return Err(not_found("crawl_run", run));
        }
        Ok(())
    }

    async fn create_sessions(&self, sessions: &[CrawlSession]) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.create_sessions");
        let mut tx = self.pool.begin().await.map_err(db)?;
        insert_sessions(&mut tx, sessions).await?;
        tx.commit().await.map_err(db)
    }

    async fn list_sessions(&self, run: CrawlRunId) -> Result<Vec<CrawlSession>, StoreError> {
        let _timer = self.query_timer("run.list_sessions");
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SESSION_COLS} FROM crawl_sessions s WHERE s.run_id = $1 ORDER BY s.schedule_slot"
        )))
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter().map(session_from_row).collect()
    }

    async fn set_session_status(&self, id: SessionId, status: SessionStatus) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.set_session_status");
        let updated = sqlx::query(
            "UPDATE crawl_sessions SET status = $2, \
               started_at = CASE WHEN $2 = 'running' THEN COALESCE(started_at, now()) ELSE started_at END, \
               finished_at = CASE WHEN $3 THEN now() ELSE finished_at END, \
               lease_owner = CASE WHEN $3 THEN NULL ELSE lease_owner END, \
               lease_expires_at = CASE WHEN $3 THEN NULL ELSE lease_expires_at END \
             WHERE session_id = $1 AND status NOT IN ('completed','failed','cancelled') RETURNING session_id",
        )
        .bind(id.0)
        .bind(status.as_str())
        .bind(status.is_terminal())
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        if updated.is_some() {
            return Ok(());
        }
        let current: Option<String> =
            sqlx::query_scalar("SELECT status FROM crawl_sessions WHERE session_id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        match current {
            Some(from) => Err(StoreError::IllegalTransition {
                from,
                to: status.as_str().to_owned(),
            }),
            None => Err(not_found("crawl_session", id)),
        }
    }

    async fn set_session_browser(&self, id: SessionId, info: &BrowserBuildInfo) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.set_session_browser");
        let mut tx = self.pool.begin().await.map_err(db)?;
        write_browser(&mut tx, id, info).await?;
        tx.commit().await.map_err(db)
    }
}

async fn write_browser(
    tx: &mut sqlx::PgConnection,
    id: SessionId,
    b: &BrowserBuildInfo,
) -> Result<(), StoreError> {
    let r = sqlx::query(
        "UPDATE crawl_sessions SET browser_build = $2, cdp_revision = $3, \
           browser_user_agent = CASE WHEN (SELECT retention_mode = 'zdr' FROM crawl_runs WHERE run_id = crawl_sessions.run_id) \
             THEN NULL ELSE $4 END, browser_pinned = $5, \
           launch_profile = $6, console_capture = $7 WHERE session_id = $1",
    )
    .bind(id.0)
    .bind(&b.chromium_version)
    .bind(&b.cdp_revision)
    .bind(&b.user_agent)
    .bind(b.pinned)
    .bind(b.launch_profile.as_str())
    .bind(b.console_capture)
    .execute(tx)
    .await
    .map_err(db)?;
    if r.rows_affected() == 0 {
        return Err(not_found("crawl_session", id));
    }
    Ok(())
}

fn durable_zdr_config(run: &CrawlRun) -> serde_json::Value {
    let config = &run.config;
    serde_json::json!({
        "privacy": "zdr",
        "parallelRolesAllowed": config.parallel_roles_allowed(),
        "dynamic": { "launchProfile": config.dynamic.launch_profile.as_str() },
        "safety": {
            "externalCommunication": config.safety.external_communication,
            "destructiveActions": config.safety.destructive_actions,
        },
        "webhookConfigured": config.output.webhook.is_some(),
        "metadata": RunMetadata::from(run),
    })
}
