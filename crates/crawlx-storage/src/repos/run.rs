//! `RunRepo` (`crawl_runs`, `crawl_sessions`, `idempotency_keys`).

use super::effects::{in_rust, settle_run};
use super::{now_plus_hours, session_from_row, SESSION_COLS};
use crate::backend::strategy::Conn;
use crate::backend::{BackendKind, Dialect, RowLock};
use crate::codec::{conv, expiry, from_json, label, parse_label, signed_bits, to_json, unsigned_bits};
use crate::error::not_found;
use crate::sql::{returning, stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::{CrawlRun, CrawlSession, RunMetadata, RunRepo, SessionStatus};
use crawlx_core::seed::CrawlSeed;
use crawlx_core::state::StateSignature;
use crawlx_core::{CrawlRunId, SessionId, StoreError, TenantId, TraceId};
use std::str::FromStr;

const QUERY_CLASSIFIER_VERSION: i16 = 1;

fn run_status(s: &str) -> Result<RunStatus, StoreError> {
    // `pausing` and `cancelling` are transient database-only states: the run still executes.
    match s {
        "pausing" | "cancelling" => Ok(RunStatus::Running),
        other => parse_label(other),
    }
}

async fn run_from_row<B: Sql>(store: &Store<B>, r: &B::Row) -> Result<CrawlRun, StoreError> {
    let mut run = CrawlRun {
        id: CrawlRunId(r.uuid("run_id")?),
        tenant: TenantId(r.uuid("tenant_id")?),
        status: run_status(&r.text("status")?)?,
        terminal_reason: r
            .opt_text("terminal_reason")?
            .map(|s| parse_label::<TerminalReason>(&s))
            .transpose()?,
        config: if r.text("retention_mode")? == "zdr" {
            store
                .ephemeral_get(
                    TenantId(r.uuid("tenant_id")?),
                    CrawlRunId(r.uuid("run_id")?),
                    i64::MIN,
                    "run_config",
                )
                .await?
        } else {
            let config = r.json("config")?;
            // Decode on an independent stack rather than the nested metadata future's stack.
            // Keep its large result boxed across the task handoff: constructing an inline
            // CreateCrawl task also consumes the already-deep caller's stack before spawning.
            *tokio::task::spawn_blocking(move || from_json::<Box<crawlx_core::config::CreateCrawl>>(config))
                .await
                .map_err(|error| StoreError::Backend(format!("run config decode task failed: {error}")))??
        },
        config_digest: crate::codec::digest(&r.bytes("config_digest")?)?,
        seed: CrawlSeed(unsigned_bits(r.i64("seed")?)?),
        policy_version: conv(r.i32("policy_version")?, "policy_version")?,
        counters: from_json(r.json("counters")?)?,
        created_at: r.ts("created_at")?,
        started_at: r.opt_ts("started_at")?,
        finished_at: r.opt_ts("finished_at")?,
        trace_id: r
            .opt_text("trace_id")?
            .map(|s| TraceId::from_str(&s).map_err(|e| StoreError::Serialization(e.to_string())))
            .transpose()?,
    };
    run.config.fetch = run.config.fetch.durable();
    Ok(run)
}

const RUN_COLS: &str = "run_id, tenant_id, status::text AS status, terminal_reason::text AS terminal_reason, config, config_digest, \
    seed, policy_version, counters, created_at, started_at, finished_at, trace_id, retention_mode::text AS retention_mode";

impl<B: Sql> Store<B> {
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
        let row = stmt!(
            B,
            format!(
                "SELECT run_id, request_hash FROM idempotency_keys WHERE tenant_id = $1 AND idem_key = $2 AND expires_at > {}",
                <B::Dialect as Dialect>::now()
            )
        )
        .uuid(tenant.0)
        .text(key)
        .fetch_optional_pool(&self.pool)
        .await?;
        row.map(|r| {
            let run = r
                .opt_uuid("run_id")?
                .ok_or_else(|| StoreError::Conflict("idempotency key has no run".to_owned()))?;
            Ok((CrawlRunId(run), crate::codec::digest(&r.bytes("request_hash")?)?))
        })
        .transpose()
    }
}

async fn insert_run<B: Sql>(
    tx: &mut Conn<B>,
    run: &CrawlRun,
    durable_config: &serde_json::Value,
    replay: Option<(CrawlRunId, &serde_json::Value)>,
) -> Result<(), StoreError> {
    let cfg = &run.config;
    let mode = label(&cfg.mode)?;
    let retention_mode = label(&cfg.retention.mode)?;
    let counters = to_json(&run.counters)?;
    let requirements = to_json(&crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(cfg)?)?;
    let replay_spec = replay.map(|(_, spec)| {
        if cfg.retention.mode == RetentionMode::Zdr {
            serde_json::json!({ "sourceRunId": spec.get("sourceRunId") })
        } else {
            spec.clone()
        }
    });
    let trace_id = run.trace_id.map(|t| t.to_string());
    stmt!(
        B,
        "INSERT INTO crawl_runs (run_id, tenant_id, status, terminal_reason, mode, seed, safety_profile, authorization_record_id, \
           policy_version, identity_version, state_algo_version, query_classifier_version, config, config_digest, counters, \
           retention_mode, retention_days, expires_at, created_at, started_at, finished_at, trace_id, run_kind, replay_of, replay_spec, data_requirements, feed_required) \
         VALUES ($1, $2, $3::text::run_status, $4::text::terminal_reason, $5::text::crawl_mode, $6, $7::text::safety_profile, $8, \
           $9, $10, $11, $12, $13, $14, $15, $16::text::retention_mode, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)"
    )
    .uuid(run.id.0)
    .uuid(run.tenant.0)
    .text(run.status.as_str())
    .opt_text(run.terminal_reason.map(TerminalReason::as_str))
    .text(&mode)
    .i64(signed_bits(run.seed.0)?)
    .text(cfg.safety.profile.as_str())
    .opt_uuid(cfg.safety.authorization_record_ref.map(|a| a.0))
    .i32(conv::<u32, i32>(run.policy_version, "policy_version")?)
    .i16(conv::<u16, i16>(cfg.crawl.identity.version.decision_version(), "identity_version")?)
    .i16(conv::<u16, i16>(StateSignature::VERSION, "state_algo_version")?)
    .i16(QUERY_CLASSIFIER_VERSION)
    .json(durable_config)
    .bytes(&run.config_digest.0)
    .json(&counters)
    .text(&retention_mode)
    .i32(i32::from(cfg.retention.days))
    .opt_ts(expiry(run.created_at, u32::from(cfg.retention.days)))
    .ts(run.created_at)
    .opt_ts(run.started_at)
    .opt_ts(run.finished_at)
    .opt_text(trace_id.as_deref())
    .text(if replay.is_some() { "replay" } else { "crawl" })
    .opt_uuid(replay.map(|(source, _)| source.0))
    .opt_json(replay_spec.as_ref())
    .json(&requirements)
    .bool(!cfg.datasets.feeds.is_empty())
    .execute(tx)
    .await?;
    Ok(())
}

async fn insert_sessions<B: Sql>(tx: &mut Conn<B>, sessions: &[CrawlSession]) -> Result<(), StoreError> {
    for s in sessions {
        // Launch profile and console capture follow the run's dynamic.launchProfile.
        let launch_profile = <B::Dialect as Dialect>::json_text(
            &<B::Dialect as Dialect>::json_extract("r.config", "dynamic"),
            "launchProfile",
        );
        let inserted = stmt!(
            B,
            format!(
                "INSERT INTO crawl_sessions (session_id, run_id, role, run_index, schedule_slot, status, action_seq, session_kind, launch_profile, console_capture) \
                 SELECT $1::uuid, r.run_id, $3::text, $4::int, $5::int, $6::text, $7::bigint, $8::text, \
                        COALESCE({launch_profile}, 'standard'), \
                        COALESCE({launch_profile}, 'standard') <> 'stealth' \
                 FROM crawl_runs r WHERE r.run_id = $2"
            )
        )
        .uuid(s.id.0)
        .uuid(s.run.0)
        .text(&s.role.0)
        .i32(i32::from(s.run_index))
        .i32(conv::<u32, i32>(s.schedule_slot, "schedule_slot")?)
        .text(s.status.as_str())
        .i64(conv::<u64, i64>(s.action_seq, "action_seq")?)
        .text(s.kind.as_str())
        .execute(&mut *tx)
        .await?;
        if inserted == 0 {
            return Err(not_found("crawl_run", s.run));
        }
        if let Some(b) = &s.browser {
            write_browser::<B>(&mut *tx, s.id, b).await?;
        }
    }
    Ok(())
}

#[async_trait]
impl<B: Sql> RunRepo for Store<B> {
    async fn create(&self, run: &CrawlRun, idempotency_key: Option<&str>) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.create");
        let durable_config = self.prepare_config(run).await?;
        let mut tx = self.begin_write().await?;
        insert_run::<B>(tx.conn(), run, &durable_config, None).await?;
        if let Some(key) = idempotency_key {
            stmt!(
                B,
                format!(
                    "INSERT INTO idempotency_keys (tenant_id, idem_key, request_hash, state, run_id, expires_at) \
                     VALUES ($1, $2, $3, 'done', $4, {})",
                    now_plus_hours::<B>(24)
                )
            )
            .uuid(run.tenant.0)
            .text(key)
            .bytes(&run.config_digest.0)
            .uuid(run.id.0)
            .execute(tx.conn())
            .await?;
        }
        tx.commit().await
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
        let mut tx = self.begin_write().await?;
        // the source run stays while the replay references it
        let share = if B::KIND == BackendKind::Postgres {
            " FOR KEY SHARE"
        } else {
            <B::Dialect as Dialect>::row_lock(RowLock::Share)
        };
        let owned = stmt!(
            B,
            format!("SELECT run_id FROM crawl_runs WHERE run_id = $1 AND tenant_id = $2{share}")
        )
        .uuid(source.0)
        .uuid(run.tenant.0)
        .fetch_optional(tx.conn())
        .await?;
        if owned.is_none() {
            return Err(not_found("crawl_run", source));
        }
        insert_run::<B>(tx.conn(), run, &durable_config, Some((source, spec))).await?;
        insert_sessions::<B>(tx.conn(), sessions).await?;
        tx.commit().await
    }

    async fn replay_spec(&self, run: CrawlRunId) -> Result<Option<serde_json::Value>, StoreError> {
        let _timer = self.query_timer("run.replay_spec");
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let row = stmt!(B, "SELECT replay_spec FROM crawl_runs WHERE run_id = $1")
            .uuid(run.0)
            .fetch_optional_pool(&self.pool)
            .await?;
        if zdr {
            let row = row.ok_or_else(|| not_found("crawl_run", run))?;
            return if row.opt_json("replay_spec")?.is_some() {
                self.ephemeral_get(tenant, run, i64::MIN, "replay_spec")
                    .await
                    .map(Some)
            } else {
                Ok(None)
            };
        }
        row.ok_or_else(|| not_found("crawl_run", run))?
            .opt_json("replay_spec")
    }

    async fn get(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let _timer = self.query_timer("run.get");
        let row = stmt!(B, format!("SELECT {RUN_COLS} FROM crawl_runs WHERE run_id = $1"))
            .uuid(id.0)
            .fetch_optional_pool(&self.pool)
            .await?
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
        let row = stmt!(B, format!("SELECT {RUN_COLS} FROM crawl_runs WHERE run_id = $1"))
            .uuid(id.0)
            .fetch_optional_pool(&self.pool)
            .await?
            .ok_or_else(|| not_found("crawl_run", id))?;
        if row.text("retention_mode")? != "zdr" {
            return Ok(RunMetadata::from(&run_from_row(self, &row).await?));
        }
        let config = row.json("config")?;
        let mut metadata: RunMetadata = from_json(
            config
                .get("metadata")
                .cloned()
                .ok_or_else(|| StoreError::Serialization("missing durable zdr run metadata".to_owned()))?,
        )?;
        metadata.id = id;
        metadata.tenant = TenantId(row.uuid("tenant_id")?);
        metadata.status = run_status(&row.text("status")?)?;
        metadata.terminal_reason = row
            .opt_text("terminal_reason")?
            .map(|reason| parse_label(&reason))
            .transpose()?;
        metadata.counters = from_json(row.json("counters")?)?;
        metadata.started_at = row.opt_ts("started_at")?;
        metadata.finished_at = row.opt_ts("finished_at")?;
        metadata.trace_id = row
            .opt_text("trace_id")?
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
        let now = <B::Dialect as Dialect>::now();
        let ret = returning::<B>("run_id");
        let update = stmt!(
            B,
            format!(
                "UPDATE crawl_runs SET status = $2::text::run_status, terminal_reason = $3::text::terminal_reason, \
                   started_at = CASE WHEN $2 = 'running' THEN COALESCE(started_at, {now}) ELSE started_at END, \
                   finished_at = CASE WHEN $4 THEN {now} ELSE finished_at END \
                 WHERE run_id = $1 AND status::text NOT IN ('completed','failed','cancelled'){ret}"
            )
        )
        .uuid(id.0)
        .text(status.as_str())
        .opt_text(reason.map(TerminalReason::as_str))
        .bool(status.is_terminal());
        let updated = if in_rust::<B>() {
            // the credential revocation of a terminal run commits with the status change
            let mut tx = self.begin_write().await?;
            let matched = update.matched(tx.conn()).await?;
            if matched {
                settle_run::<B>(tx.conn(), id).await?;
            }
            tx.commit().await?;
            matched
        } else {
            update.matched_write(&self.pool).await?
        };
        if updated {
            return Ok(());
        }
        let current = stmt!(
            B,
            "SELECT status::text AS status FROM crawl_runs WHERE run_id = $1"
        )
        .uuid(id.0)
        .fetch_optional_pool(&self.pool)
        .await?
        .map(|row| row.text("status"))
        .transpose()?;
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
        let counters = to_json(&counters)?;
        let updated = stmt!(B, "UPDATE crawl_runs SET counters = $2 WHERE run_id = $1")
            .uuid(id.0)
            .json(&counters)
            .execute_write(&self.pool)
            .await?;
        if updated == 0 {
            return Err(not_found("crawl_run", id));
        }
        Ok(())
    }

    async fn set_trace_id(&self, run: CrawlRunId, trace_id: TraceId) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.set_trace_id");
        let trace = trace_id.to_string();
        let updated = stmt!(B, "UPDATE crawl_runs SET trace_id = $2 WHERE run_id = $1")
            .uuid(run.0)
            .text(&trace)
            .execute_write(&self.pool)
            .await?;
        if updated == 0 {
            return Err(not_found("crawl_run", run));
        }
        Ok(())
    }

    async fn create_sessions(&self, sessions: &[CrawlSession]) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.create_sessions");
        let mut tx = self.begin_write().await?;
        insert_sessions::<B>(tx.conn(), sessions).await?;
        tx.commit().await
    }

    async fn list_sessions(&self, run: CrawlRunId) -> Result<Vec<CrawlSession>, StoreError> {
        let _timer = self.query_timer("run.list_sessions");
        let rows = stmt!(
            B,
            format!(
                "SELECT {SESSION_COLS} FROM crawl_sessions s WHERE s.run_id = $1 ORDER BY s.schedule_slot"
            )
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter().map(session_from_row).collect()
    }

    async fn set_session_status(&self, id: SessionId, status: SessionStatus) -> Result<(), StoreError> {
        let _timer = self.query_timer("run.set_session_status");
        let now = <B::Dialect as Dialect>::now();
        let ret = returning::<B>("session_id");
        let updated = stmt!(
            B,
            format!(
                "UPDATE crawl_sessions SET status = $2, \
                   started_at = CASE WHEN $2 = 'running' THEN COALESCE(started_at, {now}) ELSE started_at END, \
                   finished_at = CASE WHEN $3 THEN {now} ELSE finished_at END, \
                   lease_owner = CASE WHEN $3 THEN NULL ELSE lease_owner END, \
                   lease_expires_at = CASE WHEN $3 THEN NULL ELSE lease_expires_at END \
                 WHERE session_id = $1 AND status NOT IN ('completed','failed','cancelled'){ret}"
            )
        )
        .uuid(id.0)
        .text(status.as_str())
        .bool(status.is_terminal())
        .matched_write(&self.pool)
        .await?;
        if updated {
            return Ok(());
        }
        let current = stmt!(B, "SELECT status FROM crawl_sessions WHERE session_id = $1")
            .uuid(id.0)
            .fetch_optional_pool(&self.pool)
            .await?
            .map(|row| row.text("status"))
            .transpose()?;
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
        let mut tx = self.begin_write().await?;
        write_browser::<B>(tx.conn(), id, info).await?;
        tx.commit().await
    }
}

async fn write_browser<B: Sql>(
    tx: &mut Conn<B>,
    id: SessionId,
    b: &BrowserBuildInfo,
) -> Result<(), StoreError> {
    let updated = stmt!(
        B,
        "UPDATE crawl_sessions SET browser_build = $2, cdp_revision = $3, \
           browser_user_agent = CASE WHEN (SELECT retention_mode = 'zdr' FROM crawl_runs WHERE run_id = crawl_sessions.run_id) \
             THEN NULL ELSE $4 END, browser_pinned = $5, \
           launch_profile = $6, console_capture = $7 WHERE session_id = $1"
    )
    .uuid(id.0)
    .text(&b.chromium_version)
    .text(&b.cdp_revision)
    .text(&b.user_agent)
    .bool(b.pinned)
    .text(b.launch_profile.as_str())
    .bool(b.console_capture)
    .execute(tx)
    .await?;
    if updated == 0 {
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
