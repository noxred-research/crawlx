//! SQL behind [`IntelRepo`]: the tables of migration `0016_intel.sql` (`intel_jobs`,
//! `intel_trace`, `intel_snapshots`, `intel_threads`, `monitors`, `monitor_checks`,
//! `monitor_check_pages`, `monitor_baselines`, `usage_ledger`, `tenant_settings`).
//!
//! Those tables have no row-level security (see the migration header), so every statement that
//! takes a tenant filters on `tenant_id` itself. Counters travel as `BIGINT` through checked
//! conversions. Statements are runtime-checked `sqlx::query` calls timed as `intel.<method>`.

use crate::codec::{conv, get, parse_label};
use crate::error::{db, not_found};
use crate::intel::{
    Baseline, CheckPage, CheckRecord, IntelRepo, IntelResult, JobCount, JobKind, JobPatch, JobRecord,
    MonitorRecord, PurgeReport, Snapshot, ThreadRecord, TraceEvent, UsageDay, UsageEvent, UsageTotals,
};
use crate::Pg;
use async_trait::async_trait;
use crawlx_core::{StoreError, TenantId, Timestamp};
use serde_json::Value;
use sqlx::postgres::PgRow;
use std::collections::BTreeMap;
use uuid::Uuid;

const JOB_COLS: &str = "job_id, tenant_id, kind, status, request, result, error, stop_reason, tokens_used, \
     credits_used, thread_id, created_at, updated_at, finished_at, expires_at";

const MONITOR_COLS: &str = "monitor_id, tenant_id, name, status, schedule, cron, timezone, goal, targets, \
     retention_days, webhook, notification, next_run_at, last_run_at, last_check_id, claimed_until, \
     created_at, updated_at";

const CHECK_COLS: &str = "check_id, monitor_id, tenant_id, trigger_kind, state, status, summary, error, \
     started_at, finished_at, expires_at";

fn job_from_row(r: &PgRow) -> Result<JobRecord, StoreError> {
    Ok(JobRecord {
        id: get(r, "job_id")?,
        tenant: TenantId(get(r, "tenant_id")?),
        kind: parse_label(&get::<String>(r, "kind")?)?,
        status: parse_label(&get::<String>(r, "status")?)?,
        request: get(r, "request")?,
        result: get(r, "result")?,
        error: get(r, "error")?,
        stop_reason: get(r, "stop_reason")?,
        tokens_used: conv(get::<i64>(r, "tokens_used")?, "tokens_used")?,
        credits_used: conv(get::<i64>(r, "credits_used")?, "credits_used")?,
        thread_id: get(r, "thread_id")?,
        created_at: get(r, "created_at")?,
        updated_at: get(r, "updated_at")?,
        finished_at: get(r, "finished_at")?,
        expires_at: get(r, "expires_at")?,
    })
}

fn monitor_from_row(r: &PgRow) -> Result<MonitorRecord, StoreError> {
    Ok(MonitorRecord {
        id: get(r, "monitor_id")?,
        tenant: TenantId(get(r, "tenant_id")?),
        name: get(r, "name")?,
        status: parse_label(&get::<String>(r, "status")?)?,
        schedule: get(r, "schedule")?,
        cron: get(r, "cron")?,
        timezone: get(r, "timezone")?,
        goal: get(r, "goal")?,
        targets: get(r, "targets")?,
        retention_days: conv(get::<i32>(r, "retention_days")?, "retention_days")?,
        webhook: get(r, "webhook")?,
        notification: get(r, "notification")?,
        next_run_at: get(r, "next_run_at")?,
        last_run_at: get(r, "last_run_at")?,
        last_check_id: get(r, "last_check_id")?,
        claimed_until: get(r, "claimed_until")?,
        created_at: get(r, "created_at")?,
        updated_at: get(r, "updated_at")?,
    })
}

fn check_from_row(r: &PgRow) -> Result<CheckRecord, StoreError> {
    Ok(CheckRecord {
        id: get(r, "check_id")?,
        monitor: get(r, "monitor_id")?,
        tenant: TenantId(get(r, "tenant_id")?),
        trigger: get(r, "trigger_kind")?,
        state: parse_label(&get::<String>(r, "state")?)?,
        status: get(r, "status")?,
        summary: get(r, "summary")?,
        error: get(r, "error")?,
        started_at: get(r, "started_at")?,
        finished_at: get(r, "finished_at")?,
        expires_at: get(r, "expires_at")?,
    })
}

fn usage_from_row(r: &PgRow) -> Result<UsageEvent, StoreError> {
    Ok(UsageEvent {
        tenant: TenantId(get(r, "tenant_id")?),
        at: get(r, "at")?,
        endpoint: get(r, "endpoint")?,
        ref_id: get(r, "ref_id")?,
        status: get(r, "status")?,
        credits: conv(get::<i64>(r, "credits")?, "credits")?,
        prompt_tokens: conv(get::<i64>(r, "prompt_tokens")?, "prompt_tokens")?,
        completion_tokens: conv(get::<i64>(r, "completion_tokens")?, "completion_tokens")?,
    })
}

fn totals_from_row(r: &PgRow) -> Result<UsageTotals, StoreError> {
    Ok(UsageTotals {
        credits: conv(get::<i64>(r, "credits")?, "credits")?,
        prompt_tokens: conv(get::<i64>(r, "prompt_tokens")?, "prompt_tokens")?,
        completion_tokens: conv(get::<i64>(r, "completion_tokens")?, "completion_tokens")?,
        events: conv(get::<i64>(r, "events")?, "events")?,
    })
}

/// A sequence cursor that no stored row can exceed when `after` does not fit a `BIGINT`.
fn seq_cursor(after: u64) -> i64 {
    i64::try_from(after).unwrap_or(i64::MAX)
}

#[async_trait]
impl IntelRepo for Pg {
    async fn job_insert(&self, job: &JobRecord) -> IntelResult<()> {
        let _timer = self.query_timer("intel.job_insert");
        sqlx::query(
            "INSERT INTO intel_jobs (job_id, tenant_id, kind, status, request, result, error, stop_reason, \
             tokens_used, credits_used, thread_id, created_at, updated_at, finished_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
        )
        .bind(job.id)
        .bind(job.tenant.0)
        .bind(job.kind.as_str())
        .bind(job.status.as_str())
        .bind(&job.request)
        .bind(job.result.as_ref())
        .bind(job.error.as_deref())
        .bind(job.stop_reason.as_deref())
        .bind(conv::<_, i64>(job.tokens_used, "tokens_used")?)
        .bind(conv::<_, i64>(job.credits_used, "credits_used")?)
        .bind(job.thread_id)
        .bind(job.created_at)
        .bind(job.updated_at)
        .bind(job.finished_at)
        .bind(job.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn job_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<JobRecord>> {
        let _timer = self.query_timer("intel.job_get");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {JOB_COLS} FROM intel_jobs WHERE job_id = $1 AND tenant_id = $2"
        )))
        .bind(id)
        .bind(tenant.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .as_ref()
        .map(job_from_row)
        .transpose()
    }

    async fn job_update(
        &self,
        tenant: TenantId,
        id: Uuid,
        patch: &JobPatch,
    ) -> IntelResult<Option<JobRecord>> {
        let _timer = self.query_timer("intel.job_update");
        let tokens = patch
            .tokens_used
            .map(|v| conv::<_, i64>(v, "tokens_used"))
            .transpose()?;
        let credits = patch
            .credits_used
            .map(|v| conv::<_, i64>(v, "credits_used"))
            .transpose()?;
        // Every SET expression reads the pre-update row, so a terminal job keeps its status,
        // result, error, stop reason and finish time while counters and `updated_at` still move.
        // Under READ COMMITTED a concurrent writer's committed row is re-read before the SET runs.
        sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE intel_jobs SET \
           updated_at = $3, \
           status = CASE WHEN status = 'processing' THEN COALESCE($4::text, status) ELSE status END, \
           result = CASE WHEN status = 'processing' THEN COALESCE($5::jsonb, result) ELSE result END, \
           error = CASE WHEN status = 'processing' THEN COALESCE($6::text, error) ELSE error END, \
           stop_reason = CASE WHEN status = 'processing' THEN COALESCE($7::text, stop_reason) ELSE stop_reason END, \
           tokens_used = COALESCE($8::bigint, tokens_used), \
           credits_used = COALESCE($9::bigint, credits_used), \
           finished_at = CASE WHEN status = 'processing' THEN COALESCE($10::timestamptz, finished_at) ELSE finished_at END \
         WHERE job_id = $1 AND tenant_id = $2 \
         RETURNING {JOB_COLS}")))
        .bind(id)
        .bind(tenant.0)
        .bind(patch.at)
        .bind(patch.status.map(|s| s.as_str()))
        .bind(patch.result.as_ref())
        .bind(patch.error.as_deref())
        .bind(patch.stop_reason.as_deref())
        .bind(tokens)
        .bind(credits)
        .bind(patch.finished_at)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .as_ref()
        .map(job_from_row)
        .transpose()
    }

    async fn job_list(
        &self,
        tenant: TenantId,
        kind: Option<JobKind>,
        limit: u32,
        after: Option<(Timestamp, Uuid)>,
    ) -> IntelResult<Vec<JobRecord>> {
        let _timer = self.query_timer("intel.job_list");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {JOB_COLS} FROM intel_jobs \
         WHERE tenant_id = $1 \
           AND ($2::text IS NULL OR kind = $2) \
           AND ($3::timestamptz IS NULL OR (created_at, job_id) < ($3::timestamptz, $4::uuid)) \
         ORDER BY created_at DESC, job_id DESC \
         LIMIT $5"
        )))
        .bind(tenant.0)
        .bind(kind.map(JobKind::as_str))
        .bind(after.map(|(at, _)| at))
        .bind(after.map(|(_, id)| id))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(job_from_row)
        .collect()
    }

    async fn job_counts(&self, tenant: TenantId) -> IntelResult<Vec<JobCount>> {
        let _timer = self.query_timer("intel.job_counts");
        let rows = sqlx::query(
            "SELECT kind, status, count(*) AS n FROM intel_jobs WHERE tenant_id = $1 GROUP BY kind, status",
        )
        .bind(tenant.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut counts = rows
            .iter()
            .map(|r| {
                Ok(JobCount {
                    kind: parse_label(&get::<String>(r, "kind")?)?,
                    status: parse_label(&get::<String>(r, "status")?)?,
                    count: conv(get::<i64>(r, "n")?, "count")?,
                })
            })
            .collect::<Result<Vec<JobCount>, StoreError>>()?;
        counts.sort_by_key(|c| (c.kind, c.status));
        Ok(counts)
    }

    async fn trace_append(&self, job: Uuid, kind: &str, data: Value, at: Timestamp) -> IntelResult<u64> {
        let _timer = self.query_timer("intel.trace_append");
        // One statement: the counter bump takes the job's row lock, so concurrent appenders get
        // distinct, gap-free numbers in commit order.
        let seq: Option<i64> = sqlx::query_scalar(
            "WITH bumped AS (UPDATE intel_jobs SET trace_seq = trace_seq + 1 WHERE job_id = $1 \
                             RETURNING job_id, trace_seq) \
             INSERT INTO intel_trace (job_id, seq, kind, data, at) \
             SELECT job_id, trace_seq, $2::text, $3::jsonb, $4::timestamptz FROM bumped \
             RETURNING seq",
        )
        .bind(job)
        .bind(kind)
        .bind(&data)
        .bind(at)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        let seq = seq.ok_or_else(|| not_found("job", job))?;
        conv(seq, "seq")
    }

    async fn trace_list(&self, job: Uuid, after: u64, limit: u32) -> IntelResult<Vec<TraceEvent>> {
        let _timer = self.query_timer("intel.trace_list");
        let rows = sqlx::query(
            "SELECT seq, kind, data, at FROM intel_trace WHERE job_id = $1 AND seq > $2 ORDER BY seq LIMIT $3",
        )
        .bind(job)
        .bind(seq_cursor(after))
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(TraceEvent {
                    job,
                    seq: conv(get::<i64>(r, "seq")?, "seq")?,
                    kind: get(r, "kind")?,
                    data: get(r, "data")?,
                    at: get(r, "at")?,
                })
            })
            .collect()
    }

    async fn snapshot_put(&self, job: Uuid, id: &str, data: Value, at: Timestamp) -> IntelResult<()> {
        let _timer = self.query_timer("intel.snapshot_put");
        // Replacing keeps `ordinal`, so a snapshot stays at its first-creation position.
        let written = sqlx::query(
            "INSERT INTO intel_snapshots (job_id, snapshot_id, data, created_at) \
             SELECT job_id, $2::text, $3::jsonb, $4::timestamptz FROM intel_jobs WHERE job_id = $1 \
             ON CONFLICT (job_id, snapshot_id) DO UPDATE SET data = EXCLUDED.data, created_at = EXCLUDED.created_at",
        )
        .bind(job)
        .bind(id)
        .bind(&data)
        .bind(at)
        .execute(&self.pool)
        .await
        .map_err(db)?
        .rows_affected();
        if written == 0 {
            return Err(not_found("job", job));
        }
        Ok(())
    }

    async fn snapshot_get(&self, job: Uuid, id: &str) -> IntelResult<Option<Snapshot>> {
        let _timer = self.query_timer("intel.snapshot_get");
        let row = sqlx::query(
            "SELECT data, created_at FROM intel_snapshots WHERE job_id = $1 AND snapshot_id = $2",
        )
        .bind(job)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(Snapshot {
                job,
                id: id.to_owned(),
                data: get(&r, "data")?,
                created_at: get(&r, "created_at")?,
            })
        })
        .transpose()
    }

    async fn snapshot_ids(&self, job: Uuid) -> IntelResult<Vec<String>> {
        let _timer = self.query_timer("intel.snapshot_ids");
        sqlx::query_scalar("SELECT snapshot_id FROM intel_snapshots WHERE job_id = $1 ORDER BY ordinal")
            .bind(job)
            .fetch_all(&self.pool)
            .await
            .map_err(db)
    }

    async fn thread_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<ThreadRecord>> {
        let _timer = self.query_timer("intel.thread_get");
        let row = sqlx::query(
            "SELECT state, created_at, updated_at FROM intel_threads WHERE thread_id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        row.map(|r| {
            Ok(ThreadRecord {
                id,
                tenant,
                state: get(&r, "state")?,
                created_at: get(&r, "created_at")?,
                updated_at: get(&r, "updated_at")?,
            })
        })
        .transpose()
    }

    async fn thread_put(&self, tenant: TenantId, id: Uuid, state: Value, at: Timestamp) -> IntelResult<()> {
        let _timer = self.query_timer("intel.thread_put");
        // The conflict branch only fires for the owning tenant; a foreign row affects nothing.
        let written = sqlx::query(
            "INSERT INTO intel_threads (thread_id, tenant_id, state, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $4) \
             ON CONFLICT (thread_id) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at \
             WHERE intel_threads.tenant_id = EXCLUDED.tenant_id",
        )
        .bind(id)
        .bind(tenant.0)
        .bind(&state)
        .bind(at)
        .execute(&self.pool)
        .await
        .map_err(db)?
        .rows_affected();
        if written == 0 {
            return Err(StoreError::Conflict(format!(
                "thread {id} belongs to another tenant"
            )));
        }
        Ok(())
    }

    async fn monitor_insert(&self, m: &MonitorRecord) -> IntelResult<()> {
        let _timer = self.query_timer("intel.monitor_insert");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO monitors ({MONITOR_COLS}) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)"
        )))
        .bind(m.id)
        .bind(m.tenant.0)
        .bind(m.name.as_deref())
        .bind(m.status.as_str())
        .bind(&m.schedule)
        .bind(&m.cron)
        .bind(&m.timezone)
        .bind(m.goal.as_deref())
        .bind(&m.targets)
        .bind(conv::<_, i32>(m.retention_days, "retention_days")?)
        .bind(m.webhook.as_ref())
        .bind(&m.notification)
        .bind(m.next_run_at)
        .bind(m.last_run_at)
        .bind(m.last_check_id)
        .bind(m.claimed_until)
        .bind(m.created_at)
        .bind(m.updated_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn monitor_update(&self, m: &MonitorRecord) -> IntelResult<bool> {
        let _timer = self.query_timer("intel.monitor_update");
        // Scheduling state (`last_run_at`, `last_check_id`, `claimed_until`) is owned by
        // `monitor_claim_due` / `monitor_finish_run`; a PATCH that read the row before a claim
        // must not release the lease.
        let updated = sqlx::query(
            "UPDATE monitors SET name = $3, status = $4, schedule = $5, cron = $6, timezone = $7, goal = $8, \
               targets = $9, retention_days = $10, webhook = $11, notification = $12, next_run_at = $13, \
               updated_at = $14 \
             WHERE monitor_id = $1 AND tenant_id = $2",
        )
        .bind(m.id)
        .bind(m.tenant.0)
        .bind(m.name.as_deref())
        .bind(m.status.as_str())
        .bind(&m.schedule)
        .bind(&m.cron)
        .bind(&m.timezone)
        .bind(m.goal.as_deref())
        .bind(&m.targets)
        .bind(conv::<_, i32>(m.retention_days, "retention_days")?)
        .bind(m.webhook.as_ref())
        .bind(&m.notification)
        .bind(m.next_run_at)
        .bind(m.updated_at)
        .execute(&self.pool)
        .await
        .map_err(db)?
        .rows_affected();
        Ok(updated > 0)
    }

    async fn monitor_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<MonitorRecord>> {
        let _timer = self.query_timer("intel.monitor_get");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {MONITOR_COLS} FROM monitors WHERE monitor_id = $1 AND tenant_id = $2"
        )))
        .bind(id)
        .bind(tenant.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .as_ref()
        .map(monitor_from_row)
        .transpose()
    }

    async fn monitor_list(
        &self,
        tenant: TenantId,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<MonitorRecord>> {
        let _timer = self.query_timer("intel.monitor_list");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {MONITOR_COLS} FROM monitors WHERE tenant_id = $1 \
         ORDER BY created_at DESC, monitor_id DESC LIMIT $2 OFFSET $3"
        )))
        .bind(tenant.0)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(monitor_from_row)
        .collect()
    }

    async fn monitor_count(&self, tenant: TenantId) -> IntelResult<u64> {
        let _timer = self.query_timer("intel.monitor_count");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM monitors WHERE tenant_id = $1")
            .bind(tenant.0)
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
        conv(n, "count")
    }

    async fn monitor_delete(&self, tenant: TenantId, id: Uuid) -> IntelResult<bool> {
        let _timer = self.query_timer("intel.monitor_delete");
        // Checks, their pages and the baselines go with the monitor (ON DELETE CASCADE).
        let deleted = sqlx::query("DELETE FROM monitors WHERE monitor_id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant.0)
            .execute(&self.pool)
            .await
            .map_err(db)?
            .rows_affected();
        Ok(deleted > 0)
    }

    async fn monitor_claim_due(
        &self,
        now: Timestamp,
        lease_until: Timestamp,
        limit: u32,
    ) -> IntelResult<Vec<MonitorRecord>> {
        let _timer = self.query_timer("intel.monitor_claim_due");
        // One atomic statement: competing tickers skip rows another ticker holds locked, and a
        // row claimed by a committed ticker no longer satisfies the `claimed_until` predicate.
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE monitors SET claimed_until = $2 \
         WHERE monitor_id IN ( \
           SELECT monitor_id FROM monitors \
           WHERE status = 'active' AND next_run_at <= $1 AND (claimed_until IS NULL OR claimed_until <= $1) \
           ORDER BY next_run_at, monitor_id \
           LIMIT $3 \
           FOR UPDATE SKIP LOCKED) \
         RETURNING {MONITOR_COLS}"
        )))
        .bind(now)
        .bind(lease_until)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut claimed = rows
            .iter()
            .map(monitor_from_row)
            .collect::<Result<Vec<MonitorRecord>, StoreError>>()?;
        // RETURNING order is unspecified; callers get oldest-due first.
        claimed.sort_by_key(|m| (m.next_run_at, m.id));
        Ok(claimed)
    }

    async fn monitor_finish_run(
        &self,
        tenant: TenantId,
        id: Uuid,
        last_run_at: Timestamp,
        last_check_id: Uuid,
        next_run_at: Option<Timestamp>,
    ) -> IntelResult<()> {
        let _timer = self.query_timer("intel.monitor_finish_run");
        // A monitor deleted while its check ran matches no row: nothing to record.
        sqlx::query(
            "UPDATE monitors SET last_run_at = $3, last_check_id = $4, next_run_at = $5, claimed_until = NULL \
             WHERE monitor_id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant.0)
        .bind(last_run_at)
        .bind(last_check_id)
        .bind(next_run_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn check_insert(&self, c: &CheckRecord) -> IntelResult<()> {
        let _timer = self.query_timer("intel.check_insert");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO monitor_checks ({CHECK_COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
        )))
        .bind(c.id)
        .bind(c.monitor)
        .bind(c.tenant.0)
        .bind(&c.trigger)
        .bind(c.state.as_str())
        .bind(c.status.as_deref())
        .bind(&c.summary)
        .bind(c.error.as_deref())
        .bind(c.started_at)
        .bind(c.finished_at)
        .bind(c.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn check_update(&self, c: &CheckRecord) -> IntelResult<bool> {
        let _timer = self.query_timer("intel.check_update");
        let updated = sqlx::query(
            "UPDATE monitor_checks SET state = $4, status = $5, summary = $6, error = $7, finished_at = $8 \
             WHERE check_id = $1 AND monitor_id = $2 AND tenant_id = $3",
        )
        .bind(c.id)
        .bind(c.monitor)
        .bind(c.tenant.0)
        .bind(c.state.as_str())
        .bind(c.status.as_deref())
        .bind(&c.summary)
        .bind(c.error.as_deref())
        .bind(c.finished_at)
        .execute(&self.pool)
        .await
        .map_err(db)?
        .rows_affected();
        Ok(updated > 0)
    }

    async fn check_get(&self, tenant: TenantId, monitor: Uuid, id: Uuid) -> IntelResult<Option<CheckRecord>> {
        let _timer = self.query_timer("intel.check_get");
        sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {CHECK_COLS} FROM monitor_checks WHERE check_id = $1 AND monitor_id = $2 AND tenant_id = $3")))
        .bind(id)
        .bind(monitor)
        .bind(tenant.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .as_ref()
        .map(check_from_row)
        .transpose()
    }

    async fn check_list(
        &self,
        tenant: TenantId,
        monitor: Uuid,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<CheckRecord>> {
        let _timer = self.query_timer("intel.check_list");
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {CHECK_COLS} FROM monitor_checks \
         WHERE monitor_id = $1 AND tenant_id = $2 AND ($3::text IS NULL OR status = $3) \
         ORDER BY started_at DESC, check_id DESC LIMIT $4 OFFSET $5"
        )))
        .bind(monitor)
        .bind(tenant.0)
        .bind(status)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(check_from_row)
        .collect()
    }

    async fn check_pages_put(&self, pages: &[CheckPage]) -> IntelResult<()> {
        let _timer = self.query_timer("intel.check_pages_put");
        // `ON CONFLICT` cannot touch one row twice in a statement: the last page per key wins,
        // as it would for sequential writes.
        let unique: BTreeMap<(Uuid, &str, &str), &CheckPage> = pages
            .iter()
            .map(|p| ((p.check, p.target_id.as_str(), p.url.as_str()), p))
            .collect();
        if unique.is_empty() {
            return Ok(());
        }
        let checks: Vec<Uuid> = unique.values().map(|p| p.check).collect();
        let targets: Vec<&str> = unique.values().map(|p| p.target_id.as_str()).collect();
        let urls: Vec<&str> = unique.values().map(|p| p.url.as_str()).collect();
        let statuses: Vec<&str> = unique.values().map(|p| p.status.as_str()).collect();
        let data: Vec<&Value> = unique.values().map(|p| &p.data).collect();
        sqlx::query(
            "INSERT INTO monitor_check_pages (check_id, target_id, url, status, data) \
             SELECT * FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::text[], $5::jsonb[]) \
             ON CONFLICT (check_id, target_id, url) DO UPDATE SET status = EXCLUDED.status, data = EXCLUDED.data",
        )
        .bind(&checks)
        .bind(&targets)
        .bind(&urls)
        .bind(&statuses)
        .bind(&data)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn check_pages(
        &self,
        check: Uuid,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<CheckPage>> {
        let _timer = self.query_timer("intel.check_pages");
        let rows = sqlx::query(
            "SELECT target_id, url, status, data FROM monitor_check_pages \
             WHERE check_id = $1 AND ($2::text IS NULL OR status = $2) \
             ORDER BY target_id, url LIMIT $3 OFFSET $4",
        )
        .bind(check)
        .bind(status)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(CheckPage {
                    check,
                    target_id: get(r, "target_id")?,
                    url: get(r, "url")?,
                    status: get(r, "status")?,
                    data: get(r, "data")?,
                })
            })
            .collect()
    }

    async fn baselines(&self, monitor: Uuid) -> IntelResult<Vec<Baseline>> {
        let _timer = self.query_timer("intel.baselines");
        let rows = sqlx::query(
            "SELECT url, digest, markdown, seen_at FROM monitor_baselines WHERE monitor_id = $1 ORDER BY url",
        )
        .bind(monitor)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(Baseline {
                    monitor,
                    url: get(r, "url")?,
                    digest: get(r, "digest")?,
                    markdown: get(r, "markdown")?,
                    seen_at: get(r, "seen_at")?,
                })
            })
            .collect()
    }

    async fn baselines_put(&self, rows: &[Baseline]) -> IntelResult<()> {
        let _timer = self.query_timer("intel.baselines_put");
        let unique: BTreeMap<(Uuid, &str), &Baseline> =
            rows.iter().map(|b| ((b.monitor, b.url.as_str()), b)).collect();
        if unique.is_empty() {
            return Ok(());
        }
        let monitors: Vec<Uuid> = unique.values().map(|b| b.monitor).collect();
        let urls: Vec<&str> = unique.values().map(|b| b.url.as_str()).collect();
        let digests: Vec<&str> = unique.values().map(|b| b.digest.as_str()).collect();
        let markdowns: Vec<&str> = unique.values().map(|b| b.markdown.as_str()).collect();
        let seen: Vec<Timestamp> = unique.values().map(|b| b.seen_at).collect();
        sqlx::query(
            "INSERT INTO monitor_baselines (monitor_id, url, digest, markdown, seen_at) \
             SELECT * FROM UNNEST($1::uuid[], $2::text[], $3::text[], $4::text[], $5::timestamptz[]) \
             ON CONFLICT (monitor_id, url) DO UPDATE SET \
               digest = EXCLUDED.digest, markdown = EXCLUDED.markdown, seen_at = EXCLUDED.seen_at",
        )
        .bind(&monitors)
        .bind(&urls)
        .bind(&digests)
        .bind(&markdowns)
        .bind(&seen)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn baselines_remove(&self, monitor: Uuid, urls: &[String]) -> IntelResult<()> {
        let _timer = self.query_timer("intel.baselines_remove");
        if urls.is_empty() {
            return Ok(());
        }
        sqlx::query("DELETE FROM monitor_baselines WHERE monitor_id = $1 AND url = ANY($2::text[])")
            .bind(monitor)
            .bind(urls)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }

    async fn usage_record(&self, e: &UsageEvent) -> IntelResult<()> {
        let _timer = self.query_timer("intel.usage_record");
        sqlx::query(
            "INSERT INTO usage_ledger (tenant_id, at, endpoint, ref_id, status, credits, prompt_tokens, \
             completion_tokens) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(e.tenant.0)
        .bind(e.at)
        .bind(&e.endpoint)
        .bind(e.ref_id)
        .bind(&e.status)
        .bind(conv::<_, i64>(e.credits, "credits")?)
        .bind(conv::<_, i64>(e.prompt_tokens, "prompt_tokens")?)
        .bind(conv::<_, i64>(e.completion_tokens, "completion_tokens")?)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn usage_totals(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<UsageTotals> {
        let _timer = self.query_timer("intel.usage_totals");
        let row = sqlx::query(
            "SELECT COALESCE(SUM(credits), 0)::bigint AS credits, \
                    COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens, \
                    COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens, \
                    count(*) AS events \
             FROM usage_ledger WHERE tenant_id = $1 AND at >= $2 AND at < $3",
        )
        .bind(tenant.0)
        .bind(from)
        .bind(to)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        totals_from_row(&row)
    }

    async fn usage_by_day(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<Vec<UsageDay>> {
        let _timer = self.query_timer("intel.usage_by_day");
        let rows = sqlx::query(
            "SELECT to_char((at AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD') AS day, \
                    COALESCE(SUM(credits), 0)::bigint AS credits, \
                    COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens, \
                    COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens, \
                    count(*) AS events \
             FROM usage_ledger WHERE tenant_id = $1 AND at >= $2 AND at < $3 \
             GROUP BY 1 ORDER BY 1",
        )
        .bind(tenant.0)
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok(UsageDay {
                    day: get(r, "day")?,
                    totals: totals_from_row(r)?,
                })
            })
            .collect()
    }

    async fn usage_recent(
        &self,
        tenant: TenantId,
        endpoint: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<UsageEvent>> {
        let _timer = self.query_timer("intel.usage_recent");
        sqlx::query(
            "SELECT tenant_id, at, endpoint, ref_id, status, credits, prompt_tokens, completion_tokens \
             FROM usage_ledger WHERE tenant_id = $1 AND ($2::text IS NULL OR endpoint = $2) \
             ORDER BY at DESC, entry_id DESC LIMIT $3 OFFSET $4",
        )
        .bind(tenant.0)
        .bind(endpoint)
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?
        .iter()
        .map(usage_from_row)
        .collect()
    }

    async fn usage_by_ref(&self, tenant: TenantId, ref_id: Uuid) -> IntelResult<Option<UsageEvent>> {
        let _timer = self.query_timer("intel.usage_by_ref");
        sqlx::query(
            "SELECT tenant_id, at, endpoint, ref_id, status, credits, prompt_tokens, completion_tokens \
             FROM usage_ledger WHERE tenant_id = $1 AND ref_id = $2 \
             ORDER BY at DESC, entry_id DESC LIMIT 1",
        )
        .bind(tenant.0)
        .bind(ref_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?
        .as_ref()
        .map(usage_from_row)
        .transpose()
    }

    async fn setting_get(&self, tenant: TenantId, key: &str) -> IntelResult<Option<Value>> {
        let _timer = self.query_timer("intel.setting_get");
        sqlx::query_scalar("SELECT value FROM tenant_settings WHERE tenant_id = $1 AND key = $2")
            .bind(tenant.0)
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)
    }

    async fn setting_put(&self, tenant: TenantId, key: &str, value: Value, at: Timestamp) -> IntelResult<()> {
        let _timer = self.query_timer("intel.setting_put");
        sqlx::query(
            "INSERT INTO tenant_settings (tenant_id, key, value, updated_at) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at",
        )
        .bind(tenant.0)
        .bind(key)
        .bind(&value)
        .bind(at)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    async fn purge_expired(&self, now: Timestamp, usage_before: Timestamp) -> IntelResult<PurgeReport> {
        let _timer = self.query_timer("intel.purge_expired");
        // Trace, snapshots and pages go with their parent rows (ON DELETE CASCADE).
        let jobs = sqlx::query("DELETE FROM intel_jobs WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db)?
            .rows_affected();
        let checks = sqlx::query("DELETE FROM monitor_checks WHERE expires_at <= $1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db)?
            .rows_affected();
        sqlx::query("DELETE FROM usage_ledger WHERE at < $1")
            .bind(usage_before)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(PurgeReport { jobs, checks })
    }
}
