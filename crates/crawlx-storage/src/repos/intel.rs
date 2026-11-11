//! SQL behind [`IntelRepo`]: the tables of migration `0016_intel.sql` (`intel_jobs`,
//! `intel_trace`, `intel_snapshots`, `intel_threads`, `monitors`, `monitor_checks`,
//! `monitor_check_pages`, `monitor_baselines`, `usage_ledger`, `tenant_settings`).
//!
//! Every statement runs under the tenancy of [`Store::scope`]: a request handle needs a tenant
//! scope, a statement that names a tenant must name the scope's, and on engines without
//! row-level security the statements of child tables (`intel_trace`, `intel_snapshots`,
//! `monitor_check_pages`, `monitor_baselines`) carry the predicate through their job, check or
//! monitor. Counters travel as `BIGINT` through checked conversions. Statements are timed as
//! `intel.<method>`.

#![deny(clippy::disallowed_methods)]

use crate::backend::strategy::{MonitorClaim, Row};
use crate::backend::{BackendKind, Dialect};
use crate::codec::{conv, parse_label};
use crate::error::not_found;
use crate::intel::{
    Baseline, CheckPage, CheckRecord, IntelRepo, IntelResult, JobCount, JobKind, JobPatch, JobRecord,
    MonitorRecord, PurgeReport, Snapshot, ThreadRecord, TraceEvent, UsageDay, UsageEvent, UsageTotals,
};
use crate::sql::{SqlRow, Stmt};
use crate::store::Store;
use crate::tenant::{Dia, Tenancy};
use async_trait::async_trait;
use crawlx_core::{StoreError, TenantId, Timestamp};
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

const JOB_COLS: &str = "job_id, tenant_id, kind, status, request, result, error, stop_reason, tokens_used, \
     credits_used, thread_id, created_at, updated_at, finished_at, expires_at";

const MONITOR_COLS: &str = "monitor_id, tenant_id, name, status, schedule, cron, timezone, goal, targets, \
     retention_days, webhook, notification, next_run_at, last_run_at, last_check_id, claimed_until, \
     created_at, updated_at";

const CHECK_COLS: &str = "check_id, monitor_id, tenant_id, trigger_kind, state, status, summary, error, \
     started_at, finished_at, expires_at";

/// `name` as an identifier: MariaDB reserves `key` and wants `at` quoted, the others take both
/// as they are.
fn ident<B: Tenancy>(name: &str) -> String {
    if B::KIND == BackendKind::MariaDb {
        format!("`{name}`")
    } else {
        name.to_owned()
    }
}

/// `expr` as a 64-bit integer: `SUM` of integers is a decimal on MariaDB.
fn as_i64<B: Tenancy>(expr: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("{expr}::bigint"),
        BackendKind::MariaDb => format!("CAST({expr} AS SIGNED)"),
        _ => expr.to_owned(),
    }
}

/// The 32-byte key of a url on MariaDB, whose text keys are too long to index.
fn url_hash(url: &str) -> [u8; 32] {
    *blake3::hash(url.as_bytes()).as_bytes()
}

fn job_from_row<R: SqlRow>(r: &R) -> Result<JobRecord, StoreError> {
    Ok(JobRecord {
        id: r.uuid("job_id")?,
        tenant: TenantId(r.uuid("tenant_id")?),
        kind: parse_label(&r.text("kind")?)?,
        status: parse_label(&r.text("status")?)?,
        request: r.json("request")?,
        result: r.opt_json("result")?,
        error: r.opt_text("error")?,
        stop_reason: r.opt_text("stop_reason")?,
        tokens_used: conv(r.i64("tokens_used")?, "tokens_used")?,
        credits_used: conv(r.i64("credits_used")?, "credits_used")?,
        thread_id: r.opt_uuid("thread_id")?,
        created_at: r.ts("created_at")?,
        updated_at: r.ts("updated_at")?,
        finished_at: r.opt_ts("finished_at")?,
        expires_at: r.ts("expires_at")?,
    })
}

fn monitor_from_row<R: SqlRow>(r: &R) -> Result<MonitorRecord, StoreError> {
    Ok(MonitorRecord {
        id: r.uuid("monitor_id")?,
        tenant: TenantId(r.uuid("tenant_id")?),
        name: r.opt_text("name")?,
        status: parse_label(&r.text("status")?)?,
        schedule: r.json("schedule")?,
        cron: r.text("cron")?,
        timezone: r.text("timezone")?,
        goal: r.opt_text("goal")?,
        targets: r.json("targets")?,
        retention_days: conv(r.i32("retention_days")?, "retention_days")?,
        webhook: r.opt_json("webhook")?,
        notification: r.json("notification")?,
        next_run_at: r.opt_ts("next_run_at")?,
        last_run_at: r.opt_ts("last_run_at")?,
        last_check_id: r.opt_uuid("last_check_id")?,
        claimed_until: r.opt_ts("claimed_until")?,
        created_at: r.ts("created_at")?,
        updated_at: r.ts("updated_at")?,
    })
}

fn check_from_row<R: SqlRow>(r: &R) -> Result<CheckRecord, StoreError> {
    Ok(CheckRecord {
        id: r.uuid("check_id")?,
        monitor: r.uuid("monitor_id")?,
        tenant: TenantId(r.uuid("tenant_id")?),
        trigger: r.text("trigger_kind")?,
        state: parse_label(&r.text("state")?)?,
        status: r.opt_text("status")?,
        summary: r.json("summary")?,
        error: r.opt_text("error")?,
        started_at: r.ts("started_at")?,
        finished_at: r.opt_ts("finished_at")?,
        expires_at: r.ts("expires_at")?,
    })
}

fn usage_from_row<R: SqlRow>(r: &R) -> Result<UsageEvent, StoreError> {
    Ok(UsageEvent {
        tenant: TenantId(r.uuid("tenant_id")?),
        at: r.ts("at")?,
        endpoint: r.text("endpoint")?,
        ref_id: r.opt_uuid("ref_id")?,
        status: r.text("status")?,
        credits: conv(r.i64("credits")?, "credits")?,
        prompt_tokens: conv(r.i64("prompt_tokens")?, "prompt_tokens")?,
        completion_tokens: conv(r.i64("completion_tokens")?, "completion_tokens")?,
    })
}

fn totals_from_row<R: SqlRow>(r: &R) -> Result<UsageTotals, StoreError> {
    Ok(UsageTotals {
        credits: conv(r.i64("credits")?, "credits")?,
        prompt_tokens: conv(r.i64("prompt_tokens")?, "prompt_tokens")?,
        completion_tokens: conv(r.i64("completion_tokens")?, "completion_tokens")?,
        events: conv(r.i64("events")?, "events")?,
    })
}

/// A sequence cursor that no stored row can exceed when `after` does not fit a `BIGINT`.
fn seq_cursor(after: u64) -> i64 {
    i64::try_from(after).unwrap_or(i64::MAX)
}

/// The calendar day (UTC, `YYYY-MM-DD`) of the timestamp column `col`.
fn day_of<B: Tenancy>(col: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!("to_char(({col} AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD')"),
        BackendKind::MariaDb => format!("DATE_FORMAT({col}, '%Y-%m-%d')"),
        _ => format!("strftime('%Y-%m-%d', {col} / 1000000, 'unixepoch')"),
    }
}

/// `text` of the placeholders `$first ..` for `count` values, comma separated.
fn placeholders(first: usize, count: usize) -> String {
    (first..first + count)
        .map(|n| format!("${n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[async_trait]
impl<B: Tenancy> IntelRepo for Store<B>
where
    Row<B>: SqlRow,
{
    async fn job_insert(&self, job: &JobRecord) -> IntelResult<()> {
        let _timer = self.query_timer("intel.job_insert");
        let scope = self.scope()?;
        scope.authorize(job.tenant)?;
        scope
            .query(
                "intel_jobs",
                Stmt::<B>::dynamic(
                    "INSERT INTO intel_jobs (job_id, tenant_id, kind, status, request, result, error, stop_reason, \
                     tokens_used, credits_used, thread_id, created_at, updated_at, finished_at, expires_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
                )
                .uuid(job.id)
                .uuid(job.tenant.0)
                .text(job.kind.as_str())
                .text(job.status.as_str())
                .json(&job.request)
                .opt_json(job.result.as_ref())
                .opt_text(job.error.as_deref())
                .opt_text(job.stop_reason.as_deref())
                .i64(conv::<_, i64>(job.tokens_used, "tokens_used")?)
                .i64(conv::<_, i64>(job.credits_used, "credits_used")?)
                .opt_uuid(job.thread_id)
                .ts(job.created_at)
                .ts(job.updated_at)
                .opt_ts(job.finished_at)
                .ts(job.expires_at),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(())
    }

    async fn job_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<JobRecord>> {
        let _timer = self.query_timer("intel.job_get");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let sql = format!("SELECT {JOB_COLS} FROM intel_jobs WHERE job_id = $1 AND tenant_id = $2");
        scope
            .query("intel_jobs", Stmt::<B>::dynamic(&sql).uuid(id).uuid(tenant.0))?
            .fetch_optional_pool(&self.pool)
            .await?
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
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
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
        // MariaDB evaluates assignments left to right against the row as already changed, so
        // there `status` is assigned last: every other column still sees the old status.
        let status =
            "status = CASE WHEN status = 'processing' THEN COALESCE($4::text, status) ELSE status END";
        let others = "result = CASE WHEN status = 'processing' THEN COALESCE($5::jsonb, result) ELSE result END, \
           error = CASE WHEN status = 'processing' THEN COALESCE($6::text, error) ELSE error END, \
           stop_reason = CASE WHEN status = 'processing' THEN COALESCE($7::text, stop_reason) ELSE stop_reason END, \
           tokens_used = COALESCE($8::bigint, tokens_used), \
           credits_used = COALESCE($9::bigint, credits_used), \
           finished_at = CASE WHEN status = 'processing' THEN COALESCE($10::timestamptz, finished_at) ELSE finished_at END";
        let assignments = if B::KIND == BackendKind::MariaDb {
            format!("updated_at = $3, {others}, {status}")
        } else {
            format!("updated_at = $3, {status}, {others}")
        };
        let update = format!("UPDATE intel_jobs SET {assignments} WHERE job_id = $1 AND tenant_id = $2");
        let bound = |sql: &str| {
            scope.query(
                "intel_jobs",
                Stmt::<B>::dynamic(sql)
                    .uuid(id)
                    .uuid(tenant.0)
                    .ts(patch.at)
                    .opt_text(patch.status.map(|s| s.as_str()))
                    .opt_json(patch.result.as_ref())
                    .opt_text(patch.error.as_deref())
                    .opt_text(patch.stop_reason.as_deref())
                    .opt_i64(tokens)
                    .opt_i64(credits)
                    .opt_ts(patch.finished_at),
            )
        };
        if <Dia<B> as Dialect>::UPDATE_RETURNING {
            let sql = format!("{update} RETURNING {JOB_COLS}");
            return bound(&sql)?
                .fetch_optional_write(&self.pool)
                .await?
                .as_ref()
                .map(job_from_row)
                .transpose();
        }
        let mut tx = self.begin_write().await?;
        let changed = bound(&update)?.execute(tx.conn()).await?;
        let record = if changed == 0 {
            None
        } else {
            let sql = format!("SELECT {JOB_COLS} FROM intel_jobs WHERE job_id = $1 AND tenant_id = $2");
            scope
                .query("intel_jobs", Stmt::<B>::dynamic(&sql).uuid(id).uuid(tenant.0))?
                .fetch_optional(tx.conn())
                .await?
                .as_ref()
                .map(job_from_row)
                .transpose()?
        };
        tx.commit().await?;
        Ok(record)
    }

    async fn job_list(
        &self,
        tenant: TenantId,
        kind: Option<JobKind>,
        limit: u32,
        after: Option<(Timestamp, Uuid)>,
    ) -> IntelResult<Vec<JobRecord>> {
        let _timer = self.query_timer("intel.job_list");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {JOB_COLS} FROM intel_jobs \
         WHERE tenant_id = $1 \
           AND ($2::text IS NULL OR kind = $2) \
           AND ($3::timestamptz IS NULL OR (created_at, job_id) < ($3::timestamptz, $4::uuid)) \
         ORDER BY created_at DESC, job_id DESC \
         LIMIT $5"
        );
        scope
            .query(
                "intel_jobs",
                Stmt::<B>::dynamic(&sql)
                    .uuid(tenant.0)
                    .opt_text(kind.map(JobKind::as_str))
                    .opt_ts(after.map(|(at, _)| at))
                    .opt_uuid(after.map(|(_, id)| id))
                    .i64(i64::from(limit)),
            )?
            .fetch_all_pool(&self.pool)
            .await?
            .iter()
            .map(job_from_row)
            .collect()
    }

    async fn job_counts(&self, tenant: TenantId) -> IntelResult<Vec<JobCount>> {
        let _timer = self.query_timer("intel.job_counts");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(Vec::new());
        }
        let rows = scope
            .query(
                "intel_jobs",
                Stmt::<B>::dynamic(
                    "SELECT kind, status, count(*) AS n FROM intel_jobs WHERE tenant_id = $1 GROUP BY kind, status",
                )
                .uuid(tenant.0),
            )?
            .fetch_all_pool(&self.pool)
            .await?;
        let mut counts = rows
            .iter()
            .map(|r| {
                Ok(JobCount {
                    kind: parse_label(&r.text("kind")?)?,
                    status: parse_label(&r.text("status")?)?,
                    count: conv(r.i64("n")?, "count")?,
                })
            })
            .collect::<Result<Vec<JobCount>, StoreError>>()?;
        counts.sort_by_key(|c| (c.kind, c.status));
        Ok(counts)
    }

    async fn trace_append(&self, job: Uuid, kind: &str, data: Value, at: Timestamp) -> IntelResult<u64> {
        let _timer = self.query_timer("intel.trace_append");
        let scope = self.scope()?;
        let owned = scope.and("intel_jobs", "", 5)?;
        let at_col = ident::<B>("at");
        let seq: Option<i64> = if B::KIND == BackendKind::Postgres {
            // One statement: the counter bump takes the job's row lock, so concurrent appenders get
            // distinct, gap-free numbers in commit order.
            let sql = format!(
                "WITH bumped AS (UPDATE intel_jobs SET trace_seq = trace_seq + 1 WHERE job_id = $1{owned} \
                                 RETURNING job_id, trace_seq) \
                 INSERT INTO intel_trace (job_id, seq, kind, data, {at_col}) \
                 SELECT job_id, trace_seq, $2::text, $3::jsonb, $4::timestamptz FROM bumped \
                 RETURNING seq"
            );
            scope
                .bind(Stmt::<B>::dynamic(&sql).uuid(job).text(kind).json(&data).ts(at))
                .fetch_optional_write(&self.pool)
                .await?
                .map(|r| r.i64("seq"))
                .transpose()?
        } else {
            // The same two steps in one write transaction: the bump holds the job's row (or the
            // database write lock) until the trace row is in, so appenders stay gap-free.
            let mut tx = self.begin_write().await?;
            let bump = format!("UPDATE intel_jobs SET trace_seq = trace_seq + 1 WHERE job_id = $1{owned}");
            let bumped = scope
                .bind(Stmt::<B>::dynamic(&bump).uuid(job))
                .execute(tx.conn())
                .await?;
            let seq = if bumped == 0 {
                None
            } else {
                scope
                    .query(
                        "intel_jobs",
                        Stmt::<B>::dynamic("SELECT trace_seq AS seq FROM intel_jobs WHERE job_id = $1")
                            .uuid(job),
                    )?
                    .fetch_optional(tx.conn())
                    .await?
                    .map(|r| r.i64("seq"))
                    .transpose()?
            };
            if let Some(seq) = seq {
                let insert = format!(
                    "INSERT INTO intel_trace (job_id, seq, kind, data, {at_col}) VALUES ($1, $2, $3, $4, $5)"
                );
                scope
                    .query(
                        "intel_trace",
                        Stmt::<B>::dynamic(&insert)
                            .uuid(job)
                            .i64(seq)
                            .text(kind)
                            .json(&data)
                            .ts(at),
                    )?
                    .execute(tx.conn())
                    .await?;
            }
            tx.commit().await?;
            seq
        };
        let seq = seq.ok_or_else(|| not_found("job", job))?;
        conv(seq, "seq")
    }

    async fn trace_list(&self, job: Uuid, after: u64, limit: u32) -> IntelResult<Vec<TraceEvent>> {
        let _timer = self.query_timer("intel.trace_list");
        let scope = self.scope()?;
        let at_col = ident::<B>("at");
        let sql = format!(
            "SELECT seq, kind, data, {at_col} AS at FROM intel_trace WHERE job_id = $1 AND seq > $2{} ORDER BY seq LIMIT $3",
            scope.and("intel_trace", "", 4)?
        );
        let rows = scope
            .bind(
                Stmt::<B>::dynamic(&sql)
                    .uuid(job)
                    .i64(seq_cursor(after))
                    .i64(i64::from(limit)),
            )
            .fetch_all_pool(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(TraceEvent {
                    job,
                    seq: conv(r.i64("seq")?, "seq")?,
                    kind: r.text("kind")?,
                    data: r.json("data")?,
                    at: r.ts("at")?,
                })
            })
            .collect()
    }

    async fn snapshot_put(&self, job: Uuid, id: &str, data: Value, at: Timestamp) -> IntelResult<()> {
        let _timer = self.query_timer("intel.snapshot_put");
        let scope = self.scope()?;
        // Replacing keeps `ordinal`, so a snapshot stays at its first-creation position.
        let sql = format!(
            "INSERT INTO intel_snapshots (job_id, snapshot_id, data, created_at) \
             SELECT job_id, $2::text, $3::jsonb, $4::timestamptz FROM intel_jobs WHERE job_id = $1{} {}",
            scope.and("intel_jobs", "", 5)?,
            Dia::<B>::upsert_update(&["job_id", "snapshot_id"], &["data", "created_at"], None)
        );
        let written = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(job).text(id).json(&data).ts(at))
            .execute_write(&self.pool)
            .await?;
        if written == 0 {
            return Err(not_found("job", job));
        }
        Ok(())
    }

    async fn snapshot_get(&self, job: Uuid, id: &str) -> IntelResult<Option<Snapshot>> {
        let _timer = self.query_timer("intel.snapshot_get");
        let scope = self.scope()?;
        let sql = format!(
            "SELECT data, created_at FROM intel_snapshots WHERE job_id = $1 AND snapshot_id = $2{}",
            scope.and("intel_snapshots", "", 3)?
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(job).text(id))
            .fetch_optional_pool(&self.pool)
            .await?;
        row.map(|r| {
            Ok(Snapshot {
                job,
                id: id.to_owned(),
                data: r.json("data")?,
                created_at: r.ts("created_at")?,
            })
        })
        .transpose()
    }

    async fn snapshot_ids(&self, job: Uuid) -> IntelResult<Vec<String>> {
        let _timer = self.query_timer("intel.snapshot_ids");
        let scope = self.scope()?;
        let sql = format!(
            "SELECT snapshot_id FROM intel_snapshots WHERE job_id = $1{} ORDER BY ordinal",
            scope.and("intel_snapshots", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(job))
            .fetch_all_pool(&self.pool)
            .await?;
        rows.iter().map(|r| r.text("snapshot_id")).collect()
    }

    async fn thread_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<ThreadRecord>> {
        let _timer = self.query_timer("intel.thread_get");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let row = scope
            .query(
                "intel_threads",
                Stmt::<B>::dynamic(
                    "SELECT state, created_at, updated_at FROM intel_threads WHERE thread_id = $1 AND tenant_id = $2",
                )
                .uuid(id)
                .uuid(tenant.0),
            )?
            .fetch_optional_pool(&self.pool)
            .await?;
        row.map(|r| {
            Ok(ThreadRecord {
                id,
                tenant,
                state: r.json("state")?,
                created_at: r.ts("created_at")?,
                updated_at: r.ts("updated_at")?,
            })
        })
        .transpose()
    }

    async fn thread_put(&self, tenant: TenantId, id: Uuid, state: Value, at: Timestamp) -> IntelResult<()> {
        let _timer = self.query_timer("intel.thread_put");
        let scope = self.scope()?;
        scope.authorize(tenant)?;
        let taken = || StoreError::Conflict(format!("thread {id} belongs to another tenant"));
        if B::KIND == BackendKind::MariaDb {
            // `ON DUPLICATE KEY UPDATE` cannot say whether the row was left alone (a match counts
            // as affected), so the owner is read under the row lock first.
            let mut tx = self.begin_write().await?;
            let owner = scope
                .query(
                    "intel_threads",
                    Stmt::<B>::dynamic("SELECT tenant_id FROM intel_threads WHERE thread_id = $1 FOR UPDATE")
                        .uuid(id),
                )?
                .fetch_optional(tx.conn())
                .await?
                .map(|r| r.uuid("tenant_id"))
                .transpose()?;
            match owner {
                Some(owner) if owner != tenant.0 => return Err(taken()),
                Some(_) => {
                    scope
                        .query(
                            "intel_threads",
                            Stmt::<B>::dynamic(
                                "UPDATE intel_threads SET state = $2, updated_at = $3 WHERE thread_id = $1 AND tenant_id = $4",
                            )
                            .uuid(id)
                            .json(&state)
                            .ts(at)
                            .uuid(tenant.0),
                        )?
                        .execute(tx.conn())
                        .await?;
                }
                None => {
                    scope
                        .query(
                            "intel_threads",
                            Stmt::<B>::dynamic(
                                "INSERT INTO intel_threads (thread_id, tenant_id, state, created_at, updated_at) \
                                 VALUES ($1, $2, $3, $4, $4)",
                            )
                            .uuid(id)
                            .uuid(tenant.0)
                            .json(&state)
                            .ts(at),
                        )?
                        .execute(tx.conn())
                        .await?;
                }
            }
            return tx.commit().await;
        }
        // The conflict branch only fires for the owning tenant; a foreign row affects nothing.
        let sql = format!(
            "INSERT INTO intel_threads (thread_id, tenant_id, state, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $4) {}",
            Dia::<B>::upsert_update(
                &["thread_id"],
                &["state", "updated_at"],
                Some(&format!(
                    "intel_threads.tenant_id = {}",
                    Dia::<B>::excluded("tenant_id")
                ))
            )
        );
        let written = scope
            .query(
                "intel_threads",
                Stmt::<B>::dynamic(&sql)
                    .uuid(id)
                    .uuid(tenant.0)
                    .json(&state)
                    .ts(at),
            )?
            .execute_write(&self.pool)
            .await?;
        if written == 0 {
            return Err(taken());
        }
        Ok(())
    }

    async fn monitor_insert(&self, m: &MonitorRecord) -> IntelResult<()> {
        let _timer = self.query_timer("intel.monitor_insert");
        let scope = self.scope()?;
        scope.authorize(m.tenant)?;
        let sql = format!(
            "INSERT INTO monitors ({MONITOR_COLS}) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)"
        );
        scope
            .query(
                "monitors",
                Stmt::<B>::dynamic(&sql)
                    .uuid(m.id)
                    .uuid(m.tenant.0)
                    .opt_text(m.name.as_deref())
                    .text(m.status.as_str())
                    .json(&m.schedule)
                    .text(&m.cron)
                    .text(&m.timezone)
                    .opt_text(m.goal.as_deref())
                    .json(&m.targets)
                    .i32(conv::<_, i32>(m.retention_days, "retention_days")?)
                    .opt_json(m.webhook.as_ref())
                    .json(&m.notification)
                    .opt_ts(m.next_run_at)
                    .opt_ts(m.last_run_at)
                    .opt_uuid(m.last_check_id)
                    .opt_ts(m.claimed_until)
                    .ts(m.created_at)
                    .ts(m.updated_at),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(())
    }

    async fn monitor_update(&self, m: &MonitorRecord) -> IntelResult<bool> {
        let _timer = self.query_timer("intel.monitor_update");
        let scope = self.scope()?;
        if !scope.sees(m.tenant) {
            return Ok(false);
        }
        // Scheduling state (`last_run_at`, `last_check_id`, `claimed_until`) is owned by
        // `monitor_claim_due` / `monitor_finish_run`; a PATCH that read the row before a claim
        // must not release the lease.
        let updated = scope
            .query(
                "monitors",
                Stmt::<B>::dynamic(
                    "UPDATE monitors SET name = $3, status = $4, schedule = $5, cron = $6, timezone = $7, goal = $8, \
                       targets = $9, retention_days = $10, webhook = $11, notification = $12, next_run_at = $13, \
                       updated_at = $14 \
                     WHERE monitor_id = $1 AND tenant_id = $2",
                )
                .uuid(m.id)
                .uuid(m.tenant.0)
                .opt_text(m.name.as_deref())
                .text(m.status.as_str())
                .json(&m.schedule)
                .text(&m.cron)
                .text(&m.timezone)
                .opt_text(m.goal.as_deref())
                .json(&m.targets)
                .i32(conv::<_, i32>(m.retention_days, "retention_days")?)
                .opt_json(m.webhook.as_ref())
                .json(&m.notification)
                .opt_ts(m.next_run_at)
                .ts(m.updated_at),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(updated > 0)
    }

    async fn monitor_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<MonitorRecord>> {
        let _timer = self.query_timer("intel.monitor_get");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let sql = format!("SELECT {MONITOR_COLS} FROM monitors WHERE monitor_id = $1 AND tenant_id = $2");
        scope
            .query("monitors", Stmt::<B>::dynamic(&sql).uuid(id).uuid(tenant.0))?
            .fetch_optional_pool(&self.pool)
            .await?
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
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {MONITOR_COLS} FROM monitors WHERE tenant_id = $1 \
         ORDER BY created_at DESC, monitor_id DESC LIMIT $2 OFFSET $3"
        );
        scope
            .query(
                "monitors",
                Stmt::<B>::dynamic(&sql)
                    .uuid(tenant.0)
                    .i64(i64::from(limit))
                    .i64(i64::from(offset)),
            )?
            .fetch_all_pool(&self.pool)
            .await?
            .iter()
            .map(monitor_from_row)
            .collect()
    }

    async fn monitor_count(&self, tenant: TenantId) -> IntelResult<u64> {
        let _timer = self.query_timer("intel.monitor_count");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(0);
        }
        let row = scope
            .query(
                "monitors",
                Stmt::<B>::dynamic("SELECT count(*) AS v FROM monitors WHERE tenant_id = $1").uuid(tenant.0),
            )?
            .fetch_one_pool(&self.pool)
            .await?;
        conv(row.i64("v")?, "count")
    }

    async fn monitor_delete(&self, tenant: TenantId, id: Uuid) -> IntelResult<bool> {
        let _timer = self.query_timer("intel.monitor_delete");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(false);
        }
        // Checks, their pages and the baselines go with the monitor (ON DELETE CASCADE).
        let deleted = scope
            .query(
                "monitors",
                Stmt::<B>::dynamic("DELETE FROM monitors WHERE monitor_id = $1 AND tenant_id = $2")
                    .uuid(id)
                    .uuid(tenant.0),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(deleted > 0)
    }

    async fn monitor_claim_due(
        &self,
        now: Timestamp,
        lease_until: Timestamp,
        limit: u32,
    ) -> IntelResult<Vec<MonitorRecord>> {
        let _timer = self.query_timer("intel.monitor_claim_due");
        // The claim spans tenants: only the ticker's operator handle may run it.
        self.require_operator()?;
        let rows = B::claim_monitors(
            &self.pool,
            MonitorClaim {
                now,
                lease_until,
                limit: i64::from(limit),
                columns: MONITOR_COLS,
            },
        )
        .await?;
        let mut claimed = rows
            .iter()
            .map(monitor_from_row)
            .collect::<Result<Vec<MonitorRecord>, StoreError>>()?;
        // Row order is unspecified; callers get oldest-due first.
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
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(());
        }
        // A monitor deleted while its check ran matches no row: nothing to record.
        scope
            .query(
                "monitors",
                Stmt::<B>::dynamic(
                    "UPDATE monitors SET last_run_at = $3, last_check_id = $4, next_run_at = $5, claimed_until = NULL \
                     WHERE monitor_id = $1 AND tenant_id = $2",
                )
                .uuid(id)
                .uuid(tenant.0)
                .ts(last_run_at)
                .uuid(last_check_id)
                .opt_ts(next_run_at),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(())
    }

    async fn check_insert(&self, c: &CheckRecord) -> IntelResult<()> {
        let _timer = self.query_timer("intel.check_insert");
        let scope = self.scope()?;
        scope.authorize(c.tenant)?;
        let sql = format!(
            "INSERT INTO monitor_checks ({CHECK_COLS}) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
        );
        scope
            .query(
                "monitor_checks",
                Stmt::<B>::dynamic(&sql)
                    .uuid(c.id)
                    .uuid(c.monitor)
                    .uuid(c.tenant.0)
                    .text(&c.trigger)
                    .text(c.state.as_str())
                    .opt_text(c.status.as_deref())
                    .json(&c.summary)
                    .opt_text(c.error.as_deref())
                    .ts(c.started_at)
                    .opt_ts(c.finished_at)
                    .ts(c.expires_at),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(())
    }

    async fn check_update(&self, c: &CheckRecord) -> IntelResult<bool> {
        let _timer = self.query_timer("intel.check_update");
        let scope = self.scope()?;
        if !scope.sees(c.tenant) {
            return Ok(false);
        }
        let updated = scope
            .query(
                "monitor_checks",
                Stmt::<B>::dynamic(
                    "UPDATE monitor_checks SET state = $4, status = $5, summary = $6, error = $7, finished_at = $8 \
                     WHERE check_id = $1 AND monitor_id = $2 AND tenant_id = $3",
                )
                .uuid(c.id)
                .uuid(c.monitor)
                .uuid(c.tenant.0)
                .text(c.state.as_str())
                .opt_text(c.status.as_deref())
                .json(&c.summary)
                .opt_text(c.error.as_deref())
                .opt_ts(c.finished_at),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(updated > 0)
    }

    async fn check_get(&self, tenant: TenantId, monitor: Uuid, id: Uuid) -> IntelResult<Option<CheckRecord>> {
        let _timer = self.query_timer("intel.check_get");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let sql = format!(
            "SELECT {CHECK_COLS} FROM monitor_checks WHERE check_id = $1 AND monitor_id = $2 AND tenant_id = $3"
        );
        scope
            .query(
                "monitor_checks",
                Stmt::<B>::dynamic(&sql).uuid(id).uuid(monitor).uuid(tenant.0),
            )?
            .fetch_optional_pool(&self.pool)
            .await?
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
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {CHECK_COLS} FROM monitor_checks \
         WHERE monitor_id = $1 AND tenant_id = $2 AND ($3::text IS NULL OR status = $3) \
         ORDER BY started_at DESC, check_id DESC LIMIT $4 OFFSET $5"
        );
        scope
            .query(
                "monitor_checks",
                Stmt::<B>::dynamic(&sql)
                    .uuid(monitor)
                    .uuid(tenant.0)
                    .opt_text(status)
                    .i64(i64::from(limit))
                    .i64(i64::from(offset)),
            )?
            .fetch_all_pool(&self.pool)
            .await?
            .iter()
            .map(check_from_row)
            .collect()
    }

    async fn check_pages_put(&self, pages: &[CheckPage]) -> IntelResult<()> {
        let _timer = self.query_timer("intel.check_pages_put");
        let scope = self.scope()?;
        // `ON CONFLICT` cannot touch one row twice in a statement: the last page per key wins,
        // as it would for sequential writes.
        let unique: BTreeMap<(Uuid, &str, &str), &CheckPage> = pages
            .iter()
            .map(|p| ((p.check, p.target_id.as_str(), p.url.as_str()), p))
            .collect();
        if unique.is_empty() {
            return Ok(());
        }
        let maria = B::KIND == BackendKind::MariaDb;
        let (columns, key): (&[&str], &[&str]) = if maria {
            (
                &["check_id", "target_id", "url", "url_hash", "status", "data"],
                &["check_id", "target_id", "url_hash"],
            )
        } else {
            (
                &["check_id", "target_id", "url", "status", "data"],
                &["check_id", "target_id", "url"],
            )
        };
        let rows: Vec<&&CheckPage> = unique.values().collect();
        let mut tx = self.begin_write().await?;
        self.require_owned_checks(&scope, &mut tx, rows.iter().map(|p| p.check))
            .await?;
        let width = columns.len();
        let upsert = Dia::<B>::upsert_update(key, &["status", "data"], None);
        for chunk in rows.chunks(Dia::<B>::max_batch_rows(width).max(1)) {
            let values = (0..chunk.len())
                .map(|row| format!("({})", placeholders(row * width + 1, width)))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO monitor_check_pages ({}) VALUES {values} {upsert}",
                columns.join(", ")
            );
            let hashes: Vec<[u8; 32]> = chunk.iter().map(|p| url_hash(&p.url)).collect();
            let mut stmt = Stmt::<B>::dynamic(&sql);
            for (page, hash) in chunk.iter().zip(&hashes) {
                stmt = stmt.uuid(page.check).text(&page.target_id).text(&page.url);
                if maria {
                    stmt = stmt.bytes(hash.as_slice());
                }
                stmt = stmt.text(&page.status).json(&page.data);
            }
            scope
                .query("monitor_check_pages", stmt)?
                .execute(tx.conn())
                .await?;
        }
        tx.commit().await
    }

    async fn check_pages(
        &self,
        check: Uuid,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<CheckPage>> {
        let _timer = self.query_timer("intel.check_pages");
        let scope = self.scope()?;
        let order = if B::KIND == BackendKind::MariaDb {
            // LONGTEXT sorts on its first bytes only; the key breaks the tie
            "target_id, url, url_hash"
        } else {
            "target_id, url"
        };
        let sql = format!(
            "SELECT target_id, url, status, data FROM monitor_check_pages \
             WHERE check_id = $1 AND ($2::text IS NULL OR status = $2){} \
             ORDER BY {order} LIMIT $3 OFFSET $4",
            scope.and("monitor_check_pages", "", 5)?
        );
        let rows = scope
            .bind(
                Stmt::<B>::dynamic(&sql)
                    .uuid(check)
                    .opt_text(status)
                    .i64(i64::from(limit))
                    .i64(i64::from(offset)),
            )
            .fetch_all_pool(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(CheckPage {
                    check,
                    target_id: r.text("target_id")?,
                    url: r.text("url")?,
                    status: r.text("status")?,
                    data: r.json("data")?,
                })
            })
            .collect()
    }

    async fn baselines(&self, monitor: Uuid) -> IntelResult<Vec<Baseline>> {
        let _timer = self.query_timer("intel.baselines");
        let scope = self.scope()?;
        let order = if B::KIND == BackendKind::MariaDb {
            "url, url_hash"
        } else {
            "url"
        };
        let sql = format!(
            "SELECT url, digest, markdown, seen_at FROM monitor_baselines WHERE monitor_id = $1{} ORDER BY {order}",
            scope.and("monitor_baselines", "", 2)?
        );
        let rows = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(monitor))
            .fetch_all_pool(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(Baseline {
                    monitor,
                    url: r.text("url")?,
                    digest: r.text("digest")?,
                    markdown: r.text("markdown")?,
                    seen_at: r.ts("seen_at")?,
                })
            })
            .collect()
    }

    async fn baselines_put(&self, rows: &[Baseline]) -> IntelResult<()> {
        let _timer = self.query_timer("intel.baselines_put");
        let scope = self.scope()?;
        let unique: BTreeMap<(Uuid, &str), &Baseline> =
            rows.iter().map(|b| ((b.monitor, b.url.as_str()), b)).collect();
        if unique.is_empty() {
            return Ok(());
        }
        let maria = B::KIND == BackendKind::MariaDb;
        let (columns, key): (&[&str], &[&str]) = if maria {
            (
                &["monitor_id", "url", "url_hash", "digest", "markdown", "seen_at"],
                &["monitor_id", "url_hash"],
            )
        } else {
            (
                &["monitor_id", "url", "digest", "markdown", "seen_at"],
                &["monitor_id", "url"],
            )
        };
        let rows: Vec<&&Baseline> = unique.values().collect();
        let mut tx = self.begin_write().await?;
        self.require_owned_monitors(&scope, &mut tx, rows.iter().map(|b| b.monitor))
            .await?;
        let width = columns.len();
        let upsert = Dia::<B>::upsert_update(key, &["digest", "markdown", "seen_at"], None);
        for chunk in rows.chunks(Dia::<B>::max_batch_rows(width).max(1)) {
            let values = (0..chunk.len())
                .map(|row| format!("({})", placeholders(row * width + 1, width)))
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!(
                "INSERT INTO monitor_baselines ({}) VALUES {values} {upsert}",
                columns.join(", ")
            );
            let hashes: Vec<[u8; 32]> = chunk.iter().map(|b| url_hash(&b.url)).collect();
            let mut stmt = Stmt::<B>::dynamic(&sql);
            for (row, hash) in chunk.iter().zip(&hashes) {
                stmt = stmt.uuid(row.monitor).text(&row.url);
                if maria {
                    stmt = stmt.bytes(hash.as_slice());
                }
                stmt = stmt.text(&row.digest).text(&row.markdown).ts(row.seen_at);
            }
            scope.query("monitor_baselines", stmt)?.execute(tx.conn()).await?;
        }
        tx.commit().await
    }

    async fn baselines_remove(&self, monitor: Uuid, urls: &[String]) -> IntelResult<()> {
        let _timer = self.query_timer("intel.baselines_remove");
        let scope = self.scope()?;
        if urls.is_empty() {
            return Ok(());
        }
        if B::KIND == BackendKind::Postgres {
            let sql = format!(
                "DELETE FROM monitor_baselines WHERE monitor_id = $1 AND url = ANY($2::text[]){}",
                scope.and("monitor_baselines", "", 3)?
            );
            scope
                .bind(Stmt::<B>::dynamic(&sql).uuid(monitor).text_list(urls))
                .execute_write(&self.pool)
                .await?;
            return Ok(());
        }
        let maria = B::KIND == BackendKind::MariaDb;
        let hashes: Vec<[u8; 32]> = urls.iter().map(|url| url_hash(url)).collect();
        let step = Dia::<B>::MAX_BIND_PARAMS.saturating_sub(2).max(1);
        let mut tx = self.begin_write().await?;
        for (chunk, hash_chunk) in urls.chunks(step).zip(hashes.chunks(step)) {
            let list = placeholders(2, chunk.len());
            let owned = scope.and("monitor_baselines", "", 2 + chunk.len())?;
            let column = if maria { "url_hash" } else { "url" };
            let sql = format!(
                "DELETE FROM monitor_baselines WHERE monitor_id = $1 AND {column} IN ({list}){owned}"
            );
            let mut stmt = Stmt::<B>::dynamic(&sql).uuid(monitor);
            for (url, hash) in chunk.iter().zip(hash_chunk) {
                stmt = if maria {
                    stmt.bytes(hash.as_slice())
                } else {
                    stmt.text(url)
                };
            }
            scope.bind(stmt).execute(tx.conn()).await?;
        }
        tx.commit().await
    }

    async fn usage_record(&self, e: &UsageEvent) -> IntelResult<()> {
        let _timer = self.query_timer("intel.usage_record");
        let scope = self.scope()?;
        scope.authorize(e.tenant)?;
        let at_col = ident::<B>("at");
        let sql = format!(
            "INSERT INTO usage_ledger (tenant_id, {at_col}, endpoint, ref_id, status, credits, prompt_tokens, \
             completion_tokens) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        );
        scope
            .query(
                "usage_ledger",
                Stmt::<B>::dynamic(&sql)
                    .uuid(e.tenant.0)
                    .ts(e.at)
                    .text(&e.endpoint)
                    .opt_uuid(e.ref_id)
                    .text(&e.status)
                    .i64(conv::<_, i64>(e.credits, "credits")?)
                    .i64(conv::<_, i64>(e.prompt_tokens, "prompt_tokens")?)
                    .i64(conv::<_, i64>(e.completion_tokens, "completion_tokens")?),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(())
    }

    async fn usage_totals(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<UsageTotals> {
        let _timer = self.query_timer("intel.usage_totals");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(UsageTotals::default());
        }
        let at_col = ident::<B>("at");
        let sql = format!(
            "SELECT {} AS credits, {} AS prompt_tokens, {} AS completion_tokens, count(*) AS events \
             FROM usage_ledger WHERE tenant_id = $1 AND {at_col} >= $2 AND {at_col} < $3",
            as_i64::<B>("COALESCE(SUM(credits), 0)"),
            as_i64::<B>("COALESCE(SUM(prompt_tokens), 0)"),
            as_i64::<B>("COALESCE(SUM(completion_tokens), 0)"),
        );
        let row = scope
            .query(
                "usage_ledger",
                Stmt::<B>::dynamic(&sql).uuid(tenant.0).ts(from).ts(to),
            )?
            .fetch_one_pool(&self.pool)
            .await?;
        totals_from_row(&row)
    }

    async fn usage_by_day(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<Vec<UsageDay>> {
        let _timer = self.query_timer("intel.usage_by_day");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(Vec::new());
        }
        let at_col = ident::<B>("at");
        let sql = format!(
            "SELECT {} AS day, {} AS credits, {} AS prompt_tokens, {} AS completion_tokens, count(*) AS events \
             FROM usage_ledger WHERE tenant_id = $1 AND {at_col} >= $2 AND {at_col} < $3 \
             GROUP BY 1 ORDER BY 1",
            day_of::<B>(&at_col),
            as_i64::<B>("COALESCE(SUM(credits), 0)"),
            as_i64::<B>("COALESCE(SUM(prompt_tokens), 0)"),
            as_i64::<B>("COALESCE(SUM(completion_tokens), 0)"),
        );
        let rows = scope
            .query(
                "usage_ledger",
                Stmt::<B>::dynamic(&sql).uuid(tenant.0).ts(from).ts(to),
            )?
            .fetch_all_pool(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(UsageDay {
                    day: r.text("day")?,
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
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(Vec::new());
        }
        let at_col = ident::<B>("at");
        let sql = format!(
            "SELECT tenant_id, {at_col} AS at, endpoint, ref_id, status, credits, prompt_tokens, completion_tokens \
             FROM usage_ledger WHERE tenant_id = $1 AND ($2::text IS NULL OR endpoint = $2) \
             ORDER BY {at_col} DESC, entry_id DESC LIMIT $3 OFFSET $4"
        );
        scope
            .query(
                "usage_ledger",
                Stmt::<B>::dynamic(&sql)
                    .uuid(tenant.0)
                    .opt_text(endpoint)
                    .i64(i64::from(limit))
                    .i64(i64::from(offset)),
            )?
            .fetch_all_pool(&self.pool)
            .await?
            .iter()
            .map(usage_from_row)
            .collect()
    }

    async fn usage_by_ref(&self, tenant: TenantId, ref_id: Uuid) -> IntelResult<Option<UsageEvent>> {
        let _timer = self.query_timer("intel.usage_by_ref");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let at_col = ident::<B>("at");
        let sql = format!(
            "SELECT tenant_id, {at_col} AS at, endpoint, ref_id, status, credits, prompt_tokens, completion_tokens \
             FROM usage_ledger WHERE tenant_id = $1 AND ref_id = $2 \
             ORDER BY {at_col} DESC, entry_id DESC LIMIT 1"
        );
        scope
            .query(
                "usage_ledger",
                Stmt::<B>::dynamic(&sql).uuid(tenant.0).uuid(ref_id),
            )?
            .fetch_optional_pool(&self.pool)
            .await?
            .as_ref()
            .map(usage_from_row)
            .transpose()
    }

    async fn setting_get(&self, tenant: TenantId, key: &str) -> IntelResult<Option<Value>> {
        let _timer = self.query_timer("intel.setting_get");
        let scope = self.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let key_col = ident::<B>("key");
        let sql = format!("SELECT value FROM tenant_settings WHERE tenant_id = $1 AND {key_col} = $2");
        scope
            .query(
                "tenant_settings",
                Stmt::<B>::dynamic(&sql).uuid(tenant.0).text(key),
            )?
            .fetch_optional_pool(&self.pool)
            .await?
            .map(|r| r.json("value"))
            .transpose()
    }

    async fn setting_put(&self, tenant: TenantId, key: &str, value: Value, at: Timestamp) -> IntelResult<()> {
        let _timer = self.query_timer("intel.setting_put");
        let scope = self.scope()?;
        scope.authorize(tenant)?;
        let key_col = ident::<B>("key");
        let sql = format!(
            "INSERT INTO tenant_settings (tenant_id, {key_col}, value, updated_at) VALUES ($1, $2, $3, $4) {}",
            Dia::<B>::upsert_update(&["tenant_id", &key_col], &["value", "updated_at"], None)
        );
        scope
            .query(
                "tenant_settings",
                Stmt::<B>::dynamic(&sql)
                    .uuid(tenant.0)
                    .text(key)
                    .json(&value)
                    .ts(at),
            )?
            .execute_write(&self.pool)
            .await?;
        Ok(())
    }

    async fn purge_expired(&self, now: Timestamp, usage_before: Timestamp) -> IntelResult<PurgeReport> {
        let _timer = self.query_timer("intel.purge_expired");
        // Retention spans tenants: operator work.
        self.require_operator()?;
        let scope = self.scope()?;
        let at_col = ident::<B>("at");
        let mut tx = self.begin_write().await?;
        // Trace, snapshots and pages go with their parent rows (ON DELETE CASCADE).
        let jobs = scope
            .query(
                "intel_jobs",
                Stmt::<B>::dynamic("DELETE FROM intel_jobs WHERE expires_at <= $1").ts(now),
            )?
            .execute(tx.conn())
            .await?;
        let checks = scope
            .query(
                "monitor_checks",
                Stmt::<B>::dynamic("DELETE FROM monitor_checks WHERE expires_at <= $1").ts(now),
            )?
            .execute(tx.conn())
            .await?;
        let sql = format!("DELETE FROM usage_ledger WHERE {at_col} < $1");
        scope
            .query("usage_ledger", Stmt::<B>::dynamic(&sql).ts(usage_before))?
            .execute(tx.conn())
            .await?;
        tx.commit().await?;
        Ok(PurgeReport { jobs, checks })
    }
}

impl<B: Tenancy> Store<B> {
    /// Fail unless every check in `checks` belongs to the scope's tenant: a page of another
    /// tenant's check can never be written (the write-side tenancy check of the child table).
    async fn require_owned_checks(
        &self,
        scope: &crate::tenant::Scope,
        tx: &mut crate::backend::WriteTx<B::Db>,
        checks: impl Iterator<Item = Uuid>,
    ) -> Result<(), StoreError> {
        self.require_owned(scope, tx, "monitor_checks", "check_id", checks)
            .await
    }

    /// As [`Store::require_owned_checks`] for monitors.
    async fn require_owned_monitors(
        &self,
        scope: &crate::tenant::Scope,
        tx: &mut crate::backend::WriteTx<B::Db>,
        monitors: impl Iterator<Item = Uuid>,
    ) -> Result<(), StoreError> {
        self.require_owned(scope, tx, "monitors", "monitor_id", monitors)
            .await
    }

    async fn require_owned(
        &self,
        scope: &crate::tenant::Scope,
        tx: &mut crate::backend::WriteTx<B::Db>,
        table: &str,
        column: &str,
        ids: impl Iterator<Item = Uuid>,
    ) -> Result<(), StoreError> {
        let Some(tenant) = scope.tenant() else {
            return Ok(());
        };
        let ids: std::collections::BTreeSet<Uuid> = ids.collect();
        let ids: Vec<Uuid> = ids.into_iter().collect();
        for chunk in ids.chunks(Dia::<B>::MAX_BIND_PARAMS.saturating_sub(2).max(1)) {
            let list = placeholders(2, chunk.len());
            let sql =
                format!("SELECT count(*) AS v FROM {table} WHERE tenant_id = $1 AND {column} IN ({list})");
            let mut stmt = Stmt::<B>::dynamic(&sql).uuid(tenant.0);
            for id in chunk {
                stmt = stmt.uuid(*id);
            }
            let found = scope.query(table, stmt)?.fetch_one(tx.conn()).await?.i64("v")?;
            if usize::try_from(found).ok() != Some(chunk.len()) {
                return Err(StoreError::AccessDenied(format!(
                    "{table} rows of another tenant cannot be written"
                )));
            }
        }
        Ok(())
    }
}
