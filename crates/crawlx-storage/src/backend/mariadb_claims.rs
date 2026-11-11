//! MariaDB claim algorithms (10.6 or newer, `READ COMMITTED`).
//!
//! MariaDB has no `UPDATE .. RETURNING` and rejects `LIMIT` inside an `IN` subquery, so a
//! claim is a short transaction: lock the candidates with `SELECT .. FOR UPDATE SKIP LOCKED`
//! (or an `UPDATE .. JOIN (SELECT .. LIMIT n FOR UPDATE SKIP LOCKED)` carrying one claim
//! token), update them, and read them back. `INSERT IGNORE` is never used. Times bind as
//! naive UTC `DATETIME(6)` values; the database clock is `SYSDATE(6)`/`NOW(6)`.

use super::dialect::{Dialect, MariaDbDialect, MARIADB_NEG_INFINITY};
use super::mariadb::MariaBackend;
use super::strategy::{
    audit_entry_hash, AuditEntry, Concurrency, FenceSeq, FrontierClaim, MonitorClaim, OutboxClaim,
    SessionClaim, WebhookClaim, EMPTY_AUDIT_HEAD,
};
use crate::error::db;
use crate::worker_eligibility::{claim_eligible, WorkerFacts};
use chrono::NaiveDateTime;
use crawlx_core::StoreError;
use serde_json::Value;
use sqlx::mysql::MySqlRow;
use sqlx::{MySqlConnection, MySqlPool, Row};
use uuid::Uuid;

fn json_column(row: &MySqlRow, column: &str) -> Result<Value, StoreError> {
    let text: String = row.try_get(column).map_err(db)?;
    serde_json::from_str(&text).map_err(|e| StoreError::Serialization(e.to_string()))
}

/// The server clock, to the microsecond, as the claim's `now`.
async fn clock(conn: &mut MySqlConnection) -> Result<NaiveDateTime, StoreError> {
    sqlx::query_scalar("SELECT CAST(SYSDATE(6) AS DATETIME(6))")
        .fetch_one(conn)
        .await
        .map_err(db)
}

async fn worker_facts(conn: &mut MySqlConnection, worker: Uuid) -> Result<Option<WorkerFacts>, StoreError> {
    let row = sqlx::query("SELECT capacity, draining, last_heartbeat_at FROM workers WHERE worker_id = ?")
        .bind(worker)
        .fetch_optional(conn)
        .await
        .map_err(db)?;
    row.map(|row| {
        Ok(WorkerFacts {
            capacity: json_column(&row, "capacity")?,
            draining: row.try_get("draining").map_err(db)?,
            last_heartbeat_at: row
                .try_get::<NaiveDateTime, _>("last_heartbeat_at")
                .map_err(db)?
                .and_utc(),
        })
    })
    .transpose()
}

fn list(count: usize) -> String {
    MariaDbDialect::in_list(1, count)
}

pub(super) async fn claim_sessions(
    pool: &MySqlPool,
    claim: SessionClaim<'_>,
) -> Result<Option<MySqlRow>, StoreError> {
    let mut tx = MariaBackend::begin_write(pool).await?;
    let now = clock(tx.conn()).await?;
    let Some(run) = sqlx::query(
        "SELECT data_requirements FROM crawl_runs WHERE run_id = ? AND status IN ('queued', 'running') \
         AND cancel_requested_at IS NULL AND purge_requested_at IS NULL",
    )
    .bind(claim.run)
    .fetch_optional(tx.conn())
    .await
    .map_err(db)?
    else {
        return Ok(None);
    };
    let requirements = json_column(&run, "data_requirements")?;
    let worker = worker_facts(tx.conn(), claim.worker).await?;
    if !claim_eligible(
        worker.as_ref(),
        claim.run,
        now.and_utc(),
        claim.required_backends,
        claim.data_required,
        &requirements,
    ) {
        return Ok(None);
    }
    let never = MARIADB_NEG_INFINITY;
    let picked: Option<Uuid> = if claim.parallel_roles {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT c.session_id FROM crawl_sessions c \
             WHERE c.run_id = ? AND c.lease_kind = 'role' AND c.status IN ('pending', 'recovering') \
               AND (? IS NULL OR c.session_id = ?) AND COALESCE(c.lease_expires_at, '{never}') < ? \
             ORDER BY COALESCE(c.lease_expires_at, '{never}'), c.schedule_slot LIMIT 1 FOR UPDATE SKIP LOCKED"
        )))
        .bind(claim.run)
        .bind(claim.requested)
        .bind(claim.requested)
        .bind(now)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
    } else {
        // The first unfinished slot is read without a lock; only that one row is locked, so
        // a busy head is skipped without ever granting its successor.
        let head: Option<Uuid> = sqlx::query_scalar(
            "SELECT session_id FROM crawl_sessions WHERE run_id = ? AND lease_kind = 'role' \
             AND status NOT IN ('completed', 'failed', 'cancelled') ORDER BY schedule_slot LIMIT 1",
        )
        .bind(claim.run)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?;
        match head {
            Some(head) if claim.requested.is_none_or(|wanted| wanted == head) => {
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                    "SELECT session_id FROM crawl_sessions WHERE session_id = ? \
                     AND status IN ('pending', 'recovering') AND COALESCE(lease_expires_at, '{never}') < ? \
                     FOR UPDATE SKIP LOCKED"
                )))
                .bind(head)
                .bind(now)
                .fetch_optional(tx.conn())
                .await
                .map_err(db)?
            }
            _ => None,
        }
    };
    let Some(picked) = picked else {
        return Ok(None);
    };
    let fence = MariaBackend::next_fence(tx.conn(), FenceSeq::Lease).await?;
    sqlx::query(
        "UPDATE crawl_sessions SET status = CASE WHEN status = 'pending' THEN 'running' ELSE status END, \
           lease_owner = ?, lease_expires_at = DATE_ADD(?, INTERVAL ROUND(? * 1000000) MICROSECOND), \
           fencing_token = ?, last_heartbeat_at = ?, started_at = COALESCE(started_at, ?) WHERE session_id = ?",
    )
    .bind(claim.worker)
    .bind(now)
    .bind(claim.ttl_secs)
    .bind(fence)
    .bind(now)
    .bind(now)
    .bind(picked)
    .execute(tx.conn())
    .await
    .map_err(db)?;
    let columns = claim.columns;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {columns} FROM crawl_sessions s WHERE s.session_id = ?"
    )))
    .bind(picked)
    .fetch_one(tx.conn())
    .await
    .map_err(db)?;
    tx.commit().await?;
    Ok(Some(row))
}

pub(super) async fn claim_frontier_batch(
    pool: &MySqlPool,
    claim: FrontierClaim<'_>,
) -> Result<Vec<MySqlRow>, StoreError> {
    let mut tx = MariaBackend::begin_write(pool).await?;
    let now = clock(tx.conn()).await?;
    let Some(run) = sqlx::query("SELECT mode, data_requirements FROM crawl_runs WHERE run_id = ?")
        .bind(claim.run)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
    else {
        return Ok(Vec::new());
    };
    let mode: String = run.try_get("mode").map_err(db)?;
    if mode == "dynamic" {
        return Ok(Vec::new());
    }
    let requirements = json_column(&run, "data_requirements")?;
    let worker = worker_facts(tx.conn(), claim.worker).await?;
    if !claim_eligible(
        worker.as_ref(),
        claim.run,
        now.and_utc(),
        claim.required_backends,
        claim.data_required,
        &requirements,
    ) {
        return Ok(Vec::new());
    }
    // Each leased row takes a token of its own, in selection order. `-frontier_id` orders
    // newest first without the unsigned result of `~`.
    let picked: Vec<i64> = sqlx::query_scalar(
        "SELECT frontier_id FROM url_frontier \
           WHERE run_id = ? AND via <> 'interaction' AND status = 'pending' AND next_attempt_at <= ? \
           ORDER BY priority DESC, \
             CASE ? WHEN 'depth_first' THEN -depth WHEN 'priority' THEN strategy_score ELSE depth END, \
             CASE WHEN ? = 'priority' THEN depth ELSE 0 END, \
             CASE WHEN ? = 'depth_first' THEN -frontier_id ELSE frontier_id END \
           LIMIT ? FOR UPDATE SKIP LOCKED",
    )
    .bind(claim.run)
    .bind(now)
    .bind(claim.strategy)
    .bind(claim.strategy)
    .bind(claim.strategy)
    .bind(claim.limit)
    .fetch_all(tx.conn())
    .await
    .map_err(db)?;
    if picked.is_empty() {
        return Ok(Vec::new());
    }
    for id in &picked {
        let fence = MariaBackend::next_fence(tx.conn(), FenceSeq::Lease).await?;
        sqlx::query(
            "UPDATE url_frontier SET status = 'leased', lease_owner = ?, \
               lease_expires_at = DATE_ADD(?, INTERVAL ROUND(? * 1000000) MICROSECOND), \
               fencing_token = ?, attempts = attempts + 1 WHERE frontier_id = ?",
        )
        .bind(claim.worker)
        .bind(now)
        .bind(claim.ttl_secs)
        .bind(fence)
        .bind(*id)
        .execute(tx.conn())
        .await
        .map_err(db)?;
    }
    let select = format!(
        "SELECT frontier_id, run_id, query_schema, depth, status, COALESCE(denial_reason, error_code) AS denial_reason, \
           attempts, parent_id, priority, COALESCE(strategy_score, 0) AS strategy_score, fencing_token \
         FROM url_frontier WHERE frontier_id {}",
        list(picked.len())
    );
    let mut query = sqlx::query(sqlx::AssertSqlSafe(select));
    for id in &picked {
        query = query.bind(*id);
    }
    let rows = query.fetch_all(tx.conn()).await.map_err(db)?;
    tx.commit().await?;
    Ok(rows)
}

pub(super) async fn claim_webhooks(
    pool: &MySqlPool,
    claim: WebhookClaim<'_>,
) -> Result<Vec<MySqlRow>, StoreError> {
    let mut tx = MariaBackend::begin_write(pool).await?;
    let now = claim.now.naive_utc();
    let columns = claim.columns;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {columns}, next_attempt_at AS due_at FROM webhook_deliveries \
         WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at, delivery_id LIMIT ? \
         FOR UPDATE SKIP LOCKED"
    )))
    .bind(now)
    .bind(claim.limit)
    .fetch_all(tx.conn())
    .await
    .map_err(db)?;
    if rows.is_empty() {
        return Ok(rows);
    }
    let ids = rows
        .iter()
        .map(|row| row.try_get::<Uuid, _>("delivery_id").map_err(db))
        .collect::<Result<Vec<_>, _>>()?;
    let update = format!(
        "UPDATE webhook_deliveries SET next_attempt_at = DATE_ADD(?, INTERVAL ROUND(? * 1000000) MICROSECOND) \
         WHERE delivery_id {}",
        list(ids.len())
    );
    let mut query = sqlx::query(sqlx::AssertSqlSafe(update))
        .bind(now)
        .bind(claim.lease_secs);
    for id in &ids {
        query = query.bind(*id);
    }
    query.execute(tx.conn()).await.map_err(db)?;
    tx.commit().await?;
    Ok(rows)
}

pub(super) async fn claim_monitors(
    pool: &MySqlPool,
    claim: MonitorClaim,
) -> Result<Vec<MySqlRow>, StoreError> {
    let mut tx = MariaBackend::begin_write(pool).await?;
    let now = claim.now.naive_utc();
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT monitor_id FROM monitors \
         WHERE status = 'active' AND next_run_at <= ? AND (claimed_until IS NULL OR claimed_until <= ?) \
         ORDER BY next_run_at, monitor_id LIMIT ? FOR UPDATE SKIP LOCKED",
    )
    .bind(now)
    .bind(now)
    .bind(claim.limit)
    .fetch_all(tx.conn())
    .await
    .map_err(db)?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let update = format!(
        "UPDATE monitors SET claimed_until = ? WHERE monitor_id {}",
        list(ids.len())
    );
    let mut query = sqlx::query(sqlx::AssertSqlSafe(update)).bind(claim.lease_until.naive_utc());
    for id in &ids {
        query = query.bind(*id);
    }
    query.execute(tx.conn()).await.map_err(db)?;
    let columns = claim.columns;
    let select = format!(
        "SELECT {columns} FROM monitors WHERE monitor_id {}",
        list(ids.len())
    );
    let mut query = sqlx::query(sqlx::AssertSqlSafe(select));
    for id in &ids {
        query = query.bind(*id);
    }
    let rows = query.fetch_all(tx.conn()).await.map_err(db)?;
    tx.commit().await?;
    Ok(rows)
}

pub(super) async fn claim_outbox(
    conn: &mut MySqlConnection,
    claim: OutboxClaim,
) -> Result<Vec<MySqlRow>, StoreError> {
    // The run's finalization flag is read outside the row-locking statement so the claim
    // does not lock the run row.
    let finalized: Option<bool> =
        sqlx::query_scalar("SELECT feed_finalized FROM crawl_runs WHERE run_id = ?")
            .bind(claim.run)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db)?;
    let finalized = finalized.unwrap_or(false);
    let picked: Vec<i64> = sqlx::query_scalar(
        "SELECT delivery_id FROM dataset_delivery_outbox \
         WHERE tenant_id = ? AND run_id = ? AND expires_at > NOW(6) AND not_before <= NOW(6) \
           AND (NOT terminal_source OR ?) \
           AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= NOW(6))) \
         ORDER BY delivery_id LIMIT ? FOR UPDATE SKIP LOCKED",
    )
    .bind(claim.tenant)
    .bind(claim.run)
    .bind(finalized)
    .bind(claim.limit)
    .fetch_all(&mut *conn)
    .await
    .map_err(db)?;
    if picked.is_empty() {
        return Ok(Vec::new());
    }
    let update = format!(
        "UPDATE dataset_delivery_outbox SET state = 'leased', attempts = attempts + 1, fence = fence + 1, \
           lease_owner = ?, lease_expires_at = DATE_ADD(NOW(6), INTERVAL ROUND(? * 1000000) MICROSECOND) \
         WHERE delivery_id {}",
        MariaDbDialect::in_list(1, picked.len())
    );
    let mut query = sqlx::query(sqlx::AssertSqlSafe(update))
        .bind(claim.worker)
        .bind(claim.lease_secs);
    for id in &picked {
        query = query.bind(*id);
    }
    query.execute(&mut *conn).await.map_err(db)?;
    let select = format!(
        "SELECT delivery_id, payload, volatile_page, fence, attempts FROM dataset_delivery_outbox WHERE delivery_id {}",
        MariaDbDialect::in_list(1, picked.len())
    );
    let mut query = sqlx::query(sqlx::AssertSqlSafe(select));
    for id in &picked {
        query = query.bind(*id);
    }
    query.fetch_all(conn).await.map_err(db)
}

pub(super) async fn expire_outbox(pool: &MySqlPool, tenant: Uuid, run: Uuid) -> Result<u64, StoreError> {
    let mut tx = MariaBackend::begin_write(pool).await?;
    let done = sqlx::query(
        "UPDATE dataset_delivery_outbox o JOIN (SELECT delivery_id FROM dataset_delivery_outbox \
           WHERE tenant_id = ? AND run_id = ? AND state IN ('pending', 'leased') AND expires_at <= NOW(6) \
           ORDER BY delivery_id LIMIT 1000 FOR UPDATE SKIP LOCKED) e ON e.delivery_id = o.delivery_id \
         SET o.state = 'content_expired', o.lease_owner = NULL, o.lease_expires_at = NULL",
    )
    .bind(tenant)
    .bind(run)
    .execute(tx.conn())
    .await
    .map_err(db)?;
    tx.commit().await?;
    Ok(done.rows_affected())
}

pub(super) async fn append_audit_chain(
    conn: &mut MySqlConnection,
    entry: AuditEntry<'_>,
) -> Result<(), StoreError> {
    // the head row lock serializes appenders (it replaces the advisory lock)
    let prev: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT entry_hash FROM audit_chain_head WHERE id = 1 FOR UPDATE")
            .fetch_optional(&mut *conn)
            .await
            .map_err(db)?;
    let prev = prev.unwrap_or_else(|| EMPTY_AUDIT_HEAD.to_vec());
    let hash = audit_entry_hash(&prev, &entry).0.to_vec();
    sqlx::query(
        "INSERT INTO audit_events (tenant_id, run_id, actor, event, subject, prev_hash, entry_hash) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(entry.tenant)
    .bind(entry.run)
    .bind(entry.actor)
    .bind(entry.event)
    .bind(entry.subject.to_string())
    .bind(prev.as_slice())
    .bind(hash.as_slice())
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE audit_chain_head SET entry_hash = ? WHERE id = 1")
        .bind(hash.as_slice())
        .execute(&mut *conn)
        .await
        .map_err(db)?;
    Ok(())
}

pub(super) async fn heartbeat_frontier(
    pool: &MySqlPool,
    worker: Uuid,
    ttl_secs: f64,
    leases: &[(i64, i64)],
) -> Result<Vec<i64>, StoreError> {
    if leases.is_empty() {
        return Ok(Vec::new());
    }
    let mut tx = MariaBackend::begin_write(pool).await?;
    let mut extended = Vec::with_capacity(leases.len());
    // two fixed parameters plus two per pair
    for chunk in leases.chunks(MariaDbDialect::MAX_BIND_PARAMS.saturating_sub(3) / 2) {
        let pairs = vec!["(?, ?)"; chunk.len()].join(", ");
        let update = format!(
            "UPDATE url_frontier SET lease_expires_at = DATE_ADD(NOW(6), INTERVAL ROUND(? * 1000000) MICROSECOND) \
             WHERE lease_owner = ? AND status = 'leased' AND lease_expires_at > NOW(6) \
               AND (frontier_id, fencing_token) IN ({pairs})"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(update))
            .bind(ttl_secs)
            .bind(worker);
        for (id, fence) in chunk {
            query = query.bind(*id).bind(*fence);
        }
        let done = query.execute(tx.conn()).await.map_err(db)?;
        if done.rows_affected() == 0 {
            continue;
        }
        // the extended rows are exactly the listed pairs that are still live and the holder's
        let select = format!(
            "SELECT frontier_id FROM url_frontier WHERE lease_owner = ? AND status = 'leased' \
               AND lease_expires_at > NOW(6) AND (frontier_id, fencing_token) IN ({pairs})"
        );
        let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(select)).bind(worker);
        for (id, fence) in chunk {
            query = query.bind(*id).bind(*fence);
        }
        extended.extend(query.fetch_all(tx.conn()).await.map_err(db)?);
    }
    tx.commit().await?;
    Ok(extended)
}

const TRAFFIC_COLUMNS: usize = 18;

pub(super) async fn insert_traffic(
    conn: &mut MySqlConnection,
    run: Uuid,
    lane: &str,
    rows: &[super::strategy::TrafficRow<'_>],
) -> Result<(), StoreError> {
    for chunk in rows.chunks(MariaDbDialect::max_batch_rows(TRAFFIC_COLUMNS)) {
        let values = MariaDbDialect::values_rows(1, chunk.len(), TRAFFIC_COLUMNS);
        let sql = format!(
            "INSERT INTO traffic_events (occurred_at, run_id, epoch_id, unattributed_reason, seq, lane, origin, third_party, late, \
               method, url_redacted, url_hash, status, request_headers, response_headers, body_artifact_id, request_body_artifact_id, finished_at) \
             {values}"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for t in chunk {
            query = query
                .bind(t.occurred_at.naive_utc())
                .bind(run)
                .bind(t.epoch)
                .bind(t.reason)
                .bind(t.seq)
                .bind(if t.epoch.is_none() { "diagnostic" } else { lane })
                .bind(t.origin)
                .bind(t.third_party)
                .bind(t.late)
                .bind(t.method)
                .bind(t.url)
                .bind(t.url_hash.as_slice())
                .bind(t.status)
                .bind(t.request_headers.as_ref().map(crate::codec::to_json_text))
                .bind(t.response_headers.as_ref().map(crate::codec::to_json_text))
                .bind(t.body)
                .bind(t.request_body)
                .bind(t.finished_at.map(|at| at.naive_utc()));
        }
        query.execute(&mut *conn).await.map_err(db)?;
    }
    Ok(())
}
