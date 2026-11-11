//! SQLite claim algorithms.
//!
//! Every claim runs in one `BEGIN IMMEDIATE` transaction (`begin_write`): the database write
//! lock is held from the first statement, so no `SKIP LOCKED` is needed and a candidate read
//! cannot go stale before its update. Timestamps are microseconds since the epoch; the
//! database clock is the process clock (one host). `RETURNING` yields rows in scan order,
//! so callers that need an order sort the returned rows.

use super::dialect::{Dialect, SqliteDialect, SQLITE_NEG_INFINITY_MICROS};
use super::sqlite::{SqliteBackend, SqliteHandle};
use super::strategy::{
    AuditEntry, Concurrency, FenceSeq, FrontierClaim, MonitorClaim, OutboxClaim, SessionClaim, WebhookClaim,
    EMPTY_AUDIT_HEAD,
};
use crate::codec::ts_from_micros;
use crate::error::db;
use crate::worker_eligibility::{claim_eligible, WorkerFacts};
use crawlx_core::StoreError;
use serde_json::Value;
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection};
use uuid::Uuid;

/// Microseconds since the epoch on the host clock.
fn now_micros() -> i64 {
    chrono::Utc::now().timestamp_micros()
}

fn json_column(row: &SqliteRow, column: &str) -> Result<Value, StoreError> {
    let text: String = row.try_get(column).map_err(db)?;
    serde_json::from_str(&text).map_err(|e| StoreError::Serialization(e.to_string()))
}

async fn worker_facts(conn: &mut SqliteConnection, worker: Uuid) -> Result<Option<WorkerFacts>, StoreError> {
    let row = sqlx::query("SELECT capacity, draining, last_heartbeat_at FROM workers WHERE worker_id = ?1")
        .bind(worker)
        .fetch_optional(conn)
        .await
        .map_err(db)?;
    row.map(|row| {
        Ok(WorkerFacts {
            capacity: json_column(&row, "capacity")?,
            draining: row.try_get("draining").map_err(db)?,
            last_heartbeat_at: ts_from_micros(row.try_get("last_heartbeat_at").map_err(db)?)?,
        })
    })
    .transpose()
}

/// `(a, b, ..)` list of `count` numbered placeholders starting at `first`.
fn in_list(first: usize, count: usize) -> String {
    SqliteDialect::in_list(first, count)
}

pub(super) async fn claim_sessions(
    handle: &SqliteHandle,
    claim: SessionClaim<'_>,
) -> Result<Option<SqliteRow>, StoreError> {
    let mut tx = SqliteBackend::begin_write(handle).await?;
    let now = now_micros();
    let Some(run) = sqlx::query(
        "SELECT data_requirements FROM crawl_runs WHERE run_id = ?1 AND status IN ('queued', 'running') \
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
        ts_from_micros(now)?,
        claim.required_backends,
        claim.data_required,
        &requirements,
    ) {
        return Ok(None);
    }
    // Parallel runs probe only claimable states ordered by availability. Serial runs inspect
    // exactly the first unfinished slot; a successor is never granted past a busy head.
    let candidate = if claim.parallel_roles {
        "SELECT c.session_id FROM crawl_sessions c \
         WHERE c.run_id = ?1 AND c.lease_kind = 'role' AND c.status IN ('pending', 'recovering') \
           AND (?2 IS NULL OR c.session_id = ?2) AND COALESCE(c.lease_expires_at, ?3) < ?4 \
         ORDER BY COALESCE(c.lease_expires_at, ?3), c.schedule_slot LIMIT 1"
    } else {
        "SELECT c.session_id FROM crawl_sessions c \
         WHERE c.session_id = (SELECT p.session_id FROM crawl_sessions p WHERE p.run_id = ?1 \
           AND p.lease_kind = 'role' AND p.status NOT IN ('completed', 'failed', 'cancelled') \
           ORDER BY p.schedule_slot LIMIT 1) \
           AND (?2 IS NULL OR c.session_id = ?2) AND c.status IN ('pending', 'recovering') \
           AND COALESCE(c.lease_expires_at, ?3) < ?4"
    };
    let Some(picked) = sqlx::query_scalar::<_, Uuid>(candidate)
        .bind(claim.run)
        .bind(claim.requested)
        .bind(SQLITE_NEG_INFINITY_MICROS)
        .bind(now)
        .fetch_optional(tx.conn())
        .await
        .map_err(db)?
    else {
        return Ok(None);
    };
    let fence = SqliteBackend::next_fence(tx.conn(), FenceSeq::Lease).await?;
    sqlx::query(
        "UPDATE crawl_sessions SET status = CASE WHEN status = 'pending' THEN 'running' ELSE status END, \
           lease_owner = ?1, lease_expires_at = ?2 + CAST(ROUND(?3 * 1000000) AS INTEGER), fencing_token = ?4, \
           last_heartbeat_at = ?2, started_at = COALESCE(started_at, ?2) WHERE session_id = ?5",
    )
    .bind(claim.worker)
    .bind(now)
    .bind(claim.ttl_secs)
    .bind(fence)
    .bind(picked)
    .execute(tx.conn())
    .await
    .map_err(db)?;
    let columns = claim.columns;
    let row = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {columns} FROM crawl_sessions s WHERE s.session_id = ?1"
    )))
    .bind(picked)
    .fetch_one(tx.conn())
    .await
    .map_err(db)?;
    tx.commit().await?;
    Ok(Some(row))
}

pub(super) async fn claim_frontier_batch(
    handle: &SqliteHandle,
    claim: FrontierClaim<'_>,
) -> Result<Vec<SqliteRow>, StoreError> {
    let mut tx = SqliteBackend::begin_write(handle).await?;
    let now = now_micros();
    let Some(run) = sqlx::query("SELECT mode, data_requirements FROM crawl_runs WHERE run_id = ?1")
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
        ts_from_micros(now)?,
        claim.required_backends,
        claim.data_required,
        &requirements,
    ) {
        return Ok(Vec::new());
    }
    // Each leased row takes a token of its own, in selection order.
    let picked: Vec<i64> = sqlx::query_scalar(
        "SELECT frontier_id FROM url_frontier \
           WHERE run_id = ?1 AND via <> 'interaction' AND status = 'pending' AND next_attempt_at <= ?2 \
           ORDER BY priority DESC, \
             CASE ?4 WHEN 'depth_first' THEN -depth WHEN 'priority' THEN strategy_score ELSE depth END, \
             CASE WHEN ?4 = 'priority' THEN depth ELSE 0 END, \
             CASE WHEN ?4 = 'depth_first' THEN ~frontier_id ELSE frontier_id END \
           LIMIT ?3",
    )
    .bind(claim.run)
    .bind(now)
    .bind(claim.limit)
    .bind(claim.strategy)
    .fetch_all(tx.conn())
    .await
    .map_err(db)?;
    let mut rows = Vec::with_capacity(picked.len());
    for id in picked {
        let fence = SqliteBackend::next_fence(tx.conn(), FenceSeq::Lease).await?;
        let row = sqlx::query(
            "UPDATE url_frontier SET status = 'leased', lease_owner = ?2, \
               lease_expires_at = ?3 + CAST(ROUND(?4 * 1000000) AS INTEGER), fencing_token = ?5, attempts = attempts + 1 \
             WHERE frontier_id = ?1 \
             RETURNING frontier_id, run_id, query_schema, depth, status, COALESCE(denial_reason, error_code) AS denial_reason, \
               attempts, parent_id, priority, COALESCE(strategy_score, 0) AS strategy_score, fencing_token",
        )
        .bind(id)
        .bind(claim.worker)
        .bind(now)
        .bind(claim.ttl_secs)
        .bind(fence)
        .fetch_one(tx.conn())
        .await
        .map_err(db)?;
        rows.push(row);
    }
    tx.commit().await?;
    Ok(rows)
}

pub(super) async fn claim_webhooks(
    handle: &SqliteHandle,
    claim: WebhookClaim<'_>,
) -> Result<Vec<SqliteRow>, StoreError> {
    let mut tx = SqliteBackend::begin_write(handle).await?;
    let now = claim.now.timestamp_micros();
    let columns = claim.columns;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {columns}, next_attempt_at AS due_at FROM webhook_deliveries \
         WHERE status = 'pending' AND next_attempt_at <= ?1 ORDER BY next_attempt_at, delivery_id LIMIT ?2"
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
        "UPDATE webhook_deliveries SET next_attempt_at = ?1 + CAST(ROUND(?2 * 1000000) AS INTEGER) \
         WHERE delivery_id {}",
        in_list(3, ids.len())
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
    handle: &SqliteHandle,
    claim: MonitorClaim,
) -> Result<Vec<SqliteRow>, StoreError> {
    let mut tx = SqliteBackend::begin_write(handle).await?;
    let columns = claim.columns;
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE monitors SET claimed_until = ?2 WHERE monitor_id IN ( \
           SELECT monitor_id FROM monitors \
           WHERE status = 'active' AND next_run_at <= ?1 AND (claimed_until IS NULL OR claimed_until <= ?1) \
           ORDER BY next_run_at, monitor_id LIMIT ?3) \
         RETURNING {columns}"
    )))
    .bind(claim.now.timestamp_micros())
    .bind(claim.lease_until.timestamp_micros())
    .bind(claim.limit)
    .fetch_all(tx.conn())
    .await
    .map_err(db)?;
    tx.commit().await?;
    Ok(rows)
}

pub(super) async fn claim_outbox(
    conn: &mut SqliteConnection,
    claim: OutboxClaim,
) -> Result<Vec<SqliteRow>, StoreError> {
    sqlx::query(
        "UPDATE dataset_delivery_outbox SET state = 'leased', attempts = attempts + 1, fence = fence + 1, \
           lease_owner = ?4, lease_expires_at = ?5 + CAST(ROUND(?6 * 1000000) AS INTEGER) \
         WHERE delivery_id IN (SELECT delivery_id FROM dataset_delivery_outbox \
           WHERE tenant_id = ?1 AND run_id = ?2 AND expires_at > ?5 AND not_before <= ?5 \
             AND (NOT terminal_source OR (SELECT feed_finalized FROM crawl_runs WHERE run_id = ?2)) \
             AND (state = 'pending' OR (state = 'leased' AND lease_expires_at <= ?5)) \
           ORDER BY delivery_id LIMIT ?3) \
         RETURNING delivery_id, payload, volatile_page, fence, attempts",
    )
    .bind(claim.tenant)
    .bind(claim.run)
    .bind(claim.limit)
    .bind(claim.worker)
    .bind(now_micros())
    .bind(claim.lease_secs)
    .fetch_all(conn)
    .await
    .map_err(db)
}

pub(super) async fn expire_outbox(handle: &SqliteHandle, tenant: Uuid, run: Uuid) -> Result<u64, StoreError> {
    let mut tx = SqliteBackend::begin_write(handle).await?;
    let done = sqlx::query(
        "UPDATE dataset_delivery_outbox SET state = 'content_expired', lease_owner = NULL, lease_expires_at = NULL \
         WHERE delivery_id IN (SELECT delivery_id FROM dataset_delivery_outbox \
           WHERE tenant_id = ?1 AND run_id = ?2 AND state IN ('pending', 'leased') AND expires_at <= ?3 \
           ORDER BY delivery_id LIMIT 1000)",
    )
    .bind(tenant)
    .bind(run)
    .bind(now_micros())
    .execute(tx.conn())
    .await
    .map_err(db)?;
    tx.commit().await?;
    Ok(done.rows_affected())
}

pub(super) async fn append_audit_chain(
    conn: &mut SqliteConnection,
    entry: AuditEntry<'_>,
) -> Result<(), StoreError> {
    let prev: Option<Vec<u8>> = sqlx::query_scalar("SELECT entry_hash FROM audit_chain_head WHERE id = 1")
        .fetch_optional(&mut *conn)
        .await
        .map_err(db)?;
    let prev = prev.unwrap_or_else(|| EMPTY_AUDIT_HEAD.to_vec());
    let hash = super::strategy::audit_entry_hash(&prev, &entry).0.to_vec();
    sqlx::query(
        "INSERT INTO audit_events (tenant_id, run_id, actor, event, subject, prev_hash, entry_hash) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(entry.tenant)
    .bind(entry.run)
    .bind(entry.actor)
    .bind(entry.event)
    .bind(entry.subject.to_string())
    .bind(prev)
    .bind(hash.as_slice())
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    sqlx::query("UPDATE audit_chain_head SET entry_hash = ?1 WHERE id = 1")
        .bind(hash.as_slice())
        .execute(&mut *conn)
        .await
        .map_err(db)?;
    Ok(())
}

pub(super) async fn heartbeat_frontier(
    handle: &SqliteHandle,
    worker: Uuid,
    ttl_secs: f64,
    leases: &[(i64, i64)],
) -> Result<Vec<i64>, StoreError> {
    if leases.is_empty() {
        return Ok(Vec::new());
    }
    let mut tx = SqliteBackend::begin_write(handle).await?;
    let now = now_micros();
    let mut extended = Vec::with_capacity(leases.len());
    // three fixed parameters plus two per pair
    for chunk in leases.chunks(SqliteDialect::MAX_BIND_PARAMS.saturating_sub(3) / 2) {
        let pairs = (0..chunk.len())
            .map(|i| format!("(?{}, ?{})", 4 + 2 * i, 5 + 2 * i))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "UPDATE url_frontier SET lease_expires_at = ?1 + CAST(ROUND(?2 * 1000000) AS INTEGER) \
             WHERE lease_owner = ?3 AND status = 'leased' AND lease_expires_at > ?1 \
               AND (frontier_id, fencing_token) IN (VALUES {pairs}) RETURNING frontier_id"
        );
        let mut query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
            .bind(now)
            .bind(ttl_secs)
            .bind(worker);
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
    conn: &mut SqliteConnection,
    run: Uuid,
    lane: &str,
    rows: &[super::strategy::TrafficRow<'_>],
) -> Result<(), StoreError> {
    for chunk in rows.chunks(SqliteDialect::max_batch_rows(TRAFFIC_COLUMNS)) {
        let values = SqliteDialect::values_rows(1, chunk.len(), TRAFFIC_COLUMNS);
        let sql = format!(
            "INSERT INTO traffic_events (occurred_at, run_id, epoch_id, unattributed_reason, seq, lane, origin, third_party, late, \
               method, url_redacted, url_hash, status, request_headers, response_headers, body_artifact_id, request_body_artifact_id, finished_at) \
             {values}"
        );
        let mut query = sqlx::query(sqlx::AssertSqlSafe(sql));
        for t in chunk {
            query = query
                .bind(t.occurred_at.timestamp_micros())
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
                .bind(t.finished_at.map(|at| at.timestamp_micros()));
        }
        query.execute(&mut *conn).await.map_err(db)?;
    }
    Ok(())
}
