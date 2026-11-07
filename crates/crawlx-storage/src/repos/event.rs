//! `EventRepo` over `crawl_events` (the SSE/webhook outbox).

use crate::codec::{conv, get};
use crate::error::{db, not_found};
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::repo::{EventRepo, RunEvent};
use crawlx_core::{CrawlRunId, StoreError};
use sqlx::PgConnection;

const SIDEBAND_PAGE: i64 = i64::MIN + 1;

pub(crate) fn metadata_label<'a>(
    value: &'a str,
    domain: &'static str,
    zdr: bool,
) -> std::borrow::Cow<'a, str> {
    if zdr {
        std::borrow::Cow::Owned(crawlx_core::hash::Digest::of(domain, value.as_bytes()).to_hex())
    } else {
        std::borrow::Cow::Borrowed(value)
    }
}

pub(crate) fn metadata_digest(value: &serde_json::Value) -> Result<serde_json::Value, StoreError> {
    let bytes = serde_json::to_vec(value).map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(serde_json::json!({
        "digest": crawlx_core::hash::Digest::of("crawlx/zdr-metadata/v1", &bytes).to_hex(),
    }))
}

fn event_metadata(payload: &serde_json::Value) -> Result<serde_json::Value, StoreError> {
    let mut metadata = metadata_digest(payload)?;
    for key in ["pageId", "page_id"] {
        if let Some(id) = payload
            .get(key)
            .and_then(serde_json::Value::as_i64)
            .filter(|id| *id >= 0)
        {
            metadata[key] = serde_json::json!(id);
        }
    }
    Ok(metadata)
}

fn known_event_kind(kind: &str) -> bool {
    matches!(
        kind,
        "navigation"
            | "status"
            | "progress"
            | "session"
            | "page"
            | "state"
            | "action"
            | "approval_required"
            | "approval_resolved"
            | "error"
            | "unknown_outcome"
            | "paused"
            | "resumed"
            | "started"
            | "completed"
            | "failed"
            | "session.started"
            | "session.login"
            | "authorization.revoked"
            | "robots_blocked"
            | "secret.resolved"
            | "capture.backend"
            | "capture.proxy.summary"
            | "strategy_arm_assigned"
            | "replay.step_started"
            | "replay.step_completed"
            | "replay.completed"
            | "scrape.action"
            | "action.finished"
            | "action.reconciled"
            | "state_cluster_split"
    )
}

/// Allocate the next `crawl_events.seq` for `run` and insert the event. Runs inside
/// the caller's transaction so T2 and the outbox row commit together.
pub(crate) async fn append_event(
    pg: &Pg,
    conn: &mut PgConnection,
    run: CrawlRunId,
    kind: &str,
    payload: serde_json::Value,
) -> Result<u64, StoreError> {
    let seq: Option<i64> = sqlx::query_scalar(
        "UPDATE crawl_runs SET event_seq = event_seq + 1 WHERE run_id = $1 RETURNING event_seq",
    )
    .bind(run.0)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db)?;
    let seq = seq.ok_or_else(|| not_found("crawl_run", run))?;
    let (tenant, zdr) = Pg::privacy_scope_tx(conn, run).await?;
    let payload = if zdr {
        pg.ephemeral_put(
            tenant,
            run,
            SIDEBAND_PAGE,
            &format!("_event:{seq}"),
            &(kind, &payload),
        )
        .await?;
        event_metadata(&payload)?
    } else {
        payload
    };
    let stored_kind = metadata_label(kind, "crawlx/zdr-event-kind/v1", zdr && !known_event_kind(kind));
    sqlx::query("INSERT INTO crawl_events (run_id, seq, type, payload) VALUES ($1, $2, $3, $4)")
        .bind(run.0)
        .bind(seq)
        .bind(stored_kind)
        .bind(payload)
        .execute(&mut *conn)
        .await
        .map_err(db)?;
    conv(seq, "event seq")
}

#[async_trait]
impl EventRepo for Pg {
    async fn append(
        &self,
        run: CrawlRunId,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StoreError> {
        let _timer = self.query_timer("event.append");
        let mut tx = self.pool.begin().await.map_err(db)?;
        let seq = append_event(self, &mut tx, run, kind, payload).await?;
        tx.commit().await.map_err(db)?;
        Ok(seq)
    }

    async fn list_metadata_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        let _timer = self.query_timer("event.list_metadata_after");
        let rows = sqlx::query("SELECT seq, type, payload, created_at FROM crawl_events WHERE run_id = $1 AND seq > $2 ORDER BY seq LIMIT $3")
            .bind(run.0)
            .bind(conv::<u64, i64>(after_seq, "after_seq")?)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        rows.iter()
            .map(|row| {
                Ok(RunEvent {
                    seq: conv(get::<i64>(row, "seq")?, "seq")?,
                    kind: get(row, "type")?,
                    payload: get(row, "payload")?,
                    at: get(row, "created_at")?,
                })
            })
            .collect()
    }

    async fn list_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        let _timer = self.query_timer("event.list_after");
        let rows = sqlx::query("SELECT seq, type, payload, created_at, metadata_only_audit_id FROM crawl_events WHERE run_id = $1 AND seq > $2 ORDER BY seq LIMIT $3")
            .bind(run.0)
            .bind(conv::<u64, i64>(after_seq, "after_seq")?)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut events = Vec::with_capacity(rows.len());
        for r in &rows {
            let seq = conv(get::<i64>(r, "seq")?, "seq")?;
            // SQL-authored safety pauses have authenticated, metadata-only custody.
            // Never infer this exception from a missing sideband or a familiar kind.
            let metadata_only = get::<Option<i64>>(r, "metadata_only_audit_id")?.is_some();
            let (kind, payload) = if zdr && !metadata_only {
                self.ephemeral_get::<(String, serde_json::Value)>(
                    tenant,
                    run,
                    SIDEBAND_PAGE,
                    &format!("_event:{seq}"),
                )
                .await?
            } else {
                (get(r, "type")?, get(r, "payload")?)
            };
            events.push(RunEvent {
                seq,
                kind,
                payload,
                at: get(r, "created_at")?,
            });
        }
        Ok(events)
    }
}
