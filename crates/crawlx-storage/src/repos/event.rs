//! `EventRepo` over `crawl_events` (the SSE/webhook outbox).

use crate::codec::{conv, get};
use crate::error::{db, not_found};
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{EventRepo, RunEvent};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};
use sqlx::PgConnection;

const SIDEBAND_PAGE: i64 = i64::MIN + 1;

/// Check live authority independently of content expiry for immutable receipt acknowledgement.
/// Return source expiry and database time so disclosure can additionally enforce retention.
pub(super) async fn check_head_authority(
    conn: &mut PgConnection,
    run: CrawlRunId,
    tenant: TenantId,
) -> Result<(bool, Timestamp), StoreError> {
    if crate::tenant::current().is_some_and(|current| current != tenant) {
        return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
    }
    let authority = sqlx::query(
        "SELECT COALESCE(r.terminal_reason::text='authorization_revoked',false) OR \
         (r.authorization_record_id IS NOT NULL AND NOT EXISTS (\
             SELECT 1 FROM authorization_records a \
             WHERE a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id \
             AND a.revoked_at IS NULL AND a.valid_from<=clock_timestamp() \
             AND a.valid_to>clock_timestamp() \
             AND (r.authorization_body_digest IS NULL OR r.authorization_body_digest=a.body_digest)\
         )) AS revoked, \
         r.expires_at IS NOT NULL AND r.expires_at<=clock_timestamp() AS expired, \
         clock_timestamp() AS checked_at FROM crawl_runs r WHERE r.run_id=$1 AND r.tenant_id=$2",
    )
    .bind(run.0)
    .bind(tenant.0)
    .fetch_optional(&mut *conn)
    .await
    .map_err(db)?
    .ok_or(StoreError::LeaseLost)?;
    if get::<bool>(&authority, "revoked")? {
        return Err(StoreError::AccessDenied("HEAD response authority revoked".into()));
    }
    Ok((get(&authority, "expired")?, get(&authority, "checked_at")?))
}

/// Check the original HEAD source at disclosure, not merely before volatile I/O.
pub(super) async fn check_head_source(
    conn: &mut PgConnection,
    run: CrawlRunId,
    tenant: TenantId,
    deadline: Option<Timestamp>,
) -> Result<(), StoreError> {
    let (expired, checked_at) = check_head_authority(conn, run, tenant).await?;
    if expired || deadline.is_some_and(|end| end <= checked_at) {
        return Err(StoreError::RetentionDenied(
            "committed HEAD source expired".into(),
        ));
    }
    Ok(())
}

/// Read the single scoped blob shared by HEAD replay and event disclosure.
pub(super) async fn read_head_response(
    pg: &Pg,
    conn: &mut PgConnection,
    tenant: TenantId,
    run: CrawlRunId,
    request_id: i64,
) -> Result<((Digest, serde_json::Value), Timestamp), StoreError> {
    check_head_source(conn, run, tenant, None).await?;
    let missing = || StoreError::RetentionDenied("volatile HEAD response is unavailable".into());
    let page = pg
        .delivery
        .as_ref()
        .ok_or_else(missing)?
        .get(tenant, run, SIDEBAND_PAGE)
        .await?
        .ok_or_else(missing)?;
    let blob = page
        .blobs
        .get(&format!("_head_response_receipt:{request_id}"))
        .ok_or_else(missing)?;
    let payload: (Digest, serde_json::Value) = serde_json::from_slice(&blob.bytes)?;
    if payload.1.get("requestId").and_then(serde_json::Value::as_i64) != Some(request_id) {
        return Err(StoreError::RetentionDenied(
            "invalid volatile HEAD response reference".into(),
        ));
    }
    check_head_source(conn, run, tenant, Some(page.expires_at)).await?;
    Ok((payload, page.expires_at))
}

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
            | "head_response"
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
    append_event_inner(pg, conn, run, kind, payload, None).await
}

/// Publish HEAD only from the validated fenced request transaction.
pub(super) async fn append_head_response(
    pg: &Pg,
    conn: &mut PgConnection,
    run: CrawlRunId,
    receipt: Digest,
    payload: serde_json::Value,
) -> Result<u64, StoreError> {
    append_event_inner(pg, conn, run, "head_response", payload, Some(receipt)).await
}

async fn append_event_inner(
    pg: &Pg,
    conn: &mut PgConnection,
    run: CrawlRunId,
    kind: &str,
    payload: serde_json::Value,
    head_receipt: Option<Digest>,
) -> Result<u64, StoreError> {
    if kind == "head_response" && head_receipt.is_none() {
        return Err(StoreError::AccessDenied(
            "HEAD response requires a fenced request commit".into(),
        ));
    }
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
        if let Some(receipt) = head_receipt {
            let request_id = payload
                .get("requestId")
                .and_then(serde_json::Value::as_i64)
                .filter(|id| *id > 0)
                .ok_or_else(|| StoreError::Conflict("invalid HEAD response request reference".into()))?;
            // One insertion binds observation and receipt to exactly one original TTL.
            pg.ephemeral_put(
                tenant,
                run,
                SIDEBAND_PAGE,
                &format!("_head_response_receipt:{request_id}"),
                &(receipt, &payload),
            )
            .await?;
            serde_json::json!({"volatileHeadResponse": true, "requestId": request_id})
        } else {
            pg.ephemeral_put(
                tenant,
                run,
                SIDEBAND_PAGE,
                &format!("_event:{seq}"),
                &(kind, &payload),
            )
            .await?;
            event_metadata(&payload)?
        }
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
        let mut head_deadline: Option<Timestamp> = None;
        let mut disclosed_head = false;
        for r in &rows {
            let seq = conv(get::<i64>(r, "seq")?, "seq")?;
            let stored_kind: String = get(r, "type")?;
            // SQL-authored safety pauses have authenticated, metadata-only custody.
            // Never infer this exception from a missing sideband or a familiar kind.
            let metadata_only = get::<Option<i64>>(r, "metadata_only_audit_id")?.is_some();
            let (kind, payload) = if stored_kind == "head_response" {
                disclosed_head = true;
                let mut conn = self.pool.acquire().await.map_err(db)?;
                if zdr {
                    let marker: serde_json::Value = get(r, "payload")?;
                    let request_id = marker
                        .get("requestId")
                        .and_then(serde_json::Value::as_i64)
                        .filter(|id| *id > 0)
                        .ok_or_else(|| {
                            StoreError::RetentionDenied(
                                "invalid volatile HEAD response event reference".into(),
                            )
                        })?;
                    if metadata_only
                        || marker
                            != serde_json::json!({"volatileHeadResponse": true, "requestId": request_id})
                    {
                        return Err(StoreError::RetentionDenied(
                            "invalid volatile HEAD response event marker".into(),
                        ));
                    }
                    let ((_, payload), deadline) =
                        read_head_response(self, &mut conn, tenant, run, request_id).await?;
                    head_deadline = Some(head_deadline.map_or(deadline, |prior| prior.min(deadline)));
                    (stored_kind, payload)
                } else {
                    check_head_source(&mut conn, run, tenant, None).await?;
                    (stored_kind, get(r, "payload")?)
                }
            } else if zdr && !metadata_only {
                self.ephemeral_get::<(String, serde_json::Value)>(
                    tenant,
                    run,
                    SIDEBAND_PAGE,
                    &format!("_event:{seq}"),
                )
                .await?
            } else {
                (stored_kind, get(r, "payload")?)
            };
            events.push(RunEvent {
                seq,
                kind,
                payload,
                at: get(r, "created_at")?,
            });
        }
        if disclosed_head {
            let mut conn = self.pool.acquire().await.map_err(db)?;
            check_head_source(&mut conn, run, tenant, head_deadline).await?;
        }
        Ok(events)
    }
}
