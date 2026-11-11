//! `EventRepo` over `crawl_events` (the SSE/webhook outbox).

use crate::backend::strategy::Conn;
use crate::backend::Dialect;
use crate::codec::conv;
use crate::error::not_found;
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{EventRepo, RunEvent};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};

pub(crate) use crate::zdr_project::json_digest as metadata_digest;
pub(crate) use crate::zdr_project::label as metadata_label;

const SIDEBAND_PAGE: i64 = i64::MIN + 1;

/// Check live authority independently of content expiry for immutable receipt acknowledgement.
/// Return source expiry and database time so disclosure can additionally enforce retention.
pub(super) async fn check_head_authority<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    tenant: TenantId,
) -> Result<(bool, Timestamp), StoreError> {
    if crate::tenant::current().is_some_and(|current| current != tenant) {
        return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
    }
    let clock = <B::Dialect as Dialect>::clock_timestamp();
    let authority = stmt!(
        B,
        format!(
            "SELECT COALESCE(r.terminal_reason::text='authorization_revoked',false) OR \
             (r.authorization_record_id IS NOT NULL AND NOT EXISTS (\
                 SELECT 1 FROM authorization_records a \
                 WHERE a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id \
                 AND a.revoked_at IS NULL AND a.valid_from<={clock} \
                 AND a.valid_to>{clock} \
                 AND (r.authorization_body_digest IS NULL OR r.authorization_body_digest=a.body_digest)\
             )) AS revoked, \
             r.expires_at IS NOT NULL AND r.expires_at<={clock} AS expired, \
             {clock} AS checked_at FROM crawl_runs r WHERE r.run_id=$1 AND r.tenant_id=$2"
        )
    )
    .uuid(run.0)
    .uuid(tenant.0)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(StoreError::LeaseLost)?;
    if authority.flag("revoked")? {
        return Err(StoreError::AccessDenied("HEAD response authority revoked".into()));
    }
    Ok((authority.flag("expired")?, authority.ts("checked_at")?))
}

/// Check the original HEAD source at disclosure, not merely before volatile I/O.
pub(super) async fn check_head_source<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    tenant: TenantId,
    deadline: Option<Timestamp>,
) -> Result<(), StoreError> {
    let (expired, checked_at) = check_head_authority::<B>(conn, run, tenant).await?;
    if expired || deadline.is_some_and(|end| end <= checked_at) {
        return Err(StoreError::RetentionDenied(
            "committed HEAD source expired".into(),
        ));
    }
    Ok(())
}

/// Read the single scoped blob shared by HEAD replay and event disclosure.
pub(super) async fn read_head_response<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
    request_id: i64,
) -> Result<((Digest, serde_json::Value), Timestamp), StoreError> {
    check_head_source::<B>(conn, run, tenant, None).await?;
    let missing = || StoreError::RetentionDenied("volatile HEAD response is unavailable".into());
    let page = store
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
    check_head_source::<B>(conn, run, tenant, Some(page.expires_at)).await?;
    Ok((payload, page.expires_at))
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
pub(crate) async fn append_event<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    run: CrawlRunId,
    kind: &str,
    payload: serde_json::Value,
) -> Result<u64, StoreError> {
    append_event_inner(store, conn, run, kind, payload, None).await
}

/// Publish HEAD only from the validated fenced request transaction.
pub(super) async fn append_head_response<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    run: CrawlRunId,
    receipt: Digest,
    payload: serde_json::Value,
) -> Result<u64, StoreError> {
    append_event_inner(store, conn, run, "head_response", payload, Some(receipt)).await
}

async fn append_event_inner<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
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
    let seq = next_event_seq::<B>(conn, run).await?;
    let (tenant, zdr) = Store::<B>::privacy_scope_tx(conn, run).await?;
    let payload = if zdr {
        if let Some(receipt) = head_receipt {
            let request_id = payload
                .get("requestId")
                .and_then(serde_json::Value::as_i64)
                .filter(|id| *id > 0)
                .ok_or_else(|| StoreError::Conflict("invalid HEAD response request reference".into()))?;
            // One insertion binds observation and receipt to exactly one original TTL.
            store
                .ephemeral_put(
                    tenant,
                    run,
                    SIDEBAND_PAGE,
                    &format!("_head_response_receipt:{request_id}"),
                    &(receipt, &payload),
                )
                .await?;
            serde_json::json!({"volatileHeadResponse": true, "requestId": request_id})
        } else {
            store
                .ephemeral_put(
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
    stmt!(
        B,
        "INSERT INTO crawl_events (run_id, seq, type, payload) VALUES ($1, $2, $3, $4)"
    )
    .uuid(run.0)
    .i64(seq)
    .text(&stored_kind)
    .json(&payload)
    .execute(&mut *conn)
    .await?;
    conv(seq, "event seq")
}

/// Bump and read `crawl_runs.event_seq`. MariaDB has no `UPDATE .. RETURNING`: the update
/// holds the row lock until commit, so reading the value back in the same transaction is exact.
async fn next_event_seq<B: Sql>(conn: &mut Conn<B>, run: CrawlRunId) -> Result<i64, StoreError> {
    let seq = if B::KIND == crate::backend::BackendKind::Postgres {
        stmt!(
            B,
            "UPDATE crawl_runs SET event_seq = event_seq + 1 WHERE run_id = $1 RETURNING event_seq"
        )
        .uuid(run.0)
        .fetch_optional(&mut *conn)
        .await?
        .map(|row| row.i64("event_seq"))
        .transpose()?
    } else {
        let bumped = stmt!(
            B,
            "UPDATE crawl_runs SET event_seq = event_seq + 1 WHERE run_id = $1"
        )
        .uuid(run.0)
        .execute(&mut *conn)
        .await?;
        if bumped == 0 {
            None
        } else {
            let row = stmt!(B, "SELECT event_seq FROM crawl_runs WHERE run_id = $1")
                .uuid(run.0)
                .fetch_one(&mut *conn)
                .await?;
            Some(row.i64("event_seq")?)
        }
    };
    seq.ok_or_else(|| not_found("crawl_run", run))
}

#[async_trait]
impl<B: Sql> EventRepo for Store<B> {
    async fn append(
        &self,
        run: CrawlRunId,
        kind: &str,
        payload: serde_json::Value,
    ) -> Result<u64, StoreError> {
        let _timer = self.query_timer("event.append");
        let mut tx = self.begin_write().await?;
        let seq = append_event(self, tx.conn(), run, kind, payload).await?;
        tx.commit().await?;
        Ok(seq)
    }

    async fn list_metadata_after(
        &self,
        run: CrawlRunId,
        after_seq: u64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, StoreError> {
        let _timer = self.query_timer("event.list_metadata_after");
        let rows = stmt!(
            B,
            "SELECT seq, type, payload, created_at FROM crawl_events WHERE run_id = $1 AND seq > $2 ORDER BY seq LIMIT $3"
        )
        .uuid(run.0)
        .i64(conv::<u64, i64>(after_seq, "after_seq")?)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RunEvent {
                    seq: conv(row.i64("seq")?, "seq")?,
                    kind: row.text("type")?,
                    payload: row.json("payload")?,
                    at: row.ts("created_at")?,
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
        let rows = stmt!(
            B,
            "SELECT seq, type, payload, created_at, metadata_only_audit_id FROM crawl_events WHERE run_id = $1 AND seq > $2 ORDER BY seq LIMIT $3"
        )
        .uuid(run.0)
        .i64(conv::<u64, i64>(after_seq, "after_seq")?)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut events = Vec::with_capacity(rows.len());
        let mut head_deadline: Option<Timestamp> = None;
        let mut disclosed_head = false;
        for r in &rows {
            let seq = conv(r.i64("seq")?, "seq")?;
            let stored_kind: String = r.text("type")?;
            // SQL-authored safety pauses have authenticated, metadata-only custody.
            // Never infer this exception from a missing sideband or a familiar kind.
            let metadata_only = r.opt_i64("metadata_only_audit_id")?.is_some();
            let (kind, payload) = if stored_kind == "head_response" {
                disclosed_head = true;
                let mut conn = self.begin_read().await?;
                if zdr {
                    let marker: serde_json::Value = r.json("payload")?;
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
                        read_head_response(self, conn.conn(), tenant, run, request_id).await?;
                    head_deadline = Some(head_deadline.map_or(deadline, |prior| prior.min(deadline)));
                    (stored_kind, payload)
                } else {
                    check_head_source::<B>(conn.conn(), run, tenant, None).await?;
                    (stored_kind, r.json("payload")?)
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
                (stored_kind, r.json("payload")?)
            };
            events.push(RunEvent {
                seq,
                kind,
                payload,
                at: r.ts("created_at")?,
            });
        }
        if disclosed_head {
            let mut conn = self.begin_read().await?;
            check_head_source::<B>(conn.conn(), run, tenant, head_deadline).await?;
        }
        Ok(events)
    }
}
