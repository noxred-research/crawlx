//! Request extensions of the authoritative URL frontier.
use super::*;
use crate::backend::strategy::Conn;
use crate::backend::{Backend, BackendKind, Dialect, RowLock};
use crate::codec::{canonical_to_json, conv, from_json, parse_label};
use crate::error::not_found;
use crate::sql::{in_ids, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use crawlx_core::acquisition::{AcquisitionAllowanceV1, AcquisitionUsageV1};
use crawlx_core::extensions::ExtensionReceiptV1;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::*;
use crawlx_core::repo::RunRepo;
use crawlx_core::request::{RequestEnvelopeV1, RequestIdentityV1};
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use std::collections::{BTreeMap, BTreeSet};

// A ZDR receipt marks only the committed transaction. Its content hash and observation
// share one volatile blob in the original run-sideband page; replay never renews its TTL.
pub(super) const ZDR_HEAD_RECEIPT_MARKER: [u8; 32] = [0; 32];

/// A select-list expression that has no name of its own (`EXISTS(..)`, `max(..)`, a bare
/// comparison). PostgreSQL derives `pg` from the expression, so its statement text stays as
/// it always was; the other engines get the explicit alias.
#[derive(Clone, Copy)]
struct Unnamed {
    pg: &'static str,
    alias: &'static str,
    clause: &'static str,
}

const EXISTS: Unnamed = Unnamed {
    pg: "exists",
    alias: "present",
    clause: " AS present",
};
const LATEST: Unnamed = Unnamed {
    pg: "max",
    alias: "latest",
    clause: " AS latest",
};
const CLOCK: Unnamed = Unnamed {
    pg: "clock_timestamp",
    alias: "now",
    clause: " AS now",
};

impl Unnamed {
    /// Text to splice right after the expression.
    fn clause<B: Backend>(self) -> &'static str {
        if B::KIND == BackendKind::Postgres {
            ""
        } else {
            self.clause
        }
    }

    /// The result column to read the expression from.
    fn column<B: Backend>(self) -> &'static str {
        if B::KIND == BackendKind::Postgres {
            self.pg
        } else {
            self.alias
        }
    }
}

/// `base` moved forward by the seconds bound at `secs`. PostgreSQL keeps the compact spelling
/// the statements have always used.
fn plus_secs<B: Backend>(base: &str, secs: &str) -> String {
    if B::KIND == BackendKind::Postgres {
        format!("{base}+make_interval(secs=>{secs})")
    } else {
        <B::Dialect as Dialect>::add_seconds(base, secs)
    }
}

pub(super) async fn check_head_response_receipt<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    commit: &RequestCommitV1,
    tenant: TenantId,
    zdr: bool,
    stored: &[u8],
    receipt: Option<Digest>,
) -> Result<(), StoreError> {
    let matches = if zdr {
        if stored != ZDR_HEAD_RECEIPT_MARKER.as_slice() {
            return Err(StoreError::RetentionDenied(
                "invalid volatile HEAD response receipt marker".into(),
            ));
        }
        let ((live, _), _) =
            crate::repos::event::read_head_response(store, conn, tenant, commit.run, commit.request_id)
                .await?;
        receipt == Some(live)
    } else {
        crate::repos::event::check_head_authority::<B>(conn, commit.run, tenant).await?;
        receipt.is_some_and(|receipt| receipt.0.as_slice() == stored)
    };
    if matches {
        Ok(())
    } else {
        Err(StoreError::Conflict("HEAD response receipt changed".into()))
    }
}

pub(super) async fn lock_run<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
) -> Result<(TenantId, bool), StoreError> {
    let row = stmt!(
        B,
        format!(
            "SELECT tenant_id, retention_mode = 'zdr' AS zdr, status::text AS status, deadline_at FROM crawl_runs WHERE run_id=$1{lock}",
            lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
        )
    )
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| not_found("crawl run", run))?;
    Ok((TenantId(row.uuid("tenant_id")?), row.flag("zdr")?))
}

/// Create the producer row of a run when it does not exist yet. The caller holds the run lock.
async fn ensure_producer<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    tenant: TenantId,
) -> Result<(), StoreError> {
    stmt!(
        B,
        format!(
            "INSERT INTO frontier_producers(run_id,tenant_id) VALUES($1,$2) {conflict}",
            conflict = if B::KIND == BackendKind::Postgres {
                "ON CONFLICT DO NOTHING".to_owned()
            } else {
                <B::Dialect as Dialect>::upsert_do_nothing(&["run_id"])
            },
        )
    )
    .uuid(run.0)
    .uuid(tenant.0)
    .execute(conn)
    .await?;
    Ok(())
}

/// Exact scope of one callback trail. Every field is part of the durable dedupe key.
#[derive(Clone, Copy)]
pub(super) struct ExtensionAttemptKey {
    pub(super) tenant: TenantId,
    pub(super) run: CrawlRunId,
    pub(super) request_id: i64,
    pub(super) fence: i64,
    pub(super) attempt: u32,
}

pub(super) fn validate_extension_trail(receipts: &[ExtensionReceiptV1]) -> Result<(), StoreError> {
    crawlx_core::extensions::validate_extension_receipts(receipts)
        .map_err(|_| StoreError::Conflict("invalid extension attempt receipts".into()))
}

pub(super) fn extension_digest(receipts: &[ExtensionReceiptV1]) -> Result<Digest, StoreError> {
    Digest::of_value("crawlx/extension-attempt/v1", &receipts)
        .map_err(|error| StoreError::Serialization(error.to_string()))
}

/// Persist one complete callback trail inside a transaction that already holds the run lock and
/// the live request-row lock for exactly this fence and attempt. The digest row is the only
/// dedupe authority; the receipts themselves are a typed `extension_attempt` event, which the
/// existing ZDR projection already withholds. The event allocator is confined to this helper.
pub(super) async fn persist_extension_attempt<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    key: ExtensionAttemptKey,
    receipts: &[ExtensionReceiptV1],
) -> Result<(), StoreError> {
    let attempt = i32::try_from(key.attempt)
        .ok()
        .filter(|attempt| (1..=i32::from(i16::MAX)).contains(attempt))
        .ok_or_else(|| StoreError::Conflict("invalid extension attempt".into()))?;
    let digest = extension_digest(receipts)?;
    let stored = stmt!(
        B,
        "SELECT digest FROM extension_attempts WHERE tenant_id=$1 AND run_id=$2 AND request_id=$3 AND fence=$4 AND attempt=$5"
    )
    .uuid(key.tenant.0)
    .uuid(key.run.0)
    .i64(key.request_id)
    .i64(key.fence)
    .i32(attempt)
    .fetch_optional(&mut *conn)
    .await?
    .map(|row| row.bytes("digest"))
    .transpose()?;
    if let Some(stored) = stored {
        return if stored.as_slice() == digest.0.as_slice() {
            Ok(())
        } else {
            Err(StoreError::Conflict("extension attempt receipts changed".into()))
        };
    }
    if receipts.is_empty() {
        return Ok(());
    }
    let mut payload = serde_json::Map::new();
    payload.insert("requestId".into(), key.request_id.into());
    payload.insert("fence".into(), key.fence.into());
    payload.insert("attempt".into(), key.attempt.into());
    payload.insert("digest".into(), digest.to_hex().into());
    payload.insert("receipts".into(), serde_json::to_value(receipts)?);
    let seq = crate::repos::event::append_event::<B>(
        store,
        conn,
        key.run,
        "extension_attempt",
        serde_json::Value::Object(payload),
    )
    .await?;
    stmt!(
        B,
        "INSERT INTO extension_attempts (tenant_id,run_id,request_id,fence,attempt,digest,event_seq) VALUES ($1,$2,$3,$4,$5,$6,$7)"
    )
    .uuid(key.tenant.0)
    .uuid(key.run.0)
    .i64(key.request_id)
    .i64(key.fence)
    .i32(attempt)
    .bytes(digest.0.as_slice())
    .i64(conv::<u64, i64>(seq, "event seq")?)
    .execute(conn)
    .await?;
    Ok(())
}

pub(super) async fn append<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    batch: &RequestBatchV1,
    cfg: &OrchestrationConfigV1,
    completing: bool,
    observed_timing: Option<(crawlx_core::Timestamp, crawlx_core::Timestamp)>,
    duration_seconds: u32,
) -> Result<RequestBatchReceiptV1, StoreError> {
    batch.validate()?;
    let digest = Digest::of_value("crawlx/request-batch/v1", batch)
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    let (tenant, zdr) = lock_run::<B>(conn, batch.run).await?;
    if tenant != batch.tenant {
        return Err(StoreError::AccessDenied("request tenant mismatch".into()));
    }
    if let Some(row) = stmt!(
        B,
        "SELECT batch_digest,receipt FROM frontier_batch_receipts WHERE run_id=$1 AND batch_id=$2"
    )
    .uuid(batch.run.0)
    .bytes(batch.batch_id.0.as_slice())
    .fetch_optional(&mut *conn)
    .await?
    {
        if zdr {
            let reference = row
                .json("receipt")?
                .get("volatileRef")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| StoreError::Serialization("missing volatile batch reference".into()))?
                .to_owned();
            let (stored, receipt): (Digest, RequestBatchReceiptV1) = store
                .ephemeral_get(
                    tenant,
                    batch.run,
                    i64::MIN + 1,
                    &format!("_request_batch:{reference}"),
                )
                .await?;
            if stored != digest {
                return Err(StoreError::Conflict(
                    "batch id reused with different content".into(),
                ));
            }
            return Ok(receipt);
        }
        if row.bytes("batch_digest")? != digest.0 {
            return Err(StoreError::Conflict(
                "batch id reused with different content".into(),
            ));
        }
        return from_json(row.json("receipt")?);
    }
    // A queued run may not have deadline_at yet; dispatch still uses its original ceiling.
    let observed_deadline = observed_timing.map(|(_, deadline)| deadline);
    let observed_acquired = observed_timing.map(|(acquired_at, _)| acquired_at);
    let admission = stmt!(
        B,
        format!(
            "SELECT status IN ('queued','running','paused') AND cancel_requested_at IS NULL AND purge_requested_at IS NULL AND ($3::timestamptz IS NULL OR $3<={clock}) AS admits, COALESCE($2,deadline_at,{due})>COALESCE($3,{clock}) AS before_deadline FROM crawl_runs WHERE run_id=$1",
            due = plus_secs::<B>("COALESCE(started_at,created_at)", "$4"),
            clock = <B::Dialect as Dialect>::clock_timestamp(),
        )
    )
    .uuid(batch.run.0)
    .opt_ts(observed_deadline)
    .opt_ts(observed_acquired)
    .f64(f64::from(duration_seconds))
    .fetch_one(&mut *conn)
    .await?;
    if !admission.flag("admits")? {
        return Err(StoreError::AccessDenied("run no longer admits requests".into()));
    }
    if !admission.flag("before_deadline")? {
        return Err(StoreError::RunDeadlineReached);
    }
    cfg.validate()?;
    if batch.requests.len() > usize::try_from(cfg.queue.batch_size).unwrap_or(0) {
        return Err(StoreError::Conflict("configured request batch limit".into()));
    }
    if batch.principal != "anonymous"
        && !stmt!(
            B,
            format!(
                "SELECT EXISTS(SELECT 1 FROM crawl_sessions WHERE run_id=$1 AND role=$2){alias}",
                alias = EXISTS.clause::<B>(),
            )
        )
        .uuid(batch.run.0)
        .text(&batch.principal)
        .fetch_one(&mut *conn)
        .await?
        .flag(EXISTS.column::<B>())?
    {
        return Err(StoreError::AccessDenied("request principal unavailable".into()));
    }
    ensure_producer::<B>(conn, batch.run, tenant).await?;
    let producer = stmt!(
        B,
        format!(
            "SELECT epoch,sealed FROM frontier_producers WHERE run_id=$1{lock}",
            lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
        )
    )
    .uuid(batch.run.0)
    .fetch_one(&mut *conn)
    .await?;
    if producer.i64("epoch")?
        != i64::try_from(batch.producer_epoch)
            .map_err(|_| StoreError::Conflict("producer epoch overflow".into()))?
        || (producer.bool("sealed")? && batch.parent_fence.is_none() && observed_timing.is_none())
    {
        return Err(StoreError::Conflict("producer epoch closed or stale".into()));
    }
    if let Some((id, fence)) = batch.parent_fence {
        let live = stmt!(
            B,
            format!(
                "SELECT frontier_id FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>{clock}{lock}",
                clock = <B::Dialect as Dialect>::clock_timestamp(),
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
            )
        )
        .i64(id)
        .uuid(batch.run.0)
        .i64(fence)
        .fetch_optional(&mut *conn)
        .await?;
        if live.is_none() {
            return Err(StoreError::LeaseLost);
        }
    }
    if let Some(next) = &batch.next_cursor {
        let stored = stmt!(
            B,
            format!(
                "SELECT {cursor} FROM frontier_loader_cursors WHERE run_id=$1 AND source_id=$2{lock}",
                cursor = <B::Dialect as Dialect>::reserved_ident("cursor"),
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
            )
        )
        .uuid(batch.run.0)
        .text(&next.source)
        .fetch_optional(&mut *conn)
        .await?
        .map(|row| row.json("cursor"))
        .transpose()?;
        let cursor = match stored {
            Some(value) if zdr => {
                let reference = value
                    .get("volatileRef")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| StoreError::Serialization("missing volatile cursor reference".into()))?;
                Some(
                    store
                        .ephemeral_get::<LoaderCursorV1>(
                            tenant,
                            batch.run,
                            i64::MIN + 1,
                            &format!("_request_cursor:{reference}"),
                        )
                        .await?,
                )
            }
            Some(value) => Some(from_json::<LoaderCursorV1>(value)?),
            None => None,
        };
        if cursor != batch.expected_cursor {
            return Err(StoreError::Conflict("loader cursor changed".into()));
        }
    }
    let mut receipt = RequestBatchReceiptV1::empty(batch.next_cursor.clone());
    let mut seen = BTreeSet::new();
    let mut staged = Vec::with_capacity(batch.requests.len());
    let mut reserved = 0_i64;
    for envelope in &batch.requests {
        if observed_timing.is_none() && envelope.metadata.contains_key("observed_epoch") {
            return Err(StoreError::AccessDenied(
                "observation requires session transaction".into(),
            ));
        }
        if envelope.revisit_generation != 0 && !completing {
            return Err(StoreError::AccessDenied(
                "revisit requires recrawl transaction".into(),
            ));
        }
        let identity = envelope
            .identity(tenant, batch.run, &batch.principal, &BTreeMap::new(), 1)
            .map_err(|e| StoreError::Conflict(e.to_string()))?;
        let exists = stmt!(
            B,
            format!(
                "SELECT EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND canonical_key=$2 AND revisit_generation=$3){alias}",
                alias = EXISTS.clause::<B>(),
            )
        )
        .uuid(batch.run.0)
        .bytes(identity.key.0.as_slice())
        .i64(i64::from(identity.revisit_generation))
        .fetch_one(&mut *conn)
        .await?
        .flag(EXISTS.column::<B>())?;
        if exists || !seen.insert((identity.key, identity.revisit_generation)) {
            receipt.duplicates = receipt.duplicates.saturating_add(1);
            continue;
        }
        let bytes = i64::try_from(serde_json::to_vec(envelope)?.len())
            .map_err(|_| StoreError::Conflict("request size overflow".into()))?;
        reserved = reserved
            .checked_add(bytes)
            .ok_or_else(|| StoreError::Conflict("request size overflow".into()))?;
        staged.push((envelope, identity, bytes));
    }
    let releasing = if completing {
        batch.parent_fence.map(|(id, _)| id)
    } else {
        None
    };
    let counts = stmt!(
        B,
        format!(
            "SELECT count(*) AS entries,{bytes} AS bytes FROM url_frontier WHERE run_id=$1 AND status IN ('pending','leased') AND ($2::bigint IS NULL OR frontier_id<>$2)",
            bytes = <B::Dialect as Dialect>::cast_i64("COALESCE(sum(envelope_bytes),0)"),
        )
    )
    .uuid(batch.run.0)
    .opt_i64(releasing)
    .fetch_one(&mut *conn)
    .await?;
    let extra_entries = if batch.initial_denial.is_none() {
        u64::try_from(staged.len()).unwrap_or(u64::MAX)
    } else {
        0
    };
    let extra_bytes = if batch.initial_denial.is_none() {
        reserved
    } else {
        0
    };
    if u64::try_from(counts.i64("entries")?)
        .unwrap_or(u64::MAX)
        .saturating_add(extra_entries)
        > cfg.queue.max_pending_entries
        || u64::try_from(counts.i64("bytes")?.saturating_add(extra_bytes)).unwrap_or(u64::MAX)
            > cfg.queue.max_pending_envelope_bytes
    {
        return Err(StoreError::Conflict("frontier quota exhausted".into()));
    }
    for (envelope, identity, bytes) in staged {
        let schema = if zdr {
            serde_json::json!({})
        } else {
            canonical_to_json(&envelope.url)?
        };
        let origin = if zdr {
            Digest::of("crawlx/zdr-origin/v1", envelope.url.origin.as_bytes()).to_hex()
        } else {
            envelope.url.origin.clone()
        };
        let stored_envelope = if zdr {
            None
        } else {
            Some(serde_json::to_value(envelope)?)
        };
        let (denial_status, denial_reason) = match &batch.initial_denial {
            Some((status, reason)) => (status.as_str(), Some(reason.as_str())),
            None => ("pending", None),
        };
        // The reserved source survives volatile envelope expiry and every status transition.
        let id = stmt!(
            B,
            format!(
                "INSERT INTO url_frontier(run_id,canonical_key,canonical_url,origin,query_schema,depth,priority,via,parent_id,principal,route_id,revisit_generation,request_envelope,envelope_bytes,next_attempt_at,status,denial_reason,finished_at,strategy_score{tenant_column}) VALUES($1,$2,$3,$4,$5,$6,$7,$18,$8,$9,$10,$11,$12,$13,COALESCE($14,{now}),$15,$16,CASE WHEN $15<>'pending' THEN {now} END,$17{tenant_value}) RETURNING frontier_id",
                now = <B::Dialect as Dialect>::now(),
                tenant_column = super::tenant_insert::<B>().0,
                tenant_value = super::tenant_insert::<B>().1,
            )
        )
        .uuid(batch.run.0)
        .bytes(identity.key.0.as_slice())
        .opt_text((!zdr).then_some(envelope.url.url.as_str()))
        .text(&origin)
        .json(&schema)
        .i16(conv::<u16, i16>(envelope.depth, "depth")?)
        .f32(f32::from(
            i16::try_from(envelope.priority)
                .map_err(|_| StoreError::Conflict("request priority overflow".into()))?,
        ))
        .opt_i64(envelope.parent)
        .text(&batch.principal)
        .text(&envelope.route)
        .i64(i64::from(identity.revisit_generation))
        .opt_json(stored_envelope.as_ref())
        .i64(bytes)
        .opt_ts(envelope.not_before)
        .text(denial_status)
        .opt_text(denial_reason)
        .i32(conv::<u32, i32>(
            crawlx_core::priority::priority_depth(
                &envelope.url.url,
                u32::from(envelope.depth),
                envelope.method == "GET",
            ),
            "strategy score",
        )?)
        .text(if observed_timing.is_some() { "interaction" } else { "link" })
        .fetch_one(&mut *conn)
        .await?
        .i64("frontier_id")?;
        if zdr {
            store
                .ephemeral_put(
                    tenant,
                    batch.run,
                    operational_page(id)?,
                    "frontier_record",
                    &envelope.url,
                )
                .await?;
            store
                .ephemeral_put(
                    tenant,
                    batch.run,
                    operational_page(id)?,
                    "request_envelope",
                    envelope,
                )
                .await?;
        }
        receipt.inserted.push(id);
    }
    if let Some(cursor) = &batch.next_cursor {
        let stored = if zdr {
            let reference = uuid::Uuid::now_v7().to_string();
            store
                .ephemeral_put(
                    tenant,
                    batch.run,
                    i64::MIN + 1,
                    &format!("_request_cursor:{reference}"),
                    cursor,
                )
                .await?;
            serde_json::json!({"source":cursor.source,"position":cursor.position,"volatileRef":reference})
        } else {
            serde_json::to_value(cursor)?
        };
        let column = <B::Dialect as Dialect>::reserved_ident("cursor");
        stmt!(
            B,
            if B::KIND == BackendKind::Postgres {
                "INSERT INTO frontier_loader_cursors(run_id,tenant_id,source_id,cursor) VALUES($1,$2,$3,$4) ON CONFLICT(run_id,source_id) DO UPDATE SET cursor=excluded.cursor".to_owned()
            } else {
                format!(
                    "INSERT INTO frontier_loader_cursors(run_id,tenant_id,source_id,{column}) VALUES($1,$2,$3,$4) {upsert}",
                    upsert = <B::Dialect as Dialect>::upsert_update(&["run_id", "source_id"], &[column.as_str()], None),
                )
            }
        )
        .uuid(batch.run.0)
        .uuid(tenant.0)
        .text(&cursor.source)
        .json(&stored)
        .execute(&mut *conn)
        .await?;
    }
    let stored_receipt = if zdr {
        let reference = uuid::Uuid::now_v7().to_string();
        store
            .ephemeral_put(
                tenant,
                batch.run,
                i64::MIN + 1,
                &format!("_request_batch:{reference}"),
                &(digest, &receipt),
            )
            .await?;
        serde_json::json!({"inserted":receipt.inserted,"duplicates":receipt.duplicates,"volatileRef":reference})
    } else {
        serde_json::to_value(&receipt)?
    };
    let stored_digest = if zdr {
        Digest::of("crawlx/zdr-batch-reference/v1", &batch.batch_id.0)
    } else {
        digest
    };
    stmt!(
        B,
        "INSERT INTO frontier_batch_receipts(run_id,tenant_id,batch_id,batch_digest,receipt) VALUES($1,$2,$3,$4,$5)"
    )
    .uuid(batch.run.0)
    .uuid(tenant.0)
    .bytes(batch.batch_id.0.as_slice())
    .bytes(stored_digest.0.as_slice())
    .json(&stored_receipt)
    .execute(&mut *conn)
    .await?;
    if let Some((id, fence)) = batch.parent_fence {
        let live = stmt!(
            B,
            format!(
                "SELECT EXISTS(SELECT 1 FROM url_frontier WHERE frontier_id=$1 AND status='leased' AND fencing_token=$2 AND lease_expires_at>{clock}){alias}",
                clock = <B::Dialect as Dialect>::clock_timestamp(),
                alias = EXISTS.clause::<B>(),
            )
        )
        .i64(id)
        .i64(fence)
        .fetch_one(&mut *conn)
        .await?
        .flag(EXISTS.column::<B>())?;
        if !live {
            return Err(StoreError::LeaseLost);
        }
    }
    Ok(receipt)
}

/// The text of a leased row's usage counter, as the number `->>` and `::bigint` would read.
fn usage_counter(usage: Option<&serde_json::Value>, key: &str) -> Option<i64> {
    usage?
        .get(key)
        .and_then(|value| value.as_i64().or_else(|| value.as_u64().map(|_| i64::MAX)))
}

/// The membership clause and select of [`Store::request_methods_bulk`] for one engine.
fn methods_sql(membership: &str) -> String {
    format!(
        "SELECT f.frontier_id,f.request_envelope,f.envelope_bytes,r.tenant_id,r.retention_mode='zdr' AS zdr \
         FROM url_frontier f JOIN crawl_runs r ON r.run_id=f.run_id \
         WHERE f.run_id=$1 AND f.frontier_id{membership}"
    )
}

impl<B: Sql> Store<B> {
    pub(super) async fn request_append(
        &self,
        batch: RequestBatchV1,
    ) -> Result<RequestBatchReceiptV1, StoreError> {
        let run = RunRepo::get(self, batch.run).await?;
        let cfg = run.config.orchestration.clone().unwrap_or_default();
        let mut tx = self.begin_write().await?;
        let receipt = append::<B>(
            self,
            tx.conn(),
            &batch,
            &cfg,
            false,
            None,
            run.config.limits.duration_seconds,
        )
        .await?;
        tx.commit().await?;
        Ok(receipt)
    }
    pub(super) async fn request_metadata_page(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<RequestMetadataV1>, StoreError> {
        if limit == 0 || limit > 1000 {
            return Err(StoreError::Conflict("invalid frontier page limit".into()));
        }
        let rows = stmt!(
            B,
            "SELECT frontier_id,status,depth,attempts,revisit_generation FROM url_frontier WHERE run_id=$1 AND frontier_id>$2 ORDER BY frontier_id LIMIT $3"
        )
        .uuid(run.0)
        .i64(after)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RequestMetadataV1::new(
                    row.i64("frontier_id")?,
                    parse_label(&row.text("status")?)?,
                    conv(row.i16("depth")?, "depth")?,
                    conv(row.i16("attempts")?, "attempts")?,
                    conv(row.i32("revisit_generation")?, "generation")?,
                ))
            })
            .collect()
    }
    pub(super) async fn request_methods_bulk(
        &self,
        run: CrawlRunId,
        ids: &[i64],
    ) -> Result<BTreeMap<i64, String>, StoreError> {
        if ids.len() > 1000 {
            return Err(StoreError::Conflict("invalid request method batch limit".into()));
        }
        if ids.is_empty() {
            return Ok(BTreeMap::new());
        }
        let select = if B::KIND == BackendKind::Postgres {
            stmt!(B, methods_sql("=ANY($2)"))
        } else {
            Stmt::<B>::dynamic(&methods_sql(&in_ids::<B>(2, ids.len())))
        };
        let rows = select
            .uuid(run.0)
            .i64_list(ids)
            .fetch_all_pool(&self.pool)
            .await?;
        let found = rows
            .iter()
            .map(|row| row.i64("frontier_id"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if let Some(id) = ids.iter().find(|id| !found.contains(*id)) {
            return Err(not_found("frontier row", id));
        }
        let mut methods = BTreeMap::new();
        for row in rows {
            let id = row.i64("frontier_id")?;
            let tenant = TenantId(row.uuid("tenant_id")?);
            if crate::tenant::current().is_some_and(|current| current != tenant) {
                return Err(StoreError::AccessDenied("request method tenant mismatch".into()));
            }
            let stored = row.opt_json("request_envelope")?;
            let bytes = row.i64("envelope_bytes")?;
            let method = if row.flag("zdr")? && bytes > 0 {
                let envelope: RequestEnvelopeV1 = self
                    .ephemeral_get(tenant, run, operational_page(id)?, "request_envelope")
                    .await?;
                envelope.method
            } else if let Some(value) = stored {
                value
                    .get("method")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| StoreError::Serialization("missing queued request method".into()))?
                    .to_owned()
            } else if bytes == 0 {
                "GET".to_owned()
            } else {
                return Err(StoreError::Serialization(
                    "missing queued request envelope".into(),
                ));
            };
            methods.insert(id, method);
        }
        Ok(methods)
    }
    pub(super) async fn request_retry(
        &self,
        id: i64,
        fence: i64,
        not_before: crawlx_core::Timestamp,
    ) -> Result<bool, StoreError> {
        let run = stmt!(B, "SELECT run_id FROM url_frontier WHERE frontier_id=$1")
            .i64(id)
            .fetch_optional_pool(&self.pool)
            .await?
            .ok_or_else(|| not_found("frontier row", id))?
            .uuid("run_id")?;
        let record = RunRepo::get(self, CrawlRunId(run)).await?;
        let cfg = record.config.orchestration.as_ref().cloned().unwrap_or_default();
        let native = record.config.acquisition.as_ref();
        cfg.validate()?;
        let max_effects = i64::from(cfg.attempts.max_total_effects);
        let max_elapsed = std::time::Duration::from_millis(cfg.attempts.max_elapsed_ms);
        let max_attempts = native.map_or(i64::MAX, |policy| i64::from(policy.max_attempts));
        let max_network = native.map_or(i64::MAX, |policy| i64::from(policy.max_network_requests));
        let max_decoded = native.map_or(i64::MAX, |policy| {
            i64::try_from(
                policy
                    .max_decoded_bytes
                    .min(record.config.fetch.max_response_bytes),
            )
            .unwrap_or(i64::MAX)
        });
        if B::KIND != BackendKind::Postgres {
            return self
                .request_retry_portable(
                    id,
                    fence,
                    not_before,
                    RetryLimits {
                        effects: max_effects,
                        elapsed: max_elapsed,
                        attempts: max_attempts,
                        network: max_network,
                        decoded: max_decoded,
                    },
                )
                .await;
        }
        let pending = stmt!(
            B,
            "WITH held AS (SELECT frontier_id, \
             (attempts >= $4 OR effect_reservations >= $4 OR $3 >= discovered_at + make_interval(secs => $5) \
              OR $3 >= acquisition_deadline_at \
              OR (acquisition_usage->>'attemptsReserved')::bigint >= $6 \
              OR (acquisition_usage->>'networkRequestsReserved')::bigint >= $7 \
              OR (acquisition_usage->>'decodedBytesReserved')::bigint >= $8) AS exhausted \
             FROM url_frontier WHERE frontier_id=$1 AND status='leased' AND fencing_token=$2 AND lease_expires_at>clock_timestamp() FOR UPDATE) \
             UPDATE url_frontier f SET status=CASE WHEN COALESCE(held.exhausted,false) THEN 'failed' ELSE 'pending' END, \
             error_code=CASE WHEN COALESCE(held.exhausted,false) THEN 'effect_budget_exhausted' ELSE error_code END, \
             lease_owner=NULL,lease_expires_at=NULL,next_attempt_at=GREATEST(next_attempt_at,$3) \
             FROM held WHERE f.frontier_id=held.frontier_id RETURNING f.status='pending'"
        )
        .i64(id)
        .i64(fence)
        .ts(not_before)
        .i64(max_effects)
        .f64(max_elapsed.as_secs_f64())
        .i64(max_attempts)
        .i64(max_network)
        .i64(max_decoded)
        .fetch_optional_write(&self.pool)
        .await?;
        pending.ok_or(StoreError::LeaseLost)?.flag("?column?")
    }
    /// [`Store::request_retry`] for engines without `UPDATE .. FROM` over a locking CTE: read
    /// the leased row under the write lock, decide in Rust, then update it by key.
    async fn request_retry_portable(
        &self,
        id: i64,
        fence: i64,
        not_before: crawlx_core::Timestamp,
        limits: RetryLimits,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_write().await?;
        let held = stmt!(
            B,
            format!(
                "SELECT attempts,effect_reservations,discovered_at,acquisition_deadline_at,acquisition_usage \
                 FROM url_frontier WHERE frontier_id=$1 AND status='leased' AND fencing_token=$2 AND lease_expires_at>{clock}{lock}",
                clock = <B::Dialect as Dialect>::clock_timestamp(),
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
            )
        )
        .i64(id)
        .i64(fence)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        let usage = held.opt_json("acquisition_usage")?;
        let discovered = held.ts("discovered_at")?;
        let elapsed_end = chrono::Duration::from_std(limits.elapsed)
            .ok()
            .and_then(|elapsed| discovered.checked_add_signed(elapsed));
        let exhausted = i64::from(held.i16("attempts")?) >= limits.effects
            || held.i64("effect_reservations")? >= limits.effects
            || elapsed_end.is_some_and(|end| not_before >= end)
            || held
                .opt_ts("acquisition_deadline_at")?
                .is_some_and(|deadline| not_before >= deadline)
            || usage_counter(usage.as_ref(), "attemptsReserved").is_some_and(|used| used >= limits.attempts)
            || usage_counter(usage.as_ref(), "networkRequestsReserved")
                .is_some_and(|used| used >= limits.network)
            || usage_counter(usage.as_ref(), "decodedBytesReserved")
                .is_some_and(|used| used >= limits.decoded);
        let updated = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET status=$2,error_code=COALESCE($3,error_code), \
                 lease_owner=NULL,lease_expires_at=NULL,next_attempt_at={later} WHERE frontier_id=$1",
                later = <B::Dialect as Dialect>::greatest_ignoring_null(&["next_attempt_at", "$4"]),
            )
        )
        .i64(id)
        .text(if exhausted { "failed" } else { "pending" })
        .opt_text(exhausted.then_some("effect_budget_exhausted"))
        .ts(not_before)
        .execute(tx.conn())
        .await?;
        if updated != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await?;
        Ok(!exhausted)
    }
    pub(super) async fn request_reserve(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        effects: u32,
    ) -> Result<(), StoreError> {
        if effects == 0 {
            return Err(StoreError::Conflict("empty effect reservation".into()));
        }
        let cfg = RunRepo::get(self, run)
            .await?
            .config
            .orchestration
            .unwrap_or_default();
        cfg.validate()?;
        let clock = <B::Dialect as Dialect>::clock_timestamp();
        let reserved = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET effect_reservations=effect_reservations+$4,effect_escrow_fence=$3,effect_escrow_amount=$4,effect_escrow_settlement=NULL WHERE frontier_id=$1 AND run_id=$2 \
                 AND status='leased' AND fencing_token=$3 AND lease_expires_at>{clock} AND effect_reservations+$4 <= $5 \
                 AND (effect_escrow_fence IS NULL OR effect_escrow_fence<>$3) AND {clock}<{due}",
                due = plus_secs::<B>("discovered_at", "$6"),
            )
        )
        .i64(id)
        .uuid(run.0)
        .i64(fence)
        .i64(i64::from(effects))
        .i64(i64::from(cfg.attempts.max_total_effects))
        .f64(std::time::Duration::from_millis(cfg.attempts.max_elapsed_ms).as_secs_f64())
        .execute_write(&self.pool)
        .await?;
        if reserved != 1 {
            let live = stmt!(
                B,
                format!(
                    "SELECT EXISTS(SELECT 1 FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>{clock}){alias}",
                    alias = EXISTS.clause::<B>(),
                )
            )
            .i64(id)
            .uuid(run.0)
            .i64(fence)
            .fetch_one_pool(&self.pool)
            .await?
            .flag(EXISTS.column::<B>())?;
            return Err(if live {
                StoreError::Conflict("request effect budget or deadline exhausted".into())
            } else {
                StoreError::LeaseLost
            });
        }
        Ok(())
    }
    pub(super) async fn request_settle_effects(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        reserved: u32,
        actual: u32,
    ) -> Result<(), StoreError> {
        if actual > reserved {
            return Err(StoreError::Conflict(
                "effect settlement exceeds lease escrow".into(),
            ));
        }
        let mut tx = self.begin_write().await?;
        let clock = <B::Dialect as Dialect>::clock_timestamp();
        let row = stmt!(
            B,
            format!(
                "SELECT effect_reservations,effect_escrow_amount,effect_escrow_settlement FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>{clock} AND effect_escrow_fence=$3{lock}",
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
            )
        )
        .i64(id)
        .uuid(run.0)
        .i64(fence)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        if row.opt_i64("effect_escrow_amount")? != Some(i64::from(reserved)) {
            return Err(StoreError::Conflict(
                "effect settlement exceeds lease escrow".into(),
            ));
        }
        if let Some(prior) = row.opt_i64("effect_escrow_settlement")? {
            return if prior == i64::from(actual) {
                Ok(())
            } else {
                Err(StoreError::Conflict("effect settlement changed".into()))
            };
        }
        let remaining = row
            .i64("effect_reservations")?
            .checked_sub(i64::from(reserved - actual))
            .filter(|value| *value >= 0)
            .ok_or_else(|| StoreError::Conflict("effect settlement mismatch".into()))?;
        let settled = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET effect_reservations=$2,effect_escrow_settlement=$3 WHERE frontier_id=$1 AND lease_expires_at>{clock}"
            )
        )
        .i64(id)
        .i64(remaining)
        .i64(i64::from(actual))
        .execute(tx.conn())
        .await?;
        if settled != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await
    }
    pub(super) async fn acquisition_reserve(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
    ) -> Result<AcquisitionAllowanceV1, StoreError> {
        let record = RunRepo::get(self, run).await?;
        let policy = record
            .config
            .acquisition
            .as_ref()
            .ok_or_else(|| StoreError::Conflict("native acquisition policy required".into()))?;
        policy
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let mut tx = self.begin_write().await?;
        let clock = <B::Dialect as Dialect>::clock_timestamp();
        let row = stmt!(
            B,
            format!(
                "SELECT discovered_at,effect_reservations,acquisition_deadline_at,acquisition_usage,acquisition_escrow_fence,{now} AS registry_now \
                 FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>{clock}{lock}",
                now = <B::Dialect as Dialect>::now(),
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
            )
        )
        .i64(id)
        .uuid(run.0)
        .i64(fence)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        if row.opt_i64("acquisition_escrow_fence")? == Some(fence) {
            return Err(StoreError::Conflict(
                "acquisition already reserved by this lease".into(),
            ));
        }
        let now = stmt!(B, format!("SELECT {clock}{alias}", alias = CLOCK.clause::<B>()))
            .fetch_one(tx.conn())
            .await?
            .ts(CLOCK.column::<B>())?;
        let created = row.ts("discovered_at")?;
        let request_ms = record
            .config
            .orchestration
            .as_ref()
            .map_or(u64::from(policy.max_elapsed_ms), |cfg| {
                cfg.attempts.max_elapsed_ms
            });
        let elapsed = policy.max_elapsed_ms.min(
            record
                .config
                .scrape
                .as_ref()
                .map_or(policy.max_elapsed_ms, |job| job.options.timeout_ms),
        );
        let deadline = row.opt_ts("acquisition_deadline_at")?.unwrap_or_else(|| {
            (now + chrono::Duration::milliseconds(i64::from(elapsed)))
                .min(created + chrono::Duration::milliseconds(i64::try_from(request_ms).unwrap_or(i64::MAX)))
                .min(
                    record.started_at.unwrap_or(record.created_at)
                        + chrono::Duration::seconds(i64::from(record.config.limits.duration_seconds)),
                )
        });
        let previous = row
            .opt_json("acquisition_usage")?
            .map(from_json::<AcquisitionUsageV1>)
            .transpose()?
            .unwrap_or_default();
        let maximum = record
            .config
            .orchestration
            .as_ref()
            .map_or(u32::MAX, |cfg| cfg.attempts.max_total_effects);
        let reserved: u32 = conv(row.i64("effect_reservations")?, "effect reservations")?;
        let mut receipt = AcquisitionAllowanceV1::remaining(policy, previous, deadline, now)?;
        receipt.remaining_network_requests = receipt
            .remaining_network_requests
            .min(maximum.saturating_sub(reserved));
        let bytes = policy
            .max_decoded_bytes
            .min(record.config.fetch.max_response_bytes)
            .saturating_sub(receipt.previous_usage.decoded_bytes_reserved);
        receipt.remaining_decoded_bytes = receipt.remaining_decoded_bytes.min(bytes);
        if receipt.remaining_decoded_bytes == 0 {
            return Err(StoreError::Conflict(
                "parent decoded byte allowance exhausted".into(),
            ));
        }
        if receipt.remaining_network_requests == 0 {
            return Err(StoreError::Conflict("request effect budget exhausted".into()));
        }
        let held_usage = serde_json::to_value(receipt.held_usage())?;
        let escrow = serde_json::to_value(&receipt)?;
        let held = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET acquisition_deadline_at=$2,acquisition_usage=$3,acquisition_escrow=$4,acquisition_escrow_fence=$5,acquisition_settlement=NULL,effect_reservations=$6 WHERE frontier_id=$1 AND fencing_token=$5 AND lease_expires_at>{clock}"
            )
        )
        .i64(id)
        .ts(deadline)
        .json(&held_usage)
        .json(&escrow)
        .i64(fence)
        .i64(i64::from(reserved.saturating_add(receipt.remaining_network_requests)))
        .execute(tx.conn())
        .await?;
        if held != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await?;
        Ok(receipt)
    }
    pub(super) async fn acquisition_settle(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        usage: &AcquisitionUsageV1,
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let clock = <B::Dialect as Dialect>::clock_timestamp();
        let row = stmt!(
            B,
            format!(
                "SELECT effect_reservations,acquisition_escrow,acquisition_settlement FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>{clock} AND acquisition_escrow_fence=$3{lock}",
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update),
            )
        )
        .i64(id)
        .uuid(run.0)
        .i64(fence)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        if let Some(value) = row.opt_json("acquisition_settlement")? {
            let prior: AcquisitionUsageV1 = from_json(value)?;
            return if prior == *usage {
                Ok(())
            } else {
                Err(StoreError::Conflict("acquisition settlement changed".into()))
            };
        }
        let receipt: AcquisitionAllowanceV1 = from_json(
            row.opt_json("acquisition_escrow")?
                .ok_or_else(|| StoreError::Conflict("acquisition escrow missing".into()))?,
        )?;
        let settled = receipt.checked_settlement(usage)?;
        let refund = receipt
            .remaining_network_requests
            .saturating_sub(usage.network_requests_reserved);
        let reserved = row
            .i64("effect_reservations")?
            .checked_sub(i64::from(refund))
            .filter(|value| *value >= 0)
            .ok_or_else(|| StoreError::Conflict("acquisition effect settlement mismatch".into()))?;
        let settled_usage = serde_json::to_value(settled)?;
        let recorded = serde_json::to_value(usage)?;
        let settled_row = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET acquisition_usage=$2,acquisition_settlement=$3,effect_reservations=$4 WHERE frontier_id=$1 AND lease_expires_at>{clock}"
            )
        )
        .i64(id)
        .json(&settled_usage)
        .json(&recorded)
        .i64(reserved)
        .execute(tx.conn())
        .await?;
        if settled_row != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await
    }
    pub(super) async fn request_page(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<FrontierEntry>, StoreError> {
        if limit == 0 || limit > 1000 {
            return Err(StoreError::Conflict("invalid frontier page limit".into()));
        }
        let rows = stmt!(
            B,
            format!("SELECT {ENTRY_COLS} FROM url_frontier WHERE run_id=$1 AND frontier_id>$2 ORDER BY frontier_id LIMIT $3")
        )
        .uuid(run.0)
        .i64(after)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            entries.push(entry_from_row(self, row).await?);
        }
        Ok(entries)
    }
    pub(super) async fn request_get(&self, run: CrawlRunId, id: i64) -> Result<QueuedRequestV1, StoreError> {
        let row = stmt!(
            B,
            format!("SELECT {ENTRY_COLS},principal,canonical_key,revisit_generation,request_envelope,envelope_bytes,state_version FROM url_frontier WHERE run_id=$1 AND frontier_id=$2")
        )
        .uuid(run.0)
        .i64(id)
        .fetch_optional_pool(&self.pool)
        .await?
        .ok_or_else(|| not_found("frontier row", id))?;
        let entry = entry_from_row(self, &row).await?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let stored = row.opt_json("request_envelope")?;
        let envelope = if zdr && row.i64("envelope_bytes")? > 0 {
            self.ephemeral_get(tenant, run, operational_page(id)?, "request_envelope")
                .await?
        } else if let Some(value) = stored {
            from_json(value)?
        } else {
            RequestEnvelopeV1::get(entry.url.clone(), entry.depth, entry.discovered_from)
        };
        let key = Digest(
            row.bytes("canonical_key")?
                .try_into()
                .map_err(|_| StoreError::Serialization("invalid request digest".into()))?,
        );
        Ok(QueuedRequestV1::stored(
            entry,
            envelope,
            RequestIdentityV1::stored(key, 1, conv(row.i32("revisit_generation")?, "generation")?),
            conv(row.i64("state_version")?, "state version")?,
            row.text("principal")?,
        ))
    }
    pub(super) async fn request_seal(&self, run: CrawlRunId, expected_epoch: u64) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let (tenant, _) = lock_run::<B>(tx.conn(), run).await?;
        ensure_producer::<B>(tx.conn(), run, tenant).await?;
        let updated = stmt!(
            B,
            "UPDATE frontier_producers SET sealed=true WHERE run_id=$1 AND epoch=$2"
        )
        .uuid(run.0)
        .i64(
            i64::try_from(expected_epoch)
                .map_err(|_| StoreError::Conflict("producer epoch overflow".into()))?,
        )
        .execute(tx.conn())
        .await?;
        if updated != 1 {
            return Err(StoreError::Conflict("stale producer epoch".into()));
        }
        tx.commit().await
    }
    pub(super) async fn request_activity(&self, run: CrawlRunId) -> Result<FrontierActivityV1, StoreError> {
        let row = stmt!(
            B,
            format!(
                "SELECT EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND via<>'interaction' AND status='pending' AND next_attempt_at<={now} AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic') AS ready, EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND via<>'interaction' AND status='pending' AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic') AS pending, EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND via<>'interaction' AND status='leased' AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic') AS leased, (SELECT sealed FROM frontier_producers WHERE run_id=$1) AS sealed",
                now = <B::Dialect as Dialect>::now(),
            )
        )
        .uuid(run.0)
        .fetch_one_pool(&self.pool)
        .await?;
        if row.flag("ready")? {
            return Ok(FrontierActivityV1::Ready);
        }
        if row.flag("pending")? {
            return Ok(FrontierActivityV1::WaitingCooldown);
        }
        if row.flag("leased")? {
            return Ok(FrontierActivityV1::Draining);
        }
        let closed = match row.opt_flag("sealed")? {
            Some(value) => value,
            None => RunRepo::get(self, run)
                .await?
                .config
                .orchestration
                .as_ref()
                .is_none_or(|cfg| cfg.queue.producer_mode == ProducerModeV1::Finite),
        };
        Ok(if closed {
            FrontierActivityV1::Terminal
        } else {
            FrontierActivityV1::WaitingProducer
        })
    }
    pub(super) async fn request_cursor(
        &self,
        run: CrawlRunId,
        source: &str,
    ) -> Result<Option<LoaderCursorV1>, StoreError> {
        let value = stmt!(
            B,
            format!(
                "SELECT {cursor} FROM frontier_loader_cursors WHERE run_id=$1 AND source_id=$2",
                cursor = <B::Dialect as Dialect>::reserved_ident("cursor"),
            )
        )
        .uuid(run.0)
        .text(source)
        .fetch_optional_pool(&self.pool)
        .await?
        .map(|row| row.json("cursor"))
        .transpose()?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        match value {
            Some(value) if zdr => {
                let reference = value
                    .get("volatileRef")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| StoreError::Serialization("missing volatile cursor reference".into()))?;
                Ok(Some(
                    self.ephemeral_get(tenant, run, i64::MIN + 1, &format!("_request_cursor:{reference}"))
                        .await?,
                ))
            }
            Some(value) => Ok(Some(from_json(value)?)),
            None => Ok(None),
        }
    }
}

/// The ceilings [`Store::request_retry`] weighs a leased row against.
struct RetryLimits {
    /// Most effects a request may reserve.
    effects: i64,
    /// Longest a request may stay in the frontier.
    elapsed: std::time::Duration,
    /// Native acquisition attempt ceiling.
    attempts: i64,
    /// Native acquisition network request ceiling.
    network: i64,
    /// Native acquisition decoded byte ceiling.
    decoded: i64,
}

// PostgreSQL locking assumption: FOR SHARE OF s prevents session reassignment while the
// owning run is already locked; clock_timestamp() must still recheck expiry before commit.
// MariaDB's LOCK IN SHARE MODE locks the joined rows of both tables, which is stricter and
// acceptable; SQLite has one writer and takes no row locks.
pub(super) async fn observed_session_tx<B: Sql>(
    conn: &mut Conn<B>,
    lease: &crawlx_core::custody::CustodyLease,
) -> Result<String, StoreError> {
    use crawlx_core::custody::CustodySource;
    lease.check_local_cancellation()?;
    let CustodySource::Session(session) = lease.source else {
        return Err(StoreError::LeaseLost);
    };
    if crate::tenant::current().is_some_and(|tenant| tenant != lease.tenant) {
        return Err(StoreError::LeaseLost);
    }
    let role = stmt!(
        B,
        format!(
            "SELECT s.role FROM crawl_sessions s JOIN crawl_runs r ON r.run_id=s.run_id \
             WHERE s.session_id=$1 AND s.run_id=$2 AND r.tenant_id=$3 AND s.lease_owner=$4 \
             AND s.fencing_token=$5 AND s.lease_expires_at>{clock} \
             AND s.status IN ('running','recovering') AND r.status IN ('queued','running','paused') \
             AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
             AND (r.expires_at IS NULL OR r.expires_at>{clock}){lock}",
            clock = <B::Dialect as Dialect>::clock_timestamp(),
            lock = if B::KIND == BackendKind::Postgres {
                " FOR SHARE OF s"
            } else {
                <B::Dialect as Dialect>::row_lock(RowLock::Share)
            },
        )
    )
    .uuid(session.0)
    .uuid(lease.run.0)
    .uuid(lease.tenant.0)
    .uuid(lease.worker.0)
    .i64(lease.fence)
    .fetch_optional(conn)
    .await?
    .ok_or(StoreError::LeaseLost)?
    .text("role")?;
    Ok(role)
}

impl<B: Sql> Store<B> {
    pub(super) async fn append_observation(
        &self,
        mut request: ObservedRequestV1,
    ) -> Result<ObservedAppendV1, StoreError> {
        let run = RunRepo::get(self, request.lease.run).await?;
        let (deadline, _) = crate::session_binding::budget_clock_deadline(self, &run, None).await?;
        if request.acquired_at < run.started_at.unwrap_or(run.created_at) || request.acquired_at >= deadline {
            return Err(StoreError::AccessDenied(
                "observation acquired outside exploration deadline".into(),
            ));
        }
        let mut tx = self.begin_write().await?;
        let (tenant, _) = lock_run::<B>(tx.conn(), request.lease.run).await?;
        if tenant != request.lease.tenant {
            return Err(StoreError::LeaseLost);
        }
        let principal = observed_session_tx::<B>(tx.conn(), &request.lease).await?;
        let (batch_id, key) = request.prepare(&principal)?;
        // Existing opaque batch receipts retain row IDs even when envelope content is volatile.
        let prior = stmt!(
            B,
            "SELECT receipt FROM frontier_batch_receipts WHERE run_id=$1 AND batch_id=$2"
        )
        .uuid(run.id.0)
        .bytes(batch_id.0.as_slice())
        .fetch_optional(tx.conn())
        .await?
        .map(|row| row.json("receipt"))
        .transpose()?;
        if let Some(prior) = prior {
            let id = prior
                .get("inserted")
                .and_then(|value| value.get(0))
                .and_then(serde_json::Value::as_i64)
                .ok_or(StoreError::LeaseLost)?;
            let generation = stmt!(
                B,
                "SELECT revisit_generation FROM url_frontier WHERE run_id=$1 AND frontier_id=$2 AND canonical_key=$3"
            )
            .uuid(run.id.0)
            .i64(id)
            .bytes(key.0.as_slice())
            .fetch_one(tx.conn())
            .await?
            .i32("revisit_generation")?;
            return Ok(ObservedAppendV1::Duplicate {
                request_id: id,
                revisit_generation: conv(generation, "revisit generation")?,
            });
        }
        let latest = stmt!(
            B,
            format!(
                "SELECT max(revisit_generation){alias} FROM url_frontier WHERE run_id=$1 AND canonical_key=$2",
                alias = LATEST.clause::<B>(),
            )
        )
        .uuid(run.id.0)
        .bytes(key.0.as_slice())
        .fetch_one(tx.conn())
        .await?
        .opt_i32(LATEST.column::<B>())?;
        let generation = match latest {
            Some(value) if value >= i32::from(run.config.dynamic.max_page_revisits.min(128)) => {
                return Ok(ObservedAppendV1::CapReached);
            }
            Some(value) => value
                .checked_add(1)
                .ok_or_else(|| StoreError::Conflict("revisit generation overflow".into()))?,
            None => 0,
        };
        request.envelope.revisit_generation = conv(generation, "revisit generation")?;
        let mut batch = RequestBatchV1::new(tenant, run.id, principal, batch_id, vec![request.envelope]);
        let epoch = stmt!(B, "SELECT epoch FROM frontier_producers WHERE run_id=$1")
            .uuid(run.id.0)
            .fetch_optional(tx.conn())
            .await?
            .map(|row| row.i64("epoch"))
            .transpose()?;
        batch.producer_epoch = conv(epoch.unwrap_or(1), "producer epoch")?;
        let cfg = run.config.orchestration.unwrap_or_default();
        let receipt = append::<B>(
            self,
            tx.conn(),
            &batch,
            &cfg,
            true,
            Some((request.acquired_at, deadline)),
            run.config.limits.duration_seconds,
        )
        .await?;
        let id = *receipt.inserted.first().ok_or(StoreError::LeaseLost)?;
        observed_session_tx::<B>(tx.conn(), &request.lease).await?;
        tx.commit().await?;
        Ok(ObservedAppendV1::Appended {
            request_id: id,
            revisit_generation: conv(generation, "revisit generation")?,
        })
    }
}
