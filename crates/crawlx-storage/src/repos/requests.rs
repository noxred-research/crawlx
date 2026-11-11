//! Request extensions of the authoritative URL frontier.
use super::*;
use crawlx_core::acquisition::{AcquisitionAllowanceV1, AcquisitionUsageV1};
use crawlx_core::extensions::ExtensionReceiptV1;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::*;
use crawlx_core::repo::RunRepo;
use crawlx_core::request::{RequestEnvelopeV1, RequestIdentityV1};
use crawlx_core::TenantId;
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};

// A ZDR receipt marks only the committed transaction. Its content hash and observation
// share one volatile blob in the original run-sideband page; replay never renews its TTL.
const ZDR_HEAD_RECEIPT_MARKER: [u8; 32] = [0; 32];

async fn check_head_response_receipt(
    pg: &Pg,
    conn: &mut sqlx::PgConnection,
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
            crate::repos::event::read_head_response(pg, conn, tenant, commit.run, commit.request_id).await?;
        receipt == Some(live)
    } else {
        crate::repos::event::check_head_authority(conn, commit.run, tenant).await?;
        receipt.is_some_and(|receipt| receipt.0.as_slice() == stored)
    };
    if matches {
        Ok(())
    } else {
        Err(StoreError::Conflict("HEAD response receipt changed".into()))
    }
}

pub(super) async fn lock_run(
    _pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    run: CrawlRunId,
) -> Result<(TenantId, bool), StoreError> {
    let row = sqlx::query("SELECT tenant_id, retention_mode = 'zdr' AS zdr, status::text AS status, deadline_at FROM crawl_runs WHERE run_id=$1 FOR UPDATE")
        .bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?.ok_or_else(|| not_found("crawl run", run))?;
    Ok((TenantId(get(&row, "tenant_id")?), get(&row, "zdr")?))
}

/// Exact scope of one callback trail. Every field is part of the durable dedupe key.
#[derive(Clone, Copy)]
struct ExtensionAttemptKey {
    tenant: TenantId,
    run: CrawlRunId,
    request_id: i64,
    fence: i64,
    attempt: u32,
}

fn validate_extension_trail(receipts: &[ExtensionReceiptV1]) -> Result<(), StoreError> {
    crawlx_core::extensions::validate_extension_receipts(receipts)
        .map_err(|_| StoreError::Conflict("invalid extension attempt receipts".into()))
}

fn extension_digest(receipts: &[ExtensionReceiptV1]) -> Result<Digest, StoreError> {
    Digest::of_value("crawlx/extension-attempt/v1", &receipts)
        .map_err(|error| StoreError::Serialization(error.to_string()))
}

/// Persist one complete callback trail inside a transaction that already holds the run lock and
/// the live request-row lock for exactly this fence and attempt. The digest row is the only
/// dedupe authority; the receipts themselves are a typed `extension_attempt` event, which the
/// existing ZDR projection already withholds. PostgreSQL row locks and the sequence-backed
/// event allocator are confined to this helper.
async fn persist_extension_attempt(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    key: ExtensionAttemptKey,
    receipts: &[ExtensionReceiptV1],
) -> Result<(), StoreError> {
    let attempt = i32::try_from(key.attempt)
        .ok()
        .filter(|attempt| (1..=i32::from(i16::MAX)).contains(attempt))
        .ok_or_else(|| StoreError::Conflict("invalid extension attempt".into()))?;
    let digest = extension_digest(receipts)?;
    let stored: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT digest FROM extension_attempts WHERE tenant_id=$1 AND run_id=$2 AND request_id=$3 AND fence=$4 AND attempt=$5",
    )
    .bind(key.tenant.0)
    .bind(key.run.0)
    .bind(key.request_id)
    .bind(key.fence)
    .bind(attempt)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?;
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
    let seq = crate::repos::event::append_event(
        pg,
        tx,
        key.run,
        "extension_attempt",
        serde_json::Value::Object(payload),
    )
    .await?;
    sqlx::query(
        "INSERT INTO extension_attempts (tenant_id,run_id,request_id,fence,attempt,digest,event_seq) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(key.tenant.0)
    .bind(key.run.0)
    .bind(key.request_id)
    .bind(key.fence)
    .bind(attempt)
    .bind(digest.0.as_slice())
    .bind(conv::<u64, i64>(seq, "event seq")?)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    Ok(())
}

pub(super) async fn append(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    batch: &RequestBatchV1,
    cfg: &OrchestrationConfigV1,
    completing: bool,
    observed_timing: Option<(crawlx_core::Timestamp, crawlx_core::Timestamp)>,
    duration_seconds: u32,
) -> Result<RequestBatchReceiptV1, StoreError> {
    batch.validate()?;
    let digest = Digest::of_value("crawlx/request-batch/v1", batch)
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    let (tenant, zdr) = lock_run(pg, tx, batch.run).await?;
    if tenant != batch.tenant {
        return Err(StoreError::AccessDenied("request tenant mismatch".into()));
    }
    if let Some(row) = sqlx::query(
        "SELECT batch_digest,receipt FROM frontier_batch_receipts WHERE run_id=$1 AND batch_id=$2",
    )
    .bind(batch.run.0)
    .bind(batch.batch_id.0.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?
    {
        if zdr {
            let reference = get::<serde_json::Value>(&row, "receipt")?
                .get("volatileRef")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| StoreError::Serialization("missing volatile batch reference".into()))?
                .to_owned();
            let (stored, receipt): (Digest, RequestBatchReceiptV1) = pg
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
        if get::<Vec<u8>>(&row, "batch_digest")? != digest.0 {
            return Err(StoreError::Conflict(
                "batch id reused with different content".into(),
            ));
        }
        return from_json(get(&row, "receipt")?);
    }
    // A queued run may not have deadline_at yet; dispatch still uses its original ceiling.
    let admits = sqlx::query_scalar::<_,bool>("SELECT status IN ('queued','running','paused') AND cancel_requested_at IS NULL AND purge_requested_at IS NULL AND COALESCE($2,deadline_at,COALESCE(started_at,created_at)+make_interval(secs=>$4))>COALESCE($3,clock_timestamp()) AND ($3::timestamptz IS NULL OR $3<=clock_timestamp()) FROM crawl_runs WHERE run_id=$1")
        .bind(batch.run.0).bind(observed_timing.map(|(_, deadline)| deadline))
        .bind(observed_timing.map(|(acquired_at, _)| acquired_at)).bind(f64::from(duration_seconds))
        .fetch_one(&mut **tx).await.map_err(db)?;
    if !admits {
        return Err(StoreError::AccessDenied("run no longer admits requests".into()));
    }
    cfg.validate()?;
    if batch.requests.len() > usize::try_from(cfg.queue.batch_size).unwrap_or(0) {
        return Err(StoreError::Conflict("configured request batch limit".into()));
    }
    if batch.principal != "anonymous"
        && !sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM crawl_sessions WHERE run_id=$1 AND role=$2)",
        )
        .bind(batch.run.0)
        .bind(&batch.principal)
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?
    {
        return Err(StoreError::AccessDenied("request principal unavailable".into()));
    }
    sqlx::query("INSERT INTO frontier_producers(run_id,tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
        .bind(batch.run.0)
        .bind(tenant.0)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    let producer = sqlx::query("SELECT epoch,sealed FROM frontier_producers WHERE run_id=$1 FOR UPDATE")
        .bind(batch.run.0)
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    if get::<i64>(&producer, "epoch")?
        != i64::try_from(batch.producer_epoch)
            .map_err(|_| StoreError::Conflict("producer epoch overflow".into()))?
        || (get::<bool>(&producer, "sealed")? && batch.parent_fence.is_none() && observed_timing.is_none())
    {
        return Err(StoreError::Conflict("producer epoch closed or stale".into()));
    }
    if let Some((id, fence)) = batch.parent_fence {
        let live = sqlx::query_scalar::<_,i64>("SELECT frontier_id FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>clock_timestamp() FOR UPDATE")
            .bind(id).bind(batch.run.0).bind(fence).fetch_optional(&mut **tx).await.map_err(db)?;
        if live.is_none() {
            return Err(StoreError::LeaseLost);
        }
    }
    if let Some(next) = &batch.next_cursor {
        let stored: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT cursor FROM frontier_loader_cursors WHERE run_id=$1 AND source_id=$2 FOR UPDATE",
        )
        .bind(batch.run.0)
        .bind(&next.source)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?;
        let cursor = match stored {
            Some(value) if zdr => {
                let reference = value
                    .get("volatileRef")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| StoreError::Serialization("missing volatile cursor reference".into()))?;
                Some(
                    pg.ephemeral_get::<LoaderCursorV1>(
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
        let exists = sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND canonical_key=$2 AND revisit_generation=$3)")
            .bind(batch.run.0).bind(identity.key.0.as_slice()).bind(i64::from(identity.revisit_generation)).fetch_one(&mut **tx).await.map_err(db)?;
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
    let counts = sqlx::query("SELECT count(*) AS entries,COALESCE(sum(envelope_bytes),0)::bigint AS bytes FROM url_frontier WHERE run_id=$1 AND status IN ('pending','leased') AND ($2::bigint IS NULL OR frontier_id<>$2)")
        .bind(batch.run.0).bind(releasing).fetch_one(&mut **tx).await.map_err(db)?;
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
    if u64::try_from(get::<i64>(&counts, "entries")?)
        .unwrap_or(u64::MAX)
        .saturating_add(extra_entries)
        > cfg.queue.max_pending_entries
        || u64::try_from(get::<i64>(&counts, "bytes")?.saturating_add(extra_bytes)).unwrap_or(u64::MAX)
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
        // The reserved source survives volatile envelope expiry and every status transition.
        let id: i64 = sqlx::query_scalar("INSERT INTO url_frontier(run_id,canonical_key,canonical_url,origin,query_schema,depth,priority,via,parent_id,principal,route_id,revisit_generation,request_envelope,envelope_bytes,next_attempt_at,status,denial_reason,finished_at,strategy_score) VALUES($1,$2,$3,$4,$5,$6,$7,$18,$8,$9,$10,$11,$12,$13,COALESCE($14,now()),$15,$16,CASE WHEN $15<>'pending' THEN now() END,$17) RETURNING frontier_id")
            .bind(batch.run.0).bind(identity.key.0.as_slice()).bind((!zdr).then(|| envelope.url.url.as_str()))
            .bind(origin).bind(schema).bind(conv::<u16,i16>(envelope.depth,"depth")?)
            .bind(f32::from(i16::try_from(envelope.priority).map_err(|_|StoreError::Conflict("request priority overflow".into()))?))
            .bind(envelope.parent).bind(&batch.principal).bind(&envelope.route).bind(i64::from(identity.revisit_generation))
            .bind(if zdr { None } else { Some(serde_json::to_value(envelope)?) }).bind(bytes).bind(envelope.not_before)
            .bind(batch.initial_denial.as_ref().map_or("pending",|(status,_)|status.as_str()))
            .bind(batch.initial_denial.as_ref().map(|(_,reason)|reason))
            .bind(conv::<u32, i32>(crawlx_core::priority::priority_depth(
                &envelope.url.url, u32::from(envelope.depth), envelope.method == "GET",
            ), "strategy score")?)
            .bind(if observed_timing.is_some() { "interaction" } else { "link" })
            .fetch_one(&mut **tx).await.map_err(db)?;
        if zdr {
            pg.ephemeral_put(
                tenant,
                batch.run,
                operational_page(id)?,
                "frontier_record",
                &envelope.url,
            )
            .await?;
            pg.ephemeral_put(
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
            pg.ephemeral_put(
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
        sqlx::query("INSERT INTO frontier_loader_cursors(run_id,tenant_id,source_id,cursor) VALUES($1,$2,$3,$4) ON CONFLICT(run_id,source_id) DO UPDATE SET cursor=excluded.cursor")
            .bind(batch.run.0).bind(tenant.0).bind(&cursor.source).bind(stored).execute(&mut **tx).await.map_err(db)?;
    }
    let stored_receipt = if zdr {
        let reference = uuid::Uuid::now_v7().to_string();
        pg.ephemeral_put(
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
    sqlx::query("INSERT INTO frontier_batch_receipts(run_id,tenant_id,batch_id,batch_digest,receipt) VALUES($1,$2,$3,$4,$5)")
        .bind(batch.run.0).bind(tenant.0).bind(batch.batch_id.0.as_slice()).bind(stored_digest.0.as_slice()).bind(stored_receipt)
        .execute(&mut **tx).await.map_err(db)?;
    if let Some((id, fence)) = batch.parent_fence {
        let live=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM url_frontier WHERE frontier_id=$1 AND status='leased' AND fencing_token=$2 AND lease_expires_at>clock_timestamp())")
            .bind(id).bind(fence).fetch_one(&mut **tx).await.map_err(db)?;
        if !live {
            return Err(StoreError::LeaseLost);
        }
    }
    Ok(receipt)
}

impl Pg {
    pub(super) async fn request_append(
        &self,
        batch: RequestBatchV1,
    ) -> Result<RequestBatchReceiptV1, StoreError> {
        let run = self.get(batch.run).await?;
        let cfg = run.config.orchestration.clone().unwrap_or_default();
        let mut tx = self.pool.begin().await.map_err(db)?;
        let receipt = append(
            self,
            &mut tx,
            &batch,
            &cfg,
            false,
            None,
            run.config.limits.duration_seconds,
        )
        .await?;
        tx.commit().await.map_err(db)?;
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
        let rows=sqlx::query("SELECT frontier_id,status,depth,attempts,revisit_generation FROM url_frontier WHERE run_id=$1 AND frontier_id>$2 ORDER BY frontier_id LIMIT $3")
            .bind(run.0).bind(after).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(db)?;
        rows.iter()
            .map(|row| {
                Ok(RequestMetadataV1::new(
                    get(row, "frontier_id")?,
                    parse_label(&get::<String>(row, "status")?)?,
                    conv(get::<i16>(row, "depth")?, "depth")?,
                    conv(get::<i16>(row, "attempts")?, "attempts")?,
                    conv(get::<i32>(row, "revisit_generation")?, "generation")?,
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
        let rows = sqlx::query(
            "SELECT f.frontier_id,f.request_envelope,f.envelope_bytes,r.tenant_id,r.retention_mode='zdr' AS zdr \
             FROM url_frontier f JOIN crawl_runs r ON r.run_id=f.run_id \
             WHERE f.run_id=$1 AND f.frontier_id=ANY($2)",
        ).bind(run.0).bind(ids).fetch_all(&self.pool).await.map_err(db)?;
        let found = rows
            .iter()
            .map(|row| get::<i64>(row, "frontier_id"))
            .collect::<Result<BTreeSet<_>, _>>()?;
        if let Some(id) = ids.iter().find(|id| !found.contains(*id)) {
            return Err(not_found("frontier row", id));
        }
        let mut methods = BTreeMap::new();
        for row in rows {
            let id: i64 = get(&row, "frontier_id")?;
            let tenant = TenantId(get(&row, "tenant_id")?);
            if crate::tenant::current().is_some_and(|current| current != tenant) {
                return Err(StoreError::AccessDenied("request method tenant mismatch".into()));
            }
            let stored: Option<serde_json::Value> = get(&row, "request_envelope")?;
            let bytes: i64 = get(&row, "envelope_bytes")?;
            let method = if get::<bool>(&row, "zdr")? && bytes > 0 {
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
        let run: uuid::Uuid = sqlx::query_scalar("SELECT run_id FROM url_frontier WHERE frontier_id=$1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?
            .ok_or_else(|| not_found("frontier row", id))?;
        let record = self.get(CrawlRunId(run)).await?;
        let cfg = record.config.orchestration.as_ref().cloned().unwrap_or_default();
        let native = record.config.acquisition.as_ref();
        cfg.validate()?;
        let pending:Option<bool>=sqlx::query_scalar(
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
             FROM held WHERE f.frontier_id=held.frontier_id RETURNING f.status='pending'")
            .bind(id).bind(fence).bind(not_before).bind(i64::from(cfg.attempts.max_total_effects))
            .bind(std::time::Duration::from_millis(cfg.attempts.max_elapsed_ms).as_secs_f64())
            .bind(native.map_or(i64::MAX,|policy|i64::from(policy.max_attempts)))
            .bind(native.map_or(i64::MAX,|policy|i64::from(policy.max_network_requests)))
            .bind(native.map_or(i64::MAX,|policy|i64::try_from(policy.max_decoded_bytes.min(record.config.fetch.max_response_bytes)).unwrap_or(i64::MAX)))
            .fetch_optional(&self.pool).await.map_err(db)?;
        pending.ok_or(StoreError::LeaseLost)
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
        let cfg = self.get(run).await?.config.orchestration.unwrap_or_default();
        cfg.validate()?;
        let result=sqlx::query(
            "UPDATE url_frontier SET effect_reservations=effect_reservations+$4,effect_escrow_fence=$3,effect_escrow_amount=$4,effect_escrow_settlement=NULL WHERE frontier_id=$1 AND run_id=$2 \
             AND status='leased' AND fencing_token=$3 AND lease_expires_at>clock_timestamp() AND effect_reservations+$4 <= $5 \
             AND (effect_escrow_fence IS NULL OR effect_escrow_fence<>$3) AND clock_timestamp()<discovered_at+make_interval(secs=>$6)")
            .bind(id).bind(run.0).bind(fence).bind(i64::from(effects)).bind(i64::from(cfg.attempts.max_total_effects))
            .bind(std::time::Duration::from_millis(cfg.attempts.max_elapsed_ms).as_secs_f64())
            .execute(&self.pool).await.map_err(db)?;
        if result.rows_affected() != 1 {
            let live=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>clock_timestamp())")
                .bind(id).bind(run.0).bind(fence).fetch_one(&self.pool).await.map_err(db)?;
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
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row=sqlx::query("SELECT effect_reservations,effect_escrow_amount,effect_escrow_settlement FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>clock_timestamp() AND effect_escrow_fence=$3 FOR UPDATE")
            .bind(id).bind(run.0).bind(fence).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        if get::<Option<i64>>(&row, "effect_escrow_amount")? != Some(i64::from(reserved)) {
            return Err(StoreError::Conflict(
                "effect settlement exceeds lease escrow".into(),
            ));
        }
        if let Some(prior) = get::<Option<i64>>(&row, "effect_escrow_settlement")? {
            return if prior == i64::from(actual) {
                Ok(())
            } else {
                Err(StoreError::Conflict("effect settlement changed".into()))
            };
        }
        let remaining = get::<i64>(&row, "effect_reservations")?
            .checked_sub(i64::from(reserved - actual))
            .filter(|value| *value >= 0)
            .ok_or_else(|| StoreError::Conflict("effect settlement mismatch".into()))?;
        let result=sqlx::query("UPDATE url_frontier SET effect_reservations=$2,effect_escrow_settlement=$3 WHERE frontier_id=$1 AND lease_expires_at>clock_timestamp()")
            .bind(id).bind(remaining).bind(i64::from(actual)).execute(&mut *tx).await.map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await.map_err(db)
    }
    pub(super) async fn acquisition_reserve(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
    ) -> Result<AcquisitionAllowanceV1, StoreError> {
        let record = self.get(run).await?;
        let policy = record
            .config
            .acquisition
            .as_ref()
            .ok_or_else(|| StoreError::Conflict("native acquisition policy required".into()))?;
        policy
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row=sqlx::query(
            "SELECT discovered_at,effect_reservations,acquisition_deadline_at,acquisition_usage,acquisition_escrow_fence,now() AS registry_now \
             FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>clock_timestamp() FOR UPDATE")
            .bind(id).bind(run.0).bind(fence).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        if get::<Option<i64>>(&row, "acquisition_escrow_fence")? == Some(fence) {
            return Err(StoreError::Conflict(
                "acquisition already reserved by this lease".into(),
            ));
        }
        let now: crawlx_core::Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let created: crawlx_core::Timestamp = get(&row, "discovered_at")?;
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
        let deadline = get::<Option<crawlx_core::Timestamp>>(&row, "acquisition_deadline_at")?
            .unwrap_or_else(|| {
                (now + chrono::Duration::milliseconds(i64::from(elapsed)))
                    .min(
                        created
                            + chrono::Duration::milliseconds(i64::try_from(request_ms).unwrap_or(i64::MAX)),
                    )
                    .min(
                        record.started_at.unwrap_or(record.created_at)
                            + chrono::Duration::seconds(i64::from(record.config.limits.duration_seconds)),
                    )
            });
        let previous = get::<Option<serde_json::Value>>(&row, "acquisition_usage")?
            .map(from_json::<AcquisitionUsageV1>)
            .transpose()?
            .unwrap_or_default();
        let maximum = record
            .config
            .orchestration
            .as_ref()
            .map_or(u32::MAX, |cfg| cfg.attempts.max_total_effects);
        let reserved: u32 = conv(get::<i64>(&row, "effect_reservations")?, "effect reservations")?;
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
        let held=sqlx::query("UPDATE url_frontier SET acquisition_deadline_at=$2,acquisition_usage=$3,acquisition_escrow=$4,acquisition_escrow_fence=$5,acquisition_settlement=NULL,effect_reservations=$6 WHERE frontier_id=$1 AND fencing_token=$5 AND lease_expires_at>clock_timestamp()")
            .bind(id).bind(deadline).bind(serde_json::to_value(receipt.held_usage())?).bind(serde_json::to_value(&receipt)?).bind(fence)
            .bind(i64::from(reserved.saturating_add(receipt.remaining_network_requests)))
            .execute(&mut *tx).await.map_err(db)?;
        if held.rows_affected() != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await.map_err(db)?;
        Ok(receipt)
    }
    pub(super) async fn acquisition_settle(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        usage: &AcquisitionUsageV1,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row=sqlx::query("SELECT effect_reservations,acquisition_escrow,acquisition_settlement FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>clock_timestamp() AND acquisition_escrow_fence=$3 FOR UPDATE")
            .bind(id).bind(run.0).bind(fence).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        if let Some(value) = get::<Option<serde_json::Value>>(&row, "acquisition_settlement")? {
            let prior: AcquisitionUsageV1 = from_json(value)?;
            return if prior == *usage {
                Ok(())
            } else {
                Err(StoreError::Conflict("acquisition settlement changed".into()))
            };
        }
        let receipt: AcquisitionAllowanceV1 = from_json(
            get::<Option<serde_json::Value>>(&row, "acquisition_escrow")?
                .ok_or_else(|| StoreError::Conflict("acquisition escrow missing".into()))?,
        )?;
        let settled = receipt.checked_settlement(usage)?;
        let refund = receipt
            .remaining_network_requests
            .saturating_sub(usage.network_requests_reserved);
        let reserved = get::<i64>(&row, "effect_reservations")?
            .checked_sub(i64::from(refund))
            .filter(|value| *value >= 0)
            .ok_or_else(|| StoreError::Conflict("acquisition effect settlement mismatch".into()))?;
        let settled_row=sqlx::query("UPDATE url_frontier SET acquisition_usage=$2,acquisition_settlement=$3,effect_reservations=$4 WHERE frontier_id=$1 AND lease_expires_at>clock_timestamp()")
            .bind(id).bind(serde_json::to_value(settled)?).bind(serde_json::to_value(usage)?).bind(reserved)
            .execute(&mut *tx).await.map_err(db)?;
        if settled_row.rows_affected() != 1 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await.map_err(db)
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
        let rows=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {ENTRY_COLS} FROM url_frontier WHERE run_id=$1 AND frontier_id>$2 ORDER BY frontier_id LIMIT $3")))
            .bind(run.0).bind(after).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(db)?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            entries.push(entry_from_row(self, row).await?);
        }
        Ok(entries)
    }
    pub(super) async fn request_get(&self, run: CrawlRunId, id: i64) -> Result<QueuedRequestV1, StoreError> {
        let row=sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {ENTRY_COLS},principal,canonical_key,revisit_generation,request_envelope,envelope_bytes,state_version FROM url_frontier WHERE run_id=$1 AND frontier_id=$2")))
            .bind(run.0).bind(id).fetch_optional(&self.pool).await.map_err(db)?.ok_or_else(||not_found("frontier row",id))?;
        let entry = entry_from_row(self, &row).await?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let stored: Option<serde_json::Value> = get(&row, "request_envelope")?;
        let envelope = if zdr && get::<i64>(&row, "envelope_bytes")? > 0 {
            self.ephemeral_get(tenant, run, operational_page(id)?, "request_envelope")
                .await?
        } else if let Some(value) = stored {
            from_json(value)?
        } else {
            RequestEnvelopeV1::get(entry.url.clone(), entry.depth, entry.discovered_from)
        };
        let raw: Vec<u8> = get(&row, "canonical_key")?;
        let key = Digest(
            raw.try_into()
                .map_err(|_| StoreError::Serialization("invalid request digest".into()))?,
        );
        Ok(QueuedRequestV1::stored(
            entry,
            envelope,
            RequestIdentityV1::stored(
                key,
                1,
                conv(get::<i32>(&row, "revisit_generation")?, "generation")?,
            ),
            conv(get::<i64>(&row, "state_version")?, "state version")?,
            get(&row, "principal")?,
        ))
    }
    pub(super) async fn request_seal(&self, run: CrawlRunId, expected_epoch: u64) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, _) = lock_run(self, &mut tx, run).await?;
        sqlx::query("INSERT INTO frontier_producers(run_id,tenant_id) VALUES($1,$2) ON CONFLICT DO NOTHING")
            .bind(run.0)
            .bind(tenant.0)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let updated = sqlx::query("UPDATE frontier_producers SET sealed=true WHERE run_id=$1 AND epoch=$2")
            .bind(run.0)
            .bind(
                i64::try_from(expected_epoch)
                    .map_err(|_| StoreError::Conflict("producer epoch overflow".into()))?,
            )
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::Conflict("stale producer epoch".into()));
        }
        tx.commit().await.map_err(db)
    }
    pub(super) async fn request_activity(&self, run: CrawlRunId) -> Result<FrontierActivityV1, StoreError> {
        let row=sqlx::query("SELECT EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND via<>'interaction' AND status='pending' AND next_attempt_at<=now() AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic') AS ready, EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND via<>'interaction' AND status='pending' AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic') AS pending, EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND via<>'interaction' AND status='leased' AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic') AS leased, (SELECT sealed FROM frontier_producers WHERE run_id=$1) AS sealed")
            .bind(run.0).fetch_one(&self.pool).await.map_err(db)?;
        if get::<bool>(&row, "ready")? {
            return Ok(FrontierActivityV1::Ready);
        }
        if get::<bool>(&row, "pending")? {
            return Ok(FrontierActivityV1::WaitingCooldown);
        }
        if get::<bool>(&row, "leased")? {
            return Ok(FrontierActivityV1::Draining);
        }
        let sealed = get::<Option<bool>>(&row, "sealed")?;
        let closed = match sealed {
            Some(value) => value,
            None => self
                .get(run)
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
        let value: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT cursor FROM frontier_loader_cursors WHERE run_id=$1 AND source_id=$2")
                .bind(run.0)
                .bind(source)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
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

// PostgreSQL locking assumption: FOR SHARE OF s prevents session reassignment while the
// owning run is already locked; clock_timestamp() must still recheck expiry before commit.
async fn observed_session_tx(
    tx: &mut Transaction<'_, Postgres>,
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
    let role = sqlx::query_scalar(
        "SELECT s.role FROM crawl_sessions s JOIN crawl_runs r ON r.run_id=s.run_id \
         WHERE s.session_id=$1 AND s.run_id=$2 AND r.tenant_id=$3 AND s.lease_owner=$4 \
         AND s.fencing_token=$5 AND s.lease_expires_at>clock_timestamp() \
         AND s.status IN ('running','recovering') AND r.status IN ('queued','running','paused') \
         AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
         AND (r.expires_at IS NULL OR r.expires_at>clock_timestamp()) FOR SHARE OF s",
    )
    .bind(session.0)
    .bind(lease.run.0)
    .bind(lease.tenant.0)
    .bind(lease.worker.0)
    .bind(lease.fence)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?
    .ok_or(StoreError::LeaseLost)?;
    Ok(role)
}

impl Pg {
    async fn append_observation(
        &self,
        mut request: ObservedRequestV1,
    ) -> Result<ObservedAppendV1, StoreError> {
        let run = self.get(request.lease.run).await?;
        let (deadline, _) = crate::session_binding::budget_clock_deadline(self, &run, None).await?;
        if request.acquired_at < run.started_at.unwrap_or(run.created_at) || request.acquired_at >= deadline {
            return Err(StoreError::AccessDenied(
                "observation acquired outside exploration deadline".into(),
            ));
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, _) = lock_run(self, &mut tx, request.lease.run).await?;
        if tenant != request.lease.tenant {
            return Err(StoreError::LeaseLost);
        }
        let principal = observed_session_tx(&mut tx, &request.lease).await?;
        let (batch_id, key) = request.prepare(&principal)?;
        // Existing opaque batch receipts retain row IDs even when envelope content is volatile.
        let prior: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT receipt FROM frontier_batch_receipts WHERE run_id=$1 AND batch_id=$2")
                .bind(run.id.0)
                .bind(batch_id.0.as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        if let Some(prior) = prior {
            let id = prior
                .get("inserted")
                .and_then(|value| value.get(0))
                .and_then(serde_json::Value::as_i64)
                .ok_or(StoreError::LeaseLost)?;
            let generation: i32 = sqlx::query_scalar("SELECT revisit_generation FROM url_frontier WHERE run_id=$1 AND frontier_id=$2 AND canonical_key=$3")
                .bind(run.id.0).bind(id).bind(key.0.as_slice()).fetch_one(&mut *tx).await.map_err(db)?;
            return Ok(ObservedAppendV1::Duplicate {
                request_id: id,
                revisit_generation: conv(generation, "revisit generation")?,
            });
        }
        let latest: Option<i32> = sqlx::query_scalar(
            "SELECT max(revisit_generation) FROM url_frontier WHERE run_id=$1 AND canonical_key=$2",
        )
        .bind(run.id.0)
        .bind(key.0.as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        let generation = match latest {
            Some(value) if value >= i32::from(run.config.dynamic.max_page_revisits.min(128)) => {
                return Ok(ObservedAppendV1::CapReached)
            }
            Some(value) => value
                .checked_add(1)
                .ok_or_else(|| StoreError::Conflict("revisit generation overflow".into()))?,
            None => 0,
        };
        request.envelope.revisit_generation = conv(generation, "revisit generation")?;
        let mut batch = RequestBatchV1::new(tenant, run.id, principal, batch_id, vec![request.envelope]);
        let epoch: Option<i64> = sqlx::query_scalar("SELECT epoch FROM frontier_producers WHERE run_id=$1")
            .bind(run.id.0)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        batch.producer_epoch = conv(epoch.unwrap_or(1), "producer epoch")?;
        let cfg = run.config.orchestration.unwrap_or_default();
        let receipt = append(
            self,
            &mut tx,
            &batch,
            &cfg,
            true,
            Some((request.acquired_at, deadline)),
            run.config.limits.duration_seconds,
        )
        .await?;
        let id = *receipt.inserted.first().ok_or(StoreError::LeaseLost)?;
        observed_session_tx(&mut tx, &request.lease).await?;
        tx.commit().await.map_err(db)?;
        Ok(ObservedAppendV1::Appended {
            request_id: id,
            revisit_generation: conv(generation, "revisit generation")?,
        })
    }
}

#[async_trait]
impl RequestCommitRepo for Pg {
    async fn append_observed_fenced(
        &self,
        request: ObservedRequestV1,
    ) -> Result<ObservedAppendV1, StoreError> {
        self.append_observation(request).await
    }
    async fn lease_observed_fenced(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
        epoch: crawlx_core::ObservationEpoch,
        request_id: i64,
    ) -> Result<Option<(FrontierEntry, i64)>, StoreError> {
        lease.check_local_cancellation()?;
        let queued = self.request_get(lease.run, request_id).await?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, _) = lock_run(self, &mut tx, lease.run).await?;
        if tenant != lease.tenant {
            return Err(StoreError::LeaseLost);
        }
        let principal = observed_session_tx(&mut tx, lease).await?;
        let proposal = ObservedRequestV1::from_staged(lease.clone(), epoch, queued.envelope.clone())?;
        let batch = proposal.batch_id(&principal)?;
        let receipt: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT receipt FROM frontier_batch_receipts WHERE run_id=$1 AND batch_id=$2")
                .bind(lease.run.0)
                .bind(batch.0.as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        if queued.principal != principal
            || queued.envelope.metadata.get("observed_epoch") != Some(&serde_json::to_value(batch)?)
            || receipt.as_ref().and_then(|receipt| receipt.get("inserted"))
                != Some(&serde_json::json!([request_id]))
        {
            return Err(StoreError::LeaseLost);
        }
        // This exact immutable observation already happened. No worker admission or
        // drain gate may turn its receipt into a fresh target dispatch.
        let row = sqlx::query(
            "UPDATE url_frontier SET status='leased',lease_owner=$3, \
             lease_expires_at=clock_timestamp()+make_interval(secs=>$4), \
             fencing_token=nextval('lease_fence_seq'),attempts=attempts+1 \
             WHERE run_id=$1 AND frontier_id=$2 AND principal=$5 AND canonical_key=$6 \
             AND via='interaction' AND status='pending' AND next_attempt_at<=clock_timestamp() AND attempts<32767 \
             RETURNING attempts,fencing_token",
        )
        .bind(lease.run.0)
        .bind(request_id)
        .bind(lease.worker.0)
        .bind(crate::leases::secs(self.cfg.url_batch_ttl))
        .bind(principal)
        .bind(queued.identity.key.0.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        observed_session_tx(&mut tx, lease).await?;
        tx.commit().await.map_err(db)?;
        row.map(|row| {
            let mut entry = queued.entry;
            entry.status = FrontierStatus::Leased;
            entry.attempts = conv(get::<i16>(&row, "attempts")?, "attempts")?;
            Ok((entry, get(&row, "fencing_token")?))
        })
        .transpose()
    }
    async fn commit_observed_fenced(
        &self,
        mut commit: RequestCommitV1,
        lease: crawlx_core::custody::CustodyLease,
        epoch: crawlx_core::ObservationEpoch,
    ) -> Result<ObservedCommitV1, StoreError> {
        commit.observation = Some((lease, epoch));
        self.commit_fenced(commit).await?;
        Ok(ObservedCommitV1::Committed)
    }
    async fn begin_feed_finalization(
        &self,
        run: CrawlRunId,
        reason: Option<crawlx_core::counters::TerminalReason>,
    ) -> Result<Option<crawlx_core::counters::TerminalReason>, StoreError> {
        self.begin_feed_finalization_owned(run, reason).await
    }
    async fn stage_feed_batches(
        &self,
        run: CrawlRunId,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.stage_feed_batches_owned(run, batches).await
    }
    async fn staged_feed_batch(
        &self,
        run: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<crawlx_core::dataset::DeliveryBatchV1>, StoreError> {
        self.staged_feed_batch_owned(run, feed, idempotency_key).await
    }
    async fn finalize_run_feeds(
        &self,
        run: CrawlRunId,
        status: crawlx_core::counters::RunStatus,
        reason: crawlx_core::counters::TerminalReason,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.finalize_run_feeds_owned(run, status, reason, batches).await
    }
    async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError> {
        if commit.head_response.is_none() {
            return self.commit_request_owned(commit).await;
        }
        let pg = self.clone();
        let tenant = crate::tenant::current();
        // Dropping this JoinHandle detaches the owner instead of dropping its SQL
        // transaction while the delivery backend may still run spawn_blocking work.
        // The run/fence checks remain inside the owner, before any volatile write.
        tokio::spawn(async move {
            match tenant {
                Some(tenant) => crate::tenant::scope(tenant, pg.commit_request_owned(commit)).await,
                None => pg.commit_request_owned(commit).await,
            }
        })
        .await
        .map_err(|error| StoreError::Backend(format!("HEAD response commit task failed: {error}")))?
    }
    async fn record_extension_attempt(
        &self,
        run: CrawlRunId,
        request_id: i64,
        fence: i64,
        attempt: u32,
        receipts: &[ExtensionReceiptV1],
    ) -> Result<(), StoreError> {
        validate_extension_trail(receipts)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        // Same order as the terminal result: run row first, then the request row.
        let (tenant, _) = lock_run(self, &mut tx, run).await?;
        if crate::tenant::current().is_some_and(|current| current != tenant) {
            return Err(StoreError::AccessDenied(
                "extension attempt tenant mismatch".into(),
            ));
        }
        let row = sqlx::query("SELECT attempts,status::text AS status,fencing_token,lease_expires_at>clock_timestamp() AS live_lease FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND tenant_id=$3 FOR UPDATE")
            .bind(request_id).bind(run.0).bind(tenant.0)
            .fetch_optional(&mut *tx).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        if get::<String>(&row, "status")? != "leased"
            || get::<Option<i64>>(&row, "fencing_token")? != Some(fence)
            || get::<Option<bool>>(&row, "live_lease")? != Some(true)
            || u32::try_from(get::<i16>(&row, "attempts")?).ok() != Some(attempt)
        {
            return Err(StoreError::LeaseLost);
        }
        let key = ExtensionAttemptKey {
            tenant,
            run,
            request_id,
            fence,
            attempt,
        };
        persist_extension_attempt(self, &mut tx, key, receipts).await?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}

impl Pg {
    async fn commit_request_owned(&self, mut commit: RequestCommitV1) -> Result<(), StoreError> {
        commit.validate_processing_evidence()?;
        if matches!(commit.status, FrontierStatus::Pending | FrontierStatus::Leased)
            || commit.reason.as_deref().is_some_and(|reason| {
                reason.len() > 128
                    || !reason
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
            })
        {
            return Err(StoreError::Conflict("invalid request disposition".into()));
        }
        // Retained replay uses the durable digest; ZDR replay also requires live custody.
        let head_receipt = commit.head_response_receipt()?;
        if head_receipt.is_some() {
            let mut conn = self.pool.acquire().await.map_err(db)?;
            let prior = sqlx::query(
                "SELECT r.tenant_id,r.retention_mode='zdr' AS zdr,f.head_response_receipt FROM url_frontier f JOIN crawl_runs r ON r.run_id=f.run_id AND r.tenant_id=f.tenant_id WHERE f.run_id=$1 AND f.frontier_id=$2",
            )
            .bind(commit.run.0)
            .bind(commit.request_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db)?
            .ok_or(StoreError::LeaseLost)?;
            let tenant = TenantId(get(&prior, "tenant_id")?);
            let acquisition_tenant = <TenantId as serde::Deserialize>::deserialize(
                &commit.head_response.as_ref().ok_or(StoreError::LeaseLost)?["acquisition"]["tenant"],
            )?;
            if acquisition_tenant != tenant {
                return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
            }
            if crate::tenant::current().is_some_and(|current| current != tenant) {
                return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
            }
            if let Some(stored) = get::<Option<Vec<u8>>>(&prior, "head_response_receipt")? {
                return check_head_response_receipt(
                    self,
                    &mut conn,
                    &commit,
                    tenant,
                    get(&prior, "zdr")?,
                    &stored,
                    head_receipt,
                )
                .await;
            }
        }
        let run = self.get(commit.run).await?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
        }
        let cfg = run.config.orchestration.clone().unwrap_or_default();
        // Observed rows must never be completed through the generic path, including body-free failures.
        // Fetching the immutable envelope also proves volatile custody before result publication.
        let current = Some(self.request_get(commit.run, commit.request_id).await?);
        if head_receipt.is_some()
            && current
                .as_ref()
                .is_none_or(|request| request.envelope.method != "HEAD")
        {
            return Err(StoreError::Conflict(
                "HEAD response queued method mismatch".into(),
            ));
        }
        if let Some(payload) = &commit.head_response {
            let queued = current.as_ref().ok_or(StoreError::LeaseLost)?;
            let acquisition = &payload["acquisition"];
            // URL evidence may redact path/query secrets; exact authority comes from the queue key.
            let requested_url = <url::Url as serde::Deserialize>::deserialize(&acquisition["requestedUrl"])?;
            if !matches!(requested_url.scheme(), "http" | "https")
                || requested_url.origin() != queued.envelope.url.url.origin()
                || <Digest as serde::Deserialize>::deserialize(&acquisition["requestDigest"])?
                    != queued.identity.key
            {
                return Err(StoreError::Conflict(
                    "HEAD response request identity mismatch".into(),
                ));
            }
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, zdr) = lock_run(self, &mut tx, commit.run).await?;
        if crate::tenant::current().is_some_and(|current| current != tenant) {
            return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
        }
        if let Some(payload) = &commit.head_response {
            if <TenantId as serde::Deserialize>::deserialize(&payload["acquisition"]["tenant"])? != tenant {
                return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
            }
        }
        let result = sqlx::query("SELECT attempts,state_version,head_response_receipt,route_id,principal,lease_owner,via,status::text AS status,fencing_token,lease_expires_at>clock_timestamp() AS live_lease FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 FOR UPDATE")
            .bind(commit.request_id).bind(commit.run.0)
            .fetch_optional(&mut *tx).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        if let Some(stored) = get::<Option<Vec<u8>>>(&result, "head_response_receipt")? {
            // Replay never republishes the event or renews the original volatile page.
            return check_head_response_receipt(self, &mut tx, &commit, tenant, zdr, &stored, head_receipt)
                .await;
        }
        if get::<String>(&result, "status")? != "leased"
            || get::<Option<i64>>(&result, "fencing_token")? != Some(commit.fence)
            || get::<Option<bool>>(&result, "live_lease")? != Some(true)
        {
            return Err(StoreError::LeaseLost);
        }
        let live = get::<i64>(&result, "state_version")?;
        if u64::try_from(live).ok() != Some(commit.expected_state_version) {
            return Err(StoreError::Conflict("request state version changed".into()));
        }
        let observed_principal = if let Some((lease, epoch)) = &commit.observation {
            let principal = observed_session_tx(&mut tx, lease).await?;
            let queued = current.as_ref().ok_or(StoreError::LeaseLost)?;
            let proposal = ObservedRequestV1::from_staged(lease.clone(), *epoch, queued.envelope.clone())?;
            let batch = proposal.batch_id(&principal)?;
            let receipt: Option<serde_json::Value> = sqlx::query_scalar(
                "SELECT receipt FROM frontier_batch_receipts WHERE run_id=$1 AND batch_id=$2",
            )
            .bind(commit.run.0)
            .bind(batch.0.as_slice())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
            if lease.run != commit.run
                || lease.tenant != tenant
                || get::<String>(&result, "via")? != "interaction"
                || get::<String>(&result, "principal")? != principal
                || get::<Option<uuid::Uuid>>(&result, "lease_owner")? != Some(lease.worker.0)
                || queued.envelope.metadata.get("observed_epoch") != Some(&serde_json::to_value(batch)?)
                || receipt.as_ref().and_then(|receipt| receipt.get("inserted"))
                    != Some(&serde_json::json!([commit.request_id]))
                || commit.head_response.is_some()
            {
                return Err(StoreError::LeaseLost);
            }
            Some(principal)
        } else {
            if get::<String>(&result, "via")? == "interaction"
                || current
                    .as_ref()
                    .is_some_and(|queued| queued.envelope.metadata.contains_key("observed_epoch"))
            {
                return Err(StoreError::LeaseLost);
            }
            None
        };
        if head_receipt.is_some() {
            let active: bool = sqlx::query_scalar(
                "SELECT status NOT IN ('completed','failed','cancelled') FROM crawl_runs WHERE run_id=$1",
            )
            .bind(commit.run.0)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            if !active {
                return Err(StoreError::AccessDenied("HEAD response run is terminal".into()));
            }
            let authority = sqlx::query("SELECT a.revoked_at,a.valid_from,a.valid_to,a.body_digest,r.authorization_body_digest FROM crawl_runs r JOIN authorization_records a ON a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id WHERE r.run_id=$1 FOR SHARE OF a")
                .bind(commit.run.0).fetch_optional(&mut *tx).await.map_err(db)?;
            let now = chrono::Utc::now();
            let allowed = match authority {
                Some(row) => {
                    get::<Option<crawlx_core::Timestamp>>(&row, "revoked_at")?.is_none()
                        && get::<crawlx_core::Timestamp>(&row, "valid_from")? <= now
                        && get::<crawlx_core::Timestamp>(&row, "valid_to")? > now
                        && get::<Option<Vec<u8>>>(&row, "authorization_body_digest")?.is_none_or(|bound| {
                            get::<Vec<u8>>(&row, "body_digest").is_ok_and(|digest| bound == digest)
                        })
                }
                None => run.config.safety.authorization_record_ref.is_none(),
            };
            if !allowed {
                return Err(StoreError::AccessDenied(
                    "HEAD response authorization is not live".into(),
                ));
            }
            if run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr
                && run.config.retention.days != 0
                && run.created_at + chrono::Duration::days(i64::from(run.config.retention.days)) <= now
            {
                return Err(StoreError::RetentionDenied(
                    "committed HEAD source expired".into(),
                ));
            }
        }
        if let Some(page) = &commit.page {
            if page.run != commit.run
                || page.frontier_id != commit.request_id
                || commit.status != FrontierStatus::Succeeded
            {
                return Err(StoreError::Conflict("result page authority mismatch".into()));
            }
            if current
                .as_ref()
                .is_none_or(|request| request.envelope.url.key != page.url.key)
            {
                return Err(StoreError::Conflict("result page url mismatch".into()));
            }
        }
        if commit.content_dedupe.is_some() {
            crate::digest_registry::check_source(&run, chrono::Utc::now())?;
        }
        crate::digest_registry::validate_commit(&commit, tenant)?;
        let digest_outcome = if let Some(claim) = &commit.content_dedupe {
            let outcome = crate::digest_registry::claim_pg(&mut tx, claim, commit.request_id).await?;
            crate::digest_registry::apply_outcome(&mut commit, &outcome);
            Some(outcome)
        } else {
            None
        };
        let mut children = commit.children.take();
        if let Some(batch) = &children {
            if batch.run != commit.run
                || batch.parent_fence != Some((commit.request_id, commit.fence))
                || batch
                    .requests
                    .iter()
                    .any(|request| request.revisit_generation != 0)
            {
                return Err(StoreError::Conflict("result child authority mismatch".into()));
            }
        }
        if let (Some(policy), Some(current)) = (
            &cfg.recrawl,
            current.filter(|_| {
                matches!(commit.status, FrontierStatus::Succeeded | FrontierStatus::Failed)
                    && observed_principal.is_none()
            }),
        ) {
            let authority = sqlx::query("SELECT a.record_id,a.revoked_at,a.valid_from,a.valid_to,a.body_digest,r.authorization_body_digest FROM crawl_runs r JOIN authorization_records a ON a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id WHERE r.run_id=$1 FOR SHARE OF a")
                .bind(commit.run.0).fetch_optional(&mut *tx).await.map_err(db)?;
            let now = chrono::Utc::now();
            let allowed = match authority {
                Some(row) => {
                    get::<Option<crawlx_core::Timestamp>>(&row, "revoked_at")?.is_none()
                        && get::<crawlx_core::Timestamp>(&row, "valid_from")? <= now
                        && get::<crawlx_core::Timestamp>(&row, "valid_to")? > now
                        && get::<Option<Vec<u8>>>(&row, "authorization_body_digest")?.is_none_or(|bound| {
                            get::<Vec<u8>>(&row, "body_digest").is_ok_and(|digest| bound == digest)
                        })
                }
                None => run.config.safety.authorization_record_ref.is_none(),
            };
            let deadline = run.started_at.unwrap_or(run.created_at)
                + chrono::Duration::seconds(i64::from(run.config.limits.duration_seconds));
            if allowed {
                if let Some(decision) =
                    policy.next_visit_after_commit(&current.envelope, &commit, now, deadline, None)?
                {
                    let next = decision.request;
                    let principal: String =
                        sqlx::query_scalar("SELECT principal FROM url_frontier WHERE frontier_id=$1")
                            .bind(commit.request_id)
                            .fetch_one(&mut *tx)
                            .await
                            .map_err(db)?;
                    let batch = children.get_or_insert_with(|| {
                        let mut batch = RequestBatchV1::new(
                            run.tenant,
                            run.id,
                            principal,
                            Digest::of("crawlx/recrawl-batch/v1", &commit.request_id.to_be_bytes()),
                            Vec::new(),
                        );
                        batch.parent_fence = Some((commit.request_id, commit.fence));
                        batch
                    });
                    batch.requests.push(next);
                }
            }
        }
        if let Some(batch) = &children {
            append(
                self,
                &mut tx,
                batch,
                &cfg,
                true,
                None,
                run.config.limits.duration_seconds,
            )
            .await?;
        }
        crate::dataset::apply_pg(
            self,
            &mut tx,
            commit.run,
            commit.request_id,
            &commit.accepted,
            &commit.state_deltas,
            &commit.outbox,
        )
        .await?;
        if !commit.extensions.is_empty() {
            let attempt = u32::try_from(get::<i16>(&result, "attempts")?)
                .map_err(|_| StoreError::Conflict("invalid extension attempt".into()))?;
            let key = ExtensionAttemptKey {
                tenant,
                run: commit.run,
                request_id: commit.request_id,
                fence: commit.fence,
                attempt,
            };
            persist_extension_attempt(self, &mut tx, key, &commit.extensions).await?;
        }
        // Facts share the fenced result transaction and run before any commit field is moved.
        crate::report_history::append_commit_facts_pg(&mut tx, &commit, tenant).await?;
        if let Some(page) = commit.page {
            // Duplicate results retain their own immutable capture, never replace another page.
            if !digest_outcome
                .as_ref()
                .is_some_and(|outcome| outcome.is_duplicate())
                || observed_principal.is_some()
            {
                self.put_page_projection_tx(
                    &page,
                    &mut tx,
                    observed_principal.as_deref().unwrap_or("anonymous"),
                    observed_principal.is_some(),
                )
                .await?;
            }
            if run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr {
                sqlx::query(
                    "INSERT INTO page_captures (tenant_id,run_id,frontier_id,fence,state_version,payload) \
                     VALUES ($1,$2,$3,$4,$5,$6)",
                )
                .bind(run.tenant.0)
                .bind(commit.run.0)
                .bind(commit.request_id)
                .bind(commit.fence)
                .bind(live)
                .bind(
                    serde_json::to_value(page)
                        .map_err(|error| StoreError::Serialization(error.to_string()))?,
                )
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            }
        }
        if let Some(payload) = commit.head_response {
            #[cfg(all(test, target_os = "linux"))]
            tests::before_head_publish(&mut tx, commit.run).await;
            crate::repos::event::append_head_response(
                self,
                &mut tx,
                commit.run,
                head_receipt.ok_or_else(|| StoreError::Conflict("missing HEAD response receipt".into()))?,
                payload,
            )
            .await?;
        }
        if let Some(receipt) = head_receipt {
            sqlx::query("UPDATE url_frontier SET head_response_receipt=$2 WHERE frontier_id=$1")
                .bind(commit.request_id)
                .bind(if zdr {
                    ZDR_HEAD_RECEIPT_MARKER.as_slice()
                } else {
                    receipt.0.as_slice()
                })
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        if let Some(outcome) = &digest_outcome {
            sqlx::query(
                "UPDATE url_frontier SET content_dedupe_outcome=$3 WHERE run_id=$1 AND frontier_id=$2",
            )
            .bind(commit.run.0)
            .bind(commit.request_id)
            .bind(serde_json::to_value(outcome)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        let completed=sqlx::query("UPDATE url_frontier SET status=$2,error_code=$3,finished_at=now(),lease_owner=NULL,lease_expires_at=NULL,state_version=state_version+1,acquisition_ref=$4,document_ref=$5 WHERE frontier_id=$1 AND status='leased' AND fencing_token=$6 AND lease_expires_at>clock_timestamp()")
            .bind(commit.request_id).bind(commit.status.as_str()).bind(commit.reason).bind(commit.acquisition_ref.filter(|_| !zdr || head_receipt.is_none()).map(|digest|digest.0.to_vec())).bind(commit.document_ref.map(|digest|digest.0.to_vec())).bind(commit.fence).execute(&mut *tx).await.map_err(db)?;
        if completed.rows_affected() != 1 {
            return Err(StoreError::LeaseLost);
        }
        if let Some((lease, _)) = &commit.observation {
            observed_session_tx(&mut tx, lease).await?;
        }
        crate::chaos::pause("request.before_result_commit").await;
        tx.commit().await.map_err(db)?;
        crate::chaos::pause("request.after_result_commit").await;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::artifacts::FsArtifactStore;
    use crate::retention::RetentionSweeper;
    use crate::testkit::{canonical_url, crawl_run, create_crawl};
    use crate::{DeliveryBuffer, PgConfig};
    use crawlx_core::repo::FrontierRepo;
    use crawlx_core::{SystemClock, WorkerId};
    use std::os::unix::fs::MetadataExt;
    use std::sync::{Arc, LazyLock};
    use tokio::sync::oneshot;

    struct HeadPause {
        ready: oneshot::Sender<i32>,
        release: oneshot::Receiver<()>,
    }

    static HEAD_PAUSES: LazyLock<parking_lot::Mutex<BTreeMap<CrawlRunId, HeadPause>>> =
        LazyLock::new(|| parking_lot::Mutex::new(BTreeMap::new()));

    pub(super) async fn before_head_publish(conn: &mut sqlx::PgConnection, run: CrawlRunId) {
        let pause = HEAD_PAUSES.lock().remove(&run);
        if let Some(pause) = pause {
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(conn)
                .await
                .unwrap();
            pause.ready.send(pid).unwrap();
            pause.release.await.unwrap();
        }
    }

    async fn wait_for_erasure_blocker(pg: &Pg, owner: i32) {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity a \
                     WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid)))",
                )
                .bind(owner)
                .fetch_one(&pg.pool)
                .await
                .unwrap();
                if blocked {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("erasure must wait for the owned HEAD transaction");
    }

    async fn wait_for_filesystem_writer(inode: u64) {
        let inode = format!(":{inode}");
        let pid = std::process::id().to_string();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let locks = tokio::fs::read_to_string("/proc/locks").await.unwrap();
                if locks.lines().any(|line| {
                    line.contains("->")
                        && line.split_whitespace().any(|part| part == "FLOCK")
                        && line.split_whitespace().any(|part| part == pid)
                        && line.split_whitespace().any(|part| part.ends_with(&inode))
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the actual filesystem writer must block on the held OS lock");
    }

    #[tokio::test]
    async fn cancelled_head_commit_keeps_transaction_until_filesystem_publication_before_erasure() {
        let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            return;
        };
        let root = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let buffer = Arc::new(
            DeliveryBuffer::open_fs(root.path(), clock.clone(), Default::default())
                .await
                .unwrap(),
        );
        let pg = Pg::connect(
            &url,
            PgConfig {
                max_connections: 4,
                schema: Some(format!("head_cancel_{}", CrawlRunId::new().0.simple())),
                ..PgConfig::default()
            },
        )
        .await
        .unwrap()
        .with_delivery_buffer(buffer.clone());
        pg.migrate().await.unwrap();
        let tenant = TenantId::new();
        pg.ensure_tenant(tenant, "head-cancellation").await.unwrap();
        let mut config = create_crawl("https://example.test/", &[], 1);
        config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
        config.retention.days = 0;
        config.orchestration = Some(OrchestrationConfigV1::default());
        let run = crawl_run(tenant, config);
        pg.create(&run, None).await.unwrap();
        let mut envelope = RequestEnvelopeV1::get(canonical_url("https://example.test/head"), 0, None);
        envelope.method = "HEAD".into();
        let ids = pg
            .append_batch(RequestBatchV1::new(
                tenant,
                run.id,
                "anonymous".into(),
                Digest::of("test/head-cancellation", b"batch"),
                vec![envelope],
            ))
            .await
            .unwrap()
            .inserted;
        let leased = pg.lease_batch_fenced(run.id, WorkerId::new(), 1).await.unwrap();
        let queued = pg.get_request(run.id, ids[0]).await.unwrap();
        let mut acquisition = crawlx_core::acquisition::AcquisitionResultV1::new(
            run.id,
            tenant,
            queued.envelope.url.url.clone(),
            queued.identity.key,
            crawlx_core::acquisition::BackendCapabilitiesV1::native_http("crawlx-fetch", "test"),
        );
        acquisition.target_status = Some(200);
        acquisition.transport_succeeded = true;
        let mut commit =
            RequestCommitV1::terminal(run.id, ids[0], leased[0].1, 1, FrontierStatus::Succeeded, None);
        commit.head_response = Some(serde_json::json!({
            "requestId": ids[0],
            "method": "HEAD",
            "status": 200,
            "bodyBytes": 0,
            "response_headers": {"content-type": "text/html"},
            "acquisition": acquisition
        }));
        let (ready, staged) = oneshot::channel();
        let (release, proceed) = oneshot::channel();
        HEAD_PAUSES.lock().insert(
            run.id,
            HeadPause {
                ready,
                release: proceed,
            },
        );
        let caller = {
            let pg = pg.clone();
            let commit = commit.clone();
            tokio::spawn(async move { pg.commit_fenced(commit).await })
        };
        let owner = tokio::time::timeout(std::time::Duration::from_secs(30), staged)
            .await
            .unwrap()
            .unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.path().join("zdr/.lock"))
            .unwrap();
        let inode = lock.metadata().unwrap().ino();
        lock.lock().unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let store = Arc::new(
            FsArtifactStore::open(root.path().join("objects"), Arc::new(pg.clone()), clock)
                .await
                .unwrap()
                .with_zdr_buffer(buffer.clone()),
        );
        let erasing = {
            let sweeper = RetentionSweeper::new(pg.clone()).with_artifacts(store);
            tokio::spawn(async move { sweeper.purge_run_objects(run.id).await })
        };
        wait_for_erasure_blocker(&pg, owner).await;
        release.send(()).unwrap();
        wait_for_filesystem_writer(inode).await;
        wait_for_erasure_blocker(&pg, owner).await;
        assert!(!erasing.is_finished());
        lock.unlock().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), erasing)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(buffer.is_empty().await.unwrap());
        let events: i64 =
            sqlx::query_scalar("SELECT count(*) FROM crawl_events WHERE run_id=$1 AND type='head_response'")
                .bind(run.id.0)
                .fetch_one(&pg.pool)
                .await
                .unwrap();
        assert_eq!(
            events, 1,
            "the detached owner must finish its real publication before erasure"
        );
        assert!(matches!(
            pg.commit_fenced(commit).await,
            Err(StoreError::RetentionDenied(_))
        ));
        assert!(buffer.is_empty().await.unwrap());
        pg.drop_schema().await.unwrap();
    }
}
