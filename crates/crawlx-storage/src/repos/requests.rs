//! Request extensions of the authoritative URL frontier.
use super::*;
use crawlx_core::acquisition::{AcquisitionAllowanceV1, AcquisitionUsageV1};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::*;
use crawlx_core::repo::RunRepo;
use crawlx_core::request::{RequestEnvelopeV1, RequestIdentityV1};
use crawlx_core::TenantId;
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};

pub(super) async fn lock_run(
    _pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    run: CrawlRunId,
) -> Result<(TenantId, bool), StoreError> {
    let row = sqlx::query("SELECT tenant_id, retention_mode = 'zdr' AS zdr, status::text AS status, deadline_at FROM crawl_runs WHERE run_id=$1 FOR UPDATE")
        .bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?.ok_or_else(|| not_found("crawl run", run))?;
    Ok((TenantId(get(&row, "tenant_id")?), get(&row, "zdr")?))
}

pub(super) async fn append(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    batch: &RequestBatchV1,
    cfg: &OrchestrationConfigV1,
    completing: bool,
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
    let admits = sqlx::query_scalar::<_,bool>("SELECT status IN ('queued','running','paused') AND (deadline_at IS NULL OR deadline_at>now()) FROM crawl_runs WHERE run_id=$1")
        .bind(batch.run.0).fetch_one(&mut **tx).await.map_err(db)?;
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
        || (get::<bool>(&producer, "sealed")? && batch.parent_fence.is_none())
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
        let id: i64 = sqlx::query_scalar("INSERT INTO url_frontier(run_id,canonical_key,canonical_url,origin,query_schema,depth,priority,via,parent_id,principal,route_id,revisit_generation,request_envelope,envelope_bytes,next_attempt_at,status,denial_reason,finished_at,strategy_score) VALUES($1,$2,$3,$4,$5,$6,$7,'link',$8,$9,$10,$11,$12,$13,COALESCE($14,now()),$15,$16,CASE WHEN $15<>'pending' THEN now() END,$17) RETURNING frontier_id")
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
        let cfg = self
            .get(batch.run)
            .await?
            .config
            .orchestration
            .unwrap_or_default();
        let mut tx = self.pool.begin().await.map_err(db)?;
        let receipt = append(self, &mut tx, &batch, &cfg, false).await?;
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
        let row=sqlx::query("SELECT EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND status='pending' AND next_attempt_at<=now()) AS ready, EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND status='pending') AS pending, EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND status='leased') AS leased, (SELECT sealed FROM frontier_producers WHERE run_id=$1) AS sealed")
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

#[async_trait]
impl RequestCommitRepo for Pg {
    async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError> {
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
        let run = self.get(commit.run).await?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
        }
        let cfg = run.config.orchestration.clone().unwrap_or_default();
        let current = if commit.page.is_some()
            || (cfg.recrawl.is_some() && commit.status == FrontierStatus::Succeeded)
        {
            Some(self.request_get(commit.run, commit.request_id).await?.envelope)
        } else {
            None
        };
        let mut tx = self.pool.begin().await.map_err(db)?;
        lock_run(self, &mut tx, commit.run).await?;
        let live=sqlx::query_scalar::<_,i64>("SELECT state_version FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND status='leased' AND fencing_token=$3 AND lease_expires_at>clock_timestamp() FOR UPDATE")
            .bind(commit.request_id).bind(commit.run.0).bind(commit.fence).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        if u64::try_from(live).ok() != Some(commit.expected_state_version) {
            return Err(StoreError::Conflict("request state version changed".into()));
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
                .is_none_or(|request| request.url.key != page.url.key)
            {
                return Err(StoreError::Conflict("result page url mismatch".into()));
            }
        }
        let mut children = commit.children;
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
        if let (Some(policy), Some(current)) = (&cfg.recrawl, current) {
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
                if let Some(next) = policy.next_visit(&current, commit.request_id, now, deadline)? {
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
            append(self, &mut tx, batch, &cfg, true).await?;
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
        if let Some(page) = commit.page {
            self.put_page_tx(&page, &mut tx).await?;
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
        let completed=sqlx::query("UPDATE url_frontier SET status=$2,error_code=$3,finished_at=now(),lease_owner=NULL,lease_expires_at=NULL,state_version=state_version+1,acquisition_ref=$4,document_ref=$5 WHERE frontier_id=$1 AND status='leased' AND fencing_token=$6 AND lease_expires_at>clock_timestamp()")
            .bind(commit.request_id).bind(commit.status.as_str()).bind(commit.reason).bind(commit.acquisition_ref.map(|digest|digest.0.to_vec())).bind(commit.document_ref.map(|digest|digest.0.to_vec())).bind(commit.fence).execute(&mut *tx).await.map_err(db)?;
        if completed.rows_affected() != 1 {
            return Err(StoreError::LeaseLost);
        }
        crate::chaos::pause("request.before_result_commit").await;
        tx.commit().await.map_err(db)?;
        crate::chaos::pause("request.after_result_commit").await;
        Ok(())
    }
}
