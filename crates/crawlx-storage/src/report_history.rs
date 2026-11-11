//! Tenant-scoped measured history under the existing producer and retention authorities.
//!
//! Retained facts contain only finite typed metadata. ZDR payloads use the existing
//! volatile delivery buffer; their durable rows carry only opaque receipts and bounds.
//! Keyset filters run before the finite page limit. No whole-run aggregate is implied.

use crate::codec::get;
use crate::error::db;
use crate::Pg;
use async_trait::async_trait;
use crawlx_core::custody::{CustodyLease, CustodySource};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::RequestCommitV1;
use crawlx_core::report_history::{
    PipelineProgressV1, PipelineStageV1, PipelineStateV1, ProcessorStageV1, ReportDataV1, ReportEntryV1,
    ReportFactV1, ReportHistoryRepo, ReportKindV1, ReportPageV1, ReportQueryV1,
};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};
use sqlx::{Postgres, Transaction};

const MAX_FACTS_PER_RUN: i64 = 65_536;

fn conflict(message: &'static str) -> StoreError {
    StoreError::Conflict(message.into())
}

fn tenant_scope(tenant: TenantId) -> Result<(), StoreError> {
    if crate::tenant::current().is_some_and(|current| current != tenant) {
        return Err(StoreError::AccessDenied("report tenant mismatch".into()));
    }
    Ok(())
}

fn kind_label(kind: ReportKindV1) -> Result<&'static str, StoreError> {
    match kind {
        ReportKindV1::Dns => Ok("dns"),
        ReportKindV1::Stage => Ok("stage"),
        ReportKindV1::Wire => Ok("wire"),
        ReportKindV1::Alert => Ok("alert"),
        ReportKindV1::Loss => Ok("loss"),
        ReportKindV1::Pipeline => Ok("pipeline"),
        _ => Err(conflict("unsupported report kind")),
    }
}

/// Calculate the immutable source ceiling without extending it on a read or retry.
///
/// # Errors
/// Returns retention denial on elapsed ceilings or invalid source timestamps.
pub(crate) fn source_deadline(
    created: Timestamp,
    days: i32,
    expires: Option<Timestamp>,
    now: Timestamp,
    zdr: bool,
) -> Result<Option<Timestamp>, StoreError> {
    let policy = if zdr {
        Some(
            created
                .checked_add_signed(chrono::Duration::hours(1))
                .ok_or_else(|| conflict("report volatile deadline overflow"))?,
        )
    } else if days > 0 {
        Some(
            created
                .checked_add_signed(chrono::Duration::days(i64::from(days)))
                .ok_or_else(|| conflict("report source deadline overflow"))?,
        )
    } else {
        None
    };
    let deadline = match (policy, expires) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    if deadline.is_some_and(|deadline| deadline <= now) {
        return Err(StoreError::RetentionDenied("report source expired".into()));
    }
    Ok(deadline)
}

// PostgreSQL row locks and authoritative clock are confined to this adapter.
async fn locked_source(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(Timestamp, bool, Option<Timestamp>), StoreError> {
    let row = sqlx::query("SELECT created_at,retention_days,retention_mode='zdr' AS zdr,expires_at,purge_requested_at FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2 FOR UPDATE")
        .bind(tenant.0).bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?
        .ok_or_else(|| StoreError::AccessDenied("report run unavailable".into()))?;
    let now: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    if get::<Option<Timestamp>>(&row, "purge_requested_at")?.is_some() {
        return Err(StoreError::RetentionDenied("report source being purged".into()));
    }
    let zdr: bool = get(&row, "zdr")?;
    let expiry = source_deadline(
        get(&row, "created_at")?,
        get(&row, "retention_days")?,
        get(&row, "expires_at")?,
        now,
        zdr,
    )?;
    Ok((now, zdr, expiry))
}

fn volatile_page(sequence: i64) -> Result<i64, StoreError> {
    // Tag four is disjoint from run configuration, accepted items and feed manifests.
    if !(1..(1_i64 << 56)).contains(&sequence) {
        return Err(conflict("report volatile namespace exhausted"));
    }
    i64::MIN
        .checked_add(4_i64 << 56)
        .and_then(|base| base.checked_add(sequence))
        .ok_or_else(|| conflict("report volatile namespace overflow"))
}

async fn pipeline_fact(
    tx: &mut Transaction<'_, Postgres>,
    fact: &ReportFactV1,
    expiry: Option<Timestamp>,
) -> Result<(), StoreError> {
    if !matches!(
        fact.data,
        ReportDataV1::Pipeline { .. }
            | ReportDataV1::Stage {
                stage: ProcessorStageV1::Delivery,
                ..
            }
    ) {
        return Ok(());
    }
    let Some(request) = fact.request_id else {
        return if matches!(fact.data, ReportDataV1::Pipeline { .. }) {
            Err(conflict("pipeline fact requires request identity"))
        } else {
            Ok(())
        };
    };
    let prior: Option<serde_json::Value> = sqlx::query_scalar("SELECT progress FROM request_pipeline_history WHERE tenant_id=$1 AND run_id=$2 AND request_id=$3 AND attempt=$4")
        .bind(fact.tenant.0).bind(fact.run.0).bind(request).bind(i32::from(fact.attempt))
        .fetch_optional(&mut **tx).await.map_err(db)?;
    let mut progress: PipelineProgressV1 = prior.map(serde_json::from_value).transpose()?.unwrap_or_default();
    progress.apply(&fact.data)?;
    let progress = serde_json::to_value(progress)?;
    sqlx::query("INSERT INTO request_pipeline_history(tenant_id,run_id,request_id,attempt,progress,source_fact,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(tenant_id,run_id,request_id,attempt) DO UPDATE SET progress=excluded.progress,source_fact=excluded.source_fact,expires_at=CASE WHEN request_pipeline_history.expires_at IS NULL THEN excluded.expires_at WHEN excluded.expires_at IS NULL THEN request_pipeline_history.expires_at WHEN request_pipeline_history.expires_at<excluded.expires_at THEN request_pipeline_history.expires_at ELSE excluded.expires_at END")
        .bind(fact.tenant.0).bind(fact.run.0).bind(request).bind(i32::from(fact.attempt)).bind(progress).bind(serde_json::to_value(fact)?).bind(expiry)
        .execute(&mut **tx).await.map_err(db)?;
    Ok(())
}

async fn insert_fact(
    tx: &mut Transaction<'_, Postgres>,
    fact: &ReportFactV1,
    expiry: Option<Timestamp>,
    durable: bool,
) -> Result<(i64, bool), StoreError> {
    fact.validate()?;
    let bytes = serde_json::to_vec(fact)?;
    if bytes.len() > 4096 {
        return Err(conflict("report fact exceeds byte bound"));
    }
    let receipt = Digest::of("crawlx/report-fact/v1", &bytes);
    let prior = sqlx::query(
        "SELECT fact_sequence,receipt FROM report_history WHERE tenant_id=$1 AND run_id=$2 AND fact_id=$3",
    )
    .bind(fact.tenant.0)
    .bind(fact.run.0)
    .bind(fact.id.0.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?;
    if let Some(prior) = prior {
        if get::<Vec<u8>>(&prior, "receipt")? != receipt.0 {
            return Err(conflict("report fact identity reused with different evidence"));
        }
        return Ok((get(&prior, "fact_sequence")?, false));
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM report_history WHERE tenant_id=$1 AND run_id=$2")
            .bind(fact.tenant.0)
            .bind(fact.run.0)
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?;
    if count >= MAX_FACTS_PER_RUN {
        return Err(conflict("report history run capacity exhausted"));
    }
    if durable {
        pipeline_fact(tx, fact, expiry).await?;
    }
    let payload = durable.then(|| serde_json::to_value(fact)).transpose()?;
    let sequence: i64 = sqlx::query_scalar("INSERT INTO report_history(tenant_id,run_id,fact_id,receipt,kind,observed_at,url_key,host_key,duration_us,wire_bytes,fact,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING fact_sequence")
        .bind(fact.tenant.0).bind(fact.run.0).bind(fact.id.0.as_slice()).bind(receipt.0.as_slice())
        .bind(kind_label(fact.data.kind())?).bind(fact.at)
        .bind(fact.url_key.map(|key| key.0.to_vec())).bind(fact.host_key.map(|key| key.0.to_vec()))
        .bind(fact.data.duration_us().map(i64::try_from).transpose().map_err(|_| conflict("report duration overflow"))?)
        .bind(fact.data.wire_bytes().map(i64::try_from).transpose().map_err(|_| conflict("report wire size overflow"))?)
        .bind(payload).bind(expiry).fetch_one(&mut **tx).await.map_err(db)?;
    Ok((sequence, true))
}

#[async_trait]
impl ReportHistoryRepo for Pg {
    async fn append_fact(&self, lease: &CustodyLease, fact: &ReportFactV1) -> Result<u64, StoreError> {
        tenant_scope(lease.tenant)?;
        fact.validate()?;
        fact.validate_lease(lease)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (_, zdr, expiry) = locked_source(&mut tx, lease.tenant, lease.run).await?;
        crate::custody::live(&mut tx, lease).await?;
        let request = match lease.source {
            CustodySource::Url(request) => {
                if fact.request_id.is_some_and(|id| id != request) {
                    return Err(StoreError::LeaseLost);
                }
                Some(request)
            }
            _ => fact.request_id,
        };
        if let Some(request) = request {
            let attempts: Option<i16> = sqlx::query_scalar(
                "SELECT attempts FROM url_frontier WHERE tenant_id=$1 AND run_id=$2 AND frontier_id=$3",
            )
            .bind(lease.tenant.0)
            .bind(lease.run.0)
            .bind(request)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
            if attempts
                .and_then(|value| u16::try_from(value).ok())
                .map(|value| value.max(1))
                != Some(fact.attempt)
            {
                return Err(StoreError::LeaseLost);
            }
        }
        let (sequence, _) = insert_fact(&mut tx, fact, expiry, !zdr).await?;
        if zdr {
            let buffer = self
                .delivery
                .as_ref()
                .ok_or_else(|| StoreError::RetentionDenied("volatile report sink unavailable".into()))?;
            let expiry = expiry.ok_or_else(|| conflict("volatile report deadline missing"))?;
            buffer
                .insert_until(
                    lease.tenant,
                    lease.run,
                    volatile_page(sequence)?,
                    "_report_fact",
                    "application/json",
                    &serde_json::to_vec(fact)?,
                    expiry,
                )
                .await?;
        }
        crate::custody::live(&mut tx, lease).await?;
        tx.commit().await.map_err(db)?;
        u64::try_from(sequence).map_err(|_| conflict("report sequence overflow"))
    }

    async fn query_facts(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        query: &ReportQueryV1,
    ) -> Result<ReportPageV1, StoreError> {
        tenant_scope(tenant)?;
        query.validate()?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        if let Some(run) = run {
            let (_, zdr, _) = locked_source(&mut tx, tenant, run).await?;
            if zdr {
                return Err(StoreError::RetentionDenied(
                    "volatile report history withheld".into(),
                ));
            }
        }
        let now: Timestamp = sqlx::query_scalar("SELECT CURRENT_TIMESTAMP")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let rows = sqlx::query("SELECT h.fact_sequence,h.fact FROM report_history h JOIN crawl_runs r ON r.tenant_id=h.tenant_id AND r.run_id=h.run_id WHERE h.tenant_id=$1 AND COALESCE(h.run_id=$2,$2 IS NULL) AND h.fact_sequence>$3 AND h.fact IS NOT NULL AND (h.expires_at IS NULL OR h.expires_at>$4) AND r.retention_mode<>'zdr' AND r.purge_requested_at IS NULL AND (r.expires_at IS NULL OR r.expires_at>$4) AND COALESCE(h.kind=$5,$5 IS NULL) AND COALESCE(h.url_key=$6,$6 IS NULL) AND COALESCE(h.host_key=$7,$7 IS NULL) AND COALESCE(h.observed_at>=$8,$8 IS NULL) AND COALESCE(h.observed_at<=$9,$9 IS NULL) AND COALESCE(h.duration_us>=$10,$10 IS NULL) AND COALESCE(h.duration_us<=$11,$11 IS NULL) AND COALESCE(h.wire_bytes>=$12,$12 IS NULL) AND COALESCE(h.wire_bytes<=$13,$13 IS NULL) ORDER BY h.fact_sequence LIMIT $14")
            .bind(tenant.0).bind(run.map(|id|id.0)).bind(i64::try_from(query.after).map_err(|_| conflict("report cursor overflow"))?).bind(now)
            .bind(query.kind.map(kind_label).transpose()?).bind(query.url_key.map(|key|key.0.to_vec())).bind(query.host_key.map(|key|key.0.to_vec()))
            .bind(query.since).bind(query.until)
            .bind(query.min_duration_us.map(i64::try_from).transpose().map_err(|_| conflict("report duration overflow"))?)
            .bind(query.max_duration_us.map(i64::try_from).transpose().map_err(|_| conflict("report duration overflow"))?)
            .bind(query.min_wire_bytes.map(i64::try_from).transpose().map_err(|_| conflict("report wire size overflow"))?)
            .bind(query.max_wire_bytes.map(i64::try_from).transpose().map_err(|_| conflict("report wire size overflow"))?)
            .bind(i64::from(query.limit)+1).fetch_all(&mut *tx).await.map_err(db)?;
        let limit = usize::try_from(query.limit).map_err(|_| conflict("report limit overflow"))?;
        let more = rows.len() > limit;
        let mut entries = Vec::with_capacity(rows.len().min(limit));
        for row in rows.into_iter().take(limit) {
            let sequence = u64::try_from(get::<i64>(&row, "fact_sequence")?)
                .map_err(|_| conflict("report sequence overflow"))?;
            let fact: ReportFactV1 = serde_json::from_value(get(&row, "fact")?)?;
            fact.validate()?;
            if fact.tenant != tenant || run.is_some_and(|run| fact.run != run) || !query.matches(&fact) {
                return Err(conflict("report row scope or projection mismatch"));
            }
            entries.push(ReportEntryV1::new(sequence, fact));
        }
        let next = more.then(|| entries.last().map(|entry| entry.sequence)).flatten();
        tx.commit().await.map_err(db)?;
        Ok(ReportPageV1::new(entries, next))
    }
}

/// Build checkpoints from actual commit references; parse success is never inferred.
/// # Errors
/// Returns malformed scope or bounded fact encoding errors.
pub(crate) fn commit_checkpoints(
    commit: &RequestCommitV1,
    tenant: TenantId,
    at: Timestamp,
    attempt: u16,
) -> Result<Vec<ReportFactV1>, StoreError> {
    use crawlx_core::repo::FrontierStatus;
    if commit.report_facts.len() > 60 {
        return Err(conflict("too many result report facts"));
    }
    let fallback = CustodyLease::for_url(
        tenant,
        commit.run,
        commit.request_id,
        crawlx_core::WorkerId(uuid::Uuid::nil()),
        commit.fence,
    );
    let lease = commit.observation.as_ref().map_or(&fallback, |(lease, _)| lease);
    let mut facts = Vec::with_capacity(commit.report_facts.len() + 3);
    let recorded = |stage| {
        commit
            .report_facts
            .iter()
            .any(|fact| matches!(fact.data,ReportDataV1::Pipeline{stage:actual,..} if actual==stage))
    };
    if !recorded(PipelineStageV1::Fetch) {
        let state = if commit.acquisition_ref.is_some() || commit.page.is_some() {
            if commit.status == FrontierStatus::Succeeded {
                PipelineStateV1::Succeeded
            } else {
                PipelineStateV1::Failed
            }
        } else {
            PipelineStateV1::Skipped
        };
        facts.push(checkpoint(
            lease,
            commit.request_id,
            attempt,
            at,
            PipelineStageV1::Fetch,
            state,
            "crawlx/report-commit/v1",
        )?);
    }
    facts.extend(commit.report_facts.iter().cloned());
    for stage in [PipelineStageV1::Index, PipelineStageV1::Completion] {
        if !recorded(stage) {
            let state = if commit.outbox.is_empty() {
                PipelineStateV1::Skipped
            } else {
                PipelineStateV1::Pending
            };
            facts.push(checkpoint(
                lease,
                commit.request_id,
                attempt,
                at,
                stage,
                state,
                "crawlx/report-commit/v1",
            )?);
        }
    }
    Ok(facts)
}

fn checkpoint(
    lease: &CustodyLease,
    request: i64,
    attempt: u16,
    at: Timestamp,
    stage: PipelineStageV1,
    state: PipelineStateV1,
    domain: &'static str,
) -> Result<ReportFactV1, StoreError> {
    let id = Digest::of(
        domain,
        &serde_json::to_vec(&(lease.tenant, lease.run, request, lease.fence, attempt, stage))?,
    );
    let mut fact = ReportFactV1::new(lease, id, at, ReportDataV1::Pipeline { stage, state });
    fact.request_id = Some(request);
    fact.attempt = attempt;
    fact.validate()?;
    Ok(fact)
}

/// Append result facts inside the already-locked request result transaction.
///
/// The caller must validate the original request/session lease before this call
/// and again before COMMIT. This helper never grants acquisition authority.
/// # Errors
/// Returns invalid scope, bounds, retention or database errors; caller rolls back.
pub(crate) async fn append_commit_facts_pg(
    tx: &mut Transaction<'_, Postgres>,
    commit: &RequestCommitV1,
    tenant: TenantId,
) -> Result<(), StoreError> {
    tenant_scope(tenant)?;
    let (now, zdr, expiry) = locked_source(tx, tenant, commit.run).await?;
    // ZDR diagnostics remain in the explicitly volatile producer sink, never this result row.
    if zdr {
        return Ok(());
    }
    let attempt: i16 = sqlx::query_scalar(
        "SELECT attempts FROM url_frontier WHERE tenant_id=$1 AND run_id=$2 AND frontier_id=$3",
    )
    .bind(tenant.0)
    .bind(commit.run.0)
    .bind(commit.request_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    let attempt = u16::try_from(attempt).map_err(|_| conflict("invalid report attempt"))?;
    let facts = commit_checkpoints(commit, tenant, now, attempt.max(1))?;
    for fact in &facts {
        if fact.tenant != tenant
            || fact.run != commit.run
            || fact.request_id != Some(commit.request_id)
            || fact.attempt != attempt.max(1)
            || (matches!(fact.source, CustodySource::Url(_))
                && (fact.source != CustodySource::Url(commit.request_id) || fact.fence != commit.fence))
        {
            return Err(StoreError::LeaseLost);
        }
        if let CustodySource::Session(session) = fact.source {
            let Some((observation, _)) = &commit.observation else {
                return Err(StoreError::LeaseLost);
            };
            if observation.source != CustodySource::Session(session) || observation.fence != fact.fence {
                return Err(StoreError::LeaseLost);
            }
        } else if !matches!(fact.source, CustodySource::Url(_)) {
            return Err(StoreError::LeaseLost);
        }
        insert_fact(tx, fact, expiry, true).await?;
    }
    Ok(())
}

/// Lock the owning run before an outbox row, matching request commit lock order.
/// # Errors
/// Returns scope, missing-run or database errors without touching delivery state.
pub(crate) async fn lock_pipeline_ack_run(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(), StoreError> {
    tenant_scope(tenant)?;
    // PostgreSQL row locking belongs only to this backend adapter.
    sqlx::query("SELECT run_id FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2 FOR UPDATE")
        .bind(tenant.0)
        .bind(run.0)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .ok_or_else(|| StoreError::AccessDenied("delivery run unavailable".into()))?;
    Ok(())
}

/// Commit delivery checkpoints only after every actual source outbox has acknowledged.
///
/// The caller holds the existing outbox ACK transaction and fence. This function
/// does not require an expired acquisition lease or turn a partial ACK into success.
/// # Errors
/// Returns malformed source/progress, retention or database errors; caller rolls back.
pub(crate) async fn acknowledge_pipeline_pg(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
    delivery_id: i64,
) -> Result<(), StoreError> {
    tenant_scope(tenant)?;
    let source: Option<i64> = sqlx::query_scalar("SELECT source_request_id FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND state='delivered'")
        .bind(tenant.0).bind(run.0).bind(delivery_id).fetch_optional(&mut **tx).await.map_err(db)?.flatten();
    let Some(request) = source else {
        return Ok(());
    };
    let all_delivered: bool = sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND source_request_id=$3 AND state<>'delivered')")
        .bind(tenant.0).bind(run.0).bind(request).fetch_one(&mut **tx).await.map_err(db)?;
    if !all_delivered {
        return Ok(());
    }
    let (now, zdr, expiry) = match locked_source(tx, tenant, run).await {
        Ok(source) => source,
        Err(StoreError::RetentionDenied(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    if zdr {
        return Ok(());
    }
    let row=sqlx::query("SELECT progress,source_fact FROM request_pipeline_history WHERE tenant_id=$1 AND run_id=$2 AND request_id=$3 ORDER BY attempt DESC LIMIT 1")
        .bind(tenant.0).bind(run.0).bind(request).fetch_optional(&mut **tx).await.map_err(db)?;
    let Some(row) = row else {
        return Ok(());
    };
    let mut progress: PipelineProgressV1 = serde_json::from_value(get(&row, "progress")?)?;
    if progress.delivered()
        || progress.state(PipelineStageV1::Parse) != PipelineStateV1::Succeeded
        || matches!(progress.state(PipelineStageV1::Index), PipelineStateV1::Skipped)
        || matches!(
            progress.state(PipelineStageV1::Completion),
            PipelineStateV1::Skipped
        )
    {
        return Ok(());
    }
    let mut source: ReportFactV1 = serde_json::from_value(get(&row, "source_fact")?)?;
    if source.tenant != tenant || source.run != run || source.request_id != Some(request) {
        return Err(conflict("pipeline acknowledgement source mismatch"));
    }
    progress.acknowledge_delivery()?;
    sqlx::query("UPDATE request_pipeline_history SET progress=$1 WHERE tenant_id=$2 AND run_id=$3 AND request_id=$4 AND attempt=$5")
        .bind(serde_json::to_value(&progress)?).bind(tenant.0).bind(run.0).bind(request).bind(i32::from(source.attempt))
        .execute(&mut **tx).await.map_err(db)?;
    for stage in [PipelineStageV1::Index, PipelineStageV1::Completion] {
        if progress.state(stage) == PipelineStateV1::Succeeded {
            continue;
        }
        source.id = Digest::of(
            "crawlx/report-delivery-ack/v1",
            &serde_json::to_vec(&(tenant, run, request, source.fence, source.attempt, stage))?,
        );
        source.at = now;
        source.data = ReportDataV1::Pipeline {
            stage,
            state: PipelineStateV1::Succeeded,
        };
        insert_fact(tx, &source, expiry, true).await?;
    }
    Ok(())
}

impl Pg {
    /// Remove one bounded batch of expired report facts and pipeline checkpoints.
    ///
    /// Called by the existing retention sweeper; this creates no second timer.
    /// # Errors
    /// Returns tenant scope or database errors without partial batch publication.
    pub async fn purge_expired_report_history(&self) -> Result<u64, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let now: Timestamp = sqlx::query_scalar("SELECT CURRENT_TIMESTAMP")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let facts=sqlx::query("DELETE FROM report_history WHERE fact_sequence IN (SELECT fact_sequence FROM report_history WHERE expires_at<=$1 ORDER BY expires_at,fact_sequence LIMIT 512)")
            .bind(now).execute(&mut *tx).await.map_err(db)?.rows_affected();
        let progress=sqlx::query("DELETE FROM request_pipeline_history WHERE (tenant_id,run_id,request_id,attempt) IN (SELECT tenant_id,run_id,request_id,attempt FROM request_pipeline_history WHERE expires_at<=$1 ORDER BY expires_at,tenant_id,run_id,request_id,attempt LIMIT 512)")
            .bind(now).execute(&mut *tx).await.map_err(db)?.rows_affected();
        tx.commit().await.map_err(db)?;
        facts
            .checked_add(progress)
            .ok_or_else(|| conflict("report sweep count overflow"))
    }
}
