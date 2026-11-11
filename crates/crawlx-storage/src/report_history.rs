//! Tenant-scoped measured history under the existing producer and retention authorities.
//!
//! Retained facts contain only finite typed metadata. ZDR payloads use the existing
//! volatile delivery buffer; their durable rows carry only opaque receipts and bounds.
//! Keyset filters run before the finite page limit. No whole-run aggregate is implied.

use crate::backend::strategy::Conn;
use crate::backend::{Dialect, RowLock};
use crate::sql::{db_clock, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::custody::{CustodyLease, CustodySource};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::RequestCommitV1;
use crawlx_core::report_history::{
    PipelineProgressV1, PipelineStageV1, PipelineStateV1, ProcessorStageV1, ReportDataV1, ReportEntryV1,
    ReportFactV1, ReportHistoryRepo, ReportKindV1, ReportPageV1, ReportQueryV1,
};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};
use uuid::Uuid;

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

// The row lock and the authoritative database clock come from the engine's dialect.
async fn locked_source<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(Timestamp, bool, Option<Timestamp>), StoreError> {
    let row = stmt!(
        B,
        format!(
            "SELECT created_at,retention_days,retention_mode='zdr' AS zdr,expires_at,purge_requested_at FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2{}",
            <B::Dialect as Dialect>::row_lock(RowLock::Update)
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| StoreError::AccessDenied("report run unavailable".into()))?;
    let now = db_clock::<B>(conn).await?;
    if row.opt_ts("purge_requested_at")?.is_some() {
        return Err(StoreError::RetentionDenied("report source being purged".into()));
    }
    let zdr = row.flag("zdr")?;
    let expiry = source_deadline(
        row.ts("created_at")?,
        row.i32("retention_days")?,
        row.opt_ts("expires_at")?,
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

async fn pipeline_fact<B: Sql>(
    conn: &mut Conn<B>,
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
    let attempt = i32::from(fact.attempt);
    let prior = stmt!(
        B,
        "SELECT progress,expires_at FROM request_pipeline_history WHERE tenant_id=$1 AND run_id=$2 AND request_id=$3 AND attempt=$4"
    )
    .uuid(fact.tenant.0)
    .uuid(fact.run.0)
    .i64(request)
    .i32(attempt)
    .fetch_optional(conn)
    .await?;
    // The run row is locked by this transaction, so the read-modify-write below cannot race.
    let (mut progress, stored): (PipelineProgressV1, Option<Option<Timestamp>>) = match prior {
        Some(row) => (
            serde_json::from_value(row.json("progress")?)?,
            Some(row.opt_ts("expires_at")?),
        ),
        None => (PipelineProgressV1::default(), None),
    };
    progress.apply(&fact.data)?;
    let progress = serde_json::to_value(progress)?;
    let source_fact = serde_json::to_value(fact)?;
    // An existing checkpoint keeps the earlier of the two deadlines; no deadline never
    // shortens one that exists.
    let merged = match stored {
        None | Some(None) => expiry,
        Some(Some(old)) => Some(expiry.map_or(old, |new| old.min(new))),
    };
    if stored.is_some() {
        stmt!(
            B,
            "UPDATE request_pipeline_history SET progress=$5,source_fact=$6,expires_at=$7 WHERE tenant_id=$1 AND run_id=$2 AND request_id=$3 AND attempt=$4"
        )
        .uuid(fact.tenant.0)
        .uuid(fact.run.0)
        .i64(request)
        .i32(attempt)
        .json(&progress)
        .json(&source_fact)
        .opt_ts(merged)
        .execute(conn)
        .await?;
    } else {
        stmt!(
            B,
            "INSERT INTO request_pipeline_history(tenant_id,run_id,request_id,attempt,progress,source_fact,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)"
        )
        .uuid(fact.tenant.0)
        .uuid(fact.run.0)
        .i64(request)
        .i32(attempt)
        .json(&progress)
        .json(&source_fact)
        .opt_ts(merged)
        .execute(conn)
        .await?;
    }
    Ok(())
}

async fn insert_fact<B: Sql>(
    conn: &mut Conn<B>,
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
    let prior = stmt!(
        B,
        "SELECT fact_sequence,receipt FROM report_history WHERE tenant_id=$1 AND run_id=$2 AND fact_id=$3"
    )
    .uuid(fact.tenant.0)
    .uuid(fact.run.0)
    .bytes(fact.id.0.as_slice())
    .fetch_optional(conn)
    .await?;
    if let Some(prior) = prior {
        if prior.bytes("receipt")? != receipt.0 {
            return Err(conflict("report fact identity reused with different evidence"));
        }
        return Ok((prior.i64("fact_sequence")?, false));
    }
    let count = stmt!(
        B,
        "SELECT count(*) AS n FROM report_history WHERE tenant_id=$1 AND run_id=$2"
    )
    .uuid(fact.tenant.0)
    .uuid(fact.run.0)
    .fetch_one(conn)
    .await?
    .i64("n")?;
    if count >= MAX_FACTS_PER_RUN {
        return Err(conflict("report history run capacity exhausted"));
    }
    if durable {
        pipeline_fact::<B>(conn, fact, expiry).await?;
    }
    let payload = durable.then(|| serde_json::to_value(fact)).transpose()?;
    let duration = fact
        .data
        .duration_us()
        .map(i64::try_from)
        .transpose()
        .map_err(|_| conflict("report duration overflow"))?;
    let wire = fact
        .data
        .wire_bytes()
        .map(i64::try_from)
        .transpose()
        .map_err(|_| conflict("report wire size overflow"))?;
    let sequence = stmt!(
        B,
        "INSERT INTO report_history(tenant_id,run_id,fact_id,receipt,kind,observed_at,url_key,host_key,duration_us,wire_bytes,fact,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING fact_sequence"
    )
    .uuid(fact.tenant.0)
    .uuid(fact.run.0)
    .bytes(fact.id.0.as_slice())
    .bytes(receipt.0.as_slice())
    .text(kind_label(fact.data.kind())?)
    .ts(fact.at)
    .opt_bytes(fact.url_key.as_ref().map(|key| key.0.as_slice()))
    .opt_bytes(fact.host_key.as_ref().map(|key| key.0.as_slice()))
    .opt_i64(duration)
    .opt_i64(wire)
    .opt_json(payload.as_ref())
    .opt_ts(expiry)
    .fetch_one(conn)
    .await?
    .i64("fact_sequence")?;
    Ok((sequence, true))
}

#[async_trait]
impl<B: Sql> ReportHistoryRepo for Store<B> {
    async fn append_fact(&self, lease: &CustodyLease, fact: &ReportFactV1) -> Result<u64, StoreError> {
        tenant_scope(lease.tenant)?;
        self.scope()?.authorize(lease.tenant)?;
        fact.validate()?;
        fact.validate_lease(lease)?;
        let mut tx = self.begin_write().await?;
        let (_, zdr, expiry) = locked_source::<B>(tx.conn(), lease.tenant, lease.run).await?;
        crate::custody::live::<B>(tx.conn(), lease).await?;
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
            let attempts = stmt!(
                B,
                "SELECT attempts FROM url_frontier WHERE tenant_id=$1 AND run_id=$2 AND frontier_id=$3"
            )
            .uuid(lease.tenant.0)
            .uuid(lease.run.0)
            .i64(request)
            .fetch_optional(tx.conn())
            .await?
            .map(|row| row.i16("attempts"))
            .transpose()?;
            if attempts
                .and_then(|value| u16::try_from(value).ok())
                .map(|value| value.max(1))
                != Some(fact.attempt)
            {
                return Err(StoreError::LeaseLost);
            }
        }
        let (sequence, _) = insert_fact::<B>(tx.conn(), fact, expiry, !zdr).await?;
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
        crate::custody::live::<B>(tx.conn(), lease).await?;
        tx.commit().await?;
        u64::try_from(sequence).map_err(|_| conflict("report sequence overflow"))
    }

    async fn query_facts(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        query: &ReportQueryV1,
    ) -> Result<ReportPageV1, StoreError> {
        self.query_report_facts(tenant, run, query).await
    }
}

/// One optional filter value of the report query, bound in the order its predicate appears.
enum Filter {
    Uuid(Uuid),
    Bytes([u8; 32]),
    Text(&'static str),
    Ts(Timestamp),
    I64(i64),
}

impl<B: Sql> Store<B> {
    /// Keyset page of retained facts. Only the filters that are present enter the statement,
    /// so no engine has to resolve the type of an untyped null parameter.
    async fn query_report_facts(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        query: &ReportQueryV1,
    ) -> Result<ReportPageV1, StoreError> {
        tenant_scope(tenant)?;
        self.scope()?.authorize(tenant)?;
        query.validate()?;
        let mut tx = self.begin_write().await?;
        if let Some(run) = run {
            let (_, zdr, _) = locked_source::<B>(tx.conn(), tenant, run).await?;
            if zdr {
                return Err(StoreError::RetentionDenied(
                    "volatile report history withheld".into(),
                ));
            }
        }
        let now = db_clock::<B>(tx.conn()).await?;
        let after = i64::try_from(query.after).map_err(|_| conflict("report cursor overflow"))?;
        let mut sql = String::from(
            "SELECT h.fact_sequence,h.fact FROM report_history h JOIN crawl_runs r ON r.tenant_id=h.tenant_id AND r.run_id=h.run_id WHERE h.tenant_id=$1 AND h.fact_sequence>$2 AND h.fact IS NOT NULL AND (h.expires_at IS NULL OR h.expires_at>$3) AND r.retention_mode<>'zdr' AND r.purge_requested_at IS NULL AND (r.expires_at IS NULL OR r.expires_at>$3)",
        );
        let mut filters = Vec::new();
        let mut push = |predicate: &str, filter: Filter| {
            filters.push(filter);
            let n = filters.len() + 3;
            sql.push_str(" AND ");
            sql.push_str(&predicate.replace("$n", &format!("${n}")));
        };
        if let Some(run) = run {
            push("h.run_id=$n", Filter::Uuid(run.0));
        }
        if let Some(kind) = query.kind {
            push("h.kind=$n", Filter::Text(kind_label(kind)?));
        }
        if let Some(key) = query.url_key {
            push("h.url_key=$n", Filter::Bytes(key.0));
        }
        if let Some(key) = query.host_key {
            push("h.host_key=$n", Filter::Bytes(key.0));
        }
        if let Some(since) = query.since {
            push("h.observed_at>=$n", Filter::Ts(since));
        }
        if let Some(until) = query.until {
            push("h.observed_at<=$n", Filter::Ts(until));
        }
        for (predicate, value) in [
            ("h.duration_us>=$n", query.min_duration_us),
            ("h.duration_us<=$n", query.max_duration_us),
        ] {
            if let Some(value) = value {
                let value = i64::try_from(value).map_err(|_| conflict("report duration overflow"))?;
                push(predicate, Filter::I64(value));
            }
        }
        for (predicate, value) in [
            ("h.wire_bytes>=$n", query.min_wire_bytes),
            ("h.wire_bytes<=$n", query.max_wire_bytes),
        ] {
            if let Some(value) = value {
                let value = i64::try_from(value).map_err(|_| conflict("report wire size overflow"))?;
                push(predicate, Filter::I64(value));
            }
        }
        let limit_param = filters.len() + 4;
        sql.push_str(&format!(" ORDER BY h.fact_sequence LIMIT ${limit_param}"));
        let mut statement = Stmt::<B>::dynamic(&sql).uuid(tenant.0).i64(after).ts(now);
        for filter in &filters {
            statement = match filter {
                Filter::Uuid(value) => statement.uuid(*value),
                Filter::Bytes(value) => statement.bytes(value.as_slice()),
                Filter::Text(value) => statement.text(value),
                Filter::Ts(value) => statement.ts(*value),
                Filter::I64(value) => statement.i64(*value),
            };
        }
        let rows = statement
            .i64(i64::from(query.limit) + 1)
            .fetch_all(tx.conn())
            .await?;
        let limit = usize::try_from(query.limit).map_err(|_| conflict("report limit overflow"))?;
        let more = rows.len() > limit;
        let mut entries = Vec::with_capacity(rows.len().min(limit));
        for row in rows.into_iter().take(limit) {
            let sequence =
                u64::try_from(row.i64("fact_sequence")?).map_err(|_| conflict("report sequence overflow"))?;
            let fact: ReportFactV1 = serde_json::from_value(row.json("fact")?)?;
            fact.validate()?;
            if fact.tenant != tenant || run.is_some_and(|run| fact.run != run) || !query.matches(&fact) {
                return Err(conflict("report row scope or projection mismatch"));
            }
            entries.push(ReportEntryV1::new(sequence, fact));
        }
        let next = more.then(|| entries.last().map(|entry| entry.sequence)).flatten();
        tx.commit().await?;
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
    // Checkpoints synthesized here describe the same attempt as the facts the worker
    // recorded, so they join the requested host and URL those facts carry.
    let host_key = commit.report_facts.iter().find_map(|fact| fact.host_key);
    let url_key = commit.report_facts.iter().find_map(|fact| fact.url_key);
    for fact in &mut facts {
        if matches!(fact.data, ReportDataV1::Pipeline { .. }) {
            fact.host_key = fact.host_key.or(host_key);
            fact.url_key = fact.url_key.or(url_key);
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
pub(crate) async fn append_commit_facts<B: Sql>(
    conn: &mut Conn<B>,
    commit: &RequestCommitV1,
    tenant: TenantId,
) -> Result<(), StoreError> {
    tenant_scope(tenant)?;
    let (now, zdr, expiry) = locked_source::<B>(conn, tenant, commit.run).await?;
    // ZDR diagnostics remain in the explicitly volatile producer sink, never this result row.
    if zdr {
        return Ok(());
    }
    let attempt = stmt!(
        B,
        "SELECT attempts FROM url_frontier WHERE tenant_id=$1 AND run_id=$2 AND frontier_id=$3"
    )
    .uuid(tenant.0)
    .uuid(commit.run.0)
    .i64(commit.request_id)
    .fetch_one(conn)
    .await?
    .i16("attempts")?;
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
        insert_fact::<B>(conn, fact, expiry, true).await?;
    }
    Ok(())
}

/// Lock the owning run before an outbox row, matching request commit lock order.
/// # Errors
/// Returns scope, missing-run or database errors without touching delivery state.
pub(crate) async fn lock_pipeline_ack_run<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(), StoreError> {
    tenant_scope(tenant)?;
    stmt!(
        B,
        format!(
            "SELECT run_id FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2{}",
            <B::Dialect as Dialect>::row_lock(RowLock::Update)
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| StoreError::AccessDenied("delivery run unavailable".into()))?;
    Ok(())
}

/// Commit delivery checkpoints only after every actual source outbox has acknowledged.
///
/// The caller holds the existing outbox ACK transaction and fence. This function
/// does not require an expired acquisition lease or turn a partial ACK into success.
/// # Errors
/// Returns malformed source/progress, retention or database errors; caller rolls back.
pub(crate) async fn acknowledge_pipeline<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
    delivery_id: i64,
) -> Result<(), StoreError> {
    tenant_scope(tenant)?;
    let source = stmt!(
        B,
        "SELECT source_request_id FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND state='delivered'"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .i64(delivery_id)
    .fetch_optional(conn)
    .await?
    .map(|row| row.opt_i64("source_request_id"))
    .transpose()?
    .flatten();
    let Some(request) = source else {
        return Ok(());
    };
    let all_delivered = stmt!(
        B,
        "SELECT NOT EXISTS(SELECT 1 FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND source_request_id=$3 AND state<>'delivered') AS all_delivered"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .i64(request)
    .fetch_one(conn)
    .await?
    .flag("all_delivered")?;
    if !all_delivered {
        return Ok(());
    }
    let (now, zdr, expiry) = match locked_source::<B>(conn, tenant, run).await {
        Ok(source) => source,
        Err(StoreError::RetentionDenied(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    if zdr {
        return Ok(());
    }
    let row = stmt!(
        B,
        "SELECT progress,source_fact FROM request_pipeline_history WHERE tenant_id=$1 AND run_id=$2 AND request_id=$3 ORDER BY attempt DESC LIMIT 1"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .i64(request)
    .fetch_optional(conn)
    .await?;
    let Some(row) = row else {
        return Ok(());
    };
    let mut progress: PipelineProgressV1 = serde_json::from_value(row.json("progress")?)?;
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
    let mut source: ReportFactV1 = serde_json::from_value(row.json("source_fact")?)?;
    if source.tenant != tenant || source.run != run || source.request_id != Some(request) {
        return Err(conflict("pipeline acknowledgement source mismatch"));
    }
    progress.acknowledge_delivery()?;
    let stored = serde_json::to_value(&progress)?;
    stmt!(
        B,
        "UPDATE request_pipeline_history SET progress=$1 WHERE tenant_id=$2 AND run_id=$3 AND request_id=$4 AND attempt=$5"
    )
    .json(&stored)
    .uuid(tenant.0)
    .uuid(run.0)
    .i64(request)
    .i32(i32::from(source.attempt))
    .execute(conn)
    .await?;
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
        insert_fact::<B>(conn, &source, expiry, true).await?;
    }
    Ok(())
}

/// Placeholders `$first, $first+1, ..` for `count` bound values.
fn placeholders(first: usize, count: usize) -> String {
    (first..first + count)
        .map(|n| format!("${n}"))
        .collect::<Vec<_>>()
        .join(",")
}

impl<B: Sql> Store<B> {
    /// Remove one bounded batch of expired report facts and pipeline checkpoints.
    ///
    /// Called by the existing retention sweeper; this creates no second timer.
    /// # Errors
    /// Returns tenant scope or database errors without partial batch publication.
    pub async fn purge_expired_report_history(&self) -> Result<u64, StoreError> {
        self.require_operator()?;
        let mut tx = self.begin_write().await?;
        let now = db_clock::<B>(tx.conn()).await?;
        // MariaDB rejects LIMIT inside an IN subquery: pick the keys first, delete by key.
        let sequences = stmt!(
            B,
            "SELECT fact_sequence FROM report_history WHERE expires_at<=$1 ORDER BY expires_at,fact_sequence LIMIT 512"
        )
        .ts(now)
        .fetch_all(tx.conn())
        .await?
        .iter()
        .map(|row| row.i64("fact_sequence"))
        .collect::<Result<Vec<_>, _>>()?;
        let mut facts = 0_u64;
        if !sequences.is_empty() {
            let sql = format!(
                "DELETE FROM report_history WHERE fact_sequence IN ({})",
                placeholders(1, sequences.len())
            );
            let mut delete = Stmt::<B>::dynamic(&sql);
            for sequence in &sequences {
                delete = delete.i64(*sequence);
            }
            facts = delete.execute(tx.conn()).await?;
        }
        let keys = stmt!(
            B,
            "SELECT tenant_id,run_id,request_id,attempt FROM request_pipeline_history WHERE expires_at<=$1 ORDER BY expires_at,tenant_id,run_id,request_id,attempt LIMIT 512"
        )
        .ts(now)
        .fetch_all(tx.conn())
        .await?
        .iter()
        .map(|row| {
            Ok((
                row.uuid("tenant_id")?,
                row.uuid("run_id")?,
                row.i64("request_id")?,
                row.i32("attempt")?,
            ))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
        let mut progress = 0_u64;
        if !keys.is_empty() {
            let rows = (0..keys.len())
                .map(|row| format!("({})", placeholders(row * 4 + 1, 4)))
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "DELETE FROM request_pipeline_history WHERE (tenant_id,run_id,request_id,attempt) IN ({rows})"
            );
            let mut delete = Stmt::<B>::dynamic(&sql);
            for (tenant, run, request, attempt) in &keys {
                delete = delete.uuid(*tenant).uuid(*run).i64(*request).i32(*attempt);
            }
            progress = delete.execute(tx.conn()).await?;
        }
        tx.commit().await?;
        facts
            .checked_add(progress)
            .ok_or_else(|| conflict("report sweep count overflow"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crawlx_core::repo::FrontierStatus;
    use crawlx_core::WorkerId;

    #[test]
    fn synthesized_checkpoints_join_the_host_and_url_of_the_recorded_facts() {
        let tenant = TenantId::new();
        let run = CrawlRunId::new();
        let at = Timestamp::from_timestamp(1_800_000_000, 0).unwrap();
        let lease = CustodyLease::for_url(tenant, run, 7, WorkerId::new(), 3);
        let host = Digest::of("crawlx/test/host", b"example.test");
        let url = Digest::of("crawlx/test/url", b"/page");
        let mut wire = ReportFactV1::new(
            &lease,
            Digest::of("crawlx/test/fact", b"1"),
            at,
            ReportDataV1::Wire {
                received_bytes: Some(1),
                sent_bytes: None,
                duration_us: Some(1),
            },
        );
        wire.request_id = Some(7);
        wire.attempt = 1;
        wire.host_key = Some(host);
        wire.url_key = Some(url);
        let mut commit = RequestCommitV1::terminal(run, 7, 3, 1, FrontierStatus::Succeeded, None);
        commit.report_facts.push(wire);
        let facts = commit_checkpoints(&commit, tenant, at, 1).unwrap();
        let pipeline: Vec<_> = facts
            .iter()
            .filter(|fact| matches!(fact.data, ReportDataV1::Pipeline { .. }))
            .collect();
        assert_eq!(pipeline.len(), 3, "fetch, index and completion checkpoints");
        assert!(pipeline
            .iter()
            .all(|fact| fact.host_key == Some(host) && fact.url_key == Some(url)));
    }

    #[test]
    fn checkpoints_stay_unkeyed_when_no_recorded_fact_names_a_host() {
        let tenant = TenantId::new();
        let run = CrawlRunId::new();
        let at = Timestamp::from_timestamp(1_800_000_000, 0).unwrap();
        let commit = RequestCommitV1::terminal(run, 7, 3, 1, FrontierStatus::Failed, None);
        let facts = commit_checkpoints(&commit, tenant, at, 1).unwrap();
        assert!(!facts.is_empty());
        assert!(facts
            .iter()
            .all(|fact| fact.host_key.is_none() && fact.url_key.is_none()));
    }
}
