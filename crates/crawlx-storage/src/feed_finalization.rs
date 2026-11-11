//! Terminal feed publication shares the request transaction authority and existing outbox.

use super::*;
use crate::backend::strategy::Conn;
use crate::backend::{Dialect, RowLock};
use crate::dataset::{
    apply_prepared, apply_source, config_tx, prepare_memory, read_payload, verify_delivery,
};
use crate::repos::effects::settle_run;
use crate::sql::{db_clock, stmt, Sql, SqlRow};
use crate::store::Store;
use crawlx_core::dataset::{
    DeliveryBatchV1, DeliveryRangeV1, EmptyFeedPolicyV1, FeedBatchingV1, FeedFinalizationOutcomeV1,
};

fn invalid() -> StoreError {
    StoreError::Conflict("invalid terminal feed publication".into())
}

fn staged_scope(
    config: &crawlx_core::dataset::DatasetConfigV1,
    feed: &str,
    active: bool,
    expires_at: Option<crawlx_core::Timestamp>,
    now: crawlx_core::Timestamp,
) -> Result<(), StoreError> {
    crawlx_core::dataset::validate_identifier(feed)?;
    if !active
        || !config
            .feeds
            .iter()
            .any(|policy| policy.id == feed && policy.batching == FeedBatchingV1::Terminal)
    {
        return Err(invalid());
    }
    if expires_at.is_some_and(|deadline| deadline <= now) {
        return Err(StoreError::RetentionDenied("terminal feed source expired".into()));
    }
    Ok(())
}

fn check_batches(
    config: &crawlx_core::dataset::DatasetConfigV1,
    batches: &[DeliveryBatchV1],
    empty: bool,
) -> Result<(), StoreError> {
    if batches.len() > 64 {
        return Err(invalid());
    }
    let mut feeds = std::collections::BTreeSet::new();
    for batch in batches {
        let feed = config
            .feeds
            .iter()
            .find(|feed| feed.id == batch.feed)
            .ok_or_else(invalid)?;
        match batch.range {
            DeliveryRangeV1::Empty if empty && feed.empty_policy == EmptyFeedPolicyV1::Emit => {
                if batch.idempotency_key
                    != format!(
                        "terminal.empty.{}",
                        crawlx_core::dataset::feed_key_component(&feed.id)
                    )
                    || !feeds.insert(&feed.id)
                {
                    return Err(invalid());
                }
            }
            DeliveryRangeV1::Committed { first, last }
                if !empty && feed.batching == FeedBatchingV1::Terminal =>
            {
                if batch.idempotency_key
                    != format!(
                        "terminal.{}.{}.{}",
                        crawlx_core::dataset::feed_key_component(&feed.id),
                        first,
                        last
                    )
                {
                    return Err(invalid());
                }
            }
            _ => return Err(invalid()),
        }
    }
    Ok(())
}

/// Longest finalizer lease; holders renew well before it ends.
const MAX_FINALIZER_TTL: std::time::Duration = std::time::Duration::from_secs(300);

fn finalizer_ttl(ttl: std::time::Duration) -> Result<ChronoDuration, StoreError> {
    if ttl.is_zero() || ttl > MAX_FINALIZER_TTL {
        return Err(StoreError::Conflict(
            "invalid feed finalizer lease duration".into(),
        ));
    }
    ChronoDuration::from_std(ttl)
        .map_err(|_| StoreError::Conflict("invalid feed finalizer lease duration".into()))
}

fn finalizer_expiry(
    now: crawlx_core::Timestamp,
    ttl: ChronoDuration,
) -> Result<crawlx_core::Timestamp, StoreError> {
    now.checked_add_signed(ttl)
        .ok_or_else(|| StoreError::Conflict("feed finalizer lease overflow".into()))
}

fn next_fence(previous: i64) -> Result<i64, StoreError> {
    previous
        .checked_add(1)
        .ok_or_else(|| StoreError::Conflict("feed finalizer fence overflow".into()))
}

/// The finalizer claim a lease names, or `LeaseLost` when the lease is of another kind.
fn finalizer_of(lease: &crawlx_core::custody::CustodyLease) -> Result<uuid::Uuid, StoreError> {
    match lease.source {
        crawlx_core::custody::CustodySource::FeedFinalization(finalizer) => Ok(finalizer),
        _ => Err(StoreError::LeaseLost),
    }
}

fn finalizer_matches(
    claim: &crate::dataset::MemoryFinalizer,
    lease: &crawlx_core::custody::CustodyLease,
) -> bool {
    lease.source == crawlx_core::custody::CustodySource::FeedFinalization(claim.id)
        && lease.worker == claim.owner
        && lease.fence == claim.fence
}

impl MemoryStore {
    /// Whether a zero-retention run's feed finalization has lost its volatile operational
    /// value: the delivery buffer no longer holds the run's configuration page. The check
    /// awaits the buffer, so it runs before the state lock of the retirement is taken.
    pub(crate) async fn feed_volatile_missing(&self, id: CrawlRunId) -> Result<bool, StoreError> {
        let tenant = {
            let state = self.inner.lock();
            let run = state.runs.get(&id).ok_or_else(|| nf("crawl_run", id))?;
            if run.config.retention.mode != RetentionMode::Zdr
                || run.config.datasets.feeds.is_empty()
                || state.dataset.feed_finalized.contains_key(&id)
                || !(state.dataset.feed_finalizing.contains(&id)
                    || (run.status.is_terminal() && !run.config.datasets.feeds.is_empty()))
            {
                return Ok(false);
            }
            run.tenant
        };
        let buffer = self.dataset_delivery.lock().clone().ok_or_else(|| {
            StoreError::RetentionDenied("required volatile delivery backend unavailable".into())
        })?;
        Ok(buffer.get(tenant, id, i64::MIN).await?.is_none())
    }

    pub(crate) fn retire_expired_feed_finalization_owned(
        &self,
        id: CrawlRunId,
        volatile_missing: bool,
    ) -> Result<bool, StoreError> {
        let mut state = self.inner.lock();
        let run = state.runs.get(&id).ok_or_else(|| nf("crawl_run", id))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if state.dataset.feed_finalized.contains_key(&id)
            || !(state.dataset.feed_finalizing.contains(&id)
                || (run.status.is_terminal() && !run.config.datasets.feeds.is_empty()))
        {
            return Ok(false);
        }
        let now = self.clock.now();
        let run_expired = run.config.retention.mode != RetentionMode::Zdr
            && run.config.retention.days != 0
            && run
                .created_at
                .checked_add_signed(ChronoDuration::days(i64::from(run.config.retention.days)))
                .is_none_or(|deadline| deadline <= now);
        let source_expired = state.dataset.items.iter().any(|((owner, _), dataset)| {
            *owner == id
                && dataset.rows.values().any(|row| {
                    row.item.expires_at.is_some_and(|deadline| deadline <= now)
                        || row
                            .item
                            .feed_fragments
                            .iter()
                            .any(|fragment| fragment.expires_at <= now)
                })
        });
        if !run_expired && !source_expired && !volatile_missing {
            return Ok(false);
        }
        for row in state
            .dataset
            .deliveries
            .values_mut()
            .filter(|row| row.receipt.run == id)
        {
            if matches!(
                row.receipt.state,
                crawlx_core::dataset::DeliveryStateV1::Pending
                    | crawlx_core::dataset::DeliveryStateV1::Leased
            ) {
                row.receipt.state = crawlx_core::dataset::DeliveryStateV1::ContentExpired;
                row.lease_expires = None;
            }
        }
        let run = state.runs.get_mut(&id).ok_or_else(|| nf("crawl_run", id))?;
        if !run.status.is_terminal() {
            run.status = RunStatus::Failed;
            run.terminal_reason = Some(TerminalReason::FatalError);
            run.finished_at = Some(now);
        }
        for checkpoint in state
            .checkpoints
            .iter_mut()
            .filter(|checkpoint| checkpoint.run == id)
        {
            checkpoint.expires_at = checkpoint.expires_at.min(now);
        }
        state.dataset.feed_finalizing.remove(&id);
        state
            .dataset
            .feed_finalized
            .insert(id, FeedFinalizationOutcomeV1::ContentExpired);
        Ok(true)
    }

    pub(crate) async fn begin_feed_finalization_owned(
        &self,
        id: CrawlRunId,
        requested: Option<TerminalReason>,
    ) -> Result<Option<TerminalReason>, StoreError> {
        let mut state = self.inner.lock();
        let run = state.runs.get(&id).ok_or_else(|| nf("crawl_run", id))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if state.dataset.feed_finalized.contains_key(&id) {
            return Ok(None);
        }
        let terminal = run.status.is_terminal();
        if requested.is_none() && !terminal && !state.dataset.feed_finalizing.contains(&id) {
            return Ok(None);
        }
        let reason = if terminal {
            run.terminal_reason
        } else {
            state.dataset.feed_reasons.get(&id).copied().or(requested)
        };
        let Some(reason) = reason else {
            return Ok(None);
        };
        state.dataset.feed_finalizing.insert(id);
        state.dataset.feed_reasons.insert(id, reason);
        Ok(Some(reason))
    }

    pub(crate) fn claim_feed_finalizer_owned(
        &self,
        id: CrawlRunId,
        worker: crawlx_core::WorkerId,
        ttl: std::time::Duration,
    ) -> Result<crawlx_core::custody::CustodyLease, StoreError> {
        let ttl = finalizer_ttl(ttl)?;
        let now = self.clock.now();
        let mut state = self.inner.lock();
        let run = state.runs.get(&id).ok_or_else(|| nf("crawl_run", id))?;
        let tenant = run.tenant;
        if crate::tenant::current().is_some_and(|owner| owner != tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if state.dataset.feed_finalized.contains_key(&id) || !state.dataset.feed_finalizing.contains(&id) {
            return Err(StoreError::LeaseLost);
        }
        let previous = state.dataset.feed_finalizers.get(&id).copied();
        if previous.is_some_and(|claim| claim.expires_at > now) {
            return Err(StoreError::Conflict(
                "feed finalization is claimed by another worker".into(),
            ));
        }
        let claim = crate::dataset::MemoryFinalizer {
            id: uuid::Uuid::now_v7(),
            owner: worker,
            fence: next_fence(previous.map_or(0, |claim| claim.fence))?,
            expires_at: finalizer_expiry(now, ttl)?,
        };
        state.dataset.feed_finalizers.insert(id, claim);
        Ok(crawlx_core::custody::CustodyLease::for_feed_finalization(
            tenant,
            id,
            claim.id,
            worker,
            claim.fence,
        ))
    }

    pub(crate) fn renew_feed_finalizer_owned(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
        ttl: std::time::Duration,
    ) -> Result<(), StoreError> {
        let ttl = finalizer_ttl(ttl)?;
        if crate::tenant::current().is_some_and(|owner| owner != lease.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        let now = self.clock.now();
        let mut state = self.inner.lock();
        let dataset = &mut state.dataset;
        let active =
            dataset.feed_finalizing.contains(&lease.run) && !dataset.feed_finalized.contains_key(&lease.run);
        let claim = dataset
            .feed_finalizers
            .get_mut(&lease.run)
            .filter(|claim| active && finalizer_matches(claim, lease) && claim.expires_at > now)
            .ok_or(StoreError::LeaseLost)?;
        claim.expires_at = finalizer_expiry(now, ttl)?;
        Ok(())
    }

    pub(crate) fn release_feed_finalizer_owned(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
    ) -> Result<(), StoreError> {
        if crate::tenant::current().is_some_and(|owner| owner != lease.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        let now = self.clock.now();
        let mut state = self.inner.lock();
        if let Some(claim) = state
            .dataset
            .feed_finalizers
            .get_mut(&lease.run)
            .filter(|claim| finalizer_matches(claim, lease))
        {
            claim.expires_at = claim.expires_at.min(now);
        }
        Ok(())
    }

    pub(crate) async fn stage_feed_batches_owned(
        &self,
        id: CrawlRunId,
        batches: &[DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.validate_dataset_results(id, &[], &[], batches).await?;
        let mut state = self.inner.lock();
        let run = state.runs.get(&id).ok_or_else(|| nf("crawl_run", id))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if state.dataset.feed_finalized.contains_key(&id) {
            return Err(invalid());
        }
        check_batches(&run.config.datasets, batches, false)?;
        let patch = prepare_memory(&state.dataset, run, 0, &[], &[], batches, self.clock.now())?;
        apply_prepared(&mut state.dataset, patch);
        state.dataset.feed_finalizing.insert(id);
        Ok(())
    }

    fn staged_feed_batch_snapshot(
        &self,
        id: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<DeliveryBatchV1>, StoreError> {
        let state = self.inner.lock();
        let run = state.runs.get(&id).ok_or_else(|| nf("crawl_run", id))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        let now = self.clock.now();
        staged_scope(
            &run.config.datasets,
            feed,
            state.dataset.feed_finalizing.contains(&id) && !state.dataset.feed_finalized.contains_key(&id),
            crate::codec::expiry(run.created_at, u32::from(run.config.retention.days)),
            now,
        )?;
        let Some(row) = state.dataset.delivery(id, feed, idempotency_key)? else {
            return Ok(None);
        };
        if row.erased || row.receipt.state == crawlx_core::dataset::DeliveryStateV1::ContentExpired {
            return Err(StoreError::RetentionDenied(
                "terminal feed manifest expired".into(),
            ));
        }
        if !row.terminal_source {
            return Err(invalid());
        }
        let batches = std::slice::from_ref(&row.receipt.batch);
        check_batches(&run.config.datasets, batches, false)?;
        prepare_memory(&state.dataset, run, 0, &[], &[], batches, now)?;
        Ok(Some(row.receipt.batch.clone()))
    }

    pub(crate) async fn staged_feed_batch_owned(
        &self,
        id: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<DeliveryBatchV1>, StoreError> {
        crawlx_core::dataset::validate_identifier(idempotency_key)?;
        let Some(batch) = self.staged_feed_batch_snapshot(id, feed, idempotency_key)? else {
            return Ok(None);
        };
        self.validate_dataset_results(id, &[], &[], std::slice::from_ref(&batch))
            .await?;
        // Content verification awaits outside the mutex. Recheck source custody and
        // finalization authority before returning the immutable manifest.
        let current = self
            .staged_feed_batch_snapshot(id, feed, idempotency_key)?
            .ok_or_else(invalid)?;
        if current != batch {
            return Err(invalid());
        }
        Ok(Some(current))
    }

    pub(crate) async fn finalize_run_feeds_owned(
        &self,
        id: CrawlRunId,
        status: RunStatus,
        reason: TerminalReason,
        batches: &[DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        if !status.is_terminal() {
            return Err(invalid());
        }
        self.validate_dataset_results(id, &[], &[], batches).await?;
        let now = self.clock.now();
        let mut state = self.inner.lock();
        let run = state.runs.get(&id).ok_or_else(|| nf("crawl_run", id))?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if run.status.is_terminal() && (run.status != status || run.terminal_reason != Some(reason)) {
            return Err(invalid());
        }
        if state.dataset.feed_finalized.contains_key(&id) {
            return Ok(());
        }
        check_batches(&run.config.datasets, batches, true)?;
        for feed in run
            .config
            .datasets
            .feeds
            .iter()
            .filter(|feed| feed.empty_policy == EmptyFeedPolicyV1::Emit)
        {
            if !batches.iter().any(|batch| batch.feed == feed.id)
                && !state
                    .dataset
                    .deliveries
                    .values()
                    .any(|row| row.receipt.run == id && row.receipt.batch.feed == feed.id)
            {
                return Err(invalid());
            }
        }
        let eligible: Vec<_> = batches
            .iter()
            .filter(|batch| {
                !state
                    .dataset
                    .deliveries
                    .values()
                    .any(|row| row.receipt.run == id && row.receipt.batch.feed == batch.feed)
            })
            .cloned()
            .collect();
        let patch = prepare_memory(&state.dataset, run, 0, &[], &[], &eligible, now)?;
        apply_prepared(&mut state.dataset, patch);
        let run = state.runs.get_mut(&id).ok_or_else(|| nf("crawl_run", id))?;
        run.status = status;
        run.terminal_reason = Some(reason);
        run.finished_at.get_or_insert(now);
        for checkpoint in state
            .checkpoints
            .iter_mut()
            .filter(|checkpoint| checkpoint.run == id)
        {
            checkpoint.expires_at = checkpoint.expires_at.min(now);
        }
        state.dataset.feed_finalizing.remove(&id);
        state
            .dataset
            .feed_finalized
            .insert(id, FeedFinalizationOutcomeV1::Completed);
        Ok(())
    }
}

/// Database time in the caller's transaction.
fn sql_now<B: Sql>() -> &'static str {
    <B::Dialect as Dialect>::now()
}

/// The locking clause that holds a run row until the transaction ends.
fn lock_row<B: Sql>() -> &'static str {
    <B::Dialect as Dialect>::row_lock(RowLock::Update)
}

impl<B: Sql> Store<B> {
    pub(crate) async fn retire_expired_feed_finalization_owned(
        &self,
        id: CrawlRunId,
        tenant: TenantId,
        zdr: bool,
    ) -> Result<bool, StoreError> {
        let mut tx = self.begin_write().await?;
        let row = stmt!(
            B,
            format!(
                "SELECT feed_finalized,feed_finalizing,feed_required,status::text AS status,(expires_at IS NOT NULL AND expires_at<={now}) AS run_expired,EXISTS(SELECT 1 FROM dataset_items i WHERE i.run_id=$1 AND i.expires_at<={now}) AS source_expired FROM crawl_runs WHERE run_id=$1 AND tenant_id=$2{lock}",
                now = sql_now::<B>(),
                lock = lock_row::<B>()
            )
        )
        .uuid(id.0)
        .uuid(tenant.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or_else(|| crate::error::not_found("crawl_run", id))?;
        let terminal = matches!(row.text("status")?.as_str(), "completed" | "failed" | "cancelled");
        if row.bool("feed_finalized")?
            || !(row.bool("feed_finalizing")? || (terminal && row.bool("feed_required")?))
        {
            return Ok(false);
        }
        let mut expired = row.flag("source_expired")? || (!zdr && row.flag("run_expired")?);
        if zdr && !expired {
            let buffer = self.delivery.as_ref().ok_or_else(|| {
                StoreError::RetentionDenied("required volatile delivery backend unavailable".into())
            })?;
            // DeliveryBuffer refuses expired pages before loading their bytes. No missing
            // operational policy is reconstructed from durable redacted configuration.
            expired = buffer.get(tenant, id, i64::MIN).await?.is_none();
        }
        if !expired {
            return Ok(false);
        }
        stmt!(
            B,
            "UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND state IN ('pending','leased')"
        )
        .uuid(tenant.0)
        .uuid(id.0)
        .execute(tx.conn())
        .await?;
        stmt!(
            B,
            format!(
                "UPDATE crawl_runs SET terminal_reason=CASE WHEN status IN ('completed','failed','cancelled') THEN terminal_reason ELSE 'fatal_error'::terminal_reason END,status=CASE WHEN status IN ('completed','failed','cancelled') THEN status ELSE 'failed'::run_status END,finished_at=COALESCE(finished_at,{}),feed_finalizing=false,feed_finalized=true,feed_finalization_outcome='content_expired' WHERE run_id=$1 AND tenant_id=$2",
                sql_now::<B>()
            )
        )
        .uuid(id.0)
        .uuid(tenant.0)
        .execute(tx.conn())
        .await?;
        settle_run::<B>(tx.conn(), id).await?;
        tx.commit().await?;
        Ok(true)
    }

    pub(crate) async fn begin_feed_finalization_owned(
        &self,
        id: CrawlRunId,
        requested: Option<TerminalReason>,
    ) -> Result<Option<TerminalReason>, StoreError> {
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let row = stmt!(
            B,
            format!(
                "SELECT tenant_id,status::text AS status,terminal_reason::text AS reason,feed_finalizing,feed_finalized,feed_terminal_reason::text AS feed_reason FROM crawl_runs WHERE run_id=$1{}",
                lock_row::<B>()
            )
        )
        .uuid(id.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or_else(|| crate::error::not_found("crawl_run", id))?;
        let tenant = TenantId(row.uuid("tenant_id")?);
        if crate::tenant::current().is_some_and(|owner| owner != tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if row.bool("feed_finalized")? {
            return Ok(None);
        }
        let terminal = matches!(row.text("status")?.as_str(), "completed" | "failed" | "cancelled");
        if requested.is_none() && !terminal && !row.bool("feed_finalizing")? {
            return Ok(None);
        }
        let stored: Option<String> = if terminal {
            row.opt_text("reason")?
        } else {
            row.opt_text("feed_reason")?
        };
        let reason = match stored {
            Some(value) => Some(serde_json::from_value::<TerminalReason>(
                serde_json::Value::String(value),
            )?),
            None => requested,
        };
        let Some(reason) = reason else {
            return Ok(None);
        };
        stmt!(
            B,
            "UPDATE crawl_runs SET feed_finalizing=true,feed_terminal_reason=$2::text::terminal_reason WHERE run_id=$1"
        )
        .uuid(id.0)
        .text(reason.as_str())
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
        Ok(Some(reason))
    }

    pub(crate) async fn claim_feed_finalizer_owned(
        &self,
        id: CrawlRunId,
        worker: crawlx_core::WorkerId,
        ttl: std::time::Duration,
    ) -> Result<crawlx_core::custody::CustodyLease, StoreError> {
        let ttl = finalizer_ttl(ttl)?;
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let now = db_clock::<B>(tx.conn()).await?;
        let row = stmt!(
            B,
            format!(
                "SELECT tenant_id,feed_finalizing,feed_finalized,feed_finalizer_fence,feed_finalizer_expires_at FROM crawl_runs WHERE run_id=$1{}",
                lock_row::<B>()
            )
        )
        .uuid(id.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or_else(|| crate::error::not_found("crawl_run", id))?;
        let tenant = TenantId(row.uuid("tenant_id")?);
        if crate::tenant::current().is_some_and(|owner| owner != tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if row.bool("feed_finalized")? || !row.bool("feed_finalizing")? {
            return Err(StoreError::LeaseLost);
        }
        if row
            .opt_ts("feed_finalizer_expires_at")?
            .is_some_and(|expires_at| expires_at > now)
        {
            return Err(StoreError::Conflict(
                "feed finalization is claimed by another worker".into(),
            ));
        }
        let finalizer = uuid::Uuid::now_v7();
        let fence = next_fence(row.i64("feed_finalizer_fence")?)?;
        stmt!(
            B,
            "UPDATE crawl_runs SET feed_finalizer_id=$2,feed_finalizer_owner=$3,feed_finalizer_fence=$4,feed_finalizer_expires_at=$5 WHERE run_id=$1"
        )
        .uuid(id.0)
        .uuid(finalizer)
        .uuid(worker.0)
        .i64(fence)
        .ts(finalizer_expiry(now, ttl)?)
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
        Ok(crawlx_core::custody::CustodyLease::for_feed_finalization(
            tenant, id, finalizer, worker, fence,
        ))
    }

    pub(crate) async fn renew_feed_finalizer_owned(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
        ttl: std::time::Duration,
    ) -> Result<(), StoreError> {
        let ttl = finalizer_ttl(ttl)?;
        let finalizer = finalizer_of(lease)?;
        if crate::tenant::current().is_some_and(|owner| owner != lease.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        let mut tx = self.begin_write().await?;
        let now = db_clock::<B>(tx.conn()).await?;
        let renewed = stmt!(
            B,
            "UPDATE crawl_runs SET feed_finalizer_expires_at=$6 WHERE run_id=$1 AND tenant_id=$2 AND feed_finalizer_id=$3 AND feed_finalizer_owner=$4 AND feed_finalizer_fence=$5 AND feed_finalizing AND NOT feed_finalized AND feed_finalizer_expires_at>$7"
        )
        .uuid(lease.run.0)
        .uuid(lease.tenant.0)
        .uuid(finalizer)
        .uuid(lease.worker.0)
        .i64(lease.fence)
        .ts(finalizer_expiry(now, ttl)?)
        .ts(now)
        .execute(tx.conn())
        .await?;
        if renewed == 0 {
            return Err(StoreError::LeaseLost);
        }
        tx.commit().await
    }

    pub(crate) async fn release_feed_finalizer_owned(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
    ) -> Result<(), StoreError> {
        let finalizer = finalizer_of(lease)?;
        if crate::tenant::current().is_some_and(|owner| owner != lease.tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        let mut tx = self.begin_write().await?;
        let now = db_clock::<B>(tx.conn()).await?;
        stmt!(
            B,
            "UPDATE crawl_runs SET feed_finalizer_expires_at=$6 WHERE run_id=$1 AND tenant_id=$2 AND feed_finalizer_id=$3 AND feed_finalizer_owner=$4 AND feed_finalizer_fence=$5 AND feed_finalizer_expires_at>$6"
        )
        .uuid(lease.run.0)
        .uuid(lease.tenant.0)
        .uuid(finalizer)
        .uuid(lease.worker.0)
        .i64(lease.fence)
        .ts(now)
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }

    async fn feed_run_locked(
        &self,
        conn: &mut Conn<B>,
        id: CrawlRunId,
    ) -> Result<(TenantId, crawlx_core::config::CreateCrawl, String, Option<String>), StoreError> {
        let (tenant, config, _) = config_tx(self, conn, id).await?;
        let row = stmt!(
            B,
            "SELECT status::text AS status,terminal_reason::text AS reason FROM crawl_runs WHERE run_id=$1"
        )
        .uuid(id.0)
        .fetch_one(conn)
        .await?;
        Ok((tenant, config, row.text("status")?, row.opt_text("reason")?))
    }

    async fn feed_finalized(&self, conn: &mut Conn<B>, id: CrawlRunId) -> Result<bool, StoreError> {
        stmt!(
            B,
            "SELECT feed_finalized AS finalized FROM crawl_runs WHERE run_id=$1"
        )
        .uuid(id.0)
        .fetch_one(conn)
        .await?
        .bool("finalized")
    }

    pub(crate) async fn stage_feed_batches_owned(
        &self,
        id: CrawlRunId,
        batches: &[DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin_write().await?;
        let (_, config, _, _) = self.feed_run_locked(tx.conn(), id).await?;
        if self.feed_finalized(tx.conn(), id).await? {
            return Err(invalid());
        }
        check_batches(&config.datasets, batches, false)?;
        stmt!(B, "UPDATE crawl_runs SET feed_finalizing=true WHERE run_id=$1")
            .uuid(id.0)
            .execute(tx.conn())
            .await?;
        apply_source::<B>(self, tx.conn(), id, 0, None, &[], &[], batches).await?;
        tx.commit().await
    }

    pub(crate) async fn staged_feed_batch_owned(
        &self,
        id: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<DeliveryBatchV1>, StoreError> {
        crawlx_core::dataset::validate_identifier(idempotency_key)?;
        let mut tx = self.begin_write().await?;
        let (tenant, config, now) = config_tx(self, tx.conn(), id).await?;
        let authority = stmt!(
            B,
            "SELECT feed_finalizing AND NOT feed_finalized AS active, expires_at FROM crawl_runs WHERE run_id=$1"
        )
        .uuid(id.0)
        .fetch_one(tx.conn())
        .await?;
        staged_scope(
            &config.datasets,
            feed,
            authority.flag("active")?,
            authority.opt_ts("expires_at")?,
            now,
        )?;
        let row = stmt!(
            B,
            "SELECT payload,volatile_page,terminal_source,state,expires_at FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND feed=$3 AND idempotency_key=$4"
        )
        .uuid(tenant.0)
        .uuid(id.0)
        .text(feed)
        .text(idempotency_key)
        .fetch_optional(tx.conn())
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        if row.text("state")? == "content_expired" || row.ts("expires_at")? <= now {
            return Err(StoreError::RetentionDenied(
                "terminal feed manifest expired".into(),
            ));
        }
        if !row.bool("terminal_source")? {
            return Err(invalid());
        }
        let batch: DeliveryBatchV1 = read_payload(self, tenant, id, &row, "dataset_delivery").await?;
        if batch.feed != feed || batch.idempotency_key != idempotency_key {
            return Err(invalid());
        }
        check_batches(&config.datasets, std::slice::from_ref(&batch), false)?;
        verify_delivery(self, tx.conn(), tenant, id, &config, &batch, now).await?;
        tx.commit().await?;
        Ok(Some(batch))
    }

    pub(crate) async fn finalize_run_feeds_owned(
        &self,
        id: CrawlRunId,
        status: RunStatus,
        reason: TerminalReason,
        batches: &[DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        if !status.is_terminal() {
            return Err(invalid());
        }
        let mut tx = self.begin_write().await?;
        let (tenant, config, current, current_reason) = self.feed_run_locked(tx.conn(), id).await?;
        if matches!(current.as_str(), "completed" | "failed" | "cancelled")
            && (current != status.as_str() || current_reason.as_deref() != Some(reason.as_str()))
        {
            return Err(invalid());
        }
        if self.feed_finalized(tx.conn(), id).await? {
            return Ok(());
        }
        check_batches(&config.datasets, batches, true)?;
        let mut eligible = Vec::with_capacity(batches.len());
        for batch in batches {
            if !self.feed_present(tx.conn(), tenant, id, &batch.feed).await? {
                eligible.push(batch.clone());
            }
        }
        for feed in config
            .datasets
            .feeds
            .iter()
            .filter(|feed| feed.empty_policy == EmptyFeedPolicyV1::Emit)
        {
            if batches.iter().any(|batch| batch.feed == feed.id) {
                continue;
            }
            if !self.feed_present(tx.conn(), tenant, id, &feed.id).await? {
                return Err(invalid());
            }
        }
        apply_source::<B>(self, tx.conn(), id, 0, None, &[], &[], &eligible).await?;
        stmt!(
            B,
            format!(
                "UPDATE crawl_runs SET status=$2::text::run_status,terminal_reason=$3::text::terminal_reason,finished_at=COALESCE(finished_at,{}),feed_finalizing=false,feed_finalized=true,feed_finalization_outcome='completed' WHERE run_id=$1",
                sql_now::<B>()
            )
        )
        .uuid(id.0)
        .text(status.as_str())
        .text(reason.as_str())
        .execute(tx.conn())
        .await?;
        settle_run::<B>(tx.conn(), id).await?;
        tx.commit().await
    }

    /// Whether the run has an outbox row for `feed`.
    async fn feed_present(
        &self,
        conn: &mut Conn<B>,
        tenant: TenantId,
        id: CrawlRunId,
        feed: &str,
    ) -> Result<bool, StoreError> {
        stmt!(
            B,
            "SELECT EXISTS(SELECT 1 FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND feed=$3) AS present"
        )
        .uuid(tenant.0)
        .uuid(id.0)
        .text(feed)
        .fetch_one(conn)
        .await?
        .flag("present")
    }
}
