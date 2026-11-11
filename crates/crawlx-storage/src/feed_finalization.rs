//! Terminal feed publication shares the request transaction authority and existing outbox.

use super::*;
use crate::dataset::{apply_pg_source, apply_prepared, prepare_memory, read_payload, verify_pg_delivery};
use crate::{codec::get, error::db, Pg};
use crawlx_core::dataset::{
    DeliveryBatchV1, DeliveryRangeV1, EmptyFeedPolicyV1, FeedBatchingV1, FeedFinalizationOutcomeV1,
};
use sqlx::Postgres;

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

impl MemoryStore {
    pub(crate) fn retire_expired_feed_finalization_owned(&self, id: CrawlRunId) -> Result<bool, StoreError> {
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
        if !run_expired && !source_expired {
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

impl Pg {
    pub(crate) async fn retire_expired_feed_finalization_owned(
        &self,
        id: CrawlRunId,
        tenant: TenantId,
        zdr: bool,
    ) -> Result<bool, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row = sqlx::query("SELECT feed_finalized,feed_finalizing,feed_required,status::text AS status,(expires_at IS NOT NULL AND expires_at<=now()) AS run_expired,EXISTS(SELECT 1 FROM dataset_items i WHERE i.run_id=$1 AND i.expires_at<=now()) AS source_expired FROM crawl_runs WHERE run_id=$1 AND tenant_id=$2 FOR UPDATE")
            .bind(id.0).bind(tenant.0).fetch_optional(&mut *tx).await.map_err(db)?.ok_or_else(|| crate::error::not_found("crawl_run",id))?;
        let terminal = matches!(
            get::<String>(&row, "status")?.as_str(),
            "completed" | "failed" | "cancelled"
        );
        if get::<bool>(&row, "feed_finalized")?
            || !(get::<bool>(&row, "feed_finalizing")? || (terminal && get::<bool>(&row, "feed_required")?))
        {
            return Ok(false);
        }
        let mut expired = get::<bool>(&row, "source_expired")? || (!zdr && get::<bool>(&row, "run_expired")?);
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
        sqlx::query("UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND state IN ('pending','leased')")
            .bind(tenant.0).bind(id.0).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("UPDATE crawl_runs SET terminal_reason=CASE WHEN status IN ('completed','failed','cancelled') THEN terminal_reason ELSE 'fatal_error'::terminal_reason END,status=CASE WHEN status IN ('completed','failed','cancelled') THEN status ELSE 'failed'::run_status END,finished_at=COALESCE(finished_at,now()),feed_finalizing=false,feed_finalized=true,feed_finalization_outcome='content_expired' WHERE run_id=$1 AND tenant_id=$2")
            .bind(id.0).bind(tenant.0).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(true)
    }

    pub(crate) async fn begin_feed_finalization_owned(
        &self,
        id: CrawlRunId,
        requested: Option<TerminalReason>,
    ) -> Result<Option<TerminalReason>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let row = sqlx::query("SELECT tenant_id,status::text AS status,terminal_reason::text AS reason,feed_finalizing,feed_finalized,feed_terminal_reason::text AS feed_reason FROM crawl_runs WHERE run_id=$1 FOR UPDATE")
            .bind(id.0).fetch_optional(&mut *tx).await.map_err(db)?.ok_or_else(|| crate::error::not_found("crawl_run", id))?;
        let tenant = TenantId(get(&row, "tenant_id")?);
        if crate::tenant::current().is_some_and(|owner| owner != tenant) {
            return Err(StoreError::AccessDenied("feed tenant mismatch".into()));
        }
        if get::<bool>(&row, "feed_finalized")? {
            return Ok(None);
        }
        let terminal = matches!(
            get::<String>(&row, "status")?.as_str(),
            "completed" | "failed" | "cancelled"
        );
        if requested.is_none() && !terminal && !get::<bool>(&row, "feed_finalizing")? {
            return Ok(None);
        }
        let stored: Option<String> = if terminal {
            get(&row, "reason")?
        } else {
            get(&row, "feed_reason")?
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
        sqlx::query("UPDATE crawl_runs SET feed_finalizing=true,feed_terminal_reason=$2::text::terminal_reason WHERE run_id=$1")
            .bind(id.0).bind(reason.as_str()).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(Some(reason))
    }

    async fn feed_run_locked(
        &self,
        tx: &mut sqlx::Transaction<'_, Postgres>,
        id: CrawlRunId,
    ) -> Result<(TenantId, crawlx_core::config::CreateCrawl, String, Option<String>), StoreError> {
        let (tenant, config, _) = crate::dataset::config_tx(self, tx, id).await?;
        let row = sqlx::query(
            "SELECT status::text AS status,terminal_reason::text AS reason FROM crawl_runs WHERE run_id=$1",
        )
        .bind(id.0)
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
        Ok((tenant, config, get(&row, "status")?, get(&row, "reason")?))
    }

    pub(crate) async fn stage_feed_batches_owned(
        &self,
        id: CrawlRunId,
        batches: &[DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (_, config, _, _) = self.feed_run_locked(&mut tx, id).await?;
        let finalized: bool = sqlx::query_scalar("SELECT feed_finalized FROM crawl_runs WHERE run_id=$1")
            .bind(id.0)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if finalized {
            return Err(invalid());
        }
        check_batches(&config.datasets, batches, false)?;
        sqlx::query("UPDATE crawl_runs SET feed_finalizing=true WHERE run_id=$1")
            .bind(id.0)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        apply_pg_source(self, &mut tx, id, 0, None, &[], &[], batches).await?;
        tx.commit().await.map_err(db)
    }

    pub(crate) async fn staged_feed_batch_owned(
        &self,
        id: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<DeliveryBatchV1>, StoreError> {
        crawlx_core::dataset::validate_identifier(idempotency_key)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, config, now) = crate::dataset::config_tx(self, &mut tx, id).await?;
        let authority = sqlx::query("SELECT feed_finalizing AND NOT feed_finalized AS active, expires_at FROM crawl_runs WHERE run_id=$1")
            .bind(id.0).fetch_one(&mut *tx).await.map_err(db)?;
        staged_scope(
            &config.datasets,
            feed,
            get(&authority, "active")?,
            get(&authority, "expires_at")?,
            now,
        )?;
        let row = sqlx::query("SELECT payload,volatile_page,terminal_source,state,expires_at FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND feed=$3 AND idempotency_key=$4")
            .bind(tenant.0).bind(id.0).bind(feed).bind(idempotency_key)
            .fetch_optional(&mut *tx).await.map_err(db)?;
        let Some(row) = row else {
            tx.commit().await.map_err(db)?;
            return Ok(None);
        };
        if get::<String>(&row, "state")? == "content_expired"
            || get::<crawlx_core::Timestamp>(&row, "expires_at")? <= now
        {
            return Err(StoreError::RetentionDenied(
                "terminal feed manifest expired".into(),
            ));
        }
        if !get::<bool>(&row, "terminal_source")? {
            return Err(invalid());
        }
        let batch: DeliveryBatchV1 = read_payload(self, tenant, id, &row, "dataset_delivery").await?;
        if batch.feed != feed || batch.idempotency_key != idempotency_key {
            return Err(invalid());
        }
        check_batches(&config.datasets, std::slice::from_ref(&batch), false)?;
        verify_pg_delivery(self, &mut tx, tenant, id, &config, &batch, now).await?;
        tx.commit().await.map_err(db)?;
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
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, config, current, current_reason) = self.feed_run_locked(&mut tx, id).await?;
        if matches!(current.as_str(), "completed" | "failed" | "cancelled")
            && (current != status.as_str() || current_reason.as_deref() != Some(reason.as_str()))
        {
            return Err(invalid());
        }
        let finalized: bool = sqlx::query_scalar("SELECT feed_finalized FROM crawl_runs WHERE run_id=$1")
            .bind(id.0)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if finalized {
            return Ok(());
        }
        check_batches(&config.datasets, batches, true)?;
        let mut eligible = Vec::with_capacity(batches.len());
        for batch in batches {
            let row = sqlx::query("SELECT EXISTS(SELECT 1 FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND feed=$3) AS present")
                .bind(tenant.0).bind(id.0).bind(&batch.feed).fetch_one(&mut *tx).await.map_err(db)?;
            if !get::<bool>(&row, "present")? {
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
            let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND feed=$3)")
                .bind(tenant.0).bind(id.0).bind(&feed.id).fetch_one(&mut *tx).await.map_err(db)?;
            if !present {
                return Err(invalid());
            }
        }
        apply_pg_source(self, &mut tx, id, 0, None, &[], &[], &eligible).await?;
        sqlx::query("UPDATE crawl_runs SET status=$2::text::run_status,terminal_reason=$3::text::terminal_reason,finished_at=COALESCE(finished_at,now()),feed_finalizing=false,feed_finalized=true,feed_finalization_outcome='completed' WHERE run_id=$1")
            .bind(id.0).bind(status.as_str()).bind(reason.as_str()).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)
    }
}
