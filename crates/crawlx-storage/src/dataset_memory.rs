//! MemoryStore dataset and delivery implementations under its existing transaction mutex.

use super::*;
use crate::dataset::{apply_prepared, bounds, prepare_memory};
use crawlx_core::dataset::*;
use crawlx_core::repo::Sensitivity;

fn unavailable() -> StoreError {
    StoreError::RetentionDenied("dataset content_expired".into())
}
fn visible(run: &CrawlRun) -> Result<(), StoreError> {
    if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
        return Err(StoreError::AccessDenied("dataset tenant mismatch".into()));
    }
    Ok(())
}

#[async_trait]
impl DatasetRepo for MemoryStore {
    async fn items(
        &self,
        run: CrawlRunId,
        dataset: &str,
        after: u64,
        limit: u16,
    ) -> Result<Vec<DatasetItemV1>, StoreError> {
        bounds(limit)?;
        validate_identifier(dataset)?;
        let (tenant, output) = {
            let g = self.inner.lock();
            let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
            visible(owner)?;
            if !owner
                .config
                .datasets
                .stores
                .iter()
                .any(|store| store.name == dataset)
            {
                return Err(StoreError::Conflict("undeclared dataset namespace".into()));
            }
            let now = self.clock.now();
            let mut output = Vec::with_capacity(usize::from(limit));
            if let Some(rows) = g.dataset.items.get(&(run, dataset.to_owned())) {
                for (_, row) in rows
                    .rows
                    .range((std::ops::Bound::Excluded(after), std::ops::Bound::Unbounded))
                    .take(usize::from(limit))
                {
                    if row.item.expires_at.is_some_and(|end| end <= now) {
                        return Err(unavailable());
                    }
                    output.push(row.clone());
                }
            }
            (owner.tenant, output)
        };
        for row in &output {
            live_content(
                self,
                tenant,
                run,
                &row.item.content,
                row.item.size_bytes,
                row.item.expires_at,
            )
            .await?;
        }
        Ok(output)
    }
}

#[async_trait]
impl KvRepo for MemoryStore {
    async fn value(&self, run: CrawlRunId, store: &str, key: &str) -> Result<Option<KvValueV1>, StoreError> {
        validate_identifier(store)?;
        validate_identifier(key)?;
        let (tenant, value) = {
            let g = self.inner.lock();
            let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
            visible(owner)?;
            if !owner
                .config
                .datasets
                .kv_stores
                .iter()
                .any(|declaration| declaration.name == store)
            {
                return Err(StoreError::Conflict("undeclared kv namespace".into()));
            }
            if g.dataset.dropped_kv.contains(&(run, store.to_owned())) {
                return Err(StoreError::Conflict("kv namespace dropped".into()));
            }
            let value = g.dataset.kv.get(&(run, store.to_owned(), key.to_owned()));
            if value.is_some_and(|value| value.value.expires_at.is_some_and(|end| end <= self.clock.now())) {
                return Err(unavailable());
            }
            (owner.tenant, value.cloned())
        };
        if let Some(row) = &value {
            if let Some(content) = &row.value.content {
                live_content(
                    self,
                    tenant,
                    run,
                    content,
                    row.value.size_bytes,
                    row.value.expires_at,
                )
                .await?;
            }
        }
        Ok(value)
    }
    async fn compare_and_set(&self, run: CrawlRunId, delta: KvCasV1) -> Result<KvValueV1, StoreError> {
        self.validate_dataset_results(run, &[], std::slice::from_ref(&delta), &[])
            .await?;
        let mut g = self.inner.lock();
        let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
        visible(owner)?;
        let staged = prepare_memory(
            &g.dataset,
            owner,
            0,
            &[],
            std::slice::from_ref(&delta),
            &[],
            self.clock.now(),
        )?;
        apply_prepared(&mut g.dataset, staged);
        let value = g
            .dataset
            .kv
            .get(&(run, delta.store, delta.key))
            .cloned()
            .ok_or_else(|| StoreError::Backend("kv mutation did not produce a version".into()))?;
        Ok(value)
    }
    async fn keys(
        &self,
        run: CrawlRunId,
        store: &str,
        after: &str,
        limit: u16,
    ) -> Result<Vec<KvValueV1>, StoreError> {
        bounds(limit)?;
        validate_identifier(store)?;
        if !after.is_empty() {
            validate_identifier(after)?;
        }
        let (tenant, values) = {
            let g = self.inner.lock();
            let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
            visible(owner)?;
            if !owner
                .config
                .datasets
                .kv_stores
                .iter()
                .any(|declaration| declaration.name == store)
            {
                return Err(StoreError::Conflict("undeclared kv namespace".into()));
            }
            if g.dataset.dropped_kv.contains(&(run, store.to_owned())) {
                return Err(StoreError::Conflict("kv namespace dropped".into()));
            }
            let now = self.clock.now();
            let values: Vec<_> = g
                .dataset
                .kv
                .range((run, store.to_owned(), after.to_owned())..)
                .take_while(|(key, _)| key.0 == run && key.1 == store)
                .filter(|(key, row)| {
                    key.2.as_str() > after && row.value.expires_at.is_none_or(|end| end > now)
                })
                .take(usize::from(limit))
                .map(|(_, row)| row.clone())
                .collect();
            (owner.tenant, values)
        };
        for row in &values {
            if let Some(content) = &row.value.content {
                live_content(
                    self,
                    tenant,
                    run,
                    content,
                    row.value.size_bytes,
                    row.value.expires_at,
                )
                .await?;
            }
        }
        Ok(values)
    }
    async fn drop_store(&self, run: CrawlRunId, store: &str) -> Result<(), StoreError> {
        validate_identifier(store)?;
        let mut g = self.inner.lock();
        let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
        visible(owner)?;
        if !owner
            .config
            .datasets
            .kv_stores
            .iter()
            .any(|declaration| declaration.name == store)
        {
            return Err(StoreError::Conflict("undeclared kv namespace".into()));
        }
        g.dataset.drop_kv(run, store);
        Ok(())
    }
}

#[async_trait]
impl DeliveryOutboxRepo for MemoryStore {
    async fn ready_runs(&self, after: Option<CrawlRunId>, limit: u16) -> Result<Vec<CrawlRunId>, StoreError> {
        bounds(limit)?;
        let g = self.inner.lock();
        let now = self.clock.now();
        let mut runs = std::collections::BTreeSet::new();
        for row in g.dataset.deliveries.values() {
            if (matches!(
                row.receipt.state,
                DeliveryStateV1::Pending | DeliveryStateV1::Leased
            ) && (row.receipt.batch.expires_at <= now
                || (row.not_before <= now && row.lease_expires.is_none_or(|end| end <= now))))
                || (matches!(
                    row.receipt.state,
                    DeliveryStateV1::Delivered | DeliveryStateV1::ContentExpired
                ) && !row.erased)
            {
                let run = g
                    .runs
                    .get(&row.receipt.run)
                    .ok_or_else(|| nf("crawl_run", row.receipt.run))?;
                if visible(run).is_ok() && after.is_none_or(|after| row.receipt.run > after) {
                    runs.insert(row.receipt.run);
                }
            }
        }
        Ok(runs.into_iter().take(usize::from(limit)).collect())
    }
    async fn maintain(&self, run: CrawlRunId) -> Result<(), StoreError> {
        let (tenant, pages) = {
            let mut g = self.inner.lock();
            let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
            visible(owner)?;
            let tenant = owner.tenant;
            let now = self.clock.now();
            for row in g
                .dataset
                .deliveries
                .values_mut()
                .filter(|row| row.receipt.run == run)
            {
                if row.receipt.batch.expires_at <= now
                    && matches!(
                        row.receipt.state,
                        DeliveryStateV1::Pending | DeliveryStateV1::Leased
                    )
                {
                    row.receipt.state = DeliveryStateV1::ContentExpired;
                    row.lease_expires = None;
                }
            }
            let mut pages = Vec::new();
            for (id, row) in &g.dataset.deliveries {
                if row.receipt.run != run
                    || row.erased
                    || !matches!(
                        row.receipt.state,
                        DeliveryStateV1::Delivered | DeliveryStateV1::ContentExpired
                    )
                {
                    continue;
                }
                let page = match row.receipt.batch.content {
                    DatasetContentV1::Volatile { page, .. } => Some(page),
                    _ => None,
                };
                let pending=page.is_some_and(|page|g.dataset.deliveries.values().any(|other|other.receipt.run==run
                    && matches!(other.receipt.state,DeliveryStateV1::Pending|DeliveryStateV1::Leased)
                    && matches!(other.receipt.batch.content,DatasetContentV1::Volatile {page:other,..} if other==page)));
                if !pending {
                    pages.push((*id, page));
                }
                if pages.len() == 1000 {
                    break;
                }
            }
            (tenant, pages)
        };
        for (id, page) in pages {
            if let Some(page) = page {
                let buffer = self.dataset_delivery.lock().clone().ok_or_else(unavailable)?;
                buffer.ack(tenant, run, page).await?;
            }
            if let Some(row) = self.inner.lock().dataset.deliveries.get_mut(&id) {
                row.erased = true;
            }
        }
        Ok(())
    }
    async fn expire(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        {
            let mut g = self.inner.lock();
            visible(g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?)?;
            let row = g
                .dataset
                .deliveries
                .get_mut(&id)
                .filter(|row| {
                    row.receipt.run == run
                        && row.receipt.fence == fence
                        && row.receipt.batch.expires_at <= self.clock.now()
                        && matches!(
                            row.receipt.state,
                            DeliveryStateV1::Pending
                                | DeliveryStateV1::Leased
                                | DeliveryStateV1::ContentExpired
                        )
                })
                .ok_or(StoreError::LeaseLost)?;
            row.receipt.state = DeliveryStateV1::ContentExpired;
            row.lease_expires = None;
        }
        self.maintain(run).await
    }
    async fn claim(
        &self,
        run: CrawlRunId,
        _worker: WorkerId,
        limit: u16,
        lease_seconds: u16,
    ) -> Result<Vec<DurableDeliveryOutboxV1>, StoreError> {
        bounds(limit)?;
        if lease_seconds == 0 || lease_seconds > 300 {
            return Err(StoreError::Conflict("invalid delivery lease duration".into()));
        }
        self.maintain(run).await?;
        let mut g = self.inner.lock();
        visible(g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?)?;
        let now = self.clock.now();
        let expires = now
            .checked_add_signed(ChronoDuration::seconds(i64::from(lease_seconds)))
            .ok_or_else(|| StoreError::Conflict("delivery lease expiry overflow".into()))?;
        let mut claims = Vec::with_capacity(usize::from(limit));
        for row in g
            .dataset
            .deliveries
            .values_mut()
            .filter(|row| row.receipt.run == run)
        {
            if matches!(
                row.receipt.state,
                DeliveryStateV1::Delivered | DeliveryStateV1::ContentExpired
            ) {
                continue;
            }
            if row.receipt.batch.expires_at <= now {
                row.receipt.state = DeliveryStateV1::ContentExpired;
                row.lease_expires = None;
                continue;
            }
            if claims.len() == usize::from(limit) {
                break;
            }
            if row.not_before > now || row.lease_expires.is_some_and(|end| end > now) {
                continue;
            }
            row.receipt.fence = row
                .receipt
                .fence
                .checked_add(1)
                .ok_or_else(|| StoreError::Backend("delivery fence overflow".into()))?;
            row.receipt.attempts = row
                .receipt
                .attempts
                .checked_add(1)
                .ok_or_else(|| StoreError::Backend("delivery attempt overflow".into()))?;
            row.receipt.state = DeliveryStateV1::Leased;
            row.lease_expires = Some(expires);
            claims.push(row.receipt.clone());
        }
        Ok(claims)
    }
    async fn acknowledge(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        {
            let mut g = self.inner.lock();
            visible(g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?)?;
            let now = self.clock.now();
            let row = g
                .dataset
                .deliveries
                .get_mut(&id)
                .filter(|row| {
                    row.receipt.run == run
                        && row.receipt.fence == fence
                        && (row.receipt.state == DeliveryStateV1::Delivered
                            || (row.receipt.state == DeliveryStateV1::Leased
                                && row.lease_expires.is_some_and(|end| end > now)
                                && row.receipt.batch.expires_at > now))
                })
                .ok_or(StoreError::LeaseLost)?;
            row.receipt.state = DeliveryStateV1::Delivered;
            row.lease_expires = None;
        }
        self.maintain(run).await
    }
    async fn retry(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        not_before: Timestamp,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        visible(g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?)?;
        let now = self.clock.now();
        let latest = now
            .checked_add_signed(ChronoDuration::days(1))
            .ok_or_else(|| StoreError::Conflict("delivery retry timestamp overflow".into()))?;
        let row = g
            .dataset
            .deliveries
            .get_mut(&id)
            .filter(|row| {
                row.receipt.run == run
                    && row.receipt.fence == fence
                    && row.receipt.state == DeliveryStateV1::Leased
                    && row.lease_expires.is_some_and(|end| end > now)
                    && row.receipt.batch.expires_at > now
                    && not_before >= now
                    && not_before <= row.receipt.batch.expires_at
                    && not_before <= latest
            })
            .ok_or(StoreError::LeaseLost)?;
        row.receipt.state = DeliveryStateV1::Pending;
        row.lease_expires = None;
        row.not_before = not_before;
        Ok(())
    }
}

async fn live_content(
    store: &MemoryStore,
    tenant: TenantId,
    run: CrawlRunId,
    content: &DatasetContentV1,
    size: u64,
    expiry: Option<Timestamp>,
) -> Result<(), StoreError> {
    match content {
        DatasetContentV1::Volatile {
            page,
            artifact,
            expires_at,
        } => {
            let buffer = store.dataset_delivery.lock().clone().ok_or_else(unavailable)?;
            let (deadline, actual) = buffer
                .content_metadata(tenant, run, *page, artifact)
                .await?
                .ok_or_else(unavailable)?;
            if deadline != *expires_at
                || actual != size
                || deadline <= store.clock.now()
                || expiry.is_none_or(|expiry| expiry > deadline || expiry <= store.clock.now())
            {
                return Err(unavailable());
            }
        }
        DatasetContentV1::Durable { artifact } => {
            let state = store.archives.lock();
            let row = state.artifact_row(&artifact.id).ok_or_else(unavailable)?;
            if row.tenant != tenant
                || row.run != run
                || row.digest != artifact.digest
                || row.size_bytes != size
                || !matches!(row.sensitivity, Sensitivity::Content | Sensitivity::Metadata)
                || row.expires_at.is_some_and(|deadline| {
                    deadline <= store.clock.now() || expiry.is_none_or(|expiry| expiry > deadline)
                })
            {
                return Err(unavailable());
            }
        }
        _ => return Err(unavailable()),
    }
    Ok(())
}

impl MemoryStore {
    pub(crate) async fn validate_dataset_results(
        &self,
        run: CrawlRunId,
        accepted: &[AcceptedBatchV1],
        deltas: &[KvCasV1],
        outbox: &[DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        if accepted.is_empty() && deltas.is_empty() && outbox.is_empty() {
            return Ok(());
        }
        if accepted.len() > 64
            || deltas.len() > 64
            || outbox.len() > 64
            || accepted
                .iter()
                .try_fold(0usize, |sum, batch| sum.checked_add(batch.items.len()))
                .is_none_or(|sum| sum > MAX_BATCH_ITEMS)
        {
            return Err(StoreError::Conflict("dataset transaction exceeds bounds".into()));
        }
        let tenant = {
            let g = self.inner.lock();
            let owner = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
            visible(owner)?;
            owner.tenant
        };
        for batch in accepted {
            for item in &batch.items {
                live_content(self, tenant, run, &item.content, item.size_bytes, item.expires_at).await?;
            }
        }
        for delta in deltas {
            if let Some(content) = &delta.content {
                live_content(self, tenant, run, content, delta.size_bytes, delta.expires_at).await?;
            }
        }
        for batch in outbox {
            live_content(
                self,
                tenant,
                run,
                &batch.content,
                batch.size_bytes,
                Some(batch.expires_at),
            )
            .await?;
        }
        Ok(())
    }
    pub(crate) async fn validate_action_dataset_results(
        &self,
        id: ActionId,
        accepted: &[AcceptedBatchV1],
        deltas: &[KvCasV1],
        outbox: &[DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        if accepted.is_empty() && deltas.is_empty() && outbox.is_empty() {
            return Ok(());
        }
        let run = {
            let g = self.inner.lock();
            g.actions.get(&id).ok_or_else(|| nf("action", id))?.rec.run
        };
        self.validate_dataset_results(run, accepted, deltas, outbox).await
    }
}
