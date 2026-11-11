//! Memory source memo authority under the existing store mutex; no global cache or files.
use super::*;
use crate::dataset::memo::{capacity, category_valid, horizon, lookup};
use crawlx_core::dataset::memo::*;

fn owner(g: &Inner, tenant: TenantId, run: CrawlRunId) -> Result<&CrawlRun, StoreError> {
    if g.pending_purges.contains_key(&run) {
        return Err(StoreError::RetentionDenied("source memo run is purging".into()));
    }
    let row = g.runs.get(&run).ok_or_else(|| nf("crawl_run", run))?;
    visible(row)?;
    if row.tenant != tenant {
        return Err(StoreError::AccessDenied("source memo tenant mismatch".into()));
    }
    Ok(row)
}

#[async_trait]
impl SourceMemoRepo for MemoryStore {
    async fn seen(&self, scope: &MemoScopeV1, article: Digest, now: Timestamp) -> Result<bool, StoreError> {
        let key = lookup(scope, article, false)?;
        let g = self.inner.lock();
        let row = owner(&g, scope.tenant, scope.run)?;
        if horizon(row, now).is_err() {
            return Ok(false);
        }
        Ok(g.dataset
            .memo
            .get(&scope.run)
            .is_some_and(|state| state.seen.contains_key(&key)))
    }
    async fn record_seen(
        &self,
        scope: &MemoScopeV1,
        articles: &[Digest],
        max_entries: u32,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let maximum = capacity(articles, max_entries)?;
        let keys = articles
            .iter()
            .map(|key| lookup(scope, *key, false))
            .collect::<Result<Vec<_>, _>>()?;
        let mut g = self.inner.lock();
        let row = owner(&g, scope.tenant, scope.run)?;
        horizon(row, now)?;
        g.dataset
            .memo
            .entry(scope.run)
            .or_default()
            .record(&keys, maximum, now);
        Ok(())
    }
    async fn category(
        &self,
        scope: &MemoScopeV1,
        representation: Digest,
        now: Timestamp,
    ) -> Result<Option<CategoryCacheEntryV1>, StoreError> {
        let key = lookup(scope, representation, true)?;
        let g = self.inner.lock();
        let row = owner(&g, scope.tenant, scope.run)?;
        let Ok(end) = horizon(row, now) else {
            return Ok(None);
        };
        Ok(g.dataset
            .memo
            .get(&scope.run)
            .and_then(|state| state.categories.get(&key))
            .filter(|entry| entry.expires_at > now && entry.expires_at <= end)
            .cloned())
    }
    async fn cache_category(
        &self,
        scope: &MemoScopeV1,
        representation: Digest,
        entry: CategoryCacheEntryV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let key = lookup(scope, representation, true)?;
        {
            let g = self.inner.lock();
            let row = owner(&g, scope.tenant, scope.run)?;
            category_valid(
                &entry,
                row.config.retention.mode == RetentionMode::Zdr,
                horizon(row, now)?,
                now,
            )?;
        }
        live_content(
            self,
            scope.tenant,
            scope.run,
            &entry.content,
            entry.size_bytes,
            Some(entry.expires_at),
        )
        .await?;
        let mut g = self.inner.lock();
        let row = owner(&g, scope.tenant, scope.run)?;
        horizon(row, now)?;
        g.dataset
            .memo
            .entry(scope.run)
            .or_default()
            .cache(key, entry, now);
        Ok(())
    }
    async fn reset(&self, tenant: TenantId, run: CrawlRunId) -> Result<(), StoreError> {
        let mut g = self.inner.lock();
        owner(&g, tenant, run)?;
        g.dataset.memo.remove(&run);
        Ok(())
    }
}
