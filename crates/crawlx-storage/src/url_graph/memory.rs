//! URL graph implementation inside MemoryStore, sharing its run and producer authority.

use super::*;
use crate::url_graph::{invalid, retained_deadline, MemoryGraph};
use crawlx_core::custody::CustodyLease;
use crawlx_core::url_graph::{
    UrlGraphBatchV1, UrlGraphPolicyV1, UrlGraphRankStateV1, UrlGraphRanksV1, UrlGraphRepo, UrlGraphSnapshotV1,
};

fn retained(g: &Inner, tenant: TenantId, run: CrawlRunId, now: Timestamp) -> Result<Timestamp, StoreError> {
    let record = g.runs.get(&run).ok_or_else(|| nf("url_graph", run))?;
    if record.tenant != tenant
        || crate::tenant::current().is_some_and(|current| current != tenant)
        || g.pending_purges.contains_key(&run)
        || record.terminal_reason == Some(TerminalReason::AuthorizationRevoked)
    {
        return Err(StoreError::AccessDenied(
            "url graph retained authority unavailable".into(),
        ));
    }
    retained_deadline(
        record.config.retention.mode,
        i64::from(record.config.retention.days),
        record.created_at,
        None,
        now,
    )
}
fn graph(g: &Inner, run: CrawlRunId, now: Timestamp) -> Result<&MemoryGraph, StoreError> {
    let graph = g.url_graph.get(&run).ok_or_else(|| nf("url_graph", run))?;
    if graph.expires_at <= now {
        return Err(StoreError::AccessDenied("url graph retention expired".into()));
    }
    Ok(graph)
}

async fn authorized_binding(
    store: &MemoryStore,
    run: CrawlRunId,
) -> Result<Option<crawlx_core::AuthorizationRecordId>, StoreError> {
    let binding = store
        .inner
        .lock()
        .runs
        .get(&run)
        .ok_or(StoreError::LeaseLost)?
        .config
        .safety
        .authorization_record_ref;
    store.check_head_authority(run).await?;
    Ok(binding)
}

fn check_binding(
    g: &Inner,
    run: CrawlRunId,
    binding: Option<crawlx_core::AuthorizationRecordId>,
) -> Result<(), StoreError> {
    if g.runs
        .get(&run)
        .ok_or(StoreError::LeaseLost)?
        .config
        .safety
        .authorization_record_ref
        != binding
    {
        return Err(StoreError::LeaseLost);
    }
    Ok(())
}

impl MemoryStore {
    /// Erase at most 512 expired graph runs under the same run-state lock.
    /// An attached tenant scope narrows maintenance to that tenant.
    ///
    /// # Errors
    /// This in-process operation currently cannot fail.
    pub async fn purge_expired_url_graph(&self) -> Result<u64, StoreError> {
        let mut g = self.inner.lock();
        let now = self.clock.now();
        let tenant = crate::tenant::current();
        let expired: Vec<_> = g
            .url_graph
            .iter()
            .filter(|(_, graph)| {
                graph.expires_at <= now && tenant.is_none_or(|owner| owner == graph.snapshot.tenant)
            })
            .take(512)
            .map(|(run, _)| *run)
            .collect();
        let count = u64::try_from(expired.len())
            .map_err(|_| StoreError::Conflict("url graph purge count overflow".into()))?;
        for run in expired {
            g.url_graph.remove(&run);
        }
        Ok(count)
    }
}

#[async_trait]
impl UrlGraphRepo for MemoryStore {
    async fn configure(&self, lease: &CustodyLease, policy: &UrlGraphPolicyV1) -> Result<(), StoreError> {
        policy.validate().map_err(invalid)?;
        let binding = authorized_binding(self, lease.run).await?;
        let mut g = self.inner.lock();
        check_binding(&g, lease.run, binding)?;
        let now = self.clock.now();
        super::report_history::validate_lease(&g, lease, now)?;
        let ceiling = retained(&g, lease.tenant, lease.run, now)?;
        if g.url_graph.contains_key(&lease.run) {
            graph(&g, lease.run, now)?;
        }
        lease.check_local_cancellation()?;
        let graph = g.url_graph.entry(lease.run).or_insert_with(|| MemoryGraph {
            snapshot: UrlGraphSnapshotV1::empty(lease.tenant, lease.run, policy.clone()),
            expires_at: ceiling,
            ranks: None,
        });
        if graph.snapshot.policy != *policy {
            graph.snapshot.policy = policy.clone();
            graph.ranks = None;
        }
        graph.expires_at = graph.expires_at.min(ceiling);
        Ok(())
    }

    async fn replace_source(
        &self,
        lease: &CustodyLease,
        batch: &UrlGraphBatchV1,
        policy: &UrlGraphPolicyV1,
    ) -> Result<u64, StoreError> {
        batch.validate().map_err(invalid)?;
        let binding = authorized_binding(self, lease.run).await?;
        let mut g = self.inner.lock();
        check_binding(&g, lease.run, binding)?;
        let now = self.clock.now();
        super::report_history::validate_lease(&g, lease, now)?;
        retained(&g, lease.tenant, lease.run, now)?;
        graph(&g, lease.run, now)?;
        lease.check_local_cancellation()?;
        let graph = g
            .url_graph
            .get_mut(&lease.run)
            .ok_or_else(|| nf("url_graph", lease.run))?;
        if graph.snapshot.policy != *policy {
            return Err(StoreError::Conflict("url graph policy changed".into()));
        }
        if graph.snapshot.replace(batch).map_err(invalid)? {
            graph.ranks = None;
        }
        Ok(graph.snapshot.revision)
    }

    async fn snapshot(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphSnapshotV1, StoreError> {
        let binding = authorized_binding(self, run).await?;
        let g = self.inner.lock();
        check_binding(&g, run, binding)?;
        let now = self.clock.now();
        retained(&g, tenant, run, now)?;
        Ok(graph(&g, run, now)?.snapshot.clone())
    }

    async fn store_ranks(&self, lease: &CustodyLease, ranks: &UrlGraphRanksV1) -> Result<(), StoreError> {
        let binding = authorized_binding(self, lease.run).await?;
        let mut g = self.inner.lock();
        check_binding(&g, lease.run, binding)?;
        let now = self.clock.now();
        super::report_history::validate_lease(&g, lease, now)?;
        retained(&g, lease.tenant, lease.run, now)?;
        let current = graph(&g, lease.run, now)?;
        ranks.validate_for(&current.snapshot).map_err(invalid)?;
        lease.check_local_cancellation()?;
        g.url_graph
            .get_mut(&lease.run)
            .ok_or_else(|| nf("url_graph", lease.run))?
            .ranks = Some(ranks.clone());
        Ok(())
    }

    async fn ranks(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphRankStateV1, StoreError> {
        let binding = authorized_binding(self, run).await?;
        let g = self.inner.lock();
        check_binding(&g, run, binding)?;
        let now = self.clock.now();
        retained(&g, tenant, run, now)?;
        let graph = graph(&g, run, now)?;
        Ok(match &graph.ranks {
            Some(ranks)
                if ranks.revision == graph.snapshot.revision && ranks.policy == graph.snapshot.policy =>
            {
                UrlGraphRankStateV1::Current(ranks.clone())
            }
            _ => UrlGraphRankStateV1::Invalidated,
        })
    }
}
