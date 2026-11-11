//! Privacy-safe URL graph producer for admitted discovery evidence.
//! This module neither enqueues URLs nor reads the browser action graph.

use crawlx_core::custody::CustodyLease;
use crawlx_core::url::CanonicalUrl;
use crawlx_core::url_graph::{
    UrlGraphBatchV1, UrlGraphEdgeV1, UrlGraphError, UrlGraphHandles, UrlGraphPolicyV1, UrlGraphRanksV1,
    UrlGraphRepo, MAX_URL_GRAPH_BATCH,
};
use crawlx_core::StoreError;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Borrowed admitted outlink evidence. Construction alone grants no admission authority.
#[non_exhaustive]
pub struct UrlGraphLink<'a> {
    /// Target canonicalized through the ordinary discovery pipeline.
    pub target: &'a CanonicalUrl,
    /// Optional bounded anchor; only its keyed handle enters persistence.
    pub anchor: Option<&'a str>,
    /// Positive path cost under the current explicit graph policy.
    pub cost: u32,
}
impl<'a> UrlGraphLink<'a> {
    /// Describe one already admitted link without copying URL or anchor bytes.
    #[must_use]
    pub const fn new(target: &'a CanonicalUrl, anchor: Option<&'a str>, cost: u32) -> Self {
        Self { target, anchor, cost }
    }
}

/// Producer failure, with source chains and no URL/anchor text in error messages.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UrlGraphProducerError {
    /// Graph evidence exceeded a bound or failed validation.
    #[error("url graph evidence rejected")]
    Graph(#[from] UrlGraphError),
    /// Existing lease, tenant, retention or storage authority rejected publication.
    #[error("url graph publication failed")]
    Store(#[from] StoreError),
    /// Bounded analysis task failed.
    #[error("url graph analysis task failed")]
    Task(#[from] tokio::task::JoinError),
}

/// Injected URL evidence sink. The secret root key must survive restarts outside graph storage.
/// No Debug/Serialize implementation can expose this key.
#[non_exhaustive]
pub struct UrlGraphProducer {
    repo: Arc<dyn UrlGraphRepo>,
    root: Zeroizing<[u8; 32]>,
}
impl UrlGraphProducer {
    /// Bind the existing repository and operator-managed stable privacy key.
    #[must_use]
    pub fn new(repo: Arc<dyn UrlGraphRepo>, root: &[u8; 32]) -> Self {
        Self {
            repo,
            root: Zeroizing::new(*root),
        }
    }

    /// Publish a complete bounded source replacement before its real producer lease is settled.
    /// Call only after normal scope/robots/budget admission. Failure never grants navigation authority.
    /// ZDR runs must not call this retained-only sink.
    ///
    /// # Errors
    /// Returns typed size/anchor/cost errors or the repository's actual authority/storage error.
    pub async fn record(
        &self,
        lease: &CustodyLease,
        policy: &UrlGraphPolicyV1,
        source: &CanonicalUrl,
        links: &[UrlGraphLink<'_>],
    ) -> Result<u64, UrlGraphProducerError> {
        lease.check_local_cancellation()?;
        if links.len() > MAX_URL_GRAPH_BATCH {
            return Err(UrlGraphError::Limit.into());
        }
        let handles = UrlGraphHandles::new(&self.root, lease.tenant, lease.run);
        let source = handles.url(source.url.as_str())?;
        let mut edges = Vec::with_capacity(links.len());
        for link in links {
            edges.push(UrlGraphEdgeV1::new(
                source,
                handles.url(link.target.url.as_str())?,
                link.anchor.map(|text| handles.anchor(text)).transpose()?,
                link.cost,
            ));
        }
        let batch = UrlGraphBatchV1::new(source, edges)?;
        self.repo.configure(lease, policy).await?;
        Ok(self.repo.replace_source(lease, &batch, policy).await?)
    }

    /// Recompute rank off the async executor, then publish against exact snapshot provenance.
    /// A concurrent graph/policy/model update causes a conflict rather than stale publication.
    ///
    /// # Errors
    /// Returns cancellation, bounded-analysis, join, stale-input or storage failures.
    pub async fn refresh_ranks(
        &self,
        lease: &CustodyLease,
    ) -> Result<UrlGraphRanksV1, UrlGraphProducerError> {
        lease.check_local_cancellation()?;
        let graph = self.repo.snapshot(lease.tenant, lease.run).await?;
        let ranks = tokio::select! {
            biased;
            () = lease.cancelled() => return Err(StoreError::LeaseLost.into()),
            result = tokio::task::spawn_blocking(move || graph.rank()) => result??,
        };
        lease.check_local_cancellation()?;
        self.repo.store_ranks(lease, &ranks).await?;
        Ok(ranks)
    }
}
