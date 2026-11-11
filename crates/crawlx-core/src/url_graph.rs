//! Versioned URL link evidence and bounded deterministic analysis, never browser action state.
//! Handles are keyed per tenant/run. Neither URL bytes nor anchor text belong in this graph.

use crate::custody::CustodyLease;
use crate::hash::Digest;
use crate::{CrawlRunId, StoreError, TenantId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// Maximum nodes retained in one run's graph.
pub const MAX_URL_GRAPH_NODES: usize = 2048;
/// Maximum distinct edges retained in one run's graph.
pub const MAX_URL_GRAPH_EDGES: usize = 8192;
/// Maximum edges in a single source replacement.
pub const MAX_URL_GRAPH_BATCH: usize = 512;
/// Total fixed-point rank mass. Rounding uses ascending handle order.
pub const URL_GRAPH_RANK_MASS: u64 = 1_000_000;

/// Graph input or bounded-analysis failure. Errors contain no source text.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum UrlGraphError {
    /// An unsupported version or invalid parameter was supplied.
    #[error("invalid URL graph parameters")]
    Invalid,
    /// A fixed graph, input or work limit was exceeded.
    #[error("url graph limit exceeded")]
    Limit,
    /// Graph endpoints, order or scope are inconsistent.
    #[error("inconsistent URL graph snapshot")]
    Inconsistent,
    /// Arithmetic cannot represent the requested result.
    #[error("url graph arithmetic overflow")]
    Overflow,
}

/// Opaque tenant/run-specific URL identity, unrelated to browser element identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UrlHandleV1(pub Digest);

/// Ephemeral keyed handle factory. Keep the root key stable across worker restarts.
/// Its derived key is erased on drop; it is never serialized or included in Debug.
pub struct UrlGraphHandles {
    key: Zeroizing<[u8; 32]>,
}
impl UrlGraphHandles {
    /// Domain-separate a secret root key by tenant and run without copying source bytes.
    #[must_use]
    pub fn new(root: &[u8; 32], tenant: TenantId, run: CrawlRunId) -> Self {
        let mut scope = [0; 32];
        scope[..16].copy_from_slice(tenant.0.as_bytes());
        scope[16..].copy_from_slice(run.0.as_bytes());
        Self {
            key: Zeroizing::new(Digest::keyed(root, "crawlx/url-graph/scope/v1", &scope).0),
        }
    }

    /// Hash an already canonicalized URL. This grants no admission or fetch authority.
    ///
    /// # Errors
    /// Returns `Limit` for empty URLs or URLs exceeding 8192 bytes.
    pub fn url(&self, canonical: &str) -> Result<UrlHandleV1, UrlGraphError> {
        if canonical.is_empty() || canonical.len() > 8192 {
            return Err(UrlGraphError::Limit);
        }
        Ok(UrlHandleV1(Digest::keyed(
            &self.key,
            "crawlx/url-graph/url/v1",
            canonical.as_bytes(),
        )))
    }

    /// Correlate bounded anchor text without retaining or logging text.
    ///
    /// # Errors
    /// Returns `Limit` for text exceeding 4096 bytes.
    pub fn anchor(&self, text: &str) -> Result<Digest, UrlGraphError> {
        if text.len() > 4096 {
            return Err(UrlGraphError::Limit);
        }
        Ok(Digest::keyed(
            &self.key,
            "crawlx/url-graph/anchor/v1",
            text.as_bytes(),
        ))
    }
}

/// One positive-cost outlink. Distinct anchors remain separate evidence rows.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlGraphEdgeV1 {
    /// Opaque source URL.
    pub source: UrlHandleV1,
    /// Opaque target URL.
    pub target: UrlHandleV1,
    /// Opaque keyed anchor, absent when no anchor was supplied.
    pub anchor: Option<Digest>,
    /// Positive advisory path cost; never an authorization or governor limit.
    pub cost: u32,
}
impl UrlGraphEdgeV1 {
    /// Construct link evidence; snapshots validate positive cost.
    #[must_use]
    pub const fn new(source: UrlHandleV1, target: UrlHandleV1, anchor: Option<Digest>, cost: u32) -> Self {
        Self {
            source,
            target,
            anchor,
            cost,
        }
    }
}

/// Complete replacement for one source, including a source with no links.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlGraphBatchV1 {
    /// Independently versioned URL graph schema.
    pub version: u16,
    /// Source whose outgoing evidence is replaced atomically.
    pub source: UrlHandleV1,
    /// Sorted unique link evidence.
    pub edges: Vec<UrlGraphEdgeV1>,
}
impl UrlGraphBatchV1 {
    /// Sort and deduplicate bounded source evidence. Duplicate identities choose minimum cost.
    ///
    /// # Errors
    /// Returns `Limit` for oversized batches, or `Invalid` for wrong sources/zero cost.
    pub fn new(source: UrlHandleV1, mut edges: Vec<UrlGraphEdgeV1>) -> Result<Self, UrlGraphError> {
        if edges.len() > MAX_URL_GRAPH_BATCH {
            return Err(UrlGraphError::Limit);
        }
        edges.sort();
        edges.dedup_by(|later, earlier| {
            later.source == earlier.source && later.target == earlier.target && later.anchor == earlier.anchor
        });
        let batch = Self {
            version: 1,
            source,
            edges,
        };
        batch.validate()?;
        Ok(batch)
    }

    /// Validate serialized evidence before storage.
    ///
    /// # Errors
    /// Returns typed errors for unsupported, unbounded or noncanonical evidence.
    pub fn validate(&self) -> Result<(), UrlGraphError> {
        if self.version != 1
            || self
                .edges
                .iter()
                .any(|edge| edge.source != self.source || edge.cost == 0)
        {
            return Err(UrlGraphError::Invalid);
        }
        if self.edges.len() > MAX_URL_GRAPH_BATCH {
            return Err(UrlGraphError::Limit);
        }
        if self
            .edges
            .windows(2)
            .any(|pair| (pair[0].target, pair[0].anchor) >= (pair[1].target, pair[1].anchor))
        {
            return Err(UrlGraphError::Inconsistent);
        }
        Ok(())
    }
}

/// Explicit rank policy/model binding. Changing any field invalidates cached ranks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlGraphPolicyV1 {
    /// Policy schema, independent from request and browser graph versions.
    pub version: u16,
    /// Current authorization-compatible analysis policy digest.
    pub policy: Digest,
    /// Current pinned scoring model digest, even for the deterministic built-in model.
    pub model: Digest,
    /// Fixed iteration count, 1..=64.
    pub iterations: u16,
    /// Damping in basis points, 0..=10000.
    pub damping_bps: u16,
}
impl UrlGraphPolicyV1 {
    /// Construct an explicit deterministic analysis policy.
    #[must_use]
    pub const fn new(policy: Digest, model: Digest, iterations: u16, damping_bps: u16) -> Self {
        Self {
            version: 1,
            policy,
            model,
            iterations,
            damping_bps,
        }
    }

    /// Validate the finite analysis budget.
    ///
    /// # Errors
    /// Returns `Invalid` for unsupported version, iterations or damping.
    pub fn validate(&self) -> Result<(), UrlGraphError> {
        if self.version != 1 || !(1..=64).contains(&self.iterations) || self.damping_bps > 10_000 {
            return Err(UrlGraphError::Invalid);
        }
        Ok(())
    }
}

/// Canonical bounded graph snapshot. Isolated and former target nodes remain visible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlGraphSnapshotV1 {
    /// URL graph schema version.
    pub version: u16,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Owning run.
    pub run: CrawlRunId,
    /// Monotonic graph content revision.
    pub revision: u64,
    /// Current analysis policy/model binding.
    pub policy: UrlGraphPolicyV1,
    /// Strictly ascending node handles, including orphans.
    pub nodes: Vec<UrlHandleV1>,
    /// Strictly ascending edge identities.
    pub edges: Vec<UrlGraphEdgeV1>,
}
impl UrlGraphSnapshotV1 {
    /// Construct an empty run-scoped snapshot.
    #[must_use]
    pub const fn empty(tenant: TenantId, run: CrawlRunId, policy: UrlGraphPolicyV1) -> Self {
        Self {
            version: 1,
            tenant,
            run,
            revision: 0,
            policy,
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Validate all endpoints, versions, ordering and work bounds.
    ///
    /// # Errors
    /// Returns an error for malformed or unbounded snapshots.
    pub fn validate(&self) -> Result<(), UrlGraphError> {
        self.policy.validate()?;
        if self.version != 1 || self.revision > i64::MAX.unsigned_abs() {
            return Err(UrlGraphError::Invalid);
        }
        if self.nodes.len() > MAX_URL_GRAPH_NODES || self.edges.len() > MAX_URL_GRAPH_EDGES {
            return Err(UrlGraphError::Limit);
        }
        if self.nodes.windows(2).any(|pair| pair[0] >= pair[1])
            || self.edges.windows(2).any(|pair| {
                (pair[0].source, pair[0].target, pair[0].anchor)
                    >= (pair[1].source, pair[1].target, pair[1].anchor)
            })
            || self.edges.iter().any(|edge| {
                edge.cost == 0
                    || self.nodes.binary_search(&edge.source).is_err()
                    || self.nodes.binary_search(&edge.target).is_err()
            })
        {
            return Err(UrlGraphError::Inconsistent);
        }
        Ok(())
    }

    /// Atomically stage a source replacement. Replayed identical batches keep their revision.
    ///
    /// # Errors
    /// Returns an error without changing this snapshot if limits or revision overflow occur.
    pub fn replace(&mut self, batch: &UrlGraphBatchV1) -> Result<bool, UrlGraphError> {
        self.validate()?;
        batch.validate()?;
        let unchanged = self.nodes.binary_search(&batch.source).is_ok()
            && self
                .edges
                .iter()
                .filter(|edge| edge.source == batch.source)
                .eq(batch.edges.iter());
        if unchanged {
            return Ok(false);
        }
        let mut nodes: BTreeSet<_> = self.nodes.iter().copied().collect();
        nodes.insert(batch.source);
        nodes.extend(batch.edges.iter().map(|edge| edge.target));
        let retained = self
            .edges
            .iter()
            .filter(|edge| edge.source != batch.source)
            .count();
        if nodes.len() > MAX_URL_GRAPH_NODES
            || retained.saturating_add(batch.edges.len()) > MAX_URL_GRAPH_EDGES
        {
            return Err(UrlGraphError::Limit);
        }
        let revision = self
            .revision
            .checked_add(1)
            .filter(|value| *value <= i64::MAX.unsigned_abs())
            .ok_or(UrlGraphError::Overflow)?;
        self.nodes = nodes.into_iter().collect();
        self.edges.retain(|edge| edge.source != batch.source);
        self.edges.extend_from_slice(&batch.edges);
        self.edges.sort();
        self.revision = revision;
        Ok(true)
    }

    /// Invert links deterministically. Empty incoming lists explicitly preserve orphans.
    ///
    /// # Errors
    /// Returns an error for an invalid snapshot.
    pub fn invert(&self) -> Result<BTreeMap<UrlHandleV1, Vec<&UrlGraphEdgeV1>>, UrlGraphError> {
        self.validate()?;
        let mut result: BTreeMap<_, Vec<_>> = self.nodes.iter().map(|node| (*node, Vec::new())).collect();
        for edge in &self.edges {
            result
                .get_mut(&edge.target)
                .ok_or(UrlGraphError::Inconsistent)?
                .push(edge);
        }
        Ok(result)
    }

    /// Fixed-point link rank over distinct targets, not anchor multiplicity.
    /// Dangling mass and all rounding remainders return uniformly in handle order.
    ///
    /// # Errors
    /// Returns an error for an invalid snapshot or checked arithmetic failure.
    pub fn rank(&self) -> Result<UrlGraphRanksV1, UrlGraphError> {
        self.validate()?;
        let mut outgoing: BTreeMap<_, BTreeSet<_>> =
            self.nodes.iter().map(|node| (*node, BTreeSet::new())).collect();
        for edge in &self.edges {
            outgoing
                .get_mut(&edge.source)
                .ok_or(UrlGraphError::Inconsistent)?
                .insert(edge.target);
        }
        let mut scores: BTreeMap<_, u64> = self.nodes.iter().map(|node| (*node, 0)).collect();
        distribute(URL_GRAPH_RANK_MASS, &mut scores)?;
        let mut next: BTreeMap<_, u64> = self.nodes.iter().map(|node| (*node, 0)).collect();
        for _ in 0..self.policy.iterations {
            next.values_mut().for_each(|score| *score = 0);
            let mut distributed = 0_u64;
            for (source, targets) in &outgoing {
                if targets.is_empty() {
                    continue;
                }
                let mass = scores[source]
                    .checked_mul(u64::from(self.policy.damping_bps))
                    .ok_or(UrlGraphError::Overflow)?
                    / 10_000;
                let count = u64::try_from(targets.len()).map_err(|_| UrlGraphError::Overflow)?;
                for (ordinal, target) in targets.iter().enumerate() {
                    let extra = u64::from(
                        u64::try_from(ordinal).map_err(|_| UrlGraphError::Overflow)? < mass % count,
                    );
                    let share = (mass / count).checked_add(extra).ok_or(UrlGraphError::Overflow)?;
                    let score = next.get_mut(target).ok_or(UrlGraphError::Inconsistent)?;
                    *score = score.checked_add(share).ok_or(UrlGraphError::Overflow)?;
                }
                distributed = distributed.checked_add(mass).ok_or(UrlGraphError::Overflow)?;
            }
            distribute(
                URL_GRAPH_RANK_MASS
                    .checked_sub(distributed)
                    .ok_or(UrlGraphError::Overflow)?,
                &mut next,
            )?;
            std::mem::swap(&mut scores, &mut next);
        }
        let mut rows: Vec<_> = scores
            .into_iter()
            .map(|(node, score)| UrlGraphRankV1 { node, score })
            .collect();
        rows.sort_by(|a, b| b.score.cmp(&a.score).then(a.node.cmp(&b.node)));
        Ok(UrlGraphRanksV1 {
            version: 1,
            tenant: self.tenant,
            run: self.run,
            revision: self.revision,
            policy: self.policy.clone(),
            rows,
        })
    }

    /// Minimum directed positive path cost from explicit roots; unreachable nodes map to `None`.
    /// At most 2048 nodes and 8192 edges participate. This does not schedule requests.
    ///
    /// # Errors
    /// Returns an error for unknown roots, invalid graph or distance overflow.
    pub fn costs(&self, roots: &[UrlHandleV1]) -> Result<BTreeMap<UrlHandleV1, Option<u64>>, UrlGraphError> {
        self.validate()?;
        if roots.len() > MAX_URL_GRAPH_NODES {
            return Err(UrlGraphError::Limit);
        }
        let mut distances: BTreeMap<_, Option<u64>> = self.nodes.iter().map(|node| (*node, None)).collect();
        let mut pending = BTreeSet::new();
        for root in roots {
            *distances.get_mut(root).ok_or(UrlGraphError::Inconsistent)? = Some(0);
            pending.insert((0_u64, *root));
        }
        let mut outgoing: BTreeMap<_, Vec<_>> = self.nodes.iter().map(|node| (*node, Vec::new())).collect();
        for edge in &self.edges {
            outgoing
                .get_mut(&edge.source)
                .ok_or(UrlGraphError::Inconsistent)?
                .push(edge);
        }
        while let Some((distance, node)) = pending.pop_first() {
            if distances[&node] != Some(distance) {
                continue;
            }
            for edge in &outgoing[&node] {
                let candidate = distance
                    .checked_add(u64::from(edge.cost))
                    .ok_or(UrlGraphError::Overflow)?;
                let current = distances
                    .get_mut(&edge.target)
                    .ok_or(UrlGraphError::Inconsistent)?;
                if current.is_none_or(|old| candidate < old) {
                    if let Some(old) = *current {
                        pending.remove(&(old, edge.target));
                    }
                    *current = Some(candidate);
                    pending.insert((candidate, edge.target));
                }
            }
        }
        Ok(distances)
    }
}

fn distribute(mass: u64, scores: &mut BTreeMap<UrlHandleV1, u64>) -> Result<(), UrlGraphError> {
    let count = u64::try_from(scores.len()).map_err(|_| UrlGraphError::Overflow)?;
    if count == 0 {
        return Ok(());
    }
    for (ordinal, score) in scores.values_mut().enumerate() {
        let extra = u64::from(u64::try_from(ordinal).map_err(|_| UrlGraphError::Overflow)? < mass % count);
        *score = score
            .checked_add(mass / count)
            .and_then(|value| value.checked_add(extra))
            .ok_or(UrlGraphError::Overflow)?;
    }
    Ok(())
}

/// One fixed-point rank, ordered by descending score then ascending URL handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlGraphRankV1 {
    /// Ranked URL handle.
    pub node: UrlHandleV1,
    /// Integer mass share; all nonempty graph scores sum to 1000000.
    pub score: u64,
}

/// Cache provenance includes the complete policy/model and graph content revision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlGraphRanksV1 {
    /// Rank result schema version.
    pub version: u16,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Owning run.
    pub run: CrawlRunId,
    /// Exact input graph revision.
    pub revision: u64,
    /// Exact input policy and model.
    pub policy: UrlGraphPolicyV1,
    /// All ranked nodes, including orphans.
    pub rows: Vec<UrlGraphRankV1>,
}

impl UrlGraphRanksV1 {
    /// Validate complete current provenance, node coverage, total mass and canonical tie ordering.
    /// Trusted analysis producers compute scores; storage need not repeat iterations under its locks.
    ///
    /// # Errors
    /// Returns `Inconsistent` for stale, incomplete, unordered or malformed results.
    pub fn validate_for(&self, graph: &UrlGraphSnapshotV1) -> Result<(), UrlGraphError> {
        graph.validate()?;
        if self.version != 1
            || self.tenant != graph.tenant
            || self.run != graph.run
            || self.revision != graph.revision
            || self.policy != graph.policy
            || self.rows.len() != graph.nodes.len()
        {
            return Err(UrlGraphError::Inconsistent);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0_u64;
        for row in &self.rows {
            if row.score > URL_GRAPH_RANK_MASS
                || graph.nodes.binary_search(&row.node).is_err()
                || !seen.insert(row.node)
            {
                return Err(UrlGraphError::Inconsistent);
            }
            total = total.checked_add(row.score).ok_or(UrlGraphError::Overflow)?;
        }
        let expected = if graph.nodes.is_empty() {
            0
        } else {
            URL_GRAPH_RANK_MASS
        };
        if total != expected
            || self.rows.windows(2).any(|pair| {
                pair[0].score < pair[1].score
                    || (pair[0].score == pair[1].score && pair[0].node >= pair[1].node)
            })
        {
            return Err(UrlGraphError::Inconsistent);
        }
        Ok(())
    }
}

/// Explicit cache availability; stale results are never returned as current.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UrlGraphRankStateV1 {
    /// No rank computation has been committed for the current input.
    Invalidated,
    /// Complete current rank result.
    Current(UrlGraphRanksV1),
}

/// URL evidence persistence over existing lease authority, never a second frontier.
#[async_trait]
pub trait UrlGraphRepo: Send + Sync {
    /// Set policy/model explicitly, clearing rank results on any change. Creates an empty graph.
    ///
    /// # Errors
    /// Returns denial for nonretained/expired runs, stale ownership or malformed policy.
    async fn configure(&self, lease: &CustodyLease, policy: &UrlGraphPolicyV1) -> Result<(), StoreError>;
    /// Atomically replace one source's evidence and invalidate ranks on content change.
    /// The expected full policy/model binding prevents races with concurrent reconfiguration.
    ///
    /// # Errors
    /// Returns denial for lost ownership/retention, or conflict for changed policy or capacity overflow.
    async fn replace_source(
        &self,
        lease: &CustodyLease,
        batch: &UrlGraphBatchV1,
        policy: &UrlGraphPolicyV1,
    ) -> Result<u64, StoreError>;
    /// Read the complete bounded canonical graph under explicit tenant authority.
    ///
    /// # Errors
    /// Returns denial for a foreign tenant, withheld/expired run or missing graph.
    async fn snapshot(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphSnapshotV1, StoreError>;
    /// Commit only ranks matching the current revision and complete policy/model binding.
    ///
    /// # Errors
    /// Returns conflict for stale or incorrect ranks, or denial for lost ownership.
    async fn store_ranks(&self, lease: &CustodyLease, ranks: &UrlGraphRanksV1) -> Result<(), StoreError>;
    /// Return explicit invalidation when policy/model or graph content changed.
    ///
    /// # Errors
    /// Returns denial for tenant, retention or expiry violations.
    async fn ranks(&self, tenant: TenantId, run: CrawlRunId) -> Result<UrlGraphRankStateV1, StoreError>;
}
