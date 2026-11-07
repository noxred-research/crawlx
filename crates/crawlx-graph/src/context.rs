//! The in-memory enablement graph, context lookup and route-template
//! generalization.
//!
//! Lookup order is exact cluster, then route template (+0.15 cost), then
//! principal-global (+0.40). A route-template edge is created only when the
//! same `(X → T)` was seen in at least three distinct clusters of that route
//! with `p ≥ 0.7`; edges never become globally applicable on their own.

use crate::edge::{EdgeContext, EdgeTarget, EnablementEdge};
use crate::hyperedge::{Hyperedge, HyperedgeMiner};
use crate::update::GraphParams;
use crate::GraphError;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::repo::EdgeRecord;
use crawlx_core::{ActionContextId, CrawlRunId, EdgeId, RouteTemplate, StateClusterId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

type EdgeKey = (ActionContextId, EdgeTarget);

/// Probabilistic enablement graph over state clusters. All maps are
/// `BTreeMap`s so iteration, dumps and search are deterministic.
#[derive(Clone, Debug)]
pub struct EnablementGraph {
    pub(crate) run: CrawlRunId,
    pub(crate) params: GraphParams,
    edges: BTreeMap<EdgeContext, BTreeMap<EdgeKey, EnablementEdge>>,
    index: BTreeMap<EdgeId, (EdgeContext, EdgeKey)>,
    pub(crate) cluster_routes: BTreeMap<StateClusterId, RouteTemplate>,
    route_clusters: BTreeMap<RouteTemplate, BTreeSet<StateClusterId>>,
    pub(crate) visible: BTreeMap<StateClusterId, BTreeSet<ElementIdentityHash>>,
    pub(crate) action_risk: BTreeMap<ActionContextId, f32>,
    pub(crate) current_build: Option<String>,
    blocked_generalizations: BTreeSet<(RouteTemplate, ActionContextId, EdgeTarget)>,
    pub(crate) hyperedges: HyperedgeMiner,
    /// Action family of each observed source (`ActionContextKey::family_id`): the same action
    /// in every cluster. Route-template generalization pools exact edges over a family.
    pub(crate) families: BTreeMap<ActionContextId, ActionContextId>,
}

/// Serializable full state of a graph (edges of every kind, routes,
/// visibility, hyperedge episodes). `EdgeRecord` persistence only carries
/// element-target edges; this carries everything.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct GraphSnapshot {
    /// Crawl run the graph belongs to.
    pub run: CrawlRunId,
    /// Every edge, in deterministic graph order (context, source, target).
    pub edges: Vec<EnablementEdge>,
    /// Declared route template of each cluster.
    pub cluster_routes: Vec<(StateClusterId, RouteTemplate)>,
    /// Controls known visible in each cluster.
    pub visible: Vec<(StateClusterId, BTreeSet<ElementIdentityHash>)>,
    /// Per-action risk applied to new and existing edges.
    pub action_risk: Vec<(ActionContextId, f32)>,
    /// Application build id edges are currently verified against.
    pub current_build: Option<String>,
    /// Route-template edges that were retired and must not be regenerated.
    pub blocked_generalizations: BTreeSet<(RouteTemplate, ActionContextId, EdgeTarget)>,
    /// Episode log and mined hyperedges.
    pub hyperedges: HyperedgeMiner,
    /// Action family of each observed source (absent in snapshots taken before 2026-10-20).
    #[serde(default)]
    pub families: Vec<(ActionContextId, ActionContextId)>,
}

impl EnablementGraph {
    /// Empty graph for `run` with default parameters.
    #[must_use]
    pub fn new(run: CrawlRunId) -> Self {
        Self::with_params(run, GraphParams::default())
    }

    /// Empty graph with explicit parameters.
    #[must_use]
    pub fn with_params(run: CrawlRunId, params: GraphParams) -> Self {
        Self {
            run,
            params,
            edges: BTreeMap::new(),
            index: BTreeMap::new(),
            cluster_routes: BTreeMap::new(),
            route_clusters: BTreeMap::new(),
            visible: BTreeMap::new(),
            action_risk: BTreeMap::new(),
            current_build: None,
            blocked_generalizations: BTreeSet::new(),
            hyperedges: HyperedgeMiner::default(),
            families: BTreeMap::new(),
        }
    }

    /// The run this graph belongs to.
    #[must_use]
    pub fn run(&self) -> CrawlRunId {
        self.run
    }

    /// Number of edges of every kind.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Whether the graph holds no edges.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// The detected application build id edges are currently verified against.
    #[must_use]
    pub fn current_build(&self) -> Option<&str> {
        self.current_build.as_deref()
    }

    /// Edge by id.
    #[must_use]
    pub fn edge(&self, id: EdgeId) -> Option<&EnablementEdge> {
        let (ctx, key) = self.index.get(&id)?;
        self.edges.get(ctx)?.get(key)
    }

    pub(crate) fn edge_mut(&mut self, id: EdgeId) -> Option<&mut EnablementEdge> {
        let (ctx, key) = self.index.get(&id)?;
        self.edges.get_mut(ctx)?.get_mut(key)
    }

    /// Edge by its identity triple.
    #[must_use]
    pub fn find(
        &self,
        context: &EdgeContext,
        source: ActionContextId,
        target: &EdgeTarget,
    ) -> Option<&EnablementEdge> {
        self.edges.get(context)?.get(&(source, *target))
    }

    /// Every edge in deterministic order (context, then source, then target).
    pub fn edges(&self) -> impl Iterator<Item = &EnablementEdge> {
        self.edges.values().flat_map(BTreeMap::values)
    }

    /// Edges of exactly one context, in deterministic order.
    pub fn edges_in(&self, context: &EdgeContext) -> impl Iterator<Item = &EnablementEdge> {
        self.edges.get(context).into_iter().flat_map(BTreeMap::values)
    }

    /// Insert (or return the existing) edge for the triple. New edges take the
    /// per-action risk and the current build.
    pub(crate) fn upsert_mut(
        &mut self,
        context: EdgeContext,
        source: ActionContextId,
        target: EdgeTarget,
        now: Timestamp,
    ) -> &mut EnablementEdge {
        let key = (source, target);
        let risk = self.action_risk.get(&source).copied().unwrap_or(0.0);
        let build = &self.current_build;
        let outer = self.edges.entry(context);
        let ctx = outer.key().clone();
        let map = outer.or_default();
        let index = &mut self.index;
        map.entry(key).or_insert_with(|| {
            let mut e = EnablementEdge::new(source, ctx.clone(), target, now);
            e.risk = risk;
            e.last_verified_build = build.clone();
            index.insert(e.id, (ctx, key));
            e
        })
    }

    pub(crate) fn insert_edge(&mut self, edge: EnablementEdge) {
        let key = (edge.source, edge.target);
        self.index.insert(edge.id, (edge.context.clone(), key));
        self.edges
            .entry(edge.context.clone())
            .or_default()
            .insert(key, edge);
    }

    pub(crate) fn remove_edge(&mut self, id: EdgeId) -> Option<EnablementEdge> {
        let (ctx, key) = self.index.remove(&id)?;
        let map = self.edges.get_mut(&ctx)?;
        let e = map.remove(&key);
        if map.is_empty() {
            self.edges.remove(&ctx);
        }
        e
    }

    pub(crate) fn block_generalization(
        &mut self,
        route: RouteTemplate,
        source: ActionContextId,
        target: EdgeTarget,
    ) {
        self.blocked_generalizations.insert((route, source, target));
    }

    /// Declare the route template a cluster belongs to (needed for
    /// route-template generalization and lookup).
    pub fn set_cluster_route(&mut self, cluster: StateClusterId, route: RouteTemplate) {
        if let Some(old) = self.cluster_routes.insert(cluster, route.clone()) {
            if old != route {
                if let Some(set) = self.route_clusters.get_mut(&old) {
                    set.remove(&cluster);
                }
            }
        }
        self.route_clusters.entry(route).or_default().insert(cluster);
    }

    /// Route template of a cluster, if declared.
    #[must_use]
    pub fn route_of(&self, cluster: StateClusterId) -> Option<&RouteTemplate> {
        self.cluster_routes.get(&cluster)
    }

    /// Record controls known to be visible in a cluster.
    pub fn observe_visible(
        &mut self,
        cluster: StateClusterId,
        identities: impl IntoIterator<Item = ElementIdentityHash>,
    ) {
        self.visible.entry(cluster).or_default().extend(identities);
    }

    /// Controls known visible in `cluster`.
    #[must_use]
    pub fn visible_in(&self, cluster: StateClusterId) -> Option<&BTreeSet<ElementIdentityHash>> {
        self.visible.get(&cluster)
    }

    /// Edges applicable at `cluster`, in lookup order: all exact edges, then
    /// route-template edges for the cluster's route whose `(source, target)`
    /// has no exact edge here, then principal-global edges with neither.
    #[must_use]
    pub fn applicable_edges(&self, cluster: StateClusterId) -> Vec<&EnablementEdge> {
        let mut out: Vec<&EnablementEdge> = Vec::new();
        let mut seen: BTreeSet<EdgeKey> = BTreeSet::new();
        if let Some(exact) = self.edges.get(&EdgeContext::Cluster(cluster)) {
            for (k, e) in exact {
                seen.insert(*k);
                out.push(e);
            }
        }
        if let Some(route) = self.cluster_routes.get(&cluster) {
            if let Some(m) = self.edges.get(&EdgeContext::RouteTemplate(route.clone())) {
                for (k, e) in m {
                    if seen.insert(*k) {
                        out.push(e);
                    }
                }
            }
        }
        if let Some(m) = self.edges.get(&EdgeContext::PrincipalGlobal) {
            for (k, e) in m {
                if seen.insert(*k) {
                    out.push(e);
                }
            }
        }
        out
    }

    /// Action family of `source` (`ActionContextKey::family_id`, recorded by
    /// [`Self::observe_transition`]); a source never observed with a family is its own family.
    #[must_use]
    pub fn family_of(&self, source: ActionContextId) -> ActionContextId {
        self.families.get(&source).copied().unwrap_or(source)
    }

    /// Declare the action family of `source` (when rebuilding from persisted records, which
    /// carry no family; follow with [`Self::generalize_all`]).
    pub fn set_family(&mut self, source: ActionContextId, family: ActionContextId) {
        self.families.insert(source, family);
    }

    /// Create a route-template edge `(family(source) → target)` from the pooled evidence of
    /// every exact edge of `cluster`'s route whose source belongs to the same action family
    /// (the same element, action kind, route and principal in any cluster), once
    /// the pool spans at least `generalize_min_clusters` distinct clusters and its Laplace
    /// `p ≥ generalize_min_p`. The route edge's source is the family id. Returns the new
    /// edge's id.
    ///
    /// The route edge starts from the sum of its members' evidence and then
    /// evolves independently. A route edge that was retired is not recreated.
    pub fn generalize(
        &mut self,
        cluster: StateClusterId,
        source: ActionContextId,
        target: EdgeTarget,
        now: Timestamp,
    ) -> Option<EdgeId> {
        let route = self.cluster_routes.get(&cluster)?.clone();
        let family = self.family_of(source);
        let route_ctx = EdgeContext::RouteTemplate(route.clone());
        if self
            .edges
            .get(&route_ctx)
            .is_some_and(|m| m.contains_key(&(family, target)))
            || self
                .blocked_generalizations
                .contains(&(route.clone(), family, target))
        {
            return None;
        }
        let mut member_clusters: BTreeSet<StateClusterId> = BTreeSet::new();
        let mut members: Vec<&EnablementEdge> = Vec::new();
        for c in self.route_clusters.get(&route)? {
            for e in self.edges_in(&EdgeContext::Cluster(*c)) {
                if e.target == target && self.family_of(e.source) == family {
                    member_clusters.insert(*c);
                    members.push(e);
                }
            }
        }
        if member_clusters.len() < self.params.generalize_min_clusters {
            return None;
        }
        let mut agg = EnablementEdge::new(family, route_ctx, target, now);
        let mut lat: Vec<u32> = Vec::with_capacity(members.len());
        for m in &members {
            agg.support = agg.support.saturating_add(m.support);
            agg.weak_support = agg.weak_support.saturating_add(m.weak_support);
            agg.failures = agg.failures.saturating_add(m.failures);
            agg.risk = agg.risk.max(m.risk);
            agg.unverified |= m.unverified;
            lat.push(m.p50_latency_ms);
        }
        agg.first_seen = members.iter().map(|m| m.first_seen).min().unwrap_or(now);
        agg.last_seen = members.iter().map(|m| m.last_seen).max().unwrap_or(now);
        if agg.p_success(now) < self.params.generalize_min_p {
            return None;
        }
        lat.sort_unstable();
        agg.p50_latency_ms = lat.get(lat.len() / 2).copied().unwrap_or(0);
        agg.latency_window = vec![agg.p50_latency_ms];
        let first_build = members.first().and_then(|m| m.last_verified_build.clone());
        if members.iter().all(|m| m.last_verified_build == first_build) {
            agg.last_verified_build = first_build;
        }
        let id = agg.id;
        self.insert_edge(agg);
        Some(id)
    }

    /// Re-run generalization for every `(source, target)` pair across all
    /// declared routes (call after loading records and declaring routes).
    pub fn generalize_all(&mut self, now: Timestamp) -> Vec<EdgeId> {
        let mut candidates: Vec<(StateClusterId, ActionContextId, EdgeTarget)> = Vec::new();
        for (ctx, m) in &self.edges {
            if let EdgeContext::Cluster(c) = ctx {
                if self.cluster_routes.contains_key(c) {
                    candidates.extend(m.keys().map(|(s, t)| (*c, *s, *t)));
                }
            }
        }
        candidates
            .into_iter()
            .filter_map(|(c, s, t)| self.generalize(c, s, t, now))
            .collect()
    }

    /// Dump the persistable edges: element-target edges in an exact cluster
    /// or principal-global context. Route-template edges are derived data
    /// (rebuilt by [`Self::generalize_all`]); cluster-target transition edges
    /// are not representable in `EdgeRecord`, use [`Self::snapshot`] for those.
    #[must_use]
    pub fn dump(&self) -> Vec<EdgeRecord> {
        let mut out = Vec::new();
        for e in self.edges() {
            let EdgeTarget::Identity(target) = e.target else {
                continue;
            };
            let context_cluster = match &e.context {
                EdgeContext::Cluster(c) => Some(*c),
                EdgeContext::PrincipalGlobal => None,
                EdgeContext::RouteTemplate(_) => continue,
            };
            out.push(EdgeRecord {
                id: e.id,
                run: self.run,
                source: e.source,
                context_cluster,
                target,
                support: e.support,
                weak_support: e.weak_support,
                failures: e.failures,
                latency_ms_ewma: e.p50_latency_ms as f32,
                risk: e.risk,
                last_observed_at: e.last_seen,
                last_verified_build: e.last_verified_build.clone(),
            });
        }
        out
    }

    /// Merge persisted records of this run into the graph (a record for an
    /// existing key replaces it). `first_seen` is not persisted and restarts
    /// at `last_observed_at`; call [`Self::on_build_change`] afterwards if the
    /// application build may have changed. Returns the number loaded.
    pub fn load(&mut self, records: impl IntoIterator<Item = EdgeRecord>) -> usize {
        let mut n = 0;
        for r in records {
            if r.run != self.run {
                continue;
            }
            let context = r
                .context_cluster
                .map_or(EdgeContext::PrincipalGlobal, EdgeContext::Cluster);
            let mut e = EnablementEdge::new(
                r.source,
                context,
                EdgeTarget::Identity(r.target),
                r.last_observed_at,
            );
            e.id = r.id;
            e.support = r.support;
            e.weak_support = r.weak_support;
            e.failures = r.failures;
            e.p50_latency_ms = latency_from_ewma(r.latency_ms_ewma);
            e.latency_window = vec![e.p50_latency_ms];
            e.risk = r.risk;
            e.last_verified_build = r.last_verified_build;
            if let Some((ctx, key)) = self.index.remove(&e.id) {
                if let Some(m) = self.edges.get_mut(&ctx) {
                    m.remove(&key);
                }
            }
            self.insert_edge(e);
            n += 1;
        }
        n
    }

    /// Record a session window for conjunctive-precondition mining.
    pub fn record_episode(
        &mut self,
        target: ElementIdentityHash,
        actions: BTreeSet<ActionContextId>,
        appeared: bool,
    ) {
        self.hyperedges.record_episode(target, actions, appeared);
    }

    /// Mine hyperedges for `target` from its recorded episodes.
    pub fn mine_hyperedges(&mut self, target: ElementIdentityHash) -> Vec<Hyperedge> {
        self.hyperedges.mine(target)
    }

    /// The hyperedge miner (episodes and stored hyperedges).
    #[must_use]
    pub fn hyperedges(&self) -> &HyperedgeMiner {
        &self.hyperedges
    }

    /// Full lossless state.
    #[must_use]
    pub fn snapshot(&self) -> GraphSnapshot {
        GraphSnapshot {
            run: self.run,
            edges: self.edges().cloned().collect(),
            cluster_routes: self.cluster_routes.iter().map(|(c, r)| (*c, r.clone())).collect(),
            visible: self.visible.iter().map(|(c, v)| (*c, v.clone())).collect(),
            action_risk: self.action_risk.iter().map(|(a, r)| (*a, *r)).collect(),
            current_build: self.current_build.clone(),
            blocked_generalizations: self.blocked_generalizations.clone(),
            hyperedges: self.hyperedges.clone(),
            families: self.families.iter().map(|(s, f)| (*s, *f)).collect(),
        }
    }

    /// Rebuild from [`Self::snapshot`] output.
    #[must_use]
    pub fn from_snapshot(snapshot: GraphSnapshot, params: GraphParams) -> Self {
        let mut g = Self::with_params(snapshot.run, params);
        for (c, r) in snapshot.cluster_routes {
            g.set_cluster_route(c, r);
        }
        for e in snapshot.edges {
            g.insert_edge(e);
        }
        g.visible = snapshot.visible.into_iter().collect();
        g.action_risk = snapshot.action_risk.into_iter().collect();
        g.current_build = snapshot.current_build;
        g.blocked_generalizations = snapshot.blocked_generalizations;
        g.hyperedges = snapshot.hyperedges;
        g.families = snapshot.families.into_iter().collect();
        g
    }

    /// Edge lookup that fails with a typed error.
    pub(crate) fn require(&self, id: EdgeId) -> Result<&EnablementEdge, GraphError> {
        self.edge(id).ok_or(GraphError::UnknownEdge(id))
    }
}

/// Persisted latency EWMA (milliseconds, `f32`) as whole milliseconds:
/// negative and NaN clamp to `0`, values past `u32::MAX` saturate.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "float-to-int `as` saturates; the value is already clamped non-negative and rounded"
)]
fn latency_from_ewma(ewma_ms: f32) -> u32 {
    ewma_ms.max(0.0).round() as u32
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{act, cluster, graph, hash, obs, t0};
    use chrono::Duration;

    fn populated() -> EnablementGraph {
        let mut g = graph();
        g.set_cluster_route(cluster(1), RouteTemplate("/a".into()));
        g.on_build_change("v1");
        for i in 0..3 {
            let now = t0() + Duration::seconds(i);
            g.observe_transition(&obs(act(1), cluster(1), cluster(2), &[hash(7), hash(8)], now));
        }
        let mut o = obs(
            act(2),
            cluster(2),
            cluster(2),
            &[hash(9)],
            t0() + Duration::seconds(10),
        );
        o.latency_ms = 700;
        o.confounders.polling = 1;
        g.observe_transition(&o);
        g.set_action_risk(act(2), 0.25);
        g
    }

    #[test]
    fn dump_load_round_trip_through_edge_records() {
        let g = populated();
        let records = g.dump();
        // Two identity edges at cluster 1, one at cluster 2; the transition edge is not an element edge.
        assert_eq!(records.len(), 3);
        let mut h = EnablementGraph::new(g.run());
        assert_eq!(h.load(records.clone()), 3);
        assert_eq!(h.dump(), records);
        for r in &records {
            let a = g.edge(r.id).unwrap();
            let b = h.edge(r.id).unwrap();
            assert_eq!(
                (a.support, a.weak_support, a.failures),
                (b.support, b.weak_support, b.failures)
            );
            assert_eq!(a.p50_latency_ms, b.p50_latency_ms);
            assert!((a.p_success(t0()) - b.p_success(t0())).abs() < 1e-12);
        }
    }

    #[test]
    fn load_maps_missing_cluster_to_principal_global_and_skips_other_runs() {
        let g = populated();
        let mut recs = g.dump();
        recs[0].context_cluster = None;
        let mut foreign = recs[1].clone();
        foreign.run = CrawlRunId(uuid::Uuid::from_u128(1));
        recs.push(foreign);
        let mut h = EnablementGraph::new(g.run());
        assert_eq!(h.load(recs.clone()), 3);
        assert_eq!(h.edges_in(&EdgeContext::PrincipalGlobal).count(), 1);
        // Global edges apply from any cluster.
        assert_eq!(h.applicable_edges(cluster(99)).len(), 1);
    }

    #[test]
    fn route_edges_are_rebuilt_after_load_by_generalize_all() {
        let mut g = graph();
        let route = RouteTemplate("/r".into());
        for c in 1..=3u128 {
            g.set_cluster_route(cluster(c), route.clone());
            for i in 0..2 {
                g.observe_transition(&obs(
                    act(1),
                    cluster(c),
                    cluster(c),
                    &[hash(7)],
                    t0() + Duration::seconds(i),
                ));
            }
        }
        assert_eq!(g.edges_in(&EdgeContext::RouteTemplate(route.clone())).count(), 1);
        let mut h = EnablementGraph::new(g.run());
        h.load(g.dump());
        assert_eq!(h.edges_in(&EdgeContext::RouteTemplate(route.clone())).count(), 0);
        for c in 1..=3u128 {
            h.set_cluster_route(cluster(c), route.clone());
        }
        assert_eq!(h.generalize_all(t0() + Duration::seconds(2)).len(), 1);
        assert_eq!(h.edges_in(&EdgeContext::RouteTemplate(route)).count(), 1);
    }

    #[test]
    fn snapshot_is_lossless_including_transition_edges() {
        let mut g = populated();
        let tgt = hash(50);
        for _ in 0..4 {
            g.record_episode(tgt, [act(1), act(2)].into(), true);
        }
        for a in [vec![act(1)], vec![act(2)], vec![]] {
            g.record_episode(tgt, a.into_iter().collect(), false);
        }
        assert_eq!(g.mine_hyperedges(tgt).len(), 1);
        let snap = g.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: GraphSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
        let h = EnablementGraph::from_snapshot(back, GraphParams::default());
        assert_eq!(h.snapshot(), snap);
        assert!(h.edges().any(|e| matches!(e.target, EdgeTarget::Cluster(_))));
        assert_eq!(h.hyperedges().for_target(&tgt).len(), 1);
    }

    #[test]
    fn iteration_order_is_deterministic() {
        let a = populated();
        let b = populated();
        let ids_a: Vec<_> = a.edges().map(|e| e.id).collect();
        let ids_b: Vec<_> = b.edges().map(|e| e.id).collect();
        assert_eq!(ids_a, ids_b);
    }
}
