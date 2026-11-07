//! Path search over state clusters.
//!
//! Dijkstra over clusters with non-negative [`EnablementEdge::edge_cost`],
//! extended into a label-setting search so the hop limit, the reliability
//! floor and hyperedge preconditions are honoured exactly: a label is
//! `(cost, reliability, hops, hyperedge-relevant actions)` at a cluster and is
//! discarded only when another label at that cluster is no worse on all four.
//! Ties break on `(cost, hops, edge ids along the path)`, so the result is
//! deterministic.
//!
//! Only **path-safe** steps are admitted: edge `risk == 0` and the caller's
//! `is_path_safe` accepts the action. From any cluster, caller-supplied
//! `Navigate(route)` reset steps let a path restart from a known route.

use crate::context::EnablementGraph;
use crate::edge::{CostParams, EdgeContext, EdgeTarget, EnablementEdge};
use crate::hyperedge::Hyperedge;
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::{ActionContextId, EdgeId, RouteTemplate, StateClusterId, Timestamp};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use uuid::Uuid;

/// What the search is trying to achieve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathGoal {
    /// Make a control with this identity visible: any reachable cluster whose
    /// visible set contains it, a step whose edge reveals it, or all sources of
    /// a hyperedge for it performed along the path.
    RevealIdentity(ElementIdentityHash),
    /// Arrive in this cluster.
    ReachCluster(StateClusterId),
}

/// A known route a path may reset to with a `Navigate` action.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct KnownRoute {
    /// Route template the navigation loads.
    pub route: RouteTemplate,
    /// The navigation action (checked with `is_path_safe`).
    pub action: ActionContextId,
    /// Cluster the navigation lands in.
    pub landing: StateClusterId,
    /// Edge-cost-equivalent: `-ln p_nav + λ_lat·latency` (caller-computed).
    pub cost: f64,
    /// Probability the navigation lands as expected, in `(0, 1]`.
    pub p_success: f64,
}

/// Search limits and caller-supplied safety / reset inputs.
#[derive(Clone, Copy)]
pub struct SearchParams<'a> {
    /// Maximum number of steps in a plan.
    pub max_hops: usize,
    /// Minimum product of step success probabilities.
    pub min_reliability: f64,
    /// Time at which edge probabilities and costs are evaluated.
    pub now: Timestamp,
    /// Weights of the per-edge cost function.
    pub cost: CostParams,
    /// Cap on label expansions.
    pub max_expansions: usize,
    /// Kernel-side check: only reveal, navigation and reversible actions.
    pub is_path_safe: &'a dyn Fn(ActionContextId) -> bool,
    /// Routes a path may reset to with a `Navigate` step.
    pub known_routes: &'a [KnownRoute],
    /// Can a route-template edge's source (an action family, the generalization) be
    /// performed on the current page? Applied to route-template edges leaving the start
    /// cluster only (later steps run on pages not observed yet); `None` accepts every one.
    pub resolvable: Option<&'a dyn Fn(ActionContextId) -> bool>,
}

impl<'a> SearchParams<'a> {
    /// Defaults: 8 hops, reliability ≥ 0.25, 5000 expansions, no reset routes.
    #[must_use]
    pub fn new(now: Timestamp, is_path_safe: &'a dyn Fn(ActionContextId) -> bool) -> Self {
        Self {
            max_hops: 8,
            min_reliability: 0.25,
            now,
            cost: CostParams::default(),
            max_expansions: 5000,
            is_path_safe,
            known_routes: &[],
            resolvable: None,
        }
    }

    /// Only use a route-template edge from the start cluster when its source resolves on the
    /// current page.
    #[must_use]
    pub fn with_resolvable(mut self, resolvable: &'a dyn Fn(ActionContextId) -> bool) -> Self {
        self.resolvable = Some(resolvable);
        self
    }

    /// Supply the routes a path may reset to.
    #[must_use]
    pub fn with_known_routes(mut self, routes: &'a [KnownRoute]) -> Self {
        self.known_routes = routes;
        self
    }
}

impl std::fmt::Debug for SearchParams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchParams")
            .field("max_hops", &self.max_hops)
            .field("min_reliability", &self.min_reliability)
            .field("now", &self.now)
            .field("max_expansions", &self.max_expansions)
            .field("known_routes", &self.known_routes.len())
            .finish_non_exhaustive()
    }
}

/// One step of a plan.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PathStep {
    /// Graph edge traversed; for `Navigate` resets, a deterministic synthetic id.
    pub edge_id: EdgeId,
    /// The action the step performs.
    pub source_action: ActionContextId,
    /// What the step is expected to reveal or reach.
    pub expected_target: EdgeTarget,
    /// `Some(route)` for a `Navigate(route)` reset step (no graph edge behind it).
    pub navigate: Option<RouteTemplate>,
}

/// A path from the start cluster to the goal.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PathPlan {
    /// Steps in execution order; empty when the goal already holds at the start.
    pub steps: Vec<PathStep>,
    /// Sum of step costs.
    pub expected_cost: f64,
    /// Product of step success probabilities.
    pub reliability: f64,
}

#[derive(Clone)]
struct Label {
    cost: f64,
    hops: usize,
    rel: f64,
    cluster: StateClusterId,
    done: bool,
    steps: Vec<PathStep>,
    /// Actions on the path that occur in a goal hyperedge.
    relevant: BTreeSet<ActionContextId>,
}

impl Label {
    fn key_cmp(&self, other: &Self) -> Ordering {
        self.cost
            .total_cmp(&other.cost)
            .then(self.hops.cmp(&other.hops))
            .then_with(|| {
                self.steps
                    .iter()
                    .map(|s| s.edge_id)
                    .cmp(other.steps.iter().map(|s| s.edge_id))
            })
    }
}

struct Entry(Label);

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.0.key_cmp(&other.0) == Ordering::Equal
    }
}
impl Eq for Entry {}
impl PartialOrd for Entry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Entry {
    /// Reversed: `BinaryHeap` pops the greatest, we want the smallest key.
    fn cmp(&self, other: &Self) -> Ordering {
        other.0.key_cmp(&self.0)
    }
}

struct Settled {
    cost: f64,
    rel: f64,
    hops: usize,
    relevant: BTreeSet<ActionContextId>,
}

impl Settled {
    fn dominates(&self, l: &Label) -> bool {
        self.cost <= l.cost
            && self.rel >= l.rel
            && self.hops <= l.hops
            && self.relevant.is_superset(&l.relevant)
    }
}

/// Synthetic, deterministic id for a `Navigate` reset step.
fn nav_edge_id(kr: &KnownRoute) -> EdgeId {
    let mut b = Vec::with_capacity(48);
    b.extend_from_slice(&kr.action.0);
    b.extend_from_slice(kr.landing.0.as_bytes());
    b.extend_from_slice(kr.route.0.as_bytes());
    EdgeId(Uuid::from_bytes(
        Digest::of("crawlx/graph/nav-step/v1", &b).truncate16(),
    ))
}

/// Cheapest path-safe plan from `from` to `goal`, or `None` when none exists
/// within `max_hops`, `min_reliability` and `max_expansions`. A goal already
/// satisfied at `from` yields an empty plan.
#[must_use]
pub fn best_path(
    graph: &EnablementGraph,
    from: StateClusterId,
    goal: PathGoal,
    params: &SearchParams<'_>,
) -> Option<PathPlan> {
    let goal_hyper: &[Hyperedge] = match goal {
        PathGoal::RevealIdentity(h) => graph.hyperedges.for_target(&h),
        PathGoal::ReachCluster(_) => &[],
    };
    let relevant_universe: BTreeSet<ActionContextId> = goal_hyper
        .iter()
        .flat_map(|h| h.sources.iter().copied())
        .collect();

    let satisfied = |cluster: StateClusterId, relevant: &BTreeSet<ActionContextId>| -> bool {
        match goal {
            PathGoal::ReachCluster(c) => cluster == c,
            PathGoal::RevealIdentity(h) => {
                graph.visible_in(cluster).is_some_and(|v| v.contains(&h))
                    || goal_hyper.iter().any(|he| he.sources.is_subset(relevant))
            }
        }
    };
    let safe = |e: &EnablementEdge| e.risk <= 0.0 && (params.is_path_safe)(e.source);

    let start = Label {
        cost: 0.0,
        hops: 0,
        rel: 1.0,
        cluster: from,
        done: satisfied(from, &BTreeSet::new()),
        steps: Vec::new(),
        relevant: BTreeSet::new(),
    };
    let mut heap = BinaryHeap::new();
    heap.push(Entry(start));
    let mut settled: BTreeMap<StateClusterId, Vec<Settled>> = BTreeMap::new();
    let mut expansions = 0usize;

    while let Some(Entry(label)) = heap.pop() {
        if label.done {
            return Some(PathPlan {
                steps: label.steps,
                expected_cost: label.cost,
                reliability: label.rel,
            });
        }
        let bucket = settled.entry(label.cluster).or_default();
        if bucket.iter().any(|s| s.dominates(&label)) {
            continue;
        }
        bucket.push(Settled {
            cost: label.cost,
            rel: label.rel,
            hops: label.hops,
            relevant: label.relevant.clone(),
        });
        if label.hops >= params.max_hops {
            continue;
        }
        expansions += 1;
        if expansions > params.max_expansions {
            return None;
        }

        // Extend `label` by one step; pushes the child when feasible.
        let mut push = |step: PathStep, p: f64, step_cost: f64, to: StateClusterId, terminal: bool| {
            let rel = label.rel * p;
            if rel < params.min_reliability {
                return;
            }
            let mut relevant = label.relevant.clone();
            if relevant_universe.contains(&step.source_action) {
                relevant.insert(step.source_action);
            }
            let done = terminal || satisfied(to, &relevant);
            let mut steps = label.steps.clone();
            steps.push(step);
            heap.push(Entry(Label {
                cost: label.cost + step_cost,
                hops: label.hops + 1,
                rel,
                cluster: to,
                done,
                steps,
                relevant,
            }));
        };

        for e in graph.applicable_edges(label.cluster) {
            if !safe(e) {
                continue;
            }
            if label.hops == 0
                && matches!(e.context, EdgeContext::RouteTemplate(_))
                && params.resolvable.is_some_and(|r| !r(e.source))
            {
                continue;
            }
            let p = e.p_success(params.now);
            let c = e.edge_cost(params.now, &params.cost);
            let step = PathStep {
                edge_id: e.id,
                source_action: e.source,
                expected_target: e.target,
                navigate: None,
            };
            match e.target {
                EdgeTarget::Cluster(to) => {
                    if to != label.cluster {
                        push(step, p, c, to, false);
                    }
                }
                EdgeTarget::Identity(h) => {
                    // Equivalent to `sources ⊆ relevant ∪ {e.source}`: every goal
                    // hyperedge source is in `relevant_universe` by construction.
                    let terminal = matches!(goal, PathGoal::RevealIdentity(g) if g == h)
                        && (goal_hyper.is_empty()
                            || goal_hyper.iter().any(|he| {
                                he.sources
                                    .iter()
                                    .all(|s| *s == e.source || label.relevant.contains(s))
                            }));
                    // In-place steps only matter as hyperedge sources.
                    let useful_source =
                        relevant_universe.contains(&e.source) && !label.relevant.contains(&e.source);
                    if terminal || useful_source {
                        push(step, p, c, label.cluster, terminal);
                    }
                }
            }
        }
        for kr in params.known_routes {
            if kr.landing == label.cluster || !(params.is_path_safe)(kr.action) {
                continue;
            }
            let step = PathStep {
                edge_id: nav_edge_id(kr),
                source_action: kr.action,
                expected_target: EdgeTarget::Cluster(kr.landing),
                navigate: Some(kr.route.clone()),
            };
            push(
                step,
                kr.p_success.clamp(f64::MIN_POSITIVE, 1.0),
                kr.cost.max(0.0),
                kr.landing,
                false,
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::edge::EdgeContext;
    use crate::testutil::{act, cluster, graph, hash, obs, t0};
    use chrono::Duration;

    fn safe(_: ActionContextId) -> bool {
        true
    }

    /// `n` strong observations of `a: from -> to`.
    fn link(g: &mut EnablementGraph, a: u8, from: u128, to: u128, n: i64) {
        for i in 0..n {
            g.observe_transition(&obs(
                act(a),
                cluster(from),
                cluster(to),
                &[],
                t0() + Duration::seconds(i),
            ));
        }
    }

    fn fail_edge(g: &mut EnablementGraph, a: u8, from: u128, to: u128, times: i64) {
        let id = g
            .find(
                &EdgeContext::Cluster(cluster(from)),
                act(a),
                &EdgeTarget::Cluster(cluster(to)),
            )
            .unwrap()
            .id;
        for i in 0..times {
            g.record_replay(id, false, t0() + Duration::seconds(i)).unwrap();
        }
    }

    fn now() -> Timestamp {
        t0() + Duration::seconds(60)
    }

    #[test]
    fn picks_reliable_longer_path_over_unreliable_short_one() {
        let mut g = graph();
        // Short: c0 -> c3 directly, p = 2/5 after one success and two failures.
        link(&mut g, 1, 0, 3, 1);
        fail_edge(&mut g, 1, 0, 3, 2);
        // Long: c0 -> c1 -> c2 -> c3, each p = 10/11.
        link(&mut g, 2, 0, 1, 9);
        link(&mut g, 3, 1, 2, 9);
        link(&mut g, 4, 2, 3, 9);
        let sf = safe;
        let plan = best_path(
            &g,
            cluster(0),
            PathGoal::ReachCluster(cluster(3)),
            &SearchParams::new(now(), &sf),
        )
        .unwrap();
        let acts: Vec<_> = plan.steps.iter().map(|s| s.source_action).collect();
        assert_eq!(acts, vec![act(2), act(3), act(4)]);
        assert!(plan.reliability > 0.7);
        assert!(plan.expected_cost > 0.0);
    }

    #[test]
    fn unsafe_steps_are_never_used() {
        let mut g = graph();
        link(&mut g, 1, 0, 3, 9); // cheap direct edge
        link(&mut g, 2, 0, 1, 2);
        link(&mut g, 3, 1, 3, 2);
        let not_one = |a: ActionContextId| a != act(1);
        let p = SearchParams::new(now(), &not_one);
        let plan = best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(3)), &p).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert!(plan.steps.iter().all(|s| s.source_action != act(1)));

        // Risky (non-zero risk) edges are excluded even if the caller allows them.
        g.set_action_risk(act(2), 0.5);
        let sf = safe;
        let plan = best_path(
            &g,
            cluster(0),
            PathGoal::ReachCluster(cluster(3)),
            &SearchParams::new(now(), &sf),
        )
        .unwrap();
        assert_eq!(plan.steps.len(), 1);
        g.set_action_risk(act(1), 0.5);
        assert!(best_path(
            &g,
            cluster(0),
            PathGoal::ReachCluster(cluster(3)),
            &SearchParams::new(now(), &sf)
        )
        .is_none());
    }

    #[test]
    fn hop_cutoff() {
        let mut g = graph();
        for i in 0..4u8 {
            link(&mut g, i + 1, u128::from(i), u128::from(i) + 1, 9);
        }
        let sf = safe;
        let mut p = SearchParams::new(now(), &sf);
        p.max_hops = 4;
        assert_eq!(
            best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(4)), &p)
                .unwrap()
                .steps
                .len(),
            4
        );
        p.max_hops = 3;
        assert!(best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(4)), &p).is_none());
    }

    #[test]
    fn reliability_cutoff() {
        // Each edge p = 2/3.
        let chain = |len: u8| {
            let mut g = graph();
            for i in 0..len {
                link(&mut g, i + 1, u128::from(i), u128::from(i) + 1, 1);
            }
            g
        };
        let sf = safe;
        let p = SearchParams::new(now(), &sf); // floor 0.25
        let ok = best_path(&chain(3), cluster(0), PathGoal::ReachCluster(cluster(3)), &p).unwrap();
        assert!((ok.reliability - (2.0_f64 / 3.0).powi(3)).abs() < 1e-3);
        assert!(best_path(&chain(4), cluster(0), PathGoal::ReachCluster(cluster(4)), &p).is_none());
        let mut lax = p;
        lax.min_reliability = 0.1;
        assert!(best_path(&chain(4), cluster(0), PathGoal::ReachCluster(cluster(4)), &lax).is_some());
    }

    #[test]
    fn reliability_floor_can_force_a_costlier_path() {
        let mut g = graph();
        // Path B: one very reliable (p = 19/20) but slow, unverified edge c0 -> c9.
        for i in 0..18 {
            let mut o = obs(act(2), cluster(0), cluster(9), &[], t0() + Duration::seconds(i));
            o.latency_ms = 5000;
            g.observe_transition(&o);
        }
        g.on_build_change("B"); // +0.5 unverified
                                // Path A: one edge with p = 1/2, verified under B.
        link(&mut g, 1, 0, 9, 1);
        fail_edge(&mut g, 1, 0, 9, 1);
        let sf = safe;
        let mut p = SearchParams::new(now(), &sf);
        p.min_reliability = 0.0;
        let cheap = best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(9)), &p).unwrap();
        assert_eq!(cheap.steps[0].source_action, act(1));
        p.min_reliability = 0.6;
        let reliable = best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(9)), &p).unwrap();
        assert_eq!(reliable.steps[0].source_action, act(2));
        assert!(reliable.expected_cost > cheap.expected_cost);
        assert!(reliable.reliability >= 0.6);
    }

    #[test]
    fn ties_break_on_edge_id_deterministically() {
        let mut g = graph();
        link(&mut g, 1, 0, 1, 3);
        link(&mut g, 2, 0, 1, 3);
        link(&mut g, 3, 0, 1, 3);
        let sf = safe;
        let want = g.edges().map(|e| e.id).min().unwrap();
        for _ in 0..5 {
            let plan = best_path(
                &g,
                cluster(0),
                PathGoal::ReachCluster(cluster(1)),
                &SearchParams::new(now(), &sf),
            )
            .unwrap();
            assert_eq!(plan.steps[0].edge_id, want);
        }
    }

    #[test]
    fn fewer_hops_win_cost_ties() {
        // Identical total cost cannot be built from different hop counts with
        // real edges, so check the label ordering directly.
        let mk = |hops: usize, ids: &[u128]| Label {
            cost: 1.0,
            hops,
            rel: 1.0,
            cluster: cluster(0),
            done: false,
            steps: ids
                .iter()
                .map(|i| PathStep {
                    edge_id: EdgeId(Uuid::from_u128(*i)),
                    source_action: act(0),
                    expected_target: EdgeTarget::Cluster(cluster(0)),
                    navigate: None,
                })
                .collect(),
            relevant: BTreeSet::new(),
        };
        assert_eq!(mk(1, &[9]).key_cmp(&mk(2, &[1, 2])), Ordering::Less);
        assert_eq!(mk(1, &[1]).key_cmp(&mk(1, &[2])), Ordering::Less);
    }

    #[test]
    fn reveal_identity_via_visible_set_and_identity_edge() {
        let mut g = graph();
        // c0 -a1-> c1, and T becomes visible at c1.
        g.observe_transition(&obs(act(1), cluster(0), cluster(1), &[hash(5)], t0()));
        let sf = safe;
        let p = SearchParams::new(now(), &sf);
        let plan = best_path(&g, cluster(0), PathGoal::RevealIdentity(hash(5)), &p).unwrap();
        // The in-place identity edge a1 -> T at c0 is the one-step terminal.
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].expected_target, EdgeTarget::Identity(hash(5)));
        // Already visible at the start: empty plan.
        let plan = best_path(&g, cluster(1), PathGoal::RevealIdentity(hash(5)), &p).unwrap();
        assert!(plan.steps.is_empty());
        assert!((plan.reliability - 1.0).abs() < f64::EPSILON);
        assert!(best_path(&g, cluster(0), PathGoal::RevealIdentity(hash(6)), &p).is_none());
    }

    #[test]
    fn route_template_edges_are_usable_from_unseen_clusters() {
        let mut g = graph();
        let route = crawlx_core::RouteTemplate("/r".into());
        for c in 1..=4 {
            g.set_cluster_route(cluster(c), route.clone());
        }
        for c in 1..=3 {
            link(&mut g, 1, c, 100, 2);
        }
        let sf = safe;
        let plan = best_path(
            &g,
            cluster(4),
            PathGoal::ReachCluster(cluster(100)),
            &SearchParams::new(now(), &sf),
        )
        .unwrap();
        assert_eq!(plan.steps.len(), 1);
        let e = g.edge(plan.steps[0].edge_id).unwrap();
        assert!(matches!(e.context, EdgeContext::RouteTemplate(_)));
    }

    #[test]
    fn a_route_edge_from_the_start_needs_a_resolvable_source() {
        let mut g = graph();
        let route = crawlx_core::RouteTemplate("/r".into());
        for c in 1..=4 {
            g.set_cluster_route(cluster(c), route.clone());
        }
        for c in 1..=3 {
            link(&mut g, 1, c, 100, 2);
        }
        let sf = safe;
        let goal = PathGoal::ReachCluster(cluster(100));
        let absent = |_: ActionContextId| false;
        let params = SearchParams::new(now(), &sf).with_resolvable(&absent);
        assert!(best_path(&g, cluster(4), goal, &params).is_none());
        let present = |a: ActionContextId| a == act(1);
        let params = SearchParams::new(now(), &sf).with_resolvable(&present);
        let plan = best_path(&g, cluster(4), goal, &params).unwrap();
        assert_eq!(plan.steps[0].source_action, act(1));
        // exact edges never consult the predicate
        let plan = best_path(
            &g,
            cluster(1),
            goal,
            &SearchParams::new(now(), &sf).with_resolvable(&absent),
        )
        .unwrap();
        assert!(matches!(
            g.edge(plan.steps[0].edge_id).unwrap().context,
            EdgeContext::Cluster(_)
        ));
    }

    #[test]
    fn navigate_reset_edges() {
        let mut g = graph();
        link(&mut g, 1, 9, 5, 5); // from the known route's landing cluster to the goal
        let routes = [KnownRoute {
            route: crawlx_core::RouteTemplate("/home".into()),
            action: act(77),
            landing: cluster(9),
            cost: 0.3,
            p_success: 0.95,
        }];
        let sf = safe;
        let p = SearchParams::new(now(), &sf).with_known_routes(&routes);
        let plan = best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(5)), &p).unwrap();
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.steps[0].navigate.as_ref().unwrap().0, "/home");
        assert_eq!(plan.steps[0].source_action, act(77));
        assert!(plan.steps[1].navigate.is_none());
        assert!(plan.expected_cost > 0.3);
        // Without the route list, or if the navigation is unsafe, no path.
        assert!(best_path(
            &g,
            cluster(0),
            PathGoal::ReachCluster(cluster(5)),
            &SearchParams::new(now(), &sf)
        )
        .is_none());
        let no77 = |a: ActionContextId| a != act(77);
        let p = SearchParams::new(now(), &no77).with_known_routes(&routes);
        assert!(best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(5)), &p).is_none());
    }

    #[test]
    fn hyperedge_satisfied_when_all_sources_on_path() {
        let mut g = graph();
        let t = hash(50);
        link(&mut g, 1, 0, 1, 9); // A: c0 -> c1
        link(&mut g, 2, 1, 2, 9); // B: c1 -> c2
        let sf = safe;
        let p = SearchParams::new(now(), &sf);
        // Nothing reveals T yet.
        assert!(best_path(&g, cluster(0), PathGoal::RevealIdentity(t), &p).is_none());
        for _ in 0..4 {
            g.record_episode(t, [act(1), act(2), act(9)].into(), true);
        }
        for a in [
            vec![act(1), act(9)],
            vec![act(2), act(9)],
            vec![act(1)],
            vec![act(2)],
            vec![act(9)],
        ] {
            g.record_episode(t, a.into_iter().collect(), false);
        }
        let mined = g.mine_hyperedges(t);
        assert_eq!(mined.len(), 1);
        assert_eq!(mined[0].sources, [act(1), act(2)].into());
        let plan = best_path(&g, cluster(0), PathGoal::RevealIdentity(t), &p).unwrap();
        let acts: Vec<_> = plan.steps.iter().map(|s| s.source_action).collect();
        assert_eq!(acts, vec![act(1), act(2)]);
        // Unsafe source -> hyperedge cannot be satisfied.
        let no2 = |a: ActionContextId| a != act(2);
        assert!(best_path(
            &g,
            cluster(0),
            PathGoal::RevealIdentity(t),
            &SearchParams::new(now(), &no2)
        )
        .is_none());
    }

    #[test]
    fn hyperedge_gates_a_direct_reveal_edge() {
        let mut g = graph();
        let t = hash(50);
        // B reveals T at c0 (seen once, after A had happened) and A moves c0 -> c1.
        g.observe_transition(&obs(act(2), cluster(0), cluster(0), &[t], t0()));
        link(&mut g, 1, 0, 1, 9);
        for _ in 0..4 {
            g.record_episode(t, [act(1), act(2)].into(), true);
        }
        for a in [vec![act(1)], vec![act(2)], vec![]] {
            g.record_episode(t, a.into_iter().collect(), false);
        }
        assert_eq!(g.mine_hyperedges(t).len(), 1);
        let sf = safe;
        let plan = best_path(
            &g,
            cluster(0),
            PathGoal::RevealIdentity(t),
            &SearchParams::new(now(), &sf),
        )
        .unwrap();
        // B alone is not enough: A must also be on the path.
        let acts: BTreeSet<_> = plan.steps.iter().map(|s| s.source_action).collect();
        assert_eq!(acts, [act(1), act(2)].into());
    }
}
