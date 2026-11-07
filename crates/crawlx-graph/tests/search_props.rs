//! Path cost: `best_path` (label-setting Dijkstra over
//! `edge_cost`) agrees with exhaustive search on random graphs of up to 8
//! clusters and 20 edges.
//!
//! The exhaustive side enumerates every simple path from the start within the
//! hop limit and the reliability floor, over the same per-cluster adjacency
//! (`applicable_edges`: exact, route-template and principal-global edges) and
//! the same safety filter the search uses. Cycles never help: every edge cost
//! is strictly positive (`p < 1`) and every step lowers the reliability.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, TimeZone, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::{ActionContextId, CrawlRunId, RouteTemplate, StateClusterId, Timestamp};
use crawlx_graph::{
    best_path, CostParams, EdgeContext, EdgeTarget, EnablementEdge, EnablementGraph, GraphSnapshot,
    HyperedgeMiner, PathGoal, PathPlan, SearchParams,
};
use proptest::collection::vec;
use proptest::prelude::*;
use std::collections::BTreeSet;
use uuid::Uuid;

const MAX_CLUSTERS: usize = 8;
const MAX_EDGES: usize = 20;
const ACTIONS: u8 = 5;
const IDENTITIES: u8 = 3;

fn t0() -> Timestamp {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}
fn act(n: u8) -> ActionContextId {
    ActionContextId([n; 16])
}
fn hash(n: u8) -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("search-props", &[n]))
}
fn cluster(n: usize) -> StateClusterId {
    StateClusterId(Uuid::from_u128(u128::try_from(n).unwrap() + 1))
}
fn route(n: usize) -> RouteTemplate {
    RouteTemplate(format!("/route/{n}"))
}

/// One generated edge.
#[derive(Clone, Debug)]
struct EdgeSpec {
    from: usize,
    to: usize,
    action: u8,
    /// `Some(h)`: in-place reveal of identity `h`; `None`: transition to `to`.
    identity: Option<u8>,
    support: u32,
    weak: u32,
    failures: u32,
    latency_ms: u32,
    risky: bool,
    age_days: i64,
    /// Context: `RouteTemplate(route of from)` instead of the exact cluster.
    route_level: bool,
}

/// A generated graph plus a query.
#[derive(Clone, Debug)]
struct Case {
    clusters: usize,
    edges: Vec<EdgeSpec>,
    /// Identities known visible per cluster.
    visible: Vec<Option<u8>>,
    unsafe_action: Option<u8>,
    start: usize,
    goal_cluster: usize,
    goal_identity: Option<u8>,
    max_hops: usize,
    min_reliability: f64,
}

fn edge_spec(clusters: usize) -> impl Strategy<Value = EdgeSpec> {
    (
        0..clusters,
        0..clusters,
        0..ACTIONS,
        prop::option::weighted(0.3, 0..IDENTITIES),
        0..20u32,
        0..4u32,
        0..6u32,
        0..7000u32,
        prop::bool::weighted(0.1),
        0..40i64,
        prop::bool::weighted(0.2),
    )
        .prop_map(
            |(
                from,
                to,
                action,
                identity,
                support,
                weak,
                failures,
                latency_ms,
                risky,
                age_days,
                route_level,
            )| {
                EdgeSpec {
                    from,
                    to,
                    action,
                    identity,
                    support,
                    weak,
                    failures,
                    latency_ms,
                    risky,
                    age_days,
                    route_level,
                }
            },
        )
}

fn case() -> impl Strategy<Value = Case> {
    (2..=MAX_CLUSTERS).prop_flat_map(|clusters| {
        (
            Just(clusters),
            vec(edge_spec(clusters), 0..=MAX_EDGES),
            vec(prop::option::weighted(0.3, 0..IDENTITIES), clusters),
            prop::option::weighted(0.3, 0..ACTIONS),
            0..clusters,
            0..clusters,
            prop::option::weighted(0.4, 0..IDENTITIES),
            1..=8usize,
            prop_oneof![Just(0.0), Just(0.25), Just(0.6)],
        )
            .prop_map(
                |(
                    clusters,
                    edges,
                    visible,
                    unsafe_action,
                    start,
                    goal_cluster,
                    goal_identity,
                    max_hops,
                    min_reliability,
                )| Case {
                    clusters,
                    edges,
                    visible,
                    unsafe_action,
                    start,
                    goal_cluster,
                    goal_identity,
                    max_hops,
                    min_reliability,
                },
            )
    })
}

fn now() -> Timestamp {
    t0() + Duration::days(60)
}

fn build(case: &Case) -> EnablementGraph {
    let mut edges = Vec::with_capacity(case.edges.len());
    for s in &case.edges {
        let target = match s.identity {
            Some(h) => EdgeTarget::Identity(hash(h)),
            None => EdgeTarget::Cluster(cluster(s.to)),
        };
        let context = if s.route_level {
            EdgeContext::RouteTemplate(route(s.from % 2))
        } else {
            EdgeContext::Cluster(cluster(s.from))
        };
        let seen = now() - Duration::days(s.age_days);
        let mut e = EnablementEdge::new(act(s.action), context, target, seen);
        e.support = s.support;
        e.weak_support = s.weak;
        e.failures = s.failures;
        e.p50_latency_ms = s.latency_ms;
        e.risk = if s.risky { 0.5 } else { 0.0 };
        e.first_seen = seen - Duration::days(1);
        e.last_seen = seen;
        edges.push(e);
    }
    // Later specs with the same `(context, source, target)` replace earlier ones,
    // exactly as `from_snapshot` inserts them.
    let snapshot = GraphSnapshot {
        run: CrawlRunId(Uuid::from_u128(0xBEEF)),
        edges,
        cluster_routes: (0..case.clusters).map(|c| (cluster(c), route(c % 2))).collect(),
        visible: case
            .visible
            .iter()
            .enumerate()
            .filter_map(|(c, v)| v.map(|h| (cluster(c), BTreeSet::from([hash(h)]))))
            .collect(),
        action_risk: Vec::new(),
        current_build: None,
        blocked_generalizations: BTreeSet::new(),
        hyperedges: HyperedgeMiner::default(),
        families: Vec::new(),
    };
    EnablementGraph::from_snapshot(snapshot, crawlx_graph::GraphParams::default())
}

fn goal(case: &Case) -> PathGoal {
    match case.goal_identity {
        Some(h) => PathGoal::RevealIdentity(hash(h)),
        None => PathGoal::ReachCluster(cluster(case.goal_cluster)),
    }
}

/// Does the goal already hold at `at`?
fn satisfied(graph: &EnablementGraph, goal: PathGoal, at: StateClusterId) -> bool {
    match goal {
        PathGoal::ReachCluster(c) => at == c,
        PathGoal::RevealIdentity(h) => graph.visible_in(at).is_some_and(|v| v.contains(&h)),
    }
}

/// Minimum cost over every simple path (no cluster revisited) of at most
/// `max_hops` steps with reliability at least `min_reliability`, or `None`.
fn exhaustive(graph: &EnablementGraph, case: &Case, params: &SearchParams<'_>) -> Option<f64> {
    let goal = goal(case);
    let start = cluster(case.start);
    if satisfied(graph, goal, start) {
        return Some(0.0);
    }
    let mut best: Option<f64> = None;
    let mut seen = BTreeSet::from([start]);
    dfs(graph, goal, params, start, 0, 0.0, 1.0, &mut seen, &mut best);
    best
}

#[allow(clippy::too_many_arguments)]
fn dfs(
    graph: &EnablementGraph,
    goal: PathGoal,
    params: &SearchParams<'_>,
    at: StateClusterId,
    hops: usize,
    cost: f64,
    rel: f64,
    seen: &mut BTreeSet<StateClusterId>,
    best: &mut Option<f64>,
) {
    if hops >= params.max_hops {
        return;
    }
    for e in graph.applicable_edges(at) {
        if e.risk > 0.0 || !(params.is_path_safe)(e.source) {
            continue;
        }
        let rel = rel * e.p_success(params.now);
        if rel < params.min_reliability {
            continue;
        }
        let cost = cost + e.edge_cost(params.now, &params.cost);
        match e.target {
            EdgeTarget::Identity(h) => {
                if matches!(goal, PathGoal::RevealIdentity(g) if g == h) {
                    *best = Some(best.map_or(cost, |b| b.min(cost)));
                }
            }
            EdgeTarget::Cluster(to) => {
                if to == at || seen.contains(&to) {
                    continue;
                }
                if satisfied(graph, goal, to) {
                    *best = Some(best.map_or(cost, |b| b.min(cost)));
                    continue;
                }
                seen.insert(to);
                dfs(graph, goal, params, to, hops + 1, cost, rel, seen, best);
                seen.remove(&to);
            }
        }
    }
}

/// Every step's edge exists, applies at the cluster the step runs in, is
/// path-safe, costs a non-negative amount; the chain of clusters is
/// consistent; the plan's cost and reliability are the sums/products of its
/// steps and the goal holds at the end.
fn check_plan(graph: &EnablementGraph, case: &Case, params: &SearchParams<'_>, plan: &PathPlan) {
    let goal = goal(case);
    let mut at = cluster(case.start);
    let mut cost = 0.0;
    let mut rel = 1.0;
    let mut done = satisfied(graph, goal, at);
    assert!(plan.steps.len() <= params.max_hops, "{plan:?}");
    for step in &plan.steps {
        assert!(!done, "steps after the goal was reached: {plan:?}");
        assert!(step.navigate.is_none());
        let e = graph.edge(step.edge_id).expect("step edge exists");
        assert_eq!(e.source, step.source_action);
        assert_eq!(e.target, step.expected_target);
        assert!(
            e.risk <= 0.0 && (params.is_path_safe)(e.source),
            "unsafe step {step:?}"
        );
        assert!(
            graph.applicable_edges(at).iter().any(|a| a.id == e.id),
            "edge {:?} does not apply at {at:?}",
            e.id
        );
        let c = e.edge_cost(params.now, &params.cost);
        assert!(c >= 0.0 && c.is_finite(), "negative cost {c}");
        cost += c;
        rel *= e.p_success(params.now);
        match e.target {
            EdgeTarget::Cluster(to) => {
                assert_ne!(to, at, "self-loop step");
                at = to;
                done = satisfied(graph, goal, at);
            }
            EdgeTarget::Identity(h) => {
                assert!(matches!(goal, PathGoal::RevealIdentity(g) if g == h), "{step:?}");
                done = true;
            }
        }
    }
    assert!(done, "plan ends without reaching the goal: {plan:?}");
    assert!(
        (plan.expected_cost - cost).abs() < 1e-9,
        "{} vs {cost}",
        plan.expected_cost
    );
    assert!(
        (plan.reliability - rel).abs() < 1e-9,
        "{} vs {rel}",
        plan.reliability
    );
    assert!(plan.reliability >= params.min_reliability - 1e-12);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn best_path_matches_exhaustive_search_on_small_graphs(case in case()) {
        let graph = build(&case);
        let unsafe_action = case.unsafe_action.map(act);
        let safe = move |a: ActionContextId| Some(a) != unsafe_action;
        let mut params = SearchParams::new(now(), &safe);
        params.max_hops = case.max_hops;
        params.min_reliability = case.min_reliability;
        params.cost = CostParams::default();

        let want = exhaustive(&graph, &case, &params);
        let got = best_path(&graph, cluster(case.start), goal(&case), &params);
        match (want, got) {
            (None, None) => {}
            (Some(w), Some(plan)) => {
                check_plan(&graph, &case, &params, &plan);
                prop_assert!(
                    (plan.expected_cost - w).abs() < 1e-9,
                    "search cost {} vs exhaustive {w}: {plan:?}",
                    plan.expected_cost
                );
            }
            (Some(w), None) => prop_assert!(false, "search found no path, exhaustive found cost {w}"),
            (None, Some(plan)) => prop_assert!(false, "search found {plan:?}, exhaustive found none"),
        }
    }

    #[test]
    fn every_edge_cost_is_non_negative(case in case()) {
        let graph = build(&case);
        for e in graph.edges() {
            let p = e.p_success(now());
            prop_assert!(p > 0.0 && p < 1.0, "p = {p}");
            let c = e.edge_cost(now(), &CostParams::default());
            prop_assert!(c >= 0.0 && c.is_finite(), "cost = {c}");
        }
    }
}
