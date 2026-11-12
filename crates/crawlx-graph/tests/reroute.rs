//! Staleness test: after a build change the planned
//! route's reveal edge fails three traversals in a row, is retired, path search
//! routes around it through the second route, and a later identical
//! observation does not bring the retired route-template edge back
//! (`retired_route_edge_is_not_recreated` in `update.rs` covers the last rule
//! in isolation; this test runs it end to end through `ReplayValidator`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{Duration, TimeZone, Utc};
use crawlx_core::hash::Digest;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::{ActionContextId, CrawlRunId, RouteTemplate, StateClusterId, Timestamp, TrustLane};
use crawlx_graph::{
    best_path, Confounders, EdgeContext, EdgeTarget, EnablementGraph, PathGoal, ReplayValidator,
    SearchParams, StepOutcome, TransitionObservation,
};
use uuid::Uuid;

fn t0() -> Timestamp {
    Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap()
}
fn act(n: u8) -> ActionContextId {
    ActionContextId([n; 16])
}
fn cluster(n: u128) -> StateClusterId {
    StateClusterId(Uuid::from_u128(n + 1))
}
fn target() -> ElementIdentityHash {
    ElementIdentityHash(Digest::of("reroute/target", &[7]))
}
fn obs(
    source: ActionContextId,
    before: StateClusterId,
    after: StateClusterId,
    revealed: &[ElementIdentityHash],
    now: Timestamp,
) -> TransitionObservation {
    TransitionObservation {
        source,
        family: None,
        before_cluster: before,
        after_cluster: after,
        revealed: revealed.to_vec(),
        baseline_revealed: Vec::new(),
        confounders: Confounders::default(),
        latency_ms: Some(100),
        lane: TrustLane::TrustedUi,
        now,
    }
}

const START: u128 = 0;
/// Route 1 lands here; the cluster is on the `/menu` route and has no exact
/// edge of its own, so only the route-template edge applies.
const MENU_LANDING: u128 = 13;
/// Route 2 lands here.
const ALT: u128 = 2;
const NAV_MENU: u8 = 1;
const OPEN_MENU: u8 = 2;
const NAV_ALT: u8 = 3;
const OPEN_ALT: u8 = 4;

/// Two routes from `START` to the target: route 1 (`NAV_MENU` then the
/// generalized `OPEN_MENU` reveal on the `/menu` route) is the cheaper plan;
/// route 2 (`NAV_ALT` then a weakly supported `OPEN_ALT` reveal) is the fallback.
fn two_route_graph() -> EnablementGraph {
    let mut g = EnablementGraph::new(CrawlRunId(Uuid::from_u128(0xA11)));
    let route = RouteTemplate("/menu".into());
    for c in [MENU_LANDING, 21, 22, 23] {
        g.set_cluster_route(cluster(c), route.clone());
    }
    let mut t = t0();
    let mut tick = || {
        t += Duration::seconds(1);
        t
    };
    // Route 1, hop 1: strong navigation into the menu landing cluster.
    for _ in 0..9 {
        g.observe_transition(&obs(
            act(NAV_MENU),
            cluster(START),
            cluster(MENU_LANDING),
            &[],
            tick(),
        ));
    }
    // Route 1, hop 2: `OPEN_MENU` reveals the target in three sibling clusters
    // of the `/menu` route; this generalizes into a route-template edge.
    for c in [21, 22, 23] {
        for _ in 0..2 {
            g.observe_transition(&obs(act(OPEN_MENU), cluster(c), cluster(c), &[target()], tick()));
        }
    }
    // Route 2: strong navigation, then a single-observation reveal.
    for _ in 0..9 {
        g.observe_transition(&obs(act(NAV_ALT), cluster(START), cluster(ALT), &[], tick()));
    }
    g.observe_transition(&obs(
        act(OPEN_ALT),
        cluster(ALT),
        cluster(ALT),
        &[target()],
        tick(),
    ));
    g
}

fn route_edge_id(g: &EnablementGraph) -> Option<crawlx_core::EdgeId> {
    g.find(
        &EdgeContext::RouteTemplate(RouteTemplate("/menu".into())),
        act(OPEN_MENU),
        &EdgeTarget::Identity(target()),
    )
    .map(|e| e.id)
}

fn actions(plan: &crawlx_graph::PathPlan) -> Vec<ActionContextId> {
    plan.steps.iter().map(|s| s.source_action).collect()
}

#[test]
fn a_retired_edge_is_routed_around_and_never_recreated() {
    let mut g = two_route_graph();
    let route_edge = route_edge_id(&g).expect("the menu reveal generalized to the /menu route");
    let safe = |_: ActionContextId| true;
    let mut now = t0() + Duration::minutes(5);
    let params = |now| SearchParams::new(now, &safe);

    // The planned path takes route 1 through the route-template edge.
    let plan = best_path(
        &g,
        cluster(START),
        PathGoal::RevealIdentity(target()),
        &params(now),
    )
    .unwrap();
    assert_eq!(actions(&plan), vec![act(NAV_MENU), act(OPEN_MENU)]);
    assert_eq!(plan.steps[1].edge_id, route_edge);

    // The application ships a new build (the menu entry is gone): every edge is
    // unverified until replayed, the plan is unchanged.
    let marked = g.on_build_change("build-2");
    assert!(marked >= 4, "{marked} edges marked unverified");
    let plan = best_path(
        &g,
        cluster(START),
        PathGoal::RevealIdentity(target()),
        &params(now),
    )
    .unwrap();
    assert_eq!(actions(&plan), vec![act(NAV_MENU), act(OPEN_MENU)]);

    // Three traversals: the navigation succeeds, the menu reveal fails.
    let validator = ReplayValidator::new();
    for attempt in 0..3 {
        now += Duration::seconds(30);
        let plan = best_path(
            &g,
            cluster(START),
            PathGoal::RevealIdentity(target()),
            &params(now),
        )
        .unwrap();
        assert_eq!(
            plan.steps[1].edge_id, route_edge,
            "attempt {attempt} still plans route 1"
        );
        let report = validator
            .validate(&mut g, &plan, &[StepOutcome::ok(90), StepOutcome::failed()], now)
            .unwrap();
        assert_eq!(report.steps_ok, 1);
        assert_eq!(report.first_failure, Some(1));
        assert_eq!(report.stale_edges, vec![route_edge]);
        let e = g.edge(route_edge).unwrap();
        assert_eq!(e.consecutive_failures, attempt + 1);
        assert!(e.failures == attempt + 1);
        let retired = g.prune(now);
        if attempt < 2 {
            assert!(
                retired.is_empty(),
                "retired before the third failure: {retired:?}"
            );
        } else {
            assert_eq!(retired, vec![route_edge]);
        }
    }
    assert!(g.edge(route_edge).is_none(), "the failing edge is retired");
    // The navigation step was verified against the new build by its successes.
    let nav = g
        .find(
            &EdgeContext::Cluster(cluster(START)),
            act(NAV_MENU),
            &EdgeTarget::Cluster(cluster(MENU_LANDING)),
        )
        .unwrap();
    assert!(!nav.unverified);
    assert_eq!(nav.last_verified_build.as_deref(), Some("build-2"));

    // Search routes around it: route 2, and the retired edge appears nowhere.
    now += Duration::seconds(30);
    let plan = best_path(
        &g,
        cluster(START),
        PathGoal::RevealIdentity(target()),
        &params(now),
    )
    .unwrap();
    assert_eq!(actions(&plan), vec![act(NAV_ALT), act(OPEN_ALT)]);
    assert!(plan.steps.iter().all(|s| s.edge_id != route_edge));

    // A later identical observation of the menu reveal in one `/menu` cluster
    // credits that cluster's exact edge but does not recreate the retired
    // route-template edge, so the plan from `START` (whose landing cluster has
    // no exact edge) stays on route 2.
    now += Duration::seconds(30);
    let out = g.observe_transition(&obs(act(OPEN_MENU), cluster(21), cluster(21), &[target()], now));
    assert!(out.generalized.is_empty(), "{out:?}");
    assert!(
        route_edge_id(&g).is_none(),
        "the retired route edge was recreated"
    );
    let plan = best_path(
        &g,
        cluster(START),
        PathGoal::RevealIdentity(target()),
        &params(now),
    )
    .unwrap();
    assert_eq!(actions(&plan), vec![act(NAV_ALT), act(OPEN_ALT)]);
    assert!(plan.steps.iter().all(|s| s.edge_id != route_edge));
}

#[test]
fn without_a_second_route_the_search_reports_no_path_after_retirement() {
    let mut g = two_route_graph();
    let route_edge = route_edge_id(&g).unwrap();
    let alt = g
        .find(
            &EdgeContext::Cluster(cluster(ALT)),
            act(OPEN_ALT),
            &EdgeTarget::Identity(target()),
        )
        .unwrap()
        .id;
    let now = t0() + Duration::minutes(5);
    for k in 0..3 {
        g.record_replay(route_edge, false, now + Duration::seconds(k))
            .unwrap();
        g.record_replay(alt, false, now + Duration::seconds(k)).unwrap();
    }
    let mut retired = g.prune(now + Duration::seconds(5));
    retired.sort_unstable();
    let mut want = vec![route_edge, alt];
    want.sort_unstable();
    assert_eq!(retired, want);
    let safe = |_: ActionContextId| true;
    assert!(best_path(
        &g,
        cluster(START),
        PathGoal::RevealIdentity(target()),
        &SearchParams::new(now + Duration::seconds(10), &safe)
    )
    .is_none());
}
