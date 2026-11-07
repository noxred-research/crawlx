//! Merge a finished planner plan back into the deterministic frontier.
//!
//! 1. States, transitions and traffic are ordinary journaled rows; the
//!    driver already ingested each step's observation and outcome.
//! 2. Every key the plan touched is made known to the frontier (ledger
//!    registration), so the deterministic strategies can pick it up.
//! 3. A succeeded sequence becomes a *planned* composite edge with
//!    `weak_support = 1`, so path search can replay it deterministically:
//!    `first key  ──(context: first step's cluster)──▶  final cluster`.
//! 4. Coverage is credited only through trusted-lane executed keys (that
//!    already happened in `ingest_outcome`); the plan's tags stay annotations.
//! 5. The planner counters move: a success resets the failure streak and the
//!    stall counter, so the switching policy returns to `Greedy`.

use crate::exploration::ExplorationState;
use crate::llm_planner::PlanOutcome;
use crawlx_core::EdgeId;
use crawlx_graph::{EdgeContext, EdgeTarget, EnablementEdge, EnablementGraph};

/// What [`merge`] did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MergeReport {
    /// The composite edge created or reinforced, if any.
    pub composite_edge: Option<EdgeId>,
    /// Keys of the plan newly made known to the frontier.
    pub new_keys: u32,
    /// The plan counted as a planner success.
    pub success: bool,
}

/// Merge `outcome` into `state`. Safe to call for failed or aborted plans: only
/// the failure counter moves (and any trusted, succeeded steps stay known).
pub fn merge(outcome: &PlanOutcome, state: &mut ExplorationState) -> MergeReport {
    state.ledger_mut().advance(outcome.finished_at);
    let mut new_keys = 0_u32;
    for step in &outcome.steps {
        if state.ledger_mut().register(&step.key) {
            new_keys += 1;
        }
    }

    let mut composite_edge = None;
    let ok_steps: Vec<_> = outcome
        .steps
        .iter()
        .filter(|s| s.succeeded && s.lane == crawlx_core::TrustLane::TrustedUi)
        .collect();
    if outcome.success && ok_steps.len() >= 2 && ok_steps.len() == outcome.steps.len() {
        if let (Some(first), Some(last)) = (ok_steps.first(), ok_steps.last()) {
            if first.before != last.after {
                let source = first.key.id();
                let context = EdgeContext::Cluster(first.before);
                let target = EdgeTarget::Cluster(last.after);
                let id = upsert_composite(state, source, context, target, outcome.finished_at);
                composite_edge = Some(id);
            }
        }
    }

    state.note_planner_result(outcome.success);
    // planner-produced keys are new work for the greedy frontier
    state.refresh_after_merge();
    MergeReport {
        composite_edge,
        new_keys,
        success: outcome.success,
    }
}

/// Insert (or reinforce) the composite edge. The graph exposes no public
/// edge-insertion API; `GraphSnapshot` is its lossless interchange form, and
/// merges are rare (bounded by the planner call cap), so a snapshot round-trip is cheap.
fn upsert_composite(
    state: &mut ExplorationState,
    source: crawlx_core::ActionContextId,
    context: EdgeContext,
    target: EdgeTarget,
    now: crawlx_core::Timestamp,
) -> EdgeId {
    let params = state.config().graph;
    let mut snap = state.graph().snapshot();
    let existing = snap
        .edges
        .iter()
        .position(|e| e.source == source && e.context == context && e.target == target);
    let id = if let Some(i) = existing {
        let e = &mut snap.edges[i];
        e.weak_support = e.weak_support.saturating_add(1);
        e.last_seen = now;
        e.id
    } else {
        let mut e = EnablementEdge::new(source, context, target, now);
        e.weak_support = 1;
        let id = e.id;
        snap.edges.push(e);
        id
    };
    *state.graph_mut() = EnablementGraph::from_snapshot(snap, params);
    id
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::llm_planner::{AbortReason, ExecutedStep};
    use crate::testutil::{Fixture, Spec};
    use crawlx_core::hash::Digest;
    use crawlx_core::{ActionKind, Timestamp, TrustLane};

    fn outcome(f: &Fixture, steps: Vec<ExecutedStep>, success: bool) -> PlanOutcome {
        let _ = f;
        PlanOutcome {
            plan_id: Some("p".into()),
            digest: Digest::of("t", b"p"),
            coverage_tags: vec!["tag".into()],
            steps,
            success,
            aborted: (!success).then_some(AbortReason::StepFailed),
            finished_at: Timestamp::default(),
        }
    }

    fn step(f: &Fixture, name: &str, before: u128, after: u128) -> ExecutedStep {
        ExecutedStep {
            key: f.key(name, ActionKind::Click),
            succeeded: true,
            lane: TrustLane::TrustedUi,
            before: f.cluster_n(before),
            after: f.cluster_n(after),
            revealed: vec![],
            first_exercised: true,
        }
    }

    #[test]
    fn a_successful_sequence_becomes_a_composite_edge_with_weak_support_one() {
        let mut f = Fixture::new(&[Spec::button("A"), Spec::button("B")]);
        let before_edges = f.state().graph().len();
        let out = outcome(&f, vec![step(&f, "A", 1, 2), step(&f, "B", 2, 3)], true);
        let rep = merge(&out, f.state_mut());
        assert!(rep.success);
        let id = rep.composite_edge.unwrap();
        let g = f.state().graph();
        assert_eq!(g.len(), before_edges + 1);
        let e = g.edge(id).unwrap();
        assert_eq!(e.weak_support, 1);
        assert_eq!(e.support, 0);
        assert_eq!(e.source, f.key("A", ActionKind::Click).id());
        assert_eq!(e.context, EdgeContext::Cluster(f.cluster_n(1)));
        assert_eq!(e.target, EdgeTarget::Cluster(f.cluster_n(3)));
        // merging the same sequence again reinforces instead of duplicating
        let rep2 = merge(&out, f.state_mut());
        assert_eq!(rep2.composite_edge, Some(id));
        assert_eq!(f.state().graph().len(), before_edges + 1);
        assert_eq!(f.state().graph().edge(id).unwrap().weak_support, 2);
    }

    #[test]
    fn success_resets_failures_and_stall_and_keys_enter_the_frontier() {
        let mut f = Fixture::new(&[Spec::button("A")]);
        f.state_mut().stall_mut().stall = 60;
        f.state_mut().stall_mut().planner_failures = 1;
        let mut s = step(&f, "A", 1, 2);
        // a key the page never showed: planner-produced
        s.key.input_class = crawlx_core::InputClass::new("planner", "x");
        let planned = s.key.clone();
        let out = outcome(&f, vec![s], true);
        let rep = merge(&out, f.state_mut());
        assert_eq!(rep.new_keys, 1);
        assert!(
            rep.composite_edge.is_none(),
            "a single step already has its ordinary edge"
        );
        let st = f.state();
        assert!(st.ledger().contains(&planned));
        assert_eq!(st.stall().planner_failures, 0);
        assert_eq!(st.stall().planner_successes, 1);
        assert_eq!(st.stall().stall, 0);
    }

    #[test]
    fn failures_count_and_never_create_edges() {
        let mut f = Fixture::new(&[Spec::button("A"), Spec::button("B")]);
        let edges = f.state().graph().len();
        let out = outcome(&f, vec![step(&f, "A", 1, 2)], false);
        let rep = merge(&out, f.state_mut());
        assert!(!rep.success && rep.composite_edge.is_none());
        assert_eq!(f.state().stall().planner_failures, 1);
        merge(&out, f.state_mut());
        assert_eq!(f.state().stall().planner_failures, 2);
        assert_eq!(f.state().graph().len(), edges);
    }

    #[test]
    fn a_composite_edge_feeds_path_search() {
        use crawlx_graph::PathGoal;
        let mut f = Fixture::new(&[Spec::button("A"), Spec::button("B")]);
        let a = f.key("A", ActionKind::Click);
        let here = f.cluster();
        let out = outcome(
            &f,
            vec![
                ExecutedStep {
                    key: a.clone(),
                    succeeded: true,
                    lane: TrustLane::TrustedUi,
                    before: here,
                    after: f.cluster_n(8),
                    revealed: vec![],
                    first_exercised: true,
                },
                ExecutedStep {
                    key: f.key("B", ActionKind::Click),
                    succeeded: true,
                    lane: TrustLane::TrustedUi,
                    before: f.cluster_n(8),
                    after: f.cluster_n(9),
                    revealed: vec![],
                    first_exercised: false,
                },
            ],
            true,
        );
        merge(&out, f.state_mut());
        f.mark_risk(&a, crawlx_core::RiskClass::NavigationReveal);
        let ctx = f.ctx();
        let plan = ctx.path_plan(PathGoal::ReachCluster(f.cluster_n(9))).unwrap();
        assert_eq!(plan.steps.len(), 1);
        assert_eq!(plan.steps[0].source_action, a.id());
    }
}
