//! Replay validation: a plan is executed step by step and the
//! observed outcome of each step feeds back into the edges it traversed.

use crate::context::EnablementGraph;
use crate::search::PathPlan;
use crate::GraphError;
use crawlx_core::{EdgeId, Timestamp};
use serde::{Deserialize, Serialize};

/// Observed result of executing one plan step.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct StepOutcome {
    /// The after-state matched the expected cluster (≥ θ_review) or the
    /// expected target became visible.
    pub success: bool,
    /// Observed step latency in milliseconds; `None` when it was not measured.
    pub latency_ms: Option<u32>,
}

impl StepOutcome {
    /// A successful step that took `latency_ms` milliseconds.
    #[must_use]
    pub fn ok(latency_ms: u32) -> Self {
        Self {
            success: true,
            latency_ms: Some(latency_ms),
        }
    }

    /// A failed step with no latency sample.
    #[must_use]
    pub fn failed() -> Self {
        Self {
            success: false,
            latency_ms: None,
        }
    }
}

/// Result of validating a plan against observed outcomes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ReplayReport {
    /// Leading steps that matched their expectation.
    pub steps_ok: usize,
    /// Index of the first step that did not match; execution stops there.
    pub first_failure: Option<usize>,
    /// Graph edges that failed and should be reconsidered (replan / prune).
    pub stale_edges: Vec<EdgeId>,
}

/// Applies observed plan outcomes to the graph.
#[derive(Clone, Copy, Default, Debug)]
pub struct ReplayValidator;

impl ReplayValidator {
    /// A validator (stateless).
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Update the edges of `plan` from `outcomes` (one per executed step, in
    /// order; steps after the first failure are not executed and are ignored).
    /// `Navigate` reset steps have no edge and only count towards the report.
    ///
    /// Fails without mutating the graph when `outcomes` is longer than the plan
    /// or a non-navigation step references an edge no longer in the graph.
    ///
    /// # Errors
    ///
    /// [`GraphError::OutcomeCount`] when `outcomes` has more entries than the plan has
    /// steps; [`GraphError::UnknownEdge`] when a traversed step's edge is not in the graph.
    pub fn validate(
        &self,
        graph: &mut EnablementGraph,
        plan: &PathPlan,
        outcomes: &[StepOutcome],
        now: Timestamp,
    ) -> Result<ReplayReport, GraphError> {
        if outcomes.len() > plan.steps.len() {
            return Err(GraphError::OutcomeCount {
                steps: plan.steps.len(),
                outcomes: outcomes.len(),
            });
        }
        for (step, _) in plan.steps.iter().zip(outcomes) {
            if step.navigate.is_none() {
                graph.require(step.edge_id)?;
            }
        }
        let mut report = ReplayReport {
            steps_ok: 0,
            first_failure: None,
            stale_edges: Vec::new(),
        };
        for (i, (step, outcome)) in plan.steps.iter().zip(outcomes).enumerate() {
            if step.navigate.is_none() {
                graph.record_replay_timed(step.edge_id, outcome.success, outcome.latency_ms, now)?;
            }
            if outcome.success {
                report.steps_ok += 1;
            } else {
                report.first_failure = Some(i);
                if step.navigate.is_none() {
                    report.stale_edges.push(step.edge_id);
                }
                break;
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::search::{best_path, PathGoal, SearchParams};
    use crate::testutil::{act, cluster, graph, obs, t0};
    use chrono::Duration;
    use crawlx_core::ActionContextId;

    fn plan_and_graph() -> (EnablementGraph, PathPlan) {
        let mut g = graph();
        for (a, from, to) in [(1u8, 0u128, 1u128), (2, 1, 2), (3, 2, 3)] {
            for i in 0..4 {
                g.observe_transition(&obs(
                    act(a),
                    cluster(from),
                    cluster(to),
                    &[],
                    t0() + Duration::seconds(i),
                ));
            }
        }
        let sf = |_: ActionContextId| true;
        let p = SearchParams::new(t0() + Duration::seconds(10), &sf);
        let plan = best_path(&g, cluster(0), PathGoal::ReachCluster(cluster(3)), &p).unwrap();
        assert_eq!(plan.steps.len(), 3);
        (g, plan)
    }

    #[test]
    fn all_steps_ok_adds_support_and_latency() {
        let (mut g, plan) = plan_and_graph();
        let now = t0() + Duration::seconds(20);
        let before: Vec<u32> = plan
            .steps
            .iter()
            .map(|s| g.edge(s.edge_id).unwrap().support)
            .collect();
        let outcomes = [StepOutcome::ok(10), StepOutcome::ok(20), StepOutcome::ok(30)];
        let rep = ReplayValidator::new()
            .validate(&mut g, &plan, &outcomes, now)
            .unwrap();
        assert_eq!(
            rep,
            ReplayReport {
                steps_ok: 3,
                first_failure: None,
                stale_edges: vec![]
            }
        );
        for (s, b) in plan.steps.iter().zip(before) {
            let e = g.edge(s.edge_id).unwrap();
            assert_eq!(e.support, b + 1);
            assert_eq!(e.last_seen, now);
        }
    }

    #[test]
    fn failure_stops_and_marks_stale() {
        let (mut g, plan) = plan_and_graph();
        let now = t0() + Duration::seconds(20);
        let outcomes = [StepOutcome::ok(10), StepOutcome::failed(), StepOutcome::ok(30)];
        let rep = ReplayValidator::new()
            .validate(&mut g, &plan, &outcomes, now)
            .unwrap();
        assert_eq!(rep.steps_ok, 1);
        assert_eq!(rep.first_failure, Some(1));
        assert_eq!(rep.stale_edges, vec![plan.steps[1].edge_id]);
        assert_eq!(g.edge(plan.steps[1].edge_id).unwrap().failures, 1);
        // Step after the failure was not executed and is untouched.
        assert_eq!(g.edge(plan.steps[2].edge_id).unwrap().support, 4);
    }

    #[test]
    fn too_many_outcomes_or_unknown_edge_is_an_error_without_mutation() {
        let (mut g, plan) = plan_and_graph();
        let now = t0() + Duration::seconds(20);
        let v = ReplayValidator::new();
        let four = [StepOutcome::ok(1); 4];
        assert!(matches!(
            v.validate(&mut g, &plan, &four, now),
            Err(GraphError::OutcomeCount { .. })
        ));
        let first = plan.steps[0].edge_id;
        let support = g.edge(first).unwrap().support;
        g.remove_edge(plan.steps[2].edge_id);
        let three = [StepOutcome::ok(1); 3];
        assert!(matches!(
            v.validate(&mut g, &plan, &three, now),
            Err(GraphError::UnknownEdge(_))
        ));
        assert_eq!(g.edge(first).unwrap().support, support);
    }

    #[test]
    fn repeated_failed_replays_make_edge_prunable() {
        let (mut g, plan) = plan_and_graph();
        let v = ReplayValidator::new();
        for k in 0..3 {
            let now = t0() + Duration::seconds(20 + k);
            v.validate(&mut g, &plan, &[StepOutcome::failed()], now).unwrap();
        }
        let gone = g.prune(t0() + Duration::seconds(30));
        assert_eq!(gone, vec![plan.steps[0].edge_id]);
    }

    #[test]
    fn navigate_steps_touch_no_edges() {
        let (mut g, mut plan) = plan_and_graph();
        plan.steps[0].navigate = Some(crawlx_core::RouteTemplate("/x".into()));
        plan.steps[0].edge_id = EdgeId::default();
        let rep = ReplayValidator::new()
            .validate(&mut g, &plan, &[StepOutcome::failed()], t0())
            .unwrap();
        assert_eq!(rep.first_failure, Some(0));
        assert!(rep.stale_edges.is_empty());
    }
}
