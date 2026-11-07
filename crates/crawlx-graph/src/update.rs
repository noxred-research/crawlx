//! Edge updates: discovery attribution, replay credit, build change and
//! retirement.
//!
//! Nothing here reads wall time: every entry point takes `now`.

use crate::context::EnablementGraph;
use crate::edge::{EdgeContext, EdgeTarget};
use crate::GraphError;
use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::{ActionContextId, EdgeId, StateClusterId, Timestamp, TrustLane};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Tunables for updates, generalization and retirement.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct GraphParams {
    /// Distinct clusters of a route an action family's exact edges must span before they
    /// generalize to a route-template edge.
    pub generalize_min_clusters: usize,
    /// Laplace `p` of the pooled family evidence a route-template edge needs to be created.
    pub generalize_min_p: f64,
    /// Retire after this many failures in a row.
    pub retire_consecutive_failures: u32,
    /// Retire when `p` is below `retire_max_p` after at least this many trials.
    pub retire_min_trials: u32,
    /// Probability below which an edge with enough trials is retired.
    pub retire_max_p: f64,
    /// `mutation_volatile_ratio` above this counts as a confounder.
    pub volatile_ratio_threshold: f32,
}

impl Default for GraphParams {
    fn default() -> Self {
        Self {
            generalize_min_clusters: 2,
            generalize_min_p: 0.8,
            retire_consecutive_failures: 3,
            retire_min_trials: 5,
            retire_max_p: 0.2,
            volatile_ratio_threshold: 0.3,
        }
    }
}

/// What else changed in the settle window besides the action's effect.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct Confounders {
    /// WebSocket / SSE frames received in the window.
    pub ws_frames: u32,
    /// Polling responses (repeating XHR/fetch) in the window.
    pub polling: u32,
    /// Fraction of mutation records that hit regions flagged volatile.
    pub mutation_volatile_ratio: f32,
}

impl Confounders {
    /// Whether timers, pushes or other traffic could explain a reveal.
    #[must_use]
    pub fn present(&self, volatile_threshold: f32) -> bool {
        self.ws_frames > 0 || self.polling > 0 || self.mutation_volatile_ratio > volatile_threshold
    }
}

/// One executed action and what followed it.
#[derive(Clone, PartialEq, Debug)]
pub struct TransitionObservation {
    /// Action context that was executed.
    pub source: ActionContextId,
    /// Action family of `source` (`ActionContextKey::family_id`: the same action in every
    /// cluster); `None` treats the source as its own family.
    pub family: Option<ActionContextId>,
    /// State cluster the action ran in.
    pub before_cluster: StateClusterId,
    /// State cluster the page was in after settling (equal to `before_cluster` for an in-place reveal).
    pub after_cluster: StateClusterId,
    /// Controls new in the after-bundle that are still present after settle.
    pub revealed: Vec<ElementIdentityHash>,
    /// Controls the no-action control run revealed on its own.
    pub baseline_revealed: Vec<ElementIdentityHash>,
    /// Extra traffic and volatile mutations seen in the settle window.
    pub confounders: Confounders,
    /// Time from action to settled state, in milliseconds.
    pub latency_ms: u32,
    /// Execution lane; only [`TrustLane::TrustedUi`] observations become evidence.
    pub lane: TrustLane,
    /// Observation time supplied by the caller; the graph never reads the clock.
    pub now: Timestamp,
}

/// What [`EnablementGraph::observe_transition`] did.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct TransitionOutcome {
    /// Edges that gained strong support.
    pub strong: Vec<EdgeId>,
    /// Edges that gained weak (confounded) support.
    pub weak: Vec<EdgeId>,
    /// Existing edges whose expected target did not follow.
    pub failed: Vec<EdgeId>,
    /// Revealed controls rejected because the baseline run revealed them too.
    pub rejected_baseline: usize,
    /// The whole observation was ignored: the action ran in the diagnostic lane.
    pub rejected_untrusted: bool,
    /// Route-template edges created by this observation.
    pub generalized: Vec<EdgeId>,
}

impl EnablementGraph {
    /// Apply the attribution filter and update edges.
    ///
    /// A revealed control becomes evidence only if the action ran in the
    /// trusted lane and the control is absent from the no-action baseline.
    /// Credit is `support` without confounders and `weak_support` (worth half)
    /// with them. Executing a known action again in the same cluster is a
    /// replay: known edges whose target did not follow take a failure.
    pub fn observe_transition(&mut self, obs: &TransitionObservation) -> TransitionOutcome {
        let mut out = TransitionOutcome::default();
        if let Some(family) = obs.family {
            self.families.insert(obs.source, family);
        }
        if obs.after_cluster != obs.before_cluster {
            // Only a different cluster can claim the revealed controls as part of
            // its visible set; an in-place reveal leaves the cluster unchanged.
            self.visible
                .entry(obs.after_cluster)
                .or_default()
                .extend(obs.revealed.iter().copied());
        }
        if obs.lane != TrustLane::TrustedUi {
            out.rejected_untrusted = true;
            return out;
        }
        let weak = obs.confounders.present(self.params.volatile_ratio_threshold);
        let revealed: BTreeSet<ElementIdentityHash> = obs.revealed.iter().copied().collect();
        let baseline: BTreeSet<ElementIdentityHash> = obs.baseline_revealed.iter().copied().collect();
        let ctx = EdgeContext::Cluster(obs.before_cluster);

        // Replay side: known exact edges for this action whose target did not follow.
        let known: Vec<(EdgeId, EdgeTarget)> = self
            .edges_in(&ctx)
            .filter(|e| e.source == obs.source)
            .map(|e| (e.id, e.target))
            .collect();
        for (id, target) in known {
            let missed = match target {
                EdgeTarget::Identity(h) => !revealed.contains(&h) && !baseline.contains(&h),
                EdgeTarget::Cluster(c) => c != obs.after_cluster,
            };
            if missed {
                if let Some(e) = self.edge_mut(id) {
                    e.fail(obs.now);
                    out.failed.push(id);
                }
            }
        }

        // Discovery / credit side.
        let build = self.current_build.clone();
        let mut credited: Vec<EdgeTarget> = Vec::new();
        for h in &revealed {
            if baseline.contains(h) {
                out.rejected_baseline += 1;
                continue;
            }
            credited.push(EdgeTarget::Identity(*h));
        }
        if obs.before_cluster != obs.after_cluster {
            credited.push(EdgeTarget::Cluster(obs.after_cluster));
        }
        for target in credited {
            let e = self.upsert_mut(ctx.clone(), obs.source, target, obs.now);
            e.credit(weak, Some(obs.latency_ms), build.as_deref(), obs.now);
            let id = e.id;
            if weak {
                out.weak.push(id)
            } else {
                out.strong.push(id)
            }
            if let Some(g) = self.generalize(obs.before_cluster, obs.source, target, obs.now) {
                out.generalized.push(g);
            }
        }
        out
    }

    /// Record the outcome of re-executing the action behind `edge` (or of
    /// traversing it in a path). Success adds support and verifies the edge
    /// against the current build; failure adds a failure.
    ///
    /// # Errors
    ///
    /// [`GraphError::UnknownEdge`] when `edge` is not in the graph.
    pub fn record_replay(&mut self, edge: EdgeId, success: bool, now: Timestamp) -> Result<(), GraphError> {
        self.record_replay_timed(edge, success, None, now)
    }

    /// [`Self::record_replay`] with an observed latency.
    ///
    /// # Errors
    ///
    /// [`GraphError::UnknownEdge`] when `edge` is not in the graph.
    pub fn record_replay_timed(
        &mut self,
        edge: EdgeId,
        success: bool,
        latency_ms: Option<u32>,
        now: Timestamp,
    ) -> Result<(), GraphError> {
        self.require(edge)?;
        let build = self.current_build.clone();
        let Some(e) = self.edge_mut(edge) else {
            return Err(GraphError::UnknownEdge(edge));
        };
        if success {
            e.credit(false, latency_ms, build.as_deref(), now);
        } else {
            e.fail(now);
        }
        let cluster = match e.context {
            EdgeContext::Cluster(c) => Some(c),
            EdgeContext::RouteTemplate(_) | EdgeContext::PrincipalGlobal => None,
        };
        let (source, target) = (e.source, e.target);
        if success {
            if let Some(c) = cluster {
                self.generalize(c, source, target, now);
            }
        }
        Ok(())
    }

    /// Set the risk of an action: applies to its existing edges and to edges
    /// created later. `0` means reveal, navigation or reversible UI.
    pub fn set_action_risk(&mut self, source: ActionContextId, risk: f32) {
        self.action_risk.insert(source, risk);
        let ids: Vec<EdgeId> = self
            .edges()
            .filter(|e| e.source == source)
            .map(|e| e.id)
            .collect();
        for id in ids {
            if let Some(e) = self.edge_mut(id) {
                e.risk = risk;
            }
        }
    }

    /// Declare the detected application build. When it differs from the
    /// current one, every edge not verified against it becomes `unverified`
    /// (usable at extra cost until replay-verified). Returns the number of
    /// edges newly marked.
    pub fn on_build_change(&mut self, build_id: &str) -> usize {
        self.current_build = Some(build_id.to_owned());
        let ids: Vec<EdgeId> = self
            .edges()
            .filter(|e| !e.unverified && e.last_verified_build.as_deref() != Some(build_id))
            .map(|e| e.id)
            .collect();
        let n = ids.len();
        for id in ids {
            if let Some(e) = self.edge_mut(id) {
                e.unverified = true;
            }
        }
        n
    }

    /// Remove retired edges: three consecutive failures, or `p < 0.2` after at
    /// least five trials. Retired route-template edges are not regenerated.
    /// Returns the removed ids in ascending order.
    pub fn prune(&mut self, now: Timestamp) -> Vec<EdgeId> {
        let params = self.params;
        let mut retired: Vec<EdgeId> = self
            .edges()
            .filter(|e| {
                e.consecutive_failures >= params.retire_consecutive_failures
                    || (e.trials() >= params.retire_min_trials && e.p_success(now) < params.retire_max_p)
            })
            .map(|e| e.id)
            .collect();
        retired.sort_unstable();
        for id in &retired {
            if let Some(e) = self.remove_edge(*id) {
                if let EdgeContext::RouteTemplate(r) = e.context {
                    self.block_generalization(r, e.source, e.target);
                }
            }
        }
        retired
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::edge::CostParams;
    use crate::testutil::{act, cluster, graph, hash, obs, t0};
    use chrono::Duration;
    use crawlx_core::RouteTemplate;

    fn identity_edge(g: &EnablementGraph, c: u128, a: u8, h: u8) -> crate::EnablementEdge {
        g.find(
            &EdgeContext::Cluster(cluster(c)),
            act(a),
            &EdgeTarget::Identity(hash(h)),
        )
        .unwrap()
        .clone()
    }

    #[test]
    fn clean_reveal_is_strong_support() {
        let mut g = graph();
        let out = g.observe_transition(&obs(act(1), cluster(1), cluster(1), &[hash(7)], t0()));
        assert_eq!(out.strong.len(), 1);
        assert!(out.weak.is_empty());
        let e = identity_edge(&g, 1, 1, 7);
        assert_eq!((e.support, e.weak_support, e.failures), (1, 0, 0));
        assert!((e.p_success(t0()) - 2.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn confounders_give_weak_support_worth_half() {
        for c in [
            Confounders {
                ws_frames: 2,
                ..Confounders::default()
            },
            Confounders {
                polling: 1,
                ..Confounders::default()
            },
            Confounders {
                mutation_volatile_ratio: 0.31,
                ..Confounders::default()
            },
        ] {
            let mut g = graph();
            let mut o = obs(act(1), cluster(1), cluster(1), &[hash(7)], t0());
            o.confounders = c;
            let out = g.observe_transition(&o);
            assert_eq!(out.weak.len(), 1, "{c:?}");
            let e = identity_edge(&g, 1, 1, 7);
            assert_eq!((e.support, e.weak_support), (0, 1));
            // s = 0.5 -> p = 1.5 / 2.5
            assert!((e.p_success(t0()) - 0.6).abs() < 1e-12);
        }
        // Exactly 0.3 is not a confounder.
        let mut g = graph();
        let mut o = obs(act(1), cluster(1), cluster(1), &[hash(7)], t0());
        o.confounders.mutation_volatile_ratio = 0.3;
        assert_eq!(g.observe_transition(&o).strong.len(), 1);
    }

    #[test]
    fn baseline_reveals_are_not_attributed() {
        let mut g = graph();
        let mut o = obs(act(1), cluster(1), cluster(1), &[hash(7), hash(8)], t0());
        o.baseline_revealed = vec![hash(8)];
        let out = g.observe_transition(&o);
        assert_eq!(out.rejected_baseline, 1);
        assert_eq!(g.len(), 1);
        assert!(g
            .find(
                &EdgeContext::Cluster(cluster(1)),
                act(1),
                &EdgeTarget::Identity(hash(8))
            )
            .is_none());
    }

    #[test]
    fn diagnostic_lane_is_ignored() {
        let mut g = graph();
        let mut o = obs(act(1), cluster(1), cluster(2), &[hash(7)], t0());
        o.lane = TrustLane::Diagnostic;
        let out = g.observe_transition(&o);
        assert!(out.rejected_untrusted);
        assert!(g.is_empty());
    }

    #[test]
    fn cluster_change_creates_transition_edge() {
        let mut g = graph();
        g.observe_transition(&obs(act(1), cluster(1), cluster(2), &[], t0()));
        let e = g
            .find(
                &EdgeContext::Cluster(cluster(1)),
                act(1),
                &EdgeTarget::Cluster(cluster(2)),
            )
            .unwrap();
        assert_eq!(e.support, 1);
        assert_eq!(e.p50_latency_ms, 100);
    }

    #[test]
    fn repeat_without_target_is_a_failure() {
        let mut g = graph();
        g.observe_transition(&obs(act(1), cluster(1), cluster(1), &[hash(7)], t0()));
        let out = g.observe_transition(&obs(
            act(1),
            cluster(1),
            cluster(1),
            &[],
            t0() + Duration::seconds(1),
        ));
        assert_eq!(out.failed.len(), 1);
        let e = identity_edge(&g, 1, 1, 7);
        assert_eq!((e.support, e.failures, e.consecutive_failures), (1, 1, 1));
    }

    #[test]
    fn record_replay_success_and_failure() {
        let mut g = graph();
        g.observe_transition(&obs(act(1), cluster(1), cluster(1), &[hash(7)], t0()));
        let id = identity_edge(&g, 1, 1, 7).id;
        g.record_replay(id, true, t0() + Duration::seconds(5)).unwrap();
        g.record_replay(id, false, t0() + Duration::seconds(6)).unwrap();
        let e = g.edge(id).unwrap();
        assert_eq!((e.support, e.failures), (2, 1));
        assert!(g.record_replay(EdgeId::default(), true, t0()).is_err());
    }

    #[test]
    fn retire_after_three_consecutive_failures() {
        let mut g = graph();
        for i in 0..10 {
            g.observe_transition(&obs(
                act(1),
                cluster(1),
                cluster(1),
                &[hash(7)],
                t0() + Duration::seconds(i),
            ));
        }
        let id = identity_edge(&g, 1, 1, 7).id;
        g.record_replay(id, false, t0() + Duration::seconds(20)).unwrap();
        g.record_replay(id, false, t0() + Duration::seconds(21)).unwrap();
        assert!(g.prune(t0() + Duration::seconds(22)).is_empty());
        g.record_replay(id, false, t0() + Duration::seconds(23)).unwrap();
        assert_eq!(g.prune(t0() + Duration::seconds(24)), vec![id]);
        assert!(g.edge(id).is_none());
    }

    #[test]
    fn retire_when_p_low_after_five_trials() {
        let mut g = graph();
        let mk = |a: u8, failures: u32| EdgeRecord {
            id: EdgeId::default(),
            run: g.run(),
            source: act(a),
            context_cluster: Some(cluster(1)),
            target: hash(a),
            support: 0,
            weak_support: 0,
            failures,
            latency_ms_ewma: 0.0,
            risk: 0.0,
            last_observed_at: t0(),
            last_verified_build: None,
        };
        use crawlx_core::repo::EdgeRecord;
        let mut r4 = mk(1, 4); // p = 1/6 < 0.2 but only 4 trials
        r4.id = crate::derive_edge_id(
            r4.source,
            &EdgeContext::Cluster(cluster(1)),
            &EdgeTarget::Identity(r4.target),
        );
        let mut r5 = mk(2, 5); // p = 1/7 after 5 trials
        r5.id = crate::derive_edge_id(
            r5.source,
            &EdgeContext::Cluster(cluster(1)),
            &EdgeTarget::Identity(r5.target),
        );
        g.load([r4.clone(), r5.clone()]);
        assert_eq!(g.prune(t0()), vec![r5.id]);
        assert!(g.edge(r4.id).is_some());
    }

    #[test]
    fn build_change_marks_unverified_and_raises_cost() {
        let mut g = graph();
        g.on_build_change("A");
        g.observe_transition(&obs(act(1), cluster(1), cluster(1), &[hash(7)], t0()));
        let id = identity_edge(&g, 1, 1, 7).id;
        let params = CostParams::default();
        let before = g.edge(id).unwrap().edge_cost(t0(), &params);
        assert!(!g.edge(id).unwrap().unverified);

        assert_eq!(g.on_build_change("B"), 1);
        assert_eq!(g.on_build_change("B"), 0);
        let e = g.edge(id).unwrap();
        assert!(e.unverified);
        assert!((e.edge_cost(t0(), &params) - before - params.unverified_penalty).abs() < 1e-12);

        g.record_replay(id, true, t0()).unwrap();
        let e = g.edge(id).unwrap();
        assert!(!e.unverified);
        assert_eq!(e.last_verified_build.as_deref(), Some("B"));
    }

    fn observe_twice(g: &mut EnablementGraph, c: u128, a: u8, h: u8, at: i64) {
        for k in 0..2 {
            g.observe_transition(&obs(
                act(a),
                cluster(c),
                cluster(c),
                &[hash(h)],
                t0() + Duration::seconds(at + k),
            ));
        }
    }

    #[test]
    fn route_template_generalizes_from_pooled_evidence_across_two_clusters() {
        let mut g = graph();
        let route = RouteTemplate("/items/:id".into());
        for c in 1..=4 {
            g.set_cluster_route(cluster(c), route.clone());
        }
        let route_ctx = EdgeContext::RouteTemplate(route.clone());
        let target = EdgeTarget::Identity(hash(7));
        // one cluster is never enough, however strong
        observe_twice(&mut g, 1, 1, 7, 0);
        assert!(g.find(&route_ctx, act(1), &target).is_none());
        // a second cluster brings the pool to support 3: Laplace p = 4/5 = 0.8
        g.observe_transition(&obs(
            act(1),
            cluster(2),
            cluster(2),
            &[hash(7)],
            t0() + Duration::seconds(10),
        ));
        let r = g.find(&route_ctx, act(1), &target).unwrap();
        assert_eq!(r.support, 3);
        // later evidence in a third cluster does not recreate it
        observe_twice(&mut g, 3, 1, 7, 20);
        assert_eq!(g.find(&route_ctx, act(1), &target).unwrap().support, 3);
        // Cluster 4 never saw it, but the route edge applies there at +0.15.
        let app = g.applicable_edges(cluster(4));
        assert_eq!(app.len(), 1);
        assert_eq!(app[0].context, route_ctx);
        let exact = identity_edge(&g, 3, 1, 7);
        let p = CostParams::default();
        let now = t0() + Duration::seconds(21);
        // Same pattern at an exact cluster is preferred over the route edge.
        let app3 = g.applicable_edges(cluster(3));
        assert_eq!(app3.len(), 1);
        assert_eq!(app3[0].context, EdgeContext::Cluster(cluster(3)));
        assert!(exact.ctx_penalty(&p).abs() < 1e-12);
        assert!((g.find(&route_ctx, act(1), &target).unwrap().ctx_penalty(&p) - 0.15).abs() < 1e-12);
        assert!(g.edge(exact.id).unwrap().edge_cost(now, &p).is_finite());
    }

    #[test]
    fn two_clusters_with_one_observation_each_stay_below_the_pooled_bar() {
        let mut g = graph();
        let route = RouteTemplate("/r".into());
        for c in 1..=2 {
            g.set_cluster_route(cluster(c), route.clone());
            g.observe_transition(&obs(act(1), cluster(c), cluster(c), &[hash(7)], t0()));
        }
        // pooled support 2: p = 3/4 < 0.8
        assert_eq!(g.edges_in(&EdgeContext::RouteTemplate(route)).count(), 0);
    }

    /// Generalization: the same action keyed in different clusters (distinct source
    /// ids, one family) pools its evidence; the route edge's source is the family id, and
    /// another family's evidence never joins the pool.
    #[test]
    fn sources_of_one_family_pool_into_a_family_sourced_route_edge() {
        let mut g = graph();
        let route = RouteTemplate("/menu".into());
        let family = act(50);
        let target = EdgeTarget::Identity(hash(7));
        for c in 1..=3u8 {
            g.set_cluster_route(cluster(u128::from(c)), route.clone());
        }
        let observe = |g: &mut EnablementGraph, a: u8, c: u128, family: ActionContextId, at: i64| {
            let mut o = obs(
                act(a),
                cluster(c),
                cluster(c),
                &[hash(7)],
                t0() + Duration::seconds(at),
            );
            o.family = Some(family);
            g.observe_transition(&o);
        };
        // another family's evidence in a second cluster does not count
        observe(&mut g, 1, 1, family, 0);
        observe(&mut g, 9, 2, act(60), 1);
        observe(&mut g, 9, 2, act(60), 2);
        let route_ctx = EdgeContext::RouteTemplate(route);
        assert!(g.find(&route_ctx, family, &target).is_none());
        // the family's own keys in clusters 2 and 3 (sources act(2), act(3)) pool with act(1)
        observe(&mut g, 2, 2, family, 3);
        assert!(g.find(&route_ctx, family, &target).is_none(), "pooled support 2");
        observe(&mut g, 3, 3, family, 4);
        let r = g.find(&route_ctx, family, &target).unwrap();
        assert_eq!((r.source, r.support), (family, 3));
        assert_eq!(g.family_of(act(2)), family);
        assert_eq!(
            g.family_of(act(77)),
            act(77),
            "an unknown source is its own family"
        );
    }

    #[test]
    fn retired_route_edge_is_not_recreated() {
        let mut g = graph();
        let route = RouteTemplate("/r".into());
        for c in 1..=3 {
            g.set_cluster_route(cluster(c), route.clone());
            observe_twice(&mut g, c, 1, 7, i64::try_from(c).unwrap() * 10);
        }
        let route_ctx = EdgeContext::RouteTemplate(route);
        let target = EdgeTarget::Identity(hash(7));
        let id = g.find(&route_ctx, act(1), &target).unwrap().id;
        let now = t0() + Duration::seconds(100);
        for k in 0..3 {
            g.record_replay(id, false, now + Duration::seconds(k)).unwrap();
        }
        assert_eq!(g.prune(now + Duration::seconds(5)), vec![id]);
        g.observe_transition(&obs(
            act(1),
            cluster(1),
            cluster(1),
            &[hash(7)],
            now + Duration::seconds(10),
        ));
        assert!(g.find(&route_ctx, act(1), &target).is_none());
    }

    #[test]
    fn global_edges_are_never_created_implicitly() {
        let mut g = graph();
        for r in 0..5 {
            let route = RouteTemplate(format!("/r{r}"));
            for c in 1..=3u128 {
                let cl = cluster(r * 10 + c);
                g.set_cluster_route(cl, route.clone());
                observe_twice(&mut g, r * 10 + c, 1, 7, 0);
            }
        }
        assert_eq!(g.edges_in(&EdgeContext::PrincipalGlobal).count(), 0);
    }

    #[test]
    fn action_risk_applies_to_new_and_existing_edges() {
        let mut g = graph();
        g.observe_transition(&obs(act(1), cluster(1), cluster(1), &[hash(7)], t0()));
        g.set_action_risk(act(1), 0.5);
        g.observe_transition(&obs(act(1), cluster(2), cluster(2), &[hash(7)], t0()));
        assert!(g.edges().all(|e| (e.risk - 0.5).abs() < f32::EPSILON));
    }

    #[test]
    fn decay_lowers_probability_with_time() {
        let mut g = graph();
        for i in 0..4 {
            g.observe_transition(&obs(
                act(1),
                cluster(1),
                cluster(1),
                &[hash(7)],
                t0() + Duration::seconds(i),
            ));
        }
        let e = identity_edge(&g, 1, 1, 7);
        let fresh = e.p_success(e.last_seen);
        let later = e.p_success(e.last_seen + Duration::days(14));
        assert!((fresh - 5.0 / 6.0).abs() < 1e-12);
        assert!((later - 0.75).abs() < 1e-9);
    }
}
