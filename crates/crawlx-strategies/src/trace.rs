//! Round traces for golden-trace replay (a round's inputs and
//! ranked output go to the trace artifact so `crawlx replay` can re-run
//! arbitration offline; golden snapshots).
//!
//! A [`RoundTrace`] is a compact, serializable digest of one arbitration:
//! which keys were ranked in which order with which utility (quantized to
//! micro-units, so float formatting never matters), which were denied or
//! parked, and which was chosen. Replaying the same recorded
//! `(bundle, outcome)` sequence through the same strategy versions and seed
//! must reproduce the same [`GoldenTrace`].

use crate::arbiter::{ArbiterRound, ARBITER_VERSION};
use crate::context::DecisionContext;
use crate::utility::micros;
use crawlx_core::safety::RiskClass;
use crawlx_core::ActionContextId;
use serde::{Deserialize, Serialize};

/// One ranked proposal in a trace.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RankedTrace {
    /// Action-context key id of the proposal.
    pub key: ActionContextId,
    /// Name of the primary proposing strategy.
    pub strategy: String,
    /// Version of the primary proposing strategy.
    pub strategy_version: u32,
    /// Utility × 10⁶, rounded.
    pub utility_micros: i64,
    /// Risk class the kernel assigned.
    pub risk: RiskClass,
    /// Other `(strategy, version)` pairs that proposed the same key, sorted.
    pub co_proposers: Vec<(String, u32)>,
}

/// One arbitration round.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RoundTrace {
    /// Zero-based decision index of the round.
    pub decision_index: u64,
    /// Phase name (see `Phase::as_str`) the round ran in.
    pub phase: String,
    /// State cluster the round decided in.
    pub cluster: String,
    /// Allowed survivors, best first.
    pub ranked: Vec<RankedTrace>,
    /// Keys the kernel denied outright.
    pub denied: Vec<ActionContextId>,
    /// Keys parked for approval.
    pub approval_required: Vec<ActionContextId>,
    /// Key chosen for execution, if any.
    pub chosen: Option<ActionContextId>,
}

impl RoundTrace {
    /// Digest `round` as arbitrated over `ctx`.
    #[must_use]
    pub fn from_round(ctx: &DecisionContext<'_>, round: &ArbiterRound) -> Self {
        Self {
            decision_index: ctx.decision_index,
            phase: ctx.phase.as_str().to_owned(),
            cluster: ctx.cluster.to_string(),
            ranked: round
                .ranked
                .iter()
                .map(|r| RankedTrace {
                    key: r.proposal.key.id(),
                    strategy: r.proposal.strategy.to_owned(),
                    strategy_version: r.proposal.strategy_version,
                    utility_micros: micros(r.utility),
                    risk: r.verdict.risk_class,
                    co_proposers: r
                        .co_proposers
                        .iter()
                        .map(|(n, v)| ((*n).to_owned(), *v))
                        .collect(),
                })
                .collect(),
            denied: round.denied.iter().map(|(p, _)| p.key.id()).collect(),
            approval_required: round.approval_required.iter().map(|(p, _)| p.key.id()).collect(),
            chosen: round.chosen.as_ref().map(|c| c.proposal.key.id()),
        }
    }
}

/// A whole run's rounds, recorded under one seed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct GoldenTrace {
    /// Crawl seed the trace was recorded under.
    pub seed: u64,
    /// Arbiter logic version in force when recording.
    pub arbiter_version: u32,
    /// Recorded rounds in decision order.
    pub rounds: Vec<RoundTrace>,
}

impl GoldenTrace {
    /// Create an empty trace for `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            arbiter_version: ARBITER_VERSION,
            rounds: Vec::new(),
        }
    }

    /// Append the next round.
    pub fn push(&mut self, round: RoundTrace) {
        self.rounds.push(round);
    }

    /// Index of the first round that differs from `other` (or where one ends early).
    #[must_use]
    pub fn first_divergence(&self, other: &Self) -> Option<usize> {
        if self.seed != other.seed || self.arbiter_version != other.arbiter_version {
            return Some(0);
        }
        let n = self.rounds.len().max(other.rounds.len());
        (0..n).find(|&i| self.rounds.get(i) != other.rounds.get(i))
    }

    /// The chosen key of every round, in order.
    #[must_use]
    pub fn choices(&self) -> Vec<Option<ActionContextId>> {
        self.rounds.iter().map(|r| r.chosen).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::arbiter::Arbiter;
    use crate::context::BudgetView;
    use crate::exploration::{OutcomeReport, RoundInput};
    use crate::interaction_bfs::InteractionBfs;
    use crate::novelty::StateNovelty;
    use crate::runner::{run_strategies, StrategyDeadlines};
    use crate::switching::{SwitchingConfig, SwitchingPolicy};
    use crate::testutil::{Fixture, ScriptedGate, Spec};
    use crate::url_plane::UrlPlane;
    use crate::Strategy;
    use crawlx_core::seed::CrawlSeed;
    use crawlx_core::{Timestamp, TrustLane};
    use crawlx_graph::Confounders;
    use crawlx_state::OutcomeClass;
    use std::sync::Arc;

    /// A recorded scenario: the pages the "browser" shows and how actions land.
    fn pages() -> Vec<(&'static str, Vec<Spec>)> {
        vec![
            (
                "/app",
                vec![
                    Spec::button("Open menu"),
                    Spec::link("Docs", "/docs"),
                    Spec::textbox("Search", &[("type", "search")]),
                    Spec::checkbox("Remember"),
                    Spec::button("Delete account"),
                ],
            ),
            ("/docs", vec![Spec::link("Home", "/app"), Spec::button("Print")]),
            ("/other", vec![Spec::button("Back"), Spec::button("Share")]),
        ]
    }

    /// Run `rounds` decision rounds over the recorded pages; the "after" page of each
    /// chosen action is a pure function of the chosen key (the recorded outcome).
    async fn run(seed: u64, rounds: u64) -> GoldenTrace {
        let script = pages();
        let mut f = Fixture::with_seed(&script[0].1, CrawlSeed(seed));
        let gate = ScriptedGate::allow_all().with_decision(
            f.key("Delete account", crawlx_core::ActionKind::Click).element,
            crawlx_core::safety::SafetyDecision::Deny,
        );
        let strategies: Vec<Arc<dyn Strategy>> = vec![
            Arc::new(InteractionBfs::default()),
            Arc::new(StateNovelty::default()),
            Arc::new(UrlPlane::default()),
        ];
        let arbiter = Arbiter::default();
        let mut policy = SwitchingPolicy::new(SwitchingConfig::default());
        let mut trace = GoldenTrace::new(seed);
        for i in 0..rounds {
            let phase = policy.next(
                f.state().stall(),
                &BudgetView::default(),
                !f.state().hidden_targets().is_empty(),
                f.candidates.len(),
            );
            let ctx = f
                .state()
                .context(
                    RoundInput::new(
                        Arc::new(f.bundle.clone()),
                        f.candidates.clone(),
                        f.resolved.clone(),
                        f.cluster(),
                        i,
                        f.profile,
                        BudgetView::default(),
                        f.bundle.captured_at,
                    )
                    .with_phase(phase),
                )
                .unwrap();
            let round = run_strategies(&strategies, &ctx, &StrategyDeadlines::default()).await;
            let result = arbiter.choose(round.proposals, &ctx, &gate, &f.safety_ctx());
            trace.push(RoundTrace::from_round(&ctx, &result));
            let chosen = result.chosen.clone();
            drop(ctx);
            f.state_mut().ingest_round(&result);
            let Some(chosen) = chosen else { break };
            // recorded outcome: the page the action lands on is a function of the key id
            let key = chosen.proposal.key.clone();
            let pick = usize::from(key.id().0[0]) % script.len();
            let (path, specs) = &script[pick];
            f.observe_at(path, specs);
            let after_route = f.route();
            let after = f.cluster();
            f.state_mut().ingest_outcome(&OutcomeReport {
                key: key.clone(),
                outcome: OutcomeClass {
                    after_route_template: after_route,
                    after_cluster_family: None,
                    network_operation_digest: None,
                    status_class: 2,
                    unreliable: false,
                },
                lane: TrustLane::TrustedUi,
                succeeded: true,
                before: key.state_cluster,
                after,
                revealed: vec![],
                baseline_revealed: vec![],
                confounders: Confounders::default(),
                new_operation: false,
                now: Timestamp::from_timestamp_millis(10_000 + i64::try_from(i).unwrap()).unwrap(),
            });
            let _ = phase;
        }
        trace
    }

    #[tokio::test]
    async fn golden_trace_replays_to_identical_choices() {
        let recorded = run(7, 25).await;
        assert!(recorded.rounds.len() >= 10, "{}", recorded.rounds.len());
        assert!(recorded.rounds.iter().all(|r| r.chosen.is_some()));
        // denied keys (Delete account) never appear in any ranking
        assert!(recorded.rounds.iter().any(|r| !r.denied.is_empty()));
        for r in &recorded.rounds {
            assert!(r.ranked.iter().all(|x| !r.denied.contains(&x.key)));
        }
        let replay = run(7, 25).await;
        assert_eq!(recorded.first_divergence(&replay), None);
        assert_eq!(recorded.choices(), replay.choices());
        // the trace survives serialization unchanged
        let json = serde_json::to_string(&recorded).unwrap();
        let back: GoldenTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(back, recorded);
    }

    #[tokio::test]
    async fn a_different_seed_is_a_different_trace_and_divergence_is_located() {
        let a = run(7, 12).await;
        let b = run(8, 12).await;
        assert_eq!(
            a.first_divergence(&b),
            Some(0),
            "seed is part of the trace identity"
        );
        let mut c = a.clone();
        c.rounds[5].chosen = None;
        assert_eq!(a.first_divergence(&c), Some(5));
        let mut short = a.clone();
        short.rounds.truncate(3);
        assert_eq!(a.first_divergence(&short), Some(3));
    }
}
