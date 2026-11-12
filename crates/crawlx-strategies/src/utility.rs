//! The arbiter's utility function over `ActionContextKey`.
//!
//! ```text
//! U(k) =  1.00·novelty(k) + 0.80·expected_coverage_gain(k) + 0.55·enablement_probability(k)
//!       + 0.35·strategy_confidence(k) − 1.50·safety_risk(k) − 0.45·repetition_penalty(k)
//! ```
//!
//! All terms are in `[0, 1]` and computed over the key, never the element.
//! Hard denials were removed before scoring, so `safety_risk` only prices
//! allowed-but-consequential actions. The paper's layered-queue score
//! `W + 0.3·Z + E` is available as one more feature (`queue`, weight 0 by
//! default; [`UtilityWeights::paper_compat`] makes it the only term).
//!
//! No term reads measured wall-clock latency: the same seed over the same observations must
//! pick the same actions however long the browser took to run the earlier ones.

use crate::context::DecisionContext;
use crate::frontier::{route_element, stable_path_sig};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::safety::RiskClass;
use crawlx_core::{ActionContextId, ActionContextKey, ElementIdentityHash};
use crawlx_graph::{EdgeTarget, PathGoal};
use std::collections::BTreeMap;

/// `p_success` assumed for a key whose element already revealed a target with the same action
/// kind in another cluster (planning default; the graph's own edges carry measured
/// probabilities).
const KNOWN_ELEMENT_P_SUCCESS: f64 = 0.8;

/// Coefficients; versioned with the arbiter and recorded on the run.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct UtilityWeights {
    /// Weight of the key's novelty (never-exercised bonus).
    pub novelty: f32,
    /// Weight of the expected coverage gain (new keys the action is expected to uncover).
    pub expected_coverage_gain: f32,
    /// Weight of the probability that the action starts a path to a hidden target.
    pub enablement_probability: f32,
    /// Weight of the proposing strategy's confidence.
    pub strategy_confidence: f32,
    /// Weight of the kernel risk class (negative: risk lowers utility).
    pub safety_risk: f32,
    /// Weight of the repetition penalty (negative: recently repeated keys lower utility).
    pub repetition_penalty: f32,
    /// Paper layered-queue score `W + 0.3·Z + E` (lower is better, so the weight is negative).
    pub queue: f32,
}

impl Default for UtilityWeights {
    fn default() -> Self {
        Self {
            novelty: 1.00,
            expected_coverage_gain: 0.80,
            enablement_probability: 0.55,
            strategy_confidence: 0.35,
            safety_risk: -1.50,
            repetition_penalty: -0.45,
            queue: 0.0,
        }
    }
}

impl UtilityWeights {
    /// The paper's baseline: rank purely by `−(W + 0.3·Z + E)`.
    #[must_use]
    pub const fn paper_compat() -> Self {
        Self {
            novelty: 0.0,
            expected_coverage_gain: 0.0,
            enablement_probability: 0.0,
            strategy_confidence: 0.0,
            safety_risk: 0.0,
            repetition_penalty: 0.0,
            queue: -1.0,
        }
    }
}

/// The terms of `U(k)`.
#[derive(Clone, Copy, PartialEq, Debug, Default)]
pub struct KeyFeatures {
    /// Ledger novelty of the key.
    pub novelty: f32,
    /// Expected number of newly exposed keys, squashed into `[0, 1)`.
    pub expected_coverage_gain: f32,
    /// Product of edge success probabilities along the path the action starts, in `[0, 1]`.
    pub enablement_probability: f32,
    /// Proposer confidence, clamped to `[0, 1]`.
    pub strategy_confidence: f32,
    /// Kernel risk weight, from `0.0` (navigation) to `1.0` (out of scope).
    pub safety_risk: f32,
    /// Penalty for recently or repeatedly executed keys (see `FrontierStats::repetition_penalty`).
    pub repetition_penalty: f32,
    /// Paper layered-queue score `W + 0.3·Z + E` (lower is better).
    pub queue: f32,
}

impl KeyFeatures {
    /// Dot product with the weights.
    #[must_use]
    pub fn dot(&self, w: &UtilityWeights) -> f32 {
        w.novelty * self.novelty
            + w.expected_coverage_gain * self.expected_coverage_gain
            + w.enablement_probability * self.enablement_probability
            + w.strategy_confidence * self.strategy_confidence
            + w.safety_risk * self.safety_risk
            + w.repetition_penalty * self.repetition_penalty
            + w.queue * self.queue
    }
}

/// Kernel class → `safety_risk`. Denied classes never reach scoring
/// but are priced at the top of the scale for completeness.
#[must_use]
pub const fn risk_weight(class: RiskClass) -> f32 {
    match class {
        RiskClass::NavigationReveal => 0.0,
        RiskClass::ReversibleLocalPreference => 0.1,
        RiskClass::PersistentWriteOwn | RiskClass::Unclassified | RiskClass::FileUpload => 0.5,
        RiskClass::PersistentWriteOtherPrincipal
        | RiskClass::ExternalCommunication
        | RiskClass::Destructive
        | RiskClass::SecurityChange
        | RiskClass::FinancialTransaction => 0.8,
        RiskClass::OutOfScope => 1.0,
    }
}

/// Per-context scorer: precomputes the graph edges out of each key once, so
/// scoring N proposals costs one pass over the applicable edges.
pub struct Scorer<'c, 'a> {
    ctx: &'c DecisionContext<'a>,
    weights: UtilityWeights,
    edges_out: BTreeMap<ActionContextId, Vec<(EdgeTarget, f64)>>,
}

impl<'c, 'a> Scorer<'c, 'a> {
    /// Precompute the applicable graph edges of `ctx` and score with `weights`.
    #[must_use]
    pub fn new(ctx: &'c DecisionContext<'a>, weights: UtilityWeights) -> Self {
        let mut edges_out: BTreeMap<ActionContextId, Vec<(EdgeTarget, f64)>> = BTreeMap::new();
        for e in ctx.graph.applicable_edges(ctx.cluster) {
            edges_out
                .entry(e.source)
                .or_default()
                .push((e.target, e.p_success(ctx.clock_now)));
        }
        Self {
            ctx,
            weights,
            edges_out,
        }
    }

    /// `ĝ`-based gain: graph edges out of the key when known, else the ledger's cold-start estimate.
    fn expected_gain(&self, key: &ActionContextKey) -> f32 {
        let id = key.id();
        match self.edges_out.get(&id) {
            Some(edges) if !edges.is_empty() => {
                let g: f64 = edges
                    .iter()
                    .map(|(t, prob)| {
                        let unexercised = match t {
                            EdgeTarget::Cluster(c) => f64::from(self.ctx.ledger.unexercised_in_cluster(*c)),
                            EdgeTarget::Identity(_) => 1.0,
                        };
                        prob * unexercised
                    })
                    .sum();
                narrow(1.0 - (-0.5 * g).exp())
            }
            _ => self.ctx.ledger.expected_gain(key),
        }
    }

    /// `∏ p_success` along the cheapest path that starts with this proposal and
    /// reveals the proposal's expected target; for a key whose element already revealed the
    /// target with the same action kind (in any cluster), the planning-default `p = 0.8`;
    /// `0` for non-path proposals.
    fn enablement_probability(&self, key: &ActionContextKey, reveals: &[ElementIdentityHash]) -> f32 {
        let Some(target) = reveals.first() else {
            return 0.0;
        };
        if self
            .ctx
            .frontier
            .revealed_by(&key.element, key.action_kind)
            .is_some_and(|r| r.contains(target))
        {
            return narrow(KNOWN_ELEMENT_P_SUCCESS);
        }
        let Some(plan) = self.ctx.path_plan(PathGoal::RevealIdentity(*target)) else {
            return 0.0;
        };
        let Some(first) = plan.steps.first() else {
            return 0.0;
        };
        let starts_here = first.source_action == key.id()
            || first.source_action == key.family_id()
            || first
                .navigate
                .as_ref()
                .is_some_and(|route| route_element(route) == key.element);
        if starts_here {
            narrow(plan.reliability)
        } else {
            0.0
        }
    }

    /// The feature vector of `p` given the kernel's class for it.
    #[must_use]
    pub fn features(&self, p: &ActionProposal, risk: RiskClass) -> KeyFeatures {
        self.features_for(&p.key, p.confidence, &p.expected.reveals, risk)
    }

    /// Feature vector from the parts a proposal contributes (no action needed,
    /// so shortlists can be pre-scored without building browser actions).
    #[must_use]
    pub fn features_for(
        &self,
        key: &ActionContextKey,
        confidence: f32,
        reveals: &[ElementIdentityHash],
        risk: RiskClass,
    ) -> KeyFeatures {
        let ctx = self.ctx;
        let identity = ctx.identity_of(&key.element);
        let family = identity.map(stable_path_sig);
        KeyFeatures {
            novelty: ctx.ledger.novelty(key),
            expected_coverage_gain: self.expected_gain(key),
            enablement_probability: self.enablement_probability(key, reveals),
            strategy_confidence: confidence.clamp(0.0, 1.0),
            safety_risk: risk_weight(risk),
            repetition_penalty: ctx.frontier.repetition_penalty(key, identity),
            queue: family.map_or_else(
                || ctx.frontier.layer(key) as f32,
                |f| ctx.frontier.queue_score(key, &f),
            ),
        }
    }

    /// Utility of a key before any model term (shortlist pre-score): the
    /// deterministic baseline confidence of 0.5 and the given kernel class.
    #[must_use]
    pub fn prescore(&self, key: &ActionContextKey, risk: RiskClass) -> f32 {
        self.features_for(key, 0.5, &[], risk).dot(&self.weights)
    }

    /// `U(p)` with the kernel's class (the arbiter never trusts the proposer's hint).
    #[must_use]
    pub fn score(&self, p: &ActionProposal, risk: RiskClass) -> f32 {
        self.features(p, risk).dot(&self.weights)
    }
}

/// `U(p)` using the proposer's own `hinted_risk` (reveal when absent). The
/// arbiter instead calls [`Scorer::score`] with the kernel's verdict class.
#[must_use]
pub fn score(p: &ActionProposal, ctx: &DecisionContext<'_>, w: &UtilityWeights) -> f32 {
    Scorer::new(ctx, *w).score(p, p.hinted_risk.unwrap_or(RiskClass::NavigationReveal))
}

/// `x` in millionths, rounded: the fixed-point form every ranking sorts on, so float noise
/// below `1e-6` never decides an order.
#[must_use]
pub(crate) fn micros(x: f32) -> i64 {
    micros_f64(f64::from(x))
}

/// [`micros`] for a double.
#[must_use]
pub(crate) fn micros_f64(x: f64) -> i64 {
    let scaled = (x * 1_000_000.0).round().clamp(-9.0e18, 9.0e18);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "clamped into the i64 range on the line above"
    )]
    let q = scaled as i64;
    q
}

/// A probability or gain computed in `f64`, stored as `f32` (the precision of every feature).
#[must_use]
pub(crate) fn narrow(x: f64) -> f32 {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "features are small, non-negative scores"
    )]
    let v = x.clamp(f64::from(f32::MIN), f64::from(f32::MAX)) as f32;
    v
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{Fixture, Spec};
    use crawlx_core::{ActionKind, TrustLane};

    #[test]
    fn default_weights_are_main() {
        let w = UtilityWeights::default();
        assert_eq!(
            (
                w.novelty,
                w.expected_coverage_gain,
                w.enablement_probability,
                w.strategy_confidence,
                w.safety_risk,
                w.repetition_penalty
            ),
            (1.00, 0.80, 0.55, 0.35, -1.50, -0.45)
        );
        assert_eq!(w.queue, 0.0);
    }

    #[test]
    fn dot_product_matches_the_formula() {
        let f = KeyFeatures {
            novelty: 1.0,
            expected_coverage_gain: 0.5,
            enablement_probability: 0.2,
            strategy_confidence: 0.5,
            safety_risk: 0.5,
            repetition_penalty: 0.2,
            queue: 3.0,
        };
        let u = f.dot(&UtilityWeights::default());
        let expected = 1.0 + 0.8 * 0.5 + 0.55 * 0.2 + 0.35 * 0.5 - 1.5 * 0.5 - 0.45 * 0.2;
        assert!((u - expected).abs() < 1e-6, "{u} vs {expected}");
        assert!((f.dot(&UtilityWeights::paper_compat()) + 3.0).abs() < 1e-6);
    }

    #[test]
    fn risk_prices_follow_the_plan() {
        assert_eq!(risk_weight(RiskClass::NavigationReveal), 0.0);
        assert_eq!(risk_weight(RiskClass::ReversibleLocalPreference), 0.1);
        assert_eq!(risk_weight(RiskClass::PersistentWriteOwn), 0.5);
        assert_eq!(risk_weight(RiskClass::PersistentWriteOtherPrincipal), 0.8);
    }

    #[test]
    fn novel_keys_outscore_exercised_keys_and_risk_lowers_utility() {
        let mut f = Fixture::new(&[Spec::button("Open"), Spec::button("Close")]);
        let acts = f.actions();
        let open = acts
            .iter()
            .find(|a| a.candidate == 0 && a.key.action_kind == ActionKind::Click)
            .unwrap()
            .key
            .clone();
        f.exercise(&open, TrustLane::TrustedUi);
        let ctx = f.ctx();
        let w = UtilityWeights::default();
        let p_open = ctx
            .proposal_for(
                ctx.keyed_actions().iter().find(|a| a.key == open).unwrap(),
                "t",
                1,
                0.5,
            )
            .unwrap();
        let close_ka = ctx
            .keyed_actions()
            .iter()
            .find(|a| a.candidate == 1 && a.key.action_kind == ActionKind::Click)
            .unwrap();
        let p_close = ctx.proposal_for(close_ka, "t", 1, 0.5).unwrap();
        assert!(score(&p_close, &ctx, &w) > score(&p_open, &ctx, &w));
        let scorer = Scorer::new(&ctx, w);
        let reveal = scorer.score(&p_close, RiskClass::NavigationReveal);
        let write = scorer.score(&p_close, RiskClass::PersistentWriteOwn);
        assert!((reveal - write - 1.5 * 0.5).abs() < 1e-5);
    }
}
