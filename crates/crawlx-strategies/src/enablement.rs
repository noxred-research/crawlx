//! `enablement`: recovery toward hidden targets.
//!
//! Targets are identities seen earlier but not visible now. A target whose revealing control
//! is on screen now (an `(element, action kind)` pair whose trusted execution revealed it,
//! in any cluster) is re-revealed directly through that control: the precondition replay of
//! without a route reset. Otherwise the cheapest path-safe plan over the enablement
//! graph (with `Navigate` resets to known routes) is searched; the strategy proposes the
//! **next step** of the best plans. Later steps are re-derived next round from the new
//! observation, because only the first step's locator is valid at this epoch. A recovery
//! plan ends on its target: an unexercised identity a known control revealed, once it is
//! newly visible, is proposed first, so one reveal recovers every target it exposes.
//! Reveal and path steps are phase 2: proposed only in the
//! `EnablementRecovery` phase or once every visible control here has been exercised.

use crate::context::DecisionContext;
use crate::error::StrategyError;
use crate::utility::{micros_f64, narrow};
use crate::Strategy;
use async_trait::async_trait;
use crawlx_core::proposal::ActionProposal;
use crawlx_core::ElementIdentityHash;
use crawlx_graph::PathGoal;

/// Strategy name; the arbiter bookkeeping in `ExplorationState::ingest_round` keys on it.
pub const NAME: &str = "enablement";
/// Version of the enablement strategy logic, recorded in proposal attribution.
pub const VERSION: u32 = 2;

/// Planning-default success probability of re-revealing a target through a control that
/// revealed it before (the same value `utility` uses for element-level evidence).
const DIRECT_P_SUCCESS: f64 = 0.8;

/// Tuning knobs of [`EnablementRecovery`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnablementConfig {
    /// Next steps proposed per round.
    pub max_proposals: usize,
    /// Hidden targets searched per round (bounds the search cost).
    pub max_targets: usize,
    /// Propose only while the switching policy is in `EnablementRecovery`.
    pub only_in_recovery: bool,
}

impl Default for EnablementConfig {
    fn default() -> Self {
        Self {
            max_proposals: 3,
            max_targets: 16,
            only_in_recovery: false,
        }
    }
}

/// Strategy that proposes the next step toward identities seen earlier but not visible now.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnablementRecovery {
    cfg: EnablementConfig,
}

impl EnablementRecovery {
    /// Create the strategy with `cfg`.
    #[must_use]
    pub const fn new(cfg: EnablementConfig) -> Self {
        Self { cfg }
    }

    fn select(&self, ctx: &DecisionContext<'_>) -> Vec<ActionProposal> {
        if self.cfg.only_in_recovery && ctx.phase != crate::switching::Phase::EnablementRecovery {
            return Vec::new();
        }
        let mut found: Vec<(u64, ElementIdentityHash, ActionProposal)> = Vec::new();
        // the last step of a recovery plan: a target its revealer just exposed is acted on
        // before anything can hide it again (cost 0: ranks before every reveal step); this is
        // greedy follow-through and runs in every phase
        for (target, p) in Self::completions(ctx) {
            found.push((0, target, p));
        }
        // phase-2 pathfinding: reveal steps toward hidden targets only in the
        // `EnablementRecovery` phase, or once the greedy frontier here is empty (every visible
        // control's element was exercised), so recovery never outbids exploration of controls
        // that were never tried
        let phase2 = ctx.phase == crate::switching::Phase::EnablementRecovery || !Self::greedy_has_work(ctx);
        let targets: &[ElementIdentityHash] = if phase2 { &ctx.hidden_targets } else { &[] };
        for target in targets.iter().take(self.cfg.max_targets) {
            if let Some(p) = Self::direct(ctx, target) {
                // one step at the known reveal probability: ranks before any multi-step plan
                let cost = u64::try_from(micros_f64(1.0 / DIRECT_P_SUCCESS)).unwrap_or(0);
                found.push((cost, *target, p));
                continue;
            }
            let Some(plan) = ctx.path_plan(PathGoal::RevealIdentity(*target)) else {
                continue;
            };
            let Some(step) = plan.steps.first() else {
                continue;
            };
            let confidence = narrow(plan.reliability);
            let proposal = if let Some(route) = &step.navigate {
                ctx.navigate_proposal(route, NAME, VERSION, confidence)
            } else {
                ctx.keyed_actions()
                    .iter()
                    // a generalized edge's source is the action family of the step's key
                    .find(|ka| ka.key.id() == step.source_action || ka.key.family_id() == step.source_action)
                    .and_then(|ka| ctx.proposal_for(ka, NAME, VERSION, confidence))
            };
            let Some(mut p) = proposal else { continue };
            p.expected.reveals = vec![*target];
            // cost scaled to an integer for a total order (lower is better)
            let cost = u64::try_from(micros_f64(plan.expected_cost).max(0)).unwrap_or(0);
            found.push((cost, *target, p));
        }
        found.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        let mut out: Vec<ActionProposal> = Vec::new();
        for (_, _, p) in found {
            if out.iter().any(|q| q.key.id() == p.key.id()) {
                continue;
            }
            out.push(p);
            if out.len() >= self.cfg.max_proposals {
                break;
            }
        }
        out
    }

    /// A proposal for a visible control whose trusted execution revealed `target` before (same
    /// element, same action kind, any cluster) and whose kernel class is path-safe (the same
    /// rule planned paths follow), first in keyed-action order.
    fn direct(ctx: &DecisionContext<'_>, target: &ElementIdentityHash) -> Option<ActionProposal> {
        let revealers: Vec<_> = ctx.frontier.revealers_of(target).collect();
        if revealers.is_empty() {
            return None;
        }
        let ka = ctx.keyed_actions().iter().find(|ka| {
            revealers.contains(&(ka.key.element, ka.key.action_kind))
                && ctx
                    .frontier
                    .is_path_safe_element(&ka.key.element, ka.key.action_kind)
                && ctx.frontier.is_proposable(&ka.key)
        })?;
        let mut p = ctx.proposal_for(ka, NAME, VERSION, narrow(DIRECT_P_SUCCESS))?;
        p.expected.reveals = vec![*target];
        Some(p)
    }

    /// Does the greedy frontier of this context still hold a proposable key on a visible
    /// element no trusted action has exercised yet?
    fn greedy_has_work(ctx: &DecisionContext<'_>) -> bool {
        ctx.keyed_actions()
            .iter()
            .any(|ka| !ctx.exercised.contains(&ka.key.element) && ctx.frontier.is_proposable(&ka.key))
    }

    /// Recovery targets a reveal just exposed: unexercised identities newly visible this round
    /// that a known control revealed before (so they are enablement targets, not page
    /// furniture), one proposal per element (its first keyed action), in keyed-action order.
    fn completions(ctx: &DecisionContext<'_>) -> Vec<(ElementIdentityHash, ActionProposal)> {
        let mut seen: std::collections::BTreeSet<ElementIdentityHash> = std::collections::BTreeSet::new();
        let mut out = Vec::new();
        for ka in ctx.keyed_actions() {
            let h = ka.key.element;
            if !ctx.newly_visible.contains(&h)
                || ctx.exercised.contains(&h)
                || ctx.frontier.revealers_of(&h).next().is_none()
                || !ctx.frontier.is_proposable(&ka.key)
                || !seen.insert(h)
            {
                continue;
            }
            if let Some(p) = ctx.proposal_for(ka, NAME, VERSION, narrow(DIRECT_P_SUCCESS)) {
                out.push((h, p));
            }
        }
        out
    }
}

#[async_trait]
impl Strategy for EnablementRecovery {
    async fn propose(&self, ctx: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        Ok(self.select(ctx))
    }

    fn name(&self) -> &'static str {
        NAME
    }

    fn version(&self) -> u32 {
        VERSION
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::arbiter::Arbiter;
    use crate::testutil::{Fixture, ScriptedGate, Spec};
    use crawlx_core::safety::RiskClass;
    use crawlx_core::{ActionKind, TrustLane};

    /// A menu that reveals "Item A" in place, then closes again.
    fn menu_fixture() -> (Fixture, crawlx_core::ActionContextKey, ElementIdentityHash) {
        let mut f = Fixture::new(&[Spec::button("Menu"), Spec::button("Other")]);
        let menu = f.key("Menu", ActionKind::Click);
        let revealed = f.reveal_items(&["Item A"]);
        f.exec(&menu, f.open_cluster(), &revealed, TrustLane::TrustedUi);
        f.mark_risk(&menu, RiskClass::NavigationReveal);
        // the menu closed: Item A is known but hidden
        f.observe(&[Spec::button("Menu"), Spec::button("Other")]);
        (f, menu, revealed[0])
    }

    #[tokio::test]
    async fn proposes_the_next_path_step_toward_a_hidden_target() {
        let (f, menu, item) = menu_fixture();
        let ctx = f.ctx_with_phase(crate::switching::Phase::EnablementRecovery);
        assert_eq!(ctx.hidden_targets, vec![item]);
        let props = EnablementRecovery::default().propose(&ctx).await.unwrap();
        assert_eq!(props.len(), 1);
        let p = &props[0];
        assert_eq!(p.key, menu, "the graph's source action for the target");
        assert_eq!(p.expected.reveals, vec![item]);
        assert_eq!(p.strategy, NAME);
        assert!(p.confidence > 0.25 && p.confidence <= 1.0);
        // the arbiter prices the path: enablement_probability > 0
        let gate = ScriptedGate::allow_all();
        let round = Arbiter::default().choose(props, &ctx, &gate, &f.safety_ctx());
        let feats = crate::utility::Scorer::new(&ctx, Default::default())
            .features(&round.ranked[0].proposal, RiskClass::NavigationReveal);
        assert!(feats.enablement_probability > 0.0);
    }

    #[tokio::test]
    async fn unsafe_edges_are_never_part_of_a_path() {
        let (mut f, menu, _) = menu_fixture();
        f.mark_risk(&menu, RiskClass::PersistentWriteOwn);
        let ctx = f.ctx();
        assert!(EnablementRecovery::default()
            .propose(&ctx)
            .await
            .unwrap()
            .is_empty());
        // an unclassified key (kernel never saw it) is not path-safe either
        let (mut g, _, _) = menu_fixture();
        g.clear_risk();
        assert!(EnablementRecovery::default()
            .propose(&g.ctx())
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn re_reveals_through_the_known_control_in_another_cluster_without_a_reset() {
        // Item A is hidden in a cluster the recorded edge does not hold in, but the Menu that
        // revealed it is on screen: replay it directly instead of resetting the route
        let (mut f, menu, item) = menu_fixture();
        f.observe_at("/app?view=2", &[Spec::button("Menu"), Spec::button("Other")]);
        let ctx = f.ctx_with_phase(crate::switching::Phase::EnablementRecovery);
        assert!(ctx.hidden_targets.contains(&item));
        let props = EnablementRecovery::default().propose(&ctx).await.unwrap();
        assert_eq!(props.len(), 1);
        let p = &props[0];
        assert_eq!(p.key.element, menu.element);
        assert_eq!(p.key.action_kind, ActionKind::Click);
        assert_ne!(
            p.key.state_cluster, menu.state_cluster,
            "the key of the current cluster"
        );
        assert_eq!(p.expected.reveals, vec![item]);
        let feats =
            crate::utility::Scorer::new(&ctx, Default::default()).features(p, RiskClass::NavigationReveal);
        assert!(feats.enablement_probability > 0.0);
    }

    #[tokio::test]
    async fn a_target_the_reveal_exposed_again_is_proposed_first() {
        let (mut f, _, item) = menu_fixture();
        // the menu opened again: Item A is visible, unexercised and has a known revealer
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Other"),
            Spec::button("Item A"),
        ]);
        let ctx = f.ctx();
        assert!(ctx.newly_visible.contains(&item));
        let props = EnablementRecovery::default().propose(&ctx).await.unwrap();
        assert_eq!(props[0].key.element, item);
        assert_eq!(props[0].strategy, NAME);
    }

    /// Reveal steps are phase 2. While a visible control was never exercised
    /// (here `Other`) the greedy phase gets none; once it was, recovery may run in any phase.
    #[tokio::test]
    async fn reveal_steps_wait_for_an_empty_greedy_frontier_or_the_recovery_phase() {
        let (mut f, menu, item) = menu_fixture();
        assert!(EnablementRecovery::default()
            .propose(&f.ctx())
            .await
            .unwrap()
            .is_empty());
        let other = f.key("Other", ActionKind::Click);
        f.exec(&other, f.cluster(), &[], TrustLane::TrustedUi);
        f.observe(&[Spec::button("Menu"), Spec::button("Other")]);
        let props = EnablementRecovery::default().propose(&f.ctx()).await.unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].key.element, menu.element);
        assert_eq!(props[0].expected.reveals, vec![item]);
    }

    #[tokio::test]
    async fn nothing_to_do_without_hidden_targets() {
        let f = Fixture::new(&[Spec::button("Menu")]);
        assert!(EnablementRecovery::default()
            .propose(&f.ctx())
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn resets_through_a_known_route_when_the_source_is_not_here() {
        // Item A was revealed on /app by Menu; we are now on /other
        let (mut f, menu, item) = menu_fixture();
        f.observe_at("/other", &[Spec::button("Back")]);
        let ctx = f.ctx_with_phase(crate::switching::Phase::EnablementRecovery);
        assert!(ctx.hidden_targets.contains(&item));
        let props = EnablementRecovery::default().propose(&ctx).await.unwrap();
        // the path is: Navigate(/app) then Menu; only the first step is proposed
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].key.action_kind, ActionKind::Navigate);
        let crawlx_core::BrowserAction::Navigate { url } = &props[0].action else {
            panic!("expected navigate");
        };
        assert_eq!(url.path(), "/app");
        assert_ne!(props[0].key, menu);
    }

    #[tokio::test]
    async fn only_in_recovery_gates_on_phase() {
        let (f, _, _) = menu_fixture();
        let strat = EnablementRecovery::new(EnablementConfig {
            only_in_recovery: true,
            ..EnablementConfig::default()
        });
        assert!(strat.propose(&f.ctx()).await.unwrap().is_empty());
        let ctx = f.ctx_with_phase(crate::switching::Phase::EnablementRecovery);
        assert_eq!(strat.propose(&ctx).await.unwrap().len(), 1);
    }
}
