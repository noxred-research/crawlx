//! `state_novelty`: prefer actions whose expected after-state is novel
//! (state-novelty strategies run in parallel as proposal sources;
//! also the StateRecovery proposer).
//!
//! * Executed keys: the after-clusters they led to are scored `1/(1 + visits)`
//!   and blended with the last `StateDiff` novelty (share of new or renamed
//!   affordances).
//! * Never-executed keys: a structural prior (unvisited link destination,
//!   expandable control, hover reveal, ...).
//! * In `StateRecovery` (or when nothing local is unexercised) it also
//!   proposes the first step toward the cluster with the most unexercised keys.

use crate::context::DecisionContext;
use crate::error::StrategyError;
use crate::frontier::{dedupe_groups, resolve_href, Intent, KeyedAction};
use crate::switching::Phase;
use crate::utility::{micros, narrow};
use crate::Strategy;
use async_trait::async_trait;
use crawlx_core::proposal::ActionProposal;
use crawlx_core::StateClusterId;
use crawlx_graph::PathGoal;

/// Strategy name recorded in proposal attribution.
pub const NAME: &str = "state_novelty";
/// Version of the novelty strategy logic, recorded in proposal attribution.
pub const VERSION: u32 = 2;

/// Tuning knobs of [`StateNovelty`].
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct NoveltyConfig {
    /// Local proposals per round.
    pub n: usize,
    /// Recovery proposals per round.
    pub recovery_n: usize,
    /// Confidence floor; confidence = `floor + span · novelty`.
    pub floor: f32,
    /// Confidence range above `floor`, scaled by expected novelty in `[0, 1]`.
    pub span: f32,
}

impl Default for NoveltyConfig {
    fn default() -> Self {
        Self {
            n: 5,
            recovery_n: 3,
            floor: 0.3,
            span: 0.6,
        }
    }
}

/// Strategy that prefers actions whose expected after-state is novel.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateNovelty {
    cfg: NoveltyConfig,
}

impl StateNovelty {
    /// Create the strategy with `cfg`.
    #[must_use]
    pub const fn new(cfg: NoveltyConfig) -> Self {
        Self { cfg }
    }

    /// Expected novelty of the after-state of `ka`, in `[0, 1]`.
    #[must_use]
    pub fn expected_novelty(ctx: &DecisionContext<'_>, ka: &KeyedAction) -> f32 {
        let after = ctx.frontier.after_clusters(&ka.key);
        if after.is_empty() {
            return Self::prior(ctx, ka);
        }
        let total: u32 = after.iter().map(|(_, n)| *n).sum();
        let weighted: f32 = after
            .iter()
            .map(|(c, n)| *n as f32 / (1.0 + ctx.frontier.cluster_visits(*c) as f32))
            .sum();
        let mean = weighted / total.max(1) as f32;
        match ctx.frontier.last_diff(&ka.key) {
            Some(d) => 0.5 * mean + 0.5 * d.clamp(0.0, 1.0),
            None => mean,
        }
    }

    fn prior(ctx: &DecisionContext<'_>, ka: &KeyedAction) -> f32 {
        let Some(cand) = ctx.candidates.get(ka.candidate) else {
            return 0.0;
        };
        if let Some(href) = cand.descriptor.href.as_deref() {
            return match resolve_href(&ctx.bundle, href) {
                Some(u) if !ctx.frontier.url_visited(u.as_str()) => 0.9,
                Some(_) => 0.15,
                None => 0.1,
            };
        }
        let attr = |k: &str| cand.descriptor.attributes.get(k).is_some_and(|v| v != "false");
        match ka.intent {
            // a disclosure control (`aria-expanded`/`aria-haspopup`) is as likely to reveal
            // under the pointer as on activation (hover menus)
            Intent::Click | Intent::KeyboardActivate | Intent::Hover
                if attr("aria-expanded") || attr("aria-haspopup") =>
            {
                0.6
            }
            Intent::Hover => 0.35,
            Intent::Scroll => 0.3,
            // a drag moves an item between containers: a state change is likely
            Intent::Drag(_) => 0.5,
            Intent::Type(_)
            | Intent::Select
            | Intent::SetChecked(_)
            | Intent::SetRange
            | Intent::Upload(_) => 0.25,
            Intent::Click | Intent::KeyboardActivate | Intent::Keys | Intent::Dismiss => 0.4,
        }
    }

    fn local(&self, ctx: &DecisionContext<'_>) -> Vec<ActionProposal> {
        let acts = ctx.keyed_actions();
        let sampled = dedupe_groups(acts, ctx.seed, &|g| ctx.frontier.group_diverged(g)).sampled;
        let mut scored: Vec<(i64, u64, usize, f32)> = sampled
            .into_iter()
            .filter(|&i| ctx.frontier.is_proposable(&acts[i].key))
            .map(|i| {
                let nov = Self::expected_novelty(ctx, &acts[i]);
                let tie = ctx.seed.derive("novelty-tie", &[acts[i].key.id().0.as_slice()]);
                let mut first = [0_u8; 8];
                first.copy_from_slice(&tie[..8]);
                // higher novelty first -> sort ascending on the negated score
                (-micros(nov), u64::from_le_bytes(first), i, nov)
            })
            .collect();
        scored.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        scored
            .into_iter()
            .filter_map(|(_, _, i, nov)| {
                ctx.proposal_for(&acts[i], NAME, VERSION, self.cfg.floor + self.cfg.span * nov)
            })
            .take(self.cfg.n)
            .collect()
    }

    /// First step toward clusters that still hold unexercised keys.
    fn recovery(&self, ctx: &DecisionContext<'_>) -> Vec<ActionProposal> {
        let mut targets: Vec<(u32, StateClusterId)> = ctx
            .ledger
            .unexercised_by_cluster()
            .into_iter()
            .filter(|(c, _)| *c != ctx.cluster)
            .map(|(c, n)| (n, c))
            .collect();
        // most unexercised keys first, then cluster id (deterministic)
        targets.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let mut out: Vec<ActionProposal> = Vec::new();
        for (_, cluster) in targets.into_iter().take(self.cfg.recovery_n * 2) {
            if out.len() >= self.cfg.recovery_n {
                break;
            }
            let p = self.step_toward(ctx, cluster);
            if let Some(p) = p {
                if !out.iter().any(|q| q.key.id() == p.key.id()) {
                    out.push(p);
                }
            }
        }
        out
    }

    fn step_toward(&self, ctx: &DecisionContext<'_>, cluster: StateClusterId) -> Option<ActionProposal> {
        if let Some(plan) = ctx.path_plan(PathGoal::ReachCluster(cluster)) {
            if let Some(step) = plan.steps.first() {
                if let Some(route) = &step.navigate {
                    return ctx.navigate_proposal(route, NAME, VERSION, narrow(plan.reliability));
                }
                let ka = ctx
                    .keyed_actions()
                    .iter()
                    .find(|ka| ka.key.id() == step.source_action)?;
                return ctx.proposal_for(ka, NAME, VERSION, narrow(plan.reliability));
            }
        }
        let route = ctx.graph.route_of(cluster)?;
        let entry = ctx.frontier.routes().get(route)?;
        if entry.cluster != cluster
            && crawlx_core::ActionContextKey::coarsened_route_cluster(route) != cluster
        {
            return None;
        }
        ctx.navigate_proposal(route, NAME, VERSION, 0.5)
    }
}

#[async_trait]
impl Strategy for StateNovelty {
    async fn propose(&self, ctx: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        let mut out = self.local(ctx);
        if ctx.phase == Phase::StateRecovery || ctx.stall.unexercised_here == 0 {
            out.extend(self.recovery(ctx));
        }
        Ok(out)
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
    use crate::testutil::{Fixture, Spec};
    use crawlx_core::{ActionKind, TrustLane};

    #[tokio::test]
    async fn prefers_actions_leading_to_unseen_clusters() {
        let mut f = Fixture::new(&[Spec::button("Stale"), Spec::button("Fresh")]);
        let stale = f.key("Stale", ActionKind::Click);
        let fresh = f.key("Fresh", ActionKind::Click);
        let hub = f.cluster_n(1);
        let rare = f.cluster_n(2);
        f.exec(&stale, hub, &[], TrustLane::TrustedUi);
        f.exec(&fresh, rare, &[], TrustLane::TrustedUi);
        // the hub is a busy page
        f.state_mut().frontier_mut().cluster_visits.insert(hub, 9);
        let ctx = f.ctx();
        let props = StateNovelty::default().propose(&ctx).await.unwrap();
        let pos = |k: &crawlx_core::ActionContextKey| props.iter().position(|p| p.key == *k).unwrap();
        assert!(
            pos(&fresh) < pos(&stale),
            "the rarely visited after-cluster is more novel"
        );
        let conf = |k: &crawlx_core::ActionContextKey| props[pos(k)].confidence;
        assert!(conf(&fresh) > conf(&stale));
        assert!(props
            .iter()
            .all(|p| p.strategy == NAME && p.strategy_version == VERSION));
    }

    #[tokio::test]
    async fn unvisited_link_destinations_beat_visited_ones() {
        let mut f = Fixture::new(&[Spec::link("Docs", "/docs"), Spec::link("Self", "/app")]);
        f.mark_url_visited("https://app.example/app");
        let ctx = f.ctx();
        let props = StateNovelty::default().propose(&ctx).await.unwrap();
        assert_eq!(f.name_of(&props[0].key.element), "Docs");
    }

    #[tokio::test]
    async fn recovery_steps_toward_a_cluster_with_unexercised_keys() {
        // an earlier page (route /list) still holds unexercised keys; we are somewhere else
        let mut f = Fixture::new(&[Spec::button("Open")]);
        let list = f.add_page("/list", &[Spec::button("Item 1"), Spec::button("Item 2")]);
        f.observe_at("/other", &[Spec::button("Back")]);
        let ctx = f.ctx_with_phase(crate::switching::Phase::StateRecovery);
        let props = StateNovelty::default().propose(&ctx).await.unwrap();
        let nav: Vec<_> = props
            .iter()
            .filter(|p| p.key.action_kind == ActionKind::Navigate)
            .collect();
        assert_eq!(
            nav.len(),
            2,
            "one reset navigation per known route with unexercised keys"
        );
        let crawlx_core::BrowserAction::Navigate { url } = &nav[0].action else {
            panic!("expected navigate");
        };
        assert_eq!(
            url.path(),
            "/list",
            "the cluster with the most unexercised keys comes first"
        );
        assert!(list != f.cluster());
    }
    #[test]
    fn route_coarsened_remaining_keys_still_have_a_recovery_navigation() {
        let mut fixture = Fixture::new(&[Spec::button("Open")]);
        fixture.add_page("/list", &[Spec::button("Delete")]);
        let mut key = fixture.key("Delete", ActionKind::Click);
        key.state_cluster = key.coarsened_cluster();
        fixture.state_mut().ledger_mut().register(&key);
        fixture
            .state_mut()
            .graph_mut()
            .set_cluster_route(key.state_cluster, key.route_template.clone());
        fixture.observe_at("/other", &[Spec::button("Back")]);
        let context = fixture.ctx_with_phase(crate::switching::Phase::StateRecovery);
        let proposal = StateNovelty::default()
            .step_toward(&context, key.state_cluster)
            .expect("coarsened keys remain reachable through their route");
        let crawlx_core::BrowserAction::Navigate { url } = proposal.action else {
            panic!("expected recovery navigation");
        };
        assert_eq!(url.path(), "/list");
    }
}
