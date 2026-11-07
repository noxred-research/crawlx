//! `event_driven`: act first on what an event just exposed.
//!
//! A click that opens a menu, a request that renders new rows or a timer that raises a dialog all
//! change the observation: the session's newest bundle shows identities its previous bundle did
//! not ([`DecisionContext::newly_visible`]). Those controls are the cheapest new coverage on the
//! board and the page may close them again (a transient menu, a toast), so this strategy proposes
//! the actions of exactly those controls, at a confidence above the deterministic baseline so the
//! arbiter ranks them first among otherwise equal keys.
//!
//! The strategy abstains when nothing new appeared (including the first observation of a
//! session). It never decides safety: the arbiter classifies every proposal with the kernel before
//! scoring, exactly like the other strategies.

use crate::context::DecisionContext;
use crate::error::StrategyError;
use crate::frontier::dedupe_groups;
use crate::utility::micros;
use crate::Strategy;
use async_trait::async_trait;
use crawlx_core::proposal::ActionProposal;

/// Strategy name as it appears on proposals and in `dynamic.strategies` (`event_driven`).
pub const NAME: &str = "event_driven";
/// Bump when the proposals for an unchanged `DecisionContext` can change.
pub const VERSION: u32 = 2;

/// Knobs of [`EventDriven`].
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct EventDrivenConfig {
    /// Most proposals per round; the rest of the revealed controls wait for the next round.
    pub n: usize,
    /// Confidence of every proposal, in `[0, 1]`. Above the deterministic strategies' `0.5` so
    /// freshly exposed controls outrank equally novel old ones.
    pub confidence: f32,
    /// Sample template groups (§4.4) instead of enumerating every revealed row.
    pub dedupe: bool,
}

impl Default for EventDrivenConfig {
    fn default() -> Self {
        Self {
            n: 5,
            confidence: 0.8,
            dedupe: true,
        }
    }
}

/// Proposes the actions of controls that are new since the previous observation.
#[derive(Clone, Copy, Debug, Default)]
pub struct EventDriven {
    cfg: EventDrivenConfig,
}

impl EventDriven {
    /// A strategy with the given knobs.
    #[must_use]
    pub const fn new(cfg: EventDrivenConfig) -> Self {
        Self { cfg }
    }

    /// The proposals, synchronously (the trait method wraps this).
    #[must_use]
    pub fn select(&self, ctx: &DecisionContext<'_>) -> Vec<ActionProposal> {
        if ctx.newly_visible.is_empty() {
            return Vec::new();
        }
        let acts = ctx.keyed_actions();
        let sampled: Vec<usize> = if self.cfg.dedupe {
            dedupe_groups(acts, ctx.seed, &|g| ctx.frontier.group_diverged(g)).sampled
        } else {
            (0..acts.len()).collect()
        };
        let mut scored: Vec<(i64, u64, usize)> = sampled
            .into_iter()
            .filter(|&i| {
                let ka = &acts[i];
                ctx.resolved
                    .get(ka.candidate)
                    .is_some_and(|r| ctx.newly_visible.contains(&r.hash))
                    && ctx.frontier.is_proposable(&ka.key)
            })
            .map(|i| {
                let ka = &acts[i];
                // the layered queue ranks never-tried keys first, as the baseline does
                let score = ctx.frontier.queue_score(&ka.key, &ka.family);
                let tie_bytes = ctx.seed.derive("event-tie", &[ka.key.id().0.as_slice()]);
                let mut first = [0_u8; 8];
                first.copy_from_slice(&tie_bytes[..8]);
                (micros(score), u64::from_le_bytes(first), i)
            })
            .collect();
        scored.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
        scored
            .into_iter()
            .filter_map(|(_, _, i)| ctx.proposal_for(&acts[i], NAME, VERSION, self.cfg.confidence))
            .take(self.cfg.n)
            .collect()
    }
}

#[async_trait]
impl Strategy for EventDriven {
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
    use crate::interaction_bfs::InteractionBfs;
    use crate::testutil::{Fixture, ScriptedGate, Spec};
    use crawlx_core::{ActionKind, TrustLane};

    fn menu_page() -> Fixture {
        Fixture::new(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
        ])
    }

    #[tokio::test]
    async fn abstains_on_the_first_observation_of_a_session() {
        let f = menu_page();
        let ctx = f.ctx();
        assert!(ctx.newly_visible.is_empty());
        assert!(EventDriven::default().propose(&ctx).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn abstains_when_the_next_observation_shows_nothing_new() {
        let mut f = menu_page();
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
        ]);
        let ctx = f.ctx();
        assert!(ctx.newly_visible.is_empty());
        assert!(EventDriven::default().propose(&ctx).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn proposes_only_controls_the_previous_observation_did_not_show() {
        let mut f = menu_page();
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
            Spec::button("Export data"),
            Spec::button("Import data"),
        ]);
        let ctx = f.ctx();
        assert_eq!(ctx.newly_visible.len(), 2);
        let props = EventDriven::default().propose(&ctx).await.unwrap();
        assert!(!props.is_empty());
        let names: Vec<String> = props.iter().map(|p| f.name_of(&p.key.element)).collect();
        assert!(
            names.iter().all(|n| n == "Export data" || n == "Import data"),
            "{names:?}"
        );
        for p in &props {
            assert_eq!(p.strategy, "event_driven");
            assert_eq!(p.strategy_version, VERSION);
            assert_eq!(p.epoch, f.bundle.epoch);
            assert!((p.confidence - 0.8).abs() < 1e-6);
        }
    }

    #[tokio::test]
    async fn a_revealed_control_stays_new_while_visible_and_unexercised() {
        let mut f = menu_page();
        let with_item = [
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
            Spec::button("Export data"),
        ];
        f.observe(&with_item);
        assert_eq!(f.ctx().newly_visible.len(), 1);
        // still showing, still unexercised: still the cheapest coverage on the board
        f.observe(&with_item);
        assert_eq!(f.ctx().newly_visible.len(), 1);
        // exercised: no longer new
        let export = f.key("Export data", ActionKind::Click);
        f.exercise(&export, TrustLane::TrustedUi);
        f.observe(&with_item);
        assert!(f.ctx().newly_visible.is_empty());
        // it leaves and returns: an exercised control is not an event again
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
        ]);
        f.observe(&with_item);
        assert!(f.ctx().newly_visible.is_empty());
    }

    #[tokio::test]
    async fn a_revealed_control_that_hides_again_leaves_the_set() {
        let mut f = menu_page();
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
            Spec::button("Export data"),
        ]);
        assert_eq!(f.ctx().newly_visible.len(), 1);
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
        ]);
        assert!(f.ctx().newly_visible.is_empty());
    }

    #[tokio::test]
    async fn skips_revealed_keys_in_cooldown_and_respects_the_bound() {
        let mut f = menu_page();
        let revealed: Vec<Spec> = (0..8)
            .map(|i| Spec::button(&format!("Item {}", crate::testutil::letters(i))))
            .collect();
        let mut specs = vec![
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
        ];
        specs.extend(revealed);
        f.observe(&specs);
        let strategy = EventDriven::new(EventDrivenConfig {
            n: 3,
            dedupe: false,
            ..EventDrivenConfig::default()
        });
        let ctx = f.ctx();
        let props = strategy.propose(&ctx).await.unwrap();
        assert_eq!(props.len(), 3);
        let blocked = props[0].key.clone();
        drop(ctx);
        f.block(&blocked);
        let again = strategy.propose(&f.ctx()).await.unwrap();
        assert_eq!(again.len(), 3);
        assert!(again.iter().all(|p| p.key != blocked));
    }

    #[tokio::test]
    async fn revealed_controls_win_the_arbiter_over_equally_novel_old_ones() {
        let mut f = menu_page();
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
            Spec::button("Export data"),
        ]);
        let ctx = f.ctx();
        let mut proposals = InteractionBfs::default().propose(&ctx).await.unwrap();
        let event = EventDriven::default().propose(&ctx).await.unwrap();
        assert!(!event.is_empty());
        proposals.extend(event);
        let gate = ScriptedGate::allow_all();
        let round = Arbiter::default().choose(proposals, &ctx, &gate, &f.safety_ctx());
        let chosen = round.chosen.expect("a proposal wins");
        assert_eq!(f.name_of(&chosen.proposal.key.element), "Export data");
        assert_eq!(chosen.proposal.strategy, NAME);
    }

    #[tokio::test]
    async fn the_same_context_gives_the_same_proposals() {
        let mut f = menu_page();
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
            Spec::button("One"),
            Spec::button("Two"),
            Spec::button("Three"),
        ]);
        let ctx = f.ctx();
        let a = EventDriven::default().propose(&ctx).await.unwrap();
        let b = EventDriven::default().propose(&ctx).await.unwrap();
        let keys = |v: &[ActionProposal]| v.iter().map(|p| p.key.id()).collect::<Vec<_>>();
        assert_eq!(keys(&a), keys(&b));
    }

    #[tokio::test]
    async fn exercised_keys_are_not_new_coverage() {
        let mut f = menu_page();
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
            Spec::button("One"),
            Spec::button("Two"),
        ]);
        let one = f.key("One", ActionKind::Click);
        f.exercise(&one, TrustLane::TrustedUi);
        // the exercise re-observed the page (nothing new); the controls leave and return
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
        ]);
        f.observe(&[
            Spec::button("Menu"),
            Spec::button("Help"),
            Spec::button("Profile"),
            Spec::button("One"),
            Spec::button("Two"),
        ]);
        let props = EventDriven::new(EventDrivenConfig {
            dedupe: false,
            ..EventDrivenConfig::default()
        })
        .propose(&f.ctx())
        .await
        .unwrap();
        assert!(
            props.iter().all(|p| p.key.element != one.element),
            "exercised One is not proposed as new coverage"
        );
        assert!(props.iter().any(|p| f.name_of(&p.key.element) == "Two"));
    }
}
