//! `interaction_bfs`: the paper's layered-queue baseline.
//!
//! Never-tried visible candidates come first (layer `W = 0`), then once-tried
//! ones, and so on, ranked by `Score = W + 0.3·Z + E`. The action vocabulary
//! per candidate comes from `crawlx-elements`; template groups are sampled
//! (§4.4) and kernel-denied or cooling-down keys are removed.

use crate::context::DecisionContext;
use crate::error::StrategyError;
use crate::frontier::dedupe_groups;
use crate::utility::micros;
use crate::Strategy;
use async_trait::async_trait;
use crawlx_core::proposal::ActionProposal;

/// Strategy name recorded in proposal attribution.
pub const NAME: &str = "interaction_bfs";
/// Bump when the proposals for an unchanged `DecisionContext` can change.
pub const VERSION: u32 = 1;

/// BFS knobs.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct BfsConfig {
    /// Proposals per round (default 5).
    pub n: usize,
    /// Constant confidence of a deterministic strategy.
    pub confidence: f32,
    /// Sample template groups instead of enumerating every instance.
    pub dedupe: bool,
}

impl Default for BfsConfig {
    fn default() -> Self {
        Self {
            n: 5,
            confidence: 0.5,
            dedupe: true,
        }
    }
}

/// The baseline strategy.
#[derive(Clone, Copy, Debug, Default)]
pub struct InteractionBfs {
    cfg: BfsConfig,
}

impl InteractionBfs {
    /// Create the strategy with `cfg`.
    #[must_use]
    pub const fn new(cfg: BfsConfig) -> Self {
        Self { cfg }
    }

    /// The proposals, synchronously (the trait method wraps this).
    #[must_use]
    pub fn select(&self, ctx: &DecisionContext<'_>) -> Vec<ActionProposal> {
        let acts = ctx.keyed_actions();
        let sampled: Vec<usize> = if self.cfg.dedupe {
            dedupe_groups(acts, ctx.seed, &|g| ctx.frontier.group_diverged(g)).sampled
        } else {
            (0..acts.len()).collect()
        };
        let mut scored: Vec<(i64, u64, usize)> = sampled
            .into_iter()
            .filter(|&i| ctx.frontier.is_proposable(&acts[i].key))
            .map(|i| {
                let ka = &acts[i];
                let score = ctx.frontier.queue_score(&ka.key, &ka.family);
                let tie_bytes = ctx.seed.derive("bfs-tie", &[ka.key.id().0.as_slice()]);
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
impl Strategy for InteractionBfs {
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
    use crate::testutil::{Fixture, Spec};
    use crawlx_core::{ActionKind, TrustLane};

    #[tokio::test]
    async fn never_tried_candidates_come_first_and_the_vocabulary_is_respected() {
        let mut f = Fixture::new(&[
            Spec::button("Open"),
            Spec::button("Next"),
            Spec::textbox("Search", &[("type", "search")]),
            Spec::checkbox("Remember"),
        ]);
        let open = f.key("Open", ActionKind::Click);
        f.exec(&open, f.cluster(), &[], TrustLane::TrustedUi);
        let ctx = f.ctx();
        let props = InteractionBfs::new(BfsConfig {
            n: 20,
            ..BfsConfig::default()
        })
        .propose(&ctx)
        .await
        .unwrap();
        // the vocabulary: textbox -> Type only, checkbox -> SetChecked only, button -> Click|KeyboardActivate
        for p in &props {
            let name = f.name_of(&p.key.element);
            let kind = p.key.action_kind;
            match name.as_str() {
                "Search" => assert_eq!(kind, ActionKind::Type),
                "Remember" => assert_eq!(kind, ActionKind::SetChecked),
                _ => assert!(matches!(kind, ActionKind::Click | ActionKind::KeyboardActivate)),
            }
            assert_eq!(p.strategy, NAME);
            assert_eq!(p.strategy_version, VERSION);
            assert_eq!(p.epoch, f.bundle.epoch);
        }
        // the only tried key is last
        let last = props.last().unwrap();
        assert_eq!(last.key, open);
        assert!(props[..props.len() - 1]
            .iter()
            .all(|p| ctx.ledger.trusted_attempts(&p.key) == 0));
        assert_eq!(props.len(), 6, "2 buttons x 2 kinds + type + set_checked");
    }

    #[tokio::test]
    async fn limits_to_n_and_skips_cooldown_and_blocked_keys() {
        let mut f = Fixture::new(&[
            Spec::button("A"),
            Spec::button("B"),
            Spec::button("C"),
            Spec::button("D"),
        ]);
        let b = f.key("B", ActionKind::Click);
        f.block(&b);
        let ctx = f.ctx();
        let bfs = InteractionBfs::default();
        let props = bfs.propose(&ctx).await.unwrap();
        assert_eq!(props.len(), 5);
        assert!(props.iter().all(|p| p.key != b), "kernel-denied keys are removed");
        // deterministic: same context, same list
        let again = bfs.propose(&ctx).await.unwrap();
        let ids = |v: &[ActionProposal]| v.iter().map(|p| p.key.id()).collect::<Vec<_>>();
        assert_eq!(ids(&props), ids(&again));
    }

    #[tokio::test]
    async fn family_pressure_defers_crowded_families() {
        // Z(e): exercising "A" makes its stable-path family (all buttons) costlier,
        // so a different-role control wins over the next same-family button.
        let mut f = Fixture::new(&[Spec::button("A"), Spec::button("B"), Spec::checkbox("Remember")]);
        let a = f.key("A", ActionKind::Click);
        f.exec(&a, f.cluster(), &[], TrustLane::TrustedUi);
        f.exec(&a, f.cluster(), &[], TrustLane::TrustedUi);
        let ctx = f.ctx();
        let props = InteractionBfs::new(BfsConfig {
            n: 1,
            ..BfsConfig::default()
        })
        .select(&ctx);
        assert_eq!(f.name_of(&props[0].key.element), "Remember");
    }

    #[tokio::test]
    async fn paper_compat_uses_element_layers() {
        let mut f = Fixture::new(&[Spec::button("A"), Spec::button("B")]);
        let a_click = f.key("A", ActionKind::Click);
        f.exec(&a_click, f.cluster(), &[], TrustLane::TrustedUi);
        f.set_paper_compat();
        let ctx = f.ctx();
        let props = InteractionBfs::new(BfsConfig {
            n: 20,
            ..BfsConfig::default()
        })
        .select(&ctx);
        // under w_element, A's keyboard_activate key shares A's layer (1): it sorts after every B key
        let pos = |kind: ActionKind, name: &str| {
            props
                .iter()
                .position(|p| p.key.action_kind == kind && f.name_of(&p.key.element) == name)
                .unwrap()
        };
        assert!(pos(ActionKind::KeyboardActivate, "A") > pos(ActionKind::Click, "B"));
        assert!(pos(ActionKind::KeyboardActivate, "A") > pos(ActionKind::KeyboardActivate, "B"));
    }
}
