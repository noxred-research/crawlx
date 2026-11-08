//! The arbiter: merge, classify, score, order.
//!
//! Order of operations is deliberate: **kernel classification precedes
//! scoring**, so a hard denial never competes on utility. Proposals are merged
//! by `ActionContextKey::id` (the highest-confidence proposer is primary,
//! the rest are kept as co-proposers), classified, split into
//! allowed / denied / approval-required, scored over the survivors and ordered
//! with seeded tie-breaks. Greedy exploration drains fresh admitted context keys
//! before covered repeats; recovery and paper-compatible scoring retain path repeats.
//! Ranking is a pure function of `(proposals as a set, DecisionContext, seed)`.

use crate::context::DecisionContext;
use crate::utility::{micros, Scorer, UtilityWeights};
use crawlx_core::proposal::ActionProposal;
use crawlx_core::repo::{SafetyContext, SafetyGate};
use crawlx_core::safety::{SafetyDecision, SafetyVerdict};
use crawlx_core::{ActionContextId, ActionKind};
use rand::Rng;
use std::collections::BTreeMap;

/// Version of the arbiter logic and default coefficients; recorded with the run config digest.
pub const ARBITER_VERSION: u32 = 2;

/// Versioned arbiter configuration (coefficients are experimental starting values).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct ArbiterConfig {
    /// Utility coefficients applied to every surviving proposal.
    pub weights: UtilityWeights,
    /// Arbiter logic version ([`ARBITER_VERSION`] by default), recorded with the run config digest.
    pub version: u32,
}

impl Default for ArbiterConfig {
    fn default() -> Self {
        Self {
            weights: UtilityWeights::default(),
            version: ARBITER_VERSION,
        }
    }
}

/// A surviving proposal with its score and verdict.
#[derive(Clone, Debug)]
pub struct Ranked {
    /// Primary proposal for the merged key (the highest-confidence proposer).
    pub proposal: ActionProposal,
    /// Scalar utility score; higher ranks first.
    pub utility: f32,
    /// Kernel verdict for the proposal (`Allow` for ranked survivors).
    pub verdict: SafetyVerdict,
    /// Other `(strategy, version)` pairs that proposed the same key (attribution), sorted.
    pub co_proposers: Vec<(&'static str, u32)>,
}

/// Why a proposal was dropped before classification.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InvalidReason {
    /// The proposal's epoch is newer than the context's (cannot be derived from it).
    EpochFromFuture,
    /// `key.action_kind` disagrees with the action.
    KindMismatch,
    /// A targeted action carries no locator.
    MissingLocator,
    /// The key belongs to another principal.
    PrincipalMismatch,
}

/// Result of one arbitration round.
#[derive(Clone, Debug, Default)]
pub struct ArbiterRound {
    /// Allowed survivors, best first.
    pub ranked: Vec<Ranked>,
    /// Hard denials (never scored); one entry per merged key.
    pub denied: Vec<(ActionProposal, SafetyVerdict)>,
    /// Parked for approval; they leave the round.
    pub approval_required: Vec<(ActionProposal, SafetyVerdict)>,
    /// Structurally invalid proposals.
    pub invalid: Vec<(ActionProposal, InvalidReason)>,
    /// `ranked[0]`, if any.
    pub chosen: Option<Ranked>,
}

/// A merged, kernel-allowed proposal with its co-proposers and verdict.
type Survivor = (ActionProposal, Vec<(&'static str, u32)>, SafetyVerdict);

/// The arbiter.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arbiter {
    cfg: ArbiterConfig,
}

const fn needs_locator(kind: ActionKind) -> bool {
    !matches!(
        kind,
        ActionKind::Scroll
            | ActionKind::Keys
            | ActionKind::Navigate
            | ActionKind::SwitchTab
            | ActionKind::CloseTab
    )
}

fn validate(p: &ActionProposal, ctx: &DecisionContext<'_>) -> Result<(), InvalidReason> {
    if p.epoch > ctx.bundle.epoch {
        return Err(InvalidReason::EpochFromFuture);
    }
    if p.key.action_kind != p.action.kind() {
        return Err(InvalidReason::KindMismatch);
    }
    if needs_locator(p.key.action_kind) && p.action.target().is_none() {
        return Err(InvalidReason::MissingLocator);
    }
    if p.key.principal != ctx.principal {
        return Err(InvalidReason::PrincipalMismatch);
    }
    Ok(())
}

/// Primary-proposer order: highest confidence, then name, then higher version.
fn primary_order(a: &ActionProposal, b: &ActionProposal) -> std::cmp::Ordering {
    b.confidence
        .total_cmp(&a.confidence)
        .then(a.strategy.cmp(b.strategy))
        .then(b.strategy_version.cmp(&a.strategy_version))
}

impl Arbiter {
    /// Create an arbiter that scores with `cfg`.
    #[must_use]
    pub const fn new(cfg: ArbiterConfig) -> Self {
        Self { cfg }
    }

    /// Configuration this arbiter was built with.
    #[must_use]
    pub const fn config(&self) -> &ArbiterConfig {
        &self.cfg
    }

    /// Arbitrate `proposals` for the frozen `ctx`. `safety_ctx` carries the
    /// run-level facts (profile, principal, scope, sinks); per-proposal target
    /// facts come from the observation the proposal was derived from.
    #[must_use]
    pub fn choose(
        &self,
        proposals: Vec<ActionProposal>,
        ctx: &DecisionContext<'_>,
        kernel: &dyn SafetyGate,
        safety_ctx: &SafetyContext,
    ) -> ArbiterRound {
        let mut round = ArbiterRound::default();

        // 1. structural validation
        let mut valid: Vec<ActionProposal> = Vec::with_capacity(proposals.len());
        for p in proposals {
            match validate(&p, ctx) {
                Ok(()) => valid.push(p),
                Err(why) => round.invalid.push((p, why)),
            }
        }

        // 2. merge by key id (BTreeMap: deterministic order independent of input order)
        let mut merged: BTreeMap<ActionContextId, Vec<ActionProposal>> = BTreeMap::new();
        for p in valid {
            merged.entry(p.key.id()).or_default().push(p);
        }
        let mut unique: Vec<(ActionProposal, Vec<(&'static str, u32)>)> = Vec::with_capacity(merged.len());
        for (_, mut group) in merged {
            group.sort_by(primary_order);
            let mut it = group.into_iter();
            let Some(primary) = it.next() else { continue };
            let mut co: Vec<(&'static str, u32)> = it
                .map(|q| (q.strategy, q.strategy_version))
                .filter(|c| *c != (primary.strategy, primary.strategy_version))
                .collect();
            co.sort_unstable();
            co.dedup();
            unique.push((primary, co));
        }

        // 3. kernel classification BEFORE scoring; 4. drop denies, park approvals
        let mut survivors: Vec<Survivor> = Vec::new();
        for (p, co) in unique {
            let c = ctx.safety_context(safety_ctx, &p.key);
            let verdict = kernel.classify(&p, &c);
            match verdict.decision {
                SafetyDecision::Deny => round.denied.push((p, verdict)),
                SafetyDecision::ApprovalRequired => round.approval_required.push((p, verdict)),
                SafetyDecision::Allow => survivors.push((p, co, verdict)),
            }
        }

        // 5. score survivors; 6. seeded tie-break (one draw per survivor in key-id order)
        // keyed by principal, never by the random session id: the same seed and inputs must give
        // the same draws in every run (the driver gives each session of a role its own seed)
        let principal_bytes = ctx.principal.0.as_bytes();
        let index_bytes = ctx.decision_index.to_le_bytes();
        let mut rng = ctx.seed.rng("arbiter", &[principal_bytes, &index_bytes]);
        let scorer = Scorer::new(ctx, self.cfg.weights);
        // Greedy exploration tries fresh contexts before repeating attempted keys.
        // Failed browser actions must leave this tier without claiming coverage.
        // Recovery may still need covered path steps.
        let greedy = !ctx.frontier.cfg().paper_compat
            && self.cfg.weights != UtilityWeights::paper_compat()
            && matches!(ctx.phase, crate::Phase::Greedy | crate::Phase::System1);
        let mut scored: Vec<(bool, i64, u64, ActionContextId, Ranked)> = survivors
            .into_iter()
            .map(|(p, co, verdict)| {
                let utility = scorer.score(&p, verdict.risk_class);
                let tie = rng.next_u64();
                let id = p.key.id();
                let q = micros(utility);
                (
                    greedy
                        && ctx.ledger.trusted_attempts(&p.key) == 0
                        && ctx.ledger.failed_attempts(&p.key) == 0,
                    q,
                    tie,
                    id,
                    Ranked {
                        proposal: p,
                        utility,
                        verdict,
                        co_proposers: co,
                    },
                )
            })
            .collect();
        scored.sort_by(|a, b| {
            b.0.cmp(&a.0)
                .then(b.1.cmp(&a.1))
                .then(a.2.cmp(&b.2))
                .then(a.3.cmp(&b.3))
        });
        round.ranked = scored.into_iter().map(|(_, _, _, _, r)| r).collect();
        round.chosen = round.ranked.first().cloned();
        round
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testutil::{Fixture, ScriptedGate, Spec};
    use crawlx_core::seed::CrawlSeed;
    use crawlx_core::TrustLane;

    fn proposals_for(f: &Fixture, names: &[&str], strategy: &'static str, conf: f32) -> Vec<ActionProposal> {
        let ctx = f.ctx();
        names
            .iter()
            .map(|n| {
                let ka = ctx
                    .keyed_actions()
                    .iter()
                    .find(|a| a.candidate == f.index_of(n) && a.key.action_kind == ActionKind::Click)
                    .unwrap();
                ctx.proposal_for(ka, strategy, 1, conf).unwrap()
            })
            .collect()
    }

    #[test]
    fn denied_proposals_are_never_ranked_and_kernel_runs_before_scoring() {
        let f = Fixture::new(&[
            Spec::link("Open", "/open"),
            Spec::button("Delete account"),
            Spec::link("Next", "/next"),
        ]);
        let props = proposals_for(&f, &["Open", "Delete account", "Next"], "bfs", 0.5);
        let kernel = f.kernel();
        let ctx = f.ctx();
        let round = Arbiter::default().choose(props, &ctx, &kernel, &f.safety_ctx());
        assert_eq!(round.denied.len(), 1, "Delete is a hard deny under read_only");
        assert!(round.denied.iter().all(|(p, v)| p.key.element
            == f.key("Delete account", ActionKind::Click).element
            && v.decision == SafetyDecision::Deny));
        assert!(round
            .ranked
            .iter()
            .all(|r| r.verdict.decision == SafetyDecision::Allow
                && r.proposal.key.element != f.key("Delete account", ActionKind::Click).element));
        assert_eq!(round.ranked.len(), 2);
        assert!(round.chosen.is_some());
    }

    #[test]
    fn a_denied_key_with_very_high_confidence_still_loses() {
        let f = Fixture::new(&[Spec::link("Open", "/open"), Spec::button("Delete account")]);
        let mut props = proposals_for(&f, &["Open"], "bfs", 0.1);
        props.extend(proposals_for(&f, &["Delete account"], "system1", 1.0));
        let kernel = f.kernel();
        let round = Arbiter::default().choose(props, &f.ctx(), &kernel, &f.safety_ctx());
        let chosen = round.chosen.unwrap();
        assert_eq!(
            chosen.proposal.key.element,
            f.key("Open", ActionKind::Click).element
        );
    }

    #[test]
    fn utility_ordering_prefers_novel_keys() {
        let mut f = Fixture::new(&[Spec::button("Open"), Spec::button("Next"), Spec::button("Back")]);
        let open = f.key("Open", ActionKind::Click);
        let next = f.key("Next", ActionKind::Click);
        f.exec(&open, f.cluster(), &[], TrustLane::TrustedUi);
        f.exec(&open, f.cluster(), &[], TrustLane::TrustedUi);
        f.exec(&next, f.cluster(), &[], TrustLane::TrustedUi);
        let props = proposals_for(&f, &["Open", "Next", "Back"], "bfs", 0.5);
        let gate = ScriptedGate::allow_all();
        let round = Arbiter::default().choose(props, &f.ctx(), &gate, &f.safety_ctx());
        let order: Vec<_> = round.ranked.iter().map(|r| r.proposal.key.element).collect();
        assert_eq!(
            order[0],
            f.key("Back", ActionKind::Click).element,
            "never exercised first"
        );
        assert_eq!(order[1], next.element, "once-exercised before twice-exercised");
        assert_eq!(order[2], open.element);
        let us: Vec<f32> = round.ranked.iter().map(|r| r.utility).collect();
        assert!(us.windows(2).all(|w| w[0] >= w[1]));
    }

    #[test]
    fn risk_class_lowers_utility_of_allowed_but_consequential_actions() {
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Next")]);
        let props = proposals_for(&f, &["Open", "Next"], "bfs", 0.5);
        let gate = ScriptedGate::allow_all().with_risk(
            f.key("Open", ActionKind::Click).element,
            crawlx_core::RiskClass::PersistentWriteOwn,
        );
        let round = Arbiter::default().choose(props, &f.ctx(), &gate, &f.safety_ctx());
        assert_eq!(
            round.ranked[0].proposal.key.element,
            f.key("Next", ActionKind::Click).element
        );
        let gap = round.ranked[0].utility - round.ranked[1].utility;
        assert!((gap - 0.75).abs() < 1e-4, "1.5 × 0.5 risk price, got {gap}");
    }

    #[test]
    fn greedy_covers_admitted_destructive_context_before_repeating_safe_links() {
        let mut f = Fixture::new(&[
            Spec::link("First", "/first"),
            Spec::link("Second", "/second"),
            Spec::button("Delete item"),
        ]);
        for name in ["First", "Second"] {
            let key = f.key(name, ActionKind::Click);
            f.exec(&key, f.cluster(), &[], TrustLane::TrustedUi);
        }
        f.profile = crawlx_core::SafetyProfile::TestEnvironment;
        let clock = std::sync::Arc::new(crawlx_core::time::ManualClock::new(f.bundle.captured_at));
        let approvals = std::sync::Arc::new(crawlx_safety::InMemoryApprovalStore::new(clock.clone()));
        let gate = crawlx_safety::SafetyKernel::new_with_clock(
            crawlx_safety::KernelConfig {
                profile: f.profile,
                launch_profile: crawlx_core::LaunchProfile::Standard,
                has_test_sinks: false,
                destructive_approval: crawlx_core::config::DestructiveActions::Approval,
                seed_origin: crate::testutil::ORIGIN.into(),
                policy_version: 1,
            },
            clock,
        )
        .unwrap()
        .with_approval_store(approvals.clone());
        let base = SafetyContext {
            profile: f.profile,
            destructive_approval_allowed: true,
            ..f.safety_ctx()
        };
        let delete = f.key("Delete item", ActionKind::Click);
        let proposals = proposals_for(&f, &["First", "Second", "Delete item"], "bfs", 0.5);
        let pending = Arbiter::default().choose(proposals.clone(), &f.ctx(), &gate, &base);
        assert_eq!(pending.approval_required.len(), 1);
        assert_ne!(pending.chosen.unwrap().proposal.key, delete);
        let proposal = proposals
            .iter()
            .find(|proposal| proposal.key == delete)
            .unwrap()
            .clone();
        let safety = f.ctx().safety_context(&base, &delete);
        let crawlx_safety::Adjudication::ApprovalRequired(_, request) = gate.adjudicate(proposal, &safety)
        else {
            panic!("expected a real approval request");
        };
        approvals.approve_now(request.approval_id, "reviewer").unwrap();
        let round = Arbiter::default().choose(proposals.clone(), &f.ctx(), &gate, &base);
        let chosen = round.chosen.unwrap();
        assert_eq!(chosen.proposal.key, delete);
        assert_eq!(chosen.verdict.risk_class, crawlx_core::RiskClass::Destructive);
        assert_eq!(chosen.verdict.approval, Some(request.approval_id));
        let recovery = f.ctx_with_phase(crate::Phase::StateRecovery);
        let round = Arbiter::default().choose(proposals, &recovery, &gate, &base);
        assert_ne!(
            round.chosen.unwrap().proposal.key,
            delete,
            "recovery retains path repeats"
        );
        // Another state of the same control remains fresh after its old context ran.
        f.exec(&delete, f.cluster(), &[], TrustLane::TrustedUi);
        let mut next = proposals_for(&f, &["Delete item"], "bfs", 0.5).remove(0);
        next.key.state_cluster = f.cluster_n(91);
        let safety = f.ctx().safety_context(&base, &next.key);
        let crawlx_safety::Adjudication::ApprovalRequired(_, request) =
            gate.adjudicate(next.clone(), &safety)
        else {
            panic!("expected a new context-bound approval");
        };
        approvals.approve_now(request.approval_id, "reviewer").unwrap();
        let mut proposals = proposals_for(&f, &["First", "Second"], "bfs", 0.5);
        proposals.push(next.clone());
        let round = Arbiter::default().choose(proposals, &f.ctx(), &gate, &base);
        assert_eq!(round.chosen.unwrap().proposal.key, next.key);
    }

    #[test]
    fn failed_high_utility_actions_do_not_starve_fresh_contexts() {
        let f = Fixture::new(&[Spec::button("Retry"), Spec::button("Help")]);
        let props = proposals_for(&f, &["Retry", "Help"], "bfs", 0.5);
        let retry = f.key("Retry", ActionKind::Click);
        let help = f.key("Help", ActionKind::Click);
        let gate =
            ScriptedGate::allow_all().with_risk(help.element, crawlx_core::RiskClass::PersistentWriteOwn);
        let mut ledger = crate::ledger::InMemoryLedger::new();
        let mut ctx = f.ctx();
        ctx.ledger = &ledger;
        let initial = Arbiter::default().choose(props.clone(), &ctx, &gate, &f.safety_ctx());
        assert_eq!(initial.chosen.unwrap().proposal.key, retry);
        for _ in 0..3 {
            ledger.record_failure(&retry, TrustLane::TrustedUi);
            let mut ctx = f.ctx();
            ctx.ledger = &ledger;
            let round = Arbiter::default().choose(props.clone(), &ctx, &gate, &f.safety_ctx());
            assert_eq!(round.chosen.unwrap().proposal.key, help);
            assert_eq!(ctx.ledger.trusted_attempts(&retry), 0);
        }
        let restored = crate::ledger::InMemoryLedger::from_rows(ledger.rows());
        let mut ctx = f.ctx();
        ctx.ledger = &restored;
        let round = Arbiter::default().choose(props, &ctx, &gate, &f.safety_ctx());
        assert_eq!(round.chosen.unwrap().proposal.key, help);
        assert_eq!(restored.coverage(None).keys_exercised_trusted, 0);
    }

    #[test]
    fn seeded_ties_are_reproducible_and_seed_dependent() {
        let names = ["Alpha", "Beta", "Gamma", "Delta"];
        let specs: Vec<Spec> = names.iter().map(|n| Spec::button(n)).collect();
        let pick = |seed: u64, reverse: bool| {
            let f = Fixture::with_seed(&specs, CrawlSeed(seed));
            let mut props = proposals_for(&f, &names, "bfs", 0.5);
            if reverse {
                props.reverse();
            }
            let gate = ScriptedGate::allow_all();
            let round = Arbiter::default().choose(props, &f.ctx(), &gate, &f.safety_ctx());
            // all four proposals are exactly tied on utility
            let us: Vec<i64> = round.ranked.iter().map(|r| micros(r.utility)).collect();
            assert!(us.windows(2).all(|w| w[0] == w[1]), "{us:?}");
            f.name_of(&round.chosen.unwrap().proposal.key.element)
        };
        // same seed -> same choice (twice, and for permuted input order)
        for seed in [1_u64, 2, 3, 4, 5] {
            assert_eq!(pick(seed, false), pick(seed, false));
            assert_eq!(pick(seed, false), pick(seed, true), "input order must not matter");
        }
        // different seeds can differ
        let choices: std::collections::BTreeSet<String> = (0..40_u64).map(|s| pick(s, false)).collect();
        assert!(
            choices.len() > 1,
            "40 seeds should not all tie-break to {choices:?}"
        );
    }

    #[test]
    fn co_proposers_are_merged_and_attributed() {
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Next")]);
        let mut props = proposals_for(&f, &["Open"], "interaction_bfs", 0.5);
        props.extend(proposals_for(&f, &["Open"], "system1", 0.9));
        props.extend(proposals_for(&f, &["Open"], "state_novelty", 0.4));
        props.extend(proposals_for(&f, &["Next"], "interaction_bfs", 0.5));
        let gate = ScriptedGate::allow_all();
        let round = Arbiter::default().choose(props, &f.ctx(), &gate, &f.safety_ctx());
        assert_eq!(round.ranked.len(), 2, "merged by key id");
        let open = round
            .ranked
            .iter()
            .find(|r| r.proposal.key.element == f.key("Open", ActionKind::Click).element)
            .unwrap();
        assert_eq!(open.proposal.strategy, "system1", "highest confidence is primary");
        assert_eq!(
            open.co_proposers,
            vec![("interaction_bfs", 1), ("state_novelty", 1)]
        );
        let next = round
            .ranked
            .iter()
            .find(|r| r.proposal.key.element == f.key("Next", ActionKind::Click).element)
            .unwrap();
        assert!(next.co_proposers.is_empty());
    }

    #[test]
    fn approval_required_leaves_the_round() {
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Next")]);
        let props = proposals_for(&f, &["Open", "Next"], "bfs", 0.5);
        let gate = ScriptedGate::allow_all().with_decision(
            f.key("Open", ActionKind::Click).element,
            SafetyDecision::ApprovalRequired,
        );
        let round = Arbiter::default().choose(props, &f.ctx(), &gate, &f.safety_ctx());
        assert_eq!(round.approval_required.len(), 1);
        assert_eq!(round.ranked.len(), 1);
        assert!(round.denied.is_empty());
    }

    #[test]
    fn invalid_proposals_are_dropped_before_the_kernel() {
        let f = Fixture::new(&[Spec::button("Open")]);
        let mut props = proposals_for(&f, &["Open"], "bfs", 0.5);
        let mut future = props[0].clone();
        future.epoch.mutation_seq += 5;
        future.key.input_class = crawlx_core::InputClass::new("x", "future");
        let mut mismatched = props[0].clone();
        mismatched.key.action_kind = ActionKind::Hover;
        let mut foreign = props[0].clone();
        foreign.key.principal = crawlx_core::PrincipalId("other".into());
        props.extend([future, mismatched, foreign]);
        let gate = ScriptedGate::allow_all();
        let round = Arbiter::default().choose(props, &f.ctx(), &gate, &f.safety_ctx());
        assert_eq!(round.ranked.len(), 1);
        let reasons: Vec<_> = round.invalid.iter().map(|(_, r)| *r).collect();
        assert!(reasons.contains(&InvalidReason::EpochFromFuture));
        assert!(reasons.contains(&InvalidReason::KindMismatch));
        assert!(reasons.contains(&InvalidReason::PrincipalMismatch));
        assert_eq!(gate.calls(), 1, "invalid proposals never reach the kernel");
    }

    #[test]
    fn paper_compat_weights_rank_by_queue_score() {
        let mut f = Fixture::new(&[Spec::button("Open"), Spec::button("Next")]);
        let open = f.key("Open", ActionKind::Click);
        f.exec(&open, f.cluster(), &[], TrustLane::TrustedUi);
        let props = proposals_for(&f, &["Open", "Next"], "bfs", 0.5);
        let gate = ScriptedGate::allow_all();
        let arb = Arbiter::new(ArbiterConfig {
            weights: UtilityWeights::paper_compat(),
            version: ARBITER_VERSION,
        });
        let round = arb.choose(props, &f.ctx(), &gate, &f.safety_ctx());
        assert_eq!(
            round.ranked[0].proposal.key.element,
            f.key("Next", ActionKind::Click).element
        );
        assert!(round.ranked[0].utility > round.ranked[1].utility);
    }
}
