//! The production arbiter over the production safety kernel (the kernel the worker builds from a
//! crawl request): the kernel adjudicates before any scoring, so a destructive control a strategy
//! is certain about still loses to a benign one it has no confidence in under `read_only`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeBackend, FakePage, FakeScript};
use crawlx_core::browser::{BrowserBackend, ContextConfig};
use crawlx_core::config::{CreateCrawl, SafetyProfile};
use crawlx_core::ids::{CrawlRunId, PrincipalId, SessionId, StateClusterId};
use crawlx_core::observation::{LiveTargetFacts, ObservationSpec};
use crawlx_core::repo::SafetyContext;
use crawlx_core::safety::SafetyDecision;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::time::{Clock, ManualClock, Timestamp};
use crawlx_elements::{CandidateDiscovery, DiscoveryConfig, IdentityResolver, MatchWeights};
use crawlx_strategies::{
    Arbiter, ArbiterConfig, BudgetView, ExplorationConfig, ExplorationState, RoundInput,
};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::sync::Arc;

const PAGE: &str = "https://app.example/app";

/// One arbitration round over a page with a benign `open` and a destructive `delete` button:
/// `open` is proposed with confidence `open_confidence`, `delete` by each `(strategy,
/// confidence)` of `delete_proposers`.
fn arbitrate(
    profile: SafetyProfile,
    open_confidence: f32,
    delete_proposers: &[(&'static str, f32)],
) -> (
    crawlx_strategies::ArbiterRound,
    crawlx_core::ElementIdentityHash,
    crawlx_core::ElementIdentityHash,
) {
    let mut page = FakePage::new(PAGE);
    // A plain link is the benign control: an unclassified button is itself denied under
    // `read_only` (fail closed), which would hide what this test is about.
    let controls = [
        FakeAxSpec::link("open", "Open", "/open").attr("id", "open"),
        FakeAxSpec::button("delete", "Delete account").attr("id", "delete"),
    ];
    for (i, control) in controls.into_iter().enumerate() {
        page = page.node(control.bbox(10.0, 10.0 + 30.0 * i as f64, 120.0, 24.0));
    }
    let backend = FakeBackend::new(FakeScript::new().page(page));
    let canon = CanonicalizeOptions::default();
    let canonical = Canonicalizer::canonicalize_url(&url::Url::parse(PAGE).unwrap(), &canon).unwrap();
    let bundle = futures::executor::block_on(async {
        let mut ctx = backend
            .new_context(ContextConfig::new(SessionId::from(uuid::Uuid::nil())))
            .await
            .unwrap();
        ctx.navigate(&canonical).await.unwrap();
        ctx.observe(ObservationSpec::default()).await.unwrap()
    });
    let candidates = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
    let resolver = IdentityResolver::with_destination(bundle.url.url.clone(), canon);
    let mut state = ExplorationState::new(
        CrawlRunId::from(uuid::Uuid::nil()),
        PrincipalId::anonymous(),
        CrawlSeed(1),
        ExplorationConfig {
            profile,
            ..ExplorationConfig::default()
        },
    );
    let resolved: Vec<_> = candidates
        .iter()
        .map(|c| {
            resolver
                .resolve(&c.descriptor, state.identity_index(), &MatchWeights::default())
                .unwrap()
        })
        .collect();
    let cluster = StateClusterId::new();
    let now = Timestamp::default();
    state.ingest_observation(&bundle, &candidates, &resolved, cluster, now);
    let ctx = state
        .context(RoundInput::new(
            Arc::new(bundle.clone()),
            candidates.clone(),
            resolved.clone(),
            cluster,
            1,
            profile,
            BudgetView::default(),
            now,
        ))
        .unwrap();
    let action_for = |id: &str| {
        ctx.keyed_actions()
            .iter()
            .find(|ka| {
                candidates[ka.candidate]
                    .descriptor
                    .attributes
                    .get("id")
                    .map(String::as_str)
                    == Some(id)
                    && ka.key.action_kind == crawlx_core::ActionKind::Click
            })
            .unwrap_or_else(|| panic!("no click action for {id}"))
    };
    let (open, delete) = (action_for("open"), action_for("delete"));
    let mut proposals = vec![ctx.proposal_for(open, "bfs", 1, open_confidence).unwrap()];
    for (strategy, confidence) in delete_proposers {
        proposals.push(ctx.proposal_for(delete, strategy, 1, *confidence).unwrap());
    }

    // The kernel the worker builds for a crawl request of this profile.
    let mut crawl = CreateCrawl::new(url::Url::parse(PAGE).unwrap());
    crawl.safety.profile = profile;
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(Timestamp::default()));
    let kernel = crawlx_worker::run::build_kernel(&crawl, clock, None).unwrap();
    let safety = SafetyContext {
        profile,
        has_test_sinks: false,
        destructive_approval_allowed: false,
        principal: PrincipalId::anonymous(),
        seed_origin: "https://app.example".to_owned(),
        in_scope: true,
        target: LiveTargetFacts::default(),
        form_hint: None,
    };
    let round = Arbiter::new(ArbiterConfig::default()).choose(proposals, &ctx, &kernel, &safety);
    (round, open.key.element, delete.key.element)
}

#[test]
fn a_destructive_control_at_full_confidence_is_denied_and_never_ranked_under_read_only() {
    let (round, open, delete) = arbitrate(SafetyProfile::ReadOnly, 0.0, &[("system1", 1.0)]);
    assert_eq!(round.denied.len(), 1, "{round:?}");
    let (denied, verdict) = &round.denied[0];
    assert_eq!(denied.key.element, delete);
    assert_eq!(verdict.decision, SafetyDecision::Deny);
    assert!(
        round.ranked.iter().all(|r| r.proposal.key.element != delete),
        "a denied key is never ranked: {:?}",
        round.ranked
    );
    assert!(round.approval_required.is_empty(), "{round:?}");
    let chosen = round.chosen.expect("the benign control survives");
    assert_eq!(
        chosen.proposal.key.element, open,
        "confidence 0.0 on a safe key beats confidence 1.0 on a denied one"
    );
}

#[test]
fn several_confident_strategies_do_not_outvote_the_kernel() {
    let (round, open, delete) = arbitrate(
        SafetyProfile::ReadOnly,
        0.0,
        &[("system1", 1.0), ("event_driven", 1.0), ("interaction_bfs", 1.0)],
    );
    assert_eq!(round.denied.len(), 1, "one denial per merged key: {round:?}");
    assert_eq!(round.denied[0].0.key.element, delete);
    assert_eq!(round.chosen.unwrap().proposal.key.element, open);
}
