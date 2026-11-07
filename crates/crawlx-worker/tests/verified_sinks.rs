//! Verified sink records, not request booleans, authorize external communication.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use crawlx_core::config::ExternalCommunication;
use crawlx_core::observation::LiveTargetFacts;
use crawlx_core::repo::SafetyContext;
use crawlx_core::safety::{RiskClass, SafetyDecision};
use crawlx_core::time::ManualClock;
use crawlx_core::{ActionKind, CreateCrawl, PrincipalId, SafetyProfile, StateClusterId, TenantId};
use crawlx_policy::{testkit::sample_record, AuthorizationRecord};
use crawlx_worker::run::build_kernel;
use std::sync::Arc;

#[test]
fn only_the_selected_verified_unexpired_matching_sink_authorizes_external_communication() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-04T12:00:00Z")
        .unwrap()
        .to_utc();
    let clock = ManualClock::new(now);
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.safety.profile = SafetyProfile::TestEnvironment;
    crawl.safety.external_communication = ExternalCommunication::TestSinks;
    let mut record = sample_record(TenantId::new(), now, &["https://example.test"]);
    record.verified_at = Some(now);
    record
        .test_sinks
        .insert("email".into(), "https://example.test/next".into());
    crawl.safety.authorization_record_ref = Some(record.id);
    let mut proposal = crawlx_storage::testkit::proposal("anonymous", StateClusterId::new(), 1);
    proposal.hinted_risk = Some(RiskClass::ExternalCommunication);
    let context = SafetyContext {
        profile: SafetyProfile::TestEnvironment,
        // Even a caller claiming sinks exist cannot bypass actual record checks.
        has_test_sinks: true,
        destructive_approval_allowed: false,
        principal: PrincipalId::anonymous(),
        seed_origin: "https://example.test".into(),
        in_scope: true,
        target: LiveTargetFacts {
            current_url: "https://example.test/".into(),
            attributes: [("form-action".into(), "https://example.test/next".into())].into(),
            ..LiveTargetFacts::default()
        },
        form_hint: Some("external_communication".into()),
    };
    let decide = |record: Option<&AuthorizationRecord>, context: &SafetyContext| {
        build_kernel(&crawl, Arc::new(clock.clone()), record)
            .unwrap()
            .adjudicate(proposal.clone(), context)
            .decision()
    };
    assert_eq!(decide(None, &context), SafetyDecision::Deny);
    assert_eq!(decide(Some(&record), &context), SafetyDecision::Allow);
    let mut relative = context.clone();
    relative
        .target
        .attributes
        .insert("form-action".into(), "/next".into());
    assert_eq!(decide(Some(&record), &relative), SafetyDecision::Allow);
    let mut default_action = context.clone();
    default_action.target.current_url = "https://example.test/next".into();
    default_action
        .target
        .attributes
        .insert("form-action".into(), String::new());
    assert_eq!(decide(Some(&record), &default_action), SafetyDecision::Allow);
    let mut wrong_record = record.clone();
    wrong_record.id = crawlx_core::AuthorizationRecordId::new();
    let mut unverified = record.clone();
    unverified.verified_at = None;
    let mut expired = record.clone();
    expired.valid_to = now;
    let mut future = record.clone();
    future.valid_from = now + chrono::Duration::seconds(1);
    let mut revoked = record.clone();
    revoked.revoked_at = Some(now);
    let mut wrong_kind = record.clone();
    wrong_kind.test_sinks.clear();
    wrong_kind
        .test_sinks
        .insert("sms".into(), "https://example.test/next".into());
    for denied in [wrong_record, unverified, expired, future, revoked, wrong_kind] {
        assert_eq!(decide(Some(&denied), &context), SafetyDecision::Deny);
    }
    let mut wrong_destination = context.clone();
    wrong_destination
        .target
        .attributes
        .insert("form-action".into(), "https://example.test/other".into());
    assert_eq!(decide(Some(&record), &wrong_destination), SafetyDecision::Deny);
    let mut unknown_destination = context.clone();
    unknown_destination.target.attributes.clear();
    assert_eq!(decide(Some(&record), &unknown_destination), SafetyDecision::Deny);
    let kernel = build_kernel(&crawl, Arc::new(clock.clone()), Some(&record)).unwrap();
    assert!(kernel.has_verified_test_sinks());
    clock.advance_ms((record.valid_to - now).num_milliseconds());
    assert!(!kernel.has_verified_test_sinks());
    assert_eq!(
        kernel.adjudicate(proposal, &context).decision(),
        SafetyDecision::Deny
    );
}

const FORM_DESTINATION: &str = "https://example.test/invite?channel=test";

async fn observed_form_rig(channel: &str, sink_channel: &str, live_destination: &str) -> common::RigCore {
    use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
    use crawlx_core::{Clock, SystemClock};
    use crawlx_storage::MemoryStore;
    use crawlx_worker::Stores;

    let field = if channel == "sms" {
        FakeAxSpec::textbox("recipient", "Phone").attr("type", "tel")
    } else {
        FakeAxSpec::textbox("recipient", "Webhook URL")
    };
    let script = FakeScript::new().page(
        FakePage::new(common::SEED)
            .node(
                FakeAxSpec::new("form", "form")
                    .tag("form")
                    .attr("id", "invite")
                    .attr("action", FORM_DESTINATION),
            )
            .node(
                field
                    .attr("form", "invite")
                    .attr("form-action", FORM_DESTINATION)
                    .attr("form-method", "post")
                    .live_attr("form-action", live_destination),
            )
            // Explicit form ownership also covers submitters outside the form subtree.
            .node(
                FakeAxSpec::button("send", "Send invite")
                    .attr("type", "submit")
                    .attr("form", "invite")
                    .attr("form-action", FORM_DESTINATION)
                    .live_attr("form-action", live_destination),
            )
            .node(
                FakeAxSpec::button("change", "Show options")
                    .attr("type", "button")
                    .attr("aria-expanded", "false"),
            )
            .on_click(
                "change",
                vec![FakeEffect::SetName {
                    key: "recipient".into(),
                    name: "Email".into(),
                }],
            ),
    );
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = common::crawl(SafetyProfile::TestEnvironment);
    crawl.safety.respect_robots_txt = false;
    crawl.safety.external_communication = ExternalCommunication::TestSinks;
    let now = SystemClock.now();
    let mut record = sample_record(stores.tenant, now, &["https://example.test"]);
    record.verified_at = Some(now);
    record.robots_override_acknowledged = true;
    record
        .test_sinks
        .insert(sink_channel.into(), FORM_DESTINATION.into());
    crawl.safety.authorization_record_ref = Some(record.id);
    let fake = Arc::new(crawlx_browser::FakeBackend::new(script));
    common::rig_core_authorized(stores, dir, fake.clone(), fake, crawl, record, None).await
}

async fn observed_proposal(
    rig: &common::RigCore,
    name: &str,
    kind: ActionKind,
) -> (crawlx_core::proposal::ActionProposal, SafetyContext) {
    use crawlx_elements::{
        CandidateDiscovery, DiscoveryConfig, IdentityResolver, InMemoryIdentityIndex, MatchWeights,
    };
    use crawlx_graph::EnablementGraph;
    use crawlx_strategies::context::DecisionContextBuilder;
    use crawlx_strategies::frontier::FrontierStats;
    use crawlx_strategies::ledger::InMemoryLedger;
    use crawlx_worker::StateAnalyzer;

    let bundle = rig.handle.observe(Default::default()).await.unwrap();
    let analyzer = StateAnalyzer::new(
        rig.run,
        rig.session,
        rig.rc.clusters.clone(),
        rig.stores.artifacts.clone(),
        rig.rc.clock.clone(),
        rig.rc.crawl.capture.clone(),
        (&rig.rc.controls, &rig.rc.captcha_secrets),
    );
    let state = analyzer.analyze(&bundle).await.state;
    rig.stores.states.put_state(&state).await.unwrap();
    let (mut proposal, mut base) = common::proposal_for(
        &bundle,
        name,
        kind,
        state.cluster,
        &rig.principal,
        &rig.rc.seed_origin(),
        SafetyProfile::TestEnvironment,
    );
    if kind == ActionKind::Type {
        proposal.action = crawlx_core::action::BrowserAction::Type {
            target: proposal.action.target().unwrap().clone(),
            value: crawlx_core::secret::SecretOr::Plain("+15555550123".into()),
            clear_first: true,
        };
        proposal.summary = format!("type {name}");
    }
    base.has_test_sinks = rig.rc.kernel.has_verified_test_sinks();
    let candidates = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
    let resolver = IdentityResolver::with_destination(bundle.url.url.clone(), Default::default());
    let index = InMemoryIdentityIndex::new();
    let resolved = candidates
        .iter()
        .map(|c| {
            resolver
                .resolve(&c.descriptor, &index, &MatchWeights::default())
                .unwrap()
        })
        .collect();
    let ledger = InMemoryLedger::new();
    let graph = EnablementGraph::new(rig.run);
    let frontier = FrontierStats::default();
    let context = DecisionContextBuilder::new(
        bundle,
        rig.principal.clone(),
        state.cluster,
        rig.rc.seed,
        &ledger,
        &graph,
        &frontier,
    )
    .candidates(candidates, resolved)
    .build()
    .unwrap();
    let safety = context.safety_context(&base, &proposal.key);
    (proposal, safety)
}

#[tokio::test]
async fn observed_webhook_and_sms_http_forms_reach_the_selected_browser_control() {
    use crawlx_core::counters::ActionStatus;
    use crawlx_safety::Adjudication;

    for channel in ["webhook", "sms"] {
        let rig = observed_form_rig(channel, channel, FORM_DESTINATION).await;
        let (proposal, safety) = observed_proposal(&rig, "Send invite", ActionKind::Click).await;
        assert_eq!(
            safety.form_hint.as_deref(),
            Some(format!("external_communication:{channel}").as_str())
        );
        let Adjudication::Allow(admitted) = rig.rc.kernel.adjudicate(proposal, &safety) else {
            panic!("observed {channel} form must use its selected verified sink");
        };
        let outcome = rig.handle.execute(admitted, Default::default()).await.unwrap();
        assert_eq!(outcome.dropped, None, "{channel}: {outcome:?}");
        assert_eq!(outcome.status, ActionStatus::Succeeded);
        assert!(rig
            .backend
            .context_handles()
            .iter()
            .any(|handle| { handle.performed_keys().iter().any(|key| key == "click:send") }));
    }
}

#[tokio::test]
async fn observed_channel_and_latest_destination_must_both_match_the_sink() {
    use crawlx_safety::Adjudication;
    use crawlx_worker::actor::DropReason;

    for channel in ["webhook", "sms"] {
        let wrong_channel = observed_form_rig(channel, "email", FORM_DESTINATION).await;
        let (proposal, safety) = observed_proposal(&wrong_channel, "Send invite", ActionKind::Click).await;
        assert_eq!(
            wrong_channel.rc.kernel.adjudicate(proposal, &safety).decision(),
            SafetyDecision::Deny
        );
        assert_eq!(wrong_channel.performed_total(), 0);

        let moved = observed_form_rig(channel, channel, "https://example.test/other").await;
        let (proposal, safety) = observed_proposal(&moved, "Send invite", ActionKind::Click).await;
        let Adjudication::Allow(admitted) = moved.rc.kernel.adjudicate(proposal, &safety) else {
            panic!("proposal-time destination matches");
        };
        let outcome = moved.handle.execute(admitted, Default::default()).await.unwrap();
        assert_eq!(outcome.dropped, Some(DropReason::ConfirmDenied));
        assert_eq!(moved.performed_total(), 0);
    }
}

#[tokio::test]
async fn confirmation_reobserves_channel_instead_of_reusing_admitted_webhook_hint() {
    use crawlx_safety::Adjudication;
    use crawlx_worker::actor::DropReason;

    let rig = observed_form_rig("webhook", "webhook", FORM_DESTINATION).await;
    let (proposal, safety) = observed_proposal(&rig, "Send invite", ActionKind::Click).await;
    let Adjudication::Allow(admitted) = rig.rc.kernel.adjudicate(proposal, &safety) else {
        panic!("initial webhook channel matches");
    };
    let (change, safety) = observed_proposal(&rig, "Show options", ActionKind::Click).await;
    let Adjudication::Allow(change) = rig.rc.kernel.adjudicate(change, &safety) else {
        panic!("local disclosure must be actionable");
    };
    let changed = rig.handle.execute(change, Default::default()).await.unwrap();
    assert_eq!(changed.dropped, None);
    let outcome = rig.handle.execute(admitted, Default::default()).await.unwrap();
    assert_eq!(outcome.dropped, Some(DropReason::ConfirmDenied));
    assert!(!rig
        .backend
        .context_handles()
        .iter()
        .any(|handle| { handle.performed_keys().iter().any(|key| key == "click:send") }));
    assert_eq!(
        outcome.live.unwrap().observed_form_hint.as_deref(),
        Some("external_communication")
    );
}

#[tokio::test]
async fn observed_channel_does_not_authorize_an_expired_sink_at_confirmation() {
    use crawlx_safety::Adjudication;

    let rig = observed_form_rig("sms", "sms", FORM_DESTINATION).await;
    let (proposal, safety) = observed_proposal(&rig, "Send invite", ActionKind::Click).await;
    let now = chrono::DateTime::parse_from_rfc3339("2026-11-04T12:00:00Z")
        .unwrap()
        .to_utc();
    let clock = ManualClock::new(now);
    let mut record = sample_record(rig.stores.tenant, now, &["https://example.test"]);
    record.id = rig.rc.crawl.safety.authorization_record_ref.unwrap();
    record.verified_at = Some(now);
    record.valid_to = now + chrono::Duration::seconds(1);
    record.test_sinks.insert("sms".into(), FORM_DESTINATION.into());
    let kernel = build_kernel(&rig.rc.crawl, Arc::new(clock.clone()), Some(&record)).unwrap();
    let Adjudication::Allow(admitted) = kernel.adjudicate(proposal.clone(), &safety) else {
        panic!("observed SMS channel matches before expiry");
    };
    clock.advance_ms(1_000);
    assert!(kernel.confirm(&admitted, &safety.target).is_err());
    assert_eq!(
        kernel.adjudicate(proposal, &safety).decision(),
        SafetyDecision::Deny
    );
    assert_eq!(rig.performed_total(), 0);
}

#[tokio::test]
async fn native_sms_field_requires_matching_sink_before_typing_and_at_confirmation() {
    use crawlx_core::counters::ActionStatus;
    use crawlx_safety::Adjudication;
    use crawlx_worker::actor::DropReason;

    let rig = observed_form_rig("sms", "sms", FORM_DESTINATION).await;
    let (proposal, safety) = observed_proposal(&rig, "Phone", ActionKind::Type).await;
    let Adjudication::Allow(admitted) = rig.rc.kernel.adjudicate(proposal, &safety) else {
        panic!("verified SMS form must allow its native field");
    };
    let outcome = rig.handle.execute(admitted, Default::default()).await.unwrap();
    assert_eq!(outcome.dropped, None, "{outcome:?}");
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert!(rig.backend.context_handles().iter().any(|handle| {
        handle
            .typed_inputs()
            .iter()
            .any(|input| input.text.as_deref() == Some("+15555550123"))
    }));

    let wrong = observed_form_rig("sms", "email", FORM_DESTINATION).await;
    let (proposal, safety) = observed_proposal(&wrong, "Phone", ActionKind::Type).await;
    assert_eq!(
        wrong.rc.kernel.adjudicate(proposal, &safety).decision(),
        SafetyDecision::Deny
    );
    assert_eq!(wrong.performed_total(), 0);

    let moved = observed_form_rig("sms", "sms", "https://example.test/other").await;
    let (proposal, safety) = observed_proposal(&moved, "Phone", ActionKind::Type).await;
    let Adjudication::Allow(admitted) = moved.rc.kernel.adjudicate(proposal, &safety) else {
        panic!("proposal destination still matches");
    };
    let outcome = moved.handle.execute(admitted, Default::default()).await.unwrap();
    assert_eq!(outcome.dropped, Some(DropReason::ConfirmDenied));
    assert_eq!(moved.performed_total(), 0);
}
