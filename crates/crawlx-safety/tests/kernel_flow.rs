//! Kernel behaviour: approvals, sinks, hints, confirm, audit, construction.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{config, kernel, kernel_with_clock, manual_clock, verified_sinks, Case, PROFILES, SEED};
use crawlx_core::action::{BrowserAction, PointerButton};
use crawlx_core::config::{DestructiveActions, LaunchProfile, SafetyProfile};
use crawlx_core::identity::ResourceContext;
use crawlx_core::ids::SafetyDecisionId;
use crawlx_core::observation::LiveTargetFacts;
use crawlx_core::repo::SafetyGate;
use crawlx_core::safety::{ModelHint, RiskClass, SafetyDecision};
use crawlx_core::time::Clock as _;
use crawlx_safety::{
    AdjudicateOptions, Adjudication, ApprovalError, ApprovalStore, AuditEntry, AuditError, AuditSink,
    InMemoryApprovalStore, KernelError, MemoryAuditLog, SafetyDenied, SafetyKernel, SinkSpec, TestSinks,
};
use proptest::prelude::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const TE: SafetyProfile = SafetyProfile::TestEnvironment;

fn delete_case() -> Case {
    Case::click("button", "Delete project").profile(TE)
}

// ---- construction --------------------------------------------------------

#[test]
fn stealth_with_read_only_is_a_construction_error() {
    let mut cfg = config(SafetyProfile::ReadOnly);
    cfg.launch_profile = LaunchProfile::Stealth;
    assert_eq!(
        SafetyKernel::new(cfg).err(),
        Some(KernelError::StealthRequiresWritableProfile)
    );
    for p in [
        SafetyProfile::TestEnvironment,
        SafetyProfile::AuthorizedSecurityTest,
    ] {
        let mut cfg = config(p);
        cfg.launch_profile = LaunchProfile::Stealth;
        assert!(SafetyKernel::new(cfg).is_ok());
    }
}

#[test]
fn invalid_seed_origin_is_a_construction_error() {
    for bad in ["", "not a url", "ftp://example.com", "file:///x"] {
        let mut cfg = config(TE);
        cfg.seed_origin = bad.into();
        assert!(
            matches!(SafetyKernel::new(cfg), Err(KernelError::InvalidSeedOrigin(_))),
            "{bad:?}"
        );
    }
}

#[test]
fn kernel_config_seed_origin_is_authoritative() {
    // The context claims a different origin; the link is judged against the kernel's.
    let (p, mut c) = Case::click("link", "Home")
        .href("https://app.example.com/home")
        .profile(TE)
        .build();
    c.seed_origin = "https://other.example.org".into();
    assert!(matches!(kernel(TE).adjudicate(p, &c), Adjudication::Allow(_)));
}

#[test]
fn context_cannot_widen_the_kernel_profile() {
    // run profile read_only, context claims authorized_security_test
    let (p, c) = Case::click("button", "Save")
        .profile(SafetyProfile::AuthorizedSecurityTest)
        .build();
    let adj = kernel(SafetyProfile::ReadOnly).adjudicate(p, &c);
    assert_eq!(adj.decision(), SafetyDecision::Deny);
    assert!(adj.verdict().rules.iter().any(|r| r == "profile.narrowed"));
    // and the other direction narrows too
    let (p, c) = Case::click("button", "Save")
        .profile(SafetyProfile::ReadOnly)
        .build();
    assert_eq!(kernel(TE).adjudicate(p, &c).decision(), SafetyDecision::Deny);
}

// ---- audit ------------------------------------------------------------------

#[test]
fn every_adjudication_has_a_verdict_and_every_admission_has_an_audit_row() {
    let log = Arc::new(MemoryAuditLog::new());
    let mut total = 0;
    let mut allowed = 0;
    for profile in PROFILES {
        let k = kernel(profile).with_audit_sink(log.clone());
        for name in ["Save", "Delete", "Pay", "Send", "Change password", "Menu", "Go"] {
            for case in [
                Case::click("button", name),
                Case::click("link", name).href("/x"),
                Case::hover(),
            ] {
                let (p, c) = case.profile(profile).build();
                let adj = k.adjudicate(p, &c);
                total += 1;
                let v = adj.verdict();
                assert!(!v.rules.is_empty(), "verdict without rules");
                let row = log.find(v.decision_id).expect("verdict without audit row");
                assert_eq!(&row.verdict, v);
                assert_eq!(row.policy_version, 7);
                if let Adjudication::Allow(a) = &adj {
                    allowed += 1;
                    assert_eq!(a.verdict().decision, SafetyDecision::Allow);
                    assert_eq!(a.decision(), v.decision_id);
                    assert!(a.browser_action().kind() == a.proposal().action.kind());
                }
            }
        }
    }
    assert_eq!(log.len(), total);
    assert!(allowed > 0);
}

struct FailingSink;
impl AuditSink for FailingSink {
    fn record(&self, _entry: AuditEntry) -> Result<(), AuditError> {
        Err(AuditError::Unavailable("db down".into()))
    }
}

#[test]
fn audit_failure_denies_instead_of_admitting() {
    let k = kernel(TE).with_audit_sink(Arc::new(FailingSink));
    let (p, c) = Case::hover().profile(TE).build();
    let adj = k.adjudicate(p, &c);
    match adj {
        Adjudication::Deny(v) => assert!(v.rules.iter().any(|r| r == "failclosed.audit_unavailable")),
        other => panic!("expected deny, got {other:?}"),
    }
}

#[test]
fn unknown_input_denies_and_is_audited() {
    let log = Arc::new(MemoryAuditLog::new());
    let k = kernel(TE).with_audit_sink(log.clone());
    let v = k.deny_unknown("action_kind");
    assert_eq!(v.decision, SafetyDecision::Deny);
    assert!(v.rules.iter().any(|r| r == "failclosed.unknown_input"));
    assert_eq!(log.len(), 1);
}

#[test]
fn rule_hook_denies_with_its_rule_names() {
    let log = Arc::new(MemoryAuditLog::new());
    let k = kernel(TE)
        .with_audit_sink(log.clone())
        .with_rule_hook(Arc::new(|_p, c| {
            if c.target.name.as_deref() == Some("Save") {
                vec!["tenant.no_saves".to_owned()]
            } else {
                Vec::new()
            }
        }));
    let (p, c) = Case::click("button", "Save").profile(TE).build();
    let adj = k.adjudicate(p, &c);
    assert_eq!(adj.decision(), SafetyDecision::Deny);
    assert!(adj.verdict().rules.iter().any(|r| r == "tenant.no_saves"));
    let (p, c) = Case::hover().profile(TE).build();
    assert!(matches!(k.adjudicate(p, &c), Adjudication::Allow(_)));
    assert_eq!(log.len(), 2);
}

#[test]
fn a_panic_inside_the_kernel_fails_closed_and_is_audited() {
    let log = Arc::new(MemoryAuditLog::new());
    let k = kernel(TE)
        .with_audit_sink(log.clone())
        .with_rule_hook(Arc::new(|_p, _c| panic!("rule hook exploded")));
    let (p, c) = Case::hover().profile(TE).build();
    // keep the test output clean: the hook's panic is expected
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let adj = k.adjudicate(p.clone(), &c);
    let gate: &dyn SafetyGate = &k;
    let classified = gate.classify(&p, &c);
    std::panic::set_hook(prev);
    let Adjudication::Deny(v) = adj else {
        panic!("expected deny, got {adj:?}");
    };
    assert_eq!(v.rules, vec!["failclosed.kernel_panic".to_owned()]);
    assert_eq!(v.risk_class, RiskClass::Unclassified);
    let row = log.find(v.decision_id).expect("panic verdict without audit row");
    assert_eq!(row.phase, crawlx_safety::AuditPhase::Adjudicate);
    assert_eq!(row.verdict, v);
    assert_eq!(log.len(), 1, "classify writes no row");
    assert_eq!(classified.decision, SafetyDecision::Deny);
    assert!(classified.rules.iter().any(|r| r == "failclosed.kernel_panic"));
}

#[test]
fn gate_trait_matches_adjudication_without_side_effects() {
    let log = Arc::new(MemoryAuditLog::new());
    let k = kernel(TE).with_audit_sink(log.clone());
    let gate: &dyn SafetyGate = &k;
    for case in [
        Case::hover(),
        Case::click("button", "Save"),
        delete_case(),
        Case::click("button", "Pay"),
    ] {
        let (p, c) = case.profile(TE).build();
        let v = gate.classify(&p, &c);
        let adj = k.adjudicate(p, &c);
        assert_eq!(v.decision, adj.decision());
        assert_eq!(v.risk_class, adj.verdict().risk_class);
    }
    // only the four adjudications wrote rows
    assert_eq!(log.len(), 4);
    let (p, c) = delete_case().build();
    assert_eq!(gate.classify(&p, &c).approval, None);
}

// ---- sinks ----------------------------------------------------------------

fn send_case(profile: SafetyProfile) -> Case {
    Case::click("button", "Send invitation")
        .profile(profile)
        .attr("form-action", &format!("{SEED}/sink"))
}

#[test]
fn external_communication_needs_a_verified_sink_in_every_profile() {
    for profile in PROFILES {
        let allowed_profile = profile != SafetyProfile::ReadOnly;
        // sinks configured and opted in
        let (p, c) = send_case(profile).build();
        let d = kernel(profile).adjudicate(p, &c).decision();
        assert_eq!(d == SafetyDecision::Allow, allowed_profile, "{profile:?}");
        // run did not opt in
        let mut cfg = config(profile);
        cfg.has_test_sinks = false;
        let (p, c) = send_case(profile).build();
        assert_eq!(
            SafetyKernel::new(cfg).unwrap().adjudicate(p, &c).decision(),
            SafetyDecision::Deny,
            "{profile:?} no opt-in"
        );
        // context says no sinks
        let (p, c) = send_case(profile).no_sinks().build();
        assert_eq!(
            kernel(profile).adjudicate(p, &c).decision(),
            SafetyDecision::Deny,
            "{profile:?} ctx"
        );
    }
}

#[test]
fn unverified_sink_of_the_required_kind_denies() {
    let clock = manual_clock();
    let verified = clock.now() - chrono::Duration::hours(1);
    let sinks = TestSinks {
        email: Some(SinkSpec {
            address: "qa@sink.test".into(),
            verified_at: None,
            expires_at: clock.now() + chrono::Duration::hours(1),
        }),
        sms: Some(SinkSpec {
            address: "+15550100".into(),
            verified_at: Some(verified),
            expires_at: clock.now() + chrono::Duration::hours(1),
        }),
        webhook: None,
    };
    let k = kernel_with_clock(TE, &clock).with_test_sinks(sinks);
    // email form, email sink unverified
    let (p, c) = send_case(TE).form("external_communication").build();
    let adj = k.adjudicate(p, &c);
    assert_eq!(adj.decision(), SafetyDecision::Deny);
    assert!(adj
        .verdict()
        .rules
        .iter()
        .any(|r| r == "sink.required_unverified"));
    // sms form, sms sink verified
    let (p, c) = send_case(TE)
        .form("external_communication:sms")
        .attr("form-action", "sms:+15550100")
        .build();
    assert_eq!(k.adjudicate(p, &c).decision(), SafetyDecision::Allow);
    // webhook form, no webhook sink
    let (p, c) = send_case(TE).form("external_communication:webhook").build();
    assert_eq!(k.adjudicate(p, &c).decision(), SafetyDecision::Deny);
}

#[test]
fn absent_wrong_kind_expired_or_wrong_destination_sinks_deny() {
    let clock = manual_clock();
    let (p, c) = send_case(TE).build();
    let raw = SafetyKernel::new_with_clock(config(TE), Arc::new(clock.clone())).unwrap();
    assert_eq!(raw.adjudicate(p.clone(), &c).decision(), SafetyDecision::Deny);
    let mut wrong_kind = verified_sinks();
    wrong_kind.sms = wrong_kind.email.take();
    let mut expired = verified_sinks();
    expired.email.as_mut().unwrap().expires_at = clock.now();
    let mut unverified = verified_sinks();
    unverified.email.as_mut().unwrap().verified_at = None;
    for sinks in [wrong_kind, expired, unverified] {
        let k = kernel_with_clock(TE, &clock).with_test_sinks(sinks);
        assert_eq!(k.adjudicate(p.clone(), &c).decision(), SafetyDecision::Deny);
    }
    let k = kernel_with_clock(TE, &clock);
    assert_eq!(k.adjudicate(p, &c).decision(), SafetyDecision::Allow);
    for destination in ["", "https://app.example.com/sink/other", "https://evil.test/sink"] {
        let (p, c) = send_case(TE).attr("form-action", destination).build();
        assert_eq!(k.adjudicate(p, &c).decision(), SafetyDecision::Deny);
    }
    let (p, c) = send_case(TE).build();
    let Adjudication::Allow(admitted) = k.adjudicate(p, &c) else {
        panic!("verified sink must allow");
    };
    let mut live = c.target;
    live.attributes
        .insert("form-action".into(), "https://app.example.com/other".into());
    assert!(k.confirm(&admitted, &live).is_err());
}

// ---- approvals ------------------------------------------------------------------

#[test]
fn approval_flow_is_single_use_and_bound_to_the_action() {
    let clock = manual_clock();
    let store = Arc::new(InMemoryApprovalStore::new(Arc::new(clock.clone())));
    let k = kernel_with_clock(TE, &clock).with_approval_store(store.clone());

    // first sight: approval required
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(v1, req) = k.adjudicate(p, &c) else {
        panic!("expected approval_required")
    };
    assert_eq!(v1.approval, Some(req.approval_id));
    assert_eq!(req.risk, RiskClass::Destructive);
    assert!(
        !req.summary.contains("Delete project"),
        "summary must be redacted: {}",
        req.summary
    );
    assert_eq!(req.expires_at - req.created_at, chrono::Duration::hours(24));

    // same action again reuses the open request
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, again) = k.adjudicate(p, &c) else {
        panic!("expected approval_required")
    };
    assert_eq!(again.approval_id, req.approval_id);
    assert_eq!(store.len(), 1);

    // presenting a still-pending approval keeps waiting
    let (p, c) = delete_case().build();
    let opts = AdjudicateOptions {
        approval: Some(req.approval_id),
        ..AdjudicateOptions::default()
    };
    assert!(matches!(
        k.adjudicate_with(p, &c, opts),
        Adjudication::ApprovalRequired(..)
    ));

    // reviewer approves; the action is now admitted exactly once
    store.approve_now(req.approval_id, "reviewer-1").unwrap();
    let (p, c) = delete_case().build();
    let preview = k.classify(&p, &c);
    assert_eq!(preview.decision, SafetyDecision::Allow);
    assert_eq!(preview.approval, Some(req.approval_id));
    assert_eq!(
        k.classify(&p, &c).approval,
        Some(req.approval_id),
        "arbitration never consumes the grant"
    );
    let mut another_key = p.clone();
    another_key.key.principal = crawlx_core::PrincipalId("another-role".to_owned());
    assert_ne!(k.classify(&another_key, &c).decision, SafetyDecision::Allow);
    let (_, read_only) = delete_case().profile(SafetyProfile::ReadOnly).build();
    assert_eq!(
        k.classify(&p, &read_only).decision,
        SafetyDecision::Deny,
        "a grant never overrides a stricter profile"
    );
    let Adjudication::Allow(admitted) = k.adjudicate_with(p, &c, opts) else {
        panic!("expected allow")
    };
    assert_eq!(admitted.risk(), RiskClass::Destructive);
    assert!(admitted.verdict().rules.iter().any(|r| r == "approval.consumed"));
    assert_eq!(admitted.verdict().approval, Some(req.approval_id));

    let (p, c) = delete_case().build();
    assert_eq!(
        k.classify(&p, &c).decision,
        SafetyDecision::ApprovalRequired,
        "spent grants are not rankable again"
    );
    match k.adjudicate_with(p, &c, opts) {
        Adjudication::Deny(v) => assert!(
            v.rules.iter().any(|r| r == "approval.already_consumed"),
            "{:?}",
            v.rules
        ),
        other => panic!("second use must deny: {other:?}"),
    }
}

#[test]
fn parked_adjudication_issues_one_request_per_action_and_ungranted_ignores_store_grants() {
    let clock = manual_clock();
    let store = Arc::new(InMemoryApprovalStore::new(Arc::new(clock.clone())));
    let k = kernel_with_clock(TE, &clock).with_approval_store(store.clone());

    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, first) = k.adjudicate_parked(p, &c, None) else {
        panic!("expected approval_required")
    };
    // an identical action parked again is a different parked action: it gets its own request
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, second) = k.adjudicate_parked(p, &c, None) else {
        panic!("expected approval_required")
    };
    assert_ne!(first.approval_id, second.approval_id);
    assert_eq!(store.len(), 2);

    // a grant in the synchronous store ranks the action for the legacy gate only
    store.approve_now(first.approval_id, "reviewer").unwrap();
    store.approve_now(second.approval_id, "reviewer").unwrap();
    let (p, c) = delete_case().build();
    assert_eq!(k.classify(&p, &c).decision, SafetyDecision::Allow);
    let ungranted = k.classify_ungranted(&p, &c);
    assert_eq!(ungranted.decision, SafetyDecision::ApprovalRequired);
    assert_eq!(ungranted.approval, None);
}

#[test]
fn parked_request_expires_at_the_given_run_deadline() {
    let clock = manual_clock();
    let k = kernel_with_clock(TE, &clock);
    let deadline = clock.now() + chrono::Duration::hours(2);
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, req) = k.adjudicate_parked(p, &c, Some(deadline)) else {
        panic!("expected approval_required")
    };
    assert_eq!(req.expires_at, deadline);
}

#[test]
fn approval_expires_after_24_hours() {
    let clock = manual_clock();
    let store = Arc::new(InMemoryApprovalStore::new(Arc::new(clock.clone())));
    let k = kernel_with_clock(TE, &clock).with_approval_store(store.clone());
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, req) = k.adjudicate(p, &c) else {
        panic!()
    };
    store.approve_now(req.approval_id, "r").unwrap();
    clock.advance_ms(24 * 3600 * 1000);
    let (p, c) = delete_case().build();
    let opts = AdjudicateOptions {
        approval: Some(req.approval_id),
        ..AdjudicateOptions::default()
    };
    match k.adjudicate_with(p, &c, opts) {
        Adjudication::Deny(v) => assert!(v.rules.iter().any(|r| r == "approval.expired"), "{:?}", v.rules),
        other => panic!("expired approval must deny: {other:?}"),
    }
    // an expired request is not reused: a fresh one is issued
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, fresh) = k.adjudicate(p, &c) else {
        panic!()
    };
    assert_ne!(fresh.approval_id, req.approval_id);
}

#[test]
fn approval_is_capped_by_the_run_deadline() {
    let clock = manual_clock();
    let deadline = clock.now() + chrono::Duration::hours(2);
    let k = kernel_with_clock(TE, &clock).with_run_deadline(deadline);
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, req) = k.adjudicate(p, &c) else {
        panic!()
    };
    assert_eq!(req.expires_at, deadline);
}

#[test]
fn approval_does_not_waive_the_kernel_changed_action_or_class_voids_it() {
    let clock = manual_clock();
    let store = Arc::new(InMemoryApprovalStore::new(Arc::new(clock.clone())));
    let k = kernel_with_clock(TE, &clock).with_approval_store(store.clone());
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, req) = k.adjudicate(p, &c) else {
        panic!()
    };
    store.approve_now(req.approval_id, "r").unwrap();
    let opts = AdjudicateOptions {
        approval: Some(req.approval_id),
        ..AdjudicateOptions::default()
    };

    // class changed (now a security change, denied under test_environment): deny, approval untouched
    let (p, c) = Case::click("button", "Change password").profile(TE).build();
    assert_eq!(k.adjudicate_with(p, &c, opts).decision(), SafetyDecision::Deny);

    // different parameters on the same context key: mismatch
    let other = Case::click("button", "Delete project").profile(TE).action(
        crawlx_core::action::BrowserAction::SyntheticClick {
            target: common::locator(),
        },
    );
    let (p, c) = other.build();
    match k.adjudicate_with(p, &c, opts) {
        Adjudication::Deny(v) | Adjudication::ApprovalRequired(v, _) => {
            assert_ne!(v.decision, SafetyDecision::Allow)
        }
        Adjudication::Allow(_) => panic!("approval must not transfer to a different action"),
    }

    // the approval is still spendable by the original action
    let (p, c) = delete_case().build();
    assert!(matches!(k.adjudicate_with(p, &c, opts), Adjudication::Allow(_)));
}

#[test]
fn denied_approval_never_admits() {
    let clock = manual_clock();
    let store = Arc::new(InMemoryApprovalStore::new(Arc::new(clock.clone())));
    let k = kernel_with_clock(TE, &clock).with_approval_store(store.clone());
    let (p, c) = delete_case().build();
    let Adjudication::ApprovalRequired(_, req) = k.adjudicate(p, &c) else {
        panic!()
    };
    store.deny_now(req.approval_id, "r").unwrap();
    let (p, c) = delete_case().build();
    let opts = AdjudicateOptions {
        approval: Some(req.approval_id),
        ..AdjudicateOptions::default()
    };
    assert_eq!(k.adjudicate_with(p, &c, opts).decision(), SafetyDecision::Deny);
    // unknown id
    let (p, c) = delete_case().build();
    let opts = AdjudicateOptions {
        approval: Some(crawlx_core::ids::ApprovalId::new()),
        ..AdjudicateOptions::default()
    };
    assert_eq!(k.adjudicate_with(p, &c, opts).decision(), SafetyDecision::Deny);
}

struct BrokenStore;
impl ApprovalStore for BrokenStore {
    fn issue(&self, _: crawlx_safety::ApprovalRequest) -> Result<(), ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
    fn find_open(
        &self,
        _: crawlx_core::ids::ActionContextId,
        _: RiskClass,
        _: &crawlx_core::hash::Digest,
        _: crawlx_core::time::Timestamp,
    ) -> Result<Option<crawlx_safety::ApprovalRecord>, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
    fn get(
        &self,
        _: crawlx_core::ids::ApprovalId,
    ) -> Result<Option<crawlx_safety::ApprovalRecord>, ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
    fn approve(
        &self,
        _: crawlx_core::ids::ApprovalId,
        _: &str,
        _: crawlx_core::time::Timestamp,
    ) -> Result<(), ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
    fn deny(
        &self,
        _: crawlx_core::ids::ApprovalId,
        _: &str,
        _: crawlx_core::time::Timestamp,
    ) -> Result<(), ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
    fn consume(
        &self,
        _: crawlx_core::ids::ApprovalId,
        _: crawlx_core::ids::ActionContextId,
        _: RiskClass,
        _: &crawlx_core::hash::Digest,
        _: crawlx_core::time::Timestamp,
    ) -> Result<(), ApprovalError> {
        Err(ApprovalError::Unavailable)
    }
}

#[test]
fn unavailable_approval_store_denies() {
    let k = kernel(TE).with_approval_store(Arc::new(BrokenStore));
    let (p, c) = delete_case().build();
    assert_eq!(k.adjudicate(p, &c).decision(), SafetyDecision::Deny);
}

// ---- model hints ---------------------------------------------------------------

#[test]
fn model_hint_floor_raises_and_never_lowers() {
    let hint = |floor| AdjudicateOptions {
        hint: ModelHint {
            risk_floor: Some(floor),
            request_approval: false,
        },
        approval: None,
    };
    // raise: a hover becomes destructive
    let (p, c) = Case::hover().profile(TE).build();
    let adj = kernel(TE).adjudicate_with(p, &c, hint(RiskClass::Destructive));
    assert_eq!(adj.verdict().risk_class, RiskClass::Destructive);
    assert!(matches!(adj, Adjudication::ApprovalRequired(..)));
    // lower: a destructive click stays destructive
    let (p, c) = delete_case().build();
    let adj = kernel(TE).adjudicate_with(p, &c, hint(RiskClass::NavigationReveal));
    assert_eq!(adj.verdict().risk_class, RiskClass::Destructive);
    // proposal-level hint behaves the same
    let (p, c) = delete_case().hint(RiskClass::NavigationReveal).build();
    assert_eq!(
        kernel(TE).adjudicate(p, &c).verdict().risk_class,
        RiskClass::Destructive
    );
}

#[test]
fn model_cannot_flip_deny_to_allow_but_can_ask_for_approval() {
    let ask = AdjudicateOptions {
        hint: ModelHint {
            risk_floor: None,
            request_approval: true,
        },
        approval: None,
    };
    // allow -> approval_required
    let (p, c) = Case::hover().profile(TE).build();
    let adj = kernel(TE).adjudicate_with(p, &c, ask);
    assert!(matches!(adj, Adjudication::ApprovalRequired(..)));
    assert!(adj.verdict().rules.iter().any(|r| r == "hint.request_approval"));
    // deny stays deny
    let (p, c) = Case::click("button", "Pay now").profile(TE).build();
    assert_eq!(
        kernel(TE).adjudicate_with(p, &c, ask).decision(),
        SafetyDecision::Deny
    );
}

fn strictness(d: SafetyDecision) -> u8 {
    match d {
        SafetyDecision::Allow => 0,
        SafetyDecision::ApprovalRequired => 1,
        SafetyDecision::Deny => 2,
    }
}

fn any_class() -> impl Strategy<Value = RiskClass> {
    prop::sample::select(vec![
        RiskClass::NavigationReveal,
        RiskClass::ReversibleLocalPreference,
        RiskClass::PersistentWriteOwn,
        RiskClass::PersistentWriteOtherPrincipal,
        RiskClass::ExternalCommunication,
        RiskClass::FinancialTransaction,
        RiskClass::Destructive,
        RiskClass::SecurityChange,
        RiskClass::FileUpload,
        RiskClass::OutOfScope,
        RiskClass::Unclassified,
    ])
}

proptest! {
    /// Adding any hint never moves the verdict from Deny or
    /// ApprovalRequired towards Allow.
    #[test]
    fn hints_never_relax_a_decision(
        profile in prop::sample::select(PROFILES.to_vec()),
        name in prop::sample::select(vec!["Save", "Delete project", "Pay now", "Send invite", "Change password", "Menu", "Go", ""]),
        floor in prop::option::of(any_class()),
        proposal_hint in prop::option::of(any_class()),
        ask in any::<bool>(),
    ) {
        let mut base = Case::click("button", name).profile(profile);
        let k = kernel(profile);
        let (p, c) = base.build();
        let without = k.adjudicate(p, &c).decision();
        base.hinted = proposal_hint;
        let (p, c) = base.build();
        let opts = AdjudicateOptions { hint: ModelHint { risk_floor: floor, request_approval: ask }, approval: None };
        let with = k.adjudicate_with(p, &c, opts).decision();
        prop_assert!(strictness(with) >= strictness(without), "{without:?} -> {with:?}");
    }

    /// Every adjudication carries a verdict and Allow always has one.
    #[test]
    fn allow_always_has_a_matching_verdict(
        profile in prop::sample::select(PROFILES.to_vec()),
        name in "[A-Za-z ]{0,24}",
        role in prop::sample::select(vec!["button", "link", "tab", "menuitem", "combobox", "textbox"]),
    ) {
        let (p, c) = Case::click(role, &name).profile(profile).build();
        let adj = kernel(profile).adjudicate(p, &c);
        if let Adjudication::Allow(a) = &adj {
            prop_assert_eq!(a.verdict().decision, SafetyDecision::Allow);
            prop_assert_eq!(a.verdict().decision_id, a.decision());
        }
        prop_assert!(!adj.verdict().rules.is_empty());
    }
}

// ---- confirm -------------------------------------------------------------------

fn admitted_link() -> (SafetyKernel, crawlx_safety::AdmittedAction, LiveTargetFacts) {
    let k = kernel(SafetyProfile::ReadOnly);
    let case = Case::click("link", "Projects").href("/projects").tag("a");
    let facts = case.facts.clone();
    let (p, c) = case.build();
    let Adjudication::Allow(a) = k.adjudicate(p, &c) else {
        panic!("link must be allowed read_only")
    };
    (k, a, facts)
}

#[test]
fn confirm_accepts_unchanged_live_facts() {
    let (k, a, live) = admitted_link();
    assert_eq!(k.confirm(&a, &live), Ok(()));
}

#[test]
fn confirm_tolerates_counters_in_names() {
    let k = kernel(SafetyProfile::ReadOnly);
    let case = Case::click("link", "Inbox (5)").href("/inbox");
    let mut live = case.facts.clone();
    let (p, c) = case.build();
    let Adjudication::Allow(a) = k.adjudicate(p, &c) else {
        panic!()
    };
    live.name = Some("Inbox (6)".into());
    assert_eq!(k.confirm(&a, &live), Ok(()));
}

#[test]
fn confirm_denies_when_identity_changes() {
    let (k, a, live) = admitted_link();
    let mut changed = live.clone();
    changed.name = Some("Logout".into());
    assert_eq!(k.confirm(&a, &changed), Err(SafetyDenied::IdentityChanged));
    let mut changed = live.clone();
    changed.href = Some("/admin".into());
    assert_eq!(k.confirm(&a, &changed), Err(SafetyDenied::IdentityChanged));
    let mut changed = live.clone();
    changed.role = Some("button".into());
    assert_eq!(k.confirm(&a, &changed), Err(SafetyDenied::IdentityChanged));
    let mut changed = live;
    changed.href = None;
    assert_eq!(k.confirm(&a, &changed), Err(SafetyDenied::IdentityChanged));
}

#[test]
fn confirm_denies_when_the_page_left_scope() {
    let (k, a, live) = admitted_link();
    let mut moved = live.clone();
    moved.current_url = "https://evil.example.net/phish".into();
    assert_eq!(k.confirm(&a, &moved), Err(SafetyDenied::ScopeExit));
    let mut moved = live;
    moved.current_url = String::new();
    assert_eq!(k.confirm(&a, &moved), Err(SafetyDenied::ScopeExit));
}

#[test]
fn confirm_reclassifies_live_facts_and_denies_any_raise() {
    // admitted as a reveal (disclosure); live evidence now shows a write method was observed
    let k = kernel(SafetyProfile::ReadOnly);
    let case = Case::click("button", "Details").attr("aria-expanded", "false");
    let live = case.facts.clone();
    let (p, c) = case.build();
    let Adjudication::Allow(a) = k.adjudicate(p, &c) else {
        panic!()
    };
    assert_eq!(a.risk(), RiskClass::NavigationReveal);

    let mut raised = live.clone();
    raised.attributes.insert("observed-methods".into(), "POST".into());
    assert_eq!(
        k.confirm(&a, &raised),
        Err(SafetyDenied::RiskRaised {
            admitted: RiskClass::NavigationReveal,
            live: RiskClass::PersistentWriteOwn
        })
    );

    // the structural evidence disappearing is also a raise (to unclassified)
    let mut gone = live.clone();
    gone.attributes.clear();
    assert_eq!(
        k.confirm(&a, &gone),
        Err(SafetyDenied::RiskRaised {
            admitted: RiskClass::NavigationReveal,
            live: RiskClass::Unclassified
        })
    );
    assert_eq!(k.confirm(&a, &live), Ok(()));
}

#[test]
fn confirm_denials_are_audited() {
    let log = Arc::new(MemoryAuditLog::new());
    let k = kernel(SafetyProfile::ReadOnly).with_audit_sink(log.clone());
    let case = Case::click("link", "Projects").href("/projects");
    let mut live = case.facts.clone();
    let (p, c) = case.build();
    let Adjudication::Allow(a) = k.adjudicate(p, &c) else {
        panic!()
    };
    live.name = Some("Delete everything".into());
    assert!(k.confirm(&a, &live).is_err());
    let entries = log.entries();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].verdict.decision, SafetyDecision::Deny);
    assert_eq!(
        entries[1].verdict.rules,
        vec!["confirm.identity_changed".to_owned()]
    );
    assert_ne!(entries[1].verdict.decision_id, SafetyDecisionId::default());
}

#[test]
fn confirm_skips_identity_for_targetless_actions_but_checks_scope() {
    let k = kernel(SafetyProfile::ReadOnly);
    let nav = Case::new(
        SafetyProfile::ReadOnly,
        crawlx_core::action::BrowserAction::Navigate {
            url: url::Url::parse("https://app.example.com/projects").unwrap(),
        },
    );
    let (p, c) = nav.build();
    let Adjudication::Allow(a) = k.adjudicate(p, &c) else {
        panic!()
    };
    assert!(a.locator().is_none());
    let live = LiveTargetFacts {
        current_url: common::PAGE.into(),
        ..LiveTargetFacts::default()
    };
    assert_eq!(k.confirm(&a, &live), Ok(()));
    let off = LiveTargetFacts {
        current_url: "https://evil.example.net/".into(),
        ..LiveTargetFacts::default()
    };
    assert_eq!(k.confirm(&a, &off), Err(SafetyDenied::ScopeExit));
}

#[test]
fn admitted_action_exposes_proposal_action_and_locator() {
    let (_, a, _) = admitted_link();
    assert!(a.locator().is_some());
    assert_eq!(a.proposal().strategy, "test");
    assert!(matches!(
        a.browser_action(),
        crawlx_core::action::BrowserAction::Click { .. }
    ));
}

#[test]
fn destructive_option_setting_is_respected_in_config() {
    let mut cfg = config(TE);
    cfg.destructive_approval = DestructiveActions::Deny;
    let k = SafetyKernel::new(cfg).unwrap();
    let (p, c) = delete_case().build();
    let adj = k.adjudicate(p, &c);
    assert_eq!(adj.decision(), SafetyDecision::Deny);
    assert!(adj
        .verdict()
        .rules
        .iter()
        .any(|r| r == "option.destructive_actions.deny"));
}

// ---- survivors of the first mutation run -------------------------

#[test]
fn policy_version_is_the_configured_one() {
    assert_eq!(kernel(TE).policy_version(), 7);
    let mut cfg = config(TE);
    cfg.policy_version = 12;
    assert_eq!(SafetyKernel::new(cfg).unwrap().policy_version(), 12);
}

#[test]
fn memory_audit_log_is_empty_until_a_verdict_is_written() {
    let log = Arc::new(MemoryAuditLog::new());
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    let k = kernel(TE).with_audit_sink(log.clone());
    let (p, c) = Case::hover().profile(TE).build();
    let _ = k.adjudicate(p, &c);
    assert!(!log.is_empty());
    assert_eq!(log.len(), 1);
}

#[test]
fn model_floor_rule_is_recorded_only_when_the_floor_raised_the_class() {
    let floor = |class| AdjudicateOptions {
        hint: ModelHint {
            risk_floor: Some(class),
            request_approval: false,
        },
        approval: None,
    };
    let has_rule = |adj: &Adjudication| adj.verdict().rules.iter().any(|r| r == "hint.model_floor");
    let (p, c) = Case::hover().profile(TE).build();
    let adj = kernel(TE).adjudicate_with(p, &c, floor(RiskClass::PersistentWriteOwn));
    assert_eq!(adj.verdict().risk_class, RiskClass::PersistentWriteOwn);
    assert!(has_rule(&adj));
    let (p, c) = delete_case().build();
    assert!(!has_rule(&kernel(TE).adjudicate_with(
        p,
        &c,
        floor(RiskClass::NavigationReveal)
    )));
    let (p, c) = delete_case().build();
    assert!(!has_rule(&kernel(TE).adjudicate_with(
        p,
        &c,
        floor(RiskClass::Destructive)
    )));
    let (p, c) = delete_case().build();
    assert!(!has_rule(&kernel(TE).adjudicate(p, &c)));
}

#[test]
fn profile_narrowed_rule_is_absent_when_context_and_kernel_agree() {
    for profile in PROFILES {
        let (p, c) = Case::hover().profile(profile).build();
        let adj = kernel(profile).adjudicate(p, &c);
        assert!(
            !adj.verdict().rules.iter().any(|r| r == "profile.narrowed"),
            "{profile:?}: {:?}",
            adj.verdict().rules
        );
    }
}

#[test]
fn cross_principal_probe_rule_needs_allow_cross_principal_and_authorized() {
    let auth = SafetyProfile::AuthorizedSecurityTest;
    let probe = |adj: &Adjudication| adj.verdict().rules.iter().any(|r| r == "probe.cross_principal");
    // allowed under authorized_security_test, but an own write
    let (p, c) = Case::click("button", "Save").profile(auth).build();
    let adj = kernel(auth).adjudicate(p, &c);
    assert!(matches!(adj, Adjudication::Allow(_)));
    assert!(!probe(&adj), "{:?}", adj.verdict().rules);
    // cross-principal write, but under test_environment (approval required)
    let (p, c) = Case::click("button", "Save")
        .resource(ResourceContext::OtherUserSameRole)
        .profile(TE)
        .build();
    let adj = kernel(TE).adjudicate(p, &c);
    assert!(matches!(adj, Adjudication::ApprovalRequired(..)));
    assert!(!probe(&adj), "{:?}", adj.verdict().rules);
    // all three: recorded
    let (p, c) = Case::click("button", "Save")
        .resource(ResourceContext::OtherUserSameRole)
        .profile(auth)
        .build();
    let adj = kernel(auth).adjudicate(p, &c);
    assert!(matches!(adj, Adjudication::Allow(_)));
    assert!(probe(&adj));
}

#[test]
fn pending_approval_must_match_key_class_and_params() {
    let auth = SafetyProfile::AuthorizedSecurityTest;
    let clock = manual_clock();
    let store = Arc::new(InMemoryApprovalStore::new(Arc::new(clock.clone())));
    let k = kernel_with_clock(auth, &clock).with_approval_store(store.clone());
    let (p, c) = delete_case().profile(auth).build();
    let Adjudication::ApprovalRequired(_, req) = k.adjudicate(p, &c) else {
        panic!("expected approval_required")
    };
    let opts = AdjudicateOptions {
        approval: Some(req.approval_id),
        ..AdjudicateOptions::default()
    };
    let mismatch = |case: Case| {
        let (p, c) = case.build();
        match k.adjudicate_with(p, &c, opts) {
            Adjudication::Deny(v) => {
                assert!(v.rules.iter().any(|r| r == "approval.mismatch"), "{:?}", v.rules);
            }
            other => panic!("expected an approval.mismatch deny: {other:?}"),
        }
    };
    // same key and params, different class (financial, also approval-gated here)
    mismatch(Case::click("button", "Pay now").profile(auth));
    // same class and params, different key (another principal's resource)
    mismatch(
        delete_case()
            .profile(auth)
            .resource(ResourceContext::OtherUserSameRole),
    );
    // same key and class, different params (secondary button)
    mismatch(delete_case().profile(auth).action(BrowserAction::Click {
        target: common::locator(),
        button: PointerButton::Right,
        modifiers: crawlx_core::action::Modifiers::default(),
    }));
    // the original action still waits on the same request
    let (p, c) = delete_case().profile(auth).build();
    let Adjudication::ApprovalRequired(_, again) = k.adjudicate_with(p, &c, opts) else {
        panic!("expected approval_required")
    };
    assert_eq!(again.approval_id, req.approval_id);
    assert_eq!(store.len(), 1);
}

#[test]
fn confirm_denies_when_live_rules_tighten_the_decision_at_equal_risk() {
    let frozen = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&frozen);
    let k = kernel(TE).with_rule_hook(Arc::new(move |_p, _c| {
        if flag.load(Ordering::SeqCst) {
            vec!["tenant.freeze".to_owned()]
        } else {
            Vec::new()
        }
    }));
    let case = Case::click("button", "Save").profile(TE);
    let live = case.facts.clone();
    let (p, c) = case.build();
    let Adjudication::Allow(a) = k.adjudicate(p, &c) else {
        panic!("expected allow")
    };
    assert_eq!(a.risk(), RiskClass::PersistentWriteOwn);
    assert_eq!(k.confirm(&a, &live), Ok(()));
    frozen.store(true, Ordering::SeqCst);
    assert_eq!(
        k.confirm(&a, &live),
        Err(SafetyDenied::DecisionTightened {
            admitted: SafetyDecision::Allow,
            live: SafetyDecision::Deny,
        })
    );
}
