//! One test per cell of the safety table (3 profiles × 10 classes),
//! driven through `SafetyKernel::adjudicate` with proposals whose structural
//! and textual evidence produces the class.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{kernel, Case, SEED};
use crawlx_core::config::SafetyProfile;
use crawlx_core::identity::ResourceContext;
use crawlx_core::safety::{RiskClass, SafetyDecision};
use crawlx_safety::Adjudication;
use SafetyDecision::{Allow, ApprovalRequired, Deny};

fn case_for(class: RiskClass) -> Case {
    match class {
        RiskClass::NavigationReveal => Case::hover(),
        RiskClass::ReversibleLocalPreference => Case::new(
            SafetyProfile::ReadOnly,
            crawlx_core::action::BrowserAction::SetChecked {
                target: common::locator(),
                checked: true,
            },
        )
        .named("combobox", "Sort by"),
        RiskClass::PersistentWriteOwn => Case::click("button", "Save"),
        RiskClass::PersistentWriteOtherPrincipal => {
            Case::click("button", "Save").resource(ResourceContext::OtherUserSameRole)
        }
        RiskClass::ExternalCommunication => {
            Case::click("button", "Send invitation").attr("form-action", &format!("{SEED}/sink"))
        }
        RiskClass::FinancialTransaction => Case::click("button", "Pay now"),
        RiskClass::Destructive => Case::click("button", "Delete project"),
        RiskClass::SecurityChange => Case::click("button", "Change password"),
        RiskClass::FileUpload => Case::upload(),
        RiskClass::OutOfScope => Case::click("link", "Docs").href("https://evil.example.net/docs"),
        RiskClass::Unclassified => Case::click("button", ""),
    }
}

fn check(class: RiskClass, profile: SafetyProfile, expected: SafetyDecision) {
    let case = case_for(class).profile(profile);
    let (p, c) = case.build();
    let k = kernel(profile);
    let adj = k.adjudicate(p, &c);
    assert_eq!(
        adj.verdict().risk_class,
        class,
        "class for {class:?}: rules {:?}",
        adj.verdict().rules
    );
    assert_eq!(
        adj.decision(),
        expected,
        "{class:?} under {profile:?}: rules {:?}",
        adj.verdict().rules
    );
    match (&adj, expected) {
        (Adjudication::Allow(a), Allow) => assert_eq!(a.verdict().decision, Allow),
        (Adjudication::Deny(_), Deny) => {}
        (Adjudication::ApprovalRequired(v, req), ApprovalRequired) => {
            assert_eq!(v.approval, Some(req.approval_id));
            assert_eq!(req.risk, class);
        }
        other => panic!("variant does not match decision: {other:?}"),
    }
}

macro_rules! cell {
    ($name:ident, $class:expr, $profile:expr, $decision:expr) => {
        #[test]
        fn $name() {
            check($class, $profile, $decision);
        }
    };
}

use SafetyProfile::{AuthorizedSecurityTest as Auth, ReadOnly as Ro, TestEnvironment as Te};

cell!(
    navigation_reveal_read_only,
    RiskClass::NavigationReveal,
    Ro,
    Allow
);
cell!(
    navigation_reveal_test_environment,
    RiskClass::NavigationReveal,
    Te,
    Allow
);
cell!(
    navigation_reveal_authorized,
    RiskClass::NavigationReveal,
    Auth,
    Allow
);

cell!(
    local_preference_read_only,
    RiskClass::ReversibleLocalPreference,
    Ro,
    Allow
);
cell!(
    local_preference_test_environment,
    RiskClass::ReversibleLocalPreference,
    Te,
    Allow
);
cell!(
    local_preference_authorized,
    RiskClass::ReversibleLocalPreference,
    Auth,
    Allow
);

cell!(own_write_read_only, RiskClass::PersistentWriteOwn, Ro, Deny);
cell!(
    own_write_test_environment,
    RiskClass::PersistentWriteOwn,
    Te,
    Allow
);
cell!(own_write_authorized, RiskClass::PersistentWriteOwn, Auth, Allow);

cell!(
    other_principal_read_only,
    RiskClass::PersistentWriteOtherPrincipal,
    Ro,
    Deny
);
cell!(
    other_principal_test_environment,
    RiskClass::PersistentWriteOtherPrincipal,
    Te,
    ApprovalRequired
);
cell!(
    other_principal_authorized,
    RiskClass::PersistentWriteOtherPrincipal,
    Auth,
    Allow
);

cell!(external_read_only, RiskClass::ExternalCommunication, Ro, Deny);
cell!(
    external_test_environment,
    RiskClass::ExternalCommunication,
    Te,
    Allow
);
cell!(external_authorized, RiskClass::ExternalCommunication, Auth, Allow);

cell!(financial_read_only, RiskClass::FinancialTransaction, Ro, Deny);
cell!(
    financial_test_environment,
    RiskClass::FinancialTransaction,
    Te,
    Deny
);
cell!(
    financial_authorized,
    RiskClass::FinancialTransaction,
    Auth,
    ApprovalRequired
);

cell!(destructive_read_only, RiskClass::Destructive, Ro, Deny);
cell!(
    destructive_test_environment,
    RiskClass::Destructive,
    Te,
    ApprovalRequired
);
cell!(
    destructive_authorized,
    RiskClass::Destructive,
    Auth,
    ApprovalRequired
);

cell!(security_change_read_only, RiskClass::SecurityChange, Ro, Deny);
cell!(
    security_change_test_environment,
    RiskClass::SecurityChange,
    Te,
    Deny
);
cell!(
    security_change_authorized,
    RiskClass::SecurityChange,
    Auth,
    ApprovalRequired
);

cell!(file_upload_read_only, RiskClass::FileUpload, Ro, Deny);
cell!(file_upload_test_environment, RiskClass::FileUpload, Te, Allow);
cell!(file_upload_authorized, RiskClass::FileUpload, Auth, Allow);

cell!(out_of_scope_read_only, RiskClass::OutOfScope, Ro, Deny);
cell!(out_of_scope_test_environment, RiskClass::OutOfScope, Te, Deny);
cell!(out_of_scope_authorized, RiskClass::OutOfScope, Auth, Deny);

cell!(unclassified_read_only, RiskClass::Unclassified, Ro, Deny);
cell!(unclassified_test_environment, RiskClass::Unclassified, Te, Allow);
cell!(unclassified_authorized, RiskClass::Unclassified, Auth, Allow);

#[test]
fn cross_principal_probe_is_recorded_under_authorized_security_test() {
    let (p, c) = case_for(RiskClass::PersistentWriteOtherPrincipal)
        .profile(Auth)
        .build();
    let adj = kernel(Auth).adjudicate(p, &c);
    assert!(adj.verdict().rules.iter().any(|r| r == "probe.cross_principal"));
}
