//! CAPTCHA callbacks are explicit consequential actions, never free navigation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{kernel, Case};
use crawlx_core::action::BrowserAction;
use crawlx_core::config::SafetyProfile;
use crawlx_core::safety::{RiskClass, SafetyDecision};

#[test]
fn captcha_callback_requires_writable_profile_and_stays_non_idempotent() {
    for (profile, expected) in [
        (SafetyProfile::ReadOnly, SafetyDecision::Deny),
        (SafetyProfile::TestEnvironment, SafetyDecision::Allow),
        (SafetyProfile::AuthorizedSecurityTest, SafetyDecision::Allow),
    ] {
        let (proposal, context) = Case::new(profile, BrowserAction::SolveCaptcha).build();
        assert!(!proposal.action.kind().is_idempotent());
        let verdict = kernel(profile).adjudicate(proposal, &context);
        assert_eq!(verdict.decision(), expected);
        assert_eq!(verdict.verdict().risk_class, RiskClass::Unclassified);
        assert!(verdict
            .verdict()
            .rules
            .iter()
            .any(|rule| rule == "kind.captcha_callback"));
    }
}

#[test]
fn captcha_callback_cannot_escape_origin_or_lower_destructive_evidence() {
    let profile = SafetyProfile::TestEnvironment;
    let (proposal, context) = Case::new(profile, BrowserAction::SolveCaptcha)
        .url("https://outside.example.org/challenge")
        .build();
    assert_eq!(
        kernel(profile).adjudicate(proposal, &context).decision(),
        SafetyDecision::Deny
    );
    let (proposal, context) = Case::new(profile, BrowserAction::SolveCaptcha)
        .named("button", "Delete account")
        .build();
    let verdict = kernel(profile).adjudicate(proposal, &context);
    assert_eq!(verdict.verdict().risk_class, RiskClass::Destructive);
    assert_ne!(verdict.decision(), SafetyDecision::Allow);
}
