//! Preloaded durable capabilities never waive classification or live confirmation.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{kernel_with_clock, manual_clock, Case};
use crawlx_core::config::SafetyProfile;
use crawlx_core::repo::SafetyGate;
use crawlx_core::{ActionId, CrawlRunId, SessionId, TenantId};
use crawlx_safety::approvals::{ApprovalAuthority, VerifiedApproval};
use crawlx_safety::Adjudication;

fn authority() -> ApprovalAuthority {
    ApprovalAuthority::new(
        TenantId(uuid::Uuid::from_u128(1)),
        CrawlRunId(uuid::Uuid::from_u128(2)),
        SessionId(uuid::Uuid::from_u128(3)),
        ActionId(uuid::Uuid::from_u128(4)),
        7,
        crawlx_core::epoch::ObservationEpoch::default(),
    )
}

#[test]
fn preloaded_capability_is_one_shot_and_live_confirm_still_runs() {
    let clock = manual_clock();
    let kernel = kernel_with_clock(SafetyProfile::TestEnvironment, &clock);
    let (proposal, context) = Case::click("button", "Delete project")
        .profile(SafetyProfile::TestEnvironment)
        .build();
    let Adjudication::ApprovalRequired(_, request) = kernel.adjudicate(proposal.clone(), &context) else {
        panic!("approval required");
    };
    let snapshots = [request.clone()];
    let preview = kernel.preview_gate(&snapshots);
    assert_eq!(
        preview.classify(&proposal, &context).decision,
        crawlx_core::safety::SafetyDecision::Allow
    );
    assert!(matches!(
        kernel.adjudicate(proposal.clone(), &context),
        Adjudication::ApprovalRequired(..)
    ));
    let expected = authority();
    let mut verified = VerifiedApproval::from_consumed(request, expected);
    let Adjudication::Allow(admitted) =
        kernel.adjudicate_verified(proposal.clone(), &context, expected, &mut verified)
    else {
        panic!("durable capability should admit once");
    };
    assert_eq!(admitted.approval_authority(), Some(&expected));
    assert!(kernel.confirm(&admitted, &context.target).is_ok());
    let mut changed = context.target.clone();
    changed.name = Some("Delete every project".into());
    assert!(kernel.confirm(&admitted, &changed).is_err());
    assert!(matches!(
        kernel.adjudicate_verified(proposal, &context, expected, &mut verified),
        Adjudication::Deny(_)
    ));
}

#[test]
fn every_trusted_authority_dimension_is_exact_and_failed_use_is_spent() {
    let clock = manual_clock();
    let kernel = kernel_with_clock(SafetyProfile::TestEnvironment, &clock);
    let (proposal, context) = Case::click("button", "Delete project")
        .profile(SafetyProfile::TestEnvironment)
        .build();
    let Adjudication::ApprovalRequired(_, request) = kernel.adjudicate(proposal.clone(), &context) else {
        panic!("approval required");
    };
    let expected = authority();
    for dimension in 0..6 {
        let mut wrong = expected;
        match dimension {
            0 => wrong.tenant = TenantId(uuid::Uuid::from_u128(11)),
            1 => wrong.run = CrawlRunId(uuid::Uuid::from_u128(12)),
            2 => wrong.session = SessionId(uuid::Uuid::from_u128(13)),
            3 => wrong.action = ActionId(uuid::Uuid::from_u128(14)),
            4 => wrong.fence += 1,
            5 => wrong.epoch.mutation_seq += 1,
            _ => unreachable!(),
        }
        let mut verified = VerifiedApproval::from_consumed(request.clone(), expected);
        assert!(matches!(
            kernel.adjudicate_verified(proposal.clone(), &context, wrong, &mut verified),
            Adjudication::Deny(_)
        ));
        assert!(matches!(
            kernel.adjudicate_verified(proposal.clone(), &context, expected, &mut verified),
            Adjudication::Deny(_)
        ));
    }
}

#[test]
fn params_key_epoch_and_expiry_never_reuse_a_capability() {
    let clock = manual_clock();
    let kernel = kernel_with_clock(SafetyProfile::TestEnvironment, &clock);
    let (proposal, context) = Case::click("button", "Delete project")
        .profile(SafetyProfile::TestEnvironment)
        .build();
    let Adjudication::ApprovalRequired(_, request) = kernel.adjudicate(proposal.clone(), &context) else {
        panic!("approval required");
    };
    let expected = authority();
    for dimension in 0..3 {
        let mut changed = proposal.clone();
        match dimension {
            0 => {
                let crawlx_core::action::BrowserAction::Click { button, .. } = &mut changed.action else {
                    unreachable!()
                };
                *button = crawlx_core::action::PointerButton::Right;
            }
            1 => changed.key.principal.0.push_str("-other"),
            2 => changed.epoch.document_seq += 1,
            _ => unreachable!(),
        }
        let mut verified = VerifiedApproval::from_consumed(request.clone(), expected);
        assert!(matches!(
            kernel.adjudicate_verified(changed, &context, expected, &mut verified),
            Adjudication::Deny(_)
        ));
    }
    let mut verified = VerifiedApproval::from_consumed(request, expected);
    clock.advance_ms(24 * 60 * 60 * 1_000);
    assert!(matches!(
        kernel.adjudicate_verified(proposal, &context, expected, &mut verified),
        Adjudication::Deny(_)
    ));
}

#[test]
fn preloaded_approval_cannot_override_current_hard_denial() {
    let clock = manual_clock();
    let kernel = kernel_with_clock(SafetyProfile::TestEnvironment, &clock);
    let (proposal, mut context) = Case::click("button", "Delete project")
        .profile(SafetyProfile::TestEnvironment)
        .build();
    let Adjudication::ApprovalRequired(_, request) = kernel.adjudicate(proposal.clone(), &context) else {
        panic!("approval required");
    };
    context.destructive_approval_allowed = false;
    let expected = authority();
    let mut verified = VerifiedApproval::from_consumed(request, expected);
    assert!(matches!(
        kernel.adjudicate_verified(proposal, &context, expected, &mut verified),
        Adjudication::Deny(_)
    ));
}

#[test]
fn caught_classifier_panic_also_spends_the_preloaded_capability() {
    let clock = manual_clock();
    let kernel = kernel_with_clock(SafetyProfile::TestEnvironment, &clock);
    let (proposal, context) = Case::click("button", "Delete project")
        .profile(SafetyProfile::TestEnvironment)
        .build();
    let Adjudication::ApprovalRequired(_, request) = kernel.adjudicate(proposal.clone(), &context) else {
        panic!("approval required");
    };
    let first = std::sync::atomic::AtomicBool::new(true);
    let kernel = kernel.with_rule_hook(std::sync::Arc::new(move |_, _| {
        assert!(
            !first.swap(false, std::sync::atomic::Ordering::SeqCst),
            "fixture hook failure"
        );
        Vec::new()
    }));
    let expected = authority();
    let mut verified = VerifiedApproval::from_consumed(request, expected);
    assert!(matches!(
        kernel.adjudicate_verified(proposal.clone(), &context, expected, &mut verified),
        Adjudication::Deny(_)
    ));
    assert!(matches!(
        kernel.adjudicate_verified(proposal, &context, expected, &mut verified),
        Adjudication::Deny(_)
    ));
}
