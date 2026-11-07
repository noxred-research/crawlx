//! An authorization record narrows the profile matrix (`permittedRiskClasses`, `approvalRequired`)
//! and never widens it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{class_of, kernel, Case, PROFILES};
use crawlx_core::safety::{RiskClass, SafetyDecision};
use crawlx_safety::{Adjudication, RecordNarrowing};

const NAMES: [&str; 8] = [
    "Save",
    "Delete",
    "Pay",
    "Send",
    "Change password",
    "Menu",
    "Go",
    "Invite user",
];

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for name in NAMES {
        out.push(Case::click("button", name));
        out.push(Case::click("link", name).href("/x"));
    }
    out.push(Case::hover());
    out.push(Case::upload());
    out
}

const fn strictness(d: SafetyDecision) -> u8 {
    match d {
        SafetyDecision::Allow => 0,
        SafetyDecision::ApprovalRequired => 1,
        SafetyDecision::Deny => 2,
    }
}

fn rules_of(adj: &Adjudication) -> &[String] {
    &adj.verdict().rules
}

#[test]
fn a_record_listing_every_class_changes_nothing() {
    let record = RecordNarrowing::new(RiskClass::PERMITTABLE, []);
    for profile in PROFILES {
        let plain = kernel(profile);
        let narrowed = kernel(profile).with_record_narrowing(record.clone());
        for case in cases() {
            let (p, c) = case.clone().profile(profile).build();
            let before = plain.adjudicate(p, &c);
            let (p, c) = case.profile(profile).build();
            let after = narrowed.adjudicate(p, &c);
            assert_eq!(before.decision(), after.decision(), "{profile:?}");
            assert_eq!(rules_of(&before), rules_of(&after), "{profile:?}");
        }
    }
}

#[test]
fn an_unlisted_class_is_denied_with_the_record_rule() {
    // the record permits own-data writes only
    let record = RecordNarrowing::new([RiskClass::PersistentWriteOwn], []);
    let profile = common::PROFILES[1]; // test_environment
    let k = kernel(profile).with_record_narrowing(record.clone());
    let mut denied_by_record = 0;
    for case in cases() {
        let class = class_of(&case.clone().profile(profile));
        let (p, c) = case.clone().profile(profile).build();
        let base = kernel(profile).adjudicate(p, &c);
        let (p, c) = case.profile(profile).build();
        let adj = k.adjudicate(p, &c);
        if base.decision() != SafetyDecision::Deny && !record.permits(class) {
            assert_eq!(adj.decision(), SafetyDecision::Deny, "{class:?}");
            assert!(
                rules_of(&adj).iter().any(|r| r == "record.class_not_permitted"),
                "{class:?}: {:?}",
                rules_of(&adj)
            );
            denied_by_record += 1;
        } else {
            assert_eq!(adj.decision(), base.decision(), "{class:?}");
        }
    }
    assert!(denied_by_record > 0, "the fixture never exercised the rule");
}

#[test]
fn a_record_approval_class_turns_allow_into_approval_required() {
    let record = RecordNarrowing::new(RiskClass::PERMITTABLE, [RiskClass::PersistentWriteOwn]);
    let profile = common::PROFILES[1];
    let k = kernel(profile).with_record_narrowing(record);
    let mut hit = 0;
    for case in cases() {
        let class = class_of(&case.clone().profile(profile));
        let (p, c) = case.clone().profile(profile).build();
        let base = kernel(profile).adjudicate(p, &c);
        let (p, c) = case.profile(profile).build();
        let adj = k.adjudicate(p, &c);
        if class == RiskClass::PersistentWriteOwn && base.decision() == SafetyDecision::Allow {
            assert_eq!(adj.decision(), SafetyDecision::ApprovalRequired);
            assert!(rules_of(&adj).iter().any(|r| r == "record.approval_required"));
            assert!(matches!(adj, Adjudication::ApprovalRequired(..)));
            hit += 1;
        } else {
            assert_eq!(adj.decision(), base.decision(), "{class:?}");
        }
    }
    assert!(hit > 0, "the fixture never exercised the rule");
}

#[test]
fn a_record_never_loosens_any_profile_cell() {
    let records = [
        RecordNarrowing::new([], []),
        RecordNarrowing::new(RiskClass::PERMITTABLE, []),
        RecordNarrowing::new(RiskClass::PERMITTABLE, RiskClass::PERMITTABLE),
        RecordNarrowing::new([RiskClass::Destructive, RiskClass::FinancialTransaction], []),
        RecordNarrowing::new(
            [],
            [RiskClass::Destructive, RiskClass::PersistentWriteOtherPrincipal],
        ),
    ];
    for record in records {
        for profile in PROFILES {
            let k = kernel(profile).with_record_narrowing(record.clone());
            for case in cases() {
                let (p, c) = case.clone().profile(profile).build();
                let base = kernel(profile).adjudicate(p, &c);
                let (p, c) = case.clone().profile(profile).build();
                let adj = k.adjudicate(p, &c);
                assert!(
                    strictness(adj.decision()) >= strictness(base.decision()),
                    "{profile:?} {:?}: {:?} -> {:?}",
                    case.facts.name,
                    base.decision(),
                    adj.decision()
                );
                if base.decision() == SafetyDecision::Deny {
                    assert_eq!(
                        rules_of(&base),
                        rules_of(&adj),
                        "a denied action gains no record rule"
                    );
                }
            }
        }
    }
}
