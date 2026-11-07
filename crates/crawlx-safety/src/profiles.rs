//! The three safety profiles (`read_only`, `test_environment`,
//! `authorized_security_test`) as a decision table.
//!
//! The base table is `RiskClass::default_decision` from `crawlx-core`; this
//! module adds the request options that can only **narrow** it
//! (`safety.destructiveActions`, `safety.externalCommunication`), the
//! file-upload fixture rule, and the raise-only [`ModelHint`].
//! No function here can turn a `Deny` or `ApprovalRequired` into `Allow`.

use crate::classify::severity;
use crawlx_core::config::{DestructiveActions, ExternalCommunication, SafetyProfile};
use crawlx_core::identity::ActionKind;
use crawlx_core::safety::{ModelHint, RiskClass, SafetyDecision};
use std::collections::BTreeSet;

/// Run options and live facts that feed the table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProfileOptions {
    /// `safety.destructiveActions`: whether destructive actions may ask for approval.
    pub destructive: DestructiveActions,
    /// `safety.externalCommunication`: whether the run opted in to test sinks.
    pub external: ExternalCommunication,
    /// A verified test sink of the kind the action needs exists.
    pub sink_verified: bool,
}

impl Default for ProfileOptions {
    fn default() -> Self {
        Self {
            destructive: DestructiveActions::Deny,
            external: ExternalCommunication::Deny,
            sink_verified: false,
        }
    }
}

impl ProfileOptions {
    /// Sinks usable by `external_communication`: the run opted in **and** a
    /// verified sink exists.
    #[must_use]
    pub const fn has_sinks(&self) -> bool {
        matches!(self.external, ExternalCommunication::TestSinks) && self.sink_verified
    }
}

/// Table lookup result with the rule ids that produced it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProfileDecision {
    /// Table decision after the options narrowed it.
    pub decision: SafetyDecision,
    /// Rule identifiers that produced the decision, in evaluation order.
    pub rules: Vec<String>,
}

/// The stricter of two profiles (`read_only` < `test_environment` <
/// `authorized_security_test` in privilege).
#[must_use]
pub fn narrow(a: SafetyProfile, b: SafetyProfile) -> SafetyProfile {
    a.min(b)
}

/// How restrictive a decision is: `Allow` < `ApprovalRequired` < `Deny`.
#[must_use]
pub const fn strictness(d: SafetyDecision) -> u8 {
    match d {
        SafetyDecision::Allow => 0,
        SafetyDecision::ApprovalRequired => 1,
        SafetyDecision::Deny => 2,
    }
}

/// Raise `class` to `floor` if `floor` is more severe. Never lowers.
#[must_use]
pub fn raise(class: RiskClass, floor: Option<RiskClass>) -> RiskClass {
    match floor {
        Some(f) if severity(f) > severity(class) => f,
        _ => class,
    }
}

/// Decide `class` under `profile`, applying request options as narrowing only.
/// `kind` is needed for the file-upload rule: the table's "fixture files
/// only" is enforced by the action type, so only [`ActionKind::Upload`]
/// (which carries a `FixtureFileId`) may be allowed.
#[must_use]
pub fn decide(
    class: RiskClass,
    profile: SafetyProfile,
    kind: ActionKind,
    opts: &ProfileOptions,
) -> ProfileDecision {
    let base = class.default_decision(profile, opts.has_sinks());
    let mut rules = vec![format!(
        "profile.{}.{}.{}",
        profile.as_str(),
        class.as_str(),
        base.as_str()
    )];
    let mut decision = base;

    if class == RiskClass::Destructive
        && decision == SafetyDecision::ApprovalRequired
        && opts.destructive != DestructiveActions::Approval
    {
        decision = SafetyDecision::Deny;
        rules.push("option.destructive_actions.deny".to_owned());
    }
    if class == RiskClass::ExternalCommunication && !opts.has_sinks() {
        // `default_decision(.., has_sinks = false)` already denies; record why.
        rules.push("sink.required_unverified".to_owned());
    }
    if class == RiskClass::FileUpload && decision == SafetyDecision::Allow && kind != ActionKind::Upload {
        decision = SafetyDecision::Deny;
        rules.push("upload.fixture_required".to_owned());
    }
    ProfileDecision { decision, rules }
}

/// What the run's authorization record narrows on top of the profile table:
/// `permittedRiskClasses` and `approvalRequired`. It can only restrict: see [`narrow_by_record`].
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct RecordNarrowing {
    permitted: BTreeSet<RiskClass>,
    approval_required: BTreeSet<RiskClass>,
}

impl RecordNarrowing {
    /// The narrowing of a record that lists `permitted` in `permittedRiskClasses` and
    /// `approval_required` in `approvalRequired`.
    #[must_use]
    pub fn new(
        permitted: impl IntoIterator<Item = RiskClass>,
        approval_required: impl IntoIterator<Item = RiskClass>,
    ) -> Self {
        Self {
            permitted: permitted.into_iter().collect(),
            approval_required: approval_required.into_iter().collect(),
        }
    }

    /// Does the record permit `class`? The baseline classes (navigation, reversible local
    /// preferences) need no entry; every other class must be listed.
    #[must_use]
    pub fn permits(&self, class: RiskClass) -> bool {
        class.is_baseline() || self.permitted.contains(&class)
    }

    /// Does the record want a reviewer's approval for `class` even where the profile allows it?
    #[must_use]
    pub fn requires_approval(&self, class: RiskClass) -> bool {
        self.approval_required.contains(&class)
    }
}

/// Narrow the table decision `d` for `class` by the run's authorization record. A class the
/// record does not permit is denied (`record.class_not_permitted`); a permitted class the record
/// lists in `approvalRequired` turns `allow` into `approval_required`
/// (`record.approval_required`). `Deny` stays `Deny` and `ApprovalRequired` never becomes
/// `Allow`: the record is a bound, never a grant.
#[must_use]
pub fn narrow_by_record(
    mut d: ProfileDecision,
    class: RiskClass,
    record: &RecordNarrowing,
) -> ProfileDecision {
    if d.decision == SafetyDecision::Deny {
        return d;
    }
    if !record.permits(class) {
        d.decision = SafetyDecision::Deny;
        d.rules.push("record.class_not_permitted".to_owned());
    } else if d.decision == SafetyDecision::Allow && record.requires_approval(class) {
        d.decision = SafetyDecision::ApprovalRequired;
        d.rules.push("record.approval_required".to_owned());
    }
    d
}

/// Apply the model's request for approval: only ever `Allow → ApprovalRequired`.
#[must_use]
pub fn apply_hint_decision(
    decision: SafetyDecision,
    hint: ModelHint,
) -> (SafetyDecision, Option<&'static str>) {
    if hint.request_approval && decision == SafetyDecision::Allow {
        (SafetyDecision::ApprovalRequired, Some("hint.request_approval"))
    } else {
        (decision, None)
    }
}

/// Every class the table decides, in the documented row order (`Unclassified` is treated as
/// `PersistentWriteOwn` and listed last).
pub const MATRIX_CLASSES: [RiskClass; 11] = [
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
];

/// The three profiles in privilege order.
pub const MATRIX_PROFILES: [SafetyProfile; 3] = [
    SafetyProfile::ReadOnly,
    SafetyProfile::TestEnvironment,
    SafetyProfile::AuthorizedSecurityTest,
];

/// One cell of the admission matrix as the documentation prints it: the decision
/// [`decide`] reaches with every request option opted in, plus the condition the
/// table attaches to it. `external_communication` is allowed only through verified
/// test sinks and `file_upload` only for fixture files (`ActionKind::Upload`); both
/// narrow to `deny` when the condition is not met, which the cell names.
#[must_use]
pub fn risk_matrix_cell(class: RiskClass, profile: SafetyProfile) -> String {
    let opted_in = ProfileOptions {
        destructive: DestructiveActions::Approval,
        external: ExternalCommunication::TestSinks,
        sink_verified: true,
    };
    let kind = if class == RiskClass::FileUpload {
        ActionKind::Upload
    } else {
        ActionKind::Click
    };
    let decision = decide(class, profile, kind, &opted_in).decision;
    let word = match decision {
        SafetyDecision::Allow => "allow",
        SafetyDecision::Deny => "deny",
        SafetyDecision::ApprovalRequired => "approval",
    };
    let condition = match (class, profile, decision) {
        (RiskClass::ExternalCommunication, _, SafetyDecision::Allow) => Some("configured test sinks only"),
        (RiskClass::FileUpload, _, SafetyDecision::Allow) => Some("fixture files only"),
        (
            RiskClass::PersistentWriteOtherPrincipal,
            SafetyProfile::AuthorizedSecurityTest,
            SafetyDecision::Allow,
        ) => Some("recorded as cross-principal probe"),
        _ => None,
    };
    match condition {
        Some(c) => format!("{word} ({c})"),
        None => word.to_owned(),
    }
}

/// The `(RiskClass, profile)` admission matrix as a markdown table, generated from
/// [`decide`] so the documentation (`docs/design/safety-matrix.md`) and the kernel cannot drift;
/// `crawlx-safety/tests/matrix_doc.rs` asserts the two are byte-identical.
#[must_use]
pub fn risk_matrix_markdown() -> String {
    let mut out = String::from(
        "| Class | `read_only` | `test_environment` | `authorized_security_test` |\n|---|---|---|---|\n",
    );
    for class in MATRIX_CLASSES {
        out.push_str(&format!("| `{}` |", class.as_str()));
        for profile in MATRIX_PROFILES {
            out.push_str(&format!(" {} |", risk_matrix_cell(class, profile)));
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use SafetyDecision::{Allow, ApprovalRequired, Deny};
    use SafetyProfile::{AuthorizedSecurityTest as A, ReadOnly as R, TestEnvironment as T};

    fn full_opts() -> ProfileOptions {
        ProfileOptions {
            destructive: DestructiveActions::Approval,
            external: ExternalCommunication::TestSinks,
            sink_verified: true,
        }
    }

    fn kind_for(c: RiskClass) -> ActionKind {
        if c == RiskClass::FileUpload {
            ActionKind::Upload
        } else {
            ActionKind::Click
        }
    }

    /// The documented table: (class, read_only, test_environment, authorized_security_test),
    /// with test sinks configured and every option opted in.
    const TABLE: [(RiskClass, SafetyDecision, SafetyDecision, SafetyDecision); 10] = [
        (RiskClass::NavigationReveal, Allow, Allow, Allow),
        (RiskClass::ReversibleLocalPreference, Allow, Allow, Allow),
        (RiskClass::PersistentWriteOwn, Deny, Allow, Allow),
        (
            RiskClass::PersistentWriteOtherPrincipal,
            Deny,
            ApprovalRequired,
            Allow,
        ),
        (RiskClass::ExternalCommunication, Deny, Allow, Allow),
        (RiskClass::FinancialTransaction, Deny, Deny, ApprovalRequired),
        (RiskClass::Destructive, Deny, ApprovalRequired, ApprovalRequired),
        (RiskClass::SecurityChange, Deny, Deny, ApprovalRequired),
        (RiskClass::FileUpload, Deny, Allow, Allow),
        (RiskClass::OutOfScope, Deny, Deny, Deny),
    ];

    macro_rules! cell {
        ($name:ident, $row:expr, $profile:expr, $col:tt) => {
            #[test]
            fn $name() {
                let (class, ro, te, ast) = TABLE[$row];
                let expected = [ro, te, ast][$col];
                assert_eq!(
                    decide(class, $profile, kind_for(class), &full_opts()).decision,
                    expected,
                    "{class:?}"
                );
            }
        };
    }

    cell!(nav_reveal_read_only, 0, R, 0);
    cell!(nav_reveal_test_env, 0, T, 1);
    cell!(nav_reveal_authorized, 0, A, 2);
    cell!(local_pref_read_only, 1, R, 0);
    cell!(local_pref_test_env, 1, T, 1);
    cell!(local_pref_authorized, 1, A, 2);
    cell!(own_write_read_only, 2, R, 0);
    cell!(own_write_test_env, 2, T, 1);
    cell!(own_write_authorized, 2, A, 2);
    cell!(other_principal_read_only, 3, R, 0);
    cell!(other_principal_test_env, 3, T, 1);
    cell!(other_principal_authorized, 3, A, 2);
    cell!(external_read_only, 4, R, 0);
    cell!(external_test_env, 4, T, 1);
    cell!(external_authorized, 4, A, 2);
    cell!(financial_read_only, 5, R, 0);
    cell!(financial_test_env, 5, T, 1);
    cell!(financial_authorized, 5, A, 2);
    cell!(destructive_read_only, 6, R, 0);
    cell!(destructive_test_env, 6, T, 1);
    cell!(destructive_authorized, 6, A, 2);
    cell!(security_read_only, 7, R, 0);
    cell!(security_test_env, 7, T, 1);
    cell!(security_authorized, 7, A, 2);
    cell!(upload_read_only, 8, R, 0);
    cell!(upload_test_env, 8, T, 1);
    cell!(upload_authorized, 8, A, 2);
    cell!(out_of_scope_read_only, 9, R, 0);
    cell!(out_of_scope_test_env, 9, T, 1);
    cell!(out_of_scope_authorized, 9, A, 2);

    #[test]
    fn unclassified_matches_core_default() {
        let o = full_opts();
        assert_eq!(
            decide(RiskClass::Unclassified, R, ActionKind::Click, &o).decision,
            Deny
        );
        assert_eq!(
            decide(RiskClass::Unclassified, T, ActionKind::Click, &o).decision,
            Allow
        );
        assert_eq!(
            decide(RiskClass::Unclassified, A, ActionKind::Click, &o).decision,
            Allow
        );
    }

    #[test]
    fn external_denied_without_verified_sink_in_every_profile() {
        for p in [R, T, A] {
            for opts in [
                ProfileOptions::default(),
                ProfileOptions {
                    external: ExternalCommunication::TestSinks,
                    sink_verified: false,
                    ..ProfileOptions::default()
                },
                ProfileOptions {
                    external: ExternalCommunication::Deny,
                    sink_verified: true,
                    ..ProfileOptions::default()
                },
            ] {
                let d = decide(RiskClass::ExternalCommunication, p, ActionKind::Click, &opts);
                assert_eq!(d.decision, Deny, "{p:?} {opts:?}");
                assert!(d.rules.iter().any(|r| r == "sink.required_unverified"));
            }
        }
    }

    #[test]
    fn destructive_option_deny_narrows_approval_to_deny() {
        let opts = ProfileOptions {
            destructive: DestructiveActions::Deny,
            ..full_opts()
        };
        for p in [R, T, A] {
            assert_eq!(
                decide(RiskClass::Destructive, p, ActionKind::Click, &opts).decision,
                Deny
            );
        }
    }

    #[test]
    fn click_on_file_input_is_denied_even_where_upload_is_allowed() {
        let d = decide(RiskClass::FileUpload, T, ActionKind::Click, &full_opts());
        assert_eq!(d.decision, Deny);
        assert!(d.rules.iter().any(|r| r == "upload.fixture_required"));
    }

    #[test]
    fn hint_floor_only_raises() {
        assert_eq!(
            raise(RiskClass::NavigationReveal, Some(RiskClass::Destructive)),
            RiskClass::Destructive
        );
        assert_eq!(
            raise(RiskClass::Destructive, Some(RiskClass::NavigationReveal)),
            RiskClass::Destructive
        );
        assert_eq!(
            raise(RiskClass::SecurityChange, Some(RiskClass::PersistentWriteOwn)),
            RiskClass::SecurityChange
        );
        assert_eq!(
            raise(RiskClass::OutOfScope, Some(RiskClass::Unclassified)),
            RiskClass::OutOfScope
        );
        assert_eq!(raise(RiskClass::Unclassified, None), RiskClass::Unclassified);
    }

    #[test]
    fn hint_approval_request_only_escalates_allow() {
        let h = ModelHint {
            risk_floor: None,
            request_approval: true,
        };
        assert_eq!(apply_hint_decision(Allow, h).0, ApprovalRequired);
        assert_eq!(apply_hint_decision(Deny, h).0, Deny);
        assert_eq!(apply_hint_decision(ApprovalRequired, h).0, ApprovalRequired);
        assert_eq!(apply_hint_decision(Allow, ModelHint::default()).0, Allow);
    }

    #[test]
    fn narrow_picks_the_stricter_profile() {
        assert_eq!(narrow(A, R), R);
        assert_eq!(narrow(T, A), T);
        assert_eq!(narrow(T, T), T);
    }

    #[test]
    fn sink_rule_is_recorded_only_for_external_communication_without_sinks() {
        let d = decide(
            RiskClass::ExternalCommunication,
            T,
            ActionKind::Click,
            &full_opts(),
        );
        assert_eq!(d.decision, Allow);
        assert!(
            !d.rules.iter().any(|r| r == "sink.required_unverified"),
            "{:?}",
            d.rules
        );
        for class in [RiskClass::NavigationReveal, RiskClass::Destructive] {
            let d = decide(class, T, ActionKind::Click, &ProfileOptions::default());
            assert!(
                !d.rules.iter().any(|r| r == "sink.required_unverified"),
                "{class:?}: {:?}",
                d.rules
            );
        }
    }

    /// Every class under every profile with every option opted in, narrowed by `record`.
    fn narrowed(class: RiskClass, profile: SafetyProfile, record: &RecordNarrowing) -> ProfileDecision {
        narrow_by_record(
            decide(class, profile, kind_for(class), &full_opts()),
            class,
            record,
        )
    }

    #[test]
    fn record_denies_a_non_baseline_class_it_does_not_list() {
        let record = RecordNarrowing::new([RiskClass::PersistentWriteOwn], []);
        let d = narrowed(RiskClass::Destructive, T, &record);
        assert_eq!(d.decision, Deny);
        assert!(
            d.rules.iter().any(|r| r == "record.class_not_permitted"),
            "{:?}",
            d.rules
        );
        // a listed class keeps the table's decision
        assert_eq!(
            narrowed(RiskClass::PersistentWriteOwn, T, &record).decision,
            Allow
        );
        // an empty list still permits the baseline classes
        let none = RecordNarrowing::new([], []);
        for class in [RiskClass::NavigationReveal, RiskClass::ReversibleLocalPreference] {
            for p in MATRIX_PROFILES {
                assert_eq!(narrowed(class, p, &none).decision, Allow, "{class:?} {p:?}");
            }
        }
        assert_eq!(narrowed(RiskClass::PersistentWriteOwn, T, &none).decision, Deny);
    }

    #[test]
    fn record_approval_turns_allow_into_approval_required() {
        let record = RecordNarrowing::new(RiskClass::PERMITTABLE, [RiskClass::PersistentWriteOwn]);
        let d = narrowed(RiskClass::PersistentWriteOwn, T, &record);
        assert_eq!(d.decision, ApprovalRequired);
        assert!(
            d.rules.iter().any(|r| r == "record.approval_required"),
            "{:?}",
            d.rules
        );
        // classes the record does not list keep their decision
        assert_eq!(narrowed(RiskClass::FileUpload, T, &record).decision, Allow);
    }

    #[test]
    fn record_never_turns_deny_or_approval_into_allow() {
        let permissive = RecordNarrowing::new(RiskClass::PERMITTABLE, []);
        for class in MATRIX_CLASSES {
            for p in MATRIX_PROFILES {
                let base = decide(class, p, kind_for(class), &full_opts());
                let narrowed = narrow_by_record(base.clone(), class, &permissive);
                assert!(
                    strictness(narrowed.decision) >= strictness(base.decision),
                    "{class:?} {p:?}: {:?} -> {:?}",
                    base.decision,
                    narrowed.decision
                );
            }
        }
        // a record that lists everything and asks approval for everything still cannot allow
        let everything = RecordNarrowing::new(RiskClass::PERMITTABLE, RiskClass::PERMITTABLE);
        for class in MATRIX_CLASSES {
            for p in MATRIX_PROFILES {
                let base = decide(class, p, kind_for(class), &full_opts());
                let narrowed = narrow_by_record(base.clone(), class, &everything);
                assert!(
                    strictness(narrowed.decision) >= strictness(base.decision),
                    "{class:?} {p:?}"
                );
                if base.decision == Deny {
                    assert_eq!(narrowed, base, "a denied class gains no record rule");
                }
            }
        }
    }
}
