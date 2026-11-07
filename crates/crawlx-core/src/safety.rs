//! Safety vocabulary shared by the kernel (`crawlx-safety`), strategies and
//! storage. The kernel logic itself lives in `crawlx-safety`.

use crate::config::SafetyProfile;
use crate::ids::{ApprovalId, SafetyDecisionId};
use serde::{Deserialize, Serialize};

/// Side-effect class of an action (see `docs/design/safety-matrix.md`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    /// Pure navigation or revealing content (links, tabs, expanders); no state change.
    NavigationReveal,
    /// Local preference change that is easily undone (theme, language, view mode).
    ReversibleLocalPreference,
    /// Persistent write to data owned by the acting principal.
    PersistentWriteOwn,
    /// Persistent write that affects another principal's data.
    PersistentWriteOtherPrincipal,
    /// Sends a message or content to an outside party (email, post, invite).
    ExternalCommunication,
    /// Moves money or commits to a purchase.
    FinancialTransaction,
    /// Deletes or irreversibly destroys data.
    Destructive,
    /// Changes credentials, permissions, or other security settings.
    SecurityChange,
    /// Uploads a file to the target application.
    FileUpload,
    /// Target lies outside the authorized scope of the run.
    OutOfScope,
    /// Evidence insufficient; treated as `PersistentWriteOwn`.
    Unclassified,
}

impl RiskClass {
    /// Classes an authorization record may list in `permittedRiskClasses`: every
    /// class except the baseline ones (navigation, reversible preferences: always permitted)
    /// and `OutOfScope` (never permitted).
    pub const PERMITTABLE: [Self; 8] = [
        Self::PersistentWriteOwn,
        Self::PersistentWriteOtherPrincipal,
        Self::ExternalCommunication,
        Self::FinancialTransaction,
        Self::Destructive,
        Self::SecurityChange,
        Self::FileUpload,
        Self::Unclassified,
    ];

    /// Classes that need no entry in a record's `permittedRiskClasses`: passive navigation and
    /// easily undone local preferences.
    #[must_use]
    pub const fn is_baseline(self) -> bool {
        matches!(self, Self::NavigationReveal | Self::ReversibleLocalPreference)
    }

    /// Stable snake_case name, identical to the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NavigationReveal => "navigation_reveal",
            Self::ReversibleLocalPreference => "reversible_local_preference",
            Self::PersistentWriteOwn => "persistent_write_own",
            Self::PersistentWriteOtherPrincipal => "persistent_write_other_principal",
            Self::ExternalCommunication => "external_communication",
            Self::FinancialTransaction => "financial_transaction",
            Self::Destructive => "destructive",
            Self::SecurityChange => "security_change",
            Self::FileUpload => "file_upload",
            Self::OutOfScope => "out_of_scope",
            Self::Unclassified => "unclassified",
        }
    }

    /// The default decision for this class under `profile` (see `docs/design/safety-matrix.md`).
    /// `has_sinks`: tenant has verified test sinks and the run opted in.
    #[must_use]
    pub const fn default_decision(self, profile: SafetyProfile, has_sinks: bool) -> SafetyDecision {
        use SafetyDecision::{Allow, ApprovalRequired, Deny};
        use SafetyProfile::{AuthorizedSecurityTest, ReadOnly, TestEnvironment};
        match (self, profile) {
            (Self::NavigationReveal | Self::ReversibleLocalPreference, _) => Allow,
            (Self::PersistentWriteOwn | Self::Unclassified, ReadOnly) => Deny,
            (Self::PersistentWriteOwn | Self::Unclassified, _) => Allow,
            (Self::PersistentWriteOtherPrincipal, ReadOnly) => Deny,
            (Self::PersistentWriteOtherPrincipal, TestEnvironment) => ApprovalRequired,
            (Self::PersistentWriteOtherPrincipal, AuthorizedSecurityTest) => Allow,
            (Self::ExternalCommunication, ReadOnly) => Deny,
            (Self::ExternalCommunication, _) => {
                if has_sinks {
                    Allow
                } else {
                    Deny
                }
            }
            (Self::FinancialTransaction, AuthorizedSecurityTest) => ApprovalRequired,
            (Self::FinancialTransaction, _) => Deny,
            (Self::Destructive, ReadOnly) => Deny,
            (Self::Destructive, _) => ApprovalRequired,
            (Self::SecurityChange, AuthorizedSecurityTest) => ApprovalRequired,
            (Self::SecurityChange, _) => Deny,
            (Self::FileUpload, ReadOnly) => Deny,
            (Self::FileUpload, _) => Allow, // fixture files only; enforced by the action type
            (Self::OutOfScope, _) => Deny,
        }
    }
}

/// The kernel's decision.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SafetyDecision {
    /// The action may run.
    Allow,
    /// The action is refused.
    Deny,
    /// The action is held until a human approves it.
    ApprovalRequired,
}

impl SafetyDecision {
    /// Stable snake_case name, identical to the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::ApprovalRequired => "approval_required",
        }
    }
}

/// Full verdict with audit linkage (`safety_decisions` row).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct SafetyVerdict {
    /// Identifier of the persisted `safety_decisions` row.
    pub decision_id: SafetyDecisionId,
    /// Decision the kernel reached.
    pub decision: SafetyDecision,
    /// Risk class the action was assigned after any model hint.
    pub risk_class: RiskClass,
    /// Rule identifiers that fired, in evaluation order.
    pub rules: Vec<String>,
    /// Pending approval request, or the granted approval that was consumed; `None` when no approval is involved.
    pub approval: Option<ApprovalId>,
}

/// Model hint: a model may only raise risk or ask for approval.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct ModelHint {
    /// Minimum risk class the model asserts for the action; `None` means no opinion.
    pub risk_floor: Option<RiskClass>,
    /// `true` when the model asks for human approval; only turns `Allow` into `ApprovalRequired`.
    pub request_approval: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn read_only_denies_every_write() {
        for c in [
            RiskClass::PersistentWriteOwn,
            RiskClass::PersistentWriteOtherPrincipal,
            RiskClass::ExternalCommunication,
            RiskClass::FinancialTransaction,
            RiskClass::Destructive,
            RiskClass::SecurityChange,
            RiskClass::FileUpload,
            RiskClass::OutOfScope,
            RiskClass::Unclassified,
        ] {
            assert_eq!(
                c.default_decision(SafetyProfile::ReadOnly, true),
                SafetyDecision::Deny,
                "{c:?}"
            );
        }
        assert_eq!(
            RiskClass::NavigationReveal.default_decision(SafetyProfile::ReadOnly, false),
            SafetyDecision::Allow
        );
    }

    #[test]
    fn out_of_scope_denied_everywhere() {
        for p in [
            SafetyProfile::ReadOnly,
            SafetyProfile::TestEnvironment,
            SafetyProfile::AuthorizedSecurityTest,
        ] {
            assert_eq!(
                RiskClass::OutOfScope.default_decision(p, true),
                SafetyDecision::Deny
            );
        }
    }
}
