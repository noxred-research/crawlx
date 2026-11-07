//! Fixtures for tests and harnesses of this crate and of downstream crates: a complete, valid
//! [`AuthorizationRecord`] to adjust field by field, so a new record field is added in one place.

use crate::authorization::{AuthorizationRecord, Authorizer, Evidence, LegalReferences};
use crawlx_core::config::SafetyProfile;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{AuthorizationRecordId, TenantId};
use crawlx_core::safety::RiskClass;
use crawlx_core::time::Timestamp;
use std::collections::{BTreeMap, BTreeSet};

/// A record for `tenant` covering `origins`, valid from an hour before `now` for 30 days, with
/// every field filled, `profileCap` at `authorized_security_test` and every
/// permittable risk class listed. No ownership proof, not verified, not revoked.
#[must_use]
pub fn sample_record(tenant: TenantId, now: Timestamp, origins: &[&str]) -> AuthorizationRecord {
    AuthorizationRecord {
        id: AuthorizationRecordId::new(),
        tenant,
        version: 1,
        title: "test engagement".to_owned(),
        authorizer: Authorizer {
            name: "Test Authorizer".to_owned(),
            role: "owner".to_owned(),
            organization: "Example Org".to_owned(),
            contact: "authorizer@example.test".to_owned(),
            attests_ownership_or_control: true,
        },
        origins: origins.iter().map(|o| (*o).to_owned()).collect(),
        url_prefixes: Vec::new(),
        excluded_paths: Vec::new(),
        authorized_networks: Vec::new(),
        valid_from: now - chrono::Duration::hours(1),
        valid_to: now + chrono::Duration::days(30),
        profile_cap: SafetyProfile::AuthorizedSecurityTest,
        permitted_risk_classes: RiskClass::PERMITTABLE.into_iter().collect::<BTreeSet<_>>(),
        approval_required: BTreeSet::new(),
        test_accounts: Vec::new(),
        robots_override_acknowledged: false,
        test_sinks: BTreeMap::new(),
        rate_limits: None,
        evidence: Evidence {
            kind: "signed_scope_letter".to_owned(),
            artifact_id: None,
            digest: Digest::of("test", b"letter"),
        },
        legal_references: LegalReferences::default(),
        emergency_contact: "+1 555 0100".to_owned(),
        ownership: None,
        verified_at: None,
        revoked_at: None,
        revoked_reason: None,
    }
}
