//! Authorization record (table `authorization_records`).
//! The record is evidence of the operator's stated
//! authorization and a technical guardrail. `crawlx-policy` evaluates it
//! (window, revocation, profile cap, target and network coverage) and exposes
//! its target as a [`RecordScope`] that the egress policy and the scope policy
//! enforce on every request of a run. Creation, persistence and the ownership
//! challenge live in the API tier; the operator signature check is
//! [`crate::attestation`].
//!
//! The wire shape is flat (`origins`, `urlPrefixes`, `excludedPaths`,
//! `authorizedNetworks`, `validFrom`, `validTo`), not nested under `target` and
//! `window`, and `version` is also accepted as `recordVersion`. Unknown fields are rejected, so a
//! record file never loses a field silently.

use crate::error::PolicyError;
use crawlx_core::config::SafetyProfile;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{ArtifactId, AuthorizationRecordId, TenantId};
use crawlx_core::safety::RiskClass;
use crawlx_core::time::Timestamp;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use url::{Host, Url};

/// Longest allowed validity window ("at most 90 days").
pub const MAX_WINDOW_DAYS: i64 = 90;

/// Domain of [`AuthorizationRecord::body_digest`].
const BODY_DOMAIN: &str = "crawlx/authorization-record/v1";

/// Name prefix of the DNS ownership challenge: a TXT record at `_crawlx-authz.<host>`.
pub const DNS_CHALLENGE_LABEL: &str = "_crawlx-authz";

/// Path of the well-known ownership challenge file.
pub const WELL_KNOWN_CHALLENGE_PATH: &str = "/.well-known/crawlx-authorization";

/// Serialize CIDR lists as strings (`ipnet` is used without its serde feature).
mod cidr_list {
    use ipnet::IpNet;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &[IpNet], s: S) -> Result<S::Ok, S::Error> {
        v.iter().map(ToString::to_string).collect::<Vec<_>>().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<IpNet>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|s| s.parse::<IpNet>().map_err(serde::de::Error::custom))
            .collect()
    }
}

/// Evidence reference: a stored artifact with its digest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Evidence {
    /// e.g. `signed_scope_letter`.
    pub kind: String,
    /// Artifact holding the evidence document, when stored.
    #[serde(default)]
    pub artifact_id: Option<ArtifactId>,
    /// BLAKE3 digest of the evidence artifact.
    pub digest: Digest,
}

/// Rate limits a record may impose; they can only tighten politeness.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordRateLimits {
    /// Ceiling for concurrent requests per origin.
    pub max_in_flight_per_origin: u8,
    /// Floor for the delay between requests to one origin, in milliseconds.
    pub min_delay_ms: u32,
}

/// The named person who stands behind the record.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Authorizer {
    /// Full name of the authorizing person.
    pub name: String,
    /// Role of that person at the target's owner (for example `CTO`).
    pub role: String,
    /// Organization that owns or controls the target.
    pub organization: String,
    /// How to reach the authorizer (email or phone).
    pub contact: String,
    /// The authorizer attests that they own or control the target.
    pub attests_ownership_or_control: bool,
}

/// A test account the run may log in with.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestAccount {
    /// Role the account plays (`member`, `admin`).
    pub role: String,
    /// Credential reference (`vault://...`); the secret itself never enters a record.
    pub credential_ref: String,
}

/// Contract and legal references.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegalReferences {
    /// Contract or statement-of-work id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<String>,
}

/// How the record proves that the operator owns or controls the target.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum OwnershipProof {
    /// A TXT record at `_crawlx-authz.<host>` holds the record id, for every host of the target.
    DnsTxt {},
    /// `/.well-known/crawlx-authorization` on every origin of the target holds the record id.
    WellKnownFile {},
    /// A statement signed by a configured operator key ([`crate::attestation`]); the only proof
    /// that covers `authorizedNetworks`, which no outside party can probe.
    OperatorSignature {
        /// Which operator key signed.
        key_id: String,
        /// Lowercase hex HMAC-SHA256 over [`AuthorizationRecord::signing_digest`].
        signature: String,
    },
}

/// An authorization record (one immutable version).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorizationRecord {
    /// Stable id shared by all versions of the record.
    pub id: AuthorizationRecordId,
    /// Tenant that owns the record.
    pub tenant: TenantId,
    /// Record version; an amendment is a new version.
    #[serde(alias = "recordVersion")]
    pub version: u32,
    /// Human-readable title of the engagement.
    #[serde(default)]
    pub title: String,
    /// The named authorizer and their ownership attestation.
    pub authorizer: Authorizer,
    /// Explicit origins (`scheme://host[:port]`); wildcards are rejected.
    #[serde(default)]
    pub origins: Vec<String>,
    /// Alternative to origins: URL prefixes.
    #[serde(default)]
    pub url_prefixes: Vec<String>,
    /// Path patterns excluded from the target (`/billing/*`).
    #[serde(default)]
    pub excluded_paths: Vec<String>,
    /// CIDRs that private-network testing may reach (E11).
    #[serde(default, with = "cidr_list")]
    pub authorized_networks: Vec<IpNet>,
    /// Start of the validity window (inclusive).
    pub valid_from: Timestamp,
    /// End of the validity window (exclusive).
    pub valid_to: Timestamp,
    /// The most privileged safety profile a run under this record may use.
    pub profile_cap: SafetyProfile,
    /// Risk classes beyond navigation and reversible preferences that the profile matrix may
    /// allow under this record; any other class is denied by the kernel.
    pub permitted_risk_classes: BTreeSet<RiskClass>,
    /// Classes that stay behind an approval even where the profile would allow them.
    pub approval_required: BTreeSet<RiskClass>,
    /// Test accounts the run may use (credential references only).
    pub test_accounts: Vec<TestAccount>,
    /// The operator acknowledged that the record overrides robots.txt for its targets.
    #[serde(default)]
    pub robots_override_acknowledged: bool,
    /// Named sinks (`email` -> `sink://mail/example`).
    #[serde(default)]
    pub test_sinks: BTreeMap<String, String>,
    /// Optional ceilings that can only tighten politeness for this target.
    #[serde(default)]
    pub rate_limits: Option<RecordRateLimits>,
    /// Evidence supporting the authorization (e.g. a signed scope letter).
    pub evidence: Evidence,
    /// Contract and legal references.
    #[serde(default)]
    pub legal_references: LegalReferences,
    /// Whom to call when the run misbehaves.
    pub emergency_contact: String,
    /// How ownership of the target is proven; the API requires one at creation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<OwnershipProof>,
    /// Set once the ownership proof was checked (lifecycle state, outside the body digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<Timestamp>,
    /// Set when revoked; effective from that instant (lifecycle state, outside the body digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
    /// Why the record was revoked (lifecycle state, outside the body digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_reason: Option<String>,
}

/// Why a record cannot be used at a given time or for a given target.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthzFailure {
    /// The record was revoked at or before the checked instant.
    #[error("authorization record is revoked")]
    Revoked,
    /// The checked instant is before `valid_from`.
    #[error("authorization record is not yet valid")]
    NotYetValid,
    /// The checked instant is at or after `valid_to`.
    #[error("authorization record has expired")]
    Expired,
    /// The record's tenant differs from the requesting tenant.
    #[error("authorization record belongs to another tenant")]
    TenantMismatch,
    /// The named origin or URL matches no origin or URL prefix of the record.
    #[error("{0} is not covered by the authorization record")]
    NotCovered(String),
    /// The named URL matches one of the record's excluded path patterns.
    #[error("{0} is excluded by the authorization record")]
    Excluded(String),
    /// The requested safety profile is above the record's `profileCap`.
    #[error("safety profile {requested} exceeds the record's profile cap {cap}")]
    ProfileAboveCap {
        /// Wire name of the requested profile.
        requested: &'static str,
        /// Wire name of the cap.
        cap: &'static str,
    },
    /// The ownership proof was never checked.
    #[error("authorization record ownership is not verified")]
    NotVerified,
}

/// Origin string of `url` as `scheme://host[:port]` (default ports elided).
#[must_use]
pub fn origin_string(url: &Url) -> String {
    url.origin().ascii_serialization()
}

fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => path.starts_with(prefix),
        None => path == pattern || path.strip_prefix(pattern).is_some_and(|r| r.starts_with('/')),
    }
}

fn canonical_host<S: AsRef<str>>(host: &Host<S>) -> String {
    host.to_string().to_ascii_lowercase()
}

/// The target of a record, as the bound every request of a run must stay inside
/// (the kernel treats every destination outside `target` as
/// `out_of_scope_destination`). Built by [`AuthorizationRecord::scope`]; the egress
/// policy checks hosts and URLs against it on every connection and redirect hop, the scope
/// policy checks discovered URLs.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RecordScope {
    /// Origins the record names directly (`origins`), normalized.
    origins: Vec<String>,
    /// Origins of the URL prefixes, normalized; known to the run (robots) but not widened to.
    prefix_origins: Vec<String>,
    url_prefixes: Vec<String>,
    excluded_paths: Vec<String>,
    hosts: BTreeSet<String>,
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

impl RecordScope {
    fn new(origins: &[String], url_prefixes: &[String], excluded_paths: &[String]) -> Self {
        let mut hosts = BTreeSet::new();
        let mut direct = Vec::new();
        let mut from_prefixes = Vec::new();
        for (entry, is_prefix) in origins
            .iter()
            .map(|o| (o, false))
            .chain(url_prefixes.iter().map(|p| (p, true)))
        {
            if let Ok(url) = Url::parse(entry) {
                if let Some(host) = url.host() {
                    hosts.insert(canonical_host(&host));
                }
                push_unique(
                    if is_prefix {
                        &mut from_prefixes
                    } else {
                        &mut direct
                    },
                    origin_string(&url),
                );
            }
        }
        Self {
            origins: direct,
            prefix_origins: from_prefixes,
            url_prefixes: url_prefixes.to_vec(),
            excluded_paths: excluded_paths.to_vec(),
            hosts,
        }
    }

    /// Is `host` the host of one of the record's origins or URL prefixes? Subdomains are not
    /// implied: a record names the hosts it covers.
    #[must_use]
    pub fn contains_host<S: AsRef<str>>(&self, host: &Host<S>) -> bool {
        self.hosts.contains(&canonical_host(host))
    }

    /// The hosts the record covers, canonical form, in order.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    /// Does the target cover `url` (origin or prefix match, and the path is not excluded)?
    ///
    /// # Errors
    /// [`AuthzFailure::NotCovered`] or [`AuthzFailure::Excluded`].
    pub fn check_covers_url(&self, url: &Url) -> Result<(), AuthzFailure> {
        let origin = origin_string(url);
        let by_origin = self.origins.contains(&origin);
        let by_prefix = self
            .url_prefixes
            .iter()
            .any(|p| url.as_str().starts_with(p.as_str()));
        if !by_origin && !by_prefix {
            return Err(AuthzFailure::NotCovered(origin));
        }
        let path = url.path();
        if self.excluded_paths.iter().any(|p| path_pattern_matches(p, path)) {
            return Err(AuthzFailure::Excluded(path.to_owned()));
        }
        Ok(())
    }

    /// [`Self::check_covers_url`] for a request the run itself makes: the `robots.txt` of an
    /// origin of the target is always reachable, because obeying it needs it, even when the
    /// record names only a path prefix of that origin.
    ///
    /// # Errors
    /// [`AuthzFailure::NotCovered`] or [`AuthzFailure::Excluded`].
    pub fn check_request(&self, url: &Url) -> Result<(), AuthzFailure> {
        match self.check_covers_url(url) {
            Err(AuthzFailure::NotCovered(origin))
                if url.path() == "/robots.txt" && self.prefix_origins.contains(&origin) =>
            {
                Ok(())
            }
            other => other,
        }
    }
}

impl AuthorizationRecord {
    /// The record's target as an enforceable bound.
    #[must_use]
    pub fn scope(&self) -> RecordScope {
        RecordScope::new(&self.origins, &self.url_prefixes, &self.excluded_paths)
    }

    /// Structural validation (required fields).
    ///
    /// # Errors
    /// [`PolicyError::InvalidAuthorization`] describing the first problem.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let bad = |m: &str| Err(PolicyError::InvalidAuthorization(m.to_owned()));
        if self.origins.is_empty() && self.url_prefixes.is_empty() {
            return bad("target needs at least one origin or URL prefix");
        }
        for o in self.origins.iter().chain(self.url_prefixes.iter()) {
            if o.contains('*') {
                return bad("wildcards are not allowed in target origins or prefixes");
            }
            if Url::parse(o).is_err() {
                return bad("target entry is not a URL");
            }
        }
        if self.valid_to <= self.valid_from {
            return bad("validTo must be after validFrom");
        }
        if self.valid_to.signed_duration_since(self.valid_from) > chrono::Duration::days(MAX_WINDOW_DAYS) {
            return bad("validity window exceeds 90 days");
        }
        if self.evidence.kind.trim().is_empty() {
            return bad("evidence kind is required");
        }
        let a = &self.authorizer;
        if [&a.name, &a.role, &a.organization, &a.contact]
            .iter()
            .any(|f| f.trim().is_empty())
        {
            return bad("authorizer needs name, role, organization and contact");
        }
        if !a.attests_ownership_or_control {
            return bad("authorizer must attest ownership or control of the target");
        }
        if self.emergency_contact.trim().is_empty() {
            return bad("emergencyContact is required");
        }
        if self.permitted_risk_classes.contains(&RiskClass::OutOfScope) {
            return bad("out_of_scope can never be a permitted risk class");
        }
        for account in &self.test_accounts {
            if account.role.trim().is_empty() || !account.credential_ref.contains("://") {
                return bad("a test account needs a role and a credentialRef (scheme://...)");
            }
        }
        if !self.authorized_networks.is_empty()
            && self
                .ownership
                .as_ref()
                .is_some_and(|o| !matches!(o, OwnershipProof::OperatorSignature { .. }))
        {
            return bad("authorizedNetworks can only be proven by an operator signature");
        }
        Ok(())
    }

    /// Window and revocation check at `now`.
    ///
    /// # Errors
    /// [`AuthzFailure`] naming why the record is unusable.
    pub fn check_active(&self, now: Timestamp) -> Result<(), AuthzFailure> {
        if self.revoked_at.is_some_and(|r| r <= now) {
            return Err(AuthzFailure::Revoked);
        }
        if now < self.valid_from {
            return Err(AuthzFailure::NotYetValid);
        }
        if now >= self.valid_to {
            return Err(AuthzFailure::Expired);
        }
        Ok(())
    }

    /// Is `profile` within the record's `profileCap`?
    ///
    /// # Errors
    /// [`AuthzFailure::ProfileAboveCap`].
    pub fn check_profile(&self, profile: SafetyProfile) -> Result<(), AuthzFailure> {
        if profile > self.profile_cap {
            return Err(AuthzFailure::ProfileAboveCap {
                requested: profile.as_str(),
                cap: self.profile_cap.as_str(),
            });
        }
        Ok(())
    }

    /// Does the record's target cover `url` (origin or prefix match, and the
    /// path is not excluded)?
    ///
    /// # Errors
    /// [`AuthzFailure::NotCovered`] or [`AuthzFailure::Excluded`].
    pub fn check_covers_url(&self, url: &Url) -> Result<(), AuthzFailure> {
        self.scope().check_covers_url(url)
    }

    /// Is `ip` inside an authorized network?
    #[must_use]
    pub fn covers_ip(&self, ip: IpAddr) -> bool {
        self.authorized_networks.iter().any(|n| n.contains(&ip))
    }

    fn digest_with(&self, clear_signature: bool) -> Result<Digest, PolicyError> {
        let mut body = self.clone();
        body.verified_at = None;
        body.revoked_at = None;
        body.revoked_reason = None;
        if clear_signature {
            if let Some(OwnershipProof::OperatorSignature { signature, .. }) = &mut body.ownership {
                signature.clear();
            }
        }
        let json = serde_json::to_vec(&body)
            .map_err(|e| PolicyError::Digest(crawlx_core::CoreError::Serialization(e.to_string())))?;
        Ok(Digest::of(BODY_DOMAIN, &json))
    }

    /// Digest bound to a run at admission (`body_digest`): BLAKE3 over the canonical JSON of
    /// the immutable body. Lifecycle state (`verifiedAt`, `revokedAt`, `revokedReason`) is not
    /// part of it, so revoking a record does not change the digest a run was bound to.
    ///
    /// # Errors
    /// [`PolicyError::Digest`] if serialization fails.
    pub fn body_digest(&self) -> Result<Digest, PolicyError> {
        self.digest_with(false)
    }

    /// The digest an operator signature covers: [`Self::body_digest`] with the signature
    /// itself blanked.
    ///
    /// # Errors
    /// [`PolicyError::Digest`] if serialization fails.
    pub fn signing_digest(&self) -> Result<Digest, PolicyError> {
        self.digest_with(true)
    }

    /// The hosts whose ownership an internet-facing proof (DNS TXT, well-known file) must
    /// show: the host of every origin and URL prefix, canonical form, in order.
    #[must_use]
    pub fn challenge_hosts(&self) -> Vec<String> {
        self.scope().hosts().map(str::to_owned).collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::TimeZone;

    pub fn ts(day: u32) -> Timestamp {
        chrono::Utc.with_ymd_and_hms(2026, 10, day, 0, 0, 0).unwrap()
    }

    pub fn authorizer() -> Authorizer {
        Authorizer {
            name: "Ada Owner".to_owned(),
            role: "CTO".to_owned(),
            organization: "Example Corp".to_owned(),
            contact: "security@example.test".to_owned(),
            attests_ownership_or_control: true,
        }
    }

    pub fn record() -> AuthorizationRecord {
        AuthorizationRecord {
            id: AuthorizationRecordId::new(),
            tenant: TenantId::new(),
            version: 1,
            title: "Example staging test".to_owned(),
            authorizer: authorizer(),
            origins: vec!["https://staging.example.test".to_owned()],
            url_prefixes: Vec::new(),
            excluded_paths: vec!["/billing/*".to_owned()],
            authorized_networks: Vec::new(),
            valid_from: ts(20),
            valid_to: ts(28),
            profile_cap: SafetyProfile::AuthorizedSecurityTest,
            permitted_risk_classes: BTreeSet::from([
                RiskClass::PersistentWriteOwn,
                RiskClass::PersistentWriteOtherPrincipal,
                RiskClass::Destructive,
                RiskClass::SecurityChange,
                RiskClass::ExternalCommunication,
                RiskClass::FileUpload,
                RiskClass::FinancialTransaction,
                RiskClass::Unclassified,
            ]),
            approval_required: BTreeSet::from([RiskClass::Destructive]),
            test_accounts: vec![TestAccount {
                role: "member".to_owned(),
                credential_ref: "vault://crawlx/example/member".to_owned(),
            }],
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

    #[test]
    fn window_and_revocation() {
        let mut r = record();
        assert_eq!(r.check_active(ts(19)), Err(AuthzFailure::NotYetValid));
        assert_eq!(r.check_active(ts(20)), Ok(()));
        assert_eq!(r.check_active(ts(27)), Ok(()));
        assert_eq!(r.check_active(ts(28)), Err(AuthzFailure::Expired));
        r.revoked_at = Some(ts(22));
        assert_eq!(r.check_active(ts(21)), Ok(()));
        assert_eq!(r.check_active(ts(22)), Err(AuthzFailure::Revoked));
    }

    #[test]
    fn url_coverage_origin_prefix_and_exclusions() {
        let mut r = record();
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(r.check_covers_url(&u("https://staging.example.test/app")).is_ok());
        assert!(matches!(
            r.check_covers_url(&u("https://prod.example.test/")),
            Err(AuthzFailure::NotCovered(_))
        ));
        assert!(matches!(
            r.check_covers_url(&u("http://staging.example.test/")),
            Err(AuthzFailure::NotCovered(_))
        ));
        assert!(matches!(
            r.check_covers_url(&u("https://staging.example.test:8443/")),
            Err(AuthzFailure::NotCovered(_))
        ));
        assert!(matches!(
            r.check_covers_url(&u("https://staging.example.test/billing/invoices")),
            Err(AuthzFailure::Excluded(_))
        ));
        r.origins.clear();
        r.url_prefixes = vec!["https://other.example.test/app/".to_owned()];
        assert!(r.check_covers_url(&u("https://other.example.test/app/x")).is_ok());
        assert!(r
            .check_covers_url(&u("https://other.example.test/admin"))
            .is_err());
    }

    #[test]
    fn a_prefix_does_not_widen_to_its_origin_but_robots_stays_reachable() {
        let mut r = record();
        r.origins.clear();
        r.url_prefixes = vec!["https://other.example.test/app/".to_owned()];
        let scope = r.scope();
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(scope
            .check_request(&u("https://other.example.test/app/a"))
            .is_ok());
        assert!(scope
            .check_request(&u("https://other.example.test/admin"))
            .is_err());
        assert!(scope
            .check_request(&u("https://other.example.test/robots.txt"))
            .is_ok());
        assert!(scope
            .check_covers_url(&u("https://other.example.test/robots.txt"))
            .is_err());
        assert!(scope
            .check_request(&u("https://elsewhere.example.test/robots.txt"))
            .is_err());
    }

    #[test]
    fn scope_hosts_are_explicit_and_canonical() {
        let mut r = record();
        r.origins = vec![
            "https://Staging.Example.test".to_owned(),
            "http://127.0.0.1:8080".to_owned(),
            "http://[::1]:9000".to_owned(),
        ];
        let scope = r.scope();
        let h = |s: &str| Host::parse(s).unwrap();
        assert!(scope.contains_host(&h("staging.example.test")));
        assert!(scope.contains_host(&h("127.0.0.1")));
        assert!(scope.contains_host(&h("[::1]")));
        assert!(!scope.contains_host(&h("sub.staging.example.test")));
        assert!(!scope.contains_host(&h("example.test")));
        assert_eq!(r.challenge_hosts().len(), 3);
    }

    #[test]
    fn network_coverage() {
        let mut r = record();
        r.authorized_networks = vec!["10.20.0.0/16".parse().unwrap(), "fd12::/32".parse().unwrap()];
        assert!(r.covers_ip("10.20.1.1".parse().unwrap()));
        assert!(!r.covers_ip("10.21.1.1".parse().unwrap()));
        assert!(r.covers_ip("fd12::5".parse().unwrap()));
    }

    #[test]
    fn profile_cap_bounds_the_profile() {
        let mut r = record();
        r.profile_cap = SafetyProfile::TestEnvironment;
        assert!(r.check_profile(SafetyProfile::ReadOnly).is_ok());
        assert!(r.check_profile(SafetyProfile::TestEnvironment).is_ok());
        assert_eq!(
            r.check_profile(SafetyProfile::AuthorizedSecurityTest),
            Err(AuthzFailure::ProfileAboveCap {
                requested: "authorized_security_test",
                cap: "test_environment"
            })
        );
    }

    #[test]
    fn validation_rules() {
        assert!(record().validate().is_ok());
        let mut r = record();
        r.origins = vec!["https://*.example.test".to_owned()];
        assert!(r.validate().is_err());
        let mut r = record();
        r.origins.clear();
        assert!(r.validate().is_err());
        let mut r = record();
        r.valid_to = r.valid_from;
        assert!(r.validate().is_err());
        let mut r = record();
        r.valid_to = r.valid_from + chrono::Duration::days(91);
        assert!(r.validate().is_err());
        let mut r = record();
        r.valid_to = r.valid_from + chrono::Duration::days(90);
        assert!(r.validate().is_ok());
    }

    #[test]
    fn validation_requires_the_plan_05_fields() {
        let mut r = record();
        r.authorizer.name = " ".to_owned();
        assert!(r.validate().is_err(), "named authorizer");
        let mut r = record();
        r.authorizer.attests_ownership_or_control = false;
        assert!(r.validate().is_err(), "ownership attestation");
        let mut r = record();
        r.emergency_contact.clear();
        assert!(r.validate().is_err(), "emergency contact");
        let mut r = record();
        r.permitted_risk_classes.insert(RiskClass::OutOfScope);
        assert!(r.validate().is_err(), "out_of_scope is never permitted");
        let mut r = record();
        r.test_accounts[0].credential_ref = "hunter2".to_owned();
        assert!(r.validate().is_err(), "credential references only");
        let mut r = record();
        r.authorized_networks = vec!["10.0.0.0/8".parse().unwrap()];
        r.ownership = Some(OwnershipProof::DnsTxt {});
        assert!(r.validate().is_err(), "networks need an operator signature");
        r.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "k1".to_owned(),
            signature: String::new(),
        });
        assert!(r.validate().is_ok());
    }

    #[test]
    fn json_roundtrip_uses_camel_case_and_string_cidrs() {
        let mut r = record();
        r.authorized_networks = vec!["10.0.0.0/8".parse().unwrap()];
        r.ownership = Some(OwnershipProof::WellKnownFile {});
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["authorizedNetworks"][0], "10.0.0.0/8");
        assert_eq!(v["profileCap"], "authorized_security_test");
        assert_eq!(v["permittedRiskClasses"][0], "persistent_write_own");
        assert_eq!(v["ownership"]["kind"], "well_known_file");
        let signed = OwnershipProof::OperatorSignature {
            key_id: "k1".to_owned(),
            signature: "ab".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&signed).unwrap(),
            serde_json::json!({"kind": "operator_signature", "keyId": "k1", "signature": "ab"})
        );
        assert!(v.get("validFrom").is_some());
        assert!(v.get("robotsOverrideAcknowledged").is_some());
        assert!(
            v.get("revokedAt").is_none(),
            "lifecycle state is omitted until set"
        );
        let back: AuthorizationRecord = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        let good = serde_json::to_value(record()).unwrap();
        let mut top = good.clone();
        top["permittedRiskClass"] = serde_json::json!([]);
        let e = serde_json::from_value::<AuthorizationRecord>(top)
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown field `permittedRiskClass`"), "{e}");
        let mut nested = good.clone();
        nested["authorizer"]["title"] = serde_json::json!("x");
        assert!(serde_json::from_value::<AuthorizationRecord>(nested).is_err());
        let mut evidence = good.clone();
        evidence["evidence"]["blake3"] = serde_json::json!("00");
        assert!(serde_json::from_value::<AuthorizationRecord>(evidence).is_err());
        let mut proof = good;
        proof["ownership"] = serde_json::json!({"kind": "dns_txt", "host": "x"});
        assert!(serde_json::from_value::<AuthorizationRecord>(proof).is_err());
    }

    #[test]
    fn required_fields_are_required_on_the_wire() {
        let good = serde_json::to_value(record()).unwrap();
        for field in [
            "authorizer",
            "permittedRiskClasses",
            "approvalRequired",
            "testAccounts",
            "emergencyContact",
            "profileCap",
            "evidence",
            "validFrom",
            "validTo",
        ] {
            let mut v = good.clone();
            v.as_object_mut().unwrap().remove(field);
            let e = serde_json::from_value::<AuthorizationRecord>(v)
                .unwrap_err()
                .to_string();
            assert!(e.contains(&format!("missing field `{field}`")), "{field}: {e}");
        }
    }

    #[test]
    fn record_version_alias_is_accepted() {
        let mut v = serde_json::to_value(record()).unwrap();
        let version = v.as_object_mut().unwrap().remove("version").unwrap();
        v["recordVersion"] = version;
        let r: AuthorizationRecord = serde_json::from_value(v).unwrap();
        assert_eq!(r.version, 1);
    }

    #[test]
    fn body_digest_changes_with_content_not_with_lifecycle_state() {
        let a = record();
        let mut b = a.clone();
        assert_eq!(a.body_digest().unwrap(), b.body_digest().unwrap());
        b.version = 2;
        assert_ne!(a.body_digest().unwrap(), b.body_digest().unwrap());
        let mut c = a.clone();
        c.revoked_at = Some(ts(22));
        c.revoked_reason = Some("engagement ended".to_owned());
        c.verified_at = Some(ts(21));
        assert_eq!(a.body_digest().unwrap(), c.body_digest().unwrap());
        let mut d = a.clone();
        d.permitted_risk_classes.remove(&RiskClass::Destructive);
        assert_ne!(a.body_digest().unwrap(), d.body_digest().unwrap());
    }

    #[test]
    fn signing_digest_ignores_the_signature_only() {
        let mut a = record();
        a.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "k1".to_owned(),
            signature: String::new(),
        });
        let mut b = a.clone();
        b.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "k1".to_owned(),
            signature: "abcd".to_owned(),
        });
        assert_eq!(a.signing_digest().unwrap(), b.signing_digest().unwrap());
        assert_ne!(a.body_digest().unwrap(), b.body_digest().unwrap());
        b.ownership = Some(OwnershipProof::OperatorSignature {
            key_id: "k2".to_owned(),
            signature: String::new(),
        });
        assert_ne!(a.signing_digest().unwrap(), b.signing_digest().unwrap());
    }
}
