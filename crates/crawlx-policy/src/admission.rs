//! Run admission.
//!
//! [`AdmissionPolicy::admit`] normalizes a `CreateCrawl`, clamps it to the
//! tenant's limits, and evaluates the gates that need an
//! [`AuthorizationRecord`]:
//!
//! | request | requires |
//! |---|---|
//! | any record reference | the record is valid, active, within its profile cap and covers the seed; from then on the record's target bounds **every** request of the run (egress and scope policy) |
//! | `safety.profile = authorized_security_test` | the record above |
//! | `safety.allowPrivateNetworks` | the same, plus a non-empty `authorizedNetworks` (E11) |
//! | `safety.respectRobotsTxt = false` | the same, plus `robotsOverrideAcknowledged` |
//! | `dynamic.launchProfile = stealth` | profile other than `read_only` (`profile_conflict`) |
//!
//! It also runs the egress pre-resolution checks on the seed, role replica
//! URLs and the webhook so SSRF targets are refused with `url_denied` before
//! a run exists. Every violation is returned, not just the first.

use crate::authorization::{AuthorizationRecord, AuthzFailure};
use crate::egress::{EgressPolicy, PrivateHostScope};
use crate::egress_lists::SharedEgressLists;
use crate::scope::ExcludeHosts;
use crawlx_core::config::{CreateCrawl, ExternalCommunication, LaunchProfile, RetentionMode, SafetyProfile};
use crawlx_core::error::CoreError;
use crawlx_core::gates::GateStatus;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{AuthorizationRecordId, TenantId};
use crawlx_core::time::Clock;
use std::sync::Arc;
use url::Url;

/// Per-tenant ceilings (`tenants.plan`). Requests above a ceiling are clamped
/// and reported in [`Admitted::clamps`]; politeness floors are raised.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TenantLimits {
    /// When set, a supplied authorization record must belong to this tenant.
    pub tenant_id: Option<TenantId>,
    /// Ceiling for `limits.urls` (pages per run).
    pub max_urls: u32,
    /// Ceiling for `limits.interactions` (browser interactions per run).
    pub max_interactions: u32,
    /// Ceiling for `limits.states` (distinct browser states per run).
    pub max_states: u32,
    /// Ceiling for the run's wall-clock duration, in seconds.
    pub max_duration_seconds: u32,
    /// Ceiling for `scope.maxDiscoveryDepth` (link hops from the seed).
    pub max_discovery_depth: u16,
    /// Ceiling for `dynamic.maxTabs` (concurrent browser tabs).
    pub max_tabs: u8,
    /// Floor for `politeness.delayMs`.
    pub min_delay_ms: u32,
    /// Ceiling for `politeness.maxInFlightPerOrigin`.
    pub max_in_flight_per_origin: u8,
    /// Tenant requires zero-data-retention: `retention.mode` is forced to `zdr`.
    pub zdr_enforced: bool,
    /// Takedown/abuse blocklist: hosts and their subdomains (admission-time `url_denied`).
    pub blocked_hosts: Vec<String>,
}

impl Default for TenantLimits {
    fn default() -> Self {
        Self {
            tenant_id: None,
            max_urls: 1_000_000,
            max_interactions: 100_000,
            max_states: 100_000,
            max_duration_seconds: 7 * 86_400,
            max_discovery_depth: 100,
            max_tabs: 8,
            min_delay_ms: 50,
            max_in_flight_per_origin: 8,
            zdr_enforced: false,
            blocked_hosts: Vec::new(),
        }
    }
}

/// One admission violation (`details[]` entry of the error envelope).
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
#[error("{path}: {code}: {message}")]
pub struct AdmissionError {
    /// JSON pointer into the request, e.g. `/safety/profile`.
    pub path: String,
    /// One of the stable `details[].code` values.
    pub code: &'static str,
    /// Human-readable explanation of the violation.
    pub message: String,
}

impl AdmissionError {
    fn new(path: impl Into<String>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            code,
            message: message.into(),
        }
    }
}

/// A value the tenant ceiling reduced.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Clamp {
    /// JSON pointer of the clamped field, e.g. `/limits/urls`.
    pub path: &'static str,
    /// Value the request asked for.
    pub requested: u64,
    /// Value after clamping to the tenant ceiling.
    pub applied: u64,
}

/// Authorization binding recorded on the run (`authorization_record_id`, `body_digest`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AuthorizationBinding {
    /// Id of the authorization record the run is bound to.
    pub record_id: AuthorizationRecordId,
    /// Version of that record at admission time.
    pub version: u32,
    /// BLAKE3 digest of the record body at that version.
    pub body_digest: Digest,
}

/// Result of a successful admission. The `CreateCrawl` passed to
/// [`AdmissionPolicy::admit`] is normalized and clamped in place.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Admitted {
    /// Egress policy the run's fetch, browser and robots callers must use.
    pub egress: EgressPolicy,
    /// Binding to store with the run, when a record was supplied.
    pub authorization: Option<AuthorizationBinding>,
    /// Fields reduced to the tenant ceilings.
    pub clamps: Vec<Clamp>,
    /// Digest of the normalized, clamped request (`crawl_runs.config_digest`).
    pub config_digest: Digest,
}

/// Admission policy. Holds the clock (record windows) and the live deployment lists: the CIDR
/// allowlist that private-network records must stay inside and the operator host blocklist
/// (`egress.deployment_allowlist`, `egress.operator_blocklist`).
pub struct AdmissionPolicy {
    clock: Arc<dyn Clock>,
    lists: Option<SharedEgressLists>,
    require_verified: bool,
    gates: GateStatus,
}

fn pointer(field: &str) -> String {
    let mut out = String::new();
    for part in field.split('.') {
        out.push('/');
        out.push_str(&part.replace("[]", ""));
    }
    out
}

/// Map a core validation error to a `details[]` entry.
fn from_core(e: &CoreError) -> AdmissionError {
    match e {
        CoreError::Required {
            field: "safety.authorizationRecordRef",
            context,
        } => {
            let path = match *context {
                "authorized_security_test" => "/safety/profile",
                "allowPrivateNetworks" => "/safety/allowPrivateNetworks",
                _ => "/safety/respectRobotsTxt",
            };
            AdmissionError::new(path, "authorization_required", e.to_string())
        }
        CoreError::Required { field, .. } => AdmissionError::new(pointer(field), "required", e.to_string()),
        CoreError::Invalid { field, .. } => AdmissionError::new(pointer(field), e.code(), e.to_string()),
        CoreError::Conflict { a, .. } => {
            let code = if *a == "mode" {
                "mode_conflict"
            } else {
                "profile_conflict"
            };
            AdmissionError::new(pointer(a), code, e.to_string())
        }
        other => AdmissionError::new("/", other.code(), other.to_string()),
    }
}

fn clamp_u32(path: &'static str, value: &mut u32, ceiling: u32, clamps: &mut Vec<Clamp>) {
    if *value > ceiling {
        clamps.push(Clamp {
            path,
            requested: u64::from(*value),
            applied: u64::from(ceiling),
        });
        *value = ceiling;
    }
}

fn host_blocked(host: &str, blocked: &[String]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    blocked.iter().any(|b| {
        let b = b
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_ascii_lowercase();
        h == b || h.strip_suffix(&b).is_some_and(|rest| rest.ends_with('.'))
    })
}

impl AdmissionPolicy {
    /// Policy using `clock` for authorization windows.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            lists: None,
            require_verified: false,
            gates: GateStatus::NONE,
        }
    }

    /// Use the running build's verified milestone gates. Without this, no model
    /// authority above `shadow` is admitted.
    #[must_use]
    pub const fn with_gates(mut self, gates: GateStatus) -> Self {
        self.gates = gates;
        self
    }

    /// Apply the deployment lists: private-network records' `authorizedNetworks` must lie inside
    /// the allowlist, the operator blocklist refuses its hosts, and the lists
    /// travel with the run's egress policy so later reloads reach the run.
    #[must_use]
    pub fn with_egress_lists(mut self, lists: SharedEgressLists) -> Self {
        self.lists = Some(lists);
        self
    }

    /// Refuse a record whose ownership proof was never checked (`verifiedAt` unset). The API
    /// sets this: it creates records only through the verifying route. Local runs
    /// (`crawlx crawl --authorization-record`) leave it off, because the operator running the
    /// crawl is the authorizer.
    #[must_use]
    pub const fn require_verified_ownership(mut self) -> Self {
        self.require_verified = true;
        self
    }

    /// Admit `crawl`: normalize, clamp to `tenant_limits`, apply the gates.
    ///
    /// # Errors
    /// Every violation found, as [`AdmissionError`] entries.
    pub fn admit(
        &self,
        crawl: &mut CreateCrawl,
        tenant_limits: &TenantLimits,
        authorization: Option<&AuthorizationRecord>,
    ) -> Result<Admitted, Vec<AdmissionError>> {
        let mut errs: Vec<AdmissionError> = Vec::new();
        let mut clamps = Vec::new();

        if tenant_limits.zdr_enforced && crawl.retention.mode != RetentionMode::Zdr {
            crawl.retention.mode = RetentionMode::Zdr;
        }
        if let Err(core) = crawl.normalize() {
            errs.extend(core.iter().map(from_core));
        }
        if let Err(core) = crawl.check_gates(self.gates) {
            errs.push(from_core(&core));
        }

        Self::clamp_limits(crawl, tenant_limits, &mut clamps);

        let record = self.check_record(crawl, tenant_limits, authorization, &mut errs);
        errs.extend(Self::check_role_credentials(crawl, record));
        let egress = self.build_egress(crawl, record, &mut errs);
        Self::check_robots_override(crawl, record, &mut errs);
        Self::check_sinks(crawl, record, &mut errs);
        self.check_urls(crawl, tenant_limits, &egress, &mut errs);
        if let Some(rl) = record.and_then(|r| r.rate_limits) {
            crawl.politeness.delay_ms = crawl.politeness.delay_ms.max(rl.min_delay_ms);
            crawl.politeness.max_in_flight_per_origin = crawl
                .politeness
                .max_in_flight_per_origin
                .min(rl.max_in_flight_per_origin.max(1));
        }

        if !errs.is_empty() {
            return Err(errs);
        }
        let authorization = match record {
            Some(r) => {
                let body_digest = r.body_digest().map_err(|e| {
                    vec![AdmissionError::new(
                        "/safety/authorizationRecordRef",
                        "serialization",
                        e.to_string(),
                    )]
                })?;
                Some(AuthorizationBinding {
                    record_id: r.id,
                    version: r.version,
                    body_digest,
                })
            }
            None => None,
        };
        let config_digest = crawl.digest().map_err(|e| vec![from_core(&e)])?;
        Ok(Admitted {
            egress,
            authorization,
            clamps,
            config_digest,
        })
    }

    /// Check every role credential against the selected record's declared test accounts.
    /// Anonymous roles need no account. Missing records never authorize credential use.
    #[must_use]
    pub fn check_role_credentials(
        crawl: &CreateCrawl,
        record: Option<&AuthorizationRecord>,
    ) -> Vec<AdmissionError> {
        crawl
            .roles
            .iter()
            .enumerate()
            .filter_map(|(index, role)| {
                let reference = role.credential_ref.as_ref()?;
                let allowed = record.is_some_and(|record| {
                    crawl.safety.authorization_record_ref == Some(record.id)
                        && record
                            .test_accounts
                            .iter()
                            .any(|account| account.role == role.name && account.credential_ref == reference.0)
                });
                (!allowed).then(|| {
                    AdmissionError::new(
                        format!("/roles/{index}/credentialRef"),
                        "authorization_required",
                        "role credential is not declared by the selected authorization record",
                    )
                })
            })
            .collect()
    }

    fn clamp_limits(crawl: &mut CreateCrawl, t: &TenantLimits, clamps: &mut Vec<Clamp>) {
        clamp_u32("/limits/urls", &mut crawl.limits.urls, t.max_urls.max(1), clamps);
        clamp_u32(
            "/limits/interactions",
            &mut crawl.limits.interactions,
            t.max_interactions,
            clamps,
        );
        clamp_u32("/limits/states", &mut crawl.limits.states, t.max_states, clamps);
        clamp_u32(
            "/limits/durationSeconds",
            &mut crawl.limits.duration_seconds,
            t.max_duration_seconds.max(10),
            clamps,
        );
        if crawl.scope.max_discovery_depth > t.max_discovery_depth {
            clamps.push(Clamp {
                path: "/scope/maxDiscoveryDepth",
                requested: u64::from(crawl.scope.max_discovery_depth),
                applied: u64::from(t.max_discovery_depth),
            });
            crawl.scope.max_discovery_depth = t.max_discovery_depth;
        }
        let tabs_ceiling = t.max_tabs.max(1);
        if crawl.dynamic.max_tabs > tabs_ceiling {
            clamps.push(Clamp {
                path: "/dynamic/maxTabs",
                requested: u64::from(crawl.dynamic.max_tabs),
                applied: u64::from(tabs_ceiling),
            });
            crawl.dynamic.max_tabs = tabs_ceiling;
        }
        if crawl.politeness.delay_ms < t.min_delay_ms {
            clamps.push(Clamp {
                path: "/politeness/delayMs",
                requested: u64::from(crawl.politeness.delay_ms),
                applied: u64::from(t.min_delay_ms),
            });
            crawl.politeness.delay_ms = t.min_delay_ms;
        }
        let in_flight_ceiling = t.max_in_flight_per_origin.max(1);
        if crawl.politeness.max_in_flight_per_origin > in_flight_ceiling {
            clamps.push(Clamp {
                path: "/politeness/maxInFlightPerOrigin",
                requested: u64::from(crawl.politeness.max_in_flight_per_origin),
                applied: u64::from(in_flight_ceiling),
            });
            crawl.politeness.max_in_flight_per_origin = in_flight_ceiling;
        }
    }

    /// Validate the record whenever a reference is present. Returns the record only if it is
    /// usable.
    fn check_record<'a>(
        &self,
        crawl: &CreateCrawl,
        t: &TenantLimits,
        authorization: Option<&'a AuthorizationRecord>,
        errs: &mut Vec<AdmissionError>,
    ) -> Option<&'a AuthorizationRecord> {
        let s = &crawl.safety;
        let Some(reference) = s.authorization_record_ref else {
            // a missing reference was already reported by `normalize` when a gate needs it
            return None;
        };
        let path = "/safety/authorizationRecordRef";
        let Some(record) = authorization else {
            errs.push(AdmissionError::new(
                path,
                "authorization_required",
                format!("authorization record {reference} was not found"),
            ));
            return None;
        };
        let mut ok = true;
        let mut fail = |at: &str, msg: String| {
            errs.push(AdmissionError::new(at, "authorization_required", msg));
            ok = false;
        };
        if record.id != reference {
            fail(
                path,
                format!("record {} does not match reference {reference}", record.id),
            );
        }
        if t.tenant_id.is_some_and(|id| id != record.tenant) {
            fail(path, AuthzFailure::TenantMismatch.to_string());
        }
        if let Err(e) = record.validate() {
            fail(path, e.to_string());
        }
        if let Err(e) = record.check_active(self.clock.now()) {
            fail(path, e.to_string());
        }
        if let Err(e) = record.check_profile(s.profile) {
            fail("/safety/profile", e.to_string());
        }
        if self.require_verified && record.verified_at.is_none() {
            fail(path, AuthzFailure::NotVerified.to_string());
        }
        // a referenced record bounds the whole run, so it has to cover the seed
        if let Err(e) = record.check_covers_url(&crawl.seed_url) {
            fail(path, format!("seed URL: {e}"));
        }
        ok.then_some(record)
    }

    /// Build the egress policy; evaluate the private-network gate (E11). The policy carries the
    /// record's target (every request of the run stays inside it), the live deployment lists and,
    /// for `test_environment` runs, the deployment allowlist as an exemption of its own.
    fn build_egress(
        &self,
        crawl: &CreateCrawl,
        record: Option<&AuthorizationRecord>,
        errs: &mut Vec<AdmissionError>,
    ) -> EgressPolicy {
        let mut policy = EgressPolicy::new(false).with_seed_port(&crawl.seed_url);
        match ExcludeHosts::new(&crawl.scope.exclude_hosts) {
            Ok(exclusions) => policy = policy.with_host_exclusions(exclusions),
            Err(error) => {
                errs.push(AdmissionError::new(
                    "/scope/excludeHosts",
                    "invalid_pattern",
                    error.to_string(),
                ));
                return policy;
            }
        }
        for role in &crawl.roles {
            if let Some(u) = &role.replica_base_url {
                policy = policy.with_seed_port(u);
            }
        }
        if let Some(lists) = &self.lists {
            policy = policy.with_lists(lists.clone());
        }
        policy.deployment_exempt = crawl.safety.profile == SafetyProfile::TestEnvironment;
        if let Some(record) = record {
            policy = policy
                .with_record_scope(record.scope())
                .with_authorized_private_networks(Vec::new());
        }
        if !crawl.safety.allow_private_networks {
            return policy;
        }
        let path = "/safety/allowPrivateNetworks";
        // a missing record reference is reported elsewhere; without a usable record nothing is exempted
        let Some(record) = record else { return policy };
        if record.authorized_networks.is_empty() {
            errs.push(AdmissionError::new(
                path,
                "authorization_required",
                "allowPrivateNetworks needs a record listing authorizedNetworks",
            ));
            return policy;
        }
        if let Some(lists) = &self.lists {
            let snapshot = lists.snapshot();
            for net in &record.authorized_networks {
                if !snapshot.allows_network(net) {
                    errs.push(AdmissionError::new(
                        path,
                        "authorization_required",
                        format!("authorized network {net} is outside the deployment allowlist"),
                    ));
                }
            }
        }
        policy.with_private_host_scope(PrivateHostScope::new(record))
    }
    fn check_robots_override(
        crawl: &CreateCrawl,
        record: Option<&AuthorizationRecord>,
        errs: &mut Vec<AdmissionError>,
    ) {
        if crawl.safety.respect_robots_txt {
            return;
        }
        if let Some(r) = record {
            if !r.robots_override_acknowledged {
                errs.push(AdmissionError::new(
                    "/safety/respectRobotsTxt",
                    "authorization_required",
                    "respectRobotsTxt=false needs robotsOverrideAcknowledged in the authorization record",
                ));
            }
        }
    }

    fn check_sinks(
        crawl: &CreateCrawl,
        record: Option<&AuthorizationRecord>,
        errs: &mut Vec<AdmissionError>,
    ) {
        if crawl.safety.profile == SafetyProfile::AuthorizedSecurityTest
            && crawl.safety.external_communication == ExternalCommunication::TestSinks
        {
            if let Some(r) = record {
                if r.test_sinks.is_empty() {
                    errs.push(AdmissionError::new(
                        "/safety/externalCommunication",
                        "authorization_required",
                        "test_sinks needs testSinks in the authorization record",
                    ));
                }
            }
        }
        if crawl.dynamic.launch_profile == LaunchProfile::Stealth
            && crawl.safety.profile == SafetyProfile::ReadOnly
        {
            // `normalize` reports this as profile_conflict; keep the gate explicit if that ever changes
            let reported = errs
                .iter()
                .any(|e| e.path == "/dynamic/launchProfile" && e.code == "profile_conflict");
            if !reported {
                errs.push(AdmissionError::new(
                    "/dynamic/launchProfile",
                    "profile_conflict",
                    "stealth requires test_environment or authorized_security_test",
                ));
            }
        }
    }

    /// Egress pre-resolution checks and blocklists (tenant takedowns and the operator's) for
    /// every URL the request names. The seed is not held to the record's target here:
    /// `check_record` already reported an uncovered seed once.
    fn check_urls(
        &self,
        crawl: &CreateCrawl,
        t: &TenantLimits,
        egress: &EgressPolicy,
        errs: &mut Vec<AdmissionError>,
    ) {
        let mut check = |path: &str, url: &Url, policy: &EgressPolicy| {
            if let Err(e) = policy.check_url(url) {
                errs.push(AdmissionError::new(path, "url_denied", e.to_string()));
                return;
            }
            if url.host_str().is_some_and(|h| host_blocked(h, &t.blocked_hosts)) {
                errs.push(AdmissionError::new(
                    path,
                    "url_denied",
                    "host is on the operator blocklist",
                ));
            }
        };
        let mut seed_policy = egress.clone();
        seed_policy.record_scope = None;
        check("/seedUrl", &crawl.seed_url, &seed_policy);
        for (i, role) in crawl.roles.iter().enumerate() {
            if let Some(u) = &role.replica_base_url {
                check(&format!("/roles/{i}/replicaBaseUrl"), u, egress);
            }
        }
        if let Some(w) = &crawl.output.webhook {
            // delivered by the API tier, never with a private-network exemption
            let mut webhook_policy = EgressPolicy::new(false);
            webhook_policy.lists = self.lists.clone();
            check("/output/webhook/url", &w.url, &webhook_policy);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::authorization::tests::{record, ts};
    use crate::egress_lists::EgressLists;
    use crawlx_core::config::{DestructiveActions, Role};
    use crawlx_core::time::ManualClock;

    fn policy() -> AdmissionPolicy {
        // 2026-10-22: inside the fixture record's window (20th to 28th)
        AdmissionPolicy::new(Arc::new(ManualClock::new(ts(22))))
    }

    fn crawl(seed: &str) -> CreateCrawl {
        CreateCrawl::new(Url::parse(seed).unwrap())
    }

    fn staging() -> CreateCrawl {
        crawl("https://staging.example.test/")
    }

    fn with_record(c: &mut CreateCrawl, r: &AuthorizationRecord) {
        c.safety.authorization_record_ref = Some(r.id);
    }

    fn codes(errs: &[AdmissionError]) -> Vec<(&str, &'static str)> {
        errs.iter().map(|e| (e.path.as_str(), e.code)).collect()
    }

    fn admit(c: &mut CreateCrawl, r: Option<&AuthorizationRecord>) -> Result<Admitted, Vec<AdmissionError>> {
        policy().admit(c, &TenantLimits::default(), r)
    }

    #[test]
    fn plain_request_is_admitted_with_digest_and_no_binding() {
        let mut c = crawl("https://example.com/");
        let a = admit(&mut c, None).unwrap();
        assert!(a.authorization.is_none());
        assert!(a.clamps.is_empty());
        assert_eq!(a.config_digest, c.digest().unwrap());
        assert!(a.egress.check_ip("8.8.8.8".parse().unwrap()).is_ok());
        assert!(a.egress.check_ip("10.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn model_authority_requires_g3_at_admission() {
        for mode in [
            crawlx_core::config::System1Mode::Advisory,
            crawlx_core::config::System1Mode::Active,
        ] {
            let mut c = crawl("https://example.com/");
            c.dynamic.system1_mode = mode;
            let errs = admit(&mut c, None).unwrap_err();
            assert!(codes(&errs).contains(&("/dynamic/system1Mode", "profile_conflict")));
            assert!(policy()
                .with_gates(GateStatus { g1: true, g3: false })
                .admit(&mut c, &TenantLimits::default(), None)
                .is_err());
            assert!(policy()
                .with_gates(GateStatus { g1: false, g3: true })
                .admit(&mut c, &TenantLimits::default(), None)
                .is_ok());
        }
    }

    #[test]
    fn gated_strategies_require_g1_at_admission_and_defaults_do_not() {
        use crawlx_core::config::StrategyName;
        let mut default = crawl("https://example.com/");
        assert!(
            admit(&mut default, None).is_ok(),
            "default strategies need no gate"
        );
        for name in [StrategyName::StateNovelty, StrategyName::Enablement] {
            let mut c = crawl("https://example.com/");
            c.dynamic.strategies.push(name);
            let errs = admit(&mut c, None).unwrap_err();
            assert!(
                codes(&errs).contains(&("/dynamic/strategies", "profile_conflict")),
                "{errs:?}"
            );
            assert!(policy()
                .with_gates(GateStatus { g1: false, g3: true })
                .admit(&mut c, &TenantLimits::default(), None)
                .is_err());
            assert!(policy()
                .with_gates(GateStatus { g1: true, g3: false })
                .admit(&mut c, &TenantLimits::default(), None)
                .is_ok());
        }
    }

    #[test]
    fn normalize_violations_are_reported_with_paths_and_codes() {
        let mut c = crawl("https://example.com/");
        c.dynamic.strategies.clear();
        c.mode = crawlx_core::config::CrawlMode::Hybrid;
        c.roles = vec![
            Role {
                name: "a".into(),
                credential_ref: None,
                login_plan: None,
                replica_base_url: None,
            },
            Role {
                name: "a".into(),
                credential_ref: None,
                login_plan: None,
                replica_base_url: None,
            },
        ];
        let errs = admit(&mut c, None).unwrap_err();
        let got = codes(&errs);
        assert!(got.contains(&("/dynamic/strategies", "required")), "{got:?}");
        assert!(got.contains(&("/roles", "invalid_pattern")), "{got:?}");
    }

    #[test]
    fn tenant_limits_clamp_and_report() {
        let mut c = crawl("https://example.com/");
        c.limits.urls = 500_000;
        c.limits.interactions = 9_000;
        c.limits.duration_seconds = 86_400;
        c.scope.max_discovery_depth = 50;
        c.dynamic.max_tabs = 6;
        c.politeness.delay_ms = 100;
        c.politeness.max_in_flight_per_origin = 4;
        let t = TenantLimits {
            max_urls: 1000,
            max_interactions: 100,
            max_duration_seconds: 3600,
            max_discovery_depth: 5,
            max_tabs: 2,
            min_delay_ms: 500,
            max_in_flight_per_origin: 2,
            ..TenantLimits::default()
        };
        let a = policy().admit(&mut c, &t, None).unwrap();
        assert_eq!(
            (c.limits.urls, c.limits.interactions, c.limits.duration_seconds),
            (1000, 100, 3600)
        );
        assert_eq!((c.scope.max_discovery_depth, c.dynamic.max_tabs), (5, 2));
        assert_eq!(
            (c.politeness.delay_ms, c.politeness.max_in_flight_per_origin),
            (500, 2)
        );
        let paths: Vec<_> = a.clamps.iter().map(|c| c.path).collect();
        for p in [
            "/limits/urls",
            "/limits/interactions",
            "/limits/durationSeconds",
            "/scope/maxDiscoveryDepth",
            "/dynamic/maxTabs",
            "/politeness/delayMs",
            "/politeness/maxInFlightPerOrigin",
        ] {
            assert!(paths.contains(&p), "{p} missing in {paths:?}");
        }
        let urls = a.clamps.iter().find(|c| c.path == "/limits/urls").unwrap();
        assert_eq!((urls.requested, urls.applied), (500_000, 1000));
    }

    #[test]
    fn zdr_tenant_forces_zdr_retention() {
        let mut c = crawl("https://example.com/");
        let t = TenantLimits {
            zdr_enforced: true,
            ..TenantLimits::default()
        };
        policy().admit(&mut c, &t, None).unwrap();
        assert_eq!(c.retention.mode, RetentionMode::Zdr);
        assert_eq!(c.retention.days, 0);
    }

    // ---- authorized_security_test gate ----

    #[test]
    fn authorized_profile_without_reference_is_rejected() {
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        let errs = admit(&mut c, None).unwrap_err();
        assert_eq!(codes(&errs), [("/safety/profile", "authorization_required")]);
    }

    #[test]
    fn authorized_profile_with_valid_record_is_admitted_and_bound() {
        let r = record();
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        with_record(&mut c, &r);
        let a = admit(&mut c, Some(&r)).unwrap();
        let b = a.authorization.unwrap();
        assert_eq!((b.record_id, b.version), (r.id, 1));
        assert_eq!(b.body_digest, r.body_digest().unwrap());
    }

    #[test]
    fn authorized_profile_reference_without_record_is_rejected() {
        let r = record();
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        with_record(&mut c, &r);
        let errs = admit(&mut c, None).unwrap_err();
        assert_eq!(
            codes(&errs),
            [("/safety/authorizationRecordRef", "authorization_required")]
        );
    }

    #[test]
    fn record_id_mismatch_revoked_expired_and_future_are_rejected() {
        let r = record();
        let setup = |rec: &AuthorizationRecord| {
            let mut c = staging();
            c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
            with_record(&mut c, &r);
            admit(&mut c, Some(rec))
        };
        let mut other = r.clone();
        other.id = AuthorizationRecordId::new();
        assert!(setup(&other).is_err());
        let mut revoked = r.clone();
        revoked.revoked_at = Some(ts(21));
        assert!(setup(&revoked).unwrap_err()[0].message.contains("revoked"));
        let mut expired = r.clone();
        expired.valid_from = ts(10);
        expired.valid_to = ts(20);
        assert!(setup(&expired).unwrap_err()[0].message.contains("expired"));
        let mut future = r.clone();
        future.valid_from = ts(25);
        future.valid_to = ts(27);
        assert!(setup(&future).unwrap_err()[0].message.contains("not yet valid"));
        assert!(setup(&r).is_ok());
    }

    #[test]
    fn record_must_cover_the_seed_origin_and_not_exclude_its_path() {
        let r = record();
        let run = |seed: &str| {
            let mut c = crawl(seed);
            c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
            with_record(&mut c, &r);
            admit(&mut c, Some(&r))
        };
        assert!(run("https://prod.example.test/").unwrap_err()[0]
            .message
            .contains("not covered"));
        assert!(run("https://staging.example.test/billing/x").unwrap_err()[0]
            .message
            .contains("excluded"));
        assert!(run("https://staging.example.test/app").is_ok());
    }

    #[test]
    fn record_from_another_tenant_is_rejected() {
        let r = record();
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        with_record(&mut c, &r);
        let t = TenantLimits {
            tenant_id: Some(TenantId::new()),
            ..TenantLimits::default()
        };
        let errs = policy().admit(&mut c, &t, Some(&r)).unwrap_err();
        assert!(errs[0].message.contains("another tenant"));
        let t = TenantLimits {
            tenant_id: Some(r.tenant),
            ..TenantLimits::default()
        };
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        with_record(&mut c, &r);
        assert!(policy().admit(&mut c, &t, Some(&r)).is_ok());
    }

    #[test]
    fn test_sinks_under_authorized_profile_need_record_sinks() {
        let mut r = record();
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        c.safety.external_communication = ExternalCommunication::TestSinks;
        with_record(&mut c, &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert_eq!(
            codes(&errs),
            [("/safety/externalCommunication", "authorization_required")]
        );
        r.test_sinks.insert("email".into(), "sink://mail/example".into());
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        c.safety.external_communication = ExternalCommunication::TestSinks;
        with_record(&mut c, &r);
        assert!(admit(&mut c, Some(&r)).is_ok());
    }

    // ---- allowPrivateNetworks gate ----

    fn private_crawl(seed: &str, r: &AuthorizationRecord) -> CreateCrawl {
        let mut c = crawl(seed);
        c.safety.allow_private_networks = true;
        with_record(&mut c, r);
        c
    }

    #[test]
    fn private_networks_without_reference_is_rejected() {
        let mut c = crawl("http://10.20.0.5/");
        c.safety.allow_private_networks = true;
        let errs = admit(&mut c, None).unwrap_err();
        assert!(codes(&errs).contains(&("/safety/allowPrivateNetworks", "authorization_required")));
    }

    #[test]
    fn private_networks_need_authorized_networks_in_the_record() {
        let mut r = record();
        r.origins = vec!["http://10.20.0.5".into()];
        let mut c = private_crawl("http://10.20.0.5/", &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert!(codes(&errs).contains(&("/safety/allowPrivateNetworks", "authorization_required")));
        // and the private seed is still refused
        assert!(codes(&errs).contains(&("/seedUrl", "url_denied")));
    }

    #[test]
    fn private_networks_exempt_only_authorized_cidrs() {
        let mut r = record();
        r.origins = vec!["http://10.20.0.5".into()];
        r.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        let mut c = private_crawl("http://10.20.0.5/", &r);
        let a = admit(&mut c, Some(&r)).unwrap();
        assert!(a.egress.check_ip("10.20.9.9".parse().unwrap()).is_ok());
        assert!(a.egress.check_ip("10.21.9.9".parse().unwrap()).is_err());
        assert!(a.egress.check_ip("169.254.169.254".parse().unwrap()).is_err());
        assert!(a.egress.check_ip("192.168.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn private_authority_preserves_explicit_host_exclusions_at_admission() {
        let mut r = record();
        r.origins = vec!["http://10.20.0.5".into()];
        r.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        for excluded in ["private-ips", "10.20.0.0/16", "10.20.0.5", "^10\\.20\\.0\\.5$"] {
            let mut c = private_crawl("http://10.20.0.5/", &r);
            c.scope.exclude_hosts = vec![excluded.into()];
            let errors = admit(&mut c, Some(&r)).unwrap_err();
            assert!(
                codes(&errors).contains(&("/seedUrl", "url_denied")),
                "{excluded}: {errors:?}"
            );
        }
    }

    #[test]
    fn admitted_private_host_keeps_dns_and_path_denials() {
        let mut r = record();
        r.origins = vec!["https://staging.example.test".into()];
        r.excluded_paths = vec!["/billing/*".into()];
        r.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        let mut c = private_crawl("https://staging.example.test/", &r);
        c.scope.exclude_hosts = vec!["10.20.0.9".into()];
        let admitted = admit(&mut c, Some(&r)).unwrap();
        assert!(admitted
            .egress
            .check_all("staging.example.test", &["10.20.0.8".parse().unwrap()])
            .is_ok());
        assert_eq!(
            admitted
                .egress
                .check_all(
                    "staging.example.test",
                    &["10.20.0.8".parse().unwrap(), "10.20.0.9".parse().unwrap()],
                )
                .unwrap_err()
                .rule,
            crate::egress::DenyRule::HostExcluded
        );
        assert_eq!(
            admitted
                .egress
                .check_url(&Url::parse("https://staging.example.test/billing/x").unwrap())
                .unwrap_err()
                .rule,
            crate::egress::DenyRule::AuthorizationScope
        );
    }

    #[test]
    fn private_seed_outside_authorized_networks_is_url_denied() {
        let mut r = record();
        r.origins = vec!["http://10.99.0.5".into()];
        r.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        let mut c = private_crawl("http://10.99.0.5/", &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert_eq!(codes(&errs), [("/seedUrl", "url_denied")]);
    }

    #[test]
    fn metadata_seed_is_denied_even_when_authorized() {
        let mut r = record();
        r.origins = vec!["http://169.254.169.254".into()];
        r.authorized_networks = vec!["169.254.0.0/16".parse().unwrap()];
        let mut c = private_crawl("http://169.254.169.254/", &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert_eq!(codes(&errs), [("/seedUrl", "url_denied")]);
    }

    fn lists(allowlist: Option<&[&str]>, blocklist: &[&str]) -> SharedEgressLists {
        SharedEgressLists::new(
            EgressLists::new(
                allowlist.map(|a| a.iter().map(|n| n.parse().unwrap()).collect()),
                blocklist.iter().copied(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn deployment_allowlist_bounds_authorized_networks() {
        let mut r = record();
        r.origins = vec!["http://10.20.0.5".into()];
        r.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        let p = policy().with_egress_lists(lists(Some(&["10.0.0.0/8"]), &[]));
        let mut c = private_crawl("http://10.20.0.5/", &r);
        assert!(p.admit(&mut c, &TenantLimits::default(), Some(&r)).is_ok());
        let p = policy().with_egress_lists(lists(Some(&["192.168.0.0/16"]), &[]));
        let mut c = private_crawl("http://10.20.0.5/", &r);
        let errs = p.admit(&mut c, &TenantLimits::default(), Some(&r)).unwrap_err();
        assert!(
            errs.iter().any(|e| e.message.contains("deployment allowlist")),
            "{errs:?}"
        );
        // a set but empty allowlist admits no private network at all
        let p = policy().with_egress_lists(lists(Some(&[]), &[]));
        let mut c = private_crawl("http://10.20.0.5/", &r);
        assert!(p.admit(&mut c, &TenantLimits::default(), Some(&r)).is_err());
        // unset: no bound
        let p = policy().with_egress_lists(lists(None, &[]));
        let mut c = private_crawl("http://10.20.0.5/", &r);
        assert!(p.admit(&mut c, &TenantLimits::default(), Some(&r)).is_ok());
    }

    #[test]
    fn the_admitted_egress_policy_follows_list_reloads() {
        let mut r = record();
        r.origins = vec!["http://10.20.0.5".into()];
        r.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        let shared = lists(Some(&["10.0.0.0/8"]), &[]);
        let p = policy().with_egress_lists(shared.clone());
        let mut c = private_crawl("http://10.20.0.5/", &r);
        let a = p.admit(&mut c, &TenantLimits::default(), Some(&r)).unwrap();
        assert!(a.egress.check_ip("10.20.9.9".parse().unwrap()).is_ok());
        // the operator narrows the allowlist while the run is in flight
        shared.replace(
            EgressLists::new(
                Some(vec!["192.168.0.0/16".parse().unwrap()]),
                Vec::<String>::new(),
            )
            .unwrap(),
        );
        assert_eq!(
            a.egress.check_ip("10.20.9.9".parse().unwrap()).unwrap_err().rule,
            crate::egress::DenyRule::Private
        );
    }

    #[test]
    fn test_environment_reaches_only_the_networks_the_deployment_allowlist_names() {
        let p = policy().with_egress_lists(lists(Some(&["127.0.0.0/8", "10.20.0.0/16"]), &[]));
        let mut c = crawl("http://127.0.0.1:8080/");
        c.safety.profile = SafetyProfile::TestEnvironment;
        let a = p.admit(&mut c, &TenantLimits::default(), None).unwrap();
        assert!(a.egress.check_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(a.egress.check_ip("10.20.1.1".parse().unwrap()).is_ok());
        assert!(
            a.egress.check_ip("10.21.1.1".parse().unwrap()).is_err(),
            "not named"
        );
        assert!(
            a.egress.check_ip("169.254.169.254".parse().unwrap()).is_err(),
            "never exemptable"
        );
        // read_only gets no such exemption
        let mut c = crawl("http://127.0.0.1:8080/");
        let errs = p.admit(&mut c, &TenantLimits::default(), None).unwrap_err();
        assert_eq!(codes(&errs), [("/seedUrl", "url_denied")]);
        // and without a deployment allowlist test_environment is as strict as ever
        let mut c = crawl("http://127.0.0.1:8080/");
        c.safety.profile = SafetyProfile::TestEnvironment;
        assert!(admit(&mut c, None).is_err());
    }

    #[test]
    fn operator_blocklist_refuses_seed_replica_and_webhook_hosts() {
        let p = policy().with_egress_lists(lists(None, &["takedown.test", "203.0.113.0/24"]));
        let mut c = crawl("https://www.takedown.test/");
        let errs = p.admit(&mut c, &TenantLimits::default(), None).unwrap_err();
        assert_eq!(codes(&errs), [("/seedUrl", "url_denied")]);
        assert!(errs[0].message.contains("operator_blocklist"), "{errs:?}");
        let mut c = crawl("https://example.com/");
        c.output.webhook = Some(crawlx_core::config::Webhook {
            url: Url::parse("https://hooks.takedown.test/x").unwrap(),
            events: Vec::new(),
        });
        let errs = p.admit(&mut c, &TenantLimits::default(), None).unwrap_err();
        assert_eq!(codes(&errs), [("/output/webhook/url", "url_denied")]);
        let mut c = crawl("https://example.com/");
        assert!(p.admit(&mut c, &TenantLimits::default(), None).is_ok());
    }

    // ---- the record bounds the run ----

    #[test]
    fn the_egress_policy_carries_the_records_target() {
        let r = record();
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        with_record(&mut c, &r);
        let a = admit(&mut c, Some(&r)).unwrap();
        let u = |s: &str| Url::parse(s).unwrap();
        assert!(a.egress.check_url(&u("https://staging.example.test/app")).is_ok());
        for out in [
            "https://prod.example.test/",
            "https://staging.example.test/billing/x",
            "http://staging.example.test/",
        ] {
            let e = a.egress.check_url(&u(out)).unwrap_err();
            assert_eq!(e.rule, crate::egress::DenyRule::AuthorizationScope, "{out}");
        }
    }

    #[test]
    fn a_referenced_record_must_cover_the_seed_even_when_no_gate_needs_it() {
        let r = record();
        let mut c = crawl("https://prod.example.test/");
        with_record(&mut c, &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert_eq!(
            codes(&errs),
            [("/safety/authorizationRecordRef", "authorization_required")]
        );
        assert!(errs[0].message.contains("not covered"));
    }

    #[test]
    fn profile_above_the_records_cap_is_refused() {
        let mut r = record();
        r.profile_cap = SafetyProfile::TestEnvironment;
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        with_record(&mut c, &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert_eq!(codes(&errs), [("/safety/profile", "authorization_required")]);
        assert!(errs[0].message.contains("profile cap"), "{errs:?}");
        let mut c = staging();
        c.safety.profile = SafetyProfile::TestEnvironment;
        with_record(&mut c, &r);
        assert!(admit(&mut c, Some(&r)).is_ok());
    }

    #[test]
    fn an_incomplete_record_is_refused() {
        let mut r = record();
        r.emergency_contact.clear();
        let mut c = staging();
        with_record(&mut c, &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert!(errs[0].message.contains("emergencyContact"), "{errs:?}");
    }

    #[test]
    fn the_api_policy_refuses_a_record_whose_ownership_was_never_verified() {
        let mut r = record();
        let strict = || policy().require_verified_ownership();
        let mut c = staging();
        with_record(&mut c, &r);
        let errs = strict()
            .admit(&mut c, &TenantLimits::default(), Some(&r))
            .unwrap_err();
        assert!(errs[0].message.contains("not verified"), "{errs:?}");
        r.verified_at = Some(ts(21));
        let mut c = staging();
        with_record(&mut c, &r);
        assert!(strict().admit(&mut c, &TenantLimits::default(), Some(&r)).is_ok());
        // the local policy does not ask for it
        r.verified_at = None;
        let mut c = staging();
        with_record(&mut c, &r);
        assert!(admit(&mut c, Some(&r)).is_ok());
    }

    // ---- respectRobotsTxt = false gate ----

    #[test]
    fn robots_off_without_reference_is_rejected() {
        let mut c = staging();
        c.safety.respect_robots_txt = false;
        let errs = admit(&mut c, None).unwrap_err();
        assert_eq!(
            codes(&errs),
            [("/safety/respectRobotsTxt", "authorization_required")]
        );
    }

    #[test]
    fn robots_off_needs_acknowledgement() {
        let mut r = record();
        let mut c = staging();
        c.safety.respect_robots_txt = false;
        with_record(&mut c, &r);
        let errs = admit(&mut c, Some(&r)).unwrap_err();
        assert_eq!(
            codes(&errs),
            [("/safety/respectRobotsTxt", "authorization_required")]
        );
        r.robots_override_acknowledged = true;
        let mut c = staging();
        c.safety.respect_robots_txt = false;
        with_record(&mut c, &r);
        assert!(admit(&mut c, Some(&r)).is_ok());
    }

    // ---- stealth gate ----

    #[test]
    fn stealth_under_read_only_is_profile_conflict() {
        let mut c = crawl("https://example.com/");
        c.dynamic.launch_profile = LaunchProfile::Stealth;
        let errs = admit(&mut c, None).unwrap_err();
        assert_eq!(codes(&errs), [("/dynamic/launchProfile", "profile_conflict")]);
    }

    #[test]
    fn stealth_under_test_environment_is_admitted() {
        let mut c = crawl("https://example.com/");
        c.dynamic.launch_profile = LaunchProfile::Stealth;
        c.safety.profile = SafetyProfile::TestEnvironment;
        admit(&mut c, None).unwrap();
        assert_eq!(c.dynamic.launch_profile, LaunchProfile::Stealth);
    }

    #[test]
    fn stealth_under_authorized_profile_is_admitted_with_record() {
        let r = record();
        let mut c = staging();
        c.dynamic.launch_profile = LaunchProfile::Stealth;
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        with_record(&mut c, &r);
        assert!(admit(&mut c, Some(&r)).is_ok());
    }

    #[test]
    fn read_only_profile_cannot_carry_writes() {
        let mut c = crawl("https://example.com/");
        c.safety.destructive_actions = DestructiveActions::Approval;
        let errs = admit(&mut c, None).unwrap_err();
        assert_eq!(codes(&errs), [("/safety/destructiveActions", "profile_conflict")]);
    }

    // ---- URL pre-resolution checks ----

    #[test]
    fn ssrf_seeds_are_url_denied() {
        for seed in [
            "http://169.254.169.254/latest/meta-data",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
            "http://2130706433/",
            "http://metadata.google.internal/", // detection-data
            "http://10.0.0.5/",
            "ftp://example.com/",
        ] {
            let mut c = crawl(seed);
            let errs = admit(&mut c, None).unwrap_err();
            assert!(
                errs.iter()
                    .any(|e| e.path == "/seedUrl" && e.code == "url_denied"),
                "{seed}: {errs:?}"
            );
        }
    }

    #[test]
    fn seed_port_is_allowed_and_carried_in_the_egress_policy() {
        let mut c = crawl("https://example.com:8443/");
        let a = admit(&mut c, None).unwrap();
        assert!(a.egress.check_port(8443).is_ok());
        assert!(a.egress.check_port(9443).is_err());
    }

    #[test]
    fn webhook_and_replica_urls_are_checked() {
        let mut c = crawl("https://example.com/");
        c.output.webhook = Some(crawlx_core::config::Webhook {
            url: Url::parse("http://10.0.0.9/hook").unwrap(),
            events: Vec::new(),
        });
        c.roles = vec![Role {
            name: "a".into(),
            credential_ref: None,
            login_plan: None,
            replica_base_url: Some(Url::parse("http://192.168.1.2/").unwrap()),
        }];
        c.target_isolation = crawlx_core::config::TargetIsolation::PerRoleReplica;
        let errs = admit(&mut c, None).unwrap_err();
        let got = codes(&errs);
        assert!(got.contains(&("/output/webhook/url", "url_denied")), "{got:?}");
        assert!(
            got.contains(&("/roles/0/replicaBaseUrl", "url_denied")),
            "{got:?}"
        );
    }

    #[test]
    fn blocklist_denies_host_and_subdomains() {
        let t = TenantLimits {
            blocked_hosts: vec!["blocked.test".into()],
            ..TenantLimits::default()
        };
        for seed in ["https://blocked.test/", "https://www.blocked.test/x"] {
            let mut c = crawl(seed);
            let errs = policy().admit(&mut c, &t, None).unwrap_err();
            assert_eq!(codes(&errs), [("/seedUrl", "url_denied")], "{seed}");
        }
        let mut c = crawl("https://notblocked.test/");
        assert!(policy().admit(&mut c, &t, None).is_ok());
    }

    #[test]
    fn record_rate_limits_only_tighten_politeness() {
        let mut r = record();
        r.rate_limits = Some(crate::authorization::RecordRateLimits {
            max_in_flight_per_origin: 2,
            min_delay_ms: 400,
        });
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        c.politeness.delay_ms = 100;
        c.politeness.max_in_flight_per_origin = 6;
        with_record(&mut c, &r);
        admit(&mut c, Some(&r)).unwrap();
        assert_eq!(
            (c.politeness.delay_ms, c.politeness.max_in_flight_per_origin),
            (400, 2)
        );
        let mut c = staging();
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        c.politeness.delay_ms = 900;
        c.politeness.max_in_flight_per_origin = 1;
        with_record(&mut c, &r);
        admit(&mut c, Some(&r)).unwrap();
        assert_eq!(
            (c.politeness.delay_ms, c.politeness.max_in_flight_per_origin),
            (900, 1)
        );
    }

    #[test]
    fn multiple_violations_are_all_reported() {
        let mut c = crawl("http://127.0.0.1/");
        c.safety.respect_robots_txt = false;
        c.safety.allow_private_networks = true;
        c.safety.profile = SafetyProfile::AuthorizedSecurityTest;
        c.dynamic.launch_profile = LaunchProfile::Stealth;
        let errs = admit(&mut c, None).unwrap_err();
        let got = codes(&errs);
        for want in [
            ("/safety/profile", "authorization_required"),
            ("/safety/allowPrivateNetworks", "authorization_required"),
            ("/safety/respectRobotsTxt", "authorization_required"),
            ("/seedUrl", "url_denied"),
        ] {
            assert!(got.contains(&want), "{want:?} missing in {got:?}");
        }
        assert!(!got.contains(&("/dynamic/launchProfile", "profile_conflict")));
    }
}

#[cfg(test)]
mod credential_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crawlx_core::config::Role;
    use crawlx_core::secret::CredentialRef;

    #[test]
    fn every_role_needs_its_exact_declared_account_and_selected_record() {
        let mut crawl = CreateCrawl::new("https://app.example.test".parse().unwrap());
        let mut record = crate::authorization::tests::record();
        crawl.roles = vec![Role {
            name: "member".to_owned(),
            credential_ref: Some(CredentialRef("env://MEMBER".to_owned())),
            login_plan: None,
            replica_base_url: None,
        }];
        assert_eq!(AdmissionPolicy::check_role_credentials(&crawl, None).len(), 1);
        crawl.safety.authorization_record_ref = Some(record.id);
        assert_eq!(
            AdmissionPolicy::check_role_credentials(&crawl, Some(&record)).len(),
            1
        );
        record.test_accounts = vec![crate::TestAccount {
            role: "member".to_owned(),
            credential_ref: "env://MEMBER".to_owned(),
        }];
        assert!(AdmissionPolicy::check_role_credentials(&crawl, Some(&record)).is_empty());
        crawl.roles[0].name = "admin".to_owned();
        assert_eq!(
            AdmissionPolicy::check_role_credentials(&crawl, Some(&record)).len(),
            1
        );
        crawl.roles[0].name = "member".to_owned();
        crawl.roles[0].credential_ref = Some(CredentialRef("env://OTHER".to_owned()));
        assert_eq!(
            AdmissionPolicy::check_role_credentials(&crawl, Some(&record)).len(),
            1
        );
        crawl.roles[0].credential_ref = None;
        assert!(AdmissionPolicy::check_role_credentials(&crawl, None).is_empty());
    }
}
