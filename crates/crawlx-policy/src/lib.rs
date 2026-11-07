//! crawlx-policy: scope, robots (RFC 9309), SSRF/egress and admission policy.
//!
//! Pure logic, no sockets. Modules:
//!
//! * [`scope`]: `ScopePolicy::decide` over `crawlx-url`'s path filter plus host scope
//!   (`fqdn|rdn|dn|none`), URL patterns, host exclusions, extension filter and depth.
//! * [`known_files`]: robots `Allow`/`Sitemap` seeding.
//! * [`robots`]: RFC 9309 parser, matcher and the per-origin `RobotsCache`.
//! * [`egress`]: IANA special-purpose deny tables and `EgressPolicy`.
//! * [`admission`]: `AdmissionPolicy::admit`, tenant clamping and authorization gates.
//! * [`authorization`]: the `AuthorizationRecord` and its `RecordScope`.
//! * [`attestation`]: operator signatures over a record (`OperatorKeys`).
//! * [`egress_lists`]: the deployment CIDR allowlist and the operator host blocklist (reloadable).
//! * [`limits`]: run `Budget` tracking.
//! * [`testkit`]: a complete sample `AuthorizationRecord` for tests and harnesses.
//! * [`cdn`]: the bundled CDN host list behind `scope.excludeHosts: ["cdn"]`.

pub mod admission;
pub mod attestation;
pub mod authorization;
pub mod cdn;
pub mod egress;
pub mod egress_lists;
mod error;
pub mod fixture_evaluation;
pub mod known_files;
pub mod limits;
pub mod robots;
pub mod scope;
pub mod testkit;

pub use admission::{AdmissionError, AdmissionPolicy, Admitted, AuthorizationBinding, Clamp, TenantLimits};
pub use authorization::{
    AuthorizationRecord, Authorizer, AuthzFailure, Evidence, LegalReferences, OwnershipProof,
    RecordRateLimits, RecordScope, TestAccount,
};
pub use egress::{DenyRule, EgressDenied, EgressPolicy};
pub use egress_lists::{EgressLists, ListError, SharedEgressLists};
pub use error::PolicyError;
pub use limits::{Budget, BudgetExhausted, BudgetKind, Remaining};
pub use robots::{
    DisallowedBy, FetchStatus, RobotsCache, RobotsConfig, RobotsRule, RobotsTxt, RobotsVerdict,
};
pub use scope::{DenialReason, ExcludeHosts, HostScopeRule, ScopePolicy, ScopeVerdict, UrlPatterns};
