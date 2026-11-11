//! Native acquisition policy and bounded, body-free evidence.
//!
//! Runtime response bytes and volatile retention capabilities never enter this DTO.

use crate::hash::Digest;
use crate::observation::BrowserBuildInfo;
use crate::{ArtifactRef, CrawlRunId, TenantId};
use serde::{Deserialize, Serialize};
use url::Url;

/// Maximum public metadata size, independent of response body limits.
pub const MAX_METADATA_BYTES: usize = 64 * 1024;
/// At most this many workers appear in a public deployment snapshot; one extra row signals truncation.
pub const WORKER_CAPABILITY_SNAPSHOT_LIMIT: usize = 256;
/// Native refresh parser/admission/privacy provenance, independent of requested policy schema.
pub const META_REFRESH_RUNTIME_REVISION: u8 = 2;

/// Invalid native acquisition policy.
#[derive(Debug, thiserror::Error)]
#[error("invalid acquisition policy: {0}")]
pub struct AcquisitionPolicyError(pub &'static str);

/// Core-only declaration of an optional HEAD request before a static GET.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct HeadPreflight {
    /// Declared response length ceiling, 1..=64 MiB; absence uses the GET body limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_content_length: Option<u64>,
    /// Accepted MIME types, at most 16; empty accepts any MIME type.
    pub content_types: Vec<String>,
}

impl HeadPreflight {
    /// Check finite length and MIME allow-list bounds.
    ///
    /// # Errors
    /// Rejects a zero or excessive length ceiling, or malformed or excessive MIME types.
    pub fn validate(&self) -> Result<(), AcquisitionPolicyError> {
        if self
            .max_content_length
            .is_some_and(|limit| !(1..=67_108_864).contains(&limit))
            || self.content_types.len() > 16
            || self.content_types.iter().any(|mime| !valid_declared_mime(mime))
        {
            return Err(AcquisitionPolicyError("fetch preflight bounds or content types"));
        }
        Ok(())
    }
}

/// Explicit HTTP status overrides, kept sorted for deterministic serialization.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct HttpErrorStatuses {
    /// Statuses delivered without ordinary retry handling.
    pub allow: std::collections::BTreeSet<u16>,
    /// Statuses refused before extraction.
    pub deny: std::collections::BTreeSet<u16>,
}

impl HttpErrorStatuses {
    /// Check the finite HTTP status domain and disjoint allow/deny sets.
    ///
    /// # Errors
    /// Rejects statuses outside 100..=599 or a status present in both sets.
    pub fn validate(&self) -> Result<(), AcquisitionPolicyError> {
        if self
            .allow
            .iter()
            .chain(&self.deny)
            .any(|status| !(100..=599).contains(status))
            || !self.allow.is_disjoint(&self.deny)
        {
            return Err(AcquisitionPolicyError(
                "fetch declaration status bounds or conflict",
            ));
        }
        Ok(())
    }
}

/// Core-only response overrides; encoding support is checked by the fetch plane before traffic.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ResponseDeclaration {
    /// Effective MIME type, at most 100 ASCII bytes and without parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Text encoding label, 1..=128 printable ASCII bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charset: Option<String>,
    /// Explicit status allow/deny sets; empty sets preserve ordinary handling.
    pub statuses: HttpErrorStatuses,
}

impl ResponseDeclaration {
    /// Check bounded MIME, encoding-label syntax and HTTP status overrides.
    ///
    /// # Errors
    /// Rejects malformed MIME types, empty or excessive encoding labels, control bytes or invalid statuses.
    pub fn validate(&self) -> Result<(), AcquisitionPolicyError> {
        if self
            .content_type
            .as_deref()
            .is_some_and(|mime| !valid_declared_mime(mime))
        {
            return Err(AcquisitionPolicyError("fetch declaration content type"));
        }
        if self.charset.as_deref().is_some_and(|label| {
            label.trim().is_empty()
                || label.len() > 128
                || !label.bytes().all(|byte| byte.is_ascii_graphic() || byte == b' ')
        }) {
            return Err(AcquisitionPolicyError("fetch declaration charset bounds"));
        }
        self.statuses.validate()
    }
}

/// Action when the response exceeds a configured body limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OversizePolicy {
    /// Return the bounded prefix and mark the response truncated.
    #[default]
    Truncate,
    /// Refuse the response rather than extracting a partial body.
    Refuse,
}

fn valid_declared_mime(mime: &str) -> bool {
    let token = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'!' | b'#' | b'$' | b'&' | b'-' | b'^' | b'_' | b'.' | b'+')
            })
    };
    mime.len() <= 100
        && mime
            .split_once('/')
            .is_some_and(|(kind, subtype)| token(kind) && token(subtype))
}

/// Explicit opt-in policy. Absence preserves existing facade behavior.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AcquisitionPolicyV1 {
    /// Contract version; only one is supported.
    pub schema_version: u8,
    /// Bounded operator profile label, not executable configuration.
    pub profile_id: String,
    /// Ordered registered backends; no endpoints or import paths.
    pub backend_ids: Vec<String>,
    /// Explicit subset allowed for fallback.
    pub fallback_backend_ids: Vec<String>,
    /// Total dispatches, including failed transport dispatches.
    pub max_attempts: u8,
    /// Whole monotonic acquisition deadline.
    pub max_elapsed_ms: u32,
    /// Total decoded response allowance across attempts.
    pub max_decoded_bytes: u64,
    /// Total network requests, including redirects.
    pub max_network_requests: u32,
    /// Independent expected-content checks.
    pub validation: ValidationPolicyV1,
    /// Explicit retry classes; authentication and policy refusal are never retry classes.
    pub retry_on: Vec<RetryClassV1>,
    /// Optional one-transition native static HTML continuation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta_refresh: Option<MetaRefreshPolicyV1>,
}

impl Default for AcquisitionPolicyV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            profile_id: "native-v1".to_owned(),
            backend_ids: vec!["native_http".to_owned()],
            fallback_backend_ids: Vec::new(),
            max_attempts: 2,
            max_elapsed_ms: 60_000,
            max_decoded_bytes: 16 * 1024 * 1024,
            max_network_requests: 64,
            validation: ValidationPolicyV1::default(),
            retry_on: vec![RetryClassV1::Transport],
            meta_refresh: None,
        }
    }
}

impl AcquisitionPolicyV1 {
    /// Validate fixed bounds and registration names before dispatch.
    ///
    /// # Errors
    /// Returns a named bound/version/backend violation. Selector syntax is checked by extraction admission.
    pub fn validate(&self) -> Result<(), AcquisitionPolicyError> {
        if self.schema_version != 1 {
            return Err(AcquisitionPolicyError("unsupported schema version"));
        }
        if self.profile_id.is_empty() || self.profile_id.len() > 128 {
            return Err(AcquisitionPolicyError("profile id length"));
        }
        if self.backend_ids.is_empty() || self.backend_ids.len() > 4 || self.fallback_backend_ids.len() > 4 {
            return Err(AcquisitionPolicyError("backend count"));
        }
        if self.backend_ids.iter().any(|id| {
            !matches!(
                id.as_str(),
                "native_http" | "native_browser" | "acquisition_service"
            )
        }) {
            return Err(AcquisitionPolicyError("backend unavailable"));
        }
        if self
            .fallback_backend_ids
            .iter()
            .any(|id| !self.backend_ids.contains(id))
        {
            return Err(AcquisitionPolicyError("fallback backend not permitted"));
        }
        if !(1..=8).contains(&self.max_attempts)
            || !(1..=300_000).contains(&self.max_elapsed_ms)
            || !(1..=67_108_864).contains(&self.max_decoded_bytes)
            || !(1..=512).contains(&self.max_network_requests)
            || self.retry_on.len() > 5
        {
            return Err(AcquisitionPolicyError(
                "attempt, deadline, byte or request allowance",
            ));
        }
        if let Some(refresh) = &self.meta_refresh {
            refresh.validate()?;
            if self.backend_ids != ["native_http"] || !self.fallback_backend_ids.is_empty() {
                return Err(AcquisitionPolicyError("meta refresh requires native static HTTP"));
            }
        }
        self.validation.validate()
    }
}

/// Independently versioned, bounded, immediate meta-refresh policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct MetaRefreshPolicyV1 {
    /// Supported policy and parser contract.
    pub schema_version: u8,
    /// Maximum HTML input scanned; an oversized response is not partially parsed.
    pub max_parser_bytes: u32,
}
impl Default for MetaRefreshPolicyV1 {
    fn default() -> Self {
        Self {
            schema_version: 1,
            max_parser_bytes: 1_048_576,
        }
    }
}
impl MetaRefreshPolicyV1 {
    /// Check parser version and finite input ceiling.
    ///
    /// # Errors
    /// Rejects unsupported versions or input ceilings outside 1..=16 MiB.
    pub fn validate(&self) -> Result<(), AcquisitionPolicyError> {
        if self.schema_version != 1 || !(1..=16_777_216).contains(&self.max_parser_bytes) {
            return Err(AcquisitionPolicyError("meta refresh parser version or bound"));
        }
        Ok(())
    }
}

/// Body-free, privacy-projected meta transition, separate from ordinary HTTP redirects.
/// URLs are public evidence, never dispatch or replay authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MetaRefreshEvidenceV1 {
    /// Parser contract, including configured scan bound.
    pub policy: MetaRefreshPolicyV1,
    /// Observed initial representation URL, after preceding HTTP redirects.
    pub initial_url: Url,
    /// Observed initial successful response status.
    pub initial_status: u16,
    /// Resolved target selected by the first matching tag with usable content.
    pub target: Url,
    /// Actual selected final target response, absent on target failure.
    pub selected_url: Option<Url>,
    /// Observed selected target status, absent on transport or admission failure.
    pub selected_status: Option<u16>,
    /// Ordinary HTTP redirects, kept separately from the meta transition.
    pub http_redirects: Vec<AcquisitionRedirectV1>,
}
impl MetaRefreshEvidenceV1 {
    /// Record the selected transition before attempting its destination.
    #[must_use]
    pub fn new(policy: MetaRefreshPolicyV1, initial_url: Url, initial_status: u16, target: Url) -> Self {
        Self {
            policy,
            initial_url,
            initial_status,
            target,
            selected_url: None,
            selected_status: None,
            http_redirects: Vec::new(),
        }
    }
}

/// Safe retry classes, independent of target status truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RetryClassV1 {
    /// Safe GET transport failure.
    Transport,
    /// Target server failure.
    Target5xx,
    /// Shared origin cooldown, never identity rotation.
    RateLimit,
    /// Corroborated challenge.
    Challenge,
    /// Explicit expected-content mismatch.
    ContentMismatch,
}

/// Whether expected-content mismatch is report-only or terminal.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContentMismatchActionV1 {
    /// Keep compatibility error-page documents.
    #[default]
    Report,
    /// Refuse rejected/indeterminate content.
    Fail,
}

/// Bounded deterministic validation rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ValidationPolicyV1 {
    /// Native classifier version.
    pub rule_set_version: u8,
    /// Exact MIME types, ignoring parameters and ASCII case.
    pub expected_content_types: Vec<String>,
    /// Required CSS selectors, compiled before execution.
    pub required_selectors: Vec<String>,
    /// Minimum visible text bytes.
    pub minimum_text_bytes: u32,
    /// Report or fail rejected content.
    pub on_content_mismatch: ContentMismatchActionV1,
}
impl Default for ValidationPolicyV1 {
    fn default() -> Self {
        Self {
            rule_set_version: 1,
            expected_content_types: Vec::new(),
            required_selectors: Vec::new(),
            minimum_text_bytes: 0,
            on_content_mismatch: ContentMismatchActionV1::Report,
        }
    }
}
impl ValidationPolicyV1 {
    /// Check version and bounded rule inputs.
    ///
    /// # Errors
    /// Returns unsupported-version or rule-bound violations.
    pub fn validate(&self) -> Result<(), AcquisitionPolicyError> {
        if self.rule_set_version != 1 {
            return Err(AcquisitionPolicyError("unsupported rule set version"));
        }
        if self.expected_content_types.len() > 16
            || self.required_selectors.len() > 16
            || self
                .expected_content_types
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || !s.contains('/'))
            || self
                .required_selectors
                .iter()
                .any(|s| s.is_empty() || s.len() > 2048)
            || self.minimum_text_bytes > 67_108_864
        {
            return Err(AcquisitionPolicyError("validation rule bounds"));
        }
        Ok(())
    }
}

/// Body-free input facts shared with the already parsed extraction DOM.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ValidationContextV1 {
    /// Requested content rules.
    pub policy: ValidationPolicyV1,
    /// Observed target status, not gateway status.
    pub target_status: Option<u16>,
    /// A target response was received.
    pub transport_succeeded: bool,
    /// Body stopped at a byte cap or otherwise incomplete.
    pub truncated: bool,
    /// HEAD responses need no document body.
    pub method_head: bool,
    /// An owned matching cached body is available for 304.
    pub cached_body_available: bool,
    /// Existing policy denied acquisition.
    pub policy_blocked: bool,
    /// Cancellation won before completion.
    pub cancelled: bool,
}

/// Independent acquisition classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ValidationCategoryV1 {
    /// Accepted document or legitimate bodyless response.
    Valid,
    /// Authoritative header or corroborated interstitial.
    Challenge,
    /// Target 429.
    RateLimited,
    /// Target 401/407.
    AuthRequired,
    /// Explicit expected-content check failed.
    ContentMismatch,
    /// Unexpected empty body.
    Empty,
    /// Unsupported representation or MIME.
    UnsupportedContent,
    /// Other target error status.
    TargetError,
    /// Transport failed before a response.
    TransportError,
    /// Existing policy denied operation.
    PolicyBlocked,
    /// Evidence insufficient, including incomplete bodies.
    Indeterminate,
}

/// Stable independent outcome; extraction success is not implied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ValidationOutcomeV1 {
    /// Classifier version.
    pub rule_set_version: u8,
    /// Highest-priority classification.
    pub category: ValidationCategoryV1,
    /// Stable bounded signal identifiers, never page text or selectors.
    pub signals: Vec<String>,
    /// Retry class, if safe and explicitly enabled by caller policy.
    pub retry_disposition: Option<RetryClassV1>,
    /// Proven acceptance, independently of transport or extraction.
    pub content_accepted: bool,
}
impl ValidationOutcomeV1 {
    /// Unknown legacy evidence is not valid content.
    #[must_use]
    pub fn indeterminate() -> Self {
        Self {
            rule_set_version: 1,
            category: ValidationCategoryV1::Indeterminate,
            signals: Vec::new(),
            retry_disposition: None,
            content_accepted: false,
        }
    }
}

/// Where final URL evidence came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UrlEvidenceV1 {
    /// Observed by native producer.
    Observed,
    /// Declared by an adapter without independent observation.
    Declared,
    /// No evidence; requested URL is not substituted as fact.
    Unavailable,
}
/// Response representation, never conflating wire bytes and DOM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RepresentationV1 {
    /// Decoded native HTTP response bytes.
    WireResponse,
    /// Previously retained decoded response materialized after a validator-compatible 304.
    RetainedResponse,
    /// Browser serialized DOM.
    RenderedDom,
    /// Caller-supplied content without HTTP evidence.
    SuppliedHtml,
    /// Parsed non-HTML document.
    ParsedDocument,
}
/// One bounded redirect evidence item.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AcquisitionRedirectV1 {
    /// Redacted source URL.
    pub url: Url,
    /// Observed redirect status, if available.
    pub status: Option<u16>,
}
impl AcquisitionRedirectV1 {
    /// Native redirect observation.
    #[must_use]
    pub fn observed(url: Url, status: Option<u16>) -> Self {
        Self { url, status }
    }
}

/// Actual native backend facts. Unknown build remains absent, never a configured claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BackendCapabilitiesV1 {
    /// Operator-registered backend identifier.
    pub backend_id: String,
    /// Implementation package.
    pub implementation: String,
    /// Actual package version.
    pub version: String,
    /// Actual executable/image digest when an authenticated build receipt exists.
    pub build_digest: Option<Digest>,
    /// Build observed by BrowserBackend, never a requested version label.
    pub browser: Option<BrowserBuildInfo>,
    /// Availability at this execution boundary.
    pub available: bool,
    /// Stable explicit limitations.
    pub limitations: Vec<String>,
    /// Installed coherent HTTP profile; absent for ordinary HTTP or unattested service claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_profile: Option<Digest>,
}
impl BackendCapabilitiesV1 {
    /// Package-backed HTTP capability; no certificate or HTTP/3 claim.
    #[must_use]
    pub fn native_http(implementation: &str, version: &str) -> Self {
        Self {
            backend_id: "native_http".to_owned(),
            implementation: implementation.to_owned(),
            version: version.to_owned(),
            build_digest: None,
            browser: None,
            available: true,
            limitations: vec![
                "certificate_evidence_unavailable".to_owned(),
                "build_digest_unavailable".to_owned(),
            ],
            identity_profile: None,
        }
    }
    /// Capability from a real browser backend's observed build.
    #[must_use]
    pub fn native_browser(build: BrowserBuildInfo) -> Self {
        Self {
            backend_id: "native_browser".to_owned(),
            implementation: "crawlx-browser-cdp".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build_digest: None,
            limitations: vec![
                "certificate_evidence_unavailable".to_owned(),
                "wire_body_not_dom".to_owned(),
                "build_digest_unavailable".to_owned(),
            ],
            browser: Some(build),
            identity_profile: None,
            available: true,
        }
    }
    /// Browser unavailable until a real worker observes its backend build.
    #[must_use]
    pub fn native_browser_unavailable(reason: &str) -> Self {
        Self {
            backend_id: "native_browser".to_owned(),
            implementation: "crawlx-browser-cdp".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build_digest: None,
            browser: None,
            available: false,
            limitations: vec![reason.to_owned(), "build_digest_unavailable".to_owned()],
            identity_profile: None,
        }
    }
    /// Check bounded structural capability facts before publishing or accepting a heartbeat.
    ///
    /// # Errors
    /// Rejects unknown native IDs, oversized evidence, or an available browser without observed build facts.
    pub fn validate_evidence(&self) -> Result<(), AcquisitionPolicyError> {
        if let Some(digest) = self.identity_profile {
            let installed = crate::identity_profile::IdentityProfileV1::pinned_chromium();
            let expected = installed
                .digest()
                .map_err(|_| AcquisitionPolicyError("identity profile encoding"))?;
            if self.backend_id != "native_http"
                || digest != expected
                || self.implementation != installed.implementation
            {
                return Err(AcquisitionPolicyError("identity capability mismatch"));
            }
        }
        if !matches!(
            self.backend_id.as_str(),
            "native_http" | "native_browser" | "acquisition_service"
        ) || self.implementation.is_empty()
            || self.implementation.len() > 128
            || self.version.len() > 128
            || self.limitations.len() > 16
            || self.limitations.iter().any(|value| value.len() > 128)
            || (self.backend_id == "native_browser" && self.available && self.browser.is_none())
            || (self.backend_id == "acquisition_service" && self.available && self.build_digest.is_none())
            || self.browser.as_ref().is_some_and(|build| {
                build.chromium_version.len() > 256
                    || build.cdp_revision.len() > 256
                    || build.user_agent.len() > 1024
            })
        {
            return Err(AcquisitionPolicyError("invalid capability evidence"));
        }
        Ok(())
    }
}

/// Fresh worker-reported structural capabilities, from the existing worker registry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct WorkerCapabilitiesV1 {
    /// Manifest version, independently of requested acquisition policy.
    pub schema_version: u8,
    /// Existing worker registry key.
    pub worker: crate::WorkerId,
    /// Registry-authority heartbeat time, not client-provided time.
    pub heartbeat_at: crate::Timestamp,
    /// Backends observed or explicitly unavailable on this same worker.
    pub backends: Vec<BackendCapabilitiesV1>,
    /// Operator-observed data destinations and pinned language assets on this same worker.
    #[serde(default)]
    pub data: crate::data_capabilities::WorkerDataCapabilitiesV1,
}
impl WorkerCapabilitiesV1 {
    /// Construct a bounded registry observation.
    ///
    /// # Errors
    /// Rejects more than four backends or invalid/unobserved evidence.
    pub fn new(
        worker: crate::WorkerId,
        heartbeat_at: crate::Timestamp,
        backends: Vec<BackendCapabilitiesV1>,
    ) -> Result<Self, AcquisitionPolicyError> {
        if backends.len() > 4 {
            return Err(AcquisitionPolicyError("worker capability count"));
        }
        for backend in &backends {
            backend.validate_evidence()?;
        }
        Ok(Self {
            schema_version: 1,
            worker,
            heartbeat_at,
            backends,
            data: Default::default(),
        })
    }
    /// Every required backend must be available on this single fresh worker.
    #[must_use]
    pub fn supports(&self, required: &[String]) -> bool {
        self.schema_version == 1
            && required.iter().all(|id| {
                self.backends
                    .iter()
                    .any(|backend| backend.available && backend.backend_id == *id)
            })
    }
}
/// Consumption settled by one fenced lease. Reservations may exceed observed decoded bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AcquisitionUsageV1 {
    /// Reserved navigation/helper dispatches, including failed dispatches.
    pub attempts_reserved: u8,
    /// Reserved network requests, including redirects and uncertain sends.
    pub network_requests_reserved: u32,
    /// Decoded-byte allowance consumed, conservatively including uncertain body reads.
    pub decoded_bytes_reserved: u64,
    /// Decoded bytes actually observed in completed producer responses.
    pub decoded_bytes_observed: u64,
    /// A failed transport omitted exact request or byte evidence.
    pub evidence_incomplete: bool,
}
impl AcquisitionUsageV1 {
    /// Construct body-free reservation/observation facts.
    #[must_use]
    pub fn new(
        attempts_reserved: u8,
        network_requests_reserved: u32,
        decoded_bytes_reserved: u64,
        decoded_bytes_observed: u64,
        evidence_incomplete: bool,
    ) -> Self {
        Self {
            attempts_reserved,
            network_requests_reserved,
            decoded_bytes_reserved,
            decoded_bytes_observed,
            evidence_incomplete,
        }
    }
}

/// Remaining parent allowance escrowed atomically by the existing durable frontier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AcquisitionAllowanceV1 {
    /// Remaining dispatches before this lease reserves its escrow.
    pub remaining_attempts: u8,
    /// Remaining network requests before this lease reserves its escrow.
    pub remaining_network_requests: u32,
    /// Remaining decoded bytes before this lease reserves its escrow.
    pub remaining_decoded_bytes: u64,
    /// Time left until the immutable first-dispatch deadline, measured by registry authority.
    pub remaining_elapsed_ms: u32,
    /// Previously settled usage. This is not available for reuse.
    pub previous_usage: AcquisitionUsageV1,
}
impl AcquisitionAllowanceV1 {
    /// Construct the trusted repository receipt without widening configured maxima.
    #[must_use]
    pub fn new(
        remaining_attempts: u8,
        remaining_network_requests: u32,
        remaining_decoded_bytes: u64,
        remaining_elapsed_ms: u32,
        previous_usage: AcquisitionUsageV1,
    ) -> Self {
        Self {
            remaining_attempts,
            remaining_network_requests,
            remaining_decoded_bytes,
            remaining_elapsed_ms,
            previous_usage,
        }
    }
}

/// Connection observations, never a claim that an unobserved certificate was checked.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ConnectionEvidenceV1 {
    /// Origin that the native egress policy checked.
    pub checked_origin: Option<String>,
    /// Actual peer only when the transport reported it.
    pub peer: Option<std::net::IpAddr>,
    /// Actual peer matched the checked set; absent when the peer was not observed.
    pub peer_checked: Option<bool>,
    /// Approved route class (`direct`, `configured_proxy`, `proxyx_pool`), never a
    /// credential-bearing proxy URL.
    pub proxy_route: Option<String>,
    /// Pool session id the ProxyX gateway named for the tunnel that carried the request.
    /// Identifies the exit identity, never a credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_session: Option<String>,
    /// Exit IP the ProxyX gateway named for that tunnel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_exit_ip: Option<std::net::IpAddr>,
    /// Effective TLS verification configuration, independent of certificate capture.
    pub tls_verification: Option<String>,
    /// Observed certificate material is unavailable in these native adapters.
    pub certificate_observed: bool,
    /// Observed final-response application protocol; absent for unmeasured service reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_protocol: Option<crate::traffic::Protocol>,
}

/// One body-free completed dispatch summary, capped at eight per result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AcquisitionAttemptV1 {
    /// One-based dispatch ordinal under the parent allowance.
    pub ordinal: u8,
    /// Registered execution backend.
    pub backend_id: String,
    /// Actual target status if observed.
    pub target_status: Option<u16>,
    /// Independent outcome.
    pub category: ValidationCategoryV1,
}
impl AcquisitionAttemptV1 {
    /// Record bounded native facts for one reserved dispatch.
    #[must_use]
    pub fn new(
        ordinal: u8,
        backend_id: &str,
        target_status: Option<u16>,
        category: ValidationCategoryV1,
    ) -> Self {
        Self {
            ordinal,
            backend_id: backend_id.to_owned(),
            target_status,
            category,
        }
    }
}

/// Scope of an actually observed monotonic acquisition duration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AcquisitionElapsedScopeV1 {
    /// Current coordinator lease only; earlier fenced-lease elapsed is unavailable.
    CurrentCoordinator,
}

/// Serializable bounded receipt. Ownership comes only from authenticated worker context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct AcquisitionResultV1 {
    /// Contract version.
    pub schema_version: u8,
    /// Existing canonical request digest, not a new identity scheme.
    pub request_digest: Digest,
    /// Run owner.
    pub run: CrawlRunId,
    /// Tenant owner.
    pub tenant: TenantId,
    /// Existing actor session ID; absent for stateless HTTP.
    pub session: Option<crate::SessionId>,
    /// Fenced generation when the session authority supplies one; never guessed.
    pub session_generation: Option<u64>,
    /// Requested URL, passed through existing redaction before persistence.
    pub requested_url: Url,
    /// Observed final URL if available.
    pub final_url: Option<Url>,
    /// Provenance of final URL.
    pub final_url_evidence: UrlEvidenceV1,
    /// Observed redirects, capped at 20.
    pub redirects: Vec<AcquisitionRedirectV1>,
    /// Complete bounded meta continuation evidence, absent when no usable tag was selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_refresh: Option<MetaRefreshEvidenceV1>,
    /// Effective parser policy after complete evaluation, even when no usable tag existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_refresh_policy: Option<MetaRefreshPolicyV1>,
    /// Evaluated native parser/admission/privacy revision; absence is legacy unknown evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_refresh_revision: Option<u8>,
    /// Target status, never fabricated for HTML-only results.
    pub target_status: Option<u16>,
    /// Service/gateway status, absent for native direct execution.
    pub gateway_status: Option<u16>,
    /// Response media type as observed, independent of DOM representation.
    pub content_type: Option<String>,
    /// Response content encoding as observed.
    pub content_encoding: Option<String>,
    /// A target response was received, independently of accepted content.
    pub transport_succeeded: bool,
    /// Whether extraction completed, independently of acquisition acceptance.
    pub extraction_succeeded: Option<bool>,
    /// Main representation.
    pub representation: RepresentationV1,
    /// Retention-approved wire artifact, never a volatile token.
    pub wire_body: Option<ArtifactRef>,
    /// Published archive baseline used for a 304; never presented as a fresh wire response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retained_baseline: Option<crate::archive_catalog::ArchiveDependencyV1>,
    /// Retention-approved serialized DOM artifact.
    pub rendered_dom: Option<ArtifactRef>,
    /// Actual decoded bytes consumed across attempts.
    pub decoded_bytes: u64,
    /// Wire byte count only if observed independently.
    pub wire_bytes: Option<u64>,
    /// Incomplete body.
    pub truncated: bool,
    /// Effective execution backend.
    pub backend: BackendCapabilitiesV1,
    /// Checked connection evidence and explicit unobserved facts.
    pub connection: ConnectionEvidenceV1,
    /// Measured checked DNS fact; absent when the resolver did not provide one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_report: Option<crate::report_history::ReportDataV1>,
    /// Independent validation.
    pub validation: ValidationOutcomeV1,
    /// Total navigation dispatches across all backends.
    pub attempts: u8,
    /// Bounded receipt for each observed dispatch, including unsuccessful responses.
    pub attempt_summaries: Vec<AcquisitionAttemptV1>,
    /// Consumed network allowance, including conservative reservations whose send outcome is unknown.
    pub network_requests: u32,
    /// Observed dispatch count when evidence is complete; unknown failures never become invented requests.
    pub network_requests_observed: Option<u32>,
    /// Per-lease consumption for fenced settlement; reserved and observed bytes remain distinct.
    #[serde(default)]
    pub allowance_usage: AcquisitionUsageV1,
    /// Elapsed milliseconds; interpret only with `elapsed_scope`.
    pub elapsed_ms: u64,
    /// Observed duration scope. Missing legacy evidence remains unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_scope: Option<AcquisitionElapsedScopeV1>,
    /// Evidence was omitted at a bound.
    pub evidence_truncated: bool,
}
impl AcquisitionResultV1 {
    /// Construct unknown response evidence owned by the trusted worker.
    #[must_use]
    pub fn new(
        run: CrawlRunId,
        tenant: TenantId,
        requested_url: Url,
        request_digest: Digest,
        backend: BackendCapabilitiesV1,
    ) -> Self {
        Self {
            schema_version: 1,
            run,
            tenant,
            requested_url,
            request_digest,
            final_url: None,
            session: None,
            session_generation: None,
            content_type: None,
            content_encoding: None,
            transport_succeeded: false,
            extraction_succeeded: None,
            connection: ConnectionEvidenceV1::default(),
            dns_report: None,
            attempt_summaries: Vec::new(),
            final_url_evidence: UrlEvidenceV1::Unavailable,
            redirects: Vec::new(),
            meta_refresh: None,
            meta_refresh_policy: None,
            meta_refresh_revision: None,
            target_status: None,
            gateway_status: None,
            representation: RepresentationV1::WireResponse,
            wire_body: None,
            rendered_dom: None,
            retained_baseline: None,
            decoded_bytes: 0,
            wire_bytes: None,
            truncated: false,
            backend,
            validation: ValidationOutcomeV1::indeterminate(),
            attempts: 0,
            network_requests: 0,
            network_requests_observed: None,
            allowance_usage: AcquisitionUsageV1::default(),
            elapsed_ms: 0,
            elapsed_scope: None,
            evidence_truncated: false,
        }
    }
    /// Enforce public metadata bounds without silently turning incomplete evidence into valid.
    ///
    /// # Errors
    /// Returns an error if essential ownership/backend/URL metadata alone exceeds 64 KiB.
    pub fn bound(&mut self) -> Result<(), AcquisitionPolicyError> {
        if self.redirects.len() > 20 {
            self.redirects.truncate(20);
            self.evidence_truncated = true;
        }
        if let Some(refresh) = &mut self.meta_refresh {
            if refresh.http_redirects.len() > 20 {
                refresh.http_redirects.truncate(20);
                self.evidence_truncated = true;
            }
        }
        if self.validation.signals.len() > 32 {
            self.validation.signals.truncate(32);
            self.evidence_truncated = true;
        }
        if self.backend.limitations.len() > 16 {
            self.backend.limitations.truncate(16);
            self.evidence_truncated = true;
        }
        if self.attempt_summaries.len() > 8 {
            self.attempt_summaries.truncate(8);
            self.evidence_truncated = true;
        }
        let size = serde_json::to_vec(self)
            .map_err(|_| AcquisitionPolicyError("metadata serialization"))?
            .len();
        if size > MAX_METADATA_BYTES {
            self.redirects.clear();
            self.validation.signals.clear();
            self.evidence_truncated = true;
            if serde_json::to_vec(self)
                .map_err(|_| AcquisitionPolicyError("metadata serialization"))?
                .len()
                > MAX_METADATA_BYTES
            {
                return Err(AcquisitionPolicyError("metadata byte cap"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn explicit_policy_bounds_and_roundtrip() {
        let policy = AcquisitionPolicyV1::default();
        policy.validate().unwrap();
        assert_eq!(
            serde_json::from_value::<AcquisitionPolicyV1>(serde_json::to_value(&policy).unwrap()).unwrap(),
            policy
        );
        let mut invalid = policy.clone();
        invalid.schema_version = 2;
        assert!(invalid.validate().is_err());
        invalid = policy.clone();
        invalid.backend_ids = vec!["https://adapter.invalid".into()];
        assert!(invalid.validate().is_err());
        invalid = policy.clone();
        invalid.max_attempts = 9;
        assert!(invalid.validate().is_err());
        invalid = policy;
        invalid.validation.required_selectors = vec!["x".repeat(2049)];
        assert!(invalid.validate().is_err());
    }
}
