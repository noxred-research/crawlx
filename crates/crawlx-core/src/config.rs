//! The crawl request (`POST /v1/crawls`) with
//! defaults, clamping and validation. Field names are the wire names.

use crate::error::CoreError;
use crate::request_controls::{ExtraHeaders, FetchCookie};
use crate::secret::CredentialRef;
use crate::seed::CrawlSeed;
use crate::tls::TlsImpersonation;
use crate::url::ParamClass;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn t() -> bool {
    true
}

// serde `skip_serializing_if` predicates keep default values off the wire, so requests that
// never set the surface-discovery options serialize (and hash) exactly as before.
#[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
const fn is_false(v: &bool) -> bool {
    !*v
}
#[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
const fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}
#[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
const fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
#[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
const fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
#[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
const fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}
#[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
const fn is_default_max_url_length(v: &u32) -> bool {
    *v == 8192
}

/// Maximum length in bytes of one caller-supplied regex pattern.
pub const MAX_PATTERN_LEN: usize = 512;
/// Maximum number of patterns (or host exclusions, or extensions) per list.
pub const MAX_PATTERNS: usize = 100;
/// Maximum length in bytes of one path or URL pattern of `scope.includePaths`, `excludePaths`,
/// `urlInclude` and `urlExclude` (the compatibility API's limit; the compiled-size limits of `crawlx-url`
/// still bound every pattern).
pub const MAX_PATH_PATTERN_LEN: usize = 2000;
/// Maximum number of patterns in one of those four lists (the compatibility API's limit).
pub const MAX_PATH_PATTERNS: usize = 1000;
/// Maximum number of `extract.customFields`.
pub const MAX_CUSTOM_FIELDS: usize = 50;
/// Most extra seed URLs of one compatibility-API batch scrape (`scrape.urls`).
pub const MAX_BATCH_URLS: usize = 10_000;

/// `mode`: which planes run.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum CrawlMode {
    /// URL plane only: HTTP fetching, no browser.
    Static,
    /// Browser plane only, seeded by `seedUrl`.
    Dynamic,
    /// Both planes: URL discovery plus browser interaction (the default).
    #[default]
    Hybrid,
}

/// `safety.profile`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafetyProfile {
    /// Passive crawl: no external communication, no destructive actions (the default).
    #[default]
    ReadOnly,
    /// Crawl of a test deployment; may use test sinks and approval-gated destructive actions.
    TestEnvironment,
    /// Crawl covered by an authorization record; requires `authorizationRecordRef`.
    AuthorizedSecurityTest,
}

impl SafetyProfile {
    /// Wire name of the profile (`read_only`, `test_environment` or `authorized_security_test`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::TestEnvironment => "test_environment",
            Self::AuthorizedSecurityTest => "authorized_security_test",
        }
    }
}

/// `dynamic.launchProfile`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum LaunchProfile {
    /// Regular Chromium launch flags (the default).
    #[default]
    Standard,
    /// Stealth launch flags; needs `test_environment` or `authorized_security_test`.
    Stealth,
}

impl LaunchProfile {
    /// Wire name of the profile (`standard` or `stealth`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Stealth => "stealth",
        }
    }
}

/// `scope.sitemap`: how sitemaps participate in URL discovery.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum SitemapMode {
    /// Use sitemaps and follow page links (the default).
    #[default]
    Include,
    /// Ignore sitemaps; discover URLs from page links only.
    Skip,
    /// Discover from sitemaps only; page links are never followed in the URL plane.
    Only,
}

/// `scope.queryPolicy`: how URL query parameters are treated during canonicalization.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum QueryPolicy {
    /// Classify each parameter (resource id, filter, tracking, ...) and strip only noise (the default).
    #[default]
    Classify,
    /// Keep every query parameter.
    KeepAll,
    /// Strip every query parameter, which can merge distinct resources.
    StripAll,
}

/// `scope.hostScope`: which hosts count as in scope relative to the seed host.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum HostScope {
    /// Exactly the seed host; subdomains only with `allowSubdomains` (the default).
    #[default]
    Fqdn,
    /// The seed's registrable domain (public suffix list) and all of its subdomains.
    Rdn,
    /// Any host whose name contains the seed's domain keyword (`example` in `example.co.uk`).
    Dn,
    /// Every host; only URL patterns, paths and exclusions limit the crawl.
    None,
}

impl HostScope {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fqdn => "fqdn",
            Self::Rdn => "rdn",
            Self::Dn => "dn",
            Self::None => "none",
        }
    }
}

/// `scope.strategy`: frontier ordering of the URL plane.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum CrawlStrategy {
    /// Shallowest first, discovery order as the tie-break (the default).
    #[default]
    #[serde(alias = "bfs", alias = "breadth-first")]
    BreadthFirst,
    /// Most recently discovered, deepest URL first.
    #[serde(alias = "dfs", alias = "depth-first")]
    DepthFirst,
    /// Surface-priority order: lowest `depth - surface score` first, where the score rewards
    /// attack-surface path words, query strings and non-GET requests (ties: discovery order).
    Priority,
}

/// An entry of `scope.knownFiles`: well-known files mined for seed URLs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum KnownFile {
    /// `robots.txt` `Allow:` paths (and `Disallow:` paths only without robots respect under
    /// an authorization record).
    RobotsPaths,
    /// `robots.txt` `Sitemap:` URLs.
    Sitemap,
}

/// `scope.contentSimilarity.mode`: page-content near-duplicate filter of the URL plane.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum SimilarityMode {
    /// No content similarity filtering (the default).
    #[default]
    Off,
    /// 64-bit simhash over 3-word shingles; near when the Hamming distance is at most `distance`.
    Simhash,
    /// TF-IDF cosine over tokens; near when the score is at least `threshold`.
    Tfidf,
    /// Normalized BM25 over tokens; near when the score is at least `threshold`.
    Bm25,
}

impl SimilarityMode {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Simhash => "simhash",
            Self::Tfidf => "tfidf",
            Self::Bm25 => "bm25",
        }
    }
}

/// `scope.contentSimilarity`: the layer-2 content near-duplicate filter.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ContentSimilarity {
    /// Backend (default: off).
    #[serde(default)]
    pub mode: SimilarityMode,
    /// Maximum Hamming distance for `simhash`; clamped to 0..=64 (default 3).
    #[serde(default = "ContentSimilarity::default_distance")]
    pub distance: u8,
    /// Minimum cosine/BM25 score for `tfidf`/`bm25`; clamped to 0.0..=1.0 (default 0.85).
    #[serde(default = "ContentSimilarity::default_threshold")]
    pub threshold: f64,
    /// Pages fully processed per similarity cluster; clamped to 1..=1000 (default 1).
    #[serde(default = "ContentSimilarity::default_budget")]
    pub budget: u32,
}

impl ContentSimilarity {
    const fn default_distance() -> u8 {
        3
    }
    const fn default_threshold() -> f64 {
        0.85
    }
    const fn default_budget() -> u32 {
        1
    }
}

impl Default for ContentSimilarity {
    fn default() -> Self {
        Self {
            mode: SimilarityMode::Off,
            distance: Self::default_distance(),
            threshold: Self::default_threshold(),
            budget: Self::default_budget(),
        }
    }
}

/// Deterministic page classification; `scope.filterPageTypes` stops expanding
/// pages of the listed types.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum PageType {
    /// A sign-in form.
    Login,
    /// An error page (404, 500, application error).
    Error,
    /// A captcha or bot challenge.
    Captcha,
    /// A parked or placeholder domain page.
    Parked,
    /// A search form or search results page.
    Search,
    /// A list of items (index, category, feed).
    Listing,
    /// A single article or document.
    Article,
    /// A data-entry form other than login or search.
    Form,
    /// No signal matched.
    #[default]
    Unknown,
}

impl PageType {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Error => "error",
            Self::Captcha => "captcha",
            Self::Parked => "parked",
            Self::Search => "search",
            Self::Listing => "listing",
            Self::Article => "article",
            Self::Form => "form",
            Self::Unknown => "unknown",
        }
    }
}

/// `dynamic.pageLoadStrategy`: headless readiness preset mapped onto the quiescence policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum PageLoadStrategy {
    /// The default quiescence heuristic.
    #[default]
    Heuristic,
    /// Wait for the `load` event.
    Load,
    /// Wait for `DOMContentLoaded`.
    DomContentLoaded,
    /// Wait until the network is idle.
    NetworkIdle,
    /// Do not wait beyond navigation commit.
    None,
}

/// `extract.customFields[].part`: which part of the response a custom regex field scans.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum CustomFieldPart {
    /// The response body (the default).
    #[default]
    Body,
    /// The response headers.
    Header,
    /// Headers and body.
    Response,
}

/// `extract.customFields[]` entry: a named regex evaluated at extraction time.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CustomField {
    /// Field name (`[A-Za-z0-9_-]{1,64}`); unique within the request.
    pub name: String,
    /// Regex patterns, each at most 512 bytes; a value is any match of any pattern.
    #[serde(default)]
    pub regex: Vec<String>,
    /// Response part to scan (default: body).
    #[serde(default)]
    pub part: CustomFieldPart,
    /// Capture group whose text is the value; 0 is the whole match (default 0).
    #[serde(default)]
    pub group: u32,
}

/// `targetIsolation`: whether roles share one target application instance.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum TargetIsolation {
    /// All roles hit one backend, so runs are ordered round-robin (the default).
    #[default]
    Shared,
    /// Each role has its own replica (`roles[].replicaBaseUrl`); roles may run in parallel.
    PerRoleReplica,
}

/// `roleOrder`: how roles are ordered inside each round.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoleOrder {
    /// The declared `roles[]` order (the default).
    #[default]
    Declared,
    /// One permutation of `roles[]` drawn from the crawl seed and applied to every round.
    SeededShuffle,
}

/// `dynamic.system1Mode`: how much the System 1 model may influence action choice.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum System1Mode {
    /// Model never runs (the default).
    #[default]
    Off,
    /// Model runs and its decisions are recorded without effect.
    Shadow,
    /// Model confidence reorders the deterministic safe shortlist.
    Advisory,
    /// Model may pick from the shortlist; rejected until gate G3 has passed.
    Active,
}

/// `dynamic.llmPlanner`: when the LLM planner may be invoked.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum LlmPlannerMode {
    /// Planner never invoked (the default).
    #[default]
    Off,
    /// Planner invoked only after deterministic recovery is exhausted.
    StalledOnly,
    /// Planner may be invoked whenever the budget allows.
    Enabled,
}

/// `dynamic.tabPolicy`: how popups and extra tabs are handled.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum TabPolicy {
    /// Popups are closed immediately.
    Single,
    /// Up to `dynamic.maxTabs` tabs stay open (the default).
    #[default]
    Bounded,
}

/// `safety.externalCommunication`: whether actions may reach outside the target.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum ExternalCommunication {
    /// Actions that communicate externally are refused (the default).
    #[default]
    Deny,
    /// External communication is allowed toward configured test sinks only.
    TestSinks,
}

/// `safety.destructiveActions`: handling of actions that change or delete target data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum DestructiveActions {
    /// Destructive actions are refused (the default).
    #[default]
    Deny,
    /// Destructive actions run only after explicit approval.
    Approval,
}

/// Capture policy for HTML and DOM snapshots (`capture.html`, `capture.domSnapshot`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Nothing is captured.
    Off,
    /// Capture on novel state, checkpoint, error or configured interval (the default).
    #[default]
    Checkpoint,
    /// Capture on every observed state.
    EveryState,
}

/// Screenshot capture policy (`capture.screenshot`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum ScreenshotMode {
    /// No screenshots.
    Off,
    /// Screenshot when a state not seen before is observed (the default).
    #[default]
    OnNovelState,
    /// Screenshot on every observed state.
    EveryState,
}

/// `capture.responseBodies`: how much of each response body is persisted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBodies {
    /// Headers and sizes only; no body bytes (the default).
    #[default]
    MetadataOnly,
    /// Retain a bounded, sanitized prefix of same-origin JSON/HTML responses.
    TextCapped,
    /// Complete bodies; refused under `zdr` retention.
    Full,
}

/// `capture.traffic`: which trust lanes of network traffic are persisted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrafficCapture {
    /// Persist only traffic caused by trusted UI actions.
    TrustedOnly,
    /// Persist trusted and diagnostic lane traffic (the default).
    #[default]
    TrustedAndDiagnostic,
}

/// `capture.backend`: which `TrafficSource` records `traffic_events`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CaptureBackend {
    /// CDP `Network` events from inside the browser (the default).
    #[default]
    Cdp,
    /// Flows observed by the loopback egress proxy; Chromium runs with QUIC disabled
    /// (`protocols_disabled = [h3]`). HTTP/1.1 and HTTP/2 only.
    Proxy,
}

impl CaptureBackend {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cdp => "cdp",
            Self::Proxy => "proxy",
        }
    }
}

/// `retention.mode`: how long crawl artifacts are kept.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum RetentionMode {
    /// Keep for `retention.days`, clamped to 1..=30 days (the default).
    #[default]
    Standard,
    /// Keep for `retention.days`, clamped to 31..=365 days.
    Extended,
    /// Zero data retention: `days` is forced to 0 and full response bodies are refused.
    Zdr,
}

/// An entry of `output.formats`: a representation returned for each page.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// Extracted main content as Markdown.
    Markdown,
    /// Cleaned HTML of the page.
    Html,
    /// HTML exactly as fetched, before cleaning.
    RawHtml,
    /// Links found on the page.
    Links,
    /// Page metadata (title, description, language, status code, ...).
    Metadata,
    /// Screenshot of the page.
    Screenshot,
}

/// An entry of `dynamic.strategies`: a candidate-generation strategy of the browser plane.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StrategyName {
    /// Least-interacted-first frontier ordering over interactive elements.
    InteractionBfs,
    /// Actions proposed from observed event listeners.
    EventDriven,
    /// Actions aimed at reaching states not seen before.
    StateNovelty,
    /// Actions that enable disabled or hidden controls (for example by filling prerequisites).
    Enablement,
    /// Model-ranked proposals from the System 1 cascade; effect depends on `system1Mode`.
    System1,
}

impl StrategyName {
    /// Wire name (`interaction_bfs`, `state_novelty`, ...).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InteractionBfs => "interaction_bfs",
            Self::EventDriven => "event_driven",
            Self::StateNovelty => "state_novelty",
            Self::Enablement => "enablement",
            Self::System1 => "system1",
        }
    }

    /// Whether the strategy may suppress frontier entries and so needs gate G1.
    #[must_use]
    pub const fn needs_g1(self) -> bool {
        matches!(self, Self::StateNovelty | Self::Enablement)
    }
}

/// One requested implementation version and its relative session-assignment weight.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct StrategyArm {
    /// Real implementation version; unavailable versions are refused by the registry.
    pub version: u32,
    /// Relative weight; must be positive.
    pub weight: u32,
}

/// The configured arm selected for one strategy in one role session.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StrategyArmSelection {
    /// Strategy's proposal-attribution name.
    pub strategy: String,
    /// Selected implementation version, also recorded on proposals and actions.
    pub version: u32,
    /// Selected arm's configured relative weight.
    pub weight: u32,
}

impl StrategyArm {
    /// Request a real implementation version with a relative weight; validation is separate.
    #[must_use]
    pub const fn new(version: u32, weight: u32) -> Self {
        Self { version, weight }
    }
}

impl StrategyArmSelection {
    /// Record a selected configured arm without changing its implementation's attribution.
    #[must_use]
    pub fn new(strategy: String, version: u32, weight: u32) -> Self {
        Self {
            strategy,
            version,
            weight,
        }
    }
}

/// `limits`: crawl budgets; the run ends when one is exhausted.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Maximum URLs admitted to the crawl; clamped to 1..=1,000,000 (default 10,000).
    #[serde(default = "Limits::default_urls")]
    pub urls: u32,
    /// Maximum browser interactions attempted; clamped to 0..=100,000 (default 5,000).
    #[serde(default = "Limits::default_interactions")]
    pub interactions: u32,
    /// Maximum distinct states observed; clamped to 0..=100,000 (default 2,500).
    #[serde(default = "Limits::default_states")]
    pub states: u32,
    /// Wall-clock budget in seconds before the run ends; clamped to 1..=604,800 (default 14,400).
    #[serde(default = "Limits::default_duration")]
    pub duration_seconds: u32,
    /// Stop once this many pages were kept (succeeded); clamped to 0..=1,000,000 (default 0 =
    /// no item criterion). The URL plane leases no more rows than the criterion still allows, so
    /// the count is never overshot.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub items: u32,
    /// Stop once this many URL fetches ended failed or unreachable; clamped to 0..=1,000,000
    /// (default 0 = no error criterion).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub errors: u32,
    /// Stop after this many seconds without a newly kept page; clamped to 0..=604,800 (default 0
    /// = no idle criterion). Measured on the run clock from the plane's start.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub idle_seconds: u32,
    /// Stop leasing new work (a drain) once the artifact upload spool occupies this many
    /// permille of its capacity; clamped to 0..=1000 (default 0 = no disk criterion).
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub disk_pressure_permille: u16,
}

impl Limits {
    const fn default_urls() -> u32 {
        10_000
    }
    const fn default_interactions() -> u32 {
        5_000
    }
    const fn default_states() -> u32 {
        2_500
    }
    const fn default_duration() -> u32 {
        14_400
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            urls: Self::default_urls(),
            interactions: Self::default_interactions(),
            states: Self::default_states(),
            duration_seconds: Self::default_duration(),
            items: 0,
            errors: 0,
            idle_seconds: 0,
            disk_pressure_permille: 0,
        }
    }
}

/// `scope`: which URLs the crawl may discover and follow.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Scope {
    /// Ordered source stages; empty preserves legacy HTML and sitemap discovery.
    #[serde(default)]
    pub sources: Vec<crate::discovery::DiscoverySourceV1>,
    /// Lifetime known-URL ceiling, independent of fetched-page limits.
    #[serde(default = "crate::discovery::default_max_known_urls")]
    pub max_known_urls: u32,
    /// Opt-in bounded feed, focused-news and auxiliary acquisition policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<crate::discovery::SourceDiscoveryPolicyV1>,
    /// Regex patterns; when non-empty, only URL paths matching one are crawled. The seed is
    /// exempt: it is always fetched once, to start discovery, but is not a page when it matches none.
    #[serde(default)]
    pub include_paths: Vec<String>,
    /// Regex patterns; URL paths matching one are skipped.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Follow links to subdomains of the seed host.
    #[serde(default)]
    pub allow_subdomains: bool,
    /// Fetch links to other hosts (as leaves; they are not expanded).
    #[serde(default)]
    pub allow_external_links: bool,
    /// Also follow sibling and parent paths of the seed path.
    #[serde(default)]
    pub crawl_entire_domain: bool,
    /// Sitemap handling (default: include).
    #[serde(default)]
    pub sitemap: SitemapMode,
    /// Maximum link hops from the seed; clamped to 0..=100 (default 10).
    #[serde(default = "Scope::default_depth")]
    pub max_discovery_depth: u16,
    /// Query-parameter handling during URL canonicalization (default: classify).
    #[serde(default)]
    pub query_policy: QueryPolicy,
    /// Per-parameter-name class overrides; they beat the built-in classification.
    #[serde(default)]
    pub query_overrides: BTreeMap<String, ParamClass>,
    /// Compatibility alias `-ignore-query-params`: `true` forces `queryPolicy: strip_all` (default false).
    #[serde(default)]
    pub ignore_query_params: bool,
    /// Host scope relative to the seed host (default: fqdn).
    #[serde(default)]
    pub host_scope: HostScope,
    /// Regex patterns over the full URL; when non-empty, only matching URLs are crawled (the seed
    /// is exempt as for `includePaths`).
    #[serde(default)]
    pub url_include: Vec<String>,
    /// Regex patterns over the full URL; matching URLs are skipped.
    #[serde(default)]
    pub url_exclude: Vec<String>,
    /// Hosts never crawled: `private-ips`, `cdn` (the bundled list of CDN and edge hostnames,
    /// matched by name), a CIDR, an IP literal, or a host regex
    /// (default empty: private ranges are already denied by the egress policy
    /// unless `safety.allowPrivateNetworks` and an authorization record permit them;
    /// `private-ips` here is an extra scope filter and is ignored when private
    /// networks are explicitly allowed).
    #[serde(default)]
    pub exclude_hosts: Vec<String>,
    /// Frontier ordering (default: breadth_first).
    #[serde(default)]
    pub strategy: CrawlStrategy,
    /// Maximum pages admitted per host; `None` is unlimited.
    #[serde(default)]
    pub max_pages_per_host: Option<u32>,
    /// Well-known files mined for seeds (default `["sitemap"]`).
    #[serde(default = "Scope::default_known_files")]
    pub known_files: Vec<KnownFile>,
    /// When non-empty, only URLs with one of these extensions are crawled (`none` matches
    /// extensionless URLs).
    #[serde(default)]
    pub extension_match: Vec<String>,
    /// Extensions skipped in addition to the default filter.
    #[serde(default)]
    pub extension_filter: Vec<String>,
    /// Disable the default extension filter (images, fonts, archives, media, documents).
    #[serde(default)]
    pub no_default_extension_filter: bool,
    /// Filter URLs whose shape fingerprint already consumed `filterSimilarBudget` pages.
    #[serde(default)]
    pub filter_similar: bool,
    /// Distinct values at one path position before it is promoted to `{param}`;
    /// clamped to 2..=1000 (default 10).
    #[serde(default = "Scope::default_filter_similar_threshold")]
    pub filter_similar_threshold: u32,
    /// Pages fetched per URL fingerprint; clamped to 1..=1000 (default 1).
    #[serde(default = "Scope::default_filter_similar_budget")]
    pub filter_similar_budget: u32,
    /// Page-content near-duplicate filter (default: off).
    #[serde(default)]
    pub content_similarity: ContentSimilarity,
    /// Page types whose links are not followed (sorted, deduplicated).
    #[serde(default)]
    pub filter_page_types: Vec<PageType>,
    /// Admit `Regex`-confidence endpoints mined from JavaScript into the frontier
    /// (compatibility flag `-jc`; default true). `Structural` endpoints are always admitted.
    #[serde(default = "t")]
    pub js_endpoints: bool,
    /// Compatibility flag `-path-climb`: every discovered URL also enqueues its parent directory paths
    /// (`/a/b/c.html` adds `/a/b/` and `/a/`), subject to the same scope rules (default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub path_climb: bool,
    /// Compatibility flag `-disable-unique-filter`: keep pages whose body is byte-identical to an earlier
    /// page instead of dropping them as `content_exact` duplicates (default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub disable_unique_filter: bool,
    /// Compatibility flag `-field-scope <regex>`: hosts matching this regex (over the host name) are in
    /// scope in addition to what `hostScope` admits; `None` is off. At most 512 bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_scope_pattern: Option<String>,
    /// Longest URL in bytes the crawl accepts, checked before canonicalization and again on the
    /// canonical form; a longer link is refused with the stable reason `url_too_long` and counted
    /// as policy-blocked, never fetched. Clamped to 256..=65,536 (default 8,192).
    #[serde(
        default = "Scope::default_max_url_length",
        skip_serializing_if = "is_default_max_url_length"
    )]
    pub max_url_length: u32,
}

impl Scope {
    const fn default_max_url_length() -> u32 {
        8192
    }
    const fn default_depth() -> u16 {
        10
    }
    fn default_known_files() -> Vec<KnownFile> {
        vec![KnownFile::Sitemap]
    }
    const fn default_filter_similar_threshold() -> u32 {
        10
    }
    const fn default_filter_similar_budget() -> u32 {
        1
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            max_known_urls: crate::discovery::default_max_known_urls(),
            discovery: None,
            include_paths: Vec::new(),
            exclude_paths: Vec::new(),
            allow_subdomains: false,
            allow_external_links: false,
            crawl_entire_domain: false,
            sitemap: SitemapMode::Include,
            max_discovery_depth: Self::default_depth(),
            query_policy: QueryPolicy::Classify,
            query_overrides: BTreeMap::new(),
            ignore_query_params: false,
            host_scope: HostScope::Fqdn,
            url_include: Vec::new(),
            url_exclude: Vec::new(),
            exclude_hosts: Vec::new(),
            strategy: CrawlStrategy::BreadthFirst,
            max_pages_per_host: None,
            known_files: Self::default_known_files(),
            extension_match: Vec::new(),
            extension_filter: Vec::new(),
            no_default_extension_filter: false,
            filter_similar: false,
            filter_similar_threshold: Self::default_filter_similar_threshold(),
            filter_similar_budget: Self::default_filter_similar_budget(),
            content_similarity: ContentSimilarity::default(),
            filter_page_types: Vec::new(),
            js_endpoints: true,
            path_climb: false,
            disable_unique_filter: false,
            host_scope_pattern: None,
            max_url_length: Self::default_max_url_length(),
        }
    }
}

/// `roles[]` entry: a principal the crawl runs as.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Role {
    /// Unique role name; `anonymous` is the implicit role with no credential.
    pub name: String,
    /// Reference to the role's credential (never the secret itself); `None` for anonymous.
    #[serde(default)]
    pub credential_ref: Option<CredentialRef>,
    /// Login procedure, for example `builtin:form`; `None` when no login is needed.
    #[serde(default)]
    pub login_plan: Option<String>,
    /// Base URL of this role's application replica; required under `per_role_replica` isolation.
    #[serde(default)]
    pub replica_base_url: Option<url::Url>,
}

/// Longest `dynamic.browserProfile.name`.
pub const MAX_PROFILE_NAME_LEN: usize = 128;

/// Largest `dynamic.pageHookOptions.timerAcceleration` divisor.
pub const MAX_TIMER_ACCELERATION: u8 = 100;

/// `dynamic.pageHookOptions`: the behaviour-changing page hooks of the reference headless driver
/// (a page-init script), adopted as opt-in with every default off
/// They run in the page's main world, are refused under the
/// stealth profile, and a session crawled with any of them is tagged `page_hooks` with the
/// option names ([`Self::names`]) so fingerprint studies can exclude it.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct PageHookOptions {
    /// Divisor applied to every `setTimeout`/`setInterval` delay; `0` and `1` leave timers
    /// alone, `2..=100` run them that many times faster (a 5 s reveal with `10` shows after
    /// 500 ms). Clamped to `0..=100`.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub timer_acceleration: u8,
    /// Turn `form.reset()` and the `reset` event's default action into no-ops, so a page that
    /// clears a form after submitting it keeps the values the crawler typed.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prevent_form_reset: bool,
    /// Turn `window.close()` into a no-op, so a script-opened window the page closes itself
    /// stays open for exploration.
    #[serde(default, skip_serializing_if = "is_false")]
    pub prevent_window_close: bool,
}

impl PageHookOptions {
    /// Are all options off (the serialized form omits the block then)?
    #[must_use]
    pub const fn is_default(&self) -> bool {
        self.timer_acceleration == 0 && !self.prevent_form_reset && !self.prevent_window_close
    }

    /// The timer divisor when it changes anything (`>= 2`).
    #[must_use]
    pub const fn timer_divisor(&self) -> Option<u8> {
        if self.timer_acceleration >= 2 {
            Some(self.timer_acceleration)
        } else {
            None
        }
    }

    /// Does any option change the page's behaviour?
    #[must_use]
    pub const fn any(&self) -> bool {
        self.timer_divisor().is_some() || self.prevent_form_reset || self.prevent_window_close
    }

    /// The active options as session-tag names: `timer_acceleration:10`,
    /// `prevent_form_reset`, `prevent_window_close` (fixed order).
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(n) = self.timer_divisor() {
            out.push(format!("timer_acceleration:{n}"));
        }
        if self.prevent_form_reset {
            out.push("prevent_form_reset".to_owned());
        }
        if self.prevent_window_close {
            out.push("prevent_window_close".to_owned());
        }
        out
    }
}

/// `dynamic.browserProfile` (compatibility API `profile{name,saveChanges}`): a named persistent
/// browser profile. The worker keeps its cookies and web storage as encrypted, versioned state
/// under durable key custody (never as a user-data directory). `generation` names the exact
/// version to restore: 0 starts a new namespace (refused when one already exists), N >= 1
/// restores that generation or fails, never an empty profile. With `saveChanges` the run commits
/// its final state as generation `generation + 1`; without it nothing is written.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BrowserProfile {
    /// Profile name: 1 to 128 of `A-Z a-z 0-9 _ -`.
    pub name: String,
    /// Keep what the run writes into the profile (compatibility API default `true`).
    #[serde(default = "t")]
    pub save_changes: bool,
    /// Exact generation to restore; 0 creates the namespace.
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub generation: u64,
}

impl BrowserProfile {
    /// Is `name` a valid profile name (also a safe single path component)?
    #[must_use]
    pub fn name_is_valid(name: &str) -> bool {
        !name.is_empty()
            && name.len() <= MAX_PROFILE_NAME_LEN
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }
}

/// `dynamic`: configuration of the browser plane.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Dynamic {
    /// Whether the browser plane runs; must agree with `mode` (default true, forced off for `static`).
    #[serde(default = "t")]
    pub enabled: bool,
    /// Enabled candidate strategies; must not be empty while the plane is enabled.
    #[serde(default = "Dynamic::default_strategies")]
    pub strategies: Vec<StrategyName>,
    /// Optional version weights per deterministic strategy. Empty preserves the default registry.
    /// Each configured strategy must be enabled and every version must have a real implementation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub strategy_arms: BTreeMap<StrategyName, Vec<StrategyArm>>,
    /// How much the System 1 model may influence action choice (default: off).
    #[serde(default)]
    pub system1_mode: System1Mode,
    /// When the LLM planner may be invoked (default: off).
    #[serde(default)]
    pub llm_planner: LlmPlannerMode,
    /// Permit synthetic DOM click events, recorded in the diagnostic lane (default false).
    #[serde(default)]
    pub synthetic_click: bool,
    /// Popup and extra-tab handling (default: bounded).
    #[serde(default)]
    pub tab_policy: TabPolicy,
    /// Maximum simultaneous tabs under `bounded`; clamped to 1..=8 (default 3).
    #[serde(default = "Dynamic::default_max_tabs")]
    pub max_tabs: u8,
    /// Chromium launch profile (default: standard).
    #[serde(default)]
    pub launch_profile: LaunchProfile,
    /// Observe only: navigate and observe, never act.
    #[serde(default)]
    pub observe_only: bool,
    /// Path patterns (same regex dialect as `scope.includePaths`) whose pages the browser
    /// plane always renders in `hybrid` mode, regardless of the dynamic-signal classifier.
    /// At most 100 patterns.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub always_browser_paths: Vec<String>,
    /// Isolated-world discovery hooks (`pushState`, `fetch`, `WebSocket`, `window.open`,
    /// listener recorder) feeding the frontier (default false).
    #[serde(default)]
    pub page_hooks: bool,
    /// Headless readiness preset (default: heuristic).
    #[serde(default)]
    pub page_load_strategy: PageLoadStrategy,
    /// Upper bound in milliseconds the readiness preset waits for the DOM;
    /// clamped to 0..=60,000 (default 5,000).
    #[serde(default = "Dynamic::default_dom_wait_ms")]
    pub dom_wait_ms: u32,
    /// Compatibility flag `-max-scroll-steps`: after a page settles the browser plane scrolls down in
    /// viewport steps (at most this many, stopping when the page height stops growing) so lazy
    /// content loads and its links are discovered; 0 is off; clamped to 0..=100 (default 0).
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub max_scroll_steps: u8,
    /// Block requests to cookie-consent banner hosts and scripts from the bundled rule list
    /// (`crawlx-browser/data/consent_block.txt`) in the browser plane (default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub block_consent_banners: bool,
    /// Compatibility flag `-interaction-depth`: maximum consecutive interactions from one page state
    /// before the driver returns to the page URL; 0 is unlimited; clamped to 0..=100.
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub interaction_depth: u8,
    /// Compatibility flag `-interaction-selector`: CSS selectors; when non-empty only matching elements
    /// are interaction candidates. At most 100 selectors of 512 bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interaction_selector: Vec<String>,
    /// Compatibility flag `-interaction-exclude`: CSS selectors whose matching elements (and descendants)
    /// are never interaction candidates. At most 100 selectors of 512 bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interaction_exclude: Vec<String>,
    /// Compatibility flag `-interaction-settle`: milliseconds waited after each interaction before the
    /// page is observed again; 0 uses the readiness preset; clamped to 0..=60,000.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub interaction_settle_ms: u32,
    /// Compatibility flag `-interaction-duration`: wall-clock seconds the interaction phase of a session
    /// may run before it stops exploring; 0 is bounded only by `limits.durationSeconds`;
    /// clamped to 0..=604,800.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub interaction_duration_seconds: u32,
    /// Compatibility flag `-max-failure-count`: consecutive dropped actions after which a session stops;
    /// 0 keeps the driver default (30); clamped to 0..=1,000.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub max_failure_count: u32,
    /// Additional settled browser renditions retained per URL and role (default 8, at most 128).
    /// Zero keeps the first rendition and records a cap outcome for subsequent changed renditions.
    #[serde(
        default = "Dynamic::default_max_page_revisits",
        skip_serializing_if = "Dynamic::is_default_max_page_revisits"
    )]
    pub max_page_revisits: u16,
    /// Compatibility flag `-enable-diagnostics`: record per-session driver diagnostics (steps, drops,
    /// recoveries, tab evictions, state counts) in the run report (default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub enable_diagnostics: bool,
    /// Compatibility flag `-time-stable`: quiet window in milliseconds the page's DOM and network must stay
    /// unchanged before a page counts as settled. `0` keeps the `pageLoadStrategy` preset; a
    /// positive value raises both idle windows of the quiescence policy to at least this long
    /// and the settle hard timeout to at least twice as long (the window is capped at half the
    /// timeout). Clamped to 0..=60,000.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub time_stable_ms: u32,
    /// Behaviour-changing page hooks (all off by default):
    /// timer acceleration, `form.reset()` and `window.close()` prevention. Independent of
    /// [`Self::page_hooks`] (the discovery recorder); any option that is on tags the session
    /// `page_hooks` with the option names so fingerprint studies can exclude it.
    #[serde(default, skip_serializing_if = "PageHookOptions::is_default")]
    pub page_hook_options: PageHookOptions,
    /// Inject own-authored `stealth.js` equivalents (`navigator.webdriver`, `plugins`,
    /// `languages`, `window.chrome`, `Permissions.query`, WebGL vendor/renderer) into every
    /// document (default false). Needs `launchProfile = stealth`, so it
    /// is gated like the stealth profile: `test_environment` or `authorized_security_test`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub stealth_patches: bool,
    /// Compatibility API `profile{name,saveChanges}`: a named persistent browser profile (cookies,
    /// local storage) kept under the worker's `--profiles-dir` and reused across runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_profile: Option<BrowserProfile>,
}

impl Dynamic {
    /// Validate arm shape without depending on the strategy implementation crate.
    ///
    /// # Errors
    /// Returns an invalid-config error for disabled/model-backed strategies, empty arm sets,
    /// duplicate versions, version zero or zero weights. The registry checks availability.
    pub fn validate_strategy_arms(&self) -> Result<(), CoreError> {
        for (name, arms) in &self.strategy_arms {
            let reason = if *name == StrategyName::System1 || !self.strategies.contains(name) {
                Some(format!("{name:?} must be an enabled deterministic strategy"))
            } else if arms.is_empty() {
                Some(format!("{name:?} must have at least one arm"))
            } else if arms.iter().any(|arm| arm.version == 0 || arm.weight == 0) {
                Some(format!("{name:?} versions and weights must be positive"))
            } else {
                let mut versions = std::collections::BTreeSet::new();
                arms.iter()
                    .find(|arm| !versions.insert(arm.version))
                    .map(|arm| format!("{name:?} version {} appears twice", arm.version))
            };
            if let Some(reason) = reason {
                return Err(CoreError::Invalid {
                    field: "dynamic.strategyArms",
                    reason,
                });
            }
        }
        Ok(())
    }

    /// `dynamic.strategies`: the default set runs on any build without operator
    /// gate evidence. `event_driven` acts on what the previous action exposed before another
    /// action hides it again (menus, dialogs). `state_novelty` and `enablement` may suppress
    /// frontier entries, so they are opt-in and admitted only with G1 (`check_gates`).
    fn default_strategies() -> Vec<StrategyName> {
        vec![StrategyName::InteractionBfs, StrategyName::EventDriven]
    }
    const fn default_max_tabs() -> u8 {
        3
    }
    const fn default_max_page_revisits() -> u16 {
        8
    }
    fn is_default_max_page_revisits(value: &u16) -> bool {
        *value == Self::default_max_page_revisits()
    }
    const fn default_dom_wait_ms() -> u32 {
        5_000
    }
}

impl Default for Dynamic {
    fn default() -> Self {
        Self {
            enabled: true,
            strategies: Self::default_strategies(),
            strategy_arms: BTreeMap::new(),
            system1_mode: System1Mode::Off,
            llm_planner: LlmPlannerMode::Off,
            synthetic_click: false,
            tab_policy: TabPolicy::Bounded,
            max_tabs: Self::default_max_tabs(),
            launch_profile: LaunchProfile::Standard,
            observe_only: false,
            always_browser_paths: Vec::new(),
            page_hooks: false,
            page_load_strategy: PageLoadStrategy::Heuristic,
            dom_wait_ms: Self::default_dom_wait_ms(),
            max_scroll_steps: 0,
            block_consent_banners: false,
            interaction_depth: 0,
            interaction_selector: Vec::new(),
            interaction_exclude: Vec::new(),
            interaction_settle_ms: 0,
            interaction_duration_seconds: 0,
            max_failure_count: 0,
            max_page_revisits: Self::default_max_page_revisits(),
            enable_diagnostics: false,
            time_stable_ms: 0,
            page_hook_options: PageHookOptions::default(),
            stealth_patches: false,
            browser_profile: None,
        }
    }
}

/// `safety`: guard rails on what the crawl may touch and do.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Safety {
    /// Safety profile bounding the other safety options (default: read-only).
    #[serde(default)]
    pub profile: SafetyProfile,
    /// Honor robots.txt; `false` requires an authorization record (default true).
    #[serde(default = "t")]
    pub respect_robots_txt: bool,
    /// Allow private-network targets; requires an authorization record (default false).
    #[serde(default)]
    pub allow_private_networks: bool,
    /// Whether actions may communicate outside the target (default: deny).
    #[serde(default)]
    pub external_communication: ExternalCommunication,
    /// Handling of destructive actions (default: deny).
    #[serde(default)]
    pub destructive_actions: DestructiveActions,
    /// Authorization record covering this crawl; `None` when no record applies.
    #[serde(default)]
    pub authorization_record_ref: Option<crate::ids::AuthorizationRecordId>,
}

impl Default for Safety {
    fn default() -> Self {
        Self {
            profile: SafetyProfile::ReadOnly,
            respect_robots_txt: true,
            allow_private_networks: false,
            external_communication: ExternalCommunication::Deny,
            destructive_actions: DestructiveActions::Deny,
            authorization_record_ref: None,
        }
    }
}

/// `capture`: which artifacts are persisted while crawling.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Capture {
    /// HTML capture policy (default: checkpoint).
    #[serde(default)]
    pub html: CaptureMode,
    /// DOM snapshot capture policy (default: checkpoint).
    #[serde(default)]
    pub dom_snapshot: CaptureMode,
    /// Screenshot capture policy (default: on novel state).
    #[serde(default)]
    pub screenshot: ScreenshotMode,
    /// How much of response bodies is persisted (default: metadata only).
    #[serde(default)]
    pub response_bodies: ResponseBodies,
    /// Which traffic trust lanes are persisted (default: trusted and diagnostic).
    #[serde(default)]
    pub traffic: TrafficCapture,
    /// Which capture backend records traffic (default: CDP).
    #[serde(default)]
    pub backend: CaptureBackend,
    /// Explicit bounded browser evidence; disabled unless requested.
    #[serde(default)]
    pub browser: crate::browser_capture::BrowserEvidenceConfig,
}

/// `output.webhook`: where run events are delivered.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Webhook {
    /// Endpoint receiving event deliveries; checked against the egress policy.
    pub url: url::Url,
    /// Event names to deliver; empty selects the server default (terminal events).
    #[serde(default)]
    pub events: Vec<String>,
}

/// `output`: per-page result shape and delivery.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    /// Optional retained-resource archive, finalized before the run becomes terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<crate::archive::ArchiveConfigV1>,
    /// Representations returned for each page (default: markdown, links, metadata).
    #[serde(default = "Output::default_formats")]
    pub formats: Vec<OutputFormat>,
    /// Webhook receiving run events; `None` disables delivery.
    #[serde(default)]
    pub webhook: Option<Webhook>,
    /// Extract only the main content of the page (default true).
    #[serde(default = "t")]
    pub only_main_content: bool,
    /// Milliseconds to wait before extracting a page; 0 means no extra wait (default 0).
    #[serde(default)]
    pub wait_for_ms: u32,
    /// CSS selectors kept when extracting (compatibility API `includeTags`).
    #[serde(default)]
    pub include_tags: Vec<String>,
    /// CSS selectors dropped when extracting (compatibility API `excludeTags`).
    #[serde(default)]
    pub exclude_tags: Vec<String>,
    /// Record out-of-scope endpoints as `leaf_only` entries that are never fetched (default false).
    #[serde(default)]
    pub include_out_of_scope: bool,
    /// Keep the request and response as raw HTTP text (`request.raw`, `response.raw`,
    /// `-store-response`); bodies are bounded by `fetch.maxResponseBytes` (default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub capture_raw: bool,
}

impl Output {
    fn default_formats() -> Vec<OutputFormat> {
        vec![
            OutputFormat::Markdown,
            OutputFormat::Links,
            OutputFormat::Metadata,
        ]
    }
}

impl Default for Output {
    fn default() -> Self {
        Self {
            archive: None,
            formats: Self::default_formats(),
            webhook: None,
            only_main_content: true,
            wait_for_ms: 0,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
            include_out_of_scope: false,
            capture_raw: false,
        }
    }
}

/// `retention`: how long artifacts survive after the run finishes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Retention {
    /// Retention mode (default: standard).
    #[serde(default)]
    pub mode: RetentionMode,
    /// Days artifacts are kept; clamped per mode and forced to 0 under `zdr` (default 7).
    #[serde(default = "Retention::default_days")]
    pub days: u16,
}

impl Retention {
    const fn default_days() -> u16 {
        7
    }
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            mode: RetentionMode::Standard,
            days: Self::default_days(),
        }
    }
}

/// `politeness`: pacing limits against each target origin.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Politeness {
    /// Minimum milliseconds between requests to one origin; at least 50 (default 250).
    #[serde(default = "Politeness::default_delay")]
    pub delay_ms: u32,
    /// Maximum concurrent requests per origin; clamped to 1..=8 (default 1).
    #[serde(default = "Politeness::default_in_flight")]
    pub max_in_flight_per_origin: u8,
    /// Global requests per second across all hosts; `None` is unlimited (clamped to ≥1).
    #[serde(default)]
    pub global_rps: Option<u32>,
    /// Global requests per minute across all hosts; `None` is unlimited (clamped to ≥1).
    #[serde(default)]
    pub global_rpm: Option<u32>,
    /// Requests per second per host; `None` is unlimited (clamped to ≥1).
    #[serde(default)]
    pub per_host_rps: Option<u32>,
    /// Requests per minute per host; `None` is unlimited (clamped to ≥1).
    #[serde(default)]
    pub per_host_rpm: Option<u32>,
    /// Maximum concurrent fetches across all hosts; clamped to 1..=256 (default 10).
    #[serde(default = "Politeness::default_max_concurrency")]
    pub max_concurrency: u16,
}

impl Politeness {
    const fn default_delay() -> u32 {
        250
    }
    const fn default_in_flight() -> u8 {
        1
    }
    const fn default_max_concurrency() -> u16 {
        10
    }
}

impl Default for Politeness {
    fn default() -> Self {
        Self {
            delay_ms: Self::default_delay(),
            max_in_flight_per_origin: Self::default_in_flight(),
            global_rps: None,
            global_rpm: None,
            per_host_rps: None,
            per_host_rpm: None,
            max_concurrency: Self::default_max_concurrency(),
        }
    }
}

/// Which part of the parent page's URL an outbound request may carry as its `Referer`
/// (`fetch.referrerPolicy`). The wire names are the standard policy tokens.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReferrerPolicy {
    /// Never send a `Referer` (default).
    #[default]
    NoReferrer,
    /// Send the full referrer, except on an `https` to `http` downgrade.
    NoReferrerWhenDowngrade,
    /// Send the full referrer to the same origin only.
    SameOrigin,
    /// Send only the referrer's origin.
    Origin,
    /// Send only the referrer's origin, except on an `https` to `http` downgrade.
    StrictOrigin,
    /// Send the full referrer to the same origin and only the origin elsewhere.
    OriginWhenCrossOrigin,
    /// Like `origin-when-cross-origin`, and nothing on an `https` to `http` downgrade.
    StrictOriginWhenCrossOrigin,
    /// Always send the full referrer.
    UnsafeUrl,
}

impl ReferrerPolicy {
    /// Whether this is the default policy ([`Self::NoReferrer`]).
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::NoReferrer)
    }

    /// The standard policy token, identical to the serde form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoReferrer => "no-referrer",
            Self::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",
            Self::SameOrigin => "same-origin",
            Self::Origin => "origin",
            Self::StrictOrigin => "strict-origin",
            Self::OriginWhenCrossOrigin => "origin-when-cross-origin",
            Self::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",
            Self::UnsafeUrl => "unsafe-url",
        }
    }
}

/// `fetch`: static-plane request tuning.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Fetch {
    /// Maximum response body bytes read; clamped to 1 KiB..=64 MiB (default 8 MiB).
    #[serde(default = "Fetch::default_max_response_bytes")]
    pub max_response_bytes: u64,
    /// Per-request timeout in milliseconds; clamped to 100..=300,000 (default 10,000).
    #[serde(default = "Fetch::default_timeout_ms")]
    pub timeout_ms: u32,
    /// Retries after a retryable failure; clamped to 0..=10 (default 1).
    #[serde(default = "Fetch::default_retries")]
    pub retries: u8,
    /// Follow HTTP redirects (default true).
    #[serde(default = "t")]
    pub follow_redirects: bool,
    /// Upstream proxy for the fetch plane; egress checks still apply (`http`, `https`, `socks5`).
    #[serde(default)]
    pub proxy: Option<url::Url>,
    /// Compatibility flag `-resolvers`: DNS servers (`ip` or `ip:port`) the fetch plane resolves hosts
    /// with instead of the system resolver; at most 8. Egress checks apply to the answers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
    /// Headers added to every request of both planes (compatibility flag `-H`, compatibility API `headers`); names
    /// are lower-cased. `Host`, `Content-Length`, `Cookie`, `User-Agent`, `Proxy-*` and
    /// `Crawlx-*` are rejected. Values are secrets: literals or credential references
    /// (`env://`, `file://`, `vault://`, `cloud-sm://`), never logged. See [`Fetch::set_header`].
    #[serde(default, skip_serializing_if = "ExtraHeaders::is_empty")]
    pub extra_headers: ExtraHeaders,
    /// Cookies sent by both planes to hosts matching `domain`/`path` (default: the seed's
    /// registrable domain and `/`); at most 64. Values are secrets like header values.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookies: Vec<FetchCookie>,
    /// `User-Agent` of both planes; `None` keeps `crawlx/<version>` for the fetch plane and the
    /// browser's own value for the browser plane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// User-agent token robots.txt groups are matched with (compatibility API `robotsUserAgent`);
    /// `None` uses `userAgent`, else the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub robots_user_agent: Option<String>,
    /// Accept any server certificate on both planes (default false; the compatibility API maps
    /// its default `true` here explicitly).
    #[serde(default, skip_serializing_if = "is_false")]
    pub skip_tls_verification: bool,
    /// Synthetic seeded ClientHello randomization, URL-only mode (not browser impersonation).
    #[serde(default)]
    pub tls_impersonation: TlsImpersonation,
    /// Optional HEAD preflight before a static GET; absence sends no preflight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight: Option<crate::acquisition::HeadPreflight>,
    /// Optional bounded MIME, charset and HTTP status overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declaration: Option<crate::acquisition::ResponseDeclaration>,
    /// Response overflow handling; absence preserves truncation at the body limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oversize: Option<crate::acquisition::OversizePolicy>,
    /// Digest of the installed native HTTP identity profile; absence keeps the ordinary transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_profile: Option<crate::hash::Digest>,
    /// Operator registry id of an approved HTML acquisition service; never an endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acquisition_service: Option<String>,
    /// Outbound `Referer` policy of the static plane for a URL found on a page (default
    /// `no-referrer`: none is sent). The referrer is the parent page's URL without credentials or
    /// fragment and with secret query parameters removed; it is recomputed for every redirect hop.
    /// A `referer` header configured in `extraHeaders` is never replaced.
    #[serde(default, skip_serializing_if = "ReferrerPolicy::is_default")]
    pub referrer_policy: ReferrerPolicy,
}

impl Fetch {
    const fn default_max_response_bytes() -> u64 {
        8 * 1024 * 1024
    }
    const fn default_timeout_ms() -> u32 {
        10_000
    }
    const fn default_retries() -> u8 {
        1
    }
}

impl Default for Fetch {
    fn default() -> Self {
        Self {
            max_response_bytes: Self::default_max_response_bytes(),
            timeout_ms: Self::default_timeout_ms(),
            retries: Self::default_retries(),
            follow_redirects: true,
            proxy: None,
            resolvers: Vec::new(),
            extra_headers: ExtraHeaders::new(),
            cookies: Vec::new(),
            user_agent: None,
            robots_user_agent: None,
            skip_tls_verification: false,
            tls_impersonation: TlsImpersonation::Off,
            preflight: None,
            declaration: None,
            oversize: None,
            identity_profile: None,
            acquisition_service: None,
            referrer_policy: ReferrerPolicy::NoReferrer,
        }
    }
}

/// `extract.formFill`: compatibility flags `-automatic-form-fill` / `-form-config` for the URL plane.
///
/// Static forms are completed with deterministic values: a configured value per field class,
/// else a value derived from the crawl seed. GET forms become fetchable URLs; every other
/// method is only recorded (`request.method/body/raw` of the form request), never sent.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct FormFill {
    /// Fill static forms (`-aff`, default false).
    #[serde(default)]
    pub enabled: bool,
    /// Value of email inputs (`-fc` key `email`); seed-derived when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Value of color inputs (`-fc` key `color`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Value of password inputs (`-fc` key `password`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Value of telephone inputs (`-fc` key `phone`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    /// Value of every other text-like input (`-fc` key `placeholder`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
}

/// JavaScript endpoint miners selected by `extract.javascript.mode`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum JavascriptMode {
    /// Disable JavaScript and textual regex mining; keep structural HTML/header discovery.
    Off,
    /// Run regex mining only, including malformed JavaScript.
    Regex,
    /// Run AST mining only; malformed or oversized scripts yield no AST endpoints.
    Ast,
    /// Run both miners; regex remains available when AST parsing fails (native default).
    #[default]
    Both,
}

impl JavascriptMode {
    /// Whether the regex miner is selected.
    #[must_use]
    pub const fn regex(self) -> bool {
        matches!(self, Self::Regex | Self::Both)
    }

    /// Whether the AST miner is selected.
    #[must_use]
    pub const fn ast(self) -> bool {
        matches!(self, Self::Ast | Self::Both)
    }
}

/// JavaScript endpoint extraction policy.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct Javascript {
    /// Selected miners; `both` preserves native discovery behavior.
    #[serde(default)]
    pub mode: JavascriptMode,
}

/// `extract`: static extraction options.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Extract {
    /// JavaScript endpoint miners and malformed-source fallback policy.
    #[serde(default)]
    pub javascript: Javascript,
    /// Optional native article extraction and quality policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<crate::extraction::ExtractionPolicyV1>,
    /// Native content outputs, parsed and validated by the extraction crate before execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<serde_json::Value>,
    /// Native decoding options, parsed and validated by the extraction crate before execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode: Option<serde_json::Value>,
    /// Native markup retention, parsed and validated by the extraction crate before execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markup: Option<serde_json::Value>,
    /// Custom regex fields stored in `pages.metadata.custom_fields`; at most 50.
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// Detect secrets in bodies and headers, storing kind and keyed hash only (default false).
    #[serde(default)]
    pub detect_secrets: bool,
    /// Extract static forms into `pages.forms` (default true).
    #[serde(default = "t")]
    pub forms: bool,
    /// Classify `page_type` (default true).
    #[serde(default = "t")]
    pub page_type: bool,
    /// Collect the XHR/fetch requests the browser plane observed on each page into
    /// `pages.metadata.xhr_requests` (compatibility flag `-xhr-extraction`, default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub xhr: bool,
    /// Attach the `knowledgebase` object (`page_type`, `forms`, `secrets`, `endpoints`) to
    /// records (compatibility flag `-knowledge-base`; forces `pageType` and `forms`; default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub knowledge_base: bool,
    /// Classify discovered endpoints as REST, GraphQL, SOAP, XHR or static into
    /// `pages.metadata.endpoints` (compatibility flag `-kb-endpoints`, default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub kb_endpoints: bool,
    /// Send detected tokens to the provider validation endpoints the operator lists in
    /// `crawlx-extract/data/secret_validators.json` (compatibility flag `-kb-validate-secrets`;
    /// requires `detectSecrets`; default false).
    #[serde(default, skip_serializing_if = "is_false")]
    pub validate_secrets: bool,
    /// Static form filling (`-aff`, `-fc`).
    #[serde(default)]
    pub form_fill: FormFill,
}

impl Default for Extract {
    fn default() -> Self {
        Self {
            javascript: Javascript::default(),
            content: None,
            outputs: None,
            decode: None,
            markup: None,
            custom_fields: Vec::new(),
            detect_secrets: false,
            forms: true,
            page_type: true,
            xhr: false,
            knowledge_base: false,
            kb_endpoints: false,
            validate_secrets: false,
            form_fill: FormFill::default(),
        }
    }
}

/// Identity rollout policy (`crawl.identity.version`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum IdentityVersion {
    /// Original language-agnostic identity (default).
    #[default]
    V1,
    /// Locale-aware identity.
    V2,
    /// Compute and persist both versions; make decisions with V1.
    Dual,
}

impl IdentityVersion {
    /// Version used for decisions and recorded replay paths.
    #[must_use]
    pub const fn decision_version(self) -> u16 {
        match self {
            Self::V1 | Self::Dual => 1,
            Self::V2 => 2,
        }
    }
}

/// Identity rollout settings.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
#[non_exhaustive]
pub struct IdentityConfig {
    /// Identity version, defaulting to V1.
    #[serde(default)]
    pub version: IdentityVersion,
}

/// Durable crawl algorithm settings.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
#[non_exhaustive]
pub struct CrawlConfig {
    /// Element identity rollout.
    #[serde(default)]
    pub identity: IdentityConfig,
    /// Opt-in CAPTCHA solving; absent by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub captcha: Option<crate::captcha::CaptchaConfig>,
}

/// The create request.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateCrawl {
    /// Absolute `http`/`https` URL where the crawl starts.
    pub seed_url: url::Url,
    /// Crawl mode (default: hybrid).
    #[serde(default)]
    pub mode: CrawlMode,
    /// Durable crawl algorithm settings (`crawl.identity.version`).
    #[serde(default)]
    pub crawl: CrawlConfig,
    /// Seed driving every tie-break; `None` derives one from `seed_url` (see `effective_seed`).
    #[serde(default)]
    pub seed: Option<u64>,
    /// Crawl budgets.
    #[serde(default)]
    pub limits: Limits,
    /// URL scope rules.
    #[serde(default)]
    pub scope: Scope,
    /// Principals to crawl as; empty means the implicit `anonymous` role.
    #[serde(default)]
    pub roles: Vec<Role>,
    /// Runs per role; clamped to 1..=10, with roles × runs at most 64 (default 1).
    #[serde(default = "CreateCrawl::default_runs_per_role")]
    pub runs_per_role: u8,
    /// Order of roles inside each round (default: declared).
    #[serde(default)]
    pub role_order: RoleOrder,
    /// Whether roles share one target instance or have replicas (default: shared).
    #[serde(default)]
    pub target_isolation: TargetIsolation,
    /// Keep cross-principal attribution; `false` lifts the round-robin barrier (default true).
    #[serde(default = "t")]
    pub cross_principal_attribution: bool,
    /// Browser plane configuration.
    #[serde(default)]
    pub dynamic: Dynamic,
    /// Safety guard rails.
    #[serde(default)]
    pub safety: Safety,
    /// Artifact capture policy.
    #[serde(default)]
    pub capture: Capture,
    /// Per-page output options.
    #[serde(default)]
    pub output: Output,
    /// Artifact retention policy.
    #[serde(default)]
    pub retention: Retention,
    /// Request pacing per origin.
    #[serde(default)]
    pub politeness: Politeness,
    /// Static fetch tuning.
    #[serde(default)]
    pub fetch: Fetch,
    /// Optional native acquisition validation and shared attempt budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acquisition: Option<crate::acquisition::AcquisitionPolicyV1>,
    /// Optional explicit response cache and offline development replay policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<crate::cache::CachePolicyV1>,
    /// Cache authority stamped by API admission; local absence isolates reuse to one run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_principal: Option<uuid::Uuid>,
    /// First-match acquisition routes; operator registry controls delegate capabilities.
    #[serde(default)]
    pub protocol: crate::protocol::ProtocolConfigV1,
    /// Optional bounded request queue, identity and recrawl policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orchestration: Option<crate::orchestration::OrchestrationConfigV1>,
    /// Reviewed compiled extension pipeline; no executable caller code is accepted.
    #[serde(default)]
    pub extensions: crate::extensions::ExtensionPipelineV1,
    /// Optional immutable reviewed request, actor, item and discovery recipe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_recipe: Option<crate::extension_recipes::ExtensionRecipeV1>,
    /// Bounded run-local accepted-item, feed and key-value namespaces.
    #[serde(default)]
    pub datasets: crate::dataset::DatasetConfigV1,
    /// Extraction options.
    #[serde(default)]
    pub extract: Extract,
    /// Compatibility-API scrape job: when set, every page of the run is produced by the
    /// scrape engine with these options and the run is reported as a crawl or batch scrape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrape: Option<crate::scrape::ScrapeJob>,
}

impl CreateCrawl {
    const fn default_runs_per_role() -> u8 {
        1
    }

    /// Minimal request for `seed_url`.
    #[must_use]
    pub fn new(seed_url: url::Url) -> Self {
        Self {
            seed_url,
            mode: CrawlMode::Hybrid,
            crawl: CrawlConfig::default(),
            seed: None,
            limits: Limits::default(),
            scope: Scope::default(),
            roles: Vec::new(),
            runs_per_role: 1,
            role_order: RoleOrder::Declared,
            target_isolation: TargetIsolation::Shared,
            cross_principal_attribution: true,
            dynamic: Dynamic::default(),
            safety: Safety::default(),
            capture: Capture::default(),
            output: Output::default(),
            retention: Retention::default(),
            politeness: Politeness::default(),
            fetch: Fetch::default(),
            acquisition: None,
            cache: None,
            cache_principal: None,
            protocol: crate::protocol::ProtocolConfigV1::default(),
            orchestration: None,
            extensions: crate::extensions::ExtensionPipelineV1::default(),
            extension_recipe: None,
            datasets: crate::dataset::DatasetConfigV1::default(),
            extract: Extract::default(),
            scrape: None,
        }
    }

    /// Refuse unsupported refresh combinations before any target or robots traffic.
    ///
    /// # Errors
    /// Refresh requires stateless native static HTTP with no protocol routing or actions.
    pub fn validate_meta_refresh(&self) -> Result<(), crate::acquisition::AcquisitionPolicyError> {
        if !self
            .acquisition
            .as_ref()
            .is_some_and(|policy| policy.meta_refresh.is_some())
        {
            return Ok(());
        }
        if self.mode != CrawlMode::Static
            || !self.roles.is_empty()
            || !self.protocol.routes.is_empty()
            || self.dynamic.browser_profile.is_some()
            || self
                .scrape
                .as_ref()
                .is_some_and(|job| job.options.needs_browser() || !job.options.actions.is_empty())
        {
            return Err(crate::acquisition::AcquisitionPolicyError(
                "meta refresh requires stateless native static GET without actions or protocol routes",
            ));
        }
        if [
            self.cache.as_ref(),
            self.scrape.as_ref().and_then(|job| job.options.cache.as_ref()),
        ]
        .into_iter()
        .flatten()
        .any(|policy| policy.freshness != crate::cache::CacheFreshnessV1::Retained)
        {
            return Err(crate::acquisition::AcquisitionPolicyError(
                "meta refresh live cache freshness is unavailable; use retained replay",
            ));
        }
        Ok(())
    }

    /// Whether acquisition must use retained responses without any target-network requests.
    /// Explicit native cache policy overrides legacy facade cache-only controls.
    #[must_use]
    pub fn cache_only(&self) -> bool {
        self.cache
            .as_ref()
            .or_else(|| self.scrape.as_ref().and_then(|job| job.options.cache.as_ref()))
            .map_or_else(
                || {
                    self.scrape
                        .as_ref()
                        .is_some_and(|job| job.options.lockdown || job.options.min_age_ms.is_some())
                },
                crate::cache::CachePolicyV1::cache_only,
            )
    }

    /// The effective seed: the caller's, or derived from the seed URL so that
    /// omission is still reproducible for the same request.
    #[must_use]
    pub fn effective_seed(&self) -> CrawlSeed {
        CrawlSeed(self.seed.unwrap_or_else(|| {
            let d = crate::hash::Digest::of("crawlx/default-seed/v1", self.seed_url.as_str().as_bytes());
            u64::from_le_bytes([d.0[0], d.0[1], d.0[2], d.0[3], d.0[4], d.0[5], d.0[6], d.0[7]])
        }))
    }

    /// Role list with the implicit `anonymous` principal when none is declared.
    #[must_use]
    pub fn effective_roles(&self) -> Vec<Role> {
        if self.roles.is_empty() {
            vec![Role {
                name: "anonymous".to_owned(),
                credential_ref: None,
                login_plan: None,
                replica_base_url: None,
            }]
        } else {
            self.roles.clone()
        }
    }

    /// Round-robin barrier applies unless the caller declared isolation or
    /// gave up cross-principal attribution.
    #[must_use]
    pub const fn parallel_roles_allowed(&self) -> bool {
        matches!(self.target_isolation, TargetIsolation::PerRoleReplica) || !self.cross_principal_attribution
    }

    /// Normalize (clamp, fill defaults) and validate. Returns every violation,
    /// not just the first.
    ///
    /// Normalization does not grant model authority. Admission callers must also
    /// call [`Self::check_gates`] with this build's verified gate status.
    ///
    /// # Errors
    ///
    /// Returns every violation found: a non-`http(s)` or hostless seed URL, a
    /// mode/`dynamic.enabled` conflict, missing strategies or role replica URLs,
    /// duplicate roles, over-large role × run counts, missing authorization
    /// records, safety-profile conflicts, full
    /// response bodies under `zdr` retention, over-long or over-many scope
    /// patterns/host exclusions/extensions, an invalid `fetch.proxy`, TLS randomization
    /// outside URL-only static mode or with a scrape job, a zero
    /// `scope.maxPagesPerHost`, a non-finite similarity threshold, and
    /// malformed `extract.customFields` (name, missing regex, group index).
    pub fn normalize(&mut self) -> Result<(), Vec<CoreError>> {
        let mut errs = Vec::new();
        if let Some(recipe) = &self.extension_recipe {
            if self.extensions.configured() && self.extensions != recipe.pipeline {
                errs.push(CoreError::Conflict {
                    a: "extensions",
                    b: "extensionRecipe.pipeline",
                    reason: "only one effective extension pipeline may be configured".into(),
                });
            } else {
                self.extensions = recipe.pipeline.clone();
            }
        }
        if let Err(reason) = self.capture.browser.validate() {
            errs.push(CoreError::Invalid {
                field: "capture.browser",
                reason: reason.to_owned(),
            });
        }
        if self.capture.browser.enabled() && self.mode == CrawlMode::Static {
            errs.push(CoreError::Conflict {
                a: "capture.browser",
                b: "mode",
                reason: "browser evidence requires a browser-enabled crawl".to_owned(),
            });
        }
        if self.capture.browser.durable() && self.retention.mode == RetentionMode::Zdr {
            errs.push(CoreError::Conflict {
                a: "capture.browser",
                b: "retention.mode",
                reason: "durable browser evidence is refused in zdr".to_owned(),
            });
        }
        if let Some(archive) = &self.output.archive {
            if let Err(reason) = archive.validate() {
                errs.push(CoreError::Invalid {
                    field: "output.archive",
                    reason: reason.to_owned(),
                });
            }
            if self.retention.mode == RetentionMode::Zdr {
                errs.push(CoreError::Conflict {
                    a: "output.archive",
                    b: "retention.mode",
                    reason: "durable archives are forbidden for zero-data-retention runs".to_owned(),
                });
            }
            if archive.capture == crate::archive::ArchiveCapture::RequireComplete {
                errs.push(CoreError::Invalid {
                    field: "output.archive.capture",
                    reason: "complete original response and subresource capture is unavailable".to_owned(),
                });
            }
        }
        if let Err(error) = self.protocol.validate_public() {
            errs.push(CoreError::Invalid {
                field: "protocol",
                reason: error.to_string(),
            });
        }
        if !(1..=1_000_000).contains(&self.scope.max_known_urls) {
            errs.push(CoreError::Invalid {
                field: "scope.maxKnownUrls",
                reason: "must be between 1 and 1000000".to_owned(),
            });
        }
        if self.scope.sources.len() > 9
            || self
                .scope
                .sources
                .iter()
                .enumerate()
                .any(|(index, source)| self.scope.sources[..index].contains(source))
        {
            errs.push(CoreError::Invalid {
                field: "scope.sources",
                reason: "at most nine distinct discovery sources are allowed".to_owned(),
            });
        }
        if self.scope.discovery.is_none()
            && self.scope.sources.iter().any(|source| {
                !matches!(
                    source,
                    crate::discovery::DiscoverySourceV1::Html | crate::discovery::DiscoverySourceV1::Sitemap
                )
            })
        {
            errs.push(CoreError::Conflict {
                a: "scope.sources",
                b: "scope.discovery",
                reason: "non-HTML discovery sources require an explicit bounded discovery policy".to_owned(),
            });
        }
        if let Some(discovery) = &self.scope.discovery {
            if let Err(error) = discovery.validate() {
                errs.push(error);
            }
        }
        match (
            &self.cache,
            self.scrape.as_ref().and_then(|job| job.options.cache.as_ref()),
        ) {
            (Some(outer), Some(inner)) if outer != inner => errs.push(CoreError::Conflict {
                a: "cache",
                b: "scrape.options.cache",
                reason: "native cache policies must agree".to_owned(),
            }),
            (None, Some(inner)) => self.cache = Some(inner.clone()),
            _ => {}
        }
        if let Some(cache) = &self.cache {
            if let Err(error) = cache.validate() {
                errs.push(error);
            }
        }
        if let (Some(cache), Some(scrape)) = (&self.cache, &mut self.scrape) {
            scrape.options.cache = Some(cache.clone());
        }
        if let Err(error) = self.extensions.validate() {
            errs.push(CoreError::Invalid {
                field: "extensions",
                reason: error.to_string(),
            });
        }
        if let Some(recipe) = &self.extension_recipe {
            if let Err(error) = recipe.validate() {
                errs.push(CoreError::Invalid {
                    field: "extensionRecipe",
                    reason: error.to_string(),
                });
            }
        }
        if let Err(error) = self.datasets.validate() {
            errs.push(CoreError::Invalid {
                field: "datasets",
                reason: error.to_string(),
            });
        }
        if let Some(orchestration) = &self.orchestration {
            if let Err(error) = orchestration.validate() {
                errs.push(CoreError::Invalid {
                    field: "orchestration",
                    reason: error.to_string(),
                });
            }
        }
        if self.fetch.acquisition_service.is_some() && self.acquisition.is_none() {
            self.acquisition = Some(crate::acquisition::AcquisitionPolicyV1 {
                backend_ids: vec!["acquisition_service".to_owned()],
                ..Default::default()
            });
        }
        if (self.scope.discovery.is_some() || self.cache.is_some() || !self.protocol.routes.is_empty())
            && self.acquisition.is_none()
        {
            let mut acquisition = crate::acquisition::AcquisitionPolicyV1 {
                backend_ids: crate::protocol::required_native_backend_ids(&self.protocol),
                ..Default::default()
            };
            if self
                .scrape
                .as_ref()
                .is_some_and(|job| job.options.needs_browser())
            {
                acquisition.backend_ids.retain(|id| id != "native_browser");
                acquisition.backend_ids.insert(0, "native_browser".to_owned());
            }
            self.acquisition = Some(acquisition);
        }
        if let Some(acquisition) = &self.acquisition {
            if let Err(error) = self.validate_meta_refresh() {
                errs.push(CoreError::Invalid {
                    field: "acquisition.metaRefresh",
                    reason: error.to_string(),
                });
            }
            if let Err(error) = acquisition.validate() {
                errs.push(CoreError::Invalid {
                    field: "acquisition",
                    reason: error.to_string(),
                });
            }
            if let Err(error) = self.protocol.validate_acquisition(acquisition) {
                errs.push(CoreError::Invalid {
                    field: "protocol",
                    reason: error.to_string(),
                });
            }
            if self
                .scrape
                .as_ref()
                .is_some_and(|job| job.options.needs_browser())
                && acquisition
                    .backend_ids
                    .first()
                    .is_none_or(|id| id != "native_browser")
            {
                errs.push(CoreError::Conflict {
                    a: "acquisition.backendIds",
                    b: "scrape.options",
                    reason: "browser scrape options require native_browser as the primary backend".to_owned(),
                });
            }
            let service_backend = acquisition
                .backend_ids
                .iter()
                .any(|id| id == "acquisition_service");
            if service_backend != self.fetch.acquisition_service.is_some() {
                errs.push(CoreError::Conflict {
                    a: "fetch.acquisitionService",
                    b: "acquisition.backendIds",
                    reason: "the acquisition_service backend and fetch.acquisitionService require each other"
                        .to_owned(),
                });
            }
            if service_backend
                && (acquisition.backend_ids != ["acquisition_service"]
                    || !acquisition.fallback_backend_ids.is_empty())
            {
                errs.push(CoreError::Conflict {
                    a: "acquisition.backendIds",
                    b: "acquisition.fallbackBackendIds",
                    reason: "acquisition_service is the only backend and has no native fallback".to_owned(),
                });
            }
        }
        if (self.scope.discovery.is_some() || !self.datasets.stores.is_empty())
            && self.extract.content.is_none()
        {
            self.extract.content = Some(crate::extraction::ExtractionPolicyV1::default());
        }
        if self.extensions.requires_document() && self.extract.content.is_none() {
            errs.push(CoreError::Required {
                field: "extract.content",
                context: "document-transform extensions",
            });
        }
        if let Some(dataset) = &self.extensions.dataset {
            if !self
                .datasets
                .stores
                .iter()
                .any(|store| store.name == *dataset && store.schema_version == "document_item_v1")
            {
                errs.push(CoreError::Invalid {
                    field: "extensions.dataset",
                    reason: "the selected dataset must declare document_item_v1".to_owned(),
                });
            }
        }
        if self.mode != CrawlMode::Static
            && self.dynamic.enabled
            && self.extensions.requires_document()
            && self.extensions.dataset.is_none()
        {
            errs.push(CoreError::Required {
                field: "extensions.dataset",
                context: "dynamic document-transform extensions",
            });
        }
        if let Some(content) = &self.extract.content {
            if let Err(error) = content.validate() {
                errs.push(error);
            }
        }
        if let Some(captcha) = &self.crawl.captcha {
            if let Err(error) = captcha.validate() {
                errs.push(CoreError::Invalid {
                    field: "crawl.captcha",
                    reason: error.to_string(),
                });
            }
        }
        if self.crawl.captcha.is_some() && (self.mode == CrawlMode::Static || !self.dynamic.enabled) {
            errs.push(CoreError::Invalid {
                field: "crawl.captcha",
                reason: "captcha solving requires dynamic browser execution".to_owned(),
            });
        }
        match self.seed_url.scheme() {
            "http" | "https" => {}
            s => errs.push(CoreError::Invalid {
                field: "seedUrl",
                reason: format!("scheme {s} not allowed"),
            }),
        }
        if self.seed_url.host_str().is_none() {
            errs.push(CoreError::Invalid {
                field: "seedUrl",
                reason: "missing host".to_owned(),
            });
        }
        self.limits.urls = self.limits.urls.clamp(1, 1_000_000);
        self.limits.interactions = self.limits.interactions.clamp(0, 100_000);
        self.limits.states = self.limits.states.clamp(0, 100_000);
        self.limits.duration_seconds = self.limits.duration_seconds.clamp(1, 7 * 86_400);
        self.limits.items = self.limits.items.clamp(0, 1_000_000);
        self.limits.errors = self.limits.errors.clamp(0, 1_000_000);
        self.limits.idle_seconds = self.limits.idle_seconds.clamp(0, 7 * 86_400);
        self.limits.disk_pressure_permille = self.limits.disk_pressure_permille.min(1000);
        self.scope.max_url_length = self.scope.max_url_length.clamp(256, 65_536);
        self.scope.max_discovery_depth = self.scope.max_discovery_depth.min(100);
        self.runs_per_role = self.runs_per_role.clamp(1, 10);
        self.dynamic.max_tabs = self.dynamic.max_tabs.clamp(1, 8);
        if self.mode == CrawlMode::Static {
            self.dynamic.enabled = false;
        } else if !self.dynamic.enabled {
            errs.push(CoreError::Conflict {
                a: "mode",
                b: "dynamic.enabled",
                reason: "dynamic or hybrid mode requires dynamic.enabled".to_owned(),
            });
        }
        if self.fetch.tls_impersonation != TlsImpersonation::Off
            && (self.mode != CrawlMode::Static || self.scrape.is_some())
        {
            errs.push(CoreError::Conflict {
                a: "fetch.tlsImpersonation",
                b: "mode",
                reason: "TLS randomization requires URL-only static mode without a scrape job".to_owned(),
            });
        }
        if self.dynamic.enabled && self.dynamic.strategies.is_empty() {
            errs.push(CoreError::Required {
                field: "dynamic.strategies",
                context: "dynamic plane",
            });
        }
        if let Err(error) = self.dynamic.validate_strategy_arms() {
            errs.push(error);
        }
        self.dynamic.always_browser_paths.retain(|p| !p.trim().is_empty());
        if self.dynamic.always_browser_paths.len() > 100 {
            errs.push(CoreError::Invalid {
                field: "dynamic.alwaysBrowserPaths",
                reason: "at most 100 patterns".to_owned(),
            });
        }
        if !self.dynamic.always_browser_paths.is_empty() && self.mode != CrawlMode::Hybrid {
            errs.push(CoreError::Conflict {
                a: "mode",
                b: "dynamic.alwaysBrowserPaths",
                reason: "alwaysBrowserPaths only applies to hybrid mode".to_owned(),
            });
        }
        let roles = self.effective_roles();
        if roles.len() * usize::from(self.runs_per_role) > 64 {
            errs.push(CoreError::Invalid {
                field: "runsPerRole",
                reason: "roles × runs exceeds 64".to_owned(),
            });
        }
        let mut names = std::collections::BTreeSet::new();
        for r in &roles {
            if !names.insert(r.name.as_str()) {
                errs.push(CoreError::Invalid {
                    field: "roles",
                    reason: format!("duplicate role {}", r.name),
                });
            }
            if self.target_isolation == TargetIsolation::PerRoleReplica && r.replica_base_url.is_none() {
                errs.push(CoreError::Required {
                    field: "roles[].replicaBaseUrl",
                    context: "per_role_replica",
                });
            }
        }
        if self.safety.profile == SafetyProfile::AuthorizedSecurityTest
            && self.safety.authorization_record_ref.is_none()
        {
            errs.push(CoreError::Required {
                field: "safety.authorizationRecordRef",
                context: "authorized_security_test",
            });
        }
        if self.safety.allow_private_networks && self.safety.authorization_record_ref.is_none() {
            errs.push(CoreError::Required {
                field: "safety.authorizationRecordRef",
                context: "allowPrivateNetworks",
            });
        }
        if !self.safety.respect_robots_txt && self.safety.authorization_record_ref.is_none() {
            errs.push(CoreError::Required {
                field: "safety.authorizationRecordRef",
                context: "respectRobotsTxt=false",
            });
        }
        if self.safety.profile == SafetyProfile::ReadOnly {
            if self.safety.external_communication != ExternalCommunication::Deny {
                errs.push(CoreError::Conflict {
                    a: "safety.externalCommunication",
                    b: "safety.profile",
                    reason: "test_sinks requires test_environment or stronger".to_owned(),
                });
            }
            if self.safety.destructive_actions != DestructiveActions::Deny {
                errs.push(CoreError::Conflict {
                    a: "safety.destructiveActions",
                    b: "safety.profile",
                    reason: "approval requires test_environment or stronger".to_owned(),
                });
            }
            if self.dynamic.launch_profile == LaunchProfile::Stealth {
                errs.push(CoreError::Conflict {
                    a: "dynamic.launchProfile",
                    b: "safety.profile",
                    reason: "stealth requires test_environment or authorized_security_test".to_owned(),
                });
            }
        }
        match self.retention.mode {
            RetentionMode::Standard => self.retention.days = self.retention.days.clamp(1, 30),
            RetentionMode::Extended => self.retention.days = self.retention.days.clamp(31, 365),
            RetentionMode::Zdr => {
                self.retention.days = 0;
                if self.capture.response_bodies == ResponseBodies::Full {
                    errs.push(CoreError::Conflict {
                        a: "capture.responseBodies",
                        b: "retention.mode",
                        reason: "full bodies are refused in zdr".to_owned(),
                    });
                }
            }
        }
        if self.capture.response_bodies == ResponseBodies::Full && self.crawl.captcha.is_some() {
            errs.push(CoreError::Conflict {
                a: "capture.responseBodies",
                b: "crawl.captcha",
                reason: "full bodies cannot safely retain CAPTCHA callback responses".to_owned(),
            });
        }
        self.politeness.delay_ms = self.politeness.delay_ms.max(50);
        self.politeness.max_in_flight_per_origin = self.politeness.max_in_flight_per_origin.clamp(1, 8);
        for r in [
            &mut self.politeness.global_rps,
            &mut self.politeness.global_rpm,
            &mut self.politeness.per_host_rps,
            &mut self.politeness.per_host_rpm,
        ]
        .into_iter()
        .flatten()
        {
            *r = (*r).max(1);
        }
        self.politeness.max_concurrency = self.politeness.max_concurrency.clamp(1, 256);
        self.fetch.max_response_bytes = self.fetch.max_response_bytes.clamp(1024, 64 * 1024 * 1024);
        self.fetch.timeout_ms = self.fetch.timeout_ms.clamp(100, 300_000);
        self.fetch.retries = self.fetch.retries.min(10);
        self.fetch.normalize_controls(&mut errs);
        if let Some(preflight) = &self.fetch.preflight {
            if let Err(error) = preflight.validate() {
                errs.push(CoreError::Invalid {
                    field: "fetch.preflight",
                    reason: error.to_string(),
                });
            }
        }
        if let Some(declaration) = &self.fetch.declaration {
            if let Err(error) = declaration.validate() {
                errs.push(CoreError::Invalid {
                    field: "fetch.declaration",
                    reason: error.to_string(),
                });
            }
        }
        if let Some(digest) = self.fetch.identity_profile {
            let installed = crate::identity_profile::IdentityProfileV1::pinned_chromium().digest();
            if installed.ok() != Some(digest) {
                errs.push(CoreError::Invalid {
                    field: "fetch.identityProfile",
                    reason: "profile digest is not installed".to_owned(),
                });
            }
            if self.mode != CrawlMode::Static
                || self.scrape.is_some()
                || self.fetch.acquisition_service.is_some()
                || self.fetch.tls_impersonation != TlsImpersonation::Off
                || self.fetch.skip_tls_verification
                || self.fetch.user_agent.is_some()
                || !self.fetch.extra_headers.is_empty()
                || self.fetch.preflight.is_some()
            {
                errs.push(CoreError::Conflict {
                    a: "fetch.identityProfile",
                    b: "mode",
                    reason: "coherent identity requires URL-only static mode and no custom TLS, UA, headers, preflight or service"
                        .to_owned(),
                });
            }
        }
        if let Some(id) = &self.fetch.acquisition_service {
            if id.is_empty()
                || id.len() > 128
                || matches!(id.as_str(), "native_ftp" | "native_whois")
                || self.mode != CrawlMode::Static
                || self.scrape.is_some()
                || !self.fetch.extra_headers.is_empty()
                || !self.fetch.cookies.is_empty()
                || self.fetch.user_agent.is_some()
                || self.fetch.skip_tls_verification
                || self.fetch.proxy.is_some()
                || self.fetch.preflight.is_some()
            {
                errs.push(CoreError::Invalid {
                    field: "fetch.acquisitionService",
                    reason: "registry id (<=128, not reserved) requires static URL-only mode without headers, cookies, UA, proxy or preflight"
                        .to_owned(),
                });
            }
        }
        if let Some(proxy) = &self.fetch.proxy {
            if !matches!(proxy.scheme(), "http" | "https" | "socks5" | "socks5h")
                || proxy.host_str().is_none()
            {
                errs.push(CoreError::Invalid {
                    field: "fetch.proxy",
                    reason: "proxy must be an http, https or socks5 URL with a host".to_owned(),
                });
            }
        }
        self.dynamic.dom_wait_ms = self.dynamic.dom_wait_ms.min(60_000);
        self.normalize_surface_options(&mut errs);
        self.normalize_scope(&mut errs);
        self.normalize_extract(&mut errs);
        self.normalize_scrape(&mut errs);
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }

    /// Length and count bounds shared by every caller-supplied regex list
    /// (compilation itself happens in `crawlx-url`/`crawlx-policy`).
    fn check_patterns(list: &[String], field: &'static str, errs: &mut Vec<CoreError>) {
        if list.len() > MAX_PATTERNS {
            errs.push(CoreError::Invalid {
                field,
                reason: format!("at most {MAX_PATTERNS} patterns"),
            });
        }
        if list.iter().any(|p| p.len() > MAX_PATTERN_LEN) {
            errs.push(CoreError::Invalid {
                field,
                reason: format!("patterns are at most {MAX_PATTERN_LEN} bytes"),
            });
        }
    }

    /// Bounds of the four scope path lists ([`MAX_PATH_PATTERNS`] of [`MAX_PATH_PATTERN_LEN`] bytes).
    fn check_path_patterns(list: &[String], field: &'static str, errs: &mut Vec<CoreError>) {
        if list.len() > MAX_PATH_PATTERNS {
            errs.push(CoreError::Invalid {
                field,
                reason: format!("at most {MAX_PATH_PATTERNS} patterns"),
            });
        }
        if list.iter().any(|p| p.len() > MAX_PATH_PATTERN_LEN) {
            errs.push(CoreError::Invalid {
                field,
                reason: format!("patterns are at most {MAX_PATH_PATTERN_LEN} bytes"),
            });
        }
    }

    fn normalize_scope(&mut self, errs: &mut Vec<CoreError>) {
        let s = &mut self.scope;
        if s.ignore_query_params {
            s.query_policy = QueryPolicy::StripAll;
        }
        for (list, field) in [
            (&mut s.include_paths, "scope.includePaths"),
            (&mut s.exclude_paths, "scope.excludePaths"),
            (&mut s.url_include, "scope.urlInclude"),
            (&mut s.url_exclude, "scope.urlExclude"),
        ] {
            list.retain(|p| !p.trim().is_empty());
            Self::check_path_patterns(list, field, errs);
        }
        s.exclude_hosts.retain(|h| !h.trim().is_empty());
        if s.exclude_hosts.len() > MAX_PATTERNS {
            errs.push(CoreError::Invalid {
                field: "scope.excludeHosts",
                reason: format!("at most {MAX_PATTERNS} entries"),
            });
        }
        if s.exclude_hosts.iter().any(|h| h.len() > MAX_PATTERN_LEN) {
            errs.push(CoreError::Invalid {
                field: "scope.excludeHosts",
                reason: format!("entries are at most {MAX_PATTERN_LEN} bytes"),
            });
        }
        if s.max_pages_per_host == Some(0) {
            errs.push(CoreError::Invalid {
                field: "scope.maxPagesPerHost",
                reason: "must be at least 1 or omitted".to_owned(),
            });
        }
        s.known_files.sort_unstable();
        s.known_files.dedup();
        for (list, field) in [
            (&mut s.extension_match, "scope.extensionMatch"),
            (&mut s.extension_filter, "scope.extensionFilter"),
        ] {
            for e in list.iter_mut() {
                let value = e.trim();
                let extension = if value == "." {
                    value
                } else {
                    value.trim_start_matches('.')
                };
                *e = extension.to_ascii_lowercase();
            }
            list.retain(|e| !e.is_empty());
            list.sort_unstable();
            list.dedup();
            if list.len() > MAX_PATTERNS {
                errs.push(CoreError::Invalid {
                    field,
                    reason: format!("at most {MAX_PATTERNS} extensions"),
                });
            }
            if let Some(bad) = list
                .iter()
                .find(|e| e.len() > 16 || !e.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.'))
            {
                errs.push(CoreError::Invalid {
                    field,
                    reason: format!("invalid extension {bad:?}"),
                });
            }
        }
        s.filter_similar_threshold = s.filter_similar_threshold.clamp(2, 1000);
        s.filter_similar_budget = s.filter_similar_budget.clamp(1, 1000);
        let cs = &mut s.content_similarity;
        cs.distance = cs.distance.min(64);
        if !cs.threshold.is_finite() {
            errs.push(CoreError::Invalid {
                field: "scope.contentSimilarity.threshold",
                reason: "must be a finite number in 0.0..=1.0".to_owned(),
            });
            cs.threshold = ContentSimilarity::default_threshold();
        }
        cs.threshold = cs.threshold.clamp(0.0, 1.0);
        cs.budget = cs.budget.clamp(1, 1000);
        s.filter_page_types.sort_unstable();
        s.filter_page_types.dedup();
    }

    /// Bounds of the surface-discovery options (`scope.hostScopePattern`, `dynamic.interaction*`,
    /// `dynamic.maxScrollSteps`, `fetch.resolvers`, `extract.knowledgeBase`, `extract.formFill`).
    fn normalize_surface_options(&mut self, errs: &mut Vec<CoreError>) {
        if let Some(p) = &self.scope.host_scope_pattern {
            if p.trim().is_empty() {
                self.scope.host_scope_pattern = None;
            } else if p.len() > MAX_PATTERN_LEN {
                errs.push(CoreError::Invalid {
                    field: "scope.hostScopePattern",
                    reason: format!("pattern is at most {MAX_PATTERN_LEN} bytes"),
                });
            }
        }
        let d = &mut self.dynamic;
        d.max_scroll_steps = d.max_scroll_steps.min(100);
        d.interaction_depth = d.interaction_depth.min(100);
        d.interaction_settle_ms = d.interaction_settle_ms.min(60_000);
        d.interaction_duration_seconds = d.interaction_duration_seconds.min(7 * 86_400);
        d.max_failure_count = d.max_failure_count.min(1000);
        if d.max_page_revisits > 128 {
            errs.push(CoreError::Invalid {
                field: "dynamic.maxPageRevisits",
                reason: "must be at most 128".to_owned(),
            });
        }
        d.time_stable_ms = d.time_stable_ms.min(60_000);
        d.page_hook_options.timer_acceleration =
            d.page_hook_options.timer_acceleration.min(MAX_TIMER_ACCELERATION);
        if d.page_hook_options.any() && d.launch_profile == LaunchProfile::Stealth {
            errs.push(CoreError::Conflict {
                a: "dynamic.pageHookOptions",
                b: "dynamic.launchProfile",
                reason: "page hooks run in the page's main world and are refused under stealth".to_owned(),
            });
        }
        if d.stealth_patches && d.launch_profile != LaunchProfile::Stealth {
            errs.push(CoreError::Conflict {
                a: "dynamic.stealthPatches",
                b: "dynamic.launchProfile",
                reason: "stealth patches need launchProfile = stealth, which needs test_environment or \
                         authorized_security_test"
                    .to_owned(),
            });
        }
        if let Some(p) = &d.browser_profile {
            if !BrowserProfile::name_is_valid(&p.name) {
                errs.push(CoreError::Invalid {
                    field: "dynamic.browserProfile.name",
                    reason: format!("1 to {MAX_PROFILE_NAME_LEN} of A-Z a-z 0-9 _ -"),
                });
            }
            if i64::try_from(p.generation).is_err() {
                errs.push(CoreError::Invalid {
                    field: "dynamic.browserProfile.generation",
                    reason: "at most 9223372036854775807".to_owned(),
                });
            }
        }
        for (list, field) in [
            (&mut d.interaction_selector, "dynamic.interactionSelector"),
            (&mut d.interaction_exclude, "dynamic.interactionExclude"),
        ] {
            list.retain(|s| !s.trim().is_empty());
            Self::check_patterns(list, field, errs);
        }
        let r = &self.fetch.resolvers;
        if r.len() > 8 {
            errs.push(CoreError::Invalid {
                field: "fetch.resolvers",
                reason: "at most 8 resolvers".to_owned(),
            });
        }
        if let Some(bad) = r
            .iter()
            .find(|s| s.parse::<std::net::IpAddr>().is_err() && s.parse::<std::net::SocketAddr>().is_err())
        {
            errs.push(CoreError::Invalid {
                field: "fetch.resolvers",
                reason: format!("{bad:?} is not an IP address or ip:port"),
            });
        }
        let e = &mut self.extract;
        if e.knowledge_base {
            e.page_type = true;
            e.forms = true;
        }
        if e.validate_secrets && !e.detect_secrets {
            errs.push(CoreError::Conflict {
                a: "extract.validateSecrets",
                b: "extract.detectSecrets",
                reason: "validation needs detected secrets; set detectSecrets".to_owned(),
            });
        }
        let f = &e.form_fill;
        if [&f.email, &f.color, &f.password, &f.phone, &f.placeholder]
            .into_iter()
            .flatten()
            .any(|v| v.len() > 256)
        {
            errs.push(CoreError::Invalid {
                field: "extract.formFill",
                reason: "values are at most 256 bytes".to_owned(),
            });
        }
    }

    /// Validate the compatibility-API scrape job: option limits and, for batch jobs, the extra seeds.
    fn normalize_scrape(&self, errs: &mut Vec<CoreError>) {
        let Some(job) = &self.scrape else { return };
        if let Err(reason) = job.options.validate() {
            errs.push(CoreError::Invalid {
                field: "scrape.options",
                reason,
            });
        }
        if job.options.archive_behavior.is_some() && (self.mode == CrawlMode::Static || !self.dynamic.enabled)
        {
            errs.push(CoreError::Invalid {
                field: "scrape.options.archiveBehavior",
                reason: "approved recipes require the browser plane".to_owned(),
            });
        }
        if job.options.archive_behavior.is_some() && self.retention.mode == RetentionMode::Zdr {
            errs.push(CoreError::Invalid {
                field: "scrape.options.archiveBehavior",
                reason: "approved recipe provenance is unavailable under zero-data retention".to_owned(),
            });
        }
        if job.urls.len() > MAX_BATCH_URLS {
            errs.push(CoreError::Invalid {
                field: "scrape.urls",
                reason: format!("at most {MAX_BATCH_URLS} URLs"),
            });
        }
        if job
            .urls
            .iter()
            .any(|u| !matches!(u.scheme(), "http" | "https") || u.host_str().is_none())
        {
            errs.push(CoreError::Invalid {
                field: "scrape.urls",
                reason: "every URL must be http(s) with a host".to_owned(),
            });
        }
    }

    fn normalize_extract(&mut self, errs: &mut Vec<CoreError>) {
        let fields = &mut self.extract.custom_fields;
        if fields.len() > MAX_CUSTOM_FIELDS {
            errs.push(CoreError::Invalid {
                field: "extract.customFields",
                reason: format!("at most {MAX_CUSTOM_FIELDS} fields"),
            });
        }
        let mut names = std::collections::BTreeSet::new();
        for f in fields.iter_mut() {
            let valid_name = !f.name.is_empty()
                && f.name.len() <= 64
                && f.name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
            if !valid_name {
                errs.push(CoreError::Invalid {
                    field: "extract.customFields[].name",
                    reason: format!("invalid name {:?}", f.name),
                });
            } else if !names.insert(f.name.as_str()) {
                errs.push(CoreError::Invalid {
                    field: "extract.customFields[].name",
                    reason: format!("duplicate field {}", f.name),
                });
            }
            f.regex.retain(|p| !p.trim().is_empty());
            if f.regex.is_empty() {
                errs.push(CoreError::Required {
                    field: "extract.customFields[].regex",
                    context: "custom field",
                });
            }
            Self::check_patterns(&f.regex, "extract.customFields[].regex", errs);
            if f.group > 32 {
                errs.push(CoreError::Invalid {
                    field: "extract.customFields[].group",
                    reason: "capture group index is at most 32".to_owned(),
                });
            }
        }
    }

    /// Validate gated requests against this build's verified milestone gates:
    /// `dynamic.system1Mode` above `shadow` requires G3; the `state_novelty` and `enablement`
    /// strategies require G1 while the browser plane is enabled. Every admission boundary
    /// must apply this check after [`Self::normalize`] and before starting or persisting a run.
    ///
    /// # Errors
    /// Returns [`CoreError::Conflict`] when the request needs a gate `gates` lacks.
    pub fn check_gates(&self, gates: crate::gates::GateStatus) -> Result<(), CoreError> {
        if !gates.g3
            && matches!(
                self.dynamic.system1_mode,
                System1Mode::Advisory | System1Mode::Active
            )
        {
            return Err(CoreError::Conflict {
                a: "dynamic.system1Mode",
                b: "gate G3",
                reason: "modes above shadow are rejected until gates/g3.passed exists for this build"
                    .to_owned(),
            });
        }
        if !gates.g1 && self.dynamic.enabled {
            if let Some(strategy) = self.dynamic.strategies.iter().find(|s| s.needs_g1()) {
                return Err(CoreError::Conflict {
                    a: "dynamic.strategies",
                    b: "gate G1",
                    reason: format!(
                        "strategy {} needs gate G1: gates/g1.passed signed by an operator key in \
                         CRAWLX_GATE_KEYS_FILE must exist for this build; remove it from \
                         dynamic.strategies to run without gate keys",
                        strategy.as_str()
                    ),
                });
            }
        }
        Ok(())
    }

    /// Digest of the normalized request (`crawl_runs.config_digest`).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Serialization`] if the request cannot be serialized to JSON.
    pub fn digest(&self) -> Result<crate::hash::Digest, CoreError> {
        let json = serde_json::to_vec(self)?;
        Ok(crate::hash::Digest::of("crawlx/config/v1", &json))
    }

    /// Clone safe for logs, reports and API output: every `fetch.extraHeaders` and
    /// `fetch.cookies` value is replaced by `[redacted]`.
    #[must_use]
    pub fn redacted(&self) -> Self {
        Self {
            fetch: self.fetch.redacted(),
            ..self.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn browser_revisit_cap_preserves_legacy_default_serialization_and_checks_bounds() {
        let default = Dynamic::default();
        let serialized = serde_json::to_value(&default).unwrap();
        assert_eq!(default.max_page_revisits, 8);
        assert!(serialized.get("maxPageRevisits").is_none());
        let restored: Dynamic = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored.max_page_revisits, 8);
        for cap in [0, 8, 128] {
            let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
            crawl.mode = CrawlMode::Dynamic;
            crawl.dynamic.max_page_revisits = cap;
            crawl.normalize().unwrap();
            assert_eq!(crawl.dynamic.max_page_revisits, cap);
        }
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.dynamic.max_page_revisits = 129;
        assert!(crawl.normalize().unwrap_err().iter().any(|error| {
            matches!(
                error,
                CoreError::Invalid {
                    field: "dynamic.maxPageRevisits",
                    ..
                }
            )
        }));
    }

    fn req(json: &str) -> CreateCrawl {
        serde_json::from_str(json).unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn tls_randomization_defaults_off_and_exports_selected_mode() {
        let mut crawl = req(r#"{"seedUrl":"https://a.test/","mode":"static"}"#);
        assert_eq!(crawl.fetch.tls_impersonation, TlsImpersonation::Off);
        assert!(!crawl.fetch.skip_tls_verification);
        assert_eq!(
            serde_json::to_value(crawl.redacted()).unwrap()["fetch"]["tlsImpersonation"],
            "off"
        );
        crawl.fetch.tls_impersonation = TlsImpersonation::Randomized;
        crawl.fetch.set_header("authorization", "secret-token").unwrap();
        crawl.normalize().unwrap();
        let exported = serde_json::to_value(crawl.redacted()).unwrap();
        assert_eq!(exported["fetch"]["tlsImpersonation"], "randomized");
        assert!(!exported.to_string().contains("secret-token"));
        assert!(!crawl.fetch.skip_tls_verification);
        crawl.fetch.skip_tls_verification = true;
        crawl.normalize().unwrap();
        assert!(crawl.fetch.skip_tls_verification);
    }

    #[test]
    fn tls_randomization_rejects_browser_modes_and_unknown_modes() {
        for mode in ["dynamic", "hybrid"] {
            let mut crawl = req(&format!(
                r#"{{"seedUrl":"https://a.test/","mode":"{mode}","fetch":{{"tlsImpersonation":"randomized"}}}}"#
            ));
            assert!(crawl.normalize().unwrap_err().iter().any(|error| matches!(
                error,
                CoreError::Conflict {
                    a: "fetch.tlsImpersonation",
                    ..
                }
            )));
        }
        assert!(serde_json::from_str::<CreateCrawl>(
            r#"{"seedUrl":"https://a.test/","fetch":{"tlsImpersonation":"chrome"}}"#
        )
        .is_err());
    }

    #[test]
    fn tls_randomization_rejects_scrape_engine_jobs() {
        let mut crawl = req(
            r#"{"seedUrl":"https://a.test/","mode":"static","scrape":{},"fetch":{"tlsImpersonation":"randomized"}}"#,
        );
        assert!(crawl.normalize().unwrap_err().iter().any(|error| matches!(
            error,
            CoreError::Conflict {
                a: "fetch.tlsImpersonation",
                ..
            }
        )));
    }

    #[test]
    fn strategy_arms_are_additive_and_validate_shape() {
        let default = req(r#"{"seedUrl":"https://a.test/"}"#);
        assert!(default.dynamic.strategy_arms.is_empty());
        assert!(serde_json::to_value(&default).unwrap()["dynamic"]
            .get("strategyArms")
            .is_none());
        let mut configured = req(
            r#"{"seedUrl":"https://a.test/","dynamic":{"strategyArms":{"interaction_bfs":[{"version":1,"weight":7}]}}}"#,
        );
        assert!(configured.normalize().is_ok());
        assert_eq!(
            configured.dynamic.strategy_arms[&StrategyName::InteractionBfs][0].weight,
            7
        );
        for arms in [
            r#"{"interaction_bfs":[]}"#,
            r#"{"interaction_bfs":[{"version":1,"weight":0}]}"#,
            r#"{"interaction_bfs":[{"version":0,"weight":1}]}"#,
            r#"{"interaction_bfs":[{"version":1,"weight":1},{"version":1,"weight":2}]}"#,
            r#"{"system1":[{"version":1,"weight":1}]}"#,
        ] {
            let mut request = req(&format!(
                r#"{{"seedUrl":"https://a.test/","dynamic":{{"strategyArms":{arms}}}}}"#,
            ));
            assert!(request.normalize().unwrap_err().iter().any(|error| matches!(
                error,
                CoreError::Invalid {
                    field: "dynamic.strategyArms",
                    ..
                }
            )));
        }
        configured.dynamic.strategies.clear();
        assert!(configured.dynamic.validate_strategy_arms().is_err());
    }

    #[test]
    fn identity_version_defaults_to_v1_and_roundtrips_rollout_modes() {
        assert_eq!(
            req(r#"{"seedUrl":"https://a.test/"}"#).crawl.identity.version,
            IdentityVersion::V1
        );
        for (wire, version, decision) in [
            ("v1", IdentityVersion::V1, 1),
            ("v2", IdentityVersion::V2, 2),
            ("dual", IdentityVersion::Dual, 1),
        ] {
            let request = req(&format!(
                r#"{{"seedUrl":"https://a.test/","crawl":{{"identity":{{"version":"{wire}"}}}}}}"#
            ));
            assert_eq!(request.crawl.identity.version, version);
            assert_eq!(version.decision_version(), decision);
            let serialized = serde_json::to_value(&request).unwrap();
            assert_eq!(serialized["crawl"]["identity"]["version"], wire);
        }
        assert!(serde_json::from_str::<CreateCrawl>(
            r#"{"seedUrl":"https://a.test/","crawl":{"identity":{"version":"v3"}}}"#
        )
        .is_err());
    }

    #[test]
    fn minimal_request_normalizes() {
        let mut r = req(r#"{"seedUrl":"https://app.example.test/"}"#);
        assert!(r.normalize().is_ok());
        assert_eq!(r.effective_roles()[0].name, "anonymous");
        assert_eq!(r.limits.urls, 10_000);
    }

    #[test]
    fn run_control_and_url_policy_options_default_off_and_stay_off_the_wire() {
        let mut r = req(r#"{"seedUrl":"https://app.example.test/"}"#);
        assert!(r.normalize().is_ok());
        let limits = &r.limits;
        assert_eq!(
            (
                limits.items,
                limits.errors,
                limits.idle_seconds,
                limits.disk_pressure_permille
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(r.fetch.referrer_policy, ReferrerPolicy::NoReferrer);
        assert_eq!(r.scope.max_url_length, 8192);
        // defaults serialize exactly as before the options existed, so stored digests hold
        let wire = serde_json::to_value(&r).unwrap();
        for key in ["items", "errors", "idleSeconds", "diskPressurePermille"] {
            assert!(wire["limits"].get(key).is_none(), "{key}");
        }
        assert!(wire["fetch"].get("referrerPolicy").is_none());
        assert!(wire["scope"].get("maxUrlLength").is_none());
    }

    #[test]
    fn run_control_and_url_policy_options_are_clamped_and_round_trip() {
        let mut r = req(r#"{"seedUrl":"https://app.example.test/",
                "limits":{"items":3,"errors":2000000,"idleSeconds":9999999,"diskPressurePermille":5000},
                "fetch":{"referrerPolicy":"strict-origin-when-cross-origin"},
                "scope":{"maxUrlLength":10}}"#);
        assert!(r.normalize().is_ok());
        assert_eq!(r.limits.items, 3);
        assert_eq!(r.limits.errors, 1_000_000);
        assert_eq!(r.limits.idle_seconds, 7 * 86_400);
        assert_eq!(r.limits.disk_pressure_permille, 1000);
        assert_eq!(r.scope.max_url_length, 256);
        assert_eq!(
            r.fetch.referrer_policy,
            ReferrerPolicy::StrictOriginWhenCrossOrigin
        );
        let wire = serde_json::to_value(&r).unwrap();
        assert_eq!(wire["fetch"]["referrerPolicy"], "strict-origin-when-cross-origin");
        assert_eq!(wire["scope"]["maxUrlLength"], 256);
        assert_eq!(wire["limits"]["items"], 3);
        for policy in [
            ReferrerPolicy::NoReferrer,
            ReferrerPolicy::NoReferrerWhenDowngrade,
            ReferrerPolicy::SameOrigin,
            ReferrerPolicy::Origin,
            ReferrerPolicy::StrictOrigin,
            ReferrerPolicy::OriginWhenCrossOrigin,
            ReferrerPolicy::StrictOriginWhenCrossOrigin,
            ReferrerPolicy::UnsafeUrl,
        ] {
            let back: ReferrerPolicy = serde_json::from_value(serde_json::json!(policy.as_str())).unwrap();
            assert_eq!(back, policy);
        }
        assert!(serde_json::from_str::<CreateCrawl>(
            r#"{"seedUrl":"https://a.test/","fetch":{"referrerPolicy":"sometimes"}}"#
        )
        .is_err());
    }

    #[test]
    fn system1_modes_above_shadow_need_gate_g3() {
        use crate::gates::GateStatus;
        for mode in ["off", "shadow"] {
            let r = req(&format!(
                r#"{{"seedUrl":"https://a.test/","dynamic":{{"system1Mode":"{mode}"}}}}"#
            ));
            assert!(r.check_gates(GateStatus::NONE).is_ok(), "{mode}");
        }
        for mode in ["advisory", "active"] {
            let mut r = req(&format!(
                r#"{{"seedUrl":"https://a.test/","dynamic":{{"system1Mode":"{mode}"}}}}"#
            ));
            assert!(r.normalize().is_ok(), "{mode}");
            let err = r.check_gates(GateStatus::NONE).unwrap_err();
            assert_eq!(err.code(), "profile_conflict");
            assert!(err.to_string().contains("g3.passed"));
            assert!(r.check_gates(GateStatus { g1: true, g3: false }).is_err());
            assert!(r.check_gates(GateStatus { g1: false, g3: true }).is_ok());
            assert!(r.check_gates(GateStatus::ALL).is_ok());
        }
    }

    #[test]
    fn default_strategies_run_without_gates_and_gated_ones_need_g1() {
        use crate::gates::GateStatus;
        let default = req(r#"{"seedUrl":"https://a.test/"}"#);
        assert_eq!(
            default.dynamic.strategies,
            [StrategyName::InteractionBfs, StrategyName::EventDriven]
        );
        assert!(default.check_gates(GateStatus::NONE).is_ok());
        for name in ["state_novelty", "enablement"] {
            let mut r = req(&format!(
                r#"{{"seedUrl":"https://a.test/","dynamic":{{"strategies":["interaction_bfs","{name}"]}}}}"#
            ));
            assert!(r.normalize().is_ok(), "{name}");
            let err = r.check_gates(GateStatus::NONE).unwrap_err();
            assert_eq!(err.code(), "profile_conflict", "{name}");
            let text = err.to_string();
            assert!(
                text.contains(name) && text.contains("G1") && text.contains("CRAWLX_GATE_KEYS_FILE"),
                "{text}"
            );
            assert!(r.check_gates(GateStatus { g1: false, g3: true }).is_err());
            assert!(r.check_gates(GateStatus { g1: true, g3: false }).is_ok());
        }
    }

    #[test]
    fn stealth_requires_non_read_only() {
        let mut r = req(r#"{"seedUrl":"https://a.test/","dynamic":{"launchProfile":"stealth"}}"#);
        let errs = r.normalize().err().unwrap_or_default();
        assert!(errs.iter().any(|e| e.code() == "profile_conflict"));
        let mut ok = req(
            r#"{"seedUrl":"https://a.test/","dynamic":{"launchProfile":"stealth"},"safety":{"profile":"test_environment"}}"#,
        );
        assert!(ok.normalize().is_ok());
    }

    #[test]
    fn authorized_profile_needs_record() {
        let mut r = req(r#"{"seedUrl":"https://a.test/","safety":{"profile":"authorized_security_test"}}"#);
        let errs = r.normalize().err().unwrap_or_default();
        assert!(errs.iter().any(|e| matches!(
            e,
            CoreError::Required {
                field: "safety.authorizationRecordRef",
                ..
            }
        )));
    }

    #[test]
    fn zdr_forces_zero_days_and_refuses_full_bodies() {
        let mut r = req(
            r#"{"seedUrl":"https://a.test/","retention":{"mode":"zdr","days":7},"capture":{"responseBodies":"full"}}"#,
        );
        let errs = r.normalize().err().unwrap_or_default();
        assert_eq!(r.retention.days, 0);
        assert!(!errs.is_empty());
    }

    #[test]
    fn retained_response_modes_validate_policy_conflicts() {
        let mut request = req(
            r#"{"seedUrl":"https://a.test/","mode":"dynamic","capture":{"responseBodies":"full"},"crawl":{"captcha":{"provider":"task-api","key_ref":"env://CAPTCHA_KEY"}}}"#,
        );
        let errors = request.normalize().unwrap_err();
        assert!(errors.iter().any(|error| matches!(
            error,
            CoreError::Conflict {
                a: "capture.responseBodies",
                b: "crawl.captcha",
                ..
            }
        )));
        for input in [
            r#"{"seedUrl":"https://a.test/","mode":"dynamic","capture":{"responseBodies":"full"}}"#,
            r#"{"seedUrl":"https://a.test/","mode":"static","capture":{"responseBodies":"full"}}"#,
            r#"{"seedUrl":"https://a.test/","capture":{"responseBodies":"text_capped"}}"#,
        ] {
            assert!(req(input).normalize().is_ok());
        }
    }

    #[test]
    fn seed_is_reproducible_when_omitted() {
        let a = req(r#"{"seedUrl":"https://a.test/"}"#).effective_seed();
        let b = req(r#"{"seedUrl":"https://a.test/"}"#).effective_seed();
        assert_eq!(a, b);
    }

    #[test]
    fn role_order_defaults_to_declared_and_parses_seeded_shuffle() {
        assert_eq!(
            req(r#"{"seedUrl":"https://a.test/"}"#).role_order,
            RoleOrder::Declared
        );
        let r = req(r#"{"seedUrl":"https://a.test/","roleOrder":"seeded_shuffle"}"#);
        assert_eq!(r.role_order, RoleOrder::SeededShuffle);
        assert_eq!(serde_json::to_value(&r).unwrap()["roleOrder"], "seeded_shuffle");
        assert!(
            serde_json::from_str::<CreateCrawl>(r#"{"seedUrl":"https://a.test/","roleOrder":"random"}"#)
                .is_err()
        );
    }

    #[test]
    fn always_browser_paths_parse_and_require_hybrid_mode() {
        let mut r = req(r#"{"seedUrl":"https://a.test/","dynamic":{"alwaysBrowserPaths":["/app/.*"," "]}}"#);
        assert!(r.normalize().is_ok(), "hybrid is the default mode");
        assert_eq!(
            r.dynamic.always_browser_paths,
            vec!["/app/.*".to_owned()],
            "blank patterns are dropped"
        );
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(
            json["dynamic"]["alwaysBrowserPaths"],
            serde_json::json!(["/app/.*"])
        );
        assert!(
            serde_json::to_value(CreateCrawl::new(r.seed_url.clone())).unwrap()["dynamic"]
                .get("alwaysBrowserPaths")
                .is_none()
        );

        let mut s = req(
            r#"{"seedUrl":"https://a.test/","mode":"static","dynamic":{"alwaysBrowserPaths":["/app/.*"]}}"#,
        );
        let errs = s.normalize().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            CoreError::Conflict {
                b: "dynamic.alwaysBrowserPaths",
                ..
            }
        )));

        let many: Vec<String> = (0..101).map(|i| format!("/p{i}")).collect();
        let mut t = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        t.dynamic.always_browser_paths = many;
        let errs = t.normalize().unwrap_err();
        assert!(errs.iter().any(|e| matches!(
            e,
            CoreError::Invalid {
                field: "dynamic.alwaysBrowserPaths",
                ..
            }
        )));
    }

    #[test]
    fn crawl_order_aliases_preserve_canonical_serialization() {
        assert_eq!(CrawlStrategy::default(), CrawlStrategy::BreadthFirst);
        for (aliases, expected, canonical) in [
            (
                ["bfs", "breadth_first", "breadth-first"],
                CrawlStrategy::BreadthFirst,
                "breadth_first",
            ),
            (
                ["dfs", "depth_first", "depth-first"],
                CrawlStrategy::DepthFirst,
                "depth_first",
            ),
        ] {
            for alias in aliases {
                let crawl = req(&format!(
                    r#"{{"seedUrl":"https://a.test/","scope":{{"strategy":"{alias}"}}}}"#
                ));
                assert_eq!(crawl.scope.strategy, expected, "{alias}");
                assert_eq!(
                    serde_json::to_value(crawl).unwrap()["scope"]["strategy"],
                    canonical
                );
            }
        }
        assert_eq!(
            req(r#"{"seedUrl":"https://a.test/","scope":{}}"#).scope.strategy,
            CrawlStrategy::BreadthFirst
        );
    }

    #[test]
    fn surface_fields_default_per_plan_10() {
        let mut r = req(r#"{"seedUrl":"https://a.test/"}"#);
        assert!(r.normalize().is_ok());
        let s = &r.scope;
        assert_eq!(s.host_scope, HostScope::Fqdn);
        assert!(s.url_include.is_empty() && s.url_exclude.is_empty());
        assert!(
            s.exclude_hosts.is_empty(),
            "private ranges are the egress policy's job"
        );
        assert_eq!(s.strategy, CrawlStrategy::BreadthFirst);
        assert_eq!(s.max_pages_per_host, None);
        assert_eq!(s.known_files, vec![KnownFile::Sitemap]);
        assert!(!s.no_default_extension_filter && !s.filter_similar);
        assert_eq!((s.filter_similar_threshold, s.filter_similar_budget), (10, 1));
        assert_eq!(s.content_similarity.mode, SimilarityMode::Off);
        assert_eq!(s.content_similarity.distance, 3);
        assert!((s.content_similarity.threshold - 0.85).abs() < f64::EPSILON);
        assert_eq!(s.content_similarity.budget, 1);
        assert!(s.filter_page_types.is_empty());
        let p = &r.politeness;
        assert_eq!(
            (
                p.global_rps,
                p.global_rpm,
                p.per_host_rps,
                p.per_host_rpm,
                p.max_concurrency
            ),
            (None, None, None, None, 10)
        );
        let f = &r.fetch;
        assert_eq!(f.max_response_bytes, 8_388_608);
        assert_eq!((f.timeout_ms, f.retries, f.follow_redirects), (10_000, 1, true));
        assert!(f.proxy.is_none());
        let x = &r.extract;
        assert!(x.custom_fields.is_empty() && !x.detect_secrets && x.forms && x.page_type);
        assert!(!r.output.include_out_of_scope);
        assert!(!r.dynamic.page_hooks);
        assert_eq!(r.dynamic.page_load_strategy, PageLoadStrategy::Heuristic);
        assert_eq!(r.dynamic.dom_wait_ms, 5_000);
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["scope"]["hostScope"], "fqdn");
        assert_eq!(json["scope"]["strategy"], "breadth_first");
        assert_eq!(json["scope"]["contentSimilarity"]["mode"], "off");
        assert_eq!(json["dynamic"]["pageLoadStrategy"], "heuristic");
        assert_eq!(json["fetch"]["maxResponseBytes"], 8_388_608);
    }

    #[test]
    fn extension_normalization_preserves_trailing_dot_selection() {
        let mut r = req(
            r#"{"seedUrl":"https://a.test/","scope":{"extensionMatch":[" . ","NONE",".PNG"," "],"extensionFilter":[".",".PNG"]}}"#,
        );
        r.normalize().unwrap();
        assert_eq!(r.scope.extension_match, [".", "none", "png"]);
        assert_eq!(r.scope.extension_filter, [".", "png"]);
    }

    #[test]
    fn surface_fields_parse_and_clamp() {
        let mut r = req(
            r#"{"seedUrl":"https://a.test/","scope":{"hostScope":"rdn","strategy":"depth_first",
            "knownFiles":["sitemap","robots_paths","sitemap"],"extensionMatch":[".PHP","js","js"," "],
            "filterSimilarThreshold":1,"filterSimilarBudget":0,"ignoreQueryParams":true,
            "contentSimilarity":{"mode":"bm25","distance":99,"threshold":1.7,"budget":0},
            "filterPageTypes":["login","error","login"]},
            "politeness":{"globalRps":0,"maxConcurrency":0},
            "fetch":{"maxResponseBytes":1,"timeoutMs":1,"retries":99,"followRedirects":false,"proxy":"socks5://127.0.0.1:1080"},
            "dynamic":{"pageHooks":true,"pageLoadStrategy":"domcontentloaded","domWaitMs":999999},
            "output":{"includeOutOfScope":true}}"#,
        );
        assert!(r.normalize().is_ok(), "{:?}", r.normalize());
        let s = &r.scope;
        assert_eq!(s.host_scope, HostScope::Rdn);
        assert_eq!(s.strategy, CrawlStrategy::DepthFirst);
        assert_eq!(s.known_files, vec![KnownFile::RobotsPaths, KnownFile::Sitemap]);
        assert_eq!(s.extension_match, vec!["js".to_owned(), "php".to_owned()]);
        assert_eq!((s.filter_similar_threshold, s.filter_similar_budget), (2, 1));
        assert_eq!(s.query_policy, QueryPolicy::StripAll);
        assert_eq!(s.content_similarity.mode, SimilarityMode::Bm25);
        assert_eq!(s.content_similarity.distance, 64);
        assert!((s.content_similarity.threshold - 1.0).abs() < f64::EPSILON);
        assert_eq!(s.content_similarity.budget, 1);
        assert_eq!(s.filter_page_types, vec![PageType::Login, PageType::Error]);
        assert_eq!(r.politeness.global_rps, Some(1));
        assert_eq!(r.politeness.max_concurrency, 1);
        assert_eq!(r.fetch.max_response_bytes, 1024);
        assert_eq!(r.fetch.timeout_ms, 100);
        assert_eq!(r.fetch.retries, 10);
        assert!(!r.fetch.follow_redirects);
        assert_eq!(r.fetch.proxy.as_ref().unwrap().scheme(), "socks5");
        assert!(r.dynamic.page_hooks);
        assert_eq!(r.dynamic.page_load_strategy, PageLoadStrategy::DomContentLoaded);
        assert_eq!(r.dynamic.dom_wait_ms, 60_000);
        assert!(r.output.include_out_of_scope);
        assert!(serde_json::from_str::<CreateCrawl>(
            r#"{"seedUrl":"https://a.test/","scope":{"filterPageTypes":["blog"]}}"#
        )
        .is_err());
        assert!(serde_json::from_str::<CreateCrawl>(
            r#"{"seedUrl":"https://a.test/","scope":{"hostScope":"regex"}}"#
        )
        .is_err());
    }

    #[test]
    fn surface_fields_validation_errors() {
        let long = "a".repeat(513);
        let many: Vec<String> = (0..101).map(|i| format!("x{i}")).collect();
        // path/URL pattern lists have the larger compatibility-API bounds (1000 of 2000 bytes)
        let long_path = "a".repeat(MAX_PATH_PATTERN_LEN + 1);
        let many_paths: Vec<String> = (0..=MAX_PATH_PATTERNS).map(|i| format!("x{i}")).collect();
        let mut r = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        r.scope.url_include = vec![long_path];
        r.scope.url_exclude = many_paths;
        r.scope.exclude_hosts = many;
        r.scope.max_pages_per_host = Some(0);
        r.scope.extension_filter = vec!["ex/e".to_owned()];
        r.fetch.proxy = Some(url::Url::parse("ftp://proxy.test/").unwrap());
        r.extract.custom_fields = vec![
            CustomField {
                name: "bad name".to_owned(),
                regex: vec![long],
                part: CustomFieldPart::Body,
                group: 40,
            },
            CustomField {
                name: "email".to_owned(),
                regex: Vec::new(),
                part: CustomFieldPart::Header,
                group: 0,
            },
            CustomField {
                name: "email".to_owned(),
                regex: vec!["@".to_owned()],
                part: CustomFieldPart::Response,
                group: 0,
            },
        ];
        let errs = r.normalize().unwrap_err();
        let fields: Vec<&str> = errs
            .iter()
            .filter_map(|e| match e {
                CoreError::Invalid { field, .. } | CoreError::Required { field, .. } => Some(*field),
                _ => None,
            })
            .collect();
        for expected in [
            "scope.urlInclude",
            "scope.urlExclude",
            "scope.excludeHosts",
            "scope.maxPagesPerHost",
            "scope.extensionFilter",
            "fetch.proxy",
            "extract.customFields[].name",
            "extract.customFields[].regex",
            "extract.customFields[].group",
        ] {
            assert!(fields.contains(&expected), "missing {expected} in {fields:?}");
        }
        assert!(errs
            .iter()
            .all(|e| matches!(e.code(), "invalid_pattern" | "required")));
        assert!(errs
            .iter()
            .any(|e| e.to_string().contains("duplicate field email")));
    }
}
