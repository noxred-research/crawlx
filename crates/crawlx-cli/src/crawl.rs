//! `crawlx crawl`: the flags and the request they build.
//!
//! [`build_request`] is the one place flags become a [`CreateCrawl`]. The layers, lowest
//! first: crawlx's defaults, `--compat-defaults`, a JSON/TOML `--config` body, the
//! `--request` file, then the flags. A YAML `--config` file is read as a flag layer under the
//! command line, so a flag given on the command line always wins over the file.
//!
//! The run itself (seeds, parallelism, resume, outputs) is in `crawl_run`.

use crate::ai_args::AiArgs;
use crate::compat_flag_defaults;
use crate::config_file::{self, ConfigLayer};
use crate::duration::parse_duration;
use crate::headless_args::HeadlessArgs;
use crate::input::{self, InputArgs};
use crate::merge::fill;
use crate::model_args::ModelArgs;
use crate::output_args::OutputArgs;
use anyhow::{anyhow, bail, Context as _};
use clap::{Args, ValueEnum};
use crawlx_core::config::{
    CrawlMode, CrawlStrategy, CustomField, CustomFieldPart, Extract, Fetch, HostScope, JavascriptMode,
    KnownFile, LaunchProfile, OutputFormat, PageLoadStrategy, PageType, Politeness, Role, SafetyProfile,
    Scope, SimilarityMode,
};
use crawlx_core::request_controls::FetchCookie;
use crawlx_core::secret::CredentialRef;
use crawlx_core::CreateCrawl;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;

/// `--javascript-mode`: exact miners, independent of compile-time parser availability.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum JavascriptModeArg {
    /// Keep only structural HTML and header discovery.
    Off,
    /// Mine regex candidates only.
    Regex,
    /// Parse JavaScript only; malformed or oversized scripts yield no endpoints.
    Ast,
    /// Run both; regex survives malformed or oversized JavaScript.
    Both,
}

impl From<JavascriptModeArg> for JavascriptMode {
    fn from(mode: JavascriptModeArg) -> Self {
        match mode {
            JavascriptModeArg::Off => Self::Off,
            JavascriptModeArg::Regex => Self::Regex,
            JavascriptModeArg::Ast => Self::Ast,
            JavascriptModeArg::Both => Self::Both,
        }
    }
}

/// `--mode`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ModeArg {
    #[value(name = "static")]
    /// Static.
    Static,
    #[value(name = "dynamic")]
    /// Dynamic.
    Dynamic,
    #[value(name = "hybrid")]
    /// Hybrid.
    Hybrid,
}

/// `--profile`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ProfileArg {
    #[value(name = "read_only")]
    /// Read only.
    ReadOnly,
    #[value(name = "test_environment")]
    /// Test environment.
    TestEnvironment,
    #[value(name = "authorized_security_test")]
    /// Authorized security test.
    AuthorizedSecurityTest,
}

/// `--launch-profile`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum LaunchArg {
    #[value(name = "standard")]
    /// Standard.
    Standard,
    #[value(name = "stealth")]
    /// Stealth.
    Stealth,
}

/// `--trailing-slash`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TrailingArg {
    #[value(name = "keep")]
    /// Keep.
    Keep,
    #[value(name = "strip")]
    /// Strip.
    Strip,
    #[value(name = "add")]
    /// Add.
    Add,
}

/// `--field-scope` (compatibility `-fs`): a pre-defined scope or a host-name regex.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldScopeArg {
    /// `fqdn`, `rdn`, `dn` or `none`.
    Host(HostScope),
    /// A regex over the host name: hosts matching it are in scope as well.
    Pattern(String),
}

/// Longest `scope.hostScopePattern` the request accepts.
const MAX_HOST_PATTERN_BYTES: usize = 512;

fn parse_field_scope(raw: &str) -> Result<FieldScopeArg, String> {
    let text = raw.trim();
    match text.to_ascii_lowercase().as_str() {
        "fqdn" => Ok(FieldScopeArg::Host(HostScope::Fqdn)),
        "rdn" => Ok(FieldScopeArg::Host(HostScope::Rdn)),
        "dn" => Ok(FieldScopeArg::Host(HostScope::Dn)),
        "none" => Ok(FieldScopeArg::Host(HostScope::None)),
        _ if text.is_empty() => Err("empty scope (dn, rdn, fqdn, none, or a host regex)".to_owned()),
        _ if text.len() > MAX_HOST_PATTERN_BYTES => Err(format!(
            "host regex is longer than {MAX_HOST_PATTERN_BYTES} bytes"
        )),
        _ => Ok(FieldScopeArg::Pattern(text.to_owned())),
    }
}

/// `--strategy` (compatibility `-strategy`).
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum StrategyArg {
    #[value(name = "breadth-first", aliases = ["bfs", "breadth_first"])]
    /// Shallowest first.
    BreadthFirst,
    #[value(name = "depth-first", aliases = ["dfs", "depth_first"])]
    /// Deepest first.
    DepthFirst,
    #[value(name = "priority")]
    /// Highest-value URLs first: API-looking, parameterised and shallow URLs lead.
    Priority,
}

impl From<StrategyArg> for CrawlStrategy {
    fn from(a: StrategyArg) -> Self {
        match a {
            StrategyArg::BreadthFirst => Self::BreadthFirst,
            StrategyArg::DepthFirst => Self::DepthFirst,
            StrategyArg::Priority => Self::Priority,
        }
    }
}

/// `--cache-mode`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum CacheModeArg {
    #[value(name = "read_write", alias = "read-write")]
    /// Read matching fresh entries and write successful acquisitions.
    ReadWrite,
    #[value(name = "bypass")]
    /// Never read; permit writes.
    Bypass,
    #[value(name = "disabled")]
    /// Neither read nor write.
    Disabled,
    #[value(name = "read_only", alias = "read-only")]
    /// Read only; a miss never dispatches a request.
    ReadOnly,
    #[value(name = "write_only", alias = "write-only")]
    /// Never read; write successful acquisitions.
    WriteOnly,
}

impl From<CacheModeArg> for crawlx_core::cache::CacheModeV1 {
    fn from(mode: CacheModeArg) -> Self {
        match mode {
            CacheModeArg::ReadWrite => Self::ReadWrite,
            CacheModeArg::Bypass => Self::Bypass,
            CacheModeArg::Disabled => Self::Disabled,
            CacheModeArg::ReadOnly => Self::ReadOnly,
            CacheModeArg::WriteOnly => Self::WriteOnly,
        }
    }
}

/// `--known-files` (compatibility `-kf`). `all` names both files; the spellings of the
/// compatibility flag (`robotstxt`, `sitemapxml`) are accepted next to the native ones.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum KnownFileArg {
    #[value(name = "robots_paths", aliases = ["robotstxt", "robots-paths", "robots"])]
    /// `robots.txt` paths.
    RobotsPaths,
    #[value(name = "sitemap", aliases = ["sitemapxml", "sitemap-xml", "sitemap_xml"])]
    /// Sitemaps.
    Sitemap,
    #[value(name = "all")]
    /// Both of the above.
    All,
}

impl KnownFileArg {
    /// The files the flag values stand for, each once, in first-named order, so a repeated or
    /// overlapping value (`all,sitemap`) never makes the traversal visit a file twice.
    pub(crate) fn expand(values: &[Self]) -> Vec<KnownFile> {
        let mut out = Vec::with_capacity(2);
        for value in values {
            let files: &[KnownFile] = match value {
                Self::RobotsPaths => &[KnownFile::RobotsPaths],
                Self::Sitemap => &[KnownFile::Sitemap],
                Self::All => &[KnownFile::RobotsPaths, KnownFile::Sitemap],
            };
            for file in files {
                if !out.contains(file) {
                    out.push(*file);
                }
            }
        }
        out
    }
}

/// Native `--content-similar` and the compatibility flags' separate `--page-content-similar-mode`.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SimilarityArg {
    #[value(name = "off")]
    /// No content similarity filtering.
    Off,
    #[value(name = "simhash")]
    /// Simhash over shingles.
    Simhash,
    #[value(name = "tfidf")]
    /// TF-IDF cosine similarity.
    Tfidf,
    #[value(name = "bm25")]
    /// BM25 similarity.
    Bm25,
}

impl From<SimilarityArg> for SimilarityMode {
    fn from(a: SimilarityArg) -> Self {
        match a {
            SimilarityArg::Off => Self::Off,
            SimilarityArg::Simhash => Self::Simhash,
            SimilarityArg::Tfidf => Self::Tfidf,
            SimilarityArg::Bm25 => Self::Bm25,
        }
    }
}

/// `--filter-page-type` / `--no-expand-page-type` (compatibility `-filter-page-type`).
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PageTypeArg {
    #[value(name = "login")]
    /// Sign-in form.
    Login,
    #[value(name = "error")]
    /// Error page.
    Error,
    #[value(name = "captcha")]
    /// Captcha challenge.
    Captcha,
    #[value(name = "parked")]
    /// Parked domain.
    Parked,
    #[value(name = "search")]
    /// Search page.
    Search,
    #[value(name = "listing")]
    /// Listing page.
    Listing,
    #[value(name = "article")]
    /// Article.
    Article,
    #[value(name = "form")]
    /// Form page.
    Form,
    #[value(name = "unknown")]
    /// Unclassified.
    Unknown,
}

impl From<PageTypeArg> for PageType {
    fn from(a: PageTypeArg) -> Self {
        match a {
            PageTypeArg::Login => Self::Login,
            PageTypeArg::Error => Self::Error,
            PageTypeArg::Captcha => Self::Captcha,
            PageTypeArg::Parked => Self::Parked,
            PageTypeArg::Search => Self::Search,
            PageTypeArg::Listing => Self::Listing,
            PageTypeArg::Article => Self::Article,
            PageTypeArg::Form => Self::Form,
            PageTypeArg::Unknown => Self::Unknown,
        }
    }
}

/// `--page-load-strategy` (compatibility `-pls`).
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum PageLoadArg {
    #[value(name = "heuristic")]
    /// The MAIN quiescence heuristic.
    Heuristic,
    #[value(name = "load")]
    /// The `load` event.
    Load,
    #[value(name = "domcontentloaded")]
    /// The `DOMContentLoaded` event.
    DomContentLoaded,
    #[value(name = "networkidle")]
    /// Network idle.
    NetworkIdle,
    #[value(name = "none")]
    /// No wait.
    None,
}

impl From<PageLoadArg> for PageLoadStrategy {
    fn from(a: PageLoadArg) -> Self {
        match a {
            PageLoadArg::Heuristic => Self::Heuristic,
            PageLoadArg::Load => Self::Load,
            PageLoadArg::DomContentLoaded => Self::DomContentLoaded,
            PageLoadArg::NetworkIdle => Self::NetworkIdle,
            PageLoadArg::None => Self::None,
        }
    }
}

/// Arguments of `crawlx crawl`.
///
/// Traffic export is operator configuration, not a flag: `CRAWLX_TRAFFIC_ENDPOINT` (an
/// `https` URL, or `http` with `CRAWLX_TRAFFIC_ALLOW_INSECURE=1`), `CRAWLX_TRAFFIC_TOKEN`,
/// `CRAWLX_TRAFFIC_ATTRIBUTES` (comma separated record keys), and
/// `CRAWLX_TRAFFIC_INCLUDE_CREDENTIALS=1` post every fetch-plane exchange of the crawl as
/// batched JSON.
#[derive(Args, Debug, Clone, Default)]
pub struct CrawlArgs {
    /// Seeds, config file and parallelism.
    #[command(flatten)]
    pub input: InputArgs,
    /// Deployment-owned basic and enhanced proxy routes (not part of the crawl request).
    #[command(flatten)]
    pub proxy_routes: crate::config_check::ProxyArgs,
    /// Which planes run (default hybrid).
    #[arg(long, value_enum)]
    pub mode: Option<ModeArg>,
    /// Compatibility `-hl`/`-headless`: run only the browser plane (`--mode dynamic`), not window visibility.
    #[arg(long = "headless", conflicts_with_all = ["mode", "hybrid"], help_heading = "Headless")]
    pub headless_mode: bool,
    /// Compatibility `-hh`/`-hybrid`: run both planes, the URL plane and the browser plane. This is the
    /// default; the flag is the explicit spelling of `--mode hybrid` (the compatibility hijacking hybrid
    /// engine maps to two planes here).
    #[arg(long, conflicts_with = "mode")]
    pub hybrid: bool,
    /// Safety profile (default read_only).
    #[arg(long, value_enum)]
    pub profile: Option<ProfileArg>,
    /// Authorization record (JSON file): required for private networks, `authorized_security_test` and robots overrides.
    ///
    /// The file is one authorization record with every required field: `id` (UUID), `tenant` (UUID),
    /// `version`, `authorizer` (`name`, `role`, `organization`, `contact` and
    /// `attestsOwnershipOrControl: true`), `origins` or `urlPrefixes` (no wildcards), `validFrom`
    /// and `validTo` (RFC 3339, at most 90 days apart), `profileCap`, `permittedRiskClasses`,
    /// `approvalRequired`, `testAccounts` (`[]` is fine), `emergencyContact` and `evidence`
    /// (`kind`, `digest`). Optional: `title`, `excludedPaths`, `authorizedNetworks` (needed for
    /// private networks), `robotsOverrideAcknowledged`, `testSinks`, `rateLimits`,
    /// `legalReferences`. Unknown fields are refused. Every request of the run stays inside the
    /// record's `origins`/`urlPrefixes`, `excludedPaths` and `authorizedNetworks`. A local run
    /// takes you as the authorizer: no ownership proof is needed, and `crawlx authz` is how an
    /// API deployment proves ownership.
    #[arg(long, value_name = "JSON")]
    pub authorization_record: Option<PathBuf>,
    /// Crawl seed; the same seed reproduces the same decisions.
    #[arg(long)]
    pub seed: Option<u64>,
    /// Output directory for `pages/*.md`, `metadata.json`, `links.json`, `report.json` (and
    /// `results.jsonl` with `--jsonl`); default `./crawlx-out`. Several seeds write
    /// one subdirectory each.
    #[arg(long, value_name = "DIR")]
    pub output: Option<PathBuf>,
    /// Navigate and observe only; send no click, type or key action.
    #[arg(long)]
    pub observe_only: bool,
    /// Persist to the database (`postgres:`, `mariadb:` or `sqlite:`) instead of memory (needed for `crawlx inspect`).
    #[arg(long, env = "CRAWLX_DATABASE_URL", hide_env_values = true)]
    pub database_url: Option<String>,
    /// Role credential: `name=env://VAR` (value `user:password`). Repeat for several roles.
    #[arg(long = "role", value_name = "NAME=REF")]
    pub roles: Vec<String>,
    /// Browser launch profile.
    #[arg(long, value_enum)]
    pub launch_profile: Option<LaunchArg>,
    /// Allow private and loopback addresses (needs an authorization record listing `authorizedNetworks`).
    #[arg(long)]
    pub allow_private_networks: bool,
    /// Maximum URLs the static plane attempts.
    #[arg(long, value_name = "N")]
    pub limit_urls: Option<u32>,
    /// Maximum browser interactions (0 observes only).
    #[arg(long, value_name = "N")]
    pub limit_interactions: Option<u32>,
    /// Full request as JSON (`POST /v1/crawls` body); flags override its fields.
    #[arg(long, value_name = "JSON")]
    pub request: Option<PathBuf>,
    /// Trailing-slash policy of URL canonicalization.
    #[arg(long, value_enum)]
    pub trailing_slash: Option<TrailingArg>,
    /// Minimum delay between requests to one origin, in milliseconds.
    #[arg(long, value_name = "MS")]
    pub delay_ms: Option<u32>,
    /// Compatibility `-rd`/`-delay`: minimum delay between requests to one origin, in whole seconds.
    #[arg(long = "delay", value_name = "SECONDS", conflicts_with = "delay_ms")]
    pub delay_seconds: Option<u32>,
    /// Longest the crawl runs (`30s`, `5m`, `1h30m`, `2d` or bare seconds; at least 1s, at
    /// most 7d).
    #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
    pub crawl_duration: Option<Duration>,
    /// Start from the compatibility defaults (host scope rdn, depth 3, depth-first, no JavaScript
    /// endpoints or known files, no forms, 150 requests/s, delay at the politeness floor, 4
    /// MiB bodies, no `technologies` field) instead of crawlx's. Any other flag, `--config`
    /// or `--request` value overrides the preset.
    #[arg(long)]
    pub compat_defaults: bool,
    /// Print the effective per-run request (defaults, preset, `--config`, `--request` and flags
    /// folded in order, after admission, secrets redacted) with its configuration digest as a
    /// JSON array, one entry per seed, then exit. No crawl runs and nothing touches the network.
    #[arg(long, help_heading = "Debug")]
    pub print_config: bool,
    /// Response-cache behavior of the run (`read_write`, `bypass`, `disabled`, `read_only`,
    /// `write_only`); replaces the `cache.mode` of `--config`/`--request`.
    #[arg(long, value_enum, value_name = "MODE", help_heading = "Fetch")]
    pub cache_mode: Option<CacheModeArg>,
    /// Check the browser, the configuration and the network path to the seeds, print a table
    /// and exit non-zero when a check fails.
    #[arg(long, help_heading = "Debug")]
    pub health_check: bool,
    /// Ask the release endpoint (`CRAWLX_RELEASE_URL`) whether a newer crawlx exists, print
    /// the answer and exit. crawlx never downloads or replaces itself.
    #[arg(long, conflicts_with = "disable_update_check", help_heading = "Update")]
    pub update: bool,
    /// Skip the check `CRAWLX_UPDATE_CHECK=1` otherwise runs once at the start of a crawl.
    #[arg(long, help_heading = "Update")]
    pub disable_update_check: bool,

    /// URL discovery, filtering, rate limits and fetch flags.
    #[command(flatten)]
    pub url: UrlArgs,

    // --- extraction (compatibility -flc, -kb*, -fx, -aff, -fc, -td) ---
    /// Custom regex fields: YAML or JSON list of `{name, regex: [..], part, group}`.
    #[arg(
        long,
        visible_alias = "field-config",
        value_name = "FILE",
        help_heading = "Extraction"
    )]
    pub custom_field_config: Option<PathBuf>,
    /// Detect secrets in bodies and headers (kind and keyed hash only; never the value).
    #[arg(long, visible_alias = "kb-secrets", help_heading = "Extraction")]
    pub detect_secrets: bool,
    /// Extract static forms into page metadata (the default).
    #[arg(long, conflicts_with = "no_form_extraction", help_heading = "Extraction")]
    pub form_extraction: bool,
    /// Do not extract static forms.
    #[arg(long, help_heading = "Extraction")]
    pub no_form_extraction: bool,
    /// Complete static forms with deterministic values (seed-derived, or from `--form-config`):
    /// GET forms are followed, other methods are recorded as endpoints, never sent.
    #[arg(long, help_heading = "Extraction")]
    pub automatic_form_fill: bool,
    /// YAML of form values (`email`, `color`, `password`, `phone`, `placeholder`) for
    /// `--automatic-form-fill`; implies it.
    #[arg(long, value_name = "FILE", help_heading = "Extraction")]
    pub form_config: Option<PathBuf>,
    /// Add the `knowledgebase` object (page type, forms, secrets, endpoints) to JSONL records.
    #[arg(long, help_heading = "Extraction")]
    pub knowledge_base: bool,
    /// Classify discovered endpoints as REST, GraphQL, SOAP, XHR or static.
    #[arg(long, help_heading = "Extraction")]
    pub kb_endpoints: bool,
    /// Check detected secrets against the provider endpoints listed in `--secret-validators`
    /// (sends the token to that provider); implies `--detect-secrets`. With no validators
    /// configured every finding stays `unknown`.
    #[arg(long, help_heading = "Extraction")]
    pub kb_validate_secrets: bool,
    /// File of secret validators (JSON) for `--kb-validate-secrets`; the built-in list is empty.
    #[arg(
        long,
        value_name = "FILE",
        requires = "kb_validate_secrets",
        help_heading = "Extraction"
    )]
    pub secret_validators: Option<PathBuf>,
    /// Keep `technologies` in the JSONL records under `--compat-defaults` (always on otherwise).
    #[arg(long, help_heading = "Extraction")]
    pub tech_detect: bool,

    // --- browser plane (compatibility -ph, -pls, -dwt) ---
    /// Isolated-world discovery hooks (`pushState`, `fetch`, `WebSocket`, `window.open`).
    #[arg(long, help_heading = "Headless")]
    pub page_hooks: bool,
    /// Headless readiness preset.
    #[arg(long, value_enum, help_heading = "Headless")]
    pub page_load_strategy: Option<PageLoadArg>,
    /// Upper bound in seconds the readiness preset waits for the DOM.
    #[arg(long, value_name = "SECONDS", help_heading = "Headless")]
    pub dom_wait_time: Option<u32>,
    /// Browser launch and exploration flags.
    #[command(flatten)]
    pub headless: HeadlessArgs,

    // --- output (compatibility -do, -jsonl, -f, -output-template, -sf, -o, -sr, ...) ---
    /// Record out-of-scope endpoints as never-fetched leaves.
    #[arg(long, help_heading = "Output")]
    pub display_out_scope: bool,
    /// Result streams, filters and verbosity.
    #[command(flatten)]
    pub out: OutputArgs,
    /// System 1 model and LLM planner endpoints.
    #[command(flatten)]
    pub model: ModelArgs,
    /// AI-assisted form filling (`--ai-*`).
    #[command(flatten)]
    pub ai: AiArgs,
    /// Opt-in captcha solver configuration.
    #[command(flatten)]
    pub captcha: crate::captcha_args::CaptchaArgs,
    /// Directory of the milestone gate files (`g1.passed`, `g3.passed`).
    #[arg(long, env = "CRAWLX_GATES_DIR", value_name = "DIR")]
    pub gates_dir: Option<PathBuf>,
}

/// URL-plane flags, flattened without changing their command-line names or help headings.
///
/// Keeping this group separate bounds the generated argument builder's stack frame in debug builds.
#[derive(Args, Debug, Clone, Default)]
#[non_exhaustive]
pub struct UrlArgs {
    // --- scope (compatibility -fs, -cs, -cos, -exclude, -strategy, -mdp, -kf, -em, -ef, -ndef, -d, -pc) ---
    /// Host scope: `dn`, `rdn`, `fqdn`, `none`, or a regex over the host name (hosts matching
    /// it are in scope in addition to the seed host).
    #[arg(long, value_parser = parse_field_scope, value_name = "SCOPE", help_heading = "Scope")]
    pub field_scope: Option<FieldScopeArg>,
    /// Disable only host-based scope. URL filters, authorization and egress checks still apply.
    #[arg(long, conflicts_with = "field_scope", help_heading = "Scope")]
    pub no_scope: bool,
    /// Regex over the full URL, or a file of regexes; only matching URLs are crawled.
    #[arg(long = "crawl-scope", value_name = "REGEX", help_heading = "Scope")]
    pub crawl_scope: Vec<String>,
    /// Regex over the full URL, or a file of regexes; matching URLs are skipped.
    #[arg(long = "crawl-out-scope", value_name = "REGEX", help_heading = "Scope")]
    pub crawl_out_scope: Vec<String>,
    /// Hosts never crawled: `cdn` (a bundled list of CDN and asset hosts), `private-ips`,
    /// CIDRs, IP literals or host regexes (comma separated).
    #[arg(
        short = 'e',
        long,
        visible_alias = "exclude",
        value_name = "LIST",
        value_delimiter = ',',
        help_heading = "Scope"
    )]
    pub exclude_hosts: Vec<String>,
    /// Frontier ordering.
    #[arg(short = 's', long, value_enum, help_heading = "Scope")]
    pub strategy: Option<StrategyArg>,
    /// Maximum link hops from the seed (compatibility `-depth`, at most 100).
    #[arg(
        short = 'd',
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u16).range(0..=100),
        help_heading = "Scope"
    )]
    pub depth: Option<u16>,
    /// Also crawl the parent directories of every discovered URL (`/a/b/c.html` adds `/a/b/`
    /// and `/a/`), within the same scope rules.
    #[arg(long, help_heading = "Scope")]
    pub path_climb: bool,
    /// Treat URLs that differ only in query-parameter values as one page.
    #[arg(long, help_heading = "Scope")]
    pub ignore_query_params: bool,
    /// Maximum pages admitted per host.
    #[arg(long, value_name = "N", help_heading = "Scope")]
    pub max_pages_per_host: Option<u32>,
    /// Well-known files mined for seeds (comma separated).
    #[arg(
        long,
        value_enum,
        value_name = "LIST",
        value_delimiter = ',',
        help_heading = "Scope"
    )]
    pub known_files: Vec<KnownFileArg>,
    /// Only crawl URLs with one of these extensions (comma separated; `none` is extensionless).
    #[arg(long, value_name = "LIST", value_delimiter = ',', help_heading = "Scope")]
    pub extension_match: Vec<String>,
    /// Skip URLs with one of these extensions, in addition to the default filter (comma separated).
    #[arg(long, value_name = "LIST", value_delimiter = ',', help_heading = "Scope")]
    pub extension_filter: Vec<String>,
    /// Disable the default extension filter (images, fonts, archives, media, documents).
    #[arg(long, help_heading = "Scope")]
    pub no_default_ext_filter: bool,
    /// Do not admit `regex`-confidence endpoints mined from JavaScript.
    #[arg(long, conflicts_with_all = ["js_crawl", "jsluice", "javascript_mode"], help_heading = "Scope")]
    pub no_js_endpoints: bool,
    /// Select regex-only JavaScript mining and admit its endpoints. Combine with
    /// `--jsluice` for both miners; overrides lower-priority request configuration.
    #[arg(long, help_heading = "Scope")]
    pub js_crawl: bool,
    /// Select AST-only JavaScript mining and admit its endpoints; combine with
    /// `--js-crawl` for both. Fails explicitly when AST support is unavailable.
    #[arg(long, help_heading = "Extraction")]
    pub jsluice: bool,
    /// Select exact JavaScript miners (native default: both). AST-only never falls
    /// back to regex; both retains regex on malformed or oversized scripts.
    #[arg(long, value_enum, conflicts_with_all = ["js_crawl", "jsluice", "no_js_endpoints"], help_heading = "Extraction")]
    pub javascript_mode: Option<JavascriptModeArg>,

    // --- filters (compatibility -fsu/-fst, -pcs, -duf, -filter-page-type) ---
    /// Skip URLs whose shape fingerprint already consumed its page budget.
    #[arg(long, help_heading = "Filters")]
    pub filter_similar: bool,
    /// Distinct values at one path position before it becomes `{param}` (default 10).
    #[arg(long, value_name = "N", help_heading = "Filters")]
    pub filter_similar_threshold: Option<u32>,
    /// Pages fetched per URL fingerprint (default 1).
    #[arg(long, value_name = "N", help_heading = "Filters")]
    pub filter_similar_budget: Option<u32>,
    /// Enable a page-content near-duplicate backend directly (native shorthand).
    #[arg(
        long,
        value_enum,
        conflicts_with_all = ["page_content_similar", "similarity_deduplication", "page_content_similar_mode"],
        help_heading = "Filters"
    )]
    pub content_similar: Option<SimilarityArg>,
    /// Enable content similarity independently of its backend (compatibility `-pcs`).
    /// A bare flag means true; use `=false` to override a lower-priority enable.
    #[arg(
        long,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true,
        help_heading = "Filters"
    )]
    pub page_content_similar: Option<bool>,
    /// Alternate content-similarity enable (compatibility `-sdd`); combined with `-pcs` using OR.
    #[arg(
        long,
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        require_equals = true,
        help_heading = "Filters"
    )]
    pub similarity_deduplication: Option<bool>,
    /// Select a backend without enabling it (compatibility `-pcsm`; enabled default: simhash).
    /// `off` explicitly disables filtering even when an enable switch is true.
    #[arg(long, value_enum, help_heading = "Filters")]
    pub page_content_similar_mode: Option<SimilarityArg>,
    /// Maximum simhash Hamming distance for `--content-similar simhash` (default 3).
    #[arg(
        long,
        visible_alias = "page-content-similar-distance",
        value_name = "N",
        help_heading = "Filters"
    )]
    pub content_similar_distance: Option<u8>,
    /// Minimum score for `--content-similar tfidf|bm25` (default 0.85).
    #[arg(
        long,
        visible_alias = "page-content-similar-threshold",
        value_name = "F",
        help_heading = "Filters"
    )]
    pub content_similar_threshold: Option<f64>,
    /// Pages fully processed per similarity cluster (default 1).
    #[arg(
        long,
        visible_alias = "page-content-similar-budget",
        value_name = "N",
        help_heading = "Filters"
    )]
    pub content_similar_budget: Option<u32>,
    /// Keep pages whose body is byte-identical to an earlier page instead of dropping them.
    #[arg(long, help_heading = "Filters")]
    pub disable_unique_filter: bool,
    /// Page types whose links are not followed (comma separated); the pages are still recorded.
    #[arg(
        long,
        value_enum,
        value_name = "TYPES",
        value_delimiter = ',',
        help_heading = "Filters"
    )]
    pub no_expand_page_type: Vec<PageTypeArg>,

    // --- rate limits (compatibility -rl, -rlm, -c) ---
    /// Global requests per second across all hosts.
    #[arg(
        long,
        value_name = "N",
        conflicts_with = "rate_limit_minute",
        help_heading = "Rate limits"
    )]
    pub rate_limit: Option<u32>,
    /// Global requests per minute across all hosts.
    #[arg(long, value_name = "N", help_heading = "Rate limits")]
    pub rate_limit_minute: Option<u32>,
    /// Requests per second per host.
    #[arg(
        long,
        value_name = "N",
        conflicts_with = "host_rate_limit_minute",
        help_heading = "Rate limits"
    )]
    pub host_rate_limit: Option<u32>,
    /// Requests per minute per host.
    #[arg(long, value_name = "N", help_heading = "Rate limits")]
    pub host_rate_limit_minute: Option<u32>,
    /// Maximum concurrent fetches across all hosts.
    #[arg(short = 'c', long, value_name = "N", help_heading = "Rate limits")]
    pub concurrency: Option<u16>,

    // --- fetch (compatibility -mrs, -timeout, -retry, -dr, -proxy, -r, -H) ---
    /// Maximum response body bytes read.
    #[arg(long, value_name = "BYTES", help_heading = "Fetch")]
    pub max_response_size: Option<u64>,
    /// Per-request timeout in seconds.
    #[arg(long, value_name = "SECONDS", help_heading = "Fetch")]
    pub timeout: Option<u32>,
    /// Retries after a retryable failure.
    #[arg(long, visible_alias = "retry", value_name = "N", help_heading = "Fetch")]
    pub retries: Option<u8>,
    /// Do not follow HTTP redirects.
    #[arg(long, visible_alias = "disable-redirects", help_heading = "Fetch")]
    pub no_redirects: bool,
    /// Upstream proxy for the fetch plane (`http`, `https`, `socks5`); egress checks still apply.
    #[arg(long, value_name = "URL", help_heading = "Fetch")]
    pub proxy: Option<Url>,
    /// DNS servers the fetch plane resolves with (comma separated `ip` or `ip:port`, a file of
    /// them, at most 8); egress checks still apply to the answers.
    #[arg(
        short = 'r',
        long,
        value_name = "LIST",
        value_delimiter = ',',
        help_heading = "Fetch"
    )]
    pub resolvers: Vec<String>,
    /// Header sent with every request of both planes: `Name: value` (repeatable, or a file of
    /// them). `Cookie` and `User-Agent` set the cookies and the user agent. Values are secrets:
    /// never logged or written to reports; `env://VAR` reads one from the environment.
    #[arg(short = 'H', long = "headers", value_name = "HEADER", help_heading = "Fetch")]
    pub headers: Vec<String>,
    /// Cookie sent to the seed's domain: `name=value[;domain=example.com][;path=/app]`.
    /// Repeatable; the value is a secret like a header value.
    #[arg(long, value_name = "COOKIE", help_heading = "Fetch")]
    pub cookie: Vec<String>,
    /// `User-Agent` of both planes (default `crawlx/<version>`).
    #[arg(long, value_name = "UA", help_heading = "Fetch")]
    pub user_agent: Option<String>,
    /// User-agent token robots.txt groups are matched with (default: the user agent).
    #[arg(long, value_name = "UA", help_heading = "Fetch")]
    pub robots_user_agent: Option<String>,
    /// Accept any server certificate on both planes.
    #[arg(long, help_heading = "Fetch")]
    pub skip_tls_verification: bool,
    /// Synthetic TLS ClientHello randomization for URL-only crawls.
    #[command(flatten)]
    pub tls: crate::tls_args::TlsArgs,
}

impl UrlArgs {
    fn fill_from(&mut self, lower: Self) {
        let Self {
            field_scope,
            no_scope,
            crawl_scope,
            crawl_out_scope,
            exclude_hosts,
            strategy,
            depth,
            path_climb,
            ignore_query_params,
            max_pages_per_host,
            known_files,
            extension_match,
            extension_filter,
            no_default_ext_filter,
            no_js_endpoints,
            js_crawl,
            jsluice,
            javascript_mode,
            filter_similar,
            filter_similar_threshold,
            filter_similar_budget,
            content_similar,
            page_content_similar,
            similarity_deduplication,
            page_content_similar_mode,
            content_similar_distance,
            content_similar_threshold,
            content_similar_budget,
            disable_unique_filter,
            no_expand_page_type,
            rate_limit,
            rate_limit_minute,
            host_rate_limit,
            host_rate_limit_minute,
            concurrency,
            max_response_size,
            timeout,
            retries,
            no_redirects,
            proxy,
            resolvers,
            headers,
            cookie,
            user_agent,
            robots_user_agent,
            skip_tls_verification,
            tls,
        } = lower;
        fill(&mut self.field_scope, field_scope);
        fill(&mut self.no_scope, no_scope);
        fill(&mut self.crawl_scope, crawl_scope);
        fill(&mut self.crawl_out_scope, crawl_out_scope);
        fill(&mut self.exclude_hosts, exclude_hosts);
        fill(&mut self.strategy, strategy);
        fill(&mut self.depth, depth);
        fill(&mut self.path_climb, path_climb);
        fill(&mut self.ignore_query_params, ignore_query_params);
        fill(&mut self.max_pages_per_host, max_pages_per_host);
        fill(&mut self.known_files, known_files);
        fill(&mut self.extension_match, extension_match);
        fill(&mut self.extension_filter, extension_filter);
        fill(&mut self.no_default_ext_filter, no_default_ext_filter);
        // JavaScript switches form one precedence group: a command-line selection
        // replaces the YAML flag layer, rather than combining contradictory modes.
        if self.javascript_mode.is_none() && !self.js_crawl && !self.jsluice && !self.no_js_endpoints {
            self.no_js_endpoints = no_js_endpoints;
            self.js_crawl = js_crawl;
            self.jsluice = jsluice;
            self.javascript_mode = javascript_mode;
        }
        fill(&mut self.filter_similar, filter_similar);
        fill(&mut self.filter_similar_threshold, filter_similar_threshold);
        fill(&mut self.filter_similar_budget, filter_similar_budget);
        // Native mode is an enabling shorthand; the compatibility flags keep enables and backend
        // independent. Do not merge a lower native shorthand into compatibility controls,
        // or lower compatibility controls into a command-line native shorthand.
        if self.content_similar.is_none() {
            if self.page_content_similar.is_none()
                && self.similarity_deduplication.is_none()
                && self.page_content_similar_mode.is_none()
            {
                self.content_similar = content_similar;
            }
            // Both compatibility enable spellings form one precedence group. An explicit
            // CLI false must replace either YAML spelling, not OR with it.
            if self.page_content_similar.is_none() && self.similarity_deduplication.is_none() {
                self.page_content_similar = page_content_similar;
                self.similarity_deduplication = similarity_deduplication;
            }
            fill(&mut self.page_content_similar_mode, page_content_similar_mode);
        }
        fill(&mut self.content_similar_distance, content_similar_distance);
        fill(&mut self.content_similar_threshold, content_similar_threshold);
        fill(&mut self.content_similar_budget, content_similar_budget);
        fill(&mut self.disable_unique_filter, disable_unique_filter);
        fill(&mut self.no_expand_page_type, no_expand_page_type);
        fill(&mut self.rate_limit, rate_limit);
        fill(&mut self.rate_limit_minute, rate_limit_minute);
        fill(&mut self.host_rate_limit, host_rate_limit);
        fill(&mut self.host_rate_limit_minute, host_rate_limit_minute);
        fill(&mut self.concurrency, concurrency);
        fill(&mut self.max_response_size, max_response_size);
        fill(&mut self.timeout, timeout);
        fill(&mut self.retries, retries);
        fill(&mut self.no_redirects, no_redirects);
        fill(&mut self.proxy, proxy);
        fill(&mut self.resolvers, resolvers);
        fill(&mut self.headers, headers);
        fill(&mut self.cookie, cookie);
        fill(&mut self.user_agent, user_agent);
        fill(&mut self.robots_user_agent, robots_user_agent);
        fill(&mut self.skip_tls_verification, skip_tls_verification);
        self.tls.fill_from(tls);
    }
}

impl CrawlArgs {
    /// Fill every unset flag from `lower` (a `--config` flag layer).
    pub(crate) fn fill_from(&mut self, lower: Self) {
        let Self {
            input,
            proxy_routes,
            mode,
            headless_mode,
            hybrid,
            profile,
            authorization_record,
            seed,
            output,
            observe_only,
            database_url,
            roles,
            launch_profile,
            allow_private_networks,
            limit_urls,
            limit_interactions,
            request,
            trailing_slash,
            delay_ms,
            delay_seconds,
            crawl_duration,
            compat_defaults,
            print_config,
            cache_mode,
            health_check,
            update,
            disable_update_check,
            url,
            custom_field_config,
            detect_secrets,
            form_extraction,
            no_form_extraction,
            automatic_form_fill,
            form_config,
            knowledge_base,
            kb_endpoints,
            kb_validate_secrets,
            secret_validators,
            tech_detect,
            page_hooks,
            page_load_strategy,
            dom_wait_time,
            headless,
            display_out_scope,
            out,
            model,
            ai,
            captcha,
            gates_dir,
        } = lower;
        self.input.fill_from(input);
        fill(
            &mut self.proxy_routes.fetch_basic_proxy_url,
            proxy_routes.fetch_basic_proxy_url,
        );
        fill(
            &mut self.proxy_routes.fetch_enhanced_proxy_url,
            proxy_routes.fetch_enhanced_proxy_url,
        );
        self.proxy_routes.proxyx.fill_from(proxy_routes.proxyx);
        self.headless.fill_from(headless);
        self.out.fill_from(out);
        self.model.fill_from(model);
        self.captcha.fill_from(captcha);
        if self.ai.is_unset() {
            self.ai = ai;
        }
        fill(&mut self.mode, mode);
        fill(&mut self.headless_mode, headless_mode);
        fill(&mut self.hybrid, hybrid);
        fill(&mut self.profile, profile);
        fill(&mut self.authorization_record, authorization_record);
        fill(&mut self.seed, seed);
        fill(&mut self.output, output);
        fill(&mut self.observe_only, observe_only);
        fill(&mut self.database_url, database_url);
        fill(&mut self.roles, roles);
        fill(&mut self.launch_profile, launch_profile);
        fill(&mut self.allow_private_networks, allow_private_networks);
        fill(&mut self.limit_urls, limit_urls);
        fill(&mut self.limit_interactions, limit_interactions);
        fill(&mut self.request, request);
        fill(&mut self.trailing_slash, trailing_slash);
        fill(&mut self.delay_ms, delay_ms);
        fill(&mut self.delay_seconds, delay_seconds);
        fill(&mut self.crawl_duration, crawl_duration);
        fill(&mut self.compat_defaults, compat_defaults);
        fill(&mut self.print_config, print_config);
        fill(&mut self.cache_mode, cache_mode);
        fill(&mut self.health_check, health_check);
        fill(&mut self.update, update);
        fill(&mut self.disable_update_check, disable_update_check);
        self.url.fill_from(url);
        fill(&mut self.custom_field_config, custom_field_config);
        fill(&mut self.detect_secrets, detect_secrets);
        fill(&mut self.form_extraction, form_extraction);
        fill(&mut self.no_form_extraction, no_form_extraction);
        fill(&mut self.automatic_form_fill, automatic_form_fill);
        fill(&mut self.form_config, form_config);
        fill(&mut self.knowledge_base, knowledge_base);
        fill(&mut self.kb_endpoints, kb_endpoints);
        fill(&mut self.kb_validate_secrets, kb_validate_secrets);
        fill(&mut self.secret_validators, secret_validators);
        fill(&mut self.tech_detect, tech_detect);
        fill(&mut self.page_hooks, page_hooks);
        fill(&mut self.page_load_strategy, page_load_strategy);
        fill(&mut self.dom_wait_time, dom_wait_time);
        fill(&mut self.display_out_scope, display_out_scope);
        fill(&mut self.gates_dir, gates_dir);
    }

    /// The output directory (`--output`, default `./crawlx-out`).
    pub(crate) fn output_dir(&self) -> PathBuf {
        self.output
            .clone()
            .unwrap_or_else(|| PathBuf::from("./crawlx-out"))
    }
}

/// Flags merged with their `--config` layer, and the request files read once.
#[derive(Debug)]
pub(crate) struct Resolved {
    /// The command-line flags with the YAML `--config` flags filled in below them.
    pub args: CrawlArgs,
    /// `--config` body (`.json`/`.toml`), applied under `--request`.
    layer: Option<Value>,
    /// `--request` body.
    request: Option<Value>,
}

impl Resolved {
    /// Read `--config` and `--request` and layer them.
    ///
    /// # Errors
    /// An unreadable or invalid configuration file or request.
    pub(crate) fn new(mut args: CrawlArgs) -> anyhow::Result<Self> {
        let mut layer = None;
        if let Some(path) = args.input.config.clone() {
            match config_file::load(&path)? {
                ConfigLayer::Flags(flags) => args.fill_from(*flags),
                ConfigLayer::Crawl(body) => layer = Some(body),
            }
        }
        let request = match &args.request {
            Some(path) => {
                let bytes = config_file::read_document(path)?;
                let body = serde_json::from_slice(&bytes).context("parsing request JSON")?;
                Some(config_file::checked_body_over(body, layer.as_ref(), path)?)
            }
            None => None,
        };
        Ok(Self { args, layer, request })
    }

    /// The `seedUrl` of the request file, else of the `--config` body, if either has one.
    fn request_seed(&self) -> anyhow::Result<Option<Url>> {
        let found = [(&self.request, "--request"), (&self.layer, "--config")]
            .into_iter()
            .find_map(|(body, origin)| {
                body.as_ref()
                    .and_then(|b| b.get("seedUrl"))
                    .and_then(Value::as_str)
                    .map(|text| (text, origin))
            });
        let Some((text, origin)) = found else {
            return Ok(None);
        };
        Url::parse(text)
            .map(Some)
            .with_context(|| format!("{origin}: invalid seedUrl {text:?}"))
    }

    /// The seeds of the run: flags, list files, standard input (`-`), else the request's.
    ///
    /// # Errors
    /// No seed, or an invalid URL.
    pub(crate) fn seeds(&self, stdin: impl FnOnce() -> anyhow::Result<String>) -> anyhow::Result<Vec<Url>> {
        input::resolve_seeds(&self.args.input, self.request_seed()?.as_ref(), stdin)
    }

    /// The request for `seed`: defaults, preset, `--config` body, `--request`, then flags.
    ///
    /// # Errors
    /// A request that does not deserialize or a flag value the request rejects.
    pub(crate) fn template(&self, seed: &Url) -> anyhow::Result<CreateCrawl> {
        let args = &self.args;
        let mut base = CreateCrawl::new(seed.clone());
        if args.compat_defaults {
            compat_flag_defaults::apply(&mut base);
        }
        let mut doc = serde_json::to_value(&base).context("building the default request")?;
        if let Some(layer) = &self.layer {
            config_file::deep_merge(&mut doc, layer);
        }
        if let Some(request) = &self.request {
            config_file::deep_merge(&mut doc, request);
        }
        let mut crawl: CreateCrawl =
            serde_json::from_value(doc).context("the request is not a valid crawl request")?;
        crawl.seed_url = seed.clone();
        apply_flags(args, &mut crawl)?;
        Ok(crawl)
    }
}

/// Build the request for the first seed from `--request`, `--config` and the flags.
///
/// # Errors
/// An unreadable or invalid request or configuration file, a missing or invalid seed, or a
/// flag value the request rejects.
pub fn build_request(args: &CrawlArgs) -> anyhow::Result<CreateCrawl> {
    let resolved = Resolved::new(args.clone())?;
    let seeds = resolved.seeds(|| Ok(String::new()))?;
    let first = seeds
        .first()
        .ok_or_else(|| anyhow!("a seed URL or --request is required"))?;
    resolved.template(first)
}

fn parse_role(spec: &str, recorded_plan: Option<&str>) -> anyhow::Result<Role> {
    let (name, reference) = spec
        .split_once('=')
        .filter(|(n, r)| !n.is_empty() && !r.is_empty())
        .ok_or_else(|| {
            anyhow!("--role expects NAME=REF (for example admin=env://ADMIN_CREDENTIAL), got {spec:?}")
        })?;
    Ok(Role {
        name: name.to_owned(),
        credential_ref: Some(CredentialRef(reference.to_owned())),
        login_plan: recorded_plan.map(str::to_owned),
        replica_base_url: None,
    })
}

/// The `recorded:` login plan of `--recorded-flow FILE`: the file is checked to be JSON now and
/// referenced by absolute path so the flow (which may hold typed values) stays out of reports.
fn recorded_plan(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str::<Value>(&text)
        .with_context(|| format!("--recorded-flow {} is not JSON", path.display()))?;
    let absolute = std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
    Ok(format!("recorded:file://{}", absolute.display()))
}

/// Compatibility `-timeout`/`-dwt`/`-rd` take seconds; the request stores milliseconds.
fn seconds_to_ms(flag: &str, secs: u32) -> anyhow::Result<u32> {
    secs.checked_mul(1000)
        .ok_or_else(|| anyhow!("{flag} {secs} overflows the millisecond field"))
}

/// Longest `limits.durationSeconds`.
const MAX_CRAWL_SECONDS: u64 = 604_800;

fn crawl_duration_seconds(d: Duration) -> anyhow::Result<u32> {
    if d < Duration::from_secs(1) {
        bail!("--crawl-duration {d:?} is shorter than 1s");
    }
    if d.as_secs() > MAX_CRAWL_SECONDS {
        bail!("--crawl-duration {d:?} is longer than 7d");
    }
    Ok(u32::try_from(d.as_secs())?)
}

/// Fold every flag into `crawl`.
fn apply_flags(args: &CrawlArgs, crawl: &mut CreateCrawl) -> anyhow::Result<()> {
    // Also guard programmatic arguments and conflicts introduced by config-file merging.
    if (args.headless_mode && (args.mode.is_some() || args.hybrid)) || (args.hybrid && args.mode.is_some()) {
        bail!("--mode, --headless and --hybrid are mutually exclusive");
    }
    if args.url.no_scope && args.url.field_scope.is_some() {
        bail!("--no-scope conflicts with --field-scope");
    }
    if args.delay_seconds.is_some() && args.delay_ms.is_some() {
        bail!("--delay conflicts with --delay-ms");
    }
    if args.url.content_similar.is_some()
        && (args.url.page_content_similar.is_some()
            || args.url.similarity_deduplication.is_some()
            || args.url.page_content_similar_mode.is_some())
    {
        bail!("--content-similar conflicts with --page-content-similar, --similarity-deduplication and --page-content-similar-mode");
    }
    if let Some(m) = args.mode {
        crawl.mode = match m {
            ModeArg::Static => CrawlMode::Static,
            ModeArg::Dynamic => CrawlMode::Dynamic,
            ModeArg::Hybrid => CrawlMode::Hybrid,
        };
    }
    if args.headless_mode {
        crawl.mode = CrawlMode::Dynamic;
    }
    if args.hybrid {
        crawl.mode = CrawlMode::Hybrid;
    }
    if let Some(p) = args.profile {
        crawl.safety.profile = match p {
            ProfileArg::ReadOnly => SafetyProfile::ReadOnly,
            ProfileArg::TestEnvironment => SafetyProfile::TestEnvironment,
            ProfileArg::AuthorizedSecurityTest => SafetyProfile::AuthorizedSecurityTest,
        };
    }
    if let Some(s) = args.seed {
        crawl.seed = Some(s);
    }
    if args.observe_only {
        crawl.dynamic.observe_only = true;
    }
    if let Some(l) = args.launch_profile {
        crawl.dynamic.launch_profile = match l {
            LaunchArg::Standard => LaunchProfile::Standard,
            LaunchArg::Stealth => LaunchProfile::Stealth,
        };
    }
    if args.allow_private_networks {
        crawl.safety.allow_private_networks = true;
    }
    if let Some(n) = args.limit_urls {
        crawl.limits.urls = n;
    }
    if let Some(n) = args.limit_interactions {
        crawl.limits.interactions = n;
    }
    if let Some(mode) = args.cache_mode {
        crawl
            .cache
            .get_or_insert_with(crawlx_core::cache::CachePolicyV1::default)
            .mode = mode.into();
    }
    if let Some(d) = args.crawl_duration {
        crawl.limits.duration_seconds = crawl_duration_seconds(d)?;
    }
    if let Some(ms) = args.delay_ms {
        crawl.politeness.delay_ms = ms;
    }
    if let Some(secs) = args.delay_seconds {
        crawl.politeness.delay_ms = seconds_to_ms("--delay", secs)?;
    }
    let plan = args
        .headless
        .recorded_flow
        .as_deref()
        .map(recorded_plan)
        .transpose()?;
    for spec in &args.roles {
        let role = parse_role(spec, plan.as_deref())?;
        crawl.roles.retain(|r| r.name != role.name);
        crawl.roles.push(role);
    }
    apply_scope(args, &mut crawl.scope)?;
    apply_politeness(args, &mut crawl.politeness);
    apply_fetch(args, &mut crawl.fetch)?;
    apply_extract(args, &mut crawl.extract)?;
    if args.display_out_scope {
        crawl.output.include_out_of_scope = true;
    }
    if args.out.wants_raw() {
        crawl.output.capture_raw = true;
    }
    if args.out.wants_body() && !crawl.output.formats.contains(&OutputFormat::RawHtml) {
        crawl.output.formats.push(OutputFormat::RawHtml);
    }
    if args.page_hooks {
        crawl.dynamic.page_hooks = true;
    }
    if let Some(s) = args.page_load_strategy {
        crawl.dynamic.page_load_strategy = s.into();
    }
    if let Some(secs) = args.dom_wait_time {
        crawl.dynamic.dom_wait_ms = seconds_to_ms("--dom-wait-time", secs)?;
    }
    args.headless.apply_request(crawl)?;
    args.model.apply(crawl);
    args.captcha.apply(crawl)?;
    Ok(())
}

fn apply_scope(args: &CrawlArgs, scope: &mut Scope) -> anyhow::Result<()> {
    match &args.url.field_scope {
        Some(FieldScopeArg::Host(h)) => scope.host_scope = *h,
        Some(FieldScopeArg::Pattern(p)) => scope.host_scope_pattern = Some(p.clone()),
        None => {}
    }
    if args.url.no_scope {
        scope.host_scope = HostScope::None;
        scope.host_scope_pattern = None;
    }
    if !args.url.crawl_scope.is_empty() {
        scope.url_include = expand_file_values(&args.url.crawl_scope)?;
    }
    if !args.url.crawl_out_scope.is_empty() {
        scope.url_exclude = expand_file_values(&args.url.crawl_out_scope)?;
    }
    if !args.url.exclude_hosts.is_empty() {
        scope.exclude_hosts.clone_from(&args.url.exclude_hosts);
    }
    if let Some(s) = args.url.strategy {
        scope.strategy = s.into();
    }
    if let Some(n) = args.url.depth {
        scope.max_discovery_depth = n;
    }
    if args.url.path_climb {
        scope.path_climb = true;
    }
    if args.url.ignore_query_params {
        scope.ignore_query_params = true;
    }
    if let Some(n) = args.url.max_pages_per_host {
        scope.max_pages_per_host = Some(n);
    }
    if !args.url.known_files.is_empty() {
        scope.known_files = KnownFileArg::expand(&args.url.known_files);
    }
    if !args.url.extension_match.is_empty() {
        scope.extension_match.clone_from(&args.url.extension_match);
    }
    if !args.url.extension_filter.is_empty() {
        scope.extension_filter.clone_from(&args.url.extension_filter);
    }
    if args.url.no_default_ext_filter {
        scope.no_default_extension_filter = true;
    }
    if args.url.no_js_endpoints {
        scope.js_endpoints = false;
    }
    if args.url.js_crawl || args.url.jsluice || args.url.javascript_mode.is_some() {
        scope.js_endpoints = true;
        if matches!(args.url.javascript_mode, Some(JavascriptModeArg::Off)) {
            scope.js_endpoints = false;
        }
    }
    if args.url.filter_similar {
        scope.filter_similar = true;
    }
    if let Some(n) = args.url.filter_similar_threshold {
        scope.filter_similar_threshold = n;
    }
    if let Some(n) = args.url.filter_similar_budget {
        scope.filter_similar_budget = n;
    }
    if let Some(m) = args.url.content_similar {
        scope.content_similarity.mode = m.into();
    }
    if args.url.page_content_similar.is_some()
        || args.url.similarity_deduplication.is_some()
        || args.url.page_content_similar_mode.is_some()
    {
        // Compatibility-flag semantics, ContentSimilarityEnabled:
        // pcs OR sdd enables; selecting pcsm alone never enables a disabled index.
        let enabled = match (args.url.page_content_similar, args.url.similarity_deduplication) {
            (None, None) => scope.content_similarity.mode != SimilarityMode::Off,
            (pcs, sdd) => pcs.unwrap_or(false) || sdd.unwrap_or(false),
        };
        scope.content_similarity.mode = if !enabled {
            SimilarityMode::Off
        } else if let Some(mode) = args.url.page_content_similar_mode {
            mode.into()
        } else if scope.content_similarity.mode == SimilarityMode::Off {
            SimilarityMode::Simhash
        } else {
            scope.content_similarity.mode
        };
    }
    if let Some(d) = args.url.content_similar_distance {
        scope.content_similarity.distance = d;
    }
    if let Some(t) = args.url.content_similar_threshold {
        scope.content_similarity.threshold = t;
    }
    if let Some(b) = args.url.content_similar_budget {
        scope.content_similarity.budget = b;
    }
    if args.url.disable_unique_filter {
        scope.disable_unique_filter = true;
    }
    if !args.url.no_expand_page_type.is_empty() {
        scope.filter_page_types = args.url.no_expand_page_type.iter().map(|&t| t.into()).collect();
    }
    Ok(())
}

fn apply_politeness(args: &CrawlArgs, p: &mut Politeness) {
    if let Some(n) = args.url.rate_limit {
        p.global_rps = Some(n);
    }
    if let Some(n) = args.url.rate_limit_minute {
        p.global_rpm = Some(n);
    }
    if let Some(n) = args.url.host_rate_limit {
        p.per_host_rps = Some(n);
    }
    if let Some(n) = args.url.host_rate_limit_minute {
        p.per_host_rpm = Some(n);
    }
    if let Some(n) = args.url.concurrency {
        p.max_concurrency = n;
    }
}

/// Values of a flag that may name a file: a value that is an existing file stands for its
/// non-blank, non-comment lines (the compatibility file-or-list slices).
fn expand_file_values(values: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        if !value.is_empty() && Path::new(value).is_file() {
            let text = std::fs::read_to_string(value).with_context(|| format!("reading {value}"))?;
            out.extend(
                text.lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_owned),
            );
        } else {
            out.push(value.clone());
        }
    }
    Ok(out)
}

/// `Name: value`.
fn split_header(raw: &str) -> anyhow::Result<(&str, &str)> {
    raw.split_once(':')
        .map(|(n, v)| (n.trim(), v.trim()))
        .filter(|(n, _)| !n.is_empty())
        .ok_or_else(|| anyhow!("--headers expects `Name: value`, got {raw:?}"))
}

/// `name=value[;domain=..][;path=..]`.
fn parse_cookie(raw: &str) -> anyhow::Result<FetchCookie> {
    let mut parts = raw.split(';').map(str::trim);
    let (name, value) = parts
        .next()
        .and_then(|p| p.split_once('='))
        .filter(|(n, _)| !n.trim().is_empty())
        .ok_or_else(|| {
            anyhow!("--cookie expects `name=value[;domain=..][;path=..]`, got an unreadable cookie")
        })?;
    let mut cookie = FetchCookie::new(name.trim(), value.trim());
    for attribute in parts.filter(|p| !p.is_empty()) {
        match attribute.split_once('=') {
            Some((k, v)) if k.trim().eq_ignore_ascii_case("domain") => {
                cookie.domain = Some(v.trim().to_owned())
            }
            Some((k, v)) if k.trim().eq_ignore_ascii_case("path") => cookie.path = Some(v.trim().to_owned()),
            _ => bail!("--cookie: unsupported attribute {attribute:?} (domain and path only)"),
        }
    }
    Ok(cookie)
}

fn apply_fetch(args: &CrawlArgs, f: &mut Fetch) -> anyhow::Result<()> {
    if let Some(n) = args.url.max_response_size {
        f.max_response_bytes = n;
    }
    if let Some(secs) = args.url.timeout {
        f.timeout_ms = seconds_to_ms("--timeout", secs)?;
    }
    if let Some(n) = args.url.retries {
        f.retries = n;
    }
    if args.url.no_redirects {
        f.follow_redirects = false;
    }
    if let Some(p) = &args.url.proxy {
        f.proxy = Some(p.clone());
    }
    if !args.url.resolvers.is_empty() {
        f.resolvers = crate::list_values::resolvers(&args.url.resolvers)?;
    }
    for raw in expand_file_values(&args.url.headers)? {
        let (name, value) = split_header(&raw)?;
        f.set_header(name, value)
            .with_context(|| format!("--headers {name:?}"))?;
    }
    for raw in &args.url.cookie {
        f.cookies.push(parse_cookie(raw)?);
    }
    if let Some(ua) = &args.url.user_agent {
        f.user_agent = Some(ua.clone());
    }
    if let Some(ua) = &args.url.robots_user_agent {
        f.robots_user_agent = Some(ua.clone());
    }
    if args.url.skip_tls_verification {
        f.skip_tls_verification = true;
    }
    args.url.tls.apply(f);
    Ok(())
}

fn apply_extract(args: &CrawlArgs, e: &mut Extract) -> anyhow::Result<()> {
    if args.url.javascript_mode.is_some()
        && (args.url.js_crawl || args.url.jsluice || args.url.no_js_endpoints)
    {
        bail!("--javascript-mode conflicts with --js-crawl, --jsluice and --no-js-endpoints");
    }
    if args.url.no_js_endpoints && (args.url.js_crawl || args.url.jsluice) {
        bail!("--no-js-endpoints conflicts with --js-crawl and --jsluice");
    }
    if let Some(mode) = args.url.javascript_mode {
        e.javascript.mode = mode.into();
    } else if args.url.js_crawl || args.url.jsluice {
        e.javascript.mode = if args.url.js_crawl && args.url.jsluice {
            JavascriptMode::Both
        } else if args.url.js_crawl {
            JavascriptMode::Regex
        } else {
            JavascriptMode::Ast
        };
    }
    if let Some(path) = &args.custom_field_config {
        e.custom_fields = load_custom_fields(path)?;
    }
    if args.detect_secrets || args.kb_validate_secrets {
        e.detect_secrets = true;
    }
    if args.kb_validate_secrets {
        e.validate_secrets = true;
    }
    if args.form_extraction {
        e.forms = true;
    }
    if args.no_form_extraction {
        e.forms = false;
    }
    if let Some(path) = &args.form_config {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        e.form_fill = crawlx_extract::form_fill::parse_form_config(&text)
            .with_context(|| format!("parsing --form-config {}", path.display()))?;
        e.form_fill.enabled = true;
    }
    if args.automatic_form_fill {
        e.form_fill.enabled = true;
    }
    if args.knowledge_base {
        e.knowledge_base = true;
    }
    if args.kb_endpoints {
        e.kb_endpoints = true;
    }
    Ok(())
}

/// One entry of `--custom-field-config`: the shape of the compatibility `CustomFieldConfig`
/// (ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md): `name`, `type` (only `regex`), `part`,
/// `group`, `regex[]`. As in the compatibility flags an absent `part` scans the whole response.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomFieldFile {
    name: String,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    part: Option<CustomFieldPart>,
    #[serde(default)]
    group: u32,
    #[serde(default)]
    regex: Vec<String>,
}

/// Parse a `--custom-field-config` file: JSON when the extension is `.json`, YAML otherwise.
///
/// # Errors
/// The file is unreadable, malformed, or an entry has a `type` other than `regex`.
pub fn load_custom_fields(path: &Path) -> anyhow::Result<Vec<CustomField>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let entries: Vec<CustomFieldFile> = if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("json")) {
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?
    } else {
        serde_yaml_ng::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?
    };
    entries
        .into_iter()
        .map(|f| {
            if let Some(kind) = f.kind.as_deref().filter(|k| *k != "regex") {
                bail!(
                    "custom field {:?}: unsupported type {kind:?} (only `regex`)",
                    f.name
                );
            }
            Ok(CustomField {
                name: f.name,
                regex: f.regex,
                part: f.part.unwrap_or(CustomFieldPart::Response),
                group: f.group,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn field_scope_is_a_preset_or_a_host_regex() {
        assert_eq!(
            parse_field_scope("RDN").unwrap(),
            FieldScopeArg::Host(HostScope::Rdn)
        );
        assert_eq!(
            parse_field_scope("none").unwrap(),
            FieldScopeArg::Host(HostScope::None)
        );
        assert_eq!(
            parse_field_scope("(company-staging.io|company.com)").unwrap(),
            FieldScopeArg::Pattern("(company-staging.io|company.com)".to_owned())
        );
        assert!(parse_field_scope("").is_err());
        assert!(parse_field_scope(&"a".repeat(513)).is_err());
    }

    #[test]
    fn headers_and_cookies_parse() {
        assert_eq!(split_header("X-Key:  a:b ").unwrap(), ("X-Key", "a:b"));
        assert!(split_header("no-colon").is_err());
        assert!(split_header(": v").is_err());
        let c = parse_cookie("sid=abc; Domain=example.com; path=/app").unwrap();
        assert_eq!((c.name.as_str(), c.value.as_str()), ("sid", "abc"));
        assert_eq!(c.domain.as_deref(), Some("example.com"));
        assert_eq!(c.path.as_deref(), Some("/app"));
        assert!(parse_cookie("novalue").is_err());
        assert!(parse_cookie("a=b; secure").is_err());
    }

    #[test]
    fn crawl_durations_are_at_least_one_second() {
        assert_eq!(crawl_duration_seconds(Duration::from_secs(1)).unwrap(), 1);
        assert_eq!(crawl_duration_seconds(Duration::from_secs(300)).unwrap(), 300);
        assert!(crawl_duration_seconds(Duration::from_millis(900)).is_err());
        assert!(crawl_duration_seconds(Duration::from_secs(604_801)).is_err());
    }
}
