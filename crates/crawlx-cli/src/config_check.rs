//! `crawlx config check`: load the configuration surface, validate it and print
//! the effective values with secrets redacted.
//!
//! Precedence (highest first): environment (`CRAWLX_` prefix, `__` for nesting, for example
//! `CRAWLX_WORKER__MAX_SESSIONS=8`), then `crawlx.toml` (`--config`, `CRAWLX_CONFIG`, or
//! `./crawlx.toml` when present), then the built-in defaults. Command-line flags of the
//! individual commands (`serve --bind`, `worker --max-sessions`) sit above all of these and are
//! not part of this check. Unknown keys fail the check. Secret-file keys name files; deployment
//! proxy URLs may carry credentials and are fully redacted from serialized and debug output.

pub use crate::resolver_https_config::ResolverHttpsSettings;

use anyhow::{anyhow, bail, Context as _};
use clap::{Args, Subcommand, ValueEnum};
use crawlx_api::config::OPERATOR_KEYS_FILE_ENV;
use crawlx_fetch::lists::EgressListSource;
use crawlx_policy::attestation::OperatorKeys;
use crawlx_policy::EgressLists;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Environment variable naming the configuration file.
pub const CONFIG_ENV: &str = "CRAWLX_CONFIG";
/// Environment variable naming the deployment environment.
pub const ENVIRONMENT_ENV: &str = "CRAWLX_ENVIRONMENT";
/// Environment variable naming the file that replaces `egress.deployment_allowlist`.
pub const DEPLOYMENT_ALLOWLIST_FILE_ENV: &str = "CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE";
/// Environment variable naming the file that replaces `egress.operator_blocklist` (RB-10 step 5).
pub const OPERATOR_BLOCKLIST_FILE_ENV: &str = "CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE";
/// Environment variable overriding the deployment's basic proxy route.
pub const BASIC_PROXY_URL_ENV: &str = "CRAWLX_FETCH_BASIC_PROXY_URL";
/// Environment variable overriding the deployment's enhanced proxy route.
pub const ENHANCED_PROXY_URL_ENV: &str = "CRAWLX_FETCH_ENHANCED_PROXY_URL";
/// The variables the egress list feed reads besides the configuration file: the commands that
/// only need the lists (`serve`, `worker`, `crawl`) look at exactly these, so an unrelated
/// `CRAWLX_*` variable never fails them (`config check` is the strict reader).
const EGRESS_ENV: &[&str] = &[
    CONFIG_ENV,
    ENVIRONMENT_ENV,
    DEPLOYMENT_ALLOWLIST_FILE_ENV,
    OPERATOR_BLOCKLIST_FILE_ENV,
    "CRAWLX_EGRESS__DEPLOYMENT_ALLOWLIST",
    "CRAWLX_EGRESS__OPERATOR_BLOCKLIST",
    "CRAWLX_EGRESS__DEPLOYMENT_ALLOWLIST_FILE",
    "CRAWLX_EGRESS__OPERATOR_BLOCKLIST_FILE",
];
/// Prefix of configuration overrides in the environment.
const ENV_PREFIX: &str = "CRAWLX_";
/// Environment variables with the prefix that are **not** configuration keys (flags, test and
/// development knobs read directly by the commands); they are reported, not rejected.
const PASSTHROUGH_ENV: &[&str] = &[
    "CRAWLX_CONFIG",
    "CRAWLX_ENVIRONMENT",
    "CRAWLX_LOG",
    "CRAWLX_OTLP_ENDPOINT",
    "CRAWLX_DATABASE_URL",
    "CRAWLX_DATABASE_URL_FILE",
    "CRAWLX_API_DATABASE_URL",
    "CRAWLX_API_DATABASE_URL_FILE",
    "CRAWLX_ALLOW_OWNER_API",
    "CRAWLX_ARTIFACTS_DIR",
    "CRAWLX_WEBHOOK_SECRET",
    "CRAWLX_WEBHOOK_SECRET_FILE",
    "CRAWLX_METRICS_BIND",
    "CRAWLX_PPROF_BIND",
    "CRAWLX_PPROF_ALLOW_NON_LOOPBACK",
    "CRAWLX_TLS_IMPERSONATE",
    "CRAWLX_GATES_DIR",
    "CRAWLX_GATE_KEYS_FILE",
    "CRAWLX_GATE_KEY_ID",
    "CRAWLX_CHROMIUM_PATH",
    "CRAWLX_ALLOW_UNPINNED",
    "CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI",
    "CRAWLX_TEST_DATABASE_URL",
    "CRAWLX_TEST_ZDR_REDIS_URL",
    "CRAWLX_TEST_SECRET_REDIS_URL",
    "CRAWLX_S3_ENDPOINT",
    "CRAWLX_S3_BUCKET",
    "CRAWLX_S3_REGION",
    "CRAWLX_S3_PATH_STYLE",
    "CRAWLX_S3_SSE",
    "CRAWLX_S3_PROFILE",
    "CRAWLX_S3_CHECKSUM",
    "CRAWLX_S3_OBJECT_LOCK",
    "CRAWLX_S3_ALLOW_HTTP",
    "CRAWLX_S3_ALLOW_KMS",
    "CRAWLX_S3_KMS_KEY_ID",
    "CRAWLX_MODEL_BUNDLE",
    "CRAWLX_PARITY_VECTORS",
    "CRAWLX_MODEL_BUNDLE_URL",
    "CRAWLX_COMPAT_KEYS",
    "CRAWLX_COMPAT_ROBOTS_AUTHORIZATION",
    "CRAWLX_OCR_BACKEND",
    "CRAWLX_OCR_LANGUAGES",
    "CRAWLX_OCR_TESSERACT",
    "CRAWLX_OCR_TESSDATA",
    "CRAWLX_OCR_MODELS",
    "CRAWLX_OCR_RASTERIZER",
    "CRAWLX_OCR_PDFTOPPM",
    "CRAWLX_OCR_DPI",
    "CRAWLX_OCR_TIMEOUT_MS",
    "CRAWLX_OCR_MAX_PDF_PAGES",
    "CRAWLX_OCR_MAX_IMAGE_PIXELS",
    "CRAWLX_OCR_MIN_CONFIDENCE",
    "CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE",
    "CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE",
    "CRAWLX_AUTHZ_OPERATOR_KEYS_FILE",
    "CRAWLX_API_URL",
    "CRAWLX_API_KEY",
    "CRAWLX_REQUEST_IDENTITY_KEY",
    "CRAWLX_REQUEST_IDENTITY_KEY_FILE",
    "CRAWLX_CHECKPOINT_KMS_KEY_ID",
    "CRAWLX_ARTIFACT_KMS_KEY_ID",
    "CRAWLX_ARTIFACT_KEY_FILE",
    "CRAWLX_SECRET_REDIS_URL",
    "CRAWLX_SECRET_REDIS_URL_FILE",
    "CRAWLX_SECRET_AUTHORITY_TTL_SECS",
    "CRAWLX_RETAINED_PROFILES_ENABLED",
    "CRAWLX_PROFILE_KEY_REF",
    "CRAWLX_PROFILE_MAX_TTL_SECONDS",
    "CRAWLX_PROFILE_EXECUTABLE_PREFERENCES",
    "CRAWLX_PROTOCOL_REGISTRY",
    "CRAWLX_DELIVERY_REGISTRY",
    "CRAWLX_ZDR_REDIS_URL",
    "CRAWLX_ARTICLE_LANGUAGE_BUNDLE",
    // model-provider, transcription and search settings read by `serve` (`IntelConfig`)
    "CRAWLX_LLM_BASE_URL",
    "CRAWLX_LLM_API_KEY",
    "CRAWLX_LLM_MODEL",
    "CRAWLX_LOCAL_LLM_BASE_URL",
    "CRAWLX_EMBEDDING_MODEL",
    "CRAWLX_TRANSCRIBE_ENDPOINT",
    "CRAWLX_TRANSCRIBE_MODEL",
    "CRAWLX_SEARCH_ENDPOINT",
    "CRAWLX_SEARCH_ENGINES",
    "CRAWLX_SEARCH_CATEGORIES",
    "CRAWLX_SEARCH_API_KEY",
    "CRAWLX_SEARCH_API_ENGINE",
];
/// Prefixes of the passthrough variables the `intel` report section covers; their raw values
/// are never printed ([`redacted_passthrough`]).
const INTEL_ENV_PREFIXES: &[&str] = &[
    "CRAWLX_LLM_",
    "CRAWLX_LOCAL_LLM_",
    "CRAWLX_EMBEDDING_",
    "CRAWLX_TRANSCRIBE_",
    "CRAWLX_SEARCH_",
];

/// Deployment environment.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Local `docker compose`.
    Dev,
    /// Ephemeral per pipeline.
    Ci,
    /// Production-shaped canary.
    Staging,
    /// Customer crawls.
    Prod,
}

impl Environment {
    /// Development-only knobs (`allow_unpinned`, `--no-sandbox`) are refused outside these.
    const fn allows_dev_knobs(self) -> bool {
        matches!(self, Self::Dev | Self::Ci)
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Dev => "dev",
            Self::Ci => "ci",
            Self::Staging => "staging",
            Self::Prod => "prod",
        }
    }
}

macro_rules! section {
    ($(#[$meta:meta])* $name:ident { $( $(#[$fm:meta])* $field:ident : $ty:ty = $default:expr ),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
        #[serde(deny_unknown_fields, default)]
        pub struct $name {
            $( $(#[$fm])* pub $field: $ty, )*
        }
        impl Default for $name {
            fn default() -> Self {
                Self { $( $field: $default, )* }
            }
        }
    };
}

section!(/// `[database]`.
Database {
    /// File holding the PostgreSQL DSN (secret).
    url_file: Option<PathBuf> = None,
    /// Pool size per process.
    pool_max: u32 = 32,
    /// Session statement timeout.
    statement_timeout_ms: u64 = 5000,
});

section!(/// `[object_store]`.
ObjectStore {
    /// S3 API endpoint; empty for the filesystem store.
    endpoint: String = String::new(),
    /// Bucket.
    bucket: String = String::new(),
    /// Region.
    region: String = String::new(),
    /// File holding the credentials (secret).
    credentials_file: Option<PathBuf> = None,
    /// Memory-only local spool ceiling; no filesystem spool or plaintext WAL is used.
    spool_max_bytes: u64 = 2 * 1024 * 1024 * 1024,
    /// Maximum queued and active entries, including empty uploads.
    spool_max_entries: usize = 1024,
    /// Maximum upload attempts, including the first attempt.
    spool_max_attempts: u32 = 3,
    /// Delay between retryable upload failures.
    spool_retry_delay_ms: u64 = 1000,
    /// Deadline of each backend request.
    spool_request_timeout_ms: u64 = 30_000,
});

impl ObjectStore {
    fn spool_config(&self) -> anyhow::Result<crawlx_storage::UploadSpoolConfig> {
        let mut config = crawlx_storage::UploadSpoolConfig::default();
        config.max_bytes = self.spool_max_bytes;
        config.max_entries = self.spool_max_entries;
        config.max_attempts = self.spool_max_attempts;
        config.retry_delay = std::time::Duration::from_millis(self.spool_retry_delay_ms);
        config.request_timeout = std::time::Duration::from_millis(self.spool_request_timeout_ms);
        crawlx_storage::UploadSpool::new(config.clone()).context("object_store upload spool")?;
        Ok(config)
    }
}

section!(/// `[api.webhook]`.
Webhook {
    /// File holding the signing key (secret).
    signing_key_file: Option<PathBuf> = None,
    /// Retry schedule (humantime-style durations).
    retry_schedule: Vec<String> = ["10s", "1m", "5m", "30m", "2h", "6h", "12h", "24h"].iter().map(|s| (*s).to_owned()).collect(),
    /// Retry window.
    retry_window: String = "24h".to_owned(),
});

section!(/// `[api]`.
Api {
    /// Public listener.
    listen: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 8080)),
    /// Management listener (loopback).
    admin_listen: SocketAddr = SocketAddr::from(([127, 0, 0, 1], 9090)),
    /// Webhook signing and retry.
    webhook: Webhook = Webhook::default(),
});

section!(/// `[worker]`.
Worker {
    /// Leases held per worker.
    max_sessions: u32 = 4,
    /// Contexts per Chromium.
    contexts_per_browser: u32 = 4,
    /// Checkpoint cadence.
    checkpoint_every_actions: u32 = 50,
});

section!(/// `[scheduler]`.
Scheduler {
    /// Session lease TTL.
    session_lease_ttl_s: u32 = 30,
    /// URL batch lease TTL.
    url_lease_ttl_s: u32 = 60,
    /// Heartbeat period.
    heartbeat_s: u32 = 10,
    /// Reaper period.
    reaper_interval_s: u32 = 15,
    /// `open`, `drain` or `frozen` at start-up; flipped at runtime by `crawlx admin freeze`.
    admission: crawlx_storage::AdmissionMode = crawlx_storage::AdmissionMode::Open,
});

/// Secret-bearing deployment proxy input. Serialization and debug output never expose its value.
///
/// Validation is deferred until configuration validation or runtime setup so argument parsers
/// cannot echo a rejected URL, including its credentials.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct ProxyUrl(pub(crate) String);

impl std::fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for ProxyUrl {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("<redacted>")
    }
}

impl ProxyUrl {
    pub(crate) fn parse(&self) -> anyhow::Result<url::Url> {
        let url = url::Url::parse(&self.0).context("invalid proxy URL")?;
        if !matches!(url.scheme(), "http" | "https" | "socks5" | "socks5h") {
            bail!("proxy scheme must be http, https, socks5 or socks5h");
        }
        if url.host_str().is_none() {
            bail!("proxy URL must have a host");
        }
        Ok(url)
    }
}

pub(crate) fn proxy_url_arg(value: &str) -> Result<ProxyUrl, std::convert::Infallible> {
    Ok(ProxyUrl(value.to_owned()))
}

/// Deployment-owned proxy routes, separate from a crawl's per-request `--proxy`.
#[derive(Args, Clone, Debug, Default)]
pub struct ProxyArgs {
    /// Basic deployment proxy URL; overrides CRAWLX_FETCH_BASIC_PROXY_URL and [fetch].basic_proxy_url.
    #[arg(long, value_name = "URL", value_parser = proxy_url_arg, help_heading = "Deployment")]
    pub fetch_basic_proxy_url: Option<ProxyUrl>,
    /// Enhanced deployment proxy URL; overrides CRAWLX_FETCH_ENHANCED_PROXY_URL and [fetch].enhanced_proxy_url.
    #[arg(long, value_name = "URL", value_parser = proxy_url_arg, help_heading = "Deployment")]
    pub fetch_enhanced_proxy_url: Option<ProxyUrl>,
    /// ProxyX pool gateway as the upstream of the basic and/or enhanced tier.
    #[command(flatten)]
    pub proxyx: crate::proxyx_config::ProxyxArgs,
}

impl ProxyArgs {
    /// Resolve deployment routes from flags, environment and `crawlx.toml`, in that order.
    ///
    /// # Errors
    /// Fails on unreadable or malformed configuration, an invalid proxy URL or unsupported scheme,
    /// or an invalid ProxyX pool route (`[fetch.proxyx]`).
    pub fn routes(
        &self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<crawlx_fetch::ProxyRoutes> {
        let mut names: Vec<String> = [
            BASIC_PROXY_URL_ENV,
            ENHANCED_PROXY_URL_ENV,
            "CRAWLX_FETCH__BASIC_PROXY_URL",
            "CRAWLX_FETCH__ENHANCED_PROXY_URL",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        names.extend(crate::proxyx_config::env_names());
        let vars = names
            .into_iter()
            .filter_map(|name| getenv(&name).map(|value| (name, value)))
            .collect::<Vec<_>>();
        let file = getenv(CONFIG_ENV)
            .filter(|p| !p.trim().is_empty())
            .map(PathBuf::from);
        let fetch = load_from(file.as_deref(), &vars)?.config.fetch;
        let mut routes = parse_proxy_routes(
            self.fetch_basic_proxy_url
                .as_ref()
                .or(fetch.basic_proxy_url.as_ref()),
            self.fetch_enhanced_proxy_url
                .as_ref()
                .or(fetch.enhanced_proxy_url.as_ref()),
        )?;
        crate::proxyx_config::apply(&fetch.proxyx, &self.proxyx, getenv, &mut routes)?;
        Ok(routes)
    }
}

section!(/// `[fetch]`.
Fetch {
    /// Per-origin in-flight requests.
    per_origin_inflight: u32 = 1,
    /// Minimum spacing between requests to one origin.
    min_spacing_ms: u32 = 250,
    /// Deployment-owned basic upstream; unset preserves the per-request `fetch.proxy` fallback.
    basic_proxy_url: Option<ProxyUrl> = None,
    /// Deployment-owned enhanced upstream; required for enhanced and auto proxy modes.
    enhanced_proxy_url: Option<ProxyUrl> = None,
    /// ProxyX pool gateway as the upstream of the basic and/or enhanced tier (`[fetch.proxyx]`).
    proxyx: crate::proxyx_config::Proxyx = crate::proxyx_config::Proxyx::default(),
    /// Operator-only checked encrypted DNS endpoint, pins and bounded lookup budgets.
    resolver_https: Option<ResolverHttpsSettings> = None,
});

impl Fetch {
    /// Parse configured routes without exposing URLs or credentials in errors. The ProxyX org key
    /// reference is resolved through `getenv` (`env://`) or the file system (`file://`).
    ///
    /// # Errors
    /// Fails when either route has an invalid URL, unsupported scheme or missing host, or the
    /// pool route is incomplete or invalid.
    pub fn proxy_routes(
        &self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<crawlx_fetch::ProxyRoutes> {
        let mut routes = parse_proxy_routes(self.basic_proxy_url.as_ref(), self.enhanced_proxy_url.as_ref())?;
        crate::proxyx_config::apply(
            &self.proxyx,
            &crate::proxyx_config::ProxyxArgs::default(),
            getenv,
            &mut routes,
        )?;
        Ok(routes)
    }
}

fn parse_proxy_routes(
    basic: Option<&ProxyUrl>,
    enhanced: Option<&ProxyUrl>,
) -> anyhow::Result<crawlx_fetch::ProxyRoutes> {
    let mut routes = crawlx_fetch::ProxyRoutes::default();
    routes.basic = basic
        .map(ProxyUrl::parse)
        .transpose()
        .context("fetch.basic_proxy_url")?;
    routes.enhanced = enhanced
        .map(ProxyUrl::parse)
        .transpose()
        .context("fetch.enhanced_proxy_url")?;
    Ok(routes)
}

/// `egress.mode`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    /// Loopback CONNECT proxy (default).
    #[default]
    Proxy,
    /// Network namespace with nftables (`deploy/k8s/nftables-netns.example`).
    Netns,
}

section!(/// `[egress]`: the deployment lists and the operator blocklist of RB-10 step 5.
///
/// A list can come from the configuration or from a file. **A set file replaces the static list
/// of its kind** (the allowlist file is the whole allowlist, the blocklist file the whole
/// blocklist); a file that is named but missing or malformed fails start-up and `config check`.
/// A running `serve`, `worker` or `crawl` re-reads the files on `SIGHUP` and every 60 s when they
/// changed, and keeps the previous lists when a file no longer parses. The environment names the
/// files too: `CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE` and `CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE`
/// win over the keys below; the static lists are overridden by `CRAWLX_EGRESS__DEPLOYMENT_ALLOWLIST`
/// and `CRAWLX_EGRESS__OPERATOR_BLOCKLIST` as TOML arrays (`'["10.0.0.0/8"]'`).
Egress {
    /// Egress mode.
    mode: EgressMode = EgressMode::Proxy,
    /// The private, loopback and unique-local networks this deployment lets any run reach: an
    /// authorization record's `authorizedNetworks` must lie inside them, and a `test_environment`
    /// run reaches only them. CIDRs or bare addresses. Unset: the deployment sets no bound; set
    /// and empty: no private network is reachable at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_allowlist: Option<Vec<String>> = None,
    /// Hosts (a host also blocks its subdomains; `*.host` is accepted), IP addresses and CIDRs no
    /// run may reach, whatever its authorization record says (takedown requests).
    operator_blocklist: Vec<String> = Vec::new(),
    /// File with one CIDR or address per line (`#` comments); replaces `deployment_allowlist`.
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_allowlist_file: Option<PathBuf> = None,
    /// File with one host, address or CIDR per line (`#` comments); replaces `operator_blocklist`.
    #[serde(skip_serializing_if = "Option::is_none")]
    operator_blocklist_file: Option<PathBuf> = None,
});

section!(/// `[browser]`.
Browser {
    /// Pin file.
    pin_file: PathBuf = PathBuf::from("chromium-pin.toml"),
    /// Development only; recorded as `pinned = false`.
    allow_unpinned: bool = false,
    /// Launch profiles a deployment admits.
    launch_profile_allowed: Vec<String> = vec!["standard".to_owned(), "stealth".to_owned()],
});

section!(/// `[model.breaker]`.
Breaker {
    /// Failures before the breaker opens.
    failure_threshold: u32 = 5,
    /// Cooldown before a half-open probe.
    cooldown_s: u32 = 30,
});

section!(/// `[model]`.
Model {
    /// Default System-1 mode.
    mode_default: String = "shadow".to_owned(),
    /// Breaker.
    breaker: Breaker = Breaker::default(),
    /// Request timeout.
    timeout_ms: u32 = 800,
});

section!(/// `[retention]`.
Retention {
    /// Sweeper cadence.
    sweep_interval_s: u32 = 300,
    /// Overdue grace.
    grace_s: u32 = 900,
});

section!(/// `[telemetry]`.
Telemetry {
    /// OTLP collector endpoint.
    otlp_endpoint: Option<String> = None,
    /// Trace sampling ratio.
    trace_sampling: f64 = 0.1,
});

section!(/// `[safety]`.
Safety {
    /// Profile applied when a request omits it.
    default_profile: String = "read_only".to_owned(),
});

section!(/// `[shadow]`.
Shadow {
    /// Share of `X-Crawlx-Shadow` requests mirrored.
    sample_percent: u8 = 5,
});

section!(/// The whole `crawlx.toml` surface.
CrawlxConfig {
    /// Deployment environment; `CRAWLX_ENVIRONMENT` overrides.
    environment: Environment = Environment::Prod,
    /// Database.
    database: Database = Database::default(),
    /// Object store.
    object_store: ObjectStore = ObjectStore::default(),
    /// API.
    api: Api = Api::default(),
    /// Worker.
    worker: Worker = Worker::default(),
    /// Scheduler.
    scheduler: Scheduler = Scheduler::default(),
    /// Fetch.
    fetch: Fetch = Fetch::default(),
    /// Egress.
    egress: Egress = Egress::default(),
    /// Browser.
    browser: Browser = Browser::default(),
    /// Model.
    model: Model = Model::default(),
    /// Retention.
    retention: Retention = Retention::default(),
    /// Telemetry.
    telemetry: Telemetry = Telemetry::default(),
    /// Safety.
    safety: Safety = Safety::default(),
    /// Shadow mode.
    shadow: Shadow = Shadow::default(),
    /// OCR for scanned PDF pages and images (`ocr.backend`: off, tesseract, ocrs).
    ocr: crawlx_extract::parse::ocr::OcrConfig = crawlx_extract::parse::ocr::OcrConfig::default(),
});

/// Output format of `config check`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum CheckFormat {
    /// Human-readable TOML of the effective values.
    Toml,
    /// `{ "effective": …, "sources": …, "secrets": …, "warnings": [] }`.
    Json,
}

/// Arguments of `crawlx config`.
#[derive(Args, Debug)]
pub struct ConfigArgs {
    /// Subcommand.
    #[command(subcommand)]
    pub command: ConfigCommand,
}

/// `crawlx config` subcommands.
#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Load `crawlx.toml` + `CRAWLX_*` overrides, validate, print the effective values.
    Check(ConfigCheckArgs),
    /// Print the versioned feature manifest of the `crawl` flag set: per row the baseline
    /// release, the flags and compatibility spellings, the policy (including intentional
    /// deviations) and the tests that exercise it. JSON on stdout.
    Features,
}

/// The feature manifest embedded in the binary (`data/feature-manifest.json`).
pub const FEATURE_MANIFEST: &str = include_str!("../data/feature-manifest.json");

/// Arguments of `crawlx config check`.
#[derive(Args, Debug)]
pub struct ConfigCheckArgs {
    /// Configuration file; defaults to `$CRAWLX_CONFIG`, then `./crawlx.toml` when present.
    #[arg(long, env = CONFIG_ENV, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Output format.
    #[arg(long, value_enum, default_value = "toml")]
    pub format: CheckFormat,
    /// Fail (exit 1) on warnings too, not only on errors.
    #[arg(long)]
    pub strict: bool,
}

/// Where each top-level section's values came from.
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Built-in default.
    Default,
    /// `crawlx.toml`.
    File,
    /// `CRAWLX_*` environment override.
    Env,
}

/// The result of loading the surface.
#[derive(Clone, PartialEq)]
pub struct Loaded {
    /// Effective configuration.
    pub config: CrawlxConfig,
    /// File that was read, if any.
    pub file: Option<PathBuf>,
    /// Dotted key → source, for every key that is not at its default.
    pub sources: BTreeMap<String, Source>,
    /// Environment variables with the prefix that are passed through to commands untouched.
    pub passthrough: BTreeMap<String, String>,
}

impl std::fmt::Debug for Loaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loaded")
            .field("config", &self.config)
            .field("file", &self.file)
            .field("sources", &self.sources)
            .field("passthrough", &redacted_passthrough(&self.passthrough))
            .finish()
    }
}

/// Load the surface from `file` (or the discovered default) and the process environment.
///
/// # Errors
/// Fails on an unreadable or malformed file, an unknown key, an override that does not parse
/// as the key's type, or an unrecognised `CRAWLX_*` variable.
pub fn load(file: Option<&Path>) -> anyhow::Result<Loaded> {
    validate_operator_environment(&|name| std::env::var_os(name))?;
    let mut vars = Vec::new();
    for (name, value) in std::env::vars_os() {
        let Some(name) = name.to_str().filter(|name| name.starts_with(ENV_PREFIX)) else {
            continue;
        };
        let value = value
            .into_string()
            .map_err(|_| anyhow!("CRAWLX configuration values must be valid Unicode"))?;
        vars.push((name.to_owned(), value));
    }
    load_from(file, &vars)
}

/// Reject non-Unicode operator capability settings before lossy lookups can hide them.
pub(crate) fn validate_operator_environment(
    getenv: &dyn Fn(&str) -> Option<std::ffi::OsString>,
) -> anyhow::Result<()> {
    for name in [
        "CRAWLX_REQUEST_IDENTITY_KEY",
        "CRAWLX_REQUEST_IDENTITY_KEY_FILE",
        "CRAWLX_CHECKPOINT_KMS_KEY_ID",
        "CRAWLX_ARTIFACT_KMS_KEY_ID",
        "CRAWLX_ARTIFACT_KEY_FILE",
        "CRAWLX_SECRET_REDIS_URL",
        "CRAWLX_SECRET_REDIS_URL_FILE",
        "CRAWLX_SECRET_AUTHORITY_TTL_SECS",
        "CRAWLX_ARTICLE_LANGUAGE_BUNDLE",
    ]
    .into_iter()
    .chain(crate::resolver_https_config::ENV.iter().copied())
    {
        if getenv(name).is_some_and(|value| value.into_string().is_err()) {
            bail!("operator capability settings must be valid Unicode");
        }
    }
    Ok(())
}

/// [`load`] over an explicit environment (tests).
///
/// # Errors
/// See [`load`].
pub fn load_from(file: Option<&Path>, vars: &[(String, String)]) -> anyhow::Result<Loaded> {
    let file = match file {
        Some(f) => Some(f.to_path_buf()),
        None => Path::new("crawlx.toml")
            .is_file()
            .then(|| PathBuf::from("crawlx.toml")),
    };
    let mut doc: toml::Table = match &file {
        Some(path) => {
            let text =
                std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
            // TOML diagnostics include source lines, which may contain proxy credentials.
            text.parse::<toml::Table>()
                .map_err(|_| anyhow!("parsing {}: invalid TOML configuration", path.display()))?
        }
        None => toml::Table::new(),
    };
    let mut sources = BTreeMap::new();
    for key in dotted_keys(&doc, "") {
        sources.insert(key, Source::File);
    }
    let mut passthrough = BTreeMap::new();
    let mut env_vars: Vec<&(String, String)> = vars.iter().collect();
    env_vars.sort();
    for (name, value) in env_vars {
        if PASSTHROUGH_ENV.contains(&name.as_str())
            || crate::proxyx_config::SELECTOR_ENV.contains(&name.as_str())
        {
            passthrough.insert(name.clone(), value.clone());
            let secret_path = match name.as_str() {
                "CRAWLX_DATABASE_URL_FILE" => Some(vec!["database".to_owned(), "url_file".to_owned()]),
                "CRAWLX_WEBHOOK_SECRET_FILE" => Some(vec![
                    "api".to_owned(),
                    "webhook".to_owned(),
                    "signing_key_file".to_owned(),
                ]),
                _ => None,
            };
            if let Some(path) = secret_path {
                set_override(&mut doc, &path, value, name)?;
                sources.insert(path.join("."), Source::Env);
            }
            continue;
        }
        let Some(rest) = name.strip_prefix(ENV_PREFIX) else {
            continue;
        };
        let proxy_key: Option<Vec<&str>> = match name.as_str() {
            BASIC_PROXY_URL_ENV => Some(vec!["fetch", "basic_proxy_url"]),
            ENHANCED_PROXY_URL_ENV => Some(vec!["fetch", "enhanced_proxy_url"]),
            other => crate::proxyx_config::FLAT_KEY_ENV
                .iter()
                .find(|(env, _)| *env == other)
                .map(|(_, key)| vec!["fetch", "proxyx", *key]),
        };
        if let Some(path) = proxy_key {
            let path: Vec<String> = path.into_iter().map(str::to_owned).collect();
            set_override(&mut doc, &path, value, name)?;
            sources.insert(path.join("."), Source::Env);
            continue;
        }
        if !rest.contains("__") {
            bail!(
                "{name} is not a configuration key: overrides use `__` for nesting \
                 (for example CRAWLX_WORKER__MAX_SESSIONS); known flat variables are {}",
                PASSTHROUGH_ENV.join(", ")
            );
        }
        let path: Vec<String> = rest.split("__").map(|s| s.to_ascii_lowercase()).collect();
        set_override(&mut doc, &path, value, name)?;
        sources.insert(path.join("."), Source::Env);
    }
    let mut config: CrawlxConfig = doc
        .try_into()
        .map_err(|e| anyhow!("configuration is invalid: {e}"))?;
    if let Some(env) = vars.iter().find(|(k, _)| k == ENVIRONMENT_ENV) {
        config.environment = match env.1.as_str() {
            "dev" => Environment::Dev,
            "ci" => Environment::Ci,
            "staging" => Environment::Staging,
            "prod" => Environment::Prod,
            other => bail!("{ENVIRONMENT_ENV}={other:?}: expected dev, ci, staging or prod"),
        };
        sources.insert("environment".to_owned(), Source::Env);
    }
    Ok(Loaded {
        config,
        file,
        sources,
        passthrough,
    })
}

/// Every dotted leaf key of a TOML table.
fn dotted_keys(table: &toml::Table, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (k, v) in table {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            toml::Value::Table(t) => out.extend(dotted_keys(t, &key)),
            _ => out.push(key),
        }
    }
    out
}

/// Set `path` in `doc` to `value`, parsing it as TOML when it looks like a number, boolean or
/// array and as a string otherwise. Intermediate tables are created; a conflict with a
/// non-table value is an error.
fn set_override(doc: &mut toml::Table, path: &[String], value: &str, var: &str) -> anyhow::Result<()> {
    let (leaf, parents) = path.split_last().ok_or_else(|| anyhow!("{var}: empty key"))?;
    let mut table = doc;
    for p in parents {
        let entry = table
            .entry(p.clone())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        table = match entry {
            toml::Value::Table(t) => t,
            _ => bail!("{var}: `{p}` is a value, not a section"),
        };
    }
    // a scalar is not a TOML document on its own; wrap it to parse numbers, booleans, arrays
    let parsed = match format!("v = {value}")
        .parse::<toml::Table>()
        .map(|mut t| t.remove("v"))
    {
        Ok(Some(
            v @ (toml::Value::Integer(_)
            | toml::Value::Float(_)
            | toml::Value::Boolean(_)
            | toml::Value::Array(_)),
        )) => v,
        _ => toml::Value::String(value.to_owned()),
    };
    table.insert(leaf.clone(), parsed);
    Ok(())
}

/// One finding of [`validate`].
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct Finding {
    /// Dotted key.
    pub key: String,
    /// What is wrong.
    pub message: String,
    /// `true` blocks the roll; `false` is advice.
    pub error: bool,
}

fn finding(key: &str, message: impl Into<String>, error: bool) -> Finding {
    Finding {
        key: key.to_owned(),
        message: message.into(),
        error,
    }
}

/// Secret-file status for the report (never the contents).
#[derive(Clone, PartialEq, Eq, Serialize, Debug)]
pub struct SecretStatus {
    /// Dotted key.
    pub key: String,
    /// Path as configured.
    pub path: PathBuf,
    /// Readable and non-empty.
    pub present: bool,
    /// Size in bytes when present.
    pub bytes: Option<u64>,
}

/// Validate `loaded` (value ranges and production rules) and probe the secret files.
#[must_use]
pub fn validate(loaded: &Loaded) -> (Vec<Finding>, Vec<SecretStatus>) {
    let c = &loaded.config;
    let mut f = Vec::new();
    let mut secrets = Vec::new();
    let prod = !c.environment.allows_dev_knobs();
    if let Err(error) = c.object_store.spool_config() {
        f.push(finding("object_store", format!("{error:#}"), true));
    }

    // secrets: files only (never flags), must exist in staging/prod when the consumer is configured
    for (key, path, required) in [
        ("database.url_file", c.database.url_file.as_ref(), prod),
        (
            "api.webhook.signing_key_file",
            c.api.webhook.signing_key_file.as_ref(),
            prod,
        ),
        (
            "object_store.credentials_file",
            c.object_store.credentials_file.as_ref(),
            prod && !c.object_store.endpoint.is_empty(),
        ),
    ] {
        match path {
            Some(p) => {
                let bytes = std::fs::metadata(p).ok().map(|m| m.len());
                let present = bytes.is_some_and(|n| n > 0);
                if !present {
                    f.push(finding(
                        key,
                        format!("{} is missing or empty", p.display()),
                        required,
                    ));
                }
                secrets.push(SecretStatus {
                    key: key.to_owned(),
                    path: p.clone(),
                    present,
                    bytes,
                });
            }
            None if required
                && !loaded
                    .passthrough
                    .contains_key(&format!("CRAWLX_{}", flat_secret(key))) =>
            {
                f.push(finding(
                    key,
                    "not set; secrets are read from files in staging/prod",
                    true,
                ));
            }
            None => {}
        }
    }
    if loaded.passthrough.contains_key("CRAWLX_DATABASE_URL") && prod {
        f.push(finding(
            "database.url_file",
            "CRAWLX_DATABASE_URL carries the DSN in the environment; use database.url_file (CRAWLX_DATABASE_URL_FILE) in staging/prod",
            false,
        ));
    }
    if loaded.passthrough.contains_key("CRAWLX_WEBHOOK_SECRET") && prod {
        f.push(finding(
            "api.webhook.signing_key_file",
            "CRAWLX_WEBHOOK_SECRET carries the key in the environment; use api.webhook.signing_key_file",
            false,
        ));
    }

    // ranges
    if c.database.pool_max == 0 {
        f.push(finding("database.pool_max", "must be at least 1", true));
    }
    if c.worker.max_sessions == 0 || c.worker.max_sessions > 64 {
        f.push(finding("worker.max_sessions", "must be in 1..=64", true));
    }
    if c.worker.contexts_per_browser == 0 || c.worker.contexts_per_browser > 32 {
        f.push(finding("worker.contexts_per_browser", "must be in 1..=32", true));
    }
    if c.worker.checkpoint_every_actions == 0 {
        f.push(finding(
            "worker.checkpoint_every_actions",
            "must be at least 1",
            true,
        ));
    }
    if c.scheduler.heartbeat_s == 0 || c.scheduler.heartbeat_s * 2 > c.scheduler.session_lease_ttl_s {
        f.push(finding(
            "scheduler.heartbeat_s",
            "must be at least 1 and at most half of session_lease_ttl_s",
            true,
        ));
    }
    if c.scheduler.reaper_interval_s == 0 {
        f.push(finding("scheduler.reaper_interval_s", "must be at least 1", true));
    }
    if c.scheduler.session_lease_ttl_s > 60 {
        f.push(finding(
            "scheduler.session_lease_ttl_s",
            "above 60 s the 2-minute stale-lease reconciliation SLO is at risk",
            false,
        ));
    }
    if c.fetch.per_origin_inflight == 0 || c.fetch.per_origin_inflight > 8 {
        f.push(finding("fetch.per_origin_inflight", "must be in 1..=8", true));
    }
    if c.fetch.min_spacing_ms < 50 {
        f.push(finding(
            "fetch.min_spacing_ms",
            "must be at least 50 ms (politeness floor)",
            true,
        ));
    }
    for (key, proxy) in [
        ("fetch.basic_proxy_url", c.fetch.basic_proxy_url.as_ref()),
        ("fetch.enhanced_proxy_url", c.fetch.enhanced_proxy_url.as_ref()),
    ] {
        if let Some(proxy) = proxy {
            if let Err(error) = proxy.parse() {
                f.push(finding(key, format!("{error:#}"), true));
            }
        }
    }
    for (key, message) in crate::proxyx_config::check(
        &c.fetch.proxyx,
        c.fetch.basic_proxy_url.is_some(),
        c.fetch.enhanced_proxy_url.is_some(),
    ) {
        f.push(finding(key, message, true));
    }
    if let Err(error) = crate::resolver_https_config::check(loaded) {
        f.push(finding("fetch.resolver_https", format!("{error:#}"), true));
    }
    for (i, p) in c.browser.launch_profile_allowed.iter().enumerate() {
        if !matches!(p.as_str(), "standard" | "stealth") {
            f.push(finding(
                &format!("browser.launch_profile_allowed[{i}]"),
                format!("unknown launch profile {p:?}; allowed: standard, stealth"),
                true,
            ));
        }
    }
    if c.browser.launch_profile_allowed.is_empty() {
        f.push(finding(
            "browser.launch_profile_allowed",
            "must list at least `standard`",
            true,
        ));
    }
    if !matches!(
        c.model.mode_default.as_str(),
        "off" | "shadow" | "advisory" | "arbitrating"
    ) {
        f.push(finding(
            "model.mode_default",
            "must be off, shadow, advisory or arbitrating",
            true,
        ));
    }
    if c.model.breaker.failure_threshold == 0 {
        f.push(finding(
            "model.breaker.failure_threshold",
            "must be at least 1",
            true,
        ));
    }
    if c.model.timeout_ms == 0 {
        f.push(finding("model.timeout_ms", "must be at least 1", true));
    }
    if c.retention.sweep_interval_s == 0 {
        f.push(finding("retention.sweep_interval_s", "must be at least 1", true));
    }
    if !(0.0..=1.0).contains(&c.telemetry.trace_sampling) {
        f.push(finding("telemetry.trace_sampling", "must be in 0.0..=1.0", true));
    }
    if !matches!(
        c.safety.default_profile.as_str(),
        "read_only" | "safe_interactive" | "test_environment" | "authorized_security_test"
    ) {
        f.push(finding("safety.default_profile", "unknown safety profile", true));
    }
    if c.safety.default_profile == "authorized_security_test" {
        f.push(finding(
            "safety.default_profile",
            "authorized_security_test can never be a default; it needs an authorization record per run",
            true,
        ));
    }
    if let Err(e) = c.ocr.validate() {
        f.push(finding("ocr", e.to_string(), true));
    }
    if c.shadow.sample_percent > 100 {
        f.push(finding("shadow.sample_percent", "must be in 0..=100", true));
    }
    if !c.api.admin_listen.ip().is_loopback() {
        f.push(finding(
            "api.admin_listen",
            "the management listener must bind a loopback address",
            true,
        ));
    }
    for (i, d) in c.api.webhook.retry_schedule.iter().enumerate() {
        if parse_duration_secs(d).is_none() {
            f.push(finding(
                &format!("api.webhook.retry_schedule[{i}]"),
                format!("{d:?} is not a duration (10s, 5m, 2h, 1d)"),
                true,
            ));
        }
    }
    if parse_duration_secs(&c.api.webhook.retry_window).is_none() {
        f.push(finding(
            "api.webhook.retry_window",
            "not a duration (10s, 5m, 2h, 1d)",
            true,
        ));
    }
    if !c.browser.pin_file.is_file() {
        f.push(finding(
            "browser.pin_file",
            format!(
                "{} not found (the worker refuses unpinned builds unless allow_unpinned)",
                c.browser.pin_file.display()
            ),
            prod,
        ));
    }

    // production rules
    if prod && c.browser.allow_unpinned {
        f.push(finding(
            "browser.allow_unpinned",
            "true is development only",
            true,
        ));
    }
    if prod && loaded.passthrough.contains_key("CRAWLX_ALLOW_UNPINNED") {
        f.push(finding(
            "browser.allow_unpinned",
            "CRAWLX_ALLOW_UNPINNED is set; development only",
            true,
        ));
    }
    if prod && loaded.passthrough.contains_key("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI") {
        f.push(finding(
            "browser.unsafe_no_sandbox_for_ci",
            "CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI is set; `--no-sandbox` is never passed in staging/prod",
            true,
        ));
    }
    if prod && c.telemetry.otlp_endpoint.is_none() && !loaded.passthrough.contains_key("CRAWLX_OTLP_ENDPOINT")
    {
        f.push(finding(
            "telemetry.otlp_endpoint",
            "no OTLP endpoint; metrics and traces will not be exported",
            false,
        ));
    }
    if prod && c.scheduler.admission != crawlx_storage::AdmissionMode::Open {
        f.push(finding(
            "scheduler.admission",
            format!(
                "starts {}; new leases are not granted until `crawlx admin resume --admission`",
                c.scheduler.admission
            ),
            false,
        ));
    }
    validate_egress(loaded, prod, &mut f);
    validate_operator_keys(loaded, &mut f, &mut secrets);
    validate_capability_inputs(loaded, &mut f);
    (f, secrets)
}

fn validate_capability_inputs(loaded: &Loaded, findings: &mut Vec<Finding>) {
    let lookup = |name: &str| loaded.passthrough.get(name).cloned();
    if let Err(error) = crawlx_core::secret::request_identity_key_from_lookup(&lookup) {
        findings.push(finding("capabilities.request_identity", error.to_string(), true));
    }
    match crawlx_worker::config::RetainedProfilePolicy::from_env(&lookup) {
        Err(_) => findings.push(finding(
            "capabilities.retained_profiles",
            "invalid retained profile operator policy",
            true,
        )),
        Ok(Some(_)) => {
            if loaded.passthrough.contains_key("CRAWLX_ZDR_REDIS_URL") {
                findings.push(finding(
                    "capabilities.retained_profiles",
                    "retained profiles cannot be enabled with ZDR",
                    true,
                ));
            }
            if loaded.config.database.url_file.is_some()
                || loaded.passthrough.contains_key("CRAWLX_DATABASE_URL")
            {
                findings.push(finding(
                    "capabilities.retained_profiles",
                    "retained profiles are unavailable while encrypted artifact custody is enabled; PostgreSQL workers always enable it",
                    true,
                ));
            }
            if loaded.config.database.url_file.is_none()
                && !loaded.passthrough.contains_key("CRAWLX_DATABASE_URL")
            {
                findings.push(finding(
                    "capabilities.retained_profiles",
                    "retained profiles require PostgreSQL configuration",
                    true,
                ));
            }
        }
        _ => {}
    }
}

async fn validate_capability_secrets(
    loaded: &Loaded,
    findings: &mut Vec<Finding>,
    resolver: &dyn crawlx_core::secret::SecretResolver,
) {
    let lookup = |name: &str| loaded.passthrough.get(name).cloned();
    if let Ok(Some(policy)) = crawlx_worker::config::RetainedProfilePolicy::from_env(&lookup) {
        let valid = match resolver.resolve(&policy.key_ref).await {
            Ok(value) => crawlx_core::hash::Digest::from_hex(value.expose()).is_ok(),
            Err(_) => false,
        };
        if !valid {
            findings.push(finding("capabilities.retained_profiles", "profile key reference must resolve to exactly 64 hexadecimal characters through an available resolver", true));
        }
    }
    if let Some(path) = loaded.passthrough.get("CRAWLX_PROTOCOL_REGISTRY") {
        if crawlx_worker::protocol::ProtocolRegistry::from_file(Path::new(path), resolver)
            .await
            .is_err()
        {
            findings.push(finding(
                "capabilities.protocol_registry",
                "protocol registry or its credential references are unavailable or invalid",
                true,
            ));
        }
    }
    if let Some(path) = loaded.passthrough.get("CRAWLX_DELIVERY_REGISTRY") {
        if crawlx_worker::delivery::DeliveryRegistry::from_file(Path::new(path), resolver)
            .await
            .is_err()
        {
            findings.push(finding(
                "capabilities.delivery_registry",
                "delivery registry or its credential references are unavailable or invalid",
                true,
            ));
        }
    }
}

async fn validate_checkpoint_keys(loaded: &Loaded, findings: &mut Vec<Finding>) {
    let lookup = |name: &str| loaded.passthrough.get(name).cloned();
    let mut worker = crawlx_worker::WorkerConfig::default();
    if let Err(error) = worker.load_checkpoint_keys_from_lookup(&lookup).await {
        findings.push(finding(
            "capabilities.checkpoint_encryption",
            error.to_string(),
            true,
        ));
    }
}

/// Encrypted artifact custody: a malformed or contradictory setting is an error. A
/// PostgreSQL deployment without the key provider or the registry endpoint is a warning here
/// (the API runs without the endpoint); workers refuse to start without both.
async fn validate_artifact_custody(loaded: &Loaded, findings: &mut Vec<Finding>) {
    let lookup = |name: &str| loaded.passthrough.get(name).cloned();
    let mut worker = crawlx_worker::WorkerConfig::default();
    if let Err(error) = worker.load_artifact_custody_from_lookup(&lookup).await {
        findings.push(finding("capabilities.artifact_custody", error.to_string(), true));
        return;
    }
    let postgres =
        loaded.config.database.url_file.is_some() || loaded.passthrough.contains_key("CRAWLX_DATABASE_URL");
    if postgres && worker.artifact_keys.is_none() {
        findings.push(finding(
            "capabilities.artifact_custody",
            "set exactly one of CRAWLX_ARTIFACT_KMS_KEY_ID or CRAWLX_ARTIFACT_KEY_FILE: sealed artifacts cannot be read or written without a key provider",
            false,
        ));
    }
    if postgres && worker.secret_redis_url.is_none() {
        findings.push(finding(
            "capabilities.artifact_custody",
            "workers require CRAWLX_SECRET_REDIS_URL (or _FILE), the persistence-free secret registry; they refuse to start without it",
            false,
        ));
    }
}

async fn validate_article_language_bundle(loaded: &Loaded, findings: &mut Vec<Finding>) {
    let lookup = |name: &str| loaded.passthrough.get(name).cloned();
    if !lookup("CRAWLX_ARTICLE_LANGUAGE_BUNDLE").is_some_and(|path| !path.is_empty()) {
        return;
    }
    let mut worker = crawlx_worker::WorkerConfig::default();
    if worker.load_article_language_from_lookup(&lookup).await.is_err() {
        findings.push(finding(
            "capabilities.article_language",
            "article language bundle or its pinned local runtime is unavailable or invalid",
            true,
        ));
    }
}

/// Findings about the deployment lists: every entry parses, every named file exists and parses.
fn validate_egress(loaded: &Loaded, prod: bool, f: &mut Vec<Finding>) {
    let e = &loaded.config.egress;
    let allow_file = effective_list_file(
        loaded,
        DEPLOYMENT_ALLOWLIST_FILE_ENV,
        e.deployment_allowlist_file.as_deref(),
    );
    let block_file = effective_list_file(
        loaded,
        OPERATOR_BLOCKLIST_FILE_ENV,
        e.operator_blocklist_file.as_deref(),
    );
    for (i, entry) in e.deployment_allowlist.iter().flatten().enumerate() {
        if !EgressLists::parse_allowlist(entry).is_ok_and(|nets| nets.len() == 1) {
            f.push(finding(
                &format!("egress.deployment_allowlist[{i}]"),
                format!("{entry:?} is not an IP address or CIDR"),
                true,
            ));
        }
    }
    for (i, entry) in e.operator_blocklist.iter().enumerate() {
        if EgressLists::new(None, [entry]).is_err() {
            f.push(finding(
                &format!("egress.operator_blocklist[{i}]"),
                format!("{entry:?} is not a host name, IP address or CIDR"),
                true,
            ));
        }
    }
    if allow_file.is_some() && e.deployment_allowlist.is_some() {
        f.push(finding(
            "egress.deployment_allowlist",
            "ignored: the allowlist file replaces the static list",
            false,
        ));
    }
    if block_file.is_some() && !e.operator_blocklist.is_empty() {
        f.push(finding(
            "egress.operator_blocklist",
            "ignored: the blocklist file replaces the static list",
            false,
        ));
    }
    // each file on its own, so one bad file does not hide the other
    for (key, source) in [
        (
            "egress.deployment_allowlist_file",
            EgressListSource {
                allowlist_file: allow_file.clone(),
                ..EgressListSource::default()
            },
        ),
        (
            "egress.operator_blocklist_file",
            EgressListSource {
                blocklist_file: block_file,
                ..EgressListSource::default()
            },
        ),
    ] {
        if let Err(err) = source.load_blocking() {
            f.push(finding(key, err.to_string(), true));
        }
    }
    if prod && e.deployment_allowlist.is_none() && allow_file.is_none() {
        f.push(finding(
            "egress.deployment_allowlist",
            "unset: an authorization record may name any private network; bound them with \
             egress.deployment_allowlist, egress.deployment_allowlist_file or \
             CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE",
            false,
        ));
    }
}

/// Findings and secret status of the operator keys file, when the environment names one.
fn validate_operator_keys(loaded: &Loaded, f: &mut Vec<Finding>, secrets: &mut Vec<SecretStatus>) {
    let Some(path) = loaded
        .passthrough
        .get(OPERATOR_KEYS_FILE_ENV)
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from)
    else {
        return;
    };
    let key = "authz.operator_keys_file";
    let bytes = std::fs::metadata(&path).ok().map(|m| m.len());
    let present = bytes.is_some_and(|n| n > 0);
    if !present {
        f.push(finding(
            key,
            format!("{} is missing or empty", path.display()),
            true,
        ));
    } else if let Err(e) = operator_keys_from(&path) {
        f.push(finding(key, format!("{e:#}"), true));
    }
    secrets.push(SecretStatus {
        key: key.to_owned(),
        path,
        present,
        bytes,
    });
}

fn flat_secret(key: &str) -> &'static str {
    match key {
        "database.url_file" => "DATABASE_URL",
        "api.webhook.signing_key_file" => "WEBHOOK_SECRET",
        _ => "S3_CREDENTIALS",
    }
}

/// `10s`, `5m`, `2h`, `1d` → seconds.
fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: u64 = num.parse().ok()?;
    let mult = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    n.checked_mul(mult)
}

/// Effective values as JSON with the derived, env-only browser knobs added and nothing secret.
fn effective_json(loaded: &Loaded) -> anyhow::Result<Value> {
    let mut v = serde_json::to_value(&loaded.config)?;
    if let Some(browser) = v.get_mut("browser").and_then(Value::as_object_mut) {
        browser.insert(
            "unsafe_no_sandbox_for_ci".to_owned(),
            json!(loaded.passthrough.contains_key("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI")),
        );
        browser.insert(
            "allow_unpinned".to_owned(),
            json!(
                loaded.config.browser.allow_unpinned
                    || loaded.passthrough.contains_key("CRAWLX_ALLOW_UNPINNED")
            ),
        );
        browser.insert(
            "chromium_path".to_owned(),
            json!(loaded.passthrough.get("CRAWLX_CHROMIUM_PATH")),
        );
    }
    if let Some(egress) = v.get_mut("egress").and_then(Value::as_object_mut) {
        egress.insert("lists".to_owned(), egress_lists_report(loaded));
    }
    v["capabilities"] = capability_report(loaded);
    Ok(v)
}

fn capability_report(loaded: &Loaded) -> Value {
    let has = |name: &str| loaded.passthrough.contains_key(name);
    json!({
        "request_identity": {
            "configured": has("CRAWLX_REQUEST_IDENTITY_KEY") || has("CRAWLX_REQUEST_IDENTITY_KEY_FILE"),
            "source": if has("CRAWLX_REQUEST_IDENTITY_KEY_FILE") { "file" } else if has("CRAWLX_REQUEST_IDENTITY_KEY") { "inline" } else { "disabled" },
            "value": "<redacted>"
        },
        "checkpoint_encryption": {
            "configured": has("CRAWLX_CHECKPOINT_KMS_KEY_ID"),
            "key_reference": if has("CRAWLX_CHECKPOINT_KMS_KEY_ID") { "<redacted>" } else { "unset" }
        },
        "artifact_custody": {
            "key_provider": if has("CRAWLX_ARTIFACT_KMS_KEY_ID") { "kms" } else if has("CRAWLX_ARTIFACT_KEY_FILE") { "file" } else { "unset" },
            "secret_registry": if has("CRAWLX_SECRET_REDIS_URL_FILE") { "file" } else if has("CRAWLX_SECRET_REDIS_URL") { "inline" } else { "unset" },
            "key_reference": "<redacted>"
        },
        "retained_profiles": {
            "enabled": matches!(loaded.passthrough.get("CRAWLX_RETAINED_PROFILES_ENABLED").map(String::as_str), Some("true" | "1")),
            "key_reference": if has("CRAWLX_PROFILE_KEY_REF") { "<redacted>" } else { "unset" }
        },
        "protocol_registry": { "configured": has("CRAWLX_PROTOCOL_REGISTRY") },
        "delivery_registry": { "configured": has("CRAWLX_DELIVERY_REGISTRY") },
        "article_language": {
            "configured": loaded.passthrough.get("CRAWLX_ARTICLE_LANGUAGE_BUNDLE").is_some_and(|path| !path.is_empty())
        }
    })
}

/// Passthrough variables with secret-bearing values redacted.
///
/// The model-provider, transcription and search variables (`INTEL_ENV_PREFIXES`) are always
/// redacted here: their endpoints may carry credentials in the user info or query, and the
/// `intel` section of the report already shows their effective values with those parts removed.
fn redacted_passthrough(p: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    p.iter()
        .map(|(k, v)| {
            let secret = !k.ends_with("_FILE")
                && (k == "CRAWLX_ZDR_REDIS_URL"
                    || k.ends_with("_URL") && k.contains("DATABASE")
                    || k.contains("SECRET")
                    || k.contains("KEY")
                    || INTEL_ENV_PREFIXES.iter().any(|prefix| k.starts_with(prefix)));
            (
                k.clone(),
                if secret {
                    "<redacted>".to_owned()
                } else {
                    v.clone()
                },
            )
        })
        .collect()
}

pub(crate) async fn run(args: ConfigArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    match args.command {
        ConfigCommand::Check(args) => check(&args, out).await,
        ConfigCommand::Features => {
            out.write_all(FEATURE_MANIFEST.as_bytes())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

async fn check(args: &ConfigCheckArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let loaded = match load(args.config.as_deref()) {
        Ok(l) => l,
        Err(e) => {
            if args.format == CheckFormat::Json {
                writeln!(out, "{}", json!({ "ok": false, "error": format!("{e:#}") }))?;
            } else {
                writeln!(out, "config check: FAIL\n  {e:#}")?;
            }
            return Ok(ExitCode::from(1));
        }
    };
    let (mut findings, secrets) = validate(&loaded);
    if [
        "CRAWLX_PROFILE_KEY_REF",
        "CRAWLX_PROTOCOL_REGISTRY",
        "CRAWLX_DELIVERY_REGISTRY",
    ]
    .iter()
    .any(|name| loaded.passthrough.contains_key(*name))
    {
        let resolver =
            crawlx_worker::ChainResolver::from_env(std::sync::Arc::new(crawlx_core::SystemClock)).await;
        validate_capability_secrets(&loaded, &mut findings, &resolver).await;
    }
    validate_artifact_custody(&loaded, &mut findings).await;
    validate_checkpoint_keys(&loaded, &mut findings).await;
    validate_article_language_bundle(&loaded, &mut findings).await;
    // the LLM provider variables are read from the process environment by `serve` and
    // `worker` themselves, so they are reported from it too (secrets redacted)
    let intel = crate::config_intel::report(&|k| std::env::var(k).ok());
    findings.extend(intel.findings);
    let errors = findings.iter().filter(|f| f.error).count();
    let warnings = findings.len() - errors;
    let ok = errors == 0 && !(args.strict && warnings > 0);
    match args.format {
        CheckFormat::Json => {
            let doc = json!({
                "ok": ok,
                "file": loaded.file,
                "effective": effective_json(&loaded)?,
                "sources": loaded.sources,
                "passthrough": redacted_passthrough(&loaded.passthrough),
                "secrets": secrets,
                "findings": findings,
                "intel": intel.effective,
                "nativeExtensions": crawlx_core::extensions::registry_publication(),
            });
            writeln!(out, "{}", serde_json::to_string_pretty(&doc)?)?;
        }
        CheckFormat::Toml => {
            writeln!(
                out,
                "# crawlx config check: {} ({} error(s), {} warning(s)); file: {}",
                if ok { "OK" } else { "FAIL" },
                errors,
                warnings,
                loaded
                    .file
                    .as_ref()
                    .map_or_else(|| "<none>".to_owned(), |p| p.display().to_string())
            )?;
            writeln!(out, "# environment = {}", loaded.config.environment.as_str())?;
            let mut effective = loaded.config.clone();
            // never print anything the env may carry as a secret; paths stay
            effective.environment = loaded.config.environment;
            writeln!(out, "{}", toml::to_string_pretty(&effective)?)?;
            writeln!(out, "# capabilities = {}", capability_report(&loaded))?;
            for (name, list) in egress_lists_report(&loaded).as_object().into_iter().flatten() {
                writeln!(out, "# egress.{name}: {list}")?;
            }
            writeln!(out, "{}", crate::config_intel::to_toml(&intel.effective)?)?;
            writeln!(
                out,
                "# native_extensions = {}",
                crawlx_core::extensions::registry_publication()
            )?;
            if !loaded.sources.is_empty() {
                writeln!(out, "# overrides:")?;
                for (k, s) in &loaded.sources {
                    writeln!(
                        out,
                        "#   {k} <- {}",
                        match s {
                            Source::Default => "default",
                            Source::File => "file",
                            Source::Env => "env",
                        }
                    )?;
                }
            }
            for (k, v) in redacted_passthrough(&loaded.passthrough) {
                writeln!(out, "# env {k}={v}")?;
            }
            for s in &secrets {
                writeln!(
                    out,
                    "# secret {} = {} ({})",
                    s.key,
                    s.path.display(),
                    if s.present { "present" } else { "MISSING" }
                )?;
            }
            for f in &findings {
                writeln!(
                    out,
                    "# {}: {}: {}",
                    if f.error { "error" } else { "warning" },
                    f.key,
                    f.message
                )?;
            }
        }
    }
    Ok(if ok { ExitCode::SUCCESS } else { ExitCode::from(1) })
}

/// The database DSN for a command: the flag/`CRAWLX_DATABASE_URL`, else
/// `CRAWLX_DATABASE_URL_FILE`, else `database.url_file` from the loaded surface.
///
/// # Errors
/// Fails when the named file cannot be read.
pub fn database_url(flag: Option<&str>) -> anyhow::Result<Option<String>> {
    if let Some(url) = flag {
        return Ok(Some(url.to_owned()));
    }
    secret_from_file_env("CRAWLX_DATABASE_URL_FILE")
        .transpose()?
        .map_or_else(
            || {
                let loaded = load(None)?;
                loaded
                    .config
                    .database
                    .url_file
                    .as_deref()
                    .map(read_secret)
                    .transpose()
            },
            |u| Ok(Some(u)),
        )
}

/// The webhook signing secret for `serve`: the flag/`CRAWLX_WEBHOOK_SECRET`, else
/// `CRAWLX_WEBHOOK_SECRET_FILE`, else `api.webhook.signing_key_file`.
///
/// # Errors
/// Fails when the named file cannot be read.
pub fn webhook_secret(flag: Option<&str>) -> anyhow::Result<Option<String>> {
    if let Some(s) = flag {
        return Ok(Some(s.to_owned()));
    }
    secret_from_file_env("CRAWLX_WEBHOOK_SECRET_FILE")
        .transpose()?
        .map_or_else(
            || {
                let loaded = load(None)?;
                loaded
                    .config
                    .api
                    .webhook
                    .signing_key_file
                    .as_deref()
                    .map(read_secret)
                    .transpose()
            },
            |u| Ok(Some(u)),
        )
}

/// The file that feeds a list: the flat environment variable `env` when set (and not empty), else
/// the configured `file`.
fn effective_list_file(loaded: &Loaded, env: &str, file: Option<&Path>) -> Option<PathBuf> {
    loaded
        .passthrough
        .get(env)
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| file.map(Path::to_path_buf))
}

/// Where the deployment lists come from, as configured.
///
/// # Errors
/// Fails when an entry of the static allowlist is not an IP address or CIDR. Files and the
/// static blocklist are checked when the lists are built.
pub fn egress_source(loaded: &Loaded) -> anyhow::Result<EgressListSource> {
    let e = &loaded.config.egress;
    let allowlist_static = e
        .deployment_allowlist
        .as_deref()
        .map(|entries| {
            EgressLists::parse_allowlist(&entries.join("\n"))
                .map_err(|err| anyhow!("egress.deployment_allowlist: {err}"))
        })
        .transpose()?;
    Ok(EgressListSource {
        allowlist_static,
        blocklist_static: e.operator_blocklist.clone(),
        allowlist_file: effective_list_file(
            loaded,
            DEPLOYMENT_ALLOWLIST_FILE_ENV,
            e.deployment_allowlist_file.as_deref(),
        ),
        blocklist_file: effective_list_file(
            loaded,
            OPERATOR_BLOCKLIST_FILE_ENV,
            e.operator_blocklist_file.as_deref(),
        ),
    })
}

/// [`egress_source`] for a running command: `crawlx.toml` (`CRAWLX_CONFIG`, else `./crawlx.toml`
/// when present) plus the variables of [`EGRESS_ENV`], read through `getenv`.
///
/// # Errors
/// Fails on an unreadable or malformed configuration file or a bad static entry.
pub fn egress_source_from_env(getenv: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<EgressListSource> {
    let vars: Vec<(String, String)> = EGRESS_ENV
        .iter()
        .filter_map(|name| getenv(name).map(|v| ((*name).to_owned(), v)))
        .collect();
    let file = getenv(CONFIG_ENV)
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from);
    egress_source(&load_from(file.as_deref(), &vars)?)
}

/// Read memory-only upload spool limits for a running command.
///
/// # Errors
/// Fails on invalid configuration or nonpositive spool capacity, attempts or request timeout.
pub fn artifact_spool_from_env(
    getenv: &dyn Fn(&str) -> Option<String>,
) -> anyhow::Result<crawlx_storage::UploadSpoolConfig> {
    let names = [
        CONFIG_ENV,
        "CRAWLX_OBJECT_STORE__SPOOL_MAX_BYTES",
        "CRAWLX_OBJECT_STORE__SPOOL_MAX_ENTRIES",
        "CRAWLX_OBJECT_STORE__SPOOL_MAX_ATTEMPTS",
        "CRAWLX_OBJECT_STORE__SPOOL_RETRY_DELAY_MS",
        "CRAWLX_OBJECT_STORE__SPOOL_REQUEST_TIMEOUT_MS",
    ];
    let vars: Vec<_> = names
        .iter()
        .filter_map(|name| getenv(name).map(|value| ((*name).to_owned(), value)))
        .collect();
    let file = getenv(CONFIG_ENV)
        .filter(|p| !p.trim().is_empty())
        .map(PathBuf::from);
    load_from(file.as_deref(), &vars)?
        .config
        .object_store
        .spool_config()
}

/// What `config check` reports about the deployment lists: where each comes from and how many
/// entries it holds (the entries themselves are not printed).
fn egress_lists_report(loaded: &Loaded) -> Value {
    let e = &loaded.config.egress;
    let source = egress_source(loaded).ok();
    let lists = source.as_ref().and_then(|s| s.load_blocking().ok());
    let allow_file = source.as_ref().and_then(|s| s.allowlist_file.clone());
    let block_file = source.as_ref().and_then(|s| s.blocklist_file.clone());
    json!({
        "deployment_allowlist": {
            "source": if allow_file.is_some() { "file" } else if e.deployment_allowlist.is_some() { "config" } else { "unset" },
            "file": allow_file,
            "networks": lists.as_ref().and_then(|l| l.allowlist().map(<[_]>::len)),
        },
        "operator_blocklist": {
            "source": if block_file.is_some() { "file" } else if !e.operator_blocklist.is_empty() { "config" } else { "unset" },
            "file": block_file,
            "entries": lists.as_ref().map(|l| l.blocklist_entries().len()),
        },
    })
}

fn operator_keys_from(path: &Path) -> anyhow::Result<OperatorKeys> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading operator keys file {}", path.display()))?;
    let keys = OperatorKeys::parse(&text).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    if keys.is_empty() {
        bail!("operator keys file {} defines no key", path.display());
    }
    Ok(keys)
}

/// The operator keys of this deployment: the file named by `CRAWLX_AUTHZ_OPERATOR_KEYS_FILE`
/// (`key_id hex-key` per line), or none. Key material never appears in an error.
///
/// # Errors
/// Fails when the named file cannot be read, is malformed or holds no key.
pub fn operator_keys(getenv: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<OperatorKeys> {
    match getenv(OPERATOR_KEYS_FILE_ENV).filter(|p| !p.trim().is_empty()) {
        Some(path) => operator_keys_from(Path::new(&path)),
        None => Ok(OperatorKeys::new()),
    }
}

fn secret_from_file_env(var: &str) -> Option<anyhow::Result<String>> {
    std::env::var_os(var).map(|p| read_secret(Path::new(&p)))
}

fn read_secret(path: &Path) -> anyhow::Result<String> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading secret file {}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("secret file {} is empty", path.display());
    }
    Ok(trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn write(dir: &tempfile::TempDir, name: &str, text: &str) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    #[test]
    fn upload_spool_config_reaches_runtime_and_rejects_zero_limits() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(
            &dir,
            "spool.toml",
            "[object_store]\nspool_max_bytes=4096\nspool_max_entries=8\nspool_max_attempts=2\nspool_retry_delay_ms=7\nspool_request_timeout_ms=99\n",
        );
        let lookup = |name: &str| match name {
            CONFIG_ENV => Some(file.display().to_string()),
            "CRAWLX_OBJECT_STORE__SPOOL_MAX_ENTRIES" => Some("3".to_owned()),
            _ => None,
        };
        let config = artifact_spool_from_env(&lookup).unwrap();
        assert_eq!(config.max_bytes, 4096);
        assert_eq!(config.max_entries, 3);
        assert_eq!(config.max_attempts, 2);
        assert_eq!(config.retry_delay, std::time::Duration::from_millis(7));
        assert_eq!(config.request_timeout, std::time::Duration::from_millis(99));
        for key in [
            "spool_max_bytes",
            "spool_max_entries",
            "spool_max_attempts",
            "spool_request_timeout_ms",
        ] {
            let file = write(&dir, "invalid-spool.toml", &format!("[object_store]\n{key}=0\n"));
            let loaded = load_from(Some(&file), &[]).unwrap();
            assert!(loaded.config.object_store.spool_config().is_err(), "{key}");
            assert!(validate(&loaded)
                .0
                .iter()
                .any(|finding| finding.key == "object_store"));
        }
        let file = write(
            &dir,
            "disk-spool.toml",
            "[object_store]\nspool_dir='/tmp/plaintext'\n",
        );
        assert!(load_from(Some(&file), &[]).is_err());
    }

    #[test]
    fn defaults_match_the_plan_table() {
        let l = load_from(Some(Path::new("/nonexistent/none.toml")), &[]).unwrap_err();
        assert!(l.to_string().contains("reading"));
        let c = CrawlxConfig::default();
        assert_eq!(c.database.pool_max, 32);
        assert_eq!(c.database.statement_timeout_ms, 5000);
        assert_eq!(c.worker.max_sessions, 4);
        assert_eq!(c.worker.contexts_per_browser, 4);
        assert_eq!(c.worker.checkpoint_every_actions, 50);
        assert_eq!(
            (
                c.scheduler.session_lease_ttl_s,
                c.scheduler.url_lease_ttl_s,
                c.scheduler.heartbeat_s,
                c.scheduler.reaper_interval_s
            ),
            (30, 60, 10, 15)
        );
        assert_eq!(c.fetch.per_origin_inflight, 1);
        assert_eq!(c.fetch.min_spacing_ms, 250);
        assert_eq!(c.model.breaker.failure_threshold, 5);
        assert_eq!(c.model.breaker.cooldown_s, 30);
        assert_eq!(c.model.timeout_ms, 800);
        assert_eq!(c.retention.sweep_interval_s, 300);
        assert_eq!(c.retention.grace_s, 900);
        assert_eq!(c.api.webhook.retry_schedule.len(), 8);
        assert_eq!(c.safety.default_profile, "read_only");
        assert_eq!(c.shadow.sample_percent, 5);
    }

    #[test]
    fn env_overrides_file_overrides_defaults_and_unknown_keys_fail() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(
            &dir,
            "crawlx.toml",
            "[worker]\nmax_sessions = 8\n[fetch]\nmin_spacing_ms = 500\n",
        );
        let l = load_from(
            Some(&file),
            &vars(&[
                ("CRAWLX_WORKER__MAX_SESSIONS", "2"),
                ("CRAWLX_EGRESS__MODE", "netns"),
            ]),
        )
        .unwrap();
        assert_eq!(l.config.worker.max_sessions, 2, "env wins over file");
        assert_eq!(l.config.fetch.min_spacing_ms, 500, "file wins over default");
        assert_eq!(l.config.egress.mode, EgressMode::Netns);
        assert_eq!(l.sources["worker.max_sessions"], Source::Env);
        assert_eq!(l.sources["fetch.min_spacing_ms"], Source::File);

        let bad = write(&dir, "bad.toml", "[worker]\nmax_session = 8\n");
        let e = load_from(Some(&bad), &[]).unwrap_err().to_string();
        assert!(e.contains("unknown field `max_session`"), "{e}");

        let e = load_from(Some(&file), &vars(&[("CRAWLX_WORKER__NOPE", "1")]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("unknown field `nope`"), "{e}");

        let e = load_from(Some(&file), &vars(&[("CRAWLX_MYSTERY", "1")]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a configuration key"), "{e}");

        let e = load_from(Some(&file), &vars(&[("CRAWLX_WORKER__MAX_SESSIONS", "many")]))
            .unwrap_err()
            .to_string();
        assert!(e.contains("max_sessions"), "{e}");
    }

    #[test]
    fn validation_enforces_production_rules_and_probes_secret_files() {
        let dir = tempfile::tempdir().unwrap();
        let db = write(&dir, "db", "postgres://x");
        let key = write(&dir, "key", "k");
        let pin = write(&dir, "pin.toml", "[chromium]\nversion = \"1\"\n");
        let file = write(
            &dir,
            "crawlx.toml",
            &format!(
                "[database]\nurl_file = {db:?}\n[api.webhook]\nsigning_key_file = {key:?}\n[browser]\npin_file = {pin:?}\nallow_unpinned = true\n",
                db = db.display().to_string(),
                key = key.display().to_string(),
                pin = pin.display().to_string()
            ),
        );
        let l = load_from(Some(&file), &vars(&[("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI", "1")])).unwrap();
        assert_eq!(l.config.environment, Environment::Prod);
        let (f, secrets) = validate(&l);
        let keys: Vec<&str> = f.iter().filter(|f| f.error).map(|f| f.key.as_str()).collect();
        assert!(keys.contains(&"browser.allow_unpinned"), "{keys:?}");
        assert!(keys.contains(&"browser.unsafe_no_sandbox_for_ci"), "{keys:?}");
        assert!(secrets.iter().all(|s| s.present), "{secrets:?}");

        // the same knobs are fine in dev
        let l = load_from(
            Some(&file),
            &vars(&[
                ("CRAWLX_ENVIRONMENT", "dev"),
                ("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI", "1"),
            ]),
        )
        .unwrap();
        assert_eq!(l.config.environment, Environment::Dev);
        let (f, _) = validate(&l);
        assert!(f.iter().all(|f| !f.error), "{f:?}");

        // a missing secret file is an error in prod
        let gone = write(
            &dir,
            "crawlx2.toml",
            "[database]\nurl_file = \"/nonexistent/db\"\n",
        );
        let l = load_from(Some(&gone), &[]).unwrap();
        let (f, secrets) = validate(&l);
        assert!(f.iter().any(|f| f.error && f.key == "database.url_file"), "{f:?}");
        assert!(!secrets[0].present);
    }

    #[test]
    fn report_never_contains_secret_values() {
        let dir = tempfile::tempdir().unwrap();
        let db = write(&dir, "db", "postgres://user:hunter2@db/crawlx");
        let file = write(
            &dir,
            "crawlx.toml",
            &format!(
                "environment = \"dev\"\n[database]\nurl_file = {:?}\n",
                db.display().to_string()
            ),
        );
        let loaded = load_from(
            Some(&file),
            &vars(&[
                ("CRAWLX_DATABASE_URL", "postgres://user:hunter2@db/crawlx"),
                ("CRAWLX_WEBHOOK_SECRET", "s3cr3t"),
                ("CRAWLX_TLS_IMPERSONATE", "true"),
            ]),
        )
        .unwrap();
        let json = json!({
            "effective": effective_json(&loaded).unwrap(),
            "passthrough": redacted_passthrough(&loaded.passthrough),
        })
        .to_string();
        assert!(!json.contains("hunter2") && !json.contains("s3cr3t"), "{json}");
        assert!(json.contains("<redacted>"));
        assert_eq!(
            redacted_passthrough(&loaded.passthrough)["CRAWLX_TLS_IMPERSONATE"],
            "true"
        );
        assert_eq!(
            json!(effective_json(&loaded).unwrap())["browser"]["unsafe_no_sandbox_for_ci"],
            false
        );
    }

    #[test]
    fn range_checks_catch_bad_values() {
        let mut l = Loaded {
            config: CrawlxConfig::default(),
            file: None,
            sources: BTreeMap::new(),
            passthrough: BTreeMap::new(),
        };
        l.config.environment = Environment::Dev;
        l.config.scheduler.heartbeat_s = 20;
        l.config.fetch.min_spacing_ms = 10;
        l.config.shadow.sample_percent = 101;
        l.config.api.admin_listen = "0.0.0.0:9090".parse().unwrap();
        l.config.api.webhook.retry_schedule = vec!["soon".to_owned()];
        let (f, _) = validate(&l);
        let keys: Vec<&str> = f.iter().filter(|f| f.error).map(|f| f.key.as_str()).collect();
        for k in [
            "scheduler.heartbeat_s",
            "fetch.min_spacing_ms",
            "shadow.sample_percent",
            "api.admin_listen",
            "api.webhook.retry_schedule[0]",
        ] {
            assert!(keys.contains(&k), "{k} missing in {keys:?}");
        }
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("1d"), Some(86_400));
        assert_eq!(parse_duration_secs("x"), None);
    }

    fn finding_keys(l: &Loaded, error: bool) -> Vec<String> {
        validate(l)
            .0
            .into_iter()
            .filter(|f| f.error == error)
            .map(|f| f.key)
            .collect()
    }

    #[test]
    fn egress_lists_read_the_file_the_environment_and_a_file_replaces_the_static_list() {
        let dir = tempfile::tempdir().unwrap();
        let block = write(&dir, "block.txt", "# takedowns\nfile.test\n203.0.113.0/24\n");
        let file = write(
            &dir,
            "crawlx.toml",
            "environment = \"dev\"\n[egress]\ndeployment_allowlist = [\"10.0.0.0/8\", \"192.168.1.1\"]\n\
             operator_blocklist = [\"static.test\"]\n",
        );
        let l = load_from(
            Some(&file),
            &vars(&[(OPERATOR_BLOCKLIST_FILE_ENV, block.to_str().unwrap())]),
        )
        .unwrap();
        assert_eq!(
            l.passthrough[OPERATOR_BLOCKLIST_FILE_ENV],
            block.to_str().unwrap()
        );
        assert_eq!(
            l.config.egress.deployment_allowlist.as_deref().unwrap(),
            ["10.0.0.0/8", "192.168.1.1"]
        );
        let source = egress_source(&l).unwrap();
        assert_eq!(source.allowlist_static.as_ref().unwrap().len(), 2);
        assert_eq!(source.blocklist_file.as_deref(), Some(block.as_path()));
        assert_eq!(source.allowlist_file, None);
        let lists = source.load_blocking().unwrap();
        assert!(lists.blocked_host("a.file.test").is_some());
        assert!(
            lists.blocked_host("static.test").is_none(),
            "the file replaced the static blocklist"
        );
        assert_eq!(
            lists.allowlist().unwrap().len(),
            2,
            "no allowlist file: the static list stays"
        );

        // the file replaces the static list: advice, not an error
        let (f, _) = validate(&l);
        assert!(
            f.iter()
                .any(|f| !f.error && f.key == "egress.operator_blocklist" && f.message.contains("replaces")),
            "{f:?}"
        );
        assert!(
            finding_keys(&l, true).iter().all(|k| !k.starts_with("egress.")),
            "{f:?}"
        );

        // the report says where each list comes from and how many entries, not which
        let report = effective_json(&l).unwrap();
        let lists = &report["egress"]["lists"];
        assert_eq!(lists["deployment_allowlist"]["source"], "config");
        assert_eq!(lists["deployment_allowlist"]["networks"], 2);
        assert_eq!(lists["operator_blocklist"]["source"], "file");
        assert_eq!(lists["operator_blocklist"]["entries"], 2);
        assert_eq!(lists["operator_blocklist"]["file"], block.to_str().unwrap());
        assert!(
            !report.to_string().contains("file.test"),
            "entries are not printed"
        );

        // the flat variable wins over the configured file key; an empty value is unset
        let other = write(&dir, "other.txt", "other.test\n");
        let file = write(
            &dir,
            "crawlx2.toml",
            &format!(
                "[egress]\noperator_blocklist_file = {:?}\n",
                block.display().to_string()
            ),
        );
        let l = load_from(
            Some(&file),
            &vars(&[(OPERATOR_BLOCKLIST_FILE_ENV, other.to_str().unwrap())]),
        )
        .unwrap();
        assert_eq!(
            egress_source(&l).unwrap().blocklist_file.as_deref(),
            Some(other.as_path())
        );
        let l = load_from(Some(&file), &vars(&[(OPERATOR_BLOCKLIST_FILE_ENV, "")])).unwrap();
        assert_eq!(
            egress_source(&l).unwrap().blocklist_file.as_deref(),
            Some(block.as_path())
        );
    }

    #[test]
    fn egress_lists_accept_the_nested_environment_form() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(&dir, "crawlx.toml", "");
        let l = load_from(
            Some(&file),
            &vars(&[
                ("CRAWLX_EGRESS__DEPLOYMENT_ALLOWLIST", "[\"10.20.0.0/16\"]"),
                (
                    "CRAWLX_EGRESS__OPERATOR_BLOCKLIST",
                    "[\"a.test\", \"203.0.113.9\"]",
                ),
            ]),
        )
        .unwrap();
        assert_eq!(l.sources["egress.deployment_allowlist"], Source::Env);
        let lists = egress_source(&l).unwrap().load_blocking().unwrap();
        assert_eq!(lists.allowlist().unwrap().len(), 1);
        assert!(lists.blocked_host("a.test").is_some());
        assert!(lists.blocked_ip("203.0.113.9".parse().unwrap()));

        // the command-side reader sees the same through `getenv`, without a strict scan of the
        // environment (an unrelated CRAWLX_* variable does not fail it)
        let env: BTreeMap<&str, &str> = [
            (CONFIG_ENV, file.to_str().unwrap()),
            ("CRAWLX_EGRESS__OPERATOR_BLOCKLIST", "[\"b.test\"]"),
            ("CRAWLX_SOMETHING_ELSE", "1"),
        ]
        .into_iter()
        .collect();
        let source = egress_source_from_env(&|k| env.get(k).map(|v| (*v).to_owned())).unwrap();
        assert_eq!(source.blocklist_static, ["b.test"]);
        assert!(source.allowlist_static.is_none());
        let strict = load_from(Some(&file), &vars(&[("CRAWLX_SOMETHING_ELSE", "1")]));
        assert!(strict.is_err(), "`config check` stays the strict reader");
    }

    #[test]
    fn bad_cidrs_bad_hosts_and_bad_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        let malformed = write(&dir, "allow.txt", "10.0.0.0/8\nnot-a-network\n");
        let bad_block = write(&dir, "block.txt", "ok.test\nbad host name\n");
        let file = write(
            &dir,
            "crawlx.toml",
            "environment = \"dev\"\n[egress]\ndeployment_allowlist = [\"10.0.0.0/8\", \"not-a-cidr\"]\n\
             operator_blocklist = [\"good.test\", \"bad host\"]\n",
        );
        let l = load_from(Some(&file), &[]).unwrap();
        let keys = finding_keys(&l, true);
        assert!(
            keys.contains(&"egress.deployment_allowlist[1]".to_owned()),
            "{keys:?}"
        );
        assert!(
            !keys.contains(&"egress.deployment_allowlist[0]".to_owned()),
            "{keys:?}"
        );
        assert!(
            keys.contains(&"egress.operator_blocklist[1]".to_owned()),
            "{keys:?}"
        );
        assert!(
            !keys.contains(&"egress.operator_blocklist[0]".to_owned()),
            "{keys:?}"
        );
        let e = egress_source(&l).unwrap_err().to_string();
        assert!(e.contains("egress.deployment_allowlist"), "{e}");

        // named files must exist and parse; each is reported on its own
        let l = load_from(
            Some(&write(&dir, "dev.toml", "environment = \"dev\"\n")),
            &vars(&[
                (DEPLOYMENT_ALLOWLIST_FILE_ENV, "/nonexistent/allow.txt"),
                (OPERATOR_BLOCKLIST_FILE_ENV, bad_block.to_str().unwrap()),
            ]),
        )
        .unwrap();
        let (f, _) = validate(&l);
        let missing = f
            .iter()
            .find(|f| f.key == "egress.deployment_allowlist_file")
            .unwrap();
        assert!(
            missing.error && missing.message.contains("/nonexistent/allow.txt"),
            "{missing:?}"
        );
        let bad = f
            .iter()
            .find(|f| f.key == "egress.operator_blocklist_file")
            .unwrap();
        assert!(bad.error && bad.message.contains("line 2"), "{bad:?}");

        let l = load_from(
            Some(&write(&dir, "dev.toml", "environment = \"dev\"\n")),
            &vars(&[(DEPLOYMENT_ALLOWLIST_FILE_ENV, malformed.to_str().unwrap())]),
        )
        .unwrap();
        let (f, _) = validate(&l);
        let bad = f
            .iter()
            .find(|f| f.key == "egress.deployment_allowlist_file")
            .unwrap();
        assert!(bad.error && bad.message.contains("line 2"), "{bad:?}");
    }

    #[test]
    fn production_warns_when_no_deployment_allowlist_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let prod = write(&dir, "prod.toml", "");
        let warns = |l: &Loaded| {
            finding_keys(l, false)
                .iter()
                .any(|k| k == "egress.deployment_allowlist")
        };
        let l = load_from(Some(&prod), &[]).unwrap();
        assert_eq!(l.config.environment, Environment::Prod);
        assert!(warns(&l), "unset in prod is a warning");
        assert!(!finding_keys(&l, true).contains(&"egress.deployment_allowlist".to_owned()));

        let l = load_from(
            Some(&prod),
            &vars(&[("CRAWLX_EGRESS__DEPLOYMENT_ALLOWLIST", "[\"10.0.0.0/8\"]")]),
        )
        .unwrap();
        assert!(!warns(&l), "a static allowlist silences it");
        let allow = write(&dir, "allow.txt", "10.0.0.0/8\n");
        let l = load_from(
            Some(&prod),
            &vars(&[(DEPLOYMENT_ALLOWLIST_FILE_ENV, allow.to_str().unwrap())]),
        )
        .unwrap();
        assert!(!warns(&l), "so does an allowlist file");
        // a set but empty list is still a bound
        let l = load_from(
            Some(&prod),
            &vars(&[("CRAWLX_EGRESS__DEPLOYMENT_ALLOWLIST", "[]")]),
        )
        .unwrap();
        assert!(!warns(&l));

        let dev = write(&dir, "dev.toml", "environment = \"dev\"\n");
        assert!(!warns(&load_from(Some(&dev), &[]).unwrap()), "dev does not warn");
    }

    #[test]
    fn operator_keys_file_is_loaded_validated_and_never_printed() {
        let dir = tempfile::tempdir().unwrap();
        let secret_hex = "0123456789abcdef0123456789abcdef";
        let keys = write(&dir, "keys", &format!("# operator keys\nop1 {secret_hex}\n"));
        let env: BTreeMap<&str, String> = [(OPERATOR_KEYS_FILE_ENV, keys.display().to_string())]
            .into_iter()
            .collect();
        let getenv = |k: &str| env.get(k).cloned();
        assert!(!operator_keys(&getenv).unwrap().is_empty());
        assert!(operator_keys(&|_| None).unwrap().is_empty(), "no file: no keys");
        assert!(
            operator_keys(&|_| Some(String::new())).unwrap().is_empty(),
            "empty value is unset"
        );

        let dev = write(&dir, "dev.toml", "environment = \"dev\"\n");
        let l = load_from(
            Some(&dev),
            &vars(&[(OPERATOR_KEYS_FILE_ENV, keys.to_str().unwrap())]),
        )
        .unwrap();
        let (f, secrets) = validate(&l);
        assert!(f.iter().all(|f| !f.error), "{f:?}");
        let status = secrets
            .iter()
            .find(|s| s.key == "authz.operator_keys_file")
            .unwrap();
        assert!(status.present);
        // the passthrough shows the path of the file, never anything inside it
        let shown = redacted_passthrough(&l.passthrough);
        assert_eq!(shown[OPERATOR_KEYS_FILE_ENV], keys.to_str().unwrap());
        assert!(!json!(shown).to_string().contains(secret_hex));

        // a malformed key is an error that names the line, not the key
        let bad = write(&dir, "bad", &format!("op1 {secret_hex}\nop2 not-hex-at-all\n"));
        let l = load_from(
            Some(&dev),
            &vars(&[(OPERATOR_KEYS_FILE_ENV, bad.to_str().unwrap())]),
        )
        .unwrap();
        let (f, _) = validate(&l);
        let e = f.iter().find(|f| f.key == "authz.operator_keys_file").unwrap();
        assert!(e.error && e.message.contains("line 2"), "{e:?}");
        assert!(
            !e.message.contains(secret_hex) && !e.message.contains("not-hex-at-all"),
            "{e:?}"
        );
        let env: BTreeMap<&str, String> = [(OPERATOR_KEYS_FILE_ENV, bad.display().to_string())]
            .into_iter()
            .collect();
        let err = format!("{:#}", operator_keys(&|k| env.get(k).cloned()).unwrap_err());
        assert!(!err.contains(secret_hex), "{err}");

        // a key shorter than the minimum, an empty file and a missing file all fail
        let short = write(&dir, "short", "op1 abcd\n");
        let empty = write(&dir, "empty", "# nothing\n");
        for path in [short, empty, dir.path().join("missing")] {
            let env: BTreeMap<&str, String> = [(OPERATOR_KEYS_FILE_ENV, path.display().to_string())]
                .into_iter()
                .collect();
            assert!(
                operator_keys(&|k| env.get(k).cloned()).is_err(),
                "{}",
                path.display()
            );
        }

        // the API URL and key of `crawlx authz` and `crawlx mcp` are known variables, the key redacted
        let l = load_from(
            Some(&dev),
            &vars(&[
                ("CRAWLX_API_URL", "http://127.0.0.1:8080"),
                ("CRAWLX_API_KEY", "cx_live_secret"),
            ]),
        )
        .unwrap();
        let shown = redacted_passthrough(&l.passthrough);
        assert_eq!(shown["CRAWLX_API_URL"], "http://127.0.0.1:8080");
        assert_eq!(shown["CRAWLX_API_KEY"], "<redacted>");
    }

    #[test]
    fn deployment_proxy_file_env_and_flag_precedence_preserves_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(
            &dir,
            "proxy.toml",
            "[fetch]\nbasic_proxy_url = 'http://file-user:file-secret@basic.test:8080'\n\
             enhanced_proxy_url = 'socks5h://file-user:file-secret@enhanced.test:1080'\n",
        );
        let environment = vars(&[
            (CONFIG_ENV, file.to_str().unwrap()),
            (BASIC_PROXY_URL_ENV, "https://env-user:env-secret@basic-env.test"),
        ]);
        let lookup = |key: &str| environment.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        let file_routes = load_from(Some(&file), &[])
            .unwrap()
            .config
            .fetch
            .proxy_routes(&|_| None)
            .unwrap();
        assert_eq!(file_routes.basic.unwrap().password(), Some("file-secret"));
        let env_routes = ProxyArgs::default().routes(&lookup).unwrap();
        assert_eq!(
            env_routes.basic.as_ref().unwrap().host_str(),
            Some("basic-env.test")
        );
        assert_eq!(env_routes.basic.unwrap().password(), Some("env-secret"));
        assert_eq!(env_routes.enhanced.unwrap().scheme(), "socks5h");
        let flags = ProxyArgs {
            fetch_basic_proxy_url: Some(ProxyUrl("http://flag-user:flag-secret@flag.test".to_owned())),
            ..ProxyArgs::default()
        };
        let routes = flags.routes(&lookup).unwrap();
        assert_eq!(routes.basic.as_ref().unwrap().host_str(), Some("flag.test"));
        assert_eq!(routes.basic.unwrap().password(), Some("flag-secret"));
        assert_eq!(routes.enhanced.unwrap().password(), Some("file-secret"));
        let loaded = load_from(
            Some(&file),
            &vars(&[
                (BASIC_PROXY_URL_ENV, "http://flat.test"),
                ("CRAWLX_FETCH__BASIC_PROXY_URL", "http://nested.test"),
                (ENHANCED_PROXY_URL_ENV, "https://enhanced-env.test"),
            ]),
        )
        .unwrap();
        let routes = loaded.config.fetch.proxy_routes(&|_| None).unwrap();
        assert_eq!(routes.basic.unwrap().host_str(), Some("nested.test"));
        assert_eq!(routes.enhanced.unwrap().host_str(), Some("enhanced-env.test"));
        assert_eq!(loaded.sources["fetch.basic_proxy_url"], Source::Env);
        assert_eq!(loaded.sources["fetch.enhanced_proxy_url"], Source::Env);
        let defaults = Fetch::default().proxy_routes(&|_| None).unwrap();
        assert!(defaults.basic.is_none() && defaults.enhanced.is_none());
    }

    #[test]
    fn deployment_proxy_output_and_errors_never_show_urls() {
        let dir = tempfile::tempdir().unwrap();
        let file = write(&dir, "proxy.toml", "environment = 'dev'\n");
        let loaded = load_from(
            Some(&file),
            &vars(&[
                (
                    BASIC_PROXY_URL_ENV,
                    "http://secret-user:secret-password@secret-host.test/secret-path?secret-query",
                ),
                (
                    ENHANCED_PROXY_URL_ENV,
                    "ftp://secret-user:secret-password@secret-host.test",
                ),
            ]),
        )
        .unwrap();
        let (findings, _) = validate(&loaded);
        assert!(findings
            .iter()
            .any(|f| f.error && f.key == "fetch.enhanced_proxy_url"));
        for output in [
            effective_json(&loaded).unwrap().to_string(),
            toml::to_string_pretty(&loaded.config).unwrap(),
            format!("{loaded:?}"),
            format!("{findings:?}"),
            format!("{:#}", loaded.config.fetch.proxy_routes(&|_| None).unwrap_err()),
        ] {
            for secret in [
                "secret-user",
                "secret-password",
                "secret-host",
                "secret-path",
                "secret-query",
            ] {
                assert!(!output.contains(secret), "{output}");
            }
        }
        assert_eq!(
            effective_json(&loaded).unwrap()["fetch"]["basic_proxy_url"],
            "<redacted>"
        );
        let malformed = write(
            &dir,
            "malformed.toml",
            "[fetch]\nbasic_proxy_url = \"http://secret-user:secret-password@secret-host.test\n",
        );
        let error = format!("{:#}", load_from(Some(&malformed), &[]).unwrap_err());
        assert!(error.contains("invalid TOML"), "{error}");
        assert!(!error.contains("secret-"), "{error}");
    }

    #[test]
    fn deployment_proxy_schemes_and_hosts_are_validated() {
        for value in [
            "ftp://secret-user:secret-password@proxy.test",
            "file:///secret-password",
            "socks5:///secret-password",
            "secret-password",
            "http://secret-user:secret-password@proxy.test:invalid",
        ] {
            let error = format!("{:#}", ProxyUrl(value.to_owned()).parse().unwrap_err());
            assert!(!error.contains("secret-"), "{error}");
        }
        for scheme in ["http", "https", "socks5", "socks5h"] {
            let proxy = ProxyUrl(format!("{scheme}://user:password@proxy.test:1080"));
            assert_eq!(proxy.parse().unwrap().password(), Some("password"));
        }
    }

    #[test]
    fn deployment_proxy_flags_are_available_on_worker_and_crawl() {
        use clap::Parser as _;

        let dir = tempfile::tempdir().unwrap();
        let file = write(&dir, "proxy.toml", "");
        let lookup = |key: &str| (key == CONFIG_ENV).then(|| file.display().to_string());
        for command in ["worker", "crawl"] {
            let cli = crate::Cli::try_parse_from([
                "crawlx",
                command,
                "--fetch-basic-proxy-url",
                "http://flag-user:flag-password@basic.test:8080",
                "--fetch-enhanced-proxy-url",
                "socks5://flag-user:flag-password@enhanced.test:1080",
            ])
            .unwrap();
            assert!(!format!("{cli:?}").contains("flag-password"));
            let args = match cli.command {
                crate::Command::Worker(args) => args.proxy_routes,
                crate::Command::Crawl(args) => args.proxy_routes,
                _ => panic!("expected worker or crawl"),
            };
            let routes = args.routes(&lookup).unwrap();
            assert_eq!(routes.basic.unwrap().password(), Some("flag-password"));
            assert_eq!(routes.enhanced.unwrap().host_str(), Some("enhanced.test"));
        }
        // Do not let clap reject values: clap prints rejected input verbatim.
        let cli = crate::Cli::try_parse_from([
            "crawlx",
            "worker",
            "--fetch-basic-proxy-url",
            "ftp://flag-user:flag-password@basic.test",
        ])
        .unwrap();
        let crate::Command::Worker(args) = cli.command else {
            panic!("expected worker")
        };
        let error = format!("{:#}", args.proxy_routes.routes(&lookup).unwrap_err());
        assert!(error.contains("fetch.basic_proxy_url"), "{error}");
        assert!(!error.contains("flag-password"), "{error}");
    }

    #[test]
    fn capability_env_is_validated_and_never_prints_key_values() {
        let key = "a7".repeat(32);
        let loaded = load_from(
            None,
            &[
                ("CRAWLX_REQUEST_IDENTITY_KEY".into(), key.clone()),
                (
                    "CRAWLX_PROFILE_KEY_REF".into(),
                    "file:///operator/profile-key".into(),
                ),
                (
                    "CRAWLX_ZDR_REDIS_URL".into(),
                    "redis://operator:redis-canary@localhost/".into(),
                ),
            ],
        )
        .unwrap();
        let (mut findings, _) = validate(&loaded);
        assert!(!findings
            .iter()
            .any(|finding| finding.key == "capabilities.request_identity"));
        for output in [
            format!("{loaded:?}"),
            effective_json(&loaded).unwrap().to_string(),
            serde_json::to_string(&redacted_passthrough(&loaded.passthrough)).unwrap(),
        ] {
            assert!(!output.contains(&key));
            assert!(!output.contains("redis-canary"));
        }
        let mut ambiguous = loaded.clone();
        ambiguous.passthrough.insert(
            "CRAWLX_REQUEST_IDENTITY_KEY_FILE".into(),
            "/not-read-when-ambiguous".into(),
        );
        validate_capability_inputs(&ambiguous, &mut findings);
        assert!(findings
            .iter()
            .any(|finding| finding.error && finding.key == "capabilities.request_identity"));
    }

    #[tokio::test]
    async fn configured_registry_and_profile_secret_refs_fail_closed() {
        let loaded = load_from(
            None,
            &[
                ("CRAWLX_RETAINED_PROFILES_ENABLED".into(), "true".into()),
                (
                    "CRAWLX_PROFILE_KEY_REF".into(),
                    "file:///nonexistent-crawlx-profile-key".into(),
                ),
                (
                    "CRAWLX_PROTOCOL_REGISTRY".into(),
                    "/nonexistent-crawlx-protocol-registry".into(),
                ),
                (
                    "CRAWLX_DELIVERY_REGISTRY".into(),
                    "/nonexistent-crawlx-delivery-registry".into(),
                ),
            ],
        )
        .unwrap();
        let mut findings = Vec::new();
        validate_capability_secrets(&loaded, &mut findings, &crawlx_worker::FileSecretResolver).await;
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|finding| finding.error));
        assert!(!format!("{findings:?}").contains("nonexistent-crawlx"));
    }

    #[tokio::test]
    async fn private_file_secret_refs_and_real_registry_schemas_pass_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("profile-key");
        std::fs::write(&key, "6c".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let protocol = dir.path().join("protocol.json");
        std::fs::write(
            &protocol,
            r#"{"schemaVersion":1,"approvedTenants":[],"services":{}}"#,
        )
        .unwrap();
        let delivery = dir.path().join("delivery.json");
        std::fs::write(
            &delivery,
            r#"{"version":1,"destinations":[{"kind":"stdout","id":"console"}]}"#,
        )
        .unwrap();
        let loaded = load_from(
            None,
            &[
                ("CRAWLX_RETAINED_PROFILES_ENABLED".into(), "true".into()),
                (
                    "CRAWLX_PROFILE_KEY_REF".into(),
                    format!("file://{}", key.display()),
                ),
                ("CRAWLX_PROTOCOL_REGISTRY".into(), protocol.display().to_string()),
                ("CRAWLX_DELIVERY_REGISTRY".into(), delivery.display().to_string()),
            ],
        )
        .unwrap();
        let mut findings = Vec::new();
        validate_capability_secrets(&loaded, &mut findings, &crawlx_worker::FileSecretResolver).await;
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn flat_secret_files_override_configuration_with_real_effective_paths() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        std::fs::write(
            &config,
            "[database]\nurl_file = '/old/db'\n[api.webhook]\nsigning_key_file = '/old/webhook'\n",
        )
        .unwrap();
        let loaded = load_from(
            Some(&config),
            &[
                ("CRAWLX_DATABASE_URL_FILE".into(), "/effective/db".into()),
                ("CRAWLX_WEBHOOK_SECRET_FILE".into(), "/effective/webhook".into()),
            ],
        )
        .unwrap();
        assert_eq!(
            loaded.config.database.url_file.as_deref(),
            Some(Path::new("/effective/db"))
        );
        assert_eq!(
            loaded.config.api.webhook.signing_key_file.as_deref(),
            Some(Path::new("/effective/webhook"))
        );
        assert_eq!(loaded.sources["database.url_file"], Source::Env);
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_operator_settings_fail_without_lossy_fallback() {
        use std::os::unix::ffi::OsStringExt as _;
        for variable in [
            "CRAWLX_REQUEST_IDENTITY_KEY",
            "CRAWLX_REQUEST_IDENTITY_KEY_FILE",
            "CRAWLX_CHECKPOINT_KMS_KEY_ID",
            "CRAWLX_ARTICLE_LANGUAGE_BUNDLE",
        ] {
            let error = validate_operator_environment(&|name| {
                (name == variable).then(|| std::ffi::OsString::from_vec(vec![0xff, 0xfe]))
            })
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "operator capability settings must be valid Unicode"
            );
        }
        validate_operator_environment(&|_| None).unwrap();
    }

    #[tokio::test]
    async fn checkpoint_kms_key_is_opt_in_redacted_and_rejects_empty_identifiers() {
        let key_id = "arn:aws:kms:us-east-1:123456789012:key/operator-canary"; // wire-compat: key ARN shape
        let loaded = load_from(None, &vars(&[("CRAWLX_CHECKPOINT_KMS_KEY_ID", key_id)])).unwrap();
        assert_eq!(
            capability_report(&loaded)["checkpoint_encryption"]["configured"],
            true
        );
        for output in [
            format!("{loaded:?}"),
            effective_json(&loaded).unwrap().to_string(),
            serde_json::to_string(&redacted_passthrough(&loaded.passthrough)).unwrap(),
        ] {
            assert!(!output.contains(key_id));
        }
        let mut findings = Vec::new();
        for value in ["", "   "] {
            let empty = load_from(None, &vars(&[("CRAWLX_CHECKPOINT_KMS_KEY_ID", value)])).unwrap();
            validate_checkpoint_keys(&empty, &mut findings).await;
            assert_eq!(findings.len(), 1);
            assert!(findings[0].error);
            assert_eq!(findings[0].key, "capabilities.checkpoint_encryption");
            findings.clear();
        }
        let absent = load_from(None, &[]).unwrap();
        assert_eq!(
            capability_report(&absent)["checkpoint_encryption"]["configured"],
            false
        );
        validate_checkpoint_keys(&absent, &mut findings).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn article_language_env_uses_real_loader_and_fails_closed_for_missing_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-bundle");
        let loaded = load_from(
            None,
            &[(
                "CRAWLX_ARTICLE_LANGUAGE_BUNDLE".into(),
                missing.display().to_string(),
            )],
        )
        .unwrap();
        assert_eq!(capability_report(&loaded)["article_language"]["configured"], true);
        let mut findings = Vec::new();
        validate_article_language_bundle(&loaded, &mut findings).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].error);
        assert_eq!(findings[0].key, "capabilities.article_language");
        let absent = load_from(None, &[]).unwrap();
        findings.clear();
        validate_article_language_bundle(&absent, &mut findings).await;
        assert!(findings.is_empty());
    }
}
