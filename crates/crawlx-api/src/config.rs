//! API configuration.

mod providers;

pub use providers::{
    BrandingSettings, EmbeddingSettings, EnvError, ExtractionSettings, DEFAULT_BRANDING_TIMEOUT_MS,
    DEFAULT_EXTRACTION_MODEL, DEFAULT_TOP_N, UNSUPPORTED_ENV,
};

use crawlx_policy::TenantLimits;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

/// A development API key created at startup (`tenant` is a UUID or a name; names
/// map to a deterministic tenant id).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct ApiKeyBootstrap {
    /// Tenant the key belongs to: a UUID, or a name mapped to a deterministic tenant id.
    pub tenant: String,
    /// The full key: `cx_live_<26 base32>`, or `fc-<16..=64 alphanumerics>` when
    /// [`CompatConfig::firecrawl_keys`] is on.
    pub key: String,
}

impl ApiKeyBootstrap {
    /// A bootstrap key for `tenant` (UUID or name) with the full key text `key`.
    #[must_use]
    pub fn new(tenant: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            tenant: tenant.into(),
            key: key.into(),
        }
    }
}

impl std::fmt::Debug for ApiKeyBootstrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyBootstrap")
            .field("tenant", &self.tenant)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Settings of the Firecrawl-compatible facade (`/compat/firecrawl/v2`).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatConfig {
    /// Accept Firecrawl-style `fc-...` bearer keys on the `/compat/` routes in addition to
    /// `cx_live_...` keys (default off). Bootstrap keys may then be `fc-` keys too; an `fc-` key
    /// is never accepted outside `/compat/`.
    #[serde(default)]
    pub firecrawl_keys: bool,
    /// The authorization record under which `ignoreRobotsTxt: true` lowers the robots.txt gate
    /// of a facade crawl (`safety.respectRobotsTxt = false`; Firecrawl offers the option to
    /// enterprise teams only). The record must belong to the caller's tenant, be active and
    /// verified (created through `POST /v1/authorizations`), cover the seed URL and carry
    /// `robotsOverrideAcknowledged`. Unset (the default): the option is refused with
    /// `403 ROBOTS_OVERRIDE_NOT_AUTHORIZED`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub robots_authorization: Option<crawlx_core::AuthorizationRecordId>,
}

impl CompatConfig {
    /// Fill the unset settings from the environment variables `lookup` serves:
    /// `CRAWLX_COMPAT_FIRECRAWL_KEYS` (`1`/`true`) and `CRAWLX_COMPAT_ROBOTS_AUTHORIZATION` (the
    /// UUID of the authorization record behind `ignoreRobotsTxt`). A value that is already set
    /// wins.
    ///
    /// # Errors
    /// [`EnvError::Number`] when `CRAWLX_COMPAT_ROBOTS_AUTHORIZATION` is not a UUID.
    pub fn from_lookup(mut self, lookup: impl Fn(&str) -> Option<String>) -> Result<Self, EnvError> {
        let get = |k: &str| lookup(k).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        if !self.firecrawl_keys {
            self.firecrawl_keys = get("CRAWLX_COMPAT_FIRECRAWL_KEYS")
                .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"));
        }
        if self.robots_authorization.is_none() {
            if let Some(v) = get("CRAWLX_COMPAT_ROBOTS_AUTHORIZATION") {
                let id = v.parse().map_err(|_| EnvError::Number {
                    var: "CRAWLX_COMPAT_ROBOTS_AUTHORIZATION",
                    expected: "an authorization record UUID",
                })?;
                self.robots_authorization = Some(id);
            }
        }
        Ok(self)
    }
}

/// What `run` needs.
#[derive(Clone)]
pub struct ApiConfig {
    /// Socket address the HTTP server listens on.
    pub bind: SocketAddr,
    /// `None` runs on in-memory repositories (tests, development).
    pub database_url: Option<String>,
    /// Restricted non-owner request connection (`CRAWLX_API_DATABASE_URL`). The
    /// `database_url` connection remains startup/worker/maintenance authority.
    pub api_database_url: Option<String>,
    /// Explicit development-only opt-out from the separate API role requirement.
    /// Never enable this in a multi-tenant deployment.
    pub allow_owner_api: bool,
    /// Root of the filesystem artifact store.
    pub artifacts_dir: PathBuf,
    /// Bounded memory-only upload spool for artifact objects and index records.
    pub artifact_spool: crawlx_storage::UploadSpoolConfig,
    /// Development keys created (with all scopes) at startup.
    pub api_keys: Vec<ApiKeyBootstrap>,
    /// Per-tenant token bucket size/refill per minute; `0` disables rate limiting.
    pub rate_limit_per_minute: u32,
    /// HMAC secret signing webhook deliveries.
    pub webhook_secret: String,
    /// Operator-provisioned secret root for tenant-scoped request identity correlation.
    /// Missing keys disable source imports that require secret-safe correlation.
    pub request_identity_key: Option<crawlx_core::SecretOr<[u8; 32]>>,
    /// Optional second listener serving only `GET /metrics` without authentication; must be a
    /// loopback address (a sidecar scraper). `None` disables it.
    pub metrics_bind: Option<SocketAddr>,
    /// LLM, search and docs settings of the Firecrawl-compatible LLM products; unset sections
    /// are filled from the self-host environment variables when the server starts.
    pub intel: IntelConfig,
    /// Firecrawl-compatibility facade settings.
    pub compat: CompatConfig,
    /// OCR for `POST /v2/parse` uploads (scanned PDFs, images). `backend: off` (the default)
    /// keeps images refused and scanned pages empty; the facade's scrape runs read the worker's
    /// own setting (`WorkerConfig::ocr`), so configure both processes alike.
    pub ocr: crawlx_extract::parse::ocr::OcrConfig,
    /// The live deployment lists (`egress.deployment_allowlist`, `egress.operator_blocklist`):
    /// admission applies them to every run and every webhook, and the run's egress policy keeps
    /// the handle, so a reload reaches runs in flight. `None`: no deployment bound, no blocklist.
    pub egress_lists: Option<crawlx_policy::SharedEgressLists>,
    /// The deployment's operator keys: the only way to prove ownership of `authorizedNetworks`
    /// (an `operator_signature` proof). Loaded from the file named by
    /// [`OPERATOR_KEYS_FILE_ENV`]; empty (the default) refuses every operator signature.
    pub operator_keys: crawlx_policy::attestation::OperatorKeys,
    /// How the API checks the DNS TXT and well-known file ownership challenges. `None`: the
    /// [`NetworkProbe`](crate::ownership::NetworkProbe) (system DNS, public addresses only).
    pub ownership_probe: Option<std::sync::Arc<dyn crate::ownership::OwnershipProbe>>,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 8080)),
            database_url: None,
            api_database_url: None,
            allow_owner_api: false,
            artifacts_dir: PathBuf::from("./artifacts"),
            artifact_spool: crawlx_storage::UploadSpoolConfig::default(),
            api_keys: Vec::new(),
            rate_limit_per_minute: 6000,
            webhook_secret: String::new(),
            request_identity_key: None,
            metrics_bind: None,
            intel: IntelConfig::default(),
            compat: CompatConfig::default(),
            ocr: crawlx_extract::parse::ocr::OcrConfig::default(),
            egress_lists: None,
            operator_keys: crawlx_policy::attestation::OperatorKeys::default(),
            ownership_probe: None,
        }
    }
}

impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("bind", &self.bind)
            .field("database_url", &self.database_url.as_ref().map(|_| "<redacted>"))
            .field(
                "api_database_url",
                &self.api_database_url.as_ref().map(|_| "<redacted>"),
            )
            .field("allow_owner_api", &self.allow_owner_api)
            .field("artifacts_dir", &self.artifacts_dir)
            .field("artifact_spool", &self.artifact_spool)
            .field("api_keys", &self.api_keys)
            .field("rate_limit_per_minute", &self.rate_limit_per_minute)
            .field("webhook_secret", &"<redacted>")
            .field(
                "request_identity_key",
                &self.request_identity_key.as_ref().map(|_| "<redacted>"),
            )
            .field("metrics_bind", &self.metrics_bind)
            .field("intel", &self.intel)
            .field("compat", &self.compat)
            .field("ocr", &self.ocr)
            .field("egress_lists", &self.egress_lists.as_ref().map(|_| "live"))
            .field("operator_keys", &self.operator_keys)
            .field(
                "ownership_probe",
                &self.ownership_probe.as_ref().map(|_| "custom"),
            )
            .finish()
    }
}

/// Environment variable naming the operator keys file (one `key_id hex-key` pair per line,
/// `#` comments): see [`load_operator_keys`].
pub const OPERATOR_KEYS_FILE_ENV: &str = "CRAWLX_AUTHZ_OPERATOR_KEYS_FILE";

/// Read the operator keys file at `path` into [`ApiConfig::operator_keys`].
///
/// # Errors
/// [`ApiError::Config`] naming the file (never a key) when it cannot be read or a line is not
/// `key_id hex-key` with a key of at least [`crawlx_policy::attestation::MIN_KEY_BYTES`] bytes.
pub async fn load_operator_keys(
    path: &std::path::Path,
) -> Result<crawlx_policy::attestation::OperatorKeys, crate::errors::ApiError> {
    let text = tokio::fs::read_to_string(path).await.map_err(|e| {
        crate::errors::ApiError::Config(format!("operator keys file {}: {e}", path.display()))
    })?;
    crawlx_policy::attestation::OperatorKeys::parse(&text)
        .map_err(|e| crate::errors::ApiError::Config(format!("operator keys file {}: {e}", path.display())))
}

/// Tunables with defaults.
#[derive(Clone, Debug)]
pub struct Settings {
    /// Active runs per tenant (`quota_exceeded` above this).
    pub max_active_runs: u64,
    /// Admission limits applied to every create request (clamps and ceilings).
    pub tenant_limits: TenantLimits,
    /// Recorded on `crawl_runs.policy_version`.
    pub policy_version: u32,
    /// Largest accepted request body.
    pub max_body_bytes: usize,
    /// Page size of a list endpoint when `?limit=` is absent.
    pub default_page_limit: usize,
    /// Largest `?limit=` a list endpoint accepts; larger values are clamped to it.
    pub max_page_limit: usize,
    /// Page content above this size is returned as an artifact link.
    pub inline_max_bytes: usize,
    /// Pause between event-table polls while an SSE stream is caught up.
    pub sse_poll_interval: Duration,
    /// Interval of the SSE `ping` comment that keeps idle connections open.
    pub sse_keepalive: Duration,
    /// Events fetched per SSE poll.
    pub sse_batch: u32,
    /// Open SSE connections per tenant before `429 too_many_streams`.
    pub sse_max_per_tenant: usize,
    /// Open SSE connections per run before `429 too_many_streams`.
    pub sse_max_per_run: usize,
    /// Share of `X-Crawlx-Shadow: 1` compat requests that are mirrored into a shadow run
    /// (default 5); `0` mirrors nothing, `100` everything. Requests
    /// with `zeroDataRetention: true` are never mirrored regardless.
    pub shadow_sample_percent: u8,
    /// Resource limits of `POST /compat/firecrawl/v2/parse` uploads: input bytes (50 MiB
    /// default), decompressed bytes, archive entries, pages, sheets and rows.
    pub parse_limits: crawlx_extract::parse::ParseLimits,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_active_runs: 10,
            tenant_limits: TenantLimits::default(),
            policy_version: 1,
            max_body_bytes: 256 * 1024,
            default_page_limit: 100,
            max_page_limit: 1000,
            inline_max_bytes: 1024 * 1024,
            sse_poll_interval: Duration::from_millis(250),
            sse_keepalive: Duration::from_secs(15),
            sse_batch: 200,
            sse_max_per_tenant: 50,
            sse_max_per_run: 5,
            shadow_sample_percent: 5,
            parse_limits: crawlx_extract::parse::ParseLimits::default(),
        }
    }
}

/// LLM endpoint of the document products (`llm{endpoint, model, apiKeyRef, timeoutMs}`).
///
/// When [`IntelConfig::llm`] is `None`, [`IntelConfig::from_lookup`] fills it from the Firecrawl
/// self-host variables `OPENAI_BASE_URL`, `MODEL_NAME` and `OPENAI_API_KEY`.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LlmSettings {
    /// OpenAI-compatible base URL (`https://api.openai.com/v1`) or full `chat/completions` URL.
    pub endpoint: String,
    /// Model name sent with every request.
    pub model: String,
    /// Reference to the API key, never the key itself: `env:NAME` (environment variable) or
    /// `file:/path` (first line of a file). `None` sends no credential.
    #[serde(default)]
    pub api_key_ref: Option<String>,
    /// Time budget of one call, milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Base URL of the speech-to-text endpoint of the `audio` / `video` formats (OpenAI-compatible
    /// `audio/transcriptions`, e.g. a Whisper server), or its full URL. The same credential as
    /// the chat endpoint is sent. `None`: those formats return the media without a transcript.
    /// [`IntelConfig::from_lookup`] fills it from `OPENAI_TRANSCRIBE_ENDPOINT`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcribe_endpoint: Option<String>,
    /// Model sent to the speech-to-text endpoint; `None` is `whisper-1`
    /// (`TRANSCRIBE_MODEL_NAME`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcribe_model: Option<String>,
}

/// Search backend of `/search`, the `/extract` web-search option and the agent's search tool.
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "provider", rename_all = "camelCase", deny_unknown_fields)]
pub enum SearchSettings {
    /// A SearXNG instance queried with `format=json` (`SEARXNG_ENDPOINT`, `SEARXNG_ENGINES`,
    /// `SEARXNG_CATEGORIES`).
    #[serde(rename_all = "camelCase")]
    Searxng {
        /// Base URL of the instance (`http://searxng:8080`).
        endpoint: String,
        /// Engines passed as `engines=` (empty = the instance default).
        #[serde(default)]
        engines: Vec<String>,
        /// Categories passed as `categories=` when the request names none (empty = the instance default).
        #[serde(default)]
        categories: Vec<String>,
    },
    /// A SearchApi-style hosted SERP API (`SEARCHAPI_API_KEY`, `SEARCHAPI_ENGINE`).
    #[serde(rename_all = "camelCase")]
    SearchApi {
        /// Reference to the API key (`env:NAME` or `file:/path`).
        api_key_ref: String,
        /// Engine parameter (`google`, `bing`, ...).
        engine: String,
        /// Endpoint override; `None` is `https://www.searchapi.io/api/v1/search`.
        #[serde(default)]
        endpoint: Option<String>,
    },
}

/// Settings of the LLM-backed and search-backed products.
#[derive(Clone, PartialEq, Eq, Default, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IntelConfig {
    /// LLM endpoint; `None` leaves the LLM formats and `/extract` answering `503`.
    #[serde(default)]
    pub llm: Option<LlmSettings>,
    /// Search backend; `None` leaves `/search` answering `503`.
    #[serde(default)]
    pub search: Option<SearchSettings>,
    /// Directory searched by `/support/docs-search` and `/support/ask` (Markdown files).
    #[serde(default)]
    pub docs_dir: Option<PathBuf>,
    /// Embedding model that ranks the pages of an `/extract` job against its prompt before the
    /// LLM sees them (`MODEL_EMBEDDING_NAME`); `None` keeps the scrape order and sends every page.
    #[serde(default)]
    pub embeddings: Option<EmbeddingSettings>,
    /// Second endpoint for the JSON-extraction step (`/extract`, the `json` format;
    /// `EXTRACTION_PROVIDER_*`); `None` answers it with [`Self::llm`] like every other step.
    #[serde(default)]
    pub extraction: Option<ExtractionSettings>,
    /// LLM that refines the markup-derived `branding` profile (`BRANDING_LLM_*`); `None` keeps the
    /// profile as the markup heuristics produced it.
    #[serde(default)]
    pub branding: Option<BrandingSettings>,
}

/// Failure to turn configured references into credentials.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretRefError {
    /// The reference uses a scheme other than `env:` or `file:`.
    #[error("unsupported secret reference scheme in {0:?} (use env:NAME or file:/path)")]
    Scheme(String),
    /// The environment variable is not set or empty.
    #[error("environment variable {0} is not set")]
    EnvMissing(String),
    /// The file could not be read.
    #[error("cannot read secret file {path}")]
    File {
        /// Path that failed.
        path: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// Resolve `env:NAME` / `env://NAME` / `file:/path` / `file:///path` to the secret text (trimmed).
///
/// # Errors
/// [`SecretRefError`] for an unknown scheme, a missing variable or an unreadable file.
pub fn resolve_secret_ref(reference: &str) -> Result<String, SecretRefError> {
    resolve_secret_ref_with(reference, |k| std::env::var(k).ok())
}

/// [`resolve_secret_ref`] with an injectable environment lookup.
///
/// # Errors
/// As [`resolve_secret_ref`].
pub fn resolve_secret_ref_with(
    reference: &str,
    env: impl Fn(&str) -> Option<String>,
) -> Result<String, SecretRefError> {
    if let Some(name) = reference
        .strip_prefix("env://")
        .or_else(|| reference.strip_prefix("env:"))
    {
        return env(name)
            .map(|v| v.trim().to_owned())
            .filter(|v| !v.is_empty())
            .ok_or_else(|| SecretRefError::EnvMissing(name.to_owned()));
    }
    if let Some(path) = reference
        .strip_prefix("file://")
        .or_else(|| reference.strip_prefix("file:"))
    {
        return std::fs::read_to_string(path)
            .map(|s| s.trim().to_owned())
            .map_err(|source| SecretRefError::File {
                path: path.to_owned(),
                source,
            });
    }
    Err(SecretRefError::Scheme(reference.to_owned()))
}

impl LlmSettings {
    /// The client configuration these settings describe.
    ///
    /// # Errors
    /// [`SecretRefError`] when `api_key_ref` cannot be resolved.
    pub fn resolve(&self) -> Result<crawlx_model::llm::LlmConfig, SecretRefError> {
        self.resolve_with(|k| std::env::var(k).ok())
    }

    /// [`Self::resolve`] with an injectable environment lookup.
    ///
    /// # Errors
    /// As [`Self::resolve`].
    pub fn resolve_with(
        &self,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<crawlx_model::llm::LlmConfig, SecretRefError> {
        let mut cfg = crawlx_model::llm::LlmConfig::new(&self.endpoint, &self.model);
        if let Some(r) = &self.api_key_ref {
            cfg.api_key = Some(crawlx_core::secret::SecretOr::secret(resolve_secret_ref_with(
                r, env,
            )?));
        }
        if let Some(ms) = self.timeout_ms {
            cfg.timeout = Duration::from_millis(ms);
        }
        cfg.transcribe_endpoint.clone_from(&self.transcribe_endpoint);
        cfg.transcribe_model.clone_from(&self.transcribe_model);
        Ok(cfg)
    }
}

impl IntelConfig {
    /// This config with every unset section filled from the Firecrawl self-host variables looked
    /// up through `lookup`: `OPENAI_BASE_URL` (or `OLLAMA_BASE_URL`), `MODEL_NAME`, `OPENAI_API_KEY` (key kept as an
    /// `env:OPENAI_API_KEY` reference), `SEARXNG_ENDPOINT`, `SEARXNG_ENGINES`,
    /// `SEARXNG_CATEGORIES` (comma separated), `SEARCHAPI_API_KEY`, `SEARCHAPI_ENGINE`, and the
    /// per-step provider variables `MODEL_EMBEDDING_NAME`, `EXTRACT_EMBEDDING_TOP_N`,
    /// `EXTRACTION_PROVIDER_{BASE_URL,MODEL,API_KEY,ROLLOUT_PERCENT,SHADOW_PERCENT,TEAM_IDS,MAX_INPUT_BYTES}`,
    /// `BRANDING_LLM_{BASE_URL,MODEL,API_KEY}` and `BRANDING_JEV_TIMEOUT_MS` (see
    /// [`EmbeddingSettings`], [`ExtractionSettings`], [`BrandingSettings`]).
    ///
    /// # Errors
    /// [`EnvError`] for a numeric provider variable that does not parse or routing shares that
    /// exceed 100.
    pub fn from_lookup(mut self, lookup: impl Fn(&str) -> Option<String>) -> Result<Self, EnvError> {
        let get = |k: &str| lookup(k).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        let list = |k: &str| {
            get(k)
                .map(|v| {
                    v.split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };
        if self.llm.is_none() {
            // `OLLAMA_BASE_URL` (Firecrawl self-host) names the Ollama root; its OpenAI-compatible API is at `/v1`
            let base = get("OPENAI_BASE_URL")
                .or_else(|| get("OLLAMA_BASE_URL").map(|o| format!("{}/v1", o.trim_end_matches('/'))));
            let key = get("OPENAI_API_KEY");
            if base.is_some() || key.is_some() {
                self.llm = Some(LlmSettings {
                    endpoint: base.unwrap_or_else(|| crawlx_model::llm::openai::DEFAULT_ENDPOINT.to_owned()),
                    model: get("MODEL_NAME")
                        .unwrap_or_else(|| crawlx_model::llm::openai::DEFAULT_MODEL.to_owned()),
                    api_key_ref: key.map(|_| "env:OPENAI_API_KEY".to_owned()),
                    timeout_ms: None,
                    transcribe_endpoint: get("OPENAI_TRANSCRIBE_ENDPOINT"),
                    transcribe_model: get("TRANSCRIBE_MODEL_NAME"),
                });
            }
        }
        if self.search.is_none() {
            if let Some(endpoint) = get("SEARXNG_ENDPOINT") {
                self.search = Some(SearchSettings::Searxng {
                    endpoint,
                    engines: list("SEARXNG_ENGINES"),
                    categories: list("SEARXNG_CATEGORIES"),
                });
            } else if get("SEARCHAPI_API_KEY").is_some() {
                self.search = Some(SearchSettings::SearchApi {
                    api_key_ref: "env:SEARCHAPI_API_KEY".to_owned(),
                    engine: get("SEARCHAPI_ENGINE").unwrap_or_else(|| "google".to_owned()),
                    endpoint: None,
                });
            }
        }
        providers::fill(&mut self, &get)?;
        Ok(self)
    }

    /// [`Self::from_lookup`] over the process environment.
    ///
    /// # Errors
    /// As [`Self::from_lookup`].
    pub fn from_env(self) -> Result<Self, EnvError> {
        self.from_lookup(|k| std::env::var(k).ok())
    }
}

#[cfg(test)]
mod intel_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeMap;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: BTreeMap<&str, &str> = pairs.iter().copied().collect();
        move |k| map.get(k).map(|v| (*v).to_owned())
    }

    #[test]
    fn firecrawl_variables_fill_unset_sections() {
        let cfg = IntelConfig::default()
            .from_lookup(env(&[
                ("OPENAI_BASE_URL", "http://ollama:11434/v1"),
                ("MODEL_NAME", "qwen3"),
                ("SEARXNG_ENDPOINT", "http://sx:8080"),
                ("SEARXNG_ENGINES", "google, bing,"),
                ("SEARXNG_CATEGORIES", "general"),
            ]))
            .unwrap();
        let llm = cfg.llm.unwrap();
        assert_eq!(
            (llm.endpoint.as_str(), llm.model.as_str()),
            ("http://ollama:11434/v1", "qwen3")
        );
        assert_eq!(llm.api_key_ref, None);
        assert_eq!((llm.transcribe_endpoint, llm.transcribe_model), (None, None));
        assert_eq!(
            cfg.search,
            Some(SearchSettings::Searxng {
                endpoint: "http://sx:8080".to_owned(),
                engines: vec!["google".to_owned(), "bing".to_owned()],
                categories: vec!["general".to_owned()],
            })
        );
    }

    #[test]
    fn transcribe_variables_and_settings_reach_the_client_config() {
        let cfg = IntelConfig::default()
            .from_lookup(env(&[
                ("OPENAI_BASE_URL", "http://ollama:11434/v1"),
                ("OPENAI_TRANSCRIBE_ENDPOINT", "http://whisper:8000/v1"),
                ("TRANSCRIBE_MODEL_NAME", "large-v3"),
            ]))
            .unwrap();
        let llm = cfg.llm.unwrap();
        assert_eq!(llm.transcribe_endpoint.as_deref(), Some("http://whisper:8000/v1"));
        assert_eq!(llm.transcribe_model.as_deref(), Some("large-v3"));
        let client = llm.resolve_with(env(&[])).unwrap();
        assert_eq!(
            client.transcribe_endpoint.as_deref(),
            Some("http://whisper:8000/v1")
        );
        assert_eq!(client.transcribe_model.as_deref(), Some("large-v3"));
        // camelCase in the config file; absent keys stay absent when written back
        let parsed: LlmSettings = serde_json::from_value(serde_json::json!({
            "endpoint": "http://h/v1", "model": "m", "transcribeEndpoint": "http://w/v1"
        }))
        .unwrap();
        assert_eq!(parsed.transcribe_endpoint.as_deref(), Some("http://w/v1"));
        let plain = LlmSettings {
            transcribe_endpoint: None,
            ..parsed
        };
        assert!(serde_json::to_value(&plain)
            .unwrap()
            .get("transcribeEndpoint")
            .is_none());
    }

    #[test]
    fn ollama_base_url_selects_its_openai_compatible_endpoint() {
        let cfg = IntelConfig::default()
            .from_lookup(env(&[("OLLAMA_BASE_URL", "http://ollama:11434/")]))
            .unwrap();
        assert_eq!(cfg.llm.unwrap().endpoint, "http://ollama:11434/v1");
        let both = IntelConfig::default()
            .from_lookup(env(&[
                ("OLLAMA_BASE_URL", "http://ollama:11434"),
                ("OPENAI_BASE_URL", "http://other/v1"),
            ]))
            .unwrap();
        assert_eq!(
            both.llm.unwrap().endpoint,
            "http://other/v1",
            "OPENAI_BASE_URL wins"
        );
    }

    #[test]
    fn explicit_settings_win_and_searchapi_is_second_choice() {
        let explicit = IntelConfig {
            llm: Some(LlmSettings {
                endpoint: "http://x/v1".to_owned(),
                model: "m".to_owned(),
                api_key_ref: None,
                timeout_ms: Some(5),
                transcribe_endpoint: None,
                transcribe_model: None,
            }),
            ..IntelConfig::default()
        };
        let cfg = explicit
            .clone()
            .from_lookup(env(&[("OPENAI_API_KEY", "k"), ("SEARCHAPI_API_KEY", "s")]))
            .unwrap();
        assert_eq!(cfg.llm, explicit.llm);
        assert_eq!(
            cfg.search,
            Some(SearchSettings::SearchApi {
                api_key_ref: "env:SEARCHAPI_API_KEY".to_owned(),
                engine: "google".to_owned(),
                endpoint: None
            })
        );
        assert_eq!(
            IntelConfig::default().from_lookup(env(&[])).unwrap(),
            IntelConfig::default()
        );
    }

    #[test]
    fn secret_references_resolve_and_fail_typed() {
        assert_eq!(
            resolve_secret_ref_with("env:K", env(&[("K", " v \n")])).unwrap(),
            "v"
        );
        assert!(matches!(
            resolve_secret_ref_with("env:MISSING", env(&[])),
            Err(SecretRefError::EnvMissing(n)) if n == "MISSING"
        ));
        assert!(matches!(
            resolve_secret_ref_with("vault://x", env(&[])),
            Err(SecretRefError::Scheme(_))
        ));
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k");
        std::fs::write(&p, "sekret\n").unwrap();
        assert_eq!(
            resolve_secret_ref_with(&format!("file:{}", p.display()), env(&[])).unwrap(),
            "sekret"
        );
        assert!(matches!(
            resolve_secret_ref_with("file:/definitely/not/here", env(&[])),
            Err(SecretRefError::File { .. })
        ));
        let llm = LlmSettings {
            endpoint: "http://h/v1".to_owned(),
            model: "m".to_owned(),
            api_key_ref: Some("env:K".to_owned()),
            timeout_ms: Some(1500),
            transcribe_endpoint: None,
            transcribe_model: None,
        };
        let cfg = llm.resolve_with(env(&[("K", "abc")])).unwrap();
        assert_eq!(cfg.timeout, Duration::from_millis(1500));
        assert_eq!(cfg.api_key.unwrap().expose(), "abc");
    }
}
