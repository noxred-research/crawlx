//! Per-step provider settings of the LLM products, read from the self-host environment
//! variables existing deployments of the compatibility API already set:
//!
//! * [`EmbeddingSettings`]: `CRAWLX_EMBEDDING_MODEL` (the embedding model of the page ranker, served
//!   by the default LLM's chat-completions compatible endpoint and key unless overridden);
//! * [`ExtractionSettings`]: `EXTRACTION_PROVIDER_*` (a second chat-completions compatible endpoint for the
//!   JSON-extraction step: `/extract` and the `json` format);
//! * [`BrandingSettings`]: `BRANDING_LLM_*` and `BRANDING_JEV_TIMEOUT_MS` (the LLM that refines the
//!   markup-derived `branding` profile).
//!
//! Secrets are never stored here, only references (`env:NAME` / `file:/path`), so none of these
//! types can leak a key through `Debug`, serialisation or `crawlx config check`.

use super::{resolve_secret_ref_with, LlmSettings, SecretRefError};
use crawlx_core::secret::SecretOr;
use crawlx_model::llm::chat_completions::{LlmConfig, DEFAULT_ENDPOINT, DEFAULT_MODEL};
use crawlx_model::llm::embeddings::EmbeddingsConfig;
use crawlx_model::llm::routing::{ExtractionPolicy, PolicyError, DEFAULT_MAX_INPUT_BYTES};
use std::str::FromStr;
use std::time::Duration;

/// Model of the extraction provider when `EXTRACTION_PROVIDER_MODEL` is unset (upstream default).
pub const DEFAULT_EXTRACTION_MODEL: &str = "extraction-v1";
/// Pages the LLM receives after embedding ranking when `EXTRACT_EMBEDDING_TOP_N` is unset.
pub const DEFAULT_TOP_N: usize = 10;
/// Time budget of one branding refinement call when `BRANDING_JEV_TIMEOUT_MS` is unset
/// (upstream default of the branding call).
pub const DEFAULT_BRANDING_TIMEOUT_MS: u64 = 5_000;

/// Self-host variables of the reference service that crawlx reads but cannot act on, with the reason (shown by
/// `crawlx config check` when one is set).
pub const UNSUPPORTED_ENV: [(&str, &str); 6] = [
    (
        "TYPESAFE_API_KEY", // wire-compat: variable name of the reference self-host configuration
        "a hosted classifier API without a self-hostable endpoint; crawlx has no client for it",
    ),
    (
        "BRANDING_JEV",
        "crawlx has no hosted-classifier backend, so branding always goes to the BRANDING_LLM_* model (upstream's BRANDING_JEV=false) when one is configured",
    ),
    (
        "BRANDING_JEV_SCREENSHOT_PERCENT",
        "no first-screen screenshot is sent to a model: crawlx's LLM client is text-only",
    ),
    (
        "EXTRACTION_PROVIDER_REQUEST_OPT_IN",
        "the json format and /extract carry no per-request `model`; routing is by EXTRACTION_PROVIDER_TEAM_IDS and ROLLOUT_PERCENT",
    ),
    (
        "EXTRACTION_PROVIDER_INPUT_COST_PER_MTOK",
        "crawlx meters tokens and credits, not currency",
    ),
    (
        "EXTRACTION_PROVIDER_OUTPUT_COST_PER_MTOK",
        "crawlx meters tokens and credits, not currency",
    ),
];

/// A provider variable that cannot be used.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvError {
    /// A numeric variable does not hold what it accepts. The text found is not reported: a
    /// mistyped variable may hold a secret.
    #[error("{var} must be {expected}")]
    Number {
        /// Variable name.
        var: &'static str,
        /// What the variable accepts.
        expected: &'static str,
    },
    /// The extraction routing shares are inconsistent.
    #[error("EXTRACTION_PROVIDER_*: {0}")]
    Policy(#[from] PolicyError),
}

/// The embedding model that ranks the pages of an `/extract` job against its prompt
/// (`CRAWLX_EMBEDDING_MODEL`).
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EmbeddingSettings {
    /// Embedding model name.
    pub model: String,
    /// chat-completions compatible base URL; `None` uses the default LLM's endpoint.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Reference to the API key (`env:NAME` or `file:/path`); `None` uses the default LLM's key.
    #[serde(default)]
    pub api_key_ref: Option<String>,
    /// Time budget of one embeddings request, milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Pages kept after ranking (`EXTRACT_EMBEDDING_TOP_N`, default [`DEFAULT_TOP_N`]).
    #[serde(default = "default_top_n")]
    pub top_n: usize,
}

const fn default_top_n() -> usize {
    DEFAULT_TOP_N
}

impl EmbeddingSettings {
    /// The client configuration these settings describe, inheriting the endpoint and key of the
    /// default LLM `llm` where unset.
    ///
    /// # Errors
    /// [`SecretRefError`] when the key reference cannot be resolved.
    pub fn resolve_with(
        &self,
        llm: Option<&LlmSettings>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<EmbeddingsConfig, SecretRefError> {
        let endpoint = self
            .endpoint
            .as_deref()
            .or_else(|| llm.map(|l| l.endpoint.as_str()))
            .unwrap_or(DEFAULT_ENDPOINT);
        let mut cfg = EmbeddingsConfig::new(endpoint, &self.model);
        let key_ref = self
            .api_key_ref
            .as_ref()
            .or_else(|| llm.and_then(|l| l.api_key_ref.as_ref()));
        if let Some(r) = key_ref {
            cfg.api_key = Some(SecretOr::secret(resolve_secret_ref_with(r, env)?));
        }
        if let Some(ms) = self.timeout_ms {
            cfg.timeout = Duration::from_millis(ms);
        }
        Ok(cfg)
    }

    /// [`Self::resolve_with`] over the process environment.
    ///
    /// # Errors
    /// As [`Self::resolve_with`].
    pub fn resolve(&self, llm: Option<&LlmSettings>) -> Result<EmbeddingsConfig, SecretRefError> {
        self.resolve_with(llm, |k| std::env::var(k).ok())
    }
}

/// A second chat-completions compatible endpoint for the JSON-extraction step (`EXTRACTION_PROVIDER_*`).
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExtractionSettings {
    /// chat-completions compatible base URL or full `chat/completions` URL (`EXTRACTION_PROVIDER_BASE_URL`).
    pub endpoint: String,
    /// Model name sent with every request (`EXTRACTION_PROVIDER_MODEL`).
    pub model: String,
    /// Reference to the API key (`env:EXTRACTION_PROVIDER_API_KEY`); `None` sends no credential.
    #[serde(default)]
    pub api_key_ref: Option<String>,
    /// Time budget of one call, milliseconds.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Share of tenants (0 to 100) routed to the provider (`EXTRACTION_PROVIDER_ROLLOUT_PERCENT`).
    #[serde(default)]
    pub rollout_percent: u8,
    /// Share of tenants mirrored without using the answer (`EXTRACTION_PROVIDER_SHADOW_PERCENT`).
    #[serde(default)]
    pub shadow_percent: u8,
    /// Tenants always routed (`EXTRACTION_PROVIDER_TEAM_IDS`): tenant UUIDs.
    #[serde(default)]
    pub team_ids: Vec<String>,
    /// Larger inputs stay on the default model (`EXTRACTION_PROVIDER_MAX_INPUT_BYTES`).
    #[serde(default = "default_max_input_bytes")]
    pub max_input_bytes: usize,
}

const fn default_max_input_bytes() -> usize {
    DEFAULT_MAX_INPUT_BYTES
}

impl ExtractionSettings {
    /// The client configuration of the provider endpoint.
    ///
    /// # Errors
    /// [`SecretRefError`] when the key reference cannot be resolved.
    pub fn resolve_with(&self, env: impl Fn(&str) -> Option<String>) -> Result<LlmConfig, SecretRefError> {
        let mut cfg = LlmConfig::new(&self.endpoint, &self.model);
        if let Some(r) = &self.api_key_ref {
            cfg.api_key = Some(SecretOr::secret(resolve_secret_ref_with(r, env)?));
        }
        if let Some(ms) = self.timeout_ms {
            cfg.timeout = Duration::from_millis(ms);
        }
        Ok(cfg)
    }

    /// [`Self::resolve_with`] over the process environment.
    ///
    /// # Errors
    /// As [`Self::resolve_with`].
    pub fn resolve(&self) -> Result<LlmConfig, SecretRefError> {
        self.resolve_with(|k| std::env::var(k).ok())
    }

    /// The routing policy.
    ///
    /// # Errors
    /// [`PolicyError`] for a share above 100 or shares adding up past 100.
    pub fn policy(&self) -> Result<ExtractionPolicy, PolicyError> {
        ExtractionPolicy::new(
            self.rollout_percent,
            self.shadow_percent,
            self.team_ids.iter().cloned(),
            self.max_input_bytes,
        )
    }
}

/// The LLM that refines the markup-derived `branding` profile (`BRANDING_LLM_*`). Every unset
/// field inherits the default LLM's.
#[derive(Clone, PartialEq, Eq, Default, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BrandingSettings {
    /// chat-completions compatible base URL (`BRANDING_LLM_BASE_URL`).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Model name (`BRANDING_LLM_MODEL`).
    #[serde(default)]
    pub model: Option<String>,
    /// Reference to the API key (`env:BRANDING_LLM_API_KEY`).
    #[serde(default)]
    pub api_key_ref: Option<String>,
    /// Time budget of one refinement call, milliseconds (`BRANDING_JEV_TIMEOUT_MS`, default
    /// [`DEFAULT_BRANDING_TIMEOUT_MS`]).
    #[serde(default)]
    pub timeout_ms: Option<u64>,
}

impl BrandingSettings {
    /// The client configuration, inheriting what is unset from the default LLM `llm`.
    ///
    /// # Errors
    /// [`SecretRefError`] when the key reference cannot be resolved.
    pub fn resolve_with(
        &self,
        llm: Option<&LlmSettings>,
        env: impl Fn(&str) -> Option<String>,
    ) -> Result<LlmConfig, SecretRefError> {
        let endpoint = self
            .endpoint
            .as_deref()
            .or_else(|| llm.map(|l| l.endpoint.as_str()))
            .unwrap_or(DEFAULT_ENDPOINT);
        let model = self
            .model
            .as_deref()
            .or_else(|| llm.map(|l| l.model.as_str()))
            .unwrap_or(DEFAULT_MODEL);
        let mut cfg = LlmConfig::new(endpoint, model);
        let key_ref = self
            .api_key_ref
            .as_ref()
            .or_else(|| llm.and_then(|l| l.api_key_ref.as_ref()));
        if let Some(r) = key_ref {
            cfg.api_key = Some(SecretOr::secret(resolve_secret_ref_with(r, env)?));
        }
        cfg.timeout = Duration::from_millis(self.timeout_ms.unwrap_or(DEFAULT_BRANDING_TIMEOUT_MS));
        Ok(cfg)
    }

    /// [`Self::resolve_with`] over the process environment.
    ///
    /// # Errors
    /// As [`Self::resolve_with`].
    pub fn resolve(&self, llm: Option<&LlmSettings>) -> Result<LlmConfig, SecretRefError> {
        self.resolve_with(llm, |k| std::env::var(k).ok())
    }
}

fn number<T: FromStr>(
    get: &dyn Fn(&str) -> Option<String>,
    var: &'static str,
    expected: &'static str,
) -> Result<Option<T>, EnvError> {
    get(var)
        .map(|value| value.parse::<T>().map_err(|_| EnvError::Number { var, expected }))
        .transpose()
}

/// A percentage variable: `0` when unset, an error above 100.
fn percent(get: &dyn Fn(&str) -> Option<String>, var: &'static str) -> Result<u8, EnvError> {
    const EXPECTED: &str = "an integer from 0 to 100";
    match number::<u8>(get, var, EXPECTED)? {
        Some(n) if n > 100 => Err(EnvError::Number {
            var,
            expected: EXPECTED,
        }),
        Some(n) => Ok(n),
        None => Ok(0),
    }
}

/// Fill the unset provider sections of `intel` from `get` (trimmed, empty-as-unset lookups).
pub(super) fn fill(
    intel: &mut super::IntelConfig,
    get: &dyn Fn(&str) -> Option<String>,
) -> Result<(), EnvError> {
    if intel.embeddings.is_none() {
        if let Some(model) = get("CRAWLX_EMBEDDING_MODEL") {
            intel.embeddings = Some(EmbeddingSettings {
                model,
                endpoint: None,
                api_key_ref: None,
                timeout_ms: None,
                top_n: number::<usize>(get, "EXTRACT_EMBEDDING_TOP_N", "a positive integer")?
                    .filter(|n| *n > 0)
                    .unwrap_or(DEFAULT_TOP_N),
            });
        }
    }
    if intel.extraction.is_none() {
        if let Some(endpoint) = get("EXTRACTION_PROVIDER_BASE_URL") {
            let settings = ExtractionSettings {
                endpoint,
                model: get("EXTRACTION_PROVIDER_MODEL")
                    .unwrap_or_else(|| DEFAULT_EXTRACTION_MODEL.to_owned()),
                api_key_ref: get("EXTRACTION_PROVIDER_API_KEY")
                    .map(|_| "env:EXTRACTION_PROVIDER_API_KEY".to_owned()),
                timeout_ms: None,
                rollout_percent: percent(get, "EXTRACTION_PROVIDER_ROLLOUT_PERCENT")?,
                shadow_percent: percent(get, "EXTRACTION_PROVIDER_SHADOW_PERCENT")?,
                team_ids: get("EXTRACTION_PROVIDER_TEAM_IDS")
                    .map(|v| {
                        v.split(',')
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                max_input_bytes: number::<usize>(
                    get,
                    "EXTRACTION_PROVIDER_MAX_INPUT_BYTES",
                    "a non-negative integer",
                )?
                .unwrap_or(DEFAULT_MAX_INPUT_BYTES),
            };
            settings.policy()?;
            intel.extraction = Some(settings);
        }
    }
    if intel.branding.is_none() {
        let endpoint = get("BRANDING_LLM_BASE_URL");
        let model = get("BRANDING_LLM_MODEL");
        let key = get("BRANDING_LLM_API_KEY");
        if endpoint.is_some() || model.is_some() || key.is_some() {
            intel.branding = Some(BrandingSettings {
                endpoint,
                model,
                api_key_ref: key.map(|_| "env:BRANDING_LLM_API_KEY".to_owned()),
                timeout_ms: number::<u64>(
                    get,
                    "BRANDING_JEV_TIMEOUT_MS",
                    "a positive integer of milliseconds",
                )?
                .filter(|ms| *ms > 0),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::super::IntelConfig;
    use super::*;
    use std::collections::BTreeMap;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        let map: BTreeMap<&str, &str> = pairs.iter().copied().collect();
        move |k| map.get(k).map(|v| (*v).to_owned())
    }

    fn intel(pairs: &[(&str, &str)]) -> Result<IntelConfig, EnvError> {
        IntelConfig::default().from_lookup(env(pairs))
    }

    #[test]
    fn nothing_is_configured_without_the_variables() {
        let cfg = intel(&[("CRAWLX_LLM_API_KEY", "k"), ("CRAWLX_LLM_MODEL", "m")]).unwrap();
        assert!(cfg.embeddings.is_none() && cfg.extraction.is_none() && cfg.branding.is_none());
        // the model name alone (docker-compose passes empty values) is not a provider
        let cfg = intel(&[
            ("EXTRACTION_PROVIDER_BASE_URL", " "),
            ("CRAWLX_EMBEDDING_MODEL", ""),
        ])
        .unwrap();
        assert!(cfg.extraction.is_none() && cfg.embeddings.is_none());
    }

    #[test]
    fn embedding_name_enables_ranking_with_the_default_top_n() {
        let cfg = intel(&[("CRAWLX_EMBEDDING_MODEL", "embed-model")]).unwrap();
        assert_eq!(
            cfg.embeddings,
            Some(EmbeddingSettings {
                model: "embed-model".to_owned(),
                endpoint: None,
                api_key_ref: None,
                timeout_ms: None,
                top_n: DEFAULT_TOP_N,
            })
        );
        let cfg = intel(&[("CRAWLX_EMBEDDING_MODEL", "m"), ("EXTRACT_EMBEDDING_TOP_N", "3")]).unwrap();
        assert_eq!(cfg.embeddings.unwrap().top_n, 3);
        assert!(matches!(
            intel(&[
                ("CRAWLX_EMBEDDING_MODEL", "m"),
                ("EXTRACT_EMBEDDING_TOP_N", "many")
            ]),
            Err(EnvError::Number {
                var: "EXTRACT_EMBEDDING_TOP_N",
                ..
            })
        ));
    }

    #[test]
    fn embeddings_inherit_the_default_endpoint_and_key() {
        let cfg = intel(&[
            ("CRAWLX_LLM_BASE_URL", "http://local-llm:11434/v1"),
            ("CRAWLX_LLM_API_KEY", "sk-1"),
            ("CRAWLX_EMBEDDING_MODEL", "embed-model"),
        ])
        .unwrap();
        let resolved = cfg
            .embeddings
            .unwrap()
            .resolve_with(cfg.llm.as_ref(), env(&[("CRAWLX_LLM_API_KEY", "sk-1")]))
            .unwrap();
        assert_eq!(resolved.endpoint, "http://local-llm:11434/v1");
        assert_eq!(resolved.model, "embed-model");
        assert_eq!(resolved.api_key.unwrap().expose(), "sk-1");
        let own = EmbeddingSettings {
            model: "m".to_owned(),
            endpoint: Some("http://e/v1".to_owned()),
            api_key_ref: Some("env:E".to_owned()),
            timeout_ms: Some(900),
            top_n: 2,
        };
        let resolved = own.resolve_with(cfg.llm.as_ref(), env(&[("E", "own")])).unwrap();
        assert_eq!(resolved.endpoint, "http://e/v1");
        assert_eq!(resolved.api_key.unwrap().expose(), "own");
        assert_eq!(resolved.timeout, Duration::from_millis(900));
    }

    #[test]
    fn extraction_provider_variables_follow_upstream_names_and_defaults() {
        let cfg = intel(&[("EXTRACTION_PROVIDER_BASE_URL", "http://llm-server:8000/v1")]).unwrap();
        let x = cfg.extraction.unwrap();
        assert_eq!(x.endpoint, "http://llm-server:8000/v1");
        assert_eq!(x.model, "extraction-v1", "upstream default model");
        assert_eq!((x.rollout_percent, x.shadow_percent), (0, 0));
        assert_eq!(x.max_input_bytes, 400_000);
        assert!(x.api_key_ref.is_none() && x.team_ids.is_empty());

        let cfg = intel(&[
            ("EXTRACTION_PROVIDER_BASE_URL", "http://llm-server:8000/v1"),
            ("EXTRACTION_PROVIDER_MODEL", "extract-model"),
            ("EXTRACTION_PROVIDER_API_KEY", "ext-key"),
            ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "25"),
            ("EXTRACTION_PROVIDER_SHADOW_PERCENT", "10"),
            ("EXTRACTION_PROVIDER_TEAM_IDS", "a, b,,c"),
            ("EXTRACTION_PROVIDER_MAX_INPUT_BYTES", "1000"),
        ])
        .unwrap();
        let x = cfg.extraction.unwrap();
        assert_eq!(x.model, "extract-model");
        assert_eq!(x.api_key_ref.as_deref(), Some("env:EXTRACTION_PROVIDER_API_KEY"));
        assert_eq!(
            (x.rollout_percent, x.shadow_percent, x.max_input_bytes),
            (25, 10, 1000)
        );
        assert_eq!(x.team_ids, ["a", "b", "c"]);
        let resolved = x
            .resolve_with(env(&[("EXTRACTION_PROVIDER_API_KEY", "ext-key")]))
            .unwrap();
        assert_eq!(resolved.api_key.unwrap().expose(), "ext-key");
        assert_eq!(resolved.model, "extract-model");
    }

    #[test]
    fn extraction_provider_rejects_bad_shares() {
        let base = ("EXTRACTION_PROVIDER_BASE_URL", "http://x/v1");
        assert!(matches!(
            intel(&[base, ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "101")]),
            Err(EnvError::Number {
                var: "EXTRACTION_PROVIDER_ROLLOUT_PERCENT",
                ..
            })
        ));
        assert!(matches!(
            intel(&[base, ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "-1")]),
            Err(EnvError::Number { .. })
        ));
        assert!(matches!(
            intel(&[
                base,
                ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "70"),
                ("EXTRACTION_PROVIDER_SHADOW_PERCENT", "31")
            ]),
            Err(EnvError::Policy(PolicyError::Overlap {
                rollout: 70,
                shadow: 31
            }))
        ));
        assert!(matches!(
            intel(&[base, ("EXTRACTION_PROVIDER_MAX_INPUT_BYTES", "big")]),
            Err(EnvError::Number {
                var: "EXTRACTION_PROVIDER_MAX_INPUT_BYTES",
                ..
            })
        ));
    }

    #[test]
    fn branding_llm_overrides_inherit_the_default_llm() {
        let cfg = intel(&[
            ("CRAWLX_LLM_BASE_URL", "http://local-llm:11434/v1"),
            ("CRAWLX_LLM_API_KEY", "sk-1"),
            ("CRAWLX_LLM_MODEL", "chat-model"),
            ("BRANDING_LLM_MODEL", "vision-model"),
        ])
        .unwrap();
        let b = cfg.branding.clone().unwrap();
        assert_eq!(b.model.as_deref(), Some("vision-model"));
        assert!(b.endpoint.is_none() && b.api_key_ref.is_none() && b.timeout_ms.is_none());
        let resolved = b
            .resolve_with(cfg.llm.as_ref(), env(&[("CRAWLX_LLM_API_KEY", "sk-1")]))
            .unwrap();
        assert_eq!(resolved.endpoint, "http://local-llm:11434/v1");
        assert_eq!(resolved.model, "vision-model");
        assert_eq!(resolved.api_key.unwrap().expose(), "sk-1");
        assert_eq!(
            resolved.timeout,
            Duration::from_millis(5_000),
            "upstream branding timeout default"
        );
    }

    #[test]
    fn branding_endpoint_key_and_timeout_come_from_their_variables() {
        let cfg = intel(&[
            ("BRANDING_LLM_BASE_URL", "http://b/v1"),
            ("BRANDING_LLM_API_KEY", "bk"),
            ("BRANDING_JEV_TIMEOUT_MS", "1500"),
        ])
        .unwrap();
        let b = cfg.branding.unwrap();
        let resolved = b
            .resolve_with(None, env(&[("BRANDING_LLM_API_KEY", "bk")]))
            .unwrap();
        assert_eq!(resolved.endpoint, "http://b/v1");
        assert_eq!(resolved.model, DEFAULT_MODEL);
        assert_eq!(resolved.api_key.unwrap().expose(), "bk");
        assert_eq!(resolved.timeout, Duration::from_millis(1500));
        assert!(matches!(
            intel(&[("BRANDING_LLM_MODEL", "m"), ("BRANDING_JEV_TIMEOUT_MS", "soon")]),
            Err(EnvError::Number {
                var: "BRANDING_JEV_TIMEOUT_MS",
                ..
            })
        ));
        // the timeout variable alone configures no branding model
        assert!(intel(&[("BRANDING_JEV_TIMEOUT_MS", "1500")])
            .unwrap()
            .branding
            .is_none());
    }

    #[test]
    fn explicit_settings_win_over_the_environment() {
        let explicit = IntelConfig {
            extraction: Some(ExtractionSettings {
                endpoint: "http://own/v1".to_owned(),
                model: "own".to_owned(),
                api_key_ref: None,
                timeout_ms: None,
                rollout_percent: 100,
                shadow_percent: 0,
                team_ids: Vec::new(),
                max_input_bytes: 5,
            }),
            ..IntelConfig::default()
        };
        let cfg = explicit
            .clone()
            .from_lookup(env(&[("EXTRACTION_PROVIDER_BASE_URL", "http://env/v1")]))
            .unwrap();
        assert_eq!(cfg.extraction, explicit.extraction);
    }

    #[test]
    fn unsupported_variables_name_their_reason() {
        let names: Vec<&str> = UNSUPPORTED_ENV.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"TYPESAFE_API_KEY") && names.contains(&"BRANDING_JEV")); // wire-compat: reference self-host variable names
        assert!(UNSUPPORTED_ENV.iter().all(|(_, why)| !why.is_empty()));
    }
}
