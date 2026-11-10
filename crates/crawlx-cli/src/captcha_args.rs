//! Opt-in captcha solver flags and process-local credential handoff.

use anyhow::{bail, Context as _};
use clap::Args;
use crawlx_core::captcha::{CaptchaConfig, CaptchaProvider};
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{CoreError, CreateCrawl, SystemClock};
use crawlx_worker::ChainResolver;
use std::sync::Arc;
use url::Url;

/// Reference reserved for the CLI's process-local solver key, never its value.
const LOCAL_KEY_REF: &str = "env://CRAWLX_CAPTCHA_SOLVER_KEY";

/// Optional captcha solver settings. A key alone never enables solving.
#[derive(Args, Debug, Clone, Default)]
#[command(next_help_heading = "Captcha")]
pub struct CaptchaArgs {
    /// Solver provider (task-api: a task-based captcha-solving HTTP API). Solving stays disabled unless explicitly configured.
    #[arg(
        long,
        value_name = "PROVIDER",
        env = "CAPTCHA_SOLVER_PROVIDER",
        value_parser = parse_provider
    )]
    pub captcha_solver_provider: Option<CaptchaProvider>,
    /// Solver API key, held only in process memory. An explicit key reference takes precedence.
    #[arg(
        long,
        value_name = "KEY",
        env = "CAPTCHA_SOLVER_KEY",
        hide_env_values = true,
        value_parser = parse_key
    )]
    pub captcha_solver_key: Option<SecretOr<String>>,
    /// Existing env://VAR or file:///absolute/path credential reference, not a literal key.
    #[arg(long, value_name = "REF")]
    pub captcha_solver_key_ref: Option<String>,
    /// Solver endpoint (HTTPS; explicit HTTP IP-loopback endpoints are allowed for fixtures).
    #[arg(long, value_name = "URL")]
    pub captcha_solver_endpoint: Option<Url>,
    /// Whole-solve deadline in seconds (default 120).
    #[arg(long, value_name = "SECONDS")]
    pub captcha_solver_timeout_seconds: Option<u64>,
    /// Poll interval in milliseconds (default 1000).
    #[arg(long, value_name = "MS")]
    pub captcha_solver_poll_interval_ms: Option<u64>,
}

fn parse_provider(value: &str) -> Result<CaptchaProvider, &'static str> {
    match value {
        "task-api" => Ok(CaptchaProvider::TaskApi),
        _ => Err("unsupported captcha solver provider (expected task-api)"),
    }
}

fn parse_key(value: &str) -> Result<SecretOr<String>, std::convert::Infallible> {
    Ok(SecretOr::secret(value.to_owned()))
}

impl CaptchaArgs {
    /// Fill absent flags from a lower-priority configuration layer.
    pub(crate) fn fill_from(&mut self, lower: Self) {
        use crate::merge::fill;
        let Self {
            captcha_solver_provider,
            captcha_solver_key,
            captcha_solver_key_ref,
            captcha_solver_endpoint,
            captcha_solver_timeout_seconds,
            captcha_solver_poll_interval_ms,
        } = lower;
        fill(&mut self.captcha_solver_provider, captcha_solver_provider);
        // A credential is one setting: never combine a higher-priority key with a lower ref.
        if self.captcha_solver_key.is_none() && self.captcha_solver_key_ref.is_none() {
            self.captcha_solver_key = captcha_solver_key;
            self.captcha_solver_key_ref = captcha_solver_key_ref;
        }
        fill(&mut self.captcha_solver_endpoint, captcha_solver_endpoint);
        fill(
            &mut self.captcha_solver_timeout_seconds,
            captcha_solver_timeout_seconds,
        );
        fill(
            &mut self.captcha_solver_poll_interval_ms,
            captcha_solver_poll_interval_ms,
        );
    }

    /// Apply non-secret settings while keeping literal keys out of the request.
    ///
    /// # Errors
    /// Missing provider/key, empty keys, unsupported references or invalid solver settings.
    pub(crate) fn apply(&self, crawl: &mut CreateCrawl) -> anyhow::Result<()> {
        if self
            .captcha_solver_key_ref
            .as_deref()
            .is_some_and(|reference| !reference.starts_with("env://") && !reference.starts_with("file://"))
        {
            bail!("--captcha-solver-key-ref requires an env:// or file:// reference");
        }
        let mut key_ref = self
            .captcha_solver_key_ref
            .as_ref()
            .map(|reference| CredentialRef(reference.clone()))
            .or_else(|| {
                self.captcha_solver_key
                    .as_ref()
                    .map(|_| CredentialRef(LOCAL_KEY_REF.to_owned()))
            });
        let provider = self
            .captcha_solver_provider
            .or_else(|| crawl.crawl.captcha.as_ref().map(|config| config.provider));
        let Some(provider) = provider else {
            if self.captcha_solver_key_ref.is_some()
                || self.captcha_solver_endpoint.is_some()
                || self.captcha_solver_timeout_seconds.is_some()
                || self.captcha_solver_poll_interval_ms.is_some()
            {
                bail!("captcha solver settings require --captcha-solver-provider");
            }
            // An ambient CAPTCHA_SOLVER_KEY does not opt a crawl into a paid service.
            return Ok(());
        };
        if self.captcha_solver_key_ref.is_none()
            && self
                .captcha_solver_key
                .as_ref()
                .is_some_and(|key| key.expose().trim().is_empty())
        {
            bail!("captcha solver key must not be empty");
        }
        let mut config = match crawl.crawl.captcha.take() {
            Some(config) => config,
            None => CaptchaConfig::new(
                provider,
                key_ref.take().context(
                    "captcha solver provider requires --captcha-solver-key or --captcha-solver-key-ref",
                )?,
            ),
        };
        config.provider = provider;
        if let Some(reference) = key_ref {
            config.key_ref = reference;
        }
        if let Some(endpoint) = &self.captcha_solver_endpoint {
            config.endpoint.clone_from(endpoint);
        }
        if let Some(seconds) = self.captcha_solver_timeout_seconds {
            config.timeout_seconds = seconds;
        }
        if let Some(milliseconds) = self.captcha_solver_poll_interval_ms {
            config.poll_interval_ms = milliseconds;
        }
        config.validate()?;
        crawl.crawl.captcha = Some(config);
        Ok(())
    }

    /// Overlay a literal flag/environment key on the normal worker resolver chain.
    pub(crate) async fn resolver(&self) -> Option<Arc<dyn SecretResolver>> {
        if self.captcha_solver_key_ref.is_some() {
            return None;
        }
        let key = self.captcha_solver_key.as_ref()?;
        Some(Arc::new(LocalKeyResolver {
            key: key.clone(),
            fallback: Arc::new(ChainResolver::from_env(Arc::new(SystemClock)).await),
        }))
    }
}

/// This overlay exists only for this invocation. Request serialization contains its marker only.
struct LocalKeyResolver {
    key: SecretOr<String>,
    fallback: Arc<dyn SecretResolver>,
}

#[async_trait::async_trait]
impl SecretResolver for LocalKeyResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        if reference.0 == LOCAL_KEY_REF {
            Ok(self.key.clone())
        } else {
            self.fallback.resolve(reference).await
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn request() -> CreateCrawl {
        CreateCrawl::new(Url::parse("https://example.test/").unwrap())
    }

    fn configured() -> CaptchaArgs {
        CaptchaArgs {
            captcha_solver_provider: Some(CaptchaProvider::TaskApi),
            captcha_solver_key: Some(SecretOr::secret("captcha-key-canary".to_owned())),
            ..CaptchaArgs::default()
        }
    }

    #[test]
    fn solving_is_default_off_and_a_key_alone_does_not_enable_it() {
        let mut crawl = request();
        CaptchaArgs::default().apply(&mut crawl).unwrap();
        assert!(crawl.crawl.captcha.is_none());
        let mut args = configured();
        args.captcha_solver_provider = None;
        args.apply(&mut crawl).unwrap();
        assert!(crawl.crawl.captcha.is_none());
    }

    #[test]
    fn literal_key_never_enters_request_serialization_or_debug() {
        let args = configured();
        let mut crawl = request();
        args.apply(&mut crawl).unwrap();
        let config = crawl.crawl.captcha.as_ref().unwrap();
        assert_eq!(config.key_ref.0, LOCAL_KEY_REF);
        assert_eq!(config.endpoint.as_str(), "https://api.capsolver.com/"); // wire-compat: default task-API service endpoint
        assert_eq!(config.timeout_seconds, 120);
        assert_eq!(config.poll_interval_ms, 1000);
        for text in [
            format!("{args:?}"),
            format!("{crawl:?}"),
            serde_json::to_string(&crawl).unwrap(),
        ] {
            assert!(!text.contains("captcha-key-canary"), "{text}");
        }
    }

    #[test]
    fn provider_requires_a_key_and_invalid_settings_fail() {
        let mut args = configured();
        args.captcha_solver_key = None;
        assert!(args.apply(&mut request()).is_err());
        args.captcha_solver_key = Some(SecretOr::secret(String::new()));
        assert!(args.apply(&mut request()).is_err());
        args.captcha_solver_key = Some(SecretOr::secret("canary".to_owned()));
        args.captcha_solver_endpoint = Some(Url::parse("http://solver.example/").unwrap());
        assert!(args.apply(&mut request()).is_err());
        args.captcha_solver_endpoint = Some(Url::parse("http://127.0.0.1:12345/").unwrap());
        args.apply(&mut request()).unwrap();
        args.captcha_solver_timeout_seconds = Some(0);
        assert!(args.apply(&mut request()).is_err());
        args.captcha_solver_timeout_seconds = Some(120);
        args.captcha_solver_poll_interval_ms = Some(0);
        assert!(args.apply(&mut request()).is_err());
    }

    #[test]
    fn credential_layers_do_not_combine_a_key_with_a_lower_reference() {
        let mut args = configured();
        let lower = CaptchaArgs {
            captcha_solver_key_ref: Some("env://LOWER_KEY".to_owned()),
            captcha_solver_timeout_seconds: Some(45),
            ..CaptchaArgs::default()
        };
        args.fill_from(lower);
        assert!(args.captcha_solver_key_ref.is_none());
        let mut crawl = request();
        args.apply(&mut crawl).unwrap();
        let config = crawl.crawl.captcha.unwrap();
        assert_eq!(config.key_ref.0, LOCAL_KEY_REF);
        assert_eq!(config.timeout_seconds, 45);
    }

    #[test]
    fn explicit_reference_overrides_an_ambient_key() {
        let mut args = configured();
        args.captcha_solver_key_ref = Some("env://EXPLICIT_KEY".to_owned());
        let mut crawl = request();
        args.apply(&mut crawl).unwrap();
        assert_eq!(crawl.crawl.captcha.unwrap().key_ref.0, "env://EXPLICIT_KEY");
    }

    struct Fallback;

    #[async_trait::async_trait]
    impl SecretResolver for Fallback {
        async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
            assert_eq!(reference.0, "env://OTHER_KEY");
            Ok(SecretOr::secret("other-secret".to_owned()))
        }
    }

    #[tokio::test]
    async fn transient_key_resolver_preserves_normal_credential_resolution() {
        let resolver = LocalKeyResolver {
            key: SecretOr::secret("captcha-key-canary".to_owned()),
            fallback: Arc::new(Fallback),
        };
        let key = resolver
            .resolve(&CredentialRef(LOCAL_KEY_REF.to_owned()))
            .await
            .unwrap();
        assert!(key.is_secret());
        assert_eq!(key.expose(), "captcha-key-canary");
        let other = resolver
            .resolve(&CredentialRef("env://OTHER_KEY".to_owned()))
            .await
            .unwrap();
        assert_eq!(other.expose(), "other-secret");
    }
}
