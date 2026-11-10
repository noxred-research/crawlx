//! Opt-in CAPTCHA solver settings and secret-safe browser boundary types.

use crate::secret::{CredentialRef, SecretOr};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

/// External CAPTCHA solving service. Unknown providers are rejected by serde.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CaptchaProvider {
    /// A task-based captcha-solving HTTP API.
    TaskApi,
}

/// Durable solver settings. The API key itself must never enter configuration.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CaptchaConfig {
    /// Explicit provider selection.
    pub provider: CaptchaProvider,
    /// Reference resolved immediately before browser use, not a literal key.
    pub key_ref: CredentialRef,
    /// HTTPS service base URL; HTTP IP-loopback URLs are allowed for fixtures.
    #[serde(default = "default_endpoint")]
    pub endpoint: Url,
    /// Deadline covering task creation, polling, and all response bodies.
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    /// Delay before each result poll.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
}

const fn default_timeout() -> u64 {
    120
}

const fn default_poll_interval() -> u64 {
    1000
}

#[allow(clippy::expect_used, reason = "the built-in endpoint is a valid constant URL")]
fn default_endpoint() -> Url {
    Url::parse("https://api.capsolver.com/").expect("valid built-in captcha endpoint")
    // wire-compat: default task-API service endpoint
}

impl CaptchaConfig {
    /// Settings with the default endpoint, 120-second deadline, and 1-second polling.
    #[must_use]
    pub fn new(provider: CaptchaProvider, key_ref: CredentialRef) -> Self {
        Self {
            provider,
            key_ref,
            endpoint: default_endpoint(),
            timeout_seconds: default_timeout(),
            poll_interval_ms: default_poll_interval(),
        }
    }

    /// Check endpoint, explicit credential reference, and finite timing bounds.
    ///
    /// # Errors
    /// Returns [`CaptchaError::Configuration`] for invalid settings.
    pub fn validate(&self) -> Result<(), CaptchaError> {
        let Some((scheme, reference)) = self.key_ref.0.split_once("://") else {
            return Err(CaptchaError::Configuration);
        };
        if !matches!(scheme, "env" | "file" | "vault" | "k8s")
            || reference.is_empty()
            || self.key_ref.0.chars().any(char::is_whitespace)
            || self.key_ref.0.chars().any(char::is_control)
        {
            return Err(CaptchaError::Configuration);
        }
        let loopback = match self.endpoint.host() {
            Some(Host::Ipv4(ip)) => ip.is_loopback(),
            Some(Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
        if self.endpoint.host().is_none()
            || !(self.endpoint.scheme() == "https" || (self.endpoint.scheme() == "http" && loopback))
            || !self.endpoint.username().is_empty()
            || self.endpoint.password().is_some()
            || self.endpoint.query().is_some()
            || self.endpoint.fragment().is_some()
            || !(1..=600).contains(&self.timeout_seconds)
            || !(1..=60_000).contains(&self.poll_interval_ms)
            || self.poll_interval_ms >= self.timeout_seconds.saturating_mul(1000)
        {
            return Err(CaptchaError::Configuration);
        }
        Ok(())
    }
}

/// Runtime-only solver credentials, excluded from serialized configuration.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CaptchaCredentials {
    /// Validated durable settings.
    pub config: CaptchaConfig,
    /// Resolved service key, always stored as a secret.
    pub key: SecretOr<String>,
}

impl CaptchaCredentials {
    /// Pair settings with a resolved key, promoting plain inputs to secrets.
    #[must_use]
    pub fn new(config: CaptchaConfig, key: SecretOr<String>) -> Self {
        let key = match key {
            SecretOr::Secret(_) => key,
            SecretOr::Plain(value) => SecretOr::secret(value),
        };
        Self { config, key }
    }
}

/// Browser challenge family, independent of the configured solving service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CaptchaKind {
    /// Checkbox widget, family A, version 2.
    CheckboxV2,
    /// Score-based widget, family A, version 3.
    ScoreV3,
    /// Enterprise edition of the checkbox widget, family A.
    CheckboxV2Enterprise,
    /// Enterprise edition of the score-based widget, family A.
    ScoreV3Enterprise,
    /// Challenge widget, family C.
    ChallengeWidgetT,
    /// Challenge widget, family B.
    ChallengeWidgetH,
}

/// Challenge metadata captured at the browser boundary.
#[derive(Clone)]
#[non_exhaustive]
pub struct CaptchaChallenge {
    /// Challenge family.
    pub kind: CaptchaKind,
    /// Page URL provided to the solver.
    pub website_url: String,
    /// Public widget site key.
    pub site_key: String,
    /// Optional widget page action (family A) or widget action (family C).
    pub action: Option<String>,
    /// Optional enterprise payload of the family A enterprise widget.
    pub enterprise_payload: Option<serde_json::Value>,
    /// Optional family C `cData`.
    pub data: Option<String>,
    /// Optional family C `chlPageData`.
    pub pagedata: Option<String>,
}

impl CaptchaChallenge {
    /// A challenge with no optional metadata.
    #[must_use]
    pub fn new(kind: CaptchaKind, website_url: String, site_key: String) -> Self {
        Self {
            kind,
            website_url,
            site_key,
            action: None,
            enterprise_payload: None,
            data: None,
            pagedata: None,
        }
    }
}

impl std::fmt::Debug for CaptchaChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaChallenge")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Bounded solver failures. Provider bodies and transport sources are intentionally
/// discarded: they can contain service keys, solution tokens, or page metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CaptchaError {
    /// Invalid durable settings or missing resolved key.
    #[error("invalid captcha configuration")]
    Configuration,
    /// Unsupported or incomplete browser challenge.
    #[error("unsupported captcha challenge")]
    UnsupportedChallenge,
    /// HTTP transport failed; task creation must not be retried.
    #[error("captcha transport failed")]
    Transport,
    /// The service rejected a task or returned an unsuccessful HTTP status.
    #[error("captcha service failed")]
    Service,
    /// The complete solve deadline elapsed.
    #[error("captcha solve timed out")]
    Timeout,
    /// The caller cancelled the solve.
    #[error("captcha solve cancelled")]
    Cancelled,
    /// Malformed, oversized, or unknown service response.
    #[error("invalid captcha response")]
    InvalidResponse,
    /// Browser token delivery failed.
    #[error("captcha token delivery failed")]
    Delivery,
    /// The safety kernel refused provider billing and callback delivery.
    #[error("captcha callback denied by safety policy")]
    PolicyDenied,
}

/// Shared runtime-only secret registry for browser and capture redaction.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct CaptchaSecrets(std::sync::Arc<std::sync::Mutex<Vec<SecretOr<String>>>>);

impl std::fmt::Debug for CaptchaSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptchaSecrets").finish_non_exhaustive()
    }
}

impl CaptchaSecrets {
    /// Register a key or token before it can enter browser-visible state.
    ///
    /// # Errors
    /// Returns [`CaptchaError::Delivery`] if the registry lock is poisoned.
    pub fn register(&self, value: SecretOr<String>) -> Result<(), CaptchaError> {
        let value = match value {
            SecretOr::Secret(_) => value,
            SecretOr::Plain(value) => SecretOr::secret(value),
        };
        let encoded: String = url::form_urlencoded::byte_serialize(value.expose().as_bytes()).collect();
        let mut values = self.0.lock().map_err(|_| CaptchaError::Delivery)?;
        for candidate in [value, SecretOr::secret(encoded)] {
            if !candidate.expose().is_empty()
                && !values.iter().any(|known| known.expose() == candidate.expose())
            {
                values.push(candidate);
            }
        }
        values.sort_by_key(|value| std::cmp::Reverse(value.expose().len()));
        Ok(())
    }

    /// Whether any key or token has been registered.
    ///
    /// # Errors
    /// Returns [`CaptchaError::Delivery`] if the registry lock is poisoned.
    pub fn has_values(&self) -> Result<bool, CaptchaError> {
        Ok(!self.0.lock().map_err(|_| CaptchaError::Delivery)?.is_empty())
    }

    /// Capture this scoped registry in a bounded, incremental literal scanner.
    ///
    /// This does not apply the global redactor's credential-shape, field-name,
    /// session-query or canonical-schema policies and cannot create `SecretFree`
    /// approval. Keep the existing typed approval boundary. Distributed callers
    /// must separately bind this snapshot's authority epoch to publication.
    ///
    /// # Errors
    /// Refuses a poisoned registry or a snapshot exceeding scanner bounds.
    pub fn scoped_byte_scanner(
        &self,
        mode: crate::secret::SecretScanMode,
        limits: crate::secret::SecretScanLimits,
    ) -> Result<crate::secret::SecretByteScanner, crate::secret::SecretScanError> {
        let values = self
            .0
            .lock()
            .map_err(|_| crate::secret::SecretScanError::Aborted)?;
        crate::secret::SecretByteScanner::from_literals(
            values.iter().map(|value| value.expose().as_bytes()),
            mode,
            limits,
        )
    }

    /// Replace every registered value in text with `[REDACTED]`.
    ///
    /// # Errors
    /// Returns [`CaptchaError::Delivery`] if the registry lock is poisoned.
    pub fn redact(&self, text: &str) -> Result<String, CaptchaError> {
        let values = self.0.lock().map_err(|_| CaptchaError::Delivery)?;
        Ok(redact_values(text, &values))
    }

    /// Borrow unchanged text, or redact registered values under one scoped snapshot.
    ///
    /// # Errors
    /// Returns `CaptchaError::Delivery` when the registry lock is poisoned.
    pub fn redact_if_present<'a>(&self, text: &'a str) -> Result<std::borrow::Cow<'a, str>, CaptchaError> {
        let values = self.0.lock().map_err(|_| CaptchaError::Delivery)?;
        if values
            .iter()
            .any(|value| !value.expose().is_empty() && text.contains(value.expose()))
        {
            Ok(std::borrow::Cow::Owned(redact_values(text, &values)))
        } else {
            Ok(std::borrow::Cow::Borrowed(text))
        }
    }

    /// Check opaque bytes and decoded JSON values without rewriting binary captures.
    /// Duplicate JSON members are ambiguous and treated as unsafe.
    ///
    /// # Errors
    /// Returns [`CaptchaError::Delivery`] when the scoped registry lock is poisoned.
    pub fn contains_bytes(&self, bytes: &[u8]) -> Result<bool, CaptchaError> {
        let values = self.0.lock().map_err(|_| CaptchaError::Delivery)?;
        if values.is_empty() {
            return Ok(false);
        }
        let contains = |bytes: &[u8]| {
            values.iter().any(|value| {
                let secret = value.expose().as_bytes();
                !secret.is_empty() && bytes.windows(secret.len()).any(|window| window == secret)
            })
        };
        Ok(crate::secret::contains_secret_bytes(bytes, contains))
    }

    /// Redact strings and object keys recursively, using one registry snapshot.
    ///
    /// # Errors
    /// Returns [`CaptchaError::Delivery`] if the registry lock is poisoned.
    pub fn redact_json(&self, value: &mut serde_json::Value) -> Result<(), CaptchaError> {
        let values = self.0.lock().map_err(|_| CaptchaError::Delivery)?;
        redact_json_values(value, &values);
        Ok(())
    }
}

fn redact_values(text: &str, values: &[SecretOr<String>]) -> String {
    let mut redacted = text.to_owned();
    for value in values {
        redacted = redacted.replace(value.expose(), "[REDACTED]");
    }
    redacted
}

fn redact_json_values(value: &mut serde_json::Value, values: &[SecretOr<String>]) {
    match value {
        serde_json::Value::String(text) => *text = redact_values(text, values),
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_values(item, values);
            }
        }
        serde_json::Value::Object(object) => {
            let original = std::mem::take(object);
            for (key, mut value) in original {
                redact_json_values(&mut value, values);
                object.insert(redact_values(&key, values), value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn defaults_are_opt_in_secret_references() {
        let config = CaptchaConfig::new(
            CaptchaProvider::TaskApi,
            CredentialRef("env://CAPTCHA_KEY".into()),
        );
        assert_eq!(config.endpoint.as_str(), "https://api.capsolver.com/"); // wire-compat: default task-API service endpoint
        assert_eq!(config.timeout_seconds, 120);
        assert_eq!(config.poll_interval_ms, 1000);
        assert_eq!(config.validate(), Ok(()));
        assert!(crate::config::CrawlConfig::default().captcha.is_none());
        assert!(serde_json::from_str::<CaptchaProvider>("\"unknown\"").is_err());
    }

    #[test]
    fn rejects_literal_keys_insecure_endpoints_and_invalid_timing() {
        let mut config = CaptchaConfig::new(CaptchaProvider::TaskApi, CredentialRef("literal-secret".into()));
        assert_eq!(config.validate(), Err(CaptchaError::Configuration));
        config.key_ref = CredentialRef("env://KEY".into());
        for endpoint in [
            "http://api.capsolver.com/", // wire-compat: default task-API service host
            "http://localhost/",
            "https://user:secret@example.com/",
            "https://example.com/?key=secret",
        ] {
            config.endpoint = Url::parse(endpoint).unwrap();
            assert_eq!(config.validate(), Err(CaptchaError::Configuration));
        }
        config.endpoint = Url::parse("http://127.0.0.1:1234/").unwrap();
        assert_eq!(config.validate(), Ok(()));
        config.timeout_seconds = 0;
        assert_eq!(config.validate(), Err(CaptchaError::Configuration));
        config.timeout_seconds = 120;
        config.poll_interval_ms = 0;
        assert_eq!(config.validate(), Err(CaptchaError::Configuration));
    }

    #[test]
    fn credentials_and_challenge_debug_are_redacted() {
        let config = CaptchaConfig::new(CaptchaProvider::TaskApi, CredentialRef("env://KEY".into()));
        let credentials = CaptchaCredentials::new(config, SecretOr::Plain("private-key".into()));
        assert!(credentials.key.is_secret());
        assert!(!format!("{credentials:?}").contains("private-key"));
        let challenge = CaptchaChallenge::new(
            CaptchaKind::ChallengeWidgetT,
            "https://example.com/?secret".into(),
            "site-key".into(),
        );
        assert!(!format!("{challenge:?}").contains("secret"));
    }

    #[test]
    fn shared_registry_redacts_tokens_keys_and_overlapping_values() {
        let registry = CaptchaSecrets::default();
        assert!(!registry.has_values().unwrap());
        registry.register(SecretOr::Plain("private".into())).unwrap();
        let shared = registry.clone();
        shared.register(SecretOr::secret("private-token".into())).unwrap();
        assert!(registry.has_values().unwrap());
        assert_eq!(
            registry.redact("private-token and private").unwrap(),
            "[REDACTED] and [REDACTED]"
        );
        let mut value = serde_json::json!({"private-token": ["prefix private-token", {"key": "private"}]});
        registry.redact_json(&mut value).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"[REDACTED]": ["prefix [REDACTED]", {"key": "[REDACTED]"}]})
        );
        assert!(!format!("{registry:?}").contains("private"));
    }

    #[test]
    fn invalid_captcha_settings_fail_crawl_normalization() {
        let mut request = crate::config::CreateCrawl::new(Url::parse("https://example.test/").unwrap());
        request.crawl.captcha = Some(CaptchaConfig::new(
            CaptchaProvider::TaskApi,
            CredentialRef("literal-private-key".into()),
        ));
        let errors = request.normalize().unwrap_err();
        assert!(errors.iter().any(|error| matches!(
            error,
            crate::error::CoreError::Invalid {
                field: "crawl.captcha",
                ..
            }
        )));
        assert!(!format!("{errors:?}").contains("literal-private-key"));
    }

    #[test]
    fn captcha_requires_enabled_dynamic_execution() {
        for (mode, enabled) in [
            (crate::config::CrawlMode::Static, true),
            (crate::config::CrawlMode::Hybrid, false),
        ] {
            let mut request = crate::config::CreateCrawl::new(Url::parse("https://example.test/").unwrap());
            request.mode = mode;
            request.dynamic.enabled = enabled;
            request.crawl.captcha = Some(CaptchaConfig::new(
                CaptchaProvider::TaskApi,
                CredentialRef("env://KEY".into()),
            ));
            assert!(request.normalize().unwrap_err().iter().any(|error| matches!(
                error,
                crate::error::CoreError::Invalid {
                    field: "crawl.captcha",
                    ..
                }
            )));
        }
    }

    #[test]
    fn registry_masks_percent_encoded_tokens_before_url_metadata_leaves_memory() {
        let registry = CaptchaSecrets::default();
        registry
            .register(SecretOr::secret("captcha+/=token".to_owned()))
            .unwrap();
        assert_eq!(
            registry
                .redact("https://app.test/verify?answer=captcha%2B%2F%3Dtoken")
                .unwrap(),
            "https://app.test/verify?answer=[REDACTED]"
        );
    }

    #[test]
    fn poisoned_registry_fails_closed_without_panicking() {
        let registry = CaptchaSecrets::default();
        let inner = std::sync::Arc::clone(&registry.0);
        let result = std::thread::spawn(move || {
            let _guard = inner.lock().unwrap();
            panic!("poison the registry");
        })
        .join();
        assert!(result.is_err());
        assert_eq!(registry.has_values(), Err(CaptchaError::Delivery));
        assert_eq!(registry.redact("private"), Err(CaptchaError::Delivery));
        assert_eq!(
            registry.register(SecretOr::secret("private".into())),
            Err(CaptchaError::Delivery)
        );
        let mut value = serde_json::json!("private");
        assert_eq!(registry.redact_json(&mut value), Err(CaptchaError::Delivery));
    }
}

#[cfg(test)]
mod projection_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn unchanged_projection_borrows_and_registered_tokens_are_removed() {
        let secrets = CaptchaSecrets::default();
        assert!(matches!(
            secrets.redact_if_present("ordinary text").unwrap(),
            std::borrow::Cow::Borrowed(_)
        ));
        secrets
            .register(SecretOr::secret("live-canary-token".into()))
            .unwrap();
        let projected = secrets
            .redact_if_present("prefix live-canary-token suffix")
            .unwrap();
        assert!(!projected.contains("live-canary-token"));
    }

    #[test]
    fn opaque_checks_find_scoped_bytes_and_decoded_json_without_lossy_projection() {
        let secrets = CaptchaSecrets::default();
        assert!(!secrets.contains_bytes(b"\xff\x00native binary").unwrap());
        secrets
            .register(SecretOr::secret("token-sensitive".into()))
            .unwrap();
        for bytes in [
            b"\xfftoken-sensitive\x00".as_slice(),
            br#"{"value":"token-\u0073ensitive"}"#,
            br#"{"token-\u0073ensitive":7}"#,
        ] {
            assert!(secrets.contains_bytes(bytes).unwrap());
        }
        assert!(!secrets.contains_bytes(b"\xff\x00safe native binary").unwrap());
    }

    #[test]
    fn duplicate_json_members_cannot_hide_scoped_secrets_from_byte_checks() {
        let secrets = CaptchaSecrets::default();
        secrets
            .register(SecretOr::secret("duplicate-scoped-canary-q7m2".into()))
            .unwrap();
        for bytes in [
            br#"{"data":"duplicate-scoped-\u0063anary-q7m2","data":"safe"}"#.as_slice(),
            br#"{"nested":{"data":"duplicate-scoped-\u0063anary-q7m2","data":"safe"}}"#,
        ] {
            assert!(secrets.contains_bytes(bytes).unwrap());
        }
    }

    #[test]
    fn poisoned_secret_registry_is_not_an_empty_successful_projection() {
        let secrets = CaptchaSecrets::default();
        let poisoned = secrets.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.0.lock().unwrap();
            panic!("poisoned registry fixture");
        })
        .join()
        .is_err());
        assert!(secrets.redact_if_present("ordinary text").is_err());
        assert!(secrets.contains_bytes(b"\xffsafe").is_err());
        assert!(secrets
            .redact_json(&mut serde_json::json!({"title":"content"}))
            .is_err());
    }
}
