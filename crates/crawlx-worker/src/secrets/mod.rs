//! Secret resolvers: a [`CredentialRef`] names a credential by
//! scheme, and [`ChainResolver`] dispatches on [`CredentialRef::scheme`] to one resolver
//! per scheme.
//!
//! | Scheme | Resolver | Reference shape |
//! |---|---|---|
//! | `env` | [`EnvSecretResolver`] | `env://VAR` |
//! | `file` | [`FileSecretResolver`] | `file:///abs/path` (not world-readable on unix) |
//! | `vault` | [`VaultResolver`] | `vault://<mount>/<path>#<key>` (KV v2) |
//! | `aws-sm` | [`AwsSecretsManagerResolver`] | `aws-sm://<secret-id>[#<json-key>]` |
//! | `totp` | [`TotpResolver`] | `totp://<base32-secret>[?digits=6&period=30&algo=sha1]` |
//!
//! Every value leaves a resolver as [`SecretOr::secret`]; errors name the reference (or,
//! for `totp://`, only the failure) and never the value. The `secret.resolved` audit row
//! is written by the caller that triggers the resolution (`RunContext::login_material`),
//! not here, so a resolver has no store dependency.

mod aws_sm;
mod env;
mod file;
mod totp;
mod vault;

pub use aws_sm::AwsSecretsManagerResolver;
pub use env::EnvSecretResolver;
pub use file::FileSecretResolver;
pub use totp::{TotpAlgorithm, TotpResolver};
pub use vault::VaultResolver;

use async_trait::async_trait;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{Clock, CoreError};
use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

/// Why a reference could not be resolved. Messages never carry a secret value; for
/// `totp://` references (whose reference *is* the secret) they do not carry the reference
/// either.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SecretError {
    /// The reference has no `scheme://` prefix.
    #[error("credential reference has no scheme")]
    MissingScheme,
    /// No resolver is registered for the scheme.
    #[error("{scheme}:// references are not supported by this resolver")]
    UnsupportedScheme {
        /// Scheme of the reference.
        scheme: String,
    },
    /// The reference does not have the shape its scheme requires.
    #[error("malformed {scheme}:// reference: {reason}")]
    Malformed {
        /// Scheme of the reference.
        scheme: &'static str,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The resolved value is empty.
    #[error("{reference}: resolved value is empty")]
    Empty {
        /// The reference (never a `totp://` one).
        reference: String,
    },
    /// `env://VAR` and the variable is unset or empty.
    #[error("{reference}: environment variable is unset or empty")]
    EnvUnset {
        /// The reference.
        reference: String,
    },
    /// `file://` and the file is readable by everyone (unix mode `o+r`).
    #[error("secret file {path} is world-readable (mode {mode:04o}); refusing to read it")]
    WorldReadable {
        /// The file.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// `file://` and the file could not be read.
    #[error("secret file {path} is not readable")]
    FileUnreadable {
        /// The file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The HTTP client for a remote resolver could not be built.
    #[error("secret client could not be built")]
    Client(#[source] reqwest::Error),
    /// Vault answered 403.
    #[error("vault denied access to {mount}/{path}")]
    VaultForbidden {
        /// KV mount.
        mount: String,
        /// Secret path under the mount.
        path: String,
    },
    /// Vault answered 404.
    #[error("vault secret {mount}/{path} does not exist")]
    VaultNotFound {
        /// KV mount.
        mount: String,
        /// Secret path under the mount.
        path: String,
    },
    /// Vault answered another non-success status.
    #[error("vault returned status {status} for {mount}/{path}")]
    VaultStatus {
        /// HTTP status.
        status: u16,
        /// KV mount.
        mount: String,
        /// Secret path under the mount.
        path: String,
    },
    /// The Vault request did not complete or its body was not the KV v2 shape.
    #[error("vault request for {mount}/{path} failed")]
    VaultTransport {
        /// KV mount.
        mount: String,
        /// Secret path under the mount.
        path: String,
        /// Underlying error.
        #[source]
        source: reqwest::Error,
    },
    /// AWS Secrets Manager did not return the secret.
    #[error("aws secrets manager could not return {secret_id}")]
    AwsSecretsManager {
        /// Secret id or ARN.
        secret_id: String,
        /// Underlying SDK error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync + 'static>,
    },
    /// The secret body is not UTF-8.
    #[error("{reference}: secret is not utf-8 text")]
    NotUtf8 {
        /// The reference.
        reference: String,
    },
    /// A `#key` was requested but the secret body is not a JSON object.
    #[error("{reference}: secret is not a json object")]
    NotJson {
        /// The reference.
        reference: String,
    },
    /// The secret body has no string value under the requested key.
    #[error("{reference}: no string value under key {key}")]
    MissingKey {
        /// The reference.
        reference: String,
        /// Requested key.
        key: String,
    },
    /// A `totp://` reference is malformed; the reference is never echoed.
    #[error("malformed totp:// reference: {0}")]
    Totp(&'static str),
    /// The injected clock is before 1970-01-01.
    #[error("clock is before the unix epoch")]
    ClockBeforeEpoch,
}

impl From<SecretError> for CoreError {
    fn from(e: SecretError) -> Self {
        let mut msg = e.to_string();
        let mut source = std::error::Error::source(&e);
        while let Some(s) = source {
            msg.push_str(": ");
            msg.push_str(&s.to_string());
            source = s.source();
        }
        Self::CredentialUnavailable(msg)
    }
}

/// One resolver per scheme. Unknown schemes are a typed
/// [`SecretError::UnsupportedScheme`]; the order of registration does not matter.
#[derive(Clone, Default)]
pub struct ChainResolver {
    by_scheme: BTreeMap<String, Arc<dyn SecretResolver>>,
}

impl fmt::Debug for ChainResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainResolver")
            .field("schemes", &self.by_scheme.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl ChainResolver {
    /// Empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `resolver` for `scheme`, replacing any earlier one.
    #[must_use]
    pub fn with(mut self, scheme: impl Into<String>, resolver: Arc<dyn SecretResolver>) -> Self {
        self.by_scheme.insert(scheme.into(), resolver);
        self
    }

    /// Chain with every resolver the process environment allows: `env`, `file` and `totp`
    /// always; `vault` when `VAULT_ADDR` and `VAULT_TOKEN` are set; `aws-sm` when the AWS
    /// SDK environment chain has a credential source (see
    /// [`AwsSecretsManagerResolver::from_env`]). `clock` drives `totp://`.
    pub async fn from_env(clock: Arc<dyn Clock>) -> Self {
        let mut chain = Self::new()
            .with("env", Arc::new(EnvSecretResolver))
            .with("file", Arc::new(FileSecretResolver))
            .with("totp", Arc::new(TotpResolver::new(clock)));
        match VaultResolver::from_env() {
            Ok(Some(vault)) => chain = chain.with("vault", Arc::new(vault)),
            Ok(None) => {}
            Err(e) => tracing::warn!(error = %e, "vault:// references disabled"),
        }
        if let Some(aws) = AwsSecretsManagerResolver::from_env().await {
            chain = chain.with("aws-sm", Arc::new(aws));
        }
        tracing::debug!(schemes = ?chain.by_scheme.keys().collect::<Vec<_>>(), "secret resolvers");
        chain
    }

    /// Registered schemes in sorted order.
    pub fn schemes(&self) -> impl Iterator<Item = &str> {
        self.by_scheme.keys().map(String::as_str)
    }

    /// The resolver that handles `reference`.
    ///
    /// # Errors
    /// [`SecretError::MissingScheme`] without a `scheme://` prefix,
    /// [`SecretError::UnsupportedScheme`] when nothing is registered for the scheme.
    pub fn resolver_for(&self, reference: &CredentialRef) -> Result<&Arc<dyn SecretResolver>, SecretError> {
        let scheme = reference.scheme().ok_or(SecretError::MissingScheme)?;
        self.by_scheme
            .get(scheme)
            .ok_or_else(|| SecretError::UnsupportedScheme {
                scheme: scheme.to_owned(),
            })
    }
}

#[async_trait]
impl SecretResolver for ChainResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        let resolver = self.resolver_for(reference)?;
        resolver.resolve(reference).await
    }
}

/// Split `reference` into the part after `scheme://`, checking the scheme.
fn strip_scheme<'a>(reference: &'a CredentialRef, scheme: &'static str) -> Result<&'a str, SecretError> {
    match reference.0.split_once("://") {
        Some((s, rest)) if s == scheme => Ok(rest),
        Some((s, _)) => Err(SecretError::UnsupportedScheme { scheme: s.to_owned() }),
        None => Err(SecretError::MissingScheme),
    }
}

/// Value under `key` of a JSON object body, as a secret. `reference` only labels errors.
fn json_key(body: &str, key: &str, reference: &str) -> Result<SecretOr<String>, SecretError> {
    let value: serde_json::Value = serde_json::from_str(body).map_err(|_| SecretError::NotJson {
        reference: reference.to_owned(),
    })?;
    match value.get(key).and_then(serde_json::Value::as_str) {
        Some(v) if !v.is_empty() => Ok(SecretOr::secret(v.to_owned())),
        _ => Err(SecretError::MissingKey {
            reference: reference.to_owned(),
            key: key.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::time::ManualClock;

    #[tokio::test]
    async fn chain_dispatches_on_scheme() {
        std::env::set_var("CRAWLX_SECRETS_CHAIN_TEST", "u:p");
        let clock: Arc<dyn Clock> =
            Arc::new(ManualClock::new(chrono::DateTime::from_timestamp(59, 0).unwrap()));
        let chain = ChainResolver::new()
            .with("env", Arc::new(EnvSecretResolver))
            .with("totp", Arc::new(TotpResolver::new(clock)));
        assert_eq!(chain.schemes().collect::<Vec<_>>(), ["env", "totp"]);
        let v = chain
            .resolve(&CredentialRef("env://CRAWLX_SECRETS_CHAIN_TEST".to_owned()))
            .await
            .unwrap();
        assert!(v.is_secret());
        assert_eq!(v.expose(), "u:p");
        let code = chain
            .resolve(&CredentialRef(
                "totp://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ?digits=8".to_owned(),
            ))
            .await
            .unwrap();
        assert_eq!(code.expose(), "94287082");
        assert!(!format!("{chain:?}").contains("u:p"));
    }

    #[tokio::test]
    async fn chain_rejects_unknown_scheme_and_missing_scheme() {
        let chain = ChainResolver::new().with("env", Arc::new(EnvSecretResolver));
        let err = chain
            .resolver_for(&CredentialRef("vault://kv/app#pw".to_owned()))
            .err()
            .unwrap();
        assert!(matches!(&err, SecretError::UnsupportedScheme { scheme } if scheme == "vault"));
        assert!(matches!(
            chain.resolver_for(&CredentialRef("nothing".to_owned())),
            Err(SecretError::MissingScheme)
        ));
        let core = chain
            .resolve(&CredentialRef("k8s://ns/secret".to_owned()))
            .await
            .err()
            .unwrap();
        assert!(matches!(&core, CoreError::CredentialUnavailable(m) if m.contains("k8s://")));
    }

    #[test]
    fn core_error_message_carries_the_source_chain() {
        let e = SecretError::FileUnreadable {
            path: PathBuf::from("/x"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "nope"),
        };
        let CoreError::CredentialUnavailable(m) = CoreError::from(e) else {
            panic!("wrong variant");
        };
        assert_eq!(m, "secret file /x is not readable: nope");
    }

    #[test]
    fn json_key_picks_strings_only() {
        assert_eq!(
            json_key(r#"{"pw":"s3","n":1}"#, "pw", "r").unwrap().expose(),
            "s3"
        );
        assert!(matches!(
            json_key(r#"{"pw":"s3","n":1}"#, "n", "r"),
            Err(SecretError::MissingKey { .. })
        ));
        assert!(matches!(
            json_key("[1]", "n", "r"),
            Err(SecretError::MissingKey { .. })
        ));
        assert!(matches!(
            json_key("not json", "n", "r"),
            Err(SecretError::NotJson { .. })
        ));
    }
}
