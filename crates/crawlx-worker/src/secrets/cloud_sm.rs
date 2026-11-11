//! `cloud-sm://<secret-id>[#<json-key>]`: cloud secrets manager `GetSecretValue`, optionally
//! picking one string out of a JSON secret. Credentials and region come from the SDK's
//! default chain (environment, profile, web identity, container, instance metadata); TLS is rustls+ring
//! like the S3 artifact store.

use super::{json_key, strip_scheme, SecretError};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
#[allow(
    clippy::disallowed_types,
    reason = "managed secret adapter imports the raw SDK client"
)]
use aws_sdk_secretsmanager::Client;
use aws_smithy_http_client::tls;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::CoreError;
use std::fmt;
use std::future::Future;

/// Environment variables any of which means the SDK default chain has a credential
/// source without a network round trip; the resolver is registered only when one is set.
const CREDENTIAL_SOURCE_VARS: [&str; 5] = [
    "AWS_ACCESS_KEY_ID",           // wire-compat: SDK credential environment variable
    "AWS_PROFILE",                 // wire-compat: SDK credential environment variable
    "AWS_WEB_IDENTITY_TOKEN_FILE", // wire-compat: SDK credential environment variable
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", // wire-compat: SDK credential environment variable
    "AWS_CONTAINER_CREDENTIALS_FULL_URI", // wire-compat: SDK credential environment variable
];

/// Resolves `cloud-sm://<secret-id>[#<json-key>]` references.
#[allow(
    clippy::disallowed_types,
    reason = "managed secret adapter owns the raw SDK client"
)]
#[derive(Clone)]
pub struct CloudSecretsResolver {
    client: Client,
    region: Option<String>,
}

impl fmt::Debug for CloudSecretsResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudSecretsResolver")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl CloudSecretsResolver {
    /// Resolver over an already configured SDK client.
    #[must_use]
    #[allow(
        clippy::disallowed_types,
        reason = "managed secret adapter accepts the raw SDK client"
    )]
    pub fn with_client(client: Client) -> Self {
        let region = client.config().region().map(ToString::to_string);
        Self { client, region }
    }

    /// Resolver from the SDK default chain, or `None` when none of
    /// the SDK credential-source environment variables (access key id, profile, web identity
    /// token file, container credentials relative or full URI; see `CREDENTIAL_SOURCE_VARS`) is
    /// set (so a worker without cloud configuration never probes the instance metadata service).
    pub async fn from_env() -> Option<Self> {
        let configured = CREDENTIAL_SOURCE_VARS
            .iter()
            .any(|v| std::env::var(v).is_ok_and(|s| !s.trim().is_empty()));
        if !configured {
            return None;
        }
        Some(Self::from_configured_env().await)
    }

    // Keep SDK construction state out of the unconfigured path and its callers.
    #[allow(
        clippy::disallowed_types,
        reason = "managed secret adapter constructs the raw SDK client"
    )]
    fn from_configured_env() -> impl Future<Output = Self> + Send {
        Box::pin(async {
            let http = aws_smithy_http_client::Builder::new()
                .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
                .build_https();
            let sdk = aws_config::defaults(BehaviorVersion::latest())
                .http_client(http)
                .load()
                .await;
            Self::with_client(Client::new(&sdk))
        })
    }

    /// Region the client is configured for, if any.
    #[must_use]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    /// The secret string (or UTF-8 binary) named by `reference`, or its `#<json-key>`.
    ///
    /// # Errors
    /// [`SecretError::UnsupportedScheme`] / [`SecretError::Malformed`] for a bad reference,
    /// [`SecretError::CloudSecrets`] when the SDK call fails (the SDK error is the
    /// source), [`SecretError::NotUtf8`] for a binary secret that is not text,
    /// [`SecretError::NotJson`] / [`SecretError::MissingKey`] when a key was requested.
    pub async fn lookup(&self, reference: &CredentialRef) -> Result<SecretOr<String>, SecretError> {
        let rest = strip_scheme(reference, "cloud-sm")?;
        let (secret_id, key) = match rest.split_once('#') {
            Some((id, key)) => (id, Some(key)),
            None => (rest, None),
        };
        if secret_id.is_empty() || key == Some("") {
            return Err(SecretError::Malformed {
                scheme: "cloud-sm",
                reason: "expected cloud-sm://<secret-id>[#<json-key>]",
            });
        }
        let out = self
            .client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .map_err(|e| SecretError::CloudSecrets {
                secret_id: secret_id.to_owned(),
                source: Box::new(e),
            })?;
        let text: zeroize::Zeroizing<String> = match (out.secret_string(), out.secret_binary()) {
            (Some(s), _) => zeroize::Zeroizing::new(s.to_owned()),
            (None, Some(b)) => String::from_utf8(b.as_ref().to_vec())
                .map(zeroize::Zeroizing::new)
                .map_err(|_| SecretError::NotUtf8 {
                    reference: reference.0.clone(),
                })?,
            (None, None) => {
                return Err(SecretError::Empty {
                    reference: reference.0.clone(),
                })
            }
        };
        match key {
            Some(k) => json_key(&text, k, &reference.0),
            None if text.is_empty() => Err(SecretError::Empty {
                reference: reference.0.clone(),
            }),
            None => Ok(SecretOr::secret(text.to_string())),
        }
    }
}

#[async_trait]
impl SecretResolver for CloudSecretsResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        Ok(self.lookup(reference).await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use aws_sdk_secretsmanager::config::{Credentials, Region};

    #[allow(
        clippy::disallowed_types,
        reason = "test fixture builds an offline raw SDK client"
    )]
    fn offline_client() -> Client {
        let cfg = aws_sdk_secretsmanager::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("eu-west-1"))
            .credentials_provider(Credentials::for_tests())
            .endpoint_url("http://127.0.0.1:9")
            .build();
        Client::from_conf(cfg)
    }

    #[tokio::test]
    async fn malformed_references_do_not_call_the_service() {
        let r = CloudSecretsResolver::with_client(offline_client());
        assert_eq!(r.region(), Some("eu-west-1"));
        for bad in ["cloud-sm://", "cloud-sm://#k", "cloud-sm://id#"] {
            assert!(
                matches!(
                    r.lookup(&CredentialRef(bad.to_owned())).await,
                    Err(SecretError::Malformed {
                        scheme: "cloud-sm",
                        ..
                    })
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            r.lookup(&CredentialRef("vault://kv/x#k".to_owned())).await,
            Err(SecretError::UnsupportedScheme { .. })
        ));
        assert_eq!(
            format!("{r:?}"),
            "CloudSecretsResolver { region: Some(\"eu-west-1\"), .. }"
        );
    }

    #[tokio::test]
    async fn sdk_failures_are_typed_with_the_sdk_error_as_source() {
        let r = CloudSecretsResolver::with_client(offline_client());
        let err = r
            .lookup(&CredentialRef("cloud-sm://crawlx/test#password".to_owned()))
            .await
            .err()
            .unwrap();
        assert!(matches!(&err, SecretError::CloudSecrets { secret_id, .. } if secret_id == "crawlx/test"));
        assert!(std::error::Error::source(&err).is_some());
        let msg = CoreError::from(err).to_string();
        assert!(msg.starts_with("credential reference could not be resolved: cloud secrets manager could not return crawlx/test"), "{msg}");
    }

    #[tokio::test]
    async fn from_env_is_none_without_a_credential_source() {
        if CREDENTIAL_SOURCE_VARS
            .iter()
            .any(|v| std::env::var(v).is_ok_and(|s| !s.trim().is_empty()))
        {
            eprintln!("skipping: a cloud credential source is set in the environment");
            return;
        }
        assert!(CloudSecretsResolver::from_env().await.is_none());
    }

    /// Live round trip; needs the SDK access key id variable (plus the usual secret key and region)
    /// and `CRAWLX_TEST_CLOUD_SM_SECRET` naming an existing secret (optionally `#key`).
    #[tokio::test]
    async fn live_get_secret_value_when_configured() {
        let has = |v: &str| std::env::var(v).is_ok_and(|s| !s.trim().is_empty());
        let Ok(secret) = std::env::var("CRAWLX_TEST_CLOUD_SM_SECRET") else {
            eprintln!("skipping: CRAWLX_TEST_CLOUD_SM_SECRET is not set");
            return;
        };
        if !has("AWS_ACCESS_KEY_ID") {
            // wire-compat: SDK credential environment variable
            eprintln!("skipping: the SDK access key id variable is not set");
            return;
        }
        let Some(r) = CloudSecretsResolver::from_env().await else {
            panic!("the SDK access key id variable is set but the resolver was not built");
        };
        let v = r
            .resolve(&CredentialRef(format!("cloud-sm://{secret}")))
            .await
            .unwrap();
        assert!(v.is_secret());
        assert!(!v.expose().is_empty());
    }
}
