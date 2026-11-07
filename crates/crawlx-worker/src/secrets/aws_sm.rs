//! `aws-sm://<secret-id>[#<json-key>]`: AWS Secrets Manager `GetSecretValue`, optionally
//! picking one string out of a JSON secret. Credentials and region come from the SDK's
//! default chain (environment, profile, web identity, container, IMDS); TLS is rustls+ring
//! like the S3 artifact store.

use super::{json_key, strip_scheme, SecretError};
use async_trait::async_trait;
use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client;
use aws_smithy_http_client::tls;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::CoreError;
use std::fmt;

/// Environment variables any of which means the SDK default chain has a credential
/// source without a network round trip; the resolver is registered only when one is set.
const CREDENTIAL_SOURCE_VARS: [&str; 5] = [
    "AWS_ACCESS_KEY_ID",
    "AWS_PROFILE",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
];

/// Resolves `aws-sm://<secret-id>[#<json-key>]` references.
#[derive(Clone)]
pub struct AwsSecretsManagerResolver {
    client: Client,
    region: Option<String>,
}

impl fmt::Debug for AwsSecretsManagerResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsSecretsManagerResolver")
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl AwsSecretsManagerResolver {
    /// Resolver over an already configured SDK client.
    #[must_use]
    pub fn with_client(client: Client) -> Self {
        let region = client.config().region().map(ToString::to_string);
        Self { client, region }
    }

    /// Resolver from the SDK default chain, or `None` when none of
    /// `AWS_ACCESS_KEY_ID`, `AWS_PROFILE`, `AWS_WEB_IDENTITY_TOKEN_FILE`,
    /// `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, `AWS_CONTAINER_CREDENTIALS_FULL_URI` is set
    /// (so a worker without AWS configuration never probes IMDS).
    pub async fn from_env() -> Option<Self> {
        let configured = CREDENTIAL_SOURCE_VARS
            .iter()
            .any(|v| std::env::var(v).is_ok_and(|s| !s.trim().is_empty()));
        if !configured {
            return None;
        }
        let http = aws_smithy_http_client::Builder::new()
            .tls_provider(tls::Provider::Rustls(tls::rustls_provider::CryptoMode::Ring))
            .build_https();
        let sdk = aws_config::defaults(BehaviorVersion::latest())
            .http_client(http)
            .load()
            .await;
        Some(Self::with_client(Client::new(&sdk)))
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
    /// [`SecretError::AwsSecretsManager`] when the SDK call fails (the SDK error is the
    /// source), [`SecretError::NotUtf8`] for a binary secret that is not text,
    /// [`SecretError::NotJson`] / [`SecretError::MissingKey`] when a key was requested.
    pub async fn lookup(&self, reference: &CredentialRef) -> Result<SecretOr<String>, SecretError> {
        let rest = strip_scheme(reference, "aws-sm")?;
        let (secret_id, key) = match rest.split_once('#') {
            Some((id, key)) => (id, Some(key)),
            None => (rest, None),
        };
        if secret_id.is_empty() || key == Some("") {
            return Err(SecretError::Malformed {
                scheme: "aws-sm",
                reason: "expected aws-sm://<secret-id>[#<json-key>]",
            });
        }
        let out = self
            .client
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await
            .map_err(|e| SecretError::AwsSecretsManager {
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
impl SecretResolver for AwsSecretsManagerResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        Ok(self.lookup(reference).await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use aws_sdk_secretsmanager::config::{Credentials, Region};

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
        let r = AwsSecretsManagerResolver::with_client(offline_client());
        assert_eq!(r.region(), Some("eu-west-1"));
        for bad in ["aws-sm://", "aws-sm://#k", "aws-sm://id#"] {
            assert!(
                matches!(
                    r.lookup(&CredentialRef(bad.to_owned())).await,
                    Err(SecretError::Malformed { scheme: "aws-sm", .. })
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
            "AwsSecretsManagerResolver { region: Some(\"eu-west-1\"), .. }"
        );
    }

    #[tokio::test]
    async fn sdk_failures_are_typed_with_the_sdk_error_as_source() {
        let r = AwsSecretsManagerResolver::with_client(offline_client());
        let err = r
            .lookup(&CredentialRef("aws-sm://crawlx/test#password".to_owned()))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, SecretError::AwsSecretsManager { secret_id, .. } if secret_id == "crawlx/test")
        );
        assert!(std::error::Error::source(&err).is_some());
        let msg = CoreError::from(err).to_string();
        assert!(msg.starts_with("credential reference could not be resolved: aws secrets manager could not return crawlx/test"), "{msg}");
    }

    #[tokio::test]
    async fn from_env_is_none_without_a_credential_source() {
        if CREDENTIAL_SOURCE_VARS
            .iter()
            .any(|v| std::env::var(v).is_ok_and(|s| !s.trim().is_empty()))
        {
            eprintln!("skipping: an AWS credential source is set in the environment");
            return;
        }
        assert!(AwsSecretsManagerResolver::from_env().await.is_none());
    }

    /// Live round trip; needs `AWS_ACCESS_KEY_ID` (plus the usual secret key and region)
    /// and `CRAWLX_TEST_AWS_SM_SECRET` naming an existing secret (optionally `#key`).
    #[tokio::test]
    async fn live_get_secret_value_when_configured() {
        let has = |v: &str| std::env::var(v).is_ok_and(|s| !s.trim().is_empty());
        let Ok(secret) = std::env::var("CRAWLX_TEST_AWS_SM_SECRET") else {
            eprintln!("skipping: CRAWLX_TEST_AWS_SM_SECRET is not set");
            return;
        };
        if !has("AWS_ACCESS_KEY_ID") {
            eprintln!("skipping: AWS_ACCESS_KEY_ID is not set");
            return;
        }
        let Some(r) = AwsSecretsManagerResolver::from_env().await else {
            panic!("AWS_ACCESS_KEY_ID is set but the resolver was not built");
        };
        let v = r
            .resolve(&CredentialRef(format!("aws-sm://{secret}")))
            .await
            .unwrap();
        assert!(v.is_secret());
        assert!(!v.expose().is_empty());
    }
}
