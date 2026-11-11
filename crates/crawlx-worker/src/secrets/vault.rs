//! `vault://<mount>/<path>#<key>`: HashiCorp Vault KV v2 (`GET {addr}/v1/{mount}/data/{path}`,
//! value at `data.data[key]`), authenticated with `X-Vault-Token`.

use super::{strip_scheme, SecretError};
use async_trait::async_trait;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::CoreError;
use reqwest::StatusCode;
use std::fmt;
use std::time::Duration;

/// Per-request timeout; a secret lookup happens once per login, so short and strict.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Resolves `vault://<mount>/<path>#<key>` references from a KV v2 engine.
#[allow(
    clippy::disallowed_types,
    reason = "Vault resolver owns the raw reqwest client"
)]
#[derive(Clone)]
pub struct VaultResolver {
    addr: String,
    token: SecretOr<String>,
    namespace: Option<String>,
    client: reqwest::Client,
}

impl fmt::Debug for VaultResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultResolver")
            .field("addr", &self.addr)
            .field("namespace", &self.namespace)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

/// Parsed `vault://` reference.
struct VaultRef<'a> {
    mount: &'a str,
    path: &'a str,
    key: &'a str,
}

impl<'a> VaultRef<'a> {
    fn parse(reference: &'a CredentialRef) -> Result<Self, SecretError> {
        let rest = strip_scheme(reference, "vault")?;
        let (location, key) = rest.split_once('#').ok_or(SecretError::Malformed {
            scheme: "vault",
            reason: "expected vault://<mount>/<path>#<key>",
        })?;
        let (mount, path) = location.split_once('/').ok_or(SecretError::Malformed {
            scheme: "vault",
            reason: "expected vault://<mount>/<path>#<key>",
        })?;
        if mount.is_empty() || path.is_empty() || key.is_empty() || path.ends_with('/') {
            return Err(SecretError::Malformed {
                scheme: "vault",
                reason: "mount, path and key must be non-empty",
            });
        }
        Ok(Self { mount, path, key })
    }
}

impl VaultResolver {
    /// Resolver against the Vault at `addr` (scheme and host, optional path prefix; a
    /// trailing `/` is dropped) with `token`.
    ///
    /// # Errors
    /// [`SecretError::Client`] when the HTTP client cannot be built.
    #[allow(
        clippy::disallowed_types,
        reason = "Vault resolver builds the raw reqwest client"
    )]
    pub fn new(addr: impl Into<String>, token: String) -> Result<Self, SecretError> {
        let mut addr = addr.into();
        while addr.ends_with('/') {
            addr.pop();
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .user_agent(concat!("crawlx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(SecretError::Client)?;
        Ok(Self {
            addr,
            token: SecretOr::secret(token),
            namespace: None,
            client,
        })
    }

    /// Send `X-Vault-Namespace` (Vault Enterprise namespaces).
    #[must_use]
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Resolver from `VAULT_ADDR`, `VAULT_TOKEN` and optional `VAULT_NAMESPACE`; `None`
    /// when either required variable is unset or empty.
    ///
    /// # Errors
    /// [`SecretError::Client`] when the HTTP client cannot be built.
    pub fn from_env() -> Result<Option<Self>, SecretError> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let (Some(addr), Some(token)) = (var("VAULT_ADDR"), var("VAULT_TOKEN")) else {
            return Ok(None);
        };
        let mut resolver = Self::new(addr.trim(), token)?;
        if let Some(ns) = var("VAULT_NAMESPACE") {
            resolver = resolver.with_namespace(ns.trim());
        }
        Ok(Some(resolver))
    }

    /// Vault address this resolver talks to.
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// `data.data[key]` of the KV v2 secret named by `reference`.
    ///
    /// # Errors
    /// [`SecretError::UnsupportedScheme`] / [`SecretError::Malformed`] for a bad reference;
    /// [`SecretError::VaultForbidden`] (403), [`SecretError::VaultNotFound`] (404),
    /// [`SecretError::VaultStatus`] (other non-2xx), [`SecretError::VaultTransport`] (no
    /// answer or not the KV v2 body) and [`SecretError::MissingKey`] when the secret has no
    /// non-empty string under `key`.
    pub async fn lookup(&self, reference: &CredentialRef) -> Result<SecretOr<String>, SecretError> {
        let r = VaultRef::parse(reference)?;
        let location = || (r.mount.to_owned(), r.path.to_owned());
        let url = format!("{}/v1/{}/data/{}", self.addr, r.mount, r.path);
        let mut request = self
            .client
            .get(&url)
            .header("X-Vault-Token", self.token.expose().as_str())
            .header("X-Vault-Request", "true");
        if let Some(ns) = &self.namespace {
            request = request.header("X-Vault-Namespace", ns.as_str());
        }
        let response = request.send().await.map_err(|source| {
            let (mount, path) = location();
            SecretError::VaultTransport { mount, path, source }
        })?;
        match response.status() {
            StatusCode::FORBIDDEN => {
                let (mount, path) = location();
                return Err(SecretError::VaultForbidden { mount, path });
            }
            StatusCode::NOT_FOUND => {
                let (mount, path) = location();
                return Err(SecretError::VaultNotFound { mount, path });
            }
            status if !status.is_success() => {
                let (mount, path) = location();
                return Err(SecretError::VaultStatus {
                    status: status.as_u16(),
                    mount,
                    path,
                });
            }
            _ => {}
        }
        let body: KvV2Response = response.json().await.map_err(|source| {
            let (mount, path) = location();
            SecretError::VaultTransport { mount, path, source }
        })?;
        match body.data.data.get(r.key).and_then(serde_json::Value::as_str) {
            Some(v) if !v.is_empty() => Ok(SecretOr::secret(v.to_owned())),
            _ => Err(SecretError::MissingKey {
                reference: reference.0.clone(),
                key: r.key.to_owned(),
            }),
        }
    }
}

#[derive(serde::Deserialize)]
struct KvV2Response {
    data: KvV2Data,
}

#[derive(serde::Deserialize)]
struct KvV2Data {
    data: serde_json::Map<String, serde_json::Value>,
}

#[async_trait]
impl SecretResolver for VaultResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        Ok(self.lookup(reference).await?)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TOKEN: &str = "hvs.test-token-never-printed";

    async fn vault() -> (MockServer, VaultResolver) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/crawlx/example/member"))
            .and(header("X-Vault-Token", TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "request_id": "r", "lease_id": "", "renewable": false, "lease_duration": 0,
                "data": {
                    "data": { "username": "alice", "password": "s3cret", "attempts": 3 },
                    "metadata": { "version": 2 }
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/crawlx/example/member"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "errors": ["permission denied"]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/crawlx/example/absent"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({ "errors": [] })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/kv/data/crawlx/example/broken"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let resolver = VaultResolver::new(format!("{}/", server.uri()), TOKEN.to_owned()).unwrap();
        (server, resolver)
    }

    #[tokio::test]
    async fn reads_kv_v2_key_with_token_header() {
        let (server, resolver) = vault().await;
        assert_eq!(resolver.addr(), server.uri());
        let v = resolver
            .resolve(&CredentialRef(
                "vault://kv/crawlx/example/member#password".to_owned(),
            ))
            .await
            .unwrap();
        assert!(v.is_secret());
        assert_eq!(v.expose(), "s3cret");
        let dbg = format!("{resolver:?}");
        assert!(dbg.contains("[REDACTED]") && !dbg.contains(TOKEN), "{dbg}");
        let err = resolver
            .lookup(&CredentialRef(
                "vault://kv/crawlx/example/member#attempts".to_owned(),
            ))
            .await
            .err()
            .unwrap();
        assert!(matches!(&err, SecretError::MissingKey { key, .. } if key == "attempts"));
        assert!(!err.to_string().contains("s3cret"));
    }

    #[tokio::test]
    async fn forbidden_not_found_and_server_errors_are_typed() {
        let (_server, resolver) = vault().await;
        let denied = VaultResolver::new(resolver.addr(), "hvs.wrong".to_owned()).unwrap();
        let err = denied
            .lookup(&CredentialRef(
                "vault://kv/crawlx/example/member#password".to_owned(),
            ))
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&err, SecretError::VaultForbidden { mount, path } if mount == "kv" && path == "crawlx/example/member")
        );
        let msg = CoreError::from(err).to_string();
        assert!(!msg.contains("hvs.") && !msg.contains("s3cret"), "{msg}");
        assert!(matches!(
            resolver
                .lookup(&CredentialRef(
                    "vault://kv/crawlx/example/absent#password".to_owned()
                ))
                .await,
            Err(SecretError::VaultNotFound { .. })
        ));
        assert!(matches!(
            resolver
                .lookup(&CredentialRef(
                    "vault://kv/crawlx/example/broken#password".to_owned()
                ))
                .await,
            Err(SecretError::VaultStatus { status: 500, .. })
        ));
    }

    #[tokio::test]
    async fn malformed_references_do_not_hit_the_network() {
        let resolver = VaultResolver::new("http://127.0.0.1:9", "t".to_owned()).unwrap();
        for bad in [
            "vault://kv/crawlx/member",
            "vault://kv#password",
            "vault://kv/#password",
            "vault:///x#password",
            "vault://kv/x#",
            "vault://kv/x/#k",
        ] {
            assert!(
                matches!(
                    resolver.lookup(&CredentialRef(bad.to_owned())).await,
                    Err(SecretError::Malformed { scheme: "vault", .. })
                ),
                "{bad}"
            );
        }
        assert!(matches!(
            resolver.lookup(&CredentialRef("env://X".to_owned())).await,
            Err(SecretError::UnsupportedScheme { .. })
        ));
    }

    #[test]
    fn from_env_needs_both_variables() {
        std::env::remove_var("VAULT_ADDR");
        std::env::set_var("VAULT_TOKEN", "x");
        assert!(VaultResolver::from_env().unwrap().is_none());
        std::env::remove_var("VAULT_TOKEN");
    }
}
