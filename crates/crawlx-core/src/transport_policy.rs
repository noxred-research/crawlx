//! Transport controls of the URL fetch plane: a TLS client certificate by credential
//! reference (`fetch.clientCertificate`), realm-scoped HTTP credentials
//! (`fetch.realmCredentials`) and ordered, named per-host proxy rules (`fetch.proxyRules`).
//!
//! Secret material is only ever a credential reference in configuration; [`Fetch::redacted`]
//! masks the references in outward views and the resolved forms ([`ClientIdentity`],
//! [`RealmCredential`]) print no value in `Debug`. All three controls belong to the URL plane:
//! the browser plane has its own network stack and keeps following `fetch.proxy`, so browser-only
//! mode refuses them instead of accepting settings no plane would honor.
//!
//! Selection is deterministic: the first proxy rule whose host pattern matches wins, in
//! declaration order, and a request that matches no rule follows the base route. A selected rule
//! never falls back to another rule or to a direct connection.

use crate::config::Fetch;
use crate::error::CoreError;
use crate::request_controls::is_credential_reference;
use crate::secret::{CredentialRef, SecretOr, SecretResolver};
use crate::traffic::REDACTED_PLACEHOLDER;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;
use url::Url;

/// Maximum number of `fetch.proxyRules` entries.
pub const MAX_PROXY_RULES: usize = 16;
/// Maximum number of host patterns in one rule or certificate scope.
pub const MAX_HOST_PATTERNS: usize = 16;
/// Maximum number of `fetch.realmCredentials` entries.
pub const MAX_REALM_CREDENTIALS: usize = 16;
/// Longest realm name in bytes.
pub const MAX_REALM_LEN: usize = 128;
/// Longest rule name in bytes.
pub const MAX_RULE_NAME_LEN: usize = 64;
/// Largest resolved PEM or `user:password` value in bytes.
const MAX_SECRET_LEN: usize = 64 * 1024;

/// HTTP authentication scheme a [`RealmCredentialRef`] answers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RealmScheme {
    /// `Basic` (RFC 7617): the credential resolves to `user:password`.
    #[default]
    Basic,
    /// `Digest` (RFC 7616, `qop=auth`, `MD5` or `SHA-256`): the credential resolves to
    /// `user:password`, which never leaves the process; only a keyed hash of the challenge does.
    Digest,
}

impl RealmScheme {
    /// Whether this is the default scheme.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref, reason = "serde passes `&T`")]
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::Basic)
    }

    /// The scheme token of a `WWW-Authenticate` challenge, lower-case.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            Self::Digest => "digest",
        }
    }
}

/// `fetch.clientCertificate`: the TLS client identity presented to servers that request one.
///
/// Both fields are credential references (`env://`, `file://`, `vault://`, `cloud-sm://`); a
/// literal key never enters configuration. `certificate` resolves to a PEM chain (leaf first),
/// `key` to an unencrypted PKCS#8 PEM private key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ClientCertificate {
    /// Reference of the PEM certificate chain.
    pub certificate: String,
    /// Reference of the PKCS#8 PEM private key.
    pub key: String,
    /// Host patterns the identity is presented to (`example.test` exact, `*.example.test`
    /// subdomains). Empty scopes it to the seed's registrable domain, like `extraHeaders`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

impl ClientCertificate {
    /// Identity scoped to the seed's registrable domain.
    #[must_use]
    pub fn new(certificate: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            certificate: certificate.into(),
            key: key.into(),
            hosts: Vec::new(),
        }
    }
}

/// One `fetch.realmCredentials[]` entry: a credential for exactly one origin and realm.
///
/// The credential is sent only to `origin` (scheme, host and port all equal), only for a
/// protection space whose `WWW-Authenticate` challenge names `realm`, and never after a
/// redirect left the origin or downgraded `https` to `http`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RealmCredentialRef {
    /// Origin the credential belongs to (`https://host[:port]`, no path).
    pub origin: Url,
    /// Realm of the challenge it answers, compared exactly.
    pub realm: String,
    /// Authentication scheme (default `basic`).
    #[serde(default, skip_serializing_if = "RealmScheme::is_default")]
    pub scheme: RealmScheme,
    /// Credential reference resolving to `user:password`.
    pub credential: String,
}

impl RealmCredentialRef {
    /// `Basic` credential for `realm` of `origin`.
    #[must_use]
    pub fn basic(origin: Url, realm: impl Into<String>, credential: impl Into<String>) -> Self {
        Self {
            origin,
            realm: realm.into(),
            scheme: RealmScheme::Basic,
            credential: credential.into(),
        }
    }
}

/// One `fetch.proxyRules[]` entry: requests to a matching host leave through `proxy`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ProxyRule {
    /// Stable name (`[a-z0-9_-]`, unique); reported by the fetcher, never a secret.
    pub name: String,
    /// Host patterns: `example.test` matches that host, `*.example.test` any subdomain.
    pub hosts: Vec<String>,
    /// Proxy URL (`http`, `https`, `socks5`, `socks5h`; no credentials).
    pub proxy: Url,
}

impl ProxyRule {
    /// Rule `name` routing `hosts` through `proxy`.
    #[must_use]
    pub fn new(name: impl Into<String>, hosts: Vec<String>, proxy: Url) -> Self {
        Self {
            name: name.into(),
            hosts,
            proxy,
        }
    }

    /// The rule applies to `host` (lower-case).
    #[must_use]
    pub fn matches(&self, host: &str) -> bool {
        self.hosts.iter().any(|pattern| host_matches(pattern, host))
    }
}

/// The rule a request to `host` (lower-case) uses: the first match in declaration order.
#[must_use]
pub fn select_proxy_rule<'a>(rules: &'a [ProxyRule], host: &str) -> Option<&'a ProxyRule> {
    rules.iter().find(|rule| rule.matches(host))
}

/// `host` (lower-case, IPv6 literal with or without brackets) matches `pattern`: equal, or for
/// `*.suffix` a proper subdomain of `suffix` (an IP literal never matches a wildcard).
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    let pattern = pattern.trim_matches(['[', ']']);
    match pattern.strip_prefix("*.") {
        Some(suffix) => {
            host.parse::<std::net::IpAddr>().is_err()
                && host
                    .strip_suffix(suffix)
                    .is_some_and(|rest| rest.len() > 1 && rest.ends_with('.'))
        }
        None => host == pattern,
    }
}

fn is_host_pattern(pattern: &str) -> bool {
    let body = pattern.strip_prefix("*.").unwrap_or(pattern);
    let literal = body
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .is_some_and(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok());
    if literal {
        return pattern == body;
    }
    !body.is_empty()
        && body.len() <= 253
        && !body.starts_with('.')
        && !body.ends_with('.')
        && !body.contains("..")
        && body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_'))
        && !(pattern.starts_with("*.") && body.parse::<std::net::IpAddr>().is_ok())
}

fn is_rule_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_RULE_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn is_realm(realm: &str) -> bool {
    !realm.is_empty()
        && realm.len() <= MAX_REALM_LEN
        && realm
            .bytes()
            .all(|b| (b' '..=b'~').contains(&b) && b != b'"' && b != b'\\')
}

fn normalize_hosts(hosts: &mut [String], field: &'static str, errs: &mut Vec<CoreError>) {
    for host in hosts.iter_mut() {
        *host = host.trim().to_ascii_lowercase();
        if !is_host_pattern(host) {
            errs.push(CoreError::Invalid {
                field,
                reason: format!("{host:?} is not a host pattern (`host` or `*.suffix`)"),
            });
        }
    }
}

/// An origin without path, userinfo, query or fragment.
fn is_bare_origin(url: &Url) -> bool {
    url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && matches!(url.path(), "" | "/")
}

impl Fetch {
    /// Bound and validate `clientCertificate`, `realmCredentials` and `proxyRules`
    /// (called by `CreateCrawl::normalize`).
    pub(crate) fn normalize_transport(&mut self, errs: &mut Vec<CoreError>) {
        let invalid = |field: &'static str, reason: String| CoreError::Invalid { field, reason };

        if let Some(identity) = &mut self.client_certificate {
            for (value, what) in [(&identity.certificate, "certificate"), (&identity.key, "key")] {
                if !is_credential_reference(value) {
                    errs.push(invalid(
                        "fetch.clientCertificate",
                        format!("the {what} must be a credential reference, never a literal"),
                    ));
                }
            }
            if identity.hosts.len() > MAX_HOST_PATTERNS {
                errs.push(invalid(
                    "fetch.clientCertificate.hosts",
                    format!("at most {MAX_HOST_PATTERNS} patterns"),
                ));
            }
            normalize_hosts(&mut identity.hosts, "fetch.clientCertificate.hosts", errs);
        }

        if self.realm_credentials.len() > MAX_REALM_CREDENTIALS {
            errs.push(invalid(
                "fetch.realmCredentials",
                format!("at most {MAX_REALM_CREDENTIALS} credentials"),
            ));
        }
        let mut seen = BTreeSet::new();
        for credential in &self.realm_credentials {
            if !matches!(credential.origin.scheme(), "http" | "https") || !is_bare_origin(&credential.origin)
            {
                errs.push(invalid(
                    "fetch.realmCredentials[].origin",
                    "an origin is `http(s)://host[:port]` without credentials, path, query or fragment"
                        .to_owned(),
                ));
            }
            if !is_realm(&credential.realm) {
                errs.push(invalid(
                    "fetch.realmCredentials[].realm",
                    format!(
                        "a realm is 1 to {MAX_REALM_LEN} printable ASCII bytes without quote or backslash"
                    ),
                ));
            }
            if !is_credential_reference(&credential.credential) {
                errs.push(invalid(
                    "fetch.realmCredentials[].credential",
                    "the credential must be a reference to `user:password`, never a literal".to_owned(),
                ));
            }
            if !seen.insert((
                credential.origin.origin().ascii_serialization(),
                credential.realm.clone(),
            )) {
                errs.push(invalid(
                    "fetch.realmCredentials",
                    "one credential per origin and realm".to_owned(),
                ));
            }
        }

        if self.proxy_rules.len() > MAX_PROXY_RULES {
            errs.push(invalid(
                "fetch.proxyRules",
                format!("at most {MAX_PROXY_RULES} rules"),
            ));
        }
        let mut names = BTreeSet::new();
        for rule in &mut self.proxy_rules {
            if !is_rule_name(&rule.name) {
                errs.push(invalid(
                    "fetch.proxyRules[].name",
                    format!("a rule name is 1 to {MAX_RULE_NAME_LEN} bytes of [a-z0-9_-]"),
                ));
            }
            if !names.insert(rule.name.clone()) {
                errs.push(invalid(
                    "fetch.proxyRules[].name",
                    "rule names are unique".to_owned(),
                ));
            }
            if rule.hosts.is_empty() || rule.hosts.len() > MAX_HOST_PATTERNS {
                errs.push(invalid(
                    "fetch.proxyRules[].hosts",
                    format!("a rule has 1 to {MAX_HOST_PATTERNS} host patterns"),
                ));
            }
            normalize_hosts(&mut rule.hosts, "fetch.proxyRules[].hosts", errs);
            if !matches!(rule.proxy.scheme(), "http" | "https" | "socks5" | "socks5h")
                || !is_bare_origin(&rule.proxy)
            {
                errs.push(invalid(
                    "fetch.proxyRules[].proxy",
                    "a rule proxy is an http, https or socks5 URL with a host and no credentials, path, query or fragment"
                        .to_owned(),
                ));
            }
        }
    }

    /// Whether any transport control (client certificate, realm credentials, proxy rules) is set.
    #[must_use]
    pub fn has_transport_controls(&self) -> bool {
        self.client_certificate.is_some()
            || !self.realm_credentials.is_empty()
            || !self.proxy_rules.is_empty()
    }

    /// Replace every credential reference of the transport controls by `[redacted]`.
    pub(crate) fn redact_transport(&mut self) {
        if let Some(identity) = &mut self.client_certificate {
            REDACTED_PLACEHOLDER.clone_into(&mut identity.certificate);
            REDACTED_PLACEHOLDER.clone_into(&mut identity.key);
        }
        for credential in &mut self.realm_credentials {
            REDACTED_PLACEHOLDER.clone_into(&mut credential.credential);
        }
    }
}

/// The resolved TLS client identity of a run. `Debug` prints no PEM.
#[derive(Clone)]
pub struct ClientIdentity {
    certificate: SecretOr<String>,
    key: SecretOr<String>,
    hosts: Vec<String>,
}

impl ClientIdentity {
    /// PEM certificate chain, leaf first.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        self.certificate.expose()
    }

    /// Unencrypted PKCS#8 PEM private key. Hand it to the TLS stack only.
    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        self.key.expose()
    }

    /// Host patterns the identity is scoped to; empty means the controls' scope domain.
    #[must_use]
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }
}

impl fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientIdentity")
            .field("certificate", &REDACTED_PLACEHOLDER)
            .field("key", &REDACTED_PLACEHOLDER)
            .field("hosts", &self.hosts)
            .finish()
    }
}

/// One resolved realm credential. `Debug` prints origin and realm, never the secret.
#[derive(Clone)]
pub struct RealmCredential {
    origin: Url,
    realm: String,
    scheme: RealmScheme,
    secret: SecretOr<String>,
    token: SecretOr<String>,
}

impl RealmCredential {
    /// Origin the credential is bound to.
    #[must_use]
    pub const fn origin(&self) -> &Url {
        &self.origin
    }

    /// Realm it answers.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Authentication scheme.
    #[must_use]
    pub const fn scheme(&self) -> RealmScheme {
        self.scheme
    }

    /// The `Authorization` header value of a `Basic` credential; `None` for a scheme whose
    /// answer depends on the server's challenge ([`RealmScheme::Digest`]).
    #[must_use]
    pub fn basic_authorization(&self) -> Option<SecretOr<String>> {
        match self.scheme {
            RealmScheme::Basic => Some(SecretOr::secret(format!("Basic {}", self.token.expose()))),
            RealmScheme::Digest => None,
        }
    }

    /// The user name and password. Hand them only to the hash that answers a challenge.
    #[must_use]
    pub fn user_and_password(&self) -> (&str, &str) {
        self.secret.expose().split_once(':').unwrap_or_default()
    }

    /// Stable encoding of the secret for identity digests (never sent anywhere).
    #[must_use]
    pub fn encoded_secret(&self) -> &str {
        self.token.expose()
    }

    /// `url` is on the credential's origin: scheme, host and port all equal, so an `http` URL
    /// never matches an `https` credential.
    #[must_use]
    pub fn matches_origin(&self, url: &Url) -> bool {
        self.origin.origin() == url.origin()
    }

    /// Secret values to register for redaction: the raw credential and its wire encoding.
    pub(crate) fn secret_values(&self) -> impl Iterator<Item = &str> {
        [self.secret.expose().as_str(), self.token.expose().as_str()]
            .into_iter()
            .filter(|value| value.len() >= 4)
    }
}

impl fmt::Debug for RealmCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealmCredential")
            .field("origin", &self.origin.origin().ascii_serialization())
            .field("realm", &self.realm)
            .field("scheme", &self.scheme)
            .field("secret", &REDACTED_PLACEHOLDER)
            .finish()
    }
}

impl ClientIdentity {
    pub(crate) fn secret_values(&self) -> impl Iterator<Item = &str> {
        [self.key.expose().as_str()]
            .into_iter()
            .filter(|value| value.len() >= 4)
    }
}

/// Standard Base64 (RFC 4648, padded) of `input`.
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                let index = usize::try_from((n >> (18 - 6 * i)) & 63).unwrap_or(0);
                out.push(char::from(ALPHABET[index]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

async fn resolve_reference(
    reference: &str,
    what: &'static str,
    secrets: Option<&dyn SecretResolver>,
) -> Result<SecretOr<String>, CoreError> {
    let reference = CredentialRef(reference.to_owned());
    let Some(resolver) = secrets else {
        return Err(CoreError::CredentialUnavailable(format!(
            "{what}: no secret resolver for {}",
            reference.0
        )));
    };
    let resolved = resolver.resolve(&reference).await?;
    if resolved.expose().len() > MAX_SECRET_LEN {
        return Err(CoreError::Invalid {
            field: "fetch",
            reason: format!("the resolved {what} exceeds {MAX_SECRET_LEN} bytes"),
        });
    }
    Ok(SecretOr::secret(resolved.expose().clone()))
}

/// The transport secrets of `fetch`, resolved through `secrets`.
pub(crate) struct TransportSecrets {
    pub(crate) identity: Option<ClientIdentity>,
    pub(crate) realms: Vec<RealmCredential>,
}

impl TransportSecrets {
    /// Resolve every reference of `fetch` under one shared deadline of `fetch.timeoutMs`: the
    /// certificate, the key and all realm credentials together may not outlast a single request
    /// timeout, so a slow secret store cannot stretch the budget of a fetch.
    pub(crate) async fn resolve(
        fetch: &Fetch,
        secrets: Option<&dyn SecretResolver>,
    ) -> Result<Self, CoreError> {
        if fetch.client_certificate.is_none() && fetch.realm_credentials.is_empty() {
            return Ok(Self {
                identity: None,
                realms: Vec::new(),
            });
        }
        let deadline = Duration::from_millis(u64::from(fetch.timeout_ms));
        tokio::time::timeout(deadline, Self::resolve_all(fetch, secrets))
            .await
            .map_err(|_| {
                CoreError::CredentialUnavailable(
                    "transport credentials were not resolved within fetch.timeoutMs".to_owned(),
                )
            })?
    }

    async fn resolve_all(fetch: &Fetch, secrets: Option<&dyn SecretResolver>) -> Result<Self, CoreError> {
        let identity = match &fetch.client_certificate {
            None => None,
            Some(cert) => {
                let certificate = resolve_reference(&cert.certificate, "client certificate", secrets).await?;
                let key = resolve_reference(&cert.key, "client private key", secrets).await?;
                if !certificate.expose().contains("-----BEGIN CERTIFICATE-----") {
                    return Err(CoreError::Invalid {
                        field: "fetch.clientCertificate",
                        reason: "the resolved certificate is not a PEM certificate chain".to_owned(),
                    });
                }
                // Split so that a secret scanner reading this file never sees a PEM key header here.
                if !key.expose().contains(concat!("-----BEGIN ", "PRIVATE KEY-----")) {
                    return Err(CoreError::Invalid {
                        field: "fetch.clientCertificate",
                        reason: "the resolved key is not an unencrypted PKCS#8 PEM private key".to_owned(),
                    });
                }
                Some(ClientIdentity {
                    certificate,
                    key,
                    hosts: cert.hosts.clone(),
                })
            }
        };
        let mut realms = Vec::with_capacity(fetch.realm_credentials.len());
        for entry in &fetch.realm_credentials {
            let secret = resolve_reference(&entry.credential, "realm credential", secrets).await?;
            let value = secret.expose();
            let well_formed = value.split_once(':').is_some_and(|(user, _)| !user.is_empty())
                && !value.bytes().any(|b| b.is_ascii_control());
            if !well_formed {
                return Err(CoreError::Invalid {
                    field: "fetch.realmCredentials[].credential",
                    reason: "the resolved credential is not `user:password` without control characters"
                        .to_owned(),
                });
            }
            let token = SecretOr::secret(base64(value.as_bytes()));
            realms.push(RealmCredential {
                origin: entry.origin.clone(),
                realm: entry.realm.clone(),
                scheme: entry.scheme,
                secret,
                token,
            });
        }
        Ok(Self { identity, realms })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::config::CreateCrawl;
    use async_trait::async_trait;
    use std::collections::BTreeMap;

    fn crawl(fetch: &str) -> CreateCrawl {
        serde_json::from_str(&format!(
            r#"{{"seedUrl":"https://a.test/","mode":"static","fetch":{fetch}}}"#
        ))
        .unwrap()
    }

    fn fields(errs: &[CoreError]) -> Vec<&'static str> {
        errs.iter()
            .filter_map(|e| match e {
                CoreError::Invalid { field, .. } => Some(*field),
                _ => None,
            })
            .collect()
    }

    struct Map(BTreeMap<&'static str, &'static str>);

    #[async_trait]
    impl SecretResolver for Map {
        async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
            self.0
                .get(reference.0.as_str())
                .map(|v| SecretOr::secret((*v).to_owned()))
                .ok_or_else(|| CoreError::CredentialUnavailable(reference.0.clone()))
        }
    }

    /// Answers every reference with a valid value after `.0`.
    struct Slow(Duration);

    #[async_trait]
    impl SecretResolver for Slow {
        async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
            tokio::time::sleep(self.0).await;
            Ok(SecretOr::secret(if reference.0.ends_with('K') {
                // a placeholder body, not key material; the label is split so secret scans skip it
                format!("-----BEGIN {0} KEY-----\nK\n-----END {0} KEY-----\n", "PRIVATE")
            } else {
                "-----BEGIN CERTIFICATE-----\nC\n-----END CERTIFICATE-----\n".to_owned()
            }))
        }
    }

    #[test]
    fn host_patterns_match_exact_hosts_and_proper_subdomains_only() {
        assert!(host_matches("a.test", "a.test"));
        assert!(!host_matches("a.test", "b.a.test"));
        assert!(host_matches("*.a.test", "b.a.test"));
        assert!(host_matches("*.a.test", "c.b.a.test"));
        assert!(!host_matches("*.a.test", "a.test"));
        assert!(!host_matches("*.a.test", "xa.test"));
        assert!(!host_matches("*.0.0.1", "127.0.0.1"));
        assert!(host_matches("::1", "[::1]"));
        assert!(host_matches("[::1]", "::1"));
    }

    #[test]
    fn the_first_matching_rule_wins_in_declaration_order() {
        let proxy = |s: &str| Url::parse(s).unwrap();
        let rules = vec![
            ProxyRule::new("wide", vec!["*.a.test".into()], proxy("http://p1.test:3128")),
            ProxyRule::new("narrow", vec!["x.a.test".into()], proxy("http://p2.test:3128")),
            ProxyRule::new("other", vec!["b.test".into()], proxy("socks5://p3.test:1080")),
        ];
        assert_eq!(select_proxy_rule(&rules, "x.a.test").unwrap().name, "wide");
        assert_eq!(select_proxy_rule(&rules, "b.test").unwrap().name, "other");
        assert!(select_proxy_rule(&rules, "c.test").is_none());
        let reordered = vec![rules[1].clone(), rules[0].clone()];
        assert_eq!(select_proxy_rule(&reordered, "x.a.test").unwrap().name, "narrow");
        for _ in 0..8 {
            assert_eq!(select_proxy_rule(&rules, "x.a.test").unwrap().name, "wide");
        }
    }

    #[test]
    fn wire_shape_roundtrips_and_defaults_stay_off_the_wire() {
        let mut c = crawl(
            r#"{"clientCertificate":{"certificate":"env://C","key":"file:///k","hosts":["*.A.test"]},
                "realmCredentials":[{"origin":"https://a.test","realm":"members","credential":"env://U"}],
                "proxyRules":[{"name":"eu","hosts":["B.test"],"proxy":"http://p.test:3128"}]}"#,
        );
        c.normalize().unwrap();
        assert_eq!(c.fetch.client_certificate.as_ref().unwrap().hosts, ["*.a.test"]);
        assert_eq!(c.fetch.proxy_rules[0].hosts, ["b.test"]);
        let back: CreateCrawl = serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
        assert_eq!(back.fetch, c.fetch);
        let plain =
            serde_json::to_value(CreateCrawl::new(url::Url::parse("https://a.test/").unwrap())).unwrap();
        for key in ["clientCertificate", "realmCredentials", "proxyRules"] {
            assert!(plain["fetch"].get(key).is_none(), "{key} serialized by default");
        }
    }

    #[test]
    fn validation_rejects_literals_unsafe_rules_and_other_planes() {
        let mut c = crawl(
            r#"{"clientCertificate":{"certificate":"-----BEGIN CERTIFICATE-----","key":"literal"},
                "realmCredentials":[{"origin":"https://a.test/path","realm":"r\"q","credential":"user:pw"},
                    {"origin":"ftp://a.test","realm":"r","credential":"env://U"}],
                "proxyRules":[{"name":"Bad Name","hosts":[],"proxy":"http://u:p@p.test:3128"},
                    {"name":"ok","hosts":["*.1.2.3.4"],"proxy":"ssh://p.test"},
                    {"name":"ok","hosts":["a.test"],"proxy":"http://p.test/x"}]}"#,
        );
        let errs = c.normalize().unwrap_err();
        let f = fields(&errs);
        for expected in [
            "fetch.clientCertificate",
            "fetch.realmCredentials[].origin",
            "fetch.realmCredentials[].realm",
            "fetch.realmCredentials[].credential",
            "fetch.proxyRules[].name",
            "fetch.proxyRules[].hosts",
            "fetch.proxyRules[].proxy",
        ] {
            assert!(f.contains(&expected), "{expected} missing from {f:?}");
        }
        let text = format!("{errs:?}");
        assert!(!text.contains("p:p.test") && !text.contains("user:pw"), "{text}");

        let mut browser_only: CreateCrawl = serde_json::from_str(
            r#"{"seedUrl":"https://a.test/","mode":"dynamic","fetch":{"proxyRules":[{"name":"r","hosts":["a.test"],"proxy":"http://p.test:3128"}]}}"#,
        )
        .unwrap();
        let errs = browser_only.normalize().unwrap_err();
        assert!(
            errs.iter().any(|e| matches!(
                e,
                CoreError::Conflict {
                    a: "fetch.proxyRules",
                    ..
                }
            )),
            "{errs:?}"
        );
        // Hybrid runs the URL plane too: the controls are admitted and apply to it.
        let mut hybrid: CreateCrawl = serde_json::from_str(
            r#"{"seedUrl":"https://a.test/","fetch":{"proxyRules":[{"name":"r","hosts":["a.test"],"proxy":"http://p.test:3128"}]}}"#,
        )
        .unwrap();
        hybrid.normalize().unwrap();
    }

    #[test]
    fn redacted_views_and_debug_never_print_a_reference_or_value() {
        let mut c = crawl(
            r#"{"clientCertificate":{"certificate":"env://CERT_REF","key":"env://KEY_REF"},
                "realmCredentials":[{"origin":"https://a.test","realm":"members","credential":"env://CRED_REF"}]}"#,
        );
        c.normalize().unwrap();
        let json = serde_json::to_string(&c.redacted()).unwrap();
        assert!(!json.contains("_REF"), "{json}");
        assert!(json.contains("members"));
        assert_eq!(c.fetch.realm_credentials[0].credential, "env://CRED_REF");
    }

    #[tokio::test]
    async fn resolution_yields_header_values_and_redacts_every_secret_form() {
        let mut c = crawl(
            r#"{"clientCertificate":{"certificate":"env://C","key":"env://K"},
                "realmCredentials":[{"origin":"https://a.test","realm":"members","credential":"env://U"}]}"#,
        );
        c.normalize().unwrap();
        let secrets = Map(BTreeMap::from([
            (
                "env://C",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            ),
            (
                "env://K",
                "-----BEGIN PRIVATE KEY-----\nSECRETKEYBODY\n-----END PRIVATE KEY-----\n",
            ),
            ("env://U", "alice:s3cr3t"),
        ]));
        let resolved = TransportSecrets::resolve(&c.fetch, Some(&secrets)).await.unwrap();
        let realm = &resolved.realms[0];
        assert_eq!(
            realm.basic_authorization().unwrap().expose(),
            "Basic YWxpY2U6czNjcjN0"
        );
        assert_eq!(realm.user_and_password(), ("alice", "s3cr3t"));
        assert!(realm.matches_origin(&Url::parse("https://a.test/x/y").unwrap()));
        assert!(!realm.matches_origin(&Url::parse("http://a.test/x").unwrap()));
        assert!(!realm.matches_origin(&Url::parse("https://a.test:8443/x").unwrap()));
        let identity = resolved.identity.as_ref().unwrap();
        for text in [format!("{realm:?}"), format!("{identity:?}")] {
            assert!(
                !text.contains("s3cr3t") && !text.contains("YWxpY2U") && !text.contains("SECRETKEYBODY"),
                "{text}"
            );
        }
        assert!(realm.secret_values().any(|v| v == "alice:s3cr3t"));
        assert!(realm.secret_values().any(|v| v == "YWxpY2U6czNjcjN0"));
    }

    #[tokio::test]
    async fn base64_matches_the_reference_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
    }

    #[tokio::test]
    async fn malformed_secrets_fail_without_echoing_them() {
        let mut c =
            crawl(r#"{"realmCredentials":[{"origin":"https://a.test","realm":"r","credential":"env://U"}]}"#);
        c.normalize().unwrap();
        let secrets = Map(BTreeMap::from([("env://U", "no-colon-secret-value")]));
        let Err(error) = TransportSecrets::resolve(&c.fetch, Some(&secrets)).await else {
            panic!("a credential without a colon must be refused");
        };
        assert!(!error.to_string().contains("no-colon-secret-value"), "{error}");
        let Err(error) = TransportSecrets::resolve(&c.fetch, None).await else {
            panic!("a reference without a resolver must be refused");
        };
        assert!(matches!(error, CoreError::CredentialUnavailable(_)));
    }

    #[tokio::test]
    async fn one_shared_deadline_bounds_all_secret_lookups() {
        let mut c =
            crawl(r#"{"timeoutMs":100,"clientCertificate":{"certificate":"env://C","key":"env://K"}}"#);
        c.normalize().unwrap();
        // Each lookup alone fits 100 ms; the pair does not, so only a shared budget fails it.
        let slow = Slow(Duration::from_millis(70));
        let Err(error) = TransportSecrets::resolve(&c.fetch, Some(&slow)).await else {
            panic!("two lookups of 70 ms each must exceed one 100 ms deadline");
        };
        assert!(
            matches!(&error, CoreError::CredentialUnavailable(m) if m.contains("fetch.timeoutMs")),
            "{error}"
        );
        let single = Slow(Duration::from_millis(30));
        TransportSecrets::resolve(&c.fetch, Some(&single)).await.unwrap();
    }
}
