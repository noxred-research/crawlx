//! Request controls shared by the fetch and browser planes: custom request
//! headers, cookies, `User-Agent` and TLS verification (`fetch.extraHeaders`,
//! `fetch.cookies`, `fetch.userAgent`, `fetch.robotsUserAgent`, `fetch.skipTlsVerification`).
//!
//! Header and cookie values are secrets. The wire types ([`ExtraHeaders`],
//! [`FetchCookie`]) print `[redacted]` for every value in `Debug`; [`RequestControls`] is the
//! form a run executes with: values are [`SecretOr`] (zeroized, redacted in `Debug`). A value
//! is either a literal or a credential reference (`env://`, `file://`, `vault://`,
//! `aws-sm://`) resolved by the worker right before the run starts. Durable run config
//! retains references but never literal header or cookie values; execution recovers literals
//! from bounded volatile storage. [`CreateCrawl::redacted`] also masks references in outward views.
//!
//! [`CreateCrawl::redacted`]: crate::config::CreateCrawl::redacted

use crate::config::Fetch;
use crate::error::CoreError;
use crate::secret::{CredentialRef, SecretOr, SecretResolver};
use crate::traffic::REDACTED_PLACEHOLDER;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

/// Maximum number of `fetch.extraHeaders` entries.
pub const MAX_EXTRA_HEADERS: usize = 64;
/// Maximum number of `fetch.cookies` entries.
pub const MAX_COOKIES: usize = 64;
/// Maximum length in bytes of one header or cookie value, and of a User-Agent string.
pub const MAX_VALUE_LEN: usize = 8192;

/// Schemes whose values name a secret instead of holding it (resolved by the worker's
/// `ChainResolver`). `https://…` and other URL-shaped values stay literal, so a `Referer`
/// header is not mistaken for a reference.
const REFERENCE_SCHEMES: [&str; 4] = ["env", "file", "vault", "aws-sm"];

/// Header names (lower-case) that `fetch.extraHeaders` rejects: framing and routing headers
/// the transport owns, `Cookie` and `User-Agent` (use `fetch.cookies` and `fetch.userAgent`).
/// `Proxy-*` and `Crawlx-*` are rejected by prefix.
const DENIED_HEADERS: [&str; 7] = [
    "host",
    "content-length",
    "cookie",
    "user-agent",
    "connection",
    "transfer-encoding",
    "upgrade",
];

/// `fetch.extraHeaders`: request headers added to every request of both planes. Names are
/// case-insensitive and stored lower-case after normalization; every value is a secret, so
/// `Debug` prints names only.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExtraHeaders(BTreeMap<String, String>);

impl ExtraHeaders {
    /// Empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Set `name` (stored as given; [`CreateCrawl::normalize`] lower-cases and validates it),
    /// returning the previous value.
    ///
    /// [`CreateCrawl::normalize`]: crate::config::CreateCrawl::normalize
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) -> Option<String> {
        self.0.insert(name.into(), value.into())
    }

    /// Value of `name` (exact key match).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// `(name, value)` pairs in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of headers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No header is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Same names, every value replaced by `[redacted]`.
    #[must_use]
    pub fn redacted(&self) -> Self {
        Self(
            self.0
                .keys()
                .map(|k| (k.clone(), REDACTED_PLACEHOLDER.to_owned()))
                .collect(),
        )
    }

    /// Lower-case every name; `Err` carries the names that collide afterwards.
    fn lowercase(&mut self) -> Result<(), Vec<String>> {
        let mut out = BTreeMap::new();
        let mut dup = Vec::new();
        for (k, v) in std::mem::take(&mut self.0) {
            let lower = k.trim().to_ascii_lowercase();
            if out.insert(lower.clone(), v).is_some() {
                dup.push(lower);
            }
        }
        self.0 = out;
        if dup.is_empty() {
            Ok(())
        } else {
            Err(dup)
        }
    }
}

impl FromIterator<(String, String)> for ExtraHeaders {
    fn from_iter<I: IntoIterator<Item = (String, String)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl fmt::Debug for ExtraHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|k| (k, REDACTED_PLACEHOLDER)))
            .finish()
    }
}

/// One `fetch.cookies[]` entry. `domain` defaults to the seed's registrable domain (host for
/// an IP or single-label seed host) and `path` to `/`. The value is a secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FetchCookie {
    /// Cookie name: an RFC 6265 token.
    pub name: String,
    /// Cookie value (literal or credential reference); no `;`, whitespace or control characters.
    pub value: String,
    /// Domain the cookie is sent to: the host itself and its subdomains. `None` scopes the
    /// cookie to the seed's registrable domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Path prefix the cookie is sent for; `None` means `/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl FetchCookie {
    /// Cookie scoped to the seed's domain and `/`.
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            domain: None,
            path: None,
        }
    }

    /// Same cookie with the value replaced by `[redacted]`.
    #[must_use]
    pub fn redacted(&self) -> Self {
        Self {
            value: REDACTED_PLACEHOLDER.to_owned(),
            ..self.clone()
        }
    }
}

impl fmt::Debug for FetchCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchCookie")
            .field("name", &self.name)
            .field("value", &REDACTED_PLACEHOLDER)
            .field("domain", &self.domain)
            .field("path", &self.path)
            .finish()
    }
}

/// `true` when `value` names a secret instead of holding it.
#[must_use]
pub fn is_credential_reference(value: &str) -> bool {
    value
        .split_once("://")
        .is_some_and(|(scheme, _)| REFERENCE_SCHEMES.contains(&scheme))
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Header-value bytes: visible ASCII, space, tab and obs-text; no CR, LF or NUL.
fn is_header_value(s: &str) -> bool {
    s.len() <= MAX_VALUE_LEN
        && s.bytes()
            .all(|b| b == b'\t' || (b' '..=b'~').contains(&b) || b >= 0x80)
}

fn is_cookie_value(s: &str) -> bool {
    s.len() <= MAX_VALUE_LEN
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && b != b';' && b != b'"' || b >= 0x80)
}

fn is_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'[' | b']'))
}

/// Lower-cased domain without a leading dot.
fn clean_domain(s: &str) -> String {
    s.trim().trim_start_matches('.').to_ascii_lowercase()
}

/// Cookies of one `Cookie:` header value: `a=b; c=d`.
fn parse_cookie_header(value: &str) -> Result<Vec<FetchCookie>, CoreError> {
    let mut out = Vec::new();
    for pair in value.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (name, val) = pair.split_once('=').ok_or_else(|| CoreError::Invalid {
            field: "fetch.cookies",
            reason: "a Cookie header holds name=value pairs".to_owned(),
        })?;
        out.push(FetchCookie::new(name.trim(), val.trim()));
    }
    Ok(out)
}

impl Fetch {
    /// Route one raw request header (as written after `-H` or in a Firecrawl `headers` map):
    /// `Cookie` becomes [`Fetch::cookies`], `User-Agent` becomes [`Fetch::user_agent`], every
    /// other header goes to [`Fetch::extra_headers`] (a repeated name replaces the value).
    ///
    /// # Errors
    /// [`CoreError::Invalid`] when a `Cookie` value holds a pair without `=`.
    pub fn set_header(&mut self, name: &str, value: &str) -> Result<(), CoreError> {
        let lower = name.trim().to_ascii_lowercase();
        match lower.as_str() {
            "cookie" => self.cookies.extend(parse_cookie_header(value)?),
            "user-agent" => self.user_agent = Some(value.trim().to_owned()),
            _ => {
                self.extra_headers.insert(lower, value.trim().to_owned());
            }
        }
        Ok(())
    }

    /// Clone with every header and cookie value replaced by `[redacted]`.
    #[must_use]
    pub fn redacted(&self) -> Self {
        Self {
            extra_headers: self.extra_headers.redacted(),
            cookies: self.cookies.iter().map(FetchCookie::redacted).collect(),
            ..self.clone()
        }
    }

    /// Whether any header or cookie contains a literal secret instead of a credential reference.
    #[must_use]
    pub fn has_literal_secrets(&self) -> bool {
        self.extra_headers
            .iter()
            .any(|(_, value)| !is_credential_reference(value))
            || self
                .cookies
                .iter()
                .any(|cookie| !is_credential_reference(&cookie.value))
    }

    /// Durable request controls: preserve credential references, never literal secret values.
    ///
    /// Workers must recover literal values from the bounded volatile delivery authority before use.
    #[must_use]
    pub fn durable(&self) -> Self {
        let mut fetch = self.clone();
        fetch.extra_headers = self
            .extra_headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_owned(),
                    if is_credential_reference(value) {
                        value
                    } else {
                        REDACTED_PLACEHOLDER
                    }
                    .to_owned(),
                )
            })
            .collect();
        for cookie in &mut fetch.cookies {
            if !is_credential_reference(&cookie.value) {
                cookie.value = REDACTED_PLACEHOLDER.to_owned();
            }
        }
        fetch
    }

    /// Lower-case, bound and validate the request controls (called by `CreateCrawl::normalize`).
    pub(crate) fn normalize_controls(&mut self, errs: &mut Vec<CoreError>) {
        let invalid = |field: &'static str, reason: String| CoreError::Invalid { field, reason };
        if let Err(dup) = self.extra_headers.lowercase() {
            errs.push(invalid(
                "fetch.extraHeaders",
                format!("header names are case-insensitive; repeated: {}", dup.join(", ")),
            ));
        }
        if self.extra_headers.len() > MAX_EXTRA_HEADERS {
            errs.push(invalid(
                "fetch.extraHeaders",
                format!("at most {MAX_EXTRA_HEADERS} headers"),
            ));
        }
        for (name, value) in self.extra_headers.iter() {
            if !is_token(name) {
                errs.push(invalid(
                    "fetch.extraHeaders",
                    format!("{name:?} is not a valid header name"),
                ));
            } else if DENIED_HEADERS.contains(&name)
                || name.starts_with("proxy-")
                || name.starts_with("crawlx-")
            {
                let hint = match name {
                    "cookie" => "; use fetch.cookies",
                    "user-agent" => "; use fetch.userAgent",
                    _ => "",
                };
                errs.push(invalid(
                    "fetch.extraHeaders",
                    format!("header {name} is not allowed{hint}"),
                ));
            }
            if !is_header_value(value) {
                errs.push(invalid(
                    "fetch.extraHeaders",
                    format!("the value of {name} has a control character or exceeds {MAX_VALUE_LEN} bytes"),
                ));
            }
        }

        if self.cookies.len() > MAX_COOKIES {
            errs.push(invalid("fetch.cookies", format!("at most {MAX_COOKIES} cookies")));
        }
        let mut seen = std::collections::BTreeSet::new();
        for c in &mut self.cookies {
            c.name = c.name.trim().to_owned();
            c.domain = c.domain.take().map(|d| clean_domain(&d));
            c.path = c.path.take().map(|p| p.trim().to_owned());
            if !is_token(&c.name) {
                errs.push(invalid(
                    "fetch.cookies[].name",
                    format!("{:?} is not a cookie name", c.name),
                ));
            }
            if !is_cookie_value(&c.value) {
                errs.push(invalid(
                    "fetch.cookies[].value",
                    format!(
                        "the value of {} has a ';', quote, space or control character, or exceeds {MAX_VALUE_LEN} bytes",
                        c.name
                    ),
                ));
            }
            if c.domain.as_deref().is_some_and(|d| !is_domain(d)) {
                errs.push(invalid(
                    "fetch.cookies[].domain",
                    format!("{:?} is not a host name", c.domain.as_deref().unwrap_or_default()),
                ));
            }
            if c.path
                .as_deref()
                .is_some_and(|p| !p.starts_with('/') || !is_header_value(p) || p.contains(';'))
            {
                errs.push(invalid(
                    "fetch.cookies[].path",
                    format!("{:?} must start with '/'", c.path.as_deref().unwrap_or_default()),
                ));
            }
            if !seen.insert((c.name.clone(), c.domain.clone(), c.path.clone())) {
                errs.push(invalid(
                    "fetch.cookies",
                    format!("duplicate cookie {} for the same domain and path", c.name),
                ));
            }
        }

        for (ua, field) in [
            (&mut self.user_agent, "fetch.userAgent"),
            (&mut self.robots_user_agent, "fetch.robotsUserAgent"),
        ] {
            if let Some(v) = ua {
                *v = v.trim().to_owned();
                if v.is_empty() || v.len() > 512 || !is_header_value(v) {
                    errs.push(invalid(
                        field,
                        "must be 1 to 512 bytes without control characters".to_owned(),
                    ));
                }
            }
        }
    }
}

/// One cookie of a running crawl: value resolved, domain fixed.
#[derive(Clone)]
pub struct ControlCookie {
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: SecretOr<String>,
    /// Lower-case domain without a leading dot: host and subdomains match (an IP host only
    /// matches itself).
    pub domain: String,
    /// Path prefix, starting with `/`.
    pub path: String,
}

/// `host` is `domain` or one of its subdomains (an IP literal only matches itself); both
/// lower-case, either possibly an IPv6 literal in brackets.
fn domain_matches(host: &str, domain: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let domain = domain.trim_start_matches('[').trim_end_matches(']');
    host == domain
        || (host.parse::<IpAddr>().is_err()
            && host.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.')))
}

impl ControlCookie {
    /// The cookie is sent to `host` (lower-case) for `path`.
    #[must_use]
    pub fn matches(&self, host: &str, path: &str) -> bool {
        let domain_ok = domain_matches(host, &self.domain);
        let path = if path.is_empty() { "/" } else { path };
        let path_ok = self.path == "/"
            || path == self.path
            || path
                .strip_prefix(self.path.as_str())
                .is_some_and(|rest| self.path.ends_with('/') || rest.starts_with('/'));
        domain_ok && path_ok
    }
}

impl fmt::Debug for ControlCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlCookie")
            .field("name", &self.name)
            .field("value", &REDACTED_PLACEHOLDER)
            .field("domain", &self.domain)
            .field("path", &self.path)
            .finish()
    }
}

/// The request controls a run executes with: `fetch.extraHeaders`, `fetch.cookies`,
/// `fetch.userAgent`, `fetch.robotsUserAgent` and `fetch.skipTlsVerification` after credential
/// references were resolved. `Debug` never prints a value.
#[derive(Clone, Default, Debug)]
pub struct RequestControls {
    headers: BTreeMap<String, SecretOr<String>>,
    cookies: Vec<ControlCookie>,
    user_agent: Option<String>,
    robots_user_agent: Option<String>,
    skip_tls_verification: bool,
    scope_domain: String,
}

impl RequestControls {
    /// Resolve the request controls of `fetch`. Values that are credential references are
    /// looked up through `secrets` (each value exactly once). `scope_domain` (the seed's
    /// registrable domain, or its host for an IP or single-label host) limits where header
    /// values and cookies without a `domain` are sent; see [`Self::applies_to`].
    ///
    /// # Errors
    /// [`CoreError::CredentialUnavailable`] when a reference cannot be resolved or `secrets`
    /// is `None`; [`CoreError::Invalid`] when a resolved value is not a valid header or
    /// cookie value.
    pub async fn resolve(
        fetch: &Fetch,
        scope_domain: &str,
        secrets: Option<&dyn SecretResolver>,
    ) -> Result<Self, CoreError> {
        let mut headers = BTreeMap::new();
        for (name, value) in fetch.extra_headers.iter() {
            let v = resolve_value(value, secrets).await?;
            if !is_header_value(v.expose()) {
                return Err(CoreError::Invalid {
                    field: "fetch.extraHeaders",
                    reason: format!("the resolved value of {name} is not a valid header value"),
                });
            }
            headers.insert(name.to_ascii_lowercase(), v);
        }
        let default_domain = clean_domain(scope_domain);
        let mut cookies = Vec::with_capacity(fetch.cookies.len());
        for c in &fetch.cookies {
            let value = resolve_value(&c.value, secrets).await?;
            if !is_cookie_value(value.expose()) {
                return Err(CoreError::Invalid {
                    field: "fetch.cookies[].value",
                    reason: format!("the resolved value of {} is not a valid cookie value", c.name),
                });
            }
            cookies.push(ControlCookie {
                name: c.name.clone(),
                value,
                domain: c
                    .domain
                    .as_deref()
                    .map_or_else(|| default_domain.clone(), clean_domain),
                path: c.path.clone().unwrap_or_else(|| "/".to_owned()),
            });
        }
        Ok(Self {
            headers,
            cookies,
            user_agent: fetch.user_agent.clone(),
            robots_user_agent: fetch.robots_user_agent.clone(),
            skip_tls_verification: fetch.skip_tls_verification,
            scope_domain: default_domain,
        })
    }

    /// Extra headers by lower-case name.
    #[must_use]
    pub const fn headers(&self) -> &BTreeMap<String, SecretOr<String>> {
        &self.headers
    }

    /// Cookies in request order.
    #[must_use]
    pub fn cookies(&self) -> &[ControlCookie] {
        &self.cookies
    }

    /// `fetch.userAgent`; `None` keeps the plane's own value.
    #[must_use]
    pub fn user_agent(&self) -> Option<&str> {
        self.user_agent.as_deref()
    }

    /// UA robots.txt groups are matched with: `fetch.robotsUserAgent`, else `fetch.userAgent`,
    /// else `None` (the caller's default).
    #[must_use]
    pub fn robots_user_agent(&self) -> Option<&str> {
        self.robots_user_agent.as_deref().or(self.user_agent.as_deref())
    }

    /// Both planes accept any server certificate.
    #[must_use]
    pub const fn skip_tls_verification(&self) -> bool {
        self.skip_tls_verification
    }

    /// Header values go to `host` (lower-case): the seed's domain and its subdomains. A
    /// redirect or link to another registrable domain never receives them (secrets do not
    /// follow the crawl onto third-party hosts). Cookies carry their own `domain`.
    #[must_use]
    pub fn applies_to(&self, host: &str) -> bool {
        !self.scope_domain.is_empty() && domain_matches(host, &self.scope_domain)
    }

    /// No header, cookie, UA or TLS control is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
            && self.cookies.is_empty()
            && self.user_agent.is_none()
            && !self.skip_tls_verification
    }

    /// `Cookie:` value for a request to `host` (lower-case) and `path`: matching cookies in
    /// configuration order, `None` when none matches.
    #[must_use]
    pub fn cookie_header(&self, host: &str, path: &str) -> Option<String> {
        let mut out = String::new();
        for c in self.cookies.iter().filter(|c| c.matches(host, path)) {
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(&c.name);
            out.push('=');
            out.push_str(c.value.expose());
        }
        (!out.is_empty()).then_some(out)
    }

    /// Every secret value (header values, cookie values), for redacting echoes of them in
    /// captured traffic. Values shorter than 4 bytes are skipped: masking them would redact
    /// unrelated text.
    pub fn secret_values(&self) -> impl Iterator<Item = &str> {
        self.headers
            .values()
            .map(|v| v.expose().as_str())
            .chain(self.cookies.iter().map(|c| c.value.expose().as_str()))
            .filter(|v| v.len() >= 4)
    }

    /// `value` holds a configured header or cookie value (an echo of a secret).
    #[must_use]
    pub fn echoes_secret(&self, value: &str) -> bool {
        self.secret_values().any(|s| value.contains(s))
    }

    /// Replace by [`REDACTED_PLACEHOLDER`] the value of every header named in
    /// `fetch.extraHeaders` and of every header (a server may echo a request header back,
    /// a proxy may add one) whose value contains a configured header or cookie value. Run
    /// on every captured header list before it leaves the plane that saw it.
    pub fn mask_headers(&self, headers: &mut [(String, String)]) {
        if self.headers.is_empty() && self.cookies.is_empty() {
            return;
        }
        for (name, value) in headers {
            if self.headers.contains_key(&name.to_ascii_lowercase()) || self.echoes_secret(value) {
                REDACTED_PLACEHOLDER.clone_into(value);
            }
        }
    }
}

async fn resolve_value(
    value: &str,
    secrets: Option<&dyn SecretResolver>,
) -> Result<SecretOr<String>, CoreError> {
    if !is_credential_reference(value) {
        return Ok(SecretOr::secret(value.to_owned()));
    }
    let reference = CredentialRef(value.to_owned());
    let Some(resolver) = secrets else {
        return Err(CoreError::CredentialUnavailable(reference.0));
    };
    let resolved = resolver.resolve(&reference).await?;
    Ok(SecretOr::secret(resolved.expose().clone()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::config::CreateCrawl;

    fn crawl(fetch: &str) -> CreateCrawl {
        serde_json::from_str(&format!(r#"{{"seedUrl":"https://a.test/","fetch":{fetch}}}"#)).unwrap()
    }

    fn fields(errs: &[CoreError]) -> Vec<&'static str> {
        errs.iter()
            .filter_map(|e| match e {
                CoreError::Invalid { field, .. } => Some(*field),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn wire_shape_roundtrips_and_defaults_stay_off_the_wire() {
        let mut c = crawl(
            r#"{"extraHeaders":{"X-Api-Key":"k-123456","Accept-Language":"de"},
                "cookies":[{"name":"sid","value":"abc","domain":".A.test","path":"/app"},{"name":"t","value":"1"}],
                "userAgent":"  bot/1  ","robotsUserAgent":"botx","skipTlsVerification":true}"#,
        );
        c.normalize().unwrap();
        assert_eq!(c.fetch.extra_headers.get("x-api-key"), Some("k-123456"));
        assert_eq!(c.fetch.cookies[0].domain.as_deref(), Some("a.test"));
        assert_eq!(c.fetch.user_agent.as_deref(), Some("bot/1"));
        let back: CreateCrawl = serde_json::from_value(serde_json::to_value(&c).unwrap()).unwrap();
        assert_eq!(back.fetch, c.fetch);

        let plain =
            serde_json::to_value(CreateCrawl::new(url::Url::parse("https://a.test/").unwrap())).unwrap();
        for key in [
            "extraHeaders",
            "cookies",
            "userAgent",
            "robotsUserAgent",
            "skipTlsVerification",
        ] {
            assert!(plain["fetch"].get(key).is_none(), "{key} serialized by default");
        }
    }

    #[test]
    fn debug_and_redacted_views_never_print_a_value() {
        let mut c = crawl(
            r#"{"extraHeaders":{"x-api-key":"super-secret-1"},"cookies":[{"name":"sid","value":"super-secret-2"}]}"#,
        );
        c.normalize().unwrap();
        for text in [format!("{:?}", c.fetch), format!("{c:?}")] {
            assert!(!text.contains("super-secret"), "{text}");
            assert!(text.contains("x-api-key") && text.contains("sid"), "{text}");
        }
        let json = serde_json::to_string(&c.redacted()).unwrap();
        assert!(!json.contains("super-secret"), "{json}");
        assert_eq!(
            c.redacted().fetch.extra_headers.get("x-api-key"),
            Some("[redacted]")
        );
        assert_eq!(c.redacted().fetch.cookies[0].value, "[redacted]");
        assert_eq!(c.fetch.extra_headers.get("x-api-key"), Some("super-secret-1"));
    }

    #[test]
    fn validation_rejects_denied_and_malformed_controls() {
        let mut c = crawl(
            r#"{"extraHeaders":{"Host":"x","Cookie":"a=b","User-Agent":"u","Proxy-Authorization":"p","crawlx-trace":"1",
                "bad name":"v","x-ok":"line\nbreak","X-Dup":"1","x-dup":"2"},
                "cookies":[{"name":"a b","value":"v"},{"name":"c","value":"x;y"},{"name":"d","value":"v","domain":"a/b"},
                           {"name":"e","value":"v","path":"rel"},{"name":"f","value":"1"},{"name":"f","value":"2"}],
                "userAgent":"  ","robotsUserAgent":"bot\u0007"}"#,
        );
        let errs = c.normalize().unwrap_err();
        let f = fields(&errs);
        for expected in [
            "fetch.extraHeaders",
            "fetch.cookies[].name",
            "fetch.cookies[].value",
            "fetch.cookies[].domain",
            "fetch.cookies[].path",
            "fetch.cookies",
            "fetch.userAgent",
            "fetch.robotsUserAgent",
        ] {
            assert!(f.contains(&expected), "missing {expected} in {f:?}");
        }
        let text: String = errs
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        for denied in [
            "host",
            "cookie",
            "user-agent",
            "proxy-authorization",
            "crawlx-trace",
        ] {
            assert!(
                text.contains(&format!("header {denied} is not allowed")),
                "{denied}: {text}"
            );
        }
        assert!(text.contains("use fetch.cookies") && text.contains("use fetch.userAgent"));
        assert!(!text.contains("line"), "error text echoed a value: {text}");
    }

    #[test]
    fn limits_bound_counts() {
        let mut c = CreateCrawl::new(url::Url::parse("https://a.test/").unwrap());
        for i in 0..=MAX_EXTRA_HEADERS {
            c.fetch.extra_headers.insert(format!("x-h{i}"), "v");
        }
        c.fetch.cookies = (0..=MAX_COOKIES)
            .map(|i| FetchCookie::new(format!("c{i}"), "v"))
            .collect();
        let f = fields(&c.normalize().unwrap_err()).join(",");
        assert!(
            f.contains("fetch.extraHeaders") && f.contains("fetch.cookies"),
            "{f}"
        );
    }

    #[test]
    fn set_header_routes_cookie_and_user_agent() {
        let mut f = Fetch::default();
        f.set_header("Cookie", "a=1; b=2").unwrap();
        f.set_header("USER-AGENT", " agent/9 ").unwrap();
        f.set_header("X-Token", " t ").unwrap();
        assert_eq!(
            f.cookies.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(f.cookies[1].value, "2");
        assert_eq!(f.user_agent.as_deref(), Some("agent/9"));
        assert_eq!(f.extra_headers.get("x-token"), Some("t"));
        assert!(f.set_header("Cookie", "nameless").is_err());
    }

    #[test]
    fn cookie_matching_follows_domain_and_path_rules() {
        let cookie = |domain: &str, path: &str| ControlCookie {
            name: "k".to_owned(),
            value: SecretOr::secret("v".to_owned()),
            domain: domain.to_owned(),
            path: path.to_owned(),
        };
        let c = cookie("example.com", "/app");
        assert!(c.matches("example.com", "/app"));
        assert!(c.matches("www.example.com", "/app/x"));
        assert!(!c.matches("notexample.com", "/app"));
        assert!(!c.matches("example.com", "/apple"));
        assert!(!c.matches("example.com", "/"));
        assert!(cookie("example.com", "/").matches("a.b.example.com", ""));
        let ip = cookie("10.0.0.1", "/");
        assert!(ip.matches("10.0.0.1", "/x"));
        assert!(!ip.matches("10.0.0.2", "/x"));
        assert!(!cookie("0.0.1", "/").matches("10.0.0.1", "/"));
        assert!(cookie("::1", "/").matches("[::1]", "/"));
    }

    struct Vault;
    #[async_trait::async_trait]
    impl SecretResolver for Vault {
        async fn resolve(&self, r: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
            match r.0.as_str() {
                "env://TOKEN" => Ok(SecretOr::secret("resolved-token".to_owned())),
                other => Err(CoreError::CredentialUnavailable(other.to_owned())),
            }
        }
    }

    #[tokio::test]
    async fn resolve_expands_references_and_scopes_cookies() {
        let mut f = Fetch::default();
        f.extra_headers.insert("authorization", "env://TOKEN");
        f.extra_headers.insert("referer", "https://a.test/page");
        f.cookies = vec![
            FetchCookie::new("sid", "env://TOKEN"),
            FetchCookie {
                domain: Some("other.test".to_owned()),
                path: Some("/p".to_owned()),
                ..FetchCookie::new("lit", "v")
            },
        ];
        f.user_agent = Some("ua/1".to_owned());
        let c = RequestControls::resolve(&f, "a.test", Some(&Vault))
            .await
            .unwrap();
        assert_eq!(c.headers()["authorization"].expose(), "resolved-token");
        assert_eq!(c.headers()["referer"].expose(), "https://a.test/page");
        assert_eq!(
            c.cookie_header("www.a.test", "/x").as_deref(),
            Some("sid=resolved-token")
        );
        assert_eq!(c.cookie_header("other.test", "/p/1").as_deref(), Some("lit=v"));
        assert_eq!(c.cookie_header("elsewhere.test", "/").as_deref(), None);
        assert_eq!(c.robots_user_agent(), Some("ua/1"));
        assert!(c.applies_to("a.test") && c.applies_to("www.a.test"));
        assert!(!c.applies_to("evil.test") && !c.applies_to("nota.test"));
        assert!(!format!("{c:?}").contains("resolved-token"));
        assert!(c.secret_values().any(|v| v == "resolved-token"));

        let err = RequestControls::resolve(&f, "a.test", None).await.unwrap_err();
        assert!(matches!(err, CoreError::CredentialUnavailable(r) if r == "env://TOKEN"));
        f.extra_headers.insert("authorization", "vault://kv/x#k");
        assert!(RequestControls::resolve(&f, "a.test", Some(&Vault))
            .await
            .is_err());
    }

    #[test]
    fn reference_detection_is_limited_to_secret_schemes() {
        for r in [
            "env://X",
            "file:///run/secrets/t",
            "vault://kv/a#b",
            "aws-sm://id#k",
        ] {
            assert!(is_credential_reference(r), "{r}");
        }
        for v in ["https://a.test/", "Bearer abc", "totp://ABC", "env:X", ""] {
            assert!(!is_credential_reference(v), "{v}");
        }
    }

    #[tokio::test]
    async fn mask_headers_covers_configured_names_and_echoed_values() {
        let mut f = Fetch::default();
        f.extra_headers.insert("x-tenant", "tenant-value-1");
        f.extra_headers.insert("x-short", "ab");
        f.cookies.push(FetchCookie::new("sid", "cookie-value-2"));
        let c = RequestControls::resolve(&f, "a.test", None).await.unwrap();
        let mut headers = vec![
            ("X-Tenant".to_owned(), "anything".to_owned()),
            ("x-short".to_owned(), "ab".to_owned()),
            ("via".to_owned(), "proxy for tenant-value-1".to_owned()),
            ("x-echo".to_owned(), "cookie-value-2".to_owned()),
            ("accept".to_owned(), "ab and more".to_owned()),
        ];
        c.mask_headers(&mut headers);
        let masked: Vec<&str> = headers.iter().map(|(_, v)| v.as_str()).collect();
        // configured names are masked whatever the value; a value is matched only from 4 bytes
        assert_eq!(
            masked,
            [
                REDACTED_PLACEHOLDER,
                REDACTED_PLACEHOLDER,
                REDACTED_PLACEHOLDER,
                REDACTED_PLACEHOLDER,
                "ab and more"
            ]
        );
        assert!(c.echoes_secret("see cookie-value-2 here") && !c.echoes_secret("ab"));
        // nothing configured, nothing masked
        let mut untouched = vec![("x-tenant".to_owned(), "v".to_owned())];
        RequestControls::default().mask_headers(&mut untouched);
        assert_eq!(untouched[0].1, "v");
    }

    #[tokio::test]
    async fn an_ipv6_seed_scopes_to_itself_with_or_without_brackets() {
        let c = RequestControls::resolve(&Fetch::default(), "[::1]", None)
            .await
            .unwrap();
        assert!(c.applies_to("[::1]") && c.applies_to("::1"));
        assert!(!c.applies_to("[::2]"));
    }
}
