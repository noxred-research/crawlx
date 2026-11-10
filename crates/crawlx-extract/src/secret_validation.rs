//! Online secret validation plans (`extract.validateSecrets`, compatibility flag
//! `-kb-validate-secrets`).
//!
//! The reference implementation's scanning engine confirms a detected credential by calling the
//! provider's API. crawlx does the same only when an operator supplies a
//! validator file, and keeps this crate free of I/O: [`SecretValidators::plan`]
//! turns a detected token into the [`ValidationRequest`] to send (through the
//! egress-checked fetch plane, which must not follow redirects) and
//! [`SecretValidators::interpret`] turns the answer into a [`Validity`]. The
//! token is only ever held transiently (see
//! [`SecretToken`](crate::secrets::SecretToken)); nothing here stores or logs it,
//! and the `Debug` of a [`ValidationRequest`] shows no URL path, query or header
//! value.
//!
//! The embedded list (`data/secret_validators.json`) is empty: a validation is
//! a live call that shows up in the credential owner's audit log, so no
//! provider is contacted unless the operator opted in with a file.
//!
//! # File format
//!
//! ```json
//! {
//!   "version": 1,
//!   "validators": [
//!     {
//!       "kind": "github_token",
//!       "method": "GET",
//!       "url": "https://api.github.com/user",
//!       "headers": { "Authorization": "Bearer {token}" },
//!       "valid_status": [200],
//!       "invalid_status": [401]
//!     },
//!     {
//!       "kind": "generic_api_key",
//!       "url": "https://validator.example/api/check?token={token}",
//!       "valid_status": [200],
//!       "invalid_status": [401],
//!       "body_regex": "\"ok\"\\s*:\\s*true"
//!     }
//!   ]
//! }
//! ```
//!
//! * `kind`: a [`SecretKind`] wire name; at most one validator per kind.
//! * `method`: `GET` (default) or `HEAD`.
//! * `url`: absolute `https` URL. `{token}` may appear in the path or query
//!   (percent-encoded on substitution) but never in the scheme, userinfo,
//!   host or port, so a token can not steer the request to another host.
//! * `headers`: name to value template; `{token}` is substituted verbatim.
//!   Tokens with characters outside printable ASCII are never validated.
//! * `valid_status`, `invalid_status`: disjoint status lists; `valid_status`
//!   is required. Any other status (rate limit, server error) is
//!   [`Validity::Unknown`].
//! * `body_regex` (optional): a `valid_status` response is only
//!   [`Validity::Valid`] when the first 64 KiB of the body match; otherwise it
//!   is [`Validity::Invalid`] (APIs that answer `200` with `{"ok": false}`).
//! * `allow_http` (optional, default false): permit a plain-`http` URL.
//!
//! At least one `{token}` must appear in the URL or a header.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::secrets::SecretKind;

/// The embedded validator list (empty).
const BUILTIN: &str = include_str!("../data/secret_validators.json");
/// File format version.
const FORMAT_VERSION: u32 = 1;
/// Placeholder replaced by the token.
const PLACEHOLDER: &str = "{token}";
/// Longest token that is planned.
const MAX_TOKEN_LEN: usize = 4096;
/// Response body bytes matched against `body_regex`.
const MAX_BODY_BYTES: usize = 64 * 1024;

/// Verdict of a validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Validity {
    /// The provider accepted the credential.
    Valid,
    /// The provider rejected the credential.
    Invalid,
    /// No verdict: no validator for the kind, or an inconclusive response.
    Unknown,
}

impl Validity {
    /// Wire name (`valid`, `invalid`, `unknown`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Unknown => "unknown",
        }
    }
}

/// Errors loading a validator file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ValidatorError {
    /// The file could not be read.
    #[error("could not read validator file {}", path.display())]
    Io {
        /// File that was read.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The text is not the documented JSON.
    #[error("validator file is not valid")]
    Json(#[from] serde_json::Error),
    /// `version` is not the supported one.
    #[error("unsupported validator file version {0} (expected {FORMAT_VERSION})")]
    Version(u32),
    /// `kind` is not a secret kind crawlx detects.
    #[error("validator kind `{0}` is not a detected secret kind")]
    UnknownKind(String),
    /// Two validators for one kind.
    #[error("validator kind `{0}` is listed twice")]
    DuplicateKind(String),
    /// `method` is neither `GET` nor `HEAD`.
    #[error("validator `{kind}`: method `{method}` is not GET or HEAD")]
    UnsupportedMethod {
        /// Validator kind.
        kind: String,
        /// The rejected method.
        method: String,
    },
    /// The URL template is unusable.
    #[error("validator `{kind}`: url {reason}")]
    BadUrl {
        /// Validator kind.
        kind: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A header name or template is not a valid HTTP header.
    #[error("validator `{kind}`: header `{name}` is not a valid http header")]
    BadHeader {
        /// Validator kind.
        kind: String,
        /// Offending header name.
        name: String,
    },
    /// Neither the URL nor a header mentions `{token}`.
    #[error("validator `{kind}`: neither url nor headers contain {PLACEHOLDER}")]
    NoToken {
        /// Validator kind.
        kind: String,
    },
    /// The status lists are empty or overlap.
    #[error("validator `{kind}`: {reason}")]
    BadStatus {
        /// Validator kind.
        kind: String,
        /// What is wrong with them.
        reason: &'static str,
    },
    /// `body_regex` does not compile.
    #[error("validator `{kind}`: body_regex does not compile")]
    BadBodyRegex {
        /// Validator kind.
        kind: String,
        /// Compile error.
        #[source]
        source: regex::Error,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileFormat {
    version: u32,
    validators: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    kind: String,
    #[serde(default = "default_method")]
    method: String,
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    valid_status: Vec<u16>,
    #[serde(default)]
    invalid_status: Vec<u16>,
    #[serde(default)]
    body_regex: Option<String>,
    #[serde(default)]
    allow_http: bool,
}

fn default_method() -> String {
    "GET".to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Head,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

/// Scheme, host and port a planned request must keep.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    fn of(url: &Url) -> Option<Self> {
        Some(Self {
            scheme: url.scheme().to_owned(),
            host: url.host_str()?.to_owned(),
            port: url.port(),
        })
    }
}

#[derive(Debug)]
struct Validator {
    method: Method,
    url: String,
    origin: Origin,
    headers: Vec<(String, String)>,
    valid_status: BTreeSet<u16>,
    invalid_status: BTreeSet<u16>,
    body_regex: Option<Regex>,
}

/// A request that validates one token. Send it as is, without following
/// redirects.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidationRequest {
    /// Target: the validator's URL with the token substituted.
    pub url: Url,
    /// `GET` or `HEAD`.
    pub method: String,
    /// Header names and values with the token substituted.
    pub headers: Vec<(String, String)>,
}

impl fmt::Debug for ValidationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationRequest")
            .field("method", &self.method)
            .field("host", &self.url.host_str())
            .field(
                "headers",
                &self.headers.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// The configured validators, by secret kind.
#[derive(Debug, Default)]
pub struct SecretValidators {
    by_kind: BTreeMap<String, Validator>,
}

impl SecretValidators {
    /// The embedded list, which is empty.
    #[must_use]
    pub fn builtin() -> Self {
        Self::from_json(BUILTIN).unwrap_or_default()
    }

    /// Read a validator file (see the [module docs](self) for the format).
    /// Blocking I/O: call it at start-up or from a blocking task.
    ///
    /// # Errors
    ///
    /// [`ValidatorError::Io`] when the file cannot be read, otherwise the
    /// errors of [`from_json`](Self::from_json).
    pub fn load(path: &Path) -> Result<Self, ValidatorError> {
        let text = std::fs::read_to_string(path).map_err(|source| ValidatorError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&text)
    }

    /// Parse and validate a validator file's text.
    ///
    /// # Errors
    ///
    /// [`ValidatorError`] when the text is not the documented JSON, names a
    /// kind crawlx does not detect (or twice), or holds a validator that is
    /// not safe to run: a method other than `GET`/`HEAD`, a URL that is not
    /// absolute `https` (unless `allow_http`) or has `{token}` in its
    /// authority, a bad header, no `{token}` at all, empty or overlapping
    /// status lists, or a `body_regex` that does not compile.
    pub fn from_json(text: &str) -> Result<Self, ValidatorError> {
        let file: FileFormat = serde_json::from_str(text)?;
        if file.version != FORMAT_VERSION {
            return Err(ValidatorError::Version(file.version));
        }
        let mut by_kind = BTreeMap::new();
        for entry in file.validators {
            let kind = entry.kind.clone();
            if SecretKind::from_wire(&kind).is_none() {
                return Err(ValidatorError::UnknownKind(kind));
            }
            let validator = Validator::compile(entry)?;
            if by_kind.insert(kind.clone(), validator).is_some() {
                return Err(ValidatorError::DuplicateKind(kind));
            }
        }
        Ok(Self { by_kind })
    }

    /// No validator is configured: [`plan`](Self::plan) always returns `None`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_kind.is_empty()
    }

    /// Number of configured validators.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_kind.len()
    }

    /// Whether a validator exists for `kind` (a [`SecretKind::as_str`] name).
    #[must_use]
    pub fn handles(&self, kind: &str) -> bool {
        self.by_kind.contains_key(kind)
    }

    /// The request that validates `token` as a `kind` secret. `None` when
    /// there is no validator for the kind or the token is not safe to
    /// substitute: empty, over 4096 bytes, made only of dots, or holding a
    /// character outside printable ASCII (which would let it break out of a
    /// header or URL component).
    ///
    /// The URL keeps the template's scheme, host and port whatever the token
    /// holds.
    #[must_use]
    pub fn plan(&self, kind: &str, token: &str) -> Option<ValidationRequest> {
        let validator = self.by_kind.get(kind)?;
        if !token_is_safe(token) {
            return None;
        }
        let url = Url::parse(&validator.url.replace(PLACEHOLDER, &percent_encode(token))).ok()?;
        if Origin::of(&url)? != validator.origin {
            return None;
        }
        let headers = validator
            .headers
            .iter()
            .map(|(name, template)| (name.clone(), template.replace(PLACEHOLDER, token)))
            .collect::<Vec<_>>();
        if headers
            .iter()
            .any(|(_, value)| http::HeaderValue::from_str(value).is_err())
        {
            return None;
        }
        Some(ValidationRequest {
            url,
            method: validator.method.as_str().to_owned(),
            headers,
        })
    }

    /// The verdict for a response of a validation planned for `kind`.
    /// [`Validity::Unknown`] when the kind has no validator or the status is
    /// in neither list.
    #[must_use]
    pub fn interpret(&self, kind: &str, status: u16, body: &[u8]) -> Validity {
        let Some(validator) = self.by_kind.get(kind) else {
            return Validity::Unknown;
        };
        if validator.valid_status.contains(&status) {
            return match &validator.body_regex {
                None => Validity::Valid,
                Some(re) => {
                    let head = &body[..body.len().min(MAX_BODY_BYTES)];
                    if re.is_match(&String::from_utf8_lossy(head)) {
                        Validity::Valid
                    } else {
                        Validity::Invalid
                    }
                }
            };
        }
        if validator.invalid_status.contains(&status) {
            return Validity::Invalid;
        }
        Validity::Unknown
    }
}

impl Validator {
    fn compile(entry: Entry) -> Result<Self, ValidatorError> {
        let kind = entry.kind;
        let method = match entry.method.to_ascii_uppercase().as_str() {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            _ => {
                return Err(ValidatorError::UnsupportedMethod {
                    kind,
                    method: entry.method,
                })
            }
        };
        let bad_url = |reason: &'static str| ValidatorError::BadUrl {
            kind: kind.clone(),
            reason,
        };
        let authority_end = entry.url.find("://").map_or(0, |i| i + 3);
        let authority = entry.url[authority_end..]
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default();
        if authority.contains(PLACEHOLDER) {
            return Err(bad_url("must not contain {token} before the path"));
        }
        let parsed = Url::parse(&entry.url.replace(PLACEHOLDER, "x"))
            .map_err(|_| bad_url("is not an absolute url"))?;
        let scheme_ok = parsed.scheme() == "https" || (entry.allow_http && parsed.scheme() == "http");
        if !scheme_ok {
            return Err(bad_url("must use https"));
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(bad_url("must not carry credentials"));
        }
        let origin = Origin::of(&parsed).ok_or_else(|| bad_url("has no host"))?;
        let stray = entry.url.replace(PLACEHOLDER, "");
        if stray.contains(['{', '}']) {
            return Err(bad_url("contains a brace that is not {token}"));
        }

        let mut mentions_token = entry.url.contains(PLACEHOLDER);
        let mut headers = Vec::with_capacity(entry.headers.len());
        for (name, template) in entry.headers {
            let sample = template.replace(PLACEHOLDER, "x");
            if http::HeaderName::from_bytes(name.as_bytes()).is_err()
                || http::HeaderValue::from_str(&sample).is_err()
                || sample.contains(['{', '}'])
            {
                return Err(ValidatorError::BadHeader { kind, name });
            }
            mentions_token |= template.contains(PLACEHOLDER);
            headers.push((name, template));
        }
        if !mentions_token {
            return Err(ValidatorError::NoToken { kind });
        }

        let valid_status: BTreeSet<u16> = entry.valid_status.into_iter().collect();
        let invalid_status: BTreeSet<u16> = entry.invalid_status.into_iter().collect();
        if valid_status.is_empty() {
            return Err(ValidatorError::BadStatus {
                kind,
                reason: "valid_status must not be empty",
            });
        }
        if !valid_status.is_disjoint(&invalid_status) {
            return Err(ValidatorError::BadStatus {
                kind,
                reason: "valid_status and invalid_status overlap",
            });
        }
        let body_regex = entry
            .body_regex
            .map(|re| {
                RegexBuilder::new(&re)
                    .size_limit(1 << 20)
                    .dfa_size_limit(1 << 20)
                    .build()
                    .map_err(|source| ValidatorError::BadBodyRegex {
                        kind: kind.clone(),
                        source,
                    })
            })
            .transpose()?;
        Ok(Self {
            method,
            url: entry.url,
            origin,
            headers,
            valid_status,
            invalid_status,
            body_regex,
        })
    }
}

fn token_is_safe(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_LEN
        && token.bytes().all(|b| b.is_ascii_graphic())
        && !token.bytes().all(|b| b == b'.')
}

/// Percent-encode every byte but the RFC 3986 unreserved set, so the result
/// is inert in any URL component.
fn percent_encode(token: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(token.len());
    for b in token.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn percent_encoding_is_inert() {
        assert_eq!(percent_encode("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(
            percent_encode("a/b?c#d@e:f\\g h"),
            "a%2Fb%3Fc%23d%40e%3Af%5Cg%20h"
        );
    }

    #[test]
    fn embedded_list_parses_and_is_empty() {
        let v = SecretValidators::from_json(BUILTIN).unwrap();
        assert!(v.is_empty());
    }
}
