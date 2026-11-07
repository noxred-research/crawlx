//! Secrets detector (`extract.detectSecrets`): finds
//! credential shapes in headers and bodies and records **only** the kind,
//! the location and a keyed BLAKE3 hash of the value. The
//! raw value is never stored, returned, formatted or logged; findings hold
//! no reference to the scanned text. Katana delegates this to Praetorian's
//! Titus engine (`pkg/knowledgebase/extractors/secrets`); crawlx ships a
//! small fixed pattern table instead. It validates a credential online only
//! through [`crate::secret_validation`], with validators an operator supplies.
use std::sync::LazyLock;

use crawlx_core::hash::Digest;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// Domain tag of [`SecretFinding::value_hash`].
pub const SECRET_HASH_DOMAIN: &str = "crawlx.extract.secret.v1";
/// Cap on findings per response.
pub const MAX_FINDINGS: usize = 256;

/// Credential family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecretKind {
    /// `AKIA…` style AWS access key id.
    AwsAccessKeyId,
    /// 40-character AWS secret in an `aws…secret…=` assignment.
    AwsSecretAccessKey,
    /// `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` / `github_pat_` token.
    #[serde(rename = "github_token", alias = "git_hub_token")]
    GitHubToken,
    /// `xox[baprs]-` Slack token.
    SlackToken,
    /// `sk_live_` / `sk_test_` / `rk_…` Stripe key.
    StripeKey,
    /// `AIza…` Google API key.
    GoogleApiKey,
    /// JSON Web Token with a JSON header and payload.
    Jwt,
    /// PEM private key block.
    PrivateKey,
    /// `api_key=…` / `apiKey: "…"` assignment.
    GenericApiKey,
}

impl SecretKind {
    /// Wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwsAccessKeyId => "aws_access_key_id",
            Self::AwsSecretAccessKey => "aws_secret_access_key",
            Self::GitHubToken => "github_token",
            Self::SlackToken => "slack_token",
            Self::StripeKey => "stripe_key",
            Self::GoogleApiKey => "google_api_key",
            Self::Jwt => "jwt",
            Self::PrivateKey => "private_key",
            Self::GenericApiKey => "generic_api_key",
        }
    }

    /// Every kind, in declaration order.
    pub const ALL: [Self; 9] = [
        Self::AwsAccessKeyId,
        Self::AwsSecretAccessKey,
        Self::GitHubToken,
        Self::SlackToken,
        Self::StripeKey,
        Self::GoogleApiKey,
        Self::Jwt,
        Self::PrivateKey,
        Self::GenericApiKey,
    ];

    /// Kind with the given wire name ([`as_str`](Self::as_str)).
    #[must_use]
    pub fn from_wire(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }
}

/// Where a secret was found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// In the value of the named response header.
    Header {
        /// Header name as received.
        name: String,
    },
    /// In the body, at this byte offset.
    Body {
        /// Byte offset of the match start.
        offset: usize,
    },
}

/// One detected secret. Carries no part of the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretFinding {
    /// Credential family.
    pub kind: SecretKind,
    /// Header or body location.
    pub location: Location,
    /// `BLAKE3_keyed(key, domain || value)` for cross-page correlation.
    pub value_hash: Digest,
    /// Length of the matched value in bytes.
    pub preview_len: usize,
}

struct Rule {
    kind: SecretKind,
    pattern: &'static str,
    /// Capture group holding the credential (0 = whole match).
    group: usize,
}

/// Most specific shapes first: a later rule never reports a span already
/// claimed by an earlier one.
const RULES: &[Rule] = &[
    Rule {
        kind: SecretKind::PrivateKey,
        // Lazy, unbounded body: the regex crate guarantees linear time, and a
        // counted repetition this large would exceed the compiled-size limit.
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY[A-Z ]*-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY[A-Z ]*-----",
        group: 0,
    },
    Rule {
        kind: SecretKind::AwsAccessKeyId,
        pattern: r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b",
        group: 0,
    },
    Rule {
        kind: SecretKind::GitHubToken,
        pattern: r"\b(?:gh[poushr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,255})\b",
        group: 0,
    },
    Rule {
        kind: SecretKind::SlackToken,
        pattern: r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
        group: 0,
    },
    Rule {
        kind: SecretKind::StripeKey,
        pattern: r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,99}\b",
        group: 0,
    },
    Rule {
        kind: SecretKind::GoogleApiKey,
        pattern: r"\bAIza[0-9A-Za-z_-]{35}\b",
        group: 0,
    },
    Rule {
        kind: SecretKind::Jwt,
        pattern: r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        group: 0,
    },
    Rule {
        kind: SecretKind::AwsSecretAccessKey,
        pattern: r#"(?i:aws)[A-Za-z0-9_-]{0,24}(?i:secret)[A-Za-z0-9_-]{0,24}\s*[:=]\s*["']?([A-Za-z0-9/+]{40})(?:["'\s;,]|$)"#,
        group: 1,
    },
    Rule {
        kind: SecretKind::GenericApiKey,
        pattern: r#"(?i)\bapi[_-]?key["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,128})"#,
        group: 1,
    },
];

static COMPILED: LazyLock<Vec<(SecretKind, usize, Regex)>> = LazyLock::new(|| {
    RULES
        .iter()
        .filter_map(|r| {
            RegexBuilder::new(r.pattern)
                .size_limit(1 << 20)
                .dfa_size_limit(1 << 20)
                .build()
                .ok()
                .map(|re| (r.kind, r.group, re))
        })
        .collect()
});

/// Every rule compiled (a broken pattern would silently disable a kind).
#[must_use]
pub fn rules_compiled() -> bool {
    COMPILED.len() == RULES.len()
}

/// Span claimed by an earlier, more specific rule.
struct Hit {
    start: usize,
    end: usize,
}

fn scan(text: &str, key: &[u8; 32], mut emit: impl FnMut(SecretKind, usize, usize, Digest, &str)) {
    let mut hits: Vec<Hit> = Vec::new();
    for (kind, group, re) in COMPILED.iter() {
        for caps in re.captures_iter(text) {
            let Some(m) = caps.get(*group) else {
                continue;
            };
            if hits.iter().any(|h| m.start() < h.end && h.start < m.end()) {
                continue;
            }
            if hits.len() >= MAX_FINDINGS {
                return;
            }
            hits.push(Hit {
                start: m.start(),
                end: m.end(),
            });
            emit(
                *kind,
                m.start(),
                m.len(),
                Digest::keyed(key, SECRET_HASH_DOMAIN, m.as_str().as_bytes()),
                m.as_str(),
            );
        }
    }
}

/// Shared walk of [`detect`] and [`detect_tokens`]: `make` turns a finding
/// and the matched text into the caller's item. Order: headers first (input
/// order), then body by offset; at most [`MAX_FINDINGS`] items.
fn collect<T>(
    key: &[u8; 32],
    headers: &[(String, String)],
    body: &str,
    mut make: impl FnMut(SecretFinding, &str) -> T,
) -> Vec<T> {
    let mut out: Vec<T> = Vec::new();
    for (name, value) in headers {
        scan(value, key, |kind, _, len, value_hash, token| {
            if out.len() < MAX_FINDINGS {
                out.push(make(
                    SecretFinding {
                        kind,
                        location: Location::Header { name: name.clone() },
                        value_hash,
                        preview_len: len,
                    },
                    token,
                ));
            }
        });
    }
    let mut body_findings: Vec<(usize, T)> = Vec::new();
    scan(body, key, |kind, offset, len, value_hash, token| {
        body_findings.push((
            offset,
            make(
                SecretFinding {
                    kind,
                    location: Location::Body { offset },
                    value_hash,
                    preview_len: len,
                },
                token,
            ),
        ));
    });
    body_findings.sort_by_key(|(offset, _)| *offset);
    out.extend(body_findings.into_iter().map(|(_, item)| item));
    out.truncate(MAX_FINDINGS);
    out
}

/// Detect secrets in `headers` and `body`. `key` keys the value hash so the
/// digest is useless without it. Findings are ordered headers
/// first (input order), then body by offset.
#[must_use]
pub fn detect(key: &[u8; 32], headers: &[(String, String)], body: &str) -> Vec<SecretFinding> {
    collect(key, headers, body, |finding, _| finding)
}

/// [`detect`] plus the matched value of every finding, for online
/// validation (`extract.validateSecrets`, katana `-kb-validate-secrets`).
/// Same findings in the same order as [`detect`]. The values are
/// [`SecretToken`]s: hand them to
/// [`SecretValidators::plan`](crate::secret_validation::SecretValidators::plan)
/// and drop them; they must never be stored, serialized or logged.
#[must_use]
pub fn detect_tokens(
    key: &[u8; 32],
    headers: &[(String, String)],
    body: &str,
) -> Vec<(SecretFinding, SecretToken)> {
    collect(key, headers, body, |finding, token| {
        (finding, SecretToken(token.to_owned()))
    })
}

/// The matched value of a detected secret, held transiently so it can be
/// validated. Not `Clone`, not `Serialize`, not `Display`; `Debug` prints
/// only its length.
pub struct SecretToken(String);

impl SecretToken {
    /// The credential. Callers must not store, serialize or log it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for SecretToken {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretToken(<{} bytes redacted>)", self.0.len())
    }
}
