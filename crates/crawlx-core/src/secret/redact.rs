//! Shared redaction policy and immutable artifact approval.

use super::json::{inspect_json, JsonDocument};
use parking_lot::RwLock;
use regex::Regex;
use serde_json::Value;
use std::sync::{Arc, LazyLock};

/// Immutable output of the shared redactor. Only redactor methods can construct it.
///
/// No mutable view, deserializer, unchecked conversion or caller-defined approval
/// hook exists. Reading or cloning an approved value cannot change approved bytes.
///
/// Approval cannot be forged:
/// ```compile_fail
/// use crawlx_core::secret::Redacted;
/// let forged = Redacted { data: b"unverified secret".to_vec() };
/// ```
///
/// Approval cannot be deserialized:
/// ```compile_fail
/// use crawlx_core::secret::Redacted;
/// let forged: Redacted<Vec<u8>> = serde_json::from_str("[115,101,99,114,101,116]").unwrap();
/// ```
///
/// An immutable approved value cannot be changed through its inner view:
/// ```compile_fail
/// use crawlx_core::secret::Redactor;
/// let mut approved = Redactor::new().redact_text("safe");
/// approved.as_inner().push_str("unverified secret");
/// ```
#[derive(Clone, PartialEq, Eq)]
#[must_use]
pub struct Redacted<T> {
    data: T,
}

impl<T> Redacted<T> {
    /// Read the approved value without gaining mutable access.
    #[must_use]
    pub const fn as_inner(&self) -> &T {
        &self.data
    }

    /// Consume the wrapper and return its owned content without copying.
    ///
    /// The returned value no longer carries approval. Mutating or recomposing it
    /// requires fresh approval before publication through a typed sink.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Redacted<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T> std::fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Redacted(..)")
    }
}

/// Replacement text for every redacted name or value.
pub const REDACTED: &str = "[REDACTED]";

/// Field-name fragments that mark a field as secret. Matching is
/// case-insensitive and ignores `-`, `_`, `.` and other separators, so
/// `Set-Cookie`, `set_cookie` and `setCookie` are one name.
pub const DENY_NAMES: &[&str] = &[
    "password",
    "passwd",
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "secret",
    "credential",
    "apikey",
];

/// Shortest literal accepted into the run-time secret registry; shorter values
/// would mask ordinary words.
pub const MIN_REGISTERED_SECRET_LEN: usize = 6;

static REGISTERED: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));

/// Add a resolved secret value to the process-wide registry; every later log
/// value containing it is masked. Returns `false` when the value is too short
/// to be registered safely.
pub fn register_secret(value: &str) -> bool {
    if value.len() < MIN_REGISTERED_SECRET_LEN {
        return false;
    }
    let mut guard = REGISTERED.write();
    if !guard.iter().any(|s| s == value) {
        guard.push(value.to_owned());
    }
    true
}

/// Credential shapes, shared by text scrubbing and immutable/binary verification.
const CREDENTIAL_SHAPES: &str = concat!(
    // JWT: base64url header starting `eyJ`, two dots.
    r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*",
    // `Bearer <token>` / `Basic <b64>` credentials.
    r"|(?i:\bBearer\s+[A-Za-z0-9._~+/=-]+)",
    r"|(?i:\bBasic\s+[A-Za-z0-9+/=]{8,})",
    // `sk-` style provider keys.
    r"|\bsk-[A-Za-z0-9_-]{6,}",
);

/// `name=value` / `name: value` / `"name":"value"` where `name` is deny-listed.
const KEY_VALUE: &str = concat!(
    r#"(?i)(password|passwd|secret|token|api[_-]?key|authorization|set-cookie|cookie|credential|session(?:[_-]?id)?|sid|phpsessid|jsessionid)s?"#,
    r#"["']?\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;&"'}]+)"#,
);

const SESSION_QUERY: &str = r#"(?i)([?&](?:amp;)?(?:session(?:[_-]?id)?|sid|phpsessid|jsessionid|access_token|token|csrf(?:_token)?|_csrf|authenticity_token|signature|sig|expires)=)([^\s&#;"'<>\\]+)"#;

struct Patterns {
    shapes: Result<Regex, regex::Error>,
    credentials: Result<Regex, regex::Error>,
    binary_credentials: Result<regex::bytes::Regex, regex::Error>,
    key_value: Result<Regex, regex::Error>,
    session_query: Result<Regex, regex::Error>,
}

static PATTERNS: LazyLock<Patterns> = LazyLock::new(|| Patterns {
    // The hex heuristic applies to ordinary text, not canonical digests or binary.
    shapes: Regex::new(&format!("{CREDENTIAL_SHAPES}|[0-9a-fA-F]{{32,}}")),
    credentials: Regex::new(CREDENTIAL_SHAPES),
    binary_credentials: regex::bytes::Regex::new(&format!(
        "(?-u:{CREDENTIAL_SHAPES}|{KEY_VALUE}|{SESSION_QUERY})"
    )),
    key_value: Regex::new(KEY_VALUE),
    session_query: Regex::new(SESSION_QUERY),
});

#[derive(Clone, Copy)]
enum CanonicalSchema {
    Generic,
    ArticleContent,
    ArticleEnvelope,
    ArticleMetadata,
    ArticleKeywords,
    ArticleKeyword,
}

/// Redaction policy: the built-in deny-list plus caller-supplied extra names.
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    extra_deny: Arc<[String]>,
}

impl Redactor {
    /// Scrub text with every built-in and registered-secret rule, then freeze it.
    /// Ambiguous duplicate JSON members mask the complete input instead of preserving
    /// a hidden earlier value that a different JSON consumer could recover.
    pub fn redact_text(&self, value: &str) -> Redacted<String> {
        let data = match inspect_json(value.as_bytes()) {
            JsonDocument::Value(mut json) => {
                if !self.json_names_are_clean(&json) {
                    REDACTED.to_owned()
                } else if self.scrub_json(&mut json) {
                    json.to_string()
                } else {
                    value.to_owned()
                }
            }
            JsonDocument::DuplicateMembers => REDACTED.to_owned(),
            JsonDocument::Other => self.scrub(value),
        };
        Redacted { data }
    }

    /// Redact textual artifacts, or verify opaque bytes without changing their encoding.
    ///
    /// JSON is decoded before inspecting strings and sensitive field names, so
    /// JSON escapes cannot conceal a registered secret. Opaque payloads are checked
    /// for exact registered secrets and credential syntax, never text-rewritten.
    /// This policy does not decode compression, images, audio or visual text.
    ///
    /// # Errors
    /// Rejects duplicate JSON members, opaque payloads containing a known secret or
    /// credential syntax, or unavailable patterns. Ciphertext must use core AEAD sealing instead.
    pub fn redact_artifact(&self, value: &[u8]) -> Result<Redacted<Vec<u8>>, crate::StoreError> {
        let data = if let Ok(text) = std::str::from_utf8(value) {
            match inspect_json(value) {
                JsonDocument::Value(mut json) => {
                    if !self.json_names_are_clean(&json) {
                        return Err(approval_denied());
                    }
                    if self.scrub_json(&mut json) {
                        serde_json::to_vec(&json).map_err(|_| {
                            crate::StoreError::Serialization("redacted JSON encoding failed".into())
                        })?
                    } else {
                        value.to_vec()
                    }
                }
                JsonDocument::DuplicateMembers => return Err(approval_denied()),
                JsonDocument::Other => self.scrub(text).into_bytes(),
            }
        } else {
            return self.verify_binary(value);
        };
        Ok(Redacted { data })
    }

    /// Verify binary bytes without decoding, rewriting or approving unchecked bytes.
    ///
    /// This applies the registered-secret and credential-syntax rules to the
    /// actual bytes, including ASCII-only PDF/archive bodies. It does not inspect
    /// compressed, encrypted or visually encoded content. Unknown bare hex is not
    /// distinguished from legitimate binary data or hashes.
    ///
    /// # Errors
    /// Rejects known literals, credential syntax or unavailable patterns.
    pub fn verify_binary(&self, value: &[u8]) -> Result<Redacted<Vec<u8>>, crate::StoreError> {
        self.check_binary(value)?;
        Ok(Redacted { data: value.to_vec() })
    }

    pub(crate) fn check_binary(&self, value: &[u8]) -> Result<(), crate::StoreError> {
        let Ok(patterns) = &PATTERNS.binary_credentials else {
            return Err(approval_denied());
        };
        let unsafe_assignment = patterns.captures_iter(value).any(|captures| {
            !captures
                .get(2)
                .or_else(|| captures.get(4))
                .is_some_and(|matched| redacted_assignment(matched.as_bytes()))
        });
        if unsafe_assignment || contains_registered(value) {
            return Err(approval_denied());
        }
        match inspect_json(value) {
            JsonDocument::Value(json) if !self.canonical_json_is_clean(&json) => {
                return Err(approval_denied());
            }
            JsonDocument::DuplicateMembers => return Err(approval_denied()),
            _ => {}
        }
        Ok(())
    }

    /// Verify finalized UTF-8 content without rewriting canonical bytes or digests.
    ///
    /// Registered literals, credential syntax, sensitive JSON fields and session
    /// query values are checked. Only the ambiguous bare-hex heuristic is omitted:
    /// canonical content legitimately contains typed digests and literal hex text.
    /// JSON strings are checked after decoding; a caller's finalization flag does
    /// not grant approval. Redacted placeholders are permitted.
    /// Native article lexical-token fields are distinguished from credentials only
    /// after validating their envelope, source digest, tokenizer revision and keyword
    /// source slices. Their string values still receive the same secret checks.
    /// Unknown bare hexadecimal credentials can therefore pass this policy unless
    /// registered or identified by their field name; approval is not exhaustive detection.
    ///
    /// # Errors
    /// Rejects duplicate JSON members, non-UTF-8 input, remaining secrets, or unavailable patterns.
    pub fn verify_canonical(&self, value: &[u8]) -> Result<Redacted<Vec<u8>>, crate::StoreError> {
        self.check_canonical(value)?;
        Ok(Redacted { data: value.to_vec() })
    }

    /// Verify and freeze owned finalized UTF-8 bytes without copying their allocation.
    ///
    /// Uses exactly the canonical schema, source-lineage and privacy checks of
    /// [`Self::verify_canonical`]. Rejected input is never returned as approved content.
    ///
    /// # Errors
    /// Rejects duplicate JSON members, non-UTF-8 input, remaining secrets, or unavailable patterns.
    pub fn verify_canonical_owned(&self, value: Vec<u8>) -> Result<Redacted<Vec<u8>>, crate::StoreError> {
        self.check_canonical(&value)?;
        Ok(Redacted { data: value })
    }

    /// Verify and freeze JSON Lines without copying or rewriting their canonical bytes.
    ///
    /// Each record receives the same schema, source-lineage and decoded-secret checks as
    /// [`Self::verify_canonical`]. Registered literals are also checked across the full stream.
    /// An empty stream and a final newline are allowed; blank or malformed records are not.
    ///
    /// # Errors
    /// Rejects malformed JSON, duplicate members, invalid lineage, remaining secrets or unavailable patterns.
    pub fn verify_canonical_jsonl_owned(
        &self,
        value: Vec<u8>,
    ) -> Result<Redacted<Vec<u8>>, crate::StoreError> {
        if contains_registered(&value) {
            return Err(approval_denied());
        }
        if !value.is_empty() {
            for line in value
                .strip_suffix(b"\n")
                .unwrap_or(&value)
                .split(|byte| *byte == b'\n')
            {
                match inspect_json(line) {
                    JsonDocument::Value(json) if self.canonical_json_is_clean(&json) => {}
                    _ => return Err(approval_denied()),
                }
            }
        }
        Ok(Redacted { data: value })
    }

    /// Check finalized canonical bytes without copying them or granting an artifact token.
    ///
    /// This applies the same source-lineage and secret rules as [`Self::verify_canonical`].
    /// Use it when reading or validating retained content, not to authorize a raw sink write.
    ///
    /// # Errors
    /// Rejects duplicate JSON members, non-UTF-8 input, remaining secrets, or unavailable patterns.
    pub fn check_canonical(&self, value: &[u8]) -> Result<(), crate::StoreError> {
        let text = std::str::from_utf8(value).map_err(|_| approval_denied())?;
        let clean = match inspect_json(value) {
            JsonDocument::Value(json) => !contains_registered(value) && self.canonical_json_is_clean(&json),
            JsonDocument::DuplicateMembers => false,
            JsonDocument::Other => self.canonical_text_is_clean(text),
        };
        if !clean {
            return Err(approval_denied());
        }
        Ok(())
    }

    fn canonical_text_is_clean(&self, value: &str) -> bool {
        let (Ok(credentials), Ok(key_value), Ok(session)) = (
            &PATTERNS.credentials,
            &PATTERNS.key_value,
            &PATTERNS.session_query,
        ) else {
            return false;
        };
        !contains_registered(value.as_bytes())
            && !credentials.is_match(value)
            && key_value.replace_all(value, "${1}=[REDACTED]") == value
            && session.replace_all(value, "${1}[REDACTED]") == value
    }

    fn canonical_json_is_clean(&self, value: &Value) -> bool {
        let finalized = has_finalized_article_schema(value);
        if value
            .get("article")
            .and_then(|article| article.get("chunks"))
            .is_some_and(|chunks| !chunks.is_null())
            && !finalized
        {
            return false;
        }
        let schema = if finalized {
            CanonicalSchema::ArticleContent
        } else {
            CanonicalSchema::Generic
        };
        self.canonical_json_is_clean_with_schema(value, schema)
    }

    fn canonical_json_is_clean_with_schema(&self, value: &Value, schema: CanonicalSchema) -> bool {
        match value {
            Value::String(text) => self.canonical_text_is_clean(text),
            Value::Array(values) => values.iter().all(|value| {
                if matches!(schema, CanonicalSchema::ArticleKeywords) {
                    self.canonical_json_is_clean_with_schema(value, CanonicalSchema::ArticleKeyword)
                } else {
                    self.canonical_json_is_clean(value)
                }
            }),
            Value::Object(fields) => fields.iter().all(|(name, value)| {
                // These are lexical metadata, not credential fields. The complete article
                // schema, source digests and keyword source slices were verified first.
                // String values still pass every non-digest redaction rule below.
                let lexical_field = matches!(
                    (schema, name.as_str()),
                    (
                        CanonicalSchema::ArticleMetadata,
                        "tokenizerVersion" | "tokenizerUnavailable"
                    ) | (CanonicalSchema::ArticleKeyword, "token")
                );
                let child_schema = match (schema, name.as_str()) {
                    (CanonicalSchema::ArticleContent, "article") => CanonicalSchema::ArticleEnvelope,
                    (CanonicalSchema::ArticleEnvelope, "metadata") => CanonicalSchema::ArticleMetadata,
                    (CanonicalSchema::ArticleMetadata, "keywords") => CanonicalSchema::ArticleKeywords,
                    _ => CanonicalSchema::Generic,
                };
                self.canonical_text_is_clean(name)
                    && (lexical_field
                        || !self.is_sensitive_name(name)
                        || value.is_null()
                        || value.as_str() == Some(REDACTED))
                    && if matches!(child_schema, CanonicalSchema::Generic) {
                        self.canonical_json_is_clean(value)
                    } else {
                        self.canonical_json_is_clean_with_schema(value, child_schema)
                    }
            }),
            _ => true,
        }
    }

    fn scrub_json(&self, value: &mut Value) -> bool {
        match value {
            Value::String(text) => {
                let scrubbed = self.scrub(text);
                if scrubbed == *text {
                    false
                } else {
                    *text = scrubbed;
                    true
                }
            }
            Value::Array(values) => {
                let mut changed = false;
                for value in values {
                    changed |= self.scrub_json(value);
                }
                changed
            }
            Value::Object(fields) => {
                let mut changed = false;
                for (name, value) in fields {
                    if self.is_sensitive_name(name) && value.as_str() != Some(REDACTED) {
                        *value = Value::String(REDACTED.to_owned());
                        changed = true;
                    } else {
                        changed |= self.scrub_json(value);
                    }
                }
                changed
            }
            _ => false,
        }
    }

    fn json_names_are_clean(&self, value: &Value) -> bool {
        match value {
            Value::Array(values) => values.iter().all(|value| self.json_names_are_clean(value)),
            Value::Object(fields) => fields
                .iter()
                .all(|(name, value)| self.scrub(name) == *name && self.json_names_are_clean(value)),
            _ => true,
        }
    }

    /// Built-in rules only.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Built-in rules plus `extra` field-name fragments (matched like [`DENY_NAMES`]).
    #[must_use]
    pub fn with_extra_deny_names<I, S>(extra: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let extra: Vec<String> = extra
            .into_iter()
            .map(|s| normalize_name(s.as_ref()))
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            extra_deny: extra.into(),
        }
    }

    /// True when a field called `name` must never have its value emitted.
    #[must_use]
    pub fn is_sensitive_name(&self, name: &str) -> bool {
        let norm = normalize_name(name);
        DENY_NAMES.iter().any(|d| norm.contains(&normalize_name(d)))
            || self.extra_deny.iter().any(|d| norm.contains(d.as_str()))
    }
    /// Check whether text passes every built-in and registered-secret rule without copying it.
    /// Privacy-sensitive spools use this fail-closed gate before writing approved bytes.
    #[must_use]
    pub fn is_clean_text(&self, value: &str) -> bool {
        let (Ok(shapes), Ok(key_value), Ok(session)) =
            (&PATTERNS.shapes, &PATTERNS.key_value, &PATTERNS.session_query)
        else {
            return false;
        };
        !shapes.is_match(value)
            && !key_value.is_match(value)
            && !session.is_match(value)
            && !REGISTERED
                .read()
                .iter()
                .any(|secret| value.contains(secret.as_str()))
    }

    /// Mask secret shapes and registered secrets inside `value`.
    #[must_use]
    pub fn scrub(&self, value: &str) -> String {
        let (Ok(shapes), Ok(key_value), Ok(session)) =
            (&PATTERNS.shapes, &PATTERNS.key_value, &PATTERNS.session_query)
        else {
            // Patterns are literals and covered by a test; if they ever fail to
            // compile, mask everything rather than let a secret through.
            return REDACTED.to_owned();
        };
        let mut out = self.scrub_known(value);
        // Shapes first so `authorization: Bearer abc` loses `abc` before the
        // key/value rule consumes the (already masked) value.
        if let std::borrow::Cow::Owned(s) = shapes.replace_all(&out, REDACTED) {
            out = s;
        }
        if let std::borrow::Cow::Owned(s) = key_value.replace_all(&out, "${1}=[REDACTED]") {
            out = s;
        }
        if let std::borrow::Cow::Owned(s) = session.replace_all(&out, "${1}[REDACTED]") {
            out = s;
        }
        out
    }

    /// Replace resolved secrets without treating hashes or other structured values as secrets.
    #[must_use]
    pub fn scrub_known(&self, value: &str) -> String {
        let mut out = value.to_owned();
        for secret in REGISTERED.read().iter() {
            if out.contains(secret.as_str()) {
                out = out.replace(secret.as_str(), REDACTED);
            }
        }
        out
    }

    /// Mask session query values inside structured text without changing hashes or JSON syntax.
    ///
    /// Unlike [`Self::scrub`], this only rewrites URL query values. It is suitable for
    /// fingerprint artifacts whose canonical keys and other typed digests must remain readable.
    #[must_use]
    pub fn scrub_session_queries<'value>(&self, value: &'value str) -> std::borrow::Cow<'value, str> {
        match &PATTERNS.session_query {
            Ok(pattern) => pattern.replace_all(value, "${1}[REDACTED]"),
            Err(_) => std::borrow::Cow::Borrowed(REDACTED),
        }
    }

    /// Scrub registered and caller-supplied secrets from an opaque artifact body.
    ///
    /// Valid UTF-8 also receives the normal secret-shape scrub. Other bytes remain
    /// unchanged except for exact secret matches; binary data is never decoded lossily.
    #[must_use]
    pub fn scrub_bytes<'bytes, 'secret>(
        &self,
        value: &'bytes [u8],
        secrets: impl IntoIterator<Item = &'secret str>,
    ) -> std::borrow::Cow<'bytes, [u8]> {
        let mut out = std::borrow::Cow::Borrowed(value);
        let mut replace = |secret: &str| {
            let needle = secret.as_bytes();
            if needle.is_empty() || !out.windows(needle.len()).any(|w| w == needle) {
                return;
            }
            let mut replaced = Vec::with_capacity(out.len());
            let mut rest = out.as_ref();
            while let Some(at) = rest.windows(needle.len()).position(|w| w == needle) {
                replaced.extend_from_slice(&rest[..at]);
                replaced.extend_from_slice(REDACTED.as_bytes());
                rest = &rest[at + needle.len()..];
            }
            replaced.extend_from_slice(rest);
            out = std::borrow::Cow::Owned(replaced);
        };
        {
            let registered = REGISTERED.read();
            for secret in registered.iter() {
                replace(secret);
            }
        }
        for secret in secrets {
            replace(secret);
        }
        if let Ok(text) = std::str::from_utf8(&out) {
            let scrubbed = self.scrub(text);
            if scrubbed != text {
                return std::borrow::Cow::Owned(scrubbed.into_bytes());
            }
        }
        out
    }

    /// Redact a field: the whole value when the name is deny-listed, otherwise
    /// a scrubbed string. Non-string values of non-sensitive names pass through.
    #[must_use]
    pub fn redact_field(&self, name: &str, value: Value) -> Value {
        if self.is_sensitive_name(name) {
            return Value::String(REDACTED.to_owned());
        }
        match value {
            Value::String(s) => Value::String(self.scrub(&s)),
            other => other,
        }
    }
}

fn has_finalized_article_schema(value: &Value) -> bool {
    use serde::Deserialize as _;
    let Some(text) = value.get("text").and_then(Value::as_str) else {
        return false;
    };
    if value.get("comments").and_then(Value::as_str).is_none() {
        return false;
    }
    let Some(article) = value.get("article") else {
        return false;
    };
    let Ok(article) = crate::extraction::DocumentEnvelopeV1::deserialize(article) else {
        return false;
    };
    article.version == 1
        && article.main_digest
            == crate::hash::Digest::of("crawlx.extract.main.unicode_rules_v1", text.as_bytes())
        && article
            .chunks
            .as_ref()
            .is_none_or(|chunks| chunks.validate(text, &chunks.policy).is_ok())
        && article
            .metadata
            .tokenizer_version
            .as_deref()
            .is_none_or(|version| matches!(version, "unicode_rules_v1" | "icu_dictionary_uax29_v17_v1"))
        && article.metadata.keywords.iter().all(|keyword| {
            text.get(keyword.source.start..keyword.source.end)
                .is_some_and(|source| {
                    source
                        .chars()
                        .flat_map(char::to_lowercase)
                        .eq(keyword.token.chars())
                })
        })
}

fn approval_denied() -> crate::StoreError {
    crate::StoreError::RetentionDenied("artifact redaction approval denied".into())
}

fn contains_registered(value: &[u8]) -> bool {
    REGISTERED.read().iter().any(|secret| {
        value
            .windows(secret.len())
            .any(|window| window == secret.as_bytes())
    })
}

fn normalize_name(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}
fn redacted_assignment(mut value: &[u8]) -> bool {
    if value.len() >= 2 && matches!(value.first(), Some(b'"' | b'\'')) && value.first() == value.last() {
        value = &value[1..value.len() - 1];
    }
    value.strip_prefix(REDACTED.as_bytes()).is_some_and(|suffix| {
        suffix
            .iter()
            .all(|byte| byte.is_ascii_control() || matches!(byte, b')' | b']' | b'>'))
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    // Synthetic detector canary (the public jwt.io sample), assembled from parts.
    const JWT: &str = concat!(
        "eyJhbGciOiJIUzI1NiJ9.",
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    );

    #[test]
    fn patterns_compile() {
        assert!(PATTERNS.shapes.is_ok());
        assert!(PATTERNS.key_value.is_ok());
        assert!(PATTERNS.credentials.is_ok());
        assert!(PATTERNS.binary_credentials.is_ok());
        assert!(PATTERNS.session_query.is_ok());
    }

    #[test]
    fn names_match_case_and_separator_insensitively() {
        let r = Redactor::new();
        for n in [
            "password",
            "Authorization",
            "cookie",
            "Set-Cookie",
            "set_cookie",
            "setCookie",
            "access_token",
            "client.secret",
            "credential_ref",
            "X-Api-Key",
        ] {
            assert!(r.is_sensitive_name(n), "{n}");
        }
        for n in ["url", "status", "crawl_id", "message", "duration_ms"] {
            assert!(!r.is_sensitive_name(n), "{n}");
        }
    }

    #[test]
    fn extra_deny_names_apply() {
        let r = Redactor::with_extra_deny_names(["session-id"]);
        assert!(r.is_sensitive_name("session_id"));
        assert!(!Redactor::new().is_sensitive_name("session_id"));
    }

    #[test]
    fn shapes_are_masked_inside_text() {
        let r = Redactor::new();
        for secret in [
            JWT,
            "Bearer abc.def-ghi_123",
            "bearer lowercase-token",
            "Basic dXNlcjpwYXNzd29yZA==",
            "0123456789abcdef0123456789ABCDEF",
            "sk-live_abcdef012345",
        ] {
            let out = r.scrub(&format!("request failed with {secret} while fetching"));
            assert!(!out.contains(secret), "{secret} -> {out}");
            assert!(out.contains(REDACTED), "{out}");
            assert!(out.starts_with("request failed with"));
            assert!(out.ends_with("while fetching"));
        }
    }

    #[test]
    fn key_value_pairs_are_masked() {
        let r = Redactor::new();
        let out = r.scrub("GET /x?access_token=abc123&page=2 password: hunter2, ok");
        assert!(!out.contains("abc123"), "{out}");
        assert!(!out.contains("hunter2"), "{out}");
        assert!(out.contains("page=2"), "{out}");
        let json = r.scrub(r#"{"api_key":"zzz-topsecret","n":1}"#);
        assert!(!json.contains("zzz-topsecret"), "{json}");
        let auth = r.scrub("authorization: Bearer abcdefgh");
        assert!(!auth.contains("abcdefgh"), "{auth}");
    }

    #[test]
    fn session_query_values_are_scrubbed_without_secret_registration() {
        let redactor = Redactor::new();
        for name in [
            "sessionid",
            "session_id",
            "session",
            "sid",
            "PHPSESSID",
            "JSESSIONID",
        ] {
            let text = format!(
                r#"<a href="/invoice?id=3&amp;{name}=g12_session_canary_7d91e8c4&amp;page=2">Invoice</a>"#
            );
            let bytes = redactor.scrub_bytes(text.as_bytes(), std::iter::empty::<&str>());
            let scrubbed = std::str::from_utf8(&bytes).unwrap();
            assert!(!scrubbed.contains("g12_session_canary_7d91e8c4"), "{scrubbed}");
            assert!(scrubbed.contains("id=3"), "{scrubbed}");
            assert!(scrubbed.contains("page=2"), "{scrubbed}");
        }
    }

    #[test]
    fn session_query_scrub_preserves_structured_hashes_and_json() {
        let input = serde_json::json!({
            "key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "url": "/invoice?id=3&sessionid=g12_session_canary_7d91e8c4&page=2"
        })
        .to_string();
        let redactor = Redactor::new();
        let scrubbed = redactor.scrub_session_queries(&input);
        let decoded: serde_json::Value = serde_json::from_str(&scrubbed).unwrap();
        assert_eq!(
            decoded["key"],
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        );
        assert_eq!(decoded["url"], "/invoice?id=3&sessionid=[REDACTED]&page=2");
    }

    #[test]
    fn plain_text_is_untouched() {
        let r = Redactor::new();
        let text = "fetched https://example.org/a?b=1 in 12ms; risk-assessment ok; task-force";
        assert_eq!(r.scrub(text), text);
        assert_eq!(r.scrub("deadbeef"), "deadbeef");
    }

    #[test]
    fn registered_secrets_are_masked() {
        assert!(!register_secret("abc"));
        assert!(register_secret("zq9-unique-registered-canary"));
        let out = Redactor::new().scrub("typed zq9-unique-registered-canary into field");
        assert_eq!(out, "typed [REDACTED] into field");
    }

    #[test]
    fn opaque_artifacts_keep_binary_bytes_but_drop_credentials() {
        let registered = "opaque-registered-canary-7d9a";
        assert!(register_secret(registered));
        let mut input = b"\xff\0before:".to_vec();
        input.extend_from_slice(registered.as_bytes());
        input.extend_from_slice(b":short:after\0\xfe");
        let redactor = Redactor::new();
        assert_eq!(
            redactor.scrub_bytes(&input, ["short"]).as_ref(),
            b"\xff\0before:[REDACTED]:[REDACTED]:after\0\xfe"
        );
        assert_eq!(
            redactor
                .scrub_bytes(b"safe token=query-canary-4c9e", std::iter::empty())
                .as_ref(),
            b"safe token=[REDACTED]"
        );
    }

    #[test]
    fn typed_json_redaction_checks_decoded_values_and_names() {
        register_secret("boundary-decoded-canary-49c2");
        let input = br#"{"text":"boundary-\u0064ecoded-canary-49c2","password":"unregistered-value","ok":7}"#;
        let approved = Redactor::new().redact_artifact(input).unwrap();
        let json: Value = serde_json::from_slice(approved.as_ref()).unwrap();
        assert_eq!(json["text"], REDACTED);
        assert_eq!(json["password"], REDACTED);
        assert_eq!(json["ok"], 7);
        let key_canary = br#"{"boundary-\u0064ecoded-canary-49c2":"safe"}"#;
        assert!(Redactor::new().redact_artifact(key_canary).is_err());
        assert_eq!(
            Redactor::new()
                .redact_text(std::str::from_utf8(key_canary).unwrap())
                .as_inner(),
            REDACTED
        );
        assert!(Redactor::new().verify_binary(input).is_err());
        let clean = b"{\"safe\": 7}\n";
        assert_eq!(Redactor::new().redact_artifact(clean).unwrap().as_ref(), clean);
    }

    #[test]
    fn canonical_article_lexical_tokens_require_valid_schema_and_source_lineage() {
        use crate::extraction::{
            ArticleMetadataV1, DocumentEnvelopeV1, KeywordV1, QualityOutcomeV1, QualityStatusV1,
            SourceRangeV1,
        };
        const KEYWORD: &str = "Zq47lexicalcanary";
        let text = "Zq47lexicalcanary report.";
        let mut metadata = ArticleMetadataV1 {
            tokenizer_version: Some("unicode_rules_v1".into()),
            tokenizer_unavailable: false,
            ..ArticleMetadataV1::default()
        };
        metadata.keywords.push(KeywordV1::new(
            KEYWORD.to_lowercase(),
            1,
            SourceRangeV1::new(0, KEYWORD.len()),
        ));
        let mut article = DocumentEnvelopeV1::new(
            crate::hash::Digest::of("test/policy", b"safe"),
            crate::hash::Digest::of("crawlx.extract.main.unicode_rules_v1", text.as_bytes()),
            "semantic_density".into(),
            0,
            Vec::new(),
            metadata,
            QualityOutcomeV1::new(QualityStatusV1::Accepted, Vec::new(), text.chars().count(), 1, 1),
        );
        article.chunks = Some(
            crate::extraction::WordChunkEnvelopeV1::build(
                text,
                crate::extraction::WordChunkPolicyV1::default(),
            )
            .unwrap(),
        );
        let mut content = serde_json::json!({"text": text, "comments": "", "article": article});
        let original = serde_json::to_vec(&content).unwrap();
        let redactor = Redactor::new();
        assert_eq!(redactor.verify_canonical(&original).unwrap().as_ref(), original);
        let mut records = original.clone();
        records.push(b'\n');
        records.extend_from_slice(&original);
        records.push(b'\n');
        let allocation = records.as_ptr();
        let approved = redactor.verify_canonical_jsonl_owned(records.clone()).unwrap();
        assert_eq!(approved.as_ref(), &records);
        let approved = redactor.verify_canonical_jsonl_owned(records).unwrap();
        assert_eq!(approved.as_ref().as_ptr(), allocation);
        let mut corrupt_chunks = content.clone();
        corrupt_chunks["article"]["chunks"]["ranges"][0]["end"] = serde_json::json!(text.len() + 1);
        assert!(redactor
            .verify_canonical(&serde_json::to_vec(&corrupt_chunks).unwrap())
            .is_err());
        let mut invalid_records = original.clone();
        invalid_records.push(b'\n');
        invalid_records.extend_from_slice(&serde_json::to_vec(&corrupt_chunks).unwrap());
        invalid_records.push(b'\n');
        assert!(redactor.verify_canonical_jsonl_owned(invalid_records).is_err());
        content["article"]["metadata"]["keywords"][0]["token"] = Value::String("unverified".into());
        assert!(redactor
            .verify_canonical(&serde_json::to_vec(&content).unwrap())
            .is_err());
        content["article"]["metadata"]["keywords"][0]["token"] = Value::String(KEYWORD.to_lowercase());
        content["article"]["metadata"]["tokenizerVersion"] = Value::String("unknown-version-value".into());
        assert!(redactor
            .verify_canonical(&serde_json::to_vec(&content).unwrap())
            .is_err());
        assert!(redactor
            .verify_canonical(br#"{"token":"library","tokenizerUnavailable":false}"#)
            .is_err());
        register_secret(KEYWORD);
        assert!(redactor.verify_canonical(&original).is_err());
        assert!(redactor
            .verify_canonical_jsonl_owned(approved.into_inner())
            .is_err());
    }

    #[test]
    fn canonical_verification_checks_decoded_values_without_mutating_digests() {
        let redactor = Redactor::new();
        let input = serde_json::json!({
            "article": {
                "mainDigest": crate::hash::Digest::of("test/article", b"safe").to_hex(),
                "privacyProjectionVersion": 1,
            },
            "text": "safe",
            "password": "[REDACTED]",
        })
        .to_string();
        assert_eq!(
            redactor.verify_canonical(input.as_bytes()).unwrap().as_ref(),
            input.as_bytes()
        );
        register_secret("canonical-decoded-canary-97e4");
        assert!(redactor
            .verify_canonical(
                br#"{"text":"canonical-\u0064ecoded-canary-97e4","privacyProjectionVersion":1}"#
            )
            .is_err());
        assert!(redactor
            .verify_canonical(br#"{"password":"unknown-password"}"#)
            .is_err());
        assert!(redactor
            .verify_canonical(b"authorization: Bearer unknown-key")
            .is_err());
        assert!(redactor.verify_canonical(b"/?sessionid=unknown-session").is_err());
        assert!(redactor.verify_canonical(b"\xff").is_err());
    }

    #[test]
    fn canonical_jsonl_checks_every_record_without_losing_framing_or_privacy() {
        let redactor = Redactor::new();
        let safe = b"{\"n\":1}\n{\"password\":\"[REDACTED]\",\"n\":2}\n";
        assert_eq!(
            redactor
                .verify_canonical_jsonl_owned(safe.to_vec())
                .unwrap()
                .as_ref(),
            safe
        );
        assert!(redactor
            .verify_canonical_jsonl_owned(Vec::new())
            .unwrap()
            .as_ref()
            .is_empty());
        for unsafe_stream in [
            b"{\"n\":1}\nnot-json\n".as_slice(),
            b"{\"n\":1}\n{\"n\":2".as_slice(),
            b"{\"n\":1}\n{\"n\":2,\"n\":3}\n".as_slice(),
            b"{\"n\":1}\n\n{\"n\":2}\n".as_slice(),
            b"{\"n\":1}\n{\"password\":\"unregistered-value\"}\n".as_slice(),
            b"{\"n\":1}\n{\"text\":\"Bearer unregistered-value\"}\n".as_slice(),
            b"{\"n\":1}\n{\"text\":\"\xff\"}\n".as_slice(),
        ] {
            assert!(redactor
                .verify_canonical_jsonl_owned(unsafe_stream.to_vec())
                .is_err());
        }
        register_secret("jsonl-decoded-canary-9e42");
        assert!(redactor
            .verify_canonical_jsonl_owned(
                b"{\"n\":1}\n{\"text\":\"jsonl-\\u0064ecoded-canary-9e42\"}\n".to_vec()
            )
            .is_err());
        register_secret("jsonl-stream-canary-7c21\"}\n{\"text\":\"second");
        assert!(redactor
            .verify_canonical_jsonl_owned(
                b"{\"text\":\"jsonl-stream-canary-7c21\"}\n{\"text\":\"second\"}\n".to_vec()
            )
            .is_err());
    }

    #[test]
    fn binary_verification_preserves_real_pdf_and_rejects_without_scrubbing() {
        let redactor = Redactor::new();
        let pdf = include_bytes!("../../../crawlx-extract/tests/fixtures/ocr/ccitt_g4.pdf");
        assert_eq!(redactor.verify_binary(pdf).unwrap().as_ref(), pdf);
        let ascii_pdf = b"%PDF-1.7\n% 0123456789abcdef0123456789abcdef\n%%EOF";
        assert_eq!(redactor.verify_binary(ascii_pdf).unwrap().as_ref(), ascii_pdf);
        let mut contaminated = pdf.to_vec();
        contaminated.extend_from_slice(b"\0opaque-boundary-canary-f295");
        register_secret("opaque-boundary-canary-f295");
        assert!(redactor.verify_binary(&contaminated).is_err());
        assert!(contaminated.ends_with(b"opaque-boundary-canary-f295"));
        assert!(redactor.verify_binary(b"\xffpassword=unknown-value\0").is_err());
    }

    #[test]
    fn binary_placeholders_preserve_framing_but_never_approve_a_secret_suffix() {
        let redactor = Redactor::new();
        for safe in [
            b"/URI (https://example.test/?token=[REDACTED])".as_slice(),
            br#"{"password":"[REDACTED]"}"#,
            b"\xfftoken=[REDACTED]\0",
        ] {
            assert_eq!(redactor.verify_binary(safe).unwrap().as_ref(), safe);
        }
        for unsafe_bytes in [
            b"/URI (https://example.test/?token=[REDACTED]still-secret)".as_slice(),
            br#"{"password":"[REDACTED]still-secret"}"#,
            b"\xfftoken=[REDACTED]still-secret\0",
        ] {
            assert!(redactor.verify_binary(unsafe_bytes).is_err());
        }
    }

    #[test]
    fn duplicate_json_members_cannot_hide_registered_secrets_from_canonical_approval() {
        register_secret("duplicate-canonical-canary-q7m2");
        let input = br#"{"data":"duplicate-canonical-\u0063anary-q7m2","data":"safe"}"#;
        assert!(Redactor::new().verify_canonical(input).is_err());
    }

    #[test]
    fn duplicate_json_members_cannot_hide_registered_secrets_from_binary_approval() {
        register_secret("duplicate-binary-canary-q7m2");
        let input = br#"{"nested":{"data":"duplicate-binary-\u0063anary-q7m2","data":"safe"}}"#;
        assert!(Redactor::new().verify_binary(input).is_err());
    }

    #[test]
    fn duplicate_json_members_cannot_retain_registered_secrets_in_redacted_artifacts() {
        register_secret("duplicate-artifact-canary-q7m2");
        let input = br#"{"data":"duplicate-artifact-\u0063anary-q7m2","data":"safe"}"#;
        match Redactor::new().redact_artifact(input) {
            Ok(approved) => {
                let output = std::str::from_utf8(approved.as_ref()).unwrap();
                assert!(!output.contains("duplicate-artifact-canary-q7m2"));
                assert!(!output.contains(r"duplicate-artifact-\u0063anary-q7m2"));
            }
            Err(crate::StoreError::RetentionDenied(_)) => {}
            Err(error) => panic!("unexpected artifact approval error: {error}"),
        }
    }

    #[test]
    fn duplicate_json_members_cannot_retain_registered_secrets_in_redacted_text() {
        register_secret("duplicate-text-canary-q7m2");
        let input = r#"{"data":"duplicate-text-\u0063anary-q7m2","data":"safe"}"#;
        let approved = Redactor::new().redact_text(input);
        assert!(!approved.as_inner().contains("duplicate-text-canary-q7m2"));
        assert!(!approved.as_inner().contains(r"duplicate-text-\u0063anary-q7m2"));
    }

    #[tokio::test]
    async fn artifact_sink_persists_only_redactor_output() {
        use crate::repo::{ArtifactStore, Sensitivity};
        struct RecordingStore(parking_lot::Mutex<Vec<u8>>);
        #[async_trait::async_trait]
        impl ArtifactStore for RecordingStore {
            async fn put(
                &self,
                _run: crate::CrawlRunId,
                _class: Sensitivity,
                _content_type: &str,
                bytes: &[u8],
            ) -> Result<crate::ArtifactRef, crate::StoreError> {
                *self.0.lock() = bytes.to_vec();
                Ok(crate::ArtifactRef {
                    id: crate::ArtifactId::new(),
                    digest: crate::hash::Digest::of("test/artifact", bytes),
                })
            }
            async fn get(&self, _artifact: &crate::ArtifactRef) -> Result<Vec<u8>, crate::StoreError> {
                Ok(self.0.lock().clone())
            }
        }
        register_secret("artifact-persistence-canary-c3b7");
        let store = RecordingStore(parking_lot::Mutex::new(Vec::new()));
        let approved = Redactor::new().redact_text("before artifact-persistence-canary-c3b7 after");
        let reference = super::super::ArtifactSink::over(&store)
            .put(
                crate::CrawlRunId::new(),
                Sensitivity::Content,
                "text/plain",
                &approved,
            )
            .await
            .unwrap();
        assert_eq!(store.get(&reference).await.unwrap(), b"before [REDACTED] after");
    }

    #[test]
    fn redact_field_masks_by_name_regardless_of_type() {
        let r = Redactor::new();
        assert_eq!(
            r.redact_field("password", Value::from(123_456_u64)),
            Value::String(REDACTED.into())
        );
        assert_eq!(r.redact_field("count", Value::from(3_u64)), Value::from(3_u64));
    }
}
