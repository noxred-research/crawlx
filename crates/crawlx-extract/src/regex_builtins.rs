//! Safe regex extraction: a versioned table of built-in pattern names plus custom patterns.
//!
//! Every pattern runs on the linear-time `regex` engine. [`compile_regex`] is the admission gate
//! of this table (it delegates to the shared core gate): patterns with backreferences or
//! look-around (which that engine cannot run without catastrophic backtracking) fail with a
//! typed [`RegexError`] before anything is compiled, and compiled size, capture groups, input
//! bytes and match counts are all bounded.
//!
//! Built-in names carry a version (`email.v1`). A bare name (`email`) resolves to the newest
//! version that exists; a versioned name stays pinned when the table later grows a revision.

use std::collections::BTreeMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Longest pattern accepted, in bytes.
pub const MAX_PATTERN_LEN: usize = crawlx_core::extraction::MAX_REGEX_PATTERN_LEN;
/// Most capture groups (including the whole match) in one pattern.
pub const MAX_CAPTURE_GROUPS: usize = crawlx_core::extraction::MAX_REGEX_CAPTURE_GROUPS;
/// Most patterns in one extraction request.
pub const MAX_PATTERNS: usize = 32;
/// Largest input scanned, in bytes.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
/// Most matches kept per pattern.
pub const MAX_MATCHES_PER_PATTERN: usize = 1_000;
/// Longest single match kept, in bytes; longer matches are skipped and flagged as truncated.
pub const MAX_MATCH_BYTES: usize = 64 * 1024;
/// Revision of the built-in pattern table as a whole.
pub const PATTERN_TABLE_VERSION: u16 = 1;

/// One entry of the built-in pattern table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuiltinPattern {
    /// Name without version, for example `email`.
    pub name: &'static str,
    /// Revision of this pattern; a changed pattern gets a new revision, never an edit.
    pub version: u16,
    /// Pattern source in the linear-time dialect.
    pub pattern: &'static str,
    /// Capture group reported as the value (zero is the whole match).
    pub group: usize,
    /// One-line description of what the pattern recognizes.
    pub description: &'static str,
}

impl BuiltinPattern {
    /// Pinned name, for example `email.v1`.
    #[must_use]
    pub fn versioned_name(&self) -> String {
        format!("{}.v{}", self.name, self.version)
    }
}

const fn entry(
    name: &'static str,
    pattern: &'static str,
    group: usize,
    description: &'static str,
) -> BuiltinPattern {
    BuiltinPattern {
        name,
        version: 1,
        pattern,
        group,
        description,
    }
}

/// The built-in pattern table, sorted by name then version.
pub const BUILTINS: &[BuiltinPattern] = &[
    entry(
        "currency",
        r"(?:[$€£¥₹]\s?[0-9]{1,3}(?:[, ][0-9]{3})*(?:\.[0-9]{1,2})?|[0-9]{1,3}(?:[, ][0-9]{3})*(?:\.[0-9]{1,2})?\s?(?:USD|EUR|GBP|JPY|CHF|CAD|AUD|INR|CNY)\b)",
        0,
        "amount with a currency symbol prefix or an ISO currency code suffix",
    ),
    entry(
        "date_iso",
        r"\b[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])\b",
        0,
        "calendar date in year-month-day form",
    ),
    entry(
        "date_like",
        r"\b(?:[0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2}|[0-9]{1,2}[-/.][0-9]{1,2}[-/.][0-9]{2,4})\b",
        0,
        "numeric date with dash, slash or dot separators in either field order",
    ),
    entry(
        "email",
        r"[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24}",
        0,
        "email address",
    ),
    entry(
        "hashtag",
        r"(?:^|[\s(])#(\p{L}[\p{L}\p{N}_]*)",
        1,
        "hash-prefixed word, reported without the hash",
    ),
    entry(
        "hex_color",
        r"#(?:[0-9A-Fa-f]{8}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{3})\b",
        0,
        "CSS hexadecimal color",
    ),
    entry(
        "ipv4",
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b",
        0,
        "dotted-quad IPv4 address with octets in range",
    ),
    entry(
        "ipv6_full",
        r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b",
        0,
        "uncompressed eight-group IPv6 address",
    ),
    entry(
        "mention",
        r"(?:^|[\s(])@([A-Za-z0-9_]{1,30})\b",
        1,
        "at-prefixed handle, reported without the at sign",
    ),
    entry(
        "number",
        r"-?[0-9]{1,3}(?:,[0-9]{3})+(?:\.[0-9]+)?|-?[0-9]+(?:\.[0-9]+)?",
        0,
        "decimal number, optionally with thousands separators",
    ),
    entry(
        "percentage",
        r"\b[0-9]{1,3}(?:\.[0-9]+)?%",
        0,
        "number followed by a percent sign",
    ),
    entry(
        "phone_like",
        r"(?:\+?[0-9]{1,3}[\s.\-]?)?(?:\([0-9]{2,4}\)|[0-9]{2,4})[\s.\-]?[0-9]{3,4}[\s.\-]?[0-9]{3,4}\b",
        0,
        "phone-number-shaped digit group with optional country code and separators",
    ),
    entry(
        "sha256_hex",
        r"\b[0-9a-f]{64}\b",
        0,
        "lowercase hexadecimal 256-bit digest",
    ),
    entry(
        "time_like",
        r"\b(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9])?\b",
        0,
        "24-hour clock time with optional seconds",
    ),
    entry(
        "url",
        r"\bhttps?://[A-Za-z0-9\-._~:/?#@!$&'*+,;=%()\[\]]*[A-Za-z0-9\-_~/#@$&+=%]",
        0,
        "HTTP or HTTPS URL without trailing punctuation",
    ),
    entry(
        "us_zip",
        r"\b[0-9]{5}(?:-[0-9]{4})?\b",
        0,
        "United States ZIP or ZIP+4 code",
    ),
    entry(
        "uuid",
        r"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b",
        0,
        "canonical hyphenated UUID",
    ),
];

/// Why a pattern or an extraction request was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegexError {
    /// The pattern is empty.
    #[error("pattern is empty")]
    Empty,
    /// The pattern is longer than [`MAX_PATTERN_LEN`].
    #[error("pattern length {len} exceeds {MAX_PATTERN_LEN} bytes")]
    TooLong {
        /// Pattern length in bytes.
        len: usize,
    },
    /// The pattern uses a backreference, which the linear-time engine cannot evaluate.
    #[error("backreferences are not supported")]
    Backreference,
    /// The pattern uses look-ahead or look-behind, which the linear-time engine cannot evaluate.
    #[error("look-around assertions are not supported")]
    Lookaround,
    /// The pattern is not valid regex syntax.
    #[error("invalid pattern: {0}")]
    Syntax(String),
    /// The pattern nests too deeply, has too many capture groups or compiles above the size limit.
    #[error("pattern exceeds the nesting, capture-group or compiled-size limit")]
    TooComplex,
    /// The built-in name or version is not in the table.
    #[error("unknown built-in pattern `{0}`")]
    UnknownBuiltin(String),
    /// The requested group is larger than the pattern's capture-group count.
    #[error("group {group} exceeds the {groups} capture groups of the pattern")]
    GroupOutOfRange {
        /// Requested group.
        group: usize,
        /// Capture groups in the pattern, excluding the whole match.
        groups: usize,
    },
    /// A specification names both or neither of `builtin` and `pattern`.
    #[error("exactly one of `builtin` and `pattern` is required")]
    SpecAmbiguous,
    /// A label is empty, longer than 64 bytes or outside `[A-Za-z0-9_.-]`.
    #[error("invalid pattern label")]
    InvalidLabel,
    /// Two patterns share a label.
    #[error("duplicate pattern label `{0}`")]
    DuplicateLabel(String),
    /// More than [`MAX_PATTERNS`] patterns.
    #[error("too many patterns: {count} exceeds {MAX_PATTERNS}")]
    TooManyPatterns {
        /// Patterns supplied.
        count: usize,
    },
    /// The input is larger than [`MAX_INPUT_BYTES`].
    #[error("input of {len} bytes exceeds {MAX_INPUT_BYTES}")]
    InputTooLarge {
        /// Input length in bytes.
        len: usize,
    },
}

/// Find a built-in by bare or versioned name (`email` or `email.v1`).
///
/// A bare name resolves to its highest version.
///
/// # Errors
/// [`RegexError::UnknownBuiltin`] when the name or pinned version is not in the table.
pub fn builtin(name: &str) -> Result<&'static BuiltinPattern, RegexError> {
    let unknown = || RegexError::UnknownBuiltin(name.chars().take(64).collect());
    let (base, pinned) = match name.rsplit_once(".v") {
        Some((base, version)) if !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()) => {
            (base, Some(version.parse::<u16>().map_err(|_| unknown())?))
        }
        _ => (name, None),
    };
    BUILTINS
        .iter()
        .filter(|p| p.name == base && pinned.is_none_or(|v| p.version == v))
        .max_by_key(|p| p.version)
        .ok_or_else(unknown)
}

/// Pinned names of every built-in, sorted.
#[must_use]
pub fn builtin_names() -> Vec<String> {
    let mut names: Vec<String> = BUILTINS.iter().map(BuiltinPattern::versioned_name).collect();
    names.sort_unstable();
    names
}

/// Admit and compile one pattern for the linear-time engine.
///
/// # Errors
/// [`RegexError::Empty`], [`RegexError::TooLong`], [`RegexError::Backreference`],
/// [`RegexError::Lookaround`], [`RegexError::Syntax`] or [`RegexError::TooComplex`].
pub fn compile_regex(pattern: &str) -> Result<Regex, RegexError> {
    crawlx_core::extraction::admit_regex(pattern).map_err(|error| {
        use crawlx_core::extraction::RegexAdmissionError as Admission;
        match error {
            Admission::Empty => RegexError::Empty,
            Admission::TooLong { len } => RegexError::TooLong { len },
            Admission::Backreference => RegexError::Backreference,
            Admission::Lookaround => RegexError::Lookaround,
            Admission::Syntax(message) => RegexError::Syntax(message),
            // `TooComplex` and any future admission refusal share the complexity error.
            _ => RegexError::TooComplex,
        }
    })
}

/// Serialized request for one pattern: a built-in name or a custom pattern.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RegexPatternSpec {
    /// Result key; defaults to the pinned built-in name and is required for custom patterns.
    pub label: Option<String>,
    /// Built-in name, bare or versioned.
    pub builtin: Option<String>,
    /// Custom pattern in the linear-time dialect.
    pub pattern: Option<String>,
    /// Capture group reported as the value; a built-in's own group when omitted.
    pub group: Option<usize>,
}

impl RegexPatternSpec {
    /// Built-in request.
    #[must_use]
    pub fn builtin(name: &str) -> Self {
        Self {
            builtin: Some(name.to_owned()),
            ..Self::default()
        }
    }

    /// Custom pattern request.
    #[must_use]
    pub fn custom(label: &str, pattern: &str, group: usize) -> Self {
        Self {
            label: Some(label.to_owned()),
            pattern: Some(pattern.to_owned()),
            group: Some(group),
            ..Self::default()
        }
    }
}

/// A compiled pattern ready to run over text.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    label: String,
    regex: Regex,
    group: usize,
}

impl CompiledPattern {
    /// Admit one specification.
    ///
    /// # Errors
    /// Any [`RegexError`] except `TooManyPatterns`, `DuplicateLabel` and `InputTooLarge`.
    pub fn compile(spec: &RegexPatternSpec) -> Result<Self, RegexError> {
        let (default_label, source, default_group) = match (&spec.builtin, &spec.pattern) {
            (Some(name), None) => {
                let found = builtin(name)?;
                (Some(found.versioned_name()), found.pattern, found.group)
            }
            (None, Some(pattern)) => (None, pattern.as_str(), 0),
            _ => return Err(RegexError::SpecAmbiguous),
        };
        let label = spec
            .label
            .clone()
            .or(default_label)
            .ok_or(RegexError::InvalidLabel)?;
        if label.is_empty()
            || label.len() > 64
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
        {
            return Err(RegexError::InvalidLabel);
        }
        let regex = compile_regex(source)?;
        let group = spec.group.unwrap_or(default_group);
        let groups = regex.captures_len().saturating_sub(1);
        if group > groups {
            return Err(RegexError::GroupOutOfRange { group, groups });
        }
        Ok(Self { label, regex, group })
    }

    /// Admit a whole request: at most [`MAX_PATTERNS`] patterns with distinct labels.
    ///
    /// # Errors
    /// The first [`RegexError`] met, `TooManyPatterns` or `DuplicateLabel`.
    pub fn compile_all(specs: &[RegexPatternSpec]) -> Result<Vec<Self>, RegexError> {
        if specs.len() > MAX_PATTERNS {
            return Err(RegexError::TooManyPatterns { count: specs.len() });
        }
        let mut labels = std::collections::BTreeSet::new();
        let mut out = Vec::with_capacity(specs.len());
        for spec in specs {
            let compiled = Self::compile(spec)?;
            if !labels.insert(compiled.label.clone()) {
                return Err(RegexError::DuplicateLabel(compiled.label));
            }
            out.push(compiled);
        }
        Ok(out)
    }

    /// Result key of this pattern.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
}

/// One matched value with its byte span in the input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegexMatch {
    /// Text of the selected capture group.
    pub value: String,
    /// Inclusive start byte offset in the input.
    pub start: usize,
    /// Exclusive end byte offset in the input.
    pub end: usize,
}

/// Matches of one pattern, in input order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RegexExtraction {
    /// Kept matches, at most [`MAX_MATCHES_PER_PATTERN`].
    pub matches: Vec<RegexMatch>,
    /// More matches existed than were kept, or an over-long match was skipped.
    pub truncated: bool,
}

/// Run `patterns` over `text`, one [`RegexExtraction`] per label (labels without a match map to an
/// empty extraction so the result shape never depends on the input).
///
/// # Errors
/// [`RegexError::InputTooLarge`] above [`MAX_INPUT_BYTES`].
pub fn extract(
    patterns: &[CompiledPattern],
    text: &str,
) -> Result<BTreeMap<String, RegexExtraction>, RegexError> {
    if text.len() > MAX_INPUT_BYTES {
        return Err(RegexError::InputTooLarge { len: text.len() });
    }
    let mut out = BTreeMap::new();
    for pattern in patterns {
        let mut result = RegexExtraction::default();
        for caps in pattern.regex.captures_iter(text) {
            let Some(found) = caps.get(pattern.group) else {
                continue;
            };
            if result.matches.len() >= MAX_MATCHES_PER_PATTERN {
                result.truncated = true;
                break;
            }
            if found.len() > MAX_MATCH_BYTES {
                result.truncated = true;
                continue;
            }
            result.matches.push(RegexMatch {
                value: found.as_str().to_owned(),
                start: found.start(),
                end: found.end(),
            });
        }
        out.insert(pattern.label.clone(), result);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn values(label: &str, text: &str) -> Vec<String> {
        let compiled = CompiledPattern::compile(&RegexPatternSpec::builtin(label)).unwrap();
        let key = compiled.label().to_owned();
        extract(&[compiled], text).unwrap()[&key]
            .matches
            .iter()
            .map(|m| m.value.clone())
            .collect()
    }

    #[test]
    fn every_builtin_compiles_and_names_are_unique_and_sorted() {
        for pattern in BUILTINS {
            CompiledPattern::compile(&RegexPatternSpec::builtin(&pattern.versioned_name())).unwrap();
        }
        let names = builtin_names();
        assert!(names.windows(2).all(|w| w[0] < w[1]));
        assert!(BUILTINS
            .windows(2)
            .all(|w| (w[0].name, w[0].version) < (w[1].name, w[1].version)));
    }

    #[test]
    fn bare_and_pinned_names_resolve_to_the_same_revision() {
        assert_eq!(builtin("email").unwrap(), builtin("email.v1").unwrap());
        assert_eq!(builtin("email").unwrap().versioned_name(), "email.v1");
        assert!(matches!(builtin("email.v9"), Err(RegexError::UnknownBuiltin(_))));
        assert!(matches!(builtin("nope"), Err(RegexError::UnknownBuiltin(_))));
    }

    #[test]
    fn builtins_extract_expected_values() {
        let text = "Mail a.b+c@example.co.uk or x@y.org. Site https://example.com/a?b=1, then http://h.test. \
                    Call +1 415-555-0132. Host 192.168.1.10 not 999.1.1.1 id 123e4567-e89b-12d3-a456-426614174000 \
                    on 2024-02-29 and 3/4/2025 for $1,299.50 or 20 EUR #rust @crawler 12:30:05 #ff00aa 94107-1234 45.5%";
        assert_eq!(values("email", text), ["a.b+c@example.co.uk", "x@y.org"]);
        assert_eq!(
            values("url", text),
            ["https://example.com/a?b=1", "http://h.test"]
        );
        assert_eq!(values("ipv4", text), ["192.168.1.10"]);
        assert_eq!(values("uuid", text), ["123e4567-e89b-12d3-a456-426614174000"]);
        assert_eq!(values("date_iso", text), ["2024-02-29"]);
        assert!(values("date_like", text).contains(&"3/4/2025".to_owned()));
        assert_eq!(values("currency", text), ["$1,299.50", "20 EUR"]);
        assert_eq!(values("hashtag", text), ["rust", "ff00aa"]);
        assert_eq!(values("mention", text), ["crawler"]);
        assert_eq!(values("time_like", text), ["12:30:05"]);
        assert_eq!(values("hex_color", text), ["#ff00aa"]);
        assert_eq!(values("us_zip", text), ["94107-1234"]);
        assert_eq!(values("percentage", text), ["45.5%"]);
        assert!(values("phone_like", text)
            .iter()
            .any(|v| v.contains("415-555-0132")));
    }

    #[test]
    fn unsupported_constructs_are_rejected_at_admission_with_typed_errors() {
        assert_eq!(compile_regex(r"(a)\1").unwrap_err(), RegexError::Backreference);
        assert_eq!(compile_regex(r"a(?=b)").unwrap_err(), RegexError::Lookaround);
        assert_eq!(compile_regex(r"a(?!b)").unwrap_err(), RegexError::Lookaround);
        assert_eq!(compile_regex(r"(?<=a)b").unwrap_err(), RegexError::Lookaround);
        assert_eq!(compile_regex(r"(?<!a)b").unwrap_err(), RegexError::Lookaround);
        assert!(matches!(compile_regex("("), Err(RegexError::Syntax(_))));
        assert_eq!(compile_regex("").unwrap_err(), RegexError::Empty);
        assert!(matches!(
            compile_regex(&"a".repeat(MAX_PATTERN_LEN + 1)),
            Err(RegexError::TooLong { .. })
        ));
        assert_eq!(
            compile_regex(&format!("{}x{}", "(".repeat(100), ")".repeat(100))).unwrap_err(),
            RegexError::TooComplex
        );
        assert_eq!(
            compile_regex(r"(\w{1000}){1000}").unwrap_err(),
            RegexError::TooComplex
        );
    }

    #[test]
    fn catastrophic_shapes_stay_linear() {
        let compiled = CompiledPattern::compile(&RegexPatternSpec::custom("nested", r"(a+)+$", 0)).unwrap();
        let hostile = format!("{}!", "a".repeat(200_000));
        let out = extract(&[compiled], &hostile).unwrap();
        assert!(out["nested"].matches.is_empty());
    }

    #[test]
    fn requests_are_bounded_and_deterministic() {
        let specs = vec![
            RegexPatternSpec::custom("digits", r"(\d)(\d)", 2),
            RegexPatternSpec::builtin("uuid"),
        ];
        let compiled = CompiledPattern::compile_all(&specs).unwrap();
        let out = extract(&compiled, "12 34 56").unwrap();
        assert_eq!(
            out["digits"]
                .matches
                .iter()
                .map(|m| (&*m.value, m.start))
                .collect::<Vec<_>>(),
            [("2", 1), ("4", 4), ("6", 7)]
        );
        assert!(out["uuid.v1"].matches.is_empty());
        assert_eq!(
            CompiledPattern::compile(&RegexPatternSpec::custom("g", "(a)", 2)).unwrap_err(),
            RegexError::GroupOutOfRange { group: 2, groups: 1 }
        );
        assert_eq!(
            CompiledPattern::compile(&RegexPatternSpec::default()).unwrap_err(),
            RegexError::SpecAmbiguous
        );
        assert!(matches!(
            CompiledPattern::compile_all(&[
                RegexPatternSpec::builtin("uuid"),
                RegexPatternSpec::builtin("uuid.v1")
            ]),
            Err(RegexError::DuplicateLabel(_))
        ));
        let many: Vec<_> = (0..=MAX_PATTERNS)
            .map(|i| RegexPatternSpec::custom(&format!("p{i}"), "x", 0))
            .collect();
        assert!(matches!(
            CompiledPattern::compile_all(&many),
            Err(RegexError::TooManyPatterns { .. })
        ));
        let big = "x".repeat(MAX_INPUT_BYTES + 1);
        assert!(matches!(
            extract(&compiled, &big),
            Err(RegexError::InputTooLarge { .. })
        ));
    }

    #[test]
    fn match_counts_are_capped_and_flagged() {
        let compiled = CompiledPattern::compile(&RegexPatternSpec::custom("x", "x", 0)).unwrap();
        let out = extract(&[compiled], &"x".repeat(MAX_MATCHES_PER_PATTERN + 5)).unwrap();
        assert_eq!(out["x"].matches.len(), MAX_MATCHES_PER_PATTERN);
        assert!(out["x"].truncated);
    }

    #[test]
    fn spec_serde_shape_rejects_unknown_keys() {
        let spec: RegexPatternSpec = serde_json::from_str(r#"{"builtin":"email"}"#).unwrap();
        assert_eq!(spec, RegexPatternSpec::builtin("email"));
        assert!(serde_json::from_str::<RegexPatternSpec>(r#"{"builtin":"email","eval":"x"}"#).is_err());
    }
}
