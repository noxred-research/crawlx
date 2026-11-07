//! Custom regex fields evaluated at extraction time (`extract.customFields[]`).
//!
//! Ported from projectdiscovery/katana `pkg/engine/parser/parser.go`
//! (`customFieldRegexParser`) and `pkg/output/custom_field.go` at commit
//! 9662cd7 (MIT). The serde shape is [`crawlx_core::config::CustomField`]
//! (`name`, `regex[]`, `part`, `group`); this module compiles it into a
//! bounded [`CustomField`] and runs it over headers and body.
//!
//! Bounds: at most [`MAX_FIELDS`] fields, each pattern at most
//! [`MAX_PATTERN_LEN`] bytes and compiled under a fixed size limit, so a
//! request can never make extraction allocate unboundedly.

use std::collections::BTreeMap;

use regex::{Regex, RegexBuilder};

pub use crawlx_core::config::CustomField as CustomFieldSpec;
pub use crawlx_core::config::CustomFieldPart as Part;

/// Maximum number of custom fields per request.
pub const MAX_FIELDS: usize = 32;
/// Maximum pattern length in bytes.
pub const MAX_PATTERN_LEN: usize = 512;
/// Maximum values kept per field per page.
pub const MAX_VALUES_PER_FIELD: usize = 1_000;
/// Compiled-program size limit per pattern.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Why a custom field specification was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum CustomFieldError {
    /// More than [`MAX_FIELDS`] fields.
    #[error("too many custom fields: {count} exceeds {MAX_FIELDS}")]
    TooMany {
        /// Fields supplied.
        count: usize,
    },
    /// The name is not `[A-Za-z0-9_-]{1,64}`.
    #[error("invalid custom field name `{name}`")]
    InvalidName {
        /// Offending name.
        name: String,
    },
    /// A field has no patterns.
    #[error("custom field `{name}` has no regex")]
    NoPatterns {
        /// Field name.
        name: String,
    },
    /// A pattern is longer than [`MAX_PATTERN_LEN`].
    #[error("custom field `{name}`: pattern length {len} exceeds {MAX_PATTERN_LEN}")]
    PatternTooLong {
        /// Field name.
        name: String,
        /// Pattern length in bytes.
        len: usize,
    },
    /// A pattern does not compile or exceeds the size limit.
    #[error("custom field `{name}`: invalid regex: {reason}")]
    InvalidPattern {
        /// Field name.
        name: String,
        /// Compiler message.
        reason: String,
    },
    /// `group` is larger than the capture-group count of a pattern.
    #[error("custom field `{name}`: group {group} exceeds the {groups} capture groups of a pattern")]
    GroupOutOfRange {
        /// Field name.
        name: String,
        /// Requested group.
        group: u32,
        /// Capture groups in the pattern.
        groups: usize,
    },
}

/// A compiled custom field.
#[derive(Debug, Clone)]
pub struct CustomField {
    /// Field name.
    pub name: String,
    /// Compiled patterns, one per `regex[]` entry.
    pub regex: Vec<Regex>,
    /// Response part to scan.
    pub part: Part,
    /// Capture group whose text is the value (0 = whole match).
    pub group: usize,
}

impl PartialEq for CustomField {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.part == other.part
            && self.group == other.group
            && self.regex.len() == other.regex.len()
            && self
                .regex
                .iter()
                .zip(&other.regex)
                .all(|(a, b)| a.as_str() == b.as_str())
    }
}

impl Eq for CustomField {}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl CustomField {
    /// Compile one specification.
    ///
    /// # Errors
    /// Any [`CustomFieldError`] variant except `TooMany`.
    pub fn compile(spec: &CustomFieldSpec) -> Result<Self, CustomFieldError> {
        let name = spec.name.clone();
        if !valid_name(&name) {
            return Err(CustomFieldError::InvalidName { name });
        }
        if spec.regex.is_empty() {
            return Err(CustomFieldError::NoPatterns { name });
        }
        let group = usize::try_from(spec.group).unwrap_or(usize::MAX);
        let mut regex = Vec::with_capacity(spec.regex.len());
        for pattern in &spec.regex {
            if pattern.len() > MAX_PATTERN_LEN {
                return Err(CustomFieldError::PatternTooLong {
                    name,
                    len: pattern.len(),
                });
            }
            let re = RegexBuilder::new(pattern)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|e| CustomFieldError::InvalidPattern {
                    name: name.clone(),
                    reason: e.to_string(),
                })?;
            let groups = re.captures_len().saturating_sub(1);
            if group > groups {
                return Err(CustomFieldError::GroupOutOfRange {
                    name,
                    group: spec.group,
                    groups,
                });
            }
            regex.push(re);
        }
        Ok(Self {
            name,
            regex,
            part: spec.part,
            group,
        })
    }

    /// Compile a whole `extract.customFields[]` list.
    ///
    /// # Errors
    /// [`CustomFieldError::TooMany`] above [`MAX_FIELDS`]; otherwise the first field error.
    pub fn compile_all(specs: &[CustomFieldSpec]) -> Result<Vec<Self>, CustomFieldError> {
        if specs.len() > MAX_FIELDS {
            return Err(CustomFieldError::TooMany { count: specs.len() });
        }
        specs.iter().map(Self::compile).collect()
    }

    fn collect(&self, haystack: &str, out: &mut Vec<String>) {
        for re in &self.regex {
            for caps in re.captures_iter(haystack) {
                if out.len() >= MAX_VALUES_PER_FIELD {
                    return;
                }
                if let Some(m) = caps.get(self.group) {
                    out.push(m.as_str().to_owned());
                }
            }
        }
    }
}

/// Evaluate `fields` over `headers` (`name: value` lines) and `body`.
/// Fields with no match are absent; values keep match order.
#[must_use]
pub fn extract(
    fields: &[CustomField],
    headers: &[(String, String)],
    body: &str,
) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for field in fields {
        let mut values = Vec::new();
        if matches!(field.part, Part::Body | Part::Response) {
            field.collect(body, &mut values);
        }
        if matches!(field.part, Part::Header | Part::Response) {
            for (name, value) in headers {
                field.collect(&format!("{name}: {value}"), &mut values);
            }
        }
        if !values.is_empty() {
            out.insert(field.name.clone(), values);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn spec(name: &str, regex: &[&str], part: Part, group: u32) -> CustomFieldSpec {
        CustomFieldSpec {
            name: name.to_owned(),
            regex: regex.iter().map(|s| (*s).to_owned()).collect(),
            part,
            group,
        }
    }

    #[test]
    fn rejects_bad_specs() {
        assert!(matches!(
            CustomField::compile(&spec("bad name", &["x"], Part::Body, 0)),
            Err(CustomFieldError::InvalidName { .. })
        ));
        assert!(matches!(
            CustomField::compile(&spec("e", &[], Part::Body, 0)),
            Err(CustomFieldError::NoPatterns { .. })
        ));
        let long = "a".repeat(MAX_PATTERN_LEN + 1);
        assert!(matches!(
            CustomField::compile(&spec("e", &[&long], Part::Body, 0)),
            Err(CustomFieldError::PatternTooLong { .. })
        ));
        assert!(matches!(
            CustomField::compile(&spec("e", &["("], Part::Body, 0)),
            Err(CustomFieldError::InvalidPattern { .. })
        ));
        assert!(matches!(
            CustomField::compile(&spec("e", &["(a)"], Part::Body, 2)),
            Err(CustomFieldError::GroupOutOfRange { .. })
        ));
        let many: Vec<_> = (0..=MAX_FIELDS)
            .map(|i| spec(&format!("f{i}"), &["x"], Part::Body, 0))
            .collect();
        assert!(matches!(
            CustomField::compile_all(&many),
            Err(CustomFieldError::TooMany { .. })
        ));
    }

    #[test]
    fn serde_shape_is_yaml_friendly() {
        let json = r#"{"name":"email","regex":["([a-z]+)@example.org"],"part":"response","group":1}"#;
        let s: CustomFieldSpec = serde_json::from_str(json).unwrap();
        assert_eq!(s.part, Part::Response);
        assert_eq!(s.group, 1);
        let minimal: CustomFieldSpec = serde_json::from_str(r#"{"name":"x","regex":["y"]}"#).unwrap();
        assert_eq!(minimal.part, Part::Body);
        assert_eq!(minimal.group, 0);
    }
}
