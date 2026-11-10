//! Pre-acquisition URL exclusion policy.
//!
//! Evaluated on a canonical URL string before any request exists, so an excluded URL costs zero
//! target requests. It is separate from content gates such as author exclusion: an excluded URL
//! never reaches extraction, while an excluded author is observed content that is rejected from
//! ingestion with its own quality reason.

use crate::CoreError;
use serde::{Deserialize, Serialize};

/// Most substrings or patterns per list.
pub const MAX_URL_EXCLUSION_RULES: usize = 256;
/// Longest substring or pattern in bytes.
pub const MAX_URL_EXCLUSION_RULE_BYTES: usize = 512;

/// Bounded URL exclusion lists.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct UrlExclusionPolicyV1 {
    /// Case-insensitive substrings of the canonical URL string. At most 256, each non-empty and
    /// at most 512 bytes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub substrings: Vec<String>,
    /// Regular expressions matched anywhere in the canonical URL string. At most 256, each
    /// non-empty and at most 512 bytes; compiled with fixed size and nesting limits.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub patterns: Vec<String>,
}
impl UrlExclusionPolicyV1 {
    /// Check list sizes and rule lengths. Regex syntax is checked when the filter is compiled.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` for an oversized list, an empty rule or an overlong rule.
    pub fn validate(&self) -> Result<(), CoreError> {
        let ok = |list: &[String]| {
            list.len() <= MAX_URL_EXCLUSION_RULES
                && list
                    .iter()
                    .all(|rule| !rule.is_empty() && rule.len() <= MAX_URL_EXCLUSION_RULE_BYTES)
        };
        if ok(&self.substrings) && ok(&self.patterns) {
            Ok(())
        } else {
            Err(CoreError::Invalid {
                field: "extract.content.excludedUrls",
                reason: "at most 256 non-empty rules of at most 512 bytes per list".into(),
            })
        }
    }
    /// True when no rule is configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.substrings.is_empty() && self.patterns.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn bounds_are_enforced_and_empty_policy_serializes_to_nothing() {
        let mut policy = UrlExclusionPolicyV1::default();
        assert!(policy.validate().is_ok());
        assert_eq!(serde_json::to_string(&policy).unwrap(), "{}");
        policy.substrings = vec![String::new()];
        assert!(policy.validate().is_err());
        policy.substrings = vec!["x".repeat(513)];
        assert!(policy.validate().is_err());
        policy.substrings = vec!["a".into(); 257];
        assert!(policy.validate().is_err());
        policy.substrings = vec!["/tag/".into()];
        policy.patterns = vec![r"\?utm_".into()];
        assert!(policy.validate().is_ok());
    }
}
