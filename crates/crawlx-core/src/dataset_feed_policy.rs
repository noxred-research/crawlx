//! Bounded declarative feed selection and serialization policy. No executable or destination parameters.

use crate::StoreError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Bounded non-secret component for immutable feed object names and retry keys.
/// Short identifiers retain their spelling; longer valid identifiers use a scoped digest.
#[must_use]
pub fn feed_key_component(identifier: &str) -> std::borrow::Cow<'_, str> {
    if identifier.len() <= 64 {
        std::borrow::Cow::Borrowed(identifier)
    } else {
        std::borrow::Cow::Owned(
            crate::hash::Digest::of("crawlx/feed-identifier/v1", identifier.as_bytes()).to_hex(),
        )
    }
}

/// When immutable feed batches enter the delivery outbox.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FeedBatchingV1 {
    /// Publish each accepted request's prepared output immediately.
    #[default]
    PerRequest,
    /// Aggregate approved fragments in committed ordinal order when the run closes.
    Terminal,
}

/// Terminal feed finalization result, separate from destination acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FeedFinalizationOutcomeV1 {
    /// All required intents were committed; destination receipts remain independent.
    Completed,
    /// Required configuration or accepted source content expired before finalization.
    ContentExpired,
}

/// What a terminal feed with no selected items publishes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EmptyFeedPolicyV1 {
    /// Do not publish an empty feed.
    #[default]
    Skip,
    /// Publish one immutable, explicitly empty terminal manifest.
    Emit,
}

/// One non-executable predicate over a top-level approved item field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum FeedPredicateV1 {
    /// Require a present, non-null field.
    Present {
        /// Approved top-level field name.
        field: String,
    },
    /// Match an exact bounded scalar value, without coercion.
    Equals {
        /// Approved top-level field name.
        field: String,
        /// JSON scalar; arrays and objects are forbidden.
        value: Value,
    },
}

/// Conjunction of bounded field predicates applied after privacy projection.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FeedItemFilterV1 {
    /// At most sixteen scalar predicates; an empty list selects all items.
    #[serde(default)]
    pub all: Vec<FeedPredicateV1>,
}

impl FeedItemFilterV1 {
    /// Check field names and scalar bounds without reporting content.
    /// # Errors
    /// Returns a conflict for excessive predicates or non-scalar/oversized literals.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.all.len() > 16 {
            return Err(StoreError::Conflict("feed predicate limit".into()));
        }
        for predicate in &self.all {
            let field = match predicate {
                FeedPredicateV1::Present { field } => field,
                FeedPredicateV1::Equals { field, value } => {
                    if value.is_array()
                        || value.is_object()
                        || value.as_str().is_some_and(|text| text.len() > 256)
                    {
                        return Err(StoreError::Conflict("invalid feed predicate scalar".into()));
                    }
                    field
                }
            };
            super::validate_identifier(field)?;
        }
        Ok(())
    }

    /// Select approved content without reapplying defaults or inspecting unrestricted source bytes.
    #[must_use]
    pub fn matches(&self, item: &Value) -> bool {
        self.all.iter().all(|predicate| match predicate {
            FeedPredicateV1::Present { field } => item.get(field).is_some_and(|value| !value.is_null()),
            FeedPredicateV1::Equals { field, value } => item.get(field) == Some(value),
        })
    }
}

/// Safe format parameters. They cannot name URLs, paths, credentials, plugins or commands.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FeedParametersV1 {
    /// Explicit CSV field order, at most 64 unique bounded identifiers.
    #[serde(default)]
    pub csv_columns: Vec<String>,
    /// Pretty-printed JSON uses at most eight spaces per nesting level.
    #[serde(default)]
    pub json_indent: u8,
}

impl FeedParametersV1 {
    /// Validate format-specific parameters against the declared serializer.
    /// # Errors
    /// Returns a conflict for excessive, duplicate or incompatible parameters.
    pub fn validate(&self, serializer: &str) -> Result<(), StoreError> {
        if self.csv_columns.len() > 64
            || self.json_indent > 8
            || (!self.csv_columns.is_empty() && serializer != "csv")
            || (self.json_indent != 0 && serializer != "json")
        {
            return Err(StoreError::Conflict("invalid feed format parameters".into()));
        }
        let mut fields = std::collections::BTreeSet::new();
        for field in &self.csv_columns {
            super::validate_identifier(field)?;
            if !fields.insert(field) {
                return Err(StoreError::Conflict("duplicate feed column".into()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn filters_match_exact_scalars_and_missing_fields() {
        let filter: FeedItemFilterV1 = serde_json::from_value(serde_json::json!({"all":[
            {"kind":"present","field":"title"}, {"kind":"equals","field":"accepted","value":true}
        ]}))
        .unwrap();
        filter.validate().unwrap();
        assert!(filter.matches(&serde_json::json!({"title":"ok","accepted":true})));
        assert!(!filter.matches(&serde_json::json!({"title":null,"accepted":true})));
        assert!(!filter.matches(&serde_json::json!({"title":"ok","accepted":"true"})));
    }

    #[test]
    fn parameters_refuse_destination_and_executable_fields() {
        for field in ["url", "path", "credentials", "command", "plugin"] {
            assert!(serde_json::from_value::<FeedParametersV1>(serde_json::json!({(field):"x"})).is_err());
        }
        let parameters: FeedParametersV1 =
            serde_json::from_value(serde_json::json!({"csvColumns":["b","a"]})).unwrap();
        parameters.validate("csv").unwrap();
        assert!(parameters.validate("json").is_err());
    }

    #[test]
    fn predicate_and_format_bounds_fail_before_runtime() {
        let mut filter = FeedItemFilterV1 {
            all: vec![
                FeedPredicateV1::Present {
                    field: "title".into()
                };
                17
            ],
        };
        assert!(filter.validate().is_err());
        for value in [
            serde_json::json!([]),
            serde_json::json!({}),
            serde_json::json!("x".repeat(257)),
        ] {
            filter.all = vec![FeedPredicateV1::Equals {
                field: "title".into(),
                value,
            }];
            assert!(filter.validate().is_err());
        }
        let mut parameters = FeedParametersV1 {
            csv_columns: Vec::new(),
            json_indent: 9,
        };
        assert!(parameters.validate("json").is_err());
        parameters.json_indent = 0;
        parameters.csv_columns = vec!["title".into(), "title".into()];
        assert!(parameters.validate("csv").is_err());
        parameters.csv_columns = (0..65).map(|n| format!("field_{n}")).collect();
        assert!(parameters.validate("csv").is_err());
        parameters.csv_columns = vec!["../outside".into()];
        assert!(parameters.validate("csv").is_err());
    }

    #[test]
    fn longest_valid_feed_identifier_keeps_immutable_keys_bounded() {
        let identifier = "f".repeat(128);
        super::super::validate_identifier(&identifier).unwrap();
        let component = feed_key_component(&identifier);
        assert_eq!(component.len(), 64);
        let key = format!("terminal.{}.{}.{}", component, u64::MAX, u64::MAX);
        super::super::validate_identifier(&key).unwrap();
        assert_eq!(feed_key_component("short"), "short");
    }
}
