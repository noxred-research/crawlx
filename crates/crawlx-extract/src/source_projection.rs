//! Allowlisted, versioned source metadata projection with privacy-scoped logical identity.

use std::collections::{BTreeMap, BTreeSet};

use crawlx_core::{config::RetentionMode, extraction::SearchProjectionV1, hash::Digest};
use serde_json::Value;

/// Explicit source fields. No debug, raw markup, credentials or executable transforms exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SourceField {
    /// Document title.
    Title,
    /// Selected plain text.
    Text,
    /// Source headings, in document order.
    Heading,
    /// Source tags, in authored order.
    Tag,
    /// Declared or explicitly pinned detected language.
    Language,
    /// Declared licence, not a legal conclusion.
    Licence,
    /// Description.
    Description,
    /// Authored byline.
    Author,
    /// Declared publication date; no wall-clock inference.
    Published,
}

/// Closed deterministic transforms; ordering is part of the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MetadataTransform {
    /// Trim leading and trailing whitespace.
    Trim,
    /// Collapse Unicode whitespace to ASCII spaces.
    CollapseWhitespace,
    /// ASCII-only case normalization, independent of host locale.
    AsciiLowercase,
    /// Keep the first occurrence of each equal value.
    Unique,
}

/// One allowlisted source-to-index mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldMapping {
    /// Typed source key.
    pub source: SourceField,
    /// Approved flat destination name; duplicate destinations are rejected.
    pub destination: String,
    /// Ordered transforms, at most eight.
    pub transforms: Vec<MetadataTransform>,
    /// Preserve multiple values rather than selecting the first.
    pub multiple: bool,
}

/// Finite projection contract. Limits reject; they never silently discard suffixes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceProjectionPolicy {
    /// Exactly one.
    pub version: u16,
    /// Pinned implementation/config identifier.
    pub extractor_version: String,
    /// At most 64 destination fields.
    pub mappings: Vec<FieldMapping>,
    /// Total source values visited, at most 16,384.
    pub max_values: usize,
    /// Total source and finalized UTF-8 bytes, at most 16 MiB.
    pub max_bytes: usize,
}

/// Projection failure, without rejected content in diagnostics.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourceProjectionError {
    /// Invalid version, field name, collision or bound.
    #[error("invalid source projection policy")]
    Policy,
    /// Source/final output exceeds a declared budget.
    #[error("source projection budget exceeded")]
    Limit,
    /// Durable search projection is forbidden under zero-data retention.
    #[error("search projection denied by retention policy")]
    Retention,
    /// Native delivery validation failed.
    #[error("invalid search projection")]
    Native(#[source] crawlx_core::StoreError),
}

/// Derive a deletion-stable identity from tenant-scoped opaque logical identity, not content.
/// Callers must use a secret-keyed digest for sensitive URLs before supplying `logical_key`.
#[must_use]
pub fn stable_document_id(namespace: Digest, logical_key: Digest) -> String {
    let mut bytes = [0_u8; 64];
    bytes[..32].copy_from_slice(&namespace.0);
    bytes[32..].copy_from_slice(&logical_key.0);
    Digest::of("crawlx.search-document.v1", &bytes).to_string()
}

/// Derive stable child identity from parent and source ordinal; no entry name is exposed.
#[must_use]
pub fn stable_child_id(parent: Digest, ordinal: u64) -> Digest {
    let mut bytes = [0_u8; 40];
    bytes[..32].copy_from_slice(&parent.0);
    bytes[32..].copy_from_slice(&ordinal.to_be_bytes());
    Digest::of("crawlx.embedded-child.v1", &bytes)
}

impl FieldMapping {
    /// Declare one bounded mapping; the containing policy validates names and collisions.
    #[must_use]
    pub fn new(
        source: SourceField,
        destination: String,
        transforms: Vec<MetadataTransform>,
        multiple: bool,
    ) -> Self {
        Self {
            source,
            destination,
            transforms,
            multiple,
        }
    }
}

impl SourceProjectionPolicy {
    /// Build and validate a version-one source projection policy.
    ///
    /// # Errors
    /// Refuses invalid names, collisions, transform counts and budgets.
    pub fn new(
        extractor_version: String,
        mappings: Vec<FieldMapping>,
        max_values: usize,
        max_bytes: usize,
    ) -> Result<Self, SourceProjectionError> {
        let policy = Self {
            version: 1,
            extractor_version,
            mappings,
            max_values,
            max_bytes,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the whole mapping before touching source values.
    ///
    /// # Errors
    /// Refuses collisions, reserved identifiers, unsupported version and unbounded work.
    pub fn validate(&self) -> Result<(), SourceProjectionError> {
        let mut names = BTreeSet::new();
        if self.version != 1
            || self.mappings.len() > 64
            || !(1..=16_384).contains(&self.max_values)
            || !(1..=16 * 1024 * 1024).contains(&self.max_bytes)
            || crawlx_core::dataset::validate_identifier(&self.extractor_version).is_err()
            || self.mappings.iter().any(|mapping| {
                mapping.destination == "id"
                    || mapping.destination.starts_with('_')
                    || crawlx_core::dataset::validate_identifier(&mapping.destination).is_err()
                    || mapping.transforms.len() > 8
                    || !names.insert(&mapping.destination)
            })
        {
            return Err(SourceProjectionError::Policy);
        }
        Ok(())
    }

    /// Project approved typed source metadata into the existing native delivery record.
    /// `privacy` must return `None` to withhold a value; it runs after transforms.
    /// Every returned field remains content, never structural telemetry.
    ///
    /// # Errors
    /// Refuses ZDR, invalid mappings, source/output budgets and invalid native records.
    pub fn project(
        &self,
        document_id: String,
        parent_id: Option<String>,
        sources: &BTreeMap<SourceField, Vec<String>>,
        retention: RetentionMode,
        privacy: &dyn Fn(&str) -> Option<String>,
    ) -> Result<SearchProjectionV1, SourceProjectionError> {
        self.validate()?;
        if retention == RetentionMode::Zdr {
            return Err(SourceProjectionError::Retention);
        }
        let mut fields = BTreeMap::new();
        let mut values = 0_usize;
        let mut bytes = 0_usize;
        for mapping in &self.mappings {
            let mut output = Vec::new();
            if let Some(source) = sources.get(&mapping.source) {
                for value in source {
                    values = values.checked_add(1).ok_or(SourceProjectionError::Limit)?;
                    bytes = bytes
                        .checked_add(value.len())
                        .ok_or(SourceProjectionError::Limit)?;
                    if values > self.max_values || bytes > self.max_bytes {
                        return Err(SourceProjectionError::Limit);
                    }
                    let mut value = std::borrow::Cow::Borrowed(value.as_str());
                    for transform in &mapping.transforms {
                        match transform {
                            MetadataTransform::Trim => {
                                let trimmed = value.trim();
                                if trimmed.len() != value.len() {
                                    value = std::borrow::Cow::Owned(trimmed.to_owned());
                                }
                            }
                            MetadataTransform::CollapseWhitespace => {
                                value = std::borrow::Cow::Owned(crate::dom::collapse_ws(&value))
                            }
                            MetadataTransform::AsciiLowercase => {
                                if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
                                    value.to_mut().make_ascii_lowercase();
                                }
                            }
                            MetadataTransform::Unique => {}
                        }
                    }
                    let Some(value) = privacy(&value) else { continue };
                    bytes = bytes
                        .checked_add(value.len())
                        .ok_or(SourceProjectionError::Limit)?;
                    if bytes > self.max_bytes || output.len() >= 256 {
                        return Err(SourceProjectionError::Limit);
                    }
                    if !mapping.transforms.contains(&MetadataTransform::Unique)
                        || !output
                            .iter()
                            .any(|item: &Value| item.as_str() == Some(value.as_str()))
                    {
                        output.push(Value::String(value));
                    }
                }
            }
            if mapping.multiple {
                fields.insert(mapping.destination.clone(), Value::Array(output));
            } else if let Some(value) = output.into_iter().next() {
                fields.insert(mapping.destination.clone(), value);
            }
        }
        let mut projection = SearchProjectionV1::new(document_id, self.extractor_version.clone(), fields);
        projection.parent_id = parent_id;
        projection.validate().map_err(SourceProjectionError::Native)?;
        Ok(projection)
    }

    /// Create an explicit tombstone with exactly the upsert's stable identity.
    ///
    /// # Errors
    /// Refuses invalid policy, ZDR and invalid native identities.
    pub fn tombstone(
        &self,
        document_id: String,
        retention: RetentionMode,
    ) -> Result<SearchProjectionV1, SourceProjectionError> {
        self.validate()?;
        if retention == RetentionMode::Zdr {
            return Err(SourceProjectionError::Retention);
        }
        let mut projection =
            SearchProjectionV1::new(document_id, self.extractor_version.clone(), BTreeMap::new());
        projection.deleted = true;
        projection.validate().map_err(SourceProjectionError::Native)?;
        Ok(projection)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn policy() -> SourceProjectionPolicy {
        SourceProjectionPolicy {
            version: 1,
            extractor_version: "native_projection_v1".into(),
            mappings: vec![FieldMapping {
                source: SourceField::Tag,
                destination: "tags".into(),
                transforms: vec![MetadataTransform::Trim, MetadataTransform::Unique],
                multiple: true,
            }],
            max_values: 16,
            max_bytes: 4096,
        }
    }

    #[test]
    fn multiple_values_privacy_and_deletion_identity() {
        let policy = policy();
        let id = stable_document_id(Digest::of("tenant", b"a"), Digest::of("logical", b"document"));
        let sources = BTreeMap::from([(SourceField::Tag, vec![" x ".into(), "x".into(), "secret".into()])]);
        let record = policy
            .project(id.clone(), None, &sources, RetentionMode::Standard, &|value| {
                (value != "secret").then(|| value.to_owned())
            })
            .unwrap();
        assert_eq!(record.fields["tags"], serde_json::json!(["x"]));
        assert_eq!(
            policy.tombstone(id, RetentionMode::Standard).unwrap().document_id,
            record.document_id
        );
        assert!(policy
            .project("id".into(), None, &sources, RetentionMode::Zdr, &|value| Some(
                value.into()
            ))
            .is_err());
    }

    #[test]
    fn collisions_and_budget_fail_closed() {
        let mut policy = policy();
        policy.mappings.push(policy.mappings[0].clone());
        assert!(policy.validate().is_err());
        policy.mappings.pop();
        policy.max_bytes = 1;
        assert!(policy
            .project(
                "id".into(),
                None,
                &BTreeMap::from([(SourceField::Tag, vec!["too long".into()])]),
                RetentionMode::Standard,
                &|value| Some(value.into())
            )
            .is_err());
    }
}
