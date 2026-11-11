//! Bounded operator-observed delivery and language asset facts, distinct from acquisition backends.

use crate::hash::Digest;
use crate::{config::CreateCrawl, StoreError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Structural data-plane requirements of one immutable run, without endpoints or content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct WorkerDataRequirementsV1 {
    /// Destination ID to whether its approved ZDR contract is required.
    pub destinations: BTreeMap<String, bool>,
    /// Destinations that must accept already-compressed serialized bytes.
    pub compressed_destinations: BTreeSet<String>,
    /// Exact installed detector bundle, when detection was explicitly selected.
    pub language_bundle: Option<Digest>,
}
impl WorkerDataRequirementsV1 {
    /// Derive structural requirements only from admitted configuration.
    ///
    /// # Errors
    /// Returns invalid identifiers, oversized requirements or missing selected bundle errors.
    pub fn from_config(config: &CreateCrawl) -> Result<Self, StoreError> {
        let mut requirements = Self::default();
        let zdr = config.retention.mode == crate::config::RetentionMode::Zdr;
        for feed in &config.datasets.feeds {
            requirements.destinations.insert(feed.destination.clone(), zdr);
            if feed.compression != crate::dataset::FeedCompressionV1::None {
                requirements
                    .compressed_destinations
                    .insert(feed.destination.clone());
            }
        }
        for policy in config
            .scrape
            .as_ref()
            .and_then(|job| job.options.content_policy.as_ref())
            .into_iter()
            .chain(config.extract.content.as_ref())
        {
            if policy.language_mode == crate::article_language::LanguageModeV1::DeclaredOnly {
                continue;
            }
            let digest = policy.language_bundle_digest.ok_or_else(|| {
                StoreError::Conflict("selected language detector requires a pinned bundle".into())
            })?;
            if requirements.language_bundle.is_some_and(|old| old != digest) {
                return Err(StoreError::Conflict(
                    "independently selected extraction policies require different language bundles".into(),
                ));
            }
            requirements.language_bundle = Some(digest);
        }
        requirements.validate()?;
        Ok(requirements)
    }
    /// Validate bounded privacy-safe registry predicates.
    ///
    /// # Errors
    /// Returns a conflict for too many destinations or invalid IDs.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.destinations.len() > 64
            || !self
                .compressed_destinations
                .iter()
                .all(|id| self.destinations.contains_key(id))
        {
            return Err(StoreError::Conflict(
                "worker data requirements exceed bounds".into(),
            ));
        }
        for id in self.destinations.keys() {
            crate::dataset::validate_identifier(id)?;
        }
        Ok(())
    }
}

/// Fresh operator-observed data facts on exactly one worker; not a quality or feature-parity claim.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct WorkerDataCapabilitiesV1 {
    /// Installed approved destinations and their actual retention contract.
    pub destinations: BTreeMap<String, bool>,
    /// Installed destinations that accept already-compressed serialized bytes.
    pub compressed_destinations: BTreeSet<String>,
    /// Installed, digest-pinned language assets.
    pub language_bundles: BTreeSet<Digest>,
}
impl WorkerDataCapabilitiesV1 {
    /// Build bounded structural evidence, without endpoints or credentials.
    ///
    /// # Errors
    /// Returns a conflict for oversized or invalid evidence.
    pub fn new(
        destinations: BTreeMap<String, bool>,
        language_bundles: BTreeSet<Digest>,
    ) -> Result<Self, StoreError> {
        let value = Self {
            destinations,
            language_bundles,
            compressed_destinations: BTreeSet::new(),
        };
        value.validate()?;
        Ok(value)
    }
    /// Check capacity, asset count and identifier bounds before registry publication.
    ///
    /// # Errors
    /// Returns a conflict for malformed or unbounded evidence.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.destinations.len() > 64
            || self.language_bundles.len() > 8
            || !self
                .compressed_destinations
                .iter()
                .all(|id| self.destinations.contains_key(id))
        {
            return Err(StoreError::Conflict(
                "worker data capabilities exceed bounds".into(),
            ));
        }
        for id in self.destinations.keys() {
            crate::dataset::validate_identifier(id)?;
        }
        Ok(())
    }
    /// Require every destination and exact selected asset on this same worker.
    #[must_use]
    pub fn supports(&self, requirements: &WorkerDataRequirementsV1) -> bool {
        self.validate().is_ok()
            && requirements.validate().is_ok()
            && requirements.destinations.iter().all(|(id, zdr)| {
                self.destinations
                    .get(id)
                    .is_some_and(|approved| !*zdr || *approved)
            })
            && requirements
                .compressed_destinations
                .is_subset(&self.compressed_destinations)
            && requirements
                .language_bundle
                .is_none_or(|digest| self.language_bundles.contains(&digest))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn compressed_feeds_require_explicit_support_on_the_same_worker() {
        let config: CreateCrawl = serde_json::from_value(serde_json::json!({
            "seedUrl":"https://fixture.test/",
            "datasets":{
                "stores":[{"name":"docs","schemaVersion":"document_v1","maxItems":10,"maxBytes":1048576}],
                "feeds":[{"id":"out","source":"docs","serializer":"json","serializerVersion":1,
                    "destination":"sink","compression":"gzip","maxBatchItems":10,"maxBatchBytes":1048576}]
            }
        }))
        .unwrap();
        let required = WorkerDataRequirementsV1::from_config(&config).unwrap();
        assert!(required.compressed_destinations.contains("sink"));
        let mut facts =
            WorkerDataCapabilitiesV1::new(BTreeMap::from([("sink".to_owned(), false)]), BTreeSet::new())
                .unwrap();
        assert!(!facts.supports(&required));
        facts.compressed_destinations.insert("sink".into());
        assert!(facts.supports(&required));
        facts.compressed_destinations.insert("unknown".into());
        assert!(facts.validate().is_err());
    }

    #[test]
    fn legacy_capabilities_do_not_claim_compressed_delivery() {
        let facts: WorkerDataCapabilitiesV1 =
            serde_json::from_value(serde_json::json!({"destinations":{"sink":false},"languageBundles":[]}))
                .unwrap();
        assert!(facts.compressed_destinations.is_empty());
        facts.validate().unwrap();
    }
}
