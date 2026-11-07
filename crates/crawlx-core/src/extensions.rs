//! Reviewed, bounded native extensions; never a source-language or plugin ABI.
//!
//! All values are proposals. This module grants no browser, network, storage or
//! policy authority. Item values remain content-sensitive until artifact admission.

use crate::{extraction::DocumentEnvelopeV1, hash::Digest, request::RequestEnvelopeV1};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Hard descriptor count per immutable execution specification.
pub const MAX_EXTENSIONS: usize = 32;
/// Hard serialized configuration and item limit.
pub const MAX_EXTENSION_BYTES: usize = 1_048_576;

/// Fixed lifecycle boundaries, separate from discovery's RouteLearner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionStageV1 {
    /// Validate immutable configuration before work.
    Configure,
    /// Validate a newly proposed request.
    RequestProposed,
    /// Produce a replacement proposal, never an admitted effect.
    BeforeAcquisition,
    /// Inspect bounded header facts, never cookies.
    HeadersReceived,
    /// Project shared parsed document metadata.
    Parse,
    /// Run the explicit label handler.
    Route,
    /// Transform an ephemeral item candidate.
    Item,
    /// Preserve failure and policy denial.
    Terminal,
    /// Propose versioned state for the fenced commit.
    Checkpoint,
    /// Release owned ephemeral state exactly once.
    Close,
}
/// Capabilities selected from reviewed registry entries, never self-granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionCapabilityV1 {
    /// Read request proposals without credentials.
    RequestRead,
    /// Propose a new request requiring native admission.
    RequestProposal,
    /// Read retention-approved document metadata.
    DocumentRead,
    /// Create or transform an ephemeral item.
    ItemTransform,
}
/// Explicit failure behavior. Neither choice can erase a policy denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionFailurePolicyV1 {
    /// Fail this request.
    Fail,
    /// Reject this candidate without fabricating success.
    Reject,
}
/// Bounded work; one request executes one job at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionLimitsV1 {
    /// Maximum serialized input bytes.
    pub input_bytes: usize,
    /// Maximum serialized output bytes.
    pub output_bytes: usize,
    /// Maximum replacement requests, at most one.
    pub proposals: usize,
    /// Maximum candidate items, at most one.
    pub items: usize,
    /// Browser action proposals are unavailable in these built-ins; must be zero.
    pub actions: usize,
    /// Cooperative per-stage deadline, at most 30 seconds.
    pub deadline_ms: u32,
    /// Outstanding jobs per request, exactly one.
    pub outstanding: usize,
}
impl Default for ExtensionLimitsV1 {
    fn default() -> Self {
        Self {
            input_bytes: MAX_EXTENSION_BYTES,
            output_bytes: MAX_EXTENSION_BYTES,
            proposals: 1,
            items: 1,
            actions: 0,
            deadline_ms: 1000,
            outstanding: 1,
        }
    }
}
/// Typed configuration for the fixed compiled registry.
/// Empty struct variants deliberately reject unreviewed fields on internally tagged JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ExtensionConfigV1 {
    /// Refuse any method except GET/HEAD; does not authorize either method.
    ReadOnly {},
    /// Return a replacement proposal. The worker must append after fresh admission.
    ReplaceRequest {
        /// Complete bounded proposal, never patched transport state.
        request: Box<RequestEnvelopeV1>,
    },
    /// Reject a document unless its independent extraction gates accepted it.
    RequireQuality {},
    /// Trim the title candidate's Unicode whitespace.
    TrimTitle {},
    /// Reject a candidate without a nonempty title.
    RequireTitle {},
}
impl ExtensionConfigV1 {
    /// Exact compiled implementation identifier.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        match self {
            Self::ReadOnly {} => "native.read_only",
            Self::ReplaceRequest { .. } => "native.replace_request",
            Self::RequireQuality {} => "native.require_quality",
            Self::TrimTitle {} => "native.trim_title",
            Self::RequireTitle {} => "native.require_title",
        }
    }
    /// Single stage accepted by this reviewed implementation.
    #[must_use]
    pub const fn stage(&self) -> ExtensionStageV1 {
        match self {
            Self::ReadOnly {} => ExtensionStageV1::RequestProposed,
            Self::ReplaceRequest { .. } => ExtensionStageV1::BeforeAcquisition,
            Self::RequireQuality {} => ExtensionStageV1::Parse,
            Self::TrimTitle {} | Self::RequireTitle {} => ExtensionStageV1::Item,
        }
    }
    /// Exact capabilities required by this implementation.
    #[must_use]
    pub fn capabilities(&self) -> BTreeSet<ExtensionCapabilityV1> {
        [match self {
            Self::ReadOnly {} => ExtensionCapabilityV1::RequestRead,
            Self::ReplaceRequest { .. } => ExtensionCapabilityV1::RequestProposal,
            Self::RequireQuality {} => ExtensionCapabilityV1::DocumentRead,
            Self::TrimTitle {} | Self::RequireTitle {} => ExtensionCapabilityV1::ItemTransform,
        }]
        .into()
    }
}
/// Fixed, versioned descriptor. Selection never loads code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionSpecV1 {
    /// Reviewed implementation ID.
    pub id: String,
    /// Exact implementation version, currently 1.0.0.
    pub implementation_version: String,
    /// Input schema, exactly one.
    pub input_schema_version: u16,
    /// Output schema, exactly one.
    pub output_schema_version: u16,
    /// Fixed implementation stage.
    pub stage: ExtensionStageV1,
    /// Stable ascending request/item order; reverse response order when configured.
    pub order: i32,
    /// Required capabilities, exactly the reviewed implementation set.
    pub capabilities: BTreeSet<ExtensionCapabilityV1>,
    /// Pure declarative built-in settings.
    pub config: ExtensionConfigV1,
    /// Bounded execution.
    pub limits: ExtensionLimitsV1,
    /// Typed candidate failure behavior.
    pub failure_policy: ExtensionFailurePolicyV1,
}
impl ExtensionSpecV1 {
    /// Construct a reviewed version-one descriptor.
    #[must_use]
    pub fn new(config: ExtensionConfigV1, order: i32) -> Self {
        Self {
            id: config.id().into(),
            implementation_version: "1.0.0".into(),
            input_schema_version: 1,
            output_schema_version: 1,
            stage: config.stage(),
            order,
            capabilities: config.capabilities(),
            config,
            limits: ExtensionLimitsV1::default(),
            failure_policy: ExtensionFailurePolicyV1::Fail,
        }
    }
    /// Validate registry identity, configuration, versions and work bounds.
    ///
    /// # Errors
    /// Returns a typed refusal for unknown implementations, self-granted powers or excess limits.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        let l = &self.limits;
        if self.id != self.config.id()
            || self.implementation_version != "1.0.0"
            || self.input_schema_version != 1
            || self.output_schema_version != 1
            || self.stage != self.config.stage()
            || self.capabilities != self.config.capabilities()
            || !(1..=MAX_EXTENSION_BYTES).contains(&l.input_bytes)
            || !(1..=MAX_EXTENSION_BYTES).contains(&l.output_bytes)
            || l.proposals > 1
            || l.items > 1
            || !(1..=30_000).contains(&l.deadline_ms)
            || l.outstanding != 1
            || l.actions != 0
        {
            return Err(ExtensionError::InvalidSpec);
        }
        if let ExtensionConfigV1::ReplaceRequest { request } = &self.config {
            request.validate().map_err(|_| ExtensionError::InvalidSpec)?;
            if l.proposals == 0 {
                return Err(ExtensionError::Limit);
            }
        }
        if json_size(&self.config)? > l.input_bytes {
            return Err(ExtensionError::Limit);
        }
        Ok(())
    }
    /// Digest only for trusted config publication; not raw configuration values.
    ///
    /// # Errors
    /// Returns serialization failure; callers must still apply retention policy to the digest.
    pub fn config_digest(&self) -> Result<Digest, ExtensionError> {
        Ok(Digest::of_value("crawlx/extension-config/v1", &self.config)?)
    }
}
/// Compiled route, not a callback, page handle or learned URL template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HandlerV1 {
    /// Project approved DocumentEnvelopeV1 metadata into one candidate item.
    DocumentItem,
    /// Explicitly skip parsing without inventing a response or item.
    Skip,
}
/// Immutable native route and lifecycle configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionPipelineV1 {
    /// Schema version, exactly one.
    pub version: u16,
    /// Selected reviewed implementations, at most 32.
    pub extensions: Vec<ExtensionSpecV1>,
    /// Explicit labels, not discovery route templates.
    pub routes: BTreeMap<String, HandlerV1>,
    /// Optional handler for unknown labels; omission means typed failure.
    pub default_handler: Option<HandlerV1>,
    /// Reverse response, item and finalization order (Scrapy dialect).
    pub reverse_response: bool,
    /// Explicit declared dataset receiving accepted candidates; none means no dataset append.
    pub dataset: Option<String>,
}
impl Default for ExtensionPipelineV1 {
    fn default() -> Self {
        Self {
            version: 1,
            extensions: Vec::new(),
            routes: [("default".into(), HandlerV1::DocumentItem)].into(),
            default_handler: None,
            reverse_response: false,
            dataset: None,
        }
    }
}
impl ExtensionPipelineV1 {
    /// Whether configuration opts into behavior beyond the legacy default label.
    #[must_use]
    pub fn configured(&self) -> bool {
        !self.extensions.is_empty()
            || self.reverse_response
            || self.default_handler.is_some()
            || self.dataset.is_some()
            || self.routes.len() != 1
            || self.routes.get("default") != Some(&HandlerV1::DocumentItem)
    }
    /// Whether selected parse/item transforms require an explicit article envelope.
    #[must_use]
    pub fn requires_document(&self) -> bool {
        self.dataset.is_some()
            || self
                .extensions
                .iter()
                .any(|entry| matches!(entry.stage, ExtensionStageV1::Parse | ExtensionStageV1::Item))
            || (self.configured()
                && self
                    .routes
                    .iter()
                    .any(|(label, handler)| label != "default" && *handler == HandlerV1::DocumentItem))
            || self.default_handler == Some(HandlerV1::DocumentItem)
    }
    /// Validate all bounds and registry references before work.
    ///
    /// # Errors
    /// Rejects unsupported versions, duplicate implementation identities and oversized config.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if self.version != 1
            || self.extensions.len() > MAX_EXTENSIONS
            || self.routes.len() > 64
            || self.routes.keys().any(|k| !crate::request::safe_id(k))
            || self
                .dataset
                .as_ref()
                .is_some_and(|name| crate::dataset::validate_identifier(name).is_err())
        {
            return Err(ExtensionError::InvalidSpec);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.extensions {
            entry.validate()?;
            if !seen.insert((&entry.id, &entry.implementation_version)) {
                return Err(ExtensionError::InvalidSpec);
            }
        }
        if json_size(self)? > MAX_EXTENSION_BYTES {
            return Err(ExtensionError::Limit);
        }
        Ok(())
    }
    /// Resolve an explicit label, with no implicit default recovery.
    ///
    /// # Errors
    /// Returns `UnknownRoute` when neither label nor explicit default exists.
    pub fn route(&self, label: &str) -> Result<HandlerV1, ExtensionError> {
        self.routes
            .get(label)
            .copied()
            .or(self.default_handler)
            .ok_or(ExtensionError::UnknownRoute)
    }
    /// Stable forward order. Reverse execution reverses this exact sequence.
    #[must_use]
    pub fn ordered(&self) -> Vec<&ExtensionSpecV1> {
        let mut entries: Vec<_> = self.extensions.iter().collect();
        entries.sort_unstable_by(|a, b| {
            (a.stage, a.order, &a.id, &a.implementation_version).cmp(&(
                b.stage,
                b.order,
                &b.id,
                &b.implementation_version,
            ))
        });
        entries
    }
    /// Safe selected capabilities, versions and digests, never config values.
    ///
    /// # Errors
    /// Returns serialization failure or invalid configuration.
    pub fn publication(&self) -> Result<serde_json::Value, ExtensionError> {
        self.validate()?;
        let selected = self
            .ordered()
            .into_iter()
            .map(|e| {
                Ok(serde_json::json!({
                    "id": e.id, "implementationVersion": e.implementation_version,
                    "stage": e.stage, "capabilities": e.capabilities, "configDigest": e.config_digest()?,
                    "limits": e.limits,
                }))
            })
            .collect::<Result<Vec<_>, ExtensionError>>()?;
        Ok(
            serde_json::json!({"schemaVersion":1,"sdkAbiCompatible":false,"selected":selected,
            "routes":self.routes,"defaultHandler":self.default_handler,"reverseResponse":self.reverse_response,
            "dataset":self.dataset}),
        )
    }
}
/// Project bounded shared metadata, not the document body or browser state.
///
/// # Errors
/// Rejects unsupported envelopes or oversized metadata before creating a candidate.
pub fn document_item(
    document: &DocumentEnvelopeV1,
    limit: usize,
) -> Result<serde_json::Value, ExtensionError> {
    if document.version != 1
        || document
            .metadata
            .title
            .value
            .as_ref()
            .is_some_and(|s| s.len() > limit)
        || document
            .metadata
            .authors
            .value
            .as_ref()
            .is_some_and(|a| a.len() > 64 || a.iter().any(|s| s.len() > 4096))
    {
        return Err(ExtensionError::Limit);
    }
    let value = serde_json::json!({"title":document.metadata.title.value,
        "authors":document.metadata.authors.value,"language":document.metadata.language.value,
        "extractor":document.extractor,"quality":document.quality.status});
    if json_size(&value)? > limit.min(MAX_EXTENSION_BYTES) {
        return Err(ExtensionError::Limit);
    }
    Ok(value)
}

/// Count serialized JSON without allocating or cloning a content buffer.
///
/// # Errors
/// Returns serialization failure or an overflow error for an unrepresentable length.
pub fn json_size(value: &impl Serialize) -> Result<usize, ExtensionError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("extension JSON length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}
/// Public compiled registry facts. No worker health or source SDK parity is implied.
#[must_use]
pub fn registry_publication() -> serde_json::Value {
    let configs = [
        ExtensionConfigV1::ReadOnly {},
        ExtensionConfigV1::RequireQuality {},
        ExtensionConfigV1::TrimTitle {},
        ExtensionConfigV1::RequireTitle {},
    ];
    let mut entries: Vec<_> = configs
        .iter()
        .map(|c| {
            serde_json::json!({"id":c.id(),
        "implementationVersion":"1.0.0","stage":c.stage(),"capabilities":c.capabilities(),
        "inputSchemaVersion":1,"outputSchemaVersion":1})
        })
        .collect();
    entries.push(serde_json::json!({"id":"native.replace_request","implementationVersion":"1.0.0",
        "stage":"before_acquisition","capabilities":["request_proposal"],"inputSchemaVersion":1,"outputSchemaVersion":1}));
    serde_json::json!({"schemaVersion":1,"sdkAbiCompatible":false,"arbitraryCode":false,
        "maxExtensions":MAX_EXTENSIONS,"maxBytes":MAX_EXTENSION_BYTES,"registry":entries})
}
/// Extension refusal without sensitive input values.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExtensionError {
    /// Descriptor not recognized or outside the reviewed capability contract.
    #[error("invalid extension descriptor")]
    InvalidSpec,
    /// Label not configured and no explicit default exists.
    #[error("unknown extension route")]
    UnknownRoute,
    /// Bounded input, output or proposal budget exceeded.
    #[error("extension resource limit exceeded")]
    Limit,
    /// Run or request cancellation observed.
    #[error("extension cancelled")]
    Cancelled,
    /// Cooperative execution deadline expired.
    #[error("extension deadline exceeded")]
    Deadline,
    /// A compiled transform rejected this candidate.
    #[error("extension candidate rejected")]
    Rejected,
    /// A configured fail policy stopped request processing.
    #[error("extension processing failed")]
    Failed,
    /// Native policy denial always wins over later extension results.
    #[error("extension policy denied")]
    PolicyDenied,
    /// Already sealed lifecycle cannot produce more work.
    #[error("extension lifecycle closed")]
    Closed,
    /// CPU task failed without exposing input data.
    #[error("extension task failed")]
    Task,
    /// Canonical serialization failed.
    #[error("extension serialization failed")]
    Serialize(#[from] serde_json::Error),
    /// Canonical configuration digest could not be encoded.
    #[error("extension digest serialization failed")]
    Digest(#[from] ciborium::ser::Error<std::io::Error>),
}
impl crate::Classify for ExtensionError {
    fn class(&self) -> crate::ErrorClass {
        match self {
            Self::PolicyDenied => crate::ErrorClass::PolicyDenied,
            Self::Cancelled | Self::Deadline | Self::Task => crate::ErrorClass::Retryable,
            _ => crate::ErrorClass::Terminal,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn registry_refuses_unknown_versions_self_grants_and_action_capabilities() {
        let mut spec = ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0);
        spec.implementation_version = "2.0.0".into();
        assert!(spec.validate().is_err());
        spec.implementation_version = "1.0.0".into();
        spec.capabilities.insert(ExtensionCapabilityV1::RequestProposal);
        assert!(spec.validate().is_err());
        spec.capabilities = spec.config.capabilities();
        spec.limits.actions = 1;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn registry_order_is_total_and_duplicate_implementations_are_refused() {
        let mut pipeline = ExtensionPipelineV1 {
            extensions: vec![
                ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0),
                ExtensionSpecV1::new(ExtensionConfigV1::RequireTitle {}, 0),
                ExtensionSpecV1::new(ExtensionConfigV1::ReadOnly {}, 99),
            ],
            ..ExtensionPipelineV1::default()
        };
        pipeline.validate().unwrap();
        assert_eq!(
            pipeline
                .ordered()
                .iter()
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>(),
            ["native.read_only", "native.require_title", "native.trim_title"]
        );
        pipeline
            .extensions
            .push(ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 1));
        assert!(pipeline.validate().is_err());
    }

    #[test]
    fn declarative_config_rejects_unreviewed_fields() {
        assert!(
            serde_json::from_str::<ExtensionConfigV1>(r#"{"kind":"trim_title","python":"import os"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<ExtensionPipelineV1>(
            r#"{"version":1,"modulePath":"untrusted.Plugin"}"#
        )
        .is_err());
    }
}
