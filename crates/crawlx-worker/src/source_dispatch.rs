//! Operator-approved native source dispatch and finalized search projection.
//!
//! Dispatch is synchronous CPU work over already admitted bytes. Callers move input bytes
//! together with their byte permit into the blocking closure. Expansion/output admission is
//! acquired here before traversal and returned with the result; keep that carrier through
//! ArtifactSink and fenced reference admission. This module never creates frontier work,
//! performs acquisition, resolves credentials, loads a model, or claims external parser parity.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
    sync::Arc,
};

use crawlx_core::{
    config::RetentionMode,
    extraction::{DocumentEnvelopeV1, ParserPipelineV1, SearchProjectionV1},
    hash::Digest,
    parser_memory::{self, Budgeted, ByteAdmissionError},
    selectors::bounded_json_len,
    StoreError,
};
use crawlx_extract::{
    parse::traversal::{self, ChildContent, ChildRecord, TraversalError, TraversalLimits},
    pipeline::{ParserPipeline, PipelineContent, PipelineOutput},
    source_policy::{self, ReferenceEncoding, SourceFreshness},
    source_projection::{
        FieldMapping, MetadataTransform, SourceField, SourceProjectionError, SourceProjectionPolicy,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

/// Largest approved local configuration file. Source content cannot select this file.
pub const MAX_SOURCE_DISPATCH_CONFIG_BYTES: usize = 64 * 1024;

/// Typed source fields accepted by operator configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceFieldV1 {
    /// Canonical title.
    Title,
    /// Finalized selected text.
    Text,
    /// Canonical heading values, when the parser actually records them.
    Heading,
    /// Authored tags, not inferred lexical keywords.
    Tag,
    /// Declared or explicitly approved language.
    Language,
    /// Declared licence, not a legal conclusion.
    Licence,
    /// Canonical description.
    Description,
    /// Selected authors, preserving multiplicity.
    Author,
    /// Authored publication value, never wall time.
    Published,
}

impl SourceFieldV1 {
    fn native(self) -> SourceField {
        match self {
            Self::Title => SourceField::Title,
            Self::Text => SourceField::Text,
            Self::Heading => SourceField::Heading,
            Self::Tag => SourceField::Tag,
            Self::Language => SourceField::Language,
            Self::Licence => SourceField::Licence,
            Self::Description => SourceField::Description,
            Self::Author => SourceField::Author,
            Self::Published => SourceField::Published,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Title => "title",
            Self::Text => "text",
            Self::Heading => "heading",
            Self::Tag => "tag",
            Self::Language => "language",
            Self::Licence => "licence",
            Self::Description => "description",
            Self::Author => "author",
            Self::Published => "published",
        }
    }
}

/// Closed operator-approved field transforms; no source code or class names are accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceTransformV1 {
    /// Trim outer whitespace.
    Trim,
    /// Collapse whitespace.
    CollapseWhitespace,
    /// Locale-independent ASCII normalization.
    AsciiLowercase,
    /// Keep first equal finalized value.
    Unique,
}

impl SourceTransformV1 {
    fn native(self) -> MetadataTransform {
        match self {
            Self::Trim => MetadataTransform::Trim,
            Self::CollapseWhitespace => MetadataTransform::CollapseWhitespace,
            Self::AsciiLowercase => MetadataTransform::AsciiLowercase,
            Self::Unique => MetadataTransform::Unique,
        }
    }
}

/// One immutable operator field mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceMappingV1 {
    /// Canonical source key.
    pub source: SourceFieldV1,
    /// Approved flat search field name.
    pub destination: String,
    /// Ordered finite transforms.
    #[serde(default)]
    pub transforms: Vec<SourceTransformV1>,
    /// Keep all values rather than the first.
    #[serde(default)]
    pub multiple: bool,
}

/// Versioned operator projection declaration, not page metadata or request-supplied settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceProjectionConfigV1 {
    /// Exactly one.
    pub version: u16,
    /// Explicit destination mappings; missing canonical fields produce typed unavailable.
    pub mappings: Vec<SourceMappingV1>,
    /// At most 16,384 source values.
    pub max_values: usize,
    /// At most 16 MiB of source and finalized values.
    pub max_bytes: usize,
}

/// Strict version-one local operator registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceDispatchConfigV1 {
    /// Exactly one.
    pub version: u16,
    /// Enable native RSS and Atom child parsing.
    pub feeds: bool,
    /// Enable bounded native ZIP child parsing.
    pub zip: bool,
    /// Largest root/individual child input.
    pub max_input_bytes: usize,
    /// Aggregate expanded bytes across descendants.
    pub max_expanded_bytes: usize,
    /// Most descendants.
    pub max_children: usize,
    /// Maximum nested child depth.
    pub max_depth: u32,
    /// Maximum ZIP expansion ratio.
    pub max_ratio: u64,
    /// Finite traversal work budget.
    pub max_operations: usize,
    /// Total serialized finalized batch bytes.
    pub max_output_bytes: usize,
    /// Explicit soft feed entry cap, below the hard child bound.
    pub max_feed_entries: usize,
    /// Most emitted reference proposals across all children.
    pub max_references: usize,
    /// Optional approved search field projection.
    pub source_projection: Option<SourceProjectionConfigV1>,
}

impl Default for SourceDispatchConfigV1 {
    fn default() -> Self {
        Self {
            version: 1,
            feeds: true,
            zip: true,
            max_input_bytes: 16 * 1024 * 1024,
            max_expanded_bytes: 16 * 1024 * 1024,
            max_children: 1024,
            max_depth: 8,
            max_ratio: 100,
            max_operations: 1_000_000,
            max_output_bytes: 8 * 1024 * 1024,
            max_feed_entries: 1024,
            max_references: 4096,
            source_projection: None,
        }
    }
}

/// Explicit missing capability; never an implicit model/service/network fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceUnavailableReasonV1 {
    /// No operator registry was installed.
    OperatorPolicyMissing,
    /// Operator policy disabled the recognized source kind.
    SourceDisabled,
    /// Canonical article privacy projection did not run.
    CanonicalPrivacyMissing,
    /// A configured field was never recorded in finalized canonical metadata.
    CanonicalFieldUnavailable,
    /// Durable search projection is prohibited under original ZDR policy.
    RetentionDenied,
}

impl SourceUnavailableReasonV1 {
    /// Stable structural label for bounded metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OperatorPolicyMissing => "operator_policy_missing",
            Self::SourceDisabled => "source_disabled",
            Self::CanonicalPrivacyMissing => "canonical_privacy_missing",
            Self::CanonicalFieldUnavailable => "canonical_field_unavailable",
            Self::RetentionDenied => "retention_denied",
        }
    }
}

/// Search projection status suitable for a bounded sink, not unrestricted telemetry.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceProjectionOutcomeV1 {
    /// No operator projection was requested.
    NotConfigured,
    /// Requested projection cannot honestly be produced.
    Unavailable {
        /// Typed reason without raw source content.
        reason: SourceUnavailableReasonV1,
        /// Missing configured canonical fields.
        fields: Vec<SourceFieldV1>,
    },
    /// Finalized native search record, still subject to the existing retention-aware item sink.
    Produced {
        /// Existing native delivery schema.
        record: SearchProjectionV1,
        /// Exact approved operator configuration digest.
        policy_digest: Digest,
    },
}

/// Native source child's structural state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceChildStatusV1 {
    /// Native parsed child.
    Parsed,
    /// Traversed archive/feed parent.
    Container,
    /// Child format is not supported; no content was invented.
    Unsupported,
}

/// Finalized content-bearing child. Never put this directly into structural page metadata.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SourceChildV1 {
    /// Stable tenant-scoped logical identity.
    pub id: Digest,
    /// Immediate stable parent identity.
    pub parent: Option<Digest>,
    /// Original physical/authored ordinal, not an index after filtering.
    pub ordinal: u64,
    /// Root-relative child depth.
    pub depth: u32,
    /// Native parse state.
    pub status: SourceChildStatusV1,
    /// Approved title only.
    pub title: Option<String>,
    /// Approved selected text only; no raw HTML or parser diagnostics.
    pub text: String,
    /// Allowlisted canonical scalar/multivalue metadata only.
    pub metadata: BTreeMap<String, Value>,
    /// Operator-approved search result or explicit unavailability.
    pub projection: SourceProjectionOutcomeV1,
}

/// Proposal type, never authority to acquire or submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceReferenceKindV1 {
    /// Authored hyperlink/feed entry.
    Link,
    /// Authored embedded resource.
    Embed,
}

impl SourceReferenceKindV1 {
    /// Stable proposal label for bounded request metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Embed => "embed",
        }
    }
}

/// Fenced source discovery must re-admit every returned reference.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SourceReferenceV1 {
    /// HTTP(S) reference after original-run privacy validation.
    pub url: Url,
    /// Descriptive relation only.
    pub kind: SourceReferenceKindV1,
    /// Child whose source contained the reference.
    pub source_child: Digest,
    /// Source child's parent identity.
    pub parent: Option<Digest>,
    /// Original source ordinal.
    pub ordinal: u64,
    /// Native reviewed default route, never a source-selected handler.
    pub route: String,
}

/// Freshness from explicit authored dates; not HTTP cache or scheduler authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceFreshnessV1 {
    /// No authored baseline comparison exists.
    Unknown,
    /// Authored timestamp is newer.
    Modified,
    /// Authored timestamp is not newer.
    NotNewer,
    /// Explicit feed entry cap omitted content.
    Truncated,
}

impl From<SourceFreshness> for SourceFreshnessV1 {
    fn from(value: SourceFreshness) -> Self {
        match value {
            SourceFreshness::Modified => Self::Modified,
            SourceFreshness::NotNewer => Self::NotNewer,
            SourceFreshness::Truncated => Self::Truncated,
            _ => Self::Unknown,
        }
    }
}

/// One admitted content batch. Persist via the existing original-run ArtifactSink/item path.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct SourceBatchV1 {
    /// Exactly one.
    pub version: u16,
    /// Finalized child records in deterministic preorder.
    pub children: Vec<SourceChildV1>,
    /// Typed proposals for the existing fenced source admission path.
    pub references: Vec<SourceReferenceV1>,
    /// Authored feed freshness, or unknown for ZIP.
    pub freshness: SourceFreshnessV1,
    /// Soft feed entry output cap removed a suffix.
    pub truncated: bool,
    /// Exact count omitted by that soft cap.
    pub omitted_children: usize,
    /// Pinned operator configuration, without source bytes.
    pub policy_digest: Digest,
}

/// Dispatch result. The handled carrier owns the output reservation through caller sink I/O.
#[derive(Debug)]
#[non_exhaustive]
pub enum SourceDispatchOutcome {
    /// This leaf does not own the input kind; existing HTML/sitemap/connectors remain unchanged.
    NotHandled,
    /// Bounded native source batch and its transferable byte reservation.
    Handled(Budgeted<SourceBatchV1>),
}

/// Borrowed source input. Authentication/admission and original secret authority remain caller-owned.
pub struct SourceDispatchInput<'a> {
    /// Already admitted, transport-decoded body bytes.
    pub body: &'a [u8],
    /// Observed MIME declaration.
    pub content_type: Option<&'a str>,
    /// Observed response URL, used only to resolve proposals.
    pub response_url: &'a Url,
    /// Tenant-scoped, content-independent stable source identity supplied by trusted orchestration.
    pub root_id: Digest,
    /// Original run retention policy.
    pub retention: RetentionMode,
    /// Acquisition recorded an incomplete source; such input is refused, not reparsed as complete.
    pub truncated: bool,
    /// Original retained authored timestamp, if known.
    pub baseline_modified_ms: Option<i64>,
    /// Trusted original-run secret/PII projector. Errors reject the entire batch.
    pub privacy: &'a dyn Fn(&str) -> Result<String, StoreError>,
    /// Cancellation or injected deadline check.
    pub cancelled: &'a dyn Fn() -> bool,
}

/// Finalized canonical article input for the existing static article/item path.
pub struct SourceArticleInput<'a> {
    /// Canonical envelope after native privacy projection.
    pub envelope: &'a DocumentEnvelopeV1,
    /// Finalized selected text corresponding to this envelope.
    pub text: &'a str,
    /// Tenant-scoped stable logical document identity, not a raw URL.
    pub document_id: String,
    /// Immediate parent identity when this is an extracted child.
    pub parent_id: Option<String>,
    /// Original run retention policy.
    pub retention: RetentionMode,
    /// Original-run trusted projector; never an identity closure.
    pub privacy: &'a dyn Fn(&str) -> Result<String, StoreError>,
}

/// Native dispatch failure. Diagnostics contain categories, never source strings or config paths.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SourceDispatchError {
    /// Unsupported, malformed or oversized approved configuration.
    #[error("invalid source dispatch configuration")]
    Config,
    /// Local approved configuration could not be read.
    #[error("source dispatch configuration read failed")]
    Io(#[source] std::io::Error),
    /// Missing explicitly requested operator/parser capability.
    #[error("source dispatch capability unavailable")]
    Unavailable(SourceUnavailableReasonV1),
    /// Shared byte admission refused before expansion/output allocation.
    #[error("source dispatch memory admission refused")]
    Memory(#[source] ByteAdmissionError),
    /// Native container parsing refused.
    #[error("source dispatch traversal failed")]
    Traversal(#[source] TraversalError),
    /// Original privacy authority refused or could not validate a derived value.
    #[error("source dispatch privacy projection failed")]
    Privacy(#[source] StoreError),
    /// Approved native projection rejected.
    #[error("source dispatch search projection failed")]
    Projection(#[source] SourceProjectionError),
    /// Truncated acquisition bytes cannot establish complete child records.
    #[error("source dispatch input truncated")]
    SourceTruncated,
    /// Explicit cancellation/deadline.
    #[error("source dispatch cancelled")]
    Cancelled,
    /// Aggregate finalized output, metadata or reference bound exceeded.
    #[error("source dispatch resource limit exceeded")]
    Limit,
}

struct ApprovedProjection {
    config: SourceProjectionConfigV1,
    native: SourceProjectionPolicy,
}

/// Compiled immutable operator capability. It contains no acquisition or storage interface.
pub struct SourceDispatcher {
    config: SourceDispatchConfigV1,
    pipeline: ParserPipeline,
    projection: Option<ApprovedProjection>,
    digest: Digest,
}

impl std::fmt::Debug for SourceDispatcher {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("SourceDispatcher")
            .field("policy_digest", &self.digest)
            .field("feeds", &self.config.feeds)
            .field("zip", &self.config.zip)
            .field("projection_requested", &self.projection.is_some())
            .finish()
    }
}

impl SourceDispatcher {
    /// Validate and compile one immutable operator policy before any source is read.
    ///
    /// # Errors
    /// Rejects unknown versions, unbounded work, native projection collisions and invalid routes.
    pub fn new(config: SourceDispatchConfigV1) -> Result<Self, SourceDispatchError> {
        if config.version != 1
            || !(1..=128 * 1024 * 1024).contains(&config.max_input_bytes)
            || !(1..=512 * 1024 * 1024).contains(&config.max_expanded_bytes)
            || !(1..=100_000).contains(&config.max_children)
            || !(1..=64).contains(&config.max_depth)
            || !(1..=10_000).contains(&config.max_ratio)
            || !(1..=4_000_000).contains(&config.max_operations)
            || !(1..=128 * 1024 * 1024).contains(&config.max_output_bytes)
            || config.max_feed_entries > config.max_children
            || config.max_references > 100_000
        {
            return Err(SourceDispatchError::Config);
        }
        let projection = config
            .source_projection
            .as_ref()
            .map(|spec| {
                if spec.version != 1 {
                    return Err(SourceDispatchError::Config);
                }
                let mappings = spec
                    .mappings
                    .iter()
                    .map(|mapping| {
                        FieldMapping::new(
                            mapping.source.native(),
                            mapping.destination.clone(),
                            mapping
                                .transforms
                                .iter()
                                .map(|transform| transform.native())
                                .collect(),
                            mapping.multiple,
                        )
                    })
                    .collect();
                let native = SourceProjectionPolicy::new(
                    "native_source_projection_v1".into(),
                    mappings,
                    spec.max_values,
                    spec.max_bytes,
                )
                .map_err(SourceDispatchError::Projection)?;
                Ok(ApprovedProjection {
                    config: spec.clone(),
                    native,
                })
            })
            .transpose()?;
        let digest = Digest::of_value("crawlx.source-dispatch.v1", &config)
            .map_err(|_| SourceDispatchError::Config)?;
        let mut pipeline = ParserPipelineV1::for_uploads();
        pipeline.limits.max_input_bytes =
            u64::try_from(config.max_input_bytes).map_err(|_| SourceDispatchError::Config)?;
        pipeline.limits.max_output_bytes =
            u64::try_from(config.max_output_bytes).map_err(|_| SourceDispatchError::Config)?;
        pipeline.limits.max_operations =
            u64::try_from(config.max_operations).map_err(|_| SourceDispatchError::Config)?;
        pipeline.limits.max_children =
            u64::try_from(config.max_children).map_err(|_| SourceDispatchError::Config)?;
        let pipeline = ParserPipeline::new(pipeline).map_err(|_| SourceDispatchError::Config)?;
        Ok(Self {
            config,
            pipeline,
            projection,
            digest,
        })
    }

    /// Compile bounded strict operator JSON. Unknown fields are rejected.
    ///
    /// # Errors
    /// Rejects over-64-KiB JSON, malformed/unknown fields and invalid version/bounds.
    pub fn from_json(bytes: &[u8]) -> Result<Self, SourceDispatchError> {
        if bytes.len() > MAX_SOURCE_DISPATCH_CONFIG_BYTES {
            return Err(SourceDispatchError::Config);
        }
        let config = serde_json::from_slice(bytes).map_err(|_| SourceDispatchError::Config)?;
        Self::new(config)
    }

    /// Read one approved local startup file, bounded before parsing.
    ///
    /// # Errors
    /// Returns fixed-category I/O/configuration failures, without echoing source paths/content.
    pub fn from_file(path: &Path) -> Result<Self, SourceDispatchError> {
        let file = File::open(path).map_err(SourceDispatchError::Io)?;
        let cap = u64::try_from(MAX_SOURCE_DISPATCH_CONFIG_BYTES).map_err(|_| SourceDispatchError::Config)?;
        let mut bytes = Vec::new();
        file.take(cap + 1)
            .read_to_end(&mut bytes)
            .map_err(SourceDispatchError::Io)?;
        Self::from_json(&bytes)
    }

    /// Load the optional operator startup registry. Missing environment leaves capability absent.
    ///
    /// # Errors
    /// Refuses an empty configured path or invalid local operator configuration.
    pub fn from_env(
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<Arc<Self>>, SourceDispatchError> {
        let Some(path) = getenv("CRAWLX_SOURCE_DISPATCH_CONFIG") else {
            return Ok(None);
        };
        if path.trim().is_empty() {
            return Err(SourceDispatchError::Config);
        }
        Self::from_file(Path::new(&path)).map(|dispatcher| Some(Arc::new(dispatcher)))
    }

    /// Exact operator configuration identity.
    #[must_use]
    pub const fn policy_digest(&self) -> Digest {
        self.digest
    }

    /// Whether this operator registry explicitly requests search projection.
    #[must_use]
    pub const fn projection_requested(&self) -> bool {
        self.projection.is_some()
    }

    /// Identify only this dispatcher's source kinds; existing sitemap/HTML paths remain separate.
    #[must_use]
    pub fn recognizes(body: &[u8], content_type: Option<&str>) -> bool {
        source_kind(body, content_type).is_some()
    }

    /// Parse admitted feed/ZIP bytes, finalize approved content and return proposal-only refs.
    /// Keep the returned reservation until all child sink/admission work completes.
    ///
    /// # Errors
    /// Refuses disabled capability, truncated acquisition, bombs, bounds, cancellation, memory,
    /// original-run privacy and approved-projection errors. Nothing falls back to acquisition.
    pub fn dispatch(
        &self,
        input: SourceDispatchInput<'_>,
    ) -> Result<SourceDispatchOutcome, SourceDispatchError> {
        let Some(kind) = source_kind(input.body, input.content_type) else {
            return Ok(SourceDispatchOutcome::NotHandled);
        };
        if (input.cancelled)() {
            return Err(SourceDispatchError::Cancelled);
        }
        if input.truncated {
            return Err(SourceDispatchError::SourceTruncated);
        }
        if (kind == SourceKind::Zip && !self.config.zip) || (kind != SourceKind::Zip && !self.config.feeds) {
            return Err(SourceDispatchError::Unavailable(
                SourceUnavailableReasonV1::SourceDisabled,
            ));
        }
        if input.body.len() > self.config.max_input_bytes {
            return Err(SourceDispatchError::Limit);
        }
        // Transient expansion plus parser outputs and their finalized copies, reserved before traversal.
        let reservation = self
            .config
            .max_output_bytes
            .checked_mul(2)
            .and_then(|output| output.checked_add(self.config.max_expanded_bytes))
            .and_then(|bytes| {
                self.config
                    .max_children
                    .checked_mul(1024)
                    .and_then(|structure| bytes.checked_add(structure))
            })
            .ok_or(SourceDispatchError::Limit)?;
        let permit = parser_memory::global()
            .try_reserve(reservation)
            .map_err(SourceDispatchError::Memory)?;
        let mut limits = TraversalLimits::default();
        limits.max_input_bytes = self.config.max_input_bytes;
        limits.max_expanded_bytes = self.config.max_expanded_bytes;
        limits.max_children = self.config.max_children;
        limits.max_depth = self.config.max_depth;
        limits.max_ratio = self.config.max_ratio;
        limits.max_operations = self.config.max_operations;
        limits.max_output_bytes = self.config.max_output_bytes;
        let (records, freshness, omitted_children) = match kind {
            SourceKind::Zip => (
                traversal::traverse(
                    &self.pipeline,
                    input.body,
                    input.content_type,
                    input.root_id,
                    limits,
                    input.cancelled,
                )
                .map_err(SourceDispatchError::Traversal)?,
                SourceFreshnessV1::Unknown,
                0,
            ),
            SourceKind::Rss | SourceKind::Atom => {
                let mime = if kind == SourceKind::Rss {
                    "application/rss+xml"
                } else {
                    "application/atom+xml"
                };
                let report = traversal::feed_with_freshness(
                    &self.pipeline,
                    input.body,
                    mime,
                    input.root_id,
                    limits,
                    self.config.max_feed_entries,
                    input.baseline_modified_ms,
                    input.cancelled,
                )
                .map_err(SourceDispatchError::Traversal)?;
                (report.records, report.freshness.into(), report.omitted_entries)
            }
        };
        let mut children = Vec::with_capacity(records.len());
        let mut references = Vec::new();
        let mut seen = BTreeSet::new();
        for record in records {
            if (input.cancelled)() {
                return Err(SourceDispatchError::Cancelled);
            }
            let ChildRecord {
                id,
                parent,
                ordinal,
                depth,
                content,
                references: feed_references,
                ..
            } = record;
            for url in feed_references {
                self.reference(
                    &input,
                    url.as_str(),
                    SourceReferenceKindV1::Link,
                    id,
                    parent,
                    ordinal,
                    &mut seen,
                    &mut references,
                )?;
            }
            let (status, mut sources, projection) = match content {
                ChildContent::Parsed(output) => {
                    for url in output.link_urls() {
                        self.reference(
                            &input,
                            url,
                            SourceReferenceKindV1::Link,
                            id,
                            parent,
                            ordinal,
                            &mut seen,
                            &mut references,
                        )?;
                    }
                    match &output.content {
                        PipelineContent::Page(document) => {
                            for url in &document.assets {
                                self.reference(
                                    &input,
                                    url.as_str(),
                                    SourceReferenceKindV1::Embed,
                                    id,
                                    parent,
                                    ordinal,
                                    &mut seen,
                                    &mut references,
                                )?;
                            }
                        }
                        PipelineContent::Document(document) => {
                            for url in &document.images {
                                self.reference(
                                    &input,
                                    url,
                                    SourceReferenceKindV1::Embed,
                                    id,
                                    parent,
                                    ordinal,
                                    &mut seen,
                                    &mut references,
                                )?;
                            }
                        }
                        _ => {}
                    }
                    let sources = finalized_sources(&output, input.privacy, self.config.max_output_bytes)?;
                    let projection = self.project_sources(
                        &sources,
                        id.to_string(),
                        parent.map(|parent| parent.to_string()),
                        input.retention,
                        input.privacy,
                    )?;
                    (SourceChildStatusV1::Parsed, sources, projection)
                }
                ChildContent::Container => (
                    SourceChildStatusV1::Container,
                    BTreeMap::new(),
                    SourceProjectionOutcomeV1::NotConfigured,
                ),
                _ => (
                    SourceChildStatusV1::Unsupported,
                    BTreeMap::new(),
                    SourceProjectionOutcomeV1::Unavailable {
                        reason: SourceUnavailableReasonV1::CanonicalFieldUnavailable,
                        fields: Vec::new(),
                    },
                ),
            };
            let title = sources
                .remove(&SourceField::Title)
                .and_then(|values| values.into_iter().next());
            let text = sources
                .remove(&SourceField::Text)
                .and_then(|values| values.into_iter().next())
                .unwrap_or_default();
            let metadata = ALL_FIELDS
                .iter()
                .filter_map(|field| {
                    sources.remove(&field.native()).map(|values| {
                        (
                            field.name().to_owned(),
                            Value::Array(values.into_iter().map(Value::String).collect()),
                        )
                    })
                })
                .collect();
            children.push(SourceChildV1 {
                id,
                parent,
                ordinal,
                depth,
                status,
                title,
                text,
                metadata,
                projection,
            });
        }
        let batch = SourceBatchV1 {
            version: 1,
            children,
            references,
            freshness,
            truncated: omitted_children > 0,
            omitted_children,
            policy_digest: self.digest,
        };
        bounded_json_len(&batch, self.config.max_output_bytes).map_err(|_| SourceDispatchError::Limit)?;
        if (input.cancelled)() {
            return Err(SourceDispatchError::Cancelled);
        }
        Ok(SourceDispatchOutcome::Handled(Budgeted::new(batch, permit)))
    }

    /// Project only finalized canonical article values on the existing article/item path.
    /// Missing heading/licence metadata stays explicitly unavailable, never inferred from raw blobs.
    ///
    /// # Errors
    /// Refuses source/output bounds, original-run privacy failures and native policy validation.
    pub fn project_article(
        &self,
        input: SourceArticleInput<'_>,
    ) -> Result<SourceProjectionOutcomeV1, SourceDispatchError> {
        if self.projection.is_none() {
            return Ok(SourceProjectionOutcomeV1::NotConfigured);
        }
        if input.envelope.privacy_projection_version != Some(1) {
            return Ok(SourceProjectionOutcomeV1::Unavailable {
                reason: SourceUnavailableReasonV1::CanonicalPrivacyMissing,
                fields: Vec::new(),
            });
        }
        let metadata = &input.envelope.metadata;
        let mut sources = BTreeMap::new();
        let mut bytes = 0;
        add(
            &mut sources,
            SourceField::Text,
            input.text,
            input.privacy,
            &mut bytes,
            self.config.max_output_bytes,
        )?;
        if let Some(title) = &metadata.title.value {
            add(
                &mut sources,
                SourceField::Title,
                title,
                input.privacy,
                &mut bytes,
                self.config.max_output_bytes,
            )?;
        }
        if let Some(language) = &metadata.language.value {
            add(
                &mut sources,
                SourceField::Language,
                language,
                input.privacy,
                &mut bytes,
                self.config.max_output_bytes,
            )?;
        }
        if let Some(authors) = &metadata.authors.value {
            for author in authors {
                add(
                    &mut sources,
                    SourceField::Author,
                    author,
                    input.privacy,
                    &mut bytes,
                    self.config.max_output_bytes,
                )?;
            }
        }
        for tag in &metadata.declared_keywords {
            add(
                &mut sources,
                SourceField::Tag,
                tag,
                input.privacy,
                &mut bytes,
                self.config.max_output_bytes,
            )?;
        }
        if let Some(published) = &metadata.published.value {
            let published = published
                .timestamp
                .clone()
                .unwrap_or_else(|| published.date.to_string());
            add(
                &mut sources,
                SourceField::Published,
                &published,
                input.privacy,
                &mut bytes,
                self.config.max_output_bytes,
            )?;
        }
        self.project_sources(
            &sources,
            input.document_id,
            input.parent_id,
            input.retention,
            input.privacy,
        )
    }

    fn project_sources(
        &self,
        sources: &BTreeMap<SourceField, Vec<String>>,
        document_id: String,
        parent_id: Option<String>,
        retention: RetentionMode,
        privacy: &dyn Fn(&str) -> Result<String, StoreError>,
    ) -> Result<SourceProjectionOutcomeV1, SourceDispatchError> {
        let Some(projection) = &self.projection else {
            return Ok(SourceProjectionOutcomeV1::NotConfigured);
        };
        if retention == RetentionMode::Zdr {
            return Ok(SourceProjectionOutcomeV1::Unavailable {
                reason: SourceUnavailableReasonV1::RetentionDenied,
                fields: Vec::new(),
            });
        }
        let missing: BTreeSet<_> = projection
            .config
            .mappings
            .iter()
            .filter_map(|mapping| (!sources.contains_key(&mapping.source.native())).then_some(mapping.source))
            .collect();
        if !missing.is_empty() {
            return Ok(SourceProjectionOutcomeV1::Unavailable {
                reason: SourceUnavailableReasonV1::CanonicalFieldUnavailable,
                fields: missing.into_iter().collect(),
            });
        }
        let failure = std::cell::RefCell::new(None);
        let project = |value: &str| match privacy(value) {
            Ok(value) => Some(value),
            Err(error) => {
                *failure.borrow_mut() = Some(error);
                None
            }
        };
        let record = projection
            .native
            .project(document_id, parent_id, sources, retention, &project);
        if let Some(error) = failure.into_inner() {
            return Err(SourceDispatchError::Privacy(error));
        }
        let record = record.map_err(SourceDispatchError::Projection)?;
        Ok(SourceProjectionOutcomeV1::Produced {
            record,
            policy_digest: self.digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn reference(
        &self,
        input: &SourceDispatchInput<'_>,
        raw: &str,
        kind: SourceReferenceKindV1,
        source_child: Digest,
        parent: Option<Digest>,
        ordinal: u64,
        seen: &mut BTreeSet<(Digest, String)>,
        output: &mut Vec<SourceReferenceV1>,
    ) -> Result<(), SourceDispatchError> {
        if raw.len() > 4096 {
            return Err(SourceDispatchError::Limit);
        }
        let approved = (input.privacy)(raw).map_err(SourceDispatchError::Privacy)?;
        // Privacy rewriting a destination cannot confer authority on a different URL.
        if approved != raw {
            return Ok(());
        }
        let Ok(url) = source_policy::reference(input.response_url, raw, ReferenceEncoding::Literal) else {
            return Ok(());
        };
        if !seen.insert((source_child, url.as_str().to_owned())) {
            return Ok(());
        }
        if output.len() >= self.config.max_references {
            return Err(SourceDispatchError::Limit);
        }
        output.push(SourceReferenceV1 {
            url,
            kind,
            source_child,
            parent,
            ordinal,
            route: "default".into(),
        });
        Ok(())
    }
}

#[derive(PartialEq, Eq)]
enum SourceKind {
    Zip,
    Rss,
    Atom,
}

fn source_kind(body: &[u8], content_type: Option<&str>) -> Option<SourceKind> {
    if body.starts_with(b"PK\x03\x04") || body.starts_with(b"PK\x05\x06") {
        return Some(SourceKind::Zip);
    }
    let mime = content_type
        .and_then(|mime| mime.split(';').next())
        .map(str::trim);
    if mime.is_some_and(|mime| mime.eq_ignore_ascii_case("application/rss+xml")) {
        return Some(SourceKind::Rss);
    }
    if mime.is_some_and(|mime| mime.eq_ignore_ascii_case("application/atom+xml")) {
        return Some(SourceKind::Atom);
    }
    let head = &body[..body.len().min(1024)];
    let text = std::str::from_utf8(head).ok()?;
    if text.contains("<rss") || text.contains("<rdf:RDF") {
        Some(SourceKind::Rss)
    } else if text.contains("<feed") {
        Some(SourceKind::Atom)
    } else {
        None
    }
}

const ALL_FIELDS: [SourceFieldV1; 9] = [
    SourceFieldV1::Title,
    SourceFieldV1::Text,
    SourceFieldV1::Heading,
    SourceFieldV1::Tag,
    SourceFieldV1::Language,
    SourceFieldV1::Licence,
    SourceFieldV1::Description,
    SourceFieldV1::Author,
    SourceFieldV1::Published,
];

fn add(
    sources: &mut BTreeMap<SourceField, Vec<String>>,
    field: SourceField,
    value: &str,
    privacy: &dyn Fn(&str) -> Result<String, StoreError>,
    bytes: &mut usize,
    max_bytes: usize,
) -> Result<(), SourceDispatchError> {
    *bytes = bytes.checked_add(value.len()).ok_or(SourceDispatchError::Limit)?;
    if *bytes > max_bytes {
        return Err(SourceDispatchError::Limit);
    }
    let value = privacy(value).map_err(SourceDispatchError::Privacy)?;
    *bytes = bytes.checked_add(value.len()).ok_or(SourceDispatchError::Limit)?;
    if *bytes > max_bytes || sources.get(&field).is_some_and(|values| values.len() >= 256) {
        return Err(SourceDispatchError::Limit);
    }
    sources.entry(field).or_default().push(value);
    Ok(())
}

fn finalized_sources(
    output: &PipelineOutput,
    privacy: &dyn Fn(&str) -> Result<String, StoreError>,
    max_bytes: usize,
) -> Result<BTreeMap<SourceField, Vec<String>>, SourceDispatchError> {
    let mut sources = BTreeMap::new();
    let mut bytes = 0;
    add(
        &mut sources,
        SourceField::Text,
        output.text(),
        privacy,
        &mut bytes,
        max_bytes,
    )?;
    if let Some(title) = output.title() {
        add(
            &mut sources,
            SourceField::Title,
            title,
            privacy,
            &mut bytes,
            max_bytes,
        )?;
    }
    match &output.content {
        PipelineContent::Document(document) => {
            for (key, field) in [
                ("language", SourceField::Language),
                ("author", SourceField::Author),
                ("keywords", SourceField::Tag),
                ("publishedTime", SourceField::Published),
                ("license", SourceField::Licence),
                ("licence", SourceField::Licence),
                ("description", SourceField::Description),
                ("headings", SourceField::Heading),
            ] {
                match document.metadata.get(key) {
                    Some(Value::String(value)) => {
                        add(&mut sources, field, value, privacy, &mut bytes, max_bytes)?
                    }
                    Some(Value::Array(values)) => {
                        for value in values {
                            if let Value::String(value) = value {
                                add(&mut sources, field, value, privacy, &mut bytes, max_bytes)?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        PipelineContent::Page(document) => {
            if let Some(language) = &document.language {
                add(
                    &mut sources,
                    SourceField::Language,
                    language,
                    privacy,
                    &mut bytes,
                    max_bytes,
                )?;
            }
            if let Some(description) = &document.description {
                add(
                    &mut sources,
                    SourceField::Description,
                    description,
                    privacy,
                    &mut bytes,
                    max_bytes,
                )?;
            }
            if let Some(envelope) = &document.article {
                if let Some(authors) = &envelope.metadata.authors.value {
                    for author in authors {
                        add(
                            &mut sources,
                            SourceField::Author,
                            author,
                            privacy,
                            &mut bytes,
                            max_bytes,
                        )?;
                    }
                }
                for tag in &envelope.metadata.declared_keywords {
                    add(
                        &mut sources,
                        SourceField::Tag,
                        tag,
                        privacy,
                        &mut bytes,
                        max_bytes,
                    )?;
                }
            }
        }
        _ => {
            return Err(SourceDispatchError::Unavailable(
                SourceUnavailableReasonV1::CanonicalFieldUnavailable,
            ))
        }
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_extract::source_projection::stable_child_id;

    const FEED: &[u8] = b"<rss><channel><lastBuildDate>Tue, 03 Feb 2026 00:00:00 GMT</lastBuildDate><item><title>One</title><link>https://example.test/one</link></item><item><title>secret-canary</title><link>https://example.test/secret-canary</link></item></channel></rss>";

    fn privacy(value: &str) -> Result<String, StoreError> {
        Ok(value.replace("secret-canary", "[REDACTED]"))
    }

    fn input<'a>(
        body: &'a [u8],
        url: &'a Url,
        retention: RetentionMode,
        truncated: bool,
    ) -> SourceDispatchInput<'a> {
        SourceDispatchInput {
            body,
            content_type: Some("application/rss+xml"),
            response_url: url,
            root_id: Digest::of("tenant-source", b"root"),
            retention,
            truncated,
            baseline_modified_ms: Some(0),
            privacy: &privacy,
            cancelled: &|| false,
        }
    }

    fn dispatcher(projection: bool) -> SourceDispatcher {
        let mut config = SourceDispatchConfigV1 {
            max_expanded_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            ..SourceDispatchConfigV1::default()
        };
        if projection {
            config.source_projection = Some(SourceProjectionConfigV1 {
                version: 1,
                mappings: vec![SourceMappingV1 {
                    source: SourceFieldV1::Text,
                    destination: "body".into(),
                    transforms: vec![SourceTransformV1::Trim],
                    multiple: false,
                }],
                max_values: 16,
                max_bytes: 4096,
            });
        }
        SourceDispatcher::new(config).unwrap()
    }

    #[test]
    fn strict_operator_config_rejects_unknown_oversized_and_invalid_projection() {
        assert!(SourceDispatcher::from_json(br#"{"version":1,"sourceSelected":true}"#).is_err());
        assert!(SourceDispatcher::from_json(&vec![b' '; MAX_SOURCE_DISPATCH_CONFIG_BYTES + 1]).is_err());
        assert!(SourceDispatcher::from_json(br#"{"version":1,"sourceProjection":{"version":1,"mappings":[{"source":"text","destination":"id"}],"maxValues":1,"maxBytes":10}}"#).is_err());
        assert!(SourceDispatcher::from_env(&|_| None).unwrap().is_none());
        assert!(
            SourceDispatcher::from_json(br#"{"version":1}"#)
                .unwrap()
                .policy_digest()
                != Digest::of("other", b"")
        );
    }

    #[test]
    fn feed_children_keep_stable_ids_freshness_privacy_and_proposal_only_references() {
        let url = Url::parse("https://example.test/feed.xml").unwrap();
        let SourceDispatchOutcome::Handled(batch) = dispatcher(true)
            .dispatch(input(FEED, &url, RetentionMode::Standard, false))
            .unwrap()
        else {
            panic!("feed not handled")
        };
        let batch = batch.value();
        let root = Digest::of("tenant-source", b"root");
        assert_eq!(batch.children.len(), 3);
        assert_eq!(batch.children[1].id, stable_child_id(root, 0));
        assert_eq!(batch.children[2].id, stable_child_id(root, 1));
        assert_eq!(batch.children[2].parent, Some(root));
        assert_eq!(batch.freshness, SourceFreshnessV1::Modified);
        assert_eq!(batch.references.len(), 1);
        assert_eq!(batch.references[0].url.as_str(), "https://example.test/one");
        assert_eq!(batch.references[0].route, "default");
        let json = serde_json::to_string(batch).unwrap();
        assert!(!json.contains("secret-canary"));
        assert!(matches!(
            batch.children[1].projection,
            SourceProjectionOutcomeV1::Produced { .. }
        ));
    }

    #[test]
    fn explicit_unavailable_truncation_cancellation_zdr_and_html_passthrough() {
        let url = Url::parse("https://example.test/feed.xml").unwrap();
        let config = SourceDispatchConfigV1 {
            feeds: false,
            ..SourceDispatchConfigV1::default()
        };
        assert!(matches!(
            SourceDispatcher::new(config).unwrap().dispatch(input(
                FEED,
                &url,
                RetentionMode::Standard,
                false
            )),
            Err(SourceDispatchError::Unavailable(
                SourceUnavailableReasonV1::SourceDisabled
            ))
        ));
        assert!(matches!(
            dispatcher(false).dispatch(input(FEED, &url, RetentionMode::Standard, true)),
            Err(SourceDispatchError::SourceTruncated)
        ));
        let mut cancelled = input(FEED, &url, RetentionMode::Standard, false);
        cancelled.cancelled = &|| true;
        assert!(matches!(
            dispatcher(false).dispatch(cancelled),
            Err(SourceDispatchError::Cancelled)
        ));
        let SourceDispatchOutcome::Handled(batch) = dispatcher(true)
            .dispatch(input(FEED, &url, RetentionMode::Zdr, false))
            .unwrap()
        else {
            panic!("feed not handled")
        };
        assert!(matches!(
            batch.value().children[1].projection,
            SourceProjectionOutcomeV1::Unavailable {
                reason: SourceUnavailableReasonV1::RetentionDenied,
                ..
            }
        ));
        let mut html = input(
            b"<html><body>page</body></html>",
            &url,
            RetentionMode::Standard,
            false,
        );
        html.content_type = Some("text/html");
        assert!(matches!(
            dispatcher(false).dispatch(html),
            Ok(SourceDispatchOutcome::NotHandled)
        ));
        assert!(!SourceDispatcher::recognizes(b"<html></html>", Some("text/html")));
        assert!(SourceDispatcher::recognizes(b"PK\x03\x04", None));
    }
}
