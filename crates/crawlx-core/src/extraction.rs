//! Version-one native article extraction contracts.
//!
//! Envelopes contain content and PII. They are not safe structural telemetry and must
//! pass the same retention/redaction boundary as the document they describe.

use crate::{hash::Digest, CoreError};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};

mod chunks;
pub use chunks::{WordChunkEnvelopeV1, WordChunkErrorV1, WordChunkPolicyV1, WordChunkStrategyV1};

/// Native fixed-point article strategy; not upstream algorithm parity.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArticleAlgorithmV1 {
    /// Compare paragraph, gravity and density candidates.
    #[default]
    ArticleEnsembleV1,
    /// Paragraph classifier only before explicitly enabled fallback.
    ArticleRulesV1,
    /// Parent/grandparent paragraph gravity.
    ArticleGravityV1,
    /// Existing density features with integer scoring.
    ArticleDensityV1,
}
/// Selection tradeoff.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContentFocusV1 {
    /// Native balanced thresholds.
    #[default]
    Balanced,
    /// Require stronger paragraph evidence.
    Precision,
    /// Retain short neighboring text.
    Recall,
}
/// Fallback is literal; none runs no rescue stage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContentFallbackV1 {
    /// No broad rescue.
    None,
    /// One bounded original-tree block rescue.
    #[default]
    Bounded,
}
/// Blog comments never silently enter main content.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CommentPolicyV1 {
    /// Drop reader comments.
    #[default]
    Drop,
    /// Return comments as separate content.
    Separate,
}
/// Required metadata field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RequiredMetadataV1 {
    /// Selected title.
    Title,
    /// Resolved source URL.
    Url,
    /// Unambiguous publication date.
    PublishedDate,
    /// At least one author.
    Author,
    /// Declared language evidence.
    Language,
}
/// Native rule NLP or an explicitly unavailable optional model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NlpCapabilityV1 {
    /// Unicode punctuation and lexical frequency, version one.
    #[default]
    UnicodeRulesV1,
    /// Requires a licensed worker-injected bundle; unavailable in this pure parser.
    PunktModel,
    /// Disable keyword and summary generation.
    Off,
}
/// Explicit word segmentation algorithm for native article NLP.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ArticleTokenizerV1 {
    /// Existing Unicode rule tokenizer.
    #[default]
    UnicodeRulesV1,
    /// ICU dictionary and UAX 29 boundaries with Unicode 17 data.
    IcuDictionaryUax29V17V1,
}
/// Bounded, opt-in content policy. Omission preserves legacy extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtractionPolicyV1 {
    /// Schema version, exactly one.
    pub version: u16,
    /// Native strategy.
    pub algorithm: ArticleAlgorithmV1,
    /// Precision/recall tradeoff.
    pub focus: ContentFocusV1,
    /// Broad rescue policy.
    pub fallback: ContentFallbackV1,
    /// Separate reader-comment behavior.
    pub comments: CommentPolicyV1,
    /// Minimum accepted main Unicode scalar count.
    pub min_main_chars: usize,
    /// Fields required for accepted quality.
    pub required_metadata: Vec<RequiredMetadataV1>,
    /// Reject ingestion when any recognized author matches one of at most 64 names.
    /// Names are at most 256 UTF-8 bytes. Matching collapses Unicode whitespace and
    /// uses Unicode lowercase, not substrings, transliteration or fuzzy matching.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub excluded_authors: Vec<String>,
    /// Maximum main output Unicode scalar count.
    pub max_output_chars: usize,
    /// Maximum paragraph/element operations, no more than four million.
    pub max_operations: usize,
    /// Largest retained candidate block set.
    pub max_blocks: usize,
    /// Keep tables in selected output.
    pub tables: bool,
    /// Keep image references; never download images.
    pub images: bool,
    /// Keep hyperlinks in structural HTML/Markdown; never changes discovered URLs.
    #[serde(skip_serializing_if = "enabled")]
    pub links: bool,
    /// Keep inline emphasis, code, quotes and other typographic markup.
    /// Disabling preserves canonical text, block structure, tables and image policy.
    #[serde(skip_serializing_if = "enabled")]
    pub formatting: bool,
    /// Explicit reference calendar date for future-date checks; never defaults to now.
    pub reference_date: Option<NaiveDate>,
    /// Numeric date locale, e.g. en-US or en-GB; ambiguity stays unknown without it.
    pub locale: Option<String>,
    /// Explicit IANA zone or fixed offset for local date-time evidence.
    pub date_timezone: Option<String>,
    /// Optional strict declared language target; no detected language is fabricated.
    pub target_language: Option<String>,
    /// Language evidence selection policy.
    pub language_mode: crate::article_language::LanguageModeV1,
    /// Required digest of the approved local detector for detection modes.
    pub language_bundle_digest: Option<Digest>,
    /// Minimum detector probability in thousandths.
    pub language_min_probability_millis: u16,
    /// Minimum lead over the next detector result in thousandths.
    pub language_min_margin_millis: u16,
    /// Requested NLP implementation.
    pub nlp: NlpCapabilityV1,
    /// Explicit tokenizer; omission preserves existing Unicode rules.
    pub tokenizer: ArticleTokenizerV1,
    /// Keyword count (at most 35).
    pub keywords: usize,
    /// Extractive sentence count (at most 20).
    pub summary_sentences: usize,
    /// Maximum summary Unicode scalars (at most 20,000).
    pub summary_max_chars: usize,
    /// Explicit CSS/XPath static tree selection and pruning.
    pub selectors: crate::selectors::SelectorPolicyV1,
    /// Optional bounded custom-field item recipe on the original parsed tree.
    pub item_loader: Option<crate::selectors::ItemLoaderV1>,
    /// Optional native Unicode-whitespace word windows over final privacy-approved text.
    /// Absence preserves existing serialized extraction-policy identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks: Option<WordChunkPolicyV1>,
}
impl Default for ExtractionPolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            algorithm: ArticleAlgorithmV1::default(),
            focus: ContentFocusV1::default(),
            fallback: ContentFallbackV1::default(),
            comments: CommentPolicyV1::default(),
            min_main_chars: 40,
            required_metadata: Vec::new(),
            excluded_authors: Vec::new(),
            max_output_chars: 1_000_000,
            max_operations: 4_000_000,
            max_blocks: 20_000,
            tables: true,
            images: true,
            links: true,
            formatting: true,
            reference_date: None,
            locale: None,
            date_timezone: None,
            target_language: None,
            language_mode: crate::article_language::LanguageModeV1::default(),
            language_bundle_digest: None,
            language_min_probability_millis: 800,
            language_min_margin_millis: 150,
            nlp: NlpCapabilityV1::default(),
            tokenizer: ArticleTokenizerV1::default(),
            keywords: 10,
            summary_sentences: 5,
            summary_max_chars: 5000,
            selectors: crate::selectors::SelectorPolicyV1::default(),
            item_loader: None,
            chunks: None,
        }
    }
}
fn enabled(value: &bool) -> bool {
    *value
}

impl ExtractionPolicyV1 {
    /// Validate policy bounds before parsing or queue admission.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` for unknown versions, conflicts or excessive limits.
    pub fn validate(&self) -> Result<(), CoreError> {
        self.selectors.validate()?;
        if let Some(chunks) = &self.chunks {
            chunks.validate().map_err(|error| CoreError::Invalid {
                field: "extract.content.chunks",
                reason: error.to_string(),
            })?;
        }
        if let Some(loader) = &self.item_loader {
            loader.validate()?;
        }
        let valid = self.version == 1
            && (1..=4_000_000).contains(&self.max_operations)
            && (1..=20_000).contains(&self.max_blocks)
            && (1..=16_777_216).contains(&self.max_output_chars)
            && self.min_main_chars <= self.max_output_chars
            && self.required_metadata.len() <= 5
            && self.excluded_authors.len() <= 64
            && self.excluded_authors.iter().all(|name| {
                !name.trim().is_empty()
                    && name.len() <= 256
                    && !name.chars().any(|c| c.is_control() && !c.is_whitespace())
            })
            && self.keywords <= 35
            && self.summary_sentences <= 20
            && self.summary_max_chars <= 20_000
            && self.language_min_probability_millis <= 1000
            && self.language_min_margin_millis <= 1000
            && (self.language_mode == crate::article_language::LanguageModeV1::DeclaredOnly
                || self.language_bundle_digest.is_some())
            && self.locale.as_ref().is_none_or(|s| s.len() <= 64)
            && self
                .date_timezone
                .as_ref()
                .is_none_or(|s| !s.is_empty() && s.len() <= 64)
            && self.target_language.as_ref().is_none_or(|s| {
                !s.is_empty() && s.len() <= 64 && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            });
        if valid {
            Ok(())
        } else {
            Err(CoreError::Invalid {
                field: "extract.content",
                reason: "unsupported version, conflicting lengths, or content policy limit exceeded".into(),
            })
        }
    }
}
/// UTF-8 byte range in normalized selected main or comment text, never raw HTML offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SourceRangeV1 {
    /// Inclusive byte offset.
    pub start: usize,
    /// Exclusive byte offset.
    pub end: usize,
}
impl SourceRangeV1 {
    /// Construct a source range; callers must ensure UTF-8 boundaries.
    #[must_use]
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}
/// Evidence for one selected metadata value, ranked then document ordered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct MetadataEvidenceV1 {
    /// Fixed source key, not a selector supplied by a page.
    pub source: String,
    /// Original value, capped at 4096 Unicode scalars.
    pub raw: String,
    /// Zero-based evidence order within source priority.
    pub order: usize,
}
/// Selected value and retained conflict evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct MetadataValueV1<T> {
    /// Selected normalized value, absent when ambiguous.
    pub value: Option<T>,
    /// Ordered alternatives, at most 32.
    pub evidence: Vec<MetadataEvidenceV1>,
    /// Explicit ambiguity or invalid source data.
    pub uncertain: bool,
    /// Evidence was capped.
    pub truncated: bool,
}
impl<T> Default for MetadataValueV1<T> {
    fn default() -> Self {
        Self {
            value: None,
            evidence: Vec::new(),
            uncertain: false,
            truncated: false,
        }
    }
}
impl<T> MetadataValueV1<T> {
    /// Construct selected evidence without a fabricated confidence probability.
    #[must_use]
    pub fn new(
        value: Option<T>,
        evidence: Vec<MetadataEvidenceV1>,
        uncertain: bool,
        truncated: bool,
    ) -> Self {
        Self {
            value,
            evidence,
            uncertain,
            truncated,
        }
    }
}
impl MetadataEvidenceV1 {
    /// Create bounded evidence; collection owns the aggregate cap.
    #[must_use]
    pub fn new(source: &str, raw: &str, order: usize) -> Self {
        Self {
            source: source.to_owned(),
            raw: raw.chars().take(4096).collect(),
            order,
        }
    }
}
/// A normalized date preserves calendar precision instead of inventing midnight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArticleDateV1 {
    /// ISO calendar date.
    pub date: NaiveDate,
    /// Original timezone-bearing RFC3339 timestamp when known.
    pub timestamp: Option<String>,
}
impl ArticleDateV1 {
    /// Construct a calendar date and optional source timestamp.
    #[must_use]
    pub fn new(date: NaiveDate, timestamp: Option<String>) -> Self {
        Self { date, timestamp }
    }
}
/// Native lexical keyword, distinct from publisher-declared keywords.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct KeywordV1 {
    /// Lowercase token.
    pub token: String,
    /// Integer occurrence score.
    pub score: usize,
    /// First source occurrence.
    pub source: SourceRangeV1,
}
impl KeywordV1 {
    /// Construct a scored source token.
    #[must_use]
    pub fn new(token: String, score: usize, source: SourceRangeV1) -> Self {
        Self { token, score, source }
    }
}
/// Content metadata; retention restrictions apply to all fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ArticleMetadataV1 {
    /// Selected title.
    pub title: MetadataValueV1<String>,
    /// Authors in selected article order, not one collapsed string.
    pub authors: MetadataValueV1<Vec<String>>,
    /// Declared BCP47 language; unknown remains absent.
    pub language: MetadataValueV1<String>,
    /// Language declared by the source before detection.
    pub declared_language: Option<String>,
    /// Detector evidence, absent if not invoked or below thresholds.
    #[serde(default)]
    pub detected_language: MetadataValueV1<String>,
    /// Digest of the detector that produced evidence.
    pub language_model_digest: Option<Digest>,
    /// Whether the requested local detector was unavailable.
    #[serde(default)]
    pub language_model_unavailable: bool,
    /// Selected publication date.
    pub published: MetadataValueV1<ArticleDateV1>,
    /// Separate modification date.
    pub modified: MetadataValueV1<ArticleDateV1>,
    /// Publisher/site evidence.
    pub publisher: MetadataValueV1<String>,
    /// Publisher keywords, not inferred scores.
    pub declared_keywords: Vec<String>,
    /// Native lexical scores.
    pub keywords: Vec<KeywordV1>,
    /// Source-only summary slices in source order; slice main text to render.
    pub summary: Vec<SourceRangeV1>,
    /// Lexical input/unique-token/sentence safety limits omitted some NLP candidates.
    pub nlp_truncated: bool,
    /// Actual tokenizer revision when NLP ran.
    pub tokenizer_version: Option<String>,
    /// Requested tokenizer could not be used.
    #[serde(default)]
    pub tokenizer_unavailable: bool,
}
/// Stage outcome, independent of acquisition success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QualityStatusV1 {
    /// Every configured gate passed.
    Accepted,
    /// A configured content gate failed.
    Rejected,
    /// Output or operation cap prevented complete extraction.
    Partial,
    /// Requested optional capability absent.
    Unavailable,
}
/// Bounded machine-readable quality cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum QualityReasonV1 {
    /// Main content shorter than configured minimum.
    TooShort,
    /// Required metadata absent or ambiguous.
    MissingRequiredMetadata,
    /// A recognized author matched the configured ingestion exclusion.
    AuthorExcluded,
    /// Declared language differs from strict target.
    LanguageMismatch,
    /// No declared language supports strict target.
    LanguageUnknown,
    /// Output, block or operation budget reached.
    ResourceLimit,
    /// Requested licensed optional model not injected.
    ModelUnavailable,
}
/// Quality counts and reasons, safe only after normal retention projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct QualityOutcomeV1 {
    /// Overall state.
    pub status: QualityStatusV1,
    /// At most seven distinct reason codes.
    pub reasons: Vec<QualityReasonV1>,
    /// Accepted main Unicode scalar count.
    pub main_chars: usize,
    /// Number of retained blocks.
    pub blocks: usize,
    /// Charged operations.
    pub operations: usize,
}
impl QualityOutcomeV1 {
    /// Construct a bounded quality result.
    #[must_use]
    pub fn new(
        status: QualityStatusV1,
        reasons: Vec<QualityReasonV1>,
        main_chars: usize,
        blocks: usize,
        operations: usize,
    ) -> Self {
        Self {
            status,
            reasons,
            main_chars,
            blocks,
            operations,
        }
    }
}
/// Stable block source relation in the filtered owned tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ContentBlockV1 {
    /// Preorder element ID in the filtered input tree, before selection.
    pub node_id: usize,
    /// Selected-text range; absent when final privacy projection changed source lineage.
    /// Raw HTML offsets are deliberately not fabricated.
    pub source: Option<SourceRangeV1>,
    /// True for separate comment text, false for main text.
    pub comment: bool,
}
impl ContentBlockV1 {
    /// Construct a stable block relation.
    #[must_use]
    pub const fn new(node_id: usize, source: SourceRangeV1, comment: bool) -> Self {
        Self {
            node_id,
            source: Some(source),
            comment,
        }
    }
}
/// Reference purpose, never an acquisition authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DiscoveryPurposeV1 {
    /// Unverified image reference, no parser download.
    ImageReference,
    /// Explicit next/read-more hyperlink, no parser navigation.
    ReadMoreReference,
}
/// Parser-produced reference, not permission to acquire a target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DiscoveryIntentV1 {
    /// Resolved HTTP(S) target, still subject to worker scope/robots/egress/governor.
    pub url: url::Url,
    /// Fixed purpose: `image_reference` or `read_more_reference`.
    pub purpose: DiscoveryPurposeV1,
}
impl DiscoveryIntentV1 {
    /// Construct an unresolved reference without issuing a request.
    #[must_use]
    pub fn new(url: url::Url, purpose: DiscoveryPurposeV1) -> Self {
        Self { url, purpose }
    }
}

/// Versioned derived document metadata. Content remains on `crawlx_extract::Document`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DocumentEnvelopeV1 {
    /// Schema version.
    pub version: u16,
    /// Existing canonical request digest, attached only by trusted acquisition orchestration.
    pub acquisition_request_digest: Option<Digest>,
    /// Actual retention-approved input resource, absent for caller-supplied HTML.
    pub source_artifact: Option<crate::ArtifactRef>,
    /// Bounded unresolved media/read-more references. Pure extraction never follows them.
    pub discovery: Vec<DiscoveryIntentV1>,
    /// Pinned implementation/normalization ID.
    pub extractor: String,
    /// Effective policy digest.
    pub policy_digest: Digest,
    /// Normalized selected text digest; content-sensitive under privacy policy.
    pub main_digest: Digest,
    /// Strategy chosen; no upstream parity implied.
    pub strategy: String,
    /// Rescue ran exactly zero or one times.
    pub fallback_stages: u8,
    /// Stable source blocks.
    pub blocks: Vec<ContentBlockV1>,
    /// Final normalized privacy projection changed block offsets; unknown mappings are absent.
    pub source_mapping_redacted: bool,
    /// Trusted compiled worker privacy projection ran before derived outputs, if present.
    pub privacy_projection_version: Option<u16>,
    /// Article-specific content metadata.
    pub metadata: ArticleMetadataV1,
    /// Independent content gates.
    pub quality: QualityOutcomeV1,
    /// Optional source-only ranges bound to final `Document.text`, never raw HTML.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks: Option<WordChunkEnvelopeV1>,
}
impl DocumentEnvelopeV1 {
    /// Construct a version-one envelope. No acquisition facts are invented here.
    #[must_use]
    pub fn new(
        policy_digest: Digest,
        main_digest: Digest,
        strategy: String,
        fallback_stages: u8,
        blocks: Vec<ContentBlockV1>,
        metadata: ArticleMetadataV1,
        quality: QualityOutcomeV1,
    ) -> Self {
        Self {
            version: 1,
            extractor: "native_article_v1/unicode_rules_v1".into(),
            policy_digest,
            main_digest,
            strategy,
            fallback_stages,
            blocks,
            metadata,
            quality,
            acquisition_request_digest: None,
            source_artifact: None,
            discovery: Vec::new(),
            source_mapping_redacted: false,
            privacy_projection_version: None,
            chunks: None,
        }
    }
}

/// Approved search-document projection. Every field is content, not safe structural telemetry.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SearchProjectionV1 {
    /// Exactly one.
    pub version: u16,
    /// Stable logical document ID, never an endpoint or authorization token.
    pub document_id: String,
    /// Stable parent ID for extracted children, when present.
    pub parent_id: Option<String>,
    /// Explicit tombstone; no rejected/unchanged acquisition becomes an implicit delete.
    pub deleted: bool,
    /// Pinned extractor/projection version.
    pub extractor_version: String,
    /// Approved flat fields. Delivery cannot reread unrestricted source blobs.
    pub fields: std::collections::BTreeMap<String, serde_json::Value>,
}

impl SearchProjectionV1 {
    /// Build an upsert from an already approved field allowlist.
    #[must_use]
    pub fn new(
        document_id: String,
        extractor_version: String,
        fields: std::collections::BTreeMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            version: 1,
            document_id,
            parent_id: None,
            deleted: false,
            extractor_version,
            fields,
        }
    }

    /// Check version, bounded scalar mappings and immutable logical identity.
    ///
    /// # Errors
    /// Returns a privacy-safe conflict for unsupported/nested/oversized projection input.
    pub fn validate(&self) -> Result<(), crate::StoreError> {
        fn id(value: &str) -> bool {
            !value.is_empty()
                && value.len() <= 512
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/' | b':'))
        }
        fn scalar(value: &serde_json::Value) -> bool {
            !matches!(value, serde_json::Value::Array(_) | serde_json::Value::Object(_))
        }
        if self.version != 1
            || !id(&self.document_id)
            || self.parent_id.as_deref().is_some_and(|value| !id(value))
            || self.fields.len() > 64
            || (self.deleted && !self.fields.is_empty())
            || crate::dataset::validate_identifier(&self.extractor_version).is_err()
            || self.fields.iter().any(|(key, value)| {
                key == "id"
                    || key.starts_with('_')
                    || crate::dataset::validate_identifier(key).is_err()
                    || match value {
                        serde_json::Value::Array(items) => items.len() > 256 || !items.iter().all(scalar),
                        value => !scalar(value),
                    }
            })
        {
            return Err(crate::StoreError::Conflict("invalid search projection".into()));
        }
        struct Count(u64);
        impl std::io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let size =
                    u64::try_from(bytes.len()).map_err(|_| std::io::Error::other("projection byte limit"))?;
                self.0 = self
                    .0
                    .checked_add(size)
                    .filter(|size| *size <= crate::dataset::MAX_VALUE_BYTES)
                    .ok_or_else(|| std::io::Error::other("projection byte limit"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Count(0), self)
            .map_err(|_| crate::StoreError::Conflict("search projection byte limit".into()))?;
        Ok(())
    }
}
