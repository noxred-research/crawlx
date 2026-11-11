//! Opt-in content-output request and response contracts.

use schemars::JsonSchema;
use std::collections::BTreeMap;

/// Discovery scope of links and assets.
#[derive(Default, JsonSchema, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum DiscoveryScope {
    #[default]
    WholePage,
    Selected,
}

/// Source tree used for citation Markdown.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum CitationSource {
    Selected,
    Cleaned,
    Fit,
}

/// Native content renditions, all disabled by default.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ContentOutputOptions {
    /// CSS selectors narrowing selected content, not the original capture.
    #[serde(default)]
    #[schemars(length(max = 64))]
    target_elements: Vec<String>,
    /// Links and assets come from the whole page unless `selected` is requested.
    #[serde(default)]
    discovery_scope: DiscoveryScope,
    /// Return acquired HTML, subject to privacy and retention controls.
    #[serde(default)]
    raw_html: bool,
    /// Return the cleaned whole page before main-content selection.
    #[serde(default)]
    cleaned_html: bool,
    /// Build fit HTML, Markdown and a filter report.
    fit: Option<FitFilter>,
    /// Build Markdown with numbered citations; `fit` requires a fit filter.
    citations: Option<CitationSource>,
    /// Analyze tables in selected content.
    #[serde(default)]
    tables: bool,
    /// Score links/media and optionally request bounded preview intents.
    link_media: Option<LinkMediaOptions>,
}

/// Bounded deterministic fit-content filters.
#[derive(JsonSchema)]
#[serde(tag = "strategy", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum FitFilter {
    Pruning {
        #[serde(rename = "thresholdPermille")]
        #[schemars(range(max = 1000))]
        threshold_permille: Option<u32>,
        #[serde(rename = "minWords")]
        min_words: Option<u32>,
        #[serde(rename = "maxOperations")]
        #[schemars(range(min = 1))]
        max_operations: Option<u64>,
    },
    Bm25 {
        /// Nonempty search query; no network requests are made.
        #[schemars(length(max = 4096))]
        query: String,
        #[serde(rename = "k1Milli")]
        #[schemars(range(max = 10000))]
        k1_milli: Option<u32>,
        #[serde(rename = "bMilli")]
        #[schemars(range(max = 1000))]
        b_milli: Option<u32>,
        #[serde(rename = "thresholdMilli")]
        threshold_milli: Option<u32>,
        #[serde(rename = "minWords")]
        min_words: Option<u32>,
        #[serde(rename = "maxOperations")]
        #[schemars(range(min = 1))]
        max_operations: Option<u64>,
    },
}

/// Preview intent limits; worker scope, robots and egress checks still apply.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct LinkMediaOptions {
    #[serde(default)]
    #[schemars(range(max = 32))]
    max_previews: usize,
    #[serde(default)]
    min_preview_score: u32,
}

/// Requested outputs only. No field grants permission to retain source content.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContentOutputs {
    discovery_scope: DiscoveryScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cleaned_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fit_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fit_markdown: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fit: Option<FitReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    markdown_with_citations: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    citations: Vec<CitationEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tables: Option<TableExtraction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    link_media: Option<LinkMediaReport>,
    /// Fulfilled head previews or explicit worker refusal reports.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    previews: Vec<PreviewResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decode: Option<DecodeReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    markup: Option<MarkupRecord>,
    /// Privacy projection withheld derived markup.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    withheld: bool,
}

/// Counts and operations spent by one fit filter.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct FitReport {
    strategy: String,
    kept_blocks: usize,
    dropped_blocks: usize,
    operations: u64,
}

/// One numbered citation and its link-list provenance.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CitationEntry {
    index: usize,
    url: String,
    text: String,
    link_index: Option<usize>,
}

/// Table analysis and normalized cells.
#[derive(JsonSchema)]
pub(super) struct TableExtraction {
    rules: String,
    tables: Vec<ExtractedTable>,
    truncated: bool,
}

/// Data, layout or ambiguous table.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum TableKind {
    Data,
    Layout,
    Ambiguous,
}

/// One table in document order.
#[derive(JsonSchema)]
pub(super) struct ExtractedTable {
    index: usize,
    depth: usize,
    parent: Option<usize>,
    kind: TableKind,
    /// Counts and deterministic permille scoring components.
    score: TableScore,
    caption: Option<String>,
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

/// Scored links/media with bounded preview intents.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct LinkMediaReport {
    schema: String,
    links: Vec<ScoredLink>,
    images: Vec<ScoredMedia>,
    media: Vec<ScoredMedia>,
    previews: Vec<PreviewIntent>,
    refused_previews: Vec<RefusedPreview>,
    truncated: bool,
}

/// Link relation to the source page.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum LinkClass {
    Internal,
    Subdomain,
    External,
}

/// One scored link and its retained link-list index.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ScoredLink {
    link_index: usize,
    url: String,
    class: LinkClass,
    occurrences: usize,
    intrinsic: IntrinsicLinkScore,
    contextual: ContextualLinkScore,
    combined: u32,
}

/// Media element kind.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum MediaKind {
    Image,
    Audio,
    Video,
}

/// One scored media reference.
#[derive(JsonSchema)]
pub(super) struct ScoredMedia {
    url: String,
    kind: MediaKind,
    occurrences: usize,
    intrinsic: IntrinsicMediaScore,
    contextual: ContextualMediaScore,
    combined: u32,
}

/// Worker-owned bounded head preview intent, not acquisition authorization.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PreviewIntent {
    url: String,
    purpose: PreviewPurpose,
    max_head_bytes: u32,
}

/// Preview purpose vocabulary.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreviewPurpose {
    HeadMetadata,
}

/// Target refused before any preview fetch.
#[derive(JsonSchema)]
pub(super) struct RefusedPreview {
    url: String,
    reason: PreviewRefusal,
}

/// Preview target refusal vocabulary.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreviewRefusal {
    Scheme,
    Credentials,
    MissingHost,
    LocalName,
    PrivateAddress,
    Budget,
}

/// Optional byte decoder diagnostics selection.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DecodeOptions {
    declared_charset: Option<String>,
}

/// Opt-in comment and CDATA diagnostic view.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct MarkupRetention {
    #[serde(default)]
    comments: bool,
    #[serde(default)]
    cdata: bool,
}

/// Worker preview result, never a permission to bypass acquisition policy.
#[derive(JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum PreviewResult {
    Fulfilled { head: HeadProjection },
    Unavailable { reason: String },
}

/// Public head metadata projected from bounded acquired preview bytes.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct HeadProjection {
    url: String,
    title: Option<String>,
    description: Option<String>,
    language: Option<String>,
    canonical_url: Option<String>,
    image_url: Option<String>,
    site_name: Option<String>,
    noindex: bool,
    nofollow: bool,
    truncated: bool,
    open_graph: BTreeMap<String, String>,
}

/// Source of the chosen character encoding.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum EncodingSource {
    Bom,
    Declared,
    Meta,
    Default,
}

/// One malformed byte sequence replaced during decoding.
#[derive(JsonSchema)]
pub(super) struct DecodeIssue {
    offset: usize,
    length: usize,
}

/// Bounded byte-decoder diagnostics.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct DecodeReport {
    encoding: String,
    source: EncodingSource,
    bom_len: usize,
    issues: Vec<DecodeIssue>,
    issue_count: usize,
    issues_truncated: bool,
    unknown_label: Option<String>,
    declaration_conflict: bool,
}

/// Retention-controlled comments and CDATA, distinct from cleaned main text.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct MarkupRecord {
    comments: Vec<String>,
    cdata: Vec<String>,
    truncated: bool,
    source_digest: String,
}

/// Table shape and deterministic permille score components.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct TableScore {
    rows: usize,
    columns: usize,
    header_rows: usize,
    nested_tables: usize,
    link_density: u32,
    shape: u32,
    consistency: u32,
    header: u32,
    link: u32,
    structure: u32,
    fill: u32,
    brevity: u32,
    total: u32,
}

/// Link-only score components.
#[derive(JsonSchema)]
pub(super) struct IntrinsicLinkScore {
    text: u32,
    url: u32,
    rel: u32,
    total: u32,
}

/// Link placement score components.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ContextualLinkScore {
    region: u32,
    container_density: u32,
    position: u32,
    heading: u32,
    total: u32,
}

/// Media-only score components.
#[derive(JsonSchema)]
pub(super) struct IntrinsicMediaScore {
    description: u32,
    dimensions: u32,
    format: u32,
    total: u32,
}

/// Media placement score components.
#[derive(JsonSchema)]
pub(super) struct ContextualMediaScore {
    region: u32,
    figure: u32,
    position: u32,
    total: u32,
}
