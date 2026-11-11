//! Output and option types of the extractor (`output.formats`, `onlyMainContent`,
//! `includeTags`, `excludeTags`; `extract.*`).

use std::collections::BTreeMap;

use crawlx_core::config::PageType;
use crawlx_core::hash::Digest;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::custom_fields::CustomField;
use crate::endpoints::DiscoveredEndpoint;
use crate::forms::StaticForm;
use crate::metadata::Metadata;
use crate::technologies::Technology;

/// Default cap on input size: 16 MiB.
pub const DEFAULT_MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Default cap on parsed DOM nodes.
pub const DEFAULT_MAX_NODES: usize = 1_000_000;

/// Extraction options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractOptions {
    /// Restrict output to the main content block (`onlyMainContent`).
    /// Ignored when `include_tags` is non-empty.
    pub only_main_content: bool,
    /// CSS selectors (plain tag names are selectors too). When non-empty the
    /// output is built from the outermost matching elements, in document order.
    pub include_tags: Vec<String>,
    /// CSS selectors whose matches are removed with their subtree. Applied
    /// before `include_tags`.
    pub exclude_tags: Vec<String>,
    /// Inputs larger than this many bytes fail with `ExtractError::TooLarge`.
    pub max_input_bytes: usize,
    /// Documents with more parsed nodes than this fail with `ExtractError::TooLarge`.
    pub max_nodes: usize,
    /// HTTP status of the response the document came from (default 200);
    /// feeds the page-type classifier.
    pub status: u16,
    /// Response headers `(name, value)`; feed endpoint discovery, custom
    /// fields, technologies and the page-type classifier.
    pub headers: Vec<(String, String)>,
    /// Declared `Content-Type` of the response (textual guard of endpoint discovery).
    pub content_type: Option<String>,
    /// Crawl depth of the page; discovered endpoints are one deeper.
    pub depth: u32,
    /// Run the surface-discovery endpoint extractor (`Document::discovered_endpoints`).
    pub discover_endpoints: bool,
    /// JavaScript miners used when endpoint discovery is enabled.
    pub javascript_mode: crawlx_core::config::JavascriptMode,
    /// Compiled `extract.customFields[]`; evaluated when non-empty.
    pub custom_fields: Vec<CustomField>,
    /// Extract static forms (`extract.forms`, default true).
    pub forms: bool,
    /// Classify the page type (`extract.pageType`, default true).
    pub page_type: bool,
    /// Detect technologies from headers and markup (default true).
    pub technologies: bool,
    /// Keep `data:image/...` sources of `<img>` in the cleaned HTML and the Markdown (default
    /// false: such images are dropped). Used when the compatibility API `removeBase64Images` is off; the
    /// URIs stay verbatim and [`crate::base64_images::strip_base64_images`] removes them again.
    pub keep_data_images: bool,
    /// Opt-in native article selection and quality policy; absent preserves legacy behavior.
    pub content: Option<crawlx_core::extraction::ExtractionPolicyV1>,
    /// Explicit transport facts for validation against the same parsed DOM.
    pub acquisition_validation: Option<crawlx_core::acquisition::ValidationContextV1>,
    /// Collect image URL format references on the shared parse when requested.
    pub image_references: bool,
    /// Attribute format requests evaluated on the shared parse.
    pub attribute_selectors: Vec<crawlx_core::scrape::AttributeSelector>,
    /// Existing pure PII guard applied before native article NLP and source digests.
    pub content_redaction: Option<crate::parse::redact::RedactOptions>,
    /// Trusted transient local language service; never serialized as request configuration.
    pub language_detector: Option<crawlx_core::article_language::ArticleLanguageHandle>,
    /// Caller-scoped dedupe cache for block and content dedupe; never serialized request
    /// configuration. Without it dedupe compares only within the document.
    pub dedupe_cache: Option<crate::dedupe::DedupeHandle>,
    /// Opt-in content outputs (variants, fit content, citations, tables, link/media scores,
    /// target elements and discovery scope); absent keeps the legacy output.
    pub outputs: Option<crate::content_outputs::ContentOutputOptions>,
    /// Decode input bytes with diagnostics (byte-order mark, declared charset, `meta`) in
    /// [`Extractor::extract_bytes`](crate::Extractor::extract_bytes); absent keeps lossy UTF-8.
    pub decode: Option<crate::decode::DecodeOptions>,
    /// Keep comments and/or CDATA payloads from the source in [`Document::markup`]; absent
    /// keeps nothing and leaves the document unchanged.
    pub markup: Option<crate::decode::MarkupRetention>,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            only_main_content: true,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_nodes: DEFAULT_MAX_NODES,
            status: 200,
            headers: Vec::new(),
            content_type: None,
            depth: 0,
            discover_endpoints: false,
            javascript_mode: crate::endpoints::DiscoveryOptions::default().javascript_mode,
            custom_fields: Vec::new(),
            forms: true,
            page_type: true,
            technologies: true,
            keep_data_images: false,
            content: None,
            acquisition_validation: None,
            image_references: false,
            attribute_selectors: Vec::new(),
            content_redaction: None,
            language_detector: None,
            dedupe_cache: None,
            outputs: None,
            decode: None,
            markup: None,
        }
    }
}

/// A hyperlink found in the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedLink {
    /// Absolute `http(s)` URL without fragment.
    pub url: Url,
    /// Anchor text (whitespace collapsed), falling back to image `alt`,
    /// `title` or `aria-label`.
    pub text: String,
    /// Lower-case `rel` tokens.
    pub rel: Vec<String>,
    /// `rel` contains `nofollow` on every occurrence of this URL.
    pub nofollow: bool,
    /// Same host as the page URL.
    pub internal: bool,
}

/// Result of extracting one HTML document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Document {
    /// Title: `og:title`, then `<title>`, then first `<h1>`.
    pub title: Option<String>,
    /// Meta description (`description`, `og:description`, `twitter:description`).
    pub description: Option<String>,
    /// Document language (`<html lang>`, `Content-Language` meta, `og:locale`).
    pub language: Option<String>,
    /// Canonical URL (`link rel=canonical`, then `og:url`), absolute.
    pub canonical_url: Option<Url>,
    /// Base URL used to resolve relative references (`<base href>` aware).
    pub base_url: Url,
    /// Markdown of the selected content.
    pub markdown: String,
    /// Plain text of the selected content.
    pub text: String,
    /// Cleaned HTML of the selected content.
    pub html: String,
    /// BLAKE3 digest of the raw input bytes under the domain `crawlx.extract.raw_html.v1`.
    pub raw_html_digest: Digest,
    /// Structured metadata.
    pub metadata: Metadata,
    /// Links of the whole document (not only the selected content).
    pub links: Vec<ExtractedLink>,
    /// Asset URLs of the whole document.
    pub assets: Vec<Url>,
    /// Legacy whitespace words, or version-one Unicode lexical units under native content policy.
    pub word_count: usize,
    /// Static forms of the whole document (`extract.forms`).
    #[serde(default)]
    pub forms: Vec<StaticForm>,
    /// Deterministic page classification (`extract.pageType`).
    #[serde(default)]
    pub page_type: Option<PageType>,
    /// Technologies detected from headers and markup.
    #[serde(default)]
    pub technologies: Vec<Technology>,
    /// Custom regex field values, by field name (`extract.customFields`).
    #[serde(default)]
    pub custom_fields: BTreeMap<String, Vec<String>>,
    /// Typed declarative custom-field projection, evaluated on the original shared DOM.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<crawlx_core::selectors::ItemOutcomeV1>,
    /// Surface-discovery endpoints (`ExtractOptions::discover_endpoints`).
    #[serde(default)]
    pub discovered_endpoints: Vec<DiscoveredEndpoint>,
    /// Versioned article metadata. Content/PII, never unrestricted structural telemetry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub article: Option<crawlx_core::extraction::DocumentEnvelopeV1>,
    /// Separately selected reader comments, never silently merged into main text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comments: String,
    /// Acquisition validity remains separate from article quality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<crawlx_core::acquisition::ValidationOutcomeV1>,
    /// Requested image-format references from the original parsed tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_urls: Option<Vec<String>>,
    /// Requested attribute-format values from the original parsed tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<crawlx_core::scrape::AttributeResult>>,
    /// Requested content outputs; present only when [`ExtractOptions::outputs`] was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<crate::content_outputs::ContentOutputs>,
    /// How the input bytes were decoded; present only when [`ExtractOptions::decode`] was set
    /// and the document came from bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode: Option<crate::decode::DecodeReport>,
    /// Comments and CDATA payloads kept from the source; present only when
    /// [`ExtractOptions::markup`] was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markup: Option<crate::decode::MarkupRecord>,
}
