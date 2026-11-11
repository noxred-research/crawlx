//! The scrape request model behind the compatibility API: per-page options, the
//! `formats[]` vocabulary, caller-specified browser `actions[]`, and the job description that
//! turns a crawl run into a crawl, a batch scrape or a single scrape.
//!
//! The types are transport only: the API parses the compatibility API's wire JSON into them (with
//! its error shapes), the worker's scrape engine executes them. Field names on the wire
//! of *this* model are camelCase, like every other `crawlx-core` request type.

use crate::hash::Digest;
use crate::page_op::SelectorState;
use crate::parser_memory::AdmittedText;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Most `actions[]` a request may carry (compatibility API limit).
pub const MAX_ACTIONS: usize = 50;
/// Longest `waitFor` / `wait` action in milliseconds (compatibility API limit).
pub const MAX_WAIT_MS: u32 = 60_000;
/// Default `timeout` in milliseconds (compatibility API default).
pub const DEFAULT_TIMEOUT_MS: u32 = 60_000;
/// Default `maxAge` in milliseconds: two days (compatibility API default).
pub const DEFAULT_MAX_AGE_MS: u64 = 172_800_000;
/// Viewport of `mobile: true` (390x844) in CSS pixels.
pub const MOBILE_VIEWPORT: ScreenshotViewport = ScreenshotViewport {
    width: 390,
    height: 844,
};
/// `User-Agent` sent by `mobile: true`.
pub const MOBILE_USER_AGENT: &str = concat!(
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) ", // wire-compat: user-agent product token
    "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
);

fn t() -> bool {
    true
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Viewport in CSS pixels (screenshot `viewport`, `mobile`).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ScreenshotViewport {
    /// Width in CSS pixels.
    pub width: u32,
    /// Height in CSS pixels.
    pub height: u32,
}

/// `location{country, languages, geolocation}`: Accept-Language plus the browser's locale,
/// time zone and, when asked, the position `navigator.geolocation` reports.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct Location {
    /// ISO 3166-1 alpha-2 country code (upper case), e.g. `DE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Preferred languages (BCP 47), most preferred first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<String>,
    /// Position the page's `navigator.geolocation` reports for the whole browser context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geolocation: Option<crate::page_op::GeoPosition>,
}

/// `attributes` format: attribute values of the elements a selector matches.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttributeSelector {
    /// CSS selector.
    pub selector: String,
    /// Attribute whose value is returned for every match.
    pub attribute: String,
}

/// `changeTracking.modes[]`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeMode {
    /// A git-style unified text diff of the markdown.
    GitDiff,
    /// A structured per-field diff of the `json` extraction.
    Json,
}

/// `query` format `mode` (`freeform` default, or `directQuote`).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub enum QueryMode {
    /// A free-form answer in the model's own words.
    #[default]
    Freeform,
    /// An answer made only of verbatim quotes of the page.
    DirectQuote,
}

/// `redactPII.mode`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum PiiMode {
    /// The compatibility API's default.
    #[default]
    Accurate,
    /// Also treats bare 10-15 digit runs as phone numbers.
    Aggressive,
    /// Patterns only.
    Fast,
}

/// `redactPII.replaceStyle`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum PiiReplaceStyle {
    /// `<EMAIL>`-style placeholders (default).
    #[default]
    Tag,
    /// `*` for every character.
    Mask,
    /// The span text is deleted.
    Remove,
}

/// `redactPII.entities[]`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub enum PiiEntity {
    /// Personal names (needs a named-entity model).
    Person,
    /// E-mail addresses.
    Email,
    /// Phone numbers.
    Phone,
    /// Places (needs a named-entity model).
    Location,
    /// Payment card numbers and IBANs.
    Financial,
    /// API keys, tokens and private keys.
    Secret,
}

/// `redactPII` as an options object (`true` is the default of every field).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct RedactPii {
    /// Redaction strategy.
    #[serde(default)]
    pub mode: PiiMode,
    /// Entities to redact; empty means every supported entity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entities: Vec<PiiEntity>,
    /// How a match is replaced.
    #[serde(default)]
    pub replace_style: PiiReplaceStyle,
}

/// One entry of `formats[]`.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum FormatSpec {
    /// Markdown of the selected content.
    Markdown,
    /// Cleaned HTML of the selected content.
    Html,
    /// The response body verbatim (browser plane: the serialized DOM).
    RawHtml,
    /// Absolute link URLs of the page.
    Links,
    /// Absolute image URLs of the page.
    Images,
    /// The response body, base64 encoded (must be the only format).
    RawBase64,
    /// Brand identity (colors, fonts, logo, icons) from CSS and head metadata.
    Branding,
    /// Screenshot (needs the browser plane).
    #[serde(rename_all = "camelCase")]
    Screenshot {
        /// Capture the whole page instead of the viewport.
        #[serde(default)]
        full_page: bool,
        /// JPEG quality 1..=100; absent means PNG.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quality: Option<u8>,
        /// Viewport override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        viewport: Option<ScreenshotViewport>,
    },
    /// Attribute values by selector.
    Attributes {
        /// Selector and attribute pairs.
        selectors: Vec<AttributeSelector>,
    },
    /// Structured extraction through the configured LLM.
    Json {
        /// JSON schema the answer must follow.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<serde_json::Value>,
        /// Extraction instruction.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
    },
    /// A short summary through the configured LLM.
    Summary,
    /// An answer to `question` through the configured LLM.
    Question {
        /// The question.
        question: String,
    },
    /// Passages relevant to `query` through the configured LLM.
    Highlights {
        /// The query.
        query: String,
    },
    /// A free-form prompt over the page through the configured LLM (the compatibility API's deprecated
    /// `query`; its answer is returned in `answer`).
    Query {
        /// The prompt.
        prompt: String,
        /// Free-form answer or verbatim quotes.
        #[serde(default)]
        mode: QueryMode,
    },
    /// The audio track of the media the page is or references, stored as an artifact (compatibility API
    /// `audio`: a signed URL; the transcript when the LLM endpoint transcribes).
    Audio,
    /// The video of the media the page is or references, stored as an artifact.
    Video,
    /// Diff against the previous stored scrape of the same URL and tag.
    #[serde(rename_all = "camelCase")]
    ChangeTracking {
        /// Diff modes; empty means `git-diff` only.
        #[serde(default)]
        modes: Vec<ChangeMode>,
        /// Schema of the `json` mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        schema: Option<serde_json::Value>,
        /// Prompt of the `json` mode.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prompt: Option<String>,
        /// Tag separating independent histories of one URL.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tag: Option<String>,
    },
}

impl FormatSpec {
    /// The compatibility API name of the format (the `type` of its object form).
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Markdown => "markdown",
            Self::Html => "html",
            Self::RawHtml => "rawHtml",
            Self::Links => "links",
            Self::Images => "images",
            Self::RawBase64 => "rawBase64",
            Self::Branding => "branding",
            Self::Screenshot { .. } => "screenshot",
            Self::Attributes { .. } => "attributes",
            Self::Json { .. } => "json",
            Self::Summary => "summary",
            Self::Question { .. } => "question",
            Self::Highlights { .. } => "highlights",
            Self::Query { .. } => "query",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::ChangeTracking { .. } => "changeTracking",
        }
    }

    /// Does the format need the configured LLM?
    #[must_use]
    pub const fn needs_llm(&self) -> bool {
        matches!(
            self,
            Self::Json { .. }
                | Self::Summary
                | Self::Question { .. }
                | Self::Highlights { .. }
                | Self::Query { .. }
        )
    }
}

/// `parsers[].mode` of the PDF parser.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum PdfMode {
    /// Text-layer extraction only.
    Fast,
    /// Text-layer extraction first, OCR for pages without text (default).
    #[default]
    Auto,
    /// OCR on every page. crawlx has no OCR engine: the text layer is extracted and the document
    /// carries an `ocr_unavailable` warning.
    Ocr,
}

/// `parsers[]` entry (compatibility API v2 `ScrapeOptions.parsers`). The list as a whole decides which
/// file types are parsed: an absent `parsers` means `[pdf, image]`, a listed parser is on, an
/// unlisted one is off, and an empty list returns a PDF unparsed as base64.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ParserSpec {
    /// PDF text extraction.
    #[serde(rename_all = "camelCase")]
    Pdf {
        /// Parsing mode.
        #[serde(default)]
        mode: PdfMode,
        /// Stop after this many pages (1..=10 000).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_pages: Option<u32>,
        /// Also return the markdown of every physical page (`pages`).
        #[serde(default, skip_serializing_if = "is_false")]
        pages: bool,
        /// Also return typed layout blocks per page (`blocks`).
        #[serde(default, skip_serializing_if = "is_false")]
        blocks: bool,
        /// Join pages with `\n\n---\n\n<!-- page N -->\n\n`.
        #[serde(default, skip_serializing_if = "is_false")]
        page_markers: bool,
    },
    /// Raster image OCR. It has no options; crawlx has no OCR engine, so an image answers with
    /// an empty markdown and an `ocr_unavailable` warning.
    Image,
}

impl ParserSpec {
    /// The PDF parser with default options (`"pdf"` shorthand).
    #[must_use]
    pub const fn pdf() -> Self {
        Self::Pdf {
            mode: PdfMode::Auto,
            max_pages: None,
            pages: false,
            blocks: false,
            page_markers: false,
        }
    }
}

/// One physical PDF page of the `pages` parser option.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PdfPageMarkdown {
    /// 1-based physical page number.
    pub page_number: u32,
    /// Markdown of the page.
    pub markdown: String,
}

/// Scroll direction of the `scroll` action.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ScrollDirection {
    /// Towards the top.
    Up,
    /// Towards the bottom.
    Down,
}

/// One entry of `actions[]`, executed in order on the browser plane.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScrapeAction {
    /// Wait a fixed time or for the first CSS match to reach a selector state.
    Wait {
        /// Milliseconds to wait (exclusive with `selector`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        milliseconds: Option<u32>,
        /// Selector to wait for (exclusive with `milliseconds`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
        /// Desired first-match state; omission preserves attachment-only waiting.
        /// Nondefault states require `selector`. See [`SelectorState`] for visibility.
        #[serde(default)]
        state: SelectorState,
    },
    /// Take a screenshot at this point.
    #[serde(rename_all = "camelCase")]
    Screenshot {
        /// Capture the whole page.
        #[serde(default)]
        full_page: bool,
        /// JPEG quality 1..=100; absent means PNG.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        quality: Option<u8>,
        /// Viewport override.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        viewport: Option<ScreenshotViewport>,
    },
    /// Click the first (or, with `all`, every) element matching `selector`.
    Click {
        /// CSS selector.
        selector: String,
        /// Click every match instead of the first.
        #[serde(default)]
        all: bool,
    },
    /// Type `text` into the focused element.
    Write {
        /// Text to enter.
        text: String,
    },
    /// Replace text in a freshly resolved target through governed native input.
    Fill {
        /// CSS selector resolved again immediately before input.
        selector: String,
        /// Replacement value; never included in recipe dispositions.
        text: String,
    },
    /// Press one key (e.g. `Enter`).
    Press {
        /// Key name.
        key: String,
    },
    /// Scroll the page or the element `selector` matches.
    Scroll {
        /// Direction.
        direction: ScrollDirection,
        /// Element to scroll; the page when absent.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
    },
    /// Capture the HTML at this point (`actions.scrapes[]`).
    Scrape,
    /// Collect diagnostic text rows from one virtualized container.
    CollectVirtualRows {
        /// Explicit selectors and hard collection limits.
        spec: crate::dom_ops::VirtualRowsSpec,
    },
    /// Run a script in the page; its JSON result lands in `actions.javascriptReturns[]`.
    ExecuteJavascript {
        /// Script source.
        script: String,
    },
    /// Print the page to PDF (`actions.pdfs[]`).
    Pdf {
        /// Paper format (`A4`, `Letter`, ...); default `Letter`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        format: Option<String>,
        /// Landscape orientation.
        #[serde(default)]
        landscape: bool,
        /// Scale factor 0.1..=2.0 (default 1).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scale: Option<f32>,
    },
}

impl ScrapeAction {
    /// The compatibility API `type` of the action.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Wait { .. } => "wait",
            Self::Screenshot { .. } => "screenshot",
            Self::Click { .. } => "click",
            Self::Write { .. } => "write",
            Self::Fill { .. } => "fill",
            Self::Press { .. } => "press",
            Self::Scroll { .. } => "scroll",
            Self::Scrape => "scrape",
            Self::CollectVirtualRows { .. } => "collectVirtualRows",
            Self::ExecuteJavascript { .. } => "executeJavascript",
            Self::Pdf { .. } => "pdf",
        }
    }
}

/// Deployment proxy tier requested by a compatibility-API scrape.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProxyMode {
    /// Use the basic deployment route, or the existing request proxy.
    #[default]
    Basic,
    /// Use the enhanced deployment route; fail when it is not configured.
    #[serde(alias = "stealth")]
    Enhanced,
    /// Try basic first, then enhanced once for HTTP 401, 403 or 429.
    Auto,
}

impl ProxyMode {
    /// Whether an HTTP status permits the single automatic enhanced attempt.
    #[must_use]
    pub const fn escalates(self, status: u16) -> bool {
        matches!(self, Self::Auto) && matches!(status, 401 | 403 | 429)
    }
}

/// Largest provider output-token ceiling a [`ContentStrategySpecV1::ModelV1`] request may name.
pub const MAX_CONTENT_STRATEGY_OUTPUT_TOKENS: u32 = 65_536;
/// Largest decoded provider response a [`ContentStrategySpecV1::ModelV1`] request may name.
pub const MAX_CONTENT_STRATEGY_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Opt-in, versioned content strategy of one scrape. Absence means [`Self::NativeV1`]: the
/// deterministic native parser, with no model provider involved.
///
/// `ModelV1` is authenticated, immutable request configuration. Page content can never widen
/// it, and generated output never becomes a navigation or action authority.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "strategy",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum ContentStrategySpecV1 {
    /// The existing native parser and table handling.
    #[default]
    NativeV1,
    /// One bounded model call over the composed markdown; no retry, mirror or native fallback.
    ModelV1 {
        /// The requested content operation.
        target: ContentStrategyTargetV1,
        /// Provider completion-token ceiling (1..=65 536).
        max_output_tokens: u32,
        /// Decoded provider response-byte ceiling (1..=8 388 608).
        max_response_bytes: usize,
        /// Explicit consent to external model processing of the page content; must be `true`.
        external_processing_consent: bool,
    },
}

/// The operation a [`ContentStrategySpecV1::ModelV1`] strategy performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ContentStrategyTargetV1 {
    /// Normalize tables only; the markdown stays native.
    Tables,
    /// Replace the markdown with model-selected page content.
    Content,
    /// Do both: model-selected content and normalized tables.
    TablesAndContent,
}

/// Per-page scrape options (compatibility API `ScrapeOptions`).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScrapeOptions {
    /// Requested deployment proxy tier; retained for scrape, batch and crawl jobs.
    #[serde(default)]
    pub proxy: ProxyMode,
    /// Requested formats; the default is `markdown`.
    #[serde(default = "ScrapeOptions::default_formats")]
    pub formats: Vec<FormatSpec>,
    /// Keep only the main content (default true).
    #[serde(default = "t")]
    pub only_main_content: bool,
    /// Native opt-in article extraction extension. Absent preserves facade behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_policy: Option<crate::extraction::ExtractionPolicyV1>,
    /// Opt-in native content outputs, validated by the extraction boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<serde_json::Value>,
    /// Opt-in byte decoding diagnostics, validated by the extraction boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decode: Option<serde_json::Value>,
    /// Opt-in comment and CDATA handling, validated by the extraction boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markup: Option<serde_json::Value>,
    /// CSS selectors whose elements are kept.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include_tags: Vec<String>,
    /// CSS selectors whose elements are dropped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_tags: Vec<String>,
    /// Serve a stored scrape younger than this many milliseconds (default two days; 0 disables).
    #[serde(default = "ScrapeOptions::default_max_age_ms")]
    pub max_age_ms: u64,
    /// Serve only a stored scrape at least this old and never fetch (`404 SCRAPE_NO_CACHED_DATA`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_age_ms: Option<u64>,
    /// Explicit native cache behavior; absent preserves facade controls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<crate::cache::CachePolicyV1>,
    /// Server-assigned API-key principal. Admission overwrites caller-supplied values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_principal: Option<uuid::Uuid>,
    /// Server-derived keyed identity of resolved headers/cookies; never caller authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_header_identity: Option<Digest>,
    /// Server-derived extraction pipeline and route identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_execution_context: Option<Digest>,
    /// Extra request headers on both planes.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Milliseconds to wait after load before extracting (needs the browser plane).
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub wait_for_ms: u32,
    /// Emulate a phone: 390x844 viewport and a mobile `User-Agent`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub mobile: bool,
    /// Whole-scrape timeout in milliseconds (1 000..=300 000; default 60 000).
    #[serde(default = "ScrapeOptions::default_timeout_ms")]
    pub timeout_ms: u32,
    /// Parsers for non-HTML bodies.
    #[serde(default = "ScrapeOptions::default_parsers")]
    pub parsers: Vec<ParserSpec>,
    /// Browser actions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ScrapeAction>,
    /// Immutable operator-approved recipe selection; never accepts recipe contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_behavior: Option<crate::archive_behaviors::RecipeReferenceV1>,
    /// Locale emulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    /// Strip `data:image` URIs from markdown and HTML (default true).
    #[serde(default = "t")]
    pub remove_base64_images: bool,
    /// Block ad and analytics hosts (default true).
    #[serde(default = "t")]
    pub block_ads: bool,
    /// Keep the result as a stored scrape that `maxAge` and `changeTracking` can reuse (default true).
    #[serde(default = "t")]
    pub store_in_cache: bool,
    /// Serve from the stored scrapes only; a miss answers `404 SCRAPE_LOCKDOWN_CACHE_MISS`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub lockdown: bool,
    /// Accept invalid TLS certificates on the HTTP plane (default false: crawlx verifies).
    #[serde(default, skip_serializing_if = "is_false")]
    pub skip_tls_verification: bool,
    /// Run an LLM cleanup pass over the markdown to remove residual boilerplate
    /// (compatibility API `onlyCleanContent`, beta). Skipped with a document `warning` when no LLM is
    /// configured or the markdown is too long for one pass.
    #[serde(default, skip_serializing_if = "is_false")]
    pub only_clean_content: bool,
    /// Scan the markdown for prompt-injection attempts before any LLM-backed format runs; a hit
    /// fails the page as `prompt_injection_detected` (compatibility API `checkPromptInjection`, +4 credits).
    #[serde(default, skip_serializing_if = "is_false")]
    pub check_prompt_injection: bool,
    /// Compatibility API `profile{name,saveChanges}`: render in a named persistent browser profile
    /// (cookies and local storage persist across scrapes). Forces the browser leg; the run
    /// carries it as `dynamic.browserProfile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<crate::config::BrowserProfile>,
    /// Redact personal data from the returned markdown, html and rawHtml (compatibility API `redactPII`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redact_pii: Option<RedactPii>,
    /// Opt-in versioned content strategy. `None` and `nativeV1` keep the native parser untouched;
    /// `modelV1` needs explicit consent, never combines with `onlyCleanContent`, and is refused on
    /// zero-data-retention runs before any model I/O.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_strategy: Option<ContentStrategySpecV1>,
    /// Device pixel ratio of the browser page in thousandths (`2000` is 2x); forces the browser
    /// leg. Absent keeps ratio 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_scale_milli: Option<u32>,
    /// Native opt-in: block resource types and hosts besides `blockAds` in the browser leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_blocking: Option<ResourceBlocking>,
    /// Native opt-in: fold open shadow roots and readable iframes into the browser leg's
    /// serialized DOM, with per-frame origin provenance; forces the browser leg.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flatten: Option<crate::page_op::FlattenSpec>,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

impl ScrapeOptions {
    fn default_formats() -> Vec<FormatSpec> {
        vec![FormatSpec::Markdown]
    }

    const fn default_max_age_ms() -> u64 {
        DEFAULT_MAX_AGE_MS
    }

    const fn default_timeout_ms() -> u32 {
        DEFAULT_TIMEOUT_MS
    }

    /// The compatibility API's default `parsers`: `[pdf, image]`. An absent `parsers` key means this; an
    /// explicit empty list is kept (it returns PDFs as base64).
    fn default_parsers() -> Vec<ParserSpec> {
        vec![ParserSpec::pdf(), ParserSpec::Image]
    }

    /// Does any option need a rendering browser (`waitFor`, `actions`, `screenshot`, `mobile`)?
    #[must_use]
    pub fn needs_browser(&self) -> bool {
        self.wait_for_ms > 0
            || self.mobile
            || self.profile.is_some()
            || self.device_scale_milli.is_some()
            || self.location.as_ref().is_some_and(|l| l.geolocation.is_some())
            || self.flatten.is_some()
            || self.archive_behavior.is_some()
            || !self.actions.is_empty()
            || self
                .formats
                .iter()
                .any(|f| matches!(f, FormatSpec::Screenshot { .. }))
    }

    /// The first requested format named `name`.
    #[must_use]
    pub fn format(&self, name: &str) -> Option<&FormatSpec> {
        self.formats.iter().find(|f| f.name() == name)
    }

    /// Is format `name` requested?
    #[must_use]
    pub fn wants(&self, name: &str) -> bool {
        self.format(name).is_some()
    }

    /// Secret-free document-shaping digest used inside [`crate::cache::CacheKeyV1`].
    /// Cache controls and timeout do not shape bytes. Raw header values are replaced by a
    /// marker; reusable credential identity requires the separately server-derived keyed field.
    #[must_use]
    pub fn cache_digest(&self) -> Digest {
        let mut shaped = self.clone();
        shaped.max_age_ms = 0;
        shaped.min_age_ms = None;
        shaped.cache = None;
        // `nativeV1` and omission describe the same native answer.
        if matches!(shaped.content_strategy, Some(ContentStrategySpecV1::NativeV1)) {
            shaped.content_strategy = None;
        }
        shaped.store_in_cache = true;
        shaped.lockdown = false;
        shaped.timeout_ms = DEFAULT_TIMEOUT_MS;
        for value in shaped.headers.values_mut() {
            *value = "[credential-bearing-cache-requires-key]".to_owned();
        }
        let bytes = serde_json::to_vec(&shaped).unwrap_or_default();
        Digest::of("crawlx/scrape-options/v1", &bytes)
    }
}

impl Default for ScrapeOptions {
    fn default() -> Self {
        Self {
            proxy: ProxyMode::Basic,
            formats: Self::default_formats(),
            only_main_content: true,
            content_policy: None,
            outputs: None,
            decode: None,
            markup: None,
            include_tags: Vec::new(),
            exclude_tags: Vec::new(),
            max_age_ms: DEFAULT_MAX_AGE_MS,
            min_age_ms: None,
            cache: None,
            cache_principal: None,
            cache_header_identity: None,
            cache_execution_context: None,
            headers: BTreeMap::new(),
            wait_for_ms: 0,
            mobile: false,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            parsers: Self::default_parsers(),
            actions: Vec::new(),
            archive_behavior: None,
            location: None,
            remove_base64_images: true,
            block_ads: true,
            store_in_cache: true,
            lockdown: false,
            skip_tls_verification: false,
            only_clean_content: false,
            check_prompt_injection: false,
            redact_pii: None,
            content_strategy: None,
            profile: None,
            device_scale_milli: None,
            resource_blocking: None,
            flatten: None,
        }
    }
}

/// Which compatibility-API product a run serves; decides event names (`crawl.*` / `batch_scrape.*`),
/// the status route and the credit model.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// `POST /crawl`: link-following crawl, every page scraped with `options`.
    #[default]
    Crawl,
    /// `POST /batch/scrape`: the seed plus `urls`, no link following.
    Batch,
    /// `POST /scrape`: one URL, executed by a worker like any run; the API waits for it.
    Scrape,
    /// `POST /map`: the seed page and the sitemap are read and every in-scope URL found is
    /// listed (the run's `maxDiscoveryDepth` is 0, so such URLs end as `depth_exceeded`
    /// frontier rows); no page is scraped.
    Map,
}

impl JobKind {
    /// The prefix of the webhook event names (`crawl`, `batch_scrape`).
    #[must_use]
    pub const fn event_prefix(self) -> &'static str {
        match self {
            Self::Crawl => "crawl",
            Self::Batch => "batch_scrape",
            Self::Scrape => "scrape",
            Self::Map => "map",
        }
    }
}

/// The scrape half of a run: with it, every page of the run is produced by the scrape engine.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScrapeJob {
    /// The compatibility-API product.
    #[serde(default)]
    pub kind: JobKind,
    /// Options applied to every page.
    #[serde(default)]
    pub options: ScrapeOptions,
    /// Seeds besides `seedUrl` (batch scrape).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<url::Url>,
    /// Extra headers sent with every webhook delivery (compatibility API `webhook.headers`); never
    /// returned by the API (they may carry credentials).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub webhook_headers: BTreeMap<String, String>,
    /// Caller metadata echoed in every webhook payload (compatibility API `webhook.metadata`).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub webhook_metadata: serde_json::Value,
    /// Keep the `robots.txt` gate of a `scrape` or `batch` job. The compatibility API scrapes the
    /// URLs it is given and lowers the gate; the single-page commands scrape under it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub honor_robots_txt: bool,
}

impl ScrapeJob {
    /// A job of `kind` with `options`.
    #[must_use]
    pub fn new(kind: JobKind, options: ScrapeOptions) -> Self {
        Self {
            kind,
            options,
            urls: Vec::new(),
            webhook_headers: BTreeMap::new(),
            webhook_metadata: serde_json::Value::Null,
            honor_robots_txt: false,
        }
    }
}

impl ScrapeOptions {
    /// Check the compatibility API limits (`actions` ≤ [`MAX_ACTIONS`], waits ≤ [`MAX_WAIT_MS`] in total,
    /// `timeout` 1 000..=300 000, `screenshot` quality 1..=100, `rawBase64` alone, `pdf` scale
    /// 0.1..=2, unique `changeTracking`).
    ///
    /// # Errors
    /// A message naming the violated limit, suitable for a `400` response detail.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(reference) = &self.archive_behavior {
            reference.validate().map_err(|error| error.to_string())?;
            if !self.actions.is_empty()
                || self.mobile
                || self.location.is_some()
                || self.wait_for_ms != 0
                || self.device_scale_milli.is_some()
                || self.flatten.is_some()
                || self.resource_blocking.is_some()
            {
                return Err(
                    "archiveBehavior cannot be combined with actions or timing/emulation overrides"
                        .to_owned(),
                );
            }
        }
        if self.actions.len() > MAX_ACTIONS {
            return Err(format!("actions: at most {MAX_ACTIONS} actions are allowed"));
        }
        let mut waited: u64 = u64::from(self.wait_for_ms);
        for a in &self.actions {
            match a {
                ScrapeAction::CollectVirtualRows { spec } => spec.validate()?,
                ScrapeAction::Wait {
                    milliseconds,
                    selector,
                    state,
                } => match (milliseconds, selector) {
                    (Some(ms), None) if *state == SelectorState::Attached => waited += u64::from(*ms),
                    (None, Some(_)) => {}
                    _ => {
                        return Err(
                            "actions: `wait` needs exactly one of `milliseconds` and `selector`; nondefault `state` requires `selector`".to_owned(),
                        )
                    }
                },
                ScrapeAction::Screenshot { quality: Some(q), .. } if !(1..=100).contains(q) => {
                    return Err("actions: screenshot `quality` must be 1..=100".to_owned());
                }
                ScrapeAction::Pdf { scale: Some(s), .. } if !(0.1..=2.0).contains(s) => {
                    return Err("actions: pdf `scale` must be 0.1..=2".to_owned());
                }
                _ => {}
            }
        }
        if self.wait_for_ms > MAX_WAIT_MS || waited > u64::from(MAX_WAIT_MS) {
            return Err(format!(
                "waitFor and wait actions may total at most {MAX_WAIT_MS} ms"
            ));
        }
        if !(1_000..=300_000).contains(&self.timeout_ms) {
            return Err("timeout must be 1000..=300000 milliseconds".to_owned());
        }
        if self.wants("rawBase64") && self.formats.len() > 1 {
            return Err("formats: `rawBase64` must be the only format".to_owned());
        }
        if self.check_prompt_injection && self.wants("rawBase64") {
            return Err(
                "checkPromptInjection: scans page markdown and cannot be used with the `rawBase64` format"
                    .to_owned(),
            );
        }
        if self.redact_pii.is_some() && self.wants("rawBase64") {
            return Err(
                "redactPII: redacts page markdown and cannot be used with the `rawBase64` format".to_owned(),
            );
        }
        if self
            .formats
            .iter()
            .filter(|f| f.name() == "changeTracking")
            .count()
            > 1
        {
            return Err("formats: `changeTracking` may appear once".to_owned());
        }
        for f in &self.formats {
            if let FormatSpec::Screenshot { quality: Some(q), .. } = f {
                if !(1..=100).contains(q) {
                    return Err("formats: screenshot `quality` must be 1..=100".to_owned());
                }
            }
        }
        if let Some(ContentStrategySpecV1::ModelV1 {
            max_output_tokens,
            max_response_bytes,
            external_processing_consent,
            ..
        }) = &self.content_strategy
        {
            if !(1..=MAX_CONTENT_STRATEGY_OUTPUT_TOKENS).contains(max_output_tokens) {
                return Err(format!(
                    "contentStrategy: maxOutputTokens must be 1..={MAX_CONTENT_STRATEGY_OUTPUT_TOKENS}"
                ));
            }
            if !(1..=MAX_CONTENT_STRATEGY_RESPONSE_BYTES).contains(max_response_bytes) {
                return Err(format!(
                    "contentStrategy: maxResponseBytes must be 1..={MAX_CONTENT_STRATEGY_RESPONSE_BYTES}"
                ));
            }
            if !external_processing_consent {
                return Err(
                    "contentStrategy: modelV1 requires externalProcessingConsent to be true".to_owned(),
                );
            }
            if self.only_clean_content {
                return Err("contentStrategy: modelV1 cannot be combined with onlyCleanContent".to_owned());
            }
            if self.wants("rawBase64") {
                return Err(
                    "contentStrategy: modelV1 processes page markdown and cannot be used with the `rawBase64` format"
                        .to_owned(),
                );
            }
        }
        if let Some(scale) = self.device_scale_milli {
            if !(crate::page_op::DEVICE_SCALE_MIN_MILLI..=crate::page_op::DEVICE_SCALE_MAX_MILLI)
                .contains(&scale)
            {
                return Err("deviceScaleFactor must be 0.5..=4".to_owned());
            }
        }
        if let Some(geo) = self.location.as_ref().and_then(|l| l.geolocation) {
            crate::page_op::GeoPosition::new(geo.latitude_e6, geo.longitude_e6, geo.accuracy_m)
                .map_err(|member| format!("location.geolocation: {member} is out of range"))?;
        }
        if let Some(blocking) = &self.resource_blocking {
            use crate::page_op::BlockClass;
            if blocking
                .resource_types
                .iter()
                .any(|class| !matches!(class, BlockClass::Font | BlockClass::Media | BlockClass::Image))
            {
                return Err(
                    "resourceBlocking.resourceTypes: only font, media and image can be blocked".to_owned(),
                );
            }
            if blocking.domains.len() > ResourceBlocking::MAX_DOMAINS {
                return Err(format!(
                    "resourceBlocking.domains: at most {} hosts are allowed",
                    ResourceBlocking::MAX_DOMAINS
                ));
            }
            if blocking
                .domains
                .iter()
                .any(|d| !ResourceBlocking::is_valid_domain(d))
            {
                return Err(
                    "resourceBlocking.domains: hosts must be lower-case names without scheme, port or wildcard"
                        .to_owned(),
                );
            }
        }
        if let Some(flatten) = &self.flatten {
            if !flatten.shadow_dom && !flatten.frames {
                return Err("flatten: enable shadowDom or frames".to_owned());
            }
            if !(1..=crate::page_op::FlattenSpec::MAX_FRAMES_LIMIT).contains(&flatten.max_frames) {
                return Err(format!(
                    "flatten: maxFrames must be 1..={}",
                    crate::page_op::FlattenSpec::MAX_FRAMES_LIMIT
                ));
            }
        }
        Ok(())
    }
}

/// A binary or large value kept as an artifact of the run.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlobRef {
    /// The stored artifact.
    pub artifact: crate::ids::ArtifactRef,
    /// Media type (`image/png`, `application/pdf`, `text/html`, ...).
    pub content_type: String,
    /// Size in bytes.
    pub size: u64,
}

/// Result of the `attributes` format for one selector/attribute pair.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct AttributeResult {
    /// The requested selector.
    pub selector: String,
    /// The requested attribute.
    pub attribute: String,
    /// Attribute value of every matching element that has it, in document order.
    pub values: Vec<String>,
}

/// HTML captured by a `scrape` action.
///
/// The DOM is charged: clones share one allocation and its byte reservation. The wire shape
/// is a plain string; deserializing reserves the bytes before copying them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ActionScrape {
    /// Document URL at that point.
    pub url: String,
    /// Serialized DOM at that point.
    #[serde(with = "admitted_html")]
    pub html: AdmittedText,
}

/// Serde adapter writing [`AdmittedText`] as a string and admitting it before reading one.
mod admitted_html {
    use crate::parser_memory::{global, AdmittedText};
    use serde::de::{Error, Visitor};
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(html: &AdmittedText, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(html.as_str())
    }

    struct Admit;

    impl Visitor<'_> for Admit {
        type Value = AdmittedText;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string")
        }

        fn visit_str<E: Error>(self, text: &str) -> Result<AdmittedText, E> {
            let permit = global()
                .try_reserve(text.len())
                .map_err(|_| E::custom("byte admission refused the captured html"))?;
            Ok(AdmittedText::new(text.to_owned(), permit))
        }

        fn visit_string<E: Error>(self, text: String) -> Result<AdmittedText, E> {
            let permit = global()
                .try_reserve(text.capacity())
                .map_err(|_| E::custom("byte admission refused the captured html"))?;
            Ok(AdmittedText::new(text, permit))
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<AdmittedText, D::Error> {
        deserializer.deserialize_str(Admit)
    }
}

/// Value returned by an `executeJavascript` action.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct JavascriptReturn {
    /// JSON type name of `value`: `string`, `number`, `boolean`, `object`, `array` or `null`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The value.
    pub value: serde_json::Value,
}

/// `actions{screenshots, scrapes, javascriptReturns, pdfs}` of the response.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ActionResults {
    /// One image per `screenshot` action, in action order.
    pub screenshots: Vec<BlobRef>,
    /// One capture per `scrape` action.
    pub scrapes: Vec<ActionScrape>,
    /// One value per `executeJavascript` action.
    pub javascript_returns: Vec<JavascriptReturn>,
    /// One document per `pdf` action.
    pub pdfs: Vec<BlobRef>,
    /// Diagnostic transformed renditions, never inline durable row content.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub virtual_rows: Vec<BlobRef>,
}

/// `changeTracking.changeStatus`.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub enum ChangeStatus {
    /// No earlier stored scrape of the URL and tag.
    New,
    /// The markdown equals the earlier one.
    Same,
    /// The markdown differs.
    Changed,
    /// The page answers `404`/`410` and an earlier scrape exists.
    Removed,
}

/// `changeTracking` of one scrape (compatibility API shape).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChangeTrackingResult {
    /// RFC 3339 time of the earlier scrape; `null` for the first one.
    pub previous_scrape_at: Option<String>,
    /// New, same, changed or removed.
    pub change_status: ChangeStatus,
    /// `visible` or `hidden`.
    pub visibility: String,
    /// `git-diff` mode, only when `changeStatus` is `changed`: `{text, json}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff: Option<serde_json::Value>,
    /// `json` mode, only when `changeStatus` is `changed`: `{field: {previous, current}}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
}

/// Whether a stored scrape answered the request (`metadata.cacheState`).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum CacheState {
    /// A fresh fetch produced the document.
    #[default]
    Miss,
    /// A stored scrape younger than `maxAge` (or any, for `minAge`/`lockdown`) was served.
    Hit,
}

/// The compatibility-API document of one scraped page, as the scrape engine stores it in
/// `PageRecord.metadata["scrape"]`. `markdown`, `html` and `links` stay on the page row
/// (`PageRecord::markdown`, `html`, `links`); everything else of the compatibility API `data` object is
/// here. Heavy values are [`BlobRef`]s that the API resolves when it renders the response.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ScrapeDocument {
    /// Layout version of this value (1).
    pub version: u32,
    /// URL as requested (before redirects).
    pub source_url: String,
    /// URL after redirects (`metadata.url`).
    pub final_url: String,
    /// HTTP status of the final response (`metadata.statusCode`).
    pub status_code: u16,
    /// Route that produced this document (`basic` or `enhanced`), including cache hits.
    #[serde(default)]
    pub proxy_used: ProxyMode,
    /// Media type of the body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Page-level error text (`metadata.error`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Non-fatal problem the caller should know (`data.warning`), e.g. a format that was skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
    /// Compatibility API `metadata` keys derived from the page: `title`, `description`, `language`,
    /// `keywords`, `robots`, `ogTitle`, `ogDescription`, `ogUrl`, `ogImage`, `ogLocaleAlternate`,
    /// `ogSiteName` and every other `<meta>` name verbatim.
    #[serde(default)]
    pub meta: BTreeMap<String, serde_json::Value>,
    /// PDF pages parsed (`metadata.numPages`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_pages: Option<u32>,
    /// PDF pages in the file (`metadata.totalPages`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_pages: Option<u32>,
    /// Cache outcome.
    #[serde(default)]
    pub cache_state: CacheState,
    /// RFC 3339 time of the stored scrape that was served (`cacheState: hit`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_at: Option<String>,
    /// Scoped [`crate::cache::CacheKeyV1`] digest, including principal, backend and request shape.
    pub options_digest: Digest,
    /// The stored scrape is never served by `maxAge`, `minAge` or `lockdown` and is never a
    /// `changeTracking` baseline: `storeInCache` was false, or the page answered a non-2xx status.
    #[serde(default, skip_serializing_if = "is_false")]
    pub not_cacheable: bool,
    /// `changeTracking.tag` of the scrape, when the format was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_tag: Option<String>,
    /// `rawHtml`: the response body verbatim (browser plane: the serialized DOM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_html: Option<BlobRef>,
    /// `rawBase64`: the response body (base64 text of the bytes is made by the API).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_base64: Option<BlobRef>,
    /// `screenshot` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<BlobRef>,
    /// `images` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<Vec<String>>,
    /// `attributes` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<AttributeResult>>,
    /// `branding` format (compatibility API `BrandingProfile` shape).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branding: Option<serde_json::Value>,
    /// `summary` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// `json` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    /// `question` format (`data.answer`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer: Option<String>,
    /// `highlights` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlights: Option<Vec<String>>,
    /// `query` format: the answer, returned as `data.answer` (the `question` and
    /// `query` formats share that field; `question` wins when both are requested).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// `changeTracking` format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_tracking: Option<ChangeTrackingResult>,
    /// `pages` PDF parser option: the markdown of every parsed physical page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pages: Option<Vec<PdfPageMarkdown>>,
    /// `blocks` PDF parser option: typed layout blocks per page, compatibility API shape
    /// `[{pageNumber, width, height, status, items: [{id, type, label, bbox, content,
    /// markdownSpan, readingOrder, source, confidence}]}]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks: Option<serde_json::Value>,
    /// Requested native content outputs after privacy projection and retention admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outputs: Option<serde_json::Value>,
    /// GENERATED content of an opt-in `modelV1` content strategy: the final typed
    /// `ContentDocumentV1` (`version`, `markdown`, `tables`). It is untrusted model output, not
    /// native source evidence, structural metadata or a navigation authority; native `outputs`,
    /// article envelopes, source ranges, digests and discovery links never derive from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_content: Option<serde_json::Value>,
    /// Results of `actions[]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<ActionResults>,
    /// LLM tokens the formats used (prompt + completion), for the usage ledger.
    #[serde(default)]
    pub llm_tokens: u64,
    /// `audio` format: the stored audio file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<BlobRef>,
    /// `video` format: the stored video file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<BlobRef>,
    /// Transcript of the stored media (needs an LLM endpoint that transcribes audio).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript: Option<String>,
    /// `checkPromptInjection` scanned the whole markdown (the check is billed only then).
    #[serde(default, skip_serializing_if = "is_false")]
    pub prompt_injection_checked: bool,
    /// `redactPII` ran over the content (billed).
    #[serde(default, skip_serializing_if = "is_false")]
    pub pii_redacted: bool,
    /// How the page was rendered in a browser: block list version and completeness, requested
    /// versus measured device, flattened frames. Absent for the HTTP plane and for renders
    /// that used none of these.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_page: Option<BrowserPageReportV1>,
}

impl ScrapeDocument {
    /// Layout version written by this crate.
    pub const VERSION: u32 = 1;

    /// Name of the key under `PageRecord.metadata` that holds the serialized document.
    pub const METADATA_KEY: &'static str = "scrape";

    /// A document of the current layout with no format results yet.
    #[must_use]
    pub fn new(source_url: String, final_url: String, status_code: u16, options_digest: Digest) -> Self {
        Self {
            version: Self::VERSION,
            source_url,
            final_url,
            status_code,
            proxy_used: ProxyMode::Basic,
            content_type: None,
            error: None,
            warning: None,
            meta: BTreeMap::new(),
            num_pages: None,
            total_pages: None,
            cache_state: CacheState::Miss,
            cached_at: None,
            options_digest,
            change_tag: None,
            not_cacheable: false,
            raw_html: None,
            raw_base64: None,
            screenshot: None,
            images: None,
            attributes: None,
            branding: None,
            summary: None,
            json: None,
            answer: None,
            highlights: None,
            query: None,
            change_tracking: None,
            pages: None,
            blocks: None,
            outputs: None,
            model_content: None,
            actions: None,
            llm_tokens: 0,
            audio: None,
            video: None,
            transcript: None,
            prompt_injection_checked: false,
            pii_redacted: false,
            browser_page: None,
        }
    }

    /// The document stored on `metadata`, if the page was produced by the scrape engine.
    #[must_use]
    pub fn from_page_metadata(metadata: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(metadata.get(Self::METADATA_KEY)?.clone()).ok()
    }
}

/// The block list of one browser render: which version of the list was installed and how
/// completely it could be enforced.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BlockListReportV1 {
    /// Version of the built-in list the patterns were taken from.
    pub list_version: String,
    /// The built-in advertising, measurement and consent hosts were blocked (`blockAds`).
    pub ads: bool,
    /// Resource types that were blocked, in a stable order.
    pub resource_types: Vec<crate::page_op::BlockClass>,
    /// Hosts the caller named that were blocked.
    pub custom_domains: u32,
    /// Patterns installed per browser session.
    pub patterns_installed: u32,
    /// Browser sessions (tabs and child frames) the list reached.
    pub sessions_applied: u32,
    /// Browser sessions that refused the list.
    pub sessions_failed: u32,
    /// `true` when no code of `gaps` applies: every rule was enforced exactly on every session.
    pub complete: bool,
    /// Stable codes of what the list could not guarantee: `type_by_url_extension:<class>`
    /// (a resource type is matched by the URL's extension, so a font or medium served
    /// without one is not blocked), `first_party_rules_exempt:<n>` (rules for the scraped
    /// page's own host family were left out), `session_apply_failed`.
    pub gaps: Vec<String>,
}

/// What a request asked of the device and what the page measured afterwards.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceReportV1 {
    /// Requested device pixel ratio in thousandths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_scale_milli: Option<u32>,
    /// Requested geolocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_geolocation: Option<crate::page_op::GeoPosition>,
    /// Measured by script in the rendered page; absent when the page would not run the
    /// measurement script.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured: Option<crate::page_op::DeviceMeasurement>,
}

/// Frames and shadow roots folded into the extraction text of a render.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct FlattenReportV1 {
    /// What was asked for.
    pub spec: crate::page_op::FlattenSpec,
    /// Origin provenance of every frame met, main document first.
    pub frames: Vec<crate::page_op::FrameProvenance>,
    /// Frames beyond the list bound whose markup is not in the text.
    pub frames_omitted: u32,
}

/// Browser-plane facts about how a page was rendered, beside the content.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct BrowserPageReportV1 {
    /// Block list and its completeness; absent when nothing was blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_list: Option<BlockListReportV1>,
    /// Requested versus measured device; absent when no device profile was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<DeviceReportV1>,
    /// Frame and shadow-root flattening; absent when the text was not flattened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flatten: Option<FlattenReportV1>,
}

impl BrowserPageReportV1 {
    /// Is there nothing to report?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.block_list.is_none() && self.device.is_none() && self.flatten.is_none()
    }
}

/// `resourceBlocking`: native opt-in to block resource types and hosts besides `blockAds`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourceBlocking {
    /// Resource types to block ([`crate::page_op::BlockClass::Font`], `Media`, `Image`); other
    /// classes are not caller-selectable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_types: Vec<crate::page_op::BlockClass>,
    /// Hosts to block with their subdomains (lower-case, no scheme, port or wildcard).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
}

impl ResourceBlocking {
    /// Most hosts one request may name.
    pub const MAX_DOMAINS: usize = 64;

    /// Is `host` a blockable host name: lower-case letters, digits, `-` and non-empty `.`
    /// separated labels, at most 253 bytes, no scheme, port, path or wildcard?
    #[must_use]
    pub fn is_valid_domain(host: &str) -> bool {
        host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
    }
}

/// Credits for a stored page, using the same calculation before and after ZDR redaction.
#[must_use]
pub fn credits_for(run: &crate::repo::CrawlRun, page: &crate::repo::PageRecord) -> u64 {
    let Some(job) = &run.config.scrape else {
        return 1;
    };
    let Some(document) = ScrapeDocument::from_page_metadata(&page.metadata) else {
        return 1;
    };
    page_credits(
        &job.options,
        &document,
        run.config.retention.mode == crate::config::RetentionMode::Zdr,
    )
}

/// Compatibility-API credits for one document: parsed PDF pages, format extras and privacy checks.
#[must_use]
pub fn page_credits(options: &ScrapeOptions, document: &ScrapeDocument, zdr: bool) -> u64 {
    const EXTRA_CREDITS: u64 = 4;
    let pdf_parsed = options
        .parsers
        .iter()
        .any(|parser| matches!(parser, ParserSpec::Pdf { .. }));
    let base = if pdf_parsed {
        document.num_pages.filter(|count| *count > 0).map_or(1, u64::from)
    } else {
        1
    };
    if document.status_code >= 400 {
        return base;
    }
    let mut credits = base;
    for format in &options.formats {
        match format {
            FormatSpec::Json { .. }
            | FormatSpec::Question { .. }
            | FormatSpec::Query { .. }
            | FormatSpec::Highlights { .. } => credits = credits.saturating_add(EXTRA_CREDITS),
            FormatSpec::Audio if document.audio.is_some() => credits = credits.saturating_add(EXTRA_CREDITS),
            FormatSpec::Video if document.video.is_some() => credits = credits.saturating_add(EXTRA_CREDITS),
            _ => {}
        }
    }
    if document.prompt_injection_checked {
        credits = credits.saturating_add(EXTRA_CREDITS);
    }
    if document.pii_redacted {
        credits = credits.saturating_add(EXTRA_CREDITS.saturating_mul(base));
    }
    if options.lockdown {
        if document.cache_state == CacheState::Hit {
            credits = credits.saturating_add(EXTRA_CREDITS);
        }
    } else if zdr {
        credits = credits.saturating_add(1);
    }
    credits
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn defaults_follow_compat_api() {
        let o = ScrapeOptions::default();
        assert!(o.only_main_content && o.remove_base64_images && o.block_ads && o.store_in_cache);
        assert_eq!(o.max_age_ms, 172_800_000);
        assert_eq!(o.timeout_ms, 60_000);
        assert!(!o.needs_browser());
    }

    #[test]
    fn selector_wait_state_defaults_and_round_trips_through_native_options() {
        let default: ScrapeAction = serde_json::from_value(serde_json::json!({
            "type": "wait", "selector": "#ready"
        }))
        .unwrap();
        assert!(matches!(
            default,
            ScrapeAction::Wait {
                state: SelectorState::Attached,
                ..
            }
        ));
        for (wire, expected) in [
            ("attached", SelectorState::Attached),
            ("visible", SelectorState::Visible),
            ("hidden", SelectorState::Hidden),
            ("detached", SelectorState::Detached),
        ] {
            let options: ScrapeOptions = serde_json::from_value(serde_json::json!({
                "actions": [{"type": "wait", "selector": "#ready", "state": wire}]
            }))
            .unwrap();
            options.validate().unwrap();
            assert!(options.needs_browser());
            assert!(matches!(options.actions[0], ScrapeAction::Wait { state, .. } if state == expected));
            let serialized = serde_json::to_value(&options).unwrap();
            assert_eq!(serialized["actions"][0]["state"], wire);
            assert_eq!(
                serde_json::from_value::<ScrapeOptions>(serialized).unwrap(),
                options
            );
        }
        assert!(serde_json::from_value::<ScrapeAction>(serde_json::json!({
            "type": "wait", "selector": "#ready", "state": "unknown"
        }))
        .is_err());
        let options: ScrapeOptions = serde_json::from_value(serde_json::json!({
            "actions": [{"type": "wait", "milliseconds": 1, "state": "visible"}]
        }))
        .unwrap();
        assert!(options.validate().is_err());
    }

    #[test]
    fn rendering_options_need_the_browser() {
        let o = ScrapeOptions {
            wait_for_ms: 10,
            ..ScrapeOptions::default()
        };
        assert!(o.needs_browser());
        let mut o = ScrapeOptions::default();
        o.formats.push(FormatSpec::Screenshot {
            full_page: false,
            quality: None,
            viewport: None,
        });
        assert!(o.needs_browser());
    }

    #[test]
    fn formats_round_trip_through_the_tagged_form() {
        let f = FormatSpec::ChangeTracking {
            modes: vec![ChangeMode::GitDiff, ChangeMode::Json],
            schema: None,
            prompt: Some("p".to_owned()),
            tag: Some("t".to_owned()),
        };
        let v = serde_json::to_value(&f).unwrap();
        assert_eq!(v["type"], "changeTracking");
        assert_eq!(v["modes"][0], "git-diff");
        assert_eq!(serde_json::from_value::<FormatSpec>(v).unwrap(), f);
    }

    #[test]
    fn cache_digest_ignores_cache_controls_only() {
        let a = ScrapeOptions::default();
        let mut b = a.clone();
        b.max_age_ms = 5;
        b.timeout_ms = 1_000;
        assert_eq!(a.cache_digest(), b.cache_digest());
        b.only_main_content = false;
        assert_ne!(a.cache_digest(), b.cache_digest());
    }

    #[test]
    fn not_cacheable_defaults_to_false_and_is_omitted_when_false() {
        let mut doc = ScrapeDocument::new(
            "https://a.test/".to_owned(),
            "https://a.test/".to_owned(),
            200,
            ScrapeOptions::default().cache_digest(),
        );
        let v = serde_json::to_value(&doc).unwrap();
        assert!(v.get("notCacheable").is_none());
        let mut without = v.clone();
        without.as_object_mut().unwrap().remove("notCacheable");
        assert!(
            !serde_json::from_value::<ScrapeDocument>(without)
                .unwrap()
                .not_cacheable
        );
        doc.not_cacheable = true;
        let v = serde_json::to_value(&doc).unwrap();
        assert_eq!(v["notCacheable"], true);
        assert!(serde_json::from_value::<ScrapeDocument>(v).unwrap().not_cacheable);
    }

    #[test]
    fn parsers_default_to_pdf_and_image_and_an_empty_list_is_kept() {
        let absent: ScrapeOptions = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(absent.parsers, vec![ParserSpec::pdf(), ParserSpec::Image]);
        assert_eq!(absent, ScrapeOptions::default());
        let empty: ScrapeOptions = serde_json::from_value(serde_json::json!({"parsers": []})).unwrap();
        assert!(empty.parsers.is_empty());
        let back: ScrapeOptions = serde_json::from_value(serde_json::to_value(&empty).unwrap()).unwrap();
        assert!(back.parsers.is_empty(), "an empty list survives a round trip");
        assert_ne!(empty.cache_digest(), absent.cache_digest());
    }

    #[test]
    fn parser_objects_use_the_compat_names() {
        let p: ParserSpec = serde_json::from_value(serde_json::json!({
            "type": "pdf", "mode": "ocr", "maxPages": 3, "pages": true, "blocks": true, "pageMarkers": true
        }))
        .unwrap();
        assert_eq!(
            p,
            ParserSpec::Pdf {
                mode: PdfMode::Ocr,
                max_pages: Some(3),
                pages: true,
                blocks: true,
                page_markers: true,
            }
        );
        assert_eq!(
            serde_json::from_value::<ParserSpec>(serde_json::json!({"type": "pdf"})).unwrap(),
            ParserSpec::pdf()
        );
        let image = serde_json::to_value(ParserSpec::Image).unwrap();
        assert_eq!(image, serde_json::json!({"type": "image"}));
        assert_eq!(
            serde_json::from_value::<ParserSpec>(image).unwrap(),
            ParserSpec::Image
        );
        let pages = PdfPageMarkdown {
            page_number: 2,
            markdown: "m".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&pages).unwrap(),
            serde_json::json!({"pageNumber": 2, "markdown": "m"})
        );
    }
}
