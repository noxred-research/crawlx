//! Scrape and batch-scrape operations, and the scrape options every crawl-like request embeds.

use super::common::{CrawlErrorEntry, Document, JsonObject, Warning, WebhookSpec};
use super::Spec;
use schemars::JsonSchema;
use std::collections::BTreeMap;

// ---- request: scrape options ---------------------------------------------------------------

/// A format given by name.
#[derive(JsonSchema)]
pub(super) enum FormatName {
    /// Page content as Markdown.
    #[serde(rename = "markdown")]
    Markdown,
    /// Cleaned HTML.
    #[serde(rename = "html")]
    Html,
    /// The response body verbatim.
    #[serde(rename = "rawHtml")]
    RawHtml,
    /// The absolute links of the page.
    #[serde(rename = "links")]
    Links,
    /// The absolute image URLs of the page.
    #[serde(rename = "images")]
    Images,
    /// The response body, base64 encoded (must be the only format).
    #[serde(rename = "rawBase64")]
    RawBase64,
    /// The brand profile of the page.
    #[serde(rename = "branding")]
    Branding,
    /// An LLM summary of the page.
    #[serde(rename = "summary")]
    Summary,
    /// A screenshot of the viewport.
    #[serde(rename = "screenshot")]
    Screenshot,
    /// A screenshot of the full page.
    #[serde(rename = "screenshot@fullPage")]
    ScreenshotFullPage,
    /// An LLM extraction without schema or prompt.
    #[serde(rename = "json")]
    Json,
    /// Change tracking against the previous scrape with default modes.
    #[serde(rename = "changeTracking")]
    ChangeTracking,
    /// The audio of a media URL.
    #[serde(rename = "audio")]
    Audio,
    /// The video of a media URL.
    #[serde(rename = "video")]
    Video,
}

/// Viewport of a screenshot.
#[derive(JsonSchema)]
pub(super) struct Viewport {
    /// Width in pixels (1 to 10000).
    #[schemars(range(min = 1, max = 10000))]
    width: u32,
    /// Height in pixels (1 to 10000).
    #[schemars(range(min = 1, max = 10000))]
    height: u32,
}

/// One `attributes` selector.
#[derive(JsonSchema)]
pub(super) struct AttributeSelector {
    /// CSS selector.
    selector: String,
    /// Attribute to read from every match.
    attribute: String,
}

/// `changeTracking` mode.
#[derive(JsonSchema)]
pub(super) enum ChangeMode {
    /// A unified text diff of the Markdown.
    #[serde(rename = "git-diff")]
    GitDiff,
    /// A per-field diff of an LLM extraction (needs `schema` or `prompt`).
    #[serde(rename = "json")]
    Json,
}

/// How a `query` answer is formed.
#[derive(JsonSchema)]
pub(super) enum QueryMode {
    /// The answer in the model's own words (default).
    #[serde(rename = "freeform")]
    Freeform,
    /// An answer made of verbatim quotes of the page.
    #[serde(rename = "directQuote")]
    DirectQuote,
}

/// A format given as an object `{type, ...}`. `product` and `menu` are accepted and skipped with
/// an `unsupported_option` warning.
#[derive(JsonSchema)]
#[serde(tag = "type")]
pub(super) enum FormatObject {
    /// Page content as Markdown.
    #[serde(rename = "markdown")]
    Markdown {},
    /// Cleaned HTML.
    #[serde(rename = "html")]
    Html {},
    /// The response body verbatim.
    #[serde(rename = "rawHtml")]
    RawHtml {},
    /// The absolute links of the page.
    #[serde(rename = "links")]
    Links {},
    /// The absolute image URLs of the page.
    #[serde(rename = "images")]
    Images {},
    /// The response body, base64 encoded (must be the only format).
    #[serde(rename = "rawBase64")]
    RawBase64 {},
    /// The brand profile of the page.
    #[serde(rename = "branding")]
    Branding {},
    /// An LLM summary of the page.
    #[serde(rename = "summary")]
    Summary {},
    /// The audio of a media URL.
    #[serde(rename = "audio")]
    Audio {},
    /// The video of a media URL.
    #[serde(rename = "video")]
    Video {},
    /// A screenshot.
    #[serde(rename = "screenshot")]
    Screenshot {
        /// Capture the full page instead of the viewport.
        #[serde(rename = "fullPage")]
        full_page: Option<bool>,
        /// JPEG quality, 1 to 100.
        #[schemars(range(min = 1, max = 100))]
        quality: Option<u8>,
        /// Viewport size.
        viewport: Option<Viewport>,
    },
    /// Attribute values of the elements matching CSS selectors.
    #[serde(rename = "attributes")]
    Attributes {
        /// The selector and attribute pairs (each non-empty).
        selectors: Vec<AttributeSelector>,
    },
    /// LLM extraction of structured data (alias `extract`).
    #[serde(rename = "json", alias = "extract")]
    Json {
        /// JSON Schema of the answer.
        schema: Option<JsonObject>,
        /// Extraction instruction.
        prompt: Option<String>,
        /// Scan the content for prompt injection before the LLM reads it.
        #[serde(rename = "checkPromptInjection")]
        check_prompt_injection: Option<bool>,
    },
    /// Answer a question about the page.
    #[serde(rename = "question")]
    Question {
        /// The question (at most 10000 characters).
        question: String,
    },
    /// Select the passages of the page that match a query.
    #[serde(rename = "highlights")]
    Highlights {
        /// The query (at most 10000 characters).
        query: String,
    },
    /// Answer a prompt about the page.
    #[serde(rename = "query")]
    Query {
        /// The prompt.
        prompt: String,
        /// How the answer is formed.
        mode: Option<QueryMode>,
    },
    /// Compare the page with its previous scrape.
    #[serde(rename = "changeTracking")]
    ChangeTracking {
        /// Comparison modes (default: `git-diff`).
        modes: Option<Vec<ChangeMode>>,
        /// JSON Schema of the `json` mode extraction.
        schema: Option<JsonObject>,
        /// Extraction instruction of the `json` mode.
        prompt: Option<String>,
        /// Baseline tag: only scrapes with the same tag are compared.
        tag: Option<String>,
    },
}

/// A `formats[]` entry: a format name, or an object with the format's options.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum FormatItem {
    /// A format by name.
    Name(FormatName),
    /// A format with options.
    Object(FormatObject),
}

/// The PDF parser's mode.
#[derive(JsonSchema)]
pub(super) enum PdfMode {
    /// Text layer only; fails when no page has one.
    #[serde(rename = "fast")]
    Fast,
    /// Text layer, OCR where a page needs it (default).
    #[serde(rename = "auto")]
    Auto,
    /// OCR on every page.
    #[serde(rename = "ocr")]
    Ocr,
}

/// A `parsers[]` object.
#[derive(JsonSchema)]
#[serde(tag = "type")]
pub(super) enum ParserObject {
    /// The PDF parser.
    #[serde(rename = "pdf")]
    Pdf {
        /// Parsing mode.
        mode: Option<PdfMode>,
        /// Most pages to parse (1 to 10000).
        #[serde(rename = "maxPages")]
        #[schemars(range(min = 1, max = 10000))]
        max_pages: Option<u32>,
        /// Return the Markdown of every parsed page in `pages`.
        pages: Option<bool>,
        /// Return the typed layout blocks of every page in `blocks`.
        blocks: Option<bool>,
        /// Mark page boundaries in the Markdown.
        #[serde(rename = "pageMarkers")]
        page_markers: Option<bool>,
    },
    /// The image parser (OCR).
    #[serde(rename = "image")]
    Image {},
}

/// A parser by name.
#[derive(JsonSchema)]
pub(super) enum ParserName {
    /// The PDF parser with default options.
    #[serde(rename = "pdf")]
    Pdf,
    /// The image parser.
    #[serde(rename = "image")]
    Image,
}

/// A `parsers[]` entry.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum ParserItem {
    /// A parser by name.
    Name(ParserName),
    /// A parser with options.
    Object(ParserObject),
}

/// Scroll direction.
#[derive(JsonSchema)]
pub(super) enum ScrollDirection {
    /// Towards the top.
    #[serde(rename = "up")]
    Up,
    /// Towards the bottom (default).
    #[serde(rename = "down")]
    Down,
}

/// Narrow first-match selector state; not full automation-driver actionability.
#[derive(Default, JsonSchema, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum SelectorState {
    /// A matching element exists (default).
    #[default]
    Attached,
    /// First match has a positive layout box and computed visibility is not hidden/collapse.
    Visible,
    /// No match, or the first match does not satisfy visible.
    Hidden,
    /// No matching element exists.
    Detached,
}

/// One `actions[]` entry, executed in order in a browser.
#[derive(JsonSchema)]
#[serde(tag = "type")]
pub(super) enum Action {
    /// Wait a fixed time or for the first CSS match; exactly one of the two.
    #[serde(rename = "wait")]
    Wait {
        /// Milliseconds to wait (at least 1).
        milliseconds: Option<u32>,
        /// Selector to wait for.
        selector: Option<String>,
        /// First-match state; absent means attached. Nondefault states require selector.
        /// Visibility ignores opacity, viewport, hit testing, enabled state and stability.
        #[serde(default)]
        state: SelectorState,
    },
    /// Take a screenshot at this point.
    #[serde(rename = "screenshot")]
    Screenshot {
        /// Capture the full page.
        #[serde(rename = "fullPage")]
        full_page: Option<bool>,
        /// JPEG quality, 1 to 100.
        #[schemars(range(min = 1, max = 100))]
        quality: Option<u8>,
        /// Viewport size.
        viewport: Option<Viewport>,
    },
    /// Click an element.
    #[serde(rename = "click")]
    Click {
        /// CSS selector.
        selector: String,
        /// Click every match instead of the first.
        all: Option<bool>,
    },
    /// Type text into the focused element.
    #[serde(rename = "write")]
    Write {
        /// The text.
        text: String,
    },
    /// Press a key.
    #[serde(rename = "press")]
    Press {
        /// The key (`Enter`, `Tab`, ...).
        key: String,
    },
    /// Scroll the page or an element.
    #[serde(rename = "scroll")]
    Scroll {
        /// Direction (default `down`).
        direction: Option<ScrollDirection>,
        /// Element to scroll instead of the page.
        selector: Option<String>,
    },
    /// Capture the page HTML at this point.
    #[serde(rename = "scrape")]
    Scrape {},
    /// Collect exact diagnostic text rows using native journaled scrolls.
    #[serde(rename = "collectVirtualRows")]
    CollectVirtualRows {
        /// One container, scoped rows and explicit hard limits.
        spec: VirtualRowsSpec,
    },
    /// Run JavaScript in the page.
    #[serde(rename = "executeJavascript")]
    ExecuteJavascript {
        /// The script.
        script: String,
    },
    /// Render the page as a PDF.
    #[serde(rename = "pdf")]
    Pdf {
        /// Paper format (`A0` to `A6`, `Letter`, `Legal`, `Tabloid`, `Ledger`).
        format: Option<String>,
        /// Landscape orientation.
        landscape: Option<bool>,
        /// Scale factor (0.1 to 2).
        #[schemars(range(min = 0.1, max = 2.0))]
        scale: Option<f64>,
    },
}

/// Opt-in virtualized-row collection; never rewrites the live container.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct VirtualRowsSpec {
    /// CSS matching exactly one container, 1..=1024 UTF-8 bytes.
    container: String,
    /// CSS evaluated inside the container, 1..=1024 UTF-8 bytes.
    rows: String,
    /// Maximum native scroll steps, 0..=100; final step is captured.
    #[schemars(range(min = 0, max = 100))]
    max_steps: u8,
    /// Required mutation/network quiet window, 1..=1000 milliseconds.
    #[schemars(range(min = 1, max = 1000))]
    settle_ms: u32,
    /// Rows per observation, 1..=1000, no larger than maxRows.
    #[schemars(range(min = 1, max = 1000))]
    max_rows_per_window: u32,
    /// Total transferred rows including overlaps, 1..=10000.
    #[schemars(range(min = 1, max = 10000))]
    max_rows: u32,
    /// Serialized diagnostic bytes, 1024..=1048576; narrowed by parent allowance.
    #[schemars(range(min = 1024, max = 1048576))]
    max_bytes: u32,
}

/// Where the request appears to come from.
#[derive(JsonSchema)]
pub(super) struct Location {
    /// ISO 3166-1 alpha-2 country code in upper case (`US`). Accepted; crawlx has no geo proxies.
    country: Option<String>,
    /// Preferred languages (BCP 47 tags), sent as `Accept-Language`.
    languages: Option<Vec<String>>,
}

/// Proxy tier.
#[derive(JsonSchema)]
pub(super) enum Proxy {
    /// Basic deployment route, falling back to the request proxy or a direct connection.
    #[serde(rename = "basic")]
    Basic,
    /// Enhanced deployment route. Requires fetch.enhanced_proxy_url on the worker.
    #[serde(rename = "enhanced")]
    Enhanced,
    /// Basic first, then one enhanced attempt for 401/403/429 on action-free GET scrapes.
    #[serde(rename = "auto")]
    Auto,
    /// Legacy v1 spelling of enhanced.
    #[serde(rename = "stealth")]
    Stealth,
}

/// A v1 `extract` / `jsonOptions` object.
#[derive(JsonSchema)]
pub(super) struct LegacyJson {
    /// JSON Schema of the answer.
    schema: Option<JsonObject>,
    /// Extraction instruction.
    prompt: Option<String>,
}

/// `redactPII` entities.
#[derive(JsonSchema)]
pub(super) enum PiiEntity {
    /// Names of people.
    #[serde(rename = "PERSON")]
    Person,
    /// E-mail addresses.
    #[serde(rename = "EMAIL")]
    Email,
    /// Phone numbers.
    #[serde(rename = "PHONE")]
    Phone,
    /// Places.
    #[serde(rename = "LOCATION")]
    Location,
    /// Card and account numbers.
    #[serde(rename = "FINANCIAL")]
    Financial,
    /// Keys and tokens.
    #[serde(rename = "SECRET")]
    Secret,
}

/// `redactPII.mode`.
#[derive(JsonSchema)]
pub(super) enum PiiMode {
    /// Named-entity and pattern detection (default; entities that need a model are reported).
    #[serde(rename = "accurate")]
    Accurate,
    /// Also treats bare 10 to 15 digit runs as phone numbers.
    #[serde(rename = "aggressive")]
    Aggressive,
    /// Patterns only.
    #[serde(rename = "fast")]
    Fast,
}

/// `redactPII.replaceStyle`.
#[derive(JsonSchema)]
pub(super) enum PiiReplaceStyle {
    /// `[EMAIL]` (default).
    #[serde(rename = "tag")]
    Tag,
    /// `****`.
    #[serde(rename = "mask")]
    Mask,
    /// Nothing.
    #[serde(rename = "remove")]
    Remove,
}

/// `redactPII` options.
#[derive(JsonSchema)]
pub(super) struct RedactPiiOptions {
    /// Detection mode (default `accurate`).
    mode: Option<PiiMode>,
    /// Entities to redact (every one when omitted).
    entities: Option<Vec<PiiEntity>>,
    /// How a match is replaced (default `tag`).
    #[serde(rename = "replaceStyle")]
    replace_style: Option<PiiReplaceStyle>,
}

/// `redactPII`: `true` (defaults), `false` (off) or an options object.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum RedactPii {
    /// Redact with the defaults, or turn redaction off.
    Flag(bool),
    /// Redact with options.
    Options(RedactPiiOptions),
}

/// A named persistent browser profile.
#[derive(JsonSchema)]
pub(super) struct BrowserProfile {
    /// 1 to 128 characters of `A-Z a-z 0-9 _ -`.
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[A-Za-z0-9_-]+$"))]
    name: String,
    /// Keep the changes the scrape makes to the profile (default `true`).
    #[serde(rename = "saveChanges")]
    save_changes: Option<bool>,
}

/// Native article policy. All fields are optional overlays on version-one defaults.
/// This is an additive crawlx extension, not an upstream compatibility claim.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ContentPolicy {
    /// Exactly one.
    #[schemars(extend("const" = 1))]
    version: Option<u16>,
    /// Independent native selector.
    #[schemars(extend("enum" = ["article_ensemble_v1", "article_rules_v1", "article_gravity_v1", "article_density_v1"]))]
    algorithm: Option<String>,
    /// Mutually exclusive selection tradeoff.
    #[schemars(extend("enum" = ["balanced", "precision", "recall"]))]
    focus: Option<String>,
    /// Literal none disables broad rescue.
    #[schemars(extend("enum" = ["none", "bounded"]))]
    fallback: Option<String>,
    /// Reader comments stay outside main content.
    #[schemars(extend("enum" = ["drop", "separate"]))]
    comments: Option<String>,
    /// Minimum accepted Unicode scalars.
    #[schemars(range(min = 0, max = 16777216))]
    min_main_chars: Option<usize>,
    /// Required content metadata fields.
    #[schemars(length(max = 5))]
    required_metadata: Option<Vec<ContentRequiredMetadata>>,
    /// Maximum selected Unicode scalars.
    #[schemars(range(min = 1, max = 16777216))]
    max_output_chars: Option<usize>,
    /// Maximum charged selector operations.
    #[schemars(range(min = 1, max = 4000000))]
    max_operations: Option<usize>,
    /// Maximum source blocks.
    #[schemars(range(min = 1, max = 20000))]
    max_blocks: Option<usize>,
    /// Keep selected tables.
    tables: Option<bool>,
    /// Keep references, never download media in the parser.
    images: Option<bool>,
    /// Pinned ISO calendar date; absent means no future-date cutoff.
    #[schemars(extend("format" = "date"))]
    reference_date: Option<String>,
    /// Numeric date locale, never inferred from worker environment.
    #[schemars(length(max = 64))]
    locale: Option<String>,
    /// Explicit IANA zone or fixed offset for local date-time evidence.
    #[schemars(length(min = 1, max = 64))]
    date_timezone: Option<String>,
    /// Strict declared language target; unknown is not English.
    #[schemars(length(min = 1, max = 64))]
    target_language: Option<String>,
    /// Declared language or explicitly enabled local detector selection.
    #[schemars(extend("enum" = ["declared_only", "declared_then_detect", "detect"]))]
    language_mode: Option<String>,
    /// Digest of the operator-approved local detector bundle.
    language_bundle_digest: Option<String>,
    /// Minimum detection probability in thousandths.
    #[schemars(range(min = 0, max = 1000))]
    language_min_probability_millis: Option<u16>,
    /// Minimum lead over the runner-up in thousandths.
    #[schemars(range(min = 0, max = 1000))]
    language_min_margin_millis: Option<u16>,
    /// Optional Punkt model is explicitly unavailable in native pure extraction.
    #[schemars(extend("enum" = ["unicode_rules_v1", "punkt_model", "off"]))]
    nlp: Option<String>,
    /// Explicit native word segmentation algorithm.
    #[schemars(extend("enum" = ["unicode_rules_v1", "icu_dictionary_uax29_v17_v1"]))]
    tokenizer: Option<String>,
    /// Native keyword cap.
    #[schemars(range(min = 0, max = 35))]
    keywords: Option<usize>,
    /// Native extractive summary sentence cap.
    #[schemars(range(min = 0, max = 20))]
    summary_sentences: Option<usize>,
    /// Native summary Unicode scalar cap.
    #[schemars(range(min = 0, max = 20000))]
    summary_max_chars: Option<usize>,
    /// Bounded CSS/XPath include/exclude rules on the shared original DOM.
    selectors: Option<super::selectors::SelectorPolicy>,
    /// Declarative typed custom fields using the same parsed document and shared work budget.
    item_loader: Option<super::selectors::ItemLoader>,
    /// Optional native source-only word windows bound to final privacy-approved main text.
    chunks: Option<WordChunkPolicy>,
}

/// Required native metadata keys.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum ContentRequiredMetadata {
    Title,
    Url,
    PublishedDate,
    Author,
    Language,
}

/// Native Unicode-whitespace segmentation; no regex, Python or NLTK equivalence.
#[derive(JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum WordChunkStrategy {
    /// Disjoint groups including a short tail.
    Fixed {
        #[schemars(range(min = 1, max = 1000000))]
        window: usize,
    },
    /// Full windows and a final full tail window; at most one window preserves original text.
    Sliding {
        #[schemars(range(min = 1, max = 1000000))]
        window: usize,
        #[schemars(range(min = 1, max = 1000000))]
        step: usize,
    },
    /// Stop at final word, emitting a short tail; at most one window preserves original text.
    /// Overlap must be strictly smaller than window.
    Overlapping {
        #[schemars(range(min = 1, max = 1000000))]
        window: usize,
        #[schemars(range(min = 0, max = 999999))]
        overlap: usize,
    },
}

/// Inclusive native word-window limits. One over fails without partial results.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WordChunkPolicy {
    /// Exactly one; omitted fields use version-one defaults.
    #[schemars(extend("const" = 1))]
    version: Option<u16>,
    strategy: Option<WordChunkStrategy>,
    #[schemars(range(min = 1, max = 16777216))]
    max_input_bytes: Option<usize>,
    #[schemars(range(min = 1, max = 16777216))]
    max_scan_chars: Option<usize>,
    #[schemars(range(min = 1, max = 1000000))]
    max_words: Option<usize>,
    #[schemars(range(min = 1, max = 20000))]
    max_ranges: Option<usize>,
}

/// Half-open UTF-8 byte range in the retained canonical main text, never HTML.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WordChunkRange {
    start: usize,
    end: usize,
}

/// Source-only chunk envelope. Ranges preserve internal whitespace and may overlap.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WordChunkEnvelope {
    #[schemars(extend("const" = 1))]
    version: u16,
    #[schemars(extend("const" = "native_unicode_whitespace_word_windows_v1"))]
    implementation: String,
    policy: WordChunkPolicy,
    /// Digest of exact final main text bytes under crawlx.extract.chunks.final_text.v1.
    final_text_digest: String,
    #[schemars(length(max = 20000))]
    ranges: Vec<WordChunkRange>,
}

/// The scrape options of a scrape request, of `scrapeOptions` in crawl, search, extract and monitor
/// requests, and of a batch request. Keys outside this list are ignored and reported as
/// `unsupported_option` in the response `warnings`.
#[derive(JsonSchema)]
pub(super) struct ScrapeOptions {
    /// Output formats; default `["markdown"]`. A list that holds only formats crawlx does not
    /// produce keeps the default.
    formats: Option<Vec<FormatItem>>,
    /// Keep only the main content of the page (default `true`).
    #[serde(rename = "onlyMainContent")]
    only_main_content: Option<bool>,
    /// Opt-in native article policy. Unknown keys and excessive bounds fail before admission.
    #[serde(rename = "contentPolicy")]
    content_policy: Option<ContentPolicy>,
    /// Opt-in native content outputs; omitted by default.
    outputs: Option<super::outputs::ContentOutputOptions>,
    /// Opt-in byte decoding diagnostics.
    decode: Option<super::outputs::DecodeOptions>,
    /// Opt-in retention of comments and CDATA diagnostic payloads.
    markup: Option<super::outputs::MarkupRetention>,
    /// CSS selectors of elements to keep.
    #[serde(rename = "includeTags")]
    include_tags: Option<Vec<String>>,
    /// CSS selectors of elements to drop.
    #[serde(rename = "excludeTags")]
    exclude_tags: Option<Vec<String>>,
    /// Serve a stored scrape younger than this many milliseconds (default two days; `0` always
    /// fetches).
    #[serde(rename = "maxAge")]
    max_age: Option<u64>,
    /// Serve only a stored scrape at least this many milliseconds old; `404 SCRAPE_NO_CACHED_DATA`
    /// when there is none.
    #[serde(rename = "minAge")]
    min_age: Option<u64>,
    /// Request headers (values are strings); they force `storeInCache` to `false`.
    headers: Option<BTreeMap<String, String>>,
    /// Milliseconds to wait before capturing the page (0 to 60000).
    #[serde(rename = "waitFor")]
    #[schemars(range(min = 0, max = 60000))]
    wait_for: Option<u32>,
    /// Emulate a mobile device.
    mobile: Option<bool>,
    /// Do not verify TLS certificates (default `true`).
    #[serde(rename = "skipTlsVerification")]
    skip_tls_verification: Option<bool>,
    /// Milliseconds before the scrape fails with `SCRAPE_TIMEOUT` (1000 to 300000).
    #[schemars(range(min = 1000, max = 300000))]
    timeout: Option<u32>,
    /// File parsers; default `["pdf", "image"]`. An empty list turns every parser off.
    parsers: Option<Vec<ParserItem>>,
    /// Browser actions run before the capture; they force `storeInCache` to `false` and raise the
    /// run's safety profile (`actions_profile_raised` warning).
    actions: Option<Vec<Action>>,
    /// Location hints.
    location: Option<Location>,
    /// Drop inline base64 images from the Markdown and HTML.
    #[serde(rename = "removeBase64Images")]
    remove_base64_images: Option<bool>,
    /// Block advertising and cookie-popup requests.
    #[serde(rename = "blockAds")]
    block_ads: Option<bool>,
    /// Proxy tier.
    proxy: Option<Proxy>,
    /// Store the scrape so later requests can use it (default `true`).
    #[serde(rename = "storeInCache")]
    store_in_cache: Option<bool>,
    /// Serve only stored scrapes (implies zero data retention and a two-year `maxAge`).
    lockdown: Option<bool>,
    /// Do not store the scrape or its content; billed one extra credit.
    #[serde(rename = "zeroDataRetention")]
    zero_data_retention: Option<bool>,
    /// v1 alias: adds a `json` format with this schema and prompt.
    extract: Option<LegacyJson>,
    /// v1 alias: fills a bare `json` format with this schema and prompt.
    #[serde(rename = "jsonOptions")]
    json_options: Option<LegacyJson>,
    /// LLM cleanup pass that drops page chrome from the Markdown (not with zero data retention).
    #[serde(rename = "onlyCleanContent")]
    only_clean_content: Option<bool>,
    /// Scan the content for prompt injection before an LLM format runs.
    #[serde(rename = "checkPromptInjection")]
    check_prompt_injection: Option<bool>,
    /// Redact personal data from the Markdown and the LLM input.
    #[serde(rename = "redactPII")]
    redact_pii: Option<RedactPii>,
    /// A named persistent browser profile (cookies and storage kept between scrapes); needs a
    /// browser.
    profile: Option<BrowserProfile>,
}

// ---- request: scrape and batch -------------------------------------------------------------

/// `POST /scrape` body: the page to scrape, SDK bookkeeping keys and the scrape options.
#[derive(JsonSchema)]
pub(super) struct ScrapeRequest {
    /// The page to scrape (`http` or `https`; a bare host is read as `http://host`).
    #[schemars(extend("format" = "uri"))]
    url: String,
    /// SDK bookkeeping; accepted without effect.
    origin: Option<String>,
    /// SDK bookkeeping; accepted without effect.
    integration: Option<String>,
    #[serde(flatten)]
    options: ScrapeOptions,
}

/// `POST /batch/scrape` body: the URLs and the scrape options every page uses.
#[derive(JsonSchema)]
pub(super) struct BatchScrapeRequest {
    /// The pages to scrape (at least one). The first is the run's seed.
    urls: Vec<String>,
    /// Webhook for the batch events (`started`, `page`, `completed`, `failed`).
    webhook: Option<WebhookSpec>,
    /// Most pages fetched at once (1 to 256; larger values are clamped).
    #[serde(rename = "maxConcurrency")]
    max_concurrency: Option<u32>,
    /// Skip invalid URLs and list them in `invalidURLs` (default `true`); `false` rejects the
    /// request when one is invalid.
    #[serde(rename = "ignoreInvalidURLs")]
    ignore_invalid_urls: Option<bool>,
    #[serde(flatten)]
    options: ScrapeOptions,
}

// ---- responses -----------------------------------------------------------------------------

/// `{success: true, data}`: the scraped page.
#[derive(JsonSchema)]
pub(super) struct ScrapeResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The page.
    data: Document,
    /// Options that were not applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<Warning>>,
}

/// A scrape that is still running.
#[derive(JsonSchema)]
pub(super) struct ScrapePending {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Always `scraping`.
    #[schemars(extend("const" = "scraping"))]
    status: String,
}

/// `GET /scrape/{jobId}`: the document, or `status: scraping` while it runs.
#[derive(JsonSchema)]
#[serde(untagged)]
#[allow(
    clippy::large_enum_variant,
    reason = "a schema-only mirror, never constructed"
)]
pub(super) enum ScrapeStatusResponse {
    /// A finished scrape.
    Done(ScrapeResponse),
    /// A scrape still running.
    Pending(ScrapePending),
}

/// `POST /batch/scrape`: the batch was started.
#[derive(JsonSchema)]
pub(super) struct BatchCreated {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the batch.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// URL of the batch status.
    url: String,
    /// The invalid URLs that were skipped (present unless `ignoreInvalidURLs` is `false`).
    #[serde(rename = "invalidURLs", skip_serializing_if = "Option::is_none")]
    invalid_urls: Option<Vec<String>>,
    /// Options that were not applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<Warning>>,
}

/// `GET /batch/scrape/{id}`: status and one page of documents.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchStatus {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// `scraping`, `completed`, `failed` or `cancelled`.
    status: String,
    /// Pages in the batch.
    total: u64,
    /// Pages scraped so far.
    completed: u64,
    /// Credits the stored pages cost.
    credits_used: u64,
    /// RFC 3339 time the batch is deleted.
    expires_at: String,
    /// RFC 3339 time the batch started.
    created_at: String,
    /// Seconds the batch has run (or ran).
    duration: f64,
    /// URL of the next page of `data`; `null` on the last page.
    next: Option<String>,
    /// This page of documents.
    data: Vec<Document>,
    /// RFC 3339 time the batch finished (terminal batches only).
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
}

/// `DELETE /batch/scrape/{id}`.
#[derive(JsonSchema)]
pub(super) struct BatchCancelled {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The status after the cancel (`cancelled`, or the terminal status the batch already had).
    status: String,
}

/// `GET /batch/scrape/{id}/errors`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct BatchErrors {
    /// Pages that failed.
    errors: Vec<CrawlErrorEntry>,
    /// URLs robots.txt refused.
    robots_blocked: Vec<String>,
}

// ---- query strings -------------------------------------------------------------------------

/// Paging of `GET /batch/scrape/{id}`.
#[derive(JsonSchema)]
pub(super) struct BatchStatusQuery {
    /// Documents to skip (a non-negative integer).
    skip: Option<u64>,
    /// Documents per response (a positive integer, clamped to the server maximum).
    limit: Option<u64>,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "compatScrape" => Spec::new(&[400, 403, 404, 408, 409, 413, 422, 503])
            .json::<ScrapeRequest>("The page and its scrape options.")
            .header(
                "x-request-id",
                "Replay key: 1 to 128 characters of letters, digits and `.` `_` `:` `-`. The same id with the same body replays the first response; with another body it is `409 duplicate_request`; while the first request still runs, `409 request_in_flight`. `Idempotency-Key` is read when this header is absent.",
            )
            .reply::<ScrapeResponse>("200", "The scraped page."),
        "compatGetScrape" => Spec::new(&[400, 404])
            .path(
                "jobId",
                "The run id of a scrape, or `{run}.{frontier}` for one page of a crawl or batch.",
                None,
            )
            .reply::<ScrapeStatusResponse>("200", "The stored scrape, or `status: scraping` while it runs."),
        "compatBatchScrape" => Spec::new(&[400, 403, 409, 413, 422])
            .json::<BatchScrapeRequest>("The URLs and the scrape options every page uses.")
            .header(
                "Idempotency-Key",
                "Replays the first response for the same body; the same key with another body is `422 idempotency_key_reuse`.",
            )
            .reply::<BatchCreated>("200", "The batch was started."),
        "compatBatchScrapeStatus" => Spec::new(&[400, 404])
            .path("id", "Id of the batch.", Some("uuid"))
            .query::<BatchStatusQuery>()
            .reply::<BatchStatus>("200", "Status and one page of documents.")
            .reply::<super::watch::WatchFrame>("101", super::watch::UPGRADE),
        "compatBatchScrapeCancel" => Spec::new(&[404, 409])
            .path("id", "Id of the batch.", Some("uuid"))
            .reply::<BatchCancelled>("200", "The batch was cancelled."),
        "compatBatchScrapeErrors" => Spec::new(&[404])
            .path("id", "Id of the batch.", Some("uuid"))
            .reply::<BatchErrors>("200", "Failed pages and robots-blocked URLs."),
        _ => return None,
    };
    Some(s)
}
