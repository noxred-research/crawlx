//! Schemas shared by several operations: the error envelope, `warnings[]`, webhooks, the
//! scraped-document object and the counters every crawl-like response carries.

use schemars::JsonSchema;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// A free-form JSON object.
pub(super) type JsonObject = Map<String, Value>;

/// One `details[]` entry of an error: which field is wrong and why.
#[derive(JsonSchema)]
pub(super) struct Detail {
    /// JSON Pointer to the offending field (`/limit`); empty for the whole body.
    path: String,
    /// Stable machine-readable violation code (`required`, `out_of_range`, `invalid_type`, ...).
    code: String,
    /// Human-readable explanation.
    message: String,
}

/// The error body of every facade operation: `{success: false, error, code, details[], requestId}`.
/// `error` is the human-readable message, `code` the stable machine-readable one.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct FacadeError {
    /// Always `false`.
    #[schemars(extend("const" = false))]
    success: bool,
    /// Human-readable message.
    error: String,
    /// Stable error code (`BAD_REQUEST`, `scope_missing`, `not_found`, `SCRAPE_TIMEOUT`, ...).
    code: String,
    /// Every violation of a rejected request.
    details: Vec<Detail>,
    /// Id of the request (also the `x-request-id` response header).
    request_id: String,
    /// Id of the original job, on the `409 request_in_flight` and `409 duplicate_request` of
    /// `POST /crawl`.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
}

/// A `warnings[]` entry: an option crawlx accepted but did not apply, or a setting it changed.
#[derive(JsonSchema)]
pub(super) struct Warning {
    /// Stable machine-readable warning code (`unsupported_option`, `deprecated_option`, ...).
    code: String,
    /// JSON Pointer to the request field the warning is about.
    path: String,
    /// Human-readable explanation of what was ignored or changed.
    message: String,
}

/// A `webhook` request member: a URL, or an object that adds headers, metadata and the events
/// to deliver.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum WebhookSpec {
    /// The destination as an `http(s)` URL; every event of the product is delivered.
    Url(#[schemars(extend("format" = "uri"))] String),
    /// The destination with its options.
    Object(WebhookObject),
}

/// The object form of a `webhook`.
#[derive(JsonSchema)]
pub(super) struct WebhookObject {
    /// Destination (`http` or `https` URL with a host).
    #[schemars(extend("format" = "uri"))]
    url: String,
    /// Extra headers sent with every delivery (values are strings).
    headers: Option<BTreeMap<String, String>>,
    /// Echoed back as `metadata` in every payload (an object).
    metadata: Option<JsonObject>,
    /// Events to deliver (`started`, `page`, `completed`, `failed` for crawls and batches, with
    /// or without the `crawl.` / `batch_scrape.` prefix); every event when omitted.
    events: Option<Vec<String>>,
}

/// The webhook of an extract, agent or monitor job (the events of the product only).
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum JobWebhookSpec {
    /// The destination as an `http(s)` URL; every event of the product is delivered.
    Url(#[schemars(extend("format" = "uri"))] String),
    /// The destination with its options.
    Object(JobWebhookObject),
}

/// The object form of a job `webhook`.
#[derive(JsonSchema)]
pub(super) struct JobWebhookObject {
    /// Destination (`http` or `https` URL with a host).
    #[schemars(extend("format" = "uri"))]
    url: String,
    /// Extra headers sent with every delivery (values are strings).
    headers: Option<BTreeMap<String, String>>,
    /// Echoed back as `metadata` in every payload (an object).
    metadata: Option<JsonObject>,
    /// Events to deliver; every event of the product when omitted (extract: `started`,
    /// `completed`, `failed`; agent: `started`, `action`, `completed`, `failed`, `cancelled`;
    /// monitor: `monitor.page`, `monitor.check.completed`).
    events: Option<Vec<String>>,
}

/// The result of one `attributes` selector.
#[derive(JsonSchema)]
pub(super) struct AttributeResult {
    /// The requested selector.
    selector: String,
    /// The requested attribute.
    attribute: String,
    /// The attribute value of every matching element that has it, in document order.
    values: Vec<String>,
}

/// `changeTracking` of one scrape.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChangeTrackingResult {
    /// RFC 3339 time of the earlier scrape; `null` for the first one.
    previous_scrape_at: Option<String>,
    /// `new`, `same`, `changed` or `removed`.
    change_status: String,
    /// `visible` or `hidden`.
    visibility: String,
    /// `git-diff` mode, only when `changeStatus` is `changed`: `{text, json}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<Value>,
    /// `json` mode, only when `changeStatus` is `changed`: `{field: {previous, current}}`.
    #[serde(skip_serializing_if = "Option::is_none")]
    json: Option<Value>,
}

/// Output of the `actions` of a scrape.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ActionOutputs {
    /// One screenshot URL per `screenshot` action, in action order.
    screenshots: Vec<String>,
    /// One `{url, html}` capture per `scrape` action.
    scrapes: Vec<Value>,
    /// One `{type, value}` per `executeJavascript` action.
    javascript_returns: Vec<Value>,
    /// One PDF URL per `pdf` action.
    pdfs: Vec<String>,
    /// Separate diagnostic transformed virtual-row renditions or authorized artifact links.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    virtual_rows: Vec<Value>,
}

/// One physical PDF page (`parsers[].pages`).
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PdfPage {
    /// 1-based physical page number.
    page_number: u32,
    /// Markdown of the page.
    markdown: String,
}

/// The `metadata` of a scraped document: the page's own `<meta>` values (any key, verbatim)
/// plus the keys below.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct DocumentMetadata {
    /// Page title.
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// URL as requested (before redirects).
    #[serde(rename = "sourceURL", skip_serializing_if = "Option::is_none")]
    source_url: Option<String>,
    /// URL after redirects.
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    /// HTTP status of the final response.
    #[serde(skip_serializing_if = "Option::is_none")]
    status_code: Option<u16>,
    /// Media type of the body.
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
    /// Page-level error text.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// PDF pages parsed.
    #[serde(skip_serializing_if = "Option::is_none")]
    num_pages: Option<u32>,
    /// PDF pages in the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    total_pages: Option<u32>,
    /// `hit` when a stored scrape answered, `miss` for a fresh fetch.
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_state: Option<String>,
    /// RFC 3339 time of the stored scrape served on a cache hit.
    #[serde(skip_serializing_if = "Option::is_none")]
    cached_at: Option<String>,
    /// Id of the scrape (`GET /scrape/{jobId}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    scrape_id: Option<String>,
    /// Credits the page cost.
    #[serde(skip_serializing_if = "Option::is_none")]
    credits_used: Option<u64>,
    /// Proxy tier that fetched the page (`basic`).
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_used: Option<String>,
    /// Whether the run waited in the admission queue before a worker started it (more than one
    /// second from creation to start).
    #[serde(skip_serializing_if = "Option::is_none")]
    concurrency_limited: Option<bool>,
    /// Milliseconds the run waited in the admission queue; present only when `concurrencyLimited`
    /// is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    concurrency_queue_duration_ms: Option<u64>,
    /// Links to values too large to inline (`markdownRef`, `htmlRef`, `rawHtmlRef`).
    #[serde(skip_serializing_if = "Option::is_none")]
    crawlx: Option<JsonObject>,
    /// Native article envelope when `contentPolicy` is selected. This contains content/PII;
    /// retention controls apply exactly as for the rest of the scrape document.
    #[serde(skip_serializing_if = "Option::is_none")]
    article: Option<NativeArticleEnvelope>,
    /// Retention-typed canonical main text source for article UTF-8 ranges.
    #[serde(skip_serializing_if = "Option::is_none")]
    article_text_ref: Option<JsonObject>,
    /// Retention-typed separate comment source, only when policy requests comments.
    #[serde(skip_serializing_if = "Option::is_none")]
    article_comments_ref: Option<JsonObject>,
}

/// Native article metadata retains its existing extensible fields and typed chunk subset.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct NativeArticleEnvelope {
    /// Optional ranges into `articleTextRef`, not into an HTML or Markdown rendition.
    #[serde(skip_serializing_if = "Option::is_none")]
    chunks: Option<super::scrape::WordChunkEnvelope>,
    #[serde(flatten)]
    fields: JsonObject,
}

/// One scraped page (the compat API `Document`): the requested formats, `metadata` and `warning`.
/// Only the formats that were requested and produced are present. Pages of a plain (non-scrape)
/// run carry `markdown`, `html`, `rawHtml`, `links`, `screenshot` and `metadata` with the
/// native `metadata.crawlx` block.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct Document {
    /// `markdown` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    markdown: Option<String>,
    /// `html` format (cleaned HTML).
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    /// `rawHtml` format (the response body verbatim).
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_html: Option<String>,
    /// `rawBase64` format: the response body, base64 encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_base64: Option<String>,
    /// `links` format: the absolute URLs of the page.
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,
    /// `images` format: the absolute image URLs of the page.
    #[serde(skip_serializing_if = "Option::is_none")]
    images: Option<Vec<String>>,
    /// `screenshot` format: a URL of the image.
    #[serde(skip_serializing_if = "Option::is_none")]
    screenshot: Option<String>,
    /// `summary` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    /// `json` format: the extracted object.
    #[serde(skip_serializing_if = "Option::is_none")]
    json: Option<Value>,
    /// `question` / `query` format: the answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<String>,
    /// `highlights` format: the selected source passages, joined by blank lines.
    #[serde(skip_serializing_if = "Option::is_none")]
    highlights: Option<String>,
    /// `query` format: the answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    /// `attributes` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<Vec<AttributeResult>>,
    /// `branding` format: the brand profile of the page.
    #[serde(skip_serializing_if = "Option::is_none")]
    branding: Option<Value>,
    /// `changeTracking` format.
    #[serde(skip_serializing_if = "Option::is_none")]
    change_tracking: Option<ChangeTrackingResult>,
    /// Outputs of `actions[]`.
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<ActionOutputs>,
    /// PDF `pages` parser option: the markdown of every parsed page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pages: Option<Vec<PdfPage>>,
    /// PDF `blocks` parser option: typed layout blocks per page.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocks: Option<Value>,
    /// Opt-in native content renditions, table analysis and link/media reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    outputs: Option<super::outputs::ContentOutputs>,
    /// A non-fatal problem the caller should know (a format that was skipped, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
    /// Page metadata.
    metadata: DocumentMetadata,
}

/// The counters of one plane of a crawl.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PlaneCounters {
    /// URLs (or interactions, states) found.
    discovered: u64,
    /// Admitted to the frontier.
    admitted: u64,
    /// Dropped as duplicates.
    deduplicated: u64,
    /// Refused by scope or policy.
    policy_blocked: u64,
    /// Refused by robots.txt.
    robots_blocked: u64,
    /// Attempted.
    attempted: u64,
    /// Succeeded.
    succeeded: u64,
    /// Failed.
    failed: u64,
    /// Abandoned after the retry budget.
    abandoned: u64,
    /// Unreachable.
    unreachable: u64,
    /// Outcome unknown (a worker was lost mid-fetch).
    unknown_outcome: u64,
}

/// `counters` of a run: one block per plane.
#[derive(JsonSchema)]
pub(super) struct RunCounters {
    /// URL plane.
    urls: PlaneCounters,
    /// Interaction plane.
    interactions: PlaneCounters,
    /// State plane.
    states: PlaneCounters,
}

/// `coverage` summary of a run.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CoverageSummary {
    /// The coverage unit (`ActionContextKey`).
    unit: String,
    /// Units discovered.
    discovered: u64,
    /// Successful trusted executions from trusted-reachable states, excluding not-observable contexts.
    exercised_trusted: u64,
    /// Recall against fixture ground-truth input; `null` without that input.
    ground_truth_recall: Option<f64>,
}

/// An entry of `errors[]` of a crawl or batch.
#[derive(JsonSchema)]
pub(super) struct CrawlErrorEntry {
    /// Id of the failed page (`{run}.{frontier}` for batches, the frontier id for crawls).
    id: String,
    /// RFC 3339 time of the failure.
    timestamp: String,
    /// The URL.
    url: String,
    /// Failure code (`SCRAPE_*`, `unreachable`, `abandoned`, `EXTERNAL_LINK`, ...).
    code: String,
    /// Human-readable failure.
    error: String,
}

/// The `success` flag of a bare acknowledgement.
#[derive(JsonSchema)]
pub(super) struct Ack {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
}
