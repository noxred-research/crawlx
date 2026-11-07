//! Crawl operations: start, status, cancel, errors, the active list and the options preview.

use super::common::{
    CoverageSummary, CrawlErrorEntry, Document, JsonObject, RunCounters, Warning, WebhookSpec,
};
use super::scrape::ScrapeOptions;
use super::Spec;
use schemars::JsonSchema;

// ---- requests ------------------------------------------------------------------------------

/// `sitemap` mode of a crawl or map.
#[derive(JsonSchema)]
pub(super) enum SitemapMode {
    /// Ignore sitemaps.
    #[serde(rename = "skip")]
    Skip,
    /// Follow links and read sitemaps (default).
    #[serde(rename = "include")]
    Include,
    /// Read sitemaps only.
    #[serde(rename = "only")]
    Only,
}

/// `POST /crawl` body.
#[derive(JsonSchema)]
pub(super) struct CrawlRequest {
    /// The start URL (`http` or `https`; a bare host is read as `http://host`). Required even
    /// when `prompt` plans the other options.
    #[schemars(extend("format" = "uri"))]
    url: String,
    /// Natural-language description of the crawl; the configured LLM derives crawl options from
    /// it (explicit options win). Without an LLM it is ignored with a `prompt_ignored` warning.
    prompt: Option<String>,
    /// Most pages to crawl (at least 1).
    limit: Option<u32>,
    /// Regexes a page path must match (at most 1000 of at most 2000 characters).
    #[serde(rename = "includePaths")]
    include_paths: Option<Vec<String>>,
    /// Regexes that exclude a page path (at most 1000 of at most 2000 characters).
    #[serde(rename = "excludePaths")]
    exclude_paths: Option<Vec<String>>,
    /// Match `includePaths` / `excludePaths` against the full URL instead of the path.
    #[serde(rename = "regexOnFullURL")]
    regex_on_full_url: Option<bool>,
    /// Deepest link depth below the start URL (0 to 65535).
    #[serde(rename = "maxDiscoveryDepth")]
    max_discovery_depth: Option<u16>,
    /// How sitemaps are used (default `include`).
    sitemap: Option<SitemapMode>,
    /// Strip every query parameter when comparing URLs (merges distinct resources).
    #[serde(rename = "ignoreQueryParameters")]
    ignore_query_parameters: Option<bool>,
    /// Crawl pages that are not below the start URL's path.
    #[serde(rename = "crawlEntireDomain")]
    crawl_entire_domain: Option<bool>,
    /// Follow links to other sites one hop: the external page is fetched, its own links are not
    /// followed and an external homepage is skipped (reported as `EXTERNAL_LINK`).
    #[serde(rename = "allowExternalLinks")]
    allow_external_links: Option<bool>,
    /// Follow links to subdomains.
    #[serde(rename = "allowSubdomains")]
    allow_subdomains: Option<bool>,
    /// Ignore robots.txt. Not applied (it needs an authorization record): `robots_enforced` warning.
    #[serde(rename = "ignoreRobotsTxt")]
    ignore_robots_txt: Option<bool>,
    /// User agent token used to read robots.txt.
    #[serde(rename = "robotsUserAgent")]
    robots_user_agent: Option<String>,
    /// Seconds between requests (up to 60); forces the crawl to one request at a time.
    delay: Option<f64>,
    /// Most pages fetched at once (at least 1; clamped to 256).
    #[serde(rename = "maxConcurrency")]
    max_concurrency: Option<u32>,
    /// Webhook for the crawl events (`started`, `page`, `completed`, `failed`, with or without
    /// the `crawl.` prefix).
    webhook: Option<WebhookSpec>,
    /// Scrape options applied to every page.
    #[serde(rename = "scrapeOptions")]
    scrape_options: Option<ScrapeOptions>,
    /// Do not store the pages; billed one extra credit per page.
    #[serde(rename = "zeroDataRetention")]
    zero_data_retention: Option<bool>,
    /// URL normalization dedupe (default `true`, as in Firecrawl). Canonicalization always merges
    /// equivalent URLs: an explicit `false` is accepted with an `unsupported_option` warning and
    /// not honoured.
    #[serde(rename = "deduplicateSimilarURLs")]
    deduplicate_similar_urls: Option<bool>,
    /// SDK bookkeeping; accepted without effect.
    integration: Option<String>,
    /// SDK bookkeeping; accepted without effect.
    origin: Option<String>,
    /// v1 alias of `maxDiscoveryDepth`; read with a `deprecated_option` warning.
    #[serde(rename = "maxDepth")]
    max_depth: Option<u16>,
    /// v1 alias: `true` is `sitemap: skip`; read with a `deprecated_option` warning.
    #[serde(rename = "ignoreSitemap")]
    ignore_sitemap: Option<bool>,
    /// v1 alias of `crawlEntireDomain`; read with a `deprecated_option` warning.
    #[serde(rename = "allowBackwardLinks")]
    allow_backward_links: Option<bool>,
    /// v1 wrapper: an object holding any of the options above, read with a `deprecated_option`
    /// warning (top-level keys win).
    #[serde(rename = "crawlerOptions")]
    crawler_options: Option<JsonObject>,
}

/// `POST /crawl/params-preview` body.
#[derive(JsonSchema)]
pub(super) struct CrawlParamsPreviewRequest {
    /// The start URL.
    #[schemars(extend("format" = "uri"))]
    url: String,
    /// What to crawl (1 to 10000 characters).
    prompt: String,
}

// ---- responses -----------------------------------------------------------------------------

/// `POST /crawl`: the crawl was started (or, for a mirrored gateway request, shadowed).
#[derive(JsonSchema)]
pub(super) struct CrawlCreated {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the crawl.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// URL of the crawl status.
    url: String,
    /// Options that were not applied or were rewritten.
    warnings: Vec<Warning>,
    /// `true` for a request mirrored by the strangler gateway (`X-Crawlx-Shadow: 1`).
    #[serde(skip_serializing_if = "Option::is_none")]
    shadow: Option<bool>,
    /// `true` when the shadow request was run.
    #[serde(skip_serializing_if = "Option::is_none")]
    mirrored: Option<bool>,
}

/// `POST /crawl` for a shadow request that was not mirrored.
#[derive(JsonSchema)]
pub(super) struct CrawlShadowSkipped {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Always `true`.
    #[schemars(extend("const" = true))]
    shadow: bool,
    /// Always `false`.
    #[schemars(extend("const" = false))]
    mirrored: bool,
    /// `zero_data_retention` or `not_sampled`.
    reason: String,
}

/// `POST /crawl` response.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum CrawlCreateResponse {
    /// A crawl was started.
    Created(CrawlCreated),
    /// A shadow request was dropped.
    ShadowSkipped(CrawlShadowSkipped),
}

/// `GET /crawl/{id}`: status, counters and one page of documents.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CrawlStatus {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// `scraping` while the crawl runs, then `completed`, `failed` or `cancelled`.
    status: String,
    /// Pages completed plus the ones in flight or queued (failed pages are not counted).
    total: u64,
    /// Pages completed.
    completed: u64,
    /// Credits the stored pages cost.
    credits_used: u64,
    /// RFC 3339 time the crawl is deleted; `null` until it is terminal.
    expires_at: Option<String>,
    /// RFC 3339 time the crawl started.
    created_at: String,
    /// Seconds the crawl has run (or ran).
    duration: f64,
    /// URL of the next page of `data`; `null` on the last page.
    next: Option<String>,
    /// This page of documents.
    data: Vec<Document>,
    /// Why a terminal crawl ended (`frontier_exhausted`, `limit_reached`, ...); `null` while it runs.
    terminal_reason: Option<String>,
    /// Counters of the three planes.
    counters: RunCounters,
    /// Action-context coverage summary.
    coverage: CoverageSummary,
    /// Options that were not applied.
    warnings: Vec<Warning>,
    /// RFC 3339 time the crawl finished (terminal crawls only).
    #[serde(skip_serializing_if = "Option::is_none")]
    completed_at: Option<String>,
}

/// `DELETE /crawl/{id}`.
#[derive(JsonSchema)]
pub(super) struct CrawlCancelled {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The status after the cancel.
    status: String,
}

/// A URL a policy refused.
#[derive(JsonSchema)]
pub(super) struct PolicyBlocked {
    /// The URL.
    url: String,
    /// Why (`out_of_scope`, `depth_exceeded`, ...); `null` when unrecorded.
    reason: Option<String>,
}

/// `GET /crawl/{id}/errors`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CrawlErrors {
    /// Pages that failed, plus external homepages skipped under `allowExternalLinks` (code
    /// `EXTERNAL_LINK`).
    errors: Vec<CrawlErrorEntry>,
    /// URLs robots.txt refused.
    robots_blocked: Vec<String>,
    /// URLs scope or policy refused.
    policy_blocked: Vec<PolicyBlocked>,
}

/// The options of a stored crawl, with Firecrawl's names.
#[derive(JsonSchema)]
pub(super) struct CrawlOptionsEcho {
    /// Page limit.
    limit: u64,
    /// Include patterns.
    #[serde(rename = "includePaths")]
    include_paths: Vec<String>,
    /// Exclude patterns.
    #[serde(rename = "excludePaths")]
    exclude_paths: Vec<String>,
    /// Whether the patterns match the full URL.
    #[serde(rename = "regexOnFullURL")]
    regex_on_full_url: bool,
    /// Deepest link depth.
    #[serde(rename = "maxDiscoveryDepth")]
    max_discovery_depth: u64,
    /// `include`, `skip` or `only`.
    sitemap: String,
    /// Whether query parameters are stripped.
    #[serde(rename = "ignoreQueryParameters")]
    ignore_query_parameters: bool,
    /// Whether the whole domain is crawled.
    #[serde(rename = "crawlEntireDomain")]
    crawl_entire_domain: bool,
    /// Whether external links are followed one hop.
    #[serde(rename = "allowExternalLinks")]
    allow_external_links: bool,
    /// Whether subdomains are followed.
    #[serde(rename = "allowSubdomains")]
    allow_subdomains: bool,
    /// Whether equivalent URLs are merged (always `true`: URL canonicalization).
    #[serde(rename = "deduplicateSimilarURLs")]
    deduplicate_similar_urls: bool,
    /// Seconds between requests.
    delay: f64,
    /// Concurrency.
    #[serde(rename = "maxConcurrency")]
    max_concurrency: u64,
    /// The robots.txt user agent, when one was set.
    #[serde(rename = "robotsUserAgent", skip_serializing_if = "Option::is_none")]
    robots_user_agent: Option<String>,
    /// The scrape options (request headers are never echoed).
    #[serde(rename = "scrapeOptions", skip_serializing_if = "Option::is_none")]
    scrape_options: Option<JsonObject>,
}

/// One crawl of `GET /crawl/active`.
#[derive(JsonSchema)]
pub(super) struct ActiveCrawl {
    /// Id of the crawl.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// Id of the owning team (the tenant).
    #[serde(rename = "teamId")]
    #[schemars(extend("format" = "uuid"))]
    team_id: String,
    /// The start URL.
    url: String,
    /// `scraping` (queued, running or paused).
    status: String,
    /// The crawl's options.
    options: CrawlOptionsEcho,
}

/// `GET /crawl/active`.
#[derive(JsonSchema)]
pub(super) struct ActiveCrawls {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The tenant's queued, running and paused crawls.
    crawls: Vec<ActiveCrawl>,
}

/// `POST /crawl/params-preview`.
#[derive(JsonSchema)]
pub(super) struct CrawlParamsPreview {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The crawl options the LLM derived (any crawl request key) plus the `url`.
    data: JsonObject,
}

// ---- query strings -------------------------------------------------------------------------

/// Paging of `GET /crawl/{id}`.
#[derive(JsonSchema)]
pub(super) struct CrawlStatusQuery {
    /// Documents per response (a positive integer, clamped to the server maximum).
    limit: Option<u64>,
    /// Offset paging: documents to skip. Takes precedence over `cursor`.
    skip: Option<u64>,
    /// Opaque position of the previous page; the `next` link carries it.
    cursor: Option<String>,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "firecrawlCreateCrawl" => Spec::new(&[400, 409, 413, 422, 503])
            .json::<CrawlRequest>("The start URL and the crawl options.")
            .header(
                "x-request-id",
                "Replay key: 1 to 128 characters of letters, digits and `.` `_` `:` `-`. The same id with the same body replays the first response; with another body it is `409 duplicate_request`; while the first request still runs, `409 request_in_flight`. Both carry the `id` of the original crawl. `Idempotency-Key` is read when this header is absent.",
            )
            .header(
                "Idempotency-Key",
                "Replays the first response for the same body; the same key with another body is `422 idempotency_key_reuse`; while the first request still runs, `409 request_in_flight` with the `id` of the original crawl.",
            )
            .header(
                "X-Crawlx-Shadow",
                "`1` marks a request mirrored by the strangler gateway: it is run as a shadow crawl when sampled.",
            )
            .reply::<CrawlCreateResponse>("200", "The crawl was started."),
        "firecrawlGetCrawl" => Spec::new(&[400, 404])
            .path("id", "Id of the crawl.", Some("uuid"))
            .query::<CrawlStatusQuery>()
            .reply::<CrawlStatus>("200", "Status, counters and one page of documents.")
            .reply::<super::watch::WatchFrame>("101", super::watch::UPGRADE),
        "firecrawlCancelCrawl" => Spec::new(&[404, 409])
            .path("id", "Id of the crawl.", Some("uuid"))
            .reply::<CrawlCancelled>("200", "The crawl was cancelled."),
        "firecrawlCrawlErrors" => Spec::new(&[404])
            .path("id", "Id of the crawl.", Some("uuid"))
            .reply::<CrawlErrors>("200", "Failed pages, robots-blocked and policy-blocked URLs."),
        "firecrawlActiveCrawls" => Spec::new(&[]).reply::<ActiveCrawls>("200", "The tenant's active crawls."),
        "firecrawlCrawlParamsPreview" => Spec::new(&[400, 413, 502, 503, 504])
            .json::<CrawlParamsPreviewRequest>("The start URL and a description of the crawl.")
            .reply::<CrawlParamsPreview>("200", "The crawl options the LLM derived."),
        _ => return None,
    };
    Some(s)
}
