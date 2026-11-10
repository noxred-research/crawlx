//! Search operations: `POST /search`, its feedback, the feedback endpoint of every job kind, and
//! the category indexes (`developer`, `gov`, `research/papers`).

use super::common::JsonObject;
use super::scrape::ScrapeOptions;
use super::Spec;
use schemars::JsonSchema;
use serde_json::Value;

// ---- POST /search --------------------------------------------------------------------------

/// A search source by name.
#[derive(JsonSchema)]
pub(super) enum SourceName {
    /// Web results.
    #[serde(rename = "web")]
    Web,
    /// News results.
    #[serde(rename = "news")]
    News,
    /// Image results.
    #[serde(rename = "images")]
    Images,
    /// The hosted data-provider index: not available, ignored with a warning.
    #[serde(rename = "alexandria")] // wire-compat: source value clients send
    HostedIndex,
}

/// A search source with options.
#[derive(JsonSchema)]
pub(super) struct SourceObject {
    /// Source name: `web`, `news` or `images`.
    #[serde(rename = "type")]
    kind: String,
    /// Time filter of the `web` source (`qdr:d`, `qdr:w`, ...).
    tbs: Option<String>,
    /// Location of the `web` source.
    location: Option<String>,
}

/// A `sources[]` entry.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum SourceItem {
    /// A source by name.
    Name(SourceName),
    /// A source with options.
    Object(SourceObject),
}

/// A search category by name.
#[derive(JsonSchema)]
pub(super) enum CategoryName {
    /// GitHub repositories, issues and pull requests.
    #[serde(rename = "github")]
    Github,
    /// Developer documentation.
    #[serde(rename = "developer")]
    Developer,
    /// Research papers.
    #[serde(rename = "research")]
    Research,
    /// PDF documents.
    #[serde(rename = "pdf")]
    Pdf,
    /// Government sites.
    #[serde(rename = "gov")]
    Gov,
}

/// A category with a `type`.
#[derive(JsonSchema)]
pub(super) struct CategoryObject {
    /// Category name.
    #[serde(rename = "type")]
    kind: CategoryName,
}

/// A `categories[]` entry.
#[derive(JsonSchema)]
#[serde(untagged)]
pub(super) enum CategoryItem {
    /// A category by name.
    Name(CategoryName),
    /// A category object.
    Object(CategoryObject),
}

/// `POST /search` body.
#[derive(JsonSchema)]
pub(super) struct SearchRequest {
    /// The query (1 to 500 characters).
    #[schemars(length(min = 1, max = 500))]
    query: String,
    /// Results per source (1 to 100, default 10).
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    /// Sources to query (default `web`).
    sources: Option<Vec<SourceItem>>,
    /// Categories that restrict the search.
    categories: Option<Vec<CategoryItem>>,
    /// Time filter (at most 200 characters).
    tbs: Option<String>,
    /// Location (at most 200 characters).
    location: Option<String>,
    /// Country code (at most 8 characters).
    country: Option<String>,
    /// Safe search.
    safe: Option<bool>,
    /// Milliseconds the whole request may take, scraping included (1 to 300000, default 60000).
    #[schemars(range(min = 1, max = 300000))]
    timeout: Option<u32>,
    /// Drop results the scraper could not fetch (default `false`).
    #[serde(rename = "ignoreInvalidURLs")]
    ignore_invalid_urls: Option<bool>,
    /// Scrape every web and news hit with these options and merge the document into the hit.
    #[serde(rename = "scrapeOptions")]
    scrape_options: Option<ScrapeOptions>,
    /// Only these hosts (at most 100 of at most 253 characters); not with `excludeDomains`.
    #[serde(rename = "includeDomains")]
    include_domains: Option<Vec<String>>,
    /// Never these hosts (at most 100 of at most 253 characters).
    #[serde(rename = "excludeDomains")]
    exclude_domains: Option<Vec<String>>,
    /// Accepted; applies to the hosted data-provider index and is ignored.
    #[serde(rename = "domainTools")]
    domain_tools: Option<Value>,
    /// Accepted; applies to the hosted data-provider index and is ignored.
    #[serde(rename = "toolDetail")]
    tool_detail: Option<Value>,
    /// SDK bookkeeping; accepted without effect.
    integration: Option<String>,
    /// SDK bookkeeping; accepted without effect.
    origin: Option<String>,
}

/// A web hit. With `scrapeOptions` the scraped document's members (`markdown`, `html`, `links`,
/// `metadata`, ...) are merged in; a hit that could not be scraped carries `metadata.error`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct WebResult {
    /// Page title.
    title: String,
    /// Snippet.
    description: String,
    /// The URL.
    url: String,
    /// 1-based rank.
    position: u32,
    /// The category the hit belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    /// Scraped Markdown (with `scrapeOptions`).
    #[serde(skip_serializing_if = "Option::is_none")]
    markdown: Option<String>,
    /// Scraped HTML (with `scrapeOptions`).
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<String>,
    /// Scraped links (with `scrapeOptions`).
    #[serde(skip_serializing_if = "Option::is_none")]
    links: Option<Vec<String>>,
    /// Scraped page metadata, or `{error}` when the scrape failed (with `scrapeOptions`).
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<JsonObject>,
}

/// A news hit.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct NewsResult {
    /// Headline.
    title: String,
    /// Snippet.
    snippet: String,
    /// The URL.
    url: String,
    /// 1-based rank.
    position: u32,
    /// Publication date as the backend reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    date: Option<String>,
    /// Image URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    image_url: Option<String>,
    /// Scraped Markdown (with `scrapeOptions`).
    #[serde(skip_serializing_if = "Option::is_none")]
    markdown: Option<String>,
    /// Scraped page metadata, or `{error}` when the scrape failed (with `scrapeOptions`).
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<JsonObject>,
}

/// An image hit.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ImageResult {
    /// Image title.
    title: String,
    /// The image URL.
    image_url: String,
    /// The page that holds the image.
    url: String,
    /// 1-based rank.
    position: u32,
    /// Width in pixels.
    #[serde(skip_serializing_if = "Option::is_none")]
    image_width: Option<u32>,
    /// Height in pixels.
    #[serde(skip_serializing_if = "Option::is_none")]
    image_height: Option<u32>,
}

/// Search results grouped by source; a source appears when it was queried.
#[derive(JsonSchema)]
pub(super) struct SearchData {
    /// Web hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    web: Option<Vec<WebResult>>,
    /// News hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    news: Option<Vec<NewsResult>>,
    /// Image hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    images: Option<Vec<ImageResult>>,
}

/// `POST /search` response.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SearchResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The hits by source.
    data: SearchData,
    /// Options that were not applied, joined by `; `; `null` when there were none.
    warning: Option<String>,
    /// Id of the search (the `jobId` of its feedback).
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// Credits the search and its scrapes cost.
    credits_used: u64,
}

// ---- feedback ------------------------------------------------------------------------------

/// A source that helped.
#[derive(JsonSchema)]
pub(super) struct ValuableSource {
    /// The URL.
    #[schemars(extend("format" = "uri"))]
    url: String,
}

/// A result that helped.
#[derive(JsonSchema)]
pub(super) struct ValuableResult {
    /// `web`, `images` or `news`.
    source: String,
    /// 1-based position in that source (1 to 100).
    #[schemars(range(min = 1, max = 100))]
    position: u32,
}

/// Content that was missing.
#[derive(JsonSchema)]
pub(super) struct MissingContent {
    /// The topic (1 to 200 characters).
    topic: String,
}

/// How useful a result was.
#[derive(JsonSchema)]
pub(super) enum Rating {
    /// Useful.
    #[serde(rename = "good")]
    Good,
    /// Partly useful.
    #[serde(rename = "partial")]
    Partial,
    /// Not useful.
    #[serde(rename = "bad")]
    Bad,
}

/// The feedback members shared by `POST /search/{jobId}/feedback` and `POST /feedback`.
#[derive(JsonSchema)]
pub(super) struct FeedbackFields {
    /// A `good` rating needs `valuableSources` or `valuableResults`; a `partial` rating one of
    /// those or `missingContent`; a `bad` rating `missingContent` or `querySuggestions` (for
    /// scrape, parse and map feedback `issues`, `note`, `url` or `pageNumbers` also suffice).
    rating: Rating,
    /// Sources that helped (at most 50).
    #[serde(rename = "valuableSources")]
    valuable_sources: Option<Vec<ValuableSource>>,
    /// Results that helped (at most 50).
    #[serde(rename = "valuableResults")]
    valuable_results: Option<Vec<ValuableResult>>,
    /// Content that was missing (at most 50).
    #[serde(rename = "missingContent")]
    missing_content: Option<Vec<MissingContent>>,
    /// A better query (at most 2000 characters).
    #[serde(rename = "querySuggestions")]
    query_suggestions: Option<String>,
    /// Free text (at most 4000 characters).
    note: Option<String>,
    /// Issue labels: lower-case letters, digits, `_` and `-` (at most 20 of at most 80).
    issues: Option<Vec<String>>,
    /// Tags with the same rules as `issues`.
    tags: Option<Vec<String>>,
    /// The page the feedback is about.
    #[schemars(extend("format" = "uri"))]
    url: Option<String>,
    /// The PDF pages the feedback is about.
    #[serde(rename = "pageNumbers")]
    page_numbers: Option<Vec<u32>>,
    /// Free-form object of at most 8 KiB.
    metadata: Option<JsonObject>,
}

/// `POST /search/{jobId}/feedback` body.
#[derive(JsonSchema)]
pub(super) struct SearchFeedbackRequest {
    #[serde(flatten)]
    fields: FeedbackFields,
}

/// The endpoint a general feedback is about.
#[derive(JsonSchema)]
pub(super) enum FeedbackEndpoint {
    /// `POST /search`.
    #[serde(rename = "search")]
    Search,
    /// `POST /scrape`.
    #[serde(rename = "scrape")]
    Scrape,
    /// `POST /parse`.
    #[serde(rename = "parse")]
    Parse,
    /// `POST /map`.
    #[serde(rename = "map")]
    Map,
}

/// `POST /feedback` body.
#[derive(JsonSchema)]
pub(super) struct GeneralFeedbackRequest {
    /// The endpoint of the job.
    endpoint: FeedbackEndpoint,
    /// Id of the job (a UUID the tenant ran).
    #[serde(rename = "jobId")]
    #[schemars(extend("format" = "uuid"))]
    job_id: String,
    #[serde(flatten)]
    fields: FeedbackFields,
}

/// The feedback was stored.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct FeedbackResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the stored feedback.
    #[schemars(extend("format" = "uuid"))]
    feedback_id: Option<String>,
    /// Always 0: crawlx has no billing.
    credits_refunded: u64,
    /// `true` when feedback for the job already existed (it is kept).
    #[serde(skip_serializing_if = "Option::is_none")]
    already_submitted: Option<bool>,
}

// ---- category indexes ----------------------------------------------------------------------

/// A developer result type.
#[derive(JsonSchema)]
pub(super) enum DevType {
    /// Documentation.
    #[serde(rename = "doc")]
    Doc,
    /// A GitHub issue.
    #[serde(rename = "issue")]
    Issue,
    /// A GitHub pull request.
    #[serde(rename = "pull_request")]
    PullRequest,
    /// A repository README.
    #[serde(rename = "readme")]
    Readme,
}

/// Body of `POST /search/developer` (`GET` takes the same members in the query string, lists
/// comma-separated). Any other key is accepted; filters the web backend cannot honour are listed
/// in the response `warning`.
#[derive(JsonSchema)]
pub(super) struct DeveloperParams {
    /// The query.
    query: String,
    /// Results (1 to 100, default 10).
    k: Option<u32>,
    /// Result types (default all).
    types: Option<Vec<DevType>>,
    /// Restrict to GitHub repositories (`owner/name`).
    repos: Option<Vec<String>>,
    /// Restrict documentation to these hosts.
    sources: Option<Vec<String>>,
    /// Not applied by the web backend.
    skills: Option<String>,
    /// Not applied by the web backend.
    passages: Option<String>,
    /// Not applied by the web backend.
    language: Option<String>,
    /// Not applied by the web backend.
    topic: Option<String>,
    /// Not applied by the web backend.
    license: Option<String>,
    /// Not applied by the web backend.
    min_stars: Option<String>,
    /// Not applied by the web backend.
    max_stars: Option<String>,
    /// Not applied by the web backend.
    archived: Option<String>,
    /// Not applied by the web backend.
    fork: Option<String>,
}

/// Query string of `GET /search/developer`.
#[derive(JsonSchema)]
pub(super) struct DeveloperQuery {
    /// The query.
    query: String,
    /// Results (1 to 100, default 10).
    k: Option<u32>,
    /// Comma-separated result types: `doc`, `issue`, `pull_request`, `readme` (default all).
    types: Option<String>,
    /// Comma-separated GitHub repositories (`owner/name`).
    repos: Option<String>,
    /// Comma-separated hosts the documentation search is restricted to.
    sources: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    skills: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    passages: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    language: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    topic: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    license: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    min_stars: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    max_stars: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    archived: Option<String>,
    /// Not applied by the web backend (listed in `warning`).
    fork: Option<String>,
}

/// A passage of a developer hit.
#[derive(JsonSchema)]
pub(super) struct Passage {
    /// The passage text.
    text: String,
}

/// A developer hit.
#[derive(JsonSchema)]
pub(super) struct DeveloperHit {
    /// Stable id (`owner/repo#12`, the URL, ...).
    id: String,
    /// `doc`, `issue`, `pull_request` or `readme`.
    #[serde(rename = "type")]
    kind: String,
    /// The URL.
    url: String,
    /// The snippet.
    passages: Vec<Passage>,
}

/// `GET` and `POST /search/developer` response.
#[derive(JsonSchema)]
pub(super) struct DeveloperResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The hits.
    results: Vec<DeveloperHit>,
    /// Per result type: `ok`, `unavailable` or `skipped`.
    coverage: JsonObject,
    /// Always `false`: results keep the backend's order.
    reranked: bool,
    /// Filters that were not applied; `null` when there were none.
    warning: Option<String>,
}

/// Parameters of `GET` and `POST /search/gov`. Any other key is accepted; the ones the web
/// backend cannot honour are listed in the response `warning`.
#[derive(JsonSchema)]
pub(super) struct GovParams {
    /// The query.
    query: String,
    /// Results (1 to 100, default 10).
    k: Option<u32>,
    /// Restrict to this host.
    domain: Option<String>,
    /// Not applied by the web backend.
    jurisdiction: Option<String>,
    /// Not applied by the web backend.
    court: Option<String>,
    /// Not applied by the web backend.
    #[serde(rename = "courtType")]
    court_type: Option<String>,
    /// Not applied by the web backend.
    cites: Option<String>,
}

/// A government-search hit.
#[derive(JsonSchema)]
pub(super) struct GovHit {
    /// The URL.
    url: String,
    /// Snippet (the title when there is none).
    description: String,
    /// 1-based rank.
    position: u32,
}

/// The `data` of a government search.
#[derive(JsonSchema)]
pub(super) struct GovData {
    /// The hits.
    web: Vec<GovHit>,
}

/// `GET` and `POST /search/gov` response.
#[derive(JsonSchema)]
pub(super) struct GovResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The hits.
    data: GovData,
    /// Filters that were not applied and backend notes; `null` when there were none.
    warning: Option<String>,
}

/// Query string of `GET /search/research/papers`.
#[derive(JsonSchema)]
pub(super) struct PapersQuery {
    /// The query.
    query: String,
    /// Results (1 to 500, default 40).
    k: Option<u32>,
    /// Author names appended to the query.
    authors: Option<String>,
    /// Comma-separated categories (not applied; listed in `warning`).
    categories: Option<String>,
    /// Earliest date (not applied; listed in `warning`).
    from: Option<String>,
    /// Latest date (not applied; listed in `warning`).
    to: Option<String>,
}

/// A paper hit.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PaperHit {
    /// Canonical id (`arxiv:...`, `doi:...`, `pmid:...`, `pmcid:...`, else `web:<url>`).
    paper_id: String,
    /// The same as `paperId`.
    primary_id: String,
    /// Every known id by namespace.
    ids: JsonObject,
    /// Title.
    title: String,
    /// Abstract or snippet.
    #[serde(rename = "abstract")]
    abstract_text: String,
    /// Reciprocal-rank score in (0, 1].
    score: f64,
}

/// `GET /search/research/papers` response.
#[derive(JsonSchema)]
pub(super) struct PapersResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The hits.
    results: Vec<PaperHit>,
    /// Filters that were not applied; `null` when there were none.
    warning: Option<String>,
}

/// Query string of `GET /search/research/papers/{paperId}`.
#[derive(JsonSchema)]
pub(super) struct PaperQuery {
    /// Return the passages of the full text that best match this text.
    query: Option<String>,
    /// Passages to return (1 to 50, default 4).
    k: Option<u32>,
}

/// The metadata of a paper.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PaperMetadata {
    /// Canonical id.
    paper_id: String,
    /// Known ids by namespace (each a list).
    ids: JsonObject,
    /// Title.
    title: String,
    /// Abstract.
    #[serde(rename = "abstract")]
    abstract_text: String,
    /// Authors, as the page names them.
    authors: String,
    /// Categories.
    categories: Vec<String>,
    /// Creation date as the page reports it.
    created_date: String,
    /// Update date as the page reports it.
    update_date: String,
}

/// A passage of a paper's full text.
#[derive(JsonSchema)]
pub(super) struct PaperPassage {
    /// The paragraph.
    text: String,
    /// Share of the query terms it covers.
    score: f64,
}

/// `GET /search/research/papers/{paperId}` response.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct PaperResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The paper's metadata.
    paper: PaperMetadata,
    /// The paper id (with `query`).
    #[serde(skip_serializing_if = "Option::is_none")]
    paper_id: Option<String>,
    /// The query (with `query`).
    #[serde(skip_serializing_if = "Option::is_none")]
    query: Option<String>,
    /// The best matching passages (with `query`).
    #[serde(skip_serializing_if = "Option::is_none")]
    passages: Option<Vec<PaperPassage>>,
}

/// How `GET /search/research/papers/{paperId}/similar` relates papers.
#[derive(JsonSchema)]
pub(super) enum SimilarMode {
    /// Papers on the same topic (default).
    #[serde(rename = "similar")]
    Similar,
    /// Papers that cite this one.
    #[serde(rename = "citers")]
    Citers,
    /// Papers this one cites.
    #[serde(rename = "references")]
    References,
}

/// Query string of `GET /search/research/papers/{paperId}/similar`.
#[derive(JsonSchema)]
pub(super) struct SimilarQuery {
    /// What the caller looks for in related papers (required).
    intent: String,
    /// Relation (default `similar`).
    mode: Option<SimilarMode>,
    /// Results (1 to 500, default 40).
    k: Option<u32>,
    /// Text used instead of the fetched paper title.
    anchor: Option<String>,
    /// Accepted; not supported by the web backend (listed in `note`).
    rerank: Option<String>,
}

/// `GET /search/research/papers/{paperId}/similar` response.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SimilarResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The related papers.
    results: Vec<PaperHit>,
    /// Hits the backend returned before the paper itself was removed and the list cut.
    pool_size: u64,
    /// Always `false`.
    truncated: bool,
    /// Backend notes; `null` when there were none.
    note: Option<String>,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "compatSearch" => Spec::new(&[422, 502, 503, 504])
            .json::<SearchRequest>("The query and the search options.")
            .reply::<SearchResponse>("200", "The hits by source."),
        "compatSearchFeedback" => Spec::new(&[404, 422])
            .path("jobId", "Id of the search (`id` of its response).", Some("uuid"))
            .json::<SearchFeedbackRequest>("The rating and what was useful or missing.")
            .reply::<FeedbackResponse>("200", "The feedback was stored."),
        "compatSearchDeveloperGet" => Spec::new(&[422, 502, 503, 504])
            .query::<DeveloperQuery>()
            .reply::<DeveloperResponse>("200", "Developer hits by type."),
        "compatSearchDeveloper" => Spec::new(&[422, 502, 503, 504])
            .json::<DeveloperParams>("The query and filters.")
            .reply::<DeveloperResponse>("200", "Developer hits by type."),
        "compatSearchGovGet" => Spec::new(&[422, 502, 503, 504])
            .query::<GovParams>()
            .reply::<GovResponse>("200", "Government hits."),
        "compatSearchGov" => Spec::new(&[422, 502, 503, 504])
            .json::<GovParams>("The query and filters.")
            .reply::<GovResponse>("200", "Government hits."),
        "compatResearchPapers" => Spec::new(&[422, 502, 503, 504])
            .query::<PapersQuery>()
            .reply::<PapersResponse>("200", "Paper hits."),
        "compatResearchPaper" => Spec::new(&[404, 422, 503])
            .path(
                "paperId",
                "Canonical paper id: `arxiv:<id>`, `doi:<doi>`, `pmid:<id>`, `pmcid:<id>` or `web:<url>`.",
                None,
            )
            .query::<PaperQuery>()
            .reply::<PaperResponse>(
                "200",
                "The paper's metadata, and with `query` its best matching passages.",
            ),
        "compatResearchSimilar" => Spec::new(&[404, 422, 502, 503, 504])
            .path("paperId", "Canonical paper id.", None)
            .query::<SimilarQuery>()
            .reply::<SimilarResponse>("200", "Related papers."),
        _ => return None,
    };
    Some(s)
}
