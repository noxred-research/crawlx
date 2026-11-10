//! compat v2 `search` endpoints of the compat facade: `POST /search` over the
//! operator-configured backend ([`crate::intel::search::SearchProvider`]: metasearch or hosted SERP API),
//! optional scraping of the hits (`scrapeOptions`, through [`crate::intel::tools::PageTools`]),
//! `POST /search/{jobId}/feedback`, and the category endpoints (`/search/developer`,
//! `/search/gov`, `/search/research/papers*`, see [`crate::intel::indexes`]).

use crate::auth::Principal;
use crate::errors::ApiResult;
use crate::intel::common;
use crate::intel::feedback;
use crate::intel::indexes;
use crate::intel::request::{is_http_url, Body};
use crate::intel::search::{
    ImageHit, NewsHit, SearchCategory, SearchQuery, SearchResults, SearchSource, WebHit,
};
use crate::intel::usage::{self, Cost};
use crate::openapi::Operation;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use futures::StreamExt;
use serde_json::{json, Map, Value};
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Hits scraped at once when `scrapeOptions` is set.
const SCRAPE_CONCURRENCY: usize = 5;
/// Search time budget bounds, milliseconds (`timeout` defaults to 60 s).
const MAX_TIMEOUT_MS: u64 = 300_000;

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "post",
        "/compat/v2/search",
        "compatSearch",
        "compat v2 search: query the configured backend, optionally scrape the hits",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/compat/v2/search/{jobId}/feedback",
        "compatSearchFeedback",
        "compat v2 search: rate the results of one search",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/search/developer",
        "compatSearchDeveloperGet",
        "compat v2 developer search (issues, pull requests, READMEs, docs)",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/compat/v2/search/developer",
        "compatSearchDeveloper",
        "compat v2 developer search (issues, pull requests, READMEs, docs)",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/search/gov",
        "compatSearchGovGet",
        "compat v2 government search",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/compat/v2/search/gov",
        "compatSearchGov",
        "compat v2 government search",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/search/research/papers",
        "compatResearchPapers",
        "compat v2 research paper search",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/search/research/papers/{paperId}",
        "compatResearchPaper",
        "compat v2 research paper: metadata, or the passages matching `query`",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/search/research/papers/{paperId}/similar",
        "compatResearchSimilar",
        "compat v2 research papers similar to, citing or cited by a paper",
        "crawls:write",
        "200",
    ),
];

/// Routes of this module, mounted under `/compat/v2` behind authentication.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/v2/search", post(search))
        .route("/compat/v2/search/{jobId}/feedback", post(search_feedback))
        .route(
            "/compat/v2/search/developer",
            get(indexes::developer_get).post(indexes::developer_post),
        )
        .route(
            "/compat/v2/search/gov",
            get(indexes::gov_get).post(indexes::gov_post),
        )
        .route("/compat/v2/search/research/papers", get(indexes::papers))
        .route("/compat/v2/search/research/papers/{paperId}", get(indexes::paper))
        .route(
            "/compat/v2/search/research/papers/{paperId}/similar",
            get(indexes::similar),
        )
}

/// Top-level `POST /search` keys the endpoint reads.
const KNOWN: [&str; 17] = [
    "query",
    "limit",
    "sources",
    "categories",
    "tbs",
    "location",
    "country",
    "safe",
    "timeout",
    "ignoreInvalidURLs",
    "scrapeOptions",
    "includeDomains",
    "excludeDomains",
    "domainTools",
    "toolDetail",
    "integration",
    "origin",
];

/// A validated `POST /search` body.
#[derive(Debug)]
struct Request {
    query: SearchQuery,
    ignore_invalid_urls: bool,
    scrape_options: Option<Value>,
    warnings: Vec<String>,
}

fn source_of(name: &str) -> Option<SearchSource> {
    match name {
        "web" => Some(SearchSource::Web),
        "news" => Some(SearchSource::News),
        "images" => Some(SearchSource::Images),
        _ => None,
    }
}

fn category_of(name: &str) -> Option<SearchCategory> {
    match name {
        "github" => Some(SearchCategory::Github),
        "developer" => Some(SearchCategory::Developer),
        "research" => Some(SearchCategory::Research),
        "pdf" => Some(SearchCategory::Pdf),
        "gov" => Some(SearchCategory::Gov),
        _ => None,
    }
}

/// `"web"` or `{type: "web", tbs, location}` to `(name, tbs, location)`.
fn kind_of(v: &Value) -> Option<(String, Option<String>, Option<String>)> {
    match v {
        Value::String(s) => Some((s.clone(), None, None)),
        Value::Object(o) => {
            let t = o.get("type")?.as_str()?.to_owned();
            let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
            Some((t, text("tbs"), text("location")))
        }
        _ => None,
    }
}

fn parse_request(body: &Value) -> ApiResult<Request> {
    let mut b = Body::new(body)?;
    let mut warnings = Vec::new();
    let query_text = b.required_string("query", 500);
    let limit = b.integer("limit", 1, 100).unwrap_or(10);
    let mut tbs = b.string("tbs", 200);
    let mut location = b.string("location", 200);
    let country = b.string("country", 8);
    let safe = b.boolean("safe");
    let timeout_ms = b.integer("timeout", 1, MAX_TIMEOUT_MS).unwrap_or(60_000);
    let ignore_invalid_urls = b.boolean("ignoreInvalidURLs").unwrap_or(false);
    let include_domains = b.strings("includeDomains", 100, 253).unwrap_or_default();
    let exclude_domains = b.strings("excludeDomains", 100, 253).unwrap_or_default();
    if !include_domains.is_empty() && !exclude_domains.is_empty() {
        b.fail(
            "excludeDomains",
            "invalid",
            "includeDomains and excludeDomains cannot be used together",
        );
    }
    let scrape_options = b.object("scrapeOptions").cloned();

    let mut sources: Vec<SearchSource> = Vec::new();
    if let Some(items) = b.array("sources") {
        for (i, item) in items.iter().enumerate() {
            match kind_of(item) {
                Some((name, t, l)) => match source_of(&name) {
                    Some(s) => {
                        sources.push(s);
                        if s == SearchSource::Web {
                            tbs = tbs.or(t);
                            location = location.or(l);
                        }
                    }
                    None if name == "alexandria" => warnings.push(
                        // wire-compat: source value clients send
                        "source `alexandria` is a hosted data-provider index and is not available; ignored"
                            .to_owned(),
                    ),
                    None => b.fail(
                        &format!("sources/{i}"),
                        "invalid",
                        format!("unknown source {name:?}"),
                    ),
                },
                None => b.fail(
                    &format!("sources/{i}"),
                    "invalid_type",
                    "expected a source name or {type}",
                ),
            }
        }
    }
    let mut categories: Vec<SearchCategory> = Vec::new();
    if let Some(items) = b.array("categories") {
        for (i, item) in items.iter().enumerate() {
            match kind_of(item).and_then(|(n, ..)| category_of(&n)) {
                Some(c) => categories.push(c),
                None => b.fail(
                    &format!("categories/{i}"),
                    "invalid",
                    "expected one of github, developer, research, pdf, gov",
                ),
            }
        }
    }
    for key in ["domainTools", "toolDetail"] {
        if b.raw(key).is_some() {
            warnings.push(format!(
                "{key} applies to the hosted data-provider index; ignored"
            ));
        }
    }
    let unknown = b.unknown_keys(&KNOWN);
    if !unknown.is_empty() {
        warnings.push(format!("unsupported options ignored: {}", unknown.join(", ")));
    }
    let query_text = query_text.unwrap_or_default();
    b.finish()?;
    sources.sort();
    sources.dedup();
    if sources.is_empty() {
        sources.push(SearchSource::Web);
    }
    categories.sort();
    categories.dedup();
    let mut query = SearchQuery::web(&query_text, usize::try_from(limit).unwrap_or(100));
    query.sources = sources;
    query.categories = categories;
    query.include_domains = include_domains;
    query.exclude_domains = exclude_domains;
    query.tbs = tbs;
    query.location = location;
    query.country = country;
    query.safe = safe;
    query.timeout = Duration::from_millis(timeout_ms);
    Ok(Request {
        query,
        ignore_invalid_urls,
        scrape_options,
        warnings,
    })
}

fn web_json(h: &WebHit) -> Value {
    let mut o = json!({
        "title": h.title,
        "description": h.description,
        "url": h.url,
        "position": h.position,
    });
    if let Some(c) = &h.category {
        o["category"] = json!(c);
    }
    o
}

fn news_json(h: &NewsHit) -> Value {
    let mut o = json!({
        "title": h.title,
        "snippet": h.snippet,
        "url": h.url,
        "position": h.position,
    });
    if let Some(d) = &h.date {
        o["date"] = json!(d);
    }
    if let Some(i) = &h.image_url {
        o["imageUrl"] = json!(i);
    }
    o
}

fn image_json(h: &ImageHit) -> Value {
    let mut o = json!({
        "title": h.title,
        "imageUrl": h.image_url,
        "url": h.url,
        "position": h.position,
    });
    if let Some(w) = h.image_width {
        o["imageWidth"] = json!(w);
    }
    if let Some(w) = h.image_height {
        o["imageHeight"] = json!(w);
    }
    o
}

/// Credits of `n` results: 2 per started block of 10.
fn search_credits(n: usize) -> u64 {
    u64::try_from(n.div_ceil(10))
        .unwrap_or(u64::MAX)
        .saturating_mul(2)
}

/// Merge a scraped compat API document into a result object (`markdown`, `html`, `links`, ...,
/// `metadata`), or record the failure in `metadata.error`.
fn merge_scrape(hit: &mut Value, scraped: Result<crate::intel::tools::ScrapedPage, String>) -> u64 {
    match scraped {
        Ok(page) => {
            if let (Some(dst), Some(src)) = (hit.as_object_mut(), page.document.as_object()) {
                for (k, v) in src {
                    if k != "metadata" {
                        dst.insert(k.clone(), v.clone());
                    }
                }
                if let Some(m) = src.get("metadata") {
                    dst.insert("metadata".to_owned(), m.clone());
                }
            }
            page.credits
        }
        Err(e) => {
            hit["metadata"] = json!({ "error": e });
            0
        }
    }
}

/// Scrape each hit with `options`, at most [`SCRAPE_CONCURRENCY`] at a time, within `budget`.
/// Returns the credits the scrapes cost.
async fn scrape_hits(
    state: &AppState,
    principal: &Principal,
    hits: &mut [Value],
    options: &Value,
    budget: Duration,
) -> ApiResult<u64> {
    let tools = common::tools(state)?;
    let started = Instant::now();
    let urls: Vec<String> = hits
        .iter()
        .map(|h| {
            h.get("url")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    let results: Vec<Result<crate::intel::tools::ScrapedPage, String>> = futures::stream::iter(urls)
        .map(|url| {
            let tools = tools.clone();
            let tenant = principal.tenant;
            let options = options.clone();
            let remaining = budget.saturating_sub(started.elapsed());
            async move {
                match tokio::time::timeout(remaining, tools.scrape(tenant, &url, &options)).await {
                    Ok(Ok(page)) => Ok(page),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err("scrape timed out".to_owned()),
                }
            }
        })
        .buffered(SCRAPE_CONCURRENCY)
        .collect()
        .await;
    let mut credits = 0_u64;
    for (hit, r) in hits.iter_mut().zip(results) {
        credits = credits.saturating_add(merge_scrape(hit, r));
    }
    Ok(credits)
}

/// Whether the crawler's egress policy would let the page tools fetch `url`.
fn scrapeable(url: &str) -> bool {
    is_http_url(url)
        && url::Url::parse(url).ok().is_some_and(|u| {
            crawlx_policy::EgressPolicy::new(false)
                .with_seed_port(&u)
                .check_url(&u)
                .is_ok()
        })
}

/// Shape grouped results as the `data` object, honouring `ignoreInvalidURLs`.
fn data_json(results: &SearchResults, query: &SearchQuery, ignore_invalid: bool) -> Map<String, Value> {
    let keep = |url: &str| !ignore_invalid || scrapeable(url);
    let mut data = Map::new();
    for s in &query.sources {
        match s {
            SearchSource::Web => {
                data.insert(
                    "web".to_owned(),
                    Value::Array(
                        results
                            .web
                            .iter()
                            .filter(|h| keep(&h.url))
                            .map(web_json)
                            .collect(),
                    ),
                );
            }
            SearchSource::News => {
                data.insert(
                    "news".to_owned(),
                    Value::Array(
                        results
                            .news
                            .iter()
                            .filter(|h| keep(&h.url))
                            .map(news_json)
                            .collect(),
                    ),
                );
            }
            SearchSource::Images => {
                data.insert(
                    "images".to_owned(),
                    Value::Array(
                        results
                            .images
                            .iter()
                            .filter(|h| keep(&h.url))
                            .map(image_json)
                            .collect(),
                    ),
                );
            }
        }
    }
    data
}

/// `POST /compat/v2/search`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `422` for an invalid body, `503
/// search_not_configured` without a search backend, `504 search_timeout` and `502
/// search_unavailable` for backend failures.
pub async fn search(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let req = parse_request(&body)?;
    let provider = common::search(&state)?;
    let started = Instant::now();
    let results = provider
        .search(&req.query)
        .await
        .map_err(|e| common::search_error(&e))?;
    let mut data = data_json(&results, &req.query, req.ignore_invalid_urls);
    let mut search_cost = 0_u64;
    for v in data.values() {
        search_cost = search_cost.saturating_add(search_credits(v.as_array().map_or(0, Vec::len)));
    }
    let mut credits = search_cost;
    let mut warnings = req.warnings;
    warnings.extend(results.warnings);
    if let Some(options) = &req.scrape_options {
        let budget = req.query.timeout.saturating_sub(started.elapsed());
        for key in ["web", "news"] {
            if let Some(Value::Array(hits)) = data.get_mut(key) {
                let c = scrape_hits(&state, &principal, hits, options, budget).await?;
                credits = credits.saturating_add(c);
            }
        }
    }
    let id = Uuid::now_v7();
    // the page tools record the scrapes on their own ledger rows; this row is the search itself
    usage::record(
        &state,
        principal.tenant,
        "search",
        Some(id),
        "completed",
        Cost::credits(search_cost),
    )
    .await;
    let warning = if warnings.is_empty() {
        Value::Null
    } else {
        Value::String(warnings.join("; "))
    };
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "success": true,
            "data": data,
            "warning": warning,
            "id": id,
            "creditsUsed": credits,
        }),
    ))
}

/// `POST /compat/v2/search/{jobId}/feedback`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `404 not_found` for a search this tenant never
/// ran (or whose ledger row has expired), `422` for an invalid body.
pub async fn search_feedback(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(job_id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let id = common::parse_id(&job_id, "search")?;
    let reply = feedback::submit(&state, &principal, "search", id, &body).await?;
    Ok(json_response(StatusCode::OK, &reply))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn parses_sources_categories_and_options() {
        let r = parse_request(&json!({
            "query": "rust",
            "limit": 3,
            "sources": ["news", {"type": "web", "tbs": "qdr:w", "location": "Berlin"}, "alexandria"], // wire-compat
            "categories": [{"type": "research"}, "pdf"],
            "country": "DE",
            "timeout": 5000,
            "includeDomains": ["a.com"],
            "scrapeOptions": {"formats": ["markdown"]},
            "bogus": 1,
        }))
        .unwrap();
        assert_eq!(r.query.limit, 3);
        assert_eq!(r.query.sources, vec![SearchSource::Web, SearchSource::News]);
        assert_eq!(
            r.query.categories,
            vec![SearchCategory::Research, SearchCategory::Pdf]
        );
        assert_eq!(r.query.tbs.as_deref(), Some("qdr:w"));
        assert_eq!(r.query.location.as_deref(), Some("Berlin"));
        assert_eq!(r.query.timeout, Duration::from_millis(5000));
        assert!(r.scrape_options.is_some());
        assert_eq!(r.warnings.len(), 2, "{:?}", r.warnings);
    }

    #[test]
    fn rejects_bad_requests_with_all_violations() {
        let err = parse_request(&json!({
            "limit": 0,
            "sources": ["video"],
            "categories": ["nope"],
            "includeDomains": ["a.com"],
            "excludeDomains": ["b.com"],
        }))
        .unwrap_err();
        let paths: Vec<&str> = err.details.iter().map(|d| d.path.as_str()).collect();
        assert!(
            paths.contains(&"/query") && paths.contains(&"/limit"),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"/sources/0") && paths.contains(&"/categories/0"),
            "{paths:?}"
        );
        assert!(paths.contains(&"/excludeDomains"), "{paths:?}");
    }

    #[test]
    fn credits_are_two_per_started_ten() {
        assert_eq!(search_credits(0), 0);
        assert_eq!(search_credits(1), 2);
        assert_eq!(search_credits(10), 2);
        assert_eq!(search_credits(11), 4);
    }
}
