//! Firecrawl v2 `POST /map`: the URLs of a site.
//!
//! A map is a normal run a worker executes: `scrape.kind = map`, static mode, `maxDiscoveryDepth`
//! 0. The worker fetches the seed page and, per `sitemap`, reads the sitemaps; every URL it finds
//! that is in scope (`includeSubdomains` picks the registrable domain or the seed host) is
//! recorded as a frontier row that ends `policy_blocked` with the reason `depth_exceeded`. The
//! API waits for the run, then lists the seed page and those rows as `links[{url, title,
//! description}]` in discovery order: de-duplicated by canonical URL (fragment dropped, query
//! dropped under `ignoreQueryParameters`, a trailing slash ignored), ordered by relevance when
//! `search` is given ([`crawlx_extract::map_rank`]), cut to `limit`. The seed page is listed even
//! under `sitemap: only` (a sitemap lists its site's root in practice). A map costs one credit.
//!
//! | Firecrawl | crawlx |
//! |---|---|
//! | `sitemap` | `scope.sitemap` |
//! | `includeSubdomains` (default true) | `scope.hostScope` `rdn` (true) or `fqdn` |
//! | `ignoreQueryParameters` (default true) | `scope.queryPolicy` `strip_all` or `keep_all` |
//! | `limit` (default 5000, at most 100000) | applied to the listed links |
//! | `timeout` (ms) | how long the request waits for the run (`408 SCRAPE_TIMEOUT` and the run is cancelled) |
//! | `location{country, languages}` | the `Accept-Language` header of the map's requests: `languages` (else the country's main language) weighted like `de-DE,en;q=0.9`, from the table scrapes use ([`locale::http_accept_language`]); a `country` adds the `location_no_proxy` warning (no geo-located proxy) |
//! | `ignoreCache` | `true` reads nothing from the store; otherwise stored URLs extend the live results (below) |
//! | `auditMetadata`, `threatProtection` | accepted with a warning, not applied |
//!
//! **Stored URLs.** Unless `ignoreCache` is true, the live results are extended with the URLs that
//! earlier runs of the same tenant (crawls, scrapes, maps) stored for the same site
//! (`PageRepo::known_pages`): the URL of every stored page of the map's host scope
//! (`includeSubdomains`: the registrable domain, else the seed host) and the links found on those
//! pages (the `links` format), newest page first, at most 10 000 URLs. Only pages of runs that
//! have not expired and are not zero-data-retention runs, that answered below 400 and are not
//! flagged not cacheable are read, and only URLs the live map would list too (the same scope
//! rule) are added. They come after the live results, are de-duplicated against them with the
//! same key, and then `search` and `limit` apply to the merged list exactly as before. The
//! response carries a `map_cached_sources` warning with the number of URLs added. `sitemap: only`
//! lists exactly the sitemap, so it reads no stored URLs. The store is read before the map's own
//! run exists, so a map never lists its own pages as stored ones.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::usage::{self, Cost};
use crate::openapi::Operation;
use crate::resources::Warning;
use crate::routes::compat::concurrency_limit;
use crate::scrape_service::{create_scrape_run, parse_target, run_failure, wait_for_run, MapEntry};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::post;
use axum::{Extension, Router};
use crawlx_core::config::{CrawlMode, CreateCrawl, HostScope, OutputFormat, QueryPolicy, SitemapMode};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{FrontierEntry, FrontierStatus, KnownPage, PageRecord};
use crawlx_core::scrape::{JobKind, Location, ScrapeJob, ScrapeOptions};
use crawlx_core::TenantId;
use crawlx_extract::map_rank::{rank, MapItem};
use crawlx_policy::{DenialReason, ScopePolicy, ScopeVerdict};
use crawlx_worker::scrape::render::locale;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::time::Duration;
use url::Url;

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[(
    "post",
    "/compat/firecrawl/v2/map",
    "firecrawlMap",
    "Firecrawl v2 map: the URLs of a site from its sitemap and the links of its start page",
    "crawls:write",
    "200",
)];

/// Routes of this module, mounted behind authentication.
pub fn routes() -> Router<AppState> {
    Router::new().route("/compat/firecrawl/v2/map", post(map))
}

/// Request keys of a map body; everything else warns.
const KNOWN: [&str; 9] = [
    "url",
    "search",
    "sitemap",
    "includeSubdomains",
    "ignoreQueryParameters",
    "ignoreCache",
    "limit",
    "timeout",
    "location",
];

/// Request keys Firecrawl documents that crawlx does not apply.
const UNSUPPORTED: [&str; 2] = ["auditMetadata", "threatProtection"];

/// Default `limit` of a map.
const DEFAULT_LIMIT: u64 = 5000;
/// Largest `limit` of a map.
const MAX_LIMIT: u64 = 100_000;
/// How long a map without `timeout` waits for its run.
const DEFAULT_WAIT: Duration = Duration::from_secs(300);
/// The frontier reason of a URL a map lists.
const LISTED: &str = "depth_exceeded";
/// Most stored pages one map reads.
const STORED_PAGES: u32 = 10_000;
/// Most stored URLs one map adds to its live results.
const STORED_URLS: usize = 10_000;

/// A parsed map request.
#[derive(Debug)]
struct MapRequest {
    seed: Url,
    search: Option<String>,
    sitemap: SitemapMode,
    include_subdomains: bool,
    ignore_query: bool,
    ignore_cache: bool,
    limit: usize,
    wait: Duration,
    location: Location,
    warnings: Vec<Warning>,
}

fn parse_request(url: &str, options: &Value) -> Result<MapRequest, HttpError> {
    let empty = Map::new();
    let obj = match options {
        Value::Null => &empty,
        Value::Object(m) => m,
        _ => {
            return Err(HttpError::bad_request(vec![Detail::new(
                "/",
                "invalid_type",
                "map options must be an object",
            )]))
        }
    };
    let mut details = Vec::new();
    let mut warnings = Vec::new();
    let seed = match parse_target(url, "/url") {
        Ok(u) => Some(u),
        Err(d) => {
            details.push(d);
            None
        }
    };
    for k in obj.keys() {
        if UNSUPPORTED.contains(&k.as_str()) {
            warnings.push(Warning::new(
                "unsupported_option",
                &format!("/{k}"),
                format!("`{k}` is not supported and was ignored"),
            ));
        } else if !KNOWN.contains(&k.as_str()) {
            warnings.push(Warning::new(
                "unsupported_option",
                &format!("/{k}"),
                format!("option `{k}` is not supported and was ignored"),
            ));
        }
    }
    let mut bad = |key: &str, code: &str, message: &str| {
        details.push(Detail::new(format!("/{key}"), code, message));
    };
    let boolean = |key: &str, default: bool, bad: &mut dyn FnMut(&str, &str, &str)| match obj.get(key) {
        None | Some(Value::Null) => default,
        Some(Value::Bool(b)) => *b,
        Some(_) => {
            bad(key, "invalid_type", "expected a boolean");
            default
        }
    };
    let include_subdomains = boolean("includeSubdomains", true, &mut bad);
    let ignore_query = boolean("ignoreQueryParameters", true, &mut bad);
    let ignore_cache = boolean("ignoreCache", false, &mut bad);
    let search = match obj.get("search") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()).filter(|s| !s.trim().is_empty()),
        Some(_) => {
            bad("search", "invalid_type", "expected a string");
            None
        }
    };
    let sitemap = match obj.get("sitemap") {
        None | Some(Value::Null) => SitemapMode::Include,
        Some(Value::String(s)) if s == "skip" => SitemapMode::Skip,
        Some(Value::String(s)) if s == "include" => SitemapMode::Include,
        Some(Value::String(s)) if s == "only" => SitemapMode::Only,
        Some(_) => {
            bad("sitemap", "unknown_enum", "sitemap must be skip, include or only");
            SitemapMode::Include
        }
    };
    let uint = |key: &str, min: u64, max: u64, bad: &mut dyn FnMut(&str, &str, &str)| match obj.get(key) {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(n) if (min..=max).contains(&n) => Some(n),
            Some(_) => {
                bad(key, "out_of_range", &format!("must be between {min} and {max}"));
                None
            }
            None => {
                bad(key, "invalid_type", "expected a non-negative integer");
                None
            }
        },
    };
    let limit = uint("limit", 1, MAX_LIMIT, &mut bad).unwrap_or(DEFAULT_LIMIT);
    let wait = uint("timeout", 1, u64::from(u32::MAX), &mut bad).map_or(DEFAULT_WAIT, Duration::from_millis);
    let mut location = Location::default();
    match obj.get("location") {
        None | Some(Value::Null) => {}
        Some(Value::Object(l)) => {
            match l.get("country") {
                None | Some(Value::Null) => {}
                Some(Value::String(c)) if c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase()) => {
                    location.country = Some(c.clone());
                    warnings.push(Warning::new(
                        "location_no_proxy",
                        "/location/country",
                        location_note(c),
                    ));
                }
                Some(_) => bad(
                    "location/country",
                    "invalid_string",
                    "expected an ISO 3166-1 alpha-2 code",
                ),
            }
            match l.get("languages") {
                None | Some(Value::Null) => {}
                Some(Value::Array(a)) => {
                    for (i, v) in a.iter().enumerate() {
                        match v.as_str().map(str::trim).filter(|s| !s.is_empty()) {
                            Some(s) => {
                                let alone = Location {
                                    languages: vec![s.to_owned()],
                                    ..Location::default()
                                };
                                if locale::http_accept_language(&alone).is_none() {
                                    warnings.push(Warning::new(
                                        "invalid_language_tag",
                                        &format!("/location/languages/{i}"),
                                        format!("`{s}` is not a BCP 47 language tag and was ignored"),
                                    ));
                                }
                                location.languages.push(s.to_owned());
                            }
                            None => bad(
                                &format!("location/languages/{i}"),
                                "invalid_type",
                                "expected a language tag",
                            ),
                        }
                    }
                }
                Some(_) => bad(
                    "location/languages",
                    "invalid_type",
                    "expected an array of strings",
                ),
            }
        }
        Some(_) => bad("location", "invalid_type", "expected an object"),
    }
    let Some(seed) = seed.filter(|_| details.is_empty()) else {
        return Err(HttpError::bad_request(details));
    };
    Ok(MapRequest {
        seed,
        search,
        sitemap,
        include_subdomains,
        ignore_query,
        ignore_cache,
        limit: usize::try_from(limit).unwrap_or(usize::MAX),
        wait,
        location,
        warnings,
    })
}

/// The `location_no_proxy` message: crawlx emulates a country with an `Accept-Language` header.
fn location_note(country: &str) -> String {
    if locale::country_profile(country).is_some() {
        format!(
            "crawlx has no geo-located proxies: `{country}` is emulated with an Accept-Language header, not a proxy in that country"
        )
    } else {
        format!(
            "crawlx has no geo-located proxies and `{country}` has no entry in the locale table: only `languages` set the Accept-Language header"
        )
    }
}

/// The run that maps `req`.
fn map_crawl(req: &MapRequest) -> Result<CreateCrawl, HttpError> {
    let mut c = CreateCrawl::new(req.seed.clone());
    c.mode = CrawlMode::Static;
    // the seed is the only page fetched; every other URL ends as a `depth_exceeded` row
    c.limits.urls = 1;
    c.scope.max_discovery_depth = 0;
    c.scope.sitemap = req.sitemap;
    c.scope.crawl_entire_domain = true;
    c.scope.host_scope = if req.include_subdomains {
        HostScope::Rdn
    } else {
        HostScope::Fqdn
    };
    c.scope.query_policy = if req.ignore_query {
        QueryPolicy::StripAll
    } else {
        QueryPolicy::KeepAll
    };
    c.output.formats = vec![OutputFormat::Metadata];
    c.retention.days = 1;
    if let Some(value) = locale::http_accept_language(&req.location) {
        c.fetch.set_header("Accept-Language", &value).map_err(|e| {
            HttpError::bad_request(vec![Detail::new(
                "/location/languages",
                "invalid_header",
                e.to_string(),
            )])
        })?;
    }
    c.scrape = Some(ScrapeJob::new(JobKind::Map, ScrapeOptions::default()));
    Ok(c)
}

/// The key two URLs share when they are the same map entry.
fn dedupe_key(url: &Url, ignore_query: bool) -> String {
    let mut u = url.clone();
    u.set_fragment(None);
    if ignore_query {
        u.set_query(None);
    }
    let mut s = u.to_string();
    if u.path() != "/" && s.ends_with('/') && u.query().is_none() {
        s.pop();
    }
    s
}

/// The listed URL: the stored canonical URL without fragment (and without query under
/// `ignoreQueryParameters`).
fn listed_url(url: &Url, ignore_query: bool) -> String {
    let mut u = url.clone();
    u.set_fragment(None);
    if ignore_query {
        u.set_query(None);
    }
    u.to_string()
}

/// One entry of a map: the listed URL with its title and description (blank ones are dropped).
fn map_item(url: &Url, ignore_query: bool, title: Option<String>, description: Option<String>) -> MapItem {
    MapItem {
        url: listed_url(url, ignore_query),
        title: title.filter(|t| !t.trim().is_empty()),
        description: description.filter(|d| !d.trim().is_empty()),
    }
}

/// The links of a finished map run: the seed page (when it was fetched) and every
/// `depth_exceeded` row, in discovery order, one per canonical URL.
fn collect_links(frontier: &[FrontierEntry], pages: &[PageRecord], ignore_query: bool) -> Vec<MapItem> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut push = |url: &Url, title: Option<String>, description: Option<String>| {
        if seen.insert(dedupe_key(url, ignore_query)) {
            out.push(map_item(url, ignore_query, title, description));
        }
    };
    let mut rows: Vec<&FrontierEntry> = frontier.iter().collect();
    rows.sort_by_key(|r| r.id);
    for row in rows {
        match row.status {
            FrontierStatus::Succeeded => {
                let page = pages.iter().find(|p| p.frontier_id == row.id);
                let title = page.and_then(|p| p.title.clone());
                let description = page
                    .and_then(|p| p.metadata.get("description"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                push(&row.url.url, title, description);
            }
            FrontierStatus::PolicyBlocked if row.denial_reason.as_deref() == Some(LISTED) => {
                push(&row.url.url, None, None);
            }
            _ => {}
        }
    }
    out
}

/// A URL a stored page contributes to a map, with the page's title and description.
struct Stored {
    url: Url,
    title: Option<String>,
    description: Option<String>,
}

/// The stored pages of the map's site and the scope rule the live map applies to their URLs.
struct StoredSources {
    policy: ScopePolicy,
    pages: Vec<KnownPage>,
}

impl StoredSources {
    /// Would the live map list `url`? True for exactly the URLs the worker records as
    /// `depth_exceeded` rows: those that pass the exclude-hosts, host-scope, pattern and extension
    /// rules and are only too deep (the map follows no link).
    fn lists(&self, url: &Url) -> bool {
        matches!(
            self.policy.decide_url(url, 1),
            ScopeVerdict::Denied(DenialReason::DepthExceeded { .. })
        )
    }

    /// The URLs the stored pages contribute, in listing order: the pages' own URLs (newest page
    /// first, with title and description), then the links found on those pages in the same order;
    /// only URLs the live map would list.
    fn urls(&self) -> impl Iterator<Item = Stored> + '_ {
        let own = self.pages.iter().map(|p| Stored {
            url: p.url.url.clone(),
            title: p.title.clone(),
            description: p.description.clone(),
        });
        let linked = self
            .pages
            .iter()
            .flat_map(|p| p.links.iter())
            .filter_map(|l| Url::parse(l).ok())
            .map(|url| Stored {
                url,
                title: None,
                description: None,
            });
        own.chain(linked).filter(|s| self.lists(&s.url))
    }
}

/// The stored pages `req` reads, or `None` when it reads none (`ignoreCache`, or `sitemap: only`,
/// which lists exactly the sitemap). Read before the map's own run exists, so its pages never
/// count as stored ones.
async fn stored_sources(
    state: &AppState,
    tenant: TenantId,
    req: &MapRequest,
    crawl: &CreateCrawl,
) -> ApiResult<Option<StoredSources>> {
    if req.ignore_cache || req.sitemap == SitemapMode::Only {
        return Ok(None);
    }
    let Some(host) = req.seed.host_str() else {
        return Ok(None);
    };
    let policy = ScopePolicy::new(crawl).map_err(|e| {
        tracing::error!(error = %e, "map scope rule did not compile");
        HttpError::internal()
    })?;
    let (domain, subdomains) = if req.include_subdomains {
        (policy.host_scope().registrable_domain(), true)
    } else {
        (host, false)
    };
    let pages = state
        .repos
        .pages
        .known_pages(tenant, domain, subdomains, state.clock.now(), STORED_PAGES)
        .await?;
    Ok(Some(StoredSources { policy, pages }))
}

/// `items` extended with the first `cap` URLs of `stored` that no entry of `items` (nor an
/// earlier stored URL) already lists, and how many were added. `items` keep their order and come
/// first.
fn merge_stored(
    items: Vec<MapItem>,
    stored: impl Iterator<Item = Stored>,
    ignore_query: bool,
    cap: usize,
) -> (Vec<MapItem>, usize) {
    let mut seen: BTreeSet<String> = items
        .iter()
        .filter_map(|i| Url::parse(&i.url).ok())
        .map(|u| dedupe_key(&u, ignore_query))
        .collect();
    let mut out = items;
    let mut added = 0;
    for s in stored {
        if added >= cap {
            break;
        }
        if seen.insert(dedupe_key(&s.url, ignore_query)) {
            out.push(map_item(&s.url, ignore_query, s.title, s.description));
            added += 1;
        }
    }
    (out, added)
}

/// Map `url` for `principal`'s tenant with the Firecrawl map `options` (an object; `url` in it
/// is ignored) and return the listed links with the request's warnings. The usage ledger is
/// charged one credit.
async fn run_map(
    state: &AppState,
    principal: &Principal,
    url: &str,
    options: &Value,
) -> ApiResult<(Vec<MapEntry>, Vec<Warning>)> {
    let req = parse_request(url, options)?;
    let mut warnings = req.warnings.clone();
    let crawl = map_crawl(&req)?;
    let stored = stored_sources(state, principal.tenant, &req, &crawl).await?;
    let run = create_scrape_run(state, principal, crawl, &mut warnings)
        .await
        .map_err(concurrency_limit)?;
    let run = wait_for_run(state, run.id, req.wait).await?;
    let frontier = state.repos.frontier.list(run.id).await?;
    let pages = state.repos.pages.list(run.id).await?;
    let items = collect_links(&frontier, &pages, req.ignore_query);
    if items.is_empty() && run.status != RunStatus::Completed {
        usage::record(
            state,
            principal.tenant,
            "map",
            Some(run.id.0),
            "failed",
            Cost::credits(0),
        )
        .await;
        return Err(run_failure(state, &run).await);
    }
    if items.is_empty() {
        // a seed that could not be fetched and a site without links: Firecrawl answers the failure
        let seed_failed = frontier
            .iter()
            .any(|r| r.depth == 0 && !matches!(r.status, FrontierStatus::Succeeded));
        if seed_failed {
            usage::record(
                state,
                principal.tenant,
                "map",
                Some(run.id.0),
                "failed",
                Cost::credits(0),
            )
            .await;
            return Err(run_failure(state, &run).await);
        }
    }
    let items = match &stored {
        Some(sources) => {
            let (items, added) = merge_stored(items, sources.urls(), req.ignore_query, STORED_URLS);
            if added > 0 {
                warnings.push(Warning::new(
                    "map_cached_sources",
                    "/ignoreCache",
                    format!(
                        "{added} URLs of earlier crawls and scrapes of this site were added to the live results; set `ignoreCache: true` to list live results only"
                    ),
                ));
            }
            items
        }
        None => items,
    };
    let ranked = match &req.search {
        Some(q) => rank(q, items),
        None => items,
    };
    let links = ranked
        .into_iter()
        .take(req.limit)
        .map(|i| MapEntry {
            url: i.url,
            title: i.title,
            description: i.description,
        })
        .collect();
    usage::record(
        state,
        principal.tenant,
        "map",
        Some(run.id.0),
        "completed",
        Cost::credits(1),
    )
    .await;
    Ok((links, warnings))
}

/// Map `url` with Firecrawl map `options`; the body of [`crate::scrape_service::map_site`].
///
/// # Errors
/// `400 BAD_REQUEST` for an invalid URL or option, `403 UNSUPPORTED_SITE` for a target the egress
/// policy denies, `429` above the active-run quota, `408 SCRAPE_TIMEOUT` when `timeout` passes
/// before the run ends, the Firecrawl failure of the seed when nothing could be listed.
pub async fn map_links(
    state: &AppState,
    principal: &Principal,
    url: &str,
    options: &Value,
) -> ApiResult<Vec<MapEntry>> {
    Ok(run_map(state, principal, url, options).await?.0)
}

/// `POST /compat/firecrawl/v2/map`: `{success: true, links: [{url, title?, description?}]}`
/// (plus the additive `warnings[]`: options that were not applied, `location_no_proxy` for a
/// `location.country`, `map_cached_sources` when stored URLs were added).
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, and everything [`map_links`] answers.
pub async fn map(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let Some(obj) = body.as_object() else {
        return Err(HttpError::bad_request(vec![Detail::new(
            "/",
            "invalid_type",
            "body must be a JSON object",
        )]));
    };
    let Some(url) = obj.get("url").and_then(Value::as_str) else {
        return Err(HttpError::bad_request(vec![Detail::new(
            "/url",
            "required",
            "url is required",
        )]));
    };
    let (links, warnings) = run_map(&state, &principal, url, &body).await?;
    let links: Vec<Value> = links
        .into_iter()
        .map(|l| {
            let mut o = Map::new();
            o.insert("url".to_owned(), json!(l.url));
            if let Some(t) = l.title {
                o.insert("title".to_owned(), json!(t));
            }
            if let Some(d) = l.description {
                o.insert("description".to_owned(), json!(d));
            }
            Value::Object(o)
        })
        .collect();
    let mut out = json!({ "success": true, "links": links });
    if let (false, Some(o)) = (warnings.is_empty(), out.as_object_mut()) {
        o.insert("warnings".to_owned(), json!(warnings));
    }
    Ok(json_response(StatusCode::OK, &out))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::Utc;
    use crawlx_core::hash::Digest;
    use crawlx_core::{CrawlRunId, TrustLane};
    use crawlx_storage::testkit;

    fn row(id: i64, url: &str, status: FrontierStatus, reason: Option<&str>) -> FrontierEntry {
        FrontierEntry {
            id,
            run: CrawlRunId::new(),
            url: testkit::canonical_url(url),
            depth: u16::from(id > 1),
            status,
            denial_reason: reason.map(str::to_owned),
            attempts: 1,
            discovered_from: None,
        }
    }

    fn page(frontier_id: i64, url: &str, title: &str, description: &str) -> PageRecord {
        PageRecord {
            run: CrawlRunId::new(),
            frontier_id,
            url: testkit::canonical_url(url),
            status: 200,
            content_type: Some("text/html".to_owned()),
            content_digest: Digest::of("t", b"x"),
            title: Some(title.to_owned()),
            markdown: None,
            html: None,
            metadata: json!({ "description": description }),
            links: Vec::new(),
            fetched_at: Utc::now(),
            lane: TrustLane::Diagnostic,
        }
    }

    #[test]
    fn parse_applies_the_firecrawl_defaults() {
        let r = parse_request(
            "https://a.example.test",
            &json!({"url": "https://a.example.test"}),
        )
        .unwrap();
        assert_eq!(r.sitemap, SitemapMode::Include);
        assert!(r.include_subdomains && r.ignore_query);
        assert_eq!(r.limit, 5000);
        assert_eq!(r.wait, DEFAULT_WAIT);
        assert!(r.search.is_none() && r.warnings.is_empty());
        let c = map_crawl(&r).unwrap();
        assert_eq!(c.scope.host_scope, HostScope::Rdn);
        assert_eq!(c.scope.query_policy, QueryPolicy::StripAll);
        assert_eq!(c.scope.max_discovery_depth, 0);
        assert_eq!(c.scrape.as_ref().unwrap().kind, JobKind::Map);
        assert_eq!(c.output.formats, vec![OutputFormat::Metadata]);
    }

    #[test]
    fn parse_reads_every_option() {
        let r = parse_request(
            "a.example.test",
            &json!({
                "search": "blog", "sitemap": "only", "includeSubdomains": false,
                "ignoreQueryParameters": false, "ignoreCache": true, "limit": 7, "timeout": 1500,
                "location": {"country": "DE", "languages": ["de-DE", "en"]},
                "threatProtection": {"mode": "off"}, "mystery": 1,
            }),
        )
        .unwrap();
        assert_eq!(r.search.as_deref(), Some("blog"));
        assert_eq!(r.sitemap, SitemapMode::Only);
        assert!(!r.include_subdomains && !r.ignore_query);
        assert_eq!((r.limit, r.wait), (7, Duration::from_millis(1500)));
        assert_eq!(r.seed.as_str(), "http://a.example.test/");
        assert!(r.ignore_cache);
        let w: Vec<(&str, &str)> = r
            .warnings
            .iter()
            .map(|w| (w.code.as_str(), w.path.as_str()))
            .collect();
        assert_eq!(
            w,
            [
                ("unsupported_option", "/mystery"),
                ("unsupported_option", "/threatProtection"),
                ("location_no_proxy", "/location/country")
            ],
            "ignoreCache and the country are applied now: only the country's proxy is reported"
        );
        let c = map_crawl(&r).unwrap();
        assert_eq!(c.scope.host_scope, HostScope::Fqdn);
        assert_eq!(
            c.fetch.extra_headers.get("accept-language"),
            Some("de-DE,en;q=0.9")
        );
    }

    #[test]
    fn a_country_alone_sets_its_main_language_and_languages_keep_their_position() {
        let header = |location: Value| {
            let r = parse_request("https://a.example.test", &json!({ "location": location })).unwrap();
            map_crawl(&r)
                .unwrap()
                .fetch
                .extra_headers
                .get("accept-language")
                .map(str::to_owned)
        };
        assert_eq!(header(json!({"country": "DE"})).as_deref(), Some("de-DE"));
        assert_eq!(
            header(json!({"country": "DE", "languages": ["fr", "de-DE", "en"]})).as_deref(),
            Some("fr,de-DE;q=0.9,en;q=0.8"),
            "an explicit list wins and keeps its order"
        );
        assert_eq!(header(json!({"languages": ["en-GB"]})).as_deref(), Some("en-GB"));
        assert_eq!(header(json!({})), None);
        assert_eq!(
            header(json!({"country": "ZZ"})),
            None,
            "a country without a table entry names no language"
        );
        let r = parse_request(
            "https://a.example.test",
            &json!({"location": {"country": "ZZ", "languages": ["not a tag", "en"]}}),
        )
        .unwrap();
        let w: Vec<(&str, &str)> = r
            .warnings
            .iter()
            .map(|w| (w.code.as_str(), w.path.as_str()))
            .collect();
        assert_eq!(
            w,
            [
                ("location_no_proxy", "/location/country"),
                ("invalid_language_tag", "/location/languages/0")
            ]
        );
        assert!(r.warnings[0].message.contains("no entry in the locale table"));
        assert_eq!(
            map_crawl(&r).unwrap().fetch.extra_headers.get("accept-language"),
            Some("en"),
            "the invalid tag is dropped before the header is written"
        );
    }

    #[test]
    fn parse_reports_every_violation() {
        let err = parse_request(
            "ftp://x",
            &json!({"limit": 100_001, "sitemap": "x", "includeSubdomains": "yes", "timeout": 0, "search": 1}),
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        let paths: Vec<&str> = err.details.iter().map(|d| d.path.as_str()).collect();
        for p in [
            "/url",
            "/limit",
            "/sitemap",
            "/includeSubdomains",
            "/timeout",
            "/search",
        ] {
            assert!(paths.contains(&p), "{p} in {paths:?}");
        }
        assert!(parse_request("https://a.example.test", &json!([1])).is_err());
    }

    #[test]
    fn links_are_the_seed_plus_the_listed_rows_without_duplicates() {
        let frontier = vec![
            row(1, "https://a.example.test/", FrontierStatus::Succeeded, None),
            row(
                2,
                "https://a.example.test/docs",
                FrontierStatus::PolicyBlocked,
                Some("depth_exceeded"),
            ),
            row(
                3,
                "https://a.example.test/docs/",
                FrontierStatus::PolicyBlocked,
                Some("depth_exceeded"),
            ),
            row(
                4,
                "https://a.example.test/p?x=1#top",
                FrontierStatus::PolicyBlocked,
                Some("depth_exceeded"),
            ),
            row(
                5,
                "https://a.example.test/p?x=2",
                FrontierStatus::PolicyBlocked,
                Some("depth_exceeded"),
            ),
            row(
                6,
                "https://other.example.test/",
                FrontierStatus::PolicyBlocked,
                Some("external"),
            ),
            row(
                7,
                "https://a.example.test/dedupe",
                FrontierStatus::PolicyBlocked,
                Some("dedupe:fingerprint"),
            ),
            row(
                8,
                "https://a.example.test/bad",
                FrontierStatus::Failed,
                Some("http_500"),
            ),
        ];
        let pages = vec![page(1, "https://a.example.test/", "Home", "The home page")];
        let urls = |ignore: bool| {
            collect_links(&frontier, &pages, ignore)
                .into_iter()
                .map(|i| i.url)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            urls(true),
            [
                "https://a.example.test/",
                "https://a.example.test/docs",
                "https://a.example.test/p"
            ]
        );
        assert_eq!(
            urls(false),
            [
                "https://a.example.test/",
                "https://a.example.test/docs",
                "https://a.example.test/p?x=1",
                "https://a.example.test/p?x=2"
            ]
        );
        let first = &collect_links(&frontier, &pages, true)[0];
        assert_eq!(first.title.as_deref(), Some("Home"));
        assert_eq!(first.description.as_deref(), Some("The home page"));
    }

    #[test]
    fn search_orders_the_links_and_limit_cuts_them() {
        let items = vec![
            MapItem {
                url: "https://a.example.test/".into(),
                title: None,
                description: None,
            },
            MapItem {
                url: "https://a.example.test/about".into(),
                title: None,
                description: None,
            },
            MapItem {
                url: "https://a.example.test/blog/post".into(),
                title: None,
                description: None,
            },
        ];
        let ranked = rank("blog", items);
        assert_eq!(ranked[0].url, "https://a.example.test/blog/post");
        assert_eq!(ranked.len(), 3, "search orders, it never drops");
    }

    fn known(url: &str, title: Option<&str>, links: &[&str]) -> KnownPage {
        KnownPage {
            url: testkit::canonical_url(url),
            title: title.map(str::to_owned),
            description: title.map(|t| format!("{t} description")),
            links: links.iter().map(|l| (*l).to_owned()).collect(),
        }
    }

    fn sources(seed: &str, options: &Value, pages: Vec<KnownPage>) -> StoredSources {
        let req = parse_request(seed, options).unwrap();
        StoredSources {
            policy: ScopePolicy::new(&map_crawl(&req).unwrap()).unwrap(),
            pages,
        }
    }

    #[test]
    fn stored_urls_are_the_pages_then_their_links_inside_the_map_scope_only() {
        let s = sources(
            "https://a.example.test/",
            &json!({}),
            vec![
                known(
                    "https://a.example.test/new",
                    Some("New"),
                    &[
                        "https://a.example.test/linked",
                        "https://a.example.test/logo.png",
                        "https://elsewhere.test/out",
                        "not a url",
                    ],
                ),
                known("https://www.a.example.test/blog", None, &["/relative"]),
                known("https://elsewhere.test/page", None, &[]),
            ],
        );
        let got: Vec<(String, Option<String>)> = s.urls().map(|u| (u.url.to_string(), u.title)).collect();
        assert_eq!(
            got,
            [
                ("https://a.example.test/new".to_owned(), Some("New".to_owned())),
                ("https://www.a.example.test/blog".to_owned(), None),
                ("https://a.example.test/linked".to_owned(), None),
            ],
            "own URLs first (newest page first), then links; images, other sites, relative and invalid links never"
        );
        let fqdn = sources(
            "https://a.example.test/",
            &json!({"includeSubdomains": false}),
            s.pages.clone(),
        );
        let urls: Vec<String> = fqdn.urls().map(|u| u.url.to_string()).collect();
        assert_eq!(
            urls,
            ["https://a.example.test/new", "https://a.example.test/linked"],
            "a subdomain is a different host under includeSubdomains: false"
        );
    }

    #[test]
    fn stored_urls_follow_the_live_results_without_duplicates_and_respect_the_cap() {
        let live = vec![
            MapItem {
                url: "https://a.example.test/".into(),
                title: Some("Home".into()),
                description: None,
            },
            MapItem {
                url: "https://a.example.test/docs".into(),
                title: None,
                description: None,
            },
        ];
        let stored = || {
            [
                "https://a.example.test/docs/",
                "https://a.example.test/p?x=1#top",
                "https://a.example.test/p?x=2",
                "https://a.example.test/new",
            ]
            .into_iter()
            .map(|u| Stored {
                url: Url::parse(u).unwrap(),
                title: Some("From the store".to_owned()),
                description: None,
            })
        };
        let (items, added) = merge_stored(live.clone(), stored(), true, 100);
        let urls: Vec<&str> = items.iter().map(|i| i.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "https://a.example.test/",
                "https://a.example.test/docs",
                "https://a.example.test/p",
                "https://a.example.test/new"
            ],
            "live results keep their entries and order; the stored ones are deduplicated like live ones"
        );
        assert_eq!(added, 2);
        assert_eq!(
            items[1].title, None,
            "a live entry is never replaced by a stored one"
        );
        assert_eq!(items[3].title.as_deref(), Some("From the store"));

        let (items, added) = merge_stored(live.clone(), stored(), false, 100);
        assert_eq!(
            items.len(),
            5,
            "with the query kept, `?x=1` and `?x=2` are different URLs"
        );
        assert_eq!(added, 3);
        let (items, added) = merge_stored(live.clone(), stored(), true, 1);
        assert_eq!((items.len(), added), (3, 1), "at most `cap` URLs are added");
        let (items, added) = merge_stored(live, std::iter::empty(), true, 10);
        assert_eq!((items.len(), added), (2, 0));
    }
}
