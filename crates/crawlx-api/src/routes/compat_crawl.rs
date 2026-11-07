//! Firecrawl v2 crawl request translation (`POST /crawl`) and the crawl endpoints that are
//! neither start, status nor cancel: `GET /crawl/active` and `POST /crawl/params-preview`.
//!
//! [`translate`] turns a Firecrawl crawl body into a [`CreateCrawl`] whose `scrape` job
//! (`kind: crawl`) carries the per-page `scrapeOptions`: every page of the run is produced by the
//! worker's scrape engine. Options crawlx cannot honour are reported in the additive
//! `warnings[]`, never dropped silently:
//!
//! | Firecrawl | crawlx |
//! |---|---|
//! | `includePaths` / `excludePaths` | `scope.includePaths` / `excludePaths` (URL pathname regexes) |
//! | the same with `regexOnFullURL: true` | `scope.urlInclude` / `urlExclude` (full URL regexes) |
//! | `maxDiscoveryDepth`, `sitemap`, `crawlEntireDomain`, `allowSubdomains` | the `scope` fields of the same name |
//! | `allowExternalLinks` | `scope.allowExternalLinks`: external pages are fetched as leaves (one hop), external homepages are skipped and reported as `EXTERNAL_LINK` |
//! | `ignoreQueryParameters` | `scope.queryPolicy` (`strip_all`, else `keep_all`) |
//! | `deduplicateSimilarURLs` (default `true`, Firecrawl's: URL normalization) | no per-request counterpart: `crawlx-url` canonicalization always merges equivalent URLs (host case, default port, fragment, query order; a trailing slash stays a distinct URL under the worker's default `Keep` policy). An explicit `false` is accepted with an `unsupported_option` warning and not honoured. Never `scope.filterSimilar` (the URL-shape filter stays at its native default `false`) |
//! | `delay` (seconds) | `politeness.delayMs`, and concurrency 1 (Firecrawl: "delay forces concurrency to 1") |
//! | `maxConcurrency` | `politeness.maxConcurrency` (1..=256) and `maxInFlightPerOrigin` (at most 8) |
//! | `robotsUserAgent` | `fetch.robotsUserAgent` |
//! | `ignoreRobotsTxt` | `safety.respectRobotsTxt = false` under the facade's authorization record (`compat.robotsAuthorization`; [`crate::routes::compat::create`] attaches it), else `403 ROBOTS_OVERRIDE_NOT_AUTHORIZED` |
//! | `webhook{url, headers, metadata, events}` | `output.webhook{url, events}` + `scrape.webhookHeaders` / `webhookMetadata` |
//! | `zeroDataRetention` | `retention.mode = zdr` |
//! | `scrapeOptions` | [`crate::scrape_service::parse_scrape_options`] |
//! | `prompt` | crawl options planned by the configured LLM; explicit options win |
//!
//! v1 spellings are accepted with a `deprecated_option` warning: `maxDepth` (for
//! `maxDiscoveryDepth`), `ignoreSitemap` (`true` is `sitemap: skip`), `allowBackwardLinks` (for
//! `crawlEntireDomain`), the `crawlerOptions` wrapper object, and `scrapeOptions.extract` /
//! `jsonOptions` (handled by the scrape options parser).

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::common::{llm, llm_error};
use crate::intel::usage::{self, Cost};
use crate::intel::webhook::JobWebhook;
use crate::openapi::Operation;
use crate::resources::Warning;
use crate::routes::compat::facade_status;
use crate::scrape_service::{parse_scrape_options, parse_target};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use crawlx_core::config::{
    CrawlMode, CreateCrawl, QueryPolicy, RetentionMode, SitemapMode, Webhook, MAX_PATH_PATTERNS,
    MAX_PATH_PATTERN_LEN,
};
use crawlx_core::scrape::{JobKind, ScrapeOptions};
use crawlx_core::StoreError;
use serde_json::{json, Map, Value};

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "get",
        "/compat/firecrawl/v2/crawl/active",
        "firecrawlActiveCrawls",
        "Firecrawl v2 crawl facade: the tenant's queued, running and paused crawls",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/compat/firecrawl/v2/crawl/params-preview",
        "firecrawlCrawlParamsPreview",
        "Firecrawl v2 crawl facade: crawl options the configured LLM derives from a prompt",
        "crawls:write",
        "200",
    ),
];

/// Routes of this module, mounted behind authentication.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/firecrawl/v2/crawl/active", get(active))
        .route("/compat/firecrawl/v2/crawl/params-preview", post(params_preview))
}

/// Request keys of a crawl body (after v1 aliases are resolved); everything else warns.
const KNOWN: [&str; 21] = [
    "url",
    "prompt",
    "limit",
    "includePaths",
    "excludePaths",
    "regexOnFullURL",
    "maxDiscoveryDepth",
    "sitemap",
    "ignoreQueryParameters",
    "crawlEntireDomain",
    "allowExternalLinks",
    "allowSubdomains",
    "ignoreRobotsTxt",
    "robotsUserAgent",
    "delay",
    "maxConcurrency",
    "webhook",
    "scrapeOptions",
    "zeroDataRetention",
    "deduplicateSimilarURLs",
    // SDK bookkeeping that carries no behaviour
    "integration",
];

/// SDK bookkeeping keys that are accepted without a warning.
const SILENT: [&str; 1] = ["origin"];

/// Webhook event names of a crawl (Firecrawl accepts them with or without the `crawl.` prefix).
pub(crate) const WEBHOOK_EVENTS: [&str; 4] = ["started", "page", "completed", "failed"];

/// Most patterns of one `includePaths` / `excludePaths` list (Firecrawl limit).
const MAX_PATTERNS: usize = MAX_PATH_PATTERNS;
/// Longest pattern in bytes (Firecrawl limit).
const MAX_PATTERN_LEN: usize = MAX_PATH_PATTERN_LEN;
/// `politeness.maxInFlightPerOrigin` ceiling.
const MAX_PER_ORIGIN: u64 = 8;

/// A translated crawl request.
#[derive(Debug)]
pub(crate) struct Translated {
    /// The run to create.
    pub crawl: CreateCrawl,
    /// `warnings[]` of the response.
    pub warnings: Vec<Warning>,
    /// The request carried `ignoreRobotsTxt: true`: the caller asks for
    /// `safety.respectRobotsTxt = false`, which admission only allows under an authorization
    /// record. [`crate::routes::compat::create`] attaches the facade's record (or answers `403`);
    /// the translation itself keeps robots.txt respected.
    pub robots_override: bool,
}

fn warn(code: &str, path: &str, message: impl Into<String>) -> Warning {
    Warning::new(code, path, message)
}

fn deprecated(old: &str, new: &str) -> Warning {
    warn(
        "deprecated_option",
        &format!("/{old}"),
        format!("`{old}` is a v1 option; it was read as `{new}`"),
    )
}

/// Violations and warnings collected while reading one request object.
struct Cx {
    m: Map<String, Value>,
    details: Vec<Detail>,
    warnings: Vec<Warning>,
}

impl Cx {
    fn bad(&mut self, key: &str, code: &str, message: &str) {
        self.details.push(Detail::new(format!("/{key}"), code, message));
    }

    fn boolean(&mut self, key: &str) -> Option<bool> {
        match self.m.get(key)? {
            Value::Bool(b) => Some(*b),
            Value::Null => None,
            _ => {
                self.bad(key, "invalid_type", "expected a boolean");
                None
            }
        }
    }

    fn uint(&mut self, key: &str, min: u64, max: u64) -> Option<u64> {
        match self.m.get(key)? {
            Value::Null => None,
            v => match v.as_u64() {
                Some(n) if (min..=max).contains(&n) => Some(n),
                Some(_) => {
                    self.bad(key, "out_of_range", &format!("must be between {min} and {max}"));
                    None
                }
                None => {
                    self.bad(key, "invalid_type", "expected a non-negative integer");
                    None
                }
            },
        }
    }

    fn number(&mut self, key: &str) -> Option<f64> {
        match self.m.get(key)? {
            Value::Null => None,
            v => match v.as_f64().filter(|d| d.is_finite() && *d >= 0.0) {
                Some(d) => Some(d),
                None => {
                    self.bad(key, "out_of_range", "expected a non-negative number");
                    None
                }
            },
        }
    }

    fn string(&mut self, key: &str) -> Option<String> {
        match self.m.get(key)? {
            Value::Null => None,
            Value::String(s) => Some(s.clone()),
            _ => {
                self.bad(key, "invalid_type", "expected a string");
                None
            }
        }
    }

    /// A list of regex strings: at most [`MAX_PATTERNS`] of at most [`MAX_PATTERN_LEN`] bytes.
    fn patterns(&mut self, key: &str) -> Option<Vec<String>> {
        let list = match self.m.get(key)? {
            Value::Null => return None,
            Value::Array(a) => a.clone(),
            _ => {
                self.bad(key, "invalid_type", "expected an array of strings");
                return None;
            }
        };
        if list.len() > MAX_PATTERNS {
            self.bad(key, "out_of_range", &format!("at most {MAX_PATTERNS} patterns"));
            return None;
        }
        let mut out = Vec::with_capacity(list.len());
        for (i, v) in list.iter().enumerate() {
            match v.as_str() {
                Some(s) if s.len() <= MAX_PATTERN_LEN => out.push(s.to_owned()),
                Some(_) => self.details.push(Detail::new(
                    format!("/{key}/{i}"),
                    "out_of_range",
                    format!("patterns are at most {MAX_PATTERN_LEN} characters"),
                )),
                None => self.details.push(Detail::new(
                    format!("/{key}/{i}"),
                    "invalid_type",
                    "expected a string",
                )),
            }
        }
        Some(out)
    }
}

/// Move the v1 spellings of `m` to their v2 names (the v2 name wins when both are present).
fn resolve_aliases(m: &mut Map<String, Value>, warnings: &mut Vec<Warning>, details: &mut Vec<Detail>) {
    for (old, new) in [
        ("maxDepth", "maxDiscoveryDepth"),
        ("allowBackwardLinks", "crawlEntireDomain"),
    ] {
        if let Some(v) = m.remove(old) {
            warnings.push(deprecated(old, new));
            m.entry(new.to_owned()).or_insert(v);
        }
    }
    if let Some(v) = m.remove("ignoreSitemap") {
        warnings.push(deprecated("ignoreSitemap", "sitemap"));
        match v {
            Value::Bool(skip) => {
                m.entry("sitemap".to_owned())
                    .or_insert_with(|| json!(if skip { "skip" } else { "include" }));
            }
            Value::Null => {}
            _ => details.push(Detail::new(
                "/ignoreSitemap",
                "invalid_type",
                "expected a boolean",
            )),
        }
    }
}

/// The effective request object: planned options (from `prompt`) under the v1 `crawlerOptions`
/// wrapper under the top-level keys.
fn effective(
    body: &Value,
    plan: Option<&Map<String, Value>>,
    warnings: &mut Vec<Warning>,
    details: &mut Vec<Detail>,
) -> Option<Map<String, Value>> {
    let Some(obj) = body.as_object() else {
        details.push(Detail::new("/", "invalid_type", "body must be a JSON object"));
        return None;
    };
    let mut top = obj.clone();
    let wrapper = match top.remove("crawlerOptions") {
        Some(Value::Object(w)) => {
            warnings.push(warn(
                "deprecated_option",
                "/crawlerOptions",
                "`crawlerOptions` is a v1 wrapper; its keys were read as top-level options",
            ));
            Some(w)
        }
        Some(Value::Null) | None => None,
        Some(_) => {
            details.push(Detail::new(
                "/crawlerOptions",
                "invalid_type",
                "expected an object",
            ));
            None
        }
    };
    let mut wrapped = wrapper.unwrap_or_default();
    resolve_aliases(&mut wrapped, warnings, details);
    resolve_aliases(&mut top, warnings, details);
    let mut out = plan.cloned().unwrap_or_default();
    out.extend(wrapped);
    out.extend(top);
    Some(out)
}

/// `webhook` with the `crawl.` / `batch_scrape.` prefix stripped from `events`.
fn strip_event_prefixes(v: &Value) -> Value {
    let Some(obj) = v.as_object() else {
        return v.clone();
    };
    let mut out = obj.clone();
    if let Some(Value::Array(events)) = out.get_mut("events") {
        for e in events.iter_mut() {
            if let Some(s) = e.as_str() {
                let bare = s
                    .strip_prefix("crawl.")
                    .or_else(|| s.strip_prefix("batch_scrape."))
                    .unwrap_or(s);
                *e = Value::String(bare.to_owned());
            }
        }
    }
    Value::Object(out)
}

/// Check that every pattern compiles, answering one `invalid_pattern` detail per field.
fn check_patterns(cx: &mut Cx, crawl: &CreateCrawl) {
    use crawlx_url::scope::PathFilter;
    let s = &crawl.scope;
    for (key, include, exclude) in [
        ("includePaths", &s.include_paths, &Vec::new()),
        ("excludePaths", &Vec::new(), &s.exclude_paths),
        ("includePaths", &s.url_include, &Vec::new()),
        ("excludePaths", &Vec::new(), &s.url_exclude),
    ] {
        if let Err(e) = PathFilter::new(include, exclude) {
            cx.bad(key, "invalid_pattern", &e.to_string());
        }
    }
}

/// Translate a Firecrawl crawl request. `plan` is the object `plan_crawl_options` returned for
/// the request's `prompt` (explicit options override it); without a plan a `prompt` only
/// warns.
///
/// # Errors
/// `400 BAD_REQUEST` (every violation in `details`, Firecrawl's error shape) for a missing or
/// invalid `url` and any other invalid value, including a pattern that does not compile, an
/// invalid webhook and a header the fetch controls reject.
pub(crate) fn translate(body: &Value, plan: Option<&Map<String, Value>>) -> ApiResult<Translated> {
    let mut details = Vec::new();
    let mut warnings = Vec::new();
    let Some(m) = effective(body, plan, &mut warnings, &mut details) else {
        return Err(HttpError::bad_request(details));
    };
    let mut cx = Cx { m, details, warnings };
    let url_missing = cx.m.get("url").is_none_or(Value::is_null);

    for k in cx.m.keys().cloned().collect::<Vec<_>>() {
        if !KNOWN.contains(&k.as_str()) && !SILENT.contains(&k.as_str()) {
            cx.warnings.push(warn(
                "unsupported_option",
                &format!("/{k}"),
                format!("option `{k}` is not supported and was ignored"),
            ));
        }
    }
    if cx.m.contains_key("prompt") {
        match cx.string("prompt") {
            Some(_) if plan.is_none() => cx.warnings.push(warn(
                "prompt_ignored",
                "/prompt",
                "prompt-driven option generation is not applied; explicit options were used",
            )),
            _ => {}
        }
    }

    let url_value = cx.m.get("url").cloned();
    let seed = match &url_value {
        Some(Value::String(u)) => match parse_target(u, "/url") {
            Ok(u) => Some(u),
            Err(d) => {
                cx.details.push(d);
                None
            }
        },
        _ if url_missing => {
            cx.details
                .push(Detail::new("/url", "required", "url is required"));
            None
        }
        _ => {
            cx.bad("url", "invalid_type", "url must be a string");
            None
        }
    };

    let limit = cx.uint("limit", 1, u64::from(u32::MAX));
    let include = cx.patterns("includePaths");
    let exclude = cx.patterns("excludePaths");
    let on_full_url = cx.boolean("regexOnFullURL").unwrap_or(false);
    let depth = cx.uint("maxDiscoveryDepth", 0, u64::from(u16::MAX));
    let sitemap = match cx.string("sitemap").as_deref() {
        None => None,
        Some("skip") => Some(SitemapMode::Skip),
        Some("include") => Some(SitemapMode::Include),
        Some("only") => Some(SitemapMode::Only),
        Some(_) => {
            cx.bad("sitemap", "unknown_enum", "sitemap must be skip, include or only");
            None
        }
    };
    let ignore_query = cx.boolean("ignoreQueryParameters").unwrap_or(false);
    let entire_domain = cx.boolean("crawlEntireDomain");
    let external = cx.boolean("allowExternalLinks");
    let subdomains = cx.boolean("allowSubdomains");
    let dedupe = cx.boolean("deduplicateSimilarURLs");
    let ignore_robots = cx.boolean("ignoreRobotsTxt").unwrap_or(false);
    let robots_ua = cx.string("robotsUserAgent").filter(|s| !s.trim().is_empty());
    let delay = cx.number("delay");
    let concurrency = cx.uint("maxConcurrency", 1, u64::from(u32::MAX));
    let zdr = cx.boolean("zeroDataRetention").unwrap_or(false);

    let scrape_options = cx.m.get("scrapeOptions").cloned();
    let parsed = match &scrape_options {
        None | Some(Value::Null) => Some(parse_scrape_options(&Map::new(), "/scrapeOptions")),
        Some(Value::Object(o)) => Some(parse_scrape_options(o, "/scrapeOptions")),
        Some(_) => {
            cx.bad("scrapeOptions", "invalid_type", "scrapeOptions must be an object");
            None
        }
    };
    let parsed = match parsed {
        Some(Ok(p)) => Some(p),
        Some(Err(d)) => {
            cx.details.extend(d);
            None
        }
        None => None,
    };

    let hook = match cx.m.get("webhook").map(strip_event_prefixes) {
        None | Some(Value::Null) => None,
        Some(v) => match JobWebhook::parse(Some(&v), "/webhook", &WEBHOOK_EVENTS) {
            Ok(h) => h,
            Err(e) => {
                cx.details.extend(e.details);
                None
            }
        },
    };

    let Some(seed) = seed.filter(|_| cx.details.is_empty()) else {
        return Err(HttpError::bad_request(cx.details));
    };
    let Some(parsed) = parsed else {
        return Err(HttpError::bad_request(cx.details));
    };

    let mut crawl = CreateCrawl::new(seed);
    crawl.mode = CrawlMode::Static;
    if let Some(n) = limit {
        crawl.limits.urls = u32::try_from(n).unwrap_or(u32::MAX);
    }
    let scope = &mut crawl.scope;
    let (paths_in, paths_out) = if on_full_url {
        (&mut scope.url_include, &mut scope.url_exclude)
    } else {
        (&mut scope.include_paths, &mut scope.exclude_paths)
    };
    if let Some(l) = include {
        *paths_in = l;
    }
    if let Some(l) = exclude {
        *paths_out = l;
    }
    if let Some(n) = depth {
        scope.max_discovery_depth = u16::try_from(n).unwrap_or(u16::MAX);
    }
    if let Some(s) = sitemap {
        scope.sitemap = s;
    }
    scope.query_policy = if ignore_query {
        QueryPolicy::StripAll
    } else {
        QueryPolicy::KeepAll
    };
    scope.crawl_entire_domain = entire_domain.unwrap_or(false);
    scope.allow_external_links = external.unwrap_or(false);
    scope.allow_subdomains = subdomains.unwrap_or(false);
    // `deduplicateSimilarURLs` is URL normalization in Firecrawl, not a URL-shape filter:
    // `scope.filterSimilar` stays at its native default. The URL canonicalizer of `crawlx-url`
    // always merges equivalent URLs (the default `true`, the trailing slash aside: the worker's
    // `TrailingSlash::Keep` is not a per-request setting); an explicit `false` cannot be honoured.
    if dedupe == Some(false) {
        cx.warnings.push(warn(
            "unsupported_option",
            "/deduplicateSimilarURLs",
            "deduplicateSimilarURLs: false is not supported by crawlx and was ignored: URL canonicalization always merges equivalent URLs",
        ));
    }
    if ignore_query {
        cx.warnings.push(warn(
            "query_strip_merges_resources",
            "/ignoreQueryParameters",
            "ignoreQueryParameters strips every query parameter and can merge distinct resources",
        ));
    }
    let robots_override = ignore_robots;
    if let Some(ua) = robots_ua {
        crawl.fetch.robots_user_agent = Some(ua);
    }
    if let Some(d) = delay {
        crawl.politeness.delay_ms = delay_ms(d);
        // Firecrawl: setting `delay` forces concurrency to 1
        crawl.politeness.max_concurrency = 1;
        crawl.politeness.max_in_flight_per_origin = 1;
        if concurrency.is_some() {
            cx.warnings.push(warn(
                "concurrency_forced",
                "/maxConcurrency",
                "delay forces the crawl to one request at a time; maxConcurrency was not applied",
            ));
        }
    } else if let Some(n) = concurrency {
        crawl.politeness.max_concurrency = u16::try_from(n.min(256)).unwrap_or(256);
        crawl.politeness.max_in_flight_per_origin = u8::try_from(n.min(MAX_PER_ORIGIN)).unwrap_or(8);
        if n > 256 {
            cx.warnings.push(warn(
                "limit_clamped",
                "/maxConcurrency",
                "maxConcurrency was clamped to 256",
            ));
        }
    }
    if zdr {
        crawl.retention.mode = RetentionMode::Zdr;
    }
    if let Err(d) = parsed.apply(&mut crawl, JobKind::Crawl) {
        cx.details.extend(d);
    }
    cx.warnings.extend(parsed.warnings.iter().cloned());
    if let Some(h) = hook {
        let events = if h.events.is_empty() {
            WEBHOOK_EVENTS.map(str::to_owned).to_vec()
        } else {
            let mut e = h.events.clone();
            e.dedup();
            e
        };
        crawl.output.webhook = Some(Webhook { url: h.url, events });
        if let Some(job) = crawl.scrape.as_mut() {
            job.webhook_headers = h.headers;
            job.webhook_metadata = h.metadata;
        }
    }
    check_patterns(&mut cx, &crawl);
    if !cx.details.is_empty() {
        return Err(HttpError::bad_request(cx.details));
    }
    Ok(Translated {
        crawl,
        warnings: cx.warnings,
        robots_override,
    })
}

/// Firecrawl `delay` seconds as politeness milliseconds, capped at one minute.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the caller passes a finite non-negative delay and the value is capped at 60 000 before the cast"
)]
fn delay_ms(seconds: f64) -> u32 {
    (seconds * 1000.0).round().min(60_000.0) as u32
}

/// The Firecrawl name of a `scrapeOptions` key of the serialized core options.
const fn firecrawl_key(core: &str) -> Option<&'static str> {
    match core.as_bytes() {
        b"maxAgeMs" => Some("maxAge"),
        b"minAgeMs" => Some("minAge"),
        b"waitForMs" => Some("waitFor"),
        b"timeoutMs" => Some("timeout"),
        _ => None,
    }
}

/// `scrapeOptions` of a stored scrape job as Firecrawl spells them.
fn scrape_options_json(o: &ScrapeOptions) -> Value {
    let Ok(Value::Object(core)) = serde_json::to_value(o) else {
        return json!({});
    };
    let mut out = Map::new();
    for (k, v) in core {
        // request headers may carry credentials: never echoed
        if k == "headers" {
            continue;
        }
        match firecrawl_key(&k) {
            Some(name) => out.insert(name.to_owned(), v),
            None => out.insert(k, v),
        };
    }
    Value::Object(out)
}

/// The Firecrawl-shaped options of a stored crawl: what `GET /crawl/active` returns as
/// `options`. Webhook headers and metadata are never part of it.
pub(crate) fn options_json(config: &CreateCrawl) -> Value {
    let s = &config.scope;
    let full_url = !s.url_include.is_empty() || !s.url_exclude.is_empty();
    let (include, exclude) = if full_url {
        (&s.url_include, &s.url_exclude)
    } else {
        (&s.include_paths, &s.exclude_paths)
    };
    let mut o = Map::new();
    o.insert("limit".to_owned(), json!(config.limits.urls));
    o.insert("includePaths".to_owned(), json!(include));
    o.insert("excludePaths".to_owned(), json!(exclude));
    o.insert("regexOnFullURL".to_owned(), json!(full_url));
    o.insert("maxDiscoveryDepth".to_owned(), json!(s.max_discovery_depth));
    o.insert(
        "sitemap".to_owned(),
        json!(match s.sitemap {
            SitemapMode::Include => "include",
            SitemapMode::Skip => "skip",
            SitemapMode::Only => "only",
        }),
    );
    o.insert(
        "ignoreQueryParameters".to_owned(),
        json!(s.query_policy == QueryPolicy::StripAll),
    );
    o.insert("crawlEntireDomain".to_owned(), json!(s.crawl_entire_domain));
    o.insert("allowExternalLinks".to_owned(), json!(s.allow_external_links));
    o.insert("allowSubdomains".to_owned(), json!(s.allow_subdomains));
    // URL canonicalization always merges equivalent URLs, whatever the request said
    o.insert("deduplicateSimilarURLs".to_owned(), json!(true));
    o.insert(
        "delay".to_owned(),
        json!(f64::from(config.politeness.delay_ms) / 1000.0),
    );
    o.insert(
        "maxConcurrency".to_owned(),
        json!(config.politeness.max_concurrency),
    );
    if let Some(ua) = &config.fetch.robots_user_agent {
        o.insert("robotsUserAgent".to_owned(), json!(ua));
    }
    if let Some(job) = &config.scrape {
        o.insert("scrapeOptions".to_owned(), scrape_options_json(&job.options));
    }
    Value::Object(o)
}

/// `GET /compat/firecrawl/v2/crawl/active`: the tenant's queued, running and paused crawls.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, storage failures.
pub async fn active(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let mut crawls = Vec::new();
    for id in state.repos.api.active_runs(principal.tenant).await? {
        let run = match state.repos.runs.get(id).await {
            Ok(r) => r,
            Err(StoreError::NotFound { .. }) => continue,
            Err(e) => return Err(e.into()),
        };
        if run
            .config
            .scrape
            .as_ref()
            .is_none_or(|j| j.kind != JobKind::Crawl)
        {
            continue;
        }
        crawls.push(json!({
            "id": run.id,
            "teamId": run.tenant,
            "url": run.config.seed_url,
            "status": facade_status(run.status),
            "options": options_json(&run.config),
        }));
    }
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "crawls": crawls }),
    ))
}

/// `POST /compat/firecrawl/v2/crawl/params-preview`: the crawl options the configured LLM
/// derives from `prompt` for `url`, without creating a crawl.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `400 BAD_REQUEST` for a missing or invalid `url` or
/// `prompt`, `503 llm_not_configured` without a configured LLM, the LLM failure otherwise.
pub async fn params_preview(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let mut details = Vec::new();
    let obj = body.as_object();
    let url = match obj.and_then(|o| o.get("url")).and_then(Value::as_str) {
        Some(u) => parse_target(u, "/url").map_err(|d| details.push(d)).ok(),
        None => {
            details.push(Detail::new("/url", "required", "url is required"));
            None
        }
    };
    let prompt = match obj.and_then(|o| o.get("prompt")).and_then(Value::as_str) {
        Some(p) if !p.trim().is_empty() && p.chars().count() <= 10_000 => Some(p),
        Some(_) => {
            details.push(Detail::new(
                "/prompt",
                "out_of_range",
                "prompt must be 1 to 10000 characters",
            ));
            None
        }
        None => {
            details.push(Detail::new("/prompt", "required", "prompt is required"));
            None
        }
    };
    let (Some(url), Some(prompt)) = (url, prompt) else {
        return Err(HttpError::bad_request(details));
    };
    let llm = llm(&state)?;
    let planned = llm
        .plan_crawl_options(url.as_str(), prompt)
        .await
        .map_err(|e| llm_error(&e))?;
    usage::record(
        &state,
        principal.tenant,
        "crawl-params-preview",
        None,
        "completed",
        Cost {
            credits: 0,
            tokens: planned.usage,
        },
    )
    .await;
    let mut data = planned.value.as_object().cloned().unwrap_or_default();
    data.insert("url".to_owned(), json!(url));
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "data": data }),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::config::HostScope;

    fn t(body: &Value) -> Translated {
        translate(body, None).unwrap()
    }

    fn codes(w: &[Warning]) -> Vec<(&str, &str)> {
        w.iter().map(|w| (w.code.as_str(), w.path.as_str())).collect()
    }

    #[test]
    fn maps_the_documented_options() {
        let tr = t(&json!({
            "url": "https://docs.example.test/",
            "limit": 50,
            "includePaths": ["^/docs/"],
            "excludePaths": ["^/docs/old"],
            "maxDiscoveryDepth": 3,
            "sitemap": "skip",
            "ignoreQueryParameters": true,
            "crawlEntireDomain": true,
            "allowExternalLinks": true,
            "allowSubdomains": true,
            "deduplicateSimilarURLs": true,
            "robotsUserAgent": "BotX",
            "maxConcurrency": 4,
            "zeroDataRetention": true,
            "scrapeOptions": {"formats": ["markdown", "rawHtml"], "onlyMainContent": false},
        }));
        let c = &tr.crawl;
        assert_eq!(c.limits.urls, 50);
        assert_eq!(c.scope.include_paths, vec!["^/docs/"]);
        assert_eq!(c.scope.exclude_paths, vec!["^/docs/old"]);
        assert!(c.scope.url_include.is_empty() && c.scope.url_exclude.is_empty());
        assert_eq!(c.scope.max_discovery_depth, 3);
        assert_eq!(c.scope.sitemap, SitemapMode::Skip);
        assert_eq!(c.scope.query_policy, QueryPolicy::StripAll);
        assert!(c.scope.crawl_entire_domain && c.scope.allow_external_links && c.scope.allow_subdomains);
        assert!(
            !c.scope.filter_similar,
            "deduplicateSimilarURLs is not the shape filter"
        );
        assert_eq!(c.fetch.robots_user_agent.as_deref(), Some("BotX"));
        assert_eq!(c.politeness.max_concurrency, 4);
        assert_eq!(c.politeness.max_in_flight_per_origin, 4);
        assert_eq!(c.retention.mode, RetentionMode::Zdr);
        assert_eq!(c.mode, CrawlMode::Static);
        assert_eq!(c.scope.host_scope, HostScope::Fqdn);
        let job = c.scrape.as_ref().unwrap();
        assert_eq!(job.kind, JobKind::Crawl);
        assert!(job.options.wants("rawHtml") && !job.options.only_main_content);
        assert_eq!(
            codes(&tr.warnings),
            vec![("query_strip_merges_resources", "/ignoreQueryParameters")]
        );
    }

    #[test]
    fn deduplicate_similar_urls_never_turns_on_the_shape_filter() {
        // Firecrawl's option is URL normalization, not a shape filter (real pinned run,
        // 2026-10-28: the default fetches every sibling page, `false` only adds the
        // non-normalized `/s1/blog`). crawlx canonicalizes always, so the default `true` needs
        // nothing and only an explicit `false` warns.
        let seed = "https://a.example.test/";
        let default = t(&json!({"url": seed}));
        assert!(!default.crawl.scope.filter_similar);
        assert!(default.warnings.is_empty(), "{:?}", codes(&default.warnings));
        let on = t(&json!({"url": seed, "deduplicateSimilarURLs": true}));
        assert!(!on.crawl.scope.filter_similar);
        assert!(on.warnings.is_empty(), "{:?}", codes(&on.warnings));
        assert_eq!(on.crawl, default.crawl, "the explicit true is the default");
        let off = t(&json!({"url": seed, "deduplicateSimilarURLs": false}));
        assert!(!off.crawl.scope.filter_similar);
        assert_eq!(
            codes(&off.warnings),
            vec![("unsupported_option", "/deduplicateSimilarURLs")]
        );
        assert_eq!(off.crawl, default.crawl, "false changes nothing it could change");
        // the status echo says what the facade does: it always deduplicates
        for tr in [&default, &on, &off] {
            assert_eq!(options_json(&tr.crawl)["deduplicateSimilarURLs"], true);
        }
        assert!(
            !CreateCrawl::new(url::Url::parse(seed).unwrap())
                .scope
                .filter_similar,
            "the native default is unchanged"
        );
    }

    #[test]
    fn regex_on_full_url_moves_the_patterns_to_the_url_lists() {
        let c = t(&json!({
            "url": "https://a.example.test/",
            "regexOnFullURL": true,
            "includePaths": ["^https://a\\.example\\.test/docs"],
            "excludePaths": ["\\?draft="],
        }))
        .crawl;
        assert_eq!(c.scope.url_include, vec!["^https://a\\.example\\.test/docs"]);
        assert_eq!(c.scope.url_exclude, vec!["\\?draft="]);
        assert!(c.scope.include_paths.is_empty() && c.scope.exclude_paths.is_empty());
        let o = options_json(&c);
        assert_eq!(o["regexOnFullURL"], true);
        assert_eq!(o["includePaths"], json!(["^https://a\\.example\\.test/docs"]));
    }

    #[test]
    fn delay_forces_one_request_at_a_time() {
        let tr = t(&json!({"url": "https://a.example.test/", "delay": 1.5, "maxConcurrency": 9}));
        assert_eq!(tr.crawl.politeness.delay_ms, 1500);
        assert_eq!(tr.crawl.politeness.max_concurrency, 1);
        assert_eq!(tr.crawl.politeness.max_in_flight_per_origin, 1);
        assert!(codes(&tr.warnings).contains(&("concurrency_forced", "/maxConcurrency")));
        let big = t(&json!({"url": "https://a.example.test/", "maxConcurrency": 1000}));
        assert_eq!(big.crawl.politeness.max_concurrency, 256);
        assert_eq!(big.crawl.politeness.max_in_flight_per_origin, 8);
        assert!(codes(&big.warnings).contains(&("limit_clamped", "/maxConcurrency")));
    }

    #[test]
    fn v1_aliases_are_read_with_a_deprecation_warning() {
        let tr = t(&json!({
            "url": "https://a.example.test/",
            "maxDepth": 2,
            "ignoreSitemap": true,
            "allowBackwardLinks": true,
            "crawlerOptions": {"limit": 7, "maxDepth": 5},
            "scrapeOptions": {"extract": {"schema": {"type": "object"}, "prompt": "p"}},
        }));
        let c = &tr.crawl;
        assert_eq!(c.scope.max_discovery_depth, 2, "top-level wins over the wrapper");
        assert_eq!(c.scope.sitemap, SitemapMode::Skip);
        assert!(c.scope.crawl_entire_domain);
        assert_eq!(c.limits.urls, 7);
        assert!(c.scrape.as_ref().unwrap().options.wants("json"));
        let w = codes(&tr.warnings);
        for expected in [
            ("deprecated_option", "/maxDepth"),
            ("deprecated_option", "/ignoreSitemap"),
            ("deprecated_option", "/allowBackwardLinks"),
            ("deprecated_option", "/crawlerOptions"),
        ] {
            assert!(w.contains(&expected), "{expected:?} in {w:?}");
        }
        let explicit =
            t(&json!({"url": "https://a.example.test/", "ignoreSitemap": true, "sitemap": "only"}));
        assert_eq!(explicit.crawl.scope.sitemap, SitemapMode::Only);
    }

    #[test]
    fn webhook_maps_to_output_and_the_job() {
        let tr = t(&json!({
            "url": "https://a.example.test/",
            "webhook": {
                "url": "https://hooks.example.test/x",
                "headers": {"X-Auth": "s3cret"},
                "metadata": {"run": 7},
                "events": ["crawl.page", "completed"],
            },
        }));
        let hook = tr.crawl.output.webhook.as_ref().unwrap();
        assert_eq!(hook.url.as_str(), "https://hooks.example.test/x");
        assert_eq!(hook.events, vec!["page", "completed"]);
        let job = tr.crawl.scrape.as_ref().unwrap();
        assert_eq!(
            job.webhook_headers.get("X-Auth").map(String::as_str),
            Some("s3cret")
        );
        assert_eq!(job.webhook_metadata, json!({"run": 7}));
        let all = t(&json!({"url": "https://a.example.test/", "webhook": "https://hooks.example.test/y"}));
        assert_eq!(
            all.crawl.output.webhook.unwrap().events,
            vec!["started", "page", "completed", "failed"]
        );
        // the options echoed by /crawl/active carry neither headers nor metadata
        assert!(!options_json(&tr.crawl).to_string().contains("s3cret"));
    }

    #[test]
    fn warnings_cover_ignored_and_unknown_options() {
        let tr = t(&json!({
            "url": "https://a.example.test/",
            "ignoreRobotsTxt": true,
            "prompt": "crawl the blog",
            "mystery": 1,
            "integration": "sdk",
            "origin": "sdk",
            "scrapeOptions": {"nope": 1},
        }));
        let w = codes(&tr.warnings);
        for expected in [
            ("prompt_ignored", "/prompt"),
            ("unsupported_option", "/mystery"),
            ("unsupported_option", "/scrapeOptions/nope"),
        ] {
            assert!(w.contains(&expected), "{expected:?} in {w:?}");
        }
        assert!(
            tr.robots_override,
            "ignoreRobotsTxt is handed to the route, not warned"
        );
        assert!(
            !w.iter().any(|(_, p)| *p == "/integration" || *p == "/origin"),
            "{w:?}"
        );
        assert!(
            tr.crawl.safety.respect_robots_txt,
            "the translation never lowers the gate itself"
        );
    }

    #[test]
    fn a_plan_fills_in_what_the_request_leaves_out() {
        let plan = json!({"limit": 5, "includePaths": ["^/blog"], "maxDiscoveryDepth": 4});
        let tr = translate(
            &json!({"url": "https://a.example.test/", "prompt": "blog posts", "limit": 9}),
            plan.as_object(),
        )
        .unwrap();
        assert_eq!(tr.crawl.limits.urls, 9, "explicit options win");
        assert_eq!(tr.crawl.scope.include_paths, vec!["^/blog"]);
        assert_eq!(tr.crawl.scope.max_discovery_depth, 4);
        assert!(!codes(&tr.warnings).contains(&("prompt_ignored", "/prompt")));
    }

    #[test]
    fn violations_are_all_reported_with_firecrawl_status() {
        let err = translate(&json!({"limit": 0, "sitemap": "weird", "delay": -1}), None).unwrap_err();
        assert_eq!(
            err.status,
            StatusCode::BAD_REQUEST,
            "a missing url is a 400 like Firecrawl's"
        );
        assert_eq!(err.code, "BAD_REQUEST");
        let paths: Vec<&str> = err.details.iter().map(|d| d.path.as_str()).collect();
        for p in ["/url", "/limit", "/sitemap", "/delay"] {
            assert!(paths.contains(&p), "{p} in {paths:?}");
        }
        let err = translate(
            &json!({"url": "ftp://x.example.test/", "includePaths": ["("]}),
            None,
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "BAD_REQUEST");
        let err = translate(
            &json!({"url": "https://a.example.test/", "includePaths": ["("]}),
            None,
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err
            .details
            .iter()
            .any(|d| d.path == "/includePaths" && d.code == "invalid_pattern"));
        let err = translate(
            &json!({"url": "https://a.example.test/", "webhook": {"url": "https://h.example.test/", "events": ["nope"]}}),
            None,
        )
        .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        let err = translate(&json!([1]), None).unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_bare_host_is_a_valid_url() {
        let c = t(&json!({"url": "docs.example.test/start"})).crawl;
        assert_eq!(c.seed_url.as_str(), "http://docs.example.test/start");
    }

    #[test]
    fn options_json_renders_firecrawl_names() {
        let c = t(&json!({
            "url": "https://a.example.test/",
            "delay": 2,
            "scrapeOptions": {"formats": ["markdown", "links"], "waitFor": 500, "timeout": 30000, "maxAge": 1000},
        }))
        .crawl;
        let o = options_json(&c);
        assert_eq!(o["delay"], 2.0);
        assert_eq!(o["sitemap"], "include");
        let so = &o["scrapeOptions"];
        assert_eq!(so["waitFor"], 500);
        assert_eq!(so["timeout"], 30000);
        assert_eq!(so["maxAge"], 1000);
        assert_eq!(so["formats"], json!([{"type": "markdown"}, {"type": "links"}]));
        assert!(so.get("waitForMs").is_none() && so.get("headers").is_none());
    }
}
