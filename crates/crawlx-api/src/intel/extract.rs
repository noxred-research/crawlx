//! The `/extract` engine: URL expansion (globs through the map tool), scraping, optional web
//! search, LLM extraction with JSON-Schema validation (one repair retry) and source attribution.
//! Jobs run on [`crate::state::Shared::jobs`]; the result lands on the job row.

use crate::errors::ApiResult;
use crate::intel::common;
use crate::intel::jobs::{self, Outcome};
use crate::intel::request::{is_http_url, Body};
use crate::intel::search::SearchQuery;
use crate::intel::usage::{self, Cost};
use crate::intel::webhook::{JobEvent, JobWebhook};
use crate::state::AppState;
use crawlx_core::{TenantId, Timestamp};
use crawlx_model::llm::{ExtractDocument, LlmError, TokenUsage};
use crawlx_storage::JobStatus;
use futures::StreamExt;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Pages one extract job reads at most (glob expansion and web search are cut here).
pub const MAX_PAGES: usize = 50;
/// Pages scraped at once.
const SCRAPE_CONCURRENCY: usize = 5;
/// Web-search results added when `enableWebSearch` is set.
const SEARCH_RESULTS: usize = 5;
/// Links asked of the map tool when expanding a glob.
const MAP_LIMIT: u64 = 1_000;
/// Credits charged for the LLM extraction step.
pub const EXTRACTION_CREDITS: u64 = 4;
/// Longest `prompt`, characters.
pub const MAX_PROMPT: usize = 10_000;

/// Top-level keys the endpoint reads.
const KNOWN: [&str; 14] = [
    "urls",
    "prompt",
    "schema",
    "enableWebSearch",
    "ignoreSitemap",
    "includeSubdomains",
    "showSources",
    "urlTrace",
    "scrapeOptions",
    "ignoreInvalidURLs",
    "webhook",
    "threatProtection",
    "integration",
    "origin",
];

/// A validated `POST /extract` body.
#[derive(Clone, Debug)]
pub struct ExtractRequest {
    /// Valid URLs and globs, in request order.
    pub urls: Vec<String>,
    /// URLs dropped under `ignoreInvalidURLs`.
    pub invalid_urls: Vec<String>,
    /// What to extract.
    pub prompt: Option<String>,
    /// JSON Schema of the answer.
    pub schema: Option<Value>,
    /// Add pages found by web search.
    pub enable_web_search: bool,
    /// Do not read sitemaps while expanding globs.
    pub ignore_sitemap: bool,
    /// Include subdomains while expanding globs.
    pub include_subdomains: bool,
    /// Return `sources` in the status response.
    pub show_sources: bool,
    /// Return `urlTrace` (every attempted page and its outcome) in the status response.
    pub url_trace: bool,
    /// Scrape options per page (always includes `markdown`).
    pub scrape_options: Value,
    /// Job webhook.
    pub webhook: Option<JobWebhook>,
    /// Request options the endpoint ignores.
    pub warnings: Vec<String>,
}

/// Whether `formats` already asks for markdown.
fn has_markdown(formats: &[Value]) -> bool {
    formats
        .iter()
        .any(|f| f.as_str() == Some("markdown") || f.get("type").and_then(Value::as_str) == Some("markdown"))
}

/// The scrape options with `markdown` guaranteed among the formats.
fn with_markdown(options: Option<&Value>) -> Value {
    let mut o = options.and_then(Value::as_object).cloned().unwrap_or_default();
    let mut formats = o
        .get("formats")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if !has_markdown(&formats) {
        formats.insert(0, json!("markdown"));
    }
    o.insert("formats".to_owned(), Value::Array(formats));
    Value::Object(o)
}

/// Whether a URL or glob names a crawlable absolute http(s) address (`*` stands for any text).
fn valid_pattern(pattern: &str) -> bool {
    let probe = pattern.replace('*', "x");
    let Ok(u) = url::Url::parse(&probe) else {
        return false;
    };
    matches!(u.scheme(), "http" | "https")
        && u.host_str().is_some()
        && crawlx_policy::EgressPolicy::new(false)
            .with_seed_port(&u)
            .check_url(&u)
            .is_ok()
}

/// Validate a `POST /extract` body.
///
/// # Errors
/// `422` for malformed fields, a missing prompt and schema, an invalid JSON Schema, or invalid
/// URLs when `ignoreInvalidURLs` is false.
pub fn parse(body: &Value) -> ApiResult<ExtractRequest> {
    let mut b = Body::new(body)?;
    let urls = b.strings("urls", 100, 2048);
    let prompt = b.string("prompt", MAX_PROMPT).filter(|p| !p.trim().is_empty());
    let schema = b.object("schema").cloned();
    let enable_web_search = b.boolean("enableWebSearch").unwrap_or(false);
    let ignore_sitemap = b.boolean("ignoreSitemap").unwrap_or(false);
    let include_subdomains = b.boolean("includeSubdomains").unwrap_or(true);
    let show_sources = b.boolean("showSources").unwrap_or(false);
    let url_trace = b.boolean("urlTrace").unwrap_or(false);
    let ignore_invalid = b.boolean("ignoreInvalidURLs").unwrap_or(true);
    let scrape_options = b.object("scrapeOptions");
    let webhook = match JobWebhook::parse(b.raw("webhook"), "/webhook", &["started", "completed", "failed"]) {
        Ok(w) => w,
        Err(e) => {
            for d in e.details {
                b.fail(d.path.trim_start_matches('/'), &d.code, d.message);
            }
            None
        }
    };
    if urls.is_none() && b.raw("urls").is_none() {
        b.fail("urls", "required", "urls is required");
    }
    if prompt.is_none() && schema.is_none() {
        b.fail("prompt", "required", "a prompt or a schema is required");
    }
    if let Some(s) = &schema {
        if let Err(e) = jsonschema::validator_for(s) {
            b.fail("schema", "invalid", format!("not a valid JSON Schema: {e}"));
        }
    }
    let mut warnings = Vec::new();
    if b.raw("threatProtection").is_some() {
        warnings.push("threatProtection is an enterprise cloud feature; ignored".to_owned());
    }
    let unknown: Vec<String> = b.unknown_keys(&KNOWN).into_iter().collect();
    if !unknown.is_empty() {
        warnings.push(format!("unsupported options ignored: {}", unknown.join(", ")));
    }
    let scrape_options = with_markdown(scrape_options);
    let (mut valid, mut invalid) = (Vec::new(), Vec::new());
    for (i, u) in urls.unwrap_or_default().into_iter().enumerate() {
        if valid_pattern(&u) {
            valid.push(u);
        } else if ignore_invalid {
            invalid.push(u);
        } else {
            b.fail(&format!("urls/{i}"), "invalid", "not a valid http(s) URL or glob");
        }
    }
    if valid.is_empty() && !enable_web_search && !b.has_errors() {
        b.fail("urls", "invalid", "no valid URLs and enableWebSearch is off");
    }
    b.finish()?;
    Ok(ExtractRequest {
        urls: valid,
        invalid_urls: invalid,
        prompt,
        schema,
        enable_web_search,
        ignore_sitemap,
        include_subdomains,
        show_sources,
        url_trace,
        scrape_options,
        webhook,
        warnings,
    })
}

/// Whether `text` matches `pattern` where `*` matches any (possibly empty) run of characters.
#[must_use]
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0_usize, 0_usize);
    let (mut star, mut mark) = (None::<usize>, 0_usize);
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ti;
            pi += 1;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Origin (`scheme://host[:port]`) of a pattern whose host has no wildcard.
fn origin_of(pattern: &str) -> Option<String> {
    let (scheme, rest) = pattern.split_once("://")?;
    let authority = rest.split('/').next()?;
    if authority.is_empty() || authority.contains('*') {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

/// Expand globs through the map tool; plain URLs pass through. Returns `(pages, warnings)`.
async fn expand(state: &AppState, tenant: TenantId, req: &ExtractRequest) -> (Vec<String>, Vec<String>) {
    let mut pages: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut warnings = Vec::new();
    for pattern in &req.urls {
        if !pattern.contains('*') {
            if seen.insert(pattern.clone()) {
                pages.push(pattern.clone());
            }
            continue;
        }
        let (Some(origin), Ok(tools)) = (origin_of(pattern), common::tools(state)) else {
            warnings.push(format!("glob {pattern} could not be expanded"));
            continue;
        };
        let options = json!({
            "includeSubdomains": req.include_subdomains,
            "sitemap": if req.ignore_sitemap { "skip" } else { "include" },
            "limit": MAP_LIMIT,
        });
        match tools.map(tenant, &origin, &options).await {
            Ok(links) => {
                let before = pages.len();
                for l in links {
                    if glob_match(pattern, &l.url) && seen.insert(l.url.clone()) {
                        pages.push(l.url);
                    }
                }
                if pages.len() == before {
                    warnings.push(format!("glob {pattern} matched no pages"));
                }
            }
            Err(e) => warnings.push(format!("glob {pattern} could not be expanded: {e}")),
        }
    }
    if pages.len() > MAX_PAGES {
        pages.truncate(MAX_PAGES);
        warnings.push(format!("only the first {MAX_PAGES} pages were read"));
    }
    (pages, warnings)
}

/// Leaf scalars of `v` long enough to be searched for in page text.
fn leaves(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if s.trim().chars().count() >= 3 => out.push(s.trim().to_lowercase()),
        Value::Number(n) => {
            let s = n.to_string();
            if s.len() >= 3 {
                out.push(s);
            }
        }
        Value::Array(a) => a.iter().for_each(|x| leaves(x, out)),
        Value::Object(o) => o.values().for_each(|x| leaves(x, out)),
        _ => {}
    }
}

/// For each top-level field of `data`, the pages whose text contains one of the field's values.
#[must_use]
pub fn attribute_sources(data: &Value, docs: &[ExtractDocument]) -> BTreeMap<String, Vec<String>> {
    let lowered: Vec<(String, String)> = docs
        .iter()
        .map(|d| (d.url.clone(), d.markdown.to_lowercase()))
        .collect();
    let mut out = BTreeMap::new();
    let Some(obj) = data.as_object() else {
        return out;
    };
    for (key, value) in obj {
        let mut vals = Vec::new();
        leaves(value, &mut vals);
        let urls: Vec<String> = lowered
            .iter()
            .filter(|(_, text)| vals.iter().any(|v| text.contains(v.as_str())))
            .map(|(u, _)| u.clone())
            .collect();
        out.insert(key.clone(), urls);
    }
    out
}

/// Validation errors of `data` against `schema`, as text.
fn schema_errors(schema: &Value, data: &Value) -> Vec<String> {
    match jsonschema::validator_for(schema) {
        Ok(v) => v.iter_errors(data).map(|e| e.to_string()).take(5).collect(),
        Err(e) => vec![e.to_string()],
    }
}

/// What the pages are ranked against: the prompt, else the schema's text.
fn ranking_query(req: &ExtractRequest) -> Option<String> {
    req.prompt
        .clone()
        .filter(|p| !p.trim().is_empty())
        .or_else(|| req.schema.as_ref().map(Value::to_string))
}

/// LLM extraction with one repair attempt when the answer violates `schema`. The model is the
/// extraction provider when `EXTRACTION_PROVIDER_*` routes `tenant` to it, else the default LLM.
async fn extract_validated(
    state: &AppState,
    tenant: TenantId,
    docs: &[ExtractDocument],
    req: &ExtractRequest,
    usage_total: &mut TokenUsage,
) -> Result<Value, String> {
    let input_bytes = docs.iter().map(|d| d.markdown.len()).sum();
    let llm = common::extraction_llm(state, tenant, input_bytes).map_err(|e| e.message)?;
    let mut prompt = req.prompt.clone();
    for attempt in 0..2 {
        let done = llm
            .extract(docs, prompt.as_deref(), req.schema.as_ref())
            .await
            .map_err(|e: LlmError| e.to_string())?;
        usage_total.add(done.usage);
        let Some(schema) = &req.schema else {
            return Ok(done.value);
        };
        let errors = schema_errors(schema, &done.value);
        if errors.is_empty() {
            return Ok(done.value);
        }
        if attempt == 1 {
            return Err(format!(
                "the extracted data does not match the schema: {}",
                errors.join("; ")
            ));
        }
        let base = req
            .prompt
            .clone()
            .unwrap_or_else(|| "Extract the data described by the schema.".to_owned());
        prompt = Some(format!(
            "{base}\nYour previous answer was rejected by schema validation ({}). Return corrected JSON.",
            errors.join("; ")
        ));
    }
    Err("extraction failed".to_owned())
}

/// What one attempted page did: a `urlTrace` entry of the status response.
///
/// The entries follow the order of the attempts, which is the order of `urls` (a glob expands in
/// the order the map tool returns its matches), then the web search hits. Nothing in the order
/// depends on how long a page took; only the `timing` stamps do.
#[derive(Clone, Debug, PartialEq, Eq)]
struct UrlTrace {
    /// The URL as the job attempted it.
    url: String,
    /// `scraped`, or `error` when the page could not be scraped.
    status: &'static str,
    /// Why the page could not be scraped.
    error: Option<String>,
    /// A note about a page that was scraped but gave nothing to read.
    warning: Option<String>,
    /// The URL the page ended at, when it had text for the model.
    final_url: Option<String>,
    /// The page was among those the model read.
    used_in_completion: bool,
    /// When the URL joined the job's page list (glob expansion or web search).
    discovered_at: Timestamp,
    /// When the scrape returned the page; `None` when the scrape failed.
    scraped_at: Option<Timestamp>,
}

impl UrlTrace {
    fn scraped(
        url: &str,
        final_url: Option<String>,
        warning: Option<String>,
        discovered_at: Timestamp,
        scraped_at: Timestamp,
    ) -> Self {
        Self {
            url: url.to_owned(),
            status: "scraped",
            error: None,
            warning,
            final_url,
            used_in_completion: false,
            discovered_at,
            scraped_at: Some(scraped_at),
        }
    }

    fn failed(url: &str, error: String, discovered_at: Timestamp) -> Self {
        Self {
            url: url.to_owned(),
            status: "error",
            error: Some(error),
            warning: None,
            final_url: None,
            used_in_completion: false,
            discovered_at,
            scraped_at: None,
        }
    }

    /// The wire entry; `completed_at` is when the job finished with its page list.
    fn to_json(&self, completed_at: Timestamp) -> Value {
        let mut timing = json!({
            "discoveredAt": crate::util::ts(self.discovered_at),
            "completedAt": crate::util::ts(completed_at),
        });
        if let Some(at) = self.scraped_at {
            timing["scrapedAt"] = json!(crate::util::ts(at));
        }
        let mut out = json!({
            "url": self.url,
            "status": self.status,
            "timing": timing,
            "usedInCompletion": self.used_in_completion,
        });
        if let Some(error) = &self.error {
            out["error"] = json!(error);
        }
        if let Some(warning) = &self.warning {
            out["warning"] = json!(warning);
        }
        out
    }
}

/// Flag the trace entries whose page the model read (after any ranking cut pages).
fn mark_used(trace: &mut [UrlTrace], docs: &[ExtractDocument]) {
    for entry in trace {
        entry.used_in_completion = entry
            .final_url
            .as_deref()
            .is_some_and(|url| docs.iter().any(|d| d.url == url));
    }
}

fn trace_json(trace: &[UrlTrace], completed_at: Timestamp) -> Value {
    Value::Array(trace.iter().map(|t| t.to_json(completed_at)).collect())
}

/// The stored result of a job that failed: only the trace, and only when it was asked for.
fn trace_result(req: &ExtractRequest, trace: &[UrlTrace], completed_at: Timestamp) -> Option<Value> {
    (req.url_trace && !trace.is_empty()).then(|| json!({ "urlTrace": trace_json(trace, completed_at) }))
}

struct Gathered {
    /// The pages the LLM reads (ranked and cut when an embedding model is configured).
    docs: Vec<ExtractDocument>,
    /// Pages that were scraped and had text, before any ranking.
    scraped: usize,
    /// Credits of the page scrapes (the page tools record their own ledger rows).
    credits: u64,
    /// Credits of the web search (recorded on this job's ledger row).
    search_credits: u64,
    warnings: Vec<String>,
    /// Every page the job attempted, in attempt order.
    trace: Vec<UrlTrace>,
}

async fn gather(
    state: &AppState,
    tenant: TenantId,
    req: &ExtractRequest,
    cancel: &CancellationToken,
) -> Result<Gathered, String> {
    let tools = common::tools(state).map_err(|e| e.message)?;
    let (mut pages, mut warnings) = expand(state, tenant, req).await;
    let expanded_at = state.clock.now();
    let expanded = pages.len();
    let mut searched_at = expanded_at;
    let mut credits = 0_u64;
    let mut search_credits = 0_u64;
    if req.enable_web_search {
        let provider = common::search(state).map_err(|e| e.message)?;
        let text = req
            .prompt
            .clone()
            .or_else(|| {
                req.schema
                    .as_ref()
                    .and_then(|s| s.get("title").and_then(Value::as_str).map(str::to_owned))
            })
            .unwrap_or_else(|| req.urls.join(" "));
        let text: String = text.chars().take(500).collect();
        let found = provider
            .search(&SearchQuery::web(&text, SEARCH_RESULTS))
            .await
            .map_err(|e| common::search_error(&e).message)?;
        search_credits = search_credits.saturating_add(2);
        warnings.extend(found.warnings);
        searched_at = state.clock.now();
        for h in found.web {
            if pages.len() < MAX_PAGES && is_http_url(&h.url) && !pages.contains(&h.url) {
                pages.push(h.url);
            }
        }
    }
    type Attempt = (
        String,
        Result<crate::intel::tools::ScrapedPage, String>,
        Timestamp,
    );
    let scraped: Vec<Attempt> = futures::stream::iter(pages.into_iter().map(|url| {
        let tools = tools.clone();
        let clock = state.clock.clone();
        let options = req.scrape_options.clone();
        async move {
            let r = tools
                .scrape(tenant, &url, &options)
                .await
                .map_err(|e| e.to_string());
            (url, r, clock.now())
        }
    }))
    .buffered(SCRAPE_CONCURRENCY)
    .take_until(cancel.cancelled())
    .collect()
    .await;
    let mut docs = Vec::new();
    let mut trace = Vec::new();
    for (i, (url, r, returned_at)) in scraped.into_iter().enumerate() {
        let discovered_at = if i < expanded { expanded_at } else { searched_at };
        match r {
            Ok(page) => {
                credits = credits.saturating_add(page.credits);
                if page.markdown().trim().is_empty() {
                    warnings.push(format!("{url} had no text content"));
                    trace.push(UrlTrace::scraped(
                        &url,
                        None,
                        Some("no text content".to_owned()),
                        discovered_at,
                        returned_at,
                    ));
                } else {
                    let final_url = Some(page.source_url())
                        .filter(|s| !s.is_empty())
                        .unwrap_or(&url)
                        .to_owned();
                    trace.push(UrlTrace::scraped(
                        &url,
                        Some(final_url.clone()),
                        None,
                        discovered_at,
                        returned_at,
                    ));
                    docs.push(ExtractDocument {
                        url: final_url,
                        markdown: page.markdown().to_owned(),
                    });
                }
            }
            Err(e) => {
                trace.push(UrlTrace::failed(&url, e.clone(), discovered_at));
                warnings.push(format!("{url} could not be scraped: {e}"));
            }
        }
    }
    Ok(Gathered {
        scraped: docs.len(),
        docs,
        trace,
        credits,
        search_credits,
        warnings,
    })
}

async fn emit(
    state: &AppState,
    hook: Option<&JobWebhook>,
    event: &str,
    job: Uuid,
    data: Value,
    error: Option<&str>,
    cancel: &CancellationToken,
) {
    if let Some(h) = hook {
        let ev = JobEvent {
            kind: "extract",
            event,
            id: job,
            data,
            error,
        };
        state.job_webhooks.deliver(h, &ev, cancel).await;
    }
}

/// Run extract job `job` to its terminal state (spawned by the route; never returns an error).
pub async fn run(
    state: AppState,
    tenant: TenantId,
    job: Uuid,
    req: ExtractRequest,
    cancel: CancellationToken,
) {
    // webhook deliveries outlive a cancelled job only until shutdown
    let hook_cancel = state.shutdown.clone();
    emit(
        &state,
        req.webhook.as_ref(),
        "started",
        job,
        json!([]),
        None,
        &hook_cancel,
    )
    .await;
    let mut tokens = TokenUsage::default();
    let mut trace: Vec<UrlTrace> = Vec::new();
    let result: Result<(Value, Gathered), Option<String>> = async {
        let mut gathered = gather(&state, tenant, &req, &cancel).await?;
        trace = std::mem::take(&mut gathered.trace);
        if cancel.is_cancelled() {
            return Err(None);
        }
        if gathered.docs.is_empty() {
            return Err(Some(format!(
                "no page could be read for extraction{}",
                if gathered.warnings.is_empty() {
                    String::new()
                } else {
                    format!(": {}", gathered.warnings.join("; "))
                }
            )));
        }
        if let (Some(ranker), Some(query)) = (&state.embeddings, ranking_query(&req)) {
            let pages = std::mem::take(&mut gathered.docs);
            let ranked = tokio::select! {
                r = ranker.rank(&query, pages) => r,
                () = cancel.cancelled() => return Err(None),
            };
            tokens.prompt_tokens = tokens.prompt_tokens.saturating_add(ranked.tokens);
            gathered.docs = ranked.docs;
            gathered.warnings.extend(ranked.warnings);
        }
        mark_used(&mut trace, &gathered.docs);
        let data = tokio::select! {
            r = extract_validated(&state, tenant, &gathered.docs, &req, &mut tokens) => r.map_err(Some)?,
            () = cancel.cancelled() => return Err(None),
        };
        Ok((data, gathered))
    }
    .await;
    let credits_base = |g: &Gathered| {
        g.credits
            .saturating_add(g.search_credits)
            .saturating_add(EXTRACTION_CREDITS)
    };
    match result {
        Ok((data, g)) => {
            let sources = attribute_sources(&data, &g.docs);
            let urls: Vec<&str> = g.docs.iter().map(|d| d.url.as_str()).collect();
            let mut warnings = req.warnings.clone();
            warnings.extend(g.warnings.clone());
            let credits = credits_base(&g);
            let mut stored = json!({
                "data": data,
                "sources": sources,
                "urls": urls,
                "totalUrlsScraped": g.scraped,
                "warnings": warnings,
            });
            if req.url_trace {
                stored["urlTrace"] = trace_json(&trace, state.clock.now());
            }
            jobs::finish(
                &state,
                tenant,
                job,
                Outcome {
                    status: JobStatus::Completed,
                    result: Some(stored),
                    error: None,
                    stop_reason: None,
                    tokens_used: tokens.total(),
                    credits_used: credits,
                },
            )
            .await;
            usage::record(
                &state,
                tenant,
                "extract",
                Some(job),
                "completed",
                Cost {
                    credits: g.search_credits.saturating_add(EXTRACTION_CREDITS),
                    tokens,
                },
            )
            .await;
            let event = json!([{
                "success": true,
                "data": data,
                "extractId": job,
                "llmUsage": 0,
                "tokensUsed": tokens.total(),
                "totalUrlsScraped": g.scraped,
                "sources": sources,
            }]);
            emit(
                &state,
                req.webhook.as_ref(),
                "completed",
                job,
                event,
                None,
                &hook_cancel,
            )
            .await;
        }
        Err(None) => {
            jobs::finish(
                &state,
                tenant,
                job,
                Outcome {
                    status: JobStatus::Cancelled,
                    result: None,
                    error: None,
                    stop_reason: Some("cancelled".to_owned()),
                    tokens_used: tokens.total(),
                    credits_used: 0,
                },
            )
            .await;
        }
        Err(Some(message)) => {
            jobs::finish(
                &state,
                tenant,
                job,
                Outcome {
                    status: JobStatus::Failed,
                    result: trace_result(&req, &trace, state.clock.now()),
                    error: Some(message.clone()),
                    stop_reason: None,
                    tokens_used: tokens.total(),
                    credits_used: 0,
                },
            )
            .await;
            usage::record(
                &state,
                tenant,
                "extract",
                Some(job),
                "failed",
                Cost { credits: 0, tokens },
            )
            .await;
            emit(
                &state,
                req.webhook.as_ref(),
                "failed",
                job,
                json!([]),
                Some(&message),
                &hook_cancel,
            )
            .await;
        }
    }
}

/// Body of the `GET /extract/{id}` response for `job`.
#[must_use]
pub fn status_json(job: &crawlx_storage::JobRecord, show_sources: bool) -> Value {
    let mut out = Map::new();
    let result = job.result.as_ref();
    out.insert("success".to_owned(), json!(true));
    out.insert("status".to_owned(), json!(job.status.as_str()));
    out.insert(
        "data".to_owned(),
        result
            .and_then(|r| r.get("data"))
            .cloned()
            .unwrap_or_else(|| json!({})),
    );
    out.insert("expiresAt".to_owned(), json!(crate::util::ts(job.expires_at)));
    out.insert("tokensUsed".to_owned(), json!(job.tokens_used));
    out.insert("creditsUsed".to_owned(), json!(job.credits_used));
    if show_sources {
        if let Some(s) = result.and_then(|r| r.get("sources")) {
            out.insert("sources".to_owned(), s.clone());
        }
    }
    let wants_trace = job
        .request
        .get("urlTrace")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if wants_trace {
        if let Some(t) = result.and_then(|r| r.get("urlTrace")) {
            out.insert("urlTrace".to_owned(), t.clone());
        }
    }
    if let Some(e) = &job.error {
        out.insert("error".to_owned(), json!(e));
    }
    if let Some(w) = result.and_then(|r| r.get("warnings")).and_then(Value::as_array) {
        if !w.is_empty() {
            out.insert(
                "warning".to_owned(),
                json!(w.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("; ")),
            );
        }
    }
    Value::Object(out)
}

/// Admit and start an extract job; returns `(job id, invalid URLs)`.
///
/// # Errors
/// `503` when the LLM or the scrape service is missing, storage failures.
pub async fn start(
    state: &AppState,
    tenant: TenantId,
    body: &Value,
    req: ExtractRequest,
) -> ApiResult<(Uuid, Vec<String>)> {
    common::llm(state)?;
    common::tools(state)?;
    if req.enable_web_search {
        common::search(state)?;
    }
    let job = jobs::admit(
        state,
        tenant,
        crawlx_storage::JobKind::Extract,
        body.clone(),
        None,
    )
    .await?;
    let id = job.id;
    let invalid = req.invalid_urls.clone();
    let st = state.clone();
    state
        .jobs
        .spawn(id, move |cancel| run(st, tenant, id, req, cancel));
    Ok((id, invalid))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn glob_matching() {
        assert!(glob_match("https://a.com/*", "https://a.com/x/y"));
        assert!(glob_match("https://a.com/blog/*", "https://a.com/blog/p1"));
        assert!(!glob_match("https://a.com/blog/*", "https://a.com/about"));
        assert!(glob_match("https://a.com/*/edit", "https://a.com/p/edit"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("https://a.com/x", "https://a.com/xy"));
    }

    #[test]
    fn origin_of_globs() {
        assert_eq!(
            origin_of("https://a.com/blog/*").as_deref(),
            Some("https://a.com")
        );
        assert_eq!(
            origin_of("http://a.com:8080/*").as_deref(),
            Some("http://a.com:8080")
        );
        assert_eq!(origin_of("https://*.a.com/x").as_deref(), None);
    }

    #[test]
    fn markdown_is_always_requested() {
        assert_eq!(with_markdown(None), json!({"formats": ["markdown"]}));
        assert_eq!(
            with_markdown(Some(&json!({"formats": ["html"]})))["formats"],
            json!(["markdown", "html"])
        );
        assert_eq!(
            with_markdown(Some(
                &json!({"formats": [{"type": "markdown"}], "onlyMainContent": false})
            )),
            json!({"formats": [{"type": "markdown"}], "onlyMainContent": false})
        );
    }

    #[test]
    fn a_url_keeps_its_own_port_like_every_other_facade_route() {
        let r = parse(
            &json!({"urls": ["http://a.com:8080/*", "https://b.com:8443/x", "http://127.0.0.1:8080/x"], "prompt": "p"}),
        )
        .unwrap();
        assert_eq!(r.urls, ["http://a.com:8080/*", "https://b.com:8443/x"]);
        assert_eq!(
            r.invalid_urls,
            ["http://127.0.0.1:8080/x"],
            "a private address stays denied"
        );
    }

    #[test]
    fn parse_validates_and_splits_invalid_urls() {
        let r = parse(
            &json!({"urls": ["https://a.com/*", "nope", "http://127.0.0.1/x"], "prompt": "p", "bogus": 1}),
        )
        .unwrap();
        assert_eq!(r.urls, ["https://a.com/*"]);
        assert_eq!(r.invalid_urls, ["nope", "http://127.0.0.1/x"]);
        assert!(r.include_subdomains && !r.enable_web_search);
        assert_eq!(r.warnings.len(), 1);
        let strict =
            parse(&json!({"urls": ["nope"], "prompt": "p", "ignoreInvalidURLs": false})).unwrap_err();
        assert_eq!(strict.details[0].path, "/urls/0");
        assert!(
            parse(&json!({"urls": ["https://a.com"]})).is_err(),
            "prompt or schema required"
        );
        assert!(parse(&json!({"urls": ["https://a.com"], "schema": {"type": 5}})).is_err());
        assert!(parse(&json!({"urls": [], "prompt": "p"})).is_err());
        assert!(parse(&json!({"urls": [], "prompt": "p", "enableWebSearch": true})).is_ok());
    }

    #[test]
    fn sources_follow_values() {
        let docs = vec![
            ExtractDocument {
                url: "https://a.com".into(),
                markdown: "Site: Example Site, founded 1999".into(),
            },
            ExtractDocument {
                url: "https://b.com".into(),
                markdown: "Category technology".into(),
            },
        ];
        let data = json!({"siteName": "Example Site", "category": "Technology", "missing": "nowhere"});
        let s = attribute_sources(&data, &docs);
        assert_eq!(s["siteName"], ["https://a.com"]);
        assert_eq!(s["category"], ["https://b.com"]);
        assert!(s["missing"].is_empty());
    }
}
