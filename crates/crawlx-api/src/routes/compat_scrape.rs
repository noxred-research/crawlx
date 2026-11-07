//! Firecrawl v2 scrape endpoints of the compat facade: `POST /scrape`,
//! `GET /scrape/{jobId}` and the batch scrape family. The self-host health probes live in
//! [`crate::routes::compat_team`].
//!
//! Every scrape is a normal run a worker executes ([`crate::scrape_service`]); these handlers
//! only translate between Firecrawl's wire shapes and runs.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::idempotency::{idempotent, Reply};
use crate::openapi::Operation;
use crate::resources::{expires_at, Warning};
use crate::routes::compat::concurrency_limit;
use crate::routes::crawls::{apply_verb, load_run, load_run_metadata, Verb};
use crate::routes::pages::sorted_pages;
use crate::scrape_service::{
    base_url, create_scrape_run, credits_for, failure_index, firecrawl_document, first_page,
    parse_scrape_options_in, parse_target, record_run_usage, row_failure, run_failure, scrape_crawl,
    scrape_url, ParsedScrape,
};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{idempotency_key, json_response, ts, JsonBody, Params};
use crate::webhooks::announce_started;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use chrono::Duration as ChronoDuration;
use crawlx_core::config::{RetentionMode, Webhook};
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::{CrawlRun, FrontierStatus};
use crawlx_core::scrape::JobKind;
use crawlx_policy::EgressPolicy;
use serde_json::{json, Map, Value};
use url::Url;

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "post",
        "/compat/firecrawl/v2/scrape",
        "firecrawlScrape",
        "Scrape one URL synchronously (Firecrawl scrape options; x-request-id replays)",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/firecrawl/v2/scrape/{jobId}",
        "firecrawlGetScrape",
        "A stored scrape by job id (run id, or run.frontier for pages of crawls and batches)",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/compat/firecrawl/v2/batch/scrape",
        "firecrawlBatchScrape",
        "Start a batch scrape (urls, ignoreInvalidURLs, maxConcurrency, webhook, scrape options)",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/firecrawl/v2/batch/scrape/{id}",
        "firecrawlBatchScrapeStatus",
        "Status and documents of a batch scrape (skip/limit paging)",
        "crawls:read",
        "200",
    ),
    (
        "delete",
        "/compat/firecrawl/v2/batch/scrape/{id}",
        "firecrawlBatchScrapeCancel",
        "Cancel a batch scrape",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/firecrawl/v2/batch/scrape/{id}/errors",
        "firecrawlBatchScrapeErrors",
        "Failed pages and robots-blocked URLs of a batch scrape",
        "crawls:read",
        "200",
    ),
];

/// The authenticated routes of this module, mounted behind the auth layer.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/firecrawl/v2/scrape", axum::routing::post(scrape))
        .route("/compat/firecrawl/v2/scrape/{job_id}", get(scrape_status))
        .route(
            "/compat/firecrawl/v2/batch/scrape",
            axum::routing::post(batch_create),
        )
        .route(
            "/compat/firecrawl/v2/batch/scrape/{id}",
            get(crate::routes::compat_ws::batch).delete(batch_cancel),
        )
        .route("/compat/firecrawl/v2/batch/scrape/{id}/errors", get(batch_errors))
}

fn body_object(body: &Value) -> Result<&Map<String, Value>, HttpError> {
    body.as_object().ok_or_else(|| {
        HttpError::bad_request(vec![Detail::new(
            "/",
            "invalid_type",
            "the body must be a JSON object",
        )])
    })
}

/// The idempotency key of a Firecrawl request: `x-request-id` (1..=128 of letters, digits, `.`,
/// `_`, `:`, `-`), else `Idempotency-Key`. The flag tells which one it was.
pub(crate) fn request_key(headers: &HeaderMap) -> ApiResult<(Option<String>, bool)> {
    if let Some(raw) = headers.get("x-request-id") {
        let ok = raw.to_str().ok().filter(|s| {
            (1..=128).contains(&s.len())
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
        });
        return match ok {
            // namespaced so a request id never collides with an `Idempotency-Key`
            Some(s) => Ok((Some(format!("x-request-id:{s}")), true)),
            None => Err(HttpError::bad_request(vec![Detail::new(
                "/headers/x-request-id",
                "invalid_string",
                "x-request-id must be 1 to 128 characters of letters, digits, `.`, `_`, `:` and `-`",
            )])),
        };
    }
    Ok((idempotency_key(headers, true)?, false))
}

/// A reused `x-request-id` conflicts the way Firecrawl documents it (`409 duplicate_request`,
/// `409 request_in_flight`); the job the original request is about stays on the error.
pub(crate) fn request_id_conflict(e: HttpError) -> HttpError {
    let mapped = match e.code {
        "idempotency_key_reuse" => HttpError::duplicate_request(),
        "idempotency_in_progress" => HttpError::request_in_flight(),
        _ => return e,
    };
    match e.job_id {
        Some(job) => mapped.with_job_id(job),
        None => mapped,
    }
}

fn with_warnings(mut body: Value, warnings: &[Warning]) -> Value {
    if !warnings.is_empty() {
        body["warnings"] = json!(warnings);
    }
    body
}

/// `POST /compat/firecrawl/v2/scrape`: scrape `url` with the Firecrawl scrape options of the
/// body and answer `{success, data}` once the worker finished. `x-request-id` (or
/// `Idempotency-Key`) replays a completed request; the same id with another body is `409
/// duplicate_request`, with the first still running `409 request_in_flight`.
///
/// # Errors
/// `403 scope_missing`; `400 BAD_REQUEST` for an invalid URL or option (Firecrawl's `details`);
/// `403 UNSUPPORTED_SITE` for a target the egress policy denies; `404 SCRAPE_NO_CACHED_DATA` /
/// `SCRAPE_LOCKDOWN_CACHE_MISS` for `minAge` / `lockdown` without a stored scrape; `408
/// SCRAPE_TIMEOUT`; `409` for a reused request id; `413` for a body above the limit; `429
/// quota_exceeded`; `503 llm_not_configured` when a format needs the LLM; `500` with the
/// failure code of the page (`SCRAPE_SITE_ERROR`, `SCRAPE_ALL_ENGINES_FAILED`, ...).
pub async fn scrape(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let (key, by_request_id) = request_key(&headers)?;
    let base = base_url(&headers);
    let out = idempotent(
        &state,
        &principal,
        key,
        "POST",
        "/compat/firecrawl/v2/scrape",
        &body,
        || async {
            let obj = body_object(&body)?;
            let mut details = Vec::new();
            let target = match obj.get("url") {
                Some(Value::String(s)) => parse_target(s, "/url").map_err(|d| details.push(d)).ok(),
                Some(_) => {
                    details.push(Detail::new("/url", "invalid_type", "url must be a string"));
                    None
                }
                None => {
                    details.push(Detail::new("/url", "required", "url is required"));
                    None
                }
            };
            let parsed = match parse_scrape_options_in(obj, "", &["url", "origin", "integration"]) {
                Ok(p) => Some(p),
                Err(d) => {
                    details.extend(d);
                    None
                }
            };
            let (Some(target), Some(parsed)) = (target, parsed) else {
                return Err(HttpError::bad_request(details));
            };
            let mut warnings = parsed.warnings.clone();
            let scraped = scrape_url(&state, &principal, &target, &parsed, &base, &mut warnings).await?;
            let reply = Reply::new(
                StatusCode::OK,
                with_warnings(json!({ "success": true, "data": scraped.document }), &warnings),
            );
            Ok(match scraped.created_run {
                Some(id) => reply.for_run(id),
                None => reply,
            })
        },
    )
    .await;
    if by_request_id {
        out.map_err(request_id_conflict)
    } else {
        out
    }
}

/// `GET /compat/firecrawl/v2/scrape/{jobId}`: the document of a stored scrape. `jobId` is the
/// run id of a scrape run, or `{run}.{frontier}` for one page of a crawl or batch run.
///
/// # Errors
/// `403 scope_missing`; `404 not_found` for an unknown id or another tenant's run; the Firecrawl
/// failure of a page that failed.
pub async fn scrape_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let base = base_url(&headers);
    let not_found = || HttpError::not_found("scrape job");
    let (run_part, page_part) = match job_id.split_once('.') {
        Some((r, f)) => (r, Some(f)),
        None => (job_id.as_str(), None),
    };
    let run = load_run(&state, &principal, run_part)
        .await
        .map_err(|_| not_found())?;
    let scrape_run = run.config.scrape.as_ref().map(|j| j.kind) == Some(JobKind::Scrape);
    match page_part {
        None => {
            if !scrape_run {
                return Err(not_found());
            }
            if !run.status.is_terminal() {
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "success": true, "status": "scraping" }),
                ));
            }
            let Some(page) = first_page(&state, &run).await? else {
                return Err(run_failure(&state, &run).await);
            };
            let doc = firecrawl_document(&state, &run, &page, &base).await;
            Ok(json_response(
                StatusCode::OK,
                &json!({ "success": true, "data": doc }),
            ))
        }
        Some(frontier) => {
            let frontier: i64 = frontier.parse().map_err(|_| not_found())?;
            let pages = sorted_pages(&state, &run, None).await?;
            if let Some(page) = pages.iter().find(|p| p.frontier_id == frontier) {
                let doc = firecrawl_document(&state, &run, page, &base).await;
                return Ok(json_response(
                    StatusCode::OK,
                    &json!({ "success": true, "data": doc }),
                ));
            }
            let rows = state.repos.frontier.list(run.id).await?;
            let row = rows.iter().find(|r| r.id == frontier).ok_or_else(not_found)?;
            match row.status {
                FrontierStatus::Pending | FrontierStatus::Leased => Ok(json_response(
                    StatusCode::OK,
                    &json!({ "success": true, "status": "scraping" }),
                )),
                _ => Err(row_failure(row, &failure_index(&state, run.id).await)),
            }
        }
    }
}

const BATCH_KEYS: [&str; 4] = ["urls", "webhook", "maxConcurrency", "ignoreInvalidURLs"];
const WEBHOOK_EVENTS: [&str; 4] = ["started", "page", "completed", "failed"];

/// A batch webhook: the delivery target plus headers and metadata Firecrawl echoes.
struct BatchWebhook {
    hook: Webhook,
    headers: std::collections::BTreeMap<String, String>,
    metadata: Value,
}

/// `webhook` as a URL string or an object `{url, headers, metadata, events}`. Event names may
/// carry the `batch_scrape.` prefix; the run stores them without it.
fn parse_webhook(v: &Value, details: &mut Vec<Detail>) -> Option<BatchWebhook> {
    let (url, headers, metadata, events): (Option<&str>, Option<&Value>, Value, Option<&Value>) = match v {
        Value::String(u) => (Some(u), None, Value::Null, None),
        Value::Object(m) => (
            m.get("url").and_then(Value::as_str),
            m.get("headers"),
            m.get("metadata").cloned().unwrap_or(Value::Null),
            m.get("events"),
        ),
        _ => {
            details.push(Detail::new(
                "/webhook",
                "invalid_type",
                "webhook is a URL or an object",
            ));
            return None;
        }
    };
    let Some(url) = url else {
        details.push(Detail::new("/webhook/url", "required", "webhook.url is required"));
        return None;
    };
    let url = match Url::parse(url) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => u,
        _ => {
            details.push(Detail::new(
                "/webhook/url",
                "invalid_string",
                "webhook.url must be an http(s) URL",
            ));
            return None;
        }
    };
    let mut header_map = std::collections::BTreeMap::new();
    match headers {
        None | Some(Value::Null) => {}
        Some(Value::Object(m)) => {
            for (k, val) in m {
                match val.as_str() {
                    Some(s) => {
                        header_map.insert(k.clone(), s.to_owned());
                    }
                    None => details.push(Detail::new(
                        format!("/webhook/headers/{}", k.replace('~', "~0").replace('/', "~1")),
                        "invalid_type",
                        "webhook header values must be strings",
                    )),
                }
            }
        }
        Some(_) => details.push(Detail::new(
            "/webhook/headers",
            "invalid_type",
            "expected an object",
        )),
    }
    if !(metadata.is_null() || metadata.is_object()) {
        details.push(Detail::new(
            "/webhook/metadata",
            "invalid_type",
            "expected an object",
        ));
    }
    let mut names: Vec<String> = Vec::new();
    match events {
        None | Some(Value::Null) => {}
        Some(Value::Array(a)) => {
            for (i, e) in a.iter().enumerate() {
                let name = e.as_str().map(|s| s.strip_prefix("batch_scrape.").unwrap_or(s));
                match name {
                    Some(n) if WEBHOOK_EVENTS.contains(&n) => {
                        if !names.iter().any(|x| x == n) {
                            names.push(n.to_owned());
                        }
                    }
                    _ => details.push(Detail::new(
                        format!("/webhook/events/{i}"),
                        "unknown_enum",
                        "an event is started, page, completed or failed",
                    )),
                }
            }
        }
        Some(_) => details.push(Detail::new(
            "/webhook/events",
            "invalid_type",
            "expected an array",
        )),
    }
    if names.is_empty() {
        names = WEBHOOK_EVENTS.map(str::to_owned).to_vec();
    }
    Some(BatchWebhook {
        hook: Webhook { url, events: names },
        headers: header_map,
        metadata,
    })
}

/// The URLs of a batch: valid ones (deduplicated, in order) and the rejected strings. A URL is
/// rejected when it does not parse as `http(s)` with a host or the egress policy denies it.
fn split_urls(urls: &[Value], details: &mut Vec<Detail>, ignore_invalid: bool) -> (Vec<Url>, Vec<String>) {
    let mut valid: Vec<Url> = Vec::new();
    let mut invalid: Vec<String> = Vec::new();
    for (i, v) in urls.iter().enumerate() {
        let path = format!("/urls/{i}");
        let Some(text) = v.as_str() else {
            details.push(Detail::new(path, "invalid_type", "a URL is a string"));
            invalid.push(v.to_string());
            continue;
        };
        let checked = parse_target(text, &path).and_then(|u| {
            EgressPolicy::new(false)
                .with_seed_port(&u)
                .check_url(&u)
                .map(|()| u)
                .map_err(|e| Detail::new(path.clone(), "url_denied", e.to_string()))
        });
        match checked {
            Ok(u) => {
                if !valid.contains(&u) {
                    valid.push(u);
                }
            }
            Err(d) => {
                if !ignore_invalid {
                    details.push(d);
                }
                invalid.push(text.to_owned());
            }
        }
    }
    (valid, invalid)
}

/// `POST /compat/firecrawl/v2/batch/scrape`: start one run over `urls` (the first is the seed,
/// the rest `scrape.urls`) with the scrape options, `maxConcurrency` and `webhook`. Invalid URLs
/// are skipped and listed in `invalidURLs` unless `ignoreInvalidURLs` is false.
///
/// # Errors
/// `403 scope_missing`; `400 BAD_REQUEST` for a malformed body, an invalid URL with
/// `ignoreInvalidURLs: false`, or no valid URL; `403 UNSUPPORTED_SITE` for a denied seed; `429
/// quota_exceeded`; the idempotency errors of [`crate::idempotency::idempotent`].
pub async fn batch_create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let key = idempotency_key(&headers, true)?;
    let base = base_url(&headers);
    idempotent(
        &state,
        &principal,
        key,
        "POST",
        "/compat/firecrawl/v2/batch/scrape",
        &body,
        || async {
            let obj = body_object(&body)?;
            let mut details: Vec<Detail> = Vec::new();
            let ignore_invalid = match obj.get("ignoreInvalidURLs") {
                None | Some(Value::Null) => true,
                Some(Value::Bool(b)) => *b,
                Some(_) => {
                    details.push(Detail::new(
                        "/ignoreInvalidURLs",
                        "invalid_type",
                        "expected a boolean",
                    ));
                    true
                }
            };
            let (valid, invalid) = match obj.get("urls") {
                Some(Value::Array(a)) if !a.is_empty() => split_urls(a, &mut details, ignore_invalid),
                Some(Value::Array(_)) => {
                    details.push(Detail::new(
                        "/urls",
                        "too_small",
                        "urls must hold at least one URL",
                    ));
                    (Vec::new(), Vec::new())
                }
                Some(_) => {
                    details.push(Detail::new(
                        "/urls",
                        "invalid_type",
                        "urls must be an array of URLs",
                    ));
                    (Vec::new(), Vec::new())
                }
                None => {
                    details.push(Detail::new("/urls", "required", "urls is required"));
                    (Vec::new(), Vec::new())
                }
            };
            if valid.is_empty() && details.is_empty() {
                details.push(Detail::new(
                    "/urls",
                    "invalid_string",
                    "none of the URLs is valid",
                ));
            }
            let max_concurrency = match obj.get("maxConcurrency") {
                None | Some(Value::Null) => None,
                Some(v) => match v.as_u64().filter(|n| *n >= 1) {
                    Some(n) => Some(u16::try_from(n.min(256)).unwrap_or(256)),
                    None => {
                        details.push(Detail::new(
                            "/maxConcurrency",
                            "out_of_range",
                            "expected a positive integer",
                        ));
                        None
                    }
                },
            };
            let webhook = obj.get("webhook").and_then(|v| parse_webhook(v, &mut details));
            let parsed: Option<ParsedScrape> = match parse_scrape_options_in(obj, "", &BATCH_KEYS) {
                Ok(p) => Some(p),
                Err(d) => {
                    details.extend(d);
                    None
                }
            };
            let Some(parsed) = parsed.filter(|_| details.is_empty()) else {
                return Err(HttpError::bad_request(details));
            };
            let mut crawl = scrape_crawl(valid[0].clone(), JobKind::Batch, &parsed, valid.len())
                .map_err(HttpError::bad_request)?;
            if let Some(job) = crawl.scrape.as_mut() {
                job.urls = valid[1..].to_vec();
            }
            if let Some(n) = max_concurrency {
                crawl.politeness.max_concurrency = n;
            }
            if let Some(w) = webhook {
                crawl.output.webhook = Some(w.hook);
                if let Some(job) = crawl.scrape.as_mut() {
                    job.webhook_headers = w.headers;
                    job.webhook_metadata = w.metadata;
                }
            }
            let mut warnings = parsed.warnings.clone();
            let run = create_scrape_run(&state, &principal, crawl, &mut warnings)
                .await
                .map_err(concurrency_limit)?;
            announce_started(&state, &run).await?;
            let mut out = json!({
                "success": true,
                "id": run.id,
                "url": format!("{base}/compat/firecrawl/v2/batch/scrape/{}", run.id),
            });
            if ignore_invalid {
                out["invalidURLs"] = json!(invalid);
            }
            Ok(Reply::new(StatusCode::OK, with_warnings(out, &warnings)).for_run(run.id))
        },
    )
    .await
}

pub(crate) const fn batch_status_name(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Queued | RunStatus::Running | RunStatus::Paused => "scraping",
        RunStatus::Completed => "completed",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

/// Load a batch scrape run of the caller; any other run answers `404` like an unknown id.
pub(crate) async fn load_batch(state: &AppState, principal: &Principal, id: &str) -> ApiResult<CrawlRun> {
    let not_found = || HttpError::not_found("batch scrape");
    let run = load_run(state, principal, id).await.map_err(|_| not_found())?;
    if run.config.scrape.as_ref().map(|j| j.kind) == Some(JobKind::Batch) {
        Ok(run)
    } else {
        Err(not_found())
    }
}

/// Firecrawl's `total` of a batch scrape: the primary URL plus every further URL of the job.
pub(crate) fn batch_total(run: &CrawlRun) -> usize {
    1 + run.config.scrape.as_ref().map_or(0, |j| j.urls.len())
}

/// `expiresAt` of a batch scrape: the end of the retention window, counted from the creation of a
/// run that has not finished yet.
pub(crate) fn batch_expires(run: &CrawlRun) -> crawlx_core::Timestamp {
    let retention_days = if run.config.retention.mode == RetentionMode::Zdr {
        0
    } else {
        i64::from(run.config.retention.days)
    };
    expires_at(run).unwrap_or(run.created_at + ChronoDuration::days(retention_days))
}

/// `GET /compat/firecrawl/v2/batch/scrape/{id}`: `status` (`scraping`, `completed`, `failed`,
/// `cancelled`), `total`, `completed`, `creditsUsed`, `expiresAt` and the documents of this
/// page of `data`; `?skip=` and `?limit=` page through them and `next` links to the next page.
///
/// # Errors
/// `403 scope_missing`; `404 not_found` for an unknown id, another tenant's run or a run that is
/// not a batch scrape; `400 malformed_request` for a bad `skip` or `limit`.
pub async fn batch_status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    if run.scrape_kind != Some(JobKind::Batch) {
        return Err(HttpError::not_found("batch scrape"));
    }
    let live = if crate::routes::pages::zdr_output_expired(&state, &run).await? {
        None
    } else {
        Some(load_batch(&state, &principal, &id).await?)
    };
    let base = base_url(&headers);
    let skip = match params.get("skip") {
        None => 0,
        Some(v) => v
            .parse::<usize>()
            .map_err(|_| HttpError::malformed("skip must be a non-negative integer"))?,
    };
    let limit = params.limit(&state.settings)?;
    let pages = match &live {
        Some(live) => sorted_pages(&state, live, None).await?,
        None => Vec::new(),
    };
    let (credits, completed) = if run.retention.mode == RetentionMode::Zdr {
        let billing = crate::scrape_service::run_billing(&state, run.id, live.as_ref()).await?;
        (billing.credits, billing.pages)
    } else {
        let credits = match &live {
            Some(live) => pages.iter().map(|page| credits_for(live, page)).sum(),
            None => 0,
        };
        (credits, u64::try_from(pages.len()).unwrap_or(u64::MAX))
    };
    let total = run.batch_total;
    let window: Vec<_> = pages.iter().skip(skip).take(limit).collect();
    let mut data = Vec::with_capacity(window.len());
    if let Some(live) = &live {
        for page in &window {
            data.push(firecrawl_document(&state, live, page, &base).await);
        }
    }
    let next = if skip + window.len() < pages.len() {
        let mut link = format!(
            "{base}/compat/firecrawl/v2/batch/scrape/{}?skip={}",
            run.id,
            skip + window.len()
        );
        if params.get("limit").is_some() {
            link.push_str(&format!("&limit={limit}"));
        }
        Value::String(link)
    } else {
        Value::Null
    };
    match &live {
        Some(live) => record_run_usage(&state, live).await,
        None => crate::scrape_service::record_metadata_usage(&state, &run).await,
    }
    let now = state.clock.now();
    let end = run.finished_at.unwrap_or(now);
    let retention_days = if run.retention.mode == RetentionMode::Zdr {
        0
    } else {
        i64::from(run.retention.days)
    };
    let expires = crate::resources::metadata_expires_at(&run)
        .unwrap_or(run.created_at + ChronoDuration::days(retention_days));
    let mut body = json!({
        "success": true,
        "status": batch_status_name(run.status),
        "total": total,
        "completed": completed,
        "creditsUsed": credits,
        "expiresAt": ts(expires),
        "createdAt": ts(run.created_at),
        "duration": (end - run.created_at).num_milliseconds() as f64 / 1000.0,
        "next": next,
        "data": data,
    });
    if let Some(f) = run.finished_at {
        body["completedAt"] = json!(ts(f));
    }
    Ok(json_response(StatusCode::OK, &body))
}

/// `DELETE /compat/firecrawl/v2/batch/scrape/{id}`: cancel the batch.
///
/// # Errors
/// `403 scope_missing`; `404 not_found`; `409 invalid_state` when the batch already finished.
pub async fn batch_cancel(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_batch(&state, &principal, &id).await?;
    let (_, after) = apply_verb(&state, run, Verb::Cancel).await?;
    record_run_usage(&state, &after).await;
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "status": batch_status_name(after.status) }),
    ))
}

/// `GET /compat/firecrawl/v2/batch/scrape/{id}/errors`: `errors[]` (`id`, `timestamp`, `url`,
/// `code`, `error`) for every page that failed and `robotsBlocked[]` for every URL robots.txt
/// refused.
///
/// # Errors
/// `403 scope_missing`; `404 not_found`.
pub async fn batch_errors(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_batch(&state, &principal, &id).await?;
    let index = failure_index(&state, run.id).await;
    let now = ts(state.clock.now());
    let mut errors = Vec::new();
    let mut robots = Vec::new();
    for row in state.repos.frontier.list(run.id).await? {
        let url = row.url.url.to_string();
        match row.status {
            FrontierStatus::Failed | FrontierStatus::Abandoned | FrontierStatus::Unreachable => {
                let e = row_failure(&row, &index);
                let at = index.get(&url).map_or_else(|| now.clone(), |(_, at)| ts(*at));
                errors.push(json!({
                    "id": format!("{}.{}", run.id, row.id),
                    "timestamp": at,
                    "url": url,
                    "code": row.denial_reason.clone().unwrap_or_else(|| row.status.as_str().to_owned()),
                    "error": e.message,
                }));
            }
            FrontierStatus::RobotsBlocked => robots.push(Value::String(url)),
            _ => {}
        }
    }
    Ok(json_response(
        StatusCode::OK,
        &json!({ "errors": errors, "robotsBlocked": robots }),
    ))
}
