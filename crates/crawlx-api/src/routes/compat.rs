//! compat v2 compatibility facade mounted at `/compat`: start,
//! status, cancel and errors of a crawl. The request translation lives in
//! [`crate::routes::compat_crawl`], the crawl is a run whose pages the worker's scrape engine
//! produces ([`crate::scrape_service`]).
//!
//! Lenient by design: options crawlx does not support are ignored and reported in the
//! response's additive `warnings[]`. The facade crawls in `static` mode; page options that need a
//! browser (`waitFor`, `actions`, `mobile`, screenshots) are executed by the worker's renderer.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::idempotency::{idempotent, idempotent_job, Reply};
use crate::intel::common::{llm, llm_error};
use crate::intel::usage::{self, Cost};
use crate::resources::{counters_json, Warning};
use crate::routes::compat_crawl::{translate, Translated};
use crate::routes::compat_scrape::{request_id_conflict, request_key};
use crate::routes::crawls::{apply_verb, load_run, load_run_metadata, Verb};
use crate::routes::pages::{page_key, sorted_pages};
use crate::scrape_service::{
    base_url, compat_document, create_scrape_run, create_scrape_run_as, credits_for, failure_code,
    failure_index, failure_reason, failure_text, parse_target, record_run_usage,
};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, next_link, paginate, ts, JsonBody, Params};
use crate::webhooks::announce_started;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::{CreateCrawl, OutputFormat, RetentionMode};
use crawlx_core::counters::RunStatus;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{CrawlRun, FrontierEntry, FrontierStatus, PageRecord, RunMetadata};
use crawlx_core::scrape::{FormatSpec, JobKind};
use crawlx_core::TenantId;
use crawlx_model::llm::TokenUsage;
use crawlx_storage::TenantEngine;
use serde_json::{json, Map, Value};

/// Header the strangler gateway sets on mirrored requests.
pub const SHADOW_HEADER: &str = "x-crawlx-shadow";

/// Shadow crawls keep at most this many pages (planning default).
const SHADOW_LIMIT_MAX: u32 = 200;

/// Frontier denial reason of an external homepage skipped under `allowExternalLinks`
/// (`DenialReason::ExternalHomepage`); the compat API reports it as `EXTERNAL_LINK`.
const EXTERNAL_HOMEPAGE: &str = "external_homepage";

/// The `code` of the `errors[]` entry of the crawl's entry URL that `includePaths` (or
/// `regexOnFullURL` patterns) refused as a page: the compat API still fetches that URL to find links,
/// and reports it as a denied URL.
const CRAWL_DENIAL: &str = "CRAWL_DENIAL";

/// Deterministic sampling: the same `(tenant, idempotency key)` is always in or out of the
/// sample, so a gateway retry cannot flip the decision. `percent` is clamped to 0..=100.
fn shadow_sampled(tenant: TenantId, key: &str, percent: u8) -> bool {
    let percent = u16::from(percent.min(100));
    if percent == 0 {
        return false;
    }
    let digest = Digest::of("crawlx/shadow-sample/v1", format!("{tenant}\n{key}").as_bytes());
    let bucket = u16::from_le_bytes([digest.0[0], digest.0[1]]) % 100;
    bucket < percent
}

/// Rewrite a translated crawl into its shadow form: page limit clamped to 200,
/// per-origin concurrency halved, `rawHtml` added so the comparator can separate source changes
/// from extraction differences, no customer webhook, 24-hour retention.
fn shadow_rewrite(crawl: &mut CreateCrawl) {
    crawl.limits.urls = crawl.limits.urls.min(SHADOW_LIMIT_MAX);
    crawl.politeness.max_in_flight_per_origin = (crawl.politeness.max_in_flight_per_origin / 2).max(1);
    crawl.output.webhook = None;
    if !crawl.output.formats.contains(&OutputFormat::RawHtml) {
        crawl.output.formats.push(OutputFormat::RawHtml);
    }
    if let Some(job) = crawl.scrape.as_mut() {
        job.webhook_headers.clear();
        job.webhook_metadata = Value::Null;
        let o = &mut job.options;
        // `rawBase64` must stay the only format of its request
        if !o.wants("rawHtml") && !o.wants("rawBase64") {
            o.formats.push(FormatSpec::RawHtml);
        }
    }
    crawl.retention.days = 1;
}

/// Crawl options the configured LLM derives from `prompt`, with the tokens they cost.
///
/// `None` without an LLM, without a usable prompt or URL (the translation then reports what is
/// wrong with the request itself).
async fn plan_from_prompt(
    state: &AppState,
    body: &Value,
) -> ApiResult<Option<(Map<String, Value>, TokenUsage)>> {
    let Some(llm) = &state.llm else {
        return Ok(None);
    };
    let prompt = body
        .get("prompt")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty());
    let url = body
        .get("url")
        .and_then(Value::as_str)
        .and_then(|u| parse_target(u, "/url").ok());
    let (Some(prompt), Some(url)) = (prompt, url) else {
        return Ok(None);
    };
    let planned = llm
        .plan_crawl_options(url.as_str(), prompt)
        .await
        .map_err(|e| llm_error(&e))?;
    Ok(planned.value.as_object().cloned().map(|m| (m, planned.usage)))
}

/// The compat API's `429` text for an exhausted concurrency allowance.
pub(crate) fn concurrency_limit(mut e: HttpError) -> HttpError {
    if e.code == "quota_exceeded" {
        e.message = format!("Concurrency limit reached: {}", e.message);
    }
    e
}

/// Machine-readable code of a refused `ignoreRobotsTxt`.
pub const ROBOTS_OVERRIDE_CODE: &str = "ROBOTS_OVERRIDE_NOT_AUTHORIZED";

fn robots_override_denied(why: impl Into<String>) -> HttpError {
    HttpError::compat(
        StatusCode::FORBIDDEN,
        ROBOTS_OVERRIDE_CODE,
        format!("ignoreRobotsTxt is not authorized on this server: {}", why.into()),
    )
}

/// `ignoreRobotsTxt: true`: lower the robots.txt gate of `crawl` under the facade's
/// authorization record (`compat.robotsAuthorization`); admission then checks the record
/// (tenant, validity window, seed coverage, `robotsOverrideAcknowledged`).
///
/// # Errors
/// `403 ROBOTS_OVERRIDE_NOT_AUTHORIZED` when no record is configured.
fn lower_robots_gate(state: &AppState, crawl: &mut CreateCrawl) -> ApiResult<()> {
    let Some(record) = state.config.compat.robots_authorization else {
        return Err(robots_override_denied(
            "the operator has not configured an authorization record (compat.robotsAuthorization)",
        ));
    };
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(record);
    Ok(())
}

/// A failed admission of a run that lowered the robots gate: when the authorization record is
/// the reason (missing, expired, another tenant's, not covering the seed, without the robots
/// acknowledgement) the answer is `403 ROBOTS_OVERRIDE_NOT_AUTHORIZED` naming it.
fn robots_override_error(e: HttpError, lowered: bool) -> HttpError {
    let record = e
        .details
        .iter()
        .find(|d| lowered && d.code == "authorization_required");
    match record {
        Some(d) => {
            let mut denied = robots_override_denied(d.message.clone());
            denied.details = e.details;
            denied
        }
        None => concurrency_limit(e),
    }
}

/// `POST /compat/v2/crawl`. `x-request-id` (else `Idempotency-Key`) is the replay key.
///
/// The strangler gateway is honoured here: the tenant's `engine` flag decides
/// whether a non-shadow request is served (`crawlx`) or refused (`upstream`, `shadow`), and a
/// request carrying `X-Crawlx-Shadow: 1` is mirrored into a `run_kind = 'shadow'` run when it
/// falls into the configured sample and does not ask for zero data retention.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `409 engine_mismatch` when the tenant engine
/// routes the request elsewhere, `422` for a missing `url`, `400 BAD_REQUEST` for any other
/// invalid body, `403 UNSUPPORTED_SITE` for a target the egress policy denies, `429` above the
/// active-run quota (`Concurrency limit reached`), `503 llm_not_configured`-style failures of the
/// LLM when a `prompt` is planned, `400 /headers/x-request-id` for a malformed request id, `409
/// request_in_flight` (`{success:false, code, id, error}` with the `id` of the original job) for
/// a repeat that arrives while the first request is still being processed, `409
/// duplicate_request` for the same `x-request-id` with other parameters (`422
/// idempotency_key_reuse` for an `Idempotency-Key`).
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let shadow = headers
        .get(SHADOW_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "1");
    let engine = state.repos.api.tenant_engine(principal.tenant).await?;
    match (engine, shadow) {
        (TenantEngine::Upstream | TenantEngine::Shadow, false) => {
            return Err(HttpError::engine_mismatch(engine.as_str(), false));
        }
        (TenantEngine::Upstream, true) => {
            return Err(HttpError::engine_mismatch(engine.as_str(), true));
        }
        _ => {}
    }
    let (key, by_request_id) = request_key(&headers)?;
    let base = base_url(&headers);
    if shadow {
        return shadow_create(&state, &principal, key, &base, &body).await;
    }
    let (st, pr, bd, bs) = (&state, &principal, &body, &base);
    idempotent_job(st, pr, key, "POST", "/compat/v2/crawl", bd, |id| async move {
        let planned = plan_from_prompt(st, bd).await?;
        let Translated {
            mut crawl,
            mut warnings,
            robots_override,
            query_policy_unset,
        } = translate(bd, planned.as_ref().map(|(m, _)| m))?;
        st.config.compat.mode.apply(&mut crawl, query_policy_unset);
        // the LLM formats need the configured LLM: refuse before a run exists
        if crawl
            .scrape
            .as_ref()
            .is_some_and(|j| j.options.formats.iter().any(FormatSpec::needs_llm))
        {
            llm(st)?;
        }
        if robots_override {
            lower_robots_gate(st, &mut crawl)?;
        }
        // the run is created under the id the idempotency claim announced
        let run = create_scrape_run_as(st, pr, crawl, &mut warnings, id)
            .await
            .map_err(|e| robots_override_error(e, robots_override))?;
        announce_started(st, &run).await?;
        if let Some((_, tokens)) = planned {
            usage::record(
                st,
                pr.tenant,
                "crawl-prompt",
                // not the run id: `record_run_usage` books the crawl by that reference
                None,
                "completed",
                Cost { credits: 0, tokens },
            )
            .await;
        }
        Ok(Reply::new(
            StatusCode::OK,
            json!({
                "success": true,
                "id": id,
                "url": format!("{bs}/compat/v2/crawl/{id}"),
                "warnings": warnings,
            }),
        )
        .for_run(id))
    })
    .await
    .map_err(|e| crawl_request_conflict(e, by_request_id))
}

/// The conflicts of a repeated crawl request in the compat API's words: a repeat that arrives while
/// the original is still being processed is `409 request_in_flight` whichever header carried the
/// key; the same `x-request-id` with other parameters is `409 duplicate_request`. Both carry the
/// `id` of the original job. An `Idempotency-Key` with other parameters stays `422
/// idempotency_key_reuse`.
fn crawl_request_conflict(e: HttpError, by_request_id: bool) -> HttpError {
    if by_request_id || e.code == "idempotency_in_progress" {
        request_id_conflict(e)
    } else {
        e
    }
}

/// The shadow branch of [`create`]: never mirrors `zeroDataRetention: true`, samples by
/// `Settings::shadow_sample_percent`, records the mirrored run as `run_kind = 'shadow'`.
async fn shadow_create(
    state: &AppState,
    principal: &Principal,
    key: Option<String>,
    base: &str,
    body: &Value,
) -> ApiResult<Response> {
    let zdr = body.get("zeroDataRetention").and_then(Value::as_bool) == Some(true);
    let sampled = match &key {
        Some(k) => shadow_sampled(principal.tenant, k, state.settings.shadow_sample_percent),
        // without a key the gateway cannot derive one; a keyless tee is not mirrored
        None => false,
    };
    let skip = |reason: &str| json!({ "success": true, "shadow": true, "mirrored": false, "reason": reason });
    idempotent(
        state,
        principal,
        key,
        "POST",
        "/compat/v2/crawl#shadow",
        body,
        || async {
            if zdr {
                return Ok(Reply::new(StatusCode::OK, skip("zero_data_retention")));
            }
            if !sampled {
                return Ok(Reply::new(StatusCode::OK, skip("not_sampled")));
            }
            let Translated {
                mut crawl,
                mut warnings,
                query_policy_unset,
                ..
            } = translate(body, None)?;
            state.config.compat.mode.apply(&mut crawl, query_policy_unset);
            shadow_rewrite(&mut crawl);
            warnings.push(Warning::new(
                "shadow_rewritten",
                "/",
                "shadow crawl: limit clamped to 200, concurrency halved, rawHtml added, webhook dropped, retention 24h",
            ));
            let run = create_scrape_run(state, principal, crawl, &mut warnings)
                .await
                .map_err(concurrency_limit)?;
            let id = run.id;
            state.repos.api.shadow_tag(id).await?;
            state
                .repos
                .api
                .audit_append(
                    principal.tenant,
                    Some(id),
                    "gateway",
                    "shadow.mirrored",
                    json!({ "samplePercent": state.settings.shadow_sample_percent }),
                )
                .await?;
            Ok(Reply::new(
                StatusCode::OK,
                json!({
                    "success": true,
                    "id": id,
                    "url": format!("{base}/compat/v2/crawl/{id}"),
                    "shadow": true,
                    "mirrored": true,
                    "warnings": warnings,
                }),
            )
            .for_run(id))
        },
    )
    .await
}

/// The compat `status` of a run: `scraping` until it is terminal.
pub(crate) const fn facade_status(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Queued | RunStatus::Running | RunStatus::Paused => "scraping",
        RunStatus::Completed => "completed",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
    }
}

/// The compat API's `total` of a crawl: the completed pages plus the ones in flight or queued; failed
/// pages are not counted, and a finished crawl has nothing left in flight.
pub(crate) fn crawl_total(run: &CrawlRun) -> u64 {
    let c = &run.counters.urls;
    if run.status.is_terminal() {
        c.succeeded
    } else {
        c.admitted
            .saturating_sub(c.failed.saturating_add(c.abandoned).saturating_add(c.unreachable))
    }
}

/// A run of the caller's tenant that the crawl routes serve: a crawl of the facade or a native
/// run; the batch, scrape and map runs have their own routes.
pub(crate) async fn load_crawl(state: &AppState, principal: &Principal, id: &str) -> ApiResult<CrawlRun> {
    let run = load_run(state, principal, id).await?;
    match run.config.scrape.as_ref().map(|j| j.kind) {
        None | Some(JobKind::Crawl) => Ok(run),
        Some(_) => Err(HttpError::not_found("crawl")),
    }
}

/// Pages of `run` that `data` may list plus the credits the run's pages cost. Zero-data-retention
/// runs list only the pages still in the delivery buffer but bill every page.
pub(crate) async fn crawl_pages(
    state: &AppState,
    run: &CrawlRun,
) -> ApiResult<(Vec<(String, PageRecord)>, u64)> {
    let visible = sorted_pages(state, run, None).await?;
    let credits = if run.config.retention.mode == RetentionMode::Zdr {
        crate::scrape_service::run_billing(state, run.id, Some(run))
            .await?
            .credits
    } else {
        visible.iter().map(|p| credits_for(run, p)).sum()
    };
    let keyed = visible.into_iter().map(|p| (page_key(&p), p)).collect();
    Ok((keyed, credits))
}

/// `next` link of an offset (`?skip=`) page: the original query with `skip` replaced.
fn skip_link(path: &str, params: &Params, skip: usize) -> Value {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in &params.0 {
        if name != "cursor" && name != "skip" {
            ser.append_pair(name, value);
        }
    }
    ser.append_pair("skip", &skip.to_string());
    Value::String(format!("{path}?{}", ser.finish()))
}

/// A stopped crawl that found at most this many pages gets a hint on how to broaden it.
const FEW_RESULTS: u64 = 1;

/// The human-readable `warning` of a crawl status, if there is one: pages the site's robots.txt
/// disallowed (they are listed under `robotsBlocked` of the errors route), else a stopped crawl
/// that found at most one page. Wording is the one existing clients show their users.
fn status_warning(run: &RunMetadata, id: &str, seed_host: Option<&str>) -> Option<String> {
    if run.counters.urls.robots_blocked > 0 {
        return Some(format!(
            "One or more pages could not be crawled because the site's robots.txt disallows them. See the robotsBlocked list on GET /compat/v2/crawl/{id}/errors. Teams with the feature enabled can set ignoreRobotsTxt: true."
        ));
    }
    let stopped = matches!(run.status, RunStatus::Completed | RunStatus::Cancelled);
    let found = run.counters.urls.succeeded;
    if stopped && found <= FEW_RESULTS {
        let start = seed_host.map_or_else(
            || "a higher-level path".to_owned(),
            |host| format!("a higher-level path like {host}"),
        );
        return Some(format!(
            "Only {found} result(s) found. For broader coverage, try crawling with crawlEntireDomain=true or start from {start}"
        ));
    }
    None
}

/// `GET /compat/v2/crawl/{id}`.
///
/// `data` holds the compat documents of the crawl's pages (`?limit=` per response, `?skip=`
/// as an offset or `?cursor=` as the opaque position the `next` link carries). `creditsUsed`
/// sums the credits of every stored page (`1` per page plus the extras of `json` and the other
/// LLM formats); a terminal crawl is booked in the usage ledger once.
///
/// `next` is non-null only when another stored page is available, even while the crawl is
/// running. Poll this status route again to wait for new pages; `next` is not a polling link.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run, a run owned by
/// another tenant or a batch/scrape/map run, `400 malformed_request` for a bad `limit`, `skip`
/// or `cursor`.
pub async fn status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    if !matches!(run.scrape_kind, None | Some(JobKind::Crawl)) {
        return Err(HttpError::not_found("crawl"));
    }
    let live = if crate::routes::pages::zdr_output_expired(&state, &run).await? {
        None
    } else {
        Some(load_crawl(&state, &principal, &id).await?)
    };
    let limit = params.limit(&state.settings)?;
    let skip = params
        .get("skip")
        .map(str::parse::<usize>)
        .transpose()
        .map_err(|_| HttpError::malformed("skip must be a non-negative integer"))?;
    let cursor = params.cursor_key()?;
    let base = base_url(&headers);
    let (keyed, credits) = match &live {
        Some(live) => crawl_pages(&state, live).await?,
        None => (
            Vec::new(),
            crate::scrape_service::run_billing(&state, run.id, None)
                .await?
                .credits,
        ),
    };
    let path = format!("{base}/compat/v2/crawl/{}", run.id);
    let (page, next) = if let Some(skipped) = skip {
        let rest: Vec<PageRecord> = keyed.into_iter().map(|(_, p)| p).skip(skipped).collect();
        let more = rest.len() > limit;
        let page: Vec<PageRecord> = rest.into_iter().take(limit).collect();
        let next = if more {
            skip_link(&path, &params, skipped.saturating_add(limit))
        } else {
            Value::Null
        };
        (page, next)
    } else {
        let (page, next_key) = paginate(keyed, limit, cursor.as_deref());
        let next = next_link(&path, &params, next_key.as_deref());
        (page, next)
    };
    let mut data = Vec::with_capacity(page.len());
    if let Some(live) = &live {
        for p in &page {
            data.push(compat_document(&state, live, p, &base).await);
        }
    }
    let coverage = state.repos.ledger.summary(run.id).await?;
    let c = &run.counters.urls;
    let total = if run.status.is_terminal() {
        c.succeeded
    } else {
        c.admitted
            .saturating_sub(c.failed.saturating_add(c.abandoned).saturating_add(c.unreachable))
    };
    let ended = run.finished_at.filter(|_| run.status.is_terminal());
    let duration = (ended.unwrap_or_else(|| state.clock.now()) - run.created_at)
        .num_milliseconds()
        .max(0);
    let mut body = json!({
        "success": true,
        "status": facade_status(run.status),
        "total": total,
        "completed": c.succeeded,
        "creditsUsed": credits,
        "expiresAt": ts(crate::resources::status_expires_at(&run)),
        "createdAt": ts(run.created_at),
        "duration": seconds(duration),
        "next": next,
        "data": data,
        "terminalReason": run.terminal_reason,
        "counters": counters_json(&run.counters),
        "coverage": {
            "unit": "ActionContextKey",
            "discovered": coverage.discovered,
            "exercisedTrusted": coverage.exercised_trusted,
            "groundTruthRecall": Value::Null,
        },
        "warnings": crate::resources::metadata_warnings(run.query_policy),
    });
    if let (Some(at), Some(obj)) = (ended, body.as_object_mut()) {
        obj.insert("completedAt".to_owned(), json!(ts(at)));
    }
    let seed_host = live
        .as_ref()
        .and_then(|l| l.config.seed_url.host_str().map(str::to_owned));
    if let (Some(text), Some(obj)) = (
        status_warning(&run, &run.id.to_string(), seed_host.as_deref()),
        body.as_object_mut(),
    ) {
        obj.insert("warning".to_owned(), json!(text));
    }
    if run.status.is_terminal() {
        match &live {
            Some(live) => record_run_usage(&state, live).await,
            None => crate::scrape_service::record_metadata_usage(&state, &run).await,
        }
    }
    Ok(json_response(StatusCode::OK, &body))
}

/// Milliseconds as seconds with millisecond precision.
#[allow(
    clippy::cast_precision_loss,
    reason = "a crawl lasts far fewer milliseconds than 2^53"
)]
fn seconds(ms: i64) -> f64 {
    ms as f64 / 1000.0
}

/// `DELETE /compat/v2/crawl/{id}` (cancels the crawl).
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `404 not_found` for an unknown run, a run owned by
/// another tenant or a batch/scrape/map run, `409 invalid_state` when the run cannot be
/// cancelled.
pub async fn cancel(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_crawl(&state, &principal, &id).await?;
    let (_, after) = apply_verb(&state, run, Verb::Cancel).await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "status": facade_status(after.status) }),
    ))
}

/// `GET /compat/v2/crawl/{id}/errors`: `errors[{id, timestamp, url, code, error}]`
/// for pages that failed, for external homepages skipped under `allowExternalLinks` (code
/// `EXTERNAL_LINK`) and for the entry URL that `includePaths` refused as a page (code
/// `CRAWL_DENIAL`; it was fetched for its links only), `robotsBlocked[]` and the additive
/// `policyBlocked[]`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run, a run owned by
/// another tenant or a batch/scrape/map run.
pub async fn errors(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_crawl(&state, &principal, &id).await?;
    let now = ts(state.clock.now());
    let mut errors = Vec::new();
    let mut robots = Vec::new();
    let mut policy = Vec::new();
    let index = failure_index(&state, run.id).await;
    for f in state.repos.frontier.list(run.id).await? {
        let url = f.url.to_string();
        match f.status {
            FrontierStatus::Failed | FrontierStatus::Abandoned | FrontierStatus::Unreachable => {
                let reason = failure_reason(&f);
                let (message, at) = index
                    .get(f.url.url.as_str())
                    .map_or((None, None), |(m, at)| (m.as_deref(), Some(*at)));
                errors.push(json!({
                    "id": f.id.to_string(),
                    "timestamp": at.map_or_else(|| now.clone(), ts),
                    "url": url,
                    "code": failure_code(reason).code,
                    "error": failure_text(reason, message),
                }));
            }
            FrontierStatus::RobotsBlocked => robots.push(Value::String(url)),
            FrontierStatus::PolicyBlocked if f.denial_reason.as_deref() == Some(EXTERNAL_HOMEPAGE) => {
                errors.push(json!({
                    "id": f.id.to_string(),
                    "timestamp": now,
                    "url": url,
                    "code": "EXTERNAL_LINK",
                    "error": "The homepage of an external site is not crawled (allowExternalLinks follows external pages one hop)",
                }));
            }
            FrontierStatus::PolicyBlocked if is_entry_include_denial(&f) => {
                errors.push(json!({
                    "id": f.id.to_string(),
                    "timestamp": now,
                    "url": url,
                    "code": CRAWL_DENIAL,
                    "error": include_denial_text(&run.config, &f),
                }));
            }
            FrontierStatus::PolicyBlocked => policy.push(json!({
                "url": url,
                "reason": f.denial_reason,
            })),
            _ => {}
        }
    }
    Ok(json_response(
        StatusCode::OK,
        &json!({ "errors": errors, "robotsBlocked": robots, "policyBlocked": policy }),
    ))
}

/// Is `f` the crawl's entry URL, fetched for discovery only and recorded as `policy_blocked` by
/// the include filter (the worker's `not_included` / `url_not_included` at depth 0)?
fn is_entry_include_denial(f: &FrontierEntry) -> bool {
    f.depth == 0
        && f.discovered_from.is_none()
        && matches!(
            f.denial_reason.as_deref(),
            Some("not_included" | "url_not_included")
        )
}

/// The `error` of a [`CRAWL_DENIAL`] entry: which URL (its path, or the whole URL under
/// `regexOnFullURL`) matched none of the patterns the request gave.
fn include_denial_text(config: &CreateCrawl, f: &FrontierEntry) -> String {
    let (subject, patterns) = if f.denial_reason.as_deref() == Some("url_not_included") {
        (format!("This URL (\"{}\")", f.url.url), &config.scope.url_include)
    } else {
        (
            format!("This URL's path (\"{}\")", f.url.url.path()),
            &config.scope.include_paths,
        )
    };
    let list = serde_json::to_string(patterns).unwrap_or_default();
    format!(
        "{subject} does not match any of the regex patterns you provided in the includePaths parameter: {list}. When includePaths is specified, only URLs matching at least one pattern are crawled. If this URL should be crawled, add a matching pattern to includePaths or remove the includePaths restriction."
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::scrape::ScrapeJob;
    use crawlx_core::scrape::ScrapeOptions;

    #[test]
    fn shadow_rewrite_clamps_halves_and_adds_raw_html() {
        let mut c = CreateCrawl::new(url::Url::parse("https://a.example.test/").unwrap());
        c.limits.urls = 5_000;
        c.politeness.max_in_flight_per_origin = 4;
        c.output.webhook = Some(crawlx_core::config::Webhook {
            url: url::Url::parse("https://h.example.test/").unwrap(),
            events: vec!["completed".to_owned()],
        });
        let mut job = ScrapeJob::new(JobKind::Crawl, ScrapeOptions::default());
        job.webhook_headers.insert("x-secret".to_owned(), "s".to_owned());
        c.scrape = Some(job);
        shadow_rewrite(&mut c);
        assert_eq!(c.limits.urls, 200);
        assert_eq!(c.politeness.max_in_flight_per_origin, 2);
        assert!(c.output.webhook.is_none());
        assert!(c.output.formats.contains(&OutputFormat::RawHtml));
        let job = c.scrape.unwrap();
        assert!(job.options.wants("rawHtml") && job.webhook_headers.is_empty());
        assert_eq!(c.retention.days, 1);
    }

    #[test]
    fn sampling_is_deterministic() {
        let t = TenantId::new();
        assert_eq!(shadow_sampled(t, "k", 50), shadow_sampled(t, "k", 50));
        assert!(!shadow_sampled(t, "k", 0));
        assert!(shadow_sampled(t, "k", 100));
    }

    #[test]
    fn facade_statuses_map_one_to_one() {
        assert_eq!(facade_status(RunStatus::Queued), "scraping");
        assert_eq!(facade_status(RunStatus::Paused), "scraping");
        assert_eq!(facade_status(RunStatus::Completed), "completed");
        assert_eq!(facade_status(RunStatus::Failed), "failed");
        assert_eq!(facade_status(RunStatus::Cancelled), "cancelled");
    }

    #[test]
    fn concurrency_limit_rewrites_only_the_quota_error() {
        let e = concurrency_limit(HttpError::quota_exceeded(10));
        assert!(
            e.message.starts_with("Concurrency limit reached"),
            "{}",
            e.message
        );
        assert_eq!(e.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(concurrency_limit(HttpError::internal()).message, "internal error");
    }

    #[test]
    fn skip_links_replace_cursor_and_skip() {
        let params = Params(
            [("limit", "2"), ("skip", "2"), ("cursor", "x")]
                .into_iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect(),
        );
        assert_eq!(
            skip_link("/p", &params, 4),
            Value::String("/p?limit=2&skip=4".to_owned())
        );
    }
}
