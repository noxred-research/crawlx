//! compat v2 `agent` endpoints of the compat facade: `POST /agent` starts a run
//! ([`crate::intel::agent`]), `GET /agent` lists the tenant's runs, `GET|DELETE /agent/{jobId}`
//! report and cancel one, `GET /agent/{jobId}/trace` pages its execution events and
//! `GET /agent/{jobId}/snapshots/{snapshotId}` returns a working artifact.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::intel::agent::{self, stored_webhook};
use crate::intel::agent_spec::{zdr_expired, ThreadState};
use crate::intel::agent_view::{list_entry, snapshot_body, status_body, trace_events};
use crate::intel::usage::{self, Cost};
use crate::intel::webhook::JobEvent;
use crate::openapi::Operation;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::{Extension, Router};
use chrono::{DateTime, Utc};
use crawlx_core::TenantId;
use crawlx_storage::{JobKind, JobPatch, JobRecord, JobStatus};
use serde_json::{json, Value};
use uuid::Uuid;

/// Agents per page of `GET /agent` unless `limit` says otherwise (the compat API pages are fixed at 20).
pub const LIST_PAGE: u32 = 20;
/// Most agents one `GET /agent` page returns.
pub const LIST_MAX: u32 = 100;
/// Events per page of `GET /agent/{jobId}/trace` unless `limit` says otherwise.
pub const TRACE_PAGE: u32 = 200;
/// Most events one trace page returns.
pub const TRACE_MAX: u32 = 1000;

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "post",
        "/compat/v2/agent",
        "compatStartAgent",
        "compat v2 agent: start a run (prompt, urls, schema, maxCredits, effort, webhook, threadId, exchange, zeroDataRetention)",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/agent",
        "compatListAgents",
        "compat v2 agent: list the tenant's runs, newest first (before, limit, skip)",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/compat/v2/agent/{jobId}",
        "compatGetAgent",
        "compat v2 agent: run status, data, stopReason, creditsUsed, tokensUsed and expiresAt",
        "crawls:read",
        "200",
    ),
    (
        "delete",
        "/compat/v2/agent/{jobId}",
        "compatCancelAgent",
        "compat v2 agent: cancel a running run",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/agent/{jobId}/trace",
        "compatGetAgentTrace",
        "compat v2 agent: execution trace events (after, limit)",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/compat/v2/agent/{jobId}/snapshots/{snapshotId}",
        "compatGetAgentSnapshot",
        "compat v2 agent: a snapshot of fetched or produced content",
        "crawls:read",
        "200",
    ),
];

/// Routes of this module, mounted under `/compat/v2` behind authentication.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/v2/agent", get(list).post(start))
        .route("/compat/v2/agent/{jobId}", get(status).delete(cancel))
        .route("/compat/v2/agent/{jobId}/trace", get(trace))
        .route("/compat/v2/agent/{jobId}/snapshots/{snapshotId}", get(snapshot))
}

fn origin(headers: &HeaderMap) -> String {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    host.map_or_else(String::new, |h| format!("{proto}://{h}"))
}

fn parse_job(text: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(text).map_err(|_| {
        HttpError::compat(
            StatusCode::BAD_REQUEST,
            "invalid_job_id",
            "Invalid job ID format. Job ID must be a valid UUID.",
        )
    })
}

fn not_found() -> HttpError {
    HttpError::not_found("Agent job")
}

async fn load(state: &AppState, tenant: TenantId, id: &str) -> ApiResult<JobRecord> {
    let id = parse_job(id)?;
    state
        .repos
        .intel
        .job_get(tenant, id)
        .await?
        .filter(|j| j.kind == JobKind::Agent)
        .ok_or_else(not_found)
}

fn is_zdr(job: &JobRecord) -> bool {
    job.request.get("zeroDataRetention").and_then(Value::as_bool) == Some(true)
}

/// `POST /compat/v2/agent`: `{success, id, threadId, threadTurn, warnings?}` once the run
/// is admitted; it continues in the background.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `503 llm_not_configured` without an LLM, `422` for an
/// invalid body, `400 zdr_not_enabled` / `zdr_threads_unsupported` for zero-data-retention
/// requests the tenant cannot make, `404` for an unknown `threadId`, `409` while the thread's
/// previous turn runs or when `exchange.approve|decline` names no pending approval.
pub async fn start(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let started = agent::start(&state, principal.tenant, &body).await?;
    let mut out = json!({ "success": true, "id": started.id });
    if let Some(obj) = out.as_object_mut() {
        if let Some(t) = started.thread_id {
            obj.insert("threadId".to_owned(), json!(t));
            obj.insert("threadTurn".to_owned(), json!(started.thread_turn));
        }
        if !started.warnings.is_empty() {
            obj.insert("warnings".to_owned(), json!(started.warnings));
        }
    }
    Ok(json_response(StatusCode::OK, &out))
}

fn cursor_from(params: &Params) -> ApiResult<Option<(DateTime<Utc>, Uuid)>> {
    let Some(raw) = params.get("before") else {
        return Ok(None);
    };
    let bad = || HttpError::malformed("Invalid before timestamp.");
    let ms: i64 = raw.parse().map_err(|_| bad())?;
    if ms < 0 {
        return Err(bad());
    }
    let at = DateTime::<Utc>::from_timestamp_millis(ms).ok_or_else(bad)?;
    let id = match params.get("beforeId") {
        Some(s) => Uuid::parse_str(s).map_err(|_| bad())?,
        None => Uuid::nil(),
    };
    Ok(Some((at, id)))
}

fn number_param(params: &Params, key: &str, default: u32, min: u32, max: u32) -> ApiResult<u32> {
    match params.get(key) {
        None => Ok(default),
        Some(v) => match v.parse::<u32>() {
            Ok(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(HttpError::malformed(format!(
                "{key} must be an integer from {min} to {max}"
            ))),
        },
    }
}

/// `GET /compat/v2/agent`: the tenant's runs, newest first. `before` (unix milliseconds,
/// the cursor of `next`), `limit` (default 20, at most 100) and `skip` page the list.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `400` for malformed `before`, `limit` or `skip`.
pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let cursor = cursor_from(&params)?;
    let limit = number_param(&params, "limit", LIST_PAGE, 1, LIST_MAX)?;
    let skip = number_param(&params, "skip", 0, 0, 10_000)?;
    let want = skip.saturating_add(limit).saturating_add(1);
    let mut rows = state
        .repos
        .intel
        .job_list(principal.tenant, Some(JobKind::Agent), want, cursor)
        .await?;
    let skip = usize::try_from(skip).unwrap_or(0);
    let limit = usize::try_from(limit).unwrap_or(1);
    rows.drain(..skip.min(rows.len()));
    let more = rows.len() > limit;
    rows.truncate(limit);
    let mut out = json!({ "success": true, "agents": rows.iter().map(list_entry).collect::<Vec<_>>() });
    if let (true, Some(last), Some(obj)) = (more, rows.last(), out.as_object_mut()) {
        let mut q = url::form_urlencoded::Serializer::new(String::new());
        q.append_pair("before", &last.created_at.timestamp_millis().to_string());
        q.append_pair("beforeId", &last.id.to_string());
        if params.get("limit").is_some() {
            q.append_pair("limit", &limit.to_string());
        }
        obj.insert(
            "next".to_owned(),
            json!(format!("{}/compat/v2/agent?{}", origin(&headers), q.finish())),
        );
    }
    Ok(json_response(StatusCode::OK, &out))
}

/// `GET /compat/v2/agent/{jobId}`.
///
/// `status` is `processing`, `completed`, `failed` or `cancelled`. A run that stopped at its
/// credit limit is `failed` with `stopReason: "credit_limit_reached"` and the best-effort
/// `partial`; `data` is only set on completed runs.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `400` for a malformed id, `404` for an unknown run
/// or one of another tenant, `410 zdr_expired` for a zero-data-retention run whose result was
/// deleted after 24 hours.
pub async fn status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let tenant = principal.tenant;
    let job = load(&state, tenant, &id).await?;
    let now = state.clock.now();
    let envelope = if is_zdr(&job) {
        match job.status {
            JobStatus::Completed | JobStatus::Failed => Some(
                state
                    .agent_vault
                    .get(tenant, job.id, now)
                    .ok_or_else(zdr_expired)?,
            ),
            JobStatus::Processing | JobStatus::Cancelled => None,
        }
    } else {
        job.result.clone()
    };
    let resolution = match (&envelope, job.thread_id) {
        (Some(env), Some(thread)) => match env
            .get("pendingApproval")
            .and_then(|p| p.get("id"))
            .and_then(Value::as_str)
        {
            Some(approval) => thread_resolution(&state, tenant, thread, approval).await,
            None => None,
        },
        _ => None,
    };
    let body = status_body(&job, envelope.as_ref(), resolution.as_ref(), job.expires_at);
    Ok(json_response(StatusCode::OK, &body))
}

async fn thread_resolution(
    state: &AppState,
    tenant: TenantId,
    thread: Uuid,
    approval: &str,
) -> Option<Value> {
    let rec = state
        .repos
        .intel
        .thread_get(tenant, thread)
        .await
        .ok()
        .flatten()?;
    let st: ThreadState = serde_json::from_value(rec.state).ok()?;
    st.resolutions.get(approval).cloned()
}

/// `DELETE /compat/v2/agent/{jobId}`: cancel a running run. The run stops at its next
/// await point, the job becomes `cancelled` and `agent.cancelled` is delivered.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `400` for a malformed id, `404` for an unknown run
/// or one of another tenant, `409` for a run that already finished or was already cancelled.
pub async fn cancel(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let tenant = principal.tenant;
    let job = load(&state, tenant, &id).await?;
    match job.status {
        JobStatus::Cancelled => {
            return Err(HttpError::compat(
                StatusCode::CONFLICT,
                "agent_cancelled",
                "Agent is already cancelled",
            ));
        }
        JobStatus::Completed | JobStatus::Failed => {
            return Err(HttpError::compat(
                StatusCode::CONFLICT,
                "agent_finished",
                "Agent already finished",
            ));
        }
        JobStatus::Processing => {}
    }
    let now = state.clock.now();
    let mut patch = JobPatch::at(now);
    patch.status = Some(JobStatus::Cancelled);
    patch.finished_at = Some(now);
    let row = state
        .repos
        .intel
        .job_update(tenant, job.id, &patch)
        .await?
        .ok_or_else(not_found)?;
    if row.status != JobStatus::Cancelled || row.finished_at != Some(now) {
        // the run finished (or another request cancelled it) between the read and the write
        return Err(HttpError::compat(
            StatusCode::CONFLICT,
            "agent_finished",
            "Agent already finished",
        ));
    }
    if !state.jobs.cancel(job.id) {
        cancel_orphan(&state, tenant, &row);
    }
    Ok(json_response(StatusCode::OK, &json!({ "success": true })))
}

/// A run no task of this process owns (the server restarted while it ran) still ends as
/// cancelled: write its ledger row and deliver `agent.cancelled`.
fn cancel_orphan(state: &AppState, tenant: TenantId, row: &JobRecord) {
    let st = state.clone();
    let (id, credits, tokens) = (row.id, row.credits_used, row.tokens_used);
    let hook = stored_webhook(&row.request);
    state.jobs.spawn(id, move |cancel| async move {
        usage::record(&st, tenant, "agent", Some(id), "cancelled", Cost::credits(0)).await;
        if let Some(h) = hook {
            let ev = JobEvent {
                kind: "agent",
                event: "cancelled",
                id,
                data: json!([{ "creditsUsed": credits, "tokensUsed": tokens }]),
                error: Some("The agent job was cancelled."),
            };
            st.job_webhooks.deliver(&h, &ev, &cancel).await;
        }
    });
}

/// `GET /compat/v2/agent/{jobId}/trace`: canonical execution events. `after` (a stored
/// sequence number, the `seq` of an event) and `limit` (default 200, at most 1000) page the
/// stored steps; `nextAfter` is set when more remain.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `400` for a malformed id or paging parameter, `404`
/// for an unknown run or one of another tenant.
pub async fn trace(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let job = load(&state, principal.tenant, &id).await?;
    let after = match params.get("after") {
        None => 0,
        Some(v) => v
            .parse::<u64>()
            .map_err(|_| HttpError::malformed("after must be a non-negative integer"))?,
    };
    let limit = number_param(&params, "limit", TRACE_PAGE, 1, TRACE_MAX)?;
    let mut stored = state
        .repos
        .intel
        .trace_list(job.id, after, limit.saturating_add(1))
        .await?;
    let more = stored.len() > usize::try_from(limit).unwrap_or(0);
    stored.truncate(usize::try_from(limit).unwrap_or(0));
    let next_after = if more { stored.last().map(|e| e.seq) } else { None };
    let events = trace_events(&job, &stored, after == 0, !more);
    let mut out = json!({
        "success": true,
        "id": job.id,
        "events": events,
        "creditsUsed": job.credits_used,
    });
    if let (Some(n), Some(obj)) = (next_after, out.as_object_mut()) {
        obj.insert("nextAfter".to_owned(), json!(n));
    }
    if params.get("liveView") == Some("true") {
        if let Some(obj) = out.as_object_mut() {
            obj.insert("activeBrowserSessions".to_owned(), json!([]));
        }
    }
    Ok(json_response(StatusCode::OK, &out))
}

/// `GET /compat/v2/agent/{jobId}/snapshots/{snapshotId}`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `400` for a malformed job or snapshot id, `404` for
/// an unknown run, one of another tenant, or an unknown snapshot.
pub async fn snapshot(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, snapshot)): Path<(String, String)>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let job = load(&state, principal.tenant, &id).await?;
    let sid = Uuid::parse_str(&snapshot).map_err(|_| {
        HttpError::compat(
            StatusCode::BAD_REQUEST,
            "invalid_snapshot_id",
            "Invalid snapshot ID",
        )
    })?;
    let snap = state
        .repos
        .intel
        .snapshot_get(job.id, &sid.to_string())
        .await?
        .ok_or_else(|| HttpError::compat(StatusCode::NOT_FOUND, "not_found", "Snapshot not found"))?;
    Ok(json_response(StatusCode::OK, &snapshot_body(job.id, &snap)))
}
