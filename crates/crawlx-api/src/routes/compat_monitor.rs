//! compat v2 `monitor` endpoints of the compat facade.
//!
//! | endpoint | scope |
//! |---|---|
//! | `POST /monitor` | `crawls:write` |
//! | `GET /monitor` (`limit`, `offset`, `status`) | `crawls:read` |
//! | `GET /monitor/{monitorId}` | `crawls:read` |
//! | `PATCH /monitor/{monitorId}` | `crawls:write` |
//! | `DELETE /monitor/{monitorId}` | `crawls:write` |
//! | `POST /monitor/{monitorId}/run` | `crawls:write` |
//! | `GET /monitor/{monitorId}/checks` (`limit`, `offset`, `status`) | `crawls:read` |
//! | `GET /monitor/{monitorId}/checks/{checkId}` (`limit`, `skip`, `status`) | `crawls:read` |
//!
//! Every row is scoped to the key's tenant: a monitor of another tenant answers `404`. Checks past
//! their `expiresAt` (`retentionDays` after they started) are invisible even before the retention
//! sweep deletes them.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::common::{self, parse_id};
use crate::intel::monitor::engine;
use crate::intel::monitor::model::{self, MonitorPatch, NewMonitor, Target};
use crate::intel::monitor::view::{self, MonitorExtras};
use crate::openapi::Operation;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use crawlx_core::TenantId;
use crawlx_storage::{CheckRecord, CheckState, MonitorRecord, MonitorStatus};
use serde_json::{json, Value};
use uuid::Uuid;

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "post",
        "/compat/v2/monitor",
        "createMonitor",
        "Create a scheduled monitor",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/monitor",
        "listMonitors",
        "List monitors (limit, offset, status)",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/compat/v2/monitor/{monitorId}",
        "getMonitor",
        "Get a monitor",
        "crawls:read",
        "200",
    ),
    (
        "patch",
        "/compat/v2/monitor/{monitorId}",
        "updateMonitor",
        "Update, pause or resume a monitor",
        "crawls:write",
        "200",
    ),
    (
        "delete",
        "/compat/v2/monitor/{monitorId}",
        "deleteMonitor",
        "Delete a monitor with its checks and baselines",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/compat/v2/monitor/{monitorId}/run",
        "runMonitor",
        "Run a monitor check now",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/monitor/{monitorId}/checks",
        "listMonitorChecks",
        "List monitor checks (limit, offset, status)",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/compat/v2/monitor/{monitorId}/checks/{checkId}",
        "getMonitorCheck",
        "Get a monitor check with its pages (limit, skip, status)",
        "crawls:read",
        "200",
    ),
];

/// Routes of this module, mounted under `/compat/v2` behind authentication.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/v2/monitor", post(create).get(list))
        .route(
            "/compat/v2/monitor/{monitorId}",
            get(get_one).patch(update).delete(remove),
        )
        .route("/compat/v2/monitor/{monitorId}/run", post(run))
        .route("/compat/v2/monitor/{monitorId}/checks", get(checks))
        .route(
            "/compat/v2/monitor/{monitorId}/checks/{checkId}",
            get(check_detail),
        )
}

/// Default and largest `limit` of the list endpoints.
const DEFAULT_LIMIT: usize = 25;
const MAX_LIMIT: usize = 100;

fn invalid_param(name: &str, message: &str) -> HttpError {
    HttpError::validation(vec![Detail::new(format!("/{name}"), "invalid", message)])
}

/// A non-negative integer query parameter.
fn int_param(params: &Params, name: &str, default: usize, min: usize, max: usize) -> ApiResult<usize> {
    match params.get(name) {
        None => Ok(default),
        Some(text) => match text.parse::<usize>() {
            Ok(n) if (min..=max).contains(&n) => Ok(n),
            _ => Err(invalid_param(
                name,
                &format!("{name} must be an integer between {min} and {max}"),
            )),
        },
    }
}

fn enum_param<'a>(params: &'a Params, name: &str, allowed: &[&str]) -> ApiResult<Option<&'a str>> {
    match params.get(name) {
        None => Ok(None),
        Some(v) if allowed.contains(&v) => Ok(Some(v)),
        Some(_) => Err(invalid_param(
            name,
            &format!("{name} takes one of {}", allowed.join(", ")),
        )),
    }
}

fn base_url(headers: &HeaderMap) -> String {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    host.map_or_else(String::new, |h| format!("{proto}://{h}"))
}

async fn load(state: &AppState, tenant: TenantId, id: &str) -> ApiResult<MonitorRecord> {
    let id = parse_id(id, "monitor")?;
    state
        .repos
        .intel
        .monitor_get(tenant, id)
        .await?
        .ok_or_else(|| HttpError::not_found("monitor"))
}

/// The checks of `monitor` that have not expired, newest first, optionally only those whose API
/// status is `status`, `limit` rows after `offset`.
async fn visible_checks(
    state: &AppState,
    monitor: &MonitorRecord,
    status: Option<&str>,
    limit: usize,
    offset: usize,
) -> ApiResult<Vec<CheckRecord>> {
    const BATCH: u32 = 100;
    let now = state.clock.now();
    let mut out: Vec<CheckRecord> = Vec::new();
    let mut skipped = 0_usize;
    let mut raw_offset = 0_u32;
    loop {
        let batch = state
            .repos
            .intel
            .check_list(monitor.tenant, monitor.id, None, BATCH, raw_offset)
            .await?;
        let fetched = batch.len();
        for c in batch {
            if c.expires_at <= now || status.is_some_and(|s| view::check_status(&c) != s) {
                continue;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            out.push(c);
            if out.len() >= limit {
                return Ok(out);
            }
        }
        if fetched < usize::try_from(BATCH).unwrap_or(100) {
            return Ok(out);
        }
        raw_offset = raw_offset.saturating_add(BATCH);
    }
}

async fn extras(state: &AppState, monitor: &MonitorRecord) -> ApiResult<MonitorExtras> {
    let recent = visible_checks(state, monitor, None, 10, 0).await?;
    let mut out = MonitorExtras::default();
    for c in &recent {
        if c.state == CheckState::Running {
            out.current_check.get_or_insert(c.id);
        } else if out.last_summary.is_none() && view::check_status(c) != "skipped_overlap" {
            out.last_summary = Some(c.summary.clone());
        }
    }
    Ok(out)
}

async fn monitor_body(state: &AppState, monitor: &MonitorRecord) -> ApiResult<Value> {
    let extras = extras(state, monitor).await?;
    Ok(view::monitor_json(monitor, &extras))
}

fn ok(data: &Value) -> Response {
    json_response(StatusCode::OK, &json!({ "success": true, "data": data }))
}

/// The `notification` column: the validated notification object plus crawlx's `judgeEnabled`
/// when the caller chose one (otherwise judging follows whether a goal exists).
fn stored_notification(notification: &Value, judge_explicit: Option<bool>) -> Value {
    let mut out = notification.clone();
    if let Some(flag) = judge_explicit {
        out["judgeEnabled"] = json!(flag);
    }
    out
}

/// `POST /compat/v2/monitor`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`; `422 validation_failed` listing every violation
/// (targets 1-50, schedule minimum 5 minutes, `retentionDays` 1-365, timezone, webhook, goal rules).
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let new = NewMonitor::parse(&body)?;
    let now = state.clock.now();
    let record = MonitorRecord {
        id: Uuid::now_v7(),
        tenant: principal.tenant,
        name: Some(new.name),
        status: MonitorStatus::Active,
        schedule: serde_json::to_value(new.schedule.spec()).unwrap_or(Value::Null),
        cron: new.schedule.cron().to_owned(),
        timezone: new.schedule.timezone().to_owned(),
        goal: new.goal,
        targets: Value::Array(new.targets.iter().map(|t| t.value.clone()).collect()),
        retention_days: new.retention_days,
        webhook: new.webhook.as_ref().map(model::webhook_value),
        notification: stored_notification(&new.notification, new.judge_explicit),
        next_run_at: new.schedule.next_after(now),
        last_run_at: None,
        last_check_id: None,
        claimed_until: None,
        created_at: now,
        updated_at: now,
    };
    state.repos.intel.monitor_insert(&record).await?;
    Ok(ok(&view::monitor_json(&record, &MonitorExtras::default())))
}

/// `GET /compat/v2/monitor`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`; `422 validation_failed` for a bad `limit`,
/// `offset` or `status` (`active`, `paused`).
pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let limit = int_param(&params, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)?;
    let offset = int_param(
        &params,
        "offset",
        0,
        0,
        usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    )?;
    let status = enum_param(&params, "status", &["active", "paused"])?.and_then(MonitorStatus::parse);
    let repo = &state.repos.intel;
    let rows: Vec<MonitorRecord> = match status {
        None => {
            let limit = u32::try_from(limit).unwrap_or(u32::MAX);
            let offset = u32::try_from(offset).unwrap_or(u32::MAX);
            repo.monitor_list(principal.tenant, limit, offset).await?
        }
        Some(wanted) => {
            const BATCH: u32 = 100;
            let mut out = Vec::new();
            let mut skipped = 0_usize;
            let mut raw = 0_u32;
            'scan: loop {
                let batch = repo.monitor_list(principal.tenant, BATCH, raw).await?;
                let fetched = batch.len();
                for m in batch.into_iter().filter(|m| m.status == wanted) {
                    if skipped < offset {
                        skipped += 1;
                    } else {
                        out.push(m);
                        if out.len() >= limit {
                            break 'scan;
                        }
                    }
                }
                if fetched < usize::try_from(BATCH).unwrap_or(100) {
                    break;
                }
                raw = raw.saturating_add(BATCH);
            }
            out
        }
    };
    let mut data = Vec::with_capacity(rows.len());
    for m in &rows {
        data.push(monitor_body(&state, m).await?);
    }
    Ok(ok(&Value::Array(data)))
}

/// `GET /compat/v2/monitor/{monitorId}`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`; `404 not_found` for an unknown monitor or one of
/// another tenant.
pub async fn get_one(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let monitor = load(&state, principal.tenant, &id).await?;
    Ok(ok(&monitor_body(&state, &monitor).await?))
}

/// `PATCH /compat/v2/monitor/{monitorId}`: update any member, pause (`status: paused`
/// clears `nextRunAt`) or resume (`status: active` schedules the next occurrence).
///
/// # Errors
/// `403 scope_missing` without `crawls:write`; `404 not_found`; `422 validation_failed` for an
/// invalid member, an empty patch, or a patch that leaves a search target without a goal.
pub async fn update(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let patch = MonitorPatch::parse(&body)?;
    let mut m = load(&state, principal.tenant, &id).await?;
    let now = state.clock.now();

    let goal_after = match &patch.goal {
        Some(g) => g.clone(),
        None => m.goal.clone(),
    };
    // an explicit `judgeEnabled` sticks; a new goal without one turns judging on again
    let judge_explicit = match (patch.judge_enabled, &patch.goal) {
        (Some(flag), _) => Some(flag),
        (None, Some(Some(_))) => None,
        (None, _) => m.notification.get("judgeEnabled").and_then(Value::as_bool),
    };
    let targets_after: Vec<Target> = match &patch.targets {
        Some(t) => t.clone(),
        None => m
            .targets
            .as_array()
            .map(|items| items.iter().filter_map(|t| Target::from_stored(t).ok()).collect())
            .unwrap_or_default(),
    };
    MonitorPatch::check_merged(&targets_after, goal_after.as_deref(), judge_explicit)?;

    let before_status = m.status;
    let mut reschedule = false;
    if let Some(name) = patch.name {
        m.name = Some(name);
    }
    if let Some(schedule) = &patch.schedule {
        m.schedule = serde_json::to_value(schedule.spec()).unwrap_or(Value::Null);
        m.cron = schedule.cron().to_owned();
        m.timezone = schedule.timezone().to_owned();
        reschedule = true;
    }
    if let Some(targets) = &patch.targets {
        m.targets = Value::Array(targets.iter().map(|t| t.value.clone()).collect());
    }
    if let Some(days) = patch.retention_days {
        m.retention_days = days;
    }
    if let Some(hook) = &patch.webhook {
        m.webhook = hook.as_ref().map(model::webhook_value);
    }
    let notification = patch.notification.clone().unwrap_or_else(|| {
        m.notification
            .get("email")
            .map_or_else(|| json!({}), |e| json!({ "email": e }))
    });
    m.notification = stored_notification(&notification, judge_explicit);
    m.goal = goal_after;
    if let Some(status) = patch.status {
        m.status = status;
        if status == MonitorStatus::Active && before_status == MonitorStatus::Paused {
            reschedule = true;
        }
    }
    m.next_run_at = match m.status {
        MonitorStatus::Paused => None,
        MonitorStatus::Active if reschedule || m.next_run_at.is_none() => {
            crawlx_scheduler::Schedule::from_stored(&m.cron, &m.timezone)
                .ok()
                .and_then(|s| s.next_after(now))
        }
        MonitorStatus::Active => m.next_run_at,
    };
    m.updated_at = now;
    if !state.repos.intel.monitor_update(&m).await? {
        return Err(HttpError::not_found("monitor"));
    }
    let stored = load(&state, principal.tenant, &id).await?;
    Ok(ok(&monitor_body(&state, &stored).await?))
}

/// `DELETE /compat/v2/monitor/{monitorId}`: removes the monitor, its checks, pages and
/// baselines and cancels a check that is running.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`; `404 not_found`.
pub async fn remove(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let monitor = load(&state, principal.tenant, &id).await?;
    engine::cancel_running(&state, &monitor).await;
    if !state
        .repos
        .intel
        .monitor_delete(principal.tenant, monitor.id)
        .await?
    {
        return Err(HttpError::not_found("monitor"));
    }
    Ok(json_response(StatusCode::OK, &json!({ "success": true })))
}

/// `POST /compat/v2/monitor/{monitorId}/run`: starts a check now (also for a paused
/// monitor) and returns its id; the check runs in the background.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`; `404 not_found`; `409 invalid_state` while a check
/// of the monitor is still running; `503 scrape_unavailable` when no scrape service is wired.
pub async fn run(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let monitor = load(&state, principal.tenant, &id).await?;
    common::tools(&state)?;
    let check = engine::start_manual(&state, monitor).await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "id": check.id, "data": view::check_json(&check) }),
    ))
}

/// `GET /compat/v2/monitor/{monitorId}/checks`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`; `404 not_found`; `422 validation_failed` for a bad
/// `limit`, `offset` or `status`.
pub async fn checks(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let limit = int_param(&params, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)?;
    let offset = int_param(
        &params,
        "offset",
        0,
        0,
        usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    )?;
    let status = enum_param(
        &params,
        "status",
        &[
            "queued",
            "running",
            "completed",
            "failed",
            "partial",
            "skipped_overlap",
            "skipped_no_credits",
        ],
    )?;
    let monitor = load(&state, principal.tenant, &id).await?;
    let rows = visible_checks(&state, &monitor, status, limit, offset).await?;
    let data: Vec<Value> = rows.iter().map(view::check_json).collect();
    Ok(ok(&Value::Array(data)))
}

/// `GET /compat/v2/monitor/{monitorId}/checks/{checkId}`: the check with its pages,
/// ordered by target and URL, `limit` per response, `next` while more pages remain.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`; `404 not_found` for an unknown or expired check;
/// `422 validation_failed` for a bad `limit`, `skip` or `status`.
pub async fn check_detail(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((monitor_id, check_id)): Path<(String, String)>,
    headers: HeaderMap,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let limit = int_param(&params, "limit", DEFAULT_LIMIT, 1, MAX_LIMIT)?;
    let skip = int_param(
        &params,
        "skip",
        0,
        0,
        usize::try_from(u32::MAX).unwrap_or(usize::MAX),
    )?;
    let status = enum_param(&params, "status", &["same", "new", "changed", "removed", "error"])?;
    let monitor = load(&state, principal.tenant, &monitor_id).await?;
    let check_uuid = parse_id(&check_id, "monitor check")?;
    let check = state
        .repos
        .intel
        .check_get(principal.tenant, monitor.id, check_uuid)
        .await?
        .filter(|c| c.expires_at > state.clock.now())
        .ok_or_else(|| HttpError::not_found("monitor check"))?;
    let fetch = u32::try_from(limit.saturating_add(1)).unwrap_or(u32::MAX);
    let skip_u32 = u32::try_from(skip).unwrap_or(u32::MAX);
    let mut pages = state
        .repos
        .intel
        .check_pages(check.id, status, fetch, skip_u32)
        .await?;
    let more = pages.len() > limit;
    pages.truncate(limit);
    let next = if more {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("skip", &skip.saturating_add(limit).to_string());
        query.append_pair("limit", &limit.to_string());
        if let Some(s) = status {
            query.append_pair("status", s);
        }
        Value::String(format!(
            "{}/compat/v2/monitor/{}/checks/{}?{}",
            base_url(&headers),
            monitor.id,
            check.id,
            query.finish()
        ))
    } else {
        Value::Null
    };
    let mut data = view::check_json(&check);
    data["pages"] = Value::Array(pages.iter().map(view::page_json).collect());
    data["next"] = next.clone();
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "next": next, "data": data }),
    ))
}
