//! `/v1/agent-plans`: plan-first research agent.
//!
//! Propose (model-assisted or deterministic, no fetch), preview, operator approval with a
//! single-use digest-bound token, then execution as an ordinary agent run confined to the
//! plan's tools and URL set. Page content can fill data inside approved steps; a call outside
//! the plan is refused and recorded as a deviation on the job result and the plan record.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::agent::{self, PlanBinding};
use crate::intel::agent_plan::{self, PlanRequest};
use crate::intel::govern::{self, ModelCall};
use crate::intel::proposals::{self, Kind, Status};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, ts, JsonBody};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_model::policy::{ModelInputEnvelopeV1, OperatorTask, Purpose, RetentionClass};
use crawlx_model::provenance::Instruction;
use serde_json::{json, Value};

const INSTRUCTION: Instruction = Instruction::from_static(
    "Plan a bounded web research run. Propose steps that use only the tools map, scrape and extract, and \
     only URLs under the allowed starting URLs. Do not propose any other tool, host or action.",
);

fn when(ms: i64) -> String {
    ts(crawlx_core::Timestamp::from_timestamp_millis(ms).unwrap_or_default())
}

async fn model_steps(
    state: &AppState,
    principal: &Principal,
    request: &PlanRequest,
) -> Result<(agent_plan::ValidatedPlan, Value), crawlx_model::policy::GovernError> {
    let task = OperatorTask::new(&agent_plan::task_text(request))?;
    let envelope =
        ModelInputEnvelopeV1::new(INSTRUCTION, agent_plan::PROMPT_VERSION, Some(task), Vec::new())?;
    let schema = agent_plan::plan_schema();
    let scope = govern::hourly_scope(state, "plan", principal);
    let call = ModelCall {
        scope: &scope,
        run: None,
        purpose: Purpose::AgentPlan,
        retention: RetentionClass::Standard,
        schema: Some(&schema),
        schema_version: agent_plan::SCHEMA_VERSION,
    };
    let output = govern::call(state, principal, &call, &envelope).await?;
    let plan = agent_plan::validate_steps(request, &output.value);
    let record = serde_json::to_value(&output.record).unwrap_or(Value::Null);
    Ok((plan, record))
}

/// `POST /v1/agent-plans`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `422` for an invalid request. Without a usable
/// model the plan is the deterministic one (a `scrape` step per URL) and says so; a configured
/// model that fails is reported in `findings`, not as an error.
pub async fn propose(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let request = agent_plan::parse_request(&body).map_err(HttpError::validation)?;
    let mut planner = "deterministic";
    let mut model = None;
    let mut plan = agent_plan::deterministic_steps(&request);
    let mut notes: Vec<Value> = Vec::new();
    match govern::availability(&state, Purpose::AgentPlan, RetentionClass::Standard) {
        Ok(_) => match model_steps(&state, &principal, &request).await {
            Ok((proposed, record)) if !proposed.steps.is_empty() => {
                planner = "model";
                model = Some(record);
                plan = proposed;
            }
            Ok((proposed, record)) => {
                model = Some(record);
                notes.extend(proposed.findings);
                notes.push(json!({"step": 0, "code": "fallback_used", "message": "the model proposed no valid step; the deterministic plan is shown"}));
            }
            Err(error) => notes.push(json!({"step": 0, "code": "model_unavailable", "message": format!("{} ({})", error, error.code())})),
        },
        Err(error) => notes.push(json!({"step": 0, "code": "model_unavailable", "message": format!("{} ({})", error, error.code())})),
    }
    plan.findings.splice(0..0, notes);
    let stored = agent_plan::plan_body(&request, &plan, planner, model);
    let record = proposals::create(&state, &principal, Kind::Plan, stored.clone()).await?;
    let mut reply = proposals::view(&state, &record);
    if let (Some(out), Some(extra)) = (reply.as_object_mut(), stored.as_object()) {
        out.insert("planId".to_owned(), json!(record.id));
        out.insert("expiresAt".to_owned(), json!(when(record.expires_at_ms)));
        out.extend(extra.clone());
        out.insert("fetched".to_owned(), json!(false));
    }
    Ok(json_response(StatusCode::CREATED, &reply))
}

/// `GET /v1/agent-plans/{planId}`.
///
/// # Errors
/// `403 scope_missing`, `404`.
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let record = proposals::load(&state, principal.tenant, Kind::Plan, &id).await?;
    let mut reply = proposals::view(&state, &record);
    if let (Some(out), Some(body)) = (reply.as_object_mut(), record.body.as_object()) {
        out.insert("planId".to_owned(), json!(record.id));
        out.extend(body.clone());
    }
    Ok(json_response(StatusCode::OK, &reply))
}

/// `POST /v1/agent-plans/{planId}/approve`.
///
/// # Errors
/// `403 scope_missing` without `approvals:decide`, `403 self_approval_refused`, `404`, `409`,
/// `410`.
pub async fn approve(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::ApprovalsDecide)?;
    let record = proposals::load(&state, principal.tenant, Kind::Plan, &id).await?;
    if record
        .body
        .get("steps")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        return Err(HttpError::invalid_state(
            "a plan without steps cannot be approved",
        ));
    }
    let (record, token) = proposals::approve(&state, &principal, Kind::Plan, record).await?;
    audit(&state, &principal, "agent_plan.approved", &record).await;
    let expires = record.approval.as_ref().map_or(0, |a| a.expires_at_ms);
    let reply = json!({
        "planId": record.id,
        "digest": record.digest,
        "approvalToken": token,
        "expiresAt": when(expires),
        "note": "the token is shown once, is bound to this digest and is spent by the first execute",
    });
    Ok(json_response(StatusCode::OK, &reply))
}

async fn audit(state: &AppState, principal: &Principal, event: &str, record: &proposals::Record) {
    let subject = json!({"planId": record.id, "digest": record.digest});
    if let Err(error) = state
        .repos
        .api
        .audit_append(principal.tenant, None, &principal.actor(), event, subject)
        .await
    {
        tracing::warn!(%error, "plan audit row could not be written");
    }
}

/// `POST /v1/agent-plans/{planId}/cancel`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `404`, `409` once the plan was executed.
pub async fn cancel(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let mut record = proposals::load(&state, principal.tenant, Kind::Plan, &id).await?;
    if record.status == Status::Consumed {
        return Err(HttpError::invalid_state("the plan was already executed"));
    }
    record.status = Status::Cancelled;
    proposals::update(&state, principal.tenant, Kind::Plan, &record).await?;
    audit(&state, &principal, "agent_plan.cancelled", &record).await;
    Ok(json_response(StatusCode::OK, &proposals::view(&state, &record)))
}

/// `POST /v1/agent-plans/{planId}/execute`: body `{approvalToken}`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `403 approval_token_invalid`, `404`, `409` when
/// not approved, `410` when expired, and the admission errors of the agent job.
pub async fn execute(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let token = body
        .as_object()
        .filter(|m| m.keys().all(|k| k == "approvalToken"))
        .and_then(|m| m.get("approvalToken"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            HttpError::validation(vec![Detail::new(
                "/approvalToken",
                "required",
                "the body must be {\"approvalToken\": \"...\"}",
            )])
        })?;
    // the run's own model calls are outside the governor: executing needs the operator to have
    // approved external processing for plans
    govern::availability(&state, Purpose::AgentPlan, RetentionClass::Standard)
        .map_err(|e| govern::http_error(&e))?;
    let record = proposals::load(&state, principal.tenant, Kind::Plan, &id).await?;
    let tools: std::collections::BTreeSet<String> = record
        .body
        .get("tools")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    let record = proposals::consume(&state, &principal, Kind::Plan, record, token).await?;
    let mut agent_body = json!({
        "urls": record.body.get("urls").cloned().unwrap_or(Value::Null),
        "prompt": record.body.get("goal").cloned().unwrap_or(Value::Null),
        "strictConstrainToURLs": true,
        "effort": record.body.get("effort").cloned().unwrap_or(Value::Null),
        "maxCredits": record.body.get("maxCredits").cloned().unwrap_or(Value::Null),
    });
    if let (Some(map), Some(schema)) = (
        agent_body.as_object_mut(),
        record.body.get("schema").filter(|s| !s.is_null()),
    ) {
        map.insert("schema".to_owned(), schema.clone());
    }
    let binding = PlanBinding {
        plan_id: record.id,
        digest: record.digest.clone(),
        tools,
    };
    match agent::start_bound(&state, principal.tenant, &agent_body, Some(binding)).await {
        Ok(started) => {
            let mut done = record.clone();
            done.execution = Some(json!({"jobId": started.id, "status": "processing"}));
            proposals::update(&state, principal.tenant, Kind::Plan, &done).await?;
            audit(&state, &principal, "agent_plan.executed", &done).await;
            let reply = json!({
                "success": true,
                "planId": record.id,
                "planDigest": record.digest,
                "id": started.id,
                "statusUrl": format!("/compat/v2/agent/{}", started.id),
            });
            Ok(json_response(StatusCode::ACCEPTED, &reply))
        }
        Err(error) => {
            // nothing started: the approval stays spendable until it expires
            let mut restored = record;
            restored.status = Status::Approved;
            proposals::update(&state, principal.tenant, Kind::Plan, &restored).await?;
            Err(error)
        }
    }
}
