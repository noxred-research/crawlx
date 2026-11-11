//! `GET /v1/crawls/{id}/approvals`, `POST .../approvals/{approval_id}:approve|:deny`.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::idempotency::{idempotent, Reply};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::{ApprovalDecision, ApprovalRecord, DecideOutcome, Scope};
use crate::util::{idempotency_key, json_response, next_link, paginate, ts, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::repo::RunMetadata;
use crawlx_core::ApprovalId;
use serde_json::{json, Value};

/// First present key of `keys` in the stored reviewer summary.
fn s(summary: &Value, keys: &[&str]) -> Value {
    keys.iter()
        .find_map(|k| summary.get(*k))
        .cloned()
        .unwrap_or(Value::Null)
}

/// The approval resource.
pub(crate) fn approval_json(run: &RunMetadata, a: &ApprovalRecord, now: crawlx_core::Timestamp) -> Value {
    let sm = &a.summary;
    json!({
        "id": a.id,
        "actionId": a.action,
        "riskClass": a.risk_class,
        "profile": run.safety_profile,
        "summary": {
            "elementRole": s(sm, &["element_role", "elementRole"]),
            "redactedName": s(sm, &["redacted_name", "redactedName"]),
            "routeTemplate": s(sm, &["route_template", "routeTemplate"]),
            "actionKind": s(sm, &["action_kind", "actionKind"]),
            "resourceContext": s(sm, &["resource_context", "resourceContext"]),
            "valuePartition": s(sm, &["input_class", "value_partition", "valuePartition"]),
        },
        "decision": a.effective(now),
        "consumed": a.consumed_at.is_some(),
        "requestedAt": ts(a.requested_at),
        "expiresAt": ts(a.expires_at),
        "decidedBy": a.decided_by,
        "decidedAt": a.decided_at.map(ts),
        "reason": a.reason,
    })
}

/// `GET /v1/crawls/{id}/approvals`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for a bad `limit`, `cursor` or `decision` filter.
pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let limit = params.limit(&state.settings)?;
    let cursor = params.cursor_key()?;
    let decision = params
        .get("decision")
        .map(|d| {
            ApprovalDecision::parse(d)
                .ok_or_else(|| HttpError::malformed("decision must be pending, approved, denied or expired"))
        })
        .transpose()?;
    let now = state.clock.now();
    let items: Vec<(String, Value)> = state
        .repos
        .api
        .approvals_list(run.id)
        .await?
        .iter()
        .filter(|a| decision.is_none_or(|d| a.effective(now) == d))
        .map(|a| (a.id.to_string(), approval_json(&run, a, now)))
        .collect();
    let total = items.len();
    let (page, next_key) = paginate(items, limit, cursor.as_deref());
    let path = format!("/v1/crawls/{}/approvals", run.id);
    let body =
        json!({ "data": page, "next": next_link(&path, &params, next_key.as_deref()), "total": total });
    Ok(json_response(StatusCode::OK, &body))
}

/// `POST /v1/crawls/{id}/approvals/{approval_id}:approve|:deny`.
///
/// # Errors
/// `403 scope_missing` without `approvals:decide`, `404 not_found` for an unknown run or a run
/// owned by another tenant or approval, `409 approval_not_pending` when the approval was already
/// decided or expired, `422 validation_failed` for an invalid body.
pub async fn decide(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, approval_action)): Path<(String, String)>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::ApprovalsDecide)?;
    let Some((approval, action)) = approval_action.rsplit_once(':') else {
        return Err(HttpError::method_not_allowed());
    };
    let decision = match action {
        "approve" => ApprovalDecision::Approved,
        "deny" => ApprovalDecision::Denied,
        _ => return Err(HttpError::not_found("action")),
    };
    let approval_id: ApprovalId = approval.parse().map_err(|_| HttpError::not_found("approval"))?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let reason = match &body {
        Value::Null => None,
        Value::Object(m) => match m.get("reason") {
            None | Some(Value::Null) => None,
            Some(Value::String(r)) if r.len() <= 2000 => Some(r.clone()),
            Some(_) => {
                return Err(HttpError::validation(vec![Detail::new(
                    "/reason",
                    "out_of_range",
                    "reason must be a string of at most 2000 bytes",
                )]));
            }
        },
        _ => return Err(HttpError::malformed("body must be a JSON object")),
    };
    let key = idempotency_key(&headers, false)?;
    let path = format!("/v1/crawls/{}/approvals/{}", run.id, approval_action);
    idempotent(&state, &principal, key, "POST", &path, &body, || async {
        let now = state.clock.now();
        let outcome = state
            .repos
            .api
            .approval_decide(
                run.id,
                approval_id,
                decision,
                principal.key_id,
                reason.as_deref(),
                now,
            )
            .await?;
        match outcome {
            DecideOutcome::NotFound => Err(HttpError::not_found("approval")),
            DecideOutcome::NotPending(a) => Err(HttpError::approval_not_pending(format!(
                "the approval is {} and cannot become {}",
                if a.consumed_at.is_some() {
                    "consumed".to_owned()
                } else {
                    a.effective(now).as_str().to_owned()
                },
                decision.as_str()
            ))),
            DecideOutcome::Unchanged(a) => {
                Ok(Reply::new(StatusCode::OK, approval_json(&run, &a, now)).for_run(run.id))
            }
            DecideOutcome::Applied(a) => {
                let item = approval_json(&run, &a, now);
                state
                    .repos
                    .api
                    .audit_append(
                        principal.tenant,
                        Some(run.id),
                        &principal.actor(),
                        &format!("approval.{}", decision.as_str()),
                        json!({ "approval_id": a.id, "action_id": a.action }),
                    )
                    .await?;
                state
                    .repos
                    .events
                    .append(run.id, "approval_resolved", item.clone())
                    .await?;
                Ok(Reply::new(StatusCode::OK, item).for_run(run.id))
            }
        }
    })
    .await
}
