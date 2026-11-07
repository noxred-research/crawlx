//! `GET /v1/crawls/{id}/transitions`.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::{Scope, TransitionFilter};
use crate::util::{json_response, next_link, paginate, ts, Params};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::counters::ActionStatus;
use crawlx_core::TrustLane;
use serde_json::{json, Value};

fn parse_id<T: std::str::FromStr>(params: &Params, name: &str) -> Result<Option<T>, HttpError> {
    params
        .get(name)
        .map(|v| {
            v.parse()
                .map_err(|_| HttpError::malformed(format!("{name} must be a UUID")))
        })
        .transpose()
}

/// `GET /v1/crawls/{id}/transitions`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for a bad filter, `limit` or `cursor`.
pub async fn transitions(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let limit = params.limit(&state.settings)?;
    let cursor = params.cursor_key()?;
    let filter = TransitionFilter {
        session: parse_id(&params, "sessionId")?,
        role: params.get("role").map(str::to_owned),
        lane: params
            .get("lane")
            .map(|l| {
                l.parse::<TrustLane>()
                    .map_err(|_| HttpError::malformed("lane must be trusted_ui or diagnostic"))
            })
            .transpose()?,
        status: params
            .get("status")
            .map(|s| {
                s.parse::<ActionStatus>()
                    .map_err(|_| HttpError::malformed("unknown action status"))
            })
            .transpose()?,
        from_state: parse_id(&params, "fromState")?,
        to_state: parse_id(&params, "toState")?,
    };
    let records = state.repos.api.transitions_list(run.id, &filter).await?;
    let total = records.len();
    let items: Vec<(String, Value)> = records
        .into_iter()
        .map(|t| {
            (
                t.id.to_string(),
                json!({
                    "id": t.id,
                    "sessionId": t.session,
                    "role": t.role,
                    "lane": t.lane,
                    "before": t.before,
                    "after": t.after,
                    "networkEpochId": t.network_epoch,
                    "action": t.action,
                    "settle": t.settle,
                    "createdAt": ts(t.created_at),
                }),
            )
        })
        .collect();
    let (page, next_key) = paginate(items, limit, cursor.as_deref());
    let path = format!("/v1/crawls/{}/transitions", run.id);
    let body =
        json!({ "data": page, "next": next_link(&path, &params, next_key.as_deref()), "total": total });
    Ok(json_response(StatusCode::OK, &body))
}
