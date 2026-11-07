//! `GET /v1/crawls/{id}/traffic` (filterable by lane).

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::{Scope, TrafficFilter};
use crate::util::{json_response, next_link, paginate, ts, Params};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::traffic::TrafficOrigin;
use crawlx_core::TrustLane;
use serde_json::{json, Value};

fn lane_param(params: &Params) -> Result<Option<TrustLane>, HttpError> {
    match params.get("lane") {
        None | Some("trusted_ui") => Ok(Some(TrustLane::TrustedUi)),
        Some("diagnostic") => Ok(Some(TrustLane::Diagnostic)),
        Some("all") => Ok(None),
        Some(_) => Err(HttpError::malformed("lane must be trusted_ui, diagnostic or all")),
    }
}

fn origin_param(v: &str) -> Result<TrafficOrigin, HttpError> {
    match v {
        "page" => Ok(TrafficOrigin::Page),
        "service_worker" => Ok(TrafficOrigin::ServiceWorker),
        "websocket" | "web_socket" => Ok(TrafficOrigin::WebSocket),
        "event_source" => Ok(TrafficOrigin::EventSource),
        "fetch_plane" => Ok(TrafficOrigin::FetchPlane),
        _ => Err(HttpError::malformed(
            "origin must be page, service_worker, websocket, event_source or fetch_plane",
        )),
    }
}

/// Wire label (the `traffic_events.origin` column values).
const fn origin_label(o: TrafficOrigin) -> &'static str {
    match o {
        TrafficOrigin::Page => "page",
        TrafficOrigin::ServiceWorker => "service_worker",
        TrafficOrigin::WebSocket => "websocket",
        TrafficOrigin::EventSource => "event_source",
        TrafficOrigin::FetchPlane => "fetch_plane",
    }
}

/// `GET /v1/crawls/{id}/traffic`: trusted lane by default.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown run or a run owned by
/// another tenant, `400 malformed_request` for a bad filter, `limit` or `cursor`.
pub async fn traffic(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let limit = params.limit(&state.settings)?;
    let cursor = params.cursor_key()?;
    let filter = TrafficFilter {
        lane: lane_param(&params)?,
        role: params.get("role").map(str::to_owned),
        epoch: params
            .get("epochId")
            .map(|v| {
                v.parse()
                    .map_err(|_| HttpError::malformed("epochId must be a UUID"))
            })
            .transpose()?,
        origin: params.get("origin").map(origin_param).transpose()?,
    };
    let records = state.repos.api.traffic_list(run.id, &filter).await?;
    let total = records.len();
    let items: Vec<(String, Value)> = records
        .into_iter()
        .map(|t| {
            (
                t.id.clone(),
                json!({
                    "id": t.id,
                    "epochId": t.epoch_id,
                    "actionId": t.action,
                    "lane": t.lane,
                    "role": t.role,
                    "origin": origin_label(t.origin),
                    "method": t.method,
                    "url": t.url,
                    "status": t.status,
                    "thirdParty": t.third_party,
                    "late": t.late,
                    "requestHeaders": t.request_headers,
                    "responseHeaders": t.response_headers,
                    "responseBodyRef": t.response_body.map(|a| format!("/v1/crawls/{}/artifacts/{}", run.id, a.id)),
                    "occurredAt": ts(t.occurred_at),
                }),
            )
        })
        .collect();
    let (page, next_key) = paginate(items, limit, cursor.as_deref());
    let path = format!("/v1/crawls/{}/traffic", run.id);
    let body =
        json!({ "data": page, "next": next_link(&path, &params, next_key.as_deref()), "total": total });
    Ok(json_response(StatusCode::OK, &body))
}
