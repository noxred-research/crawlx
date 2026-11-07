//! Firecrawl v2 `extract` endpoints of the compat facade: `POST /extract` starts an
//! asynchronous job ([`crate::intel::extract`]), `GET /extract/{id}` reports it.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::intel::{common, extract};
use crate::openapi::Operation;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Router};
use crawlx_storage::JobKind;
use serde_json::{json, Value};

/// OpenAPI rows of this module (`GET /v1/openapi.json`).
pub const OPERATIONS: &[Operation] = &[
    (
        "post",
        "/compat/firecrawl/v2/extract",
        "firecrawlExtract",
        "Firecrawl v2 extract: structured data from URLs (globs), prompt and schema",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/firecrawl/v2/extract/{id}",
        "firecrawlExtractStatus",
        "Firecrawl v2 extract: job status, data, tokensUsed and expiresAt",
        "crawls:read",
        "200",
    ),
];

/// Routes of this module, mounted under `/compat/firecrawl/v2` behind authentication.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/compat/firecrawl/v2/extract", post(create))
        .route("/compat/firecrawl/v2/extract/{id}", get(status))
}

/// `POST /compat/firecrawl/v2/extract`.
///
/// # Errors
/// `403 scope_missing` without `crawls:write`, `422` for an invalid body, `503
/// llm_not_configured` / `search_not_configured` when a backend the request
/// needs is not configured.
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let req = extract::parse(&body)?;
    let warnings = req.warnings.clone();
    let (id, invalid) = extract::start(&state, principal.tenant, &body, req).await?;
    let mut out = json!({ "success": true, "id": id, "invalidURLs": invalid });
    if !warnings.is_empty() {
        out["warning"] = json!(warnings.join("; "));
    }
    Ok(json_response(StatusCode::OK, &out))
}

/// `GET /compat/firecrawl/v2/extract/{id}`.
///
/// # Errors
/// `403 scope_missing` without `crawls:read`, `404 not_found` for an unknown, expired or foreign job.
pub async fn status(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let id = common::parse_id(&id, "extract job")?;
    let job = state
        .repos
        .intel
        .job_get(principal.tenant, id)
        .await?
        .filter(|j| j.kind == JobKind::Extract && j.expires_at > state.clock.now())
        .ok_or_else(|| HttpError::not_found("extract job"))?;
    let show = job
        .request
        .get("showSources")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok(json_response(StatusCode::OK, &extract::status_json(&job, show)))
}
