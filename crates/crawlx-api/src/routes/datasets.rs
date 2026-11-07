//! Authenticated run-local dataset declarations and keyset item reads.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, Params};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use serde_json::json;

pub(crate) fn keyset(params: &Params) -> ApiResult<(u64, u16)> {
    let after = params
        .get("cursor")
        .unwrap_or("0")
        .parse::<u64>()
        .map_err(|_| HttpError::malformed("invalid dataset cursor"))?;
    let limit = params
        .get("limit")
        .unwrap_or("100")
        .parse::<u16>()
        .map_err(|_| HttpError::malformed("invalid dataset page limit"))?;
    if limit == 0 || limit > 1000 {
        return Err(HttpError::malformed("dataset page limit must be 1..=1000"));
    }
    Ok((after, limit))
}

/// List declared datasets without scanning accepted items.
///
/// # Errors
/// Returns authentication, scope, tenant ownership, expiry or storage errors.
pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({"data":run.config.datasets.stores}),
    ))
}

/// Read committed items using an ordinal cursor; content stays behind authenticated artifact URLs.
///
/// # Errors
/// Returns scope, ownership, invalid cursor, content-expired or repository errors.
pub async fn items(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, name)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let (after, limit) = keyset(&params)?;
    let items = state.repos.datasets.items(run.id, &name, after, limit).await?;
    let next = items
        .last()
        .filter(|_| items.len() == usize::from(limit))
        .map(|item| item.ordinal.to_string());
    let data: Vec<_> = items
        .into_iter()
        .map(|item| {
            let content_url = format!(
                "/v1/crawls/{}/artifacts/{}",
                run.id,
                item.item.content.artifact().id
            );
            json!({"item":item,"contentUrl":content_url})
        })
        .collect();
    Ok(json_response(
        StatusCode::OK,
        &json!({"data":data,"nextCursor":next}),
    ))
}
