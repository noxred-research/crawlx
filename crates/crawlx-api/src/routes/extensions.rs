//! Authenticated compiled extension facts. No runtime code registration exists.

use crate::{
    auth::Principal,
    errors::{ApiResult, HttpError},
    state::AppState,
    store::Scope,
    util::json_response,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    Extension,
};

/// Publish reviewed registry versions, fixed schemas and capability ceilings.
/// This reports compiled implementation facts, not worker health or SDK compatibility.
///
/// # Errors
/// Returns `403 scope_missing` without `crawls:read`.
pub async fn registry(Extension(principal): Extension<Principal>) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    Ok(json_response(
        StatusCode::OK,
        &crawlx_core::extensions::registry_publication(),
    ))
}

/// Publish a tenant-owned run's selected registry versions and config digests.
/// Raw configuration, document content, headers and credentials are never returned.
///
/// # Errors
/// Requires `crawls:read`; absent and foreign runs return the same `404`.
/// Expired operational configuration follows the existing retention error path.
pub async fn effective(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = super::crawls::load_run(&state, &principal, &id).await?;
    let publication = run
        .config
        .extensions
        .publication()
        .map_err(|_| HttpError::internal())?;
    Ok(json_response(StatusCode::OK, &publication))
}
