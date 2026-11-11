//! Explicit tenant-owned source memo reset. Frontier identities and queued work remain intact.
use crate::auth::Principal;
use crate::errors::ApiResult;
use crate::routes::crawls::load_run;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::json_response;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Extension;
use serde_json::json;

/// Forget all article-seen and category scopes for one authenticated run.
/// ZDR resets the same shared volatile authority used by workers, without durable memo writes.
///
/// # Errors
/// Returns authentication, write-scope, tenant ownership, expiry or repository errors.
pub async fn reset(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    state.repos.source_memo.reset(run.tenant, run.id).await?;
    let mut response = json_response(StatusCode::OK, &json!({"reset":true,"frontierUnchanged":true}));
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}
