//! Versioned KV over authenticated run namespaces. Bytes must already pass artifact privacy gates.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::{DatasetContentV1, KvCasV1, KvValueV1};
use crawlx_core::repo::{CrawlRun, Sensitivity};
use serde_json::json;

fn expected(headers: &HeaderMap) -> ApiResult<u64> {
    let value = headers
        .get(header::IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            HttpError::malformed("If-Match with exact quoted KV version is required; use \"0\" for creation")
        })?;
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| HttpError::malformed("invalid KV version ETag"))
}
fn response(value: KvValueV1) -> ApiResult<Response> {
    let mut response = json_response(StatusCode::OK, &json!(value));
    response.headers_mut().insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", value.version))
            .map_err(|_| HttpError::malformed("invalid KV version"))?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}
async fn verify(state: &AppState, run: &CrawlRun, delta: &KvCasV1) -> ApiResult<()> {
    let Some(content) = &delta.content else {
        return Ok(());
    };
    match content {
        DatasetContentV1::Durable { artifact } if run.config.retention.mode != RetentionMode::Zdr => {
            let row = state
                .repos
                .artifacts
                .row(artifact.id)
                .await?
                .filter(|row| row.run == run.id && row.tenant == run.tenant && row.digest == artifact.digest)
                .ok_or_else(|| HttpError::not_found("artifact"))?;
            if !matches!(row.sensitivity, Sensitivity::Metadata | Sensitivity::Content)
                || row.expires_at.is_some_and(|end| end <= state.clock.now())
                || row
                    .expires_at
                    .is_some_and(|end| delta.expires_at.is_none_or(|expiry| expiry > end))
                || row.size_bytes != delta.size_bytes
                || row.content_type != delta.content_type
            {
                return Err(HttpError::artifact_unavailable(
                    "KV artifact exceeds retention or content policy",
                ));
            }
        }
        DatasetContentV1::Volatile {
            page,
            artifact,
            expires_at,
        } if run.config.retention.mode == RetentionMode::Zdr => {
            let (original_expiry, actual_size) = state
                .zdr
                .content_metadata(run.tenant, run.id, *page, artifact)
                .await?
                .ok_or_else(|| HttpError::expired("KV content_expired"))?;
            if original_expiry != *expires_at
                || *expires_at <= state.clock.now()
                || delta.expires_at.is_none_or(|end| end > *expires_at)
                || actual_size != delta.size_bytes
            {
                return Err(HttpError::expired("KV content_expired"));
            }
        }
        _ => {
            return Err(HttpError::artifact_unavailable(
                "KV content retention class mismatch",
            ))
        }
    }
    Ok(())
}

/// Read a typed KV value and its exact ETag.
///
/// # Errors
/// Returns scope, tenant, missing value, expiry or storage errors.
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, store, key)): Path<(String, String, String)>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let value = state
        .repos
        .kv
        .value(run.id, &store, &key)
        .await?
        .ok_or_else(|| HttpError::not_found("kv value"))?;
    response(value)
}

/// CAS a previously privacy-approved artifact reference. Namespace and version must match path/ETag.
///
/// # Errors
/// Returns scope, ownership, malformed input, CAS collision, quota or retention errors.
pub async fn put(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, store, key)): Path<(String, String, String)>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    let delta: KvCasV1 =
        serde_json::from_value(body).map_err(|_| HttpError::malformed("invalid typed KV delta"))?;
    if delta.store != store || delta.key != key || delta.expected_version != expected(&headers)? {
        return Err(HttpError::malformed(
            "KV namespace/key/version must match path and If-Match",
        ));
    }
    verify(&state, &run, &delta).await?;
    response(state.repos.kv.compare_and_set(run.id, delta).await?)
}

/// Write a tombstone under an exact ETag; never reset version or extend expiry.
///
/// # Errors
/// Returns scope, ownership, missing value, stale ETag, expiry or storage errors.
pub async fn delete(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, store, key)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    let old = state
        .repos
        .kv
        .value(run.id, &store, &key)
        .await?
        .ok_or_else(|| HttpError::not_found("kv value"))?;
    let mut delta = old.value;
    delta.expected_version = expected(&headers)?;
    delta.content = None;
    delta.size_bytes = 0;
    response(state.repos.kv.compare_and_set(run.id, delta).await?)
}

/// List bounded KV metadata by keyset, never an unrestricted prefix scan.
///
/// # Errors
/// Returns scope, ownership, invalid bounds, expiry or storage errors.
pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, store)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let limit = params
        .get("limit")
        .unwrap_or("100")
        .parse::<u16>()
        .map_err(|_| HttpError::malformed("invalid KV page limit"))?;
    let values = state
        .repos
        .kv
        .keys(run.id, &store, params.get("cursor").unwrap_or(""), limit)
        .await?;
    let next = values
        .last()
        .filter(|_| values.len() == usize::from(limit))
        .map(|value| value.value.key.clone());
    Ok(json_response(
        StatusCode::OK,
        &json!({"data":values,"nextCursor":next}),
    ))
}

/// Drop a run-scoped namespace permanently; old CAS tokens cannot recreate its keys.
///
/// # Errors
/// Returns scope, ownership, declaration or storage errors.
pub async fn drop_store(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, store)): Path<(String, String)>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    state.repos.kv.drop_store(run.id, &store).await?;
    Ok(json_response(StatusCode::OK, &json!({"dropped":true})))
}
