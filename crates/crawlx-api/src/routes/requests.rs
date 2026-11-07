//! Authenticated bounded request append, metadata keysets and producer sealing.
//!
//! This route accepts anonymous GET proposals only. Body-bearing methods, session
//! bindings and credential controls remain behind their existing admitted-effect paths.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{LoaderCursorV1, RequestBatchV1};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_policy::ScopePolicy;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use url::Url;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Proposal {
    url: Url,
    #[serde(default = "get_method")]
    method: String,
    #[serde(default = "default_route")]
    route: String,
    #[serde(default)]
    metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    depth: u16,
    #[serde(default)]
    priority: i32,
}
fn get_method() -> String {
    "GET".into()
}
fn default_route() -> String {
    "default".into()
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Append {
    requests: Vec<Proposal>,
    producer_epoch: u64,
    #[serde(default)]
    expected_cursor: Option<LoaderCursorV1>,
    #[serde(default)]
    next_cursor: Option<LoaderCursorV1>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Seal {
    producer_epoch: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Import {
    export: serde_json::Value,
    producer_epoch: u64,
    #[serde(default)]
    expected_cursor: Option<LoaderCursorV1>,
    #[serde(default)]
    next_cursor: Option<LoaderCursorV1>,
}

/// Import a pinned declarative upstream queue through the native admitted frontier.
/// Source JSON is never executed and raw source keys never enter durable queue rows.
///
/// # Errors
/// Returns scope, ownership, missing operator key, unsupported source options, quota or cursor errors.
pub async fn import(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    if let Some(record) = run.config.safety.authorization_record_ref {
        let record = state
            .repos
            .api
            .authorization_get(principal.tenant, record)
            .await?
            .ok_or_else(|| HttpError::not_found("authorization"))?;
        record
            .check_active(state.clock.now())
            .map_err(|_| HttpError::malformed("run authorization is no longer active"))?;
    }
    let input: Import =
        serde_json::from_value(body).map_err(|_| HttpError::malformed("invalid request import"))?;
    let root = state
        .config
        .request_identity_key
        .as_ref()
        .map(crawlx_core::SecretOr::expose)
        .ok_or_else(|| {
            HttpError::backend_unavailable(
                "request_import_unavailable",
                "operator request identity key is required",
            )
        })?;
    let tenant_key = Digest::keyed(root, "crawlx/tenant-request-key/v1", run.tenant.0.as_bytes());
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or_else(|| HttpError::malformed("Idempotency-Key is required for request import"))?;
    let batch_id = Digest::keyed(&tenant_key.0, "crawlx/import-request-batch/v1", key.as_bytes());
    let canonical = CanonicalizeOptions::from_scope(
        &run.config.scope,
        run.seed.derive("resource-id-key", &[run.id.0.as_bytes()]),
    );
    let source =
        serde_json::to_vec(&input.export).map_err(|_| HttpError::malformed("invalid request export"))?;
    let requests = crawlx_core::request::import::decode_export(&source, &tenant_key.0, batch_id, |url| {
        Canonicalizer::canonicalize_url(url, &canonical)
            .map_err(|_| crawlx_core::request::import::ImportError::Request)
    })
    .map_err(|error| HttpError::malformed(error.to_string()))?;
    let scope = ScopePolicy::new(&run.config).map_err(|_| HttpError::malformed("invalid run scope"))?;
    for request in &requests {
        if !scope.decide(&request.url, request.depth).is_admitted() {
            return Err(HttpError::malformed(
                "imported request outside admitted run scope",
            ));
        }
        run.config
            .extensions
            .route(&request.route)
            .map_err(|_| HttpError::malformed("unknown imported request route"))?;
    }
    let mut batch = RequestBatchV1::new(run.tenant, run.id, "anonymous".into(), batch_id, requests);
    batch.producer_epoch = input.producer_epoch;
    batch.expected_cursor = input.expected_cursor;
    batch.next_cursor = input.next_cursor;
    let receipt = state.repos.frontier.append_batch(batch).await?;
    Ok(json_response(StatusCode::OK, &json!({"data":receipt})))
}

/// Append a bounded retryable native request batch with server-derived authority.
///
/// # Errors
/// Returns scope, ownership, revoked authorization, invalid proposal, quota or cursor errors.
pub async fn append(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    headers: HeaderMap,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    let input: Append =
        serde_json::from_value(body).map_err(|_| HttpError::malformed("invalid native request batch"))?;
    let maximum = run
        .config
        .orchestration
        .as_ref()
        .map_or(256, |cfg| cfg.queue.batch_size);
    if input.requests.len() > usize::try_from(maximum).unwrap_or(0) {
        return Err(HttpError::malformed("request batch exceeds configured limit"));
    }
    let key = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii_graphic())
        })
        .ok_or_else(|| HttpError::malformed("Idempotency-Key of 1..=128 printable bytes is required"))?;
    if let Some(record) = run.config.safety.authorization_record_ref {
        let record = state
            .repos
            .api
            .authorization_get(principal.tenant, record)
            .await?
            .ok_or_else(|| HttpError::not_found("authorization"))?;
        record
            .check_active(state.clock.now())
            .map_err(|_| HttpError::malformed("run authorization is no longer active"))?;
    }
    let resource_key = run.seed.derive("resource-id-key", &[run.id.0.as_bytes()]);
    let canonical = CanonicalizeOptions::from_scope(&run.config.scope, resource_key);
    let scope = ScopePolicy::new(&run.config).map_err(|_| HttpError::malformed("invalid run scope"))?;
    let mut requests = Vec::with_capacity(input.requests.len());
    for proposal in input.requests {
        if proposal.method != "GET" {
            return Err(HttpError::malformed(
                "request methods other than GET require journalled action admission",
            ));
        }
        if !proposal.url.username().is_empty() || proposal.url.password().is_some() {
            return Err(HttpError::malformed("URL credentials are not accepted"));
        }
        let url = Canonicalizer::canonicalize_url(&proposal.url, &canonical)
            .map_err(|_| HttpError::malformed("invalid request URL"))?;
        if !scope.decide(&url, proposal.depth).is_admitted() {
            return Err(HttpError::malformed("request outside admitted run scope"));
        }
        run.config
            .extensions
            .route(&proposal.route)
            .map_err(|_| HttpError::malformed("unknown request route"))?;
        let mut envelope = RequestEnvelopeV1::get(url, proposal.depth, None);
        envelope.route = proposal.route;
        envelope.metadata = proposal.metadata;
        envelope.priority = proposal.priority;
        envelope
            .validate()
            .map_err(|_| HttpError::malformed("invalid request envelope"))?;
        requests.push(envelope);
    }
    let batch_id = Digest::of_value("crawlx/api-request-batch/v1", &(run.tenant, run.id, key))
        .map_err(|_| HttpError::malformed("invalid request receipt key"))?;
    let mut batch = RequestBatchV1::new(run.tenant, run.id, "anonymous".into(), batch_id, requests);
    batch.producer_epoch = input.producer_epoch;
    batch.expected_cursor = input.expected_cursor;
    batch.next_cursor = input.next_cursor;
    batch.validate().map_err(HttpError::from)?;
    let receipt = state.repos.frontier.append_batch(batch).await?;
    Ok(json_response(StatusCode::OK, &json!({"data":receipt})))
}

/// Read a bounded keyset of privacy-safe request metadata, never raw URL/header/body values.
///
/// # Errors
/// Returns scope, ownership, invalid cursor/limit or repository errors.
pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = crate::routes::crawls::load_run_metadata(&state, &principal, &id).await?;
    let after = params
        .get("cursor")
        .unwrap_or("0")
        .parse::<i64>()
        .map_err(|_| HttpError::malformed("invalid request cursor"))?;
    let limit = params
        .get("limit")
        .unwrap_or("256")
        .parse::<u32>()
        .map_err(|_| HttpError::malformed("invalid request limit"))?;
    if after < 0 || limit == 0 || limit > 1000 {
        return Err(HttpError::malformed("invalid request keyset bounds"));
    }
    let data = state.repos.frontier.metadata_page(run.id, after, limit).await?;
    let next = data
        .last()
        .filter(|_| data.len() == usize::try_from(limit).unwrap_or(0))
        .map(|row| row.id.to_string());
    let activity = state.repos.frontier.activity(run.id).await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({"data":data,"nextCursor":next,"activity":activity}),
    ))
}

/// Seal authenticated producer input under its expected epoch; queued work continues draining.
///
/// # Errors
/// Returns scope, ownership, stale epoch or repository errors.
pub async fn seal(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    let input: Seal =
        serde_json::from_value(body).map_err(|_| HttpError::malformed("invalid producer seal"))?;
    state.repos.frontier.seal(run.id, input.producer_epoch).await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({"sealed":true,"producerEpoch":input.producer_epoch}),
    ))
}
