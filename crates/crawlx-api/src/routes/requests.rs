//! Authenticated bounded request append, metadata keysets and producer sealing.
//!
//! A batch is either anonymous `GET`/`HEAD` proposals or admitted writes (`POST`, `PUT`, `PATCH`,
//! `DELETE`). Write bodies are retained as credential-bearing artifacts (never queue JSON) and
//! referenced by a tenant-keyed digest, and every write batch is recorded in the audit trail
//! under the calling key before it is queued. This route only queues: the URL plane decides
//! every write against the run's safety profile and authorization record, journals it and sends
//! it at most once. A reviewer approval for an approval-gated class is accepted only from a key
//! that also holds `approvals:decide`. Roles, session bindings and credential controls are not
//! accepted here: a write acts as the anonymous principal.

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
use base64::Engine as _;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{LoaderCursorV1, RequestBatchV1};
use crawlx_core::request::{
    keyed_body_digest, RequestBodyV1, RequestEnvelopeV1, WriteApprovalV1, MAX_WRITE_BODY_BYTES,
};
use crawlx_core::safety::RiskClass;
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
    #[serde(default)]
    body: Option<ProposalBody>,
    #[serde(default)]
    approval: Option<ProposalApproval>,
}

/// Body bytes of a write: exactly one of `text` (verbatim), `json` (compact serialization) or
/// `base64` (decoded bytes).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProposalBody {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    json: Option<serde_json::Value>,
    #[serde(default)]
    base64: Option<String>,
    #[serde(default)]
    media_type: Option<String>,
}

/// A reviewer's approval of the write's risk class.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProposalApproval {
    risk_class: RiskClass,
}

impl ProposalBody {
    /// The exact bytes and the declared (or default) media type.
    fn into_parts(self) -> ApiResult<(Vec<u8>, String)> {
        let (bytes, default_type) = match (self.text, self.json, self.base64) {
            (Some(text), None, None) => (text.into_bytes(), "text/plain; charset=utf-8"),
            (None, Some(json), None) => (
                serde_json::to_vec(&json).map_err(|_| HttpError::malformed("invalid request body"))?,
                "application/json",
            ),
            (None, None, Some(encoded)) => (
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| HttpError::malformed("request body is not valid base64"))?,
                "application/octet-stream",
            ),
            _ => {
                return Err(HttpError::malformed(
                    "a request body holds exactly one of text, json or base64",
                ))
            }
        };
        Ok((bytes, self.media_type.unwrap_or_else(|| default_type.to_owned())))
    }
}

/// What a write batch needs from the run and the deployment before any body is retained.
struct WritePlan<'a> {
    key: &'a [u8; 32],
}

impl<'a> WritePlan<'a> {
    /// Refuse a write batch the run cannot execute, with the reason a client can act on.
    fn prepare(state: &'a AppState, run: &crawlx_core::repo::CrawlRun) -> ApiResult<Self> {
        if run.config.safety.profile == crawlx_core::config::SafetyProfile::ReadOnly {
            return Err(HttpError::compat(
                StatusCode::BAD_REQUEST,
                "write_read_only",
                "the run's safety profile is read_only: mutating requests are refused",
            ));
        }
        if run.config.orchestration.is_none() {
            return Err(HttpError::malformed(
                "mutating requests require orchestration attempt limits on the run",
            ));
        }
        let key = state
            .config
            .request_identity_key
            .as_ref()
            .map(crawlx_core::SecretOr::expose)
            .ok_or_else(|| {
                HttpError::backend_unavailable(
                    "request_writes_unavailable",
                    "operator request identity key is required",
                )
            })?;
        Ok(Self { key })
    }

    /// Retain `body` as a credential-bearing artifact of the run and reference it by its
    /// tenant-keyed digest. An empty body is no body.
    async fn retain(
        &self,
        state: &AppState,
        run: &crawlx_core::repo::CrawlRun,
        body: ProposalBody,
    ) -> ApiResult<Option<RequestBodyV1>> {
        let (bytes, media_type) = body.into_parts()?;
        if media_type.len() > 128 || media_type.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(HttpError::malformed("invalid request body media type"));
        }
        let length = u64::try_from(bytes.len()).map_err(|_| HttpError::malformed("invalid request body"))?;
        if length > MAX_WRITE_BODY_BYTES {
            return Err(HttpError::payload_too_large(
                usize::try_from(MAX_WRITE_BODY_BYTES).unwrap_or(usize::MAX),
            ));
        }
        if length == 0 {
            return Ok(None);
        }
        let artifacts = state.repos.artifacts.artifact_store().ok_or_else(|| {
            HttpError::backend_unavailable(
                "request_writes_unavailable",
                "typed request body artifact sink unavailable",
            )
        })?;
        let artifact = artifacts
            .put(
                run.id,
                crawlx_core::repo::Sensitivity::CredentialBearing,
                &media_type,
                &bytes,
            )
            .await?;
        Ok(Some(RequestBodyV1::for_artifact(
            &artifact,
            keyed_body_digest(self.key, run.tenant, &bytes),
            1,
            length,
            media_type,
        )))
    }
}
fn get_method() -> String {
    "GET".into()
}
fn default_route() -> String {
    "default".into()
}

fn require_url_queue(mode: crawlx_core::config::CrawlMode) -> ApiResult<()> {
    if matches!(
        mode,
        crawlx_core::config::CrawlMode::Static | crawlx_core::config::CrawlMode::Hybrid
    ) {
        Ok(())
    } else {
        Err(HttpError::malformed(
            "native request queue requires a static or hybrid URL plane",
        ))
    }
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

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImportFormat {
    #[default]
    RequestExportV1,
    CheckpointExportV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Import {
    #[serde(default)]
    format: ImportFormat,
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
    require_url_queue(run.config.mode)?;
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
    let batch = match input.format {
        ImportFormat::RequestExportV1 => {
            let requests =
                crawlx_core::request::import::decode_export(&source, &tenant_key.0, batch_id, |url| {
                    Canonicalizer::canonicalize_url(url, &canonical)
                        .map_err(|_| crawlx_core::request::import::ImportError::Request)
                })
                .map_err(|error| HttpError::malformed(error.to_string()))?;
            let mut batch = RequestBatchV1::new(run.tenant, run.id, "anonymous".into(), batch_id, requests);
            batch.producer_epoch = input.producer_epoch;
            batch.expected_cursor = input.expected_cursor;
            batch.next_cursor = input.next_cursor;
            batch
        }
        ImportFormat::CheckpointExportV1 => {
            if input.expected_cursor.is_some() || input.next_cursor.is_some() {
                return Err(HttpError::malformed(
                    "checkpoint export owns its cursor transition",
                ));
            }
            let loader = input
                .export
                .get("source")
                .and_then(serde_json::Value::as_str)
                .filter(|id| {
                    !id.is_empty()
                        && id.len() <= 64
                        && id
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
                })
                .ok_or_else(|| HttpError::malformed("invalid checkpoint source identifier"))?;
            let current = state.repos.frontier.loader_cursor(run.id, loader).await?;
            let authority = crawlx_core::request::import::ImportAdmissionV1::new(
                run.tenant,
                run.id,
                "anonymous".into(),
                batch_id,
                input.producer_epoch,
            );
            crawlx_core::request::import::decode_checkpoint_export(
                &source,
                &tenant_key.0,
                authority,
                current.as_ref(),
                |url| {
                    Canonicalizer::canonicalize_url(url, &canonical)
                        .map_err(|_| crawlx_core::request::import::ImportError::Request)
                },
            )
            .map_err(|error| HttpError::malformed(error.to_string()))?
        }
    };
    let scope = ScopePolicy::new(&run.config).map_err(|_| HttpError::malformed("invalid run scope"))?;
    for request in &batch.requests {
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
    require_url_queue(run.config.mode)?;
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
    let writes = input
        .requests
        .iter()
        .filter(|proposal| RequestEnvelopeV1::is_write_method(&proposal.method))
        .count();
    if writes != 0 && writes != input.requests.len() {
        return Err(HttpError::malformed(
            "a request batch is either all reads or all writes",
        ));
    }
    let write_plan = if writes == 0 {
        None
    } else {
        Some(WritePlan::prepare(&state, &run)?)
    };
    let mut requests = Vec::with_capacity(input.requests.len());
    for proposal in input.requests {
        if write_plan.is_none() {
            if !matches!(proposal.method.as_str(), "GET" | "HEAD") {
                return Err(HttpError::malformed(
                    "request methods other than GET, HEAD and the write methods are not supported",
                ));
            }
            if proposal.body.is_some() || proposal.approval.is_some() {
                return Err(HttpError::malformed(
                    "only write methods carry a body or an approval",
                ));
            }
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
        let mut envelope = RequestEnvelopeV1::new(url, proposal.method, proposal.depth, None);
        envelope.route = proposal.route;
        envelope.metadata = proposal.metadata;
        envelope.priority = proposal.priority;
        if let Some(plan) = &write_plan {
            if let Some(body) = proposal.body {
                envelope.body = plan.retain(&state, &run, body).await?;
            }
            if let Some(approval) = proposal.approval {
                principal.require(Scope::ApprovalsDecide)?;
                if envelope.write_risk() != Some(approval.risk_class) {
                    return Err(HttpError::malformed(
                        "the approved risk class does not match the request method",
                    ));
                }
                envelope.approval = Some(WriteApprovalV1::new(
                    approval.risk_class,
                    principal.actor(),
                    state.clock.now(),
                ));
            }
        }
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
    if write_plan.is_some() {
        let approved: Vec<&str> = batch
            .requests
            .iter()
            .filter_map(|request| request.approval.as_ref().map(|approval| approval.risk.as_str()))
            .collect();
        state
            .repos
            .api
            .audit_append(
                principal.tenant,
                Some(run.id),
                &principal.actor(),
                "requests.write_submitted",
                json!({
                    "batch": batch.batch_id.to_hex(),
                    "writes": batch.requests.len(),
                    "approved": approved,
                }),
            )
            .await?;
    }
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
