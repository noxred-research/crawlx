//! `POST /v1/authorizations`, `GET /v1/authorizations/{id}`,
//! `POST /v1/authorizations/{id}/revoke`, `POST /v1/authorizations/{id}/verify`
//! (every change writes an audit event).
//!
//! A record is immutable evidence. It is created once, after its ownership proof verified
//! ([`crate::ownership`]), and then only changes lifecycle state: revocation, re-verification.
//! An amendment is a new record id with `version` + 1 and a new proof. Every response is the
//! record resource:
//!
//! ```json
//! { "record": { ...the record with verifiedAt / revokedAt / revokedReason... },
//!   "bodyDigest": "<hex>", "status": "active|not_yet_valid|expired|revoked",
//!   "verification": { "kind": "...", "checkedAt": "...", "hosts|origins|keyId": "..." } }
//! ```
//!
//! Audit events (`authorization.created`, `.verified`, `.revoked`, and `.used` at run creation,
//! see [`used_subject`]) carry ids and digests, never record content.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::ownership::{verify_ownership, OwnershipFailure, OwnershipOutcome};
use crate::routes::crawls::serde_detail;
use crate::state::AppState;
use crate::store::{AuthorizationEntry, AuthorizationInsert, Scope};
use crate::util::{json_response, JsonBody};
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::hash::Digest;
use crawlx_core::{AuthorizationRecordId, CrawlRunId, TenantId, Timestamp};
use crawlx_policy::{AuthorizationRecord, AuthzFailure};
use serde_json::{json, Value};

/// Lifecycle keys of a record: set by the server, refused in a create body.
const LIFECYCLE_KEYS: [&str; 3] = ["verifiedAt", "revokedAt", "revokedReason"];

/// Longest `reason` of a revocation, in characters.
const MAX_REASON_CHARS: usize = 1000;

/// What an authorization record is, at `now`: `active`, `not_yet_valid`, `expired` or `revoked`.
fn status(record: &AuthorizationRecord, now: Timestamp) -> &'static str {
    match record.check_active(now) {
        Ok(()) => "active",
        Err(AuthzFailure::Revoked) => "revoked",
        Err(AuthzFailure::NotYetValid) => "not_yet_valid",
        Err(_) => "expired",
    }
}

/// The record resource.
fn entry_json(entry: &AuthorizationEntry, now: Timestamp) -> Value {
    json!({
        "record": entry.record,
        "bodyDigest": entry.body_digest.to_string(),
        "status": status(&entry.record, now),
        "verification": entry.verification,
    })
}

fn record_response(code: StatusCode, entry: &AuthorizationEntry, now: Timestamp) -> Response {
    let mut resp = json_response(code, &entry_json(entry, now));
    if code == StatusCode::CREATED {
        if let Ok(location) = HeaderValue::from_str(&format!("/v1/authorizations/{}", entry.record.id)) {
            resp.headers_mut().insert(header::LOCATION, location);
        }
    }
    resp
}

/// Audit subject of the `authorization.*` events: ids and the body digest, never record content.
fn subject(entry: &AuthorizationEntry) -> Value {
    json!({
        "record_id": entry.record.id,
        "version": entry.record.version,
        "bodyDigest": entry.body_digest.to_string(),
    })
}

/// Audit subject of `authorization.used`, written when a run is created under a record: the
/// record id and version, the body digest the run is bound to, and the run.
pub(crate) fn used_subject(
    record: AuthorizationRecordId,
    version: u32,
    body_digest: Digest,
    run: CrawlRunId,
) -> Value {
    json!({
        "record_id": record,
        "version": version,
        "bodyDigest": body_digest.to_string(),
        "run_id": run,
    })
}

/// Parse a create body into a record of `principal`'s tenant and run the structural checks.
/// Every violation found is reported, with a JSON pointer and a code.
fn parse_record(principal: &Principal, body: Value) -> Result<AuthorizationRecord, HttpError> {
    let Value::Object(mut map) = body else {
        return Err(HttpError::invalid_request(vec![Detail::new(
            "",
            "invalid_type",
            "the body must be a JSON object holding an authorization record",
        )]));
    };
    let mut details = Vec::new();
    for key in LIFECYCLE_KEYS {
        if map.contains_key(key) {
            details.push(Detail::new(
                format!("/{key}"),
                "read_only",
                format!("`{key}` is set by the server and cannot be supplied"),
            ));
        }
    }
    match map.get("tenant") {
        None => {
            map.insert("tenant".to_owned(), json!(principal.tenant));
        }
        Some(given) => {
            let same = serde_json::from_value::<TenantId>(given.clone()).is_ok_and(|t| t == principal.tenant);
            if !same {
                details.push(Detail::new(
                    "/tenant",
                    "tenant_mismatch",
                    "tenant must be the caller's tenant; omit it to use the caller's tenant",
                ));
            }
        }
    }
    let record: AuthorizationRecord = match serde_json::from_value(Value::Object(map)) {
        Ok(record) => record,
        Err(e) => {
            details.push(serde_detail(&e));
            return Err(HttpError::invalid_request(details));
        }
    };
    if record.ownership.is_none() {
        details.push(Detail::new(
            "/ownership",
            "required",
            "an ownership proof is required: dns_txt, well_known_file or operator_signature",
        ));
    }
    if let Err(e) = record.validate() {
        details.push(Detail::new("", "invalid_authorization", e.to_string()));
    }
    if details.is_empty() {
        Ok(record)
    } else {
        Err(HttpError::invalid_request(details))
    }
}

/// `422 ownership_unverified` naming each failing host or origin.
fn unverified(failures: Vec<OwnershipFailure>) -> HttpError {
    HttpError::ownership_unverified(
        failures
            .into_iter()
            .map(|f| {
                Detail::new(
                    "/ownership",
                    "ownership_unverified",
                    format!("{}: {}", f.subject, f.reason),
                )
            })
            .collect(),
    )
}

/// Run the proof of `record`; `Ok` carries the verification evidence to store.
async fn prove(state: &AppState, record: &AuthorizationRecord, now: Timestamp) -> Result<Value, HttpError> {
    verify_evidence(state, record).await?;
    match verify_ownership(record, &state.config.operator_keys, state.ownership.as_ref(), now).await {
        OwnershipOutcome::Verified { verification } => Ok(verification),
        OwnershipOutcome::Unverified { failures } => Err(unverified(failures)),
    }
}

async fn verify_evidence(state: &AppState, record: &AuthorizationRecord) -> Result<(), HttpError> {
    let invalid = || {
        HttpError::invalid_request(vec![Detail::new(
            "/evidence",
            "evidence_unverified",
            "evidence must resolve to an available tenant-owned artifact with the declared digest",
        )])
    };
    let id = record.evidence.artifact_id.ok_or_else(invalid)?;
    let row = state.repos.artifacts.row(id).await?.ok_or_else(invalid)?;
    if row.tenant != record.tenant
        || row.digest != record.evidence.digest
        || row.expires_at.is_some_and(|expiry| expiry <= state.clock.now())
    {
        return Err(invalid());
    }
    let reference = crawlx_core::ArtifactRef {
        id,
        digest: row.digest,
    };
    let bytes = state
        .repos
        .artifacts
        .read(&reference)
        .await
        .map_err(|error| match error {
            crawlx_core::StoreError::NotFound { .. } => invalid(),
            other => other.into(),
        })?;
    if Digest::of("crawlx/artifact/v1", &bytes) != record.evidence.digest {
        return Err(invalid());
    }
    Ok(())
}

/// `POST /v1/authorizations/evidence`: store a UTF-8 document on an existing owned run.
///
/// The body is `{"runId": "...", "document": "..."}`. ZDR runs refuse durable evidence.
/// Returns the artifact id and digest to place in an authorization's `evidence` object.
///
/// # Errors
/// Refuses missing scopes, foreign runs, empty documents, ZDR writes and storage failures.
pub async fn upload_evidence(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::AuthorizationsWrite)?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Upload {
        run_id: CrawlRunId,
        document: String,
    }
    let upload: Upload = serde_json::from_value(body)
        .map_err(|error| HttpError::invalid_request(vec![serde_detail(&error)]))?;
    let run =
        crate::routes::crawls::load_run_metadata(&state, &principal, &upload.run_id.to_string()).await?;
    if upload.document.trim().is_empty() {
        return Err(HttpError::invalid_request(vec![Detail::new(
            "/document",
            "required",
            "an evidence document is required",
        )]));
    }
    let artifact = state
        .repos
        .artifacts
        .put_evidence(run.id, upload.document.as_bytes())
        .await?;
    audit(
        &state,
        &principal,
        "authorization.evidence_uploaded",
        json!({
            "artifact_id": artifact.id, "digest": artifact.digest,
        }),
    )
    .await?;
    Ok(json_response(
        StatusCode::CREATED,
        &json!({
            "artifactId": artifact.id, "digest": artifact.digest,
        }),
    ))
}

fn parse_id(id: &str) -> Result<AuthorizationRecordId, HttpError> {
    id.parse()
        .map_err(|_| HttpError::not_found("authorization record"))
}

async fn load(
    state: &AppState,
    principal: &Principal,
    id: AuthorizationRecordId,
) -> ApiResult<AuthorizationEntry> {
    state
        .repos
        .api
        .authorization_entry(principal.tenant, id)
        .await?
        .ok_or_else(|| HttpError::not_found("authorization record"))
}

async fn audit(state: &AppState, principal: &Principal, event: &str, subject: Value) -> ApiResult<()> {
    state
        .repos
        .api
        .audit_append(principal.tenant, None, &principal.actor(), event, subject)
        .await?;
    Ok(())
}

/// `POST /v1/authorizations`: store a new record after its ownership proof verified.
///
/// `tenant` may be omitted (the caller's tenant is used); `id` and `ownership` are required and
/// `verifiedAt`, `revokedAt` and `revokedReason` are refused. The same id with the same body
/// answers `200` with the stored record without probing again.
///
/// # Errors
/// `403 scope_missing` without `authorizations:write`, `422 invalid_request` (unknown field, missing
/// key, failed validation, another tenant, a window that already ended) with `details[]`, `422
/// ownership_unverified` with one detail per failing host or origin, `409 authorization_exists` for
/// the same id with another body (or another tenant's record).
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::AuthorizationsWrite)?;
    let record = parse_record(&principal, body)?;
    let api = &state.repos.api;
    let digest = record.body_digest().map_err(|e| {
        tracing::error!(error = %e, "could not digest an authorization record");
        HttpError::internal()
    })?;
    let now = state.clock.now();
    if let Some(existing) = api.authorization_entry(principal.tenant, record.id).await? {
        // records are immutable: the identical body is a replay, any other body is a conflict
        return if existing.body_digest == digest {
            Ok(record_response(StatusCode::OK, &existing, now))
        } else {
            Err(HttpError::authorization_exists())
        };
    }
    if record.valid_to <= now {
        return Err(HttpError::invalid_request(vec![Detail::new(
            "/validTo",
            "out_of_range",
            "validTo must be in the future",
        )]));
    }
    let verification = prove(&state, &record, now).await?;
    match api
        .authorization_create(principal.tenant, principal.key_id, &record, &verification, now)
        .await?
    {
        AuthorizationInsert::Created => {}
        AuthorizationInsert::Taken => return Err(HttpError::authorization_exists()),
        // a concurrent identical create won the insert: answer like the replay it is
        _ => {
            let existing = load(&state, &principal, record.id).await?;
            return Ok(record_response(StatusCode::OK, &existing, now));
        }
    }
    let entry = load(&state, &principal, record.id).await?;
    audit(&state, &principal, "authorization.created", subject(&entry)).await?;
    let mut verified = subject(&entry);
    verified["kind"] = verification["kind"].clone();
    audit(&state, &principal, "authorization.verified", verified).await?;
    Ok(record_response(StatusCode::CREATED, &entry, now))
}

/// `GET /v1/authorizations/{id}`.
///
/// # Errors
/// `403 scope_missing` without `authorizations:read`, `404 not_found` for an unknown record or a
/// record of another tenant.
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::AuthorizationsRead)?;
    let entry = load(&state, &principal, parse_id(&id)?).await?;
    Ok(record_response(StatusCode::OK, &entry, state.clock.now()))
}

/// `POST /v1/authorizations/{id}/revoke` with an optional `{"reason": "..."}`: revoke the record
/// now. Runs under it stop at their next re-check; new runs are refused at admission. Idempotent:
/// a second call answers with the first revocation and writes no second audit event.
///
/// # Errors
/// `403 scope_missing` without `authorizations:write`, `404 not_found` for an unknown record or a
/// record of another tenant, `422 invalid_request` for a body other than `{}` or `{"reason":
/// string}`.
pub async fn revoke(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::AuthorizationsWrite)?;
    let id = parse_id(&id)?;
    let reason = revoke_reason(&body)?;
    let now = state.clock.now();
    let revoked = state
        .repos
        .api
        .authorization_revoke(principal.tenant, id, principal.key_id, reason.as_deref(), now)
        .await?
        .ok_or_else(|| HttpError::not_found("authorization record"))?;
    if revoked.first {
        audit(
            &state,
            &principal,
            "authorization.revoked",
            subject(&revoked.entry),
        )
        .await?;
    }
    Ok(record_response(StatusCode::OK, &revoked.entry, now))
}

/// The `reason` of a revoke body (`null` and `{}` have none).
fn revoke_reason(body: &Value) -> Result<Option<String>, HttpError> {
    let invalid = |path: &str, code: &str, message: &str| {
        HttpError::invalid_request(vec![Detail::new(path, code, message)])
    };
    let map = match body {
        Value::Null => return Ok(None),
        Value::Object(map) => map,
        _ => return Err(invalid("", "invalid_type", "the body must be a JSON object")),
    };
    if let Some(key) = map.keys().find(|k| k.as_str() != "reason") {
        return Err(invalid(
            &format!("/{key}"),
            "unknown_field",
            &format!("unknown field `{key}`, expected `reason`"),
        ));
    }
    match map.get("reason") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(reason)) if reason.chars().count() <= MAX_REASON_CHARS => Ok(Some(reason.clone())),
        Some(Value::String(_)) => Err(invalid(
            "/reason",
            "out_of_range",
            &format!("reason is longer than {MAX_REASON_CHARS} characters"),
        )),
        Some(_) => Err(invalid("/reason", "invalid_type", "reason must be a string")),
    }
}

/// `POST /v1/authorizations/{id}/verify`: run the ownership check of the stored record again.
/// The body is not touched; on success `verifiedAt` and `verification` are renewed.
///
/// # Errors
/// `403 scope_missing` without `authorizations:write`, `404 not_found` for an unknown record or a
/// record of another tenant, `409 invalid_state` for a revoked record, `422 ownership_unverified`
/// when the proof no longer holds.
pub async fn verify(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::AuthorizationsWrite)?;
    let id = parse_id(&id)?;
    let entry = load(&state, &principal, id).await?;
    if entry.record.revoked_at.is_some() {
        return Err(HttpError::invalid_state(
            "a revoked authorization record cannot be verified again",
        ));
    }
    let now = state.clock.now();
    let verification = prove(&state, &entry.record, now).await?;
    let entry = state
        .repos
        .api
        .authorization_mark_verified(principal.tenant, id, &verification, now)
        .await?
        .ok_or_else(|| HttpError::not_found("authorization record"))?;
    let mut verified = subject(&entry);
    verified["kind"] = verification["kind"].clone();
    audit(&state, &principal, "authorization.verified", verified).await?;
    Ok(record_response(StatusCode::OK, &entry, now))
}
