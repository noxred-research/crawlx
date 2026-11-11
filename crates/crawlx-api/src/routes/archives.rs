//! Authenticated retained archive catalog, bounded progress, streamed export and cascading erase.
//! Sensitive byte and record projections require `artifacts:read_sensitive`; ordinary progress
//! stays visible without exposing the sensitive manifest or byte references.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, Params};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::archive::ArchiveFormat;
use crawlx_core::archive_catalog::{ArchiveExportState, ArchiveExportV1, ArchiveReadV1};
use crawlx_core::config::RetentionMode;
use serde_json::json;
use uuid::Uuid;

fn require_bytes(principal: &Principal, row: &ArchiveExportV1) -> ApiResult<()> {
    if row.custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive {
        principal.require(Scope::ArtifactsReadSensitive)?;
    }
    Ok(())
}

async fn progress(
    state: &AppState,
    principal: &Principal,
    row: &ArchiveExportV1,
) -> ApiResult<serde_json::Value> {
    let mut body = value(row)?;
    let sensitive = row.custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive;
    let authorized = !sensitive || principal.require(Scope::ArtifactsReadSensitive).is_ok();
    let source_live = if sensitive && authorized && row.state == ArchiveExportState::Published {
        match &row.artifact {
            Some(artifact) => {
                state
                    .repos
                    .archives
                    .artifact_visible(principal.tenant, artifact, state.clock.now())
                    .await?
            }
            None => false,
        }
    } else {
        true
    };
    if sensitive && (!authorized || !source_live) {
        // Progress remains visible; content-bearing capture metadata and byte references do not.
        body["manifest"] = serde_json::Value::Null;
        body["artifact"] = serde_json::Value::Null;
        body["index"] = serde_json::Value::Null;
    }
    Ok(body)
}

fn value<T: serde::Serialize>(body: &T) -> ApiResult<serde_json::Value> {
    serde_json::to_value(body)
        .map_err(|error| crawlx_core::StoreError::Serialization(error.to_string()).into())
}
async fn load(
    state: &AppState,
    principal: &Principal,
    id: &str,
    export_id: &str,
) -> ApiResult<ArchiveExportV1> {
    let run = load_run_metadata(state, principal, id).await?;
    if run.retention.mode == RetentionMode::Zdr {
        return Err(HttpError::artifact_unavailable(
            "durable archives are unavailable for zero-data-retention runs",
        ));
    }
    let export_id: Uuid = export_id.parse().map_err(|_| HttpError::not_found("archive"))?;
    match state
        .repos
        .archives
        .get(principal.tenant, export_id, state.clock.now())
        .await?
    {
        ArchiveReadV1::Available(row) if row.run == run.id => Ok(*row),
        ArchiveReadV1::Expired if export_id == run.id.0 => {
            Err(HttpError::expired("archive source retention expired"))
        }
        _ => Err(HttpError::not_found("archive")),
    }
}

/// List retained archive finalization progress. Requires `crawls:read`.
///
/// # Errors
/// Returns typed tenant/not-found, scope or storage failures.
pub async fn list(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let rows = state
        .repos
        .archives
        .list(principal.tenant, run.id, state.clock.now())
        .await?;
    let mut visible = Vec::with_capacity(rows.len());
    for row in &rows {
        visible.push(progress(&state, &principal, row).await?);
    }
    Ok(json_response(StatusCode::OK, &json!({"archives":visible})))
}

/// Read an export's progress or published manifest, never a speculative download URL.
///
/// # Errors
/// Returns 404 for foreign/deleted exports, 410 for expired sources, or storage/scope errors.
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, export_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let row = load(&state, &principal, &id, &export_id).await?;
    Ok(json_response(
        StatusCode::OK,
        &progress(&state, &principal, &row).await?,
    ))
}

/// Bounded committed-record projection. Accepts `after` ordinal and `limit` 1..64.
///
/// # Errors
/// Returns catalog, scope, expiry or invalid cursor errors.
pub async fn records(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, export_id)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let row = load(&state, &principal, &id, &export_id).await?;
    require_bytes(&principal, &row)?;
    if row.custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive
        && row.state == ArchiveExportState::Published
    {
        let artifact = row
            .artifact
            .as_ref()
            .ok_or_else(|| HttpError::expired("archive source is unavailable"))?;
        if !state
            .repos
            .archives
            .artifact_visible(principal.tenant, artifact, state.clock.now())
            .await?
        {
            return Err(HttpError::expired("archive source is unavailable"));
        }
    }
    let after = params
        .get("after")
        .map(str::parse::<u64>)
        .transpose()
        .map_err(|_| HttpError::invalid_state("archive cursor must be an unsigned ordinal"))?;
    if after.is_some_and(|ordinal| i64::try_from(ordinal).is_err()) {
        return Err(HttpError::invalid_state(
            "archive cursor exceeds the supported ordinal range",
        ));
    }
    let limit = params
        .get("limit")
        .map(str::parse::<u32>)
        .transpose()
        .map_err(|_| HttpError::invalid_state("archive record limit must be 1..64"))?
        .unwrap_or(64);
    if !(1..=64).contains(&limit) {
        return Err(HttpError::invalid_state("archive record limit must be 1..64"));
    }
    let records = state
        .repos
        .archives
        .records(principal.tenant, row.id, after, limit, state.clock.now())
        .await?;
    let next = records.last().map(|record| record.ordinal);
    Ok(json_response(
        StatusCode::OK,
        &json!({"records":records,"next":next}),
    ))
}

/// Stream only a published, retained archive. No full-archive body allocation or live fetch.
///
/// # Errors
/// Returns 409 while recording, 410 after expiry, 404 for foreign/deleted exports, or storage failures.
pub async fn export(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, export_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let row = load(&state, &principal, &id, &export_id).await?;
    require_bytes(&principal, &row)?;
    row.custody.validate(state.clock.now())?;
    if row.state != ArchiveExportState::Published {
        return Err(HttpError::invalid_state("archive manifest is not published"));
    }
    let artifact = row
        .artifact
        .as_ref()
        .ok_or_else(|| HttpError::artifact_unavailable("published archive object missing"))?;
    if !state
        .repos
        .archives
        .artifact_visible(principal.tenant, artifact, state.clock.now())
        .await?
    {
        return Err(HttpError::expired("archive dependency or source is unavailable"));
    }
    let stream = if row.custody.sensitivity == crawlx_core::repo::Sensitivity::Content {
        state
            .repos
            .artifacts
            .stream(artifact, row.config.max_bytes)
            .await?
    } else {
        state
            .repos
            .artifacts
            .stream_archive(artifact, row.config.max_bytes, &row.custody)
            .await?
    };
    if row.custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive {
        state
            .repos
            .api
            .audit_append(
                principal.tenant,
                Some(row.run),
                &principal.actor(),
                "artifact.read_sensitive",
                json!({"artifact_id":artifact.id,"kind":"archive"}),
            )
            .await?;
    }
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(if row.config.format == ArchiveFormat::Warc {
            "application/warc"
        } else {
            "application/wacz+zip"
        }),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        axum::http::HeaderName::from_static("x-crawlx-sensitivity"),
        HeaderValue::from_static(row.custody.sensitivity.as_str()),
    );
    let extension = if row.config.format == ArchiveFormat::Warc {
        "warc.gz"
    } else {
        "wacz"
    };
    let disposition = format!("attachment; filename=\"crawlx-archive-{}.{extension}\"", row.id);
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition)
            .map_err(|error| crawlx_core::StoreError::Serialization(error.to_string()))?,
    );
    Ok(response)
}

/// Tombstone an export and all transitive dependents, then erase artifacts in bounded batches.
/// Retrying the same endpoint resumes physical cleanup after an object-store failure.
///
/// # Errors
/// Returns scope/tenant errors or a physical erasure error. No erased export stays readable.
pub async fn erase(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, export_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let export: Uuid = export_id.parse().map_err(|_| HttpError::not_found("archive"))?;
    if export != run.id.0 {
        return Err(HttpError::not_found("archive"));
    }
    crate::store::erase_archives(
        state.repos.archives.as_ref(),
        state.repos.artifacts.as_ref(),
        principal.tenant,
        export,
    )
    .await?;
    state
        .repos
        .api
        .audit_append(
            principal.tenant,
            Some(run.id),
            &principal.actor(),
            "archive.erase",
            json!({"exportId":export,"dependentPolicy":"erase"}),
        )
        .await?;
    Ok(json_response(
        StatusCode::OK,
        &json!({"id":export,"deleted":true}),
    ))
}
