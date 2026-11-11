//! `GET /v1/crawls/{id}/artifacts/{artifact_id}`.
//!
//! `metadata` and `content` artifacts are served with `crawls:read` (`content` as a `307` to a
//! presigned object-store URL when the backend offers one, 60 s); `sensitive` ones need
//! `artifacts:read_sensitive`, are never presigned and write an audit event; `credential_bearing`
//! artifacts answer `410 artifact_unavailable`. A zero-data-retention run serves only the
//! `content` renditions still in its delivery buffer; everything else is `410`.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, ts, Params};
use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderName, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::Sensitivity;
use crawlx_core::{ArtifactId, ArtifactRef};
use crawlx_storage::PRESIGN_MAX_TTL;
use serde_json::json;

/// `GET /v1/crawls/{id}/artifacts/{artifact_id}`.
///
/// `content` artifacts redirect (`307`, `Cache-Control: private, no-store`) to a presigned URL
/// when the store returns one; otherwise the bytes are streamed. For a zero-data-retention run
/// the only retrievable artifacts are the `content` renditions still in the delivery buffer;
/// they are served from the ephemeral delivery store with the `x-crawlx-sensitivity: content` header
/// and no audit row.
///
/// # Errors
/// `403 scope_missing` without `crawls:read` (or `artifacts:read_sensitive` for sensitive
/// artifacts), `404 not_found` for an unknown run or a run owned by another tenant or artifact,
/// `410 artifact_unavailable` for purged, ZDR or credential-bearing artifacts, `unavailable` when
/// storage fails.
pub async fn artifact(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, artifact_id)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run_metadata(&state, &principal, &id).await?;
    let aid: ArtifactId = artifact_id
        .parse()
        .map_err(|_| HttpError::not_found("artifact"))?;
    if run.retention.mode == RetentionMode::Zdr {
        let blob = state.zdr.find(run.tenant, run.id, aid).await?.ok_or_else(|| {
            HttpError::artifact_unavailable(
                "artifacts of zero-data-retention runs are retrievable only while their page awaits delivery",
            )
        })?;
        return Ok(bytes_response(
            blob.bytes,
            &blob.content_type,
            &blob.artifact.digest.to_hex(),
            Sensitivity::Content,
        ));
    }
    let row = state
        .repos
        .artifacts
        .row(aid)
        .await?
        .filter(|r| r.run == run.id && r.tenant == principal.tenant)
        .ok_or_else(|| HttpError::not_found("artifact"))?;
    match row.sensitivity {
        Sensitivity::CredentialBearing => {
            return Err(HttpError::artifact_unavailable(
                "credential-bearing artifacts are never served",
            ));
        }
        Sensitivity::Sensitive => principal.require(Scope::ArtifactsReadSensitive)?,
        Sensitivity::Metadata | Sensitivity::Content => {}
    }
    if row.expires_at.is_some_and(|e| e <= state.clock.now()) {
        return Err(HttpError::expired("the artifact was purged by retention"));
    }
    if matches!(
        row.content_type.as_str(),
        "application/warc" | "application/wacz+zip" | "application/cdxj"
    ) {
        let reference = ArtifactRef {
            id: row.id,
            digest: row.digest,
        };
        if !state
            .repos
            .archives
            .artifact_visible(principal.tenant, &reference, state.clock.now())
            .await?
        {
            return Err(HttpError::artifact_unavailable(
                "archive is not published or has been erased",
            ));
        }
        if params.get("view") != Some("metadata") {
            let custody = crawlx_core::archive_catalog::ArchiveCustodyV1::new(
                row.sensitivity,
                row.expires_at,
                state.clock.now(),
            )?;
            let stream = state
                .repos
                .artifacts
                .stream_archive(&reference, row.size_bytes, &custody)
                .await?;
            if row.sensitivity == Sensitivity::Sensitive {
                state
                    .repos
                    .api
                    .audit_append(
                        principal.tenant,
                        Some(run.id),
                        &principal.actor(),
                        "artifact.read_sensitive",
                        json!({"artifact_id":row.id,"kind":row.kind}),
                    )
                    .await?;
            }
            let mut response = Response::new(Body::from_stream(stream));
            if let Ok(content_type) = HeaderValue::from_str(&row.content_type) {
                response.headers_mut().insert(header::CONTENT_TYPE, content_type);
            }
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("private, no-store"),
            );
            response.headers_mut().insert(
                HeaderName::from_static("x-crawlx-sensitivity"),
                HeaderValue::from_static(row.sensitivity.as_str()),
            );
            return Ok(response);
        }
    }
    let digest_hex = row.digest.to_hex();
    if params.get("view") == Some("metadata") {
        let body = json!({
            "id": row.id,
            "runId": row.run,
            "kind": row.kind,
            "sizeBytes": row.size_bytes,
            "digest": format!("blake3:{digest_hex}"),
            "contentType": row.content_type,
            "sensitivity": row.sensitivity,
            "createdAt": ts(row.created_at),
            "expiresAt": row.expires_at.map(ts),
        });
        return Ok(json_response(StatusCode::OK, &body));
    }
    let reference = ArtifactRef {
        id: row.id,
        digest: row.digest,
    };
    // `content` goes out as a 307 to a presigned URL when the store has one
    let mut sealed = false;
    if row.sensitivity == Sensitivity::Content {
        match state.repos.artifacts.presign(&reference, PRESIGN_MAX_TTL).await {
            Ok(Some(url)) => {
                if let Ok(location) = HeaderValue::from_str(url.as_str()) {
                    let mut resp = Response::new(Body::empty());
                    *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
                    resp.headers_mut().insert(header::LOCATION, location);
                    resp.headers_mut().insert(
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("private, no-store"),
                    );
                    return Ok(resp);
                }
            }
            Ok(None) => {}
            // A sealed object is ciphertext: a raw URL would hand it out undecrypted.
            Err(crawlx_core::StoreError::AccessDenied(_)) => sealed = true,
            Err(e) => tracing::debug!(error = %e, artifact = %row.id, "presign failed; serving bytes"),
        }
    }
    if sealed {
        // Bounded: authenticated chunks stream out; nothing is buffered whole.
        let stream = state.repos.artifacts.stream(&reference, row.size_bytes).await?;
        let mut resp = Response::new(Body::from_stream(stream));
        let headers = resp.headers_mut();
        if let Ok(value) = HeaderValue::from_str(&row.content_type) {
            headers.insert(header::CONTENT_TYPE, value);
        }
        if let Ok(value) = HeaderValue::from_str(&format!("blake3={digest_hex}")) {
            headers.insert(HeaderName::from_static("digest"), value);
        }
        headers.insert(
            HeaderName::from_static("x-crawlx-sensitivity"),
            HeaderValue::from_static(row.sensitivity.as_str()),
        );
        headers.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        return Ok(resp);
    }
    let bytes = state
        .repos
        .artifacts
        .read(&reference)
        .await
        .map_err(|e| match e {
            crawlx_core::StoreError::NotFound { .. } => {
                HttpError::expired("the artifact was purged by retention")
            }
            other => other.into(),
        })?;
    if row.sensitivity == Sensitivity::Sensitive {
        state
            .repos
            .api
            .audit_append(
                principal.tenant,
                Some(run.id),
                &principal.actor(),
                "artifact.read_sensitive",
                json!({ "artifact_id": row.id, "kind": row.kind }),
            )
            .await?;
    }
    Ok(bytes_response(
        bytes,
        &row.content_type,
        &digest_hex,
        row.sensitivity,
    ))
}

fn bytes_response(
    bytes: Vec<u8>,
    content_type: &str,
    digest_hex: &str,
    sensitivity: Sensitivity,
) -> Response {
    let mut resp = Response::new(Body::from(bytes));
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(content_type) {
        h.insert(header::CONTENT_TYPE, v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("blake3={digest_hex}")) {
        h.insert(HeaderName::from_static("digest"), v);
    }
    h.insert(
        HeaderName::from_static("x-crawlx-sensitivity"),
        HeaderValue::from_static(sensitivity.as_str()),
    );
    resp
}
