//! Native uploads of immutable recorded login flows on existing source runs.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::routes::crawls::load_run_metadata;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::json_response;
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::config::RetentionMode;
use crawlx_core::secret::Redactor;
use serde::Deserialize;
use serde_json::json;

const MAX_FLOW_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Upload {
    flow: String,
}

fn invalid_flow() -> HttpError {
    HttpError::validation(vec![Detail::new(
        "/flow",
        "invalid_login_flow",
        "flow must be a supported recorded login flow without literal credentials or secrets",
    )])
}

/// `POST /v1/crawls/{id}/login-flows`.
///
/// Stores exact approved source bytes without changing any accepted crawl configuration.
/// The returned descriptor is an identifier, not authority to read across tenant boundaries.
///
/// # Errors
/// Requires both `crawls:write` and `crawls:read`; returns 404 for absent or foreign source
/// runs, 409 for ZDR, 410 for expired sources, 413 for either byte bound, and 400/422 for
/// malformed bodies or invalid/secret-bearing flows. Storage errors propagate.
pub async fn create(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    principal.require(Scope::CrawlsRead)?;
    let source = load_run_metadata(&state, &principal, &id).await?;
    if source.retention.mode == RetentionMode::Zdr {
        return Err(HttpError::invalid_state(
            "recorded login flows require a retained source run",
        ));
    }
    let deadline = source
        .created_at
        .checked_add_signed(chrono::Duration::days(i64::from(source.retention.days)))
        .ok_or_else(HttpError::internal)?;
    if deadline <= state.clock.now() {
        return Err(HttpError::expired("source run expired"));
    }
    let limit = state.settings.max_body_bytes;
    let body = axum::body::to_bytes(request.into_body(), limit)
        .await
        .map_err(|_| HttpError::payload_too_large(limit))?;
    // Deserialize directly, not through Value: duplicate members must not be collapsed.
    let upload: Upload = serde_json::from_slice(&body)
        .map_err(|_| HttpError::malformed("expected exactly one string field: flow"))?;
    if upload.flow.len() > MAX_FLOW_BYTES {
        return Err(HttpError::payload_too_large(MAX_FLOW_BYTES));
    }
    crawlx_worker::login::validate_recorded_login_flow(upload.flow.as_bytes()).map_err(|_| invalid_flow())?;
    // Shared canonical/global secret policy remains authoritative. Never sanitize an upload
    // into a different executable flow, or create a new unchecked approval token.
    let approved = Redactor::new()
        .verify_canonical_owned(upload.flow.into_bytes())
        .map_err(|_| invalid_flow())?;
    let artifact = state
        .repos
        .artifacts
        .put_login_flow(source.id, &approved, deadline)
        .await?;
    let row = state
        .repos
        .artifacts
        .row(artifact.id)
        .await?
        .ok_or_else(HttpError::internal)?;
    let descriptor = json!({
        "tenant": source.tenant,
        "run": source.id,
        "sensitivity": "content",
        "artifact": artifact,
    });
    let login_plan = format!("recorded:artifact://{descriptor}");
    state
        .repos
        .api
        .audit_append(
            principal.tenant,
            Some(source.id),
            &principal.actor(),
            "login_flow.uploaded",
            json!({"source_run": source.id, "artifact_id": artifact.id, "digest": artifact.digest}),
        )
        .await?;
    Ok(json_response(
        StatusCode::CREATED,
        &json!({"artifact": artifact, "loginPlan": login_plan, "expiresAt": row.expires_at}),
    ))
}

/// Resolve artifact references while the API principal is still available. Worker execution
/// repeats these checks because retention, source erasure and object bytes can change later.
pub(crate) async fn validate_references(
    state: &AppState,
    principal: &Principal,
    crawl: &crawlx_core::config::CreateCrawl,
) -> ApiResult<()> {
    for plan in crawl.roles.iter().filter_map(|role| role.login_plan.as_deref()) {
        let Some((tenant, source_id, artifact)) =
            crawlx_worker::login::parse_recorded_login_artifact(plan).map_err(|_| invalid_flow())?
        else {
            continue;
        };
        principal.require(Scope::CrawlsRead)?;
        if tenant != principal.tenant {
            return Err(HttpError::not_found("crawl"));
        }
        let source = load_run_metadata(state, principal, &source_id.to_string()).await?;
        if source.retention.mode == RetentionMode::Zdr {
            return Err(HttpError::invalid_state(
                "recorded login flows require a retained source run",
            ));
        }
        let deadline = source
            .created_at
            .checked_add_signed(chrono::Duration::days(i64::from(source.retention.days)))
            .ok_or_else(HttpError::internal)?;
        if deadline <= state.clock.now() {
            return Err(HttpError::expired("source run expired"));
        }
        let row = state
            .repos
            .artifacts
            .row(artifact.id)
            .await?
            .filter(|row| {
                row.run == source_id
                    && row.tenant == principal.tenant
                    && row.digest == artifact.digest
                    && row.sensitivity == crawlx_core::repo::Sensitivity::Content
            })
            .ok_or_else(|| HttpError::not_found("artifact"))?;
        if row.expires_at.is_some_and(|expiry| expiry <= state.clock.now()) {
            return Err(HttpError::expired("recorded login artifact expired"));
        }
        let max_bytes = crawlx_worker::login::MAX_RECORDED_ARTIFACT_BYTES;
        if row.size_bytes > max_bytes {
            return Err(HttpError::payload_too_large(MAX_FLOW_BYTES));
        }
        let bytes = state
            .repos
            .artifacts
            .read_limited(&artifact, max_bytes)
            .await
            .map_err(|_| invalid_flow())?;
        crawlx_worker::login::validate_recorded_login_flow(&bytes).map_err(|_| invalid_flow())?;
        Redactor::new()
            .check_canonical(&bytes)
            .map_err(|_| invalid_flow())?;
    }
    Ok(())
}
