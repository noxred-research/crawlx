//! Authenticated bounded dataset export import through the existing live request fence.

use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, Params};
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::dataset::import::{commit_import, DatasetImportV1, ImportError};
use crawlx_core::orchestration::RequestCommitV1;
use crawlx_core::repo::FrontierStatus;
use serde_json::json;

/// Apply safe JSON objects to an existing admitted, leased request in the caller's run.
///
/// Query fields `requestId`, `fence`, and `stateVersion` identify operator-owned live work.
/// Neither the export nor the client chooses tenant/run authority, retention, or backend.
/// The existing relational commit checks the supplied live fence again after artifact writes.
///
/// # Errors
/// Returns authentication/scope/tenant, revoked authorization, invalid export/config,
/// expired run, stale fence/state, privacy, retention and storage errors.
pub async fn apply(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(id): Path<String>,
    params: Params,
    body: Bytes,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    if run.status != crawlx_core::counters::RunStatus::Running {
        return Err(HttpError::malformed(
            "dataset import requires a running admitted crawl",
        ));
    }
    if let Some(record) = run.config.safety.authorization_record_ref {
        state
            .repos
            .api
            .authorization_get(principal.tenant, record)
            .await?
            .ok_or_else(|| HttpError::not_found("authorization"))?
            .check_active(state.clock.now())
            .map_err(|_| HttpError::malformed("run authorization is no longer active"))?;
    }
    let request_id = params
        .get("requestId")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|id| *id > 0)
        .ok_or_else(|| HttpError::malformed("positive requestId is required"))?;
    let fence = params
        .get("fence")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|fence| *fence > 0)
        .ok_or_else(|| HttpError::malformed("positive fence is required"))?;
    let version = params
        .get("stateVersion")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|version| *version > 0)
        .ok_or_else(|| HttpError::malformed("positive stateVersion is required"))?;
    let queued = state.repos.frontier.get_request(run.id, request_id).await?;
    if queued.entry.run != run.id
        || queued.entry.status != FrontierStatus::Leased
        || queued.state_version != version
    {
        return Err(crawlx_core::StoreError::Conflict("dataset import request state mismatch".into()).into());
    }
    let import = DatasetImportV1::parse(&body).map_err(import_error)?;
    let report = import.inspect();
    if !report.incompatibilities.is_empty() {
        return Ok(json_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            &json!({"data":report}),
        ));
    }
    let execution_deadline = run
        .started_at
        .unwrap_or(run.created_at)
        .checked_add_signed(chrono::Duration::seconds(i64::from(
            run.config.limits.duration_seconds,
        )))
        .ok_or_else(|| HttpError::malformed("invalid execution deadline"))?;
    let retention_deadline = run
        .created_at
        .checked_add_signed(chrono::Duration::days(i64::from(run.config.retention.days)))
        .ok_or_else(|| HttpError::malformed("invalid retention deadline"))?;
    let deadline = if run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr {
        execution_deadline
    } else {
        execution_deadline.min(retention_deadline)
    };
    if deadline <= state.clock.now() {
        return Err(HttpError::malformed("dataset import deadline expired"));
    }
    let artifacts = state.repos.artifacts.artifact_store().ok_or_else(|| {
        HttpError::backend_unavailable(
            "dataset_import_unavailable",
            "typed dataset artifact sink unavailable",
        )
    })?;
    let commit = RequestCommitV1::terminal(
        run.id,
        request_id,
        fence,
        version,
        FrontierStatus::Succeeded,
        None,
    );
    commit_import(
        import,
        &run.config.datasets,
        commit,
        deadline,
        artifacts,
        state.repos.request_commits.as_ref(),
    )
    .await
    .map_err(import_error)?;
    Ok(json_response(
        StatusCode::OK,
        &json!({"data":{"requestId":request_id,"itemCount":report.item_count,"completeCoverage":false,"possibleOmissions":report.possible_omissions}}),
    ))
}

fn import_error(error: ImportError) -> HttpError {
    match error {
        ImportError::Store(crawlx_core::StoreError::LeaseLost) => {
            HttpError::invalid_state("dataset import request lease lost or fenced")
        }
        ImportError::Store(error) => error.into(),
        _ => HttpError::malformed("invalid or unsupported bounded dataset export"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn only_typed_lease_loss_becomes_import_conflict() {
        let lease = import_error(ImportError::Store(crawlx_core::StoreError::LeaseLost));
        assert_eq!(lease.status, StatusCode::CONFLICT);
        assert_eq!(lease.code, "invalid_state");
        let backend = import_error(ImportError::Store(crawlx_core::StoreError::Backend(
            "test backend failure".into(),
        )));
        assert_eq!(backend.status, StatusCode::INTERNAL_SERVER_ERROR);
        let unavailable = import_error(ImportError::Store(crawlx_core::StoreError::Unavailable(
            "test unavailable".into(),
        )));
        assert_eq!(unavailable.status, StatusCode::SERVICE_UNAVAILABLE);
    }
}
