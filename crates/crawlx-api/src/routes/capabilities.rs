//! Authenticated, bounded worker capability snapshots.
//!
//! A fresh registry heartbeat is reported evidence, not a promise of future worker health.
//! Only the worker probes its browser; this API endpoint never launches one.

use crate::auth::Principal;
use crate::errors::ApiResult;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::json_response;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use serde_json::json;
use std::time::Duration;

/// Maximum age of a worker report considered for native capability admission.
pub(crate) const WORKER_MAX_AGE: Duration = Duration::from_secs(90);

/// Return bounded fresh worker-reported acquisition capabilities.
///
/// # Errors
/// Returns `403 scope_missing` without `crawls:read`, or a registry storage error.
pub async fn acquisition(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let mut workers = state
        .repos
        .worker_registry
        .live_acquisition_workers(WORKER_MAX_AGE)
        .await?;
    let truncated = workers.len() > 256;
    workers.truncate(256);
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "schemaVersion": 1,
            "scope": "live_worker_registry",
            "observedAt": state.clock.now(),
            "maxWorkerAgeMs": WORKER_MAX_AGE.as_millis(),
            "maxWorkers": 256,
            "truncated": truncated,
            "workers": workers,
        }),
    ))
}
