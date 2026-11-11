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
use crawlx_core::page_op::{DeviceMatrixV1, DevicePreset};
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
    let workers = serde_json::to_value(&workers).unwrap_or_default();
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "schemaVersion": 1,
            "scope": "live_worker_registry",
            "observedAt": state.clock.now(),
            "maxWorkerAgeMs": WORKER_MAX_AGE.as_millis(),
            "maxWorkers": 256,
            "truncated": truncated,
            "devices": device_summary(&workers),
            "workers": workers,
        }),
    ))
}

/// What the device presets mean and how many reporting workers measured them: the preset
/// catalogue, and the number of fresh workers whose browser capability carries a measured
/// matrix (`backends[].deviceMatrix`) and of those whose every row is coherent. The measured
/// values themselves stay with the worker that measured them; the matrix makes no stealth or
/// detection-evasion claim.
fn device_summary(workers: &serde_json::Value) -> serde_json::Value {
    let presets: Vec<serde_json::Value> = DevicePreset::ALL
        .iter()
        .map(|preset| {
            let emulation = preset.emulation("0", "en-US");
            json!({
                "preset": preset,
                "viewport": emulation.viewport.map(|(width, height)| json!({ "width": width, "height": height })),
                "deviceScaleFactorMilli": emulation.device_scale_milli,
                "mobile": emulation.mobile,
            })
        })
        .collect();
    let matrices: Vec<&serde_json::Value> = workers
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|worker| worker.get("backends")?.as_array())
        .flatten()
        .filter(|backend| {
            backend.get("backendId").and_then(serde_json::Value::as_str) == Some("native_browser")
        })
        .filter_map(|backend| backend.get("deviceMatrix"))
        .filter(|matrix| matrix.is_object())
        .collect();
    let coherent = matrices
        .iter()
        .filter(|matrix| {
            matrix
                .get("entries")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|rows| {
                    !rows.is_empty()
                        && rows
                            .iter()
                            .all(|row| row.get("coherent").and_then(serde_json::Value::as_bool) == Some(true))
                })
        })
        .count();
    json!({
        "matrixVersion": DeviceMatrixV1::VERSION,
        "stealthClaim": false,
        "presets": presets,
        "measuredWorkers": matrices.len(),
        "coherentWorkers": coherent,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn worker(matrix: Option<serde_json::Value>) -> serde_json::Value {
        let mut browser = json!({ "backendId": "native_browser", "available": true });
        if let Some(matrix) = matrix {
            browser["deviceMatrix"] = matrix;
        }
        json!({ "backends": [{ "backendId": "native_http" }, browser] })
    }

    #[test]
    fn the_summary_lists_the_presets_and_counts_only_measured_coherent_workers() {
        let coherent = json!({ "entries": [{ "coherent": true }, { "coherent": true }] });
        let broken = json!({ "entries": [{ "coherent": true }, { "coherent": false }] });
        let empty = json!({ "entries": [] });
        let summary = device_summary(&json!([
            worker(Some(coherent)),
            worker(Some(broken)),
            worker(Some(empty)),
            worker(None),
        ]));
        assert_eq!(summary["stealthClaim"], json!(false));
        assert_eq!(summary["measuredWorkers"], json!(3));
        assert_eq!(summary["coherentWorkers"], json!(1));
        let names: Vec<_> = summary["presets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["preset"].clone())
            .collect();
        assert_eq!(names, [json!("desktop"), json!("phone"), json!("tablet")]);
        assert_eq!(
            summary["presets"][1]["viewport"],
            json!({ "width": 412, "height": 915 })
        );
        assert_eq!(summary["presets"][1]["deviceScaleFactorMilli"], json!(2625));
        assert_eq!(summary["presets"][1]["mobile"], json!(true));
    }

    #[test]
    fn no_workers_means_no_measurements_but_the_catalogue_is_still_documented() {
        let summary = device_summary(&json!([]));
        assert_eq!(summary["measuredWorkers"], json!(0));
        assert_eq!(summary["coherentWorkers"], json!(0));
        assert_eq!(summary["presets"].as_array().unwrap().len(), 3);
    }
}
