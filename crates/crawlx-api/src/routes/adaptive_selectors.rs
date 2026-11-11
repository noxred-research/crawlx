//! Authenticated structural descriptor capture and offline relocation over retained page HTML.
//! Scope authority comes from the caller and source run, never from a submitted descriptor.
use crate::auth::Principal;
use crate::errors::{ApiResult, HttpError};
use crate::routes::crawls::load_run;
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use crawlx_core::cache::AdaptiveSelectorRecordV1;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::{CrawlRun, PageRecord};
use crawlx_core::selectors::SelectorScopeV1;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Capture {
    page: i64,
    node: usize,
    source: String,
    schema: String,
    #[serde(default)]
    expires_at: Option<crawlx_core::Timestamp>,
    #[serde(default)]
    threshold: Option<u16>,
    #[serde(default)]
    runner_up_margin: Option<u16>,
    #[serde(default)]
    max_candidates: Option<usize>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Relocate {
    page: i64,
    source: String,
    schema: String,
}
fn invalid(error: impl std::fmt::Display) -> HttpError {
    HttpError::malformed(error.to_string())
}

async fn page(state: &AppState, run: &CrawlRun, id: i64) -> ApiResult<PageRecord> {
    state
        .repos
        .pages
        .get_committed(run.id, id)
        .await?
        .ok_or_else(|| HttpError::not_found("page"))
}
fn scope(
    principal: &Principal,
    page: &PageRecord,
    source: String,
    schema: String,
) -> ApiResult<SelectorScopeV1> {
    let acquired = page
        .metadata
        .get("final_url")
        .and_then(serde_json::Value::as_str)
        .or_else(|| page.metadata.get("acquisition")?.get("finalUrl")?.as_str())
        .ok_or_else(|| invalid("acquired origin evidence unavailable"))?;
    let acquired = url::Url::parse(acquired).map_err(invalid)?;
    if !matches!(acquired.scheme(), "http" | "https") || acquired.host_str().is_none() {
        return Err(invalid("acquired origin is not an HTTP origin"));
    }
    let scope = SelectorScopeV1::new(
        principal.tenant.to_string(),
        principal.key_id.to_string(),
        acquired.origin().ascii_serialization(),
        source,
        schema,
    );
    scope.validate().map_err(invalid)?;
    Ok(scope)
}
fn cpu() -> &'static crawlx_worker::CpuPool {
    static CPU: std::sync::LazyLock<crawlx_worker::CpuPool> =
        std::sync::LazyLock::new(|| crawlx_worker::CpuPool::with_permits(std::num::NonZeroUsize::MIN));
    &CPU
}
async fn html(
    state: &AppState,
    principal: &Principal,
    run: &CrawlRun,
    page: &PageRecord,
) -> ApiResult<String> {
    const MAX_BYTES: usize = 8 * 1024 * 1024;
    let artifact = page.html.as_ref().ok_or_else(|| {
        HttpError::compat(
            StatusCode::GONE,
            "STORED_BODY_UNAVAILABLE",
            "Retained HTML is unavailable",
        )
    })?;
    let bytes = if run.config.retention.mode == RetentionMode::Zdr {
        state
            .zdr
            .read_for_run_limited(principal.tenant, run.id, artifact, MAX_BYTES)
            .await?
            .ok_or_else(|| HttpError::artifact_unavailable("volatile HTML expired"))?
            .bytes
    } else {
        let row = state
            .repos
            .artifacts
            .row(artifact.id)
            .await?
            .filter(|r| r.tenant == principal.tenant && r.run == run.id && r.digest == artifact.digest)
            .ok_or_else(|| HttpError::not_found("artifact"))?;
        match row.sensitivity {
            crawlx_core::repo::Sensitivity::CredentialBearing => {
                return Err(HttpError::artifact_unavailable(
                    "credential-bearing HTML cannot be used",
                ));
            }
            crawlx_core::repo::Sensitivity::Sensitive => principal.require(Scope::ArtifactsReadSensitive)?,
            _ => {}
        }
        if row.expires_at.is_some_and(|end| end <= state.clock.now()) {
            return Err(HttpError::expired("HTML retention expired"));
        }
        if row.size_bytes > u64::try_from(MAX_BYTES).unwrap_or(u64::MAX) {
            return Err(invalid("retained selector HTML exceeds 8 MiB"));
        }
        state
            .repos
            .artifacts
            .read_limited(artifact, u64::try_from(MAX_BYTES).unwrap_or(u64::MAX))
            .await?
    };
    String::from_utf8(bytes).map_err(invalid)
}

/// Capture a sanitized descriptor from retained HTML, then save under fixed source retention.
/// # Errors
/// Returns scope/ownership, missing-body, invalid-node, retention or repository errors.
pub async fn put(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, selector_id)): Path<(String, String)>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let run = load_run(&state, &principal, &id).await?;
    let input: Capture = serde_json::from_value(body).map_err(invalid)?;
    let page = page(&state, &run, input.page).await?;
    let scope = scope(&principal, &page, input.source, input.schema)?;
    let html = html(&state, &principal, &run, &page).await?;
    let mut spec = cpu()
        .run(move || crawlx_extract::adaptive_selector::capture_html(&html, input.node, selector_id, scope))
        .await
        .map_err(invalid)?
        .map_err(invalid)?;
    if let Some(value) = input.threshold {
        spec.threshold = value;
    }
    if let Some(value) = input.runner_up_margin {
        spec.runner_up_margin = value;
    }
    if let Some(value) = input.max_candidates {
        spec.max_candidates = value;
    }
    spec.validate().map_err(invalid)?;
    let horizon = run.created_at
        + if run.config.retention.mode == RetentionMode::Zdr {
            chrono::Duration::hours(1)
        } else {
            chrono::Duration::days(i64::from(run.config.retention.days))
        };
    let record = AdaptiveSelectorRecordV1::new(run.id, spec, input.expires_at.unwrap_or(horizon));
    state.repos.adaptive_selectors.put(&record).await?;
    // Read back the fixed deadline: neither replacement nor volatile insertion may renew it.
    let saved = state
        .repos
        .adaptive_selectors
        .get(&record.spec.scope, &record.spec.selector_id, state.clock.now())
        .await?
        .ok_or_else(|| {
            HttpError::compat(StatusCode::GONE, "SELECTOR_EXPIRED", "Selector retention expired")
        })?;
    Ok(json_response(StatusCode::OK, &json!({"data":saved})))
}

/// Read a descriptor in the exact authenticated origin/source/schema namespace.
/// # Errors
/// Returns scope, ownership, malformed query or storage errors.
pub async fn get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, selector_id)): Path<(String, String)>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let page_id = params
        .get("page")
        .ok_or_else(|| invalid("page is required"))?
        .parse::<i64>()
        .map_err(invalid)?;
    let page = page(&state, &run, page_id).await?;
    let source = params
        .get("source")
        .ok_or_else(|| invalid("source is required"))?
        .to_owned();
    let schema = params
        .get("schema")
        .ok_or_else(|| invalid("schema is required"))?
        .to_owned();
    let scope = scope(&principal, &page, source, schema)?;
    let record = state
        .repos
        .adaptive_selectors
        .get(&scope, &selector_id, state.clock.now())
        .await?
        .ok_or_else(|| HttpError::not_found("adaptive_selector"))?;
    Ok(json_response(StatusCode::OK, &json!({"data":record})))
}

/// Relocate a stored descriptor within retained HTML. Ambiguity never emits a selected node.
/// # Errors
/// Returns scope, ownership, missing-body, bounded-evaluation or storage errors.
pub async fn relocate(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path((id, selector_id)): Path<(String, String)>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsRead)?;
    let run = load_run(&state, &principal, &id).await?;
    let input: Relocate = serde_json::from_value(body).map_err(invalid)?;
    let page = page(&state, &run, input.page).await?;
    let scope = scope(&principal, &page, input.source, input.schema)?;
    let record = state
        .repos
        .adaptive_selectors
        .get(&scope, &selector_id, state.clock.now())
        .await?
        .ok_or_else(|| HttpError::not_found("adaptive_selector"))?;
    let html = html(&state, &principal, &run, &page).await?;
    let outcome = cpu()
        .run(move || crawlx_extract::adaptive_selector::relocate_html(&html, &record.spec, &scope))
        .await
        .map_err(invalid)?
        .map_err(invalid)?;
    use crawlx_extract::adaptive_selector::RelocationOutcome;
    let result = match outcome {
        RelocationOutcome::Recovered { node, score } => {
            json!({"outcome":"recovered","node":node,"score":score})
        }
        RelocationOutcome::Ambiguous { best, runner_up } => {
            json!({"outcome":"ambiguous","best":best,"runnerUp":runner_up})
        }
        RelocationOutcome::NotFound => json!({"outcome":"not_found"}),
        _ => return Err(invalid("unsupported relocation outcome")),
    };
    Ok(json_response(
        StatusCode::OK,
        &json!({"data":result,"networkRequests":0}),
    ))
}
