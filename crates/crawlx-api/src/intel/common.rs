//! Plumbing shared by the routes of the LLM products: backend accessors that answer a typed
//! `503` when the operator has not configured the backend, and the mapping of backend failures
//! to the compat error envelope.

use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::search::{SearchError, SearchProvider};
use crate::intel::tools::{PageTools, ToolError};
use crate::state::AppState;
use axum::http::StatusCode;
use crawlx_core::TenantId;
use crawlx_model::llm::{LlmError, LlmExtractor};
use std::sync::Arc;
use uuid::Uuid;

/// Hours extract and agent results stay readable (`expiresAt`).
pub const JOB_TTL_HOURS: i64 = 24;

/// The document LLM.
///
/// # Errors
/// `503 llm_not_configured` without `llm{endpoint, model}` settings (or `CRAWLX_LLM_BASE_URL`).
pub fn llm(state: &AppState) -> ApiResult<Arc<dyn LlmExtractor>> {
    state.llm.clone().ok_or_else(|| {
        HttpError::backend_unavailable(
            "llm_not_configured",
            "no LLM endpoint is configured; set intel.llm or CRAWLX_LLM_BASE_URL / CRAWLX_LLM_MODEL / CRAWLX_LLM_API_KEY",
        )
    })
}

/// The LLM of the extraction step (`/extract`) for `tenant` over `input_bytes` of page text: the
/// extraction provider when `EXTRACTION_PROVIDER_*` routes the tenant to it (with the default LLM
/// as the fallback), the default LLM otherwise.
///
/// # Errors
/// `503 llm_not_configured` without a default LLM, as [`llm`].
pub fn extraction_llm(
    state: &AppState,
    tenant: TenantId,
    input_bytes: usize,
) -> ApiResult<Arc<dyn LlmExtractor>> {
    let default = llm(state)?;
    Ok(match &state.extraction {
        Some(router) => router.select(&tenant.to_string(), false, input_bytes),
        None => default,
    })
}

/// The search backend.
///
/// # Errors
/// `503 search_not_configured` without `intel.search` settings (or `CRAWLX_SEARCH_ENDPOINT` /
/// `CRAWLX_SEARCH_API_KEY`).
pub fn search(state: &AppState) -> ApiResult<Arc<dyn SearchProvider>> {
    state.search.clone().ok_or_else(|| {
        HttpError::backend_unavailable(
            "search_not_configured",
            "no search backend is configured; set intel.search or CRAWLX_SEARCH_ENDPOINT / CRAWLX_SEARCH_API_KEY",
        )
    })
}

/// The scrape and map tools: the injected ones (tests, embedders) or the facade's scrape service.
///
/// # Errors
/// None today; the `Result` keeps call sites stable for a deployment without a scrape service.
pub fn tools(state: &AppState) -> ApiResult<Arc<dyn PageTools>> {
    Ok(state
        .tools
        .clone()
        .unwrap_or_else(|| Arc::new(crate::intel::tools::ServiceTools::new(state.clone()))))
}

/// Map an LLM failure to the response the caller sees.
#[must_use]
pub fn llm_error(e: &LlmError) -> HttpError {
    match e {
        LlmError::NotConfigured => HttpError::backend_unavailable("llm_not_configured", e.to_string()),
        LlmError::Timeout { .. } => {
            HttpError::compat(StatusCode::GATEWAY_TIMEOUT, "llm_timeout", e.to_string())
        }
        LlmError::Transport(_) | LlmError::Status { .. } => {
            HttpError::compat(StatusCode::BAD_GATEWAY, "llm_unavailable", e.to_string())
        }
        LlmError::InvalidOutput(_) => {
            HttpError::compat(StatusCode::BAD_GATEWAY, "llm_invalid_output", e.to_string())
        }
        LlmError::InvalidRequest(m) => HttpError::validation(vec![Detail::new("/", "invalid", m.clone())]),
        _ => HttpError::compat(StatusCode::BAD_GATEWAY, "llm_failed", e.to_string()),
    }
}

/// Map a search-provider failure to the response the caller sees.
#[must_use]
pub fn search_error(e: &SearchError) -> HttpError {
    match e {
        SearchError::Timeout { .. } => {
            HttpError::compat(StatusCode::GATEWAY_TIMEOUT, "search_timeout", e.to_string())
        }
        _ => HttpError::compat(StatusCode::BAD_GATEWAY, "search_unavailable", e.to_string()),
    }
}

/// Map a page-tool failure to the response the caller sees.
#[must_use]
pub fn tool_error(e: &ToolError) -> HttpError {
    match e {
        ToolError::Invalid(m) => {
            HttpError::validation(vec![Detail::new("/scrapeOptions", "invalid", m.clone())])
        }
        _ => HttpError::compat(StatusCode::BAD_GATEWAY, "scrape_failed", e.to_string()),
    }
}

/// Parse a path id; an unparsable id is a `404` like an unknown one.
///
/// # Errors
/// `404 not_found` naming `what`.
pub fn parse_id(text: &str, what: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(text).map_err(|_| HttpError::not_found(what))
}

/// A short human message for a job failure recorded on the job row.
#[must_use]
pub fn failure_text(e: &HttpError) -> String {
    e.message.clone()
}
