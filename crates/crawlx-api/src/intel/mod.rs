//! Services behind the compatibility-API LLM products: the search provider seam
//! ([`search`]), the page tools seam over the scrape engine ([`tools`]), usage accounting
//! ([`usage`]), job admission and background execution ([`jobs`]), job webhooks ([`webhook`]), embedding ranking of the pages
//! `/extract` reads ([`rank`]) and shared route plumbing ([`common`]).
//!
//! The routes live in `routes/compat_{search,extract,agent,parse,monitor,team}.rs`; this module
//! holds what they share.

pub mod agent;
pub mod agent_spec;
pub mod agent_view;
pub mod common;
pub mod docs_search;
pub mod exchange;
pub mod extract;
pub mod feedback;
pub mod indexes;
pub mod jobs;
pub mod metasearch;
pub mod monitor;
pub mod rank;
pub mod request;
pub mod search;
pub mod search_http;
pub mod serp;
pub mod tools;
pub mod usage;
pub mod webhook;
pub mod zdr_vault;

use crate::config::IntelConfig;
use crate::errors::ApiError;
use crawlx_model::llm::{
    ChatCompletionsClient, EmbeddingsClient, ExtractionRouter, HttpEmbeddings, LlmExtractor,
};
use rank::PageRanker;
use search::SearchProvider;
use std::sync::Arc;

/// What an [`IntelConfig`] configures in the API process.
#[derive(Default)]
#[non_exhaustive]
pub struct Backends {
    /// The default document LLM.
    pub llm: Option<Arc<dyn LlmExtractor>>,
    /// The search provider.
    pub search: Option<Arc<dyn SearchProvider>>,
    /// Router of the `/extract` LLM step between the default model and the extraction provider
    /// (`EXTRACTION_PROVIDER_*`).
    pub extraction: Option<Arc<ExtractionRouter>>,
    /// Embedding ranking of the pages `/extract` reads (`CRAWLX_EMBEDDING_MODEL`).
    pub embeddings: Option<Arc<PageRanker>>,
}

/// What an [`IntelConfig`] configures in a worker process: the LLM steps of the scrape formats.
#[derive(Default)]
#[non_exhaustive]
pub struct WorkerLlm {
    /// The default document LLM (`summary`, `question`, `highlights`, `query`, change tracking).
    pub llm: Option<Arc<dyn LlmExtractor>>,
    /// Router of the `json` format between the default model and the extraction provider.
    pub extraction: Option<Arc<ExtractionRouter>>,
    /// The LLM that refines the `branding` profile (`BRANDING_LLM_*`).
    pub branding: Option<Arc<dyn LlmExtractor>>,
}

fn default_llm(cfg: &IntelConfig) -> Result<Option<Arc<dyn LlmExtractor>>, ApiError> {
    let Some(settings) = &cfg.llm else {
        return Ok(None);
    };
    let resolved = settings
        .resolve()
        .map_err(|e| ApiError::Config(format!("intel.llm: {e}")))?;
    let client =
        ChatCompletionsClient::new(resolved).map_err(|e| ApiError::Config(format!("intel.llm: {e}")))?;
    Ok(Some(Arc::new(client)))
}

/// The router of the extraction step. The default model is its fallback, so a provider without a
/// default LLM is a configuration error rather than a silently unused setting.
fn extraction_router(
    cfg: &IntelConfig,
    default: Option<&Arc<dyn LlmExtractor>>,
) -> Result<Option<Arc<ExtractionRouter>>, ApiError> {
    let Some(settings) = &cfg.extraction else {
        return Ok(None);
    };
    let Some(default) = default else {
        return Err(ApiError::Config(
            "intel.extraction: the extraction provider falls back to the default LLM, which is not configured \
             (set intel.llm or CRAWLX_LLM_BASE_URL / CRAWLX_LLM_MODEL / CRAWLX_LLM_API_KEY)"
                .to_owned(),
        ));
    };
    let policy = settings
        .policy()
        .map_err(|e| ApiError::Config(format!("intel.extraction: {e}")))?;
    let resolved = settings
        .resolve()
        .map_err(|e| ApiError::Config(format!("intel.extraction: {e}")))?;
    let provider = ChatCompletionsClient::new(resolved)
        .map_err(|e| ApiError::Config(format!("intel.extraction: {e}")))?;
    Ok(Some(Arc::new(ExtractionRouter::new(
        Arc::clone(default),
        Arc::new(provider),
        policy,
    ))))
}

/// Everything `cfg` configures for the API process (`None` for an unset section).
///
/// # Errors
/// [`ApiError::Config`] when a key reference cannot be resolved or an endpoint is invalid.
pub fn backends(cfg: &IntelConfig) -> Result<Backends, ApiError> {
    let llm = default_llm(cfg)?;
    let extraction = extraction_router(cfg, llm.as_ref())?;
    let embeddings = match &cfg.embeddings {
        Some(settings) => {
            let resolved = settings
                .resolve(cfg.llm.as_ref())
                .map_err(|e| ApiError::Config(format!("intel.embeddings: {e}")))?;
            let client = HttpEmbeddings::new(resolved)
                .map_err(|e| ApiError::Config(format!("intel.embeddings: {e}")))?;
            Some(Arc::new(PageRanker::new(
                Arc::new(client) as Arc<dyn EmbeddingsClient>,
                settings.top_n,
            )))
        }
        None => None,
    };
    let search = match &cfg.search {
        Some(settings) => Some(
            search::from_settings(settings).map_err(|e| ApiError::Config(format!("intel.search: {e}")))?,
        ),
        None => None,
    };
    Ok(Backends {
        llm,
        search,
        extraction,
        embeddings,
    })
}

/// The LLM steps `cfg` configures for a worker process.
///
/// # Errors
/// [`ApiError::Config`] when a key reference cannot be resolved or an endpoint is invalid.
pub fn worker_llm(cfg: &IntelConfig) -> Result<WorkerLlm, ApiError> {
    let llm = default_llm(cfg)?;
    let extraction = extraction_router(cfg, llm.as_ref())?;
    let branding = match &cfg.branding {
        Some(settings) => {
            let resolved = settings
                .resolve(cfg.llm.as_ref())
                .map_err(|e| ApiError::Config(format!("intel.branding: {e}")))?;
            let client = ChatCompletionsClient::new(resolved)
                .map_err(|e| ApiError::Config(format!("intel.branding: {e}")))?;
            Some(Arc::new(client) as Arc<dyn LlmExtractor>)
        }
        None => None,
    };
    Ok(WorkerLlm {
        llm,
        extraction,
        branding,
    })
}
