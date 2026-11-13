//! Services behind the compatibility-API LLM products: the search provider seam
//! ([`search`]), the page tools seam over the scrape engine ([`tools`]), usage accounting
//! ([`usage`]), job admission and background execution ([`jobs`]), job webhooks ([`webhook`]), embedding ranking of the pages
//! `/extract` reads ([`rank`]) and shared route plumbing ([`common`]).
//!
//! The routes live in `routes/compat_{search,extract,agent,parse,monitor,team}.rs`; this module
//! holds what they share.

pub mod agent;
pub mod agent_plan;
pub mod agent_spec;
pub mod agent_view;
pub mod common;
pub mod docs_search;
pub mod evidence;
pub mod exchange;
pub mod extract;
pub mod extract_evidence;
pub mod feedback;
pub mod govern;
pub mod indexes;
pub mod jobs;
pub mod metasearch;
pub mod monitor;
pub mod proposals;
pub mod rank;
pub mod request;
pub mod search;
pub mod search_http;
pub mod serp;
pub mod spec_compile;
pub mod summary;
pub mod tools;
pub mod triage;
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
    /// The model-egress governor and proposal settings of the native AI endpoints (`intel.policy`).
    pub ai: govern::AiPolicy,
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
    /// The embedding model of the scrape `clusters` option (`intel.embeddings`).
    pub embeddings: Option<crawlx_worker::ClusterEmbeddings>,
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
    let ai = ai_policy(cfg)?;
    Ok(Backends {
        llm,
        search,
        extraction,
        embeddings,
        ai,
    })
}

/// The governor of `intel.policy`: every approved provider gets its own bounded client, so a
/// provider never inherits another endpoint's credential.
fn ai_policy(cfg: &IntelConfig) -> Result<govern::AiPolicy, ApiError> {
    use crawlx_model::policy::{Budgets, ModelGovernor, ModelProcessingPolicyV1, ProviderPolicy};
    use std::collections::{BTreeMap, BTreeSet};
    let Some(settings) = &cfg.policy else {
        return Ok(govern::AiPolicy::default());
    };
    let fail = |message: String| ApiError::Config(format!("intel.policy: {message}"));
    let mut budgets = Budgets::default();
    if let Some(v) = settings.max_input_bytes {
        budgets.max_input_bytes = v;
    }
    if let Some(v) = settings.max_output_tokens {
        budgets.max_output_tokens = v;
    }
    if let Some(v) = settings.max_response_bytes {
        budgets.max_response_bytes = v;
    }
    if let Some(v) = settings.max_run_calls {
        budgets.max_run_calls = v;
    }
    if let Some(v) = settings.max_run_tokens {
        budgets.max_run_tokens = v;
    }
    if let Some(v) = settings.deadline_ms {
        budgets.deadline_ms = v;
    }
    let mut providers = BTreeMap::new();
    let mut clients: BTreeMap<String, Arc<dyn LlmExtractor>> = BTreeMap::new();
    for (id, provider) in &settings.providers {
        let id_ok = (1..=32).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'));
        if !id_ok {
            return Err(fail(format!(
                "provider id {id:?} must be 1 to 32 characters of a-z, 0-9, '-' or '_'"
            )));
        }
        let inherited = cfg.llm.as_ref();
        let own_endpoint = provider.endpoint.is_some();
        let endpoint = provider
            .endpoint
            .clone()
            .or_else(|| inherited.map(|l| l.endpoint.clone()))
            .ok_or_else(|| fail(format!("provider {id}: no endpoint and no intel.llm to inherit")))?;
        let model = provider
            .model
            .clone()
            .or_else(|| inherited.map(|l| l.model.clone()))
            .ok_or_else(|| fail(format!("provider {id}: no model and no intel.llm to inherit")))?;
        // a credential is inherited only together with the endpoint it belongs to
        let api_key_ref = provider.api_key_ref.clone().or_else(|| {
            if own_endpoint {
                None
            } else {
                inherited.and_then(|l| l.api_key_ref.clone())
            }
        });
        let llm_settings = crate::config::LlmSettings {
            endpoint,
            model: model.clone(),
            api_key_ref,
            timeout_ms: provider
                .timeout_ms
                .or_else(|| inherited.and_then(|l| l.timeout_ms)),
            transcribe_endpoint: None,
            transcribe_model: None,
        };
        let resolved = llm_settings
            .resolve()
            .map_err(|e| fail(format!("provider {id}: {e}")))?;
        let client = ChatCompletionsClient::new(resolved).map_err(|e| fail(format!("provider {id}: {e}")))?;
        clients.insert(id.clone(), Arc::new(client));
        providers.insert(
            id.clone(),
            ProviderPolicy {
                model,
                revision: provider.revision.clone().unwrap_or_else(|| "1".to_owned()),
                retention: provider.retention_capability,
                purposes: provider.allowed_purposes.iter().copied().collect::<BTreeSet<_>>(),
            },
        );
    }
    let policy = ModelProcessingPolicyV1 {
        external_processing: settings.external_processing,
        providers,
        budgets,
        ..ModelProcessingPolicyV1::default()
    };
    let governor = ModelGovernor::new(policy, clients).map_err(|e| fail(e.to_string()))?;
    let ttl = settings
        .proposal_ttl_secs
        .unwrap_or(govern::DEFAULT_PROPOSAL_TTL_SECS);
    if !(1..=govern::MAX_PROPOSAL_TTL_SECS).contains(&ttl) {
        return Err(fail(format!(
            "proposalTtlSecs must be in 1..={}",
            govern::MAX_PROPOSAL_TTL_SECS
        )));
    }
    Ok(govern::AiPolicy {
        governor: Some(Arc::new(governor)),
        proposal_ttl_secs: ttl,
        allow_self_approval: settings.allow_self_approval,
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
    let embeddings = match &cfg.embeddings {
        Some(settings) => {
            let resolved = settings
                .resolve(cfg.llm.as_ref())
                .map_err(|e| ApiError::Config(format!("intel.embeddings: {e}")))?;
            let model = resolved.model.clone();
            let client = HttpEmbeddings::new(resolved)
                .map_err(|e| ApiError::Config(format!("intel.embeddings: {e}")))?;
            Some(crawlx_worker::ClusterEmbeddings::new(
                Arc::new(client) as Arc<dyn EmbeddingsClient>,
                model,
            ))
        }
        None => None,
    };
    Ok(WorkerLlm {
        llm,
        extraction,
        branding,
        embeddings,
    })
}
