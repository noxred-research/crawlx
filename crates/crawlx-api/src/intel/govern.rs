//! API side of the model-egress policy: the configured governor, the error mapping of its
//! refusals, audit rows of governed calls and the status document of `GET /v1/capabilities/ai`.
//!
//! The native AI endpoints never talk to a model client directly; they call [`call`], which
//! picks an approved provider, runs the call through [`crawlx_model::policy::ModelGovernor`]
//! and writes a digest-only audit row. Page text, prompts and replies never enter the audit.

use crate::auth::Principal;
use crate::errors::{Detail, HttpError};
use crate::state::AppState;
use axum::http::StatusCode;
use crawlx_core::config::RetentionMode;
use crawlx_core::CrawlRunId;
use crawlx_model::llm::LlmError;
use crawlx_model::policy::{
    GovernError, GovernedRequest, ModelGovernor, ModelInputEnvelopeV1, ModelOutputEnvelopeV1, Purpose,
    RetentionClass,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Seconds a proposal stays approvable unless `intel.policy.proposalTtlSecs` says otherwise.
pub const DEFAULT_PROPOSAL_TTL_SECS: u64 = 900;
/// Longest configurable proposal lifetime.
pub const MAX_PROPOSAL_TTL_SECS: u64 = 86_400;

/// What `intel.policy` configures at runtime.
#[derive(Clone)]
pub struct AiPolicy {
    /// The governor; `None` leaves every model call of the native AI endpoints unavailable.
    pub governor: Option<Arc<ModelGovernor>>,
    /// Seconds a compiled spec, agent plan or approval stays valid.
    pub proposal_ttl_secs: u64,
    /// Whether the key that proposed a spec or plan may also approve it.
    pub allow_self_approval: bool,
}

impl Default for AiPolicy {
    fn default() -> Self {
        Self {
            governor: None,
            proposal_ttl_secs: DEFAULT_PROPOSAL_TTL_SECS,
            allow_self_approval: false,
        }
    }
}

impl std::fmt::Debug for AiPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AiPolicy")
            .field("governor", &self.governor)
            .field("proposal_ttl_secs", &self.proposal_ttl_secs)
            .field("allow_self_approval", &self.allow_self_approval)
            .finish()
    }
}

/// Retention class of a run for model egress.
#[must_use]
pub const fn retention_class(mode: RetentionMode) -> RetentionClass {
    match mode {
        RetentionMode::Zdr => RetentionClass::Zdr,
        _ => RetentionClass::Standard,
    }
}

/// The response a refusal or failure of governed processing becomes. Messages carry no
/// content; the codes are stable.
#[must_use]
pub fn http_error(error: &GovernError) -> HttpError {
    let code = error.code();
    let text = error.to_string();
    match error {
        GovernError::ExternalProcessingDisabled
        | GovernError::PurposeNotAllowed { .. }
        | GovernError::ZdrIncompatible(_) => HttpError::compat(StatusCode::FORBIDDEN, code, text),
        GovernError::ProviderNotConfigured(_) | GovernError::InvalidPolicy(_) => {
            HttpError::backend_unavailable("ai_not_configured", text)
        }
        GovernError::InvalidSchema(_) | GovernError::InvalidInput(_) => {
            HttpError::validation(vec![Detail::new("/", code, text)])
        }
        GovernError::InputTooLarge { .. } => HttpError::compat(StatusCode::PAYLOAD_TOO_LARGE, code, text),
        GovernError::BudgetExhausted(_) => {
            HttpError::compat(StatusCode::TOO_MANY_REQUESTS, "ai_budget_exhausted", text)
        }
        GovernError::DeadlineExceeded => HttpError::compat(StatusCode::GATEWAY_TIMEOUT, "ai_timeout", text),
        GovernError::Model(LlmError::Cancelled) => {
            HttpError::compat(StatusCode::SERVICE_UNAVAILABLE, "ai_cancelled", text)
        }
        GovernError::Model(source) => crate::intel::common::llm_error(source),
        _ => HttpError::internal(),
    }
}

/// Budget scope of a model call that belongs to no run yet (spec compiling, plan proposals): the
/// calling key and the current hour, so a long-lived key gets a fresh budget each hour.
#[must_use]
pub fn hourly_scope(state: &AppState, label: &str, principal: &Principal) -> String {
    let hour = state.clock.now().timestamp_millis().div_euclid(3_600_000);
    format!("{label}:{}:{hour}", principal.key_id)
}

/// One governed model call.
#[derive(Clone, Debug)]
pub struct ModelCall<'a> {
    /// Budget scope: run id, plan id or spec id.
    pub scope: &'a str,
    /// Run whose content is sent (audit subject and retention source), if any.
    pub run: Option<CrawlRunId>,
    /// Purpose.
    pub purpose: Purpose,
    /// Retention class of the content.
    pub retention: RetentionClass,
    /// Structured-output schema.
    pub schema: Option<&'a Value>,
    /// Version label of the schema.
    pub schema_version: &'a str,
}

/// Whether a model could serve `purpose` for content of `retention` right now.
///
/// # Errors
/// The governed refusal that applies.
pub fn availability(
    state: &AppState,
    purpose: Purpose,
    retention: RetentionClass,
) -> Result<String, GovernError> {
    let governor = state
        .ai
        .governor
        .as_ref()
        .ok_or(GovernError::ExternalProcessingDisabled)?;
    governor.select(purpose, retention).map(str::to_owned)
}

/// Run `envelope` through the governor and audit the call.
///
/// # Errors
/// Every refusal and failure of [`ModelGovernor::process`].
pub async fn call(
    state: &AppState,
    principal: &Principal,
    call: &ModelCall<'_>,
    envelope: &ModelInputEnvelopeV1,
) -> Result<ModelOutputEnvelopeV1, GovernError> {
    let governor = state
        .ai
        .governor
        .as_ref()
        .ok_or(GovernError::ExternalProcessingDisabled)?;
    let provider = governor.select(call.purpose, call.retention)?.to_owned();
    let tenant = principal.tenant.0.to_string();
    let request = GovernedRequest {
        tenant: &tenant,
        scope: call.scope,
        provider: &provider,
        purpose: call.purpose,
        retention: call.retention,
        schema: call.schema,
        schema_version: call.schema_version,
    };
    let cancel = CancellationToken::new();
    let output = governor.process(&request, envelope, &cancel).await;
    let subject = match &output {
        Ok(out) => json!({ "outcome": "ok", "record": out.record }),
        Err(error) => json!({
            "outcome": error.code(),
            "provider": provider,
            "purpose": call.purpose.as_str(),
            "policyDigest": governor.policy_digest(),
            "inputDigest": envelope.digest(),
        }),
    };
    if let Err(error) = state
        .repos
        .api
        .audit_append(
            principal.tenant,
            call.run,
            &principal.actor(),
            "model.processed",
            subject,
        )
        .await
    {
        tracing::warn!(%error, "model audit row could not be written");
    }
    output
}

/// The document of `GET /v1/capabilities/ai`. It names providers, models and limits; it never
/// carries endpoints, keys, prompts or content.
#[must_use]
pub fn capabilities(state: &AppState) -> Value {
    let ai = &state.ai;
    let endpoints: Vec<&str> = vec![
        "POST /v1/crawl-specs/validate",
        "POST /v1/crawl-specs/compile",
        "POST /v1/agent-plans",
        "POST /v1/crawls/{id}/extractions",
        "POST /v1/crawls/{id}/triage",
        "POST /v1/crawls/{id}/summaries",
    ];
    let Some(governor) = &ai.governor else {
        return json!({
            "policyVersion": crawlx_model::policy::POLICY_VERSION,
            "externalProcessing": false,
            "configured": false,
            "providers": [],
            "modelAssisted": [],
            "deterministic": ["validateCrawlSpec", "triageSurfaces", "summarizeRun"],
            "endpoints": endpoints,
            "proposalTtlSecs": ai.proposal_ttl_secs,
            "note": "no intel.policy is configured: model-assisted operations answer ai_not_configured and the deterministic ones run without a model",
        });
    };
    let policy = governor.policy();
    let providers: Vec<Value> = policy
        .providers
        .iter()
        .map(|(id, p)| {
            json!({
                "id": id,
                "model": p.model,
                "revision": p.revision,
                "retentionCapability": p.retention,
                "allowedPurposes": p.purposes,
            })
        })
        .collect();
    json!({
        "policyVersion": policy.version,
        "policyDigest": governor.policy_digest(),
        "externalProcessing": policy.external_processing,
        "configured": true,
        "providers": providers,
        "budgets": policy.budgets,
        "modelAssisted": Purpose::ALL.map(Purpose::as_str),
        "deterministic": ["validateCrawlSpec", "triageSurfaces", "summarizeRun"],
        "endpoints": endpoints,
        "proposalTtlSecs": ai.proposal_ttl_secs,
        "allowSelfApproval": ai.allow_self_approval,
    })
}
