//! The worker side of the opt-in `modelV1` content strategy.
//!
//! The native default never reaches this module's model path: no projection, no provider call and
//! no copy of the composed markdown. `modelV1` is explicit, bounded and without fallback: every
//! failure (unavailable model, policy refusal, provider, schema, privacy, cancellation) ends the
//! page with a typed reason instead of a native success. Generated output is untrusted content; it
//! lands only in `markdown` (target `content`/`tablesAndContent`) and in the
//! [`ScrapeDocument::model_content`] sidecar, never in native outputs, source evidence, discovery
//! links or any action.

use super::{llm, FailReason, ScrapeEngine, ScrapeFailure};
use crawlx_core::scrape::{ContentStrategySpecV1, ContentStrategyTargetV1, ScrapeDocument, ScrapeOptions};
use crawlx_extract::parse::redact::{self, RedactOptions};
use crawlx_model::llm::content_strategy::{
    apply_content_strategy, ContentPrivacyV1, ContentProcessingPolicyV1, ContentStrategyError,
    ContentStrategyV1, ContentTargetV1,
};
use crawlx_model::llm::extractor::{CompletionLimits, MaxOutputTokens};
use crawlx_model::llm::LlmError;
use tokio_util::sync::CancellationToken;

/// Privacy projection of the current run: configured credentials and registered secrets first,
/// then the request's `redactPII` policy. An unenforceable PII entity fails the projection.
struct StrategyPrivacy<'a> {
    engine: &'a ScrapeEngine,
    pii: Option<RedactOptions>,
}

impl ContentPrivacyV1 for StrategyPrivacy<'_> {
    fn project(&self, text: &str) -> Result<String, ContentStrategyError> {
        let text = self.engine.redact(text);
        match &self.pii {
            Some(options) => {
                let result = redact::redact(&text, options);
                if !result.unsupported.is_empty() {
                    return Err(ContentStrategyError::PrivacyProjection);
                }
                Ok(result.text)
            }
            None => Ok(text),
        }
    }
}

/// Map the request spec to the model strategy. Limits are validated, never clamped.
///
/// # Errors
/// [`LlmError::InvalidRequest`] for out-of-range limits or a spec this worker does not know.
fn model_strategy(spec: Option<&ContentStrategySpecV1>) -> Result<ContentStrategyV1, LlmError> {
    match spec {
        None | Some(ContentStrategySpecV1::NativeV1) => Ok(ContentStrategyV1::NativeV1),
        Some(ContentStrategySpecV1::ModelV1 {
            target,
            max_output_tokens,
            max_response_bytes,
            ..
        }) => {
            let target = match target {
                ContentStrategyTargetV1::Tables => ContentTargetV1::Tables,
                ContentStrategyTargetV1::Content => ContentTargetV1::Content,
                ContentStrategyTargetV1::TablesAndContent => ContentTargetV1::TablesAndContent,
                _ => {
                    return Err(LlmError::InvalidRequest(
                        "unsupported content strategy target".to_owned(),
                    ))
                }
            };
            let tokens = MaxOutputTokens::new(*max_output_tokens)?;
            let limits = CompletionLimits::new(tokens, *max_response_bytes)?;
            Ok(ContentStrategyV1::ModelV1 { target, limits })
        }
        Some(_) => Err(LlmError::InvalidRequest(
            "unsupported content strategy version".to_owned(),
        )),
    }
}

/// Consent of the authenticated immutable request. A stricter operator or tenant prohibition
/// would narrow this boolean; `false` is never widened.
fn consent(spec: Option<&ContentStrategySpecV1>) -> bool {
    matches!(
        spec,
        Some(ContentStrategySpecV1::ModelV1 {
            external_processing_consent: true,
            ..
        })
    )
}

/// Does the request select the model strategy?
pub(super) fn is_model(opts: &ScrapeOptions) -> bool {
    matches!(opts.content_strategy, Some(ContentStrategySpecV1::ModelV1 { .. }))
}

/// Static, content-free failure of a strategy error: provider bodies, parser diagnostics and page
/// text never reach a message.
fn failure(error: &ContentStrategyError) -> ScrapeFailure {
    match error {
        ContentStrategyError::ModelUnavailable => ScrapeFailure::new(
            FailReason::LlmNotConfigured,
            "the model content strategy needs an LLM and this worker has none configured",
        ),
        ContentStrategyError::Model(LlmError::Cancelled) => {
            ScrapeFailure::new(FailReason::Cancelled, "the model content strategy was cancelled")
        }
        other => ScrapeFailure::new(
            FailReason::LlmFailed,
            match other {
                ContentStrategyError::ZeroDataRetention => {
                    "the model content strategy is not allowed with zero data retention"
                }
                ContentStrategyError::ExternalProcessingDenied => {
                    "the model content strategy lacks external-processing consent"
                }
                ContentStrategyError::InputLimit => "the page exceeds the model content strategy input limit",
                ContentStrategyError::InvalidSchema => {
                    "the model content strategy returned an invalid response schema"
                }
                ContentStrategyError::OutputLimit => "the model content strategy output exceeds its limit",
                ContentStrategyError::PrivacyProjection => {
                    "the model content strategy could not enforce the privacy policy"
                }
                ContentStrategyError::Model(LlmError::UnsupportedOutputBudget) => {
                    "the configured model provider does not support bounded completions"
                }
                ContentStrategyError::Model(_) => "the model content strategy call failed",
                _ => "the model content strategy failed",
            },
        ),
    }
}

/// Run the selected content strategy over the composed `markdown`.
///
/// `None` and `nativeV1` return immediately with every native value untouched. `modelV1` charges
/// the provider tokens to `doc`, replaces `markdown` for the `content` targets and stores the
/// final typed document in [`ScrapeDocument::model_content`].
///
/// # Errors
/// A [`ScrapeFailure`] for every explicit-model failure; it never becomes a native success.
pub(super) async fn apply(
    engine: &ScrapeEngine,
    opts: &ScrapeOptions,
    markdown: &mut Option<String>,
    doc: &mut ScrapeDocument,
    cancel: &CancellationToken,
) -> Result<(), ScrapeFailure> {
    let spec = opts.content_strategy.as_ref();
    if !is_model(opts) {
        return Ok(());
    }
    let strategy = model_strategy(spec).map_err(|_| {
        ScrapeFailure::new(
            FailReason::LlmFailed,
            "the model content strategy limits are invalid",
        )
    })?;
    let policy = ContentProcessingPolicyV1::new(engine.zdr, consent(spec));
    let privacy = StrategyPrivacy {
        engine,
        pii: opts.redact_pii.as_ref().map(super::guard::redact_options),
    };
    let done = apply_content_strategy(
        strategy,
        engine.llm.as_deref(),
        markdown.as_deref().unwrap_or(""),
        &policy,
        &privacy,
        cancel,
    )
    .await
    .map_err(|error| failure(&error))?;
    let Some(completion) = done else {
        return Ok(());
    };
    llm::charge(doc, completion.usage);
    if matches!(
        spec,
        Some(ContentStrategySpecV1::ModelV1 {
            target: ContentStrategyTargetV1::Content | ContentStrategyTargetV1::TablesAndContent,
            ..
        })
    ) {
        *markdown = Some(completion.value.markdown.clone());
    }
    doc.model_content = Some(serde_json::to_value(&completion.value).map_err(|_| {
        ScrapeFailure::new(FailReason::LlmFailed, "the model content could not be serialized")
    })?);
    Ok(())
}
