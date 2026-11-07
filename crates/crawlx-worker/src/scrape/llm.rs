//! The LLM formats of a scrape: `json`, `summary`, `question`, `highlights` and `query`.
//!
//! The input is the page markdown. [`LlmExtractor`] fences it as untrusted data, so page text
//! can never instruct the model. Tokens (prompt + completion) of every call add up in
//! [`ScrapeDocument::llm_tokens`].

use crate::scrape::{FailReason, ScrapeFailure};
use crawlx_core::scrape::{FormatSpec, ScrapeDocument};
use crawlx_model::llm::{LlmError, LlmExtractor, TokenUsage};

/// The page failure of an LLM error.
pub(crate) fn failure(e: &LlmError) -> ScrapeFailure {
    let reason = match e {
        LlmError::NotConfigured => FailReason::LlmNotConfigured,
        _ => FailReason::LlmFailed,
    };
    ScrapeFailure::new(reason, e.to_string())
}

/// Run every LLM format over `markdown`, in request order, filling the matching fields of `doc`.
///
/// # Errors
/// The first failing call, as [`FailReason::LlmFailed`] (or `LlmNotConfigured`).
pub(crate) async fn run_formats(
    llm: &dyn LlmExtractor,
    formats: &[FormatSpec],
    markdown: &str,
    doc: &mut ScrapeDocument,
) -> Result<(), ScrapeFailure> {
    let mut tokens = TokenUsage::default();
    for format in formats {
        match format {
            FormatSpec::Json { schema, prompt } => {
                let c = llm
                    .json(markdown, schema.as_ref(), prompt.as_deref())
                    .await
                    .map_err(|e| failure(&e))?;
                tokens.add(c.usage);
                doc.json = Some(c.value);
            }
            FormatSpec::Summary => {
                let c = llm.summary(markdown).await.map_err(|e| failure(&e))?;
                tokens.add(c.usage);
                doc.summary = Some(c.value);
            }
            FormatSpec::Question { question } => {
                let c = llm.answer(markdown, question).await.map_err(|e| failure(&e))?;
                tokens.add(c.usage);
                doc.answer = Some(c.value);
            }
            FormatSpec::Highlights { query } => {
                let c = llm.highlights(markdown, query).await.map_err(|e| failure(&e))?;
                tokens.add(c.usage);
                doc.highlights = Some(c.value);
            }
            FormatSpec::Query { prompt, mode } => {
                let c = llm
                    .query(markdown, prompt, *mode)
                    .await
                    .map_err(|e| failure(&e))?;
                tokens.add(c.usage);
                doc.query = Some(c.value);
            }
            FormatSpec::Markdown
            | FormatSpec::Html
            | FormatSpec::RawHtml
            | FormatSpec::Links
            | FormatSpec::Images
            | FormatSpec::RawBase64
            | FormatSpec::Branding
            | FormatSpec::Audio
            | FormatSpec::Video
            | FormatSpec::Screenshot { .. }
            | FormatSpec::Attributes { .. }
            | FormatSpec::ChangeTracking { .. } => {}
        }
    }
    doc.llm_tokens = doc.llm_tokens.saturating_add(tokens.total());
    Ok(())
}

/// Add the tokens of `usage` to `doc`.
pub(crate) fn charge(doc: &mut ScrapeDocument, usage: TokenUsage) {
    doc.llm_tokens = doc.llm_tokens.saturating_add(usage.total());
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::scrape::ScrapeOptions;
    use crawlx_model::llm::MockLlm;
    use serde_json::json;

    fn doc() -> ScrapeDocument {
        ScrapeDocument::new(
            "https://a.test/".to_owned(),
            "https://a.test/".to_owned(),
            200,
            ScrapeOptions::default().cache_digest(),
        )
    }

    #[tokio::test]
    async fn formats_fill_their_fields_and_count_tokens() {
        let llm = MockLlm::scripted(vec![Ok(json!({"summary": "short"})), Ok(json!({"answer": "42"}))]);
        let options = ScrapeOptions {
            formats: vec![
                FormatSpec::Summary,
                FormatSpec::Question {
                    question: "meaning?".to_owned(),
                },
            ],
            ..ScrapeOptions::default()
        };
        let mut d = doc();
        run_formats(&llm, &options.formats, "# page", &mut d)
            .await
            .unwrap();
        assert_eq!(d.summary.as_deref(), Some("short"));
        assert_eq!(d.answer.as_deref(), Some("42"));
        assert!(d.llm_tokens > 0);
        assert_eq!(llm.calls().len(), 2);
    }

    #[tokio::test]
    async fn an_llm_error_fails_the_page_with_llm_failed() {
        let llm = MockLlm::scripted(vec![Err(LlmError::Status { status: 500 })]);
        let options = ScrapeOptions {
            formats: vec![FormatSpec::Summary],
            ..ScrapeOptions::default()
        };
        let f = run_formats(&llm, &options.formats, "x", &mut doc())
            .await
            .unwrap_err();
        assert_eq!(f.reason, FailReason::LlmFailed);
    }
}
