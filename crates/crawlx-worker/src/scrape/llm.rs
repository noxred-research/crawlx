//! The LLM formats of a scrape: `json`, `summary`, `question`, `highlights` and `query`, plus the
//! embedding-cluster extraction of the final text ([`cluster_chunks`]).
//!
//! The input is the page markdown. [`LlmExtractor`] fences it as untrusted data, so page text
//! can never instruct the model. Tokens (prompt + completion) of every call add up in
//! [`ScrapeDocument::llm_tokens`].

use crate::scrape::{FailReason, ScrapeFailure};
use crawlx_core::extraction::{ClusterEnvelopeV1, ClusterPolicyV1, WordChunkEnvelopeV1, WordChunkPolicyV1};
use crawlx_core::scrape::{FormatSpec, ScrapeDocument};
use crawlx_core::seed::CrawlSeed;
use crawlx_model::llm::embeddings::{cluster_ranges, ClusterRequest, ClusterTextsError};
use crawlx_model::llm::{EmbeddingsClient, LlmError, LlmExtractor, TokenUsage};

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

/// What [`cluster_chunks`] groups: the final privacy-projected text, how it is chunked, and how
/// the chunks are clustered.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct ChunkClusterRequest<'a> {
    /// The operator-configured embedding client; `None` when no model is configured.
    pub embeddings: Option<&'a dyn EmbeddingsClient>,
    /// The exact final text, after every privacy projection.
    pub text: &'a str,
    /// How the text is cut into the units that get embedded.
    pub chunks: WordChunkPolicyV1,
    /// Cluster count and hard caps (the vector cap is checked before any embedding call).
    pub policy: ClusterPolicyV1,
    /// Label of the embedding model, recorded on the result.
    pub model: &'a str,
    /// Run seed the clustering derives from.
    pub seed: CrawlSeed,
}

impl<'a> ChunkClusterRequest<'a> {
    /// A request over `text`.
    #[must_use]
    pub const fn new(
        embeddings: Option<&'a dyn EmbeddingsClient>,
        text: &'a str,
        chunks: WordChunkPolicyV1,
        policy: ClusterPolicyV1,
        model: &'a str,
        seed: CrawlSeed,
    ) -> Self {
        Self {
            embeddings,
            text,
            chunks,
            policy,
            model,
            seed,
        }
    }
}

impl std::fmt::Debug for ChunkClusterRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Neither the text nor the client is printed: the text is page content.
        f.debug_struct("ChunkClusterRequest")
            .field("embeddings", &self.embeddings.is_some())
            .field("text_bytes", &self.text.len())
            .field("chunks", &self.chunks)
            .field("policy", &self.policy)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

/// The chunks of a text and the clusters of those chunks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ChunkClusters {
    /// The source-only chunk ranges that were embedded.
    pub chunks: WordChunkEnvelopeV1,
    /// The clusters over exactly those ranges.
    pub clusters: ClusterEnvelopeV1,
}

/// Cut the final text into chunks and group the chunks by embedding similarity, charging the
/// endpoint's reported tokens to `doc`.
///
/// Both stages work over the final text only, so nothing a privacy projection removed can reach
/// the embedding endpoint. A missing model fails the page with
/// [`FailReason::LlmNotConfigured`] before anything is sent; every other failure (chunk cap,
/// vector cap, endpoint error, malformed reply) is [`FailReason::LlmFailed`] or
/// [`FailReason::ExtractFailed`] and never leaves a partial result.
///
/// # Errors
/// A [`ScrapeFailure`] for an unavailable model, a refused chunk policy or cluster request, or an
/// embeddings failure.
pub async fn cluster_chunks(
    request: &ChunkClusterRequest<'_>,
    doc: &mut ScrapeDocument,
) -> Result<ChunkClusters, ScrapeFailure> {
    if request.embeddings.is_none() {
        return Err(ScrapeFailure::new(
            FailReason::LlmNotConfigured,
            "no embedding model is configured for cluster extraction",
        ));
    }
    let chunks = WordChunkEnvelopeV1::build(request.text, request.chunks)
        .map_err(|e| ScrapeFailure::new(FailReason::ExtractFailed, e.to_string()))?;
    let inner = ClusterRequest::new(
        request.text,
        &chunks.ranges,
        request.model,
        request.policy,
        request.seed,
    );
    let done = cluster_ranges(request.embeddings, &inner)
        .await
        .map_err(|e| match e {
            ClusterTextsError::Unavailable => ScrapeFailure::new(FailReason::LlmNotConfigured, e.to_string()),
            ClusterTextsError::Cluster(_) => ScrapeFailure::new(FailReason::ExtractFailed, e.to_string()),
            _ => ScrapeFailure::new(FailReason::LlmFailed, e.to_string()),
        })?;
    charge(
        doc,
        TokenUsage {
            prompt_tokens: done.tokens,
            completion_tokens: 0,
        },
    );
    Ok(ChunkClusters {
        chunks,
        clusters: done.envelope,
    })
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

    const PAGE: &str = "river water flows past the river bank.\n\nthe lake water meets the river shore.\n\n\
        market price trade stock market rally.\n\nstock trade price falls in the market.\n\n\
        mountain trail hiking trail summit.\n\nhiking the summit trail on the mountain.";

    fn request<'a>(
        client: Option<&'a dyn EmbeddingsClient>,
        text: &'a str,
        policy: ClusterPolicyV1,
    ) -> ChunkClusterRequest<'a> {
        let mut chunks = WordChunkPolicyV1::default();
        chunks.strategy = crawlx_core::extraction::WordChunkStrategyV1::Regex {
            pattern: crawlx_core::extraction::ChunkPatternV1::new(r"\n\s*\n").unwrap(),
        };
        ChunkClusterRequest::new(client, text, chunks, policy, "mock", CrawlSeed(9))
    }

    #[tokio::test]
    async fn clusters_regex_chunks_of_the_final_text_and_charges_tokens() {
        let mock = crawlx_model::llm::MockEmbeddings::new(256);
        let mut policy = ClusterPolicyV1::default();
        policy.clusters = 3;
        let mut d = doc();
        let done = cluster_chunks(&request(Some(&mock), PAGE, policy), &mut d)
            .await
            .unwrap();
        assert_eq!(done.chunks.ranges.len(), 6);
        assert_eq!(done.clusters.clusters.len(), 3);
        assert!(done.clusters.clusters.iter().all(|c| c.members.len() == 2));
        done.chunks
            .validate(PAGE, &request(None, PAGE, policy).chunks)
            .unwrap();
        done.clusters.validate(PAGE, &policy).unwrap();
        assert!(d.llm_tokens > 0);
        // Each chunk was embedded exactly once, in one call, from the final text only.
        let calls = mock.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].len(), 6);
        assert!(calls[0].iter().all(|text| PAGE.contains(text.as_str())));
    }

    #[tokio::test]
    async fn a_missing_model_fails_the_page_as_not_configured_without_sending_anything() {
        let f = cluster_chunks(&request(None, PAGE, ClusterPolicyV1::default()), &mut doc())
            .await
            .unwrap_err();
        assert_eq!(f.reason, FailReason::LlmNotConfigured);
    }

    #[tokio::test]
    async fn the_vector_cap_and_endpoint_failures_fail_the_page_without_partial_clusters() {
        let mock = crawlx_model::llm::MockEmbeddings::new(8);
        let mut policy = ClusterPolicyV1::default();
        policy.max_vectors = 5;
        let mut d = doc();
        let f = cluster_chunks(&request(Some(&mock), PAGE, policy), &mut d)
            .await
            .unwrap_err();
        assert_eq!(f.reason, FailReason::ExtractFailed);
        assert!(
            mock.calls().is_empty(),
            "over-cap input must never reach the endpoint"
        );
        assert_eq!(d.llm_tokens, 0);
        let failing = crawlx_model::llm::MockEmbeddings::new(8)
            .failing(crawlx_model::llm::EmbeddingsError::Status { status: 503 });
        let f = cluster_chunks(&request(Some(&failing), PAGE, ClusterPolicyV1::default()), &mut d)
            .await
            .unwrap_err();
        assert_eq!(f.reason, FailReason::LlmFailed);
        assert_eq!(d.llm_tokens, 0);
    }
}
