//! Embedding ranking of the pages an `/extract` job read (`MODEL_EMBEDDING_NAME`).
//!
//! Firecrawl self-host ranks candidates by the cosine similarity between the request's text and
//! each candidate's embedding (`apps/api/src/lib/ranker.ts`). `/extract` applies the same
//! ranking to its scraped pages: the pages are ordered by similarity to the prompt (the schema
//! when there is no prompt) and only the best [`PageRanker::top_n`] reach the LLM, so the model
//! reads the most relevant pages first and spends its input budget on them.
//!
//! Without a configured embedding model nothing in this module runs and the pages go to the
//! LLM exactly as scraped. When the embeddings call itself fails the pages also go as scraped,
//! with a warning on the job: ranking improves the input, it is not a precondition of the answer.

use crawlx_model::llm::{rank_texts, EmbeddingsClient, ExtractDocument};
use std::sync::Arc;

/// Pages ordered for the LLM.
#[derive(Debug)]
pub struct RankedPages {
    /// The pages the LLM reads, best first.
    pub docs: Vec<ExtractDocument>,
    /// Embedding tokens the endpoint reported.
    pub tokens: u64,
    /// What the caller should tell the user (pages dropped, ranking skipped).
    pub warnings: Vec<String>,
}

/// Ranks pages against a query with an embeddings client.
pub struct PageRanker {
    client: Arc<dyn EmbeddingsClient>,
    top_n: usize,
}

impl std::fmt::Debug for PageRanker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageRanker")
            .field("top_n", &self.top_n)
            .finish_non_exhaustive()
    }
}

impl PageRanker {
    /// A ranker keeping the `top_n` (at least one) best pages.
    #[must_use]
    pub fn new(client: Arc<dyn EmbeddingsClient>, top_n: usize) -> Self {
        Self {
            client,
            top_n: top_n.max(1),
        }
    }

    /// Pages kept after ranking.
    #[must_use]
    pub const fn top_n(&self) -> usize {
        self.top_n
    }

    /// `docs` ordered by similarity to `query`, cut to [`Self::top_n`]. Fewer than two pages
    /// need no ranking and make no call.
    pub async fn rank(&self, query: &str, docs: Vec<ExtractDocument>) -> RankedPages {
        if docs.len() < 2 {
            return RankedPages {
                docs,
                tokens: 0,
                warnings: Vec::new(),
            };
        }
        let texts: Vec<String> = docs
            .iter()
            .map(|d| format!("{}\n{}", d.url, d.markdown))
            .collect();
        match rank_texts(self.client.as_ref(), query, &texts).await {
            Ok(ranking) => {
                let total = docs.len();
                let mut slots: Vec<Option<ExtractDocument>> = docs.into_iter().map(Some).collect();
                let kept: Vec<ExtractDocument> = ranking
                    .order
                    .iter()
                    .take(self.top_n)
                    .filter_map(|r| slots.get_mut(r.index).and_then(Option::take))
                    .collect();
                let warnings = if kept.len() < total {
                    vec![format!(
                        "embedding ranking sent the {} most relevant of {total} pages to the model",
                        kept.len()
                    )]
                } else {
                    Vec::new()
                };
                RankedPages {
                    docs: kept,
                    tokens: ranking.tokens,
                    warnings,
                }
            }
            Err(error) => {
                tracing::warn!(%error, "embedding ranking failed; pages go to the model in scrape order");
                RankedPages {
                    docs,
                    tokens: 0,
                    warnings: vec![format!(
                        "embedding ranking was skipped ({error}); pages were sent to the model in scrape order"
                    )],
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_model::llm::{EmbeddingsError, MockEmbeddings};

    fn doc(url: &str, text: &str) -> ExtractDocument {
        ExtractDocument {
            url: url.to_owned(),
            markdown: text.to_owned(),
        }
    }

    fn pages() -> Vec<ExtractDocument> {
        vec![
            doc("https://a.test/far", "far away content"),
            doc("https://a.test/near", "near content"),
            doc("https://a.test/mid", "mid content"),
        ]
    }

    fn mock() -> Arc<MockEmbeddings> {
        Arc::new(
            MockEmbeddings::new(2)
                .with_rule("QUERY", vec![1.0, 0.0])
                .with_rule("near", vec![0.95, 0.05])
                .with_rule("mid", vec![0.5, 0.5])
                .with_rule("far", vec![0.0, 1.0]),
        )
    }

    #[tokio::test]
    async fn pages_come_back_in_similarity_order_cut_to_top_n() {
        let client = mock();
        let ranked = PageRanker::new(client.clone(), 2).rank("QUERY", pages()).await;
        let urls: Vec<&str> = ranked.docs.iter().map(|d| d.url.as_str()).collect();
        assert_eq!(urls, ["https://a.test/near", "https://a.test/mid"]);
        assert_eq!(ranked.warnings.len(), 1);
        assert!(
            ranked.warnings[0].contains("2 most relevant of 3"),
            "{:?}",
            ranked.warnings
        );
        assert!(ranked.tokens > 0);
        assert_eq!(client.calls().len(), 1, "one embeddings call for query and pages");
        assert_eq!(client.calls()[0][0], "QUERY");
    }

    #[tokio::test]
    async fn top_n_above_the_page_count_only_reorders() {
        let ranked = PageRanker::new(mock(), 10).rank("QUERY", pages()).await;
        let urls: Vec<&str> = ranked.docs.iter().map(|d| d.url.as_str()).collect();
        assert_eq!(
            urls,
            ["https://a.test/near", "https://a.test/mid", "https://a.test/far"]
        );
        assert!(ranked.warnings.is_empty());
    }

    #[tokio::test]
    async fn fewer_than_two_pages_make_no_call() {
        let client = mock();
        let ranker = PageRanker::new(client.clone(), 3);
        assert!(ranker.rank("QUERY", Vec::new()).await.docs.is_empty());
        assert_eq!(ranker.rank("QUERY", vec![doc("u", "t")]).await.docs.len(), 1);
        assert!(client.calls().is_empty());
    }

    #[tokio::test]
    async fn a_failing_endpoint_keeps_scrape_order_and_warns() {
        let client = Arc::new(MockEmbeddings::new(2).failing(EmbeddingsError::Status { status: 503 }));
        let ranked = PageRanker::new(client, 1).rank("QUERY", pages()).await;
        assert_eq!(ranked.docs.len(), 3, "nothing is dropped without a ranking");
        assert_eq!(ranked.docs[0].url, "https://a.test/far");
        assert!(ranked.warnings[0].contains("HTTP 503"), "{:?}", ranked.warnings);
        assert_eq!(ranked.tokens, 0);
    }

    #[test]
    fn top_n_is_at_least_one() {
        assert_eq!(PageRanker::new(mock(), 0).top_n(), 1);
    }
}
