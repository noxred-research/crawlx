//! Text embeddings for ranking: the [`EmbeddingsClient`] seam, its OpenAI-compatible HTTP client
//! ([`OpenAiEmbeddings`], `POST {base}/embeddings`), a deterministic test double
//! ([`MockEmbeddings`]) and the cosine ranking the `/extract` engine applies to scraped pages
//! before the LLM sees them ([`rank_texts`], [`rank_by_cosine`]).
//!
//! Firecrawl self-host reads `MODEL_EMBEDDING_NAME` to pick the embedding model of its link
//! ranker (`apps/api/src/lib/ranker.ts`: cosine similarity between the search query and each
//! candidate, equal scores keep their original order). The model is served by the same
//! OpenAI-compatible endpoint and key as the chat model, so [`OpenAiEmbeddings`] is configured
//! like [`OpenAiCompatible`](super::OpenAiCompatible).
//!
//! Bounds: at most [`MAX_INPUTS`] texts per [`EmbeddingsClient::embed`] call, sent to the
//! endpoint in batches of `max_batch`, each text cut to `max_input_chars`; the response is
//! size-capped, every vector must be finite and of one dimension, redirects are not followed
//! and the API key is only sent as a bearer header. Neither texts nor vectors are logged.
//!
//! Ranking is deterministic: scores are accumulated in `f64` in index order and ties keep the
//! candidate order, so one input always produces one output.

use super::extractor::truncate_chars;
use async_trait::async_trait;
use crawlx_core::secret::SecretOr;
use parking_lot::Mutex;
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use thiserror::Error;

/// Default per-call time budget (one batch).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default texts per HTTP request.
pub const DEFAULT_MAX_BATCH: usize = 32;
/// Largest `max_batch` accepted (the OpenAI request limit is 2048; 256 keeps bodies small).
pub const MAX_BATCH: usize = 256;
/// Most texts one [`EmbeddingsClient::embed`] call accepts.
pub const MAX_INPUTS: usize = 512;
/// Default longest text (characters) sent per input; longer text is cut.
pub const DEFAULT_MAX_INPUT_CHARS: usize = 8_000;
/// Largest response body accepted from the endpoint.
pub const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// Failures of an embeddings call.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EmbeddingsError {
    /// The call exceeded its time budget.
    #[error("embeddings call timed out after {after_ms} ms")]
    Timeout {
        /// Budget that elapsed, in milliseconds.
        after_ms: u64,
    },
    /// The endpoint could not be reached or the connection failed.
    #[error("embeddings transport error: {0}")]
    Transport(String),
    /// The endpoint answered with a non-success HTTP status.
    #[error("embeddings endpoint returned HTTP {status}")]
    Status {
        /// HTTP status received.
        status: u16,
    },
    /// The reply did not have the documented shape (count, index, dimension, finiteness, size).
    #[error("invalid embeddings output: {0}")]
    InvalidOutput(String),
    /// The request itself is unusable (empty text, too many texts, bad configuration).
    #[error("invalid embeddings request: {0}")]
    InvalidRequest(String),
}

/// Vectors of one [`EmbeddingsClient::embed`] call and the tokens they cost.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Embedded {
    /// One vector per input, in input order; all of one dimension.
    pub vectors: Vec<Vec<f32>>,
    /// Input tokens the endpoint reported (0 when it reports none).
    pub tokens: u64,
}

/// Turns texts into vectors. Object-safe.
#[async_trait]
pub trait EmbeddingsClient: Send + Sync {
    /// One vector per text, in order.
    ///
    /// # Errors
    /// [`EmbeddingsError::InvalidRequest`] for an empty text or more than [`MAX_INPUTS`] texts,
    /// otherwise the failure of the underlying call.
    async fn embed(&self, texts: &[String]) -> Result<Embedded, EmbeddingsError>;
}

/// Settings of an [`OpenAiEmbeddings`] client.
#[derive(Clone)]
pub struct EmbeddingsConfig {
    /// Base URL (`https://api.openai.com/v1`) or a full `.../embeddings` or `.../chat/completions`
    /// URL of the same API.
    pub endpoint: String,
    /// Embedding model name (`MODEL_EMBEDDING_NAME`).
    pub model: String,
    /// Bearer credential, if the endpoint needs one.
    pub api_key: Option<SecretOr<String>>,
    /// Time budget of one HTTP request.
    pub timeout: Duration,
    /// Texts per HTTP request, `1..=`[`MAX_BATCH`].
    pub max_batch: usize,
    /// Longest text (characters) sent per input.
    pub max_input_chars: usize,
}

impl std::fmt::Debug for EmbeddingsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingsConfig")
            .field("endpoint", &"[REDACTED]")
            .field("model", &self.model)
            .field("api_key", &self.api_key)
            .field("timeout", &self.timeout)
            .field("max_batch", &self.max_batch)
            .field("max_input_chars", &self.max_input_chars)
            .finish()
    }
}

impl EmbeddingsConfig {
    /// A config for `endpoint` and `model` with the default timeout, batch and input budget.
    #[must_use]
    pub fn new(endpoint: &str, model: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            model: model.to_owned(),
            api_key: None,
            timeout: DEFAULT_TIMEOUT,
            max_batch: DEFAULT_MAX_BATCH,
            max_input_chars: DEFAULT_MAX_INPUT_CHARS,
        }
    }
}

/// OpenAI-compatible embeddings client (OpenAI, Ollama `/v1`, vLLM, LiteLLM, ...).
pub struct OpenAiEmbeddings {
    client: reqwest::Client,
    url: reqwest::Url,
    model: String,
    api_key: Option<SecretOr<String>>,
    timeout_ms: u64,
    max_batch: usize,
    max_input: usize,
}

impl std::fmt::Debug for OpenAiEmbeddings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiEmbeddings")
            .field("url", &"[REDACTED]")
            .field("model", &self.model)
            .field("api_key", &self.api_key)
            .finish_non_exhaustive()
    }
}

/// The `embeddings` URL of a configured endpoint.
fn embeddings_url(endpoint: &str) -> Result<reqwest::Url, EmbeddingsError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let base = trimmed
        .strip_suffix("/chat/completions")
        .or_else(|| trimmed.strip_suffix("/embeddings"))
        .unwrap_or(trimmed);
    let url = reqwest::Url::parse(&format!("{base}/embeddings"))
        .map_err(|e| EmbeddingsError::InvalidRequest(format!("endpoint: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(EmbeddingsError::InvalidRequest(
            "endpoint must be http or https".to_owned(),
        ));
    }
    Ok(url)
}

#[derive(Deserialize)]
struct Reply {
    data: Vec<Item>,
    #[serde(default)]
    usage: Option<Usage>,
}

#[derive(Deserialize)]
struct Item {
    #[serde(default)]
    index: Option<usize>,
    embedding: Vec<f32>,
}

#[derive(Deserialize, Default)]
struct Usage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    total_tokens: u64,
}

impl OpenAiEmbeddings {
    /// Build the client.
    ///
    /// # Errors
    /// [`EmbeddingsError::InvalidRequest`] for a malformed or non-HTTP endpoint, an empty model
    /// or a `max_batch` outside `1..=`[`MAX_BATCH`]; [`EmbeddingsError::Transport`] when the HTTP
    /// client cannot be built.
    pub fn new(config: EmbeddingsConfig) -> Result<Self, EmbeddingsError> {
        let url = embeddings_url(&config.endpoint)?;
        if config.model.trim().is_empty() {
            return Err(EmbeddingsError::InvalidRequest("model is empty".to_owned()));
        }
        if !(1..=MAX_BATCH).contains(&config.max_batch) {
            return Err(EmbeddingsError::InvalidRequest(format!(
                "max_batch must be between 1 and {MAX_BATCH}"
            )));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .build()
            .map_err(|e| EmbeddingsError::Transport(e.without_url().to_string()))?;
        Ok(Self {
            client,
            url,
            model: config.model,
            api_key: config.api_key,
            timeout_ms: u64::try_from(config.timeout.as_millis()).unwrap_or(u64::MAX),
            max_batch: config.max_batch,
            max_input: config.max_input_chars.max(1),
        })
    }

    fn map_err(&self, e: reqwest::Error) -> EmbeddingsError {
        let e = e.without_url();
        if e.is_timeout() {
            EmbeddingsError::Timeout {
                after_ms: self.timeout_ms,
            }
        } else {
            EmbeddingsError::Transport(e.to_string())
        }
    }

    /// One HTTP request: the vectors of `texts` in order and the tokens reported.
    async fn batch(&self, texts: &[&str]) -> Result<(Vec<Vec<f32>>, u64), EmbeddingsError> {
        let mut request = self.client.post(self.url.clone()).json(&json!({
            "model": self.model,
            "input": texts,
            "encoding_format": "float",
        }));
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key.expose());
        }
        let mut response = request.send().await.map_err(|e| self.map_err(e))?;
        let status = response.status();
        if !status.is_success() {
            return Err(EmbeddingsError::Status {
                status: status.as_u16(),
            });
        }
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| self.map_err(e))? {
            if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(EmbeddingsError::InvalidOutput(format!(
                    "response exceeds {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        let reply: Reply = serde_json::from_slice(&bytes).map_err(|e| {
            EmbeddingsError::InvalidOutput(format!("response is not an embeddings reply: {e}"))
        })?;
        if reply.data.len() != texts.len() {
            return Err(EmbeddingsError::InvalidOutput(format!(
                "{} vectors for {} inputs",
                reply.data.len(),
                texts.len()
            )));
        }
        let mut slots: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        for (position, item) in reply.data.into_iter().enumerate() {
            let index = item.index.unwrap_or(position);
            let Some(slot) = slots.get_mut(index) else {
                return Err(EmbeddingsError::InvalidOutput(format!(
                    "vector index {index} is out of range"
                )));
            };
            if slot.replace(item.embedding).is_some() {
                return Err(EmbeddingsError::InvalidOutput(format!(
                    "vector index {index} appears twice"
                )));
            }
        }
        let vectors: Vec<Vec<f32>> = slots.into_iter().flatten().collect();
        let usage = reply.usage.unwrap_or_default();
        Ok((vectors, usage.prompt_tokens.max(usage.total_tokens)))
    }
}

/// Reject empty, non-finite or inconsistent vectors; `dims` carries the dimension across batches.
fn check_vectors(vectors: &[Vec<f32>], dims: &mut Option<usize>) -> Result<(), EmbeddingsError> {
    for v in vectors {
        if v.is_empty() {
            return Err(EmbeddingsError::InvalidOutput("empty vector".to_owned()));
        }
        if v.iter().any(|x| !x.is_finite()) {
            return Err(EmbeddingsError::InvalidOutput(
                "vector holds a non-finite number".to_owned(),
            ));
        }
        match dims {
            Some(d) if *d != v.len() => {
                return Err(EmbeddingsError::InvalidOutput(format!(
                    "vectors of {} and {} dimensions in one reply",
                    d,
                    v.len()
                )))
            }
            Some(_) => {}
            None => *dims = Some(v.len()),
        }
    }
    Ok(())
}

#[async_trait]
impl EmbeddingsClient for OpenAiEmbeddings {
    async fn embed(&self, texts: &[String]) -> Result<Embedded, EmbeddingsError> {
        check_inputs(texts)?;
        let mut out = Embedded {
            vectors: Vec::with_capacity(texts.len()),
            tokens: 0,
        };
        let mut dims = None;
        for chunk in texts.chunks(self.max_batch) {
            let cut: Vec<&str> = chunk.iter().map(|t| truncate_chars(t, self.max_input)).collect();
            let (vectors, tokens) = self.batch(&cut).await?;
            check_vectors(&vectors, &mut dims)?;
            out.vectors.extend(vectors);
            out.tokens = out.tokens.saturating_add(tokens);
        }
        Ok(out)
    }
}

fn check_inputs(texts: &[String]) -> Result<(), EmbeddingsError> {
    if texts.len() > MAX_INPUTS {
        return Err(EmbeddingsError::InvalidRequest(format!(
            "{} texts exceed the limit of {MAX_INPUTS} per call",
            texts.len()
        )));
    }
    if let Some(i) = texts.iter().position(|t| t.trim().is_empty()) {
        return Err(EmbeddingsError::InvalidRequest(format!("text {i} is empty")));
    }
    Ok(())
}

/// A deterministic [`EmbeddingsClient`] for tests.
///
/// Without a matching rule a text becomes a hashed bag of words: lower-cased alphanumeric words
/// are counted into `dims` buckets chosen by a hash of the word, so texts that share words are
/// cosine-similar and the same text always yields the same vector. A rule
/// ([`Self::with_rule`]) pins the vector of every text that contains its needle (first rule
/// wins), which lets a test dictate the ranking. Every call is recorded.
pub struct MockEmbeddings {
    dims: usize,
    rules: Vec<(String, Vec<f32>)>,
    failure: Option<EmbeddingsError>,
    calls: Mutex<Vec<Vec<String>>>,
}

impl std::fmt::Debug for MockEmbeddings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockEmbeddings")
            .field("dims", &self.dims)
            .field("calls", &self.calls.lock().len())
            .finish_non_exhaustive()
    }
}

impl MockEmbeddings {
    /// A mock producing vectors of `dims` entries (at least one).
    #[must_use]
    pub fn new(dims: usize) -> Self {
        Self {
            dims: dims.max(1),
            rules: Vec::new(),
            failure: None,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Every text containing `needle` embeds to `vector` (zero-padded or cut to the mock's
    /// dimension).
    #[must_use]
    pub fn with_rule(mut self, needle: &str, mut vector: Vec<f32>) -> Self {
        vector.resize(self.dims, 0.0);
        self.rules.push((needle.to_owned(), vector));
        self
    }

    /// Make every call fail with `error`.
    #[must_use]
    pub fn failing(mut self, error: EmbeddingsError) -> Self {
        self.failure = Some(error);
        self
    }

    /// The texts of every call made so far, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<Vec<String>> {
        self.calls.lock().clone()
    }

    fn vector(&self, text: &str) -> Vec<f32> {
        if let Some((_, v)) = self
            .rules
            .iter()
            .find(|(needle, _)| text.contains(needle.as_str()))
        {
            return v.clone();
        }
        let mut v = vec![0.0_f32; self.dims];
        for word in text
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
        {
            let hash = blake3::hash(word.to_lowercase().as_bytes());
            let b = hash.as_bytes();
            let bucket =
                usize::try_from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0) % self.dims;
            v[bucket] += 1.0;
        }
        v
    }
}

#[async_trait]
impl EmbeddingsClient for MockEmbeddings {
    async fn embed(&self, texts: &[String]) -> Result<Embedded, EmbeddingsError> {
        self.calls.lock().push(texts.to_vec());
        if let Some(e) = &self.failure {
            return Err(e.clone());
        }
        check_inputs(texts)?;
        let vectors: Vec<Vec<f32>> = texts.iter().map(|t| self.vector(t)).collect();
        let tokens = texts
            .iter()
            .map(|t| u64::try_from(t.chars().count().div_ceil(4)).unwrap_or(u64::MAX))
            .fold(0_u64, u64::saturating_add);
        Ok(Embedded { vectors, tokens })
    }
}

/// One candidate's place in a ranking.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Ranked {
    /// Position of the candidate in the input slice.
    pub index: usize,
    /// Cosine similarity to the query (`0.0` when either vector is all zeros).
    pub score: f64,
}

/// Cosine similarity of `a` and `b`; `0.0` when either has no magnitude.
///
/// # Errors
/// [`EmbeddingsError::InvalidOutput`] when the vectors differ in length.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> Result<f64, EmbeddingsError> {
    if a.len() != b.len() {
        return Err(EmbeddingsError::InvalidOutput(format!(
            "cannot compare vectors of {} and {} dimensions",
            a.len(),
            b.len()
        )));
    }
    let (mut dot, mut na, mut nb) = (0.0_f64, 0.0_f64, 0.0_f64);
    for (x, y) in a.iter().zip(b) {
        let (x, y) = (f64::from(*x), f64::from(*y));
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    if na == 0.0 || nb == 0.0 {
        return Ok(0.0);
    }
    Ok(dot / (na.sqrt() * nb.sqrt()))
}

/// `candidates` ordered by descending cosine similarity to `query`; equal scores keep their
/// input order.
///
/// # Errors
/// [`EmbeddingsError::InvalidOutput`] when a candidate's dimension differs from the query's.
pub fn rank_by_cosine(query: &[f32], candidates: &[Vec<f32>]) -> Result<Vec<Ranked>, EmbeddingsError> {
    let mut ranked = candidates
        .iter()
        .enumerate()
        .map(|(index, v)| cosine_similarity(query, v).map(|score| Ranked { index, score }))
        .collect::<Result<Vec<_>, _>>()?;
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.index.cmp(&b.index)));
    Ok(ranked)
}

/// A ranking of texts and the tokens it cost.
#[derive(Clone, PartialEq, Debug)]
pub struct Ranking {
    /// Every text, best first.
    pub order: Vec<Ranked>,
    /// Embedding tokens the endpoint reported.
    pub tokens: u64,
}

/// Rank `texts` against `query` with `client` (one `embed` call: the query first, then the
/// texts).
///
/// # Errors
/// [`EmbeddingsError`] from the call, or [`EmbeddingsError::InvalidOutput`] when the client
/// returns the wrong number of vectors or vectors of differing dimensions.
pub async fn rank_texts(
    client: &dyn EmbeddingsClient,
    query: &str,
    texts: &[String],
) -> Result<Ranking, EmbeddingsError> {
    let mut inputs = Vec::with_capacity(texts.len() + 1);
    inputs.push(query.to_owned());
    inputs.extend_from_slice(texts);
    let embedded = client.embed(&inputs).await?;
    let Some((q, rest)) = embedded.vectors.split_first() else {
        return Err(EmbeddingsError::InvalidOutput("no vectors returned".to_owned()));
    };
    if rest.len() != texts.len() {
        return Err(EmbeddingsError::InvalidOutput(format!(
            "{} vectors for {} inputs",
            embedded.vectors.len(),
            inputs.len()
        )));
    }
    Ok(Ranking {
        order: rank_by_cosine(q, rest)?,
        tokens: embedded.tokens,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::Value;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn client(server: &MockServer, tweak: impl FnOnce(&mut EmbeddingsConfig)) -> OpenAiEmbeddings {
        let mut cfg = EmbeddingsConfig::new(&format!("{}/v1", server.uri()), "embed-test");
        cfg.api_key = Some(SecretOr::secret("sk-secret".to_owned()));
        cfg.timeout = Duration::from_secs(5);
        tweak(&mut cfg);
        OpenAiEmbeddings::new(cfg).unwrap()
    }

    fn texts(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Answers an embeddings request with `[len, i]` vectors, optionally shuffled by `index`.
    struct Echo {
        reversed: bool,
    }

    impl Respond for Echo {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let body: Value = request.body_json().unwrap();
            let input = body["input"].as_array().unwrap();
            let mut data: Vec<Value> = input
                .iter()
                .enumerate()
                .map(|(i, t)| {
                    json!({
                        "object": "embedding",
                        "index": i,
                        "embedding": [t.as_str().unwrap().chars().count() as f64, i as f64],
                    })
                })
                .collect();
            if self.reversed {
                data.reverse();
            }
            ResponseTemplate::new(200).set_body_json(json!({
                "data": data,
                "usage": {"prompt_tokens": 3 * input.len(), "total_tokens": 3 * input.len()},
            }))
        }
    }

    #[test]
    fn endpoint_forms_resolve_to_the_embeddings_url() {
        for form in [
            "http://h:1/v1",
            "http://h:1/v1/",
            "http://h:1/v1/embeddings",
            "http://h:1/v1/chat/completions",
        ] {
            assert_eq!(
                embeddings_url(form).unwrap().as_str(),
                "http://h:1/v1/embeddings",
                "{form}"
            );
        }
        assert!(embeddings_url("ftp://h").is_err());
        assert!(embeddings_url("not a url").is_err());
    }

    #[test]
    fn construction_rejects_unusable_settings() {
        let bad_model = EmbeddingsConfig::new("http://h/v1", " ");
        assert!(matches!(
            OpenAiEmbeddings::new(bad_model),
            Err(EmbeddingsError::InvalidRequest(m)) if m.contains("model")
        ));
        for batch in [0, MAX_BATCH + 1] {
            let mut cfg = EmbeddingsConfig::new("http://h/v1", "m");
            cfg.max_batch = batch;
            assert!(matches!(
                OpenAiEmbeddings::new(cfg),
                Err(EmbeddingsError::InvalidRequest(m)) if m.contains("max_batch")
            ));
        }
    }

    #[tokio::test]
    async fn posts_model_and_inputs_with_bearer_and_returns_vectors_in_order() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .and(header("authorization", "Bearer sk-secret"))
            .and(body_partial_json(json!({
                "model": "embed-test",
                "input": ["ab", "cde"],
                "encoding_format": "float",
            })))
            .respond_with(Echo { reversed: true })
            .expect(1)
            .mount(&server)
            .await;
        let got = client(&server, |_| {})
            .embed(&texts(&["ab", "cde"]))
            .await
            .unwrap();
        assert_eq!(
            got.vectors,
            vec![vec![2.0, 0.0], vec![3.0, 1.0]],
            "re-ordered by index"
        );
        assert_eq!(got.tokens, 6);
    }

    #[tokio::test]
    async fn batches_by_max_batch_and_cuts_long_inputs() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/embeddings"))
            .respond_with(Echo { reversed: false })
            .expect(3)
            .mount(&server)
            .await;
        let c = client(&server, |cfg| {
            cfg.max_batch = 2;
            cfg.max_input_chars = 4;
        });
        let got = c
            .embed(&texts(&["aaaaaaaaaa", "b", "c", "d", "e"]))
            .await
            .unwrap();
        assert_eq!(got.vectors.len(), 5);
        assert_eq!(got.vectors[0][0], 4.0, "cut to max_input_chars");
        assert_eq!(got.tokens, 15, "tokens add up over the three requests");
        let sizes: Vec<usize> = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|r| r.body_json::<Value>().unwrap()["input"].as_array().unwrap().len())
            .collect();
        assert_eq!(sizes, [2, 2, 1]);
    }

    #[tokio::test]
    async fn request_limits_are_enforced_before_any_call() {
        let server = MockServer::start().await;
        let c = client(&server, |_| {});
        assert!(matches!(
            c.embed(&texts(&["ok", "  "])).await,
            Err(EmbeddingsError::InvalidRequest(m)) if m.contains("text 1")
        ));
        let many = vec!["x".to_owned(); MAX_INPUTS + 1];
        assert!(matches!(
            c.embed(&many).await,
            Err(EmbeddingsError::InvalidRequest(m)) if m.contains("limit")
        ));
        assert_eq!(c.embed(&[]).await.unwrap(), Embedded::default());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn http_status_and_transport_errors_are_typed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        let c = client(&server, |_| {});
        assert_eq!(
            c.embed(&texts(&["a"])).await,
            Err(EmbeddingsError::Status { status: 429 })
        );
        let dead = OpenAiEmbeddings::new(EmbeddingsConfig::new("http://127.0.0.1:1/v1", "m")).unwrap();
        assert!(matches!(
            dead.embed(&texts(&["a"])).await,
            Err(EmbeddingsError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn a_slow_endpoint_times_out() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(500)))
            .mount(&server)
            .await;
        let c = client(&server, |cfg| cfg.timeout = Duration::from_millis(50));
        assert_eq!(
            c.embed(&texts(&["a"])).await,
            Err(EmbeddingsError::Timeout { after_ms: 50 })
        );
    }

    async fn reply_with(body: Value) -> Result<Embedded, EmbeddingsError> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        client(&server, |_| {}).embed(&texts(&["a", "b"])).await
    }

    #[tokio::test]
    async fn malformed_replies_are_invalid_output() {
        let cases = [
            (
                json!({"data": [{"index": 0, "embedding": [1.0]}]}),
                "1 vectors for 2",
            ),
            (
                json!({"data": [{"index": 0, "embedding": [1.0]}, {"index": 0, "embedding": [1.0]}]}),
                "appears twice",
            ),
            (
                json!({"data": [{"index": 0, "embedding": [1.0]}, {"index": 5, "embedding": [1.0]}]}),
                "out of range",
            ),
            (
                json!({"data": [{"index": 0, "embedding": [1.0]}, {"index": 1, "embedding": [1.0, 2.0]}]}),
                "dimensions",
            ),
            (
                json!({"data": [{"index": 0, "embedding": []}, {"index": 1, "embedding": [1.0]}]}),
                "empty vector",
            ),
            (json!({"nope": true}), "not an embeddings reply"),
        ];
        for (body, needle) in cases {
            match reply_with(body.clone()).await {
                Err(EmbeddingsError::InvalidOutput(m)) => assert!(m.contains(needle), "{body}: {m}"),
                other => panic!("{body}: {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn an_oversize_reply_is_refused() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_RESPONSE_BYTES + 1]))
            .mount(&server)
            .await;
        assert!(matches!(
            client(&server, |_| {}).embed(&texts(&["a"])).await,
            Err(EmbeddingsError::InvalidOutput(m)) if m.contains("exceeds")
        ));
    }

    #[test]
    fn cosine_is_scale_free_and_zero_safe() {
        assert!((cosine_similarity(&[1.0, 0.0], &[2.0, 0.0]).unwrap() - 1.0).abs() < 1e-12);
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 3.0]).unwrap().abs() < 1e-12);
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]).unwrap() + 1.0).abs() < 1e-12);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]).unwrap(), 0.0);
        assert!(cosine_similarity(&[1.0], &[1.0, 2.0]).is_err());
    }

    #[test]
    fn ranking_orders_by_score_and_ties_keep_input_order() {
        let q = [1.0, 0.0];
        let candidates = vec![
            vec![0.0, 1.0], // 0: orthogonal
            vec![1.0, 1.0], // 1: 0.707
            vec![2.0, 0.0], // 2: 1.0
            vec![1.0, 1.0], // 3: ties with 1
            vec![0.0, 0.0], // 4: no magnitude -> 0, ties with 0
        ];
        let order: Vec<usize> = rank_by_cosine(&q, &candidates)
            .unwrap()
            .iter()
            .map(|r| r.index)
            .collect();
        assert_eq!(order, [2, 1, 3, 0, 4]);
        for _ in 0..3 {
            let again: Vec<usize> = rank_by_cosine(&q, &candidates)
                .unwrap()
                .iter()
                .map(|r| r.index)
                .collect();
            assert_eq!(again, order, "deterministic");
        }
        assert!(rank_by_cosine(&q, &[vec![1.0]]).is_err());
        assert!(rank_by_cosine(&q, &[]).unwrap().is_empty());
    }

    #[tokio::test]
    async fn mock_hashes_words_deterministically_and_records_calls() {
        let m = MockEmbeddings::new(16);
        let a = m.embed(&texts(&["rust async runtime"])).await.unwrap().vectors;
        let b = m.embed(&texts(&["Runtime, ASYNC rust!"])).await.unwrap().vectors;
        assert_eq!(a, b, "case and punctuation do not matter");
        let ranking = rank_texts(&m, "rust async", &texts(&["gardening tips", "async rust guide"]))
            .await
            .unwrap();
        assert_eq!(ranking.order[0].index, 1);
        assert_eq!(m.calls().len(), 3);
        assert_eq!(m.calls()[2][0], "rust async", "query goes first");
    }

    #[tokio::test]
    async fn mock_rules_dictate_vectors_and_failures_are_scripted() {
        let m = MockEmbeddings::new(2)
            .with_rule("QUERY", vec![1.0, 0.0])
            .with_rule("near", vec![0.9, 0.1])
            .with_rule("far", vec![0.0, 1.0]);
        let r = rank_texts(&m, "QUERY", &texts(&["far page", "near page"]))
            .await
            .unwrap();
        assert_eq!(r.order.iter().map(|x| x.index).collect::<Vec<_>>(), [1, 0]);
        let failing = MockEmbeddings::new(2).failing(EmbeddingsError::Status { status: 500 });
        assert_eq!(
            rank_texts(&failing, "q", &texts(&["a"])).await,
            Err(EmbeddingsError::Status { status: 500 })
        );
    }
}
