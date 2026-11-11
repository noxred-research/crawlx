//! [`LlmExtractor`] over a chat-completions compatible `chat/completions` endpoint (hosted
//! gateways, local model servers, ...), configured through `CRAWLX_LLM_BASE_URL`,
//! `CRAWLX_LLM_MODEL` and `CRAWLX_LLM_API_KEY`.
//!
//! Requests ask for JSON: `response_format: json_schema` when the caller supplies a schema,
//! `json_object` otherwise, temperature 0. The reply's `choices[0].message.content` is parsed
//! as JSON (a surrounding Markdown code fence is tolerated) and `usage` is returned as the
//! call's token accounting. The API key is sent only as a bearer header, redirects are not
//! followed, the response is size-capped, and neither prompts nor replies are logged.

use super::extractor::{
    Completion, CompletionLimits, LlmError, LlmExtractor, TokenUsage, DEFAULT_MAX_INPUT_CHARS,
};
use async_trait::async_trait;
use crawlx_core::secret::SecretOr;
use serde_json::{json, Value};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Largest response body accepted from the endpoint.
pub const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Default per-call time budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
/// Endpoint used when only an API key is configured (`CRAWLX_LLM_BASE_URL` unset).
pub const DEFAULT_ENDPOINT: &str = "https://api.openai.com/v1"; // wire-compat: default hosted chat-completions endpoint
/// Model used when `CRAWLX_LLM_MODEL` is unset.
pub const DEFAULT_MODEL: &str = "gpt-4o-mini"; // wire-compat: default hosted model id
/// Model used for `audio/transcriptions` when `CRAWLX_TRANSCRIBE_MODEL` is unset.
pub const DEFAULT_TRANSCRIBE_MODEL: &str = "whisper-1"; // wire-compat: default hosted speech-to-text model id
/// Largest audio file [`ChatCompletionsClient::transcribe`] uploads (the `audio/transcriptions`
/// limit); a larger file is refused with [`LlmError::InvalidRequest`] before any network call.
pub const MAX_TRANSCRIBE_BYTES: usize = 25 * 1024 * 1024;

/// Settings of a [`ChatCompletionsClient`].
#[derive(Clone)]
pub struct LlmConfig {
    /// Base URL (`https://host/v1`) or the full `.../chat/completions` URL.
    pub endpoint: String,
    /// Model name sent in every request.
    pub model: String,
    /// Bearer credential, if the endpoint needs one.
    pub api_key: Option<SecretOr<String>>,
    /// Time budget of one call.
    pub timeout: Duration,
    /// Longest page text (characters) sent to the model.
    pub max_input_chars: usize,
    /// Base URL of the speech-to-text endpoint (`http://speech:8000/v1`) or the full
    /// `.../audio/transcriptions` URL; `None` leaves [`LlmExtractor::can_transcribe`] `false`.
    /// The same bearer credential as the chat endpoint is sent.
    pub transcribe_endpoint: Option<String>,
    /// Model sent to the speech-to-text endpoint; `None` is [`DEFAULT_TRANSCRIBE_MODEL`].
    pub transcribe_model: Option<String>,
}

impl std::fmt::Debug for LlmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmConfig")
            .field("endpoint", &"[REDACTED]")
            .field("model", &self.model)
            .field("api_key", &self.api_key)
            .field("timeout", &self.timeout)
            .field("max_input_chars", &self.max_input_chars)
            .field(
                "transcribe_endpoint",
                &self.transcribe_endpoint.as_ref().map(|_| "[REDACTED]"),
            )
            .field("transcribe_model", &self.transcribe_model)
            .finish()
    }
}

impl LlmConfig {
    /// A config for `endpoint` and `model` with the default timeout and input budget.
    #[must_use]
    pub fn new(endpoint: &str, model: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            model: model.to_owned(),
            api_key: None,
            timeout: DEFAULT_TIMEOUT,
            max_input_chars: DEFAULT_MAX_INPUT_CHARS,
            transcribe_endpoint: None,
            transcribe_model: None,
        }
    }

    /// Config from the `CRAWLX_LLM_*` variables, looked up through `lookup`:
    /// `CRAWLX_LLM_BASE_URL`, `CRAWLX_LLM_MODEL`, `CRAWLX_LLM_API_KEY`, plus
    /// `CRAWLX_TRANSCRIBE_ENDPOINT` and `CRAWLX_TRANSCRIBE_MODEL` for the speech-to-text endpoint
    /// of the `audio`/`video` formats.
    /// `None` when neither a base URL nor a key is set (LLM features stay off).
    #[must_use]
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let get = |k: &str| lookup(k).map(|v| v.trim().to_owned()).filter(|v| !v.is_empty());
        let base = get("CRAWLX_LLM_BASE_URL");
        let key = get("CRAWLX_LLM_API_KEY");
        if base.is_none() && key.is_none() {
            return None;
        }
        let mut cfg = Self::new(
            base.as_deref().unwrap_or(DEFAULT_ENDPOINT),
            get("CRAWLX_LLM_MODEL").as_deref().unwrap_or(DEFAULT_MODEL),
        );
        cfg.api_key = key.map(SecretOr::secret);
        cfg.transcribe_endpoint = get("CRAWLX_TRANSCRIBE_ENDPOINT");
        cfg.transcribe_model = get("CRAWLX_TRANSCRIBE_MODEL");
        Some(cfg)
    }

    /// [`Self::from_lookup`] over the process environment.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }
}

/// Chat-completions client implementing [`LlmExtractor`].
pub struct ChatCompletionsClient {
    #[allow(clippy::disallowed_types, reason = "HTTP provider adapter boundary")]
    client: reqwest::Client,
    url: reqwest::Url,
    model: String,
    transcribe_url: Option<reqwest::Url>,
    transcribe_model: String,
    api_key: Option<SecretOr<String>>,
    timeout_ms: u64,
    max_input: usize,
}

impl std::fmt::Debug for ChatCompletionsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatCompletionsClient")
            .field("url", &"[REDACTED]")
            .field("model", &self.model)
            .field(
                "transcribe_url",
                &self.transcribe_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("api_key", &self.api_key)
            .finish_non_exhaustive()
    }
}

/// The `chat/completions` URL for a configured endpoint.
fn completions_url(endpoint: &str) -> Result<reqwest::Url, LlmError> {
    endpoint_url(endpoint, "/chat/completions")
}

/// The `audio/transcriptions` URL for a configured speech-to-text endpoint.
fn transcriptions_url(endpoint: &str) -> Result<reqwest::Url, LlmError> {
    endpoint_url(endpoint, "/audio/transcriptions")
}

/// `endpoint` as an HTTP(S) URL ending in `suffix` (appended unless already present).
fn endpoint_url(endpoint: &str, suffix: &str) -> Result<reqwest::Url, LlmError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    let full = if trimmed.ends_with(suffix) {
        trimmed.to_owned()
    } else {
        format!("{trimmed}{suffix}")
    };
    let url = reqwest::Url::parse(&full).map_err(|e| LlmError::InvalidRequest(format!("endpoint: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(LlmError::InvalidRequest(
            "endpoint must be http or https".to_owned(),
        ));
    }
    Ok(url)
}

/// A `multipart/form-data` body with the `file`, `model` and `response_format=json` fields of an
/// `audio/transcriptions` request, and the boundary it uses. The boundary is a digest of
/// the content, so it is deterministic and cannot occur inside the audio.
fn transcription_form(model: &str, file_name: &str, content_type: &str, audio: &[u8]) -> (String, Vec<u8>) {
    let boundary = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(model.as_bytes());
        hasher.update(file_name.as_bytes());
        hasher.update(audio);
        format!("crawlx-{}", hasher.finalize().to_hex())
    };
    let ascii = |text: &str| -> String {
        text.chars()
            .map(|c| {
                if c.is_ascii_graphic() && c != '"' && c != '\\' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    };
    let mut content_type = ascii(content_type);
    if !content_type.contains('/') {
        "application/octet-stream".clone_into(&mut content_type);
    }
    let mut body = Vec::with_capacity(audio.len() + 512);
    let mut text_field = |name: &str, value: &str| {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n")
                .as_bytes(),
        );
    };
    text_field("model", model);
    text_field("response_format", "json");
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n\
             Content-Type: {content_type}\r\n\r\n",
            ascii(file_name)
        )
        .as_bytes(),
    );
    body.extend_from_slice(audio);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

/// Strip a surrounding Markdown code fence (` ```json ... ``` `), if any.
fn strip_fence(text: &str) -> &str {
    let t = text.trim();
    let Some(rest) = t.strip_prefix("```") else {
        return t;
    };
    let body = rest.split_once('\n').map_or(rest, |(_, b)| b);
    body.trim_end().strip_suffix("```").unwrap_or(body).trim()
}

impl ChatCompletionsClient {
    /// Build the client.
    ///
    /// # Errors
    /// [`LlmError::InvalidRequest`] for a malformed or non-HTTP endpoint,
    /// [`LlmError::Transport`] when the HTTP client cannot be built.
    #[allow(clippy::disallowed_types, reason = "HTTP provider adapter boundary")]
    pub fn new(config: LlmConfig) -> Result<Self, LlmError> {
        let url = completions_url(&config.endpoint)?;
        let transcribe_url = config
            .transcribe_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|e| !e.is_empty())
            .map(transcriptions_url)
            .transpose()
            .map_err(|e| LlmError::InvalidRequest(format!("transcribe {e}")))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.timeout)
            .build()
            .map_err(|e| LlmError::Transport(e.without_url().to_string()))?;
        Ok(Self {
            client,
            url,
            model: config.model,
            transcribe_url,
            transcribe_model: config
                .transcribe_model
                .filter(|m| !m.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_TRANSCRIBE_MODEL.to_owned()),
            api_key: config.api_key,
            timeout_ms: u64::try_from(config.timeout.as_millis()).unwrap_or(u64::MAX),
            max_input: config.max_input_chars,
        })
    }

    fn request_body(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
        limits: CompletionLimits,
    ) -> Value {
        let response_format = match schema {
            Some(s) => json!({
                "type": "json_schema",
                "json_schema": { "name": "result", "schema": s, "strict": false },
            }),
            None => json!({ "type": "json_object" }),
        };
        json!({
            "model": self.model,
            "temperature": 0,
            "max_tokens": limits.max_output_tokens().get(),
            "stream": false,
            "response_format": response_format,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
        })
    }

    #[allow(clippy::disallowed_types, reason = "HTTP provider adapter boundary")]
    fn map_err(&self, e: reqwest::Error) -> LlmError {
        let e = e.without_url();
        if e.is_timeout() {
            LlmError::Timeout {
                after_ms: self.timeout_ms,
            }
        } else {
            LlmError::Transport(e.to_string())
        }
    }

    /// Read chunks under a finite decoded-byte ceiling, without trusting Content-Length.
    #[allow(clippy::disallowed_types, reason = "HTTP provider adapter boundary")]
    async fn read_body(&self, mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, LlmError> {
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(max).unwrap_or(u64::MAX))
        {
            return Err(LlmError::ResponseBytesExceeded { max });
        }
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| self.map_err(e))? {
            if chunk.len() > max.saturating_sub(bytes.len()) {
                return Err(LlmError::ResponseBytesExceeded { max });
            }
            let required = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or(LlmError::ResponseBytesExceeded { max })?;
            if required > bytes.capacity() {
                let capacity = bytes
                    .capacity()
                    .saturating_mul(2)
                    .max(4096)
                    .min(max)
                    .max(required);
                bytes
                    .try_reserve_exact(capacity.saturating_sub(bytes.len()))
                    .map_err(|_| LlmError::InvalidOutput("response allocation failed".to_owned()))?;
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn bounded_request(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
        limits: CompletionLimits,
    ) -> Result<Completion<Value>, LlmError> {
        let mut request = self
            .client
            .post(self.url.clone())
            .json(&self.request_body(system, user, schema, limits));
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key.expose());
        }
        let response = request.send().await.map_err(|e| self.map_err(e))?;
        let status = response.status();
        if !status.is_success() {
            // Never read or retain a provider error body: it can echo the prompt.
            return Err(LlmError::Status {
                status: status.as_u16(),
            });
        }
        // A repeated header must not hide an event stream behind an earlier JSON value.
        if response
            .headers()
            .get_all(reqwest::header::CONTENT_TYPE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|t| t.trim().eq_ignore_ascii_case("text/event-stream"))
            })
        {
            return Err(LlmError::UnsupportedOutputBudget);
        }
        let bytes = self.read_body(response, limits.max_response_bytes()).await?;
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|_| LlmError::InvalidOutput("response is not JSON".to_owned()))?;
        if body
            .get("choices")
            .and_then(Value::as_array)
            .is_none_or(|v| v.len() != 1)
        {
            return Err(LlmError::InvalidOutput(
                "response has no message content or multiple choices".to_owned(),
            ));
        }
        if body.pointer("/choices/0/finish_reason").and_then(Value::as_str) != Some("stop")
            || body
                .pointer("/choices/0/message/refusal")
                .is_some_and(|v| !v.is_null())
            || body
                .pointer("/choices/0/message/tool_calls")
                .is_some_and(|v| !v.is_null())
        {
            return Err(LlmError::TruncatedOutput);
        }
        let content = body
            .pointer("/choices/0/message/content")
            .and_then(Value::as_str)
            .ok_or_else(|| LlmError::InvalidOutput("response has no message content".to_owned()))?;
        let value: Value = serde_json::from_str(strip_fence(content))
            .map_err(|_| LlmError::InvalidOutput("message is not JSON".to_owned()))?;
        let usage = checked_usage(&body, limits)?;
        Ok(Completion { value, usage })
    }
}

fn token(usage: &Value, key: &str) -> u64 {
    usage.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn checked_usage(body: &Value, limits: CompletionLimits) -> Result<TokenUsage, LlmError> {
    let usage = body.get("usage").ok_or(LlmError::InvalidUsage)?;
    let prompt_tokens = usage
        .get("prompt_tokens")
        .and_then(Value::as_u64)
        .ok_or(LlmError::InvalidUsage)?;
    let completion_tokens = usage
        .get("completion_tokens")
        .and_then(Value::as_u64)
        .ok_or(LlmError::InvalidUsage)?;
    if completion_tokens > u64::from(limits.max_output_tokens().get()) {
        return Err(LlmError::OutputTokenLimitExceeded {
            max: limits.max_output_tokens().get(),
        });
    }
    let sum = prompt_tokens
        .checked_add(completion_tokens)
        .ok_or(LlmError::InvalidUsage)?;
    if usage
        .get("total_tokens")
        .is_some_and(|total| total.as_u64() != Some(sum))
    {
        return Err(LlmError::InvalidUsage);
    }
    Ok(TokenUsage {
        prompt_tokens,
        completion_tokens,
    })
}

#[async_trait]
impl LlmExtractor for ChatCompletionsClient {
    async fn complete(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        self.complete_bounded(
            system,
            user,
            schema,
            CompletionLimits::default(),
            &CancellationToken::new(),
        )
        .await
    }

    async fn complete_bounded(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
        limits: CompletionLimits,
        cancel: &CancellationToken,
    ) -> Result<Completion<Value>, LlmError> {
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(LlmError::Cancelled),
            result = self.bounded_request(system, user, schema, limits) => {
                if cancel.is_cancelled() {
                    return Err(LlmError::Cancelled);
                }
                result
            }
        }
    }

    fn max_input_chars(&self) -> usize {
        self.max_input
    }

    fn can_transcribe(&self) -> bool {
        self.transcribe_url.is_some()
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        file_name: &str,
        content_type: &str,
    ) -> Result<Completion<String>, LlmError> {
        let url = self.transcribe_url.clone().ok_or(LlmError::NotConfigured)?;
        if audio.is_empty() {
            return Err(LlmError::InvalidRequest("no audio to transcribe".to_owned()));
        }
        if audio.len() > MAX_TRANSCRIBE_BYTES {
            return Err(LlmError::InvalidRequest(format!(
                "audio exceeds the {MAX_TRANSCRIBE_BYTES} byte transcription limit"
            )));
        }
        let (boundary, body) = transcription_form(&self.transcribe_model, file_name, content_type, audio);
        let mut request = self
            .client
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key.expose());
        }
        let response = request.send().await.map_err(|e| self.map_err(e))?;
        let status = response.status();
        if !status.is_success() {
            return Err(LlmError::Status {
                status: status.as_u16(),
            });
        }
        let bytes = self.read_body(response, MAX_RESPONSE_BYTES).await?;
        let body: Value = serde_json::from_slice(&bytes)
            .map_err(|_| LlmError::InvalidOutput("response is not JSON".to_owned()))?;
        let text = body
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| LlmError::InvalidOutput("response has no `text`".to_owned()))?;
        let usage = body.get("usage").cloned().unwrap_or(Value::Null);
        let pick = |a: &str, b: &str| token(&usage, a).max(token(&usage, b));
        Ok(Completion {
            value: text.trim().to_owned(),
            usage: TokenUsage {
                prompt_tokens: pick("input_tokens", "prompt_tokens"),
                completion_tokens: pick("output_tokens", "completion_tokens"),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn reply(content: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": content}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        }))
    }

    fn client(server: &MockServer, key: Option<&str>) -> ChatCompletionsClient {
        let mut cfg = LlmConfig::new(&format!("{}/v1", server.uri()), "test-model");
        cfg.api_key = key.map(|k| SecretOr::secret(k.to_owned()));
        cfg.timeout = Duration::from_secs(5);
        ChatCompletionsClient::new(cfg).unwrap()
    }

    #[test]
    fn env_lookup_follows_crawlx_llm_variables() {
        assert!(LlmConfig::from_lookup(|_| None).is_none());
        let cfg = LlmConfig::from_lookup(|k| (k == "CRAWLX_LLM_API_KEY").then(|| "sk-x".to_owned())).unwrap();
        assert_eq!(
            (cfg.endpoint.as_str(), cfg.model.as_str()),
            (DEFAULT_ENDPOINT, DEFAULT_MODEL)
        );
        assert!(cfg.api_key.is_some());
        let cfg = LlmConfig::from_lookup(|k| match k {
            "CRAWLX_LLM_BASE_URL" => Some("http://models:11434/v1".to_owned()),
            "CRAWLX_LLM_MODEL" => Some("qwen3".to_owned()),
            _ => None,
        })
        .unwrap();
        assert_eq!(cfg.model, "qwen3");
        assert!(cfg.api_key.is_none());
    }

    #[test]
    fn endpoint_forms_resolve_to_the_completions_url() {
        assert_eq!(
            completions_url("http://h:1/v1/").unwrap().as_str(),
            "http://h:1/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://h/v1/chat/completions").unwrap().as_str(),
            "http://h/v1/chat/completions"
        );
        assert!(completions_url("ftp://h").is_err());
        assert!(completions_url("not a url").is_err());
    }

    #[test]
    fn code_fences_are_stripped() {
        assert_eq!(strip_fence("```json\n{\"a\":1}\n```"), "{\"a\":1}");
        assert_eq!(strip_fence("  {\"a\":1} "), "{\"a\":1}");
        assert_eq!(strip_fence("```\n[1]\n```"), "[1]");
    }

    #[tokio::test]
    async fn posts_schema_request_with_bearer_and_reports_usage() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .and(header("authorization", "Bearer sk-secret"))
            .and(body_partial_json(json!({
                "model": "test-model",
                "temperature": 0,
                "response_format": {"type": "json_schema", "json_schema": {"schema": {"type": "object"}}},
            })))
            .respond_with(reply("{\"title\": \"Hi\"}"))
            .expect(1)
            .mount(&server)
            .await;
        let llm = client(&server, Some("sk-secret"));
        let schema = json!({"type": "object"});
        let got = llm
            .json("# Page", Some(&schema), Some("get the title"))
            .await
            .unwrap();
        assert_eq!(got.value, json!({"title": "Hi"}));
        assert_eq!(
            got.usage,
            TokenUsage {
                prompt_tokens: 11,
                completion_tokens: 7
            }
        );
        assert_eq!(got.usage.total(), 18);
        let sent: Value = server.received_requests().await.unwrap()[0].body_json().unwrap();
        let user = sent["messages"][1]["content"].as_str().unwrap();
        assert!(
            user.contains("get the title") && user.contains("<<DATA\n# Page\nDATA>>"),
            "{user}"
        );
    }

    #[tokio::test]
    async fn no_schema_uses_json_object_mode_and_tolerates_fences() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_partial_json(
                json!({"response_format": {"type": "json_object"}}),
            ))
            .respond_with(reply("```json\n{\"limit\": 5}\n```"))
            .mount(&server)
            .await;
        let llm = client(&server, None);
        let got = llm
            .plan_crawl_options("https://x.test", "five pages")
            .await
            .unwrap();
        assert_eq!(got.value, json!({"limit": 5}));
        assert!(server.received_requests().await.unwrap()[0]
            .headers
            .get("authorization")
            .is_none());
    }

    #[tokio::test]
    async fn failures_are_typed() {
        let server = MockServer::start().await;
        Mock::given(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(429))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(path("/v1/chat/completions"))
            .respond_with(reply("not json"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"choices": []})))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        let llm = client(&server, None);
        assert_eq!(
            llm.complete("s", "u", None).await,
            Err(LlmError::Status { status: 429 })
        );
        assert!(
            matches!(llm.complete("s", "u", None).await, Err(LlmError::InvalidOutput(m)) if m.contains("not JSON"))
        );
        assert!(
            matches!(llm.complete("s", "u", None).await, Err(LlmError::InvalidOutput(m)) if m.contains("no message"))
        );
        let dead = ChatCompletionsClient::new(LlmConfig::new("http://127.0.0.1:1/v1", "m")).unwrap();
        assert!(matches!(
            dead.complete("s", "u", None).await,
            Err(LlmError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn slow_endpoint_times_out() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(reply("{}").set_delay(Duration::from_millis(400)))
            .mount(&server)
            .await;
        let mut cfg = LlmConfig::new(&server.uri(), "m");
        cfg.timeout = Duration::from_millis(100);
        let llm = ChatCompletionsClient::new(cfg).unwrap();
        assert_eq!(
            llm.complete("s", "u", None).await,
            Err(LlmError::Timeout { after_ms: 100 })
        );
    }
}
