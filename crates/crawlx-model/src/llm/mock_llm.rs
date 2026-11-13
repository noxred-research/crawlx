//! A scripted [`LlmExtractor`] for tests: replies come from a queue or from a handler closure,
//! every call is recorded, and token usage is a deterministic estimate (one token per four
//! characters, rounded up).

use super::extractor::{Completion, CompletionLimits, LlmError, LlmExtractor, TokenUsage};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// One recorded call to [`LlmExtractor::complete`].
#[derive(Clone, PartialEq, Debug)]
pub struct LlmCall {
    /// System prompt.
    pub system: String,
    /// User prompt, including fenced data.
    pub user: String,
    /// Structured-output schema, when one was requested.
    pub schema: Option<Value>,
}

/// One recorded call to [`LlmExtractor::transcribe`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TranscribeCall {
    /// File name offered to the endpoint.
    pub file_name: String,
    /// Content type offered to the endpoint.
    pub content_type: String,
    /// The audio bytes.
    pub audio: Vec<u8>,
}

type Handler = dyn Fn(&LlmCall) -> Result<Value, LlmError> + Send + Sync;

enum Source {
    Script(Mutex<VecDeque<Result<Value, LlmError>>>),
    Handler(Arc<Handler>),
}

/// Scripted [`LlmExtractor`].
pub struct MockLlm {
    source: Source,
    calls: Mutex<Vec<LlmCall>>,
    transcript: Option<Result<String, LlmError>>,
    transcriptions: Mutex<Vec<TranscribeCall>>,
    max_input: usize,
    bounded: bool,
    invalid_usage: bool,
}

impl std::fmt::Debug for MockLlm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockLlm")
            .field("calls", &self.calls.lock().len())
            .finish()
    }
}

fn estimate(chars: usize) -> u64 {
    u64::try_from(chars.div_ceil(4)).unwrap_or(u64::MAX)
}

impl MockLlm {
    /// A mock that answers calls in order with `replies`; once the queue is empty a call fails
    /// with [`LlmError::InvalidOutput`].
    #[must_use]
    pub fn scripted(replies: Vec<Result<Value, LlmError>>) -> Self {
        Self {
            source: Source::Script(Mutex::new(replies.into())),
            calls: Mutex::new(Vec::new()),
            transcript: None,
            transcriptions: Mutex::new(Vec::new()),
            max_input: super::extractor::DEFAULT_MAX_INPUT_CHARS,
            bounded: false,
            invalid_usage: false,
        }
    }

    /// As [`Self::scripted`], and the mock supports [`LlmExtractor::complete_bounded`] (limits and
    /// usage are checked against the scripted reply).
    #[must_use]
    pub fn bounded_scripted(replies: Vec<Result<Value, LlmError>>) -> Self {
        let mut mock = Self::scripted(replies);
        mock.bounded = true;
        mock
    }

    /// As [`Self::from_fn`], and the mock supports [`LlmExtractor::complete_bounded`].
    #[must_use]
    pub fn bounded_from_fn(f: impl Fn(&LlmCall) -> Result<Value, LlmError> + Send + Sync + 'static) -> Self {
        let mut mock = Self::from_fn(f);
        mock.bounded = true;
        mock
    }

    /// A mock whose reply is a function of the call (agent loops, per-page answers).
    #[must_use]
    pub fn from_fn(f: impl Fn(&LlmCall) -> Result<Value, LlmError> + Send + Sync + 'static) -> Self {
        Self {
            source: Source::Handler(Arc::new(f)),
            calls: Mutex::new(Vec::new()),
            transcript: None,
            transcriptions: Mutex::new(Vec::new()),
            max_input: super::extractor::DEFAULT_MAX_INPUT_CHARS,
            bounded: false,
            invalid_usage: false,
        }
    }

    /// Change the input budget the provided methods use.
    #[must_use]
    pub const fn with_max_input_chars(mut self, max: usize) -> Self {
        self.max_input = max;
        self
    }

    /// Make a bounded mock's [`LlmExtractor::complete_bounded`] fail with [`LlmError::InvalidUsage`],
    /// as a provider that reports no token usage does.
    #[must_use]
    pub const fn with_invalid_usage(mut self) -> Self {
        self.invalid_usage = true;
        self
    }

    /// Make [`LlmExtractor::can_transcribe`] true and answer every
    /// [`LlmExtractor::transcribe`] with `text`.
    #[must_use]
    pub fn with_transcript(mut self, text: &str) -> Self {
        self.transcript = Some(Ok(text.to_owned()));
        self
    }

    /// Make [`LlmExtractor::can_transcribe`] true and fail every [`LlmExtractor::transcribe`]
    /// with `error`.
    #[must_use]
    pub fn with_transcript_error(mut self, error: LlmError) -> Self {
        self.transcript = Some(Err(error));
        self
    }

    /// Every call made so far, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<LlmCall> {
        self.calls.lock().clone()
    }

    /// Every transcription requested so far, oldest first.
    #[must_use]
    pub fn transcriptions(&self) -> Vec<TranscribeCall> {
        self.transcriptions.lock().clone()
    }
}

#[async_trait]
impl LlmExtractor for MockLlm {
    async fn complete(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        let call = LlmCall {
            system: system.to_owned(),
            user: user.to_owned(),
            schema: schema.cloned(),
        };
        let reply = match &self.source {
            Source::Script(q) => q
                .lock()
                .pop_front()
                .unwrap_or_else(|| Err(LlmError::InvalidOutput("mock script exhausted".to_owned()))),
            Source::Handler(h) => h(&call),
        };
        self.calls.lock().push(call);
        let value = reply?;
        let usage = TokenUsage {
            prompt_tokens: estimate(system.chars().count() + user.chars().count()),
            completion_tokens: estimate(value.to_string().chars().count()),
        };
        Ok(Completion { value, usage })
    }

    async fn complete_bounded(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
        limits: CompletionLimits,
        cancel: &CancellationToken,
    ) -> Result<Completion<Value>, LlmError> {
        if cancel.is_cancelled() {
            return Err(LlmError::Cancelled);
        }
        if !self.bounded {
            return Err(LlmError::UnsupportedOutputBudget);
        }
        let completion = self.complete(system, user, schema).await?;
        if self.invalid_usage {
            return Err(LlmError::InvalidUsage);
        }
        let max_tokens = u64::from(limits.max_output_tokens().get());
        if completion.usage.completion_tokens > max_tokens {
            return Err(LlmError::OutputTokenLimitExceeded {
                max: limits.max_output_tokens().get(),
            });
        }
        let max_bytes = limits.max_response_bytes();
        if completion.value.to_string().len() > max_bytes {
            return Err(LlmError::ResponseBytesExceeded { max: max_bytes });
        }
        Ok(completion)
    }

    fn max_input_chars(&self) -> usize {
        self.max_input
    }

    fn can_transcribe(&self) -> bool {
        self.transcript.is_some()
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        file_name: &str,
        content_type: &str,
    ) -> Result<Completion<String>, LlmError> {
        let reply = self.transcript.clone().unwrap_or(Err(LlmError::NotConfigured));
        self.transcriptions.lock().push(TranscribeCall {
            file_name: file_name.to_owned(),
            content_type: content_type.to_owned(),
            audio: audio.to_vec(),
        });
        let value = reply?;
        let usage = TokenUsage {
            prompt_tokens: 0,
            completion_tokens: estimate(value.chars().count()),
        };
        Ok(Completion { value, usage })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn script_is_consumed_in_order_and_recorded() {
        let m = MockLlm::scripted(vec![Ok(json!({"a": 1})), Err(LlmError::Timeout { after_ms: 5 })]);
        let first = m.complete("sys", "abcd", None).await.unwrap();
        assert_eq!(first.value, json!({"a": 1}));
        assert_eq!(first.usage.prompt_tokens, 2, "7 chars -> 2 tokens");
        assert_eq!(
            m.complete("s", "u", None).await,
            Err(LlmError::Timeout { after_ms: 5 })
        );
        assert!(matches!(
            m.complete("s", "u", None).await,
            Err(LlmError::InvalidOutput(_))
        ));
        assert_eq!(m.calls().len(), 3);
    }

    #[tokio::test]
    async fn handler_sees_the_call() {
        let m = MockLlm::from_fn(|c| Ok(json!({"len": c.user.len()})));
        assert_eq!(
            m.complete("s", "four", None).await.unwrap().value,
            json!({"len": 4})
        );
    }
}
