//! The `--ai-*` flags of `crawl` (compatibility flags `-ai-url`, `-ai-model`, `-ai-key`, `-ai-record`,
//! `-ai-replay`, `-ai-max-calls`): a chat-completions compatible model that decides values for form
//! fields the automatic form filler cannot classify.

use anyhow::{bail, Context, Result};
use clap::Args;
use crawlx_core::secret::SecretOr;
use crawlx_model::llm::chat_completions::{ChatCompletionsClient, LlmConfig};
use crawlx_model::llm::LlmExtractor;
use crawlx_model::llm_cache::{CallCap, Offline, RecordingLlm};
use crawlx_worker::surface::form_ai::{FormAi, LlmFormAi};
use std::path::PathBuf;
use std::sync::Arc;

/// Environment variable the API key is read from when `--ai-key-env` is not given (the
/// compatibility flags' default).
pub const DEFAULT_KEY_ENV: &str = "AI_API_KEY"; // wire-compat: environment variable existing scripts set

/// Most model calls per crawl when `--ai-max-calls` is not given (the compatibility default); `0`
/// lifts the limit.
pub const DEFAULT_MAX_CALLS: u64 = 100;

/// AI form-decision flags. All are optional; with none given the crawl makes no model calls.
#[derive(Args, Debug, Clone, Default, PartialEq, Eq)]
#[command(next_help_heading = "AI")]
pub struct AiArgs {
    /// Chat-completions compatible API base URL used to decide form field values
    /// (e.g. http://127.0.0.1:11434/v1). Needs --ai-model.
    #[arg(long, value_name = "URL", env = "AI_URL")]
    pub ai_url: Option<String>,
    /// Model to use with --ai-url.
    #[arg(long, value_name = "MODEL", env = "AI_MODEL")]
    pub ai_model: Option<String>,
    /// Name of the environment variable holding the API key of --ai-url (the key is never a flag
    /// value). Defaults to AI_API_KEY when that variable is set.
    #[arg(long, value_name = "VAR")]
    pub ai_key_env: Option<String>,
    /// File to record model answers to (JSON Lines, no prompts or keys); answers already in it
    /// are reused instead of asking the model again.
    #[arg(long, value_name = "FILE", conflicts_with = "ai_replay")]
    pub ai_record: Option<PathBuf>,
    /// File to replay recorded model answers from, without calling any API (needs no --ai-url;
    /// a form the file has no answer for gets no AI values).
    #[arg(long, value_name = "FILE")]
    pub ai_replay: Option<PathBuf>,
    /// Most model calls per crawl; 0 means unlimited [default: 100].
    #[arg(long, value_name = "N")]
    pub ai_max_calls: Option<u64>,
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

impl AiArgs {
    /// `true` when no `--ai-*` flag (or `AI_URL`/`AI_MODEL`) was given.
    #[must_use]
    pub const fn is_unset(&self) -> bool {
        self.ai_url.is_none()
            && self.ai_model.is_none()
            && self.ai_key_env.is_none()
            && self.ai_record.is_none()
            && self.ai_replay.is_none()
            && self.ai_max_calls.is_none()
    }

    /// The form decider these flags describe, or `None` when no AI flag is set.
    ///
    /// With `--ai-replay` answers come only from the file and no network is used (any URL,
    /// model, key or call cap is ignored); otherwise the decider asks the chat-completions compatible
    /// endpoint, through a recording when `--ai-record` is set, and stops after
    /// `--ai-max-calls` calls. The API key is read from the environment variable named by
    /// `--ai-key-env` (default `AI_API_KEY`).
    ///
    /// # Errors
    /// `--ai-record` together with `--ai-replay`; no `--ai-url` or no `--ai-model` without
    /// `--ai-replay`; an unusable URL; `--ai-key-env` naming an unset or empty variable; an
    /// unreadable or corrupt recording.
    pub fn settings(&self) -> Result<Option<Arc<dyn FormAi>>> {
        self.settings_with(&|name| std::env::var(name).ok())
    }

    /// [`Self::settings`] reading environment variables through `env`.
    ///
    /// # Errors
    /// See [`Self::settings`].
    pub fn settings_with(&self, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Arc<dyn FormAi>>> {
        if self.is_unset() {
            return Ok(None);
        }
        if self.ai_record.is_some() && self.ai_replay.is_some() {
            bail!("--ai-record and --ai-replay are mutually exclusive");
        }
        let llm: Arc<dyn LlmExtractor> = if let Some(path) = &self.ai_replay {
            let replay = RecordingLlm::replay(Offline, path)
                .with_context(|| format!("--ai-replay {}", path.display()))?;
            Arc::new(replay)
        } else {
            let client = self.client(env)?;
            let cap = CallCap::from_flag(self.ai_max_calls.unwrap_or(DEFAULT_MAX_CALLS));
            match &self.ai_record {
                Some(path) => Arc::new(
                    RecordingLlm::record(client, path, cap)
                        .with_context(|| format!("--ai-record {}", path.display()))?,
                ),
                None => Arc::new(RecordingLlm::passthrough(client, cap)),
            }
        };
        Ok(Some(Arc::new(LlmFormAi::new(llm))))
    }

    fn client(&self, env: &dyn Fn(&str) -> Option<String>) -> Result<ChatCompletionsClient> {
        let Some(url) = non_empty(self.ai_url.as_deref()) else {
            bail!("the --ai-* flags need --ai-url (or --ai-replay FILE to answer from a recording)");
        };
        let Some(model) = non_empty(self.ai_model.as_deref()) else {
            bail!("--ai-url needs --ai-model");
        };
        let mut config = LlmConfig::new(url, model);
        config.api_key = self.api_key(env)?.map(SecretOr::secret);
        ChatCompletionsClient::new(config).context("--ai-url")
    }

    fn api_key(&self, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<String>> {
        match self.ai_key_env.as_deref().map(str::trim) {
            Some("") => bail!("--ai-key-env needs the name of an environment variable"),
            Some(var) => match non_empty(env(var).as_deref()) {
                Some(key) => Ok(Some(key.to_owned())),
                None => bail!("--ai-key-env {var}: the environment variable is not set or is empty"),
            },
            None => Ok(non_empty(env(DEFAULT_KEY_ENV).as_deref()).map(str::to_owned)),
        }
    }
}
