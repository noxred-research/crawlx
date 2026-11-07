//! Per-step provider routing of the `/extract` and `json` LLM step (Firecrawl self-host
//! `EXTRACTION_PROVIDER_*`, `apps/api/src/lib/extraction-provider.ts`).
//!
//! An operator can point the JSON-extraction step at a second OpenAI-compatible endpoint while
//! every other LLM step (`summary`, `question`, `highlights`, `query`, crawl planning, the agent,
//! monitor judging) keeps the default model. Which requests take the second endpoint is decided
//! by [`ExtractionPolicy::route`], a port of upstream's `selectExtractionRoute`:
//!
//! * a tenant lands in a stable cohort bucket `0..100` ([`cohort_bucket`]), so a rollout
//!   percentage selects the same tenants every time and can be widened without reshuffling;
//! * buckets below `rollout_percent` are routed to the provider, the next `shadow_percent`
//!   buckets are mirrored (the provider is called, its answer is discarded, only the outcome is
//!   logged), tenants listed in `team_ids` are always routed;
//! * zero-data-retention requests and inputs over `max_input_bytes` stay on the default model.
//!
//! A routed request that fails on the provider (transport, status, timeout, unusable output) is
//! answered by the default model instead, as upstream does ("per-request fallback").

use super::extractor::{Completion, ExtractDocument, LlmError, LlmExtractor};
use async_trait::async_trait;
use crawlx_core::scrape::QueryMode;
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;
use thiserror::Error;

/// Default `max_input_bytes`: larger inputs stay on the default model (upstream 400 000).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 400_000;

/// An invalid [`ExtractionPolicy`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PolicyError {
    /// A percentage is above 100.
    #[error("{name} is {value}, expected 0 to 100")]
    Percent {
        /// Which percentage.
        name: &'static str,
        /// The offending value.
        value: u16,
    },
    /// Rollout and shadow shares overlap.
    #[error("rollout percent ({rollout}) plus shadow percent ({shadow}) must not exceed 100")]
    Overlap {
        /// Rollout share.
        rollout: u8,
        /// Shadow share.
        shadow: u8,
    },
}

/// Where one request goes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    /// The extraction provider answers; the default model answers if it fails.
    Provider,
    /// The default model answers and the provider is called on the side (answer discarded).
    Shadow,
    /// The default model answers.
    Default,
}

/// Who is routed to the extraction provider.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct ExtractionPolicy {
    rollout_percent: u8,
    shadow_percent: u8,
    team_ids: BTreeSet<String>,
    max_input_bytes: usize,
}

impl ExtractionPolicy {
    /// A policy routing `rollout_percent` of the tenants and always the `team_ids`, mirroring the
    /// next `shadow_percent`, for inputs up to `max_input_bytes`.
    ///
    /// # Errors
    /// [`PolicyError`] for a percentage above 100 or shares that add up past 100.
    pub fn new(
        rollout_percent: u8,
        shadow_percent: u8,
        team_ids: impl IntoIterator<Item = String>,
        max_input_bytes: usize,
    ) -> Result<Self, PolicyError> {
        for (name, value) in [
            ("rollout percent", rollout_percent),
            ("shadow percent", shadow_percent),
        ] {
            if value > 100 {
                return Err(PolicyError::Percent {
                    name,
                    value: u16::from(value),
                });
            }
        }
        if u16::from(rollout_percent) + u16::from(shadow_percent) > 100 {
            return Err(PolicyError::Overlap {
                rollout: rollout_percent,
                shadow: shadow_percent,
            });
        }
        Ok(Self {
            rollout_percent,
            shadow_percent,
            team_ids: team_ids.into_iter().filter(|t| !t.is_empty()).collect(),
            max_input_bytes,
        })
    }

    /// Where a request of `team` with `input_bytes` of page text goes.
    #[must_use]
    pub fn route(&self, team: &str, zero_data_retention: bool, input_bytes: usize) -> Route {
        if zero_data_retention || input_bytes > self.max_input_bytes || team.is_empty() {
            return Route::Default;
        }
        if self.team_ids.contains(team) {
            return Route::Provider;
        }
        let bucket = u16::from(cohort_bucket(team));
        let rollout = u16::from(self.rollout_percent);
        if bucket < rollout {
            Route::Provider
        } else if bucket < rollout + u16::from(self.shadow_percent) {
            Route::Shadow
        } else {
            Route::Default
        }
    }
}

/// The stable cohort bucket `0..100` of `team`: the first four bytes of its BLAKE3 digest, read
/// big-endian, modulo 100 (upstream uses SHA-1 the same way, so individual buckets differ).
#[must_use]
pub fn cohort_bucket(team: &str) -> u8 {
    let digest = blake3::hash(team.as_bytes());
    let b = digest.as_bytes();
    let n = u32::from_be_bytes([b[0], b[1], b[2], b[3]]) % 100;
    u8::try_from(n).unwrap_or(0)
}

/// Chooses, per request, the LLM that answers the extraction step.
pub struct ExtractionRouter {
    default: Arc<dyn LlmExtractor>,
    provider: Arc<dyn LlmExtractor>,
    policy: ExtractionPolicy,
}

impl std::fmt::Debug for ExtractionRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractionRouter")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl ExtractionRouter {
    /// A router between `default` (the model of every other step, and the fallback) and
    /// `provider` according to `policy`.
    #[must_use]
    pub fn new(
        default: Arc<dyn LlmExtractor>,
        provider: Arc<dyn LlmExtractor>,
        policy: ExtractionPolicy,
    ) -> Self {
        Self {
            default,
            provider,
            policy,
        }
    }

    /// The routing policy.
    #[must_use]
    pub const fn policy(&self) -> &ExtractionPolicy {
        &self.policy
    }

    /// The LLM that answers an extraction step of `team` over `input_bytes` of page text.
    #[must_use]
    pub fn select(&self, team: &str, zero_data_retention: bool, input_bytes: usize) -> Arc<dyn LlmExtractor> {
        match self.policy.route(team, zero_data_retention, input_bytes) {
            Route::Default => Arc::clone(&self.default),
            Route::Provider => Arc::new(Fallback {
                primary: Arc::clone(&self.provider),
                fallback: Arc::clone(&self.default),
            }),
            Route::Shadow => Arc::new(Shadow {
                primary: Arc::clone(&self.default),
                mirror: Arc::clone(&self.provider),
            }),
        }
    }

    /// An LLM for one page's scrape formats: only the JSON-extraction step (`json`, `extract`) is
    /// answered by what [`Self::select`] picks, every other step (`summary`, `answer`,
    /// `highlights`, crawl planning, ...) by the default model.
    #[must_use]
    pub fn per_step(
        &self,
        team: &str,
        zero_data_retention: bool,
        input_bytes: usize,
    ) -> Arc<dyn LlmExtractor> {
        if self.policy.route(team, zero_data_retention, input_bytes) == Route::Default {
            return Arc::clone(&self.default);
        }
        Arc::new(PerStep {
            default: Arc::clone(&self.default),
            extraction: self.select(team, zero_data_retention, input_bytes),
        })
    }
}

/// `default` answers every step except JSON extraction, which `extraction` answers.
struct PerStep {
    default: Arc<dyn LlmExtractor>,
    extraction: Arc<dyn LlmExtractor>,
}

#[async_trait]
impl LlmExtractor for PerStep {
    async fn complete(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        self.default.complete(system, user, schema).await
    }

    fn max_input_chars(&self) -> usize {
        self.default.max_input_chars()
    }

    async fn json(
        &self,
        input: &str,
        schema: Option<&Value>,
        prompt: Option<&str>,
    ) -> Result<Completion<Value>, LlmError> {
        self.extraction.json(input, schema, prompt).await
    }

    async fn extract(
        &self,
        documents: &[ExtractDocument],
        prompt: Option<&str>,
        schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        self.extraction.extract(documents, prompt, schema).await
    }

    // Every other step is the default model's, whatever it overrides itself.

    fn can_transcribe(&self) -> bool {
        self.default.can_transcribe()
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        file_name: &str,
        content_type: &str,
    ) -> Result<Completion<String>, LlmError> {
        self.default.transcribe(audio, file_name, content_type).await
    }

    async fn summary(&self, input: &str) -> Result<Completion<String>, LlmError> {
        self.default.summary(input).await
    }

    async fn answer(&self, input: &str, question: &str) -> Result<Completion<String>, LlmError> {
        self.default.answer(input, question).await
    }

    async fn highlights(&self, input: &str, query: &str) -> Result<Completion<Vec<String>>, LlmError> {
        self.default.highlights(input, query).await
    }

    async fn query(
        &self,
        input: &str,
        prompt: &str,
        mode: QueryMode,
    ) -> Result<Completion<String>, LlmError> {
        self.default.query(input, prompt, mode).await
    }

    async fn clean_markdown(&self, input: &str) -> Result<Completion<String>, LlmError> {
        self.default.clean_markdown(input).await
    }

    async fn plan_crawl_options(&self, url: &str, prompt: &str) -> Result<Completion<Value>, LlmError> {
        self.default.plan_crawl_options(url, prompt).await
    }
}

/// Answers with `primary`; when it fails the same call goes to `fallback`.
struct Fallback {
    primary: Arc<dyn LlmExtractor>,
    fallback: Arc<dyn LlmExtractor>,
}

#[async_trait]
impl LlmExtractor for Fallback {
    async fn complete(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        match self.primary.complete(system, user, schema).await {
            Ok(done) => Ok(done),
            Err(error) => {
                tracing::warn!(%error, "extraction provider failed; answering with the default model");
                self.fallback.complete(system, user, schema).await
            }
        }
    }

    fn max_input_chars(&self) -> usize {
        self.primary.max_input_chars()
    }

    fn can_transcribe(&self) -> bool {
        self.primary.can_transcribe() || self.fallback.can_transcribe()
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        file_name: &str,
        content_type: &str,
    ) -> Result<Completion<String>, LlmError> {
        if self.primary.can_transcribe() {
            match self.primary.transcribe(audio, file_name, content_type).await {
                Ok(done) => return Ok(done),
                Err(error) if self.fallback.can_transcribe() => {
                    tracing::warn!(%error, "transcription provider failed; transcribing with the default model");
                }
                Err(error) => return Err(error),
            }
        }
        self.fallback.transcribe(audio, file_name, content_type).await
    }
}

/// Answers with `primary` and calls `mirror` with the same request on the side.
struct Shadow {
    primary: Arc<dyn LlmExtractor>,
    mirror: Arc<dyn LlmExtractor>,
}

#[async_trait]
impl LlmExtractor for Shadow {
    async fn complete(
        &self,
        system: &str,
        user: &str,
        schema: Option<&Value>,
    ) -> Result<Completion<Value>, LlmError> {
        // The mirror deliberately outlives the request that triggered it (its answer is discarded)
        // and is bounded by the provider client's own timeout, so it is not tied to a task scope.
        let mirror = Arc::clone(&self.mirror);
        let (sys, usr, sch) = (system.to_owned(), user.to_owned(), schema.cloned());
        tokio::spawn(async move {
            match mirror.complete(&sys, &usr, sch.as_ref()).await {
                Ok(done) => tracing::info!(
                    outcome = "ok",
                    prompt_tokens = done.usage.prompt_tokens,
                    completion_tokens = done.usage.completion_tokens,
                    "extraction shadow call finished"
                ),
                Err(error) => tracing::info!(outcome = "error", %error, "extraction shadow call finished"),
            }
        });
        self.primary.complete(system, user, schema).await
    }

    fn max_input_chars(&self) -> usize {
        self.primary.max_input_chars()
    }

    /// Audio is never mirrored to the shadow provider: only `primary` transcribes.
    fn can_transcribe(&self) -> bool {
        self.primary.can_transcribe()
    }

    async fn transcribe(
        &self,
        audio: &[u8],
        file_name: &str,
        content_type: &str,
    ) -> Result<Completion<String>, LlmError> {
        self.primary.transcribe(audio, file_name, content_type).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::llm::MockLlm;
    use serde_json::json;
    use std::time::Duration;

    fn policy(rollout: u8, shadow: u8, teams: &[&str], max: usize) -> ExtractionPolicy {
        ExtractionPolicy::new(rollout, shadow, teams.iter().map(|t| (*t).to_owned()), max).unwrap()
    }

    /// A tenant name in cohort bucket `want`.
    fn team_in_bucket(want: u8) -> String {
        (0..10_000)
            .map(|i| format!("team-{i}"))
            .find(|t| cohort_bucket(t) == want)
            .unwrap()
    }

    #[test]
    fn invalid_policies_are_rejected() {
        assert_eq!(
            ExtractionPolicy::new(101, 0, [], 1),
            Err(PolicyError::Percent {
                name: "rollout percent",
                value: 101
            })
        );
        assert_eq!(
            ExtractionPolicy::new(60, 41, [], 1),
            Err(PolicyError::Overlap {
                rollout: 60,
                shadow: 41
            })
        );
        assert!(ExtractionPolicy::new(60, 40, [], 1).is_ok());
    }

    #[test]
    fn buckets_are_stable_and_spread() {
        assert_eq!(cohort_bucket("acme"), cohort_bucket("acme"));
        let distinct: BTreeSet<u8> = (0..500).map(|i| cohort_bucket(&format!("t{i}"))).collect();
        assert!(
            distinct.len() > 60,
            "500 tenants cover most of 100 buckets: {}",
            distinct.len()
        );
        assert!(distinct.iter().all(|b| *b < 100));
    }

    #[test]
    fn route_follows_the_documented_order() {
        let t10 = team_in_bucket(10);
        let t55 = team_in_bucket(55);
        let t90 = team_in_bucket(90);
        let p = policy(20, 50, &[], 100);
        assert_eq!(p.route(&t10, false, 1), Route::Provider, "bucket 10 < 20");
        assert_eq!(p.route(&t55, false, 1), Route::Shadow, "20 <= 55 < 70");
        assert_eq!(p.route(&t90, false, 1), Route::Default);
        assert_eq!(p.route(&t10, true, 1), Route::Default, "zero data retention");
        assert_eq!(p.route(&t10, false, 101), Route::Default, "input over the cap");
        assert_eq!(p.route(&t10, false, 100), Route::Provider, "cap is inclusive");
        assert_eq!(p.route("", false, 1), Route::Default, "no team");
        let listed = policy(0, 0, &[t90.as_str()], 100);
        assert_eq!(
            listed.route(&t90, false, 1),
            Route::Provider,
            "listed teams are always routed"
        );
        assert_eq!(
            listed.route(&t90, true, 1),
            Route::Default,
            "...except zero data retention"
        );
        assert_eq!(listed.route(&t10, false, 1), Route::Default);
        assert_eq!(ExtractionPolicy::default().route(&t10, false, 0), Route::Default);
    }

    #[test]
    fn raising_the_rollout_only_adds_teams() {
        let teams: Vec<String> = (0..200).map(|i| format!("t{i}")).collect();
        let routed = |pct| -> BTreeSet<&String> {
            let p = policy(pct, 0, &[], 10);
            teams
                .iter()
                .filter(|t| p.route(t, false, 1) == Route::Provider)
                .collect()
        };
        let (a, b) = (routed(10), routed(40));
        assert!(a.is_subset(&b) && b.len() > a.len());
        assert_eq!(routed(100).len(), teams.len());
        assert!(routed(0).is_empty());
    }

    fn router(default: &Arc<MockLlm>, provider: &Arc<MockLlm>, p: ExtractionPolicy) -> ExtractionRouter {
        ExtractionRouter::new(default.clone(), provider.clone(), p)
    }

    #[tokio::test]
    async fn a_routed_request_is_answered_by_the_provider_only() {
        let default = Arc::new(MockLlm::scripted(vec![Ok(json!({"from": "default"}))]));
        let provider = Arc::new(MockLlm::scripted(vec![Ok(json!({"from": "provider"}))]));
        let r = router(&default, &provider, policy(100, 0, &[], 1_000));
        let llm = r.select("acme", false, 10);
        let got = llm.json("page", None, Some("title")).await.unwrap();
        assert_eq!(got.value, json!({"from": "provider"}));
        assert_eq!((provider.calls().len(), default.calls().len()), (1, 0));
    }

    #[tokio::test]
    async fn an_unrouted_request_never_touches_the_provider() {
        let default = Arc::new(MockLlm::scripted(vec![Ok(json!({"from": "default"}))]));
        let provider = Arc::new(MockLlm::scripted(vec![]));
        let r = router(&default, &provider, policy(0, 0, &[], 1_000));
        let got = r
            .select("acme", false, 10)
            .json("page", None, Some("t"))
            .await
            .unwrap();
        assert_eq!(got.value, json!({"from": "default"}));
        assert!(provider.calls().is_empty());
    }

    #[tokio::test]
    async fn a_failing_provider_falls_back_to_the_default_model() {
        let default = Arc::new(MockLlm::scripted(vec![Ok(json!({"from": "default"}))]));
        let provider = Arc::new(MockLlm::scripted(vec![Err(LlmError::Status { status: 503 })]));
        let r = router(&default, &provider, policy(100, 0, &[], 1_000));
        let got = r
            .select("acme", false, 10)
            .json("page", None, Some("t"))
            .await
            .unwrap();
        assert_eq!(got.value, json!({"from": "default"}));
        assert_eq!((provider.calls().len(), default.calls().len()), (1, 1));
    }

    #[tokio::test]
    async fn both_failing_reports_the_default_models_error() {
        let default = Arc::new(MockLlm::scripted(vec![Err(LlmError::Status { status: 500 })]));
        let provider = Arc::new(MockLlm::scripted(vec![Err(LlmError::Status { status: 503 })]));
        let r = router(&default, &provider, policy(100, 0, &[], 1_000));
        let err = r
            .select("acme", false, 10)
            .json("p", None, Some("t"))
            .await
            .unwrap_err();
        assert_eq!(err, LlmError::Status { status: 500 });
    }

    #[tokio::test]
    async fn only_the_json_steps_move_to_the_provider() {
        use crate::llm::ExtractDocument;
        let default = Arc::new(MockLlm::from_fn(|c| {
            Ok(if c.user.contains("Summarize") {
                json!({"summary": "from default"})
            } else if c.user.contains("Answer the question") {
                json!({"answer": "from default"})
            } else {
                json!({"highlights": ["from default"]})
            })
        }));
        let provider = Arc::new(MockLlm::from_fn(|_| Ok(json!({"from": "provider"}))));
        let r = router(&default, &provider, policy(100, 0, &[], 1_000));
        let llm = r.per_step("acme", false, 10);

        assert_eq!(
            llm.json("page", None, Some("t")).await.unwrap().value,
            json!({"from": "provider"})
        );
        let docs = [ExtractDocument {
            url: "https://a.test".to_owned(),
            markdown: "text".to_owned(),
        }];
        assert_eq!(
            llm.extract(&docs, Some("t"), None).await.unwrap().value,
            json!({"from": "provider"})
        );
        assert_eq!(provider.calls().len(), 2);
        assert!(
            default.calls().is_empty(),
            "json and extract never reach the default model"
        );

        assert_eq!(llm.summary("page").await.unwrap().value, "from default");
        assert_eq!(llm.answer("page", "what?").await.unwrap().value, "from default");
        assert_eq!(llm.highlights("page", "q").await.unwrap().value, ["from default"]);
        assert_eq!(
            default.calls().len(),
            3,
            "every other step uses the default model"
        );
        assert_eq!(provider.calls().len(), 2, "...and the provider saw none of them");

        // an unrouted team gets the plain default model for the json step too
        let unrouted = router(&default, &provider, policy(0, 0, &[], 1_000)).per_step("acme", false, 10);
        unrouted.json("page", None, Some("t")).await.unwrap();
        assert_eq!((default.calls().len(), provider.calls().len()), (4, 2));
    }

    #[tokio::test]
    async fn a_shadow_request_is_answered_by_default_and_mirrored() {
        let default = Arc::new(MockLlm::scripted(vec![Ok(json!({"from": "default"}))]));
        let provider = Arc::new(MockLlm::scripted(vec![Ok(json!({"from": "provider"}))]));
        let t = team_in_bucket(5);
        let r = router(&default, &provider, policy(0, 10, &[], 1_000));
        assert_eq!(r.policy().route(&t, false, 1), Route::Shadow);
        let got = r
            .select(&t, false, 10)
            .json("page", None, Some("t"))
            .await
            .unwrap();
        assert_eq!(got.value, json!({"from": "default"}));
        for _ in 0..100 {
            if !provider.calls().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(provider.calls().len(), 1, "the provider saw the mirrored request");
        assert_eq!(provider.calls()[0].user, default.calls()[0].user, "same request");
    }
}
