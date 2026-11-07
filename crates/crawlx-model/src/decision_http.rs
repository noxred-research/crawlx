//! HTTP adapter for a System-One style typed-question service.
//!
//! Wire format (one POST, JSON both ways):
//!
//! ```json
//! // request
//! { "goal": "...", "state": {"provenance": "page_text", "value": {...}},
//!   "questions": [ {"kind": "choice", "id": "next_action", "options": [0, 3, 7]},
//!                  {"kind": "score",  "id": "risk", "criteria": ["none", "low", "high"]},
//!                  {"kind": "noul",   "id": "modal_blocking", "question": "..."} ] }
//! // response
//! { "answers": [ {"kind": "choice", "id": "next_action",
//!                 "probs": [{"option": 3, "p": 0.8}, {"option": 0, "p": 0.1}, {"option": 7, "p": 0.05}],
//!                 "none": 0.05},
//!                {"kind": "score", "id": "risk", "probs": [0.7, 0.2, 0.1]},
//!                {"kind": "noul", "id": "modal_blocking", "p_yes": 0.9} ] }
//! ```
//!
//! The adapter validates the request, sanitizes the state at the wire
//! boundary, runs the call through a [`CallGuard`] (breaker, concurrency cap,
//! time budget — a failure is recorded, never retried), validates the response
//! against the closed schema (extra fields, unknown options, probabilities not
//! summing to 1 are all `Malformed`) and applies the confidence [`Gate`] to
//! choice answers. Probabilities are taken as calibrated by the service for
//! the checkpoint named in [`ModelId`]. Redirects are not followed and the API
//! key is only ever sent as a bearer header.

use crate::calibration::Gate;
use crate::error::ModelError;
use crate::guard::{CallGuard, GuardConfig};
use crate::typed::{
    choice_answer, validate_parts, DecisionEngine, ModelId, ProvenanceTagged, StateView, TypedAnswer,
    TypedDecision, TypedDecisionRequest, TypedQuestion,
};
use crawlx_core::secret::SecretOr;
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Largest response body accepted.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// Tolerance when checking that a probability vector sums to 1.
pub const PROB_SUM_TOLERANCE: f32 = 0.02;

/// Configuration of a [`DecisionHttpEngine`].
#[derive(Clone)]
pub struct DecisionHttpConfig {
    /// `http://` or `https://` endpoint of the typed-decision API.
    pub endpoint: String,
    /// Bearer credential, if the service needs one.
    pub api_key: Option<SecretOr<String>>,
    /// Identity of the served model, recorded in decision provenance.
    pub model: ModelId,
    /// Confidence gate that decides between accepting and abstaining.
    pub gate: Gate,
    /// Timeout, concurrency and breaker settings of the remote call.
    pub guard: GuardConfig,
}

impl std::fmt::Debug for DecisionHttpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionHttpConfig")
            .field("endpoint", &"[REDACTED]")
            .field("api_key", &self.api_key)
            .field("model", &self.model)
            .field("gate", &self.gate)
            .field("guard", &self.guard)
            .finish()
    }
}

impl DecisionHttpConfig {
    /// A config with default gate and remote guard settings.
    #[must_use]
    pub fn new(endpoint: &str, model: ModelId) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            api_key: None,
            model,
            gate: Gate::default(),
            guard: GuardConfig::remote(),
        }
    }
}

#[derive(Serialize)]
struct WireRequest<'a> {
    goal: &'a str,
    state: ProvenanceTagged<StateView>,
    questions: &'a [TypedQuestion],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    answers: Vec<WireAnswer>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum WireAnswer {
    Choice {
        id: String,
        probs: Vec<WireProb>,
        #[serde(default)]
        none: f32,
    },
    Score {
        id: String,
        probs: Vec<f32>,
    },
    Noul {
        id: String,
        p_yes: f32,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProb {
    option: u32,
    p: f32,
}

impl WireAnswer {
    fn id(&self) -> &str {
        match self {
            Self::Choice { id, .. } | Self::Score { id, .. } | Self::Noul { id, .. } => id,
        }
    }
}

/// Typed-decision engine over HTTP.
pub struct DecisionHttpEngine {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    api_key: Option<SecretOr<String>>,
    model: ModelId,
    gate: Gate,
    guard: CallGuard,
    budget_ms: u64,
}

impl std::fmt::Debug for DecisionHttpEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionHttpEngine")
            .field("endpoint", &"[REDACTED]")
            .field("api_key", &self.api_key)
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

impl DecisionHttpEngine {
    /// Build the engine.
    ///
    /// # Errors
    /// [`ModelError::InvalidRequest`] for a malformed or non-HTTP endpoint,
    /// [`ModelError::Transport`] if the HTTP client cannot be built.
    pub fn new(config: DecisionHttpConfig) -> Result<Self, ModelError> {
        Self::build(config, false)
    }

    /// Build a transport confined to a controlled local fixture model service.
    /// No environment proxy or redirect may widen this endpoint.
    ///
    /// # Errors
    /// Refuses any endpoint other than literal HTTP IPv4 localhost, credentials in URLs,
    /// and the ordinary client construction failures.
    pub fn for_loopback_fixture(config: DecisionHttpConfig) -> Result<Self, ModelError> {
        Self::build(config, true)
    }

    fn build(config: DecisionHttpConfig, fixture: bool) -> Result<Self, ModelError> {
        let endpoint = reqwest::Url::parse(&config.endpoint)
            .map_err(|e| ModelError::InvalidRequest(format!("endpoint: {e}")))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(ModelError::InvalidRequest(
                "endpoint must be http or https".to_owned(),
            ));
        }
        if fixture
            && (endpoint.scheme() != "http"
                || endpoint.host_str() != Some("127.0.0.1")
                || !endpoint.username().is_empty()
                || endpoint.password().is_some())
        {
            return Err(ModelError::InvalidRequest(
                "fixture model endpoint must be literal http://127.0.0.1".to_owned(),
            ));
        }
        let builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.guard.timeout);
        let client = (if fixture { builder.no_proxy() } else { builder })
            .build()
            .map_err(|e| ModelError::Transport(e.without_url().to_string()))?;
        Ok(Self {
            client,
            endpoint,
            api_key: config.api_key,
            model: config.model,
            gate: config.gate,
            guard: CallGuard::new(config.guard),
            budget_ms: u64::try_from(config.guard.timeout.as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// The engine's call guard (breaker state, open check).
    #[must_use]
    pub const fn guard(&self) -> &CallGuard {
        &self.guard
    }

    async fn call(&self, body: &WireRequest<'_>) -> Result<WireResponse, ModelError> {
        let mut request = self.client.post(self.endpoint.clone()).json(body);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key.expose());
        }
        let budget = self.budget_ms;
        let mut response = request.send().await.map_err(|e| map_transport(e, budget))?;
        let status = response.status();
        if !status.is_success() {
            return Err(ModelError::Http {
                status: status.as_u16(),
            });
        }
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| map_transport(e, budget))? {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(ModelError::Malformed(format!(
                    "response exceeds {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&bytes).map_err(|e| ModelError::Malformed(format!("response schema: {e}")))
    }
}

fn map_transport(e: reqwest::Error, budget_ms: u64) -> ModelError {
    let e = e.without_url();
    if e.is_timeout() {
        ModelError::Timeout { after_ms: budget_ms }
    } else {
        ModelError::Transport(e.to_string())
    }
}

fn check_prob(p: f32, what: &str) -> Result<(), ModelError> {
    if p.is_finite() && (0.0..=1.0).contains(&p) {
        Ok(())
    } else {
        Err(ModelError::Malformed(format!(
            "{what}: probability {p} outside [0, 1]"
        )))
    }
}

fn check_sum(sum: f32, what: &str) -> Result<(), ModelError> {
    if (sum - 1.0).abs() <= PROB_SUM_TOLERANCE {
        Ok(())
    } else {
        Err(ModelError::Malformed(format!(
            "{what}: probabilities sum to {sum}, expected 1"
        )))
    }
}

/// Validate `response` against `req` and turn it into typed answers plus the
/// ids of questions the gate abstained on.
fn interpret(
    req: &TypedDecisionRequest,
    response: WireResponse,
    gate: &Gate,
) -> Result<(Vec<TypedAnswer>, Vec<String>), ModelError> {
    let malformed = |m: String| Err(ModelError::Malformed(m));
    if response.answers.len() != req.questions.len() {
        return malformed(format!(
            "{} answers for {} questions",
            response.answers.len(),
            req.questions.len()
        ));
    }
    let mut answers = Vec::with_capacity(req.questions.len());
    let mut abstained = Vec::new();
    for question in &req.questions {
        let Some(wire) = response.answers.iter().find(|a| a.id() == question.id()) else {
            return malformed(format!("no answer for question {:?}", question.id()));
        };
        match (question, wire) {
            (TypedQuestion::Choice { id, options }, WireAnswer::Choice { probs, none, .. }) => {
                check_prob(*none, id)?;
                let mut ordered = Vec::with_capacity(options.len());
                for opt in options {
                    let mut matching = probs.iter().filter(|p| p.option == opt.0);
                    let (Some(p), None) = (matching.next(), matching.next()) else {
                        return malformed(format!("{id}: option {} missing or repeated", opt.0));
                    };
                    check_prob(p.p, id)?;
                    ordered.push(p.p);
                }
                if probs.len() != options.len() {
                    let offered: Vec<u32> = options.iter().map(|o| o.0).collect();
                    let stray = probs
                        .iter()
                        .find(|p| !offered.contains(&p.option))
                        .map_or(0, |p| p.option);
                    return malformed(format!("{id}: option {stray} was not offered"));
                }
                check_sum(ordered.iter().sum::<f32>() + none, id)?;
                let (answer, did_abstain) = choice_answer(id, options, &ordered, *none, gate);
                if did_abstain {
                    abstained.push(id.clone());
                }
                answers.push(answer);
            }
            (TypedQuestion::Score { id, criteria }, WireAnswer::Score { probs, .. }) => {
                if probs.len() != criteria.len() {
                    return malformed(format!(
                        "{id}: {} levels for {} criteria",
                        probs.len(),
                        criteria.len()
                    ));
                }
                for p in probs {
                    check_prob(*p, id)?;
                }
                check_sum(probs.iter().sum(), id)?;
                let level = probs
                    .iter()
                    .enumerate()
                    .fold(
                        (0, f32::NEG_INFINITY),
                        |best, (i, p)| if *p > best.1 { (i, *p) } else { best },
                    )
                    .0;
                answers.push(TypedAnswer::Score {
                    id: id.clone(),
                    distribution: probs.clone(),
                    level,
                });
            }
            (TypedQuestion::Noul { id, .. }, WireAnswer::Noul { p_yes, .. }) => {
                check_prob(*p_yes, id)?;
                answers.push(TypedAnswer::Noul {
                    id: id.clone(),
                    p_yes: *p_yes,
                });
            }
            (q, _) => return malformed(format!("answer kind does not match question {:?}", q.id())),
        }
    }
    Ok((answers, abstained))
}

#[async_trait::async_trait]
impl DecisionEngine for DecisionHttpEngine {
    async fn decide(&self, req: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
        req.validate()?;
        let started = Instant::now();
        let state = ProvenanceTagged::new(req.state.provenance(), req.state.value().sanitized());
        let body = WireRequest {
            goal: req.goal.as_str(),
            state,
            questions: &req.questions,
        };
        // Interpretation runs inside the guard: a schema-valid but semantically
        // wrong reply is a model failure and counts against the breaker too.
        let (answers, abstained) = self
            .guard
            .run(|| async {
                let response = self.call(&body).await?;
                interpret(&req, response, &self.gate)
            })
            .await?;
        Ok(TypedDecision {
            answers,
            abstained,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            model: self.model.clone(),
        })
    }

    fn id(&self) -> &ModelId {
        &self.model
    }

    fn breaker_state(&self) -> Option<crate::breaker::BreakerState> {
        Some(self.guard.breaker_state())
    }
}

/// A request as a typed-decision *server* receives it (the other end of the wire format above).
///
/// The goal is plain text here: an [`Instruction`](crate::provenance::Instruction) is
/// constructible only from static templates, which is the crawler's guarantee, not the
/// server's. Servers pass the text to [`crate::onnx_ranker::OnnxRankerEngine::decide_parts`].
#[derive(Clone, PartialEq, Debug, Deserialize)]
pub struct ServedRequest {
    /// Crawler-authored goal text.
    pub goal: String,
    /// Provenance-tagged page state (the shortlist and its text).
    pub state: ProvenanceTagged<StateView>,
    /// The questions to answer.
    pub questions: Vec<TypedQuestion>,
}

impl ServedRequest {
    /// Check the request is legal before an engine sees it.
    ///
    /// # Errors
    /// [`ModelError::InvalidRequest`], as [`TypedDecisionRequest::validate`].
    pub fn validate(&self) -> Result<(), ModelError> {
        validate_parts(self.state.provenance(), self.state.value(), &self.questions)
    }
}

/// The JSON body a server answers with for `decision`: exactly what [`DecisionHttpEngine`] parses
/// (calibrated probabilities per option plus `none`, level probabilities, `p_yes`).
#[must_use]
pub fn served_response(decision: &TypedDecision) -> serde_json::Value {
    let answers: Vec<serde_json::Value> = decision
        .answers
        .iter()
        .map(|a| match a {
            TypedAnswer::Choice {
                id, probs, none_p, ..
            } => serde_json::json!({
                "kind": "choice",
                "id": id,
                "probs": probs
                    .iter()
                    .map(|(option, p)| serde_json::json!({ "option": option.0, "p": p }))
                    .collect::<Vec<_>>(),
                "none": none_p,
            }),
            TypedAnswer::Score { id, distribution, .. } => serde_json::json!({
                "kind": "score",
                "id": id,
                "probs": distribution,
            }),
            TypedAnswer::Noul { id, p_yes } => serde_json::json!({
                "kind": "noul",
                "id": id,
                "p_yes": p_yes,
            }),
        })
        .collect();
    serde_json::json!({ "answers": answers })
}
