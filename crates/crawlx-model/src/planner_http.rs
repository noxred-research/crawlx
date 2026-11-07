//! HTTP adapter of the LLM planner seam ([`PlannerClient`]).
//!
//! Wire format (one POST, JSON both ways):
//!
//! ```json
//! // request
//! { "goal": "...",
//!   "candidates": [ {"role": "button", "text": "Open settings", "region": "main"} ],
//!   "state": {"provenance": "page_text", "route_template": "/app", "regions": []},
//!   "known_routes": ["/app", "/settings"], "max_steps": 12 }
//! // response: an ActionPlan
//! { "version": 1, "steps": [ {"op": "click", "target": 0} ] }
//! ```
//!
//! The body of the reply is returned unparsed as untrusted model output; [`plan_validated`]
//! parses it against the closed plan vocabulary and discards, never repairs, anything outside it.
//! Like the typed-decision adapter the call runs through a [`CallGuard`] (breaker, concurrency
//! cap, time budget), redirects are not followed and the key is only sent as a bearer header.
//!
//! [`plan_validated`]: crate::llm::plan_validated

use crate::decision_http::MAX_RESPONSE_BYTES;
use crate::error::ModelError;
use crate::guard::{CallGuard, GuardConfig};
use crate::llm::{PlannerClient, PlannerRequest};
use crate::provenance::{Provenance, Untrusted};
use crate::typed::CandidateView;
use crawlx_core::secret::SecretOr;
use serde::Serialize;

/// Configuration of an [`HttpPlanner`].
#[derive(Clone)]
pub struct HttpPlannerConfig {
    /// `http://` or `https://` endpoint that accepts the planner request.
    pub endpoint: String,
    /// Bearer credential, if the service needs one.
    pub api_key: Option<SecretOr<String>>,
    /// Timeout, concurrency and breaker settings of the remote call.
    pub guard: GuardConfig,
}

impl std::fmt::Debug for HttpPlannerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPlannerConfig")
            .field("endpoint", &"[REDACTED]")
            .field("api_key", &self.api_key)
            .field("guard", &self.guard)
            .finish()
    }
}

impl HttpPlannerConfig {
    /// A config with default remote guard settings.
    #[must_use]
    pub fn new(endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_owned(),
            api_key: None,
            guard: GuardConfig::remote(),
        }
    }
}

#[derive(Serialize)]
struct WireState<'a> {
    provenance: &'a str,
    route_template: &'a str,
    regions: &'a [crate::typed::RegionSummary],
}

#[derive(Serialize)]
struct WireRequest<'a> {
    goal: &'a str,
    candidates: &'a [CandidateView],
    state: WireState<'a>,
    known_routes: &'a [String],
    max_steps: usize,
}

/// The planner over HTTP.
pub struct HttpPlanner {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    api_key: Option<SecretOr<String>>,
    guard: CallGuard,
    budget_ms: u64,
}

impl std::fmt::Debug for HttpPlanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpPlanner")
            .field("endpoint", &"[REDACTED]")
            .field("api_key", &self.api_key)
            .finish_non_exhaustive()
    }
}

impl HttpPlanner {
    /// Build the adapter.
    ///
    /// # Errors
    /// [`ModelError::InvalidRequest`] for a malformed or non-HTTP endpoint,
    /// [`ModelError::Transport`] if the HTTP client cannot be built.
    pub fn new(config: HttpPlannerConfig) -> Result<Self, ModelError> {
        let endpoint = reqwest::Url::parse(&config.endpoint)
            .map_err(|e| ModelError::InvalidRequest(format!("endpoint: {e}")))?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(ModelError::InvalidRequest(
                "endpoint must be http or https".to_owned(),
            ));
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(config.guard.timeout)
            .build()
            .map_err(|e| ModelError::Transport(e.without_url().to_string()))?;
        Ok(Self {
            client,
            endpoint,
            api_key: config.api_key,
            budget_ms: u64::try_from(config.guard.timeout.as_millis()).unwrap_or(u64::MAX),
            guard: CallGuard::new(config.guard),
        })
    }

    /// The adapter's call guard (breaker state, open check).
    #[must_use]
    pub const fn guard(&self) -> &CallGuard {
        &self.guard
    }

    async fn call(&self, req: &PlannerRequest) -> Result<String, ModelError> {
        let state = req.state.value().sanitized();
        let body = WireRequest {
            goal: req.goal.as_str(),
            candidates: &state.candidates,
            state: WireState {
                provenance: req.state.provenance().as_str(),
                route_template: &state.route_template,
                regions: &state.regions,
            },
            known_routes: &req.known_routes,
            max_steps: req.max_steps.min(crate::llm::MAX_PLAN_STEPS),
        };
        let mut request = self.client.post(self.endpoint.clone()).json(&body);
        if let Some(key) = &self.api_key {
            request = request.bearer_auth(key.expose());
        }
        let budget = self.budget_ms;
        let map = |e: reqwest::Error| {
            let e = e.without_url();
            if e.is_timeout() {
                ModelError::Timeout { after_ms: budget }
            } else {
                ModelError::Transport(e.to_string())
            }
        };
        let mut response = request.send().await.map_err(map)?;
        let status = response.status();
        if !status.is_success() {
            return Err(ModelError::Http {
                status: status.as_u16(),
            });
        }
        let mut bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(map)? {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(ModelError::Malformed(format!(
                    "response exceeds {MAX_RESPONSE_BYTES} bytes"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        String::from_utf8(bytes).map_err(|_| ModelError::Malformed("response is not UTF-8".to_owned()))
    }
}

#[async_trait::async_trait]
impl PlannerClient for HttpPlanner {
    async fn plan(&self, req: &PlannerRequest) -> Result<Untrusted<String>, ModelError> {
        let text = self.guard.run(|| self.call(req)).await?;
        Untrusted::new(Provenance::ModelOutput, text).map_err(|e| ModelError::Malformed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::llm::plan_validated;
    use crate::provenance::{Instruction, ProvenanceTagged};
    use crate::typed::StateView;
    use std::time::Duration;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn request() -> PlannerRequest {
        PlannerRequest {
            goal: Instruction::from_static("Explore."),
            state: ProvenanceTagged::new(
                Provenance::PageText,
                StateView {
                    route_template: "/app".to_owned(),
                    regions: Vec::new(),
                    candidates: vec![CandidateView::new("button", "Open", Some("main"))],
                },
            ),
            known_routes: vec!["/app".to_owned()],
            max_steps: 4,
        }
    }

    #[tokio::test]
    async fn posts_the_request_and_returns_the_validated_plan() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("authorization", "Bearer k"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(r#"{"version":1,"steps":[{"op":"click","target":0}]}"#),
            )
            .mount(&server)
            .await;
        let mut cfg = HttpPlannerConfig::new(&server.uri());
        cfg.api_key = Some(SecretOr::secret("k".to_owned()));
        let planner = HttpPlanner::new(cfg).unwrap();
        let plan = plan_validated(&planner, &request()).await.unwrap();
        assert_eq!(plan.steps().len(), 1);
        let seen = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(body["goal"], "Explore.");
        assert_eq!(body["candidates"][0]["text"], "Open");
        assert_eq!(body["state"]["route_template"], "/app");
        assert_eq!(body["max_steps"], 4);
    }

    #[tokio::test]
    async fn a_slow_endpoint_times_out_and_opens_the_breaker() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let mut cfg = HttpPlannerConfig::new(&server.uri());
        cfg.guard.timeout = Duration::from_millis(100);
        let planner = HttpPlanner::new(cfg).unwrap();
        let mut last = None;
        for _ in 0..20 {
            match planner.plan(&request()).await {
                Err(e) => last = Some(e),
                Ok(_) => panic!("must not succeed"),
            }
            if matches!(last, Some(ModelError::BreakerOpen)) {
                break;
            }
        }
        assert!(matches!(last, Some(ModelError::BreakerOpen)), "{last:?}");
    }

    #[tokio::test]
    async fn http_errors_and_bad_endpoints_are_typed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let planner = HttpPlanner::new(HttpPlannerConfig::new(&server.uri())).unwrap();
        assert!(matches!(
            planner.plan(&request()).await,
            Err(ModelError::Http { status: 503 })
        ));
        assert!(matches!(
            HttpPlanner::new(HttpPlannerConfig::new("ftp://x")),
            Err(ModelError::InvalidRequest(_))
        ));
    }
}
