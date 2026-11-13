//! Plan-first research agent: the deterministic half.
//!
//! A planner (a model, or the deterministic fallback) proposes a bounded list of steps over URLs
//! the operator supplied. [`validate_steps`] checks every step against the closed tool
//! vocabulary and the operator's URL set and drops what fails, recording a finding for each
//! drop; nothing the model wrote can add a host, a tool or a step beyond the budget. The
//! validated plan is previewed, approved by an operator and only then executed as an agent run
//! confined to the plan (see `routes::agent_plans`).

use crate::errors::Detail;
use crate::intel::agent_spec::{Effort, DEFAULT_MAX_CREDITS, MAX_PROMPT_CHARS};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use url::Url;

/// Prompt label of the model plan call.
pub const PROMPT_VERSION: &str = "agent-plan.prompt.v1";
/// Schema label of the model plan reply.
pub const SCHEMA_VERSION: &str = "agent-plan.v1";
/// Most operator URLs.
pub const MAX_URLS: usize = 20;
/// Most steps of any plan.
pub const MAX_STEPS: usize = 16;
/// Longest step purpose.
pub const MAX_PURPOSE_CHARS: usize = 200;
/// Largest `maxCredits` a plan may carry.
pub const MAX_CREDITS: u64 = 50_000;

/// The tools a plan may use. There is no search, exchange or free-form tool.
pub const PLAN_TOOLS: [&str; 3] = ["map", "scrape", "extract"];

/// A validated request to plan.
#[derive(Clone, Debug)]
pub struct PlanRequest {
    /// The research goal.
    pub goal: String,
    /// The operator's URLs, normalized.
    pub urls: Vec<Url>,
    /// Optional result schema.
    pub schema: Option<Value>,
    /// Reasoning budget.
    pub effort: Effort,
    /// Credit ceiling of the run.
    pub max_credits: u64,
}

fn detail(path: &str, code: &str, message: &str) -> Detail {
    Detail::new(path, code, message)
}

/// Normalize one operator URL: absolute `http`/`https`, a host, no credentials.
fn operator_url(text: &str) -> Option<Url> {
    let mut url = Url::parse(text).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    url.set_fragment(None);
    Some(url)
}

/// Parse and validate a plan request body.
///
/// # Errors
/// Every violation, as `details[]` entries.
pub fn parse_request(body: &Value) -> Result<PlanRequest, Vec<Detail>> {
    let mut details = Vec::new();
    let Some(map) = body.as_object() else {
        return Err(vec![detail("/", "invalid", "the body must be a JSON object")]);
    };
    for key in map.keys() {
        if !["prompt", "urls", "schema", "effort", "maxCredits"].contains(&key.as_str()) {
            details.push(detail(
                &format!("/{key}"),
                "unknown_field",
                &format!("unknown field `{key}`"),
            ));
        }
    }
    let goal = match map.get("prompt").and_then(Value::as_str) {
        Some(p) if !p.trim().is_empty() && p.chars().count() <= MAX_PROMPT_CHARS => p.to_owned(),
        _ => {
            details.push(detail(
                "/prompt",
                "invalid",
                "prompt must be a non-empty string of at most 10000 characters",
            ));
            String::new()
        }
    };
    let mut urls = Vec::new();
    match map.get("urls").and_then(Value::as_array) {
        Some(list) if (1..=MAX_URLS).contains(&list.len()) => {
            for (n, item) in list.iter().enumerate() {
                match item.as_str().and_then(operator_url) {
                    Some(url) => {
                        if !urls.contains(&url) {
                            urls.push(url);
                        }
                    }
                    None => details.push(detail(
                        &format!("/urls/{n}"),
                        "invalid",
                        "urls must be absolute http or https URLs without credentials",
                    )),
                }
            }
        }
        _ => details.push(detail(
            "/urls",
            "invalid",
            "urls must be an array of 1 to 20 URLs",
        )),
    }
    let schema = match map.get("schema") {
        None | Some(Value::Null) => None,
        Some(schema) => {
            if let Err(e) = crawlx_model::policy::validate_schema_bounds(schema) {
                details.push(detail("/schema", "invalid_schema", &e.to_string()));
            } else if jsonschema::validator_for(schema).is_err() {
                details.push(detail(
                    "/schema",
                    "invalid_schema",
                    "the schema is not a valid JSON Schema",
                ));
            }
            Some(schema.clone())
        }
    };
    let effort = match map.get("effort").and_then(Value::as_str) {
        None => Effort::Low,
        Some("low") => Effort::Low,
        Some("medium") => Effort::Medium,
        Some("high") => Effort::High,
        Some(_) => {
            details.push(detail("/effort", "invalid", "effort must be low, medium or high"));
            Effort::Low
        }
    };
    let max_credits = match map.get("maxCredits") {
        None => DEFAULT_MAX_CREDITS.min(MAX_CREDITS),
        Some(v) => match v.as_u64().filter(|n| (1..=MAX_CREDITS).contains(n)) {
            Some(n) => n,
            None => {
                details.push(detail(
                    "/maxCredits",
                    "out_of_range",
                    "maxCredits must be in 1..=50000",
                ));
                DEFAULT_MAX_CREDITS
            }
        },
    };
    if details.is_empty() {
        Ok(PlanRequest {
            goal,
            urls,
            schema,
            effort,
            max_credits,
        })
    } else {
        Err(details)
    }
}

/// The JSON Schema a model plan reply must satisfy.
#[must_use]
pub fn plan_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["steps"],
        "properties": {
            "steps": {
                "type": "array",
                "maxItems": MAX_STEPS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["tool", "url"],
                    "properties": {
                        "tool": {"type": "string", "enum": PLAN_TOOLS},
                        "url": {"type": "string", "maxLength": 2048},
                        "purpose": {"type": "string", "maxLength": MAX_PURPOSE_CHARS},
                    },
                },
            },
        },
    })
}

/// The task text of the model plan call.
#[must_use]
pub fn task_text(request: &PlanRequest) -> String {
    let urls: Vec<&str> = request.urls.iter().map(Url::as_str).collect();
    format!(
        "Research goal: {}\nAllowed starting URLs (a step may use only these hosts and paths): {}\nPropose at most {} steps using the tools map, scrape and extract.",
        request.goal,
        urls.join(", "),
        max_steps(request),
    )
}

/// Most steps this request allows.
#[must_use]
pub fn max_steps(request: &PlanRequest) -> usize {
    usize::try_from(request.effort.steps())
        .unwrap_or(MAX_STEPS)
        .min(MAX_STEPS)
}

/// Whether `candidate` is on one of the operator's hosts and under its path prefix, by the same
/// rule the agent applies when `strictConstrainToURLs` is on.
#[must_use]
pub fn permitted(urls: &[Url], candidate: &Url) -> bool {
    let Some(host) = candidate.host_str().map(str::to_ascii_lowercase) else {
        return false;
    };
    let port = candidate.port_or_known_default();
    let path = candidate.path();
    urls.iter().any(|allowed| {
        let prefix = allowed.path().trim_end_matches('/');
        allowed.host_str().map(str::to_ascii_lowercase).as_deref() == Some(host.as_str())
            && allowed.port_or_known_default() == port
            && (prefix.is_empty()
                || path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/')))
    })
}

/// The steps that survived validation and what was dropped.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedPlan {
    /// Steps in order, numbered from 1.
    pub steps: Vec<Value>,
    /// Tools the steps use.
    pub tools: BTreeSet<&'static str>,
    /// One entry per dropped or adjusted step.
    pub findings: Vec<Value>,
}

fn finding(step: usize, code: &str, message: &str) -> Value {
    json!({"step": step, "code": code, "message": message})
}

/// Validate the `steps` of a model reply against the request.
#[must_use]
pub fn validate_steps(request: &PlanRequest, raw: &Value) -> ValidatedPlan {
    let mut steps = Vec::new();
    let mut tools = BTreeSet::new();
    let mut findings = Vec::new();
    let limit = max_steps(request);
    let empty = Vec::new();
    let items = raw.get("steps").and_then(Value::as_array).unwrap_or(&empty);
    for (index, item) in items.iter().enumerate() {
        let n = index + 1;
        if steps.len() >= limit {
            findings.push(finding(
                n,
                "step_budget",
                "more steps than the effort allows; the rest were dropped",
            ));
            break;
        }
        let Some(map) = item.as_object() else {
            findings.push(finding(n, "step_malformed", "a step must be an object"));
            continue;
        };
        let tool = map
            .get("tool")
            .and_then(Value::as_str)
            .and_then(|t| PLAN_TOOLS.iter().copied().find(|k| *k == t));
        let Some(tool) = tool else {
            findings.push(finding(
                n,
                "tool_not_allowed",
                "only map, scrape and extract are allowed",
            ));
            continue;
        };
        let Some(url) = map.get("url").and_then(Value::as_str).and_then(operator_url) else {
            findings.push(finding(
                n,
                "url_invalid",
                "the step URL is not an absolute http or https URL",
            ));
            continue;
        };
        if !permitted(&request.urls, &url) {
            findings.push(finding(
                n,
                "url_outside_scope",
                "the step URL is not under an operator-supplied URL",
            ));
            continue;
        }
        let purpose = map
            .get("purpose")
            .and_then(Value::as_str)
            .map(|p| crawlx_model::provenance::sanitize_untrusted(p, MAX_PURPOSE_CHARS))
            .unwrap_or_default();
        tools.insert(tool);
        steps.push(json!({"n": steps.len() + 1, "tool": tool, "url": url.as_str(), "purpose": purpose}));
    }
    ValidatedPlan {
        steps,
        tools,
        findings,
    }
}

/// The plan without a model: one `scrape` step per operator URL.
#[must_use]
pub fn deterministic_steps(request: &PlanRequest) -> ValidatedPlan {
    let steps: Vec<Value> = request
        .urls
        .iter()
        .take(max_steps(request))
        .enumerate()
        .map(|(i, url)| json!({"n": i + 1, "tool": "scrape", "url": url.as_str(), "purpose": "read the supplied page"}))
        .collect();
    ValidatedPlan {
        tools: BTreeSet::from(["scrape"]),
        steps,
        findings: Vec::new(),
    }
}

/// The stored plan body: everything the approval binds to.
#[must_use]
pub fn plan_body(request: &PlanRequest, plan: &ValidatedPlan, planner: &str, model: Option<Value>) -> Value {
    let allowed: Vec<Value> = request
        .urls
        .iter()
        .map(|u| {
            json!({
                "host": u.host_str().unwrap_or_default().to_ascii_lowercase(),
                "port": u.port_or_known_default(),
                "pathPrefix": u.path().trim_end_matches('/'),
            })
        })
        .collect();
    let mut body = Map::new();
    body.insert("goal".to_owned(), json!(request.goal));
    body.insert(
        "urls".to_owned(),
        json!(request.urls.iter().map(Url::as_str).collect::<Vec<_>>()),
    );
    body.insert("allowed".to_owned(), Value::Array(allowed));
    body.insert("steps".to_owned(), Value::Array(plan.steps.clone()));
    body.insert("tools".to_owned(), json!(plan.tools));
    body.insert("effort".to_owned(), json!(request.effort.as_str()));
    body.insert("maxSteps".to_owned(), json!(max_steps(request)));
    body.insert("maxCredits".to_owned(), json!(request.max_credits));
    body.insert("schema".to_owned(), request.schema.clone().unwrap_or(Value::Null));
    body.insert("planner".to_owned(), json!(planner));
    body.insert("findings".to_owned(), Value::Array(plan.findings.clone()));
    body.insert("model".to_owned(), model.unwrap_or(Value::Null));
    Value::Object(body)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn request() -> PlanRequest {
        parse_request(&json!({
            "prompt": "find the pricing page",
            "urls": ["https://shop.example.test/docs", "https://api.example.test:8443/"],
            "effort": "low",
        }))
        .unwrap()
    }

    #[test]
    fn requests_are_validated() {
        assert!(parse_request(&json!({"prompt": "x", "urls": []})).is_err());
        assert!(parse_request(&json!({"prompt": "x", "urls": ["ftp://a.test/"]})).is_err());
        assert!(parse_request(&json!({"prompt": "x", "urls": ["https://u:p@a.test/"]})).is_err());
        assert!(parse_request(&json!({"prompt": "", "urls": ["https://a.test/"]})).is_err());
        assert!(parse_request(&json!({"prompt": "x", "urls": ["https://a.test/"], "exchange": {}})).is_err());
        assert!(parse_request(
            &json!({"prompt": "x", "urls": ["https://a.test/"], "schema": {"$ref": "https://evil.test/s"}})
        )
        .is_err());
        assert!(
            parse_request(&json!({"prompt": "x", "urls": ["https://a.test/"], "maxCredits": 0})).is_err()
        );
    }

    #[test]
    fn hostile_steps_are_dropped_with_findings() {
        let plan = validate_steps(
            &request(),
            &json!({"steps": [
                {"tool": "scrape", "url": "https://shop.example.test/docs/pricing", "purpose": "read prices"},
                {"tool": "scrape", "url": "https://evil.test/exfil?x=1"},
                {"tool": "search", "url": "https://shop.example.test/docs"},
                {"tool": "scrape", "url": "https://shop.example.test/admin"},
                {"tool": "map", "url": "https://api.example.test:8443/v1"},
                {"tool": "scrape", "url": "https://api.example.test/v1"},
                {"tool": "evaluate", "url": "javascript:alert(1)"},
                "not an object",
            ]}),
        );
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.tools, BTreeSet::from(["map", "scrape"]));
        let codes: Vec<&str> = plan
            .findings
            .iter()
            .map(|f| f["code"].as_str().unwrap())
            .collect();
        assert_eq!(
            codes,
            vec![
                "url_outside_scope",
                "tool_not_allowed",
                "url_outside_scope",
                "url_outside_scope",
                "tool_not_allowed",
                "step_malformed"
            ]
        );
    }

    #[test]
    fn the_step_budget_is_enforced() {
        let many: Vec<Value> = (0..10)
            .map(|i| json!({"tool": "scrape", "url": format!("https://shop.example.test/docs/{i}")}))
            .collect();
        let plan = validate_steps(&request(), &json!({"steps": many}));
        assert_eq!(plan.steps.len(), 4, "effort low allows four steps");
        assert!(plan.findings.iter().any(|f| f["code"] == "step_budget"));
    }

    #[test]
    fn prefix_matching_respects_path_boundaries() {
        let urls = vec![Url::parse("https://a.test/docs").unwrap()];
        assert!(permitted(&urls, &Url::parse("https://a.test/docs").unwrap()));
        assert!(permitted(&urls, &Url::parse("https://a.test/docs/x").unwrap()));
        assert!(!permitted(
            &urls,
            &Url::parse("https://a.test/docs-private").unwrap()
        ));
        assert!(!permitted(&urls, &Url::parse("https://b.test/docs").unwrap()));
        assert!(!permitted(&urls, &Url::parse("http://a.test/docs").unwrap()));
    }

    #[test]
    fn the_deterministic_plan_needs_no_model() {
        let plan = deterministic_steps(&request());
        assert_eq!(plan.steps.len(), 2);
        assert_eq!(plan.tools, BTreeSet::from(["scrape"]));
    }
}
