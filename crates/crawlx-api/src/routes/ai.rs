//! Native AI endpoints: the operation table shared with the OpenAPI document.

use crate::openapi::Operation;

/// Operations of the policy-bound AI endpoints.
pub const OPERATIONS: &[Operation] = &[
    (
        "get",
        "/v1/capabilities/ai",
        "getAiCapabilities",
        "Model-processing policy status: external processing switch, provider ids with retention capability and allowed purposes, budgets and enabled AI endpoints (never endpoints, keys or prompts)",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawl-specs/validate",
        "validateCrawlSpec",
        "Dry-run the native create validation and admission for a crawl configuration; performs no target I/O and creates nothing. Returns the digest of the admitted configuration",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawl-specs/compile",
        "compileCrawlSpec",
        "Compile a natural-language engagement description into a native crawl configuration: bounded intent, deterministic compiler, preview admission, diff, warnings and unsupported intents. No target I/O; creates a spec awaiting operator approval",
        "crawls:read",
        "201",
    ),
    (
        "get",
        "/v1/crawl-specs/{specId}",
        "getCrawlSpec",
        "Read a compiled spec with its digests, approval state and expiry",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawl-specs/{specId}/approve",
        "approveCrawlSpec",
        "Operator approval of one compiled spec digest; returns a single-use, digest-bound approval token (shown once)",
        "approvals:decide",
        "200",
    ),
    (
        "post",
        "/v1/crawl-specs/{specId}/create",
        "createCrawlFromSpec",
        "Create the crawl a spec compiled, when the operator approval token matches the digest; admission, authorization expiry and policy are re-checked before start",
        "crawls:write",
        "202",
    ),
    (
        "post",
        "/v1/agent-plans",
        "proposeAgentPlan",
        "Plan-first agent: propose a bounded plan (model-assisted or deterministic) over operator-supplied URLs; validated deterministically, previewed, nothing is fetched",
        "crawls:read",
        "201",
    ),
    (
        "get",
        "/v1/agent-plans/{planId}",
        "getAgentPlan",
        "Read a plan with its digest, validation findings, approval state and deviations",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/agent-plans/{planId}/approve",
        "approveAgentPlan",
        "Operator approval of one plan digest; returns a single-use, digest-bound approval token (shown once)",
        "approvals:decide",
        "200",
    ),
    (
        "post",
        "/v1/agent-plans/{planId}/cancel",
        "cancelAgentPlan",
        "Cancel a plan that has not been executed",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/agent-plans/{planId}/execute",
        "executeAgentPlan",
        "Execute an approved plan as a research agent job confined to the plan; the approval token is consumed. Out-of-plan calls are refused and recorded as deviations",
        "crawls:write",
        "202",
    ),
    (
        "post",
        "/v1/crawls/{id}/extractions",
        "extractEvidence",
        "Schema extraction over retained pages with exact field evidence: every field is observed (quote and byte span verified), inferred, unknown, conflicting or rejected as ungrounded",
        "crawls:read",
        "201",
    ),
    (
        "get",
        "/v1/crawls/{id}/extractions",
        "listExtractions",
        "Stored evidence extractions of a run",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/triage",
        "triageSurfaces",
        "Passive, evidence-backed endpoint and vulnerability-surface triage of retained pages, requests and traffic; rules first, optional cited model explanation; never initiates target I/O",
        "crawls:read",
        "201",
    ),
    (
        "get",
        "/v1/crawls/{id}/triage",
        "listSurfaceTriage",
        "The latest surface triage of a run",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/summaries",
        "summarizeRun",
        "Grounded run or findings summary: a deterministic accumulator plus optional model prose in which every claim cites artifact ids; claims that fail validation are dropped",
        "crawls:read",
        "201",
    ),
    (
        "get",
        "/v1/crawls/{id}/summaries",
        "listSummaries",
        "Stored summaries of a run",
        "crawls:read",
        "200",
    ),
    (
        "put",
        "/v1/crawls/{id}/findings/{findingId}",
        "putReviewedFinding",
        "Operator-reviewed finding record; the only source of confirmed finding status in summaries",
        "approvals:decide",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/findings",
        "listReviewedFindings",
        "Operator-reviewed finding records of a run",
        "crawls:read",
        "200",
    ),
];

fn body(required: &[&str], properties: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "required": true,
        "content": {"application/json": {"schema": {
            "type": "object",
            "additionalProperties": false,
            "required": required,
            "properties": properties,
        }}}
    })
}

/// The JSON request body of an AI operation, or `None` for operations without one (and for
/// `validateCrawlSpec`, which takes the native create body).
#[must_use]
pub fn request_body(id: &str) -> Option<serde_json::Value> {
    use serde_json::json;
    let token = json!({"approvalToken": {"type": "string", "description": "the single-use token returned by the approve operation"}});
    Some(match id {
        "compileCrawlSpec" => body(
            &["baseConfig"],
            &json!({
                "prompt": {"type": "string", "maxLength": 10000, "description": "natural-language engagement description (give exactly one of prompt and intent)"},
                "intent": {"type": "object", "description": "a typed crawl intent (CrawlIntentV1) instead of a prompt"},
                "baseConfig": {"type": "object", "description": "the operator's native create body; the intent can only narrow it"},
                "authorizationId": {"type": "string", "format": "uuid"},
            }),
        ),
        "createCrawlFromSpec" | "executeAgentPlan" => body(&["approvalToken"], &token),
        "proposeAgentPlan" => body(
            &["prompt", "urls"],
            &json!({
                "prompt": {"type": "string", "maxLength": 10000},
                "urls": {"type": "array", "minItems": 1, "maxItems": 20, "items": {"type": "string", "format": "uri"}},
                "schema": {"type": "object"},
                "effort": {"type": "string", "enum": ["low", "medium", "high"]},
                "maxCredits": {"type": "integer", "minimum": 1, "maximum": 50000},
            }),
        ),
        "extractEvidence" => body(
            &[],
            &json!({
                "artifacts": {"type": "array", "maxItems": 8, "items": {"type": "string"}},
                "urls": {"type": "array", "maxItems": 8, "items": {"type": "string"}},
                "schema": {"type": "object", "description": "JSON Schema, at most 6000 bytes, local references only (give a schema or a preset)"},
                "preset": {"type": "string", "enum": ["endpoint_inventory", "forms", "auth_mechanisms", "api_parameters", "response_metadata"], "description": "a versioned schema instead of a custom one"},
                "task": {"type": "string", "maxLength": 2000},
                "expectedDigests": {"type": "object", "additionalProperties": {"type": "string"}},
                "includeInferred": {"type": "boolean"},
            }),
        ),
        "triageSurfaces" => body(
            &[],
            &json!({
                "mode": {"type": "string", "enum": ["rules", "advisory"]},
                "maxSurfaces": {"type": "integer", "minimum": 1, "maximum": 500},
                "batchSize": {"type": "integer", "minimum": 1, "maximum": 50},
            }),
        ),
        "summarizeRun" => body(
            &[],
            &json!({
                "kind": {"type": "string", "enum": ["run", "findings"]},
                "useModel": {"type": "boolean"},
            }),
        ),
        "putReviewedFinding" => body(
            &["title", "status", "severity"],
            &json!({
                "title": {"type": "string", "maxLength": 200},
                "status": {"type": "string", "enum": ["confirmed", "dismissed", "needs_review"]},
                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                "evidence": {"type": "array", "maxItems": 20, "items": {"type": "string", "description": "artifact:<id>, traffic:<id> or surface:<id>"}},
                "notes": {"type": "string", "maxLength": 2000},
            }),
        ),
        _ => return None,
    })
}
