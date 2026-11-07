//! Agent operations: start, list, status, cancel, trace and snapshots.

use super::common::{JobWebhookSpec, JsonObject, Warning};
use super::Spec;
use schemars::JsonSchema;
use serde_json::Value;

// ---- request -------------------------------------------------------------------------------

/// The model of a run. Every run executes on `spark-2`; the deprecated names are routed to it
/// with a `model_deprecated` warning.
#[derive(JsonSchema)]
pub(super) enum AgentModel {
    /// The model every run executes on.
    #[serde(rename = "spark-2")]
    Spark2,
    /// Deprecated; routed to `spark-2`.
    #[serde(rename = "spark-1-mini")]
    Spark1Mini,
    /// Deprecated; routed to `spark-2`.
    #[serde(rename = "spark-1-pro")]
    Spark1Pro,
}

/// Reasoning budget: bounds the number of steps of a run.
#[derive(JsonSchema)]
pub(super) enum Effort {
    /// Fewest steps.
    #[serde(rename = "low")]
    Low,
    /// The default budget.
    #[serde(rename = "medium")]
    Medium,
    /// Most steps.
    #[serde(rename = "high")]
    High,
}

/// Thread mode.
#[derive(JsonSchema)]
pub(super) enum AgentMode {
    /// Extract data into the schema (default).
    #[serde(rename = "extract")]
    Extract,
    /// Converse; the only mode that supports `exchange.requireApproval`.
    #[serde(rename = "chat")]
    Chat,
}

/// `exchange.onTermsRequired`.
#[derive(JsonSchema)]
pub(super) enum TermsMode {
    /// Skip a tool that needs terms to be accepted (default).
    #[serde(rename = "skip")]
    Skip,
    /// Ask for approval.
    #[serde(rename = "ask")]
    Ask,
}

/// `exchange.approve`: the answer to the previous turn's `pendingApproval`.
#[derive(JsonSchema)]
pub(super) struct ExchangeApprove {
    /// The approval answered.
    #[serde(rename = "approvalId")]
    #[schemars(extend("format" = "uuid"))]
    approval_id: String,
    /// Approve only these tool calls (at most 64); every call when omitted.
    #[serde(rename = "callIds")]
    call_ids: Option<Vec<String>>,
    /// Stop asking for the rest of the thread.
    always: Option<bool>,
}

/// `exchange.decline`: decline the previous turn's `pendingApproval`.
#[derive(JsonSchema)]
pub(super) struct ExchangeDecline {
    /// The approval declined.
    #[serde(rename = "approvalId")]
    #[schemars(extend("format" = "uuid"))]
    approval_id: String,
}

/// Third-party tool calls of a run.
#[derive(JsonSchema)]
pub(super) struct Exchange {
    /// Allow tool calls (default `true` when `exchange` is sent).
    enabled: Option<bool>,
    /// Provider slugs the run may use (at most 5 of at most 64 characters).
    toolkits: Option<Vec<String>>,
    /// Most tool calls (1 to 30, default 16).
    #[serde(rename = "maxCalls")]
    #[schemars(range(min = 1, max = 30))]
    max_calls: Option<u32>,
    /// Hold every call for approval (needs `mode: "chat"` on the same request).
    #[serde(rename = "requireApproval")]
    require_approval: Option<bool>,
    /// What to do when a tool needs terms accepted.
    #[serde(rename = "onTermsRequired")]
    on_terms_required: Option<TermsMode>,
    /// Approve the previous turn's pending approval (needs `threadId`; not with `decline`).
    approve: Option<ExchangeApprove>,
    /// Decline the previous turn's pending approval (needs `threadId`; not with `approve`).
    decline: Option<ExchangeDecline>,
}

/// `location` of an agent run: only `country` is read.
#[derive(JsonSchema)]
pub(super) struct AgentLocation {
    /// ISO 3166-1 alpha-2 country code (case-insensitive).
    country: String,
}

/// `auditMetadata`: accepted and ignored (crawlx has no SIEM log sink).
#[derive(JsonSchema)]
pub(super) struct AuditMetadata {
    /// Required, at most 1024 characters.
    username: String,
}

/// `POST /agent` body.
#[derive(JsonSchema)]
pub(super) struct AgentRequest {
    /// What the agent should do (1 to 10000 characters).
    #[schemars(length(min = 1, max = 10000))]
    prompt: String,
    /// Pages the agent starts from (at most 100 absolute `http(s)` URLs). Inherited from the
    /// previous turn of a thread when omitted.
    urls: Option<Vec<String>>,
    /// JSON Schema of the answer. Inherited from the previous turn when omitted.
    schema: Option<JsonObject>,
    /// Most credits the run may spend (at least 1, default 2500). Not inherited.
    #[serde(rename = "maxCredits")]
    max_credits: Option<f64>,
    /// Stay on `urls` (needs a non-empty `urls`). Not inherited.
    #[serde(rename = "strictConstrainToURLs")]
    strict_constrain_to_urls: Option<bool>,
    /// The model (see [`AgentModel`] in the schemas).
    model: Option<AgentModel>,
    /// Reasoning budget. Inherited from the previous turn when omitted.
    effort: Option<Effort>,
    /// Webhook for the run events (`started`, `action`, `completed`, `failed`, `cancelled`).
    webhook: Option<JobWebhookSpec>,
    /// Accepted and ignored.
    #[serde(rename = "auditMetadata")]
    audit_metadata: Option<AuditMetadata>,
    /// Accepted; not supported, ignored with an `unsupported_option` warning.
    #[serde(rename = "threatProtection")]
    threat_protection: Option<Value>,
    /// Continue this thread (a UUID of an earlier run).
    #[serde(rename = "threadId")]
    #[schemars(extend("format" = "uuid"))]
    thread_id: Option<String>,
    /// Thread mode. Inherited from the previous turn when omitted.
    mode: Option<AgentMode>,
    /// Keep nothing: the result is deleted after 24 hours and the run has no thread.
    #[serde(rename = "zeroDataRetention")]
    zero_data_retention: Option<bool>,
    /// Location hint. Inherited from the previous turn when omitted.
    location: Option<AgentLocation>,
    /// Third-party tool calls. Inherited from the previous turn when omitted.
    exchange: Option<Exchange>,
    /// SDK bookkeeping; accepted without effect.
    integration: Option<String>,
    /// SDK bookkeeping; accepted without effect.
    origin: Option<String>,
}

// ---- responses -----------------------------------------------------------------------------

/// `POST /agent`: the run was admitted.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentStarted {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the run.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// Id of the thread the run belongs to (absent for zero-data-retention runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "uuid"))]
    thread_id: Option<String>,
    /// 1-based turn of the thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_turn: Option<u32>,
    /// Options that were not applied or were rewritten.
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<Warning>>,
}

/// The settings a list entry echoes.
#[derive(JsonSchema)]
pub(super) struct AgentListOptions {
    /// The request's `urls` (absent for zero-data-retention runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    urls: Option<Vec<String>>,
    /// The request's prompt (absent for zero-data-retention runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    prompt: Option<String>,
    /// The request's schema (absent for zero-data-retention runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<Value>,
    /// Always `spark-2`.
    model: String,
    /// The request's effort.
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<String>,
}

/// One run of `GET /agent`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentListEntry {
    /// Id of the run.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// RFC 3339 creation time.
    created_at: String,
    /// The first URL or the start of the prompt (at most 120 characters).
    #[serde(skip_serializing_if = "Option::is_none")]
    target_hint: Option<String>,
    /// Always `api`.
    origin: String,
    /// Always `{}`.
    settings: JsonObject,
    /// `processing`, `completed`, `failed` or `cancelled`.
    status: String,
    /// The settings of the run.
    options: AgentListOptions,
}

/// `GET /agent`.
#[derive(JsonSchema)]
pub(super) struct AgentList {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The tenant's runs, newest first.
    agents: Vec<AgentListEntry>,
    /// URL of the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next: Option<String>,
}

/// `GET /agent` query string.
#[derive(JsonSchema)]
pub(super) struct AgentListQuery {
    /// Page before this run's creation time (unix milliseconds); the `next` link carries it.
    before: Option<u64>,
    /// Tie-breaker for `before`: the id of the last run of the previous page.
    #[serde(rename = "beforeId")]
    before_id: Option<String>,
    /// Runs per page (1 to 100, default 20).
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    /// Runs to skip (0 to 10000).
    #[schemars(range(min = 0, max = 10000))]
    skip: Option<u32>,
}

/// `GET /agent/{jobId}`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentStatus {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// `processing`, `completed`, `failed` or `cancelled`.
    status: String,
    /// The answer (completed runs only).
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    /// The best-effort answer of a run that stopped early.
    #[serde(skip_serializing_if = "Option::is_none")]
    partial: Option<Value>,
    /// Whether `partial` validates against the schema.
    #[serde(skip_serializing_if = "Option::is_none")]
    partial_schema_valid: Option<bool>,
    /// Why the run stopped early (`credit_limit_reached`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    stop_reason: Option<String>,
    /// A note about the outcome.
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// Always `spark-2`.
    model: String,
    /// The request's effort.
    #[serde(skip_serializing_if = "Option::is_none")]
    effort: Option<String>,
    /// Why the run failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// RFC 3339 time the result is deleted.
    expires_at: String,
    /// Credits the run cost.
    credits_used: u64,
    /// LLM tokens the run used.
    tokens_used: u64,
    /// Thread of the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_id: Option<String>,
    /// Turn of the thread.
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_turn: Option<u32>,
    /// Thread mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    /// Follow-up suggestions.
    #[serde(skip_serializing_if = "Option::is_none")]
    suggestions: Option<Value>,
    /// A tool call waiting for approval, with the `resolution` a later turn gave it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pending_approval: Option<JsonObject>,
    /// The tool calls the run made.
    #[serde(skip_serializing_if = "Option::is_none")]
    exchange: Option<Value>,
    /// Options that were not applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<Warning>>,
}

/// `DELETE /agent/{jobId}`.
#[derive(JsonSchema)]
pub(super) struct AgentCancelled {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
}

/// `GET /agent/{jobId}/trace` query string.
#[derive(JsonSchema)]
pub(super) struct AgentTraceQuery {
    /// Return events after this stored sequence number (the `seq` of an event; default 0).
    after: Option<u64>,
    /// Stored steps per page (1 to 1000, default 200).
    #[schemars(range(min = 1, max = 1000))]
    limit: Option<u32>,
    /// `true` adds an empty `activeBrowserSessions` list.
    #[serde(rename = "liveView")]
    live_view: Option<bool>,
}

/// One canonical trace event. The members depend on `type` (`run.started`,
/// `reasoning.summary`, `tool_call.started`, `tool_call.finished`, `artifact.updated`,
/// `progress.reported`, `error.occurred`, `run.finished`).
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentTraceEvent {
    /// Always 1.
    schema_version: u32,
    /// Stable id of the event.
    #[schemars(extend("format" = "uuid"))]
    event_id: String,
    /// Id of the run.
    #[schemars(extend("format" = "uuid"))]
    run_id: String,
    /// RFC 3339 time of the event.
    occurred_at: Option<String>,
    /// Monotonic position of the event in the run.
    producer_sequence: u64,
    /// The actor: `{id, role, name}`.
    agent: JsonObject,
    /// The event type.
    #[serde(rename = "type")]
    kind: String,
    /// The stored sequence number (absent on `run.started` and `run.finished`).
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
}

/// `GET /agent/{jobId}/trace`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentTrace {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the run.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// The events of this page.
    events: Vec<AgentTraceEvent>,
    /// Credits the run cost so far.
    credits_used: u64,
    /// Pass as `after` to read the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_after: Option<u64>,
    /// Present (empty) with `liveView=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    active_browser_sessions: Option<Vec<Value>>,
}

/// `GET /agent/{jobId}/snapshots/{snapshotId}`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct AgentSnapshot {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the run.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// Id of the snapshot.
    snapshot_id: String,
    /// The snapshot content as text (JSON values are serialized).
    snapshot: String,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "firecrawlStartAgent" => Spec::new(&[404, 409, 422, 503])
            .json::<AgentRequest>("The prompt and the run settings.")
            .reply::<AgentStarted>("200", "The run was admitted and continues in the background."),
        "firecrawlListAgents" => Spec::new(&[400])
            .query::<AgentListQuery>()
            .reply::<AgentList>("200", "The tenant's runs, newest first."),
        "firecrawlGetAgent" => Spec::new(&[400, 404, 410])
            .path("jobId", "Id of the agent run.", Some("uuid"))
            .reply::<AgentStatus>("200", "The run's status, result, usage and expiry."),
        "firecrawlCancelAgent" => Spec::new(&[400, 404, 409])
            .path("jobId", "Id of the agent run.", Some("uuid"))
            .reply::<AgentCancelled>("200", "The run was cancelled."),
        "firecrawlGetAgentTrace" => Spec::new(&[400, 404])
            .path("jobId", "Id of the agent run.", Some("uuid"))
            .query::<AgentTraceQuery>()
            .reply::<AgentTrace>("200", "One page of canonical execution events."),
        "firecrawlGetAgentSnapshot" => Spec::new(&[400, 404])
            .path("jobId", "Id of the agent run.", Some("uuid"))
            .path("snapshotId", "Id of the snapshot (a UUID).", Some("uuid"))
            .reply::<AgentSnapshot>("200", "The snapshot content."),
        _ => return None,
    };
    Some(s)
}
