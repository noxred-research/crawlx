//! Team usage, activity, support and health operations.

use super::common::JsonObject;
use super::Spec;
use schemars::JsonSchema;

// ---- usage ---------------------------------------------------------------------------------

/// The `data` of `GET /team/credit-usage`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreditUsageData {
    /// Always -1: credits are unlimited.
    remaining_credits: i64,
    /// Always -1: credits are unlimited.
    plan_credits: i64,
    /// Always `true`.
    unlimited: bool,
    /// Credits used in the current billing period (the UTC calendar month).
    credits_used: u64,
    /// RFC 3339 start of the period.
    billing_period_start: String,
    /// RFC 3339 end of the period.
    billing_period_end: String,
}

/// `GET /team/credit-usage`.
#[derive(JsonSchema)]
pub(super) struct CreditUsageResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The usage.
    data: CreditUsageData,
}

/// The `data` of `GET /team/token-usage`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenUsageData {
    /// Always -1: tokens are unlimited.
    remaining_tokens: i64,
    /// Always -1: tokens are unlimited.
    plan_tokens: i64,
    /// Always `true`.
    unlimited: bool,
    /// Prompt plus completion tokens used in the current billing period.
    tokens_used: u64,
    /// Prompt tokens used.
    prompt_tokens: u64,
    /// Completion tokens used.
    completion_tokens: u64,
    /// RFC 3339 start of the period.
    billing_period_start: String,
    /// RFC 3339 end of the period.
    billing_period_end: String,
}

/// `GET /team/token-usage`.
#[derive(JsonSchema)]
pub(super) struct TokenUsageResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The usage.
    data: TokenUsageData,
}

/// One month of credit usage.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreditPeriod {
    /// RFC 3339 start of the month.
    start_date: String,
    /// RFC 3339 end of the month.
    end_date: String,
    /// Always `null`: usage is not tracked per API key.
    api_key: Option<String>,
    /// Credits used in the month.
    total_credits: u64,
}

/// `GET /team/credit-usage/historical`.
#[derive(JsonSchema)]
pub(super) struct CreditHistoricalResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Up to 12 months with usage, oldest first.
    periods: Vec<CreditPeriod>,
}

/// One month of token usage.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct TokenPeriod {
    /// RFC 3339 start of the month.
    start_date: String,
    /// RFC 3339 end of the month.
    end_date: String,
    /// Always `null`: usage is not tracked per API key.
    api_key: Option<String>,
    /// Tokens used in the month.
    total_tokens: u64,
}

/// `GET /team/token-usage/historical`.
#[derive(JsonSchema)]
pub(super) struct TokenHistoricalResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Up to 12 months with usage, oldest first.
    periods: Vec<TokenPeriod>,
}

/// `GET /team/queue-status`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct QueueStatusResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Extract and agent jobs still processing.
    jobs_in_queue: u64,
    /// The same as `jobsInQueue`.
    active_jobs_in_queue: u64,
    /// Always 0: jobs start at once.
    waiting_jobs_in_queue: u64,
    /// The tenant's active-run limit.
    max_concurrency: u64,
    /// RFC 3339 time of the last completed job; `null` when there is none.
    most_recent_success: Option<String>,
}

/// One ledger row of `GET /team/activity`.
#[derive(JsonSchema)]
pub(super) struct ActivityEntry {
    /// Id of the job (the nil UUID when the row has none).
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// The endpoint (`scrape`, `crawl`, `search`, ...).
    endpoint: String,
    /// Always `v2`.
    api_version: String,
    /// RFC 3339 time of the request.
    created_at: String,
    /// Always `null`.
    target: Option<String>,
    /// `completed`, `failed`, ...
    status: String,
    /// Credits the request cost.
    credits: u64,
    /// LLM tokens the request used.
    tokens: u64,
}

/// `GET /team/activity`.
#[derive(JsonSchema)]
pub(super) struct ActivityResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The requests of the last 24 hours, newest first.
    data: Vec<ActivityEntry>,
    /// Pass as `cursor` for the next page; `null` on the last page.
    cursor: Option<String>,
    /// Whether another page follows.
    has_more: bool,
}

/// Query string of `GET /team/activity`.
#[derive(JsonSchema)]
pub(super) struct ActivityQuery {
    /// Only requests to this endpoint.
    endpoint: Option<String>,
    /// Rows per page (1 to 100, default 50).
    #[schemars(range(min = 1, max = 100))]
    limit: Option<u32>,
    /// Opaque position of the previous page.
    cursor: Option<String>,
}

// ---- support -------------------------------------------------------------------------------

/// `POST /support/docs-search` body.
#[derive(JsonSchema)]
pub(super) struct DocsSearchRequest {
    /// The documentation question (1 to 4000 characters).
    #[schemars(length(min = 1, max = 4000))]
    question: String,
}

/// `POST /support/ask` body.
#[derive(JsonSchema)]
pub(super) struct SupportAskRequest {
    /// The problem or question (1 to 4000 characters).
    #[schemars(length(min = 1, max = 4000))]
    question: String,
    /// Context for the diagnosis (read with the question; at most 4000 characters are sent on).
    rationale: Option<String>,
}

/// A documentation passage that supports an answer.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct Evidence {
    /// The document the passage is from.
    path_or_url: String,
    /// Why it matches.
    reason: String,
}

/// LLM usage of a support answer.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SupportUsage {
    /// Prompt tokens.
    input_tokens: u64,
    /// Completion tokens.
    output_tokens: u64,
    /// Both.
    total_tokens: u64,
}

/// `POST /support/docs-search` response.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct DocsSearchResponse {
    /// Id of the request.
    #[schemars(extend("format" = "uuid"))]
    request_id: String,
    /// The answer.
    answer: String,
    /// The passages it is based on.
    evidence: Vec<Evidence>,
    /// LLM usage (all zero without an LLM).
    usage: SupportUsage,
    /// Milliseconds the request took.
    duration_ms: u64,
}

/// Confidence of a support diagnosis.
#[derive(JsonSchema)]
pub(super) enum Confidence {
    /// High.
    #[serde(rename = "high")]
    High,
    /// Medium.
    #[serde(rename = "medium")]
    Medium,
    /// Low (also the answer without an LLM).
    #[serde(rename = "low")]
    Low,
}

/// `POST /support/ask` response.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct SupportAskResponse {
    /// Id of the request.
    #[schemars(extend("format" = "uuid"))]
    request_id: String,
    /// The diagnosis.
    answer: String,
    /// How sure the answer is.
    confidence: Confidence,
    /// API request parameters that may fix the issue; `null` when there are none.
    fix_parameters: Option<JsonObject>,
    /// Always `null`.
    validation: Option<JsonObject>,
    /// Without an LLM: a note and the tenant's recent failures; otherwise `null`.
    feedback: Option<JsonObject>,
    /// The passages the answer is based on.
    evidence: Vec<Evidence>,
    /// Milliseconds the request took.
    duration_ms: u64,
}

// ---- health --------------------------------------------------------------------------------

/// `GET /v0/health/readiness`.
#[derive(JsonSchema)]
pub(super) struct Readiness {
    /// `ok` when storage answers, else `unavailable`.
    status: String,
    /// `ok` or `unavailable`.
    storage: String,
}

/// `GET /v0/health/liveness`.
#[derive(JsonSchema)]
pub(super) struct Liveness {
    /// Always `ok`.
    status: String,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "firecrawlCreditUsage" => {
            Spec::new(&[]).reply::<CreditUsageResponse>("200", "Credits used this period.")
        }
        "firecrawlCreditUsageHistorical" => {
            Spec::new(&[]).reply::<CreditHistoricalResponse>("200", "Credits used per month.")
        }
        "firecrawlTokenUsage" => {
            Spec::new(&[]).reply::<TokenUsageResponse>("200", "Tokens used this period.")
        }
        "firecrawlTokenUsageHistorical" => {
            Spec::new(&[]).reply::<TokenHistoricalResponse>("200", "Tokens used per month.")
        }
        "firecrawlQueueStatus" => {
            Spec::new(&[]).reply::<QueueStatusResponse>("200", "Jobs in the tenant's queue.")
        }
        "firecrawlActivity" => Spec::new(&[400, 422])
            .query::<ActivityQuery>()
            .reply::<ActivityResponse>("200", "The tenant's requests of the last 24 hours."),
        "firecrawlFeedback" => Spec::new(&[404, 422])
            .json::<super::search::GeneralFeedbackRequest>("The job and the rating.")
            .reply::<super::search::FeedbackResponse>("200", "The feedback was stored."),
        "firecrawlSupportAsk" => Spec::new(&[422, 502, 504])
            .json::<SupportAskRequest>("The question and its context.")
            .reply::<SupportAskResponse>("200", "A diagnosis from the documentation and recent failures."),
        "firecrawlSupportDocsSearch" => Spec::new(&[422, 502, 504])
            .json::<DocsSearchRequest>("The documentation question.")
            .reply::<DocsSearchResponse>("200", "An answer with citations."),
        "readiness" => Spec::open(&[])
            .reply::<Readiness>("200", "Storage answers.")
            .reply::<Readiness>("503", "Storage does not answer."),
        "liveness" => Spec::open(&[]).reply::<Liveness>("200", "The process serves requests."),
        _ => return None,
    };
    Some(s)
}
