//! `POST /extract` and `GET /extract/{id}`.

use super::common::{JobWebhookSpec, JsonObject};
use super::scrape::ScrapeOptions;
use super::Spec;
use schemars::JsonSchema;
use serde_json::Value;

/// `POST /extract` body. At least one of `prompt` and `schema` is required.
#[derive(JsonSchema)]
pub(super) struct ExtractRequest {
    /// URLs or globs (`*` stands for any text) of the pages to read: 1 to 100 absolute `http(s)`
    /// addresses of at most 2048 characters.
    urls: Vec<String>,
    /// What to extract (at most 10000 characters).
    prompt: Option<String>,
    /// JSON Schema of the answer (must be a valid schema).
    schema: Option<JsonObject>,
    /// Also read pages found by a web search (needs a configured search backend).
    #[serde(rename = "enableWebSearch")]
    enable_web_search: Option<bool>,
    /// Do not read sitemaps while expanding globs.
    #[serde(rename = "ignoreSitemap")]
    ignore_sitemap: Option<bool>,
    /// Include subdomains while expanding globs (default `true`).
    #[serde(rename = "includeSubdomains")]
    include_subdomains: Option<bool>,
    /// Return `sources` in the status response.
    #[serde(rename = "showSources")]
    show_sources: Option<bool>,
    /// Scrape options per page (`markdown` is always among the formats).
    #[serde(rename = "scrapeOptions")]
    scrape_options: Option<ScrapeOptions>,
    /// Drop invalid URLs instead of rejecting the request (default `true`).
    #[serde(rename = "ignoreInvalidURLs")]
    ignore_invalid_urls: Option<bool>,
    /// Webhook for the job events (`started`, `completed`, `failed`).
    webhook: Option<JobWebhookSpec>,
    /// Accepted; enterprise-only, ignored with a `warning`.
    #[serde(rename = "threatProtection")]
    threat_protection: Option<Value>,
    /// SDK bookkeeping; accepted without effect.
    integration: Option<String>,
    /// SDK bookkeeping; accepted without effect.
    origin: Option<String>,
}

/// `POST /extract`: the job was started.
#[derive(JsonSchema)]
pub(super) struct ExtractCreated {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// Id of the job.
    #[schemars(extend("format" = "uuid"))]
    id: String,
    /// The URLs that were dropped as invalid.
    #[serde(rename = "invalidURLs")]
    invalid_urls: Vec<String>,
    /// Options that were not applied, joined by `; `.
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

/// `GET /extract/{id}`.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExtractStatus {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// `processing`, `completed`, `failed` or `cancelled`.
    status: String,
    /// The extracted data (`{}` until the job completes).
    data: Value,
    /// RFC 3339 time the job is deleted.
    expires_at: String,
    /// LLM tokens the job used.
    tokens_used: u64,
    /// Credits the job cost.
    credits_used: u64,
    /// For each top-level field of `data`, the pages that support it (`showSources` only).
    #[serde(skip_serializing_if = "Option::is_none")]
    sources: Option<JsonObject>,
    /// Why the job failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    /// Notes of the job, joined by `; `.
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "compatExtract" => Spec::new(&[422, 503])
            .json::<ExtractRequest>("The URLs, the prompt or schema, and the options.")
            .reply::<ExtractCreated>("200", "The job was started."),
        "compatExtractStatus" => Spec::new(&[400, 404])
            .path("id", "Id of the extract job.", Some("uuid"))
            .reply::<ExtractStatus>("200", "The job's status, data, usage and expiry."),
        _ => return None,
    };
    Some(s)
}
