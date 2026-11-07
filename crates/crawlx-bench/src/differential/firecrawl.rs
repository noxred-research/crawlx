//! The Firecrawl side as data: a v2 crawl export.
//!
//! The export is the `GET /v2/crawl/{id}` status body with every `next` page merged into
//! `data`, plus the `GET /v2/crawl/{id}/errors` body under `errors`. The shapes are the
//! documented wire format (`status`, `total`, `completed`, `creditsUsed`, `data[]`,
//! `metadata.sourceURL`, `metadata.statusCode`, `errors[]`, `robotsBlocked[]`); unknown
//! fields are ignored so exports from newer servers still load. No Firecrawl source is
//! involved.

use crate::error::BenchError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A merged crawl export.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FirecrawlExport {
    /// Job status: `scraping`, `completed`, `failed` or `cancelled`.
    #[serde(default)]
    pub status: String,
    /// Reported `total`.
    #[serde(default)]
    pub total: u64,
    /// Reported `completed`.
    #[serde(default)]
    pub completed: u64,
    /// Reported `creditsUsed` (`-1` is the SDK's "no billing record").
    #[serde(default = "minus_one")]
    pub credits_used: i64,
    /// Documents of every status page, merged.
    #[serde(default)]
    pub data: Vec<FirecrawlDocument>,
    /// Body of the `/errors` endpoint.
    #[serde(default)]
    pub errors: FirecrawlErrors,
    /// The gym's access log of the crawl (`/__gym/ledger` of the fresh gym this crawl was the
    /// only client of); `None` for captures taken before it was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_log: Option<super::access::AccessLog>,
}

const fn minus_one() -> i64 {
    -1
}

/// One `data[]` document.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FirecrawlDocument {
    /// Markdown rendition, when the `markdown` format was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markdown: Option<String>,
    /// Link URLs, when the `links` format was requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<String>,
    /// Page metadata.
    #[serde(default)]
    pub metadata: FirecrawlMetadata,
}

/// The `metadata` block of a document; only the fields the comparison uses.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FirecrawlMetadata {
    /// URL the document was scraped from.
    #[serde(rename = "sourceURL", default)]
    pub source_url: String,
    /// Final URL after redirects, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// HTTP status code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    /// Title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Content type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Body of `GET /v2/crawl/{id}/errors`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FirecrawlErrors {
    /// Failed pages.
    #[serde(default)]
    pub errors: Vec<FirecrawlError>,
    /// URLs the crawler skipped because of `robots.txt`.
    #[serde(default)]
    pub robots_blocked: Vec<String>,
}

/// One `errors[]` entry.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FirecrawlError {
    /// Error id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// When it happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    /// The page URL.
    #[serde(default)]
    pub url: String,
    /// Error code.
    #[serde(default)]
    pub code: String,
    /// Error message.
    #[serde(default)]
    pub error: String,
}

impl FirecrawlExport {
    /// Load an export file.
    ///
    /// # Errors
    /// [`BenchError::Io`] when the file cannot be read, [`BenchError::Json`] when it is not an
    /// export.
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let bytes = std::fs::read(path).map_err(|e| BenchError::io(path, e))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// The origin of the crawl, taken from the first document's `sourceURL`.
    #[must_use]
    pub fn origin(&self) -> Option<url::Url> {
        self.data
            .iter()
            .find_map(|d| url::Url::parse(&d.metadata.source_url).ok())
            .map(|u| super::normalize::origin_of(&u))
            .and_then(|o| url::Url::parse(&o).ok())
    }
}
