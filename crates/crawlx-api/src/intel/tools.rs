//! The page tools seam: [`PageTools`] is what `/extract`, `/agent`, `/search` (`scrapeOptions`)
//! and `/monitor` use to scrape and map pages. The production implementation is a thin adapter
//! over the scrape service of the compat facade; [`MockPageTools`] serves canned documents for
//! hermetic tests.

use async_trait::async_trait;
use crawlx_core::TenantId;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::BTreeMap;

/// A scraped page in the Firecrawl `data` shape (`markdown`, `html`, `links`, `metadata`, ...).
#[derive(Clone, PartialEq, Debug)]
pub struct ScrapedPage {
    /// The Firecrawl document object.
    pub document: Value,
    /// Credits the scrape cost.
    pub credits: u64,
}

impl ScrapedPage {
    /// The page's markdown, empty when the document has none.
    #[must_use]
    pub fn markdown(&self) -> &str {
        self.document
            .get("markdown")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    /// `metadata.sourceURL` (falling back to `metadata.url`), empty when absent.
    #[must_use]
    pub fn source_url(&self) -> &str {
        let meta = self.document.get("metadata");
        meta.and_then(|m| m.get("sourceURL").or_else(|| m.get("url")))
            .and_then(Value::as_str)
            .unwrap_or("")
    }
}

/// A URL found by [`PageTools::map`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MapLink {
    /// Absolute URL.
    pub url: String,
    /// Page title when known.
    pub title: Option<String>,
    /// Page description when known.
    pub description: Option<String>,
}

/// Failure of a page tool.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolError {
    /// The options or URL are invalid (maps to HTTP 400/422).
    #[error("invalid input: {0}")]
    Invalid(String),
    /// The target refused or could not be reached; carries the Firecrawl-style error text.
    #[error("{0}")]
    Failed(String),
}

/// Scrape and map pages on behalf of a tenant. Object-safe.
#[async_trait]
pub trait PageTools: Send + Sync {
    /// Scrape `url` with Firecrawl scrape `options` (`formats`, `onlyMainContent`, ...).
    ///
    /// # Errors
    /// [`ToolError::Invalid`] for bad options or URL, [`ToolError::Failed`] when the page cannot be scraped.
    async fn scrape(&self, tenant: TenantId, url: &str, options: &Value) -> Result<ScrapedPage, ToolError>;

    /// List URLs of the site of `url` with Firecrawl map `options` (`search`, `limit`,
    /// `includeSubdomains`, `sitemap`, ...).
    ///
    /// # Errors
    /// [`ToolError::Invalid`] for bad options or URL, [`ToolError::Failed`] when the site cannot be mapped.
    async fn map(&self, tenant: TenantId, url: &str, options: &Value) -> Result<Vec<MapLink>, ToolError>;
}

/// A [`PageTools`] with canned pages (keyed by exact URL) and links (keyed by the site URL).
/// Pages can be replaced between calls to simulate change.
#[derive(Debug, Default)]
pub struct MockPageTools {
    pages: Mutex<BTreeMap<String, Result<ScrapedPage, ToolError>>>,
    links: Mutex<BTreeMap<String, Vec<MapLink>>>,
    scraped: Mutex<Vec<(String, Value)>>,
}

impl MockPageTools {
    /// An empty mock: every URL fails with `ToolError::Failed("no such page")`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serve `markdown` (with `metadata.sourceURL = url`) for `url`, replacing any earlier page.
    pub fn set_markdown(&self, url: &str, markdown: &str) {
        let document = serde_json::json!({
            "markdown": markdown,
            "metadata": { "sourceURL": url, "url": url, "statusCode": 200, "title": url },
        });
        self.pages
            .lock()
            .insert(url.to_owned(), Ok(ScrapedPage { document, credits: 1 }));
    }

    /// Serve a full document for `url`.
    pub fn set_document(&self, url: &str, document: Value) {
        self.pages
            .lock()
            .insert(url.to_owned(), Ok(ScrapedPage { document, credits: 1 }));
    }

    /// Make scraping `url` fail with `error`.
    pub fn set_failure(&self, url: &str, error: ToolError) {
        self.pages.lock().insert(url.to_owned(), Err(error));
    }

    /// Remove the page of `url` (it fails afterwards).
    pub fn remove(&self, url: &str) {
        self.pages.lock().remove(url);
    }

    /// Serve `links` for mapping `site`.
    pub fn set_links(&self, site: &str, links: Vec<MapLink>) {
        self.links.lock().insert(site.to_owned(), links);
    }

    /// `(url, options)` of every scrape so far, oldest first.
    #[must_use]
    pub fn scraped(&self) -> Vec<(String, Value)> {
        self.scraped.lock().clone()
    }
}

#[async_trait]
impl PageTools for MockPageTools {
    async fn scrape(&self, _tenant: TenantId, url: &str, options: &Value) -> Result<ScrapedPage, ToolError> {
        self.scraped.lock().push((url.to_owned(), options.clone()));
        self.pages
            .lock()
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err(ToolError::Failed("no such page".to_owned())))
    }

    async fn map(&self, _tenant: TenantId, url: &str, _options: &Value) -> Result<Vec<MapLink>, ToolError> {
        self.links
            .lock()
            .get(url)
            .cloned()
            .ok_or_else(|| ToolError::Failed("no such site".to_owned()))
    }
}

/// The production [`PageTools`]: scrapes and maps through the compat facade's scrape service
/// ([`crate::scrape_service`]) as `tenant`, so every page goes through the same fetch, render,
/// format and usage-ledger path as `POST /scrape` and `POST /map`.
#[derive(Clone)]
pub struct ServiceTools {
    state: crate::state::AppState,
}

impl std::fmt::Debug for ServiceTools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTools").finish_non_exhaustive()
    }
}

impl ServiceTools {
    /// Tools over `state`'s scrape service.
    #[must_use]
    pub const fn new(state: crate::state::AppState) -> Self {
        Self { state }
    }
}

/// Classify a scrape-service failure: request problems are the caller's, the rest is the
/// target's or the service's.
fn tool_error(e: &crate::errors::HttpError) -> ToolError {
    let text = if e.details.is_empty() {
        e.message.clone()
    } else {
        let d: Vec<String> = e
            .details
            .iter()
            .map(|d| format!("{}: {}", d.path, d.message))
            .collect();
        format!("{} ({})", e.message, d.join("; "))
    };
    if e.status == axum::http::StatusCode::BAD_REQUEST
        || e.status == axum::http::StatusCode::UNPROCESSABLE_ENTITY
    {
        ToolError::Invalid(text)
    } else {
        ToolError::Failed(text)
    }
}

#[async_trait]
impl PageTools for ServiceTools {
    async fn scrape(&self, tenant: TenantId, url: &str, options: &Value) -> Result<ScrapedPage, ToolError> {
        crate::scrape_service::scrape_one(&self.state, tenant, url, options)
            .await
            .map(|d| ScrapedPage {
                document: d.document,
                credits: d.credits,
            })
            .map_err(|e| tool_error(&e))
    }

    async fn map(&self, tenant: TenantId, url: &str, options: &Value) -> Result<Vec<MapLink>, ToolError> {
        crate::scrape_service::map_site(&self.state, tenant, url, options)
            .await
            .map(|links| {
                links
                    .into_iter()
                    .map(|l| MapLink {
                        url: l.url,
                        title: l.title,
                        description: l.description,
                    })
                    .collect()
            })
            .map_err(|e| tool_error(&e))
    }
}
