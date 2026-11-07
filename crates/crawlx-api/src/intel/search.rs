//! The search provider seam: [`SearchProvider`] turns a [`SearchQuery`] into [`SearchResults`].
//! Implementations: [`crate::intel::searxng::SearxngProvider`] (SearXNG JSON API) and
//! [`crate::intel::searchapi::SearchApiProvider`] (SearchApi SERP API), built from the operator
//! settings by [`from_settings`], plus [`MockSearch`] for tests.

use async_trait::async_trait;
use parking_lot::Mutex;
use std::time::Duration;

/// Result kinds of `sources`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SearchSource {
    /// Web pages.
    Web,
    /// News articles.
    News,
    /// Images.
    Images,
}

/// Result categories of `categories` (the dedicated `/search/developer|gov|research` indexes and
/// `pdf`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum SearchCategory {
    /// Code hosting (`github`).
    Github,
    /// The developer index.
    Developer,
    /// Research papers.
    Research,
    /// PDF documents.
    Pdf,
    /// Government sources.
    Gov,
}

impl SearchCategory {
    /// Wire label (`github`, `developer`, `research`, `pdf`, `gov`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Github => "github",
            Self::Developer => "developer",
            Self::Research => "research",
            Self::Pdf => "pdf",
            Self::Gov => "gov",
        }
    }
}

/// What to search for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SearchQuery {
    /// Query text (at most 500 characters).
    pub query: String,
    /// Most results per source.
    pub limit: usize,
    /// Result kinds wanted; empty means web.
    pub sources: Vec<SearchSource>,
    /// Categories to restrict to.
    pub categories: Vec<SearchCategory>,
    /// Only results from these hosts.
    pub include_domains: Vec<String>,
    /// No results from these hosts.
    pub exclude_domains: Vec<String>,
    /// Time-based filter (`qdr:d`, `qdr:w`, ...).
    pub tbs: Option<String>,
    /// Free-text location bias.
    pub location: Option<String>,
    /// ISO country code.
    pub country: Option<String>,
    /// Safe-search on.
    pub safe: Option<bool>,
    /// Time budget of the provider call.
    pub timeout: Duration,
}

impl SearchQuery {
    /// A web search for `query` with `limit` results and a 60 s budget.
    #[must_use]
    pub fn web(query: &str, limit: usize) -> Self {
        Self {
            query: query.to_owned(),
            limit,
            sources: vec![SearchSource::Web],
            categories: Vec::new(),
            include_domains: Vec::new(),
            exclude_domains: Vec::new(),
            tbs: None,
            location: None,
            country: None,
            safe: None,
            timeout: Duration::from_secs(60),
        }
    }
}

/// A web result.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WebHit {
    /// Page title.
    pub title: String,
    /// Page URL.
    pub url: String,
    /// Snippet.
    pub description: String,
    /// Category the provider matched it under (`github`, `research`, `pdf`, ...).
    pub category: Option<String>,
    /// 1-based rank.
    pub position: u32,
}

/// A news result.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NewsHit {
    /// Article title.
    pub title: String,
    /// Article URL.
    pub url: String,
    /// Snippet.
    pub snippet: String,
    /// Publication date as the provider reports it.
    pub date: Option<String>,
    /// Thumbnail URL.
    pub image_url: Option<String>,
    /// 1-based rank.
    pub position: u32,
}

/// An image result.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ImageHit {
    /// Image title.
    pub title: String,
    /// Page the image is on.
    pub url: String,
    /// Image URL.
    pub image_url: String,
    /// Width in pixels.
    pub image_width: Option<u32>,
    /// Height in pixels.
    pub image_height: Option<u32>,
    /// 1-based rank.
    pub position: u32,
}

/// Results by kind.
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct SearchResults {
    /// Web results.
    pub web: Vec<WebHit>,
    /// News results.
    pub news: Vec<NewsHit>,
    /// Image results.
    pub images: Vec<ImageHit>,
    /// Request options the backend could not honour (reported as the response `warning`).
    pub warnings: Vec<String>,
}

/// Failure of a provider call.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SearchError {
    /// The call exceeded its budget.
    #[error("search timed out after {after_ms} ms")]
    Timeout {
        /// Budget in milliseconds.
        after_ms: u64,
    },
    /// The provider could not be reached.
    #[error("search transport error: {0}")]
    Transport(String),
    /// The provider answered with a non-success status.
    #[error("search provider returned HTTP {status}")]
    Status {
        /// HTTP status.
        status: u16,
    },
    /// The provider's reply was not the expected JSON.
    #[error("invalid search provider reply: {0}")]
    InvalidReply(String),
}

/// A search backend. Object-safe.
#[async_trait]
pub trait SearchProvider: Send + Sync {
    /// Short stable name (`searxng`, `searchapi`, `mock`) for logs and metrics.
    fn name(&self) -> &'static str;

    /// Run `query`.
    ///
    /// # Errors
    /// [`SearchError`] for timeouts, transport and status failures and malformed replies.
    async fn search(&self, query: &SearchQuery) -> Result<SearchResults, SearchError>;
}

/// A [`SearchProvider`] that returns canned results and records the queries it saw.
#[derive(Debug, Default)]
pub struct MockSearch {
    results: SearchResults,
    seen: Mutex<Vec<SearchQuery>>,
}

impl MockSearch {
    /// A mock answering every query with `results`.
    #[must_use]
    pub fn new(results: SearchResults) -> Self {
        Self {
            results,
            seen: Mutex::new(Vec::new()),
        }
    }

    /// Queries received so far, oldest first.
    #[must_use]
    pub fn queries(&self) -> Vec<SearchQuery> {
        self.seen.lock().clone()
    }
}

#[async_trait]
impl SearchProvider for MockSearch {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn search(&self, query: &SearchQuery) -> Result<SearchResults, SearchError> {
        self.seen.lock().push(query.clone());
        Ok(self.results.clone())
    }
}

/// Failure to build the configured provider.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProviderBuildError {
    /// The API key reference could not be resolved.
    #[error(transparent)]
    Secret(#[from] crate::config::SecretRefError),
    /// The provider rejected its settings (bad endpoint, HTTP client).
    #[error(transparent)]
    Search(#[from] SearchError),
}

/// Build the provider the operator configured.
///
/// # Errors
/// [`ProviderBuildError`] for an unresolvable key reference or an invalid endpoint.
pub fn from_settings(
    settings: &crate::config::SearchSettings,
) -> Result<std::sync::Arc<dyn SearchProvider>, ProviderBuildError> {
    use crate::config::SearchSettings;
    match settings {
        SearchSettings::Searxng {
            endpoint,
            engines,
            categories,
        } => Ok(std::sync::Arc::new(crate::intel::searxng::SearxngProvider::new(
            endpoint,
            engines.clone(),
            categories.clone(),
        )?)),
        SearchSettings::SearchApi {
            api_key_ref,
            engine,
            endpoint,
        } => {
            let key = crate::config::resolve_secret_ref(api_key_ref)?;
            Ok(std::sync::Arc::new(
                crate::intel::searchapi::SearchApiProvider::new(&key, engine, endpoint.as_deref())?,
            ))
        }
    }
}
