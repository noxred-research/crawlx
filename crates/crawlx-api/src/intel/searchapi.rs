//! [`SearchApiProvider`]: the SearchApi (`searchapi.io`) SERP API. Settings: `SEARCHAPI_API_KEY`
//! (kept as a secret reference, sent as a bearer token and never logged) and `SEARCHAPI_ENGINE`.

use crate::intel::search::{
    ImageHit, NewsHit, SearchError, SearchProvider, SearchQuery, SearchResults, SearchSource, WebHit,
};
use crate::intel::search_http::{
    decorate_query, get_json, parse_tbs, url_allowed, TimeRange, MAX_REPLY_BYTES,
};
use async_trait::async_trait;
use crawlx_core::secret::SecretOr;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::Duration;

/// Default API endpoint.
pub const DEFAULT_ENDPOINT: &str = "https://www.searchapi.io/api/v1/search";

/// SearchApi results per request the provider asks for at most.
const MAX_NUM: usize = 100;

/// A SearchApi client for one engine (`google`, `bing`, `duckduckgo`, ...).
#[derive(Clone)]
pub struct SearchApiProvider {
    client: reqwest::Client,
    endpoint: url::Url,
    engine: String,
    api_key: SecretOr<String>,
}

impl std::fmt::Debug for SearchApiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchApiProvider")
            .field("endpoint", &"<redacted>")
            .field("engine", &self.engine)
            .field("api_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl SearchApiProvider {
    /// A client sending `api_key` as a bearer token to `endpoint` (`None` is [`DEFAULT_ENDPOINT`]).
    ///
    /// # Errors
    /// [`SearchError::Transport`] when `endpoint` is not an absolute http(s) URL or the HTTP
    /// client cannot be built.
    pub fn new(api_key: &str, engine: &str, endpoint: Option<&str>) -> Result<Self, SearchError> {
        let endpoint = endpoint.unwrap_or(DEFAULT_ENDPOINT);
        let url = url::Url::parse(endpoint)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| SearchError::Transport(format!("invalid SearchApi endpoint {endpoint:?}")))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("crawlx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| SearchError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            endpoint: url,
            engine: engine.to_owned(),
            api_key: SecretOr::secret(api_key.to_owned()),
        })
    }

    /// Engine to ask for `source`: news and images ride the Google verticals; other engines
    /// serve web only.
    fn engine_for(&self, source: SearchSource) -> Option<String> {
        match source {
            SearchSource::Web => Some(self.engine.clone()),
            SearchSource::News if self.engine == "google" => Some("google_news".to_owned()),
            SearchSource::Images if self.engine == "google" => Some("google_images".to_owned()),
            _ => None,
        }
    }
}

fn text(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn opt_text(v: &Value, key: &str) -> Option<String> {
    Some(text(v, key)).filter(|s| !s.is_empty())
}

fn dim(v: &Value, key: &str) -> Option<u32> {
    v.get(key)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

const fn time_period(r: TimeRange) -> &'static str {
    match r {
        TimeRange::Hour => "last_hour",
        TimeRange::Day => "last_day",
        TimeRange::Week => "last_week",
        TimeRange::Month => "last_month",
        TimeRange::Year => "last_year",
    }
}

#[async_trait]
impl SearchProvider for SearchApiProvider {
    fn name(&self) -> &'static str {
        "searchapi"
    }

    async fn search(&self, query: &SearchQuery) -> Result<SearchResults, SearchError> {
        let mut out = SearchResults::default();
        let range = match parse_tbs(query.tbs.as_deref()) {
            Ok(r) => r,
            Err(w) => {
                out.warnings.push(w);
                None
            }
        };
        let mut sources = if query.sources.is_empty() {
            vec![SearchSource::Web]
        } else {
            query.sources.clone()
        };
        sources.sort();
        sources.dedup();
        let q = decorate_query(
            &query.query,
            &query.include_domains,
            &query.exclude_domains,
            &query.categories,
        );
        // the requested limit is applied after filtering, so ask for headroom when filters are on
        let filtered = !query.include_domains.is_empty()
            || !query.exclude_domains.is_empty()
            || !query.categories.is_empty();
        let num = if filtered {
            query.limit.saturating_mul(3)
        } else {
            query.limit
        }
        .clamp(1, MAX_NUM);
        for source in sources {
            let Some(engine) = self.engine_for(source) else {
                out.warnings.push(format!(
                    "engine {:?} has no {} vertical; that source was skipped",
                    self.engine,
                    if source == SearchSource::News {
                        "news"
                    } else {
                        "images"
                    }
                ));
                continue;
            };
            let mut params: Vec<(&str, String)> =
                vec![("engine", engine), ("q", q.clone()), ("num", num.to_string())];
            if let Some(r) = range {
                params.push(("time_period", time_period(r).to_owned()));
            }
            if let Some(l) = &query.location {
                params.push(("location", l.clone()));
            }
            if let Some(c) = &query.country {
                params.push(("gl", c.to_ascii_lowercase()));
            }
            if query.safe == Some(true) {
                params.push(("safe", "active".to_owned()));
            }
            let request = self
                .client
                .get(self.endpoint.clone())
                .query(&params)
                .bearer_auth(self.api_key.expose());
            let reply = get_json(request, query.timeout, MAX_REPLY_BYTES).await?;
            if let Some(err) = reply.get("error").and_then(Value::as_str) {
                return Err(SearchError::InvalidReply(format!("provider error: {err}")));
            }
            let mut seen: BTreeSet<String> = BTreeSet::new();
            let mut collected = 0_usize;
            match source {
                SearchSource::Web | SearchSource::News => {
                    let items = reply.get("organic_results").or_else(|| reply.get("news_results"));
                    for h in items
                        .and_then(Value::as_array)
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                    {
                        let url = text(h, "link");
                        if collected >= query.limit
                            || !url_allowed(
                                &url,
                                &query.include_domains,
                                &query.exclude_domains,
                                &query.categories,
                            )
                            || !seen.insert(url.clone())
                        {
                            continue;
                        }
                        collected += 1;
                        let position = u32::try_from(collected).unwrap_or(u32::MAX);
                        if source == SearchSource::Web {
                            out.web.push(WebHit {
                                title: text(h, "title"),
                                url,
                                description: text(h, "snippet"),
                                category: None,
                                position,
                            });
                        } else {
                            out.news.push(NewsHit {
                                title: text(h, "title"),
                                url,
                                snippet: text(h, "snippet"),
                                date: opt_text(h, "date"),
                                image_url: opt_text(h, "thumbnail"),
                                position,
                            });
                        }
                    }
                }
                SearchSource::Images => {
                    let items = reply.get("images").and_then(Value::as_array);
                    for h in items.map(Vec::as_slice).unwrap_or_default() {
                        let page = h
                            .get("source")
                            .map(|s| text(s, "link"))
                            .filter(|s| !s.is_empty())
                            .unwrap_or_else(|| text(h, "link"));
                        let original = h.get("original").cloned().unwrap_or(Value::Null);
                        let image_url = opt_text(&original, "link").unwrap_or_else(|| text(h, "thumbnail"));
                        if collected >= query.limit
                            || !url_allowed(
                                &page,
                                &query.include_domains,
                                &query.exclude_domains,
                                &query.categories,
                            )
                            || !seen.insert(image_url.clone())
                        {
                            continue;
                        }
                        collected += 1;
                        out.images.push(ImageHit {
                            title: text(h, "title"),
                            url: page,
                            image_url,
                            image_width: dim(&original, "width"),
                            image_height: dim(&original, "height"),
                            position: u32::try_from(collected).unwrap_or(u32::MAX),
                        });
                    }
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn provider(server: &MockServer, engine: &str) -> SearchApiProvider {
        SearchApiProvider::new(
            "sk-secret",
            engine,
            Some(&format!("{}/api/v1/search", server.uri())),
        )
        .unwrap()
    }

    #[test]
    fn debug_redacts_endpoint_credentials_and_provider_key() {
        let provider = SearchApiProvider::new(
            "search-provider-key-canary",
            "google",
            Some("https://user:search-password-canary@example.test/search?token=search-query-canary"),
        )
        .unwrap();
        let debug = format!("{provider:?}");
        for secret in [
            "search-provider-key-canary",
            "search-password-canary",
            "search-query-canary",
        ] {
            assert!(!debug.contains(secret), "{debug}");
        }
    }

    #[tokio::test]
    async fn web_results_use_bearer_auth_and_query_params() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/search"))
            .and(header("authorization", "Bearer sk-secret"))
            .and(query_param("engine", "bing"))
            .and(query_param("time_period", "last_day"))
            .and(query_param("gl", "de"))
            .and(query_param("safe", "active"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"organic_results": [
                    {"position": 1, "title": "A", "link": "https://a.com/1", "snippet": "sa"},
                    {"position": 2, "title": "B", "link": "https://b.com/2", "snippet": "sb"},
                    {"position": 3, "title": "C", "link": "https://a.com/1", "snippet": "dup"},
                ]})),
            )
            .mount(&server)
            .await;
        let p = provider(&server, "bing");
        let mut q = SearchQuery::web("rust", 5);
        q.tbs = Some("qdr:d".into());
        q.country = Some("DE".into());
        q.safe = Some(true);
        let r = p.search(&q).await.unwrap();
        assert_eq!(r.web.len(), 2);
        assert_eq!(r.web[1].title, "B");
        assert!(!format!("{p:?}").contains("sk-secret"));
    }

    #[tokio::test]
    async fn google_verticals_and_unsupported_verticals() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("engine", "google_news"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"organic_results": [
                {"title": "N", "link": "https://n.com/1", "snippet": "s", "date": "1 day ago", "thumbnail": "https://n.com/t.png"}
            ]})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("engine", "google_images"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"images": [
                {"title": "I", "source": {"link": "https://i.com/p"}, "original": {"link": "https://i.com/x.png", "width": 800, "height": 600}}
            ]})))
            .mount(&server)
            .await;
        let mut q = SearchQuery::web("x", 3);
        q.sources = vec![SearchSource::News, SearchSource::Images];
        let r = provider(&server, "google").search(&q).await.unwrap();
        assert_eq!(r.news[0].date.as_deref(), Some("1 day ago"));
        assert_eq!(
            (r.images[0].image_width, r.images[0].image_height),
            (Some(800), Some(600))
        );
        let r = provider(&server, "bing").search(&q).await.unwrap();
        assert!(r.news.is_empty() && r.images.is_empty());
        assert_eq!(r.warnings.len(), 2);
    }

    #[tokio::test]
    async fn provider_errors_are_typed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("q", "quota"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("q", "bad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"error": "Invalid engine"})))
            .mount(&server)
            .await;
        let p = provider(&server, "google");
        assert_eq!(
            p.search(&SearchQuery::web("quota", 3)).await.unwrap_err(),
            SearchError::Status { status: 429 }
        );
        assert!(matches!(
            p.search(&SearchQuery::web("bad", 3)).await.unwrap_err(),
            SearchError::InvalidReply(_)
        ));
        assert!(SearchApiProvider::new("k", "google", Some("nope")).is_err());
    }
}
