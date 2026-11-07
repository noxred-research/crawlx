//! [`SearxngProvider`]: a SearXNG instance queried through its JSON API
//! (`GET <endpoint>/search?format=json`). Settings: `SEARXNG_ENDPOINT`, `SEARXNG_ENGINES`,
//! `SEARXNG_CATEGORIES` (see [`crate::config::SearchSettings`]).

use crate::intel::search::{
    ImageHit, NewsHit, SearchCategory, SearchError, SearchProvider, SearchQuery, SearchResults, SearchSource,
    WebHit,
};
use crate::intel::search_http::{
    decorate_query, get_json, parse_tbs, url_allowed, TimeRange, MAX_REPLY_BYTES,
};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// SearXNG result pages fetched for one source at most (about ten hits each).
const MAX_PAGES: u32 = 10;

/// A SearXNG JSON search client.
#[derive(Clone, Debug)]
pub struct SearxngProvider {
    client: reqwest::Client,
    endpoint: url::Url,
    engines: Vec<String>,
    categories: Vec<String>,
}

impl SearxngProvider {
    /// A client for the instance at `endpoint`. `engines` is passed as `engines=` and
    /// `categories` as `categories=` for web searches that name no category (both empty means the
    /// instance defaults).
    ///
    /// # Errors
    /// [`SearchError::Transport`] when `endpoint` is not an absolute http(s) URL or the HTTP
    /// client cannot be built.
    pub fn new(endpoint: &str, engines: Vec<String>, categories: Vec<String>) -> Result<Self, SearchError> {
        let mut url = url::Url::parse(endpoint)
            .ok()
            .filter(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
            .ok_or_else(|| SearchError::Transport(format!("invalid SearXNG endpoint {endpoint:?}")))?;
        if !url.path().ends_with('/') {
            let p = format!("{}/", url.path());
            url.set_path(&p);
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(3))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("crawlx/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| SearchError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            endpoint: url,
            engines,
            categories,
        })
    }

    /// SearXNG `categories=` for one source and query categories.
    fn categories_param(&self, source: SearchSource, wanted: &[SearchCategory]) -> Option<String> {
        match source {
            SearchSource::News => Some("news".to_owned()),
            SearchSource::Images => Some("images".to_owned()),
            SearchSource::Web => {
                let mut cats: BTreeSet<&str> = BTreeSet::new();
                for c in wanted {
                    match c {
                        SearchCategory::Research => {
                            cats.insert("science");
                        }
                        SearchCategory::Github | SearchCategory::Developer => {
                            cats.insert("it");
                        }
                        SearchCategory::Pdf | SearchCategory::Gov => {
                            cats.insert("general");
                        }
                    }
                }
                if cats.is_empty() {
                    if self.categories.is_empty() {
                        None
                    } else {
                        Some(self.categories.join(","))
                    }
                } else {
                    Some(cats.into_iter().collect::<Vec<_>>().join(","))
                }
            }
        }
    }

    async fn page(
        &self,
        query: &SearchQuery,
        source: SearchSource,
        q: &str,
        pageno: u32,
        remaining: Duration,
        range: Option<TimeRange>,
    ) -> Result<Vec<Value>, SearchError> {
        let url = self
            .endpoint
            .join("search")
            .map_err(|e| SearchError::Transport(e.to_string()))?;
        let mut params: Vec<(&str, String)> = vec![
            ("q", q.to_owned()),
            ("format", "json".to_owned()),
            ("pageno", pageno.to_string()),
        ];
        if let Some(c) = self.categories_param(source, &query.categories) {
            params.push(("categories", c));
        }
        if !self.engines.is_empty() && source == SearchSource::Web {
            params.push(("engines", self.engines.join(",")));
        }
        if let Some(r) = range {
            let v = match r {
                TimeRange::Hour | TimeRange::Day => "day",
                TimeRange::Week => "week",
                TimeRange::Month => "month",
                TimeRange::Year => "year",
            };
            params.push(("time_range", v.to_owned()));
        }
        if query.safe == Some(true) {
            params.push(("safesearch", "2".to_owned()));
        }
        let reply = get_json(self.client.get(url).query(&params), remaining, MAX_REPLY_BYTES).await?;
        let results = reply
            .get("results")
            .and_then(Value::as_array)
            .ok_or_else(|| SearchError::InvalidReply("missing `results` array".to_owned()))?;
        Ok(results.clone())
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

/// `"1920 x 1080"` to `(1920, 1080)`.
fn resolution(v: &Value) -> (Option<u32>, Option<u32>) {
    let Some(r) = v.get("resolution").and_then(Value::as_str) else {
        return (None, None);
    };
    let mut it = r
        .split(['x', 'X', '\u{d7}'])
        .map(|p| p.trim().parse::<u32>().ok());
    (it.next().flatten(), it.next().flatten())
}

#[async_trait]
impl SearchProvider for SearxngProvider {
    fn name(&self) -> &'static str {
        "searxng"
    }

    async fn search(&self, query: &SearchQuery) -> Result<SearchResults, SearchError> {
        let started = Instant::now();
        let mut out = SearchResults::default();
        let range = match parse_tbs(query.tbs.as_deref()) {
            Ok(r) => r,
            Err(w) => {
                out.warnings.push(w);
                None
            }
        };
        if query.location.is_some() {
            out.warnings
                .push("location is not supported by SearXNG; ignored".to_owned());
        }
        let sources: Vec<SearchSource> = if query.sources.is_empty() {
            vec![SearchSource::Web]
        } else {
            let mut s = query.sources.clone();
            s.sort();
            s.dedup();
            s
        };
        let q = decorate_query(
            &query.query,
            &query.include_domains,
            &query.exclude_domains,
            &query.categories,
        );
        for source in sources {
            let mut seen: BTreeSet<String> = BTreeSet::new();
            let mut collected = 0_usize;
            for pageno in 1..=MAX_PAGES {
                let remaining = query.timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(SearchError::Timeout {
                        after_ms: u64::try_from(query.timeout.as_millis()).unwrap_or(u64::MAX),
                    });
                }
                let hits = self.page(query, source, &q, pageno, remaining, range).await?;
                if hits.is_empty() {
                    break;
                }
                let mut fresh = 0_usize;
                for h in &hits {
                    let url = text(h, "url");
                    let is_new = seen.insert(url.clone());
                    if is_new {
                        fresh += 1;
                    }
                    if collected >= query.limit
                        || !is_new
                        || !url_allowed(
                            &url,
                            &query.include_domains,
                            &query.exclude_domains,
                            &query.categories,
                        )
                    {
                        continue;
                    }
                    collected += 1;
                    let position = u32::try_from(collected).unwrap_or(u32::MAX);
                    match source {
                        SearchSource::Web => out.web.push(WebHit {
                            title: text(h, "title"),
                            url,
                            description: text(h, "content"),
                            category: opt_text(h, "category"),
                            position,
                        }),
                        SearchSource::News => out.news.push(NewsHit {
                            title: text(h, "title"),
                            url,
                            snippet: text(h, "content"),
                            date: opt_text(h, "publishedDate"),
                            image_url: opt_text(h, "thumbnail").or_else(|| opt_text(h, "img_src")),
                            position,
                        }),
                        SearchSource::Images => {
                            let (w, hgt) = resolution(h);
                            out.images.push(ImageHit {
                                title: text(h, "title"),
                                url,
                                image_url: text(h, "img_src"),
                                image_width: w,
                                image_height: hgt,
                                position,
                            });
                        }
                    }
                }
                if collected >= query.limit || fresh == 0 {
                    break;
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
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn hit(i: u32, host: &str) -> Value {
        json!({"url": format!("https://{host}/p{i}"), "title": format!("T{i}"), "content": format!("D{i}"), "category": "general"})
    }

    #[tokio::test]
    async fn pages_until_limit_and_maps_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .and(query_param("pageno", "1"))
            .and(query_param("format", "json"))
            .and(query_param("engines", "google,bing"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"results": [hit(1, "a.com"), hit(2, "a.com")]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/search"))
            .and(query_param("pageno", "2"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"results": [hit(2, "a.com"), hit(3, "b.com")]})),
            )
            .mount(&server)
            .await;
        let p = SearxngProvider::new(&server.uri(), vec!["google".into(), "bing".into()], vec![]).unwrap();
        let r = p.search(&SearchQuery::web("rust", 3)).await.unwrap();
        let urls: Vec<&str> = r.web.iter().map(|w| w.url.as_str()).collect();
        assert_eq!(
            urls,
            ["https://a.com/p1", "https://a.com/p2", "https://b.com/p3"],
            "duplicates dropped, limit honoured"
        );
        assert_eq!(r.web[2].position, 3);
        assert_eq!(r.web[0].description, "D1");
    }

    #[tokio::test]
    async fn news_images_time_range_and_domain_filters() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("categories", "news"))
            .and(query_param("time_range", "week"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [
                {"url": "https://n.com/1", "title": "N", "content": "S", "publishedDate": "2026-01-02", "thumbnail": "https://n.com/t.png"},
                {"url": "https://blocked.com/2", "title": "B", "content": "S"},
            ]})))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("categories", "images"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [
                {"url": "https://i.com/page", "title": "I", "img_src": "https://i.com/x.jpg", "resolution": "640 x 480"},
            ]})))
            .mount(&server)
            .await;
        let p = SearxngProvider::new(&server.uri(), vec![], vec![]).unwrap();
        let mut q = SearchQuery::web("x", 5);
        q.sources = vec![SearchSource::News, SearchSource::Images];
        q.tbs = Some("qdr:w".into());
        q.exclude_domains = vec!["blocked.com".into()];
        let r = p.search(&q).await.unwrap();
        assert_eq!(r.news.len(), 1);
        assert_eq!(r.news[0].date.as_deref(), Some("2026-01-02"));
        assert_eq!(r.news[0].image_url.as_deref(), Some("https://n.com/t.png"));
        assert_eq!(
            (r.images[0].image_width, r.images[0].image_height),
            (Some(640), Some(480))
        );
        assert!(r.warnings.is_empty());
    }

    #[tokio::test]
    async fn research_category_selects_science_and_warnings_report_ignored_options() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("categories", "science"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [hit(1, "arxiv.org")]})))
            .mount(&server)
            .await;
        let p = SearxngProvider::new(&server.uri(), vec![], vec![]).unwrap();
        let mut q = SearchQuery::web("x", 5);
        q.categories = vec![SearchCategory::Research];
        q.location = Some("Berlin".into());
        q.tbs = Some("cdr:1,cd_min:1/1/2020,cd_max:1/2/2020".into());
        let r = p.search(&q).await.unwrap();
        assert_eq!(r.web.len(), 1);
        assert_eq!(r.warnings.len(), 2, "{:?}", r.warnings);
    }

    #[tokio::test]
    async fn failures_are_typed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param("q", "status"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("q", "junk"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("q", "slow"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_delay(Duration::from_secs(3))
                    .set_body_json(json!({"results": []})),
            )
            .mount(&server)
            .await;
        let p = SearxngProvider::new(&server.uri(), vec![], vec![]).unwrap();
        assert_eq!(
            p.search(&SearchQuery::web("status", 3)).await.unwrap_err(),
            SearchError::Status { status: 503 }
        );
        assert!(matches!(
            p.search(&SearchQuery::web("junk", 3)).await.unwrap_err(),
            SearchError::InvalidReply(_)
        ));
        let mut slow = SearchQuery::web("slow", 3);
        slow.timeout = Duration::from_millis(200);
        assert!(matches!(
            p.search(&slow).await.unwrap_err(),
            SearchError::Timeout { .. }
        ));
        assert!(SearxngProvider::new("not a url", vec![], vec![]).is_err());
    }
}
