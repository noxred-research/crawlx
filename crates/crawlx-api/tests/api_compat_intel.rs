#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! compat v2 compat endpoints backed by an LLM, a search provider and page tools:
//! `/search` (+ feedback, categories), `/extract`, `/team/*`, `/feedback`,
//! `/support/*`, health probes. Every backend is a mock or a wiremock server.

use async_trait::async_trait;
use axum::body::Body;
#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::config::IntelConfig;
use crawlx_api::intel::metasearch::MetasearchProvider;
use crawlx_api::intel::search::{
    MockSearch, NewsHit, SearchCategory, SearchError, SearchProvider, SearchQuery, SearchResults, WebHit,
};
use crawlx_api::intel::tools::{MapLink, MockPageTools, ToolError};
use crawlx_api::intel::webhook::{compat_signature, JobWebhookSink};
use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookTransport};
use crawlx_api::{ApiConfig, AppState, Repos, Scope};
use crawlx_core::TenantId;
use crawlx_model::llm::{LlmError, MockLlm};
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::MemoryStore;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;

const V2: &str = "/compat/v2";
const SECRET: &str = "whsec_test";

#[derive(Default)]
struct Recorder {
    sent: Mutex<Vec<WebhookRequest>>,
}

#[async_trait]
impl WebhookTransport for Recorder {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        self.sent.lock().push(req);
        Ok(200)
    }
}

struct T {
    app: Router,
    state: AppState,
    key: String,
    tenant: TenantId,
    tools: Arc<MockPageTools>,
    hooks: Arc<Recorder>,
}

struct Setup {
    llm: Option<Arc<MockLlm>>,
    search: Option<Arc<dyn SearchProvider>>,
    intel: IntelConfig,
}

impl Setup {
    fn new() -> Self {
        Self {
            llm: None,
            search: None,
            intel: IntelConfig::default(),
        }
    }

    fn llm(mut self, llm: MockLlm) -> Self {
        self.llm = Some(Arc::new(llm));
        self
    }

    fn search(mut self, s: Arc<dyn SearchProvider>) -> Self {
        self.search = Some(s);
        self
    }

    fn build(self) -> T {
        let store = Arc::new(MemoryStore::new());
        let repos = Repos::memory(store);
        let hooks = Arc::new(Recorder::default());
        let tools = Arc::new(MockPageTools::new());
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            webhook_secret: SECRET.to_owned(),
            intel: self.intel,
            ..ApiConfig::default()
        };
        let sink = JobWebhookSink::new(hooks.clone(), SECRET)
            .allow_private_networks(true)
            .retry_delays([Duration::ZERO, Duration::ZERO]);
        let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
        let mut b = AppState::builder(repos.clone(), AdmissionPolicy::new(clock.clone()), config)
            .clock(clock)
            .page_tools(tools.clone())
            .job_webhooks(sink);
        if let Some(l) = self.llm {
            b = b.llm(l);
        }
        if let Some(s) = self.search {
            b = b.search_provider(s);
        }
        let state = b.build();
        let app = crawlx_api::router(state.clone());
        let tenant = tenant_id_for("acme");
        let key = generate_key();
        let rec = key_record(&key, tenant, Scope::all_set()).unwrap();
        futures::executor::block_on(async { repos.api.key_insert(&rec, "acme").await.unwrap() });
        T {
            app,
            state,
            key,
            tenant,
            tools,
            hooks,
        }
    }
}

impl T {
    async fn call(
        &self,
        method: Method,
        uri: &str,
        key: Option<&str>,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(k) = key {
            b = b.header("authorization", format!("Bearer {k}"));
        }
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, v)
    }

    async fn post(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        self.call(Method::POST, &format!("{V2}{path}"), Some(&self.key), Some(body))
            .await
    }

    async fn get(&self, path: &str) -> (StatusCode, Value) {
        self.call(Method::GET, &format!("{V2}{path}"), Some(&self.key), None)
            .await
    }

    async fn other_key(&self) -> String {
        let key = generate_key();
        let rec = key_record(&key, tenant_id_for("globex"), Scope::all_set()).unwrap();
        self.state.repos.api.key_insert(&rec, "globex").await.unwrap();
        key
    }

    /// Poll `path` until its `status` is no longer `processing`.
    async fn finished(&self, path: &str) -> Value {
        for _ in 0..250 {
            let (s, v) = self.get(path).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            if v["status"] != "processing" {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("job at {path} never finished");
    }

    /// Webhook bodies delivered so far, once at least `n` arrived.
    async fn webhooks(&self, n: usize) -> Vec<(Vec<(String, String)>, Value)> {
        for _ in 0..250 {
            let sent = self.hooks.sent.lock().clone();
            if sent.len() >= n {
                return sent
                    .into_iter()
                    .map(|r| {
                        let sig = r
                            .headers
                            .iter()
                            .find(|(k, _)| k == "X-Firecrawl-Signature") // wire-compat
                            .map(|(_, v)| v.clone())
                            .unwrap();
                        assert_eq!(
                            sig,
                            compat_signature(SECRET, &r.body),
                            "signature covers the raw body"
                        );
                        (r.headers.clone(), serde_json::from_slice(&r.body).unwrap())
                    })
                    .collect();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!(
            "fewer than {n} webhooks delivered: {}",
            self.hooks.sent.lock().len()
        );
    }
}

fn web(title: &str, url: &str, position: u32) -> WebHit {
    WebHit {
        title: title.to_owned(),
        url: url.to_owned(),
        description: format!("about {title}"),
        category: None,
        position,
    }
}

fn results() -> SearchResults {
    SearchResults {
        web: vec![
            web("Rust", "https://rust-lang.org/", 1),
            web("Docs", "https://doc.rust-lang.org/book", 2),
        ],
        news: vec![NewsHit {
            title: "News".into(),
            url: "https://news.example.com/a".into(),
            snippet: "snippet".into(),
            date: Some("2026-01-02".into()),
            image_url: None,
            position: 1,
        }],
        ..SearchResults::default()
    }
}

// ---- /search ----------------------------------------------------------------------------------------

#[tokio::test]
async fn search_returns_grouped_results_credits_and_ledger_rows() {
    let mock = Arc::new(MockSearch::new(results()));
    let t = Setup::new().search(mock.clone()).build();
    let (s, v) = t
        .post(
            "/search",
            &json!({"query": "rust", "limit": 5, "sources": ["web", {"type": "news"}], "tbs": "qdr:w", "country": "DE", "includeDomains": ["rust-lang.org"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    assert_eq!(v["data"]["web"][0]["title"], "Rust");
    assert_eq!(v["data"]["web"][1]["position"], 2);
    assert_eq!(v["data"]["news"][0]["date"], "2026-01-02");
    assert!(
        v["data"].get("images").is_none(),
        "only requested sources are present"
    );
    assert_eq!(
        v["creditsUsed"], 4,
        "two credits per started block of ten results, per source"
    );
    assert!(v["warning"].is_null());
    let q = &mock.queries()[0];
    assert_eq!(q.query, "rust");
    assert_eq!(q.limit, 5);
    assert_eq!(q.tbs.as_deref(), Some("qdr:w"));
    assert_eq!(q.country.as_deref(), Some("DE"));
    assert_eq!(q.include_domains, ["rust-lang.org"]);

    let (_, usage) = t.get("/team/credit-usage").await;
    assert_eq!(usage["data"]["creditsUsed"], 4);
    assert_eq!(usage["data"]["remainingCredits"], -1);
    let (_, act) = t.get("/team/activity?endpoint=search").await;
    assert_eq!(act["data"].as_array().unwrap().len(), 1);
    assert_eq!(act["data"][0]["endpoint"], "search");
    assert_eq!(act["data"][0]["id"], v["id"]);
}

#[tokio::test]
async fn search_passes_categories_and_reports_validation_errors_together() {
    let mock = Arc::new(MockSearch::new(results()));
    let t = Setup::new().search(mock.clone()).build();
    let (s, v) = t
        .post(
            "/search",
            &json!({"query": "q", "categories": [{"type": "research"}, "pdf"], "sources": ["alexandria"]}), // wire-compat
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        mock.queries()[0].categories,
        [SearchCategory::Research, SearchCategory::Pdf]
    );
    assert!(v["warning"].as_str().unwrap().contains("alexandria"), "{v}"); // wire-compat

    let (s, v) = t
        .post("/search", &json!({"limit": 0, "sources": ["video"], "includeDomains": ["a.com"], "excludeDomains": ["b.com"]}))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let paths: Vec<&str> = v["details"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["path"].as_str().unwrap())
        .collect();
    assert!(
        paths.contains(&"/query") && paths.contains(&"/limit") && paths.contains(&"/sources/0"),
        "{paths:?}"
    );
}

#[tokio::test]
async fn search_without_backend_or_credentials_is_a_typed_error() {
    let t = Setup::new().build();
    let (s, v) = t.post("/search", &json!({"query": "q"})).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(v["code"], "search_not_configured");
    let (s, _) = t
        .call(
            Method::POST,
            &format!("{V2}/search"),
            None,
            Some(&json!({"query": "q"})),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let read_only = {
        let key = generate_key();
        let rec = key_record(&key, t.tenant, [Scope::CrawlsRead].into_iter().collect()).unwrap();
        t.state.repos.api.key_insert(&rec, "acme").await.unwrap();
        key
    };
    let (s, v) = t
        .call(
            Method::POST,
            &format!("{V2}/search"),
            Some(&read_only),
            Some(&json!({"query": "q"})),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
}

struct Failing(SearchError);

#[async_trait]
impl SearchProvider for Failing {
    fn name(&self) -> &'static str {
        "failing"
    }

    async fn search(&self, _: &SearchQuery) -> Result<SearchResults, SearchError> {
        Err(self.0.clone())
    }
}

#[tokio::test]
async fn provider_failures_map_to_gateway_statuses() {
    let t = Setup::new()
        .search(Arc::new(Failing(SearchError::Timeout { after_ms: 5 })))
        .build();
    let (s, v) = t.post("/search", &json!({"query": "q"})).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::GATEWAY_TIMEOUT, Some("search_timeout"))
    );
    let t = Setup::new()
        .search(Arc::new(Failing(SearchError::Status { status: 503 })))
        .build();
    let (s, v) = t.post("/search", &json!({"query": "q"})).await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::BAD_GATEWAY, Some("search_unavailable"))
    );
}

#[tokio::test]
async fn search_scrape_options_merge_documents_and_record_failures() {
    let t = Setup::new().search(Arc::new(MockSearch::new(results()))).build();
    t.tools
        .set_markdown("https://rust-lang.org/", "# Rust\nA language.");
    t.tools.set_failure(
        "https://doc.rust-lang.org/book",
        ToolError::Failed("blocked".into()),
    );
    let (s, v) = t
        .post(
            "/search",
            &json!({"query": "rust", "scrapeOptions": {"formats": ["markdown"]}}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let first = &v["data"]["web"][0];
    assert_eq!(first["markdown"], "# Rust\nA language.");
    assert_eq!(first["metadata"]["sourceURL"], "https://rust-lang.org/");
    assert_eq!(
        first["title"], "Rust",
        "search fields are kept next to the scraped document"
    );
    let second = &v["data"]["web"][1];
    assert_eq!(second["metadata"]["error"], "blocked");
    assert!(second.get("markdown").is_none());
    assert_eq!(
        v["creditsUsed"],
        2 + 1,
        "two for the search block, one for the scraped page"
    );
    let scraped = t.tools.scraped();
    assert_eq!(scraped.len(), 2);
    assert_eq!(scraped[0].1, json!({"formats": ["markdown"]}));
}

#[tokio::test]
async fn metasearch_end_to_end_through_the_route() {
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/search"))
        .and(query_param("format", "json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [
            {"url": "https://a.com/1", "title": "A1", "content": "first"},
            {"url": "https://b.com/2", "title": "B2", "content": "second"},
            {"url": "https://a.com/3", "title": "A3", "content": "third"},
        ]})))
        .mount(&server)
        .await;
    let provider = Arc::new(MetasearchProvider::new(&server.uri(), vec![], vec![]).unwrap());
    let t = Setup::new().search(provider).build();
    let (s, v) = t
        .post(
            "/search",
            &json!({"query": "x", "limit": 5, "excludeDomains": ["b.com"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let urls: Vec<&str> = v["data"]["web"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["url"].as_str().unwrap())
        .collect();
    assert_eq!(urls, ["https://a.com/1", "https://a.com/3"]);
    let received = server.received_requests().await.unwrap();
    let q = received[0].url.query().unwrap();
    assert!(q.contains("-site%3Ab.com") || q.contains("-site:b.com"), "{q}");
}

#[tokio::test]
async fn search_feedback_is_validated_idempotent_and_tenant_scoped() {
    let t = Setup::new().search(Arc::new(MockSearch::new(results()))).build();
    let (_, search) = t.post("/search", &json!({"query": "rust"})).await;
    let id = search["id"].as_str().unwrap().to_owned();
    let (s, v) = t
        .post(
            &format!("/search/{id}/feedback"),
            &json!({"rating": "good", "valuableResults": [{"source": "web", "position": 1}]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    assert_eq!(v["creditsRefunded"], 0);
    let feedback_id = v["feedbackId"].clone();
    let (_, again) = t
        .post(
            &format!("/search/{id}/feedback"),
            &json!({"rating": "bad", "querySuggestions": "use quotes"}),
        )
        .await;
    assert_eq!(again["alreadySubmitted"], true);
    assert_eq!(again["feedbackId"], feedback_id);

    let (s, v) = t
        .post(&format!("/search/{id}/feedback"), &json!({"rating": "good"}))
        .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a good rating needs valuable sources or results: {v}"
    );
    let (s, _) = t
        .post(
            &format!("/search/{}/feedback", uuid::Uuid::now_v7()),
            &json!({"rating": "bad", "querySuggestions": "x"}),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let other = t.other_key().await;
    let (s, _) = t
        .call(
            Method::POST,
            &format!("{V2}/search/{id}/feedback"),
            Some(&other),
            Some(&json!({"rating": "bad", "querySuggestions": "x"})),
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "another tenant cannot rate this search");

    let (s, v) = t
        .post("/feedback", &json!({"endpoint": "search", "jobId": id, "rating": "partial", "missingContent": [{"topic": "pricing"}]}))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true);
    let (s, _) = t
        .post(
            "/feedback",
            &json!({"endpoint": "crawl", "jobId": id, "rating": "bad"}),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---- category indexes -----------------------------------------------------------------------------------

#[tokio::test]
async fn developer_search_classifies_github_hits_and_reports_coverage() {
    let mock = Arc::new(MockSearch::new(SearchResults {
        web: vec![
            web("issue", "https://github.com/acme/app/issues/12", 1),
            web("pr", "https://github.com/acme/app/pull/7", 2),
            web("readme", "https://github.com/acme/app", 3),
            web("docs", "https://docs.rs/app", 4),
        ],
        ..SearchResults::default()
    }));
    let t = Setup::new().search(mock.clone()).build();
    let (s, v) = t
        .post(
            "/search/developer",
            &json!({"query": "panic", "k": 10, "types": ["issue", "pull_request", "readme"]}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let ids: Vec<&str> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    assert_eq!(
        ids,
        ["issue:acme/app#12", "pull_request:acme/app#7", "readme:acme/app"],
        "docs hit filtered out by `types`"
    );
    assert_eq!(v["coverage"]["doc"], "skipped");
    assert_eq!(v["coverage"]["issue"], "ok");
    assert_eq!(v["results"][0]["passages"][0]["text"], "about issue");
    assert_eq!(mock.queries()[0].categories, [SearchCategory::Github]);
    let (s, v) = t.get("/search/developer?query=panic&types=doc").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["results"][0]["type"], "doc");
    assert_eq!(v["coverage"]["readme"], "skipped");
    let (s, _) = t.get("/search/developer").await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "query is required");
}

#[tokio::test]
async fn gov_search_uses_the_gov_category() {
    let mock = Arc::new(MockSearch::new(results()));
    let t = Setup::new().search(mock.clone()).build();
    let (s, v) = t
        .post(
            "/search/gov",
            &json!({"query": "tax", "domain": "irs.gov", "court": "scotus"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"]["web"][0]["position"], 1);
    assert!(v["warning"].as_str().unwrap().contains("court"), "{v}");
    let q = &mock.queries()[0];
    assert_eq!(q.categories, [SearchCategory::Gov]);
    assert_eq!(q.include_domains, ["irs.gov"]);
}

#[tokio::test]
async fn research_papers_search_read_and_similar() {
    let mock = Arc::new(MockSearch::new(SearchResults {
        web: vec![
            web("Attention paper", "https://arxiv.org/abs/1706.03762", 1),
            web("Other paper", "https://doi.org/10.1000/xyz", 2),
        ],
        ..SearchResults::default()
    }));
    let t = Setup::new().search(mock.clone()).build();
    let (s, v) = t.get("/search/research/papers?query=transformers&k=5").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["results"][0]["primaryId"], "arxiv:1706.03762");
    assert_eq!(v["results"][0]["ids"]["arxiv"][0], "1706.03762");
    assert_eq!(v["results"][1]["paperId"], "doi:10.1000/xyz");
    assert_eq!(v["results"][0]["score"], 1.0);
    assert_eq!(mock.queries()[0].categories, [SearchCategory::Research]);

    t.tools.set_document(
        "https://arxiv.org/abs/1706.03762",
        json!({"markdown": "Abstract. The dominant sequence transduction models are based on complex recurrent networks and attention.",
               "metadata": {"citation_title": "Attention Is All You Need", "description": "We propose the Transformer.", "citation_author": "Vaswani, Ashish"}}),
    );
    t.tools.set_markdown(
        "https://arxiv.org/pdf/1706.03762",
        "Intro paragraph about nothing in particular that matters here at all.\n\nMulti-head attention allows the model to jointly attend to information from different positions.\n\nTraining used eight GPUs for several days of wall clock time overall.",
    );
    let (s, v) = t.get("/search/research/papers/arxiv:1706.03762").await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["paper"]["title"], "Attention Is All You Need");
    assert_eq!(v["paper"]["abstract"], "We propose the Transformer.");
    assert_eq!(v["paper"]["authors"], "Vaswani, Ashish");
    let (s, v) = t
        .get("/search/research/papers/arxiv:1706.03762?query=multi-head%20attention&k=1")
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["passages"].as_array().unwrap().len(), 1);
    assert!(
        v["passages"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("Multi-head"),
        "{v}"
    );
    assert!(v["passages"][0]["score"].as_f64().unwrap() > 0.0);
    let (s, _) = t.get("/search/research/papers/bogus:1").await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, v) = t
        .get("/search/research/papers/arxiv:1706.03762/similar?intent=successors&mode=citers&k=3")
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["results"].as_array().unwrap().len(),
        1,
        "the paper itself is excluded: {v}"
    );
    assert_eq!(v["results"][0]["paperId"], "doi:10.1000/xyz");
    let q = mock.queries().pop().unwrap();
    assert!(
        q.query.contains("Attention Is All You Need") && q.query.contains("cited by"),
        "{}",
        q.query
    );
    let (s, _) = t.get("/search/research/papers/arxiv:1706.03762/similar").await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "intent is required");
}

// ---- /extract ----------------------------------------------------------------------------------------

fn extract_llm() -> MockLlm {
    MockLlm::from_fn(|call| {
        if call.user.contains("Extract") || call.user.contains("extract") {
            Ok(json!({"siteName": "Example Site", "category": "Technology"}))
        } else {
            Err(LlmError::InvalidOutput("unexpected call".into()))
        }
    })
}

#[tokio::test]
async fn extract_runs_a_job_validates_the_schema_and_delivers_webhooks() {
    let llm = Arc::new(extract_llm());
    let mut setup = Setup::new();
    setup.llm = Some(llm.clone());
    let t = setup.build();
    t.tools
        .set_markdown("https://example.com/", "Example Site is a blog.");
    t.tools
        .set_markdown("https://example.com/about", "About: category is Technology.");
    t.tools.set_links(
        "https://example.com",
        vec![
            MapLink {
                url: "https://example.com/".into(),
                title: None,
                description: None,
            },
            MapLink {
                url: "https://example.com/about".into(),
                title: None,
                description: None,
            },
            MapLink {
                url: "https://other.example.com/x".into(),
                title: None,
                description: None,
            },
        ],
    );
    let schema = json!({"type": "object", "properties": {"siteName": {"type": "string"}, "category": {"type": "string"}}, "required": ["siteName"]});
    let (s, v) = t
        .post(
            "/extract",
            &json!({
                "urls": ["https://example.com/*", "not a url"],
                "prompt": "Extract the site name and category",
                "schema": schema,
                "showSources": true,
                "webhook": {"url": "https://hooks.example.org/x", "metadata": {"run": 7}, "headers": {"X-Tenant": "acme"}},
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["invalidURLs"], json!(["not a url"]));
    let id = v["id"].as_str().unwrap().to_owned();
    let done = t.finished(&format!("/extract/{id}")).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        done["data"],
        json!({"siteName": "Example Site", "category": "Technology"})
    );
    assert!(done["tokensUsed"].as_u64().unwrap() > 0);
    assert!(done["expiresAt"].is_string());
    assert_eq!(done["sources"]["siteName"], json!(["https://example.com/"]));
    assert_eq!(done["sources"]["category"], json!(["https://example.com/about"]));
    // the glob expanded through the map tool: both example.com pages scraped, the other host not
    let scraped: Vec<String> = t.tools.scraped().into_iter().map(|(u, _)| u).collect();
    assert_eq!(scraped.len(), 2, "{scraped:?}");
    assert!(t
        .tools
        .scraped()
        .iter()
        .all(|(_, o)| o["formats"] == json!(["markdown"])));
    let call = &llm.calls()[0];
    assert_eq!(
        call.schema.as_ref().unwrap(),
        &schema,
        "the schema is sent as the structured-output contract"
    );
    assert!(call.user.contains("Example Site is a blog"));

    let hooks = t.webhooks(2).await;
    let types: Vec<&str> = hooks.iter().map(|(_, b)| b["type"].as_str().unwrap()).collect();
    assert_eq!(types, ["extract.started", "extract.completed"]);
    assert_eq!(hooks[1].1["id"], id.as_str());
    assert_eq!(hooks[1].1["metadata"], json!({"run": 7}));
    assert_eq!(hooks[1].1["data"][0]["data"]["siteName"], "Example Site");
    assert_eq!(hooks[1].1["data"][0]["totalUrlsScraped"], 2);
    assert!(hooks[1].0.iter().any(|(k, v)| k == "X-Tenant" && v == "acme"));
    assert!(hooks[0].1["webhookId"].is_string());

    let (_, usage) = t.get("/team/token-usage").await;
    assert_eq!(usage["data"]["tokensUsed"], done["tokensUsed"]);
    let (_, credits) = t.get("/team/credit-usage").await;
    assert_eq!(
        credits["data"]["creditsUsed"], 4,
        "the ledger row is the extraction step; real page tools record the scrapes themselves"
    );
    assert_eq!(
        done["creditsUsed"],
        2 + 4,
        "the job reports scrapes plus the extraction step"
    );
}

#[tokio::test]
async fn extract_repairs_one_schema_violation_then_fails_on_a_second() {
    let llm = MockLlm::scripted(vec![
        Ok(json!({"siteName": 5})),
        Ok(json!({"siteName": "Fixed"})),
        Ok(json!({"siteName": 5})),
        Ok(json!({"siteName": 6})),
    ]);
    let t = Setup::new().llm(llm).build();
    t.tools.set_markdown("https://example.com/", "Fixed is the name.");
    let body = json!({"urls": ["https://example.com/"], "schema": {"type": "object", "properties": {"siteName": {"type": "string"}}, "required": ["siteName"]}});
    let (_, v) = t.post("/extract", &body).await;
    let ok = t
        .finished(&format!("/extract/{}", v["id"].as_str().unwrap()))
        .await;
    assert_eq!(ok["status"], "completed", "{ok}");
    assert_eq!(ok["data"]["siteName"], "Fixed");

    let mut with_hook = body.clone();
    with_hook["webhook"] = json!("https://hooks.example.org/y");
    let before = t.hooks.sent.lock().len();
    let (_, v) = t.post("/extract", &with_hook).await;
    let failed = t
        .finished(&format!("/extract/{}", v["id"].as_str().unwrap()))
        .await;
    assert_eq!(failed["status"], "failed", "{failed}");
    assert!(
        failed["error"]
            .as_str()
            .unwrap()
            .contains("does not match the schema"),
        "{failed}"
    );
    let hooks = t.webhooks(before + 2).await;
    let last = &hooks[hooks.len() - 1].1;
    assert_eq!(last["type"], "extract.failed");
    assert_eq!(last["success"], false);
    assert!(last["error"].as_str().unwrap().contains("schema"));
}

#[tokio::test]
async fn extract_validation_backends_and_isolation() {
    let t = Setup::new().build();
    let (s, v) = t
        .post("/extract", &json!({"urls": ["https://a.com"], "prompt": "p"}))
        .await;
    assert_eq!(
        (s, v["code"].as_str()),
        (StatusCode::SERVICE_UNAVAILABLE, Some("llm_not_configured"))
    );

    let t = Setup::new().llm(extract_llm()).build();
    let (s, v) = t.post("/extract", &json!({"urls": ["https://a.com"]})).await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "prompt or schema required: {v}"
    );
    let (s, v) = t
        .post(
            "/extract",
            &json!({"urls": ["nope"], "prompt": "p", "ignoreInvalidURLs": false}),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(v["details"][0]["path"], "/urls/0");
    let (s, _) = t
        .post(
            "/extract",
            &json!({"urls": ["https://a.com"], "prompt": "p", "schema": {"type": 12}}),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = t
        .post(
            "/extract",
            &json!({"urls": ["https://a.com"], "prompt": "p", "webhook": {"url": "ftp://x"}}),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    t.tools.set_markdown("https://a.com/", "Example Site data");
    let (_, v) = t
        .post(
            "/extract",
            &json!({"urls": ["https://a.com/"], "prompt": "Extract the site"}),
        )
        .await;
    let id = v["id"].as_str().unwrap().to_owned();
    let done = t.finished(&format!("/extract/{id}")).await;
    assert_eq!(done["status"], "completed");
    assert!(done.get("sources").is_none(), "sources only with showSources");
    let other = t.other_key().await;
    let (s, _) = t
        .call(Method::GET, &format!("{V2}/extract/{id}"), Some(&other), None)
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = t.get("/extract/not-a-uuid").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = t.get(&format!("/extract/{}", uuid::Uuid::now_v7())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn extract_with_web_search_reads_found_pages_and_fails_cleanly_without_content() {
    let search = Arc::new(MockSearch::new(SearchResults {
        web: vec![web("Found", "https://found.example.org/page", 1)],
        ..SearchResults::default()
    }));
    let t = Setup::new().llm(extract_llm()).search(search.clone()).build();
    t.tools
        .set_markdown("https://found.example.org/page", "Example Site found by search");
    let (s, v) = t
        .post(
            "/extract",
            &json!({"urls": [], "prompt": "Extract the site name", "enableWebSearch": true}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let done = t
        .finished(&format!("/extract/{}", v["id"].as_str().unwrap()))
        .await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(search.queries()[0].query, "Extract the site name");
    assert_eq!(t.tools.scraped()[0].0, "https://found.example.org/page");

    let t = Setup::new().llm(extract_llm()).build();
    let (_, v) = t
        .post(
            "/extract",
            &json!({"urls": ["https://gone.example.org/"], "prompt": "Extract"}),
        )
        .await;
    let failed = t
        .finished(&format!("/extract/{}", v["id"].as_str().unwrap()))
        .await;
    assert_eq!(failed["status"], "failed");
    assert!(
        failed["error"]
            .as_str()
            .unwrap()
            .contains("no page could be read"),
        "{failed}"
    );
}

// ---- team ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn team_reports_historical_usage_queue_and_activity_paging() {
    let t = Setup::new().search(Arc::new(MockSearch::new(results()))).build();
    for _ in 0..3 {
        let (s, _) = t.post("/search", &json!({"query": "rust"})).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (s, v) = t.get("/team/credit-usage/historical").await;
    assert_eq!(s, StatusCode::OK);
    let periods = v["periods"].as_array().unwrap();
    assert_eq!(periods.len(), 1);
    assert_eq!(
        periods[0]["totalCredits"], 6,
        "three searches of three results: two credits each"
    );
    assert!(periods[0]["apiKey"].is_null());
    let (_, v) = t.get("/team/token-usage/historical").await;
    assert_eq!(v["periods"][0]["totalTokens"], 0, "no LLM usage yet");

    let (_, q) = t.get("/team/queue-status").await;
    assert_eq!(
        (q["jobsInQueue"].clone(), q["waitingJobsInQueue"].clone()),
        (json!(0), json!(0))
    );
    assert!(q["mostRecentSuccess"].is_string());

    let (_, page1) = t.get("/team/activity?limit=2").await;
    assert_eq!(page1["data"].as_array().unwrap().len(), 2);
    assert_eq!(page1["has_more"], true);
    let cursor = page1["cursor"].as_str().unwrap();
    let (_, page2) = t.get(&format!("/team/activity?limit=2&cursor={cursor}")).await;
    assert_eq!(page2["data"].as_array().unwrap().len(), 1);
    assert_eq!(page2["has_more"], false);
    assert!(page2["cursor"].is_null());
    let (s, _) = t.get("/team/activity?limit=500").await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = t.get("/team/activity?cursor=%21%21").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let other = t.other_key().await;
    let (_, mine) = t
        .call(
            Method::GET,
            &format!("{V2}/team/credit-usage"),
            Some(&other),
            None,
        )
        .await;
    assert_eq!(mine["data"]["creditsUsed"], 0, "usage is per tenant");
}

// ---- support ---------------------------------------------------------------------------------------------

fn docs_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("webhooks.md"),
        "# Webhooks\n\nWebhook deliveries are signed: verify the X-Firecrawl-Signature header by recomputing the HMAC-SHA256 of the raw body with your secret.\n", // wire-compat
    )
    .unwrap();
    std::fs::write(
        dir.path().join("crawl.md"),
        "# Crawl\n\nA crawl follows links from the seed URL within the configured scope, limits and politeness budget.\n",
    )
    .unwrap();
    dir
}

#[tokio::test]
async fn docs_search_answers_with_citations_with_and_without_an_llm() {
    let dir = docs_dir();
    let mut setup = Setup::new();
    setup.intel.docs_dir = Some(dir.path().to_path_buf());
    let t = setup.build();
    let (s, v) = t
        .post(
            "/support/docs-search",
            &json!({"question": "how do I verify the webhook signature hmac"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["answer"].as_str().unwrap().contains("HMAC-SHA256"), "{v}");
    assert_eq!(v["evidence"][0]["pathOrUrl"], "webhooks.md");
    assert_eq!(v["usage"]["totalTokens"], 0);
    let (s, v) = t
        .post("/support/docs-search", &json!({"question": "zzzz qqqq"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["evidence"], json!([]));
    let (s, _) = t.post("/support/docs-search", &json!({})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let llm = Arc::new(MockLlm::scripted(vec![Ok(json!({
        "answer": "Recompute the HMAC over the raw body.",
        "evidence": [{"pathOrUrl": "webhooks.md", "reason": "signing"}, {"pathOrUrl": "invented.md", "reason": "x"}],
    }))]));
    let mut setup = Setup::new();
    setup.intel.docs_dir = Some(dir.path().to_path_buf());
    setup.llm = Some(llm.clone());
    let t = setup.build();
    let (s, v) = t
        .post(
            "/support/docs-search",
            &json!({"question": "verify webhook signature"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["answer"], "Recompute the HMAC over the raw body.");
    assert_eq!(
        v["evidence"].as_array().unwrap().len(),
        1,
        "citations of unknown documents are dropped: {v}"
    );
    assert!(v["usage"]["totalTokens"].as_u64().unwrap() > 0);
    assert!(
        llm.calls()[0].user.contains("X-Firecrawl-Signature"), // wire-compat
        "retrieved passages reach the model, fenced"
    );
}

#[tokio::test]
async fn support_ask_uses_docs_and_recent_failures() {
    let dir = docs_dir();
    let llm = Arc::new(MockLlm::scripted(vec![Ok(json!({
        "answer": "Raise the limit.", "confidence": "high", "fixParameters": {"limit": 50},
    }))]));
    let mut setup = Setup::new();
    setup.intel.docs_dir = Some(dir.path().to_path_buf());
    setup.llm = Some(llm.clone());
    let t = setup.build();
    let (s, v) = t
        .post(
            "/support/ask",
            &json!({"question": "my crawl stops early", "rationale": "limit"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["answer"], "Raise the limit.");
    assert_eq!(v["confidence"], "high");
    assert_eq!(v["fixParameters"], json!({"limit": 50}));
    assert!(v["durationMs"].is_number());

    let mut setup = Setup::new();
    setup.intel.docs_dir = Some(dir.path().to_path_buf());
    let t = setup.build();
    let (s, v) = t
        .post(
            "/support/ask",
            &json!({"question": "how do crawls follow links scope"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["confidence"], "low");
    assert!(v["answer"].as_str().unwrap().contains("seed URL"), "{v}");
    assert_eq!(v["evidence"][0]["pathOrUrl"], "crawl.md");
}

// ---- health and openapi ---------------------------------------------------------------------------------

#[tokio::test]
async fn health_probes_need_no_credentials() {
    let t = Setup::new().build();
    let (s, v) = t.call(Method::GET, "/v0/health/readiness", None, None).await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("ok")));
    let (s, v) = t.call(Method::GET, "/v0/health/liveness", None, None).await;
    assert_eq!((s, v["status"].as_str()), (StatusCode::OK, Some("ok")));
}

#[tokio::test]
async fn openapi_lists_the_intel_operations() {
    let t = Setup::new().build();
    let (s, doc) = t.call(Method::GET, "/v1/openapi.json", None, None).await;
    assert_eq!(s, StatusCode::OK);
    for (m, p) in [
        ("post", "/compat/v2/search"),
        ("post", "/compat/v2/search/{jobId}/feedback"),
        ("get", "/compat/v2/search/research/papers/{paperId}/similar"),
        ("post", "/compat/v2/extract"),
        ("get", "/compat/v2/extract/{id}"),
        ("get", "/compat/v2/team/activity"),
        ("post", "/compat/v2/support/docs-search"),
        ("get", "/v0/health/readiness"),
    ] {
        assert!(doc["paths"][p][m].is_object(), "missing {m} {p}");
    }
    assert_eq!(doc["paths"]["/v0/health/readiness"]["get"]["security"], json!([]));
}
