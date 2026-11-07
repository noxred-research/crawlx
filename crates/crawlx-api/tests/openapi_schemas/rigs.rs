//! The APIs the drift tests talk to: an in-memory API with every mock backend wired (`Intel`), and
//! the scrape rig (a real worker over the same API).

use super::*;

/// Accepts every webhook delivery.
struct Accepting;

#[async_trait]
impl WebhookTransport for Accepting {
    async fn post(&self, _req: WebhookRequest) -> Result<u16, TransportError> {
        Ok(200)
    }
}

/// An in-memory API with a mock search backend, mock page tools, a mock toolkit provider and the
/// given LLM. Request controls and artifact content share the API's volatile delivery buffer.
pub struct Intel {
    pub app: Router,
    pub state: AppState,
    pub key: String,
    pub tools: Arc<MockPageTools>,
    pub search: Arc<MockSearch>,
}

pub fn web_hit(position: u32, url: &str) -> WebHit {
    WebHit {
        title: format!("Result {position}"),
        url: url.to_owned(),
        description: "a snippet".to_owned(),
        category: None,
        position,
    }
}

pub fn search_results() -> SearchResults {
    SearchResults {
        web: vec![
            web_hit(1, "https://rust-lang.org/"),
            web_hit(2, "https://doc.rust-lang.org/book"),
            web_hit(3, "https://github.com/rust-lang/rust/issues/1"),
            web_hit(4, "https://arxiv.org/abs/1706.03762"),
        ],
        news: vec![NewsHit {
            title: "News".to_owned(),
            url: "https://news.example.com/a".to_owned(),
            snippet: "a snippet".to_owned(),
            date: Some("2026-01-02".to_owned()),
            image_url: Some("https://news.example.com/a.png".to_owned()),
            position: 1,
        }],
        images: vec![ImageHit {
            title: "Logo".to_owned(),
            url: "https://rust-lang.org/".to_owned(),
            image_url: "https://rust-lang.org/logo.png".to_owned(),
            image_width: Some(64),
            image_height: Some(32),
            position: 1,
        }],
        ..SearchResults::default()
    }
}

/// An LLM that answers the prompts of every facade endpoint.
pub fn generic_llm() -> Arc<MockLlm> {
    Arc::new(MockLlm::from_fn(|call: &LlmCall| {
        let props = call
            .schema
            .as_ref()
            .and_then(|s| s.get("properties"))
            .cloned()
            .unwrap_or(Value::Null);
        let u = &call.user;
        if props.get("evidence").is_some() {
            Ok(json!({ "answer": "See the documentation.", "evidence": [] }))
        } else if props.get("confidence").is_some() {
            Ok(
                json!({ "answer": "Lower the limit.", "confidence": "medium", "fixParameters": { "limit": 5 } }),
            )
        } else if u.contains("Turn the crawl request into crawl options") {
            Ok(json!({ "limit": 5, "maxDiscoveryDepth": 2 }))
        } else if u.contains("Summarize the page") {
            Ok(json!({ "summary": "A fixture page." }))
        } else if u.contains("Answer the question") {
            Ok(json!({ "answer": "forty-two" }))
        } else if u.contains("most relevant to the query") {
            Ok(json!({ "highlights": ["The answer is forty-two."] }))
        } else if u.contains("Extract") || u.contains("extract") {
            Ok(json!({ "title": "Example" }))
        } else {
            Err(LlmError::InvalidOutput("unscripted".to_owned()))
        }
    }))
}

pub fn intel(llm: Option<Arc<dyn LlmExtractor>>) -> Intel {
    let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
    let store = Arc::new(MemoryStore::new());
    let zdr = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
    store.set_dataset_delivery(zdr.clone());
    let artifacts =
        Arc::new(MemoryArtifactStore::in_memory(store.clone(), clock.clone()).with_zdr_buffer(zdr.clone()));
    let (repos, api) = Repos::memory_with_api(store, artifacts);
    let tools = Arc::new(MockPageTools::new());
    let search = Arc::new(MockSearch::new(search_results()));
    let exchange = Arc::new(MockExchange::new(vec![Toolkit {
        slug: "apollo".to_owned(),
        name: "Apollo".to_owned(),
        capabilities: vec![Capability {
            name: "people/search".to_owned(),
            description: "find people at a company".to_owned(),
            paid: true,
            credits_estimate: Some(5),
            supports_zdr: false,
        }],
        terms: None,
    }]));
    let config = crawlx_api::ApiConfig {
        rate_limit_per_minute: 0,
        ..crawlx_api::ApiConfig::default()
    };
    let mut builder = AppState::builder(repos, AdmissionPolicy::new(clock.clone()), config)
        .settings(crawlx_api::Settings {
            max_active_runs: 1_000_000,
            ..crawlx_api::Settings::default()
        })
        .clock(clock)
        .zdr_buffer(zdr)
        .page_tools(tools.clone())
        .search_provider(search.clone())
        .exchange_provider(exchange)
        .job_webhooks(JobWebhookSink::new(Arc::new(Accepting), "whsec_test").allow_private_networks(true));
    if let Some(l) = llm {
        builder = builder.llm(l);
    }
    let state = builder.build();
    let app = crawlx_api::router(state.clone());
    let tenant = tenant_id_for("acme");
    let key = generate_key();
    let rec = key_record(&key, tenant, Scope::all_set()).unwrap();
    futures::executor::block_on(async {
        crawlx_api::ApiStore::key_insert(api.as_ref(), &rec, "acme")
            .await
            .unwrap();
    });
    Intel {
        app,
        state,
        key,
        tools,
        search,
    }
}

impl Intel {
    pub async fn call(&self, method: Method, path: &str, body: Option<&Value>) -> Reply {
        json_call(&self.app, Some(&self.key), method, &format!("{V2}{path}"), body).await
    }

    pub async fn get(&self, path: &str) -> Reply {
        self.call(Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Reply {
        self.call(Method::POST, path, Some(body)).await
    }
}

/// What a request told the test: the status, the `warnings[]` / `warning` the response carried and
/// the `details[]` of a rejection.
#[derive(Debug, Default)]
pub struct Report {
    pub status: u16,
    /// `(code, path)` of every `warnings[]` entry.
    pub warnings: Vec<(String, String)>,
    /// The `warning` text of the routes that report options as one string.
    pub text: String,
    /// `(path, code)` of every `details[]` entry.
    pub details: Vec<(String, String)>,
    pub body: Value,
}

impl Report {
    pub fn of(r: &Reply) -> Self {
        let pairs = |v: &Value, a: &str, b: &str| -> Vec<(String, String)> {
            v.as_array()
                .map(|xs| {
                    xs.iter()
                        .map(|x| {
                            (
                                x[a].as_str().unwrap_or_default().to_owned(),
                                x[b].as_str().unwrap_or_default().to_owned(),
                            )
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let warnings = if r.body["warnings"].is_array() {
            &r.body["warnings"]
        } else {
            &r.body["data"]["warnings"]
        };
        Self {
            status: r.status.as_u16(),
            warnings: pairs(warnings, "code", "path"),
            text: r.body["warning"].as_str().unwrap_or_default().to_owned(),
            details: pairs(&r.body["details"], "path", "code"),
            body: r.body.clone(),
        }
    }

    /// The request paths the response reports as unsupported options.
    pub fn unsupported(&self) -> BTreeSet<String> {
        let mut out: BTreeSet<String> = self
            .warnings
            .iter()
            .filter(|(code, _)| code == "unsupported_option")
            .map(|(_, path)| path.clone())
            .collect();
        if let Some(list) = self.text.split("unsupported options ignored: ").nth(1) {
            for key in list.split(';').next().unwrap_or_default().split(", ") {
                out.insert(format!("/{}", key.trim()));
            }
        }
        out
    }
}

/// A body part of a multipart upload.
pub fn multipart(parts: &[(&str, Option<&str>, &[u8])]) -> (String, Vec<u8>) {
    const BOUNDARY: &str = "----crawlxopenapiboundary7MA4YWxkTrZu0gW";
    let mut body = Vec::new();
    for (name, filename, data) in parts {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(f) => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\r\n").as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\nContent-Type: application/json\r\n\r\n")
                    .as_bytes(),
            ),
        }
        body.extend_from_slice(data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={BOUNDARY}"), body)
}

pub const UPLOAD_HTML: &str = r#"<!doctype html><html lang="en"><head><title>Uploaded Page</title><meta name="description" content="from a file"></head><body><nav><a href="/menu">Menu</a></nav><main><h1>Hello</h1><p>Body with <a href="https://example.com/abs">an absolute link</a>.</p><img src="pic.png" alt="pic"></main></body></html>"#;

/// `POST /parse` of `UPLOAD_HTML` with `options` as the options part.
pub async fn upload(app: &Router, key: &str, options: Option<&Value>) -> Reply {
    let opts = options.map(Value::to_string);
    let mut parts: Vec<(&str, Option<&str>, &[u8])> =
        vec![("file", Some("page.html"), UPLOAD_HTML.as_bytes())];
    if let Some(o) = &opts {
        parts.push(("options", None, o.as_bytes()));
    }
    let (content_type, body) = multipart(&parts);
    send(
        app,
        Some(key),
        &Method::POST,
        &format!("{V2}/parse"),
        Some(&content_type),
        &[],
        body,
    )
    .await
}

/// Every backend the request-drift probes need.
pub struct Rigs {
    /// A plain API without a worker (the `/scrape` envelope).
    pub plain: Env,
    /// An API with every mock backend and the generic LLM.
    pub ai: Intel,
    /// A real worker over its own API and a fixture site (`/map`).
    pub rig: scrape_rig::Rig,
    pub monitor: tokio::sync::OnceCell<String>,
    pub search_job: tokio::sync::OnceCell<String>,
}

impl Rigs {
    pub async fn start() -> Self {
        let llm: Arc<dyn LlmExtractor> = generic_llm();
        Self {
            plain: common::env(),
            ai: intel(Some(llm.clone())),
            rig: scrape_rig::Rig::start(scrape_rig::RigConfig {
                llm: Some(llm),
                ..scrape_rig::RigConfig::default()
            })
            .await,
            monitor: tokio::sync::OnceCell::new(),
            search_job: tokio::sync::OnceCell::new(),
        }
    }

    /// The id of a monitor `PATCH` can change.
    pub async fn monitor_id(&self) -> String {
        self.monitor
            .get_or_init(|| async {
                let r = self
                    .ai
                    .post(
                        "/monitor",
                        &json!({
                            "name": "base",
                            "schedule": { "text": "every 30 minutes" },
                            "targets": [{ "type": "scrape", "urls": ["https://a.example.test/"] }],
                        }),
                    )
                    .await;
                assert_eq!(r.status, StatusCode::OK, "{}", r.body);
                r.body["data"]["id"].as_str().unwrap().to_owned()
            })
            .await
            .clone()
    }

    /// The id of a search the tenant ran (a job feedback may be about).
    pub async fn search_job_id(&self) -> String {
        self.search_job
            .get_or_init(|| async {
                let r = self.ai.post("/search", &json!({ "query": "rust" })).await;
                assert_eq!(r.status, StatusCode::OK, "{}", r.body);
                r.body["id"].as_str().unwrap().to_owned()
            })
            .await
            .clone()
    }
}
