//! Response drift: real responses of the facade validate against the generated response schemas.
//!
//! The scrape, crawl, batch and map responses come from a real worker (`scrape_rig`) that fetches
//! a fixture site; the other endpoints run over mocked backends. Every response, error envelopes
//! included, is checked against the schema the document gives for that operation and status.

use super::rigs::*;
use super::*;
use crawlx_model::llm::{Completion, TokenUsage};
use futures::StreamExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Notify;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// The `(operation id, status)` pairs whose responses were validated.
#[derive(Default)]
struct Covered(Mutex<BTreeSet<(String, u16)>>);

impl Covered {
    /// Validate `body`, the response of `method template` with `status`, against the document.
    fn check(&self, doc: &Value, method: &str, template: &str, status: StatusCode, body: &Value) {
        let op = &doc["paths"][template][method];
        assert!(op.is_object(), "{method} {template} is not documented");
        let code = status.as_u16().to_string();
        let schema = response_schema(op, &code)
            .unwrap_or_else(|| panic!("{method} {template}: the {code} response is not documented"));
        let errors = errors_of(&validator(doc, &schema), body);
        assert!(
            errors.is_empty(),
            "{method} {template} {code}: the response does not match its schema:\n  {}\nresponse: {body}",
            errors.join("\n  ")
        );
        self.0
            .lock()
            .insert((op["operationId"].as_str().unwrap().to_owned(), status.as_u16()));
    }

    fn has(&self, id: &str, status: u16) -> bool {
        self.0.lock().contains(&(id.to_owned(), status))
    }
}

fn full(path: &str) -> String {
    if path.starts_with("/v0/") {
        path.to_owned()
    } else {
        format!("{V2}{path}")
    }
}

/// One API plus the document and the coverage record: every call is checked.
struct Api<'a> {
    app: &'a Router,
    key: &'a str,
    doc: &'a Value,
    c: &'a Covered,
}

impl Api<'_> {
    /// Call `path` (a concrete path with an optional query) of the operation documented as
    /// `template`, expect `status` and validate the body.
    async fn call(
        &self,
        method: Method,
        template: &str,
        path: &str,
        body: Option<&Value>,
        status: u16,
    ) -> Reply {
        let r = json_call(self.app, Some(self.key), method.clone(), &full(path), body).await;
        assert_eq!(r.status.as_u16(), status, "{method} {path}: {}", r.body);
        self.c.check(
            self.doc,
            &method.as_str().to_ascii_lowercase(),
            &full(template),
            r.status,
            &r.body,
        );
        r
    }

    async fn get(&self, template: &str, path: &str, status: u16) -> Reply {
        self.call(Method::GET, template, path, None, status).await
    }

    async fn post(&self, template: &str, path: &str, body: &Value, status: u16) -> Reply {
        self.call(Method::POST, template, path, Some(body), status).await
    }

    async fn delete(&self, template: &str, path: &str, status: u16) -> Reply {
        self.call(Method::DELETE, template, path, None, status).await
    }

    /// Poll `path` until `done` holds for its body (every poll is validated).
    async fn until(&self, template: &str, path: &str, what: &str, done: impl Fn(&Value) -> bool) -> Reply {
        for _ in 0..600 {
            let r = self.get(template, path, 200).await;
            if done(&r.body) {
                return r;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{path} never reached {what}");
    }
}

/// The path and query of a `next` link.
fn local(link: &Value) -> String {
    let url = url::Url::parse(link.as_str().unwrap_or_else(|| panic!("no next link in {link}")))
        .or_else(|_| url::Url::parse(&format!("http://localhost{}", link.as_str().unwrap())))
        .unwrap();
    let path = url.path().strip_prefix(V2).unwrap().to_owned();
    match url.query() {
        Some(q) => format!("{path}?{q}"),
        None => path,
    }
}

// ---- scrape, batch, crawl and map over a real worker ---------------------------------------------
/// The JSON frames a watcher sends on `path` until it closes the connection.
async fn watch_frames(app: &Router, key: &str, path: &str) -> Vec<Value> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = app.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let mut request = format!("ws://{addr}{V2}{path}").into_client_request().unwrap();
    request.headers_mut().insert(
        "Authorization",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_str(&format!("Bearer {key}")).unwrap(),
    );
    let (mut socket, _) =
        tokio::time::timeout(Duration::from_secs(10), tokio_tungstenite::connect_async(request))
            .await
            .expect("the handshake answers")
            .expect("the upgrade is accepted");
    let mut frames = Vec::new();
    while let Some(message) = tokio::time::timeout(Duration::from_secs(30), socket.next())
        .await
        .expect("a frame arrives in time")
    {
        match message.unwrap() {
            tokio_tungstenite::tungstenite::Message::Text(text) => {
                frames.push(serde_json::from_str(text.as_str()).unwrap());
            }
            tokio_tungstenite::tungstenite::Message::Close(_) => break,
            _ => {}
        }
    }
    server.abort();
    frames
}

async fn worker_flows(c: &Covered, doc: &Value) {
    let rig = scrape_rig::Rig::start(scrape_rig::RigConfig {
        llm: Some(generic_llm()),
        ..scrape_rig::RigConfig::default()
    })
    .await;
    let api = Api {
        app: &rig.env.app,
        key: &rig.env.key,
        doc,
        c,
    };
    let site = |p: &str| rig.url(p);

    // POST /scrape
    let r = api
        .post("/scrape", "/scrape", &json!({ "url": site("/") }), 200)
        .await;
    let scrape_id = r.body["data"]["metadata"]["scrapeId"]
        .as_str()
        .unwrap()
        .to_owned();
    api.post(
        "/scrape",
        "/scrape",
        &json!({
            "url": site("/"),
            "formats": [
                "markdown", "html", "rawHtml", "links", "images", "branding", "summary", "changeTracking",
                { "type": "attributes", "selectors": [{ "selector": "a", "attribute": "href" }] },
                { "type": "json", "prompt": "Extract the title" },
                { "type": "question", "question": "What is the answer?" },
                { "type": "highlights", "query": "the answer" },
            ],
            "onlyMainContent": false,
        }),
        200,
    )
    .await;
    let r = api
        .post(
            "/scrape",
            "/scrape",
            &json!({
                "url": site("/doc.pdf"),
                "parsers": [{ "type": "pdf", "pages": true, "blocks": true, "pageMarkers": true }],
            }),
            200,
        )
        .await;
    assert!(r.body["data"]["pages"].is_array(), "{}", r.body);
    api.post("/scrape", "/scrape", &json!({ "url": site("/status/404") }), 200)
        .await;
    // a scrape that fails answers the compat error envelope
    let r = api.post("/scrape", "/scrape", &json!({}), 400).await;
    assert_eq!(r.body["success"], false);

    // GET /scrape/{jobId}
    api.get("/scrape/{jobId}", &format!("/scrape/{scrape_id}"), 200)
        .await;
    api.get("/scrape/{jobId}", &format!("/scrape/{UNKNOWN_ID}"), 404)
        .await;

    // batch scrape
    let r = api
        .post(
            "/batch/scrape",
            "/batch/scrape",
            &json!({
                "urls": [site("/a"), site("/b"), site("/private/x"), site("/status/500"), "not a url"],
                "ignoreInvalidURLs": true,
                "formats": ["markdown", "links"],
            }),
            200,
        )
        .await;
    assert_eq!(r.body["invalidURLs"], json!(["not a url"]));
    let batch = r.body["id"].as_str().unwrap().to_owned();
    let path = format!("/batch/scrape/{batch}");
    let done = api
        .until("/batch/scrape/{id}", &path, "a terminal status", |b| {
            b["status"] != "scraping"
        })
        .await;
    let first_page = done.body["data"][0]["metadata"]["scrapeId"]
        .as_str()
        .unwrap()
        .to_owned();
    api.get("/scrape/{jobId}", &format!("/scrape/{first_page}"), 200)
        .await;
    let paged = api
        .get("/batch/scrape/{id}", &format!("{path}?limit=1"), 200)
        .await;
    assert!(paged.body["next"].is_string(), "{}", paged.body);
    api.get("/batch/scrape/{id}", &local(&paged.body["next"]), 200)
        .await;
    api.get("/batch/scrape/{id}", &format!("{path}?skip=1&limit=1"), 200)
        .await;
    api.get("/batch/scrape/{id}", &format!("/batch/scrape/{UNKNOWN_ID}"), 404)
        .await;
    api.get("/batch/scrape/{id}", &format!("{path}?skip=x"), 400)
        .await;
    let errors = api
        .get("/batch/scrape/{id}/errors", &format!("{path}/errors"), 200)
        .await;
    assert!(
        errors.body["errors"].is_array() && errors.body["robotsBlocked"].is_array(),
        "{}",
        errors.body
    );
    api.delete("/batch/scrape/{id}", &path, 409).await;
    let r = api
        .post(
            "/batch/scrape",
            "/batch/scrape",
            &json!({ "urls": [site("/slow")] }),
            200,
        )
        .await;
    let slow = r.body["id"].as_str().unwrap().to_owned();
    let r = api
        .delete("/batch/scrape/{id}", &format!("/batch/scrape/{slow}"), 200)
        .await;
    assert_eq!(r.body["status"], "cancelled");

    // crawl
    let r = api
        .post(
            "/crawl",
            "/crawl",
            &json!({ "url": site("/"), "limit": 4, "scrapeOptions": { "formats": ["markdown", "links"] } }),
            200,
        )
        .await;
    let crawl = r.body["id"].as_str().unwrap().to_owned();
    let path = format!("/crawl/{crawl}");
    api.get("/crawl/active", "/crawl/active", 200).await;
    let done = api
        .until("/crawl/{id}", &path, "a terminal status", |b| {
            b["status"] != "scraping"
        })
        .await;
    assert_eq!(done.body["status"], "completed", "{}", done.body);
    let paged = api.get("/crawl/{id}", &format!("{path}?limit=1"), 200).await;
    assert!(paged.body["next"].is_string(), "{}", paged.body);
    api.get("/crawl/{id}", &local(&paged.body["next"]), 200).await;
    api.get("/crawl/{id}", &format!("{path}?skip=1&limit=1"), 200)
        .await;
    api.get("/crawl/{id}", &format!("/crawl/{UNKNOWN_ID}"), 404).await;
    api.get("/crawl/{id}/errors", &format!("{path}/errors"), 200)
        .await;
    api.delete("/crawl/{id}", &path, 409).await;
    let r = api.post("/crawl", "/crawl", &json!({ "limit": 1 }), 400).await;
    assert_eq!(r.body["code"], "BAD_REQUEST");

    // the watchers: a plain GET of a `/ws` path answers the status, an upgrade streams frames
    api.get("/crawl/{id}/ws", &format!("/crawl/{crawl}/ws"), 200)
        .await;
    api.get("/batch/scrape/{id}/ws", &format!("/batch/scrape/{batch}/ws"), 200)
        .await;
    for (template, path) in [
        ("/crawl/{id}", format!("/crawl/{crawl}")),
        ("/crawl/{id}/ws", format!("/crawl/{crawl}/ws")),
        ("/batch/scrape/{id}", format!("/batch/scrape/{batch}")),
        ("/batch/scrape/{id}/ws", format!("/batch/scrape/{batch}/ws")),
    ] {
        let frames = watch_frames(&rig.env.app, &rig.env.key, &path).await;
        let kinds: Vec<&str> = frames.iter().map(|f| f["type"].as_str().unwrap()).collect();
        assert_eq!(kinds.first(), Some(&"catchup"), "{path}: {kinds:?}");
        assert_eq!(kinds.last(), Some(&"done"), "{path}: {kinds:?}");
        for f in &frames {
            c.check(doc, "get", &full(template), StatusCode::SWITCHING_PROTOCOLS, f);
        }
    }

    // map
    api.post("/map", "/map", &json!({ "url": site("/"), "limit": 10 }), 200)
        .await;
    api.post("/map", "/map", &json!({ "url": "ftp://x.example.test/" }), 400)
        .await;

    // the crawl options the configured LLM plans
    api.post(
        "/crawl/params-preview",
        "/crawl/params-preview",
        &json!({ "url": site("/"), "prompt": "crawl the docs" }),
        200,
    )
    .await;

    rig.stop().await;
}

/// A crawl nobody works on: queued, listed as active, cancelled.
async fn plain_flows(c: &Covered, doc: &Value) {
    let env = common::env();
    let api = Api {
        app: &env.app,
        key: &env.key,
        doc,
        c,
    };
    let r = api
        .post(
            "/crawl",
            "/crawl",
            &json!({ "url": "https://docs.example.test/", "limit": 2, "scrapeOptions": { "waitFor": 10 } }),
            200,
        )
        .await;
    let id = r.body["id"].as_str().unwrap().to_owned();
    let r = api.get("/crawl/{id}", &format!("/crawl/{id}"), 200).await;
    assert_eq!(r.body["status"], "scraping");
    let r = api.get("/crawl/active", "/crawl/active", 200).await;
    assert!(
        r.body["crawls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x["id"] == id.as_str()),
        "{}",
        r.body
    );
    api.get("/crawl/{id}/errors", &format!("/crawl/{id}/errors"), 200)
        .await;
    let r = api.delete("/crawl/{id}", &format!("/crawl/{id}"), 200).await;
    assert_eq!(r.body["status"], "cancelled");
    api.get("/crawl/{id}", &format!("/crawl/{id}"), 200).await;
}

// ---- search, team, support, extract, monitor, parse ----------------------------------------------

async fn intel_flows(c: &Covered, doc: &Value) {
    let t = intel(Some(generic_llm()));
    let api = Api {
        app: &t.app,
        key: &t.key,
        doc,
        c,
    };

    // health
    for (id, path) in [
        ("readiness", "/v0/health/readiness"),
        ("liveness", "/v0/health/liveness"),
    ] {
        let r = json_call(&t.app, None, Method::GET, path, None).await;
        assert_eq!(r.status, StatusCode::OK);
        c.check(doc, "get", path, r.status, &r.body);
        assert!(c.has(id, 200));
    }

    // search and feedback
    let r = api
        .post(
            "/search",
            "/search",
            &json!({ "query": "rust", "sources": ["web", "news", "images"] }),
            200,
        )
        .await;
    let job = r.body["id"].as_str().unwrap().to_owned();
    t.tools
        .set_markdown("https://rust-lang.org/", "# Rust\n\nA language.");
    api.post(
        "/search",
        "/search",
        &json!({ "query": "rust", "limit": 2, "scrapeOptions": { "formats": ["markdown", "links"] } }),
        200,
    )
    .await;
    api.post("/search", "/search", &json!({ "limit": 0 }), 422).await;
    let feedback = json!({ "rating": "good", "valuableSources": [{ "url": "https://rust-lang.org/" }] });
    api.post(
        "/search/{jobId}/feedback",
        &format!("/search/{job}/feedback"),
        &feedback,
        200,
    )
    .await;
    let r = api
        .post(
            "/search/{jobId}/feedback",
            &format!("/search/{job}/feedback"),
            &feedback,
            200,
        )
        .await;
    assert_eq!(r.body["alreadySubmitted"], true);
    api.post(
        "/search/{jobId}/feedback",
        &format!("/search/{UNKNOWN_ID}/feedback"),
        &feedback,
        404,
    )
    .await;
    api.post(
        "/feedback",
        "/feedback",
        &json!({ "endpoint": "search", "jobId": job, "rating": "bad", "querySuggestions": "rust lang" }),
        200,
    )
    .await;
    api.post("/feedback", "/feedback", &json!({ "endpoint": "nope" }), 422)
        .await;

    // the category indexes
    t.tools.set_markdown(
        "https://arxiv.org/abs/2401.00001",
        "Attention is all you need.\n\nAn attention mechanism relates positions of a sequence in a long enough paragraph.",
    );
    t.tools.set_markdown(
        "https://arxiv.org/pdf/2401.00001",
        "Attention is all you need.\n\nAn attention mechanism relates positions of a sequence in a long enough paragraph.",
    );
    api.get(
        "/search/developer",
        "/search/developer?query=rust&types=doc,issue,readme",
        200,
    )
    .await;
    api.post(
        "/search/developer",
        "/search/developer",
        &json!({ "query": "rust", "repos": ["rust-lang/rust"], "types": ["issue", "pull_request"] }),
        200,
    )
    .await;
    api.get("/search/gov", "/search/gov?query=tax&domain=irs.gov", 200)
        .await;
    api.post("/search/gov", "/search/gov", &json!({ "query": "tax" }), 200)
        .await;
    api.get(
        "/search/research/papers",
        "/search/research/papers?query=attention&k=2",
        200,
    )
    .await;
    api.get(
        "/search/research/papers/{paperId}",
        "/search/research/papers/arxiv:2401.00001",
        200,
    )
    .await;
    api.get(
        "/search/research/papers/{paperId}",
        "/search/research/papers/arxiv:2401.00001?query=attention&k=2",
        200,
    )
    .await;
    api.get(
        "/search/research/papers/{paperId}",
        "/search/research/papers/nope:1",
        404,
    )
    .await;
    api.get(
        "/search/research/papers/{paperId}/similar",
        "/search/research/papers/arxiv:2401.00001/similar?intent=methods&mode=references&k=2",
        200,
    )
    .await;

    // team
    api.get("/team/credit-usage", "/team/credit-usage", 200).await;
    api.get(
        "/team/credit-usage/historical",
        "/team/credit-usage/historical",
        200,
    )
    .await;
    api.get("/team/token-usage", "/team/token-usage", 200).await;
    api.get(
        "/team/token-usage/historical",
        "/team/token-usage/historical",
        200,
    )
    .await;
    api.get("/team/queue-status", "/team/queue-status", 200).await;
    let r = api.get("/team/activity", "/team/activity?limit=1", 200).await;
    assert!(r.body["cursor"].is_string(), "{}", r.body);
    api.get(
        "/team/activity",
        &format!(
            "/team/activity?limit=1&cursor={}",
            r.body["cursor"].as_str().unwrap()
        ),
        200,
    )
    .await;
    api.get("/team/activity", "/team/activity?endpoint=search", 200)
        .await;
    api.get("/team/activity", "/team/activity?limit=0", 422).await;

    // support
    api.post(
        "/support/ask",
        "/support/ask",
        &json!({ "question": "Why did my scrape fail?" }),
        200,
    )
    .await;
    api.post(
        "/support/docs-search",
        "/support/docs-search",
        &json!({ "question": "How do I crawl?" }),
        200,
    )
    .await;
    api.post("/support/docs-search", "/support/docs-search", &json!({}), 422)
        .await;

    // extract
    t.tools
        .set_markdown("https://example.com/", "Example Site is a blog.");
    let r = api
        .post(
            "/extract",
            "/extract",
            &json!({
                "urls": ["https://example.com/", "not a url"],
                "prompt": "Extract the title",
                "schema": { "type": "object", "properties": { "title": { "type": "string" } }, "required": ["title"] },
                "showSources": true,
            }),
            200,
        )
        .await;
    let id = r.body["id"].as_str().unwrap().to_owned();
    let done = api
        .until(
            "/extract/{id}",
            &format!("/extract/{id}"),
            "a terminal status",
            |b| b["status"] != "processing",
        )
        .await;
    assert_eq!(done.body["status"], "completed", "{}", done.body);
    api.get("/extract/{id}", &format!("/extract/{UNKNOWN_ID}"), 404)
        .await;

    // monitors
    t.tools
        .set_markdown("https://blog.example.test/", "The first version of the page.");
    let r = api
        .post(
            "/monitor",
            "/monitor",
            &json!({
                "name": "Blog",
                "schedule": { "text": "every 30 minutes" },
                "targets": [{ "type": "scrape", "urls": ["https://blog.example.test/"] }],
                "webhook": "https://hooks.example.test/monitor",
                "notification": { "email": { "enabled": true, "recipients": ["ops@example.test"] } },
            }),
            200,
        )
        .await;
    let monitor = r.body["data"]["id"].as_str().unwrap().to_owned();
    api.get("/monitor", "/monitor?limit=5&status=active", 200).await;
    api.get("/monitor/{monitorId}", &format!("/monitor/{monitor}"), 200)
        .await;
    let r = api
        .call(
            Method::PATCH,
            "/monitor/{monitorId}",
            &format!("/monitor/{monitor}"),
            Some(&json!({ "name": "Renamed", "status": "paused" })),
            200,
        )
        .await;
    assert_eq!(r.body["data"]["status"], "paused");
    api.call(
        Method::PATCH,
        "/monitor/{monitorId}",
        &format!("/monitor/{monitor}"),
        Some(&json!({ "status": "active" })),
        200,
    )
    .await;
    let r = api
        .post(
            "/monitor/{monitorId}/run",
            &format!("/monitor/{monitor}/run"),
            &json!({}),
            200,
        )
        .await;
    let check = r.body["id"].as_str().unwrap().to_owned();
    let detail = format!("/monitor/{monitor}/checks/{check}?limit=100");
    let done = api
        .until(
            "/monitor/{monitorId}/checks/{checkId}",
            &detail,
            "a finished check",
            |b| b["data"]["status"] != "running",
        )
        .await;
    assert_eq!(done.body["data"]["status"], "completed", "{}", done.body);
    // a second run sees the same page again
    t.tools
        .set_markdown("https://blog.example.test/", "The second version of the page.");
    for _ in 0..200 {
        if !t.state.jobs.is_running(check.parse().unwrap()) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let r = api
        .post(
            "/monitor/{monitorId}/run",
            &format!("/monitor/{monitor}/run"),
            &json!({}),
            200,
        )
        .await;
    let check2 = r.body["id"].as_str().unwrap().to_owned();
    let detail2 = format!("/monitor/{monitor}/checks/{check2}?limit=100");
    api.until(
        "/monitor/{monitorId}/checks/{checkId}",
        &detail2,
        "a finished check",
        |b| b["data"]["status"] != "running",
    )
    .await;
    api.get(
        "/monitor/{monitorId}/checks",
        &format!("/monitor/{monitor}/checks"),
        200,
    )
    .await;
    api.get(
        "/monitor/{monitorId}/checks",
        &format!("/monitor/{monitor}/checks?status=completed&limit=1"),
        200,
    )
    .await;
    api.get(
        "/monitor/{monitorId}/checks/{checkId}",
        &format!("/monitor/{monitor}/checks/{check2}?limit=1&status=changed"),
        200,
    )
    .await;
    api.get("/monitor/{monitorId}", &format!("/monitor/{monitor}"), 200)
        .await;
    api.get("/monitor/{monitorId}", &format!("/monitor/{UNKNOWN_ID}"), 404)
        .await;
    api.post("/monitor", "/monitor", &json!({ "name": "x" }), 422)
        .await;
    api.delete("/monitor/{monitorId}", &format!("/monitor/{monitor}"), 200)
        .await;

    // parse
    let ok = |label: &str, r: Reply| {
        assert_eq!(r.status, StatusCode::OK, "{label}: {}", r.body);
        c.check(doc, "post", &full("/parse"), r.status, &r.body);
        r
    };
    ok(
        "html",
        upload(
            &t.app,
            &t.key,
            Some(&json!({ "formats": ["markdown", "html", "rawHtml", "text", "links", "images"] })),
        )
        .await,
    );
    ok(
        "llm formats",
        upload(
            &t.app,
            &t.key,
            Some(&json!({
                "formats": ["summary", { "type": "question", "question": "What is this?" },
                            { "type": "highlights", "query": "hello" },
                            { "type": "json", "prompt": "Extract the title" }],
                "redactPII": true,
                "checkPromptInjection": true,
                "zeroDataRetention": true,
                "proxy": "basic",
            })),
        )
        .await,
    );
    let pdf = scrape_rig::pdf(&["Alpha page one", "Beta page two"]);
    let pdf_upload = |options: Value| {
        let (content_type, body) = multipart(&[
            ("file", Some("two.pdf"), pdf.as_slice()),
            ("options", None, options.to_string().as_bytes()),
        ]);
        let app = &t.app;
        let key = &t.key;
        async move {
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
    };
    let r = ok(
        "pdf",
        pdf_upload(
            json!({ "parsers": [{ "type": "pdf", "pages": true, "blocks": true, "pageMarkers": true }] }),
        )
        .await,
    );
    assert!(
        r.body["data"]["pages"].is_array() && r.body["data"]["blocks"].is_array(),
        "{}",
        r.body
    );
    let r = ok("raw pdf", pdf_upload(json!({ "parsers": [] })).await);
    assert!(r.body["data"]["rawBase64"].is_string(), "{}", r.body);
    api.get("/parse/formats", "/parse/formats", 200).await;
    let r = upload(&t.app, &t.key, Some(&json!({ "formats": ["nope"] }))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    c.check(doc, "post", &full("/parse"), r.status, &r.body);
}

// ---- agent ---------------------------------------------------------------------------------------

fn act(action: &str, args: Value) -> Result<Value, LlmError> {
    Ok(json!({ "reasoning": format!("step {action}"), "action": action, "args": args }))
}

/// An LLM that scripts one scrape and then waits for ever (a run to cancel).
struct GateLlm {
    calls: AtomicUsize,
    entered: Arc<Notify>,
}

#[async_trait]
impl LlmExtractor for GateLlm {
    async fn complete(&self, _: &str, _: &str, _: Option<&Value>) -> Result<Completion<Value>, LlmError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            return Ok(Completion {
                value: act("scrape", json!({ "url": ABOUT }))?,
                usage: TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 5,
                },
            });
        }
        self.entered.notify_one();
        std::future::pending::<()>().await;
        Err(LlmError::NotConfigured)
    }
}

const ABOUT: &str = "https://acme.example.test/about";

async fn agent_flows(c: &Covered, doc: &Value) {
    let script: Arc<dyn LlmExtractor> = Arc::new(MockLlm::scripted(vec![
        act("search", json!({ "query": "acme founders", "limit": 3 })),
        act("scrape", json!({ "url": ABOUT })),
        act("extract", json!({})),
        Ok(json!({ "founders": [{ "name": "Ada" }] })),
        act("finish", json!({ "message": "done" })),
    ]));
    let t = intel(Some(script));
    t.tools
        .set_markdown(ABOUT, "Acme was founded by Ada Lovelace in 1843.");
    let api = Api {
        app: &t.app,
        key: &t.key,
        doc,
        c,
    };
    let r = api
        .post(
            "/agent",
            "/agent",
            &json!({
                "prompt": "Find the founders of Acme",
                "schema": { "type": "object", "properties": { "founders": { "type": "array" } }, "required": ["founders"] },
                "webhook": { "url": "https://hooks.example.test/agent" },
            }),
            200,
        )
        .await;
    let id = r.body["id"].as_str().unwrap().to_owned();
    let done = api
        .until(
            "/agent/{jobId}",
            &format!("/agent/{id}"),
            "a terminal status",
            |b| b["status"] != "processing",
        )
        .await;
    assert_eq!(done.body["status"], "completed", "{}", done.body);
    let uuid: uuid::Uuid = id.parse().unwrap();
    for _ in 0..1000 {
        if !t.state.jobs.is_running(uuid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    api.get("/agent", "/agent", 200).await;
    api.get("/agent", "/agent?limit=1&skip=0", 200).await;
    api.get("/agent", "/agent?before=x", 400).await;
    let trace = api
        .get("/agent/{jobId}/trace", &format!("/agent/{id}/trace"), 200)
        .await;
    let paged = api
        .get(
            "/agent/{jobId}/trace",
            &format!("/agent/{id}/trace?limit=2&liveView=true"),
            200,
        )
        .await;
    assert!(paged.body["nextAfter"].is_u64(), "{}", paged.body);
    api.get(
        "/agent/{jobId}/trace",
        &format!("/agent/{id}/trace?after=2&limit=2"),
        200,
    )
    .await;
    let snapshot = trace.body["events"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|e| e["artifact"]["snapshotId"].as_str())
        .expect("an artifact event")
        .to_owned();
    api.get(
        "/agent/{jobId}/snapshots/{snapshotId}",
        &format!("/agent/{id}/snapshots/{snapshot}"),
        200,
    )
    .await;
    api.get(
        "/agent/{jobId}/snapshots/{snapshotId}",
        &format!("/agent/{id}/snapshots/xyz"),
        400,
    )
    .await;
    api.get(
        "/agent/{jobId}/snapshots/{snapshotId}",
        &format!("/agent/{id}/snapshots/{UNKNOWN_ID}"),
        404,
    )
    .await;
    api.delete("/agent/{jobId}", &format!("/agent/{id}"), 409).await;
    api.get("/agent/{jobId}", &format!("/agent/{UNKNOWN_ID}"), 404)
        .await;
    api.post("/agent", "/agent", &json!({}), 422).await;

    // a run that is cancelled while it works
    let entered = Arc::new(Notify::new());
    let gate: Arc<dyn LlmExtractor> = Arc::new(GateLlm {
        calls: AtomicUsize::new(0),
        entered: entered.clone(),
    });
    let t = intel(Some(gate));
    t.tools
        .set_markdown(ABOUT, "Acme was founded by Ada Lovelace in 1843.");
    let api = Api {
        app: &t.app,
        key: &t.key,
        doc,
        c,
    };
    let r = api.post("/agent", "/agent", &json!({ "prompt": "p" }), 200).await;
    let id = r.body["id"].as_str().unwrap().to_owned();
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    let r = api.get("/agent/{jobId}", &format!("/agent/{id}"), 200).await;
    assert_eq!(r.body["status"], "processing");
    api.delete("/agent/{jobId}", &format!("/agent/{id}"), 200).await;
    let r = api.get("/agent/{jobId}", &format!("/agent/{id}"), 200).await;
    assert_eq!(r.body["status"], "cancelled");
}

// ---- errors of every operation -------------------------------------------------------------------

/// Every authenticated operation answers `401` without a key and `403` with a key that lacks its
/// scope, and a body that is not an object is refused with a documented status; all in the
/// documented error envelope.
async fn error_flows(c: &Covered, doc: &Value) {
    let env = common::env();
    let weak = env.key_for("acme-weak", &[Scope::MetricsRead]).await;
    for (method, path, op) in facade_operations(doc) {
        if op["security"] == json!([]) {
            continue;
        }
        let m = Method::from_bytes(method.to_ascii_uppercase().as_bytes()).unwrap();
        // the required query parameters of the operation, with any value
        let required: Vec<String> = op["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| p["in"] == "query" && p["required"] == true)
            .map(|p| format!("{}=x", p["name"].as_str().unwrap()))
            .collect();
        let mut uri = fill(&path);
        if !required.is_empty() {
            uri = format!("{uri}?{}", required.join("&"));
        }
        let has_body = matches!(m, Method::POST | Method::PATCH | Method::PUT);
        // a body with the required members: some handlers read the body before the scope check
        let mut required = serde_json::Map::new();
        if let Some((_, schema)) = request_schema(op) {
            for name in resolve(doc, &schema)["required"].as_array().into_iter().flatten() {
                required.insert(name.as_str().unwrap().to_owned(), json!("x"));
            }
        }
        let empty = Value::Object(required);
        let body = has_body.then_some(&empty);
        let id = op["operationId"].as_str().unwrap();

        let r = json_call(&env.app, None, m.clone(), &uri, body).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{id}: {}", r.body);
        c.check(doc, &method, &path, r.status, &r.body);

        let r = json_call(&env.app, Some(&weak), m.clone(), &uri, body).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{id}: {}", r.body);
        assert_eq!(r.body["code"], "scope_missing");
        c.check(doc, &method, &path, r.status, &r.body);

        if request_schema(op).is_some_and(|(media, _)| media == "application/json") {
            let r = json_call(&env.app, Some(&env.key), m.clone(), &uri, Some(&json!([]))).await;
            assert!(
                matches!(r.status.as_u16(), 400 | 422 | 503),
                "{id}: an array body answered {} {}",
                r.status,
                r.body
            );
            c.check(doc, &method, &path, r.status, &r.body);
            // a body that is not JSON at all
            let r = send(
                &env.app,
                Some(&env.key),
                &m,
                &uri,
                Some("application/json"),
                &[],
                b"{not json".to_vec(),
            )
            .await;
            assert_eq!(r.status, StatusCode::BAD_REQUEST, "{id}: {}", r.body);
            c.check(doc, &method, &path, r.status, &r.body);
        }
    }

    // the rate limit
    let limited = common::env_with(
        crawlx_api::ApiConfig {
            rate_limit_per_minute: 1,
            ..crawlx_api::ApiConfig::default()
        },
        crawlx_api::Settings::default(),
        Arc::new(crawlx_core::SystemClock),
    );
    let mut seen_429 = false;
    for _ in 0..5 {
        let r = json_call(
            &limited.app,
            Some(&limited.key),
            Method::GET,
            &format!("{V2}/team/queue-status"),
            None,
        )
        .await;
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            c.check(doc, "get", &full("/team/queue-status"), r.status, &r.body);
            assert!(r.headers.contains_key("retry-after"));
            seen_429 = true;
            break;
        }
    }
    assert!(seen_429, "the rate limit never answered 429");
}

#[tokio::test]
async fn real_responses_validate_against_the_generated_schemas() {
    let doc = doc();
    let c = Covered::default();
    tokio::join!(
        worker_flows(&c, &doc),
        plain_flows(&c, &doc),
        intel_flows(&c, &doc),
        agent_flows(&c, &doc),
        error_flows(&c, &doc),
    );
    let uncovered: Vec<String> = facade_operations(&doc)
        .into_iter()
        .filter_map(|(_, path, op)| {
            let id = op["operationId"].as_str().unwrap();
            (!c.has(id, 200)).then(|| format!("{id} ({path})"))
        })
        .collect();
    assert!(
        uncovered.is_empty(),
        "no real 200 response was validated for: {uncovered:?}"
    );
    let total = facade_operations(&doc).len();
    eprintln!(
        "openapi: real responses validated for {total}/{total} operations ({} (operation, status) pairs)",
        c.0.lock().len()
    );
}

#[tokio::test]
async fn native_word_chunks_reach_actual_facade_response_and_canonical_source() {
    use crawlx_core::repo::ArtifactStore as _;
    let rig = scrape_rig::Rig::start(scrape_rig::RigConfig {
        site_routes: Some(axum::Router::new().route("/chunk-article", axum::routing::get(|| async {
            axum::response::Html("<article><h1>Native chunk fixture</h1><pre>α\tbeta\n   中🙂 delta\n tail</pre><p>The local article retains real canonical text and never invents copied chunk strings or HTML offsets.</p></article>")
        }))),
        ..Default::default()
    }).await;
    let document = doc();
    let covered = Covered::default();
    let api = Api {
        app: &rig.env.app,
        key: &rig.env.key,
        doc: &document,
        c: &covered,
    };
    let request = json!({
        "url": rig.url("/chunk-article"),
        "formats": ["markdown", "html"],
        "onlyMainContent": false,
        "contentPolicy": {
            "chunks": {"strategy": {"kind": "sliding", "window": 4, "step": 3}},
        },
    });
    let schema = request_schema(&document["paths"][format!("{V2}/scrape")]["post"])
        .unwrap()
        .1;
    assert!(errors_of(&validator(&document, &schema), &request).is_empty());
    let response = api.post("/scrape", "/scrape", &request, 200).await;
    let meta = &response.body["data"]["metadata"];
    let chunks: crawlx_core::extraction::WordChunkEnvelopeV1 =
        serde_json::from_value(meta["article"]["chunks"].clone()).unwrap();
    let reference: crawlx_core::scrape::BlobRef =
        serde_json::from_value(meta["articleTextRef"].clone()).unwrap();
    let text = String::from_utf8(rig.env.artifacts.get(&reference.artifact).await.unwrap()).unwrap();
    chunks.validate(&text, &chunks.policy).unwrap();
    assert!(text.contains("α\tbeta\n   中🙂 delta"));
    assert!(chunks.ranges.len() > 1);
    assert!(chunks
        .ranges
        .iter()
        .all(|range| text.get(range.start..range.end).is_some()));
    assert_eq!(meta["article"]["chunks"].get("strings"), None);
}
