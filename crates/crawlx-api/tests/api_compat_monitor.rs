#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! compat v2 `/monitor` endpoints: lifecycle, validation, change detection, JSON-mode change
//! tracking, goal judging, search targets, webhooks, the ticker and retention. Everything runs
//! in memory on a manual clock with mocked scrape, search, LLM and webhook transport.

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::intel::monitor::{scheduler, spawn_monitor_loop_every};
use crawlx_api::intel::search::{MockSearch, SearchResults, WebHit};
use crawlx_api::intel::tools::{MapLink, MockPageTools, ToolError};
use crawlx_api::intel::webhook::{compat_signature, JobWebhookSink};
use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookTransport};
use crawlx_api::{ApiConfig, AppState, MemoryApiStore, Repos, Scope};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_model::llm::{LlmError, MockLlm};
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::{CheckRecord, CheckState, DeliveryBuffer, MemoryArtifactStore, MemoryStore};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;
use uuid::Uuid;

const BASE: &str = "/compat/v2";
const SECRET: &str = "whsec-monitor-test";

fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
    s.parse().unwrap()
}

// ---- harness ----------------------------------------------------------------------------------

/// Records every webhook POST and answers 200.
#[derive(Default)]
struct Recorder {
    posts: Mutex<Vec<Posted>>,
}

#[derive(Clone, Debug)]
struct Posted {
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Posted {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[async_trait]
impl WebhookTransport for Recorder {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        self.posts.lock().push(Posted {
            url: req.url.to_string(),
            headers: req.headers,
            body: req.body,
        });
        Ok(200)
    }
}

#[derive(Default)]
struct Setup {
    llm: Option<Arc<MockLlm>>,
    search: Option<Arc<MockSearch>>,
    shutdown: Option<CancellationToken>,
}

struct Env {
    app: Router,
    state: AppState,
    api: Arc<MemoryApiStore>,
    key: String,
    tenant: TenantId,
    tools: Arc<MockPageTools>,
    clock: ManualClock,
    hooks: Arc<Recorder>,
}

fn env() -> Env {
    env_with(Setup::default())
}

fn env_with(setup: Setup) -> Env {
    let clock = ManualClock::new(utc("2025-06-01T12:00:00Z"));
    let shared: Arc<dyn Clock> = Arc::new(clock.clone());
    let store = Arc::new(MemoryStore::new());
    let zdr = Arc::new(DeliveryBuffer::with_defaults(shared.clone()));
    let artifacts = Arc::new(
        MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock)).with_zdr_buffer(zdr.clone()),
    );
    let (repos, api) = Repos::memory_with_api(store, artifacts);
    let tools = Arc::new(MockPageTools::new());
    let hooks = Arc::new(Recorder::default());
    let config = ApiConfig {
        rate_limit_per_minute: 0,
        ..ApiConfig::default()
    };
    let mut builder = AppState::builder(repos, AdmissionPolicy::new(shared.clone()), config)
        .clock(shared)
        .zdr_buffer(zdr)
        .job_webhooks(JobWebhookSink::new(hooks.clone(), SECRET));
    builder = builder.page_tools(tools.clone());
    if let Some(llm) = setup.llm {
        builder = builder.llm(llm);
    }
    if let Some(search) = setup.search {
        builder = builder.search_provider(search);
    }
    if let Some(token) = setup.shutdown {
        builder = builder.shutdown(token);
    }
    let state = builder.build();
    let app = crawlx_api::router(state.clone());
    let tenant = tenant_id_for("acme");
    let key = generate_key();
    let rec = key_record(&key, tenant, Scope::all_set()).unwrap();
    futures::executor::block_on(async {
        crawlx_api::ApiStore::key_insert(api.as_ref(), &rec, "acme")
            .await
            .unwrap()
    });
    Env {
        app,
        state,
        api,
        key,
        tenant,
        tools,
        clock,
        hooks,
    }
}

impl Env {
    async fn send_as(
        &self,
        key: &str,
        method: Method,
        uri: &str,
        body: Option<&Value>,
    ) -> (StatusCode, Value) {
        let b = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {key}"));
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let (parts, body) = resp.into_parts();
        let bytes = axum::body::to_bytes(body, 64 * 1024 * 1024).await.unwrap();
        let v = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (parts.status, v)
    }

    async fn send(&self, method: Method, uri: &str, body: Option<&Value>) -> (StatusCode, Value) {
        self.send_as(&self.key, method, uri, body).await
    }

    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        self.send(Method::GET, uri, None).await
    }

    async fn post(&self, uri: &str, body: &Value) -> (StatusCode, Value) {
        self.send(Method::POST, uri, Some(body)).await
    }

    async fn patch(&self, uri: &str, body: &Value) -> (StatusCode, Value) {
        self.send(Method::PATCH, uri, Some(body)).await
    }

    async fn delete(&self, uri: &str) -> (StatusCode, Value) {
        self.send(Method::DELETE, uri, None).await
    }

    async fn key_for(&self, tenant: &str, scopes: &[Scope]) -> String {
        let key = generate_key();
        let set: BTreeSet<Scope> = scopes.iter().copied().collect();
        let rec = key_record(&key, tenant_id_for(tenant), set).unwrap();
        crawlx_api::ApiStore::key_insert(self.api.as_ref(), &rec, tenant)
            .await
            .unwrap();
        key
    }

    /// Create a monitor and return its `data` object.
    async fn create(&self, body: &Value) -> Value {
        let (s, v) = self.post(&format!("{BASE}/monitor"), body).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        assert_eq!(v["success"], true);
        v["data"].clone()
    }

    /// Run a check now and wait for it to leave `running`; returns the check with its first 100 pages.
    async fn run_check(&self, monitor: &str) -> Value {
        let (s, v) = self
            .post(&format!("{BASE}/monitor/{monitor}/run"), &json!({}))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let id = v["id"].as_str().unwrap().to_owned();
        assert_eq!(v["data"]["id"], id.as_str());
        assert_eq!(v["data"]["trigger"], "manual");
        assert_eq!(v["data"]["status"], "running");
        for _ in 0..500 {
            let (s, v) = self
                .get(&format!("{BASE}/monitor/{monitor}/checks/{id}?limit=100"))
                .await;
            assert_eq!(s, StatusCode::OK, "{v}");
            if v["data"]["status"] != "running" {
                // the background task still books usage and the monitor's last run
                let check: Uuid = id.parse().unwrap();
                until("the check task to end", || !self.state.jobs.is_running(check)).await;
                return v["data"].clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("check {id} did not finish");
    }

    fn webhook_posts(&self) -> Vec<Posted> {
        self.hooks.posts.lock().clone()
    }
}

async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..500 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

fn scrape_monitor(urls: &[&str]) -> Value {
    json!({
        "name": "Blog monitor",
        "schedule": { "text": "every 30 minutes", "timezone": "UTC" },
        "targets": [{ "type": "scrape", "urls": urls }],
    })
}

fn page<'a>(check: &'a Value, url: &str) -> &'a Value {
    check["pages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["url"] == url)
        .unwrap_or_else(|| panic!("no page {url} in {check}"))
}

fn summary(check: &Value) -> (u64, u64, u64, u64, u64, u64) {
    let s = &check["summary"];
    let n = |k: &str| s[k].as_u64().unwrap();
    (
        n("totalPages"),
        n("same"),
        n("new"),
        n("changed"),
        n("removed"),
        n("error"),
    )
}

fn detail_paths(v: &Value) -> Vec<(String, String)> {
    v["details"]
        .as_array()
        .unwrap_or_else(|| panic!("no details in {v}"))
        .iter()
        .map(|d| {
            (
                d["path"].as_str().unwrap().to_owned(),
                d["code"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// ---- lifecycle --------------------------------------------------------------------------------

#[tokio::test]
async fn monitor_lifecycle_create_list_get_patch_pause_resume_delete() {
    let e = env();
    let data = e.create(&scrape_monitor(&["https://blog.test/"])).await;
    let id = data["id"].as_str().unwrap().to_owned();
    assert_eq!(data["name"], "Blog monitor");
    assert_eq!(data["status"], "active");
    assert_eq!(
        data["schedule"],
        json!({ "cron": "*/30 * * * *", "timezone": "UTC" })
    );
    assert_eq!(data["nextRunAt"], "2025-06-01T12:30:00.000Z");
    assert_eq!(data["lastRunAt"], Value::Null);
    assert_eq!(data["currentCheckId"], Value::Null);
    assert_eq!(data["lastCheckSummary"], Value::Null);
    assert_eq!(data["retentionDays"], 30);
    assert_eq!(data["goal"], Value::Null);
    assert_eq!(data["judgeEnabled"], false);
    assert_eq!(data["webhook"], Value::Null);
    assert_eq!(data["notification"], json!({}));
    assert_eq!(
        data["estimatedCreditsPerMonth"], 1_440,
        "one page, 48 runs a day, 30 days"
    );
    assert_eq!(data["createdAt"], "2025-06-01T12:00:00.000Z");
    assert_eq!(data["targets"][0]["type"], "scrape");
    assert_eq!(data["targets"][0]["urls"], json!(["https://blog.test/"]));
    Uuid::parse_str(data["targets"][0]["id"].as_str().unwrap()).unwrap();

    // get
    let (s, v) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["data"], data);

    // rename and retention
    let (s, v) = e
        .patch(
            &format!("{BASE}/monitor/{id}"),
            &json!({ "name": "Renamed", "retentionDays": 7 }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"]["name"], "Renamed");
    assert_eq!(v["data"]["retentionDays"], 7);
    assert_eq!(
        v["data"]["nextRunAt"], "2025-06-01T12:30:00.000Z",
        "unrelated patches keep the schedule"
    );

    // pause: nextRunAt cleared, list filters by status
    let (s, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "status": "paused" }))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"]["status"], "paused");
    assert_eq!(v["data"]["nextRunAt"], Value::Null);
    let (_, v) = e.get(&format!("{BASE}/monitor?status=paused")).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 1);
    let (_, v) = e.get(&format!("{BASE}/monitor?status=active")).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 0);

    // resume at a later instant: the next occurrence is computed from now
    e.clock.advance_ms(10 * 60_000);
    let (_, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "status": "active" }))
        .await;
    assert_eq!(v["data"]["status"], "active");
    assert_eq!(v["data"]["nextRunAt"], "2025-06-01T12:30:00.000Z");

    // new schedule in another zone
    let (s, v) = e
        .patch(
            &format!("{BASE}/monitor/{id}"),
            &json!({ "schedule": { "cron": "0 9 * * *", "timezone": "Asia/Kolkata" } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["data"]["schedule"],
        json!({ "cron": "0 9 * * *", "timezone": "Asia/Kolkata" })
    );
    assert_eq!(v["data"]["nextRunAt"], "2025-06-02T03:30:00.000Z");

    // goal switches judging on; judgeEnabled: false switches it off; judging without a goal is refused
    let (_, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "goal": "price drops" }))
        .await;
    assert_eq!(
        (v["data"]["goal"].as_str(), v["data"]["judgeEnabled"].as_bool()),
        (Some("price drops"), Some(true))
    );
    let (_, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "judgeEnabled": false }))
        .await;
    assert_eq!(
        (v["data"]["goal"].as_str(), v["data"]["judgeEnabled"].as_bool()),
        (Some("price drops"), Some(false))
    );
    let (s, v) = e
        .patch(
            &format!("{BASE}/monitor/{id}"),
            &json!({ "goal": null, "judgeEnabled": true }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        detail_paths(&v),
        vec![("/judgeEnabled".to_owned(), "invalid".to_owned())]
    );
    let (_, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "goal": null }))
        .await;
    assert_eq!(v["data"]["goal"], Value::Null);
    assert_eq!(v["data"]["judgeEnabled"], false);

    // an empty patch is a validation error
    let (s, v) = e.patch(&format!("{BASE}/monitor/{id}"), &json!({})).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(detail_paths(&v), vec![(String::new(), "required".to_owned())]);
    // so is an invalid status
    let (s, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "status": "deleted" }))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        detail_paths(&v),
        vec![("/status".to_owned(), "invalid".to_owned())]
    );

    // delete
    let (s, v) = e.delete(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!((s, &v["success"]), (StatusCode::OK, &json!(true)));
    for (s, v) in [
        e.get(&format!("{BASE}/monitor/{id}")).await,
        e.delete(&format!("{BASE}/monitor/{id}")).await,
        e.patch(&format!("{BASE}/monitor/{id}"), &json!({ "name": "x" }))
            .await,
        e.post(&format!("{BASE}/monitor/{id}/run"), &json!({})).await,
        e.get(&format!("{BASE}/monitor/{id}/checks")).await,
    ] {
        assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
        assert_eq!(v["success"], false);
        assert_eq!(v["code"], "not_found");
    }
    let (_, v) = e.get(&format!("{BASE}/monitor")).await;
    assert_eq!(v["data"], json!([]));
}

#[tokio::test]
async fn list_pages_newest_first_and_validates_query() {
    let e = env();
    let mut ids = Vec::new();
    for n in 0..3 {
        e.clock.advance_ms(1_000);
        let mut body = scrape_monitor(&["https://blog.test/"]);
        body["name"] = json!(format!("m{n}"));
        ids.push(e.create(&body).await["id"].as_str().unwrap().to_owned());
    }
    let names = |v: &Value| -> Vec<String> {
        v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let (_, v) = e.get(&format!("{BASE}/monitor")).await;
    assert_eq!(names(&v), ["m2", "m1", "m0"]);
    let (_, v) = e.get(&format!("{BASE}/monitor?limit=2")).await;
    assert_eq!(names(&v), ["m2", "m1"]);
    let (_, v) = e.get(&format!("{BASE}/monitor?limit=2&offset=2")).await;
    assert_eq!(names(&v), ["m0"]);
    // pause the middle one: the status filter pages over the filtered rows
    e.patch(
        &format!("{BASE}/monitor/{}", ids[1]),
        &json!({ "status": "paused" }),
    )
    .await;
    let (_, v) = e
        .get(&format!("{BASE}/monitor?status=active&limit=1&offset=1"))
        .await;
    assert_eq!(names(&v), ["m0"]);
    for bad in ["limit=0", "limit=101", "limit=x", "offset=-1", "status=deleted"] {
        let (s, v) = e.get(&format!("{BASE}/monitor?{bad}")).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}: {v}");
        assert_eq!(v["code"], "validation_failed");
    }
}

#[tokio::test]
async fn scopes_and_tenants_are_enforced() {
    let e = env();
    let data = e.create(&scrape_monitor(&["https://blog.test/"])).await;
    let id = data["id"].as_str().unwrap();
    let reader = e.key_for("acme", &[Scope::CrawlsRead]).await;
    let (s, _) = e
        .send_as(&reader, Method::GET, &format!("{BASE}/monitor/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = e
        .send_as(&reader, Method::GET, &format!("{BASE}/monitor/{id}/checks"), None)
        .await;
    assert_eq!(s, StatusCode::OK);
    for (method, uri, body) in [
        (
            Method::POST,
            format!("{BASE}/monitor"),
            Some(scrape_monitor(&["https://blog.test/"])),
        ),
        (
            Method::PATCH,
            format!("{BASE}/monitor/{id}"),
            Some(json!({ "name": "x" })),
        ),
        (Method::DELETE, format!("{BASE}/monitor/{id}"), None),
        (Method::POST, format!("{BASE}/monitor/{id}/run"), Some(json!({}))),
    ] {
        let (s, v) = e.send_as(&reader, method.clone(), &uri, body.as_ref()).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {uri}: {v}");
        assert_eq!(v["code"], "scope_missing");
    }
    let writer = e.key_for("acme", &[Scope::CrawlsWrite]).await;
    let (s, _) = e
        .send_as(&writer, Method::GET, &format!("{BASE}/monitor/{id}"), None)
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // another tenant sees nothing of it
    let other = e.key_for("other", &[Scope::CrawlsRead, Scope::CrawlsWrite]).await;
    for (method, uri) in [
        (Method::GET, format!("{BASE}/monitor/{id}")),
        (Method::DELETE, format!("{BASE}/monitor/{id}")),
        (Method::POST, format!("{BASE}/monitor/{id}/run")),
        (Method::GET, format!("{BASE}/monitor/{id}/checks")),
    ] {
        let (s, v) = e.send_as(&other, method.clone(), &uri, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {uri}: {v}");
    }
    let (_, v) = e
        .send_as(&other, Method::GET, &format!("{BASE}/monitor"), None)
        .await;
    assert_eq!(v["data"], json!([]));
    let (s, _) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(s, StatusCode::OK, "the owner still has it");
    let (s, _) = e.send(Method::GET, "/compat/v2/monitor", None).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn validation_reports_every_violation_with_json_pointers() {
    let e = env();
    let good = scrape_monitor(&["https://blog.test/"]);
    let with = |f: &dyn Fn(&mut Value)| {
        let mut v = good.clone();
        f(&mut v);
        v
    };
    let many_targets: Vec<Value> = (0..51)
        .map(|i| json!({ "type": "scrape", "urls": [format!("https://blog.test/{i}")] }))
        .collect();
    let cases: Vec<(Value, &str, &str)> = vec![
        (
            with(&|v| {
                v.as_object_mut().unwrap().remove("name");
            }),
            "/name",
            "required",
        ),
        (
            with(&|v| v["name"] = json!("n".repeat(257))),
            "/name",
            "out_of_range",
        ),
        (
            with(&|v| {
                v.as_object_mut().unwrap().remove("schedule");
            }),
            "/schedule",
            "required",
        ),
        (with(&|v| v["schedule"] = json!({})), "/schedule", "required"),
        (
            with(&|v| v["schedule"] = json!({ "cron": "0 * * * *", "text": "hourly" })),
            "/schedule",
            "invalid",
        ),
        (
            with(&|v| v["schedule"] = json!({ "text": "every 3 minutes" })),
            "/schedule/text",
            "too_frequent",
        ),
        (
            with(&|v| v["schedule"] = json!({ "cron": "* * * * *" })),
            "/schedule/cron",
            "too_frequent",
        ),
        (
            with(&|v| v["schedule"] = json!({ "text": "sometimes" })),
            "/schedule/text",
            "invalid",
        ),
        (
            with(&|v| v["schedule"] = json!({ "cron": "61 * * * *" })),
            "/schedule/cron",
            "invalid",
        ),
        (
            with(&|v| v["schedule"] = json!({ "text": "hourly", "timezone": "Mars/Olympus" })),
            "/schedule/timezone",
            "invalid",
        ),
        (with(&|v| v["schedule"] = json!("hourly")), "/schedule", "invalid"),
        (
            with(&|v| {
                v.as_object_mut().unwrap().remove("targets");
            }),
            "/targets",
            "required",
        ),
        (with(&|v| v["targets"] = json!([])), "/targets", "out_of_range"),
        (
            with(&|v| v["targets"] = json!(many_targets)),
            "/targets",
            "out_of_range",
        ),
        (
            with(&|v| v["targets"] = json!([{ "urls": ["https://blog.test/"] }])),
            "/targets/0/type",
            "required",
        ),
        (
            with(&|v| v["targets"] = json!([{ "type": "feed" }])),
            "/targets/0/type",
            "invalid",
        ),
        (
            with(&|v| v["targets"] = json!([{ "type": "scrape" }])),
            "/targets/0/urls",
            "required",
        ),
        (
            with(&|v| v["targets"] = json!([{ "type": "scrape", "urls": ["ftp://x.test/"] }])),
            "/targets/0/urls/0",
            "invalid",
        ),
        (
            with(&|v| v["targets"] = json!([{ "type": "crawl" }])),
            "/targets/0/url",
            "required",
        ),
        (
            with(&|v| {
                v["targets"] =
                    json!([{ "type": "crawl", "url": "https://blog.test/", "crawlOptions": { "limit": 0 } }])
            }),
            "/targets/0/crawlOptions/limit",
            "out_of_range",
        ),
        (
            with(
                &|v| v["targets"] = json!([{ "type": "crawl", "url": "https://blog.test/", "crawlOptions": { "includePaths": ["("] } }]),
            ),
            "/targets/0/crawlOptions/includePaths",
            "invalid",
        ),
        (
            with(&|v| v["targets"] = json!([{ "type": "search", "queries": ["a"] }])),
            "/goal",
            "required",
        ),
        (
            with(&|v| {
                v["goal"] = json!("g");
                v["targets"] = json!([{ "type": "search", "queries": (0..13).map(|i| format!("q{i}")).collect::<Vec<_>>() }]);
            }),
            "/targets/0/queries",
            "out_of_range",
        ),
        (
            with(&|v| {
                v["goal"] = json!("g");
                v["targets"] = json!([{ "type": "search", "queries": ["a"], "searchWindow": "2h" }]);
            }),
            "/targets/0/searchWindow",
            "invalid",
        ),
        (
            with(&|v| {
                v["goal"] = json!("g");
                v["targets"] = json!([{ "type": "search", "queries": ["a"], "maxResults": 51 }]);
            }),
            "/targets/0/maxResults",
            "out_of_range",
        ),
        (
            with(&|v| {
                v["goal"] = json!("g");
                v["targets"] = json!([{ "type": "search", "queries": ["a"], "includeDomains": ["a.test"], "excludeDomains": ["b.test"] }]);
            }),
            "/targets/0/excludeDomains",
            "invalid",
        ),
        (
            with(
                &|v| v["targets"] = json!([{ "type": "scrape", "urls": ["https://blog.test/"], "scrapeOptions": { "formats": [{ "type": "changeTracking", "modes": ["json"] }] } }]),
            ),
            "/targets/0/scrapeOptions/formats/0",
            "required",
        ),
        (
            with(&|v| {
                v["targets"] = json!([
                    { "type": "scrape", "urls": ["https://a.test/"], "id": "019df960-09bb-7c11-8001-1f12f50ab1c2" },
                    { "type": "scrape", "urls": ["https://b.test/"], "id": "019df960-09bb-7c11-8001-1f12f50ab1c2" },
                ])
            }),
            "/targets/1/id",
            "invalid",
        ),
        (
            with(&|v| v["retentionDays"] = json!(366)),
            "/retentionDays",
            "out_of_range",
        ),
        (
            with(&|v| v["retentionDays"] = json!(0)),
            "/retentionDays",
            "out_of_range",
        ),
        (
            with(&|v| v["retentionDays"] = json!("30")),
            "/retentionDays",
            "invalid",
        ),
        (
            with(&|v| v["goal"] = json!("g".repeat(2001))),
            "/goal",
            "out_of_range",
        ),
        (
            with(&|v| v["judgeEnabled"] = json!(true)),
            "/judgeEnabled",
            "invalid",
        ),
        (
            with(&|v| v["webhook"] = json!({ "url": "ftp://hooks.test/" })),
            "/webhook/url",
            "invalid",
        ),
        (
            with(&|v| v["webhook"] = json!({ "url": "https://hooks.test/", "events": ["bogus"] })),
            "/webhook/events",
            "invalid",
        ),
        (
            with(&|v| v["webhook"] = json!({ "url": "https://hooks.test/", "events": ["page"] })),
            "/webhook/events",
            "invalid",
        ),
        (
            with(&|v| v["notification"] = json!({ "email": { "recipients": ["not-an-address"] } })),
            "/notification/email/recipients/0",
            "invalid",
        ),
        (
            with(
                &|v| v["notification"] = json!({ "email": { "recipients": (0..26).map(|i| format!("u{i}@x.test")).collect::<Vec<_>>() } }),
            ),
            "/notification/email/recipients",
            "out_of_range",
        ),
    ];
    for (body, path, code) in cases {
        let (s, v) = e.post(&format!("{BASE}/monitor"), &body).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{path}: {v}");
        assert_eq!(v["success"], false);
        assert_eq!(v["code"], "validation_failed");
        let found = detail_paths(&v);
        assert!(
            found.contains(&(path.to_owned(), code.to_owned())),
            "{path} {code} missing in {found:?}"
        );
    }

    // several violations come back together
    let (s, v) = e
        .post(
            &format!("{BASE}/monitor"),
            &json!({ "schedule": { "text": "every minute" }, "targets": [], "retentionDays": 999 }),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let found = detail_paths(&v);
    for expected in [
        ("/name", "required"),
        ("/schedule/text", "too_frequent"),
        ("/targets", "out_of_range"),
        ("/retentionDays", "out_of_range"),
    ] {
        assert!(
            found.contains(&(expected.0.to_owned(), expected.1.to_owned())),
            "{expected:?} in {found:?}"
        );
    }
    // a body that is not an object
    let (s, v) = e.post(&format!("{BASE}/monitor"), &json!([1])).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    // nothing was stored by any of the rejected requests
    let (_, v) = e.get(&format!("{BASE}/monitor")).await;
    assert_eq!(v["data"], json!([]));

    // boundaries accepted: 50 targets, 365 days, the 5 minute floor
    let fifty: Vec<Value> = (0..50)
        .map(|i| json!({ "type": "scrape", "urls": [format!("https://blog.test/{i}")] }))
        .collect();
    let data = e
        .create(&with(&|v| {
            v["targets"] = json!(fifty);
            v["retentionDays"] = json!(365);
            v["schedule"] = json!({ "text": "every 5 minutes" });
        }))
        .await;
    assert_eq!(data["retentionDays"], 365);
    assert_eq!(data["targets"].as_array().unwrap().len(), 50);
    assert_eq!(data["schedule"]["cron"], "*/5 * * * *");
}

#[tokio::test]
async fn patching_to_a_search_target_requires_a_goal_unless_judging_is_off() {
    let e = env();
    let id = e.create(&scrape_monitor(&["https://blog.test/"])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let search = json!([{ "type": "search", "queries": ["q"] }]);
    let (s, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "targets": search }))
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(detail_paths(&v).contains(&("/goal".to_owned(), "required".to_owned())));
    let (s, v) = e
        .patch(
            &format!("{BASE}/monitor/{id}"),
            &json!({ "targets": search, "judgeEnabled": false }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["data"]["targets"][0]["type"], "search");
    let (s, _) = e
        .patch(
            &format!("{BASE}/monitor/{id}"),
            &json!({ "targets": search, "goal": "find launches" }),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
}

// ---- change detection -----------------------------------------------------------------------------

#[tokio::test]
async fn crawl_target_reports_new_same_changed_removed() {
    let e = env();
    let seed = "https://site.test/docs";
    let (a, b) = ("https://site.test/docs/a", "https://site.test/docs/b");
    e.tools.set_markdown(seed, "# Docs\nindex");
    e.tools.set_markdown(a, "# A\nold text");
    e.tools.set_markdown(b, "# B\nbody");
    let links = |urls: &[&str]| -> Vec<MapLink> {
        urls.iter()
            .map(|u| MapLink {
                url: (*u).to_owned(),
                title: None,
                description: None,
            })
            .collect()
    };
    e.tools
        .set_links(seed, links(&[a, b, "https://elsewhere.test/x"]));
    let data = e
        .create(&json!({
            "name": "Docs monitor",
            "schedule": { "cron": "7-59/15 * * * *", "timezone": "UTC" },
            "targets": [{ "type": "crawl", "url": seed, "crawlOptions": { "limit": 10 } }],
        }))
        .await;
    let id = data["id"].as_str().unwrap().to_owned();
    assert_eq!(data["schedule"]["cron"], "7-59/15 * * * *");

    // 1: everything is new (the off-site link is not part of the crawl)
    let c1 = e.run_check(&id).await;
    assert_eq!(c1["status"], "completed");
    assert_eq!(c1["monitorId"], id.as_str());
    assert_eq!(summary(&c1), (3, 0, 3, 0, 0, 0));
    assert_eq!(c1["actualCredits"], 3);
    assert_eq!(c1["billingStatus"], "settled");
    assert_eq!(c1["targetResults"][0]["status"], "completed");
    assert_eq!(c1["targetResults"][0]["type"], "crawl");
    assert_eq!(c1["targetResults"][0]["pages"], 3);
    assert!(c1["summary"].get("goalJudging").is_none() && c1["summary"].get("relevant").is_none());
    let urls: Vec<&str> = c1["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["url"].as_str().unwrap())
        .collect();
    assert_eq!(urls, [seed, a, b], "pages are ordered by target then URL");
    assert_eq!(page(&c1, a)["status"], "new");
    assert_eq!(page(&c1, a)["statusCode"], 200);
    assert_eq!(
        page(&c1, a)["metadata"]["changeTracking"],
        json!({ "previousScrapeAt": null, "changeStatus": "new", "visibility": "visible" })
    );
    assert_eq!(page(&c1, a)["targetId"], data["targets"][0]["id"]);
    assert!(page(&c1, a).get("diff").is_none());
    assert_eq!(e.tools.scraped().len(), 3);

    // 2: nothing changed
    e.clock.advance_ms(60_000);
    let c2 = e.run_check(&id).await;
    assert_eq!(summary(&c2), (3, 3, 0, 0, 0, 0));
    assert_eq!(page(&c2, a)["status"], "same");
    assert_eq!(
        page(&c2, a)["metadata"]["changeTracking"],
        json!({ "previousScrapeAt": "2025-06-01T12:00:00.000Z", "changeStatus": "same", "visibility": "visible" })
    );

    // 3: page a changed
    e.clock.advance_ms(60_000);
    e.tools.set_markdown(a, "# A\nnew text");
    let c3 = e.run_check(&id).await;
    assert_eq!(summary(&c3), (3, 2, 0, 1, 0, 0));
    let changed = page(&c3, a);
    assert_eq!(changed["status"], "changed");
    assert_eq!(
        changed["diff"]["text"],
        "--- previous\n+++ current\n@@ -1,2 +1,2 @@\n # A\n-old text\n+new text\n"
    );
    let chunk = &changed["diff"]["json"]["files"][0]["chunks"][0];
    assert_eq!(chunk["content"], "@@ -1,2 +1,2 @@");
    let kinds: Vec<&str> = chunk["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["normal", "del", "add"]);
    assert_eq!(changed["metadata"]["changeTracking"]["changeStatus"], "changed");
    assert_eq!(
        changed["metadata"]["changeTracking"]["previousScrapeAt"],
        "2025-06-01T12:00:00.000Z"
    );
    // the status filter and pagination of the check detail
    let (_, v) = e
        .get(&format!(
            "{BASE}/monitor/{id}/checks/{}?status=changed",
            c3["id"].as_str().unwrap()
        ))
        .await;
    let only: Vec<&str> = v["data"]["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["url"].as_str().unwrap())
        .collect();
    assert_eq!(only, [a]);
    assert_eq!(v["next"], Value::Null);
    let c3_id = c3["id"].as_str().unwrap();
    let (_, p1) = e
        .get(&format!("{BASE}/monitor/{id}/checks/{c3_id}?limit=2"))
        .await;
    assert_eq!(p1["data"]["pages"].as_array().unwrap().len(), 2);
    let next = p1["next"].as_str().unwrap().to_owned();
    assert_eq!(p1["data"]["next"], p1["next"]);
    assert!(
        next.ends_with(&format!("/monitor/{id}/checks/{c3_id}?skip=2&limit=2")),
        "{next}"
    );
    let (s, p2) = e.get(&next).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(p2["data"]["pages"].as_array().unwrap().len(), 1);
    assert_eq!(p2["next"], Value::Null);
    assert_eq!(p2["data"]["pages"][0]["url"], b);

    // 4: page b disappears from the site
    e.clock.advance_ms(60_000);
    e.tools.set_links(seed, links(&[a]));
    e.tools.remove(b);
    let c4 = e.run_check(&id).await;
    assert_eq!(summary(&c4), (3, 2, 0, 0, 1, 0));
    let removed = page(&c4, b);
    assert_eq!(removed["status"], "removed");
    assert_eq!(removed["metadata"]["changeTracking"]["changeStatus"], "removed");
    assert_eq!(removed["metadata"]["changeTracking"]["visibility"], "hidden");

    // 5: the removal is reported once
    let c5 = e.run_check(&id).await;
    assert_eq!(summary(&c5), (2, 2, 0, 0, 0, 0));
    assert!(c5["pages"].as_array().unwrap().iter().all(|p| p["url"] != b));

    // the monitor shows the newest finished check
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(v["data"]["lastCheckSummary"]["totalPages"], 2);
    assert_eq!(v["data"]["lastCheckSummary"]["same"], 2);
    assert_eq!(v["data"]["lastRunAt"], "2025-06-01T12:03:00.000Z");
    assert_eq!(v["data"]["currentCheckId"], Value::Null);
    // and checks list newest first, filterable by status
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks")).await;
    let ids: Vec<&str> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 5);
    assert_eq!(ids[0], c5["id"].as_str().unwrap());
    assert_eq!(ids[4], c1["id"].as_str().unwrap());
    let (_, v) = e
        .get(&format!(
            "{BASE}/monitor/{id}/checks?status=completed&limit=2&offset=1"
        ))
        .await;
    let ids: Vec<&str> = v["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, [c4["id"].as_str().unwrap(), c3["id"].as_str().unwrap()]);
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks?status=failed")).await;
    assert_eq!(v["data"], json!([]));
    let (s, _) = e.get(&format!("{BASE}/monitor/{id}/checks?status=bogus")).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // usage: the scrape service books pages itself; the monitor row carries only the extras (none here)
    let rows = e
        .state
        .repos
        .intel
        .usage_recent(e.tenant, Some("monitor"), 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|r| r.credits == 0 && r.status == "completed"));
    assert_eq!(rows[0].ref_id, Some(id.parse().unwrap()));
}

#[tokio::test]
async fn scrape_target_errors_removals_and_scrape_options() {
    let e = env();
    let (ok, gone, flaky) = ("https://s.test/ok", "https://s.test/gone", "https://s.test/flaky");
    e.tools.set_markdown(ok, "fine");
    e.tools.set_markdown(gone, "here today");
    e.tools.set_markdown(flaky, "stable");
    let id = e
        .create(&json!({
            "name": "Scrape",
            "schedule": { "text": "hourly" },
            "targets": [{
                "type": "scrape",
                "urls": [ok, gone, flaky],
                "scrapeOptions": { "formats": ["markdown", "links"], "onlyMainContent": false, "waitFor": 250 },
            }],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let c1 = e.run_check(&id).await;
    assert_eq!(summary(&c1), (3, 0, 3, 0, 0, 0));
    // the scrape options reach the scrape service unchanged
    for (url, options) in e.tools.scraped() {
        assert_eq!(
            options,
            json!({ "formats": ["markdown", "links"], "onlyMainContent": false, "waitFor": 250 }),
            "{url}"
        );
    }

    // `gone` answers 404 now, `flaky` fails
    e.tools.set_document(
        gone,
        json!({ "markdown": "", "metadata": { "sourceURL": gone, "statusCode": 404 } }),
    );
    e.tools
        .set_failure(flaky, ToolError::Failed("connection reset".to_owned()));
    e.clock.advance_ms(60_000);
    let c2 = e.run_check(&id).await;
    assert_eq!(summary(&c2), (3, 1, 0, 0, 1, 1));
    assert_eq!(c2["status"], "partial", "some pages failed");
    assert_eq!(page(&c2, gone)["status"], "removed");
    let failed = page(&c2, flaky);
    assert_eq!(failed["status"], "error");
    assert_eq!(failed["error"], "connection reset");
    assert_eq!(failed["statusCode"], Value::Null);

    // the failing page keeps its baseline: once it answers with the same content it is `same`;
    // the 404 page lost its baseline, so it is now an error rather than a second removal
    e.tools.set_markdown(flaky, "stable");
    let c3 = e.run_check(&id).await;
    assert_eq!(summary(&c3), (3, 2, 0, 0, 0, 1));
    assert_eq!(page(&c3, flaky)["status"], "same");
    assert_eq!(page(&c3, gone)["status"], "error");
    assert_eq!(page(&c3, gone)["error"], "the page answered HTTP 404");

    // a 404 that was never seen is an error, and a check whose only page fails is `failed`
    let lone = "https://s.test/lone";
    e.tools.set_document(
        lone,
        json!({ "markdown": "", "metadata": { "sourceURL": lone, "statusCode": 404 } }),
    );
    let id2 = e.create(&scrape_monitor(&[lone])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let c = e.run_check(&id2).await;
    assert_eq!(summary(&c), (1, 0, 0, 0, 0, 1));
    assert_eq!(c["status"], "failed");
    assert_eq!(c["error"], "the page answered HTTP 404");
    assert_eq!(page(&c, lone)["error"], "the page answered HTTP 404");
}

#[tokio::test]
async fn json_mode_change_tracking_extracts_fields_and_diffs_them() {
    let llm = Arc::new(MockLlm::from_fn(|call| {
        let price = if call.user.contains("$24") {
            "$24/mo"
        } else {
            "$19/mo"
        };
        Ok(json!({ "plans": [{ "name": "Starter", "price": price }] }))
    }));
    let e = env_with(Setup {
        llm: Some(llm.clone()),
        ..Setup::default()
    });
    let (pricing, plans, misc) = (
        "https://shop.test/pricing",
        "https://shop.test/plans",
        "https://shop.test/misc",
    );
    e.tools.set_markdown(pricing, "# Pricing\nStarter $19");
    e.tools.set_markdown(plans, "# Plans\nStarter $19");
    e.tools.set_markdown(misc, "# Misc\nStarter $19");
    let schema = json!({ "type": "object", "properties": { "plans": { "type": "array" } } });
    let tracking =
        |modes: Value| json!({ "formats": [{ "type": "changeTracking", "modes": modes, "schema": schema }] });
    let id = e
        .create(&json!({
            "name": "Pricing",
            "schedule": { "text": "hourly" },
            "targets": [
                { "type": "scrape", "urls": [pricing], "scrapeOptions": tracking(json!(["json"])) },
                { "type": "scrape", "urls": [plans], "scrapeOptions": tracking(json!(["json", "git-diff"])) },
                { "type": "scrape", "urls": [misc], "scrapeOptions": tracking(json!(["json"])) },
            ],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let c1 = e.run_check(&id).await;
    assert_eq!(summary(&c1), (3, 0, 3, 0, 0, 0));
    let first = json!({ "plans": [{ "name": "Starter", "price": "$19/mo" }] });
    assert_eq!(page(&c1, pricing)["snapshot"], json!({ "json": first }));
    assert!(page(&c1, pricing).get("diff").is_none());
    // the changeTracking format never reaches the scrape service; markdown is always requested
    assert!(e
        .tools
        .scraped()
        .iter()
        .all(|(_, o)| o["formats"] == json!(["markdown"])));

    e.clock.advance_ms(60_000);
    e.tools.set_markdown(pricing, "# Pricing\nStarter $24");
    e.tools.set_markdown(plans, "# Plans\nStarter $24");
    e.tools.set_markdown(misc, "# Misc (updated copy)\nStarter $19");
    let c2 = e.run_check(&id).await;
    assert_eq!(
        summary(&c2),
        (3, 1, 0, 2, 0, 0),
        "misc changed only outside the tracked fields"
    );
    let field = json!({ "plans[0].price": { "previous": "$19/mo", "current": "$24/mo" } });
    let json_only = page(&c2, pricing);
    assert_eq!(json_only["status"], "changed");
    assert_eq!(json_only["diff"]["json"], field);
    assert!(
        json_only["diff"].get("text").is_none(),
        "json-only monitors carry no markdown diff"
    );
    assert_eq!(json_only["snapshot"]["json"]["plans"][0]["price"], "$24/mo");
    let mixed = page(&c2, plans);
    assert_eq!(mixed["status"], "changed");
    assert_eq!(mixed["diff"]["json"], field);
    assert_eq!(
        mixed["diff"]["text"],
        "--- previous\n+++ current\n@@ -1,2 +1,2 @@\n # Plans\n-Starter $19\n+Starter $24\n"
    );
    assert_eq!(page(&c2, misc)["status"], "same");
    assert!(page(&c2, misc).get("diff").is_none());
    // the baseline of the unchanged-fields page moved on, so the next check is `same` everywhere
    let c3 = e.run_check(&id).await;
    assert_eq!(summary(&c3), (3, 3, 0, 0, 0, 0));

    // tokens were spent and booked
    let rows = e
        .state
        .repos
        .intel
        .usage_recent(e.tenant, Some("monitor"), 10, 0)
        .await
        .unwrap();
    assert!(rows.iter().map(|r| r.prompt_tokens).sum::<u64>() > 0);
    assert!(!llm.calls().is_empty());
}

#[tokio::test]
async fn json_mode_without_an_llm_falls_back_to_the_markdown_diff() {
    let e = env();
    let url = "https://shop.test/pricing";
    e.tools.set_markdown(url, "Starter $19");
    let id = e
        .create(&json!({
            "name": "Pricing",
            "schedule": { "text": "hourly" },
            "targets": [{ "type": "scrape", "urls": [url], "scrapeOptions": {
                "formats": [{ "type": "changeTracking", "modes": ["json", "git-diff"], "prompt": "prices" }] } }],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    e.run_check(&id).await;
    e.tools.set_markdown(url, "Starter $24");
    let c = e.run_check(&id).await;
    let p = page(&c, url);
    assert_eq!(p["status"], "changed");
    assert_eq!(p["metadata"]["changeTrackingJson"], "skipped(llm_not_configured)");
    assert!(p["diff"]["text"].as_str().unwrap().contains("-Starter $19"));
    assert!(p.get("snapshot").is_none());
}

// ---- goals and judging -----------------------------------------------------------------------------

fn judge_llm(fail: Arc<AtomicBool>) -> Arc<MockLlm> {
    Arc::new(MockLlm::from_fn(move |call| {
        if fail.load(Ordering::SeqCst) {
            return Err(LlmError::Transport("the model is down".to_owned()));
        }
        if call.user.contains("page-a") {
            Ok(json!({
                "meaningful": true,
                "confidence": "high",
                "reason": "the price dropped",
                "meaningfulChanges": [{ "type": "changed", "before": "$20", "after": "$10", "reason": "cheaper" }],
            }))
        } else {
            Ok(json!({ "meaningful": false, "confidence": "medium", "reason": "cosmetic" }))
        }
    }))
}

#[tokio::test]
async fn goal_judging_counts_only_relevant_changes() {
    let fail = Arc::new(AtomicBool::new(false));
    let llm = judge_llm(fail.clone());
    let e = env_with(Setup {
        llm: Some(llm.clone()),
        ..Setup::default()
    });
    let (a, b) = ("https://shop.test/page-a", "https://shop.test/page-b");
    e.tools.set_markdown(a, "Price: $20");
    e.tools.set_markdown(b, "Footer: 2024");
    let data = e
        .create(&json!({
            "name": "Prices",
            "schedule": { "text": "hourly" },
            "goal": "Tell me when a price drops",
            "webhook": { "url": "https://hooks.test/m" },
            "targets": [{ "type": "scrape", "urls": [a, b] }],
        }))
        .await;
    let id = data["id"].as_str().unwrap().to_owned();
    assert_eq!(data["goal"], "Tell me when a price drops");
    assert_eq!(data["judgeEnabled"], true, "a goal turns judging on");

    // new pages are not judged
    let c1 = e.run_check(&id).await;
    assert_eq!(summary(&c1), (2, 0, 2, 0, 0, 0));
    assert_eq!(c1["summary"]["goalJudging"], "completed");
    assert_eq!(c1["summary"]["relevant"], 0);
    assert!(llm.calls().is_empty());
    assert_eq!(page(&c1, a)["judgment"], Value::Null);

    // both pages change, only one change matters
    e.clock.advance_ms(60_000);
    e.tools.set_markdown(a, "Price: $10");
    e.tools.set_markdown(b, "Footer: 2025");
    let c2 = e.run_check(&id).await;
    assert_eq!(summary(&c2), (2, 0, 0, 2, 0, 0));
    assert_eq!(c2["summary"]["relevant"], 1);
    assert_eq!(c2["summary"]["goalJudging"], "completed");
    assert_eq!(llm.calls().len(), 2);
    let ja = &page(&c2, a)["judgment"];
    assert_eq!(ja["meaningful"], true);
    assert_eq!(ja["confidence"], "high");
    assert_eq!(ja["reason"], "the price dropped");
    assert_eq!(ja["meaningfulChanges"][0]["after"], "$10");
    let jb = &page(&c2, b)["judgment"];
    assert_eq!(
        (jb["meaningful"].as_bool(), jb["reason"].as_str()),
        (Some(false), Some("cosmetic"))
    );
    // the judge saw the goal, the URL and the diff, all inside data fences
    let prompt = &llm.calls()[0].user;
    assert!(
        prompt.contains("Tell me when a price drops")
            && prompt.contains("-Price: $20")
            && prompt.contains("+Price: $10")
    );
    assert_eq!(c2["actualCredits"], 4, "two scrapes and two judged pages");

    // the judge failing leaves the pages unjudged and says so
    e.clock.advance_ms(60_000);
    fail.store(true, Ordering::SeqCst);
    e.tools.set_markdown(a, "Price: $5");
    let c3 = e.run_check(&id).await;
    assert_eq!(summary(&c3), (2, 1, 0, 1, 0, 0));
    assert_eq!(c3["status"], "completed");
    assert_eq!(c3["summary"]["goalJudging"], "partial");
    assert_eq!(c3["summary"]["relevant"], 0);
    assert_eq!(page(&c3, a)["judgment"], Value::Null);
    assert!(page(&c3, a)["metadata"]["judgeError"]
        .as_str()
        .unwrap()
        .contains("the model is down"));

    // webhook events carry the judgment
    until("webhook events", || e.webhook_posts().len() >= 8).await;
    let page_events: Vec<Value> = e
        .webhook_posts()
        .iter()
        .map(Posted::json)
        .filter(|b| b["type"] == "monitor.page" && b["id"] == c2["id"])
        .collect();
    assert_eq!(page_events.len(), 2);
    let by_url = |url: &str| {
        page_events
            .iter()
            .find(|b| b["data"][0]["url"] == url)
            .unwrap()
            .clone()
    };
    assert_eq!(by_url(a)["data"][0]["isMeaningful"], true);
    assert_eq!(by_url(a)["data"][0]["judgment"]["reason"], "the price dropped");
    assert_eq!(by_url(b)["data"][0]["isMeaningful"], false);
    assert!(by_url(a)["data"][0]["diff"]["text"]
        .as_str()
        .unwrap()
        .contains("+Price: $10"));

    // judging cost is booked incrementally: 1 credit and the tokens per judged page
    let rows = e
        .state
        .repos
        .intel
        .usage_recent(e.tenant, Some("monitor"), 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.iter().map(|r| r.credits).sum::<u64>(), 2);
    assert!(
        rows.iter()
            .map(|r| r.prompt_tokens + r.completion_tokens)
            .sum::<u64>()
            > 0
    );
}

#[tokio::test]
async fn a_goal_without_an_llm_skips_judging_and_still_completes() {
    let e = env();
    let url = "https://shop.test/page-a";
    e.tools.set_markdown(url, "v1");
    let id = e
        .create(&json!({
            "name": "Goal without model",
            "schedule": { "text": "hourly" },
            "goal": "anything interesting",
            "targets": [{ "type": "scrape", "urls": [url] }],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    e.run_check(&id).await;
    e.tools.set_markdown(url, "v2");
    let c = e.run_check(&id).await;
    assert_eq!(c["status"], "completed");
    assert_eq!(summary(&c), (1, 0, 0, 1, 0, 0));
    assert_eq!(c["summary"]["goalJudging"], "skipped(llm_not_configured)");
    assert!(c["summary"].get("relevant").is_none());
    assert_eq!(page(&c, url)["judgment"], Value::Null);
}

#[tokio::test]
async fn judge_enabled_false_keeps_the_goal_but_does_not_judge() {
    let llm = judge_llm(Arc::new(AtomicBool::new(false)));
    let e = env_with(Setup {
        llm: Some(llm.clone()),
        ..Setup::default()
    });
    let url = "https://shop.test/page-a";
    e.tools.set_markdown(url, "v1");
    let data = e
        .create(&json!({
            "name": "Parked goal",
            "schedule": { "text": "hourly" },
            "goal": "later",
            "judgeEnabled": false,
            "targets": [{ "type": "scrape", "urls": [url] }],
        }))
        .await;
    assert_eq!(
        (data["goal"].as_str(), data["judgeEnabled"].as_bool()),
        (Some("later"), Some(false))
    );
    let id = data["id"].as_str().unwrap();
    e.run_check(id).await;
    e.tools.set_markdown(url, "v2");
    let c = e.run_check(id).await;
    assert_eq!(summary(&c), (1, 0, 0, 1, 0, 0));
    assert_eq!(c["summary"]["goalJudging"], "disabled");
    assert!(llm.calls().is_empty());
}

// ---- search targets -----------------------------------------------------------------------------------

fn hit(url: &str, position: u32) -> WebHit {
    WebHit {
        title: url.to_owned(),
        url: url.to_owned(),
        description: String::new(),
        category: None,
        position,
    }
}

#[tokio::test]
async fn search_target_alerts_on_new_relevant_results_once() {
    let search = Arc::new(MockSearch::new(SearchResults {
        web: vec![
            hit("https://news.test/launch", 1),
            hit("https://news.test/funding", 2),
            hit("https://other.test/launch", 3),
        ],
        ..SearchResults::default()
    }));
    let llm = Arc::new(MockLlm::from_fn(|call| {
        if call.user.contains("news.test/launch") {
            Ok(json!({ "meaningful": true, "confidence": "high", "reason": "a launch" }))
        } else {
            Ok(json!({ "meaningful": false, "confidence": "high", "reason": "funding news" }))
        }
    }));
    let e = env_with(Setup {
        llm: Some(llm.clone()),
        search: Some(search.clone()),
        ..Setup::default()
    });
    e.tools
        .set_markdown("https://news.test/launch", "Acme launches an assistant");
    e.tools
        .set_markdown("https://news.test/funding", "Acme raises money");
    e.tools
        .set_markdown("https://other.test/launch", "should be filtered out");
    let id = e
        .create(&json!({
            "name": "Launches",
            "schedule": { "text": "every 30 minutes" },
            "goal": "Alert when an assistant is launched",
            "targets": [{
                "type": "search",
                "queries": ["open source assistant"],
                "searchWindow": "24h",
                "maxResults": 10,
                "includeDomains": ["news.test"],
            }],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let c1 = e.run_check(&id).await;
    assert_eq!(c1["status"], "completed");
    assert_eq!(summary(&c1), (2, 1, 1, 0, 0, 0));
    assert_eq!(c1["summary"]["relevant"], 1);
    let launch = page(&c1, "https://news.test/launch");
    assert_eq!(launch["status"], "new");
    assert_eq!(launch["metadata"]["searchStatus"], "alert");
    assert_eq!(launch["judgment"]["meaningful"], true);
    let funding = page(&c1, "https://news.test/funding");
    assert_eq!(funding["status"], "same");
    assert_eq!(funding["metadata"]["searchStatus"], "ignored");
    assert_eq!(funding["judgment"]["reason"], "funding news");
    assert!(c1["pages"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["url"] != "https://other.test/launch"));
    let queries = search.queries();
    assert_eq!(
        (queries.len(), queries[0].query.as_str(), queries[0].limit),
        (1, "open source assistant", 10)
    );
    assert_eq!(queries[0].include_domains, ["news.test"]);
    assert_eq!(queries[0].tbs.as_deref(), Some("qdr:d"));
    // 2 credits for the search block, 2 judge credits are the incremental ledger entries
    let rows = e
        .state
        .repos
        .intel
        .usage_recent(e.tenant, Some("monitor"), 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.iter().map(|r| r.credits).sum::<u64>(), 4);
    assert_eq!(c1["actualCredits"], 6);

    // the same results again are `already_seen`: no new scrape, no new judging
    e.clock.advance_ms(60_000);
    let (scraped, judged) = (e.tools.scraped().len(), llm.calls().len());
    let c2 = e.run_check(&id).await;
    assert_eq!(summary(&c2), (2, 2, 0, 0, 0, 0));
    assert_eq!(
        page(&c2, "https://news.test/launch")["metadata"]["searchStatus"],
        "already_seen"
    );
    assert_eq!((e.tools.scraped().len(), llm.calls().len()), (scraped, judged));
}

#[tokio::test]
async fn search_target_without_a_provider_fails_per_target() {
    let e = env();
    let ok = "https://blog.test/";
    e.tools.set_markdown(ok, "hello");
    // search only: every target failed, so the check failed
    let id = e
        .create(&json!({
            "name": "Search only",
            "schedule": { "text": "hourly" },
            "judgeEnabled": false,
            "targets": [{ "type": "search", "queries": ["x"] }],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let c = e.run_check(&id).await;
    assert_eq!(c["status"], "failed");
    assert_eq!(c["targetResults"][0]["status"], "failed");
    assert!(
        c["targetResults"][0]["error"]
            .as_str()
            .unwrap()
            .contains("search_not_configured"),
        "{c}"
    );
    assert!(c["error"].as_str().unwrap().contains("search_not_configured"));
    // search next to a working target: the check is partial
    let id = e
        .create(&json!({
            "name": "Mixed",
            "schedule": { "text": "hourly" },
            "judgeEnabled": false,
            "targets": [{ "type": "scrape", "urls": [ok] }, { "type": "search", "queries": ["x"] }],
        }))
        .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let c = e.run_check(&id).await;
    assert_eq!(c["status"], "partial");
    assert_eq!(summary(&c), (1, 0, 1, 0, 0, 0));
    let results = c["targetResults"].as_array().unwrap();
    assert_eq!(
        (results[0]["status"].as_str(), results[1]["status"].as_str()),
        (Some("completed"), Some("failed"))
    );
}

// ---- webhooks ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn webhook_events_are_signed_and_filtered() {
    let e = env();
    let (a, b) = ("https://blog.test/a", "https://blog.test/b");
    e.tools.set_markdown(a, "one");
    e.tools.set_markdown(b, "two");
    let data = e
        .create(&json!({
            "name": "Hooked",
            "schedule": { "text": "hourly" },
            "webhook": {
                "url": "https://hooks.test/monitor",
                "headers": { "X-Token": "abc" },
                "metadata": { "env": "test" },
            },
            "targets": [{ "type": "scrape", "urls": [a, b] }],
        }))
        .await;
    let id = data["id"].as_str().unwrap().to_owned();
    assert_eq!(
        data["webhook"]["events"],
        json!(["monitor.page", "monitor.check.completed"])
    );
    assert_eq!(data["webhook"]["headers"], json!({ "X-Token": "abc" }));

    // check 1: two new pages and the completion
    let c1 = e.run_check(&id).await;
    until("3 events", || e.webhook_posts().len() == 3).await;
    let posts = e.webhook_posts();
    let types: Vec<String> = posts
        .iter()
        .map(|p| p.json()["type"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(types, ["monitor.page", "monitor.page", "monitor.check.completed"]);
    for p in &posts {
        assert_eq!(p.url, "https://hooks.test/monitor");
        let body = p.json();
        assert_eq!(body["success"], true);
        assert_eq!(body["id"], c1["id"]);
        assert_eq!(body["metadata"], json!({ "env": "test" }));
        Uuid::parse_str(body["webhookId"].as_str().unwrap()).unwrap();
        assert_eq!(body["data"][0]["monitorId"], id.as_str());
        assert_eq!(body["data"][0]["checkId"], c1["id"]);
        assert_eq!(
            p.header("X-Firecrawl-Signature"), // wire-compat
            Some(compat_signature(SECRET, &p.body).as_str())
        );
        assert!(p.header("X-Firecrawl-Signature").unwrap().starts_with("sha256=")); // wire-compat
        assert_eq!(p.header("X-Token"), Some("abc"));
        assert_eq!(p.header("Content-Type"), Some("application/json"));
        assert_eq!(p.header("Crawlx-Event"), body["type"].as_str());
    }
    let first = posts[0].json();
    assert_eq!(first["data"][0]["status"], "new");
    assert_eq!(first["data"][0]["url"], a);
    assert_eq!(first["data"][0]["error"], Value::Null);
    let done = posts[2].json();
    assert_eq!(done["data"][0]["status"], "completed");
    assert_eq!(done["data"][0]["summary"]["totalPages"], 2);
    assert_eq!(done["data"][0]["summary"]["new"], 2);

    // check 2: nothing changed, so only the completion is sent
    e.clock.advance_ms(60_000);
    e.run_check(&id).await;
    until("completion", || e.webhook_posts().len() == 4).await;
    assert_eq!(e.webhook_posts()[3].json()["type"], "monitor.check.completed");

    // only the events the monitor asks for
    let (s, v) = e
        .patch(
            &format!("{BASE}/monitor/{id}"),
            &json!({ "webhook": { "url": "https://hooks.test/monitor", "events": ["monitor.check.completed"] } }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    e.clock.advance_ms(60_000);
    e.tools.set_markdown(a, "one changed");
    e.run_check(&id).await;
    until("one more", || e.webhook_posts().len() == 5).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let posts = e.webhook_posts();
    assert_eq!(posts.len(), 5, "the page event was filtered out");
    assert_eq!(posts[4].json()["data"][0]["summary"]["changed"], 1);

    // a failed check reports success: false with the reason
    e.clock.advance_ms(60_000);
    e.tools.set_failure(a, ToolError::Failed("dns".to_owned()));
    e.tools.set_failure(b, ToolError::Failed("dns".to_owned()));
    let failed = e.run_check(&id).await;
    assert_eq!(failed["status"], "failed");
    until("failure event", || e.webhook_posts().len() == 6).await;
    let body = e.webhook_posts()[5].json();
    assert_eq!(body["success"], false);
    assert_eq!(body["error"], "dns");
    assert_eq!(body["data"][0]["status"], "failed");

    // clearing the webhook stops delivery
    let (_, v) = e
        .patch(&format!("{BASE}/monitor/{id}"), &json!({ "webhook": null }))
        .await;
    assert_eq!(v["data"]["webhook"], Value::Null);
    e.tools.set_markdown(a, "again");
    e.tools.set_markdown(b, "again");
    e.run_check(&id).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(e.webhook_posts().len(), 6);
}

// ---- scheduler, overlap, retention ------------------------------------------------------------------------

#[tokio::test]
async fn the_ticker_runs_due_monitors_through_the_engine_and_reschedules() {
    let e = env();
    let url = "https://blog.test/";
    e.tools.set_markdown(url, "hello");
    let id = e.create(&scrape_monitor(&[url])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let sched = scheduler(&e.state);
    assert_eq!(sched.tick(e.clock.now()).await.unwrap().claimed, 0, "not due yet");

    e.clock.advance_ms(31 * 60_000); // 12:31
    let report = sched.tick(e.clock.now()).await.unwrap();
    assert_eq!((report.claimed, report.ran.len()), (1, 1));
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(v["data"]["lastRunAt"], "2025-06-01T12:31:00.000Z");
    assert_eq!(v["data"]["nextRunAt"], "2025-06-01T13:00:00.000Z");
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks")).await;
    let checks = v["data"].as_array().unwrap();
    assert_eq!(checks.len(), 1);
    assert_eq!(
        (checks[0]["trigger"].as_str(), checks[0]["status"].as_str()),
        (Some("scheduled"), Some("completed"))
    );
    assert_eq!(checks[0]["id"], json!(report.ran[0].1));
    assert_eq!(checks[0]["scheduledFor"], "2025-06-01T12:30:00.000Z");
    assert_eq!(checks[0]["summary"].get("scheduledFor"), None);
    assert_eq!(
        sched.tick(e.clock.now()).await.unwrap().claimed,
        0,
        "claimed exactly once per due time"
    );

    // a paused monitor is not ticked, but still runs on demand
    e.patch(&format!("{BASE}/monitor/{id}"), &json!({ "status": "paused" }))
        .await;
    e.clock.advance_ms(3_600_000);
    assert_eq!(sched.tick(e.clock.now()).await.unwrap().claimed, 0);
    let manual = e.run_check(&id).await;
    assert_eq!(
        (manual["trigger"].as_str(), manual["status"].as_str()),
        (Some("manual"), Some("completed"))
    );
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(
        v["data"]["nextRunAt"],
        Value::Null,
        "a manual run does not schedule a paused monitor"
    );
}

#[tokio::test]
async fn the_background_loop_picks_up_due_monitors_and_stops_on_shutdown() {
    let shutdown = CancellationToken::new();
    let e = env_with(Setup {
        shutdown: Some(shutdown.clone()),
        ..Setup::default()
    });
    let url = "https://blog.test/";
    e.tools.set_markdown(url, "hello");
    let id = e.create(&scrape_monitor(&[url])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    e.clock.advance_ms(31 * 60_000);
    let handle = spawn_monitor_loop_every(e.state.clone(), Duration::from_millis(10));
    let mut seen = false;
    for _ in 0..500 {
        let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks")).await;
        if v["data"]
            .as_array()
            .is_some_and(|c| c.len() == 1 && c[0]["status"] == "completed")
        {
            seen = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(seen, "the loop never ran the due monitor");
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .unwrap()
        .unwrap();
}

fn running_check(monitor: &str, tenant: TenantId, started_at: &str) -> CheckRecord {
    let started = utc(started_at);
    CheckRecord {
        id: Uuid::now_v7(),
        monitor: monitor.parse().unwrap(),
        tenant,
        trigger: "scheduled".to_owned(),
        state: CheckState::Running,
        status: None,
        summary: json!({ "totalPages": 0, "same": 0, "changed": 0, "new": 0, "removed": 0, "error": 0 }),
        error: None,
        started_at: started,
        finished_at: None,
        expires_at: started + chrono::Duration::days(30),
    }
}

#[tokio::test]
async fn overlapping_runs_are_skipped_or_refused_and_dead_checks_are_reaped() {
    let e = env();
    let url = "https://blog.test/";
    e.tools.set_markdown(url, "hello");
    let id = e.create(&scrape_monitor(&[url])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let sched = scheduler(&e.state);

    // a check is running (started 5 minutes ago)
    e.clock.advance_ms(31 * 60_000); // 12:31
    let running = running_check(&id, e.tenant, "2025-06-01T12:26:00Z");
    e.state.repos.intel.check_insert(&running).await.unwrap();
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(v["data"]["currentCheckId"], running.id.to_string());

    // the ticker records a skipped_overlap check and moves on
    let report = sched.tick(e.clock.now()).await.unwrap();
    assert_eq!(report.ran.len(), 1);
    let (_, v) = e
        .get(&format!("{BASE}/monitor/{id}/checks?status=skipped_overlap"))
        .await;
    let skipped = v["data"].as_array().unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0]["status"], "skipped_overlap");
    assert_eq!(skipped[0]["trigger"], "scheduled");
    assert_eq!(e.tools.scraped().len(), 0, "nothing was scraped");
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(v["data"]["nextRunAt"], "2025-06-01T13:00:00.000Z");
    assert_eq!(v["data"]["currentCheckId"], running.id.to_string());

    // a manual run is refused while it runs
    let (s, v) = e.post(&format!("{BASE}/monitor/{id}/run"), &json!({})).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["code"], "invalid_state");

    // an hour later the running check is dead: it is failed and a new check runs
    e.clock.advance_ms(60 * 60_000);
    let fresh = e.run_check(&id).await;
    assert_eq!(fresh["status"], "completed");
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks/{}", running.id)).await;
    assert_eq!(v["data"]["status"], "failed");
    assert!(v["data"]["error"].as_str().unwrap().contains("abandoned"));
}

#[tokio::test]
async fn retention_hides_expired_checks_and_the_sweep_deletes_them() {
    let e = env();
    let url = "https://blog.test/";
    e.tools.set_markdown(url, "hello");
    let mut body = scrape_monitor(&[url]);
    body["retentionDays"] = json!(2);
    let id = e.create(&body).await["id"].as_str().unwrap().to_owned();
    let c1 = e.run_check(&id).await;
    let check_id: Uuid = c1["id"].as_str().unwrap().parse().unwrap();
    let monitor_id: Uuid = id.parse().unwrap();
    let stored = e
        .state
        .repos
        .intel
        .check_get(e.tenant, monitor_id, check_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.expires_at, stored.started_at + chrono::Duration::days(2));

    // the default retention is 30 days
    let other = e.create(&scrape_monitor(&[url])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    e.run_check(&other).await;
    let (_, v) = e.get(&format!("{BASE}/monitor/{other}/checks")).await;
    let other_check: Uuid = v["data"][0]["id"].as_str().unwrap().parse().unwrap();
    let kept = e
        .state
        .repos
        .intel
        .check_get(e.tenant, other.parse().unwrap(), other_check)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(kept.expires_at, kept.started_at + chrono::Duration::days(30));

    e.clock.advance_ms(24 * 3_600_000); // one day: still there
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks")).await;
    assert_eq!(v["data"].as_array().unwrap().len(), 1);

    e.clock.advance_ms(2 * 24 * 3_600_000); // three days: expired
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks")).await;
    assert_eq!(v["data"], json!([]));
    let (s, _) = e.get(&format!("{BASE}/monitor/{id}/checks/{check_id}")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(v["data"]["lastCheckSummary"], Value::Null);
    // the row is still stored until the sweep runs
    assert!(e
        .state
        .repos
        .intel
        .check_get(e.tenant, monitor_id, check_id)
        .await
        .unwrap()
        .is_some());
    let report = e
        .state
        .repos
        .intel
        .purge_expired(e.clock.now(), chrono::DateTime::UNIX_EPOCH)
        .await
        .unwrap();
    assert_eq!(report.checks, 1);
    assert!(e
        .state
        .repos
        .intel
        .check_get(e.tenant, monitor_id, check_id)
        .await
        .unwrap()
        .is_none());
    assert!(e
        .state
        .repos
        .intel
        .check_get(e.tenant, other.parse().unwrap(), other_check)
        .await
        .unwrap()
        .is_some());
    // the monitor itself is not retention-bound
    let (s, _) = e.get(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn deleting_a_monitor_removes_checks_pages_and_baselines() {
    let e = env();
    let url = "https://blog.test/";
    e.tools.set_markdown(url, "hello");
    let id = e.create(&scrape_monitor(&[url])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let c = e.run_check(&id).await;
    let monitor_id: Uuid = id.parse().unwrap();
    let check_id: Uuid = c["id"].as_str().unwrap().parse().unwrap();
    let repo = &e.state.repos.intel;
    assert_eq!(repo.baselines(monitor_id).await.unwrap().len(), 1);
    let baseline = &repo.baselines(monitor_id).await.unwrap()[0];
    assert_eq!(baseline.markdown, "hello");
    assert_eq!(baseline.digest, blake3::hash(b"hello").to_hex().to_string());
    assert_eq!(repo.check_pages(check_id, None, 10, 0).await.unwrap().len(), 1);
    let (s, _) = e.delete(&format!("{BASE}/monitor/{id}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(repo.baselines(monitor_id).await.unwrap().is_empty());
    assert!(repo
        .check_get(e.tenant, monitor_id, check_id)
        .await
        .unwrap()
        .is_none());
    assert!(repo.check_pages(check_id, None, 10, 0).await.unwrap().is_empty());
}

#[tokio::test]
async fn unknown_monitor_and_check_ids_are_not_found() {
    let e = env();
    let id = e.create(&scrape_monitor(&["https://blog.test/"])).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (_, v) = e.get(&format!("{BASE}/monitor/{id}/checks")).await;
    assert_eq!(v["data"], json!([]), "nothing ran yet");
    let unknown = Uuid::now_v7().to_string();
    for bad in ["not-a-uuid", unknown.as_str()] {
        let (s, _) = e.get(&format!("{BASE}/monitor/{id}/checks/{bad}")).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }
    let (s, _) = e.get(&format!("{BASE}/monitor/not-a-uuid")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn openapi_lists_the_monitor_operations() {
    let listed = crawlx_api::openapi::operations();
    for (method, path) in [
        ("post", "/compat/v2/monitor"),
        ("get", "/compat/v2/monitor"),
        ("get", "/compat/v2/monitor/{monitorId}"),
        ("patch", "/compat/v2/monitor/{monitorId}"),
        ("delete", "/compat/v2/monitor/{monitorId}"),
        ("post", "/compat/v2/monitor/{monitorId}/run"),
        ("get", "/compat/v2/monitor/{monitorId}/checks"),
        ("get", "/compat/v2/monitor/{monitorId}/checks/{checkId}"),
    ] {
        assert!(listed.contains(&(method, path)), "{method} {path}");
    }
}
