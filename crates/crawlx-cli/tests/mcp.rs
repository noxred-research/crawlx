//! `crawlx mcp` end to end: the real binary on stdio pipes against a wiremock stand-in for
//! the crawlx API's compatibility API (v2).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{json, Value};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::task::JoinHandle;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const FACADE: &str = "/compat/v2";
const TOOL_SCRAPE: &str = "firecrawl_scrape"; // wire-compat: MCP tool name
const TOOL_MAP: &str = "firecrawl_map"; // wire-compat: MCP tool name
const TOOL_SEARCH: &str = "firecrawl_search"; // wire-compat: MCP tool name
const TOOL_CRAWL: &str = "firecrawl_crawl"; // wire-compat: MCP tool name
const TOOL_CRAWL_STATUS: &str = "firecrawl_check_crawl_status"; // wire-compat: MCP tool name
const TOOL_EXTRACT: &str = "firecrawl_extract"; // wire-compat: MCP tool name
const TOOL_EXTRACT_STATUS: &str = "firecrawl_extract_status"; // wire-compat: MCP tool name
const TOOL_PARSE: &str = "firecrawl_parse"; // wire-compat: MCP tool name
const TOOL_AGENT: &str = "firecrawl_agent"; // wire-compat: MCP tool name
const TOOL_AGENT_STATUS: &str = "firecrawl_agent_status"; // wire-compat: MCP tool name
const WAIT: Duration = Duration::from_secs(30);

/// One `crawlx mcp` process with its pipes.
struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    stderr: JoinHandle<String>,
    next_id: i64,
}

impl Session {
    /// Spawn against `api_url` with the given extra flags and environment. The inherited
    /// `CRAWLX_*`/drop-in client/proxy variables are cleared so the run is hermetic.
    async fn spawn(args: &[&str], env: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_crawlx"));
        command.arg("mcp").args(args);
        for name in [
            "CRAWLX_API_URL",
            "CRAWLX_API_KEY",
            "FIRECRAWL_API_URL", // wire-compat: variable set by drop-in MCP client configs
            "FIRECRAWL_API_KEY", // wire-compat: variable set by drop-in MCP client configs
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
        ] {
            command.env_remove(name);
        }
        command.env("NO_PROXY", "127.0.0.1,localhost");
        for (name, value) in env {
            command.env(name, value);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut stderr_pipe = child.stderr.take().unwrap();
        let stderr = tokio::spawn(async move {
            let mut text = String::new();
            stderr_pipe.read_to_string(&mut text).await.unwrap();
            text
        });
        Self {
            child,
            stdin,
            stdout,
            stderr,
            next_id: 0,
        }
    }

    /// Spawn with `--api-url` and `--api-key test-key`, poll interval 10 ms.
    async fn start(api_url: &str) -> Self {
        Self::spawn(
            &[
                "--api-url",
                api_url,
                "--api-key",
                "test-key",
                "--poll-interval-ms",
                "10",
            ],
            &[],
        )
        .await
    }

    async fn send_line(&mut self, line: &str) {
        let stdin = self.stdin.as_mut().unwrap();
        stdin.write_all(line.as_bytes()).await.unwrap();
        stdin.write_all(b"\n").await.unwrap();
        stdin.flush().await.unwrap();
    }

    async fn send(&mut self, message: &Value) {
        self.send_line(&message.to_string()).await;
    }

    /// The next stdout line, which must be a JSON value: nothing else may reach stdout.
    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        let read = tokio::time::timeout(WAIT, self.stdout.read_line(&mut line))
            .await
            .expect("timed out waiting for a frame")
            .unwrap();
        assert!(read > 0, "stdout closed while a frame was expected");
        assert!(line.ends_with('\n'), "frame without newline: {line:?}");
        serde_json::from_str(line.trim_end())
            .unwrap_or_else(|error| panic!("stdout line is not JSON ({error}): {line:?}"))
    }

    /// Send a request and return its reply (which must carry the same id).
    async fn request(&mut self, rpc_method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": rpc_method, "params": params}))
            .await;
        let reply = self.recv().await;
        assert_eq!(reply["id"], json!(id), "{reply}");
        assert_eq!(reply["jsonrpc"], json!("2.0"), "{reply}");
        reply
    }

    async fn initialize(&mut self) -> Value {
        let reply = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                }),
            )
            .await;
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        reply
    }

    /// `tools/call`, returning the whole JSON-RPC reply.
    async fn call_raw(&mut self, tool: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name": tool, "arguments": arguments}))
            .await
    }

    /// `tools/call` that must succeed at protocol level; returns the tool result.
    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let reply = self.call_raw(tool, arguments).await;
        assert!(reply.get("error").is_none(), "protocol error: {reply}");
        reply["result"].clone()
    }

    /// Close stdin and wait for the process; returns its exit status and stderr.
    async fn finish(mut self) -> (ExitStatus, String) {
        drop(self.stdin.take());
        let status = tokio::time::timeout(WAIT, self.child.wait())
            .await
            .expect("the server did not exit after stdin closed")
            .unwrap();
        let mut rest = String::new();
        self.stdout.read_to_string(&mut rest).await.unwrap();
        assert!(
            rest.is_empty(),
            "unexpected output after the last reply: {rest:?}"
        );
        (status, self.stderr.await.unwrap())
    }
}

fn text_of(result: &Value) -> &str {
    assert_eq!(result["content"].as_array().unwrap().len(), 1, "{result}");
    assert_eq!(result["content"][0]["type"], json!("text"), "{result}");
    result["content"][0]["text"].as_str().unwrap()
}

/// The JSON a successful tool result carries.
fn json_of(result: &Value) -> Value {
    assert_eq!(result["isError"], json!(false), "{result}");
    serde_json::from_str(text_of(result)).unwrap()
}

fn facade(endpoint: &str) -> String {
    format!("{FACADE}/{endpoint}")
}

async fn ok_json(server: &MockServer, rpc_method: &str, endpoint: &str, body: Value) {
    Mock::given(method(rpc_method))
        .and(path(facade(endpoint)))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn initialize_downgrades_to_the_client_revision_or_the_latest() {
    let server = MockServer::start().await;
    let mut mcp = Session::start(&server.uri()).await;
    for (asked, answered) in [
        ("2024-11-05", "2024-11-05"),
        ("2025-03-26", "2025-03-26"),
        ("2099-01-01", "2025-03-26"),
    ] {
        let reply = mcp
            .request(
                "initialize",
                json!({"protocolVersion": asked, "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}),
            )
            .await;
        assert_eq!(
            reply["result"]["protocolVersion"],
            json!(answered),
            "asked {asked}"
        );
    }
    let missing = mcp.request("initialize", json!({"capabilities": {}})).await;
    assert_eq!(missing["error"]["code"], json!(-32602), "{missing}");
    mcp.finish().await;
}

#[tokio::test]
async fn scrape_posts_the_compat_body_with_a_bearer_token_and_returns_the_data() {
    let server = MockServer::start().await;
    let document = json!({"markdown": "# Hello", "metadata": {"title": "Hello", "statusCode": 200}});
    Mock::given(method("POST"))
        .and(path(facade("scrape")))
        .and(header("authorization", "Bearer test-key"))
        .and(body_json(json!({
            "url": "https://example.com/a",
            "formats": ["markdown", {"type": "json", "prompt": "name", "schema": {"type": "object"}}],
            "onlyMainContent": true,
            "waitFor": 250,
            "location": {"country": "DE"},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "data": document})))
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let result = mcp
        .call(
            TOOL_SCRAPE,
            json!({
                "url": "https://example.com/a",
                "formats": ["markdown", "json"],
                "jsonOptions": {"prompt": "name", "schema": {"type": "object"}},
                "onlyMainContent": true,
                "waitFor": 250,
                "location": {"country": "DE"},
                // tolerated like upstream: dropped, never forwarded
                "unknownOption": 1,
                "includeTags": [],
                "excludeTags": null,
                "mobile": null,
            }),
        )
        .await;
    assert_eq!(json_of(&result), document);
    // the text is pretty-printed JSON of `data`
    assert!(
        text_of(&result).contains("\n  \"markdown\": \"# Hello\""),
        "{result}"
    );
    mcp.finish().await;
}

#[tokio::test]
async fn search_returns_the_result_groups() {
    let server = MockServer::start().await;
    let data = json!({"web": [{"url": "https://example.com", "title": "Example", "description": "d", "position": 1}]});
    Mock::given(method("POST"))
        .and(path(facade("search")))
        .and(body_json(json!({
            "query": "rust mcp",
            "limit": 3,
            "sources": ["web", "news"],
            "categories": ["pdf"],
            "tbs": "qdr:w",
            "location": "Berlin",
            "scrapeOptions": {"formats": ["markdown"], "onlyMainContent": true},
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": true, "data": data, "id": "s1", "creditsUsed": 2})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let result = mcp
        .call(
            TOOL_SEARCH,
            json!({
                "query": "rust mcp",
                "limit": 3,
                "sources": ["web", "news"],
                "categories": ["pdf"],
                "tbs": "qdr:w",
                "location": "Berlin",
                "scrapeOptions": {"formats": ["markdown"], "onlyMainContent": true},
            }),
        )
        .await;
    assert_eq!(json_of(&result), data);
    mcp.finish().await;
}

#[tokio::test]
async fn map_returns_the_links() {
    let server = MockServer::start().await;
    let links = json!([{"url": "https://example.com/a"}, {"url": "https://example.com/b", "title": "B"}]);
    Mock::given(method("POST"))
        .and(path(facade("map")))
        .and(body_json(
            json!({"url": "https://example.com", "search": "docs", "limit": 10, "sitemap": "only"}),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "links": links})))
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let result = mcp
        .call(
            TOOL_MAP,
            json!({"url": "https://example.com", "search": "docs", "limit": 10, "sitemap": "only"}),
        )
        .await;
    assert_eq!(json_of(&result), json!({"links": links}));
    mcp.finish().await;
}

#[tokio::test]
async fn crawl_returns_the_id_and_the_status_tool_reads_it() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("crawl")))
        .and(header("authorization", "Bearer test-key"))
        .and(body_json(json!({
            "url": "https://example.com/blog/*",
            "limit": 5,
            "maxDiscoveryDepth": 2,
            "includePaths": ["blog/.*"],
            "webhook": {"url": "https://hooks.example.com/x", "headers": {"X-Token": "t"}},
            "scrapeOptions": {"formats": [{"type": "json", "prompt": "title"}]},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "id": "crawl-1",
            "url": "http://api/compat/v2/crawl/crawl-1",
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(facade("crawl/crawl-1")))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "status": "completed",
            "total": 1,
            "completed": 1,
            "creditsUsed": 1,
            "expiresAt": "2030-01-01T00:00:00Z",
            "data": [{"markdown": "# page", "metadata": {"sourceURL": "https://example.com/blog/a"}}],
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let started = mcp
        .call(
            TOOL_CRAWL,
            json!({
                "url": "https://example.com/blog/*",
                "limit": 5,
                "maxDiscoveryDepth": 2,
                "includePaths": ["blog/.*"],
                "webhook": "https://hooks.example.com/x",
                "webhookHeaders": {"X-Token": "t"},
                "scrapeOptions": {"formats": ["json"], "jsonOptions": {"prompt": "title"}},
            }),
        )
        .await;
    let started = json_of(&started);
    assert_eq!(started["id"], json!("crawl-1"));
    let status = mcp.call(TOOL_CRAWL_STATUS, json!({"id": started["id"]})).await;
    let status = json_of(&status);
    assert_eq!(status["status"], json!("completed"));
    assert_eq!(status["completed"], json!(1));
    assert_eq!(status["data"][0]["markdown"], json!("# page"));
    assert!(status.get("success").is_none(), "{status}");
    mcp.finish().await;
}

#[tokio::test]
async fn crawl_order_defaults_to_breadth_first_through_real_mcp_api() {
    use crawlx_api::auth::{generate_key, key_record_for, tenant_id_for};
    use crawlx_api::{ApiConfig, AppState, Repos, Scope};
    use crawlx_core::repo::RunRepo as _;
    use crawlx_core::{Clock, CrawlRunId, SystemClock};
    use crawlx_policy::AdmissionPolicy;
    use crawlx_storage::{MemoryArtifactStore, MemoryStore};
    use std::sync::Arc;

    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let store = Arc::new(MemoryStore::new());
    let artifacts = Arc::new(MemoryArtifactStore::in_memory(store.clone(), clock.clone()));
    let (repos, api) = Repos::memory_with_api(store.clone(), artifacts);
    let state = AppState::builder(
        repos,
        AdmissionPolicy::new(clock.clone()),
        ApiConfig {
            rate_limit_per_minute: 0,
            ..ApiConfig::default()
        },
    )
    .clock(clock)
    .build();
    let key = generate_key();
    let record = key_record_for(&key, tenant_id_for("mcp-order"), Scope::all_set(), false).unwrap();
    crawlx_api::ApiStore::key_insert(api.as_ref(), &record, "mcp-order")
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
        axum::serve(listener, crawlx_api::router(state)).await.unwrap();
    }));
    let mut mcp = Session::spawn(&["--api-url", &api_url, "--api-key", &key], &[]).await;
    mcp.initialize().await;
    let result = mcp.call(TOOL_CRAWL, json!({"url":"https://example.test/"})).await;
    let body = json_of(&result);
    let id: CrawlRunId = body["id"].as_str().expect("crawl accepted").parse().unwrap();
    let run = store.get(id).await.unwrap();
    assert_eq!(
        run.config.scope.strategy,
        crawlx_core::config::CrawlStrategy::BreadthFirst
    );
    mcp.finish().await;
    drop(server);
}

#[tokio::test]
async fn crawl_status_path_encodes_the_id() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(facade("crawl/a%2Fb%20c")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"success": true, "status": "scraping"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let result = mcp.call(TOOL_CRAWL_STATUS, json!({"id": "a/b c"})).await;
    assert_eq!(json_of(&result)["status"], json!("scraping"));
    mcp.finish().await;
}

#[tokio::test]
async fn extract_polls_until_the_job_completes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("extract")))
        .and(body_json(json!({
            "urls": ["https://example.com/*"],
            "prompt": "company name",
            "schema": {"type": "object", "properties": {"name": {"type": "string"}}},
            "enableWebSearch": true,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "id": "job-1"})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(facade("extract/job-1")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": true, "status": "processing", "data": {}})),
        )
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(facade("extract/job-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "status": "completed",
            "data": {"name": "Example Corp"},
            "expiresAt": "2030-01-01T00:00:00Z",
            "tokensUsed": 42,
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let result = mcp
        .call(
            TOOL_EXTRACT,
            json!({
                "urls": ["https://example.com/*"],
                "prompt": "company name",
                "schema": {"type": "object", "properties": {"name": {"type": "string"}}},
                "enableWebSearch": true,
            }),
        )
        .await;
    let done = json_of(&result);
    assert_eq!(done["status"], json!("completed"));
    assert_eq!(done["data"], json!({"name": "Example Corp"}));
    assert_eq!(done["tokensUsed"], json!(42));
    mcp.finish().await;
}

#[tokio::test]
async fn extract_without_wait_returns_the_id_and_status_reads_the_job() {
    let server = MockServer::start().await;
    ok_json(
        &server,
        "POST",
        "extract",
        json!({"success": true, "id": "job-2", "invalidURLs": []}),
    )
    .await;
    Mock::given(method("GET"))
        .and(path(facade("extract/job-2")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"success": true, "status": "processing"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let started = mcp
        .call(
            TOOL_EXTRACT,
            json!({"urls": ["https://example.com"], "prompt": "x", "wait": false}),
        )
        .await;
    let started = json_of(&started);
    assert_eq!(started["id"], json!("job-2"));
    // `wait` is a client-side flag: it is never forwarded
    let requests = server.received_requests().await.unwrap();
    let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert!(body.get("wait").is_none(), "{body}");
    let status = mcp.call(TOOL_EXTRACT_STATUS, json!({"id": "job-2"})).await;
    assert_eq!(json_of(&status)["status"], json!("processing"));
    mcp.finish().await;
}

#[tokio::test]
async fn extract_job_that_fails_is_an_error_result_with_the_final_body() {
    let server = MockServer::start().await;
    ok_json(
        &server,
        "POST",
        "extract",
        json!({"success": true, "id": "job-3"}),
    )
    .await;
    ok_json(
        &server,
        "GET",
        "extract/job-3",
        json!({"success": true, "status": "failed", "error": "no extractable content"}),
    )
    .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let result = mcp
        .call(
            TOOL_EXTRACT,
            json!({"urls": ["https://example.com"], "prompt": "x"}),
        )
        .await;
    assert_eq!(result["isError"], json!(true), "{result}");
    let text = text_of(&result);
    assert!(
        text.contains("failed") && text.contains("no extractable content"),
        "{text}"
    );
    mcp.finish().await;
}

#[tokio::test]
async fn extract_that_outlives_the_poll_budget_reports_the_id() {
    let server = MockServer::start().await;
    ok_json(
        &server,
        "POST",
        "extract",
        json!({"success": true, "id": "job-4"}),
    )
    .await;
    ok_json(
        &server,
        "GET",
        "extract/job-4",
        json!({"success": true, "status": "processing"}),
    )
    .await;
    let mut mcp = Session::spawn(
        &[
            "--api-url",
            &server.uri(),
            "--poll-interval-ms",
            "10",
            "--poll-timeout-ms",
            "50",
        ],
        &[],
    )
    .await;
    mcp.initialize().await;
    let result = mcp
        .call(TOOL_EXTRACT, json!({"urls": ["https://example.com"]}))
        .await;
    let pending = json_of(&result);
    assert_eq!(pending["id"], json!("job-4"));
    assert_eq!(pending["status"], json!("processing"));
    assert!(
        pending["note"].as_str().unwrap().contains("extract status tool"),
        "{pending}"
    );
    mcp.finish().await;
}

#[tokio::test]
async fn agent_returns_the_job_id_and_status_reads_it_and_wait_polls() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("agent")))
        .and(body_json(json!({
            "prompt": "find the founders",
            "urls": ["https://example.com"],
            "effort": "low",
            "maxCredits": 100,
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "id": "agent-1",
            "threadId": "6f1c2d9e-2c1d-4f8a-9d3e-3f1d2c4b5a69",
            "threadTurn": 1,
        })))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(facade("agent/agent-1")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "status": "completed",
            "data": {"founders": ["A", "B"]},
        })))
        .expect(2)
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let arguments = json!({
        "prompt": "find the founders",
        "urls": ["https://example.com"],
        "effort": "low",
        "maxCredits": 100,
    });
    let started = json_of(&mcp.call(TOOL_AGENT, arguments.clone()).await);
    assert_eq!(started["id"], json!("agent-1"));
    assert_eq!(started["threadId"], json!("6f1c2d9e-2c1d-4f8a-9d3e-3f1d2c4b5a69"));
    let status = json_of(&mcp.call(TOOL_AGENT_STATUS, json!({"id": "agent-1"})).await);
    assert_eq!(status["status"], json!("completed"));
    assert_eq!(status["data"]["founders"], json!(["A", "B"]));

    let mut waited = arguments;
    waited["wait"] = json!(true);
    let waited = json_of(&mcp.call(TOOL_AGENT, waited).await);
    assert_eq!(waited["data"]["founders"], json!(["A", "B"]));
    mcp.finish().await;
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[tokio::test]
async fn parse_uploads_the_file_as_multipart() {
    let server = MockServer::start().await;
    let data = json!({"markdown": "parsed text", "metadata": {"title": "Sample"}});
    Mock::given(method("POST"))
        .and(path(facade("parse")))
        .and(header("authorization", "Bearer test-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "data": data})))
        .expect(2)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("sample.pdf");
    let bytes: Vec<u8> = b"%PDF-1.4\n\x00\x01\x02 binary \xff\xfe payload\n%%EOF".to_vec();
    std::fs::write(&file, &bytes).unwrap();

    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let by_path = mcp
        .call(
            TOOL_PARSE,
            json!({"filePath": file.to_str().unwrap(), "formats": ["markdown"], "onlyMainContent": true}),
        )
        .await;
    assert_eq!(json_of(&by_path), data);
    // the alias `path` and inline base64 take the same route
    use base64::Engine as _;
    let inline = mcp
        .call(
            TOOL_PARSE,
            json!({
                "contentBase64": base64::engine::general_purpose::STANDARD.encode(&bytes),
                "filename": "inline.pdf",
            }),
        )
        .await;
    assert_eq!(json_of(&inline), data);

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let first = &requests[0];
    let content_type = first.headers.get("content-type").unwrap().to_str().unwrap();
    assert!(
        content_type.starts_with("multipart/form-data; boundary="),
        "{content_type}"
    );
    assert!(
        contains(&first.body, &bytes),
        "file bytes missing from the multipart body"
    );
    assert!(contains(&first.body, b"name=\"file\""));
    assert!(contains(&first.body, b"filename=\"sample.pdf\""));
    assert!(contains(&first.body, b"Content-Type: application/pdf"));
    assert!(contains(&first.body, b"name=\"options\""));
    assert!(contains(
        &first.body,
        br#"{"formats":["markdown"],"onlyMainContent":true}"#
    ));
    let second = &requests[1];
    assert!(contains(&second.body, &bytes));
    assert!(contains(&second.body, b"filename=\"inline.pdf\""));
    assert!(
        !contains(&second.body, b"name=\"options\""),
        "no options were given"
    );
    mcp.finish().await;
}

#[tokio::test]
async fn parse_reports_unreadable_files_and_bad_combinations() {
    let server = MockServer::start().await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let missing = mcp
        .call(TOOL_PARSE, json!({"filePath": "/nonexistent/dir/missing.pdf"}))
        .await;
    assert_eq!(missing["isError"], json!(true), "{missing}");
    assert!(
        text_of(&missing).contains("cannot read /nonexistent/dir/missing.pdf"),
        "{missing}"
    );
    for (arguments, fragment) in [
        (json!({}), "exactly one of filePath"),
        (
            json!({"filePath": "/a.pdf", "contentBase64": "AAAA", "filename": "a.pdf"}),
            "exactly one of filePath",
        ),
        (json!({"contentBase64": "AAAA"}), "contentBase64 needs filename"),
        (
            json!({"contentBase64": "***", "filename": "a.pdf"}),
            "not valid base64",
        ),
        (
            json!({"filePath": "/a.pdf", "jsonOptions": {"prompt": "x"}}),
            "jsonOptions needs formats",
        ),
    ] {
        let reply = mcp.call_raw(TOOL_PARSE, arguments.clone()).await;
        assert_eq!(reply["error"]["code"], json!(-32602), "{arguments}: {reply}");
        assert!(
            reply["error"]["message"].as_str().unwrap().contains(fragment),
            "{arguments}: {reply}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    mcp.finish().await;
}

#[tokio::test]
async fn unknown_tool_and_bad_arguments_are_invalid_params_and_the_server_keeps_serving() {
    let server = MockServer::start().await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;

    let unknown = mcp.call_raw("no_such_tool", json!({})).await;
    assert_eq!(unknown["error"]["code"], json!(-32602), "{unknown}");
    assert!(unknown["error"]["message"]
        .as_str()
        .unwrap()
        .contains("unknown tool: no_such_tool"));

    let cases = [
        (TOOL_SCRAPE, json!({}), "arguments.url is required"),
        (TOOL_SCRAPE, json!({"url": 5}), "arguments.url must be a string"),
        (
            TOOL_SCRAPE,
            json!({"url": "ftp://example.com"}),
            "arguments.url must be an absolute http(s) URL",
        ),
        (
            TOOL_SCRAPE,
            json!({"url": "https://e.com", "formats": ["pdf"]}),
            "arguments.formats[0] must be one of",
        ),
        (
            TOOL_SCRAPE,
            json!({"url": "https://e.com", "waitFor": 1.5}),
            "arguments.waitFor must be an integer",
        ),
        (
            TOOL_SCRAPE,
            json!({"url": "https://e.com", "waitFor": -1}),
            "arguments.waitFor must be at least 0",
        ),
        (
            TOOL_SCRAPE,
            json!({"url": "https://e.com", "jsonOptions": {"prompt": "x"}}),
            "jsonOptions needs formats to include \"json\"",
        ),
        (
            TOOL_SEARCH,
            json!({"query": ""}),
            "arguments.query must be at least 1 character(s) long",
        ),
        (
            TOOL_SEARCH,
            json!({"query": "q", "limit": 500}),
            "arguments.limit must be at most 100",
        ),
        (
            TOOL_SEARCH,
            json!({"query": "q", "includeDomains": ["a.com"], "excludeDomains": ["b.com"]}),
            "cannot both be set",
        ),
        (
            TOOL_SEARCH,
            json!({"query": "q", "categories": ["gov", "pdf"]}),
            "cannot be combined",
        ),
        (
            TOOL_EXTRACT,
            json!({"urls": []}),
            "arguments.urls must have at least 1 item",
        ),
        (TOOL_CRAWL_STATUS, json!({}), "arguments.id is required"),
        (
            TOOL_AGENT,
            json!({"prompt": "p", "threadId": "not-a-uuid"}),
            "arguments.threadId must be a UUID",
        ),
        (
            TOOL_AGENT,
            json!({"prompt": "p", "effort": "extreme"}),
            "arguments.effort must be one of",
        ),
    ];
    for (tool, arguments, fragment) in cases {
        let reply = mcp.call_raw(tool, arguments.clone()).await;
        assert_eq!(
            reply["error"]["code"],
            json!(-32602),
            "{tool} {arguments}: {reply}"
        );
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(message.contains(fragment), "{tool} {arguments}: {message}");
        assert!(reply["error"]["data"]["issues"].is_array(), "{reply}");
    }
    // `arguments` must be an object and `name` a string
    let wrong = mcp
        .request("tools/call", json!({"name": TOOL_MAP, "arguments": [1]}))
        .await;
    assert_eq!(wrong["error"]["code"], json!(-32602), "{wrong}");
    let nameless = mcp.request("tools/call", json!({"arguments": {}})).await;
    assert_eq!(nameless["error"]["code"], json!(-32602), "{nameless}");

    // several problems are reported together
    let many = mcp
        .call_raw(
            TOOL_SCRAPE,
            json!({"url": 1, "formats": "markdown", "waitFor": "slow"}),
        )
        .await;
    assert_eq!(
        many["error"]["data"]["issues"].as_array().unwrap().len(),
        3,
        "{many}"
    );

    // no request reached the API, and the server still answers
    assert!(server.received_requests().await.unwrap().is_empty());
    let pong = mcp.request("ping", json!({})).await;
    assert_eq!(pong["result"], json!({}));
    mcp.finish().await;
}

#[tokio::test]
async fn api_failures_become_is_error_results_carrying_the_compat_error_text() {
    let server = MockServer::start().await;
    for (endpoint, response) in [
        (
            "scrape",
            ResponseTemplate::new(422).set_body_json(json!({
                "success": false,
                "error": "Invalid URL: scheme not allowed",
                "code": "BAD_REQUEST",
                "details": [{"path": ["url"], "message": "bad"}],
                "requestId": "req-9",
            })),
        ),
        (
            "map",
            ResponseTemplate::new(500)
                .set_body_json(json!({"error": "An unexpected error occurred on the server."})),
        ),
        (
            "search",
            ResponseTemplate::new(402)
                .set_body_json(json!({"error": "Payment required to access this resource."})),
        ),
        (
            "crawl",
            ResponseTemplate::new(502).set_body_string("<html>Bad Gateway</html>"),
        ),
        (
            "extract",
            ResponseTemplate::new(200)
                .set_body_json(json!({"success": false, "error": "extraction is not configured"})),
        ),
        (
            "agent",
            ResponseTemplate::new(503).set_body_json(
                json!({"success": false, "error": "no llm backend", "code": "LLM_UNAVAILABLE"}),
            ),
        ),
    ] {
        Mock::given(method("POST"))
            .and(path(facade(endpoint)))
            .respond_with(response)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path(facade("crawl/gone")))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"success": false, "error": "Job not found", "code": "NOT_FOUND"})),
        )
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let cases = [
        (
            TOOL_SCRAPE,
            json!({"url": "https://example.com"}),
            vec!["422", "Invalid URL: scheme not allowed", "BAD_REQUEST", "req-9"],
        ),
        (
            TOOL_MAP,
            json!({"url": "https://example.com"}),
            vec!["500", "An unexpected error occurred on the server."],
        ),
        (
            TOOL_SEARCH,
            json!({"query": "q"}),
            vec!["402", "Payment required to access this resource."],
        ),
        (
            TOOL_CRAWL,
            json!({"url": "https://example.com"}),
            vec!["502", "Bad Gateway"],
        ),
        (
            TOOL_EXTRACT,
            json!({"urls": ["https://example.com"]}),
            vec!["extraction is not configured"],
        ),
        (
            TOOL_AGENT,
            json!({"prompt": "p"}),
            vec!["503", "no llm backend", "LLM_UNAVAILABLE"],
        ),
        (
            TOOL_CRAWL_STATUS,
            json!({"id": "gone"}),
            vec!["404", "Job not found", "NOT_FOUND"],
        ),
    ];
    for (tool, arguments, fragments) in cases {
        let reply = mcp.call_raw(tool, arguments).await;
        assert!(reply.get("error").is_none(), "{tool}: protocol error {reply}");
        let result = &reply["result"];
        assert_eq!(result["isError"], json!(true), "{tool}: {result}");
        let text = text_of(result);
        for fragment in fragments {
            assert!(
                text.contains(fragment),
                "{tool}: {fragment:?} missing from {text:?}"
            );
        }
    }
    let pong = mcp.request("ping", json!({})).await;
    assert_eq!(pong["result"], json!({}));
    mcp.finish().await;
}

#[tokio::test]
async fn an_unreachable_api_is_an_is_error_result() {
    // nothing listens on port 9 (discard) on loopback in the test environment
    let mut mcp = Session::spawn(&["--api-url", "http://127.0.0.1:9", "--timeout-ms", "5000"], &[]).await;
    mcp.initialize().await;
    let result = mcp.call(TOOL_SCRAPE, json!({"url": "https://example.com"})).await;
    assert_eq!(result["isError"], json!(true), "{result}");
    assert!(text_of(&result).contains("/compat/v2/scrape"), "{result}");
    mcp.finish().await;
}

#[tokio::test]
async fn a_slow_api_hits_the_per_call_timeout() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("scrape")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(5))
                .set_body_json(json!({"success": true, "data": {}})),
        )
        .mount(&server)
        .await;
    let mut mcp = Session::spawn(&["--api-url", &server.uri(), "--timeout-ms", "300"], &[]).await;
    mcp.initialize().await;
    let started = std::time::Instant::now();
    let result = mcp.call(TOOL_SCRAPE, json!({"url": "https://example.com"})).await;
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "the call outlived its timeout"
    );
    assert_eq!(result["isError"], json!(true), "{result}");
    assert!(text_of(&result).contains("timed out after 300 ms"), "{result}");
    mcp.finish().await;
}

#[tokio::test]
async fn oversized_results_are_cut_at_one_mebibyte_with_a_marker() {
    let server = MockServer::start().await;
    ok_json(
        &server,
        "POST",
        "scrape",
        json!({"success": true, "data": {"markdown": "a".repeat(1_600_000)}}),
    )
    .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    let result = mcp.call(TOOL_SCRAPE, json!({"url": "https://example.com"})).await;
    assert_eq!(result["isError"], json!(false));
    let text = text_of(&result);
    assert!(
        text.contains("[output truncated: 1048576 of "),
        "{}",
        &text[text.len() - 120..]
    );
    assert!(text.len() < 1_048_576 + 128, "{}", text.len());
    assert!(text.starts_with("{\n  \"markdown\": \"aaaa"));
    mcp.finish().await;
}

#[tokio::test]
async fn malformed_lines_get_the_right_json_rpc_error_and_the_server_keeps_serving() {
    let server = MockServer::start().await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;

    mcp.send_line("{this is not json").await;
    let parse = mcp.recv().await;
    assert_eq!(parse["id"], Value::Null);
    assert_eq!(parse["error"]["code"], json!(-32700), "{parse}");

    mcp.send_line("").await; // blank lines are ignored
    mcp.send_line("42").await;
    let not_object = mcp.recv().await;
    assert_eq!(not_object["error"]["code"], json!(-32600), "{not_object}");
    assert_eq!(not_object["id"], Value::Null);

    mcp.send(&json!({"jsonrpc": "1.0", "id": 7, "method": "ping"}))
        .await;
    let wrong_version = mcp.recv().await;
    assert_eq!(wrong_version["error"]["code"], json!(-32600), "{wrong_version}");
    assert_eq!(wrong_version["id"], json!(7));

    mcp.send(&json!({"jsonrpc": "2.0", "id": 8, "method": 5})).await;
    let bad_method = mcp.recv().await;
    assert_eq!(bad_method["error"]["code"], json!(-32600), "{bad_method}");
    assert_eq!(bad_method["id"], json!(8));

    mcp.send(&json!({"jsonrpc": "2.0", "id": 9, "method": "ping", "params": 3}))
        .await;
    let bad_params = mcp.recv().await;
    assert_eq!(bad_params["error"]["code"], json!(-32600), "{bad_params}");

    let missing = mcp.request("resources/list", json!({})).await;
    assert_eq!(missing["error"]["code"], json!(-32601), "{missing}");

    // string ids are echoed as strings
    mcp.send(&json!({"jsonrpc": "2.0", "id": "abc", "method": "ping"}))
        .await;
    let pong = mcp.recv().await;
    assert_eq!(pong["id"], json!("abc"));
    assert_eq!(pong["result"], json!({}));

    // notifications never get a reply, known or not
    mcp.send(&json!({"jsonrpc": "2.0", "method": "notifications/unknown"}))
        .await;
    let after = mcp.request("ping", json!({})).await;
    assert_eq!(after["result"], json!({}));

    // batches answer as a batch
    mcp.send(&json!([
        {"jsonrpc": "2.0", "id": 21, "method": "ping"},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 22, "method": "nope"},
    ]))
    .await;
    let batch = mcp.recv().await;
    let replies = batch.as_array().unwrap();
    assert_eq!(replies.len(), 2, "{batch}");
    assert_eq!(replies[0]["id"], json!(21));
    assert_eq!(replies[1]["error"]["code"], json!(-32601));
    mcp.send_line("[]").await;
    let empty = mcp.recv().await;
    assert_eq!(empty["error"]["code"], json!(-32600), "{empty}");

    let (status, _) = mcp.finish().await;
    assert!(status.success());
}

#[tokio::test]
async fn end_of_input_answers_what_was_sent_and_exits_zero() {
    let server = MockServer::start().await;
    ok_json(&server, "POST", "map", json!({"success": true, "links": []})).await;
    let mut mcp = Session::start(&server.uri()).await;
    // no reads between the writes: everything is queued, then stdin closes
    mcp.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}))
        .await;
    mcp.send(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": TOOL_MAP, "arguments": {"url": "https://example.com"}},
    }))
    .await;
    // the last line has no trailing newline
    let stdin = mcp.stdin.as_mut().unwrap();
    stdin
        .write_all(br#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#)
        .await
        .unwrap();
    drop(mcp.stdin.take());
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(mcp.recv().await["id"].as_i64().unwrap());
    }
    ids.sort_unstable();
    assert_eq!(ids, [1, 2, 3]);
    let (status, stderr) = mcp.finish().await;
    assert!(status.success(), "exit status {status:?}, stderr: {stderr}");
}

#[tokio::test]
async fn a_cancelled_request_gets_no_reply_and_does_not_hold_the_server_up() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("scrape")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(60))
                .set_body_json(json!({"success": true, "data": {}})),
        )
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    mcp.send(&json!({
        "jsonrpc": "2.0", "id": 100, "method": "tools/call",
        "params": {"name": TOOL_SCRAPE, "arguments": {"url": "https://example.com"}},
    }))
    .await;
    mcp.send(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 100, "reason": "user"}}))
        .await;
    // the next frame is the ping's reply: the cancelled call produced none
    let pong = mcp.request("ping", json!({})).await;
    assert_eq!(pong["result"], json!({}));
    let started = std::time::Instant::now();
    let (status, _) = mcp.finish().await;
    assert!(status.success());
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "exit waited for the cancelled call"
    );
}

#[tokio::test]
async fn ping_is_answered_while_a_slow_call_is_in_flight() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("scrape")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .set_body_json(json!({"success": true, "data": {"markdown": "slow"}})),
        )
        .mount(&server)
        .await;
    let mut mcp = Session::start(&server.uri()).await;
    mcp.initialize().await;
    mcp.send(&json!({
        "jsonrpc": "2.0", "id": 100, "method": "tools/call",
        "params": {"name": TOOL_SCRAPE, "arguments": {"url": "https://example.com"}},
    }))
    .await;
    mcp.send(&json!({"jsonrpc": "2.0", "id": 101, "method": "ping"}))
        .await;
    let first = mcp.recv().await;
    assert_eq!(
        first["id"],
        json!(101),
        "the ping waited behind the slow call: {first}"
    );
    let second = mcp.recv().await;
    assert_eq!(second["id"], json!(100));
    assert_eq!(json_of(&second["result"]), json!({"markdown": "slow"}));
    mcp.finish().await;
}

#[tokio::test]
async fn dropin_environment_variables_are_the_fallback_and_crawlx_ones_win() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("map")))
        .and(header("authorization", "Bearer from-dropin-env"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "links": []})))
        .expect(1)
        .mount(&server)
        .await;
    let mut mcp = Session::spawn(
        &[],
        &[
            ("FIRECRAWL_API_URL", &server.uri()), // wire-compat: variable set by drop-in MCP client configs
            ("FIRECRAWL_API_KEY", "from-dropin-env"), // wire-compat: variable set by drop-in MCP client configs
        ],
    )
    .await;
    mcp.initialize().await;
    json_of(&mcp.call(TOOL_MAP, json!({"url": "https://example.com"})).await);
    mcp.finish().await;

    let other = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(facade("map")))
        .and(header("authorization", "Bearer from-crawlx-env"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"success": true, "links": []})))
        .expect(1)
        .mount(&other)
        .await;
    let mut mcp = Session::spawn(
        &[],
        &[
            ("CRAWLX_API_URL", &other.uri()),
            ("CRAWLX_API_KEY", "from-crawlx-env"),
            ("FIRECRAWL_API_URL", "http://127.0.0.1:9"), // wire-compat: variable set by drop-in MCP client configs
            ("FIRECRAWL_API_KEY", "from-dropin-env"), // wire-compat: variable set by drop-in MCP client configs
        ],
    )
    .await;
    mcp.initialize().await;
    json_of(&mcp.call(TOOL_MAP, json!({"url": "https://example.com"})).await);
    mcp.finish().await;
}

#[tokio::test]
async fn without_a_key_no_authorization_header_is_sent() {
    let server = MockServer::start().await;
    ok_json(&server, "POST", "map", json!({"success": true, "links": []})).await;
    let mut mcp = Session::spawn(&["--api-url", &server.uri()], &[]).await;
    mcp.initialize().await;
    json_of(&mcp.call(TOOL_MAP, json!({"url": "https://example.com"})).await);
    let requests = server.received_requests().await.unwrap();
    assert!(requests[0].headers.get("authorization").is_none());
    mcp.finish().await;
}

#[tokio::test]
async fn the_api_key_never_appears_on_stdout_or_stderr() {
    let secret = "sk-very-secret-key-0123456789";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"error": "boom"})))
        .mount(&server)
        .await;
    let mut mcp = Session::spawn(
        &["--api-url", &server.uri(), "--api-key", secret, "--log", "trace"],
        &[],
    )
    .await;
    let init = mcp.initialize().await;
    assert!(!init.to_string().contains(secret));
    let failed = mcp.call(TOOL_SCRAPE, json!({"url": "https://example.com"})).await;
    assert_eq!(failed["isError"], json!(true));
    assert!(!failed.to_string().contains(secret));
    let (status, stderr) = mcp.finish().await;
    assert!(status.success());
    assert!(!stderr.contains(secret), "the key leaked into the logs: {stderr}");

    // `--help` and an environment-provided key do not echo it either
    let help = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["mcp", "--help"])
        .env("CRAWLX_API_KEY", secret)
        .output()
        .unwrap();
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(!help.contains(secret), "{help}");
    for flag in [
        "--api-url",
        "--api-key",
        "--timeout-ms",
        "--poll-interval-ms",
        "--poll-timeout-ms",
    ] {
        assert!(help.contains(flag), "`{flag}` missing from:\n{help}");
    }
}

#[tokio::test]
async fn an_invalid_api_url_fails_at_startup_without_touching_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["mcp", "--api-url", "not a url"])
        .env_remove("CRAWLX_API_URL")
        .env_remove("FIRECRAWL_API_URL") // wire-compat: variable set by drop-in MCP client configs
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "{:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("api url"),
        "{:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

// ---- audit log ----

fn crawlx_command(args: &[&str]) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx"));
    command.arg("mcp").args(args).stdin(Stdio::null());
    command
}

#[tokio::test]
async fn the_audit_log_records_calls_of_the_real_binary_and_audit_verify_checks_it() {
    let server = MockServer::start().await;
    ok_json(
        &server,
        "POST",
        "scrape",
        json!({"success": true, "data": {"markdown": "# CANARY-PAGE"}}),
    )
    .await;
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("mcp-audit.jsonl");
    let log_arg = log.to_str().unwrap();
    let mut mcp = Session::spawn(
        &[
            "--api-url",
            &server.uri(),
            "--api-key",
            "test-key",
            "--audit-log",
            log_arg,
        ],
        &[],
    )
    .await;
    mcp.initialize().await;
    mcp.call(TOOL_SCRAPE, json!({"url": "https://example.com/CANARY-URL"}))
        .await;
    // a second server on the same file must not start while the first holds it
    let second = crawlx_command(&["--api-url", &server.uri(), "--audit-log", log_arg])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("in use by another process"));
    mcp.call_raw("not_a_tool", json!({})).await;
    let (status, _) = mcp.finish().await;
    assert!(status.success());

    let text = std::fs::read_to_string(&log).unwrap();
    assert_eq!(text.lines().count(), 4, "{text}");
    for secret in ["CANARY", "test-key", "example.com"] {
        assert!(!text.contains(secret), "{secret} reached the audit log");
    }

    let verified = crawlx_command(&["audit-verify", log_arg]).output().unwrap();
    assert!(verified.status.success(), "{verified:?}");
    let stdout = String::from_utf8(verified.stdout).unwrap();
    assert!(stdout.starts_with("entries: 4\nlast_hash: "), "{stdout}");

    let mut lines: Vec<&str> = text.lines().collect();
    lines.swap(1, 2);
    std::fs::write(&log, format!("{}\n", lines.join("\n"))).unwrap();
    let broken = crawlx_command(&["audit-verify", log_arg]).output().unwrap();
    assert_eq!(broken.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&broken.stdout).contains("broken: line 2: "));
}

#[tokio::test]
async fn an_audit_log_that_cannot_be_opened_stops_the_server_from_starting() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("no-such-dir").join("audit.jsonl");
    let output = crawlx_command(&["--audit-log", log.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("audit log"));
}
