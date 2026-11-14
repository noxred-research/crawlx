//! The audit log wired into the server: every tool and resource path is recorded, nothing but
//! digests reaches the file, and a log that cannot record refuses the call.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::api::{tokio_sleep, Api, Config};
use super::audit::{self, Audit};
use super::catalog::{Capability, ENTRIES};
use super::native::Native;
use super::protocol::AUDIT_UNAVAILABLE;
use super::tools::Tool;
use super::*;
use clap::{CommandFactory as _, Parser as _};
use sha2::{Digest as _, Sha256};
use std::path::Path;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SECRET_KEY: &str = "KEY-CANARY-7731";

#[derive(clap::Parser, Debug)]
struct Wrapper {
    #[command(flatten)]
    args: McpArgs,
}

const SCRAPE_TOOL: &str = "firecrawl_scrape"; // wire-compat: MCP tool name
const MAP_TOOL: &str = "firecrawl_map"; // wire-compat: MCP tool name

fn api_for(url: &str) -> Api {
    let config = Config {
        api_url: Url::parse(url).unwrap(),
        api_key: Some(SECRET_KEY.to_owned()),
        timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(10),
        poll_timeout: Duration::from_millis(50),
    };
    Api::new(&config, tokio_sleep()).unwrap()
}

/// A sink the test reads back.
#[derive(Clone, Default)]
struct Shared(Arc<Mutex<Vec<u8>>>);

impl Write for Shared {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Shared {
    fn records(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

/// A sink that accepts `allowed` writes, then fails.
struct Flaky {
    allowed: usize,
    inner: Shared,
}

impl Write for Flaky {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.allowed == 0 {
            return Err(std::io::Error::other("disk gone"));
        }
        self.allowed -= 1;
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn memory_audit() -> (Arc<Audit>, Shared) {
    let sink = Shared::default();
    (Arc::new(Audit::in_memory(Box::new(sink.clone()))), sink)
}

fn compat_server(url: &str, audit: Arc<Audit>) -> Server {
    Server::new(api_for(url)).with_audit(Some(audit))
}

fn native_server(url: &str, capabilities: &[Capability], audit: Arc<Audit>) -> Server {
    let native = Native::new(capabilities, 1 << 20, &[]).unwrap();
    Server::build(api_for(url), Some(native), 32).with_audit(Some(audit))
}

fn tool_call(name: &str, arguments: Value) -> Option<Value> {
    Some(json!({ "name": name, "arguments": arguments }))
}

/// The intent and result records of `tool`, which must be exactly one pair.
fn pair<'a>(records: &'a [Value], tool: &str) -> (&'a Value, &'a Value) {
    let of_tool: Vec<&Value> = records
        .iter()
        .filter(|record| record["tool"] == json!(tool))
        .collect();
    assert_eq!(of_tool.len(), 2, "records of {tool}: {of_tool:?}");
    let (intent, result) = (of_tool[0], of_tool[1]);
    assert_eq!(intent["phase"], json!("intent"), "{tool}");
    assert_eq!(result["phase"], json!("result"), "{tool}");
    assert_eq!(result["intent_seq"], intent["seq"], "{tool}");
    (intent, result)
}

async fn quiet_api() -> MockServer {
    MockServer::start().await
}

#[tokio::test]
async fn every_compat_tool_goes_through_the_hook() {
    let api = quiet_api().await;
    let (audit, sink) = memory_audit();
    let server = compat_server(&api.uri(), audit);
    for tool in Tool::ALL {
        let _ = server
            .dispatch("tools/call", tool_call(tool.name(), json!({})))
            .await;
    }
    let records = sink.records();
    assert_eq!(records.len(), 2 * Tool::ALL.len());
    for tool in Tool::ALL {
        let (intent, result) = pair(&records, tool.name());
        assert_eq!(intent["capability"], json!("compat"));
        assert_eq!(result["method"], json!("tools/call"));
        assert_ne!(result["outcome"], json!("intent"));
    }
}

#[tokio::test]
async fn every_native_tool_goes_through_the_hook() {
    let api = quiet_api().await;
    let (audit, sink) = memory_audit();
    let server = native_server(&api.uri(), &Capability::ALL, audit);
    for entry in ENTRIES {
        let _ = server
            .dispatch("tools/call", tool_call(entry.name, json!({})))
            .await;
    }
    let records = sink.records();
    assert_eq!(records.len(), 2 * ENTRIES.len());
    for entry in ENTRIES {
        let (intent, result) = pair(&records, entry.name);
        assert_eq!(
            intent["capability"],
            json!(entry.capability.name()),
            "{}",
            entry.name
        );
        assert_ne!(result["outcome"], json!("refused"), "{}", entry.name);
    }
}

#[tokio::test]
async fn refused_calls_are_recorded_as_refused() {
    let api = quiet_api().await;
    let (audit, sink) = memory_audit();
    let hidden = ENTRIES
        .iter()
        .find(|entry| entry.capability == Capability::Erase)
        .unwrap();
    let server = native_server(&api.uri(), &[Capability::Inspect], audit);
    let denied = server
        .dispatch("tools/call", tool_call(hidden.name, json!({ "id": "x" })))
        .await
        .unwrap_err();
    assert_eq!(denied.code, protocol::INVALID_PARAMS);
    let unknown = server
        .dispatch("tools/call", tool_call("page_text_as_a_tool_name", json!({})))
        .await
        .unwrap_err();
    assert_eq!(unknown.code, protocol::INVALID_PARAMS);
    let records = sink.records();
    let (intent, result) = pair(&records, hidden.name);
    assert_eq!(intent["capability"], json!("erase"));
    assert_eq!(result["outcome"], json!("refused"));
    assert_eq!(result["error_code"], json!("capability_not_granted"));
    let (intent, result) = pair(&records, "unknown");
    assert_eq!(intent["capability"], json!("none"));
    assert_eq!(result["outcome"], json!("refused"));
    assert_eq!(result["error_code"], json!("unknown_tool"));
    // the name the model sent is not in the log
    assert!(!records
        .iter()
        .any(|record| record.to_string().contains("page_text")));
    assert!(api.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn resource_reads_are_recorded_and_refused_without_inspect() {
    let api = quiet_api().await;
    let run_id = "0192f3a0-7b1c-7cde-8a40-1234567890ab";
    Mock::given(method("GET"))
        .and(path_regex("^/v1/crawls/[^/]+$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "status": "running" })))
        .mount(&api)
        .await;

    let (audit, sink) = memory_audit();
    let server = native_server(&api.uri(), &[Capability::Inspect], audit);
    let params = Some(json!({ "uri": format!("crawlx://runs/{run_id}/status") }));
    server.dispatch("resources/read", params.clone()).await.unwrap();
    let records = sink.records();
    let (intent, result) = pair(&records, "resources/read");
    assert_eq!(intent["method"], json!("resources/read"));
    assert_eq!(intent["resource_ids"], json!([run_id]));
    assert_eq!(result["outcome"], json!("ok"));
    assert!(result["result_bytes"].as_u64().unwrap() > 0);

    let (audit, sink) = memory_audit();
    let server = native_server(&api.uri(), &[Capability::Control], audit);
    server
        .dispatch("resources/read", params.clone())
        .await
        .unwrap_err();
    let records = sink.records();
    let (_, result) = pair(&records, "resources/read");
    assert_eq!(result["outcome"], json!("refused"));
    assert_eq!(result["error_code"], json!("capability_not_granted"));

    let (audit, sink) = memory_audit();
    let server = compat_server(&api.uri(), audit);
    server.dispatch("resources/read", params).await.unwrap_err();
    let records = sink.records();
    let (_, result) = pair(&records, "resources/read");
    assert_eq!(result["outcome"], json!("refused"));
    assert_eq!(result["error_code"], json!("method_not_found"));
}

#[tokio::test]
async fn methods_that_read_nothing_write_nothing() {
    let api = quiet_api().await;
    let (audit, sink) = memory_audit();
    let server = native_server(&api.uri(), &[Capability::Inspect], audit);
    server
        .dispatch(
            "initialize",
            Some(json!({ "protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {} })),
        )
        .await
        .unwrap();
    server.dispatch("ping", None).await.unwrap();
    server.dispatch("tools/list", Some(json!({}))).await.unwrap();
    server.dispatch("resources/list", Some(json!({}))).await.unwrap();
    server
        .dispatch("resources/templates/list", Some(json!({})))
        .await
        .unwrap();
    assert!(sink.records().is_empty());
}

/// `request` through a file log, then the file's text.
#[tokio::test]
async fn arguments_results_errors_and_keys_never_reach_the_file() {
    let api = quiet_api().await;
    Mock::given(method("POST"))
        .and(path_regex("scrape$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "data": { "markdown": "RESULT-CANARY-5521 page text" }
        })))
        .mount(&api)
        .await;
    Mock::given(method("POST"))
        .and(path_regex("map$"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "success": false,
            "error": "ERROR-CANARY-9902 leaked page text"
        })))
        .mount(&api)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("audit.jsonl");
    let audit = Arc::new(Audit::open(&file).unwrap());
    let server = compat_server(&api.uri(), audit);

    let args = json!({ "url": "https://example.invalid/ARG-CANARY-1187?token=ARG-CANARY-0042" });
    let reply = server
        .dispatch("tools/call", tool_call(SCRAPE_TOOL, args.clone()))
        .await
        .unwrap();
    assert!(
        reply.to_string().contains("RESULT-CANARY-5521"),
        "the caller still gets the result"
    );
    let failed = server
        .dispatch(
            "tools/call",
            tool_call(
                MAP_TOOL,
                json!({ "url": "https://example.invalid/ARG-CANARY-3300" }),
            ),
        )
        .await
        .unwrap();
    assert_eq!(failed["isError"], json!(true));
    assert!(failed.to_string().contains("ERROR-CANARY-9902"));
    server
        .dispatch(
            "tools/call",
            tool_call("CANARY-TOOL-NAME-8841", json!({ "q": "ARG-CANARY-7000" })),
        )
        .await
        .unwrap_err();

    let text = std::fs::read_to_string(&file).unwrap();
    for canary in ["CANARY", SECRET_KEY, "example.invalid", "page text", "Bearer"] {
        assert!(!text.contains(canary), "{canary} reached the audit log:\n{text}");
    }
    let records: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 6);
    // the digest is the SHA-256 of the canonical JSON of the arguments (one key: its plain JSON)
    assert_eq!(
        records[0]["args_digest"],
        json!(hex::encode(Sha256::digest(
            serde_json::to_string(&args).unwrap().as_bytes()
        )))
    );
    assert_eq!(records[1]["outcome"], json!("ok"));
    assert_eq!(records[1]["error_code"], Value::Null);
    assert_eq!(records[3]["outcome"], json!("error"));
    assert_eq!(records[3]["error_code"], json!("tool_error"));
    assert_eq!(records[5]["outcome"], json!("refused"));
    assert_eq!(audit::verify(&file).unwrap().broken, None);
}

#[tokio::test]
async fn a_log_that_cannot_record_the_intent_refuses_the_call_before_it_runs() {
    let api = quiet_api().await;
    let sink = Shared::default();
    let flaky = Flaky {
        allowed: 0,
        inner: sink.clone(),
    };
    let server = compat_server(&api.uri(), Arc::new(Audit::in_memory(Box::new(flaky))));
    let error = server
        .dispatch(
            "tools/call",
            tool_call(SCRAPE_TOOL, json!({ "url": "https://example.invalid/" })),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, AUDIT_UNAVAILABLE);
    assert_eq!(
        error.data,
        Some(json!({ "error": { "code": "audit_unavailable" } }))
    );
    assert!(
        api.received_requests().await.unwrap().is_empty(),
        "the call must not run"
    );
    assert!(sink.records().is_empty());
}

#[tokio::test]
async fn a_write_that_fails_mid_run_refuses_that_call_and_every_later_one() {
    let api = quiet_api().await;
    Mock::given(method("POST"))
        .and(path_regex("scrape$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "success": true,
            "data": { "markdown": "RESULT-CANARY-5521" }
        })))
        .mount(&api)
        .await;
    let sink = Shared::default();
    // the first call's intent is written; its result record is the write that fails
    let flaky = Flaky {
        allowed: 1,
        inner: sink.clone(),
    };
    let server = compat_server(&api.uri(), Arc::new(Audit::in_memory(Box::new(flaky))));
    let first = server
        .dispatch(
            "tools/call",
            tool_call(SCRAPE_TOOL, json!({ "url": "https://example.invalid/" })),
        )
        .await
        .unwrap_err();
    assert_eq!(first.code, AUDIT_UNAVAILABLE);
    assert!(
        !first.to_value().to_string().contains("RESULT-CANARY"),
        "the result is withheld"
    );
    assert_eq!(
        api.received_requests().await.unwrap().len(),
        1,
        "the intent was on record"
    );

    let second = server
        .dispatch(
            "tools/call",
            tool_call(SCRAPE_TOOL, json!({ "url": "https://example.invalid/" })),
        )
        .await
        .unwrap_err();
    assert_eq!(second.code, AUDIT_UNAVAILABLE);
    assert_eq!(
        api.received_requests().await.unwrap().len(),
        1,
        "no later call runs"
    );
    assert_eq!(sink.records().len(), 1);
}

#[tokio::test]
async fn a_cancelled_call_is_recorded_as_cancelled() {
    let api = quiet_api().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(30))
                .set_body_json(json!({})),
        )
        .mount(&api)
        .await;
    let (audit, sink) = memory_audit();
    let server = Arc::new(compat_server(&api.uri(), audit));
    let waiting = tokio::time::timeout(
        Duration::from_millis(200),
        server.dispatch(
            "tools/call",
            tool_call(SCRAPE_TOOL, json!({ "url": "https://example.invalid/" })),
        ),
    )
    .await;
    assert!(waiting.is_err(), "the call was meant to be cut short");
    let records = sink.records();
    let (_, result) = pair(&records, SCRAPE_TOOL);
    assert_eq!(result["outcome"], json!("error"));
    assert_eq!(result["error_code"], json!("cancelled"));
}

#[tokio::test]
async fn concurrent_calls_keep_the_chain_linear() {
    let api = quiet_api().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("audit.jsonl");
    let server = Arc::new(compat_server(&api.uri(), Arc::new(Audit::open(&file).unwrap())));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..24 {
        let server = Arc::clone(&server);
        tasks.spawn(async move {
            let _ = server
                .dispatch(
                    "tools/call",
                    tool_call(
                        MAP_TOOL,
                        json!({ "url": format!("https://example.invalid/{index}") }),
                    ),
                )
                .await;
        });
    }
    while tasks.join_next().await.is_some() {}
    let found = audit::verify(&file).unwrap();
    assert_eq!((found.entries, found.broken), (48, None));
}

#[tokio::test]
async fn the_server_does_not_start_when_the_log_cannot_be_opened() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("absent").join("audit.jsonl");
    let args = Wrapper::try_parse_from(["crawlx-mcp", "--audit-log", missing.to_str().unwrap()])
        .unwrap()
        .args;
    let mut out = Vec::new();
    let error = run(args, &mut out).await.unwrap_err();
    assert!(format!("{error:#}").contains("audit log"), "{error:#}");
    assert!(out.is_empty());
}

#[test]
fn the_flag_and_the_environment_variable_name_the_log() {
    let command = McpArgs::augment_args(clap::Command::new("mcp"));
    let argument = command
        .get_arguments()
        .find(|argument| argument.get_id() == "audit_log")
        .unwrap();
    assert_eq!(
        argument.get_env().and_then(|name| name.to_str()),
        Some("CRAWLX_MCP_AUDIT_LOG")
    );
    let parsed = Wrapper::try_parse_from(["crawlx-mcp", "--audit-log", "/var/log/mcp.jsonl"]).unwrap();
    assert_eq!(parsed.args.audit_log, Some(PathBuf::from("/var/log/mcp.jsonl")));
    assert!(parsed.args.command.is_none());
    let parsed = Wrapper::try_parse_from(["crawlx-mcp", "audit-verify", "/var/log/mcp.jsonl"]).unwrap();
    assert!(matches!(
        parsed.args.command,
        Some(McpCommand::AuditVerify { .. })
    ));
    Wrapper::command().debug_assert();
}

#[tokio::test]
async fn audit_verify_prints_the_count_and_last_hash_and_names_the_first_broken_line() {
    let api = quiet_api().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("audit.jsonl");
    let server = compat_server(&api.uri(), Arc::new(Audit::open(&file).unwrap()));
    for _ in 0..3 {
        let _ = server
            .dispatch(
                "tools/call",
                tool_call(MAP_TOOL, json!({ "url": "https://example.invalid/" })),
            )
            .await;
    }
    drop(server);

    let verify = |path: &Path| {
        let args = Wrapper::try_parse_from(["crawlx-mcp", "audit-verify", path.to_str().unwrap()])
            .unwrap()
            .args;
        async move {
            let mut out = Vec::new();
            let code = run(args, &mut out).await.unwrap();
            (code, String::from_utf8(out).unwrap())
        }
    };
    let (code, text) = verify(&file).await;
    assert_eq!(code, ExitCode::SUCCESS);
    let last = std::fs::read_to_string(&file).unwrap();
    let last: Value = serde_json::from_str(last.lines().last().unwrap()).unwrap();
    assert_eq!(
        text,
        format!("entries: 6\nlast_hash: {}\n", last["hash"].as_str().unwrap())
    );

    let mut lines: Vec<String> = std::fs::read_to_string(&file)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    lines.remove(3);
    std::fs::write(&file, format!("{}\n", lines.join("\n"))).unwrap();
    let (code, text) = verify(&file).await;
    assert_eq!(code, ExitCode::from(1));
    assert!(text.starts_with("entries: 3\n"), "{text}");
    assert!(text.contains("broken: line 4: "), "{text}");

    let unreadable = verify_error(&dir.path().join("none.jsonl")).await;
    assert!(unreadable.contains("none.jsonl"), "{unreadable}");
}

async fn verify_error(path: &Path) -> String {
    let args = Wrapper::try_parse_from(["crawlx-mcp", "audit-verify", path.to_str().unwrap()])
        .unwrap()
        .args;
    let mut out = Vec::new();
    format!("{:#}", run(args, &mut out).await.unwrap_err())
}
