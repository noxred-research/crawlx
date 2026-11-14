//! Real local acquisitions and stored-page command/config boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::http::{Method, StatusCode};
use axum::{extract::State, response::IntoResponse, routing::any, Router};
use clap::Parser as _;
use crawlx_cli::scrape::{ScrapeArgs, ShellArgs};
use crawlx_core::{Clock as _, SystemClock, TenantId};
use crawlx_policy::{testkit::sample_record, AuthorizationRecord};
use serde_json::{json, Value};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

type Requests = Arc<Mutex<Vec<(String, String)>>>;
struct Site {
    origin: String,
    requests: Requests,
    task: tokio::task::JoinHandle<()>,
    files: tempfile::TempDir,
}
impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn respond(
    State(requests): State<Requests>,
    method: Method,
    uri: axum::http::Uri,
) -> axum::response::Response {
    requests
        .lock()
        .unwrap()
        .push((method.to_string(), uri.path().into()));
    if uri.path() == "/robots.txt" {
        return (
            [("content-type", "text/plain")],
            "User-agent: *\nDisallow: /denied\n",
        )
            .into_response();
    }
    if uri.path() == "/moved" {
        return (StatusCode::FOUND, [("location", "/page")]).into_response();
    }
    (
        [("content-type", "text/html; charset=utf-8")],
        "<html><body><h1>Stored title</h1><p class='price'>17</p><a href='/next'>Next</a></body></html>",
    )
        .into_response()
}
impl Site {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/{*path}", any(respond))
            .route("/", any(respond))
            .with_state(requests.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let files = tempfile::tempdir().unwrap();
        let record = AuthorizationRecord {
            authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
            ..sample_record(TenantId::new(), SystemClock.now(), &[&origin])
        };
        std::fs::write(
            files.path().join("authorization.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        Self {
            origin,
            requests,
            task,
            files,
        }
    }
    fn args(&self, command: &str, extra: &[&str]) -> crawlx_cli::Command {
        self.args_at("/page", command, extra)
    }
    fn args_at(&self, path: &str, command: &str, extra: &[&str]) -> crawlx_cli::Command {
        let url = format!("{}{path}", self.origin);
        let record = self.files.path().join("authorization.json");
        let mut argv = vec![
            "crawlx",
            command,
            url.as_str(),
            "--authorization-record",
            record.to_str().unwrap(),
            "--allow-private-networks",
        ];
        argv.extend_from_slice(extra);
        crawlx_cli::Cli::try_parse_from(argv).unwrap().command
    }
    fn scrape_at(&self, path: &str, extra: &[&str]) -> ScrapeArgs {
        let crawlx_cli::Command::Scrape(args) = self.args_at(path, "scrape", extra) else {
            panic!("scrape")
        };
        args
    }
    fn scrape(&self, extra: &[&str]) -> ScrapeArgs {
        let crawlx_cli::Command::Scrape(args) = self.args("scrape", extra) else {
            panic!("scrape")
        };
        args
    }
    fn shell(&self, extra: &[&str]) -> ShellArgs {
        let crawlx_cli::Command::Shell(args) = self.args("shell", extra) else {
            panic!("shell")
        };
        args
    }
    fn pages(&self) -> Vec<(String, String)> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path != "/robots.txt")
            .cloned()
            .collect()
    }
    fn json_file(&self, name: &str, value: Value) -> std::path::PathBuf {
        let path = self.files.path().join(name);
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }
}
async fn run(args: ScrapeArgs) -> anyhow::Result<String> {
    let mut out = Vec::new();
    let _exit =
        crawlx_cli::scrape::run_with_cancel(args, &mut out, &|_| None, CancellationToken::new()).await?;
    Ok(String::from_utf8(out).unwrap())
}

#[tokio::test]
async fn get_selectors_and_head_use_actual_requested_method() {
    let site = Site::start().await;
    assert_eq!(
        run(site.scrape(&["--css", "h1::text", "--json"]))
            .await
            .unwrap()
            .trim(),
        "[\"Stored title\"]"
    );
    assert_eq!(
        run(site.scrape(&["--xpath", "string(//p)", "--json"]))
            .await
            .unwrap()
            .trim(),
        "\"17\""
    );
    let head: Value =
        serde_json::from_str(&run(site.scrape(&["--method", "HEAD", "--json"])).await.unwrap()).unwrap();
    assert_eq!(head["method"], "HEAD");
    assert_eq!(head["status"], 200);
    assert_eq!(head["bodyBytes"], 0);
    assert_eq!(
        site.pages(),
        [
            ("GET".into(), "/page".into()),
            ("GET".into(), "/page".into()),
            ("HEAD".into(), "/page".into())
        ]
    );
}

#[tokio::test]
async fn head_follows_a_same_host_redirect_outside_the_seed_path_like_get() {
    let site = Site::start().await;
    assert_eq!(
        run(site.scrape_at("/moved", &["--css", "h1::text", "--json"]))
            .await
            .unwrap()
            .trim(),
        "[\"Stored title\"]"
    );
    let head: Value = serde_json::from_str(
        &run(site.scrape_at("/moved", &["--method", "HEAD", "--json"]))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(head["method"], "HEAD");
    assert_eq!(head["status"], 200);
    assert_eq!(head["bodyBytes"], 0);
    assert_eq!(
        site.pages(),
        [
            ("GET".into(), "/moved".into()),
            ("GET".into(), "/page".into()),
            ("HEAD".into(), "/moved".into()),
            ("HEAD".into(), "/page".into())
        ]
    );
}

#[tokio::test]
async fn shell_fetches_once_then_css_xpath_regex_and_item_use_stored_page() {
    let site = Site::start().await;
    let recipe = json!({"version":1,"fields":[{"name":"price","selectors":[{"kind":"css","expression":"p.price"}],"extraction":{"kind":"text"},"cardinality":"one"}]});
    let input = format!("css h1::text\nxpath string(//p)\nregex [0-9]+\nitem {recipe}\nquit\n");
    let mut out = Vec::new();
    let _exit = crawlx_cli::scrape::shell_with_input(
        site.shell(&[]),
        input.as_bytes(),
        &mut out,
        &|_| None,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let values: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        values,
        [
            json!(["Stored title"]),
            json!("17"),
            json!(["1", "1", "17"]),
            json!({"price":"17"})
        ]
    );
    assert_eq!(site.pages(), [("GET".into(), "/page".into())]);
    assert_eq!(
        site.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, path)| path == "/robots.txt")
            .count(),
        1
    );
}

#[tokio::test]
async fn regex_builtin_names_work_from_flag_extraction_file_and_shell() {
    let site = Site::start().await;
    let expected = json!(["1", "1", "17"]);
    let from_flag: Value = serde_json::from_str(
        &run(site.scrape(&["--regex-builtin", "number", "--json"]))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(from_flag, expected);
    let pinned: Value = serde_json::from_str(
        &run(site.scrape(&["--regex-builtin", "number.v1", "--json"]))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(pinned, expected);
    let file = site.json_file("builtin.json", json!({"type":"builtin","name":"number"}));
    let from_file: Value = serde_json::from_str(
        &run(site.scrape(&["--extraction", file.to_str().unwrap(), "--json"]))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(from_file, expected);
    let mut out = Vec::new();
    let _exit = crawlx_cli::scrape::shell_with_input(
        site.shell(&[]),
        b"builtin number\nquit\n".as_slice(),
        &mut out,
        &|_| None,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&out).unwrap(),
        expected,
        "shell uses the same built-in table"
    );
}

#[tokio::test]
async fn unknown_regex_builtin_fails_before_network() {
    let site = Site::start().await;
    assert!(
        run(site.scrape(&["--regex-builtin", "no_such_pattern", "--json"]))
            .await
            .is_err()
    );
    let file = site.json_file("bad.json", json!({"type":"builtin","name":"no_such_pattern"}));
    assert!(
        run(site.scrape(&["--extraction", file.to_str().unwrap(), "--json"]))
            .await
            .is_err()
    );
    assert!(crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "scrape",
        site.origin.as_str(),
        "--regex-builtin",
        "number",
        "--regex",
        "x"
    ])
    .is_err());
    assert!(site.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn malformed_or_executable_shell_commands_never_fetch_again() {
    for command in [
        "css [\n",
        "xpath document('https://other.invalid/')\n",
        "exec anything\n",
        "fetch https://other.invalid/\n",
        "item {bad}\n",
    ] {
        let site = Site::start().await;
        let mut out = Vec::new();
        assert!(crawlx_cli::scrape::shell_with_input(
            site.shell(&[]),
            command.as_bytes(),
            &mut out,
            &|_| None,
            CancellationToken::new()
        )
        .await
        .is_err());
        assert_eq!(site.pages().len(), 1);
        assert!(out.is_empty());
    }
}

#[tokio::test]
async fn unsafe_methods_options_missing_extraction_and_unknown_types_fail_before_network() {
    let site = Site::start().await;
    for extra in [
        vec!["--method", "POST"],
        vec!["--method", "PUT"],
        vec!["--method", "DELETE"],
        vec!["--data", "x"],
        vec!["--eval", "x"],
    ] {
        let mut argv = vec!["crawlx", "scrape", site.origin.as_str()];
        argv.extend(extra);
        assert!(crawlx_cli::Cli::try_parse_from(argv).is_err());
    }
    for extra in [
        vec!["--json"],
        vec!["--css", "["],
        vec!["--xpath", "document('https://other.invalid/')"],
        vec!["--method", "HEAD", "--css", "h1"],
    ] {
        assert!(run(site.scrape(&extra)).await.is_err());
    }
    for value in [
        json!({"method":"POST"}),
        json!({"extraction":{"type":"python","expression":"x"}}),
        json!({"extractor":"css"}),
        json!({"crawl":{"tenant":"foreign"}}),
        json!({"crawl":{"scrape":{"options":{"actions":[{"type":"executeJavascript","script":"x"}]}}}}),
    ] {
        let file = site.json_file("bad.json", value);
        assert!(run(site.scrape(&["--config", file.to_str().unwrap()]))
            .await
            .is_err());
    }
    assert!(site.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn layered_precedence_is_immutable_and_tenant_defaults_cannot_set_authority() {
    let site = Site::start().await;
    let tenant = site.json_file(
        "tenant.json",
        json!({"output":"json","extraction":{"type":"css","expression":"h1::text"}}),
    );
    let config = site.json_file(
        "config.json",
        json!({"extraction":{"type":"xpath","expression":"string(//p)"}}),
    );
    let request = site.json_file(
        "request.json",
        json!({"extraction":{"type":"regex","pattern":"Stored"}}),
    );
    let layers = [
        "--tenant-config",
        tenant.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--request",
        request.to_str().unwrap(),
    ];
    assert_eq!(run(site.scrape(&layers)).await.unwrap().trim(), "[\"Stored\"]");
    let mut flags = layers.to_vec();
    flags.extend(["--css", "p::text"]);
    assert_eq!(run(site.scrape(&flags)).await.unwrap().trim(), "[\"17\"]");
    assert_eq!(
        run(site.scrape(&["--tenant-config", tenant.to_str().unwrap()]))
            .await
            .unwrap()
            .trim(),
        "[\"Stored title\"]"
    );
    assert!(run(site.scrape(&["--json"])).await.is_err());
    let foreign = site.json_file(
        "foreign.json",
        json!({"crawl":{"safety":{"respectRobotsTxt":false}}}),
    );
    let before = site.pages().len();
    assert!(run(site.scrape(&["--tenant-config", foreign.to_str().unwrap()]))
        .await
        .is_err());
    assert_eq!(site.pages().len(), before);
}

struct CancelOnWrite {
    cancel: CancellationToken,
    bytes: Vec<u8>,
}
impl Write for CancelOnWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        self.cancel.cancel();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn cancellation_stops_stored_commands_and_pre_cancel_starts_no_request() {
    let site = Site::start().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let mut out = Vec::new();
    assert!(
        crawlx_cli::scrape::run_with_cancel(site.scrape(&[]), &mut out, &|_| None, cancel)
            .await
            .is_err()
    );
    assert!(site.requests.lock().unwrap().is_empty());
    let cancel = CancellationToken::new();
    let mut out = CancelOnWrite {
        cancel: cancel.clone(),
        bytes: Vec::new(),
    };
    assert!(crawlx_cli::scrape::shell_with_input(
        site.shell(&[]),
        &b"css h1::text\nxpath //p\n"[..],
        &mut out,
        &|_| None,
        cancel
    )
    .await
    .is_err());
    assert_eq!(site.pages().len(), 1);
    assert_eq!(String::from_utf8(out.bytes).unwrap().lines().count(), 1);
}

#[tokio::test]
async fn robots_denial_and_shell_input_overflow_are_explicit() {
    let site = Site::start().await;
    let mut args = site.shell(&[]);
    args.page.url = url::Url::parse(&format!("{}/denied", site.origin)).unwrap();
    let mut out = Vec::new();
    assert!(crawlx_cli::scrape::shell_with_input(
        args,
        &b"css h1\n"[..],
        &mut out,
        &|_| None,
        CancellationToken::new()
    )
    .await
    .is_err());
    assert!(site.pages().is_empty());
    let input = format!("css {}\n", "a".repeat(65_536));
    assert!(crawlx_cli::scrape::shell_with_input(
        site.shell(&[]),
        input.as_bytes(),
        &mut out,
        &|_| None,
        CancellationToken::new()
    )
    .await
    .is_err());
    assert_eq!(site.pages().len(), 1);
}

#[test]
fn crawl_request_unknown_keys_and_forbidden_types_fail_without_mutating_defaults() {
    let files = tempfile::tempdir().unwrap();
    for value in [
        json!({"tenant":"foreign"}),
        json!({"fetch":{"unknown":true}}),
        json!({"mode":{"type":"code"}}),
    ] {
        let path = files.path().join("request.json");
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let cli = crawlx_cli::Cli::try_parse_from([
            "crawlx",
            "crawl",
            "https://config.invalid/",
            "--request",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let crawlx_cli::Command::Crawl(args) = cli.command else {
            panic!("crawl")
        };
        assert!(crawlx_cli::crawl::build_request(&args).is_err());
    }
    let cli =
        crawlx_cli::Cli::try_parse_from(["crawlx", "crawl", "https://config.invalid/", "--mode", "static"])
            .unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!("crawl")
    };
    assert_eq!(
        crawlx_cli::crawl::build_request(&args).unwrap().mode,
        crawlx_core::config::CrawlMode::Static
    );
}

#[tokio::test]
async fn output_alias_renders_html_and_shell_command_count_is_bounded() {
    let site = Site::start().await;
    let html = run(site.scrape(&["--output", "html"])).await.unwrap();
    assert!(html.contains("<h1>Stored title</h1>"));
    let commands = "css h1::text\n".repeat(129);
    let mut out = Vec::new();
    let error = crawlx_cli::scrape::shell_with_input(
        site.shell(&[]),
        commands.as_bytes(),
        &mut out,
        &|_| None,
        CancellationToken::new(),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("command limit"));
    assert_eq!(String::from_utf8(out).unwrap().lines().count(), 128);
    assert_eq!(site.pages().len(), 2);
}

#[tokio::test]
async fn foreign_origin_is_denied_before_target_network() {
    let site = Site::start().await;
    let mut args = site.scrape(&[]);
    args.url = url::Url::parse("https://foreign.invalid/page").unwrap();
    assert!(run(args).await.is_err());
    assert!(site.requests.lock().unwrap().is_empty());
}
