//! `crawlx serve` and `crawlx config check` read `[intel.policy]` of the configuration file: the
//! real binary, the real HTTP API on a loopback port, a scripted chat-completions endpoint. With
//! the policy enabled the native AI endpoints reach the approved provider; without it (no file,
//! or `externalProcessing = false`) they answer `403 external_processing_disabled`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_api::auth::generate_key;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The provider key: only ever in the child's environment, referenced as `env:` by the file.
const PROVIDER_KEY: &str = "sk-policy-provider-7777";

struct Serve {
    child: Child,
    port: u16,
    log: PathBuf,
}

impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn crawlx() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("NO_COLOR", "1");
    cmd
}

/// One HTTP/1.1 exchange with `Connection: close`; returns the status and the JSON body.
fn http(port: u16, method: &str, path: &str, key: &str, body: Option<&Value>) -> (u16, Value) {
    let payload = body.map(Value::to_string).unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {key}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
        payload.len()
    );
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    // `Connection: close` responses may be chunked; the JSON object is the span between the braces
    let json = match (body.find('{'), body.rfind('}')) {
        (Some(start), Some(end)) if start < end => {
            serde_json::from_str(&body[start..=end]).unwrap_or(Value::Null)
        }
        _ => Value::Null,
    };
    (status, json)
}

async fn call(
    serve: &Serve,
    method: &'static str,
    path: &'static str,
    key: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let port = serve.port;
    let key = key.to_owned();
    tokio::task::spawn_blocking(move || http(port, method, path, &key, body.as_ref()))
        .await
        .unwrap()
}

async fn start(dir: &Path, key: &str, config: Option<&Path>) -> Serve {
    let port = free_loopback_port();
    let log = dir.join("serve.log");
    let mut cmd = crawlx();
    cmd.env("POLICY_PROVIDER_KEY", PROVIDER_KEY).current_dir(dir);
    if let Some(config) = config {
        cmd.env("CRAWLX_CONFIG", config);
    }
    let child = cmd
        .args(["serve", "--bind", &format!("127.0.0.1:{port}"), "--api-key"])
        .arg(format!("acme={key}"))
        .arg("--artifacts-dir")
        .arg(dir.join("artifacts"))
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .unwrap();
    let mut serve = Serve { child, port, log };
    for _ in 0..400 {
        if let Some(status) = serve.child.try_wait().unwrap() {
            panic!(
                "crawlx serve exited early ({status}): {}",
                std::fs::read_to_string(&serve.log).unwrap()
            );
        }
        if reqwest::get(format!("http://127.0.0.1:{port}/v0/health/liveness"))
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return serve;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "crawlx serve did not come up: {}",
        std::fs::read_to_string(&serve.log).unwrap()
    );
}

/// A `crawlx.toml` approving one provider at `endpoint`; `enabled` is the master switch.
fn config_text(endpoint: &str, enabled: bool) -> String {
    format!(
        "environment = \"dev\"\n\n[intel.policy]\nexternalProcessing = {enabled}\nmaxRunCalls = 4\n\n\
         [intel.policy.providers.analysis]\nendpoint = \"{endpoint}\"\nmodel = \"reviewer-1\"\n\
         apiKeyRef = \"env:POLICY_PROVIDER_KEY\"\nallowedPurposes = [\"crawl_spec\"]\n"
    )
}

/// A chat-completions endpoint that answers every call with the crawl-spec intent.
async fn provider() -> MockServer {
    let server = MockServer::start().await;
    let intent = json!({"version": 1, "maxPages": 50, "excludePaths": ["/logout"], "forbid": ["form_submission"], "goals": ["coverage"]});
    Mock::given(method("POST"))
        .and(header("authorization", format!("Bearer {PROVIDER_KEY}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": intent.to_string()}}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
        })))
        .mount(&server)
        .await;
    server
}

fn compile_body() -> Value {
    json!({"baseConfig": {"seedUrl": "https://app.example.test/", "seed": 7}, "prompt": "crawl lightly"})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_configured_policy_lets_the_ai_endpoints_reach_the_approved_provider() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_key();
    let server = provider().await;
    let config = dir.path().join("crawlx.toml");
    std::fs::write(&config, config_text(&format!("{}/v1", server.uri()), true)).unwrap();
    let serve = start(dir.path(), &key, Some(&config)).await;

    let (status, caps) = call(&serve, "GET", "/v1/capabilities/ai", &key, None).await;
    assert_eq!(status, 200, "{caps}");
    assert_eq!(caps["externalProcessing"], true, "{caps}");
    assert_eq!(caps["providers"][0]["id"], "analysis");
    assert!(!caps.to_string().contains(PROVIDER_KEY));

    let (status, spec) = call(
        &serve,
        "POST",
        "/v1/crawl-specs/compile",
        &key,
        Some(compile_body()),
    )
    .await;
    assert_eq!(status, 201, "{spec}");
    assert_eq!(spec["intent"]["source"], "model", "{spec}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert!(!spec.to_string().contains(PROVIDER_KEY));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_policy_or_with_the_switch_off_the_endpoints_stay_refused() {
    let key = generate_key();
    let server = provider().await;
    // no configuration file at all
    let dir = tempfile::tempdir().unwrap();
    let serve = start(dir.path(), &key, None).await;
    let (status, v) = call(
        &serve,
        "POST",
        "/v1/crawl-specs/compile",
        &key,
        Some(compile_body()),
    )
    .await;
    assert_eq!(status, 403, "{v}");
    assert_eq!(v["error"]["code"], "external_processing_disabled", "{v}");
    drop(serve);
    // a policy whose master switch is off
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("crawlx.toml");
    std::fs::write(&config, config_text(&format!("{}/v1", server.uri()), false)).unwrap();
    let serve = start(dir.path(), &key, Some(&config)).await;
    let (status, v) = call(
        &serve,
        "POST",
        "/v1/crawl-specs/compile",
        &key,
        Some(compile_body()),
    )
    .await;
    assert_eq!(status, 403, "{v}");
    assert_eq!(v["error"]["code"], "external_processing_disabled", "{v}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn serve_refuses_an_unknown_policy_key_and_an_inline_credential() {
    let dir = tempfile::tempdir().unwrap();
    let run = |text: &str| {
        let config = dir.path().join("bad.toml");
        std::fs::write(&config, text).unwrap();
        crawlx()
            .current_dir(dir.path())
            .env("CRAWLX_CONFIG", &config)
            .args(["serve", "--bind", "127.0.0.1:0"])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let unknown = run("[intel.policy]\nexternalProcesing = true\n");
    assert!(!unknown.status.success());
    let inline = run(
        "[intel.policy]\nexternalProcessing = true\n[intel.policy.providers.analysis]\n\
         endpoint = \"https://m.example/v1\"\nmodel = \"m\"\napiKeyRef = \"sk-inline-secret-1234\"\n",
    );
    assert!(!inline.status.success());
    let stderr = String::from_utf8_lossy(&inline.stderr);
    assert!(stderr.contains("apiKeyRef"), "{stderr}");
    assert!(!stderr.contains("sk-inline-secret-1234"), "{stderr}");
}

fn check(config: &Path, format: &str) -> std::process::Output {
    let dir = config.parent().unwrap();
    std::fs::write(dir.join("chromium-pin.toml"), "[chromium]\nversion = \"1\"\n").unwrap();
    crawlx()
        .current_dir(dir)
        .env("POLICY_PROVIDER_KEY", PROVIDER_KEY)
        .env("CRAWLX_ENVIRONMENT", "dev")
        .args(["config", "check", "--format", format, "--config"])
        .arg(config)
        .output()
        .unwrap()
}

#[test]
fn config_check_validates_and_reports_the_policy_without_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("crawlx.toml");
    std::fs::write(
        &config,
        config_text("https://svc:hunter2@models.internal.example/v1?token=tok-1", true),
    )
    .unwrap();
    // an endpoint with credentials is an error, and nothing of it is printed
    let out = check(&config, "json");
    assert!(!out.status.success());
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(!text.contains("hunter2") && !text.contains("tok-1"), "{text}");
    assert!(!text.contains(PROVIDER_KEY), "{text}");

    std::fs::write(&config, config_text("https://models.internal.example/v1", true)).unwrap();
    for format in ["json", "toml"] {
        let out = check(&config, format);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(
            out.status.success(),
            "{format}: {text} {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!text.contains(PROVIDER_KEY), "{text}");
        assert!(
            text.contains("analysis") && text.contains("externalProcessing"),
            "{text}"
        );
    }
    let out = check(&config, "json");
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    let policy = &report["intel"]["policy"];
    assert_eq!(policy["externalProcessing"], true);
    assert_eq!(policy["providers"]["analysis"]["apiKey"]["status"], "present");
    assert_eq!(
        policy["providers"]["analysis"]["apiKey"]["ref"],
        "env:POLICY_PROVIDER_KEY"
    );
    assert_eq!(policy["maxRunCalls"], 4);

    // an unknown key fails the check
    std::fs::write(&config, "[intel.policy]\nexternalProcesing = true\n").unwrap();
    assert!(!check(&config, "json").status.success());
}
