//! Real offline command smoke tests, with a listener detecting forbidden outbound activity.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use serde_json::Value;
use std::{
    io::{ErrorKind, Write},
    net::TcpListener,
    process::{Command, Stdio},
};

#[test]
fn file_and_stdin_share_pipeline_without_target_update_or_otlp_connections() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/article", listener.local_addr().unwrap());
    let html = format!("<html lang='en'><head><title>Offline bridge report</title><meta property='og:image' content='{base}/image'></head><body><main><p>The bridge has reopened for buses, and the town will inspect the new road surface tomorrow.</p><a rel='next' href='/more'>More</a></main></body></html>");
    let input = root.path().join("article.html");
    let policy = root.path().join("policy.json");
    std::fs::write(&input, &html).unwrap();
    std::fs::write(
        &policy,
        r#"{"version":1,"referenceDate":"2026-11-04","comments":"separate"}"#,
    )
    .unwrap();
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_crawlx"));
        command
            .args(["extract", "--base-url", &base, "--request"])
            .arg(&policy)
            .env("HOME", root.path())
            .env("CRAWLX_UPDATE_CHECK", "1")
            .env("CRAWLX_RELEASE_URL", &base)
            .env("CRAWLX_OTLP_ENDPOINT", &base)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    };
    let file = command().arg("--input").arg(&input).output().unwrap();
    assert!(file.status.success(), "{}", String::from_utf8_lossy(&file.stderr));
    let mut child = command()
        .arg("--stdin-html")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(html.as_bytes()).unwrap();
    let stdin = child.wait_with_output().unwrap();
    assert!(
        stdin.status.success(),
        "{}",
        String::from_utf8_lossy(&stdin.stderr)
    );
    assert_eq!(
        file.stdout, stdin.stdout,
        "same bytes and pinned policy must serialize identically"
    );
    let document: Value = serde_json::from_slice(&stdin.stdout).unwrap();
    assert_eq!(document["article"]["quality"]["status"], "accepted");
    assert_eq!(document["article"]["discovery"].as_array().unwrap().len(), 2);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        ErrorKind::WouldBlock,
        "offline command must not connect to resolution base, media, read-more, update or OTLP"
    );
    assert_eq!(
        std::fs::read_dir(root.path()).unwrap().count(),
        2,
        "no durable spool or backup may appear"
    );
}
#[test]
fn rejected_and_unavailable_outputs_have_distinct_exit_codes_and_keep_observed_text() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("article.html");
    let policy = root.path().join("policy.json");
    std::fs::write(&input, "<main><p>The report is a real document, even when its length fails the configured quality gate.</p></main>").unwrap();
    for (body, expected, status) in [
        (r#"{"version":1,"minMainChars":1000}"#, 2, "rejected"),
        (r#"{"version":1,"nlp":"sentence_model"}"#, 3, "unavailable"),
    ] {
        std::fs::write(&policy, body).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_crawlx"))
            .args([
                "extract",
                "--base-url",
                "https://fixture.invalid/article",
                "--input",
            ])
            .arg(&input)
            .arg("--request")
            .arg(&policy)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["article"]["quality"]["status"], status);
        assert!(document["text"].as_str().unwrap().contains("real document"));
        assert!(
            document.get("validation").is_none(),
            "offline HTML has no observed HTTP response"
        );
    }
}

const BASE: &str = "https://fixture.invalid/articles/one";

fn page() -> Vec<u8> {
    let mut html = b"<html><head><title>Caf".to_vec();
    html.push(0xE9);
    html.extend_from_slice(b"</title></head><body><main><p>The caf");
    html.push(0xE9);
    html.extend_from_slice(
        b" will reopen after the bridge works finish, and the council will publish the timetable.</p>\
          <!-- editorial note --><![CDATA[ cdata payload ]]>\
          <a class='more' href='rest'>Read more</a></main></body></html>",
    );
    html
}

fn run_extract(dir: &std::path::Path, extra: &[&std::ffi::OsStr]) -> std::process::Output {
    let input = dir.join("page.html");
    std::fs::write(&input, page()).unwrap();
    Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["extract", "--base-url", BASE, "--input"])
        .arg(&input)
        .args(extra)
        .output()
        .unwrap()
}

fn write_config(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    path
}

#[test]
fn extract_config_enables_decode_markup_and_outputs_offline() {
    let root = tempfile::tempdir().unwrap();
    let plain = run_extract(root.path(), &[]);
    assert!(
        plain.status.success(),
        "{}",
        String::from_utf8_lossy(&plain.stderr)
    );
    let plain: Value = serde_json::from_slice(&plain.stdout).unwrap();
    for key in ["decode", "markup", "outputs"] {
        assert!(plain.get(key).is_none(), "{key} is opt-in");
    }
    let config = write_config(
        root.path(),
        "extract.json",
        r#"{"outputs":{"rawHtml":true,"cleanedHtml":true},"decode":{"declaredCharset":"windows-1252"},"markup":{"comments":true,"cdata":true}}"#,
    );
    let output = run_extract(root.path(), &["--extract-config".as_ref(), config.as_os_str()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["decode"]["encoding"], "windows-1252");
    assert_eq!(document["decode"]["source"], "declared");
    assert_eq!(document["decode"]["issueCount"], 0);
    assert!(document["text"].as_str().unwrap().contains("caf\u{e9}"));
    assert_eq!(
        document["markup"]["comments"],
        serde_json::json!([" editorial note "])
    );
    assert_eq!(
        document["markup"]["cdata"],
        serde_json::json!([" cdata payload "])
    );
    let raw = document["outputs"]["rawHtml"].as_str().unwrap();
    assert!(raw.contains("<!-- editorial note -->"), "{raw}");
    assert!(document["outputs"]["cleanedHtml"].as_str().is_some());
}

#[test]
fn invalid_extract_config_is_refused_before_extraction() {
    let root = tempfile::tempdir().unwrap();
    for body in [
        r#"{"customFields":[]}"#,
        r#"{"outputs":{"targetElements":[""]}}"#,
        r#"{"decode":{"charset":"utf-8"}}"#,
        r#"{"markup":{"comments":"yes"}}"#,
        "not json",
        "[null,null,null]",
        r#"[{"rawHtml":true},null,null]"#,
    ] {
        let config = write_config(root.path(), "extract.json", body);
        let output = run_extract(root.path(), &["--extract-config".as_ref(), config.as_os_str()]);
        assert!(!output.status.success(), "{body}");
        assert!(output.stdout.is_empty(), "{body}");
    }
}

#[test]
fn request_policy_read_more_base_selects_document_or_page_base() {
    let root = tempfile::tempdir().unwrap();
    let urls = |base: &str| {
        let policy = write_config(
            root.path(),
            "policy.json",
            &format!(
                r#"{{"version":1,"selectors":{{"readMore":[{{"kind":"css","expression":"a.more"}}]{base}}}}}"#
            ),
        );
        let input = root.path().join("page.html");
        std::fs::write(
            &input,
            "<html><head><base href='https://cdn.fixture.invalid/assets/'></head><body><article>\
             <p>A teaser paragraph that is long enough to be selected as the main article block here.</p>\
             <a class='more' href='rest'>Read more</a></article></body></html>",
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_crawlx"))
            .args(["extract", "--base-url", BASE, "--input"])
            .arg(&input)
            .arg("--request")
            .arg(&policy)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        document["article"]["discovery"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|intent| intent["purpose"] == "read_more_reference")
            .map(|intent| intent["url"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(urls(""), ["https://cdn.fixture.invalid/assets/rest"]);
    assert_eq!(
        urls(r#","readMoreBase":"page""#),
        ["https://fixture.invalid/articles/rest"]
    );
}
