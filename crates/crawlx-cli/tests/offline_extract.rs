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
        (r#"{"version":1,"nlp":"punkt_model"}"#, 3, "unavailable"),
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
