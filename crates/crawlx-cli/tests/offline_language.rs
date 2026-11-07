//! Authored MIT fixtures for operator-only offline language capability injection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::{article_language::LanguageModeV1, extraction::ExtractionPolicyV1, hash::Digest};
use std::{net::TcpListener, path::Path, process::Command};

fn command(root: &Path, base: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    command
        .current_dir(root)
        .args(["extract", "--base-url", base, "--request", "policy.json"])
        .env_remove("CRAWLX_ARTICLE_LANGUAGE_BUNDLE")
        .env("HOME", root)
        .env("CRAWLX_OTLP_ENDPOINT", base)
        .env("CRAWLX_RELEASE_URL", base)
        .env("CRAWLX_UPDATE_CHECK", "1");
    command
}

fn policy(root: &Path, mode: LanguageModeV1, digest: Option<Digest>) {
    let mut policy = ExtractionPolicyV1::default();
    policy.language_mode = mode;
    policy.language_bundle_digest = digest;
    policy.reference_date = Some("2026-11-04".parse().unwrap());
    std::fs::write(root.join("policy.json"), serde_json::to_vec(&policy).unwrap()).unwrap();
}

#[test]
fn absent_or_wrong_pinned_model_exits_three_before_reading_html_without_network() {
    let root = tempfile::tempdir().unwrap();
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let base = format!("http://{}/article", trap.local_addr().unwrap());
    for digest in [
        crawlx_model::article_language::expected_bundle_digest(),
        Digest::of("wrong-language-bundle", b"not approved"),
    ] {
        policy(root.path(), LanguageModeV1::Detect, Some(digest));
        let output = command(root.path(), &base)
            .args(["--input", "does-not-exist.html"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("article language capability unavailable"));
    }
    assert_eq!(trap.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn declared_only_policy_ignores_ambient_model_path_and_still_uses_native_pipeline() {
    let root = tempfile::tempdir().unwrap();
    policy(root.path(), LanguageModeV1::DeclaredOnly, None);
    std::fs::write(root.path().join("article.html"), "<html lang='en'><main><p>The village library opened its reading room before sunrise. Volunteers helped the children choose books about rivers, birds, and distant planets.</p></main></html>").unwrap();
    let output = command(root.path(), "https://fixture.invalid/article")
        .env(
            "CRAWLX_ARTICLE_LANGUAGE_BUNDLE",
            root.path().join("not-installed"),
        )
        .args(["--input", "article.html"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["article"]["metadata"]["language"]["value"], "en");
    assert_eq!(value["article"]["metadata"]["languageModelUnavailable"], false);
    assert!(value["article"]["metadata"]["languageModelDigest"].is_null());
}

#[cfg(feature = "onnx")]
#[test]
fn explicitly_installed_pinned_bundle_reaches_actual_cli_detector_without_network() {
    let Some(bundle) = std::env::var_os("CRAWLX_TEST_ARTICLE_LANGUAGE_BUNDLE") else {
        eprintln!("skipped: approved test article language bundle not explicitly installed");
        return;
    };
    let Some(runtime) = std::env::var_os("ORT_DYLIB_PATH") else {
        eprintln!("skipped: operator ONNX runtime not explicitly installed");
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    let base = format!("http://{}/article", trap.local_addr().unwrap());
    let digest = crawlx_model::article_language::expected_bundle_digest();
    policy(root.path(), LanguageModeV1::Detect, Some(digest));
    std::fs::write(root.path().join("article.html"), "<main><p>The village library opened its reading room before sunrise. Volunteers carried wooden chairs into the garden and helped children choose books about rivers, birds, and distant planets.</p></main>").unwrap();
    let output = command(root.path(), &base)
        .env("CRAWLX_ARTICLE_LANGUAGE_BUNDLE", bundle)
        .env("ORT_DYLIB_PATH", runtime)
        .args(["--input", "article.html"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["article"]["metadata"]["detectedLanguage"]["value"], "en");
    assert_eq!(
        value["article"]["metadata"]["languageModelDigest"],
        serde_json::to_value(digest).unwrap()
    );
    assert_eq!(value["article"]["metadata"]["languageModelUnavailable"], false);
    assert_eq!(trap.accept().unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}
