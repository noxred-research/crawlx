//! Captcha flag compatibility, configuration layering, environment and secret boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::Parser as _;
use crawlx_core::captcha::CaptchaProvider;
use crawlx_core::CreateCrawl;
use std::process::Command;

const KEY: &str = "captcha-cli-secret-canary";

fn parse(args: &[&str]) -> crawlx_cli::CrawlArgs {
    let mut argv = vec!["crawlx", "crawl", "https://example.test/"];
    argv.extend_from_slice(args);
    let cli = crawlx_cli::Cli::try_parse_from(crawlx_cli::normalize_args(argv)).unwrap();
    let crawlx_cli::Command::Crawl(args) = cli.command else {
        panic!("expected crawl command");
    };
    *args
}

fn build(args: &[&str]) -> CreateCrawl {
    crawlx_cli::crawl::build_request(&parse(args)).unwrap()
}

#[test]
fn katana_short_single_dash_long_and_normal_flags_build_the_same_request() {
    for (provider, key) in [
        ("-csp", "-csk"),
        ("-captcha-solver-provider", "-captcha-solver-key"),
        ("--captcha-solver-provider", "--captcha-solver-key"),
    ] {
        let args = parse(&[provider, "capsolver", key, KEY]);
        let request = crawlx_cli::crawl::build_request(&args).unwrap();
        let config = request.crawl.captcha.as_ref().unwrap();
        assert_eq!(config.provider, CaptchaProvider::Capsolver);
        assert_eq!(config.key_ref.0, "env://CRAWLX_CAPTCHA_SOLVER_KEY");
        assert_eq!(config.endpoint.as_str(), "https://api.capsolver.com/");
        for text in [
            format!("{args:?}"),
            format!("{request:?}"),
            serde_json::to_string(&request).unwrap(),
        ] {
            assert!(!text.contains(KEY), "{text}");
        }
    }
    let request = build(&["-csp=capsolver", "-csk=captcha-cli-secret-canary"]);
    assert!(request.crawl.captcha.is_some());
}

#[test]
fn references_and_explicit_fixture_timing_reach_typed_configuration() {
    for reference in ["env://MY_CAPTCHA_KEY", "file:///run/secrets/captcha-key"] {
        let request = build(&[
            "--captcha-solver-provider",
            "capsolver",
            "--captcha-solver-key-ref",
            reference,
            "--captcha-solver-endpoint",
            "http://127.0.0.1:12345/solver/",
            "--captcha-solver-timeout-seconds",
            "15",
            "--captcha-solver-poll-interval-ms",
            "25",
        ]);
        let config = request.crawl.captcha.unwrap();
        assert_eq!(config.key_ref.0, reference);
        assert_eq!(config.endpoint.as_str(), "http://127.0.0.1:12345/solver/");
        assert_eq!(config.timeout_seconds, 15);
        assert_eq!(config.poll_interval_ms, 25);
    }
}

#[test]
fn unknown_provider_and_missing_or_literal_references_fail() {
    assert!(crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "https://example.test/",
        "--captcha-solver-provider",
        "unknown-service",
    ])
    .is_err());
    assert!(crawlx_cli::crawl::build_request(&parse(&["--captcha-solver-provider", "capsolver",])).is_err());
    let error = crawlx_cli::crawl::build_request(&parse(&[
        "--captcha-solver-provider",
        "capsolver",
        "--captcha-solver-key-ref",
        KEY,
    ]))
    .unwrap_err();
    assert!(!format!("{error:#}").contains(KEY));
}

#[test]
fn yaml_flags_merge_below_cli_without_serializing_the_literal_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("captcha.yaml");
    std::fs::write(
        &path,
        format!(
            "captcha-solver-provider: capsolver\ncaptcha-solver-key: {KEY}\ncaptcha-solver-timeout-seconds: 30\ncaptcha-solver-poll-interval-ms: 50\n"
        ),
    )
    .unwrap();
    let request = build(&[
        "--config",
        path.to_str().unwrap(),
        "--captcha-solver-timeout-seconds",
        "60",
    ]);
    let config = request.crawl.captcha.as_ref().unwrap();
    assert_eq!(config.timeout_seconds, 60);
    assert_eq!(config.poll_interval_ms, 50);
    assert!(!serde_json::to_string(&request).unwrap().contains(KEY));
    let request = build(&[
        "--config",
        path.to_str().unwrap(),
        "--captcha-solver-key-ref",
        "env://CLI_KEY",
    ]);
    assert_eq!(request.crawl.captcha.unwrap().key_ref.0, "env://CLI_KEY");
}

#[test]
fn json_request_settings_merge_below_flags() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("captcha.json");
    std::fs::write(
        &path,
        r#"{"crawl":{"captcha":{"provider":"capsolver","key_ref":"env://JSON_KEY","timeout_seconds":30,"poll_interval_ms":50}}}"#,
    )
    .unwrap();
    let request_path = dir.path().join("request.json");
    std::fs::write(
        &request_path,
        r#"{"crawl":{"captcha":{"key_ref":"env://REQUEST_KEY","timeout_seconds":40}}}"#,
    )
    .unwrap();
    let request = build(&[
        "--config",
        path.to_str().unwrap(),
        "--request",
        request_path.to_str().unwrap(),
        "--captcha-solver-timeout-seconds",
        "60",
    ]);
    let config = request.crawl.captcha.unwrap();
    assert_eq!(config.key_ref.0, "env://REQUEST_KEY");
    assert_eq!(config.timeout_seconds, 60);
    assert_eq!(config.poll_interval_ms, 50);
}

#[test]
fn environment_settings_are_parsed_without_parent_environment_mutation() {
    for scenario in ["configured", "key_only", "unknown", "reference_override"] {
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args(["--exact", "environment_parser_child", "--nocapture"])
            .env("CRAWLX_CAPTCHA_TEST_SCENARIO", scenario)
            .env("CAPTCHA_SOLVER_KEY", KEY)
            .env_remove("CAPTCHA_SOLVER_PROVIDER");
        if scenario != "key_only" {
            child.env(
                "CAPTCHA_SOLVER_PROVIDER",
                if scenario == "unknown" {
                    "unknown-service"
                } else {
                    "capsolver"
                },
            );
        }
        let output = child.output().unwrap();
        assert!(
            output.status.success(),
            "{scenario}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn environment_parser_child() {
    let Ok(scenario) = std::env::var("CRAWLX_CAPTCHA_TEST_SCENARIO") else {
        return;
    };
    if scenario == "unknown" {
        assert!(crawlx_cli::Cli::try_parse_from(["crawlx", "crawl", "https://example.test/",]).is_err());
        return;
    }
    let flags: &[&str] = if scenario == "reference_override" {
        &["--captcha-solver-key-ref", "env://EXPLICIT_KEY"]
    } else {
        &[]
    };
    let args = parse(flags);
    assert_eq!(args.captcha.captcha_solver_key.as_ref().unwrap().expose(), KEY);
    assert!(!format!("{args:?}").contains(KEY));
    let request = crawlx_cli::crawl::build_request(&args).unwrap();
    if scenario == "key_only" {
        assert!(request.crawl.captcha.is_none());
    } else {
        let config = request.crawl.captcha.as_ref().unwrap();
        assert_eq!(config.provider, CaptchaProvider::Capsolver);
        assert_eq!(
            config.key_ref.0,
            if scenario == "reference_override" {
                "env://EXPLICIT_KEY"
            } else {
                "env://CRAWLX_CAPTCHA_SOLVER_KEY"
            }
        );
    }
    assert!(!serde_json::to_string(&request).unwrap().contains(KEY));
}

#[test]
fn help_never_prints_the_environment_key_value() {
    let output = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["crawl", "--help"])
        .env("CAPTCHA_SOLVER_PROVIDER", "capsolver")
        .env("CAPTCHA_SOLVER_KEY", KEY)
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--captcha-solver-provider"));
    assert!(help.contains("--captcha-solver-key-ref"));
    assert!(!help.contains(KEY));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(KEY));
}
