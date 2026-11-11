//! Operator surface regressions that need no database: `--help` never prints secret environment
//! values, and a database URL of another engine is refused with a typed, actionable message.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output};

const SECRET_URL: &str = "postgres://operator:hunter2-sentinel@db.internal:5432/crawlx";

fn crawlx(args: &[&str], envs: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(args)
        .env_remove("CRAWLX_DATABASE_URL")
        .env_remove("CRAWLX_DATABASE_URL_FILE")
        .env_remove("CRAWLX_CONFIG")
        .envs(envs.iter().copied())
        .output()
        .unwrap()
}

#[test]
fn help_never_prints_secret_environment_values() {
    let envs = [
        ("CRAWLX_DATABASE_URL", SECRET_URL),
        ("CRAWLX_API_DATABASE_URL", SECRET_URL),
        ("CRAWLX_WEBHOOK_SECRET", "hunter2-sentinel"),
    ];
    for args in [
        &["serve", "--help"][..],
        &["worker", "--help"],
        &["migrate", "--help"],
        &["inspect", "run", "00000000-0000-7000-8000-000000000000", "--help"],
        &["export", "--help"],
        &["replay", "--help"],
        &["archive", "export", "--help"],
        &["replay-response", "--help"],
        &["crawl", "--help"],
        &["admin", "status", "--help"],
        &["admin", "audit-export", "--help"],
        &["profiles", "--help"],
    ] {
        let out = crawlx(args, &envs);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !text.contains("hunter2-sentinel"),
            "{args:?} printed a secret:\n{text}"
        );
    }
}

#[test]
fn a_failed_connection_never_prints_the_database_password() {
    for url in [
        "mariadb://crawlx:pw-sentinel@127.0.0.1:1/crawlx",
        "postgres://crawlx:pw-sentinel@127.0.0.1:1/crawlx",
    ] {
        for args in [
            &["migrate"][..],
            &["inspect", "run", "00000000-0000-7000-8000-000000000000"],
        ] {
            let out = crawlx(args, &[("CRAWLX_DATABASE_URL", url)]);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(2), "{args:?} {url}: {stderr}");
            assert!(
                stderr.starts_with("error: connecting to the database: "),
                "{args:?} {url}: {stderr}"
            );
            assert!(!stderr.contains("pw-sentinel"), "{args:?} {url}: {stderr}");
        }
    }
}

#[test]
fn an_unknown_database_scheme_is_refused_with_the_supported_list() {
    let out = crawlx(&["migrate"], &[("CRAWLX_DATABASE_URL", "unknown://u:p@h/db")]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("refused: scheme"), "{stderr}");
    assert!(
        stderr.contains("expected postgres, mariadb or sqlite"),
        "{stderr}"
    );
}

#[test]
fn an_unreachable_postgres_reports_the_cause_not_just_the_category() {
    // port 1 refuses immediately; the message must carry the driver's reason
    let out = crawlx(
        &["migrate"],
        &[("CRAWLX_DATABASE_URL", "postgres://crawlx@127.0.0.1:1/crawlx")],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(
        stderr.starts_with("error: connecting to the database: "),
        "{stderr}"
    );
    assert!(
        stderr.trim_end().len() > "error: connecting to the database: database operation failed".len(),
        "the driver cause is missing: {stderr}"
    );
}

#[test]
fn malformed_bootstrap_key_diagnostics_never_print_the_supplied_secret() {
    let out = crawlx(&["serve", "--api-key", "secret-sentinel-with-no-tenant"], &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("--api-key expects TENANT=KEY"), "{stderr}");
    assert!(!stderr.contains("secret-sentinel"), "{stderr}");
}

#[test]
fn bootstrap_key_refusal_names_the_lowercase_native_alphabet() {
    let out = crawlx(
        &["serve", "--api-key", "t=cx_live_ABCDEFGHIJKLMNOPQRSTUVWXYZ"],
        &[],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "{stderr}");
    assert!(stderr.contains("lowercase letters a-z or digits 2-7"), "{stderr}");
}
