//! `crawlx config check` and the shared-instance namespaces: the PostgreSQL schema, the
//! object-store key prefix and the Valkey key prefix are validated before anything runs. Runs the
//! real binary with a controlled environment.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

fn check(database_url: &str, extra: &[(&str, &str)]) -> String {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("chromium-pin.toml"),
        "[chromium]\nversion = \"1\"\n",
    )
    .unwrap();
    let url_file = dir.path().join("database-url");
    std::fs::write(&url_file, database_url).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("CRAWLX_ENVIRONMENT", "dev")
        .env("CRAWLX_DATABASE__URL_FILE", &url_file)
        .args(["config", "check", "--format", "json"]);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let output = cmd.output().unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_postgres_schema_is_accepted_and_checked() {
    let url = "postgres://u:p@127.0.0.1:5432/crawlx";
    let good = check(url, &[("CRAWLX_DATABASE__SCHEMA", "crawlx_blue")]);
    assert!(!good.contains("must be 1 to 63"), "{good}");
    for bad in ["bad-name", "has space", "semi;colon", &"x".repeat(64)] {
        let report = check(url, &[("CRAWLX_DATABASE__SCHEMA", bad)]);
        assert!(report.contains("must be 1 to 63"), "{bad}: {report}");
    }
}

#[test]
fn a_schema_is_refused_where_the_engine_has_none() {
    for url in ["mariadb://u:p@127.0.0.1:3306/crawlx", "sqlite:///data/crawlx.db"] {
        let report = check(url, &[("CRAWLX_DATABASE__SCHEMA", "crawlx")]);
        assert!(report.contains("only postgres has schemas"), "{url}: {report}");
    }
}

#[test]
fn key_prefixes_are_validated_by_the_check() {
    let url = "postgres://u:p@127.0.0.1:5432/crawlx";
    let report = check(
        url,
        &[
            ("CRAWLX_REDIS_KEY_PREFIX", "bad prefix"),
            ("CRAWLX_S3_BUCKET", "b"),
            ("CRAWLX_S3_PREFIX", "a//b"),
        ],
    );
    assert!(
        report.contains("CRAWLX_REDIS_KEY_PREFIX") || report.contains("key prefix"),
        "{report}"
    );
    assert!(
        report.contains("CRAWLX_S3_PREFIX") || report.contains("prefix"),
        "{report}"
    );
}
