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

fn check_with(format: &str, extra: &[(&str, &str)]) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("CRAWLX_ENVIRONMENT", "dev")
        .args(["config", "check", "--format", format]);
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let output = cmd.output().unwrap();
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[test]
fn the_zdr_redis_url_file_is_a_known_secret_file_variable() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("zdr-url");
    std::fs::write(&file, "redis://user:hunter2@127.0.0.1:6390/1\n").unwrap();
    let path = file.to_str().unwrap();
    for format in ["toml", "json"] {
        let (ok, report) = check_with(format, &[("CRAWLX_ZDR_REDIS_URL_FILE", path)]);
        assert!(ok, "{format}: {report}");
        assert!(!report.contains("not a configuration key"), "{format}: {report}");
        assert!(!report.contains("hunter2"), "the URL was printed: {report}");
        assert!(report.contains("zdr_redis"), "{format}: {report}");
    }
}

#[test]
fn the_zdr_redis_url_file_is_validated_like_the_other_secret_files() {
    let dir = tempfile::tempdir().unwrap();
    let url = "redis://user:hunter2@127.0.0.1:6390/1";
    let good = dir.path().join("zdr-url");
    std::fs::write(&good, url).unwrap();
    let empty = dir.path().join("empty");
    std::fs::write(&empty, "  \n").unwrap();
    let missing = dir.path().join("missing");
    let huge = dir.path().join("huge");
    std::fs::write(&huge, "r".repeat(5000)).unwrap();

    let (ok, report) = check_with(
        "toml",
        &[
            ("CRAWLX_ZDR_REDIS_URL_FILE", good.to_str().unwrap()),
            ("CRAWLX_ZDR_REDIS_URL", url),
        ],
    );
    assert!(!ok, "{report}");
    assert!(report.contains("mutually exclusive"), "{report}");
    assert!(!report.contains("hunter2"), "the URL was printed: {report}");

    for (file, needle) in [
        (&missing, "unreadable or oversized"),
        (&huge, "unreadable or oversized"),
        (&empty, "is empty"),
    ] {
        let (ok, report) = check_with("toml", &[("CRAWLX_ZDR_REDIS_URL_FILE", file.to_str().unwrap())]);
        assert!(!ok, "{}: {report}", file.display());
        assert!(report.contains(needle), "{}: {report}", file.display());
    }
}

#[test]
fn config_check_shows_the_object_store_bucket_and_prefix_from_the_environment() {
    let env = [
        ("CRAWLX_S3_BUCKET", "shared-bucket"),
        ("CRAWLX_S3_PREFIX", "tenant-a/blue"),
    ];
    let (ok, report) = check_with("toml", &env);
    assert!(ok, "{report}");
    assert!(report.contains("bucket = \"shared-bucket\""), "{report}");
    assert!(!report.contains("bucket = \"\""), "{report}");
    assert!(report.contains("tenant-a/blue"), "{report}");

    let (ok, report) = check_with("json", &env);
    assert!(ok, "{report}");
    let doc: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(doc["effective"]["object_store"]["bucket"], "shared-bucket");
    assert!(doc["effective"]["object_store"]["prefix"]
        .as_str()
        .is_some_and(|prefix| prefix.contains("tenant-a/blue")));

    // without a bucket the section keeps its empty default
    let (_, report) = check_with("json", &[]);
    let doc: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert_eq!(doc["effective"]["object_store"]["bucket"], "");
    assert!(doc["effective"]["object_store"].get("prefix").is_none());
}

#[test]
fn the_shared_prefix_switch_is_a_known_boolean_s3_variable() {
    let bucket = ("CRAWLX_S3_BUCKET", "shared-bucket");
    let (ok, report) = check_with("toml", &[bucket, ("CRAWLX_S3_ALLOW_SHARED_PREFIX", "1")]);
    assert!(ok, "{report}");
    assert!(!report.contains("not a configuration key"), "{report}");
    let (ok, report) = check_with("toml", &[bucket, ("CRAWLX_S3_ALLOW_SHARED_PREFIX", "maybe")]);
    assert!(!ok, "{report}");
    assert!(report.contains("CRAWLX_S3_ALLOW_SHARED_PREFIX"), "{report}");
}
