//! One configuration file for every command: `CRAWLX_CONFIG`, else `./crawlx.toml`, selected the
//! same way by `crawlx config check`, `migrate`, `serve`, `worker`, `crawl` and the operator
//! commands. Runs the real binary with a controlled environment.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RUN: &str = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";
const TENANT: &str = "0197a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5c";

/// The binary in `cwd` with only `PATH` and `CRAWLX_ENVIRONMENT=dev` inherited.
fn crawlx(cwd: &Path, args: &[&str], env: &[(&str, &Path)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("CRAWLX_ENVIRONMENT", "dev")
        .env("HOME", cwd)
        .args(args);
    for (name, value) in env {
        cmd.env(name, value);
    }
    cmd.output().unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn write(dir: &Path, name: &str, content: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn migrate_reads_the_database_url_file_of_the_config_named_by_the_environment() {
    let dir = tempfile::tempdir().unwrap();
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let database = dir.path().join("named.db");
    let url_file = write(
        dir.path(),
        "database-url",
        &format!("sqlite:{}\n", database.display()),
    );
    let config = write(
        dir.path(),
        "named.toml",
        &format!("[database]\nurl_file = \"{}\"\n", url_file.display()),
    );
    // the working directory has no crawlx.toml: only CRAWLX_CONFIG can supply the URL
    let output = crawlx(&work, &["migrate"], &[("CRAWLX_CONFIG", &config)]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(text(&output).contains("migrations applied"), "{}", text(&output));
    assert!(
        database.is_file(),
        "the SQLite file named by the config was not created"
    );

    // without it the command asks for a URL, as before
    let output = crawlx(&work, &["migrate"], &[]);
    assert!(!output.status.success());
    assert!(text(&output).contains("pass --database-url"), "{}", text(&output));
}

#[test]
fn the_file_named_by_the_environment_wins_over_the_working_directory_file() {
    let dir = tempfile::tempdir().unwrap();
    let named_db = dir.path().join("named.db");
    let local_db = dir.path().join("local.db");
    let named_url = write(dir.path(), "named-url", &format!("sqlite:{}", named_db.display()));
    let local_url = write(dir.path(), "local-url", &format!("sqlite:{}", local_db.display()));
    let config = write(
        dir.path(),
        "named.toml",
        &format!("[database]\nurl_file = \"{}\"\n", named_url.display()),
    );
    write(
        dir.path(),
        "crawlx.toml",
        &format!("[database]\nurl_file = \"{}\"\n", local_url.display()),
    );
    let output = crawlx(dir.path(), &["migrate"], &[("CRAWLX_CONFIG", &config)]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(named_db.is_file());
    assert!(
        !local_db.exists(),
        "./crawlx.toml was read although CRAWLX_CONFIG names a file"
    );

    // and ./crawlx.toml still applies when the variable is absent
    let output = crawlx(dir.path(), &["migrate"], &[]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(local_db.is_file());
}

/// Every command that reads database settings, with a SQLite URL on the command line.
fn database_commands(url: &str, artifacts: &str) -> Vec<(&'static str, Vec<String>)> {
    let own = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    let with_url = |name: &'static str, args: &[&str]| {
        let mut argv = own(args);
        argv.extend(own(&["--database-url", url]));
        (name, argv)
    };
    vec![
        with_url("migrate", &["migrate"]),
        with_url("serve", &["serve", "--bind", "127.0.0.1:0"]),
        with_url("worker", &["worker"]),
        with_url("crawl", &["crawl", "https://example.invalid/"]),
        with_url("inspect", &["inspect", "run", RUN]),
        with_url("export", &["export", RUN]),
        with_url("replay", &["replay", RUN, "--to", RUN]),
        with_url("admin status", &["admin", "status"]),
        with_url("admin workers", &["admin", "workers"]),
        with_url("admin verify-artifacts", &["admin", "verify-artifacts"]),
        with_url("admin sweep-retention", &["admin", "sweep-retention"]),
        with_url("admin durability-audit", &["admin", "durability-audit"]),
        with_url("archive cancel", &["archive", "cancel", RUN, "--tenant", TENANT]),
        (
            "replay-response",
            own(&[
                "replay-response",
                RUN,
                "--frontier",
                "1",
                "--identity",
                &"0".repeat(64),
                "--tenant",
                TENANT,
                "--database-url",
                url,
                "--artifacts-dir",
                artifacts,
            ]),
        ),
    ]
}

#[test]
fn every_database_command_applies_the_database_section_of_the_named_file() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    let url = format!("sqlite:{}", dir.path().join("x.db").display());
    // a schema is a PostgreSQL concept: a command that read the file refuses it for SQLite
    let schema = write(dir.path(), "schema.toml", "[database]\nschema = \"other\"\n");
    let missing = dir.path().join("missing.toml");
    for (name, argv) in database_commands(&url, artifacts.to_str().unwrap()) {
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = crawlx(dir.path(), &args, &[("CRAWLX_CONFIG", &schema)]);
        let report = text(&output);
        assert!(!output.status.success(), "{name}: {report}");
        assert!(
            report.contains("database.schema is \"other\" but only postgres has schemas"),
            "{name} did not apply the file named by CRAWLX_CONFIG: {report}"
        );

        // a named file that is missing is an error for the command too, never ./crawlx.toml
        write(
            dir.path(),
            "crawlx.toml",
            "[database]\nstatement_timeout_ms = 5000\n",
        );
        let output = crawlx(dir.path(), &args, &[("CRAWLX_CONFIG", &missing)]);
        let report = text(&output);
        assert!(!output.status.success(), "{name}: {report}");
        assert!(
            report.contains("missing.toml"),
            "{name} fell back to another file instead of failing: {report}"
        );
        assert!(
            !report.contains("statement_timeout_ms"),
            "{name} read ./crawlx.toml although CRAWLX_CONFIG names a file: {report}"
        );
        std::fs::remove_file(dir.path().join("crawlx.toml")).unwrap();
    }
}

#[test]
fn every_database_command_discovers_the_working_directory_file_without_the_variable() {
    let dir = tempfile::tempdir().unwrap();
    let artifacts = dir.path().join("artifacts");
    std::fs::create_dir(&artifacts).unwrap();
    let url = format!("sqlite:{}", dir.path().join("x.db").display());
    write(dir.path(), "crawlx.toml", "[database]\nschema = \"other\"\n");
    for (name, argv) in database_commands(&url, artifacts.to_str().unwrap()) {
        let args: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = crawlx(dir.path(), &args, &[]);
        let report = text(&output);
        assert!(!output.status.success(), "{name}: {report}");
        assert!(
            report.contains("database.schema is \"other\" but only postgres has schemas"),
            "{name} did not read ./crawlx.toml: {report}"
        );
    }
}

#[test]
fn a_blank_config_variable_selects_the_working_directory_file() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("local.db");
    let url_file = write(dir.path(), "url", &format!("sqlite:{}", database.display()));
    write(
        dir.path(),
        "crawlx.toml",
        &format!("[database]\nurl_file = \"{}\"\n", url_file.display()),
    );
    let output = crawlx(dir.path(), &["migrate"], &[("CRAWLX_CONFIG", Path::new(" "))]);
    assert!(output.status.success(), "{}", text(&output));
    assert!(database.is_file());
}

/// `CRAWLX_TEST_DATABASE_URL` (PostgreSQL); skipped without it.
#[tokio::test]
async fn migrate_creates_the_schema_of_the_named_file_and_nothing_in_public() {
    let Ok(base) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    if !base.starts_with("postgres") {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not a PostgreSQL URL");
        return;
    }
    let schema = format!("t_cfg_{}", uuid::Uuid::now_v7().simple());
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&base)
        .await
        .unwrap();
    let tables = |schema: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT table_name::text FROM information_schema.tables \
                 WHERE table_schema = $1 AND table_type = 'BASE TABLE' ORDER BY 1",
            )
            .bind(schema)
            .fetch_all(&pool)
            .await
            .unwrap()
        }
    };
    let public_before = tables("public".to_owned()).await;

    let dir = tempfile::tempdir().unwrap();
    // the URL arrives from the environment, the namespace only from the file CRAWLX_CONFIG names
    let url_file = write(dir.path(), "database-url", &base);
    let config = write(
        dir.path(),
        "probe.toml",
        &format!("[database]\nschema = \"{schema}\"\n"),
    );
    let output = crawlx(
        dir.path(),
        &["migrate"],
        &[
            ("CRAWLX_CONFIG", &config),
            ("CRAWLX_DATABASE_URL_FILE", &url_file),
        ],
    );
    let report = text(&output);
    let in_schema = tables(schema.clone()).await;
    let public_after = tables("public".to_owned()).await;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {schema} CASCADE"
    )))
    .execute(&pool)
    .await
    .unwrap();

    assert!(output.status.success(), "{report}");
    assert!(
        in_schema.iter().any(|table| table == "crawl_runs"),
        "no tables in schema {schema}: {report}"
    );
    assert_eq!(public_before, public_after, "migrate touched public: {report}");
}
