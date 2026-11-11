//! Operator commands over every database engine: the URL scheme picks the engine, the database
//! commands refuse what an engine cannot serve with a typed `refused: <code>: ...` message, and no
//! command panics, creates a mistyped database file or hides the cause behind a generic error.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::process::{Command, Output, Stdio};

const TENANT: &str = "00000000-0000-4000-8000-000000000002";
const RUN: &str = "01a1cabb-492f-76e6-a9e9-871ec477e7a5";
const KEY_ONE: &str = "cx_live_refusalone234567abcdefghij";
const KEY_TWO: &str = "cx_live_refusaltwo234567abcdefghij";

fn crawlx(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    command.args(args);
    for name in [
        "DEBUG",
        "CRAWLX_LOG",
        "NO_COLOR",
        "RUST_BACKTRACE",
        "CRAWLX_DATABASE_URL",
        "CRAWLX_DATABASE_URL_FILE",
        "CRAWLX_API_DATABASE_URL",
        "CRAWLX_ENVIRONMENT",
        "CRAWLX_SQLITE_ALLOW_MULTI_TENANT",
        "CRAWLX_ARTIFACT_KEY_FILE",
        "CRAWLX_ARTIFACT_KMS_KEY_ID",
        "CRAWLX_SECRET_REDIS_URL",
    ] {
        command.env_remove(name);
    }
    command
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn migrated_sqlite(dir: &Path) -> String {
    let url = format!("sqlite:{}", dir.join("db.sqlite").display());
    let output = crawlx(&["migrate", "--database-url", &url], &[]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    url
}

/// Every operator command that reads run data, as an argument list for `url`.
fn database_commands(url: &str, dir: &Path) -> Vec<(&'static str, Vec<String>)> {
    let artifacts = dir.join("artifacts");
    std::fs::create_dir_all(&artifacts).unwrap();
    let artifacts = artifacts.display().to_string();
    let scope = dir.join("scope.json");
    std::fs::write(
        &scope,
        format!(
            r#"{{"tenant":"{TENANT}","principal":"anonymous","name":"p","allowed_origins":["http://127.0.0.1:1"],"backend_build":"{}","egress":"{}"}}"#,
            "a".repeat(64),
            "b".repeat(64)
        ),
    )
    .unwrap();
    let owned = |args: &[&str]| args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>();
    vec![
        (
            "archive export",
            owned(&[
                "archive",
                "export",
                RUN,
                "--tenant",
                TENANT,
                "--out",
                dir.join("export").to_str().unwrap(),
                "--artifacts-dir",
                &artifacts,
                "--database-url",
                url,
            ]),
        ),
        (
            "replay-response",
            owned(&[
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
                &artifacts,
            ]),
        ),
        (
            "reparse",
            owned(&[
                "reparse",
                RUN,
                "--frontier",
                "1",
                "--tenant",
                TENANT,
                "--principal",
                "local",
                "--database-url",
                url,
                "--artifacts-dir",
                &artifacts,
            ]),
        ),
        (
            "profiles",
            owned(&[
                "profiles",
                "--tenant",
                TENANT,
                "--run",
                RUN,
                "--session",
                "00000000-0000-4000-8000-0000000000aa",
                "--worker",
                "00000000-0000-4000-8000-0000000000bb",
                "--fence",
                "1",
                "--scope",
                scope.to_str().unwrap(),
                "--key-ref",
                "env://NO_SUCH_PROFILE_KEY",
                "--database-url",
                url,
                "inspect",
                "--generation",
                "1",
            ]),
        ),
        ("inspect", owned(&["inspect", "run", RUN, "--database-url", url])),
    ]
}

fn key_file(dir: &Path) -> String {
    let path = dir.join("artifact.key");
    std::fs::write(&path, "00".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path.display().to_string()
}

#[test]
fn every_database_command_refuses_an_unknown_scheme_with_the_typed_message() {
    let dir = tempfile::tempdir().unwrap();
    let key = key_file(dir.path());
    for (name, args) in database_commands("oracle://db.example/crawlx", dir.path()) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = crawlx(&args, &[("CRAWLX_ARTIFACT_KEY_FILE", &key)]);
        assert_eq!(output.status.code(), Some(2), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains(
                "refused: scheme: unsupported database url scheme; expected postgres, mariadb or sqlite"
            ),
            "{name}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn database_commands_run_on_sqlite_and_report_a_missing_run_not_an_unavailable_engine() {
    let dir = tempfile::tempdir().unwrap();
    let url = migrated_sqlite(dir.path());
    let key = key_file(dir.path());
    for (name, args) in database_commands(&url, dir.path()) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = crawlx(&args, &[("CRAWLX_ARTIFACT_KEY_FILE", &key)]);
        let text = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{name}: {text}");
        assert!(text.starts_with("error: "), "{name}: {text}");
        for banned in ["backend_unimplemented", "panicked", "database operation failed"] {
            assert!(!text.contains(banned), "{name}: {text}");
        }
        assert!(
            output.stdout.is_empty(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

/// Opening a database reads only the `[database]` overrides: development and integration
/// variables in the environment (failpoints, compatibility mode) never stop a command, while
/// a database override still applies.
#[test]
fn database_commands_ignore_unrelated_variables_and_honour_database_overrides() {
    let dir = tempfile::tempdir().unwrap();
    let url = migrated_sqlite(dir.path());
    let key = key_file(dir.path());
    for (name, args) in database_commands(&url, dir.path()) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let unrelated = crawlx(
            &args,
            &[
                ("CRAWLX_ARTIFACT_KEY_FILE", &key),
                ("CRAWLX_FAILPOINTS", "during_outcome_tx=sleep(1)"),
                ("CRAWLX_COMPAT_MODE", "strict"),
            ],
        );
        let text = stderr(&unrelated);
        assert!(!text.contains("is not a configuration key"), "{name}: {text}");
        let overridden = crawlx(
            &args,
            &[
                ("CRAWLX_ARTIFACT_KEY_FILE", &key),
                ("CRAWLX_DATABASE__STATEMENT_TIMEOUT_MS", "5"),
            ],
        );
        let text = stderr(&overridden);
        assert_eq!(overridden.status.code(), Some(2), "{name}: {text}");
        assert!(
            text.contains("no server-side statement timeout"),
            "{name}: {text}"
        );
    }
}

#[test]
fn a_mistyped_sqlite_path_is_refused_and_not_created() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite:{}", dir.path().join("typo.sqlite").display());
    let key = key_file(dir.path());
    for (name, args) in database_commands(&url, dir.path()) {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = crawlx(&args, &[("CRAWLX_ARTIFACT_KEY_FILE", &key)]);
        assert_eq!(output.status.code(), Some(2), "{name}: {}", stderr(&output));
        assert!(
            stderr(&output).contains("connecting to the database: "),
            "{name}: {}",
            stderr(&output)
        );
    }
    assert!(!dir.path().join("typo.sqlite").exists());
}

#[test]
fn the_safety_auditor_is_refused_on_sqlite_and_mariadb_before_any_connection() {
    let sqlite = "sqlite:/nonexistent/crawlx.sqlite";
    let mariadb = "mysql://nobody:nothing@127.0.0.1:1/none";
    let refused = |reader: &str, pause: &str| {
        let output = crawlx(
            &[
                "admin",
                "safety-audit",
                "--reader-database-url",
                reader,
                "--pause-database-url",
                pause,
            ],
            &[],
        );
        assert_eq!(output.status.code(), Some(2));
        stderr(&output)
    };
    let expected = "error: refused: sqlite_safety_auditor: the independent safety auditor needs two \
                    distinct database identities (reader and pauser); sqlite has none\n";
    assert_eq!(refused(sqlite, sqlite), expected);
    assert_eq!(refused(sqlite, mariadb), expected);
    // the reader is checked first: an engine without the auditor is refused before the second URL
    assert_eq!(
        refused(mariadb, sqlite),
        "error: refused: backend_unimplemented: the independent safety auditor is not available on \
         mariadb yet; use postgres\n"
    );
    assert_eq!(
        refused(mariadb, mariadb),
        "error: refused: backend_unimplemented: the independent safety auditor is not available on \
         mariadb yet; use postgres\n"
    );
}

fn serve(url: &str, dir: &Path, keys: &[&str], env: &[(&str, &str)], extra: &[&str]) -> Output {
    let artifacts = dir.join("served-artifacts");
    let mut args: Vec<String> = [
        "serve",
        "--bind",
        "127.0.0.1:0",
        "--metrics-bind",
        "127.0.0.1:0",
        "--database-url",
        url,
        "--artifacts-dir",
        artifacts.to_str().unwrap(),
    ]
    .iter()
    .map(|a| (*a).to_owned())
    .collect();
    for (tenant, key) in ["one", "two"].iter().zip(keys) {
        args.push("--api-key".to_owned());
        args.push(format!("{tenant}={key}"));
    }
    args.extend(extra.iter().map(|a| (*a).to_owned()));
    // the API stops on its own only through a refusal; bound the others
    let mut child = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(&args)
        .env_remove("CRAWLX_DATABASE_URL")
        .env_remove("CRAWLX_API_DATABASE_URL")
        .env_remove("CRAWLX_SQLITE_ALLOW_MULTI_TENANT")
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn a_second_tenant_is_refused_on_production_sqlite_unless_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let url = migrated_sqlite(dir.path());
    let output = serve(
        &url,
        dir.path(),
        &[KEY_ONE, KEY_TWO],
        &[("CRAWLX_ENVIRONMENT", "prod")],
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "refused: sqlite_multi_tenant: sqlite enforces tenant isolation in the application only; \
             this database already has a tenant; set CRAWLX_SQLITE_ALLOW_MULTI_TENANT=1 to accept \
             that, or use postgres"
        ),
        "{}",
        stderr(&output)
    );
    // with the acknowledgement the same start-up gets past the refusal and serves until stopped
    let accepted = serve(
        &url,
        dir.path(),
        &[KEY_ONE, KEY_TWO],
        &[
            ("CRAWLX_ENVIRONMENT", "prod"),
            ("CRAWLX_SQLITE_ALLOW_MULTI_TENANT", "1"),
        ],
        &[],
    );
    assert!(
        !stderr(&accepted).contains("sqlite_multi_tenant"),
        "{}",
        stderr(&accepted)
    );
}

#[test]
fn sqlite_refuses_a_request_login() {
    let dir = tempfile::tempdir().unwrap();
    let url = migrated_sqlite(dir.path());
    let output = serve(
        &url,
        dir.path(),
        &[],
        &[("CRAWLX_ENVIRONMENT", "dev")],
        &["--api-database-url", "postgres://nobody@127.0.0.1:1/none"],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
    assert!(
        stderr(&output).contains(
            "refused: sqlite_no_roles: sqlite has no database roles; remove CRAWLX_API_DATABASE_URL \
             (the API uses the same file under application-enforced tenancy)"
        ),
        "{}",
        stderr(&output)
    );
}
