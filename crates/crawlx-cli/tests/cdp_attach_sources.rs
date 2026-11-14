//! Where `crawl` and `worker` take the browser's DevTools URL from. The URL is a bearer token, so
//! the real binary reads it from a private file or the environment, refuses an unsafe file or more
//! than one source, warns when it is passed as an argument, and never prints it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_cli::cdp_attach::ARGV_DEPRECATION;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const URL: &str = "ws://127.0.0.1:9222/devtools/browser/lease-token-4242";

fn url_file(dir: &Path, mode: u32) -> std::path::PathBuf {
    let path = dir.join("cdp-ws-url");
    std::fs::write(&path, format!("{URL}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn crawlx(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    cmd.current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("NO_COLOR", "1")
        .args(args)
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn worker_warns_once_when_the_url_is_an_argument_and_never_prints_it() {
    let dir = tempfile::tempdir().unwrap();
    let out = crawlx(dir.path(), &[], &["worker", "--cdp-ws-url", URL]);
    // no database is configured: the command stops after the attach settings were read
    assert!(!out.status.success());
    let err = stderr(&out);
    assert_eq!(err.matches(ARGV_DEPRECATION).count(), 1, "{err}");
    assert!(err.contains("leases work from the database"), "{err}");
    assert!(!text(&out).contains("lease-token-4242"), "{}", text(&out));
    // the compatibility spelling is the same argument
    let out = crawlx(dir.path(), &[], &["worker", "--chrome-ws-url", URL]);
    assert!(stderr(&out).contains(ARGV_DEPRECATION));
    assert!(!text(&out).contains("lease-token-4242"));
}

#[test]
fn worker_takes_the_url_from_a_private_file_or_the_environment_without_a_warning() {
    let dir = tempfile::tempdir().unwrap();
    let file = url_file(dir.path(), 0o600);
    let file = file.to_str().unwrap();
    for (env, args) in [
        (vec![], vec!["worker", "--cdp-ws-url-file", file]),
        (vec![("CRAWLX_CDP_WS_URL_FILE", file)], vec!["worker"]),
        (vec![("CRAWLX_CDP_WS_URL", URL)], vec!["worker", "--no-incognito"]),
    ] {
        let out = crawlx(dir.path(), &env, &args);
        let err = stderr(&out);
        // the attach settings were accepted: the command gets as far as the database check
        assert!(err.contains("leases work from the database"), "{args:?}: {err}");
        assert!(!err.contains("deprecated"), "{args:?}: {err}");
        assert!(
            !text(&out).contains("lease-token-4242"),
            "{args:?}: {}",
            text(&out)
        );
    }
}

#[test]
fn a_url_file_the_group_or_others_can_read_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o644, 0o640, 0o604] {
        let file = url_file(dir.path(), mode);
        let out = crawlx(
            dir.path(),
            &[],
            &["worker", "--cdp-ws-url-file", file.to_str().unwrap()],
        );
        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(
            err.contains(&format!("mode {mode:04o}")) && err.contains("chmod 600"),
            "{err}"
        );
        assert!(!err.contains("leases work from the database"), "{err}");
        assert!(!text(&out).contains("lease-token-4242"), "{}", text(&out));
    }
}

#[test]
fn two_sources_are_an_error_that_names_them_not_the_url() {
    let dir = tempfile::tempdir().unwrap();
    let file = url_file(dir.path(), 0o600);
    let file = file.to_str().unwrap();
    type Case<'a> = (Vec<(&'a str, &'a str)>, Vec<&'a str>);
    let cases: [Case; 3] = [
        (
            vec![("CRAWLX_CDP_WS_URL", URL)],
            vec!["worker", "--cdp-ws-url-file", file],
        ),
        (
            vec![("CRAWLX_CDP_WS_URL", URL), ("CRAWLX_CDP_WS_URL_FILE", file)],
            vec!["worker"],
        ),
        (
            vec![],
            vec!["worker", "--cdp-ws-url", URL, "--cdp-ws-url-file", file],
        ),
    ];
    for (env, args) in cases {
        let out = crawlx(dir.path(), &env, &args);
        assert!(!out.status.success());
        let err = stderr(&out);
        assert!(err.contains("more than once"), "{args:?}: {err}");
        assert!(
            !text(&out).contains("lease-token-4242"),
            "{args:?}: {}",
            text(&out)
        );
    }
}

#[test]
fn a_malformed_url_is_refused_without_being_echoed() {
    let dir = tempfile::tempdir().unwrap();
    let bad = "https://user:hunter2@browser.example/devtools/browser/tok-9";
    for (env, args) in [
        (vec![], vec!["worker", "--cdp-ws-url", bad]),
        (vec![("CRAWLX_CDP_WS_URL", bad)], vec!["worker"]),
    ] {
        let out = crawlx(dir.path(), &env, &args);
        assert!(!out.status.success());
        let all = text(&out);
        assert!(all.contains("not a ws:// or wss:// URL"), "{all}");
        assert!(!all.contains("hunter2") && !all.contains("tok-9"), "{all}");
    }
}

#[test]
fn crawl_applies_the_same_sources_and_warning() {
    let dir = tempfile::tempdir().unwrap();
    let file = url_file(dir.path(), 0o600);
    let out = crawlx(
        dir.path(),
        &[],
        &[
            "crawl",
            "https://example.test/",
            "--cdp-ws-url",
            URL,
            "--cdp-ws-url-file",
            file.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let all = text(&out);
    assert!(all.contains(ARGV_DEPRECATION), "{all}");
    assert!(all.contains("more than once"), "{all}");
    assert!(!all.contains("lease-token-4242"), "{all}");

    let loose = url_file(dir.path(), 0o644);
    let out = crawlx(
        dir.path(),
        &[],
        &[
            "crawl",
            "https://example.test/",
            "--cdp-ws-url-file",
            loose.to_str().unwrap(),
        ],
    );
    assert!(!out.status.success());
    let all = text(&out);
    assert!(all.contains("chmod 600") && !all.contains("deprecated"), "{all}");
    assert!(!all.contains("lease-token-4242"), "{all}");
}

#[test]
fn config_check_reports_the_environment_sources_without_the_url() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("chromium-pin.toml"),
        "[chromium]\nversion = \"1\"\n",
    )
    .unwrap();
    let file = url_file(dir.path(), 0o600);
    let ok = crawlx(
        dir.path(),
        &[("CRAWLX_ENVIRONMENT", "dev"), ("CRAWLX_CDP_WS_URL", URL)],
        &["config", "check", "--format", "json"],
    );
    let all = text(&ok);
    assert!(ok.status.success(), "{all}");
    assert!(!all.contains("lease-token-4242"), "{all}");
    assert!(all.contains("<redacted>"), "{all}");
    let both = crawlx(
        dir.path(),
        &[
            ("CRAWLX_ENVIRONMENT", "dev"),
            ("CRAWLX_CDP_WS_URL", URL),
            ("CRAWLX_CDP_WS_URL_FILE", file.to_str().unwrap()),
        ],
        &["config", "check", "--format", "json"],
    );
    let all = text(&both);
    assert!(!both.status.success(), "{all}");
    assert!(
        all.contains("browser.attach") && !all.contains("lease-token-4242"),
        "{all}"
    );
}
