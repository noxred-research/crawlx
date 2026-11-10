//! The native error and exit contract of the binary: results on stdout, diagnostics on stderr,
//! a failure is never exit 0, and the verbosity switches (`-nc`, `-silent`, `-v`, `-debug`,
//! `DEBUG=true`) never change what stdout carries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output, Stdio};

fn crawlx(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(args)
        .env_remove("DEBUG")
        .env_remove("CRAWLX_LOG")
        .env_remove("NO_COLOR")
        .env_remove("RUST_BACKTRACE")
        .envs(env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn usage_errors_exit_two_and_write_nothing_to_stdout() {
    for args in [
        &["crawl", "--depth", "many", "https://example.test/"][..],
        &["crawl", "--no-such-flag"],
        &["no-such-command"],
        &["extract"],
    ] {
        let output = crawlx(args, &[]);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}: {}", text(&output.stdout));
        assert!(!output.stderr.is_empty(), "{args:?}");
    }
}

#[test]
fn a_failed_command_is_never_exit_zero_and_reports_on_stderr_only() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-request.json");
    let output = crawlx(&["crawl", "--request", missing.to_str().unwrap()], &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = text(&output.stderr);
    assert!(stderr.starts_with("error: "), "{stderr}");
    assert!(
        !stderr.contains("stack backtrace"),
        "no backtrace without DEBUG=true: {stderr}"
    );
}

#[test]
fn version_goes_to_stdout_with_exit_zero_and_nothing_on_stderr() {
    let output = crawlx(&["--version"], &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(
        text(&output.stdout).starts_with("crawlx "),
        "{}",
        text(&output.stdout)
    );
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
}

#[test]
fn colour_is_never_written_to_a_pipe_and_no_color_keeps_stderr_plain() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-request.json");
    let args = ["crawl", "-nc", "--request", missing.to_str().unwrap()];
    for env in [&[][..], &[("NO_COLOR", "1")], &[("CLICOLOR_FORCE", "1")]] {
        let output = crawlx(&args, env);
        assert!(
            !text(&output.stderr).contains('\u{1b}'),
            "{env:?}: {}",
            text(&output.stderr)
        );
        assert!(!text(&output.stdout).contains('\u{1b}'), "{env:?}");
    }
}

#[test]
fn verbosity_switches_never_change_stdout() {
    let plain = crawlx(&["crawl", "--list-output-fields"], &[]);
    assert_eq!(plain.status.code(), Some(0));
    assert!(!plain.stdout.is_empty());
    for (args, env) in [
        (&["crawl", "--list-output-fields", "-v"][..], &[][..]),
        (&["crawl", "--list-output-fields", "-debug"], &[]),
        (&["crawl", "--list-output-fields", "-silent"], &[]),
        (&["crawl", "--list-output-fields"], &[("DEBUG", "true")]),
        (&["--log", "trace", "crawl", "--list-output-fields"], &[]),
    ] {
        let output = crawlx(args, env);
        assert_eq!(output.status.code(), Some(0), "{args:?}");
        assert_eq!(output.stdout, plain.stdout, "{args:?} {env:?}");
    }
}

#[test]
fn debug_adds_the_error_chain_to_stderr_without_touching_the_exit_code_or_stdout() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-request.json");
    let args = ["crawl", "--request", missing.to_str().unwrap()];
    let quiet = crawlx(&args, &[]);
    let debug = crawlx(&args, &[("DEBUG", "true")]);
    assert_eq!(quiet.status.code(), debug.status.code());
    assert!(quiet.stdout.is_empty() && debug.stdout.is_empty());
    assert!(
        text(&debug.stderr).contains("Caused by:"),
        "{}",
        text(&debug.stderr)
    );
    assert!(!text(&quiet.stderr).contains("Caused by:"));
}
