//! `crawlx extract --list`, `--backup-dir` and `--zero-retention` through the real binary: list
//! mode discovers without extracting, backups are exclusive and retention-gated, and stdout stays
//! parseable while diagnostics go to stderr.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::{
    io::ErrorKind,
    net::TcpListener,
    path::Path,
    process::{Command, Output, Stdio},
};

const HTML: &str = "<html><head><title>Notes</title></head><body><main><p>The council has reopened the local bridge after a complete inspection of the deck and the cables.</p></main></body></html>";

fn crawlx(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .current_dir(root)
        .arg("extract")
        .args(args)
        .env("HOME", root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

/// `input/{a,b}/index.html` (same file name in two directories) and `input/top.html`.
fn fixture(root: &Path) {
    for dir in ["a", "b"] {
        std::fs::create_dir_all(root.join("input").join(dir)).unwrap();
        std::fs::write(
            root.join("input").join(dir).join("index.html"),
            format!("{HTML}<!-- {dir} -->"),
        )
        .unwrap();
    }
    std::fs::write(root.join("input/top.html"), HTML).unwrap();
}

fn lines(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn list_prints_the_discovered_entries_in_order_and_extracts_nothing() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    // an unreachable base proves list mode needs none and never connects anywhere
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let run = || crawlx(root.path(), &["--input-dir", "input", "--list"]);
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, run().stdout, "deterministic");
    let entries = lines(&first);
    let sources: Vec<&str> = entries.iter().map(|e| e["source"].as_str().unwrap()).collect();
    assert_eq!(sources, ["a/index.html", "b/index.html", "top.html"]);
    assert_eq!(entries[2]["bytes"], HTML.len());
    let stdout = String::from_utf8(first.stdout).unwrap();
    assert!(
        !stdout.contains("council") && !stdout.contains("document"),
        "no extracted content: {stdout}"
    );
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    // nothing was written next to the input
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn list_reports_refused_entries_and_exits_two() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    std::os::unix::fs::symlink("top.html", root.path().join("input/link.html")).unwrap();
    let output = crawlx(root.path(), &["--input-dir", "input", "--list"]);
    assert_eq!(output.status.code(), Some(2));
    let entries = lines(&output);
    let refused = entries.iter().find(|e| e["source"] == "link.html").unwrap();
    assert_eq!(refused["refused"], "symlink_or_special_file");
    assert!(entries
        .iter()
        .any(|e| e["source"] == "top.html" && e["bytes"].is_u64()));
}

#[test]
fn list_conflicts_with_extraction_options_and_needs_a_directory() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    for args in [
        &[
            "--input-dir",
            "input",
            "--list",
            "--base-url",
            "https://fixture.test/",
        ][..],
        &["--input-dir", "input", "--list", "--output", "out.json"],
        &["--input-dir", "input", "--list", "--backup-dir", "bak"],
        &["--input", "input/top.html", "--list"],
        &["--stdin-html", "--list"],
    ] {
        let output = crawlx(root.path(), args);
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    assert!(!root.path().join("out.json").exists() && !root.path().join("bak").exists());
}

#[test]
fn backup_keeps_relative_paths_never_overwrites_and_leaves_stdout_parseable() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let args = [
        "--input-dir",
        "input",
        "--base-url",
        "https://fixture.test/article",
        "--backup-dir",
        "bak",
    ];
    let output = crawlx(root.path(), &args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(records.as_array().unwrap().len(), 3);
    for relative in ["a/index.html", "b/index.html", "top.html"] {
        assert_eq!(
            std::fs::read(root.path().join("bak").join(relative)).unwrap(),
            std::fs::read(root.path().join("input").join(relative)).unwrap(),
            "{relative}"
        );
    }
    // two same-named files stayed two different copies
    assert_ne!(
        std::fs::read(root.path().join("bak/a/index.html")).unwrap(),
        std::fs::read(root.path().join("bak/b/index.html")).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &str| {
            std::fs::metadata(root.path().join(p))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode("bak"), 0o700);
        assert_eq!(mode("bak/top.html"), 0o600);
    }
    // a second run cannot reuse the directory, so nothing is overwritten or merged
    let again = crawlx(root.path(), &args);
    assert!(!again.status.success());
    assert!(
        again.stdout.is_empty(),
        "no extraction after a refused backup directory"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("bak/top.html")).unwrap(),
        HTML
    );
}

#[test]
fn backup_directory_inside_the_source_tree_is_refused_before_anything_is_written() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let output = crawlx(
        root.path(),
        &[
            "--input-dir",
            "input",
            "--base-url",
            "https://fixture.test/article",
            "--backup-dir",
            "input/bak",
        ],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("outside the input source tree"));
    assert!(!root.path().join("input/bak").exists());
}

#[test]
fn a_single_input_file_is_backed_up_under_its_name() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let output = crawlx(
        root.path(),
        &[
            "--input",
            "input/top.html",
            "--base-url",
            "https://fixture.test/article",
            "--backup-dir",
            "bak",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("bak/top.html")).unwrap(),
        HTML
    );
    assert!(serde_json::from_slice::<Value>(&output.stdout).is_ok());
}

#[test]
fn zero_retention_makes_every_disk_sink_impossible() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let base = [
        "--input-dir",
        "input",
        "--base-url",
        "https://fixture.test/article",
    ];
    for sink in [["--backup-dir", "bak"], ["--output", "out.json"]] {
        let mut args = base.to_vec();
        args.push("--zero-retention");
        args.extend(sink);
        let output = crawlx(root.path(), &args);
        assert!(!output.status.success(), "{sink:?}");
        assert!(output.stdout.is_empty(), "{sink:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("cannot be used with"),
            "{sink:?}"
        );
    }
    assert!(!root.path().join("bak").exists() && !root.path().join("out.json").exists());
    // stdout alone is the sink, and nothing appears on disk
    let mut args = base.to_vec();
    args.push("--zero-retention");
    let output = crawlx(root.path(), &args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}
