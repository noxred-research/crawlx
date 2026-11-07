//! Authored MIT CLI fixtures. These exercise the actual binary, not a parser stand-in.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::{
    io::ErrorKind,
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
};

const HTML: &str = "<html><head><title>=1+2</title></head><body><main><p>Unicode source café 中文 🙂 contains &lt;tag&gt; &amp; quoted data. The council has reopened the local bridge after a complete inspection.</p></main></body></html>";

fn command(root: &Path, base: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_crawlx"));
    command
        .current_dir(root)
        .args(["extract", "--base-url", base])
        .env("HOME", root)
        .env("CRAWLX_UPDATE_CHECK", "1")
        .env("CRAWLX_RELEASE_URL", base)
        .env("CRAWLX_OTLP_ENDPOINT", base)
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", base)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn fixture(root: &Path) {
    std::fs::create_dir_all(root.join("input/nested")).unwrap();
    // Deliberately create reverse lexical order. Filenames require URL percent-decoding.
    for file in ["z.html", "é.html", "nested/中.html", "a %.html"] {
        std::fs::write(root.join("input").join(file), HTML).unwrap();
    }
}

#[test]
fn actual_batch_is_cwd_relative_lexical_unicode_stable_and_never_connects() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/article", listener.local_addr().unwrap());
    let run = || {
        command(root.path(), &base)
            .args(["--input-dir", "input"])
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, run().stdout);
    let records: Value = serde_json::from_slice(&first.stdout).unwrap();
    let paths: Vec<_> = records
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["source"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["a %.html", "nested/中.html", "z.html", "é.html"]);
    assert!(records[0]["document"]["text"]
        .as_str()
        .unwrap()
        .contains("café 中文 🙂"));
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn all_stream_formats_have_real_collection_or_length_boundaries() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    for format in ["jsonl", "csv", "xml", "html", "text", "markdown"] {
        let output = command(root.path(), "https://fixture.invalid/")
            .args(["--input-dir", "input", "--format", format])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{format}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        match format {
            "jsonl" => {
                assert_eq!(text.lines().count(), 4);
                for line in text.lines() {
                    assert!(serde_json::from_str::<Value>(line).unwrap()["document"].is_object());
                }
            }
            "csv" => {
                assert_eq!(text.matches("source,title,source_url,text,comments").count(), 1);
                assert_eq!(text.matches("\"'=1+2\"").count(), 4);
            }
            "xml" => {
                assert_eq!(text.matches("<?xml").count(), 1);
                assert_eq!(text.matches("<entry source=").count(), 4);
                assert!(text.ends_with("</articles>\n"));
            }
            "html" => {
                assert_eq!(text.matches("<!doctype html>").count(), 1);
                assert_eq!(text.matches("<section data-source=").count(), 4);
            }
            _ => {
                let mut bytes = text.as_bytes();
                let mut count = 0;
                while !bytes.is_empty() {
                    assert_eq!(bytes[0], 0x1e);
                    let header_end = bytes.iter().position(|b| *b == b'\n').unwrap();
                    let header = std::str::from_utf8(&bytes[1..header_end]).unwrap();
                    let (length, source) = header.split_once(' ').unwrap();
                    let length: usize = length.parse().unwrap();
                    assert!(serde_json::from_str::<String>(source).is_ok());
                    assert_eq!(bytes[header_end + 1 + length], b'\n');
                    bytes = &bytes[header_end + 2 + length..];
                    count += 1;
                }
                assert_eq!(count, 4);
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn unsafe_children_fail_independently_and_output_never_clobbers() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("secret"), "outside-secret").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("input/escape")).unwrap();
    let fd = rustix::fs::open(
        root.path().join("input"),
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .unwrap();
    rustix::fs::mkfifoat(fd, "pipe", rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
    let output = command(root.path(), "https://fixture.invalid/")
        .args(["--input-dir", "input"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let errors: Vec<Value> = String::from_utf8(output.stderr)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(errors.iter().filter(|e| e["status"] == "refused").count(), 2);
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("outside-secret"));
    std::fs::write(root.path().join("occupied"), b"keep existing bytes").unwrap();
    let refused = command(root.path(), "https://fixture.invalid/")
        .args(["--input-dir", "input", "--output", "occupied"])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert_eq!(
        std::fs::read(root.path().join("occupied")).unwrap(),
        b"keep existing bytes"
    );
    let created = command(root.path(), "https://fixture.invalid/")
        .args(["--input", "input/z.html", "--output", "new.json"])
        .output()
        .unwrap();
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    assert!(created.stdout.is_empty());
    assert!(serde_json::from_slice::<Value>(&std::fs::read(root.path().join("new.json")).unwrap()).is_ok());
    let inside = command(root.path(), "https://fixture.invalid/")
        .args(["--input-dir", "input", "--output", "input/new.json"])
        .output()
        .unwrap();
    assert!(!inside.status.success());
    assert!(!root.path().join("input/new.json").exists());
    std::os::unix::fs::symlink(root.path().join("input"), root.path().join("rootlink")).unwrap();
    let linked_root = command(root.path(), "https://fixture.invalid/")
        .args(["--input-dir", "rootlink"])
        .output()
        .unwrap();
    assert!(!linked_root.status.success());
    let device = command(root.path(), "https://fixture.invalid/")
        .args(["--input", "/dev/null"])
        .output()
        .unwrap();
    assert!(!device.status.success());
    assert!(device.stdout.is_empty());
}

#[cfg(unix)]
#[test]
fn xml_forbidden_source_scalar_is_an_independent_refusal_not_partial_markup() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    std::fs::write(root.path().join("input/bad\u{1}.html"), HTML).unwrap();
    let output = command(root.path(), "https://fixture.invalid/")
        .args(["--input-dir", "input", "--format", "xml"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let xml = String::from_utf8(output.stdout).unwrap();
    assert_eq!(xml.matches("<entry source=").count(), 4);
    assert!(!xml.contains('\u{1}'));
    assert!(xml.ends_with("</articles>\n"));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .contains("invalid_xml_scalar"));
}

#[test]
fn aggregate_file_depth_and_entry_limits_are_enforced_by_real_consumer() {
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    for options in [
        vec!["--max-files", "1"],
        vec!["--max-depth", "0"],
        vec!["--max-file-bytes", "1"],
        vec!["--max-total-bytes", "1"],
        vec!["--max-entries", "1"],
    ] {
        let output = command(root.path(), "https://fixture.invalid/")
            .args(["--input-dir", "input"])
            .args(&options)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{options:?}");
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn complete_tei_corpus_validates_and_malformed_grammar_and_entities_are_refused() {
    if !Path::new("/usr/bin/xmllint").is_file() {
        eprintln!("skipped: operator-approved /usr/bin/xmllint TEI capability unavailable");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    fixture(root.path());
    let output = command(root.path(), "https://fixture.invalid/")
        .args(["--input-dir", "input", "--format", "tei", "--validate-tei"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::write(root.path().join("corpus.xml"), output.stdout).unwrap();
    let valid = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .current_dir(root.path())
        .args(["extract", "--tei-input", "corpus.xml"])
        .output()
        .unwrap();
    assert!(
        valid.status.success(),
        "{}",
        String::from_utf8_lossy(&valid.stderr)
    );
    let report: Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(report["valid"], true);
    assert_eq!(
        report["sha256"],
        "95fa3f6e47cd196c353124e007bd5c4994989dba8a64496458442136293dafd0"
    );
    assert_eq!(report["license"], "BSD-2-Clause");
    let trap = TcpListener::bind("127.0.0.1:0").unwrap();
    trap.set_nonblocking(true).unwrap();
    for xml in [
        "<TEI xmlns='http://www.tei-c.org/ns/1.0'><body/></TEI>".to_owned(),
        format!(
            "<!DOCTYPE TEI SYSTEM 'http://{}/external.dtd'><TEI xmlns='http://www.tei-c.org/ns/1.0'/>",
            trap.local_addr().unwrap()
        ),
        "<!DOCTYPE TEI [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><TEI>&x;</TEI>".to_owned(),
        "<!DOCTYPE TEI [<!ENTITY a 'aaaaaaaa'><!ENTITY b '&a;&a;&a;&a;'>]><TEI>&b;</TEI>".to_owned(),
    ] {
        std::fs::write(root.path().join("bad.xml"), xml).unwrap();
        let bad = Command::new(env!("CARGO_BIN_EXE_crawlx"))
            .current_dir(root.path())
            .args(["extract", "--tei-input", "bad.xml"])
            .output()
            .unwrap();
        assert!(!bad.status.success());
        assert!(bad.stdout.is_empty());
    }
    assert_eq!(trap.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
}

#[cfg(target_os = "linux")]
#[test]
fn cancellation_while_waiting_for_stdin_exits_130_without_content_or_spool() {
    let root = tempfile::tempdir().unwrap();
    let mut child = command(root.path(), "https://fixture.invalid/")
        .arg("--stdin-html")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    // Wait for the child's actual SIGINT handler rather than racing a fixed sleep.
    loop {
        assert!(
            std::time::Instant::now() < deadline,
            "SIGINT handler was not installed"
        );
        assert!(child.try_wait().unwrap().is_none());
        let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
        let caught = status
            .lines()
            .find_map(|line| line.strip_prefix("SigCgt:\t"))
            .unwrap();
        if u64::from_str_radix(caught.trim(), 16).unwrap() & 2 != 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::INT).unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
