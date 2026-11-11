//! The `-mdc` / `-fdc` condition language through the real binary: a function the language does
//! not have is refused before any request is made, naming the flag, the function and its byte
//! position. The function table itself is checked against the pinned reference in the worker crate's
//! `output_dsl_functions` test.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

fn crawl_with(flag: &str, condition: &str) -> (bool, String) {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("CRAWLX_ENVIRONMENT", "dev")
        // a refused condition must stop before any request is made
        .args(["crawl", flag, condition, "https://example.com/"])
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

#[test]
fn an_unsupported_or_unlisted_condition_function_is_refused_before_the_crawl_with_its_position() {
    for (flag, condition, needles) in [
        (
            "--match-condition",
            "status_code == 200 && rand_int(5) == 1",
            &["--match-condition", "rand_int", "byte 22", "not supported"][..],
        ),
        (
            "--filter-condition",
            "gzip(body) == 'x'",
            &["--filter-condition", "gzip", "byte 0", "not supported"][..],
        ),
        (
            "-mdc",
            "contains(url, 'a') || eval(url)",
            &["--match-condition", "eval", "byte 22", "unknown function"][..],
        ),
        (
            "-fdc",
            "status_code == 200 && system('id')",
            &["--filter-condition", "system", "byte 22", "unknown function"][..],
        ),
    ] {
        let (ok, text) = crawl_with(flag, condition);
        assert!(!ok, "{condition}: {text}");
        for needle in needles {
            assert!(
                text.contains(needle),
                "{condition}: missing {needle:?} in:\n{text}"
            );
        }
    }
}
