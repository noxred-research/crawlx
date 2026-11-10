//! Every Criterion bench file of this crate is declared in `Cargo.toml` and registered in
//! `ci/bench-gate.sh`, so a bench cannot silently drop out of the regression gate.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// File stems of `benches/*.rs`.
fn bench_files() -> BTreeSet<String> {
    std::fs::read_dir(crate_dir().join("benches"))
        .expect("benches directory")
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .map(|p| p.file_stem().unwrap().to_string_lossy().into_owned())
        .collect()
}

/// `name = "..."` of every `[[bench]]` table whose `harness = false`.
fn declared_benches() -> BTreeSet<String> {
    let manifest = std::fs::read_to_string(crate_dir().join("Cargo.toml")).unwrap();
    let mut out = BTreeSet::new();
    for table in manifest.split("[[bench]]").skip(1) {
        let table = table.split("\n[").next().unwrap();
        let field = |key: &str| {
            table
                .lines()
                .filter_map(|l| l.split_once('='))
                .find(|(k, _)| k.trim() == key)
                .map(|(_, v)| v.trim().trim_matches('"').to_owned())
        };
        assert_eq!(
            field("harness").as_deref(),
            Some("false"),
            "bench {:?} must set `harness = false` (Criterion)",
            field("name")
        );
        out.insert(field("name").expect("bench name"));
    }
    out
}

/// Benches of this crate listed in the `BENCHES` array of `ci/bench-gate.sh`.
fn gated_benches() -> BTreeSet<String> {
    let script = std::fs::read_to_string(crate_dir().join("../../ci/bench-gate.sh")).unwrap();
    let body = script
        .split("BENCHES=(")
        .nth(1)
        .and_then(|rest| rest.split("\n)").next())
        .expect("BENCHES array in ci/bench-gate.sh");
    body.lines()
        .filter_map(|l| l.trim().strip_prefix("crawlx-storage:"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn every_bench_file_is_declared_and_gated() {
    let files = bench_files();
    assert!(!files.is_empty(), "crawlx-storage has Criterion benches");
    assert_eq!(
        files,
        declared_benches(),
        "benches/*.rs and the [[bench]] tables of Cargo.toml must match"
    );
    assert_eq!(
        files,
        gated_benches(),
        "benches/*.rs and the crawlx-storage entries of ci/bench-gate.sh BENCHES must match"
    );
}

#[test]
fn the_plan_benches_exist() {
    let journal = std::fs::read_to_string(crate_dir().join("benches/journal.rs")).unwrap();
    let key = std::fs::read_to_string(crate_dir().join("benches/artifact_key.rs")).unwrap();
    for name in ["action_journal_insert", "transition_write_batch"] {
        assert!(
            journal.contains(&format!("benchmark_group(\"{name}\")")),
            "{name}"
        );
    }
    assert!(key.contains("benchmark_group(\"artifact_key_derive\")"));
}
