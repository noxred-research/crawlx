//! The versioned feature manifest (`crawlx config features`): every row names flags and
//! compatibility spellings that exist, a policy (a deviation says how it differs), and tests that
//! exist and are real tests; every compatibility spelling the binary rewrites is accounted for.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::CommandFactory as _;
use crawlx_cli::config_check::FEATURE_MANIFEST;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

fn manifest() -> Value {
    serde_json::from_str(FEATURE_MANIFEST).unwrap()
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect()
}

/// `(spelling, long name)` pairs of the compatibility table, read from its source.
fn compat_table() -> Vec<(String, String)> {
    let source = std::fs::read_to_string(crate_dir().join("src/compat_flags.rs")).unwrap();
    let table = source
        .split("const COMPAT_SHORT")
        .nth(1)
        .unwrap()
        .split("];")
        .next()
        .unwrap();
    table
        .lines()
        .filter_map(|line| {
            let line = line.trim().strip_prefix("(\"")?;
            let (short, rest) = line.split_once("\", \"")?;
            let (long, _) = rest.split_once("\")")?;
            Some((short.to_owned(), long.to_owned()))
        })
        .collect()
}

#[test]
fn the_manifest_is_versioned_pins_a_baseline_and_covers_every_flag_row() {
    let m = manifest();
    assert_eq!(m["version"], 1);
    assert_eq!(m["baseline"]["dialect"], "surface-flags");
    assert_eq!(m["baseline"]["release"], "1.8.0");
    let inventory = std::fs::read_to_string(
        crate_dir()
            .join("../..")
            .join(m["baseline"]["inventory"].as_str().unwrap()),
    )
    .unwrap();
    let known: BTreeSet<&str> = inventory
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split('\t').next())
        .collect();
    let mut ids = BTreeSet::new();
    for row in m["rows"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        assert!(ids.insert(id), "duplicate row {id}");
        assert!(known.contains(id), "{id} is not an inventory row of the baseline");
    }
    for n in 1..=23 {
        assert!(
            ids.contains(format!("SR-{n:02}").as_str()),
            "SR-{n:02} has no manifest row"
        );
    }
    assert!(ids.contains("SR-G12"));
}

#[test]
fn every_row_names_real_flags_compat_spellings_and_existing_gates() {
    let m = manifest();
    let policies: BTreeSet<&str> = m["policies"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let cli = crawlx_cli::Cli::command();
    let flags_of = |name: &str| -> BTreeSet<String> {
        cli.find_subcommand(name)
            .unwrap_or_else(|| panic!("no subcommand {name}"))
            .get_arguments()
            .flat_map(|a| {
                let aliases = a.get_all_aliases().into_iter().flatten().map(str::to_owned);
                a.get_long().map(str::to_owned).into_iter().chain(aliases)
            })
            .collect()
    };
    let tests_dir = crate_dir().join("tests");
    for row in m["rows"].as_array().unwrap() {
        let id = row["id"].as_str().unwrap();
        let policy = row["policy"].as_str().unwrap();
        assert!(policies.contains(policy), "{id}: policy {policy}");
        assert_eq!(
            row.get("deviation").is_some(),
            policy == "deviation",
            "{id}: a deviation row says how it differs, and only a deviation row does"
        );
        let mut row_flags = BTreeSet::new();
        for flag in strings(&row["flags"]) {
            match flag.split_once(" --") {
                Some((command, long)) => {
                    assert!(
                        flags_of(command).contains(long),
                        "{id}: `{flag}` is not a flag of `{command}`"
                    );
                    row_flags.insert(format!("{command} --{long}"));
                }
                None => {
                    let (parent, child) = flag.split_once(' ').unwrap();
                    assert!(
                        cli.find_subcommand(parent)
                            .unwrap()
                            .find_subcommand(child)
                            .is_some(),
                        "{id}: `{flag}` is not a command"
                    );
                }
            }
        }
        assert!(!strings(&row["gates"]).is_empty(), "{id}: no gate");
        for gate in strings(&row["gates"]) {
            let (file, name) = gate.split_once("::").unwrap();
            let source =
                std::fs::read_to_string(tests_dir.join(file)).unwrap_or_else(|e| panic!("{id}: {gate}: {e}"));
            let at = source
                .find(&format!("fn {name}("))
                .unwrap_or_else(|| panic!("{id}: {gate} does not exist"));
            let before: Vec<&str> = source[..at].lines().rev().take(4).collect();
            assert!(
                before
                    .iter()
                    .any(|l| l.contains("#[test]") || l.contains("#[tokio::test")),
                "{id}: {gate} is not a test"
            );
        }
        for spelling in strings(&row["compat"]) {
            let rewritten = crawlx_cli::normalize_args(["crawlx", "crawl", spelling]);
            let long = rewritten[2].to_str().unwrap().to_owned();
            assert!(
                long.starts_with("--"),
                "{id}: {spelling} is not a compatibility spelling"
            );
            assert!(
                row_flags.contains(&format!("crawl {long}")),
                "{id}: {spelling} rewrites to {long}, which the row does not list"
            );
        }
    }
}

#[test]
fn every_compatibility_spelling_of_the_binary_belongs_to_a_row() {
    let m = manifest();
    let mut owner: BTreeMap<String, &str> = BTreeMap::new();
    for row in m["rows"].as_array().unwrap() {
        for spelling in strings(&row["compat"]) {
            owner.insert(spelling.to_owned(), row["id"].as_str().unwrap());
        }
    }
    let table = compat_table();
    assert!(
        table.len() > 60,
        "the compatibility table was not read: {} entries",
        table.len()
    );
    let missing: Vec<String> = table
        .iter()
        .map(|(short, _)| format!("-{short}"))
        .filter(|spelling| !owner.contains_key(spelling))
        .collect();
    assert!(
        missing.is_empty(),
        "compatibility spellings without a manifest row: {missing:?}"
    );
}

#[test]
fn the_command_prints_the_same_document() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_crawlx"))
        .args(["config", "features"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), FEATURE_MANIFEST);
}
