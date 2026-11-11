//! Registry of the identity-version checks CI runs by name.
//!
//! The V2 identity tests and the dual-mode (V1 decides, V2 recorded) tests are selected by
//! name in the `unit` job (`cargo test -p crawlx-elements -- v2_` and
//! `cargo test -p crawlx-worker --test replay_hybrid -- dual_mode`). A rename or an `#[ignore]`
//! would make that filter match fewer tests (or none) and the job would still pass. This test
//! fails first: every gated test must still exist, be a test, and not be ignored.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

/// `(file relative to `crates/`, test function name)` of every identity check CI selects by name.
const GATED: [(&str, &str); 4] = [
    (
        "crawlx-elements/src/identity.rs",
        "v2_locale_names_are_stable_and_domains_never_overlap",
    ),
    (
        "crawlx-elements/tests/weight_regression.rs",
        "v2_keeps_all_353_pairs_at_perfect_precision_and_recall",
    ),
    (
        "crawlx-worker/tests/replay_hybrid.rs",
        "dual_mode_writes_version_pairs_in_memory",
    ),
    (
        "crawlx-worker/tests/replay_hybrid.rs",
        "dual_mode_writes_version_pairs_in_postgres",
    ),
];

/// Why a gated test no longer runs, or `None` when `source` still defines it as an active test.
fn gate_problem(source: &str, name: &str) -> Option<String> {
    let lines: Vec<&str> = source.lines().collect();
    let definition = format!("fn {name}(");
    let mut found = lines.iter().enumerate().filter(|(_, l)| l.contains(&definition));
    let Some((index, _)) = found.next() else {
        return Some(format!("`{name}` is not defined (renamed or removed)"));
    };
    if found.next().is_some() {
        return Some(format!("`{name}` is defined more than once"));
    }
    // the attribute and doc block directly above the signature
    let mut attributes = Vec::new();
    for line in lines[..index].iter().rev() {
        let line = line.trim();
        if line.starts_with("#[") || line.starts_with("///") || line.starts_with("//") {
            attributes.push(line);
        } else {
            break;
        }
    }
    if let Some(ignored) = attributes.iter().find(|a| a.starts_with("#[ignore")) {
        return Some(format!("`{name}` is ignored: {ignored}"));
    }
    let is_test = attributes
        .iter()
        .any(|a| a.starts_with("#[test]") || a.starts_with("#[tokio::test"));
    if !is_test {
        return Some(format!("`{name}` is not a test (no #[test] / #[tokio::test])"));
    }
    None
}

#[test]
fn every_identity_check_selected_by_ci_still_exists_and_is_not_ignored() {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut problems = Vec::new();
    for (file, name) in GATED {
        let path = crates.join(file);
        match std::fs::read_to_string(&path) {
            Ok(source) => problems.extend(gate_problem(&source, name).map(|p| format!("{file}: {p}"))),
            Err(e) => problems.push(format!("{file}: unreadable: {e}")),
        }
    }
    assert!(
        problems.is_empty(),
        "identity gate registry is stale:\n{}",
        problems.join("\n")
    );
}

#[test]
fn the_registry_detects_a_removed_renamed_ignored_or_demoted_test() {
    let active = "#[test]\nfn v2_a() {}\n";
    assert_eq!(gate_problem(active, "v2_a"), None);
    let async_active = "/// doc\n#[tokio::test]\nasync fn dual_b() {}\n";
    assert_eq!(gate_problem(async_active, "dual_b"), None);
    assert!(gate_problem(active, "v2_renamed")
        .unwrap()
        .contains("not defined"));
    let ignored = "#[test]\n#[ignore = \"slow\"]\nfn v2_a() {}\n";
    assert!(gate_problem(ignored, "v2_a").unwrap().contains("ignored"));
    let ignored_first = "#[ignore]\n#[tokio::test]\nasync fn v2_a() {}\n";
    assert!(gate_problem(ignored_first, "v2_a").unwrap().contains("ignored"));
    let demoted = "fn v2_a() {}\n";
    assert!(gate_problem(demoted, "v2_a").unwrap().contains("not a test"));
    let duplicated = "#[test]\nfn v2_a() {}\n#[test]\nfn v2_a() {}\n";
    assert!(gate_problem(duplicated, "v2_a")
        .unwrap()
        .contains("more than once"));
}
