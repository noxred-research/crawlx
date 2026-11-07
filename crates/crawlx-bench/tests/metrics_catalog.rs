//! Every catalogued metric has a producer: each `names::*` constant of
//! `crawlx_telemetry::metrics::catalog` is referenced from non-test code of
//! some crate other than `crawlx-telemetry` itself. Every catalogued metric must have a real producer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_telemetry::metrics::catalog::{CATALOG, NAMES_BY_IDENT};
use std::fs;
use std::path::{Path, PathBuf};

fn crates_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates/")
        .to_path_buf()
}

/// Non-test source of a `.rs` file: everything before its first `#[cfg(test)]` *module* (the
/// repository convention for inline test modules). Item-level `#[cfg(test)]` (an import, a
/// `pub(crate)` test accessor) is ordinary production-file code and must not hide the producers
/// that follow it.
fn non_test_source(path: &Path) -> String {
    const MARKER: &str = "#[cfg(test)]";
    let text = fs::read_to_string(path).expect("read source");
    let mut from = 0;
    while let Some(found) = text[from..].find(MARKER) {
        let at = from + found;
        let mut rest = text[at + MARKER.len()..].trim_start();
        // further attributes (`#[path = "..."]`) may sit between the marker and the item
        while rest.starts_with("#[") {
            match rest.find(']') {
                Some(end) => rest = rest[end + 1..].trim_start(),
                None => break,
            }
        }
        if rest.starts_with("mod ") || rest.starts_with("pub(crate) mod ") {
            return text[..at].to_owned();
        }
        from = at + MARKER.len();
    }
    text
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("read dir")
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// `(crate name, source)` for every `crates/*/src/**/*.rs` outside the
/// telemetry crate, test modules stripped.
fn producer_sources() -> Vec<(String, String)> {
    let mut crates: Vec<_> = fs::read_dir(crates_dir())
        .expect("read crates/")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.join("src").is_dir())
        .collect();
    crates.sort();
    let mut out = Vec::new();
    for krate in crates {
        let name = krate.file_name().unwrap().to_string_lossy().into_owned();
        if name == "crawlx-telemetry" {
            continue;
        }
        let mut files = Vec::new();
        walk(&krate.join("src"), &mut files);
        let mut source = String::new();
        for f in files {
            source.push_str(&non_test_source(&f));
            source.push('\n');
        }
        out.push((name, source));
    }
    out
}

#[test]
fn every_catalogued_metric_is_produced_outside_the_telemetry_crate() {
    let sources = producer_sources();
    assert!(sources.len() > 10, "found {} crates", sources.len());
    let mut orphans = Vec::new();
    for (ident, name) in NAMES_BY_IDENT {
        let by_ident = format!("names::{ident}");
        let by_literal = format!("\"{name}\"");
        let produced = sources
            .iter()
            .any(|(_, src)| src.contains(&by_ident) || src.contains(&by_literal));
        if !produced {
            orphans.push(format!("{name}: no producer"));
        }
    }
    assert!(orphans.is_empty(), "catalog/producer mismatch: {orphans:#?}");
}

#[test]
fn the_ident_table_matches_the_catalog() {
    assert_eq!(NAMES_BY_IDENT.len(), CATALOG.len());
    for ((ident, name), def) in NAMES_BY_IDENT.iter().zip(CATALOG) {
        assert_eq!(*name, def.name);
        let derived = name
            .strip_prefix("crawlx.")
            .expect("catalog names start with crawlx.")
            .replace('.', "_")
            .to_ascii_uppercase();
        assert_eq!(*ident, derived, "constant for {name}");
    }
}
