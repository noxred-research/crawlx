//! Shared harness of the authored extraction corpus: manifest loading, token-level scoring and
//! the per-family floors every `corpus*.rs` test binary reuses.
//!
//! Every file under `tests/corpus/` was written for this repository (license
//! `authored-for-this-repo`). `manifest.json` and every `manifest.<family>.json` list their files
//! with SHA-256 digests; the loader merges all of them, so a family is added by dropping its
//! fixtures and one manifest file next to the others.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::Deserialize;
use sha2::{Digest, Sha256};

pub const LICENSE: &str = "authored-for-this-repo";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub rights: String,
    pub cases: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub family: String,
    pub license: String,
    pub page_url: String,
    pub files: Files,
    /// Family-specific parameters (policy overrides, selector rules, expected outcome classes).
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Files {
    pub input: FileRef,
    pub gold: FileRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRef {
    pub path: String,
    pub sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Gold {
    pub id: String,
    pub family: String,
    #[allow(dead_code)]
    pub note: String,
    pub expected_text: String,
    pub spans: Vec<Span>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Span {
    pub label: String,
    pub start: usize,
    pub end: usize,
}

pub fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

pub fn read(relative: &str) -> Vec<u8> {
    std::fs::read(corpus_dir().join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes).iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Names of every manifest file in the corpus directory: `manifest.json` first, then each
/// `manifest.<family>.json` in sorted order.
pub fn manifest_files() -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(corpus_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name == "manifest.json" || (name.starts_with("manifest.") && name.ends_with(".json")))
        .collect();
    names.sort_by(|a, b| (a != "manifest.json", a).cmp(&(b != "manifest.json", b)));
    names
}

/// Every manifest merged in `manifest_files` order; the rights statement must agree.
pub fn manifest() -> Manifest {
    let mut merged: Option<Manifest> = None;
    for name in manifest_files() {
        let one: Manifest = serde_json::from_slice(&read(&name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        match &mut merged {
            None => merged = Some(one),
            Some(all) => {
                assert_eq!(all.version, one.version, "{name}: manifest version");
                assert_eq!(all.rights, one.rights, "{name}: manifest rights statement");
                all.cases.extend(one.cases);
            }
        }
    }
    merged.expect("manifest.json exists")
}

pub struct Case {
    pub entry: Entry,
    pub html: String,
    pub gold: Gold,
}

pub fn cases() -> Vec<Case> {
    manifest()
        .cases
        .into_iter()
        .map(|entry| {
            let html = String::from_utf8(read(&entry.files.input.path)).unwrap();
            let gold: Gold = serde_json::from_slice(&read(&entry.files.gold.path)).unwrap();
            Case { entry, html, gold }
        })
        .collect()
}

/// The cases of the named families.
pub fn cases_of(families: &[&str]) -> Vec<Case> {
    cases()
        .into_iter()
        .filter(|case| families.contains(&case.entry.family.as_str()))
        .collect()
}

impl Gold {
    pub fn text_of(&self, label: &str) -> Vec<&str> {
        self.spans
            .iter()
            .filter(|span| span.label == label)
            .map(|span| &self.expected_text[span.start..span.end])
            .collect()
    }
}

// ------------------------------------------------------------------------------------------
// token-level scoring
// ------------------------------------------------------------------------------------------

pub fn is_cjk(c: char) -> bool {
    matches!(c, '\u{3040}'..='\u{30FF}' | '\u{3400}'..='\u{4DBF}' | '\u{4E00}'..='\u{9FFF}' | '\u{AC00}'..='\u{D7AF}')
}

/// Lowercase alphanumeric runs; every Han, kana or Hangul character is a token of its own.
pub fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut run = String::new();
    for c in text.chars() {
        if is_cjk(c) {
            if !run.is_empty() {
                out.push(std::mem::take(&mut run));
            }
            out.push(c.to_string());
        } else if c.is_alphanumeric() {
            run.extend(c.to_lowercase());
        } else if !run.is_empty() {
            out.push(std::mem::take(&mut run));
        }
    }
    if !run.is_empty() {
        out.push(run);
    }
    out
}

pub type Bag = BTreeMap<String, usize>;

pub fn bag<I: IntoIterator<Item = String>>(items: I) -> Bag {
    let mut bag = Bag::new();
    for item in items {
        *bag.entry(item).or_default() += 1;
    }
    bag
}

pub fn size(bag: &Bag) -> usize {
    bag.values().sum()
}

/// Multiset intersection size.
pub fn overlap(a: &Bag, b: &Bag) -> usize {
    a.iter()
        .map(|(k, n)| (*n).min(b.get(k).copied().unwrap_or(0)))
        .sum()
}

/// Multiset difference: counts of `a` not covered by `b`.
pub fn minus(a: &Bag, b: &Bag) -> Bag {
    a.iter()
        .filter_map(|(k, n)| {
            let rest = n.saturating_sub(b.get(k).copied().unwrap_or(0));
            (rest > 0).then(|| (k.clone(), rest))
        })
        .collect()
}

/// True positives, predicted and gold counts.
#[derive(Clone, Copy, Default, Debug)]
pub struct Counts {
    pub tp: usize,
    pub predicted: usize,
    pub gold: usize,
}

impl Counts {
    #[allow(clippy::cast_precision_loss)]
    pub fn ratio(n: usize, d: usize) -> f64 {
        if d == 0 {
            1.0
        } else {
            n as f64 / d as f64
        }
    }
    pub fn precision(self) -> f64 {
        Self::ratio(self.tp, self.predicted)
    }
    pub fn recall(self) -> f64 {
        Self::ratio(self.tp, self.gold)
    }
    pub fn f1(self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
    pub fn add(self, other: Self) -> Self {
        Self {
            tp: self.tp + other.tp,
            predicted: self.predicted + other.predicted,
            gold: self.gold + other.gold,
        }
    }
}

/// Aggregate over cases: macro mean of case F1, micro counts summed, worst case.
#[derive(Debug)]
pub struct Family {
    pub macro_f1: f64,
    pub micro: Counts,
    pub worst_f1: f64,
}

#[allow(clippy::cast_precision_loss)]
pub fn aggregate(per_case: &[Counts]) -> Family {
    Family {
        macro_f1: per_case.iter().map(|c| c.f1()).sum::<f64>() / per_case.len() as f64,
        micro: per_case.iter().fold(Counts::default(), |acc, c| acc.add(*c)),
        worst_f1: per_case.iter().map(|c| c.f1()).fold(1.0, f64::min),
    }
}

pub struct Floors {
    pub macro_f1: f64,
    pub micro_precision: f64,
    pub micro_recall: f64,
    pub worst_case_f1: f64,
}

pub fn check(name: &str, family: &Family, floors: &Floors) {
    eprintln!(
        "{name}: macro_f1={:.4} micro_p={:.4} micro_r={:.4} worst_case_f1={:.4}",
        family.macro_f1,
        family.micro.precision(),
        family.micro.recall(),
        family.worst_f1
    );
    assert!(
        family.macro_f1 >= floors.macro_f1,
        "{name} macro F1 {:.4}",
        family.macro_f1
    );
    assert!(
        family.micro.precision() >= floors.micro_precision,
        "{name} micro precision"
    );
    assert!(
        family.micro.recall() >= floors.micro_recall,
        "{name} micro recall"
    );
    assert!(
        family.worst_f1 >= floors.worst_case_f1,
        "{name} worst case F1 {:.4}",
        family.worst_f1
    );
}

/// Ids listed by a manifest, sorted; used by the corpus-size gates.
pub fn ids_of(family: &str) -> BTreeSet<String> {
    manifest()
        .cases
        .into_iter()
        .filter(|case| case.family == family)
        .map(|case| case.id)
        .collect()
}
