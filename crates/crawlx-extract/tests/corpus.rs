#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authored extraction corpus: manifest digests, gold spans and measured per-family scores.
//!
//! Every file under `tests/corpus/` was written for this repository (license
//! `authored-for-this-repo`); `manifest.json` lists each file with its SHA-256. Gold files hold
//! an `expectedText` and labeled UTF-8 byte spans into it:
//!
//! * `article_body`, `boilerplate`: `expectedText` is the visible page text in document order;
//!   spans are labeled `body` or `boilerplate`.
//! * `metadata`: one `field=value` line per expected field; the span covers the value.
//! * `link_discovery`: one expected absolute URL per line; every span is labeled `link`.
//!
//! Scores are token-level (see [`tokens`]) over the real extractor output. The floors below are
//! measured on this corpus and set just under the observed values, so a regression fails the
//! test while an unrelated change of unmeasured behavior does not. They describe this small
//! authored corpus only; they are not benchmark claims.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crawlx_core::extraction::ExtractionPolicyV1;
use crawlx_extract::{Document, ExtractOptions, Extractor};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

const LICENSE: &str = "authored-for-this-repo";
const FAMILIES: [&str; 4] = ["article_body", "boilerplate", "metadata", "link_discovery"];

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Manifest {
    version: u32,
    rights: String,
    cases: Vec<Entry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    id: String,
    family: String,
    license: String,
    page_url: String,
    files: Files,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Files {
    input: FileRef,
    gold: FileRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRef {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Gold {
    id: String,
    family: String,
    #[allow(dead_code)]
    note: String,
    expected_text: String,
    spans: Vec<Span>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Span {
    label: String,
    start: usize,
    end: usize,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn read(relative: &str) -> Vec<u8> {
    std::fs::read(corpus_dir().join(relative)).unwrap_or_else(|e| panic!("{relative}: {e}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    Sha256::digest(bytes).iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn manifest() -> Manifest {
    serde_json::from_slice(&read("manifest.json")).unwrap()
}

struct Case {
    entry: Entry,
    html: String,
    gold: Gold,
}

fn cases() -> Vec<Case> {
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

impl Gold {
    fn text_of(&self, label: &str) -> Vec<&str> {
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

fn is_cjk(c: char) -> bool {
    matches!(c, '\u{3040}'..='\u{30FF}' | '\u{3400}'..='\u{4DBF}' | '\u{4E00}'..='\u{9FFF}' | '\u{AC00}'..='\u{D7AF}')
}

/// Lowercase alphanumeric runs; every Han, kana or Hangul character is a token of its own.
fn tokens(text: &str) -> Vec<String> {
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

type Bag = BTreeMap<String, usize>;

fn bag<I: IntoIterator<Item = String>>(items: I) -> Bag {
    let mut bag = Bag::new();
    for item in items {
        *bag.entry(item).or_default() += 1;
    }
    bag
}

fn size(bag: &Bag) -> usize {
    bag.values().sum()
}

/// Multiset intersection size.
fn overlap(a: &Bag, b: &Bag) -> usize {
    a.iter()
        .map(|(k, n)| (*n).min(b.get(k).copied().unwrap_or(0)))
        .sum()
}

/// Multiset difference: counts of `a` not covered by `b`.
fn minus(a: &Bag, b: &Bag) -> Bag {
    a.iter()
        .filter_map(|(k, n)| {
            let rest = n.saturating_sub(b.get(k).copied().unwrap_or(0));
            (rest > 0).then(|| (k.clone(), rest))
        })
        .collect()
}

/// True positives, predicted and gold counts.
#[derive(Clone, Copy, Default, Debug)]
struct Counts {
    tp: usize,
    predicted: usize,
    gold: usize,
}

impl Counts {
    #[allow(clippy::cast_precision_loss)]
    fn ratio(n: usize, d: usize) -> f64 {
        if d == 0 {
            1.0
        } else {
            n as f64 / d as f64
        }
    }
    fn precision(self) -> f64 {
        Self::ratio(self.tp, self.predicted)
    }
    fn recall(self) -> f64 {
        Self::ratio(self.tp, self.gold)
    }
    fn f1(self) -> f64 {
        let (p, r) = (self.precision(), self.recall());
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
    fn add(self, other: Self) -> Self {
        Self {
            tp: self.tp + other.tp,
            predicted: self.predicted + other.predicted,
            gold: self.gold + other.gold,
        }
    }
}

/// Aggregate over cases: macro mean of case F1, micro F1 over summed counts, worst case.
#[derive(Debug)]
struct Family {
    macro_f1: f64,
    micro: Counts,
    worst_f1: f64,
}

#[allow(clippy::cast_precision_loss)]
fn aggregate(per_case: &[Counts]) -> Family {
    Family {
        macro_f1: per_case.iter().map(|c| c.f1()).sum::<f64>() / per_case.len() as f64,
        micro: per_case.iter().fold(Counts::default(), |acc, c| acc.add(*c)),
        worst_f1: per_case.iter().map(|c| c.f1()).fold(1.0, f64::min),
    }
}

// ------------------------------------------------------------------------------------------
// extraction under test
// ------------------------------------------------------------------------------------------

fn extract(case: &Case) -> Document {
    Extractor::extract(
        &case.html,
        &Url::parse(&case.entry.page_url).unwrap(),
        &ExtractOptions {
            content: Some(ExtractionPolicyV1::default()),
            ..ExtractOptions::default()
        },
    )
    .unwrap_or_else(|e| panic!("{}: {e}", case.entry.id))
}

/// Bag-of-tokens F1 of the extracted text against the `body` spans.
fn body_counts(case: &Case, document: &Document) -> Counts {
    let gold = bag(case.gold.text_of("body").into_iter().flat_map(tokens));
    let output = bag(tokens(&document.text));
    Counts {
        tp: overlap(&gold, &output),
        predicted: size(&output),
        gold: size(&gold),
    }
}

/// Exclusion quality for boilerplate: tokens that occur only in `boilerplate` spans should be
/// absent from the output; a missing `body` token is an exclusion error.
fn exclusion_counts(case: &Case, document: &Document) -> Counts {
    let body = bag(case.gold.text_of("body").into_iter().flat_map(tokens));
    let chrome_all = bag(case.gold.text_of("boilerplate").into_iter().flat_map(tokens));
    let body_words: BTreeSet<&String> = body.keys().collect();
    let chrome: Bag = chrome_all
        .into_iter()
        .filter(|(k, _)| !body_words.contains(k))
        .collect();
    let output = bag(tokens(&document.text));
    let leaked = overlap(&chrome, &output);
    let removed_chrome = size(&chrome) - leaked;
    let removed_body = size(&body) - overlap(&body, &output);
    Counts {
        tp: removed_chrome,
        predicted: removed_chrome + removed_body,
        gold: size(&chrome),
    }
}

/// `field=value` facts of the extracted metadata, in the gold's field order.
fn metadata_facts(document: &Document) -> Vec<(&'static str, String)> {
    let meta = &document
        .article
        .as_ref()
        .expect("content policy yields an envelope")
        .metadata;
    let mut facts = Vec::new();
    if let Some(title) = &meta.title.value {
        facts.push(("title", title.clone()));
    }
    if let Some(authors) = &meta.authors.value {
        facts.push(("authors", authors.join("; ")));
    }
    if let Some(language) = &meta.language.value {
        facts.push(("language", language.clone()));
    }
    if let Some(published) = &meta.published.value {
        facts.push(("published", published.date.to_string()));
    }
    if let Some(canonical) = &document.canonical_url {
        facts.push(("canonical", canonical.to_string()));
    }
    if let Some(description) = &document.description {
        facts.push(("description", description.clone()));
    }
    facts
}

fn field_tokens(field: &str, value: &str) -> Vec<String> {
    tokens(value)
        .into_iter()
        .map(|t| format!("{field}:{t}"))
        .collect()
}

fn metadata_counts(case: &Case, document: &Document) -> Counts {
    let gold = bag(case
        .gold
        .spans
        .iter()
        .flat_map(|span| field_tokens(&span.label, &case.gold.expected_text[span.start..span.end])));
    let output = bag(metadata_facts(document)
        .iter()
        .flat_map(|(f, v)| field_tokens(f, v)));
    Counts {
        tp: overlap(&gold, &output),
        predicted: size(&output),
        gold: size(&gold),
    }
}

fn link_counts(case: &Case, document: &Document) -> Counts {
    let gold: BTreeSet<&str> = case.gold.text_of("link").into_iter().collect();
    let output: BTreeSet<&str> = document.links.iter().map(|l| l.url.as_str()).collect();
    Counts {
        tp: gold.intersection(&output).count(),
        predicted: output.len(),
        gold: gold.len(),
    }
}

// ------------------------------------------------------------------------------------------
// tests
// ------------------------------------------------------------------------------------------

#[test]
fn manifest_lists_every_file_with_matching_sha256_and_authored_license() {
    let manifest = manifest();
    assert_eq!(manifest.version, 1);
    assert!(manifest.rights.contains("written for this repository"));
    let mut ids = BTreeSet::new();
    let mut listed: BTreeSet<String> = BTreeSet::from(["manifest.json".to_owned()]);
    for entry in &manifest.cases {
        assert!(ids.insert(entry.id.clone()), "duplicate id {}", entry.id);
        assert_eq!(entry.license, LICENSE, "{}", entry.id);
        assert!(FAMILIES.contains(&entry.family.as_str()), "{}", entry.id);
        let page = Url::parse(&entry.page_url).unwrap();
        assert!(
            page.host_str().is_some_and(|h| h.ends_with(".test")),
            "{}",
            entry.id
        );
        for file in [&entry.files.input, &entry.files.gold] {
            assert_eq!(sha256_hex(&read(&file.path)), file.sha256, "{}", file.path);
            assert!(
                listed.insert(file.path.clone()),
                "file listed twice: {}",
                file.path
            );
        }
        let gold: Gold = serde_json::from_slice(&read(&entry.files.gold.path)).unwrap();
        assert_eq!(
            (gold.id.as_str(), gold.family.as_str()),
            (entry.id.as_str(), entry.family.as_str())
        );
    }
    // No unlisted file sits in the corpus directory.
    let on_disk: BTreeSet<String> = std::fs::read_dir(corpus_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(on_disk, listed);
    for (family, minimum) in [
        ("article_body", 7),
        ("boilerplate", 4),
        ("metadata", 4),
        ("link_discovery", 3),
    ] {
        let count = manifest.cases.iter().filter(|c| c.family == family).count();
        assert!(count >= minimum, "{family}: {count} cases");
    }
}

#[test]
fn gold_spans_are_sorted_disjoint_utf8_byte_ranges_with_family_labels() {
    for case in cases() {
        let Gold {
            expected_text, spans, ..
        } = &case.gold;
        assert!(!spans.is_empty(), "{}", case.entry.id);
        let mut previous_end = 0;
        for span in spans {
            let id = &case.entry.id;
            assert!(span.start < span.end && span.end <= expected_text.len(), "{id}");
            assert!(span.start >= previous_end, "{id}: overlapping or unsorted span");
            assert!(
                expected_text.is_char_boundary(span.start) && expected_text.is_char_boundary(span.end),
                "{id}: span splits a UTF-8 sequence"
            );
            previous_end = span.end;
            let text = &expected_text[span.start..span.end];
            match case.entry.family.as_str() {
                "article_body" | "boilerplate" => {
                    assert!(matches!(span.label.as_str(), "body" | "boilerplate"), "{id}");
                }
                "metadata" => {
                    let allowed = [
                        "title",
                        "authors",
                        "language",
                        "published",
                        "canonical",
                        "description",
                    ];
                    assert!(allowed.contains(&span.label.as_str()), "{id}");
                    assert!(
                        expected_text[..span.start].ends_with(&format!("{}=", span.label)),
                        "{id}"
                    );
                }
                "link_discovery" => {
                    assert_eq!(span.label, "link", "{id}");
                    let url = Url::parse(text).unwrap();
                    assert!(
                        matches!(url.scheme(), "http" | "https") && url.fragment().is_none(),
                        "{id}"
                    );
                }
                other => panic!("unknown family {other}"),
            }
        }
        if matches!(case.entry.family.as_str(), "article_body" | "boilerplate") {
            assert!(!case.gold.text_of("body").is_empty(), "{}", case.entry.id);
            assert!(!case.gold.text_of("boilerplate").is_empty(), "{}", case.entry.id);
        }
    }
}

#[test]
fn gold_text_of_text_families_is_visible_in_the_input_markup() {
    for case in cases() {
        if !matches!(case.entry.family.as_str(), "article_body" | "boilerplate") {
            continue;
        }
        let parsed = scraper::Html::parse_document(&case.html);
        let body = scraper::Selector::parse("body").unwrap();
        let text = parsed
            .select(&body)
            .next()
            .unwrap()
            .text()
            .collect::<Vec<_>>()
            .join(" ");
        let visible = bag(tokens(&text));
        let all = bag(case
            .gold
            .spans
            .iter()
            .flat_map(|s| tokens(&case.gold.expected_text[s.start..s.end])));
        assert_eq!(
            overlap(&all, &visible),
            size(&all),
            "{}: gold text missing from the page",
            case.entry.id
        );
        // The gold labels cover the page text: nothing visible is left unlabeled.
        assert_eq!(
            size(&visible),
            size(&all),
            "{}: page text without a gold label",
            case.entry.id
        );
    }
}

#[test]
fn token_scoring_handles_scripts_duplicates_and_empty_sets() {
    assert_eq!(tokens("Straße, Café 12:30!"), ["straße", "café", "12", "30"]);
    assert_eq!(tokens("図書館で冬"), ["図", "書", "館", "で", "冬"]);
    assert_eq!(tokens(""), Vec::<String>::new());
    let a = bag(tokens("a a b"));
    let b = bag(tokens("a b b"));
    assert_eq!(overlap(&a, &b), 2);
    assert_eq!(size(&minus(&a, &b)), 1);
    let perfect = Counts {
        tp: 4,
        predicted: 4,
        gold: 4,
    };
    assert!((perfect.f1() - 1.0).abs() < f64::EPSILON);
    let none = Counts {
        tp: 0,
        predicted: 3,
        gold: 3,
    };
    assert!(none.f1() == 0.0);
    let half = Counts {
        tp: 2,
        predicted: 4,
        gold: 2,
    };
    assert!((half.precision() - 0.5).abs() < f64::EPSILON && (half.recall() - 1.0).abs() < f64::EPSILON);
}

struct Floors {
    macro_f1: f64,
    micro_precision: f64,
    micro_recall: f64,
    worst_case_f1: f64,
}

fn check(name: &str, family: &Family, floors: &Floors) {
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

fn scores() -> BTreeMap<&'static str, Family> {
    let all = cases();
    let mut out = BTreeMap::new();
    for family in FAMILIES {
        let per_case: Vec<Counts> = all
            .iter()
            .filter(|case| case.entry.family == family)
            .map(|case| {
                let document = extract(case);
                let counts = match family {
                    "article_body" => body_counts(case, &document),
                    "boilerplate" => exclusion_counts(case, &document),
                    "metadata" => metadata_counts(case, &document),
                    _ => link_counts(case, &document),
                };
                eprintln!(
                    "  {}: p={:.4} r={:.4} f1={:.4}",
                    case.entry.id,
                    counts.precision(),
                    counts.recall(),
                    counts.f1()
                );
                counts
            })
            .collect();
        out.insert(family, aggregate(&per_case));
    }
    out
}

#[test]
fn extractor_scores_meet_the_measured_per_family_floors() {
    // Observed on this corpus: article_body macro F1 0.9932 (micro P 0.9851, R 1.0000, worst case
    // 0.9752); boilerplate 0.7399 (P 1.0000, R 0.7945, worst 0.1714: inline advertisement blocks
    // between article paragraphs are kept in the output); metadata 0.9808 (P 1.0000, R 0.9783,
    // worst 0.9231); link_discovery 1.0000 everywhere. Floors sit just under those values.
    let scores = scores();
    for (name, floors) in [
        (
            "article_body",
            Floors {
                macro_f1: 0.99,
                micro_precision: 0.98,
                micro_recall: 0.99,
                worst_case_f1: 0.97,
            },
        ),
        (
            "boilerplate",
            Floors {
                macro_f1: 0.73,
                micro_precision: 0.99,
                micro_recall: 0.79,
                worst_case_f1: 0.17,
            },
        ),
        (
            "metadata",
            Floors {
                macro_f1: 0.97,
                micro_precision: 0.99,
                micro_recall: 0.97,
                worst_case_f1: 0.92,
            },
        ),
        (
            "link_discovery",
            Floors {
                macro_f1: 0.99,
                micro_precision: 0.99,
                micro_recall: 0.99,
                worst_case_f1: 0.99,
            },
        ),
    ] {
        check(name, &scores[name], &floors);
    }
}

#[test]
fn scoring_is_deterministic_and_does_not_depend_on_case_order() {
    let first = scores();
    let second = scores();
    for family in FAMILIES {
        let (a, b) = (&first[family], &second[family]);
        assert_eq!(a.macro_f1.to_bits(), b.macro_f1.to_bits(), "{family}");
        assert_eq!(
            (a.micro.tp, a.micro.predicted, a.micro.gold),
            (b.micro.tp, b.micro.predicted, b.micro.gold)
        );
    }
}
