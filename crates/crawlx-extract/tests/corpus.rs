#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authored extraction corpus: manifest digests, gold spans and measured per-family scores for
//! the article, boilerplate, metadata and link families (see `corpus_support` for the shared
//! harness and the other `corpus_*.rs` family suites).
//!
//! Every file under `tests/corpus/` was written for this repository (license
//! `authored-for-this-repo`); the manifests list each file with its SHA-256. Gold files hold
//! an `expectedText` and labeled UTF-8 byte spans into it:
//!
//! * `article_body`, `boilerplate`: `expectedText` is the visible page text in document order;
//!   spans are labeled `body` or `boilerplate`.
//! * `metadata`: one `field=value` line per expected field; the span covers the value.
//! * `link_discovery`: one expected absolute URL per line; every span is labeled `link`.
//!
//! Scores are token-level (see `corpus_support::tokens`) over the real extractor output. The
//! floors below are measured on this corpus and set just under the observed values, so a
//! regression fails the test while an unrelated change of unmeasured behavior does not. They
//! describe this authored corpus only; they are not benchmark claims.

mod corpus_support;

use std::collections::{BTreeMap, BTreeSet};

use corpus_support::*;
use crawlx_core::extraction::ExtractionPolicyV1;
use crawlx_extract::{Document, ExtractOptions, Extractor};
use url::Url;

/// Families scored by this suite. Other families (`focus`, `comments`, language, NLP, selector,
/// feed) have their own `corpus_*.rs` suites over the same manifests.
const FAMILIES: [&str; 4] = ["article_body", "boilerplate", "metadata", "link_discovery"];

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

/// Plan minimum fixture counts per family, summed over every manifest.
const MINIMUMS: [(&str, usize); 4] = [
    ("article_body", 24),
    ("boilerplate", 4),
    ("metadata", 4),
    ("link_discovery", 3),
];

#[test]
fn manifest_lists_every_file_with_matching_sha256_and_authored_license() {
    let manifest = manifest();
    assert_eq!(manifest.version, 1);
    assert!(manifest.rights.contains("written for this repository"));
    let mut ids = BTreeSet::new();
    let mut listed: BTreeSet<String> = manifest_files().into_iter().collect();
    for entry in &manifest.cases {
        assert!(ids.insert(entry.id.clone()), "duplicate id {}", entry.id);
        assert_eq!(entry.license, LICENSE, "{}", entry.id);
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
    for (family, minimum) in MINIMUMS {
        let count = manifest.cases.iter().filter(|c| c.family == family).count();
        assert!(
            count >= minimum,
            "{family}: {count} cases, plan minimum {minimum}"
        );
    }
}

#[test]
fn gold_spans_are_sorted_disjoint_utf8_byte_ranges_with_family_labels() {
    for case in cases_of(&FAMILIES) {
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
    for case in cases_of(&["article_body", "boilerplate"]) {
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
    // Plan gate for the article family: macro F1 >= 0.95 and no case below 0.90, with both micro
    // precision and micro recall >= 0.98. The other families keep floors measured on this
    // corpus, set just under the observed values.
    let scores = scores();
    for (name, floors) in [
        (
            "article_body",
            Floors {
                macro_f1: 0.95,
                micro_precision: 0.98,
                micro_recall: 0.98,
                worst_case_f1: 0.90,
            },
        ),
        (
            "boilerplate",
            Floors {
                macro_f1: 0.99,
                micro_precision: 0.99,
                micro_recall: 0.99,
                worst_case_f1: 0.98,
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
