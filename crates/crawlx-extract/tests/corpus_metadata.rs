#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authored metadata corpus (family `meta_exact`): exact selected fields, selection provenance
//! and raw alternatives over conflicting sources, author lists and bylines, structured-data
//! graphs, dates with locale and zone evidence, canonical and rights links, declared language,
//! images and keywords, malformed structured data and script-injected canary text.
//!
//! Gold files list one `field=value` line per expected selected field (the span covers the
//! value). The manifest `params` object of each case declares, per envelope field, the exact
//! evidence list the extractor must keep (`[source, raw]` pairs in order), the index of the
//! winning entry and whether the field is flagged uncertain. Fields a case does not list are
//! compared by value only. `knownMiss` records a field whose gold value is the page's real
//! meaning but which the extractor does not report; the test requires that the field really
//! still differs, so a fix forces the marker to be removed.
//!
//! Language tags are compared ASCII case-insensitively (tags are case-insensitive and the
//! envelope stores the lower-case form); every other field is compared exactly.
//!
//! The extraction API owns no network client. The purity test additionally rewrites every
//! absolute URL of every fixture to point at a loopback listener and checks that nothing ever
//! connects, so URLs found in metadata are only reported, never fetched.

mod corpus_support;

use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpListener;

use chrono::NaiveDate;
use corpus_support::*;
use crawlx_core::extraction::{DiscoveryPurposeV1, ExtractionPolicyV1};
use crawlx_extract::{Document, ExtractOptions, Extractor};
use serde::Deserialize;
use url::Url;

const FAMILY: &str = "meta_exact";
/// Plan minimum for the metadata set: the four `metadata` cases plus this family.
const MINIMUM_TOTAL: usize = 40;
/// Field order of the gold lines.
const FIELDS: [&str; 15] = [
    "title",
    "authors",
    "publisher",
    "language",
    "published",
    "publishedTimestamp",
    "modified",
    "modifiedTimestamp",
    "canonical",
    "description",
    "keywords",
    "section",
    "rights",
    "license",
    "image",
];
/// Envelope fields that carry evidence.
const EVIDENCE_FIELDS: [&str; 6] = [
    "title",
    "authors",
    "publisher",
    "language",
    "published",
    "modified",
];

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyParams {
    locale: Option<String>,
    date_timezone: Option<String>,
    reference_date: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldParams {
    evidence: Vec<(String, String)>,
    winner: Option<usize>,
    uncertain: bool,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Params {
    #[serde(default)]
    policy: PolicyParams,
    #[serde(default)]
    fields: BTreeMap<String, FieldParams>,
    #[serde(default)]
    canary_absent: Vec<String>,
    #[serde(default)]
    known_miss: BTreeMap<String, String>,
    discovery: Option<Vec<(String, String)>>,
    json_ld_blocks: Option<usize>,
}

fn params(case: &Case) -> Params {
    if case.entry.params.is_null() {
        return Params::default();
    }
    serde_json::from_value(case.entry.params.clone())
        .unwrap_or_else(|e| panic!("{}: params: {e}", case.entry.id))
}

fn policy(p: &PolicyParams) -> ExtractionPolicyV1 {
    let mut policy = ExtractionPolicyV1::default();
    policy.locale.clone_from(&p.locale);
    policy.date_timezone.clone_from(&p.date_timezone);
    policy.reference_date = p
        .reference_date
        .as_deref()
        .map(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").unwrap());
    policy
}

fn extract_html(case: &Case, html: &str, page_url: &str) -> Document {
    Extractor::extract(
        html,
        &Url::parse(page_url).unwrap(),
        &ExtractOptions {
            content: Some(policy(&params(case).policy)),
            ..ExtractOptions::default()
        },
    )
    .unwrap_or_else(|e| panic!("{}: {e}", case.entry.id))
}

fn extract(case: &Case) -> Document {
    extract_html(case, &case.html, &case.entry.page_url)
}

fn meta_cases() -> Vec<Case> {
    cases_of(&[FAMILY])
}

/// Selected facts in gold field order.
fn facts(document: &Document) -> Vec<(&'static str, String)> {
    let meta = &document
        .article
        .as_ref()
        .expect("content policy yields an envelope")
        .metadata;
    let mut facts = Vec::new();
    let mut add = |field: &'static str, value: Option<String>| {
        if let Some(value) = value {
            facts.push((field, value));
        }
    };
    add("title", meta.title.value.clone());
    add("authors", meta.authors.value.as_ref().map(|a| a.join("; ")));
    add("publisher", meta.publisher.value.clone());
    add("language", meta.language.value.clone());
    add(
        "published",
        meta.published.value.as_ref().map(|d| d.date.to_string()),
    );
    add(
        "publishedTimestamp",
        meta.published.value.as_ref().and_then(|d| d.timestamp.clone()),
    );
    add(
        "modified",
        meta.modified.value.as_ref().map(|d| d.date.to_string()),
    );
    add(
        "modifiedTimestamp",
        meta.modified.value.as_ref().and_then(|d| d.timestamp.clone()),
    );
    add(
        "canonical",
        document.canonical_url.as_ref().map(ToString::to_string),
    );
    add("description", document.description.clone());
    add(
        "keywords",
        (!meta.declared_keywords.is_empty()).then(|| meta.declared_keywords.join("; ")),
    );
    let raw = |names: &[&str]| {
        names.iter().find_map(|n| {
            document
                .metadata
                .all_meta
                .get(*n)
                .and_then(|v| v.first().cloned())
        })
    };
    add("section", raw(&["article:section"]));
    add(
        "rights",
        raw(&["dc.rights", "dcterms.rights", "rights", "copyright"]),
    );
    add(
        "license",
        document
            .links
            .iter()
            .find(|l| l.rel.iter().any(|r| r == "license"))
            .map(|l| l.url.to_string()),
    );
    add(
        "image",
        document
            .article
            .as_ref()
            .unwrap()
            .discovery
            .iter()
            .find(|i| i.purpose == DiscoveryPurposeV1::ImageReference)
            .map(|i| i.url.to_string()),
    );
    facts
}

fn gold_facts(case: &Case) -> Vec<(String, String)> {
    case.gold
        .spans
        .iter()
        .map(|s| {
            (
                s.label.clone(),
                case.gold.expected_text[s.start..s.end].to_owned(),
            )
        })
        .collect()
}

fn same(field: &str, gold: &str, actual: &str) -> bool {
    if field == "language" {
        gold.eq_ignore_ascii_case(actual)
    } else {
        gold == actual
    }
}

/// Evidence view of one envelope field.
struct View {
    value_present: bool,
    evidence: Vec<(String, String, usize)>,
    uncertain: bool,
}

fn view(document: &Document, field: &str) -> View {
    let m = &document.article.as_ref().unwrap().metadata;
    fn of<T>(v: &crawlx_core::extraction::MetadataValueV1<T>) -> View {
        View {
            value_present: v.value.is_some(),
            evidence: v
                .evidence
                .iter()
                .map(|e| (e.source.clone(), e.raw.clone(), e.order))
                .collect(),
            uncertain: v.uncertain,
        }
    }
    match field {
        "title" => of(&m.title),
        "authors" => of(&m.authors),
        "publisher" => of(&m.publisher),
        "language" => of(&m.language),
        "published" => of(&m.published),
        "modified" => of(&m.modified),
        other => panic!("unknown evidence field {other}"),
    }
}

// ------------------------------------------------------------------------------------------
// manifest and gold
// ------------------------------------------------------------------------------------------

#[test]
fn family_manifest_lists_authored_cases_and_meets_the_plan_minimum() {
    let all = manifest();
    let mine = meta_cases();
    let legacy = all.cases.iter().filter(|c| c.family == "metadata").count();
    assert!(
        legacy + mine.len() >= MINIMUM_TOTAL,
        "metadata {legacy} + {FAMILY} {} < {MINIMUM_TOTAL}",
        mine.len()
    );
    let listed: BTreeSet<String> = manifest_files().into_iter().collect();
    assert!(listed.contains("manifest.meta.json"));
    let mut ids = BTreeSet::new();
    for case in &mine {
        let e = &case.entry;
        assert!(ids.insert(e.id.clone()), "duplicate id {}", e.id);
        assert_eq!(e.license, LICENSE, "{}", e.id);
        assert!(
            e.id.starts_with('m') && e.id[1..3].parse::<u32>().unwrap() >= 5,
            "{}",
            e.id
        );
        let page = Url::parse(&e.page_url).unwrap();
        assert!(page.host_str().is_some_and(|h| h.ends_with(".test")), "{}", e.id);
        for file in [&e.files.input, &e.files.gold] {
            assert_eq!(sha256_hex(&read(&file.path)), file.sha256, "{}", file.path);
        }
        assert_eq!(case.gold.id, e.id);
        assert_eq!(case.gold.family, e.family);
        let known = params(case).known_miss;
        assert!(known.keys().all(|f| FIELDS.contains(&f.as_str())), "{}", e.id);
    }
    // Every hostname in a fixture is a reserved `.test` name.
    for case in &mine {
        for part in case.html.split("://").skip(1) {
            let host: String = part
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect();
            assert!(host.ends_with(".test"), "{}: host {host}", case.entry.id);
        }
    }
}

#[test]
fn gold_spans_are_sorted_disjoint_field_values_in_field_order() {
    for case in meta_cases() {
        let id = &case.entry.id;
        let Gold {
            expected_text, spans, ..
        } = &case.gold;
        assert!(!spans.is_empty(), "{id}");
        let mut previous_end = 0;
        let mut previous_field = None;
        let mut covered = 0;
        for span in spans {
            assert!(span.start < span.end && span.end <= expected_text.len(), "{id}");
            assert!(span.start >= previous_end, "{id}: overlapping or unsorted span");
            assert!(
                expected_text.is_char_boundary(span.start) && expected_text.is_char_boundary(span.end),
                "{id}: span splits a UTF-8 sequence"
            );
            let position = FIELDS
                .iter()
                .position(|f| *f == span.label)
                .unwrap_or_else(|| panic!("{id}: label {}", span.label));
            assert!(
                previous_field.is_none_or(|p| p < position),
                "{id}: field order or duplicate"
            );
            previous_field = Some(position);
            assert!(
                expected_text[..span.start].ends_with(&format!("{}=", span.label)),
                "{id}: span is not a field value"
            );
            assert!(
                span.start == 0
                    || expected_text[..span.start - span.label.len() - 1].ends_with('\n')
                    || span.start == span.label.len() + 1,
                "{id}: field does not start a line"
            );
            previous_end = span.end;
            covered += span.label.len() + 1 + (span.end - span.start) + 1;
        }
        // Exactly one `field=value` line per span, nothing else.
        assert_eq!(covered - 1, expected_text.len(), "{id}: text outside spans");
        assert_eq!(expected_text.lines().count(), spans.len(), "{id}");
    }
}

// ------------------------------------------------------------------------------------------
// exact fields, provenance, raw alternatives
// ------------------------------------------------------------------------------------------

#[test]
fn selected_fields_are_exact_and_known_misses_stay_misses() {
    let mut misses = Vec::new();
    for case in meta_cases() {
        let id = &case.entry.id;
        let p = params(&case);
        let actual: BTreeMap<&str, String> = facts(&extract(&case)).into_iter().collect();
        let gold = gold_facts(&case);
        let gold_fields: BTreeSet<&str> = gold.iter().map(|(f, _)| f.as_str()).collect();
        for (field, value) in &gold {
            if let Some(reason) = p.known_miss.get(field) {
                let differs = actual.get(field.as_str()).is_none_or(|a| !same(field, value, a));
                assert!(
                    differs,
                    "{id}: {field} is now reported exactly; remove its knownMiss ({reason})"
                );
                misses.push(format!("{id}:{field} ({reason})"));
                continue;
            }
            let got = actual.get(field.as_str());
            assert!(
                got.is_some_and(|a| same(field, value, a)),
                "{id}: {field}: gold {value:?}, extracted {got:?}"
            );
        }
        // No unexpected extra selected field: everything extracted is in the gold.
        for (field, value) in &actual {
            assert!(
                gold_fields.contains(field),
                "{id}: extracted {field}={value:?} that the gold does not list"
            );
        }
    }
    println!("known misses ({}): {misses:#?}", misses.len());
}

#[test]
fn provenance_and_raw_alternatives_are_exact() {
    for case in meta_cases() {
        let id = &case.entry.id;
        let p = params(&case);
        let document = extract(&case);
        let gold: BTreeMap<String, String> = gold_facts(&case).into_iter().collect();
        for (name, want) in &p.fields {
            assert!(EVIDENCE_FIELDS.contains(&name.as_str()), "{id}: {name}");
            let got = view(&document, name);
            let pairs: Vec<(&str, &str)> = got
                .evidence
                .iter()
                .map(|(s, r, _)| (s.as_str(), r.as_str()))
                .collect();
            let expected: Vec<(&str, &str)> = want
                .evidence
                .iter()
                .map(|(s, r)| (s.as_str(), r.as_str()))
                .collect();
            assert_eq!(pairs, expected, "{id}: {name} raw alternatives");
            for (index, (_, _, order)) in got.evidence.iter().enumerate() {
                assert_eq!(*order, index, "{id}: {name} evidence order");
            }
            assert_eq!(got.uncertain, want.uncertain, "{id}: {name} uncertain");
            assert_eq!(got.value_present, want.winner.is_some(), "{id}: {name} selected");
            if let Some(winner) = want.winner {
                assert!(winner < want.evidence.len(), "{id}: {name} winner index");
                let raw = &want.evidence[winner].1;
                match name.as_str() {
                    "title" | "publisher" => {
                        assert_eq!(
                            gold.get(name.as_str()),
                            Some(raw),
                            "{id}: {name} winner raw is the gold value"
                        );
                    }
                    "language" => {
                        let normalized = raw.replace('_', "-");
                        assert!(
                            gold.get("language")
                                .is_some_and(|g| g.eq_ignore_ascii_case(&normalized)),
                            "{id}: language winner"
                        );
                    }
                    "authors" => {
                        let authors = gold.get("authors").unwrap();
                        assert!(authors.split("; ").any(|a| a == raw), "{id}: authors winner");
                    }
                    _ => {
                        // Dates: the winning raw text carries the gold calendar evidence.
                        assert!(
                            gold.contains_key(name.as_str()),
                            "{id}: {name} winner has a gold date"
                        );
                    }
                }
            } else {
                assert!(!gold.contains_key(name.as_str()), "{id}: {name} has no selection");
            }
        }
    }
}

#[test]
fn canary_text_and_malformed_structured_data_never_reach_metadata() {
    let mut checked = 0;
    for case in meta_cases() {
        let p = params(&case);
        if p.canary_absent.is_empty() && p.json_ld_blocks.is_none() {
            continue;
        }
        checked += 1;
        let id = &case.entry.id;
        let document = extract(&case);
        let meta = &document.article.as_ref().unwrap().metadata;
        let mut haystack = serde_json::to_string(meta).unwrap();
        haystack.push_str(&serde_json::to_string(&document.article.as_ref().unwrap().discovery).unwrap());
        haystack.push_str(&document.text);
        haystack.push_str(
            &document
                .metadata
                .all_meta
                .values()
                .flatten()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n"),
        );
        haystack.push_str(document.title.as_deref().unwrap_or(""));
        haystack.push_str(document.description.as_deref().unwrap_or(""));
        for canary in &p.canary_absent {
            assert!(
                !haystack.contains(canary.as_str()),
                "{id}: canary {canary} leaked"
            );
        }
        if let Some(blocks) = p.json_ld_blocks {
            assert_eq!(
                document.metadata.json_ld.len(),
                blocks,
                "{id}: retained JSON-LD blocks"
            );
        }
    }
    assert!(checked >= 2);
}

#[test]
fn discovery_proposals_are_exact_http_references_in_document_order() {
    let mut checked = 0;
    for case in meta_cases() {
        let p = params(&case);
        let document = extract(&case);
        let intents = &document.article.as_ref().unwrap().discovery;
        for intent in intents {
            assert!(
                matches!(intent.url.scheme(), "http" | "https"),
                "{}",
                case.entry.id
            );
            assert!(
                matches!(
                    intent.purpose,
                    DiscoveryPurposeV1::ImageReference | DiscoveryPurposeV1::ReadMoreReference
                ),
                "{}",
                case.entry.id
            );
        }
        if let Some(expected) = p.discovery {
            checked += 1;
            let got: Vec<(String, String)> = intents
                .iter()
                .map(|i| {
                    (
                        serde_json::to_value(i.purpose)
                            .unwrap()
                            .as_str()
                            .unwrap()
                            .to_owned(),
                        i.url.to_string(),
                    )
                })
                .collect();
            assert_eq!(got, expected, "{}", case.entry.id);
        }
    }
    assert!(checked >= 2);
}

// ------------------------------------------------------------------------------------------
// purity
// ------------------------------------------------------------------------------------------

#[test]
fn extraction_never_connects_to_any_url_found_in_metadata() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://127.0.0.1:{}/via/", listener.local_addr().unwrap().port());
    let mut with_urls = 0;
    for case in meta_cases() {
        // Every absolute URL of the page, the metadata, the structured data and the page URL
        // now points at the listener; a fetch of any of them would connect.
        let html = case.html.replace("https://", &origin);
        let page_url = case.entry.page_url.replace("https://", &origin);
        let document = extract_html(&case, &html, &page_url);
        let intents = &document.article.as_ref().unwrap().discovery;
        let loopback = |u: &Url| u.as_str().starts_with(&origin);
        assert!(intents.iter().all(|i| loopback(&i.url)), "{}", case.entry.id);
        if document.canonical_url.as_ref().is_some_and(loopback) || !intents.is_empty() {
            with_urls += 1;
        }
    }
    assert!(with_urls >= 5, "only {with_urls} cases exercised loopback URLs");
    match listener.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        other => panic!("extraction connected to a metadata URL: {other:?}"),
    }
}

#[test]
fn extraction_is_deterministic() {
    for case in meta_cases() {
        let first = extract(&case);
        let second = extract(&case);
        assert_eq!(first.article, second.article, "{}", case.entry.id);
        assert_eq!(first.canonical_url, second.canonical_url, "{}", case.entry.id);
        assert_eq!(first.description, second.description, "{}", case.entry.id);
    }
}

// ------------------------------------------------------------------------------------------
// family gate
// ------------------------------------------------------------------------------------------

#[test]
fn legacy_metadata_cases_are_exact_except_the_listed_known_miss() {
    // The plain by-line of m04 has no author markup; see `authors-by-and-plain` in this family.
    let known_misses = [("m04-byline-and-time", "authors")];
    let legacy = cases_of(&["metadata"]);
    assert!(legacy.len() >= 4);
    let mut seen = 0;
    for case in legacy {
        let actual: BTreeMap<&str, String> = facts(&extract(&case)).into_iter().collect();
        for (field, value) in gold_facts(&case) {
            let got = actual.get(field.as_str());
            let exact = got.is_some_and(|a| same(&field, &value, a));
            if known_misses.contains(&(case.entry.id.as_str(), field.as_str())) {
                assert!(
                    !exact,
                    "{}: {field} is now exact; remove the known miss",
                    case.entry.id
                );
                seen += 1;
            } else {
                assert!(
                    exact,
                    "{}: {field}: gold {value:?}, extracted {got:?}",
                    case.entry.id
                );
            }
        }
    }
    assert_eq!(seen, known_misses.len());
}

#[test]
fn family_gate_every_expected_field_is_exact_except_listed_known_misses() {
    let cases = meta_cases();
    let mut expected_fields = 0;
    let mut exact = 0;
    let mut by_field: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut missed = Vec::new();
    for case in &cases {
        let p = params(case);
        let actual: BTreeMap<&str, String> = facts(&extract(case)).into_iter().collect();
        for (field, value) in gold_facts(case) {
            expected_fields += 1;
            let slot = by_field.entry(field.clone()).or_default();
            slot.0 += 1;
            if actual
                .get(field.as_str())
                .is_some_and(|a| same(&field, &value, a))
            {
                exact += 1;
                slot.1 += 1;
            } else {
                missed.push(format!("{}:{field}", case.entry.id));
                assert!(
                    p.known_miss.contains_key(&field),
                    "{}: {field} unexpectedly missed",
                    case.entry.id
                );
            }
        }
    }
    println!(
        "meta_exact cases {}, expected fields {expected_fields}, exact {exact}",
        cases.len()
    );
    println!("per field (expected, exact): {by_field:?}");
    println!("misses: {missed:?}");
    assert_eq!(expected_fields - exact, missed.len());
    // The recorded extractor gaps are the only differences.
    let known: usize = cases.iter().map(|c| params(c).known_miss.len()).sum();
    assert_eq!(missed.len(), known);
    assert!(cases.len() >= MINIMUM_TOTAL - 4);
}
