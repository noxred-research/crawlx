#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authored extraction corpus, `focus` and `comments` families.
//!
//! * `focus`: mixed main/navigation/recommendation pages. `expectedText` is the visible page
//!   text in document order, spans are labeled `body` (the main text) or `boilerplate`
//!   (navigation, recommendation cards, trending lists, sponsor boxes, footers, ...). Each page
//!   is extracted with `ContentFocusV1::Precision`, `Recall` and the default `Balanced` focus.
//! * `comments`: blog, forum, Q&A and discussion layouts. Spans are labeled `body` (main or
//!   post text), `comment` (reader comment text), `quote` (an intentional quote of main text
//!   inside a comment, or inside a forum post) or `boilerplate` (everything else). Each page is
//!   extracted with the comment policy off (`Drop`) and on (`Separate`).
//!
//! Gold is written from the page semantics, never from extractor output. Scores are token-level
//! (see `corpus_support::tokens`). Gates asserted here:
//!
//! * precision profile: micro precision of the output against the `body` tokens at least 0.98;
//! * recall profile: micro recall at least 0.98;
//! * both complementary metrics and the balanced baseline are published on stderr; the balanced
//!   profile may not fall more than one percentage point below the recorded baseline;
//! * main text and comment text share no run of five tokens except inside an intentional quote
//!   span, no comment-only token reaches the main text, forum posts appear exactly once, no main
//!   block is duplicated, and switching the comment policy off changes nothing but the comment
//!   output.

mod corpus_support;

use std::collections::{BTreeMap, BTreeSet};

use corpus_support::*;
use crawlx_core::extraction::{CommentPolicyV1, ContentFocusV1, ExtractionPolicyV1};
use crawlx_extract::{Document, ExtractOptions, Extractor};
use url::Url;

const FOCUS: &str = "focus";
const COMMENTS: &str = "comments";

/// Plan minimum fixture counts.
const MINIMUM_FOCUS: usize = 12;
const MINIMUM_COMMENTS: usize = 12;

/// Plan gates.
const PRECISION_PROFILE_PRECISION: f64 = 0.98;
const RECALL_PROFILE_RECALL: f64 = 0.98;
/// Largest allowed drop, in absolute score, of the default profile below its recorded baseline.
const BALANCED_TOLERANCE: f64 = 0.01;

/// Measured on this corpus with the default (`Balanced`) focus: micro precision, micro recall
/// and micro F1 of the output against the `body` tokens (rounded down to four decimals).
const BALANCED_BASELINE_PRECISION: f64 = 0.9353;
const BALANCED_BASELINE_RECALL: f64 = 0.9980;
const BALANCED_BASELINE_F1: f64 = 0.9656;

/// Honest measured floors of the metrics that are not plan gates (set just under the observed
/// values).
const PRECISION_PROFILE_RECALL_FLOOR: f64 = 0.99;
const RECALL_PROFILE_PRECISION_FLOOR: f64 = 0.93;
const COMMENT_MAIN_RECALL_FLOOR: f64 = 0.98;
const COMMENT_MAIN_PRECISION_FLOOR: f64 = 0.96;
const COMMENT_TEXT_RECALL_FLOOR: f64 = 0.98;

/// Length of the token run that counts as shared text between main and comment output. A run of
/// Han, kana or Hangul tokens (one character each) must be longer to be more than a common
/// grammatical ending.
const SHINGLE: usize = 5;
const SHINGLE_CJK: usize = 12;
/// Shortest gold line, in tokens, checked for multiplicity.
const MIN_LINE_TOKENS: usize = 6;

// ------------------------------------------------------------------------------------------
// extraction under test
// ------------------------------------------------------------------------------------------

fn extract(case: &Case, focus: ContentFocusV1, comments: CommentPolicyV1) -> Document {
    let mut policy = ExtractionPolicyV1::default();
    policy.focus = focus;
    policy.comments = comments;
    Extractor::extract(
        &case.html,
        &Url::parse(&case.entry.page_url).unwrap(),
        &ExtractOptions {
            content: Some(policy),
            ..ExtractOptions::default()
        },
    )
    .unwrap_or_else(|e| panic!("{}: {e}", case.entry.id))
}

fn gold_bag(case: &Case, labels: &[&str]) -> Bag {
    bag(case
        .gold
        .spans
        .iter()
        .filter(|span| labels.contains(&span.label.as_str()))
        .flat_map(|span| tokens(&case.gold.expected_text[span.start..span.end])))
}

fn counts(gold: &Bag, text: &str) -> Counts {
    let output = bag(tokens(text));
    Counts {
        tp: overlap(gold, &output),
        predicted: size(&output),
        gold: size(gold),
    }
}

fn flag(case: &Case, name: &str) -> bool {
    case.entry.params.get(name).and_then(serde_json::Value::as_bool) == Some(true)
}

// ------------------------------------------------------------------------------------------
// corpus integrity
// ------------------------------------------------------------------------------------------

fn visible_page_tokens(html: &str) -> Bag {
    let parsed = scraper::Html::parse_document(html);
    let body = scraper::Selector::parse("body").unwrap();
    let text = parsed
        .select(&body)
        .next()
        .unwrap()
        .text()
        .collect::<Vec<_>>()
        .join(" ");
    bag(tokens(&text))
}

#[test]
fn manifests_hold_the_minimum_fixture_sets_with_unique_ids_and_family_prefixes() {
    let manifest = manifest();
    let mut seen = BTreeSet::new();
    for entry in &manifest.cases {
        assert!(seen.insert(entry.id.clone()), "duplicate id {}", entry.id);
    }
    let focus = ids_of(FOCUS);
    let comments = ids_of(COMMENTS);
    assert!(focus.len() >= MINIMUM_FOCUS, "focus: {} cases", focus.len());
    assert!(
        comments.len() >= MINIMUM_COMMENTS,
        "comments: {} cases",
        comments.len()
    );
    assert!(focus.iter().all(|id| id.starts_with('f')));
    assert!(comments.iter().all(|id| id.starts_with('c')));
    for case in cases_of(&[FOCUS, COMMENTS]) {
        assert_eq!(case.entry.license, LICENSE, "{}", case.entry.id);
        let page = Url::parse(&case.entry.page_url).unwrap();
        assert!(
            page.host_str().is_some_and(|h| h.ends_with(".test")),
            "{}",
            case.entry.id
        );
        assert_eq!(
            (case.gold.id.as_str(), case.gold.family.as_str()),
            (case.entry.id.as_str(), case.entry.family.as_str())
        );
    }
}

#[test]
fn gold_spans_are_sorted_disjoint_char_aligned_with_family_labels_and_cover_the_page_text() {
    for case in cases_of(&[FOCUS, COMMENTS]) {
        let id = &case.entry.id;
        let text = &case.gold.expected_text;
        let allowed: &[&str] = if case.entry.family == FOCUS {
            &["body", "boilerplate"]
        } else {
            &["body", "comment", "quote", "boilerplate"]
        };
        assert!(!case.gold.spans.is_empty(), "{id}");
        let mut previous_end = 0;
        for span in &case.gold.spans {
            assert!(span.start < span.end && span.end <= text.len(), "{id}");
            assert!(span.start >= previous_end, "{id}: overlapping or unsorted span");
            assert!(
                text.is_char_boundary(span.start) && text.is_char_boundary(span.end),
                "{id}: span splits a UTF-8 sequence"
            );
            assert!(
                allowed.contains(&span.label.as_str()),
                "{id}: label {}",
                span.label
            );
            previous_end = span.end;
        }
        assert!(!case.gold.text_of("body").is_empty(), "{id}: no body span");
        let labeled = gold_bag(&case, &["body", "comment", "quote", "boilerplate"]);
        let visible = visible_page_tokens(&case.html);
        assert_eq!(
            labeled, visible,
            "{id}: gold tokens differ from the visible page text"
        );
        if case.entry.family == FOCUS {
            assert!(
                !case.gold.text_of("boilerplate").is_empty(),
                "{id}: no boilerplate span"
            );
        } else {
            let expects_comments = !flag(&case, "noComments") && !flag(&case, "forum");
            assert_eq!(
                !case.gold.text_of("comment").is_empty(),
                expects_comments,
                "{id}: comment spans"
            );
            assert_eq!(
                !case.gold.text_of("quote").is_empty(),
                flag(&case, "quote"),
                "{id}: quote spans"
            );
        }
    }
}

#[test]
fn quote_spans_are_verbatim_main_text_long_enough_to_detect() {
    for case in cases_of(&[COMMENTS]) {
        let n = shingle_len(&case);
        let main = tokens(&case.gold.text_of("body").join("\n"));
        let main_shingles = shingles(&main, n);
        for quote in case.gold.text_of("quote") {
            let quote = tokens(quote);
            assert!(
                quote.len() >= n,
                "{}: quote too short to be detected",
                case.entry.id
            );
            if !flag(&case, "forum") {
                // A comment quote is verbatim main text.
                assert!(
                    shingles(&quote, n).is_subset(&main_shingles),
                    "{}: quote is not a verbatim run of the main text",
                    case.entry.id
                );
            }
        }
    }
}

// ------------------------------------------------------------------------------------------
// focus
// ------------------------------------------------------------------------------------------

struct Profile {
    name: &'static str,
    focus: ContentFocusV1,
}

const PROFILES: [Profile; 3] = [
    Profile {
        name: "precision",
        focus: ContentFocusV1::Precision,
    },
    Profile {
        name: "recall",
        focus: ContentFocusV1::Recall,
    },
    Profile {
        name: "balanced",
        focus: ContentFocusV1::Balanced,
    },
];

fn focus_counts(focus: ContentFocusV1) -> Vec<(String, Counts)> {
    cases_of(&[FOCUS])
        .iter()
        .map(|case| {
            let document = extract(case, focus, CommentPolicyV1::Drop);
            (
                case.entry.id.clone(),
                counts(&gold_bag(case, &["body"]), &document.text),
            )
        })
        .collect()
}

fn micro(per_case: &[(String, Counts)]) -> Counts {
    per_case.iter().fold(Counts::default(), |acc, (_, c)| acc.add(*c))
}

fn publish(profile: &str, per_case: &[(String, Counts)]) -> Counts {
    let total = micro(per_case);
    let all: Vec<Counts> = per_case.iter().map(|(_, c)| *c).collect();
    let family = aggregate(&all);
    eprintln!(
        "focus[{profile}]: micro_p={:.4} micro_r={:.4} micro_f1={:.4} macro_f1={:.4} worst_case_f1={:.4}",
        total.precision(),
        total.recall(),
        total.f1(),
        family.macro_f1,
        family.worst_f1
    );
    for (id, c) in per_case {
        eprintln!(
            "focus[{profile}] {id}: p={:.4} r={:.4} tp={} predicted={} gold={}",
            c.precision(),
            c.recall(),
            c.tp,
            c.predicted,
            c.gold
        );
    }
    total
}

fn focus_totals() -> BTreeMap<&'static str, Counts> {
    let mut totals = BTreeMap::new();
    for profile in &PROFILES {
        totals.insert(profile.name, publish(profile.name, &focus_counts(profile.focus)));
    }
    totals
}

/// Cases whose `metric` falls below `gate`, for the failure message.
fn below(focus: ContentFocusV1, metric: fn(Counts) -> f64, gate: f64) -> Vec<String> {
    focus_counts(focus)
        .into_iter()
        .filter(|(_, c)| metric(*c) < gate)
        .map(|(id, c)| format!("{id} ({:.4})", metric(c)))
        .collect()
}

#[test]
fn focus_precision_profile_meets_the_precision_gate() {
    let totals = focus_totals();
    let precision = totals["precision"];
    eprintln!(
        "focus complementary: precision profile recall={:.4}, recall profile precision={:.4}",
        precision.recall(),
        totals["recall"].precision()
    );
    assert!(
        precision.precision() >= PRECISION_PROFILE_PRECISION,
        "precision profile micro precision {:.4} is below {PRECISION_PROFILE_PRECISION}; cases below the gate: {:?}",
        precision.precision(),
        below(ContentFocusV1::Precision, Counts::precision, PRECISION_PROFILE_PRECISION)
    );
}

#[test]
fn focus_recall_profile_meets_the_recall_gate() {
    let recall = focus_totals()["recall"];
    assert!(
        recall.recall() >= RECALL_PROFILE_RECALL,
        "recall profile micro recall {:.4} is below {RECALL_PROFILE_RECALL}; cases below the gate: {:?}",
        recall.recall(),
        below(ContentFocusV1::Recall, Counts::recall, RECALL_PROFILE_RECALL)
    );
}

#[test]
fn focus_complementary_metrics_hold_their_measured_floors() {
    let totals = focus_totals();
    assert!(
        totals["precision"].recall() >= PRECISION_PROFILE_RECALL_FLOOR,
        "precision profile micro recall {:.4}",
        totals["precision"].recall()
    );
    assert!(
        totals["recall"].precision() >= RECALL_PROFILE_PRECISION_FLOOR,
        "recall profile micro precision {:.4}",
        totals["recall"].precision()
    );
}

#[test]
fn focus_balanced_profile_stays_within_one_point_of_the_recorded_baseline() {
    let balanced = focus_totals()["balanced"];
    for (name, value, baseline) in [
        ("precision", balanced.precision(), BALANCED_BASELINE_PRECISION),
        ("recall", balanced.recall(), BALANCED_BASELINE_RECALL),
        ("f1", balanced.f1(), BALANCED_BASELINE_F1),
    ] {
        assert!(
            value >= baseline - BALANCED_TOLERANCE,
            "balanced micro {name} {value:.4} fell more than one point below the baseline {baseline:.4}"
        );
    }
}

#[test]
fn focus_extraction_is_deterministic_for_every_profile() {
    for case in cases_of(&[FOCUS]) {
        for profile in &PROFILES {
            let first = extract(&case, profile.focus, CommentPolicyV1::Drop);
            let second = extract(&case, profile.focus, CommentPolicyV1::Drop);
            assert_eq!(first.text, second.text, "{} {}", case.entry.id, profile.name);
        }
    }
}

// ------------------------------------------------------------------------------------------
// comments
// ------------------------------------------------------------------------------------------

/// Token run length used to detect shared text in `case`.
fn shingle_len(case: &Case) -> usize {
    let all = tokens(&case.gold.expected_text);
    let single_cjk = all
        .iter()
        .filter(|t| {
            let mut chars = t.chars();
            matches!((chars.next(), chars.next()), (Some(c), None) if is_cjk(c))
        })
        .count();
    if single_cjk * 2 > all.len() {
        SHINGLE_CJK
    } else {
        SHINGLE
    }
}

/// Distinct runs of `n` consecutive tokens.
fn shingles(tokens: &[String], n: usize) -> BTreeSet<String> {
    tokens.windows(n).map(|w| w.join(" ")).collect()
}

/// Tokens that occur in comment spans and in no other gold label.
fn comment_only_tokens(case: &Case) -> BTreeSet<String> {
    let comment = gold_bag(case, &["comment"]);
    let others = gold_bag(case, &["body", "quote", "boilerplate"]);
    comment
        .into_keys()
        .filter(|token| !others.contains_key(token))
        .collect()
}

/// How often `needle` occurs as a contiguous run of `haystack`.
fn occurrences(haystack: &[String], needle: &[String]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// Long gold lines whose multiplicity the main output must not exceed (every body line, plus
/// the quoted lines of forum posts, which are part of the posts), and the token stream they are
/// counted in.
fn counted_lines(case: &Case) -> (Vec<Vec<String>>, Vec<String>) {
    let labels: &[&str] = if flag(case, "forum") {
        &["body", "quote"]
    } else {
        &["body"]
    };
    let lines: Vec<Vec<String>> = case
        .gold
        .spans
        .iter()
        .filter(|span| labels.contains(&span.label.as_str()))
        .map(|span| tokens(&case.gold.expected_text[span.start..span.end]))
        .collect();
    let stream = lines.iter().flatten().cloned().collect();
    let long = lines
        .into_iter()
        .filter(|line| line.len() >= MIN_LINE_TOKENS)
        .collect();
    (long, stream)
}

#[test]
fn comment_policy_off_is_exact_and_changes_nothing_but_the_comment_output() {
    for case in cases_of(&[COMMENTS]) {
        let id = &case.entry.id;
        let off = extract(&case, ContentFocusV1::Balanced, CommentPolicyV1::Drop);
        let on = extract(&case, ContentFocusV1::Balanced, CommentPolicyV1::Separate);
        assert!(
            off.comments.is_empty(),
            "{id}: comments leaked with the policy off"
        );
        assert_eq!(off.text, on.text, "{id}: comment policy changed the main text");
        let hidden = comment_only_tokens(&case);
        let main_off = bag(tokens(&off.text));
        let leaked: Vec<&String> = hidden.iter().filter(|t| main_off.contains_key(*t)).collect();
        assert!(
            leaked.is_empty(),
            "{id}: comment-only tokens in the main text: {leaked:?}"
        );
        if flag(&case, "noComments") || flag(&case, "forum") {
            assert!(on.comments.is_empty(), "{id}: unexpected comment output");
        } else {
            assert!(
                !on.comments.is_empty(),
                "{id}: comment policy on produced no comments"
            );
        }
    }
}

#[test]
fn main_and_comment_text_share_nothing_except_intentional_quotes() {
    for case in cases_of(&[COMMENTS]) {
        let id = &case.entry.id;
        let on = extract(&case, ContentFocusV1::Balanced, CommentPolicyV1::Separate);
        let main = tokens(&on.text);
        let comment = tokens(&on.comments);
        let n = shingle_len(&case);
        let allowed = shingles(&tokens(&case.gold.text_of("quote").join("\n")), n);
        let shared: BTreeSet<String> = shingles(&main, n)
            .intersection(&shingles(&comment, n))
            .cloned()
            .collect();
        let unexpected: Vec<&String> = shared.difference(&allowed).collect();
        assert!(
            unexpected.is_empty(),
            "{id}: main and comment text share {unexpected:?}"
        );
        // The main-only vocabulary never reaches the comments (the quote vocabulary is shared by
        // design).
        let others = gold_bag(&case, &["comment", "quote", "boilerplate"]);
        let comment_bag = bag(comment.iter().cloned());
        let reversed: Vec<String> = gold_bag(&case, &["body"])
            .into_keys()
            .filter(|t| !others.contains_key(t) && comment_bag.contains_key(t))
            .collect();
        assert!(
            reversed.is_empty(),
            "{id}: main-only tokens in the comments: {reversed:?}"
        );
        if !flag(&case, "forum") && !case.gold.text_of("quote").is_empty() {
            // The intentional quote is kept in the comment, where the reader put it.
            assert!(
                allowed.is_subset(&shingles(&comment, n)),
                "{id}: quoted text missing from the comments"
            );
        }
    }
}

#[test]
fn main_blocks_are_never_duplicated_and_forum_posts_appear_exactly_once() {
    for case in cases_of(&[COMMENTS]) {
        let id = &case.entry.id;
        let on = extract(&case, ContentFocusV1::Balanced, CommentPolicyV1::Separate);
        let output = tokens(&on.text);
        let forum = flag(&case, "forum");
        let (lines, stream) = counted_lines(&case);
        assert!(!lines.is_empty(), "{id}: no long body line");
        for line in &lines {
            let (found, expected) = (occurrences(&output, line), occurrences(&stream, line));
            let text = line.join(" ");
            assert!(
                found <= expected,
                "{id}: block `{text}` is duplicated ({found} > {expected})"
            );
            if forum {
                assert_eq!(
                    found, expected,
                    "{id}: post `{text}` is not preserved exactly once"
                );
            }
        }
        if forum {
            // Every post of a forum topic is main text, so nothing may be split off as comment.
            assert!(on.comments.is_empty(), "{id}");
            assert!(lines.len() >= 3, "{id}: a forum topic holds several posts");
        }
    }
}

#[test]
fn comment_corpus_scores_meet_the_measured_floors() {
    let mut main = Vec::new();
    let mut comment_text = Vec::new();
    for case in cases_of(&[COMMENTS]) {
        let on = extract(&case, ContentFocusV1::Balanced, CommentPolicyV1::Separate);
        let body = counts(&gold_bag(&case, &["body"]), &on.text);
        eprintln!(
            "comments {}: main p={:.4} r={:.4}",
            case.entry.id,
            body.precision(),
            body.recall()
        );
        main.push(body);
        if !case.gold.text_of("comment").is_empty() {
            let mut expected = gold_bag(&case, &["comment"]);
            for (token, n) in gold_bag(&case, &["quote"]) {
                *expected.entry(token).or_default() += n;
            }
            let c = counts(&expected, &on.comments);
            eprintln!(
                "comments {}: comment text p={:.4} r={:.4}",
                case.entry.id,
                c.precision(),
                c.recall()
            );
            comment_text.push(c);
        }
    }
    let main = aggregate(&main);
    let comment_text = aggregate(&comment_text);
    eprintln!(
        "comments main: micro_p={:.4} micro_r={:.4} macro_f1={:.4} worst_f1={:.4}",
        main.micro.precision(),
        main.micro.recall(),
        main.macro_f1,
        main.worst_f1
    );
    eprintln!(
        "comments text: micro_p={:.4} micro_r={:.4} macro_f1={:.4} worst_f1={:.4}",
        comment_text.micro.precision(),
        comment_text.micro.recall(),
        comment_text.macro_f1,
        comment_text.worst_f1
    );
    assert!(main.micro.recall() >= COMMENT_MAIN_RECALL_FLOOR, "main recall");
    assert!(
        main.micro.precision() >= COMMENT_MAIN_PRECISION_FLOOR,
        "main precision"
    );
    assert!(
        comment_text.micro.recall() >= COMMENT_TEXT_RECALL_FLOOR,
        "comment recall"
    );
}
