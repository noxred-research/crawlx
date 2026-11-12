#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Authored language-evidence, tokenizer and native-NLP corpus (families `language` and `nlp`).
//!
//! Every file under `tests/corpus/` was written for this repository (license
//! `authored-for-this-repo`); `manifest.language.json` and `manifest.nlp.json` list the fixtures
//! with SHA-256 digests and per-case `params`. Gold files hold an `expectedText` and labeled
//! UTF-8 byte spans into it.
//!
//! # `language`
//!
//! * Gold: `expectedText` is the expected tokens of the main text joined by `|`; every span is
//!   labeled `token`. The tokenizer under test is `params.tokenizer` (`unicode_rules_v1` or
//!   `dictionary_uax29`, the dictionary and word-boundary tokenizer). Segmentation is observed through the keyword list: the
//!   fixtures hold at most 35 distinct keyword tokens, so the extractor's keywords (count, token,
//!   first source range) determine the token multiset and every first occurrence exactly. The
//!   test also tiles the extracted main text with the gold tokens: no word of the main text may
//!   lie outside a gold token.
//! * `params.language` holds the expected declared-language evidence: selected value, declared
//!   value, uncertainty, the exact `(source, raw)` evidence list in order, and whether the
//!   detector is reported unavailable. A page without any language evidence must yield no
//!   language; an unavailable detector must be reported, never replaced by a guess.
//! * `params.class` groups documents. Every supported class of each tokenizer needs at least five
//!   documents. Unsupported classes (`supported: false`) keep a semantic gold, carry a
//!   `knownDivergence` pin (reason plus the measured keyword list) and are published; the test
//!   fails if a pinned output changes or starts to match, so a fix must promote the class.
//! * Detection accuracy is not gated here: the statistical language detector bundle is
//!   operator-supplied and unavailable in this repository, so no detector F1 is claimed. The
//!   suite proves only the explicit unavailable state (`language_model_unavailable`, quality
//!   reason `model_unavailable`, no detected value).
//!
//! # `nlp`
//!
//! * Gold: `expectedText` lists the semantic sentences (label `sentence`, one per line) followed
//!   by `token=count` lines (labels `keyword` and `score`) for the top `params.keywords`
//!   keywords. Keyword gold follows the documented rule: score is the occurrence count,
//!   ordered by count descending, first occurrence ascending, then token; digits-only tokens are
//!   dropped; the 26-word English list is dropped only when the declared language is English.
//! * Sentences are observed through the summary with room for every sentence (20 sentences,
//!   20,000 characters). Gate assertions (hard): summary slices lie inside the main text and the
//!   source paragraphs, appear in source order, are deterministic, match the documented ranking
//!   (reference model over the extractor's own sentences and keywords), keyword counts and
//!   ordering are exact and invariant under doubling the input, `Off` and `SentenceModel` are
//!   bounded. Sentence boundaries against the semantic gold are a measured metric; cases where
//!   the rule splitter differs carry a pin.

mod corpus_support;

use std::collections::{BTreeMap, BTreeSet};

use corpus_support::*;
use crawlx_core::article_language::LanguageModeV1;
use crawlx_core::extraction::{
    ArticleTokenizerV1, ExtractionPolicyV1, NlpCapabilityV1, QualityReasonV1, QualityStatusV1,
};
use crawlx_core::hash::Digest;
use crawlx_extract::{Document, ExtractOptions, Extractor};
use serde_json::Value;
use url::Url;

const RULES: &str = "unicode_rules_v1";
const DICT: &str = "dictionary_uax29";

/// Supported classes per tokenizer, each needing at least five documents.
const SUPPORTED_CLASSES: [(&str, &str); 10] = [
    (RULES, "latin"),
    (RULES, "cyrillic"),
    (RULES, "greek"),
    (RULES, "abjad"),
    (RULES, "han_kana"),
    (DICT, "thai"),
    (DICT, "chinese"),
    (DICT, "japanese"),
    (DICT, "devanagari"),
    (DICT, "uax29_latin"),
];

/// Script classes with no authored fixtures: nothing is claimed for them.
const UNVERIFIED_CLASSES: [&str; 5] = [
    "dictionary tokenizer: Khmer, Lao and Burmese (no authored fixtures)",
    "dictionary tokenizer: Korean (space-delimited; no authored fixtures)",
    "rules tokenizer: Indic scripts, Thai and Southeast Asian scripts without spaces (see unsupported classes)",
    "language detection accuracy (needs the operator-supplied detector bundle, unavailable here)",
    "sentence boundaries of scripts without terminal punctuation (Thai)",
];

/// Token-level segmentation floors, measured on this corpus (pinned unsupported classes
/// included) and set just under the observed values; the worst rules case is an unsupported
/// script. They describe this authored corpus only.
const FLOOR_RULES_MACRO: f64 = 0.93;
const FLOOR_RULES_PRECISION: f64 = 0.96;
const FLOOR_RULES_RECALL: f64 = 0.97;
const FLOOR_RULES_WORST: f64 = 0.0;
const FLOOR_DICT_MACRO: f64 = 0.93;
const FLOOR_DICT_PRECISION: f64 = 0.92;
const FLOOR_DICT_RECALL: f64 = 0.92;
const FLOOR_DICT_WORST: f64 = 0.63;

const FLOOR_SENTENCE_MACRO: f64 = 0.84;
const FLOOR_SENTENCE_PRECISION: f64 = 0.79;
const FLOOR_SENTENCE_RECALL: f64 = 0.88;
const FLOOR_SENTENCE_WORST: f64 = 0.0;

const ENGLISH_STOPWORDS: [&str; 26] = [
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "in", "is", "it", "of", "on",
    "or", "that", "the", "their", "this", "to", "was", "were", "will", "with",
];

// ------------------------------------------------------------------------------------------
// shared helpers
// ------------------------------------------------------------------------------------------

fn param<'a>(case: &'a Case, key: &str) -> &'a Value {
    &case.entry.params[key]
}

fn param_str<'a>(case: &'a Case, key: &str) -> &'a str {
    param(case, key)
        .as_str()
        .unwrap_or_else(|| panic!("{}: params.{key} is not a string", case.entry.id))
}

fn tokenizer_of(case: &Case) -> ArticleTokenizerV1 {
    match param_str(case, "tokenizer") {
        RULES => ArticleTokenizerV1::UnicodeRulesV1,
        DICT => ArticleTokenizerV1::IcuDictionaryUax29V17V1,
        other => panic!("{}: unknown tokenizer {other}", case.entry.id),
    }
}

/// The tokenizer revision the envelope records: the serialized name of the requested tokenizer.
fn expected_tokenizer_version(case: &Case) -> String {
    serde_json::to_value(tokenizer_of(case))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn is_cjk(c: char) -> bool {
    ('\u{3400}'..='\u{9fff}').contains(&c) || ('\u{3040}'..='\u{30ff}').contains(&c)
}

/// The documented `unicode_rules_v1` word rule: alphanumeric runs, each Han or kana scalar alone.
fn rules_tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut run = String::new();
    for c in text.chars().chain(std::iter::once(' ')) {
        if c.is_alphanumeric() && !is_cjk(c) {
            run.push(c);
            continue;
        }
        if !run.is_empty() {
            out.push(run.to_lowercase());
            run.clear();
        }
        if is_cjk(c) {
            out.push(c.to_lowercase().collect());
        }
    }
    out
}

fn extract(html: &str, page: &str, policy: ExtractionPolicyV1) -> Document {
    Extractor::extract(
        html,
        &Url::parse(page).unwrap(),
        &ExtractOptions {
            content: Some(policy),
            ..ExtractOptions::default()
        },
    )
    .unwrap_or_else(|e| panic!("{page}: {e}"))
}

fn base_policy(case: &Case) -> ExtractionPolicyV1 {
    let mut policy = ExtractionPolicyV1::default();
    policy.tokenizer = tokenizer_of(case);
    policy.min_main_chars = 1;
    policy.keywords = 35;
    policy.summary_sentences = 20;
    policy.summary_max_chars = 20_000;
    policy
}

/// Keyword-rule view of gold tokens: digits-only tokens and (for English) listed stopwords drop.
fn keyword_ranking(tokens: &[String], english: bool) -> Vec<(String, usize)> {
    let mut counts: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for (index, token) in tokens.iter().enumerate() {
        if (english && ENGLISH_STOPWORDS.contains(&token.as_str())) || token.chars().all(char::is_numeric) {
            continue;
        }
        counts.entry(token).or_insert((0, index)).0 += 1;
    }
    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|(ta, (ca, fa)), (tb, (cb, fb))| cb.cmp(ca).then(fa.cmp(fb)).then(ta.cmp(tb)));
    ranked
        .into_iter()
        .map(|(token, (count, _))| (token.to_owned(), count))
        .collect()
}

fn actual_keywords(document: &Document) -> Vec<(String, usize)> {
    document
        .article
        .as_ref()
        .expect("content policy yields an envelope")
        .metadata
        .keywords
        .iter()
        .map(|k| (k.token.clone(), k.score))
        .collect()
}

fn pinned_keywords(pin: &Value) -> Vec<(String, usize)> {
    pin["measured"]["keywords"]
        .as_array()
        .expect("pin carries the measured keyword list")
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().unwrap().to_owned(),
                usize::try_from(pair[1].as_u64().unwrap()).unwrap(),
            )
        })
        .collect()
}

/// Locate `token` (lowercase) in `main` at or after `from`: the first source slice whose
/// lowercase equals the token. Returns the byte range.
fn locate(main: &str, from: usize, token: &str) -> Option<(usize, usize)> {
    let first = token.chars().next()?;
    for (start, ch) in main[from..].char_indices() {
        let start = from + start;
        if !ch.to_lowercase().next().is_some_and(|l| l == first) && ch != first {
            continue;
        }
        for (offset, last) in main[start..].char_indices() {
            let end = start + offset + last.len_utf8();
            let lowered = main[start..end].to_lowercase();
            if lowered == token {
                return Some((start, end));
            }
            if lowered.len() > token.len() {
                break;
            }
        }
    }
    None
}

/// Tile `main` with `tokens` in order. Returns the byte range of every token, or the reason the
/// tiling fails (a token that is absent, or a word of `main` that lies outside every token).
fn tile(main: &str, tokens: &[String]) -> Result<Vec<(usize, usize)>, String> {
    let mut cursor = 0;
    let mut ranges = Vec::with_capacity(tokens.len());
    for token in tokens {
        let (start, end) = locate(main, cursor, token)
            .ok_or_else(|| format!("token {token:?} not found after byte {cursor}"))?;
        if let Some(gap) = main[cursor..start].chars().find(|c| c.is_alphanumeric()) {
            return Err(format!(
                "text {:?} before token {token:?} lies outside every gold token (first word char {gap:?})",
                &main[cursor..start]
            ));
        }
        ranges.push((start, end));
        cursor = end;
    }
    if let Some(gap) = main[cursor..].chars().find(|c| c.is_alphanumeric()) {
        return Err(format!(
            "trailing text {:?} lies outside every gold token (first word char {gap:?})",
            &main[cursor..]
        ));
    }
    Ok(ranges)
}

/// Visible text of the page's `article`/`main` element, paragraph by paragraph.
fn page_paragraphs(html: &str) -> Vec<String> {
    let parsed = scraper::Html::parse_document(html);
    let selector = scraper::Selector::parse("article > *, main > *").unwrap();
    parsed
        .select(&selector)
        .map(|e| e.text().collect::<String>())
        .collect()
}

fn gold_ranges_valid(case: &Case, labels: &[&str]) {
    let id = &case.entry.id;
    let Gold {
        expected_text, spans, ..
    } = &case.gold;
    assert!(!spans.is_empty(), "{id}: no spans");
    let mut previous_end = 0;
    for span in spans {
        assert!(
            span.start < span.end && span.end <= expected_text.len(),
            "{id}: span out of range"
        );
        assert!(span.start >= previous_end, "{id}: overlapping or unsorted span");
        assert!(
            expected_text.is_char_boundary(span.start) && expected_text.is_char_boundary(span.end),
            "{id}: span splits a UTF-8 sequence"
        );
        assert!(
            labels.contains(&span.label.as_str()),
            "{id}: unexpected label {}",
            span.label
        );
        previous_end = span.end;
    }
}

fn manifest_digests_match(family: &str, file: &str) {
    let parsed: Manifest = serde_json::from_slice(&read(file)).unwrap();
    assert_eq!(parsed.version, 1);
    assert!(parsed.rights.contains("written for this repository"));
    for entry in &parsed.cases {
        assert_eq!(entry.family, family, "{file}: {}", entry.id);
        assert_eq!(entry.license, LICENSE, "{}", entry.id);
        assert!(
            Url::parse(&entry.page_url)
                .unwrap()
                .host_str()
                .is_some_and(|h| h.ends_with(".test")),
            "{}",
            entry.id
        );
        for reference in [&entry.files.input, &entry.files.gold] {
            assert_eq!(
                sha256_hex(&read(&reference.path)),
                reference.sha256,
                "{}",
                reference.path
            );
        }
        let gold: Gold = serde_json::from_slice(&read(&entry.files.gold.path)).unwrap();
        assert_eq!(
            (gold.id.as_str(), gold.family.as_str()),
            (entry.id.as_str(), family)
        );
    }
}

// ------------------------------------------------------------------------------------------
// language
// ------------------------------------------------------------------------------------------

fn language_cases() -> Vec<Case> {
    cases_of(&["language"])
}

fn language_policy(case: &Case) -> ExtractionPolicyV1 {
    let mut policy = base_policy(case);
    policy.language_mode = match param_str(case, "mode") {
        "declared_only" => LanguageModeV1::DeclaredOnly,
        "declared_then_detect" => LanguageModeV1::DeclaredThenDetect,
        "detect" => LanguageModeV1::Detect,
        other => panic!("{}: unknown mode {other}", case.entry.id),
    };
    if policy.language_mode != LanguageModeV1::DeclaredOnly {
        // A digest that no injected detector carries: the operator bundle is absent.
        policy.language_bundle_digest = Some(Digest::of("corpus.test.language-bundle", b"absent"));
    }
    if let Some(target) = param(case, "targetLanguage").as_str() {
        policy.target_language = Some(target.to_owned());
    }
    policy
}

fn language_document(case: &Case) -> Document {
    extract(&case.html, &case.entry.page_url, language_policy(case))
}

fn gold_tokens(case: &Case) -> Vec<String> {
    case.gold
        .spans
        .iter()
        .map(|s| case.gold.expected_text[s.start..s.end].to_owned())
        .collect()
}

fn expected_language(case: &Case) -> &Value {
    param(case, "language")
}

fn english_value(case: &Case) -> bool {
    expected_language(case)["value"]
        .as_str()
        .is_some_and(|v| v == "en" || v.starts_with("en-"))
}

/// Exact segmentation check: `Err` lists every difference from gold.
fn segmentation_diff(case: &Case, document: &Document) -> Result<(), String> {
    let tokens = gold_tokens(case);
    let metadata = &document.article.as_ref().expect("envelope").metadata;
    let mut problems = Vec::new();
    let expected_version = expected_tokenizer_version(case);
    if metadata.tokenizer_version.as_deref() != Some(expected_version.as_str()) {
        problems.push(format!("tokenizer_version {:?}", metadata.tokenizer_version));
    }
    if metadata.tokenizer_unavailable || metadata.nlp_truncated {
        problems.push("tokenizer unavailable or output truncated".to_owned());
    }
    let ranges = match tile(&document.text, &tokens) {
        Ok(ranges) => ranges,
        Err(reason) => {
            problems.push(reason);
            Vec::new()
        }
    };
    let expected = keyword_ranking(&tokens, english_value(case));
    let actual = actual_keywords(document);
    if expected != actual {
        problems.push(format!("keywords expected {expected:?}, got {actual:?}"));
    } else if !ranges.is_empty() {
        for (keyword, (token, _)) in metadata.keywords.iter().zip(&expected) {
            let index = tokens.iter().position(|t| t == token).unwrap();
            let (start, end) = ranges[index];
            if (keyword.source.start, keyword.source.end) != (start, end) {
                problems.push(format!(
                    "first range of {token:?} expected {start}..{end}, got {}..{}",
                    keyword.source.start, keyword.source.end
                ));
            }
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("; "))
    }
}

#[test]
fn language_manifest_has_plan_sized_classes_and_valid_gold() {
    manifest_digests_match("language", "manifest.language.json");
    let cases = language_cases();
    let mut classes: BTreeMap<(String, String), usize> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for case in &cases {
        let id = &case.entry.id;
        assert!(ids.insert(id.clone()), "duplicate id {id}");
        let number: usize = id[1..].split('-').next().unwrap().parse().unwrap();
        assert!(
            id.starts_with('l') && number >= 10,
            "{id}: language ids are l10 and up"
        );
        gold_ranges_valid(case, &["token"]);
        let tokens = gold_tokens(case);
        assert_eq!(
            case.gold.expected_text,
            tokens.join("|"),
            "{id}: expectedText is the tokens joined by |"
        );
        assert!(tokens.iter().all(|t| !t.is_empty() && !t.contains('|')), "{id}");
        let distinct = keyword_ranking(&tokens, english_value(case)).len();
        assert!(
            distinct <= 35,
            "{id}: {distinct} distinct keyword tokens exceed the 35 observable"
        );
        // Gold is checked against the page itself, not extractor output: the tokens tile the
        // visible text of the article element, with no word left over.
        let paragraphs = page_paragraphs(&case.html).join("\n");
        tile(&paragraphs, &tokens)
            .unwrap_or_else(|reason| panic!("{id}: gold does not tile the page text: {reason}"));
        *classes
            .entry((
                param_str(case, "tokenizer").to_owned(),
                param_str(case, "class").to_owned(),
            ))
            .or_default() += 1;
        let pin = param(case, "knownDivergence");
        if param(case, "supported") == &Value::Bool(false) {
            assert!(
                pin["reason"].as_str().is_some_and(|r| !r.is_empty()),
                "{id}: unsupported class needs a pin"
            );
            assert!(
                pin["measured"]["keywords"].is_array(),
                "{id}: unsupported class pins the measured keywords"
            );
        }
        if pin.is_object() {
            assert!(
                pin["reason"].as_str().is_some_and(|r| !r.is_empty()),
                "{id}: a pin needs a reason"
            );
        }
    }
    for (tokenizer, class) in SUPPORTED_CLASSES {
        let count = classes
            .get(&(tokenizer.to_owned(), class.to_owned()))
            .copied()
            .unwrap_or(0);
        assert!(count >= 5, "{tokenizer}/{class}: {count} documents, need 5");
    }
    for (class, minimum) in [
        ("no_evidence", 3),
        ("mixed", 3),
        ("conflict", 2),
        ("invalid", 2),
        ("short", 2),
        ("detector_unavailable", 3),
        ("target", 3),
        ("declared", 3),
    ] {
        let count: usize = classes
            .iter()
            .filter(|((_, c), _)| c == class)
            .map(|(_, n)| n)
            .sum();
        assert!(count >= minimum, "{class}: {count} documents, need {minimum}");
    }
    assert!(cases.len() >= 60, "{} language documents", cases.len());
}

#[test]
fn language_tokenizer_segmentation_is_exact_or_pinned_as_unsupported() {
    let mut exact = 0;
    let mut pinned = Vec::new();
    let mut failures = Vec::new();
    for case in language_cases() {
        let id = case.entry.id.clone();
        let document = language_document(&case);
        let outcome = segmentation_diff(&case, &document);
        let pin = param(&case, "knownDivergence");
        match (outcome, pin["measured"]["keywords"].is_array()) {
            (Ok(()), false) => exact += 1,
            (Err(diff), false) => failures.push(format!("{id}: {diff}")),
            (Ok(()), true) => failures.push(format!(
                "{id}: pinned divergence now matches gold; promote the class"
            )),
            (Err(_), true) => {
                if actual_keywords(&document) == pinned_keywords(pin) {
                    pinned.push((id, pin["reason"].as_str().unwrap().to_owned()));
                } else {
                    failures.push(format!(
                        "{id}: pinned output changed: {:?} (pin {:?})",
                        actual_keywords(&document),
                        pinned_keywords(pin)
                    ));
                }
            }
        }
    }
    eprintln!(
        "language segmentation: {exact} exact, {} pinned divergences",
        pinned.len()
    );
    for (id, reason) in &pinned {
        eprintln!("  pinned {id}: {reason}");
    }
    assert!(
        failures.is_empty(),
        "segmentation differs from gold:\n{}",
        failures.join("\n")
    );
}

/// Token-level scores of the extractor's segmentation against gold, per tokenizer, over every
/// document including the pinned ones. Published; the floors are measured.
fn segmentation_scores() -> BTreeMap<String, Family> {
    let mut per_tokenizer: BTreeMap<String, Vec<Counts>> = BTreeMap::new();
    for case in language_cases() {
        let document = language_document(&case);
        let gold = bag(keyword_ranking(&gold_tokens(&case), english_value(&case))
            .into_iter()
            .flat_map(|(token, count)| std::iter::repeat_n(token, count)));
        let output = bag(actual_keywords(&document)
            .into_iter()
            .flat_map(|(token, count)| std::iter::repeat_n(token, count)));
        per_tokenizer
            .entry(param_str(&case, "tokenizer").to_owned())
            .or_default()
            .push(Counts {
                tp: overlap(&gold, &output),
                predicted: size(&output),
                gold: size(&gold),
            });
    }
    per_tokenizer
        .into_iter()
        .map(|(tokenizer, counts)| (tokenizer, aggregate(&counts)))
        .collect()
}

#[test]
fn language_segmentation_scores_are_published_with_measured_floors() {
    let scores = segmentation_scores();
    check(
        "language segmentation (unicode_rules_v1)",
        &scores[RULES],
        &Floors {
            macro_f1: FLOOR_RULES_MACRO,
            micro_precision: FLOOR_RULES_PRECISION,
            micro_recall: FLOOR_RULES_RECALL,
            worst_case_f1: FLOOR_RULES_WORST,
        },
    );
    check(
        "language segmentation (dictionary_uax29)",
        &scores[DICT],
        &Floors {
            macro_f1: FLOOR_DICT_MACRO,
            micro_precision: FLOOR_DICT_PRECISION,
            micro_recall: FLOOR_DICT_RECALL,
            worst_case_f1: FLOOR_DICT_WORST,
        },
    );
}

#[test]
fn language_evidence_is_exact_and_never_fabricated() {
    let mut failures = Vec::new();
    for case in language_cases() {
        let id = &case.entry.id;
        let document = language_document(&case);
        let envelope = document.article.as_ref().expect("envelope");
        let metadata = &envelope.metadata;
        let expected = expected_language(&case);
        let evidence: Vec<(String, String)> = metadata
            .language
            .evidence
            .iter()
            .map(|e| (e.source.clone(), e.raw.clone()))
            .collect();
        let expected_evidence: Vec<(String, String)> = expected["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_owned(),
                    pair[1].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let mut check = |what: &str, ok: bool, detail: String| {
            if !ok {
                failures.push(format!("{id}: {what}: {detail}"));
            }
        };
        let pinned = &param(&case, "knownDivergence")["measured"]["language"];
        if pinned.is_object() {
            // A measured divergence from the gold: pinned exactly, and it must still differ.
            let measured: Vec<(String, String)> = pinned["evidence"]
                .as_array()
                .unwrap()
                .iter()
                .map(|pair| {
                    (
                        pair[0].as_str().unwrap().to_owned(),
                        pair[1].as_str().unwrap().to_owned(),
                    )
                })
                .collect();
            let same_as_pin = metadata.language.value.as_deref() == pinned["value"].as_str()
                && Some(metadata.language.uncertain) == pinned["uncertain"].as_bool()
                && evidence == measured;
            let same_as_gold = metadata.language.value.as_deref() == expected["value"].as_str()
                && Some(metadata.language.uncertain) == expected["uncertain"].as_bool()
                && evidence == expected_evidence;
            check(
                "pinned language evidence",
                same_as_pin && !same_as_gold,
                format!("{evidence:?} uncertain {}", metadata.language.uncertain),
            );
        } else {
            check(
                "value",
                metadata.language.value.as_deref() == expected["value"].as_str(),
                format!("{:?} vs {:?}", metadata.language.value, expected["value"]),
            );
            check(
                "uncertain",
                Some(metadata.language.uncertain) == expected["uncertain"].as_bool(),
                format!("{} vs {:?}", metadata.language.uncertain, expected["uncertain"]),
            );
            check(
                "evidence",
                evidence == expected_evidence,
                format!("{evidence:?} vs {expected_evidence:?}"),
            );
        }
        check(
            "declared",
            metadata.declared_language.as_deref() == expected["declared"].as_str(),
            format!("{:?} vs {:?}", metadata.declared_language, expected["declared"]),
        );
        check(
            "model unavailable",
            Some(metadata.language_model_unavailable) == expected["unavailable"].as_bool(),
            format!(
                "{} vs {:?}",
                metadata.language_model_unavailable, expected["unavailable"]
            ),
        );
        check(
            "no detected value or bundle",
            metadata.detected_language.value.is_none() && metadata.language_model_digest.is_none(),
            format!(
                "{:?} {:?}",
                metadata.detected_language.value, metadata.language_model_digest
            ),
        );
        let reasons: Vec<String> = envelope
            .quality
            .reasons
            .iter()
            .map(|r| serde_json::to_value(r).unwrap().as_str().unwrap().to_owned())
            .collect();
        let expected_reasons: Vec<String> = param(&case, "qualityReasons")
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r.as_str().unwrap().to_owned())
            .collect();
        check(
            "quality reasons",
            reasons == expected_reasons,
            format!("{reasons:?} vs {expected_reasons:?}"),
        );
        let status = serde_json::to_value(envelope.quality.status).unwrap();
        check(
            "quality status",
            status == param(&case, "qualityStatus").clone(),
            format!("{status} vs {}", param(&case, "qualityStatus")),
        );
        // No page without a declaration may be assigned English or any other language.
        if expected_evidence.is_empty() {
            check(
                "fabricated language",
                metadata.language.value.is_none(),
                format!("{:?}", metadata.language.value),
            );
        }
    }
    assert!(
        failures.is_empty(),
        "language evidence differs from gold:\n{}",
        failures.join("\n")
    );
}

#[test]
fn unavailable_detector_is_explicit_for_every_detection_mode() {
    let cases = language_cases();
    let detection: Vec<&Case> = cases
        .iter()
        .filter(|c| param_str(c, "mode") != "declared_only")
        .collect();
    let (needed, not_needed): (Vec<&Case>, Vec<&Case>) = detection
        .iter()
        .partition(|c| expected_language(c)["unavailable"] == Value::Bool(true));
    assert!(needed.len() >= 3 && !not_needed.is_empty());
    for case in needed {
        let document = language_document(case);
        let envelope = document.article.as_ref().unwrap();
        assert!(envelope.metadata.language_model_unavailable, "{}", case.entry.id);
        assert!(envelope.metadata.detected_language.uncertain, "{}", case.entry.id);
        assert!(
            envelope.metadata.detected_language.value.is_none(),
            "{}",
            case.entry.id
        );
        assert_eq!(
            envelope.quality.status,
            QualityStatusV1::Unavailable,
            "{}",
            case.entry.id
        );
        assert!(
            envelope
                .quality
                .reasons
                .contains(&QualityReasonV1::ModelUnavailable),
            "{}",
            case.entry.id
        );
        assert!(
            !document.text.is_empty(),
            "{}: the page text is still extracted",
            case.entry.id
        );
    }
    // A valid declaration satisfies `declared_then_detect`: the detector is never needed.
    for case in not_needed {
        let envelope = language_document(case).article.unwrap();
        assert!(!envelope.metadata.language_model_unavailable, "{}", case.entry.id);
        assert!(envelope.metadata.language.value.is_some(), "{}", case.entry.id);
    }
    // Declared-only extraction never invokes or reports a detector.
    for case in cases.iter().filter(|c| param_str(c, "mode") == "declared_only") {
        let envelope = language_document(case).article.unwrap();
        assert!(!envelope.metadata.language_model_unavailable, "{}", case.entry.id);
        assert!(
            !envelope
                .quality
                .reasons
                .contains(&QualityReasonV1::ModelUnavailable),
            "{}",
            case.entry.id
        );
    }
    // A detector mode needs a digest at admission; the policy is rejected without one.
    let case = &cases[0];
    let mut policy = base_policy(case);
    policy.language_mode = LanguageModeV1::Detect;
    assert!(Extractor::extract(
        &case.html,
        &Url::parse(&case.entry.page_url).unwrap(),
        &ExtractOptions {
            content: Some(policy),
            ..ExtractOptions::default()
        }
    )
    .is_err());
}

#[test]
fn pages_without_language_evidence_yield_no_language() {
    let english = "<html><head><title>Plain notice</title></head><body><article><p>The ferry leaves at nine and the passengers queue by the harbor gate.</p></article></body></html>";
    let envelope = extract(
        english,
        "https://corpus.test/plain",
        ExtractionPolicyV1::default(),
    )
    .article
    .unwrap();
    assert_eq!(envelope.metadata.language.value, None);
    assert!(envelope.metadata.language.evidence.is_empty());
    assert!(!envelope.metadata.language.uncertain);
    assert_eq!(envelope.metadata.declared_language, None);
    let mut policy = ExtractionPolicyV1::default();
    policy.language_mode = LanguageModeV1::Detect;
    policy.language_bundle_digest = Some(Digest::of("corpus.test.language-bundle", b"absent"));
    let envelope = extract(english, "https://corpus.test/plain", policy)
        .article
        .unwrap();
    assert_eq!(envelope.metadata.language.value, None);
    assert!(envelope.metadata.language_model_unavailable);
}

#[test]
fn language_classes_and_unsupported_scripts_are_published() {
    let mut table: BTreeMap<(String, String), (usize, usize)> = BTreeMap::new();
    for case in language_cases() {
        let supported = param(&case, "supported") == &Value::Bool(true);
        let row = table
            .entry((
                param_str(&case, "tokenizer").to_owned(),
                param_str(&case, "class").to_owned(),
            ))
            .or_default();
        row.0 += 1;
        row.1 += usize::from(!supported);
    }
    eprintln!("language classes (tokenizer / class: documents, unsupported documents)");
    for ((tokenizer, class), (documents, unsupported)) in &table {
        eprintln!("  {tokenizer} / {class}: {documents}, unsupported {unsupported}");
    }
    eprintln!("unverified classes (no fixtures, no claim):");
    for line in UNVERIFIED_CLASSES {
        eprintln!("  {line}");
    }
    let unsupported: BTreeSet<&str> = table
        .iter()
        .filter(|(_, (_, unsupported))| *unsupported > 0)
        .map(|((_, class), _)| class.as_str())
        .collect();
    assert_eq!(
        unsupported,
        BTreeSet::from([
            "unsupported_contractions",
            "unsupported_devanagari",
            "unsupported_katakana_middle_dot",
            "unsupported_thai"
        ])
    );
    // Every supported class holds only supported documents.
    for (tokenizer, class) in SUPPORTED_CLASSES {
        assert_eq!(
            table[&(tokenizer.to_owned(), class.to_owned())].1,
            0,
            "{tokenizer}/{class}"
        );
    }
}

// ------------------------------------------------------------------------------------------
// nlp
// ------------------------------------------------------------------------------------------

struct NlpGold {
    sentences: Vec<String>,
    keywords: Vec<(String, usize)>,
}

fn nlp_cases() -> Vec<Case> {
    cases_of(&["nlp"])
}

fn nlp_gold(case: &Case) -> NlpGold {
    let text = &case.gold.expected_text;
    let mut sentences = Vec::new();
    let mut keywords = Vec::new();
    let mut spans = case.gold.spans.iter();
    while let Some(span) = spans.next() {
        let slice = &text[span.start..span.end];
        match span.label.as_str() {
            "sentence" => sentences.push(slice.to_owned()),
            "keyword" => {
                let score = spans.next().expect("a score follows every keyword");
                assert_eq!(score.label, "score", "{}", case.entry.id);
                assert_eq!(&text[span.end..span.end + 1], "=", "{}", case.entry.id);
                keywords.push((slice.to_owned(), text[score.start..score.end].parse().unwrap()));
            }
            other => panic!("{}: unexpected label {other}", case.entry.id),
        }
    }
    NlpGold { sentences, keywords }
}

fn nlp_policy(case: &Case) -> ExtractionPolicyV1 {
    let mut policy = base_policy(case);
    policy.keywords = usize::try_from(param(case, "keywords").as_u64().unwrap()).unwrap();
    policy
}

fn nlp_document(case: &Case, html: &str, policy: ExtractionPolicyV1) -> Document {
    extract(html, &case.entry.page_url, policy)
}

fn summary_slices(document: &Document) -> Vec<&str> {
    document
        .article
        .as_ref()
        .unwrap()
        .metadata
        .summary
        .iter()
        .map(|r| &document.text[r.start..r.end])
        .collect()
}

/// All sentences of the main text as the extractor splits them: a summary with room for all.
fn native_sentences(case: &Case) -> Vec<String> {
    let document = nlp_document(case, &case.html, nlp_policy(case));
    summary_slices(&document).into_iter().map(str::to_owned).collect()
}

fn pin_sentences(pin: &Value) -> Vec<String> {
    pin["measured"]["sentences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn nlp_manifest_has_plan_sized_gold() {
    manifest_digests_match("nlp", "manifest.nlp.json");
    let cases = nlp_cases();
    assert!(cases.len() >= 30, "{} nlp cases, plan minimum 30", cases.len());
    let mut classes: BTreeMap<String, usize> = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for case in &cases {
        let id = &case.entry.id;
        assert!(ids.insert(id.clone()) && id.starts_with('n'), "{id}");
        gold_ranges_valid(case, &["sentence", "keyword", "score"]);
        let gold = nlp_gold(case);
        assert!(!gold.sentences.is_empty() && gold.sentences.len() <= 20, "{id}");
        assert_eq!(
            gold.sentences.len(),
            usize::try_from(param(case, "sentences").as_u64().unwrap()).unwrap(),
            "{id}"
        );
        assert!(
            gold.keywords.len() <= usize::try_from(param(case, "keywords").as_u64().unwrap()).unwrap(),
            "{id}"
        );
        // Gold sentences are real, in-order slices of the page's own paragraphs.
        let paragraphs = page_paragraphs(&case.html);
        let mut paragraph = 0;
        let mut cursor = 0;
        for sentence in &gold.sentences {
            loop {
                let text = paragraphs
                    .get(paragraph)
                    .unwrap_or_else(|| panic!("{id}: sentence {sentence:?} not in the page"));
                if let Some(found) = text[cursor..].find(sentence.as_str()) {
                    cursor += found + sentence.len();
                    break;
                }
                paragraph += 1;
                cursor = 0;
            }
        }
        // Gold keywords follow the documented rule over the page's own tokens.
        let english = param(case, "language")
            .as_str()
            .is_some_and(|l| l == "en" || l.starts_with("en-"));
        let tokens: Vec<String> = if param_str(case, "tokenizer") == RULES {
            paragraphs.iter().flat_map(|p| rules_tokens(p)).collect()
        } else {
            Vec::new()
        };
        if !tokens.is_empty() {
            let ranked = keyword_ranking(&tokens, english);
            let limit = usize::try_from(param(case, "keywords").as_u64().unwrap()).unwrap();
            assert_eq!(
                gold.keywords,
                ranked.into_iter().take(limit).collect::<Vec<_>>(),
                "{id}"
            );
        }
        *classes.entry(param_str(case, "class").to_owned()).or_default() += 1;
    }
    for class in [
        "sentences",
        "abbreviation",
        "quote",
        "cjk",
        "thai",
        "ties",
        "numbers",
        "limits",
    ] {
        assert!(classes.get(class).copied().unwrap_or(0) >= 1, "{class}");
    }
    assert!(
        classes["abbreviation"] >= 6 && classes["quote"] >= 5 && classes["cjk"] >= 6 && classes["ties"] >= 6
    );
}

#[test]
fn nlp_keywords_follow_the_documented_rule_exactly() {
    let mut failures = Vec::new();
    for case in nlp_cases() {
        let gold = nlp_gold(&case);
        let document = nlp_document(&case, &case.html, nlp_policy(&case));
        let actual = actual_keywords(&document);
        let pin = param(&case, "knownDivergence");
        if let Some(measured) = pin["measured"].get("keywords") {
            let measured = pinned_keywords(&serde_json::json!({ "measured": { "keywords": measured } }));
            if actual != measured || actual == gold.keywords {
                failures.push(format!(
                    "{}: keyword pin {measured:?}, got {actual:?}, gold {:?}",
                    case.entry.id, gold.keywords
                ));
            }
        } else if actual != gold.keywords {
            failures.push(format!(
                "{}: keywords {actual:?}, gold {:?}",
                case.entry.id, gold.keywords
            ));
        }
        let article = document.article.as_ref().unwrap();
        for keyword in &article.metadata.keywords {
            let slice = &document.text[keyword.source.start..keyword.source.end];
            if slice.to_lowercase() != keyword.token {
                failures.push(format!(
                    "{}: keyword {:?} range slices {slice:?}",
                    case.entry.id, keyword.token
                ));
            }
        }
        if article.metadata.tokenizer_version.as_deref() != Some(expected_tokenizer_version(&case).as_str()) {
            failures.push(format!(
                "{}: tokenizer version {:?}",
                case.entry.id, article.metadata.tokenizer_version
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Keyword ties: equal counts order by first occurrence, never alphabetically.
#[test]
fn keyword_ties_break_by_first_occurrence_then_token() {
    let cases = nlp_cases();
    let case = |id: &str| {
        cases
            .iter()
            .find(|c| c.entry.id == id)
            .unwrap_or_else(|| panic!("{id}"))
    };
    let order = |id: &str| {
        let case = case(id);
        let document = nlp_document(case, &case.html, nlp_policy(case));
        actual_keywords(&document)
    };
    assert_eq!(
        order("n28-ties-first-occurrence-not-alphabetical"),
        [("zebra", 2), ("mango", 2), ("apple", 2), ("kiwi", 2)].map(|(t, c)| (t.to_owned(), c))
    );
    assert_eq!(
        order("n29-ties-two-levels"),
        [("copper", 3), ("tin", 2), ("zinc", 1), ("lead", 1), ("nickel", 1)].map(|(t, c)| (t.to_owned(), c))
    );
    assert_eq!(
        order("n34-keyword-limit-with-all-ties"),
        [("alder", 1), ("birch", 1), ("cedar", 1)].map(|(t, c)| (t.to_owned(), c))
    );
    // Source order of every equal-count run is first-occurrence order.
    for case in &cases {
        let document = nlp_document(case, &case.html, nlp_policy(case));
        let keywords = &document.article.as_ref().unwrap().metadata.keywords;
        for pair in keywords.windows(2) {
            assert!(pair[0].score >= pair[1].score, "{}", case.entry.id);
            if pair[0].score == pair[1].score {
                assert!(
                    (pair[0].source.start, &pair[0].token) < (pair[1].source.start, &pair[1].token),
                    "{}: tie order",
                    case.entry.id
                );
            }
        }
    }
}

#[test]
fn nlp_sentence_boundaries_are_measured_against_semantic_gold() {
    let mut per_case = Vec::new();
    let mut by_class: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut divergent = Vec::new();
    for case in nlp_cases() {
        let id = case.entry.id.clone();
        let gold = nlp_gold(&case);
        let actual = native_sentences(&case);
        let gold_bag = bag(gold.sentences.iter().cloned());
        let actual_bag = bag(actual.iter().cloned());
        per_case.push(Counts {
            tp: overlap(&gold_bag, &actual_bag),
            predicted: size(&actual_bag),
            gold: size(&gold_bag),
        });
        let row = by_class.entry(param_str(&case, "class").to_owned()).or_default();
        row.0 += 1;
        let pin = param(&case, "knownDivergence");
        if let Some(measured) = pin["measured"].get("sentences") {
            let measured = pin_sentences(&serde_json::json!({ "measured": { "sentences": measured } }));
            if actual != measured || actual == gold.sentences {
                failures.push(format!(
                    "{id}: sentence pin {measured:?}, got {actual:?}, gold {:?}",
                    gold.sentences
                ));
            }
            divergent.push((id, pin["reason"].as_str().unwrap().to_owned()));
        } else {
            row.1 += 1;
            if actual != gold.sentences {
                failures.push(format!("{id}: sentences {actual:?}, gold {:?}", gold.sentences));
            }
        }
    }
    let family = aggregate(&per_case);
    eprintln!(
        "nlp sentence boundaries: macro F1 {:.4}, micro P {:.4} R {:.4} F1 {:.4}, worst case F1 {:.4}",
        family.macro_f1,
        family.micro.precision(),
        family.micro.recall(),
        family.micro.f1(),
        family.worst_f1
    );
    for (class, (cases, exact)) in &by_class {
        eprintln!("  {class}: {exact}/{cases} exact");
    }
    eprintln!("sentence classes where the rule splitter differs from the semantic gold:");
    for (id, reason) in &divergent {
        eprintln!("  {id}: {reason}");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    check(
        "nlp sentence boundaries",
        &family,
        &Floors {
            macro_f1: FLOOR_SENTENCE_MACRO,
            micro_precision: FLOOR_SENTENCE_PRECISION,
            micro_recall: FLOOR_SENTENCE_RECALL,
            worst_case_f1: FLOOR_SENTENCE_WORST,
        },
    );
}

/// Reference model of the documented summary selection: score = 32 per title token + 8 per
/// keyword score + (64 - index) + min(words, 40); highest score first, earlier start on ties;
/// sentences that would pass the character budget are skipped; at most `limit` are kept and
/// returned in source order.
fn reference_summary(
    sentences: &[String],
    title: &str,
    keywords: &[(String, usize)],
    limit: usize,
    max_chars: usize,
) -> Vec<String> {
    let title_tokens: BTreeSet<String> = rules_tokens(title).into_iter().collect();
    let scores: BTreeMap<&str, usize> = keywords.iter().map(|(t, s)| (t.as_str(), *s)).collect();
    let mut scored: Vec<(usize, usize, &String)> = sentences
        .iter()
        .enumerate()
        .map(|(index, sentence)| {
            let words = rules_tokens(sentence);
            let mut score = 0usize;
            for word in &words {
                if title_tokens.contains(word) {
                    score += 32;
                }
                score += scores.get(word.as_str()).map_or(0, |s| s * 8);
            }
            score += 64usize.saturating_sub(index) + words.len().min(40);
            (score, index, sentence)
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut chars = 0usize;
    let mut kept: Vec<(usize, &String)> = Vec::new();
    for (_, index, sentence) in scored {
        let count = sentence.chars().count() + usize::from(chars > 0);
        if chars + count > max_chars {
            continue;
        }
        chars += count;
        kept.push((index, sentence));
        if kept.len() == limit {
            break;
        }
    }
    kept.sort_by_key(|(index, _)| *index);
    kept.into_iter().map(|(_, s)| s.clone()).collect()
}

#[test]
fn summary_sentences_belong_to_the_main_text_in_source_order_and_follow_the_ranking() {
    let mut checked_model = 0;
    for case in nlp_cases() {
        let id = &case.entry.id;
        let policy = nlp_policy(&case);
        let everything = nlp_document(&case, &case.html, policy.clone());
        let all = summary_slices(&everything)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let paragraphs = page_paragraphs(&case.html);
        let envelope = everything.article.as_ref().unwrap();
        let title = envelope.metadata.title.value.clone().unwrap_or_default();
        let keywords = actual_keywords(&everything);
        for (limit, max_chars) in [(1, 20_000), (2, 20_000), (3, 20_000), (2, 60), (20, 20_000)] {
            let mut bounded = policy.clone();
            bounded.summary_sentences = limit;
            bounded.summary_max_chars = max_chars;
            let document = nlp_document(&case, &case.html, bounded);
            let metadata = &document.article.as_ref().unwrap().metadata;
            let mut previous_end = 0;
            for range in &metadata.summary {
                // Every summary sentence is a non-empty, trimmed slice of the extracted main text
                // and of one source paragraph; ranges are disjoint and ascend.
                let slice = document
                    .text
                    .get(range.start..range.end)
                    .unwrap_or_else(|| panic!("{id}: range {range:?} is not a slice of the main text"));
                assert!(!slice.is_empty() && slice == slice.trim(), "{id}: {slice:?}");
                assert!(range.start >= previous_end, "{id}: summary out of source order");
                previous_end = range.end;
                assert!(
                    paragraphs.iter().any(|p| p.contains(slice)),
                    "{id}: summary sentence {slice:?} is not inside a source paragraph"
                );
            }
            let slices: Vec<String> = summary_slices(&document).into_iter().map(str::to_owned).collect();
            assert!(slices.len() <= limit, "{id}");
            if max_chars >= 20_000 {
                assert_eq!(slices.len(), limit.min(all.len()), "{id}: limit {limit}");
            }
            let total: usize =
                slices.iter().map(|s| s.chars().count()).sum::<usize>() + slices.len().saturating_sub(1);
            assert!(total <= max_chars, "{id}: {total} characters exceed {max_chars}");
            if param_str(&case, "tokenizer") == RULES {
                assert_eq!(
                    slices,
                    reference_summary(&all, &title, &keywords, limit, max_chars),
                    "{id}: limit {limit}, budget {max_chars}"
                );
                checked_model += 1;
            }
        }
    }
    assert!(checked_model >= 100, "{checked_model} reference comparisons");
}

#[test]
fn nlp_output_is_deterministic_and_stable_under_repetition() {
    let mut permuted = 0;
    for case in nlp_cases() {
        let id = &case.entry.id;
        let mut policy = nlp_policy(&case);
        policy.keywords = 35;
        let first = nlp_document(&case, &case.html, policy.clone());
        let second = nlp_document(&case, &case.html, policy.clone());
        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap(),
            "{id}: two runs differ"
        );
        let baseline = actual_keywords(&first);
        let ranges: Vec<_> = first
            .article
            .as_ref()
            .unwrap()
            .metadata
            .keywords
            .iter()
            .map(|k| (k.source.start, k.source.end))
            .collect();
        // Repeating the body twice doubles every count; order and first-occurrence ranges stay.
        let paragraphs = page_paragraphs(&case.html);
        let doubled: Vec<String> = paragraphs.iter().chain(paragraphs.iter()).cloned().collect();
        let doubled_document = nlp_document(&case, &rebuild(&case.html, &doubled), policy.clone());
        let doubled_keywords = actual_keywords(&doubled_document);
        assert_eq!(
            doubled_keywords,
            baseline
                .iter()
                .map(|(t, c)| (t.clone(), c * 2))
                .collect::<Vec<_>>(),
            "{id}: doubled input"
        );
        let doubled_ranges: Vec<_> = doubled_document
            .article
            .as_ref()
            .unwrap()
            .metadata
            .keywords
            .iter()
            .map(|k| (k.source.start, k.source.end))
            .collect();
        assert_eq!(doubled_ranges, ranges, "{id}: first occurrences move");
        // Reordering the sentences keeps every keyword count (checked when the list is complete).
        if baseline.len() < 35 {
            let gold = nlp_gold(&case);
            let reversed = vec![gold.sentences.iter().rev().cloned().collect::<Vec<_>>().join(" ")];
            let reordered = actual_keywords(&nlp_document(&case, &rebuild(&case.html, &reversed), policy));
            let as_map = |list: &[(String, usize)]| list.iter().cloned().collect::<BTreeMap<_, _>>();
            assert_eq!(
                as_map(&reordered),
                as_map(&baseline),
                "{id}: counts depend on sentence order"
            );
            permuted += 1;
        }
    }
    assert!(permuted >= 25, "{permuted} reordering comparisons");
}

/// The input page with its article paragraphs replaced.
fn rebuild(html: &str, paragraphs: &[String]) -> String {
    let (open, close) = (
        html.find("<article>").unwrap() + "<article>".len(),
        html.find("</article>").unwrap(),
    );
    let body: String = paragraphs
        .iter()
        .map(|p| {
            format!(
                "<p>{}</p>\n",
                p.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
            )
        })
        .collect();
    format!("{}\n{}{}", &html[..open], body, &html[close..])
}

#[test]
fn off_sentence_model_and_limits_are_bounded() {
    for case in nlp_cases() {
        let id = &case.entry.id;
        let baseline = nlp_document(&case, &case.html, nlp_policy(&case));
        let mut off = nlp_policy(&case);
        off.nlp = NlpCapabilityV1::Off;
        let off = nlp_document(&case, &case.html, off);
        let metadata = &off.article.as_ref().unwrap().metadata;
        assert!(
            metadata.keywords.is_empty() && metadata.summary.is_empty(),
            "{id}: Off"
        );
        assert!(
            metadata.tokenizer_version.is_none() && !metadata.tokenizer_unavailable,
            "{id}: Off"
        );
        assert_eq!(off.text, baseline.text, "{id}: Off changes the main text");
        assert!(
            !off.article
                .as_ref()
                .unwrap()
                .quality
                .reasons
                .contains(&QualityReasonV1::ModelUnavailable),
            "{id}"
        );

        let mut model = nlp_policy(&case);
        model.nlp = NlpCapabilityV1::SentenceModel;
        let model = nlp_document(&case, &case.html, model);
        let envelope = model.article.as_ref().unwrap();
        assert!(
            envelope.metadata.keywords.is_empty() && envelope.metadata.summary.is_empty(),
            "{id}: SentenceModel"
        );
        assert!(
            envelope.metadata.tokenizer_version.is_none(),
            "{id}: SentenceModel"
        );
        assert_eq!(envelope.quality.status, QualityStatusV1::Unavailable, "{id}");
        assert!(
            envelope
                .quality
                .reasons
                .contains(&QualityReasonV1::ModelUnavailable),
            "{id}"
        );
        assert_eq!(
            model.text, baseline.text,
            "{id}: SentenceModel changes the main text"
        );

        let mut none = nlp_policy(&case);
        none.keywords = 0;
        none.summary_sentences = 0;
        let none = nlp_document(&case, &case.html, none);
        let metadata = &none.article.as_ref().unwrap().metadata;
        assert!(
            metadata.keywords.is_empty() && metadata.summary.is_empty(),
            "{id}: zero limits"
        );
    }
    // Limits above the documented maximum are typed policy errors, not silent clamps.
    let case = &nlp_cases()[0];
    for edit in [
        (|p: &mut ExtractionPolicyV1| p.keywords = 36) as fn(&mut ExtractionPolicyV1),
        |p| p.summary_sentences = 21,
        |p| p.summary_max_chars = 20_001,
    ] {
        let mut policy = nlp_policy(case);
        edit(&mut policy);
        assert!(Extractor::extract(
            &case.html,
            &Url::parse(&case.entry.page_url).unwrap(),
            &ExtractOptions {
                content: Some(policy),
                ..ExtractOptions::default()
            }
        )
        .is_err());
    }
}

#[test]
fn nlp_cases_cover_the_plan_scripts() {
    let cases = nlp_cases();
    let classes: BTreeSet<&str> = cases.iter().map(|c| param_str(c, "class")).collect();
    for class in ["cjk", "thai", "abbreviation", "quote", "ties", "other_scripts"] {
        assert!(classes.contains(class), "{class}");
    }
    let tokenizers: BTreeSet<&str> = cases.iter().map(|c| param_str(c, "tokenizer")).collect();
    assert_eq!(tokenizers, BTreeSet::from([RULES, DICT]));
}
