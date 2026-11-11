//! Block dedupe, distinct digests and content dedupe over the native article path.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use crawlx_core::extraction::{
    DedupeCache, DedupePolicyV1, DedupeScopeV1, ExtractionPolicyV1, QualityReasonV1, QualityStatusV1,
    DEDUPE_NORMALIZATION_V1,
};
use crawlx_extract::{DedupeHandle, Document, ExtractOptions, Extractor};
use url::Url;

const BOILERPLATE: &str = "Join the weekly newsletter for market updates delivered every morning.";
const LEGAL_QUOTE: &str =
    "The authority shall not be liable for any delay caused by circumstances beyond its control.";

fn policy(blocks: bool, content: bool) -> ExtractionPolicyV1 {
    let mut policy = ExtractionPolicyV1::default();
    let mut dedupe = DedupePolicyV1::default();
    dedupe.blocks = blocks;
    dedupe.content = content;
    policy.dedupe = Some(dedupe);
    policy
}

fn handle(namespace: &str, role: &str, cache: &Arc<Mutex<DedupeCache>>) -> DedupeHandle {
    DedupeHandle::new(
        DedupeScopeV1::new("tenant-a", namespace, role).unwrap(),
        Arc::clone(cache),
    )
}

fn cache(capacity: usize) -> Arc<Mutex<DedupeCache>> {
    Arc::new(Mutex::new(DedupeCache::new(capacity).unwrap()))
}

fn run(
    html: &str,
    url: &str,
    policy: ExtractionPolicyV1,
    whole: bool,
    handle: Option<DedupeHandle>,
) -> Document {
    Extractor::extract(
        html,
        &Url::parse(url).unwrap(),
        &ExtractOptions {
            content: Some(policy),
            only_main_content: !whole,
            dedupe_cache: handle,
            ..ExtractOptions::default()
        },
    )
    .unwrap()
}

fn story(chrome: &str, paragraphs: &[&str]) -> String {
    let body: String = paragraphs.iter().map(|p| format!("<p>{p}</p>")).collect();
    format!(
        "<html><head><title>Ferry timetable changes</title></head><body>{chrome}<article><h1>Ferry timetable changes</h1>{body}</article></body></html>"
    )
}

const FIRST: &str = "The harbour authority announced new crossing times for the winter season on Monday.";
const SECOND: &str =
    "Passengers on the northern route will see the earliest departure moved by twenty minutes.";
const THIRD: &str =
    "Ticket prices stay unchanged and the harbour authority will publish the full timetable online.";

#[test]
fn repeated_boilerplate_paragraph_is_removed_only_when_enabled() {
    let html = story("", &[FIRST, BOILERPLATE, SECOND, BOILERPLATE]);
    let off = run(
        &html,
        "https://example.test/a",
        ExtractionPolicyV1::default(),
        false,
        None,
    );
    assert_eq!(off.text.matches(BOILERPLATE).count(), 2);

    let digests_only = run(&html, "https://example.test/a", policy(false, false), false, None);
    assert_eq!(digests_only.text.matches(BOILERPLATE).count(), 2);

    let on = run(&html, "https://example.test/a", policy(true, false), false, None);
    assert_eq!(on.text.matches(BOILERPLATE).count(), 1);
    assert!(on.text.contains(FIRST) && on.text.contains(SECOND));
    // first occurrence wins: stable admission order
    assert!(on.text.find(FIRST).unwrap() < on.text.find(BOILERPLATE).unwrap());
    assert!(on.text.find(BOILERPLATE).unwrap() < on.text.find(SECOND).unwrap());
    let report = on.article.as_ref().unwrap().dedupe.as_ref().unwrap();
    assert_eq!(report.blocks_removed, 1);
    assert!(!report.cache_scoped);
    // retained blocks still map to real ranges of the final text
    let article = on.article.as_ref().unwrap();
    for block in &article.blocks {
        let range = block.source.unwrap();
        assert!(on.text.is_char_boundary(range.start) && range.end <= on.text.len());
    }
}

#[test]
fn whole_page_selection_prunes_nested_repeats_and_keeps_distinct_blocks() {
    let html = format!(
        "<html><body><section><p>{BOILERPLATE}</p></section><article><p>{FIRST}</p><p>{BOILERPLATE}</p><p>{SECOND}</p></article></body></html>"
    );
    let on = run(&html, "https://example.test/a", policy(true, false), true, None);
    assert_eq!(on.text.matches(BOILERPLATE).count(), 1);
    assert!(on.text.contains(FIRST) && on.text.contains(SECOND));
    let off = run(&html, "https://example.test/a", policy(false, false), true, None);
    assert_eq!(off.text.matches(BOILERPLATE).count(), 2);
}

#[test]
fn repeated_legal_quote_is_retained_when_block_dedupe_is_off() {
    let html = format!(
        "<html><body><article><h1>Notice</h1><p>{FIRST}</p><blockquote>{LEGAL_QUOTE}</blockquote><p>{SECOND}</p><blockquote>{LEGAL_QUOTE}</blockquote></article></body></html>"
    );
    let retained = run(&html, "https://example.test/a", policy(false, false), false, None);
    assert_eq!(retained.text.matches(LEGAL_QUOTE).count(), 2);
    let removed = run(&html, "https://example.test/a", policy(true, false), false, None);
    assert_eq!(removed.text.matches(LEGAL_QUOTE).count(), 1);
}

#[test]
fn short_blocks_are_never_deduplicated() {
    let html = story("", &[FIRST, "Read more", SECOND, "Read more", THIRD]);
    let on = run(&html, "https://example.test/a", policy(true, false), true, None);
    assert_eq!(on.text.matches("Read more").count(), 2);
    assert_eq!(on.text.matches(FIRST).count(), 1);
}

#[test]
fn cache_scope_separates_namespace_role_tenant_and_replays_identically() {
    let html = story("", &[FIRST, BOILERPLATE, SECOND]);
    let sequence = || {
        let shared = cache(64);
        let texts: Vec<usize> = [
            ("run-1", "anonymous"),
            ("run-1", "anonymous"),
            ("run-2", "anonymous"),
            ("run-1", "member"),
        ]
        .iter()
        .map(|(namespace, role)| {
            let doc = run(
                &html,
                "https://example.test/a",
                policy(true, false),
                false,
                Some(handle(namespace, role, &shared)),
            );
            doc.text.matches(BOILERPLATE).count() + doc.text.matches(FIRST).count() * 10
        })
        .collect();
        texts
    };
    let first = sequence();
    // run-1/anonymous second extraction sees every block already admitted; other scopes do not
    assert_eq!(first, [11, 0, 11, 11]);
    assert_eq!(first, sequence());
}

#[test]
fn cache_is_bounded_and_stores_hashes_not_text() {
    let shared = cache(2);
    for n in 0..8 {
        let paragraph =
            format!("Distinct paragraph number {n} carries enough words to be compared reliably.");
        let html = story("", &[&paragraph]);
        let _ = run(
            &html,
            "https://example.test/a",
            policy(true, false),
            false,
            Some(handle("run-1", "anonymous", &shared)),
        );
        assert!(shared.lock().unwrap().len() <= 2);
    }
    let rendered = format!("{:?}", shared.lock().unwrap());
    assert!(!rendered.contains("Distinct paragraph"));
}

#[test]
fn same_main_text_under_different_chrome_has_same_main_digest_and_different_raw_digest() {
    let plain = story("", &[FIRST, SECOND]);
    let chrome = story(
        "<header><a href=\"/\">Home</a></header><nav><a href=\"/x\">Sections</a></nav><div>Advertisement slot sponsored banner</div>",
        &[FIRST, SECOND],
    );
    let a = run(
        &plain,
        "https://example.test/a",
        policy(false, false),
        false,
        None,
    );
    let b = run(
        &chrome,
        "https://example.test/a",
        policy(false, false),
        false,
        None,
    );
    let a = a
        .article
        .as_ref()
        .unwrap()
        .dedupe
        .as_ref()
        .unwrap()
        .digests
        .clone();
    let b = b
        .article
        .as_ref()
        .unwrap()
        .dedupe
        .as_ref()
        .unwrap()
        .digests
        .clone();
    assert_eq!(a.main, b.main);
    assert_eq!(a.main_simhash, b.main_simhash);
    assert_ne!(a.raw, b.raw);
    assert_ne!(a.page, a.main);
    assert_eq!(a.normalization, DEDUPE_NORMALIZATION_V1);
    assert_eq!(a.version, 1);
    assert!(a.domain.starts_with("crawlx.extract.dedupe."));
    assert_eq!(a.main_simhash.len(), 16);
    assert!(a.comment.is_none());
    // punctuation, case and whitespace differences normalize away in the main digest
    let shouting = story("", &[&FIRST.to_uppercase(), &format!("  {SECOND}\n")]);
    let c = run(
        &shouting,
        "https://example.test/a",
        policy(false, false),
        false,
        None,
    );
    assert_eq!(a.main, c.article.unwrap().dedupe.unwrap().digests.main);
}

#[test]
fn same_content_at_two_origins_dedupes_ingestion_but_keeps_both_acquisitions() {
    let shared = cache(64);
    let html = story("", &[FIRST, SECOND]);
    let first = run(
        &html,
        "http://example.test/news/a",
        policy(false, true),
        false,
        Some(handle("run-1", "anonymous", &shared)),
    );
    let second = run(
        &html,
        "https://www.example.test/story/b",
        policy(false, true),
        false,
        Some(handle("run-1", "anonymous", &shared)),
    );
    let (a, b) = (first.article.as_ref().unwrap(), second.article.as_ref().unwrap());
    assert_eq!(a.quality.status, QualityStatusV1::Accepted);
    assert_eq!(b.quality.status, QualityStatusV1::Rejected);
    assert_eq!(b.quality.reasons, vec![QualityReasonV1::DuplicateMain]);
    // both acquisitions keep their own base URL and full extraction
    assert_eq!(first.text, second.text);
    assert_eq!(first.base_url.as_str(), "http://example.test/news/a");
    assert_eq!(second.base_url.as_str(), "https://www.example.test/story/b");
    let (ra, rb) = (a.dedupe.as_ref().unwrap(), b.dedupe.as_ref().unwrap());
    assert!(!ra.content_duplicate && rb.content_duplicate);
    assert_eq!(ra.content_sha256, rb.content_sha256);
    assert_eq!(ra.content_sha256.as_ref().unwrap().len(), 64);
    // origins are exact: http/https and www never merge
    assert_eq!(ra.origin, "http://example.test");
    assert_eq!(rb.origin, "https://www.example.test");
    assert_eq!(rb.duplicate_same_origin, Some(false));

    // the comparison is against the first sighting's origin: a repeat from it is same-origin
    let third = run(
        &html,
        "http://example.test/news/c",
        policy(false, true),
        false,
        Some(handle("run-1", "anonymous", &shared)),
    );
    let c = third.article.unwrap();
    assert_eq!(c.dedupe.as_ref().unwrap().duplicate_same_origin, Some(true));
    assert_eq!(c.quality.reasons, vec![QualityReasonV1::DuplicateMain]);
}

#[test]
fn content_dedupe_needs_a_scope_and_a_clean_first_acceptance() {
    let html = story("", &[FIRST, SECOND]);
    // no handle: nothing to compare against
    for _ in 0..2 {
        let doc = run(&html, "https://example.test/a", policy(false, true), false, None);
        let article = doc.article.unwrap();
        assert_eq!(article.quality.status, QualityStatusV1::Accepted);
        assert!(!article.dedupe.unwrap().content_duplicate);
    }
    // a different title is different content
    let shared = cache(64);
    let other = html.replace("Ferry timetable changes", "Harbour notice");
    for page in [&html, &other] {
        let doc = run(
            page,
            "https://example.test/a",
            policy(false, true),
            false,
            Some(handle("run-1", "anonymous", &shared)),
        );
        assert_eq!(doc.article.unwrap().quality.status, QualityStatusV1::Accepted);
    }
    // a document rejected for another reason is not admitted, so it cannot shadow a later one
    let mut strict = policy(false, true);
    strict.min_main_chars = 10_000;
    let shared = cache(64);
    for _ in 0..2 {
        let doc = run(
            &html,
            "https://example.test/a",
            strict.clone(),
            false,
            Some(handle("run-2", "anonymous", &shared)),
        );
        let article = doc.article.unwrap();
        assert_eq!(article.quality.reasons, vec![QualityReasonV1::TooShort]);
        assert!(article.dedupe.unwrap().content_sha256.is_some());
    }
}

#[test]
fn omitting_dedupe_keeps_policy_identity_and_envelope_unchanged() {
    let value = serde_json::to_value(ExtractionPolicyV1::default()).unwrap();
    assert!(value.get("dedupe").is_none() && value.get("excludedUrls").is_none());
    let html = story("", &[FIRST, SECOND]);
    let doc = run(
        &html,
        "https://example.test/a",
        ExtractionPolicyV1::default(),
        false,
        None,
    );
    assert!(doc.article.unwrap().dedupe.is_none());
    let enabled = serde_json::to_value(policy(true, true)).unwrap();
    assert_eq!(enabled["dedupe"]["blocks"], true);
}
