//! Pruning and BM25 fit filters against labeled fixture corpora.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::content_outputs::ContentOutputOptions;
use crawlx_extract::fit::{Bm25Params, FilterError, FitFilter, PruningParams};
use crawlx_extract::{Document, ExtractError, ExtractOptions, Extractor};
use scraper::{Html, Selector};
use url::Url;

const CORPUS: &str = include_str!("fixtures/content_filter_corpus.html");
const SHORT: &str = include_str!("fixtures/content_filter_short.html");
const BM25: &str = include_str!("fixtures/content_bm25_corpus.html");

fn page() -> Url {
    Url::parse("https://fixture.test/page").unwrap()
}

fn run(html: &str, fit: FitFilter) -> Result<Document, ExtractError> {
    let mut outputs = ContentOutputOptions::default();
    outputs.fit = Some(fit);
    Extractor::extract(
        html,
        &page(),
        &ExtractOptions {
            only_main_content: false,
            outputs: Some(outputs),
            ..ExtractOptions::default()
        },
    )
}

/// `(marker token, label)` of every labeled element of the fixture.
fn labels(html: &str, attr: &str) -> Vec<(String, String)> {
    let doc = Html::parse_document(html);
    let selector = Selector::parse(&format!("[{attr}]")).unwrap();
    doc.select(&selector)
        .map(|el| {
            let text: String = el.text().collect::<Vec<_>>().join(" ");
            let token = text
                .split_whitespace()
                .find(|w| w.starts_with("zq"))
                .unwrap_or_else(|| panic!("no marker in {text}"))
                .to_owned();
            (token, el.value().attr(attr).unwrap().to_owned())
        })
        .collect()
}

fn check_labels(html: &str, attr: &str, keep: &str, fit_markdown: &str) {
    let labeled = labels(html, attr);
    assert!(labeled.len() >= 4, "fixture must label several blocks");
    for (token, label) in &labeled {
        let present = fit_markdown.contains(token.as_str());
        assert_eq!(
            present,
            label == keep,
            "{token} labeled {label}: present={present}\n{fit_markdown}"
        );
    }
}

#[test]
fn pruning_matches_boilerplate_and_content_labels() {
    let doc = run(CORPUS, FitFilter::default()).unwrap();
    let outputs = doc.outputs.as_ref().unwrap();
    let fit = outputs.fit_markdown.as_deref().unwrap();
    check_labels(CORPUS, "data-label", "content", fit);
    let html = outputs.fit_html.as_deref().unwrap();
    check_labels(CORPUS, "data-label", "content", html);
    let report = outputs.fit.as_ref().unwrap();
    assert_eq!(report.strategy, "pruning_v1");
    assert!(
        (report.kept_blocks, report.dropped_blocks) == (9, 8),
        "{report:?}"
    );
    // The unfiltered page keeps the boilerplate, so fit is a strict subset.
    assert!(doc.markdown.contains("zq01") && doc.markdown.contains("zq18"));
    assert!(fit.len() < doc.markdown.len());
}

#[test]
fn pruning_keeps_short_content_pages() {
    let doc = run(SHORT, FitFilter::default()).unwrap();
    let fit = doc.outputs.unwrap().fit_markdown.unwrap();
    check_labels(SHORT, "data-label", "content", &fit);
}

#[test]
fn pruning_is_deterministic_and_reports_operations() {
    let a = run(CORPUS, FitFilter::default()).unwrap().outputs.unwrap();
    let b = run(CORPUS, FitFilter::default()).unwrap().outputs.unwrap();
    assert_eq!(a.fit_html, b.fit_html);
    assert_eq!(a.fit, b.fit);
    assert!(a.fit.unwrap().operations > 0);
}

#[test]
fn pruning_word_threshold_drops_short_blocks() {
    let strict = FitFilter::Pruning(PruningParams::default().with_min_words(12));
    let doc = run(CORPUS, strict).unwrap();
    let fit = doc.outputs.unwrap().fit_markdown.unwrap();
    // The six-word heading is gone; the 27-word paragraph stays.
    assert!(!fit.contains("zq03"), "{fit}");
    assert!(fit.contains("zq04"), "{fit}");
}

#[test]
fn pruning_threshold_controls_strictness() {
    let loose = FitFilter::Pruning(PruningParams::default().with_threshold_permille(0));
    let doc = run(CORPUS, loose).unwrap();
    let fit = doc.outputs.unwrap().fit_markdown.unwrap();
    // Threshold zero disables score-based dropping except the container veto.
    assert!(fit.contains("zq03") && fit.contains("zq15"));
}

#[test]
fn operation_budget_fails_closed() {
    let tight = FitFilter::Pruning(PruningParams::default().with_max_operations(5));
    let err = run(CORPUS, tight).unwrap_err();
    assert!(
        matches!(
            &err,
            ExtractError::Outputs(crawlx_extract::content_outputs::ContentOutputError::Filter(
                FilterError::Budget { limit: 5 }
            ))
        ),
        "{err:?}"
    );
}

#[test]
fn invalid_parameters_are_rejected_before_parsing() {
    let bad = FitFilter::Pruning(PruningParams::default().with_threshold_permille(1001));
    assert!(matches!(run(CORPUS, bad), Err(ExtractError::Outputs(_))));
    let empty = FitFilter::Bm25(Bm25Params::new("the and of"));
    assert!(matches!(run(CORPUS, empty), Err(ExtractError::Outputs(_))));
    let long = FitFilter::Bm25(Bm25Params::new("x".repeat(5000)));
    assert!(matches!(run(CORPUS, long), Err(ExtractError::Outputs(_))));
}

#[test]
fn bm25_keeps_blocks_relevant_to_the_query() {
    let doc = run(BM25, FitFilter::Bm25(Bm25Params::new("River sediment delta"))).unwrap();
    let outputs = doc.outputs.unwrap();
    let fit = outputs.fit_markdown.unwrap();
    check_labels(BM25, "data-relevance", "yes", &fit);
    let report = outputs.fit.unwrap();
    assert_eq!(report.strategy, "bm25_v1");
    assert_eq!(report.kept_blocks, 3);
    assert_eq!(report.dropped_blocks, 5);
}

#[test]
fn bm25_is_deterministic_and_query_order_insensitive() {
    let a = run(BM25, FitFilter::Bm25(Bm25Params::new("sediment river"))).unwrap();
    let b = run(BM25, FitFilter::Bm25(Bm25Params::new("River  SEDIMENT river"))).unwrap();
    assert_eq!(a.outputs.unwrap().fit_html, b.outputs.unwrap().fit_html);
}

#[test]
fn bm25_threshold_filters_weak_matches() {
    // No block can reach a score of twenty, so a high threshold keeps nothing.
    let doc = run(
        BM25,
        FitFilter::Bm25(Bm25Params::new("sediment").with_threshold_milli(20_000)),
    )
    .unwrap();
    assert_eq!(doc.outputs.unwrap().fit.unwrap().kept_blocks, 0);
}

#[test]
fn filter_spec_round_trips_with_versioned_strategy_ids() {
    let spec: FitFilter =
        serde_json::from_str(r#"{"strategy":"bm25","query":"tide table","thresholdMilli":300}"#).unwrap();
    assert_eq!(spec.strategy_id(), "bm25_v1");
    let pruning: FitFilter =
        serde_json::from_str(r#"{"strategy":"pruning","thresholdPermille":500}"#).unwrap();
    assert_eq!(pruning.strategy_id(), "pruning_v1");
    assert!(serde_json::from_str::<FitFilter>(r#"{"strategy":"pruning","unknown":1}"#).is_err());
}
