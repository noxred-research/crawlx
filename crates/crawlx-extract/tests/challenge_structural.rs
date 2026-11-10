//! Challenge detection is structural: words alone never exclude a page, and an excluded page
//! carries the structural evidence that excluded it. No backend is selected or switched here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::acquisition::{
    RetryClassV1, ValidationCategoryV1 as Category, ValidationContextV1, ValidationOutcomeV1,
};
use crawlx_core::extraction::{ExtractionPolicyV1, QualityStatusV1};
use crawlx_extract::validation::{validate_acquisition, ValidationInput};
use crawlx_extract::{ExtractOptions, Extractor};
use scraper::Html;
use url::Url;

const MENTIONING_ARTICLE: &str = r#"<html><head><title>How interstitial challenges work</title></head><body>
<article><h1>Why a CDN shows a captcha</h1>
<p>Sites behind a CDN sometimes answer with a page titled "Just a moment..." that says "Checking your
browser before accessing the site" and asks you to verify you are human. The markup of such a page
uses an element called <code>challenge-form</code> and a path under <code>/cdn-cgi/challenge-platform/</code>.
This explainer only describes those pages; it is ordinary reporting with a captcha screenshot caption.</p>
<p>Operators tune the rules so that readers rarely see the interstitial, and researchers measure how
often automated clients are slowed down by it across thousands of public sites every month.</p></article></body></html>"#;

/// Words a challenge page uses, with none of its structure.
const KEYWORD_ONLY: &str = r#"<html><head><title>Just a moment...</title></head><body>
<p>Checking your browser before accessing the site. Please verify you are human.</p></body></html>"#;

/// A genuine interstitial: a form posting to the challenge platform and no article content.
const GENUINE_CHALLENGE: &str = r#"<html><head><title>Just a moment...</title></head><body>
<div id="challenge-stage"><form id="challenge-form" action="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page">
<noscript>Enable JavaScript and cookies to continue</noscript></form></div></body></html>"#;

/// Real content that happens to embed the same widget markup.
fn article_with_widget() -> String {
    let paragraphs = "<p>Careful reporting about local transport funding, with named sources, figures and context for readers who follow the budget debate.</p>".repeat(12);
    format!(
        r#"<html><body><article><h1>Budget debate</h1>{paragraphs}
<form id="challenge-form" action="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page"></form></article></body></html>"#
    )
}

fn validate(status: u16, html: &str, headers: &[(String, String)]) -> ValidationOutcomeV1 {
    let doc = Html::parse_document(html);
    let mut context = ValidationContextV1::default();
    context.target_status = Some(status);
    context.transport_succeeded = true;
    validate_acquisition(&ValidationInput {
        context: &context,
        content_type: Some("text/html; charset=utf-8"),
        headers,
        body: html.as_bytes(),
        document: Some(&doc),
    })
}

fn has(outcome: &ValidationOutcomeV1, signal: &str) -> bool {
    outcome.signals.iter().any(|s| s == signal)
}

#[test]
fn article_mentioning_challenge_words_and_element_names_passes() {
    let outcome = validate(200, MENTIONING_ARTICLE, &[]);
    assert_eq!(outcome.category, Category::Valid);
    assert!(outcome.content_accepted);
    assert!(!has(&outcome, "challenge_structure_present"));
    assert!(!has(&outcome, "challenge_missing_expected_content"));
}

#[test]
fn keyword_only_page_is_never_denied_as_a_challenge() {
    let outcome = validate(200, KEYWORD_ONLY, &[]);
    assert_eq!(outcome.category, Category::Valid);
    assert!(outcome.signals.iter().all(|s| !s.starts_with("challenge")));
}

#[test]
fn genuine_200_challenge_is_excluded_with_structural_evidence() {
    let outcome = validate(200, GENUINE_CHALLENGE, &[]);
    assert_eq!(outcome.category, Category::Challenge);
    assert!(!outcome.content_accepted);
    // evidence: the structure that was found and why it was not offset by real content
    assert!(has(&outcome, "challenge_structure_present"));
    assert!(has(&outcome, "challenge_missing_expected_content"));
    // no header evidence was involved; the decision is structural alone
    assert!(!has(&outcome, "authoritative_challenge_header"));
    // the disposition is a retry class only: nothing here switches a fetch backend or session
    assert_eq!(outcome.retry_disposition, Some(RetryClassV1::Challenge));
}

#[test]
fn challenge_structure_inside_real_content_does_not_exclude() {
    let outcome = validate(200, &article_with_widget(), &[]);
    assert_eq!(outcome.category, Category::Valid);
    assert!(has(&outcome, "challenge_structure_present"));
    assert!(!has(&outcome, "challenge_missing_expected_content"));
}

#[test]
fn authoritative_header_alone_is_a_distinct_evidence_kind() {
    let headers = [("cf-mitigated".to_owned(), "challenge".to_owned())];
    let outcome = validate(200, MENTIONING_ARTICLE, &headers);
    assert_eq!(outcome.category, Category::Challenge);
    assert!(has(&outcome, "authoritative_challenge_header"));
    assert!(!has(&outcome, "challenge_structure_present"));
}

#[test]
fn extractor_reports_validation_beside_unchanged_article_quality() {
    let run = |html: &str| {
        let mut context = ValidationContextV1::default();
        context.target_status = Some(200);
        context.transport_succeeded = true;
        Extractor::extract(
            html,
            &Url::parse("https://fixture.test/story").unwrap(),
            &ExtractOptions {
                content: Some(ExtractionPolicyV1::default()),
                acquisition_validation: Some(context),
                ..ExtractOptions::default()
            },
        )
        .unwrap()
    };
    let article = run(MENTIONING_ARTICLE);
    assert_eq!(article.validation.as_ref().unwrap().category, Category::Valid);
    assert_eq!(article.article.unwrap().quality.status, QualityStatusV1::Accepted);

    let challenge = run(GENUINE_CHALLENGE);
    let validation = challenge.validation.as_ref().unwrap();
    assert_eq!(validation.category, Category::Challenge);
    assert!(!validation.content_accepted);
    assert!(validation
        .signals
        .iter()
        .any(|s| s == "challenge_structure_present"));
}
