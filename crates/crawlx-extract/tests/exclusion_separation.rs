//! Author exclusion blocks ingestion after acquisition; URL exclusion blocks the request itself.
//! The two have separate typed reasons and separate accounting.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::acquisition::{ValidationCategoryV1, ValidationContextV1};
use crawlx_core::extraction::{ExtractionPolicyV1, QualityReasonV1, QualityStatusV1, UrlExclusionPolicyV1};
use crawlx_extract::{ExtractOptions, Extractor};
use crawlx_url::{PreFetchDecision, PreFetchGate, ScopeFilter, UrlExclusionFilter};
use url::Url;

const SOURCE: &str = r#"<html><head><meta name="author" content="Alex Example"></head><body><article>
<p>Original reporting explains the verified findings and preserves source evidence for independent audit.</p>
</article></body></html>"#;

#[test]
fn excluded_author_rejects_ingestion_but_keeps_acquisition_and_content_accounting() {
    let mut policy = ExtractionPolicyV1::default();
    policy.excluded_authors = vec!["alex example".into()];
    let mut context = ValidationContextV1::default();
    context.target_status = Some(200);
    context.transport_succeeded = true;
    let doc = Extractor::extract(
        SOURCE,
        &Url::parse("https://fixture.test/story").unwrap(),
        &ExtractOptions {
            content: Some(policy),
            acquisition_validation: Some(context),
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    // the acquisition is valid and observed; only ingestion eligibility changes
    let validation = doc.validation.as_ref().unwrap();
    assert_eq!(validation.category, ValidationCategoryV1::Valid);
    assert!(validation.content_accepted);
    let article = doc.article.as_ref().unwrap();
    assert_eq!(article.quality.status, QualityStatusV1::Rejected);
    assert_eq!(article.quality.reasons, vec![QualityReasonV1::AuthorExcluded]);
    assert!(article.quality.main_chars > 0 && article.quality.blocks > 0);
    assert!(doc.text.contains("verified findings"));
    assert_eq!(
        article.metadata.authors.value,
        Some(vec!["Alex Example".to_owned()])
    );
}

#[test]
fn url_exclusion_and_author_exclusion_use_distinct_reasons() {
    let mut urls = UrlExclusionPolicyV1::default();
    urls.substrings = vec!["/authors/alex-example".into()];
    let mut policy = ExtractionPolicyV1::default();
    policy.excluded_urls = Some(urls.clone());
    policy.validate().unwrap();

    let gate = PreFetchGate::new(
        ScopeFilter::new(&Url::parse("https://fixture.test/").unwrap(), &Default::default()).unwrap(),
        UrlExclusionFilter::from_policy(&urls).unwrap(),
    );
    let excluded = gate.decide(&Url::parse("https://fixture.test/authors/alex-example").unwrap());
    let PreFetchDecision::UrlExcluded(reason) = excluded else {
        panic!("expected a URL exclusion");
    };
    assert_eq!(reason.code(), "url_excluded");
    let author = serde_json::to_value(QualityReasonV1::AuthorExcluded).unwrap();
    assert_ne!(author, reason.code());
    assert_eq!(author, "author_excluded");

    // an over-bounded URL policy is refused by the content policy itself
    policy.excluded_urls.as_mut().unwrap().substrings = vec!["x".into(); 257];
    assert!(policy.validate().is_err());
}
