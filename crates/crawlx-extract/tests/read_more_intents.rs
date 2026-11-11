//! Read-more selection produces unresolved discovery intents from static XPath/CSS; the extractor
//! never issues a request. Authored fixtures only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::{
    extraction::{DiscoveryPurposeV1, ExtractionPolicyV1},
    selectors::{ReadMoreBaseV1, SelectorPolicyV1},
};
use crawlx_extract::{item_loader::read_more_intents, xpath::SelectorDocument, ExtractOptions, Extractor};
use scraper::Html;
use serde_json::json;
use url::Url;

const PAGE: &str = "<html><head><base href='https://cdn.fixture.test/assets/'></head><body><article>\
    <p>A teaser paragraph that is long enough to be selected as the main article content block here.</p>\
    <a class='more' href='rest'>Read more</a>\
    <a class='continue' href='/page/2'>Continue</a>\
    <a class='continue' href='javascript:void(0)'>Script</a>\
    <a class='continue' href='/page/2'>Duplicate</a>\
    </article></body></html>";

fn page_url() -> Url {
    Url::parse("https://fixture.test/articles/one").unwrap()
}

fn policy(extra: serde_json::Value) -> ExtractionPolicyV1 {
    let mut selectors = json!({"readMore":[
        {"kind":"xpath","expression":"//a[@class='more'] | //a[@class='continue']"}]});
    selectors
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    serde_json::from_value(json!({"selectors":selectors})).unwrap()
}

fn read_more_urls(policy: ExtractionPolicyV1) -> Vec<String> {
    let doc = Extractor::extract(
        PAGE,
        &page_url(),
        &ExtractOptions {
            content: Some(policy),
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    doc.article
        .unwrap()
        .discovery
        .into_iter()
        .filter(|intent| intent.purpose == DiscoveryPurposeV1::ReadMoreReference)
        .map(|intent| intent.url.to_string())
        .collect()
}

#[test]
fn union_xpath_yields_document_ordered_deduplicated_read_more_intents() {
    assert_eq!(
        read_more_urls(policy(json!({}))),
        [
            "https://cdn.fixture.test/assets/rest",
            "https://cdn.fixture.test/page/2"
        ]
    );
}

#[test]
fn page_base_ignores_the_base_element_and_resolves_against_the_acquired_url() {
    assert_eq!(
        read_more_urls(policy(json!({"readMoreBase":"page"}))),
        [
            "https://fixture.test/articles/rest",
            "https://fixture.test/page/2"
        ]
    );
}

#[test]
fn intents_are_pure_references_and_offline_extraction_is_identical() {
    let selectors: SelectorPolicyV1 = serde_json::from_value(json!({
        "readMore":[{"kind":"css","expression":"a.more"}],
        "readMoreBase":"page"
    }))
    .unwrap();
    assert_eq!(selectors.read_more_base, Some(ReadMoreBaseV1::Page));
    let html = Html::parse_document(PAGE);
    let document_base = Url::parse("https://cdn.fixture.test/assets/").unwrap();
    let run = || {
        let mut doc = SelectorDocument::new(&html).unwrap();
        read_more_intents(&mut doc, &selectors, &document_base, &page_url()).unwrap()
    };
    let intents = run();
    assert_eq!(intents.len(), 1);
    assert_eq!(intents[0].purpose, DiscoveryPurposeV1::ReadMoreReference);
    assert_eq!(intents[0].url.as_str(), "https://fixture.test/articles/rest");
    // No state, clock or network input: a second run is identical.
    assert_eq!(intents, run());
}

#[test]
fn read_more_base_is_digest_stable_when_omitted() {
    let default_json = serde_json::to_string(&SelectorPolicyV1::default()).unwrap();
    assert!(!default_json.contains("readMoreBase"), "{default_json}");
    let policy_json = serde_json::to_string(&ExtractionPolicyV1::default()).unwrap();
    assert!(!policy_json.contains("readMoreBase"));
    let with_page: SelectorPolicyV1 = serde_json::from_value(json!({"readMoreBase":"page"})).unwrap();
    assert!(serde_json::to_string(&with_page)
        .unwrap()
        .contains("\"readMoreBase\":\"page\""));
    assert!(serde_json::from_value::<SelectorPolicyV1>(json!({"readMoreBase":"elsewhere"})).is_err());
}
