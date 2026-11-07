//! Every charged parse site refuses with a typed error when the process-wide parse-memory
//! budget is exhausted, never blocks, reserves nothing on refusal, and releases its charge when
//! the parsed DOM is gone. One `#[test]` because the budget is process-wide.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::scrape::AttributeSelector;
use crawlx_extract::endpoints::{discover_with, DiscoveryError, DiscoveryInput, DiscoveryOptions};
use crawlx_extract::parse::{parse_document, ParseError, ParseLimits};
use crawlx_extract::parse_budget::{charge, charge_bytes, global};
use crawlx_extract::xpath::SelectorError;
use crawlx_extract::{adaptive_selector, attributes, ExtractError, ExtractOptions, Extractor, LinkExtractor};
use url::Url;

const HTML: &str = "<html><head><title>t</title></head><body><article><p>A paragraph of article text \
    that is long enough to be selected as the main content of this small page.</p>\
    <a href=\"/next\">next</a></article></body></html>";

#[test]
fn exhausted_budget_refuses_every_charged_parse_site_and_recovers() {
    let budget = global();
    let base = Url::parse("https://example.test/page").unwrap();
    let need = charge_bytes(HTML.len()).unwrap();
    // room for exactly one parse of HTML, plus a little
    budget.set_limit(need + 10);
    assert_eq!(budget.used(), 0);

    let options = ExtractOptions::default();
    Extractor::extract(HTML, &base, &options).unwrap();
    assert_eq!(budget.used(), 0, "the charge is released with the DOM");

    // another parse holds the budget: every site refuses at once, typed, reserving nothing
    let held = charge(HTML.len()).unwrap();
    assert_eq!(budget.used(), need);

    let refused = |error: &ExtractError| match error {
        ExtractError::ParseMemory(e) => e.requested == need && e.available == 10 && e.limit == need + 10,
        _ => false,
    };
    assert!(refused(&Extractor::extract(HTML, &base, &options).unwrap_err()));
    assert!(refused(
        &Extractor::extract_bytes(HTML.as_bytes(), &base, &options).unwrap_err()
    ));
    assert!(refused(
        &Extractor::extract_bytes_with_projection(HTML.as_bytes(), &base, &options, &|_| None).unwrap_err()
    ));
    assert!(refused(&LinkExtractor::links(HTML, &base).unwrap_err()));
    let pair = AttributeSelector {
        selector: "a".to_owned(),
        attribute: "href".to_owned(),
    };
    assert!(refused(&attributes::attributes(HTML, &[pair]).unwrap_err()));

    let input = DiscoveryInput {
        url: &base,
        status: 200,
        headers: &[],
        content_type: Some("text/html"),
        body: HTML.as_bytes(),
        depth: 0,
    };
    assert!(matches!(
        discover_with(&input, &DiscoveryOptions::default()),
        Err(DiscoveryError::ParseMemory(e)) if e.requested == need
    ));

    let scope = crawlx_core::selectors::SelectorScopeV1::new(
        "tenant".into(),
        "principal".into(),
        "https://example.test".into(),
        "news".into(),
        "article/v1".into(),
    );
    assert!(matches!(
        adaptive_selector::capture_html(HTML, 0, "id".into(), scope),
        Err(SelectorError::Budget("parse memory"))
    ));

    assert!(matches!(
        parse_document(HTML.as_bytes(), Some("page.html"), Some("text/html"), &ParseLimits::default()),
        Err(ParseError::ParseMemory(e)) if e.requested == need
    ));
    assert_eq!(budget.used(), need, "refusals reserve nothing");

    // the parse that held the budget finishes: the same calls succeed again
    drop(held);
    assert_eq!(budget.used(), 0);
    Extractor::extract_bytes(HTML.as_bytes(), &base, &options).unwrap();
    LinkExtractor::links(HTML, &base).unwrap();
    assert_eq!(budget.used(), 0);

    // the charge is held while the DOM is alive: the projection hook runs after the parse
    let policy = serde_json::from_value(serde_json::json!({})).unwrap();
    let content = ExtractOptions {
        content: Some(policy),
        ..ExtractOptions::default()
    };
    let seen = std::cell::Cell::new(0usize);
    let document = Extractor::extract_bytes_with_projection(HTML.as_bytes(), &base, &content, &|_| {
        seen.set(seen.get().max(budget.used()));
        None
    });
    assert!(document.is_ok(), "{document:?}");
    assert_eq!(
        seen.get(),
        need,
        "the charge was held while the parsed DOM was alive"
    );
    assert_eq!(budget.used(), 0);

    // lossy decoding is covered: replacement characters expand the input and the charge follows
    let mut invalid = HTML.as_bytes().to_vec();
    invalid.extend_from_slice(&[0xFF; 64]);
    let wanted = charge_bytes(invalid.len() + 64 * 2).unwrap();
    budget.set_limit(wanted);
    Extractor::extract_bytes(&invalid, &base, &options).unwrap();
    budget.set_limit(wanted - 1);
    assert!(matches!(
        Extractor::extract_bytes(&invalid, &base, &options),
        Err(ExtractError::ParseMemory(_))
    ));
    assert_eq!(budget.used(), 0);
}
