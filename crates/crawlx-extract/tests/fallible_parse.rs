//! The fallible tree sink: a reservation too small for the document's own need is refused with
//! the typed error by every charged parse entrypoint, no partial tree is returned and nothing
//! stays reserved; with room, the same calls succeed. One `#[test]` because the budget is
//! process-wide.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::scrape::AttributeSelector;
use crawlx_core::selectors::SelectorScopeV1;
use crawlx_extract::decode::{markup_text, MarkupOptions};
use crawlx_extract::endpoints::{discover_with, DiscoveryError, DiscoveryInput, DiscoveryOptions};
use crawlx_extract::forms;
use crawlx_extract::link_options::{LinkFilter, LinkOptions};
use crawlx_extract::parse::{parse_document, ParseError, ParseLimits};
use crawlx_extract::parse_budget::{charge, charge_bytes, global};
use crawlx_extract::xpath::SelectorError;
use crawlx_extract::{
    adaptive_selector, attributes, dom, ExtractError, ExtractOptions, Extractor, LinkExtractor,
};
use url::Url;

/// What one entrypoint did with a document.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Refused for parse memory, carrying the size of the request.
    Refused,
    Ok,
    Other(String),
}

fn from_extract<T>(result: Result<T, ExtractError>) -> Outcome {
    match result {
        Ok(_) => Outcome::Ok,
        Err(ExtractError::ParseMemory(_)) => Outcome::Refused,
        Err(other) => Outcome::Other(other.to_string()),
    }
}

type Entrypoint<'a> = (&'static str, &'a str, Box<dyn Fn() -> Outcome + 'a>);

#[test]
fn a_reservation_below_the_documents_need_is_refused_by_every_entrypoint() {
    let budget = global();
    let page = Url::parse("https://example.test/page").unwrap();
    let options = ExtractOptions::default();
    let selector = [AttributeSelector {
        selector: "a".to_owned(),
        attribute: "href".to_owned(),
    }];
    let filter = LinkFilter::new(&LinkOptions::default()).unwrap();
    let scope = SelectorScopeV1::new(
        "tenant".into(),
        "principal".into(),
        "https://example.test".into(),
        "news".into(),
        "article/v1".into(),
    );
    let discovery_url = page.clone();
    let intent = crawlx_core::extraction::PreviewIntentV1::with_budget(
        page.clone(),
        crawlx_core::extraction::PreviewPurposeV1::HeadMetadata,
        4096,
    )
    .unwrap();

    // Documents small enough that the bytes admitted for them (500 per input byte) are below
    // what building their tree needs: the cap is lower than the document's need.
    let entrypoints: Vec<Entrypoint<'_>> = vec![
        (
            "Extractor::extract",
            "<p>x</p>",
            Box::new(|| from_extract(Extractor::extract("<p>x</p>", &page, &options))),
        ),
        (
            "Extractor::extract_bytes",
            "<p>x</p>",
            Box::new(|| from_extract(Extractor::extract_bytes(b"<p>x</p>", &page, &options))),
        ),
        (
            "Extractor::extract_bytes_with_projection",
            "<p>x</p>",
            Box::new(|| {
                from_extract(Extractor::extract_bytes_with_projection(
                    b"<p>x</p>",
                    &page,
                    &options,
                    &|_| None,
                ))
            }),
        ),
        (
            "LinkExtractor::links",
            "<a href=x>t</a>",
            Box::new(|| from_extract(LinkExtractor::links("<a href=x>t</a>", &page))),
        ),
        (
            "LinkFilter::links",
            "<a href=x>t</a>",
            Box::new(|| match filter.links("<a href=x>t</a>", &page) {
                Ok(_) => Outcome::Ok,
                Err(crawlx_extract::link_options::LinkOptionsError::Extract(ExtractError::ParseMemory(
                    _,
                ))) => Outcome::Refused,
                Err(other) => Outcome::Other(other.to_string()),
            }),
        ),
        (
            "attributes::attributes",
            "<a href=x>t</a>",
            Box::new(|| from_extract(attributes::attributes("<a href=x>t</a>", &selector))),
        ),
        (
            "decode::markup_text",
            "<p>x</p>",
            Box::new(|| from_extract(markup_text("<p>x</p>", &MarkupOptions::default()))),
        ),
        (
            "forms::extract_str",
            "<form></form>",
            Box::new(|| from_extract(forms::extract_str("<form></form>", &page))),
        ),
        (
            "link_media::project_head",
            "<title>t</title>",
            Box::new(|| {
                from_extract(crawlx_extract::link_media::project_head(
                    &intent,
                    b"<title>t</title>",
                ))
            }),
        ),
        (
            "endpoints::discover_with",
            "<a href=x>",
            Box::new(|| {
                let input = DiscoveryInput {
                    url: &discovery_url,
                    status: 200,
                    headers: &[],
                    content_type: Some("text/html"),
                    body: b"<a href=x>",
                    depth: 0,
                };
                match discover_with(&input, &DiscoveryOptions::default()) {
                    Ok(_) => Outcome::Ok,
                    Err(DiscoveryError::ParseMemory(_)) => Outcome::Refused,
                    Err(other) => Outcome::Other(other.to_string()),
                }
            }),
        ),
        (
            "adaptive_selector::capture_html",
            "<p>x</p>",
            Box::new(
                || match adaptive_selector::capture_html("<p>x</p>", 0, "id".into(), scope.clone()) {
                    Err(SelectorError::Budget("parse memory")) => Outcome::Refused,
                    Ok(_) => Outcome::Ok,
                    Err(other) => Outcome::Other(other.to_string()),
                },
            ),
        ),
        (
            "parse::parse_document",
            "<p>x</p>",
            Box::new(|| {
                match parse_document(
                    b"<p>x</p>",
                    Some("page.html"),
                    Some("text/html"),
                    &ParseLimits::default(),
                ) {
                    Ok(_) => Outcome::Ok,
                    Err(ParseError::ParseMemory(_)) => Outcome::Refused,
                    Err(other) => Outcome::Other(other.to_string()),
                }
            }),
        ),
    ];

    for (name, document, call) in &entrypoints {
        let admitted = charge_bytes(document.len()).unwrap();
        // the admission charge fits exactly; the tree the document needs does not
        budget.set_limit(admitted);
        assert_eq!(budget.used(), 0, "{name}");
        assert_eq!(call(), Outcome::Refused, "{name} at a cap of {admitted} bytes");
        assert_eq!(
            budget.used(),
            0,
            "{name}: a refused parse leaves nothing reserved"
        );

        // with room the same call parses the same document
        budget.set_limit(admitted + (1 << 20));
        let outcome = call();
        assert!(
            outcome == Outcome::Ok || matches!(&outcome, Outcome::Other(_)),
            "{name} with room: {outcome:?}"
        );
        assert_ne!(outcome, Outcome::Refused, "{name} with room");
        assert_eq!(budget.used(), 0, "{name}: the charge is released with the tree");
    }

    // the sink itself, on a large document and a reservation that covers only part of it:
    // typed error, no tree, the budget exactly as it was
    let large = "<div><b>t</b><a href=\"/x\">link</a></div>".repeat(20_000);
    budget.set_limit(charge_bytes(1).unwrap() + 192 * 1024);
    let mut held = charge(1).unwrap();
    let before = budget.used();
    let refused = dom::parse_document(&mut held, &large).unwrap_err();
    assert!(
        refused.requested > 192 * 1024,
        "the parse got part way: {refused}"
    );
    assert_eq!(budget.used(), before);
    assert_eq!(held.tree_bytes(), 0);
    assert!(dom::parse_fragment(&mut held, &large).is_err());
    assert_eq!(budget.used(), before);
    budget.set_limit(usize::MAX);
    let tree = dom::parse_document(&mut held, &large).unwrap();
    assert!(
        held.tree_bytes() > large.len(),
        "the model covers at least the markup"
    );
    assert_eq!(
        tree.select(&scraper::Selector::parse("a").unwrap()).count(),
        20_000
    );
    drop(tree);
    drop(held);
    assert_eq!(budget.used(), 0);
}
