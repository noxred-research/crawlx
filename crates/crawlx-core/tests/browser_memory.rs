//! Charged browser payloads: DOM text and raw artifacts keep their byte reservation for as long
//! as any clone is alive, and memory refusal never looks like a dead browser target.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::hash::Digest;
use crawlx_core::ids::{SessionId, TabId};
use crawlx_core::observation::ObservationBundle;
use crawlx_core::page_op::PageOpResult;
use crawlx_core::parser_memory::{AdmittedBytes, AdmittedText, ByteAdmissionError, ByteBudget};
use crawlx_core::scrape::ActionScrape;
use crawlx_core::url::RouteTemplate;
use crawlx_core::{BrowserError, CanonicalUrl, Classify, ErrorClass};
use std::error::Error as _;
use std::sync::Arc;

fn text(budget: &Arc<ByteBudget>, value: &str) -> AdmittedText {
    AdmittedText::new(value.to_owned(), budget.try_reserve(value.len()).unwrap())
}

fn bytes(budget: &Arc<ByteBudget>, value: &[u8]) -> AdmittedBytes {
    AdmittedBytes::new(value.to_vec(), budget.try_reserve(value.len()).unwrap())
}

fn bundle() -> ObservationBundle {
    let url = url::Url::parse("https://example.test/page").unwrap();
    let canonical = CanonicalUrl {
        key: Digest::of("test/url", url.as_str().as_bytes()),
        origin: url.origin().ascii_serialization(),
        route_template: RouteTemplate(url.path().to_owned()),
        params: Vec::new(),
        url,
    };
    ObservationBundle::empty(SessionId::new(), TabId("tab".to_owned()), canonical)
}

#[test]
fn memory_error_keeps_its_typed_cause_and_is_never_a_target_crash() {
    let budget = Arc::new(ByteBudget::new(8));
    let held = budget.try_reserve(6).unwrap();
    let refused = budget.try_reserve(4).unwrap_err();
    assert!(!refused.exceeds_budget());
    let error = BrowserError::from(refused);
    assert!(!error.is_target_crash());
    assert_eq!(error.class(), ErrorClass::OutcomeUnknown);
    let source = error.source().expect("typed source");
    assert_eq!(source.downcast_ref::<ByteAdmissionError>(), Some(&refused));
    assert_eq!(error.to_string(), "browser byte admission failed");
    drop(held);
}

#[test]
fn memory_error_that_can_never_fit_is_terminal() {
    let budget = Arc::new(ByteBudget::new(8));
    let refused = budget.try_reserve(9).unwrap_err();
    assert!(refused.exceeds_budget());
    let error = BrowserError::Memory(refused);
    assert_eq!(error.class(), ErrorClass::Terminal);
    assert!(!error.is_target_crash());
}

#[test]
fn html_result_clones_share_one_reservation() {
    let budget = Arc::new(ByteBudget::new(64));
    let result = PageOpResult::Html {
        html: text(&budget, "<p>dom</p>"),
        url: "https://example.test/".to_owned(),
    };
    assert_eq!(budget.used(), 10);
    let copy = result.clone();
    assert_eq!(
        budget.used(),
        10,
        "clone shares ownership, it does not copy bytes"
    );
    assert_eq!(result, copy);
    drop(result);
    assert_eq!(budget.used(), 10, "a surviving clone retains the permit");
    let PageOpResult::Html { html, .. } = copy else {
        panic!("html result");
    };
    drop(html);
    assert_eq!(budget.used(), 0);
}

#[test]
fn bundle_clones_retain_html_and_raw_artifacts_until_the_last_drops() {
    let budget = Arc::new(ByteBudget::new(256));
    let mut original = bundle();
    original.html = Some(text(&budget, "<html></html>"));
    let original = original
        .with_raw_artifact("dom_snapshot", bytes(&budget, b"{\"nodes\":[]}"))
        .with_raw_artifact("screenshot", bytes(&budget, b"\x89PNG"));
    let held = 13 + 12 + 4;
    assert_eq!(budget.used(), held);
    assert_eq!(original.raw_artifact("screenshot"), Some(&b"\x89PNG"[..]));

    let clone = original.clone();
    assert_eq!(
        budget.used(),
        held,
        "cloning a bundle never copies charged payloads"
    );
    drop(original);
    assert_eq!(budget.used(), held, "a surviving bundle keeps every permit");
    assert_eq!(clone.html.as_deref(), Some("<html></html>"));
    drop(clone);
    assert_eq!(budget.used(), 0);
}

#[test]
fn replacing_a_raw_artifact_releases_only_the_replaced_blob() {
    let budget = Arc::new(ByteBudget::new(64));
    let bundle = bundle()
        .with_raw_artifact("screenshot", bytes(&budget, b"1234"))
        .with_raw_artifact("dom_snapshot", bytes(&budget, b"12345678"));
    assert_eq!(budget.used(), 12);
    let bundle = bundle.with_raw_artifact("screenshot", bytes(&budget, b"12"));
    assert_eq!(budget.used(), 10);
    assert_eq!(bundle.raw_artifacts.len(), 2);
    assert_eq!(bundle.raw_artifact("screenshot"), Some(&b"12"[..]));
}

#[test]
fn refused_admission_attaches_nothing_to_a_bundle() {
    let budget = Arc::new(ByteBudget::new(4));
    let held = budget.try_reserve(3).unwrap();
    assert!(budget.try_reserve(2).is_err());
    let bundle = bundle();
    assert!(bundle.html.is_none() && bundle.raw_artifacts.is_empty());
    assert_eq!(budget.used(), 3);
    drop(held);
    assert_eq!(budget.used(), 0);
}

#[test]
fn action_scrape_keeps_the_plain_string_wire_shape() {
    let budget = Arc::new(ByteBudget::new(64));
    let scrape = ActionScrape {
        url: "https://example.test/".to_owned(),
        html: text(&budget, "<p>step</p>"),
    };
    let wire = serde_json::to_value(&scrape).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"url": "https://example.test/", "html": "<p>step</p>"})
    );
    let back: ActionScrape = serde_json::from_value(wire).unwrap();
    assert_eq!(back, scrape);
    let cloned = scrape.clone();
    assert_eq!(
        budget.used(),
        11,
        "serialize and clone never charge the test budget twice"
    );
    drop(scrape);
    assert_eq!(budget.used(), 11);
    drop(cloned);
    assert_eq!(budget.used(), 0);
}

#[test]
fn bytes_result_clones_share_one_reservation() {
    let budget = Arc::new(ByteBudget::new(64));
    let result = PageOpResult::Bytes {
        bytes: bytes(&budget, b"\x89PNG-data"),
        content_type: "image/png",
    };
    assert_eq!(budget.used(), 9);
    let copy = result.clone();
    assert_eq!(budget.used(), 9, "clone shares ownership, it does not copy bytes");
    drop(result);
    assert_eq!(budget.used(), 9, "a surviving clone retains the permit");
    drop(copy);
    assert_eq!(budget.used(), 0);
}
