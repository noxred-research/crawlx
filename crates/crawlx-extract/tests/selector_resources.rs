//! Authored resource-reservation and finalized-item privacy regressions; no network fixtures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::{
    hash::Digest,
    selectors::{bounded_json_len, FieldQualityV1, ItemLoaderV1},
};
use crawlx_extract::{
    item_loader::{project_outcome, CompiledItemLoader},
    xpath::{CompiledSelector, SelectorDocument, SelectorError, XPathValue},
};
use scraper::Html;
use serde::{ser::SerializeSeq, Serialize, Serializer};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicUsize, Ordering},
};
use url::Url;
fn recipe(value: Value) -> ItemLoaderV1 {
    serde_json::from_value(value).unwrap()
}
fn base() -> Url {
    Url::parse("https://fixture.test/").unwrap()
}
fn load(spec: &ItemLoaderV1, source: &str) -> crawlx_core::selectors::ItemOutcomeV1 {
    let html = Html::parse_document(source);
    let mut doc = SelectorDocument::new(&html).unwrap();
    CompiledItemLoader::compile(spec)
        .unwrap()
        .load(&mut doc, &base())
        .unwrap()
}
fn with_schema(mut spec: ItemLoaderV1, schema: Value) -> ItemLoaderV1 {
    let key = Digest::of("crawlx.item.schema.v1", &serde_json::to_vec(&schema).unwrap()).to_hex();
    spec.schema = Some(key.clone());
    spec.schemas.insert(key, schema);
    spec
}

#[test]
fn capped_json_counter_stops_serialization_without_materializing_the_remaining_sequence() {
    struct LongSequence<'a>(&'a AtomicUsize);
    impl Serialize for LongSequence<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let mut sequence = serializer.serialize_seq(Some(100_000))?;
            let value = "x".repeat(64);
            for _ in 0..100_000 {
                self.0.fetch_add(1, Ordering::Relaxed);
                sequence.serialize_element(&value)?;
            }
            sequence.end()
        }
    }
    let visits = AtomicUsize::new(0);
    assert!(bounded_json_len(&LongSequence(&visits), 65).is_err());
    assert_eq!(visits.load(Ordering::Relaxed), 1);
    assert_eq!(bounded_json_len(&"x".repeat(65_534), 65_536).unwrap(), 65_536);
    assert!(bounded_json_len(&"x".repeat(65_535), 65_536).is_err());
}

#[test]
fn schema_reference_expansion_reserves_literal_bytes_before_enum_cloning() {
    let schema = json!({"$defs":{"values":{"enum":(0..40_000).collect::<Vec<_>>()}},
        "allOf":vec![json!({"$ref":"#/$defs/values"});254]});
    let spec = with_schema(ItemLoaderV1::default(), schema);
    spec.validate().unwrap();
    assert!(matches!(
        CompiledItemLoader::compile(&spec),
        Err(SelectorError::Budget("expanded schema literal bytes"))
    ));
}

#[test]
fn empty_relative_urls_pay_for_repeated_large_base_expansion_before_joining() {
    let spec = recipe(
        json!({"fields":[{"name":"urls","selectors":[{"kind":"xpath","expression":"//a"}],
        "extraction":{"kind":"attribute","name":"href"},"cardinality":"many","transforms":[{"kind":"resolve_url"}]}]}),
    );
    let html = Html::parse_document(&"<a href=''></a>".repeat(1000));
    let mut doc = SelectorDocument::new(&html).unwrap();
    let large_base = Url::parse(&format!("https://fixture.test/{}", "x".repeat(65_536))).unwrap();
    assert!(matches!(
        CompiledItemLoader::compile(&spec)
            .unwrap()
            .load(&mut doc, &large_base),
        Err(SelectorError::Budget(_))
    ));
}

#[test]
fn duplicated_default_payloads_cannot_exceed_retained_output_budget() {
    // Both fields[].value and item retain the caller's data. Their observable
    // payload alone exceeds the ceiling; this does not depend on DOM visit costs.
    let value = "x".repeat(64_000);
    let fields = (0..9)
        .map(|index| {
            json!({"name":format!("field{index}"),
        "selectors":[{"kind":"xpath","expression":"//missing"}],
        "extraction":{"kind":"text"},"cardinality":"one","default":value})
        })
        .collect::<Vec<_>>();
    let spec = recipe(json!({"fields":fields}));
    assert!(9usize * value.len() * 2 > crawlx_core::selectors::MAX_OPERATIONS);
    let html = Html::parse_document("<p>unrelated acquired content</p>");
    let mut doc = SelectorDocument::new(&html).unwrap();
    assert!(matches!(
        CompiledItemLoader::compile(&spec)
            .unwrap()
            .load(&mut doc, &base()),
        Err(SelectorError::Budget(_))
    ));
}

#[test]
fn caller_budget_applies_to_wide_dom_before_child_queue_expansion() {
    let html = Html::parse_document(&format!("<!doctype html>{}<p>end</p>", "<!--x-->".repeat(50_000)));
    assert!(matches!(
        SelectorDocument::with_operation_limit(&html, 3),
        Err(SelectorError::Budget("operations"))
    ));
}

#[test]
fn lazy_sibling_traversal_preserves_document_order_after_doctype_and_comments() {
    let html = Html::parse_document("<!doctype html><!--before--><p>one</p><p>two</p><!--after-->");
    let mut doc = SelectorDocument::new(&html).unwrap();
    let XPathValue::Nodes(nodes) = doc
        .evaluate(&CompiledSelector::xpath("//p/text()").unwrap(), &BTreeMap::new())
        .unwrap()
    else {
        panic!()
    };
    let values = nodes
        .into_iter()
        .map(|node| doc.string_value(node).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values, ["one", "two"]);
}

#[test]
fn finalized_text_revalidates_schema_and_omits_html_even_when_raw_markup_hides_logical_text() {
    let spec = with_schema(
        recipe(json!({"fields":[
            {"name":"plain","selectors":[{"kind":"xpath","expression":"//p"}],"extraction":{"kind":"text"},"cardinality":"one"},
            {"name":"markup","selectors":[{"kind":"xpath","expression":"//p"}],"extraction":{"kind":"html"},"cardinality":"one"}
        ]})),
        json!({"type":"object","properties":{"plain":{"const":"secret"}},"required":["plain"]}),
    );
    let mut outcome = load(&spec, "<p>sec<b>ret</b></p>");
    assert_eq!(outcome.schema_valid, Some(true));
    project_outcome(&mut outcome, &spec, &|value| {
        Some(value.replace("secret", "[private]"))
    })
    .unwrap();
    assert_eq!(outcome.item["plain"], "[private]");
    assert!(!outcome.item.to_string().contains("secret"));
    assert_eq!(outcome.schema_valid, Some(false));
    assert!(!outcome.valid);
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::Selected);
    assert!(outcome.fields[0].redacted);
    assert_eq!(outcome.fields[1].quality, FieldQualityV1::Redacted);
    assert!(outcome.fields[1].value.is_none());
}

#[test]
fn projected_numeric_and_date_types_are_not_reported_as_successful_pre_redaction_values() {
    let spec = recipe(json!({"fields":[
        {"name":"number","selectors":[{"kind":"xpath","expression":"count(//p)"}],"extraction":{"kind":"text"},"cardinality":"one"},
        {"name":"date","selectors":[{"kind":"xpath","expression":"//time"}],"extraction":{"kind":"text"},"cardinality":"one","transforms":[{"kind":"iso_date"}]}
    ]}));
    let mut outcome = load(&spec, "<p>x</p><time>2026-11-04</time>");
    assert!(outcome.valid);
    project_outcome(&mut outcome, &spec, &|value| {
        let number_one = serde_json::from_str::<serde_json::Number>(value)
            .is_ok_and(|number| number.as_f64() == Some(1.0));
        Some(if number_one || value == "2026-11-04" {
            "[private]".into()
        } else {
            value.into()
        })
    })
    .unwrap();
    assert!(!outcome.valid);
    assert!(outcome.item.as_object().unwrap().is_empty());
    assert!(outcome
        .fields
        .iter()
        .all(|field| field.quality == FieldQualityV1::Redacted && field.value.is_none()));
}

#[test]
fn caller_defaults_keep_default_provenance_but_removed_nested_values_do_not_keep_stale_objects() {
    let spec = recipe(json!({"fields":[
        {"name":"retained","selectors":[{"kind":"xpath","expression":"//missing"}],"extraction":{"kind":"text"},"cardinality":"one","default":"secret"},
        {"name":"removed","selectors":[{"kind":"xpath","expression":"//missing"}],"extraction":{"kind":"text"},"cardinality":"one","default":{"inside":"remove","safe":true}}
    ]}));
    let mut outcome = load(&spec, "<p>x</p>");
    project_outcome(&mut outcome, &spec, &|value| {
        if value == "remove" {
            None
        } else {
            Some(value.replace("secret", "[private]"))
        }
    })
    .unwrap();
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::Defaulted);
    assert!(outcome.fields[0].redacted);
    assert_eq!(outcome.item["retained"], "[private]");
    assert!(outcome.item.get("removed").is_none());
    assert_eq!(outcome.fields[1].quality, FieldQualityV1::Redacted);
    assert!(!outcome.valid);
}

#[test]
fn projection_errors_destroy_original_outcome_instead_of_leaving_sensitive_fallback_content() {
    let spec = recipe(json!({"fields":[
        {"name":"a","selectors":[{"kind":"xpath","expression":"//p"}],"extraction":{"kind":"text"},"cardinality":"one"},
        {"name":"b","selectors":[{"kind":"xpath","expression":"//p"}],"extraction":{"kind":"text"},"cardinality":"one"}
    ]}));
    let mut outcome = load(&spec, "<p>secret</p>");
    assert!(project_outcome(&mut outcome, &spec, &|value| Some(
        if matches!(value, "a" | "b") {
            "same".into()
        } else {
            value.into()
        }
    ))
    .is_err());
    assert!(outcome.fields.is_empty());
    assert!(outcome.item.as_object().unwrap().is_empty());
    assert!(!outcome.valid);
    assert_eq!(outcome.schema_valid, None);
}

#[test]
fn configured_read_more_selectors_resolve_attribute_nodes_without_issuing_requests() {
    let policy: crawlx_core::selectors::SelectorPolicyV1 = serde_json::from_value(json!({
        "readMore":[{"kind":"xpath","expression":"//a[@class='teaser']/@href"},
            {"kind":"css","expression":"a.teaser"}]
    }))
    .unwrap();
    let html=Html::parse_document("<a class='teaser' href='/first'>First</a><a class='teaser' href='/second'>Second</a><a class='teaser' href='javascript:alert(1)'>Denied</a>");
    let mut doc = SelectorDocument::new(&html).unwrap();
    let urls = crawlx_extract::item_loader::select_read_more(&mut doc, &policy, &base()).unwrap();
    assert_eq!(
        urls.iter().map(Url::as_str).collect::<Vec<_>>(),
        ["https://fixture.test/first", "https://fixture.test/second"]
    );
}

#[test]
fn configured_read_more_exhaustion_is_not_a_truncated_success() {
    let policy: crawlx_core::selectors::SelectorPolicyV1 = serde_json::from_value(json!({
        "readMore":[{"kind":"xpath","expression":"//a/@href"}]
    }))
    .unwrap();
    let source = (0..33)
        .map(|n| format!("<a href='/page{n}'>Next</a>"))
        .collect::<String>();
    let html = Html::parse_document(&source);
    let mut doc = SelectorDocument::new(&html).unwrap();
    assert!(matches!(
        crawlx_extract::item_loader::select_read_more(&mut doc, &policy, &base()),
        Err(SelectorError::Budget("read-more references"))
    ));
}
