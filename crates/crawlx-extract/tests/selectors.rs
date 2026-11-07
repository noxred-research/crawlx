//! Authored selector/item-loader pipeline cases. No sockets or upstream source copies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::{
    extraction::ExtractionPolicyV1,
    hash::Digest,
    selectors::{FieldQualityV1, ItemLoaderV1},
};
use crawlx_extract::{
    item_loader::CompiledItemLoader,
    xpath::{SelectorDocument, SelectorError},
    ExtractOptions, Extractor,
};
use scraper::Html;
use serde_json::json;
use url::Url;
fn recipe(value: serde_json::Value) -> ItemLoaderV1 {
    serde_json::from_value(value).unwrap()
}
#[test]
fn actual_pipeline_applies_xpath_and_loads_fields_from_original_tree() {
    let policy:ExtractionPolicyV1=serde_json::from_value(json!({"selectors":{"include":[{"kind":"xpath","expression":"//article"}],"exclude":[{"kind":"xpath","expression":"//aside"}]},"itemLoader":{"version":1,"fields":[{"name":"url","selectors":[{"kind":"xpath","expression":"//nav/a"}],"extraction":{"kind":"attribute","name":"href"},"cardinality":"one","transforms":[{"kind":"resolve_url"}],"required":true}]}})).unwrap();
    let source="<nav><a href='/discover'>discovery</a></nav><article><p>Selected article with enough useful text for a real content output.</p><aside>remove this</aside></article>";
    let doc = Extractor::extract(
        source,
        &Url::parse("https://fixture.test/base").unwrap(),
        &ExtractOptions {
            content: Some(policy),
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    assert!(doc.text.contains("Selected article"));
    assert!(!doc.text.contains("remove this"));
    assert!(!doc.text.contains("discovery"));
    assert!(doc
        .links
        .iter()
        .any(|link| link.url.as_str() == "https://fixture.test/discover"));
    let item = doc.item.unwrap();
    assert!(item.valid);
    assert_eq!(item.item["url"], "https://fixture.test/discover");
}
#[test]
fn explicit_empty_include_does_not_fall_back_to_body() {
    let policy: ExtractionPolicyV1 = serde_json::from_value(
        json!({"selectors":{"include":[{"kind":"xpath","expression":"//does-not-exist"}]}}),
    )
    .unwrap();
    let doc = Extractor::extract(
        "<article>Do not return broad fallback.</article>",
        &Url::parse("https://fixture.test").unwrap(),
        &ExtractOptions {
            content: Some(policy),
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    assert!(doc.text.is_empty());
}
#[test]
fn ordered_transforms_cardinality_defaults_and_quality() {
    let spec = recipe(json!({"version":1,"fields":[
        {"name":"tags","selectors":[{"kind":"xpath","expression":"//p"}],"extraction":{"kind":"text"},"cardinality":"many","transforms":[{"kind":"trim"},{"kind":"normalize_whitespace"},{"kind":"dedupe"},{"kind":"join","separator":"|"}]},
        {"name":"singular","selectors":[{"kind":"css","expression":"p"}],"extraction":{"kind":"text"},"cardinality":"one"},
        {"name":"default","selectors":[{"kind":"xpath","expression":"//missing"}],"extraction":{"kind":"text"},"cardinality":"one","default":"caller-data"},
        {"name":"missing","selectors":[{"kind":"xpath","expression":"//missing"}],"extraction":{"kind":"text"},"cardinality":"one","required":true},
        {"name":"number","selectors":[{"kind":"xpath","expression":"//p[1]"}],"extraction":{"kind":"text"},"cardinality":"one","transforms":[{"kind":"number"}]}
    ]}));
    let compiled = CompiledItemLoader::compile(&spec).unwrap();
    let html = Html::parse_document("<p> a  b </p><p>a b</p><p>c</p>");
    let mut doc = SelectorDocument::new(&html).unwrap();
    let out = compiled
        .load(&mut doc, &Url::parse("https://fixture.test").unwrap())
        .unwrap();
    assert!(!out.valid);
    assert_eq!(out.item["tags"], "a b|c");
    assert_eq!(out.item["default"], "caller-data");
    assert_eq!(
        out.fields.iter().map(|f| f.quality).collect::<Vec<_>>(),
        vec![
            FieldQualityV1::Selected,
            FieldQualityV1::CardinalityMismatch,
            FieldQualityV1::Defaulted,
            FieldQualityV1::Missing,
            FieldQualityV1::MalformedTransform
        ]
    );
}
#[test]
fn local_schema_is_digest_pinned_and_validates_typed_item() {
    let schema = json!({"type":"object","properties":{"count":{"type":"number","minimum":2}},"required":["count"],"additionalProperties":false});
    let digest = Digest::of("crawlx.item.schema.v1", &serde_json::to_vec(&schema).unwrap()).to_hex();
    let mut spec = recipe(
        json!({"version":1,"fields":[{"name":"count","selectors":[{"kind":"xpath","expression":"count(//p)"}],"extraction":{"kind":"text"},"cardinality":"one"}]}),
    );
    spec.schema = Some(digest.clone());
    spec.schemas.insert(digest, schema);
    let compiled = CompiledItemLoader::compile(&spec).unwrap();
    let html = Html::parse_document("<p>one</p><p>two</p>");
    let mut doc = SelectorDocument::new(&html).unwrap();
    let out = compiled
        .load(&mut doc, &Url::parse("https://fixture.test").unwrap())
        .unwrap();
    assert_eq!(out.schema_valid, Some(true));
    assert_eq!(out.item["count"], 2.0);
}
#[test]
fn remote_references_cycles_and_unknown_assertions_reject_before_load() {
    for schema in [
        json!({"$ref":"https://127.0.0.1/secret"}),
        json!({"$ref":"#"}),
        json!({"$defs":{"loop":{"$ref":"#/$defs/loop"}},"$ref":"#/$defs/loop"}),
        json!({"madeUpAssertion":true}),
    ] {
        let key = Digest::of("crawlx.item.schema.v1", &serde_json::to_vec(&schema).unwrap()).to_hex();
        let mut spec = ItemLoaderV1::default();
        spec.schema = Some(key.clone());
        spec.schemas.insert(key, schema);
        assert!(matches!(
            CompiledItemLoader::compile(&spec),
            Err(SelectorError::Schema(_))
        ));
    }
}
#[test]
fn loader_budget_failure_never_returns_valid_empty_item() {
    let spec = recipe(
        json!({"version":1,"fields":[{"name":"field","selectors":[{"kind":"xpath","expression":"//p"}],"extraction":{"kind":"text"},"cardinality":"many"}]}),
    );
    let compiled = CompiledItemLoader::compile(&spec).unwrap();
    let html = Html::parse_document("<p>x</p>");
    let mut doc = SelectorDocument::new(&html).unwrap();
    doc.restrict_operations(1);
    assert!(matches!(
        compiled.load(&mut doc, &Url::parse("https://fixture.test").unwrap()),
        Err(SelectorError::Budget(_))
    ));
}

#[test]
fn explicit_null_default_differs_from_absent_default_and_survives_roundtrip() {
    let spec = recipe(json!({"fields":[
        {"name":"null","selectors":[{"kind":"xpath","expression":"//missing"}],"extraction":{"kind":"text"},"cardinality":"one","default":null},
        {"name":"absent","selectors":[{"kind":"xpath","expression":"//missing"}],"extraction":{"kind":"text"},"cardinality":"one"}
    ]}));
    assert_eq!(spec.fields[0].default, Some(serde_json::Value::Null));
    assert_eq!(spec.fields[1].default, None);
    let spec: ItemLoaderV1 = serde_json::from_value(serde_json::to_value(spec).unwrap()).unwrap();
    assert_eq!(spec.fields[1].default, None);
    let html = Html::parse_document("<p>x</p>");
    let mut doc = SelectorDocument::new(&html).unwrap();
    let output = CompiledItemLoader::compile(&spec)
        .unwrap()
        .load(&mut doc, &Url::parse("https://fixture.test").unwrap())
        .unwrap();
    assert_eq!(output.fields[0].quality, FieldQualityV1::Defaulted);
    assert_eq!(output.fields[1].quality, FieldQualityV1::Missing);
    assert!(output.item["null"].is_null());
    assert!(output.item.get("absent").is_none());
    assert!(output.valid);
}
