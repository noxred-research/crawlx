//! Content-policy admission checks deliberately use no HTML parser, resource or network fixture.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crawlx_core::{extraction::ExtractionPolicyV1, hash::Digest, selectors::ItemLoaderV1};
use crawlx_extract::{validate_content_policy, xpath::SelectorError, ExtractError};
use serde_json::{json, Value};
fn policy(value: Value) -> ExtractionPolicyV1 {
    serde_json::from_value(value).unwrap()
}
fn schema_policy(schema: Value) -> ExtractionPolicyV1 {
    let mut spec = ItemLoaderV1::default();
    let key = Digest::of("crawlx.item.schema.v1", &serde_json::to_vec(&schema).unwrap()).to_hex();
    spec.schema = Some(key.clone());
    spec.schemas.insert(key, schema);
    let mut policy = ExtractionPolicyV1::default();
    policy.item_loader = Some(spec);
    policy
}
#[test]
fn malformed_css_and_xpath_reject_in_every_content_selector_slot() {
    for slot in ["include", "exclude", "readMore"] {
        for (kind, expression) in [("css", "a["), ("xpath", "//a[")] {
            let mut selectors = serde_json::Map::new();
            selectors.insert(slot.into(), json!([{"kind":kind,"expression":expression}]));
            let error = validate_content_policy(&policy(json!({"selectors":selectors}))).unwrap_err();
            assert!(matches!(error, ExtractError::Selector(_)), "{slot}/{kind}");
        }
    }
}
#[test]
fn static_namespace_validation_does_not_depend_on_document_matches() {
    let missing = policy(json!({"selectors":{"include":[{"kind":"xpath","expression":"//news:item"}]}}));
    assert!(matches!(
        validate_content_policy(&missing),
        Err(ExtractError::Selector(SelectorError::Namespace))
    ));
    let nested = policy(
        json!({"selectors":{"readMore":[{"kind":"xpath","expression":"//a[ancestor::news:article]/@href"}]}}),
    );
    assert!(matches!(
        validate_content_policy(&nested),
        Err(ExtractError::Selector(SelectorError::Namespace))
    ));
    let declared = policy(
        json!({"selectors":{"include":[{"kind":"xpath","expression":"//news:item"}],"namespaces":{"news":"urn:example:news"}}}),
    );
    validate_content_policy(&declared).unwrap();
    validate_content_policy(&policy(
        json!({"selectors":{"include":[{"kind":"xpath","expression":"//a[@title='news:item']"}]}}),
    ))
    .unwrap();
}
#[test]
fn item_field_selector_syntax_and_namespaces_reject_before_evaluation() {
    for selector in [
        json!({"kind":"css","expression":"p["}),
        json!({"kind":"xpath","expression":"//p["}),
        json!({"kind":"xpath","expression":"//missing:item"}),
    ] {
        let request = policy(
            json!({"itemLoader":{"fields":[{"name":"field","selectors":[selector],
            "extraction":{"kind":"text"},"cardinality":"one"}]}}),
        );
        assert!(matches!(
            validate_content_policy(&request),
            Err(ExtractError::Selector(_))
        ));
    }
}
#[test]
fn unsupported_schema_remote_refs_cycles_and_wrong_pins_reject_during_admission() {
    for schema in [
        json!({"unsupportedAssertion":true}),
        json!({"$ref":"https://127.0.0.1/private"}),
        json!({"$ref":"#"}),
        json!({"$defs":{"loop":{"$ref":"#/$defs/loop"}},"$ref":"#/$defs/loop"}),
    ] {
        assert!(matches!(
            validate_content_policy(&schema_policy(schema)),
            Err(ExtractError::Selector(SelectorError::Schema(_)))
        ));
    }
    let mut wrong = schema_policy(json!({"type":"object"}));
    if let Some(value) = wrong.item_loader.as_mut().unwrap().schemas.values_mut().next() {
        *value = json!({"type":"array"});
    }
    assert!(matches!(
        validate_content_policy(&wrong),
        Err(ExtractError::Selector(SelectorError::Schema(_)))
    ));
}
#[test]
fn default_and_supported_local_schema_admit_without_any_document() {
    validate_content_policy(&ExtractionPolicyV1::default()).unwrap();
    validate_content_policy(&schema_policy(
        json!({"type":"object","properties":{"title":{"type":"string"}},"required":["title"]}),
    ))
    .unwrap();
}
#[test]
fn policy_bounds_and_external_xpath_functions_reject_before_acquisition() {
    let mut unknown = ExtractionPolicyV1::default();
    unknown.version = 2;
    assert!(validate_content_policy(&unknown).is_err());
    let malicious = policy(
        json!({"selectors":{"exclude":[{"kind":"xpath","expression":"document('http://127.0.0.1/private')"}]}}),
    );
    assert!(matches!(
        validate_content_policy(&malicious),
        Err(ExtractError::Selector(SelectorError::UnsupportedFunction))
    ));
    let excessive = policy(json!({"selectors":{"include":[{"kind":"xpath","expression":"x".repeat(4097)}]}}));
    assert!(validate_content_policy(&excessive).is_err());
}
