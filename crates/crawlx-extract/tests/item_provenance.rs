//! Ordered processor and field evidence, including schema rejection and final privacy projection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::{
    hash::Digest,
    selectors::{FieldProcessorKindV1, FieldQualityV1, FieldSourceKindV1, ItemLoaderV1, ItemOutcomeV1},
};
use crawlx_extract::{
    item_loader::{project_outcome, CompiledItemLoader},
    xpath::{SelectorDocument, SelectorError},
};
use scraper::Html;
use serde_json::{json, Value};
use url::Url;

fn recipe(fields: Value) -> ItemLoaderV1 {
    serde_json::from_value(json!({"version":1,"fields":fields})).unwrap()
}

fn load(spec: &ItemLoaderV1, source: &str) -> ItemOutcomeV1 {
    let html = Html::parse_document(source);
    let mut document = SelectorDocument::new(&html).unwrap();
    CompiledItemLoader::compile(spec)
        .unwrap()
        .load(&mut document, &Url::parse("https://fixture.test/").unwrap())
        .unwrap()
}

#[test]
fn union_selection_and_input_processing_precede_cardinality_and_output_processing() {
    let spec = recipe(json!([{
        "name":"amount", "selectors":[
            {"kind":"css","expression":"p"},
            {"kind":"css","expression":"p.first"},
            {"kind":"css","expression":".missing"}
        ],
        "extraction":{"kind":"text"}, "cardinality":"one",
        "inputProcessors":[{"kind":"trim"},{"kind":"dedupe"}],
        "transforms":[{"kind":"number"}]
    }]));
    let mut outcome = load(&spec, "<p class='first'> 7 </p><p>7</p>");
    assert!(outcome.valid);
    assert_eq!(outcome.item, json!({"amount":7}));
    let evidence = outcome.fields[0].provenance.as_ref().unwrap();
    evidence.validate(&spec.fields[0]).unwrap();
    assert_eq!(evidence.source, FieldSourceKindV1::Context);
    assert_eq!(
        evidence.selections.iter().map(|s| s.matches).collect::<Vec<_>>(),
        [2, 1, 0]
    );
    assert_eq!(evidence.selected_values, 2);
    assert_eq!(evidence.input_processors[0].kind, FieldProcessorKindV1::Trim);
    assert_eq!(evidence.input_processors[0].input_values, 2);
    assert_eq!(evidence.input_processors[0].output_values, Some(2));
    assert_eq!(evidence.input_processors[1].kind, FieldProcessorKindV1::Dedupe);
    assert_eq!(evidence.input_processors[1].output_values, Some(1));
    assert_eq!(evidence.output_processors[0].kind, FieldProcessorKindV1::Number);
    assert_eq!(evidence.output_processors[0].input_values, 1);
    project_outcome(&mut outcome, &spec, &|s| Some(s.to_owned())).unwrap();
    assert_eq!(outcome.item, json!({"amount":7}));
}

#[test]
fn processors_keep_declared_order_and_output_join_keeps_existing_scalar_shape() {
    let spec = recipe(json!([{
        "name":"codes", "selectors":[{"kind":"css","expression":"p"}],
        "extraction":{"kind":"text"}, "cardinality":"many",
        "inputProcessors":[{"kind":"trim"},{"kind":"regex","pattern":"ID:(.+)","group":1}],
        "transforms":[{"kind":"dedupe"},{"kind":"join","separator":","},{"kind":"trim"}]
    }]));
    let outcome = load(&spec, "<p> ID:a </p><p>ID:a</p><p>ID:b</p>");
    assert_eq!(outcome.item, json!({"codes":"a,b"}));
    let evidence = outcome.fields[0].provenance.as_ref().unwrap();
    assert_eq!(
        evidence
            .input_processors
            .iter()
            .map(|e| e.kind)
            .collect::<Vec<_>>(),
        [FieldProcessorKindV1::Trim, FieldProcessorKindV1::Regex,]
    );
    assert_eq!(
        evidence
            .output_processors
            .iter()
            .map(|e| e.kind)
            .collect::<Vec<_>>(),
        [
            FieldProcessorKindV1::Dedupe,
            FieldProcessorKindV1::Join,
            FieldProcessorKindV1::Trim,
        ]
    );
    assert_eq!(
        evidence
            .output_processors
            .iter()
            .map(|e| e.output_values)
            .collect::<Vec<_>>(),
        [Some(2), Some(1), Some(1),]
    );
}

#[test]
fn input_rejection_records_only_executed_prefix_and_never_uses_default() {
    let spec = recipe(json!([{
        "name":"amount", "selectors":[{"kind":"css","expression":"p"}],
        "extraction":{"kind":"text"}, "cardinality":"one", "default":99,
        "inputProcessors":[{"kind":"number"},{"kind":"trim"}],
        "transforms":[{"kind":"limit","count":1}]
    }]));
    let outcome = load(&spec, "<p>not-a-number</p>");
    assert!(!outcome.valid);
    assert_eq!(outcome.item, json!({}));
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::MalformedTransform);
    assert!(outcome.fields[0].value.is_none());
    let evidence = outcome.fields[0].provenance.as_ref().unwrap();
    assert_eq!(evidence.input_processors.len(), 1);
    assert_eq!(evidence.input_processors[0].output_values, None);
    assert!(evidence.output_processors.is_empty());
}

#[test]
fn output_rejection_and_cardinality_rejection_skip_later_processors() {
    let spec = recipe(json!([
        {"name":"malformed", "selectors":[{"kind":"css","expression":"p.first"}],
         "extraction":{"kind":"text"}, "cardinality":"one",
         "transforms":[{"kind":"number"},{"kind":"trim"}]},
        {"name":"multiple", "selectors":[{"kind":"css","expression":"p"}],
         "extraction":{"kind":"text"}, "cardinality":"one",
         "inputProcessors":[{"kind":"trim"}], "transforms":[{"kind":"number"}]}
    ]));
    let outcome = load(&spec, "<p class='first'>bad</p><p>7</p>");
    assert!(!outcome.valid);
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::MalformedTransform);
    let evidence = outcome.fields[0].provenance.as_ref().unwrap();
    assert_eq!(evidence.output_processors.len(), 1);
    assert_eq!(evidence.output_processors[0].output_values, None);
    assert_eq!(outcome.fields[1].quality, FieldQualityV1::CardinalityMismatch);
    let evidence = outcome.fields[1].provenance.as_ref().unwrap();
    assert_eq!(evidence.input_processors.len(), 1);
    assert!(evidence.output_processors.is_empty());
}

#[test]
fn missing_and_defaulted_sources_have_zero_match_evidence_and_no_processor_execution() {
    let spec = recipe(json!([
        {"name":"missing", "selectors":[{"kind":"css","expression":".absent"}],
         "extraction":{"kind":"text"}, "cardinality":"one", "required":true,
         "inputProcessors":[{"kind":"number"}]},
        {"name":"defaulted", "selectors":[{"kind":"css","expression":".absent"}],
         "extraction":{"kind":"text"}, "cardinality":"one", "default":null,
         "inputProcessors":[{"kind":"number"}], "transforms":[{"kind":"trim"}]}
    ]));
    let outcome = load(&spec, "<p>x</p>");
    assert!(!outcome.valid);
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::Missing);
    assert_eq!(outcome.fields[1].quality, FieldQualityV1::Defaulted);
    assert_eq!(outcome.fields[1].value, Some(Value::Null));
    for field in &outcome.fields {
        let evidence = field.provenance.as_ref().unwrap();
        assert_eq!(evidence.selected_values, 0);
        assert_eq!(evidence.selections[0].matches, 0);
        assert!(evidence.input_processors.is_empty());
        assert!(evidence.output_processors.is_empty());
    }
}

#[test]
fn privacy_projection_preserves_safe_evidence_without_selector_or_processor_parameters() {
    let spec = recipe(json!([{
        "name":"value", "selectors":[{"kind":"css","expression":"[data-private='private-token']"}],
        "extraction":{"kind":"attribute","name":"data-private"}, "cardinality":"many",
        "inputProcessors":[{"kind":"regex","pattern":"(private-token)","group":1}],
        "transforms":[{"kind":"join","separator":"private-separator"}]
    }]));
    let mut outcome = load(&spec, "<p data-private='private-token'>private-text</p>");
    let evidence = outcome.fields[0].provenance.clone();
    project_outcome(&mut outcome, &spec, &|s| {
        Some(if s.contains("private-") {
            "[removed]".to_owned()
        } else {
            s.to_owned()
        })
    })
    .unwrap();
    assert!(outcome.valid);
    assert!(outcome.fields[0].redacted);
    assert_eq!(outcome.fields[0].provenance, evidence);
    let encoded = serde_json::to_string(&outcome).unwrap();
    assert!(!encoded.contains("private-"), "{encoded}");

    let mut outcome = load(&spec, "<p data-private='private-token'>x</p>");
    project_outcome(&mut outcome, &spec, &|s| {
        (!s.contains("private-")).then(|| s.to_owned())
    })
    .unwrap();
    assert!(!outcome.valid);
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::Redacted);
    assert_eq!(outcome.fields[0].provenance, evidence);
    assert!(!serde_json::to_string(&outcome).unwrap().contains("private-"));
}

#[test]
fn projection_rejects_invalid_evidence_and_leaves_no_unprojected_content() {
    let spec = recipe(json!([{
        "name":"value", "selectors":[{"kind":"css","expression":"p"}],
        "extraction":{"kind":"text"}, "cardinality":"one"
    }]));
    let mut outcome = load(&spec, "<p>unprojected-content</p>");
    outcome.fields[0].provenance.as_mut().unwrap().version = 2;
    assert!(project_outcome(&mut outcome, &spec, &|s| Some(s.to_owned())).is_err());
    assert!(!outcome.valid);
    assert!(outcome.fields.is_empty());
    assert_eq!(outcome.item, json!({}));
}

#[test]
fn nested_sibling_fields_keep_structural_sources_and_zero_matches_when_source_is_absent() {
    let spec = recipe(json!([{
        "name":"rows", "selectors":[{"kind":"css","expression":"dt"}],
        "extraction":{"kind":"group"}, "cardinality":"many", "fields":[
            {"name":"next", "source":{"kind":"next_sibling"},
             "selectors":[{"kind":"xpath","expression":"."}],
             "extraction":{"kind":"text"}, "cardinality":"one"},
            {"name":"previous", "source":{"kind":"previous_sibling"},
             "selectors":[{"kind":"xpath","expression":"."}],
             "extraction":{"kind":"text"}, "cardinality":"one", "default":"none"}
        ]
    }]));
    let mut outcome = load(&spec, "<dl><dt>key</dt><dd>value</dd></dl>");
    let fields = &outcome.fields[0].groups[0];
    assert_eq!(
        fields[0].provenance.as_ref().unwrap().source,
        FieldSourceKindV1::NextSibling
    );
    let previous = fields[1].provenance.as_ref().unwrap();
    assert_eq!(previous.source, FieldSourceKindV1::PreviousSibling);
    assert_eq!(previous.selections[0].matches, 0);
    assert_eq!(previous.selected_values, 0);
    assert_eq!(fields[1].quality, FieldQualityV1::Defaulted);
    project_outcome(&mut outcome, &spec, &|s| Some(s.to_owned())).unwrap();
    assert!(outcome.valid);
    assert!(outcome.fields[0].groups[0][0].provenance.is_some());
}

#[test]
fn schema_rejection_keeps_successful_field_evidence_but_never_accepts_item() {
    let mut spec = recipe(json!([{
        "name":"value", "selectors":[{"kind":"css","expression":"p"}],
        "extraction":{"kind":"text"}, "cardinality":"one"
    }]));
    let schema = json!({"type":"object","required":["other"]});
    let key = Digest::of("crawlx.item.schema.v1", &serde_json::to_vec(&schema).unwrap()).to_hex();
    spec.schema = Some(key.clone());
    spec.schemas.insert(key, schema);
    let mut outcome = load(&spec, "<p>x</p>");
    assert_eq!(outcome.schema_valid, Some(false));
    assert!(!outcome.valid);
    assert_eq!(outcome.fields[0].quality, FieldQualityV1::Selected);
    assert!(outcome.fields[0].provenance.is_some());
    project_outcome(&mut outcome, &spec, &|s| Some(s.to_owned())).unwrap();
    assert_eq!(outcome.schema_valid, Some(false));
    assert!(!outcome.valid);
}

#[test]
fn input_regexes_compile_with_existing_bounded_engine_and_reject_invalid_syntax() {
    let spec = recipe(json!([{
        "name":"value", "selectors":[{"kind":"css","expression":"p"}],
        "extraction":{"kind":"text"}, "cardinality":"one",
        "inputProcessors":[{"kind":"regex","pattern":"(?=unsupported)"}]
    }]));
    assert!(matches!(
        CompiledItemLoader::compile(&spec),
        Err(SelectorError::Regex(_))
    ));
}
