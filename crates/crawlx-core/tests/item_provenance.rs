//! Field evidence remains bounded, versioned and free of recipe parameters or source values.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::selectors::{
    FieldOutcomeV1, FieldProcessorKindV1, FieldProcessorOutcomeV1, FieldProvenanceV1, FieldSelectionV1,
    FieldSourceKindV1, ItemFieldV1, ItemLoaderV1, MAX_SELECTED,
};
use serde_json::{json, Value};

fn rule() -> ItemFieldV1 {
    serde_json::from_value(json!({
        "name":"amount", "selectors":[{"kind":"css","expression":".private-source"}],
        "extraction":{"kind":"text"}, "cardinality":"one",
        "inputProcessors":[{"kind":"trim"}], "transforms":[{"kind":"number"}]
    }))
    .unwrap()
}

fn evidence() -> FieldProvenanceV1 {
    let mut evidence = FieldProvenanceV1::new(FieldSourceKindV1::Context);
    evidence.selections.push(FieldSelectionV1::new(0, 1));
    evidence.selected_values = 1;
    evidence.input_processors.push(FieldProcessorOutcomeV1::new(
        0,
        FieldProcessorKindV1::Trim,
        1,
        Some(1),
    ));
    evidence.output_processors.push(FieldProcessorOutcomeV1::new(
        0,
        FieldProcessorKindV1::Number,
        1,
        Some(1),
    ));
    evidence
}

#[test]
fn provenance_round_trip_has_only_structural_counts_and_operation_kinds() {
    let evidence = evidence();
    evidence.validate(&rule()).unwrap();
    let encoded = serde_json::to_value(&evidence).unwrap();
    assert_eq!(
        encoded,
        json!({
            "version":1, "source":"context", "selections":[{"index":0,"matches":1}],
            "selectedValues":1,
            "inputProcessors":[{"index":0,"kind":"trim","inputValues":1,"outputValues":1}],
            "outputProcessors":[{"index":0,"kind":"number","inputValues":1,"outputValues":1}]
        })
    );
    assert_eq!(
        serde_json::from_value::<FieldProvenanceV1>(encoded).unwrap(),
        evidence
    );
}

#[test]
fn provenance_rejects_wrong_versions_counts_indices_and_recipe_identities() {
    let rule = rule();
    let mut candidates = Vec::new();
    let mut invalid = evidence();
    invalid.version = 2;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.source = FieldSourceKindV1::NextSibling;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.selected_values = MAX_SELECTED + 1;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.selections[0].matches = MAX_SELECTED + 1;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.selections[0].index = 1;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.selections.clear();
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.output_processors[0].kind = FieldProcessorKindV1::Trim;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.input_processors[0].input_values = MAX_SELECTED + 1;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.output_processors[0].output_values = Some(MAX_SELECTED + 1);
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid.output_processors[0].index = 1;
    candidates.push(invalid);
    let mut invalid = evidence();
    invalid
        .input_processors
        .resize(17, invalid.input_processors[0].clone());
    candidates.push(invalid);
    for invalid in candidates {
        assert!(invalid.validate(&rule).is_err(), "{invalid:?}");
    }
}

#[test]
fn rejected_processor_can_only_end_the_executed_prefix() {
    let mut rule = rule();
    rule.input_processors.push(rule.input_processors[0].clone());
    let mut evidence = evidence();
    evidence.input_processors[0].output_values = None;
    evidence.output_processors.clear();
    evidence.validate(&rule).unwrap();
    evidence.input_processors.push(FieldProcessorOutcomeV1::new(
        1,
        FieldProcessorKindV1::Trim,
        1,
        Some(1),
    ));
    assert!(evidence.validate(&rule).is_err());
}

#[test]
fn legacy_outcome_keeps_provenance_absent_and_legacy_recipe_keeps_input_stage_empty() {
    let old = json!({"name":"amount","quality":"selected","value":7,"redacted":false});
    let outcome: FieldOutcomeV1 = serde_json::from_value(old.clone()).unwrap();
    assert!(outcome.provenance.is_none());
    assert_eq!(serde_json::to_value(outcome).unwrap(), old);
    let mut encoded = serde_json::to_value(rule()).unwrap();
    encoded.as_object_mut().unwrap().remove("inputProcessors");
    let legacy: ItemFieldV1 = serde_json::from_value(encoded).unwrap();
    assert!(legacy.input_processors.is_empty());
    assert!(serde_json::to_value(legacy)
        .unwrap()
        .get("inputProcessors")
        .is_none());
}

#[test]
fn input_processors_share_existing_recipe_limits_and_parameter_validation() {
    let mut loader = ItemLoaderV1::default();
    loader.fields.push(rule());
    loader.validate().unwrap();
    loader.fields[0]
        .input_processors
        .resize(17, crawlx_core::selectors::FieldTransformV1::Trim);
    assert!(loader.validate().is_err());
    let mut encoded = serde_json::to_value(rule()).unwrap();
    for processor in [
        json!({"kind":"regex","pattern":"x".repeat(513)}),
        json!({"kind":"limit","count":0}),
        json!({"kind":"join","separator":"x".repeat(1025)}),
    ] {
        encoded["inputProcessors"] = Value::Array(vec![processor]);
        loader.fields[0] = serde_json::from_value(encoded.clone()).unwrap();
        assert!(loader.validate().is_err());
    }
}
