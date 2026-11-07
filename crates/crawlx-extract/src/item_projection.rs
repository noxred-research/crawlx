//! Final retention projection for item fields. No raw HTML survives the text projector.
use super::{
    schema::{ProjectionBudget, WorkBudget},
    CompiledItemLoader,
};
use crate::xpath::SelectorError;
use crawlx_core::selectors::{
    bounded_json_len, FieldCardinalityV1, FieldExtractionV1, FieldQualityV1, FieldTransformV1, ItemFieldV1,
    ItemLoaderV1, ItemOutcomeV1, MAX_OPERATIONS,
};
use serde_json::{Map, Value};

/// Project retained item content and recompute field/type/schema quality from finalized values.
///
/// The callback is the caller's bounded normalized-text privacy projector, not an HTML sanitizer.
/// HTML projections are therefore omitted with `redacted` quality. Defaults are not reapplied and
/// transforms are not rerun. A removed nested value removes its whole field, avoiding silent array
/// cardinality or object-shape changes. Default provenance is retained when replacement succeeds.
///
/// On any error `outcome` is left empty and invalid, never holding its unprojected prior payload.
/// # Errors
/// Returns malformed recipe, source mismatch, projection budget or schema compilation errors.
pub fn project_outcome(
    outcome: &mut ItemOutcomeV1,
    spec: &ItemLoaderV1,
    project: &dyn Fn(&str) -> Option<String>,
) -> Result<(), SelectorError> {
    let original = std::mem::replace(
        outcome,
        ItemOutcomeV1::new(Vec::new(), Value::Object(Map::new()), false, None),
    );
    let compiled = CompiledItemLoader::compile(spec)?;
    if original.fields.len() != spec.fields.len() {
        return Err(SelectorError::Schema("item projection field count mismatch"));
    }
    let mut budget = ProjectionBudget::default();
    let mut fields = Vec::with_capacity(original.fields.len());
    let mut item = Map::new();
    let mut valid = true;
    for (index, (mut field, rule)) in original.fields.into_iter().zip(&spec.fields).enumerate() {
        if field.name != rule.name {
            return Err(SelectorError::Schema("item projection field identity mismatch"));
        }
        let original_quality = field.quality;
        let approved_name = project_string(&field.name, project, &mut budget)?;
        let name_changed = approved_name.as_ref() != Some(&field.name);
        let name_rejected = approved_name
            .as_ref()
            .is_none_or(|name| name.is_empty() || name.len() > 64);
        field.name = if name_rejected {
            format!("redacted_field_{index}")
        } else {
            approved_name.unwrap_or_default()
        };
        let old_value = field.value.take();
        let (value, changed) = if name_rejected || matches!(rule.extraction, FieldExtractionV1::Html) {
            (None, old_value.is_some())
        } else if let Some(value) = old_value {
            project_value(value, project, &mut budget, 0)?
        } else {
            (None, false)
        };
        field.redacted |= name_changed || changed;
        let rejected = (changed || name_rejected) && value.is_none();
        if rejected {
            field.quality = FieldQualityV1::Redacted;
            field.redacted = true;
            valid = false;
        } else if let Some(value) = value {
            if matches!(original_quality, FieldQualityV1::Selected) && !valid_selected_type(&value, rule) {
                field.quality = FieldQualityV1::Redacted;
                field.redacted = true;
                valid = false;
            } else {
                let bytes = bounded_json_len(&value, MAX_OPERATIONS)
                    .map_err(|_| SelectorError::Budget("projected item bytes"))?;
                budget.charge(bytes)?;
                if item.contains_key(&field.name) {
                    return Err(SelectorError::Schema("projected item key collision"));
                }
                item.insert(field.name.clone(), value.clone());
                field.value = Some(value);
            }
        }
        match field.quality {
            FieldQualityV1::Missing => {
                if rule.required {
                    valid = false;
                }
            }
            FieldQualityV1::CardinalityMismatch
            | FieldQualityV1::MalformedTransform
            | FieldQualityV1::Redacted => valid = false,
            FieldQualityV1::Selected | FieldQualityV1::Defaulted => {}
            _ => return Err(SelectorError::Schema("unknown projected field quality")),
        }
        fields.push(field);
    }
    let item = Value::Object(item);
    let schema_valid = compiled
        .schema
        .as_ref()
        .map(|schema| schema.validate(&item, &mut budget))
        .transpose()?;
    valid &= schema_valid.unwrap_or(true);
    *outcome = ItemOutcomeV1::new(fields, item, valid, schema_valid);
    Ok(())
}
fn project_string(
    value: &str,
    project: &dyn Fn(&str) -> Option<String>,
    budget: &mut impl WorkBudget,
) -> Result<Option<String>, SelectorError> {
    budget.charge(value.len())?;
    let result = project(value);
    if let Some(result) = &result {
        budget.charge(result.len())?;
    }
    Ok(result)
}
fn project_value(
    value: Value,
    project: &dyn Fn(&str) -> Option<String>,
    budget: &mut impl WorkBudget,
    depth: usize,
) -> Result<(Option<Value>, bool), SelectorError> {
    budget.charge(1)?;
    if depth > 64 {
        return Err(SelectorError::Budget("item projection depth"));
    }
    match value {
        Value::String(value) => {
            let approved = project_string(&value, project, budget)?;
            let changed = approved.as_ref() != Some(&value);
            if changed && approved.as_ref().is_some_and(String::is_empty) {
                return Ok((None, true));
            }
            Ok((approved.map(Value::String), changed))
        }
        Value::Array(values) => {
            budget.charge(values.len())?;
            let mut output = Vec::with_capacity(values.len());
            let mut changed = false;
            for value in values {
                let (value, updated) = project_value(value, project, budget, depth + 1)?;
                changed |= updated;
                let Some(value) = value else {
                    return Ok((None, true));
                };
                output.push(value);
            }
            Ok((Some(Value::Array(output)), changed))
        }
        Value::Object(values) => {
            let mut output = Map::new();
            let mut changed = false;
            for (key, value) in values {
                let approved_key = project_string(&key, project, budget)?;
                let Some(approved_key) = approved_key else {
                    return Ok((None, true));
                };
                changed |= approved_key != key;
                if output.contains_key(&approved_key) {
                    return Ok((None, true));
                }
                let (value, updated) = project_value(value, project, budget, depth + 1)?;
                changed |= updated;
                let Some(value) = value else {
                    return Ok((None, true));
                };
                output.insert(approved_key, value);
            }
            Ok((Some(Value::Object(output)), changed))
        }
        scalar => {
            let source = scalar.to_string();
            let approved = project_string(&source, project, budget)?;
            let changed = approved.as_ref() != Some(&source);
            let Some(approved) = approved else {
                return Ok((None, true));
            };
            let Ok(value) = serde_json::from_str::<Value>(&approved) else {
                return Ok((None, true));
            };
            let same_type = matches!(
                (&scalar, &value),
                (Value::Number(_), Value::Number(_))
                    | (Value::Bool(_), Value::Bool(_))
                    | (Value::Null, Value::Null)
            );
            Ok((same_type.then_some(value), changed || !same_type))
        }
    }
}
fn valid_selected_type(value: &Value, rule: &ItemFieldV1) -> bool {
    enum Kind {
        Any,
        String,
        Number,
        Date,
        Url,
    }
    let mut kind = if matches!(rule.extraction, FieldExtractionV1::Attribute { .. }) {
        Kind::String
    } else {
        Kind::Any
    };
    let mut joined = false;
    for transform in &rule.transforms {
        match transform {
            FieldTransformV1::Number => kind = Kind::Number,
            FieldTransformV1::IsoDate => kind = Kind::Date,
            FieldTransformV1::ResolveUrl => kind = Kind::Url,
            FieldTransformV1::Join { .. } => {
                kind = Kind::String;
                joined = true;
            }
            FieldTransformV1::Trim | FieldTransformV1::NormalizeWhitespace | FieldTransformV1::Dedupe => {}
            _ => return false,
        }
    }
    let valid = |value: &Value| match kind {
        Kind::Any => !value.is_array() && !value.is_object(),
        Kind::String => value.is_string(),
        Kind::Number => value.is_number(),
        Kind::Date => value.as_str().is_some_and(|s| {
            chrono::DateTime::parse_from_rfc3339(s).is_ok()
                || chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                    .is_ok_and(|d| d.format("%Y-%m-%d").to_string() == s)
        }),
        Kind::Url => value.as_str().is_some_and(|s| url::Url::parse(s).is_ok()),
    };
    if matches!(rule.cardinality, FieldCardinalityV1::Many) && !joined {
        value.as_array().is_some_and(|values| values.iter().all(valid))
    } else {
        valid(value)
    }
}
