//! Compiled, bounded item field projection on one existing DOM index.
//! JSON Schema uses an explicitly bounded offline vocabulary; unknown assertions fail admission.
use crate::xpath::{CompiledSelector, SelectorDocument, SelectorError, XPathValue};
use chrono::{DateTime, NaiveDate};
use crawlx_core::{
    hash::Digest,
    selectors::{
        FieldCardinalityV1, FieldExtractionV1, FieldOutcomeV1, FieldQualityV1, FieldTransformV1, ItemFieldV1,
        ItemLoaderV1, ItemOutcomeV1, MAX_SELECTED,
    },
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;
#[path = "item_projection.rs"]
mod projection;
#[path = "item_schema.rs"]
mod schema;
pub use projection::project_outcome;
#[derive(Debug)]
struct Field {
    rule: ItemFieldV1,
    selectors: Vec<CompiledSelector>,
}
/// A recipe compiled once. It never owns or reparses response bodies.
#[derive(Debug)]
pub struct CompiledItemLoader {
    fields: Vec<Field>,
    namespaces: BTreeMap<String, String>,
    schema: Option<schema::Schema>,
}
impl CompiledItemLoader {
    /// Compile selectors, schema references and transformation rules.
    /// # Errors
    /// Returns typed admission errors, including cyclic/remote/unpinned schema references.
    pub fn compile(spec: &ItemLoaderV1) -> Result<Self, SelectorError> {
        spec.validate()?;
        for (key, value) in &spec.schemas {
            let bytes = serde_json::to_vec(value).map_err(|_| SelectorError::Schema("serialization"))?;
            if Digest::of("crawlx.item.schema.v1", &bytes).to_hex() != *key {
                return Err(SelectorError::Schema("digest mismatch"));
            }
        }
        let schema = spec
            .schema
            .as_ref()
            .map(|key| schema::compile_registry(key, &spec.schemas))
            .transpose()?;
        let fields = spec
            .fields
            .iter()
            .map(|rule| {
                let selectors = rule
                    .selectors
                    .iter()
                    .map(|selector| {
                        let selector = CompiledSelector::compile(selector)?;
                        selector.validate_namespaces(&spec.namespaces)?;
                        Ok(selector)
                    })
                    .collect::<Result<_, SelectorError>>()?;
                Ok(Field {
                    rule: rule.clone(),
                    selectors,
                })
            })
            .collect::<Result<_, SelectorError>>()?;
        Ok(Self {
            fields,
            namespaces: spec.namespaces.clone(),
            schema,
        })
    }
    /// Evaluate every rule against the same index and shared operation budget.
    /// # Errors
    /// Resource or selector failures abort the item; field data failures remain typed outcomes.
    pub fn load(&self, doc: &mut SelectorDocument<'_>, base: &Url) -> Result<ItemOutcomeV1, SelectorError> {
        let mut fields = Vec::with_capacity(self.fields.len());
        let mut item = Map::new();
        let mut valid = true;
        for field in &self.fields {
            let mut nodes = Vec::new();
            let mut scalars = Vec::new();
            for selector in &field.selectors {
                match doc.evaluate(selector, &self.namespaces)? {
                    XPathValue::Nodes(n) => {
                        doc.charge(n.len())?;
                        nodes.extend(n);
                    }
                    XPathValue::String(s) => scalars.push(Value::String(s)),
                    XPathValue::Boolean(b) => scalars.push(Value::Bool(b)),
                    XPathValue::Number(n) => {
                        let Some(n) = serde_json::Number::from_f64(n) else {
                            return Err(SelectorError::Schema("non-finite selector number"));
                        };
                        scalars.push(Value::Number(n));
                    }
                }
            }
            let levels = usize::try_from(nodes.len().checked_ilog2().unwrap_or(0))
                .unwrap_or(usize::MAX)
                .saturating_add(1);
            doc.charge(nodes.len().saturating_mul(levels))?;
            nodes.sort_unstable();
            nodes.dedup();
            if nodes.len().saturating_add(scalars.len()) > MAX_SELECTED {
                return Err(SelectorError::Budget("selected nodes"));
            }
            let mut values = Vec::with_capacity(nodes.len().saturating_add(scalars.len()));
            for node in nodes {
                let value = match &field.rule.extraction {
                    FieldExtractionV1::Text => Some(doc.string_value(node)?),
                    FieldExtractionV1::Attribute { name } => {
                        if let Some(el) = doc.element(node) {
                            doc.charge(el.value().attrs.len())?;
                            let value = el
                                .value()
                                .attrs()
                                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                                .map(|(_, v)| v);
                            if let Some(value) = value {
                                doc.charge(value.len())?;
                                Some(value.to_owned())
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    FieldExtractionV1::Html => {
                        if doc.element(node).is_some() {
                            Some(doc.markup(node)?)
                        } else {
                            None
                        }
                    }
                    _ => return Err(SelectorError::Schema("unknown projection")),
                };
                if let Some(value) = value {
                    doc.charge(value.len())?;
                    values.push(Value::String(value));
                }
            }
            if !scalars.is_empty() && !matches!(field.rule.extraction, FieldExtractionV1::Text) {
                return Err(SelectorError::NodeSetRequired);
            }
            values.extend(scalars);
            let (quality, value) = if values.is_empty() {
                if let Some(default) = &field.rule.default {
                    let bytes = crawlx_core::selectors::bounded_json_len(default, 65_536)?;
                    doc.charge(bytes)?;
                    (FieldQualityV1::Defaulted, Some(default.clone()))
                } else if field.rule.required {
                    valid = false;
                    (FieldQualityV1::Missing, None)
                } else {
                    (
                        FieldQualityV1::Missing,
                        if matches!(field.rule.cardinality, FieldCardinalityV1::Many) {
                            Some(Value::Array(Vec::new()))
                        } else {
                            None
                        },
                    )
                }
            } else if matches!(field.rule.cardinality, FieldCardinalityV1::One) && values.len() != 1 {
                valid = false;
                (FieldQualityV1::CardinalityMismatch, None)
            } else {
                let mut malformed = false;
                for transform in &field.rule.transforms {
                    if !transform_values(&mut values, transform, base, doc)? {
                        malformed = true;
                        break;
                    }
                }
                if malformed {
                    valid = false;
                    (FieldQualityV1::MalformedTransform, None)
                } else {
                    let value = if matches!(field.rule.cardinality, FieldCardinalityV1::One)
                        || field
                            .rule
                            .transforms
                            .iter()
                            .any(|t| matches!(t, FieldTransformV1::Join { .. }))
                    {
                        values.into_iter().next().unwrap_or(Value::Null)
                    } else {
                        Value::Array(values)
                    };
                    (FieldQualityV1::Selected, Some(value))
                }
            };
            if let Some(value) = &value {
                let bytes =
                    crawlx_core::selectors::bounded_json_len(value, crawlx_core::selectors::MAX_OPERATIONS)
                        .map_err(|_| SelectorError::Budget("retained item bytes"))?;
                doc.charge(bytes)?;
                item.insert(field.rule.name.clone(), value.clone());
            }
            fields.push(FieldOutcomeV1::new(field.rule.name.clone(), quality, value));
        }
        let item = Value::Object(item);
        let schema_valid = self.schema.as_ref().map(|s| s.validate(&item, doc)).transpose()?;
        valid &= schema_valid.unwrap_or(true);
        Ok(ItemOutcomeV1::new(fields, item, valid, schema_valid))
    }
}

/// Validate a native content policy before accepting work or acquiring content.
///
/// This compiles every include/exclude/read-more selector and item field, checks static XPath
/// namespace bindings, and compiles the bounded digest-pinned local item schema. It creates no DOM,
/// opens no resource and performs no network operation. Compiled artifacts are transient; workers
/// reconstruct them from the validated persisted policy rather than serializing engine internals.
/// # Errors
/// Preserves typed policy, selector syntax/function/namespace/budget and schema errors.
pub fn validate_content_policy(
    policy: &crawlx_core::extraction::ExtractionPolicyV1,
) -> Result<(), crate::ExtractError> {
    policy.validate()?;
    crate::article_dates::validate_timezone(policy)?;
    for selector in policy
        .selectors
        .include
        .iter()
        .chain(&policy.selectors.exclude)
        .chain(&policy.selectors.read_more)
    {
        let compiled = CompiledSelector::compile(selector)?;
        compiled.validate_namespaces(&policy.selectors.namespaces)?;
    }
    if let Some(loader) = &policy.item_loader {
        CompiledItemLoader::compile(loader)?;
    }
    Ok(())
}

/// Resolve explicitly configured read-more nodes on the shared original document.
///
/// Element matches project their href. Attribute/text/comment matches project their XPath
/// string value. Only HTTP(S) references are returned, in document order with stable dedupe.
/// Returned URLs are intents, never authorization or a parser-owned acquisition.
/// # Errors
/// Returns selector/type/work exhaustion or more than 32 distinct read-more references.
pub fn select_read_more(
    doc: &mut SelectorDocument<'_>,
    policy: &crawlx_core::selectors::SelectorPolicyV1,
    base: &Url,
) -> Result<Vec<Url>, SelectorError> {
    policy.validate()?;
    let mut nodes = Vec::new();
    for rule in &policy.read_more {
        let compiled = CompiledSelector::compile(rule)?;
        let XPathValue::Nodes(selected) = doc.evaluate(&compiled, &policy.namespaces)? else {
            return Err(SelectorError::NodeSetRequired);
        };
        doc.charge(selected.len())?;
        nodes.extend(selected);
    }
    let levels = usize::try_from(nodes.len().checked_ilog2().unwrap_or(0))
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    doc.charge(nodes.len().saturating_mul(levels))?;
    nodes.sort_unstable();
    nodes.dedup();
    if nodes.len() > MAX_SELECTED {
        return Err(SelectorError::Budget("selected nodes"));
    }
    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    for node in nodes {
        let raw = if let Some(element) = doc.element(node) {
            doc.charge(element.value().attrs.len())?;
            let Some(href) = element.attr("href") else {
                continue;
            };
            doc.charge(href.len())?;
            href.to_owned()
        } else {
            doc.string_value(node)?
        };
        doc.charge(
            base.as_str()
                .len()
                .saturating_add(raw.len())
                .saturating_mul(3)
                .saturating_add(64),
        )?;
        let Some(url) =
            crate::dom::resolve(base, &raw).filter(|url| matches!(url.scheme(), "http" | "https"))
        else {
            continue;
        };
        doc.charge(url.as_str().len().saturating_mul(6))?;
        if seen.insert(url.as_str().to_owned()) {
            if output.len() >= 32 {
                return Err(SelectorError::Budget("read-more references"));
            }
            output.push(url);
        }
    }
    Ok(output)
}
fn transform_values(
    values: &mut Vec<Value>,
    transform: &FieldTransformV1,
    base: &Url,
    doc: &mut SelectorDocument<'_>,
) -> Result<bool, SelectorError> {
    if matches!(transform, FieldTransformV1::Dedupe) {
        let mut keys = BTreeSet::new();
        let mut retained = Vec::new();
        for value in values.drain(..) {
            let bytes =
                crawlx_core::selectors::bounded_json_len(&value, crawlx_core::selectors::MAX_OPERATIONS)
                    .map_err(|_| SelectorError::Budget("item transform bytes"))?;
            doc.charge(bytes)?;
            let key =
                serde_json::to_string(&value).map_err(|_| SelectorError::Schema("value serialization"))?;
            if keys.insert(key) {
                retained.push(value);
            }
        }
        *values = retained;
        return Ok(true);
    }
    if let FieldTransformV1::Join { separator } = transform {
        let Some(strings) = values.iter().map(Value::as_str).collect::<Option<Vec<_>>>() else {
            return Ok(false);
        };
        let bytes = strings
            .iter()
            .fold(0usize, |bytes, value| bytes.saturating_add(value.len()));
        doc.charge(bytes.saturating_add(separator.len().saturating_mul(strings.len())))?;
        let joined = strings.join(separator);
        *values = vec![Value::String(joined)];
        return Ok(true);
    }
    for value in values {
        let Some(s) = value.as_str() else {
            return Ok(false);
        };
        doc.charge(s.len())?;
        let result = match transform {
            FieldTransformV1::Trim => Value::String(s.trim().into()),
            FieldTransformV1::NormalizeWhitespace => {
                Value::String(s.split_whitespace().collect::<Vec<_>>().join(" "))
            }
            FieldTransformV1::ResolveUrl => {
                // Canonical base bytes can be repeated by an empty/short relative reference.
                // Reserve a percent-encoding upper bound before joining or cloning the URL.
                let expansion = base
                    .as_str()
                    .len()
                    .saturating_add(s.len())
                    .saturating_mul(3)
                    .saturating_add(64);
                doc.charge(expansion)?;
                let Ok(url) = base.join(s) else {
                    return Ok(false);
                };
                Value::String(url.into())
            }
            FieldTransformV1::IsoDate => {
                if let Ok(date) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
                    let normalized = date.format("%Y-%m-%d").to_string();
                    if normalized != s {
                        return Ok(false);
                    }
                    Value::String(normalized)
                } else if let Ok(date) = DateTime::parse_from_rfc3339(s) {
                    Value::String(date.to_rfc3339())
                } else {
                    return Ok(false);
                }
            }
            FieldTransformV1::Number => {
                let Ok(number) = serde_json::from_str::<serde_json::Number>(s) else {
                    return Ok(false);
                };
                Value::Number(number)
            }
            _ => return Err(SelectorError::Schema("unknown transform")),
        };
        *value = result;
    }
    Ok(true)
}
