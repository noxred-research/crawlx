//! Compiled, bounded item field projection on one existing DOM index.
//! JSON Schema uses an explicitly bounded offline vocabulary; unknown assertions fail admission.
//!
//! A recipe is a tree of fields. Top-level fields select from the document; a `group` field
//! selects base elements and evaluates its nested fields relative to each one (optionally from a
//! sibling of the base). Nothing here fetches or evaluates code: selectors, transforms and the
//! schema are all static data under one shared operation budget.
use crate::handlers;
use crate::regex_builtins;
use crate::xpath::{CompiledSelector, SelectorDocument, SelectorError, XPathValue};
use chrono::{DateTime, NaiveDate};
use crawlx_core::{
    extraction::{DiscoveryIntentV1, DiscoveryPurposeV1},
    hash::Digest,
    selectors::{
        FieldCardinalityV1, FieldExtractionV1, FieldOutcomeV1, FieldQualityV1, FieldSourceV1,
        FieldTransformV1, ItemFieldV1, ItemLoaderV1, ItemOutcomeV1, ReadMoreBaseV1, SelectorV1, MAX_SELECTED,
    },
};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;
#[path = "item_projection.rs"]
mod projection;
#[path = "item_schema.rs"]
mod schema;
pub use projection::project_outcome;
#[derive(Debug)]
struct TransformRegex {
    regex: Regex,
    group: usize,
}
#[derive(Debug)]
struct Field {
    /// Unique within one compiled loader; keys the per-run sibling selection cache.
    id: usize,
    rule: ItemFieldV1,
    selectors: Vec<CompiledSelector>,
    /// One entry per transform; present for `regex` and `builtin` transforms.
    regexes: Vec<Option<TransformRegex>>,
    source_selector: Option<CompiledSelector>,
    children: Vec<Field>,
}
/// A recipe compiled once. It never owns or reparses response bodies.
#[derive(Debug)]
pub struct CompiledItemLoader {
    fields: Vec<Field>,
    namespaces: BTreeMap<String, String>,
    schema: Option<schema::Schema>,
}
/// Per-load mutable state shared by every nesting level.
struct Run<'a> {
    base: &'a Url,
    valid: bool,
    /// Elements selected by a sibling-source selector, keyed by field id and parent node.
    siblings: BTreeMap<(usize, usize), BTreeSet<usize>>,
}
fn compile_fields(
    specs: &[ItemFieldV1],
    namespaces: &BTreeMap<String, String>,
    next_id: &mut usize,
) -> Result<Vec<Field>, SelectorError> {
    let compile_selector = |selector: &SelectorV1| {
        let selector = CompiledSelector::compile(selector)?;
        selector.validate_namespaces(namespaces)?;
        Ok::<_, SelectorError>(selector)
    };
    specs
        .iter()
        .map(|rule| -> Result<Field, SelectorError> {
            let id = *next_id;
            *next_id += 1;
            let selectors = rule
                .selectors
                .iter()
                .map(compile_selector)
                .collect::<Result<Vec<_>, SelectorError>>()?;
            let regexes = rule
                .transforms
                .iter()
                .map(compile_transform_regex)
                .collect::<Result<Vec<_>, SelectorError>>()?;
            let source_selector = match &rule.source {
                Some(
                    FieldSourceV1::NextSibling {
                        selector: Some(selector),
                    }
                    | FieldSourceV1::PreviousSibling {
                        selector: Some(selector),
                    },
                ) => Some(compile_selector(selector)?),
                _ => None,
            };
            Ok(Field {
                id,
                rule: rule.clone(),
                selectors,
                regexes,
                source_selector,
                children: compile_fields(&rule.fields, namespaces, next_id)?,
            })
        })
        .collect()
}
fn compile_transform_regex(transform: &FieldTransformV1) -> Result<Option<TransformRegex>, SelectorError> {
    match transform {
        FieldTransformV1::Regex { pattern, group, .. } => {
            let regex = regex_builtins::compile_regex(pattern)?;
            let groups = regex.captures_len().saturating_sub(1);
            if *group > groups {
                return Err(regex_builtins::RegexError::GroupOutOfRange {
                    group: *group,
                    groups,
                }
                .into());
            }
            Ok(Some(TransformRegex { regex, group: *group }))
        }
        FieldTransformV1::Builtin { name, .. } => {
            let found = regex_builtins::builtin(name)?;
            Ok(Some(TransformRegex {
                regex: regex_builtins::compile_regex(found.pattern)?,
                group: found.group,
            }))
        }
        _ => Ok(None),
    }
}
impl CompiledItemLoader {
    /// Compile selectors, schema references and transformation rules.
    /// # Errors
    /// Returns typed admission errors, including cyclic/remote/unpinned schema references and
    /// regex patterns the linear-time engine does not admit.
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
        let fields = compile_fields(&spec.fields, &spec.namespaces, &mut 0)?;
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
        let mut run = Run {
            base,
            valid: true,
            siblings: BTreeMap::new(),
        };
        let (fields, item) = self.load_fields(&self.fields, 0, doc, &mut run)?;
        let item = Value::Object(item);
        let schema_valid = self.schema.as_ref().map(|s| s.validate(&item, doc)).transpose()?;
        let valid = run.valid & schema_valid.unwrap_or(true);
        Ok(ItemOutcomeV1::new(fields, item, valid, schema_valid))
    }
    /// The element a field's selectors start from: the context itself or one of its siblings.
    fn resolve_source(
        &self,
        field: &Field,
        context: usize,
        doc: &mut SelectorDocument<'_>,
        run: &mut Run<'_>,
    ) -> Result<Option<usize>, SelectorError> {
        let forward = match &field.rule.source {
            None | Some(FieldSourceV1::Context) => return Ok(Some(context)),
            Some(FieldSourceV1::NextSibling { .. }) => true,
            Some(FieldSourceV1::PreviousSibling { .. }) => false,
            Some(_) => return Err(SelectorError::Schema("unknown field source")),
        };
        let Some(parent) = doc.parent_of(context) else {
            return Ok(None);
        };
        let siblings = doc.element_children(parent)?;
        let Some(position) = siblings.iter().position(|node| *node == context) else {
            return Ok(None);
        };
        let allowed = if let Some(selector) = &field.source_selector {
            let key = (field.id, parent);
            if let std::collections::btree_map::Entry::Vacant(entry) = run.siblings.entry(key) {
                let XPathValue::Nodes(nodes) = doc.evaluate_in(selector, parent, &self.namespaces)? else {
                    return Err(SelectorError::NodeSetRequired);
                };
                entry.insert(nodes.into_iter().collect());
            }
            run.siblings.get(&key)
        } else {
            None
        };
        let ordered: Vec<usize> = if forward {
            siblings[position + 1..].to_vec()
        } else {
            siblings[..position].iter().rev().copied().collect()
        };
        Ok(ordered
            .into_iter()
            .find(|node| allowed.is_none_or(|set| set.contains(node))))
    }
    fn load_fields(
        &self,
        fields: &[Field],
        context: usize,
        doc: &mut SelectorDocument<'_>,
        run: &mut Run<'_>,
    ) -> Result<(Vec<FieldOutcomeV1>, Map<String, Value>), SelectorError> {
        let mut outcomes = Vec::with_capacity(fields.len());
        let mut item = Map::new();
        for field in fields {
            let origin = self.resolve_source(field, context, doc, run)?;
            let mut nodes = Vec::new();
            let mut scalars = Vec::new();
            if let Some(origin) = origin {
                for selector in &field.selectors {
                    match doc.evaluate_in(selector, origin, &self.namespaces)? {
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
            let mut groups = Vec::new();
            if matches!(field.rule.extraction, FieldExtractionV1::Group) {
                if !scalars.is_empty() {
                    return Err(SelectorError::NodeSetRequired);
                }
                for node in nodes {
                    if doc.element(node).is_none() {
                        return Err(SelectorError::NodeSetRequired);
                    }
                    let (child_outcomes, object) = self.load_fields(&field.children, node, doc, run)?;
                    groups.push(child_outcomes);
                    values.push(Value::Object(object));
                }
            } else {
                for node in nodes {
                    let value = match &field.rule.extraction {
                        FieldExtractionV1::Text => Some(Value::String(doc.string_value(node)?)),
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
                                    Some(Value::String(value.to_owned()))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        FieldExtractionV1::Attributes => {
                            if let Some(el) = doc.element(node) {
                                doc.charge(el.value().attrs.len())?;
                                let object = handlers::attribute_object(el);
                                let bytes = crawlx_core::selectors::bounded_json_len(
                                    &object,
                                    crawlx_core::selectors::MAX_OPERATIONS,
                                )
                                .map_err(|_| SelectorError::Budget("attribute bytes"))?;
                                doc.charge(bytes)?;
                                Some(Value::Object(object))
                            } else {
                                None
                            }
                        }
                        FieldExtractionV1::Html => {
                            if doc.element(node).is_some() {
                                Some(Value::String(doc.markup(node)?))
                            } else {
                                None
                            }
                        }
                        _ => return Err(SelectorError::Schema("unknown projection")),
                    };
                    if let Some(value) = value {
                        if let Value::String(s) = &value {
                            doc.charge(s.len())?;
                        }
                        values.push(value);
                    }
                }
                if !scalars.is_empty() && !matches!(field.rule.extraction, FieldExtractionV1::Text) {
                    return Err(SelectorError::NodeSetRequired);
                }
                values.extend(scalars);
            }
            let (quality, value) = if values.is_empty() {
                if let Some(default) = &field.rule.default {
                    let bytes = crawlx_core::selectors::bounded_json_len(default, 65_536)?;
                    doc.charge(bytes)?;
                    (FieldQualityV1::Defaulted, Some(default.clone()))
                } else if field.rule.required {
                    run.valid = false;
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
                run.valid = false;
                (FieldQualityV1::CardinalityMismatch, None)
            } else {
                let mut malformed = false;
                for (transform, regex) in field.rule.transforms.iter().zip(&field.regexes) {
                    if !transform_values(&mut values, transform, regex.as_ref(), run.base, doc)? {
                        malformed = true;
                        break;
                    }
                }
                let one = matches!(field.rule.cardinality, FieldCardinalityV1::One);
                if malformed || (one && values.is_empty()) {
                    run.valid = false;
                    (FieldQualityV1::MalformedTransform, None)
                } else {
                    let value = if one
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
            let mut outcome = FieldOutcomeV1::new(field.rule.name.clone(), quality, value);
            if matches!(quality, FieldQualityV1::Selected) {
                outcome.groups = groups;
            }
            outcomes.push(outcome);
        }
        Ok((outcomes, item))
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

/// Base URL against which read-more targets of `policy` resolve: the document base (honoring a
/// `base` element) by default, or the page URL itself when the policy selects it.
#[must_use]
pub fn read_more_base<'u>(
    policy: &crawlx_core::selectors::SelectorPolicyV1,
    document_base: &'u Url,
    page: &'u Url,
) -> &'u Url {
    match policy.read_more_base {
        Some(ReadMoreBaseV1::Page) => page,
        _ => document_base,
    }
}

/// Resolve explicitly configured read-more nodes on the shared original document into unresolved
/// discovery intents.
///
/// The selected nodes come from static CSS/XPath (union selectors allowed) and are returned as
/// `ReadMoreReference` intents in document order. The extractor never fetches them: whether a
/// target may be followed is decided later by the worker under scope, robots and budgets. With no
/// network available the result is identical, because no request is ever issued here.
/// # Errors
/// Same as [`select_read_more`].
pub fn read_more_intents(
    doc: &mut SelectorDocument<'_>,
    policy: &crawlx_core::selectors::SelectorPolicyV1,
    document_base: &Url,
    page: &Url,
) -> Result<Vec<DiscoveryIntentV1>, SelectorError> {
    Ok(
        select_read_more(doc, policy, read_more_base(policy, document_base, page))?
            .into_iter()
            .map(|url| DiscoveryIntentV1::new(url, DiscoveryPurposeV1::ReadMoreReference))
            .collect(),
    )
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
    compiled: Option<&TransformRegex>,
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
    if let FieldTransformV1::Limit { count } = transform {
        values.truncate(*count);
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
    if let (FieldTransformV1::Regex { all, .. } | FieldTransformV1::Builtin { all, .. }, Some(compiled)) =
        (transform, compiled)
    {
        let mut retained = Vec::new();
        for value in values.drain(..) {
            let Some(s) = value.as_str() else {
                return Ok(false);
            };
            doc.charge(s.len().saturating_mul(2))?;
            for found in handlers::regex_values(&compiled.regex, compiled.group, s, *all) {
                doc.charge(found.len())?;
                if retained.len() >= MAX_SELECTED {
                    return Err(SelectorError::Budget("selected nodes"));
                }
                retained.push(Value::String(found));
            }
        }
        *values = retained;
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
            FieldTransformV1::Clean => Value::String(handlers::clean_text(s)),
            FieldTransformV1::JsonParse => {
                let Ok(parsed) = handlers::parse_json(s) else {
                    return Ok(false);
                };
                doc.charge(s.len())?;
                parsed
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
