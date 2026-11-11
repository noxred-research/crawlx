//! Bounded static selectors, declarative item loading and relocation contracts.
//!
//! These are extraction data, never browser action locators or authorization.
use crate::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Hard expression byte cap.
pub const MAX_EXPRESSION_BYTES: usize = 4096;
/// Hard AST node cap.
pub const MAX_AST_NODES: usize = 512;
/// Hard operation cap per shared document evaluation budget.
pub const MAX_OPERATIONS: usize = 1_000_000;
/// Hard selected-node cap.
pub const MAX_SELECTED: usize = 10_000;

/// Static selector syntax.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SelectorV1 {
    /// Standards CSS on the existing HTML tree.
    Css {
        /// Selector expression.
        expression: String,
    },
    /// XPath 1.0; no extensions or external documents.
    Xpath {
        /// Selector expression.
        expression: String,
    },
}
impl SelectorV1 {
    /// Borrow the expression.
    #[must_use]
    pub fn expression(&self) -> &str {
        match self {
            Self::Css { expression } | Self::Xpath { expression } => expression,
        }
    }
}
/// Selection and pruning policy. Empty include keeps existing main-content logic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SelectorPolicyV1 {
    /// Included static elements.
    pub include: Vec<SelectorV1>,
    /// Excluded static elements and their descendants.
    pub exclude: Vec<SelectorV1>,
    /// Explicit read-more node selectors. Produce references only; never fetch in the parser.
    pub read_more: Vec<SelectorV1>,
    /// Prefix to namespace URI bindings. Unprefixed HTML names use HTML namespace.
    pub namespaces: BTreeMap<String, String>,
    /// Base for relative read-more targets; omission means [`ReadMoreBaseV1::Document`] and keeps
    /// the serialized policy unchanged.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_more_base: Option<ReadMoreBaseV1>,
}
impl SelectorPolicyV1 {
    /// Check bounded source sizes; compilation checks syntax.
    /// # Errors
    /// Returns invalid policy for excessive expressions or namespace bindings.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self
            .include
            .len()
            .saturating_add(self.exclude.len())
            .saturating_add(self.read_more.len())
            > 64
            || self
                .include
                .iter()
                .chain(&self.exclude)
                .chain(&self.read_more)
                .any(|s| s.expression().is_empty() || s.expression().len() > MAX_EXPRESSION_BYTES)
            || self.namespaces.len() > 32
            || self
                .namespaces
                .iter()
                .any(|(k, v)| k.is_empty() || k.len() > 64 || v.len() > 1024)
        {
            return Err(invalid("selector policy exceeds bounds"));
        }
        Ok(())
    }
}
/// Element a nested field group's rules start from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum FieldSourceV1 {
    /// The group's base element.
    Context,
    /// The nearest following element sibling, optionally restricted to a selector match.
    NextSibling {
        /// Sibling must also be selected by this selector (evaluated on the whole document).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<SelectorV1>,
    },
    /// The nearest preceding element sibling, optionally restricted to a selector match.
    PreviousSibling {
        /// Sibling must also be selected by this selector (evaluated on the whole document).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<SelectorV1>,
    },
}
/// Base URL used to resolve relative read-more targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReadMoreBaseV1 {
    /// Honor a document `base` element, the default.
    Document,
    /// Resolve against the page URL the document was acquired from, ignoring any `base` element.
    Page,
}
/// Selected-node projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum FieldExtractionV1 {
    /// XPath string value or element text.
    Text,
    /// Element attribute.
    Attribute {
        /// Local attribute name.
        name: String,
    },
    /// Serialized element markup.
    Html,
    /// Every attribute of the element as a name to value object.
    Attributes,
    /// Nested object built from the field's own `fields`; carries no value of its own.
    Group,
}
/// Number of output values, checked before any joining transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FieldCardinalityV1 {
    /// Exactly one selected value.
    One,
    /// Zero or more selected values.
    Many,
}
/// Ordered pure transformations; URL resolution does not fetch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum FieldTransformV1 {
    /// Strip Unicode edge whitespace.
    Trim,
    /// Collapse Unicode whitespace.
    NormalizeWhitespace,
    /// Resolve against acquired document base URL.
    ResolveUrl,
    /// Parse ISO calendar date or RFC3339 datetime, preserving precision.
    IsoDate,
    /// Parse a finite JSON number, no locale guessing.
    Number,
    /// Join string values.
    Join {
        /// Literal separator.
        separator: String,
    },
    /// Stable first-occurrence deduplication.
    Dedupe,
    /// Collapse whitespace, remove control and zero-width characters, then trim.
    Clean,
    /// Safe-regex projection of each string: the capture `group` of the first match, or of every
    /// match when `all` is set. Values without a match are dropped.
    Regex {
        /// Pattern in the bounded linear-time regex dialect (no backreferences or lookaround).
        pattern: String,
        /// Capture group, zero for the whole match.
        #[serde(default)]
        group: usize,
        /// Keep every match instead of only the first.
        #[serde(default)]
        all: bool,
    },
    /// Versioned built-in pattern (for example `email`) applied like `Regex`.
    Builtin {
        /// Name from the built-in pattern table.
        name: String,
        /// Keep every match instead of only the first.
        #[serde(default)]
        all: bool,
    },
    /// Parse each string as bounded JSON.
    JsonParse,
    /// Keep at most the first `count` values of a list.
    Limit {
        /// Number of values retained, one through 10,000.
        count: usize,
    },
}
/// One field compiled before evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ItemFieldV1 {
    /// Unique output key.
    pub name: String,
    /// Union of selectors; duplicate nodes removed in document order.
    pub selectors: Vec<SelectorV1>,
    /// Projection.
    pub extraction: FieldExtractionV1,
    /// Selection cardinality.
    pub cardinality: FieldCardinalityV1,
    /// Applied in listed order.
    #[serde(default)]
    pub transforms: Vec<FieldTransformV1>,
    /// Missing value fails field quality.
    #[serde(default)]
    pub required: bool,
    /// Caller-provided default; always labeled defaulted.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_default"
    )]
    pub default: Option<serde_json::Value>,
    /// Nested field group: when non-empty the `selectors` select base elements and each nested
    /// rule is evaluated relative to one base element. Requires the `group` projection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<ItemFieldV1>,
    /// Element the nested selectors start from, relative to the group's base element.
    /// Valid only on nested fields; absence means the base element itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<FieldSourceV1>,
}

fn present_default<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}
/// Digest-pinned, purely local JSON-schema registry and declarative field recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ItemLoaderV1 {
    /// Exactly one.
    pub version: u16,
    /// Ordered field rules, at most 64.
    pub fields: Vec<ItemFieldV1>,
    /// XPath namespace bindings.
    pub namespaces: BTreeMap<String, String>,
    /// Optional root schema registry key (64 lowercase BLAKE3 hexadecimal digits).
    pub schema: Option<String>,
    /// Digest::of("crawlx.item.schema.v1", serde_json bytes) keys. References are registry:<digest> or # pointers.
    pub schemas: BTreeMap<String, serde_json::Value>,
}
impl Default for ItemLoaderV1 {
    fn default() -> Self {
        Self {
            version: 1,
            fields: Vec::new(),
            namespaces: BTreeMap::new(),
            schema: None,
            schemas: BTreeMap::new(),
        }
    }
}
impl ItemLoaderV1 {
    /// Validate structural source bounds before compilation.
    /// # Errors
    /// Returns invalid policy for unsupported version or excessive field/schema sizes.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.version != 1
            || self.fields.len() > 64
            || self.schemas.len() > 32
            || self.namespaces.len() > 32
            || self
                .namespaces
                .iter()
                .any(|(k, v)| k.is_empty() || k.len() > 64 || v.len() > 1024)
        {
            return Err(invalid("item loader version or collection limit invalid"));
        }
        let mut total = 0usize;
        validate_fields(&self.fields, 1, &mut total)?;
        bounded_json_len(&self.schemas, 262_144)?;
        Ok(())
    }
}
/// Deepest nesting of field groups, counting the top level as one.
pub const MAX_FIELD_DEPTH: usize = 4;
/// Most field rules in a recipe, including nested ones.
pub const MAX_TOTAL_FIELDS: usize = 256;
fn validate_fields(fields: &[ItemFieldV1], depth: usize, total: &mut usize) -> Result<(), CoreError> {
    let selector_invalid =
        |s: &SelectorV1| s.expression().is_empty() || s.expression().len() > MAX_EXPRESSION_BYTES;
    let mut names = std::collections::BTreeSet::new();
    for f in fields {
        *total = total.saturating_add(1);
        let group = matches!(&f.extraction, FieldExtractionV1::Group);
        if *total > MAX_TOTAL_FIELDS
            || f.name.is_empty()
            || f.name.len() > 64
            || !names.insert(&f.name)
            || f.selectors.is_empty()
            || f.selectors.len() > 16
            || f.transforms.len() > 16
            || f.selectors.iter().any(selector_invalid)
            || matches!(&f.extraction, FieldExtractionV1::Attribute { name } if name.is_empty() || name.len()>128)
            || f.transforms.iter().any(|t| match t {
                FieldTransformV1::Join { separator } => separator.len() > 1024,
                FieldTransformV1::Regex { pattern, .. } => pattern.is_empty() || pattern.len() > 512,
                FieldTransformV1::Builtin { name, .. } => name.is_empty() || name.len() > 64,
                FieldTransformV1::Limit { count } => !(1..=10_000).contains(count),
                _ => false,
            })
            || group != !f.fields.is_empty()
            || ((group || matches!(&f.extraction, FieldExtractionV1::Attributes)) && !f.transforms.is_empty())
            || (!f.fields.is_empty() && depth >= MAX_FIELD_DEPTH)
            || f.fields.len() > 64
            || match &f.source {
                None => false,
                Some(FieldSourceV1::Context) => depth < 2,
                Some(
                    FieldSourceV1::NextSibling { selector } | FieldSourceV1::PreviousSibling { selector },
                ) => depth < 2 || selector.as_ref().is_some_and(selector_invalid),
            }
        {
            return Err(invalid("item loader field limit invalid"));
        }
        if let Some(default) = &f.default {
            bounded_json_len(default, 65_536)?;
        }
        validate_fields(&f.fields, depth + 1, total)?;
    }
    Ok(())
}

/// Count JSON bytes without allocating a serialized copy, stopping at the caller ceiling.
///
/// # Errors
/// Returns invalid policy as soon as serialized output would exceed `limit`, or serialization fails.
pub fn bounded_json_len(value: &impl Serialize, limit: usize) -> Result<usize, CoreError> {
    struct Counter {
        bytes: usize,
        limit: usize,
    }
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next = self
                .bytes
                .checked_add(bytes.len())
                .filter(|next| *next <= self.limit)
                .ok_or_else(|| std::io::Error::other("selector JSON byte limit exceeded"))?;
            self.bytes = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { bytes: 0, limit };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| invalid("serialized selector data exceeds byte limit"))?;
    Ok(counter.bytes)
}
/// Field quality never hides defaults or malformed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FieldQualityV1 {
    /// Values selected and transformed.
    Selected,
    /// Explicit caller default used.
    Defaulted,
    /// No selected source value and no explicit caller default.
    Missing,
    /// Singular rule selected more than one value.
    CardinalityMismatch,
    /// Pure transform rejected input.
    MalformedTransform,
    /// Final privacy projection removed data or rejected its post-projection type.
    Redacted,
}
/// One field's retained quality and value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct FieldOutcomeV1 {
    /// Output key.
    pub name: String,
    /// Explicit quality.
    pub quality: FieldQualityV1,
    /// Selected/defaulted data, absent on field failure.
    pub value: Option<serde_json::Value>,
    /// Privacy projection changed or omitted content; default provenance remains explicit.
    #[serde(default)]
    pub redacted: bool,
    /// Nested group fields: one ordered outcome list per base element, empty for plain fields.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<Vec<FieldOutcomeV1>>,
}
/// Complete typed item result, independent of network or persistence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ItemOutcomeV1 {
    /// Field outcomes in recipe order.
    pub fields: Vec<FieldOutcomeV1>,
    /// Projected object containing successful/defaulted fields.
    pub item: serde_json::Value,
    /// False if required/cardinality/transform/schema quality fails.
    pub valid: bool,
    /// Root schema result; None when no schema requested.
    pub schema_valid: Option<bool>,
}
impl FieldOutcomeV1 {
    /// Construct a field result.
    #[must_use]
    pub fn new(name: String, quality: FieldQualityV1, value: Option<serde_json::Value>) -> Self {
        Self {
            name,
            quality,
            value,
            redacted: false,
            groups: Vec::new(),
        }
    }
}
impl ItemOutcomeV1 {
    /// Construct evaluated item quality.
    #[must_use]
    pub fn new(
        fields: Vec<FieldOutcomeV1>,
        item: serde_json::Value,
        valid: bool,
        schema_valid: Option<bool>,
    ) -> Self {
        Self {
            fields,
            item,
            valid,
            schema_valid,
        }
    }
}

/// Caller-provided authority namespace. A descriptor never supplies request authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct SelectorScopeV1 {
    /// Tenant identifier, sourced from authenticated caller.
    pub tenant: String,
    /// Principal/identity class, sourced from authenticated caller.
    pub principal: String,
    /// Canonical acquired origin.
    pub origin: String,
    /// Source catalog namespace.
    pub source: String,
    /// Schema namespace and version.
    pub schema: String,
}
impl SelectorScopeV1 {
    /// Construct explicit caller scope; validation occurs before descriptor use.
    #[must_use]
    pub fn new(tenant: String, principal: String, origin: String, source: String, schema: String) -> Self {
        Self {
            tenant,
            principal,
            origin,
            source,
            schema,
        }
    }
    /// Validate bounded scope strings.
    /// # Errors
    /// Returns invalid policy when any namespace is empty or oversized.
    pub fn validate(&self) -> Result<(), CoreError> {
        if [
            &self.tenant,
            &self.principal,
            &self.origin,
            &self.source,
            &self.schema,
        ]
        .iter()
        .any(|s| s.is_empty() || s.len() > 1024)
        {
            return Err(invalid("invalid adaptive selector scope"));
        }
        Ok(())
    }
}
/// Sanitized structural features, not page text, URLs, IDs or action identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct StructuralDescriptorV1 {
    /// Local element tag.
    pub tag: String,
    /// Parent tag.
    pub parent_tag: Option<String>,
    /// Grandparent tag.
    pub grandparent_tag: Option<String>,
    /// Sorted local attribute names only; no values.
    pub attribute_names: Vec<String>,
    /// Zero-based element sibling position.
    pub sibling_index: usize,
}
impl StructuralDescriptorV1 {
    /// Construct sanitized features; use the relocation engine to validate bounds.
    #[must_use]
    pub fn new(
        tag: String,
        parent_tag: Option<String>,
        grandparent_tag: Option<String>,
        attribute_names: Vec<String>,
        sibling_index: usize,
    ) -> Self {
        Self {
            tag,
            parent_tag,
            grandparent_tag,
            attribute_names,
            sibling_index,
        }
    }
}
/// Versioned adaptive extraction descriptor. Persistence additionally requires retention permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AdaptiveSelectorSpecV1 {
    /// Exactly one.
    pub version: u16,
    /// Stable caller-assigned selector identifier.
    pub selector_id: String,
    /// Tenant/principal/origin/source/schema authority namespace.
    pub scope: SelectorScopeV1,
    /// Structural feature snapshot.
    pub descriptor: StructuralDescriptorV1,
    /// Minimum fixed-point match score, 0 through 1000.
    pub threshold: u16,
    /// Required score advantage over runner-up; at least one.
    pub runner_up_margin: u16,
    /// Maximum scanned elements, at most 10,000.
    pub max_candidates: usize,
}
impl AdaptiveSelectorSpecV1 {
    /// Construct a descriptor with conservative recovery defaults.
    #[must_use]
    pub fn new(selector_id: String, scope: SelectorScopeV1, descriptor: StructuralDescriptorV1) -> Self {
        Self {
            version: 1,
            selector_id,
            scope,
            descriptor,
            threshold: 800,
            runner_up_margin: 100,
            max_candidates: 1000,
        }
    }
    /// Validate all serialized bounds before matching or storage.
    /// # Errors
    /// Returns invalid policy for unsupported version or malformed structural data.
    pub fn validate(&self) -> Result<(), CoreError> {
        self.scope.validate()?;
        let d = &self.descriptor;
        let name = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':'))
        };
        if self.version != 1
            || self.selector_id.is_empty()
            || self.selector_id.len() > 128
            || self.threshold > 1000
            || self.runner_up_margin == 0
            || self.runner_up_margin > 1000
            || !(1..=10_000).contains(&self.max_candidates)
            || !name(&d.tag)
            || d.parent_tag.as_ref().is_some_and(|s| !name(s))
            || d.grandparent_tag.as_ref().is_some_and(|s| !name(s))
            || d.attribute_names.len() > 64
            || d.attribute_names.iter().any(|s| !name(s))
            || d.attribute_names.windows(2).any(|p| p[0] >= p[1])
        {
            return Err(invalid("invalid adaptive selector descriptor"));
        }
        Ok(())
    }
}
fn invalid(reason: &str) -> CoreError {
    CoreError::Invalid {
        field: "extract.content.selectors",
        reason: reason.into(),
    }
}
