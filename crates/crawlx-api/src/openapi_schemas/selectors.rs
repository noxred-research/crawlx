//! Schemas for native bounded static selectors and declarative item extraction.
//! Mirrors crawlx_core::selectors serde contracts; request admission also checks UTF-8 byte budgets.
use schemars::JsonSchema;
use serde_json::Value;
use std::collections::BTreeMap;

/// A standards CSS or XPath 1.0 expression on acquired static content.
#[derive(JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Selector {
    /// CSS selects existing elements; no pseudo-element string rewriting.
    Css {
        /// At most 4096 UTF-8 bytes; invalid syntax fails admission.
        #[schemars(length(min = 1, max = 4096))]
        expression: String,
    },
    /// XPath 1.0 core syntax; no extensions, variables or external documents.
    Xpath {
        /// At most 4096 UTF-8 bytes, 512 AST nodes and one million shared operations.
        #[schemars(length(min = 1, max = 4096))]
        expression: String,
    },
}

/// Optional overlays on empty inclusion/exclusion and namespace defaults.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SelectorPolicy {
    /// Included elements. An explicit nonempty rule list matching nothing returns no body content.
    #[schemars(length(max = 64))]
    include: Option<Vec<Selector>>,
    /// Excluded elements and their subtrees. Combined include/exclude cap is 64 expressions.
    #[schemars(length(max = 64))]
    exclude: Option<Vec<Selector>>,
    /// Explicit read-more href/text nodes. Combined include/exclude/readMore cap is 64.
    /// Parser returns at most 32 HTTP(S) intents; worker scope/robots/governor remain authoritative.
    #[schemars(length(max = 64))]
    read_more: Option<Vec<Selector>>,
    /// At most 32 prefixes (64 bytes each), mapped to namespace URIs (1024 bytes each).
    #[schemars(extend("maxProperties" = 32))]
    namespaces: Option<BTreeMap<String, String>>,
}

/// Node projection. Attribute projection reads a local element attribute name.
#[derive(JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum FieldExtraction {
    Text,
    Attribute {
        #[schemars(length(min = 1, max = 128))]
        name: String,
    },
    Html,
}

/// Cardinality is checked before join/dedupe transforms.
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
pub(super) enum FieldCardinality {
    One,
    Many,
}

/// Ordered pure transformations. URL resolution never performs a fetch.
#[derive(JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum FieldTransform {
    Trim,
    NormalizeWhitespace,
    ResolveUrl,
    IsoDate,
    Number,
    Join {
        #[schemars(length(max = 1024))]
        separator: String,
    },
    Dedupe,
}

/// One required declarative field rule; names must be unique within the loader.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ItemField {
    #[schemars(length(min = 1, max = 64))]
    name: String,
    /// Unioned in static document order, with duplicate nodes removed.
    #[schemars(length(min = 1, max = 16))]
    selectors: Vec<Selector>,
    extraction: FieldExtraction,
    cardinality: FieldCardinality,
    #[schemars(length(max = 16))]
    transforms: Option<Vec<FieldTransform>>,
    /// Defaults to false.
    required: Option<bool>,
    /// Explicit caller data; emitted quality is defaulted, never fetched or inferred.
    default: Option<Value>,
}

/// Bounded offline item schema and field recipe; omission overlays version-one defaults.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ItemLoader {
    #[schemars(extend("const" = 1))]
    version: Option<u16>,
    #[schemars(length(max = 64))]
    fields: Option<Vec<ItemField>>,
    #[schemars(extend("maxProperties" = 32))]
    namespaces: Option<BTreeMap<String, String>>,
    /// Root digest key in schemas. BLAKE3 domain crawlx.item.schema.v1 over serde_json bytes.
    #[schemars(length(min = 64, max = 64), regex(pattern = "^[0-9a-f]{64}$"))]
    schema: Option<String>,
    /// At most 32 digest-pinned local schemas and 256 KiB serialized aggregate.
    /// References must be registry:<digest> or local JSON pointers. Cycles, remote refs,
    /// unsupported assertion vocabulary and malformed bounded regex patterns fail admission.
    #[schemars(extend("maxProperties" = 32))]
    schemas: Option<BTreeMap<String, Value>>,
}

/// Authenticated caller namespace. Page content never selects this authority.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SelectorScope {
    #[schemars(length(min = 1, max = 1024))]
    tenant: String,
    #[schemars(length(min = 1, max = 1024))]
    principal: String,
    #[schemars(length(min = 1, max = 1024))]
    origin: String,
    #[schemars(length(min = 1, max = 1024))]
    source: String,
    #[schemars(length(min = 1, max = 1024))]
    schema: String,
}

/// Sanitized structural features, not action identity or page text.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct StructuralDescriptor {
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[A-Za-z0-9_:-]+$"))]
    tag: String,
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[A-Za-z0-9_:-]+$"))]
    parent_tag: Option<String>,
    #[schemars(length(min = 1, max = 128), regex(pattern = "^[A-Za-z0-9_:-]+$"))]
    grandparent_tag: Option<String>,
    /// Sorted unique local names, never attribute values.
    #[schemars(length(max = 64))]
    attribute_names: Vec<String>,
    sibling_index: usize,
}

/// Pure adaptive descriptor. Durable storage requires separate caller retention permission.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AdaptiveSelectorSpec {
    #[schemars(extend("const" = 1))]
    version: u16,
    #[schemars(length(min = 1, max = 128))]
    selector_id: String,
    scope: SelectorScope,
    descriptor: StructuralDescriptor,
    /// Fixed-point score, not calibrated probability.
    #[schemars(range(min = 0, max = 1000))]
    threshold: u16,
    /// Minimum score advantage; equal decoys always abstain.
    #[schemars(range(min = 1, max = 1000))]
    runner_up_margin: u16,
    #[schemars(range(min = 1, max = 10000))]
    max_candidates: usize,
}
