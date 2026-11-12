//! Translation of an exported struct-tag manifest into a versioned [`ItemLoaderV1`].
//!
//! A trusted exporter lists the tagged fields of a Go struct (the CSS selector and attribute tags
//! of the collector library's unmarshal helpers) as JSON. This module turns that list into the
//! declarative item recipe and reports, per field, whether it was translated. It never reads Go
//! source and has no notion of reflection: only the field kinds the recipe can express exactly are
//! translated.
//!
//! * `string` and `*string` select one value, `[]string` and `[]*string` any number of values;
//!   with an `attr` tag the value is that attribute, otherwise the element text;
//! * `struct` and `*struct` select one element and `[]struct`, `[]*struct` any number, with the
//!   nested tagged fields evaluated relative to each selected element.
//!
//! Every other Go type (numbers, booleans, maps, channels, functions, interfaces, arrays, named
//! types) and every field without a selector is reported as unsupported with the reason. An
//! unsupported field is never dropped or filled with its Go zero value: the translation yields no
//! loader at all while any field is unsupported, so a caller cannot mistake a partial recipe for the
//! struct it was exported from.

use crawlx_core::selectors::{ItemLoaderV1, MAX_EXPRESSION_BYTES};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Most tagged fields one struct level may carry; the recipe allows 64 per level.
pub const MAX_STRUCT_TAG_FIELDS: usize = 64;

/// One tagged field of an exported struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct StructTagFieldV1 {
    /// The Go field name; it becomes the key of the extracted item.
    pub name: String,
    /// The Go type as written (`string`, `*string`, `[]string`, `[]struct`, `map[string]string`).
    pub go_type: String,
    /// The CSS selector tag. A field without one is unsupported: Go leaves it at its zero value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    /// The attribute tag; absent selects the element text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr: Option<String>,
    /// The tagged fields of a struct type, relative to the selected element.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<StructTagFieldV1>,
}

/// An exported struct: the tagged fields of one Go type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct StructTagManifestV1 {
    /// Exactly one.
    pub version: u16,
    /// The tagged fields in declaration order.
    pub fields: Vec<StructTagFieldV1>,
}

/// What became of one field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StructTagRowV1 {
    /// Dotted path of the field (`authors.name`).
    pub path: String,
    /// True when the field is part of the loader.
    pub translated: bool,
    /// Why the field was or was not translated.
    pub reason: &'static str,
}

/// The loader (only when every field translated) and one row per field, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StructTagTranslation {
    /// The versioned recipe; `None` while any row is unsupported.
    pub loader: Option<ItemLoaderV1>,
    /// One row per field, nested fields after their parent.
    pub rows: Vec<StructTagRowV1>,
}

impl StructTagTranslation {
    /// True when every field translated.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.loader.is_some()
    }
}

/// How a supported Go type maps onto the recipe.
enum Kind {
    Scalar { many: bool },
    Struct { many: bool },
}

/// The kind of a supported type, or the reason a type is not translated.
fn classify(go_type: &str) -> Result<Kind, &'static str> {
    let text = go_type.trim();
    let (many, element) = match text.strip_prefix("[]") {
        Some(element) => (true, element),
        None => (false, text),
    };
    let element = element.strip_prefix('*').unwrap_or(element);
    match element {
        "string" => Ok(Kind::Scalar { many }),
        "struct" => Ok(Kind::Struct { many }),
        _ if text.contains("map[") => {
            Err("a Go map has no counterpart in a field recipe and is not zero-filled")
        }
        _ if text.starts_with("chan") || text.starts_with("<-chan") || element.starts_with("chan") => {
            Err("a Go channel has no counterpart in a field recipe and is not zero-filled")
        }
        _ if text.starts_with("func") || element.starts_with("func") => {
            Err("a Go function value has no counterpart in a field recipe and is not zero-filled")
        }
        _ if element == "any" || element.starts_with("interface") => {
            Err("an interface field has no static type to convert to and is not zero-filled")
        }
        _ if text.starts_with('[') && !text.starts_with("[]") => {
            Err("a fixed-size Go array is not translated and is not zero-filled")
        }
        _ if matches!(
            element,
            "bool"
                | "byte"
                | "rune"
                | "int"
                | "int8"
                | "int16"
                | "int32"
                | "int64"
                | "uint"
                | "uint8"
                | "uint16"
                | "uint32"
                | "uint64"
                | "uintptr"
                | "float32"
                | "float64"
                | "complex64"
                | "complex128"
        ) =>
        {
            Err("Go's numeric and boolean conversions (and their parse errors) are not reproduced; the text is not converted")
        }
        _ => Err("a named or unknown Go type cannot be translated; export it as string, []string or struct"),
    }
}

fn selector_of(field: &StructTagFieldV1) -> Result<Value, &'static str> {
    let expression = field
        .selector
        .as_deref()
        .ok_or("no selector tag: Go leaves an untagged field at its zero value, which is not imported")?;
    if expression.trim().is_empty() || expression.len() > MAX_EXPRESSION_BYTES {
        return Err("the selector tag is empty or longer than the recipe allows");
    }
    Ok(json!({ "kind": "css", "expression": expression }))
}

/// What a translated field becomes: its selector, extraction, cardinality and nested fields, as
/// the recipe's JSON (the recipe types are deserialized once, at the end, and validated there).
type Translated = (Value, Value, bool, Vec<Value>);

fn translate_kind(
    field: &StructTagFieldV1,
    path: &str,
    rows: &mut Vec<StructTagRowV1>,
) -> Result<Translated, &'static str> {
    let kind = classify(&field.go_type)?;
    let selector = selector_of(field)?;
    match kind {
        Kind::Scalar { many } => {
            if !field.fields.is_empty() {
                return Err("nested fields are only valid on a struct type");
            }
            let extraction = match field.attr.as_deref() {
                None => json!({ "kind": "text" }),
                Some("") => return Err("the attribute tag is empty"),
                Some(name) => json!({ "kind": "attribute", "name": name }),
            };
            Ok((selector, extraction, many, Vec::new()))
        }
        Kind::Struct { many } => {
            if field.attr.is_some() {
                return Err("an attribute tag on a struct field selects no value");
            }
            if field.fields.is_empty() {
                return Err("a struct without tagged fields has nothing to extract");
            }
            let mut nested = Vec::with_capacity(field.fields.len());
            let mut complete = true;
            for child in &field.fields {
                match translate_field(child, &format!("{path}.{}", child.name), rows) {
                    Some(item) => nested.push(item),
                    None => complete = false,
                }
            }
            if complete {
                Ok((selector, json!({ "kind": "group" }), many, nested))
            } else {
                Err("a nested field is unsupported")
            }
        }
    }
}

fn translate_field(field: &StructTagFieldV1, path: &str, rows: &mut Vec<StructTagRowV1>) -> Option<Value> {
    let row = rows.len();
    rows.push(StructTagRowV1 {
        path: path.to_owned(),
        translated: false,
        reason: "",
    });
    match translate_kind(field, path, rows) {
        Ok((selector, extraction, many, nested)) => {
            rows[row].translated = true;
            rows[row].reason = "translated to a bounded CSS selector projection; whitespace and multi-match handling follow the native extraction, not the Go library's";
            let mut item = json!({
                "name": field.name,
                "selectors": [selector],
                "extraction": extraction,
                "cardinality": if many { "many" } else { "one" },
            });
            if !nested.is_empty() {
                item["fields"] = Value::Array(nested);
            }
            Some(item)
        }
        Err(reason) => {
            rows[row].reason = reason;
            None
        }
    }
}

/// Translate `manifest`; see the [module documentation](self) for what is supported.
///
/// An unsupported version, a field list over [`MAX_STRUCT_TAG_FIELDS`], a duplicate field name or
/// a recipe the native bounds refuse is reported as a row too, never as an error: the caller
/// always gets the full list of reasons.
#[must_use]
pub fn translate_struct_tags(manifest: &StructTagManifestV1) -> StructTagTranslation {
    let mut rows = Vec::new();
    if manifest.version != 1 {
        rows.push(StructTagRowV1 {
            path: String::new(),
            translated: false,
            reason: "unsupported struct-tag manifest version",
        });
        return StructTagTranslation { loader: None, rows };
    }
    if manifest.fields.is_empty() || manifest.fields.len() > MAX_STRUCT_TAG_FIELDS {
        rows.push(StructTagRowV1 {
            path: String::new(),
            translated: false,
            reason: "a struct needs between one and 64 tagged fields",
        });
        return StructTagTranslation { loader: None, rows };
    }
    let mut fields = Vec::with_capacity(manifest.fields.len());
    let mut complete = true;
    for field in &manifest.fields {
        match translate_field(field, &field.name, &mut rows) {
            Some(item) => fields.push(item),
            None => complete = false,
        }
    }
    if !complete {
        return StructTagTranslation { loader: None, rows };
    }
    let loader = serde_json::from_value::<ItemLoaderV1>(json!({ "version": 1, "fields": fields }))
        .ok()
        .filter(|loader| loader.validate().is_ok());
    let Some(loader) = loader else {
        // a duplicate name, a name or nesting beyond the recipe bounds: no single row can be blamed
        for row in &mut rows {
            row.translated = false;
            row.reason = "the recipe exceeds the native item loader bounds (duplicate or over-long names, nesting depth, field count)";
        }
        return StructTagTranslation { loader: None, rows };
    };
    StructTagTranslation {
        loader: Some(loader),
        rows,
    }
}
