//! Exact-byte exporters for approved generic JSON-object items (JSON, JSONL, CSV, XML).
//!
//! Output is deterministic: JSON object members and XML fields are written in sorted key order,
//! CSV columns are either sorted or the caller's explicit column list. The behaviors that
//! spreadsheet and XML consumers care about are explicit options rather than implicit defaults:
//!
//! * CSV cells that a spreadsheet would execute as a formula are prefix-escaped with `'`
//!   ([`CsvFormulaPolicy::PrefixEscape`]) or make the whole item fail before any byte is written
//!   ([`CsvFormulaPolicy::Reject`]).
//! * XML 1.0 cannot represent most control characters, even as character references; they are
//!   rejected ([`XmlControlPolicy::Reject`]) or replaced by U+FFFD ([`XmlControlPolicy::Replace`]).
//! * XML strings are entity-escaped, or written as CDATA sections ([`XmlTextMode::Cdata`]).
//!
//! Every limit is checked before the first output byte.

use crate::serialize::{
    csv_field, csv_formula_trigger, valid_xml_scalars, xml_text_with, ArticleWriteError, ItemFormat,
};
use serde_json::Value;
use std::borrow::Cow;
use std::io::Write;

const MAX_FIELDS: usize = 256;
const MAX_DEPTH: u16 = 32;

/// What to do with a CSV cell that spreadsheet software would evaluate as a formula.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum CsvFormulaPolicy {
    /// Prefix the cell with `'` (the cell text is otherwise unchanged).
    #[default]
    PrefixEscape,
    /// Fail with [`ArticleWriteError::CsvFormula`] before writing anything.
    Reject,
}

/// What to do with scalars XML 1.0 cannot represent (most C0 controls, U+FFFE, U+FFFF).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum XmlControlPolicy {
    /// Fail with [`ArticleWriteError::InvalidXmlScalar`] before writing anything.
    #[default]
    Reject,
    /// Write U+FFFD in place of each forbidden scalar.
    Replace,
}

/// How XML string values are written.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum XmlTextMode {
    /// Entity-escape `& < > " '` and write tab, line feed and carriage return as references.
    #[default]
    Escaped,
    /// Write a CDATA section, splitting any `]]>` across two sections. Strings containing a
    /// carriage return stay entity-escaped because a CDATA section would lose it to line-end
    /// normalization. Field names are always escaped.
    Cdata,
}

/// Explicit exporter policies; the default reproduces [`crate::serialize::write_item`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ItemExportOptions {
    /// Formula-cell policy for CSV.
    pub csv_formula: CsvFormulaPolicy,
    /// Forbidden-scalar policy for XML.
    pub xml_control: XmlControlPolicy,
    /// String rendering for XML.
    pub xml_text: XmlTextMode,
    /// Explicit CSV column order. Fields not listed are not exported and listed fields the item
    /// lacks are written as an empty unquoted cell (an empty string is `""`, `null` is `"null"`).
    /// `None` exports every field in sorted order.
    pub csv_columns: Option<Vec<String>>,
    /// Write the CSV header line (turn off when appending rows under an existing header).
    pub csv_header: bool,
}

impl Default for ItemExportOptions {
    fn default() -> Self {
        Self {
            csv_formula: CsvFormulaPolicy::default(),
            xml_control: XmlControlPolicy::default(),
            xml_text: XmlTextMode::default(),
            csv_columns: None,
            csv_header: true,
        }
    }
}

fn limit(reason: &'static str) -> ArticleWriteError {
    std::io::Error::other(reason).into()
}

fn sorted(fields: &serde_json::Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut sorted: Vec<_> = fields.iter().collect();
    sorted.sort_unstable_by_key(|(name, _)| *name);
    sorted
}

/// Replace or reject forbidden XML scalars; borrowed when the value is already valid.
fn xml_clean(value: &str, policy: XmlControlPolicy) -> Result<Cow<'_, str>, ArticleWriteError> {
    if valid_xml_scalars(value) {
        return Ok(Cow::Borrowed(value));
    }
    match policy {
        XmlControlPolicy::Reject => Err(ArticleWriteError::InvalidXmlScalar),
        XmlControlPolicy::Replace => Ok(Cow::Owned(
            value
                .chars()
                .map(|ch| {
                    if valid_xml_scalars(ch.encode_utf8(&mut [0; 4])) {
                        ch
                    } else {
                        '\u{fffd}'
                    }
                })
                .collect(),
        )),
    }
}

fn xml_string(
    out: &mut dyn Write,
    value: &str,
    options: &ItemExportOptions,
) -> Result<(), ArticleWriteError> {
    out.write_all(b"<string>")?;
    let replace = options.xml_control == XmlControlPolicy::Replace;
    if options.xml_text == XmlTextMode::Cdata && !value.contains('\r') {
        let clean = xml_clean(value, options.xml_control)?;
        out.write_all(b"<![CDATA[")?;
        out.write_all(clean.replace("]]>", "]]]]><![CDATA[>").as_bytes())?;
        out.write_all(b"]]>")?;
    } else {
        xml_text_with(out, value, replace)?;
    }
    out.write_all(b"</string>")?;
    Ok(())
}

fn item_xml(
    out: &mut dyn Write,
    value: &Value,
    depth: u16,
    options: &ItemExportOptions,
) -> Result<(), ArticleWriteError> {
    if depth > MAX_DEPTH {
        return Err(limit("item XML depth limit"));
    }
    let replace = options.xml_control == XmlControlPolicy::Replace;
    match value {
        Value::Object(fields) => {
            out.write_all(b"<object>")?;
            for (name, value) in sorted(fields) {
                out.write_all(b"<field name=\"")?;
                xml_text_with(out, name, replace)?;
                out.write_all(b"\">")?;
                item_xml(out, value, depth.saturating_add(1), options)?;
                out.write_all(b"</field>")?;
            }
            out.write_all(b"</object>")?;
        }
        Value::Array(items) => {
            out.write_all(b"<array>")?;
            for item in items {
                out.write_all(b"<entry>")?;
                item_xml(out, item, depth.saturating_add(1), options)?;
                out.write_all(b"</entry>")?;
            }
            out.write_all(b"</array>")?;
        }
        Value::String(value) => xml_string(out, value, options)?,
        Value::Number(value) => write!(out, "<number>{value}</number>")?,
        Value::Bool(value) => write!(out, "<boolean>{value}</boolean>")?,
        Value::Null => out.write_all(b"<null/>")?,
    }
    Ok(())
}

/// Compact JSON with object members in sorted key order, independent of the map implementation.
fn json_sorted(out: &mut dyn Write, value: &Value) -> Result<(), ArticleWriteError> {
    match value {
        Value::Object(fields) => {
            out.write_all(b"{")?;
            for (index, (name, value)) in sorted(fields).into_iter().enumerate() {
                if index > 0 {
                    out.write_all(b",")?;
                }
                serde_json::to_writer(&mut *out, name)?;
                out.write_all(b":")?;
                json_sorted(out, value)?;
            }
            out.write_all(b"}")?;
        }
        Value::Array(items) => {
            out.write_all(b"[")?;
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.write_all(b",")?;
                }
                json_sorted(out, item)?;
            }
            out.write_all(b"]")?;
        }
        scalar => serde_json::to_writer(&mut *out, scalar)?,
    }
    Ok(())
}

/// Escapes `"` as `""` for JSON text embedded in a quoted CSV cell.
struct CsvJson<'a>(&'a mut dyn Write);

impl Write for CsvJson<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let mut start = 0;
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'"' {
                self.0.write_all(&bytes[start..=index])?;
                self.0.write_all(b"\"")?;
                start = index.saturating_add(1);
            }
        }
        self.0.write_all(&bytes[start..])?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

fn validate_item(
    value: &Value,
    depth: u8,
    nodes: &mut u32,
    xml_strict: bool,
) -> Result<(), ArticleWriteError> {
    *nodes = nodes.checked_add(1).ok_or_else(|| limit("item node limit"))?;
    if depth > 32 || *nodes > 100_000 {
        return Err(limit("item structural limit"));
    }
    match value {
        Value::Object(fields) => {
            if fields.len() > MAX_FIELDS {
                return Err(limit("item field limit"));
            }
            for (name, value) in fields {
                if name.len() > 16 * 1024 * 1024 {
                    return Err(limit("item key byte limit"));
                }
                if xml_strict && !valid_xml_scalars(name) {
                    return Err(ArticleWriteError::InvalidXmlScalar);
                }
                validate_item(value, depth.saturating_add(1), nodes, xml_strict)?;
            }
        }
        Value::Array(items) => {
            if items.len() > 100_000 {
                return Err(limit("item array limit"));
            }
            for value in items {
                validate_item(value, depth.saturating_add(1), nodes, xml_strict)?;
            }
        }
        Value::String(value) => {
            if value.len() > 16 * 1024 * 1024 {
                return Err(limit("item string limit"));
            }
            if xml_strict && !valid_xml_scalars(value) {
                return Err(ArticleWriteError::InvalidXmlScalar);
            }
        }
        _ => {}
    }
    Ok(())
}

struct ItemOutput<'a> {
    out: &'a mut dyn Write,
    remaining: usize,
}

impl Write for ItemOutput<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| std::io::Error::other("item output byte limit"))?;
        self.out.write_all(bytes)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.out.flush()
    }
}

/// CSV column names for one item: the explicit list, or the item's sorted field names.
fn csv_columns<'a>(
    fields: &'a serde_json::Map<String, Value>,
    options: &'a ItemExportOptions,
) -> Result<Vec<&'a str>, ArticleWriteError> {
    let Some(columns) = &options.csv_columns else {
        return Ok(sorted(fields)
            .into_iter()
            .map(|(name, _)| name.as_str())
            .collect());
    };
    if columns.is_empty() || columns.len() > MAX_FIELDS {
        return Err(limit("item CSV column limit"));
    }
    let mut seen = std::collections::BTreeSet::new();
    if columns.iter().any(|name| !seen.insert(name.as_str())) {
        return Err(limit("item CSV duplicate column"));
    }
    Ok(columns.iter().map(String::as_str).collect())
}

fn reject_formulas(
    fields: &serde_json::Map<String, Value>,
    columns: &[&str],
    header: bool,
) -> Result<(), ArticleWriteError> {
    let header_hit = header && columns.iter().any(|name| csv_formula_trigger(name));
    let cell_hit = columns
        .iter()
        .any(|name| matches!(fields.get(*name), Some(Value::String(value)) if csv_formula_trigger(value)));
    if header_hit || cell_hit {
        return Err(ArticleWriteError::CsvFormula);
    }
    Ok(())
}

/// Stream one approved item with explicit exporter policies.
///
/// JSON and JSONL are compact with sorted object members and end in `\n`; CSV is one optional
/// header line plus one row, `\n`-terminated; XML is a typed `<item version="1">` document.
/// Structural, size, scalar and policy violations fail before the first byte is written.
///
/// # Errors
/// Returns output/JSON errors, a non-object item, field-count, size or nesting bound violations,
/// [`ArticleWriteError::InvalidXmlScalar`] under [`XmlControlPolicy::Reject`] and
/// [`ArticleWriteError::CsvFormula`] under [`CsvFormulaPolicy::Reject`].
pub fn write_item_with(
    out: &mut dyn Write,
    item: &Value,
    format: ItemFormat,
    options: &ItemExportOptions,
) -> Result<(), ArticleWriteError> {
    let fields = item
        .as_object()
        .ok_or_else(|| std::io::Error::other("item serializer requires an object"))?;
    if fields.len() > MAX_FIELDS {
        return Err(limit("item serializer field limit"));
    }
    let mut nodes = 0;
    let xml_strict = matches!(format, ItemFormat::Xml) && options.xml_control == XmlControlPolicy::Reject;
    validate_item(item, 0, &mut nodes, xml_strict)?;
    let columns = if matches!(format, ItemFormat::Csv) {
        let columns = csv_columns(fields, options)?;
        if options.csv_formula == CsvFormulaPolicy::Reject {
            reject_formulas(fields, &columns, options.csv_header)?;
        }
        columns
    } else {
        Vec::new()
    };
    let mut bounded = ItemOutput {
        out,
        remaining: 16 * 1024 * 1024,
    };
    let out: &mut dyn Write = &mut bounded;
    match format {
        ItemFormat::Json | ItemFormat::Jsonl => json_sorted(out, item)?,
        ItemFormat::Csv => {
            if options.csv_header {
                for (index, name) in columns.iter().enumerate() {
                    if index > 0 {
                        out.write_all(b",")?;
                    }
                    csv_field(out, name)?;
                }
                out.write_all(b"\n")?;
            }
            for (index, name) in columns.iter().enumerate() {
                if index > 0 {
                    out.write_all(b",")?;
                }
                match fields.get(*name) {
                    None => {}
                    Some(Value::String(value)) => csv_field(out, value)?,
                    Some(value) => {
                        out.write_all(b"\"")?;
                        serde_json::to_writer(CsvJson(&mut *out), value)?;
                        out.write_all(b"\"")?;
                    }
                }
            }
        }
        ItemFormat::Xml => {
            out.write_all(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<item version=\"1\">")?;
            item_xml(out, item, 0, options)?;
            out.write_all(b"</item>")?;
        }
    }
    out.write_all(b"\n")?;
    Ok(())
}
