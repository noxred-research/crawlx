//! Retain only the Unicode mappings required by surviving native glyph codes.

use std::collections::BTreeSet;

use lopdf::content::{Content, Operation};
use lopdf::{Dictionary, Document, Encoding, Object, ObjectId, StringFormat};

use super::{bound_font_cmap, map_lopdf, nesting, ContentWork};
use crate::parse::ParseError;

pub(super) fn cmap_id(doc: &Document, font: &Dictionary) -> Result<Option<ObjectId>, ParseError> {
    let Ok(value) = font.get(b"ToUnicode") else {
        return Ok(None);
    };
    let (id, object) = doc.dereference(value).map_err(map_lopdf)?;
    if !matches!(object, Object::Stream(_)) || id.is_none() {
        return Err(ParseError::corrupt(
            "pdf",
            "font Unicode map must be an indirect stream",
        ));
    }
    Ok(id)
}

pub(super) fn font_encoding<'a>(
    doc: &'a Document,
    font: &'a Dictionary,
    limit: usize,
) -> Result<Encoding<'a>, ParseError> {
    if let Some(id) = cmap_id(doc, font)? {
        // PDF text strings use ToUnicode when present, even when a simple font also has
        // a WinAnsi Encoding entry. Do not let that entry conceal Unicode metadata.
        return unicode_encoding(doc, id, limit);
    }
    font.get_font_encoding_with_limit(doc, limit).map_err(map_lopdf)
}

fn unicode_encoding(doc: &Document, id: ObjectId, limit: usize) -> Result<Encoding<'static>, ParseError> {
    let mut font = Dictionary::new();
    font.set("Type", "Font");
    font.set("ToUnicode", Object::Reference(id));
    let encoding = font.get_font_encoding_with_limit(doc, limit).map_err(map_lopdf)?;
    match encoding {
        Encoding::UnicodeMapEncoding(map) => Ok(Encoding::UnicodeMapEncoding(map)),
        _ => Err(ParseError::corrupt("pdf", "font Unicode map is unsupported")),
    }
}

pub(super) fn font_cmaps(doc: &Document) -> Result<BTreeSet<ObjectId>, ParseError> {
    let mut ids = BTreeSet::new();
    for object in doc.objects.values() {
        collect_cmaps(doc, object, 0, &mut ids)?;
    }
    Ok(ids)
}

fn collect_cmaps(
    doc: &Document,
    object: &Object,
    depth: usize,
    ids: &mut BTreeSet<ObjectId>,
) -> Result<(), ParseError> {
    nesting(depth)?;
    match object {
        Object::Dictionary(dict) => {
            if dict.has_type(b"Font") {
                if let Some(id) = cmap_id(doc, dict)? {
                    ids.insert(id);
                }
            }
            for (_, value) in dict {
                collect_cmaps(doc, value, depth.saturating_add(1), ids)?;
            }
        }
        Object::Array(values) => {
            for value in values {
                collect_cmaps(doc, value, depth.saturating_add(1), ids)?;
            }
        }
        Object::Stream(stream) => {
            for (_, value) in &stream.dict {
                collect_cmaps(doc, value, depth.saturating_add(1), ids)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn rewrite_cmaps(
    doc: &mut Document,
    work: &mut ContentWork,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
) -> Result<(), ParseError> {
    let mut replacements = Vec::new();
    for (id, codes) in &work.cmaps {
        let mut font = Dictionary::new();
        font.set("Type", "Font");
        font.set("ToUnicode", Object::Reference(*id));
        let max_glyph_bytes = bound_font_cmap(doc, &font, &mut work.budget, &mut work.objects_remaining)?;
        let encoding = unicode_encoding(doc, *id, work.budget.limit)?;
        let stream = doc
            .get_object(*id)
            .and_then(Object::as_stream)
            .map_err(map_lopdf)?;
        let (mut content, objects, bytes) = Content::decode_bounded_with_usage(
            &stream.content,
            work.objects_remaining,
            work.budget.remaining,
        )
        .map_err(map_lopdf)?;
        work.objects_remaining = work
            .objects_remaining
            .checked_sub(objects)
            .ok_or_else(|| ParseError::corrupt("pdf", "CMap parser exceeded object budget"))?;
        work.budget.charge(bytes)?;
        content.operations.retain(|operation| {
            !matches!(
                operation.operator.as_str(),
                "beginbfchar" | "endbfchar" | "beginbfrange" | "endbfrange"
            )
        });
        let end = content
            .operations
            .iter()
            .position(|operation| operation.operator == "endcmap")
            .ok_or_else(|| ParseError::corrupt("pdf", "unterminated font Unicode map"))?;
        let mut mappings = Vec::new();
        let mut entries = Vec::new();
        for code in codes {
            work.budget.charge(max_glyph_bytes.saturating_mul(8))?;
            let original = encoding.bytes_to_string(code).map_err(map_lopdf)?;
            let clean = redact(&original)?;
            work.budget
                .charge(clean.len().saturating_mul(4).saturating_add(256))?;
            let target = clean
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<_>>();
            entries.push(Object::String(code.clone(), StringFormat::Hexadecimal));
            entries.push(Object::String(target, StringFormat::Hexadecimal));
            if entries.len() == 200 {
                append_mappings(&mut mappings, &mut entries)?;
            }
        }
        append_mappings(&mut mappings, &mut entries)?;
        content.operations.splice(end..end, mappings);
        let bytes = content.encode().map_err(map_lopdf)?;
        work.budget.charge(bytes.len())?;
        replacements.push((*id, bytes));
    }
    for (id, bytes) in replacements {
        doc.get_object_mut(id)
            .and_then(Object::as_stream_mut)
            .map_err(map_lopdf)?
            .set_plain_content(bytes);
    }
    Ok(())
}

fn append_mappings(operations: &mut Vec<Operation>, entries: &mut Vec<Object>) -> Result<(), ParseError> {
    if entries.is_empty() {
        return Ok(());
    }
    let count = i64::try_from(entries.len() / 2)
        .map_err(|source| ParseError::corrupt_from("pdf", "too many Unicode mappings", source))?;
    operations.push(Operation::new("beginbfchar", vec![Object::Integer(count)]));
    operations.push(Operation::new("endbfchar", std::mem::take(entries)));
    Ok(())
}
