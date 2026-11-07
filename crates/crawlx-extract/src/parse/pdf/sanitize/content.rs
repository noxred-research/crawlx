//! One text/provenance plane across page content, invoked Forms and annotation appearances.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::sync::Arc;

use lopdf::content::Content;
use lopdf::{Dictionary, Document, Encoding, Object, ObjectId};

use super::cmap::{cmap_id, font_encoding};
use super::{
    bound_font_cmap, check_limit, map_lopdf, nesting, removed_ranges, sanitize_object, ContentWork,
    MAX_GLYPHS,
};
use crate::parse::ParseError;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Source {
    node: usize,
    operation: usize,
    operand: usize,
    element: Option<usize>,
}

struct Glyph {
    source: Source,
    bytes: Range<usize>,
    text: Range<usize>,
    cmap: Option<ObjectId>,
    code: [u8; 4],
    width: usize,
}

struct Node {
    form: Option<ObjectId>,
    content: Content,
}

struct Page<'a> {
    nodes: BTreeMap<usize, Node>,
    next_node: usize,
    text: String,
    glyphs: Vec<Glyph>,
    work: &'a mut ContentWork,
}

#[derive(Clone)]
struct Font<'a> {
    encoding: Arc<Encoding<'a>>,
    max_glyph_bytes: usize,
    cmap: Option<ObjectId>,
}

pub(super) fn sanitize_content(
    doc: &Document,
    bytes: &[u8],
    resources: &Dictionary,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
    work: &mut ContentWork,
    appearances: &[ObjectId],
) -> Result<Vec<u8>, ParseError> {
    let mut page = Page {
        nodes: BTreeMap::new(),
        next_node: 0,
        text: String::new(),
        glyphs: Vec::new(),
        work,
    };
    let root = collect(doc, bytes, resources, None, 0, &mut page)?;
    for id in appearances {
        let stream = doc
            .get_object(*id)
            .and_then(Object::as_stream)
            .map_err(map_lopdf)?;
        let own = stream
            .dict
            .get_deref(b"Resources", doc)
            .and_then(Object::as_dict)
            .unwrap_or(resources);
        collect(doc, &stream.content, own, Some(*id), 0, &mut page)?;
    }
    // All invoked text contributes in paint order, rather than giving each Form its own
    // redaction universe. Glyph provenance still points at its original native operand.
    let removed = redaction_mask(&mut page, redact)?;
    for (index, glyph) in page.glyphs.iter().enumerate() {
        if removed[index] {
            continue;
        }
        if let Some(cmap) = glyph.cmap {
            let code = &glyph.code[..glyph.width];
            let used = page
                .work
                .cmaps
                .get_mut(&cmap)
                .ok_or_else(|| ParseError::corrupt("pdf", "missing font Unicode map provenance"))?;
            if !used.contains(code) {
                page.work.budget.charge(code.len().saturating_add(128))?;
                used.insert(code.to_vec());
            }
        }
    }
    let mut glyph_offset = 0;
    for group in page.glyphs.chunk_by(|left, right| left.source == right.source) {
        let source = group[0].source;
        let node = page
            .nodes
            .get_mut(&source.node)
            .ok_or_else(|| ParseError::corrupt("pdf", "missing text provenance"))?;
        let operand = &mut node.content.operations[source.operation].operands[source.operand];
        let value = if let Some(element) = source.element {
            &mut operand.as_array_mut().map_err(map_lopdf)?[element]
        } else {
            operand
        };
        if let Object::String(bytes, _) = value {
            let mut kept = None;
            let mut cursor = 0;
            for (index, glyph) in group.iter().enumerate() {
                if removed[glyph_offset + index] {
                    let kept = kept.get_or_insert_with(|| Vec::with_capacity(bytes.len()));
                    kept.extend_from_slice(&bytes[cursor..glyph.bytes.start]);
                    cursor = glyph.bytes.end;
                }
            }
            if let Some(mut kept) = kept {
                kept.extend_from_slice(&bytes[cursor..]);
                *bytes = kept;
            }
        }
        glyph_offset += group.len();
    }
    let mut root_bytes = None;
    for (id, mut node) in page.nodes {
        for operation in &mut node.content.operations {
            if !matches!(operation.operator.as_str(), "Tj" | "TJ" | "'" | "\"") {
                for operand in &mut operation.operands {
                    sanitize_object(operand, redact, 0)?;
                }
            }
        }
        let bytes = node.content.encode().map_err(map_lopdf)?;
        page.work.budget.charge(bytes.len())?;
        if let Some(form) = node.form {
            if page.work.forms.get(&form).is_some_and(|old| old != &bytes) {
                return Err(ParseError::corrupt(
                    "pdf",
                    "shared form has conflicting text redactions",
                ));
            }
            page.work.forms.insert(form, bytes);
        } else if id == root {
            root_bytes = Some(bytes);
        }
    }
    root_bytes.ok_or_else(|| ParseError::corrupt("pdf", "missing page content"))
}

fn collect(
    doc: &Document,
    bytes: &[u8],
    resources: &Dictionary,
    form: Option<ObjectId>,
    depth: usize,
    page: &mut Page<'_>,
) -> Result<usize, ParseError> {
    nesting(depth)?;
    page.work.budget.charge(bytes.len())?;
    page.work
        .budget
        .charge(std::mem::size_of::<Node>().saturating_mul(2))?;
    let node = page.next_node;
    page.next_node = page
        .next_node
        .checked_add(1)
        .ok_or_else(|| ParseError::corrupt("pdf", "content invocation count overflow"))?;
    check_limit("PDF content invocations", page.next_node, MAX_GLYPHS)?;
    let (content, objects, allocated) =
        Content::decode_bounded_with_usage(bytes, page.work.objects_remaining, page.work.budget.remaining)
            .map_err(map_lopdf)?;
    page.work.objects_remaining = page
        .work
        .objects_remaining
        .checked_sub(objects)
        .ok_or_else(|| ParseError::corrupt("pdf", "content parser exceeded object budget"))?;
    page.work.budget.charge(allocated)?;
    let fonts = resources.get_deref(b"Font", doc).and_then(Object::as_dict).ok();
    let mut font: Option<Font<'_>> = None;
    let mut stack = Vec::new();
    let mut loaded_fonts: BTreeMap<Vec<u8>, Font<'_>> = BTreeMap::new();
    for (index, operation) in content.operations.iter().enumerate() {
        match operation.operator.as_str() {
            "q" => {
                page.work.budget.charge(std::mem::size_of::<Option<Font<'_>>>())?;
                stack.push(font.clone());
            }
            "Q" => font = stack.pop().flatten(),
            "Tf" => {
                let name = operation
                    .operands
                    .first()
                    .and_then(|value| value.as_name().ok())
                    .ok_or_else(|| ParseError::corrupt("pdf", "missing text font"))?;
                if let Some(cached) = loaded_fonts.get(name) {
                    font = Some(cached.clone());
                    continue;
                }
                let dict = fonts
                    .and_then(|fonts| fonts.get_deref(name, doc).ok())
                    .and_then(|font| font.as_dict().ok())
                    .ok_or_else(|| ParseError::corrupt("pdf", "text font is unavailable"))?;
                let max_glyph_bytes =
                    bound_font_cmap(doc, dict, &mut page.work.budget, &mut page.work.objects_remaining)?;
                let loaded = Font {
                    encoding: Arc::new(font_encoding(doc, dict, page.work.budget.limit)?),
                    max_glyph_bytes,
                    cmap: cmap_id(doc, dict)?,
                };
                page.work
                    .budget
                    .charge(name.len().saturating_add(std::mem::size_of::<Font<'_>>()))?;
                loaded_fonts.insert(name.to_vec(), loaded.clone());
                font = Some(loaded);
            }
            "Tj" | "TJ" | "'" | "\"" => {
                let operand = operation
                    .operands
                    .len()
                    .checked_sub(1)
                    .ok_or_else(|| ParseError::corrupt("pdf", "missing text operand"))?;
                let font = font
                    .as_ref()
                    .ok_or_else(|| ParseError::corrupt("pdf", "text encoding is unavailable"))?;
                let source = Source {
                    node,
                    operation: index,
                    operand,
                    element: None,
                };
                match &operation.operands[operand] {
                    Object::String(bytes, _) => add_glyphs(bytes, font, source, page)?,
                    Object::Array(values) if operation.operator == "TJ" => {
                        for (element, value) in values.iter().enumerate() {
                            if let Object::String(bytes, _) = value {
                                add_glyphs(
                                    bytes,
                                    font,
                                    Source {
                                        element: Some(element),
                                        ..source
                                    },
                                    page,
                                )?;
                            }
                        }
                    }
                    _ => return Err(ParseError::corrupt("pdf", "invalid text operand")),
                }
            }
            "Do" => {
                let name = operation
                    .operands
                    .first()
                    .and_then(|value| value.as_name().ok())
                    .ok_or_else(|| ParseError::corrupt("pdf", "missing XObject name"))?;
                let objects = resources
                    .get_deref(b"XObject", doc)
                    .and_then(Object::as_dict)
                    .map_err(map_lopdf)?;
                let id = objects
                    .get(name)
                    .and_then(Object::as_reference)
                    .map_err(map_lopdf)?;
                let stream = doc
                    .get_object(id)
                    .and_then(Object::as_stream)
                    .map_err(map_lopdf)?;
                if stream.dict.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Form") {
                    let own = stream
                        .dict
                        .get_deref(b"Resources", doc)
                        .and_then(Object::as_dict)
                        .unwrap_or(resources);
                    collect(doc, &stream.content, own, Some(id), depth.saturating_add(1), page)?;
                }
            }
            "BI" if !matches!(operation.operands.as_slice(), [Object::Stream(_)]) => {
                return Err(ParseError::corrupt("pdf", "inline image encoding is unsupported"));
            }
            _ => {}
        }
    }
    page.nodes.insert(node, Node { form, content });
    Ok(node)
}

fn add_glyphs(bytes: &[u8], font: &Font<'_>, source: Source, page: &mut Page<'_>) -> Result<(), ParseError> {
    let mut offset = 0;
    while offset < bytes.len() {
        // Reserve the maximum glyph expansion and decoding temporaries before asking lopdf
        // to allocate them. This allowance is shared by all Forms and pages in the document.
        page.work.budget.charge(font.max_glyph_bytes.saturating_mul(8))?;
        page.work
            .budget
            .charge(std::mem::size_of::<Glyph>().saturating_mul(2))?;
        if page.work.glyphs_remaining == 0 {
            return Err(ParseError::TooLarge {
                what: "PDF text glyphs",
                limit: MAX_GLYPHS,
                actual: MAX_GLYPHS.saturating_add(1),
            });
        }
        page.work.glyphs_remaining -= 1;
        let width = match font.encoding.as_ref() {
            Encoding::UnicodeMapEncoding(map) => map
                .next_code_width(&bytes[offset..])
                .ok_or_else(|| ParseError::corrupt("pdf", "unmapped text glyph"))?,
            Encoding::SimpleEncoding(b"UniGB-UCS2-H" | b"UniGB-UTF16-H") => 2,
            _ => 1,
        };
        let end = offset.saturating_add(width);
        let code = bytes
            .get(offset..end)
            .ok_or_else(|| ParseError::corrupt("pdf", "truncated text glyph"))?;
        let decoded = font.encoding.bytes_to_string(code).map_err(map_lopdf)?;
        if decoded.is_empty() || decoded.contains('\u{fffd}') {
            return Err(ParseError::corrupt("pdf", "unmapped text glyph"));
        }
        page.work.budget.charge(decoded.len())?;
        let start = page.text.len();
        page.text.push_str(&decoded);
        let mut code_bytes = [0; 4];
        code_bytes[..code.len()].copy_from_slice(code);
        page.glyphs.push(Glyph {
            source,
            bytes: offset..end,
            text: start..page.text.len(),
            cmap: font.cmap,
            code: code_bytes,
            width,
        });
        offset = end;
    }
    Ok(())
}

fn redaction_mask(
    page: &mut Page<'_>,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
) -> Result<Vec<bool>, ParseError> {
    page.work.budget.charge(page.glyphs.len())?;
    let mut removed = vec![false; page.glyphs.len()];
    loop {
        // Removing glyphs must not concatenate previously separated safe fragments into
        // another registered secret. Every pass removes glyphs or stops, and all passes
        // consume the same finite document work allowance.
        page.work.budget.charge(page.text.len())?;
        let mut visible = String::with_capacity(page.text.len());
        for (index, glyph) in page.glyphs.iter().enumerate() {
            if !removed[index] {
                visible.push_str(&page.text[glyph.text.clone()]);
            }
        }
        let clean = redact(&visible)?;
        page.work.budget.charge(clean.len())?;
        let ranges = removed_ranges(&visible, &clean);
        if ranges.is_empty() {
            return Ok(removed);
        }
        let mut cursor = 0;
        let mut changed = false;
        for (index, glyph) in page.glyphs.iter().enumerate() {
            if removed[index] {
                continue;
            }
            let end = cursor + glyph.text.len();
            let first = ranges.partition_point(|range| range.end <= cursor);
            if ranges.get(first).is_some_and(|range| range.start < end) {
                removed[index] = true;
                changed = true;
            }
            cursor = end;
        }
        if !changed {
            return Err(ParseError::corrupt(
                "pdf",
                "text redaction cannot be represented by native glyphs",
            ));
        }
    }
}

pub(super) fn appearance_forms(doc: &Document, page: ObjectId) -> Result<Vec<ObjectId>, ParseError> {
    let mut result = Vec::new();
    for annotation in doc.get_page_annotations(page).map_err(map_lopdf)? {
        if let Ok(appearances) = annotation.get_deref(b"AP", doc).and_then(Object::as_dict) {
            if let Ok(normal) = appearances.get(b"N") {
                let state = annotation.get_deref(b"AS", doc).and_then(Object::as_name).ok();
                collect_appearances(doc, normal, state, 0, &mut BTreeSet::new(), &mut result)?;
            }
        }
    }
    Ok(result)
}

fn collect_appearances(
    doc: &Document,
    object: &Object,
    state: Option<&[u8]>,
    depth: usize,
    path: &mut BTreeSet<ObjectId>,
    result: &mut Vec<ObjectId>,
) -> Result<(), ParseError> {
    nesting(depth)?;
    match object {
        Object::Reference(id) => {
            if !path.insert(*id) {
                return Err(ParseError::corrupt("pdf", "cyclic annotation appearance"));
            }
            let object = doc.get_object(*id).map_err(map_lopdf)?;
            if matches!(object, Object::Stream(stream)
                if stream.dict.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Form"))
            {
                // This is an invocation, not a set membership: repeated annotations and
                // their original /Annots order must remain part of the visible text plane.
                result.push(*id);
            } else {
                collect_appearances(doc, object, state, depth.saturating_add(1), path, result)?;
            }
            path.remove(id);
        }
        Object::Dictionary(dict) => {
            if let Some(state) = state {
                let selected = dict.get(state).map_err(map_lopdf)?;
                collect_appearances(doc, selected, None, depth.saturating_add(1), path, result)?;
            } else {
                for (_, value) in dict {
                    collect_appearances(doc, value, None, depth.saturating_add(1), path, result)?;
                }
            }
        }
        Object::Array(values) => {
            for value in values {
                collect_appearances(doc, value, state, depth.saturating_add(1), path, result)?;
            }
        }
        Object::Stream(_) => {
            return Err(ParseError::corrupt(
                "pdf",
                "direct appearance stream is unsupported",
            ))
        }
        _ => return Err(ParseError::corrupt("pdf", "invalid annotation appearance")),
    }
    Ok(())
}
