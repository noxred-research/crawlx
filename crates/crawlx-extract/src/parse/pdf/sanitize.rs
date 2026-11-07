//! Structural sanitization of native PDF strings and text-show operations.
//!
//! Fonts, page geometry and safe glyph bytes stay native. This is not OCR: images, embedded
//! files, unknown stream encodings and secrets without a usable font mapping remain outside
//! text-layer coverage. Callers must still apply core binary approval before storing output.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::ops::Range;

use lopdf::content::Content;
use lopdf::{Dictionary, Document, LoadOptions, Object, ObjectId, Stream, StringFormat};

use super::map_lopdf;
use crate::parse::{guard, ParseError, ParseLimits};

const MAX_DEPTH: usize = 64;
const MAX_GLYPHS: usize = 1_000_000;

mod cmap;
mod content;
use content::{appearance_forms, sanitize_content};
mod xml;
use xml::sanitize_xml;

#[cfg(test)]
mod tests;

/// Sanitize decoded PDF strings, metadata and native text-layer glyphs, rebuilding the xref.
///
/// `redact` must apply the caller's authoritative text policy, using `[REDACTED]` for matches.
/// Text glyphs corresponding to matches are removed, not painted over or hidden. Adjacent text
/// show operands are inspected together so splitting a secret across `Tj`/`TJ` cannot hide it.
/// Safe glyphs retain their original encoding; no replacement font or substitute document is used.
/// Synchronous and CPU-bound: invoke on a blocking thread. The result is not an approved artifact.
///
/// Images, opaque embedded streams and unknown visual encodings are not OCR'd. This function
/// does not claim exhaustive privacy detection. Malformed or unmappable text is rejected.
///
/// # Errors
/// Returns the text policy's error, or a typed parser error for malformed/encrypted PDFs,
/// undecodable text, excessive nesting, object/page counts, decoded bytes or serialized bytes.
pub fn sanitize_pdf(
    bytes: &[u8],
    limits: &ParseLimits,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
) -> Result<Vec<u8>, ParseError> {
    check_limit("input bytes", bytes.len(), limits.max_input_bytes)?;
    guard("pdf", || sanitize_inner(bytes, limits, redact))
}

fn check_limit(what: &'static str, actual: usize, limit: usize) -> Result<(), ParseError> {
    if actual > limit {
        return Err(ParseError::TooLarge { what, limit, actual });
    }
    Ok(())
}

fn nesting(depth: usize) -> Result<(), ParseError> {
    check_limit("PDF nesting depth", depth, MAX_DEPTH)
}

struct Budget {
    remaining: usize,
    limit: usize,
}

impl Budget {
    fn charge(&mut self, len: usize) -> Result<(), ParseError> {
        if len > self.remaining {
            return Err(ParseError::TooLarge {
                what: "decompressed stream bytes",
                limit: self.limit,
                actual: self.limit.saturating_add(1),
            });
        }
        self.remaining -= len;
        Ok(())
    }
}

fn sanitize_inner(
    bytes: &[u8],
    limits: &ParseLimits,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
) -> Result<Vec<u8>, ParseError> {
    let mut doc = Document::load_mem_with_options(
        bytes,
        LoadOptions {
            max_total_decompressed_size: Some(limits.max_uncompressed_bytes),
            max_objects: Some(limits.max_entries),
            ..LoadOptions::with_max_decompressed_size(limits.max_uncompressed_bytes)
        },
    )
    .map_err(map_lopdf)?;
    if doc.is_encrypted() {
        return Err(ParseError::Encrypted { format: "pdf" });
    }
    check_limit("PDF objects", doc.objects.len(), limits.max_entries)?;
    let pages = doc.get_pages();
    if pages.is_empty() {
        return Err(ParseError::corrupt("pdf", "document has no pages"));
    }
    check_limit("PDF pages", pages.len(), limits.max_pages)?;
    let mut budget = Budget {
        remaining: limits.max_uncompressed_bytes,
        limit: limits.max_uncompressed_bytes,
    };
    // Normalize supported compression once, before font CMap decoding. Account for every
    // successfully decoded stream, including font programs, against one aggregate allowance.
    for object in doc.objects.values_mut() {
        if let Object::Stream(stream) = object {
            match stream.decompressed_content_with_limit(budget.remaining) {
                Ok(decoded) => {
                    budget.charge(decoded.len())?;
                    stream.set_plain_content(decoded);
                }
                Err(lopdf::Error::Decompress(lopdf::DecompressError::MemoryLimitExceeded { limit })) => {
                    return Err(ParseError::TooLarge {
                        what: "decompressed stream bytes",
                        limit,
                        actual: limit.saturating_add(1),
                    });
                }
                // E.g. JPEG/JPX image data: preserve native bytes, never text-rewrite them.
                Err(_) => budget.charge(stream.content.len())?,
            }
        }
    }
    let mut work = ContentWork {
        forms: BTreeMap::new(),
        cmaps: cmap::font_cmaps(&doc)?
            .into_iter()
            .map(|id| (id, BTreeSet::new()))
            .collect(),
        objects_remaining: limits.max_entries,
        glyphs_remaining: MAX_GLYPHS,
        budget: Budget {
            remaining: limits.max_uncompressed_bytes,
            limit: limits.max_uncompressed_bytes,
        },
    };
    let mut contents = Vec::with_capacity(pages.len());
    for page in pages.values() {
        let resources = page_resources(&doc, *page)?;
        let content = doc
            .get_page_content_with_limit(*page, limits.max_uncompressed_bytes)
            .map_err(map_lopdf)?;
        let appearances = appearance_forms(&doc, *page)?;
        let sanitized = sanitize_content(&doc, &content, &resources, redact, &mut work, &appearances)?;
        contents.push((*page, sanitized));
    }
    // Reachable Forms need not be invoked by a page Do (annotation /AP is one example).
    // Process remaining Forms too, so references through other supported dictionaries
    // cannot retain an uninspected native text layer.
    for (id, object) in &doc.objects {
        let Object::Stream(stream) = object else {
            continue;
        };
        if stream.dict.get(b"Subtype").and_then(Object::as_name).ok() == Some(b"Form")
            && !work.forms.contains_key(id)
        {
            let empty = Dictionary::new();
            let resources = stream
                .dict
                .get_deref(b"Resources", &doc)
                .and_then(Object::as_dict)
                .unwrap_or(&empty);
            let clean = sanitize_content(&doc, &stream.content, resources, redact, &mut work, &[])?;
            work.forms.insert(*id, clean);
        }
    }
    for (id, content) in std::mem::take(&mut work.forms) {
        doc.get_object_mut(id)
            .and_then(Object::as_stream_mut)
            .map_err(map_lopdf)?
            .set_plain_content(content);
    }
    cmap::rewrite_cmaps(&mut doc, &mut work, redact)?;
    for (page, content) in contents {
        let id = doc.add_object(Stream::new(Dictionary::new(), content));
        doc.get_object_mut(page)
            .and_then(Object::as_dict_mut)
            .map_err(map_lopdf)?
            .set("Contents", Object::Reference(id));
    }
    for object in doc.objects.values_mut() {
        sanitize_object(object, redact, 0)?;
        if let Object::Stream(stream) = object {
            if stream.dict.get(b"Type").and_then(Object::as_name).ok() == Some(b"Metadata") {
                let clean = sanitize_xml(&stream.content, work.budget.remaining, redact)?;
                work.budget.charge(clean.len())?;
                stream.set_plain_content(clean);
            }
        }
    }
    sanitize_dictionary(&mut doc.trailer, redact, 0)?;
    // Full serialization, not an incremental update: no old content or stale xref survives.
    doc.prune_objects();
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        limit: limits.max_uncompressed_bytes,
    };
    doc.save_to(&mut writer)
        .map_err(|source| ParseError::corrupt_from("pdf", "sanitized serialization failed", source))?;
    Ok(writer.bytes)
}

fn page_resources(doc: &Document, page: ObjectId) -> Result<Dictionary, ParseError> {
    let (direct, inherited) = doc.get_page_resources(page).map_err(map_lopdf)?;
    let mut result = direct.cloned().unwrap_or_default();
    for id in inherited {
        for (key, value) in doc.get_dictionary(id).map_err(map_lopdf)? {
            if !result.has(key) {
                result.set(key.clone(), value.clone());
            }
        }
    }
    Ok(result)
}

fn sanitize_dictionary(
    dict: &mut Dictionary,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
    depth: usize,
) -> Result<(), ParseError> {
    nesting(depth)?;
    let policy = crawlx_core::secret::Redactor::new();
    for (name, value) in dict.iter_mut() {
        if matches!(value, Object::String(_, _)) && policy.is_sensitive_name(&String::from_utf8_lossy(name)) {
            *value = Object::string_literal(crawlx_core::secret::REDACTED);
        } else {
            sanitize_object(value, redact, depth.saturating_add(1))?;
        }
    }
    Ok(())
}

fn sanitize_object(
    object: &mut Object,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
    depth: usize,
) -> Result<(), ParseError> {
    nesting(depth)?;
    match object {
        Object::String(_, _) => {
            let text = lopdf::decode_text_string(object).map_err(map_lopdf)?;
            let clean = redact(&text)?;
            if clean != text {
                let mut encoded = vec![0xfe, 0xff];
                encoded.extend(clean.encode_utf16().flat_map(u16::to_be_bytes));
                *object = Object::String(encoded, StringFormat::Hexadecimal);
            }
        }
        Object::Array(values) => {
            for value in values {
                sanitize_object(value, redact, depth.saturating_add(1))?;
            }
        }
        Object::Dictionary(dict) => sanitize_dictionary(dict, redact, depth.saturating_add(1))?,
        Object::Stream(stream) => sanitize_dictionary(&mut stream.dict, redact, depth.saturating_add(1))?,
        _ => {}
    }
    Ok(())
}

struct ContentWork {
    forms: BTreeMap<ObjectId, Vec<u8>>,
    budget: Budget,
    glyphs_remaining: usize,
    objects_remaining: usize,
    cmaps: BTreeMap<ObjectId, BTreeSet<Vec<u8>>>,
}

fn removed_ranges(original: &str, clean: &str) -> Vec<Range<usize>> {
    if original == clean {
        return Vec::new();
    }
    let mut removed = Vec::new();
    let mut cursor = 0;
    for (index, safe) in clean.split(crawlx_core::secret::REDACTED).enumerate() {
        if safe.is_empty() {
            continue;
        }
        let Some(found) = original[cursor..].find(safe) else {
            // Unrecognized policy output cannot justify retaining any text glyphs.
            return std::iter::once(0..original.len()).collect();
        };
        let start = cursor + found;
        if start != cursor {
            removed.push(cursor..start);
        }
        if index == 0 && start != 0 {
            return std::iter::once(0..original.len()).collect();
        }
        cursor = start + safe.len();
    }
    if cursor < original.len() {
        removed.push(cursor..original.len());
    }
    removed
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("sanitized PDF exceeds output byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn xml_error(source: impl std::error::Error + Send + Sync + 'static) -> ParseError {
    ParseError::corrupt_from("pdf", "metadata XML cannot be sanitized", source)
}

fn cmap_code(object: &Object) -> Result<u32, ParseError> {
    let bytes = object.as_str().map_err(map_lopdf)?;
    if bytes.is_empty() || bytes.len() > 4 {
        return Err(ParseError::corrupt("pdf", "invalid CMap source code"));
    }
    Ok(bytes
        .iter()
        .fold(0u32, |code, byte| code * 256 + u32::from(*byte)))
}

fn bound_font_cmap(
    doc: &Document,
    font: &Dictionary,
    budget: &mut Budget,
    objects_remaining: &mut usize,
) -> Result<usize, ParseError> {
    let Ok(stream) = font.get_deref(b"ToUnicode", doc).and_then(Object::as_stream) else {
        return Ok(4);
    };
    budget.charge(stream.content.len())?;
    // lopdf builds a reverse map eagerly. A tiny CMap can expand a four-byte code range
    // into billions of entries; bounded decompression alone does not bound that work.
    // Reuse lopdf's operator parser to account for mapping expansion before loading it.
    let (content, objects, bytes) =
        Content::decode_bounded_with_usage(&stream.content, *objects_remaining, budget.remaining)
            .map_err(map_lopdf)?;
    *objects_remaining = objects_remaining
        .checked_sub(objects)
        .ok_or_else(|| ParseError::corrupt("pdf", "CMap parser exceeded object budget"))?;
    budget.charge(bytes)?;
    let mut max_glyph_bytes = 4;
    for operation in content.operations {
        let stride = match operation.operator.as_str() {
            "endbfchar" => 2,
            "endbfrange" => 3,
            _ => continue,
        };
        let chunks = operation.operands.chunks_exact(stride);
        if !chunks.remainder().is_empty() {
            return Err(ParseError::corrupt("pdf", "invalid CMap mapping operands"));
        }
        for mapping in chunks {
            let count = if stride == 3 {
                let low = cmap_code(&mapping[0])?;
                let high = cmap_code(&mapping[1])?;
                high.checked_sub(low)
                    .and_then(|difference| difference.checked_add(1))
                    .ok_or_else(|| ParseError::corrupt("pdf", "invalid CMap code range"))?
            } else {
                1
            };
            let count = usize::try_from(count)
                .map_err(|source| ParseError::corrupt_from("pdf", "CMap range is too large", source))?;
            check_limit("PDF CMap entries", count, MAX_GLYPHS)?;
            let target = &mapping[stride - 1];
            let target_bytes = match target {
                Object::String(bytes, _) => bytes.len(),
                Object::Array(values) => values.iter().try_fold(0usize, |total, value| {
                    value
                        .as_str()
                        .map(|bytes| total.saturating_add(bytes.len()))
                        .map_err(map_lopdf)
                })?,
                _ => return Err(ParseError::corrupt("pdf", "invalid CMap target")),
            };
            max_glyph_bytes = max_glyph_bytes.max(target_bytes);
            // Include reverse-map nodes, code vectors and Unicode copies, not only text bytes.
            budget.charge(count.saturating_mul(target_bytes.saturating_mul(8).saturating_add(512)))?;
        }
    }
    Ok(max_glyph_bytes)
}
