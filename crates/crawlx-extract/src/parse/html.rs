//! HTML, XHTML and EPUB chapters: the page [`Extractor`] over decoded bytes.
//!
//! An uploaded file has no URL, so the extractor runs against a placeholder base
//! ([`BASE`]); every reference it resolved against that base is turned back into the
//! reference as written, and links that do not resolve to a real host are dropped from the link
//! list.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use encoding_rs::{Encoding, UTF_8, WINDOWS_1252};
use regex::Regex;
use serde_json::Value;
use url::Url;

use crate::{compat_meta, images, ExtractError, ExtractOptions, Extractor};

use super::{ParseError, ParseLimits};

/// Placeholder page URL of an upload.
const BASE: &str = "https://upload.invalid/";

/// Extraction options for one HTML part.
pub(crate) struct HtmlOpts<'a> {
    pub only_main_content: bool,
    pub include_tags: &'a [String],
    pub exclude_tags: &'a [String],
}

/// The converted form of one HTML part.
pub(crate) struct HtmlDoc {
    pub markdown: String,
    pub html: String,
    pub text: String,
    pub links: Vec<String>,
    pub images: Vec<String>,
    pub title: Option<String>,
    pub metadata: BTreeMap<String, Value>,
    /// The decoded source.
    pub raw: String,
}

static CHARSET: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r#"(?i)charset\s*=\s*["']?\s*([a-z0-9_:.\-]+)"#).ok());

/// Decode `bytes` to text: BOM, then UTF-8, then a `charset=` declaration in the first 2 KiB,
/// then Windows-1252.
pub(crate) fn decode(bytes: &[u8]) -> String {
    if let Some((enc, len)) = Encoding::for_bom(bytes) {
        return enc.decode_without_bom_handling(&bytes[len..]).0.into_owned();
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_owned();
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]);
    let declared = CHARSET
        .as_ref()
        .and_then(|re| re.captures(&head))
        .and_then(|c| c.get(1))
        .and_then(|m| Encoding::for_label(m.as_str().as_bytes()));
    let enc = declared.filter(|e| *e != UTF_8).unwrap_or(WINDOWS_1252);
    enc.decode_without_bom_handling(bytes).0.into_owned()
}

fn unbase(s: &str) -> String {
    s.replace(BASE, "")
}

fn map_extract(e: ExtractError) -> ParseError {
    match e {
        ExtractError::TooLarge { what, limit, actual } => ParseError::TooLarge { what, limit, actual },
        ExtractError::InvalidSelector { selector, reason } => {
            ParseError::InvalidSelector { selector, reason }
        }
        ExtractError::InvalidContentPolicy(source) => {
            ParseError::corrupt_from("html", "content policy validation failed", source)
        }
        ExtractError::WordChunks(source) => {
            ParseError::corrupt_from("html", "word chunk extraction failed", source)
        }
        ExtractError::Selector(source) => {
            ParseError::corrupt_from("html", "static selector evaluation failed", source)
        }
        ExtractError::Discovery(source) => {
            ParseError::corrupt_from("html", "endpoint discovery unavailable", source)
        }
        ExtractError::ParseMemory(source) => ParseError::ParseMemory(source),
    }
}

/// Convert HTML bytes.
///
/// # Errors
/// [`ParseError::TooLarge`] beyond the input, node or depth limits;
/// [`ParseError::ParseMemory`] when the process-wide parse-memory budget is exhausted;
/// [`ParseError::InvalidSelector`] for a bad include/exclude selector.
pub(crate) fn convert(
    bytes: &[u8],
    opts: &HtmlOpts<'_>,
    limits: &ParseLimits,
) -> Result<HtmlDoc, ParseError> {
    let raw = decode(bytes);
    let base = Url::parse(BASE).map_err(|e| ParseError::corrupt_from("html", "internal base URL", e))?;
    let eo = ExtractOptions {
        only_main_content: opts.only_main_content,
        include_tags: opts.include_tags.to_vec(),
        exclude_tags: opts.exclude_tags.to_vec(),
        max_input_bytes: limits.max_input_bytes,
        forms: false,
        page_type: false,
        technologies: false,
        ..ExtractOptions::default()
    };
    let doc = Extractor::extract(&raw, &base, &eo).map_err(map_extract)?;
    let mut links: Vec<String> = Vec::new();
    for l in &doc.links {
        if l.url.host_str() != Some("upload.invalid") {
            let s = l.url.as_str().to_owned();
            if !links.contains(&s) {
                links.push(s);
            }
        }
    }
    // `images` re-parses the document; hold a charge for that parse (the extractor's own
    // charge was released with its DOM when `Extractor::extract` returned)
    let imgs = {
        let _charge = crate::parse_budget::charge(raw.len()).map_err(ParseError::ParseMemory)?;
        images::images(&raw, &base)
            .into_iter()
            .map(|u| unbase(&u))
            .collect()
    };
    Ok(HtmlDoc {
        markdown: unbase(&doc.markdown),
        html: unbase(&doc.html),
        text: doc.text.clone(),
        links,
        images: imgs,
        title: doc.title.clone(),
        metadata: compat_meta::compat_meta(&doc),
        raw,
    })
}
