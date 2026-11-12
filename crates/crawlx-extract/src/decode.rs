//! Bounded byte decoding with diagnostics, and the comment/CDATA-aware text view of a document.
//!
//! Charset negotiation normally belongs to the fetcher. [`decode`] is the extractor's own
//! entry for callers that hold raw bytes: it picks an encoding by byte-order mark, then the
//! caller-declared charset, then an early `<meta>` declaration, then UTF-8, decodes without
//! panicking on any input, and returns a [`DecodeReport`] that records the chosen encoding, why
//! it was chosen and every malformed byte sequence (bounded) instead of hiding replacements.
//!
//! [`markup_text`] separates what the source says from what the cleaned view keeps: comments and
//! CDATA sections never leak into the cleaned text unless [`MarkupOptions`] asks for them, and
//! they are collected as separate, bounded lists on request. The digest of the decoded source is
//! always reported so a cleaned view can be tied back to its input.

use crawlx_core::hash::Digest;
use scraper::{Html, Node};
use serde::{Deserialize, Serialize};

use crate::{ExtractError, ExtractOptions};

/// Largest input decoded, in bytes.
pub const MAX_DECODE_BYTES: usize = 16 * 1024 * 1024;
/// Most malformed-sequence records kept in a [`DecodeReport`].
pub const MAX_RECORDED_ISSUES: usize = 64;
/// Bytes at the start of a document searched for a `<meta>` charset declaration.
const META_PRESCAN_BYTES: usize = 1024;
/// Most comment or CDATA entries collected by [`markup_text`].
pub const MAX_COLLECTED: usize = 10_000;
/// Most bytes of comment or CDATA text collected by [`markup_text`].
pub const MAX_COLLECTED_BYTES: usize = 1 << 20;

/// Failure of a bounded decode or markup view.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input is larger than [`MAX_DECODE_BYTES`].
    #[error("input of {len} bytes exceeds the {MAX_DECODE_BYTES} byte decode limit")]
    TooLarge {
        /// Input length in bytes.
        len: usize,
    },
}

/// Where the chosen encoding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EncodingSource {
    /// A byte-order mark.
    Bom,
    /// The caller-declared charset (for example from `Content-Type`).
    Declared,
    /// A `<meta>` declaration in the first bytes of the document.
    Meta,
    /// Nothing declared an encoding; UTF-8 was assumed.
    Default,
}

/// One malformed byte sequence replaced by U+FFFD.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DecodeIssue {
    /// Byte offset of the sequence in the input.
    pub offset: usize,
    /// Length of the sequence in bytes.
    pub length: usize,
}

/// What a decode did, for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DecodeReport {
    /// WHATWG name of the encoding used.
    pub encoding: String,
    /// Why that encoding was used.
    pub source: EncodingSource,
    /// Length of a consumed byte-order mark in bytes, zero when none.
    pub bom_len: usize,
    /// The first [`MAX_RECORDED_ISSUES`] malformed sequences.
    pub issues: Vec<DecodeIssue>,
    /// Total malformed sequences, including unrecorded ones.
    pub issue_count: usize,
    /// More malformed sequences occurred than were recorded.
    pub issues_truncated: bool,
    /// A declared charset label that names no known encoding (truncated to 64 characters).
    pub unknown_label: Option<String>,
    /// A declaration other than the chosen source named a different known encoding.
    pub declaration_conflict: bool,
}

/// Decoded text and its report.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decoded {
    /// Decoded text; malformed sequences are U+FFFD.
    pub text: String,
    /// How the text was produced.
    pub report: DecodeReport,
}

/// Extract the `charset` parameter of a `Content-Type` value.
#[must_use]
pub fn charset_of_content_type(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (key, value) = param.split_once('=')?;
        key.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches(['"', '\'']).to_owned())
            .filter(|v| !v.is_empty())
    })
}

/// Find a `<meta charset=…>` / `<meta http-equiv … content="…; charset=…">` label in the first
/// bytes of a document.
#[must_use]
pub fn sniff_meta_charset(bytes: &[u8]) -> Option<String> {
    let head = &bytes[..bytes.len().min(META_PRESCAN_BYTES)];
    let lower: Vec<u8> = head.iter().map(u8::to_ascii_lowercase).collect();
    let mut from = 0usize;
    while let Some(at) = find(&lower, b"<meta", from) {
        let end = lower[at..]
            .iter()
            .position(|b| *b == b'>')
            .map_or(lower.len(), |p| at + p);
        let tag = &lower[at..end];
        if let Some(c) = find(tag, b"charset", 0) {
            let mut i = c + b"charset".len();
            while tag.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
                i += 1;
            }
            if tag.get(i) == Some(&b'=') {
                i += 1;
                while tag.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
                    i += 1;
                }
                let quote = tag.get(i).copied().filter(|b| matches!(b, b'"' | b'\''));
                if quote.is_some() {
                    i += 1;
                }
                let label: Vec<u8> = tag[i..]
                    .iter()
                    .copied()
                    .take_while(|b| match quote {
                        Some(q) => *b != q,
                        None => !b.is_ascii_whitespace() && !matches!(b, b';' | b'"' | b'\'' | b'/'),
                    })
                    .collect();
                if !label.is_empty() {
                    return String::from_utf8(label).ok();
                }
            }
        }
        from = end.max(at + 1);
    }
    None
}

fn find(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    haystack
        .get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

/// Decode `bytes` with diagnostics.
///
/// `declared` is a charset label from outside the document (for example the `charset` parameter
/// of `Content-Type`, see [`charset_of_content_type`]). A byte-order mark wins over it, and a
/// `<meta>` declaration is only consulted when neither exists. UTF-16 named by `<meta>` is read
/// as UTF-8, because a document whose first bytes are readable ASCII cannot be UTF-16.
///
/// # Errors
/// [`DecodeError::TooLarge`] above [`MAX_DECODE_BYTES`].
pub fn decode(bytes: &[u8], declared: Option<&str>) -> Result<Decoded, DecodeError> {
    if bytes.len() > MAX_DECODE_BYTES {
        return Err(DecodeError::TooLarge { len: bytes.len() });
    }
    let label = |l: &str| encoding_rs::Encoding::for_label(l.trim().as_bytes());
    let mut unknown_label = None;
    let declared_encoding = declared.and_then(|l| {
        let found = label(l);
        if found.is_none() {
            unknown_label = Some(l.chars().take(64).collect::<String>());
        }
        found
    });
    let meta_encoding = sniff_meta_charset(bytes).and_then(|l| {
        label(&l).map(|e| {
            if e == encoding_rs::UTF_16LE || e == encoding_rs::UTF_16BE {
                encoding_rs::UTF_8
            } else {
                e
            }
        })
    });
    let (encoding, source, bom_len) = if let Some((e, len)) = encoding_rs::Encoding::for_bom(bytes) {
        (e, EncodingSource::Bom, len)
    } else if let Some(e) = declared_encoding {
        (e, EncodingSource::Declared, 0)
    } else if let Some(e) = meta_encoding {
        (e, EncodingSource::Meta, 0)
    } else {
        (encoding_rs::UTF_8, EncodingSource::Default, 0)
    };
    let others = [declared_encoding, meta_encoding];
    let declaration_conflict = others.iter().flatten().any(|e| *e != encoding);

    let payload = &bytes[bom_len..];
    let mut out = String::new();
    let mut issues = Vec::new();
    let mut issue_count = 0usize;
    let mut decoder = encoding.new_decoder_without_bom_handling();
    let mut pos = 0usize;
    out.reserve(
        decoder
            .max_utf8_buffer_length_without_replacement(payload.len())
            .unwrap_or(payload.len())
            .min(MAX_DECODE_BYTES.saturating_mul(3)),
    );
    loop {
        let (result, read) = decoder.decode_to_string_without_replacement(&payload[pos..], &mut out, true);
        pos += read;
        match result {
            encoding_rs::DecoderResult::InputEmpty => break,
            encoding_rs::DecoderResult::OutputFull => out.reserve(payload.len().saturating_sub(pos).max(64)),
            encoding_rs::DecoderResult::Malformed(bad, good) => {
                issue_count += 1;
                if issues.len() < MAX_RECORDED_ISSUES {
                    let length = usize::from(bad);
                    issues.push(DecodeIssue {
                        offset: bom_len + pos.saturating_sub(usize::from(good)).saturating_sub(length),
                        length,
                    });
                }
                out.push('\u{FFFD}');
            }
        }
    }
    Ok(Decoded {
        text: out,
        report: DecodeReport {
            encoding: encoding.name().to_owned(),
            source,
            bom_len,
            issues_truncated: issue_count > issues.len(),
            issues,
            issue_count,
            unknown_label,
            declaration_conflict,
        },
    })
}

/// What [`markup_text`] does with comments.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MarkupComments {
    /// Ignore comments.
    #[default]
    Drop,
    /// Collect comment bodies into [`MarkupText::comments`]; they never enter the cleaned text.
    Collect,
}

/// What [`markup_text`] does with CDATA sections (`<![CDATA[…]]>`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MarkupCdata {
    /// Treat the section's payload as text, at its position in the cleaned text.
    #[default]
    Text,
    /// Collect payloads into [`MarkupText::cdata`]; they do not enter the cleaned text.
    Collect,
    /// Ignore the section.
    Drop,
}

/// Options of [`markup_text`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MarkupOptions {
    /// Comment handling.
    pub comments: MarkupComments,
    /// CDATA handling.
    pub cdata: MarkupCdata,
    /// Keep the decoded source text in [`MarkupText::source`].
    pub keep_source: bool,
}

impl MarkupOptions {
    /// Options collecting comments and CDATA payloads separately and keeping the source.
    #[must_use]
    pub fn preserving() -> Self {
        Self {
            comments: MarkupComments::Collect,
            cdata: MarkupCdata::Collect,
            keep_source: true,
        }
    }
}

/// Cleaned text of a document next to its separately retained source facts.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MarkupText {
    /// Whitespace-normalized text outside `script`, `style`, `template` and comments.
    pub text: String,
    /// Collected comment bodies in document order (empty unless requested).
    pub comments: Vec<String>,
    /// Collected CDATA payloads in document order (empty unless requested).
    pub cdata: Vec<String>,
    /// More comments or CDATA payloads existed than the bounds allow.
    pub truncated: bool,
    /// Decoded source, when [`MarkupOptions::keep_source`] was set.
    pub source: Option<String>,
    /// Digest of the decoded source text.
    pub source_digest: Digest,
    /// Decode report when the view was built from bytes.
    pub decode: Option<DecodeReport>,
}

fn cdata_payload(comment: &str) -> Option<&str> {
    // The HTML tokenizer turns `<![CDATA[x]]>` outside foreign content into a bogus comment
    // whose body is `[CDATA[x]]`.
    comment.strip_prefix("[CDATA[")?.strip_suffix("]]")
}

/// Build the cleaned text view of `html` according to `options`.
///
/// # Errors
/// [`ExtractError::TooLarge`] / [`ExtractError::ParseMemory`] under the default extraction limits.
pub fn markup_text(html: &str, options: &MarkupOptions) -> Result<MarkupText, ExtractError> {
    crate::precheck(html, &ExtractOptions::default())?;
    // declared before `doc`: released after the parsed tree is dropped
    let mut charge = crate::parse_budget::charge(html.len())?;
    let doc = crate::dom::parse_document(&mut charge, html)?;
    let mut raw = String::new();
    let mut comments = Vec::new();
    let mut cdata = Vec::new();
    let mut collected_bytes = 0usize;
    let mut truncated = false;
    let mut collect = |list: &mut Vec<String>, body: &str, truncated: &mut bool| {
        if list.len() >= MAX_COLLECTED || collected_bytes.saturating_add(body.len()) > MAX_COLLECTED_BYTES {
            *truncated = true;
        } else {
            collected_bytes += body.len();
            list.push(body.to_owned());
        }
    };
    let mut stack = vec![doc.tree.root().id()];
    // Iterative preorder walk; children are pushed reversed so document order is preserved.
    while let Some(id) = stack.pop() {
        let Some(node) = doc.tree.get(id) else {
            continue;
        };
        match node.value() {
            Node::Text(t) => {
                raw.push_str(t);
                continue;
            }
            Node::Comment(c) => {
                let body: &str = c;
                if let Some(payload) = cdata_payload(body) {
                    match options.cdata {
                        MarkupCdata::Text => raw.push_str(payload),
                        MarkupCdata::Collect => collect(&mut cdata, payload, &mut truncated),
                        MarkupCdata::Drop => {}
                    }
                } else if options.comments == MarkupComments::Collect {
                    collect(&mut comments, body, &mut truncated);
                }
                continue;
            }
            Node::Element(e) => {
                raw.push(' ');
                if matches!(e.name(), "script" | "style" | "template") {
                    continue;
                }
            }
            _ => {}
        }
        let children: Vec<_> = node.children().map(|c| c.id()).collect();
        stack.extend(children.into_iter().rev());
    }
    Ok(MarkupText {
        text: crate::handlers::clean_text(&raw),
        comments,
        cdata,
        truncated,
        source: options.keep_source.then(|| html.to_owned()),
        source_digest: Digest::of("crawlx.extract.decoded_source.v1", html.as_bytes()),
        decode: None,
    })
}

/// Retention switches for the extractor (`ExtractOptions::markup`).
///
/// The cleaned `Document` text is unchanged by these switches; they only choose which source
/// facts are kept beside it, so a cleaned view and its source stay distinguishable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct MarkupRetention {
    /// Collect comment bodies into [`MarkupRecord::comments`].
    pub comments: bool,
    /// Collect CDATA payloads into [`MarkupRecord::cdata`].
    pub cdata: bool,
}

impl MarkupRetention {
    /// Retain both comments and CDATA payloads.
    #[must_use]
    pub fn all() -> Self {
        Self {
            comments: true,
            cdata: true,
        }
    }
}

/// Byte-input decoding switches for the extractor (`ExtractOptions::decode`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DecodeOptions {
    /// Charset label from outside the document; the `charset` of `ExtractOptions::content_type`
    /// is used when absent.
    pub declared_charset: Option<String>,
}

impl DecodeOptions {
    /// Options with an explicit declared charset label.
    #[must_use]
    pub fn with_charset(label: &str) -> Self {
        Self {
            declared_charset: Some(label.to_owned()),
        }
    }
}

/// Comments and CDATA payloads kept from the source, beside the cleaned `Document` text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct MarkupRecord {
    /// Comment bodies in document order.
    pub comments: Vec<String>,
    /// CDATA payloads in document order.
    pub cdata: Vec<String>,
    /// More entries existed than the bounds allow.
    pub truncated: bool,
    /// Digest of the decoded source text the document was parsed from.
    pub source_digest: Digest,
}

/// Collect retained comments and CDATA payloads from an already parsed document.
pub(crate) fn collect_markup(doc: &Html, source: &str, retention: MarkupRetention) -> MarkupRecord {
    let mut record = MarkupRecord {
        comments: Vec::new(),
        cdata: Vec::new(),
        truncated: false,
        source_digest: Digest::of("crawlx.extract.decoded_source.v1", source.as_bytes()),
    };
    let mut bytes = 0usize;
    for node in doc.tree.root().descendants() {
        let Node::Comment(comment) = node.value() else {
            continue;
        };
        let body: &str = comment;
        let (list, text) = match cdata_payload(body) {
            Some(payload) if retention.cdata => (&mut record.cdata, payload),
            None if retention.comments => (&mut record.comments, body),
            _ => continue,
        };
        if list.len() >= MAX_COLLECTED || bytes.saturating_add(text.len()) > MAX_COLLECTED_BYTES {
            record.truncated = true;
        } else {
            bytes += text.len();
            list.push(text.to_owned());
        }
    }
    record
}

/// Decode `bytes` (see [`decode`]) and build the text view of the result.
///
/// # Errors
/// [`ExtractError::TooLarge`] for input above the decode or extraction limits,
/// [`ExtractError::ParseMemory`] under parse-memory pressure.
pub fn markup_text_bytes(
    bytes: &[u8],
    declared: Option<&str>,
    options: &MarkupOptions,
) -> Result<MarkupText, ExtractError> {
    let decoded = decode(bytes, declared).map_err(|error| match error {
        DecodeError::TooLarge { len } => ExtractError::TooLarge {
            what: "bytes",
            limit: MAX_DECODE_BYTES,
            actual: len,
        },
    })?;
    let mut view = markup_text(&decoded.text, options)?;
    view.decode = Some(decoded.report);
    Ok(view)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn utf8_decodes_cleanly_and_reports_default_source() {
        let out = decode("héllo".as_bytes(), None).unwrap();
        assert_eq!(out.text, "héllo");
        assert_eq!(out.report.encoding, "UTF-8");
        assert_eq!(out.report.source, EncodingSource::Default);
        assert_eq!(out.report.issue_count, 0);
    }

    #[test]
    fn malformed_utf8_is_replaced_and_every_sequence_recorded_with_offsets() {
        let bytes = b"ok \xff\xfe mid \xc3 end";
        let out = decode(bytes, None).unwrap();
        assert_eq!(out.text.matches('\u{FFFD}').count(), 3);
        assert!(out.text.starts_with("ok ") && out.text.ends_with(" end"));
        assert_eq!(out.report.issue_count, 3);
        assert_eq!(
            out.report
                .issues
                .iter()
                .map(|i| (i.offset, i.length))
                .collect::<Vec<_>>(),
            [(3, 1), (4, 1), (10, 1)]
        );
        assert!(!out.report.issues_truncated);
    }

    #[test]
    fn issue_records_are_bounded_but_counted() {
        let bytes = vec![0xffu8; MAX_RECORDED_ISSUES + 10];
        let out = decode(&bytes, None).unwrap();
        assert_eq!(out.report.issue_count, MAX_RECORDED_ISSUES + 10);
        assert_eq!(out.report.issues.len(), MAX_RECORDED_ISSUES);
        assert!(out.report.issues_truncated);
        assert_eq!(out.text.chars().count(), MAX_RECORDED_ISSUES + 10);
    }

    #[test]
    fn encoding_priority_is_bom_then_declared_then_meta() {
        let latin = b"<meta charset=iso-8859-1><p>caf\xe9</p>";
        let meta = decode(latin, None).unwrap();
        assert_eq!(meta.report.source, EncodingSource::Meta);
        assert!(meta.text.contains("café"));
        let declared = decode(latin, Some("windows-1252")).unwrap();
        assert_eq!(declared.report.source, EncodingSource::Declared);
        assert!(declared.text.contains("café"));
        assert!(!declared.report.declaration_conflict);
        let mut bom = vec![0xef, 0xbb, 0xbf];
        bom.extend_from_slice("é".as_bytes());
        let out = decode(&bom, Some("iso-8859-1")).unwrap();
        assert_eq!(out.text, "é");
        assert_eq!(out.report.source, EncodingSource::Bom);
        assert_eq!(out.report.bom_len, 3);
        assert!(out.report.declaration_conflict);
    }

    #[test]
    fn unknown_labels_are_reported_not_fatal() {
        let out = decode(b"abc", Some("x-not-an-encoding")).unwrap();
        assert_eq!(out.text, "abc");
        assert_eq!(out.report.unknown_label.as_deref(), Some("x-not-an-encoding"));
        assert_eq!(out.report.source, EncodingSource::Default);
    }

    #[test]
    fn utf16_meta_is_read_as_utf8_and_oversize_is_refused() {
        let out = decode(b"<meta charset=utf-16><p>x</p>", None).unwrap();
        assert_eq!(out.report.encoding, "UTF-8");
        assert!(matches!(
            decode(&vec![b'a'; MAX_DECODE_BYTES + 1], None),
            Err(DecodeError::TooLarge { .. })
        ));
    }

    #[test]
    fn charset_parsers_handle_headers_and_meta_forms() {
        assert_eq!(
            charset_of_content_type("text/html; Charset=\"UTF-8\"").as_deref(),
            Some("UTF-8")
        );
        assert_eq!(charset_of_content_type("text/html"), None);
        assert_eq!(
            sniff_meta_charset(br#"<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=Shift_JIS">"#)
                .as_deref(),
            Some("shift_jis")
        );
        assert_eq!(sniff_meta_charset(b"<p>no meta</p>"), None);
    }

    const PAGE: &str = "<html><body><p>one</p><!-- note: <b>x</b> --><p>two</p>\
        <script>var a = 1;</script><![CDATA[kept & raw text]]><p>three</p>\
        <svg><![CDATA[inside svg]]></svg></body></html>";

    #[test]
    fn default_view_drops_comments_keeps_cdata_text_and_separates_source() {
        let view = markup_text(PAGE, &MarkupOptions::default()).unwrap();
        assert_eq!(view.text, "one two kept & raw text three inside svg");
        assert!(view.comments.is_empty() && view.cdata.is_empty());
        assert!(view.source.is_none());
        assert_eq!(
            view.source_digest,
            Digest::of("crawlx.extract.decoded_source.v1", PAGE.as_bytes())
        );
    }

    #[test]
    fn preserving_view_collects_comments_and_cdata_apart_from_text() {
        let view = markup_text(PAGE, &MarkupOptions::preserving()).unwrap();
        assert_eq!(view.comments, [" note: <b>x</b> "]);
        assert_eq!(view.cdata, ["kept & raw text"]);
        assert!(!view.text.contains("note"));
        assert!(!view.text.contains("kept"));
        assert_eq!(view.source.as_deref(), Some(PAGE));
        let dropped = markup_text(
            PAGE,
            &MarkupOptions {
                cdata: MarkupCdata::Drop,
                ..MarkupOptions::default()
            },
        )
        .unwrap();
        assert!(!dropped.text.contains("kept"));
    }

    #[test]
    fn collected_entries_are_bounded() {
        let page = format!("<body>{}</body>", "<!--c-->".repeat(MAX_COLLECTED + 5));
        let view = markup_text(&page, &MarkupOptions::preserving()).unwrap();
        assert_eq!(view.comments.len(), MAX_COLLECTED);
        assert!(view.truncated);
    }

    #[test]
    fn byte_entry_records_decode_errors_and_still_yields_expected_text() {
        let bytes = b"<meta charset=utf-8><p>good \xff bad</p><!-- c \xfe -->";
        let view = markup_text_bytes(bytes, None, &MarkupOptions::preserving()).unwrap();
        let report = view.decode.as_ref().unwrap();
        assert_eq!(report.issue_count, 2);
        assert_eq!(view.text, "good \u{FFFD} bad");
        assert_eq!(view.comments, [" c \u{FFFD} "]);
    }
}
