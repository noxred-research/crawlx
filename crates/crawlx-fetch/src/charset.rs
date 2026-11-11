//! Charset detection and deterministic decoding of text responses.
//!
//! Detection order, first match wins: an explicit override, a byte-order mark, the
//! `Content-Type` `charset` parameter, a bounded `<meta>` / XML-declaration prescan (the
//! first [`PRESCAN_BYTES`] bytes of HTML and XML), then UTF-8. Every result records the
//! [`CharsetSource`] and the label the sender declared, so an extraction pipeline can tell a
//! declared encoding from a guessed one.
//!
//! Decoding is strict by default ([`decode_strict`]): bytes that are not valid in the
//! selected encoding are an error carrying the encoding, never silently replaced. The lossy
//! variant exists for callers that explicitly accept replacement characters and reports
//! whether any were inserted. Labels that resolve to the WHATWG "replacement" encoding
//! (which decodes everything to U+FFFD) are never honoured.

use encoding_rs::Encoding;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

/// Bytes of HTML/XML inspected for an in-document declaration.
pub const PRESCAN_BYTES: usize = 1024;

/// Longest declared label recorded.
const MAX_LABEL: usize = 40;

/// Where the effective encoding came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CharsetSource {
    /// An explicit declaration-level override.
    Override,
    /// A byte-order mark.
    Bom,
    /// The `Content-Type` `charset` parameter.
    Header,
    /// A `<meta>` charset or XML declaration.
    Meta,
    /// Nothing declared: UTF-8.
    Default,
}

/// The encoding selected for a body and how it was selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct CharsetEvidence {
    /// Canonical encoding name (`utf-8`, `windows-1252`, `shift_jis`, ...).
    pub label: String,
    /// Where it came from.
    pub source: CharsetSource,
    /// The label as the sender wrote it, when a header or document declared one that was
    /// not the selected encoding or needed normalization (unknown labels are recorded here
    /// and never honoured).
    pub declared: Option<String>,
}

/// A body is not valid in its selected encoding.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The bytes contain a sequence the encoding does not allow.
    #[error("body is not valid {encoding}{}", .offset.map_or_else(String::new, |o| format!(" at byte {o}")))]
    Malformed {
        /// Canonical encoding name.
        encoding: String,
        /// First invalid byte offset, known for UTF-8.
        offset: Option<usize>,
    },
}

/// Lower-cased media type without parameters.
#[must_use]
pub fn essence(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Whether a media type carries text that charset decoding applies to.
#[must_use]
pub fn is_text_like(essence: &str) -> bool {
    essence.starts_with("text/")
        || essence.ends_with("+xml")
        || essence.ends_with("+json")
        || matches!(
            essence,
            "application/xml"
                | "application/json"
                | "application/javascript"
                | "application/ecmascript"
                | "application/x-javascript"
        )
}

fn is_markup(essence: &str) -> bool {
    essence == "text/html" || essence == "application/xhtml+xml"
}

fn is_xml(essence: &str) -> bool {
    essence == "application/xml" || essence == "text/xml" || essence.ends_with("+xml")
}

/// The encoding a label names, if it names one this plane honours.
fn lookup(label: &str) -> Option<&'static Encoding> {
    let encoding = Encoding::for_label(label.trim().as_bytes())?;
    (encoding != encoding_rs::REPLACEMENT).then_some(encoding)
}

/// Whether `label` names an honoured encoding (used to validate overrides before traffic).
#[must_use]
pub fn is_supported_label(label: &str) -> bool {
    lookup(label).is_some()
}

fn clean_label(raw: &str) -> String {
    raw.chars()
        .filter(char::is_ascii_graphic)
        .take(MAX_LABEL)
        .collect()
}

/// `charset` parameter value of a `Content-Type`.
fn header_charset(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches(|c| c == '"' || c == '\'').to_owned())
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Value following `charset` / `encoding` `=` in `tag` (already lower-cased in `lower`).
fn attribute_value(tag: &[u8], lower: &[u8], name: &[u8]) -> Option<String> {
    let at = find(lower, name)? + name.len();
    let rest = tag.get(at..)?;
    let rest = rest.trim_ascii_start().strip_prefix(b"=")?.trim_ascii_start();
    let (quote, rest) = match rest.first() {
        Some(q @ (b'"' | b'\'')) => (Some(*q), &rest[1..]),
        _ => (None, rest),
    };
    let end = rest
        .iter()
        .position(|b| match quote {
            Some(q) => *b == q,
            None => b.is_ascii_whitespace() || matches!(b, b';' | b'>' | b'"' | b'\'' | b'/'),
        })
        .unwrap_or(rest.len());
    let value = std::str::from_utf8(&rest[..end]).ok()?.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Declared encoding inside the first [`PRESCAN_BYTES`] bytes of a document.
fn prescan(essence: &str, body: &[u8]) -> Option<String> {
    let prefix = &body[..body.len().min(PRESCAN_BYTES)];
    let lower = prefix.to_ascii_lowercase();
    if is_xml(essence) || lower.trim_ascii_start().starts_with(b"<?xml") {
        if let Some(start) = find(&lower, b"<?xml") {
            let end = find(&lower[start..], b"?>").map_or(lower.len(), |e| start + e);
            if let Some(value) = attribute_value(&prefix[start..end], &lower[start..end], b"encoding") {
                return Some(value);
            }
        }
    }
    if !is_markup(essence) {
        return None;
    }
    let mut from = 0;
    while let Some(at) = find(&lower[from..], b"<meta") {
        let start = from + at + b"<meta".len();
        if !lower
            .get(start)
            .is_some_and(|b| b.is_ascii_whitespace() || *b == b'/')
        {
            from = start;
            continue;
        }
        let end = lower[start..]
            .iter()
            .position(|b| *b == b'>')
            .map_or(lower.len(), |e| start + e);
        if let Some(value) = attribute_value(&prefix[start..end], &lower[start..end], b"charset") {
            return Some(value);
        }
        from = end;
    }
    None
}

/// Select the encoding of `body`.
///
/// Returns `None` for a response that is not text-like (`content_type` absent counts as
/// text-like), unless an override applies. An override that is not an honoured label is
/// ignored here: validate overrides up front with [`is_supported_label`].
#[must_use]
pub fn detect(
    content_type: Option<&str>,
    body: &[u8],
    override_label: Option<&str>,
) -> Option<CharsetEvidence> {
    let media = content_type.map(essence);
    if let Some(encoding) = override_label.and_then(lookup) {
        return Some(CharsetEvidence {
            label: encoding.name().to_ascii_lowercase(),
            source: CharsetSource::Override,
            declared: content_type.and_then(header_charset).map(|l| clean_label(&l)),
        });
    }
    let media_ref = media.as_deref().unwrap_or("");
    if media.is_some() && !is_text_like(media_ref) {
        return None;
    }
    let result = |encoding: &'static Encoding, source, declared: Option<String>| {
        let label = encoding.name().to_ascii_lowercase();
        let declared = declared.map(|d| clean_label(&d)).filter(|d| *d != label);
        Some(CharsetEvidence {
            label,
            source,
            declared,
        })
    };
    if let Some((encoding, _)) = Encoding::for_bom(body) {
        let declared = content_type.and_then(header_charset);
        return result(encoding, CharsetSource::Bom, declared);
    }
    let from_header = content_type.and_then(header_charset);
    if let Some(label) = &from_header {
        if let Some(encoding) = lookup(label) {
            return result(encoding, CharsetSource::Header, Some(label.clone()));
        }
    }
    if let Some(label) = prescan(media_ref, body) {
        if let Some(encoding) = lookup(&label) {
            return result(encoding, CharsetSource::Meta, Some(label));
        }
        return result(encoding_rs::UTF_8, CharsetSource::Default, Some(label));
    }
    result(encoding_rs::UTF_8, CharsetSource::Default, from_header)
}

fn resolve(evidence: &CharsetEvidence) -> &'static Encoding {
    lookup(&evidence.label).unwrap_or(encoding_rs::UTF_8)
}

/// Body without the byte-order mark that selected `evidence`'s encoding.
fn without_bom<'a>(body: &'a [u8], evidence: &CharsetEvidence) -> &'a [u8] {
    if evidence.source == CharsetSource::Bom {
        if let Some((_, len)) = Encoding::for_bom(body) {
            return &body[len..];
        }
    }
    body
}

/// Decode `body` strictly.
///
/// # Errors
/// [`DecodeError::Malformed`] when `body` is not valid in the selected encoding.
pub fn decode_strict<'a>(body: &'a [u8], evidence: &CharsetEvidence) -> Result<Cow<'a, str>, DecodeError> {
    let encoding = resolve(evidence);
    let body = without_bom(body, evidence);
    encoding
        .decode_without_bom_handling_and_without_replacement(body)
        .ok_or_else(|| DecodeError::Malformed {
            encoding: encoding.name().to_ascii_lowercase(),
            offset: (encoding == encoding_rs::UTF_8)
                .then(|| std::str::from_utf8(body).err().map(|e| e.valid_up_to()))
                .flatten(),
        })
}

/// Decode `body`, replacing invalid sequences with U+FFFD. The flag reports whether any
/// replacement happened.
#[must_use]
pub fn decode_lossy<'a>(body: &'a [u8], evidence: &CharsetEvidence) -> (Cow<'a, str>, bool) {
    resolve(evidence).decode_without_bom_handling(without_bom(body, evidence))
}

/// `content_type` with its `charset` parameter replaced by (or set to) `label`.
#[must_use]
pub fn with_charset(content_type: &str, label: &str) -> String {
    let mut parts = content_type.split(';');
    let mut out = parts.next().unwrap_or("").trim().to_owned();
    for param in parts {
        let keep = param
            .split_once('=')
            .is_none_or(|(name, _)| !name.trim().eq_ignore_ascii_case("charset"));
        if keep && !param.trim().is_empty() {
            out.push_str("; ");
            out.push_str(param.trim());
        }
    }
    out.push_str("; charset=");
    out.push_str(label);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const LATIN1_PAGE: &[u8] = b"<html><head><title>caf\xe9</title></head><body>na\xefve</body></html>";

    #[test]
    fn precedence_override_then_bom_then_header_then_meta_then_default() {
        let html = Some("text/html; charset=iso-8859-2");
        let over = detect(html, b"x", Some("shift_jis")).unwrap();
        assert_eq!(
            (over.label.as_str(), over.source),
            ("shift_jis", CharsetSource::Override)
        );
        assert_eq!(over.declared.as_deref(), Some("iso-8859-2"));

        let bom = detect(html, b"\xef\xbb\xbf<html>", None).unwrap();
        assert_eq!((bom.label.as_str(), bom.source), ("utf-8", CharsetSource::Bom));

        let header = detect(html, b"<meta charset=utf-8>", None).unwrap();
        assert_eq!(
            (header.label.as_str(), header.source),
            ("iso-8859-2", CharsetSource::Header)
        );

        let meta = detect(Some("text/html"), b"<html><meta charset=\"koi8-r\">", None).unwrap();
        assert_eq!(
            (meta.label.as_str(), meta.source),
            ("koi8-r", CharsetSource::Meta)
        );

        let none = detect(Some("text/html"), b"<html>", None).unwrap();
        assert_eq!(
            (none.label.as_str(), none.source),
            ("utf-8", CharsetSource::Default)
        );
    }

    #[test]
    fn http_equiv_meta_xml_declaration_and_attribute_forms() {
        let http_equiv = br#"<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">"#;
        let found = detect(Some("text/html"), http_equiv, None).unwrap();
        assert_eq!(
            (found.label.as_str(), found.source),
            ("windows-1252", CharsetSource::Meta)
        );
        assert_eq!(found.declared.as_deref(), Some("ISO-8859-1"));

        let xml = b"<?xml version=\"1.0\" encoding='windows-1251'?><r/>";
        let found = detect(Some("application/xml"), xml, None).unwrap();
        assert_eq!(
            (found.label.as_str(), found.source),
            ("windows-1251", CharsetSource::Meta)
        );

        // `<metadata>` is not a meta tag, and a declaration past the prescan window is ignored.
        assert_eq!(
            detect(Some("text/html"), b"<metadata charset=koi8-r>", None)
                .unwrap()
                .source,
            CharsetSource::Default
        );
        let mut late = vec![b' '; PRESCAN_BYTES];
        late.extend_from_slice(b"<meta charset=koi8-r>");
        assert_eq!(
            detect(Some("text/html"), &late, None).unwrap().source,
            CharsetSource::Default
        );
    }

    #[test]
    fn unknown_and_replacement_labels_are_recorded_never_honoured() {
        let unknown = detect(Some("text/html; charset=klingon"), b"x", None).unwrap();
        assert_eq!(
            (unknown.label.as_str(), unknown.source),
            ("utf-8", CharsetSource::Default)
        );
        assert_eq!(unknown.declared.as_deref(), Some("klingon"));
        let replacement = detect(Some("text/html; charset=iso-2022-kr"), b"x", None).unwrap();
        assert_eq!(replacement.label, "utf-8");
        assert!(!is_supported_label("hz-gb-2312"));
        assert!(!is_supported_label("klingon"));
        assert!(is_supported_label(" Shift_JIS "));
    }

    #[test]
    fn non_text_responses_have_no_charset_unless_overridden() {
        assert!(detect(Some("image/png"), b"\x89PNG", None).is_none());
        assert!(detect(Some("application/pdf"), b"%PDF", None).is_none());
        assert!(detect(Some("application/pdf"), b"%PDF", Some("utf-8")).is_some());
        assert!(detect(Some("application/ld+json"), b"{}", None).is_some());
        assert!(detect(None, b"abc", None).is_some());
    }

    #[test]
    fn wrong_charset_fixture_decodes_deterministically() {
        // Declared UTF-8 but the bytes are Latin-1: strict decoding refuses, with an offset.
        let wrong = detect(Some("text/html; charset=utf-8"), LATIN1_PAGE, None).unwrap();
        let error = decode_strict(LATIN1_PAGE, &wrong).unwrap_err();
        assert_eq!(
            error,
            DecodeError::Malformed {
                encoding: "utf-8".to_owned(),
                offset: Some(22)
            }
        );
        assert_eq!(error.to_string(), "body is not valid utf-8 at byte 22");
        let (lossy, had_errors) = decode_lossy(LATIN1_PAGE, &wrong);
        assert!(had_errors && lossy.contains('\u{fffd}'));

        // The override fixes it, identically on every run.
        let fixed = detect(Some("text/html; charset=utf-8"), LATIN1_PAGE, Some("iso-8859-1")).unwrap();
        assert_eq!(fixed.label, "windows-1252");
        let text = decode_strict(LATIN1_PAGE, &fixed).unwrap();
        assert!(text.contains("café") && text.contains("naïve"));
        assert_eq!(text, decode_strict(LATIN1_PAGE, &fixed).unwrap());
    }

    #[test]
    fn bom_is_stripped_and_utf16_decodes() {
        let evidence = detect(Some("text/plain"), b"\xef\xbb\xbfhi", None).unwrap();
        assert_eq!(decode_strict(b"\xef\xbb\xbfhi", &evidence).unwrap(), "hi");
        let utf16 = b"\xff\xfeh\x00i\x00";
        let evidence = detect(Some("text/plain"), utf16, None).unwrap();
        assert_eq!(evidence.label, "utf-16le");
        assert_eq!(decode_strict(utf16, &evidence).unwrap(), "hi");
    }

    #[test]
    fn mime_override_replaces_only_the_charset_parameter() {
        assert_eq!(with_charset("text/html", "utf-8"), "text/html; charset=utf-8");
        assert_eq!(
            with_charset("text/html; Charset=latin1; format=flowed", "utf-8"),
            "text/html; format=flowed; charset=utf-8"
        );
        assert_eq!(essence(" Text/HTML ; charset=x"), "text/html");
    }
}
