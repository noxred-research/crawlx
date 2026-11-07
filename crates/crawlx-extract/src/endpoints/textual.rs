//! Textual-response guard: only text-like bodies are regex-mined for
//! endpoints, so binary payloads never launder chance `./x` byte runs into
//! requests.
//!
//! Ported from projectdiscovery/katana `pkg/engine/parser/parser.go`
//! (`isTextualMediaType`, `isTextualResponse`) at commit 9662cd7 (MIT). The
//! magic-byte sniffer stands in for Go's `http.DetectContentType`: it knows
//! the binary formats the guard must exclude and otherwise falls back to the
//! "no control bytes → text" rule of the MIME sniffing algorithm.

/// Prefix the sniffer examines (same as Go's `sniffLen`).
pub const SNIFF_LEN: usize = 512;

/// Is `media_type` (lower-cased or not, without parameters) worth regex-scraping?
///
/// `+xml` / `+json` suffixes count deliberately: an SVG is XML text carrying
/// `href` attributes and possibly a `<script>`.
#[must_use]
pub fn is_textual_media_type(media_type: &str) -> bool {
    let mt = media_type.trim().to_ascii_lowercase();
    if mt.starts_with("text/") {
        return true;
    }
    matches!(
        mt.as_str(),
        "application/javascript"
            | "application/x-javascript"
            | "application/ecmascript"
            | "application/json"
            | "application/xml"
            | "application/xhtml+xml"
    ) || mt.ends_with("+json")
        || mt.ends_with("+xml")
}

/// Media type without parameters, lower-cased; `None` when empty.
#[must_use]
pub fn media_type_of(content_type: &str) -> Option<String> {
    let mt = content_type.split(';').next()?.trim();
    if mt.is_empty() {
        return None;
    }
    Some(mt.to_ascii_lowercase())
}

/// Should this body be regex-scraped for endpoints?
///
/// The declared `Content-Type` decides when present and specific. When it is
/// absent or the generic `application/octet-stream`, the body is sniffed
/// rather than skipped: untyped responses are common on embedded servers.
#[must_use]
pub fn is_textual(content_type: Option<&str>, body: &[u8]) -> bool {
    let declared = content_type.and_then(media_type_of);
    match declared {
        Some(mt) if mt != "application/octet-stream" => is_textual_media_type(&mt),
        _ => {
            if body.is_empty() {
                return false;
            }
            is_textual_media_type(sniff(body))
        }
    }
}

/// Media type guessed from the leading bytes of `body`.
///
/// Known binary signatures (PNG, JPEG, GIF, WEBP, PDF, ZIP, GZIP, ELF, WOFF,
/// WOFF2) are reported by their type; HTML and XML markers yield `text/html`
/// / `text/xml`; anything else is `text/plain` unless the prefix contains
/// control bytes, in which case it is `application/octet-stream`.
#[must_use]
pub fn sniff(body: &[u8]) -> &'static str {
    let head = &body[..body.len().min(SNIFF_LEN)];
    const SIGNATURES: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
        (b"%PDF-", "application/pdf"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b\x08", "application/x-gzip"),
        (b"\x7fELF", "application/octet-stream"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
    ];
    for (magic, mt) in SIGNATURES {
        if head.starts_with(magic) {
            return mt;
        }
    }
    if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return "image/webp";
    }
    // Byte-order marks mark text regardless of the bytes that follow.
    if head.starts_with(b"\xef\xbb\xbf") || head.starts_with(b"\xfe\xff") || head.starts_with(b"\xff\xfe") {
        return "text/plain";
    }
    let trimmed = skip_ws(head);
    if trimmed.starts_with(b"<?xml") {
        return "text/xml";
    }
    if starts_with_html_tag(trimmed) {
        return "text/html";
    }
    if head.iter().any(|&b| is_binary_byte(b)) {
        "application/octet-stream"
    } else {
        "text/plain"
    }
}

fn skip_ws(b: &[u8]) -> &[u8] {
    let n = b
        .iter()
        .take_while(|&&c| matches!(c, b'\t' | b'\n' | b'\x0c' | b'\r' | b' '))
        .count();
    &b[n..]
}

fn is_binary_byte(b: u8) -> bool {
    matches!(b, 0x00..=0x08 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f)
}

fn starts_with_html_tag(b: &[u8]) -> bool {
    const TAGS: &[&[u8]] = &[
        b"<!DOCTYPE HTML",
        b"<HTML",
        b"<HEAD",
        b"<SCRIPT",
        b"<IFRAME",
        b"<H1",
        b"<DIV",
        b"<FONT",
        b"<TABLE",
        b"<A",
        b"<STYLE",
        b"<TITLE",
        b"<B",
        b"<BODY",
        b"<BR",
        b"<P",
        b"<!--",
    ];
    TAGS.iter().any(|tag| {
        b.len() > tag.len()
            && b[..tag.len()].eq_ignore_ascii_case(tag)
            && matches!(b[tag.len()], b' ' | b'>' | b'\n' | b'\r' | b'\t' | b'/')
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn declared_types() {
        assert!(is_textual(Some("text/html; charset=utf-8"), b""));
        assert!(is_textual(Some("image/svg+xml"), b""));
        assert!(is_textual(Some("application/ld+json"), b""));
        assert!(!is_textual(Some("image/png"), b"<a href=/x>"));
        assert!(!is_textual(Some("application/pdf"), b"%PDF-"));
    }

    #[test]
    fn sniffed_types() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n\0\0"), "image/png");
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), "image/webp");
        assert_eq!(sniff(b"wOF2abc"), "font/woff2");
        assert_eq!(sniff(b"  <!doctype html><html>"), "text/html");
        assert_eq!(sniff(b"var a = './x';"), "text/plain");
        assert_eq!(sniff(b"abc\0def"), "application/octet-stream");
        assert!(!is_textual(None, b"\x89PNG\r\n\x1a\n./x"));
        assert!(is_textual(None, b"plain text ./x"));
        assert!(is_textual(Some("application/octet-stream"), b"plain text"));
        assert!(!is_textual(None, b""));
    }
}
