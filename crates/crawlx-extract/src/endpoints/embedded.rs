//! Bounded, offline discovery inside SVG data images and conditional comments.
//!
//! Only image references become proposals. Scripts, event handlers, entities, DTDs and
//! external resources are never executed or loaded. Refused children yield no proposals.

use std::borrow::Cow;

use base64::Engine as _;
use quick_xml::{events::Event, Reader};
use url::Url;

use super::{body::IMG_DATA, Confidence, DiscoveredEndpoint};

pub(super) const MAX_SOURCE_BYTES: usize = 64 * 1024;
const MAX_TOTAL_BYTES: usize = 256 * 1024;
const MAX_CHILDREN: usize = 32;
const MAX_NESTING: usize = 4;
const MAX_CANDIDATES: usize = 128;
const MAX_XML_EVENTS: usize = 8192;
const MAX_XML_DEPTH: usize = 64;

/// Shared across all embedded children of one response, not reset per image.
pub(super) struct Budget {
    bytes: usize,
    children: usize,
    candidates: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            bytes: MAX_TOTAL_BYTES,
            children: MAX_CHILDREN,
            candidates: MAX_CANDIDATES,
        }
    }
}

impl Budget {
    pub(super) fn admit(&mut self, bytes: usize) -> bool {
        if bytes > MAX_SOURCE_BYTES || bytes > self.bytes || self.children == 0 {
            return false;
        }
        self.bytes -= bytes;
        self.children -= 1;
        true
    }

    pub(super) fn image(&mut self, raw: &str, base: &Url, depth: u32, out: &mut Vec<DiscoveredEndpoint>) {
        self.nested_image(raw, base, depth, 0, out);
    }

    fn nested_image(
        &mut self,
        raw: &str,
        base: &Url,
        depth: u32,
        nesting: usize,
        out: &mut Vec<DiscoveredEndpoint>,
    ) {
        if nesting >= MAX_NESTING || !self.admit(raw.len()) {
            return;
        }
        let Some(xml) = decode_svg(raw) else { return };
        let start = out.len();
        // Validate to EOF before keeping proposals, including DTDs after an image.
        if self.svg(&xml, base, depth, nesting, out).is_none() {
            out.truncate(start);
        }
    }

    fn svg(
        &mut self,
        xml: &str,
        base: &Url,
        depth: u32,
        nesting: usize,
        out: &mut Vec<DiscoveredEndpoint>,
    ) -> Option<()> {
        let mut reader = Reader::from_str(xml);
        let mut level = 0usize;
        let mut root_seen = false;
        for _ in 0..MAX_XML_EVENTS {
            let event = reader.read_event().ok()?;
            let empty = matches!(&event, Event::Empty(_));
            match event {
                Event::Start(e) | Event::Empty(e) => {
                    if level == 0 {
                        if root_seen || e.name().into_inner().rsplit(':').next() != Some("svg") {
                            return None;
                        }
                        root_seen = true;
                    }
                    if !empty {
                        level = level.checked_add(1)?;
                        if level > MAX_XML_DEPTH {
                            return None;
                        }
                    }
                    for attribute in e.attributes() {
                        let attribute = attribute.ok()?;
                        let value = quick_xml::escape::unescape_with(
                            &attribute.value,
                            quick_xml::escape::resolve_xml_entity,
                        )
                        .ok()?;
                        if e.name().into_inner().rsplit(':').next() != Some("image")
                            || attribute.key.into_inner().rsplit(':').next() != Some("href")
                        {
                            continue;
                        }
                        if value.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("data:")) {
                            self.nested_image(&value, base, depth, nesting.saturating_add(1), out);
                        } else if self.candidates > 0 {
                            if let Some(endpoint) =
                                DiscoveredEndpoint::get(base, &value, IMG_DATA, Confidence::Structural, depth)
                            {
                                self.candidates -= 1;
                                out.push(endpoint);
                            }
                        }
                    }
                }
                Event::End(_) => level = level.checked_sub(1)?,
                Event::DocType(_) | Event::GeneralRef(_) => return None,
                Event::Eof => return (root_seen && level == 0).then_some(()),
                _ => {}
            }
        }
        None
    }
}

/// Recognize only complete conditional wrappers, not arbitrary HTML comments.
pub(super) fn conditional(comment: &str) -> Option<&str> {
    let comment = comment.trim();
    if !comment.get(..4)?.eq_ignore_ascii_case("[if ") {
        return None;
    }
    let (condition, body) = comment.split_once("]>")?;
    if condition.len() > 128 || !condition.is_ascii() {
        return None;
    }
    let suffix = body.len().checked_sub("<![endif]".len())?;
    if !body.get(suffix..)?.eq_ignore_ascii_case("<![endif]") {
        return None;
    }
    body.get(..suffix)
}

fn decode_svg(raw: &str) -> Option<Cow<'_, str>> {
    let (header, payload) = raw.trim().split_once(',')?;
    let mut parts = header.split(';');
    if !parts.next()?.eq_ignore_ascii_case("data:image/svg+xml") {
        return None;
    }
    let mut base64 = false;
    for part in parts {
        if part.eq_ignore_ascii_case("base64") && !base64 {
            base64 = true;
        } else if !part.eq_ignore_ascii_case("charset=utf-8") {
            return None;
        }
    }
    let payload = percent_decode(payload)?;
    if base64 {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload.as_bytes())
            .ok()?;
        String::from_utf8(bytes).ok().map(Cow::Owned)
    } else {
        Some(payload)
    }
}

fn percent_decode(raw: &str) -> Option<Cow<'_, str>> {
    if !raw.contains('%') {
        return Some(Cow::Borrowed(raw));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(raw.len()).ok()?;
    let mut input = raw.bytes();
    while let Some(byte) = input.next() {
        if byte == b'%' {
            let high = char::from(input.next()?).to_digit(16)?;
            let low = char::from(input.next()?).to_digit(16)?;
            bytes.push(u8::try_from(high * 16 + low).ok()?);
        } else {
            bytes.push(byte);
        }
    }
    String::from_utf8(bytes).ok().map(Cow::Owned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn encoded(xml: &str) -> String {
        format!(
            "data:image/svg+xml;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(xml)
        )
    }

    fn image(href: &str) -> String {
        format!("<svg xmlns='http://www.w3.org/2000/svg'><image href='{href}'/></svg>")
    }

    fn urls(raw: &str) -> Vec<String> {
        let mut out = Vec::new();
        Budget::default().image(
            raw,
            &Url::parse("https://fixture.test/base/").unwrap(),
            7,
            &mut out,
        );
        assert!(out
            .iter()
            .all(|e| e.method == http::Method::GET && e.body.is_none() && e.depth == 8));
        out.into_iter().map(|e| e.url.to_string()).collect()
    }

    #[test]
    fn raw_percent_base64_and_nested_svg_produce_only_http_proposals() {
        let xml = image("../target?q=1&amp;k=2");
        let expected = vec!["https://fixture.test/target?q=1&k=2"];
        assert_eq!(urls(&format!("data:image/svg+xml,{xml}")), expected);
        assert_eq!(
            urls("DATA:image/svg+xml,%3Csvg%3E%3Cimage%20href%3D%27../target?q=1%26amp;k=2%27/%3E%3C/svg%3E"),
            expected
        );
        assert_eq!(urls(&encoded(&xml)), expected);
        assert_eq!(urls(&encoded(&image(&encoded(&xml)))), expected);
    }

    #[test]
    fn scripts_entities_invalid_markup_and_non_image_payloads_are_refused() {
        for raw in [
            "data:text/html,<a href='/refused'>x</a>",
            "data:image/png,<svg><image href='/refused'/></svg>",
            "data:image/svg+xml;unsupported=1,<svg><image href='/refused'/></svg>",
            "data:image/svg+xml;base64,%%%%",
            "data:image/svg+xml,%GG",
            "data:image/svg+xml,%ff",
            "data:image/svg+xml,<svg><image href='/refused'></svg>",
            "data:image/svg+xml,<!DOCTYPE svg SYSTEM 'https://outside.test/dtd'><svg><image href='/refused'/></svg>",
            "data:image/svg+xml,<svg><image href='/refused'/><!DOCTYPE svg></svg>",
            "data:image/svg+xml,<svg><image href='&external;'/></svg>",
        ] {
            assert!(urls(raw).is_empty(), "{raw}");
        }
        assert!(urls(&encoded("<svg onload=\"fetch('/event')\"><script href='/script'>fetch('/run')</script><foreignObject><a href='/anchor'>x</a></foreignObject></svg>")).is_empty());
        for href in [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://fixture.test/file",
            "data:text/html,unsafe",
            "#fragment",
        ] {
            assert!(urls(&encoded(&image(href))).is_empty(), "{href}");
        }
    }

    #[test]
    fn size_depth_child_and_candidate_caps_apply_across_one_response() {
        let oversized = format!(
            "data:image/svg+xml,{}{}",
            " ".repeat(MAX_SOURCE_BYTES),
            image("/large")
        );
        assert!(urls(&oversized).is_empty());
        let mut nested = encoded(&image("/deep"));
        for _ in 1..MAX_NESTING {
            nested = encoded(&image(&nested));
        }
        assert_eq!(urls(&nested), ["https://fixture.test/deep"]);
        assert!(urls(&encoded(&image(&nested))).is_empty());

        let base = Url::parse("https://fixture.test/").unwrap();
        let raw = encoded(&image("/child"));
        let mut budget = Budget::default();
        let mut out = Vec::new();
        for _ in 0..MAX_CHILDREN + 1 {
            budget.image(&raw, &base, 0, &mut out);
        }
        assert_eq!(out.len(), MAX_CHILDREN);

        let many = format!(
            "<svg>{}</svg>",
            "<image href='/many'/>".repeat(MAX_CANDIDATES + 1)
        );
        assert_eq!(urls(&encoded(&many)).len(), MAX_CANDIDATES);
        let mut budget = Budget::default();
        for _ in 0..MAX_TOTAL_BYTES / MAX_SOURCE_BYTES {
            assert!(budget.admit(MAX_SOURCE_BYTES));
        }
        assert!(!budget.admit(1));
    }

    #[test]
    fn only_complete_bounded_conditional_wrappers_are_recognized() {
        assert_eq!(
            conditional("[if IE]><link href='/ok'><![endif]"),
            Some("<link href='/ok'>")
        );
        assert_eq!(
            conditional(" [IF lt IE 9]><img src='/ok'><![ENDIF] "),
            Some("<img src='/ok'>")
        );
        for comment in [
            "<link href='/ordinary'>",
            "[if IE]><link href='/incomplete'>",
            "[if IE]><link href='/x'><![endif]extra",
        ] {
            assert!(conditional(comment).is_none());
        }
    }
    #[test]
    fn xml_event_and_structure_limits_refuse_the_entire_child() {
        let deep = format!(
            "<svg>{}{}{} </svg>",
            "<g>".repeat(MAX_XML_DEPTH),
            "<image href='/deep'/>",
            "</g>".repeat(MAX_XML_DEPTH)
        );
        assert!(urls(&encoded(&deep)).is_empty());
        let many_events = format!(
            "<svg>{}<image href='/late'/></svg>",
            "<g/>".repeat(MAX_XML_EVENTS)
        );
        assert!(urls(&encoded(&many_events)).is_empty());
    }
}
