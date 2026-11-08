//! Sitemap parsing (sitemaps.org protocol).
//!
//! [`SitemapParser::parse`] reads one document with `quick-xml`: `urlset`,
//! `sitemapindex` or the plain-text format. DTD entities are never expanded,
//! memory is bounded by [`MAX_URLS`] entries, and gzip input is only
//! *detected* (`SitemapDoc::gzip`); the caller decompresses with its own
//! ratio cap. [`SitemapTraversal`] walks nested indexes with the depth
//! ([`MAX_DEPTH`]) and total-URL ([`MAX_URLS`]) bounds while leaving the
//! fetching to the caller.

use std::collections::BTreeSet;

use chrono::{DateTime, NaiveDate, Utc};
use crawlx_core::time::Timestamp;
use quick_xml::events::Event;
use quick_xml::name::ResolveResult;
use quick_xml::reader::NsReader;

use crate::error::UrlError;

/// Maximum index nesting depth (root document is depth 0).
pub const MAX_DEPTH: usize = 5;
/// Maximum URLs collected (per document and per traversal).
pub const MAX_URLS: usize = 50_000;
const MAX_LOC_LEN: usize = 2048;
const MAX_XML_DEPTH: usize = 64;

/// Document flavour.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SitemapKind {
    /// `<urlset>` of page URLs.
    UrlSet,
    /// `<sitemapindex>` pointing at nested sitemaps.
    Index,
    /// One URL per line.
    Text,
    /// Gzip magic detected; nothing was parsed.
    Gzip,
}

/// One `<url>` entry.
#[derive(Clone, PartialEq, Debug)]
pub struct SitemapUrl {
    /// `<loc>` as written (not yet resolved or canonicalized).
    pub loc: String,
    /// `<lastmod>` when present and parseable.
    pub lastmod: Option<Timestamp>,
    /// `<priority>` in `0.0..=1.0`; only a frontier tie-break.
    pub priority: Option<f32>,
    /// `<changefreq>` hint as written (e.g. `daily`).
    pub changefreq: Option<String>,
    /// Explicit XHTML alternate-language variants, still subject to URL admission.
    pub hreflang: Vec<SitemapVariant>,
}

/// One namespace-checked XHTML alternate in a sitemap URL entry.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SitemapVariant {
    /// Language hint exactly as declared; not verified document language.
    pub language: String,
    /// Original alternate location, never an authorization exemption.
    pub loc: String,
}

/// One `<sitemap>` entry of an index.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SitemapRef {
    /// `<loc>` of the nested sitemap, as written.
    pub loc: String,
    /// `<lastmod>` when present and parseable.
    pub lastmod: Option<Timestamp>,
}

/// Parsed document.
#[derive(Clone, PartialEq, Debug)]
pub struct SitemapDoc {
    /// Flavour of the parsed document.
    pub kind: SitemapKind,
    /// `<url>` entries (or text-format lines), capped at the entry limit.
    pub urls: Vec<SitemapUrl>,
    /// Nested sitemap locations (index documents).
    pub nested: Vec<SitemapRef>,
    /// The input starts with the gzip magic bytes; decompress and parse again.
    pub gzip: bool,
    /// The entry cap was hit.
    pub truncated: bool,
    /// The XML ended with an error after a usable prefix was read.
    pub malformed: bool,
}

impl SitemapDoc {
    fn empty(kind: SitemapKind) -> Self {
        Self {
            kind,
            urls: Vec::new(),
            nested: Vec::new(),
            gzip: false,
            truncated: false,
            malformed: false,
        }
    }
}

/// Stateless parser.
pub struct SitemapParser;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    UrlSet,
    SitemapIndex,
    Url,
    Sitemap,
    Loc,
    Lastmod,
    Priority,
    Changefreq,
    Other,
}

fn classify_tag(local: &str) -> Tag {
    match local {
        "urlset" => Tag::UrlSet,
        "sitemapindex" => Tag::SitemapIndex,
        "url" => Tag::Url,
        "sitemap" => Tag::Sitemap,
        "loc" => Tag::Loc,
        "lastmod" => Tag::Lastmod,
        "priority" => Tag::Priority,
        "changefreq" => Tag::Changefreq,
        _ => Tag::Other,
    }
}

#[derive(Default)]
struct Entry {
    loc: Option<String>,
    lastmod: Option<String>,
    priority: Option<String>,
    changefreq: Option<String>,
    hreflang: Vec<SitemapVariant>,
}

// Keep literal whitespace unchanged while resolving only XML's built-in references.
fn attribute_text<'a>(
    attribute: &'a quick_xml::events::attributes::Attribute<'_>,
) -> Result<std::borrow::Cow<'a, str>, quick_xml::Error> {
    let raw: &str = &attribute.value;
    Ok(quick_xml::escape::unescape_with(
        raw,
        quick_xml::escape::resolve_xml_entity,
    )?)
}

impl SitemapParser {
    /// Parse one (already decompressed) sitemap document.
    ///
    /// # Errors
    /// Same as [`Self::parse_limited`].
    pub fn parse(bytes: &[u8]) -> Result<SitemapDoc, UrlError> {
        Self::parse_limited(bytes, MAX_URLS)
    }

    /// Parse with an explicit entry cap.
    ///
    /// # Errors
    /// Returns [`UrlError::Sitemap`] when the document is empty or its XML is malformed.
    pub fn parse_limited(bytes: &[u8], max_entries: usize) -> Result<SitemapDoc, UrlError> {
        if bytes.len() > 8_388_608 {
            return Err(UrlError::Sitemap("document byte limit exceeded".into()));
        }
        if bytes.starts_with(&[0x1f, 0x8b]) {
            let mut d = SitemapDoc::empty(SitemapKind::Gzip);
            d.gzip = true;
            return Ok(d);
        }
        let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(bytes);
        match bytes.iter().find(|b| !b.is_ascii_whitespace()) {
            None => Err(UrlError::Sitemap("empty document".into())),
            Some(b'<') => Self::parse_xml(bytes, max_entries),
            Some(_) => Ok(Self::parse_text(bytes, max_entries)),
        }
    }

    fn parse_text(bytes: &[u8], max_entries: usize) -> SitemapDoc {
        let mut doc = SitemapDoc::empty(SitemapKind::Text);
        for line in String::from_utf8_lossy(bytes).lines() {
            let line = line.trim();
            if !valid_loc(line) {
                continue;
            }
            if doc.urls.len() >= max_entries {
                doc.truncated = true;
                break;
            }
            doc.urls.push(SitemapUrl {
                loc: line.to_owned(),
                lastmod: None,
                priority: None,
                changefreq: None,
                hreflang: Vec::new(),
            });
        }
        doc
    }

    fn parse_xml(bytes: &[u8], max_entries: usize) -> Result<SitemapDoc, UrlError> {
        let mut reader = NsReader::from_reader(bytes);
        reader.config_mut().expand_empty_elements = true;

        let mut doc: Option<SitemapDoc> = None;
        let mut stack: Vec<Tag> = Vec::new();
        let mut entry = Entry::default();
        // Keep spaces around references until the complete field can be trimmed.
        let mut text = String::new();
        loop {
            let ev = match reader.read_event() {
                Ok(ev) => ev,
                Err(e) => {
                    return match doc {
                        Some(mut d) => {
                            d.malformed = true;
                            Ok(d)
                        }
                        None => Err(UrlError::Sitemap(e.to_string())),
                    };
                }
            };
            if !matches!(&ev, Event::Text(_) | Event::GeneralRef(_) | Event::CData(_)) {
                assign_text(&stack, &mut entry, &text);
                text.clear();
            }
            match ev {
                Event::Start(e) => {
                    for attribute in e.attributes() {
                        let attribute = attribute.map_err(|error| UrlError::Sitemap(error.to_string()))?;
                        attribute_text(&attribute).map_err(|error| UrlError::Sitemap(error.to_string()))?;
                    }
                    let tag = match reader.resolver().resolve_element(e.name()).0 {
                        ResolveResult::Unbound => classify_tag(e.local_name().as_ref()),
                        ResolveResult::Bound(namespace)
                            if namespace.as_ref() == "http://www.sitemaps.org/schemas/sitemap/0.9" =>
                        {
                            classify_tag(e.local_name().as_ref())
                        }
                        ResolveResult::Unknown(_) => {
                            return Err(UrlError::Sitemap("unbound namespace prefix".into()))
                        }
                        _ => Tag::Other,
                    };
                    if e.local_name().as_ref() == "link" && stack.last() == Some(&Tag::Url) {
                        let (namespace, _) = reader.resolver().resolve_element(e.name());
                        if matches!(namespace, ResolveResult::Bound(ns) if ns.as_ref() == "http://www.w3.org/1999/xhtml")
                        {
                            let mut rel = None;
                            let mut language = None;
                            let mut href = None;
                            for attribute in e.attributes() {
                                let attribute =
                                    attribute.map_err(|error| UrlError::Sitemap(error.to_string()))?;
                                let value = attribute_text(&attribute)
                                    .map_err(|error| UrlError::Sitemap(error.to_string()))?
                                    .into_owned();
                                match attribute.key.as_ref() {
                                    "rel" => rel = Some(value),
                                    "hreflang" => language = Some(value),
                                    "href" => href = Some(value),
                                    _ => {}
                                }
                            }
                            if rel.as_deref() == Some("alternate") && entry.hreflang.len() < 16 {
                                if let (Some(language), Some(loc)) = (
                                    language.filter(|language| !language.is_empty() && language.len() <= 64),
                                    href.filter(|href| valid_loc(href)),
                                ) {
                                    entry.hreflang.push(SitemapVariant { language, loc });
                                }
                            }
                        }
                    }
                    if doc.is_none() {
                        doc = Some(match tag {
                            Tag::UrlSet => SitemapDoc::empty(SitemapKind::UrlSet),
                            Tag::SitemapIndex => SitemapDoc::empty(SitemapKind::Index),
                            _ => {
                                return Err(UrlError::Sitemap(
                                    "root element is neither urlset nor sitemapindex".into(),
                                ))
                            }
                        });
                    }
                    if stack.len() >= MAX_XML_DEPTH {
                        if let Some(d) = doc.as_mut() {
                            d.malformed = true;
                        }
                        break;
                    }
                    if matches!(tag, Tag::Url | Tag::Sitemap) {
                        entry = Entry::default();
                    }
                    stack.push(tag);
                }
                Event::End(_) => {
                    let Some(done) = stack.pop() else { continue };
                    if !matches!(done, Tag::Url | Tag::Sitemap) {
                        continue;
                    }
                    let Some(d) = doc.as_mut() else { continue };
                    let e = std::mem::take(&mut entry);
                    let Some(loc) = e.loc.filter(|l| valid_loc(l)) else {
                        continue;
                    };
                    if d.urls.len() + d.nested.len() >= max_entries {
                        d.truncated = true;
                        break;
                    }
                    let lastmod = e.lastmod.as_deref().and_then(parse_lastmod);
                    if done == Tag::Url {
                        d.urls.push(SitemapUrl {
                            loc,
                            lastmod,
                            priority: e
                                .priority
                                .and_then(|p| p.trim().parse::<f32>().ok())
                                .filter(|p| (0.0..=1.0).contains(p)),
                            changefreq: e.changefreq,
                            hreflang: e.hreflang,
                        });
                    } else {
                        d.nested.push(SitemapRef { loc, lastmod });
                    }
                }
                Event::Text(part) => {
                    text.push_str(&part);
                }
                Event::GeneralRef(reference) => {
                    if let Some(ch) = reference
                        .resolve_char_ref()
                        .map_err(|error| UrlError::Sitemap(error.to_string()))?
                    {
                        text.push(ch);
                    } else {
                        let name: &str = &reference;
                        text.push_str(
                            quick_xml::escape::resolve_xml_entity(name).ok_or_else(|| {
                                UrlError::Sitemap("custom XML entities are forbidden".into())
                            })?,
                        );
                    }
                }
                Event::CData(part) => {
                    text.push_str(&part);
                }
                Event::DocType(_) => {
                    return Err(UrlError::Sitemap(
                        "DTD and entity declarations are forbidden".into(),
                    ))
                }
                Event::Eof => break,
                _ => {}
            }
        }
        doc.ok_or_else(|| UrlError::Sitemap("no root element".into()))
    }
}

fn assign_text(stack: &[Tag], entry: &mut Entry, text: &str) {
    let [.., parent, field] = stack else { return };
    if !matches!(parent, Tag::Url | Tag::Sitemap) {
        return;
    }
    let text = text.trim();
    let slot = match field {
        Tag::Loc => &mut entry.loc,
        Tag::Lastmod => &mut entry.lastmod,
        Tag::Priority => &mut entry.priority,
        Tag::Changefreq => &mut entry.changefreq,
        _ => return,
    };
    if slot.is_none() && !text.is_empty() && text.len() <= MAX_LOC_LEN {
        *slot = Some(text.to_owned());
    }
}

fn valid_loc(l: &str) -> bool {
    let l = l.trim();
    if l.len() > MAX_LOC_LEN {
        return false;
    }
    let starts = |p: &str| l.get(..p.len()).is_some_and(|h| h.eq_ignore_ascii_case(p));
    starts("https://") || starts("http://")
}

/// W3C datetime subset: RFC 3339, `YYYY-MM-DDThh:mm±hh:mm`, `YYYY-MM-DD`.
#[must_use]
pub fn parse_lastmod(s: &str) -> Option<Timestamp> {
    let s = s.trim();
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Some(d.with_timezone(&Utc));
    }
    if let Ok(d) = DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M%:z") {
        return Some(d.with_timezone(&Utc));
    }
    if let Some(naive) = s
        .strip_suffix('Z')
        .and_then(|t| chrono::NaiveDateTime::parse_from_str(t, "%Y-%m-%dT%H:%M").ok())
    {
        return Some(naive.and_utc());
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|n| n.and_utc())
}

/// A nested sitemap still to fetch.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PendingSitemap {
    /// Absolute or relative `<loc>` of the nested sitemap, as written.
    pub loc: String,
    /// Nesting depth of the nested sitemap (the root document is 0).
    pub depth: usize,
}

/// Bounded walk over nested sitemap indexes. The caller fetches and
/// decompresses; each document is passed to [`Self::ingest`], which returns
/// the nested documents to fetch next.
#[derive(Debug, Default)]
pub struct SitemapTraversal {
    urls: Vec<SitemapUrl>,
    visited: BTreeSet<String>,
    skipped_depth: usize,
    truncated: bool,
    documents: usize,
}

impl SitemapTraversal {
    /// Empty traversal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the root location visited (cycle guard) and ingest its bytes.
    ///
    /// # Errors
    /// Same as [`Self::ingest`].
    pub fn ingest_root(&mut self, loc: &str, bytes: &[u8]) -> Result<Vec<PendingSitemap>, UrlError> {
        self.visited.insert(loc.to_owned());
        self.ingest(bytes, 0)
    }

    /// Ingest a document at `depth` (root is 0). Documents that were still
    /// gzip-compressed are rejected.
    ///
    /// # Errors
    /// Returns [`UrlError::Sitemap`] for gzip-compressed or unparseable documents.
    pub fn ingest(&mut self, bytes: &[u8], depth: usize) -> Result<Vec<PendingSitemap>, UrlError> {
        self.ingest_limited(bytes, depth, MAX_URLS)
    }

    /// Ingest through the existing traversal with a smaller per-document entry ceiling.
    ///
    /// # Errors
    /// Returns [`UrlError::Sitemap`] for compressed, malformed or forbidden DTD input.
    pub fn ingest_limited(
        &mut self,
        bytes: &[u8],
        depth: usize,
        max_entries: usize,
    ) -> Result<Vec<PendingSitemap>, UrlError> {
        let doc = SitemapParser::parse_limited(bytes, max_entries.min(MAX_URLS))?;
        if doc.malformed {
            return Err(UrlError::Sitemap("malformed sitemap source".into()));
        }
        if doc.gzip {
            return Err(UrlError::Sitemap(
                "document is gzip-compressed; decompress before ingest".into(),
            ));
        }
        self.documents += 1;
        let room = MAX_URLS.saturating_sub(self.urls.len());
        if doc.urls.len() > room {
            self.truncated = true;
        }
        self.urls.extend(doc.urls.into_iter().take(room));
        if doc.truncated {
            self.truncated = true;
        }
        if depth >= MAX_DEPTH {
            self.skipped_depth += doc.nested.len();
            return Ok(Vec::new());
        }
        let mut pending = Vec::new();
        for n in doc.nested {
            if self.visited.insert(n.loc.clone()) {
                pending.push(PendingSitemap {
                    loc: n.loc,
                    depth: depth + 1,
                });
            }
        }
        Ok(pending)
    }

    /// Collected URLs (at most [`MAX_URLS`]).
    #[must_use]
    pub fn urls(&self) -> &[SitemapUrl] {
        &self.urls
    }

    /// Consume into the collected URLs.
    #[must_use]
    pub fn into_urls(self) -> Vec<SitemapUrl> {
        self.urls
    }

    /// Nested sitemaps not followed because of the depth bound.
    #[must_use]
    pub const fn skipped_for_depth(&self) -> usize {
        self.skipped_depth
    }

    /// The URL cap truncated the result.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }

    /// Documents ingested so far.
    #[must_use]
    pub const fn documents(&self) -> usize {
        self.documents
    }

    /// Can more URLs be accepted?
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.urls.len() < MAX_URLS
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeMap;

    const URLSET: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1">
  <url><loc>https://example.com/a?x=1&amp;y=2</loc><lastmod>2024-05-01</lastmod><changefreq>daily</changefreq><priority>0.8</priority>
    <image:image><image:loc>https://example.com/img.png</image:loc></image:image></url>
  <url><loc><![CDATA[https://example.com/b]]></loc><lastmod>2024-05-01T10:30:00+02:00</lastmod></url>
  <url><loc>ftp://example.com/skip</loc></url>
  <url><lastmod>2024-01-01</lastmod></url>
</urlset>"#;

    #[test]
    fn parses_urlset() {
        let d = SitemapParser::parse(URLSET.as_bytes()).unwrap();
        assert_eq!(d.kind, SitemapKind::UrlSet);
        assert_eq!(d.urls.len(), 2);
        assert_eq!(d.urls[0].loc, "https://example.com/a?x=1&y=2");
        assert_eq!(d.urls[0].priority, Some(0.8));
        assert_eq!(d.urls[0].changefreq.as_deref(), Some("daily"));
        assert_eq!(
            d.urls[0].lastmod.unwrap().to_rfc3339(),
            "2024-05-01T00:00:00+00:00"
        );
        assert_eq!(d.urls[1].loc, "https://example.com/b");
        assert_eq!(
            d.urls[1].lastmod.unwrap().to_rfc3339(),
            "2024-05-01T08:30:00+00:00"
        );
        assert!(!d.gzip && !d.truncated && !d.malformed);
    }
    #[test]
    fn references_preserve_complete_sitemap_fields() {
        let d = SitemapParser::parse(
            br#"<urlset><url><loc> https://example.test/?q=a&#32;b&amp;n=&#x32; </loc><lastmod>2026-11-0&#54;</lastmod><priority>0.&#56;</priority><changefreq>dai&#108;y</changefreq></url></urlset>"#,
        ).unwrap();
        assert_eq!(d.urls[0].loc, "https://example.test/?q=a b&n=2");
        assert_eq!(
            d.urls[0].lastmod.unwrap().to_rfc3339(),
            "2026-11-06T00:00:00+00:00"
        );
        assert_eq!(d.urls[0].priority, Some(0.8));
        assert_eq!(d.urls[0].changefreq.as_deref(), Some("daily"));
        for bytes in [
            br#"<urlset><url><loc>https://example.test/&custom;</loc></url></urlset>"#.as_slice(),
            br#"<urlset><url><loc>https://example.test/&#x110000;</loc></url></urlset>"#.as_slice(),
            br#"<urlset duplicate="1" duplicate="2"/>"#.as_slice(),
        ] {
            assert!(SitemapParser::parse(bytes).is_err());
        }
    }

    #[test]
    fn parses_index_and_text_and_gzip() {
        let idx = r#"<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>https://example.com/s1.xml</loc><lastmod>2024-01-01T00:00:00Z</lastmod></sitemap>
          <sitemap><loc>https://example.com/s2.xml.gz</loc></sitemap></sitemapindex>"#;
        let d = SitemapParser::parse(idx.as_bytes()).unwrap();
        assert_eq!(d.kind, SitemapKind::Index);
        assert!(d.urls.is_empty());
        assert_eq!(d.nested.len(), 2);
        assert_eq!(d.nested[1].loc, "https://example.com/s2.xml.gz");

        let t = SitemapParser::parse(b"https://a.example/1\nnot a url\n  http://a.example/2  \n").unwrap();
        assert_eq!(t.kind, SitemapKind::Text);
        assert_eq!(t.urls.len(), 2);

        let g = SitemapParser::parse(&[0x1f, 0x8b, 8, 0, 0]).unwrap();
        assert!(g.gzip);
        assert_eq!(g.kind, SitemapKind::Gzip);
    }

    #[test]
    fn rejects_non_sitemaps_and_keeps_prefix_of_broken_xml() {
        assert!(SitemapParser::parse(b"<html><body/></html>").is_err());
        assert!(SitemapParser::parse(b"   ").is_err());
        let broken = b"<urlset><url><loc>https://a.example/1</loc></url><url><loc>https://a.example/2</loc></oops></urlset>";
        let d = SitemapParser::parse(broken).unwrap();
        assert_eq!(d.urls.len(), 1);
        assert!(d.malformed);
    }

    #[test]
    fn entity_declarations_reject_the_entire_document() {
        let xml = r#"<!DOCTYPE urlset [<!ENTITY big "AAAAAAAAAA">]><urlset><url><loc>https://a.example/&big;</loc></url></urlset>"#;
        let error = SitemapParser::parse(xml.as_bytes()).unwrap_err();
        assert!(matches!(&error, UrlError::Sitemap(reason)
            if reason == "DTD and entity declarations are forbidden"));
    }

    #[test]
    fn entry_cap_truncates() {
        let mut xml = String::from("<urlset>");
        for i in 0..20 {
            xml.push_str(&format!("<url><loc>https://a.example/{i}</loc></url>"));
        }
        xml.push_str("</urlset>");
        let d = SitemapParser::parse_limited(xml.as_bytes(), 5).unwrap();
        assert_eq!(d.urls.len(), 5);
        assert!(d.truncated);
    }

    #[test]
    fn traversal_is_depth_bounded_and_cycle_safe() {
        // chain: s0 -> s1 -> ... -> s9, each also lists itself (cycle) and one url
        let mut docs: BTreeMap<String, String> = BTreeMap::new();
        for i in 0..10 {
            docs.insert(
                format!("https://a.example/s{i}.xml"),
                format!(
                    "<sitemapindex><sitemap><loc>https://a.example/s{i}.xml</loc></sitemap><sitemap><loc>https://a.example/s{}.xml</loc></sitemap></sitemapindex>",
                    i + 1
                ),
            );
        }
        let mut t = SitemapTraversal::new();
        let root = "https://a.example/s0.xml";
        let mut queue = t.ingest_root(root, docs[root].as_bytes()).unwrap();
        let mut max_depth = 0;
        while let Some(p) = queue.pop() {
            max_depth = max_depth.max(p.depth);
            let next = t.ingest(docs[&p.loc].as_bytes(), p.depth).unwrap();
            queue.extend(next);
        }
        assert_eq!(max_depth, MAX_DEPTH);
        assert_eq!(t.documents(), MAX_DEPTH + 1);
        assert!(t.skipped_for_depth() >= 1);
    }

    #[test]
    fn traversal_caps_total_urls() {
        let mut xml = String::from("<urlset>");
        for i in 0..30_000 {
            xml.push_str(&format!("<url><loc>https://a.example/{i}</loc></url>"));
        }
        xml.push_str("</urlset>");
        let mut t = SitemapTraversal::new();
        t.ingest(xml.as_bytes(), 0).unwrap();
        t.ingest(xml.as_bytes(), 0).unwrap();
        assert_eq!(t.urls().len(), MAX_URLS);
        assert!(t.truncated());
        assert!(!t.has_room());
        assert!(t.ingest(&[0x1f, 0x8b], 0).is_err());
    }
    #[test]
    fn namespace_checked_hreflang_variants_and_dtd_refusal() {
        let document = SitemapParser::parse(br#"<urlset xmlns:h="http://www.w3.org/1999/xhtml" xmlns:e="urn:evil"><url><loc>https://example.test/en</loc><h:link rel="alternate" hreflang="fr" href="https://example.test/fr"/><e:link rel="alternate" hreflang="xx" href="https://evil.test/"/></url></urlset>"#).unwrap();
        assert_eq!(
            document.urls[0].hreflang,
            vec![SitemapVariant {
                language: "fr".into(),
                loc: "https://example.test/fr".into()
            }]
        );
        assert!(SitemapParser::parse(
            br#"<!DOCTYPE urlset [<!ENTITY x SYSTEM "http://127.0.0.1/secret">]><urlset/>"#
        )
        .is_err());
    }
}
