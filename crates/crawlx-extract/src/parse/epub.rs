//! EPUB (`.epub`): the OPF spine in reading order, each XHTML chapter converted with the HTML
//! extractor. Dublin Core metadata (`dc:title`, `dc:creator`, `dc:language`, ...) becomes the
//! document properties. DRM-encrypted books fail with [`ParseError::Encrypted`]; only the
//! font-obfuscation encryption of the standard is accepted.

use std::collections::BTreeMap;

use super::blocks::collapse;
use super::html::{self, HtmlOpts};
use super::xml::{self, attr, tag, Ev};
use super::zipbox::ZipBox;
use super::{ParseError, ParseLimits};

/// A parsed book.
pub(crate) struct EpubOut {
    pub markdown: String,
    pub html: String,
    pub text: String,
    pub links: Vec<String>,
    pub images: Vec<String>,
    pub meta: BTreeMap<String, String>,
    pub title: Option<String>,
    pub warnings: Vec<String>,
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 3])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Parse an EPUB.
///
/// # Errors
/// [`ParseError::Corrupt`], [`ParseError::Encrypted`] or [`ParseError::TooLarge`].
pub(crate) fn parse_epub(bytes: &[u8], limits: &ParseLimits) -> Result<EpubOut, ParseError> {
    let mut z = ZipBox::open(bytes, "epub", limits)?;
    if let Some(enc) = z.read("META-INF/encryption.xml")? {
        let text = String::from_utf8_lossy(&enc);
        let drm = text.contains("EncryptionMethod")
            && text.split("Algorithm=\"").skip(1).any(|a| {
                !a.starts_with("http://www.idpf.org/2008/embedding")
                    && !a.starts_with("http://ns.adobe.com/pdf/enc#RC")
            });
        if drm {
            return Err(ParseError::Encrypted { format: "epub" });
        }
    }
    let container = z.require("META-INF/container.xml")?;
    let mut opf_path: Option<String> = None;
    xml::walk(&container, "epub", |ev| {
        if let Ev::Start(e) = ev {
            if tag(e) == b"rootfile" && opf_path.is_none() {
                opf_path = attr(e, "full-path");
            }
        }
        Ok(true)
    })?;
    let opf_path =
        opf_path.ok_or_else(|| ParseError::corrupt("epub", "container.xml names no package document"))?;
    let opf = z.require(&opf_path)?;

    let mut manifest: BTreeMap<String, (String, String)> = BTreeMap::new();
    let mut spine: Vec<String> = Vec::new();
    let mut meta: BTreeMap<String, String> = BTreeMap::new();
    let mut cur: Option<&'static str> = None;
    let mut text = String::new();
    xml::walk(&opf, "epub", |ev| {
        match ev {
            Ev::Start(e) => {
                text.clear();
                cur = match tag(e) {
                    b"item" => {
                        if let (Some(id), Some(href)) = (attr(e, "id"), attr(e, "href")) {
                            manifest.insert(id, (href, attr(e, "media-type").unwrap_or_default()));
                        }
                        None
                    }
                    b"itemref" => {
                        if let Some(id) = attr(e, "idref") {
                            spine.push(id);
                        }
                        None
                    }
                    b"title" => Some("title"),
                    b"creator" => Some("author"),
                    b"language" => Some("language"),
                    b"description" => Some("description"),
                    b"publisher" => Some("publisher"),
                    b"identifier" => Some("identifier"),
                    b"date" => Some("published"),
                    b"subject" => Some("subject"),
                    _ => None,
                };
            }
            Ev::Text(t) => {
                if cur.is_some() {
                    text.push_str(t);
                }
            }
            Ev::End(_) => {
                if let Some(k) = cur.take() {
                    let v = collapse(&text);
                    if !v.is_empty() {
                        meta.entry(k.to_owned()).or_insert(v);
                    }
                }
                text.clear();
            }
        }
        Ok(true)
    })?;
    let mut out = EpubOut {
        markdown: String::new(),
        html: String::new(),
        text: String::new(),
        links: Vec::new(),
        images: Vec::new(),
        title: meta.get("title").cloned(),
        meta,
        warnings: Vec::new(),
    };
    if spine.len() > limits.max_pages {
        out.warnings.push(format!(
            "the book has {} spine items; only the first {} were parsed",
            spine.len(),
            limits.max_pages
        ));
        spine.truncate(limits.max_pages);
    }
    let opts = HtmlOpts {
        only_main_content: false,
        include_tags: &[],
        exclude_tags: &[],
    };
    let dir = opf_path.rsplit_once('/').map_or("", |(d, _)| d);
    for idref in spine {
        let Some((href, media)) = manifest.get(&idref) else {
            out.warnings
                .push(format!("spine item {idref} is not in the manifest"));
            continue;
        };
        if !(media.contains("html") || media.contains("xml")) {
            continue;
        }
        let rel = percent_decode(href.split('#').next().unwrap_or(href));
        let path = if dir.is_empty() {
            rel
        } else {
            format!("{dir}/{rel}")
        };
        let path = normalise_path(&path);
        let Some(chapter) = z.read(&path)? else {
            out.warnings
                .push(format!("spine item {path} is missing from the archive"));
            continue;
        };
        let doc = html::convert(&chapter, &opts, limits)?;
        if !doc.markdown.trim().is_empty() {
            if !out.markdown.is_empty() {
                out.markdown.push_str("\n\n");
                out.text.push_str("\n\n");
            }
            out.markdown.push_str(doc.markdown.trim());
            out.text.push_str(doc.text.trim());
            out.html.push_str("<section>");
            out.html.push_str(&doc.html);
            out.html.push_str("</section>");
        }
        for l in doc.links {
            if !out.links.contains(&l) {
                out.links.push(l);
            }
        }
        for i in doc.images {
            if !out.images.contains(&i) {
                out.images.push(i);
            }
        }
    }
    Ok(out)
}

fn normalise_path(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}
