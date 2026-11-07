//! Light navigational link scanner. Extracts `a`, `area`
//! and `link rel=alternate|canonical` targets without building a DOM;
//! `crawlx-extract` does full HTML. Honors the first `<base href>`.
//! Only `http`/`https` targets survive; pure-fragment hrefs are skipped.

use std::borrow::Cow;

use url::Url;

const MAX_LINKS: usize = 100_000;
const MAX_HREF_LEN: usize = 8192;
const MAX_TEXT_LEN: usize = 256;

/// Where a link came from.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum LinkKind {
    /// `<a href>`.
    Anchor,
    /// `<area href>` of an image map.
    Area,
    /// `<link rel="alternate">`.
    Alternate,
    /// `<link rel="canonical">`.
    Canonical,
}

/// A discovered link, resolved against the (possibly `<base>`-adjusted) base URL.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RawLink {
    /// Resolved absolute URL.
    pub url: Url,
    /// The href as written (entity-decoded, trimmed).
    pub raw: String,
    /// Kind of element the link came from.
    pub kind: LinkKind,
    /// `rel` contains `nofollow` (anchors and areas).
    pub nofollow: bool,
    /// Whitespace-collapsed anchor text (anchors only, capped at 256 bytes).
    pub text: Option<String>,
    /// `hreflang` attribute of `link` elements (language of the target).
    pub hreflang: Option<String>,
    /// Declared target MIME type, including an anchor's optional `type` attribute.
    pub media_type: Option<String>,
}

struct Tag<'a> {
    name: String,
    attrs: Vec<(String, Cow<'a, str>)>,
    end: usize,
}

impl Tag<'_> {
    fn attr(&self, n: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_ref())
    }
}

/// Scan `html` for navigational links.
#[must_use]
pub fn extract_links(html: &str, base: &Url) -> Vec<RawLink> {
    let b = html.as_bytes();
    let mut links: Vec<RawLink> = Vec::new();
    let mut base_url = base.clone();
    let mut base_seen = false;
    let mut open_anchor: Option<usize> = None;
    let mut text = String::new();
    let mut i = 0;
    while i < b.len() && links.len() < MAX_LINKS {
        let Some(rel) = memchr(b'<', &b[i..]) else { break };
        let lt = i + rel;
        if open_anchor.is_some() && text.len() < MAX_TEXT_LEN {
            if let Some(t) = html.get(i..lt) {
                text.push_str(&decode_entities(t));
                text.push(' ');
            }
        }
        i = lt + 1;
        let Some(&c) = b.get(i) else { break };
        if c == b'!' {
            if b[i..].starts_with(b"!--") {
                i = find(b, i + 3, b"-->").map_or(b.len(), |p| p + 3);
            } else {
                i = memchr(b'>', &b[i..]).map_or(b.len(), |p| i + p + 1);
            }
            continue;
        }
        if c == b'?' {
            i = memchr(b'>', &b[i..]).map_or(b.len(), |p| i + p + 1);
            continue;
        }
        if c == b'/' {
            let end = memchr(b'>', &b[i..]).map_or(b.len(), |p| i + p + 1);
            let name = html
                .get(i + 1..end.saturating_sub(1))
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if name == "a" {
                finish_anchor(&mut links, &mut open_anchor, &mut text);
            }
            i = end;
            continue;
        }
        if !c.is_ascii_alphabetic() {
            continue; // a literal '<' in text
        }
        let tag = parse_tag(html, i);
        i = tag.end;
        match tag.name.as_str() {
            "script" | "style" | "textarea" | "title" => {
                let close = format!("</{}", tag.name);
                i = find_ci(b, i, close.as_bytes()).unwrap_or(b.len());
            }
            "base" => {
                if !base_seen {
                    base_seen = true;
                    if let Some(h) = tag.attr("href") {
                        if let Ok(u) = base.join(decode_entities(h).trim()) {
                            base_url = u;
                        }
                    }
                }
            }
            "a" => {
                finish_anchor(&mut links, &mut open_anchor, &mut text);
                if let Some(l) = make_link(&tag, &base_url, LinkKind::Anchor) {
                    links.push(l);
                    open_anchor = Some(links.len() - 1);
                    text.clear();
                }
            }
            "area" => {
                if let Some(l) = make_link(&tag, &base_url, LinkKind::Area) {
                    links.push(l);
                }
            }
            "link" => {
                let rel = tag.attr("rel").unwrap_or("").to_ascii_lowercase();
                let tokens: Vec<&str> = rel.split_whitespace().collect();
                let kind = if tokens.contains(&"canonical") {
                    Some(LinkKind::Canonical)
                } else if tokens.contains(&"alternate") && !tokens.contains(&"stylesheet") {
                    Some(LinkKind::Alternate)
                } else {
                    None
                };
                if let Some(l) = kind.and_then(|k| make_link(&tag, &base_url, k)) {
                    links.push(l);
                }
            }
            _ => {}
        }
    }
    finish_anchor(&mut links, &mut open_anchor, &mut text);
    links
}

fn finish_anchor(links: &mut [RawLink], open: &mut Option<usize>, text: &mut String) {
    if let Some(idx) = open.take() {
        let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let capped: String = if collapsed.len() > MAX_TEXT_LEN {
            collapsed.chars().take(MAX_TEXT_LEN / 4).collect()
        } else {
            collapsed
        };
        if let Some(l) = links.get_mut(idx) {
            l.text = Some(capped);
        }
    }
    text.clear();
}

fn make_link(tag: &Tag<'_>, base: &Url, kind: LinkKind) -> Option<RawLink> {
    let href = decode_entities(tag.attr("href")?);
    let href = href.trim();
    if href.is_empty() || href.starts_with('#') || href.len() > MAX_HREF_LEN {
        return None;
    }
    let url = Url::options().base_url(Some(base)).parse(href).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let nofollow = tag
        .attr("rel")
        .is_some_and(|r| r.split_whitespace().any(|t| t.eq_ignore_ascii_case("nofollow")));
    Some(RawLink {
        url,
        raw: href.to_owned(),
        kind,
        nofollow,
        text: None,
        hreflang: tag.attr("hreflang").map(|s| s.trim().to_owned()),
        media_type: tag.attr("type").map(|s| s.trim().to_owned()),
    })
}

/// Parse a start tag whose name begins at `start` (an ASCII letter).
fn parse_tag(html: &str, start: usize) -> Tag<'_> {
    let b = html.as_bytes();
    let mut i = start;
    while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' && b[i] != b'/' {
        i += 1;
    }
    let name = html.get(start..i).unwrap_or("").to_ascii_lowercase();
    let mut attrs = Vec::new();
    loop {
        while i < b.len() && (b[i].is_ascii_whitespace() || b[i] == b'/') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        if b[i] == b'>' {
            i += 1;
            break;
        }
        let ns = i;
        while i < b.len() && !b[i].is_ascii_whitespace() && !matches!(b[i], b'=' | b'>' | b'/') {
            i += 1;
        }
        if i == ns {
            i += 1; // stray '=' or similar; guarantee progress
            continue;
        }
        let an = html.get(ns..i).unwrap_or("").to_ascii_lowercase();
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut value: Cow<'_, str> = Cow::Borrowed("");
        if i < b.len() && b[i] == b'=' {
            i += 1;
            while i < b.len() && b[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
                let q = b[i];
                let vs = i + 1;
                let ve = memchr(q, &b[vs..]).map_or(b.len(), |p| vs + p);
                value = Cow::Borrowed(html.get(vs..ve).unwrap_or(""));
                i = (ve + 1).min(b.len());
            } else {
                let vs = i;
                while i < b.len() && !b[i].is_ascii_whitespace() && b[i] != b'>' {
                    i += 1;
                }
                value = Cow::Borrowed(html.get(vs..i).unwrap_or(""));
            }
        }
        if !attrs.iter().any(|(k, _): &(String, Cow<'_, str>)| *k == an) {
            attrs.push((an, value));
        }
    }
    Tag { name, attrs, end: i }
}

fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&c| c == needle)
}

fn find(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn find_ci(hay: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    hay.get(from..)?
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
        .map(|p| p + from)
}

/// Decode the common HTML character references.
fn decode_entities(s: &str) -> Cow<'_, str> {
    if !s.contains('&') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find('&') {
        out.push_str(&rest[..p]);
        rest = &rest[p..];
        let decoded = rest.find(';').filter(|&e| e <= 10).and_then(|e| {
            let ent = &rest[1..e];
            let ch = match ent {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                "nbsp" => Some('\u{a0}'),
                _ => ent
                    .strip_prefix('#')
                    .and_then(|n| match n.strip_prefix(['x', 'X']) {
                        Some(h) => u32::from_str_radix(h, 16).ok(),
                        None => n.parse::<u32>().ok(),
                    })
                    .and_then(char::from_u32),
            };
            ch.map(|c| (c, e + 1))
        });
        if let Some((c, used)) = decoded {
            out.push(c);
            rest = &rest[used..];
        } else {
            out.push('&');
            rest = &rest[1..];
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/dir/page").unwrap()
    }

    #[test]
    fn extracts_kinds_and_flags() {
        let html = r##"<!doctype html><html><head>
            <link rel="canonical" href="/canon">
            <link rel="alternate" hreflang="de" href="https://example.com/de/">
            <link rel="stylesheet" href="/s.css">
            <link rel="alternate stylesheet" href="/s2.css">
            <script>var a = "<a href='/in-script'>";</script>
            <!-- <a href="/commented"> -->
          </head><body>
            <a href="a?x=1&amp;y=2">  First <b>link</b> </a>
            <a href='/b' rel="NoFollow external">b</a>
            <a href=/unquoted>c</a>
            <a href="#frag">skip</a><a href="javascript:void(0)">skip</a><a href="mailto:x@y.z">skip</a>
            <a name="noop">skip</a>
            <area href="/map" rel="nofollow">
            <iframe src="/frame"></iframe>
          </body></html>"##;
        let l = extract_links(html, &base());
        let got: Vec<(&str, LinkKind, bool)> =
            l.iter().map(|x| (x.url.as_str(), x.kind, x.nofollow)).collect();
        assert_eq!(
            got,
            vec![
                ("https://example.com/canon", LinkKind::Canonical, false),
                ("https://example.com/de/", LinkKind::Alternate, false),
                ("https://example.com/dir/a?x=1&y=2", LinkKind::Anchor, false),
                ("https://example.com/b", LinkKind::Anchor, true),
                ("https://example.com/unquoted", LinkKind::Anchor, false),
                ("https://example.com/map", LinkKind::Area, true),
            ]
        );
        assert_eq!(l[1].hreflang.as_deref(), Some("de"));
        assert_eq!(l[2].text.as_deref(), Some("First link"));
        assert_eq!(l[2].raw, "a?x=1&y=2");
    }

    #[test]
    fn honors_base_href() {
        let html = r#"<base href="https://cdn.example.org/root/"><a href="x">x</a><base href="/ignored/"><a href="y">y</a>"#;
        let l = extract_links(html, &base());
        assert_eq!(l[0].url.as_str(), "https://cdn.example.org/root/x");
        assert_eq!(l[1].url.as_str(), "https://cdn.example.org/root/y");
    }

    #[test]
    fn tolerates_garbage() {
        for html in [
            "<",
            "<a",
            "<a href=",
            "<a href=\"x",
            "< a href=x>",
            "<a href='é'>é",
            "a < b <a href=/ok>",
            "<<<>>>",
            "",
        ] {
            let _ = extract_links(html, &base());
        }
        let l = extract_links("a < b <a href=/ok>ok</a>", &base());
        assert_eq!(l.len(), 1);
    }
}
