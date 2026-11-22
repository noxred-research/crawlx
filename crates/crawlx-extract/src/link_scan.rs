//! Metadata-only link scan: a bounded, streaming pass over an HTML body that never builds a DOM.
//!
//! A page the isolated parser refuses (address space, CPU or wall limit, or the parse-memory
//! budget) used to cost the crawl its whole subtree: no links, no metadata. [`scan`] recovers
//! them. It feeds the body through `html5ever`'s *tokenizer* alone, in fixed-size decoded chunks,
//! and keeps only what a crawl needs:
//!
//! * `a[href]` and `area[href]` links with their anchor text and `rel` tokens, resolved against
//!   the effective base (`<base href>` aware, like [`crate::links::extract_links`]), `http` and
//!   `https` only, fragments removed, duplicates merged;
//! * the title (`og:title`, then `<title>`), the description (`description`, then
//!   `og:description`), the canonical URL (`<link rel=canonical>`, then `og:url`), the document
//!   language and the `robots` / `crawlx` meta directives.
//!
//! # Bounds
//!
//! The tokenizer holds one token at a time, so its working set is bounded by the input, never by
//! the document's shape (no tree, no open-element stack, no formatting list). Everything the scan
//! keeps is capped: [`MAX_LINKS`] links, [`MAX_HREF_BYTES`] per reference, [`MAX_LINK_BYTES`] of
//! resolved link text in total, and short strings for titles, descriptions and anchor text. A
//! page that hits a cap still returns what was collected, with [`LinkScan::links_truncated`] set.
//! Callers reserve [`charge_bytes`] from the shared byte budget before scanning.
//!
//! # Fidelity
//!
//! The raw-text and RCDATA elements (`script`, `style`, `title`, `textarea`, `noscript`, ...)
//! switch the tokenizer exactly as the tree builder would, and `template` content is skipped, so
//! links inside scripts or templates are not reported. The scan does not run the tree builder,
//! so markup that only the tree-construction rules move (foster parenting, implied elements)
//! may be seen at its source position. Input decodes as UTF-8, malformed sequences replaced by
//! U+FFFD, the same as [`crate::Extractor::extract_bytes`] without decode options.

use std::cell::RefCell;
use std::collections::HashMap;

use html5ever::tendril::StrTendril;
use html5ever::tokenizer::states::RawKind;
use html5ever::tokenizer::{
    BufferQueue, CharacterTokens, EndTag, StartTag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer,
    TokenizerOpts,
};
use url::Url;

use crate::document::ExtractedLink;
use crate::dom::{collapse_ws, resolve};
use crate::metadata::RobotsMeta;

/// Most links one scan keeps.
pub const MAX_LINKS: usize = 100_000;
/// Longest reference (the raw `href` value) a scan accepts; a longer one is skipped.
pub const MAX_HREF_BYTES: usize = 4096;
/// Most bytes of raw `href` text, and of resolved link text, one scan keeps.
pub const MAX_LINK_BYTES: usize = 16 * 1024 * 1024;
/// Bytes of the body decoded and tokenized per step.
const CHUNK_BYTES: usize = 32 * 1024;
/// Longest text kept per link, in characters.
const MAX_LINK_TEXT_CHARS: usize = 512;
/// Raw bytes of anchor text kept before whitespace collapsing.
const MAX_ANCHOR_RAW_BYTES: usize = 2048;
/// Raw bytes of title text kept before whitespace collapsing.
const MAX_TITLE_RAW_BYTES: usize = 2048;
/// Longest `content`, `lang` or `rel` value kept.
const MAX_ATTRIBUTE_BYTES: usize = 2048;
/// Longest title or description returned, in characters.
const MAX_META_CHARS: usize = 2048;
/// Per input byte: the chunk copies, the one token being accumulated and the attribute vector
/// of the widest tag (about 40 bytes per attribute slot, doubled by growth, for attributes
/// that can be as short as three input bytes), with slack.
const SCAN_BYTES_PER_INPUT_BYTE: usize = 64;
/// Fixed allowance for the tokenizer state, the collected links and the dedupe index.
const SCAN_FIXED_BYTES: usize = 2 * MAX_LINK_BYTES + 1024 * 1024;

/// What [`scan`] recovered from one body.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct LinkScan {
    /// `og:title`, then the first `<title>`.
    pub title: Option<String>,
    /// `description`, then `og:description`.
    pub description: Option<String>,
    /// `<link rel=canonical>`, then `og:url`.
    pub canonical_url: Option<Url>,
    /// `<html lang>`.
    pub language: Option<String>,
    /// `robots` and `crawlx` meta directives.
    pub robots: RobotsMeta,
    /// Deduplicated `http(s)` links in document order.
    pub links: Vec<ExtractedLink>,
    /// A cap stopped the collection of links; later links of the page are missing.
    pub links_truncated: bool,
}

/// Bytes to reserve from the shared byte budget before [`scan`]ning `input_len` bytes, or `None`
/// when the charge overflows.
#[must_use]
pub fn charge_bytes(input_len: usize) -> Option<usize> {
    input_len
        .checked_mul(SCAN_BYTES_PER_INPUT_BYTE)
        .and_then(|bytes| bytes.checked_add(SCAN_FIXED_BYTES))
}

/// A link as written, before resolution.
struct RawLink {
    href: String,
    text: String,
    rel: Vec<String>,
}

#[derive(Default)]
struct State {
    raw_links: Vec<RawLink>,
    raw_bytes: usize,
    truncated: bool,
    /// Index of the open anchor whose text is being collected.
    anchor: Option<usize>,
    template_depth: usize,
    in_title: bool,
    title_seen: bool,
    title_raw: String,
    lang: Option<String>,
    base_href: Option<String>,
    canonical_href: Option<String>,
    description: Option<String>,
    og_title: Option<String>,
    og_description: Option<String>,
    og_url: Option<String>,
    robots: Vec<String>,
}

/// Token sink that records links and metadata and never builds a tree.
struct Collector {
    state: RefCell<State>,
}

fn clipped(value: &str, limit: usize) -> String {
    if value.len() <= limit {
        return value.to_owned();
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

fn attribute<'a>(tag: &'a html5ever::tokenizer::Tag, name: &str) -> Option<&'a str> {
    tag.attrs
        .iter()
        .find(|attribute| &*attribute.name.local == name)
        .map(|attribute| &*attribute.value)
}

impl State {
    fn start_anchor(&mut self, tag: &html5ever::tokenizer::Tag) {
        self.anchor = None;
        if self.template_depth > 0 {
            return;
        }
        let Some(href) = attribute(tag, "href").map(str::trim) else {
            return;
        };
        if href.is_empty() || href.starts_with('#') || href.len() > MAX_HREF_BYTES {
            return;
        }
        if self.raw_links.len() >= MAX_LINKS || self.raw_bytes.saturating_add(href.len()) > MAX_LINK_BYTES {
            self.truncated = true;
            return;
        }
        self.raw_bytes += href.len();
        let rel = attribute(tag, "rel")
            .map(|value| {
                clipped(value, MAX_ATTRIBUTE_BYTES)
                    .split_whitespace()
                    .map(str::to_ascii_lowercase)
                    .collect()
            })
            .unwrap_or_default();
        self.raw_links.push(RawLink {
            href: href.to_owned(),
            text: String::new(),
            rel,
        });
        // `<area>` has no content; only `<a>` collects text
        if &*tag.name == "a" {
            self.anchor = Some(self.raw_links.len() - 1);
        }
    }

    fn meta(&mut self, tag: &html5ever::tokenizer::Tag) {
        let Some(content) = attribute(tag, "content").map(|value| clipped(value, MAX_ATTRIBUTE_BYTES)) else {
            return;
        };
        let key = attribute(tag, "name")
            .or_else(|| attribute(tag, "property"))
            .map(str::to_ascii_lowercase);
        match key.as_deref() {
            Some("robots" | "crawlx") => self.robots.extend(
                content
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|token| !token.is_empty())
                    .map(str::to_ascii_lowercase),
            ),
            Some("description") => {
                self.description.get_or_insert(content);
            }
            Some("og:title") => {
                self.og_title.get_or_insert(content);
            }
            Some("og:description") => {
                self.og_description.get_or_insert(content);
            }
            Some("og:url") => {
                self.og_url.get_or_insert(content);
            }
            _ => {}
        }
    }

    fn link_element(&mut self, tag: &html5ever::tokenizer::Tag) {
        if self.canonical_href.is_some() {
            return;
        }
        let canonical = attribute(tag, "rel").is_some_and(|rel| {
            rel.split_whitespace()
                .any(|token| token.eq_ignore_ascii_case("canonical"))
        });
        if canonical {
            if let Some(href) = attribute(tag, "href").filter(|href| href.len() <= MAX_HREF_BYTES) {
                self.canonical_href = Some(href.to_owned());
            }
        }
    }

    fn start(&mut self, tag: &html5ever::tokenizer::Tag) -> TokenSinkResult<()> {
        match &*tag.name {
            "a" | "area" => self.start_anchor(tag),
            "html" => {
                if self.lang.is_none() {
                    self.lang = attribute(tag, "lang")
                        .map(|lang| clipped(lang.trim(), MAX_ATTRIBUTE_BYTES))
                        .filter(|lang| !lang.is_empty());
                }
            }
            "base" => {
                if self.base_href.is_none() {
                    self.base_href = attribute(tag, "href")
                        .filter(|href| href.len() <= MAX_HREF_BYTES)
                        .map(str::to_owned);
                }
            }
            "meta" => self.meta(tag),
            "link" => self.link_element(tag),
            "template" => self.template_depth += 1,
            "title" => {
                if !self.title_seen {
                    self.title_seen = true;
                    self.in_title = true;
                }
                return TokenSinkResult::RawData(RawKind::Rcdata);
            }
            "textarea" => return TokenSinkResult::RawData(RawKind::Rcdata),
            "script" => return TokenSinkResult::RawData(RawKind::ScriptData),
            "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
                return TokenSinkResult::RawData(RawKind::Rawtext);
            }
            "plaintext" => return TokenSinkResult::Plaintext,
            _ => {}
        }
        TokenSinkResult::Continue
    }

    fn end(&mut self, tag: &html5ever::tokenizer::Tag) {
        match &*tag.name {
            "a" => self.anchor = None,
            "template" => self.template_depth = self.template_depth.saturating_sub(1),
            "title" => self.in_title = false,
            _ => {}
        }
    }

    fn text(&mut self, text: &str) {
        if self.in_title && self.title_raw.len() < MAX_TITLE_RAW_BYTES {
            let room = MAX_TITLE_RAW_BYTES - self.title_raw.len();
            self.title_raw.push_str(&clipped(text, room));
        }
        if let Some(index) = self.anchor {
            if let Some(link) = self.raw_links.get_mut(index) {
                if link.text.len() < MAX_ANCHOR_RAW_BYTES {
                    let room = MAX_ANCHOR_RAW_BYTES - link.text.len();
                    link.text.push_str(&clipped(text, room));
                }
            }
        }
    }
}

impl TokenSink for Collector {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<()> {
        let mut state = self.state.borrow_mut();
        match token {
            TagToken(tag) => match tag.kind {
                StartTag => return state.start(&tag),
                EndTag => state.end(&tag),
            },
            CharacterTokens(text) => state.text(&text),
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

/// Decode `bytes` chunk by chunk and run the tokenizer over each chunk.
fn tokenize(bytes: &[u8]) -> State {
    let collector = Collector {
        state: RefCell::new(State::default()),
    };
    let tokenizer = Tokenizer::new(collector, TokenizerOpts::default());
    let queue = BufferQueue::default();
    let mut decoder = encoding_rs::UTF_8.new_decoder_with_bom_removal();
    let mut text = String::new();
    let mut chunks = bytes.chunks(CHUNK_BYTES).peekable();
    while let Some(chunk) = chunks.next() {
        text.clear();
        text.reserve(
            decoder
                .max_utf8_buffer_length(chunk.len())
                .unwrap_or(chunk.len().saturating_mul(3)),
        );
        // the reserved capacity covers the worst case, so the whole chunk is always consumed
        let _ = decoder.decode_to_string(chunk, &mut text, chunks.peek().is_none());
        queue.push_back(StrTendril::from_slice(&text));
        // the sink never asks to pause for a script, so one call drains the queue
        let _ = tokenizer.feed(&queue);
    }
    tokenizer.end();
    tokenizer.sink.state.into_inner()
}

/// Scan `bytes`, the body fetched from `page`, for links and metadata without building a DOM.
///
/// Never fails and never allocates more than [`charge_bytes`] for `bytes.len()`; see the module
/// documentation for what it keeps and what a cap drops.
#[must_use]
pub fn scan(bytes: &[u8], page: &Url) -> LinkScan {
    finish(tokenize(bytes), page)
}

fn finish(state: State, page: &Url) -> LinkScan {
    let base = state
        .base_href
        .as_deref()
        .and_then(|href| resolve(page, href))
        .filter(|base| matches!(base.scheme(), "http" | "https"))
        .unwrap_or_else(|| page.clone());
    let mut links: Vec<ExtractedLink> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut truncated = state.truncated;
    let mut resolved_bytes = 0usize;
    for raw in state.raw_links {
        let Some(mut url) = resolve(&base, &raw.href) else {
            continue;
        };
        if !matches!(url.scheme(), "http" | "https") {
            continue;
        }
        url.set_fragment(None);
        let nofollow = raw.rel.iter().any(|token| token == "nofollow");
        let mut text = collapse_ws(&raw.text);
        if text.chars().count() > MAX_LINK_TEXT_CHARS {
            text = text.chars().take(MAX_LINK_TEXT_CHARS).collect();
        }
        if let Some(&at) = index.get(url.as_str()) {
            let link = &mut links[at];
            if link.text.is_empty() {
                link.text = text;
            }
            for token in raw.rel {
                if !link.rel.contains(&token) {
                    link.rel.push(token);
                }
            }
            link.nofollow &= nofollow;
            continue;
        }
        resolved_bytes = resolved_bytes.saturating_add(url.as_str().len());
        if resolved_bytes > MAX_LINK_BYTES {
            truncated = true;
            break;
        }
        index.insert(url.as_str().to_owned(), links.len());
        let internal = url.host_str().is_some() && url.host_str() == page.host_str();
        links.push(ExtractedLink {
            url,
            text,
            rel: raw.rel,
            nofollow,
            internal,
        });
    }
    let mut robots = RobotsMeta::default();
    for token in &state.robots {
        robots.apply(token);
    }
    let meta_text = |value: Option<String>| {
        value
            .map(|value| collapse_ws(&value))
            .filter(|value| !value.is_empty())
            .map(|value| value.chars().take(MAX_META_CHARS).collect::<String>())
    };
    let title_tag = meta_text(Some(state.title_raw));
    let canonical_url = state
        .canonical_href
        .as_deref()
        .and_then(|href| resolve(&base, href))
        .or_else(|| state.og_url.as_deref().and_then(|href| resolve(&base, href)))
        .filter(|url| matches!(url.scheme(), "http" | "https"));
    LinkScan {
        title: meta_text(state.og_title).or(title_tag),
        description: meta_text(state.description).or_else(|| meta_text(state.og_description)),
        canonical_url,
        language: state.lang,
        robots,
        links,
        links_truncated: truncated,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::{ExtractOptions, Extractor};

    fn page() -> Url {
        Url::parse("https://example.test/dir/page").unwrap()
    }

    fn urls(scan: &LinkScan) -> Vec<&str> {
        scan.links.iter().map(|link| link.url.as_str()).collect()
    }

    #[test]
    fn links_resolve_dedupe_merge_and_skip_what_the_extractor_skips() {
        let html = r##"<!doctype html><html lang="de"><head><title>  Hello
            world </title><base href="/base/"></head><body>
            <a href="one" rel="Nofollow noopener">First <b>one</b></a>
            <a href="one#frag" rel="author">again</a>
            <a href="/abs?q=1&amp;r=2">Absolute</a>
            <area href="area-target" alt="x">
            <a href="#top">top</a><a href="">empty</a><a>no href</a>
            <a href="mailto:a@example.test">mail</a><a href="javascript:void(0)">js</a>
            <script>var s = '<a href="/in-script">x</a>';</script>
            <style>a::after{content:'<a href="/in-style">'}</style>
            <noscript><a href="/in-noscript">x</a></noscript>
            <template><a href="/in-template">x</a></template>
            <textarea><a href="/in-textarea">x</a></textarea>
            <!-- <a href="/in-comment">x</a> -->
            <a href="https://other.test/x">External</a>
            </body></html>"##;
        let scan = scan(html.as_bytes(), &page());
        assert_eq!(
            urls(&scan),
            [
                "https://example.test/base/one",
                "https://example.test/abs?q=1&r=2",
                "https://example.test/base/area-target",
                "https://other.test/x",
            ]
        );
        let one = &scan.links[0];
        assert_eq!(one.text, "First one");
        assert_eq!(one.rel, ["nofollow", "noopener", "author"]);
        assert!(
            !one.nofollow,
            "one occurrence without nofollow clears it, like the extractor"
        );
        assert!(one.internal);
        assert!(!scan.links[3].internal);
        assert_eq!(scan.title.as_deref(), Some("Hello world"));
        assert_eq!(scan.language.as_deref(), Some("de"));
        assert!(!scan.links_truncated);
    }

    #[test]
    fn metadata_prefers_open_graph_and_reads_robots_and_canonical() {
        let html = r#"<html lang="en"><head><title>Tag title</title>
            <meta property="og:title" content="OG title">
            <meta name="description" content="  The   description ">
            <meta property="og:description" content="OG description">
            <meta name="robots" content="NoIndex, nofollow">
            <meta name="crawlx" content="noarchive">
            <link rel="stylesheet" href="/x.css">
            <link rel="Canonical" href="/canonical/">
            <meta property="og:url" content="/og-url"></head><body></body></html>"#;
        let scan = scan(html.as_bytes(), &page());
        assert_eq!(scan.title.as_deref(), Some("OG title"));
        assert_eq!(scan.description.as_deref(), Some("The description"));
        assert_eq!(
            scan.canonical_url.as_ref().map(Url::as_str),
            Some("https://example.test/canonical/")
        );
        assert!(scan.robots.noindex && scan.robots.nofollow && scan.robots.noarchive);
        assert_eq!(scan.language.as_deref(), Some("en"));
        assert!(scan.links.is_empty());

        let og_only = scan_og_url();
        assert_eq!(
            og_only.canonical_url.as_ref().map(Url::as_str),
            Some("https://example.test/og-url")
        );
        assert_eq!(og_only.description.as_deref(), Some("OG description"));
        assert_eq!(og_only.title.as_deref(), Some("Tag title"));
    }

    fn scan_og_url() -> LinkScan {
        scan(
            br#"<title>Tag title</title><meta property="og:url" content="/og-url">
                <meta property="og:description" content="OG description">"#,
            &page(),
        )
    }

    #[test]
    fn a_title_is_the_first_one_and_is_bounded() {
        let long = "x".repeat(10_000);
        let html = format!("<title>{long}</title><title>second</title>");
        let scan = scan(html.as_bytes(), &page());
        assert_eq!(scan.title.as_ref().map(String::len), Some(MAX_TITLE_RAW_BYTES));
    }

    #[test]
    fn utf8_split_across_chunk_boundaries_and_malformed_bytes_are_handled() {
        // pad before the anchor so the 2-byte `é` straddles the first chunk boundary
        let mut body = vec![b' '; CHUNK_BYTES - 1 - "<a href=\"/x\">".len()];
        body.extend_from_slice(b"<a href=\"/x\">");
        body.extend_from_slice("é€🙂".as_bytes());
        body.extend_from_slice(b"</a><a href=\"/bad\xff\xfe\">bad</a><a href=\"/y\">y</a>");
        let scan = scan(&body, &page());
        assert_eq!(scan.links.len(), 3);
        assert_eq!(scan.links[0].text, "é€🙂");
        assert!(scan.links[1].url.as_str().starts_with("https://example.test/bad"));
        assert_eq!(scan.links[2].url.as_str(), "https://example.test/y");
    }

    #[test]
    fn caps_stop_collection_and_report_truncation() {
        let mut body = String::new();
        for n in 0..(MAX_LINKS + 50) {
            body.push_str(&format!("<a href=\"/p/{n}\">l</a>"));
        }
        let scan = scan(body.as_bytes(), &page());
        assert_eq!(scan.links.len(), MAX_LINKS);
        assert!(scan.links_truncated);

        let too_long = format!(
            "<a href=\"/{}\">x</a><a href=\"/ok\">ok</a>",
            "a".repeat(MAX_HREF_BYTES + 1)
        );
        let scan = super::scan(too_long.as_bytes(), &page());
        assert_eq!(urls(&scan), ["https://example.test/ok"]);
    }

    #[test]
    fn hostile_shapes_stay_bounded_and_finish() {
        // unterminated constructs, deep nesting and a huge attribute list: no tree, no recursion
        let deep = "<div>".repeat(200_000) + "<a href=\"/deep\">d</a>";
        assert_eq!(
            urls(&scan(deep.as_bytes(), &page())),
            ["https://example.test/deep"]
        );
        let attrs = (0..20_000)
            .map(|n| format!("a{n}=1"))
            .collect::<Vec<_>>()
            .join(" ");
        let wide = format!("<a {attrs} href=\"/wide\">w</a><!-- never closed <a href=\"/hidden\">");
        assert_eq!(
            urls(&scan(wide.as_bytes(), &page())),
            ["https://example.test/wide"]
        );
        assert!(scan(b"", &page()).links.is_empty());
        assert!(scan(b"\xef\xbb\xbf<a href=\"/bom\">x</a>", &page()).links.len() == 1);
    }

    #[test]
    fn the_scan_agrees_with_the_extractor_on_a_realistic_page() {
        let mut html = String::from(
            "<!doctype html><html lang=\"en\"><head><title>Agree</title><base href=\"https://example.test/b/\">\
             <meta name=\"description\" content=\"D\"><link rel=\"canonical\" href=\"c\"></head><body><nav>",
        );
        for n in 0..300 {
            html.push_str(&format!(
                "<a href=\"item/{}\" rel=\"{}\">Item {n} <span>text</span></a>",
                n % 250,
                if n % 7 == 0 { "nofollow" } else { "" }
            ));
        }
        html.push_str("<a href=\"/x#a\">x</a><a href=\"/x#b\">x2</a><script>var a='<a href=\"/no\">';</script></nav></body></html>");
        let base = Url::parse("https://example.test/dir/page").unwrap();
        let document = Extractor::extract(&html, &base, &ExtractOptions::default()).unwrap();
        let scanned = scan(html.as_bytes(), &base);
        let expected: Vec<_> = document
            .links
            .iter()
            .map(|link| (link.url.as_str(), link.text.as_str(), link.nofollow))
            .collect();
        let got: Vec<_> = scanned
            .links
            .iter()
            .map(|link| (link.url.as_str(), link.text.as_str(), link.nofollow))
            .collect();
        assert_eq!(got, expected);
        assert_eq!(scanned.title, document.title);
        assert_eq!(scanned.description, document.description);
        assert_eq!(scanned.canonical_url, document.canonical_url);
        assert_eq!(scanned.language, document.language);
    }

    #[test]
    fn the_reservation_covers_the_input_and_the_fixed_allowance() {
        assert_eq!(charge_bytes(0), Some(SCAN_FIXED_BYTES));
        assert_eq!(
            charge_bytes(1000),
            Some(1000 * SCAN_BYTES_PER_INPUT_BYTE + SCAN_FIXED_BYTES)
        );
        assert_eq!(charge_bytes(usize::MAX), None);
    }
}
