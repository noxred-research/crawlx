//! Owned, filtered DOM used by the markdown/text/html emitters and by
//! `readability`.
//!
//! The parsed `scraper` tree is converted once into this simpler tree while
//! dropping non-content elements (`script`, `style`, `noscript`, `template`,
//! `svg`, hidden elements) and user `exclude` selectors. All later stages work
//! on this tree, so they never see markup that must not reach the output.
//!
//! Recursion depth is bounded by [`MAX_DEPTH`], which [`check_limits`] enforces
//! before any recursive walk starts.

use std::collections::HashSet;

use ego_tree::{NodeId, NodeRef};
use scraper::{ElementRef, Html};
use url::Url;

use crate::ExtractError;

/// Maximum element nesting depth (matches the browser tree-builder limit).
pub const MAX_DEPTH: usize = 512;

/// Tags that never produce output.
const REMOVED_TAGS: &[&str] = &[
    "script", "style", "noscript", "template", "svg", "head", "title", "meta", "link", "base", "iframe",
    "frame", "frameset", "noframes", "object", "embed", "applet", "canvas", "input", "select", "textarea",
    "datalist", "optgroup", "video", "audio", "source", "track", "map", "area",
];

/// Elements pruned when they end up with no children at all.
const PRUNE_IF_EMPTY: &[&str] = &[
    "div",
    "span",
    "p",
    "section",
    "article",
    "main",
    "header",
    "footer",
    "nav",
    "aside",
    "form",
    "label",
    "blockquote",
    "figure",
    "figcaption",
    "ul",
    "ol",
    "dl",
    "b",
    "i",
    "em",
    "strong",
    "u",
    "small",
    "big",
    "font",
    "center",
    "a",
    "code",
    "li",
    "dd",
    "dt",
    "pre",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
];

/// Subtree statistics used by readability scoring.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Characters of trimmed text in the subtree.
    pub text_len: usize,
    /// Characters of text that sit inside anchors.
    pub link_len: usize,
    /// Commas (ASCII and full-width) in the subtree text.
    pub commas: usize,
}

/// A content node.
#[derive(Debug, Clone)]
pub enum Node {
    /// Character data.
    Text(String),
    /// Element.
    Elem(Elem),
}

/// A content element.
#[derive(Debug, Clone)]
pub struct Elem {
    /// Lower-case local name.
    pub tag: String,
    /// Attributes in source order.
    pub attrs: Vec<(String, String)>,
    /// Child nodes.
    pub children: Vec<Node>,
    /// Filled by `readability::annotate`.
    pub stats: Stats,
    /// A descendant is `main`, `article` or `role=main`.
    pub has_main: bool,
    /// Matched an `include` selector.
    pub matched: bool,
}

impl Elem {
    /// Create an element with no children.
    #[must_use]
    pub fn new(tag: &str) -> Self {
        Self {
            tag: tag.to_owned(),
            attrs: Vec::new(),
            children: Vec::new(),
            stats: Stats::default(),
            has_main: false,
            matched: false,
        }
    }

    /// Attribute value by (lower-case) name.
    #[must_use]
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// `role` attribute, lower-cased and trimmed.
    #[must_use]
    pub fn role(&self) -> Option<String> {
        self.attr("role").map(|r| r.trim().to_ascii_lowercase())
    }

    /// Iterator over child elements.
    pub fn child_elems(&self) -> impl Iterator<Item = &Elem> {
        self.children.iter().filter_map(|c| match c {
            Node::Elem(e) => Some(e),
            Node::Text(_) => None,
        })
    }
}

/// Selector match sets applied while converting.
#[derive(Debug, Default)]
pub struct Selected {
    /// Elements removed with their subtree.
    pub exclude: HashSet<NodeId>,
    /// Elements that form the output when non-empty.
    pub include: HashSet<NodeId>,
}

/// Verify input shape: node count and nesting depth, iteratively.
///
/// # Errors
/// [`ExtractError::TooLarge`] when the tree has more than `max_nodes` nodes or is
/// nested deeper than `MAX_DEPTH`.
pub fn check_limits(html: &Html, max_nodes: usize) -> Result<(), ExtractError> {
    let mut count = 0usize;
    let mut stack = vec![(html.tree.root(), 0usize)];
    while let Some((n, depth)) = stack.pop() {
        count += 1;
        if count > max_nodes {
            return Err(ExtractError::TooLarge {
                what: "nodes",
                limit: max_nodes,
                actual: count,
            });
        }
        if depth > MAX_DEPTH {
            return Err(ExtractError::TooLarge {
                what: "depth",
                limit: MAX_DEPTH,
                actual: depth,
            });
        }
        for c in n.children() {
            stack.push((c, depth + 1));
        }
    }
    Ok(())
}

/// Walk elements in document order. `f` returns `false` to skip the subtree.
pub fn walk<'a>(root: NodeRef<'a, scraper::Node>, mut f: impl FnMut(ElementRef<'a>) -> bool) {
    let mut stack = vec![root];
    while let Some(n) = stack.pop() {
        if let Some(el) = ElementRef::wrap(n) {
            if !f(el) {
                continue;
            }
        }
        stack.extend(n.children().rev());
    }
}

/// True for `hidden`, `aria-hidden=true`, inline `display:none` / `visibility:hidden`
/// and `<input type=hidden>`.
fn is_hidden(el: &scraper::node::Element) -> bool {
    if el.attr("hidden").is_some() {
        return true;
    }
    if el
        .attr("aria-hidden")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
    {
        return true;
    }
    if let Some(style) = el.attr("style") {
        for decl in style.split(';') {
            let Some((prop, value)) = decl.split_once(':') else {
                continue;
            };
            let prop = prop.trim();
            let value = value.trim().trim_end_matches("!important").trim();
            if (prop.eq_ignore_ascii_case("display") && value.eq_ignore_ascii_case("none"))
                || (prop.eq_ignore_ascii_case("visibility") && value.eq_ignore_ascii_case("hidden"))
            {
                return true;
            }
        }
    }
    false
}

/// Convert a parsed node (typically `body`) and its subtree into a content
/// node; `None` when the node is dropped (removed tag, hidden, excluded).
#[must_use]
pub fn convert_node(n: NodeRef<'_, scraper::Node>, sel: &Selected) -> Option<Node> {
    match n.value() {
        scraper::Node::Text(t) => Some(Node::Text(t.to_string())),
        scraper::Node::Element(el) => {
            let tag = el.name();
            if REMOVED_TAGS.contains(&tag) || is_hidden(el) || sel.exclude.contains(&n.id()) {
                return None;
            }
            let mut out = Elem::new(tag);
            out.attrs = el.attrs().map(|(k, v)| (k.to_owned(), v.to_owned())).collect();
            out.matched = sel.include.contains(&n.id());
            for c in n.children() {
                if let Some(child) = convert_node(c, sel) {
                    out.children.push(child);
                }
            }
            if out.children.is_empty() && PRUNE_IF_EMPTY.contains(&tag) {
                return None;
            }
            out.has_main = out.children.iter().any(|c| match c {
                Node::Elem(e) => {
                    e.tag == "main" || e.tag == "article" || e.role().as_deref() == Some("main") || e.has_main
                }
                Node::Text(_) => false,
            });
            Some(Node::Elem(out))
        }
        _ => None,
    }
}

/// Collapse outermost `matched` elements out of `nodes`, in document order.
#[must_use]
pub fn collect_matched(nodes: Vec<Node>) -> Vec<Node> {
    let mut out = Vec::new();
    collect_matched_into(nodes, &mut out);
    out
}

fn collect_matched_into(nodes: Vec<Node>, out: &mut Vec<Node>) {
    for n in nodes {
        if let Node::Elem(e) = n {
            if e.matched {
                out.push(Node::Elem(e));
            } else {
                collect_matched_into(e.children, out);
            }
        }
    }
}

/// Resolve `raw` against `base`; `None` for empty or unparsable input.
#[must_use]
pub fn resolve(base: &Url, raw: &str) -> Option<Url> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    base.join(raw).ok()
}

/// Schemes that are safe to emit as link targets.
#[must_use]
pub fn is_safe_link_scheme(u: &Url) -> bool {
    matches!(u.scheme(), "http" | "https" | "mailto" | "tel" | "ftp")
}

/// First candidate URL of a `srcset` value.
#[must_use]
pub fn srcset_urls(value: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        let mut url = &value[start..i];
        if url.is_empty() {
            break;
        }
        if url.ends_with(',') {
            url = url.trim_end_matches(',');
        } else {
            // Skip the descriptor (up to the next comma outside parentheses).
            let mut paren = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'(' => paren += 1,
                    b')' => paren = paren.saturating_sub(1),
                    b',' if paren == 0 => break,
                    _ => {}
                }
                i += 1;
            }
        }
        if !url.is_empty() {
            out.push(url);
        }
    }
    out
}

/// Best image source of an `img` element: `src`, then lazy-loading attributes, then `srcset`.
/// `data:` URIs are only returned when `keep_data` is set, and then only when the element has no
/// `http(s)` source at all (a lazy-loading placeholder must not hide the real image); only
/// `data:image/...` URIs qualify.
#[must_use]
pub fn image_src(e: &Elem, base: &Url, keep_data: bool) -> Option<Url> {
    let direct = ["src", "data-src", "data-original", "data-lazy-src"];
    for name in direct {
        if let Some(v) = e.attr(name) {
            if let Some(u) = resolve(base, v) {
                if matches!(u.scheme(), "http" | "https") {
                    return Some(u);
                }
            }
        }
    }
    for name in ["srcset", "data-srcset"] {
        if let Some(v) = e.attr(name) {
            if let Some(first) = srcset_urls(v).first() {
                if let Some(u) = resolve(base, first) {
                    if matches!(u.scheme(), "http" | "https") {
                        return Some(u);
                    }
                }
            }
        }
    }
    if keep_data {
        for name in direct {
            let data = e
                .attr(name)
                .map(str::trim)
                .filter(|v| v.get(..11).is_some_and(|p| p.eq_ignore_ascii_case("data:image/")));
            if let Some(u) = data.and_then(|v| Url::parse(v).ok()) {
                return Some(u);
            }
        }
    }
    None
}

/// Collapse whitespace runs to single spaces and trim.
#[must_use]
pub fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut pending = false;
    for c in s.chars() {
        if c.is_whitespace() || c == '\u{a0}' {
            pending = true;
        } else {
            if pending && !out.is_empty() {
                out.push(' ');
            }
            pending = false;
            out.push(c);
        }
    }
    out
}

/// Concatenated text of a subtree with block boundaries ignored.
#[must_use]
pub fn plain_text(nodes: &[Node]) -> String {
    let mut s = String::new();
    for n in nodes {
        match n {
            Node::Text(t) => s.push_str(t),
            Node::Elem(e) => s.push_str(&plain_text(&e.children)),
        }
    }
    s
}

/// Text of a `pre` subtree: `br` becomes a newline and line-like block
/// children (`div`, `p`, `tr`, `li`) end with one.
pub fn pre_text(nodes: &[Node], s: &mut String) {
    for n in nodes {
        match n {
            Node::Text(t) => s.push_str(t),
            Node::Elem(e) if e.tag == "br" => s.push('\n'),
            Node::Elem(e) => {
                pre_text(&e.children, s);
                if matches!(e.tag.as_str(), "div" | "p" | "tr" | "li") && !s.ends_with('\n') {
                    s.push('\n');
                }
            }
        }
    }
}
