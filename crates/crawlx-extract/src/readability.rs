//! Main-content selection (`onlyMainContent`).
//!
//! The algorithm is a clean-room variant of the classic text-density approach:
//!
//! 1. Remove boilerplate: `nav`/`footer`/`aside`, landmark roles, `header`
//!    outside articles, and elements whose `class`/`id` carry negative hints
//!    (`sidebar`, `comment`, `ad`, ...) unless they hold most of the page text.
//! 2. Prefer a `main`/`[role=main]` element, then a single dominant `article`.
//! 3. Otherwise score blocks: paragraph-like children contribute
//!    `1 + commas + min(len/100, 3)` to their parent and half to the
//!    grandparent; tag and class/id hints add a base score; the score is
//!    scaled by `1 - link_density`. The best candidate is widened to its
//!    parent while it holds at least 75 % of the parent's text.
//! 4. Fall back to the whole (stripped) body when the candidate covers less
//!    than 20 % of the page text.

use crate::dom::{Elem, Node, Stats};

const BLOCK_TAGS: &[&str] = &[
    "div",
    "p",
    "ul",
    "ol",
    "dl",
    "table",
    "blockquote",
    "pre",
    "section",
    "article",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "form",
    "figure",
    "header",
    "footer",
    "main",
    "aside",
    "nav",
    "hr",
];

/// Class/id segments (split on `-`, `_`, `.`) that mark non-content blocks.
pub(crate) const NEGATIVE: &[&str] = &[
    "nav",
    "navbar",
    "navigation",
    "navbox",
    "menu",
    "menubar",
    "footer",
    "sidebar",
    "sidenav",
    "aside",
    "comment",
    "comments",
    "disqus",
    "advert",
    "advertisement",
    "ad",
    "ads",
    "adsense",
    "adslot",
    "banner",
    "cookie",
    "cookies",
    "consent",
    "popup",
    "modal",
    "overlay",
    "share",
    "sharing",
    "social",
    "related",
    "recommended",
    "promo",
    "sponsor",
    "sponsored",
    "newsletter",
    "subscribe",
    "subscription",
    "breadcrumb",
    "breadcrumbs",
    "widget",
    "toolbar",
    "masthead",
    "skip",
];

/// Whole class/id tokens that vouch for a block being content.
const POSITIVE_EXACT: &[&str] = &[
    "main",
    "content",
    "article",
    "post",
    "entry",
    "page",
    "container",
    "wrapper",
    "body",
    "main-content",
    "content-main",
    "article-body",
    "post-content",
    "entry-content",
    "post-body",
    "story-body",
    "article-content",
    "page-content",
    "hentry",
];

/// Class/id segments that raise a candidate's base score.
const POSITIVE: &[&str] = &[
    "article", "body", "content", "entry", "main", "page", "post", "text", "story", "hentry",
];

fn segments(token: &str) -> impl Iterator<Item = &str> {
    token.split(['-', '_', '.', ':']).filter(|s| !s.is_empty())
}

fn hint_tokens(e: &Elem) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(c) = e.attr("class") {
        out.extend(c.split_whitespace().map(str::to_ascii_lowercase));
    }
    if let Some(i) = e.attr("id") {
        let i = i.trim().to_ascii_lowercase();
        if !i.is_empty() {
            out.push(i);
        }
    }
    out
}

fn negative_hint(e: &Elem) -> bool {
    let tokens = hint_tokens(e);
    if tokens.iter().any(|t| POSITIVE_EXACT.contains(&t.as_str())) {
        return false;
    }
    tokens.iter().any(|t| segments(t).any(|s| NEGATIVE.contains(&s)))
}

fn class_weight(e: &Elem) -> f64 {
    let mut w: f64 = 0.0;
    for t in hint_tokens(e) {
        if segments(&t).any(|s| NEGATIVE.contains(&s)) {
            w -= 25.0;
        } else if segments(&t).any(|s| POSITIVE.contains(&s)) {
            w += 25.0;
        }
    }
    w.clamp(-25.0, 25.0)
}

/// Recompute [`Stats`] bottom-up for `e` and its subtree.
pub fn annotate(e: &mut Elem) {
    let mut st = Stats::default();
    for c in &mut e.children {
        match c {
            Node::Text(t) => {
                let t = t.trim();
                st.text_len += t.chars().count();
                st.commas += t.chars().filter(|c| matches!(c, ',' | '，' | '、')).count();
            }
            Node::Elem(ch) => {
                annotate(ch);
                st.text_len += ch.stats.text_len;
                st.commas += ch.stats.commas;
                st.link_len += ch.stats.link_len;
            }
        }
    }
    if e.tag == "a" && e.attr("href").is_some() {
        st.link_len = st.text_len;
    }
    e.stats = st;
}

fn is_landmark_boilerplate(e: &Elem, in_content: bool) -> bool {
    if matches!(e.tag.as_str(), "nav" | "footer" | "aside" | "dialog") {
        return true;
    }
    if e.tag == "header" && !in_content {
        return true;
    }
    if e.attr("aria-modal")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
    {
        return true;
    }
    match e.role().as_deref() {
        Some("navigation" | "contentinfo" | "complementary" | "search" | "dialog" | "alertdialog") => true,
        Some("banner") => !in_content,
        _ => false,
    }
}

fn is_main_like(e: &Elem) -> bool {
    e.tag == "main" || e.tag == "article" || e.role().as_deref() == Some("main")
}

fn strip(e: &mut Elem, in_content: bool, total: usize) {
    let child_in = in_content || is_main_like(e);
    e.children.retain_mut(|c| match c {
        Node::Text(_) => true,
        Node::Elem(ch) => {
            if is_landmark_boilerplate(ch, child_in) {
                return false;
            }
            let protected = matches!(ch.tag.as_str(), "html" | "body" | "main" | "article")
                || ch.has_main
                || ch.stats.text_len * 10 >= total * 6;
            if !protected && negative_hint(ch) {
                return false;
            }
            strip(ch, child_in, total);
            true
        }
    });
}

fn is_block(e: &Elem) -> bool {
    BLOCK_TAGS.contains(&e.tag.as_str())
}

fn paragraph_value(c: &Elem) -> f64 {
    let para_like = matches!(c.tag.as_str(), "p" | "pre" | "td" | "blockquote")
        || (matches!(c.tag.as_str(), "div" | "section") && !c.child_elems().any(is_block));
    if !para_like || c.stats.text_len < 25 {
        return 0.0;
    }
    1.0 + c.stats.commas as f64 + (c.stats.text_len / 100).min(3) as f64
}

fn base_score(e: &Elem) -> f64 {
    let tag = match e.tag.as_str() {
        "div" => 5.0,
        "article" => 5.0,
        "pre" | "td" | "blockquote" => 3.0,
        "address" | "ol" | "ul" | "dl" | "dd" | "dt" | "li" | "form" => -3.0,
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "th" => -5.0,
        _ => 0.0,
    };
    tag + class_weight(e)
}

fn link_density(e: &Elem) -> f64 {
    e.stats.link_len as f64 / e.stats.text_len.max(1) as f64
}

struct Best {
    score: f64,
    path: Vec<usize>,
}

fn walk(e: &Elem, path: &mut Vec<usize>, best: &mut Best) {
    let mut content = 0.0;
    for c in e.child_elems() {
        content += paragraph_value(c);
        for g in c.child_elems() {
            content += paragraph_value(g) / 2.0;
        }
    }
    if content > 0.0 {
        let score = (base_score(e) + content) * (1.0 - link_density(e));
        if score > best.score {
            best.score = score;
            best.path.clone_from(path);
        }
    }
    for (i, c) in e.children.iter().enumerate() {
        if let Node::Elem(ch) = c {
            path.push(i);
            walk(ch, path, best);
            path.pop();
        }
    }
}

fn find_first<'a>(e: &'a Elem, pred: &dyn Fn(&Elem) -> bool) -> Option<&'a Elem> {
    for c in e.child_elems() {
        if pred(c) {
            return Some(c);
        }
        if let Some(f) = find_first(c, pred) {
            return Some(f);
        }
    }
    None
}

fn collect_outer<'a>(e: &'a Elem, pred: &dyn Fn(&Elem) -> bool, out: &mut Vec<&'a Elem>) {
    for c in e.child_elems() {
        if pred(c) {
            out.push(c);
        } else {
            collect_outer(c, pred, out);
        }
    }
}

fn at_path<'a>(root: &'a Elem, path: &[usize]) -> Vec<&'a Elem> {
    let mut chain = vec![root];
    let mut cur = root;
    for &i in path {
        match cur.children.get(i) {
            Some(Node::Elem(e)) => {
                chain.push(e);
                cur = e;
            }
            _ => break,
        }
    }
    chain
}

/// Remove short, link-dominated blocks (link lists, "share" rows) below `e`.
fn prune_link_heavy(e: &mut Elem) {
    e.children.retain_mut(|c| match c {
        Node::Text(_) => true,
        Node::Elem(ch) => {
            let block = matches!(ch.tag.as_str(), "div" | "ul" | "ol" | "section" | "dl");
            if block && ch.stats.text_len < 250 && link_density(ch) > 0.5 {
                return false;
            }
            prune_link_heavy(ch);
            true
        }
    });
}

/// Strip boilerplate from `body` and return the main content element
/// (a clone of a subtree of the stripped body, or the stripped body itself).
#[must_use]
pub fn extract_main(mut body: Elem) -> Elem {
    annotate(&mut body);
    let total = body.stats.text_len;
    strip(&mut body, false, total);
    annotate(&mut body);
    let total = body.stats.text_len;
    if total == 0 {
        return body;
    }

    if let Some(m) = find_first(&body, &|e| e.tag == "main" || e.role().as_deref() == Some("main")) {
        if m.stats.text_len * 5 >= total {
            return m.clone();
        }
    }
    let mut articles = Vec::new();
    collect_outer(&body, &|e| e.tag == "article", &mut articles);
    if let [only] = articles.as_slice() {
        if only.stats.text_len * 2 >= total {
            return (*only).clone();
        }
    }

    let mut best = Best {
        score: 0.0,
        path: Vec::new(),
    };
    walk(&body, &mut Vec::new(), &mut best);
    if best.score <= 0.0 {
        return body;
    }
    let chain = at_path(&body, &best.path);
    let mut idx = chain.len() - 1;
    while idx > 1 {
        let (top, parent) = (chain[idx], chain[idx - 1]);
        if top.stats.text_len * 4 >= parent.stats.text_len * 3 {
            idx -= 1;
        } else {
            break;
        }
    }
    let chosen = chain[idx];
    if chosen.stats.text_len * 5 < total {
        return body;
    }
    let mut root = chosen.clone();
    prune_link_heavy(&mut root);
    root
}
