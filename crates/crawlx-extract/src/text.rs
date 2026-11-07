//! Plain-text rendering of the content tree.
//!
//! Paragraph-like blocks are separated by one blank line, line-like blocks
//! (`div`, `li`, `tr`, `br`, ...) by a single newline, table cells by a space.
//! `pre` content is kept verbatim.

use crate::dom::{pre_text, Elem, Node};

struct Out {
    buf: String,
    /// Pending newlines (0, 1 or 2) before the next character.
    newlines: u8,
    /// Pending single space before the next character.
    space: bool,
}

impl Out {
    fn flush_pending(&mut self) {
        if self.buf.is_empty() {
            self.newlines = 0;
            self.space = false;
            return;
        }
        if self.newlines > 0 {
            for _ in 0..self.newlines {
                self.buf.push('\n');
            }
        } else if self.space && !self.buf.ends_with('\n') {
            self.buf.push(' ');
        }
        self.newlines = 0;
        self.space = false;
    }

    fn brk(&mut self, n: u8) {
        self.newlines = self.newlines.max(n);
        self.space = false;
    }

    fn text(&mut self, t: &str) {
        for c in t.chars() {
            if c.is_whitespace() {
                self.space = true;
            } else if !matches!(c, '\u{200b}' | '\u{feff}' | '\u{ad}') {
                self.flush_pending();
                self.buf.push(c);
            }
        }
    }

    fn verbatim(&mut self, t: &str) {
        let t = t.trim_matches('\n');
        if t.trim().is_empty() {
            return;
        }
        self.brk(2);
        self.flush_pending();
        self.buf.push_str(t.trim_end());
        self.brk(2);
    }
}

fn block_break(tag: &str) -> u8 {
    match tag {
        "p" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "blockquote" | "table" | "hr" | "figure" => 2,
        "ul" | "ol" | "dl" | "menu" | "div" | "li" | "tr" | "br" | "dt" | "dd" | "section" | "article"
        | "header" | "footer" | "nav" | "aside" | "main" | "form" | "address" | "figcaption" | "caption"
        | "fieldset" | "center" | "summary" | "details" | "body" | "html" | "legend" => 1,
        _ => 0,
    }
}

fn node(n: &Node, out: &mut Out) {
    match n {
        Node::Text(t) => out.text(t),
        Node::Elem(e) => elem(e, out),
    }
}

fn elem(e: &Elem, out: &mut Out) {
    let tag = e.tag.as_str();
    if tag == "pre" {
        let mut s = String::new();
        pre_text(&e.children, &mut s);
        out.verbatim(&s.replace("\r\n", "\n").replace('\r', "\n"));
        return;
    }
    if matches!(tag, "td" | "th") {
        out.space = true;
        for c in &e.children {
            node(c, out);
        }
        out.space = true;
        return;
    }
    if matches!(tag, "video" | "audio" | "rt" | "rp") {
        return;
    }
    let b = block_break(tag);
    if b > 0 {
        out.brk(b);
    }
    for c in &e.children {
        node(c, out);
    }
    if b > 0 {
        out.brk(b);
    }
}

/// Render `nodes` as plain text.
#[must_use]
pub fn to_text(nodes: &[Node]) -> String {
    let mut out = Out {
        buf: String::new(),
        newlines: 0,
        space: false,
    };
    for n in nodes {
        node(n, &mut out);
    }
    out.buf
}

/// Render a borrowed element without cloning its owned subtree.
pub(crate) fn element_text(element: &Elem) -> String {
    let mut out = Out {
        buf: String::new(),
        newlines: 0,
        space: false,
    };
    elem(element, &mut out);
    out.buf
}
