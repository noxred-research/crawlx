//! A small CSS scanner for the branding heuristics.
//!
//! It reads stylesheets into flat rules (`selectors` plus `declarations`) without evaluating
//! selectors: that is all the heuristics need. At-rule containers (`@media`, `@supports`,
//! `@layer`, `@container`, `@scope`) are flattened; `@media print` content is dropped; rules in
//! `@media (prefers-color-scheme: dark)` or under selectors that all mention `dark` are marked
//! so the light theme is not diluted. `@font-face` families and `@keyframes` names are
//! collected. CSS nesting is flattened too (the nested selector is kept as written).
//!
//! Everything is bounded: [`MAX_CSS_BYTES`] of input per sheet, [`MAX_RULES`] rules, nesting
//! depth [`MAX_DEPTH`].

/// Longest stylesheet text read; the rest is ignored.
pub(super) const MAX_CSS_BYTES: usize = 2 * 1024 * 1024;
/// Most rules kept over all sheets.
pub(super) const MAX_RULES: usize = 50_000;
/// Deepest block nesting followed.
const MAX_DEPTH: usize = 24;

/// One `property: value` pair; `prop` is lower-cased except for custom properties, `value` has
/// no `!important`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Decl {
    pub prop: String,
    pub value: String,
}

/// A style rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rule {
    /// Comma-separated selectors, lower-cased, whitespace collapsed.
    pub selectors: Vec<String>,
    pub decls: Vec<Decl>,
    /// Applies only to a dark colour scheme.
    pub dark: bool,
}

/// Everything read from the stylesheets of a page.
#[derive(Debug, Default)]
pub(super) struct Sheet {
    pub rules: Vec<Rule>,
    /// Raw `font-family` values of `@font-face` blocks.
    pub font_faces: Vec<String>,
    /// `@keyframes` names in source order.
    pub keyframes: Vec<String>,
}

#[derive(Clone, Copy)]
struct Ctx {
    dark: bool,
    depth: usize,
}

struct Scanner<'a> {
    s: &'a [u8],
    i: usize,
}

/// What ended a prelude.
#[derive(PartialEq, Eq)]
enum End {
    Open,
    Semi,
    Close,
    Eof,
}

impl<'a> Scanner<'a> {
    fn skip_comment(&mut self) -> bool {
        if self.s.get(self.i) == Some(&b'/') && self.s.get(self.i + 1) == Some(&b'*') {
            self.i += 2;
            while self.i < self.s.len() && !(self.s[self.i] == b'*' && self.s.get(self.i + 1) == Some(&b'/'))
            {
                self.i += 1;
            }
            self.i = (self.i + 2).min(self.s.len());
            true
        } else {
            false
        }
    }

    /// Read text up to a top-level `{`, `;` or `}` (comments removed, strings and parentheses
    /// kept whole); the terminator is consumed except `}`.
    fn prelude(&mut self) -> (String, End) {
        let mut buf: Vec<u8> = Vec::new();
        let mut paren = 0usize;
        while self.i < self.s.len() {
            if self.skip_comment() {
                continue;
            }
            let b = self.s[self.i];
            match b {
                b'"' | b'\'' => {
                    buf.push(b);
                    self.i += 1;
                    while self.i < self.s.len() && self.s[self.i] != b {
                        if self.s[self.i] == b'\\' && self.i + 1 < self.s.len() {
                            buf.push(self.s[self.i]);
                            self.i += 1;
                        }
                        buf.push(self.s[self.i]);
                        self.i += 1;
                    }
                    if self.i < self.s.len() {
                        buf.push(b);
                        self.i += 1;
                    }
                    continue;
                }
                b'(' | b'[' => paren += 1,
                b')' | b']' => paren = paren.saturating_sub(1),
                b'{' if paren == 0 => {
                    self.i += 1;
                    return (text(buf), End::Open);
                }
                b';' if paren == 0 => {
                    self.i += 1;
                    return (text(buf), End::Semi);
                }
                b'}' if paren == 0 => return (text(buf), End::Close),
                _ => {}
            }
            buf.push(b);
            self.i += 1;
        }
        (text(buf), End::Eof)
    }

    /// Skip a block whose `{` was already consumed.
    fn skip_block(&mut self) {
        let mut depth = 1usize;
        while self.i < self.s.len() && depth > 0 {
            if self.skip_comment() {
                continue;
            }
            match self.s[self.i] {
                b'"' | b'\'' => {
                    let q = self.s[self.i];
                    self.i += 1;
                    while self.i < self.s.len() && self.s[self.i] != q {
                        if self.s[self.i] == b'\\' {
                            self.i += 1;
                        }
                        self.i += 1;
                    }
                    self.i += 1;
                    continue;
                }
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            self.i += 1;
        }
    }

    /// Parse items until the closing `}` (consumed) or EOF into `decls` and `sheet`.
    fn items(&mut self, ctx: Ctx, decls: &mut Vec<Decl>, sheet: &mut Sheet) {
        loop {
            let (head, end) = self.prelude();
            match end {
                End::Eof => {
                    push_decl(decls, &head);
                    return;
                }
                End::Close => {
                    push_decl(decls, &head);
                    self.i += 1;
                    return;
                }
                End::Semi => push_decl(decls, &head),
                End::Open => {
                    if ctx.depth >= MAX_DEPTH || sheet.rules.len() >= MAX_RULES {
                        self.skip_block();
                    } else if let Some(at) = head.trim().strip_prefix('@') {
                        self.at_rule(at, ctx, sheet);
                    } else {
                        let selectors = split_selectors(&head);
                        let mut inner = Vec::new();
                        let inner_ctx = Ctx {
                            depth: ctx.depth + 1,
                            ..ctx
                        };
                        self.items(inner_ctx, &mut inner, sheet);
                        if !selectors.is_empty() && !inner.is_empty() {
                            let dark = ctx.dark || selectors.iter().all(|s| s.contains("dark"));
                            sheet.rules.push(Rule {
                                selectors,
                                decls: inner,
                                dark,
                            });
                        }
                    }
                }
            }
        }
    }

    fn at_rule(&mut self, at: &str, ctx: Ctx, sheet: &mut Sheet) {
        let name_end = at
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(at.len());
        let (name, params) = at.split_at(name_end);
        let name = name.to_ascii_lowercase();
        let params = params.trim().to_ascii_lowercase();
        let inner_ctx = Ctx {
            depth: ctx.depth + 1,
            ..ctx
        };
        match name.as_str() {
            "media"
                if params
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .any(|w| w == "print") =>
            {
                self.skip_block()
            }
            "media" | "supports" | "layer" | "container" | "scope" | "document" | "-moz-document" => {
                let dark = ctx.dark || (params.contains("prefers-color-scheme") && params.contains("dark"));
                let mut scratch = Vec::new();
                self.items(Ctx { dark, ..inner_ctx }, &mut scratch, sheet);
            }
            "font-face" => {
                let mut inner = Vec::new();
                self.items(inner_ctx, &mut inner, sheet);
                if let Some(d) = inner.into_iter().find(|d| d.prop == "font-family") {
                    sheet.font_faces.push(d.value);
                }
            }
            "keyframes" | "-webkit-keyframes" | "-moz-keyframes" => {
                let kf = unquote(&params);
                if !kf.is_empty() && sheet.keyframes.len() < 64 && !sheet.keyframes.contains(&kf) {
                    sheet.keyframes.push(kf);
                }
                self.skip_block();
            }
            _ => self.skip_block(),
        }
    }
}

fn text(buf: Vec<u8>) -> String {
    String::from_utf8(buf).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches(|c| c == '"' || c == '\'').to_owned()
}

fn split_selectors(head: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    let mut push = |piece: &str| {
        let norm = piece
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase();
        if !norm.is_empty() {
            out.push(norm);
        }
    };
    for (i, c) in head.char_indices() {
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                push(&head[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    push(&head[start..]);
    out
}

/// Append the declaration in `raw` (`prop: value`), ignoring anything else.
fn push_decl(decls: &mut Vec<Decl>, raw: &str) {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('@') {
        return;
    }
    let Some((prop, value)) = raw.split_once(':') else {
        return;
    };
    let prop = prop.trim();
    if prop.is_empty() || prop.contains(char::is_whitespace) {
        return;
    }
    let mut value = value.trim();
    if let Some(i) = value.to_ascii_lowercase().rfind("!important") {
        value = value[..i].trim_end();
    }
    if value.is_empty() {
        return;
    }
    let prop = if prop.starts_with("--") {
        prop.to_owned()
    } else {
        prop.to_ascii_lowercase()
    };
    decls.push(Decl {
        prop,
        value: value.to_owned(),
    });
}

/// Parse `css` (at most [`MAX_CSS_BYTES`]) and append what it holds to `sheet`.
pub(super) fn parse(css: &str, sheet: &mut Sheet) {
    let mut end = css.len().min(MAX_CSS_BYTES);
    while !css.is_char_boundary(end) {
        end -= 1;
    }
    let mut sc = Scanner {
        s: &css.as_bytes()[..end],
        i: 0,
    };
    let ctx = Ctx {
        dark: false,
        depth: 0,
    };
    let mut stray = Vec::new();
    while sc.i < sc.s.len() {
        sc.items(ctx, &mut stray, sheet);
    }
}

/// Declarations of a `style=""` attribute.
pub(super) fn parse_declarations(attr: &str) -> Vec<Decl> {
    let mut sc = Scanner {
        s: attr.as_bytes(),
        i: 0,
    };
    let mut decls = Vec::new();
    loop {
        let (head, end) = sc.prelude();
        push_decl(&mut decls, &head);
        match end {
            End::Eof => return decls,
            End::Close => sc.i += 1,
            End::Open | End::Semi => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn sheet(css: &str) -> Sheet {
        let mut s = Sheet::default();
        parse(css, &mut s);
        s
    }

    #[test]
    fn rules_selectors_and_declarations() {
        let s = sheet(
            "/* c */ body , HTML{ color:#111 ; background : #fff !important }\n.a:hover > b { margin: 0 }",
        );
        assert_eq!(s.rules.len(), 2);
        assert_eq!(s.rules[0].selectors, ["body", "html"]);
        assert_eq!(
            s.rules[0].decls[1],
            Decl {
                prop: "background".into(),
                value: "#fff".into()
            }
        );
        assert_eq!(s.rules[1].selectors, [".a:hover > b"]);
    }

    #[test]
    fn semicolons_inside_urls_and_strings_do_not_split() {
        let s = sheet("a{background:url(data:image/png;base64,AAAA) #123;font-family:\"A;B\",serif}");
        let d = &s.rules[0].decls;
        assert_eq!(d.len(), 2);
        assert!(d[0].value.starts_with("url(data:image/png;base64"));
        assert_eq!(d[1].value, "\"A;B\",serif");
    }

    #[test]
    fn media_is_flattened_print_dropped_and_dark_marked() {
        let s = sheet(
            "@media (min-width:600px){.x{color:red}}\
             @media print{.p{color:green}}\
             @media (prefers-color-scheme: dark){.d{color:#fff}}\
             .dark .y{color:blue}",
        );
        let by = |sel: &str| s.rules.iter().find(|r| r.selectors[0] == sel);
        assert!(!by(".x").unwrap().dark);
        assert!(by(".p").is_none());
        assert!(by(".d").unwrap().dark);
        assert!(by(".dark .y").unwrap().dark);
    }

    #[test]
    fn custom_properties_keep_their_case_and_font_faces_keyframes_are_collected() {
        let s = sheet(
            ":root{--Brand:#ff6b35}\
             @font-face{font-family:'My Font';src:url(a.woff2)}\
             @keyframes spin{from{opacity:0}to{opacity:1}}\
             @import url(x.css);\
             a{color:red}",
        );
        assert_eq!(s.rules[0].decls[0].prop, "--Brand");
        assert_eq!(s.font_faces, ["'My Font'"]);
        assert_eq!(s.keyframes, ["spin"]);
        assert_eq!(s.rules.len(), 2);
    }

    #[test]
    fn nested_rules_are_flattened_and_garbage_never_panics() {
        let s = sheet(".card{color:red;&:hover{color:blue}.t{color:green}}");
        assert_eq!(s.rules.len(), 3);
        for junk in [
            "}}}{{{",
            "a{",
            "a{b",
            "@media{",
            "/*",
            "a{b:'",
            "\u{1F600}{color:red}",
            "a{color:red;;;}",
        ] {
            let _ = sheet(junk);
        }
    }

    #[test]
    fn style_attribute_declarations() {
        let d = parse_declarations("color: red; background:url(a;b) #000 !important;;font-weight:700");
        let pairs: Vec<(&str, &str)> = d.iter().map(|x| (x.prop.as_str(), x.value.as_str())).collect();
        assert_eq!(
            pairs,
            [
                ("color", "red"),
                ("background", "url(a;b) #000"),
                ("font-weight", "700")
            ]
        );
    }

    #[test]
    fn rule_count_is_bounded() {
        let css = "a{color:red}".repeat(MAX_RULES + 10);
        assert_eq!(sheet(&css).rules.len(), MAX_RULES);
    }
}
