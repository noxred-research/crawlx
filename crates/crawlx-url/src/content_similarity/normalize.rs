//! Page-body normalization for similarity scoring.
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md.
//!
//! HTML bodies are reduced to the text of `main`/`[role=main]` (else every
//! `article`, else `body`) with `script`/`style`/`noscript`/`svg`/`template`
//! removed everywhere and `nav`/`header`/`footer`/`aside` removed inside the
//! chosen root; non-HTML bodies are tokenized as plain text.

use ego_tree::NodeRef;
use scraper::{Html, Node};

/// Fewer tokens than this is "low signal": such pages are always accepted.
pub const MIN_TOKENS: usize = 5;
/// Shingle width in tokens.
pub const SHINGLE_SIZE: usize = 3;

/// Elements removed everywhere.
const REMOVED: &[&str] = &["script", "style", "noscript", "svg", "template"];
/// Chrome removed inside the chosen root.
const CHROME: &[&str] = &["nav", "header", "footer", "aside"];

/// Normalized page content ready for similarity scoring.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Document {
    /// Lowercased alphanumeric tokens of length ≥ 2, in document order.
    pub tokens: Vec<String>,
    /// 3-token shingles (or the tokens themselves when fewer than 3).
    pub shingles: Vec<String>,
}

/// Extract comparable features from `body`; `None` when there is too little
/// signal (fewer than [`MIN_TOKENS`] tokens). An HTML body is parsed by `parse`, so the caller
/// decides how the tree is built and charged (the worker builds it under the parse-memory
/// budget); a plain-text body never calls it.
///
/// # Errors
/// The error `parse` returns for an HTML body.
pub fn normalize<E>(body: &[u8], parse: impl FnOnce(&str) -> Result<Html, E>) -> Result<Option<Document>, E> {
    let text = extract_text(body, parse)?;
    let tokens = tokenize(&text);
    if tokens.len() < MIN_TOKENS {
        return Ok(None);
    }
    let shingles = shingles(&tokens, SHINGLE_SIZE);
    Ok(Some(Document { tokens, shingles }))
}

fn looks_html(trimmed: &[u8]) -> bool {
    let head = &trimmed[..trimmed.len().min(512)];
    let head_lower = head.to_ascii_lowercase();
    contains(&head_lower, b"<html")
        || contains(&head_lower, b"<!doctype")
        || contains(trimmed, b"<body")
        || contains(trimmed, b"<div")
        || contains(trimmed, b"<p")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Root elements compared: the first `main`/`[role=main]`, else every
/// `article` (so multi-article index pages are compared on their full
/// content), else `body`, else the document.
fn roots(doc: &Html) -> Vec<NodeRef<'_, Node>> {
    let mut main = None;
    let mut articles = Vec::new();
    let mut body = None;
    let mut stack = vec![doc.tree.root()];
    while let Some(n) = stack.pop() {
        if let Node::Element(el) = n.value() {
            let name = el.name();
            if main.is_none() && (name == "main" || el.attr("role").is_some_and(|r| r.trim() == "main")) {
                main = Some(n);
                break;
            }
            if name == "article" {
                articles.push(n);
            } else if name == "body" && body.is_none() {
                body = Some(n);
            }
        }
        stack.extend(n.children().rev());
    }
    if let Some(m) = main {
        vec![m]
    } else if !articles.is_empty() {
        articles
    } else {
        vec![body.unwrap_or_else(|| doc.tree.root())]
    }
}

/// Text of the body: the chosen root's text with chrome and code removed,
/// or the raw body when it is not HTML. An HTML body is parsed by `parse`.
///
/// # Errors
/// The error `parse` returns for an HTML body.
pub fn extract_text<E>(body: &[u8], parse: impl FnOnce(&str) -> Result<Html, E>) -> Result<String, E> {
    let trimmed = String::from_utf8_lossy(body);
    let trimmed = trimmed.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !looks_html(trimmed.as_bytes()) {
        return Ok(trimmed.to_owned());
    }
    let doc = parse(trimmed)?;
    let mut out = String::new();
    for root in roots(&doc) {
        collect_text(root, true, &mut out);
    }
    Ok(out)
}

fn collect_text(node: ego_tree::NodeRef<'_, Node>, strip_chrome: bool, out: &mut String) {
    for child in node.children() {
        match child.value() {
            Node::Text(t) => out.push_str(t),
            Node::Element(el) => {
                let name = el.name();
                if REMOVED.contains(&name) || (strip_chrome && CHROME.contains(&name)) {
                    continue;
                }
                collect_text(child, strip_chrome, out);
            }
            _ => {}
        }
    }
}

/// Lowercased alphanumeric runs of at least two characters.
#[must_use]
pub fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|f| f.chars().count() >= 2)
        .map(str::to_lowercase)
        .collect()
}

/// `n`-token shingles; the tokens themselves when fewer than `n`.
#[must_use]
pub fn shingles(tokens: &[String], n: usize) -> Vec<String> {
    if n == 0 || tokens.len() < n {
        return tokens.to_vec();
    }
    tokens.windows(n).map(|w| w.join(" ")).collect()
}

/// Test-only [`normalize`] with the plain, uncharged `scraper` parse.
#[cfg(test)]
pub(crate) fn normalize_plain(body: &[u8]) -> Option<Document> {
    match normalize(body, |html| {
        Ok::<_, std::convert::Infallible>(Html::parse_document(html))
    }) {
        Ok(doc) => doc,
        Err(never) => match never {},
    }
}

#[cfg(test)]
pub(crate) fn html_page(nav: &str, main: &str) -> Vec<u8> {
    format!(
        "<!doctype html><html><body>\n<nav>{nav}</nav>\n<main>{main}</main>\n<footer>copyright 2026 example corp</footer>\n<script>var x = 1;</script>\n</body></html>"
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn strips_chrome_and_scripts() {
        let doc = normalize_plain(&html_page(
            "Home About Contact Login",
            "Unique Product Alpha with rare widget terminology and packing details",
        ))
        .unwrap();
        let joined = doc.tokens.join(" ");
        assert!(joined.contains("unique") && joined.contains("product"));
        assert!(!joined.contains("login"));
        assert!(!joined.contains("copyright"));
        assert!(!joined.contains("var"));
    }

    #[test]
    fn plain_text_and_too_short() {
        let doc = normalize_plain(b"Alpha beta gamma delta epsilon zeta eta").unwrap();
        assert!(doc.tokens.len() >= MIN_TOKENS);
        assert_eq!(doc.shingles.len(), doc.tokens.len() - SHINGLE_SIZE + 1);
        assert!(normalize_plain(b"hi").is_none());
        assert!(normalize_plain(b"").is_none());
    }

    #[test]
    fn multi_article_without_main_uses_all_articles() {
        let a = b"<!doctype html><html><body>\n<article>Shared lead story about space telescopes and deep sky surveys with nebulae catalogs</article>\n<article>Unique page one second story about urban cycling cargo bikes commuting safety</article>\n</body></html>";
        let b = b"<!doctype html><html><body>\n<article>Shared lead story about space telescopes and deep sky surveys with nebulae catalogs</article>\n<article>Unique page two second story about sourdough baking hydration fermentation crumb</article>\n</body></html>";
        let ja = normalize_plain(a).unwrap().tokens.join(" ");
        let jb = normalize_plain(b).unwrap().tokens.join(" ");
        assert!(ja.contains("cycling"));
        assert!(jb.contains("sourdough"));
        assert_ne!(ja, jb);
    }

    #[test]
    fn body_fallback_strips_nested_chrome_and_keeps_main_only() {
        let body = b"<html><body><header>Site Header Words</header><div><p>Body paragraph with several distinct words here</p><aside>Side note words</aside></div></body></html>";
        let j = normalize_plain(body).unwrap().tokens.join(" ");
        assert!(j.contains("paragraph"));
        assert!(!j.contains("header") && !j.contains("side"));
        let with_main = b"<html><body><div>Outside the landmark text that is ignored</div><div role=main>Inside landmark alpha beta gamma delta epsilon</div></body></html>";
        let j = normalize_plain(with_main).unwrap().tokens.join(" ");
        assert!(j.contains("inside") && !j.contains("outside"));
    }
}
