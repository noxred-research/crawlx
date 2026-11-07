//! Link and asset extraction.
//!
//! Links come from `a[href]` and `area[href]` only. Relative references are
//! resolved against the effective base (`<base href>` aware) with
//! `url::Url::join`; only `http` and `https` targets are kept. Fragments are
//! removed and pure-fragment hrefs (`#top`) are skipped because they never
//! lead to another page. Duplicates collapse into the first occurrence: the
//! first non-empty text wins, `rel` tokens are unioned, and a link is
//! `nofollow` only if every occurrence is.

use std::collections::HashMap;

use scraper::{ElementRef, Html};
use url::Url;

use crate::document::ExtractedLink;
use crate::dom::{collapse_ws, resolve, srcset_urls, walk};
use crate::metadata::effective_base;
use crate::ExtractError;

/// Maximum length of the text stored per link.
const MAX_LINK_TEXT: usize = 512;

fn anchor_text(el: ElementRef<'_>) -> String {
    let mut t = collapse_ws(&el.text().collect::<String>());
    if t.is_empty() {
        let alt = el
            .descendent_elements()
            .find_map(|d| d.value().attr("alt").map(collapse_ws).filter(|a| !a.is_empty()));
        t = alt
            .or_else(|| {
                el.value()
                    .attr("title")
                    .map(collapse_ws)
                    .filter(|a| !a.is_empty())
            })
            .or_else(|| {
                el.value()
                    .attr("aria-label")
                    .map(collapse_ws)
                    .filter(|a| !a.is_empty())
            })
            .unwrap_or_default();
    }
    if t.chars().count() > MAX_LINK_TEXT {
        t = t.chars().take(MAX_LINK_TEXT).collect();
    }
    t
}

/// Extract deduplicated links from a parsed document.
///
/// `page` is the URL the document was fetched from (used for the
/// internal/external decision); `base` is the effective base for resolution.
#[must_use]
pub fn extract_links(html: &Html, page: &Url, base: &Url) -> Vec<ExtractedLink> {
    let mut out: Vec<ExtractedLink> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    walk(html.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "script" | "style" | "template" => return false,
            "a" | "area" => {}
            _ => return true,
        }
        let Some(href) = v.attr("href").map(str::trim) else {
            return true;
        };
        if href.is_empty() || href.starts_with('#') {
            return true;
        }
        let Some(mut url) = resolve(base, href) else {
            return true;
        };
        if !matches!(url.scheme(), "http" | "https") {
            return true;
        }
        url.set_fragment(None);
        let rel: Vec<String> = v
            .attr("rel")
            .unwrap_or("")
            .split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect();
        let nofollow = rel.iter().any(|r| r == "nofollow");
        let text = anchor_text(el);
        match index.get(url.as_str()) {
            Some(&i) => {
                let l = &mut out[i];
                if l.text.is_empty() {
                    l.text = text;
                }
                for r in rel {
                    if !l.rel.contains(&r) {
                        l.rel.push(r);
                    }
                }
                l.nofollow &= nofollow;
            }
            None => {
                index.insert(url.as_str().to_owned(), out.len());
                let internal = url.host_str().is_some() && url.host_str() == page.host_str();
                out.push(ExtractedLink {
                    url,
                    text,
                    rel,
                    nofollow,
                    internal,
                });
            }
        }
        true
    });
    out
}

/// Extract asset URLs (images, media, scripts, stylesheets, icons) in
/// document order, deduplicated, `http`/`https` only.
#[must_use]
pub fn extract_assets(html: &Html, base: &Url) -> Vec<Url> {
    let mut out: Vec<Url> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut add = |raw: &str| {
        if let Some(mut u) = resolve(base, raw) {
            if matches!(u.scheme(), "http" | "https") {
                u.set_fragment(None);
                if seen.insert(u.as_str().to_owned()) {
                    out.push(u);
                }
            }
        }
    };
    walk(html.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "img" => {
                for name in ["src", "data-src", "data-original", "data-lazy-src"] {
                    if let Some(s) = v.attr(name) {
                        add(s);
                    }
                }
                for name in ["srcset", "data-srcset"] {
                    if let Some(s) = v.attr(name) {
                        srcset_urls(s).into_iter().for_each(&mut add);
                    }
                }
            }
            "source" => {
                if let Some(s) = v.attr("src") {
                    add(s);
                }
                if let Some(s) = v.attr("srcset") {
                    srcset_urls(s).into_iter().for_each(&mut add);
                }
            }
            "video" => {
                for name in ["src", "poster"] {
                    if let Some(s) = v.attr(name) {
                        add(s);
                    }
                }
            }
            "audio" | "track" | "embed" => {
                if let Some(s) = v.attr("src") {
                    add(s);
                }
            }
            "object" => {
                if let Some(s) = v.attr("data") {
                    add(s);
                }
            }
            "script" => {
                if let Some(s) = v.attr("src") {
                    add(s);
                }
                return false;
            }
            "link" => {
                let rel = v.attr("rel").unwrap_or("").to_ascii_lowercase();
                let wanted = rel.split_whitespace().any(|r| {
                    matches!(
                        r,
                        "stylesheet"
                            | "icon"
                            | "apple-touch-icon"
                            | "apple-touch-icon-precomposed"
                            | "manifest"
                    )
                });
                if wanted {
                    if let Some(s) = v.attr("href") {
                        add(s);
                    }
                }
                return false;
            }
            "style" | "template" => return false,
            _ => {}
        }
        true
    });
    out
}

/// Standalone link extractor.
pub struct LinkExtractor;

impl LinkExtractor {
    /// Parse `html` and return its links, honouring `<base href>`.
    ///
    /// # Errors
    /// [`ExtractError::TooLarge`] when `html` exceeds the default size, node or depth limits;
    /// [`ExtractError::ParseMemory`] when the process-wide parse-memory budget is exhausted.
    pub fn links(html: &str, page: &Url) -> Result<Vec<ExtractedLink>, ExtractError> {
        let opts = crate::ExtractOptions::default();
        crate::precheck(html, &opts)?;
        // declared before `doc`: released after the parsed tree is dropped
        let _charge = crate::parse_budget::charge(html.len())?;
        let doc = Html::parse_document(html);
        crate::dom::check_limits(&doc, opts.max_nodes)?;
        let base = effective_base(&doc, page);
        Ok(extract_links(&doc, page, &base))
    }
}
