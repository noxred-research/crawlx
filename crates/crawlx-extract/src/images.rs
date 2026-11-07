//! The Firecrawl `images` format: every image URL a page references.
//!
//! [`images`] reads `<img>` (`src`, the lazy-loading attributes `data-src`/`data-original`/
//! `data-lazy-src` and every candidate of `srcset`/`data-srcset`), the `srcset` of `<source>`
//! elements inside `<picture>`, and the Open Graph image meta tags. URLs resolve against the
//! document's effective base (`<base href>` aware), are limited to `http`/`https` (inline
//! `data:` images are not URLs worth listing), lose their fragment, and are de-duplicated in
//! document order.

use std::collections::HashSet;

use scraper::Html;
use url::Url;

use crate::dom::{resolve, srcset_urls, walk};
use crate::metadata::effective_base;
use crate::ExtractOptions;

/// Most image URLs returned for one page.
pub const MAX_IMAGES: usize = 5_000;

/// Lazy-loading and plain source attributes of `<img>`, in precedence order.
const IMG_SRC_ATTRS: [&str; 4] = ["src", "data-src", "data-original", "data-lazy-src"];
/// `srcset` attributes of `<img>` and `<source>`.
const SRCSET_ATTRS: [&str; 2] = ["srcset", "data-srcset"];
/// Open Graph meta properties that name an image.
const OG_IMAGE_KEYS: [&str; 3] = ["og:image", "og:image:url", "og:image:secure_url"];

/// Absolute, de-duplicated image URLs of `html` in document order, at most [`MAX_IMAGES`].
/// `base` is the page URL; `<base href>` in the document refines it. Input beyond the default
/// extraction limits yields an empty list. The parse is not charged to [`crate::parse_budget`]:
/// callers hold a [`crate::parse_budget::charge`] around this call.
#[must_use]
pub fn images(html: &str, base: &Url) -> Vec<String> {
    if crate::precheck(html, &ExtractOptions::default()).is_err() {
        return Vec::new();
    }
    let doc = Html::parse_document(html);
    let base = effective_base(&doc, base);
    from_document(&doc, &base)
}

/// Collect image references from an existing, resource-checked HTML parse.
/// `base` must already reflect the document's effective base.
#[must_use]
pub fn from_document(doc: &Html, base: &Url) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |raw: &str| {
        if out.len() >= MAX_IMAGES {
            return;
        }
        if let Some(mut u) = resolve(base, raw) {
            if matches!(u.scheme(), "http" | "https") {
                u.set_fragment(None);
                if seen.insert(u.as_str().to_owned()) {
                    out.push(u.into());
                }
            }
        }
    };
    walk(doc.tree.root(), |el| {
        let v = el.value();
        match v.name() {
            "img" => {
                for name in IMG_SRC_ATTRS {
                    if let Some(s) = v.attr(name) {
                        add(s);
                    }
                }
                for name in SRCSET_ATTRS {
                    if let Some(s) = v.attr(name) {
                        srcset_urls(s).into_iter().for_each(&mut add);
                    }
                }
            }
            "source" => {
                let in_picture = el
                    .parent()
                    .and_then(scraper::ElementRef::wrap)
                    .is_some_and(|p| p.value().name() == "picture");
                if in_picture {
                    for name in SRCSET_ATTRS {
                        if let Some(s) = v.attr(name) {
                            srcset_urls(s).into_iter().for_each(&mut add);
                        }
                    }
                }
            }
            "meta" => {
                let key = v.attr("property").or_else(|| v.attr("name")).map(str::trim);
                if key.is_some_and(|k| OG_IMAGE_KEYS.iter().any(|o| k.eq_ignore_ascii_case(o))) {
                    if let Some(c) = v.attr("content") {
                        add(c);
                    }
                }
                return false;
            }
            "script" | "style" | "template" => return false,
            _ => {}
        }
        true
    });
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn base() -> Url {
        Url::parse("https://example.com/blog/post").unwrap()
    }

    const PAGE: &str = r#"<!doctype html><html><head>
        <meta property="og:image" content="/social/card.png">
        <meta property="og:image:width" content="1200">
        <script>var s = '<img src="/in-script.png">';</script>
      </head><body>
        <img src="logo.svg" alt="logo">
        <img src="/hero.jpg" srcset="/hero-1x.jpg 1x, /hero-2x.jpg 2x, https://cdn.example.org/hero-3x.jpg 3x">
        <img data-src="/lazy.png" src="data:image/gif;base64,R0lGODlhAQABAAAAACw=">
        <picture>
          <source srcset="/art-wide.webp 1200w, /art-narrow.webp 600w" media="(min-width: 800px)">
          <img src="/art.jpg">
        </picture>
        <video><source src="/clip.mp4"></video>
        <img src="/hero.jpg#again">
        <img src="mailto:nobody@example.com">
      </body></html>"#;

    #[test]
    fn collects_img_srcset_picture_and_og_in_document_order_without_duplicates() {
        let got = images(PAGE, &base());
        assert_eq!(
            got,
            [
                "https://example.com/social/card.png",
                "https://example.com/blog/logo.svg",
                "https://example.com/hero.jpg",
                "https://example.com/hero-1x.jpg",
                "https://example.com/hero-2x.jpg",
                "https://cdn.example.org/hero-3x.jpg",
                "https://example.com/lazy.png",
                "https://example.com/art-wide.webp",
                "https://example.com/art-narrow.webp",
                "https://example.com/art.jpg",
            ]
        );
    }

    #[test]
    fn data_uris_scripts_video_sources_and_non_http_schemes_are_skipped() {
        let got = images(PAGE, &base());
        assert!(got.iter().all(|u| u.starts_with("http")));
        assert!(!got
            .iter()
            .any(|u| u.contains("in-script") || u.contains("clip.mp4")));
        assert!(!got.iter().any(|u| u.contains("data:")));
    }

    #[test]
    fn base_href_redirects_relative_urls() {
        let html = r#"<head><base href="https://static.example.net/assets/"></head>
            <body><img src="a.png"><img src="/b.png"></body>"#;
        assert_eq!(
            images(html, &base()),
            [
                "https://static.example.net/assets/a.png",
                "https://static.example.net/b.png"
            ]
        );
    }

    #[test]
    fn result_is_capped() {
        let mut html = String::from("<body>");
        for i in 0..(MAX_IMAGES + 50) {
            html.push_str(&format!("<img src=\"/i{i}.png\">"));
        }
        assert_eq!(images(&html, &base()).len(), MAX_IMAGES);
    }

    #[test]
    fn empty_and_imageless_documents_yield_nothing() {
        assert!(images("", &base()).is_empty());
        assert!(images("<p>no images</p>", &base()).is_empty());
    }
}
