//! Removal of inline base64 images from rendered output (compatibility API `removeBase64Images`).
//!
//! Inline `data:image/...;base64,<payload>` URIs bloat Markdown and HTML without carrying
//! anything a text consumer can use. [`strip_base64_images`] replaces every such URI with the
//! placeholder [`PLACEHOLDER`] and leaves the surrounding syntax intact, so
//! `![logo](data:image/png;base64,AAAA)` becomes `![logo](<Base64-Image-Removed>)`,
//! `<img src="data:image/gif;base64,R0lG">` becomes `<img src="<Base64-Image-Removed>">` and
//! `url(data:image/svg+xml;base64,PHN2)` becomes `url(<Base64-Image-Removed>)`.
//!
//! Only base64 image URIs are touched: non-image data URIs and percent-encoded (non-base64)
//! `data:image/svg+xml,%3Csvg` URIs are kept.

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;

/// Text that replaces a removed base64 image URI (the compatibility API's literal).
pub const PLACEHOLDER: &str = "<Base64-Image-Removed>";

/// Marker every removable URI contains; a cheap guard before the regex runs.
const MARKER: &str = ";base64,";

/// `data:image/<subtype>[;param=value]*;base64,<payload>`. The payload alphabet is standard and
/// URL-safe base64 including padding; it stops at whitespace, quotes, parentheses or `<`/`>`.
/// `None` only if the constant pattern fails to compile (asserted by the unit tests).
static DATA_URI: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)data:image/[a-z0-9.+_-]+(?:;[a-z0-9._-]+=[a-z0-9._+-]+)*;base64,[a-z0-9+/_=-]*").ok()
});

/// Replace every inline base64 image URI of `text` (Markdown, HTML or CSS) with
/// [`PLACEHOLDER`]. Returns the input borrowed when there is nothing to remove.
#[must_use]
pub fn strip_base64_images(text: &str) -> Cow<'_, str> {
    match DATA_URI.as_ref() {
        Some(re) if text.contains(MARKER) => re.replace_all(text, regex::NoExpand(PLACEHOLDER)),
        _ => Cow::Borrowed(text),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn pattern_compiles() {
        assert!(DATA_URI.is_some());
    }

    #[test]
    fn markdown_image_keeps_alt_and_drops_payload() {
        let md = "Intro\n\n![logo](data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==)\n\nText";
        let out = strip_base64_images(md);
        assert_eq!(out, "Intro\n\n![logo](<Base64-Image-Removed>)\n\nText");
    }

    #[test]
    fn markdown_image_with_title_keeps_title() {
        let md = r#"![a](data:image/jpeg;base64,/9j/4AAQSkZJRg "Photo")"#;
        assert_eq!(strip_base64_images(md), r#"![a](<Base64-Image-Removed> "Photo")"#);
    }

    #[test]
    fn html_img_src_and_srcset_are_stripped() {
        let html = concat!(
            r#"<p><img alt="x" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7">"#,
            r#"<img srcset="data:image/webp;base64,UklGRg== 1x, /real.webp 2x"></p>"#
        );
        let out = strip_base64_images(html);
        assert_eq!(
            out,
            concat!(
                r#"<p><img alt="x" src="<Base64-Image-Removed>">"#,
                r#"<img srcset="<Base64-Image-Removed> 1x, /real.webp 2x"></p>"#
            )
        );
    }

    #[test]
    fn css_url_in_style_is_stripped_in_quoted_and_bare_forms() {
        let css = "a{background:url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciLz4=)}\
                   b{background:url('data:image/png;charset=utf-8;base64,AAAA')}";
        let out = strip_base64_images(css);
        assert_eq!(
            out,
            "a{background:url(<Base64-Image-Removed>)}b{background:url('<Base64-Image-Removed>')}"
        );
    }

    #[test]
    fn non_image_and_non_base64_data_uris_are_kept() {
        let text =
            "[f](data:text/plain;base64,SGVsbG8=) <img src=\"data:image/svg+xml,%3Csvg%3E%3C/svg%3E\">";
        let out = strip_base64_images(text);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(out, text);
    }

    #[test]
    fn text_without_a_data_uri_is_returned_borrowed() {
        let text = "![a](https://example.com/a.png) base64 is a word here";
        assert!(matches!(strip_base64_images(text), Cow::Borrowed(_)));
    }

    #[test]
    fn several_images_are_all_removed() {
        let text = "![a](data:image/png;base64,AAAA) ![b](data:image/png;base64,BBBB)";
        assert_eq!(
            strip_base64_images(text),
            "![a](<Base64-Image-Removed>) ![b](<Base64-Image-Removed>)"
        );
    }
}
