#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `ExtractOptions::keep_data_images` (compatibility API `removeBase64Images: false`) and its pairing
//! with `base64_images::strip_base64_images`.

use crawlx_extract::base64_images::strip_base64_images;
use crawlx_extract::{ExtractOptions, Extractor};
use url::Url;

fn page() -> Url {
    Url::parse("https://example.com/dir/page").unwrap()
}

fn extract(html: &str, keep: bool) -> crawlx_extract::Document {
    let opts = ExtractOptions {
        only_main_content: false,
        keep_data_images: keep,
        ..ExtractOptions::default()
    };
    Extractor::extract(html, &page(), &opts).unwrap()
}

const PAGE: &str = r#"<html><body><p>Intro</p>
<img src="data:image/png;base64,iVBORw0KGgo=" alt="pic">
<img src="/real.png" alt="real">
<img src="data:text/html;base64,PHNjcmlwdD4=" alt="evil">
<img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" data-src="/lazy.jpg" alt="lazy">
</body></html>"#;

#[test]
fn data_images_are_dropped_by_default() {
    let doc = extract(PAGE, false);
    assert!(!doc.markdown.contains("data:"), "{}", doc.markdown);
    assert!(!doc.html.contains("data:"), "{}", doc.html);
    assert!(doc.markdown.contains("![real](https://example.com/real.png)"));
    assert!(doc.markdown.contains("![lazy](https://example.com/lazy.jpg)"));
}

#[test]
fn keep_data_images_keeps_image_data_uris_verbatim_in_markdown_and_html() {
    let doc = extract(PAGE, true);
    assert!(
        doc.markdown
            .contains("![pic](data:image/png;base64,iVBORw0KGgo=)"),
        "{}",
        doc.markdown
    );
    assert!(
        doc.html
            .contains(r#"<img src="data:image/png;base64,iVBORw0KGgo=" alt="pic">"#),
        "{}",
        doc.html
    );
}

#[test]
fn a_real_source_beats_a_data_placeholder_and_non_image_data_uris_stay_dropped() {
    let doc = extract(PAGE, true);
    assert!(
        doc.markdown.contains("![lazy](https://example.com/lazy.jpg)"),
        "{}",
        doc.markdown
    );
    assert!(!doc.markdown.contains("R0lGOD"), "{}", doc.markdown);
    assert!(!doc.markdown.contains("PHNjcmlwdD4"), "{}", doc.markdown);
    assert!(!doc.html.contains("PHNjcmlwdD4"), "{}", doc.html);
    assert!(doc.markdown.contains("![real](https://example.com/real.png)"));
}

#[test]
fn stripping_removes_what_keeping_kept() {
    let doc = extract(PAGE, true);
    let md = strip_base64_images(&doc.markdown);
    assert!(md.contains("![pic](<Base64-Image-Removed>)"), "{md}");
    assert!(!md.contains("base64,"), "{md}");
    let html = strip_base64_images(&doc.html);
    assert!(
        html.contains(r#"<img src="<Base64-Image-Removed>" alt="pic">"#),
        "{html}"
    );
}

#[test]
fn default_output_is_unchanged_for_pages_without_data_images() {
    let html =
        r#"<html><body><h1>T</h1><p>Hello <a href="/x">link</a></p><img src="/a.png" alt="a"></body></html>"#;
    let (a, b) = (extract(html, false), extract(html, true));
    assert_eq!(a.markdown, b.markdown);
    assert_eq!(a.html, b.html);
}
