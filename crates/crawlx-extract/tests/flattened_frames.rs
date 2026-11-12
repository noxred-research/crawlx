//! Extraction over a flattened browser serialization: text of shadow roots and frames reaches
//! the outputs, the frame provenance markers survive in the cleaned HTML only in their
//! validated form, and page-authored attributes on those elements never do.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::{Document, ExtractOptions, Extractor};
use url::Url;

fn extract(html: &str) -> Document {
    let base = Url::parse("https://example.com/").unwrap();
    Extractor::extract(html, &base, &ExtractOptions::default()).unwrap()
}

const FLATTENED: &str = concat!(
    "<!DOCTYPE html><html><head><title>Host</title></head><body>",
    "<article><h1>Heading</h1><p>light paragraph with enough words to count as the main content of the page.</p>",
    "<div><crawlx-shadow data-crawlx-mode=\"open\"><p>shadow paragraph that is part of the same article text.</p></crawlx-shadow></div>",
    "<crawlx-frame data-crawlx-frame=\"1\" data-crawlx-origin=\"https://widgets.example\" data-crawlx-status=\"flattened\">",
    "<p>frame paragraph that belongs to another origin entirely.</p></crawlx-frame>",
    "<crawlx-frame data-crawlx-frame=\"2\" data-crawlx-origin=\"http://127.0.0.1:8080\" data-crawlx-status=\"cross_origin\"></crawlx-frame>",
    "</article></body></html>"
);

#[test]
fn shadow_and_frame_text_reach_the_markdown_text_and_html() {
    let doc = extract(FLATTENED);
    for part in ["light paragraph", "shadow paragraph", "frame paragraph"] {
        assert!(
            doc.markdown.contains(part),
            "markdown lacks {part}: {}",
            doc.markdown
        );
        assert!(doc.text.contains(part), "text lacks {part}: {}", doc.text);
        assert!(doc.html.contains(part), "html lacks {part}: {}", doc.html);
    }
}

#[test]
fn validated_provenance_markers_survive_in_the_cleaned_html() {
    let doc = extract(FLATTENED);
    assert!(
        doc.html.contains(
            "<crawlx-frame data-crawlx-frame=\"1\" data-crawlx-origin=\"https://widgets.example\" data-crawlx-status=\"flattened\">"
        ),
        "{}",
        doc.html
    );
    assert!(
        doc.html.contains("<crawlx-shadow data-crawlx-mode=\"open\">"),
        "{}",
        doc.html
    );
}

#[test]
fn malformed_or_extra_attributes_on_provenance_elements_are_dropped() {
    let hostile = concat!(
        "<!DOCTYPE html><html><body><article><p>text long enough to be the main content of this page, really.</p>",
        "<crawlx-frame data-crawlx-frame=\"12x\" data-crawlx-origin=\"javascript:alert(1)\" data-crawlx-status=\"trusted\" onclick=\"x()\" class=\"c\">a</crawlx-frame>",
        "<crawlx-frame data-crawlx-frame=\"3\" data-crawlx-origin=\"https://a.example/path?q=1\" data-crawlx-status=\"flattened\">b</crawlx-frame>",
        "<crawlx-shadow data-crawlx-mode=\"closed\" id=\"x\">c</crawlx-shadow>",
        "</article></body></html>"
    );
    let doc = extract(hostile);
    assert!(!doc.html.contains("javascript:"), "{}", doc.html);
    assert!(!doc.html.contains("onclick"), "{}", doc.html);
    assert!(!doc.html.contains("trusted"), "{}", doc.html);
    assert!(!doc.html.contains("12x"), "{}", doc.html);
    assert!(
        !doc.html.contains("a.example"),
        "an origin with a path or query is not an origin: {}",
        doc.html
    );
    assert!(!doc.html.contains("closed"), "{}", doc.html);
    assert!(!doc.html.contains("id=\"x\""), "{}", doc.html);
    // the page's text is still there
    for part in ["a", "b", "c"] {
        assert!(doc.text.contains(part));
    }
}
