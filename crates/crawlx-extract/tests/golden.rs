#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Golden tests: HTML fixtures in `tests/fixtures/*.html` against expected
//! Markdown in `tests/fixtures/*.md`.

use crawlx_extract::{ExtractError, ExtractOptions, Extractor};
use url::Url;

fn fixture(name: &str) -> String {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {p}: {e}"))
}

fn page(u: &str) -> Url {
    Url::parse(u).unwrap()
}

fn opts(only_main: bool) -> ExtractOptions {
    ExtractOptions {
        only_main_content: only_main,
        ..ExtractOptions::default()
    }
}

#[test]
fn article_with_nested_lists_code_and_table() {
    let doc = Extractor::extract(
        &fixture("article.html"),
        &page("https://example.com/post"),
        &opts(true),
    )
    .unwrap();
    assert_eq!(doc.markdown, fixture("article.md").trim_end_matches('\n'));
    assert_eq!(doc.title.as_deref(), Some("Parsing Pipelines"));
    assert_eq!(doc.language.as_deref(), Some("en"));
    assert!(!doc.markdown.contains("tracking"));
    assert!(!doc.html.contains("script"));
    assert!(doc.word_count > 50);
}

#[test]
fn article_is_identical_without_main_content_filter() {
    let a = Extractor::extract(
        &fixture("article.html"),
        &page("https://example.com/post"),
        &opts(true),
    )
    .unwrap();
    let b = Extractor::extract(
        &fixture("article.html"),
        &page("https://example.com/post"),
        &opts(false),
    )
    .unwrap();
    assert_eq!(a.markdown, b.markdown);
}

#[test]
fn noise_is_stripped_when_only_main_content() {
    let doc = Extractor::extract(&fixture("noise.html"), &page("https://example.com/"), &opts(true)).unwrap();
    assert_eq!(doc.markdown, fixture("noise.md").trim_end_matches('\n'));
    for noise in [
        "Menu A",
        "Trend one",
        "Copyright",
        "Nice article",
        "hidden by",
        "Share this",
        "Related links",
    ] {
        assert!(!doc.markdown.contains(noise), "{noise} leaked into main content");
        assert!(!doc.text.contains(noise), "{noise} leaked into text");
    }
}

#[test]
fn noise_without_filter_keeps_navigation_but_not_hidden_or_scripts() {
    let doc = Extractor::extract(
        &fixture("noise.html"),
        &page("https://example.com/"),
        &opts(false),
    )
    .unwrap();
    for kept in [
        "Menu A",
        "Trend one",
        "Copyright footer text",
        "Nice article",
        "The Real Story",
    ] {
        assert!(doc.markdown.contains(kept), "{kept} missing");
    }
    for dropped in ["hidden by style", "hidden by attribute", "hidden by aria", "evil"] {
        assert!(!doc.markdown.contains(dropped), "{dropped} should be removed");
    }
}

#[test]
fn base_href_and_relative_links() {
    let doc = Extractor::extract(
        &fixture("links_base.html"),
        &page("https://www.example.com/a/b"),
        &opts(false),
    )
    .unwrap();
    assert_eq!(doc.markdown, fixture("links_base.md").trim_end_matches('\n'));
    assert_eq!(doc.base_url.as_str(), "https://cdn.example.com/docs/v2/");
    let got: Vec<(&str, &str, bool, bool)> = doc
        .links
        .iter()
        .map(|l| (l.url.as_str(), l.text.as_str(), l.nofollow, l.internal))
        .collect();
    assert_eq!(
        got,
        vec![
            (
                "https://cdn.example.com/docs/v2/intro.html",
                "Intro",
                false,
                false
            ),
            ("https://cdn.example.com/docs/index.html", "Index", false, false),
            ("https://cdn.example.com/root", "Root", false, false),
            ("https://other.example.net/x", "Protocol relative", false, false),
            ("https://www.example.com/page", "Page host", false, true),
            (
                "https://cdn.example.com/docs/v2/ext.html",
                "External nofollow",
                true,
                false
            ),
        ]
    );
    let intro = &doc.links[0];
    assert_eq!(intro.rel, vec!["nofollow".to_owned()]);
    let assets: Vec<&str> = doc.assets.iter().map(Url::as_str).collect();
    assert_eq!(
        assets,
        vec![
            "https://cdn.example.com/docs/v2/pics/a.png",
            "https://cdn.example.com/docs/v2/pics/lazy.png"
        ]
    );
}

#[test]
fn metadata_open_graph_twitter_and_fallbacks() {
    let doc = Extractor::extract(
        &fixture("metadata.html"),
        &page("https://example.com/blog/x"),
        &opts(true),
    )
    .unwrap();
    // og:title wins over <title>.
    assert_eq!(doc.title.as_deref(), Some("OG Title"));
    assert_eq!(doc.description.as_deref(), Some("Plain description"));
    assert_eq!(doc.language.as_deref(), Some("en-GB"));
    assert_eq!(doc.base_url.as_str(), "https://example.com/blog/");
    assert_eq!(
        doc.canonical_url.as_ref().map(Url::as_str),
        Some("https://example.com/blog/post-1")
    );
    let md = &doc.metadata;
    assert_eq!(
        md.open_graph.get("og:title").map(String::as_str),
        Some("OG Title")
    );
    assert_eq!(
        md.open_graph.get("og:image").map(String::as_str),
        Some("img/cover.png")
    );
    assert_eq!(
        md.twitter.get("twitter:card").map(String::as_str),
        Some("summary_large_image")
    );
    assert_eq!(
        md.twitter.get("twitter:title").map(String::as_str),
        Some("Tweet Title")
    );
    assert_eq!(md.meta.get("keywords").map(String::as_str), Some("a,b"));
    assert_eq!(md.published_time.as_deref(), Some("2024-05-01T10:00:00Z"));
    assert_eq!(md.modified_time.as_deref(), Some("2024-06-01T10:00:00Z"));
    assert_eq!(md.author.as_deref(), Some("Ada Lovelace"));
    assert!(md.robots.noindex && md.robots.nofollow && !md.robots.noarchive);
    let alts: Vec<(&str, &str)> = md
        .alternates
        .iter()
        .map(|a| (a.hreflang.as_str(), a.url.as_str()))
        .collect();
    assert_eq!(
        alts,
        vec![
            ("fr", "https://example.com/blog/fr/post-1"),
            ("x-default", "https://example.com/post-1")
        ]
    );
    assert_eq!(md.json_ld.len(), 1);
}

#[test]
fn title_falls_back_to_title_tag_then_h1() {
    let u = page("https://example.com/");
    let d = Extractor::extract("<title> T  one </title><h1>H</h1>", &u, &opts(false)).unwrap();
    assert_eq!(d.title.as_deref(), Some("T one"));
    let d = Extractor::extract("<h1>Only <b>heading</b></h1>", &u, &opts(false)).unwrap();
    assert_eq!(d.title.as_deref(), Some("Only heading"));
    let d = Extractor::extract("<p>none</p>", &u, &opts(false)).unwrap();
    assert_eq!(d.title, None);
}

#[test]
fn malformed_html_does_not_panic_and_recovers_content() {
    let doc = Extractor::extract(
        &fixture("malformed.html"),
        &page("https://example.com/"),
        &opts(false),
    )
    .unwrap();
    assert_eq!(doc.markdown, fixture("malformed.md").trim_end_matches('\n'));
}

#[test]
fn include_and_exclude_tags() {
    let html = "<body><div class=a><p>keep one</p><span class=x>drop me</span></div><p>outside</p><div class=a><p>keep two</p></div></body>";
    let o = ExtractOptions {
        include_tags: vec!["div.a".into()],
        exclude_tags: vec![".x".into()],
        ..ExtractOptions::default()
    };
    let d = Extractor::extract(html, &page("https://example.com/"), &o).unwrap();
    assert_eq!(d.markdown, "keep one\n\nkeep two");
    assert_eq!(d.text, "keep one\n\nkeep two");
    assert_eq!(d.html, "<div><p>keep one</p></div><div><p>keep two</p></div>");
}

#[test]
fn invalid_selector_is_an_error() {
    let o = ExtractOptions {
        exclude_tags: vec!["div[".into()],
        ..ExtractOptions::default()
    };
    let r = Extractor::extract("<p>x</p>", &page("https://example.com/"), &o);
    assert!(matches!(r, Err(ExtractError::InvalidSelector { .. })));
}

#[test]
fn oversized_input_is_rejected() {
    let o = ExtractOptions {
        max_input_bytes: 10,
        ..ExtractOptions::default()
    };
    let r = Extractor::extract(
        "<p>this is longer than ten bytes</p>",
        &page("https://example.com/"),
        &o,
    );
    assert!(matches!(r, Err(ExtractError::TooLarge { what: "bytes", .. })));
}

#[test]
fn too_many_nodes_is_rejected() {
    let o = ExtractOptions {
        max_nodes: 50,
        ..ExtractOptions::default()
    };
    let html = "<p>x</p>".repeat(200);
    let r = Extractor::extract(&html, &page("https://example.com/"), &o);
    assert!(matches!(r, Err(ExtractError::TooLarge { what: "nodes", .. })));
}

#[test]
fn excessive_nesting_is_rejected_without_stack_overflow() {
    // html5ever builds this deep tree iteratively; the extractor must refuse it
    // before any recursive walk.
    let html = "<div>".repeat(5000);
    let r = Extractor::extract(&html, &page("https://example.com/"), &ExtractOptions::default());
    assert!(matches!(r, Err(ExtractError::TooLarge { what: "depth", .. })));
}

#[test]
fn digest_covers_raw_input() {
    let u = page("https://example.com/");
    let a = Extractor::extract("<p>a</p>", &u, &opts(false)).unwrap();
    let b = Extractor::extract("<p>b</p>", &u, &opts(false)).unwrap();
    let a2 = Extractor::extract("<p>a</p>", &u, &opts(false)).unwrap();
    assert_ne!(a.raw_html_digest, b.raw_html_digest);
    assert_eq!(a.raw_html_digest, a2.raw_html_digest);
}

#[test]
fn extraction_is_deterministic() {
    let html = fixture("article.html");
    let u = page("https://example.com/post");
    let a = Extractor::extract(&html, &u, &opts(true)).unwrap();
    let b = Extractor::extract(&html, &u, &opts(true)).unwrap();
    assert_eq!(a, b);
}
