#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Main-content selection and resource-bound cases.

use crawlx_extract::{ExtractOptions, Extractor};
use url::Url;

fn run(html: &str, only_main: bool) -> String {
    let base = Url::parse("https://example.com/").unwrap();
    let o = ExtractOptions {
        only_main_content: only_main,
        ..ExtractOptions::default()
    };
    Extractor::extract(html, &base, &o).unwrap().markdown
}

const LONG: &str = "This paragraph is deliberately long enough to count as real prose, with commas, clauses, and plenty of words in it.";

#[test]
fn main_element_wins() {
    let html = format!(
        "<body><div class=top><p>{LONG} outside main</p></div><main><p>{LONG} inside main</p></main><div><p>{LONG} after</p></div></body>"
    );
    assert_eq!(run(&html, true), format!("{LONG} inside main"));
}

#[test]
fn role_main_is_honoured() {
    let html = format!("<body><div role='main'><p>{LONG} one</p></div><div><p>short</p></div></body>");
    assert_eq!(run(&html, true), format!("{LONG} one"));
}

#[test]
fn scoring_picks_text_dense_block_and_widens_to_heading() {
    let html = format!(
        "<body><div id=wrap><div class=menu-list><ul><li><a href=/a>A</a></li><li><a href=/b>B</a></li></ul></div>\
<div class=post><h2>Title</h2><div class=text><p>{LONG} one</p><p>{LONG} two</p><p>{LONG} three</p></div></div>\
<div class=links><a href=/x>x</a> <a href=/y>y</a> <a href=/z>z</a></div></div></body>"
    );
    let out = run(&html, true);
    assert!(out.starts_with("## Title\n\n"), "{out}");
    assert!(out.contains("two") && out.contains("three"));
    assert!(!out.contains("[A]") && !out.contains("[x]"));
}

#[test]
fn negative_class_hints_are_removed_but_wrapper_with_sidebar_class_is_kept() {
    let html = format!(
        "<body><div class='layout with-sidebar'><div class=content><p>{LONG} body</p></div><div class='ad-slot'><p>buy now</p></div></div></body>"
    );
    let out = run(&html, true);
    assert!(out.contains("body"));
    assert!(!out.contains("buy now"));
}

#[test]
fn header_inside_article_is_kept_outside_is_dropped() {
    let html = format!(
        "<body><header><p>Site banner text</p></header><article><header><h1>Headline</h1></header><p>{LONG} a</p><p>{LONG} b</p></article></body>"
    );
    let out = run(&html, true);
    assert!(out.starts_with("# Headline"), "{out}");
    assert!(!out.contains("banner"));
}

#[test]
fn falls_back_to_whole_body_when_candidate_is_small() {
    // Ten comparable articles: no single block dominates, so nothing is dropped.
    let mut html = String::from("<body>");
    for i in 0..10 {
        html.push_str(&format!("<div class=item><p>{LONG} item{i}</p></div>"));
    }
    html.push_str("</body>");
    let out = run(&html, true);
    for i in 0..10 {
        assert!(out.contains(&format!("item{i}")), "item{i} lost");
    }
}

#[test]
fn deep_but_allowed_nesting_does_not_overflow_the_stack() {
    let depth = 480;
    let html = format!(
        "{}<p>deep text</p>{}",
        "<div>".repeat(depth),
        "</div>".repeat(depth)
    );
    assert_eq!(run(&html, false), "deep text");
    assert_eq!(run(&html, true), "deep text");
    let lists = format!(
        "{}<li>leaf</li>{}",
        "<ul><li>".repeat(200),
        "</li></ul>".repeat(200)
    );
    let out = run(&lists, false);
    assert!(out.contains("leaf"));
}

#[test]
fn huge_colspan_is_bounded() {
    let html =
        "<table><tr><th colspan=999999999>h</th></tr><tr><td colspan=99999 rowspan=99999>x</td></tr></table>";
    let out = run(html, false);
    assert!(out.len() < 20_000, "table expansion not bounded: {}", out.len());
}
