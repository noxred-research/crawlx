#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Property tests of the Firecrawl scrape-format functions: they never panic on
//! arbitrary input and keep their invariants (a diff reconstructs the new document, ranking is a
//! permutation, branding is deterministic and well-formed).

use crawlx_core::scrape::AttributeSelector;
use crawlx_extract::branding::{branding, BrandingInput};
use crawlx_extract::diff::{json_diff, markdown_diff};
use crawlx_extract::map_rank::{rank, MapItem};
use crawlx_extract::{attributes, base64_images, images};
use proptest::prelude::*;
use serde_json::Value;
use url::Url;

fn page() -> Url {
    Url::parse("https://example.com/dir/page").unwrap()
}

fn as_text(lines: &[String]) -> String {
    lines.iter().map(|l| format!("{l}\n")).collect()
}

/// Rebuild the new document from the old one and the structured hunks.
fn apply(prev: &[String], diff: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pos = 0usize;
    for chunk in diff["files"][0]["chunks"].as_array().cloned().unwrap_or_default() {
        let header = chunk["content"].as_str().unwrap();
        let old = header.split_whitespace().nth(1).unwrap().trim_start_matches('-');
        let (start, len) = old.split_once(',').unwrap();
        let (start, len): (usize, usize) = (start.parse().unwrap(), len.parse().unwrap());
        let zero_based = if len == 0 { start } else { start - 1 };
        out.extend(prev[pos..zero_based].iter().cloned());
        for change in chunk["changes"].as_array().unwrap() {
            let content = change["content"].as_str().unwrap().to_owned();
            match change["type"].as_str().unwrap() {
                "normal" | "add" => out.push(content),
                "del" => {}
                other => panic!("unknown change type {other}"),
            }
        }
        pos = zero_based + len;
    }
    out.extend(prev[pos..].iter().cloned());
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn markdown_diff_reconstructs_the_current_document(
        prev in proptest::collection::vec("[a-c]{0,2}", 0..40),
        cur in proptest::collection::vec("[a-c]{0,2}", 0..40),
    ) {
        let d = markdown_diff(&as_text(&prev), &as_text(&cur));
        prop_assert_eq!(apply(&prev, &d.json), cur.clone());
        prop_assert_eq!(d.text.is_empty(), prev == cur);
        // Every text line is a header or a prefixed content line.
        for line in d.text.lines() {
            prop_assert!(line.starts_with("@@ ") || matches!(line.chars().next(), Some(' ' | '-' | '+')));
        }
    }

    #[test]
    fn json_diff_keys_are_the_union(
        a in proptest::collection::btree_map("[a-d]", 0u8..3, 0..4),
        b in proptest::collection::btree_map("[a-d]", 0u8..3, 0..4),
    ) {
        let (va, vb) = (serde_json::to_value(&a).unwrap(), serde_json::to_value(&b).unwrap());
        let d = json_diff(&va, &vb);
        let keys: std::collections::BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        let got: std::collections::BTreeSet<&String> = d.as_object().unwrap().keys().collect();
        prop_assert_eq!(got, keys);
    }

    #[test]
    fn branding_never_panics_and_is_deterministic_and_well_formed(
        css in "[{}();:/*'\"a-z0-9 @#.,%!-]{0,300}",
        html_parts in proptest::collection::vec(
            prop_oneof![
                Just("<style>".to_owned()), Just("</style>".to_owned()), Just("<img class=logo src=/a.png>".to_owned()),
                Just("<meta name=theme-color content=#336699>".to_owned()), Just("<header>".to_owned()),
                Just("<link rel=icon href=/f.ico>".to_owned()), Just("<body style=\"background:#123\">".to_owned()),
                "[ -~]{0,12}",
            ],
            0..40,
        ),
    ) {
        let html = format!("{}<style>{css}</style>", html_parts.concat());
        let sheets = [css.clone()];
        let input = BrandingInput { html: &html, base: &page(), stylesheets: &sheets };
        let a = branding(&input);
        prop_assert_eq!(&a, &branding(&input));
        for (_, c) in a["colors"].as_object().into_iter().flatten() {
            let s = c.as_str().unwrap();
            prop_assert!(s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_lowercase()), "{s}");
        }
        prop_assert!(matches!(a["colorScheme"].as_str(), Some("light" | "dark")));
    }

    #[test]
    fn images_attributes_and_base64_never_panic(html in "[<>a-z=\"'/ .:;,0-9#-]{0,400}") {
        let _ = images::images(&html, &page());
        let sel = [AttributeSelector { selector: "a, img[src]".to_owned(), attribute: "href".to_owned() }];
        let _ = attributes::attributes(&html, &sel);
        let once = base64_images::strip_base64_images(&html).into_owned();
        prop_assert_eq!(base64_images::strip_base64_images(&once).into_owned(), once);
    }

    #[test]
    fn rank_is_a_permutation_and_keeps_every_item(
        search in "[a-c ]{0,6}",
        urls in proptest::collection::vec("[a-c/]{1,8}", 0..20),
    ) {
        let items: Vec<MapItem> = urls
            .iter()
            .map(|u| MapItem { url: format!("https://example.com/{u}"), title: None, description: None })
            .collect();
        let ranked = rank(&search, items.clone());
        let mut a: Vec<&str> = items.iter().map(|i| i.url.as_str()).collect();
        let mut b: Vec<&str> = ranked.iter().map(|i| i.url.as_str()).collect();
        a.sort_unstable();
        b.sort_unstable();
        prop_assert_eq!(a, b);
    }
}
