//! HTML/Markdown variants, citations and target elements.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_extract::content_outputs::{
    CitationSource, ContentOutputError, ContentOutputOptions, DiscoveryScope,
};
use crawlx_extract::fit::FitFilter;
use crawlx_extract::{Document, ExtractError, ExtractOptions, Extractor};
use url::Url;

const PAGE: &str = r#"<!doctype html>
<html lang="en"><head><title>Variant page</title>
<script>var secret = 1;</script><style>p { color: red }</style></head>
<body>
<nav><a href="/home">Home</a> <a href="/news">News</a></nav>
<main><article>
<h1>Heading</h1>
<p class="lead">Read the <a href="/guide#intro">guide</a> and the <a href="https://other.test/ref">reference</a> before the <a href="/guide">guide again</a>. Mail <a href="mailto:a@b.test">us</a>.</p>
<p>Plain paragraph with enough words to count as the body of the article text in this page.</p>
<div class="byline"><span>By</span> <a href="/u/jane">Jane</a></div>
<img src="/i.png" alt="pic">
</article></main>
<footer><a href="/privacy">Privacy</a></footer>
</body></html>"#;

fn page() -> Url {
    Url::parse("https://fixture.test/p").unwrap()
}

fn extract(configure: impl FnOnce(&mut ContentOutputOptions)) -> Result<Document, ExtractError> {
    let mut outputs = ContentOutputOptions::default();
    configure(&mut outputs);
    Extractor::extract(
        PAGE,
        &page(),
        &ExtractOptions {
            outputs: Some(outputs),
            ..ExtractOptions::default()
        },
    )
}

#[test]
fn variants_are_distinct_and_exact() {
    let doc = extract(|o| {
        o.raw_html = true;
        o.cleaned_html = true;
        o.fit = Some(FitFilter::default());
    })
    .unwrap();
    let out = doc.outputs.as_ref().unwrap();
    assert_eq!(out.raw_html.as_deref(), Some(PAGE));
    let cleaned = out.cleaned_html.as_deref().unwrap();
    assert!(cleaned.contains("Home") && cleaned.contains("Privacy") && cleaned.contains("Heading"));
    assert!(!cleaned.contains("secret") && !cleaned.contains("<script") && !cleaned.contains("color: red"));
    // The selected content is the article only.
    assert!(doc.html.contains("Heading") && !doc.html.contains("Home") && !doc.html.contains("Privacy"));
    let fit_html = out.fit_html.as_deref().unwrap();
    assert!(fit_html.contains("Heading") && fit_html.contains("Plain paragraph"));
    assert!(!fit_html.contains("Jane"), "{fit_html}");
    assert!(doc.html.contains("Jane"), "{}", doc.html);
    let fit_markdown = out.fit_markdown.as_deref().unwrap();
    assert!(fit_markdown.contains("[guide](https://fixture.test/guide#intro)"));
    assert!(!fit_markdown.contains("Jane"));
    let all = [PAGE, cleaned, doc.html.as_str(), fit_html];
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(a, b);
        }
    }
    assert_ne!(out.fit_markdown.as_deref(), Some(doc.markdown.as_str()));
}

#[test]
fn outputs_are_absent_without_the_option() {
    let doc = Extractor::extract(PAGE, &page(), &ExtractOptions::default()).unwrap();
    assert!(doc.outputs.is_none());
}

#[test]
fn citations_resolve_to_retained_links_without_fetching() {
    let doc = extract(|o| o.citations = Some(CitationSource::Selected)).unwrap();
    let out = doc.outputs.as_ref().unwrap();
    let md = out.markdown_with_citations.as_deref().unwrap();
    assert!(
        md.contains("Read the guide⟨1⟩ and the reference⟨2⟩ before the guide again⟨3⟩. Mail us⟨4⟩."),
        "{md}"
    );
    assert!(
        !md.contains("](https://fixture.test/guide"),
        "links became markers: {md}"
    );
    assert!(
        md.contains("![pic](https://fixture.test/i.png)"),
        "images stay inline"
    );
    let expected_refs = "⟨1⟩ https://fixture.test/guide#intro: guide\n\
⟨2⟩ https://other.test/ref: reference\n\
⟨3⟩ https://fixture.test/guide: guide again\n\
⟨4⟩ mailto:a@b.test: us\n\
⟨5⟩ https://fixture.test/u/jane: Jane";
    assert!(md.ends_with(expected_refs), "{md}");
    assert_eq!(out.citations.len(), 5);
    for (i, c) in out.citations.iter().enumerate() {
        assert_eq!(c.index, i + 1);
    }
    // Provenance: the marker's URL (fragment ignored) is the retained link at `link_index`.
    let by_index = |n: usize| &out.citations[n - 1];
    let guide = by_index(1).link_index.unwrap();
    assert_eq!(doc.links[guide].url.as_str(), "https://fixture.test/guide");
    assert_eq!(by_index(3).link_index, Some(guide));
    assert_eq!(
        doc.links[by_index(2).link_index.unwrap()].url.as_str(),
        "https://other.test/ref"
    );
    assert_eq!(by_index(4).link_index, None, "mailto is not a retained page link");
    // The plain Markdown is unchanged by the option.
    assert!(doc.markdown.contains("[guide](https://fixture.test/guide#intro)"));
}

#[test]
fn citation_source_selects_the_content_tree() {
    let selected = extract(|o| o.citations = Some(CitationSource::Selected)).unwrap();
    let cleaned = extract(|o| o.citations = Some(CitationSource::Cleaned)).unwrap();
    let fit = extract(|o| {
        o.fit = Some(FitFilter::default());
        o.citations = Some(CitationSource::Fit);
    })
    .unwrap();
    let cites = |d: &Document| d.outputs.as_ref().unwrap().citations.len();
    assert_eq!(cites(&selected), 5);
    assert_eq!(
        cites(&cleaned),
        8,
        "navigation and footer links join the whole page"
    );
    assert_eq!(cites(&fit), 4, "the byline link is pruned before numbering");
    let cleaned_md = cleaned.outputs.unwrap().markdown_with_citations.unwrap();
    assert!(cleaned_md.contains("Home⟨1⟩ News⟨2⟩"), "{cleaned_md}");
}

#[test]
fn fit_citation_source_needs_a_filter() {
    let err = extract(|o| o.citations = Some(CitationSource::Fit)).unwrap_err();
    assert!(
        matches!(
            err,
            ExtractError::Outputs(ContentOutputError::InvalidOption {
                name: "citations",
                ..
            })
        ),
        "{err:?}"
    );
}

#[test]
fn target_elements_narrow_content_but_not_discovery() {
    let doc = extract(|o| {
        o.target_elements = vec!["p.lead".into()];
        o.cleaned_html = true;
    })
    .unwrap();
    assert!(doc.text.contains("Read the guide") && !doc.text.contains("Plain paragraph"));
    assert!(!doc.markdown.contains("Home") && !doc.html.contains("Privacy"));
    // Links and assets keep the whole-page scope.
    let urls: Vec<&str> = doc.links.iter().map(|l| l.url.as_str()).collect();
    for expected in [
        "https://fixture.test/home",
        "https://fixture.test/news",
        "https://fixture.test/privacy",
        "https://fixture.test/u/jane",
        "https://other.test/ref",
    ] {
        assert!(urls.contains(&expected), "{expected} in {urls:?}");
    }
    assert!(doc
        .assets
        .iter()
        .any(|a| a.as_str() == "https://fixture.test/i.png"));
    let out = doc.outputs.as_ref().unwrap();
    assert_eq!(out.discovery_scope, DiscoveryScope::WholePage);
    assert!(out.cleaned_html.as_deref().unwrap().contains("Privacy"));
}

#[test]
fn selected_discovery_scope_limits_links_and_assets() {
    let doc = extract(|o| {
        o.target_elements = vec!["p.lead".into()];
        o.discovery_scope = DiscoveryScope::Selected;
    })
    .unwrap();
    let urls: Vec<&str> = doc.links.iter().map(|l| l.url.as_str()).collect();
    assert_eq!(urls, ["https://fixture.test/guide", "https://other.test/ref"]);
    assert!(doc.assets.is_empty(), "{:?}", doc.assets);
    assert_eq!(doc.outputs.unwrap().discovery_scope, DiscoveryScope::Selected);
}

#[test]
fn target_elements_without_a_match_extract_nothing_but_keep_links() {
    let doc = extract(|o| o.target_elements = vec!["section.missing".into()]).unwrap();
    assert!(doc.text.is_empty() && doc.markdown.is_empty());
    assert_eq!(doc.links.len(), 6);
}

#[test]
fn malformed_and_oversized_target_selectors_are_rejected() {
    for bad in ["p[", "div >", ":::", "p..lead"] {
        let err = extract(|o| o.target_elements = vec![bad.into()]).unwrap_err();
        assert!(
            matches!(err, ExtractError::InvalidSelector { .. }),
            "{bad}: {err:?}"
        );
    }
    for bad in [
        vec![String::new()],
        vec!["  ".to_owned()],
        vec!["p".repeat(2000)],
        (0..65).map(|i| format!("p.c{i}")).collect::<Vec<_>>(),
    ] {
        let err = extract(|o| o.target_elements = bad.clone()).unwrap_err();
        assert!(
            matches!(
                err,
                ExtractError::Outputs(ContentOutputError::InvalidOption {
                    name: "targetElements",
                    ..
                })
            ),
            "{err:?}"
        );
    }
}

#[test]
fn options_round_trip_and_reject_unknown_fields() {
    let json = r#"{"targetElements":["p.lead"],"discoveryScope":"selected","citations":"fit","fit":{"strategy":"pruning"}}"#;
    let options: ContentOutputOptions = serde_json::from_str(json).unwrap();
    assert_eq!(options.discovery_scope, DiscoveryScope::Selected);
    assert_eq!(options.citations, Some(CitationSource::Fit));
    assert!(serde_json::from_str::<ContentOutputOptions>(r#"{"unknown":true}"#).is_err());
}
