//! The compatibility API `attributes` format: attribute values of the elements a CSS selector matches.
//!
//! [`attributes`] answers every requested `{selector, attribute}` pair with an
//! [`AttributeResult`] whose `values` are the attribute values of the matching elements in
//! document order. Elements without the attribute contribute nothing; values are returned
//! verbatim (no trimming, no URL resolution). Attribute names match ASCII case-insensitively,
//! like in HTML.

use crawlx_core::scrape::{AttributeResult, AttributeSelector};
use scraper::{Html, Selector};

use crate::{ExtractError, ExtractOptions};

/// Most values returned for one `{selector, attribute}` pair.
pub const MAX_VALUES: usize = 10_000;

/// Evaluate `selectors` against `html`; one [`AttributeResult`] per requested pair, in request
/// order (duplicates included).
///
/// # Errors
///
/// [`ExtractError::InvalidSelector`] when a selector does not parse (checked before the
/// document is parsed, so the first invalid selector wins);
/// [`ExtractError::TooLarge`] when `html` exceeds the default extraction limits;
/// [`ExtractError::ParseMemory`] when the process-wide parse-memory budget is exhausted.
pub fn attributes(html: &str, selectors: &[AttributeSelector]) -> Result<Vec<AttributeResult>, ExtractError> {
    let compiled = compile(selectors)?;
    if compiled.is_empty() {
        return Ok(Vec::new());
    }
    crate::precheck(html, &ExtractOptions::default())?;
    // declared before `doc`: released after the parsed tree is dropped
    let mut charge = crate::parse_budget::charge(html.len())?;
    let doc = crate::dom::parse_document(&mut charge, html)?;
    Ok(evaluate(&doc, selectors, &compiled))
}

fn compile(selectors: &[AttributeSelector]) -> Result<Vec<Selector>, ExtractError> {
    selectors
        .iter()
        .map(|s| {
            crate::xpath::compile_css(&s.selector).map_err(|error| match error {
                crate::xpath::SelectorError::Syntax | crate::xpath::SelectorError::Unsupported(_) => {
                    ExtractError::InvalidSelector {
                        selector: s.selector.clone(),
                        reason: error.to_string(),
                    }
                }
                other => ExtractError::Selector(other),
            })
        })
        .collect()
}

fn evaluate(doc: &Html, selectors: &[AttributeSelector], compiled: &[Selector]) -> Vec<AttributeResult> {
    selectors
        .iter()
        .zip(compiled)
        .map(|(req, sel)| AttributeResult {
            selector: req.selector.clone(),
            attribute: req.attribute.clone(),
            values: doc
                .select(sel)
                .filter_map(|el| {
                    el.value()
                        .attrs()
                        .find(|(name, _)| name.eq_ignore_ascii_case(&req.attribute))
                        .map(|(_, value)| value.to_owned())
                })
                .take(MAX_VALUES)
                .collect(),
        })
        .collect()
}

/// Evaluate attribute pairs on one existing resource-checked HTML parse.
///
/// # Errors
/// Returns `ExtractError::InvalidSelector` for malformed CSS.
pub fn from_document(
    doc: &Html,
    selectors: &[AttributeSelector],
) -> Result<Vec<AttributeResult>, ExtractError> {
    Ok(evaluate(doc, selectors, &compile(selectors)?))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn pair(selector: &str, attribute: &str) -> AttributeSelector {
        AttributeSelector {
            selector: selector.to_owned(),
            attribute: attribute.to_owned(),
        }
    }

    const PAGE: &str = r#"<html><body>
        <nav class="menu"><a href="/home" data-track="nav-home">Home</a><a href="/docs">Docs</a></nav>
        <main>
          <article class="post featured"><h2><a href="/p/1" data-track="post-1">One</a></h2>
            <img src="one.png" alt=""></article>
          <article class="post"><h2><a href="/p/2">Two</a></h2><img src="two.png"></article>
        </main>
        <a href="https://other.example/x" rel="nofollow  noopener">external</a>
        <input type="text" value="  padded  " data-Mixed="Yes">
      </body></html>"#;

    #[test]
    fn values_come_back_in_document_order_for_every_match() {
        let got = attributes(PAGE, &[pair("a", "href")]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].selector, "a");
        assert_eq!(got[0].attribute, "href");
        assert_eq!(
            got[0].values,
            ["/home", "/docs", "/p/1", "/p/2", "https://other.example/x"]
        );
    }

    #[test]
    fn only_elements_that_have_the_attribute_contribute() {
        let got = attributes(PAGE, &[pair("a", "data-track")]).unwrap();
        assert_eq!(got[0].values, ["nav-home", "post-1"]);
    }

    #[test]
    fn nested_selectors_combinators_and_attribute_filters_work() {
        let got = attributes(
            PAGE,
            &[
                pair("main article.featured h2 > a", "href"),
                pair("article.post:not(.featured) img", "src"),
                pair("a[rel~=nofollow]", "href"),
                pair("nav.menu a:first-child", "data-track"),
            ],
        )
        .unwrap();
        assert_eq!(got[0].values, ["/p/1"]);
        assert_eq!(got[1].values, ["two.png"]);
        assert_eq!(got[2].values, ["https://other.example/x"]);
        assert_eq!(got[3].values, ["nav-home"]);
    }

    #[test]
    fn one_result_per_requested_pair_in_request_order_including_duplicates_and_misses() {
        let got = attributes(
            PAGE,
            &[pair("img", "alt"), pair(".absent", "href"), pair("img", "alt")],
        )
        .unwrap();
        assert_eq!(got.len(), 3);
        // `alt=""` is present (empty) on the first image only.
        assert_eq!(got[0].values, [""]);
        assert!(got[1].values.is_empty());
        assert_eq!(got[2], got[0]);
    }

    #[test]
    fn values_are_verbatim_and_attribute_names_ignore_case() {
        let got = attributes(PAGE, &[pair("input", "value"), pair("input", "DATA-MIXED")]).unwrap();
        assert_eq!(got[0].values, ["  padded  "]);
        assert_eq!(got[1].values, ["Yes"]);
        let rel = attributes(PAGE, &[pair("a[rel]", "rel")]).unwrap();
        assert_eq!(rel[0].values, ["nofollow  noopener"]);
    }

    #[test]
    fn relative_urls_are_not_resolved() {
        let got = attributes(PAGE, &[pair("img", "src")]).unwrap();
        assert_eq!(got[0].values, ["one.png", "two.png"]);
    }

    #[test]
    fn invalid_selector_is_reported_with_the_offending_text() {
        let err = attributes(PAGE, &[pair("a", "href"), pair("a[", "href")]).unwrap_err();
        match err {
            ExtractError::InvalidSelector { selector, reason } => {
                assert_eq!(selector, "a[");
                assert!(!reason.is_empty());
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn no_selectors_means_no_results() {
        assert!(attributes(PAGE, &[]).unwrap().is_empty());
    }

    #[test]
    fn values_per_pair_are_capped() {
        let mut html = String::from("<body>");
        for i in 0..(MAX_VALUES + 25) {
            html.push_str(&format!("<i data-n=\"{i}\"></i>"));
        }
        let got = attributes(&html, &[pair("i", "data-n")]).unwrap();
        assert_eq!(got[0].values.len(), MAX_VALUES);
        assert_eq!(got[0].values[0], "0");
    }

    #[test]
    fn oversized_documents_are_refused() {
        let huge = "<i>".repeat(crate::document::DEFAULT_MAX_NODES + 1);
        assert!(matches!(
            attributes(&huge, &[pair("i", "x")]),
            Err(ExtractError::TooLarge { .. })
        ));
    }
}
