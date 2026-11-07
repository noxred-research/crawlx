//! Consumer-visible JavaScript miner selection and parser capability boundaries.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::config::{Extract, JavascriptMode};
use crawlx_extract::endpoints::{self, DiscoveredEndpoint, DiscoveryInput, DiscoveryOptions};
use crawlx_extract::{ExtractOptions, Extractor};
use url::Url;

// Authored fixture: the comment is regex-only; the request URL requires constant folding.
const SCRIPT: &str = r#"
    const section = "folded";
    fetch("/" + section + "/ast-only");
    // "/regex-only.js"
"#;

fn discover(source: &str, media: &str, mode: JavascriptMode) -> Vec<DiscoveredEndpoint> {
    let url = Url::parse("https://fixture.test/").unwrap();
    endpoints::discover_with(
        &DiscoveryInput {
            url: &url,
            status: 200,
            headers: &[],
            content_type: Some(media),
            body: source.as_bytes(),
            depth: 0,
        },
        &DiscoveryOptions {
            javascript_mode: mode,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap()
}

fn has(found: &[DiscoveredEndpoint], path: &str) -> bool {
    found.iter().any(|endpoint| endpoint.url.path() == path)
}

#[cfg(feature = "js-ast")]
#[test]
fn standalone_and_inline_modes_select_real_miners() {
    for (source, media) in [
        (SCRIPT.to_owned(), "text/javascript"),
        (format!("<script>{SCRIPT}</script>"), "text/html"),
    ] {
        for (mode, ast, regex) in [
            (JavascriptMode::Off, false, false),
            (JavascriptMode::Regex, false, true),
            (JavascriptMode::Ast, true, false),
            (JavascriptMode::Both, true, true),
        ] {
            let found = discover(&source, media, mode);
            assert_eq!(has(&found, "/folded/ast-only"), ast, "{mode:?}: {found:?}");
            assert_eq!(has(&found, "/regex-only.js"), regex, "{mode:?}: {found:?}");
        }
        let urls = |mode| {
            discover(&source, media, mode)
                .into_iter()
                .map(|endpoint| endpoint.url)
                .collect::<std::collections::BTreeSet<_>>()
        };
        let mut union = urls(JavascriptMode::Ast);
        union.extend(urls(JavascriptMode::Regex));
        assert_eq!(urls(JavascriptMode::Both), union);
    }
}

#[cfg(feature = "js-ast")]
#[test]
fn event_handlers_run_only_when_ast_is_selected() {
    let html = r#"<button onclick="fetch('/events/ast-only')">click</button>"#;
    for (mode, expected) in [
        (JavascriptMode::Off, false),
        (JavascriptMode::Regex, false),
        (JavascriptMode::Ast, true),
        (JavascriptMode::Both, true),
    ] {
        assert_eq!(
            has(&discover(html, "text/html", mode), "/events/ast-only"),
            expected
        );
    }
}

#[test]
fn off_keeps_structural_html_headers_and_extractor_links() {
    let url = Url::parse("https://fixture.test/").unwrap();
    let html =
        format!("<a href='/structural'>link</a><script src='/app.js'></script><script>{SCRIPT}</script>");
    let document = Extractor::extract(
        &html,
        &url,
        &ExtractOptions {
            discover_endpoints: true,
            javascript_mode: JavascriptMode::Off,
            headers: vec![("Link".into(), "</header>; rel=next".into())],
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    assert!(has(&document.discovered_endpoints, "/structural"));
    assert!(has(&document.discovered_endpoints, "/app.js"));
    assert!(has(&document.discovered_endpoints, "/header"));
    assert!(!has(&document.discovered_endpoints, "/regex-only.js"));
    assert!(!has(&document.discovered_endpoints, "/folded/ast-only"));
    assert!(document.links.iter().any(|link| link.url.path() == "/structural"));
}

#[test]
fn malformed_javascript_keeps_regex_only_when_selected() {
    let malformed = r#"fetch('/malformed.js', { ;"#;
    assert!(has(
        &discover(malformed, "text/javascript", JavascriptMode::Regex),
        "/malformed.js"
    ));
    assert!(discover(malformed, "text/javascript", JavascriptMode::Off).is_empty());
    #[cfg(feature = "js-ast")]
    for (source, media) in [
        (malformed.to_owned(), "text/javascript"),
        (format!("<script>{malformed}</script>"), "text/html"),
    ] {
        assert!(discover(&source, media, JavascriptMode::Ast).is_empty());
        assert!(has(
            &discover(&source, media, JavascriptMode::Both),
            "/malformed.js"
        ));
    }
}

#[cfg(feature = "js-ast")]
#[test]
fn oversized_ast_source_does_not_enable_regex_in_ast_only_mode() {
    let source = format!(
        "/*{}*/fetch('/oversized.js');",
        " ".repeat(endpoints::ast::MAX_AST_BYTES)
    );
    assert!(discover(&source, "text/javascript", JavascriptMode::Ast).is_empty());
    assert!(has(
        &discover(&source, "text/javascript", JavascriptMode::Both),
        "/oversized.js"
    ));
}

#[cfg(not(feature = "js-ast"))]
#[test]
fn requested_ast_is_explicitly_unavailable_without_feature() {
    let url = Url::parse("https://fixture.test/app.js").unwrap();
    for mode in [JavascriptMode::Ast, JavascriptMode::Both] {
        let result = endpoints::discover_with(
            &DiscoveryInput {
                url: &url,
                status: 200,
                headers: &[],
                content_type: Some("text/javascript"),
                body: SCRIPT.as_bytes(),
                depth: 0,
            },
            &DiscoveryOptions {
                javascript_mode: mode,
                ..DiscoveryOptions::default()
            },
        );
        assert!(matches!(result, Err(endpoints::DiscoveryError::AstUnavailable)));
        let error = Extractor::extract(
            &format!("<script>{SCRIPT}</script>"),
            &url,
            &ExtractOptions {
                discover_endpoints: true,
                javascript_mode: mode,
                ..ExtractOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            crawlx_extract::ExtractError::Discovery(endpoints::DiscoveryError::AstUnavailable)
        ));
    }
}

#[test]
fn config_rejects_unknown_javascript_modes_and_keys() {
    assert!(
        serde_json::from_value::<Extract>(serde_json::json!({"javascript": {"mode": "unknown"}})).is_err()
    );
    assert!(serde_json::from_value::<Extract>(
        serde_json::json!({"javascript": {"mode": "off", "typo": true}})
    )
    .is_err());
}
