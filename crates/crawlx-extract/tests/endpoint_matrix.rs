#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Golden construct matrix for structural and header endpoint discovery.
//!
//! Every file in `tests/fixtures/endpoints/matrix/` is one construct: the input
//! response (final URL, status, headers, declared content type, body) and the
//! exact, ordered list of endpoints the extractor must report. Nothing else may
//! appear in the output, so an over-eager new miner fails here as loudly as a
//! missing one.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crawlx_core::config::JavascriptMode;
use crawlx_extract::endpoints::{self, Confidence, DiscoveredEndpoint, DiscoveryInput, DiscoveryOptions};
use serde::Deserialize;
use url::Url;

const DEFAULT_PAGE: &str = "https://matrix.test/dir/page.html";

fn default_page() -> String {
    DEFAULT_PAGE.to_owned()
}

fn default_status() -> u16 {
    200
}

fn default_content_type() -> Option<String> {
    Some("text/html; charset=utf-8".to_owned())
}

/// Structural fixtures run with the script miners off, so only the construct
/// under test can produce output; mining fixtures name their mode.
fn default_mode() -> JavascriptMode {
    JavascriptMode::Off
}

fn default_confidence() -> String {
    "structural".to_owned()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    /// Construct under test (documentation; must equal the file stem).
    construct: String,
    /// Final URL of the response.
    #[serde(default = "default_page")]
    url: String,
    #[serde(default = "default_status")]
    status: u16,
    #[serde(default = "default_content_type")]
    content_type: Option<String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    /// Body lines, joined with `\n`.
    #[serde(default)]
    body: Vec<String>,
    /// Body as hex bytes (binary fixtures); wins over `body`.
    #[serde(default)]
    body_hex: Option<String>,
    #[serde(default = "default_mode")]
    javascript_mode: JavascriptMode,
    /// Needs the AST miner (skipped when the build lacks `js-ast`).
    #[serde(default)]
    requires_ast: bool,
    expected: Vec<Expected>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Expected {
    method: String,
    url: String,
    /// `tag/attribute`.
    source: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default = "default_confidence")]
    confidence: String,
    #[serde(default)]
    headers: Vec<String>,
}

impl Expected {
    fn of(e: &DiscoveredEndpoint) -> Self {
        assert_eq!(e.depth, 1, "depth is input depth + 1 for {}", e.url);
        Self {
            method: e.method.to_string(),
            url: e.url.to_string(),
            source: format!("{}/{}", e.source.tag, e.source.attribute),
            body: e.body.clone(),
            content_type: e.content_type.clone(),
            confidence: match e.confidence {
                Confidence::Structural => "structural".to_owned(),
                Confidence::Regex => "regex".to_owned(),
                _ => panic!("unexpected confidence"),
            },
            headers: e.headers.clone(),
        }
    }
}

fn matrix_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/endpoints/matrix")
}

fn show(items: &[Expected]) -> String {
    items
        .iter()
        .map(|e| {
            format!(
                "    {} {} {} [{}] body={:?} ct={:?} headers={:?}",
                e.method, e.url, e.source, e.confidence, e.body, e.content_type, e.headers
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("bad hex digit"),
        })
        .collect();
    assert_eq!(digits.len() % 2, 0, "odd hex length");
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

fn load() -> Vec<(String, Fixture)> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(matrix_dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|p| {
            let stem = p.file_stem().unwrap().to_string_lossy().into_owned();
            let text = std::fs::read_to_string(&p).unwrap();
            let fixture: Fixture = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{stem}: {e}"));
            assert_eq!(fixture.construct, stem, "construct must equal the file stem");
            (stem, fixture)
        })
        .collect()
}

fn run(f: &Fixture) -> Vec<DiscoveredEndpoint> {
    let url = Url::parse(&f.url).unwrap();
    let body = match &f.body_hex {
        Some(h) => hex_bytes(h),
        None => f.body.join("\n").into_bytes(),
    };
    endpoints::discover_with(
        &DiscoveryInput {
            url: &url,
            status: f.status,
            headers: &f.headers,
            content_type: f.content_type.as_deref(),
            body: &body,
            depth: 0,
        },
        &DiscoveryOptions {
            javascript_mode: f.javascript_mode,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap()
}

#[test]
fn every_construct_fixture_yields_exactly_its_expected_output() {
    let fixtures = load();
    assert!(
        fixtures.len() >= 60,
        "matrix shrank to {} fixtures",
        fixtures.len()
    );
    let mut failures = Vec::new();
    for (name, f) in &fixtures {
        if f.requires_ast && !cfg!(feature = "js-ast") {
            continue;
        }
        let got: Vec<Expected> = run(f).iter().map(Expected::of).collect();
        if got != f.expected {
            failures.push(format!(
                "{name}:\n  want\n{}\n  got\n{}",
                show(&f.expected),
                show(&got)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Constructs the matrix must cover (one fixture each).
const REQUIRED: &[&str] = &[
    "header-content-location",
    "header-link",
    "header-location",
    "header-refresh",
    "a-href",
    "a-ping",
    "area-href-ping",
    "link-href",
    "frame-src",
    "iframe-src",
    "iframe-srcdoc",
    "script-src",
    "script-inline",
    "img-src",
    "img-srcset",
    "img-legacy-attributes",
    "picture-source-srcset",
    "input-image-src",
    "video-src-poster",
    "video-track-src",
    "video-source-src",
    "audio-src",
    "audio-source",
    "applet-archive-codebase",
    "object-data-codebase-param",
    "embed-src",
    "svg-image-href",
    "svg-script-href",
    "table-background",
    "td-background",
    "body-background",
    "blockquote-cite",
    "q-cite",
    "del-cite",
    "ins-cite",
    "base-href",
    "form-get",
    "form-post-urlencoded",
    "form-post-multipart",
    "meta-refresh",
    "htmx-get",
    "htmx-post",
    "htmx-put",
    "htmx-patch",
    "binary-png-body",
    "escaped-entities",
    "escaped-js-string",
    "final-url-resolution",
];

#[test]
fn matrix_has_one_fixture_per_required_construct() {
    let names: BTreeSet<String> = load().into_iter().map(|(n, _)| n).collect();
    let missing: Vec<&&str> = REQUIRED.iter().filter(|r| !names.contains(**r)).collect();
    assert!(missing.is_empty(), "missing construct fixtures: {missing:?}");
}

/// Every structural source the extractor can emit appears in at least one
/// fixture, so a newly added construct cannot ship without a golden row.
#[test]
fn every_structural_source_has_a_golden_row() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (_, f) in load() {
        for e in &f.expected {
            seen.insert(e.source.clone());
        }
    }
    let missing: Vec<String> = endpoints::ALL_SOURCES
        .iter()
        .filter(|s| s.tag != "js")
        .map(|s| format!("{}/{}", s.tag, s.attribute))
        .filter(|s| !seen.contains(s))
        .collect();
    assert!(missing.is_empty(), "sources without a golden row: {missing:?}");
}
