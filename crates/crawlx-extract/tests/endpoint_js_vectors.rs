#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Behavioral vectors for JavaScript endpoint mining.
//!
//! `tests/fixtures/endpoints/js/*.json` hold arrays of vectors: a script (or an
//! HTML page carrying scripts and handlers), the exact endpoints the AST miner
//! must report, and the exact unresolved outcomes (kind, matcher, the source
//! text under the span, whether an endpoint was still emitted). Scripts are
//! only parsed; the vectors include code that would loop, throw or call `eval`
//! if it were ever run.
#![cfg(feature = "js-ast")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crawlx_core::config::JavascriptMode;
use crawlx_extract::endpoints::unresolved::{ScriptOrigin, UnresolvedKind};
use crawlx_extract::endpoints::{self, DiscoveredEndpoint, DiscoveryInput, DiscoveryOptions};
use serde::Deserialize;
use url::Url;

const BASE: &str = "https://vec.test";
const SCRIPT_URL: &str = "https://vec.test/app/main.js";
const PAGE_URL: &str = "https://vec.test/app/page.html";

fn get() -> String {
    "GET".to_owned()
}

fn structural() -> String {
    "structural".to_owned()
}

fn ast() -> JavascriptMode {
    JavascriptMode::Ast
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    name: String,
    /// Script response body (final URL `https://vec.test/app/main.js`).
    #[serde(default)]
    js: Option<String>,
    /// HTML response body (final URL `https://vec.test/app/page.html`).
    #[serde(default)]
    html: Option<String>,
    #[serde(default = "ast")]
    mode: JavascriptMode,
    expected: Vec<Want>,
    #[serde(default)]
    unresolved: Vec<WantUnresolved>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Want {
    #[serde(default = "get")]
    method: String,
    /// Absolute URL, or a path on `https://vec.test`.
    url: String,
    source: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    content_type: Option<String>,
    #[serde(default)]
    headers: Vec<String>,
    #[serde(default = "structural")]
    confidence: String,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WantUnresolved {
    kind: UnresolvedKind,
    source: String,
    #[serde(default = "get")]
    method: String,
    /// Source text under the span.
    text: String,
    #[serde(default)]
    partial: bool,
    #[serde(default)]
    origin: Option<ScriptOrigin>,
    /// Text the span indexes into when it is not the whole body (handler or
    /// inline script text after entity decoding).
    #[serde(default)]
    script_text: Option<String>,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/endpoints/js")
}

fn load() -> Vec<(String, Vector)> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for p in files {
        let stem = p.file_stem().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(&p).unwrap();
        let vectors: Vec<Vector> = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{stem}: {e}"));
        out.extend(vectors.into_iter().map(|v| (format!("{stem}/{}", v.name), v)));
    }
    out
}

fn absolute(u: &str) -> String {
    if u.starts_with("http") {
        u.to_owned()
    } else {
        format!("{BASE}{u}")
    }
}

fn run(v: &Vector) -> endpoints::unresolved::DiscoveryReport {
    let (url, content_type, body) = match (&v.js, &v.html) {
        (Some(js), None) => (SCRIPT_URL, "text/javascript", js.as_str()),
        (None, Some(html)) => (PAGE_URL, "text/html", html.as_str()),
        _ => panic!("{}: exactly one of js/html", v.name),
    };
    let url = Url::parse(url).unwrap();
    endpoints::discover_report(
        &DiscoveryInput {
            url: &url,
            status: 200,
            headers: &[],
            content_type: Some(content_type),
            body: body.as_bytes(),
            depth: 0,
        },
        &DiscoveryOptions {
            javascript_mode: v.mode,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap()
}

fn want_of(e: &DiscoveredEndpoint) -> Want {
    Want {
        method: e.method.to_string(),
        url: e.url.to_string(),
        source: format!("{}/{}", e.source.tag, e.source.attribute),
        body: e.body.clone(),
        content_type: e.content_type.clone(),
        headers: e.headers.clone(),
        confidence: match e.confidence {
            endpoints::Confidence::Structural => "structural".to_owned(),
            endpoints::Confidence::Regex => "regex".to_owned(),
            _ => panic!("unexpected confidence"),
        },
    }
}

#[test]
fn every_vector_yields_its_endpoints_and_unresolved_outcomes() {
    let vectors = load();
    assert!(vectors.len() >= 80, "vector set shrank to {}", vectors.len());
    let started = Instant::now();
    let mut failures = Vec::new();
    for (name, v) in &vectors {
        let report = run(v);
        let got: Vec<Want> = report.endpoints.iter().map(want_of).collect();
        let want: Vec<Want> = v
            .expected
            .iter()
            .map(|w| Want {
                method: w.method.clone(),
                url: absolute(&w.url),
                source: w.source.clone(),
                body: w.body.clone(),
                content_type: w.content_type.clone(),
                headers: w.headers.clone(),
                confidence: w.confidence.clone(),
            })
            .collect();
        if got != want {
            failures.push(format!("{name}: endpoints\n  want {want:?}\n  got  {got:?}"));
        }
        let got_unresolved: Vec<WantUnresolved> = report
            .unresolved
            .iter()
            .enumerate()
            .map(|(i, u)| {
                let want = v.unresolved.get(i);
                let script_text = want.and_then(|w| w.script_text.clone());
                let whole = script_text.clone().or_else(|| v.js.clone()).unwrap_or_default();
                WantUnresolved {
                    kind: u.kind,
                    source: format!("{}/{}", u.source.tag, u.source.attribute),
                    method: u.method.to_string(),
                    text: whole
                        .get(u.span.start as usize..u.span.end as usize)
                        .map_or_else(|| "<span out of range>".to_owned(), str::to_owned),
                    partial: u.partial,
                    origin: want.and_then(|w| w.origin).map(|_| u.origin),
                    script_text,
                }
            })
            .collect();
        if got_unresolved != v.unresolved {
            failures.push(format!(
                "{name}: unresolved\n  want {:?}\n  got  {got_unresolved:?}",
                v.unresolved
            ));
        }
        for u in &report.unresolved {
            assert_eq!(u.depth, 1, "{name}: unresolved depth");
        }
        assert_eq!(report.unresolved_dropped, 0, "{name}");
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "vectors must be parsed, never executed (took {:?})",
        started.elapsed()
    );
}

#[test]
fn unresolved_outcomes_are_bounded_and_counted() {
    let js: String = (0..50).map(|i| format!("fetch(v{i});\n")).collect();
    let url = Url::parse(SCRIPT_URL).unwrap();
    let input = DiscoveryInput {
        url: &url,
        status: 200,
        headers: &[],
        content_type: Some("text/javascript"),
        body: js.as_bytes(),
        depth: 0,
    };
    let report = endpoints::discover_report(
        &input,
        &DiscoveryOptions {
            javascript_mode: JavascriptMode::Ast,
            max_unresolved: 7,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.unresolved.len(), 7);
    assert_eq!(report.unresolved_dropped, 43);
    assert!(report.endpoints.is_empty());
    // the first seven in script order
    let texts: Vec<&str> = report
        .unresolved
        .iter()
        .map(|u| &js[u.span.start as usize..u.span.end as usize])
        .collect();
    assert_eq!(texts, ["v0", "v1", "v2", "v3", "v4", "v5", "v6"]);

    let none = endpoints::discover_report(
        &input,
        &DiscoveryOptions {
            javascript_mode: JavascriptMode::Ast,
            max_unresolved: 0,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap();
    assert!(none.unresolved.is_empty());
    assert_eq!(none.unresolved_dropped, 50);
}

#[test]
fn unresolved_is_empty_without_the_ast_miner() {
    let url = Url::parse(SCRIPT_URL).unwrap();
    for mode in [JavascriptMode::Off, JavascriptMode::Regex] {
        let report = endpoints::discover_report(
            &DiscoveryInput {
                url: &url,
                status: 200,
                headers: &[],
                content_type: Some("text/javascript"),
                body: b"fetch(dynamic);",
                depth: 0,
            },
            &DiscoveryOptions {
                javascript_mode: mode,
                ..DiscoveryOptions::default()
            },
        )
        .unwrap();
        assert!(report.unresolved.is_empty(), "{mode:?}");
    }
}

#[test]
fn oversized_and_malformed_scripts_report_nothing_unresolved() {
    let url = Url::parse(SCRIPT_URL).unwrap();
    let mut huge = String::from("fetch(dynamic);");
    huge.push_str(&" ".repeat(endpoints::ast::MAX_AST_BYTES));
    for body in [huge.as_str(), "fetch(dynamic", "fetch(dynamic));"] {
        let report = endpoints::discover_report(
            &DiscoveryInput {
                url: &url,
                status: 200,
                headers: &[],
                content_type: Some("text/javascript"),
                body: body.as_bytes(),
                depth: 0,
            },
            &DiscoveryOptions {
                javascript_mode: JavascriptMode::Ast,
                ..DiscoveryOptions::default()
            },
        )
        .unwrap();
        assert!(report.endpoints.is_empty());
        assert!(report.unresolved.is_empty());
    }
}

/// No JavaScript engine is linked: the static plane can only parse.
#[test]
fn no_script_engine_is_a_dependency() {
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    for engine in [
        "boa_engine",
        "rquickjs",
        "quick-js",
        "deno_core",
        "v8",
        "rusty_v8",
        "mozjs",
        "duktape",
        "rhai",
        "mlua",
    ] {
        assert!(
            !manifest.lines().any(|l| l.trim_start().starts_with(engine)),
            "script engine dependency {engine} would break the static plane"
        );
    }
}

/// Mines `js` on a 2 MiB stack (a default worker thread): the script is
/// refused or mined, never crashes the process.
fn mine_on_small_stack(js: String) -> Vec<String> {
    let handle = std::thread::Builder::new()
        .stack_size(2 << 20)
        .spawn(move || {
            let url = Url::parse(SCRIPT_URL).unwrap();
            endpoints::discover_report(
                &DiscoveryInput {
                    url: &url,
                    status: 200,
                    headers: &[],
                    content_type: Some("text/javascript"),
                    body: js.as_bytes(),
                    depth: 0,
                },
                &DiscoveryOptions {
                    javascript_mode: JavascriptMode::Ast,
                    ..DiscoveryOptions::default()
                },
            )
            .unwrap()
            .endpoints
            .iter()
            .map(|e| e.url.path().to_owned())
            .collect()
        })
        .unwrap();
    handle.join().expect("mining thread must not panic")
}

/// The deepest nesting the AST pass accepts of each shape still parses and
/// mines on a 2 MiB stack (the guard's bounds leave the parser enough room).
#[test]
fn the_deepest_accepted_nesting_of_every_shape_is_mined_on_a_small_stack() {
    let n = 127; // the guard allows 128 open brackets / pending operators
    let shapes: [(&str, String); 9] = [
        (
            "/b/p",
            format!("fetch({}'/b/p'{});", "(".repeat(n - 1), ")".repeat(n - 1)),
        ),
        (
            "/b/br",
            format!("{}fetch('/b/br'){};", "[".repeat(n), "]".repeat(n)),
        ),
        (
            "/b/bl",
            format!("{}fetch('/b/bl');{}", "{".repeat(n), "}".repeat(n)),
        ),
        (
            "/b/t",
            format!("fetch({}'/b/t'{});", "`${".repeat(n - 1), "}`".repeat(n - 1)),
        ),
        (
            "/b/fn",
            format!("{}fetch('/b/fn');{}", "function f(){".repeat(n), "}".repeat(n)),
        ),
        ("/b/un", format!("{}fetch('/b/un');", "!".repeat(n))),
        ("/b/as", format!("{}fetch('/b/as');", "x=".repeat(n))),
        ("/b/co", format!("x{}?fetch('/b/co'):x;", "?x:x".repeat(n - 1))),
        ("/b/ar", format!("{}fetch('/b/ar');", "x=>".repeat(n))),
    ];
    for (path, js) in shapes {
        assert!(
            mine_on_small_stack(js).iter().any(|p| p == path),
            "{path} must be mined at the accepted depth"
        );
    }
}

const HOSTILE_DEPTH: usize = 200_000;

#[test]
fn hostile_parentheses_survive_a_small_stack() {
    let n = HOSTILE_DEPTH;
    mine_on_small_stack(format!("fetch({}'/deep/x'{});", "(".repeat(n), ")".repeat(n)));
}

#[test]
fn hostile_brackets_survive_a_small_stack() {
    let n = HOSTILE_DEPTH;
    mine_on_small_stack(format!("{}fetch('/deep/y'){}", "[".repeat(n), "]".repeat(n)));
}

#[test]
fn hostile_braces_survive_a_small_stack() {
    let n = HOSTILE_DEPTH;
    mine_on_small_stack(format!("{}fetch('/deep/b');{}", "{".repeat(n), "}".repeat(n)));
}

#[test]
fn hostile_templates_survive_a_small_stack() {
    let n = HOSTILE_DEPTH / 4;
    mine_on_small_stack(format!("fetch({}'/deep/t'{});", "`${".repeat(n), "}`".repeat(n)));
}

#[test]
fn hostile_binary_chain_survives_a_small_stack() {
    mine_on_small_stack(format!("fetch('/a'{});", " + '/b'".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_parenthesized_chain_survives_a_small_stack() {
    mine_on_small_stack(format!("fetch('/a'{});", "+('/b')".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_unary_run_survives_a_small_stack() {
    mine_on_small_stack(format!("{}1;fetch('/deep/z');", "!".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_assignment_chain_survives_a_small_stack() {
    mine_on_small_stack(format!("{}x;fetch('/deep/q');", "x=".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_conditional_chain_survives_a_small_stack() {
    mine_on_small_stack(format!("x{};fetch('/deep/c');", "?x:x".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_arrow_chain_survives_a_small_stack() {
    mine_on_small_stack(format!("{}x;fetch('/deep/a');", "x=>".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_member_chain_survives_a_small_stack() {
    mine_on_small_stack(format!("fetch(x{});", ".y".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_call_chain_survives_a_small_stack() {
    mine_on_small_stack(format!("fetch(x{});", "()".repeat(HOSTILE_DEPTH)));
}

#[test]
fn hostile_function_nesting_survives_a_small_stack() {
    let n = HOSTILE_DEPTH / 8;
    mine_on_small_stack(format!(
        "{}fetch('/deep/f');{}",
        "function f(){".repeat(n),
        "}".repeat(n)
    ));
}
