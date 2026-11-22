//! A page the isolated parser helper refuses keeps its subtree: the bounded link scan recovers the
//! links, which are crawled like the links of a parsed page (issue #71).
//!
//! The helper is the real `crawlx` executable run with an address-space limit that is below the
//! allocator's own 1 GiB reservation, so every page above the in-process size fails with the typed
//! `parser_limit_exceeded`, the same way every time. This file holds one test because the helper
//! configuration is process-wide and read once.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use clap::Parser as _;
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;

fn html(body: String) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
}

/// A link-rich page above the 1 MiB in-process size: the links come after the padding, so a scan
/// that stopped early would miss them.
fn oversized_page(base: &str) -> String {
    let mut body = String::from(
        "<!doctype html><html lang=\"en\"><head><title>Oversized hub</title>\
         <meta name=\"description\" content=\"Too big for the helper limits\">\
         <link rel=\"canonical\" href=\"/hub\"></head><body><main>",
    );
    while body.len() < 1_600 * 1024 {
        body.push_str(
            "<p>Padding paragraph with several words to count and parse, and no links at all.</p>\n",
        );
    }
    body.push_str(&format!(
        "<a href=\"/leaf/1\">Leaf one</a> <a href=\"{base}/leaf/2\">Leaf two</a> <a href=\"/leaf/1#again\">dup</a>\
         <script>var s = '<a href=\"/leaf/script\">never</a>';</script></main></body></html>"
    ));
    body
}

fn record_for(origin: &str) -> AuthorizationRecord {
    AuthorizationRecord {
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        ..sample_record(TenantId::new(), SystemClock.now(), &[origin])
    }
}

#[tokio::test]
async fn a_refused_page_still_leads_the_crawl_to_its_links() {
    std::env::set_var("CRAWLX_PARSER_HELPER", env!("CARGO_BIN_EXE_crawlx"));
    std::env::set_var(
        "CRAWLX_PARSER_HELPER_ADDRESS_SPACE_BYTES",
        (128 * 1024 * 1024).to_string(),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hub = oversized_page(&base);
    let app = Router::new()
        .route(
            "/",
            get(move || {
                let hub = hub.clone();
                async move { html(hub) }
            }),
        )
        .route(
            "/leaf/1",
            get(|| async {
                html(
                    "<html><head><title>Leaf 1</title></head><body><main><p>One.</p></main></body></html>"
                        .to_owned(),
                )
            }),
        )
        .route(
            "/leaf/2",
            get(|| async {
                html(
                    "<html><head><title>Leaf 2</title></head><body><main><p>Two.</p></main></body></html>"
                        .to_owned(),
                )
            }),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") });
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let dir = tempfile::tempdir().unwrap();
    let authz = dir.path().join("authz.local.json");
    std::fs::write(&authz, serde_json::to_vec_pretty(&record_for(&base)).unwrap()).unwrap();
    let out_dir = dir.path().join("out");
    let seed = format!("{base}/");
    let cli = crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        seed.as_str(),
        "--mode",
        "static",
        "--authorization-record",
        authz.to_str().unwrap(),
        "--allow-private-networks",
        "--seed",
        "20261122",
        "--delay-ms",
        "0",
        "--output",
        out_dir.to_str().unwrap(),
    ])
    .unwrap();
    let mut out = Vec::new();
    let code = crawlx_cli::execute(cli, &mut out).await;
    server.abort();
    let stdout = String::from_utf8(out).unwrap();
    let _exit = code.unwrap();

    // the hub fails typed, its two distinct links are fetched and parsed
    for (name, value) in [
        ("urls.attempted", 3),
        ("urls.succeeded", 2),
        ("urls.failed", 1),
        ("unknown_outcome", 0),
    ] {
        let expected = format!("{name:<20}{value:>3}");
        assert!(
            stdout.lines().any(|l| l == expected),
            "`{expected}` missing from:\n{stdout}"
        );
    }
    assert!(
        stdout.contains("mode=static terminal_reason=frontier_exhausted"),
        "{stdout}"
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("metadata.json")).unwrap()).unwrap();
    let mut titles: Vec<&str> = metadata
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|page| page["title"].as_str())
        .collect();
    titles.sort_unstable();
    assert_eq!(titles, ["Leaf 1", "Leaf 2"], "the script's link is not followed");
}
