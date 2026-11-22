//! `X-Robots-Tag` is recorded in `metadata.json` (`x_robots_tag`, `robots_effective`) and changes
//! nothing that is requested. Loopback fixture only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderName, HeaderValue, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use clap::Parser as _;
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;

async fn respond(State(log): State<Arc<Mutex<Vec<String>>>>, uri: Uri) -> axum::response::Response {
    log.lock().unwrap().push(uri.path().to_owned());
    let (body, tags): (&str, &[&str]) = match uri.path() {
        "/" => (
            r#"<a href="/hidden">hidden</a> <a href="/scoped">scoped</a> <a href="/plain">plain</a>"#,
            &[],
        ),
        "/hidden" => (
            r#"<meta name="robots" content="noarchive"><a href="/leaf">leaf</a>"#,
            &["NoIndex, NoFollow", "unavailable_after: 25 Jun 2030 15:00:00 PST"],
        ),
        "/scoped" => ("", &["googlebot: noindex", "crawlx: nosnippet"]),
        "/plain" | "/leaf" => ("", &[]),
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let mut response = (
        [(header::CONTENT_TYPE, "text/html")],
        format!(
            "<html><head><title>T</title></head><body><main><p>{}</p>{body}</main></body></html>",
            "Fixture text that is long enough to be a page. ".repeat(6)
        ),
    )
        .into_response();
    for tag in tags {
        response.headers_mut().append(
            HeaderName::from_static("x-robots-tag"),
            HeaderValue::from_str(tag).unwrap(),
        );
    }
    response
}

#[tokio::test]
async fn the_header_is_recorded_in_metadata_json_and_every_link_is_still_requested() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(respond).with_state(Arc::clone(&log));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let dir = tempfile::tempdir().unwrap();
    let authz = dir.path().join("authz.local.json");
    let record = AuthorizationRecord {
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        ..sample_record(TenantId::new(), SystemClock.now(), &[base.as_str()])
    };
    std::fs::write(&authz, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
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
    let _exit = code.unwrap();

    let requested = log.lock().unwrap().clone();
    for path in ["/hidden", "/scoped", "/plain", "/leaf"] {
        assert!(
            requested.iter().any(|p| p == path),
            "{path} not requested: {requested:?}"
        );
    }
    let metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("metadata.json")).unwrap()).unwrap();
    let page = |path: &str| {
        metadata
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["url"].as_str().unwrap().ends_with(path))
            .unwrap_or_else(|| panic!("no page {path}"))["metadata"]
            .clone()
    };
    let hidden = page("/hidden");
    assert_eq!(hidden["x_robots_tag"]["noindex"], true);
    assert_eq!(hidden["x_robots_tag"]["nofollow"], true);
    assert_eq!(hidden["x_robots_tag"]["noarchive"], false);
    assert_eq!(hidden["robots"]["noarchive"], true);
    assert_eq!(hidden["robots_effective"]["noarchive"], true);
    assert_eq!(hidden["robots_effective"]["noindex"], true);
    let scoped = page("/scoped");
    assert_eq!(
        scoped["x_robots_tag"]["noindex"], false,
        "googlebot scope is not ours"
    );
    assert_eq!(scoped["x_robots_tag"]["nosnippet"], true, "crawlx scope is");
    let plain = page("/plain");
    assert!(plain.get("x_robots_tag").is_none() && plain.get("robots_effective").is_none());
}
