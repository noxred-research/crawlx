//! A static crawl requests a page's `<base href>` URL once, like every other URL-bearing
//! attribute the endpoint miner reports (benchmark finding X-05: a lone `GET /p/` that answered
//! 404 after the JSON endpoint requests; the source was `<base href="/p/">` on one fixture page).
//! The request is documented behaviour (`docs/reference.md`), pinned here so it stays explained.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::Router;
use clap::Parser as _;
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;

async fn respond(State(log): State<Arc<Mutex<Vec<String>>>>, uri: Uri) -> axum::response::Response {
    log.lock().unwrap().push(uri.path().to_owned());
    match uri.path() {
        "/" => (
            [(header::CONTENT_TYPE, "text/html")],
            r#"<html><head><title>Home</title><base href="/dir/"></head><body><main><p>Home page.</p><a href="x">X</a></main></body></html>"#,
        )
            .into_response(),
        "/dir/x" => (
            [(header::CONTENT_TYPE, "text/html")],
            "<html><head><title>X</title></head><body><main><p>Leaf.</p></main></body></html>",
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

#[tokio::test]
async fn the_base_href_url_is_requested_once_and_relative_links_resolve_against_it() {
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
        dir.path().join("out").to_str().unwrap(),
    ])
    .unwrap();
    let mut out = Vec::new();
    let code = crawlx_cli::execute(cli, &mut out).await;
    server.abort();
    let _exit = code.unwrap();

    let requested = log.lock().unwrap().clone();
    let count = |path: &str| requested.iter().filter(|p| *p == path).count();
    assert_eq!(count("/dir/x"), 1, "{requested:?}");
    assert_eq!(
        count("/dir/"),
        1,
        "the base URL is a structural endpoint: {requested:?}"
    );
    assert_eq!(
        count("/x"),
        0,
        "relative links resolve against the base: {requested:?}"
    );
}
