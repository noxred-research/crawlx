//! `scope.hostChecks: ["soft_404"]` through the CLI: the probe is one request to a random path of the
//! seed origin, its fact lands in `report.json`, and without the key nothing extra is sent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, Uri};
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
            "<html><head><title>Home</title></head><body><main><p>Home page.</p></main></body></html>",
        )
            .into_response(),
        // a server that answers every unknown path with a page
        _ => (
            [(header::CONTENT_TYPE, "text/html")],
            "<html><head><title>Not here</title></head><body><main><p>Nothing here.</p></main></body></html>",
        )
            .into_response(),
    }
}

/// Crawl `/` of a loopback site; returns the paths the site saw and the parsed `report.json`.
async fn crawl(host_checks: &[&str]) -> (Vec<String>, serde_json::Value) {
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
    let request = dir.path().join("request.json");
    std::fs::write(
        &request,
        serde_json::to_vec(&serde_json::json!({
            "seedUrl": format!("{base}/"),
            "scope": {"hostChecks": host_checks},
        }))
        .unwrap(),
    )
    .unwrap();
    let out_dir = dir.path().join("out");
    let cli = crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        "--request",
        request.to_str().unwrap(),
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
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("report.json")).unwrap()).unwrap();
    let requested = log.lock().unwrap().clone();
    (requested, report)
}

#[tokio::test]
async fn soft_404_probe_is_one_request_recorded_in_the_report() {
    let (requested, report) = crawl(&["soft_404"]).await;
    let probes: Vec<_> = requested
        .iter()
        .filter(|p| p.starts_with("/crawlx-absent-"))
        .collect();
    assert_eq!(probes.len(), 1, "{requested:?}");
    let checks = report["host_checks"].as_array().unwrap();
    assert_eq!(checks.len(), 1, "{report}");
    let check = &checks[0];
    assert_eq!(check["check"], "soft_404");
    assert_eq!(check["verdict"], "soft_404");
    assert_eq!(check["status"], 200);
    assert_eq!(check["requested"], true);
    assert!(check["url"].as_str().unwrap().ends_with(probes[0].as_str()));
    assert!(check.get("reason").is_none());
}

#[tokio::test]
async fn without_the_key_no_probe_is_sent_and_the_report_has_no_host_checks() {
    let (requested, report) = crawl(&[]).await;
    assert!(
        requested.iter().all(|p| !p.starts_with("/crawlx-absent-")),
        "{requested:?}"
    );
    assert!(report.get("host_checks").is_none(), "{report}");
}
