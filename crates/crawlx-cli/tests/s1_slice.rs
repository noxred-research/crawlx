//! Vertical slice 1: `crawlx crawl <fixture> --mode static` against the
//! CrawlerGym S1 site must produce the manifest's counters.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::Parser as _;
use crawlx_bench::gym::manifest::FixtureManifest;
use crawlx_bench::gym::server::GymServer;
use crawlx_core::{Clock, SystemClock, TenantId};
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;

#[tokio::test]
async fn s1_static_crawl_matches_the_manifest_counters() {
    let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let manifest = FixtureManifest::embedded("s1").unwrap();
    let expected = manifest.expected.url_counters.expect("s1 has url counters");

    let dir = tempfile::tempdir().unwrap();
    let now = SystemClock.now();
    let record = AuthorizationRecord {
        authorized_networks: vec!["127.0.0.0/8".parse().unwrap()],
        ..sample_record(TenantId::new(), now, &[gym.base_url.as_str()])
    };
    let authz = dir.path().join("authz.local.json");
    std::fs::write(&authz, serde_json::to_vec(&record).unwrap()).unwrap();
    let out_dir = dir.path().join("out");
    let cli = crawlx_cli::Cli::try_parse_from([
        "crawlx",
        "crawl",
        &format!("{}/s1/", gym.base_url),
        "--mode",
        "static",
        "--authorization-record",
        authz.to_str().unwrap(),
        "--allow-private-networks",
        "--seed",
        "20261019",
        "--trailing-slash",
        "strip",
        "--delay-ms",
        "0",
        "--output",
        out_dir.to_str().unwrap(),
    ])
    .unwrap();
    let mut out = Vec::new();
    let _exit = crawlx_cli::execute(cli, &mut out).await.unwrap();
    let stdout = String::from_utf8(out).unwrap();
    println!("{stdout}");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out_dir.join("report.json")).unwrap()).unwrap();
    let got: crawlx_core::counters::Counters =
        serde_json::from_value(report["counters"]["urls"].clone()).unwrap();
    assert!(got.invariants_hold());
    assert_eq!(got, expected, "stdout:\n{stdout}");
    gym.shutdown().await;
}
