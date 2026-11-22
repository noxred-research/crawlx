//! `scope.hostChecks: ["soft_404"]` on the static plane: one request to a random path of the seed
//! origin, admitted like any other fetch. Owned loopback fixture only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::{CrawlMode, SitemapMode};
use crawlx_core::host_checks::{HostCheck, HostCheckReason, HostCheckVerdict};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const PROBE_PREFIX: &str = "/crawlx-absent-";
const PROBE_BODY_LEN: usize = 4096;

struct Site {
    base: String,
    hits: Arc<Mutex<Vec<(String, Instant)>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Site {
    fn paths(&self) -> Vec<String> {
        self.hits.lock().unwrap().iter().map(|(p, _)| p.clone()).collect()
    }
    fn probes(&self) -> Vec<String> {
        self.paths()
            .into_iter()
            .filter(|p| p.starts_with(PROBE_PREFIX))
            .collect()
    }
}

/// `/` is a page; any `/crawlx-absent-*` path answers `probe_status`; `robots.txt` is `robots`.
async fn site(probe_status: u16, robots: &'static str) -> Site {
    let hits = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = {
        let hits = Arc::clone(&hits);
        Router::new()
            .route(
                "/",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/html")],
                        "<html><head><title>Home</title></head><body><main><h1>Home</h1>\
                         <p>A page with enough text to be extracted as content for the check.</p></main></body></html>",
                    )
                }),
            )
            .route("/robots.txt", get(move || async move { robots }))
            .fallback(move |uri: axum::http::Uri| async move {
                if uri.path().starts_with(PROBE_PREFIX) {
                    let status = StatusCode::from_u16(probe_status).unwrap();
                    // over 2 KiB, so a body cap or an oversize policy has something to act on
                    let body = format!("<html><body>probe answer {}</body></html>", "x".repeat(PROBE_BODY_LEN));
                    (
                        status,
                        [(header::LOCATION, "/elsewhere"), (header::CONTENT_TYPE, "text/html")],
                        body,
                    )
                        .into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            })
            .layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let hits = Arc::clone(&hits);
                    async move {
                        hits.lock()
                            .unwrap()
                            .push((request.uri().path().to_owned(), Instant::now()));
                        next.run(request).await
                    }
                },
            ))
    };
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, hits, task }
}

async fn crawl(site: &Site, tweak: impl FnOnce(&mut CreateCrawl)) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_122);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.host_checks = vec![HostCheck::Soft404];
    tweak(&mut crawl);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    run_local_with(LocalRun::new(crawl, config).with_stores(stores))
        .await
        .unwrap()
}

#[tokio::test]
async fn a_success_status_for_the_random_path_is_soft_404() {
    let site = site(200, "User-agent: *\nAllow: /\n").await;
    let report = crawl(&site, |_| {}).await;
    assert_eq!(
        site.probes().len(),
        1,
        "exactly one probe request: {:?}",
        site.paths()
    );
    let [record] = report.host_checks.as_slice() else {
        panic!("one record expected: {:?}", report.host_checks);
    };
    assert_eq!(record.check, HostCheck::Soft404);
    assert!(record.requested);
    assert_eq!(record.status, Some(200));
    assert_eq!(record.verdict, HostCheckVerdict::Soft404);
    assert_eq!(record.reason, None);
    assert_eq!(record.origin, site.base);
    assert_eq!(record.url, format!("{}{}", site.base, site.probes()[0]));
    // the fixed prefix and 32 lowercase hex digits
    assert_eq!(site.probes()[0].len(), PROBE_PREFIX.len() + 32);
}

#[tokio::test]
async fn statuses_map_to_verdicts_and_nothing_is_followed() {
    let table: &[(u16, HostCheckVerdict, Option<HostCheckReason>)] = &[
        (404, HostCheckVerdict::NotSoft404, None),
        (410, HostCheckVerdict::NotSoft404, None),
        (
            301,
            HostCheckVerdict::Inconclusive,
            Some(HostCheckReason::UnclassifiedStatus),
        ),
        (
            302,
            HostCheckVerdict::Inconclusive,
            Some(HostCheckReason::UnclassifiedStatus),
        ),
        (
            401,
            HostCheckVerdict::Inconclusive,
            Some(HostCheckReason::UnclassifiedStatus),
        ),
        (
            403,
            HostCheckVerdict::Inconclusive,
            Some(HostCheckReason::UnclassifiedStatus),
        ),
        (
            500,
            HostCheckVerdict::Inconclusive,
            Some(HostCheckReason::UnclassifiedStatus),
        ),
        (
            503,
            HostCheckVerdict::Inconclusive,
            Some(HostCheckReason::UnclassifiedStatus),
        ),
    ];
    for (status, verdict, reason) in table {
        let site = site(*status, "").await;
        let report = crawl(&site, |_| {}).await;
        assert_eq!(site.probes().len(), 1, "status {status}: {:?}", site.paths());
        assert!(
            !site.paths().contains(&"/elsewhere".to_owned()),
            "status {status}: the Location target is never requested"
        );
        let [record] = report.host_checks.as_slice() else {
            panic!("status {status}: {:?}", report.host_checks);
        };
        assert!(record.requested, "status {status}");
        assert_eq!(record.status, Some(*status));
        assert_eq!(record.verdict, *verdict, "status {status}");
        assert_eq!(record.reason, *reason, "status {status}");
    }
}

#[tokio::test]
async fn default_off_sends_nothing() {
    let site = site(200, "").await;
    let report = crawl(&site, |crawl| crawl.scope.host_checks.clear()).await;
    assert!(site.probes().is_empty(), "{:?}", site.paths());
    assert!(report.host_checks.is_empty());
}

#[tokio::test]
async fn the_probe_path_is_reproducible_under_the_run_seed_and_the_check_is_listed_once() {
    let site = site(404, "").await;
    let first = crawl(&site, |crawl| {
        crawl.scope.host_checks = vec![HostCheck::Soft404, HostCheck::Soft404];
    })
    .await;
    let second = crawl(&site, |_| {}).await;
    let third = crawl(&site, |crawl| crawl.seed = Some(7)).await;
    let probes = site.probes();
    assert_eq!(probes.len(), 3, "one request per run: {probes:?}");
    assert_eq!(probes[0], probes[1], "same seed, same path");
    assert_ne!(probes[1], probes[2], "another seed, another path");
    assert_eq!(first.host_checks.len(), 1, "a duplicate entry is one check");
    assert_eq!(second.host_checks[0].url, first.host_checks[0].url);
    assert_ne!(third.host_checks[0].url, first.host_checks[0].url);
}

#[tokio::test]
async fn robots_disallow_covering_the_probe_path_sends_nothing() {
    let site = site(200, "User-agent: *\nDisallow: /crawlx-absent-\n").await;
    let report = crawl(&site, |_| {}).await;
    assert!(site.probes().is_empty(), "{:?}", site.paths());
    let [record] = report.host_checks.as_slice() else {
        panic!("{:?}", report.host_checks);
    };
    assert!(!record.requested);
    assert_eq!(record.status, None);
    assert_eq!(record.verdict, HostCheckVerdict::Inconclusive);
    assert_eq!(record.reason, Some(HostCheckReason::Robots));
}

#[tokio::test]
async fn scope_refusal_sends_nothing() {
    let site = site(200, "").await;
    let report = crawl(&site, |crawl| {
        crawl.scope.exclude_paths = vec!["^/crawlx-absent-".into()];
    })
    .await;
    assert!(site.probes().is_empty(), "{:?}", site.paths());
    let [record] = report.host_checks.as_slice() else {
        panic!("{:?}", report.host_checks);
    };
    assert!(!record.requested);
    assert_eq!(record.verdict, HostCheckVerdict::Inconclusive);
    assert_eq!(record.reason, Some(HostCheckReason::Scope));
}

#[tokio::test]
async fn crawl_delay_spaces_the_probe_from_the_next_request() {
    let site = site(404, "User-agent: *\nCrawl-delay: 1\n").await;
    let report = crawl(&site, |_| {}).await;
    assert_eq!(report.host_checks.len(), 1);
    let hits = site.hits.lock().unwrap().clone();
    let probe = hits
        .iter()
        .position(|(p, _)| p.starts_with(PROBE_PREFIX))
        .unwrap();
    let next = hits[probe + 1..]
        .iter()
        .find(|(p, _)| p == "/")
        .map(|(_, at)| *at)
        .expect("the seed page is requested after the probe");
    let gap = next.duration_since(hits[probe].1);
    assert!(gap.as_millis() >= 900, "crawl delay honoured, gap {gap:?}");
}

#[tokio::test]
async fn a_configured_head_preflight_does_not_add_a_request_to_the_probe() {
    let site = site(404, "").await;
    let report = crawl(&site, |crawl| {
        let mut preflight = crawlx_core::acquisition::HeadPreflight::default();
        preflight.max_content_length = Some(1024);
        crawl.fetch.preflight = Some(preflight);
    })
    .await;
    assert_eq!(
        site.probes().len(),
        1,
        "exactly one probe request: {:?}",
        site.paths()
    );
    let [record] = report.host_checks.as_slice() else {
        panic!("{:?}", report.host_checks);
    };
    assert!(record.requested);
    assert_eq!(record.status, Some(404));
    assert_eq!(record.verdict, HostCheckVerdict::NotSoft404);
    assert_eq!(record.reason, None);
}

#[tokio::test]
async fn an_oversize_refusal_policy_does_not_turn_a_large_answer_into_a_failed_probe() {
    let site = site(200, "").await;
    let report = crawl(&site, |crawl| {
        crawl.fetch.oversize = Some(crawlx_core::acquisition::OversizePolicy::Refuse);
    })
    .await;
    assert_eq!(
        site.probes().len(),
        1,
        "exactly one probe request: {:?}",
        site.paths()
    );
    let [record] = report.host_checks.as_slice() else {
        panic!("{:?}", report.host_checks);
    };
    assert!(record.requested);
    assert_eq!(record.status, Some(200));
    assert_eq!(record.verdict, HostCheckVerdict::Soft404);
    assert_eq!(record.reason, None);
    assert_eq!(record.error_code, None);
}

#[tokio::test]
async fn a_longest_match_allow_overrides_a_disallow_prefix_covering_the_probe_path() {
    let site = site(404, "User-agent: *\nDisallow: /crawlx-\nAllow: /crawlx-absent-\n").await;
    let report = crawl(&site, |_| {}).await;
    assert_eq!(site.probes().len(), 1, "{:?}", site.paths());
    let [record] = report.host_checks.as_slice() else {
        panic!("{:?}", report.host_checks);
    };
    assert!(record.requested);
    assert_eq!(record.verdict, HostCheckVerdict::NotSoft404);
}

#[tokio::test]
async fn a_dollar_anchored_disallow_that_does_not_match_the_probe_path_allows_it() {
    let site = site(404, "User-agent: *\nDisallow: /crawlx-absent-$\n").await;
    let report = crawl(&site, |_| {}).await;
    assert_eq!(site.probes().len(), 1, "{:?}", site.paths());
    let [record] = report.host_checks.as_slice() else {
        panic!("{:?}", report.host_checks);
    };
    assert!(record.requested);
    assert_eq!(record.verdict, HostCheckVerdict::NotSoft404);
}

#[tokio::test]
async fn an_egress_policy_denial_sends_nothing() {
    let site = site(200, "").await;
    let report = crawl(&site, |crawl| {
        crawl.safety.allow_private_networks = false;
    })
    .await;
    assert!(site.paths().is_empty(), "{:?}", site.paths());
    let [record] = report.host_checks.as_slice() else {
        panic!("{:?}", report.host_checks);
    };
    assert!(!record.requested);
    assert_eq!(record.status, None);
    assert_eq!(record.verdict, HostCheckVerdict::Inconclusive);
    assert_eq!(record.reason, Some(HostCheckReason::Egress));
}
