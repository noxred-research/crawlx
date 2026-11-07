//! Egress capture on the HTTP plane: a crawl whose pages link to hosts outside the
//! fixture dials nothing but the fixture host. Every fetched frontier row is on the fixture's
//! IP literal, and the resolver, which every fetch of a named host goes through, is never
//! asked for a name. The browser-plane capture (G24 form submissions through the egress
//! proxy) lives in `crawlx-bench/tests/worker_e2e.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::FrontierStatus;
use crawlx_core::CreateCrawl;
use crawlx_fetch::{FetchError, Resolver, StaticResolver};
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

/// Records every host the HTTP plane asked to resolve.
struct RecordingResolver {
    inner: StaticResolver,
    asked: Mutex<BTreeSet<String>>,
}

#[async_trait]
impl Resolver for RecordingResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, FetchError> {
        self.asked.lock().insert(host.to_ascii_lowercase());
        self.inner.resolve(host).await
    }
}

#[tokio::test]
async fn http_plane_never_dials_a_host_outside_the_fixture() {
    let site = common::site::start().await;
    let resolver = Arc::new(RecordingResolver {
        inner: StaticResolver::new(),
        asked: Mutex::new(BTreeSet::new()),
    });
    let dir = tempfile::tempdir().unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::clone(&resolver) as Arc<dyn Resolver>),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_019);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    let stores = Stores::open(&cfg).await.unwrap();
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone()))
        .await
        .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert!(report.counters.urls.succeeded >= 4, "{:?}", report.counters);

    // the fixture links to `https://external.example/out`: admission records it as blocked
    let rows = stores.frontier.list(report.run_id).await.unwrap();
    let external: Vec<_> = rows
        .iter()
        .filter(|e| e.url.url.host_str() != Some("127.0.0.1"))
        .collect();
    assert!(!external.is_empty(), "the fixture must carry an off-host link");
    assert!(
        external
            .iter()
            .all(|e| e.status == FrontierStatus::PolicyBlocked && e.attempts == 0),
        "{external:?}"
    );
    // every fetched row is on the fixture host (an IP literal, which needs no lookup) ...
    let attempted: Vec<_> = rows.iter().filter(|e| e.attempts > 0).collect();
    assert!(attempted.len() >= 5, "{attempted:?}");
    assert!(attempted
        .iter()
        .all(|e| e.url.url.host_str() == Some("127.0.0.1")));
    // ... and the resolver, which every fetch of a named host goes through, was never asked
    // for a name: `external.example` was refused by admission before any lookup
    let asked = resolver.asked.lock().clone();
    assert!(asked.is_empty(), "{asked:?}");
    // no browser plane, so no proxy traffic either
    assert_eq!(report.egress.dialed_hosts, Vec::<(String, u16)>::new());
    assert!(report.egress.denied_events.is_empty());
}
