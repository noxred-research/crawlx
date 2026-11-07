//! Consumer-visible native meta continuation, using owned loopback HTTP fixtures only.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
mod resume_rig;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, Uri},
    response::IntoResponse,
    Router,
};
use crawlx_core::{
    acquisition::{AcquisitionPolicyV1, MetaRefreshPolicyV1},
    config::{CrawlMode, SitemapMode},
    CreateCrawl,
};
use crawlx_fetch::StaticResolver;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: String,
    location: Option<String>,
    park: bool,
}
impl Reply {
    fn html(body: impl Into<String>) -> Self {
        Self {
            status: StatusCode::OK,
            body: body.into(),
            location: None,
            park: false,
        }
    }
    fn redirect(target: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FOUND,
            body: String::new(),
            location: Some(target.into()),
            park: false,
        }
    }
}
#[derive(Default)]
struct StateData {
    replies: Mutex<BTreeMap<String, Reply>>,
    hits: Mutex<Vec<(String, HeaderMap, Instant)>>,
    parked: Notify,
    release: Notify,
    robots_served: Notify,
}
struct Site {
    base: String,
    state: Arc<StateData>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Site {
    fn url(&self, path: &str) -> Url {
        Url::parse(&format!("{}{path}", self.base)).unwrap()
    }
    fn set(&self, path: &str, reply: Reply) {
        self.state.replies.lock().unwrap().insert(path.into(), reply);
    }
    fn count(&self, path: &str) -> usize {
        self.state
            .hits
            .lock()
            .unwrap()
            .iter()
            .filter(|hit| hit.0 == path)
            .count()
    }
}
async fn serve(
    State(state): State<Arc<StateData>>,
    uri: Uri,
    headers: HeaderMap,
) -> axum::response::Response {
    state
        .hits
        .lock()
        .unwrap()
        .push((uri.path().into(), headers, Instant::now()));
    if uri.path() == "/robots.txt" && !state.replies.lock().unwrap().contains_key("/robots.txt") {
        state.robots_served.notify_one();
        return "User-agent: *\nDisallow: /robots-private\n".into_response();
    }
    if uri.path() == "/transport-failure" {
        return axum::response::Response::builder()
            .header("content-type", "text/html")
            .body(axum::body::Body::from_stream(futures::stream::once(async {
                Err::<bytes::Bytes, _>(std::io::Error::other("owned fixture body transport failure"))
            })))
            .unwrap();
    }
    if uri.path() == "/exact-cap-error" {
        use futures::StreamExt as _;
        let body = state.replies.lock().unwrap()["/exact-cap-error"].body.clone();
        let chunks = futures::stream::once(async move { Ok::<_, std::io::Error>(bytes::Bytes::from(body)) })
            .chain(futures::stream::once(async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Err::<bytes::Bytes, _>(std::io::Error::other("owned exact-cap transport failure"))
            }));
        return axum::response::Response::builder()
            .header("content-type", "text/html")
            .body(axum::body::Body::from_stream(chunks))
            .unwrap();
    }
    let reply = state
        .replies
        .lock()
        .unwrap()
        .get(uri.path())
        .cloned()
        .unwrap_or(Reply {
            status: StatusCode::NOT_FOUND,
            body: "missing".into(),
            location: None,
            park: false,
        });
    if reply.park {
        state.parked.notify_one();
        state.release.notified().await;
    }
    let mut response = (reply.status, [("content-type", "text/html")], reply.body).into_response();
    if uri.path() == "/final" {
        response
            .headers_mut()
            .insert("etag", "\"selected-v1\"".parse().unwrap());
    }
    if let Some(location) = reply.location {
        response
            .headers_mut()
            .insert("location", location.parse().unwrap());
    }
    if uri.path() == "/robots.txt" {
        state.robots_served.notify_one();
    }
    response
}
async fn site() -> Site {
    site_on("127.0.0.1").await
}
async fn site_on(host: &str) -> Site {
    let state = Arc::new(StateData::default());
    let listener = tokio::net::TcpListener::bind((host, 0)).await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(serve).with_state(Arc::clone(&state));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let site = Site { base, state, task };
    site.set("/final", Reply::html("<html><title>Selected final</title><main id=expected>Final selected document with enough visible words for validation and extraction.</main></html>"));
    site
}
fn refresh(target: &str, delay: &str) -> Reply {
    Reply::html(format!("<html><head><title>Initial source</title><meta http-equiv=refresh content=\"{delay}; URL = '{target}'\"></head><body>Initial source must not become the selected final representation.</body></html>"))
}
fn enable(crawl: &mut CreateCrawl) {
    let mut policy = AcquisitionPolicyV1::default();
    policy.max_attempts = 8;
    policy.max_network_requests = 8;
    policy.meta_refresh = Some(MetaRefreshPolicyV1::default());
    crawl.acquisition = Some(policy);
    crawl.mode = CrawlMode::Static;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.crawl_entire_domain = true;
    crawl.scope.known_files.clear();
    crawl.politeness.delay_ms = 0;
}
fn request(site: &Site, path: &str) -> CreateCrawl {
    let mut crawl = CreateCrawl::new(site.url(path));
    enable(&mut crawl);
    crawl.seed = Some(20_261_105);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.scope.max_discovery_depth = 0;
    crawl
}
fn config(path: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: path.into(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    }
}
fn config_with_targets(path: &std::path::Path, targets: &[&Site]) -> WorkerConfig {
    let mut cfg = config(path);
    // Authorization coverage does not bypass the independent egress port gate.
    cfg.egress.extra_ports = targets.iter().filter_map(|site| site.url("/").port()).collect();
    cfg
}
async fn run(crawl: CreateCrawl) -> RunReport {
    run_with_targets(crawl, &[]).await
}
async fn run_with_targets(crawl: CreateCrawl, targets: &[&Site]) -> RunReport {
    let dir = tempfile::tempdir_in("/data").unwrap();
    common::authorization::run_authorized_local(crawl, config_with_targets(dir.path(), targets))
        .await
        .unwrap()
}

#[tokio::test]
async fn refresh_cannot_widen_the_native_seed_path_scope() {
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    let mut crawl = request(&site, "/source");
    crawl.scope.crawl_entire_domain = false;
    let report = run(crawl).await;
    assert!(report.pages.is_empty());
    assert_eq!(site.count("/source"), 1);
    assert_eq!(site.count("/final"), 0);
}

#[tokio::test]
async fn opt_in_selects_first_matching_tag_and_observed_relative_url_without_changing_frontier() {
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    let mut off = request(&site, "/source");
    off.acquisition.as_mut().unwrap().meta_refresh = None;
    let report = run(off).await;
    assert_eq!(report.pages[0].title.as_deref(), Some("Initial source"));
    assert_eq!(site.count("/final"), 0);
    let mut crawl = request(&site, "/source");
    crawl.acquisition.as_mut().unwrap().validation.required_selectors = vec!["#expected".into()];
    site.set("/source", Reply::redirect("/observed/page"));
    site.set("/observed/page", Reply::html("<base href='/wrong/'><MeTa HtTp-EqUiV=' ReFrEsH ' CoNtEnT=\"999999; uRl = '../final'\"><meta http-equiv=refresh content='0;url=/never'><title>Not selected</title>"));
    let report = run(crawl).await;
    assert_eq!(report.pages.len(), 1);
    let page = &report.pages[0];
    assert_eq!(page.url.url, site.url("/source"));
    assert_eq!(page.title.as_deref(), Some("Selected final"));
    assert_eq!(page.status, 200);
    let receipt = &page.metadata["acquisition"];
    assert_eq!(receipt["requestedUrl"], site.url("/source").as_str());
    assert_eq!(receipt["finalUrl"], site.url("/final").as_str());
    assert_eq!(
        receipt["metaRefresh"]["initialUrl"],
        site.url("/observed/page").as_str()
    );
    assert_eq!(receipt["metaRefresh"]["initialStatus"], 200);
    assert_eq!(receipt["metaRefresh"]["selectedStatus"], 200);
    assert_eq!(receipt["redirects"][0]["status"], 302);
    assert_eq!(receipt["networkRequests"], 3);
    assert_eq!(receipt["validation"]["contentAccepted"], true);
    assert_eq!(site.count("/never"), 0);
    // Target meta tags cannot authorize a second transition.
    site.set("/final", refresh("/never", "0"));
    assert_eq!(run(request(&site, "/source")).await.pages.len(), 1);
    assert_eq!(site.count("/never"), 0);
}

#[tokio::test]
async fn malformed_or_bounded_tags_do_not_follow_and_long_delay_keeps_governor_spacing() {
    let site = site().await;
    for body in [
        "<meta http-equiv=refresh><meta http-equiv=refresh content='0;url=/final'>",
        "<meta http-equiv=refresh content='wat;url=/final'><meta http-equiv=refresh content='0;url=/final'>",
        "<script>\"<meta http-equiv=refresh content=\"0;url=/final\">\"</script>",
    ] {
        site.set(
            "/source",
            Reply::html(format!(
                "<title>Original</title>{body}<main>Original document.</main>"
            )),
        );
        assert_eq!(
            run(request(&site, "/source")).await.pages[0].title.as_deref(),
            Some("Original")
        );
    }
    assert_eq!(site.count("/final"), 0);
    site.set("/source", refresh("/final", "86400"));
    let mut bounded = request(&site, "/source");
    bounded
        .acquisition
        .as_mut()
        .unwrap()
        .meta_refresh
        .as_mut()
        .unwrap()
        .max_parser_bytes = 16;
    assert_eq!(
        run(bounded).await.pages[0].title.as_deref(),
        Some("Initial source")
    );
    assert_eq!(site.count("/final"), 0);
    let mut paced = request(&site, "/source");
    paced.politeness.delay_ms = 80;
    paced.acquisition.as_mut().unwrap().max_elapsed_ms = 2000;
    let report = run(paced).await;
    assert_eq!(report.pages[0].title.as_deref(), Some("Selected final"));
    let hits = site.state.hits.lock().unwrap();
    let source = hits.iter().rev().find(|hit| hit.0 == "/source").unwrap().2;
    let final_hit = hits.iter().rev().find(|hit| hit.0 == "/final").unwrap().2;
    assert!(final_hit.duration_since(source) >= Duration::from_millis(60));
}

#[tokio::test]
async fn loops_target_failure_and_forbidden_destinations_never_return_original_success() {
    let site = site().await;
    site.set("/mixed", Reply::redirect("/source"));
    for target in [
        "/source",
        "/mixed",
        "/missing",
        "/transport-failure",
        "/robots-private",
        "/outside",
        "http://169.254.169.254/latest/meta-data/",
        "javascript:alert(1)",
    ] {
        site.set("/source", refresh(target, "0"));
        let mut crawl = request(&site, "/source");
        crawl.scope.exclude_paths = vec!["^/outside$".into()];
        let before = site.count("/source");
        let report = run(crawl).await;
        assert!(report.pages.is_empty(), "{target}");
        assert_eq!(site.count("/source") - before, 1, "{target}");
    }
    assert_eq!(site.count("/robots-private"), 0);
    assert_eq!(site.count("/outside"), 0);
    assert_eq!(site.count("/latest/meta-data/"), 0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_target = format!("http://{}/unreachable", listener.local_addr().unwrap());
    drop(listener);
    site.set("/source", refresh(&dead_target, "0"));
    assert!(run(request(&site, "/source")).await.pages.is_empty());
}

#[tokio::test]
async fn transition_shares_attempt_request_byte_deadline_and_combined_hop_allowances() {
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    for limit in ["attempt", "request", "bytes"] {
        let mut crawl = request(&site, "/source");
        let policy = crawl.acquisition.as_mut().unwrap();
        match limit {
            "attempt" => policy.max_attempts = 1,
            "request" => policy.max_network_requests = 1,
            _ => {
                policy.max_decoded_bytes =
                    u64::try_from(site.state.replies.lock().unwrap()["/source"].body.len()).unwrap()
            }
        }
        let before = site.count("/final");
        assert!(run(crawl).await.pages.is_empty(), "{limit}");
        assert_eq!(site.count("/final"), before, "{limit}");
    }
    // Eight attempts include the meta transition; an HTTP chain cannot get a fresh allowance.
    for index in 0..8 {
        site.set(
            &format!("/hop{index}"),
            Reply::redirect(format!("/hop{}", index + 1)),
        );
    }
    site.set("/source", refresh("/hop0", "0"));
    assert!(run(request(&site, "/source")).await.pages.is_empty());
    assert_eq!(site.count("/hop6"), 1);
    assert_eq!(site.count("/hop7"), 0);
    let mut parked = Reply::html("<title>Late target</title>");
    parked.park = true;
    site.set("/final", parked);
    site.set("/source", refresh("/final", "0"));
    let mut deadline = request(&site, "/source");
    deadline.acquisition.as_mut().unwrap().max_elapsed_ms = 100;
    assert!(run(deadline).await.pages.is_empty());
}

#[tokio::test]
async fn origin_change_strips_credentials_and_validators_without_restoring_them_on_return() {
    let source = site().await;
    let target = site().await;
    source.set("/source", Reply::redirect(target.url("/cross").as_str()));
    target.set("/cross", Reply::redirect(source.url("/refresh").as_str()));
    source.set("/refresh", refresh("/final", "0"));
    let mut crawl = request(&source, "/source");
    crawl
        .fetch
        .set_header("authorization", "Bearer owned-fixture-secret")
        .unwrap();
    crawl
        .fetch
        .set_header("if-none-match", "owned-validator")
        .unwrap();
    crawl
        .fetch
        .set_header("cookie", "owned_session=owned-cookie-secret")
        .unwrap();
    crawl
        .fetch
        .set_header("if-modified-since", "Wed, 21 Oct 2015 07:28:00 GMT")
        .unwrap();
    let report = run_with_targets(crawl, &[&target]).await;
    assert_eq!(report.pages[0].title.as_deref(), Some("Selected final"));
    for site in [&source, &target] {
        for (path, headers, _) in site.state.hits.lock().unwrap().iter() {
            if ["/cross", "/refresh", "/final"].contains(&path.as_str()) {
                assert!(!headers.contains_key("authorization"), "{path}");
                assert!(!headers.contains_key("cookie"), "{path}");
                assert!(!headers.contains_key("if-none-match"), "{path}");
                assert!(!headers.contains_key("if-modified-since"), "{path}");
            }
        }
    }
    for (_, headers, _) in target.state.hits.lock().unwrap().iter() {
        assert!(
            !headers.contains_key("authorization"),
            "cross-origin robots must not restore credentials"
        );
        assert!(!headers.contains_key("cookie"));
        assert!(!headers.contains_key("if-none-match"));
        assert!(!headers.contains_key("if-modified-since"));
    }
    let hits = source.state.hits.lock().unwrap();
    assert!(hits
        .iter()
        .find(|hit| hit.0 == "/source")
        .unwrap()
        .1
        .contains_key("authorization"));
}

#[tokio::test]
async fn retained_replay_preserves_selected_evidence_and_uses_zero_network_with_policy_separation() {
    use crawlx_core::cache::{CacheModeV1, CachePolicyV1};
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = request(&site, "/source");
    crawl.cache = Some(CachePolicyV1::default());
    crawl.cache_principal = Some(uuid::Uuid::from_u128(30));
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl.clone(), config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.pages[0].title.as_deref(), Some("Selected final"));
    let before = site.state.hits.lock().unwrap().len();
    crawl.cache.as_mut().unwrap().mode = CacheModeV1::ReadOnly;
    let mut legacy = report.pages[0].clone();
    legacy.metadata["acquisition"]
        .as_object_mut()
        .unwrap()
        .remove("metaRefreshRevision");
    stores.pages.put(&legacy).await.unwrap();
    let incompatible = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl.clone(), config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert!(
        incompatible.pages.is_empty(),
        "unknown prior revision must not be promoted into compatible evidence"
    );
    assert_eq!(site.state.hits.lock().unwrap().len(), before);
    stores.pages.put(&report.pages[0]).await.unwrap();
    let cached = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl.clone(), config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(cached.pages[0].title.as_deref(), Some("Selected final"));
    assert_eq!(
        cached.pages[0].metadata["acquisition"]["metaRefresh"]["selectedStatus"],
        200
    );
    assert_eq!(site.state.hits.lock().unwrap().len(), before);
    crawl.acquisition.as_mut().unwrap().meta_refresh = None;
    let separated = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl, config(dir.path())).with_stores(stores),
    )
    .await
    .unwrap();
    assert!(separated.pages.is_empty());
    assert_eq!(site.state.hits.lock().unwrap().len(), before);
}

#[tokio::test]
async fn cancellation_of_selected_target_does_not_publish_original() {
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    let mut parked = Reply::html("<title>Not observed</title>");
    parked.park = true;
    site.set("/final", parked);
    let dir = tempfile::tempdir_in("/data").unwrap();
    let cancel = CancellationToken::new();
    let local = LocalRun::new(request(&site, "/source"), config(dir.path())).with_cancel(cancel.clone());
    let task = tokio::spawn(common::authorization::run_authorized_local_with(local));
    tokio::time::timeout(Duration::from_secs(10), site.state.parked.notified())
        .await
        .unwrap();
    cancel.cancel();
    let report = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(report.pages.is_empty());
    assert_eq!(site.count("/source"), 1);
    assert_eq!(site.count("/final"), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fenced_restart_cannot_reset_meta_count_or_parent_escrow() {
    use resume_rig::{enqueue, finish, fleet_reaper, page_paths, Doomed, Rig};
    let rig = Rig::memory();
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    let mut parked = Reply::html("<title>Never observed</title>");
    parked.park = true;
    site.set("/final", parked);
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = rig.stores(dir.path()).await;
    let run = enqueue(&rig, &stores, &site.base, |crawl| {
        enable(crawl);
        crawl.seed_url = site.url("/source");
    })
    .await;
    let worker = Doomed::start(&rig, dir.path().into(), CancellationToken::new());
    tokio::time::timeout(Duration::from_secs(30), site.state.parked.notified())
        .await
        .unwrap();
    worker.kill();
    site.state.release.notify_waiters();
    rig.expire_session_leases(&stores, run).await;
    let reaper = fleet_reaper(&stores);
    tokio::time::timeout(Duration::from_secs(30), async {
        while reaper.reaped().requeued == 0 {
            tokio::time::sleep(resume_rig::REAP_EVERY).await;
        }
    })
    .await
    .unwrap();
    finish(&rig, dir.path()).await;
    let _ = reaper.stop().await;
    assert_eq!(site.count("/source"), 1);
    assert_eq!(site.count("/final"), 1);
    assert!(page_paths(&stores, run).await.is_empty());
    rig.teardown().await;
}

#[tokio::test]
async fn unsupported_modes_actions_and_sessions_refuse_before_any_connection() {
    let site = site().await;
    for mode in [CrawlMode::Dynamic, CrawlMode::Hybrid] {
        let mut crawl = request(&site, "/source");
        crawl.mode = mode;
        let dir = tempfile::tempdir_in("/data").unwrap();
        assert!(
            common::authorization::run_authorized_local(crawl, config(dir.path()))
                .await
                .is_err()
        );
    }
    for action in [
        crawlx_core::scrape::ScrapeAction::Write {
            text: "denied write".into(),
        },
        crawlx_core::scrape::ScrapeAction::ExecuteJavascript {
            script: "fetch('/unknown-effect')".into(),
        },
    ] {
        let mut crawl = request(&site, "/source");
        let mut options = crawlx_core::scrape::ScrapeOptions::default();
        options.actions.push(action);
        crawl.scrape = Some(crawlx_core::scrape::ScrapeJob::new(
            crawlx_core::scrape::JobKind::Scrape,
            options,
        ));
        let dir = tempfile::tempdir_in("/data").unwrap();
        assert!(
            common::authorization::run_authorized_local(crawl, config(dir.path()))
                .await
                .is_err()
        );
    }
    let mut session = request(&site, "/source");
    session.roles.push(crawlx_core::config::Role {
        name: "member".into(),
        credential_ref: None,
        login_plan: Some("builtin:form".into()),
        replica_base_url: None,
    });
    let dir = tempfile::tempdir_in("/data").unwrap();
    assert!(
        common::authorization::run_authorized_local(session, config(dir.path()))
            .await
            .is_err()
    );
    let mut browser = request(&site, "/source");
    browser.acquisition.as_mut().unwrap().backend_ids = vec!["native_browser".into()];
    assert!(
        common::authorization::run_authorized_local(browser, config(dir.path()))
            .await
            .is_err()
    );
    let mut delegate = request(&site, "/source");
    delegate.protocol.routes.push(
        serde_json::from_value(serde_json::json!({
            "id":"denied-delegate","schemes":["http"],"origin":null,"pathPattern":null,
            "schedulerMetadata":{},"backend":"delegate","delegateId":"owned-unconfigured",
            "requiredCapabilities":[],"maxBodyBytes":1024,"maxElapsedMs":1000,"policyRevision":"owned-v1"
        }))
        .unwrap(),
    );
    assert!(
        common::authorization::run_authorized_local(delegate, config(dir.path()))
            .await
            .is_err()
    );
    assert!(site.state.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn target_404_publishes_initial_and_selected_failure_facts_not_a_success_page() {
    let site = site().await;
    site.set("/source", refresh("/missing", "0"));
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(request(&site, "/source"), config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert!(report.pages.is_empty());
    let events = stores.events.list_after(report.run_id, 0, 1000).await.unwrap();
    let failure = events.iter().find(|event| event.kind == "page.failed").unwrap();
    assert_eq!(failure.payload["reason"], "meta_refresh_failed");
    assert_eq!(failure.payload["cause"], "meta_refresh_target");
    assert_eq!(failure.payload["metaRefresh"]["initialStatus"], 200);
    assert_eq!(
        failure.payload["metaRefresh"]["initialUrl"],
        site.url("/source").as_str()
    );
    assert_eq!(failure.payload["metaRefresh"]["selectedStatus"], 404);
    assert_eq!(
        failure.payload["metaRefresh"]["selectedUrl"],
        site.url("/missing").as_str()
    );
}

#[tokio::test]
async fn static_scrape_consumer_selects_target_instead_of_composing_initial_html() {
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    let mut crawl = request(&site, "/source");
    crawl.scrape = Some(crawlx_core::scrape::ScrapeJob::new(
        crawlx_core::scrape::JobKind::Scrape,
        crawlx_core::scrape::ScrapeOptions::default(),
    ));
    let report = run(crawl).await;
    assert_eq!(report.pages.len(), 1);
    assert_eq!(report.pages[0].url.url, site.url("/source"));
    assert_eq!(report.pages[0].title.as_deref(), Some("Selected final"));
    assert_eq!(
        report.pages[0].metadata["acquisition"]["metaRefresh"]["selectedStatus"],
        200
    );
    assert_eq!(site.count("/source"), 1);
    assert_eq!(site.count("/final"), 1);
}

#[tokio::test]
async fn private_target_listener_receives_no_connection_outside_authorized_network() {
    let source = site().await;
    let target = site_on("127.0.0.2").await;
    source.set("/source", refresh(target.url("/final").as_str(), "0"));
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = request(&source, "/source");
    crawl.scope.host_scope = crawlx_core::config::HostScope::None;
    let mut record = common::authorization::verified_record(&crawl, stores.tenant);
    record.url_prefixes = vec![source.base.clone(), target.base.clone()];
    record.authorized_networks = vec!["127.0.0.1/32".parse().unwrap()];
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl, config_with_targets(dir.path(), &[&target]))
            .with_stores(stores)
            .with_authorization(record),
    )
    .await
    .unwrap();
    assert!(report.pages.is_empty());
    assert_eq!(source.count("/source"), 1);
    assert!(target.state.hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn continuation_admission_never_dispatches_a_differently_normalized_raw_url() {
    let site = site().await;
    site.set(
        "/robots.txt",
        Reply::html("User-agent: *\nDisallow: /final?token=\nDisallow: /effect\n"),
    );
    for (target, strip_all) in [
        ("/final?token=refresh_query_canary_8e4f", false),
        ("/effect?action=delete", true),
    ] {
        site.set("/source", refresh(target, "0"));
        let mut crawl = request(&site, "/source");
        if strip_all {
            crawl.scope.query_policy = crawlx_core::config::QueryPolicy::StripAll;
        }
        let report = run(crawl).await;
        assert!(report.pages.is_empty());
    }
    assert_eq!(site.count("/final"), 0);
    assert_eq!(site.count("/effect"), 0);
}

#[tokio::test]
async fn rejected_refresh_urls_do_not_persist_userinfo_or_session_query_values() {
    let site = site().await;
    let dir = tempfile::tempdir_in("/data").unwrap();
    for target in [
        format!(
            "http://owned-user:refresh_password_canary_810a@{}/final",
            site.url("/").host_str().unwrap()
        ),
        site.url("/final?sessionid=refresh_session_canary_992b")
            .to_string(),
    ] {
        site.set("/source", refresh(&target, "0"));
        let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let report = common::authorization::run_authorized_local_with(
            LocalRun::new(request(&site, "/source"), config(dir.path())).with_stores(stores.clone()),
        )
        .await
        .unwrap();
        assert!(report.pages.is_empty());
        let events = stores.events.list_after(report.run_id, 0, 1000).await.unwrap();
        let durable = serde_json::to_string(&events).unwrap();
        assert!(!durable.contains("refresh_password_canary_810a"));
        assert!(!durable.contains("refresh_session_canary_992b"));
        assert!(!durable.contains("owned-user"));
    }
    assert_eq!(site.count("/final"), 0);
}

#[tokio::test]
async fn continuation_cache_live_freshness_refuses_before_validator_or_redirect_traffic() {
    use crawlx_core::cache::{CacheFreshnessV1, CachePolicyV1};
    let site = site().await;
    site.set("/source", refresh("/final", "0"));
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = request(&site, "/source");
    crawl.cache = Some(CachePolicyV1::default());
    crawl.cache_principal = Some(uuid::Uuid::from_u128(30_301));
    let saved = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl.clone(), config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(saved.pages.len(), 1);
    site.set("/source", Reply::redirect("/robots-private"));
    let before = site.state.hits.lock().unwrap().len();
    for freshness in [CacheFreshnessV1::Head, CacheFreshnessV1::ConditionalGet] {
        crawl.cache.as_mut().unwrap().freshness = freshness;
        let result = common::authorization::run_authorized_local_with(
            LocalRun::new(crawl.clone(), config(dir.path())).with_stores(stores.clone()),
        )
        .await;
        assert!(
            result.is_err(),
            "unsupported live freshness must refuse explicitly"
        );
        assert_eq!(site.state.hits.lock().unwrap().len(), before);
    }
    assert_eq!(site.count("/robots-private"), 0);
}

#[tokio::test]
async fn conditional_not_modified_is_not_an_http_redirect_or_a_second_successful_target() {
    let site = site().await;
    let mut not_modified = Reply::redirect("/final");
    not_modified.status = StatusCode::NOT_MODIFIED;
    site.set("/not-modified", not_modified);
    site.set("/source", refresh("/not-modified", "0"));
    let report = run(request(&site, "/source")).await;
    assert!(report.pages.is_empty());
    assert_eq!(site.count("/final"), 0);
    assert_eq!(site.count("/not-modified"), 1);
}

#[tokio::test]
async fn exact_cap_chunk_error_cannot_select_initial_refresh_or_accept_final_target() {
    let site = site().await;
    for initial in [true, false] {
        let body = if initial {
            refresh("/final", "0").body
        } else {
            "<html><title>Incomplete selected target</title><main>Content</main></html>".into()
        };
        let mut exact = body;
        exact.push_str(&" ".repeat(1024 - exact.len()));
        site.set("/exact-cap-error", Reply::html(exact));
        if !initial {
            site.set("/source", refresh("/exact-cap-error", "0"));
        }
        let mut crawl = request(&site, if initial { "/exact-cap-error" } else { "/source" });
        crawl.fetch.max_response_bytes = 1024;
        let before = site.count("/final");
        let report = run(crawl).await;
        assert!(report.pages.is_empty());
        assert_eq!(site.count("/final"), before);
    }
}

#[tokio::test]
async fn exhausted_parent_allowances_deny_uncached_new_origin_robots_before_connection() {
    for limit in ["attempt", "request", "bytes"] {
        let source = site().await;
        let target = site().await;
        let initial = refresh(target.url("/final").as_str(), "0");
        let initial_len = initial.body.len();
        source.set("/source", initial);
        let mut crawl = request(&source, "/source");
        let policy = crawl.acquisition.as_mut().unwrap();
        match limit {
            "attempt" => policy.max_attempts = 1,
            "request" => policy.max_network_requests = 1,
            _ => policy.max_decoded_bytes = u64::try_from(initial_len).unwrap(),
        }
        assert!(
            run_with_targets(crawl, &[&target]).await.pages.is_empty(),
            "{limit}"
        );
        assert_eq!(source.count("/source"), 1);
        assert!(target.state.hits.lock().unwrap().is_empty(), "{limit}");
    }
}

#[tokio::test]
async fn new_origin_robots_consumes_parent_allowances_before_target_dispatch() {
    const ROBOTS: &str = "User-agent: *\nDisallow: /robots-private\n";
    for limit in ["attempt", "request", "bytes", "success"] {
        let source = site().await;
        let target = site().await;
        let initial = refresh(target.url("/final").as_str(), "0");
        let initial_len = initial.body.len();
        source.set("/source", initial);
        let mut crawl = request(&source, "/source");
        let policy = crawl.acquisition.as_mut().unwrap();
        match limit {
            "attempt" => policy.max_attempts = 2,
            "request" => policy.max_network_requests = 2,
            "bytes" => policy.max_decoded_bytes = u64::try_from(initial_len + ROBOTS.len()).unwrap(),
            _ => {
                policy.max_attempts = 3;
                policy.max_network_requests = 3;
            }
        }
        let report = run_with_targets(crawl, &[&target]).await;
        assert_eq!(target.count("/robots.txt"), 1, "{limit}");
        if limit == "success" {
            assert_eq!(target.count("/final"), 1);
            assert_eq!(report.pages[0].title.as_deref(), Some("Selected final"));
            assert_eq!(report.pages[0].metadata["acquisition"]["attempts"], 3);
            assert_eq!(report.pages[0].metadata["acquisition"]["networkRequests"], 3);
        } else {
            assert!(report.pages.is_empty(), "{limit}");
            assert_eq!(target.count("/final"), 0, "{limit}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaced_parent_fence_during_uncached_robots_cannot_dispatch_selected_target() {
    use crawlx_core::Clock as _;
    let source = site().await;
    let target = site().await;
    source.set("/source", refresh(target.url("/final").as_str(), "0"));
    let mut parked = Reply::html("User-agent: *\nAllow: /\n");
    parked.park = true;
    target.set("/robots.txt", parked);
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let local = LocalRun::new(
        request(&source, "/source"),
        config_with_targets(dir.path(), &[&target]),
    )
    .with_stores(stores.clone());
    let task = tokio::spawn(common::authorization::run_authorized_local_with(local));
    tokio::time::timeout(Duration::from_secs(10), target.state.parked.notified())
        .await
        .unwrap();
    let reaped = stores
        .leases
        .reap_frontier(crawlx_core::SystemClock.now() + chrono::Duration::hours(1), 5)
        .await
        .unwrap();
    assert_eq!(reaped.requeued, 1);
    target.state.release.notify_waiters();
    let _ = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source.count("/source"), 1);
    assert_eq!(target.count("/robots.txt"), 1);
    assert_eq!(target.count("/final"), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaced_parent_fence_cancels_target_waiting_for_origin_governor() {
    use crawlx_core::Clock as _;
    let source = site().await;
    let target = site().await;
    source.set("/source", refresh(target.url("/final").as_str(), "0"));
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = request(&source, "/source");
    crawl.politeness.delay_ms = 1000;
    let task = tokio::spawn(common::authorization::run_authorized_local_with(
        LocalRun::new(crawl, config_with_targets(dir.path(), &[&target])).with_stores(stores.clone()),
    ));
    tokio::time::timeout(Duration::from_secs(10), target.state.robots_served.notified())
        .await
        .unwrap();
    // The fresh target's next request waits behind its just-completed robots request.
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(target.count("/final"), 0);
    assert_eq!(
        stores
            .leases
            .reap_frontier(crawlx_core::SystemClock.now() + chrono::Duration::hours(1), 5)
            .await
            .unwrap()
            .requeued,
        1
    );
    let _ = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(source.count("/source"), 1);
    assert_eq!(target.count("/robots.txt"), 1);
    assert_eq!(target.count("/final"), 0);
}

#[tokio::test]
async fn completed_short_governor_wait_rechecks_original_parent_fence_before_dispatch() {
    use crawlx_core::Clock as _;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Pause at the fourth DNS lookup: source robots, source, target robots, target.
    // The target has passed coordinator admission but has not entered its 80 ms
    // governor wait. Keeping time below 100 ms prevents the watcher masking a send.
    struct DispatchResolver {
        lookups: AtomicUsize,
        target_ready: Notify,
    }
    #[async_trait::async_trait]
    impl crawlx_fetch::Resolver for DispatchResolver {
        async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, crawlx_fetch::FetchError> {
            assert_eq!(host, "dispatch.fixture.test");
            if self.lookups.fetch_add(1, Ordering::SeqCst) == 3 {
                tokio::time::pause();
                self.target_ready.notify_one();
            }
            Ok(vec![std::net::IpAddr::from([127, 0, 0, 1])])
        }
    }

    for replace_fence in [false, true] {
        let mut source = site().await;
        let mut target = site().await;
        source.base = source.base.replace("127.0.0.1", "dispatch.fixture.test");
        target.base = target.base.replace("127.0.0.1", "dispatch.fixture.test");
        source.set("/source", refresh(target.url("/final").as_str(), "0"));
        let dir = tempfile::tempdir_in("/data").unwrap();
        let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let resolver = Arc::new(DispatchResolver {
            lookups: AtomicUsize::new(0),
            target_ready: Notify::new(),
        });
        let mut cfg = config_with_targets(dir.path(), &[&target]);
        cfg.egress.resolver = Some(resolver.clone());
        let mut crawl = request(&source, "/source");
        crawl.politeness.delay_ms = 80;
        let mut record = common::authorization::verified_record(&crawl, stores.tenant);
        // The shared helper authorizes literal loopback URLs. This fixture needs
        // an owned DNS name to stop immediately before the governor wait.
        record.url_prefixes = vec!["http://dispatch.fixture.test".into()];
        let mut task = tokio::spawn(common::authorization::run_authorized_local_with(
            LocalRun::new(crawl, cfg)
                .with_stores(stores.clone())
                .with_authorization(record),
        ));
        tokio::select! {
            result = &mut task => {
                let report = result.unwrap().unwrap();
                let events = stores.events.list_after(report.run_id, 0, 1000).await.unwrap();
                panic!(
                    "run ended before target governor: lookups={}, source={}, target_robots={}, events={:?}",
                    resolver.lookups.load(Ordering::SeqCst),
                    source.count("/source"),
                    target.count("/robots.txt"),
                    events.iter().map(|event| (&event.kind, &event.payload)).collect::<Vec<_>>(),
                );
            }
            ready = tokio::time::timeout(Duration::from_secs(10), resolver.target_ready.notified()) =>
                ready.unwrap(),
        }
        assert_eq!(source.count("/source"), 1);
        assert_eq!(target.count("/robots.txt"), 1);
        assert_eq!(target.count("/final"), 0);
        if replace_fence {
            assert_eq!(
                stores
                    .leases
                    .reap_frontier(crawlx_core::SystemClock.now() + chrono::Duration::hours(1), 5)
                    .await
                    .unwrap()
                    .requeued,
                1
            );
        }
        tokio::time::advance(Duration::from_millis(80)).await;
        // Remain runnable while loopback I/O drains, so Tokio cannot auto-advance
        // to the 100 ms watcher. The live-fence control proves this releases dispatch.
        let drained_until = Instant::now() + Duration::from_millis(250);
        while Instant::now() < drained_until && !task.is_finished() {
            tokio::task::yield_now().await;
        }
        let target_count = target.count("/final");
        tokio::time::resume();
        let _ = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            target_count,
            usize::from(!replace_fence),
            "replaced={replace_fence}"
        );
        assert_eq!(target.count("/final"), usize::from(!replace_fence));
        assert_eq!(source.count("/source"), 1, "parent acquisition must not restart");
        assert_eq!(target.count("/robots.txt"), 1);
    }
}

#[tokio::test]
async fn uncached_continuation_robots_obeys_parent_cancellation_and_deadline() {
    for cause in ["cancel", "deadline"] {
        let source = site().await;
        let target = site().await;
        source.set("/source", refresh(target.url("/final").as_str(), "0"));
        let mut parked = Reply::html("User-agent: *\nAllow: /\n");
        parked.park = true;
        target.set("/robots.txt", parked);
        let dir = tempfile::tempdir_in("/data").unwrap();
        let mut crawl = request(&source, "/source");
        if cause == "deadline" {
            crawl.acquisition.as_mut().unwrap().max_elapsed_ms = 500;
        }
        let cancel = CancellationToken::new();
        let local =
            LocalRun::new(crawl, config_with_targets(dir.path(), &[&target])).with_cancel(cancel.clone());
        let task = tokio::spawn(common::authorization::run_authorized_local_with(local));
        tokio::time::timeout(Duration::from_secs(10), target.state.parked.notified())
            .await
            .unwrap();
        if cause == "cancel" {
            cancel.cancel();
        }
        let report = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(report.pages.is_empty(), "{cause}");
        assert_eq!(target.count("/robots.txt"), 1);
        assert_eq!(target.count("/final"), 0);
    }
}

#[tokio::test]
async fn static_scrape_failure_keeps_selected_continuation_facts_in_consumer_event() {
    let site = site().await;
    site.set("/source", refresh("/missing", "0"));
    let dir = tempfile::tempdir_in("/data").unwrap();
    let stores = Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = request(&site, "/source");
    crawl.scrape = Some(crawlx_core::scrape::ScrapeJob::new(
        crawlx_core::scrape::JobKind::Scrape,
        crawlx_core::scrape::ScrapeOptions::default(),
    ));
    let report = common::authorization::run_authorized_local_with(
        LocalRun::new(crawl, config(dir.path())).with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert!(report.pages.is_empty());
    let events = stores.events.list_after(report.run_id, 0, 1000).await.unwrap();
    let failure = events.iter().find(|event| event.kind == "page.failed").unwrap();
    assert_eq!(failure.payload["metaRefresh"]["initialStatus"], 200);
    assert_eq!(failure.payload["metaRefresh"]["selectedStatus"], 404);
    assert_eq!(
        failure.payload["metaRefresh"]["selectedUrl"],
        site.url("/missing").as_str()
    );
}
