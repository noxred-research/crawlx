//! The static plane end to end against an in-process site.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::authorization::{run_authorized_local as run_local, run_authorized_local_with as run_local_with};
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{FrontierEntry, FrontierStatus};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};

fn config(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    }
}

fn static_crawl(base: &str) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_019);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c
}

async fn crawl(site: &common::site::Site, tweak: impl FnOnce(&mut CreateCrawl)) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let mut c = static_crawl(&site.base);
    tweak(&mut c);
    run_local(c, config(dir.path())).await.unwrap()
}

#[tokio::test]
async fn production_dispatch_records_bounded_worker_admission_before_leasing() {
    let site = common::site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut request = static_crawl(&site.base);
    request.politeness.max_concurrency = 1;
    let mut orchestration = crawlx_core::orchestration::OrchestrationConfigV1::default();
    orchestration.admission.mode = crawlx_core::runtime_admission::AdmissionModeV1::AdaptiveV1;
    request.orchestration = Some(orchestration);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(LocalRun::new(request, config(dir.path())).with_stores(stores.clone()))
        .await
        .unwrap();
    let events = stores.events.list_after(report.run_id, 0, 256).await.unwrap();
    let records: Vec<crawlx_core::runtime_admission::AdmissionRecordV1> = events
        .into_iter()
        .filter(|event| event.kind == "runtime.admission")
        .map(|event| serde_json::from_value(event.payload).unwrap())
        .collect();
    assert!(
        !records.is_empty(),
        "real URL dispatch must persist its admission decision"
    );
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.source_run, report.run_id);
        assert_eq!(record.decision.tick, u64::try_from(index).unwrap() + 1);
        assert_eq!(record.decision.hard_limit, 1);
        assert!(record.decision.ceiling <= 1);
        assert!(record.decision.pressure.spool_permille.is_some());
        assert_eq!(record.decision.pressure.store_available, Some(true));
    }
    assert!(report.counters.urls.invariants_hold());
}

#[tokio::test]
async fn python_source_429_returns_to_frontier_with_durable_effect_charge_then_succeeds() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = requests.clone();
    let app = Router::new().route("/", get(move || {
        let observed = observed.clone();
        async move {
            if observed.fetch_add(1, Ordering::Relaxed) == 0 {
                (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "0")], "slow down").into_response()
            } else {
                (StatusCode::OK, [(header::CONTENT_TYPE, "text/html")],
                    "<html><title>Ready</title><main><h1>Ready</h1><p>Rate limit cleared.</p></main></html>").into_response()
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let site = Counted {
        base,
        hits: Arc::new(Mutex::new(Vec::new())),
        task,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut request = static_crawl(&site.base);
    request.safety.respect_robots_txt = false;
    request.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    request.scope.max_discovery_depth = 0;
    let mut orchestration = crawlx_core::orchestration::OrchestrationConfigV1::default();
    orchestration.pacing_dialect = crawlx_core::runtime_admission::PacingDialectV1::CrawleePythonThrottleV1;
    request.orchestration = Some(orchestration);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        run_local_with(LocalRun::new(request, config(dir.path())).with_stores(stores.clone())),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(requests.load(Ordering::Relaxed), 2);
    assert_eq!(report.pages.len(), 1);
    assert_eq!(report.pages[0].title.as_deref(), Some("Ready"));
    let events = stores.events.list_after(report.run_id, 0, 256).await.unwrap();
    let cooldowns: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "request.rate_limited")
        .collect();
    assert_eq!(
        cooldowns.len(),
        1,
        "429 must escape the HTTP retry loop and release URL dispatch"
    );
    assert_eq!(cooldowns[0].payload["pending"], true);
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    let row = frontier.iter().find(|row| row.url.url.path() == "/").unwrap();
    assert_eq!(row.attempts, 2, "real attempts remain charged across cooldown");
}

fn paths(r: &RunReport) -> Vec<String> {
    let mut v: Vec<String> = r.pages.iter().map(|p| p.url.url.path().to_owned()).collect();
    v.sort();
    v
}

#[tokio::test]
async fn static_crawl_matches_the_fixture_counters_and_invariants() {
    let site = common::site::start().await;
    let report = crawl(&site, |_| {}).await;
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.terminal_reason, Some(TerminalReason::FrontierExhausted));
    let u = report.counters.urls;
    assert_eq!(
        (
            u.discovered,
            u.admitted,
            u.deduplicated,
            u.policy_blocked,
            u.robots_blocked
        ),
        (13, 5, 6, 1, 1),
        "{u:?}"
    );
    assert_eq!(
        (
            u.attempted,
            u.succeeded,
            u.failed,
            u.abandoned,
            u.unreachable,
            u.unknown_outcome
        ),
        (5, 4, 1, 0, 0, 0)
    );
    assert!(u.invariants_hold());
    assert!(report.counters.interactions.invariants_hold() && report.counters.states.invariants_hold());
    assert_eq!(paths(&report), vec!["/", "/a", "/b", "/c"]);
    // pages carry markdown artifacts and links
    let home = report.pages.iter().find(|p| p.url.url.path() == "/").unwrap();
    assert_eq!(home.title.as_deref(), Some("Home"));
    assert!(home.links.iter().any(|l| l.ends_with("/a")));
    let md = report
        .page_contents
        .iter()
        .find(|c| c.url.ends_with('/'))
        .unwrap()
        .markdown
        .clone()
        .unwrap();
    assert!(md.contains("Welcome to the fixture site."), "{md}");
    // the robots-blocked and external URLs were never fetched
    assert!(report
        .pages
        .iter()
        .all(|p| !p.url.url.path().starts_with("/private")));
}

#[tokio::test]
async fn reruns_with_the_same_seed_give_identical_page_sets() {
    let site = common::site::start().await;
    let a = crawl(&site, |_| {}).await;
    let b = crawl(&site, |_| {}).await;
    assert_eq!(paths(&a), paths(&b));
    assert_eq!(a.counters, b.counters);
}

#[tokio::test]
async fn the_url_limit_stops_the_run_with_limit_reached() {
    let site = common::site::start().await;
    let report = crawl(&site, |c| c.limits.urls = 2).await;
    assert_eq!(report.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(report.counters.urls.attempted, 2);
    assert!(report.counters.urls.invariants_hold());
    assert_eq!(report.pages.len(), 2);
}

#[tokio::test]
async fn ignoring_robots_requires_nothing_here_but_fetches_the_blocked_path() {
    let site = common::site::start().await;
    let report = crawl(&site, |c| c.safety.respect_robots_txt = false).await;
    assert_eq!(report.counters.urls.robots_blocked, 0);
    assert!(report.pages.iter().any(|p| p.url.url.path() == "/private/secret"));
    assert!(report.counters.urls.invariants_hold());
}

#[tokio::test]
async fn depth_zero_discovers_links_but_fetches_only_the_seed() {
    let site = common::site::start().await;
    let report = crawl(&site, |c| {
        c.scope.max_discovery_depth = 0;
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    })
    .await;
    // links of the seed are at depth 1 > 0: all policy-blocked (or robots-blocked), only the seed is attempted
    assert_eq!(report.counters.urls.attempted, 1);
    assert_eq!(report.pages.len(), 1);
    assert!(report.counters.urls.policy_blocked >= 3);
    assert!(report.counters.urls.invariants_hold());
}

/// A site that counts every request it serves. `/` links to `/docs/a` and `/blog/b`; `/docs/a`
/// links back to `/` and on to `/blog/b`; `/blog/b` is a leaf. `robots` is its `robots.txt`.
struct Counted {
    base: String,
    hits: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Counted {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Counted {
    fn count(&self, path: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| *p == path).count()
    }
}

async fn count_hit(
    State(hits): State<Arc<Mutex<Vec<String>>>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.lock().unwrap().push(req.uri().path().to_owned());
    next.run(req).await
}

async fn counted_site(robots: &'static str) -> Counted {
    fn page(title: &str, links: &str) -> axum::response::Response {
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            format!(
                "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>The {title} page.</p>{links}</main></body></html>"
            ),
        )
            .into_response()
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route(
            "/",
            get(|| async { page("Home", r#"<a href="/docs/a">A</a> <a href="/blog/b">B</a>"#) }),
        )
        .route(
            "/docs/a",
            get(|| async { page("Docs A", r#"<a href="/">Home</a> <a href="/blog/b">B</a>"#) }),
        )
        .route("/blog/b", get(|| async { page("Blog B", "") }))
        .route("/robots.txt", get(move || async move { robots }))
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), count_hit));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Counted { base, hits, task }
}

/// Run a crawl of `site` with the in-memory stores kept, to read the frontier afterwards.
async fn crawl_with_frontier(
    site: &Counted,
    tweak: impl FnOnce(&mut CreateCrawl),
) -> (RunReport, Vec<FrontierEntry>) {
    let dir = tempfile::tempdir().unwrap();
    let mut c = static_crawl(&site.base);
    tweak(&mut c);
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(LocalRun::new(c, config(dir.path())).with_stores(stores.clone()))
        .await
        .unwrap();
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    (report, frontier)
}

fn row<'a>(frontier: &'a [FrontierEntry], path: &str) -> &'a FrontierEntry {
    frontier
        .iter()
        .find(|e| e.url.url.path() == path)
        .unwrap_or_else(|| panic!("no frontier row for {path}"))
}

/// The entry URL outside `includePaths` is fetched once, to start discovery: its matching links
/// are crawled, it is not a page, and it ends `policy_blocked` `not_included` (the accounting of a
/// denied seed: discovered and policy-blocked, never attempted).
#[tokio::test]
async fn an_entry_url_outside_include_paths_is_fetched_once_for_discovery_only() {
    let site = counted_site("User-agent: *\nAllow: /\n").await;
    let (report, frontier) = crawl_with_frontier(&site, |c| {
        c.scope.include_paths = vec!["^/docs/".to_owned()];
    })
    .await;
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(paths(&report), ["/docs/a"]);
    assert_eq!(site.count("/"), 1, "the entry URL is fetched exactly once");
    assert_eq!(site.count("/docs/a"), 1);
    assert_eq!(site.count("/blog/b"), 0, "outside includePaths: never fetched");

    let seed = row(&frontier, "/");
    assert_eq!(seed.depth, 0);
    assert_eq!(seed.status, FrontierStatus::PolicyBlocked);
    assert_eq!(seed.denial_reason.as_deref(), Some("not_included"));
    let blog = row(&frontier, "/blog/b");
    assert_eq!(blog.status, FrontierStatus::PolicyBlocked);
    assert_eq!(blog.denial_reason.as_deref(), Some("not_included"));
    assert_eq!(row(&frontier, "/docs/a").status, FrontierStatus::Succeeded);

    let u = report.counters.urls;
    assert_eq!(
        (u.admitted, u.attempted, u.succeeded, u.failed, u.policy_blocked),
        (1, 1, 1, 0, 2),
        "{u:?}"
    );
    assert!(u.invariants_hold(), "{u:?}");
}

/// `urlInclude` (the `regexOnFullURL` form of `includePaths`) exempts the entry URL the same way.
#[tokio::test]
async fn an_entry_url_outside_url_include_is_fetched_once_for_discovery_only() {
    let site = counted_site("").await;
    let (report, frontier) = crawl_with_frontier(&site, |c| {
        c.scope.url_include = vec![format!("^{}/docs/", site.base.replace('.', "\\."))];
    })
    .await;
    assert_eq!(paths(&report), ["/docs/a"]);
    assert_eq!(site.count("/"), 1);
    assert_eq!(site.count("/blog/b"), 0);
    let seed = row(&frontier, "/");
    assert_eq!(seed.status, FrontierStatus::PolicyBlocked);
    assert_eq!(seed.denial_reason.as_deref(), Some("url_not_included"));
    assert_eq!(
        row(&frontier, "/blog/b").denial_reason.as_deref(),
        Some("url_not_included")
    );
    assert!(report.counters.urls.invariants_hold());
}

/// Only the include filters are lifted for the entry URL: an excluded or robots-blocked one stays
/// out of the crawl, and nothing is fetched from it.
#[tokio::test]
async fn an_excluded_or_robots_blocked_entry_url_is_still_denied() {
    let site = counted_site("").await;
    let (report, frontier) = crawl_with_frontier(&site, |c| {
        c.scope.include_paths = vec!["^/docs/".to_owned()];
        c.scope.exclude_paths = vec!["^/$".to_owned()];
    })
    .await;
    assert!(report.pages.is_empty(), "{:?}", paths(&report));
    assert_eq!(site.count("/"), 0);
    let seed = row(&frontier, "/");
    assert_eq!(seed.status, FrontierStatus::PolicyBlocked);
    assert_eq!(seed.denial_reason.as_deref(), Some("excluded_path:^/$"));

    let blocked = counted_site("User-agent: *\nDisallow: /\n").await;
    let (report, frontier) = crawl_with_frontier(&blocked, |c| {
        c.scope.include_paths = vec!["^/docs/".to_owned()];
    })
    .await;
    assert!(report.pages.is_empty(), "{:?}", paths(&report));
    assert_eq!(blocked.count("/"), 0);
    let seed = row(&frontier, "/");
    assert_eq!(seed.status, FrontierStatus::RobotsBlocked);
    assert_eq!(seed.denial_reason.as_deref(), Some("robots_disallow"));
}

/// The discovery fetch is not a page: it does not spend `limits.urls`, so a one-URL budget still
/// crawls one matching page.
#[tokio::test]
async fn the_discovery_fetch_of_the_entry_url_spends_no_url_budget() {
    let site = counted_site("").await;
    let (report, _) = crawl_with_frontier(&site, |c| {
        c.scope.include_paths = vec!["^/docs/".to_owned()];
        c.limits.urls = 1;
    })
    .await;
    assert_eq!(paths(&report), ["/docs/a"]);
    assert_eq!(site.count("/blog/b"), 0);
}

/// The `crawlx.urls.*` counters grow by the run's own counters (the registry is
/// process-global and the other tests of this binary crawl concurrently, so the deltas are
/// lower bounds), and the frontier depth gauge is set for the static plane.
#[tokio::test]
async fn the_static_plane_emits_the_url_metrics() {
    let site = common::site::start().await;
    let m = Metrics::global();
    let urls = &[("plane", "urls")];
    let read = || {
        (
            m.counter(names::URLS_DISCOVERED).get(urls),
            m.counter(names::URLS_ADMITTED).get(urls),
            m.counter(names::URLS_DEDUPLICATED).get(urls),
            m.counter(names::URLS_ATTEMPTED).get(urls),
            m.counter(names::URLS_SUCCEEDED).get(urls),
            m.counter(names::URLS_FAILED)
                .get(&[("plane", "urls"), ("reason", "http_4xx")]),
            m.counter(names::URLS_ROBOTS_BLOCKED).get(urls),
        )
    };
    let before = read();
    let report = crawl(&site, |_| {}).await;
    let after = read();
    let u = report.counters.urls;
    assert_eq!(report.status, RunStatus::Completed);
    assert!(
        after.0 - before.0 >= u.discovered,
        "discovered {before:?} -> {after:?} vs {u:?}"
    );
    assert!(after.1 - before.1 >= u.admitted, "admitted");
    assert!(after.2 - before.2 >= u.deduplicated, "deduplicated");
    assert!(after.3 - before.3 >= u.attempted, "attempted");
    assert!(after.4 - before.4 >= u.succeeded, "succeeded");
    assert!(after.5 - before.5 >= u.failed, "failed{{reason=http_4xx}}");
    assert!(after.6 - before.6 >= u.robots_blocked, "robots_blocked");
    assert!(
        m.gauge(names::FRONTIER_DEPTH).get(urls).is_some(),
        "frontier depth is set for the urls plane"
    );
    assert_eq!(
        m.counter(names::URLS_DISCOVERED).get(&[("plane", "nope")]),
        0,
        "unknown planes never get a series"
    );
}
