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
    let tasks: Vec<_> = events
        .iter()
        .filter(|event| event.kind == "runtime.task")
        .collect();
    assert!(
        !tasks.is_empty(),
        "each admitted URL task must record bounded resource observations"
    );
    for task in tasks {
        assert_eq!(task.payload["version"], 1);
        assert!(task.payload["elapsed_ms"].as_u64().is_some());
        assert!(task.payload["frontier_id"].as_i64().is_some());
        for key in ["process_rss_before_bytes", "process_rss_after_bytes"] {
            assert!(task.payload[key].is_null() || task.payload[key].as_u64().is_some());
        }
    }
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
        assert!(record.decision.pressure.event_loop_lag_ms.is_some());
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
    orchestration.pacing_dialect =
        crawlx_core::runtime_admission::PacingDialectV1::AdaptiveConcurrencyThrottleV1;
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

/// Policy fixtures count methods separately so a refused HEAD cannot pass as a GET.
async fn acquisition_policy_site() -> Counted {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/robots.txt", get(|| async { "" }))
        .route(
            "/preflight",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html><title>GET must not run</title><body>Refused target.</body></html>",
                )
            })
            .head(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "application/octet-stream"),
                        (header::CONTENT_LENGTH, "8192"),
                    ],
                    "",
                )
            }),
        )
        .route(
            "/declared",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                    "<html><head><title>Declared article</title></head><body><main>\
                     <h1>Declared article</h1><p>This article reaches HTML extraction only \
                     through the explicit response declaration.</p></main></body></html>",
                )
            }),
        )
        .route(
            "/oversize",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    format!(
                        "<html><title>Partial page must not persist</title><body><main><p>{}</p>\
                         </main></body></html>",
                        "Bounded article content. ".repeat(256),
                    ),
                )
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&hits),
            |State(hits): State<Arc<Mutex<Vec<String>>>>,
             req: axum::extract::Request,
             next: axum::middleware::Next| async move {
                hits.lock()
                    .unwrap()
                    .push(format!("{} {}", req.method(), req.uri().path()));
                next.run(req).await
            },
        ));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Counted { base, hits, task }
}

/// Acceptance #1: both HEAD refusal rules stop the target GET and persist failure.
#[tokio::test]
async fn acceptance_1_fetch_preflight_refusal_prevents_target_get() {
    let site = acquisition_policy_site().await;
    for (max_content_length, content_types) in
        [(Some(1024), Vec::new()), (None, vec!["text/html".to_owned()])]
    {
        let heads_before = site.count("HEAD /preflight");
        let (report, frontier) = crawl_with_frontier(&site, |crawl| {
            crawl.seed_url = url::Url::parse(&format!("{}/preflight", site.base)).unwrap();
            crawl.fetch.retries = 0;
            let mut preflight = crawlx_core::acquisition::HeadPreflight::default();
            preflight.max_content_length = max_content_length;
            preflight.content_types = content_types;
            crawl.fetch.preflight = Some(preflight);
        })
        .await;

        assert_eq!(report.status, RunStatus::Completed);
        assert_eq!(site.count("HEAD /preflight"), heads_before + 1);
        assert_eq!(site.count("GET /preflight"), 0);
        assert!(report.pages.is_empty());
        assert!(report.page_contents.is_empty());
        assert_eq!(report.counters.urls.attempted, 1);
        assert_eq!(report.counters.urls.failed, 1);
        assert_eq!(report.counters.urls.succeeded, 0);
        assert_eq!(report.failures.len(), 1);
        assert_eq!(report.failures[0].reason, "preflight_refused");
        let target = row(&frontier, "/preflight");
        assert_eq!(target.status, FrontierStatus::Failed);
        assert_eq!(target.denial_reason.as_deref(), Some("preflight_refused"));
    }
}

/// Acceptance #2: the declared MIME type, not the plain wire type, selects HTML extraction.
#[tokio::test]
async fn acceptance_2_response_declaration_routes_plain_response_to_html_extraction() {
    let site = acquisition_policy_site().await;
    let (ordinary, _) = crawl_with_frontier(&site, |crawl| {
        crawl.seed_url = url::Url::parse(&format!("{}/declared", site.base)).unwrap();
    })
    .await;
    assert_eq!(ordinary.pages.len(), 1);
    assert_eq!(ordinary.pages[0].title, None);

    let (declared, frontier) = crawl_with_frontier(&site, |crawl| {
        crawl.seed_url = url::Url::parse(&format!("{}/declared", site.base)).unwrap();
        let mut declaration = crawlx_core::acquisition::ResponseDeclaration::default();
        declaration.content_type = Some("text/html".to_owned());
        declaration.charset = Some("utf-8".to_owned());
        crawl.fetch.declaration = Some(declaration);
    })
    .await;

    assert_eq!(declared.status, RunStatus::Completed);
    assert_eq!(declared.pages.len(), 1);
    assert_eq!(declared.pages[0].title.as_deref(), Some("Declared article"));
    let markdown = declared.page_contents[0].markdown.as_deref().unwrap();
    assert!(
        markdown.contains("through the explicit response declaration."),
        "{markdown}"
    );
    assert!(!markdown.contains("<main>"), "{markdown}");
    assert_eq!(declared.counters.urls.succeeded, 1);
    assert_eq!(declared.counters.urls.failed, 0);
    assert_eq!(row(&frontier, "/declared").status, FrontierStatus::Succeeded);
    assert_eq!(site.count("GET /declared"), 2);
    assert_eq!(site.count("HEAD /declared"), 0);
}

/// Acceptance #2: refusing an oversized body produces no partial extracted page.
#[tokio::test]
async fn acceptance_2_oversize_refusal_fails_without_persisting_partial_page() {
    let site = acquisition_policy_site().await;
    let (report, frontier) = crawl_with_frontier(&site, |crawl| {
        crawl.seed_url = url::Url::parse(&format!("{}/oversize", site.base)).unwrap();
        crawl.fetch.max_response_bytes = 1024;
        crawl.fetch.retries = 0;
        crawl.fetch.oversize = Some(crawlx_core::acquisition::OversizePolicy::Refuse);
    })
    .await;

    assert_eq!(site.count("GET /oversize"), 1);
    assert_eq!(site.count("HEAD /oversize"), 0);
    assert!(report.pages.is_empty());
    assert!(report.page_contents.is_empty());
    assert_eq!(report.counters.urls.attempted, 1);
    assert_eq!(report.counters.urls.failed, 1);
    assert_eq!(report.counters.urls.succeeded, 0);
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].reason, "body_limit");
    let target = row(&frontier, "/oversize");
    assert_eq!(target.status, FrontierStatus::Failed);
    assert_eq!(target.denial_reason.as_deref(), Some("body_limit"));
}

#[tokio::test]
async fn extraction_url_exclusion_blocks_target_and_robots_before_any_request() {
    for use_pattern in [false, true] {
        let site = counted_site("").await;
        let (report, frontier) = crawl_with_frontier(&site, |crawl| {
            let mut exclusions = crawlx_core::extraction::UrlExclusionPolicyV1::default();
            if use_pattern {
                exclusions.patterns = vec![r"^http://127\.0\.0\.1:[0-9]+/$".to_owned()];
            } else {
                exclusions.substrings = vec![site.base.to_ascii_uppercase()];
            }
            let mut content = crawlx_core::extraction::ExtractionPolicyV1::default();
            content.excluded_urls = Some(exclusions);
            crawl.extract.content = Some(content);
        })
        .await;

        assert!(site.hits.lock().unwrap().is_empty());
        assert_eq!(site.count("/"), 0);
        assert_eq!(site.count("/robots.txt"), 0);
        assert!(report.pages.is_empty());
        assert_eq!(report.counters.urls.policy_blocked, 1);
        assert_eq!(report.counters.urls.attempted, 0);
        let seed = row(&frontier, "/");
        assert_eq!(seed.status, FrontierStatus::PolicyBlocked);
        assert_eq!(seed.denial_reason.as_deref(), Some("url_excluded"));
    }
}

#[tokio::test]
async fn selected_ast_mode_persists_bounded_unresolved_endpoint_outcomes() {
    use crawlx_extract::endpoints::{ScriptOrigin, UnresolvedEndpoint, UnresolvedKind};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let script = "fetch(runtimeEndpoint);".repeat(1003);
    let script_bytes = u32::try_from(script.len()).unwrap();
    let body = format!(
        "<html><head><title>Unresolved endpoints</title></head><body><main>\
         <p>Static analysis must not evaluate dynamic request expressions.</p></main>\
         <script>{script}</script></body></html>"
    );
    let app = Router::new()
        .route(
            "/",
            get(move || async move { ([(header::CONTENT_TYPE, "text/html")], body) }),
        )
        .route("/robots.txt", get(|| async { "" }))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), count_hit));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let site = Counted { base, hits, task };
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = static_crawl(&site.base);
    crawl.extract.javascript.mode = crawlx_core::config::JavascriptMode::Ast;
    crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    let report = run_local_with(LocalRun::new(crawl, config(dir.path())).with_stores(stores.clone()))
        .await
        .unwrap();

    assert_eq!(report.browser_launches, 0);
    assert_eq!(report.pages.len(), 1);
    let persisted = stores.pages.list(report.run_id).await.unwrap();
    assert_eq!(persisted.len(), 1);
    let discovery = &persisted[0].metadata["endpointDiscovery"];
    assert_eq!(*discovery, report.pages[0].metadata["endpointDiscovery"]);
    assert_eq!(discovery["unresolvedDropped"], 3);
    let unresolved = discovery["unresolved"].as_array().unwrap();
    assert_eq!(unresolved.len(), 1000);
    for value in unresolved {
        let object = value.as_object().unwrap();
        assert_eq!(object.len(), 7, "{value}");
        let outcome: UnresolvedEndpoint = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(outcome.kind, UnresolvedKind::Variable);
        assert_eq!(outcome.origin, ScriptOrigin::InlineScript);
        assert_eq!(outcome.method, http::Method::GET);
        assert_eq!(outcome.depth, 1);
        assert!(!outcome.partial);
        assert!(outcome.span.start < outcome.span.end);
        assert!(outcome.span.end <= script_bytes);
    }
    assert!(!discovery.to_string().contains("runtimeEndpoint"));
    assert_eq!(site.count("/"), 1);
    assert_eq!(site.count("/robots.txt"), 1);
    assert_eq!(site.count("/sitemap.xml"), 0);
    assert_eq!(site.hits.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn duplicate_article_marks_second_url_without_crossing_runs_or_tenants() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let hits: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let article = || async {
        (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<html><head><title>Shared article</title></head><body>\
             <nav><a href=\"/article-b\">Second address</a></nav><main><article>\
             <h1>Shared article</h1><p>This substantial article has identical main content \
             at both addresses. Its distinct acquisitions must remain visible, while \
             ingestion rejects the repeated normalized title and body.</p>\
             <p>Each crawl owns its content admission cache. Neither later runs nor \
             another tenant may inherit the earlier admission decision.</p>\
             </article></main></body></html>",
        )
    };
    let app = Router::new()
        .route("/article-a", get(article))
        .route("/article-b", get(article))
        .route("/robots.txt", get(|| async { "" }))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), count_hit));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let site = Counted { base, hits, task };
    let dir = tempfile::tempdir().unwrap();
    let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let original_tenant = stores.tenant;
    let mut prior_runs = Vec::new();
    for change_tenant in [false, false, true] {
        if change_tenant {
            stores.tenant = crawlx_core::TenantId::new();
            assert_ne!(stores.tenant, original_tenant);
        } else {
            assert_eq!(stores.tenant, original_tenant);
        }
        let mut crawl = static_crawl(&site.base);
        crawl.seed_url = url::Url::parse(&format!("{}/article-a", site.base)).unwrap();
        // The duplicate lives beside the seed, not beneath its default path scope.
        crawl.scope.crawl_entire_domain = true;
        crawl.politeness.max_concurrency = 1;
        crawl.scope.disable_unique_filter = true;
        let mut dedupe = crawlx_core::extraction::DedupePolicyV1::default();
        dedupe.content = true;
        let mut content = crawlx_core::extraction::ExtractionPolicyV1::default();
        content.dedupe = Some(dedupe);
        crawl.extract.content = Some(content);
        let report = run_local_with(LocalRun::new(crawl, config(dir.path())).with_stores(stores.clone()))
            .await
            .unwrap();

        assert!(!prior_runs.contains(&report.run_id));
        prior_runs.push(report.run_id);
        assert_eq!(report.status, RunStatus::Completed);
        assert_eq!(report.counters.urls.succeeded, 2);
        assert_eq!(paths(&report), vec!["/article-a", "/article-b"]);
        let persisted = stores.pages.list(report.run_id).await.unwrap();
        assert_eq!(persisted.len(), 2);
        let frontier = stores.frontier.list(report.run_id).await.unwrap();
        for path in ["/article-a", "/article-b"] {
            let entry = frontier
                .iter()
                .find(|entry| entry.url.url.path() == path)
                .unwrap();
            assert_eq!(entry.status, FrontierStatus::Succeeded);
        }
        for (path, status, reasons) in [
            ("/article-a", "accepted", serde_json::json!([])),
            ("/article-b", "rejected", serde_json::json!(["duplicate_main"])),
        ] {
            let page = persisted.iter().find(|page| page.url.url.path() == path).unwrap();
            let quality = &page.metadata["extraction"]["quality"];
            assert_eq!(quality["status"], status, "{quality}");
            assert_eq!(quality["reasons"], reasons, "{quality}");
            assert!(quality["mainChars"].as_u64().unwrap() >= 40);
            assert_eq!(page.status, 200);
            assert!(!page.metadata["extraction"]["content"].is_null());
        }
    }
    assert_eq!(site.count("/article-a"), 3);
    assert_eq!(site.count("/article-b"), 3);
}

/// Dotted hosts exercise the preview target guard while all sockets stay on loopback.
async fn native_preview_site() -> Counted {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let base = format!("http://preview.example.test:{}", address.port());
    let hits = Arc::new(Mutex::new(Vec::new()));
    let source = format!(
        "<html><head><title>Preview source</title></head><body><main>\
         <p>Preview requests must use the guarded shared acquisition allowance.</p>\
         <a href='/preview'>Preview article</a>\
         <a href='http://{address}/refused'>Private literal target</a>\
         </main></body></html>"
    );
    let app = Router::new()
        .route(
            "/",
            get(move || async move { ([(header::CONTENT_TYPE, "text/html")], source) }),
        )
        .route(
            "/preview",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html lang='en'><head><title>Fulfilled preview</title>\
                     <meta name='description' content='Retained auxiliary head metadata'>\
                     <link rel='canonical' href='/preview-canonical'>\
                     <meta property='og:image' content='/preview-image.png'>\
                     <meta property='og:site_name' content='Preview fixture'>\
                     </head><body>Auxiliary representation.</body></html>",
                )
            }),
        )
        .route(
            "/entry",
            get(|| async { axum::response::Redirect::temporary("/article") }),
        )
        .route(
            "/article",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/html")],
                    "<html lang='en'><head><title>Retained primary head</title>\
                     <meta name='description' content='Already acquired primary representation'>\
                     <link rel='canonical' href='/article'>\
                     </head><body><main><p>The original URL previews this same representation \
                     after its redirect, without acquiring the primary document again.</p>\
                     <a href='/entry'>Original article address</a></main></body></html>",
                )
            }),
        )
        .route(
            "/refused",
            get(|| async { "<title>Private preview must never be fetched</title>" }),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "unexpected request") })
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), count_hit));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Counted { base, hits, task }
}

async fn run_native_previews(site: &Counted, path: &str) -> (RunReport, serde_json::Value) {
    use crawlx_extract::content_outputs::ContentOutputOptions;
    use crawlx_extract::link_media::LinkMediaOptions;

    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut request = static_crawl(&site.base);
    request.seed_url = url::Url::parse(&format!("{}{path}", site.base)).unwrap();
    request.scope.max_discovery_depth = 0;
    request.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    request.safety.respect_robots_txt = false;
    request.retention.mode = crawlx_core::config::RetentionMode::Standard;
    request.fetch.retries = 0;
    let mut link_media = LinkMediaOptions::with_previews(4);
    link_media.min_preview_score = 0;
    let mut outputs = ContentOutputOptions::default();
    outputs.link_media = Some(link_media);
    request.extract.outputs = Some(serde_json::to_value(outputs).unwrap());
    assert!(request.acquisition.is_none());
    assert!(request.scope.discovery.is_none());
    let mut cfg = config(dir.path());
    cfg.egress.resolver = Some(Arc::new(
        StaticResolver::new().with("preview.example.test", [std::net::IpAddr::from([127, 0, 0, 1])]),
    ));
    let mut authorization = common::authorization::verified_record(&request, stores.tenant);
    authorization.url_prefixes = vec![site.base.clone()];
    let report = run_local_with(
        LocalRun::new(request, cfg)
            .with_authorization(authorization)
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.browser_launches, 0);
    assert_eq!(report.pages.len(), 1);
    assert!(report.failures.is_empty());
    assert_eq!(report.counters.urls.attempted, 1);
    assert_eq!(report.counters.urls.succeeded, 1);
    assert!(report.counters.urls.invariants_hold());
    let persisted = stores.pages.list(report.run_id).await.unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].metadata, report.pages[0].metadata);
    let auxiliary = &persisted[0].metadata["discovery_auxiliary"];
    assert_eq!(auxiliary["count"], 1);
    assert_eq!(auxiliary.as_object().unwrap().len(), 2);
    assert!(auxiliary.get("head").is_none());
    let reference: crawlx_core::ArtifactRef = serde_json::from_value(auxiliary["content"].clone()).unwrap();
    let reports: serde_json::Value =
        serde_json::from_slice(&stores.artifacts.get(&reference).await.unwrap()).unwrap();
    assert_eq!(reports.as_array().unwrap().len(), 1);
    assert_eq!(reports[0]["purpose"], "preview");
    assert_eq!(reports[0]["status"], "fulfilled");
    (report, reports)
}

#[tokio::test]
async fn native_preview_without_acquisition_or_discovery_fetches_guarded_target_once() {
    let site = native_preview_site().await;
    let (report, previews) = run_native_previews(&site, "/").await;
    assert_eq!(site.count("/"), 1);
    assert_eq!(site.count("/preview"), 1);
    assert_eq!(site.count("/refused"), 0);
    assert_eq!(site.hits.lock().unwrap().len(), 2);
    assert!(report.pages[0]
        .links
        .iter()
        .any(|link| link.ends_with("/refused")));
    assert_eq!(report.pages[0].title.as_deref(), Some("Preview source"));
    let acquisition: crawlx_core::acquisition::AcquisitionResultV1 =
        serde_json::from_value(report.pages[0].metadata["acquisition"].clone()).unwrap();
    assert_eq!(acquisition.network_requests, 2, "primary plus auxiliary request");
    assert_eq!(acquisition.network_requests_observed, Some(2));
    assert_eq!(acquisition.allowance_usage.network_requests_reserved, 2);
    assert_eq!(acquisition.attempts, 2);
    let head = &previews[0]["head"];
    assert_eq!(head["url"], format!("{}/preview", site.base));
    assert_eq!(head["title"], "Fulfilled preview");
    assert_eq!(head["description"], "Retained auxiliary head metadata");
    assert_eq!(head["language"], "en");
    assert_eq!(head["canonicalUrl"], format!("{}/preview-canonical", site.base));
    assert_eq!(head["imageUrl"], format!("{}/preview-image.png", site.base));
    assert_eq!(head["siteName"], "Preview fixture");
    assert_eq!(head["truncated"], false);
    assert!(!report.pages[0]
        .metadata
        .to_string()
        .contains("Retained auxiliary head metadata"));
}

#[tokio::test]
async fn native_self_preview_reuses_redirected_primary_without_second_get() {
    let site = native_preview_site().await;
    // Exact final-URL self-links are not preview intents. The original redirect URL is an
    // intent, so this exercises the worker's primary-representation reuse path end to end.
    let (report, previews) = run_native_previews(&site, "/entry").await;
    assert_eq!(site.count("/entry"), 1);
    assert_eq!(site.count("/article"), 1);
    assert_eq!(site.count("/preview"), 0);
    assert_eq!(site.count("/refused"), 0);
    assert_eq!(site.hits.lock().unwrap().len(), 2);
    assert_eq!(
        report.pages[0].metadata["final_url"],
        format!("{}/article", site.base)
    );
    assert_eq!(report.pages[0].title.as_deref(), Some("Retained primary head"));
    let acquisition: crawlx_core::acquisition::AcquisitionResultV1 =
        serde_json::from_value(report.pages[0].metadata["acquisition"].clone()).unwrap();
    assert_eq!(
        acquisition.network_requests, 2,
        "only the original redirect and primary GET"
    );
    assert_eq!(acquisition.network_requests_observed, Some(2));
    assert_eq!(acquisition.allowance_usage.network_requests_reserved, 2);
    assert_eq!(
        acquisition.attempts, 1,
        "the redirect stays inside the primary attempt"
    );
    let head = &previews[0]["head"];
    assert_eq!(head["url"], format!("{}/entry", site.base));
    assert_eq!(head["title"], "Retained primary head");
    assert_eq!(head["description"], "Already acquired primary representation");
    assert_eq!(head["canonicalUrl"], format!("{}/article", site.base));
    assert_eq!(head["truncated"], false);
}

#[tokio::test]
async fn local_url_work_preserves_tenant_scope_after_spawning() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct ScopedResolver {
        tenant: crawlx_core::TenantId,
        inner: StaticResolver,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl crawlx_fetch::Resolver for ScopedResolver {
        async fn resolve(&self, host: &str) -> Result<Vec<std::net::IpAddr>, crawlx_fetch::FetchError> {
            assert_eq!(crawlx_storage::tenant::current(), Some(self.tenant));
            self.calls.fetch_add(1, Ordering::Relaxed);
            crawlx_fetch::Resolver::resolve(&self.inner, host).await
        }
    }

    let site = common::site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut url = url::Url::parse(&site.base).unwrap();
    url.set_host(Some("tenant-fixture.test")).unwrap();
    let mut request = static_crawl(&url.origin().ascii_serialization());
    request.safety.respect_robots_txt = false;
    request.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    request.scope.max_discovery_depth = 0;
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let tenant = stores.tenant;
    let mut record = common::authorization::verified_record(&request, tenant);
    record.url_prefixes = vec![url.origin().ascii_serialization()];
    let calls = Arc::new(AtomicUsize::new(0));
    let mut cfg = config(dir.path());
    cfg.egress.resolver = Some(Arc::new(ScopedResolver {
        tenant,
        inner: StaticResolver::new().with("tenant-fixture.test", [std::net::Ipv4Addr::LOCALHOST.into()]),
        calls: Arc::clone(&calls),
    }));
    let report = crawlx_storage::tenant::scope(
        tenant,
        crawlx_worker::run_local_with(
            LocalRun::new(request, cfg)
                .with_stores(stores)
                .with_authorization(record),
        ),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.pages.len(), 1);
    assert!(calls.load(Ordering::Relaxed) > 0);
}
