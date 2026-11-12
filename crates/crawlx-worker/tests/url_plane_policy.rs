//! URL-plane policy and run control against in-process sites: the order of the seed page's links
//! and the sitemap entries, the outbound `Referer`, the stable refusal of over-long links, the
//! run-level stop criteria and the terminal detail of a run that kept no page.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use axum::http::{header, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::authorization::{run_authorized_local as run_local, run_authorized_local_with as run_local_with};
use crawlx_core::config::{CrawlMode, ReferrerPolicy};
use crawlx_core::counters::{RunStatus, TerminalDetail, TerminalReason};
use crawlx_core::repo::{ArtifactStore, FrontierEntry, FrontierStatus, Sensitivity};
use crawlx_core::{ArtifactRef, CrawlRunId, CreateCrawl, StoreError};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::sync::atomic::{AtomicU16, Ordering};
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
    c.seed = Some(20_261_112);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c
}

/// One request a [`Recorded`] site served.
struct Seen {
    path: String,
    referer: Option<String>,
}

/// An in-process site that records the path and `Referer` of every request.
struct Recorded {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Recorded {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Recorded {
    /// Requests for `path`.
    fn count(&self, path: &str) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.path == path)
            .count()
    }

    /// The `Referer` of the last request for `path`: `None` when it was never requested.
    fn referer(&self, path: &str) -> Option<Option<String>> {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|s| s.path == path)
            .map(|s| s.referer.clone())
    }

    /// The longest request path served.
    fn longest_path(&self) -> usize {
        self.seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.path.len())
            .max()
            .unwrap_or(0)
    }

    /// Distinct non-robots, non-sitemap paths served, sorted.
    fn pages(&self) -> Vec<String> {
        let mut paths: Vec<String> = self
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|s| s.path.clone())
            .filter(|p| p != "/robots.txt" && p != "/sitemap.xml")
            .collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

/// Serve `build(port)` on a loopback port, recording every request.
async fn recorded_site(build: impl FnOnce(u16) -> Router) -> Recorded {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<Seen>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let app = build(addr.port()).layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let sink = Arc::clone(&sink);
            async move {
                sink.lock().unwrap().push(Seen {
                    path: req.uri().path().to_owned(),
                    referer: req
                        .headers()
                        .get(header::REFERER)
                        .map(|value| value.to_str().unwrap().to_owned()),
                });
                next.run(req).await
            }
        },
    ));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Recorded {
        base: format!("http://{addr}"),
        seen,
        task,
    }
}

fn html_page(title: &str, links: &str) -> axum::response::Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>The {title} page.</p>{links}</main></body></html>"
        ),
    )
        .into_response()
}

fn anchors(paths: &[String]) -> String {
    paths
        .iter()
        .map(|p| format!(r#"<a href="{p}">{p}</a>"#))
        .collect()
}

fn not_found() -> axum::response::Response {
    (StatusCode::NOT_FOUND, "not found").into_response()
}

/// `/` links to `/l1`..`/l3`; the sitemap named by `robots.txt` lists `/s1`..`/s3`; all are leaves.
async fn linked_and_mapped_site() -> Recorded {
    recorded_site(|port| {
        let base = format!("http://127.0.0.1:{port}");
        let sitemap = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{}</urlset>"#,
            ["/s1", "/s2", "/s3"]
                .iter()
                .map(|p| format!("<url><loc>{base}{p}</loc></url>"))
                .collect::<String>()
        );
        let robots = format!("User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n");
        Router::new()
            .route(
                "/robots.txt",
                get(move || {
                    let robots = robots.clone();
                    async move { ([(header::CONTENT_TYPE, "text/plain")], robots) }
                }),
            )
            .route(
                "/sitemap.xml",
                get(move || {
                    let sitemap = sitemap.clone();
                    async move { ([(header::CONTENT_TYPE, "application/xml")], sitemap) }
                }),
            )
            .fallback(|uri: Uri| async move {
                match uri.path() {
                    "/" => html_page("Home", &anchors(&["/l1".into(), "/l2".into(), "/l3".into()])),
                    "/l1" | "/l2" | "/l3" | "/s1" | "/s2" | "/s3" => html_page(uri.path(), ""),
                    _ => not_found(),
                }
            })
    })
    .await
}

/// Run a crawl of `site` over kept in-memory stores, returning the report and the frontier.
async fn crawl(site: &Recorded, tweak: impl FnOnce(&mut CreateCrawl)) -> (RunReport, Vec<FrontierEntry>) {
    let (report, frontier, _) = crawl_with_stores(site, tweak).await;
    (report, frontier)
}

async fn crawl_with_stores(
    site: &Recorded,
    tweak: impl FnOnce(&mut CreateCrawl),
) -> (RunReport, Vec<FrontierEntry>, Stores) {
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
    (report, frontier, stores)
}

fn paths(report: &RunReport) -> Vec<String> {
    let mut v: Vec<String> = report.pages.iter().map(|p| p.url.url.path().to_owned()).collect();
    v.sort();
    v
}

fn id_of(frontier: &[FrontierEntry], path: &str) -> i64 {
    frontier
        .iter()
        .find(|e| e.url.url.path() == path)
        .unwrap_or_else(|| panic!("no frontier row for {path}"))
        .id
}

/// Every `run.stopped` event of a run: its reason and detail.
async fn stop_records(stores: &Stores, run: CrawlRunId) -> Vec<(String, String)> {
    stores
        .events
        .list_after(run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "run.stopped")
        .map(|event| {
            (
                event.payload["terminalReason"].as_str().unwrap().to_owned(),
                event.payload["terminalDetail"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

// ---- seed page links before sitemap entries --------------------------------------------------

/// A crawl bounded by `limits.urls` keeps the seed's own neighbours, the same ones on every run,
/// and the sitemap entries only once the links are spent; the queue order is the discovery order.
#[tokio::test]
async fn seed_page_links_are_enqueued_before_sitemap_entries_so_a_limit_keeps_the_links() {
    let site = linked_and_mapped_site().await;
    let (report, frontier) = crawl(&site, |c| c.limits.urls = 4).await;
    assert_eq!(paths(&report), vec!["/", "/l1", "/l2", "/l3"]);
    assert_eq!(report.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(report.terminal_detail, Some(TerminalDetail::UrlsLimit));
    for sitemap_only in ["/s1", "/s2", "/s3"] {
        assert_eq!(site.count(sitemap_only), 0, "{sitemap_only} is beyond the limit");
    }
    let order: Vec<i64> = ["/", "/l1", "/l2", "/l3", "/s1", "/s2", "/s3"]
        .iter()
        .map(|p| id_of(&frontier, p))
        .collect();
    assert!(
        order.windows(2).all(|pair| pair[0] < pair[1]),
        "enqueue order is seed, links in document order, then sitemap entries: {order:?}"
    );

    // one more page: the first sitemap entry, and the same pages on a rerun
    let (report, _) = crawl(&site, |c| c.limits.urls = 5).await;
    assert_eq!(paths(&report), vec!["/", "/l1", "/l2", "/l3", "/s1"]);
    let (rerun, _) = crawl(&site, |c| c.limits.urls = 5).await;
    assert_eq!(paths(&rerun), paths(&report));

    // unbounded: both sources are crawled
    let (report, _) = crawl(&site, |_| {}).await;
    assert_eq!(report.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert_eq!(report.terminal_detail, None);
    assert_eq!(report.pages.len(), 7);
    assert!(report.counters.urls.invariants_hold());
}

/// The sitemap is still discovered when the seed page has no link and when the seed fails.
#[tokio::test]
async fn sitemap_entries_are_still_discovered_without_seed_links_and_after_a_failed_seed() {
    let site = recorded_site(|port| {
        let base = format!("http://127.0.0.1:{port}");
        let sitemap = format!(
            r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{base}/s1</loc></url></urlset>"#
        );
        let robots = format!("User-agent: *\nAllow: /\nSitemap: {base}/sitemap.xml\n");
        Router::new()
            .route("/robots.txt", get(move || {
                let robots = robots.clone();
                async move { robots }
            }))
            .route("/sitemap.xml", get(move || {
                let sitemap = sitemap.clone();
                async move { ([(header::CONTENT_TYPE, "application/xml")], sitemap) }
            }))
            .route("/", get(|| async { html_page("Bare", "") }))
            .route("/s1", get(|| async { html_page("S1", "") }))
            .route("/broken", get(|| async { StatusCode::INTERNAL_SERVER_ERROR }))
    })
    .await;
    let (report, _) = crawl(&site, |_| {}).await;
    assert_eq!(paths(&report), vec!["/", "/s1"]);
    assert_eq!(report.terminal_reason, Some(TerminalReason::FrontierExhausted));

    let (report, frontier) = crawl(&site, |c| {
        c.seed_url = url::Url::parse(&format!("{}/broken", site.base)).unwrap();
        c.fetch.retries = 0;
        c.scope.crawl_entire_domain = true;
    })
    .await;
    assert_eq!(
        paths(&report),
        vec!["/s1"],
        "a failed seed still discovers the sitemap"
    );
    assert_eq!(
        frontier
            .iter()
            .filter(|e| e.status == FrontierStatus::Failed)
            .count(),
        1
    );
}

// ---- outbound Referer ------------------------------------------------------------------------

/// `/start` (the seed) links to `/near` on its own origin and to `/far` on another origin.
async fn referer_sites() -> (Recorded, Recorded) {
    let far = recorded_site(|_| {
        Router::new()
            .route("/robots.txt", get(|| async { "" }))
            .route("/far", get(|| async { html_page("Far", "") }))
    })
    .await;
    let far_url = format!("{}/far", far.base);
    let near = recorded_site(move |_| {
        Router::new()
            .route("/robots.txt", get(|| async { "" }))
            .route(
                "/start",
                get(move || {
                    let far_url = far_url.clone();
                    async move {
                        html_page(
                            "Start",
                            &format!(r#"<a href="/near">near</a> <a href="{far_url}">far</a>"#),
                        )
                    }
                }),
            )
            .route("/near", get(|| async { html_page("Near", "") }))
    })
    .await;
    (near, far)
}

const SECRET: &str = "configured-secret-1234";

async fn referer_crawl(near: &Recorded, policy: ReferrerPolicy) -> RunReport {
    let dir = tempfile::tempdir().unwrap();
    let mut c = static_crawl(&near.base);
    c.seed_url = url::Url::parse(&format!(
        "{}/start?keep=1&session_token=abcdefghijklmnopqrstuvwxyz0123456789&ref={SECRET}",
        near.base
    ))
    .unwrap();
    // keep every query parameter, so the secrets reach the page URL the links are found on
    c.scope.query_policy = crawlx_core::config::QueryPolicy::KeepAll;
    c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    c.scope.crawl_entire_domain = true;
    c.scope.allow_external_links = true;
    c.fetch.referrer_policy = policy;
    c.fetch.extra_headers.insert("x-api-key", SECRET);
    run_local(c, config(dir.path())).await.unwrap()
}

#[tokio::test]
async fn referer_follows_the_declared_policy_per_origin_and_never_leaks_secrets() {
    let (near, far) = referer_sites().await;

    // the default sends none, whatever the page URL carries
    let report = referer_crawl(&near, ReferrerPolicy::NoReferrer).await;
    assert!(report.pages.len() >= 2, "{:?}", paths(&report));
    assert_eq!(near.referer("/near"), Some(None));
    assert_ne!(far.referer("/far"), Some(Some(String::new())));
    assert!(far.referer("/far").is_none_or(|r| r.is_none()));
    assert_eq!(near.referer("/start"), Some(None), "the seed has no parent page");

    // full URL on the same origin, origin only across origins
    referer_crawl(&near, ReferrerPolicy::OriginWhenCrossOrigin).await;
    assert_eq!(
        near.referer("/near"),
        Some(Some(format!("{}/start?keep=1", near.base))),
        "same origin: the parent page without its secret parameters"
    );
    // the cross-origin leaf (when the fixture's egress policy lets it through) gets the origin only
    if let Some(referer) = far.referer("/far") {
        assert_eq!(referer, Some(format!("{}/", near.base)));
    }
    assert_eq!(near.referer("/start"), Some(None));

    // the same-origin policy sends nothing across origins
    referer_crawl(&near, ReferrerPolicy::SameOrigin).await;
    assert_eq!(
        near.referer("/near"),
        Some(Some(format!("{}/start?keep=1", near.base)))
    );
    assert!(far.referer("/far").is_none_or(|r| r.is_none()));

    // no policy ever put a secret on the wire
    for site in [&near, &far] {
        for seen in site.seen.lock().unwrap().iter() {
            let referer = seen.referer.as_deref().unwrap_or_default();
            assert!(!referer.contains(SECRET), "{referer}");
            assert!(!referer.contains("abcdefghijklmnop"), "{referer}");
            assert!(!referer.contains("session_token"), "{referer}");
            assert!(!referer.contains('#'), "{referer}");
        }
    }
}

// ---- over-long links ---------------------------------------------------------------------------

#[tokio::test]
async fn an_over_long_link_is_counted_as_url_too_long_and_never_fetched() {
    let long = format!("/{}", "a".repeat(9 * 1024));
    let site = {
        let long = long.clone();
        recorded_site(move |_| {
            let links = anchors(&["/ok".into(), long]);
            Router::new()
                .route("/robots.txt", get(|| async { "" }))
                .route(
                    "/",
                    get(move || {
                        let links = links.clone();
                        async move { html_page("Home", &links) }
                    }),
                )
                .route("/ok", get(|| async { html_page("Ok", "") }))
        })
        .await
    };
    let m = Metrics::global();
    let reason = [("plane", "urls"), ("reason", "url_too_long")];
    let before = m.counter(names::URLS_POLICY_BLOCKED).get(&reason);
    let (report, frontier) = crawl(&site, |c| {
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip
    })
    .await;

    let u = report.counters.urls;
    assert_eq!((u.discovered, u.admitted, u.policy_blocked), (3, 2, 1), "{u:?}");
    assert!(u.invariants_hold());
    assert_eq!(paths(&report), vec!["/", "/ok"]);
    assert_eq!(
        site.pages(),
        vec!["/".to_owned(), "/ok".to_owned()],
        "the long link was never requested"
    );
    assert!(site.longest_path() < 100);
    assert_eq!(frontier.len(), 2);
    assert!(
        m.counter(names::URLS_POLICY_BLOCKED).get(&reason) > before,
        "the refusal is counted under its stable reason"
    );

    // the bound is the request's `scope.maxUrlLength`
    let (report, _) = crawl(&site, |c| {
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        c.scope.max_url_length = 60_000;
    })
    .await;
    assert_eq!(report.counters.urls.policy_blocked, 0);
    assert_eq!(
        site.count(&long),
        1,
        "under a larger bound the link is an ordinary URL"
    );
    let (report, _) = crawl(&site, |c| {
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        c.scope.max_url_length = 256;
    })
    .await;
    assert_eq!(report.counters.urls.policy_blocked, 1);
}

// ---- run-level stop criteria -------------------------------------------------------------------

/// `/` links to `/p1`..`/p8`, all leaves.
async fn fan_site() -> Recorded {
    recorded_site(|_| {
        let links = anchors(&(1..=8).map(|n| format!("/p{n}")).collect::<Vec<_>>());
        Router::new()
            .route("/robots.txt", get(|| async { "" }))
            .route(
                "/",
                get(move || {
                    let links = links.clone();
                    async move { html_page("Home", &links) }
                }),
            )
            .fallback(|uri: Uri| async move { html_page(uri.path(), "") })
    })
    .await
}

/// A run that stops on a criterion ends with its reason and detail, seals its producers and
/// leaves everything else untouched: no row is finished, abandoned or fetched after the stop.
#[tokio::test]
async fn the_item_limit_stops_the_run_at_exactly_that_many_pages() {
    let site = fan_site().await;
    let (report, frontier, stores) = crawl_with_stores(&site, |c| {
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        c.limits.items = 3;
    })
    .await;
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(report.terminal_detail, Some(TerminalDetail::ItemsLimit));
    assert_eq!(report.pages.len(), 3);
    assert_eq!(report.counters.urls.succeeded, 3);
    assert_eq!(
        site.pages(),
        vec!["/", "/p1", "/p2"],
        "nothing is fetched beyond the limit"
    );
    let pending = frontier
        .iter()
        .filter(|e| e.status == FrontierStatus::Pending)
        .count();
    assert_eq!(pending, 6, "the unfetched rows stay queued, untouched");
    assert!(report.counters.urls.invariants_hold());
    assert_eq!(
        stop_records(&stores, report.run_id).await,
        vec![("limit_reached".to_owned(), "items_limit".to_owned())]
    );
    let completed = stores
        .events
        .list_after(report.run_id, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.kind == "completed")
        .unwrap();
    assert_eq!(completed.payload["terminalReason"], "limit_reached");
    assert_eq!(completed.payload["terminalDetail"], "items_limit");

    // the same site under the url limit names that criterion instead
    let (report, _, stores) = crawl_with_stores(&site, |c| {
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        c.limits.urls = 3;
    })
    .await;
    assert_eq!(report.terminal_detail, Some(TerminalDetail::UrlsLimit));
    assert_eq!(
        stop_records(&stores, report.run_id).await,
        vec![("limit_reached".to_owned(), "urls_limit".to_owned())]
    );
}

/// `/` links to `/e1`..`/e6`, every one of them a 404.
async fn failing_site() -> Recorded {
    recorded_site(|_| {
        let links = anchors(&(1..=6).map(|n| format!("/e{n}")).collect::<Vec<_>>());
        Router::new()
            .route("/robots.txt", get(|| async { "" }))
            .route(
                "/",
                get(move || {
                    let links = links.clone();
                    async move { html_page("Home", &links) }
                }),
            )
            .fallback(|| async { not_found() })
    })
    .await
}

#[tokio::test]
async fn the_error_limit_stops_the_run_with_its_own_detail() {
    let site = failing_site().await;
    let (report, frontier, stores) = crawl_with_stores(&site, |c| {
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        c.limits.errors = 2;
    })
    .await;
    assert_eq!(report.terminal_reason, Some(TerminalReason::PolicyStopped));
    assert_eq!(report.terminal_detail, Some(TerminalDetail::ErrorsLimit));
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(
        report.counters.urls.failed, 2,
        "the lease is capped, the count is exact"
    );
    assert_eq!(report.counters.urls.succeeded, 1, "the seed was kept");
    assert_eq!(site.pages().len(), 3);
    assert_eq!(
        frontier
            .iter()
            .filter(|e| e.status == FrontierStatus::Pending)
            .count(),
        4
    );
    assert_eq!(
        stop_records(&stores, report.run_id).await,
        vec![("policy_stopped".to_owned(), "errors_limit".to_owned())]
    );
}

/// An artifact store whose spool fills by one tenth with every object put.
struct FillingSpool {
    inner: Arc<dyn ArtifactStore>,
    permille: AtomicU16,
}

#[async_trait]
impl ArtifactStore for FillingSpool {
    fn spool_pressure_permille(&self) -> Option<u16> {
        Some(self.permille.load(Ordering::SeqCst))
    }
    async fn put(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        self.permille.fetch_add(100, Ordering::SeqCst);
        self.inner.put(run, class, content_type, bytes).await
    }
    async fn put_dataset(
        &self,
        run: CrawlRunId,
        page: i64,
        rendition: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        self.inner
            .put_dataset(run, page, rendition, content_type, bytes)
            .await
    }
    async fn erase_run_credentials(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        self.inner.erase_run_credentials(run).await
    }
    async fn get(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        self.inner.get(artifact).await
    }
}

#[tokio::test]
async fn disk_pressure_drains_the_run_without_finishing_queued_rows() {
    let site = fan_site().await;
    let dir = tempfile::tempdir().unwrap();
    let mut c = static_crawl(&site.base);
    c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    c.limits.disk_pressure_permille = 500;
    c.politeness.max_concurrency = 1;
    let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    stores.artifacts = Arc::new(FillingSpool {
        inner: Arc::clone(&stores.artifacts),
        permille: AtomicU16::new(0),
    });
    let report = run_local_with(LocalRun::new(c, config(dir.path())).with_stores(stores.clone()))
        .await
        .unwrap();
    assert_eq!(report.terminal_reason, Some(TerminalReason::PolicyStopped));
    assert_eq!(report.terminal_detail, Some(TerminalDetail::DiskPressure));
    assert!(
        !report.pages.is_empty() && report.pages.len() < 9,
        "{}",
        report.pages.len()
    );
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    assert!(frontier.iter().any(|e| e.status == FrontierStatus::Pending));
    assert_eq!(
        stop_records(&stores, report.run_id).await,
        vec![("policy_stopped".to_owned(), "disk_pressure".to_owned())]
    );
    assert!(report.counters.urls.invariants_hold());
}

// ---- drained runs that kept no page ------------------------------------------------------------

async fn failing_seed_site() -> Recorded {
    recorded_site(|_| {
        let doc_links = anchors(&["/docs/a".into(), "/docs/b".into()]);
        Router::new()
            .route("/robots.txt", get(|| async { "" }))
            .route("/missing", get(|| async { not_found() }))
            .route("/down", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
            .route("/big", get(|| async { html_page("Big", &"x".repeat(4096)) }))
            .route(
                "/gate",
                get(|| async {
                    (
                        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                        r#"<html><head><title>Just a moment...</title></head><body>
<div id="challenge-stage"><form id="challenge-form" action="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page">
<noscript>Enable JavaScript and cookies to continue</noscript></form></div></body></html>"#,
                    )
                }),
            )
            .route("/", get(move || {
                let doc_links = doc_links.clone();
                async move { html_page("Home", &doc_links) }
            }))
            .route("/docs/a", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
            .route("/docs/b", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
    })
    .await
}

async fn drained(site: &Recorded, tweak: impl FnOnce(&mut CreateCrawl)) -> RunReport {
    let (report, _, stores) = crawl_with_stores(site, |c| {
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        c.fetch.retries = 0;
        tweak(c);
    })
    .await;
    // a drained run's detail is recorded for the report as well
    let stops = stop_records(&stores, report.run_id).await;
    match report.terminal_detail {
        Some(detail) => assert_eq!(
            stops,
            vec![("frontier_exhausted".to_owned(), detail.as_str().to_owned())]
        ),
        None => assert!(stops.is_empty()),
    }
    assert_eq!(report.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert_eq!(report.status, RunStatus::Completed);
    report
}

#[tokio::test]
async fn a_drained_run_that_kept_no_page_names_why() {
    let site = failing_seed_site().await;
    let seed = |path: &'static str| {
        move |c: &mut CreateCrawl| {
            c.seed_url =
                url::Url::parse(&format!("{}{path}", c.seed_url.origin().ascii_serialization())).unwrap();
        }
    };

    // the seed itself cannot be fetched
    for path in ["/missing", "/down"] {
        let report = drained(&site, seed(path)).await;
        assert_eq!(report.terminal_detail, Some(TerminalDetail::SeedError), "{path}");
        assert!(report.pages.is_empty());
    }

    // responses over the body limit
    let report = drained(&site, |c| {
        seed("/big")(c);
        c.fetch.max_response_bytes = 1024;
        c.fetch.oversize = Some(crawlx_core::acquisition::OversizePolicy::Refuse);
    })
    .await;
    assert_eq!(report.terminal_detail, Some(TerminalDetail::ByteLimit));

    // responses that fail the content validation
    let report = drained(&site, seed("/gate")).await;
    assert_eq!(
        report.terminal_detail,
        Some(TerminalDetail::ContentValidationFailed)
    );

    // the entry URL is not a page of the crawl, and every page it links to keeps failing
    let report = drained(&site, |c| c.scope.include_paths = vec!["^/docs/".to_owned()]).await;
    assert_eq!(report.terminal_detail, Some(TerminalDetail::RetriesExhausted));
    assert_eq!(report.counters.urls.failed, 2);

    // a page kept: no detail, however many others failed
    let site = failing_site().await;
    let report = drained(&site, |_| {}).await;
    assert_eq!(report.terminal_detail, None);
    assert_eq!(report.counters.urls.succeeded, 1);
    assert_eq!(report.counters.urls.failed, 6);
}
