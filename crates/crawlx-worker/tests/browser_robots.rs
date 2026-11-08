//! `robots.txt` obedience of the browser plane: the same
//! decision as the URL plane, a refused navigation journaled and counted, never fetched.
//!
//! A local HTTP site serves `robots.txt` and records every request; the browser plane runs on
//! a `FakeBackend` that honours the navigation guard, scripted with the same pages. The mock
//! server therefore sees exactly what the run asks of the network: the `robots.txt` lookups of
//! the gate, and nothing for a refused page.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use authorization_fixture::run_authorized_local_with as run_local_with;
use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::ActionStatus;
use crawlx_core::identity::ActionKind;
use crawlx_core::repo::{EventRepo, FrontierStatus};
use crawlx_core::{AuthorizationRecordId, Clock, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, RunReport, Stores, WorkerConfig, WorkerError};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

/// What the site answers for `/robots.txt`.
#[derive(Clone, Copy)]
enum Robots {
    Text(&'static str),
    Status(StatusCode),
}

/// `robots.txt` fixtures of the URL-plane tests (`url_plane.rs`, `katana_url_plane.rs`,
/// `common/site.rs`): the broad rule, `Allow` precedence, everything disallowed, an empty file,
/// a missing file and an unavailable one.
const FIXTURES: [(&str, Robots); 6] = [
    (
        "disallow /private/",
        Robots::Text("User-agent: *\nDisallow: /private/\n"),
    ),
    (
        "allow wins over the shorter disallow",
        Robots::Text("User-agent: *\nDisallow: /private/\nAllow: /private/open\n"),
    ),
    ("disallow /", Robots::Text("User-agent: *\nDisallow: /\n")),
    ("empty file", Robots::Text("")),
    ("404", Robots::Status(StatusCode::NOT_FOUND)),
    ("503", Robots::Status(StatusCode::SERVICE_UNAVAILABLE)),
];

struct Site {
    base: String,
    hits: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Site {
    fn count(&self, path: &str) -> usize {
        self.hits.lock().unwrap().iter().filter(|p| *p == path).count()
    }

    fn requested(&self) -> BTreeSet<String> {
        self.hits.lock().unwrap().iter().cloned().collect()
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

/// `/` links to `/public`, `/private/x` and `/private/open`; each of them is a leaf page.
async fn site(robots: Robots) -> Site {
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
            get(|| async {
                page(
                    "Home",
                    r#"<a href="/public">Public</a> <a href="/private/x">Secret</a> <a href="/private/open">Open</a>"#,
                )
            }),
        )
        .route("/public", get(|| async { page("Public", "") }))
        .route("/private/x", get(|| async { page("Secret", "") }))
        .route("/private/open", get(|| async { page("Open", "") }))
        .route(
            "/robots.txt",
            get(move || async move {
                match robots {
                    Robots::Text(text) => ([(header::CONTENT_TYPE, "text/plain")], text).into_response(),
                    Robots::Status(status) => (status, "").into_response(),
                }
            }),
        )
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), count_hit));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { base, hits, task }
}

/// The same pages as the site, for the scripted browser: every link navigates to its target,
/// whether the explorer clicks it or activates it from the keyboard (as a real link does), and
/// every leaf links back home. Without the way back, a walk that happens to visit `/public`
/// first would be stranded on a page with nothing to act on and end before it reached the
/// disallowed links; the order of the walk depends on element identities, which depend on the
/// mock server's port.
fn script(base: &str) -> FakeScript {
    fn link(page: FakePage, key: &str, name: &str, path: &str) -> FakePage {
        let navigate = vec![FakeEffect::Navigate(path.to_owned())];
        page.node(FakeAxSpec::link(key, name, path))
            .on_click(key, navigate.clone())
            .on(ActionKind::KeyboardActivate, key, navigate)
    }
    let mut home = FakePage::new(&format!("{base}/")).title("Home");
    for (key, name, path) in [
        ("lnk-public", "Public", "/public"),
        ("lnk-secret", "Secret", "/private/x"),
        ("lnk-open", "Open", "/private/open"),
    ] {
        home = link(home, key, name, path);
    }
    let leaf = |path: &str, title: &str| {
        link(
            FakePage::new(&format!("{base}{path}")).title(title),
            "lnk-home",
            "Home",
            "/",
        )
    };
    FakeScript::new()
        .page(home)
        .page(leaf("/public", "Public"))
        .page(leaf("/private/x", "Secret"))
        .page(leaf("/private/open", "Open"))
}

fn config(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

/// A crawl of the site in `mode`; loopback is allowed under a record reference, like the
/// static-plane tests do.
fn crawl(base: &str, mode: CrawlMode) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    c.mode = mode;
    c.seed = Some(20_261_019);
    c.limits.interactions = 30;
    c.limits.states = 50;
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c
}

struct Browsed {
    report: RunReport,
    backend: Arc<FakeBackend>,
    store: Arc<MemoryStore>,
}

impl Browsed {
    /// Paths of the documents the browser observed.
    fn states(&self) -> BTreeSet<String> {
        self.report
            .states
            .iter()
            .map(|s| s.url.url.path().to_owned())
            .collect()
    }

    /// Documents the fake browser loaded, as requested.
    fn loaded(&self) -> Vec<String> {
        self.backend
            .context_handles()
            .iter()
            .flat_map(|h| h.navigations())
            .collect()
    }

    /// Navigations the fake browser's guard refused.
    fn refused(&self) -> Vec<String> {
        self.backend
            .context_handles()
            .iter()
            .flat_map(|h| h.refused_navigations())
            .map(|b| b.url)
            .collect()
    }

    /// `(path, reason, plane)` of every `robots_blocked` run event.
    async fn events(&self) -> BTreeSet<(String, String, String)> {
        EventRepo::list_after(self.store.as_ref(), self.report.run_id, 0, 5000)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "robots_blocked")
            .map(|e| {
                let url = url::Url::parse(e.payload["url"].as_str().unwrap()).unwrap();
                (
                    url.path().to_owned(),
                    e.payload["reason"].as_str().unwrap().to_owned(),
                    e.payload["plane"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }
}

/// Run `crawl` on a guard-honouring fake browser scripted with the site's pages.
async fn browse(site: &Site, crawl: CreateCrawl) -> Browsed {
    let dir = tempfile::tempdir().unwrap();
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script(&site.base))
            .honour_navigation_guard()
            .build(),
    );
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let report = run_local_with(
        LocalRun::new(crawl, config(dir.path()))
            .with_backend(backend.clone())
            .with_stores(stores),
    )
    .await
    .unwrap();
    Browsed {
        report,
        backend,
        store,
    }
}

fn set<const N: usize>(items: [&str; N]) -> BTreeSet<String> {
    items.into_iter().map(str::to_owned).collect()
}

/// An observe-only walk checks every discovered link before it queues it: a disallowed URL is
/// counted and announced, never navigated, and the mock server never sees a request for it.
#[tokio::test]
async fn the_observe_only_walk_skips_disallowed_paths_and_the_server_never_sees_them() {
    let site = site(FIXTURES[0].1).await;
    let mut c = crawl(&site.base, CrawlMode::Dynamic);
    c.dynamic.observe_only = true;
    let run = browse(&site, c).await;

    assert_eq!(run.states(), set(["/", "/public"]));
    let urls = run.report.counters.urls;
    assert_eq!(urls.robots_blocked, 2, "{urls:?}");
    assert!(urls.invariants_hold(), "{urls:?}");
    assert_eq!(
        run.events().await,
        BTreeSet::from([
            (
                "/private/open".to_owned(),
                "robots_disallow".to_owned(),
                "browser".to_owned()
            ),
            (
                "/private/x".to_owned(),
                "robots_disallow".to_owned(),
                "browser".to_owned()
            ),
        ])
    );
    // the browser never navigated there, and neither did anything else
    assert!(
        run.loaded().iter().all(|u| !u.contains("/private/")),
        "{:?}",
        run.loaded()
    );
    assert!(
        run.refused().is_empty(),
        "the pre-flight check kept it from the browser"
    );
    assert_eq!(site.count("/private/x"), 0);
    assert_eq!(site.count("/private/open"), 0);
    assert_eq!(site.count("/robots.txt"), 1, "fetched once for the origin");
    assert!(
        run.report.pages.is_empty(),
        "no page record: the URL plane never ran"
    );
}

/// Exploration clicks the link; the browser refuses the document request it triggers. The
/// action is journaled as failed (never `unknown`), the refusal is counted and announced, the
/// page stays where it was and nothing reaches the server.
#[tokio::test]
async fn a_clicked_link_to_a_disallowed_page_is_refused_in_the_browser_and_journaled() {
    let site = site(FIXTURES[0].1).await;
    let run = browse(&site, crawl(&site.base, CrawlMode::Dynamic)).await;

    assert!(
        run.states().contains("/public"),
        "allowed links are explored: {:?}",
        run.states()
    );
    assert!(
        run.states().iter().all(|p| !p.starts_with("/private/")),
        "no state for a refused page: {:?}",
        run.states()
    );
    assert!(
        run.loaded().iter().all(|u| !u.contains("/private/")),
        "{:?}",
        run.loaded()
    );
    let refused = run.refused();
    assert!(refused.iter().any(|u| u.ends_with("/private/x")), "{refused:?}");

    let failed = run
        .report
        .actions
        .iter()
        .filter(|a| a.status == ActionStatus::Failed)
        .count();
    assert!(failed >= 1, "the refused clicks are journaled as failed");
    assert!(
        run.report
            .actions
            .iter()
            .all(|a| a.status != ActionStatus::Unknown),
        "a refused navigation is a known outcome"
    );
    assert_eq!(run.report.counters.interactions.unknown_outcome, 0);
    let urls = run.report.counters.urls;
    assert!(urls.robots_blocked >= 1, "{urls:?}");
    assert!(urls.invariants_hold(), "{urls:?}");
    let events = run.events().await;
    assert!(
        events.contains(&(
            "/private/x".to_owned(),
            "robots_disallow".to_owned(),
            "browser".to_owned()
        )),
        "{events:?}"
    );
    assert_eq!(site.count("/private/x"), 0);
    assert_eq!(site.count("/private/open"), 0);
}

/// The browser plane decides exactly as the URL plane does on the fixtures the URL-plane tests
/// use: the same `(path, reason)` pairs end up refused, `Allow` precedence and an unavailable
/// `robots.txt` included.
#[tokio::test]
async fn the_browser_plane_decides_like_the_url_plane_on_the_same_robots_files() {
    for (name, robots) in FIXTURES {
        let url_site = site(robots).await;
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let mut c = crawl(&url_site.base, CrawlMode::Static);
        c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
        let report = run_local_with(LocalRun::new(c, config(dir.path())).with_stores(stores.clone()))
            .await
            .unwrap();
        let url_plane: BTreeSet<(String, String)> = stores
            .frontier
            .list(report.run_id)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.status == FrontierStatus::RobotsBlocked)
            .map(|e| (e.url.url.path().to_owned(), e.denial_reason.unwrap()))
            .collect();

        let browser_site = site(robots).await;
        let mut c = crawl(&browser_site.base, CrawlMode::Dynamic);
        c.dynamic.observe_only = true;
        let run = browse(&browser_site, c).await;
        let browser_plane: BTreeSet<(String, String)> = run
            .events()
            .await
            .into_iter()
            .map(|(path, reason, _)| (path, reason))
            .collect();

        assert_eq!(browser_plane, url_plane, "fixture: {name}");
        // what neither plane may load, neither requested
        for (path, _) in &url_plane {
            assert_eq!(url_site.count(path), 0, "{name}: URL plane fetched {path}");
            assert_eq!(
                browser_site.count(path),
                0,
                "{name}: browser plane requested {path}"
            );
        }
        assert_eq!(
            run.report.counters.urls.robots_blocked,
            u64::try_from(browser_plane.len()).unwrap(),
            "fixture: {name}"
        );
    }
}

/// A hybrid run reads each origin's `robots.txt` once: the URL plane and the browser plane share
/// the cache. The refused paths are requested by neither.
#[tokio::test]
async fn a_hybrid_run_shares_one_robots_cache_between_its_planes() {
    let site = site(FIXTURES[0].1).await;
    let mut c = crawl(&site.base, CrawlMode::Hybrid);
    c.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    let run = browse(&site, c).await;

    assert_eq!(site.count("/robots.txt"), 1, "requested: {:?}", site.requested());
    assert_eq!(site.count("/private/x"), 0);
    assert!(
        run.loaded().iter().all(|u| !u.contains("/private/")),
        "{:?}",
        run.loaded()
    );
    assert!(run.report.counters.urls.invariants_hold());
}

/// `respectRobotsTxt: false` under a record that acknowledges the override: the browser
/// navigates the disallowed path and the gate never reads `robots.txt`.
#[tokio::test]
async fn ignoring_robots_under_a_record_navigates_the_disallowed_path() {
    let site = site(FIXTURES[0].1).await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut record = crawlx_policy::testkit::sample_record(stores.tenant, SystemClock.now(), &[&site.base]);
    record.verified_at = Some(SystemClock.now());
    record.robots_override_acknowledged = true;
    let mut c = crawl(&site.base, CrawlMode::Dynamic);
    c.dynamic.observe_only = true;
    c.safety.respect_robots_txt = false;
    c.safety.authorization_record_ref = Some(record.id);

    let backend = Arc::new(
        FakeBackend::builder()
            .script(script(&site.base))
            .honour_navigation_guard()
            .build(),
    );
    let report = run_local_with(
        LocalRun::new(c, config(dir.path()))
            .with_backend(backend.clone())
            .with_stores(stores)
            .with_authorization(record),
    )
    .await
    .unwrap();
    let states: BTreeSet<String> = report
        .states
        .iter()
        .map(|s| s.url.url.path().to_owned())
        .collect();
    assert_eq!(states, set(["/", "/public", "/private/x", "/private/open"]));
    assert_eq!(report.counters.urls.robots_blocked, 0);
    assert_eq!(
        site.count("/robots.txt"),
        0,
        "an ignored robots.txt is not even read"
    );
    assert!(backend.context_handles()[0].refused_navigations().is_empty());
}

/// The same override without a record reference is a configuration error before any session
/// starts (admission refuses it too: `robots_off_without_reference_is_rejected`).
#[tokio::test]
async fn ignoring_robots_in_the_browser_without_a_record_is_a_configuration_error() {
    let site = site(FIXTURES[0].1).await;
    let dir = tempfile::tempdir().unwrap();
    let mut c = crawl(&site.base, CrawlMode::Dynamic);
    c.safety.respect_robots_txt = false;
    c.safety.authorization_record_ref = None;
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script(&site.base))
            .honour_navigation_guard()
            .build(),
    );
    let err = run_local_with(LocalRun::new(c, config(dir.path())).with_backend(backend.clone()))
        .await
        .unwrap_err();
    assert!(matches!(err, WorkerError::Config(_)), "{err:?}");
    assert!(err.to_string().to_lowercase().contains("robots"), "{err}");
    assert_eq!(backend.contexts_created(), 0, "no browser context was opened");
    assert_eq!(site.count("/robots.txt"), 0);
}

/// A backend that does not honour a navigation guard (the default of `FakeBackend`: scripted
/// sites on made-up hosts have no `robots.txt` to read) leaves the browser plane unchecked, and
/// the gate is not consulted at all.
#[tokio::test]
async fn a_backend_without_a_guard_runs_unchecked() {
    let site = site(FIXTURES[0].1).await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let mut c = crawl(&site.base, CrawlMode::Dynamic);
    c.dynamic.observe_only = true;
    let backend = Arc::new(FakeBackend::new(script(&site.base)));
    let report = run_local_with(
        LocalRun::new(c, config(dir.path()))
            .with_backend(backend)
            .with_stores(stores),
    )
    .await
    .unwrap();
    let states: BTreeSet<String> = report
        .states
        .iter()
        .map(|s| s.url.url.path().to_owned())
        .collect();
    assert!(states.contains("/private/x"), "{states:?}");
    assert_eq!(report.counters.urls.robots_blocked, 0);
    assert_eq!(site.count("/robots.txt"), 0);
}
