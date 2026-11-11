//! Admission equivalence of the two planes and mode isolation.
//!
//! * `static` and `hybrid` admit the same URL set on a URL-only fixture: the browser plane's
//!   page-hook discoveries go through the same admission pipeline and add no row that the URL
//!   plane did not already record with the same status.
//! * `static` never launches a browser; `dynamic` never fetches over the HTTP plane.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::{run_authorized_local as run_local, run_authorized_local_with as run_local_with};
use crawlx_browser::fake::{FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::RunStatus;
use crawlx_core::repo::FrontierStatus;
use crawlx_core::{CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_worker::{EgressCapture, EgressConfig, LocalRun, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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

fn crawl(base: &str, mode: CrawlMode) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    c.mode = mode;
    c.seed = Some(20_261_019);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c.limits.interactions = 10;
    c
}

/// The browser's view of `common::site`: every page reports exactly the links its HTML
/// carries through the page-hooks discovery sink, so the browser plane feeds
/// the same URL set through admission that the URL plane extracted from the HTML.
fn site_script(base: &str) -> FakeScript {
    let page = |path: &str, title: &str| FakePage::new(&format!("{base}{path}")).title(title);
    FakeScript::new()
        .page(
            page("/", "Home")
                .discovered("/a", "link")
                .discovered("/b", "link")
                .discovered("/a?utm_source=newsletter", "link")
                .discovered("/private/secret", "link")
                .discovered("https://external.example/out", "link")
                .discovered("/c", "link"),
        )
        .page(page("/a", "A").discovered("/", "link").discovered("/b", "link"))
        .page(
            page("/b", "B")
                .discovered("/c", "link")
                .discovered("/missing", "link"),
        )
        .page(page("/c", "C"))
        .page(page("/private/secret", "Secret"))
        .page(page("/missing", "Missing"))
}

fn fake(script: FakeScript) -> Arc<FakeBackend> {
    Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    )
}

/// `(path?query, status)` of every frontier row of `run`, keyed by canonical key.
async fn admissions(
    stores: &Stores,
    run: crawlx_core::CrawlRunId,
) -> BTreeMap<String, (String, FrontierStatus)> {
    stores
        .frontier
        .list(run)
        .await
        .unwrap()
        .into_iter()
        .map(|e| {
            let mut path = e.url.url.path().to_owned();
            if let Some(q) = e.url.url.query() {
                path.push('?');
                path.push_str(q);
            }
            (e.url.key.to_hex(), (path, e.status))
        })
        .collect()
}

#[tokio::test]
async fn static_and_hybrid_admit_the_same_url_set_for_a_url_only_fixture() {
    let site = common::site::start().await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let static_stores = Stores::open(&cfg).await.unwrap();
    let static_report = run_local_with(
        LocalRun::new(crawl(&site.base, CrawlMode::Static), cfg.clone()).with_stores(static_stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(static_report.status, RunStatus::Completed);

    let hybrid_stores = Stores::open(&cfg).await.unwrap();
    let mut hybrid = crawl(&site.base, CrawlMode::Hybrid);
    hybrid.dynamic.page_hooks = true;
    let hybrid_report = run_local_with(
        LocalRun::new(hybrid, cfg)
            .with_stores(hybrid_stores.clone())
            .with_backend(fake(site_script(&site.base))),
    )
    .await
    .unwrap();
    assert_eq!(hybrid_report.status, RunStatus::Completed);
    assert!(
        !hybrid_report.sessions.is_empty() && hybrid_report.browser_launches >= 1,
        "the hybrid run must have exercised the browser plane: {:?}",
        hybrid_report.counters
    );

    let a = admissions(&static_stores, static_report.run_id).await;
    let b = admissions(&hybrid_stores, hybrid_report.run_id).await;
    assert_eq!(
        a, b,
        "admission must not depend on which plane discovered the URL"
    );
    // the fixture's known admission outcomes (common::site docs)
    let by_path: BTreeMap<&str, FrontierStatus> = a.values().map(|(p, s)| (p.as_str(), *s)).collect();
    assert_eq!(by_path["/"], FrontierStatus::Succeeded);
    assert_eq!(by_path["/a"], FrontierStatus::Succeeded);
    assert_eq!(by_path["/b"], FrontierStatus::Succeeded);
    assert_eq!(by_path["/c"], FrontierStatus::Succeeded);
    assert_eq!(by_path["/missing"], FrontierStatus::Failed);
    assert_eq!(by_path["/private/secret"], FrontierStatus::RobotsBlocked);
    assert_eq!(by_path["/out"], FrontierStatus::PolicyBlocked);
    assert!(!by_path.contains_key("/a?utm_source=newsletter"), "{by_path:?}");

    // the URL plane produced the same pages in both modes
    let pages = |r: &crawlx_worker::RunReport| {
        let mut v: Vec<String> = r.pages.iter().map(|p| p.url.url.path().to_owned()).collect();
        v.sort();
        v
    };
    assert_eq!(pages(&static_report), pages(&hybrid_report));
    assert_eq!(
        static_report.counters.urls.succeeded,
        hybrid_report.counters.urls.succeeded
    );
    assert_eq!(
        static_report.counters.urls.admitted,
        hybrid_report.counters.urls.admitted
    );
}

#[tokio::test]
async fn static_mode_never_launches_a_browser() {
    let site = common::site::start().await;

    // the production pool (Chromium launcher) is wired but never asked for a process
    let dir = tempfile::tempdir().unwrap();
    let report = run_local(crawl(&site.base, CrawlMode::Static), config(dir.path()))
        .await
        .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.browser_launches, 0);
    assert!(report.sessions.is_empty(), "{:?}", report.sessions);
    assert_eq!(report.http_coordinators.len(), 1);
    let coordinator = &report.http_coordinators[0];
    assert_eq!(coordinator.kind, crawlx_core::repo::SessionKind::HttpCoordinator);
    assert_eq!(coordinator.status, crawlx_core::repo::SessionStatus::Completed);
    assert!(coordinator.browser.is_none());
    assert_eq!(report.counters.interactions.attempted, 0);
    assert_eq!(
        report.egress,
        EgressCapture::default(),
        "no egress proxy runs in static mode"
    );

    // an injected backend sees the same: no context is ever opened
    let backend = fake(site_script(&site.base));
    let dir = tempfile::tempdir().unwrap();
    let report = run_local_with(
        LocalRun::new(crawl(&site.base, CrawlMode::Static), config(dir.path()))
            .with_backend(Arc::clone(&backend) as Arc<dyn crawlx_core::BrowserBackend>),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.browser_launches, 0);
    assert_eq!(backend.contexts_created(), 0);
    assert!(report.sessions.is_empty());
    assert_eq!(report.http_coordinators.len(), 1);
    let coordinator = &report.http_coordinators[0];
    assert_eq!(coordinator.kind, crawlx_core::repo::SessionKind::HttpCoordinator);
    assert_eq!(coordinator.status, crawlx_core::repo::SessionStatus::Completed);
    assert!(coordinator.browser.is_none());
    assert!(report.counters.urls.succeeded >= 4, "{:?}", report.counters);
}

#[tokio::test]
async fn dynamic_mode_never_fetches_over_the_http_plane() {
    use axum::routing::get;
    let hits = Arc::new(AtomicU64::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().fallback(get(move || {
        let counted = Arc::clone(&counted);
        async move {
            counted.fetch_add(1, Ordering::SeqCst);
            (
                [("content-type", "text/html")],
                "<html><body><a href=\"/a\">A</a></body></html>",
            )
        }
    }));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let base = format!("http://127.0.0.1:{port}");

    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path());
    let stores = Stores::open(&cfg).await.unwrap();
    let mut dynamic = crawl(&base, CrawlMode::Dynamic);
    dynamic.dynamic.page_hooks = true;
    let script = FakeScript::new()
        .page(
            FakePage::new(&format!("{base}/"))
                .title("Home")
                .discovered("/a", "link"),
        )
        .page(FakePage::new(&format!("{base}/a")).title("A"));
    let report = run_local_with(
        LocalRun::new(dynamic, cfg)
            .with_stores(stores.clone())
            .with_backend(fake(script)),
    )
    .await
    .unwrap();
    server.abort();
    assert_eq!(report.status, RunStatus::Completed);
    assert!(!report.sessions.is_empty());
    assert!(report.browser_launches >= 1);
    // Browser output retains observed-only custody rows, never HTTP-plane work.
    let rows = stores.frontier.list(report.run_id).await.unwrap();
    assert!(
        !rows.is_empty(),
        "settled browser pages retain observation custody"
    );
    for row in &rows {
        let request = stores.frontier.get_request(report.run_id, row.id).await.unwrap();
        assert!(request.envelope.metadata.contains_key("observed_epoch"));
        assert_eq!(row.status, FrontierStatus::Succeeded);
    }
    assert_eq!(
        stores.frontier.state_counts(report.run_id).await.unwrap(),
        crawlx_core::repo::FrontierStateCounts::default()
    );
    assert_eq!(report.counters.urls, crawlx_core::counters::Counters::default());
    assert!(
        !report.pages.is_empty(),
        "settled browser documents remain page output"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancellation_before_either_plane_starts_closes_every_unleased_session() {
    for mode in [CrawlMode::Dynamic, CrawlMode::Hybrid] {
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::open(&config(dir.path())).await.unwrap();
        let mut request = crawl("https://example.test", mode);
        request.runs_per_role = 3;
        let backend = fake(site_script("https://example.test"));
        let cancel = tokio_util::sync::CancellationToken::new();
        cancel.cancel();

        let report = run_local_with(
            LocalRun::new(request, config(dir.path()))
                .with_stores(stores.clone())
                .with_backend(backend.clone())
                .with_cancel(cancel),
        )
        .await
        .unwrap();

        assert_eq!(report.status, RunStatus::Cancelled);
        assert_eq!(report.browser_launches, 0);
        assert!(backend.context_handles().is_empty());
        let sessions = stores.runs.list_sessions(report.run_id).await.unwrap();
        assert_eq!(sessions.len(), 3);
        assert!(sessions
            .iter()
            .all(|s| s.status == crawlx_core::repo::SessionStatus::Cancelled));
        assert!(stores.journal.list(report.run_id, None).await.unwrap().is_empty());
    }
}

#[tokio::test]
async fn cancellation_during_hybrid_fetch_closes_sessions_before_browser_admission() {
    let cancel = tokio_util::sync::CancellationToken::new();
    let stop = cancel.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = axum::Router::new().route(
        "/",
        axum::routing::get(move || {
            let stop = stop.clone();
            async move {
                stop.cancel();
                ([("content-type", "text/html")], "<html><body>Home</body></html>")
            }
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::open(&config(dir.path())).await.unwrap();
    let backend = fake(site_script(&base));
    let mut request = crawl(&base, CrawlMode::Hybrid);
    request.runs_per_role = 3;
    let report = run_local_with(
        LocalRun::new(request, config(dir.path()))
            .with_stores(stores.clone())
            .with_backend(backend.clone())
            .with_cancel(cancel.clone()),
    )
    .await
    .unwrap();
    server.abort();

    assert!(
        cancel.is_cancelled(),
        "the URL plane reached the cancellation barrier"
    );
    assert_eq!(report.status, RunStatus::Cancelled);
    assert_eq!(report.browser_launches, 0);
    assert!(backend.context_handles().is_empty());
    let sessions = stores.runs.list_sessions(report.run_id).await.unwrap();
    assert_eq!(sessions.len(), 3);
    assert!(sessions
        .iter()
        .all(|s| s.status == crawlx_core::repo::SessionStatus::Cancelled));
}
