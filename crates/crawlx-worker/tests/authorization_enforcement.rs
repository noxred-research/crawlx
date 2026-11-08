//! Authorization records at run time: the record bounds every request of a run, and a record that is revoked,
//! expired or removed ends the run (`authorization_revoked`, status `failed`).
//!
//! In-memory stores, an in-process axum site and `FakeBackend`; the PostgreSQL variant is
//! `tests/authorization_pg.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use chrono::Duration as Span;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, Role};
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::repo::{ActionJournal, CrawlRun, FrontierEntry, FrontierStatus, RunRepo, SessionStatus};
use crawlx_core::scrape::{JobKind, ScrapeJob, ScrapeOptions};
use crawlx_core::{
    ActionProposal, AuthorizationRecordId, Clock, CrawlRunId, CreateCrawl, SafetyProfile, SystemClock,
    TenantId,
};
use crawlx_fetch::StaticResolver;
use crawlx_policy::testkit::sample_record;
use crawlx_policy::{AuthorizationRecord, EgressLists, SharedEgressLists};
use crawlx_scheduler::RunPlanner;
use crawlx_storage::MemoryStore;
use crawlx_strategies::{DecisionContext, Strategy, StrategyError};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{
    build_strategies, run_local_with, AuthorizationSource, EgressConfig, LocalRun, RunReport,
    StaticAuthorizationSource, Stores, WorkerConfig, WorkerError,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

// ---- fixtures ---------------------------------------------------------------------------------

type Hits = Arc<Mutex<Vec<String>>>;
/// A change to a record under test.
type Tweak = Box<dyn FnOnce(&mut AuthorizationRecord)>;

/// An in-process site that logs the path of every request it answers.
struct Site {
    base: String,
    port: u16,
    hits: Hits,
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

    fn requests(&self) -> Vec<String> {
        self.hits.lock().unwrap().clone()
    }
}

async fn log_request(
    axum::extract::State(hits): axum::extract::State<Hits>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.lock().unwrap().push(req.uri().path().to_owned());
    next.run(req).await
}

/// Start a site whose routes `routes` builds from the site's own base URL.
async fn site(routes: impl FnOnce(&str) -> Router) -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let app = routes(&base)
        .fallback(|| async { (StatusCode::NOT_FOUND, "not found") })
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&hits),
            log_request,
        ));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        base,
        port: addr.port(),
        hits,
        task,
    }
}

fn page(title: &str, links: &str) -> axum::response::Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>The {title} page.</p>{links}</main></body></html>"
        ),
    )
        .into_response()
}

fn record(origins: &[&str], tweak: impl FnOnce(&mut AuthorizationRecord)) -> AuthorizationRecord {
    let mut r = sample_record(TenantId::new(), SystemClock.now(), origins);
    r.verified_at = Some(SystemClock.now());
    tweak(&mut r);
    r
}

fn static_crawl(seed: &str, record: &AuthorizationRecord) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(seed).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_028);
    // the fixture lives on loopback
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(record.id);
    c.politeness.delay_ms = 0;
    c
}

fn config(dir: &std::path::Path, extra_ports: &[u16]) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            extra_ports: extra_ports.to_vec(),
            ..EgressConfig::default()
        },
        // every check reads the source: a revocation is seen at the next check
        authorization_recheck: Duration::ZERO,
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

/// A local run with the in-memory stores kept, to read the frontier and events afterwards.
async fn local(
    crawl: CreateCrawl,
    record: AuthorizationRecord,
    extra_ports: &[u16],
    tweak: impl FnOnce(LocalRun) -> LocalRun,
) -> (RunReport, Stores) {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let run = LocalRun::new(crawl, config(dir.path(), extra_ports))
        .with_stores(stores.clone())
        .with_authorization(record);
    let report = run_local_with(tweak(run)).await.unwrap();
    (report, stores)
}

fn row<'a>(frontier: &'a [FrontierEntry], url: &str) -> &'a FrontierEntry {
    frontier
        .iter()
        .find(|e| e.url.url.as_str() == url)
        .unwrap_or_else(|| {
            panic!(
                "no frontier row for {url}: {:?}",
                frontier.iter().map(|e| e.url.url.as_str()).collect::<Vec<_>>()
            )
        })
}

async fn event_payloads(stores: &Stores, run: CrawlRunId, kind: &str) -> Vec<serde_json::Value> {
    stores
        .events
        .list_after(run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.payload)
        .collect()
}

// ---- admission --------------------------------------------------------------------------------

#[tokio::test]
async fn a_revoked_expired_not_yet_valid_or_missing_record_refuses_the_run_before_any_request() {
    let now = SystemClock.now();
    let cases: [(&str, Tweak, bool); 4] = [
        (
            "revoked",
            Box::new(move |r| r.revoked_at = Some(now - Span::seconds(5))),
            true,
        ),
        (
            "expired",
            Box::new(move |r| {
                r.valid_from = now - Span::hours(3);
                r.valid_to = now - Span::minutes(1);
            }),
            true,
        ),
        (
            "not_yet_valid",
            Box::new(move |r| {
                r.valid_from = now + Span::hours(1);
                r.valid_to = now + Span::hours(2);
            }),
            true,
        ),
        ("missing", Box::new(|_| {}), false),
    ];
    for (reason, tweak, stored) in cases {
        let s = site(|_| Router::new().route("/", get(|| async { page("Home", "") }))).await;
        let rec = record(&[&s.base], tweak);
        // for `missing` the source knows no record at all
        let source = if stored {
            StaticAuthorizationSource::new(rec.clone())
        } else {
            StaticAuthorizationSource::default()
        };
        let crawl = static_crawl(&format!("{}/", s.base), &rec);
        let (report, stores) = local(crawl, rec.clone(), &[], |run| {
            run.with_authorization_source(Arc::new(source))
        })
        .await;
        assert_eq!(report.status, RunStatus::Failed, "{reason}");
        assert_eq!(
            report.terminal_reason,
            Some(TerminalReason::AuthorizationRevoked),
            "{reason}"
        );
        assert!(report.pages.is_empty(), "{reason}");
        assert!(
            s.requests().is_empty(),
            "{reason}: the site was requested: {:?}",
            s.requests()
        );
        let events = event_payloads(&stores, report.run_id, "authorization.revoked").await;
        assert_eq!(events.len(), 1, "{reason}: {events:?}");
        assert_eq!(events[0]["reason"], reason);
        assert_eq!(events[0]["stage"], "admission");
        assert_eq!(events[0]["recordId"], serde_json::json!(rec.id));
    }
}

#[tokio::test]
async fn a_record_other_than_the_one_the_request_names_refuses_the_run() {
    let s = site(|_| Router::new().route("/", get(|| async { page("Home", "") }))).await;
    let rec = record(&[&s.base], |_| {});
    let mut crawl = static_crawl(&format!("{}/", s.base), &rec);
    crawl.safety.authorization_record_ref = Some(AuthorizationRecordId::new());
    let (report, stores) = local(crawl, rec, &[], |run| run).await;
    assert_eq!(report.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    assert!(s.requests().is_empty());
    let events = event_payloads(&stores, report.run_id, "authorization.revoked").await;
    assert_eq!(events[0]["reason"], "mismatch");
}

// ---- the record's target bounds every request -------------------------------------------------

#[tokio::test]
async fn a_redirect_outside_the_record_is_policy_blocked_authorization_scope_and_never_requested() {
    let other = site(|_| Router::new().route("/landing", get(|| async { page("Landing", "") }))).await;
    let landing = format!("{}/landing", other.base);
    let s = site(move |_| {
        Router::new()
            .route(
                "/",
                get(|| async { page("Home", r#"<a href="/go">go</a> <a href="/fine">fine</a>"#) }),
            )
            .route("/fine", get(|| async { page("Fine", "") }))
            .route(
                "/go",
                get(move || {
                    let landing = landing.clone();
                    async move { (StatusCode::FOUND, [(header::LOCATION, landing)]).into_response() }
                }),
            )
    })
    .await;
    let rec = record(&[&s.base], |_| {});
    let crawl = static_crawl(&format!("{}/", s.base), &rec);
    // the redirect target's port is allowed by the egress rules: only the record refuses it
    let (report, stores) = local(crawl, rec, &[other.port], |run| run).await;
    let frontier = stores.frontier.list(report.run_id).await.unwrap();

    let go = row(&frontier, &format!("{}/go", s.base));
    assert_eq!(go.status, FrontierStatus::PolicyBlocked, "{go:?}");
    assert_eq!(go.denial_reason.as_deref(), Some("authorization_scope"));
    assert_eq!(
        row(&frontier, &format!("{}/fine", s.base)).status,
        FrontierStatus::Succeeded
    );
    assert_eq!(s.count("/go"), 1, "the redirecting URL itself is in scope");
    assert!(
        other.requests().is_empty(),
        "the redirect target must never be requested: {:?}",
        other.requests()
    );
    // reclassified like any other policy block: not a failure
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    let u = report.counters.urls;
    assert_eq!((u.policy_blocked, u.failed, u.succeeded), (1, 0, 2), "{u:?}");
    assert!(u.invariants_hold(), "{u:?}");
    assert_eq!(report.status, RunStatus::Completed);
}

#[tokio::test]
async fn a_scrape_crawl_blocks_a_redirect_outside_the_record_like_the_plain_plane() {
    let other = site(|_| Router::new().route("/landing", get(|| async { page("Landing", "") }))).await;
    let landing = format!("{}/landing", other.base);
    let s = site(move |_| {
        Router::new()
            .route("/", get(|| async { page("Home", r#"<a href="/go">go</a>"#) }))
            .route(
                "/go",
                get(move || {
                    let landing = landing.clone();
                    async move { (StatusCode::FOUND, [(header::LOCATION, landing)]).into_response() }
                }),
            )
    })
    .await;
    let rec = record(&[&s.base], |_| {});
    let mut crawl = static_crawl(&format!("{}/", s.base), &rec);
    crawl.mode = CrawlMode::Static;
    crawl.scope.max_discovery_depth = 1;
    crawl.scrape = Some(ScrapeJob::new(JobKind::Crawl, ScrapeOptions::default()));
    let (report, stores) = local(crawl, rec, &[other.port], |run| run).await;
    let frontier = stores.frontier.list(report.run_id).await.unwrap();

    let go = row(&frontier, &format!("{}/go", s.base));
    assert_eq!(go.status, FrontierStatus::PolicyBlocked, "{go:?}");
    assert_eq!(go.denial_reason.as_deref(), Some("authorization_scope"));
    assert!(other.requests().is_empty(), "{:?}", other.requests());
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(
        report.counters.urls.policy_blocked, 1,
        "{:?}",
        report.counters.urls
    );
}

#[tokio::test]
async fn discovered_links_sitemap_urls_and_excluded_paths_outside_the_record_are_policy_blocked() {
    let other = site(|_| {
        Router::new()
            .route("/other", get(|| async { page("Other", "") }))
            .route("/mapped", get(|| async { page("Mapped", "") }))
    })
    .await;
    let other_link = format!("{}/other", other.base);
    let other_mapped = format!("{}/mapped", other.base);
    let s = site(move |base| {
        let base = base.to_owned();
        let sitemap = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>{base}/ok</loc></url><url><loc>{base}/billing/plans</loc></url><url><loc>{other_mapped}</loc></url></urlset>"#
        );
        let home = format!(
            r#"<a href="/ok">ok</a> <a href="/billing/invoices">billing</a> <a href="{other_link}">other</a>"#
        );
        Router::new()
            .route(
                "/",
                get(move || {
                    let home = home.clone();
                    async move { page("Home", &home) }
                }),
            )
            .route("/ok", get(|| async { page("Ok", "") }))
            .route("/billing/invoices", get(|| async { page("Invoices", "") }))
            .route("/billing/plans", get(|| async { page("Plans", "") }))
            .route(
                "/sitemap.xml",
                get(move || {
                    let sitemap = sitemap.clone();
                    async move { ([(header::CONTENT_TYPE, "application/xml")], sitemap) }
                }),
            )
    })
    .await;
    let rec = record(&[&s.base], |r| r.excluded_paths = vec!["/billing/*".to_owned()]);
    let mut crawl = static_crawl(&format!("{}/", s.base), &rec);
    // the run's own scope would admit the same host on another port and every path: only the
    // record keeps them out
    crawl.scope.allow_external_links = true;
    let (report, stores) = local(crawl, rec, &[other.port], |run| run).await;
    let frontier = stores.frontier.list(report.run_id).await.unwrap();

    for blocked in [
        format!("{}/billing/invoices", s.base),
        format!("{}/billing/plans", s.base),
        format!("{}/other", other.base),
        format!("{}/mapped", other.base),
    ] {
        let r = row(&frontier, &blocked);
        assert_eq!(r.status, FrontierStatus::PolicyBlocked, "{blocked}");
        assert_eq!(
            r.denial_reason.as_deref(),
            Some("authorization_scope"),
            "{blocked}"
        );
    }
    assert_eq!(
        row(&frontier, &format!("{}/ok", s.base)).status,
        FrontierStatus::Succeeded
    );
    assert_eq!(
        s.count("/billing/invoices") + s.count("/billing/plans"),
        0,
        "{:?}",
        s.requests()
    );
    assert!(other.requests().is_empty(), "{:?}", other.requests());
    let u = report.counters.urls;
    assert_eq!(u.policy_blocked, 4, "{u:?}");
    assert!(u.invariants_hold(), "{u:?}");
}

#[tokio::test]
async fn a_run_that_names_a_record_without_a_source_is_refused_before_requests() {
    // A reference is not authorization when no source can resolve its record.
    let s = site(|_| {
        Router::new()
            .route(
                "/",
                get(|| async { page("Home", r#"<a href="/billing/invoices">b</a>"#) }),
            )
            .route("/billing/invoices", get(|| async { page("Invoices", "") }))
    })
    .await;
    let dir = tempfile::tempdir().unwrap();
    let rec = record(&[&s.base], |_| {});
    let crawl = static_crawl(&format!("{}/", s.base), &rec);
    let report = run_local_with(LocalRun::new(crawl, config(dir.path(), &[])))
        .await
        .unwrap();
    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(report.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    assert!(report.pages.is_empty());
    assert!(s.requests().is_empty());
}

// ---- revocation of a running run --------------------------------------------------------------

/// A strategy that proposes nothing and takes `gap` to say so; on its `revoke_on`-th call it
/// revokes the record.
struct RevokingPacer {
    source: StaticAuthorizationSource,
    record: AuthorizationRecordId,
    revoke_on: usize,
    gap: Duration,
    calls: Arc<AtomicUsize>,
    revoked_at: Arc<Mutex<Option<Instant>>>,
}

#[async_trait]
impl Strategy for RevokingPacer {
    async fn propose(&self, _: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if n + 1 == self.revoke_on {
            assert!(self
                .source
                .revoke(self.record, SystemClock.now(), "takedown request"));
            *self.revoked_at.lock().unwrap() = Some(Instant::now());
        }
        tokio::time::sleep(self.gap).await;
        Ok(Vec::new())
    }

    fn name(&self) -> &'static str {
        "test_revoking_pacer"
    }

    fn version(&self) -> u32 {
        1
    }
}

fn three_pages() -> FakeScript {
    let page = |url: &str, title: &str, links: &[(&str, &str)]| {
        let mut p = FakePage::new(url).title(title);
        for (key, to) in links {
            p = p
                .node(FakeAxSpec::link(*key, format!("Go to {key}"), *to))
                .on_click(key, vec![FakeEffect::Navigate((*to).to_owned())]);
        }
        p
    };
    FakeScript::new()
        .page(page("https://example.test/", "Home", &[("a", "/a"), ("b", "/b")]))
        .page(page("https://example.test/a", "A", &[("home", "/"), ("b", "/b")]))
        .page(page("https://example.test/b", "B", &[("home", "/"), ("a", "/a")]))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_the_record_mid_run_stops_a_dynamic_run_within_one_recheck_interval() {
    let rec = record(&["https://example.test"], |_| {});
    let source = StaticAuthorizationSource::new(rec.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    let revoked_at = Arc::new(Mutex::new(None));
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(20_261_028);
    crawl.limits.interactions = 200;
    crawl.limits.states = 200;
    crawl.safety.authorization_record_ref = Some(rec.id);
    let mut strategies = build_strategies(&crawl.dynamic).unwrap();
    strategies.push(Arc::new(RevokingPacer {
        source: source.clone(),
        record: rec.id,
        revoke_on: 2,
        gap: Duration::from_millis(400),
        calls: Arc::clone(&calls),
        revoked_at: Arc::clone(&revoked_at),
    }));

    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let cfg = WorkerConfig {
        authorization_recheck: Duration::from_millis(100),
        ..config(dir.path(), &[])
    };
    let backend = Arc::new(FakeBackend::new(three_pages()));
    let report = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_stores(stores.clone())
            .with_backend(backend)
            .with_authorization(rec)
            .with_authorization_source(Arc::new(source))
            .with_strategies(strategies),
    )
    .await
    .unwrap();
    let finished = Instant::now();

    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(report.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    let revoked = revoked_at.lock().unwrap().expect("the pacer revoked the record");
    // the strategy that revoked was still inside its 400 ms round; nothing runs after it
    assert!(
        finished.duration_since(revoked) < Duration::from_secs(3),
        "the run outlived the revocation by {:?}",
        finished.duration_since(revoked)
    );
    assert!(
        calls.load(Ordering::SeqCst) <= 3,
        "{} rounds",
        calls.load(Ordering::SeqCst)
    );
    assert!(
        report.sessions.iter().all(|s| s.status.is_terminal()),
        "{:?}",
        report.sessions
    );
    let events = event_payloads(&stores, report.run_id, "authorization.revoked").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["reason"], "revoked");
    assert!(
        events[0].get("stage").is_none(),
        "a mid-run stop is not an admission refusal"
    );
}

#[tokio::test]
async fn revoking_the_record_mid_run_stops_the_url_plane_and_abandons_the_frontier() {
    let rec = record(&["http://127.0.0.1"], |_| {});
    let source = StaticAuthorizationSource::new(rec.clone());
    let id = rec.id;
    let revoker = source.clone();
    let s = site(move |_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        r#"<a href="/a">a</a> <a href="/b">b</a> <a href="/c">c</a> <a href="/d">d</a>"#,
                    )
                }),
            )
            .route(
                "/a",
                get(move || {
                    let revoker = revoker.clone();
                    async move {
                        // the operator revokes the record while the run is fetching this page
                        assert!(revoker.revoke(id, SystemClock.now(), "takedown request"));
                        page("A", "")
                    }
                }),
            )
            .route("/b", get(|| async { page("B", "") }))
            .route("/c", get(|| async { page("C", "") }))
            .route("/d", get(|| async { page("D", "") }))
    })
    .await;
    // the record names the site's origin; the sample record has to cover it
    let rec = AuthorizationRecord {
        origins: vec![s.base.clone()],
        ..rec
    };
    source.insert(rec.clone());
    let crawl = static_crawl(&format!("{}/", s.base), &rec);
    let (report, stores) = local(crawl, rec, &[], |run| {
        run.with_authorization_source(Arc::new(source))
    })
    .await;

    assert_eq!(report.status, RunStatus::Failed);
    assert_eq!(report.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    assert_eq!(s.count("/a"), 1);
    for later in ["/b", "/c", "/d"] {
        assert_eq!(s.count(later), 0, "{later} was requested after the revocation");
    }
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    for later in ["/b", "/c", "/d"] {
        assert_eq!(
            row(&frontier, &format!("{}{later}", s.base)).status,
            FrontierStatus::Abandoned,
            "{later}"
        );
    }
    // `/a` is in flight when the record is revoked: the guard's stop token aborts it
    // (abandoned), or its response lands first and the commit refuses it (policy blocked).
    let in_flight = row(&frontier, &format!("{}/a", s.base)).status;
    let expected_abandoned = match in_flight {
        FrontierStatus::Abandoned => 4,
        FrontierStatus::PolicyBlocked => 3,
        other => panic!("/a ended {other:?} after the revocation"),
    };
    assert_eq!(
        report.counters.urls.abandoned, expected_abandoned,
        "{:?}",
        report.counters.urls
    );
    assert!(report.counters.urls.invariants_hold());
    let events = event_payloads(&stores, report.run_id, "authorization.revoked").await;
    assert_eq!(events.len(), 1, "{events:?}");
}

// ---- the lease loop ---------------------------------------------------------------------------

/// What the API does: persist a queued run and its sessions.
async fn enqueue(stores: &Stores, mut crawl: CreateCrawl) -> CrawlRunId {
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    run.id
}

fn worker_cfg(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        idle_exit_after: Some(Duration::from_millis(600)),
        max_sessions: 1,
        ..config(dir, &[])
    }
}

/// Observe the real authorization recheck performed after worker drain has begun.
struct DrainObservedSource {
    inner: StaticAuthorizationSource,
    drain: CancellationToken,
    observed: tokio::sync::Notify,
}

#[async_trait]
impl AuthorizationSource for DrainObservedSource {
    async fn fetch(&self, id: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError> {
        let record = self.inner.fetch(id).await?;
        if self.drain.is_cancelled() {
            self.observed.notify_one();
        }
        Ok(record)
    }
}

#[derive(Clone, Copy)]
enum StopDuringDrain {
    Revocation,
    CallerCancellation,
}

async fn stop_interrupts_an_in_flight_legacy_drain(stop: StopDuringDrain) {
    let started = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&started);
    let s = site(move |_| {
        Router::new().route(
            "/",
            get(move || {
                let signal = Arc::clone(&signal);
                async move {
                    signal.notify_one();
                    // Never release the response: a hard stop must interrupt the client.
                    std::future::pending::<axum::response::Response>().await
                }
            }),
        )
    })
    .await;
    let rec = record(&[&s.base], |record| {
        record.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
    });
    let drain = CancellationToken::new();
    let source = Arc::new(DrainObservedSource {
        inner: StaticAuthorizationSource::new(rec.clone()),
        drain: drain.clone(),
        observed: tokio::sync::Notify::new(),
    });
    let dir = tempfile::tempdir().unwrap();
    // Production URL TTL: the stop poll must not inherit its ten-second heartbeat cadence.
    let store = Arc::new(MemoryStore::new());
    let mut stores = Stores::over_memory(store, dir.path())
        .await
        .unwrap()
        .with_authorization_source(source.clone());
    stores.tenant = rec.tenant;
    let mut crawl = static_crawl(&format!("{}/", s.base), &rec);
    crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    crawl.scope.known_files.clear();
    let run = enqueue(&stores, crawl).await;
    let mut cfg = worker_cfg(dir.path());
    cfg.authorization_recheck = Duration::from_millis(30);
    cfg.egress.extra_ports = vec![s.port];
    cfg.egress.extra_allow = vec!["127.0.0.0/8".parse().unwrap()];
    let worker = tokio::spawn(run_with(cfg, stores.clone(), None, drain.clone()));
    tokio::time::timeout(Duration::from_secs(10), started.notified())
        .await
        .expect("legacy request started");
    drain.cancel();
    tokio::time::timeout(Duration::from_secs(3), source.observed.notified())
        .await
        .expect("in-flight request entered worker drain");
    match stop {
        StopDuringDrain::Revocation => {
            assert!(source
                .inner
                .revoke(rec.id, SystemClock.now(), "takedown during drain"));
        }
        StopDuringDrain::CallerCancellation => {
            stores
                .runs
                .set_status(run, RunStatus::Cancelled, Some(TerminalReason::Cancelled))
                .await
                .unwrap();
        }
    }
    tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .expect("hard stop interrupted the response without releasing the listener")
        .unwrap()
        .unwrap();
    assert!(stores.pages.list(run).await.unwrap().is_empty());
    let rows = stores.frontier.list(run).await.unwrap();
    assert_eq!(
        row(&rows, &format!("{}/", s.base)).status,
        FrontierStatus::Abandoned
    );
    assert_eq!(s.count("/"), 1, "no retry or replacement authority after drain");
    if matches!(stop, StopDuringDrain::Revocation) {
        assert_eq!(
            event_payloads(&stores, run, "authorization.revoked").await.len(),
            1
        );
    }
}

#[tokio::test]
async fn revocation_after_worker_drain_interrupts_the_in_flight_legacy_response() {
    stop_interrupts_an_in_flight_legacy_drain(StopDuringDrain::Revocation).await;
}

#[tokio::test]
async fn caller_cancellation_after_worker_drain_interrupts_the_in_flight_legacy_response() {
    stop_interrupts_an_in_flight_legacy_drain(StopDuringDrain::CallerCancellation).await;
}

/// Pause a real heartbeat so a test can transfer its actual lease before the check resumes.
struct HeldRoleHeartbeat {
    inner: Arc<dyn crawlx_storage::LeaseRepo>,
    granted: Mutex<Option<crawlx_storage::SessionLease>>,
    pause: std::sync::atomic::AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
    lost: tokio::sync::Notify,
}

#[async_trait]
impl crawlx_storage::LeaseRepo for HeldRoleHeartbeat {
    async fn now(&self) -> Result<crawlx_core::Timestamp, crawlx_core::StoreError> {
        self.inner.now().await
    }
    async fn active_runs(&self) -> Result<Vec<crawlx_storage::ActiveRun>, crawlx_core::StoreError> {
        self.inner.active_runs().await
    }
    async fn claim_session(
        &self,
        run: CrawlRunId,
        worker: crawlx_core::WorkerId,
        parallel: bool,
    ) -> Result<Option<crawlx_storage::SessionLease>, crawlx_core::StoreError> {
        let lease = self.inner.claim_session(run, worker, parallel).await?;
        if let Some(lease) = &lease {
            *self.granted.lock().unwrap() = Some(lease.clone());
        }
        Ok(lease)
    }
    async fn heartbeat(
        &self,
        lease: &crawlx_storage::SessionLease,
    ) -> Result<crawlx_core::Timestamp, crawlx_core::StoreError> {
        if self.pause.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let result = self.inner.heartbeat(lease).await;
        if matches!(result, Err(crawlx_core::StoreError::LeaseLost)) {
            self.lost.notify_one();
        }
        result
    }
    async fn release(
        &self,
        lease: &crawlx_storage::SessionLease,
        to: SessionStatus,
    ) -> Result<(), crawlx_core::StoreError> {
        self.inner.release(lease, to).await
    }
    async fn reap(
        &self,
        now: crawlx_core::Timestamp,
    ) -> Result<crawlx_storage::ReapReport, crawlx_core::StoreError> {
        self.inner.reap(now).await
    }
    async fn reap_frontier(
        &self,
        now: crawlx_core::Timestamp,
        attempts: u16,
    ) -> Result<crawlx_storage::leases::FrontierReap, crawlx_core::StoreError> {
        self.inner.reap_frontier(now, attempts).await
    }
    async fn heartbeat_frontier(
        &self,
        worker: crawlx_core::WorkerId,
        leases: &[(i64, i64)],
    ) -> Result<Vec<i64>, crawlx_core::StoreError> {
        self.inner.heartbeat_frontier(worker, leases).await
    }
    fn url_batch_ttl(&self) -> Duration {
        self.inner.url_batch_ttl()
    }
    async fn admission(&self) -> Result<crawlx_storage::AdmissionMode, crawlx_core::StoreError> {
        self.inner.admission().await
    }
}

#[tokio::test]
async fn queued_hybrid_role_fence_loss_and_worker_drain_do_not_finish_the_held_response() {
    let started = Arc::new(tokio::sync::Notify::new());
    let signal = Arc::clone(&started);
    let s = site(move |_| {
        Router::new().route(
            "/",
            get(move || {
                let signal = Arc::clone(&signal);
                async move {
                    signal.notify_one();
                    std::future::pending::<axum::response::Response>().await
                }
            }),
        )
    })
    .await;
    let rec = record(&[&s.base], |record| {
        record.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
    });
    let dir = tempfile::tempdir().unwrap();
    let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap()
        .with_authorization_source(Arc::new(StaticAuthorizationSource::new(rec.clone())));
    stores.tenant = rec.tenant;
    let leases = Arc::new(HeldRoleHeartbeat {
        inner: Arc::clone(&stores.leases),
        granted: Mutex::new(None),
        pause: std::sync::atomic::AtomicBool::new(true),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        lost: tokio::sync::Notify::new(),
    });
    stores.leases = leases.clone();
    let mut crawl = static_crawl(&format!("{}/", s.base), &rec);
    crawl.mode = CrawlMode::Hybrid;
    // The first actual keepalive is one full protocol interval after session admission.
    // Keep the original held request alive across that interval; never extend it on drain.
    crawl.fetch.timeout_ms = u32::try_from((crawlx_scheduler::HEARTBEAT_INTERVAL * 3).as_millis()).unwrap();
    crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    crawl.scope.known_files.clear();
    let run = enqueue(&stores, crawl).await;
    let mut cfg = worker_cfg(dir.path());
    cfg.egress.extra_ports = vec![s.port];
    cfg.egress.extra_allow = vec!["127.0.0.0/8".parse().unwrap()];
    let backend = Arc::new(FakeBackend::new(
        FakeScript::new().page(FakePage::new(&format!("{}/", s.base))),
    ));
    let drain = CancellationToken::new();
    let worker = tokio::spawn(run_with(cfg, stores.clone(), Some(backend), drain.clone()));
    tokio::time::timeout(Duration::from_secs(10), started.notified())
        .await
        .unwrap();
    tokio::time::timeout(
        crawlx_scheduler::HEARTBEAT_INTERVAL + Duration::from_secs(3),
        leases.entered.notified(),
    )
    .await
    .expect("first real role heartbeat follows the full protocol interval");
    let original = leases
        .granted
        .lock()
        .unwrap()
        .clone()
        .expect("actual granted role lease");
    leases
        .inner
        .release(&original, SessionStatus::Recovering)
        .await
        .unwrap();
    let replacement = leases
        .inner
        .claim_session_exact(run, original.session.id, crawlx_core::WorkerId::new(), false)
        .await
        .unwrap()
        .expect("real replacement role lease");
    assert!(replacement.fencing_token > original.fencing_token);
    // Both real stop causes exist before the held HTTP response can complete.
    drain.cancel();
    leases.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), leases.lost.notified())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .expect("ambiguous hybrid cancellation must not drain the held response")
        .unwrap()
        .unwrap();
    assert!(stores.pages.list(run).await.unwrap().is_empty());
    let rows = stores.frontier.list(run).await.unwrap();
    assert_eq!(
        row(&rows, &format!("{}/", s.base)).status,
        FrontierStatus::Pending
    );
    assert_eq!(s.count("/"), 1);
    leases.inner.heartbeat(&replacement).await.unwrap();
    assert_eq!(
        stores
            .runs
            .list_sessions(run)
            .await
            .unwrap()
            .into_iter()
            .find(|session| session.id == replacement.session.id)
            .unwrap()
            .status,
        replacement.session.status
    );
}

fn dynamic_crawl(record: &AuthorizationRecord) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    c.mode = CrawlMode::Dynamic;
    c.seed = Some(20_261_028);
    c.limits.interactions = 100_000;
    c.limits.states = 100_000;
    c.safety.authorization_record_ref = Some(record.id);
    c
}

/// A page that never exhausts: every action is novel because the page keeps growing.
fn endless_page() -> FakeScript {
    FakeScript::new().page(
        FakePage::new("https://example.test/")
            .node(FakeAxSpec::button("more", "Show more").attr("aria-expanded", "false"))
            .on_click("more", vec![FakeEffect::Nothing]),
    )
}

#[tokio::test]
async fn the_lease_loop_refuses_a_run_whose_stored_record_is_revoked_expired_or_missing() {
    let now = SystemClock.now();
    let cases: [(&str, Option<Tweak>); 3] = [
        (
            "revoked",
            Some(Box::new(move |r| r.revoked_at = Some(now - Span::seconds(5)))),
        ),
        (
            "expired",
            Some(Box::new(move |r| {
                r.valid_from = now - Span::hours(3);
                r.valid_to = now - Span::minutes(1);
            })),
        ),
        ("missing", None),
    ];
    for (reason, tweak) in cases {
        let rec = record(&["https://example.test"], |_| {});
        let source = StaticAuthorizationSource::default();
        if let Some(tweak) = tweak {
            let mut stored = rec.clone();
            tweak(&mut stored);
            source.insert(stored);
        }
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryStore::new());
        let stores = Stores::over_memory(store, dir.path())
            .await
            .unwrap()
            .with_authorization_source(Arc::new(source));
        let run = enqueue(&stores, dynamic_crawl(&rec)).await;
        let backend = Arc::new(FakeBackend::new(endless_page()));
        run_with(
            worker_cfg(dir.path()),
            stores.clone(),
            Some(backend.clone()),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        let row = stores.runs.get(run).await.unwrap();
        assert_eq!(row.status, RunStatus::Failed, "{reason}");
        assert_eq!(
            row.terminal_reason,
            Some(TerminalReason::AuthorizationRevoked),
            "{reason}"
        );
        assert!(
            backend.context_handles().is_empty(),
            "{reason}: a browser context was opened"
        );
        let sessions = stores.runs.list_sessions(run).await.unwrap();
        assert!(
            sessions.iter().all(|s| s.status != SessionStatus::Completed),
            "{reason}"
        );
        let events = event_payloads(&stores, run, "authorization.revoked").await;
        assert_eq!(events.len(), 1, "{reason}: {events:?}");
        assert_eq!(events[0]["reason"], reason);
        assert_eq!(events[0]["stage"], "admission");
    }
}

/// Where in the run the record is revoked.
enum Trigger {
    /// As soon as one session of the run has completed: exactly between two sessions.
    SessionCompleted,
    /// As soon as the run has journaled this many actions: in the middle of a session.
    ActionsJournaled(usize),
}

/// A source that revokes the record the first time it is read after `trigger`, so a revocation
/// lands at an exact point of the run whatever the speed of the machine.
struct RevokeWhen {
    inner: StaticAuthorizationSource,
    store: Arc<MemoryStore>,
    run: Mutex<Option<CrawlRunId>>,
    trigger: Trigger,
    revoked_at: Mutex<Option<Instant>>,
}

impl RevokeWhen {
    fn new(inner: StaticAuthorizationSource, store: &Arc<MemoryStore>, trigger: Trigger) -> Arc<Self> {
        Arc::new(Self {
            inner,
            store: Arc::clone(store),
            run: Mutex::new(None),
            trigger,
            revoked_at: Mutex::new(None),
        })
    }

    fn revoked_at(&self) -> Option<Instant> {
        *self.revoked_at.lock().unwrap()
    }
}

#[async_trait]
impl AuthorizationSource for RevokeWhen {
    async fn fetch(&self, record: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError> {
        let run = *self.run.lock().unwrap();
        if let (Some(run), None) = (run, self.revoked_at()) {
            let due = match self.trigger {
                Trigger::SessionCompleted => RunRepo::list_sessions(self.store.as_ref(), run)
                    .await
                    .unwrap()
                    .iter()
                    .any(|s| s.status == SessionStatus::Completed),
                Trigger::ActionsJournaled(n) => {
                    ActionJournal::list(self.store.as_ref(), run, None)
                        .await
                        .unwrap()
                        .len()
                        >= n
                }
            };
            if due {
                assert!(self.inner.revoke(record, SystemClock.now(), "takedown request"));
                *self.revoked_at.lock().unwrap() = Some(Instant::now());
            }
        }
        self.inner.fetch(record).await
    }
}

/// `n` pages, each linking to every other page: `n·(n−1)` click keys.
fn mesh(n: usize) -> FakeScript {
    let path = |i: usize| if i == 0 { "/".to_owned() } else { format!("/p{i}") };
    let mut script = FakeScript::new();
    for i in 0..n {
        let mut page = FakePage::new(&format!("https://example.test{}", path(i))).title(format!("Page {i}"));
        for j in (0..n).filter(|j| *j != i) {
            let key = format!("to{j}");
            page = page
                .node(FakeAxSpec::link(key.clone(), format!("Go to {j}"), path(j)))
                .on_click(&key, vec![FakeEffect::Navigate(path(j))]);
        }
        script = script.page(page);
    }
    script
}

#[tokio::test]
async fn revoking_the_stored_record_stops_a_leased_run_within_one_recheck_interval() {
    let rec = record(&["https://example.test"], |record| {
        record.robots_override_acknowledged = true;
    });
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let source = RevokeWhen::new(
        StaticAuthorizationSource::new(rec.clone()),
        &store,
        Trigger::ActionsJournaled(3),
    );
    let mut stores = Stores::over_memory(Arc::clone(&store), dir.path())
        .await
        .unwrap()
        .with_authorization_source(source.clone());
    stores.tenant = rec.tenant;
    let mut crawl = dynamic_crawl(&rec);
    // Fake pages make no HTTP requests; authorize the override instead of contacting example.test.
    crawl.safety.respect_robots_txt = false;
    let run = enqueue(&stores, crawl).await;
    *source.run.lock().unwrap() = Some(run);
    let interval = Duration::from_millis(30);
    let cfg = WorkerConfig {
        authorization_recheck: interval,
        ..worker_cfg(dir.path())
    };
    // 90 click keys: far more than the run does before the 30 ms recheck finds the revocation
    let backend = Arc::new(FakeBackend::new(mesh(10)));
    let worker = {
        let stores = stores.clone();
        tokio::spawn(async move { run_with(cfg, stores, Some(backend), CancellationToken::new()).await })
    };
    let seen_terminal = loop {
        if stores.runs.get(run).await.unwrap().status.is_terminal() {
            break Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let revoked = source
        .revoked_at()
        .expect("the source revoked the record after three actions");
    let stopped_after = seen_terminal.duration_since(revoked);
    assert!(
        stopped_after < interval + Duration::from_secs(3),
        "stopped {stopped_after:?} after the revocation with a {interval:?} recheck interval"
    );
    tokio::time::timeout(Duration::from_secs(15), worker)
        .await
        .expect("the worker exits once idle")
        .unwrap()
        .unwrap();

    let row = stores.runs.get(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Failed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    let actions = stores.journal.list(run, None).await.unwrap().len();
    assert!((3..60).contains(&actions), "{actions} actions journaled");
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    assert!(
        sessions
            .iter()
            .all(|s| s.status == crawlx_core::repo::SessionStatus::Failed),
        "{sessions:?}"
    );
    let events = event_payloads(&stores, run, "authorization.revoked").await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0]["reason"], "revoked");
}

#[tokio::test]
async fn a_record_revoked_between_two_sessions_keeps_the_second_one_from_starting() {
    let rec = record(&["https://example.test"], |record| {
        record.robots_override_acknowledged = true;
    });
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let source = RevokeWhen::new(
        StaticAuthorizationSource::new(rec.clone()),
        &store,
        Trigger::SessionCompleted,
    );
    let mut stores = Stores::over_memory(Arc::clone(&store), dir.path())
        .await
        .unwrap()
        .with_authorization_source(source.clone());
    stores.tenant = rec.tenant;
    let mut crawl = dynamic_crawl(&rec);
    // Fake pages make no HTTP requests; authorize the override instead of contacting example.test.
    crawl.safety.respect_robots_txt = false;
    crawl.limits.interactions = 1_000;
    crawl.roles = ["alice", "bob"]
        .into_iter()
        .map(|name| Role {
            name: name.to_owned(),
            credential_ref: None,
            login_plan: None,
            replica_base_url: None,
        })
        .collect();
    let run = enqueue(&stores, crawl).await;
    *source.run.lock().unwrap() = Some(run);
    // a finite page: alice's session completes on its own
    let backend = Arc::new(FakeBackend::new(three_pages()));
    run_with(
        worker_cfg(dir.path()),
        stores.clone(),
        Some(backend.clone()),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let row = stores.runs.get(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Failed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    let completed = sessions
        .iter()
        .filter(|s| s.status == SessionStatus::Completed)
        .count();
    assert_eq!(completed, 1, "alice's session ran, bob's did not: {sessions:?}");
    assert_eq!(
        backend.context_handles().len(),
        1,
        "only the first session ever opened a browser context"
    );
    let events = event_payloads(&stores, run, "authorization.revoked").await;
    assert_eq!(events.len(), 1, "{events:?}");
}

// ---- the kernel is narrowed by the record -----------------------------------------------------

#[tokio::test]
async fn the_records_permitted_risk_classes_narrow_the_kernel_of_the_run() {
    let script = FakeScript::new().page(
        FakePage::new("https://example.test/")
            .title("Home")
            .node(FakeAxSpec::button("b", "Details"))
            .on_click("b", vec![FakeEffect::Nothing]),
    );
    let attempted = |permitted: Vec<crawlx_core::safety::RiskClass>| {
        let script = script.clone();
        async move {
            let rec = record(&["https://example.test"], |r| {
                r.permitted_risk_classes = permitted.into_iter().collect();
            });
            let mut crawl = dynamic_crawl(&rec);
            crawl.limits.interactions = 20;
            crawl.safety.profile = SafetyProfile::TestEnvironment;
            let dir = tempfile::tempdir().unwrap();
            let report = run_local_with(
                LocalRun::new(crawl, config(dir.path(), &[]))
                    .with_backend(Arc::new(FakeBackend::new(script)))
                    .with_authorization(rec),
            )
            .await
            .unwrap();
            report.counters.interactions.attempted
        }
    };
    // test_environment allows the plain button; a record that permits no class denies it
    assert!(attempted(crawlx_core::safety::RiskClass::PERMITTABLE.to_vec()).await >= 1);
    assert_eq!(attempted(Vec::new()).await, 0);
}

// ---- test_environment without a record --------------------------------------------------------

/// A no-record run under `profile` against a loopback fixture, with the deployment allowlist
/// `allowlist` (`None`: the deployment sets no list). Returns the pages fetched and the requests
/// the site saw.
async fn loopback_run(profile: SafetyProfile, allowlist: Option<&[&str]>) -> (usize, usize) {
    let s = site(|_| Router::new().route("/", get(|| async { page("Home", "") }))).await;
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", s.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.safety.profile = profile;
    crawl.politeness.delay_ms = 0;
    let lists = allowlist.map(|nets| {
        SharedEgressLists::new(
            EgressLists::new(
                Some(nets.iter().map(|n| n.parse().unwrap()).collect()),
                Vec::<String>::new(),
            )
            .unwrap(),
        )
    });
    let mut cfg = config(dir.path(), &[]);
    cfg.egress.lists = lists;
    let report = run_local_with(LocalRun::new(crawl, cfg)).await.unwrap();
    (report.pages.len(), s.requests().len())
}

#[tokio::test]
async fn a_test_environment_run_without_a_record_reaches_loopback_only_when_the_allowlist_names_it() {
    let (pages, requests) = loopback_run(SafetyProfile::TestEnvironment, Some(&["127.0.0.0/8"])).await;
    assert_eq!(pages, 1, "the allowlist names loopback");
    assert!(requests >= 1);

    for (profile, allowlist, why) in [
        (
            SafetyProfile::TestEnvironment,
            Some(vec!["10.0.0.0/8"]),
            "the allowlist names other networks",
        ),
        (
            SafetyProfile::TestEnvironment,
            Some(vec![]),
            "an empty allowlist exempts nothing",
        ),
        (
            SafetyProfile::TestEnvironment,
            None,
            "the deployment sets no list",
        ),
        (
            SafetyProfile::ReadOnly,
            Some(vec!["127.0.0.0/8"]),
            "read_only never gets the exemption",
        ),
        (SafetyProfile::ReadOnly, None, "read_only without a list"),
    ] {
        let (pages, requests) = loopback_run(profile, allowlist.as_deref()).await;
        assert_eq!((pages, requests), (0, 0), "{why}");
    }
}

#[tokio::test]
async fn undeclared_credentials_refuse_local_lease_and_direct_context_admission() {
    for declared in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let mut rec = sample_record(stores.tenant, SystemClock.now(), &["https://example.test"]);
        rec.verified_at = Some(SystemClock.now());
        rec.test_accounts = if declared {
            vec![crawlx_policy::TestAccount {
                role: "member".to_owned(),
                credential_ref: "env://DIFFERENT".to_owned(),
            }]
        } else {
            Vec::new()
        };
        let mut crawl = CreateCrawl::new("https://example.test/".parse().unwrap());
        crawl.mode = CrawlMode::Static;
        crawl.safety.authorization_record_ref = Some(rec.id);
        crawl.roles = vec![Role {
            name: "member".to_owned(),
            credential_ref: Some(crawlx_core::secret::CredentialRef("env://ACTUAL".to_owned())),
            login_plan: None,
            replica_base_url: None,
        }];
        let source = Arc::new(StaticAuthorizationSource::new(rec.clone()));
        let stores = stores.with_authorization_source(source.clone());
        let cfg = config(dir.path(), &[]);
        let local = LocalRun::new(crawl.clone(), cfg.clone())
            .with_stores(stores.clone())
            .with_authorization(rec.clone());
        assert!(
            matches!(run_local_with(local).await, Err(WorkerError::Config(message)) if message.contains("testAccounts"))
        );

        let run = crawlx_storage::testkit::crawl_run(stores.tenant, crawl.clone());
        stores.runs.create(&run, None).await.unwrap();
        let guard = crawlx_worker::AuthorizationGuard::admit(
            run.id,
            None,
            Some(rec.id),
            source,
            Arc::new(SystemClock),
            stores.events.clone(),
            Duration::ZERO,
        )
        .await
        .unwrap();
        let context = crawlx_worker::RunContext::build(
            &run,
            &cfg,
            stores.clone(),
            None,
            None,
            CancellationToken::new(),
            None,
            Some(guard),
        )
        .await;
        assert!(matches!(context, Err(WorkerError::Config(message)) if message.contains("testAccounts")));

        stores
            .runs
            .create_sessions(&RunPlanner::sessions(run.id, &crawl))
            .await
            .unwrap();
        let worker = run_with(cfg, stores, None, CancellationToken::new()).await;
        assert!(matches!(worker, Err(WorkerError::Config(message)) if message.contains("testAccounts")));
    }
}
