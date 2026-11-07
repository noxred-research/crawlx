//! The worker process: lease loop over the in-memory store.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::repo::{CrawlRun, SessionStatus};
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_scheduler::RunPlanner;
use crawlx_storage::MemoryStore;
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{EgressConfig, Stores, WorkerConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

fn cfg(dir: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        idle_exit_after: Some(Duration::from_millis(600)),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

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

fn app() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("a", "A", "/a"))
                .on_click("a", vec![FakeEffect::Navigate("/a".into())]),
        )
        .page(
            FakePage::new("https://example.test/a")
                .title("A")
                .node(FakeAxSpec::link("h", "Home", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        )
}

#[tokio::test]
async fn leased_hybrid_preserves_imported_handler_through_http_and_browser_redirects() {
    use axum::{routing::get, Router};
    use crawlx_core::extensions::HandlerV1;
    use crawlx_core::hash::Digest;
    use crawlx_core::orchestration::RequestBatchV1;
    use crawlx_core::request::RequestEnvelopeV1;

    let html = include_str!("../../crawlx-bench/fixtures/ext-article/main.html");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let app = Router::new()
            .route(
                "/",
                get(|| async { axum::response::Redirect::temporary("/settled") }),
            )
            .route("/settled", get(move || async move { axum::response::Html(html) }));
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Hybrid;
    crawl.seed = Some(7);
    crawl.safety.allow_private_networks = true;
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.dynamic.observe_only = true;
    crawl.dynamic.always_browser_paths = vec!["^/$".into()];
    crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
    crawl.extensions.routes.insert("default".into(), HandlerV1::Skip);
    crawl
        .extensions
        .routes
        .insert("imported_article".into(), HandlerV1::DocumentItem);
    crawl.extensions.dataset = Some("items".into());
    crawl.datasets.stores.push(
        serde_json::from_value(serde_json::json!({
            "name": "items", "schemaVersion": "document_item_v1",
            "maxItems": 10, "maxBytes": 1_000_000
        }))
        .unwrap(),
    );
    let mut record = common::authorization::verified_record(&crawl, stores.tenant);
    record.robots_override_acknowledged = true;
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let mut request = RequestEnvelopeV1::get(common::canonical(&format!("{base}/")), 0, None);
    request.route = "imported_article".into();
    let run = enqueue(&stores, crawl).await;
    let append = stores
        .frontier
        .append_batch(RequestBatchV1::new(
            stores.tenant,
            run,
            "anonymous".into(),
            Digest::of("hybrid-route-fixture", b"imported-seed"),
            vec![request.clone()],
        ))
        .await
        .unwrap();
    assert_eq!(append.inserted.len(), 1);

    let final_url = format!("{base}/settled");
    let page = FakePage::new(&final_url)
        .title("River report")
        .html(html)
        .redirect_from([request.url.url.to_string()]);
    let mut script = FakeScript::new().page(page.clone());
    script.pages.insert(request.url.url.to_string(), page);
    let backend = Arc::new(FakeBackend::new(script));
    let mut config = cfg(dir.path());
    config.checkpoint_keys = Some(Arc::new(
        crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap(),
    ));
    run_with(
        config,
        stores.clone(),
        Some(backend.clone()),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    server.abort();

    let row = stores.runs.get(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Completed, "{:?}", row.terminal_reason);
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    assert!(sessions
        .iter()
        .all(|session| session.status == SessionStatus::Completed));
    let pages = stores.pages.list(run).await.unwrap();
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].metadata["dynamic_signal"], "always_browser_path");
    assert_eq!(pages[0].metadata["final_url"], final_url);
    assert_eq!(
        stores
            .frontier
            .get_request(run, append.inserted[0])
            .await
            .unwrap()
            .envelope,
        request,
    );
    let contexts = backend.context_handles();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].navigations(), vec![request.url.url.to_string()]);
    // The native default is Skip: a reconstructed default GET could not reach this document.
}

#[tokio::test]
async fn the_worker_claims_a_queued_dynamic_run_explores_it_and_finalizes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 20;
    let run = enqueue(&stores, crawl).await;
    run_with(
        cfg(dir.path()),
        stores.clone(),
        Some(Arc::new(FakeBackend::new(app()))),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let row = stores.runs.get(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Completed);
    assert!(matches!(
        row.terminal_reason,
        Some(TerminalReason::FrontierExhausted | TerminalReason::LimitReached)
    ));
    assert!(row.counters.interactions.attempted >= 2);
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    assert!(sessions.iter().all(|s| s.status == SessionStatus::Completed));
}

#[tokio::test]
async fn the_worker_seeds_and_crawls_a_queued_static_run() {
    let site = common::site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    let record = common::authorization::verified_record(&crawl, stores.tenant);
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let run = enqueue(&stores, crawl).await;
    run_with(cfg(dir.path()), stores.clone(), None, CancellationToken::new())
        .await
        .unwrap();
    let row = stores.runs.get(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Completed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::FrontierExhausted));
    assert_eq!(
        (
            row.counters.urls.discovered,
            row.counters.urls.succeeded,
            row.counters.urls.failed
        ),
        (13, 4, 1)
    );
    assert!(row.counters.urls.invariants_hold());
}

#[tokio::test]
async fn shutdown_drains_sessions_checkpoints_and_releases_them_for_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 100_000;
    crawl.limits.states = 100_000;
    // a page that never exhausts: every action is novel because the page keeps growing
    let script = FakeScript::new().page(
        FakePage::new("https://example.test/")
            .node(FakeAxSpec::button("more", "Show more").attr("aria-expanded", "false"))
            .on_click("more", vec![FakeEffect::Nothing]),
    );
    let run = enqueue(&stores, crawl).await;
    let cancel = CancellationToken::new();
    let worker = {
        let cancel = cancel.clone();
        let stores = stores.clone();
        let cfg = WorkerConfig {
            idle_exit_after: None,
            ..cfg(dir.path())
        };
        tokio::spawn(
            async move { run_with(cfg, stores, Some(Arc::new(FakeBackend::new(script))), cancel).await },
        )
    };
    // wait until the session is running, then SIGTERM-equivalent
    for _ in 0..200 {
        let s = stores.runs.list_sessions(run).await.unwrap();
        if s.iter().any(|s| s.status == SessionStatus::Running) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(10), worker)
        .await
        .expect("drained in time")
        .unwrap()
        .unwrap();
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    assert!(
        sessions
            .iter()
            .all(|s| s.status == SessionStatus::Recovering || s.status.is_terminal()),
        "{sessions:?}"
    );
    let cps = crawlx_core::repo::CheckpointRepo::list(store.as_ref(), sessions[0].id)
        .await
        .unwrap();
    assert!(cps.iter().any(|c| c.reason == "shutdown"), "{cps:?}");
}

#[tokio::test]
async fn a_recovering_session_reconciles_its_unknown_actions_before_exploring() {
    use crawlx_core::counters::ActionStatus;
    use crawlx_core::repo::ActionJournal;
    use crawlx_scheduler::Scheduler;
    use crawlx_storage::testkit;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 10;
    let run = enqueue(&stores, crawl).await;

    // a previous holder claimed the session, journaled intent for an action, then died
    let scheduler = Scheduler::new(store.clone());
    let lease = scheduler
        .lease_in_run(run, crawlx_core::WorkerId::new(), false)
        .await
        .unwrap()
        .unwrap();
    let session = lease.session.id;
    let proposal = testkit::proposal("anonymous", crawlx_core::StateClusterId::new(), 1);
    let id = ActionJournal::propose(store.as_ref(), run, session, &proposal, &testkit::allow_verdict())
        .await
        .unwrap();
    ActionJournal::intend(
        store.as_ref(),
        id,
        session,
        crawlx_core::ObservationEpoch::default(),
    )
    .await
    .unwrap();
    store.expire_session_lease(session, SystemClock.now() - chrono::Duration::hours(1));

    run_with(
        cfg(dir.path()),
        stores.clone(),
        Some(Arc::new(FakeBackend::new(app()))),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let rec = ActionJournal::get(store.as_ref(), id).await.unwrap();
    assert_eq!(
        rec.status,
        ActionStatus::Reconciled,
        "never re-executed blindly: {rec:?}"
    );
    assert!(rec.reconcile_resolution.is_some());
    let sessions = stores.runs.list_sessions(run).await.unwrap();
    assert_eq!(sessions[0].status, SessionStatus::Completed);
    assert_eq!(stores.runs.get(run).await.unwrap().status, RunStatus::Completed);
}

#[tokio::test]
async fn referenced_authorization_without_a_source_refuses_before_requests_or_actions() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let router = axum::Router::new().fallback(move || {
        counted.fetch_add(1, Ordering::SeqCst);
        async { "must not be requested" }
    });
    let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    for mode in [CrawlMode::Static, CrawlMode::Dynamic] {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(MemoryStore::new());
        let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
        let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
        crawl.mode = mode;
        crawl.safety.allow_private_networks = true;
        crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        let run = enqueue(&stores, crawl).await;
        run_with(
            cfg(dir.path()),
            stores.clone(),
            Some(Arc::new(FakeBackend::new(app()))),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let row = stores.runs.get(run).await.unwrap();
        assert_eq!(row.status, RunStatus::Failed);
        assert_eq!(row.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
        assert!(stores.journal.list(run, None).await.unwrap().is_empty());
        let sessions = stores.runs.list_sessions(run).await.unwrap();
        assert!(sessions
            .iter()
            .all(|session| session.status != SessionStatus::Running));
        assert!(sessions
            .iter()
            .all(|session| session.action_seq == 0 && session.browser.is_none()));
        assert!(stores.frontier.list(run).await.unwrap().is_empty());
    }
    server.abort();
}
