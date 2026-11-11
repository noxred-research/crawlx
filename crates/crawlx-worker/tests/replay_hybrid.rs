//! Replay of a recorded path and hybrid-mode hand-off to the browser plane.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, SafetyProfile};
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::{CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::replay::{ReplayMode, ReplayPlan, ReplayRunner, StepVerdict};
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

fn cfg(dir: &std::path::Path) -> WorkerConfig {
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

fn app() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("a", "Alpha", "/alpha"))
                .on_click("a", vec![FakeEffect::Navigate("/alpha".into())]),
        )
        .page(
            FakePage::new("https://example.test/alpha")
                .title("Alpha")
                .node(FakeAxSpec::link("b", "Beta", "/beta"))
                .on_click("b", vec![FakeEffect::Navigate("/beta".into())]),
        )
        .page(
            FakePage::new("https://example.test/beta")
                .title("Beta")
                .node(FakeAxSpec::link("h", "Back", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        )
}

fn real_clock_backend(script: FakeScript) -> Arc<FakeBackend> {
    Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(SystemClock))
            .build(),
    )
}

async fn dual_alias_scenario(stores: Stores, worker: WorkerConfig) {
    use crawlx_core::config::IdentityVersion;
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.crawl.identity.version = IdentityVersion::Dual;
    crawl.limits.interactions = 3;
    let report = run_local_with(
        LocalRun::new(crawl, worker)
            .with_backend(real_clock_backend(app()))
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert!(!report.actions.is_empty());
    let mut descriptor_actions = 0;
    for action in &report.actions {
        let aliases = stores
            .identity_aliases
            .aliases_of(report.run_id, action.key.element)
            .await
            .unwrap();
        if action.strategy == crawlx_worker::driver::DISCOVERED_URLS_STRATEGY {
            // URL-derived identities do not use either descriptor identity algorithm.
            assert_eq!(action.key.action_kind, crawlx_core::ActionKind::Navigate);
            assert_eq!(action.lane, Some(crawlx_core::TrustLane::Diagnostic));
            assert!(["/", "/alpha", "/beta"].iter().any(|path| {
                crawlx_worker::driver::discovered_url_element(&format!("https://example.test{path}"))
                    == action.key.element
            }));
            assert!(aliases.is_empty(), "synthetic URL identities have no V1/V2 pair");
            continue;
        }
        descriptor_actions += 1;
        assert!(
            aliases.iter().any(|alias| {
                alias.from_version == 2
                    && alias.to_version == 1
                    && alias.alias != alias.canonical
                    && (alias.score - 1.0).abs() < f32::EPSILON
            }),
            "missing dual-compute alias for {:?}",
            action.key.element
        );
    }
    assert!(
        descriptor_actions > 0,
        "exercise descriptor identity dual computation"
    );
    let target = report
        .actions
        .iter()
        .find(|a| a.status == ActionStatus::Succeeded)
        .unwrap();
    let plan = ReplayPlan::load(&stores, report.run_id, target.id).await.unwrap();
    assert_eq!(plan.identity_version, 1, "dual mode must decide with V1");
}

#[tokio::test]
async fn dual_mode_writes_version_pairs_in_memory() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    dual_alias_scenario(stores, cfg(dir.path())).await;
}

#[tokio::test]
async fn dual_mode_writes_version_pairs_in_postgres() {
    use crawlx_core::repo::RunRepo;
    use crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys;
    use crawlx_storage::{FsArtifactStore, Pg, PgConfig};
    let Ok(database) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
        return;
    };
    let pg = Pg::connect(
        &database,
        PgConfig {
            schema: Some(format!("t_identity_{}", uuid::Uuid::now_v7().simple())),
            ..PgConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
    let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
        .await
        .unwrap()
        .with_index(Arc::new(pg.clone()));
    let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), crawlx_core::TenantId::new());
    stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());
    dual_alias_scenario(stores, cfg(dir.path())).await;
    let versions: Vec<i16> =
        sqlx::query_scalar("SELECT DISTINCT identity_version FROM elements ORDER BY identity_version")
            .fetch_all(pg.pool())
            .await
            .unwrap();
    assert_eq!(versions, [1, 2]);
    pg.drop_schema().await.unwrap();
}

#[tokio::test]
async fn v2_replays_use_v2_and_v1_paths_refuse_v2_resolution() {
    use crawlx_core::config::IdentityVersion;
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.crawl.identity.version = IdentityVersion::V2;
    crawl.limits.interactions = 3;
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(real_clock_backend(app()))
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    let target = report
        .actions
        .iter()
        .find(|a| a.status == ActionStatus::Succeeded)
        .unwrap();
    let mut plan = ReplayPlan::load(&stores, report.run_id, target.id).await.unwrap();
    assert_eq!(plan.identity_version, 2);
    let replay = ReplayRunner::run(
        cfg(dir.path()),
        plan.clone(),
        ReplayMode::Reproduce,
        Some(real_clock_backend(app())),
        None,
    )
    .await
    .unwrap();
    assert!(replay.ok);
    plan.identity_version = 1;
    let error = ReplayRunner::run(
        cfg(dir.path()),
        plan,
        ReplayMode::Reproduce,
        Some(real_clock_backend(app())),
        None,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("replay identity version mismatch"));
}

#[tokio::test]
async fn a_recorded_path_replays_and_verifies_against_the_live_target() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 6;
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(real_clock_backend(app()))
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    let target = report
        .actions
        .iter()
        .filter(|a| a.status == ActionStatus::Succeeded)
        .nth(1)
        .expect("two succeeded actions");

    let plan = ReplayPlan::load(&stores, report.run_id, target.id).await.unwrap();
    assert_eq!(plan.steps.len(), 2);
    let verified = ReplayRunner::run(
        cfg(dir.path()),
        plan.clone(),
        ReplayMode::Verify,
        Some(real_clock_backend(app())),
        None,
    )
    .await
    .unwrap();
    assert!(verified.ok, "{verified:#?}");
    assert!(verified
        .steps
        .iter()
        .all(|s| matches!(s.verdict, StepVerdict::Matched { .. })));

    let reproduced = ReplayRunner::run(
        cfg(dir.path()),
        plan.clone(),
        ReplayMode::Reproduce,
        Some(real_clock_backend(app())),
        None,
    )
    .await
    .unwrap();
    assert!(reproduced.ok);
    assert!(reproduced
        .steps
        .iter()
        .all(|s| s.verdict == StepVerdict::Executed));

    // the target changed: the first control no longer exists, the replay stops there
    let changed = FakeScript::new().page(
        FakePage::new("https://example.test/")
            .title("Home")
            .node(FakeAxSpec::link("x", "Other", "/o")),
    );
    let broken = ReplayRunner::run(
        cfg(dir.path()),
        plan,
        ReplayMode::Reproduce,
        Some(real_clock_backend(changed)),
        None,
    )
    .await
    .unwrap();
    assert!(!broken.ok);
    assert_eq!(broken.steps.len(), 1);
    assert_eq!(broken.steps[0].verdict, StepVerdict::ElementNotFound);
}

/// A page whose only route to `/alpha` is a page-hook discovery: no AX candidates and no
/// rendered link.
fn hook_navigation_script(target: &str) -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .discovered(target, "pushState"),
        )
        .page(FakePage::new("https://example.test/alpha").title("Alpha"))
        .page(FakePage::new("https://example.test/changed").title("Changed"))
}

#[tokio::test]
async fn page_hook_navigation_replays_without_ax_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let script = hook_navigation_script("/alpha");
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.dynamic.page_hooks = true;
    crawl.limits.interactions = 1;
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(real_clock_backend(script.clone()))
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    let target = report
        .actions
        .iter()
        .find(|action| action.status == ActionStatus::Succeeded)
        .expect("a page-hook destination supplies a navigation target without AX candidates");
    assert_eq!(target.strategy, crawlx_worker::driver::DISCOVERED_URLS_STRATEGY);
    let plan = ReplayPlan::load(&stores, report.run_id, target.id).await.unwrap();
    assert_eq!(plan.steps.len(), 1);
    let verified = ReplayRunner::run(
        cfg(dir.path()),
        plan.clone(),
        ReplayMode::Verify,
        Some(real_clock_backend(script)),
        None,
    )
    .await
    .unwrap();
    assert!(verified.ok, "{verified:#?}");
    assert_eq!(verified.steps.len(), 1);
    assert!(verified
        .steps
        .iter()
        .all(|step| matches!(step.verdict, StepVerdict::Matched { .. })));

    let broken = ReplayRunner::run(
        cfg(dir.path()),
        plan,
        ReplayMode::Verify,
        Some(real_clock_backend(hook_navigation_script("/changed"))),
        None,
    )
    .await
    .unwrap();
    assert!(!broken.ok);
    assert_eq!(broken.steps.len(), 1);
    assert_eq!(broken.steps[0].verdict, StepVerdict::ElementNotFound);
}

/// Recording a rendered document never turns its HTML links into navigation proposals: with
/// page hooks off and no AX candidates the session has nothing to execute.
#[tokio::test]
async fn rendered_html_links_alone_add_no_navigation_proposal() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let script = FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .html("<html><body><a href='/alpha'>Alpha</a></body></html>"),
        )
        .page(FakePage::new("https://example.test/alpha").title("Alpha"));
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.dynamic.page_hooks = false;
    crawl.limits.interactions = 1;
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(real_clock_backend(script))
            .with_stores(stores),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    assert!(
        report
            .actions
            .iter()
            .all(|action| action.strategy != crawlx_worker::driver::DISCOVERED_URLS_STRATEGY),
        "{:#?}",
        report.actions
    );
}

/// A submit control inside a `<form method=post>`: the descriptor the replay admits on has no
/// form facts, so admission classifies it `Unclassified`; the live target then reports
/// `form-method=post` (`PersistentWriteOwn`) and the kernel refuses the raise at
/// confirmation. The driver re-admits once on those live facts; the replay must do the same
/// or every recorded path through such a control reports `confirm_denied` (the G1 gate on
/// real Chromium matched 0/10 before this).
fn form_app() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(
                    FakeAxSpec::button("go", "Continue")
                        .live_attr("form-method", "post")
                        .live_attr("form-action", "/next"),
                )
                .on_click("go", vec![FakeEffect::Navigate("/next".into())]),
        )
        .page(
            FakePage::new("https://example.test/next")
                .title("Next")
                .node(FakeAxSpec::link("h", "Home", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_step_whose_live_facts_raise_the_risk_class_is_readmitted_and_matches() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.safety.profile = SafetyProfile::TestEnvironment;
    crawl.limits.interactions = 4;
    let report = run_local_with(
        LocalRun::new(crawl, cfg(dir.path()))
            .with_backend(real_clock_backend(form_app()))
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(report.status, RunStatus::Completed);
    let submit = report
        .actions
        .iter()
        .find(|a| a.status == ActionStatus::Succeeded && a.key.route_template.0 == "/")
        .expect("the recorded run exercised the submit control");

    let plan = ReplayPlan::load(&stores, report.run_id, submit.id).await.unwrap();
    let verified = ReplayRunner::run(
        cfg(dir.path()),
        plan,
        ReplayMode::Verify,
        Some(real_clock_backend(form_app())),
        None,
    )
    .await
    .unwrap();
    assert!(verified.ok, "{verified:#?}");
    assert!(verified
        .steps
        .iter()
        .all(|s| matches!(s.verdict, StepVerdict::Matched { .. })));
}

#[tokio::test]
async fn hybrid_mode_hands_spa_pages_to_the_browser_plane() {
    use axum::routing::get;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app_router = axum::Router::new().route(
        "/",
        get(|| async {
            (
                [("content-type", "text/html")],
                r#"<html><body><div id="app"></div><script type="module" src="/main.js"></script></body></html>"#,
            )
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app_router).await;
    });
    let url = format!("http://127.0.0.1:{port}/");
    let script = FakeScript::new()
        .page(
            FakePage::new(&url)
                .title("SPA")
                .node(FakeAxSpec::link("l", "Inside", format!("{url}inside")))
                .on_click("l", vec![FakeEffect::Navigate(format!("{url}inside"))]),
        )
        .page(
            FakePage::new(&format!("{url}inside"))
                .title("Inside")
                .node(FakeAxSpec::link("b", "Back", &url)),
        );
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&url).unwrap());
    crawl.mode = CrawlMode::Hybrid;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.limits.interactions = 10;
    let report =
        run_local_with(LocalRun::new(crawl, cfg(dir.path())).with_backend(real_clock_backend(script)))
            .await
            .unwrap();
    server.abort();
    assert_eq!(report.status, RunStatus::Completed);
    // the static plane fetched the shell page ...
    assert_eq!(report.counters.urls.succeeded, 1);
    // ... and the browser plane explored it
    assert!(
        report.counters.interactions.attempted >= 1,
        "{:?}",
        report.counters
    );
    assert!(report.states.iter().any(|s| s.url.url.path() == "/inside"));
}

#[tokio::test]
async fn hybrid_mode_honors_always_browser_paths_for_plain_pages() {
    use axum::routing::get;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Two plain server-rendered pages with no dynamic signal at all; only `/app/...` is
    // covered by the explicit rule.
    let plain = |title: &'static str| {
        move || async move {
            (
                [("content-type", "text/html")],
                format!(
                    "<html><head><title>{title}</title></head><body><h1>{title}</h1><p>{}</p><a href=\"/app/board\">Board</a><a href=\"/about\">About</a></body></html>",
                    "plain server rendered text ".repeat(40)
                ),
            )
        }
    };
    let app_router = axum::Router::new()
        .route("/", get(plain("Home")))
        .route("/about", get(plain("About")))
        .route("/app/board", get(plain("Board")));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app_router).await;
    });
    let url = format!("http://127.0.0.1:{port}/");
    let board = format!("{url}app/board");
    let script = FakeScript::new()
        // The browser's view of the home page has no link to the board: only the explicit
        // rule can bring the board into a session.
        .page(FakePage::new(&url).title("Home"))
        .page(
            FakePage::new(&board)
                .title("Board")
                .node(FakeAxSpec::link("b", "Home", &url)),
        );
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&url).unwrap());
    crawl.mode = CrawlMode::Hybrid;
    crawl.dynamic.always_browser_paths = vec!["^/app/".to_owned()];
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.limits.interactions = 10;
    let report =
        run_local_with(LocalRun::new(crawl, cfg(dir.path())).with_backend(real_clock_backend(script)))
            .await
            .unwrap();
    server.abort();
    assert_eq!(report.status, RunStatus::Completed);
    assert_eq!(report.counters.urls.succeeded, 3, "{:?}", report.counters);
    // The rule-matched page was handed to the browser plane and observed there.
    assert!(
        report.states.iter().any(|s| s.url.url.path() == "/app/board"),
        "{:?}",
        report
            .states
            .iter()
            .map(|s| s.url.url.path().to_owned())
            .collect::<Vec<_>>()
    );
    assert!(!report.states.iter().any(|s| s.url.url.path() == "/about"));
}

#[tokio::test]
async fn retained_body_replay_runs_the_parser_pipeline_without_target_requests() {
    use crawlx_core::cache::CachePolicyV1;
    use crawlx_core::config::{HostScope, SitemapMode};
    use crawlx_core::extraction::ParserPipelineV1;

    let site = common::site::start().await;
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_110);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.host_scope = HostScope::None;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files.clear();
    crawl.scope.max_discovery_depth = 0;
    crawl.cache_principal = Some(uuid::Uuid::from_u128(1));
    crawl.cache = Some(CachePolicyV1::default());
    let source = run_local_with(LocalRun::new(crawl.clone(), cfg(dir.path())).with_stores(stores.clone()))
        .await
        .unwrap();
    assert_eq!(source.status, RunStatus::Completed);
    assert_eq!(source.pages.len(), 1);
    let mut legacy = source.pages[0].clone();
    assert!(legacy.metadata["nativeCache"]["wire"].is_object());
    // A retained capture can predate pipeline provenance. Its derived projection must not
    // supply either the replay's title or its current parser version.
    legacy.title = Some("Obsolete derived projection".to_owned());
    legacy.metadata.as_object_mut().unwrap().remove("parserPipeline");
    stores.pages.put(&legacy).await.unwrap();
    drop(site);

    crawl.cache.as_mut().unwrap().development_replay = true;
    let replay = run_local_with(LocalRun::new(crawl, cfg(dir.path())).with_stores(stores.clone()))
        .await
        .unwrap();
    assert_eq!(replay.status, RunStatus::Completed);
    assert_eq!(replay.pages.len(), 1, "{:?}", replay.failures);
    let page = &replay.pages[0];
    assert_eq!(page.title.as_deref(), Some("Home"));
    assert_eq!(page.content_digest, legacy.content_digest);
    assert_eq!(page.fetched_at, legacy.fetched_at);
    assert_eq!(
        page.metadata["developmentReplay"],
        serde_json::json!({
            "version": 1,
            "provenance": "retained_artifacts",
            "sourceRun": source.run_id,
            "networkRequests": 0,
        }),
    );
    assert_eq!(page.metadata["robots_observation"], "unobserved_replay");
    let spec = ParserPipelineV1::default();
    assert_eq!(
        page.metadata["parserPipeline"],
        serde_json::json!({
            "recordVersion": spec.record_version().unwrap(),
            "digest": spec.digest().unwrap(),
        }),
    );
    let unchanged = stores.pages.list(source.run_id).await.unwrap();
    assert_eq!(unchanged[0].title, legacy.title);
    assert!(unchanged[0].metadata.get("parserPipeline").is_none());
}
