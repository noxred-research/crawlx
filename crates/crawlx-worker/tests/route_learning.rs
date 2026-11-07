//! Sibling route slots learned online by the worker: the
//! URL plane and the browser plane feed every admitted or observed path to the run's
//! `RouteLearner`; once five siblings share a structure the shared templater renders them
//! as one route (`/user/:slug`), the rules are persisted as a `route_templates` run event,
//! and a `RunContext` built over the same store (a resumed run) restores them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::RunStatus;
use crawlx_core::{ActionKind, CreateCrawl};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{
    EgressConfig, LearnedRoutes, LocalRun, RunContext, RunReport, Stores, WorkerConfig, ROUTE_TEMPLATES_EVENT,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const USERS: [&str; 6] = ["alice", "bob", "carol", "dave", "erin", "frank"];

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

fn html(body: String) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
}

/// `/` links to six `/user/<name>` pages and `/about`; every user page links home.
async fn user_site() -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let links: String = USERS
        .iter()
        .map(|u| format!(r#"<a href="/user/{u}">{u}</a> "#))
        .collect();
    let home = format!(
        r#"<html><head><title>Home</title></head><body><main><h1>Users</h1>{links}<a href="/about">About</a></main></body></html>"#
    );
    let app = Router::new()
        .route("/", get(move || async move { html(home) }))
        .route(
            "/user/{name}",
            get(|axum::extract::Path(name): axum::extract::Path<String>| async move {
                html(format!(
                    r#"<html><head><title>{name}</title></head><body><main><h1>{name}</h1><p>Profile of {name}.</p><a href="/">Home</a></main></body></html>"#
                ))
            }),
        )
        .route(
            "/about",
            get(|| async { html("<html><head><title>About</title></head><body><main><h1>About</h1></main></body></html>".to_owned()) }),
        )
        .route("/robots.txt", get(|| async { ([(header::CONTENT_TYPE, "text/plain")], "User-agent: *\nAllow: /\n") }));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, task)
}

async fn persisted_rules(stores: &Stores, run: crawlx_core::CrawlRunId) -> Vec<LearnedRoutes> {
    stores
        .events
        .list_after(run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == ROUTE_TEMPLATES_EVENT)
        .map(|e| serde_json::from_value(e.payload).unwrap())
        .collect()
}

async fn resumed_context(stores: &Stores, dir: &std::path::Path, run: crawlx_core::CrawlRunId) -> RunContext {
    let row = stores.runs.get(run).await.unwrap();
    let cfg = config(dir);
    let authorization = common::authorization::admit(stores, &row, &cfg).await;
    RunContext::build(
        &row,
        &cfg,
        stores.clone(),
        None,
        None,
        CancellationToken::new(),
        None,
        Some(authorization),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn the_url_plane_learns_sibling_slots_persists_them_and_a_resumed_run_restores_them() {
    let (base, server) = user_site().await;
    let dir = tempfile::tempdir().unwrap();
    let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_020);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    stores.authorization = Some(Arc::new(crawlx_worker::StaticAuthorizationSource::new(
        common::authorization::verified_record(&crawl, stores.tenant),
    )));
    let report: RunReport =
        run_local_with(LocalRun::new(crawl, config(dir.path())).with_stores(stores.clone()))
            .await
            .unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert_eq!(report.pages.len(), 8, "home, six users, about");

    // the fifth admitted sibling learned the slot: later URLs key as `/user/:slug`
    let rules = persisted_rules(&stores, report.run_id).await;
    assert_eq!(rules.len(), 1, "one rule change: {rules:?}");
    assert_eq!(rules[0].version, 1);
    assert_eq!(rules[0].min_distinct, 5);
    assert!(rules[0].learned.contains_key("user"), "{:?}", rules[0].learned);
    let templates: Vec<String> = report
        .pages
        .iter()
        .filter(|p| p.url.url.path().starts_with("/user/"))
        .map(|p| p.url.route_template.0.clone())
        .collect();
    assert!(
        templates.iter().any(|t| t == "/user/:slug"),
        "a sibling discovered after the rule change carries the learned route: {templates:?}"
    );
    assert!(
        templates.iter().filter(|t| *t == "/user/:slug").count() < templates.len(),
        "siblings discovered before the fifth keep their literal route (online learning re-keys later URLs only): {templates:?}"
    );

    // a worker picking the run up builds its context over the same store: the rules and the
    // observed paths come back, so the same URL keys the same way
    let rc = resumed_context(&stores, dir.path(), report.run_id).await;
    let restored = rc.routes.snapshot();
    assert_eq!(
        (restored.version, &restored.learned),
        (rules[0].version, &rules[0].learned)
    );
    assert_eq!(rc.routes.paths_seen(), 8);
    assert_eq!(rc.canon.templater.read().template("/user/zoe").0, "/user/:slug");
    assert_eq!(rc.canon.templater.read().template("/about").0, "/about");
    let keyed = crawlx_url::Canonicalizer::canonicalize_url(
        &url::Url::parse(&format!("{base}/user/zoe")).unwrap(),
        &rc.canon,
    )
    .unwrap();
    assert_eq!(keyed.route_template.0, "/user/:slug");
    // nothing new was observed: the restored learner reports no rule change on known paths
    assert!(rc
        .routes
        .observe_all(USERS.iter().map(|u| format!("/user/{u}")))
        .is_none());
    server.abort();
}

/// Six user pages reachable from home, each with a `Follow` button and a home link. A link
/// navigates on a click and on keyboard activation alike, as it does in Chromium: the session
/// reaches the pages with trusted input only (the scripted `url_plane` navigation is the
/// recovery fallback).
fn user_app() -> FakeScript {
    let to = |path: String| vec![FakeEffect::Navigate(path)];
    let mut home = FakePage::new("https://example.test/").title("Home");
    for u in USERS {
        home = home
            .node(FakeAxSpec::link(u, format!("User {u}"), format!("/user/{u}")))
            .on_click(u, to(format!("/user/{u}")))
            .on(ActionKind::KeyboardActivate, u, to(format!("/user/{u}")));
    }
    let mut script = FakeScript::new().page(home);
    for u in USERS {
        script = script.page(
            FakePage::new(&format!("https://example.test/user/{u}"))
                .title(format!("User {u}"))
                .node(FakeAxSpec::button("follow", "Follow"))
                .node(FakeAxSpec::link("home", "Home", "/"))
                .on_click("home", to("/".into()))
                .on(ActionKind::KeyboardActivate, "home", to("/".into())),
        );
    }
    script
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_browser_plane_learns_sibling_slots_from_observed_states() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(20_261_020);
    crawl.limits.interactions = 60;
    crawl.limits.states = 100;
    let report = run_local_with(
        LocalRun::new(crawl, config(dir.path()))
            .with_backend(Arc::new(FakeBackend::new(user_app())))
            .with_stores(stores.clone()),
    )
    .await
    .unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    let visited: std::collections::BTreeSet<&str> = report
        .states
        .iter()
        .map(|s| s.url.url.path())
        .filter(|p| p.starts_with("/user/"))
        .collect();
    assert!(
        visited.len() >= 5,
        "the session reached five sibling pages: {visited:?}"
    );
    let rules = persisted_rules(&stores, report.run_id).await;
    assert_eq!(rules.len(), 1, "{rules:?}");
    assert!(rules[0].learned.contains_key("user"), "{:?}", rules[0].learned);
    assert!(
        report
            .states
            .iter()
            .any(|s| s.url.route_template.0 == "/user/:slug"),
        "states observed after the rule change carry the learned route"
    );
    assert!(
        report
            .ledger
            .iter()
            .any(|row| row.key.route_template.0 == "/user/:slug"),
        "action contexts of later sibling pages share the learned route"
    );
}
