//! Real Chromium: skipped when no browser binary is installed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::routing::get;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::RunStatus;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

#[tokio::test]
async fn observe_only_in_real_chromium_produces_a_state_with_ax_nodes_and_the_build_info() {
    let Some(exe) = crawlx_browser::launch::find_executable() else {
        eprintln!("skipped: no Chromium binary (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = axum::Router::new().route(
        "/",
        get(|| async {
            (
                [("content-type", "text/html")],
                r#"<!doctype html><html><head><title>Fixture</title></head><body>
                <h1>Fixture</h1><button id="go">Go</button><a href="/other">Other page</a>
                <label>Name <input type="text" name="n"></label></body></html>"#,
            )
        }),
    );
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.dynamic.observe_only = true;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.limits.states = 1;
    let mut cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    cfg.launch.executable = exe;
    cfg.launch.allow_unpinned = true;
    if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_err() && std::env::var_os("CI").is_none() {
        // containers commonly lack user namespaces; the launcher reports a clear error otherwise
        cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |u| u == "root");
    }
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone()))
        .await
        .unwrap();
    server.abort();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert!(!report.states.is_empty(), "no state recorded");
    let state = &report.states[0];
    let (_, ax) = state
        .artifacts
        .iter()
        .find(|(k, _)| k == "ax_tree")
        .expect("ax_tree artifact");
    let json: serde_json::Value = serde_json::from_slice(&stores.artifacts.get(ax).await.unwrap()).unwrap();
    let nodes = json["nodes"].as_array().unwrap();
    assert!(nodes.len() >= 4, "AX nodes: {}", nodes.len());
    assert!(
        nodes.iter().any(|n| n["role"] == "button" && n["name"] == "Go"),
        "{nodes:?}"
    );
    assert!(nodes.iter().any(|n| n["role"] == "link"));
    let build = report.sessions[0]
        .browser
        .as_ref()
        .expect("BrowserBuildInfo on the session");
    assert!(!build.chromium_version.is_empty() && !build.cdp_revision.is_empty());
    assert!(report.actions.is_empty(), "observe-only sends no actions");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_popup_policy_waits_evicts_and_journals_download_and_external_closes() {
    let Some(exe) = crawlx_browser::launch::find_executable() else {
        eprintln!("skipped: no Chromium binary (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let external_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let external_port = external_listener.local_addr().unwrap().port();
    // Prime one existing popup, then open the four-window fixture. Two in-scope
    // newcomers alone cannot cause eviction with maxTabs=3 (home occupies one slot).
    let html = format!(
        r#"<!doctype html><title>Popup policy</title>
        <button onclick="this.remove();
          window.open('/old');
          window.open('/keep');
          const blank = window.open('about:blank');
          setTimeout(() => blank.location.href = '/new', 500);
          window.open('http://127.0.0.1:{external_port}/external');
          window.open('/download');">Open windows</button>"#
    );
    let app = axum::Router::new()
        .route(
            "/",
            get(move || {
                let html = html.clone();
                async move { axum::response::Html(html) }
            }),
        )
        .route(
            "/old",
            get(|| async { axum::response::Html("<h1>Old popup</h1>") }),
        )
        .route(
            "/keep",
            get(|| async { axum::response::Html("<h1>Keep popup</h1>") }),
        )
        .route(
            "/new",
            get(|| async { axum::response::Html("<h1>Delayed popup</h1>") }),
        )
        .route(
            "/download",
            get(|| async {
                (
                    [
                        ("content-type", "application/octet-stream"),
                        ("content-disposition", "attachment; filename=report.csv"),
                    ],
                    "id\n1\n",
                )
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let external = tokio::spawn(async move {
        axum::serve(
            external_listener,
            axum::Router::new().route(
                "/external",
                get(|| async { axum::response::Html("<h1>External window</h1>") }),
            ),
        )
        .await
        .unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let base = format!("http://127.0.0.1:{port}");
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(20_261_020);
    crawl.dynamic.max_tabs = 3;
    crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.limits.interactions = 30;
    crawl.limits.duration_seconds = 40;
    let mut cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            extra_allow: vec!["127.0.0.1/32".parse().unwrap()],
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    cfg.launch.executable = exe;
    cfg.launch.allow_unpinned = true;
    cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").is_ok_and(|u| u == "root");
    let report = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores))
        .await
        .unwrap();
    server.abort();
    external.abort();
    let policy: Vec<_> = report
        .actions
        .iter()
        .filter(|a| a.strategy == "tab_policy")
        .collect();
    let position = |kind, url: &str| {
        policy
            .iter()
            .position(|a| {
                a.key.action_kind == kind
                    && a.key.element == crawlx_worker::driver::tab_element(url)
                    && a.status == crawlx_core::counters::ActionStatus::Succeeded
            })
            .unwrap_or_else(|| panic!("missing {kind:?} {url}: {policy:?}"))
    };
    let evicted = position(crawlx_core::ActionKind::CloseTab, &format!("{base}/old"));
    let admitted = position(crawlx_core::ActionKind::SwitchTab, &format!("{base}/new"));
    let download = position(crawlx_core::ActionKind::CloseTab, &format!("{base}/download"));
    let rejected = position(
        crawlx_core::ActionKind::CloseTab,
        &format!("http://127.0.0.1:{external_port}/external"),
    );
    assert!(
        download < evicted && rejected < evicted && evicted < admitted,
        "{policy:?}"
    );
    assert!(report.states.iter().any(|s| s.url.url.path() == "/new"));
    assert!(policy.iter().all(|a| a.strategy_version == 2));
    assert!(policy
        .iter()
        .filter(|a| a.status == crawlx_core::counters::ActionStatus::Succeeded)
        .all(|a| a.lane == Some(crawlx_core::TrustLane::Diagnostic)));
}
