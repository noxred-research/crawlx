//! Dynamic page output uses settled browser evidence, never a second HTTP acquisition.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::{CrawlMode, OutputFormat};
use crawlx_core::counters::RunStatus;
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use std::sync::Arc;

fn config(directory: &std::path::Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: directory.to_path_buf(),
        egress: EgressConfig {
            // No DNS answers: any accidental static target acquisition cannot succeed.
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn request() -> CreateCrawl {
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.seed = Some(42);
    crawl.dynamic.observe_only = true;
    crawl.dynamic.page_hooks = true;
    crawl.limits.states = 20;
    crawl.scope.max_discovery_depth = 1;
    crawl.extract.forms = true;
    crawl.extract.xhr = true;
    crawl.extract.detect_secrets = true;
    crawl.extract.kb_endpoints = true;
    crawl.output.formats = vec![OutputFormat::Markdown, OutputFormat::Html];
    crawl
}

#[tokio::test]
async fn dynamic_emits_settled_dom_pages_and_follows_rendered_and_hook_urls_without_refetch() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), directory.path())
        .await
        .unwrap();
    let backend = Arc::new(FakeBackend::builder().script(FakeScript::new().settle_waited_ms(321)
        .page(FakePage::new("https://example.test/")
            .html("<html><head><title>Rendered article</title></head><body><main><h1>Settled browser content</h1><p>Content exists only in the browser document.</p><a href='/rendered'>Rendered child</a><a href='https://outside.test/no'>Outside</a><form action='/submit' method='post'><input name='email' type='email'></form></main><script>const api_key='fixture_token_1234567890';</script></body></html>")
            // No AX link: traversal must use shared extraction of rendered HTML.
            .discovered("/hook", "history.pushState")
            .xhr("GET", "https://example.test/api", 200))
        .page(FakePage::new("https://example.test/rendered")
            .html("<html><head><title>Rendered child</title></head><body><p>Rendered destination.</p></body></html>"))
        .page(FakePage::new("https://example.test/hook")
            .html("<html><head><title>Hook child</title></head><body><p>Hook destination.</p></body></html>"))).clock(Arc::new(crawlx_core::SystemClock)).build());
    let report = run_local_with(
        LocalRun::new(request(), config(directory.path()))
            .with_backend(backend.clone())
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
    assert_eq!(report.pages.len(), 3);
    assert!(report.actions.is_empty());
    let root = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/")
        .unwrap();
    assert_eq!(root.title.as_deref(), Some("Rendered article"));
    assert_eq!(root.metadata["browser"]["representation"], "settled_rendered_dom");
    assert_eq!(root.metadata["browser"]["settle"]["waited_ms"], 321);
    assert!(root.metadata["parserPipeline"].is_object());
    assert!(root.frontier_id > 0);
    assert!(root.links.iter().any(|url| url.ends_with("/rendered")));
    assert!(root.links.iter().any(|url| url.ends_with("/hook")));
    assert!(!root.metadata["forms"].as_array().unwrap().is_empty());
    assert!(!root.metadata["xhr_requests"].as_array().unwrap().is_empty());
    let markdown = stores
        .artifacts
        .get(root.markdown.as_ref().unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&markdown).contains("Settled browser content"));
    assert!(!root.metadata["endpoints"].as_array().unwrap().is_empty());
    assert!(!root.metadata["secrets"].as_array().unwrap().is_empty());
    assert!(root.metadata["discovered_endpoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|endpoint| endpoint["method"] == "POST"));
    assert!(!serde_json::to_string(&root.metadata)
        .unwrap()
        .contains("fixture_token_1234567890"));
    let mut navigations: Vec<_> = backend
        .context_handles()
        .iter()
        .flat_map(|handle| handle.navigations())
        .collect();
    navigations.sort();
    assert_eq!(
        navigations,
        vec![
            "https://example.test/",
            "https://example.test/hook",
            "https://example.test/rendered",
        ]
    );
    assert!(backend
        .context_handles()
        .iter()
        .all(|handle| handle.performed_keys().is_empty()));
}

#[tokio::test]
async fn dynamic_keeps_the_final_action_destination_when_interaction_budget_ends() {
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), directory.path())
        .await
        .unwrap();
    let effects = vec![FakeEffect::Navigate("https://example.test/next".into())];
    let backend = Arc::new(FakeBackend::builder().script(FakeScript::new()
        .page(FakePage::new("https://example.test/")
            .html("<html><head><title>Before</title></head><body><a href='/next'>Next</a></body></html>")
            .node(FakeAxSpec::link("next", "Next", "/next"))
            .on_click("next", effects.clone())
            .on(crawlx_core::ActionKind::KeyboardActivate, "next", effects))
        .page(FakePage::new("https://example.test/next")
            .html("<html><head><title>After last action</title></head><body><p>Final settled document.</p></body></html>"))).clock(Arc::new(crawlx_core::SystemClock)).build());
    let mut crawl = request();
    crawl.dynamic.observe_only = false;
    crawl.limits.interactions = 1;
    let report = run_local_with(
        LocalRun::new(crawl, config(directory.path()))
            .with_backend(backend.clone())
            .with_stores(stores),
    )
    .await
    .unwrap();
    assert_eq!(report.pages.len(), 2, "{:?}", report.terminal_reason);
    assert!(report
        .pages
        .iter()
        .any(|page| page.title.as_deref() == Some("After last action")));
    assert_eq!(
        report
            .actions
            .iter()
            .filter(|action| action.intended_at.is_some())
            .count(),
        1
    );
    assert_eq!(
        backend
            .context_handles()
            .iter()
            .map(|handle| handle.navigations().len())
            .sum::<usize>(),
        2
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_dynamic_output_uses_script_mutated_dom_and_one_document_request_per_url() {
    let Some(executable) = crawlx_browser::launch::find_executable() else {
        eprintln!("skipped: no Chromium binary (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let root_requests = Arc::clone(&requests);
    let child_requests = Arc::clone(&requests);
    let app = axum::Router::new()
        .route("/robots.txt", axum::routing::get(|| async { "User-agent: *\nAllow: /\n" }))
        .route("/", axum::routing::get(move || {
            root_requests.lock().unwrap().push("/");
            async { axum::response::Html("<!doctype html><title>Initial shell</title><main id='article'></main><script>setTimeout(()=>{document.title='Rendered by browser';document.querySelector('#article').innerHTML='<h1>Settled script content</h1><a href=\"/child\">Browser child</a>';},50);</script>") }
        }))
        .route("/child", axum::routing::get(move || {
            child_requests.lock().unwrap().push("/child");
            async { axum::response::Html("<!doctype html><title>Browser child</title><p>Child page.</p>") }
        }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), directory.path())
        .await
        .unwrap();
    let mut crawl = request();
    crawl.seed_url = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    let mut cfg = config(directory.path());
    cfg.launch.executable = executable;
    cfg.launch.allow_unpinned = true;
    if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_err() && std::env::var_os("CI").is_none() {
        cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |user| user == "root");
    }
    let result = run_local_with(LocalRun::new(crawl, cfg).with_stores(stores.clone())).await;
    server.abort();
    let report = result.unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert_eq!(report.pages.len(), 2);
    let root = report
        .pages
        .iter()
        .find(|page| page.url.url.path() == "/")
        .unwrap();
    assert_eq!(root.title.as_deref(), Some("Rendered by browser"));
    let markdown = stores
        .artifacts
        .get(root.markdown.as_ref().unwrap())
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&markdown).contains("Settled script content"));
    assert!(root.links.iter().any(|url| url.ends_with("/child")));
    assert_eq!(*requests.lock().unwrap(), vec!["/", "/child"]);
    assert!(report.actions.is_empty());
}

#[tokio::test]
async fn response_read_rejects_navigation_after_the_settled_dom_observation() {
    let rig = common::rig(
        FakeScript::new()
            .page(FakePage::new(common::SEED).html("<title>First document</title>"))
            .page(
                FakePage::new("https://example.test/next")
                    .status(201)
                    .html("<title>Second document</title>"),
            ),
        crawlx_core::SafetyProfile::ReadOnly,
    )
    .await;
    let before = rig
        .handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            common::canonical("https://example.test/next"),
            1,
            None,
        ))
        .await
        .unwrap();
    assert!(matches!(
        rig.handle.document_response(before.epoch).await,
        Err(crawlx_worker::SessionError::ObservationEpochChanged { expected, current })
            if expected == before.epoch && current != expected
    ));
    let after = rig
        .handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    assert!(matches!(
        rig.handle.document_response(after.epoch).await.unwrap(),
        crawlx_core::page_op::PageOpResult::Response {
            status: Some(201),
            ..
        }
    ));
    assert_eq!(
        rig.backend
            .context_handles()
            .iter()
            .map(|handle| handle.navigations().len())
            .sum::<usize>(),
        2
    );
}

#[tokio::test]
async fn dynamic_preview_uses_one_auxiliary_budget_without_refetching_browser_primary() {
    use axum::routing::get;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let origin = format!("http://article.example.test:{port}");
    let root_url = format!("{origin}/");
    let observed = Arc::new(std::sync::Mutex::new(Vec::new()));
    let root_observed = Arc::clone(&observed);
    let preview_observed = Arc::clone(&observed);
    let app = axum::Router::new()
        .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
        .route(
            "/",
            get(move || {
                root_observed.lock().unwrap().push("/");
                async { axum::response::Html("<title>Wrong HTTP primary</title>") }
            }),
        )
        .route(
            "/preview",
            get(move || {
                preview_observed.lock().unwrap().push("/preview");
                async {
                    axum::response::Html(
                        "<title>Preview only</title><meta name='description' content='Auxiliary head'>",
                    )
                }
            }),
        );
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let directory = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), directory.path())
        .await
        .unwrap();
    let backend = Arc::new(FakeBackend::builder().script(FakeScript::new().page(
        FakePage::new(&root_url).html("<html><head><title>Browser primary</title></head><body><main><a href='/preview'>Preview article</a><a href='/'>This article</a></main></body></html>"),
    )).clock(Arc::new(crawlx_core::SystemClock)).build());
    let mut crawl = request();
    crawl.seed_url = url::Url::parse(&root_url).unwrap();
    crawl.scope.max_discovery_depth = 0;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.extract.outputs = Some(serde_json::json!({
        "linkMedia": {"maxPreviews": 2, "minPreviewScore": 0}
    }));
    let mut cfg = config(directory.path());
    cfg.egress.resolver = Some(Arc::new(
        StaticResolver::new().with("article.example.test", [std::net::IpAddr::from([127, 0, 0, 1])]),
    ));
    let mut authorization = common::authorization::verified_record(&crawl, stores.tenant);
    authorization.url_prefixes = vec![origin];
    let result = run_local_with(
        LocalRun::new(crawl, cfg)
            .with_authorization(authorization)
            .with_backend(backend.clone())
            .with_stores(stores.clone()),
    )
    .await;
    server.abort();
    let report = result.unwrap();
    assert_eq!(
        report.status,
        RunStatus::Completed,
        "{:?}",
        report.terminal_reason
    );
    assert_eq!(report.pages.len(), 1);
    let page = &report.pages[0];
    assert_eq!(page.title.as_deref(), Some("Browser primary"));
    assert_eq!(page.metadata["acquisition"]["representation"], "rendered_dom");
    assert!(page.metadata["browser_auxiliary_budget"].is_object());
    assert_eq!(*observed.lock().unwrap(), vec!["/preview"]);
    assert_eq!(
        backend
            .context_handles()
            .iter()
            .map(|handle| handle.navigations().len())
            .sum::<usize>(),
        1
    );
}

#[tokio::test]
async fn same_url_reveal_appends_renditions_and_marks_disabled_revisits_without_refetch() {
    for cap in [1, 0] {
        let directory = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), directory.path())
            .await
            .unwrap();
        let revealed = "<html><head><title>Revealed article</title></head><body><main><h1>Revealed browser article</h1><p>Content appeared after the trusted click.</p></main></body></html>";
        let effects = vec![FakeEffect::SetHtml(revealed.into())];
        let backend = Arc::new(FakeBackend::builder().script(FakeScript::new().page(
            FakePage::new("https://example.test/")
                .html("<html><head><title>Initial shell</title></head><body><button>Reveal article</button></body></html>")
                .node(FakeAxSpec::button("reveal", "Reveal article"))
                .on_click("reveal", effects.clone())
                .on(crawlx_core::ActionKind::KeyboardActivate, "reveal", effects),
        )).clock(Arc::new(crawlx_core::SystemClock)).build());
        let mut crawl = request();
        crawl.dynamic.observe_only = false;
        crawl.dynamic.max_page_revisits = cap;
        crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
        crawl.limits.interactions = 1;
        let report = run_local_with(
            LocalRun::new(crawl, config(directory.path()))
                .with_backend(backend.clone())
                .with_stores(stores.clone()),
        )
        .await
        .unwrap();
        assert_eq!(report.pages.len(), if cap == 0 { 1 } else { 2 });
        assert_eq!(report.pages[0].title.as_deref(), Some("Initial shell"));
        assert_eq!(report.pages[0].metadata["browser"]["revisitGeneration"], 0);
        assert_eq!(report.pages[0].metadata["browser"]["canonical"], true);
        if cap == 1 {
            let second = &report.pages[1];
            assert_eq!(second.title.as_deref(), Some("Revealed article"));
            assert_eq!(second.url.url, report.pages[0].url.url);
            assert!(second.frontier_id > report.pages[0].frontier_id);
            assert_eq!(second.metadata["browser"]["revisitGeneration"], 1);
            assert_eq!(second.metadata["browser"]["canonical"], false);
            let markdown = stores
                .artifacts
                .get(second.markdown.as_ref().unwrap())
                .await
                .unwrap();
            assert!(String::from_utf8_lossy(&markdown).contains("Revealed browser article"));
            assert_ne!(
                second.metadata["browser"]["epoch"],
                report.pages[0].metadata["browser"]["epoch"]
            );
            let late = crawlx_worker::XhrSink::default();
            late.record(
                vec![crawlx_core::dom_ops::XhrRecord {
                    page_url: second.url.url.to_string(),
                    method: "GET".into(),
                    url: "https://example.test/late-api".into(),
                    status: Some(200),
                    resource_type: "fetch".into(),
                    content_type: Some("application/json".into()),
                }],
                &crawlx_url::CanonicalizeOptions::default(),
            );
            assert_eq!(late.apply(stores.pages.as_ref(), report.run_id).await.unwrap(), 0);
            assert_eq!(
                second.metadata["late_xhr_attribution"],
                "late_xhr_not_epoch_attributed"
            );
            let canonical = stores
                .pages
                .recent_for_url(stores.tenant, &report.pages[0].url, 10)
                .await
                .unwrap();
            assert_eq!(canonical[0].frontier_id, report.pages[0].frontier_id);
            assert_eq!(canonical[0].title.as_deref(), Some("Initial shell"));
        } else {
            let events = stores.events.list_after(report.run_id, 0, 10_000).await.unwrap();
            assert!(events.iter().any(|event| event.kind == "browser.page"
                && event.payload["reason"] == "revisit_cap_reached"
                && serde_json::to_string(&event.payload["outcome"])
                    .unwrap()
                    .contains("revisit_cap_reached")));
        }
        assert_eq!(
            report
                .actions
                .iter()
                .filter(|action| action.intended_at.is_some())
                .count(),
            1
        );
        assert_eq!(
            backend
                .context_handles()
                .iter()
                .map(|handle| handle.navigations().len())
                .sum::<usize>(),
            1
        );
    }
}
