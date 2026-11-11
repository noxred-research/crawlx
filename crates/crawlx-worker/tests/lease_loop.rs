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
    let backend = Arc::new(
        FakeBackend::builder()
            .script(script)
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
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
async fn leased_hybrid_explicit_http_route_never_acquires_browser() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(|| async {
                axum::response::Html(
                    r#"<html><body><div id="app"></div><script type="module" src="/main.js"></script></body></html>"#,
                )
            }),
        );
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Hybrid;
    crawl.seed = Some(7);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    crawl.scope.known_files.clear();
    crawl.politeness.delay_ms = 0;
    crawl.dynamic.observe_only = true;
    crawl.dynamic.always_browser_paths = vec![".*".into()];
    crawl.protocol.routes.push(
        serde_json::from_value(serde_json::json!({
            "id": "native-http", "schemes": ["http"], "origin": base,
            "pathPattern": "^/", "schedulerMetadata": {"source_kind": "url_plane"},
            "backend": "http", "delegateId": null, "requiredCapabilities": [],
            "maxBodyBytes": 1048576, "maxElapsedMs": 10000, "policyRevision": "revision-1"
        }))
        .unwrap(),
    );
    let record = common::authorization::verified_record(&crawl, stores.tenant);
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let run = enqueue(&stores, crawl).await;
    let backend = Arc::new(
        FakeBackend::builder()
            .script(FakeScript::new().page(FakePage::new(&format!("{base}/"))))
            .clock(Arc::new(SystemClock))
            .build(),
    );
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
    assert_eq!(stores.runs.get(run).await.unwrap().status, RunStatus::Completed);
    assert!(stores.states.list_states(run).await.unwrap().is_empty());
    assert!(backend.context_handles().is_empty());
}

#[tokio::test]
async fn bodyless_head_preserves_get_document_and_never_enters_article_ingestion() {
    use axum::{http::header, routing::get, Router};
    use crawlx_core::hash::Digest;
    use crawlx_core::orchestration::RequestBatchV1;
    use crawlx_core::request::RequestEnvelopeV1;
    use std::sync::Mutex;

    for native_acquisition in [false, true] {
        let observed = Arc::new(Mutex::new(Vec::new()));
        let get_observed = Arc::clone(&observed);
        let head_observed = Arc::clone(&observed);
        let redirect_observed = Arc::clone(&observed);
        let scope_redirect_observed = Arc::clone(&observed);
        let robots_redirect_observed = Arc::clone(&observed);
        let scope_denied_observed = Arc::clone(&observed);
        let robots_denied_observed = Arc::clone(&observed);
        let external_observed = Arc::clone(&observed);
        let external_redirect_observed = Arc::clone(&observed);
        let external_denied_redirect_observed = Arc::clone(&observed);
        let external_listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        let external_port = external_listener.local_addr().unwrap().port();
        let external_base = format!("http://{}", external_listener.local_addr().unwrap());
        let external_app = Router::new().fallback(axum::routing::any(
            move |method: axum::http::Method, uri: axum::http::Uri| {
                external_observed
                    .lock()
                    .unwrap()
                    .push(format!("{method} external{}", uri.path()));
                async move {
                    if uri.path() == "/robots.txt" {
                        (
                            [
                                (header::CONTENT_TYPE, "text/plain"),
                                (header::HeaderName::from_static("x-owned-head"), "observed"),
                            ],
                            "User-agent: *\nDisallow: /denied\n",
                        )
                    } else {
                        (
                            [
                                (header::CONTENT_TYPE, "text/html"),
                                (header::HeaderName::from_static("x-owned-head"), "observed"),
                            ],
                            "HEAD must not download this entity body",
                        )
                    }
                }
            },
        ));
        let external_server = tokio::spawn(async move {
            axum::serve(external_listener, external_app).await.unwrap();
        });
        let external_leaf = format!("{external_base}/leaf");
        let external_denied = format!("{external_base}/denied");
        let html = concat!(
            "<html><head><title>HEAD boundary article</title></head><body><article id=\"main\">",
            "<h1>HEAD boundary article</h1><p>Owned research teams preserve exact source text ",
            "while reserving bounded output capacity before serialization begins. This article ",
            "describes a local fixture with no external acquisition dependencies.</p>",
            "<p>Dataset acceptance must retain the GET document when a later HEAD request observes ",
            "only response headers. Redirects must retain HEAD while checking every destination ",
            "against scope, robots, authorization and the original finite acquisition budget.</p>",
            "</article></body></html>",
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route(
                "/article",
                get(move || {
                    get_observed.lock().unwrap().push("GET /article".to_owned());
                    async move { axum::response::Html(html) }
                })
                .head(move || {
                    head_observed.lock().unwrap().push("HEAD /article".to_owned());
                    async {
                        (
                            [
                                (header::CONTENT_TYPE, "text/html"),
                                (header::CONTENT_LENGTH, "1000000"),
                                (header::HeaderName::from_static("x-owned-head"), "observed"),
                                (header::SET_COOKIE, "session=ownedHeadCookie"),
                            ],
                            "",
                        )
                    }
                }),
            )
            .route(
                "/head",
                get(move || {
                    redirect_observed.lock().unwrap().push("HEAD /head".to_owned());
                    async { axum::response::Redirect::temporary("/article") }
                }),
            )
            .route(
                "/external",
                axum::routing::head(move || {
                    external_redirect_observed
                        .lock()
                        .unwrap()
                        .push("HEAD /external".to_owned());
                    let target = external_leaf.clone();
                    async move { axum::response::Redirect::temporary(&target) }
                }),
            )
            .route(
                "/external-denied",
                axum::routing::head(move || {
                    external_denied_redirect_observed
                        .lock()
                        .unwrap()
                        .push("HEAD /external-denied".to_owned());
                    let target = external_denied.clone();
                    async move { axum::response::Redirect::temporary(&target) }
                }),
            )
            .route(
                "/robots.txt",
                get(|| async { "User-agent: *\nDisallow: /robots-denied\n" }),
            )
            .route(
                "/scope_redirect",
                axum::routing::head(move || {
                    scope_redirect_observed
                        .lock()
                        .unwrap()
                        .push("HEAD /scope_redirect".to_owned());
                    async { axum::response::Redirect::temporary("/scope-denied") }
                }),
            )
            .route(
                "/robots_redirect",
                axum::routing::head(move || {
                    robots_redirect_observed
                        .lock()
                        .unwrap()
                        .push("HEAD /robots_redirect".to_owned());
                    async { axum::response::Redirect::temporary("/robots-denied") }
                }),
            )
            .route(
                "/scope-denied",
                axum::routing::any(move |method: axum::http::Method| {
                    scope_denied_observed
                        .lock()
                        .unwrap()
                        .push(format!("{method} /scope-denied"));
                    async { axum::http::StatusCode::OK }
                }),
            )
            .route(
                "/robots-denied",
                axum::routing::any(move |method: axum::http::Method| {
                    robots_denied_observed
                        .lock()
                        .unwrap()
                        .push(format!("{method} /robots-denied"));
                    async { axum::http::StatusCode::OK }
                }),
            );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/article")).unwrap());
        crawl.mode = CrawlMode::Static;
        crawl.seed = Some(7);
        crawl.safety.allow_private_networks = true;
        crawl.safety.respect_robots_txt = true;
        crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
        crawl.politeness.delay_ms = 0;
        crawl.scope.crawl_entire_domain = true;
        crawl.scope.allow_external_links = true;
        crawl.scope.exclude_paths = vec!["^/scope-denied$".into()];
        crawl.output.formats = vec![crawlx_core::config::OutputFormat::Html];
        crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
        crawl.orchestration = Some(crawlx_core::orchestration::OrchestrationConfigV1::default());
        crawl.acquisition = native_acquisition.then(crawlx_core::acquisition::AcquisitionPolicyV1::default);
        if let Some(policy) = &mut crawl.acquisition {
            policy.max_attempts = 4;
            policy.validation.required_selectors = vec!["#main".into()];
            policy.validation.minimum_text_bytes = 100;
        }
        crawl.datasets = serde_json::from_value(serde_json::json!({
            "version":1, "articleDataset":"articles",
            "stores":[{"name":"articles","schemaVersion":"document_v1",
                       "maxItems":10,"maxBytes":16777216}]
        }))
        .unwrap();
        let mut record = common::authorization::verified_record(&crawl, stores.tenant);
        record.robots_override_acknowledged = true;
        record.url_prefixes.push(external_base.clone());
        let stores =
            stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
        let run = enqueue(&stores, crawl).await;
        // A prequeued HEAD cannot suppress the depth-zero GET seed. Later HEAD
        // responses must not replace its page or ingest an empty article.
        let head = RequestEnvelopeV1::new(
            common::canonical(&format!("{base}/article")),
            "HEAD".into(),
            1,
            None,
        );
        let redirected =
            RequestEnvelopeV1::new(common::canonical(&format!("{base}/head")), "HEAD".into(), 1, None);
        let scope_redirect = RequestEnvelopeV1::new(
            common::canonical(&format!("{base}/scope_redirect")),
            "HEAD".into(),
            1,
            None,
        );
        let robots_redirect = RequestEnvelopeV1::new(
            common::canonical(&format!("{base}/robots_redirect")),
            "HEAD".into(),
            1,
            None,
        );
        let external = RequestEnvelopeV1::new(
            common::canonical(&format!("{base}/external")),
            "HEAD".into(),
            1,
            None,
        );
        let external_denied = RequestEnvelopeV1::new(
            common::canonical(&format!("{base}/external-denied")),
            "HEAD".into(),
            1,
            None,
        );
        let receipt = stores
            .frontier
            .append_batch(RequestBatchV1::new(
                stores.tenant,
                run,
                "anonymous".into(),
                Digest::of("head-worker-fixture", b"two-bodyless-requests"),
                vec![
                    head,
                    redirected,
                    external,
                    external_denied,
                    scope_redirect,
                    robots_redirect,
                ],
            ))
            .await
            .unwrap();
        let mut worker = cfg(dir.path());
        worker.egress.extra_ports.push(external_port);
        let result = tokio::time::timeout(
            Duration::from_secs(30),
            run_with(worker, stores.clone(), None, CancellationToken::new()),
        )
        .await;
        server.abort();
        external_server.abort();
        result.unwrap().unwrap();
        assert_eq!(
            observed.lock().unwrap().as_slice(),
            [
                "GET /article",
                "HEAD /article",
                "HEAD /head",
                "HEAD /article",
                "HEAD /external",
                "GET external/robots.txt",
                "HEAD external/leaf",
                "HEAD /external-denied",
                "HEAD /scope_redirect",
                "HEAD /robots_redirect"
            ],
            "native acquisition: {native_acquisition}",
        );
        for id in &receipt.inserted[..3] {
            let request = stores.frontier.get_request(run, *id).await.unwrap();
            assert_eq!(request.envelope.method, "HEAD");
            assert_eq!(request.entry.status, crawlx_core::repo::FrontierStatus::Succeeded);
        }
        for id in &receipt.inserted[3..] {
            assert_eq!(
                stores.frontier.get_request(run, *id).await.unwrap().entry.status,
                crawlx_core::repo::FrontierStatus::Failed,
            );
        }
        let pages = stores.pages.list(run).await.unwrap();
        assert_eq!(pages.len(), 1);
        assert!(!receipt.inserted.contains(&pages[0].frontier_id));
        assert!(pages[0].html.is_some());
        assert_eq!(
            pages[0].content_digest,
            Digest::of("crawlx/page-body/v1", html.as_bytes())
        );
        assert_eq!(
            stores.datasets.items(run, "articles", 0, 10).await.unwrap().len(),
            1
        );
        let events = stores.events.list_after(run, 0, 1000).await.unwrap();
        let heads: Vec<_> = events
            .iter()
            .filter(|event| event.kind == "head_response")
            .collect();
        assert_eq!(heads.len(), 3);
        for event in heads {
            assert_eq!(event.payload["method"], "HEAD");
            assert_eq!(event.payload["status"], 200);
            assert_eq!(event.payload["response_headers"]["x-owned-head"], "observed");
            assert_eq!(event.payload["bodyBytes"], 0);
            let external = event.payload["requestId"] == receipt.inserted[2];
            assert_eq!(
                event.payload["acquisition"]["decodedBytes"],
                if external {
                    u64::try_from("User-agent: *\nDisallow: /denied\n".len()).unwrap()
                } else {
                    0
                },
            );
            assert_eq!(
                event.payload["acquisition"]["finalUrl"],
                if external {
                    format!("{external_base}/leaf")
                } else {
                    format!("{base}/article")
                }
            );
            assert!(event.payload["acquisition"]["wireBody"].is_null());
            assert!(event.payload["acquisition"]["extractionSucceeded"].is_null());
            if native_acquisition {
                assert!(event.payload["acquisition"]["validation"]["signals"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!("body_expectations_unobserved_head")));
            }
            assert!(!event.payload.to_string().contains("ownedHeadCookie"));
        }
    }
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
        Some(Arc::new(
            FakeBackend::builder()
                .script(app())
                .clock(Arc::new(crawlx_core::SystemClock))
                .build(),
        )),
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
async fn invalid_retained_profile_run_does_not_stop_a_healthy_run() {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = CreateCrawl::new("https://example.test/".parse().unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 2;
    let mut invalid = crawl.clone();
    invalid.dynamic.browser_profile = Some(crawlx_core::config::BrowserProfile {
        name: "unapproved".to_owned(),
        generation: 0,
        save_changes: true,
    });
    let rejected = enqueue(&stores, invalid).await;
    let healthy = enqueue(&stores, crawl).await;
    let backend = Arc::new(
        FakeBackend::builder()
            .script(app())
            .clock(Arc::new(SystemClock))
            .build(),
    );
    run_with(
        cfg(dir.path()),
        stores.clone(),
        Some(backend),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let rejected = stores.runs.get(rejected).await.unwrap();
    assert_eq!(rejected.status, RunStatus::Failed);
    assert_eq!(rejected.terminal_reason, Some(TerminalReason::FatalError));
    let healthy = stores.runs.get(healthy).await.unwrap();
    assert_eq!(healthy.status, RunStatus::Completed);
    assert!(healthy.counters.interactions.succeeded > 0);
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
        tokio::spawn(async move {
            run_with(
                cfg,
                stores,
                Some(Arc::new(
                    FakeBackend::builder()
                        .script(script)
                        .clock(Arc::new(crawlx_core::SystemClock))
                        .build(),
                )),
                cancel,
            )
            .await
        })
    };
    // A claimed lease precedes actor startup. Wait for a durable action, so this
    // fixture drains an initialized actor rather than racing its construction.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let acted = !stores.journal.list(run, None).await.unwrap().is_empty();
        if acted {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "session never acted");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
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
        Some(Arc::new(
            FakeBackend::builder()
                .script(app())
                .clock(Arc::new(crawlx_core::SystemClock))
                .build(),
        )),
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
            Some(Arc::new(
                FakeBackend::builder()
                    .script(app())
                    .clock(Arc::new(crawlx_core::SystemClock))
                    .build(),
            )),
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
