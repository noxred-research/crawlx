//! Surface discovery on the static plane: path climb, the unique filter, the priority strategy, static
//! form filling (with and without a form AI), endpoint classification, the failure list and
//! the request/raw metadata of a page.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod surface_common;

use async_trait::async_trait;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Router;
use crawlx_core::config::{CrawlStrategy, FormFill};
use crawlx_core::counters::TerminalReason;
use crawlx_extract::form_fill::UnresolvedField;
use crawlx_worker::surface::form_ai::FormAi;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use surface_common::{crawl, crawl_with, page, page_at, page_paths, Site};
use url::Url;

fn query_of(target: &str) -> BTreeMap<String, String> {
    let url = Url::parse(&format!("http://h.test{target}")).unwrap();
    url.query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect()
}

// ---- scope.pathClimb ----------------------------------------------------------------------

async fn docs_site() -> Site {
    Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async { page("Home", r#"<a href="/docs/guide/intro.html">intro</a>"#) }),
            )
            .route("/docs/guide/intro.html", get(|| async { page("Intro", "") }))
            .route("/docs/guide/", get(|| async { page("Guide index", "") }))
            .route("/docs/", get(|| async { page("Docs index", "") }))
            .fallback(|| async { StatusCode::NOT_FOUND })
    })
    .await
}

#[tokio::test]
async fn path_climb_fetches_the_parent_directories_at_the_childs_depth() {
    let site = docs_site().await;
    let run = crawl(&site.base, |c| c.scope.path_climb = true).await;
    assert_eq!(
        page_paths(&run.report),
        ["/", "/docs/", "/docs/guide/", "/docs/guide/intro.html"]
    );
    // each parent is fetched exactly once and found by the climb, one hop from the page
    assert_eq!(site.gets().iter().filter(|p| *p == "/docs/").count(), 1);
    let child_depth = run
        .frontier()
        .await
        .iter()
        .find(|f| f.url.url.path() == "/docs/guide/intro.html")
        .unwrap()
        .depth;
    for parent in ["/docs/", "/docs/guide/"] {
        let row = run
            .frontier()
            .await
            .into_iter()
            .find(|f| f.url.url.path() == parent)
            .unwrap();
        assert_eq!(row.depth, child_depth, "{parent}");
        assert_eq!(
            page_at(&run.report, parent).metadata["request"]["tag"],
            "path-climb"
        );
    }
}

#[tokio::test]
async fn without_path_climb_the_parents_are_not_visited() {
    let site = docs_site().await;
    let run = crawl(&site.base, |_| {}).await;
    assert_eq!(page_paths(&run.report), ["/", "/docs/guide/intro.html"]);
    assert_eq!(
        site.count("/docs/"),
        1,
        "only the linked page itself: {:?}",
        site.gets()
    );
}

// ---- scope.disableUniqueFilter ------------------------------------------------------------

async fn identical_pages_site() -> Site {
    Site::start(|_| {
        // `/d1/p` and `/d2/p` are byte-identical; their relative link leads to different URLs
        let same = || async { page("Same", r#"<a href="next">next</a>"#) };
        Router::new()
            .route(
                "/",
                get(|| async { page("Home", r#"<a href="/d1/p">1</a><a href="/d2/p">2</a>"#) }),
            )
            .route("/d1/p", get(same))
            .route("/d2/p", get(same))
            .route("/d1/next", get(|| async { page("Next one", "") }))
            .route("/d2/next", get(|| async { page("Next two", "") }))
    })
    .await
}

#[tokio::test]
async fn identical_pages_are_deduplicated_and_not_expanded_by_default() {
    let site = identical_pages_site().await;
    let run = crawl(&site.base, |_| {}).await;
    let second = page_at(&run.report, "/d2/p");
    assert_eq!(second.metadata["dedupe"]["reason"], "content_exact");
    assert!(page_at(&run.report, "/d1/p").metadata.get("dedupe").is_none());
    assert!(
        !page_paths(&run.report).contains(&"/d2/next".to_owned()),
        "{:?}",
        site.gets()
    );
}

#[tokio::test]
async fn disable_unique_filter_records_and_expands_identical_pages() {
    let site = identical_pages_site().await;
    let run = crawl(&site.base, |c| c.scope.disable_unique_filter = true).await;
    assert!(page_at(&run.report, "/d1/p").metadata.get("dedupe").is_none());
    assert!(page_at(&run.report, "/d2/p").metadata.get("dedupe").is_none());
    assert_eq!(
        page_paths(&run.report),
        ["/", "/d1/next", "/d1/p", "/d2/next", "/d2/p"],
        "both identical pages are recorded and both are followed"
    );
}

// ---- scope.strategy = priority ------------------------------------------------------------

async fn surface_site() -> Site {
    Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        r#"<a href="/plain-1">1</a><a href="/plain-2">2</a><a href="/plain-3">3</a><a href="/admin?x=1">admin</a>"#,
                    )
                }),
            )
            .route("/plain-1", get(|| async { page("P1", "") }))
            .route("/plain-2", get(|| async { page("P2", "") }))
            .route("/plain-3", get(|| async { page("P3", "") }))
            .route("/admin", get(|| async { page("Admin", "") }))
    })
    .await
}

#[tokio::test]
async fn priority_strategy_fetches_surface_urls_before_plain_links() {
    let site = surface_site().await;
    crawl(&site.base, |c| c.scope.strategy = CrawlStrategy::Priority).await;
    assert_eq!(
        site.gets(),
        ["/", "/admin?x=1", "/plain-1", "/plain-2", "/plain-3"],
        "the admin URL jumps the queue, equals keep discovery order"
    );
}

#[tokio::test]
async fn breadth_first_keeps_discovery_order() {
    let site = surface_site().await;
    crawl(&site.base, |_| {}).await;
    assert_eq!(
        site.gets(),
        ["/", "/plain-1", "/plain-2", "/plain-3", "/admin?x=1"]
    );
}

// ---- scope.strategy across execution planes -----------------------------------------------

const STRATEGY_TREE: [(&str, &[&str]); 15] = [
    ("/", &["/a", "/b"]),
    ("/a", &["/a/0", "/a/1"]),
    ("/b", &["/b/0", "/b/1"]),
    ("/a/0", &["/a/0/0", "/a/0/1"]),
    ("/a/1", &["/a/1/0", "/a/1/1"]),
    ("/b/0", &["/b/0/0", "/b/0/1"]),
    ("/b/1", &["/b/1/0", "/b/1/1"]),
    ("/a/0/0", &[]),
    ("/a/0/1", &[]),
    ("/a/1/0", &[]),
    ("/a/1/1", &[]),
    ("/b/0/0", &[]),
    ("/b/0/1", &[]),
    ("/b/1/0", &[]),
    ("/b/1/1", &[]),
];

fn strategy_tree_order(strategy: CrawlStrategy) -> Vec<&'static str> {
    match strategy {
        CrawlStrategy::BreadthFirst => STRATEGY_TREE.iter().map(|(path, _)| *path).collect(),
        CrawlStrategy::DepthFirst => vec![
            "/", "/b", "/b/1", "/b/1/1", "/b/1/0", "/b/0", "/b/0/1", "/b/0/0", "/a", "/a/1", "/a/1/1",
            "/a/1/0", "/a/0", "/a/0/1", "/a/0/0",
        ],
        CrawlStrategy::Priority => unreachable!("this fixture pins BFS and DFS"),
    }
}

async fn strategy_tree_site() -> Site {
    Site::start(|_| {
        Router::new().fallback(|uri: axum::http::Uri| async move {
            let Some((path, children)) = STRATEGY_TREE.iter().find(|(path, _)| *path == uri.path()) else {
                return StatusCode::NOT_FOUND.into_response();
            };
            let links = children
                .iter()
                .map(|child| format!(r#"<a href="{child}">{child}</a>"#))
                .collect::<String>();
            page(path, &links)
        })
    })
    .await
}

fn strategy_tree_browser(base: &str) -> crawlx_browser::FakeBackend {
    use crawlx_browser::fake::{FakePage, FakeScript};

    let script = STRATEGY_TREE
        .iter()
        .fold(FakeScript::new(), |script, (path, children)| {
            let mut document = FakePage::new(&format!("{base}{path}")).title(*path).html(format!(
                "<html><head><title>{path}</title></head><body><p>Page {path}</p></body></html>"
            ));
            // Hooks, not AX controls: navigation must pass through the browser URL queue.
            for child in *children {
                document = document.discovered(*child, "fixture");
            }
            script.page(document)
        });
    crawlx_browser::FakeBackend::builder()
        .script(script)
        .clock(Arc::new(crawlx_core::SystemClock))
        .build()
}

async fn run_queued_strategy_tree(
    crawl: crawlx_core::CreateCrawl,
    mut config: crawlx_worker::WorkerConfig,
    stores: crawlx_worker::Stores,
    backend: Arc<crawlx_browser::FakeBackend>,
) -> crawlx_core::CrawlRunId {
    use crawlx_core::counters::{PlaneCounters, RunStatus};
    use crawlx_core::{Clock, CrawlRunId, SystemClock};

    let run = crawlx_core::repo::CrawlRun {
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
        .create_sessions(&crawlx_scheduler::RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    config.idle_exit_after = Some(std::time::Duration::from_millis(200));
    config.checkpoint_keys = Some(Arc::new(
        crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap(),
    ));
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        crawlx_worker::lease_loop::run_with(
            config,
            stores.clone(),
            Some(backend),
            tokio_util::sync::CancellationToken::new(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let finished = stores.runs.get(run.id).await.unwrap();
    assert_eq!(
        finished.status,
        RunStatus::Completed,
        "{:?}",
        finished.terminal_reason
    );
    assert_eq!(finished.terminal_reason, Some(TerminalReason::FrontierExhausted));
    run.id
}

async fn assert_strategy_tree(
    mode: crawlx_core::config::CrawlMode,
    strategy: CrawlStrategy,
    leased: bool,
    observe_only: bool,
) {
    use crawlx_core::config::CrawlMode;
    use crawlx_core::counters::RunStatus;

    let site = strategy_tree_site().await;
    let directory = tempfile::tempdir().unwrap();
    let mut crawl = surface_common::static_crawl(&site.base);
    crawl.mode = mode;
    crawl.scope.strategy = strategy;
    crawl.scope.max_discovery_depth = 3;
    crawl.dynamic.observe_only = observe_only;
    crawl.dynamic.page_hooks = true;
    if mode == CrawlMode::Hybrid {
        crawl.dynamic.always_browser_paths = vec!["^/$".into()];
    }
    crawl.limits.states = 100;
    crawl.limits.interactions = 100;
    crawl.normalize().unwrap();
    let stores =
        crawlx_worker::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), directory.path())
            .await
            .unwrap();
    let record = surface_common::authorization_fixture::verified_record(&crawl, stores.tenant);
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let backend = Arc::new(strategy_tree_browser(&site.base));
    let config = surface_common::config(directory.path());
    let run = if leased {
        run_queued_strategy_tree(crawl, config, stores.clone(), backend.clone()).await
    } else {
        let report = surface_common::authorization_fixture::run_authorized_local_with(
            crawlx_worker::LocalRun::new(crawl, config)
                .with_stores(stores.clone())
                .with_backend(backend.clone()),
        )
        .await
        .unwrap();
        assert_eq!(
            report.status,
            RunStatus::Completed,
            "{:?}",
            report.terminal_reason
        );
        assert_eq!(report.terminal_reason, Some(TerminalReason::FrontierExhausted));
        report.run_id
    };
    let expected = strategy_tree_order(strategy);
    let pages = stores.pages.list(run).await.unwrap();
    assert_eq!(
        pages.len(),
        STRATEGY_TREE.len(),
        "{mode:?}, {strategy:?}, leased={leased}"
    );
    if mode != CrawlMode::Dynamic {
        assert_eq!(
            site.gets(),
            expected,
            "HTTP {mode:?}, {strategy:?}, leased={leased}"
        );
    } else {
        assert!(
            site.gets().is_empty(),
            "dynamic never fetches target pages over HTTP"
        );
    }
    if mode != CrawlMode::Static {
        let contexts = backend.context_handles();
        assert_eq!(contexts.len(), 1);
        let navigated: Vec<_> = contexts[0]
            .navigations()
            .iter()
            .map(|url| Url::parse(url).unwrap().path().to_owned())
            .collect();
        assert_eq!(
            navigated, expected,
            "browser {mode:?}, {strategy:?}, leased={leased}, observe_only={observe_only}"
        );
    }
}

#[tokio::test]
async fn static_tree_preserves_bfs_levels_and_dfs_deepest_first_locally_and_when_leased() {
    for leased in [false, true] {
        for strategy in [CrawlStrategy::BreadthFirst, CrawlStrategy::DepthFirst] {
            assert_strategy_tree(crawlx_core::config::CrawlMode::Static, strategy, leased, true).await;
        }
    }
}

#[tokio::test]
async fn hybrid_tree_preserves_bfs_levels_and_dfs_deepest_first_locally_and_when_leased() {
    for leased in [false, true] {
        for strategy in [CrawlStrategy::BreadthFirst, CrawlStrategy::DepthFirst] {
            for observe_only in [true, false] {
                assert_strategy_tree(
                    crawlx_core::config::CrawlMode::Hybrid,
                    strategy,
                    leased,
                    observe_only,
                )
                .await;
            }
        }
    }
}

#[tokio::test]
async fn dynamic_tree_preserves_bfs_levels_and_dfs_deepest_first_locally_and_when_leased() {
    for leased in [false, true] {
        for strategy in [CrawlStrategy::BreadthFirst, CrawlStrategy::DepthFirst] {
            for observe_only in [true, false] {
                assert_strategy_tree(
                    crawlx_core::config::CrawlMode::Dynamic,
                    strategy,
                    leased,
                    observe_only,
                )
                .await;
            }
        }
    }
}

// ---- extract.formFill ---------------------------------------------------------------------

const FORMS_PAGE: &str = r#"
    <form method="get" action="/search">
      <input type="email" name="mail"><input type="password" name="pw">
      <input type="text" name="note" placeholder="needle"><input type="submit" value="go">
    </form>
    <form method="post" action="/submit">
      <input type="password" name="pw"><input type="hidden" name="csrf" value="tok"><input type="submit" value="send">
    </form>"#;

async fn forms_site() -> Site {
    Site::start(|_| {
        Router::new()
            .route("/", get(|| async { page("Forms", FORMS_PAGE) }))
            .route("/search", get(|| async { page("Results", "") }))
            .route("/submit", any(|| async { page("Submitted", "") }))
    })
    .await
}

fn fill() -> FormFill {
    FormFill {
        enabled: true,
        email: Some("qa@example.test".to_owned()),
        password: Some("hunter2-test".to_owned()),
        ..FormFill::default()
    }
}

fn search_query(site: &Site) -> BTreeMap<String, String> {
    let target = site
        .gets()
        .into_iter()
        .find(|p| p.starts_with("/search"))
        .unwrap_or_else(|| panic!("/search was not fetched: {:?}", site.gets()));
    query_of(&target)
}

#[tokio::test]
async fn form_fill_fetches_get_forms_with_the_configured_values() {
    let site = forms_site().await;
    let run = crawl(&site.base, |c| c.extract.form_fill = fill()).await;
    let query = search_query(&site);
    assert_eq!(query["mail"], "qa@example.test");
    assert_eq!(query["pw"], "hunter2-test");
    assert_eq!(
        query["note"], "needle",
        "the placeholder is the fallback of an unclassified field"
    );
    let search = run
        .report
        .pages
        .iter()
        .find(|p| p.url.url.path() == "/search")
        .expect("the filled GET form is a page");
    assert_eq!(search.metadata["request"]["tag"], "form");
    assert_eq!(search.metadata["request"]["attribute"], "action");
}

#[tokio::test]
async fn form_fill_records_post_forms_with_their_body_and_never_sends_them() {
    let site = forms_site().await;
    let run = crawl(&site.base, |c| c.extract.form_fill = fill()).await;
    assert_eq!(
        site.count("/submit"),
        0,
        "a POST form is only recorded: {:?}",
        site.requests()
    );
    assert!(site.requests().iter().all(|(m, _)| m == "GET"));
    let home = page_at(&run.report, "/");
    let recorded = home.metadata["discovered_endpoints"].as_array().unwrap();
    let post = recorded
        .iter()
        .find(|e| e["method"] == "POST")
        .unwrap_or_else(|| panic!("no recorded POST in {recorded:?}"));
    assert!(post["url"].as_str().unwrap().ends_with("/submit"));
    let body = post["body"].as_str().unwrap();
    assert!(body.contains("pw=hunter2-test"), "{body}");
    assert!(body.contains("csrf=tok"), "{body}");
    assert_eq!(post["content_type"], "application/x-www-form-urlencoded");
    assert_eq!(
        (post["tag"].as_str(), post["attribute"].as_str()),
        (Some("form"), Some("action"))
    );
}

#[tokio::test]
async fn without_form_fill_the_configured_values_are_not_used() {
    let site = forms_site().await;
    crawl(&site.base, |_| {}).await;
    let query = search_query(&site);
    assert_ne!(query.get("mail").map(String::as_str), Some("qa@example.test"));
    assert_ne!(query.get("pw").map(String::as_str), Some("hunter2-test"));
}

/// Answers every unresolved field with `zebra` and remembers which ones it was asked about.
struct Zebra(Mutex<Vec<String>>);

#[async_trait]
impl FormAi for Zebra {
    async fn decide(
        &self,
        _page: &Url,
        _action: &Url,
        unresolved: &[UnresolvedField],
    ) -> BTreeMap<String, String> {
        let mut asked = self.0.lock().unwrap();
        unresolved
            .iter()
            .map(|f| {
                asked.push(f.name.clone());
                (f.name.clone(), "zebra".to_owned())
            })
            .collect()
    }
}

#[tokio::test]
async fn unresolved_form_fields_are_filled_by_the_form_ai() {
    let site = Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Ask",
                        r#"<form action="/ask"><input type="text" name="zzfield"></form>"#,
                    )
                }),
            )
            .route("/ask", get(|| async { page("Answer", "") }))
    })
    .await;
    let ai = Arc::new(Zebra(Mutex::new(Vec::new())));
    let decider: Arc<dyn FormAi> = ai.clone();
    crawl_with(
        &site.base,
        |c| c.extract.form_fill = fill(),
        move |cfg| cfg.form_ai = Some(decider),
        |run| run,
    )
    .await;
    let target = site.gets().into_iter().find(|p| p.starts_with("/ask")).unwrap();
    assert_eq!(query_of(&target)["zzfield"], "zebra");
    assert_eq!(*ai.0.lock().unwrap(), ["zzfield"]);
}

#[tokio::test]
async fn without_a_form_ai_unresolved_fields_keep_their_seeded_value() {
    let site = Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Ask",
                        r#"<form action="/ask"><input type="text" name="zzfield"></form>"#,
                    )
                }),
            )
            .route("/ask", get(|| async { page("Answer", "") }))
    })
    .await;
    crawl(&site.base, |c| c.extract.form_fill = fill()).await;
    let target = site.gets().into_iter().find(|p| p.starts_with("/ask")).unwrap();
    let value = &query_of(&target)["zzfield"];
    assert!(!value.is_empty() && value != "zebra", "{value}");
}

// ---- extract.kbEndpoints ------------------------------------------------------------------

async fn endpoints_site() -> Site {
    Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        r#"<a href="/graphql">g</a><a href="/docs/x">d</a>
                           <form method="post" action="/api/v1/users"><input name="n" value="1"></form>"#,
                    )
                }),
            )
            .route("/graphql", get(|| async { page("GraphQL", "") }))
            .route("/docs/x", get(|| async { page("Doc", "") }))
    })
    .await
}

#[tokio::test]
async fn kb_endpoints_classify_every_discovered_endpoint() {
    let site = endpoints_site().await;
    let run = crawl(&site.base, |c| c.extract.kb_endpoints = true).await;
    let endpoints = page_at(&run.report, "/").metadata["endpoints"]
        .as_array()
        .unwrap()
        .clone();
    let class_of = |suffix: &str| -> String {
        endpoints
            .iter()
            .find(|e| e["url"].as_str().unwrap().ends_with(suffix))
            .unwrap_or_else(|| panic!("{suffix} missing in {endpoints:?}"))["class"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(class_of("/graphql"), "graphql");
    assert_eq!(class_of("/docs/x"), "static");
    assert_eq!(class_of("/api/v1/users"), "rest");
    let post = endpoints
        .iter()
        .find(|e| e["url"].as_str().unwrap().ends_with("/api/v1/users"))
        .unwrap();
    assert_eq!(post["method"], "POST");
}

#[tokio::test]
async fn endpoints_are_not_classified_unless_asked() {
    let site = endpoints_site().await;
    let run = crawl(&site.base, |_| {}).await;
    assert!(page_at(&run.report, "/").metadata.get("endpoints").is_none());
}

// ---- failures -----------------------------------------------------------------------------

#[tokio::test]
async fn failed_urls_are_reported_sorted_with_their_status() {
    let site = Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        r#"<a href="/zz-missing">m</a><a href="/aa-gone">g</a><a href="/fine">f</a>"#,
                    )
                }),
            )
            .route("/fine", get(|| async { page("Fine", "") }))
            .route("/aa-gone", get(|| async { StatusCode::GONE }))
            .fallback(|| async { StatusCode::NOT_FOUND })
    })
    .await;
    let run = crawl(&site.base, |_| {}).await;
    assert_eq!(
        run.report.terminal_reason,
        Some(TerminalReason::FrontierExhausted)
    );
    let failures: Vec<(String, u16, String, Option<u16>)> = run
        .report
        .failures
        .iter()
        .map(|f| (f.url.replace(&site.base, ""), f.depth, f.reason.clone(), f.status))
        .collect();
    assert_eq!(
        failures,
        [
            ("/aa-gone".to_owned(), 1, "http_410".to_owned(), Some(410)),
            ("/zz-missing".to_owned(), 1, "http_404".to_owned(), Some(404)),
        ]
    );
    assert!(
        run.report.resume.is_none(),
        "an exhausted frontier has nothing to resume"
    );
}

// ---- request and raw metadata -------------------------------------------------------------

const HOME: &str = r#"<a href="/other">other</a>"#;

async fn raw_site() -> Site {
    Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    (
                        [
                            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                            (header::SET_COOKIE, "sid=abcdef-session-secret; HttpOnly"),
                            (header::HeaderName::from_static("x-debug"), "on"),
                        ],
                        format!("<html><head><title>Home</title></head><body><main><h1>Home</h1><p>Text.</p>{HOME}</main></body></html>"),
                    )
                        .into_response()
                }),
            )
            .route("/other", get(|| async { page("Other", "") }))
    })
    .await
}

#[tokio::test]
async fn every_page_records_its_request_and_content_length() {
    let site = raw_site().await;
    let run = crawl(&site.base, |_| {}).await;
    let home = page_at(&run.report, "/");
    let request = &home.metadata["request"];
    assert_eq!(request["method"], "GET");
    assert!(request["headers"]["user-agent"]
        .as_str()
        .unwrap()
        .starts_with("crawlx/"));
    let expected = format!(
        "<html><head><title>Home</title></head><body><main><h1>Home</h1><p>Text.</p>{HOME}</main></body></html>"
    );
    assert_eq!(home.metadata["content_length"], expected.len());
    assert!(
        request.get("raw").is_none(),
        "raw text only under output.captureRaw"
    );
    assert!(home.metadata.get("raw_artifact").is_none());
    assert!(run.report.page_contents.iter().all(|c| c.raw.is_none()));
    // the page found by a link also says how
    let other = page_at(&run.report, "/other");
    assert_eq!(other.metadata["request"]["tag"], "a");
    assert_eq!(other.metadata["request"]["method"], "GET");
}

#[tokio::test]
async fn capture_raw_keeps_the_exchange_text_with_credentials_redacted() {
    let site = raw_site().await;
    let run = crawl(&site.base, |c| c.output.capture_raw = true).await;
    let home = page_at(&run.report, "/");
    let request_raw = home.metadata["request"]["raw"].as_str().unwrap();
    assert!(
        request_raw.starts_with(&format!("GET / HTTP/1.1\r\nhost: {}\r\n", site.addr)),
        "{request_raw:?}"
    );
    assert!(request_raw.ends_with("\r\n\r\n"));

    let content = run
        .report
        .page_contents
        .iter()
        .find(|c| c.url.ends_with('/') && c.url.starts_with(&site.base))
        .unwrap();
    let raw = content.raw.as_deref().expect("raw response text");
    let artifact: crawlx_core::ArtifactRef =
        serde_json::from_value(home.metadata["raw_artifact"].clone()).expect("retained raw response receipt");
    assert_eq!(run.stores.artifacts.get(&artifact).await.unwrap(), raw.as_bytes());
    assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{raw:?}");
    assert!(raw.contains("x-debug: on\r\n"));
    assert!(!raw.contains("abcdef-session-secret"));
    assert!(
        raw.contains("\r\n\r\n<html>"),
        "headers, a blank line, then the body"
    );
    assert!(raw.ends_with("</html>"));
}

#[tokio::test]
async fn capture_raw_masks_json_before_embedding_it_in_http_exchange_text() {
    const ESCAPED: &str =
        r#"{"pass\u0077ord":"escaped-member-canary-q7m2","marker":"visible-json-marker-q7m2"}"#;
    const DUPLICATE: &str = r#"{"data":"duplicate-\u0068idden-canary-q7m2","data":"safe"}"#;
    let site = Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        r#"<a href="/escaped-json">escaped</a><a href="/duplicate-json">duplicate</a>"#,
                    )
                }),
            )
            .route(
                "/escaped-json",
                get(|| async { ([(header::CONTENT_TYPE, "application/json")], ESCAPED) }),
            )
            .route(
                "/duplicate-json",
                get(|| async { ([(header::CONTENT_TYPE, "application/json")], DUPLICATE) }),
            )
    })
    .await;
    // Neither canary is registered or supplied as a request-control secret.
    let run = crawl(&site.base, |crawl| crawl.output.capture_raw = true).await;
    for path in ["/escaped-json", "/duplicate-json"] {
        assert_eq!(site.gets().iter().filter(|got| got.as_str() == path).count(), 1);
        let page = page_at(&run.report, path);
        let artifact: crawlx_core::ArtifactRef =
            serde_json::from_value(page.metadata["raw_artifact"].clone())
                .expect("retained redacted HTTP diagnostic receipt");
        let bytes = run.stores.artifacts.get(&artifact).await.unwrap();
        let raw = std::str::from_utf8(&bytes).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{path}: {raw:?}");
        assert!(!raw.contains("escaped-member-canary-q7m2"), "{path}: {raw:?}");
        assert!(!raw.contains("duplicate-hidden-canary-q7m2"), "{path}: {raw:?}");
        assert!(
            !raw.contains(r"duplicate-\u0068idden-canary-q7m2"),
            "{path}: {raw:?}"
        );
        assert!(!raw.contains(ESCAPED), "{path}: {raw:?}");
        assert!(!raw.contains(DUPLICATE), "{path}: {raw:?}");
        if path == "/escaped-json" {
            assert!(raw.contains("visible-json-marker-q7m2"), "{raw:?}");
        }
        let reported = run
            .report
            .page_contents
            .iter()
            .find(|content| content.url == page.url.url.as_str())
            .unwrap();
        assert_eq!(reported.raw.as_deref(), Some(raw));
    }
}

#[tokio::test]
async fn capture_raw_masks_uninspectable_escaped_json_bodies_and_keeps_public_prefixes() {
    const PARTIAL: &str = r#"{"pass\u0077ord":"partial-unknown-canary"#;
    let capped = bytes::Bytes::from(format!("{PARTIAL}{}\"}}", "x".repeat(2048)));
    let public = bytes::Bytes::from(format!(
        "{{\"message\":\"public-prefix-marker{}\"}}",
        "x".repeat(2048)
    ));
    let site = Site::start(move |_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        r#"<a href="/malformed-json">malformed</a><a href="/capped-json">capped</a><a href="/public-prefix">public</a>"#,
                    )
                }),
            )
            .route(
                "/malformed-json",
                get(|| async { ([(header::CONTENT_TYPE, "application/json")], PARTIAL) }),
            )
            .route(
                "/capped-json",
                get(move || {
                    let body = capped.clone();
                    async move { ([(header::CONTENT_TYPE, "application/json")], body) }
                }),
            )
            .route(
                "/public-prefix",
                get(move || {
                    let body = public.clone();
                    async move { ([(header::CONTENT_TYPE, "application/json")], body) }
                }),
            )
    })
    .await;
    let run = crawl(&site.base, |crawl| {
        crawl.output.capture_raw = true;
        crawl.fetch.max_response_bytes = 1024;
    })
    .await;
    for (path, body_length) in [
        ("/malformed-json", PARTIAL.len()),
        ("/capped-json", 1024),
        ("/public-prefix", 1024),
    ] {
        let page = page_at(&run.report, path);
        assert_eq!(page.content_type.as_deref(), Some("application/json"));
        assert_eq!(page.metadata["content_length"], body_length, "{path}");
        let artifact: crawlx_core::ArtifactRef =
            serde_json::from_value(page.metadata["raw_artifact"].clone())
                .expect("retained redacted HTTP diagnostic receipt");
        let bytes = run.stores.artifacts.get(&artifact).await.unwrap();
        let raw = std::str::from_utf8(&bytes).unwrap();
        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{path}: {raw:?}");
        assert!(!raw.contains("partial-unknown-canary"), "{path}: {raw:?}");
        assert!(!raw.contains(PARTIAL), "{path}: {raw:?}");
        if path == "/public-prefix" {
            assert!(raw.contains("public-prefix-marker"), "{raw:?}");
        }
    }
}

#[tokio::test]
async fn custom_fields_are_also_reported_under_the_request() {
    let site = Site::start(|_| {
        Router::new().route(
            "/",
            get(|| async { page("Home", "<p>build-4711 and build-4712</p>") }),
        )
    })
    .await;
    let run = crawl(&site.base, |c| {
        c.extract.custom_fields = vec![crawlx_core::config::CustomField {
            name: "build".to_owned(),
            regex: vec![r"build-\d+".to_owned()],
            part: crawlx_core::config::CustomFieldPart::default(),
            group: 0,
        }];
    })
    .await;
    let home = page_at(&run.report, "/");
    let fields = &home.metadata["custom_fields"];
    assert_eq!(fields["build"], serde_json::json!(["build-4711", "build-4712"]));
    assert_eq!(home.metadata["request"]["custom_fields"], *fields);
}
