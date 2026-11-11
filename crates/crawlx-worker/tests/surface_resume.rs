//! The `-resume` compatibility flag on the static plane: a run stopped by a limit or a cancellation reports
//! what it did and what is left, and a second run seeded with that state finishes the site
//! without fetching anything twice.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod surface_common;

use axum::routing::get;
use axum::Router;
use crawlx_core::counters::TerminalReason;
use crawlx_worker::surface::resume::ResumeState;
use std::collections::BTreeSet;
use surface_common::authorization_fixture;
use surface_common::{crawl_with, page, page_paths, Site};
use tokio_util::sync::CancellationToken;

/// `/` links to a, b and c; each of them links to its own leaves: eight pages.
async fn tree_site() -> Site {
    fn leaf(title: &'static str) -> axum::routing::MethodRouter {
        get(move || async move { page(title, "") })
    }
    Site::start(|_| {
        Router::new()
            .route(
                "/",
                get(|| async {
                    page(
                        "Home",
                        r#"<a href="/a">a</a><a href="/b">b</a><a href="/c">c</a>"#,
                    )
                }),
            )
            .route(
                "/a",
                get(|| async { page("A", r#"<a href="/a1">a1</a><a href="/a2">a2</a>"#) }),
            )
            .route("/b", get(|| async { page("B", r#"<a href="/b1">b1</a>"#) }))
            .route("/c", get(|| async { page("C", r#"<a href="/c1">c1</a>"#) }))
            .route("/a1", leaf("A1"))
            .route("/a2", leaf("A2"))
            .route("/b1", leaf("B1"))
            .route("/c1", leaf("C1"))
    })
    .await
}

const ALL: [&str; 8] = ["/", "/a", "/a1", "/a2", "/b", "/b1", "/c", "/c1"];

fn paths_of(urls: &[String]) -> Vec<String> {
    let mut v: Vec<String> = urls
        .iter()
        .map(|u| url::Url::parse(u).unwrap().path().to_owned())
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn a_limited_run_reports_what_is_left_and_a_second_run_finishes_the_site() {
    let site = tree_site().await;
    let first = crawl_with(&site.base, |c| c.limits.urls = 4, |_| {}, |run| run).await;
    assert_eq!(first.report.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(page_paths(&first.report), ["/", "/a", "/b", "/c"]);
    let state = first
        .report
        .resume
        .clone()
        .expect("the frontier was not exhausted");
    assert_eq!(paths_of(&state.visited), ["/", "/a", "/b", "/c"]);
    assert_eq!(
        paths_of(&state.pending.iter().map(|e| e.url.clone()).collect::<Vec<_>>()),
        ["/a1", "/a2", "/b1", "/c1"]
    );
    assert!(state.pending.iter().all(|e| e.depth == 2));

    // the state survives a trip through a file
    let state = ResumeState::from_json(&state.to_json().unwrap()).unwrap();
    let second = crawl_with(&site.base, |_| {}, |_| {}, |run| run.with_resume(state)).await;
    assert_eq!(
        second.report.terminal_reason,
        Some(TerminalReason::FrontierExhausted)
    );
    assert!(second.report.resume.is_none(), "nothing is left");
    assert_eq!(page_paths(&second.report), ["/a1", "/a2", "/b1", "/c1"]);

    // together the runs fetched the whole site, each page once
    let fetched = site.gets();
    let unique: BTreeSet<&String> = fetched.iter().collect();
    assert_eq!(fetched.len(), unique.len(), "no page twice: {fetched:?}");
    let mut got: Vec<&str> = fetched.iter().map(String::as_str).collect();
    got.sort_unstable();
    assert_eq!(got, ALL);
}

#[tokio::test]
async fn a_cancelled_run_leaves_its_seed_pending_and_resume_completes_it() {
    let site = tree_site().await;
    let cancel = CancellationToken::new();
    cancel.cancel();
    let first = crawl_with(&site.base, |_| {}, |_| {}, |run| run.with_cancel(cancel)).await;
    assert!(site.gets().is_empty(), "a cancelled run fetches nothing");
    let state = first.report.resume.clone().expect("the seed was never fetched");
    assert!(state.visited.is_empty());
    assert_eq!(
        paths_of(&state.pending.iter().map(|e| e.url.clone()).collect::<Vec<_>>()),
        ["/"]
    );

    let second = crawl_with(&site.base, |_| {}, |_| {}, |run| run.with_resume(state)).await;
    assert_eq!(page_paths(&second.report), ALL);
    assert!(second.report.resume.is_none());
}

#[tokio::test]
async fn visited_urls_are_not_fetched_again_even_when_the_site_links_to_them() {
    let site = tree_site().await;
    // `/a` and `/c` count as done: the second run must walk around them
    let visited = [format!("{}/a", site.base), format!("{}/c", site.base)];
    let state = ResumeState::new(visited, []);
    let run = crawl_with(&site.base, |_| {}, |_| {}, |run| run.with_resume(state)).await;
    assert_eq!(page_paths(&run.report), ["/", "/b", "/b1"]);
    assert!(
        !site
            .gets()
            .iter()
            .any(|p| p.starts_with("/a") || p.starts_with("/c")),
        "{:?}",
        site.gets()
    );
}

#[tokio::test]
async fn interrupted_article_resume_preserves_duplicate_main_and_refuses_foreign_tenant() {
    use crawlx_core::extraction::{DedupePolicyV1, DedupeSnapshotError, ExtractionPolicyV1};
    use crawlx_worker::surface::resume::ResumeError;
    use crawlx_worker::{LocalRun, WorkerError};
    use surface_common::{config, page_at, static_crawl};

    let site = Site::start(|_| {
        let article = || async {
            surface_common::html(
                "<html><head><title>Repeated article</title></head><body>\
                 <nav><a href='/b'>Second address</a></nav><main><article>\
                 <h1>Repeated article</h1><p>This article has identical title and main content \
                 at two addresses. An interrupted crawl must retain its first admission \
                 and reject the second address after its authorized continuation.</p>\
                 <p>Only bounded hashes and counts travel with the existing checkpoint. \
                 Article content never enters the continuation cache.</p>\
                 </article></main></body></html>",
            )
        };
        Router::new().route("/a", get(article)).route("/b", get(article))
    })
    .await;
    let configure = |crawl: &mut crawlx_core::CreateCrawl| {
        crawl.seed_url = url::Url::parse(&format!("{}/a", site.base)).unwrap();
        // The duplicate lives beside the seed, not beneath its default path scope.
        crawl.scope.crawl_entire_domain = true;
        crawl.politeness.max_concurrency = 1;
        crawl.scope.disable_unique_filter = true;
        let mut dedupe = DedupePolicyV1::default();
        dedupe.content = true;
        let mut content = ExtractionPolicyV1::default();
        content.dedupe = Some(dedupe);
        crawl.extract.content = Some(content);
    };
    let baseline = crawl_with(&site.base, configure, |_| {}, |run| run).await;
    assert_eq!(page_paths(&baseline.report), ["/a", "/b"]);
    let first = crawl_with(
        &site.base,
        |crawl| {
            configure(crawl);
            crawl.limits.urls = 1;
        },
        |_| {},
        |run| run,
    )
    .await;
    assert_eq!(first.report.terminal_reason, Some(TerminalReason::LimitReached));
    assert_eq!(page_paths(&first.report), ["/a"]);
    let state = first.report.resume.as_ref().unwrap();
    assert!(state.dedupe.is_some());
    let json = state.to_json().unwrap();
    assert!(!json.contains("This article has identical"));
    let state = ResumeState::from_json(&json).unwrap();
    let mut crawl = static_crawl(&site.base);
    configure(&mut crawl);
    let resumed = authorization_fixture::run_authorized_local_with(
        LocalRun::new(crawl.clone(), config(first.dir.path()))
            .with_stores(first.stores.clone())
            .with_resume(state.clone()),
    )
    .await
    .unwrap();
    assert_ne!(resumed.run_id, first.report.run_id);
    assert_eq!(page_paths(&resumed), ["/b"]);
    assert!(resumed.resume.is_none());
    let extraction = &page_at(&resumed, "/b").metadata["extraction"];
    let mut expected = page_at(&baseline.report, "/b").metadata["extraction"].clone();
    // Each run owns a new immutable artifact ID; its digest and extraction must match.
    assert_ne!(extraction["content"]["id"], expected["content"]["id"]);
    expected["content"]["id"] = extraction["content"]["id"].clone();
    assert_eq!(*extraction, expected);
    let quality = &page_at(&resumed, "/b").metadata["extraction"]["quality"];
    assert_eq!(quality["status"], "rejected");
    assert_eq!(quality["reasons"], serde_json::json!(["duplicate_main"]));
    assert_eq!(
        first.report.counters.urls.succeeded + resumed.counters.urls.succeeded,
        baseline.report.counters.urls.succeeded
    );
    let mut combined = page_paths(&first.report);
    combined.extend(page_paths(&resumed));
    combined.sort();
    assert_eq!(combined, page_paths(&baseline.report));
    let persisted = first.stores.pages.list(resumed.run_id).await.unwrap();
    assert_eq!(persisted.len(), 1);
    assert_eq!(persisted[0].url.url.path(), "/b");
    assert_eq!(persisted[0].status, 200);
    assert!(!persisted[0].metadata["extraction"]["content"].is_null());
    assert_eq!(persisted[0].metadata["extraction"]["quality"], *quality);

    let mut foreign = first.stores.clone();
    foreign.tenant = crawlx_core::TenantId::new();
    let before = site.gets();
    let refused = authorization_fixture::run_authorized_local_with(
        LocalRun::new(crawl, config(first.dir.path()))
            .with_stores(foreign)
            .with_resume(state),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(
            refused,
            WorkerError::Resume(ResumeError::Dedupe(DedupeSnapshotError::Binding))
        ),
        "{refused}"
    );
    assert_eq!(
        site.gets(),
        before,
        "tenant refusal happens before target requests"
    );
}
