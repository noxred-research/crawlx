//! Katana `-resume` on the static plane: a run stopped by a limit or a cancellation reports
//! what it did and what is left, and a second run seeded with that state finishes the site
//! without fetching anything twice.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod katana_p4_common;

use axum::routing::get;
use axum::Router;
use crawlx_core::counters::TerminalReason;
use crawlx_worker::katana::resume::ResumeState;
use katana_p4_common::{crawl_with, page, page_paths, Site};
use std::collections::BTreeSet;
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
