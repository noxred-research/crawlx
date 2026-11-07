//! The navigation guard against a local Chromium (skipped without one; set
//! `CRAWLX_CHROMIUM_PATH`): `Fetch.requestPaused` for main-frame documents, `Fetch.failRequest`
//! (`Aborted`) for a refusal, and nothing paused for subresources and frames. The scripted
//! twin of these tests runs everywhere in `navigation_guard.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod katana_p4_support;

use async_trait::async_trait;
use crawlx_browser::{CdpContext, NavigationGuard, NavigationVerdict};
use crawlx_core::browser::{BrowserContext, BrowserError, ContextConfig};
use crawlx_core::observation::QuiescencePolicy;
use katana_p4_support::{canonical, context_config, launch, serve};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

/// Refuses every document under `/private/`; remembers every URL it was asked about.
#[derive(Debug, Default)]
struct PrivateGuard {
    asked: Mutex<Vec<String>>,
}

#[async_trait]
impl NavigationGuard for PrivateGuard {
    async fn check(&self, url: &Url) -> NavigationVerdict {
        self.asked.lock().push(url.path().to_owned());
        if url.path().starts_with("/private/") {
            NavigationVerdict::RobotsBlocked {
                reason: "robots_disallow",
            }
        } else {
            NavigationVerdict::Allow
        }
    }
}

fn html(body: &str) -> (&'static str, String) {
    (
        "text/html; charset=utf-8",
        format!("<!doctype html><html><head><title>t</title></head><body>{body}</body></html>"),
    )
}

fn guarded() -> (ContextConfig, Arc<PrivateGuard>) {
    let guard = Arc::new(PrivateGuard::default());
    let mut config = context_config();
    config.navigation_guard = Some(Arc::clone(&guard) as Arc<dyn NavigationGuard>);
    (config, guard)
}

async fn path_of(ctx: &CdpContext) -> String {
    ctx.evaluate_isolated("location.pathname")
        .await
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_navigation_is_never_sent_and_an_allowed_one_loads() {
    let routes = BTreeMap::from([
        ("127.0.0.1/".to_owned(), html("<p>home</p>")),
        ("127.0.0.1/private/x".to_owned(), html("<p>secret</p>")),
    ]);
    let server = serve(routes, false).await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let (config, guard) = guarded();
    let mut ctx = backend.new_cdp_context(config).await.unwrap();

    let base = format!("http://127.0.0.1:{}", server.port);
    ctx.navigate(&canonical(&format!("{base}/"))).await.unwrap();
    assert_eq!(path_of(&ctx).await, "/");

    let err = ctx
        .navigate(&canonical(&format!("{base}/private/x")))
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::RobotsBlocked { .. }), "{err:?}");
    assert_eq!(path_of(&ctx).await, "/", "the page stays where it was");
    assert_eq!(
        server.hits.count("127.0.0.1/private/x"),
        0,
        "{:?}",
        server.hits.all()
    );
    // refused before anything was sent: nothing for the next drain either
    assert!(ctx.drain_blocked_navigations().is_empty());
    assert!(guard.asked.lock().contains(&"/private/x".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_link_the_page_follows_is_aborted_in_the_browser() {
    let routes = BTreeMap::from([
        (
            "127.0.0.1/".to_owned(),
            html(r#"<a id="secret" href="/private/x">secret</a><a id="open" href="/public">open</a>"#),
        ),
        ("127.0.0.1/private/x".to_owned(), html("<p>secret</p>")),
        ("127.0.0.1/public".to_owned(), html("<p>public</p>")),
    ]);
    let server = serve(routes, false).await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let (config, _guard) = guarded();
    let mut ctx = backend.new_cdp_context(config).await.unwrap();
    let base = format!("http://127.0.0.1:{}", server.port);
    ctx.navigate(&canonical(&format!("{base}/"))).await.unwrap();

    ctx.evaluate_isolated("document.getElementById('secret').click()")
        .await
        .unwrap();
    // the paused request is answered off the event pump: wait for the refusal to be recorded
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut refused = ctx.drain_blocked_navigations();
    while refused.is_empty() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        refused = ctx.drain_blocked_navigations();
    }
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].url.ends_with("/private/x"), "{refused:?}");
    assert_eq!(refused[0].reason, "robots_disallow");
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    assert_eq!(
        path_of(&ctx).await,
        "/",
        "an aborted navigation leaves the document in place"
    );
    assert_eq!(
        server.hits.count("127.0.0.1/private/x"),
        0,
        "{:?}",
        server.hits.all()
    );

    // an allowed link still navigates
    ctx.evaluate_isolated("document.getElementById('open').click()")
        .await
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while path_of(&ctx).await != "/public" && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(path_of(&ctx).await, "/public");
    assert!(ctx.drain_blocked_navigations().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subresources_and_frames_are_never_judged() {
    let routes = BTreeMap::from([
        (
            "127.0.0.1/".to_owned(),
            html(r#"<img src="/private/pic.svg"><iframe src="/private/frame"></iframe>"#),
        ),
        (
            "127.0.0.1/private/pic.svg".to_owned(),
            (
                "image/svg+xml",
                "<svg xmlns='http://www.w3.org/2000/svg'/>".to_owned(),
            ),
        ),
        ("127.0.0.1/private/frame".to_owned(), html("<p>framed</p>")),
    ]);
    let server = serve(routes, false).await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let (config, guard) = guarded();
    let mut ctx = backend.new_cdp_context(config).await.unwrap();
    let base = format!("http://127.0.0.1:{}", server.port);
    ctx.navigate(&canonical(&format!("{base}/"))).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();

    // the main document is judged before `Page.navigate` and again when the browser pauses its
    // request; no subresource and no frame document is ever judged
    let asked = guard.asked.lock().clone();
    assert!(
        !asked.is_empty() && asked.iter().all(|p| p == "/"),
        "only the main document was judged: {asked:?}"
    );
    assert_eq!(
        server.hits.count("127.0.0.1/private/pic.svg"),
        1,
        "{:?}",
        server.hits.all()
    );
    assert_eq!(
        server.hits.count("127.0.0.1/private/frame"),
        1,
        "{:?}",
        server.hits.all()
    );
    assert!(ctx.drain_blocked_navigations().is_empty());
}
