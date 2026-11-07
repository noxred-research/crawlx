//! The navigation guard (`ContextConfig::navigation_guard`) on `FakeBackend`: consulted before
//! any document loads, a refused navigation never reaches the (fake) network and is reported as
//! `BrowserError::RobotsBlocked`, a page's own navigations (link clicks, popups) are refused in
//! the browser, and subresources never ask the guard. No Chromium needed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::{FakeBackend, FakeContext, NavigationGuard, NavigationVerdict};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, BrowserContext, BrowserError, ContextConfig};
use crawlx_core::error::{Classify, ErrorClass};
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationBundle, ObservationSpec, RuntimeLocator};
use crawlx_core::url::CanonicalUrl;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use std::sync::Arc;
use url::Url;

const HOME: &str = "https://site.test/";
const PRIVATE: &str = "https://site.test/private/x";

fn canon(s: &str) -> CanonicalUrl {
    Canonicalizer::canonicalize_url(&Url::parse(s).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

/// Refuses every path under `/private/`; remembers every URL it was asked about and how many
/// documents the context had loaded at that moment.
#[derive(Debug, Default)]
struct PrivateGuard {
    asked: Mutex<Vec<(String, usize)>>,
    loaded: Mutex<Option<crawlx_browser::fake::FakeContextHandle>>,
}

impl PrivateGuard {
    fn urls(&self) -> Vec<String> {
        self.asked.lock().iter().map(|(u, _)| u.clone()).collect()
    }
}

#[async_trait]
impl NavigationGuard for PrivateGuard {
    async fn check(&self, url: &Url) -> NavigationVerdict {
        let loaded = self.loaded.lock().as_ref().map_or(0, |h| h.navigations().len());
        self.asked.lock().push((url.to_string(), loaded));
        if url.path().starts_with("/private/") {
            NavigationVerdict::RobotsBlocked {
                reason: "robots_disallow",
            }
        } else {
            NavigationVerdict::Allow
        }
    }
}

/// Never answers.
#[derive(Debug)]
struct SilentGuard;

#[async_trait]
impl NavigationGuard for SilentGuard {
    async fn check(&self, _url: &Url) -> NavigationVerdict {
        std::future::pending().await
    }
}

fn site() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new(HOME)
                .title("Home")
                .node(FakeAxSpec::link("lnk-public", "Public", "/public"))
                .node(FakeAxSpec::link("lnk-private", "Private", "/private/x"))
                .node(FakeAxSpec::button("btn-popup-private", "Popup private"))
                .node(FakeAxSpec::button("btn-popup-public", "Popup public"))
                .node(FakeAxSpec::button("btn-menu", "Menu"))
                .on_click("lnk-public", vec![FakeEffect::Navigate("/public".to_owned())])
                .on_click("lnk-private", vec![FakeEffect::Navigate("/private/x".to_owned())])
                .on_click(
                    "btn-popup-private",
                    vec![FakeEffect::OpenTab("https://site.test/private/x".to_owned())],
                )
                .on_click(
                    "btn-popup-public",
                    vec![FakeEffect::OpenTab("https://site.test/public".to_owned())],
                )
                .on_click(
                    "btn-menu",
                    vec![FakeEffect::Reveal(vec![FakeAxSpec::button("mi-1", "Item 1")])],
                )
                // subresources: an XHR to a path robots would disallow as a document
                .xhr("GET", "https://site.test/private/api", 200),
        )
        .page(FakePage::new("https://site.test/public").title("Public"))
        .page(FakePage::new(PRIVATE).title("Private"))
}

struct Rig {
    ctx: FakeContext,
    guard: Arc<PrivateGuard>,
}

fn guarded() -> Rig {
    let guard = Arc::new(PrivateGuard::default());
    let mut config = ContextConfig::new(SessionId::new());
    config.navigation_guard = Some(Arc::clone(&guard) as Arc<dyn NavigationGuard>);
    let ctx = enforcing().new_fake_context(config);
    *guard.loaded.lock() = Some(ctx.handle());
    Rig { ctx, guard }
}

/// A backend whose contexts consult the guard, as a real browser's do.
fn enforcing() -> FakeBackend {
    FakeBackend::builder()
        .script(site())
        .honour_navigation_guard()
        .build()
}

fn unguarded() -> FakeContext {
    FakeBackend::new(site()).new_fake_context(ContextConfig::new(SessionId::new()))
}

fn locator(bundle: &ObservationBundle, key: &str) -> RuntimeLocator {
    bundle
        .ax
        .nodes
        .iter()
        .find(|n| n.locator.ax_node_id.as_ref().is_some_and(|a| a.0 == key))
        .unwrap()
        .locator
        .clone()
}

fn click(target: RuntimeLocator) -> BrowserAction {
    BrowserAction::Click {
        target,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    }
}

async fn home(rig: &mut Rig) -> ObservationBundle {
    rig.ctx.navigate(&canon(HOME)).await.unwrap();
    rig.ctx.observe(ObservationSpec::default()).await.unwrap()
}

#[tokio::test]
async fn the_guard_is_consulted_before_the_document_loads() {
    let mut rig = guarded();
    rig.ctx.navigate(&canon(HOME)).await.unwrap();
    assert_eq!(rig.guard.urls(), vec![HOME.to_owned()]);
    // the context had loaded nothing when the guard was asked, and loaded the page after
    assert_eq!(rig.guard.asked.lock()[0].1, 0);
    assert_eq!(rig.ctx.handle().navigations(), vec![HOME.to_owned()]);
}

#[tokio::test]
async fn a_refused_navigation_is_robots_blocked_and_sends_nothing() {
    let mut rig = guarded();
    home(&mut rig).await;
    let before = rig.ctx.handle().navigations();
    rig.ctx.drain_traffic();

    let err = rig.ctx.navigate(&canon(PRIVATE)).await.unwrap_err();
    match &err {
        BrowserError::RobotsBlocked { url, reason } => {
            assert_eq!(url, PRIVATE);
            assert_eq!(*reason, "robots_disallow");
        }
        other => panic!("expected RobotsBlocked, got {other:?}"),
    }
    // callers tell it from a network failure and from an egress denial
    assert!(!matches!(
        err,
        BrowserError::Navigation(_) | BrowserError::EgressDenied(_)
    ));
    assert_eq!(err.class(), ErrorClass::PolicyDenied);

    let handle = rig.ctx.handle();
    assert_eq!(
        handle.navigations(),
        before,
        "no document request for the refused URL"
    );
    assert!(rig.ctx.drain_traffic().is_empty(), "no network request either");
    assert_eq!(handle.current_url(), HOME, "the page stays where it was");
    let refused = handle.refused_navigations();
    assert_eq!(refused.len(), 1);
    assert_eq!(
        (refused[0].url.as_str(), refused[0].reason),
        (PRIVATE, "robots_disallow")
    );
    // an error the caller already got is not reported a second time
    assert!(rig.ctx.drain_blocked_navigations().is_empty());
}

#[tokio::test]
async fn an_allowed_navigation_passes_and_a_context_without_a_guard_is_unchecked() {
    let mut rig = guarded();
    rig.ctx
        .navigate(&canon("https://site.test/public"))
        .await
        .unwrap();
    assert_eq!(rig.ctx.handle().current_url(), "https://site.test/public");
    assert!(rig.ctx.drain_blocked_navigations().is_empty());

    let mut open = unguarded();
    open.navigate(&canon(PRIVATE)).await.unwrap();
    assert_eq!(open.handle().current_url(), PRIVATE);
    assert!(open.handle().refused_navigations().is_empty());
}

#[tokio::test]
async fn a_navigate_action_is_refused_like_navigate() {
    let mut rig = guarded();
    home(&mut rig).await;
    let err = rig
        .ctx
        .perform(BrowserAction::Navigate {
            url: Url::parse(PRIVATE).unwrap(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::RobotsBlocked { .. }), "{err:?}");
    assert_eq!(rig.ctx.handle().current_url(), HOME);
    assert_eq!(rig.ctx.handle().navigations(), vec![HOME.to_owned()]);
}

#[tokio::test]
async fn a_clicked_link_to_a_disallowed_page_is_refused_in_the_browser() {
    let mut rig = guarded();
    let page = home(&mut rig).await;
    let handle = rig.ctx.handle();
    rig.ctx.drain_traffic();

    // the click itself is performed; the page's own navigation is what the browser refuses
    rig.ctx
        .perform(click(locator(&page, "lnk-private")))
        .await
        .unwrap();
    assert_eq!(handle.current_url(), HOME, "the document stayed where it was");
    assert_eq!(handle.navigations(), vec![HOME.to_owned()]);
    let refused = rig.ctx.drain_blocked_navigations();
    assert_eq!(refused.len(), 1);
    assert_eq!(
        (refused[0].url.as_str(), refused[0].reason),
        (PRIVATE, "robots_disallow")
    );
    assert!(rig.ctx.drain_blocked_navigations().is_empty(), "drained once");
    assert!(
        rig.ctx
            .drain_traffic()
            .iter()
            .all(|t| !t.url.contains("/private/")),
        "nothing was requested from the refused URL"
    );
    // the guard was asked before the action ran
    assert!(rig.guard.urls().contains(&PRIVATE.to_owned()));

    // an allowed link still navigates
    let page = rig.ctx.observe(ObservationSpec::default()).await.unwrap();
    rig.ctx
        .perform(click(locator(&page, "lnk-public")))
        .await
        .unwrap();
    assert_eq!(handle.current_url(), "https://site.test/public");
    assert!(rig.ctx.drain_blocked_navigations().is_empty());
}

#[tokio::test]
async fn a_popup_to_a_disallowed_page_is_never_opened() {
    let mut rig = guarded();
    let page = home(&mut rig).await;
    let handle = rig.ctx.handle();

    rig.ctx
        .perform(click(locator(&page, "btn-popup-private")))
        .await
        .unwrap();
    assert_eq!(handle.tab_ids().len(), 1, "no tab for a refused popup");
    let refused = rig.ctx.drain_blocked_navigations();
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].url, PRIVATE);

    rig.ctx
        .perform(click(locator(&page, "btn-popup-public")))
        .await
        .unwrap();
    assert_eq!(handle.tab_ids().len(), 2, "an allowed popup opens");
    assert!(rig.ctx.drain_blocked_navigations().is_empty());
}

#[tokio::test]
async fn subresources_and_page_internal_changes_never_ask_the_guard() {
    let mut rig = guarded();
    let page = home(&mut rig).await;
    // the page's XHR targets a path the guard would refuse as a document: it is reported, not judged
    let xhr = rig.ctx.drain_xhr();
    assert_eq!(xhr.len(), 1);
    assert!(xhr[0].url.contains("/private/api"), "{xhr:?}");
    rig.ctx.perform(click(locator(&page, "btn-menu"))).await.unwrap();
    assert_eq!(
        rig.guard.urls(),
        vec![HOME.to_owned()],
        "only the document was judged"
    );
    assert!(rig.ctx.drain_blocked_navigations().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_guard_that_never_answers_refuses_instead_of_hanging() {
    let mut config = ContextConfig::new(SessionId::new());
    config.navigation_guard = Some(Arc::new(SilentGuard));
    let mut ctx = enforcing().new_fake_context(config);
    let err = ctx.navigate(&canon(HOME)).await.unwrap_err();
    match err {
        BrowserError::RobotsBlocked { reason, .. } => assert_eq!(reason, "robots_unavailable"),
        other => panic!("expected RobotsBlocked, got {other:?}"),
    }
    assert!(ctx.handle().navigations().is_empty());
}

#[tokio::test]
async fn a_backend_that_does_not_honour_the_guard_navigates_unchecked() {
    // the default of `FakeBackend`: scripted sites on made-up hosts have no robots.txt to read
    let backend = FakeBackend::new(site());
    assert!(!backend.honours_navigation_guard());
    assert!(enforcing().honours_navigation_guard());
    let mut config = ContextConfig::new(SessionId::new());
    config.navigation_guard = Some(Arc::new(PrivateGuard::default()));
    let mut ctx = backend.new_fake_context(config);
    ctx.navigate(&canon(PRIVATE)).await.unwrap();
    assert_eq!(ctx.handle().current_url(), PRIVATE);
    assert!(ctx.handle().refused_navigations().is_empty());
}
