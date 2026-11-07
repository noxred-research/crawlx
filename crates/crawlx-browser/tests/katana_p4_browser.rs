//! Browser-plane behaviours against a local Chromium (skipped without one; set
//! `CRAWLX_CHROMIUM_PATH`): consent-banner blocking, lazy-content scroll, CSS candidate
//! filtering, XHR/fetch collation and the page-stable window.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod katana_p4_support;

use crawlx_browser::consent;
use crawlx_core::browser::BrowserContext;
use crawlx_core::dom_ops::{CssFilter, LazyScrollSpec};
use crawlx_core::observation::{AxNode, ObservationBundle, ObservationSpec, QuiescencePolicy};
use crawlx_core::page_op::PageOp;
use katana_p4_support::{canonical, context_config, launch, serve};
use std::collections::BTreeMap;

fn html(body: &str) -> (&'static str, String) {
    (
        "text/html; charset=utf-8",
        format!("<!doctype html><html><head><title>t</title></head><body>{body}</body></html>"),
    )
}

fn js(body: &str) -> (&'static str, String) {
    ("application/javascript", body.to_owned())
}

fn node<'a>(bundle: &'a ObservationBundle, role: &str, name: &str) -> &'a AxNode {
    bundle
        .ax
        .nodes
        .iter()
        .find(|n| n.role == role && n.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no {role} named {name:?}"))
}

fn link_names(bundle: &ObservationBundle) -> Vec<String> {
    bundle
        .ax
        .nodes
        .iter()
        .filter(|n| n.role == "link")
        .filter_map(|n| n.name.clone())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consent_banner_requests_never_reach_the_network_when_blocked() {
    let page = html(
        r#"<h1>App</h1>
<script src="http://consent.cookiebot.com/banner.js"></script>
<script src="http://cdn.cookielaw.org/scripttemplates/otSDK.js"></script>
<script src="http://app.test/app.js"></script>"#,
    );
    let banner = js("var d=document.createElement('div');d.id='cmp-banner';document.body.appendChild(d);");
    let routes = BTreeMap::from([
        ("app.test/".to_owned(), page),
        (
            "app.test/app.js".to_owned(),
            js("var d=document.createElement('div');d.id='app-ok';document.body.appendChild(d);"),
        ),
        ("consent.cookiebot.com/banner.js".to_owned(), banner.clone()),
        ("cdn.cookielaw.org/scripttemplates/otSDK.js".to_owned(), banner),
    ]);
    let server = serve(routes, true).await;
    let Some(backend) = launch(Some(server.port), |_| {}).await else {
        return;
    };

    // blocked: the flag's list is applied through `PageOp::BlockUrls` before the navigation
    let mut blocked = backend.new_cdp_context(context_config()).await.unwrap();
    blocked
        .page_op(PageOp::BlockUrls(consent::patterns().to_vec()))
        .await
        .unwrap();
    blocked.navigate(&canonical("http://app.test/")).await.unwrap();
    blocked.settle(QuiescencePolicy::default()).await.unwrap();
    assert_eq!(
        blocked
            .evaluate_isolated("!!document.getElementById('app-ok')")
            .await
            .unwrap(),
        true,
        "the application's own script still runs"
    );
    assert_eq!(
        blocked
            .evaluate_isolated("!!document.getElementById('cmp-banner')")
            .await
            .unwrap(),
        false,
        "the banner script never ran"
    );
    assert_eq!(
        server.hits.count("consent.cookiebot.com"),
        0,
        "{:?}",
        server.hits.all()
    );
    assert_eq!(
        server.hits.count("cdn.cookielaw.org"),
        0,
        "{:?}",
        server.hits.all()
    );
    assert_eq!(server.hits.count("app.test/app.js"), 1);

    // not blocked: the same page reaches both consent hosts and renders the banner
    let mut open = backend.new_cdp_context(context_config()).await.unwrap();
    open.navigate(&canonical("http://app.test/")).await.unwrap();
    open.settle(QuiescencePolicy::default()).await.unwrap();
    assert_eq!(
        open.evaluate_isolated("!!document.getElementById('cmp-banner')")
            .await
            .unwrap(),
        true
    );
    assert_eq!(
        server.hits.count("consent.cookiebot.com"),
        1,
        "{:?}",
        server.hits.all()
    );
    assert_eq!(
        server.hits.count("cdn.cookielaw.org"),
        1,
        "{:?}",
        server.hits.all()
    );
    backend.close().await.unwrap();
}

const FEED: &str = r#"<div style="height:2500px">feed</div>
<div id="more"></div><div id="sentinel" style="height:10px"></div>
<script>
let batches = 0;
const more = document.getElementById('more');
new IntersectionObserver((entries) => {
  if (!entries.some((e) => e.isIntersecting) || batches >= 3) return;
  batches++;
  for (let i = 1; i <= 2; i++) {
    const n = (batches - 1) * 2 + i;
    const a = document.createElement('a');
    a.href = '/item/' + n; a.textContent = 'item ' + n;
    a.style.display = 'block'; a.style.height = '400px';
    more.appendChild(a);
  }
}).observe(document.getElementById('sentinel'));
</script>"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lazy_scroll_reveals_links_that_exist_only_after_scrolling() {
    let server = serve(BTreeMap::from([("127.0.0.1/feed".to_owned(), html(FEED))]), false).await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let url = canonical(&format!("http://127.0.0.1:{}/feed", server.port));
    let mut ctx = backend.new_cdp_context(context_config()).await.unwrap();

    // 0 steps: nothing is scrolled, the sentinel is never reached
    ctx.navigate(&url).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let none = ctx.lazy_scroll(LazyScrollSpec::steps(0)).await.unwrap();
    assert_eq!((none.steps, none.reached_bottom), (0, false));
    assert!(link_names(&ctx.observe(ObservationSpec::default()).await.unwrap()).is_empty());

    // one step is not enough to reach a sentinel 2500 px down
    let one = ctx.lazy_scroll(LazyScrollSpec::steps(1)).await.unwrap();
    assert_eq!(one.steps, 1);
    assert!(link_names(&ctx.observe(ObservationSpec::default()).await.unwrap()).is_empty());

    // N steps: every batch appears and the scroll stops by itself once the page stops growing
    ctx.navigate(&url).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let report = ctx.lazy_scroll(LazyScrollSpec::steps(50)).await.unwrap();
    assert!(report.reached_bottom, "{report:?}");
    assert!(
        report.steps >= 3 && report.steps < 50,
        "stopped at the bottom: {report:?}"
    );
    assert!(report.document_height > 2500 + 6 * 400, "{report:?}");
    let after = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(
        link_names(&after),
        ["item 1", "item 2", "item 3", "item 4", "item 5", "item 6"]
    );
    assert_eq!(
        ctx.evaluate_isolated("window.scrollY").await.unwrap(),
        0,
        "the page is back at the top"
    );
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn css_filter_applies_selector_and_exclude_in_the_page() {
    let page = html(
        r#"<button id="a" class="go">Alpha</button>
<div class="promo"><button id="b" class="go">Beta</button></div>
<button id="c">Gamma</button>
<a href="/x" id="d" class="go">Delta</a>"#,
    );
    let server = serve(
        BTreeMap::from([
            ("127.0.0.1/".to_owned(), page.clone()),
            ("127.0.0.1/other".to_owned(), page),
        ]),
        false,
    )
    .await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let mut ctx = backend.new_cdp_context(context_config()).await.unwrap();
    ctx.navigate(&canonical(&format!("http://127.0.0.1:{}/", server.port)))
        .await
        .unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    let targets: Vec<_> = [
        ("button", "Alpha"),
        ("button", "Beta"),
        ("button", "Gamma"),
        ("link", "Delta"),
    ]
    .iter()
    .map(|(role, name)| node(&bundle, role, name).locator.clone())
    .collect();
    let strings = |items: &[&str]| items.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    let run = |include: &[&str], exclude: &[&str]| {
        let filter = CssFilter {
            include: strings(include),
            exclude: strings(exclude),
        };
        (filter, targets.clone())
    };

    let (f, t) = run(&[], &[]);
    assert_eq!(ctx.css_filter(&f, &t).await.unwrap(), [true, true, true, true]);
    let (f, t) = run(&[".go"], &[]);
    assert_eq!(ctx.css_filter(&f, &t).await.unwrap(), [true, true, false, true]);
    let (f, t) = run(&[".go"], &[".promo"]);
    assert_eq!(
        ctx.css_filter(&f, &t).await.unwrap(),
        [true, false, false, true],
        "an excluded container rejects its descendants"
    );
    let (f, t) = run(&[], &[".promo"]);
    assert_eq!(ctx.css_filter(&f, &t).await.unwrap(), [true, false, true, true]);
    let (f, t) = run(&["button", "a.go"], &["#a"]);
    assert_eq!(ctx.css_filter(&f, &t).await.unwrap(), [false, true, true, true]);
    let (f, t) = run(&["[["], &[]);
    assert_eq!(
        ctx.css_filter(&f, &t).await.unwrap(),
        [false, false, false, false],
        "an invalid selector matches nothing instead of failing the call"
    );

    // locators of a replaced document are not admitted
    ctx.navigate(&canonical(&format!("http://127.0.0.1:{}/other", server.port)))
        .await
        .unwrap();
    let (f, t) = run(&[".go"], &[]);
    assert_eq!(
        ctx.css_filter(&f, &t).await.unwrap(),
        [false, false, false, false]
    );
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhr_and_fetch_requests_are_collated_per_page() {
    let page = html(
        r#"<img src="/pixel.gif">
<script>
fetch('/api/list?token=abcdef0123456789abcdef01').catch(() => {});
const x = new XMLHttpRequest();
x.open('POST', '/api/save');
x.setRequestHeader('Content-Type', 'application/json');
x.send('{}');
</script>"#,
    );
    let json = ("application/json", "{}".to_owned());
    let server = serve(
        BTreeMap::from([
            ("127.0.0.1/xhr".to_owned(), page),
            ("127.0.0.1/api/list".to_owned(), json.clone()),
            ("127.0.0.1/api/save".to_owned(), json),
        ]),
        false,
    )
    .await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let page_url = format!("http://127.0.0.1:{}/xhr", server.port);
    let mut ctx = backend.new_cdp_context(context_config()).await.unwrap();
    ctx.navigate(&canonical(&page_url)).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();

    let mut records = ctx.drain_xhr();
    records.sort_by(|a, b| a.url.cmp(&b.url));
    assert_eq!(records.len(), 2, "{records:?} (the image is not an XHR)");
    assert_eq!(records[0].method, "GET");
    assert_eq!(records[0].resource_type, "fetch");
    assert!(
        records[0].url.contains("/api/list?token=[redacted]"),
        "{}",
        records[0].url
    );
    assert_eq!(records[0].status, Some(200));
    assert_eq!(records[0].content_type.as_deref(), Some("application/json"));
    assert_eq!(records[1].method, "POST");
    assert_eq!(records[1].resource_type, "xhr");
    assert!(records[1].url.ends_with("/api/save"), "{}", records[1].url);
    for r in &records {
        assert_eq!(r.page_url, page_url, "each record names the page that issued it");
    }
    assert!(ctx.drain_xhr().is_empty(), "drain takes the records");
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn time_stable_waits_for_a_late_mutation_that_the_default_window_misses() {
    let page = html(
        r#"<script>setTimeout(() => { const p = document.createElement('p'); p.id = 'late'; document.body.appendChild(p); }, 1200);</script>"#,
    );
    let server = serve(BTreeMap::from([("127.0.0.1/late".to_owned(), page)]), false).await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let url = canonical(&format!("http://127.0.0.1:{}/late", server.port));
    let mut ctx = backend.new_cdp_context(context_config()).await.unwrap();

    ctx.navigate(&url).await.unwrap();
    let quick = ctx.settle(QuiescencePolicy::default()).await.unwrap();
    assert!(!quick.settle_timeout, "{quick:?}");
    assert_eq!(
        ctx.evaluate_isolated("!!document.getElementById('late')")
            .await
            .unwrap(),
        false,
        "the default window settles before the late mutation: {quick:?}"
    );

    ctx.navigate(&url).await.unwrap();
    let stable = ctx
        .settle(QuiescencePolicy::default().with_time_stable(2_000))
        .await
        .unwrap();
    assert!(!stable.settle_timeout, "{stable:?}");
    assert!(stable.waited_ms >= 3_000, "{stable:?}");
    assert_eq!(
        ctx.evaluate_isolated("!!document.getElementById('late')")
            .await
            .unwrap(),
        true,
        "the page stayed quiet for 2 s only after the late mutation: {stable:?}"
    );
    backend.close().await.unwrap();
}
