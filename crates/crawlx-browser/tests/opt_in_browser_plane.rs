//! Opt-in browser-plane behaviours against a local Chromium (skipped without one; set
//! `CRAWLX_CHROMIUM_PATH`): katana's timer / form-reset / window-close hooks
//! (`dynamic.pageHookOptions`), the stealth patches (`dynamic.stealthPatches`) and named
//! persistent profiles (`dynamic.browserProfile`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod katana_p4_support;

use crawlx_browser::CdpContext;
use crawlx_core::browser::{BrowserBackend, BrowserContext, ContextConfig, ProfileSpec};
use crawlx_core::config::{LaunchProfile, PageHookOptions};
use crawlx_core::observation::QuiescencePolicy;
use katana_p4_support::{canonical, context_config, launch, serve};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

fn html(body: &str) -> (&'static str, String) {
    (
        "text/html; charset=utf-8",
        format!("<!doctype html><html><head><title>t</title></head><body>{body}</body></html>"),
    )
}

fn hooks(options: PageHookOptions) -> ContextConfig {
    let mut c = context_config();
    c.page_hook_options = options;
    c
}

/// Poll the isolated-world expression `js` until it is `true` or `within` has passed.
async fn becomes_true(ctx: &CdpContext, js: &str, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if ctx.evaluate_isolated(js).await.unwrap() == true {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

const REVEALED: &str = "document.getElementById('late').style.display === 'block'";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn timer_acceleration_shows_a_five_second_reveal_within_a_second() {
    let page = html(
        "<div id=late style=\"display:none\">late</div>\
         <script>setTimeout(function(){document.getElementById('late').style.display='block'},5000)</script>",
    );
    let server = serve(BTreeMap::from([("127.0.0.1/".to_owned(), page)]), false).await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let url = canonical(&format!("http://127.0.0.1:{}/", server.port));

    let mut fast = backend
        .new_cdp_context(hooks(PageHookOptions {
            timer_acceleration: 10,
            ..PageHookOptions::default()
        }))
        .await
        .unwrap();
    fast.navigate(&url).await.unwrap();
    assert!(
        becomes_true(&fast, REVEALED, Duration::from_millis(1000)).await,
        "a 5 s setTimeout must fire within 1 s under acceleration 10"
    );

    // default off: the same page is still hidden after the same wait
    let mut plain = backend.new_cdp_context(context_config()).await.unwrap();
    plain.navigate(&url).await.unwrap();
    assert!(
        !becomes_true(&plain, REVEALED, Duration::from_millis(1000)).await,
        "without the option timers are untouched"
    );
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn form_reset_is_prevented_only_when_asked() {
    let page = html(
        "<form id=f onsubmit=\"event.preventDefault(); this.reset();\">\
         <input id=name><input type=reset id=r></form>",
    );
    let server = serve(BTreeMap::from([("127.0.0.1/".to_owned(), page)]), false).await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let url = canonical(&format!("http://127.0.0.1:{}/", server.port));
    let typed_survives_submit = "(function(){var n=document.getElementById('name');n.value='typed';\
         document.getElementById('f').requestSubmit();return n.value==='typed';})()";
    let typed_survives_reset_button = "(function(){var n=document.getElementById('name');n.value='typed';\
         document.getElementById('r').click();return n.value==='typed';})()";

    let mut on = backend
        .new_cdp_context(hooks(PageHookOptions {
            prevent_form_reset: true,
            ..PageHookOptions::default()
        }))
        .await
        .unwrap();
    on.navigate(&url).await.unwrap();
    on.settle(QuiescencePolicy::default()).await.unwrap();
    assert_eq!(on.evaluate_isolated(typed_survives_submit).await.unwrap(), true);
    assert_eq!(
        on.evaluate_isolated(typed_survives_reset_button).await.unwrap(),
        true
    );

    let mut off = backend.new_cdp_context(context_config()).await.unwrap();
    off.navigate(&url).await.unwrap();
    off.settle(QuiescencePolicy::default()).await.unwrap();
    assert_eq!(
        off.evaluate_isolated(typed_survives_submit).await.unwrap(),
        false,
        "the page's own reset() clears the field when the option is off"
    );
    assert_eq!(
        off.evaluate_isolated(typed_survives_reset_button).await.unwrap(),
        false
    );
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn window_close_is_prevented_only_when_asked() {
    // the opener opens a child that closes itself 300 ms after loading, and reports whether
    // the child is still open 1.5 s after opening it
    let opener = html(
        "<script>window.__child = window.open('/child');\
         setTimeout(function(){document.documentElement.dataset.childClosed = String(window.__child.closed);\
         document.documentElement.dataset.checked = '1'}, 1500)</script>",
    );
    let child = html("<script>setTimeout(function(){window.close()},300)</script>");
    let server = serve(
        BTreeMap::from([
            ("127.0.0.1/".to_owned(), opener),
            ("127.0.0.1/child".to_owned(), child),
        ]),
        false,
    )
    .await;
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let url = canonical(&format!("http://127.0.0.1:{}/", server.port));

    for (options, expect_closed) in [
        (
            PageHookOptions {
                prevent_window_close: true,
                ..PageHookOptions::default()
            },
            false,
        ),
        (PageHookOptions::default(), true),
    ] {
        let mut ctx = backend.new_cdp_context(hooks(options)).await.unwrap();
        ctx.navigate(&url).await.unwrap();
        assert!(
            becomes_true(
                &ctx,
                "document.documentElement.dataset.checked === '1'",
                Duration::from_secs(5)
            )
            .await,
            "the opener reports within 5 s"
        );
        assert_eq!(
            ctx.evaluate_isolated("document.documentElement.dataset.childClosed === 'true'")
                .await
                .unwrap(),
            expect_closed,
            "options {options:?}"
        );
    }
    backend.close().await.unwrap();
}

/// A page that records what a script can observe about the browser into `data-probe`.
fn probe_page() -> (&'static str, String) {
    html(
        r#"<script>
(function () {
  var out = {
    webdriver: navigator.webdriver,
    languages: Array.prototype.slice.call(navigator.languages),
    plugins: navigator.plugins.length,
    chrome: typeof window.chrome,
    notification: Notification.permission,
    queryNative: /\[native code\]/.test(Function.prototype.toString.call(navigator.permissions.query))
  };
  try {
    var gl = document.createElement('canvas').getContext('webgl');
    var ext = gl.getExtension('WEBGL_debug_renderer_info');
    out.vendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
    out.renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
  } catch (e) { out.vendor = 'error:' + e; out.renderer = 'error:' + e; }
  navigator.permissions.query({ name: 'notifications' }).then(function (status) {
    out.queried = status.state;
    document.documentElement.dataset.probe = JSON.stringify(out);
  });
})();
</script>"#,
    )
}

async fn probe(
    backend: &crawlx_browser::ChromiumBackend,
    url: &crawlx_core::url::CanonicalUrl,
    patches: bool,
) -> serde_json::Value {
    let mut cfg = context_config();
    cfg.launch_profile = LaunchProfile::Stealth;
    cfg.console_capture = false;
    cfg.stealth_patches = patches;
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    ctx.navigate(url).await.unwrap();
    assert!(
        becomes_true(
            &ctx,
            "!!document.documentElement.dataset.probe",
            Duration::from_secs(5)
        )
        .await,
        "the probe page reports"
    );
    let raw = ctx
        .evaluate_isolated("document.documentElement.dataset.probe")
        .await
        .unwrap();
    serde_json::from_str(raw.as_str().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealth_patches_change_what_the_page_sees_only_when_enabled() {
    let server = serve(BTreeMap::from([("127.0.0.1/".to_owned(), probe_page())]), false).await;
    let Some(backend) = launch(None, |cfg| cfg.launch_profile = LaunchProfile::Stealth).await else {
        return;
    };
    let url = canonical(&format!("http://127.0.0.1:{}/", server.port));

    let patched = probe(&backend, &url, true).await;
    assert_eq!(patched["webdriver"], serde_json::json!(false), "{patched}");
    assert_eq!(
        patched["languages"],
        serde_json::json!(["en-US", "en"]),
        "{patched}"
    );
    assert!(patched["plugins"].as_u64().unwrap() >= 1, "{patched}");
    assert_eq!(patched["chrome"], "object", "{patched}");
    assert_eq!(patched["queryNative"], true, "{patched}");
    assert_eq!(
        patched["vendor"],
        crawlx_browser::stealth::WEBGL_VENDOR,
        "{patched}"
    );
    assert_eq!(
        patched["renderer"],
        crawlx_browser::stealth::WEBGL_RENDERER,
        "{patched}"
    );
    let notification = patched["notification"].as_str().unwrap();
    let expected_query = if notification == "default" {
        "prompt"
    } else {
        notification
    };
    assert_eq!(patched["queried"], expected_query, "{patched}");

    let plain = probe(&backend, &url, false).await;
    assert_ne!(plain["vendor"], patched["vendor"], "unpatched: {plain}");
    assert_ne!(plain["renderer"], patched["renderer"], "unpatched: {plain}");
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealth_patches_and_page_hook_options_are_refused_where_they_do_not_fit() {
    let Some(backend) = launch(None, |_| {}).await else {
        return;
    };
    let mut cfg = context_config();
    cfg.stealth_patches = true;
    let err = backend.new_cdp_context(cfg).await.err().unwrap();
    assert!(
        err.to_string().contains("stealth launch profile"),
        "patches need the stealth profile: {err}"
    );
    backend.close().await.unwrap();

    let Some(stealth) = launch(None, |cfg| cfg.launch_profile = LaunchProfile::Stealth).await else {
        return;
    };
    let mut cfg = hooks(PageHookOptions {
        prevent_window_close: true,
        ..PageHookOptions::default()
    });
    cfg.launch_profile = LaunchProfile::Stealth;
    cfg.console_capture = false;
    let err = stealth.new_cdp_context(cfg).await.err().unwrap();
    assert!(err.to_string().contains("stealth"), "{err}");
    stealth.close().await.unwrap();
}

/// Run one session in profile `spec`: read `document.cookie` and `localStorage`, then write
/// `write` into both. The browser is shut down gracefully, so the profile is flushed.
async fn session_in_profile(
    profiles: &std::path::Path,
    spec: &ProfileSpec,
    server_port: u16,
    write: Option<&str>,
) -> Option<(String, String)> {
    let backend = launch(None, |cfg| {
        cfg.profiles_dir = Some(profiles.to_path_buf());
        cfg.profile = Some(spec.clone());
    })
    .await?;
    let mut cfg = context_config();
    cfg.incognito = false;
    cfg.browser_profile = Some(spec.clone());
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    ctx.navigate(&canonical(&format!("http://127.0.0.1:{server_port}/")))
        .await
        .unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let cookie = ctx.evaluate_isolated("document.cookie").await.unwrap();
    let storage = ctx
        .evaluate_isolated("localStorage.getItem('profile-key') || ''")
        .await
        .unwrap();
    if let Some(v) = write {
        let js = format!(
            "document.cookie = 'profile-cookie-{v}={v}; max-age=86400; path=/'; \
             localStorage.setItem('profile-key', localStorage.getItem('profile-key') + '{v};'); true"
        );
        ctx.evaluate_isolated(&js).await.unwrap();
    }
    drop(ctx);
    BrowserBackend::shutdown(&backend).await;
    Some((
        cookie.as_str().unwrap().to_owned(),
        storage.as_str().unwrap().to_owned(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_named_profile_keeps_cookies_and_storage_only_with_save_changes() {
    let server = serve(
        BTreeMap::from([(
            "127.0.0.1/".to_owned(),
            html("<script>if (localStorage.getItem('profile-key') === null) localStorage.setItem('profile-key', '')</script>"),
        )]),
        false,
    )
    .await;
    let profiles = tempfile::tempdir().unwrap();
    let spec = |dir: &str, save_changes: bool| ProfileSpec {
        dir: dir.to_owned(),
        save_changes,
    };

    // saveChanges: true: what run 1 wrote is there in run 2
    let kept = spec("tenant/kept", true);
    let Some((cookie, storage)) = session_in_profile(profiles.path(), &kept, server.port, Some("one")).await
    else {
        return;
    };
    assert_eq!(
        (cookie.as_str(), storage.as_str()),
        ("", ""),
        "a new profile starts empty"
    );
    let (cookie, storage) = session_in_profile(profiles.path(), &kept, server.port, None)
        .await
        .unwrap();
    assert!(
        cookie.contains("profile-cookie-one=one"),
        "kept cookie: {cookie:?}"
    );
    assert!(storage.contains("one;"), "kept local storage: {storage:?}");

    // saveChanges: false: run 2 starts empty again because run 1's writes were discarded
    let discarded = spec("tenant/discarded", false);
    session_in_profile(profiles.path(), &discarded, server.port, Some("one"))
        .await
        .unwrap();
    let (cookie, storage) = session_in_profile(profiles.path(), &discarded, server.port, None)
        .await
        .unwrap();
    assert_eq!((cookie.as_str(), storage.as_str()), ("", ""), "nothing was saved");
    assert!(
        !profiles.path().join("tenant/discarded").exists()
            || std::fs::read_dir(profiles.path().join("tenant/discarded"))
                .unwrap()
                .count()
                == 0,
        "the discarded profile never reached the profiles directory"
    );

    // a discarded session starts from the saved profile but cannot change it
    let mixed = spec("tenant/mixed", true);
    session_in_profile(profiles.path(), &mixed, server.port, Some("saved"))
        .await
        .unwrap();
    let readonly = spec("tenant/mixed", false);
    let (cookie, _) = session_in_profile(profiles.path(), &readonly, server.port, Some("scratch"))
        .await
        .unwrap();
    assert!(
        cookie.contains("profile-cookie-saved=saved"),
        "copied cookie: {cookie:?}"
    );
    let (cookie, storage) = session_in_profile(profiles.path(), &mixed, server.port, None)
        .await
        .unwrap();
    assert!(cookie.contains("profile-cookie-saved=saved"), "{cookie:?}");
    assert!(
        !cookie.contains("scratch") && !storage.contains("scratch;"),
        "the discarded run's writes are gone: {cookie:?} {storage:?}"
    );
}
