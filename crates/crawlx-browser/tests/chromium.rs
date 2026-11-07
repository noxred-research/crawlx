//! Integration tests against a local Chromium. Skipped (with a message) when no Chromium
//! executable is found; set `CRAWLX_CHROMIUM_PATH` to point at a specific binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::egress::is_browser_background_host;
use crawlx_browser::launch::find_executable;
use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::action::{BrowserAction, KeyChord, Modifiers, OptionKey, PointerButton, ScrollDelta};
use crawlx_core::browser::{BrowserBackend, BrowserContext, BrowserError, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::ids::{SessionId, TabId};
use crawlx_core::observation::{AxNode, ObservationBundle, ObservationSpec, QuiescencePolicy, Revalidation};
use crawlx_core::secret::SecretOr;
use crawlx_core::traffic::{Fidelity, TrustLane};
use crawlx_core::url::CanonicalUrl;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const HOME: &str = r#"<!doctype html><html><head><title>Crawlx Test</title></head><body>
<h1>Hello</h1>
<button id="b" onclick="setTimeout(function(){document.getElementById('out').textContent='clicked';fetch('/api/ping?token=abcdef0123456789abcdef01').catch(function(){});},50)">Click me</button>
<p id="out">idle</p>
<a href="/two">Go two</a>
<input id="name" aria-label="Your name" type="text">
<label><input id="chk" type="checkbox"> Agree</label>
<select id="sel" aria-label="Color"><option value="r">Red</option><option value="g">Green</option><option value="b">Blue</option></select>
<input id="rng" type="range" min="0" max="10" step="1" value="2" aria-label="Level">
<div style="height:3000px"></div>
</body></html>"#;

const TWO: &str = "<!doctype html><html><head><title>Two</title></head><body><h1>Page two</h1><button>Back</button></body></html>";

const STATES: &str = r#"<!doctype html><html><head><title>States</title>
<style>@keyframes mv{from{left:0}to{left:2000px}} #e{position:absolute;left:0;top:300px;animation:mv 10s linear infinite}</style></head><body>
<button id="a">Alpha</button> <button id="b2">Beta</button> <button id="c">Gamma</button>
<button id="d">Delta</button> <button id="z">Zeta</button> <button id="e">Eps</button>
</body></html>"#;

const WIDGETS: &str = r#"<!doctype html><html><head><title>Widgets</title></head><body>
<p id="o2">none</p>
<button id="k" onclick="document.getElementById('o2').textContent='kbd'">Kbd</button>
<button id="hov" onmouseover="document.getElementById('o2').textContent='hovered'">Hover me</button>
<button id="syn" onclick="document.getElementById('o2').textContent='synthetic ' + event.isTrusted">Syn</button>
<button id="conf" onclick="if (confirm('Really?')) { document.getElementById('o2').textContent='confirmed'; }">Confirm</button>
<input type="file" id="f" aria-label="Upload file" onchange="document.getElementById('o2').textContent='file:' + this.files[0].name">
<button id="drag" draggable="true" ondragstart="event.dataTransfer.setData('text/plain','x')" style="position:absolute;left:20px;top:300px;width:120px;height:40px">Drag me</button>
<div id="drop" role="region" aria-label="Drop zone" ondragover="event.preventDefault()" ondrop="event.preventDefault();document.getElementById('o2').textContent='dropped'" style="position:absolute;left:300px;top:300px;width:200px;height:100px;background:#ddd">Drop here</div>
<div id="cb" role="combobox" tabindex="0" aria-label="Fruit" aria-expanded="false" onclick="document.getElementById('list').hidden=false">Pick a fruit</div>
<ul id="list" role="listbox" hidden style="position:absolute;left:20px;top:420px">
<li role="option" onclick="document.getElementById('o2').textContent='apple';document.getElementById('list').hidden=true">Apple</li>
<li role="option" onclick="document.getElementById('o2').textContent='pear';document.getElementById('list').hidden=true">Pear</li></ul>
</body></html>"#;

const POPUPS: &str = r#"<!doctype html><html><head><title>Popups</title></head><body>
<button id="open" onclick="window.open('/two')">Open</button></body></html>"#;

struct Server {
    port: u16,
}

async fn serve(routes: BTreeMap<&'static str, &'static str>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let routes = routes.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let target = head.split_whitespace().nth(1).unwrap_or("/").to_owned();
                let path = target.split('?').next().unwrap_or("/").to_owned();
                let (status, ctype, body) = match routes.get(path.as_str()) {
                    Some(b) => ("200 OK", "text/html; charset=utf-8", (*b).to_owned()),
                    None if path.starts_with("/api/") => ("200 OK", "application/json", "{}".to_owned()),
                    None => ("404 Not Found", "text/plain", "not found".to_owned()),
                };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Server { port }
}

fn site() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("/", HOME),
        ("/two", TWO),
        ("/states", STATES),
        ("/popups", POPUPS),
        ("/widgets", WIDGETS),
    ])
}

fn canonical(port: u16, path: &str) -> CanonicalUrl {
    let base = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    Canonicalizer::canonicalize(path, &base, &CanonicalizeOptions::default()).unwrap()
}

async fn launch(profile: LaunchProfile, proxy: Option<u16>) -> Option<ChromiumBackend> {
    launch_with(profile, proxy, |_| {}).await
}

async fn launch_with(
    profile: LaunchProfile,
    proxy: Option<u16>,
    tweak: impl Fn(&mut LaunchConfig),
) -> Option<ChromiumBackend> {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.launch_profile = profile;
    cfg.allow_unpinned = true;
    cfg.egress_proxy_port = proxy;
    tweak(&mut cfg);
    match ChromiumBackend::launch(cfg.clone()).await {
        Ok(b) => Some(b),
        Err(first) => {
            eprintln!(
                "warning: launch failed ({first}); retrying once with --no-sandbox (CI containers only)"
            );
            cfg.unsafe_no_sandbox_for_ci = true;
            Some(ChromiumBackend::launch(cfg).await.expect("chromium must launch"))
        }
    }
}

fn config(profile: LaunchProfile) -> ContextConfig {
    let mut c = ContextConfig::new(SessionId::new());
    c.launch_profile = profile;
    c
}

fn find<'a>(b: &'a ObservationBundle, role: &str, name: &str) -> &'a AxNode {
    b.ax.nodes
        .iter()
        .find(|n| n.role == role && n.name.as_deref() == Some(name))
        .unwrap_or_else(|| {
            let seen: Vec<_> =
                b.ax.nodes
                    .iter()
                    .map(|n| (n.role.clone(), n.name.clone()))
                    .collect();
            panic!("no {role} named {name:?}; saw {seen:?}")
        })
}

async fn out_text(ctx: &CdpContext) -> serde_json::Value {
    eval(ctx, "document.getElementById('o2').textContent").await
}

async fn eval(ctx: &CdpContext, expr: &str) -> serde_json::Value {
    ctx.evaluate_isolated(expr).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standard_profile_end_to_end() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let info = backend.build_info().clone();
    assert_eq!(info.launch_profile, LaunchProfile::Standard);
    assert!(info.chromium_version.split('.').count() == 4, "{info:?}");
    assert!(backend.launch_flags().iter().any(|f| f == "--enable-automation"));
    assert!(backend.launch_flags().iter().all(|f| f != "--no-sandbox") || !backend.is_sandboxed());

    let server = serve(site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();

    let nav = ctx.navigate(&canonical(server.port, "/")).await.unwrap();
    assert_eq!(nav.status, Some(200));
    assert!(nav.final_url.ends_with('/'));
    assert_eq!(nav.epoch.navigation_seq, 1);
    assert!(nav.blocked_by_egress.is_empty());

    let spec = ObservationSpec {
        ax: true,
        dom_supplement: true,
        dom_snapshot: true,
        screenshot: true,
        revalidation_only: false,
    };
    let before = ctx.observe(spec).await.unwrap();
    let button = find(&before, "button", "Click me").clone();
    assert!(before.html.as_deref().unwrap().contains("Click me"));
    assert_eq!(before.title.as_deref(), Some("Crawlx Test"));
    assert!(button.bbox.is_some_and(|b| b.width > 0.0 && b.height > 0.0));
    assert!(before
        .dom_supplement
        .nodes
        .contains_key(&button.locator.backend_node_id.0));
    let sup = &before.dom_supplement.nodes[&button.locator.backend_node_id.0];
    assert_eq!(sup.tag, "button");
    assert_eq!(sup.attributes.get("id").map(String::as_str), Some("b"));
    assert!(before.raw_artifact("screenshot").unwrap().starts_with(b"\x89PNG"));
    assert!(before.raw_artifact("dom_snapshot").is_some_and(|b| !b.is_empty()));
    assert!(find(&before, "link", "Go two").locator.backend_node_id.0 > 0);
    assert_eq!(before.tabs.len(), 1);
    assert_eq!(before.frames.len(), 1);
    assert_eq!(before.epoch, ctx.current_epoch());
    let mutation_before = before.epoch.mutation_seq;

    // revalidate: actionable with live facts and hit points
    let rv = ctx.revalidate(&button.locator, before.epoch).await.unwrap();
    let Revalidation::Actionable { live } = rv else {
        panic!("expected Actionable, got {rv:?}");
    };
    assert_eq!(live.name.as_deref(), Some("Click me"));
    assert_eq!(live.role.as_deref(), Some("button"));
    assert_eq!(live.tag.as_deref(), Some("button"));
    assert!(!live.hit_points.is_empty() && live.hit_points.len() <= 5);
    assert_eq!(live.attributes.get("type").map(String::as_str), Some("submit"));

    // click -> page JS changes text and fires a fetch
    let receipt = ctx
        .perform(BrowserAction::Click {
            target: button.locator.clone(),
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        })
        .await
        .unwrap();
    assert_eq!(receipt.fidelity, Fidelity::NativePointer);
    assert_eq!(receipt.lane, TrustLane::TrustedUi);
    let report = ctx.settle(QuiescencePolicy::default()).await.unwrap();
    assert!(!report.settle_timeout, "{report:?}");
    assert!(report.network_idle && report.mutation_idle && report.navigation_settled);

    let after = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert!(
        after.epoch.mutation_seq > mutation_before,
        "mutation_seq {} should exceed {mutation_before}",
        after.epoch.mutation_seq
    );
    assert!(after.mutation.records >= 1 && after.mutation.text_changes + after.mutation.added_nodes >= 1);
    assert!(after.html.as_deref().unwrap().contains("clicked"));
    assert!(after
        .ax
        .nodes
        .iter()
        .any(|n| n.name.as_deref() == Some("clicked")));
    assert_eq!(after.epoch.navigation_seq, before.epoch.navigation_seq);
    assert!(after.settle.is_some());
    assert!(after
        .network
        .operations
        .iter()
        .any(|operation| operation == "GET /api/ping"));

    // redacted traffic: the page document and the token-bearing fetch
    let traffic = ctx.drain_traffic();
    let ping = traffic
        .iter()
        .find(|t| t.url.contains("/api/ping"))
        .expect("ping captured");
    assert!(ping.url.contains("token=[redacted]"), "{}", ping.url);
    assert!(!ping.third_party);
    assert_eq!(ping.status, Some(200));
    let doc = traffic
        .iter()
        .find(|t| t.url.ends_with('/'))
        .expect("document captured");
    assert_eq!(doc.status, Some(200));
    assert!(ctx.drain_traffic().is_empty());

    // typing (secret value), checkbox, select, range, keys, scroll
    let name = find(&after, "textbox", "Your name").clone();
    let r = ctx
        .perform(BrowserAction::Type {
            target: name.locator.clone(),
            value: SecretOr::secret("Ada".to_owned()),
            clear_first: true,
        })
        .await
        .unwrap();
    assert_eq!(r.fidelity, Fidelity::NativeTextInput);
    assert_eq!(eval(&ctx, "document.getElementById('name').value").await, "Ada");
    ctx.perform(BrowserAction::Type {
        target: name.locator.clone(),
        value: SecretOr::Plain("Grace".to_owned()),
        clear_first: true,
    })
    .await
    .unwrap();
    assert_eq!(eval(&ctx, "document.getElementById('name').value").await, "Grace");

    let after = ctx.observe(ObservationSpec::default()).await.unwrap();
    let chk = after
        .ax
        .nodes
        .iter()
        .find(|n| n.role == "checkbox")
        .expect("checkbox")
        .clone();
    ctx.perform(BrowserAction::SetChecked {
        target: chk.locator.clone(),
        checked: true,
    })
    .await
    .unwrap();
    assert_eq!(eval(&ctx, "document.getElementById('chk').checked").await, true);

    let sel = after
        .ax
        .nodes
        .iter()
        .find(|n| n.name.as_deref() == Some("Color"))
        .expect("select")
        .clone();
    let r = ctx
        .perform(BrowserAction::Select {
            target: sel.locator.clone(),
            options: vec![OptionKey::Label("Blue".to_owned())],
        })
        .await
        .unwrap();
    assert_eq!(r.fidelity, Fidelity::NativeKeyboard);
    assert_eq!(eval(&ctx, "document.getElementById('sel').value").await, "b");

    let rng = after
        .ax
        .nodes
        .iter()
        .find(|n| n.role == "slider")
        .expect("slider")
        .clone();
    ctx.perform(BrowserAction::SetRange {
        target: rng.locator.clone(),
        value: 7.0,
    })
    .await
    .unwrap();
    assert_eq!(eval(&ctx, "document.getElementById('rng').value").await, "7");

    ctx.perform(BrowserAction::Scroll {
        container: None,
        delta: ScrollDelta { dx: 0.0, dy: 400.0 },
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let scrolled = eval(&ctx, "window.scrollY").await.as_f64().unwrap();
    assert!(scrolled > 0.0, "scrollY {scrolled}");

    ctx.perform(BrowserAction::Keys {
        sequence: vec![KeyChord {
            key: "Tab".to_owned(),
            modifiers: Modifiers::default(),
        }],
    })
    .await
    .unwrap();

    // synthetic click is refused unless allowed
    let err = ctx
        .perform(BrowserAction::SyntheticClick {
            target: button.locator.clone(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::Unsupported(_)), "{err:?}");

    // standard profile enables Runtime for console capture
    assert!(backend.cdp_transcript().iter().any(|m| m == "Runtime.enable"));

    // navigation bumps navigation_seq and document_seq; the old locator is stale
    let nav2 = ctx.navigate(&canonical(server.port, "/two")).await.unwrap();
    assert_eq!(nav2.epoch.navigation_seq, 2);
    assert_eq!(nav2.epoch.document_seq, 2);
    let stale = ctx.revalidate(&button.locator, before.epoch).await.unwrap();
    assert!(
        matches!(stale, Revalidation::StaleEpoch { current } if current.navigation_seq == 2),
        "{stale:?}"
    );
    let err = ctx
        .perform(BrowserAction::Click {
            target: button.locator.clone(),
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::StaleLocator(_)), "{err:?}");

    // same-document navigation: document_seq only
    let hash = ctx
        .perform(BrowserAction::Navigate {
            url: url::Url::parse(&format!("http://127.0.0.1:{}/two#frag", server.port)).unwrap(),
        })
        .await
        .unwrap();
    assert_eq!(hash.lane, TrustLane::Diagnostic);
    let e = ctx.current_epoch();
    assert_eq!((e.navigation_seq, e.document_seq), (2, 3));

    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealth_profile_never_enables_runtime_and_hides_webdriver() {
    let Some(backend) = launch(LaunchProfile::Stealth, None).await else {
        return;
    };
    let flags = backend.launch_flags().to_vec();
    assert!(flags.contains(&"--disable-blink-features=AutomationControlled".to_owned()));
    for banned in [
        "--enable-automation",
        "--disable-popup-blocking",
        "--disable-component-update",
        "--disable-default-apps",
    ] {
        assert!(!flags.iter().any(|f| f == banned), "{banned}");
    }
    assert!(!backend.build_info().console_capture);

    // a context with the other profile is refused: flags are process-wide
    let err = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .err()
        .expect("must refuse");
    assert!(matches!(err, BrowserError::Unsupported(_)));

    let server = serve(site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Stealth))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/")).await.unwrap();
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    let button = find(&bundle, "button", "Click me").clone();
    let rv = ctx.revalidate(&button.locator, bundle.epoch).await.unwrap();
    assert!(matches!(rv, Revalidation::Actionable { .. }), "{rv:?}");
    ctx.perform(BrowserAction::Click {
        target: button.locator,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    })
    .await
    .unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    assert!(eval(&ctx, "document.getElementById('out').textContent").await == "clicked");

    let webdriver = eval(&ctx, "navigator.webdriver").await;
    assert_ne!(
        webdriver,
        serde_json::Value::Bool(true),
        "navigator.webdriver leaked"
    );

    let transcript = backend.cdp_transcript();
    assert!(!transcript.is_empty());
    assert!(
        !transcript
            .iter()
            .any(|m| m == "Runtime.enable" || m == "Console.enable" || m == "Log.enable"),
        "stealth transcript contains an enabling call: {transcript:?}"
    );
    assert!(transcript.iter().any(|m| m == "Runtime.evaluate"));
    assert!(transcript.iter().any(|m| m == "Page.createIsolatedWorld"));
    assert!(ctx.console_messages().is_empty());
    Box::new(ctx).close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revalidation_reports_each_failure_mode() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/states")).await.unwrap();
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    let get = |name: &str| find(&b, "button", name).locator.clone();
    let (alpha, beta, gamma, delta, zeta, eps) = (
        get("Alpha"),
        get("Beta"),
        get("Gamma"),
        get("Delta"),
        get("Zeta"),
        get("Eps"),
    );

    // untouched controls are actionable
    for l in [&alpha, &beta, &gamma] {
        let rv = ctx.revalidate(l, b.epoch).await.unwrap();
        assert!(matches!(rv, Revalidation::Actionable { .. }), "{rv:?}");
    }
    eval(&ctx, "document.getElementById('a').remove()").await;
    assert_eq!(
        ctx.revalidate(&alpha, b.epoch).await.unwrap(),
        Revalidation::Detached
    );
    eval(&ctx, "document.getElementById('b2').disabled = true").await;
    assert_eq!(
        ctx.revalidate(&beta, b.epoch).await.unwrap(),
        Revalidation::Disabled
    );
    eval(&ctx, "document.getElementById('d').textContent = 'Changed'").await;
    assert_eq!(
        ctx.revalidate(&delta, b.epoch).await.unwrap(),
        Revalidation::IdentityChanged
    );
    eval(&ctx, "document.getElementById('z').style.visibility = 'hidden'").await;
    assert_eq!(
        ctx.revalidate(&zeta, b.epoch).await.unwrap(),
        Revalidation::NotVisible
    );
    assert_eq!(
        ctx.revalidate(&eps, b.epoch).await.unwrap(),
        Revalidation::Unstable
    );

    // mutation drift is visible through current_epoch after revalidate
    assert!(ctx.current_epoch().mutation_seq >= 4);

    eval(
        &ctx,
        "(() => { const o = document.createElement('div'); o.id = 'overlay'; \
         o.style.cssText = 'position:fixed;left:0;top:0;width:100vw;height:100vh;background:#fff;z-index:99'; \
         document.body.appendChild(o); })()",
    )
    .await;
    let rv = ctx.revalidate(&gamma, b.epoch).await.unwrap();
    assert!(
        matches!(
            rv,
            Revalidation::Obscured {
                by_backend_node_id: Some(_)
            }
        ),
        "{rv:?}"
    );
    let err = ctx
        .perform(BrowserAction::Click {
            target: gamma,
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::Script(m) if m.contains("obscured")));

    // a mismatching expected epoch is stale without touching the page
    let mut wrong = b.epoch;
    wrong.navigation_seq += 5;
    let rv = ctx.revalidate(&delta, wrong).await.unwrap();
    assert!(matches!(rv, Revalidation::StaleEpoch { .. }));
    Box::new(ctx).close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn popups_are_bounded_and_tabs_switch() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(site()).await;
    let mut cfg = config(LaunchProfile::Standard);
    cfg.max_tabs = 2;
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    ctx.navigate(&canonical(server.port, "/popups")).await.unwrap();
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    let open = find(&b, "button", "Open").locator.clone();
    let click = |l: crawlx_core::observation::RuntimeLocator| BrowserAction::Click {
        target: l,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    };
    ctx.perform(click(open.clone())).await.unwrap();
    for _ in 0..60 {
        if ctx.tab_ids().len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(ctx.tab_ids().len(), 2);
    ctx.perform(click(open)).await.unwrap(); // excess target waits for a journaled policy decision
    for _ in 0..60 {
        if ctx
            .observe(ObservationSpec::default())
            .await
            .unwrap()
            .tabs
            .iter()
            .any(|t| t.pending)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(ctx.rejected_popups(), 0);
    assert_eq!(ctx.tab_ids().len(), 3);

    let waiting = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(waiting.tabs.len(), 3);
    let pending = waiting.tabs.iter().find(|t| t.pending).unwrap();
    let close = ctx
        .perform(BrowserAction::CloseTab {
            tab: pending.id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(close.lane, TrustLane::Diagnostic);
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(b.tabs.len(), 2);
    let popup = b.tabs.iter().find(|t| !t.active).expect("popup tab").clone();
    assert!(popup.opener.is_some());
    ctx.perform(BrowserAction::SwitchTab {
        tab: popup.id.clone(),
    })
    .await
    .unwrap();
    // wait for the popup document, then observe it
    for _ in 0..60 {
        if ctx
            .observe(ObservationSpec::default())
            .await
            .is_ok_and(|b| b.url.url.path() == "/two")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pb = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(pb.url.url.path(), "/two");
    assert_eq!(pb.tab, popup.id);
    find(&pb, "button", "Back");
    ctx.perform(BrowserAction::CloseTab {
        tab: popup.id.clone(),
    })
    .await
    .unwrap();
    assert_eq!(ctx.tab_ids().len(), 1);
    let home = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(home.url.url.path(), "/popups");
    let err = ctx
        .perform(BrowserAction::SwitchTab {
            tab: TabId("does-not-exist".to_owned()),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::TargetClosed));
    Box::new(ctx).close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn storage_round_trips_between_contexts() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(site()).await;
    let mut a = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    a.navigate(&canonical(server.port, "/two")).await.unwrap();
    eval(
        &a,
        "document.cookie = 'sid=abc123; path=/'; localStorage.setItem('k', 'v'); 1",
    )
    .await;
    let blob = a.export_storage().await.unwrap();
    let text = String::from_utf8(blob.clone()).unwrap();
    assert!(text.contains("sid") && text.contains("abc123"), "{text}");
    assert!(text.contains("\"local\":[[\"k\",\"v\"]]"), "{text}");

    // a second incognito context starts empty, then restores the checkpoint
    let mut b = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    b.navigate(&canonical(server.port, "/two")).await.unwrap();
    assert_eq!(eval(&b, "document.cookie").await, "");
    assert_eq!(
        eval(&b, "localStorage.getItem('k')").await,
        serde_json::Value::Null
    );
    b.import_storage(&blob).await.unwrap();
    b.navigate(&canonical(server.port, "/")).await.unwrap();
    assert!(eval(&b, "document.cookie")
        .await
        .as_str()
        .unwrap()
        .contains("sid=abc123"));
    assert_eq!(eval(&b, "localStorage.getItem('k')").await, "v");
    assert!(b.import_storage(b"not json").await.is_err());
    Box::new(a).close().await.unwrap();
    Box::new(b).close().await.unwrap();
}

// A real loopback HTTP proxy/request trap, not a command-line snapshot. It never forwards
// a request, and records each attempt with the status it answered before replying.
// Using its own address as the fixture also detects Chromium's implicit loopback bypass:
// only proxy-form (absolute or CONNECT) request targets can reach the fixture routes.
//
// The stock pinned Chromium makes unsolicited Google-service requests (see
// `docs/design/data-and-secrets.md`). They are accepted as *denied containment* only: each must arrive in proxy
// form at a host in `BROWSER_BACKGROUND_HOST_SUFFIXES` and be answered 403. Anything else
// that is not a fixture GET fails the test.

/// Host of a proxy-form request line (`CONNECT host:port` or `METHOD http://host[:port]/...`);
/// `None` for an origin-form request, which would mean Chromium bypassed the proxy.
fn proxy_form_host(request: &str) -> Option<&str> {
    let mut parts = request.split_whitespace();
    let (method, target) = (parts.next()?, parts.next()?);
    let authority = if method == "CONNECT" {
        target
    } else {
        let rest = target.strip_prefix("http://")?;
        rest.split('/').next()?
    };
    Some(authority.rsplit_once(':').map_or(authority, |(host, _)| host))
}

async fn startup_background_traffic_is_proxy_denied(profile: LaunchProfile) {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let origin = format!("http://127.0.0.1:{port}");
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, u16)>::new()));
    let seen = std::sync::Arc::clone(&requests);
    let fixture = origin.clone();
    let trap = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = proxy.accept() => {
                    let (socket, _) = accepted.unwrap();
                    let seen = std::sync::Arc::clone(&seen);
                    let fixture = fixture.clone();
                    connections.spawn(async move {
                        let mut socket = tokio::io::BufReader::new(socket);
                        let mut line = String::new();
                        if socket.read_line(&mut line).await.unwrap() == 0 {
                            return; // abandoned TCP preconnect, not an HTTP request
                        }
                        let request = line.trim_end().to_owned();
                        let target = request.split_whitespace().nth(1).unwrap().to_owned();
                        let path = target.strip_prefix(&fixture);
                        let (status, content_type, body) = match path {
                            Some("/") => (
                                200,
                                "text/html",
                                "<!doctype html><h1>loading</h1><script>\
                                 fetch('/api/ping').then(r=>r.text()).then(t=>\
                                 document.querySelector('h1').textContent=t)</script>",
                            ),
                            Some("/api/ping") => (200, "text/plain", "fixture ready"),
                            Some("/favicon.ico") => (204, "image/x-icon", ""),
                            _ => (403, "text/plain", "denied"),
                        };
                        seen.lock().unwrap().push((request, status));
                        let reason = match status {
                            200 => "OK",
                            204 => "No Content",
                            _ => "Forbidden",
                        };
                        loop {
                            line.clear();
                            if socket.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" {
                                break;
                            }
                        }
                        let response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = socket.get_mut().write_all(response.as_bytes()).await;
                    });
                }
                completed = connections.join_next(), if !connections.is_empty() => {
                    completed.unwrap().unwrap();
                }
            }
        }
    });
    let Some(backend) = launch_with(profile, Some(port), |cfg| {
        // The owned parameter must coexist with operator feature configuration.
        cfg.extra_args.push("--enable-features=Http2".to_owned());
    })
    .await
    else {
        trap.abort();
        return;
    };
    // Keep the trap open through asynchronous startup work, before any managed page.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let startup = requests.lock().unwrap().clone();

    let mut cfg = config(profile);
    cfg.egress_proxy_port = Some(port);
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    ctx.navigate(&canonical(port, "/")).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if eval(&ctx, "document.querySelector('h1').textContent").await == "fixture ready" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fixture document and fetch must work through the proxy");
    let traffic = ctx.drain_traffic();
    for path in ["/", "/api/ping"] {
        assert!(
            traffic
                .iter()
                .any(|event| { event.url == format!("{origin}{path}") && event.status == Some(200) }),
            "{profile:?} must capture real {path} traffic: {traffic:?}"
        );
    }
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
    let attempted = requests.lock().unwrap().clone();
    trap.abort();
    assert!(
        attempted
            .iter()
            .any(|(request, status)| *status == 200 && request.starts_with(&format!("GET {origin}/"))),
        "the proxy must observe fixture traffic: {attempted:?}"
    );
    // (a) nothing bypassed the proxy: every request reached the trap in proxy form
    // (b) each browser-owned background request targets a known service host and was denied
    // (c) everything else is a fixture GET the trap served
    let is_fixture = |request: &str| request.starts_with(&format!("GET {origin}/"));
    for (request, status) in &attempted {
        let host = proxy_form_host(request)
            .unwrap_or_else(|| panic!("{profile:?} bypassed the proxy with {request:?}: {attempted:?}"));
        if is_fixture(request) {
            assert!(
                matches!(status, 200 | 204),
                "{profile:?} fixture request refused: {request:?} {status}"
            );
        } else {
            assert!(
                is_browser_background_host(host),
                "{profile:?} attempted an unknown host {host:?}: {attempted:?}"
            );
            assert_eq!(
                *status, 403,
                "{profile:?} background request not denied: {request:?}"
            );
        }
    }
    // startup traffic (before any managed page) is background traffic only, never the fixture
    assert!(
        startup
            .iter()
            .all(|(request, status)| !is_fixture(request) && *status == 403),
        "{profile:?} startup reached something other than denied background hosts: {startup:?}"
    );
    eprintln!(
        "{profile:?} startup denied: {:?}; all denied: {:?}",
        startup.iter().map(|(r, _)| r.as_str()).collect::<Vec<_>>(),
        attempted
            .iter()
            .filter(|(request, _)| !is_fixture(request))
            .map(|(r, _)| r.as_str())
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn standard_startup_background_traffic_is_proxy_denied() {
    startup_background_traffic_is_proxy_denied(LaunchProfile::Standard).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stealth_startup_background_traffic_is_proxy_denied() {
    startup_background_traffic_is_proxy_denied(LaunchProfile::Stealth).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn egress_denials_are_reported_through_the_proxy() {
    // a stand-in egress proxy that denies everything the way crawlx-fetch's proxy does
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = proxy.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = proxy.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let mut got = Vec::new();
                while !got.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                let body = "denied";
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nX-Crawlx-Egress-Denied: private-range\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    let Some(backend) = launch(LaunchProfile::Standard, Some(proxy_port)).await else {
        return;
    };
    assert!(backend
        .launch_flags()
        .contains(&format!("--proxy-server=http://127.0.0.1:{proxy_port}")));
    let mut cfg = config(LaunchProfile::Standard);
    cfg.egress_proxy_port = Some(proxy_port);
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    let base = url::Url::parse("http://internal.test/").unwrap();
    let target = Canonicalizer::canonicalize(
        "http://internal.test/admin",
        &base,
        &CanonicalizeOptions::default(),
    )
    .unwrap();
    let nav = ctx.navigate(&target).await.unwrap();
    assert_eq!(nav.status, Some(403));
    // the favicon request is denied as well; the document itself must be reported first
    assert_eq!(
        nav.blocked_by_egress.first().map(String::as_str),
        Some("http://internal.test/admin")
    );
    Box::new(ctx).close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyboard_hover_drag_upload_dialogs_and_custom_listbox() {
    let fixtures = tempfile::tempdir().unwrap();
    std::fs::write(fixtures.path().join("report.txt"), "hello").unwrap();
    let dir = fixtures.path().to_path_buf();
    let Some(backend) = launch_with(LaunchProfile::Standard, None, move |c| {
        c.fixtures_dir = Some(dir.clone())
    })
    .await
    else {
        return;
    };
    let server = serve(site()).await;
    let mut cfg = config(LaunchProfile::Standard);
    cfg.synthetic_click_allowed = true;
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    ctx.navigate(&canonical(server.port, "/widgets")).await.unwrap();
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();

    // keyboard activation
    let kbd = find(&b, "button", "Kbd").locator.clone();
    let r = ctx
        .perform(BrowserAction::KeyboardActivate { target: kbd })
        .await
        .unwrap();
    assert_eq!(r.fidelity, Fidelity::NativeKeyboard);
    assert_eq!(out_text(&ctx).await, "kbd");

    // hover
    let hov = find(&b, "button", "Hover me").locator.clone();
    let r = ctx.perform(BrowserAction::Hover { target: hov }).await.unwrap();
    assert_eq!(
        (r.fidelity, r.lane),
        (Fidelity::NativePointer, TrustLane::TrustedUi)
    );
    assert_eq!(out_text(&ctx).await, "hovered");

    // synthetic click (allowed in this context): untrusted event, diagnostic lane
    let syn = find(&b, "button", "Syn").locator.clone();
    let r = ctx
        .perform(BrowserAction::SyntheticClick { target: syn.clone() })
        .await
        .unwrap();
    assert_eq!(
        (r.fidelity, r.lane),
        (Fidelity::SyntheticDomEvent, TrustLane::Diagnostic)
    );
    assert_eq!(out_text(&ctx).await, "synthetic false");
    // a native click on the same control is trusted
    ctx.perform(BrowserAction::Click {
        target: syn,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    })
    .await
    .unwrap();
    assert_eq!(out_text(&ctx).await, "synthetic true");

    // upload through a fixture
    let file = find(&b, "button", "Upload file").locator.clone();
    let r = ctx
        .perform(BrowserAction::Upload {
            target: file.clone(),
            fixture: crawlx_core::ids::FixtureFileId("report.txt".to_owned()),
        })
        .await
        .unwrap();
    assert_eq!(
        (r.fidelity, r.lane),
        (Fidelity::FileChooser, TrustLane::Diagnostic)
    );
    assert_eq!(out_text(&ctx).await, "file:report.txt");
    let err = ctx
        .perform(BrowserAction::Upload {
            target: file,
            fixture: crawlx_core::ids::FixtureFileId("../etc/passwd".to_owned()),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::Unsupported(_)), "{err:?}");

    // native HTML5 drag and drop
    let drag = find(&b, "button", "Drag me").locator.clone();
    let drop_zone = find(&b, "region", "Drop zone").locator.clone();
    let r = ctx
        .perform(BrowserAction::Drag {
            source: drag,
            destination: drop_zone,
        })
        .await
        .unwrap();
    assert_eq!(r.fidelity, Fidelity::NativePointer);
    assert_eq!(out_text(&ctx).await, "dropped");

    // custom listbox: click to open, then click the option
    let combo = find(&b, "combobox", "Fruit").locator.clone();
    ctx.perform(BrowserAction::Select {
        target: combo,
        options: vec![OptionKey::Label("Pear".to_owned())],
    })
    .await
    .unwrap();
    assert_eq!(out_text(&ctx).await, "pear");

    // confirm dialogs are dismissed, recorded, and remembered for revalidation
    let conf = find(&b, "button", "Confirm").locator.clone();
    ctx.perform(BrowserAction::Click {
        target: conf.clone(),
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    })
    .await
    .unwrap();
    let after = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(after.dialogs.len(), 1);
    assert_eq!(after.dialogs[0].kind, "confirm");
    assert_ne!(out_text(&ctx).await, "confirmed");
    let rv = ctx.revalidate(&conf, after.epoch).await.unwrap();
    let Revalidation::Actionable { live } = rv else {
        panic!("{rv:?}")
    };
    assert_eq!(
        live.attributes.get("confirm-dialog").map(String::as_str),
        Some("true")
    );
    // only http(s) may be loaded
    let err = ctx
        .perform(BrowserAction::Navigate {
            url: url::Url::parse("file:///etc/passwd").unwrap(),
        })
        .await
        .unwrap_err();
    assert!(matches!(err, BrowserError::EgressDenied(_)), "{err:?}");
    Box::new(ctx).close().await.unwrap();
}

const NESTED_SCROLL: &str = r#"<!doctype html><html><head><title>Scroll</title><style>
#outer{width:400px;height:200px;overflow:auto;border:1px solid #000}
#inner{width:300px;height:100px;overflow:auto;border:1px solid #444;margin:10px}
.sp{height:900px}
</style></head><body>
<p id="out">idle</p>
<div id="outer"><div class="sp"></div>
<div id="inner"><div class="sp"></div><button id="deep" onclick="document.getElementById('out').textContent='deep'">Deep</button><div class="sp"></div></div>
<div class="sp"></div></div></body></html>"#;

const FORCED_SCROLL: &str = r#"<!doctype html><html><head><title>Forced</title></head>
<body><p id="out">idle</p>
<button id="far" style="position:absolute;left:20px;top:5000px" onclick="document.getElementById('out').textContent='far'">Far</button>
<div style="height:9000px"></div>
<script>window.addEventListener('wheel', (e) => e.preventDefault(), { passive: false });</script>
</body></html>"#;

const TICKER: &str = r#"<!doctype html><html><head><title>Ticker</title></head><body>
<div id="t">0</div><div id="live" aria-live="polite">a</div><button id="b">B</button>
<script>
let n = 0;
setInterval(() => { n++; document.getElementById('t').textContent = 'tick ' + n; }, 250);
setInterval(() => { document.getElementById('live').textContent = 's' + Math.random(); }, 700);
</script></body></html>"#;

const CHAIN: &str = r#"<!doctype html><html><head><title>Chain</title></head><body>
<div id="c0"></div><div id="c1"></div><div id="c2"></div><div id="c3"></div>
<div id="c4"></div><div id="c5"></div><div id="c6"></div><div id="c7"></div>
<script>
let i = 0;
(function step() {
  if (i < 8) { document.getElementById('c' + i).textContent = 'done'; i++; setTimeout(step, 150); }
})();
</script></body></html>"#;

fn scroll_site() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        ("/nested", NESTED_SCROLL),
        ("/forced", FORCED_SCROLL),
        ("/ticker", TICKER),
        ("/chain", CHAIN),
    ])
}

fn click(target: crawlx_core::observation::RuntimeLocator) -> BrowserAction {
    BrowserAction::Click {
        target,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_control_in_nested_scrollers_is_revealed_by_wheel_events_and_stays_trusted() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(scroll_site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/nested")).await.unwrap();
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    let deep = find(&b, "button", "Deep").locator.clone();
    let rv = ctx.revalidate(&deep, b.epoch).await.unwrap();
    assert!(matches!(rv, Revalidation::Actionable { .. }), "{rv:?}");
    let scrolled = eval(
        &ctx,
        "[document.getElementById('outer').scrollTop, document.getElementById('inner').scrollTop]",
    )
    .await;
    assert!(
        scrolled[0].as_f64().unwrap() > 0.0 && scrolled[1].as_f64().unwrap() > 0.0,
        "both containers scrolled by the wheel: {scrolled}"
    );
    let receipt = ctx.perform(click(deep)).await.unwrap();
    assert_eq!(
        (receipt.fidelity, receipt.lane),
        (Fidelity::NativePointer, TrustLane::TrustedUi)
    );
    assert_eq!(
        eval(&ctx, "document.getElementById('out').textContent").await,
        "deep"
    );
    Box::new(ctx).close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_target_the_wheel_cannot_reach_is_scrolled_by_script_and_demoted_to_the_diagnostic_lane() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(scroll_site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/forced")).await.unwrap();
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    let far = find(&b, "button", "Far").locator.clone();
    let rv = ctx.revalidate(&far, b.epoch).await.unwrap();
    assert!(matches!(rv, Revalidation::Actionable { .. }), "{rv:?}");
    assert!(eval(&ctx, "window.scrollY").await.as_f64().unwrap() > 0.0);
    let receipt = ctx.perform(click(far.clone())).await.unwrap();
    assert_eq!(
        (receipt.fidelity, receipt.lane),
        (Fidelity::ScriptedScroll, TrustLane::Diagnostic)
    );
    assert_eq!(
        eval(&ctx, "document.getElementById('out').textContent").await,
        "far"
    );
    // the mark is consumed by the action it described
    let again = ctx.perform(click(far)).await.unwrap();
    assert_eq!(again.fidelity, Fidelity::NativePointer);
    Box::new(ctx).close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn periodic_and_live_region_mutations_do_not_block_quiescence() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(scroll_site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/ticker")).await.unwrap();
    let policy = QuiescencePolicy {
        hard_timeout_ms: 5_000,
        ..QuiescencePolicy::default()
    };
    let first = ctx.settle(policy).await.unwrap();
    assert!(!first.settle_timeout && first.mutation_idle, "{first:?}");
    assert!(first.excluded_volatile_targets >= 1, "{first:?}");
    assert!(first.waited_ms < 4_000, "{first:?}");
    // the ticker is already known to be volatile: only the idle windows remain
    let second = ctx.settle(policy).await.unwrap();
    assert!(!second.settle_timeout, "{second:?}");
    assert!(second.waited_ms < 1_500, "{second:?}");
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert!(b.mutation.volatile_permille > 0, "{:?}", b.mutation);
    Box::new(ctx).close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chain_of_one_off_mutations_still_holds_the_settle_window_open() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(scroll_site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/chain")).await.unwrap();
    let report = ctx.settle(QuiescencePolicy::default()).await.unwrap();
    assert!(!report.settle_timeout, "{report:?}");
    assert_eq!(report.excluded_volatile_targets, 0, "{report:?}");
    // each target changes once, so none is volatile and settle waited for the last one
    assert_eq!(
        eval(&ctx, "document.getElementById('c7').textContent").await,
        "done"
    );
    Box::new(ctx).close().await.unwrap();
}

/// `crawlx.browser.rss_bytes` is sampled from `/proc` within one interval of launch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rss_gauge_is_sampled_after_launch() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let gauge =
        crawlx_telemetry::Metrics::global().gauge(crawlx_telemetry::metrics::names::BROWSER_RSS_BYTES);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(7);
    let mut sampled = gauge.get(&[]);
    while !sampled.is_some_and(|v| v > 0.0) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
        sampled = gauge.get(&[]);
    }
    backend.close().await.unwrap();
    assert!(
        sampled.is_some_and(|v| v > 0.0),
        "rss gauge not sampled: {sampled:?}"
    );
}

// ---------------------------------------------------------------------------
// Attach mode, page hooks, page-load presets
// ---------------------------------------------------------------------------

const HOOKED: &str = r#"<!doctype html><html><head><title>Hooked</title></head><body>
<div id="card" style="width:200px;height:50px;background:#eee">Card</div>
<p id="o3">idle</p>
<script>
  document.getElementById('card').addEventListener('click', function () {
    document.getElementById('o3').textContent = 'card clicked';
  });
  history.pushState({}, '', '/app/pushed');
  fetch('/api/x').catch(function () {});
</script>
</body></html>"#;

fn hooks_site() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([("/", HOME), ("/hooked", HOOKED)])
}

/// Spawn a Chromium that is *not* ours (the "user's browser"), returning its DevTools
/// browser endpoint. The caller kills it at the end; attach must never do so.
struct ForeignBrowser {
    child: tokio::process::Child,
    ws_url: url::Url,
    _profile: tempfile::TempDir,
}

async fn spawn_foreign_browser() -> Option<ForeignBrowser> {
    let exe = find_executable()?;
    let profile = tempfile::Builder::new()
        .prefix("crawlx-foreign-")
        .tempdir()
        .unwrap();
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe.clone();
    cfg.allow_unpinned = true;
    if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_ok() {
        cfg.unsafe_no_sandbox_for_ci = true;
    }
    let flags = cfg.launch_flags(profile.path());
    let mut child = tokio::process::Command::new(&exe)
        .args(&flags)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut lines = tokio::io::BufReader::new(stderr).lines();
    let ws = tokio::time::timeout(Duration::from_secs(30), async {
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(rest) = line.split("DevTools listening on ").nth(1) {
                return Some(rest.trim().to_owned());
            }
        }
        None
    })
    .await
    .ok()
    .flatten();
    let Some(ws) = ws else {
        // sandbox failure in a container: retry once without it
        if !cfg.unsafe_no_sandbox_for_ci {
            let _ = child.kill().await;
            std::env::set_var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI", "1");
            return Box::pin(spawn_foreign_browser()).await;
        }
        panic!("foreign chromium printed no DevTools endpoint");
    };
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    Some(ForeignBrowser {
        child,
        ws_url: url::Url::parse(&ws).unwrap(),
        _profile: profile,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_drives_a_running_browser_and_leaves_it_alive() {
    let Some(mut foreign) = spawn_foreign_browser().await else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return;
    };
    let server = serve(site()).await;

    let mut cfg = LaunchConfig::new();
    cfg.allow_unpinned = false; // irrelevant for attach: never pinned, never fails
    cfg.cdp_ws_url = Some(foreign.ws_url.clone());
    let backend = ChromiumBackend::launch(cfg).await.unwrap();
    let info = backend.build_info().clone();
    assert!(info.attached && !info.pinned, "{info:?}");
    assert!(backend.is_attached());
    assert!(backend.launch_flags().is_empty());
    assert!(
        !backend.is_sandboxed(),
        "sandbox state of a foreign browser is unknown"
    );
    assert!(backend
        .cdp_transcript()
        .iter()
        .any(|m| m == "Target.getBrowserContexts"));

    // incognito context: observe works as with a launched browser
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    let nav = ctx.navigate(&canonical(server.port, "/two")).await.unwrap();
    assert_eq!(nav.status, Some(200));
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(b.title.as_deref(), Some("Two"));
    Box::new(ctx).close().await.unwrap();

    // non-incognito: the default context's page is adopted and left open afterwards
    let mut cfg = config(LaunchProfile::Standard);
    cfg.incognito = false;
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    let adopted = ctx.tab_ids();
    assert_eq!(adopted.len(), 1);
    ctx.navigate(&canonical(server.port, "/")).await.unwrap();
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert_eq!(b.title.as_deref(), Some("Crawlx Test"));
    // only the incognito context above created a browser context
    let created = backend
        .cdp_transcript()
        .iter()
        .filter(|m| *m == "Target.createBrowserContext")
        .count();
    assert_eq!(created, 1);
    Box::new(ctx).close().await.unwrap();
    // the adopted page was neither closed nor its context disposed
    let transcript = backend.cdp_transcript();
    assert_eq!(
        transcript
            .iter()
            .filter(|m| *m == "Target.disposeBrowserContext")
            .count(),
        1,
        "{transcript:?}"
    );

    backend.close().await.unwrap();
    // the foreign browser is still running: a fresh connection succeeds
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        foreign.child.try_wait().unwrap().is_none(),
        "attach must not kill the browser"
    );
    let again = ChromiumBackend::attach(&foreign.ws_url, LaunchConfig::new())
        .await
        .unwrap();
    let pages = again
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    Box::new(pages).close().await.unwrap();
    again.close().await.unwrap();
    let _ = foreign.child.kill().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn attach_rejects_a_page_endpoint_and_a_dead_endpoint() {
    let dead = url::Url::parse("ws://127.0.0.1:1/devtools/browser/nope").unwrap();
    let err = ChromiumBackend::attach(&dead, LaunchConfig::new())
        .await
        .err()
        .unwrap();
    assert!(matches!(err, BrowserError::Transport(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_hooks_capture_navigation_sinks_and_listeners() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(hooks_site()).await;

    // hooks off: nothing is captured and nothing is installed
    let mut off = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    off.navigate(&canonical(server.port, "/hooked")).await.unwrap();
    let b = off.observe(ObservationSpec::default()).await.unwrap();
    assert!(b.discovered_urls.is_empty(), "{:?}", b.discovered_urls);
    assert!(off.drain_discovery().await.unwrap().is_empty());
    let installed = off
        .evaluate_isolated("typeof window.__crawlxDrainDiscovery")
        .await
        .unwrap();
    assert_eq!(installed, "undefined");
    Box::new(off).close().await.unwrap();

    // hooks on
    let mut cfg = config(LaunchProfile::Standard);
    cfg.page_hooks = true;
    let mut ctx = backend.new_cdp_context(cfg).await.unwrap();
    ctx.navigate(&canonical(server.port, "/hooked")).await.unwrap();
    let spec = ObservationSpec {
        ax: true,
        dom_supplement: true,
        dom_snapshot: false,
        screenshot: false,
        revalidation_only: false,
    };
    let safety = ctx
        .observe(ObservationSpec {
            revalidation_only: true,
            ..spec
        })
        .await
        .unwrap();
    assert!(safety.discovered_urls.is_empty());
    let b = ctx.observe(spec).await.unwrap();
    assert_eq!(b.seq, safety.seq + 1);
    let sources: Vec<(&str, &str)> = b
        .discovered_urls
        .iter()
        .map(|(u, s)| (u.as_str(), s.as_str()))
        .collect();
    assert!(
        sources.contains(&("/app/pushed", "history.pushState")),
        "{sources:?}"
    );
    assert!(sources.contains(&("/api/x", "fetch")), "{sources:?}");
    // the div's click listener is a listener candidate with its backend node id
    let card = b
        .dom_supplement
        .nodes
        .iter()
        .find(|(_, n)| n.attributes.get("id").map(String::as_str) == Some("card"))
        .map(|(id, _)| *id);
    let candidates: Vec<i64> = b.dom_supplement.listener_candidates.iter().map(|c| c.0).collect();
    assert!(
        !candidates.is_empty(),
        "no listener candidates: {:?}",
        b.dom_supplement
    );
    if let Some(id) = card {
        assert!(candidates.contains(&id), "card {id} not in {candidates:?}");
        assert!(b.dom_supplement.nodes[&id]
            .listeners
            .contains(&"click".to_owned()));
    }
    // drained: a second observation without new activity reports nothing
    let again = ctx.observe(ObservationSpec::default()).await.unwrap();
    assert!(again.discovered_urls.is_empty(), "{:?}", again.discovered_urls);
    // hooks never dispatch: the click handler did not run
    assert_eq!(
        eval(&ctx, "document.getElementById('o3').textContent").await,
        "idle"
    );
    // the page's own call still went through the original fetch (it reached the server)
    assert_eq!(eval(&ctx, "location.pathname").await, "/app/pushed");
    Box::new(ctx).close().await.unwrap();

    // stealth refuses the hooks
    let stealth = launch(LaunchProfile::Stealth, None).await.unwrap();
    let mut cfg = config(LaunchProfile::Stealth);
    cfg.page_hooks = true;
    let err = stealth.new_cdp_context(cfg).await.err().unwrap();
    assert!(matches!(err, BrowserError::Unsupported(_)), "{err:?}");
    stealth.close().await.unwrap();
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_load_presets_drive_settle() {
    use crawlx_core::config::PageLoadStrategy;
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(site()).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/two")).await.unwrap();
    // domcontentloaded: the fixed wait is honored and counted
    let dcl = ctx
        .settle(QuiescencePolicy::preset(PageLoadStrategy::DomContentLoaded, 400))
        .await
        .unwrap();
    assert!(dcl.waited_ms >= 400, "{dcl:?}");
    assert!(!dcl.settle_timeout && dcl.navigation_settled, "{dcl:?}");
    // none: returns at once
    let none = ctx
        .settle(QuiescencePolicy::preset(PageLoadStrategy::None, 5_000))
        .await
        .unwrap();
    assert!(none.waited_ms < 200, "{none:?}");
    // load / networkidle: a settled static page is idle immediately
    for s in [
        PageLoadStrategy::Load,
        PageLoadStrategy::NetworkIdle,
        PageLoadStrategy::Heuristic,
    ] {
        let r = ctx.settle(QuiescencePolicy::preset(s, 5_000)).await.unwrap();
        assert!(!r.settle_timeout, "{s:?}: {r:?}");
    }
    Box::new(ctx).close().await.unwrap();
}

/// A page with a cross-origin iframe (`localhost` against the page's `127.0.0.1`): an
/// out-of-process iframe whose document only its own CDP session can see.
const OOPIF: &str = r#"<!doctype html><html><head><title>Frames</title></head><body>
<h1>Outer</h1><p id="out">none</p>
<button id="top-btn" onclick="document.getElementById('out').textContent='top'">Top</button>
<div style="height:200px"></div>
<iframe id="xo" name="xo" title="Cross origin" style="width:400px;height:150px;border:3px solid red"></iframe>
<script>
window.addEventListener('message', function (ev) { document.getElementById('out').textContent = ev.data; });
document.getElementById('xo').src = 'http://localhost:' + location.port + '/frame';
</script></body></html>"#;

const OOPIF_FRAME: &str = r#"<!doctype html><html><head><title>Inner</title></head><body>
<p>inner document</p>
<button id="fb" onclick="parent.postMessage('frame:' + event.isTrusted, '*')">In frame</button>
</body></html>"#;

/// An out-of-process iframe is auto-attached, its document observed with the frame lineage
/// and boxes in the page's viewport, and its controls act through native input on their
/// own session (G05).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn out_of_process_iframes_are_observed_and_actionable() {
    use crawlx_browser::context::state::{split_node_id, NODE_ID_SPAN};
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    let server = serve(BTreeMap::from([("/oopif", OOPIF), ("/frame", OOPIF_FRAME)])).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/oopif")).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let b = ctx.observe(ObservationSpec::default()).await.unwrap();

    let main = b.frames.first().unwrap();
    let child = b
        .frames
        .iter()
        .find(|f| f.url.contains("localhost"))
        .unwrap_or_else(|| panic!("cross-origin frame missing from {:?}", b.frames));
    assert_eq!(child.parent.as_ref(), Some(&main.id));
    assert!(!child.same_origin && child.lineage.len() == 1, "{child:?}");

    let inner = find(&b, "button", "In frame");
    let top = find(&b, "button", "Top");
    assert_eq!(inner.locator.frame, child.id);
    assert_eq!(top.locator.frame, main.id);
    let (index, raw) = split_node_id(inner.locator.backend_node_id.0);
    assert!(index == 1 && raw > 0 && inner.locator.backend_node_id.0 >= NODE_ID_SPAN);
    // the frame's box is translated into the page viewport: below the 200 px spacer
    let (inner_box, top_box) = (inner.bbox.unwrap(), top.bbox.unwrap());
    assert!(inner_box.y > top_box.y + 200.0, "{inner_box:?} vs {top_box:?}");
    let supplement = &b.dom_supplement.nodes[&inner.locator.backend_node_id.0];
    assert_eq!(supplement.attributes.get("id").map(String::as_str), Some("fb"));

    let target = inner.locator.clone();
    let rv = ctx.revalidate(&target, b.epoch).await.unwrap();
    assert!(matches!(rv, Revalidation::Actionable { .. }), "{rv:?}");
    let receipt = ctx.perform(click(target)).await.unwrap();
    assert_eq!(
        (receipt.fidelity, receipt.lane),
        (Fidelity::NativePointer, TrustLane::TrustedUi)
    );
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    assert_eq!(
        eval(&ctx, "document.getElementById('out').textContent").await,
        "frame:true"
    );
    // the page's own controls keep working alongside
    let receipt = ctx.perform(click(top.locator.clone())).await.unwrap();
    assert_eq!(receipt.fidelity, Fidelity::NativePointer);
    assert_eq!(
        eval(&ctx, "document.getElementById('out').textContent").await,
        "top"
    );
    Box::new(ctx).close().await.unwrap();
}

/// Owned fields use the form's destination, not submitter-only overrides on a field.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_form_fields_keep_owner_destination_through_revalidation_and_typing() {
    let Some(backend) = launch(LaunchProfile::Standard, None).await else {
        return;
    };
    const FORM: &str = r#"<!doctype html><title>Native form</title>
<form id="invite" action="/sink" method="post">
<input id="phone" type="tel" aria-label="Phone" formaction="/wrong" formmethod="get">
<select aria-label="Channel"><option>SMS</option><option>Email</option></select>
<textarea aria-label="Message"></textarea>
<button formaction="/override" formmethod="get">Send invite</button>
<button type="button">Show options</button>
</form>
<input aria-label="External phone" type="tel" form="invite">"#;
    let server = serve(BTreeMap::from([("/form", FORM)])).await;
    let mut ctx = backend
        .new_cdp_context(config(LaunchProfile::Standard))
        .await
        .unwrap();
    ctx.navigate(&canonical(server.port, "/form")).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    let destination = format!("http://127.0.0.1:{}/sink", server.port);
    for (role, name) in [
        ("textbox", "Phone"),
        ("combobox", "Channel"),
        ("textbox", "Message"),
        ("textbox", "External phone"),
    ] {
        let node = find(&bundle, role, name);
        let attrs = &bundle.dom_supplement.nodes[&node.locator.backend_node_id.0].attributes;
        assert_eq!(
            attrs.get("form-action").map(String::as_str),
            Some("/sink"),
            "{name}"
        );
        assert_eq!(
            attrs.get("form-method").map(String::as_str),
            Some("post"),
            "{name}"
        );
        let Revalidation::Actionable { live: facts } =
            ctx.revalidate(&node.locator, bundle.epoch).await.unwrap()
        else {
            panic!("{name} must remain actionable");
        };
        assert_eq!(facts.attributes.get("form-action"), Some(&destination), "{name}");
        assert_eq!(
            facts.attributes.get("form-method").map(String::as_str),
            Some("post"),
            "{name}"
        );
    }
    let submit = find(&bundle, "button", "Send invite");
    let Revalidation::Actionable { live: facts } =
        ctx.revalidate(&submit.locator, bundle.epoch).await.unwrap()
    else {
        panic!("submitter must remain actionable");
    };
    assert_eq!(
        facts.attributes.get("form-action"),
        Some(&format!("http://127.0.0.1:{}/override", server.port))
    );
    assert_eq!(
        facts.attributes.get("form-method").map(String::as_str),
        Some("get")
    );
    let local = find(&bundle, "button", "Show options");
    let Revalidation::Actionable { live: facts } =
        ctx.revalidate(&local.locator, bundle.epoch).await.unwrap()
    else {
        panic!("local button must remain actionable");
    };
    assert!(!facts.attributes.contains_key("form-action"));
    let phone = find(&bundle, "textbox", "Phone");
    let receipt = ctx
        .perform(BrowserAction::Type {
            target: phone.locator.clone(),
            value: SecretOr::Plain("+15555550123".into()),
            clear_first: true,
        })
        .await
        .unwrap();
    assert_eq!(receipt.fidelity, Fidelity::NativeTextInput);
    assert_eq!(
        eval(&ctx, "document.getElementById('phone').value").await,
        "+15555550123"
    );
    Box::new(ctx).close().await.unwrap();
}
