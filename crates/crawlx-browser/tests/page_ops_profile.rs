//! Chromium integration tests of the context profile page operations: device pixel ratio and
//! geolocation emulation, versioned resource block lists, shadow-DOM and iframe flattening
//! with per-frame provenance, and the measured device matrix. Skipped (with a message) when no
//! Chromium executable is found; set `CRAWLX_CHROMIUM_PATH` to point at a specific binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::launch::find_executable;
use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserBackend, BrowserContext, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::ids::SessionId;
use crawlx_core::page_op::{
    BlockClass, BlockEntry, DevicePreset, Emulation, FlattenSpec, FrameStatus, GeoPosition, PageOp,
    PageOpResult, ResourceBlockSpec, ShotSpec,
};
use crawlx_core::url::CanonicalUrl;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Route {
    content_type: &'static str,
    body: Vec<u8>,
}

fn html(body: &str) -> Route {
    Route {
        content_type: "text/html; charset=utf-8",
        body: body.as_bytes().to_vec(),
    }
}

fn asset(content_type: &'static str, body: &str) -> Route {
    Route {
        content_type,
        body: body.as_bytes().to_vec(),
    }
}

struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Server {
    /// Request targets (with query) whose path is `path`.
    fn requests(&self, path: &str) -> Vec<String> {
        self.seen
            .lock()
            .iter()
            .filter(|t| t.split('?').next() == Some(path))
            .cloned()
            .collect()
    }

    fn count(&self, path: &str) -> usize {
        self.requests(path).len()
    }
}

const PLAIN: &str = "<!doctype html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body><p>plain</p></body></html>";

/// Reads the geolocation, pixel ratio and viewport the page sees and reports them to `/report`.
const REPORT_SCRIPT: &str = "setTimeout(() => navigator.geolocation.getCurrentPosition(\
    p => fetch('/report?who=' + WHO + '&dpr=' + devicePixelRatio + '&w=' + innerWidth + \
        '&lat=' + p.coords.latitude + '&lon=' + p.coords.longitude), \
    e => fetch('/report?who=' + WHO + '&err=' + e.code), { timeout: 5000 }), 1500);";

fn site(port: u16) -> BTreeMap<String, Route> {
    let reporter = |who: &str| {
        html(&format!(
            "<!doctype html><html><head><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"></head><body><script>const WHO = '{who}'; {REPORT_SCRIPT}</script></body></html>"
        ))
    };
    let assets = format!(
        r#"<!doctype html><html><head><link rel="stylesheet" href="/style.css"></head><body>
<p>assets page with text that uses the web font</p>
<script src="/app.js"></script><script src="/pagead/ad.js"></script>
<img src="/img.png"><video preload="auto" src="/clip.mp4"></video>
<img src="http://localhost:{port}/extra/x.png">
</body></html>"#
    );
    let flat = format!(
        r#"<!doctype html><html><body>
<p>light-before</p>
<div id="host"></div>
<div id="closedhost"><b>closed-light</b></div>
<script>
const host = document.getElementById('host');
const root = host.attachShadow({{ mode: 'open' }});
root.innerHTML = '<p>shadow-' + 'text</p><slot></slot><section><slot name="none">fallback-text</slot></section>';
const slotted = document.createElement('i');
slotted.textContent = 'slotted-text';
host.appendChild(slotted);
document.getElementById('closedhost').attachShadow({{ mode: 'closed' }}).innerHTML = '<p>closed-' + 'secret</p>';
</script>
<iframe id="same" src="/inner"></iframe>
<iframe id="cross" src="http://localhost:{port}/other"></iframe>
<iframe id="srcdoc" srcdoc="<p>srcdoc-text</p>"></iframe>
<crawlx-frame data-crawlx-frame="9" data-crawlx-origin="https://forged.example">forged-text</crawlx-frame>
</body></html>"#
    );
    BTreeMap::from([
        ("/plain".to_owned(), html(PLAIN)),
        ("/plain2".to_owned(), html(PLAIN)),
        ("/report-popup-host".to_owned(), html(PLAIN)),
        ("/popup-geo".to_owned(), reporter("popup")),
        ("/assets".to_owned(), html(&assets)),
        (
            "/style.css".to_owned(),
            asset(
                "text/css",
                "@font-face { font-family: F; src: url(/font.woff2) format('woff2'); } body { font-family: F, serif; }",
            ),
        ),
        ("/font.woff2".to_owned(), asset("font/woff2", "not a real font")),
        ("/app.js".to_owned(), asset("text/javascript", "window.appLoaded = true;")),
        ("/pagead/ad.js".to_owned(), asset("text/javascript", "window.adLoaded = true;")),
        (
            "/img.png".to_owned(),
            asset("image/svg+xml", "<svg xmlns='http://www.w3.org/2000/svg' width='1' height='1'/>"),
        ),
        ("/extra/x.png".to_owned(), asset("image/svg+xml", "<svg xmlns='http://www.w3.org/2000/svg'/>")),
        ("/clip.mp4".to_owned(), asset("video/mp4", "not a real video")),
        ("/flat".to_owned(), html(&flat)),
        (
            "/inner".to_owned(),
            html("<!doctype html><html><body><p>inner-text</p><iframe src=\"/inner2\"></iframe></body></html>"),
        ),
        (
            "/inner2".to_owned(),
            html("<!doctype html><html><body><p>deep-text</p></body></html>"),
        ),
        (
            "/other".to_owned(),
            html("<!doctype html><html><body><p>other-origin-text</p></body></html>"),
        ),
    ])
}

async fn serve() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let routes = Arc::new(site(port));
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(handle(sock, Arc::clone(&routes), Arc::clone(&seen)));
            }
        });
    }
    Server { port, seen }
}

async fn handle(mut sock: TcpStream, routes: Arc<BTreeMap<String, Route>>, seen: Arc<Mutex<Vec<String>>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let target = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap_or("/")
        .to_owned();
    let path = target.split('?').next().unwrap_or("/").to_owned();
    seen.lock().push(target);
    let (status, content_type, body) = match (path.as_str(), routes.get(&path)) {
        ("/report", _) => ("200 OK", "text/plain", b"ok".to_vec()),
        (_, Some(route)) => ("200 OK", route.content_type, route.body.clone()),
        _ => ("404 Not Found", "text/plain", b"not found".to_vec()),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.write_all(&body).await;
    let _ = sock.shutdown().await;
}

async fn launch() -> Option<ChromiumBackend> {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.launch_profile = LaunchProfile::Standard;
    cfg.allow_unpinned = true;
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

async fn start() -> Option<(ChromiumBackend, CdpContext, Server)> {
    let backend = launch().await?;
    let mut config = ContextConfig::new(SessionId::new());
    config.launch_profile = LaunchProfile::Standard;
    let ctx = backend.new_cdp_context(config).await.unwrap();
    Some((backend, ctx, serve().await))
}

fn canonical(port: u16, path: &str) -> CanonicalUrl {
    let base = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    Canonicalizer::canonicalize(path, &base, &CanonicalizeOptions::default()).unwrap()
}

async fn goto(ctx: &mut CdpContext, server: &Server, path: &str) {
    ctx.navigate(&canonical(server.port, path)).await.unwrap();
}

async fn op(ctx: &mut CdpContext, op: PageOp) -> PageOpResult {
    ctx.page_op(op).await.unwrap()
}

async fn eval(ctx: &mut CdpContext, script: &str) -> Value {
    match op(
        ctx,
        PageOp::EvaluateScript {
            script: script.to_owned(),
        },
    )
    .await
    {
        PageOpResult::Json(v) => v,
        other => panic!("{other:?}"),
    }
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn measure(ctx: &mut CdpContext, probe_geolocation: bool) -> crawlx_core::page_op::DeviceMeasurement {
    match op(ctx, PageOp::MeasureDevice { probe_geolocation }).await {
        PageOpResult::Device(m) => m,
        other => panic!("{other:?}"),
    }
}

fn png_size(bytes: &[u8]) -> (u32, u32) {
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
    (
        u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
        u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
    )
}

/// The query parameter `key` of a `/report?...` target.
fn param(target: &str, key: &str) -> Option<String> {
    target
        .split_once('?')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{key}=")).map(str::to_owned))
}

fn spec(entries: &[(&str, BlockClass)]) -> ResourceBlockSpec {
    ResourceBlockSpec {
        list_version: "test-list/1".to_owned(),
        entries: entries
            .iter()
            .map(|(pattern, class)| BlockEntry {
                pattern: (*pattern).to_owned(),
                class: *class,
            })
            .collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn device_scale_and_geolocation_are_measured_and_stable_across_the_context() {
    let Some((_backend, mut ctx, server)) = start().await else {
        return;
    };
    goto(&mut ctx, &server, "/plain").await;
    let baseline = measure(&mut ctx, true).await;
    assert_eq!(baseline.device_pixel_ratio_milli, 1_000, "{baseline:?}");
    assert_eq!(
        baseline.geolocation, None,
        "no position without a request: {baseline:?}"
    );

    let munich = GeoPosition::new(48_137_154, 11_576_124, 25).unwrap();
    let emulation = Emulation {
        viewport: Some((412, 915)),
        mobile: true,
        device_scale_milli: Some(2_625),
        geolocation: Some(munich),
        ..Emulation::default()
    };
    assert_eq!(op(&mut ctx, PageOp::Emulate(emulation)).await, PageOpResult::Done);

    // the requested values are what the page reports, on the first and every later document
    for path in ["/plain", "/plain2", "/plain"] {
        goto(&mut ctx, &server, path).await;
        let seen = measure(&mut ctx, true).await;
        assert_eq!(seen.viewport, (412, 915), "{path}: {seen:?}");
        assert_eq!(seen.device_pixel_ratio_milli, 2_625, "{path}: {seen:?}");
        assert_eq!(seen.geolocation, Some(munich), "{path}: {seen:?}");
        assert_eq!(seen.geolocation_error, None, "{path}: {seen:?}");
    }

    // a popup attached afterwards and an out-of-process iframe report the same device
    goto(&mut ctx, &server, "/plain").await;
    eval(&mut ctx, "window.open('/popup-geo'); 1").await;
    eventually("the popup to report", || server.count("/report") >= 1).await;
    let popup = server.requests("/report").remove(0);
    assert_eq!(param(&popup, "who").as_deref(), Some("popup"), "{popup}");
    assert_eq!(
        param(&popup, "err"),
        None,
        "popup could not read the position: {popup}"
    );
    assert_eq!(param(&popup, "dpr").as_deref(), Some("2.625"), "{popup}");
    assert_eq!(param(&popup, "w").as_deref(), Some("412"), "{popup}");
    assert_eq!(param(&popup, "lat").as_deref(), Some("48.137154"), "{popup}");
    assert_eq!(param(&popup, "lon").as_deref(), Some("11.576124"), "{popup}");

    // NOTE: an out-of-process iframe's own geolocation read is not asserted here; the override
    // is installed on frame sessions, but its read-back is not covered by this test.

    // the screenshot is taken at the requested pixel ratio
    op(
        &mut ctx,
        PageOp::Emulate(Emulation {
            viewport: Some((300, 200)),
            device_scale_milli: Some(2_000),
            ..Emulation::default()
        }),
    )
    .await;
    goto(&mut ctx, &server, "/plain").await;
    let PageOpResult::Bytes { bytes, .. } = op(&mut ctx, PageOp::Screenshot(ShotSpec::default())).await
    else {
        panic!("screenshot")
    };
    assert_eq!(png_size(&bytes), (600, 400));

    // clearing the emulation puts ratio and geolocation back
    op(&mut ctx, PageOp::Emulate(Emulation::default())).await;
    goto(&mut ctx, &server, "/plain").await;
    let restored = measure(&mut ctx, true).await;
    assert_eq!(restored.device_pixel_ratio_milli, 1_000, "{restored:?}");
    assert_eq!(restored.geolocation, None, "{restored:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_lists_keep_fonts_media_ads_and_hosts_out_of_the_access_log() {
    let Some((_backend, mut ctx, server)) = start().await else {
        return;
    };
    let list = spec(&[
        ("*://*/pagead/*", BlockClass::Ads),
        ("*://localhost/*", BlockClass::Domain),
        ("*://localhost:*/*", BlockClass::Domain),
        ("*.woff2", BlockClass::Font),
        ("*.woff2?*", BlockClass::Font),
        ("*.mp4", BlockClass::Media),
        ("*.mp4?*", BlockClass::Media),
    ]);
    let PageOpResult::BlockInstalled(install) = op(&mut ctx, PageOp::BlockResources(list)).await else {
        panic!("install")
    };
    assert_eq!(install.patterns, 7);
    assert!(install.sessions_applied >= 1, "{install:?}");
    assert_eq!(install.sessions_failed, 0, "{install:?}");

    goto(&mut ctx, &server, "/assets").await;
    eventually("the allowed subresources", || {
        server.count("/style.css") == 1 && server.count("/app.js") == 1 && server.count("/img.png") == 1
    })
    .await;
    // the blocked ones had every chance to go out before the page settled
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(server.count("/font.woff2"), 0, "font reached the server");
    assert_eq!(server.count("/clip.mp4"), 0, "media reached the server");
    assert_eq!(server.count("/pagead/ad.js"), 0, "ad reached the server");
    assert_eq!(
        server.count("/extra/x.png"),
        0,
        "a blocked host reached the server"
    );
    assert_eq!(eval(&mut ctx, "window.adLoaded === undefined").await, json!(true));

    // the next list replaces the first: nothing is blocked any more
    let PageOpResult::BlockInstalled(empty) = op(&mut ctx, PageOp::BlockResources(spec(&[]))).await else {
        panic!("install")
    };
    assert_eq!(empty.patterns, 0);
    goto(&mut ctx, &server, "/assets").await;
    eventually("the formerly blocked requests", || {
        server.count("/font.woff2") >= 1
            && server.count("/clip.mp4") >= 1
            && server.count("/pagead/ad.js") >= 1
            && server.count("/extra/x.png") >= 1
    })
    .await;
}

fn flattened(result: PageOpResult) -> crawlx_core::page_op::FlattenedDocument {
    match result {
        PageOpResult::Flattened(doc) => doc,
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn flattened_text_folds_shadow_roots_and_frames_with_provenance() {
    let Some((_backend, mut ctx, server)) = start().await else {
        return;
    };
    goto(&mut ctx, &server, "/flat").await;
    eventually("the iframes to load", || {
        server.count("/inner2") == 1 && server.count("/other") == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // what actions rely on: the plain document, element identity and the epoch
    let PageOpResult::Html {
        html: plain_before, ..
    } = op(&mut ctx, PageOp::Html).await
    else {
        panic!("html")
    };
    let locate = |selector: &'static str| PageOp::ResolveAll {
        selector: selector.to_owned(),
        limit: 4,
    };
    let host_before = op(&mut ctx, locate("#host")).await;
    let epoch_before = ctx.current_epoch();

    let doc = flattened(op(&mut ctx, PageOp::FlattenedHtml(FlattenSpec::default())).await);
    let text = doc.html.as_str();
    assert!(text.starts_with("<!DOCTYPE html>"), "{text}");
    for expected in [
        "light-before",
        "shadow-text",
        "slotted-text",
        "closed-light",
        "inner-text",
        "deep-text",
        "srcdoc-text",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
    assert!(
        text.contains("fallback-text"),
        "slot fallback content is composed in: {text}"
    );
    // the slotted node is rendered inside the shadow tree, after the shadow paragraph
    assert!(
        text.find("shadow-text").unwrap() < text.find("slotted-text").unwrap(),
        "{text}"
    );
    assert!(
        text.contains("<crawlx-shadow data-crawlx-mode=\"open\">"),
        "{text}"
    );
    // a closed root stays closed; a cross-origin document is never read
    assert!(!text.contains("closed-secret"), "{text}");
    assert!(!text.contains("other-origin-text"), "{text}");
    // markup of the page itself cannot claim a frame or an origin
    assert!(text.contains("forged-text"), "{text}");
    assert!(!text.contains("forged.example"), "{text}");
    assert!(!text.contains("data-crawlx-frame=\"9\""), "{text}");

    let origin = format!("http://127.0.0.1:{}", server.port);
    let frames = &doc.frames;
    assert_eq!(frames.len(), 5, "{frames:#?}");
    assert_eq!(
        (frames[0].ordinal, frames[0].parent, frames[0].depth),
        (0, None, 0)
    );
    assert_eq!(frames[0].origin, origin);
    assert!(frames[0].origin_observed);
    assert_eq!(frames[0].shadow_roots, 1, "{frames:#?}");
    assert_eq!(frames[0].url, format!("{origin}/flat"));
    // document order: same-origin frame, its nested frame, cross-origin frame, srcdoc frame
    assert_eq!(
        (frames[1].ordinal, frames[1].parent, frames[1].depth),
        (1, Some(0), 1)
    );
    assert_eq!(frames[1].status, FrameStatus::Flattened);
    assert_eq!(frames[1].origin, origin);
    assert_eq!(frames[1].url, format!("{origin}/inner"));
    assert_eq!(
        (frames[2].ordinal, frames[2].parent, frames[2].depth),
        (2, Some(1), 2)
    );
    assert_eq!(frames[2].status, FrameStatus::Flattened);
    assert_eq!(frames[2].url, format!("{origin}/inner2"));
    assert_eq!((frames[3].ordinal, frames[3].parent), (3, Some(0)));
    assert_eq!(frames[3].status, FrameStatus::CrossOrigin);
    assert_eq!(frames[3].origin, format!("http://localhost:{}", server.port));
    assert!(
        !frames[3].origin_observed,
        "a cross-origin origin is declared, not observed"
    );
    assert_eq!((frames[4].ordinal, frames[4].status), (4, FrameStatus::Flattened));
    assert_eq!(
        frames[4].origin, origin,
        "a srcdoc frame inherits its parent's origin"
    );
    assert_eq!(doc.frames_omitted, 0);
    for (n, frame) in frames.iter().enumerate().skip(1) {
        assert!(
            text.contains(&format!(
                "data-crawlx-frame=\"{n}\" data-crawlx-origin=\"{}\"",
                frame.origin
            )),
            "frame {n} has no provenance marker: {text}"
        );
    }

    // reading changed nothing the actor depends on
    let PageOpResult::Html {
        html: plain_after, ..
    } = op(&mut ctx, PageOp::Html).await
    else {
        panic!("html")
    };
    assert_eq!(
        plain_before.as_str(),
        plain_after.as_str(),
        "the live DOM was altered"
    );
    assert_eq!(op(&mut ctx, locate("#host")).await, host_before);
    assert_eq!(ctx.current_epoch(), epoch_before);

    // each part can be left out
    let only_frames = flattened(
        op(
            &mut ctx,
            PageOp::FlattenedHtml(FlattenSpec {
                shadow_dom: false,
                ..FlattenSpec::default()
            }),
        )
        .await,
    );
    assert!(!only_frames.html.as_str().contains("shadow-text"));
    assert!(only_frames.html.as_str().contains("inner-text"));
    let only_shadow = flattened(
        op(
            &mut ctx,
            PageOp::FlattenedHtml(FlattenSpec {
                frames: false,
                ..FlattenSpec::default()
            }),
        )
        .await,
    );
    assert!(only_shadow.html.as_str().contains("shadow-text"));
    assert!(!only_shadow.html.as_str().contains("inner-text"));
    assert!(
        only_shadow.html.as_str().contains("<iframe"),
        "iframes stay as they are"
    );
    assert_eq!(only_shadow.frames.len(), 1);

    // the frame bound is reported, never silently exceeded
    let bounded = flattened(
        op(
            &mut ctx,
            PageOp::FlattenedHtml(FlattenSpec {
                max_frames: 2,
                ..FlattenSpec::default()
            }),
        )
        .await,
    );
    let statuses: Vec<_> = bounded.frames.iter().map(|f| f.status).collect();
    assert_eq!(
        statuses,
        [
            FrameStatus::Flattened,
            FrameStatus::Flattened,
            FrameStatus::FrameLimit,
            FrameStatus::CrossOrigin,
            FrameStatus::FrameLimit
        ],
        "{:#?}",
        bounded.frames
    );
    assert!(!bounded.html.as_str().contains("deep-text"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_device_matrix_is_measured_coherent_and_restores_the_context() {
    let Some((backend, ctx, server)) = start().await else {
        return;
    };
    let mut ctx = ctx;
    goto(&mut ctx, &server, "/plain").await;
    let before = measure(&mut ctx, false).await;
    let build = backend.build_info().clone();
    let matrix = ctx
        .measure_device_matrix(&build.chromium_version, build.pinned)
        .await
        .unwrap();
    assert_eq!(matrix.schema_version, 1);
    assert_eq!(matrix.build.chromium_version, build.chromium_version);
    assert!(!matrix.stealth_claim);
    let presets: Vec<_> = matrix.entries.iter().map(|e| e.preset).collect();
    assert_eq!(presets, DevicePreset::ALL);
    for entry in &matrix.entries {
        assert!(
            entry.coherent,
            "{:?}: {:?} / {:?}",
            entry.preset, entry.violations, entry.measured
        );
    }
    assert!(matrix.coherent());
    let phone = &matrix.entries[1];
    assert_eq!(phone.measured.screen, (412, 915));
    assert_eq!(phone.measured.device_pixel_ratio_milli, 2_625);
    assert!(phone.measured.max_touch_points > 0);
    assert!(
        phone.measured.user_agent.contains(" Mobile Safari/"),
        "{:?}",
        phone.measured
    );
    let desktop = &matrix.entries[0];
    assert_eq!(desktop.measured.max_touch_points, 0);
    assert_eq!(desktop.measured.device_pixel_ratio_milli, 1_000);
    let tablet = &matrix.entries[2];
    assert_eq!(tablet.measured.screen, (800, 1280));
    assert!(
        !tablet.measured.user_agent.contains(" Mobile"),
        "{:?}",
        tablet.measured
    );

    // the context is the way it was
    assert_eq!(measure(&mut ctx, false).await, before);
}
