//! Chromium integration tests of `BrowserContext::page_op`: request blocking,
//! emulation, the document response, script evaluation, serialization, screenshots, PDF,
//! selector waits and element resolution. Skipped (with a message) when no Chromium
//! executable is found; set `CRAWLX_CHROMIUM_PATH` to point at a specific binary.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::egress::REDACTED;
use crawlx_browser::launch::find_executable;
use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::browser::{BrowserBackend, BrowserContext, BrowserError, ContextConfig};
use crawlx_core::config::LaunchProfile;
use crawlx_core::ids::SessionId;
use crawlx_core::observation::RuntimeLocator;
use crawlx_core::page_op::{Emulation, PageOp, PageOpResult, PdfSpec, SelectorState, ShotSpec};
use crawlx_core::url::CanonicalUrl;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The `User-Agent` the emulation tests install.
const PHONE_UA: &str = "CrawlxPhone/1.0 (Linux; Android 14; Pixel) Mobile";

const IMG_PAGE: &str = r#"<!doctype html><html><body>
<img id="blocked" src="/blocked/a.svg"><img id="allowed" src="/allowed/b.svg">
</body></html>"#;

/// Waits for the test to open `/gate`, then loads one blocked and one allowed image: the
/// popup's session is attached long before it asks.
const POPUP: &str = r#"<!doctype html><html><body><script>
(function poll() {
  fetch('/gate').then(function (r) { return r.text(); }).then(function (t) {
    if (t === 'open') {
      new Image().src = '/blocked/popup.svg';
      new Image().src = '/allowed/popup.svg';
    } else { setTimeout(poll, 50); }
  });
})();
</script></body></html>"#;

const FRAME_HOST_PREFIX: &str = r#"<!doctype html><html><body><iframe src="http://localhost:"#;

const FRAME: &str = r#"<!doctype html><html><body>
<img src="/blocked/frame.svg"><img src="/allowed/frame.svg">
</body></html>"#;

const PHONE_PAGE: &str = r#"<!doctype html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Phone</title></head>
<body><p>phone</p></body></html>"#;

/// Waits for the test to open `/gate`, then reports what the popup's page sees.
const PHONE_POPUP: &str = r#"<!doctype html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1"></head><body><script>
(function poll() {
  fetch('/gate').then(function (r) { return r.text(); }).then(function (t) {
    if (t === 'open') {
      fetch('/report?ua=' + encodeURIComponent(navigator.userAgent) + '&w=' + innerWidth +
        '&touch=' + navigator.maxTouchPoints +
        '&tz=' + encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone));
    } else { setTimeout(poll, 50); }
  });
})();
</script></body></html>"#;

const DOM_PAGE: &str = r#"<!doctype html><html lang="en"><head><title>Dom</title></head><body>
<div id="a">static</div>
<script>
document.getElementById('a').textContent = 'from script';
var p = document.createElement('p'); p.id = 'late'; p.textContent = 'made by script';
document.body.appendChild(p);
window.marker = 41;
</script></body></html>"#;

const QUIRKS_PAGE: &str = "<html><body>no doctype</body></html>";

const TALL_PAGE: &str = r#"<!doctype html><html><body style="margin:0">
<div style="height:3000px;background:#0a7"></div></body></html>"#;

const HUGE_PAGE: &str = r#"<!doctype html><html><body style="margin:0">
<div style="height:20000px;background:#a70"></div></body></html>"#;

/// `#late` appears 1.5 s after the script ran.
const LATE_PAGE: &str = r#"<!doctype html><html><body><h1>late</h1><script>
setTimeout(function () {
  var d = document.createElement('div'); d.id = 'late'; document.body.appendChild(d);
}, 1500);
</script></body></html>"#;

const SELECTOR_PAGE: &str = r#"<!doctype html><html><body>
<div id="visible" style="width:20px;height:20px">visible</div>
<div id="display-none" style="display:none">hidden</div>
<div id="visibility-hidden" style="visibility:hidden;width:20px;height:20px">hidden</div>
<div id="visibility-collapse" style="visibility:collapse;width:20px;height:20px">hidden</div>
<div style="display:none"><div id="hidden-parent">hidden</div></div>
<div id="zero-width" style="width:0;height:20px"></div>
<div id="zero-height" style="width:20px;height:0"></div>
<div id="transparent" style="opacity:0;width:20px;height:20px"></div>
<div id="offscreen" style="position:absolute;left:-10000px;width:20px;height:20px"></div>
<div class="first" style="display:none">first hidden</div>
<div class="first" style="width:20px;height:20px">second visible</div>
</body></html>"#;

const LIST_PAGE: &str = r#"<!doctype html><html><body><p id="out">idle</p><ul>
<li><button class="b" onclick="document.getElementById('out').textContent='clicked 1'">One</button></li>
<li><button class="b" onclick="document.getElementById('out').textContent='clicked 2'">Two</button></li>
<li><button class="b" onclick="document.getElementById('out').textContent='clicked 3'">Three</button></li>
<li><button class="b" onclick="document.getElementById('out').textContent='clicked 4'">Four</button></li>
<li><button class="b" onclick="document.getElementById('out').textContent='clicked 5'">Five</button></li>
</ul></body></html>"#;

const FORM_PAGE: &str = r#"<!doctype html><html><body>
<form id="f" method="post" action="/submit"><input name="a" value="1"></form></body></html>"#;

const DONE_PAGE: &str = r#"<!doctype html><html><body><div id="final">done</div></body></html>"#;

struct Route {
    status: &'static str,
    content_type: &'static str,
    headers: Vec<(&'static str, &'static str)>,
    body: Vec<u8>,
}

fn page(body: &str) -> Route {
    Route {
        status: "200 OK",
        content_type: "text/html; charset=utf-8",
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
}

fn image() -> Route {
    Route {
        status: "200 OK",
        content_type: "image/svg+xml",
        headers: Vec::new(),
        body: br#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><rect width="1" height="1"/></svg>"#
            .to_vec(),
    }
}

fn redirect(status: &'static str, location: &'static str, hop: &'static str) -> Route {
    Route {
        status,
        content_type: "text/plain",
        headers: vec![("Location", location), ("X-Hop", hop)],
        body: b"moved".to_vec(),
    }
}

/// One request the fixture server saw.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
}

struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    gate: Arc<AtomicBool>,
}

impl Server {
    /// Requests whose path (without the query) is `path`.
    fn requests(&self, path: &str) -> Vec<Seen> {
        self.seen
            .lock()
            .iter()
            .filter(|s| s.target.split('?').next() == Some(path))
            .cloned()
            .collect()
    }

    fn count(&self, path: &str) -> usize {
        self.requests(path).len()
    }

    fn open_gate(&self) {
        self.gate.store(true, Ordering::SeqCst);
    }
}

fn site(port: u16) -> BTreeMap<String, Route> {
    let mut frame_host = String::from(FRAME_HOST_PREFIX);
    frame_host.push_str(&format!("{port}/frame\"></iframe></body></html>"));
    let mut headers = page("<!doctype html><html><body>headers</body></html>");
    headers.headers = vec![
        ("X-Custom", "hello"),
        ("Set-Cookie", "sid=abc123; Path=/"),
        ("Authorization", "Bearer leaked-secret"),
    ];
    let mut missing = page("<!doctype html><html><body>gone</body></html>");
    missing.status = "404 Not Found";
    let mut done = page(DONE_PAGE);
    done.headers = vec![("X-Hop", "done")];
    BTreeMap::from([
        ("/img-page".to_owned(), page(IMG_PAGE)),
        ("/popup".to_owned(), page(POPUP)),
        ("/frame-host".to_owned(), page(&frame_host)),
        ("/frame".to_owned(), page(FRAME)),
        ("/blocked/a.svg".to_owned(), image()),
        ("/allowed/b.svg".to_owned(), image()),
        ("/blocked/popup.svg".to_owned(), image()),
        ("/allowed/popup.svg".to_owned(), image()),
        ("/blocked/frame.svg".to_owned(), image()),
        ("/allowed/frame.svg".to_owned(), image()),
        ("/phone".to_owned(), page(PHONE_PAGE)),
        ("/phone-popup".to_owned(), page(PHONE_POPUP)),
        ("/dom".to_owned(), page(DOM_PAGE)),
        (
            "/virtual".to_owned(),
            page(include_str!("fixtures/virtual_rows.html")),
        ),
        ("/quirks".to_owned(), page(QUIRKS_PAGE)),
        ("/tall".to_owned(), page(TALL_PAGE)),
        ("/huge".to_owned(), page(HUGE_PAGE)),
        ("/late".to_owned(), page(LATE_PAGE)),
        ("/selector-states".to_owned(), page(SELECTOR_PAGE)),
        ("/list".to_owned(), page(LIST_PAGE)),
        ("/headers".to_owned(), headers),
        ("/missing-page".to_owned(), missing),
        ("/form".to_owned(), page(FORM_PAGE)),
        ("/submit".to_owned(), redirect("303 See Other", "/hop", "submit")),
        ("/hop".to_owned(), redirect("302 Found", "/done", "hop")),
        ("/done".to_owned(), done),
    ])
}

async fn serve() -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let routes = Arc::new(site(port));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new(AtomicBool::new(false));
    {
        let (seen, gate) = (Arc::clone(&seen), Arc::clone(&gate));
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(handle(
                    sock,
                    Arc::clone(&routes),
                    Arc::clone(&seen),
                    Arc::clone(&gate),
                ));
            }
        });
    }
    Server { port, seen, gate }
}

async fn handle(
    mut sock: TcpStream,
    routes: Arc<BTreeMap<String, Route>>,
    seen: Arc<Mutex<Vec<Seen>>>,
    gate: Arc<AtomicBool>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.lines();
    let mut request_line = lines.next().unwrap_or_default().split_whitespace();
    let method = request_line.next().unwrap_or("GET").to_owned();
    let target = request_line.next().unwrap_or("/").to_owned();
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    // read the whole body: answering a POST before it arrived would reset the connection
    let length: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < head_end + length {
        match sock.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let path = target.split('?').next().unwrap_or("/").to_owned();
    seen.lock().push(Seen {
        method,
        target,
        headers,
    });
    let (status, content_type, extra, body): (&str, &str, Vec<(&str, &str)>, Vec<u8>) = match path.as_str() {
        "/gate" => {
            let word: &[u8] = if gate.load(Ordering::SeqCst) {
                b"open"
            } else {
                b"closed"
            };
            ("200 OK", "text/plain", Vec::new(), word.to_vec())
        }
        "/report" => ("200 OK", "text/plain", Vec::new(), b"ok".to_vec()),
        other => match routes.get(other) {
            Some(r) => (r.status, r.content_type, r.headers.clone(), r.body.clone()),
            None => ("404 Not Found", "text/plain", Vec::new(), b"not found".to_vec()),
        },
    };
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str("\r\n");
    let _ = sock.write_all(response.as_bytes()).await;
    let _ = sock.write_all(&body).await;
    let _ = sock.shutdown().await;
}

async fn launch(profile: LaunchProfile) -> Option<ChromiumBackend> {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
    cfg.launch_profile = profile;
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

/// A launched browser with one context and a fixture server; `None` when Chromium is absent.
async fn start(profile: LaunchProfile) -> Option<(ChromiumBackend, CdpContext, Server)> {
    let backend = launch(profile).await?;
    let mut config = ContextConfig::new(SessionId::new());
    config.launch_profile = profile;
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

async fn script_error(ctx: &mut CdpContext, script: &str) -> String {
    match ctx
        .page_op(PageOp::EvaluateScript {
            script: script.to_owned(),
        })
        .await
    {
        Err(BrowserError::Script(message)) => message,
        other => panic!("expected a script error, got {other:?}"),
    }
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// How often `method` went out on the shared DevTools connection.
fn sent(ctx: &CdpContext, method: &str) -> usize {
    ctx.cdp_transcript()
        .iter()
        .filter(|m| m.as_str() == method)
        .count()
}

fn click(target: RuntimeLocator) -> BrowserAction {
    BrowserAction::Click {
        target,
        button: PointerButton::Left,
        modifiers: Modifiers::default(),
    }
}

fn png_size(bytes: &[u8]) -> (u32, u32) {
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n", "not a PNG");
    (
        u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
        u32::from_be_bytes(bytes[20..24].try_into().unwrap()),
    )
}

/// `(width, height)` from the first start-of-frame segment of a JPEG.
fn jpeg_size(bytes: &[u8]) -> (u32, u32) {
    assert_eq!(&bytes[..3], &[0xFF, 0xD8, 0xFF], "not a JPEG");
    let mut i = 2;
    while i + 9 < bytes.len() {
        assert_eq!(bytes[i], 0xFF, "malformed JPEG segment");
        let marker = bytes[i + 1];
        let len = usize::from(u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]));
        if matches!(marker, 0xC0..=0xC2) {
            return (
                u32::from(u16::from_be_bytes([bytes[i + 7], bytes[i + 8]])),
                u32::from(u16::from_be_bytes([bytes[i + 5], bytes[i + 6]])),
            );
        }
        i += 2 + len;
    }
    panic!("no start-of-frame segment");
}

/// `(width, height)` in points of the first `/MediaBox` of a PDF.
fn media_box(pdf: &[u8]) -> (f64, f64) {
    let text = String::from_utf8_lossy(pdf);
    let at = text.find("/MediaBox").expect("a MediaBox");
    let rest = &text[at..];
    let open = rest.find('[').unwrap();
    let close = rest.find(']').unwrap();
    let numbers: Vec<f64> = rest[open + 1..close]
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect();
    (numbers[2] - numbers[0], numbers[3] - numbers[1])
}

/// Natural width of every `<img>` of the document once settled; 0 for a blocked one.
const IMAGE_WIDTHS: &str = "Promise.all([...document.images].map(i => new Promise(r => { \
    if (i.complete) { r(i.naturalWidth); } \
    else { i.onload = () => r(i.naturalWidth); i.onerror = () => r(0); } })))";

const PHONE_PROBE: &str = "({ ua: navigator.userAgent, w: innerWidth, h: innerHeight, \
    touch: navigator.maxTouchPoints, language: navigator.language, \
    locale: Intl.DateTimeFormat().resolvedOptions().locale, \
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone, dpr: devicePixelRatio })";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_urls_stops_subresources_in_tabs_and_popups_and_replaces() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    let done = op(&mut ctx, PageOp::BlockUrls(vec!["*/blocked/*".to_owned()])).await;
    assert_eq!(done, PageOpResult::Done);

    goto(&mut ctx, &server, "/img-page").await;
    assert_eq!(eval(&mut ctx, IMAGE_WIDTHS).await, json!([0, 1]));
    assert_eq!(
        server.count("/blocked/a.svg"),
        0,
        "the blocked request never left the browser"
    );
    assert_eq!(server.count("/allowed/b.svg"), 1);

    // a popup opened after the op gets the list from its own session setup
    let before = sent(&ctx, "Network.setBlockedURLs");
    eval(&mut ctx, "window.open('/popup'); 1").await;
    eventually("the popup session to receive the block list", || {
        sent(&ctx, "Network.setBlockedURLs") > before
    })
    .await;
    server.open_gate();
    eventually("the popup's allowed image", || {
        server.count("/allowed/popup.svg") == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        server.count("/blocked/popup.svg"),
        0,
        "the popup's blocked request left the browser"
    );

    // an empty list clears the block
    assert_eq!(
        op(&mut ctx, PageOp::BlockUrls(Vec::new())).await,
        PageOpResult::Done
    );
    goto(&mut ctx, &server, "/img-page").await;
    assert_eq!(eval(&mut ctx, IMAGE_WIDTHS).await, json!([1, 1]));
    assert_eq!(server.count("/blocked/a.svg"), 1);
    assert_eq!(server.count("/allowed/b.svg"), 2);

    // a new list replaces the previous one instead of adding to it
    op(&mut ctx, PageOp::BlockUrls(vec!["*/allowed/*".to_owned()])).await;
    goto(&mut ctx, &server, "/img-page").await;
    assert_eq!(eval(&mut ctx, IMAGE_WIDTHS).await, json!([1, 0]));
    assert_eq!(
        server.count("/blocked/a.svg"),
        2,
        "the first list no longer applies"
    );
    assert_eq!(server.count("/allowed/b.svg"), 2, "the second list does");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_urls_reach_out_of_process_frames() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    op(&mut ctx, PageOp::BlockUrls(vec!["*/blocked/*".to_owned()])).await;
    // `localhost` is another site than `127.0.0.1`: the iframe is its own renderer process
    // and its own CDP session, paused until its setup applied the block list
    goto(&mut ctx, &server, "/frame-host").await;
    eventually("the frame's allowed image", || {
        server.count("/allowed/frame.svg") == 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(server.count("/blocked/frame.svg"), 0);
    assert!(
        sent(&ctx, "Network.setBlockedURLs") >= 2,
        "the frame session received its own block list"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn emulate_mobile_sets_viewport_agent_touch_locale_and_zone_for_tabs_and_popups() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/phone").await;
    let baseline = eval(&mut ctx, PHONE_PROBE).await;
    assert_eq!(baseline["w"], json!(1280));
    assert_eq!(baseline["touch"], json!(0));
    let baseline_language = server.requests("/phone")[0].headers["accept-language"].clone();

    let phone = Emulation {
        viewport: Some((390, 844)),
        mobile: true,
        user_agent: Some(PHONE_UA.to_owned()),
        accept_language: Some("de-DE".to_owned()),
        locale: Some("de-DE".to_owned()),
        timezone: Some("Asia/Tokyo".to_owned()),
        ..Emulation::default()
    };
    assert_eq!(op(&mut ctx, PageOp::Emulate(phone)).await, PageOpResult::Done);
    goto(&mut ctx, &server, "/phone").await;
    let seen = eval(&mut ctx, PHONE_PROBE).await;
    assert_eq!(seen["ua"], json!(PHONE_UA));
    assert_eq!(seen["w"], json!(390));
    assert_eq!(seen["h"], json!(844));
    assert!(seen["touch"].as_u64().unwrap() > 0, "{seen}");
    assert_eq!(seen["locale"], json!("de-DE"));
    assert_eq!(seen["language"], json!("de-DE"));
    assert_eq!(seen["tz"], json!("Asia/Tokyo"));
    assert_eq!(seen["dpr"], json!(1));
    let request = server.requests("/phone").pop().unwrap();
    assert_eq!(request.headers["user-agent"], PHONE_UA);
    assert!(
        request.headers["accept-language"].starts_with("de-DE"),
        "{request:?}"
    );

    // a screenshot viewport override is restored to the emulated viewport
    let PageOpResult::Bytes { bytes, .. } = op(
        &mut ctx,
        PageOp::Screenshot(ShotSpec {
            viewport: Some((300, 200)),
            ..ShotSpec::default()
        }),
    )
    .await
    else {
        panic!("bytes")
    };
    assert_eq!(png_size(&bytes), (300, 200));
    assert_eq!(eval(&mut ctx, "innerWidth").await, json!(390));

    // a popup opened afterwards is emulated by its own session setup
    let before = sent(&ctx, "Emulation.setTouchEmulationEnabled");
    eval(&mut ctx, "window.open('/phone-popup'); 1").await;
    eventually("the popup session to be emulated", || {
        sent(&ctx, "Emulation.setTouchEmulationEnabled") > before
    })
    .await;
    server.open_gate();
    eventually("the popup's report", || server.count("/report") == 1).await;
    let report = server.requests("/report").pop().unwrap();
    let query: BTreeMap<String, String> = url::Url::parse(&format!("http://h{}", report.target))
        .unwrap()
        .query_pairs()
        .into_owned()
        .collect();
    assert_eq!(query["ua"], PHONE_UA);
    assert_eq!(query["w"], "390");
    assert_eq!(query["tz"], "Asia/Tokyo");
    assert!(query["touch"].parse::<u32>().unwrap() > 0, "{query:?}");

    // only `acceptLanguage`: the context's own user agent stays
    let french = Emulation {
        accept_language: Some("fr-FR".to_owned()),
        ..Emulation::default()
    };
    op(&mut ctx, PageOp::Emulate(french)).await;
    goto(&mut ctx, &server, "/phone").await;
    let seen = eval(&mut ctx, PHONE_PROBE).await;
    let request = server.requests("/phone").pop().unwrap();
    assert!(
        request.headers["accept-language"].starts_with("fr-FR"),
        "{request:?}"
    );
    assert!(!request.headers["user-agent"].contains("Crawlx"), "{request:?}");
    assert!(request.headers["user-agent"].contains("Chrome"), "{request:?}");
    assert_eq!(seen["ua"], json!(request.headers["user-agent"]));
    assert_eq!(seen["w"], json!(1280));
    assert_eq!(seen["touch"], json!(0));

    // the default emulation puts everything back
    op(&mut ctx, PageOp::Emulate(Emulation::default())).await;
    goto(&mut ctx, &server, "/phone").await;
    let seen = eval(&mut ctx, PHONE_PROBE).await;
    assert_eq!(seen, baseline);
    let request = server.requests("/phone").pop().unwrap();
    assert_eq!(request.headers["accept-language"], baseline_language);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn html_returns_the_post_script_dom_and_evaluate_script_returns_json_or_errors() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/dom").await;
    let PageOpResult::Html { html, url } = op(&mut ctx, PageOp::Html).await else {
        panic!("html")
    };
    assert!(html.starts_with("<!DOCTYPE html><html lang=\"en\">"), "{html}");
    assert!(html.contains("<div id=\"a\">from script</div>"), "{html}");
    assert!(html.contains("<p id=\"late\">made by script</p>"), "{html}");
    assert_eq!(url, format!("http://127.0.0.1:{}/dom", server.port));

    goto(&mut ctx, &server, "/quirks").await;
    let PageOpResult::Html { html, .. } = op(&mut ctx, PageOp::Html).await else {
        panic!("html")
    };
    assert!(html.starts_with("<html>"), "no doctype, no prefix: {html}");
    assert!(html.contains("no doctype"));

    goto(&mut ctx, &server, "/dom").await;
    assert_eq!(eval(&mut ctx, "1 + 1").await, json!(2));
    assert_eq!(
        eval(&mut ctx, "({ a: [1, 'x', null], b: { c: true } })").await,
        json!({ "a": [1, "x", null], "b": { "c": true } })
    );
    assert_eq!(
        eval(&mut ctx, "Promise.resolve('settled')").await,
        json!("settled")
    );
    assert_eq!(
        eval(&mut ctx, "new Promise(r => setTimeout(() => r(42), 50))").await,
        json!(42)
    );
    assert_eq!(eval(&mut ctx, "undefined").await, Value::Null);
    // the main world: the page's own globals are visible and a write persists
    assert_eq!(eval(&mut ctx, "window.marker").await, json!(41));
    assert_eq!(
        eval(&mut ctx, "window.marker = 42; window.marker").await,
        json!(42)
    );
    assert_eq!(eval(&mut ctx, "document.title").await, json!("Dom"));

    assert_eq!(
        script_error(&mut ctx, "(() => { throw new Error('boom'); })()").await,
        "Error: boom"
    );
    assert_eq!(script_error(&mut ctx, "throw 'plain'").await, "plain");
    assert_eq!(
        script_error(&mut ctx, "Promise.reject(new Error('nope'))").await,
        "Error: nope"
    );
    let syntax = script_error(&mut ctx, "foo bar").await;
    assert!(syntax.starts_with("SyntaxError"), "{syntax}");
    // the context survives a failed script
    assert_eq!(eval(&mut ctx, "window.marker").await, json!(42));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn screenshot_captures_png_jpeg_full_page_and_viewport_overrides() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/tall").await;
    let shot = |spec: ShotSpec| PageOp::Screenshot(spec);
    let PageOpResult::Bytes { bytes, content_type } = op(&mut ctx, shot(ShotSpec::default())).await else {
        panic!("bytes")
    };
    assert_eq!(content_type, "image/png");
    assert_eq!(png_size(&bytes), (1280, 800), "the viewport");

    let PageOpResult::Bytes { bytes, content_type } = op(
        &mut ctx,
        shot(ShotSpec {
            full_page: true,
            ..ShotSpec::default()
        }),
    )
    .await
    else {
        panic!("bytes")
    };
    assert_eq!(content_type, "image/png");
    assert_eq!(png_size(&bytes), (1280, 3000), "the whole page");

    let PageOpResult::Bytes { bytes, content_type } = op(
        &mut ctx,
        shot(ShotSpec {
            quality: Some(60),
            ..ShotSpec::default()
        }),
    )
    .await
    else {
        panic!("bytes")
    };
    assert_eq!(content_type, "image/jpeg");
    assert_eq!(jpeg_size(&bytes), (1280, 800));

    let PageOpResult::Bytes { bytes, .. } = op(
        &mut ctx,
        shot(ShotSpec {
            full_page: true,
            quality: Some(60),
            viewport: Some((640, 480)),
        }),
    )
    .await
    else {
        panic!("bytes")
    };
    assert_eq!(
        jpeg_size(&bytes),
        (640, 3000),
        "a full-page JPEG at the overridden width"
    );

    // the override applied to that capture only
    let PageOpResult::Bytes { bytes, .. } = op(
        &mut ctx,
        shot(ShotSpec {
            viewport: Some((500, 300)),
            ..ShotSpec::default()
        }),
    )
    .await
    else {
        panic!("bytes")
    };
    assert_eq!(png_size(&bytes), (500, 300));
    assert_eq!(
        eval(&mut ctx, "[innerWidth, innerHeight]").await,
        json!([1280, 800])
    );
    let PageOpResult::Bytes { bytes, .. } = op(&mut ctx, shot(ShotSpec::default())).await else {
        panic!("bytes")
    };
    assert_eq!(png_size(&bytes), (1280, 800));

    // a page taller than a texture is capped
    goto(&mut ctx, &server, "/huge").await;
    let PageOpResult::Bytes { bytes, .. } = op(
        &mut ctx,
        shot(ShotSpec {
            full_page: true,
            ..ShotSpec::default()
        }),
    )
    .await
    else {
        panic!("bytes")
    };
    assert_eq!(png_size(&bytes), (1280, 16_384));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn print_to_pdf_honours_format_orientation_and_rejects_unknown_ones() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/dom").await;
    let pdf = |format: Option<&str>, landscape: bool, scale: f32| {
        PageOp::PrintToPdf(PdfSpec {
            format: format.map(str::to_owned),
            landscape,
            scale,
        })
    };
    let PageOpResult::Bytes { bytes, content_type } = op(&mut ctx, pdf(None, false, 1.0)).await else {
        panic!("bytes")
    };
    assert_eq!(content_type, "application/pdf");
    assert!(bytes.starts_with(b"%PDF"));
    let (w, h) = media_box(&bytes);
    assert!(
        (w - 612.0).abs() < 1.0 && (h - 792.0).abs() < 1.0,
        "Letter: {w} x {h}"
    );

    let PageOpResult::Bytes { bytes, .. } = op(&mut ctx, pdf(Some("A4"), false, 0.8)).await else {
        panic!("bytes")
    };
    assert!(bytes.starts_with(b"%PDF"));
    let (w, h) = media_box(&bytes);
    assert!(
        (w - 595.0).abs() < 1.5 && (h - 842.0).abs() < 1.5,
        "A4: {w} x {h}"
    );

    let PageOpResult::Bytes { bytes, .. } = op(&mut ctx, pdf(Some("legal"), true, 1.0)).await else {
        panic!("bytes")
    };
    let (w, h) = media_box(&bytes);
    assert!(
        (w - 1008.0).abs() < 1.0 && (h - 612.0).abs() < 1.0,
        "Legal landscape: {w} x {h}"
    );

    for bad in [
        pdf(Some("A7"), false, 1.0),
        pdf(None, false, 5.0),
        pdf(None, false, 0.0),
    ] {
        let err = ctx.page_op(bad).await.unwrap_err();
        assert!(matches!(err, BrowserError::Unsupported(_)), "{err:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wait_for_selector_finds_late_elements_and_times_out_cleanly() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/late").await;
    let wait = |selector: &str, timeout_ms: u32| PageOp::WaitForSelector {
        selector: selector.to_owned(),
        state: SelectorState::Attached,
        timeout_ms,
    };
    assert_eq!(
        op(&mut ctx, wait("h1", 0)).await,
        PageOpResult::Found(true),
        "already there"
    );
    assert_eq!(
        op(&mut ctx, wait("#late", 0)).await,
        PageOpResult::Found(false),
        "not inserted yet"
    );
    let started = Instant::now();
    assert_eq!(
        op(&mut ctx, wait("#late", 10_000)).await,
        PageOpResult::Found(true)
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "returned at the first probe that saw it"
    );

    let started = Instant::now();
    assert_eq!(
        op(&mut ctx, wait("#never", 300)).await,
        PageOpResult::Found(false)
    );
    let waited = started.elapsed();
    assert!(waited >= Duration::from_millis(300), "{waited:?}");
    assert!(waited < Duration::from_secs(5), "{waited:?}");

    // a selector the browser cannot parse is an error, not a timeout
    let err = ctx.page_op(wait("div[", 500)).await.unwrap_err();
    assert!(matches!(err, BrowserError::Script(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn selector_wait_states_use_first_match_layout_visibility_and_detachment() {
    let Some((backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/selector-states").await;
    let wait = |selector: &str, state, timeout_ms| PageOp::WaitForSelector {
        selector: selector.to_owned(),
        state,
        timeout_ms,
    };
    for selector in [
        "#display-none",
        "#visibility-hidden",
        "#visibility-collapse",
        "#hidden-parent",
        "#zero-width",
        "#zero-height",
        ".first",
    ] {
        for (state, expected) in [
            (SelectorState::Attached, true),
            (SelectorState::Visible, false),
            (SelectorState::Hidden, true),
            (SelectorState::Detached, false),
        ] {
            assert_eq!(
                op(&mut ctx, wait(selector, state, 0)).await,
                PageOpResult::Found(expected),
                "{selector}: {state:?}"
            );
        }
    }
    for selector in ["#visible", "#transparent", "#offscreen"] {
        assert_eq!(
            op(&mut ctx, wait(selector, SelectorState::Visible, 0)).await,
            PageOpResult::Found(true),
            "{selector} is visible under the narrow contract"
        );
        assert_eq!(
            op(&mut ctx, wait(selector, SelectorState::Hidden, 0)).await,
            PageOpResult::Found(false)
        );
    }
    for (state, expected) in [
        (SelectorState::Attached, false),
        (SelectorState::Visible, false),
        (SelectorState::Hidden, true),
        (SelectorState::Detached, true),
    ] {
        assert_eq!(
            op(&mut ctx, wait("#missing", state, 0)).await,
            PageOpResult::Found(expected)
        );
        let error = ctx.page_op(wait("div[", state, 300)).await.unwrap_err();
        assert!(matches!(error, BrowserError::Script(_)), "{state:?}: {error:?}");
    }
    // The selector remains JSON data, including quotes and script-looking text.
    assert_eq!(
        op(
            &mut ctx,
            wait(
                "[id=\"'); throw new Error('injected'); //\"]",
                SelectorState::Hidden,
                0
            )
        )
        .await,
        PageOpResult::Found(true)
    );
    for (selector, state, script) in [
        (
            "#display-none",
            SelectorState::Visible,
            "setTimeout(() => { document.querySelector('#display-none').style.cssText = 'width:20px;height:20px'; }, 200)",
        ),
        (
            "#visible",
            SelectorState::Hidden,
            "setTimeout(() => { document.querySelector('#visible').style.display = 'none'; }, 200)",
        ),
        (
            "#visible",
            SelectorState::Detached,
            "setTimeout(() => { document.querySelector('#visible').remove(); }, 200)",
        ),
    ] {
        eval(&mut ctx, script).await;
        assert_eq!(
            op(&mut ctx, wait(selector, state, 3000)).await,
            PageOpResult::Found(true),
            "{selector}: {state:?} transition"
        );
    }
    let started = Instant::now();
    assert_eq!(
        op(&mut ctx, wait("#visibility-hidden", SelectorState::Visible, 300)).await,
        PageOpResult::Found(false)
    );
    assert!(started.elapsed() >= Duration::from_millis(300));
    assert!(started.elapsed() < Duration::from_secs(5));
    Box::new(ctx).close().await.unwrap();
    backend.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolve_all_returns_ordered_locators_that_perform_can_use() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/list").await;
    let resolve = |selector: &str, limit: u32| PageOp::ResolveAll {
        selector: selector.to_owned(),
        limit,
    };
    let PageOpResult::Locators(found) = op(&mut ctx, resolve(".b", 100)).await else {
        panic!("locators")
    };
    assert_eq!(found.len(), 5);
    let epoch = ctx.current_epoch();
    let mut ids: Vec<i64> = found.iter().map(|l| l.backend_node_id.0).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 5, "five distinct elements");
    for l in &found {
        assert_eq!(l.tab, found[0].tab);
        assert_eq!(l.frame, found[0].frame);
        assert_eq!(l.epoch.navigation_seq, epoch.navigation_seq);
        assert_eq!(l.epoch.document_seq, epoch.document_seq);
        assert!(l.object_id.is_none() && l.ax_node_id.is_none());
    }

    // document order: clicking them in order reads "clicked 1" .. "clicked 5"
    for (i, locator) in found.iter().enumerate() {
        ctx.perform(click(locator.clone())).await.unwrap();
        assert_eq!(
            eval(&mut ctx, "document.getElementById('out').textContent").await,
            json!(format!("clicked {}", i + 1))
        );
    }

    let PageOpResult::Locators(two) = op(&mut ctx, resolve(".b", 2)).await else {
        panic!("locators")
    };
    assert_eq!(
        two.iter().map(|l| l.backend_node_id).collect::<Vec<_>>(),
        found[..2].iter().map(|l| l.backend_node_id).collect::<Vec<_>>(),
        "the limit keeps the first matches"
    );
    for empty in [
        resolve(".missing", 10),
        resolve("li[", 10),
        resolve(".b", 0),
        resolve("  ", 10),
    ] {
        assert_eq!(op(&mut ctx, empty).await, PageOpResult::Locators(Vec::new()));
    }

    // a navigation makes the old locators stale
    goto(&mut ctx, &server, "/dom").await;
    let err = ctx.perform(click(found[0].clone())).await.unwrap_err();
    assert!(matches!(err, BrowserError::StaleLocator(_)), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn document_response_reports_status_headers_and_the_final_hop() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    let nothing = PageOpResult::Response {
        status: None,
        headers: Vec::new(),
        content_type: None,
    };
    assert_eq!(
        op(&mut ctx, PageOp::DocumentResponse).await,
        nothing,
        "about:blank"
    );

    goto(&mut ctx, &server, "/headers").await;
    let PageOpResult::Response {
        status,
        headers,
        content_type,
    } = op(&mut ctx, PageOp::DocumentResponse).await
    else {
        panic!("response")
    };
    assert_eq!(status, Some(200));
    assert_eq!(content_type.as_deref(), Some("text/html"));
    assert!(
        headers.contains(&("x-custom".to_owned(), "hello".to_owned())),
        "{headers:?}"
    );
    assert!(
        headers.iter().all(|(name, _)| *name == name.to_ascii_lowercase()),
        "{headers:?}"
    );
    for (name, value) in &headers {
        if name == "set-cookie" || name == "authorization" {
            assert_eq!(value, REDACTED, "{name}");
        }
    }
    assert!(!format!("{headers:?}").contains("leaked-secret"));
    assert!(!format!("{headers:?}").contains("abc123"));

    goto(&mut ctx, &server, "/missing-page").await;
    let PageOpResult::Response { status, .. } = op(&mut ctx, PageOp::DocumentResponse).await else {
        panic!("response")
    };
    assert_eq!(status, Some(404));

    // a POST answered by a 303 and a 302 reports the response of the last hop
    goto(&mut ctx, &server, "/form").await;
    assert_eq!(
        eval(&mut ctx, "document.getElementById('f').submit()").await,
        Value::Null
    );
    assert_eq!(
        op(
            &mut ctx,
            PageOp::WaitForSelector {
                selector: "#final".to_owned(),
                state: SelectorState::Attached,
                timeout_ms: 10_000,
            }
        )
        .await,
        PageOpResult::Found(true)
    );
    let PageOpResult::Response {
        status,
        headers,
        content_type,
    } = op(&mut ctx, PageOp::DocumentResponse).await
    else {
        panic!("response")
    };
    assert_eq!(status, Some(200));
    assert_eq!(content_type.as_deref(), Some("text/html"));
    assert!(
        headers.contains(&("x-hop".to_owned(), "done".to_owned())),
        "{headers:?}"
    );
    assert_eq!(server.requests("/submit")[0].method, "POST");
    assert_eq!(server.requests("/hop")[0].method, "GET");
    assert_eq!(eval(&mut ctx, "location.pathname").await, json!("/done"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_ops_work_under_the_stealth_profile() {
    let Some((_backend, mut ctx, server)) = start(LaunchProfile::Stealth).await else {
        return;
    };
    goto(&mut ctx, &server, "/dom").await;
    let PageOpResult::Html { html, url } = op(&mut ctx, PageOp::Html).await else {
        panic!("html")
    };
    assert!(html.starts_with("<!DOCTYPE html>"), "{html}");
    assert!(html.contains("made by script"));
    assert!(url.ends_with("/dom"));
    assert_eq!(eval(&mut ctx, "window.marker").await, json!(41));
    assert_eq!(
        op(
            &mut ctx,
            PageOp::WaitForSelector {
                selector: "#late".to_owned(),
                state: SelectorState::Attached,
                timeout_ms: 1000,
            }
        )
        .await,
        PageOpResult::Found(true)
    );
    let PageOpResult::Locators(found) = op(
        &mut ctx,
        PageOp::ResolveAll {
            selector: "p".to_owned(),
            limit: 5,
        },
    )
    .await
    else {
        panic!("locators")
    };
    assert_eq!(found.len(), 1);
    let PageOpResult::Response { status, .. } = op(&mut ctx, PageOp::DocumentResponse).await else {
        panic!("response")
    };
    assert_eq!(status, Some(200));
    op(&mut ctx, PageOp::BlockUrls(vec!["*/never/*".to_owned()])).await;
    op(&mut ctx, PageOp::Emulate(Emulation::default())).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_op_fails_cleanly_once_the_browser_is_gone() {
    let Some((backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/dom").await;
    backend.close().await.unwrap();
    // the pump marks the context closed once the DevTools connection drops
    let deadline = Instant::now() + Duration::from_secs(15);
    while ctx.page_op(PageOp::DocumentResponse).await.is_ok() {
        assert!(
            Instant::now() < deadline,
            "the context never noticed the lost browser"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let ops = [
        PageOp::Emulate(Emulation::default()),
        PageOp::BlockUrls(vec!["*/x/*".to_owned()]),
        PageOp::DocumentResponse,
        PageOp::EvaluateScript {
            script: "1".to_owned(),
        },
        PageOp::Html,
        PageOp::Screenshot(ShotSpec::default()),
        PageOp::PrintToPdf(PdfSpec {
            format: None,
            landscape: false,
            scale: 1.0,
        }),
        PageOp::WaitForSelector {
            selector: "h1".to_owned(),
            state: SelectorState::Attached,
            timeout_ms: 100,
        },
        PageOp::ResolveAll {
            selector: "h1".to_owned(),
            limit: 1,
        },
    ];
    for op in ops {
        let name = op.name();
        let outcome = tokio::time::timeout(Duration::from_secs(40), ctx.page_op(op))
            .await
            .unwrap_or_else(|_| panic!("{name} is not bounded"));
        let err = outcome.unwrap_err();
        assert!(matches!(err, BrowserError::TargetClosed), "{name}: {err:?}");
    }
}

fn virtual_spec() -> crawlx_core::dom_ops::VirtualRowsSpec {
    serde_json::from_value(json!({
        "container": "#virtual", "rows": ".row", "maxSteps": 2, "settleMs": 50,
        "maxRowsPerWindow": 10, "maxRows": 100, "maxBytes": 65536
    }))
    .unwrap()
}

async fn virtual_step(ctx: &mut CdpContext) {
    let PageOpResult::Locators(mut targets) = op(ctx, PageOp::VirtualRowsTarget).await else {
        panic!("pinned container locator");
    };
    ctx.perform(BrowserAction::Scroll {
        container: targets.pop(),
        delta: crawlx_core::action::ScrollDelta { dx: 0.0, dy: 100.0 },
    })
    .await
    .unwrap();
    let settled = ctx
        .settle(crawlx_core::observation::QuiescencePolicy {
            mutation_idle_window_ms: 50,
            network_idle_window_ms: 50,
            navigation_settled: true,
            hard_timeout_ms: 1000,
            fixed_wait_ms: 0,
        })
        .await
        .unwrap();
    assert!(!settled.settle_timeout);
}

#[tokio::test]
async fn virtual_rows_capture_replaced_ten_row_windows_and_restore_nonzero_position() {
    use crawlx_core::dom_ops::{VirtualRowsReport, VirtualRowsRestoration};
    let Some((backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/virtual").await;
    let original = eval(&mut ctx, "document.querySelector('#virtual').scrollTop").await;
    assert_eq!(original, json!(50));
    let PageOpResult::VirtualRows(initial) = op(&mut ctx, PageOp::BeginVirtualRows(virtual_spec())).await
    else {
        panic!("initial window");
    };
    assert_eq!(initial.rows.len(), 10);
    let mut report = VirtualRowsReport::new(initial, 65536);
    for _ in 0..2 {
        virtual_step(&mut ctx).await;
        let PageOpResult::VirtualRows(window) = op(&mut ctx, PageOp::ReadVirtualRows).await else {
            panic!("settled window");
        };
        assert_eq!(window.rows.len(), 10);
        assert_eq!(window.epoch.document_seq, report.windows[0].epoch.document_seq);
        assert_eq!(
            window.epoch.navigation_seq,
            report.windows[0].epoch.navigation_seq
        );
        report.windows.push(window);
    }
    assert!(report.windows[2].epoch.mutation_seq > report.windows[0].epoch.mutation_seq);
    report
        .project_rows(|row| Ok::<_, std::convert::Infallible>(row.into()))
        .unwrap();
    let rows: Vec<&str> = report
        .windows
        .iter()
        .flat_map(|window| &window.rows)
        .map(String::as_str)
        .collect();
    assert_eq!(rows.len(), 20);
    assert_eq!(
        &rows[..7],
        ["C++", "C#", "naïve", "naive", "東京", "东 京", "pré\n  texte"]
    );
    assert_eq!(rows.last(), Some(&"row 19"));
    assert_eq!(
        op(&mut ctx, PageOp::RestoreVirtualRows).await,
        PageOpResult::VirtualRowsRestored(VirtualRowsRestoration::Restored)
    );
    assert_eq!(
        eval(&mut ctx, "document.querySelector('#virtual').scrollTop").await,
        original
    );
    assert_eq!(
        eval(&mut ctx, "document.querySelectorAll('#virtual .row').length").await,
        json!(10),
        "collector never merges historical rows into live DOM"
    );
    Box::new(ctx).close().await.unwrap();
    backend.shutdown().await;
}

#[tokio::test]
async fn virtual_rows_reject_selectors_cap_before_transfer_and_expose_replacement() {
    use crawlx_core::dom_ops::VirtualRowsRestoration;
    let Some((backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/virtual").await;
    for selector in ["#missing", "div", "div["] {
        let mut spec = virtual_spec();
        spec.container = selector.into();
        assert!(
            ctx.page_op(PageOp::BeginVirtualRows(spec)).await.is_err(),
            "{selector}"
        );
    }
    let mut spec = virtual_spec();
    spec.rows = "[".into();
    assert!(ctx.page_op(PageOp::BeginVirtualRows(spec)).await.is_err());
    let mut spec = virtual_spec();
    spec.rows = ".missing".into();
    assert!(ctx.page_op(PageOp::BeginVirtualRows(spec)).await.is_err());
    op(&mut ctx, PageOp::RestoreVirtualRows).await;
    let mut spec = virtual_spec();
    spec.max_rows_per_window = 9;
    let PageOpResult::VirtualRows(capped) = op(&mut ctx, PageOp::BeginVirtualRows(spec)).await else {
        panic!("cap");
    };
    assert!(capped.capped);
    assert_eq!(capped.rows.len(), 9);
    op(&mut ctx, PageOp::RestoreVirtualRows).await;
    eval(
        &mut ctx,
        "document.querySelector('.row').textContent = 'é'.repeat(100000)",
    )
    .await;
    let mut spec = virtual_spec();
    spec.max_bytes = 1024;
    let PageOpResult::VirtualRows(capped) = op(&mut ctx, PageOp::BeginVirtualRows(spec)).await else {
        panic!("byte cap");
    };
    assert!(capped.capped && capped.rows.is_empty());
    assert!(capped.transport_bytes <= 1024);
    op(&mut ctx, PageOp::RestoreVirtualRows).await;
    goto(&mut ctx, &server, "/virtual").await;
    op(&mut ctx, PageOp::BeginVirtualRows(virtual_spec())).await;
    eval(
        &mut ctx,
        "document.querySelector('#virtual').replaceWith(document.querySelector('#virtual').cloneNode(true))",
    )
    .await;
    assert!(ctx.page_op(PageOp::VirtualRowsTarget).await.is_err());
    assert!(ctx.page_op(PageOp::ReadVirtualRows).await.is_err());
    assert_eq!(
        op(&mut ctx, PageOp::RestoreVirtualRows).await,
        PageOpResult::VirtualRowsRestored(VirtualRowsRestoration::Replaced)
    );
    goto(&mut ctx, &server, "/virtual").await;
    op(&mut ctx, PageOp::BeginVirtualRows(virtual_spec())).await;
    goto(&mut ctx, &server, "/dom").await;
    assert!(ctx.page_op(PageOp::ReadVirtualRows).await.is_err());
    assert_eq!(
        op(&mut ctx, PageOp::RestoreVirtualRows).await,
        PageOpResult::VirtualRowsRestored(VirtualRowsRestoration::Replaced)
    );
    // Closing with an active collection uses the same cleanup path as a cancelled actor.
    goto(&mut ctx, &server, "/virtual").await;
    op(&mut ctx, PageOp::BeginVirtualRows(virtual_spec())).await;
    virtual_step(&mut ctx).await;
    Box::new(ctx).close().await.unwrap();
    backend.shutdown().await;
}

#[tokio::test]
async fn virtual_rows_stale_spa_epoch_does_not_restore_into_new_view() {
    use crawlx_core::dom_ops::VirtualRowsRestoration;
    let Some((backend, mut ctx, server)) = start(LaunchProfile::Standard).await else {
        return;
    };
    goto(&mut ctx, &server, "/virtual").await;
    op(&mut ctx, PageOp::BeginVirtualRows(virtual_spec())).await;
    virtual_step(&mut ctx).await;
    eval(&mut ctx, "history.pushState({}, '', '/virtual?new-spa-view=1'); document.querySelector('#virtual').scrollTop = 350;").await;
    // Synchronize the same-document CDP event and its mutation counter before cleanup.
    assert!(ctx.page_op(PageOp::ReadVirtualRows).await.is_err());
    assert_eq!(
        op(&mut ctx, PageOp::RestoreVirtualRows).await,
        PageOpResult::VirtualRowsRestored(VirtualRowsRestoration::Replaced)
    );
    assert_eq!(
        eval(&mut ctx, "document.querySelector('#virtual').scrollTop").await,
        json!(350),
        "stale cleanup must not scroll the reused container in a new SPA view"
    );
    Box::new(ctx).close().await.unwrap();
    backend.shutdown().await;
}
