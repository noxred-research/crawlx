//! Request controls of the browser plane: `fetch.extraHeaders`, `fetch.cookies`,
//! `fetch.userAgent` and `fetch.skipTlsVerification` reach every request of a page, of its
//! same-site frames and of its out-of-process (cross-site) frames. Skipped (with a message)
//! when no Chromium executable is found; set `CRAWLX_CHROMIUM_PATH` to point at one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserContext, ContextConfig};
use crawlx_core::config::Fetch;
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{ObservationSpec, QuiescencePolicy};
use crawlx_core::request_controls::{FetchCookie, RequestControls};
use crawlx_core::traffic::REDACTED_PLACEHOLDER;
use crawlx_core::url::CanonicalUrl;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;

const KEY: &str = "k-browser-1234567";
const SID: &str = "s-browser-7654321";
const LOCAL_SID: &str = "l-browser-1357911";
const UA: &str = "crawlx-browser-test-ua/9";

/// One request the server received.
#[derive(Clone, Debug)]
struct Seen {
    host: String,
    path: String,
    user_agent: Option<String>,
    key: Option<String>,
    cookie: Option<String>,
}

struct Server {
    port: u16,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
}

impl Server {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn of(&self, path: &str) -> Vec<Seen> {
        self.seen().into_iter().filter(|s| s.path == path).collect()
    }
}

/// Page, frames and subresources served on one loopback port. `127.0.0.1` and `localhost`
/// are different sites, so a frame loaded through the other name is an out-of-process iframe.
fn response(path: &str, port: u16) -> (&'static str, &'static str, String, Option<&'static str>) {
    match path {
        "/" => (
            "200 OK",
            "text/html; charset=utf-8",
            format!(
                r#"<!doctype html><html><head><title>Controls</title></head><body><h1>Controls</h1>
<iframe id="same" src="/same"></iframe>
<iframe id="cross" src="http://localhost:{port}/cross"></iframe>
<img src="http://localhost:{port}/pixel.png">
<script>fetch('/api/data').then(function(r){{return r.text();}}).catch(function(){{}});fetch('/echo').catch(function(){{}});</script>
</body></html>"#
            ),
            None,
        ),
        "/same" => ("200 OK", "text/html", "<p>same-site frame</p>".to_owned(), None),
        "/cross" => (
            "200 OK",
            "text/html",
            "<p>cross-site frame</p><img src=\"/cross-sub.png\">".to_owned(),
            None,
        ),
        "/api/data" => ("200 OK", "application/json", "{}".to_owned(), None),
        // a server that echoes a request header back must not leak it through captured traffic
        "/echo" => ("200 OK", "text/plain", "ok".to_owned(), Some("x-echo")),
        "/pixel.png" | "/cross-sub.png" => ("200 OK", "image/png", String::new(), None),
        _ => ("404 Not Found", "text/plain", "not found".to_owned(), None),
    }
}

async fn handle<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    port: u16,
    seen: Arc<std::sync::Mutex<Vec<Seen>>>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let target = lines
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    let path = target.split('?').next().unwrap_or("/").to_owned();
    let header = |name: &str| {
        head.split("\r\n").skip(1).find_map(|l| {
            let (n, v) = l.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| v.trim().to_owned())
        })
    };
    seen.lock().unwrap().push(Seen {
        host: header("host")
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_owned(),
        path: path.clone(),
        user_agent: header("user-agent"),
        key: header("x-api-key"),
        cookie: header("cookie"),
    });
    let (status, ctype, body, echo) = response(&path, port);
    let echo_line = echo.map_or_else(String::new, |h| format!("{h}: seen {KEY}\r\n"));
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\n{echo_line}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

async fn serve(tls: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let acceptor = tls.then(|| {
        let certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(include_bytes!("fixtures/selfsigned.crt"))
                .collect::<Result<_, _>>()
                .unwrap();
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("fixtures/selfsigned.key")).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    });
    let recorded = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let seen = Arc::clone(&recorded);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                match acceptor {
                    Some(a) => {
                        if let Ok(stream) = a.accept(tcp).await {
                            handle(stream, port, seen).await;
                        }
                    }
                    None => handle(tcp, port, seen).await,
                }
            });
        }
    });
    Server { port, seen }
}

async fn launch() -> Option<ChromiumBackend> {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
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

fn canonical(scheme: &str, port: u16, path: &str) -> CanonicalUrl {
    let base = url::Url::parse(&format!("{scheme}://127.0.0.1:{port}/")).unwrap();
    Canonicalizer::canonicalize(path, &base, &CanonicalizeOptions::default()).unwrap()
}

fn context_with(controls: RequestControls) -> ContextConfig {
    let mut c = ContextConfig::new(SessionId::new());
    c.request_controls = controls;
    c
}

async fn controls(edit: impl FnOnce(&mut Fetch)) -> RequestControls {
    let mut fetch = Fetch::default();
    edit(&mut fetch);
    RequestControls::resolve(&fetch, "127.0.0.1", None).await.unwrap()
}

/// Header, cookie and User-Agent on the page, a same-site frame, a cross-site frame (its own
/// renderer and CDP session) and their subresources; cookies only where domain and path match.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headers_cookies_and_user_agent_reach_page_frames_and_out_of_process_frames() {
    let Some(backend) = launch().await else {
        return;
    };
    let server = serve(false).await;
    let ctl = controls(|f| {
        f.extra_headers.insert("x-api-key", KEY);
        f.user_agent = Some(UA.to_owned());
        // scoped to the seed's domain by default (127.0.0.1), to `/` ...
        f.cookies.push(FetchCookie::new("sid", SID));
        // ... and to the other site name, which only the cross-site frame is loaded through
        f.cookies.push(FetchCookie {
            domain: Some("localhost".to_owned()),
            ..FetchCookie::new("lsid", LOCAL_SID)
        });
        // a path that is never requested
        f.cookies.push(FetchCookie {
            path: Some("/never".to_owned()),
            ..FetchCookie::new("hidden", "h-123456")
        });
    })
    .await;
    let mut ctx = backend.new_cdp_context(context_with(ctl)).await.unwrap();
    ctx.navigate(&canonical("http", server.port, "/")).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    // observing waits for the auto-attached out-of-process frame to finish its setup
    let bundle = ctx.observe(ObservationSpec::default()).await.unwrap();
    let cross = bundle
        .frames
        .iter()
        .find(|f| f.url.contains("localhost"))
        .unwrap_or_else(|| panic!("cross-site frame missing from {:?}", bundle.frames));
    assert!(!cross.same_origin, "{cross:?}");
    assert_eq!(
        ctx.evaluate_isolated("navigator.userAgent").await.unwrap(),
        UA,
        "the page's own user agent"
    );

    for path in [
        "/",
        "/same",
        "/cross",
        "/pixel.png",
        "/cross-sub.png",
        "/api/data",
        "/echo",
    ] {
        let hits = server.of(path);
        assert!(
            !hits.is_empty(),
            "{path} was never requested; saw {:?}",
            server.seen()
        );
        for s in &hits {
            assert_eq!(s.user_agent.as_deref(), Some(UA), "{path}: {s:?}");
            assert_eq!(s.key.as_deref(), Some(KEY), "{path}: {s:?}");
        }
    }
    // cookies follow their own domain: the seed's cookie reaches 127.0.0.1, the localhost
    // cookie only localhost (a cross-site frame in a Lax-by-default browser may or may not
    // carry it, but it never carries the seed's), and a cookie for another path never
    let on_seed: Vec<Seen> = server
        .seen()
        .into_iter()
        .filter(|s| s.host == "127.0.0.1")
        .collect();
    assert!(on_seed.len() >= 3, "{:?}", server.seen());
    for s in &on_seed {
        let cookie = s.cookie.as_deref().unwrap_or_default();
        assert!(cookie.contains(&format!("sid={SID}")), "{s:?}");
        assert!(!cookie.contains("lsid") && !cookie.contains("hidden"), "{s:?}");
    }
    let same = &server.of("/same")[0];
    assert!(
        same.cookie
            .as_deref()
            .unwrap_or_default()
            .contains(&format!("sid={SID}")),
        "{same:?}"
    );
    for s in server.seen().into_iter().filter(|s| s.host == "localhost") {
        let cookie = s.cookie.unwrap_or_default();
        assert!(
            !cookie.contains(&format!("sid={SID}")) && !cookie.contains("hidden"),
            "{cookie}"
        );
    }
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

/// Captured traffic names the configured header but never prints its value, nor a cookie
/// value, nor a response header that echoes one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn captured_traffic_never_carries_a_configured_value() {
    let Some(backend) = launch().await else {
        return;
    };
    let server = serve(false).await;
    let ctl = controls(|f| {
        f.extra_headers.insert("x-api-key", KEY);
        f.cookies.push(FetchCookie::new("sid", SID));
    })
    .await;
    let mut ctx = backend.new_cdp_context(context_with(ctl)).await.unwrap();
    ctx.navigate(&canonical("http", server.port, "/")).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
    let _ = ctx.observe(ObservationSpec::default()).await.unwrap();
    let traffic = ctx.drain_traffic();
    assert!(!traffic.is_empty());
    let text = format!("{traffic:?}");
    assert!(!text.contains(KEY) && !text.contains(SID), "{text}");
    let api = traffic
        .iter()
        .find(|t| t.url.ends_with("/api/data"))
        .unwrap_or_else(|| panic!("no /api/data in {text}"));
    let value = |hs: &[(String, String)], name: &str| {
        hs.iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        value(&api.request_headers, "x-api-key").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    let echo = traffic.iter().find(|t| t.url.ends_with("/echo")).unwrap();
    assert_eq!(
        value(&echo.response_headers, "x-echo").as_deref(),
        Some(REDACTED_PLACEHOLDER)
    );
    // the server did receive the real values
    assert_eq!(server.of("/api/data")[0].key.as_deref(), Some(KEY));
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

/// Certificate errors fail a navigation unless `fetch.skipTlsVerification` is set, and the
/// setting stays with the context that asked for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn skip_tls_verification_applies_to_its_context_only() {
    let Some(backend) = launch().await else {
        return;
    };
    let server = serve(true).await;
    let target = canonical("https", server.port, "/");

    let mut strict = backend
        .new_cdp_context(context_with(controls(|_| {}).await))
        .await
        .unwrap();
    let err = strict.navigate(&target).await;
    assert!(
        err.is_err(),
        "a self-signed certificate must fail verification: {err:?}"
    );
    assert!(server.seen().is_empty(), "{:?}", server.seen());

    let lax_controls = controls(|f| {
        f.skip_tls_verification = true;
        f.user_agent = Some(UA.to_owned());
    })
    .await;
    let mut lax = backend.new_cdp_context(context_with(lax_controls)).await.unwrap();
    let nav = lax.navigate(&target).await.unwrap();
    assert_eq!(nav.status, Some(200));
    let root = server.of("/");
    assert_eq!(root.len(), 1, "{:?}", server.seen());
    assert_eq!(root[0].user_agent.as_deref(), Some(UA));

    // a context created afterwards without the flag still verifies
    let mut again = backend
        .new_cdp_context(context_with(controls(|_| {}).await))
        .await
        .unwrap();
    assert!(again.navigate(&target).await.is_err());
    for ctx in [strict, lax, again] {
        Box::new(ctx).close().await.unwrap();
    }
    backend.close().await.unwrap();
}
