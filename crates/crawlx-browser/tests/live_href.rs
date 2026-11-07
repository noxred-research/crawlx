//! `LiveTargetFacts::href` is the `href` attribute as written, the shape the observed
//! descriptor carries. The safety kernel digests both byte for byte at confirmation, so a
//! resolved URL on the live side makes every relative link look changed (`confirm.identity_changed`
//! on the first click, then a scripted `Navigate` on the diagnostic lane). Skipped (with a
//! message) when no Chromium executable is found; set `CRAWLX_CHROMIUM_PATH`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserContext, ContextConfig};
use crawlx_core::ids::SessionId;
use crawlx_core::observation::{AxNode, ObservationBundle, ObservationSpec, Revalidation};
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAGE: &str = r#"<!doctype html><html><head><title>Links</title></head><body>
<a id="rel" href="/two?id=1">Relative</a>
<a id="padded" href="  /two#frag  ">Padded</a>
<a id="abs" href="http://127.0.0.1:1/elsewhere">Absolute</a>
<a id="empty" href="">Empty</a>
<button id="btn" type="button">Button</button>
</body></html>"#;

async fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{PAGE}",
                    PAGE.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    port
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

fn find<'a>(b: &'a ObservationBundle, role: &str, name: &str) -> &'a AxNode {
    b.ax.nodes
        .iter()
        .find(|n| n.role == role && n.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no {role} named {name:?}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_href_is_the_attribute_as_written_not_the_resolved_url() {
    let Some(backend) = launch().await else {
        return;
    };
    let port = serve().await;
    let mut ctx = backend
        .new_cdp_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    let base = url::Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
    let home = Canonicalizer::canonicalize("/", &base, &CanonicalizeOptions::default()).unwrap();
    ctx.navigate(&home).await.unwrap();
    let spec = ObservationSpec {
        ax: true,
        dom_supplement: true,
        dom_snapshot: false,
        screenshot: false,
        revalidation_only: false,
    };
    let bundle = ctx.observe(spec).await.unwrap();

    let mut seen = Vec::new();
    for (name, written) in [
        ("Relative", Some("/two?id=1")),
        // whitespace around the attribute is trimmed, as the descriptor trims it
        ("Padded", Some("/two#frag")),
        ("Absolute", Some("http://127.0.0.1:1/elsewhere")),
    ] {
        let link = find(&bundle, "link", name).clone();
        let Revalidation::Actionable { live } = ctx.revalidate(&link.locator, bundle.epoch).await.unwrap()
        else {
            panic!("{name}: expected Actionable");
        };
        assert_eq!(live.href.as_deref(), written, "{name}");
        seen.push((name, live.href));
    }
    assert_eq!(seen.len(), 3);

    // a node that is not an anchor carries no href
    let button = find(&bundle, "button", "Button").clone();
    let Revalidation::Actionable { live } = ctx.revalidate(&button.locator, bundle.epoch).await.unwrap()
    else {
        panic!("button: expected Actionable");
    };
    assert_eq!(live.href, None);
}
