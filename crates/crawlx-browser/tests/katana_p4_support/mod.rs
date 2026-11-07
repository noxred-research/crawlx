//! Shared helpers of the katana browser tests: launching Chromium (skipped when none is
//! installed), a local HTTP server and a local forward proxy that records which hosts were
//! asked for.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::launch::find_executable;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::ContextConfig;
use crawlx_core::ids::SessionId;
use crawlx_core::url::CanonicalUrl;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// One served resource: content type and body.
pub type Resource = (&'static str, String);

/// Launch Chromium with `tweak` applied; `None` (and a note on stderr) when no Chromium is
/// installed. Retries once with `--no-sandbox` for CI containers that cannot create user
/// namespaces.
pub async fn launch(proxy: Option<u16>, tweak: impl Fn(&mut LaunchConfig)) -> Option<ChromiumBackend> {
    let Some(exe) = find_executable() else {
        eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
        return None;
    };
    let mut cfg = LaunchConfig::new();
    cfg.executable = exe;
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

pub fn context_config() -> ContextConfig {
    ContextConfig::new(SessionId::new())
}

pub fn canonical(url: &str) -> CanonicalUrl {
    Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &CanonicalizeOptions::default()).unwrap()
}

/// Requests a local server received, in arrival order, as `host/path` (query dropped).
#[derive(Clone, Default)]
pub struct Hits(Arc<Mutex<Vec<String>>>);

impl Hits {
    pub fn all(&self) -> Vec<String> {
        self.0.lock().clone()
    }

    /// Requests whose `host/path` starts with `prefix`.
    pub fn count(&self, prefix: &str) -> usize {
        self.0.lock().iter().filter(|h| h.starts_with(prefix)).count()
    }

    fn push(&self, hit: String) {
        self.0.lock().push(hit);
    }
}

/// A local HTTP/1.1 server. With `proxy = false` it serves `http://127.0.0.1:<port>/path`
/// requests by path; with `proxy = true` it is a forward proxy that serves absolute-form
/// requests (`GET http://host/path`) by `host/path`, so any host name reaches it without DNS.
pub struct Server {
    pub port: u16,
    pub hits: Hits,
}

pub async fn serve(routes: BTreeMap<String, Resource>, proxy: bool) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Hits::default();
    let seen = hits.clone();
    let routes = Arc::new(routes);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let routes = Arc::clone(&routes);
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).into_owned();
                let mut words = head.split_whitespace();
                let method = words.next().unwrap_or("GET").to_owned();
                let target = words.next().unwrap_or("/").to_owned();
                let key = if proxy {
                    target.strip_prefix("http://").unwrap_or(&target).to_owned()
                } else {
                    format!("127.0.0.1{target}")
                };
                let key = key.split('?').next().unwrap_or_default().to_owned();
                seen.push(key.clone());
                let (status, ctype, body) = match routes.get(&key) {
                    Some((ctype, body)) => ("200 OK", *ctype, body.clone()),
                    None => ("404 Not Found", "text/plain", "not found".to_owned()),
                };
                let body = if method == "HEAD" { String::new() } else { body };
                let resp = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Server { port, hits }
}
