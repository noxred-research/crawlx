//! An MHTML snapshot is admitted against the shared byte budget before it is built.
//!
//! This binary holds one test: it lowers the process-wide budget while the browser holds a
//! snapshot larger than the budget can keep, which would starve any sibling test running in the
//! same process. Skips without `CRAWLX_CHROMIUM_PATH`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserContext, BrowserError, ContextConfig};
use crawlx_core::browser_capture::{
    BrowserCaptureSink, CaptureArtifact, CaptureDescriptor, CaptureKind, CaptureSpec,
};
use crawlx_core::hash::Digest;
use crawlx_core::ids::{ArtifactId, ArtifactRef, SessionId};
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::parser_memory::global;
use crawlx_core::secret::{Redacted, Redactor};
use crawlx_core::StoreError;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

const LIMIT: u64 = 4 * 1024 * 1024;
// Twelve stylesheets under the per-resource privacy bound; the browser re-serializes their
// rules, which together are larger than one metadata reply and than the headroom left to the
// budget below.
const STYLE_RULES: usize = 6_000;
const PAGE: &str = r#"<!doctype html><html><head>
<link rel="stylesheet" href="/s-0.css"><link rel="stylesheet" href="/s-1.css">
<link rel="stylesheet" href="/s-2.css"><link rel="stylesheet" href="/s-3.css">
<link rel="stylesheet" href="/s-4.css"><link rel="stylesheet" href="/s-5.css">
<link rel="stylesheet" href="/s-6.css"><link rel="stylesheet" href="/s-7.css">
<link rel="stylesheet" href="/s-8.css"><link rel="stylesheet" href="/s-9.css">
<link rel="stylesheet" href="/s-10.css"><link rel="stylesheet" href="/s-11.css">
</head><body><p>large retained document</p></body></html>"#;
/// Bytes the budget may still grant once the snapshot is requested: enough for every earlier
/// step, far less than the snapshot's frame alone.
const HEADROOM: usize = 1024 * 1024;

#[derive(Debug, Default)]
struct Sink {
    stored: Mutex<Vec<usize>>,
}

#[async_trait]
impl BrowserCaptureSink for Sink {
    async fn authorize(&self, _kind: CaptureKind) -> Result<bool, StoreError> {
        Ok(true)
    }

    async fn authorize_source(&self, source: &[u8]) -> Result<bool, StoreError> {
        let approved = Redactor::new().verify_binary(source)?;
        Ok(approved.as_ref() == source)
    }

    async fn store(
        &self,
        descriptor: &CaptureDescriptor,
        bytes: &Redacted<Vec<u8>>,
    ) -> Result<Option<ArtifactRef>, StoreError> {
        self.stored.lock().push(bytes.as_inner().len());
        Ok(Some(ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of(
                "test/browser-capture-artifact",
                descriptor.content_type.as_bytes(),
            ),
        }))
    }
}

struct Origin {
    port: u16,
    task: JoinHandle<()>,
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Origin {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept(), if connections.len() < 16 => {
                        let (stream, _) = accepted.unwrap();
                        connections.spawn(async move {
                            tokio::time::timeout(Duration::from_secs(10), exchange(stream)).await.unwrap();
                        });
                    }
                    result = connections.join_next(), if !connections.is_empty() => {
                        result.unwrap().unwrap();
                    }
                }
            }
        });
        Self { port, task }
    }
}

async fn exchange(mut stream: TcpStream) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let Ok(byte) = stream.read_u8().await else { return };
        request.push(byte);
        assert!(request.len() <= 16 * 1024);
    }
    let request = String::from_utf8(request).unwrap();
    let path = request.split_whitespace().nth(1).unwrap();
    let style: String = (0..STYLE_RULES)
        .map(|rule| format!(".r{rule}{{color:red}}"))
        .collect();
    let (status, mime, body) = match path {
        "/" => ("200 OK", "text/html", PAGE),
        _ if path.starts_with("/s-") => ("200 OK", "text/css", style.as_str()),
        _ => ("404 Not Found", "text/plain", "missing"),
    };
    let header = format!("HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len());
    if stream.write_all(header.as_bytes()).await.is_ok() {
        let _ = stream.write_all(body.as_bytes()).await;
        let _ = stream.shutdown().await;
    }
}

async fn launch() -> Option<ChromiumBackend> {
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("SKIP: retained capture budget requires CRAWLX_CHROMIUM_PATH");
        return None;
    };
    let mut config = LaunchConfig::new();
    config.executable = executable.into();
    config.allow_unpinned = true;
    Some(ChromiumBackend::launch(config).await.unwrap())
}

async fn capture(ctx: &mut CdpContext) -> Result<CaptureArtifact, BrowserError> {
    ctx.retained_capture(CaptureSpec::Mhtml { max_bytes: LIMIT })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_the_budget_cannot_keep_is_refused_before_it_is_built() {
    let Some(backend) = launch().await else { return };
    let origin = Origin::start().await;
    let sink = Arc::new(Sink::default());
    let mut config = ContextConfig::new(SessionId::new());
    config.browser_capture_sink = Some(Arc::clone(&sink) as Arc<dyn BrowserCaptureSink>);
    config.viewport.width = 800;
    config.viewport.height = 600;
    let mut ctx = backend.new_cdp_context(config).await.unwrap();
    let base = url::Url::parse(&format!("http://127.0.0.1:{}/", origin.port)).unwrap();
    let url = Canonicalizer::canonicalize("/", &base, &CanonicalizeOptions::default()).unwrap();
    ctx.navigate(&url).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();

    // With the whole budget the snapshot, larger than a metadata reply, is retained.
    let artifact = capture(&mut ctx).await.unwrap();
    assert!(artifact.bytes > 1024 * 1024, "{} bytes", artifact.bytes);
    assert_eq!(sink.stored.lock().len(), 1);

    // The same snapshot against a budget with less headroom than its frame is refused with the
    // typed memory error, and nothing is stored.
    let original = global().limit();
    global().set_limit(global().used().saturating_add(HEADROOM));
    let refused = capture(&mut ctx).await;
    global().set_limit(original);
    assert!(matches!(refused, Err(BrowserError::Memory(_))), "{refused:?}");
    assert_eq!(
        sink.stored.lock().len(),
        1,
        "the refused snapshot is never stored"
    );
    let snapshots = ctx
        .cdp_transcript()
        .iter()
        .filter(|entry| entry.as_str() == "Page.captureSnapshot")
        .count();
    assert_eq!(snapshots, 2, "the refusal came from the snapshot reply itself");
    let _ = backend.close().await;
}
