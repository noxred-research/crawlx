//! Explicit download policy, safety bounds and cancellation against loopback Chromium.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod surface_support;

use async_trait::async_trait;
use crawlx_browser::{CdpContext, ChromiumBackend, NavigationGuard, NavigationVerdict};
use crawlx_core::browser::{BrowserContext, BrowserError};
use crawlx_core::browser_capture::{BrowserCaptureSink, CaptureDescriptor, CaptureKind};
use crawlx_core::browser_download::DownloadSpec;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{ArtifactId, ArtifactRef, CrawlRunId};
use crawlx_core::repo::{ArtifactStore, Sensitivity};
use crawlx_core::secret::{ArtifactSink, Redacted};
use crawlx_core::StoreError;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use url::Url;

const PUBLIC: &[u8] = b"approved public download content";
const DEADLINE: Duration = Duration::from_secs(10);
static TEST_LEASE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Debug, Default)]
struct MemoryStore(Mutex<BTreeMap<String, Vec<u8>>>);

#[async_trait]
impl ArtifactStore for MemoryStore {
    async fn put(
        &self,
        _run: CrawlRunId,
        class: Sensitivity,
        _content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        assert_eq!(class, Sensitivity::Content);
        let artifact = ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("crawlx/download-test/v1", bytes),
        };
        self.0.lock().insert(artifact.id.to_string(), bytes.to_vec());
        Ok(artifact)
    }

    async fn get(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        self.0
            .lock()
            .get(&artifact.id.to_string())
            .cloned()
            .ok_or_else(|| StoreError::NotFound {
                entity: "artifact",
                id: artifact.id.to_string(),
            })
    }
}

#[derive(Debug)]
struct PolicySink {
    allowed: bool,
    run: CrawlRunId,
    store: MemoryStore,
    stored: AtomicUsize,
}

impl PolicySink {
    fn new(allowed: bool) -> Self {
        Self {
            allowed,
            run: CrawlRunId::new(),
            store: MemoryStore::default(),
            stored: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl BrowserCaptureSink for PolicySink {
    async fn authorize(&self, kind: CaptureKind) -> Result<bool, StoreError> {
        assert_eq!(kind, CaptureKind::Download);
        Ok(self.allowed)
    }

    async fn store(
        &self,
        descriptor: &CaptureDescriptor,
        bytes: &Redacted<Vec<u8>>,
    ) -> Result<Option<ArtifactRef>, StoreError> {
        assert!(self.allowed);
        assert_eq!(bytes.as_ref(), PUBLIC);
        self.stored.fetch_add(1, Ordering::Relaxed);
        ArtifactSink::over(&self.store)
            .put(self.run, Sensitivity::Content, &descriptor.content_type, bytes)
            .await
            .map(Some)
    }
}

struct Origin {
    base: Url,
    hits: Arc<AtomicUsize>,
    started: Arc<Notify>,
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
        let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let notified = Arc::clone(&started);
        let count = Arc::clone(&hits);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (mut socket, _) = accepted.unwrap();
                        let count = Arc::clone(&count);
                        let notified = Arc::clone(&notified);
                        connections.spawn(async move {
                            let mut head = Vec::new();
                            while !head.ends_with(b"\r\n\r\n") {
                                let Ok(byte) = socket.read_u8().await else { return };
                                head.push(byte);
                                assert!(head.len() < 16 * 1024);
                            }
                            let head = String::from_utf8(head).unwrap();
                            let path = head.split_whitespace().nth(1).unwrap();
                            count.fetch_add(1, Ordering::Relaxed);
                            let name = if path == "/traversal" { "../outside.txt" } else { "public.txt" };
                            let slow = path == "/slow" || path == "/oversize";
                            let body_size = if slow { 128 * 1024 } else { PUBLIC.len() };
                            let chunked = path == "/oversize";
                            let framing = if chunked {
                                "Transfer-Encoding: chunked".to_owned()
                            } else {
                                format!("Content-Length: {body_size}")
                            };
                            let header = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{name}\"\r\n{framing}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"
                            );
                            if socket.write_all(header.as_bytes()).await.is_err() { return; }
                            notified.notify_one();
                            if slow {
                                for _ in 0..128 {
                                    if chunked && socket.write_all(b"400\r\n").await.is_err() { return; }
                                    if socket.write_all(&[b'x'; 1024]).await.is_err() { return; }
                                    if chunked && socket.write_all(b"\r\n").await.is_err() { return; }
                                    tokio::time::sleep(Duration::from_millis(20)).await;
                                }
                                if chunked { let _ = socket.write_all(b"0\r\n\r\n").await; }
                            } else {
                                let _ = socket.write_all(PUBLIC).await;
                            }
                            let _ = socket.shutdown().await;
                        });
                    }
                    joined = connections.join_next(), if !connections.is_empty() => {
                        joined.unwrap().unwrap();
                    }
                }
            }
        });
        Self {
            base,
            hits,
            started,
            task,
        }
    }

    fn spec(&self, path: &str, limit: u64) -> DownloadSpec {
        DownloadSpec::new(self.base.join(path).unwrap(), limit, 5000)
    }
}

async fn context(
    sink: Arc<PolicySink>,
    guard: Option<Arc<dyn NavigationGuard>>,
) -> Option<(ChromiumBackend, CdpContext, CancellationToken)> {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        eprintln!("SKIP: CRAWLX_CHROMIUM_PATH is not set");
        return None;
    }
    let backend = surface_support::launch(None, |_| {}).await?;
    let mut config = surface_support::context_config();
    config.browser_capture_sink = Some(sink);
    config.navigation_guard = guard;
    let cancel = config.captcha_cancel.clone();
    let context = backend.new_cdp_context(config).await.unwrap();
    Some((backend, context, cancel))
}

async fn spools() -> BTreeSet<PathBuf> {
    let mut entries = tokio::fs::read_dir(std::env::temp_dir()).await.unwrap();
    let mut paths = BTreeSet::new();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with("crawlx-download-")
        {
            paths.insert(entry.path());
        }
    }
    paths
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn success_returns_only_typed_artifact_and_restores_deny() {
    let _lease = TEST_LEASE.lock().await;
    let sink = Arc::new(PolicySink::new(true));
    let Some((backend, mut ctx, _)) = context(Arc::clone(&sink), None).await else {
        return;
    };
    let origin = Origin::start().await;
    let before = spools().await;
    let capture = ctx.download(origin.spec("/public", 1024)).await.unwrap();
    assert_eq!(capture.descriptor.kind, CaptureKind::Download);
    assert_eq!(capture.descriptor.filename.as_deref(), Some("public.txt"));
    assert_eq!(capture.bytes, u64::try_from(PUBLIC.len()).unwrap());
    assert_eq!(sink.store.get(&capture.artifact).await.unwrap(), PUBLIC);
    assert_eq!(spools().await, before);
    // An ordinary navigation remains denied after the explicit operation ends.
    let _ = ctx
        .navigate(&surface_support::canonical(
            origin.base.join("/outside").unwrap().as_str(),
        ))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(spools().await, before);
    assert_eq!(sink.stored.load(Ordering::Relaxed), 1);
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

#[derive(Debug)]
struct DenyGuard;

#[async_trait]
impl NavigationGuard for DenyGuard {
    async fn check(&self, _: &Url) -> NavigationVerdict {
        NavigationVerdict::RobotsBlocked {
            reason: "robots_disallow",
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_url_and_denied_sink_never_reach_origin() {
    let _lease = TEST_LEASE.lock().await;
    let origin = Origin::start().await;
    let sink = Arc::new(PolicySink::new(true));
    let Some((backend, mut ctx, _)) = context(Arc::clone(&sink), Some(Arc::new(DenyGuard))).await else {
        return;
    };
    let error = ctx.download(origin.spec("/forbidden", 1024)).await.unwrap_err();
    assert!(matches!(error, BrowserError::RobotsBlocked { .. }));
    assert_eq!(origin.hits.load(Ordering::Relaxed), 0);
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
    let denied = Arc::new(PolicySink::new(false));
    let (backend, mut ctx, _) = context(Arc::clone(&denied), None).await.unwrap();
    assert!(ctx.download(origin.spec("/denied", 1024)).await.is_err());
    assert_eq!(origin.hits.load(Ordering::Relaxed), 0);
    assert_eq!(denied.stored.load(Ordering::Relaxed), 0);
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traversal_suggestion_and_oversize_fail_closed() {
    let _lease = TEST_LEASE.lock().await;
    let sink = Arc::new(PolicySink::new(true));
    let Some((backend, mut ctx, _)) = context(Arc::clone(&sink), None).await else {
        return;
    };
    let origin = Origin::start().await;
    let before = spools().await;
    let error = ctx.download(origin.spec("/traversal", 1024)).await.unwrap_err();
    assert!(error.to_string().contains("filename"), "{error:?}");
    assert_eq!(spools().await, before);
    let error = ctx.download(origin.spec("/oversize", 2048)).await.unwrap_err();
    assert!(error.to_string().contains("byte limit"), "{error:?}");
    assert_eq!(spools().await, before);
    assert_eq!(sink.stored.load(Ordering::Relaxed), 0);
    // Cleanup leaves the same context usable for the next explicit operation.
    ctx.download(origin.spec("/public", 1024)).await.unwrap();
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_keeps_partial_data_off_disk() {
    let _lease = TEST_LEASE.lock().await;
    let sink = Arc::new(PolicySink::new(true));
    let Some((backend, mut ctx, cancel)) = context(Arc::clone(&sink), None).await else {
        return;
    };
    let origin = Origin::start().await;
    let before = spools().await;
    let mut operation = Box::pin(ctx.download(origin.spec("/slow", 1024 * 1024)));
    tokio::select! {
        result = &mut operation => panic!("download ended before cancellation: {result:?}"),
        () = origin.started.notified() => {},
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();
    assert!(tokio::time::timeout(DEADLINE, operation).await.unwrap().is_err());
    assert_eq!(spools().await, before);
    assert_eq!(sink.stored.load(Ordering::Relaxed), 0);
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_download_future_aborts_stream_and_unblocks_next_download() {
    let _lease = TEST_LEASE.lock().await;
    let sink = Arc::new(PolicySink::new(true));
    let Some((backend, mut ctx, _)) = context(Arc::clone(&sink), None).await else {
        return;
    };
    let origin = Origin::start().await;
    let before = spools().await;
    let mut operation = Box::pin(ctx.download(origin.spec("/slow", 1024 * 1024)));
    tokio::select! {
        result = &mut operation => panic!("download ended before drop: {result:?}"),
        () = origin.started.notified() => {},
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(operation);
    ctx.download(origin.spec("/public", 1024)).await.unwrap();
    assert_eq!(sink.stored.load(Ordering::Relaxed), 1);
    assert_eq!(spools().await, before);
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deadline_aborts_stream_without_retaining_partial_data() {
    let _lease = TEST_LEASE.lock().await;
    let sink = Arc::new(PolicySink::new(true));
    let Some((backend, mut ctx, _)) = context(Arc::clone(&sink), None).await else {
        return;
    };
    let origin = Origin::start().await;
    let before = spools().await;
    let mut spec = origin.spec("/slow", 1024 * 1024);
    spec.timeout_ms = 100;
    assert!(matches!(
        ctx.download(spec).await,
        Err(BrowserError::Timeout(100))
    ));
    assert_eq!(spools().await, before);
    assert_eq!(sink.stored.load(Ordering::Relaxed), 0);
    ctx.download(origin.spec("/public", 1024)).await.unwrap();
    Box::new(ctx).close().await.unwrap();
    backend.close().await.unwrap();
}
