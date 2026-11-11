//! Deterministic policy checks and opt-in loopback Chromium retained-capture coverage.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use crawlx_browser::{CdpContext, ChromiumBackend, LaunchConfig};
use crawlx_core::browser::{BrowserContext, BrowserError, ContextConfig};
use crawlx_core::browser_capture::{
    BrowserCaptureSink, CaptureCompleteness, CaptureDescriptor, CaptureKind, CaptureSpec,
};
use crawlx_core::config::{Fetch, RetentionMode};
use crawlx_core::hash::Digest;
use crawlx_core::ids::{ArtifactId, ArtifactRef, CrawlRunId, SessionId};
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::page_op::{PageOp, PageOpResult, PdfSpec, ShotSpec};
use crawlx_core::repo::{ArtifactStore, Sensitivity};
use crawlx_core::request_controls::RequestControls;
use crawlx_core::secret::{register_secret, ArtifactSink, Redacted, Redactor};
use crawlx_core::StoreError;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

const LIMIT: u64 = 4 * 1024 * 1024;
const PAGE: &str = r#"<!doctype html><html><head><link rel="stylesheet" href="/style.css"></head>
<body><p>retained public document</p><img src="/image.svg"></body></html>"#;
const STYLE: &str = "p { color: rgb(12, 34, 56); }";
const IMAGE: &str = r#"<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><rect width="16" height="16" fill="green"/></svg>"#;
// Twelve stylesheets, each below the per-resource privacy bound, whose re-serialized rules
// together are larger than one metadata reply.
const BIG_STYLE_RULES: usize = 6_000;
const BIG_PAGE: &str = r#"<!doctype html><html><head>
<link rel="stylesheet" href="/big-0.css"><link rel="stylesheet" href="/big-1.css">
<link rel="stylesheet" href="/big-2.css"><link rel="stylesheet" href="/big-3.css">
<link rel="stylesheet" href="/big-4.css"><link rel="stylesheet" href="/big-5.css">
<link rel="stylesheet" href="/big-6.css"><link rel="stylesheet" href="/big-7.css">
<link rel="stylesheet" href="/big-8.css"><link rel="stylesheet" href="/big-9.css">
<link rel="stylesheet" href="/big-10.css"><link rel="stylesheet" href="/big-11.css">
</head><body><p>large retained document</p></body></html>"#;

#[derive(Debug, Default)]
struct RecordingStore {
    writes: Mutex<Vec<(String, Vec<u8>)>>,
}

#[async_trait]
impl ArtifactStore for RecordingStore {
    async fn put(
        &self,
        _run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        assert_eq!(class, Sensitivity::Content);
        self.writes.lock().push((content_type.to_owned(), bytes.to_vec()));
        Ok(ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("test/browser-capture-artifact", bytes),
        })
    }

    async fn get(&self, _artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        Ok(self.writes.lock().last().unwrap().1.clone())
    }
}

#[derive(Debug)]
struct PolicySink {
    store: Arc<RecordingStore>,
    run: CrawlRunId,
    enabled: bool,
    retention: RetentionMode,
    allow_source: bool,
}

impl PolicySink {
    fn public() -> Self {
        Self {
            store: Arc::new(RecordingStore::default()),
            run: CrawlRunId::new(),
            enabled: true,
            retention: RetentionMode::Standard,
            allow_source: true,
        }
    }
}

#[async_trait]
impl BrowserCaptureSink for PolicySink {
    async fn authorize(&self, _kind: CaptureKind) -> Result<bool, StoreError> {
        Ok(self.enabled && self.retention != RetentionMode::Zdr)
    }

    async fn authorize_source(&self, source: &[u8]) -> Result<bool, StoreError> {
        let approved = Redactor::new().verify_binary(source)?;
        Ok(self.allow_source && approved.as_ref() == source)
    }

    async fn store(
        &self,
        descriptor: &CaptureDescriptor,
        bytes: &Redacted<Vec<u8>>,
    ) -> Result<Option<ArtifactRef>, StoreError> {
        if !self.authorize(descriptor.kind).await? {
            return Ok(None);
        }
        ArtifactSink::over(self.store.as_ref())
            .put(self.run, Sensitivity::Content, &descriptor.content_type, bytes)
            .await
            .map(Some)
    }
}

#[tokio::test]
async fn policy_opt_in_and_zdr_refuse_without_artifact_writes() {
    let mut sink = PolicySink::public();
    sink.enabled = false;
    assert!(!sink.authorize(CaptureKind::Mhtml).await.unwrap());
    sink.enabled = true;
    sink.retention = RetentionMode::Zdr;
    assert!(!sink.authorize(CaptureKind::Screenshot).await.unwrap());
    let descriptor = CaptureDescriptor::new(CaptureKind::Text, "text/plain", "http://127.0.0.1/");
    let approved = Redactor::new().verify_binary(b"public text").unwrap();
    assert!(sink.store(&descriptor, &approved).await.unwrap().is_none());
    assert!(sink.store.writes.lock().is_empty());
}

#[tokio::test]
async fn source_secret_and_opaque_secret_fail_closed() {
    let sink = PolicySink::public();
    let secret = "retained-source-private-canary-482651";
    assert!(register_secret(secret));
    assert!(sink.authorize_source(secret.as_bytes()).await.is_err());
    assert!(Redactor::new()
        .verify_binary(format!("%PDF-1.7 {secret}").as_bytes())
        .is_err());
    assert!(sink.store.writes.lock().is_empty());
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
    let big_style = path.starts_with("/big-").then(|| {
        (0..BIG_STYLE_RULES)
            .map(|rule| format!(".r{rule}{{color:red}}"))
            .collect::<String>()
    });
    let (status, mime, body) = match path {
        "/" => ("200 OK", "text/html", PAGE),
        "/style.css" => ("200 OK", "text/css", STYLE),
        "/image.svg" => ("200 OK", "image/svg+xml", IMAGE),
        "/tall" => ("200 OK", "text/html", "<!doctype html><body style='margin:0'><div style='height:20000px;background:green'>tall</div></body>"),
        "/missing" => ("200 OK", "text/html", "<!doctype html><body><img src='/absent.svg'>missing asset</body>"),
        "/secret" => ("200 OK", "text/html", "<!doctype html><body>retained-browser-private-canary-673284</body>"),
        "/password" => ("200 OK", "text/html", "<!doctype html><body><input type=password value=private></body>"),
        "/large" => ("200 OK", "text/html", "<!doctype html><body><script>document.body.append('x'.repeat(1048577))</script></body>"),
        "/big" => ("200 OK", "text/html", BIG_PAGE),
        _ if big_style.is_some() => ("200 OK", "text/css", big_style.as_deref().unwrap()),
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
        eprintln!("SKIP: retained capture requires CRAWLX_CHROMIUM_PATH");
        return None;
    };
    let mut config = LaunchConfig::new();
    config.executable = executable.into();
    config.allow_unpinned = true;
    Some(ChromiumBackend::launch(config).await.unwrap())
}

async fn context(backend: &ChromiumBackend, sink: Arc<PolicySink>) -> CdpContext {
    let mut config = ContextConfig::new(SessionId::new());
    config.browser_capture_sink = Some(sink);
    config.viewport.width = 800;
    config.viewport.height = 600;
    backend.new_cdp_context(config).await.unwrap()
}

async fn navigate(ctx: &mut CdpContext, origin: &Origin, path: &str) {
    let base = url::Url::parse(&format!("http://127.0.0.1:{}/", origin.port)).unwrap();
    let url = Canonicalizer::canonicalize(path, &base, &CanonicalizeOptions::default()).unwrap();
    ctx.navigate(&url).await.unwrap();
    ctx.settle(QuiescencePolicy::default()).await.unwrap();
}

fn sent(ctx: &CdpContext, method: &str) -> usize {
    ctx.cdp_transcript()
        .iter()
        .filter(|entry| entry.as_str() == method)
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mhtml_retains_styles_and_images_with_honest_completeness() {
    let Some(backend) = launch().await else { return };
    let origin = Origin::start().await;
    let sink = Arc::new(PolicySink::public());
    let mut ctx = context(&backend, Arc::clone(&sink)).await;
    navigate(&mut ctx, &origin, "/").await;
    // The original Network response buffer, not the HTTP/Page cache or traffic queue,
    // supplies privacy inspection for resources explicitly served with no-store.
    assert!(!ctx.drain_traffic().is_empty());
    let artifact = ctx
        .retained_capture(CaptureSpec::Mhtml { max_bytes: LIMIT })
        .await
        .unwrap();
    assert_eq!(artifact.descriptor.content_type, "multipart/related");
    assert_eq!(artifact.completeness, CaptureCompleteness::Unknown);
    let body = sink.store.get(&artifact.artifact).await.unwrap();
    assert_eq!(artifact.bytes, u64::try_from(body.len()).unwrap());
    let mhtml = String::from_utf8(body).unwrap();
    assert!(mhtml.contains("Content-Type: text/html"));
    assert!(mhtml.contains("/style.css"));
    assert!(mhtml.contains("Content-Type: text/css"));
    assert!(mhtml.contains("/image.svg"));
    assert!(mhtml.contains("Content-Type: image/svg+xml"));
    assert_eq!(sent(&ctx, "Page.captureSnapshot"), 1);
    assert!(sent(&ctx, "Network.getResponseBody") >= 3);
    assert_eq!(sent(&ctx, "Page.getResourceContent"), 0);
    navigate(&mut ctx, &origin, "/missing").await;
    let missing = ctx
        .retained_capture(CaptureSpec::Mhtml { max_bytes: LIMIT })
        .await;
    // Some browser builds cannot expose a failed resource at all. Refusal is an explicit
    // unavailable result; neither outcome may claim a complete resource snapshot.
    if let Ok(missing) = missing {
        assert_eq!(missing.completeness, CaptureCompleteness::Unknown);
        assert!(missing.descriptor.truncated);
    }
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn screenshot_clipping_encoding_and_pixel_bounds_are_truthful() {
    let Some(backend) = launch().await else { return };
    let origin = Origin::start().await;
    let sink = Arc::new(PolicySink::public());
    let mut ctx = context(&backend, Arc::clone(&sink)).await;
    navigate(&mut ctx, &origin, "/tall").await;
    let clipped = ctx
        .retained_capture(CaptureSpec::Screenshot {
            shot: ShotSpec {
                full_page: true,
                ..ShotSpec::default()
            },
            max_bytes: LIMIT,
            max_pixels: 20_000_000,
        })
        .await
        .unwrap();
    assert_eq!(clipped.descriptor.content_type, "image/png");
    assert_eq!((clipped.width, clipped.height), (Some(800), Some(16_384)));
    assert_eq!(clipped.completeness, CaptureCompleteness::Clipped);
    assert!(clipped.descriptor.truncated);
    let before = sent(&ctx, "Page.captureScreenshot");
    assert!(ctx
        .retained_capture(CaptureSpec::Screenshot {
            shot: ShotSpec::default(),
            max_bytes: LIMIT,
            max_pixels: 100,
        })
        .await
        .is_err());
    assert_eq!(sent(&ctx, "Page.captureScreenshot"), before);
    let jpeg = ctx
        .retained_capture(CaptureSpec::Screenshot {
            shot: ShotSpec {
                quality: Some(80),
                ..ShotSpec::default()
            },
            max_bytes: LIMIT,
            max_pixels: 480_000,
        })
        .await
        .unwrap();
    assert_eq!(jpeg.descriptor.content_type, "image/jpeg");
    assert_eq!((jpeg.width, jpeg.height), (Some(800), Some(600)));
    let bytes = sink.store.get(&jpeg.artifact).await.unwrap();
    assert!(bytes.starts_with(&[0xff, 0xd8]));
    assert_eq!(jpeg.completeness, CaptureCompleteness::Complete);
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn policy_source_secrets_and_byte_bounds_never_write_artifacts() {
    let Some(backend) = launch().await else { return };
    let origin = Origin::start().await;
    let mut no_sink = backend
        .new_cdp_context(ContextConfig::new(SessionId::new()))
        .await
        .unwrap();
    assert!(no_sink
        .retained_capture(CaptureSpec::Mhtml { max_bytes: LIMIT })
        .await
        .is_err());
    assert_eq!(sent(&no_sink, "Page.captureSnapshot"), 0);
    let mut refused_source = PolicySink::public();
    refused_source.allow_source = false;
    let refused_source = Arc::new(refused_source);
    let mut refused = context(&backend, Arc::clone(&refused_source)).await;
    navigate(&mut refused, &origin, "/").await;
    assert!(refused
        .retained_capture(CaptureSpec::Screenshot {
            shot: ShotSpec::default(),
            max_bytes: LIMIT,
            max_pixels: 1_000_000,
        })
        .await
        .is_err());
    assert_eq!(sent(&refused, "Page.captureScreenshot"), 0);
    assert!(refused_source.store.writes.lock().is_empty());
    for retention in [RetentionMode::Zdr, RetentionMode::Standard] {
        let mut policy = PolicySink::public();
        policy.retention = retention;
        policy.enabled = retention == RetentionMode::Zdr;
        let sink = Arc::new(policy);
        let mut ctx = context(&backend, Arc::clone(&sink)).await;
        navigate(&mut ctx, &origin, "/").await;
        assert!(ctx
            .retained_capture(CaptureSpec::Mhtml { max_bytes: LIMIT })
            .await
            .is_err());
        assert_eq!(sent(&ctx, "Page.captureSnapshot"), 0);
        assert!(sink.store.writes.lock().is_empty());
    }
    let sink = Arc::new(PolicySink::public());
    let mut ctx = context(&backend, Arc::clone(&sink)).await;
    assert!(register_secret("retained-browser-private-canary-673284"));
    for path in ["/secret", "/password", "/large"] {
        navigate(&mut ctx, &origin, path).await;
        assert!(ctx
            .retained_capture(CaptureSpec::Screenshot {
                shot: ShotSpec::default(),
                max_bytes: LIMIT,
                max_pixels: 1_000_000,
            })
            .await
            .is_err());
        assert_eq!(sent(&ctx, "Page.captureScreenshot"), 0);
    }
    navigate(&mut ctx, &origin, "/").await;
    assert!(ctx
        .retained_capture(CaptureSpec::Mhtml { max_bytes: 1 })
        .await
        .is_err());
    assert!(ctx
        .retained_capture(CaptureSpec::Pdf {
            spec: PdfSpec {
                format: None,
                landscape: false,
                scale: 1.0
            },
            max_bytes: 1,
        })
        .await
        .is_err());
    assert!(sink.store.writes.lock().is_empty());
    let mut config = ContextConfig::new(SessionId::new());
    let mut fetch = Fetch::default();
    fetch.extra_headers.insert("x-private", "short");
    config.request_controls = RequestControls::resolve(&fetch, "127.0.0.1", None).await.unwrap();
    config.browser_capture_sink = Some(Arc::clone(&sink) as Arc<dyn BrowserCaptureSink>);
    let mut secret_ctx = backend.new_cdp_context(config).await.unwrap();
    let before_snapshot = sent(&secret_ctx, "Page.captureSnapshot");
    assert!(secret_ctx
        .retained_capture(CaptureSpec::Mhtml { max_bytes: LIMIT })
        .await
        .is_err());
    assert_eq!(sent(&secret_ctx, "Page.captureSnapshot"), before_snapshot);
    assert!(sink.store.writes.lock().is_empty());
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_pdf_and_text_use_typed_policy_dispatch() {
    let Some(backend) = launch().await else { return };
    let origin = Origin::start().await;
    let sink = Arc::new(PolicySink::public());
    let mut ctx = context(&backend, Arc::clone(&sink)).await;
    navigate(&mut ctx, &origin, "/").await;
    let pdf = ctx
        .retained_capture(CaptureSpec::Pdf {
            spec: PdfSpec {
                format: Some("A4".to_owned()),
                landscape: false,
                scale: 1.0,
            },
            max_bytes: LIMIT,
        })
        .await
        .unwrap();
    assert_eq!(pdf.descriptor.content_type, "application/pdf");
    assert!(sink.store.get(&pdf.artifact).await.unwrap().starts_with(b"%PDF-"));
    let result = ctx
        .page_op(PageOp::Capture(CaptureSpec::Text { max_bytes: 8 }))
        .await
        .unwrap();
    let PageOpResult::Capture(text) = result else {
        panic!("capture result required")
    };
    assert_eq!(text.completeness, CaptureCompleteness::Clipped);
    assert!(text.descriptor.truncated);
    assert!(text.bytes <= 8);
    backend.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mhtml_above_the_metadata_cap_is_admitted_and_refused_above_its_limit() {
    let Some(backend) = launch().await else { return };
    let origin = Origin::start().await;
    let sink = Arc::new(PolicySink::public());
    let mut ctx = context(&backend, Arc::clone(&sink)).await;
    navigate(&mut ctx, &origin, "/big").await;
    let artifact = ctx
        .retained_capture(CaptureSpec::Mhtml { max_bytes: LIMIT })
        .await
        .unwrap();
    let stored = sink.store.get(&artifact.artifact).await.unwrap();
    // A snapshot this large cannot have passed through the 1 MiB metadata-reply cap.
    assert!(stored.len() > 1024 * 1024, "{} bytes", stored.len());
    assert_eq!(artifact.bytes, u64::try_from(stored.len()).unwrap());
    assert_eq!(sink.store.writes.lock().len(), 1);
    // The very same snapshot against a smaller limit is refused with the typed memory error.
    let refused = ctx
        .retained_capture(CaptureSpec::Mhtml {
            max_bytes: 1024 * 1024,
        })
        .await;
    assert!(matches!(refused, Err(BrowserError::Memory(_))), "{refused:?}");
    assert_eq!(
        sink.store.writes.lock().len(),
        1,
        "the refused snapshot is never stored"
    );
    backend.close().await.unwrap();
}
