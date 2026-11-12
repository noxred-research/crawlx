//! The image pipeline: image URLs re-enter the frontier under the run's scope, and downloaded
//! bytes are validated, checksummed, de-duplicated per scope and stored inside the CPU and byte
//! quotas. A loopback fixture site and in-memory stores; no network, no model.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use common::authorization::run_authorized_local_with as run_local_with;
use crawlx_core::config::CrawlMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ArtifactStore, FrontierStatus, Sensitivity};
use crawlx_core::{ArtifactId, ArtifactRef, CrawlRunId, CreateCrawl, StoreError, TenantId, Timestamp};
use crawlx_extract::images::{ImageError, ImagePolicy};
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::media_probe::ingest::{ImageIngest, ImagePipeline, ImageRefusal, ImageScope, ScopeUsage};
use crawlx_worker::media_probe::ImageQuota;
use crawlx_worker::runtime::CpuPool;
use crawlx_worker::{EgressConfig, LocalRun, Stores, WorkerConfig};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use url::Url;

// ---- image bytes ---------------------------------------------------------------------------

fn png(width: u32, height: u32, seed: u8) -> Vec<u8> {
    let mut pixels = image::RgbaImage::new(width, height);
    for (x, y, pixel) in pixels.enumerate_pixels_mut() {
        let v = u8::try_from((x * 5 + y * 11 + u32::from(seed)) % 251).unwrap();
        *pixel = image::Rgba([v, v.wrapping_mul(7), seed, 255]);
    }
    let mut out = std::io::Cursor::new(Vec::new());
    pixels.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

fn corrupt(mut bytes: Vec<u8>) -> Vec<u8> {
    let at = bytes.len() / 2;
    bytes[at] ^= 0xff;
    bytes
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A PNG that declares a huge canvas and carries no pixel data.
fn pixel_bomb() -> Vec<u8> {
    let mut bytes = Vec::from(&b"\x89PNG\r\n\x1a\n"[..]);
    let mut ihdr = Vec::from(&b"IHDR"[..]);
    ihdr.extend_from_slice(&70_000_u32.to_be_bytes());
    ihdr.extend_from_slice(&70_000_u32.to_be_bytes());
    ihdr.extend_from_slice(&[8, 6, 0, 0, 0]);
    bytes.extend_from_slice(&13_u32.to_be_bytes());
    bytes.extend_from_slice(&ihdr);
    bytes.extend_from_slice(&crc32(&ihdr).to_be_bytes());
    let mut idat = Vec::from(&b"IDAT"[..]);
    idat.extend_from_slice(&[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
    bytes.extend_from_slice(&8_u32.to_be_bytes());
    bytes.extend_from_slice(&idat);
    bytes.extend_from_slice(&crc32(&idat).to_be_bytes());
    bytes
}

// ---- stores --------------------------------------------------------------------------------

/// One recorded write: run, content type, byte length and the optional retention deadline.
type Write = (CrawlRunId, String, usize, Option<Timestamp>);

/// Records every write; `fail_next` makes the next write fail once.
#[derive(Default)]
struct RecordingStore {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    writes: Mutex<Vec<Write>>,
    fail_next: Mutex<bool>,
}

impl RecordingStore {
    fn writes(&self) -> usize {
        self.writes.lock().len()
    }
    fn record(
        &self,
        run: CrawlRunId,
        content_type: &str,
        bytes: &[u8],
        deadline: Option<Timestamp>,
    ) -> Result<ArtifactRef, StoreError> {
        if std::mem::take(&mut *self.fail_next.lock()) {
            return Err(StoreError::Unavailable("scripted failure".into()));
        }
        self.writes
            .lock()
            .push((run, content_type.to_owned(), bytes.len(), deadline));
        let artifact = ArtifactRef {
            id: ArtifactId::new(),
            digest: Digest::of("crawlx/image-test/v1", bytes),
        };
        self.objects
            .lock()
            .insert(artifact.id.to_string(), bytes.to_vec());
        Ok(artifact)
    }
}

#[async_trait]
impl ArtifactStore for RecordingStore {
    async fn put(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        assert_eq!(class, Sensitivity::Content);
        // yield so concurrent identical ingests would interleave if they were not serialized
        tokio::task::yield_now().await;
        self.record(run, content_type, bytes, None)
    }

    async fn put_until(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
        deadline: Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        assert_eq!(class, Sensitivity::Content);
        self.record(run, content_type, bytes, Some(deadline))
    }

    async fn get(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        self.objects
            .lock()
            .get(&artifact.id.to_string())
            .cloned()
            .ok_or_else(|| StoreError::NotFound {
                entity: "artifact",
                id: artifact.id.to_string(),
            })
    }
}

fn scope() -> ImageScope {
    ImageScope::new(TenantId::new(), CrawlRunId::new())
}

fn ingest(scope: ImageScope, path: &str, bytes: &[u8]) -> ImageIngest {
    ImageIngest::new(
        scope,
        Url::parse(&format!("https://images.test{path}")).unwrap(),
        Bytes::copy_from_slice(bytes),
    )
}

fn pool(permits: usize) -> CpuPool {
    CpuPool::with_permits(NonZeroUsize::new(permits).unwrap())
}

fn pipeline(policy: ImagePolicy, quota: ImageQuota) -> ImagePipeline {
    ImagePipeline::new(policy, quota).unwrap()
}

// ---- frontier re-entry ---------------------------------------------------------------------

type Hits = Arc<Mutex<Vec<String>>>;

struct Site {
    base: String,
    hits: Hits,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Site {
    fn fetched(&self, path: &str) -> bool {
        self.hits.lock().iter().any(|p| p == path)
    }
}

async fn record(
    axum::extract::State(hits): axum::extract::State<Hits>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    hits.lock().push(req.uri().path().to_owned());
    next.run(req).await
}

fn image_response(bytes: Vec<u8>) -> axum::response::Response {
    ([(header::CONTENT_TYPE, "image/png")], bytes).into_response()
}

async fn start() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let home = r#"<html><head><title>Gallery</title></head><body><main><h1>Gallery</h1><p>Pictures.</p>
        <img src="/img/a.png"><img src="/img/b.png"><img src="/img/c.png"><img src="/img/bad.png">
        <img src="http://elsewhere.invalid/out-of-scope.png"></main></body></html>"#;
    let app = Router::new()
        .route(
            "/",
            get(move || async move {
                ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], home).into_response()
            }),
        )
        .route("/img/a.png", get(|| async { image_response(png(24, 16, 1)) }))
        .route("/img/b.png", get(|| async { image_response(png(24, 16, 1)) }))
        .route("/img/c.png", get(|| async { image_response(png(32, 32, 2)) }))
        .route(
            "/img/bad.png",
            get(|| async { image_response(corrupt(png(40, 40, 3))) }),
        )
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site {
        base: format!("http://{addr}"),
        hits,
        task,
    }
}

#[tokio::test]
async fn image_urls_re_enter_the_frontier_under_scope_and_are_fetched_by_the_run() {
    let site = start().await;
    let dir = tempfile::tempdir().unwrap();
    let mut crawl = CreateCrawl::new(Url::parse(&format!("{}/", site.base)).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_101);
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.scope.sitemap = crawlx_core::config::SitemapMode::Skip;
    // the default extension filter keeps images out of the frontier; opting in re-admits them
    crawl.scope.no_default_extension_filter = true;
    let config = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let report = run_local_with(LocalRun::new(crawl, config).with_stores(stores.clone()))
        .await
        .unwrap();
    let frontier = stores.frontier.list(report.run_id).await.unwrap();
    let status_of = |path: &str| {
        frontier
            .iter()
            .find(|entry| entry.url.url.path() == path)
            .map(|entry| entry.status)
    };
    // every in-scope image became a frontier row and was fetched through the run's fetcher
    for path in ["/img/a.png", "/img/b.png", "/img/c.png", "/img/bad.png"] {
        assert!(status_of(path).is_some(), "{path} never entered the frontier");
        assert_ne!(status_of(path), Some(FrontierStatus::PolicyBlocked), "{path}");
        assert!(site.fetched(path), "{path} was not fetched");
    }
    // the out-of-scope host never produced a request
    assert!(!site.fetched("/out-of-scope.png"));
    let outside = frontier
        .iter()
        .find(|entry| entry.url.url.path() == "/out-of-scope.png")
        .map(|entry| entry.status);
    assert!(outside.is_none() || outside == Some(FrontierStatus::PolicyBlocked));
    // the page's image references and the scope predicate agree with the frontier
    let page = r#"<img src="/img/a.png"><img src="http://elsewhere.invalid/out-of-scope.png">"#;
    let mut charge = crawlx_extract::parse_budget::charge(page.len()).unwrap();
    let refs = crawlx_extract::images::images(
        &mut charge,
        page,
        &Url::parse(&format!("{}/", site.base)).unwrap(),
    )
    .unwrap();
    let host = Url::parse(&site.base).unwrap();
    let proposed = crawlx_extract::images::frontier_candidates(&refs, |u| u.origin() == host.origin(), 10);
    assert_eq!(proposed.len(), 1);
    assert_eq!(proposed[0].path(), "/img/a.png");
}

// ---- ingest ---------------------------------------------------------------------------------

#[tokio::test]
async fn identical_bytes_are_stored_once_per_scoped_identity_with_a_checksum() {
    let store = RecordingStore::default();
    let cpu = pool(2);
    let pipe = pipeline(ImagePolicy::default(), ImageQuota::default());
    let (mine, theirs) = (scope(), scope());
    let a = png(24, 16, 1);

    let first = pipe
        .ingest(&cpu, &store, &ingest(mine, "/a.png", &a))
        .await
        .unwrap();
    assert!(!first.deduplicated);
    assert_eq!(
        (
            first.stored.facts.format,
            first.stored.facts.width,
            first.stored.facts.height
        ),
        ("png", 24, 16)
    );
    assert_eq!(first.stored.facts.bytes, a.len());
    assert_eq!(
        first.stored.facts.checksum,
        crawlx_extract::images::inspect_image(&a, &ImagePolicy::default())
            .unwrap()
            .facts
            .checksum
    );
    assert_eq!(store.get(&first.stored.artifact).await.unwrap(), a);

    // the same bytes under another URL in the same scope: no new object, same artifact
    let again = pipe
        .ingest(&cpu, &store, &ingest(mine, "/copy-of-a.png", &a))
        .await
        .unwrap();
    assert!(again.deduplicated);
    assert_eq!(again.stored, first.stored);
    assert_eq!(again.source.path(), "/copy-of-a.png");
    assert_eq!(store.writes(), 1);

    // different bytes are a different identity
    let other = pipe
        .ingest(&cpu, &store, &ingest(mine, "/c.png", &png(32, 32, 2)))
        .await
        .unwrap();
    assert!(!other.deduplicated);
    assert_ne!(other.stored.facts.checksum, first.stored.facts.checksum);
    assert_eq!(store.writes(), 2);

    // another scope never shares, exposes or removes this scope's copy
    let foreign = pipe
        .ingest(&cpu, &store, &ingest(theirs, "/a.png", &a))
        .await
        .unwrap();
    assert!(!foreign.deduplicated);
    assert_ne!(foreign.stored.artifact, first.stored.artifact);
    assert_eq!(foreign.stored.facts.checksum, first.stored.facts.checksum);
    assert_eq!(store.writes(), 3);
    let usage = pipe.usage(&mine);
    assert_eq!(usage.images, 2);
    assert_eq!(
        usage.bytes,
        u64::try_from(a.len() + png(32, 32, 2).len()).unwrap()
    );
    assert_eq!(pipe.usage(&theirs).images, 1);
}

#[tokio::test]
async fn concurrent_identical_ingests_store_exactly_once() {
    let store = Arc::new(RecordingStore::default());
    let cpu = pool(4);
    let pipe = Arc::new(pipeline(ImagePolicy::default(), ImageQuota::default()));
    let one = scope();
    let bytes = png(20, 20, 9);
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..12 {
        let (store, cpu, pipe, bytes) = (Arc::clone(&store), cpu.clone(), Arc::clone(&pipe), bytes.clone());
        tasks.spawn(async move {
            pipe.ingest(
                &cpu,
                store.as_ref(),
                &ingest(one, &format!("/dup-{i}.png"), &bytes),
            )
            .await
            .unwrap()
        });
    }
    let mut results = Vec::new();
    while let Some(done) = tasks.join_next().await {
        results.push(done.unwrap());
    }
    assert_eq!(store.writes(), 1);
    assert_eq!(results.iter().filter(|r| !r.deduplicated).count(), 1);
    assert!(results.windows(2).all(|pair| pair[0].stored == pair[1].stored));
    assert_eq!(pipe.usage(&one).images, 1);
}

#[tokio::test]
async fn a_corrupt_png_is_refused_inside_the_cpu_and_byte_quota() {
    let store = RecordingStore::default();
    let cpu = pool(1);
    let good = png(40, 40, 3);
    let mut quota = ImageQuota::default();
    quota.max_scope_bytes = u64::try_from(good.len()).unwrap();
    let pipe = pipeline(ImagePolicy::default(), quota);
    let one = scope();

    // corrupt pixel data: refused after a bounded decode on the pool, nothing written or charged
    let refusal = pipe
        .ingest(&cpu, &store, &ingest(one, "/bad.png", &corrupt(good.clone())))
        .await
        .unwrap_err();
    assert!(
        matches!(refusal, ImageRefusal::Image(ImageError::Corrupt(_))),
        "{refusal:?}"
    );
    // a truncated file is just as corrupt
    let refusal = pipe
        .ingest(&cpu, &store, &ingest(one, "/cut.png", &good[..good.len() / 2]))
        .await
        .unwrap_err();
    assert!(
        matches!(refusal, ImageRefusal::Image(ImageError::Corrupt(_))),
        "{refusal:?}"
    );
    // a pixel bomb is refused from its header, before any pixel is decoded
    let refusal = pipe
        .ingest(&cpu, &store, &ingest(one, "/bomb.png", &pixel_bomb()))
        .await
        .unwrap_err();
    assert!(
        matches!(refusal, ImageRefusal::Image(ImageError::PixelLimit { .. })),
        "{refusal:?}"
    );
    // an unsupported type is refused the same way
    let refusal = pipe
        .ingest(
            &cpu,
            &store,
            &ingest(one, "/x.svg", b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(refusal, ImageRefusal::Image(ImageError::Unsupported)),
        "{refusal:?}"
    );
    assert_eq!(store.writes(), 0);
    assert_eq!(pipe.usage(&one), ScopeUsage::default());

    // the refusals left the whole quota free: the valid image fits exactly (inclusive) ...
    assert!(pipe
        .ingest(&cpu, &store, &ingest(one, "/good.png", &good))
        .await
        .is_ok());
    assert_eq!(pipe.usage(&one).bytes, u64::try_from(good.len()).unwrap());
    // ... and one more distinct byte is over the byte quota and fails closed
    let refusal = pipe
        .ingest(&cpu, &store, &ingest(one, "/more.png", &png(8, 8, 4)))
        .await
        .unwrap_err();
    assert!(matches!(refusal, ImageRefusal::ByteQuota { .. }), "{refusal:?}");
    assert_eq!(store.writes(), 1);
    // a duplicate costs nothing against the quota
    assert!(
        pipe.ingest(&cpu, &store, &ingest(one, "/good-again.png", &good))
            .await
            .unwrap()
            .deduplicated
    );
}

#[tokio::test]
async fn the_image_count_quota_and_the_byte_ceiling_are_inclusive() {
    let store = RecordingStore::default();
    let cpu = pool(2);
    let mut quota = ImageQuota::default();
    quota.max_images = 2;
    let mut policy = ImagePolicy::default();
    let small = png(8, 8, 1);
    policy.max_bytes = png(8, 8, 3).len();
    let pipe = pipeline(policy, quota);
    let one = scope();
    pipe.ingest(&cpu, &store, &ingest(one, "/1.png", &small))
        .await
        .unwrap();
    pipe.ingest(&cpu, &store, &ingest(one, "/2.png", &png(8, 8, 2)))
        .await
        .unwrap();
    assert!(matches!(
        pipe.ingest(&cpu, &store, &ingest(one, "/3.png", &png(8, 8, 3)))
            .await,
        Err(ImageRefusal::TooManyImages { max: 2 })
    ));
    // over the per-image byte ceiling is refused before any CPU is spent on a decode
    let big = png(64, 64, 5);
    assert!(big.len() > policy.max_bytes);
    assert!(matches!(
        pipe.ingest(&cpu, &store, &ingest(scope(), "/big.png", &big))
            .await,
        Err(ImageRefusal::Image(ImageError::TooLarge { .. }))
    ));
    assert_eq!(store.writes(), 2);
}

#[tokio::test]
async fn thumbnails_and_expiry_deadlines_reach_the_store_and_count_against_the_quota() {
    let store = RecordingStore::default();
    let cpu = pool(1);
    let mut policy = ImagePolicy::default();
    policy.thumbnail_edge = Some(8);
    let pipe = pipeline(policy, ImageQuota::default());
    let one = scope();
    let deadline = chrono::DateTime::from_timestamp(1_900_000_000, 0).unwrap();
    let mut request = ingest(one, "/t.png", &png(64, 32, 7));
    request.deadline = Some(deadline);
    let done = pipe.ingest(&cpu, &store, &request).await.unwrap();
    let thumbnail = done.stored.thumbnail.as_ref().unwrap();
    let thumb_bytes = store.get(thumbnail).await.unwrap();
    let thumb = crawlx_extract::images::inspect_image(&thumb_bytes, &ImagePolicy::default()).unwrap();
    assert!(thumb.facts.width <= 8 && thumb.facts.height <= 8);
    let writes = store.writes.lock().clone();
    assert_eq!(writes.len(), 2);
    assert!(
        writes.iter().all(|(_, _, _, d)| *d == Some(deadline)),
        "{writes:?}"
    );
    assert_eq!(writes[0].1, "image/png");
    assert_eq!(
        pipe.usage(&one).bytes,
        u64::try_from(writes[0].2 + writes[1].2).unwrap()
    );
}

#[tokio::test]
async fn a_failed_write_releases_the_reservation_and_a_retry_stores_normally() {
    let store = RecordingStore::default();
    let cpu = pool(1);
    let pipe = pipeline(ImagePolicy::default(), ImageQuota::default());
    let one = scope();
    let bytes = png(16, 16, 4);
    *store.fail_next.lock() = true;
    assert!(matches!(
        pipe.ingest(&cpu, &store, &ingest(one, "/r.png", &bytes)).await,
        Err(ImageRefusal::Store(_))
    ));
    assert_eq!(pipe.usage(&one), ScopeUsage::default());
    let retried = pipe
        .ingest(&cpu, &store, &ingest(one, "/r.png", &bytes))
        .await
        .unwrap();
    assert!(
        !retried.deduplicated,
        "a failed first write must not look like a stored copy"
    );
    assert_eq!(store.writes(), 1);
    assert_eq!(pipe.usage(&one).images, 1);
}

#[tokio::test]
async fn invalid_pipeline_settings_are_refused_at_construction() {
    let mut policy = ImagePolicy::default();
    policy.max_pixels = 0;
    assert!(ImagePipeline::new(policy, ImageQuota::default()).is_err());
    let mut quota = ImageQuota::default();
    quota.max_images = 0;
    assert!(ImagePipeline::new(ImagePolicy::default(), quota).is_err());
}
