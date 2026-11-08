//! Bounded upload admission, retries, cancellation and object-before-reference ordering.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{TimeZone, Utc};
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::{Clock as _, StoreError, TenantId};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{
    artifacts::ArtifactReaper as _, ArtifactBlobs, ArtifactIndex, ArtifactRow, BlobEntry, MemBlobs,
    MemoryStore, ObjectArtifactStore, UploadSpool, UploadSpoolConfig,
};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

// Serialize process-global spool gauge observations.
static METRICS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A real in-memory object backend with deterministic outage and completion barriers.
struct Backend {
    blobs: MemBlobs,
    failures: AtomicUsize,
    head_failures: AtomicUsize,
    delete_failures: AtomicUsize,
    head_attempts: AtomicUsize,
    denied: AtomicBool,
    blocked: AtomicBool,
    block_index: AtomicBool,
    entered: Semaphore,
    release: Semaphore,
    attempts: Mutex<Vec<(String, usize)>>,
}

impl Backend {
    fn new() -> Self {
        Self {
            blobs: MemBlobs::default(),
            failures: AtomicUsize::new(0),
            head_failures: AtomicUsize::new(0),
            delete_failures: AtomicUsize::new(0),
            head_attempts: AtomicUsize::new(0),
            denied: AtomicBool::new(false),
            blocked: AtomicBool::new(false),
            block_index: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            attempts: Mutex::new(Vec::new()),
        }
    }

    async fn wait_for_attempt(&self) {
        self.entered.acquire().await.unwrap().forget();
    }
}

#[derive(Clone)]
struct BackendHandle(Arc<Backend>);

impl std::ops::Deref for BackendHandle {
    type Target = Backend;

    fn deref(&self) -> &Backend {
        &self.0
    }
}

#[async_trait]
impl ArtifactBlobs for BackendHandle {
    fn bucket(&self) -> &str {
        "deterministic"
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.put_shared(key, Bytes::copy_from_slice(bytes)).await
    }

    async fn put_shared(&self, key: &str, bytes: Bytes) -> Result<(), StoreError> {
        self.attempts
            .lock()
            .push((key.to_owned(), bytes.as_ptr() as usize));
        self.entered.add_permits(1);
        if self.blocked.load(Ordering::SeqCst)
            || (self.block_index.load(Ordering::SeqCst) && key.starts_with("_index/"))
        {
            self.release.acquire().await.unwrap().forget();
        }
        if self.denied.load(Ordering::SeqCst) {
            return Err(StoreError::AccessDenied("backend rejects upload".into()));
        }
        if self
            .failures
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(StoreError::Unavailable("deterministic outage".into()));
        }
        self.blobs.put(key, &bytes).await
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.blobs.get(key).await
    }

    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        self.head_attempts.fetch_add(1, Ordering::SeqCst);
        if self
            .head_failures
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(StoreError::Unavailable("deterministic head outage".into()));
        }
        self.blobs.exists(key).await
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        if !key.starts_with("_index/")
            && self
                .delete_failures
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return Err(StoreError::Unavailable(
                "deterministic object delete outage".into(),
            ));
        }
        self.blobs.delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<BlobEntry>, StoreError> {
        self.blobs.list(prefix).await
    }
}

fn spool(bytes: u64, entries: usize) -> Arc<UploadSpool> {
    let mut config = UploadSpoolConfig::default();
    config.max_bytes = bytes;
    config.max_entries = entries;
    config.max_attempts = 3;
    config.retry_delay = Duration::ZERO;
    Arc::new(UploadSpool::new(config).unwrap())
}

#[tokio::test]
async fn outage_retries_are_bounded_reuse_bytes_and_release_capacity() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    backend.failures.store(10, Ordering::SeqCst);
    let spool = spool(8, 1);
    assert!(spool.put(&backend, "object", b"payload").await.is_err());
    let attempts = backend.attempts.lock().clone();
    assert_eq!(attempts.len(), 3);
    assert!(attempts.iter().all(|(_, ptr)| *ptr == attempts[0].1));
    assert_eq!(spool.queued_bytes(), 0);
    assert_eq!(spool.queued_entries(), 0);
    assert!(!backend.exists("object").await.unwrap());

    backend.failures.store(2, Ordering::SeqCst);
    spool.put(&backend, "object", b"payload").await.unwrap();
    assert_eq!(backend.get("object").await.unwrap().unwrap(), b"payload");
    assert_eq!(backend.attempts.lock().len(), 6);
    assert_eq!(spool.queued_bytes(), 0);
}

#[tokio::test]
async fn non_retryable_failures_stop_immediately() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    backend.denied.store(true, Ordering::SeqCst);
    let spool = spool(8, 2);
    assert!(matches!(
        spool.put(&backend, "object", b"data").await,
        Err(StoreError::AccessDenied(_))
    ));
    assert_eq!(backend.attempts.lock().len(), 1);
    assert_eq!(spool.queued_entries(), 0);
}

#[tokio::test]
async fn preflight_outage_retries_inside_the_spool_before_publishing_objects() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    let spool = spool(8, 2);
    backend.head_failures.store(10, Ordering::SeqCst);
    assert!(spool.ensure(&backend, "object", b"data").await.is_err());
    assert_eq!(backend.head_attempts.load(Ordering::SeqCst), 3);
    assert!(backend.attempts.lock().is_empty());
    assert_eq!(spool.queued_entries(), 0);
    backend.head_failures.store(2, Ordering::SeqCst);
    spool.ensure(&backend, "object", b"data").await.unwrap();
    assert_eq!(backend.head_attempts.load(Ordering::SeqCst), 6);
    assert_eq!(backend.get("object").await.unwrap().unwrap(), b"data");
}

#[tokio::test]
async fn stalled_requests_have_bounded_deadlines_and_release_quota() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    backend.blocked.store(true, Ordering::SeqCst);
    let mut config = UploadSpoolConfig::default();
    config.max_attempts = 2;
    config.request_timeout = Duration::from_millis(1);
    config.retry_delay = Duration::ZERO;
    let spool = UploadSpool::new(config).unwrap();
    assert!(
        matches!(spool.put(&backend, "stalled", b"data").await, Err(StoreError::Unavailable(s)) if s == "upload request timed out")
    );
    assert_eq!(backend.attempts.lock().len(), 2);
    assert_eq!(spool.queued_bytes(), 0);
    assert!(backend.list("").await.unwrap().is_empty());
}

#[tokio::test]
async fn shutdown_interrupts_retry_sleep_without_an_extra_attempt() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    backend.failures.store(10, Ordering::SeqCst);
    let mut config = UploadSpoolConfig::default();
    config.retry_delay = Duration::from_secs(3600);
    let spool = UploadSpool::new(config).unwrap();
    let upload = spool.put(&backend, "retrying", b"data");
    tokio::pin!(upload);
    tokio::select! {
        biased;
        result = &mut upload => panic!("upload completed instead of waiting to retry: {result:?}"),
        () = backend.wait_for_attempt() => {}
    }
    spool.cancel();
    assert!(upload.await.is_err());
    assert_eq!(backend.attempts.lock().len(), 1);
    assert_eq!(spool.queued_entries(), 0);
}

#[tokio::test]
async fn queued_bytes_and_entries_are_bounded_and_recovery_drains() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    backend.blocked.store(true, Ordering::SeqCst);
    let spool = spool(4, 2);
    let gauge =
        crawlx_telemetry::Metrics::global().gauge(crawlx_telemetry::metrics::names::OBJECTSTORE_SPOOL_BYTES);
    let before = gauge.get(&[]).unwrap_or_default();
    let first = {
        let backend = backend.clone();
        let spool = spool.clone();
        tokio::spawn(async move { spool.put(&backend, "first", b"1234").await })
    };
    backend.wait_for_attempt().await;
    assert_eq!(spool.queued_bytes(), 4);
    assert_eq!(gauge.get(&[]), Some(before + 4.0));
    assert!(
        matches!(spool.put(&backend, "oversize", b"x").await, Err(StoreError::Unavailable(s)) if s == "upload spool full")
    );

    // Empty uploads consume entry capacity even when byte capacity is exhausted.
    let second = spool.put(&backend, "second", b"");
    tokio::pin!(second);
    tokio::select! {
        biased;
        result = &mut second => panic!("queued upload completed before backend recovery: {result:?}"),
        () = std::future::ready(()) => {}
    }
    assert_eq!(spool.queued_entries(), 2);
    assert!(
        matches!(spool.put(&backend, "third", b"").await, Err(StoreError::Unavailable(s)) if s == "upload spool full")
    );
    backend.blocked.store(false, Ordering::SeqCst);
    backend.release.add_permits(1);
    first.await.unwrap().unwrap();
    second.await.unwrap();
    assert_eq!(spool.queued_entries(), 0);
    assert_eq!(spool.queued_bytes(), 0);
    assert_eq!(backend.list("").await.unwrap().len(), 2);
    assert_eq!(gauge.get(&[]), Some(before));
}

#[tokio::test]
async fn dropping_queued_callers_and_shutdown_release_capacity_without_background_uploads() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    backend.blocked.store(true, Ordering::SeqCst);
    let spool = spool(8, 2);
    let active = spool.put(&backend, "active", b"1234");
    tokio::pin!(active);
    tokio::select! {
        biased;
        result = &mut active => panic!("blocked upload completed: {result:?}"),
        () = backend.wait_for_attempt() => {}
    }
    {
        let queued = spool.put(&backend, "queued", b"1234");
        tokio::pin!(queued);
        tokio::select! {
            biased;
            result = &mut queued => panic!("queued upload completed: {result:?}"),
            () = std::future::ready(()) => {}
        }
        assert_eq!(spool.queued_entries(), 2);
    }
    assert_eq!(spool.queued_entries(), 1);
    spool.cancel();
    assert!(active.await.is_err());
    assert_eq!(spool.queued_bytes(), 0);
    assert_eq!(backend.attempts.lock().len(), 1);
    assert!(backend.list("").await.unwrap().is_empty());
    assert!(spool.put(&backend, "after-stop", b"x").await.is_err());
}

#[tokio::test]
async fn dropping_active_upload_releases_uploader_to_the_next_queued_caller() {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    backend.blocked.store(true, Ordering::SeqCst);
    let spool = spool(8, 2);
    let queued = spool.put(&backend, "queued", b"next");
    tokio::pin!(queued);
    {
        let active = spool.put(&backend, "active", b"lost");
        tokio::pin!(active);
        tokio::select! {
            biased;
            result = &mut active => panic!("blocked upload completed: {result:?}"),
            () = backend.wait_for_attempt() => {}
        }
        tokio::select! {
            biased;
            result = &mut queued => panic!("queued upload completed: {result:?}"),
            () = std::future::ready(()) => {}
        }
        assert_eq!(spool.queued_entries(), 2);
    }
    assert_eq!(spool.queued_bytes(), 4);
    backend.blocked.store(false, Ordering::SeqCst);
    queued.await.unwrap();
    assert_eq!(spool.queued_entries(), 0);
    assert!(!backend.exists("active").await.unwrap());
    assert_eq!(backend.get("queued").await.unwrap().unwrap(), b"next");
}

struct Index {
    backend: BackendHandle,
    rows: Mutex<Vec<ArtifactRow>>,
}

#[async_trait]
impl ArtifactIndex for Index {
    async fn record(&self, row: &ArtifactRow) -> Result<(), StoreError> {
        assert!(self.backend.exists(&row.object_key).await?);
        let key = format!("_index/{}.json", row.id);
        let saved = self.backend.get(&key).await?.unwrap();
        let indexed: ArtifactRow = serde_json::from_slice(&saved).unwrap();
        assert_eq!(&indexed, row);
        self.rows.lock().push(row.clone());
        Ok(())
    }

    async fn retention(
        &self,
        id: crawlx_core::ArtifactId,
    ) -> Result<Option<crawlx_storage::artifacts::ArtifactRetention>, StoreError> {
        Ok(self
            .rows
            .lock()
            .iter()
            .find(|row| row.id == id)
            .map(|row| crawlx_storage::artifacts::ArtifactRetention::new(row.expires_at, None)))
    }

    async fn mark_deleted(&self, ids: &[crawlx_core::ArtifactId]) -> Result<(), StoreError> {
        self.rows.lock().retain(|row| !ids.contains(&row.id));
        Ok(())
    }
}

async fn store() -> (
    ObjectArtifactStore<BackendHandle>,
    BackendHandle,
    Arc<Index>,
    Arc<UploadSpool>,
    crawlx_core::CrawlRunId,
) {
    let backend = BackendHandle(Arc::new(Backend::new()));
    let index = Arc::new(Index {
        backend: backend.clone(),
        rows: Mutex::new(Vec::new()),
    });
    let runs = Arc::new(MemoryStore::new());
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Standard;
    let run = crawl_run(TenantId::new(), config);
    runs.create(&run, None).await.unwrap();
    let spool = spool(4096, 8);
    let clock = ManualClock::new(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    let store = ObjectArtifactStore::new(backend.clone(), runs, Arc::new(clock))
        .with_index(index.clone())
        .with_upload_spool(spool.clone());
    (store, backend, index, spool, run.id)
}

#[tokio::test]
async fn object_completion_precedes_index_upload_and_metadata_commit() {
    let _metrics = METRICS_LOCK.lock().await;
    let (store, backend, index, spool, run) = store().await;
    backend.blocked.store(true, Ordering::SeqCst);
    let upload = store.put(run, Sensitivity::Content, "text/html", b"<p>content</p>");
    tokio::pin!(upload);
    tokio::select! {
        biased;
        result = &mut upload => panic!("blocked artifact completed: {result:?}"),
        () = backend.wait_for_attempt() => {}
    }
    assert!(index.rows.lock().is_empty());
    assert!(backend.list("_index/").await.unwrap().is_empty());
    backend.blocked.store(false, Ordering::SeqCst);
    backend.release.add_permits(1);
    let artifact = upload.await.unwrap();
    assert_eq!(store.get(&artifact).await.unwrap(), b"<p>content</p>");
    assert_eq!(index.rows.lock().len(), 1);
    let attempts = backend.attempts.lock();
    assert!(attempts[0].0.starts_with("content/"));
    assert!(attempts[1].0.starts_with("_index/"));
    assert_eq!(spool.queued_bytes(), 0);
}

#[tokio::test]
async fn failed_or_cancelled_object_upload_never_commits_references() {
    let _metrics = METRICS_LOCK.lock().await;
    let (store, backend, index, spool, run) = store().await;
    backend.failures.store(10, Ordering::SeqCst);
    assert!(store
        .put(run, Sensitivity::Content, "text/html", b"failed")
        .await
        .is_err());
    assert!(index.rows.lock().is_empty());
    assert!(backend.list("").await.unwrap().is_empty());

    backend.blocked.store(true, Ordering::SeqCst);
    {
        let upload = store.put(run, Sensitivity::Content, "text/html", b"cancelled");
        tokio::pin!(upload);
        tokio::select! {
            biased;
            result = &mut upload => panic!("blocked artifact completed: {result:?}"),
            () = std::future::ready(()) => {}
        }
        assert_eq!(spool.queued_entries(), 1);
    }
    assert_eq!(spool.queued_bytes(), 0);
    assert!(index.rows.lock().is_empty());
    assert!(backend.list("").await.unwrap().is_empty());
}

#[tokio::test]
async fn cancellation_during_index_upload_leaves_only_an_orphan_object() {
    let _metrics = METRICS_LOCK.lock().await;
    let (store, backend, index, spool, run) = store().await;
    backend.block_index.store(true, Ordering::SeqCst);
    {
        let upload = store.put(run, Sensitivity::Content, "text/html", b"orphan");
        tokio::pin!(upload);
        tokio::select! {
            biased;
            result = &mut upload => panic!("blocked index upload completed: {result:?}"),
            () = async {
                backend.wait_for_attempt().await;
                backend.wait_for_attempt().await;
            } => {}
        }
        assert_eq!(backend.list("content/").await.unwrap().len(), 1);
        assert!(backend.list("_index/").await.unwrap().is_empty());
        assert!(index.rows.lock().is_empty());
    }
    assert_eq!(spool.queued_bytes(), 0);
    assert!(index.rows.lock().is_empty());
    assert!(backend.list("_index/").await.unwrap().is_empty());
    assert_eq!(backend.list("content/").await.unwrap().len(), 1);

    // A later call reuses the orphan object, but failed index retries still
    // cannot publish a database reference.
    backend.block_index.store(false, Ordering::SeqCst);
    backend.failures.store(10, Ordering::SeqCst);
    let before = backend.attempts.lock().len();
    assert!(store
        .put(run, Sensitivity::Content, "text/html", b"orphan")
        .await
        .is_err());
    assert_eq!(backend.attempts.lock().len() - before, 3);
    assert!(index.rows.lock().is_empty());
    assert!(backend.list("_index/").await.unwrap().is_empty());
    assert_eq!(backend.list("content/").await.unwrap().len(), 1);
}

async fn assert_secret_erasure_retry(terminal: bool) {
    let _metrics = METRICS_LOCK.lock().await;
    let backend = BackendHandle(Arc::new(Backend::new()));
    let clock = ManualClock::new(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());
    let runs = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Standard;
    config.retention.days = 7;
    let run = crawl_run(TenantId::new(), config.clone());
    let foreign_run = crawl_run(TenantId::new(), config);
    runs.create(&run, None).await.unwrap();
    runs.create(&foreign_run, None).await.unwrap();
    let index = Arc::new(Index {
        backend: backend.clone(),
        rows: Mutex::new(Vec::new()),
    });
    let store = ObjectArtifactStore::new(backend.clone(), runs.clone(), Arc::new(clock.clone()))
        .with_index(index.clone())
        .with_upload_spool(spool(4096, 8));
    let secret_bytes = br#"{"cookies":[{"name":"session","value":"delete-retry-secret"}],"origins":[]}"#;
    let secret = store
        .put(
            run.id,
            Sensitivity::CredentialBearing,
            "application/json",
            secret_bytes,
        )
        .await
        .unwrap();
    let mut live = Vec::new();
    for run in [run.id, run.id, foreign_run.id] {
        live.push(
            store
                .put(run, Sensitivity::Content, "text/plain", b"live content")
                .await
                .unwrap(),
        );
    }
    let rows = index.rows.lock().clone();
    assert_eq!(rows[1].object_key, rows[2].object_key);
    assert_ne!(rows[1].object_key, rows[3].object_key);
    let cursor = format!("_index/{}.json", secret.id);
    let cursor_bytes = backend.get(&cursor).await.unwrap().unwrap();
    let row: ArtifactRow = serde_json::from_slice(&cursor_bytes).unwrap();
    assert_eq!(row.id, secret.id);
    assert_eq!(backend.get(&row.object_key).await.unwrap().unwrap(), secret_bytes);

    if terminal {
        runs.set_status(
            run.id,
            crawlx_core::counters::RunStatus::Completed,
            Some(crawlx_core::counters::TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
        assert!(
            row.expires_at.unwrap() > clock.now(),
            "terminal revocation must precede the old TTL"
        );
    } else {
        // Credential-bearing state expires after one day; content remains live for seven.
        clock.advance_ms(24 * 3_600_000 + 1_000);
        assert!(row.expires_at.is_some_and(|expiry| expiry <= clock.now()));
    }
    assert!(matches!(
        store.get(&secret).await,
        Err(StoreError::NotFound { .. })
    ));
    backend.delete_failures.store(1, Ordering::SeqCst);
    let erased = if terminal {
        store.erase_run_credentials(run.id).await
    } else {
        store.reap_expired(clock.now()).await
    };
    assert!(matches!(
        erased,
        Err(StoreError::Unavailable(message)) if message == "deterministic object delete outage"
    ));
    assert_eq!(backend.delete_failures.load(Ordering::SeqCst), 0);
    assert_eq!(backend.get(&row.object_key).await.unwrap().unwrap(), secret_bytes);
    assert_eq!(backend.get(&cursor).await.unwrap().unwrap(), cursor_bytes);
    assert!(index.retention(secret.id).await.unwrap().is_some());

    // The bounded outage has recovered. The ordinary sweep must rediscover the cursor.
    assert_eq!(store.reap_expired(clock.now()).await.unwrap(), 1);
    assert!(backend.get(&row.object_key).await.unwrap().is_none());
    assert!(backend.get(&cursor).await.unwrap().is_none());
    assert!(index.retention(secret.id).await.unwrap().is_none());
    assert_eq!(store.reap_expired(clock.now()).await.unwrap(), 0);
    for artifact in &live {
        let live_row = rows.iter().find(|row| row.id == artifact.id).unwrap();
        assert_eq!(store.get(artifact).await.unwrap(), b"live content");
        assert_eq!(
            backend.get(&live_row.object_key).await.unwrap().unwrap(),
            b"live content"
        );
        assert!(backend
            .get(&format!("_index/{}.json", artifact.id))
            .await
            .unwrap()
            .is_some());
        assert!(index.retention(artifact.id).await.unwrap().is_some());
    }
    for entry in backend.list("").await.unwrap() {
        let bytes = backend.get(&entry.key).await.unwrap().unwrap();
        assert!(
            !bytes
                .windows(b"delete-retry-secret".len())
                .any(|window| window == b"delete-retry-secret"),
            "expired secret bytes remain in object storage"
        );
    }
}

#[tokio::test]
async fn expired_artifact_delete_failure_keeps_retry_cursor_until_secret_bytes_are_removed() {
    assert_secret_erasure_retry(false).await;
}

#[tokio::test]
async fn terminal_secret_delete_failure_keeps_retry_cursor_for_the_ordinary_sweeper() {
    assert_secret_erasure_retry(true).await;
}
