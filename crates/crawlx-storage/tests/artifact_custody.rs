//! Encrypted artifact custody: the secret-registered-during-upload race, round trips,
//! tamper detection, legacy plaintext reads and the missing-producer refusal.
//!
//! The PostgreSQL variant needs `CRAWLX_TEST_DATABASE_URL` and a dedicated secret-custody
//! Valkey in `CRAWLX_TEST_SECRET_REDIS_URL`; it reports and returns when either is absent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use crawlx_core::config::RetentionMode;
use crawlx_core::custody::{with_producer, CustodyLease, SecretRegistrar as _};
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::{CrawlRunId, SecretOr, SessionId, StoreError, TenantId, WorkerId};
use crawlx_storage::artifact_custody::{
    ArtifactCustody, CustodyWrites, LeasedSecretRegistrar, LocalArtifactCustody, PgArtifactCustody,
};
use crawlx_storage::artifact_key_crypto::{ArtifactKeys, FileArtifactKeys, MemoryArtifactKeys};
use crawlx_storage::artifacts::{ArtifactBlobs, BlobEntry, FsArtifactStore, MemBlobs, ObjectArtifactStore};
use crawlx_storage::custody::PgSecretAuthority;
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_storage::{MemoryStore, Pg, PgConfig};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use uuid::Uuid;

const BODY: &[u8] = b"<html>reflected-captcha-token-8812</html>";

/// In-memory blobs whose first encrypted-object upload can be paused mid-flight.
struct PausedBlobs {
    inner: MemBlobs,
    armed: AtomicBool,
    entered: Semaphore,
    release: Semaphore,
    received: Mutex<Vec<Vec<u8>>>,
    fail_delete: AtomicBool,
}

impl PausedBlobs {
    fn new() -> Self {
        Self {
            inner: MemBlobs::default(),
            armed: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            received: Mutex::new(Vec::new()),
            fail_delete: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl ArtifactBlobs for PausedBlobs {
    fn bucket(&self) -> &str {
        self.inner.bucket()
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.put_shared(key, Bytes::copy_from_slice(bytes)).await
    }
    async fn put_shared(&self, key: &str, bytes: Bytes) -> Result<(), StoreError> {
        if key.starts_with("encrypted/") {
            self.received.lock().push(bytes.to_vec());
            if self.armed.swap(false, Ordering::SeqCst) {
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
            }
        } else if key.starts_with("content/") || key.starts_with("sensitive/") {
            self.received.lock().push(bytes.to_vec());
        }
        self.inner.put(key, &bytes).await
    }
    async fn reader(&self, key: &str) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        self.inner.reader(key).await
    }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.get(key).await
    }
    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        self.inner.exists(key).await
    }
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        if self.fail_delete.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable("injected delete failure".into()));
        }
        self.inner.delete(key).await
    }
    async fn list(&self, prefix: &str) -> Result<Vec<BlobEntry>, StoreError> {
        self.inner.list(prefix).await
    }
}

fn temp_key_file(byte: u8) -> (tempfile::TempDir, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact.key");
    std::fs::write(&path, format!("{}\n", format!("{byte:02x}").repeat(32))).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path)
}

fn file_keys(path: &std::path::Path) -> Arc<dyn ArtifactKeys> {
    let path = path.to_string_lossy().into_owned();
    Arc::new(
        FileArtifactKeys::from_lookup(&|name| (name == "CRAWLX_ARTIFACT_KEY_FILE").then(|| path.clone()))
            .unwrap()
            .unwrap(),
    )
}

struct Local {
    runs: Arc<MemoryStore>,
    clock: ManualClock,
    tenant: TenantId,
    run: CrawlRunId,
    custody: Arc<LocalArtifactCustody>,
    lease: CustodyLease,
}

async fn local() -> Local {
    let clock = ManualClock::new(Utc::now());
    let runs = Arc::new(MemoryStore::with_clock(Arc::new(clock.clone())));
    let tenant = TenantId::new();
    let mut config = create_crawl("https://example.test/", &[], 1);
    config.retention.mode = RetentionMode::Standard;
    config.retention.days = 7;
    let run = crawl_run(tenant, config);
    runs.create(&run, None).await.unwrap();
    Local {
        lease: CustodyLease::new(tenant, run.id, SessionId::new(), WorkerId::new(), 1),
        runs,
        clock,
        tenant,
        run: run.id,
        custody: Arc::new(LocalArtifactCustody::new()),
    }
}

impl Local {
    fn store<B: ArtifactBlobs>(&self, blobs: B, writes: CustodyWrites) -> ObjectArtifactStore<B> {
        ObjectArtifactStore::new(blobs, self.runs.clone(), Arc::new(self.clock.clone()))
            .with_index(self.runs.clone())
            .with_custody(
                self.custody.clone(),
                Arc::new(MemoryArtifactKeys::new().unwrap()),
                writes,
            )
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[tokio::test]
async fn secret_registered_during_paused_upload_is_never_published_or_readable_local() {
    let w = local().await;
    let store = Arc::new(w.store(PausedBlobs::new(), CustodyWrites::Required));
    store.blobs().armed.store(true, Ordering::SeqCst);
    let writer = {
        let store = Arc::clone(&store);
        let run = w.run;
        tokio::spawn(with_producer(w.lease.clone(), async move {
            store.put(run, Sensitivity::Content, "text/html", BODY).await
        }))
    };
    store.blobs().entered.acquire().await.unwrap().forget();
    // The worker already scanned the body against the then-current registry; now a second
    // worker's CAPTCHA token (equal to the body) is registered run-wide.
    w.custody
        .register(
            &w.lease,
            &SecretOr::secret(String::from_utf8(BODY.to_vec()).unwrap()),
        )
        .await
        .unwrap();
    store.blobs().release.add_permits(1);
    let outcome = writer.await.unwrap();
    assert!(
        matches!(outcome, Err(StoreError::RetentionDenied(_))),
        "unexpected {outcome:?}"
    );
    let blobs = store.blobs();
    assert!(
        blobs.list("").await.unwrap().is_empty(),
        "no object or index record may remain"
    );
    let received = blobs.received.lock();
    assert_eq!(received.len(), 1);
    assert_ne!(received[0], BODY);
    assert!(!contains(&received[0], b"reflected-captcha-token"));
}

#[tokio::test]
async fn rejected_publication_with_undeletable_stage_reports_unresolved_object() {
    let w = local().await;
    let store = Arc::new(w.store(PausedBlobs::new(), CustodyWrites::Required));
    store.blobs().armed.store(true, Ordering::SeqCst);
    let writer = {
        let store = Arc::clone(&store);
        let run = w.run;
        tokio::spawn(with_producer(w.lease.clone(), async move {
            store.put(run, Sensitivity::Content, "text/html", BODY).await
        }))
    };
    store.blobs().entered.acquire().await.unwrap().forget();
    store.blobs().fail_delete.store(true, Ordering::SeqCst);
    w.custody
        .register(
            &w.lease,
            &SecretOr::secret(String::from_utf8(BODY.to_vec()).unwrap()),
        )
        .await
        .unwrap();
    store.blobs().release.add_permits(1);
    match writer.await.unwrap() {
        Err(StoreError::Unavailable(detail)) => assert!(detail.contains("unresolved"), "{detail}"),
        other => panic!("unexpected {other:?}"),
    }
    // The orphan stays on the backend for the reaper, but is not published.
    assert_eq!(store.blobs().inner.object_keys().len(), 1);
    store.blobs().fail_delete.store(false, Ordering::SeqCst);
    let removed = crawlx_storage::ArtifactReaper::collect_orphans(
        store.as_ref(),
        &crawlx_storage::LiveArtifacts::default(),
        Utc::now() + chrono::Duration::hours(1),
    )
    .await
    .unwrap();
    assert_eq!(removed, 1, "the reaper collects the unpublished encrypted object");
    assert!(store.blobs().inner.object_keys().is_empty());
}

#[tokio::test]
async fn unrelated_secret_registered_during_upload_retries_publication_and_succeeds() {
    let w = local().await;
    let store = Arc::new(w.store(PausedBlobs::new(), CustodyWrites::Required));
    store.blobs().armed.store(true, Ordering::SeqCst);
    let writer = {
        let store = Arc::clone(&store);
        let run = w.run;
        tokio::spawn(with_producer(w.lease.clone(), async move {
            store.put(run, Sensitivity::Content, "text/html", BODY).await
        }))
    };
    store.blobs().entered.acquire().await.unwrap().forget();
    w.custody
        .register(&w.lease, &SecretOr::secret("unrelated-token-value".into()))
        .await
        .unwrap();
    store.blobs().release.add_permits(1);
    let reference = writer.await.unwrap().unwrap();
    assert_eq!(store.get(&reference).await.unwrap(), BODY);
}

#[tokio::test]
async fn leased_registrar_registers_run_wide_and_mirrors_into_the_local_registry() {
    let w = local().await;
    let local_secrets = crawlx_core::captcha::CaptchaSecrets::default();
    let registrar = LeasedSecretRegistrar::new(w.custody.clone(), w.lease.clone(), local_secrets.clone());
    registrar
        .register(&SecretOr::secret("solver-token-77".into()))
        .await
        .unwrap();
    assert!(local_secrets.contains_bytes(b"x solver-token-77 y").unwrap());
    let snapshot = w.custody.snapshot(&w.lease).await.unwrap();
    assert!(snapshot.secrets.contains_bytes(b"solver-token-77").unwrap());
    assert!(!format!("{registrar:?}").contains("solver-token-77"));
    // A write containing the registered token is refused before anything is uploaded.
    let store = w.store(PausedBlobs::new(), CustodyWrites::Required);
    let refused = with_producer(
        w.lease.clone(),
        store.put(w.run, Sensitivity::Content, "text/plain", b"echo solver-token-77"),
    )
    .await;
    assert!(
        matches!(refused, Err(StoreError::RetentionDenied(_))),
        "{refused:?}"
    );
    assert!(store.blobs().received.lock().is_empty());
}

#[tokio::test]
async fn sealed_round_trip_returns_exact_plaintext_through_every_read_path() {
    let w = local().await;
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
            .await
            .unwrap()
            .with_index(w.runs.clone())
            .with_custody(
                w.custody.clone(),
                Arc::new(MemoryArtifactKeys::new().unwrap()),
                CustodyWrites::Required,
            )
            .with_read_scope(w.tenant, w.run),
    );
    let large: Vec<u8> = (0..200_000u32).map(|n| u8::try_from(n % 251).unwrap()).collect();
    let (content, sensitive, big) = with_producer(w.lease.clone(), async {
        (
            store
                .put(w.run, Sensitivity::Content, "text/html", BODY)
                .await
                .unwrap(),
            store
                .put(w.run, Sensitivity::Sensitive, "application/json", b"{\"ax\":1}")
                .await
                .unwrap(),
            store
                .put(w.run, Sensitivity::Content, "application/octet-stream", &large)
                .await
                .unwrap(),
        )
    })
    .await;

    assert_eq!(store.get(&content).await.unwrap(), BODY);
    assert_eq!(store.get(&sensitive).await.unwrap(), b"{\"ax\":1}");
    assert_eq!(store.get(&big).await.unwrap(), large);
    assert_eq!(store.read_content_limited(&content, 1024).await.unwrap(), BODY);
    assert_eq!(store.read_content_limited(&big, 1 << 20).await.unwrap(), large);
    assert!(matches!(
        store.read_content_limited(&big, 1024).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert_eq!(
        store
            .read_archive_content(w.tenant, w.run, &content, 1024)
            .await
            .unwrap(),
        BODY
    );
    let mut streamed = Vec::new();
    {
        use futures::TryStreamExt as _;
        let mut stream = store.stream_content(&big, 1 << 20).await.unwrap();
        while let Some(chunk) = stream.try_next().await.unwrap() {
            streamed.extend_from_slice(&chunk);
        }
    }
    assert_eq!(streamed, large);
    let copy = dir.path().join("copy.bin");
    assert_eq!(
        store
            .copy_archive_content(w.tenant, w.run, &big, &copy, 1 << 20)
            .await
            .unwrap(),
        large.len() as u64
    );
    assert_eq!(std::fs::read(&copy).unwrap(), large);
    assert_eq!(
        store
            .get_bounded(&content, Sensitivity::Content, 1024)
            .await
            .unwrap(),
        BODY
    );
    assert_eq!(
        store
            .get_bounded(&sensitive, Sensitivity::Sensitive, 1024)
            .await
            .unwrap(),
        b"{\"ax\":1}"
    );
    // Sealed objects are never presigned.
    assert!(matches!(
        store.presign(&content, Duration::from_secs(30)).await,
        Err(StoreError::AccessDenied(detail)) if detail == "sealed artifact cannot be presigned"
    ));

    // The plaintext object is never written: nothing on disk contains the body.
    let mut seen = 0;
    for entry in walk(dir.path()) {
        let bytes = std::fs::read(&entry).unwrap();
        assert!(
            !contains(&bytes, b"reflected-captcha-token"),
            "{}",
            entry.display()
        );
        seen += 1;
    }
    assert!(seen >= 6);
    assert!(!dir
        .path()
        .join(format!("content/{}/{}", w.tenant, w.run))
        .exists());

    // Archive file path: sealed from a file, read back byte for byte.
    let source = dir.path().join("source.warc");
    std::fs::write(&source, &large).unwrap();
    let archive = with_producer(
        w.lease.clone(),
        store.put_archive_file(w.run, "application/warc", &source, 1 << 20),
    )
    .await
    .unwrap();
    assert_eq!(store.get(&archive).await.unwrap(), large);
    let again = dir.path().join("again.warc");
    store
        .copy_archive_content(w.tenant, w.run, &archive, &again, 1 << 20)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&again).unwrap(), large);
    // ...and a source file that contains a registered secret is refused without publication.
    w.custody
        .register(&w.lease, &SecretOr::secret("reflected-captcha-token-8812".into()))
        .await
        .unwrap();
    let tainted = dir.path().join("tainted.warc");
    std::fs::write(&tainted, BODY).unwrap();
    let refused = with_producer(
        w.lease.clone(),
        store.put_archive_file(w.run, "application/warc", &tainted, 1 << 20),
    )
    .await;
    assert!(
        matches!(refused, Err(StoreError::RetentionDenied(_))),
        "{refused:?}"
    );
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

#[tokio::test]
async fn tampered_ciphertext_is_refused_and_no_plaintext_is_returned() {
    let w = local().await;
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap()
        .with_index(w.runs.clone())
        .with_custody(
            w.custody.clone(),
            Arc::new(MemoryArtifactKeys::new().unwrap()),
            CustodyWrites::Required,
        )
        .with_read_scope(w.tenant, w.run);
    let reference = with_producer(
        w.lease.clone(),
        store.put(w.run, Sensitivity::Content, "text/html", BODY),
    )
    .await
    .unwrap();
    let object = walk(&dir.path().join("encrypted")).pop().unwrap();
    let pristine = std::fs::read(&object).unwrap();
    for offset in [0, 25, pristine.len() - 1] {
        let mut tampered = pristine.clone();
        tampered[offset] ^= 0x01;
        std::fs::write(&object, &tampered).unwrap();
        assert!(store.get(&reference).await.is_err(), "flip at {offset}");
        assert!(store.read_content_limited(&reference, 1024).await.is_err());
        assert!(store
            .get_bounded(&reference, Sensitivity::Content, 1024)
            .await
            .is_err());
        let copy = dir.path().join("tampered.copy");
        assert!(store
            .copy_archive_content(w.tenant, w.run, &reference, &copy, 1024)
            .await
            .is_err());
        assert!(!copy.exists(), "unverified plaintext must not remain on disk");
        use futures::TryStreamExt as _;
        let delivered = match store.stream_content(&reference, 1024).await {
            Err(_) => Vec::new(),
            Ok(mut stream) => {
                let mut delivered = Vec::new();
                let mut failed = false;
                loop {
                    match stream.try_next().await {
                        Ok(Some(chunk)) => delivered.extend_from_slice(&chunk),
                        Ok(None) => break,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                assert!(failed, "a tampered stream must end in an error");
                delivered
            }
        };
        assert!(
            delivered.is_empty(),
            "the final chunk is withheld until verification"
        );
    }
    // Truncation and appended bytes are refused as well.
    std::fs::write(&object, &pristine[..pristine.len() - 3]).unwrap();
    assert!(store.get(&reference).await.is_err());
    let mut extended = pristine.clone();
    extended.push(0);
    std::fs::write(&object, &extended).unwrap();
    assert!(store.get(&reference).await.is_err());
    std::fs::write(&object, &pristine).unwrap();
    assert_eq!(store.get(&reference).await.unwrap(), BODY);
}

#[tokio::test]
async fn legacy_plaintext_artifacts_stay_readable_after_custody_is_attached() {
    let w = local().await;
    let dir = tempfile::tempdir().unwrap();
    let legacy_store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap()
        .with_index(w.runs.clone());
    let legacy = legacy_store
        .put(w.run, Sensitivity::Content, "text/html", b"<p>legacy</p>")
        .await
        .unwrap();
    let source = dir.path().join("legacy.warc");
    std::fs::write(&source, b"legacy archive").unwrap();
    let legacy_archive = legacy_store
        .put_archive_file(w.run, "application/warc", &source, 1024)
        .await
        .unwrap();

    let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap()
        .with_index(w.runs.clone())
        .with_custody(
            w.custody.clone(),
            Arc::new(MemoryArtifactKeys::new().unwrap()),
            CustodyWrites::Required,
        )
        .with_read_scope(w.tenant, w.run);
    assert_eq!(store.get(&legacy).await.unwrap(), b"<p>legacy</p>");
    assert_eq!(
        store.read_content_limited(&legacy, 1024).await.unwrap(),
        b"<p>legacy</p>"
    );
    assert_eq!(
        store
            .get_bounded(&legacy, Sensitivity::Content, 1024)
            .await
            .unwrap(),
        b"<p>legacy</p>"
    );
    let copy = dir.path().join("legacy.copy");
    store
        .copy_archive_content(w.tenant, w.run, &legacy_archive, &copy, 1024)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&copy).unwrap(), b"legacy archive");
    // Legacy plaintext artifacts keep their ordinary presign gate (no sealed denial).
    assert!(store
        .presign(&legacy, Duration::from_secs(30))
        .await
        .unwrap()
        .is_none());
    // Metadata is outside the sealed classes and stays plaintext under a producer-less write.
    let manifest = store
        .put(w.run, Sensitivity::Metadata, "application/json", b"{\"m\":1}")
        .await
        .unwrap();
    assert_eq!(store.get(&manifest).await.unwrap(), b"{\"m\":1}");
}

#[tokio::test]
async fn required_writes_without_a_current_producer_are_unavailable() {
    let w = local().await;
    let store = w.store(PausedBlobs::new(), CustodyWrites::Required);
    for class in [Sensitivity::Content, Sensitivity::Sensitive] {
        let refused = store.put(w.run, class, "text/html", BODY).await;
        assert!(
            matches!(&refused, Err(StoreError::Unavailable(detail)) if detail.contains("producer lease required")),
            "{refused:?}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("a.warc");
    std::fs::write(&source, b"x").unwrap();
    assert!(matches!(
        store
            .put_archive_file(w.run, "application/warc", &source, 16)
            .await,
        Err(StoreError::Unavailable(_))
    ));
    assert!(store.blobs().received.lock().is_empty());
    // A producer for another run is not accepted either.
    let foreign = CustodyLease::new(w.tenant, CrawlRunId::new(), SessionId::new(), WorkerId::new(), 1);
    let refused = with_producer(foreign, store.put(w.run, Sensitivity::Content, "text/html", BODY)).await;
    assert!(matches!(refused, Err(StoreError::AccessDenied(_))), "{refused:?}");
    // ReadOnly custody never needs a producer: operator inputs stay plaintext.
    let operator = w.store(PausedBlobs::new(), CustodyWrites::ReadOnly);
    let reference = operator
        .put(w.run, Sensitivity::Sensitive, "application/json", b"{}")
        .await
        .unwrap();
    assert_eq!(operator.get(&reference).await.unwrap(), b"{}");
    assert!(operator
        .blobs()
        .inner
        .object_keys()
        .iter()
        .all(|key| key.starts_with("sensitive/")));
}

struct Pgw {
    pg: Pg,
    peer: Pg,
    tenant: TenantId,
    run: CrawlRunId,
    lease_a: CustodyLease,
    lease_b: CustodyLease,
    custody_a: Arc<PgArtifactCustody>,
    custody_b: Arc<PgArtifactCustody>,
}

async fn pg_world() -> Option<Pgw> {
    use crawlx_core::counters::RunStatus;
    use crawlx_storage::leases::LeaseRepo as _;
    let Ok(database) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        eprintln!("SKIPPED: CRAWLX_TEST_DATABASE_URL is not set");
        return None;
    };
    let Ok(redis_url) = std::env::var("CRAWLX_TEST_SECRET_REDIS_URL") else {
        eprintln!("SKIPPED: CRAWLX_TEST_SECRET_REDIS_URL is not set");
        return None;
    };
    let config = PgConfig {
        schema: Some(format!("artcustody_{}", Uuid::now_v7().simple())),
        ..PgConfig::default()
    };
    let pg = Pg::connect(&database, config.clone()).await.unwrap();
    pg.migrate().await.unwrap();
    let peer = Pg::connect(&database, config).await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "artifact-custody-regression")
        .await
        .unwrap();
    let run = crawl_run(tenant, create_crawl("https://example.test/", &["role0"], 2));
    pg.create(&run, None).await.unwrap();
    pg.create_sessions(&sessions(run.id, 1, 2)).await.unwrap();
    pg.set_status(run.id, RunStatus::Running, None).await.unwrap();
    let first = pg
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let second = peer
        .claim_session(run.id, WorkerId::new(), true)
        .await
        .unwrap()
        .unwrap();
    let lease = |claim: &crawlx_storage::leases::SessionLease| {
        CustodyLease::new(
            tenant,
            run.id,
            claim.session.id,
            claim.worker,
            claim.fencing_token,
        )
    };
    let ttl = Duration::from_secs(120);
    Some(Pgw {
        custody_a: Arc::new(PgArtifactCustody::new(
            PgSecretAuthority::open(pg.clone(), &redis_url, ttl)
                .await
                .unwrap(),
        )),
        custody_b: Arc::new(PgArtifactCustody::new(
            PgSecretAuthority::open(peer.clone(), &redis_url, ttl)
                .await
                .unwrap(),
        )),
        lease_a: lease(&first),
        lease_b: lease(&second),
        pg,
        peer,
        tenant,
        run: run.id,
    })
}

#[tokio::test]
async fn secret_registered_on_another_worker_during_paused_upload_is_never_published_pg() {
    let Some(w) = pg_world().await else {
        return;
    };
    eprintln!("RAN: secret_registered_on_another_worker_during_paused_upload_is_never_published_pg");
    let (_dir, key_path) = temp_key_file(0x5a);
    let keys = file_keys(&key_path);
    let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
    // Worker B uploads through its own PostgreSQL handle and its own custody instance.
    let store = Arc::new(
        ObjectArtifactStore::new(PausedBlobs::new(), Arc::new(w.peer.clone()), clock)
            .with_index(Arc::new(w.peer.clone()))
            .with_custody(w.custody_b.clone(), keys.clone(), CustodyWrites::Required),
    );
    store.blobs().armed.store(true, Ordering::SeqCst);
    let writer = {
        let store = Arc::clone(&store);
        let run = w.run;
        tokio::spawn(with_producer(w.lease_b.clone(), async move {
            store.put(run, Sensitivity::Content, "text/html", BODY).await
        }))
    };
    store.blobs().entered.acquire().await.unwrap().forget();
    // Worker A registers the CAPTCHA token (equal to the body) through its own instance.
    w.custody_a
        .register(
            &w.lease_a,
            &SecretOr::secret(String::from_utf8(BODY.to_vec()).unwrap()),
        )
        .await
        .unwrap();
    store.blobs().release.add_permits(1);
    let outcome = writer.await.unwrap();
    assert!(
        matches!(outcome, Err(StoreError::RetentionDenied(_))),
        "unexpected {outcome:?}"
    );
    let rows: (i64, i64) =
        sqlx::query_as("SELECT (SELECT count(*) FROM artifacts),(SELECT count(*) FROM artifact_key_custody)")
            .fetch_one(w.pg.pool())
            .await
            .unwrap();
    assert_eq!(rows, (0, 0), "no catalog or key custody row may exist");
    assert!(
        store.blobs().list("").await.unwrap().is_empty(),
        "no object may remain"
    );
    {
        let received = store.blobs().received.lock();
        assert_eq!(received.len(), 1);
        assert_ne!(received[0], BODY);
        assert!(!contains(&received[0], b"reflected-captcha-token"));
    }

    // Positive control: a body that is not registered publishes and reads back across workers.
    let clean = with_producer(
        w.lease_b.clone(),
        store.put(w.run, Sensitivity::Content, "text/html", b"<p>clean</p>"),
    )
    .await
    .unwrap();
    assert_eq!(store.get(&clean).await.unwrap(), b"<p>clean</p>");
    assert_eq!(
        store.read_content_limited(&clean, 1024).await.unwrap(),
        b"<p>clean</p>"
    );
    let sealed = w
        .custody_a
        .custody(w.tenant, w.run, clean.id)
        .await
        .unwrap()
        .expect("published artifact has encrypted custody");
    assert!(sealed.ciphertext.size_bytes > 12);
    // Once registered, the same body is refused up front by either worker.
    let again = with_producer(
        w.lease_b.clone(),
        store.put(
            w.run,
            Sensitivity::Content,
            "text/html",
            String::from_utf8(BODY.to_vec()).unwrap().as_bytes(),
        ),
    )
    .await;
    assert!(matches!(again, Err(StoreError::RetentionDenied(_))), "{again:?}");
    // An unknown artifact has no custody (legacy path).
    let unknown = w
        .custody_b
        .custody(w.tenant, w.run, crawlx_core::ArtifactId::new())
        .await
        .unwrap();
    assert!(unknown.is_none());

    // Admin verification decrypts sealed rows: clean, then a flipped ciphertext byte and a
    // stranded unpublished encrypted object (counted as an orphan).
    let ops = crawlx_storage::AdminOps::new(&w.pg, "custody-test");
    let verdict = ops
        .verify_artifacts_with_keys(store.blobs(), Some(keys.as_ref()), None)
        .await
        .unwrap();
    assert_eq!(verdict.checked, 1);
    assert!(verdict.defects.is_empty(), "{:?}", verdict.defects);
    assert_eq!(verdict.orphans, 0);
    let object_key: String = sqlx::query_scalar("SELECT object_key FROM artifacts")
        .fetch_one(w.pg.pool())
        .await
        .unwrap();
    assert!(object_key.starts_with("encrypted/"));
    let pristine = store.blobs().get(&object_key).await.unwrap().unwrap();
    let mut flipped = pristine.clone();
    flipped[30] ^= 1;
    store.blobs().put(&object_key, &flipped).await.unwrap();
    let verdict = ops
        .verify_artifacts_with_keys(store.blobs(), Some(keys.as_ref()), None)
        .await
        .unwrap();
    assert_eq!(verdict.defects.len(), 1);
    assert_eq!(verdict.defects[0].defect, "digest_mismatch");
    assert!(store.get(&clean).await.is_err());
    store.blobs().put(&object_key, &pristine).await.unwrap();
    store
        .blobs()
        .put(
            &format!("encrypted/{}/{}/{}/stranded", w.tenant, w.run, Uuid::now_v7()),
            b"orphan",
        )
        .await
        .unwrap();
    let verdict = ops
        .verify_artifacts_with_keys(store.blobs(), Some(keys.as_ref()), None)
        .await
        .unwrap();
    assert!(verdict.defects.is_empty());
    assert_eq!(verdict.orphans, 1);
}

#[tokio::test]
async fn retained_archive_reads_decrypt_sealed_rows_and_refuse_tampering() {
    use crawlx_core::ArtifactRef;
    use crawlx_storage::archive::{retained, ArchiveError, Limits};
    let w = local().await;
    let dir = tempfile::tempdir().unwrap();
    let keys: Arc<dyn ArtifactKeys> = Arc::new(MemoryArtifactKeys::new().unwrap());
    let legacy_store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap()
        .with_index(w.runs.clone());
    let legacy = legacy_store
        .put(w.run, Sensitivity::Content, "text/html", b"<p>legacy</p>")
        .await
        .unwrap();
    let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap()
        .with_index(w.runs.clone())
        .with_custody(w.custody.clone(), keys.clone(), CustodyWrites::Required);
    let sealed = with_producer(
        w.lease.clone(),
        store.put(w.run, Sensitivity::Content, "text/html", BODY),
    )
    .await
    .unwrap();
    let now = Utc::now();
    let limits = Limits::default();
    let custody: &dyn ArtifactCustody = w.custody.as_ref();
    let read = |reference: ArtifactRef| {
        let keys = keys.clone();
        let root = dir.path().to_owned();
        let tenant = w.tenant;
        let run = w.run;
        let custody = w.custody.clone();
        async move {
            retained::read_sealed(
                &root,
                &reference,
                tenant,
                run,
                now,
                limits,
                custody.as_ref(),
                keys.as_ref(),
            )
            .await
        }
    };
    // Sealed rows decrypt; legacy rows keep their path; the plain reader refuses sealed rows.
    assert_eq!(read(sealed.clone()).await.unwrap().bytes, BODY);
    assert_eq!(read(legacy.clone()).await.unwrap().bytes, b"<p>legacy</p>");
    assert!(matches!(
        retained::read(dir.path(), &sealed, w.tenant, w.run, now, limits),
        Err(ArchiveError::CapabilityUnavailable(
            "sealed_artifact_requires_custody"
        ))
    ));
    // Foreign run, wrong digest and an oversized bound are refused.
    let foreign = retained::read_sealed(
        dir.path(),
        &sealed,
        w.tenant,
        CrawlRunId::new(),
        now,
        limits,
        custody,
        keys.as_ref(),
    )
    .await;
    assert!(foreign.is_err());
    let wrong = ArtifactRef {
        id: sealed.id,
        digest: crawlx_core::hash::Digest::of("x", b"y"),
    };
    assert!(read(wrong).await.is_err());
    let mut small = limits;
    small.record_bytes = 4;
    assert!(retained::read_sealed(
        dir.path(),
        &sealed,
        w.tenant,
        w.run,
        now,
        small,
        custody,
        keys.as_ref(),
    )
    .await
    .is_err());
    // Tampered, truncated and extended ciphertext never yields plaintext.
    let object = walk(&dir.path().join("encrypted")).pop().unwrap();
    let pristine = std::fs::read(&object).unwrap();
    let mut flipped = pristine.clone();
    flipped[30] ^= 1;
    let mut extended = pristine.clone();
    extended.push(0);
    for bad in [flipped, pristine[..pristine.len() - 3].to_vec(), extended] {
        std::fs::write(&object, &bad).unwrap();
        assert!(read(sealed.clone()).await.is_err());
    }
    std::fs::write(&object, &pristine).unwrap();
    assert_eq!(read(sealed).await.unwrap().bytes, BODY);
}

#[tokio::test]
async fn archive_export_lease_authorizes_sealed_archive_writes_only_while_recording_at_its_fence() {
    let Some(w) = pg_world().await else {
        return;
    };
    eprintln!("RAN: archive_export_lease_authorizes_sealed_archive_writes_only_while_recording_at_its_fence");
    let export = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO archive_exports(tenant_id,run_id,export_id,state,fence,lease_until,payload) \
         VALUES($1,$2,$3,'recording',3,clock_timestamp()+interval '2 minutes','{}'::jsonb)",
    )
    .bind(w.tenant.0)
    .bind(w.run.0)
    .bind(export)
    .execute(w.pg.pool())
    .await
    .unwrap();
    let lease = |fence| CustodyLease::for_archive_export(w.tenant, w.run, export, WorkerId::new(), fence);
    let (_dir, key_path) = temp_key_file(0x6b);
    let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
    let root = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(root.path(), Arc::new(w.pg.clone()), clock)
        .await
        .unwrap()
        .with_index(Arc::new(w.pg.clone()))
        .with_custody(w.custody_a.clone(), file_keys(&key_path), CustodyWrites::Required);
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("export.warc");
    std::fs::write(&source, b"WARC/1.0 packaged").unwrap();

    // A stale fence is refused before anything is uploaded.
    let stale = with_producer(
        lease(2),
        store.put_archive_file(w.run, "application/warc", &source, 1 << 20),
    )
    .await;
    assert!(matches!(stale, Err(StoreError::LeaseLost)), "{stale:?}");
    assert!(walk(root.path()).is_empty());

    let reference = with_producer(
        lease(3),
        store.put_archive_file(w.run, "application/warc", &source, 1 << 20),
    )
    .await
    .unwrap();
    assert_eq!(store.get(&reference).await.unwrap(), b"WARC/1.0 packaged");
    let copy = dir.path().join("copy.warc");
    store
        .copy_archive_content(w.tenant, w.run, &reference, &copy, 1 << 20)
        .await
        .unwrap();
    assert_eq!(std::fs::read(&copy).unwrap(), b"WARC/1.0 packaged");

    // Once the export is published its lease no longer authorizes writes.
    sqlx::query("UPDATE archive_exports SET state='published' WHERE export_id=$1")
        .bind(export)
        .execute(w.pg.pool())
        .await
        .unwrap();
    let late = with_producer(
        lease(3),
        store.put_archive_file(w.run, "application/warc", &source, 1 << 20),
    )
    .await;
    assert!(matches!(late, Err(StoreError::LeaseLost)), "{late:?}");
}

#[tokio::test]
async fn pg_publish_refuses_a_stale_or_closed_archive_export_fence() {
    use crawlx_core::hash::Digest;
    use crawlx_storage::artifacts::ArtifactRow;
    use crawlx_storage::custody::{
        encrypted_object_key, ArtifactKeyEnvelope, CiphertextIdentity, CIPHERTEXT_DIGEST_DOMAIN,
    };
    let Some(w) = pg_world().await else {
        return;
    };
    eprintln!("RAN: pg_publish_refuses_a_stale_or_closed_archive_export_fence");
    let export = Uuid::now_v7();
    sqlx::query(
        "INSERT INTO archive_exports(tenant_id,run_id,export_id,state,fence,lease_until,payload) \
         VALUES($1,$2,$3,'recording',5,clock_timestamp()+interval '2 minutes','{}'::jsonb)",
    )
    .bind(w.tenant.0)
    .bind(w.run.0)
    .bind(export)
    .execute(w.pg.pool())
    .await
    .unwrap();
    let lease = |fence| CustodyLease::for_archive_export(w.tenant, w.run, export, WorkerId::new(), fence);
    // The authority is initialized under a real session lease, then archive producers use it.
    w.custody_a.snapshot(&w.lease_a).await.unwrap();
    let snapshot = w.custody_a.snapshot(&lease(5)).await.unwrap();
    let id = crawlx_core::ArtifactId::new();
    let identity = CiphertextIdentity::new(Digest::of(CIPHERTEXT_DIGEST_DOMAIN, &[1; 64]), 64).unwrap();
    let row = ArtifactRow {
        id,
        tenant: w.tenant,
        run: w.run,
        kind: "evidence".into(),
        bucket: "mem".into(),
        object_key: encrypted_object_key(w.tenant, w.run, id, identity.digest),
        size_bytes: 10,
        digest: Digest::of("crawlx/artifact/v1", &[2; 10]),
        content_type: "application/warc".into(),
        sensitivity: Sensitivity::Content,
        created_at: w.pg.db_now().await.unwrap(),
        expires_at: None,
    };
    let envelope =
        ArtifactKeyEnvelope::new(w.tenant, w.run, id, "file-artifact-key:test".into(), vec![9; 60]).unwrap();
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM artifacts")
            .fetch_one(w.pg.pool())
            .await
            .unwrap()
    };
    // A stale fence and an unknown export are both fenced off.
    for stale in [lease(4), lease(6)] {
        let refused = w
            .custody_a
            .publish(&stale, snapshot.version, &row, &identity, &envelope)
            .await;
        assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
    }
    let unknown = CustodyLease::for_archive_export(w.tenant, w.run, Uuid::now_v7(), WorkerId::new(), 5);
    assert!(matches!(
        w.custody_a
            .publish(&unknown, snapshot.version, &row, &identity, &envelope)
            .await,
        Err(StoreError::LeaseLost)
    ));
    assert_eq!(count().await, 0);
    // A fence renewed after the snapshot fences the old holder off at publication.
    sqlx::query("UPDATE archive_exports SET fence=6 WHERE export_id=$1")
        .bind(export)
        .execute(w.pg.pool())
        .await
        .unwrap();
    let refused = w
        .custody_a
        .publish(&lease(5), snapshot.version, &row, &identity, &envelope)
        .await;
    assert!(matches!(refused, Err(StoreError::LeaseLost)), "{refused:?}");
    assert_eq!(count().await, 0);
    // The current fence publishes; a published (closed) export no longer does.
    w.custody_a
        .publish(&lease(6), snapshot.version, &row, &identity, &envelope)
        .await
        .unwrap();
    assert_eq!(count().await, 1);
    sqlx::query("UPDATE archive_exports SET state='published' WHERE export_id=$1")
        .bind(export)
        .execute(w.pg.pool())
        .await
        .unwrap();
    let mut second = row.clone();
    second.id = crawlx_core::ArtifactId::new();
    second.object_key = encrypted_object_key(w.tenant, w.run, second.id, identity.digest);
    let envelope = ArtifactKeyEnvelope::new(
        w.tenant,
        w.run,
        second.id,
        "file-artifact-key:test".into(),
        vec![9; 60],
    )
    .unwrap();
    let closed = w
        .custody_a
        .publish(&lease(6), snapshot.version, &second, &identity, &envelope)
        .await;
    assert!(matches!(closed, Err(StoreError::LeaseLost)), "{closed:?}");
    assert_eq!(count().await, 1);
}

#[tokio::test]
async fn terminal_run_refuses_session_and_url_producers_but_keeps_operator_and_archive_paths() {
    use crawlx_core::counters::{RunStatus, TerminalReason};
    let w = local().await;
    w.runs.set_status(w.run, RunStatus::Running, None).await.unwrap();
    w.runs
        .set_status(
            w.run,
            RunStatus::Completed,
            Some(TerminalReason::FrontierExhausted),
        )
        .await
        .unwrap();
    let store = w.store(PausedBlobs::new(), CustodyWrites::Required);
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("late.warc");
    std::fs::write(&source, b"late").unwrap();
    let url = CustodyLease::for_url(w.tenant, w.run, 7, WorkerId::new(), 1);
    for producer in [w.lease.clone(), url] {
        for class in [Sensitivity::Content, Sensitivity::Sensitive] {
            let refused = with_producer(producer.clone(), store.put(w.run, class, "text/html", BODY)).await;
            assert!(
                matches!(&refused, Err(StoreError::RetentionDenied(detail)) if detail == "run ended; artifact not retained"),
                "{refused:?}"
            );
        }
        let refused = with_producer(
            producer.clone(),
            store.put_archive_file(w.run, "application/warc", &source, 1024),
        )
        .await;
        assert!(
            matches!(refused, Err(StoreError::RetentionDenied(_))),
            "{refused:?}"
        );
    }
    assert!(store.blobs().inner.is_empty(), "nothing may be written");
    assert!(store.blobs().received.lock().is_empty());
    // Operator inputs (no producer) keep the legacy plaintext path on a terminal run.
    let operator = store
        .put(w.run, Sensitivity::Content, "text/html", b"<p>op</p>")
        .await
        .unwrap();
    assert_eq!(store.get(&operator).await.unwrap(), b"<p>op</p>");
}

/// Commits the publication, then (once) reports an unknown outcome after registering a secret.
struct FlakyCustody {
    inner: Arc<dyn ArtifactCustody>,
    secret: String,
    armed: AtomicBool,
    seen: Mutex<Option<crawlx_core::ArtifactId>>,
}

#[async_trait]
impl ArtifactCustody for FlakyCustody {
    async fn snapshot(
        &self,
        lease: &CustodyLease,
    ) -> Result<crawlx_core::custody::RunSecretSnapshot, StoreError> {
        self.inner.snapshot(lease).await
    }
    async fn register(
        &self,
        lease: &CustodyLease,
        value: &SecretOr<String>,
    ) -> Result<crawlx_core::custody::RunSecretSnapshot, StoreError> {
        self.inner.register(lease, value).await
    }
    async fn publish(
        &self,
        lease: &CustodyLease,
        expected: crawlx_core::custody::SecretEpoch,
        row: &crawlx_storage::ArtifactRow,
        ciphertext: &crawlx_storage::custody::CiphertextIdentity,
        envelope: &crawlx_storage::custody::ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        *self.seen.lock() = Some(row.id);
        let outcome = self
            .inner
            .publish(lease, expected, row, ciphertext, envelope)
            .await;
        if self.armed.swap(false, Ordering::SeqCst) {
            outcome?;
            // The COMMIT landed but its reply was lost; meanwhile another worker registers a secret.
            self.inner
                .register(lease, &SecretOr::secret(self.secret.clone()))
                .await?;
            return Err(StoreError::Unavailable("injected lost publication reply".into()));
        }
        outcome
    }
    async fn custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: crawlx_core::ArtifactId,
    ) -> Result<Option<crawlx_storage::custody::ArtifactKeyCustody>, StoreError> {
        self.inner.custody(tenant, run, id).await
    }
    async fn withdraw(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: crawlx_core::ArtifactId,
    ) -> Result<(), StoreError> {
        self.inner.withdraw(tenant, run, id).await
    }
    fn publishes_catalog_row(&self) -> bool {
        self.inner.publishes_catalog_row()
    }
}

#[tokio::test]
async fn lost_publication_reply_then_secret_withdraws_the_published_row_and_deletes_the_object() {
    let w = local().await;
    let flaky = Arc::new(FlakyCustody {
        inner: w.custody.clone(),
        secret: String::from_utf8(BODY.to_vec()).unwrap(),
        armed: AtomicBool::new(true),
        seen: Mutex::new(None),
    });
    let store = ObjectArtifactStore::new(PausedBlobs::new(), w.runs.clone(), Arc::new(w.clock.clone()))
        .with_index(w.runs.clone())
        .with_custody(
            flaky.clone(),
            Arc::new(MemoryArtifactKeys::new().unwrap()),
            CustodyWrites::Required,
        );
    let outcome = with_producer(
        w.lease.clone(),
        store.put(w.run, Sensitivity::Content, "text/html", BODY),
    )
    .await;
    assert!(
        matches!(outcome, Err(StoreError::RetentionDenied(_))),
        "{outcome:?}"
    );
    assert!(
        store.blobs().list("").await.unwrap().is_empty(),
        "no dangling object"
    );
    let id = flaky.seen.lock().expect("publication was attempted");
    assert!(
        w.custody.custody(w.tenant, w.run, id).await.unwrap().is_none(),
        "custody withdrawn"
    );
}

#[tokio::test]
async fn withdrawal_failure_keeps_the_object_and_reports_unresolved() {
    let w = local().await;
    struct StuckWithdraw(FlakyCustody);
    #[async_trait]
    impl ArtifactCustody for StuckWithdraw {
        async fn snapshot(
            &self,
            lease: &CustodyLease,
        ) -> Result<crawlx_core::custody::RunSecretSnapshot, StoreError> {
            self.0.snapshot(lease).await
        }
        async fn register(
            &self,
            lease: &CustodyLease,
            value: &SecretOr<String>,
        ) -> Result<crawlx_core::custody::RunSecretSnapshot, StoreError> {
            self.0.register(lease, value).await
        }
        async fn publish(
            &self,
            lease: &CustodyLease,
            expected: crawlx_core::custody::SecretEpoch,
            row: &crawlx_storage::ArtifactRow,
            ciphertext: &crawlx_storage::custody::CiphertextIdentity,
            envelope: &crawlx_storage::custody::ArtifactKeyEnvelope,
        ) -> Result<(), StoreError> {
            self.0.publish(lease, expected, row, ciphertext, envelope).await
        }
        async fn custody(
            &self,
            tenant: TenantId,
            run: CrawlRunId,
            id: crawlx_core::ArtifactId,
        ) -> Result<Option<crawlx_storage::custody::ArtifactKeyCustody>, StoreError> {
            self.0.custody(tenant, run, id).await
        }
        async fn withdraw(
            &self,
            _: TenantId,
            _: CrawlRunId,
            _: crawlx_core::ArtifactId,
        ) -> Result<(), StoreError> {
            Err(StoreError::Unavailable("injected withdrawal failure".into()))
        }
        fn publishes_catalog_row(&self) -> bool {
            self.0.publishes_catalog_row()
        }
    }
    let stuck = Arc::new(StuckWithdraw(FlakyCustody {
        inner: w.custody.clone(),
        secret: String::from_utf8(BODY.to_vec()).unwrap(),
        armed: AtomicBool::new(true),
        seen: Mutex::new(None),
    }));
    let store = ObjectArtifactStore::new(PausedBlobs::new(), w.runs.clone(), Arc::new(w.clock.clone()))
        .with_index(w.runs.clone())
        .with_custody(
            stuck,
            Arc::new(MemoryArtifactKeys::new().unwrap()),
            CustodyWrites::Required,
        );
    let outcome = with_producer(
        w.lease.clone(),
        store.put(w.run, Sensitivity::Content, "text/html", BODY),
    )
    .await;
    assert!(
        matches!(&outcome, Err(StoreError::Unavailable(detail)) if detail == "published artifact withdrawal unresolved"),
        "{outcome:?}"
    );
    assert_eq!(
        store.blobs().inner.object_keys().len(),
        1,
        "the possibly-published object is kept"
    );
}

#[tokio::test]
async fn pg_lost_publication_reply_then_secret_leaves_no_live_row_or_object() {
    let Some(w) = pg_world().await else {
        return;
    };
    eprintln!("RAN: pg_lost_publication_reply_then_secret_leaves_no_live_row_or_object");
    let (_dir, key_path) = temp_key_file(0x7c);
    let flaky = Arc::new(FlakyCustody {
        inner: w.custody_b.clone(),
        secret: String::from_utf8(BODY.to_vec()).unwrap(),
        armed: AtomicBool::new(true),
        seen: Mutex::new(None),
    });
    let store = ObjectArtifactStore::new(
        PausedBlobs::new(),
        Arc::new(w.peer.clone()),
        Arc::new(crawlx_core::SystemClock),
    )
    .with_index(Arc::new(w.peer.clone()))
    .with_custody(flaky, file_keys(&key_path), CustodyWrites::Required);
    let outcome = with_producer(
        w.lease_b.clone(),
        store.put(w.run, Sensitivity::Content, "text/html", BODY),
    )
    .await;
    assert!(
        matches!(outcome, Err(StoreError::RetentionDenied(_))),
        "{outcome:?}"
    );
    let live: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE deleted_at IS NULL")
        .fetch_one(w.pg.pool())
        .await
        .unwrap();
    let tombstoned: i64 = sqlx::query_scalar("SELECT count(*) FROM artifacts WHERE deleted_at IS NOT NULL")
        .fetch_one(w.pg.pool())
        .await
        .unwrap();
    assert_eq!((live, tombstoned), (0, 1));
    assert!(store.blobs().list("").await.unwrap().is_empty());
}
