//! Artifact store behavior without a database (runs come from the in-memory store).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::time::ManualClock;
use crawlx_core::{ArtifactRef, Clock as _, StoreError, TenantId};
use crawlx_storage::artifacts::{ArtifactReaper as _, FsArtifactStore, MemoryArtifactStore};
use crawlx_storage::testkit::{crawl_run, create_crawl};
use crawlx_storage::{DeliveryBuffer, MemoryStore};
use std::sync::Arc;
use std::time::Duration;

struct World {
    clock: ManualClock,
    runs: Arc<MemoryStore>,
    tenant: TenantId,
}

async fn world() -> World {
    let clock = ManualClock::new(Utc::now());
    World {
        runs: Arc::new(MemoryStore::with_clock(Arc::new(clock.clone()))),
        clock,
        tenant: TenantId::new(),
    }
}

impl World {
    async fn run(&self, mode: RetentionMode, days: u16) -> crawlx_core::CrawlRunId {
        let mut cfg = create_crawl("https://example.test/", &[], 1);
        cfg.retention.mode = mode;
        cfg.retention.days = days;
        let run = crawl_run(self.tenant, cfg);
        self.runs.create(&run, None).await.unwrap();
        run.id
    }
}

#[tokio::test]
async fn fs_store_uses_the_class_tenant_run_digest_layout_and_verifies_content() {
    let w = world().await;
    let run = w.run(RetentionMode::Standard, 7).await;
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap();

    let r = store
        .put(run, Sensitivity::Content, "text/html", b"<h1>hi</h1>")
        .await
        .unwrap();
    let path = dir
        .path()
        .join(format!("content/{}/{run}/{}", w.tenant, r.digest.to_hex()));
    assert_eq!(std::fs::read(&path).unwrap(), b"<h1>hi</h1>");
    assert_eq!(store.get(&r).await.unwrap(), b"<h1>hi</h1>");

    // a reference with a wrong digest or unknown id is not served
    let wrong = ArtifactRef {
        id: r.id,
        digest: crawlx_core::hash::Digest::of("x", b"y"),
    };
    assert!(matches!(
        store.get(&wrong).await,
        Err(StoreError::NotFound { .. })
    ));
    let unknown = ArtifactRef {
        id: crawlx_core::ArtifactId::new(),
        digest: r.digest,
    };
    assert!(matches!(
        store.get(&unknown).await,
        Err(StoreError::NotFound { .. })
    ));

    // corrupted object bytes are detected, not returned
    std::fs::write(&path, b"tampered").unwrap();
    assert!(matches!(store.get(&r).await, Err(StoreError::Backend(_))));

    // a reopened store sees the same artifacts (the index lives next to the objects)
    std::fs::write(&path, b"<h1>hi</h1>").unwrap();
    let reopened = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap();
    assert_eq!(reopened.get(&r).await.unwrap(), b"<h1>hi</h1>");
}

#[tokio::test]
async fn identical_content_shares_one_object_and_survives_until_the_last_use_expires() {
    let w = world().await;
    let run = w.run(RetentionMode::Standard, 1).await;
    let store = MemoryArtifactStore::in_memory(w.runs.clone(), Arc::new(w.clock.clone()));
    let a = store
        .put(run, Sensitivity::Content, "text/markdown", b"same")
        .await
        .unwrap();
    w.clock.advance_ms(3_600_000);
    let b = store
        .put(run, Sensitivity::Content, "text/markdown", b"same")
        .await
        .unwrap();
    assert_ne!(a.id, b.id, "one use per put");
    assert_eq!(a.digest, b.digest);
    assert_eq!(store.blobs().object_keys().len(), 1, "one object for both uses");

    // 1-day retention: the first use expires first, the object stays for the second
    w.clock.advance_ms(23 * 3_600_000 + 1_000);
    assert!(
        matches!(store.get(&a).await, Err(StoreError::NotFound { .. })),
        "expired uses are not served"
    );
    assert_eq!(store.get(&b).await.unwrap(), b"same");
    assert_eq!(store.reap_expired(w.clock.now()).await.unwrap(), 1);
    assert_eq!(store.blobs().object_keys().len(), 1);
    w.clock.advance_ms(3_600_000);
    assert_eq!(store.reap_expired(w.clock.now()).await.unwrap(), 1);
    assert!(store.blobs().is_empty(), "object and index records are gone");
}

#[tokio::test]
async fn metadata_never_expires_and_purge_run_removes_everything_of_a_run() {
    let w = world().await;
    let keep = w.run(RetentionMode::Standard, 1).await;
    let purge = w.run(RetentionMode::Standard, 1).await;
    let store = MemoryArtifactStore::in_memory(w.runs.clone(), Arc::new(w.clock.clone()));
    let meta = store
        .put(keep, Sensitivity::Metadata, "application/json", b"{}")
        .await
        .unwrap();
    store
        .put(purge, Sensitivity::Sensitive, "image/webp", b"img")
        .await
        .unwrap();
    store
        .put(purge, Sensitivity::Content, "text/html", b"html")
        .await
        .unwrap();
    w.clock.advance_ms(400 * 24 * 3_600_000);
    assert_eq!(store.get(&meta).await.unwrap(), b"{}");
    assert_eq!(store.reap_expired(w.clock.now()).await.unwrap(), 2);
    store
        .put(purge, Sensitivity::Content, "text/html", b"again")
        .await
        .unwrap();
    assert_eq!(store.purge_run(purge).await.unwrap(), 1);
    assert_eq!(store.get(&meta).await.unwrap(), b"{}", "other runs untouched");
}

#[tokio::test]
async fn tenant_scoped_erasure_and_run_purge_preserve_foreign_artifacts_with_a_shared_index() {
    use crawlx_storage::tenant::scope;
    use crawlx_storage::ArtifactIndex as _;

    let w = world().await;
    let foreign = World {
        clock: w.clock.clone(),
        runs: w.runs.clone(),
        tenant: TenantId::new(),
    };
    let run = scope(w.tenant, w.run(RetentionMode::Standard, 7)).await;
    let foreign_run = scope(foreign.tenant, foreign.run(RetentionMode::Standard, 7)).await;
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap()
        .with_index(w.runs.clone());

    let (erased, purged) = scope(w.tenant, async {
        let erased = store
            .put(run, Sensitivity::Content, "text/plain", b"erase owned")
            .await
            .unwrap();
        let purged = store
            .put(run, Sensitivity::Content, "text/plain", b"purge owned")
            .await
            .unwrap();
        (erased, purged)
    })
    .await;
    let foreign_artifacts = scope(foreign.tenant, async {
        let first = store
            .put(foreign_run, Sensitivity::Content, "text/plain", b"erase owned")
            .await
            .unwrap();
        let second = store
            .put(foreign_run, Sensitivity::Content, "text/plain", b"purge owned")
            .await
            .unwrap();
        [first, second]
    })
    .await;
    assert_eq!(erased.digest, foreign_artifacts[0].digest);
    assert_eq!(purged.digest, foreign_artifacts[1].digest);

    scope(w.tenant, async {
        let erased_row = store.row(erased.id).await.unwrap().unwrap();
        let purged_row = store.row(purged.id).await.unwrap().unwrap();
        let erased_path = dir.path().join(erased_row.object_key);
        let purged_path = dir.path().join(purged_row.object_key);
        assert_eq!(std::fs::read(&erased_path).unwrap(), b"erase owned");
        assert_eq!(std::fs::read(&purged_path).unwrap(), b"purge owned");

        assert_eq!(store.erase_artifact(&erased).await.unwrap(), 1);
        assert!(!erased_path.exists());
        assert!(store.row(erased.id).await.unwrap().is_none());
        assert!(w.runs.retention(erased.id).await.unwrap().is_none());
        assert!(matches!(
            store.get(&erased).await,
            Err(StoreError::NotFound { .. })
        ));
        assert_eq!(store.get(&purged).await.unwrap(), b"purge owned");

        assert_eq!(store.purge_run(run).await.unwrap(), 1);
        assert!(!purged_path.exists());
        assert!(store.row(purged.id).await.unwrap().is_none());
        assert!(w.runs.retention(purged.id).await.unwrap().is_none());
        assert!(matches!(
            store.get(&purged).await,
            Err(StoreError::NotFound { .. })
        ));
    })
    .await;

    scope(foreign.tenant, async {
        for (artifact, expected) in foreign_artifacts.iter().zip([b"erase owned", b"purge owned"]) {
            let row = store.row(artifact.id).await.unwrap().unwrap();
            assert_eq!(row.tenant, foreign.tenant);
            assert_eq!(row.run, foreign_run);
            assert!(w.runs.retention(artifact.id).await.unwrap().is_some());
            assert_eq!(std::fs::read(dir.path().join(row.object_key)).unwrap(), expected);
            assert_eq!(store.get(artifact).await.unwrap(), expected);
        }
    })
    .await;
}

#[tokio::test]
async fn zdr_runs_accept_only_metadata_in_every_backend() {
    let w = world().await;
    let zdr = w.run(RetentionMode::Zdr, 0).await;
    let dir = tempfile::tempdir().unwrap();
    let fs = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap();
    let mem = MemoryArtifactStore::in_memory(w.runs.clone(), Arc::new(w.clock.clone()));
    for class in [
        Sensitivity::Content,
        Sensitivity::Sensitive,
        Sensitivity::CredentialBearing,
    ] {
        assert!(
            matches!(
                fs.put(zdr, class, "text/html", b"x").await,
                Err(StoreError::RetentionDenied(_))
            ),
            "fs {class:?}"
        );
        assert!(
            matches!(
                mem.put(zdr, class, "text/html", b"x").await,
                Err(StoreError::RetentionDenied(_))
            ),
            "mem {class:?}"
        );
    }
    assert!(mem.blobs().is_empty());
    assert!(
        std::fs::read_dir(dir.path()).unwrap().next().is_none(),
        "denied writes touch nothing on disk"
    );
    fs.put(zdr, Sensitivity::Metadata, "application/json", b"{}")
        .await
        .unwrap();
    assert!(
        matches!(
            fs.put(
                crawlx_core::CrawlRunId::new(),
                Sensitivity::Content,
                "text/html",
                b"x"
            )
            .await,
            Err(StoreError::NotFound { .. })
        ),
        "unknown run"
    );
}

#[tokio::test]
async fn zdr_runs_buffer_page_content_when_a_delivery_buffer_is_attached() {
    let w = world().await;
    let zdr = w.run(RetentionMode::Zdr, 0).await;
    let standard = w.run(RetentionMode::Standard, 7).await;
    let buffer = Arc::new(DeliveryBuffer::with_defaults(Arc::new(w.clock.clone())));
    let mem = MemoryArtifactStore::in_memory(w.runs.clone(), Arc::new(w.clock.clone()))
        .with_zdr_buffer(buffer.clone());

    // content of a zdr run goes to the buffer, keyed by page, and never to the backend
    let md = mem
        .put_page(zdr, 7, Sensitivity::Content, "text/markdown", b"# zdr")
        .await
        .unwrap();
    let html = mem
        .put_page(zdr, 7, Sensitivity::Content, "text/html", b"<p>zdr</p>")
        .await
        .unwrap();
    assert!(mem.blobs().is_empty(), "nothing durable");
    let page = buffer.get(w.tenant, zdr, 7).await.unwrap().unwrap();
    assert_eq!(page.blobs["markdown"].artifact, md);
    assert_eq!(page.blobs["html"].artifact, html);
    assert_eq!(mem.get(&md).await.unwrap(), b"# zdr");
    assert_eq!(mem.get(&html).await.unwrap(), b"<p>zdr</p>");
    // plain `put` (no page) and every other class are still refused under zdr
    assert!(matches!(
        mem.put(zdr, Sensitivity::Content, "text/html", b"x").await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        mem.put_page(zdr, 7, Sensitivity::Sensitive, "image/webp", b"x")
            .await,
        Err(StoreError::RetentionDenied(_))
    ));
    // a standard run's `put_page` is an ordinary durable write
    let durable = mem
        .put_page(standard, 1, Sensitivity::Content, "text/markdown", b"# kept")
        .await
        .unwrap();
    assert_eq!(mem.blobs().object_keys().len(), 1);
    assert!(buffer.get(w.tenant, standard, 1).await.unwrap().is_none());
    assert_eq!(mem.get(&durable).await.unwrap(), b"# kept");
    // acknowledged content is gone from the store's point of view too
    assert!(buffer.ack(w.tenant, zdr, 7).await.unwrap());
    assert!(matches!(mem.get(&md).await, Err(StoreError::NotFound { .. })));
}

#[tokio::test]
async fn presign_is_none_for_local_backends_and_denied_outside_content() {
    let w = world().await;
    let run = w.run(RetentionMode::Standard, 7).await;
    let dir = tempfile::tempdir().unwrap();
    let fs = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap();
    let mem = MemoryArtifactStore::in_memory(w.runs.clone(), Arc::new(w.clock.clone()));
    let ttl = Duration::from_secs(60);
    for store in [&fs as &dyn ArtifactStore, &mem] {
        let content = store
            .put(run, Sensitivity::Content, "text/markdown", b"# c")
            .await
            .unwrap();
        assert_eq!(store.presign(&content, ttl).await.unwrap(), None);
        for (class, ct) in [
            (Sensitivity::Sensitive, "image/webp"),
            (Sensitivity::CredentialBearing, "application/octet-stream"),
            (Sensitivity::Metadata, "application/json"),
        ] {
            let r = store.put(run, class, ct, b"x").await.unwrap();
            assert!(
                matches!(store.presign(&r, ttl).await, Err(StoreError::AccessDenied(_))),
                "{class:?}"
            );
        }
        let unknown = ArtifactRef {
            id: crawlx_core::ArtifactId::new(),
            digest: content.digest,
        };
        assert!(matches!(
            store.presign(&unknown, ttl).await,
            Err(StoreError::NotFound { .. })
        ));
    }
}

#[tokio::test]
async fn object_keys_cannot_escape_the_root() {
    let w = world().await;
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path().join("root"), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap();
    let blobs = store.blobs();
    for bad in ["../x", "a/../../x", "/abs", "a//b", ""] {
        assert!(
            matches!(
                crawlx_storage::ArtifactBlobs::put(blobs, bad, b"x").await,
                Err(StoreError::Conflict(_))
            ),
            "{bad:?}"
        );
    }
}

#[tokio::test]
async fn read_scope_rejects_other_runs_and_tenants_before_serving_content_or_urls() {
    let w = world().await;
    let run = w.run(RetentionMode::Standard, 7).await;
    let other_run = w.run(RetentionMode::Standard, 7).await;
    let store = MemoryArtifactStore::in_memory(w.runs.clone(), Arc::new(w.clock.clone()));
    let own = store
        .put(run, Sensitivity::Content, "text/plain", b"own content")
        .await
        .unwrap();
    let other = store
        .put(other_run, Sensitivity::Content, "text/plain", b"other content")
        .await
        .unwrap();
    let store = store.with_read_scope(w.tenant, run);
    assert_eq!(store.get(&own).await.unwrap(), b"own content");
    assert!(matches!(
        store.get(&other).await,
        Err(StoreError::NotFound { .. })
    ));
    assert!(matches!(
        store.presign(&other, Duration::from_secs(30)).await,
        Err(StoreError::NotFound { .. })
    ));

    // A correct run id is not enough when the tenant does not own that run.
    let store = store.with_read_scope(TenantId::new(), run);
    assert!(matches!(store.get(&own).await, Err(StoreError::NotFound { .. })));
    assert!(matches!(
        store.presign(&own, Duration::from_secs(30)).await,
        Err(StoreError::NotFound { .. })
    ));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn bounded_fs_reads_enforce_scope_class_size_fixity_and_index_ceiling() {
    use crawlx_storage::artifacts::BoundedArtifactError as Bound;
    let w = world().await;
    let run = w.run(RetentionMode::Standard, 7).await;
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap();
    let artifact = store
        .put(run, Sensitivity::Content, "text/plain", b"retained")
        .await
        .unwrap();
    assert!(matches!(
        store.get_bounded(&artifact, Sensitivity::Content, 8).await,
        Err(Bound::Store(StoreError::AccessDenied(_)))
    ));
    let store = store.with_read_scope(w.tenant, run);
    assert_eq!(
        store
            .get_bounded(&artifact, Sensitivity::Content, 8)
            .await
            .unwrap(),
        b"retained"
    );
    assert!(matches!(
        store.get_bounded(&artifact, Sensitivity::Content, 7).await,
        Err(Bound::Limit(_))
    ));
    assert!(matches!(
        store.get_bounded(&artifact, Sensitivity::Sensitive, 8).await,
        Err(Bound::Store(StoreError::AccessDenied(_)))
    ));
    let foreign = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap()
        .with_read_scope(TenantId::new(), run);
    assert!(matches!(
        foreign.get_bounded(&artifact, Sensitivity::Content, 8).await,
        Err(Bound::Store(StoreError::NotFound { .. }))
    ));
    let row = store.row(artifact.id).await.unwrap().unwrap();
    std::fs::write(dir.path().join(&row.object_key), b"modified").unwrap();
    assert!(matches!(
        store.get_bounded(&artifact, Sensitivity::Content, 8).await,
        Err(Bound::Store(StoreError::Backend(_)))
    ));
    let mut expired = row;
    expired.expires_at = Some(w.clock.now() - chrono::Duration::seconds(1));
    let index = dir.path().join(format!("_index/{}.json", artifact.id));
    std::fs::write(&index, serde_json::to_vec(&expired).unwrap()).unwrap();
    assert!(matches!(
        store.get_bounded(&artifact, Sensitivity::Content, 8).await,
        Err(Bound::Store(StoreError::NotFound { .. }))
    ));
    std::fs::write(&index, vec![b' '; 65_537]).unwrap();
    assert!(matches!(
        store.get_bounded(&artifact, Sensitivity::Content, 8).await,
        Err(Bound::Limit(_))
    ));
    std::fs::write(dir.path().join("bundle.json"), vec![b' '; 65_537]).unwrap();
    assert!(matches!(
        FsArtifactStore::read_bundle_descriptor(dir.path()).await,
        Err(Bound::Limit(_))
    ));
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn bounded_fs_reads_refuse_symlinks_and_fifos_without_blocking() {
    use crawlx_storage::artifacts::BoundedArtifactError as Bound;
    let w = world().await;
    let run = w.run(RetentionMode::Standard, 7).await;
    let dir = tempfile::tempdir().unwrap();
    let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
        .await
        .unwrap();
    let artifact = store
        .put(run, Sensitivity::Content, "text/plain", b"retained")
        .await
        .unwrap();
    let row = store.row(artifact.id).await.unwrap().unwrap();
    let store = store.with_read_scope(w.tenant, run);
    let object = dir.path().join(&row.object_key);
    let same_bytes = dir.path().join("same-bytes.txt");
    std::fs::write(&same_bytes, b"retained").unwrap();
    std::fs::remove_file(&object).unwrap();
    std::os::unix::fs::symlink(&same_bytes, &object).unwrap();
    assert!(matches!(
        store.get_bounded(&artifact, Sensitivity::Content, 8).await,
        Err(Bound::Io(_))
    ));
    std::fs::remove_file(&object).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(&object)
        .status()
        .unwrap()
        .success());
    // Keep a writer present so even a regressed blocking open cannot orphan a test thread.
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&object)
        .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        store.get_bounded(&artifact, Sensitivity::Content, 8),
    )
    .await;
    drop(guard);
    assert!(matches!(result, Ok(Err(Bound::Io(error))) if error.kind() == std::io::ErrorKind::InvalidInput));
}

#[tokio::test]
async fn terminal_runs_revoke_and_erase_encrypted_recovery_without_erasing_content() {
    use crawlx_core::counters::{RunStatus, TerminalReason};
    use crawlx_storage::checkpoint_crypto::{CheckpointContext, CheckpointKeys, MemoryCheckpointKeys};
    for mode in [RetentionMode::Standard, RetentionMode::Extended] {
        for (status, reason) in [
            (RunStatus::Completed, TerminalReason::FrontierExhausted),
            (RunStatus::Failed, TerminalReason::FatalError),
            (RunStatus::Cancelled, TerminalReason::Cancelled),
        ] {
            let w = world().await;
            let run = w.run(mode, 7).await;
            let dir = tempfile::tempdir().unwrap();
            let store = FsArtifactStore::open(dir.path(), w.runs.clone(), Arc::new(w.clock.clone()))
                .await
                .unwrap()
                .with_index(w.runs.clone())
                .with_read_scope(w.tenant, run);
            let keys = MemoryCheckpointKeys::new().unwrap();
            let context = CheckpointContext::new(
                w.tenant,
                run,
                crawlx_core::SessionId::new(),
                crawlx_core::CheckpointId::new(),
            );
            let plaintext = b"{\"cookies\":[{\"value\":\"terminal-cookie-canary\"}]}";
            let encrypted = keys
                .seal(&context, zeroize::Zeroizing::new(plaintext.to_vec()))
                .await
                .unwrap();
            for class in [
                Sensitivity::Metadata,
                Sensitivity::Content,
                Sensitivity::Sensitive,
            ] {
                assert!(matches!(
                    crawlx_core::secret::ArtifactSink::over(&store)
                        .put(
                            run,
                            class,
                            "application/vnd.crawlx.checkpoint-encrypted",
                            &&encrypted
                        )
                        .await,
                    Err(StoreError::RetentionDenied(_))
                ));
            }
            let secret = store
                .put_until(
                    run,
                    Sensitivity::CredentialBearing,
                    "application/vnd.crawlx.checkpoint-encrypted",
                    encrypted.as_ref(),
                    w.clock.now() + chrono::Duration::minutes(1),
                )
                .await
                .unwrap();
            let row = store.row(secret.id).await.unwrap().unwrap();
            let content = store
                .put(run, Sensitivity::Content, "text/plain", b"retained evidence")
                .await
                .unwrap();
            w.runs.set_status(run, RunStatus::Running, None).await.unwrap();
            w.runs.set_status(run, RunStatus::Paused, None).await.unwrap();
            assert_eq!(store.get(&secret).await.unwrap(), encrypted.as_ref());
            assert!(matches!(
                store.erase_run_credentials(run).await,
                Err(StoreError::Conflict(_))
            ));
            w.runs.set_status(run, status, Some(reason)).await.unwrap();
            assert!(matches!(
                store.get(&secret).await,
                Err(StoreError::NotFound { .. })
            ));
            assert!(matches!(
                store
                    .get_bounded(&secret, Sensitivity::CredentialBearing, 4096)
                    .await,
                Err(crawlx_storage::artifacts::BoundedArtifactError::Store(
                    StoreError::RetentionDenied(_)
                ))
            ));
            assert!(
                dir.path().join(&row.object_key).exists(),
                "revocation must not depend on erasure I/O"
            );
            assert!(matches!(
                store
                    .put_until(
                        run,
                        Sensitivity::CredentialBearing,
                        "application/vnd.crawlx.checkpoint-encrypted",
                        encrypted.as_ref(),
                        w.clock.now() + chrono::Duration::minutes(1),
                    )
                    .await,
                Err(StoreError::RetentionDenied(_))
            ));
            assert_eq!(store.erase_run_credentials(run).await.unwrap(), 1);
            assert!(!dir.path().join(&row.object_key).exists());
            assert!(!dir.path().join(format!("_index/{}.json", secret.id)).exists());
            assert_eq!(store.erase_run_credentials(run).await.unwrap(), 0);
            assert_eq!(store.get(&content).await.unwrap(), b"retained evidence");
            assert_eq!(w.runs.get_metadata(run).await.unwrap().status, status);
        }
    }
}

#[tokio::test]
async fn explicit_checkpoint_deadline_expires_the_object_and_memory_recovery_at_the_same_boundary() {
    use crawlx_core::repo::{CheckpointRecord, CheckpointRepo};
    let w = world().await;
    let run = w.run(RetentionMode::Standard, 7).await;
    let sessions = crawlx_storage::testkit::sessions(run, 1, 1);
    w.runs.create_sessions(&sessions).await.unwrap();
    let store = MemoryArtifactStore::in_memory(w.runs.clone(), Arc::new(w.clock.clone()));
    let deadline = w.clock.now() + chrono::Duration::seconds(1);
    let artifact = store
        .put_until(
            run,
            Sensitivity::CredentialBearing,
            "application/octet-stream",
            b"opaque recovery state",
            deadline,
        )
        .await
        .unwrap();
    let record = CheckpointRecord {
        id: crawlx_core::CheckpointId::new(),
        run,
        session: sessions[0].id,
        epoch: crawlx_core::ObservationEpoch::default(),
        action_seq: 1,
        reason: "shutdown".into(),
        storage: artifact.clone(),
        url_hash: None,
        created_at: w.clock.now(),
        expires_at: deadline,
    };
    w.runs.put(&record).await.unwrap();
    assert_eq!(
        store.row(artifact.id).await.unwrap().unwrap().expires_at,
        Some(deadline)
    );
    assert_eq!(
        w.runs.latest(sessions[0].id).await.unwrap().unwrap().id,
        record.id
    );
    w.clock.advance_ms(1000);
    assert!(w.runs.latest(sessions[0].id).await.unwrap().is_none());
    assert!(matches!(
        store.get(&artifact).await,
        Err(StoreError::NotFound { .. })
    ));
    assert_eq!(store.reap_expired(w.clock.now()).await.unwrap(), 1);
    assert!(store.blobs().is_empty());
}
