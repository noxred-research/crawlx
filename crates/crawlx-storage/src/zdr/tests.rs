//! Local-memory and filesystem delivery contract regressions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use chrono::{TimeZone, Utc};
use crawlx_core::time::ManualClock;

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
    ))
}

fn buffer(limits: BufferLimits) -> (Arc<ManualClock>, DeliveryBuffer) {
    let clock = clock();
    (clock.clone(), DeliveryBuffer::new(clock, limits))
}

async fn insert(
    buffer: &DeliveryBuffer,
    tenant: TenantId,
    run: CrawlRunId,
    page: i64,
    kind: &str,
    bytes: &[u8],
) -> ArtifactRef {
    buffer
        .insert(tenant, run, page, kind, "text/plain", bytes)
        .await
        .unwrap()
}

#[tokio::test]
async fn insert_get_read_and_ack() {
    let (_, b) = buffer(BufferLimits::default());
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let md = b
        .insert(tenant, run, 7, "markdown", "text/markdown", b"# hi")
        .await
        .unwrap();
    let html = b
        .insert(tenant, run, 7, "html", "text/html", b"<p>hi</p>")
        .await
        .unwrap();
    assert_eq!(b.len().await.unwrap(), 1);
    assert_eq!(b.bytes().await.unwrap(), 4 + 9);
    let page = b.get(tenant, run, 7).await.unwrap().unwrap();
    assert_eq!(page.tenant, tenant);
    assert_eq!(page.blobs.len(), 2);
    assert_eq!(page.blobs["markdown"].bytes, b"# hi");
    assert_eq!(b.read(&md).await.unwrap().unwrap().bytes, b"# hi");
    assert_eq!(b.read(&html).await.unwrap().unwrap().content_type, "text/html");
    // A wrong digest does not resolve.
    let bad = ArtifactRef {
        id: md.id,
        digest: Digest::of("x", b"other"),
    };
    assert!(b.read(&bad).await.unwrap().is_none());
    assert!(b.read_for_run(tenant, run, &bad).await.unwrap().is_none());
    // Replacing a rendition drops the old reference and keeps the byte count right.
    let md2 = insert(&b, tenant, run, 7, "markdown", b"# hello").await;
    assert!(b.read(&md).await.unwrap().is_none());
    assert_eq!(b.read(&md2).await.unwrap().unwrap().bytes, b"# hello");
    assert_eq!(b.bytes().await.unwrap(), 7 + 9);
    assert_eq!(b.list(tenant, run).await.unwrap().len(), 1);
    assert!(b.ack(tenant, run, 7).await.unwrap());
    assert!(!b.ack(tenant, run, 7).await.unwrap());
    assert!(b.get(tenant, run, 7).await.unwrap().is_none());
    assert!(b.read(&md2).await.unwrap().is_none());
    assert!(b.is_empty().await.unwrap());
    assert_eq!(b.bytes().await.unwrap(), 0);
}

#[tokio::test]
async fn list_is_per_tenant_and_run_and_sorted_by_page() {
    let (_, b) = buffer(BufferLimits::default());
    let tenant = TenantId::new();
    let other = TenantId::new();
    let a = CrawlRunId::new();
    let c = CrawlRunId::new();
    for page in [5, 1, 3] {
        insert(&b, tenant, a, page, "markdown", b"x").await;
    }
    insert(&b, tenant, c, 2, "markdown", b"y").await;
    let foreign = insert(&b, other, a, 1, "markdown", b"foreign").await;
    let pages: Vec<_> = b
        .list(tenant, a)
        .await
        .unwrap()
        .into_iter()
        .map(|page| page.page)
        .collect();
    assert_eq!(pages, [1, 3, 5]);
    assert_eq!(b.list(tenant, c).await.unwrap().len(), 1);
    assert!(b.find(tenant, a, foreign.id).await.unwrap().is_none());
    assert!(b.find(other, c, foreign.id).await.unwrap().is_none());
    assert!(b.read_for_run(tenant, a, &foreign).await.unwrap().is_none());
    assert!(b.read_for_run(other, c, &foreign).await.unwrap().is_none());
    assert_eq!(b.purge_run(tenant, a).await.unwrap(), 3);
    assert_eq!(b.len().await.unwrap(), 2);
    assert!(b.get(other, a, 1).await.unwrap().is_some());
    assert!(!b.ack(tenant, a, 1).await.unwrap());
    assert_eq!(b.purge_run_id(a).await.unwrap(), 1);
    assert_eq!(b.len().await.unwrap(), 1);
}

#[tokio::test]
async fn ttl_sweep_hides_then_removes() {
    let (clock, b) = buffer(BufferLimits::default());
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let reference = insert(&b, tenant, run, 1, "markdown", b"x").await;
    clock.advance_ms(30 * 60 * 1000);
    insert(&b, tenant, run, 2, "markdown", b"y").await;
    clock.advance_ms(30 * 60 * 1000);
    assert!(
        b.get(tenant, run, 1).await.unwrap().is_none(),
        "expired pages are not served"
    );
    assert!(b.read(&reference).await.unwrap().is_none());
    assert!(b.find(tenant, run, reference.id).await.unwrap().is_none());
    assert_eq!(b.list(tenant, run).await.unwrap().len(), 1);
    assert_eq!(b.len().await.unwrap(), 2, "still held until swept");
    assert_eq!(b.sweep(clock.now()).await.unwrap(), 1);
    assert_eq!(b.len().await.unwrap(), 1);
    assert_eq!(b.sweep(clock.now()).await.unwrap(), 0);
    clock.advance_ms(30 * 60 * 1000);
    assert_eq!(b.sweep(clock.now()).await.unwrap(), 1);
    assert!(b.is_empty().await.unwrap());
}

#[tokio::test]
async fn reads_and_renditions_never_refresh_first_insert_deadline() {
    let (clock, b) = buffer(BufferLimits {
        ttl: Duration::from_secs(3 * 60 * 60),
        ..BufferLimits::default()
    });
    assert_eq!(b.limits().ttl, DEFAULT_TTL);
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let first = insert(&b, tenant, run, 1, "markdown", b"first").await;
    let before = b.get(tenant, run, 1).await.unwrap().unwrap();
    clock.advance_ms(60 * 60 * 1000 - 1);
    assert!(b.read(&first).await.unwrap().is_some());
    let second = insert(&b, tenant, run, 1, "html", b"second").await;
    let after = b.get(tenant, run, 1).await.unwrap().unwrap();
    assert_eq!(before.inserted_at, after.inserted_at);
    assert_eq!(before.expires_at, after.expires_at);
    clock.advance_ms(1);
    assert!(b.read(&first).await.unwrap().is_none());
    assert!(b.read(&second).await.unwrap().is_none());
    assert_eq!(b.sweep(clock.now()).await.unwrap(), 1);
}

#[tokio::test]
async fn entry_bound_evicts_oldest_first_even_after_rendition_update() {
    let (_, b) = buffer(BufferLimits {
        max_entries: 2,
        ..BufferLimits::default()
    });
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    insert(&b, tenant, run, 1, "markdown", b"a").await;
    insert(&b, tenant, run, 2, "markdown", b"b").await;
    // Touching page 1 must not refresh its eviction age, even with a frozen clock.
    insert(&b, tenant, run, 1, "html", b"<a>").await;
    insert(&b, tenant, run, 3, "markdown", b"c").await;
    let pages: Vec<_> = b
        .list(tenant, run)
        .await
        .unwrap()
        .into_iter()
        .map(|page| page.page)
        .collect();
    assert_eq!(pages, [2, 3]);
    insert(&b, tenant, run, 4, "markdown", b"d").await;
    let pages: Vec<_> = b
        .list(tenant, run)
        .await
        .unwrap()
        .into_iter()
        .map(|page| page.page)
        .collect();
    assert_eq!(pages, [3, 4]);
}

#[tokio::test]
async fn byte_bound_evicts_until_it_fits_and_refuses_oversize() {
    let (_, b) = buffer(BufferLimits {
        max_bytes: 10,
        ..BufferLimits::default()
    });
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    for page in [1, 2, 3] {
        insert(&b, tenant, run, page, "markdown", b"aaaa").await;
    }
    assert_eq!(b.bytes().await.unwrap(), 8);
    let pages: Vec<_> = b
        .list(tenant, run)
        .await
        .unwrap()
        .into_iter()
        .map(|page| page.page)
        .collect();
    assert_eq!(pages, [2, 3]);
    // One rendition larger than the buffer is refused before eviction.
    assert!(matches!(
        b.insert(tenant, run, 4, "markdown", "text/plain", &[0; 11]).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert_eq!(b.len().await.unwrap(), 2);
    // Combined oversized renditions drop the complete page, not just one rendition.
    insert(&b, tenant, run, 5, "markdown", &[0; 6]).await;
    assert!(matches!(
        b.insert(tenant, run, 5, "html", "text/plain", &[0; 6]).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(b.get(tenant, run, 5).await.unwrap().is_none());
    assert!(b.bytes().await.unwrap() <= 10);
}

#[tokio::test]
async fn insert_sweeps_expired_before_evicting_live_pages() {
    let (clock, b) = buffer(BufferLimits {
        max_entries: 2,
        ttl: Duration::from_secs(10),
        ..BufferLimits::default()
    });
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    insert(&b, tenant, run, 1, "markdown", b"expired").await;
    clock.advance_ms(5_000);
    insert(&b, tenant, run, 2, "markdown", b"live").await;
    clock.advance_ms(5_000);
    insert(&b, tenant, run, 3, "markdown", b"new").await;
    assert!(b.get(tenant, run, 1).await.unwrap().is_none());
    assert!(b.get(tenant, run, 2).await.unwrap().is_some());
    assert_eq!(b.len().await.unwrap(), 2);
}

#[tokio::test]
async fn filesystem_startup_sweeps_and_never_touches_durable_artifacts() {
    let root = tempfile::tempdir().unwrap();
    tokio::fs::write(root.path().join("durable-index.json"), b"durable sentinel")
        .await
        .unwrap();
    let clock = clock();
    let limits = BufferLimits {
        ttl: Duration::from_secs(1),
        ..BufferLimits::default()
    };
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let b = DeliveryBuffer::open_fs(root.path(), clock.clone(), limits)
        .await
        .unwrap();
    insert(&b, tenant, run, 1, "markdown", b"x").await;
    let run_dir = root
        .path()
        .join("zdr")
        .join(tenant.to_string())
        .join(run.to_string());
    let orphan = run_dir.join(format!(".page-{}.tmp", ArtifactId::new()));
    tokio::fs::write(&orphan, b"unfinished private content")
        .await
        .unwrap();
    drop(b);
    clock.advance_ms(1_000);
    let reopened = DeliveryBuffer::open_fs(root.path(), clock.clone(), limits)
        .await
        .unwrap();
    assert!(reopened.is_empty().await.unwrap());
    assert!(!tokio::fs::try_exists(run_dir.join("1.json")).await.unwrap());
    assert!(!tokio::fs::try_exists(&orphan).await.unwrap());
    assert_eq!(
        tokio::fs::read(root.path().join("durable-index.json"))
            .await
            .unwrap(),
        b"durable sentinel"
    );
    assert!(tokio::fs::try_exists(root.path().join("zdr/.lock"))
        .await
        .unwrap());
}

#[tokio::test]
async fn filesystem_replacement_preserves_first_insert_mtime_and_is_atomic_on_error() {
    let root = tempfile::tempdir().unwrap();
    let clock = clock();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let b = DeliveryBuffer::open_fs(root.path(), clock.clone(), BufferLimits::default())
        .await
        .unwrap();
    let first = insert(&b, tenant, run, 1, "markdown", b"before").await;
    let path = root
        .path()
        .join("zdr")
        .join(tenant.to_string())
        .join(run.to_string())
        .join("1.json");
    let before = tokio::fs::metadata(&path).await.unwrap().modified().unwrap();
    assert_eq!(before, std::time::SystemTime::from(clock.now()));
    clock.advance_ms(30_000);
    insert(&b, tenant, run, 1, "html", b"second rendition").await;
    assert_eq!(
        tokio::fs::metadata(&path).await.unwrap().modified().unwrap(),
        before
    );
    // An oversized header fails before commit, retaining the complete previous page.
    let huge_kind = "k".repeat(70_000);
    assert!(b
        .insert(tenant, run, 1, &huge_kind, "text/plain", b"x")
        .await
        .is_err());
    assert_eq!(b.read(&first).await.unwrap().unwrap().bytes, b"before");
    let retained = b.get(tenant, run, 1).await.unwrap().unwrap();
    assert_eq!(retained.blobs.len(), 2);
    assert!(!retained.blobs.contains_key(&huge_kind));
}

#[tokio::test]
async fn malformed_files_fail_closed_instead_of_returning_empty_content() {
    let root = tempfile::tempdir().unwrap();
    let clock = clock();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let b = DeliveryBuffer::open_fs(root.path(), clock.clone(), BufferLimits::default())
        .await
        .unwrap();
    insert(&b, tenant, run, 1, "markdown", b"private").await;
    let path = root
        .path()
        .join("zdr")
        .join(tenant.to_string())
        .join(run.to_string())
        .join("1.json");
    tokio::fs::write(path, vec![b'x'; 70_000]).await.unwrap();
    assert!(matches!(
        b.get(tenant, run, 1).await,
        Err(StoreError::Serialization(_))
    ));
    assert_eq!(
        b.len().await.unwrap(),
        0,
        "corrupt content is removed after reporting the error"
    );
    let reopened = DeliveryBuffer::open_fs(root.path(), clock, BufferLimits::default())
        .await
        .unwrap();
    assert!(reopened.is_empty().await.unwrap());
}

#[cfg(unix)]
#[tokio::test]
async fn filesystem_rejects_symlink_namespace_without_writing_target() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    tokio::fs::symlink(outside.path(), root.path().join("zdr"))
        .await
        .unwrap();
    assert!(
        DeliveryBuffer::open_fs(root.path(), clock(), BufferLimits::default())
            .await
            .is_err()
    );
    assert!(tokio::fs::read_dir(outside.path())
        .await
        .unwrap()
        .next_entry()
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn disabled_backend_rejects_all_content_paths() {
    let b = DeliveryBuffer {
        backend: Backend::Disabled,
        clock: clock(),
        limits: BufferLimits::default(),
    };
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let reference = ArtifactRef {
        id: ArtifactId::new(),
        digest: Digest::of("test", b"secret"),
    };
    assert!(!b.is_enabled());
    assert!(matches!(
        b.insert(tenant, run, 1, "markdown", "text/plain", b"x").await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.get(tenant, run, 1).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.list(tenant, run).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.find(tenant, run, reference.id).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.read(&reference).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.read_for_run(tenant, run, &reference).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.ack(tenant, run, 1).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.purge_run(tenant, run).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.purge_run_id(run).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(
        b.sweep(b.clock.now()).await,
        Err(StoreError::RetentionDenied(_))
    ));
    assert!(matches!(b.len().await, Err(StoreError::RetentionDenied(_))));
    assert!(matches!(b.bytes().await, Err(StoreError::RetentionDenied(_))));
    assert!(matches!(b.is_empty().await, Err(StoreError::RetentionDenied(_))));
}

#[tokio::test]
async fn delivery_debug_never_exposes_content_kinds_or_content_types() {
    let (_, b) = buffer(BufferLimits::default());
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let reference = b
        .insert(
            tenant,
            run,
            1,
            "sensitive-kind",
            "sensitive-mime",
            b"sensitive-bytes",
        )
        .await
        .unwrap();
    let page = b.get(tenant, run, 1).await.unwrap().unwrap();
    let blob = b.read(&reference).await.unwrap().unwrap();
    let debug = format!("{page:?} {blob:?} {b:?}");
    for secret in ["sensitive-kind", "sensitive-mime", "sensitive-bytes"] {
        assert!(!debug.contains(secret));
    }
    let encoded = serde_json::to_vec(&page).unwrap();
    assert_eq!(serde_json::from_slice::<BufferedPage>(&encoded).unwrap(), page);
    let encoded = serde_json::to_vec(&blob).unwrap();
    assert_eq!(serde_json::from_slice::<BufferedBlob>(&encoded).unwrap(), blob);
}
