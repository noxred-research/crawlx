//! Cross-process zero-data-retention delivery, expiry, bounds, and crash recovery.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::{DateTime, Utc};
use crawlx_core::time::ManualClock;
use crawlx_core::{ArtifactId, ArtifactRef, Clock as _, CrawlRunId, TenantId};
use crawlx_storage::{BufferLimits, BufferedBlob, BufferedPage, DeliveryBuffer};
use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

const ROOT_ENV: &str = "CRAWLX_ZDR_PROCESS_ROOT";
const REDIS_ENV: &str = "CRAWLX_TEST_ZDR_REDIS_URL";
const CHILD_REDIS_ENV: &str = "CRAWLX_ZDR_PROCESS_REDIS_URL";
const EPOCH: &str = "2026-01-01T00:00:00Z";
const CRASH_EXIT: i32 = 23;
const LOCK_READY: &str = "ZDR_LOCKED";

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(EPOCH.parse::<DateTime<Utc>>().unwrap()))
}

fn limits(max_entries: usize, max_bytes: usize) -> BufferLimits {
    let mut limits = BufferLimits::default();
    limits.max_entries = max_entries;
    limits.max_bytes = max_bytes;
    limits
}

fn child_command(root: &Path, tenant: TenantId, run: CrawlRunId, role: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "process_child", "--nocapture", "--test-threads=1"])
        .env(ROOT_ENV, root)
        .env("CRAWLX_ZDR_PROCESS_TENANT", tenant.to_string())
        .env("CRAWLX_ZDR_PROCESS_RUN", run.to_string())
        .env("CRAWLX_ZDR_PROCESS_ROLE", role);
    command
}

async fn child_output(mut command: Command) -> Output {
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "child status {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn page_path(root: &Path, tenant: TenantId, run: CrawlRunId, page: i64) -> PathBuf {
    root.join("zdr")
        .join(tenant.to_string())
        .join(run.to_string())
        .join(format!("{page}.json"))
}

async fn insert(buffer: &DeliveryBuffer, tenant: TenantId, run: CrawlRunId, page: i64) -> ArtifactRef {
    buffer
        .insert(tenant, run, page, "markdown", "text/markdown", b"one!")
        .await
        .unwrap()
}

// A synchronous harness entry is needed for the real std::process child and lock-holder role.
// The producer uses its own runtime; no parent memory or runtime state crosses the process boundary.
#[test]
fn process_child() {
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        return;
    };
    let root = PathBuf::from(root);
    let tenant = std::env::var("CRAWLX_ZDR_PROCESS_TENANT")
        .unwrap()
        .parse::<TenantId>()
        .unwrap();
    let run = std::env::var("CRAWLX_ZDR_PROCESS_RUN")
        .unwrap()
        .parse::<CrawlRunId>()
        .unwrap();
    let role = std::env::var("CRAWLX_ZDR_PROCESS_ROLE").unwrap();
    if role == "hold-lock" {
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join("zdr/.lock"))
            .unwrap();
        lock.lock().unwrap();
        let directory = page_path(&root, tenant, run, 1).parent().unwrap().to_owned();
        std::fs::write(
            directory.join(format!(".page-{}.tmp", ArtifactId::new())),
            b"private incomplete page",
        )
        .unwrap();
        println!("{LOCK_READY}");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let clock = clock();
        let offset =
            std::env::var("CRAWLX_ZDR_PROCESS_OFFSET").map_or(0, |value| value.parse::<i64>().unwrap());
        clock.advance_ms(offset);
        let max_entries =
            std::env::var("CRAWLX_ZDR_PROCESS_ENTRIES").map_or(8, |value| value.parse::<usize>().unwrap());
        let max_bytes =
            std::env::var("CRAWLX_ZDR_PROCESS_BYTES").map_or(64, |value| value.parse::<usize>().unwrap());
        let mut configured_limits = limits(max_entries, max_bytes);
        if let Ok(ttl_ms) = std::env::var("CRAWLX_ZDR_PROCESS_TTL_MS") {
            configured_limits.ttl = std::time::Duration::from_millis(ttl_ms.parse().unwrap());
        }
        let buffer = if let Ok(url) = std::env::var(CHILD_REDIS_ENV) {
            DeliveryBuffer::open_redis(&url, clock, configured_limits)
                .await
                .unwrap()
        } else {
            DeliveryBuffer::open_fs(&root, clock, configured_limits)
                .await
                .unwrap()
        };
        match role.as_str() {
            "produce" | "crash-produce" => {
                insert(&buffer, tenant, run, 1).await;
                buffer
                    .insert(tenant, run, 1, "html", "text/html", b"<p/>")
                    .await
                    .unwrap();
                insert(&buffer, tenant, run, 2).await;
                if role == "crash-produce" {
                    // Exit without Rust destructors after committed writes.
                    std::process::exit(CRASH_EXIT);
                }
            }
            "insert" => {
                let first = std::env::var("CRAWLX_ZDR_PROCESS_PAGE")
                    .unwrap()
                    .parse::<i64>()
                    .unwrap();
                let count = std::env::var("CRAWLX_ZDR_PROCESS_COUNT")
                    .map_or(1, |value| value.parse::<i64>().unwrap());
                for page in first..first.checked_add(count).unwrap() {
                    insert(&buffer, tenant, run, page).await;
                }
            }
            _ => panic!("unknown child role {role}"),
        }
    });
}

#[tokio::test]
async fn producer_exit_and_crash_leave_tenant_scoped_content_for_another_process() {
    for role in ["produce", "crash-produce"] {
        let directory = tempfile::tempdir().unwrap();
        let tenant = TenantId::new();
        let other = TenantId::new();
        let run = CrawlRunId::new();
        let clock = clock();
        // Open before the child writes: reads must not use a stale process-local index.
        let consumer = DeliveryBuffer::open_fs(directory.path(), clock.clone(), limits(8, 64))
            .await
            .unwrap();
        let output = child_output(child_command(directory.path(), tenant, run, role)).await;
        if role == "crash-produce" {
            assert_eq!(output.status.code(), Some(CRASH_EXIT));
        } else {
            assert_success(&output);
        }
        let pages = consumer.list(tenant, run).await.unwrap();
        assert_eq!(pages.len(), 2);
        let page = consumer.get(tenant, run, 1).await.unwrap().unwrap();
        assert_eq!(page.tenant, tenant);
        assert_eq!(page.run, run);
        assert_eq!(page.blobs["markdown"].bytes, b"one!");
        assert_eq!(page.blobs["html"].bytes, b"<p/>");
        let artifact = &page.blobs["markdown"].artifact;
        let blob = consumer
            .read_for_run(tenant, run, artifact)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(blob.content_type, "text/markdown");
        assert_eq!(consumer.read(artifact).await.unwrap(), Some(blob.clone()));
        assert_eq!(
            serde_json::from_slice::<BufferedPage>(&serde_json::to_vec(&page).unwrap()).unwrap(),
            page,
        );
        assert_eq!(
            serde_json::from_slice::<BufferedBlob>(&serde_json::to_vec(&blob).unwrap()).unwrap(),
            blob,
        );
        assert!(consumer.get(other, run, 1).await.unwrap().is_none());
        assert!(consumer.list(other, run).await.unwrap().is_empty());
        assert!(consumer.find(other, run, artifact.id).await.unwrap().is_none());
        assert!(consumer
            .read_for_run(other, run, artifact)
            .await
            .unwrap()
            .is_none());
        assert!(consumer
            .read_for_run(tenant, CrawlRunId::new(), artifact)
            .await
            .unwrap()
            .is_none());
        assert!(!consumer.ack(other, run, 1).await.unwrap());
        assert_eq!(consumer.purge_run(other, run).await.unwrap(), 0);
        let other_artifact = insert(&consumer, other, run, 1).await;
        assert!(consumer
            .read_for_run(tenant, run, &other_artifact)
            .await
            .unwrap()
            .is_none());
        assert_eq!(consumer.find(tenant, run, artifact.id).await.unwrap(), Some(blob));
        let wrong_digest = ArtifactRef {
            id: artifact.id,
            digest: crawlx_core::hash::Digest::of("wrong", b"digest"),
        };
        assert!(consumer
            .read_for_run(tenant, run, &wrong_digest)
            .await
            .unwrap()
            .is_none());

        // A successful delivery acknowledges the entire page, including every rendition.
        assert!(consumer.ack(tenant, run, 1).await.unwrap());
        assert!(!consumer.ack(tenant, run, 1).await.unwrap());
        assert!(
            !tokio::fs::try_exists(page_path(directory.path(), tenant, run, 1))
                .await
                .unwrap()
        );
        assert!(consumer.read(artifact).await.unwrap().is_none());
        assert!(consumer
            .read(&page.blobs["html"].artifact)
            .await
            .unwrap()
            .is_none());
        let reopened = DeliveryBuffer::open_fs(directory.path(), clock, limits(8, 64))
            .await
            .unwrap();
        assert!(reopened.get(tenant, run, 1).await.unwrap().is_none());
        assert!(reopened.get(other, run, 1).await.unwrap().is_some());
        assert_eq!(reopened.purge_run(tenant, run).await.unwrap(), 1);
        assert!(consumer.list(tenant, run).await.unwrap().is_empty());
        assert!(consumer.read(&other_artifact).await.unwrap().is_some());
    }
}

#[tokio::test]
async fn reads_and_renditions_do_not_refresh_exact_ttl_and_sweeper_removes_files() {
    let directory = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let clock = clock();
    let buffer = DeliveryBuffer::open_fs(directory.path(), clock.clone(), limits(8, 64))
        .await
        .unwrap();
    assert_success(&child_output(child_command(directory.path(), tenant, run, "produce")).await);
    let original = buffer.get(tenant, run, 1).await.unwrap().unwrap();
    let artifact = &original.blobs["markdown"].artifact;
    let ttl_ms = i64::try_from(buffer.limits().ttl.as_millis()).unwrap();
    clock.advance_ms(ttl_ms.checked_sub(1).unwrap());
    assert!(buffer.read(artifact).await.unwrap().is_some());
    assert!(buffer
        .read_for_run(tenant, run, artifact)
        .await
        .unwrap()
        .is_some());
    assert!(buffer.find(tenant, run, artifact.id).await.unwrap().is_some());
    assert_eq!(buffer.list(tenant, run).await.unwrap().len(), 2);
    buffer
        .insert(tenant, run, 1, "json", "application/json", b"{}")
        .await
        .unwrap();
    let near_expiry = buffer.get(tenant, run, 1).await.unwrap().unwrap();
    assert_eq!(near_expiry.inserted_at, original.inserted_at);
    assert_eq!(near_expiry.expires_at, original.expires_at);
    let first_path = page_path(directory.path(), tenant, run, 1);
    let second_path = page_path(directory.path(), tenant, run, 2);
    assert!(tokio::fs::try_exists(&first_path).await.unwrap());
    assert!(tokio::fs::try_exists(&second_path).await.unwrap());
    clock.advance_ms(1);
    assert_eq!(clock.now(), original.expires_at);
    assert_eq!(buffer.sweep(clock.now()).await.unwrap(), 2);
    assert!(!tokio::fs::try_exists(first_path).await.unwrap());
    assert!(!tokio::fs::try_exists(second_path).await.unwrap());
    assert!(buffer.get(tenant, run, 1).await.unwrap().is_none());
    assert!(buffer.read(artifact).await.unwrap().is_none());
    assert!(buffer
        .read_for_run(tenant, run, artifact)
        .await
        .unwrap()
        .is_none());
    assert!(buffer.find(tenant, run, artifact.id).await.unwrap().is_none());
    assert!(buffer.list(tenant, run).await.unwrap().is_empty());
    assert!(buffer.is_empty().await.unwrap());
    assert_eq!(buffer.bytes().await.unwrap(), 0);
    assert_eq!(buffer.sweep(clock.now()).await.unwrap(), 0);
}

#[tokio::test]
async fn expired_content_is_unreadable_without_an_explicit_sweep() {
    let directory = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let clock = clock();
    let buffer = DeliveryBuffer::open_fs(directory.path(), clock.clone(), limits(8, 64))
        .await
        .unwrap();
    let artifact = insert(&buffer, tenant, run, 1).await;
    clock.advance_ms(i64::try_from(buffer.limits().ttl.as_millis()).unwrap());
    assert!(buffer
        .read_for_run(tenant, run, &artifact)
        .await
        .unwrap()
        .is_none());
    assert!(buffer.read(&artifact).await.unwrap().is_none());
    assert!(buffer.get(tenant, run, 1).await.unwrap().is_none());
    assert!(buffer.find(tenant, run, artifact.id).await.unwrap().is_none());
    assert!(buffer.list(tenant, run).await.unwrap().is_empty());
}

#[tokio::test]
async fn entry_and_byte_bounds_apply_across_handles_and_concurrent_processes() {
    for (max_entries, max_bytes) in [(2, 64), (8, 8)] {
        let directory = tempfile::tempdir().unwrap();
        let tenant = TenantId::new();
        let run = CrawlRunId::new();
        let clock = clock();
        let buffer = DeliveryBuffer::open_fs(directory.path(), clock.clone(), limits(max_entries, max_bytes))
            .await
            .unwrap();
        let peer = DeliveryBuffer::open_fs(directory.path(), clock.clone(), limits(max_entries, max_bytes))
            .await
            .unwrap();
        insert(&buffer, tenant, run, 1).await;
        clock.advance_ms(1);
        insert(&peer, tenant, run, 2).await;
        let mut command = child_command(directory.path(), tenant, run, "insert");
        command
            .env("CRAWLX_ZDR_PROCESS_PAGE", "3")
            .env("CRAWLX_ZDR_PROCESS_OFFSET", "2")
            .env("CRAWLX_ZDR_PROCESS_ENTRIES", max_entries.to_string())
            .env("CRAWLX_ZDR_PROCESS_BYTES", max_bytes.to_string());
        assert_success(&child_output(command).await);
        assert!(buffer.get(tenant, run, 1).await.unwrap().is_none());
        assert_eq!(buffer.len().await.unwrap(), 2);
        assert_eq!(peer.bytes().await.unwrap(), 8);
        assert_eq!(
            peer.list(tenant, run)
                .await
                .unwrap()
                .iter()
                .map(|page| page.page)
                .collect::<Vec<_>>(),
            [2, 3],
        );

        let mut commands = [
            child_command(directory.path(), tenant, run, "insert"),
            child_command(directory.path(), tenant, run, "insert"),
        ];
        for (command, first) in commands.iter_mut().zip([10, 30]) {
            command
                .env("CRAWLX_ZDR_PROCESS_PAGE", first.to_string())
                .env("CRAWLX_ZDR_PROCESS_COUNT", "20")
                .env("CRAWLX_ZDR_PROCESS_OFFSET", "3")
                .env("CRAWLX_ZDR_PROCESS_ENTRIES", max_entries.to_string())
                .env("CRAWLX_ZDR_PROCESS_BYTES", max_bytes.to_string());
        }
        let outputs = tokio::task::spawn_blocking(move || {
            let [mut first, mut second] = commands;
            let first = first
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let second = second
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            [
                first.wait_with_output().unwrap(),
                second.wait_with_output().unwrap(),
            ]
        })
        .await
        .unwrap();
        for output in &outputs {
            assert_success(output);
        }
        assert_eq!(buffer.len().await.unwrap(), 2);
        assert_eq!(peer.bytes().await.unwrap(), 8);
        assert_eq!(buffer.list(tenant, run).await.unwrap().len(), 2);
        assert!(peer.get(tenant, run, 2).await.unwrap().is_none());
        assert!(peer.get(tenant, run, 3).await.unwrap().is_none());
    }
}

#[tokio::test]
async fn killed_lock_holder_releases_lock_and_partial_temp_is_never_delivered() {
    let directory = tempfile::tempdir().unwrap();
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let clock = clock();
    let buffer = DeliveryBuffer::open_fs(directory.path(), clock.clone(), limits(8, 64))
        .await
        .unwrap();
    let artifact = insert(&buffer, tenant, run, 1).await;
    let durable = directory.path().join("content/sentinel");
    tokio::fs::create_dir_all(durable.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&durable, b"unrelated durable content")
        .await
        .unwrap();
    let mut command = child_command(directory.path(), tenant, run, "hold-lock");
    tokio::task::spawn_blocking(move || {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut ready = false;
        for line in std::io::BufReader::new(stdout).lines() {
            if line.unwrap().contains(LOCK_READY) {
                ready = true;
                break;
            }
        }
        if !ready {
            let status = child.wait().unwrap();
            panic!("lock-holder exited before readiness: {status}");
        }
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
    })
    .await
    .unwrap();
    let reopened = DeliveryBuffer::open_fs(directory.path(), clock, limits(8, 64))
        .await
        .unwrap();
    assert_eq!(reopened.read(&artifact).await.unwrap().unwrap().bytes, b"one!");
    assert_eq!(reopened.len().await.unwrap(), 1);
    assert_eq!(reopened.bytes().await.unwrap(), 4);
    let page_directory = page_path(directory.path(), tenant, run, 1)
        .parent()
        .unwrap()
        .to_owned();
    let mut files = tokio::fs::read_dir(page_directory).await.unwrap();
    while let Some(file) = files.next_entry().await.unwrap() {
        assert_ne!(
            file.path().extension().and_then(|extension| extension.to_str()),
            Some("tmp")
        );
    }
    assert_eq!(
        tokio::fs::read(durable).await.unwrap(),
        b"unrelated durable content"
    );
    assert!(buffer.ack(tenant, run, 1).await.unwrap());
    assert!(reopened.read(&artifact).await.unwrap().is_none());
}

fn redis_child_command(url: &str, tenant: TenantId, run: CrawlRunId, role: &str) -> Command {
    let mut command = child_command(Path::new("."), tenant, run, role);
    command.env(CHILD_REDIS_ENV, url);
    command
}

// Redis capacity is deployment-global. Keep this executable's Redis scenarios serial.
static REDIS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn redis_process_exchange_ack_expiry_and_crash_preserve_tenant_boundaries() {
    let Ok(url) = std::env::var(REDIS_ENV) else {
        eprintln!("skipped: CRAWLX_TEST_ZDR_REDIS_URL is not set");
        return;
    };
    let _guard = REDIS_LOCK.lock().await;
    for role in ["produce", "crash-produce"] {
        let tenant = TenantId::new();
        let other = TenantId::new();
        let run = CrawlRunId::new();
        let clock = clock();
        let consumer = DeliveryBuffer::open_redis(&url, clock.clone(), limits(8, 64))
            .await
            .unwrap();
        let output = child_output(redis_child_command(&url, tenant, run, role)).await;
        if role == "crash-produce" {
            assert_eq!(output.status.code(), Some(CRASH_EXIT));
        } else {
            assert_success(&output);
        }
        let page = consumer.get(tenant, run, 1).await.unwrap().unwrap();
        let artifact = &page.blobs["markdown"].artifact;
        assert_eq!(page.tenant, tenant);
        assert_eq!(page.blobs["markdown"].bytes, b"one!");
        assert_eq!(page.blobs["html"].bytes, b"<p/>");
        assert_eq!(consumer.list(tenant, run).await.unwrap().len(), 2);
        assert!(consumer.get(other, run, 1).await.unwrap().is_none());
        assert!(consumer.list(other, run).await.unwrap().is_empty());
        assert!(consumer.find(other, run, artifact.id).await.unwrap().is_none());
        assert!(consumer
            .read_for_run(other, run, artifact)
            .await
            .unwrap()
            .is_none());
        assert!(consumer
            .read_for_run(tenant, CrawlRunId::new(), artifact)
            .await
            .unwrap()
            .is_none());
        assert!(!consumer.ack(other, run, 1).await.unwrap());
        assert_eq!(consumer.purge_run(other, run).await.unwrap(), 0);
        assert!(consumer.ack(tenant, run, 1).await.unwrap());
        assert!(!consumer.ack(tenant, run, 1).await.unwrap());
        assert!(consumer.read(artifact).await.unwrap().is_none());
        assert!(consumer
            .read(&page.blobs["html"].artifact)
            .await
            .unwrap()
            .is_none());
        let peer = DeliveryBuffer::open_redis(&url, clock.clone(), limits(8, 64))
            .await
            .unwrap();
        assert!(peer.get(tenant, run, 1).await.unwrap().is_none());
        let remaining = peer.get(tenant, run, 2).await.unwrap().unwrap();
        let remaining_artifact = &remaining.blobs["markdown"].artifact;
        let ttl_ms = i64::try_from(peer.limits().ttl.as_millis()).unwrap();
        clock.advance_ms(ttl_ms.checked_sub(1).unwrap());
        assert!(consumer.read(remaining_artifact).await.unwrap().is_some());
        assert!(consumer
            .read_for_run(tenant, run, remaining_artifact)
            .await
            .unwrap()
            .is_some());
        assert!(peer
            .find(tenant, run, remaining_artifact.id)
            .await
            .unwrap()
            .is_some());
        peer.insert(tenant, run, 2, "json", "application/json", b"{}")
            .await
            .unwrap();
        let unchanged = peer.get(tenant, run, 2).await.unwrap().unwrap();
        assert_eq!(unchanged.inserted_at, remaining.inserted_at);
        assert_eq!(unchanged.expires_at, remaining.expires_at);
        clock.advance_ms(1);
        assert_eq!(clock.now(), remaining.expires_at);
        assert_eq!(peer.sweep(clock.now()).await.unwrap(), 1);
        assert!(consumer.get(tenant, run, 2).await.unwrap().is_none());
        assert!(consumer.read(remaining_artifact).await.unwrap().is_none());
        assert!(consumer.list(tenant, run).await.unwrap().is_empty());
        assert!(consumer.is_empty().await.unwrap());
        assert_eq!(consumer.bytes().await.unwrap(), 0);

        // Expired reads must fail even when no sweeper or native server expiry has run.
        let expired_on_read = insert(&peer, tenant, run, 3).await;
        clock.advance_ms(ttl_ms.checked_sub(1).unwrap());
        assert!(consumer.read(&expired_on_read).await.unwrap().is_some());
        clock.advance_ms(1);
        assert!(consumer.read(&expired_on_read).await.unwrap().is_none());
        assert!(consumer
            .read_for_run(tenant, run, &expired_on_read)
            .await
            .unwrap()
            .is_none());
        assert!(consumer.get(tenant, run, 3).await.unwrap().is_none());
        assert!(consumer
            .find(tenant, run, expired_on_read.id)
            .await
            .unwrap()
            .is_none());
        assert!(consumer.list(tenant, run).await.unwrap().is_empty());
        peer.sweep(clock.now()).await.unwrap();
        assert!(consumer.is_empty().await.unwrap());
    }
}

#[tokio::test]
async fn redis_entry_and_byte_bounds_cover_handles_and_concurrent_processes() {
    let Ok(url) = std::env::var(REDIS_ENV) else {
        eprintln!("skipped: CRAWLX_TEST_ZDR_REDIS_URL is not set");
        return;
    };
    let _guard = REDIS_LOCK.lock().await;
    for (max_entries, max_bytes) in [(2, 64), (8, 8)] {
        let tenant = TenantId::new();
        let run = CrawlRunId::new();
        let clock = clock();
        let buffer = DeliveryBuffer::open_redis(&url, clock.clone(), limits(max_entries, max_bytes))
            .await
            .unwrap();
        let peer = DeliveryBuffer::open_redis(&url, clock.clone(), limits(max_entries, max_bytes))
            .await
            .unwrap();
        insert(&buffer, tenant, run, 1).await;
        clock.advance_ms(1);
        insert(&peer, tenant, run, 2).await;
        let mut command = redis_child_command(&url, tenant, run, "insert");
        command
            .env("CRAWLX_ZDR_PROCESS_PAGE", "3")
            .env("CRAWLX_ZDR_PROCESS_OFFSET", "2")
            .env("CRAWLX_ZDR_PROCESS_ENTRIES", max_entries.to_string())
            .env("CRAWLX_ZDR_PROCESS_BYTES", max_bytes.to_string());
        assert_success(&child_output(command).await);
        assert!(buffer.get(tenant, run, 1).await.unwrap().is_none());
        assert_eq!(buffer.len().await.unwrap(), 2);
        assert_eq!(peer.bytes().await.unwrap(), 8);
        let mut first = redis_child_command(&url, tenant, run, "insert");
        let mut second = redis_child_command(&url, tenant, run, "insert");
        for (command, page) in [(&mut first, 10), (&mut second, 30)] {
            command
                .env("CRAWLX_ZDR_PROCESS_PAGE", page.to_string())
                .env("CRAWLX_ZDR_PROCESS_COUNT", "20")
                .env("CRAWLX_ZDR_PROCESS_OFFSET", "3")
                .env("CRAWLX_ZDR_PROCESS_ENTRIES", max_entries.to_string())
                .env("CRAWLX_ZDR_PROCESS_BYTES", max_bytes.to_string());
        }
        let (first_output, second_output) = tokio::join!(child_output(first), child_output(second));
        assert_success(&first_output);
        assert_success(&second_output);
        assert_eq!(buffer.len().await.unwrap(), 2);
        assert_eq!(peer.bytes().await.unwrap(), 8);
        assert_eq!(buffer.list(tenant, run).await.unwrap().len(), 2);
        assert!(peer.get(tenant, run, 2).await.unwrap().is_none());
        assert!(peer.get(tenant, run, 3).await.unwrap().is_none());
        assert_eq!(peer.purge_run(tenant, run).await.unwrap(), 2);
    }
}

#[tokio::test]
async fn redis_native_ttl_expires_with_a_frozen_application_clock_without_read_refresh() {
    let Ok(url) = std::env::var(REDIS_ENV) else {
        eprintln!("skipped: CRAWLX_TEST_ZDR_REDIS_URL is not set");
        return;
    };
    let _guard = REDIS_LOCK.lock().await;
    let tenant = TenantId::new();
    let run = CrawlRunId::new();
    let clock = clock();
    let mut configured_limits = limits(8, 64);
    configured_limits.ttl = std::time::Duration::from_millis(1_000);
    let buffer = DeliveryBuffer::open_redis(&url, clock.clone(), configured_limits)
        .await
        .unwrap();
    let artifact = insert(&buffer, tenant, run, 1).await;
    let page = buffer.get(tenant, run, 1).await.unwrap().unwrap();
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut connection = client.get_multiplexed_async_connection().await.unwrap();
    let page_key = format!("crawlx:zdr:{{delivery}}:page:{tenant}:{run}:1");
    let wait_key = format!("crawlx:zdr:{{delivery}}:test-wait:{tenant}");
    let initial_ttl: i64 = redis::cmd("PTTL")
        .arg(&page_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(initial_ttl > 0 && initial_ttl <= 1_000, "{initial_ttl}");

    // Redis itself waits on an absent list. No sleeps or application-clock advance
    // can create the elapsed server time needed to prove that a rendition does not refresh TTL.
    let waiting: Option<(String, String)> = redis::cmd("BLPOP")
        .arg(&wait_key)
        .arg("0.05")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(waiting.is_none());
    let before_refresh: i64 = redis::cmd("PTTL")
        .arg(&page_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(before_refresh > 0 && before_refresh < initial_ttl);
    assert!(buffer.read(&artifact).await.unwrap().is_some());
    assert!(buffer
        .read_for_run(tenant, run, &artifact)
        .await
        .unwrap()
        .is_some());
    buffer
        .insert(tenant, run, 1, "html", "text/html", b"<p/>")
        .await
        .unwrap();
    let after_refresh: i64 = redis::cmd("PTTL")
        .arg(&page_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(after_refresh > 0 && after_refresh <= before_refresh);
    assert_eq!(
        buffer.get(tenant, run, 1).await.unwrap().unwrap().expires_at,
        page.expires_at
    );

    let waiting: Option<(String, String)> = redis::cmd("BLPOP")
        .arg(&wait_key)
        .arg("1.1")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!(waiting.is_none());
    let expired_ttl: i64 = redis::cmd("PTTL")
        .arg(&page_key)
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        expired_ttl, -2,
        "Redis removed the page hash, not just its API visibility"
    );
    assert_eq!(clock.now(), EPOCH.parse::<DateTime<Utc>>().unwrap());
    assert!(buffer.get(tenant, run, 1).await.unwrap().is_none());
    assert!(buffer.read(&artifact).await.unwrap().is_none());
    assert!(buffer
        .read_for_run(tenant, run, &artifact)
        .await
        .unwrap()
        .is_none());
    assert!(buffer.find(tenant, run, artifact.id).await.unwrap().is_none());
    assert!(buffer.list(tenant, run).await.unwrap().is_empty());
    assert!(buffer.is_empty().await.unwrap());
    assert_eq!(buffer.bytes().await.unwrap(), 0);
}
