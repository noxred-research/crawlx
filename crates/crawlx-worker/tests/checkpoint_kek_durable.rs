//! The local key-encryption-key (KEK) file provider on the durable stores other than
//! PostgreSQL: SQLite (always) and MariaDB (`CRAWLX_TEST_MARIADB_URL`), each with filesystem
//! artifacts and with an S3-compatible artifact store (an in-process S3 server).
//!
//! On every store the keyless worker refuses a browser-mode run with `checkpoint_keys_required`;
//! with `CRAWLX_CHECKPOINT_KEK_FILE` the run is admitted and a checkpoint written under the
//! primary key id restores; after a rotation the old checkpoint still restores while new ones
//! use the new id; and an unusable file leaves the worker refusing browser runs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::checkpoint_crypto::HEADER_BYTES;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{PlaneCounters, RunFailure, RunFailureCode, RunStatus, TerminalReason};
use crawlx_core::repo::{ArtifactStore, CheckpointRecord, CrawlRun};
use crawlx_core::{
    BrowserBackend as _, Clock, ContextConfig, CrawlRunId, CreateCrawl, ObservationEpoch, SystemClock,
    TenantId,
};
use crawlx_fetch::StaticResolver;
use crawlx_scheduler::{CheckpointReason, RunPlanner};
use crawlx_storage::checkpoint_crypto::{CheckpointContext, CheckpointCryptoError, CheckpointKeys};
use crawlx_storage::s3::S3Profile;
use crawlx_storage::sql::Sql;
use crawlx_storage::testkit::fake_s3::FakeS3;
use crawlx_storage::testkit::Rig;
use crawlx_storage::{FsArtifactStore, S3ArtifactStore, Store};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{Checkpointer, DurableStore, EgressConfig, Stores, WorkerConfig, WorkerError};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const KEK_OLD: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
const KEK_NEW: &str = "7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c";
const PAGE_URL: &str = "https://example.test/a";

fn worker(dir: &Path) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        idle_exit_after: Some(Duration::from_millis(1_500)),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

/// The worker configuration of a process started with `kek` as `CRAWLX_CHECKPOINT_KEK_FILE`.
async fn worker_with_kek(dir: &Path, kek: &Path) -> Result<WorkerConfig, WorkerError> {
    let mut cfg = worker(dir);
    cfg.load_checkpoint_keys_from_lookup(&|name| {
        (name == "CRAWLX_CHECKPOINT_KEK_FILE").then(|| kek.display().to_string())
    })
    .await?;
    Ok(cfg)
}

/// A KEK file in `dir`: one `<id>:<key>` line per entry, primary first.
fn kek_file(dir: &Path, name: &str, keys: &[(&str, &str)], mode: u32) -> PathBuf {
    let path = dir.join(name);
    let body: String = keys.iter().map(|(id, key)| format!("{id}:{key}\n")).collect();
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn app() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .node(FakeAxSpec::link("a", "A", "/a"))
                .on_click("a", vec![FakeEffect::Navigate("/a".into())]),
        )
        .page(
            FakePage::new(PAGE_URL)
                .title("A")
                .node(FakeAxSpec::link("h", "Home", "/"))
                .on_click("h", vec![FakeEffect::Navigate("/".into())]),
        )
}

fn fake_browser() -> Arc<FakeBackend> {
    Arc::new(
        FakeBackend::builder()
            .script(app())
            .clock(Arc::new(SystemClock))
            .build(),
    )
}

/// What the API does: persist a queued browser-mode run and its sessions.
async fn enqueue_dynamic(stores: &Stores) -> CrawlRunId {
    let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
    crawl.mode = CrawlMode::Dynamic;
    crawl.limits.interactions = 20;
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    run.id
}

async fn run_failures(stores: &Stores, run: CrawlRunId) -> Vec<RunFailure> {
    stores
        .events
        .list_after(run, 0, 1_000)
        .await
        .unwrap()
        .iter()
        .filter(|event| event.kind == RunFailure::EVENT_KIND)
        .map(|event| RunFailure::from_event_payload(&event.payload).expect("a typed failure"))
        .collect()
}

/// Lease and run everything queued in `stores` with `cfg`; the browser the run used.
async fn work(cfg: WorkerConfig, stores: &Stores) -> Arc<FakeBackend> {
    let backend = fake_browser();
    run_with(
        cfg,
        stores.clone(),
        Some(backend.clone()),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    backend
}

async fn artifacts_over<B: Sql>(store: &Store<B>, dir: &Path, s3: Option<&FakeS3>) -> Arc<dyn ArtifactStore> {
    let runs: Arc<dyn crawlx_core::repo::RunRepo> = Arc::new(store.clone());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    match s3 {
        None => Arc::new(
            FsArtifactStore::open(dir, runs, clock)
                .await
                .unwrap()
                .with_index(Arc::new(store.clone())),
        ),
        Some(server) => {
            let config = server.config(S3Profile::Compatible);
            Arc::new(
                S3ArtifactStore::new(
                    server
                        .blobs_with(&config)
                        .unwrap()
                        .with_deployment(Arc::new(store.clone())),
                    runs,
                    clock,
                )
                .with_index(Arc::new(store.clone())),
            )
        }
    }
}

/// Durable stores over the rig's migrated database, with no checkpoint key provider.
async fn keyless_stores(rig: &Rig, dir: &Path, s3: Option<&FakeS3>) -> Stores {
    rig.migrate().await;
    let durable = DurableStore::open(rig.database()).unwrap();
    let tenant = TenantId::new();
    durable.ensure_tenant(tenant, "kek-durable").await.unwrap();
    let artifacts = crawlx_worker::on_store!(&durable, store => artifacts_over(store, dir, s3).await);
    let stores = Stores::over_durable(durable, artifacts, tenant);
    assert!(
        !stores.checkpoint_keys.is_available(),
        "a durable open installs no checkpoint provider of its own"
    );
    stores
}

/// The key id a file-wrapped checkpoint envelope names.
fn wrapped_key_id(envelope: &[u8]) -> String {
    let len = usize::from(envelope[HEADER_BYTES]);
    String::from_utf8(envelope[HEADER_BYTES + 1..HEADER_BYTES + 1 + len].to_vec()).unwrap()
}

/// Write one checkpoint of `run`'s first session with `keys`, as the actor does.
async fn checkpoint_with(
    stores: &Stores,
    run: CrawlRunId,
    keys: &Arc<dyn CheckpointKeys>,
) -> (Checkpointer, CheckpointRecord) {
    let session = stores.runs.list_sessions(run).await.unwrap().remove(0).id;
    let checkpointer = Checkpointer::new(
        stores.tenant,
        run,
        session,
        stores.checkpoints.clone(),
        stores.artifacts.clone(),
        Arc::new(SystemClock),
        1,
    )
    .with_keys(Arc::clone(keys));
    let backend = fake_browser();
    let mut context = backend.new_context(ContextConfig::new(session)).await.unwrap();
    let record = checkpointer
        .write(
            context.as_mut(),
            PAGE_URL,
            Some("default"),
            ObservationEpoch::default(),
            7,
            CheckpointReason::Shutdown,
        )
        .await
        .unwrap();
    (checkpointer, record)
}

async fn stored_key_id(stores: &Stores, record: &CheckpointRecord) -> String {
    wrapped_key_id(&stores.artifacts.get(&record.storage).await.unwrap())
}

async fn open_with(
    keys: &dyn CheckpointKeys,
    stores: &Stores,
    record: &CheckpointRecord,
) -> Result<(), CheckpointCryptoError> {
    let context = CheckpointContext::new(stores.tenant, record.run, record.session, record.id);
    let bytes = stores.artifacts.get(&record.storage).await.unwrap();
    keys.open(&context, bytes).await.map(|_| ())
}

/// Every claim of the module doc, on one durable store.
async fn kek_file_lifecycle(rig: Rig, s3: Option<FakeS3>) {
    let dir = tempfile::tempdir().unwrap();
    let stores = keyless_stores(&rig, dir.path(), s3.as_ref()).await;

    // (1) no provider: the browser-mode run is refused with the typed reason
    let refused = enqueue_dynamic(&stores).await;
    let backend = work(worker(dir.path()), &stores).await;
    let row = stores.runs.get(refused).await.unwrap();
    assert_eq!(row.status, RunStatus::Failed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::FatalError));
    assert!(
        backend.context_handles().is_empty(),
        "no browser context was acquired"
    );
    let failures = run_failures(&stores, refused).await;
    assert_eq!(failures.len(), 1, "{failures:?}");
    assert_eq!(failures[0].code, RunFailureCode::CheckpointKeysRequired);
    assert_eq!(failures[0].code.as_str(), "checkpoint_keys_required");

    // (2) the KEK file admits the run the keyless worker refused
    let kek_v1 = kek_file(dir.path(), "v1.kek", &[("k1", KEK_OLD)], 0o600);
    let cfg_v1 = worker_with_kek(dir.path(), &kek_v1).await.unwrap();
    let keys_v1 = cfg_v1
        .checkpoint_keys
        .clone()
        .expect("the file installs the provider");
    let admitted = enqueue_dynamic(&stores).await;
    work(cfg_v1, &stores).await;
    let row = stores.runs.get(admitted).await.unwrap();
    assert_eq!(row.status, RunStatus::Completed, "{:?}", row.terminal_reason);
    assert!(row.counters.interactions.attempted >= 2);
    assert!(run_failures(&stores, admitted).await.is_empty());

    // a checkpoint written under the primary key id restores (the artifact of a checkpoint is
    // removed when its run ends, so these are written to a run that is still queued)
    let live = enqueue_dynamic(&stores).await;
    let (checkpointer_v1, old) = checkpoint_with(&stores, live, &keys_v1).await;
    assert_eq!(stored_key_id(&stores, &old).await, "k1");
    let payload = checkpointer_v1.load(&old).await.unwrap();
    assert_eq!((payload.url.as_str(), payload.action_seq), (PAGE_URL, 7));
    let at_rest = stores.artifacts.get(&old.storage).await.unwrap();
    assert!(
        !at_rest
            .windows(PAGE_URL.len())
            .any(|window| window == PAGE_URL.as_bytes()),
        "the stored checkpoint is ciphertext"
    );
    if let Some(server) = &s3 {
        assert!(
            server.objects().values().any(|object| *object == at_rest),
            "the ciphertext is the object in the bucket"
        );
    }

    // (3) rotate: the new key goes on top, the old line stays
    let kek_v2 = kek_file(dir.path(), "v2.kek", &[("k2", KEK_NEW), ("k1", KEK_OLD)], 0o600);
    let cfg_v2 = worker_with_kek(dir.path(), &kek_v2).await.unwrap();
    let keys_v2 = cfg_v2.checkpoint_keys.clone().unwrap();
    open_with(keys_v2.as_ref(), &stores, &old)
        .await
        .expect("the retained old line still unwraps the old checkpoint");
    let restorer = Checkpointer::new(
        stores.tenant,
        old.run,
        old.session,
        stores.checkpoints.clone(),
        stores.artifacts.clone(),
        Arc::new(SystemClock),
        1,
    )
    .with_keys(Arc::clone(&keys_v2));
    let payload = restorer.load(&old).await.unwrap();
    assert_eq!((payload.url.as_str(), payload.action_seq), (PAGE_URL, 7));
    let (checkpointer_v2, fresh) = checkpoint_with(&stores, live, &keys_v2).await;
    assert_eq!(
        stored_key_id(&stores, &fresh).await,
        "k2",
        "new checkpoints use the new primary"
    );
    assert_eq!(checkpointer_v2.load(&fresh).await.unwrap().url, PAGE_URL);
    assert!(matches!(
        open_with(keys_v1.as_ref(), &stores, &fresh).await,
        Err(CheckpointCryptoError::UnknownKey)
    ));
    // the rotated worker admits and runs the run that holds both checkpoints
    work(cfg_v2, &stores).await;
    let row = stores.runs.get(live).await.unwrap();
    assert_eq!(row.status, RunStatus::Completed, "{:?}", row.terminal_reason);
    assert!(run_failures(&stores, live).await.is_empty());

    // (4) an unusable file fails closed: the provider is not installed and the run stays refused
    let group_writable = kek_file(dir.path(), "group.kek", &[("k1", KEK_OLD)], 0o660);
    let world_readable = kek_file(dir.path(), "world.kek", &[("k1", KEK_OLD)], 0o604);
    let unreadable = kek_file(dir.path(), "none.kek", &[("k1", KEK_OLD)], 0o000);
    let mut bad = vec![
        (group_writable, "0600"),
        (world_readable, "0600"),
        (dir.path().join("absent.kek"), "unavailable"),
        (dir.path().to_path_buf(), "regular file"),
    ];
    if std::fs::File::open(&unreadable).is_err() {
        bad.push((unreadable, "unavailable"));
    }
    for (path, hint) in bad {
        let mut cfg = worker(dir.path());
        let error = cfg
            .load_checkpoint_keys_from_lookup(&|name| {
                (name == "CRAWLX_CHECKPOINT_KEK_FILE").then(|| path.display().to_string())
            })
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("CRAWLX_CHECKPOINT_KEK_FILE"), "{message}");
        assert!(message.contains(hint), "{}: {message}", path.display());
        assert!(!message.contains(KEK_OLD));
        assert!(cfg.checkpoint_keys.is_none(), "{}", path.display());

        let still_refused = enqueue_dynamic(&stores).await;
        let backend = work(cfg, &stores).await;
        assert!(backend.context_handles().is_empty());
        assert_eq!(
            stores.runs.get(still_refused).await.unwrap().status,
            RunStatus::Failed
        );
        let failures = run_failures(&stores, still_refused).await;
        assert_eq!(failures.len(), 1, "{failures:?}");
        assert_eq!(failures[0].code, RunFailureCode::CheckpointKeysRequired);
    }

    drop(stores);
    rig.close().await;
}

#[tokio::test]
async fn sqlite_kek_file_admits_and_checkpoints_browser_runs() {
    kek_file_lifecycle(Rig::sqlite().await, None).await;
}

#[tokio::test]
async fn sqlite_with_s3_artifacts_kek_file_admits_and_checkpoints_browser_runs() {
    let server = FakeS3::start().await.unwrap();
    kek_file_lifecycle(Rig::sqlite().await, Some(server)).await;
}

#[tokio::test]
async fn mariadb_kek_file_admits_and_checkpoints_browser_runs() {
    let Some(rig) = Rig::mariadb().await else {
        eprintln!("skipped: CRAWLX_TEST_MARIADB_URL is not set");
        return;
    };
    kek_file_lifecycle(rig, None).await;
}

#[tokio::test]
async fn mariadb_with_s3_artifacts_kek_file_admits_and_checkpoints_browser_runs() {
    let Some(rig) = Rig::mariadb().await else {
        eprintln!("skipped: CRAWLX_TEST_MARIADB_URL is not set");
        return;
    };
    let server = FakeS3::start().await.unwrap();
    kek_file_lifecycle(rig, Some(server)).await;
}
