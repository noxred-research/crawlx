//! The lease loop over PostgreSQL enforces the stored authorization record: a run
//! whose record was revoked before the lease is refused, and an `UPDATE authorization_records SET
//! revoked_at = now()` while the run is exploring stops it with `authorization_revoked`.
//! Skipped without `CRAWLX_TEST_DATABASE_URL`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::repo::{CrawlRun, RunRepo, SessionStatus};
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::StaticResolver;
use crawlx_policy::testkit::sample_record;
use crawlx_policy::AuthorizationRecord;
use crawlx_scheduler::RunPlanner;
use crawlx_storage::checkpoint_crypto::{MemoryCheckpointKeys, UnavailableCheckpointKeys};
use crawlx_storage::{FsArtifactStore, Pg, StoreConfig};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{EgressConfig, RunContext, Stores, WorkerConfig, WorkerError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct Rig {
    pg: Pg,
    stores: Stores,
    dir: tempfile::TempDir,
    record: AuthorizationRecord,
}

impl Rig {
    async fn new() -> Option<Self> {
        let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            eprintln!("skipped: CRAWLX_TEST_DATABASE_URL is not set");
            return None;
        };
        let pg = Pg::connect(
            &url,
            StoreConfig {
                schema: Some(format!("t_authz_{}", uuid::Uuid::now_v7().simple())),
                ..StoreConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let tenant = TenantId::new();
        pg.ensure_tenant(tenant, "authz").await.unwrap();
        let runs: Arc<dyn RunRepo> = Arc::new(pg.clone());
        let artifacts = FsArtifactStore::open(dir.path(), runs, Arc::new(SystemClock))
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone()));
        let mut stores = Stores::over_durable(
            crawlx_worker::DurableStore::Postgres(pg.clone()),
            Arc::new(artifacts),
            tenant,
        );
        stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());
        let mut record = sample_record(tenant, SystemClock.now(), &["https://example.test"]);
        record.verified_at = Some(SystemClock.now());
        authorization_fixture::register_verified(&pg, &record).await;
        Some(Self {
            pg,
            stores,
            dir,
            record,
        })
    }

    fn cfg(&self, recheck: Duration) -> WorkerConfig {
        WorkerConfig {
            artifacts_dir: self.dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(StaticResolver::new())),
                ..EgressConfig::default()
            },
            idle_exit_after: Some(Duration::from_millis(700)),
            max_sessions: 1,
            authorization_recheck: recheck,
            gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            ..WorkerConfig::default()
        }
    }

    /// A queued dynamic run that references the stored record.
    async fn enqueue(&self) -> CrawlRunId {
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.seed = Some(20_261_028);
        crawl.limits.interactions = 100_000;
        crawl.limits.states = 100_000;
        crawl.safety.authorization_record_ref = Some(self.record.id);
        crawl.normalize().unwrap();
        let run = CrawlRun {
            id: CrawlRunId::new(),
            tenant: self.stores.tenant,
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
        self.stores.runs.create(&run, None).await.unwrap();
        self.stores
            .runs
            .create_sessions(&RunPlanner::sessions(run.id, &crawl))
            .await
            .unwrap();
        run.id
    }

    /// What an operator does: revoke the stored record.
    async fn revoke(&self, ago: &str) {
        sqlx::query(sqlx::AssertSqlSafe(format!("UPDATE authorization_records SET revoked_at = now() - interval '{ago}', revoked_reason = 'takedown request' WHERE record_id = $1")))
        .bind(self.record.id.0)
        .execute(self.pg.pool())
        .await
        .unwrap();
    }

    async fn teardown(self) {
        self.pg.drop_schema().await.unwrap();
    }
}

/// `n` pages, each linking to every other page: `n·(n−1)` click keys.
fn mesh(n: usize) -> FakeScript {
    let path = |i: usize| if i == 0 { "/".to_owned() } else { format!("/p{i}") };
    let mut script = FakeScript::new();
    for i in 0..n {
        let mut page = FakePage::new(&format!("https://example.test{}", path(i))).title(format!("Page {i}"));
        for j in (0..n).filter(|j| *j != i) {
            let key = format!("to{j}");
            page = page
                .node(FakeAxSpec::link(key.clone(), format!("Go to {j}"), path(j)))
                .on_click(&key, vec![FakeEffect::Navigate(path(j))]);
        }
        script = script.page(page);
    }
    script
}

async fn terminal_reason_in_sql(rig: &Rig, run: CrawlRunId) -> (String, String) {
    sqlx::query_as::<_, (String, String)>(
        "SELECT status::text, terminal_reason::text FROM crawl_runs WHERE run_id = $1",
    )
    .bind(run.0)
    .fetch_one(rig.pg.pool())
    .await
    .unwrap()
}

async fn events(rig: &Rig, run: CrawlRunId, kind: &str) -> Vec<serde_json::Value> {
    rig.stores
        .events
        .list_after(run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == kind)
        .map(|e| e.payload)
        .collect()
}

#[tokio::test]
async fn missing_checkpoint_custody_refuses_an_authorized_dynamic_run_before_browser_acquisition() {
    let Some(mut rig) = Rig::new().await else { return };
    let run_id = rig.enqueue().await;
    let run = rig.stores.runs.get(run_id).await.unwrap();
    let cfg = rig.cfg(Duration::from_secs(60));
    assert!(cfg.checkpoint_keys.is_none());
    let authorization = authorization_fixture::admit(&rig.stores, &run, &cfg).await;
    rig.stores.checkpoint_keys = Arc::new(UnavailableCheckpointKeys);
    let backend = Arc::new(
        FakeBackend::builder()
            .script(mesh(3))
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );

    let result = RunContext::build(
        &run,
        &cfg,
        rig.stores.clone(),
        Some(backend.clone()),
        None,
        CancellationToken::new(),
        None,
        Some(authorization),
    )
    .await;

    assert!(matches!(result, Err(WorkerError::Config(_))));
    assert_eq!(backend.contexts_created(), 0);
    assert!(
        backend.context_handles().is_empty(),
        "no browser context exists to navigate or send target requests"
    );
    assert!(rig.stores.journal.list(run_id, None).await.unwrap().is_empty());
    assert_eq!(
        rig.stores.runs.get(run_id).await.unwrap().status,
        RunStatus::Queued
    );
    rig.teardown().await;
}

#[tokio::test]
async fn a_run_whose_stored_record_was_revoked_before_the_lease_is_refused() {
    let Some(rig) = Rig::new().await else { return };
    let run = rig.enqueue().await;
    rig.revoke("1 second").await;
    let backend = Arc::new(
        FakeBackend::builder()
            .script(mesh(3))
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    run_with(
        rig.cfg(Duration::from_secs(60)),
        rig.stores.clone(),
        Some(backend.clone()),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let row = rig.stores.runs.get(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Failed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    assert_eq!(
        terminal_reason_in_sql(&rig, run).await,
        ("failed".to_owned(), "authorization_revoked".to_owned())
    );
    assert!(
        backend.context_handles().is_empty(),
        "no browser context was opened"
    );
    let sessions = rig.stores.runs.list_sessions(run).await.unwrap();
    assert!(
        sessions.iter().all(|s| s.status != SessionStatus::Completed),
        "{sessions:?}"
    );
    let revoked = events(&rig, run, "authorization.revoked").await;
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert_eq!(revoked[0]["reason"], "revoked");
    assert_eq!(revoked[0]["stage"], "admission");
    rig.teardown().await;
}

#[tokio::test]
async fn revoking_the_stored_record_with_an_update_stops_a_run_mid_flight() {
    let Some(rig) = Rig::new().await else { return };
    let run = rig.enqueue().await;
    let interval = Duration::from_millis(50);
    let cfg = rig.cfg(interval);
    // 90 click keys: far more than the run does before the recheck finds the revocation
    let backend = Arc::new(
        FakeBackend::builder()
            .script(mesh(10))
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let worker = {
        let stores = rig.stores.clone();
        tokio::spawn(async move { run_with(cfg, stores, Some(backend), CancellationToken::new()).await })
    };
    // wait until the run is exploring
    for _ in 0..1000 {
        if rig.stores.journal.list(run, None).await.unwrap().len() >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rig.stores.runs.get(run).await.unwrap().status, RunStatus::Running);
    rig.revoke("0 seconds").await;
    let revoked = Instant::now();
    loop {
        if rig.stores.runs.get(run).await.unwrap().status.is_terminal() {
            break;
        }
        assert!(
            revoked.elapsed() < Duration::from_secs(15),
            "the run kept going after the revocation"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let stopped_after = revoked.elapsed();
    assert!(
        stopped_after < interval + Duration::from_secs(5),
        "stopped {stopped_after:?} after the revocation with a {interval:?} recheck interval"
    );
    tokio::time::timeout(Duration::from_secs(30), worker)
        .await
        .expect("the worker exits once idle")
        .unwrap()
        .unwrap();

    let row = rig.stores.runs.get(run).await.unwrap();
    assert_eq!(row.status, RunStatus::Failed);
    assert_eq!(row.terminal_reason, Some(TerminalReason::AuthorizationRevoked));
    assert_eq!(
        terminal_reason_in_sql(&rig, run).await,
        ("failed".to_owned(), "authorization_revoked".to_owned())
    );
    let actions = rig.stores.journal.list(run, None).await.unwrap().len();
    assert!((3..90).contains(&actions), "{actions} actions journaled");
    let sessions = rig.stores.runs.list_sessions(run).await.unwrap();
    assert!(
        sessions
            .iter()
            .all(|s| s.status == crawlx_core::repo::SessionStatus::Failed),
        "{sessions:?}"
    );
    let revoked = events(&rig, run, "authorization.revoked").await;
    assert_eq!(revoked.len(), 1, "{revoked:?}");
    assert_eq!(revoked[0]["reason"], "revoked");
    rig.teardown().await;
}

#[tokio::test]
async fn rejected_local_admission_never_leaves_a_runnable_run() {
    let Some(rig) = Rig::new().await else { return };
    for retained in [false, true] {
        let mut crawl = CreateCrawl::new("https://example.test/".parse().unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.safety.authorization_record_ref = Some(rig.record.id);
        if retained {
            crawl.dynamic.browser_profile = Some(crawlx_core::config::BrowserProfile {
                name: "unapproved".to_owned(),
                generation: 0,
                save_changes: true,
            });
        } else {
            crawl.roles = vec![crawlx_core::config::Role {
                name: "undeclared".to_owned(),
                credential_ref: Some(crawlx_core::secret::CredentialRef("env://UNDECLARED".to_owned())),
                login_plan: None,
                replica_base_url: None,
            }];
        }
        let local = crawlx_worker::LocalRun::new(crawl, rig.cfg(Duration::ZERO))
            .with_stores(rig.stores.clone())
            .with_authorization(rig.record.clone())
            .with_backend(Arc::new(FakeBackend::new(mesh(2))));
        assert!(matches!(
            crawlx_worker::run_local_with(local).await,
            Err(WorkerError::Config(_))
        ));
    }
    let states: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT status::text, terminal_reason::text FROM crawl_runs WHERE tenant_id = $1 ORDER BY created_at",
    )
    .bind(rig.stores.tenant.0)
    .fetch_all(rig.pg.pool())
    .await
    .unwrap();
    assert_eq!(
        states,
        vec![
            ("failed".to_owned(), Some("fatal_error".to_owned())),
            ("failed".to_owned(), Some("fatal_error".to_owned())),
        ]
    );
    rig.teardown().await;
}
