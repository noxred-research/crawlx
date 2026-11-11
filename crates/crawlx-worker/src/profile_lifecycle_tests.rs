//! Optional real-browser regressions for approved retained-profile lifecycle.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::actor::SessionConfig;
use crate::config::{EgressConfig, WorkerConfig};
use crate::run::{run_session, RunContext};
use crate::{AuthorizationGuard, DriverConfig, StaticAuthorizationSource, Stores};
use crawlx_core::browser::BrowserContext;
use crawlx_core::config::{BrowserProfile, CrawlMode};
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::observation::ObservationSpec;
use crawlx_core::page_op::{PageOp, PageOpResult};
use crawlx_core::repo::{CrawlRun, SessionStatus};
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock, TenantId};
use crawlx_fetch::{EgressOptions, EgressProxyHandle, StaticResolver};
use crawlx_scheduler::{RunPlanner, Scheduler};
use crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys;
use crawlx_storage::{FsArtifactStore, Pg, PgConfig};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

const WAIT: Duration = Duration::from_secs(60);
const HOME: &str = r#"<!doctype html><title>Retained profile fixture</title>
<button onclick="window.open('/popup')">Open</button>"#;

struct Fixture {
    rc: Arc<RunContext>,
    pg: Pg,
    scheduler: Scheduler,
    blocked: Arc<Notify>,
    proxy: EgressProxyHandle,
    stop: CancellationToken,
    server: JoinSet<()>,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new(seed_path: &str) -> Option<Self> {
        let (Some(database), Some(executable)) = (
            std::env::var_os("CRAWLX_TEST_DATABASE_URL"),
            std::env::var_os("CRAWLX_CHROMIUM_PATH"),
        ) else {
            eprintln!("skipped: CRAWLX_TEST_DATABASE_URL and CRAWLX_CHROMIUM_PATH are required");
            return None;
        };
        // Missing tmpfs is a failed prerequisite, never a disk-backed fallback.
        check_tmpfs().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let blocked = Arc::new(Notify::new());
        let notify = Arc::clone(&blocked);
        let app = axum::Router::new()
            .route("/", axum::routing::get(|| async { axum::response::Html(HOME) }))
            .route(
                "/popup",
                axum::routing::get(|| async { axum::response::Html("<title>Popup</title>") }),
            )
            .route(
                "/robots.txt",
                axum::routing::get(|| async { "User-agent: *\nAllow: /\n" }),
            )
            .route(
                "/blocked",
                axum::routing::get(move || {
                    let notify = Arc::clone(&notify);
                    async move {
                        notify.notify_one();
                        std::future::pending::<&'static str>().await
                    }
                }),
            );
        let stop = CancellationToken::new();
        let shutdown = stop.clone();
        let mut server = JoinSet::new();
        server.spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(shutdown.cancelled_owned())
                .await
                .unwrap();
        });
        let pg = Pg::connect(
            database.to_str().unwrap(),
            PgConfig {
                schema: Some(format!("profile_restart_{}", uuid::Uuid::now_v7().simple())),
                ..PgConfig::default()
            },
        )
        .await
        .unwrap();
        pg.migrate().await.unwrap();
        let tenant = TenantId::new();
        pg.ensure_tenant(tenant, "profile-fixture").await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let artifacts = FsArtifactStore::open(dir.path(), Arc::new(pg.clone()), Arc::new(SystemClock))
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone()));
        // This public seam intentionally installs a non-custody artifact store. Retained
        // profiles remain unavailable with artifact custody; do not clear a live authority.
        let mut stores = Stores::over_pg(pg.clone(), Arc::new(artifacts), tenant);
        assert!(stores.custody.is_none());
        stores.checkpoint_keys = Arc::new(MemoryCheckpointKeys::new().unwrap());
        let mut crawl = CreateCrawl::new(format!("{origin}{seed_path}").parse().unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.seed = Some(26_111_117);
        crawl.runs_per_role = 2;
        crawl.limits.duration_seconds = 180;
        crawl.dynamic.max_tabs = 2;
        crawl.dynamic.browser_profile = Some(BrowserProfile {
            name: "approved_fixture".to_owned(),
            save_changes: true,
        });
        crawl.safety.profile = crawlx_core::SafetyProfile::TestEnvironment;
        crawl.safety.allow_private_networks = true;
        let now = SystemClock.now();
        let mut record = crawlx_policy::testkit::sample_record(tenant, now, &[&origin]);
        record.verified_at = Some(now);
        record.authorized_networks = vec!["127.0.0.1/32".parse().unwrap()];
        crawl.safety.authorization_record_ref = Some(record.id);
        let body = serde_json::to_value(&record).unwrap();
        let digest = record.body_digest().unwrap();
        pg.ensure_authorization_record(&crawlx_storage::AuthorizationRow {
            tenant,
            record: record.id,
            version: i32::try_from(record.version).unwrap(),
            body: &body,
            body_digest: &digest.0,
            valid_from: record.valid_from,
            valid_to: record.valid_to,
        })
        .await
        .unwrap();
        crawlx_storage::PgApiRepo::new(pg.clone())
            .authorization_mark_verified(
                tenant,
                record.id,
                &serde_json::json!({"kind": "test_fixture"}),
                now,
            )
            .await
            .unwrap()
            .unwrap();
        let run = CrawlRun {
            id: CrawlRunId::new(),
            tenant,
            status: RunStatus::Running,
            terminal_reason: None,
            seed: crawl.effective_seed(),
            config_digest: crawl.digest().unwrap(),
            config: crawl.clone(),
            policy_version: 1,
            counters: PlaneCounters::default(),
            created_at: now,
            started_at: Some(now),
            finished_at: None,
            trace_id: None,
        };
        stores.runs.create(&run, None).await.unwrap();
        stores
            .runs
            .create_sessions(&RunPlanner::sessions(run.id, &crawl))
            .await
            .unwrap();
        stores = stores.with_authorization_source(Arc::new(StaticAuthorizationSource::new(record.clone())));
        // Resolve an actual local test key. No environment lookup or operational secret is used.
        let key_path = dir.path().join("profile.key");
        tokio::fs::write(&key_path, "42".repeat(32)).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .await
                .unwrap();
        }
        let cfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            retained_profiles: Some(RetainedProfilePolicy {
                key_ref: crawlx_core::secret::CredentialRef(format!("file://{}", key_path.display())),
                max_ttl: Duration::from_secs(600),
                executable_preferences: true,
            }),
            egress: EgressConfig {
                extra_allow: vec!["127.0.0.1/32".parse().unwrap()],
                resolver: Some(Arc::new(StaticResolver::new())),
                ..EgressConfig::default()
            },
            gates: crate::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            launch: crawlx_browser::LaunchConfig {
                executable: executable.into(),
                allow_unpinned: true,
                unsafe_no_sandbox_for_ci: std::env::var("USER").is_ok_and(|user| user == "root"),
                ..crawlx_browser::LaunchConfig::default()
            },
            ..WorkerConfig::default()
        };
        let guard = AuthorizationGuard::admit(
            run.id,
            Some(record.clone()),
            Some(record.id),
            Arc::clone(stores.authorization.as_ref().unwrap()),
            Arc::new(SystemClock),
            Arc::clone(&stores.events),
            cfg.authorization_recheck,
        )
        .await
        .unwrap();
        let proxy = cfg
            .egress
            .serve_proxy(
                &crawl,
                run.id,
                Some(&record),
                cfg.egress.resolver_for(&crawl).unwrap(),
                EgressOptions::new(),
            )
            .await
            .unwrap();
        let resolver =
            crate::secrets::ChainResolver::new().with("file", Arc::new(crate::secrets::FileSecretResolver));
        let rc = Arc::new(
            RunContext::build(
                &run,
                &cfg,
                stores,
                None,
                Some(Arc::new(resolver)),
                CancellationToken::new(),
                Some(&proxy),
                Some(guard),
            )
            .await
            .unwrap(),
        );
        crate::acquisition::admit_runtime(&rc, &cfg, false, true)
            .await
            .unwrap();
        let scheduler = Scheduler::new(Arc::clone(&rc.stores.leases));
        Some(Self {
            rc,
            pg,
            scheduler,
            blocked,
            proxy,
            stop,
            server,
            _dir: dir,
        })
    }

    async fn claim(&self) -> SessionLease {
        self.scheduler
            .lease_in_run(self.rc.run, self.rc.worker, false)
            .await
            .unwrap()
            .expect("eligible real PostgreSQL session lease")
    }

    async fn acquire(&self, lease: &SessionLease) -> (SessionConfig, crate::pool::PooledContext) {
        let mut cfg = self.rc.session_config(&lease.session);
        let pooled = tokio::time::timeout(WAIT, self.rc.acquire_bound_session(lease, &mut cfg))
            .await
            .unwrap()
            .unwrap();
        (cfg, pooled)
    }

    async fn finish(mut self) {
        self.rc.supervisor.shutdown().await;
        self.rc.pool.shutdown_persistent().await;
        self.proxy.shutdown().await;
        self.stop.cancel();
        self.server.shutdown().await;
        self.pg.drop_schema().await.unwrap();
    }
}

async fn evaluate(context: &mut dyn BrowserContext, script: &str) -> serde_json::Value {
    let result = context
        .page_op(PageOp::EvaluateScript {
            script: script.to_owned(),
        })
        .await
        .unwrap();
    let PageOpResult::Json(value) = result else {
        panic!("expected browser script result")
    };
    value
}

async fn close(pooled: crate::pool::PooledContext) {
    let (context, _, capacity) = pooled.into_parts();
    tokio::time::timeout(WAIT, context.close())
        .await
        .unwrap()
        .unwrap();
    // Owned-process shutdown has its own bounded kill/reap path; do not cancel it.
    capacity.release(true).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approved_owned_profile_restores_browser_cookie_and_storage_after_confirmed_restart() {
    let Some(f) = Fixture::new("/").await else { return };
    let first = f.claim().await;
    let (cfg, mut pooled) = f.acquire(&first).await;
    let build = pooled.build.clone();
    let binding = cfg.context.session_binding.as_ref().unwrap();
    assert_eq!(
        binding.identity.egress,
        f.rc.egress.route_for(&f.rc.crawl).unwrap().egress_digest()
    );
    assert!(!cfg.context.incognito);
    assert!(cfg.exclusive_browser);
    let path = Path::new(PROFILE_TMPFS).join(&cfg.context.browser_profile.as_ref().unwrap().dir);
    pooled.ctx.navigate(&f.rc.seed_url().unwrap()).await.unwrap();
    assert_eq!(
        evaluate(pooled.ctx.as_mut(), "localStorage.getItem('retained')").await,
        serde_json::Value::Null
    );
    assert_eq!(
        evaluate(
            pooled.ctx.as_mut(),
            r#"(() => {
        document.cookie = 'profile_fixture=retained; Max-Age=3600; Path=/; SameSite=Lax';
        localStorage.setItem('retained', 'approved-state');
        return localStorage.getItem('retained');
    })()"#
        )
        .await,
        "approved-state"
    );
    close(pooled).await;
    assert!(
        !path.exists(),
        "plaintext copy must be erased after encrypted save"
    );
    assert_eq!(
        f.rc.pool.browsers(),
        0,
        "release confirms exclusive process death"
    );
    let (cipher, egress) = ProfileRun::encryption(&f.rc).await.unwrap();
    let foreign = ProfileScopeV1::new(
        TenantId::new(),
        first.session.role.clone(),
        "approved_fixture".to_owned(),
        BTreeSet::from([f.rc.seed_origin()]),
        binding.identity.backend_build,
        egress,
    )
    .unwrap();
    assert!(
        BrowserProfileRepo::new(&f.pg, cipher.as_ref())
            .acquire(&first, &foreign, true)
            .await
            .is_err(),
        "a real lease cannot acquire profile state for another tenant"
    );
    f.scheduler
        .release(&first, SessionStatus::Completed)
        .await
        .unwrap();

    // A distinct scheduler session performs an approved restart, not an implicit
    // same-actor generation swap or storage import into an already-running browser.
    let second = f.claim().await;
    assert_ne!(second.session.id, first.session.id);
    assert_eq!(second.session.role, first.session.role);
    let (cfg, mut restarted) = f.acquire(&second).await;
    assert_eq!(restarted.build, build, "compatible browser build is mandatory");
    assert_eq!(
        cfg.context.session_binding.as_ref().unwrap().identity.tenant,
        f.rc.stores.tenant
    );
    restarted.ctx.navigate(&f.rc.seed_url().unwrap()).await.unwrap();
    assert_eq!(
        evaluate(restarted.ctx.as_mut(), "localStorage.getItem('retained')").await,
        "approved-state"
    );
    assert!(evaluate(restarted.ctx.as_mut(), "document.cookie")
        .await
        .as_str()
        .unwrap()
        .split(';')
        .any(|cookie| cookie.trim() == "profile_fixture=retained"));
    close(restarted).await;
    f.scheduler
        .release(&second, SessionStatus::Completed)
        .await
        .unwrap();
    assert_eq!(f.rc.pool.browsers(), 0);
    f.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_during_real_profile_navigation_returns_fenced_session_lease() {
    let Some(f) = Fixture::new("/blocked").await else {
        return;
    };
    let lease = f.claim().await;
    let request = crawlx_core::request::RequestEnvelopeV1::get(f.rc.seed_url().unwrap(), 0, None);
    let mut running = Box::pin(run_session(
        Arc::clone(&f.rc),
        f.scheduler.clone(),
        lease.clone(),
        async move { Ok(vec![request]) },
        DriverConfig::default(),
        None,
    ));
    tokio::select! {
        end = &mut running => panic!("session ended before fixture navigation: {end:?}"),
        () = tokio::time::sleep(WAIT) => panic!("profile navigation did not reach loopback fixture"),
        () = f.blocked.notified() => {}
    }
    f.scheduler
        .heartbeat(&lease)
        .await
        .expect("cancellation must exercise the existing live real lease");
    f.rc.cancel.cancel();
    let end = tokio::time::timeout(WAIT, &mut running).await.unwrap();
    assert_eq!(end.terminal, TerminalReason::Cancelled);
    assert_eq!(end.error, None);
    assert!(
        f.scheduler.heartbeat(&lease).await.is_err(),
        "the old holder must lose authority after cleanup"
    );
    assert_eq!(
        f.rc.pool.browsers(),
        0,
        "capacity returns only after owned process death"
    );
    let replacement = f.claim().await;
    assert_eq!(replacement.session.id, lease.session.id);
    assert!(replacement.fencing_token > lease.fencing_token);
    f.scheduler.heartbeat(&replacement).await.unwrap();
    assert!(f.scheduler.heartbeat(&lease).await.is_err());
    f.scheduler
        .release(&replacement, SessionStatus::Completed)
        .await
        .unwrap();
    f.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approved_profile_bounds_admitted_tabs_and_one_pending_popup() {
    use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
    let Some(f) = Fixture::new("/").await else { return };
    let lease = f.claim().await;
    let (_, mut pooled) = f.acquire(&lease).await;
    pooled.ctx.navigate(&f.rc.seed_url().unwrap()).await.unwrap();
    let observed = pooled.ctx.observe(ObservationSpec::default()).await.unwrap();
    let open = observed
        .ax
        .nodes
        .iter()
        .find(|node| node.name.as_deref() == Some("Open"))
        .expect("fixture popup button")
        .locator
        .clone();
    for _ in 0..5 {
        pooled
            .ctx
            .perform(BrowserAction::Click {
                target: open.clone(),
                button: PointerButton::Left,
                modifiers: Modifiers::default(),
            })
            .await
            .unwrap();
    }
    // Target events arrive after browser-side creation. The native bound is two
    // admitted tabs plus one quarantined target, not a physical pre-creation cap.
    let mut largest = 1;
    let mut largest_admitted = 1;
    let mut largest_pending = 0;
    for _ in 0..40 {
        let observed = pooled.ctx.observe(ObservationSpec::default()).await.unwrap();
        largest = largest.max(observed.tabs.len());
        largest_admitted = largest_admitted.max(observed.tabs.iter().filter(|tab| !tab.pending).count());
        largest_pending = largest_pending.max(observed.tabs.iter().filter(|tab| tab.pending).count());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    close(pooled).await;
    f.scheduler
        .release(&lease, SessionStatus::Completed)
        .await
        .unwrap();
    f.finish().await;
    assert!(
        largest <= 3,
        "total tracked targets include the one quarantine slot"
    );
    assert_eq!(largest_admitted, 2);
    assert_eq!(largest_pending, 1);
}
