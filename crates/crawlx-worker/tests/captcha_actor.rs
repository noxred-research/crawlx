//! Controlled loopback CAPTCHA widgets exercise the real actor, kernel, T1 and T2.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use axum::routing::{get, post};
use axum::{Json, Router};
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::captcha::{CaptchaConfig, CaptchaError, CaptchaProvider};
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::identity::ActionKind;
use crawlx_core::page_op::{PageOp, PageOpResult};
use crawlx_core::repo::{ActionJournal, EventRepo, LedgerRepo, StateRepo};
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::{
    AuthorizationRecordId, BrowserBackend as _, BrowserError, CoreError, CreateCrawl, SafetyProfile,
};
use crawlx_scheduler::{RunPlanner, Scheduler};
use crawlx_storage::{testkit::crawl_run, MemoryStore};
use crawlx_worker::actor::{SessionActor, ShutdownReason};
use crawlx_worker::{RunContext, StateAnalyzer, StaticAuthorizationSource, Stores, WorkerConfig};
use serde_json::json;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const KEY: &str = "actor-provider-key-secret-canary";
const TOKEN: &str = "actor-delivered-token-secret-canary";
// wire-compat: the widget marker class below is what the solver matches on target pages
const PAGE: &str = r#"<!doctype html><html><head><title>Controlled challenge</title></head><body>
<form id="danger" action="/destroy" method="post"><div class="g-recaptcha" data-sitekey="controlled-key" data-callback="accepted"></div></form><!-- wire-compat -->
<h1 id="result">Waiting</h1><output id="token"></output>
<script>function accepted(token) {
 document.getElementById('result').textContent = 'Solved';
 document.getElementById('token').textContent = token;
 console.log(token);
 try { document.getElementById('danger').submit(); } catch (_) {}
}</script></body></html>"#;

struct FixtureKey;
#[async_trait]
impl SecretResolver for FixtureKey {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        assert_eq!(reference.0, "env://ACTOR_CAPTCHA_FIXTURE");
        Ok(SecretOr::secret(KEY.to_owned()))
    }
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Server {
    base: url::Url,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = url::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let cancel = CancellationToken::new();
        let stop = cancel.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(stop.cancelled_owned())
                .await
                .unwrap();
        });
        Self { base, cancel, task }
    }
    async fn close(self) {
        self.cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap();
    }
}

fn assert_no_secret(bytes: &[u8]) {
    for secret in [KEY, TOKEN] {
        assert!(
            !bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "secret canary escaped its runtime-only boundary"
        );
    }
}

async fn assert_artifacts_redacted(root: &Path) {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        let mut entries = tokio::fs::read_dir(directory).await.unwrap();
        while let Some(entry) = entries.next_entry().await.unwrap() {
            let kind = entry.file_type().await.unwrap();
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                directories.push(entry.path());
            } else {
                assert_no_secret(&tokio::fs::read(entry.path()).await.unwrap());
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn actor_refuses_read_only_before_billing_and_commits_one_authorized_redacted_solve() {
    let Some(executable) = std::env::var_os("CRAWLX_CHROMIUM_PATH") else {
        eprintln!("SKIP: CRAWLX_CHROMIUM_PATH absent; real pinned Chromium required");
        return;
    };
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);

    for profile in [SafetyProfile::ReadOnly, SafetyProfile::TestEnvironment] {
        let creates = Arc::new(AtomicUsize::new(0));
        let t1_seen = Arc::new(AtomicBool::new(false));
        let destructive_posts = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&destructive_posts);
        let site = Server::start(
            Router::new()
                .route("/", get(|| async { axum::response::Html(PAGE) }))
                .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
                .route(
                    "/destroy",
                    post(move || {
                        let count = Arc::clone(&count);
                        async move {
                            count.fetch_add(1, Ordering::SeqCst);
                            "forbidden"
                        }
                    }),
                ),
        )
        .await;
        let dir = tempfile::tempdir().unwrap();
        let memory = Arc::new(MemoryStore::new());
        let stores = Stores::over_memory(Arc::clone(&memory), dir.path())
            .await
            .unwrap();
        let mut crawl = CreateCrawl::new(site.base.clone());
        crawl.seed = Some(7);
        crawl.safety.profile = profile;
        crawl.safety.allow_private_networks = true;
        crawl.safety.authorization_record_ref = Some(AuthorizationRecordId::new());
        let record = common::authorization::verified_record(&crawl, stores.tenant);
        let stores = stores.with_authorization_source(Arc::new(StaticAuthorizationSource::new(record)));
        let mut run = crawl_run(stores.tenant, crawl);
        let run_id = run.id;
        let provider_store = Arc::clone(&memory);
        let create_count = Arc::clone(&creates);
        let observed_t1 = Arc::clone(&t1_seen);
        let provider = Server::start(
            Router::new()
                .route(
                    "/createTask",
                    post(move |Json(body): Json<serde_json::Value>| {
                        let store = Arc::clone(&provider_store);
                        let count = Arc::clone(&create_count);
                        let seen = Arc::clone(&observed_t1);
                        async move {
                            assert_eq!(body["clientKey"], KEY);
                            let actions = ActionJournal::list(store.as_ref(), run_id, None).await.unwrap();
                            let intended: Vec<_> = actions
                                .iter()
                                .filter(|action| action.key.action_kind == ActionKind::SolveCaptcha)
                                .collect();
                            assert_eq!(intended.len(), 1, "billing requires exactly one durable intent");
                            assert_eq!(intended[0].status, ActionStatus::Intended);
                            assert!(intended[0].intended_at.is_some() && intended[0].before_state.is_some());
                            seen.store(true, Ordering::SeqCst);
                            count.fetch_add(1, Ordering::SeqCst);
                            Json(json!({"errorId":0,"taskId":"controlled-task"}))
                        }
                    }),
                )
                .route(
                    "/getTaskResult",
                    post(|| async {
                        Json(json!({"errorId":0,"status":"ready","solution":{"gRecaptchaResponse":TOKEN}}))
                        // wire-compat: provider API field
                    }),
                ),
        )
        .await;
        let mut solver = CaptchaConfig::new(
            CaptchaProvider::TaskApi,
            CredentialRef("env://ACTOR_CAPTCHA_FIXTURE".into()),
        );
        solver.endpoint = provider.base.clone();
        solver.timeout_seconds = 10;
        solver.poll_interval_ms = 1;
        run.config.crawl.captcha = Some(solver);
        run.config_digest = run.config.digest().unwrap();
        stores.runs.create(&run, None).await.unwrap();
        let sessions = RunPlanner::sessions(run.id, &run.config);
        stores.runs.create_sessions(&sessions).await.unwrap();
        stores
            .runs
            .set_status(run.id, RunStatus::Running, None)
            .await
            .unwrap();
        let session = &sessions[0];
        let cfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            ..WorkerConfig::default()
        };
        let authorization = common::authorization::admit(&stores, &run, &cfg).await;
        let mut launch = LaunchConfig::new();
        launch.executable = executable.clone().into();
        // Keep browser pin, sandbox and normal browser admission enabled. No fallback.
        let backend = Arc::new(ChromiumBackend::launch(launch).await.unwrap());
        let rc = RunContext::build(
            &run,
            &cfg,
            stores.clone(),
            Some(backend.clone()),
            Some(Arc::new(FixtureKey)),
            CancellationToken::new(),
            None,
            Some(authorization),
        )
        .await
        .unwrap();
        // Creating sessions leaves them pending. Claim through the real scheduler:
        // T1 correctly refuses an actor whose durable session has no live grant.
        let scheduler = Scheduler::new(Arc::clone(&stores.leases));
        let lease = scheduler
            .lease_in_run(run.id, rc.worker, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(lease.session.id, session.id);
        assert_eq!(lease.session.status, crawlx_core::repo::SessionStatus::Running);
        let heartbeat_cancel = CancellationToken::new();
        let heartbeat = scheduler.keep_alive(lease.clone(), Duration::from_secs(1), heartbeat_cancel.clone());
        let config = rc.session_config(session);
        let pooled = rc
            .pool
            .acquire(config.context.clone(), config.exclusive_browser)
            .await
            .unwrap();
        let analyzer = Arc::new(StateAnalyzer::new(
            run.id,
            session.id,
            rc.clusters.clone(),
            Arc::clone(&stores.artifacts),
            Arc::clone(&rc.clock),
            run.config.capture.clone(),
            (&rc.controls, &rc.captcha_secrets),
        ));
        let handle = SessionActor::spawn(config, rc.services(), analyzer, 7, pooled)
            .await
            .unwrap();
        let navigation = handle
            .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                rc.seed_url().unwrap(),
                0,
                None,
            ))
            .await;
        let actions = ActionJournal::list(memory.as_ref(), run.id, None).await.unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].key.action_kind, ActionKind::SolveCaptcha);
        if profile == SafetyProfile::ReadOnly {
            assert!(matches!(
                navigation,
                Err(crawlx_worker::SessionError::Browser(BrowserError::Captcha(
                    CaptchaError::PolicyDenied
                )))
            ));
            assert_eq!(actions[0].status, ActionStatus::Proposed);
            assert!(actions[0].intended_at.is_none() && actions[0].finished_at.is_none());
            assert_eq!(creates.load(Ordering::SeqCst), 0);
            assert!(!t1_seen.load(Ordering::SeqCst));
        } else {
            navigation.unwrap();
            assert_eq!(actions[0].status, ActionStatus::Succeeded);
            assert!(actions[0].intended_at.is_some() && actions[0].finished_at.is_some());
            assert!(actions[0].before_state.is_some());
            assert_eq!(creates.load(Ordering::SeqCst), 1);
            assert!(t1_seen.load(Ordering::SeqCst));
            let observation = handle
                .observe(crawlx_observe::spec::after_action())
                .await
                .unwrap();
            assert_no_secret(format!("{observation:?}").as_bytes());
            match handle.page_op(PageOp::Html).await.unwrap() {
                PageOpResult::Html { html, .. } => {
                    assert!(html.contains("Solved"));
                    assert_no_secret(html.as_bytes());
                }
                other => panic!("unexpected HTML reply: {other:?}"),
            }
            assert_eq!(
                ActionJournal::list(memory.as_ref(), run.id, None)
                    .await
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                creates.load(Ordering::SeqCst),
                1,
                "observing the solved page must not bill again"
            );
            assert!(
                memory.list_states(run.id).await.unwrap().len() >= 2,
                "T2 persists the after-state"
            );
            let events = EventRepo::list_after(memory.as_ref(), run.id, 0, 1000)
                .await
                .unwrap();
            assert!(events.iter().any(|event| event.kind == "action.finished"));
            let ledger = LedgerRepo::list(memory.as_ref(), run.id).await.unwrap();
            assert_eq!(
                ledger.iter().map(|entry| entry.trusted_exercised).sum::<u32>(),
                0,
                "solver injection is diagnostic, not trusted UI coverage"
            );
        }
        assert_eq!(
            destructive_posts.load(Ordering::SeqCst),
            0,
            "solver callback must not submit the form"
        );
        assert_no_secret(&serde_json::to_vec(&actions).unwrap());
        assert_no_secret(&serde_json::to_vec(&memory.list_states(run.id).await.unwrap()).unwrap());
        assert_no_secret(
            &serde_json::to_vec(
                &EventRepo::list_after(memory.as_ref(), run.id, 0, 1000)
                    .await
                    .unwrap(),
            )
            .unwrap(),
        );
        handle.shutdown(ShutdownReason::Graceful).await.unwrap();
        heartbeat_cancel.cancel();
        heartbeat.await.unwrap().unwrap();
        scheduler.complete(&lease).await.unwrap();
        backend.shutdown_confirmed().await.unwrap();
        assert_artifacts_redacted(dir.path()).await;
        provider.close().await;
        site.close().await;
    }
    assert_no_secret(&logs.0.lock().unwrap());
}
