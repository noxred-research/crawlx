//! The crawlx side of the wire families, in process: the compat facade
//! on a real TCP port, a REAL worker lease loop over the same store (the in-memory store or one
//! throwaway schema of `CRAWLX_TEST_DATABASE_URL`), a webhook sender delivering to the runner's
//! sink, and a CrawlerGym server, all reached under the host names the upstream containers use
//! (`gym.test`, ...): admission denies literal loopback, so the worker's injected resolver maps
//! the names of `d2::HOSTS` to 127.0.0.1.
//!
//! The worker runs on a runtime of its own (over PostgreSQL its connection pool lives there
//! too). Killing it drops that runtime, which abandons every task of the worker without running
//! any cleanup, the in-process equivalent of `SIGKILL`: its session lease stays held until the
//! 30 s TTL runs out and a second worker re-leases it, its URL batch leases until the 60 s TTL
//! has run out and a reaper has returned the rows. The API listener is killed by aborting its
//! task and bound again on the same port.
//! Process-level kills of `crawlx serve` / `crawlx worker` against PostgreSQL are the chaos
//! suite's (`crawlx-cli/tests/chaos.rs`).

use async_trait::async_trait;
use axum::Router;
use crawlx_api::auth::{generate_compat_key, key_record_for, tenant_id_for};
use crawlx_api::config::CompatConfig;
use crawlx_api::webhooks::{TransportError, WebhookRequest, WebhookSender, WebhookTransport};
use crawlx_api::{ApiConfig, ApiStore, AppState, Repos, Scope};
use crawlx_bench::differential::wire::driver::Target;
use crawlx_bench::differential::wire::{Hooks, Sink};
use crawlx_bench::gym::fixtures::d2;
use crawlx_bench::gym::{GymHandle, GymServer};
use crawlx_core::counters::PlaneCounters;
use crawlx_core::repo::{ArtifactStore, CrawlRun, CrawlSession, RunRepo};
use crawlx_core::{AuthorizationRecordId, Clock, CrawlRunId, SessionId, StoreError, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_policy::{testkit::sample_record, AdmissionPolicy, AuthorizationRecord};
use crawlx_storage::checkpoint_crypto::{CheckpointKeys, MemoryCheckpointKeys};
use crawlx_storage::{DeliveryBuffer, FsArtifactStore, MemoryArtifactStore, MemoryStore, Pg, PgConfig};
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{AuthorizationSource, EgressConfig, Stores, WorkerConfig, WorkerError};
use parking_lot::Mutex;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const WEBHOOK_SECRET: &str = "whsec_wire_rig";

/// A `RunRepo` that lets the worker reach the loopback gym with its stored authorization.
/// Admission in the API still runs on the unmodified request.
struct PrivateNetworks(Arc<dyn RunRepo>, AuthorizationRecordId);

#[async_trait]
impl RunRepo for PrivateNetworks {
    async fn create(&self, run: &CrawlRun, key: Option<&str>) -> Result<(), StoreError> {
        self.0.create(run, key).await
    }
    async fn create_replay(
        &self,
        run: &CrawlRun,
        sessions: &[CrawlSession],
        spec: &serde_json::Value,
    ) -> Result<(), StoreError> {
        self.0.create_replay(run, sessions, spec).await
    }
    async fn replay_spec(&self, run: CrawlRunId) -> Result<Option<serde_json::Value>, StoreError> {
        self.0.replay_spec(run).await
    }
    async fn get(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let mut run = RunRepo::get(self.0.as_ref(), id).await?;
        run.config.safety.allow_private_networks = true;
        run.config.safety.authorization_record_ref = Some(self.1);
        run.config.politeness.delay_ms = 0;
        Ok(run)
    }
    async fn get_for_execution(&self, id: CrawlRunId) -> Result<CrawlRun, StoreError> {
        let mut run = self.get(id).await?;
        run.config.fetch = self.0.get_for_execution(id).await?.config.fetch;
        Ok(run)
    }
    async fn set_status(
        &self,
        id: CrawlRunId,
        status: crawlx_core::counters::RunStatus,
        reason: Option<crawlx_core::counters::TerminalReason>,
    ) -> Result<(), StoreError> {
        self.0.set_status(id, status, reason).await
    }
    async fn update_counters(&self, id: CrawlRunId, counters: PlaneCounters) -> Result<(), StoreError> {
        self.0.update_counters(id, counters).await
    }
    async fn create_sessions(&self, sessions: &[CrawlSession]) -> Result<(), StoreError> {
        self.0.create_sessions(sessions).await
    }
    async fn list_sessions(&self, run: CrawlRunId) -> Result<Vec<CrawlSession>, StoreError> {
        self.0.list_sessions(run).await
    }
    async fn set_session_status(
        &self,
        id: SessionId,
        status: crawlx_core::repo::SessionStatus,
    ) -> Result<(), StoreError> {
        self.0.set_session_status(id, status).await
    }
    async fn set_session_browser(
        &self,
        id: SessionId,
        info: &crawlx_core::observation::BrowserBuildInfo,
    ) -> Result<(), StoreError> {
        self.0.set_session_browser(id, info).await
    }
    async fn set_trace_id(&self, run: CrawlRunId, trace_id: crawlx_core::TraceId) -> Result<(), StoreError> {
        self.0.set_trace_id(run, trace_id).await
    }
}

/// Read memory-backed authorization through the same API store that admitted the record.
struct ApiAuthorizationSource(Arc<dyn ApiStore>);

#[async_trait]
impl AuthorizationSource for ApiAuthorizationSource {
    async fn fetch(&self, id: AuthorizationRecordId) -> Result<Option<AuthorizationRecord>, WorkerError> {
        Ok(self.0.authorization_get(tenant_id_for("acme"), id).await?)
    }
}

/// Webhook transport that delivers to the runner's sink: whatever host name and port the
/// webhook URL names (admission only accepts the default ports, so the URL is
/// `http://hooks.example.test/...`), the connection goes to the sink on 127.0.0.1. The egress
/// policy already ran on the name in the sender.
struct LoopbackTransport {
    sink_port: u16,
}

#[async_trait]
impl WebhookTransport for LoopbackTransport {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        let host = req
            .url
            .host_str()
            .ok_or_else(|| TransportError::Egress("missing host".to_owned()))?
            .to_owned();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .resolve(&host, SocketAddr::from(([127, 0, 0, 1], self.sink_port)))
            .build()
            .map_err(|e| TransportError::Network(e.to_string()))?;
        let mut rb = client.post(req.url.clone()).body(req.body);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;
        Ok(resp.status().as_u16())
    }
}

/// A worker on a runtime of its own; dropping the runtime kills it without cleanup.
struct WorkerProcess {
    runtime: Option<tokio::runtime::Runtime>,
}

impl WorkerProcess {
    fn kill(&mut self) {
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

/// Where the rig keeps its runs.
#[derive(Clone)]
enum Backing {
    Memory(Arc<MemoryStore>),
    /// One throwaway schema of the test database; `admin` owns it and serves the API.
    Postgres {
        url: String,
        schema: String,
        admin: Pg,
        /// Explicit process-local custody survives worker runtime restarts, not process restarts.
        checkpoint_keys: Arc<dyn CheckpointKeys>,
    },
}

fn pg_config(schema: &str) -> PgConfig {
    PgConfig {
        schema: Some(schema.to_owned()),
        ..PgConfig::default()
    }
}

impl Backing {
    /// The stores of one worker. Over PostgreSQL the worker opens a pool of its own on the
    /// runtime it runs on, so killing the worker takes its connections with it and leaves the
    /// API's pool alone.
    async fn worker_stores(
        &self,
        dir: &Path,
        artifacts: Arc<dyn ArtifactStore>,
        api: Arc<dyn ApiStore>,
        authorization: AuthorizationRecordId,
    ) -> Stores {
        let mut stores = match self {
            Self::Memory(store) => {
                let mut stores = Stores::over_memory(store.clone(), dir).await.unwrap();
                stores.tenant = tenant_id_for("acme");
                stores.with_authorization_source(Arc::new(ApiAuthorizationSource(api)))
            }
            Self::Postgres {
                url,
                schema,
                checkpoint_keys,
                ..
            } => {
                let pg = Pg::connect(url, pg_config(schema)).await.unwrap();
                let mut stores = Stores::over_pg(pg, artifacts.clone(), tenant_id_for("acme"));
                stores.checkpoint_keys = Arc::clone(checkpoint_keys);
                stores
            }
        };
        stores.artifacts = artifacts;
        stores.runs = Arc::new(PrivateNetworks(stores.runs.clone(), authorization));
        stores
    }
}

/// The facade, a worker, a gym and a sink, wired to each other.
pub struct FacadeRig {
    /// The gym the crawls run against.
    pub gym: GymHandle,
    /// The webhook sink.
    pub sink: Arc<Sink>,
    /// The `fc-` key of tenant `acme`.
    pub key: String,
    port: u16,
    router: Router,
    backing: Backing,
    api_store: Arc<dyn ApiStore>,
    authorization: AuthorizationRecordId,
    artifacts: Arc<dyn ArtifactStore>,
    dir: tempfile::TempDir,
    api: Mutex<Option<JoinHandle<()>>>,
    worker: Mutex<WorkerProcess>,
    stop: CancellationToken,
    sender: Mutex<Option<JoinHandle<()>>>,
}

impl FacadeRig {
    /// Start everything over the in-memory store; the gym claims the origin-level files for `d2`.
    pub async fn start() -> Arc<Self> {
        Self::start_on(Backing::Memory(Arc::new(MemoryStore::new()))).await
    }

    /// [`Self::start`] over one throwaway schema of `CRAWLX_TEST_DATABASE_URL`; `None` without it.
    pub async fn start_postgres() -> Option<Arc<Self>> {
        let url = std::env::var("CRAWLX_TEST_DATABASE_URL").ok()?;
        let schema = format!("t_wire_{}", uuid::Uuid::now_v7().simple());
        let admin = Pg::connect(&url, pg_config(&schema)).await.unwrap();
        admin.migrate().await.unwrap();
        Some(
            Self::start_on(Backing::Postgres {
                url,
                schema,
                admin,
                checkpoint_keys: Arc::new(MemoryCheckpointKeys::new().unwrap()),
            })
            .await,
        )
    }

    async fn start_on(backing: Backing) -> Arc<Self> {
        let gym = GymServer::start("127.0.0.1:0".parse().unwrap()).await.unwrap();
        gym.claim_origin(d2::ID);
        let sink = Arc::new(Sink::start("127.0.0.1:0".parse().unwrap()).await.unwrap());
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let zdr = Arc::new(DeliveryBuffer::with_defaults(clock.clone()));
        let dir = tempfile::tempdir().unwrap();
        let (repos, artifacts): (Repos, Arc<dyn ArtifactStore>) = match &backing {
            Backing::Memory(store) => {
                let artifacts = Arc::new(
                    MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock))
                        .with_zdr_buffer(zdr.clone()),
                );
                let (repos, _) = Repos::memory_with_api(store.clone(), artifacts.clone());
                (repos, artifacts)
            }
            Backing::Postgres { admin, .. } => {
                let artifacts = Arc::new(
                    FsArtifactStore::open(dir.path(), Arc::new(admin.clone()), clock.clone())
                        .await
                        .unwrap()
                        .with_index(Arc::new(admin.clone()))
                        .with_zdr_buffer(zdr.clone()),
                );
                (Repos::pg(admin, artifacts.clone()), artifacts)
            }
        };
        let key = generate_compat_key();
        let rec = key_record_for(&key, tenant_id_for("acme"), Scope::all_set(), true).unwrap();
        crawlx_api::ApiStore::key_insert(repos.api.as_ref(), &rec, "acme")
            .await
            .unwrap();
        let now = clock.now();
        let mut record = sample_record(tenant_id_for("acme"), now, &[]);
        record.origins = d2::HOSTS
            .iter()
            .map(|host| format!("http://{host}:{}", gym.port))
            .collect();
        record.authorized_networks = vec!["127.0.0.0/8".parse().unwrap()];
        record.verified_at = Some(now);
        let verification = serde_json::json!({
            "kind": "fixture",
            "checkedAt": now,
            "hosts": d2::HOSTS,
        });
        repos
            .api
            .authorization_create(record.tenant, rec.key_id, &record, &verification, now)
            .await
            .unwrap();
        let authorization = record.id;
        let api_store = repos.api.clone();
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            webhook_secret: WEBHOOK_SECRET.to_owned(),
            compat: CompatConfig {
                prefixed_keys: true,
                ..CompatConfig::default()
            },
            ..ApiConfig::default()
        };
        let state = AppState::builder(repos, AdmissionPolicy::new(clock.clone()), config)
            .clock(clock.clone())
            .zdr_buffer(zdr.clone())
            .build();
        let router = crawlx_api::router(state.clone());

        let stop = CancellationToken::new();
        let sender = Arc::new(
            WebhookSender::new(
                state.repos.api.clone(),
                state.repos.runs.clone(),
                state.repos.events.clone(),
                Arc::new(LoopbackTransport { sink_port: sink.port }),
                WEBHOOK_SECRET.to_owned(),
                clock,
            )
            .with_zdr_buffer(zdr)
            .with_documents(state.clone()),
        );
        let sender_task = tokio::spawn(sender.run_forever(Duration::from_secs(1), stop.child_token()));

        // bind the API once to learn the port; every restart binds the same one
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let rig = Arc::new(Self {
            gym,
            sink,
            key,
            port,
            router,
            backing,
            api_store,
            authorization,
            artifacts,
            dir,
            api: Mutex::new(None),
            worker: Mutex::new(WorkerProcess { runtime: None }),
            stop,
            sender: Mutex::new(Some(sender_task)),
        });
        *rig.api.lock() = Some(rig.serve_on(listener));
        rig.start_worker();
        rig
    }

    fn serve_on(&self, listener: tokio::net::TcpListener) -> JoinHandle<()> {
        let app = self.router.clone();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        })
    }

    fn start_worker(&self) {
        let mut resolver = StaticResolver::new();
        for host in d2::HOSTS {
            resolver = resolver.with(host, ["127.0.0.1".parse().unwrap()]);
        }
        let wcfg = WorkerConfig {
            artifacts_dir: self.dir.path().to_path_buf(),
            egress: EgressConfig {
                resolver: Some(Arc::new(resolver)),
                extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
                extra_ports: vec![self.gym.port],
                ..EgressConfig::default()
            },
            idle_exit_after: None,
            gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            ..WorkerConfig::default()
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let token = CancellationToken::new();
        let backing = self.backing.clone();
        let artifacts = self.artifacts.clone();
        let dir = self.dir.path().to_path_buf();
        let api = self.api_store.clone();
        let authorization = self.authorization;
        runtime.spawn(async move {
            let stores = backing.worker_stores(&dir, artifacts, api, authorization).await;
            if let Err(e) = run_with(wcfg, stores, None, token).await {
                eprintln!("worker ended: {e}");
            }
        });
        self.worker.lock().runtime = Some(runtime);
    }

    /// The runner's view of the facade as a [`Target`].
    pub fn target(self: &Arc<Self>) -> Target {
        Target::new(
            "crawlx",
            "crawlx_facade",
            &format!("http://127.0.0.1:{}/compat", self.port),
            &self.key,
            &format!("http://gym.test:{}", self.gym.port),
        )
        .with_gym_ledger(&format!("http://127.0.0.1:{}/__gym/ledger", self.gym.port))
        .with_sink(self.sink.clone(), "http://hooks.example.test")
        .with_hooks(Arc::new(RestartAll(self.clone())))
    }

    /// Kill the API listener and the worker, then start both again (the API on the same port).
    async fn restart_all(&self) -> Result<(), String> {
        let api = self.api.lock().take();
        if let Some(api) = api {
            api.abort();
            let _ = api.await;
        }
        self.worker.lock().kill();
        // the aborted listener's socket is released with the task; rebind with retries
        let mut last = String::new();
        for _ in 0..50 {
            match tokio::net::TcpListener::bind(("127.0.0.1", self.port)).await {
                Ok(listener) => {
                    *self.api.lock() = Some(self.serve_on(listener));
                    self.start_worker();
                    return Ok(());
                }
                Err(e) => {
                    last = e.to_string();
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err(format!("cannot rebind the API port: {last}"))
    }

    /// Stop everything.
    pub async fn stop(&self) {
        self.stop.cancel();
        if let Some(t) = self.api.lock().take() {
            t.abort();
        }
        if let Some(t) = self.sender.lock().take() {
            t.abort();
        }
        self.worker.lock().kill();
        if let Backing::Postgres { admin, .. } = &self.backing {
            if let Err(e) = admin.clone().drop_schema().await {
                eprintln!("the rig's schema was not dropped: {e}");
            }
        }
    }
}

/// Restart of the API and the worker, the counterpart of restarting the upstream container.
struct RestartAll(Arc<FacadeRig>);

#[async_trait]
impl Hooks for RestartAll {
    async fn restart(&self) -> Result<(), String> {
        self.0.restart_all().await
    }
}
