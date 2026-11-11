//! crawlx-api: Axum REST/SSE API, auth, idempotency, webhooks, compat facade. The API never touches a browser: it persists runs in
//! `queued` status for the worker lease loop and serves everything the worker journals.
//!
//! * [`router`] builds the `axum::Router` over an [`AppState`];
//! * [`run`] wires repositories from an [`ApiConfig`] (PostgreSQL when `database_url` is
//!   set, in-memory otherwise), bootstraps development API keys, starts the webhook sender
//!   and serves.
//!
//! Error envelope, scopes, rate limits, SSE connection caps and idempotency follow
//! the public API contract (a reused `Idempotency-Key` with a different body answers
//! `422 idempotency_key_reuse`; more than 50 streams per tenant or 5 per run answer
//! `429 too_many_streams`).
//!
//! Every request is counted in `crawlx.api.requests{route,outcome}` by templated route;
//! `GET /metrics` (scope `metrics:read`) renders the Prometheus exposition, and
//! [`ApiConfig::metrics_bind`] optionally adds an unauthenticated loopback-only listener for
//! a scraper sidecar ([`metrics`]).
//!
//! Authorization records: `POST /v1/authorizations` stores an immutable record
//! after its ownership proof verified ([`ownership`]), `GET`, `…/revoke` and `…/verify` read and
//! change its lifecycle ([`routes::authorizations`]), every run created under a record is bound
//! to the record's body digest, and [`admission_policy`] makes admission refuse a record whose
//! ownership was never verified, is revoked or expired.

pub mod auth;
pub mod config;
pub mod errors;
pub mod idempotency;
pub mod intel;
pub mod memory;
pub mod metrics;
pub mod openapi;
pub(crate) mod openapi_schemas;
pub mod ownership;
pub mod pg;
pub mod resources;
pub mod routes;
pub mod scrape_service;
pub mod state;
pub mod store;
pub(crate) mod streams;
pub mod util;
pub mod webhooks;

pub use config::{ApiConfig, ApiKeyBootstrap, CompatConfig, CompatMode, Settings};
pub use errors::{ApiError, Detail, HttpError};
pub use memory::MemoryApiStore;
pub use pg::{PgApiStore, PgEraser};
pub use routes::router;
pub use state::{AppState, AppStateBuilder, DeploymentBuild, Repos};
pub use store::{ApiStore, ArtifactSource, Eraser, Scope};
pub use webhooks::{ReqwestTransport, WebhookSender, WebhookTransport};

use crawlx_core::{Clock, SystemClock};
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::{FsArtifactStore, MemoryStore, Pg, PgConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// The admission policy of the API: authorization windows on `clock`, a referenced record must
/// have a verified ownership proof ([`AdmissionPolicy::require_verified_ownership`]; the API
/// stores only records created through the verifying route), and the deployment lists of
/// [`ApiConfig::egress_lists`] bound private-network records and refuse blocklisted hosts.
/// Authenticated milestone evidence from `CRAWLX_GATES_DIR` (default `./gates`)
/// controls model authority; missing or invalid evidence closes the gate.
#[must_use]
pub fn admission_policy(cfg: &ApiConfig, clock: Arc<dyn Clock>) -> AdmissionPolicy {
    let policy = AdmissionPolicy::new(clock)
        .with_gates(crawlx_worker::Gates::load_default().status())
        .require_verified_ownership();
    match &cfg.egress_lists {
        Some(lists) => policy.with_egress_lists(lists.clone()),
        None => policy,
    }
}

/// Create the configured bootstrap API keys (all scopes). `fc-` keys are accepted only when
/// [`CompatConfig::prefixed_keys`] is on.
async fn bootstrap_keys(api: &dyn ApiStore, cfg: &ApiConfig) -> Result<(), ApiError> {
    for b in &cfg.api_keys {
        let tenant = auth::tenant_id_for(&b.tenant);
        let record = auth::key_record_for(&b.key, tenant, Scope::all_set(), cfg.compat.prefixed_keys)
            .ok_or_else(|| {
                ApiError::Config(format!(
                    "API key for tenant {:?} must look like {}<{} base32 characters>{}",
                    b.tenant,
                    auth::KEY_PREFIX,
                    auth::SECRET_LEN,
                    if cfg.compat.prefixed_keys {
                        format!(" or {}<16..=64 alphanumerics>", auth::COMPAT_KEY_PREFIX)
                    } else {
                        String::new()
                    }
                ))
            })?;
        api.key_insert(&record, &b.tenant).await?;
    }
    Ok(())
}

/// Serve the API until `Ctrl-C`.
///
/// # Errors
/// Configuration, storage and socket failures.
pub async fn run(cfg: ApiConfig) -> Result<(), ApiError> {
    let shutdown = CancellationToken::new();
    let on_signal = shutdown.clone();
    let watcher = tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %e, "ctrl-c handler failed; shutting down");
        }
        on_signal.cancel();
    });
    let served = run_until(cfg, shutdown).await;
    watcher.abort();
    served
}

/// Serve the API until `shutdown` is cancelled, then drain: open event streams end, the
/// HTTP server finishes in-flight requests and the webhook sender completes its current tick.
///
/// # Errors
/// Configuration, storage and socket failures.
pub async fn run_until(cfg: ApiConfig, shutdown: CancellationToken) -> Result<(), ApiError> {
    run_until_bound(cfg, shutdown, None).await
}

/// [`run_until`] that reports the address the server bound to through `bound`, so a caller
/// that binds port 0 learns the port without a bind-then-release race.
///
/// # Errors
/// As [`run_until`].
pub async fn run_until_bound(
    mut cfg: ApiConfig,
    shutdown: CancellationToken,
    bound: Option<tokio::sync::oneshot::Sender<std::net::SocketAddr>>,
) -> Result<(), ApiError> {
    if cfg.api_database_url.is_none() {
        cfg.api_database_url = std::env::var("CRAWLX_API_DATABASE_URL")
            .ok()
            .filter(|url| !url.trim().is_empty());
    }
    if cfg.api_database_url.is_none() {
        if let Some(path) = std::env::var_os("CRAWLX_API_DATABASE_URL_FILE").filter(|path| !path.is_empty()) {
            let path = std::path::PathBuf::from(path);
            let value = tokio::fs::read_to_string(&path)
                .await
                .map_err(|source| ApiError::SecretFile { path, source })?;
            let value = value.trim();
            if value.is_empty() {
                return Err(ApiError::Config("api database secret file is empty".to_owned()));
            }
            cfg.api_database_url = Some(value.to_owned());
        }
    }
    if cfg.allow_owner_api
        && std::env::var("CRAWLX_ENVIRONMENT")
            .ok()
            .is_some_and(|environment| !matches!(environment.as_str(), "dev" | "ci"))
    {
        return Err(ApiError::Config(
            "allow_owner_api is forbidden outside dev/ci".to_owned(),
        ));
    }
    if cfg.database_url.is_some() && cfg.api_database_url.is_none() && !cfg.allow_owner_api {
        return Err(ApiError::Config(
            "postgresql API requires CRAWLX_API_DATABASE_URL with a restricted non-owner role; \
             allow_owner_api is for local development only"
                .to_owned(),
        ));
    }
    cfg.intel = cfg
        .intel
        .clone()
        .from_env()
        .map_err(|e| ApiError::Config(format!("intel: {e}")))?;
    cfg.compat = cfg
        .compat
        .from_lookup(|k| std::env::var(k).ok())
        .map_err(|e| ApiError::Config(format!("compat: {e}")))?;
    if cfg.request_identity_key.is_none() {
        for name in ["CRAWLX_REQUEST_IDENTITY_KEY", "CRAWLX_REQUEST_IDENTITY_KEY_FILE"] {
            if std::env::var_os(name).is_some_and(|value| value.to_str().is_none()) {
                return Err(ApiError::Config(format!("{name} must be valid Unicode")));
            }
        }
        cfg.request_identity_key =
            crawlx_core::secret::request_identity_key_from_lookup(&|name| std::env::var(name).ok())?;
    }
    if cfg.operator_keys.is_empty() {
        if let Some(path) = std::env::var_os(config::OPERATOR_KEYS_FILE_ENV).filter(|p| !p.is_empty()) {
            cfg.operator_keys = config::load_operator_keys(std::path::Path::new(&path)).await?;
        }
    }
    let backends = intel::backends(&cfg.intel)?;
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    // API and workers share only the ephemeral `zdr/` namespace, never normal artifacts.
    let zdr = Arc::new(match cfg.database_url {
        Some(_) => {
            crawlx_storage::DeliveryBuffer::open_runtime(
                clock.clone(),
                crawlx_storage::BufferLimits::default(),
            )
            .await?
        }
        None => crawlx_storage::DeliveryBuffer::with_defaults(clock.clone()),
    });
    let spool = Arc::new(crawlx_storage::UploadSpool::new(cfg.artifact_spool.clone())?);
    let repos = match &cfg.database_url {
        Some(url) => {
            let pg = Pg::connect(url, PgConfig::default()).await?;
            pg.migrate().await?;
            let pg = match &cfg.api_database_url {
                Some(api_url) => pg.with_api_role(api_url).await?,
                None => pg,
            };
            let pg = pg.with_delivery_buffer(zdr.clone());
            // The API never publishes sealed artifacts; it decrypts them through the catalog. Without
            // a key provider, sealed artifacts fail with a clear error and legacy ones stay readable.
            let (custody, keys) =
                crawlx_worker::config::read_only_custody_from_lookup(&pg, &|name| std::env::var(name).ok())
                    .await
                    .map_err(|error| ApiError::Config(error.to_string()))?;
            let artifacts = FsArtifactStore::open(&cfg.artifacts_dir, Arc::new(pg.clone()), clock.clone())
                .await?
                .with_index(Arc::new(pg.clone()))
                .with_zdr_buffer(zdr.clone())
                .with_upload_spool(spool.clone())
                .with_custody(custody, keys, crawlx_storage::CustodyWrites::ReadOnly);
            Repos::pg(&pg, Arc::new(artifacts))
        }
        None => {
            let store = Arc::new(MemoryStore::new());
            let artifacts = FsArtifactStore::open(&cfg.artifacts_dir, store.clone(), clock.clone())
                .await?
                .with_zdr_buffer(zdr.clone())
                .with_upload_spool(spool.clone());
            Repos::memory_with(store, Arc::new(artifacts))
        }
    };
    bootstrap_keys(repos.api.as_ref(), &cfg).await?;
    let mut builder = AppState::builder(repos, admission_policy(&cfg, clock.clone()), cfg.clone())
        .clock(clock.clone())
        .shutdown(shutdown.clone())
        .zdr_buffer(zdr.clone());
    if let Some(llm) = backends.llm {
        builder = builder.llm(llm);
    }
    if let Some(router) = backends.extraction {
        builder = builder.extraction_router(router);
    }
    if let Some(ranker) = backends.embeddings {
        builder = builder.page_ranker(ranker);
    }
    if let Some(search) = backends.search {
        builder = builder.search_provider(search);
    }
    // the probe runs `tesseract --version` (or loads models): blocking work, off the reactor
    let ocr_config = cfg.ocr.clone();
    let ocr = tokio::task::spawn_blocking(move || crawlx_extract::parse::ocr::Ocr::shared(&ocr_config))
        .await
        .map_err(|e| ApiError::Config(format!("ocr: {e}")))?
        .map_err(|e| ApiError::Config(format!("ocr: {e}")))?;
    if let Some(ocr) = ocr {
        tracing::info!(backend = ocr.backend().name(), "OCR enabled for /parse");
        builder = builder.ocr(ocr);
    }
    let state = builder.build();
    let jobs = state.jobs.clone();
    let sender = Arc::new(
        WebhookSender::new(
            state.repos.api.clone(),
            state.repos.runs.clone(),
            state.repos.events.clone(),
            Arc::new(ReqwestTransport),
            cfg.webhook_secret.clone(),
            clock,
        )
        .with_zdr_buffer(zdr)
        .with_dual_signing(cfg.compat.mode.dual_signs_native_webhooks())
        .with_documents(state.clone()),
    );
    let metrics_stop = shutdown.child_token();
    let metrics_listener = match cfg.metrics_bind {
        Some(bind) => {
            let listener = metrics::bind_metrics(bind).await?;
            tracing::info!(metrics_bind = %bind, "unauthenticated loopback metrics listener enabled");
            Some(tokio::spawn(metrics::serve_metrics_on(
                listener,
                metrics_stop.clone(),
            )))
        }
        None => None,
    };
    let webhooks_stop = shutdown.child_token();
    let webhooks = tokio::spawn(sender.run_forever(Duration::from_secs(1), webhooks_stop.clone()));
    let monitors = intel::monitor::spawn_monitor_loop(state.clone());
    let served = serve(&cfg, state, &shutdown, bound).await;
    // extract/agent/monitor jobs observe `shutdown` through their own tokens; let them settle
    shutdown.cancel();
    if tokio::time::timeout(Duration::from_secs(10), jobs.drain())
        .await
        .is_err()
    {
        tracing::warn!("background jobs did not finish within 10 s of shutdown");
    }
    webhooks_stop.cancel();
    metrics_stop.cancel();
    if let Err(e) = webhooks.await {
        tracing::warn!(error = %e, "webhook sender task ended abnormally");
    }
    if let Err(e) = monitors.await {
        tracing::warn!(error = %e, "monitor loop ended abnormally");
    }
    if let Some(task) = metrics_listener {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!(error = %e, "metrics listener failed"),
            Err(e) => tracing::warn!(error = %e, "metrics listener task ended abnormally"),
        }
    }
    served
}

/// Bind and serve until `shutdown` is cancelled; `bound` receives the bound address.
async fn serve(
    cfg: &ApiConfig,
    state: AppState,
    shutdown: &CancellationToken,
    bound: Option<tokio::sync::oneshot::Sender<std::net::SocketAddr>>,
) -> Result<(), ApiError> {
    let listener = tokio::net::TcpListener::bind(cfg.bind)
        .await
        .map_err(|e| ApiError::Bind(cfg.bind, e))?;
    let addr = listener.local_addr().map_err(|e| ApiError::Bind(cfg.bind, e))?;
    tracing::info!(bind = %addr, "crawlx-api listening");
    if let Some(tx) = bound {
        // the receiver may have gone away; the server does not care
        let _ = tx.send(addr);
    }
    let stop = shutdown.clone();
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move { stop.cancelled().await })
        .await
        .map_err(ApiError::Serve)
}
