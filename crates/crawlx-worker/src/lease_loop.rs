//! The worker process: lease sessions and URL batches, heartbeat, reap,
//! drain on SIGINT/SIGTERM.
//!
//! One [`RunContext`] is built per run the worker touches. Sessions run under the
//! [`Supervisor`]; the session leases are kept alive by [`Scheduler::keep_alive`]. The URL plane
//! of a run is processed by [`UrlPlaneRunner`]; a run finishes when its static plane and all
//! its sessions are done (the worker that observes that sets the terminal status).
//!
//! Limitation: the URL-plane counters of one run are kept per worker process and persisted
//! after every batch; run a single worker per static run when exact counters matter.

use crate::authorization::{AuthorizationGuard, AuthorizationStop};
use crate::config::WorkerConfig;
use crate::driver::DriverConfig;
use crate::error::WorkerError;
use crate::run::{
    build_fetcher, crawl_mode_name, merge_reasons, observe_round_wait, observe_session_end, run_session,
    status_for, RunContext, SessionEnd,
};
use crate::stores::Stores;
use crate::supervisor::Supervisor;
use crate::url_plane::{UrlPlaneDeps, UrlPlaneRunner};
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{RunStatus, TerminalReason};
use crawlx_core::repo::{CrawlRun, FrontierStatus, SessionStatus};
use crawlx_core::{BrowserBackend, CrawlRunId, SystemClock};
use crawlx_fetch::{EgressOptions, EgressProxyHandle};
use crawlx_scheduler::{Reaper, ReaperConfig, Scheduler, HEARTBEAT_INTERVAL};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::spans;
use crawlx_telemetry::Metrics;
use futures::stream::{FuturesUnordered, StreamExt as _};
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

/// How long the loop sleeps when no work is claimable.
const IDLE_POLL: Duration = Duration::from_millis(250);

/// Run the worker until SIGINT/SIGTERM (or until idle, when `idle_exit_after` is set).
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub async fn run(cfg: WorkerConfig) -> Result<(), WorkerError> {
    let stores = Stores::open(&cfg).await?;
    let cancel = CancellationToken::new();
    // the watcher lives in a `JoinSet`: dropping it at the end of `run` aborts the task
    let mut signals = tokio::task::JoinSet::new();
    install_signal_handler(&mut signals, cancel.clone());
    let result = run_with(cfg, stores, None, cancel.clone()).await;
    cancel.cancel();
    result
}

/// Spawn the SIGINT/SIGTERM watcher into `set`; it only flips `cancel`.
fn install_signal_handler(set: &mut tokio::task::JoinSet<()>, cancel: CancellationToken) {
    set.spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let term = signal(SignalKind::terminate());
            match term {
                Ok(mut term) => {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {}
                        _ = term.recv() => {}
                    }
                }
                Err(_) => {
                    let _ = tokio::signal::ctrl_c().await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        tracing::info!("shutdown signal received; draining sessions");
        cancel.cancel();
    });
}

/// One bounded URL-plane completion receipt shared with the run's leased role sessions.
type HybridStarts = Option<Result<Arc<Vec<crawlx_core::request::RequestEnvelopeV1>>, TerminalReason>>;

/// Per-run state of this worker.
struct RunSlot {
    rc: Arc<RunContext>,
    crawl_row: CrawlRun,
    /// Replay metadata is loaded before any URL-plane or exploration work.
    replay: Option<serde_json::Value>,
    proxy: Option<EgressProxyHandle>,
    plane: Option<Arc<UrlPlaneRunner>>,
    plane_task:
        Option<crate::supervisor::SupervisedTask<Result<crate::url_plane::UrlPlaneOutcome, WorkerError>>>,
    url_terminal: Option<TerminalReason>,
    hybrid_starts: tokio::sync::watch::Sender<HybridStarts>,
    session_reasons: Vec<TerminalReason>,
    /// The run's authorization guard; `None` for a run that references no record.
    authorization: Option<Arc<AuthorizationGuard>>,
    /// The run was ended because its authorization was lost; set once.
    halted: bool,
    /// The `crawl` span; every session of the run is instrumented under it.
    span: tracing::Span,
}

/// Wait without acquiring a browser; `run_session` retains the existing lease heartbeat.
async fn hybrid_start_requests(
    mut receipt: tokio::sync::watch::Receiver<HybridStarts>,
) -> Result<Vec<crawlx_core::request::RequestEnvelopeV1>, WorkerError> {
    loop {
        let ready = receipt.borrow_and_update().clone();
        if let Some(result) = ready {
            return result
                .map(|requests| requests.as_ref().clone())
                .map_err(|reason| {
                    WorkerError::Other(format!("hybrid URL plane ended: {}", reason.as_str()))
                });
        }
        receipt
            .changed()
            .await
            .map_err(|_| WorkerError::Other("hybrid URL plane handoff closed".into()))?;
    }
}

/// Observe worker-local capabilities without contacting a target or opening an attached browser.
fn acquisition_manifest<'a>(
    cfg: &'a WorkerConfig,
    backend: Option<&'a Arc<dyn BrowserBackend>>,
    cancel: &'a CancellationToken,
) -> impl Future<Output = Result<Vec<crawlx_core::acquisition::BackendCapabilitiesV1>, WorkerError>> + Send + 'a
{
    Box::pin(acquisition_manifest_inner(cfg, backend, cancel))
}

async fn acquisition_manifest_inner(
    cfg: &WorkerConfig,
    backend: Option<&Arc<dyn BrowserBackend>>,
    cancel: &CancellationToken,
) -> Result<Vec<crawlx_core::acquisition::BackendCapabilitiesV1>, WorkerError> {
    use crawlx_core::acquisition::BackendCapabilitiesV1;
    let http = BackendCapabilitiesV1::native_http("crawlx-fetch/native", env!("CARGO_PKG_VERSION"));
    let mut probe_launch = cfg.launch.clone();
    if let Some(settings) = crate::netns::NamespaceSettings::from_env(&|name| std::env::var(name).ok())
        .map_err(|error| WorkerError::Config(error.to_string()))?
    {
        settings
            .prepare(&mut probe_launch)
            .await
            .map_err(|error| WorkerError::Config(error.to_string()))?;
    }
    let browser = if cfg.renderer.is_some() {
        BackendCapabilitiesV1::native_browser_unavailable("operator_renderer_capability_unattested")
    } else if let Some(backend) = backend {
        let mut capability =
            BackendCapabilitiesV1::native_browser_unavailable("operator_backend_capability_unattested");
        capability.implementation = "operator_browser_backend".to_owned();
        capability.browser = Some(backend.build_info().clone());
        capability
    } else if cfg.launch.cdp_ws_url.is_some() {
        BackendCapabilitiesV1::native_browser_unavailable("attached_browser_requires_run_admission")
    } else if probe_launch.namespace.is_some() {
        match crate::netns::probe_namespaced_build(&probe_launch, cancel).await {
            Ok(build) => {
                let mut capability = BackendCapabilitiesV1::native_browser(build);
                capability.limitations.push("startup_probe_build_only".to_owned());
                capability.limitations.push("namespace_isolated_probe".to_owned());
                capability
            }
            Err(reason) => BackendCapabilitiesV1::native_browser_unavailable(reason.reason()),
        }
    } else {
        let mut launch = cfg.launch.clone();
        launch.user_data_dir = None;
        launch.profile = None;
        launch.profiles_dir = None;
        launch.egress_proxy_port = None;
        launch.auto_download_chromium = false;
        let launch_profile = launch.launch_profile;
        let observed = tokio::select! {
            biased;
            () = cancel.cancelled() => None,
            result = tokio::time::timeout(Duration::from_secs(30), crawlx_browser::ChromiumBackend::launch(launch)) => result.ok().and_then(Result::ok),
        };
        match observed {
            Some(browser) => {
                let build = browser.build_info().clone();
                let device_matrix = probe_device_matrix(&browser, launch_profile, &build).await;
                match tokio::time::timeout(Duration::from_secs(10), browser.shutdown_confirmed()).await {
                    Ok(Ok(())) => {
                        let mut capability = BackendCapabilitiesV1::native_browser(build);
                        capability.limitations.push("startup_probe_build_only".to_owned());
                        if device_matrix.is_none() {
                            capability.limitations.push("device_matrix_unmeasured".to_owned());
                        }
                        capability.device_matrix = device_matrix;
                        capability
                    }
                    _ => BackendCapabilitiesV1::native_browser_unavailable("probe_shutdown_unconfirmed"),
                }
            }
            None => BackendCapabilitiesV1::native_browser_unavailable("browser_startup_probe_failed"),
        }
    };
    let registry = match &cfg.protocol_registry {
        Some(registry) => Some(Arc::clone(registry)),
        None => crate::protocol::ProtocolRegistry::from_operator_env().await?,
    };
    let mut capabilities = vec![http, browser];
    if let Some(service) = registry
        .as_deref()
        .map(crate::protocol::ProtocolRegistry::acquisition_capability)
        .transpose()?
        .flatten()
    {
        capabilities.push(service);
    }
    Ok(capabilities)
}

/// Measure the emulated-device matrix on the startup probe's own browser, in a throwaway
/// context. `None` when the browser does not answer within the bound: the worker then reports
/// no matrix rather than a partial one.
async fn probe_device_matrix(
    browser: &crawlx_browser::ChromiumBackend,
    launch_profile: crawlx_core::LaunchProfile,
    build: &crawlx_core::observation::BrowserBuildInfo,
) -> Option<crawlx_core::page_op::DeviceMatrixV1> {
    use crawlx_core::browser::BrowserContext as _;
    let mut config = crawlx_core::ContextConfig::new(crawlx_core::SessionId::new());
    config.launch_profile = launch_profile;
    let measure = async {
        let context = browser.new_cdp_context(config).await.ok()?;
        let matrix = context
            .measure_device_matrix(&build.chromium_version, build.pinned)
            .await
            .ok();
        // A context that cannot close is still reaped with the probe browser.
        let _ = Box::new(context).close().await;
        matrix
    };
    tokio::time::timeout(Duration::from_secs(15), measure)
        .await
        .ok()
        .flatten()
}

/// [`run`] over explicit stores, backend and cancellation (tests).
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
#[must_use = "the run does not execute unless the future is polled"]
pub fn run_with(
    cfg: WorkerConfig,
    stores: Stores,
    backend: Option<Arc<dyn BrowserBackend>>,
    cancel: CancellationToken,
) -> impl Future<Output = Result<(), WorkerError>> + Send {
    Box::pin(run_with_inner(cfg, stores, backend, cancel))
}

#[allow(clippy::too_many_lines)]
async fn run_with_inner(
    cfg: WorkerConfig,
    stores: Stores,
    backend: Option<Arc<dyn BrowserBackend>>,
    cancel: CancellationToken,
) -> Result<(), WorkerError> {
    let scheduler = Scheduler::new(Arc::clone(&stores.leases));
    let reaper = Arc::new(Reaper::new(
        Arc::clone(&stores.leases),
        Arc::clone(&stores.journal),
        ReaperConfig::default(),
    ))
    .spawn(cancel.child_token());
    // flip leases left by a dead holder before the first claim
    if let Err(e) = Reaper::new(
        Arc::clone(&stores.leases),
        Arc::clone(&stores.journal),
        ReaperConfig::default(),
    )
    .run_once()
    .await
    {
        tracing::warn!(error = %e, "initial reap failed");
    }

    // Reuse the existing registry in the database or its shared in-memory counterpart.
    // Re-registration clears prior process/build claims before fresh facts are published.
    let durable_registry = stores
        .durable
        .as_ref()
        .map(crate::durable::DurableStore::worker_registry);
    let registry: Option<&dyn crawlx_storage::WorkerRegistry> = match (&durable_registry, &stores.memory) {
        (Some(registry), _) => Some(registry.as_ref()),
        (None, Some(memory)) => Some(memory.as_ref()),
        (None, None) => None,
    };
    if let Some(registry) = registry {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_owned());
        registry
            .register_worker(cfg.worker_id, &hostname, env!("CARGO_PKG_VERSION"))
            .await?;
        let manifest = acquisition_manifest(&cfg, backend.as_ref(), &cancel).await?;
        registry
            .publish_acquisition_capabilities(cfg.worker_id, &manifest)
            .await?;
        registry
            .publish_data_capabilities(cfg.worker_id, &cfg.data_capabilities()?)
            .await?;
    }
    // A bounded independent task keeps durable outbox recovery alive after runs terminate.
    // It shares cancellation and is aborted on scope exit through JoinSet.
    let mut delivery_tasks = tokio::task::JoinSet::new();
    let delivery_cfg = cfg.clone();
    let delivery_stores = stores.clone();
    let delivery_cancel = cancel.clone();
    delivery_tasks.spawn(async move {
        let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
        let mut delivery_governors = BTreeMap::new();
        let mut delivery_after = None;
        loop {
            tokio::select! {
                () = delivery_cancel.cancelled() => break,
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            if let Err(error) = crate::delivery::recover_once(
                &delivery_stores,
                &delivery_cfg,
                &clock,
                &delivery_cancel,
                &mut delivery_governors,
                &mut delivery_after,
            )
            .await
            {
                tracing::warn!(%error, "delivery recovery deferred");
            }
        }
    });

    let supervisor = Supervisor::new();
    let mut slots: BTreeMap<CrawlRunId, RunSlot> = BTreeMap::new();
    let mut running = FuturesUnordered::new();
    let mut idle_since: Option<Instant> = None;
    let mut last_worker_heartbeat = Instant::now();
    // a lease refused while sessions of some runs are still running means a role of
    // one of those runs may be waiting for its turn; the wait ends when a session of such a
    // run is granted
    let mut active_sessions: BTreeMap<CrawlRunId, usize> = BTreeMap::new();
    let mut waiting_since: Option<(std::time::Instant, Vec<CrawlRunId>)> = None;

    loop {
        // 0. worker heartbeat; an operator drain cancels exactly like SIGTERM: no new leases,
        //    every session hands over at its next action boundary
        if let Some(registry) = registry {
            if last_worker_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
                last_worker_heartbeat = Instant::now();
                match registry.worker_heartbeat(cfg.worker_id).await {
                    Ok(true) if !cancel.is_cancelled() => {
                        tracing::info!(worker = %cfg.worker_id, "drain requested by operator; draining sessions");
                        cancel.cancel();
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "worker heartbeat failed"),
                }
            }
        }
        let draining = cancel.is_cancelled();
        let mut did_work = false;
        if !draining {
            let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
            for export in stores.archives.recoverable(clock.now(), 2).await? {
                let row = stores.runs.get(export.run).await?;
                match crate::archive_recorder::finalize(
                    &stores,
                    &row,
                    Arc::clone(&clock),
                    &cancel,
                    export.terminal_reason,
                )
                .await?
                {
                    crate::archive_recorder::Finalization::Busy => {}
                    outcome => {
                        let reason = if outcome == crate::archive_recorder::Finalization::Failed {
                            TerminalReason::FatalError
                        } else {
                            export.terminal_reason
                        };
                        stores
                            .finish_run(row.id, reason, &cfg.cpu_pool, cfg.worker_id)
                            .await?;
                        did_work = true;
                    }
                }
            }
        }

        // 1. sessions (and the coordinator slot of static runs)
        while !draining && running.len() < cfg.max_sessions.max(1) {
            let Some(lease) = scheduler.lease_next(cfg.worker_id).await? else {
                // a wait whose runs all finished without granting a session was not a round wait
                if waiting_since
                    .as_ref()
                    .is_some_and(|(_, runs)| runs.iter().all(|r| !active_sessions.contains_key(r)))
                {
                    waiting_since = None;
                }
                if waiting_since.is_none() && !active_sessions.is_empty() {
                    waiting_since = Some((
                        std::time::Instant::now(),
                        active_sessions.keys().copied().collect(),
                    ));
                }
                break;
            };
            if waiting_since
                .as_ref()
                .is_some_and(|(_, runs)| runs.contains(&lease.session.run))
            {
                if let Some((since, _)) = waiting_since.take() {
                    observe_round_wait(since, &lease.session.role.0);
                }
            }
            did_work = true;
            let run_id = lease.session.run;
            let admission = match slot_for(&mut slots, &cfg, &stores, &backend, &cancel, run_id, &lease).await
            {
                Ok(slot) => slot,
                Err(WorkerError::AcquisitionUnavailable(reason)) => {
                    // This worker narrowed its live manifest. Another capable worker may recover the run.
                    match scheduler.release(&lease, SessionStatus::Recovering).await {
                        Ok(()) => {}
                        Err(error) if error.is_lease_lost() => {}
                        Err(error) => return Err(error.into()),
                    }
                    tracing::warn!(run=%run_id,reason,"acquisition unavailable; session returned for recovery");
                    continue;
                }
                Err(WorkerError::Config(_)) => {
                    // Refuse this run without taking unrelated sessions down with it.
                    match scheduler.fail(&lease).await {
                        Ok(()) => {}
                        Err(error) if error.is_lease_lost() => {}
                        Err(error) => return Err(error.into()),
                    }
                    stores
                        .finish_run(run_id, TerminalReason::FatalError, &cfg.cpu_pool, cfg.worker_id)
                        .await?;
                    tracing::warn!(run = %run_id, "run configuration refused");
                    continue;
                }
                Err(error) if admission_lease_lost(&error) => {
                    // The run was cancelled or the session was fenced between leasing and
                    // admission. Its new owner decides the run's fate; this worker only lost
                    // one lease and keeps serving its other runs.
                    tracing::warn!(run = %run_id, session = %lease.session.id, "session lease lost during run admission");
                    continue;
                }
                Err(error) => return Err(error),
            };
            let Some(slot) = admission else {
                // the run's authorization was refused and the run ended with it: so does this lease
                let _ = scheduler.fail(&lease).await;
                continue;
            };
            // no session starts under a record that is revoked or expired
            if let Some(guard) = slot.authorization.clone() {
                if guard.check_now().await.is_err() {
                    halt_unauthorized(&stores, slot).await;
                    let _ = scheduler.fail(&lease).await;
                    continue;
                }
            }
            let rc = Arc::clone(&slot.rc);
            let mode = slot.crawl_row.config.mode;
            let task = if let Some(spec) = slot.replay.clone() {
                supervisor.spawn_for(
                    "replay",
                    Some(lease.session.id),
                    crate::replay_queue::run_session(rc, scheduler.clone(), lease.clone(), spec)
                        .instrument(slot.span.clone()),
                )
            } else {
                match (mode, slot.plane.clone()) {
                    (CrawlMode::Static, Some(plane)) => supervisor.spawn_for(
                        "static-coordinator",
                        Some(lease.session.id),
                        static_coordinator(
                            plane,
                            scheduler.clone(),
                            lease.clone(),
                            rc.stores.session_producer(rc.run, &lease),
                            rc.cancel.clone(),
                            rc.stores.secret_authority.clone(),
                        )
                        .instrument(slot.span.clone()),
                    ),
                    _ => {
                        if mode == CrawlMode::Hybrid
                            && slot.plane_task.is_none()
                            && slot.url_terminal.is_none()
                        {
                            if let Some(plane) = slot.plane.clone() {
                                let token = rc.cancel.clone();
                                slot.plane_task = Some(supervisor.spawn(
                                    "url-plane",
                                    async move { plane.run(&token).await }.instrument(slot.span.clone()),
                                ));
                            }
                        }
                        let starts = (mode == CrawlMode::Hybrid).then(|| slot.hybrid_starts.subscribe());
                        supervisor.spawn_for(
                            "session",
                            Some(lease.session.id),
                            run_session(
                                rc,
                                scheduler.clone(),
                                lease.clone(),
                                async move {
                                    match starts {
                                        Some(receipt) => hybrid_start_requests(receipt).await,
                                        None => Ok(Vec::new()),
                                    }
                                },
                                DriverConfig::default(),
                                None,
                            )
                            .instrument(slot.span.clone()),
                        )
                    }
                }
            };
            *active_sessions.entry(run_id).or_default() += 1;
            running.push(async move { (run_id, lease, task.await) });
        }

        // 2. completed hybrid URL planes
        for slot in slots.values_mut() {
            let finished = slot
                .plane_task
                .as_ref()
                .is_some_and(tokio::task::JoinHandle::is_finished);
            if finished {
                if let Some(task) = slot.plane_task.take() {
                    let (terminal, requests) = match task.await {
                        Ok(Ok(Ok(outcome))) => (outcome.terminal, Some(outcome.dynamic_requests)),
                        Ok(Ok(Err(e))) => {
                            tracing::error!(error = %e, "url plane failed");
                            (TerminalReason::FatalError, None)
                        }
                        Ok(Err(failure)) => {
                            tracing::error!(message = %failure.message, "url plane panicked");
                            (TerminalReason::FatalError, None)
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "url plane task aborted");
                            (TerminalReason::FatalError, None)
                        }
                    };
                    let _ = slot
                        .hybrid_starts
                        .send_replace(Some(requests.map(Arc::new).ok_or(terminal)));
                    slot.url_terminal = Some(terminal);
                    did_work = true;
                }
            }
        }

        // 3. session completions
        if running.is_empty() {
            if draining {
                break;
            }
        } else {
            let next = tokio::time::timeout(IDLE_POLL, running.next()).await;
            if let Ok(Some((run_id, lease, joined))) = next {
                did_work = true;
                if let Entry::Occupied(mut e) = active_sessions.entry(run_id) {
                    *e.get_mut() -= 1;
                    if *e.get() == 0 {
                        e.remove();
                    }
                }
                let reason = match joined {
                    Ok(Ok(end)) => end.terminal,
                    Ok(Err(failure)) => {
                        tracing::error!(session = %lease.session.id, message = %failure.message, "session panicked");
                        let _ = scheduler.fail(&lease).await;
                        TerminalReason::FatalError
                    }
                    Err(e) => {
                        tracing::error!(session = %lease.session.id, error = %e, "session task aborted");
                        let _ = scheduler.fail(&lease).await;
                        TerminalReason::FatalError
                    }
                };
                if let Some(slot) = slots.get_mut(&run_id) {
                    if slot.replay.is_none() && slot.crawl_row.config.mode == CrawlMode::Static {
                        // the coordinator slot is the URL plane, not a role session
                        slot.url_terminal = Some(reason);
                    } else {
                        observe_session_end(reason);
                    }
                    slot.session_reasons.push(reason);
                }
            }
        }

        // 3b. a record that was revoked or has expired ends its run, whichever
        //     session or plane is in flight (the guard re-reads the record at most once per
        //     recheck interval, so this is the lease loop's heartbeat check)
        if !draining {
            for slot in slots.values_mut() {
                let Some(guard) = slot.authorization.clone() else {
                    continue;
                };
                if !slot.halted && guard.check_now().await.is_err() {
                    halt_unauthorized(&stores, slot).await;
                    did_work = true;
                }
            }
        }

        // 4. finalize finished runs
        if !draining {
            let ids: Vec<CrawlRunId> = slots.keys().copied().collect();
            for id in ids {
                // Revocation marks the run terminal immediately to stop new leases.
                // Keep its proxy and shared services alive until owned tasks drain.
                if active_sessions.contains_key(&id)
                    || slots.get(&id).is_some_and(|slot| slot.plane_task.is_some())
                {
                    continue;
                }
                if finalize_if_done(&stores, &mut slots, id).await? {
                    did_work = true;
                    if let Some(slot) = slots.remove(&id) {
                        Metrics::global().gauge(names::CRAWLS_ACTIVE).add(-1.0, &[]);
                        slot.rc.finish_traffic().await;
                        if let Some(p) = slot.proxy {
                            p.shutdown().await;
                        }
                    }
                }
            }
        }

        if draining && running.is_empty() {
            break;
        }
        if did_work || !running.is_empty() {
            idle_since = None;
        } else {
            let since = *idle_since.get_or_insert_with(Instant::now);
            if let Some(limit) = cfg.idle_exit_after {
                if since.elapsed() >= limit {
                    break;
                }
            }
            tokio::select! {
                () = tokio::time::sleep(IDLE_POLL) => {}
                () = cancel.cancelled() => {}
            }
        }
    }

    cancel.cancel();
    let _ = reaper.await;
    supervisor.shutdown().await;
    for (_, slot) in slots {
        slot.rc.finish_traffic().await;
        if let Some(p) = slot.proxy {
            p.shutdown().await;
        }
    }
    Ok(())
}

/// Did admission fail only because this worker's session lease was fenced or cancelled?
///
/// That outcome concerns one lease of one run, never the worker process.
fn admission_lease_lost(error: &WorkerError) -> bool {
    matches!(
        error,
        WorkerError::Store(crawlx_core::StoreError::LeaseLost)
            | WorkerError::Scheduler(crawlx_scheduler::SchedulerError::Store(
                crawlx_core::StoreError::LeaseLost
            ))
    )
}

/// Build the slot of `run_id`, or `None` when the run's authorization record is missing,
/// unreadable, revoked, expired or not yet valid: the run is then ended as `failed` with
/// `authorization_revoked` and an `authorization.revoked` event, and no session of it is served.
async fn slot_for<'a>(
    slots: &'a mut BTreeMap<CrawlRunId, RunSlot>,
    cfg: &WorkerConfig,
    stores: &Stores,
    backend: &Option<Arc<dyn BrowserBackend>>,
    cancel: &CancellationToken,
    run_id: CrawlRunId,
    lease: &crawlx_storage::SessionLease,
) -> Result<Option<&'a mut RunSlot>, WorkerError> {
    match slots.entry(run_id) {
        Entry::Occupied(o) => Ok(Some(o.into_mut())),
        Entry::Vacant(v) => {
            let mut row = stores.runs.get_for_execution(run_id).await?;
            let replay = stores.runs.replay_spec(run_id).await?;
            // a scrape run is a static run whose pages the scrape engine produces: its only
            // session slot is the URL-plane coordinator and it never explores in a browser
            if row.config.scrape.is_some() {
                row.config.mode = CrawlMode::Static;
            }
            if row.status == RunStatus::Queued {
                // a lost race with another worker is fine: either way the run is `running`
                let _ = stores.runs.set_status(run_id, RunStatus::Running, None).await;
            }
            // a request above `shadow` needs gates/g3.passed on this worker
            cfg.check_gates(&row.config)?;
            // the stored record bounds the run; one that is missing, unreadable,
            // revoked or expired refuses it
            let authorization = match authorize(stores, cfg, &row).await {
                Ok(guard) => guard,
                Err(WorkerError::Authorization(stop)) => {
                    refuse_run(stores, run_id, &stop, &cfg.cpu_pool, cfg.worker_id).await;
                    return Ok(None);
                }
                Err(e) => return Err(e),
            };
            // the token the run's plane and sessions honour: the worker's own (drain, SIGTERM)
            // or a lost authorization
            let run_cancel = cancel.child_token();
            if let Some(guard) = &authorization {
                guard.cancels(run_cancel.clone());
            }
            let record = authorization.as_ref().map(|guard| guard.record());
            let dynamic =
                replay.is_some() || (row.config.mode != CrawlMode::Static && row.config.dynamic.enabled);
            let resolver = cfg.egress.resolver_for(&row.config)?;
            let proxy = if dynamic || crate::scrape::needs_browser_renderer(&row.config, cfg) {
                Some(
                    cfg.egress
                        .serve_proxy(
                            &row.config,
                            run_id,
                            record,
                            resolver,
                            EgressOptions::new().with_global_cap(Arc::clone(&cfg.origin_cap)),
                        )
                        .await?,
                )
            } else {
                None
            };
            let context = RunContext::build(
                &row,
                cfg,
                stores.clone(),
                backend.clone(),
                None,
                run_cancel,
                proxy.as_ref(),
                authorization.clone(),
            )
            .await;
            let rc = match context {
                Ok(context) => Arc::new(context),
                Err(error) => {
                    if let Some(proxy) = proxy {
                        proxy.shutdown().await;
                    }
                    return Err(error);
                }
            };
            // Everything below can fail on a lease that was fenced or cancelled after it was
            // leased; the egress proxy must not outlive such an admission.
            let admitted = async {
                crate::acquisition::admit_runtime(&rc, cfg, backend.is_some(), false).await?;
                if replay.is_some() || row.config.mode == CrawlMode::Dynamic {
                    return Ok(None);
                }
                let (fetcher, _) = build_fetcher(
                    &row.config,
                    run_id,
                    row.seed,
                    cfg,
                    rc.controls.clone(),
                    record,
                    Arc::clone(&rc.origin_governor),
                )?;
                let fetcher = rc.capture_fetcher(fetcher)?;
                // Facade scrapes use their stateless run fetcher, not a strict named HTTP client.
                let http_session = if row.config.mode == CrawlMode::Static && row.config.scrape.is_none() {
                    Some(crate::session_lifecycle::register_http_session(&rc, lease, &fetcher).await?)
                } else {
                    None
                };
                let mut plane = UrlPlaneRunner::new(
                    run_id,
                    row.config.clone(),
                    cfg.worker_id,
                    UrlPlaneDeps {
                        runs: Arc::clone(&stores.runs),
                        frontier: Arc::clone(&stores.frontier),
                        request_commits: Arc::clone(&stores.request_commits),
                        source_memo: Arc::clone(&stores.source_memo),
                        leases: Arc::clone(&stores.leases),
                        pages: Arc::clone(&stores.pages),
                        events: Arc::clone(&stores.events),
                        artifacts: Arc::clone(&stores.artifacts),
                        archives: Arc::clone(&stores.archives),
                        clock: Arc::clone(&rc.clock),
                    },
                    fetcher,
                    rc.counters.clone(),
                    rc.canon.clone(),
                )?
                .with_cpu_pool(rc.cpu_pool.clone())
                .with_route_learner(rc.routes.clone())
                .with_surface_services(&rc)
                .with_scrape_services(&rc, cfg)
                .with_authorization(authorization.clone())
                .with_graceful_drain(cancel.clone(), None);
                if let Some(http_session) = http_session {
                    plane = plane.with_http_sessions(http_session.manager, http_session.authority);
                }
                let plane = Arc::new(plane);
                plane.seed_if_empty().await?;
                Ok::<_, WorkerError>(Some(plane))
            }
            .await;
            let plane = match admitted {
                Ok(plane) => plane,
                Err(error) => {
                    if let Some(proxy) = proxy {
                        proxy.shutdown().await;
                    }
                    return Err(error);
                }
            };
            let span = spans::crawl_span(
                &run_id,
                crawl_mode_name(row.config.mode),
                row.config.safety.profile.as_str(),
            );
            if let Some(t) = crawlx_telemetry::trace_id::trace_id_of(&span) {
                stores.runs.set_trace_id(run_id, t).await?;
            }
            Metrics::global().gauge(names::CRAWLS_ACTIVE).add(1.0, &[]);
            Ok(Some(v.insert(RunSlot {
                rc,
                crawl_row: row,
                replay,
                proxy,
                plane,
                plane_task: None,
                url_terminal: None,
                hybrid_starts: tokio::sync::watch::channel(None).0,
                session_reasons: Vec::new(),
                span,
                authorization,
                halted: false,
            })))
        }
    }
}

/// The authorization guard of a run the worker is about to serve: the stored record named by
/// `safety.authorizationRecordRef`, read through the stores' [`AuthorizationSource`].
/// Only a run that references no record may run without an authorization source.
/// Memory-backed admissions retain the live source and original body binding for uncached HEAD
/// disclosure after the worker releases the run; a global API authorizer still takes precedence.
///
/// [`AuthorizationSource`]: crate::authorization::AuthorizationSource
async fn authorize(
    stores: &Stores,
    cfg: &WorkerConfig,
    row: &CrawlRun,
) -> Result<Option<Arc<AuthorizationGuard>>, WorkerError> {
    let Some(record) = row.config.safety.authorization_record_ref else {
        crate::run::check_role_credentials(&row.config, None)?;
        return Ok(None);
    };
    let source = stores
        .authorization
        .as_ref()
        .ok_or_else(|| WorkerError::Authorization(AuthorizationStop::Missing(record)))?;
    let guard = AuthorizationGuard::admit(
        row.id,
        None,
        Some(record),
        Arc::clone(source),
        Arc::new(SystemClock),
        Arc::clone(&stores.events),
        cfg.authorization_recheck,
    )
    .await?;
    guard.check_tenant(row.tenant)?;
    crate::run::check_role_credentials(&row.config, Some(&guard))?;
    if let Some(memory) = &stores.memory {
        memory.set_run_head_response_authorizer(row.id, guard.head_response_authorizer()?);
    }
    Ok(Some(guard))
}

/// End a run the worker refused to serve because its authorization was lost at lease time: failed
/// with `authorization_revoked`. Its sessions are never leased again (leases need a running run).
async fn refuse_run(
    stores: &Stores,
    run: CrawlRunId,
    stop: &AuthorizationStop,
    cpu: &crate::runtime::CpuPool,
    worker: crawlx_core::WorkerId,
) {
    tracing::warn!(run = %run, reason = stop.reason(), "run refused: authorization record unusable");
    end_unauthorized(stores, run, stop.reason(), None, cpu, worker).await;
}

/// End a running run whose authorization was lost: the guard has cancelled its token, here the
/// run row follows (`failed`, `authorization_revoked`), which also stops the leasing of its other
/// sessions.
async fn halt_unauthorized(stores: &Stores, slot: &mut RunSlot) {
    if slot.halted {
        return;
    }
    slot.halted = true;
    let reason = slot.authorization.as_ref().and_then(|guard| guard.stop());
    let code = reason.as_ref().map_or("revoked", AuthorizationStop::reason);
    end_unauthorized(
        stores,
        slot.rc.run,
        code,
        Some(&slot.rc),
        &slot.rc.cpu_pool,
        slot.rc.worker,
    )
    .await;
}

async fn end_unauthorized(
    stores: &Stores,
    run: CrawlRunId,
    code: &str,
    rc: Option<&Arc<RunContext>>,
    cpu: &crate::runtime::CpuPool,
    worker: crawlx_core::WorkerId,
) {
    let reason = TerminalReason::AuthorizationRevoked;
    if let Some(rc) = rc {
        if let Err(e) = rc.counters.persist(stores.runs.as_ref(), run).await {
            tracing::warn!(run = %run, error = %e, "counters not persisted");
        }
    }
    match stores.finish_run(run, reason, cpu, worker).await {
        Ok(()) => {
            let _ = stores
                .events
                .append(
                    run,
                    "completed",
                    serde_json::json!({
                        "status": status_for(reason).as_str(),
                        "terminalReason": reason.as_str(),
                        "authorization": code,
                    }),
                )
                .await;
        }
        // an operator cancelled or finished the run in the same instant
        Err(crawlx_core::StoreError::IllegalTransition { .. }) => {}
        Err(e) => tracing::warn!(run = %run, error = %e, "run not ended after losing its authorization"),
    }
}

/// A static run's only session slot is its coordinator: it holds the lease while this worker
/// runs the URL plane, so the lease, heartbeat and reaper machinery covers the static plane too.
async fn static_coordinator(
    plane: Arc<UrlPlaneRunner>,
    scheduler: Scheduler,
    lease: crawlx_storage::SessionLease,
    producer: crawlx_core::custody::CustodyLease,
    cancel: CancellationToken,
    authority: Option<Arc<crate::durable::DurableAuthority>>,
) -> SessionEnd {
    let keepalive_cancel = CancellationToken::new();
    let keepalive = scheduler.keep_alive(lease.clone(), HEARTBEAT_INTERVAL, keepalive_cancel.clone());
    // Discovery and any write outside a leased URL row publish under the coordinator's
    // session fence; each leased row narrows this to its own frontier lease.
    let result = crawlx_core::custody::with_producer(
        producer.clone(),
        crate::custody_renewal::with_custody_renewal(authority, producer, Box::pin(plane.run(&cancel))),
    )
    .await;
    keepalive_cancel.cancel();
    let _ = keepalive.await;
    let (end, release) = match result {
        Ok(outcome) => {
            // a lost authorization ends the session for good; a drain hands it over
            let release = if cancel.is_cancelled() && outcome.terminal != TerminalReason::AuthorizationRevoked
            {
                SessionStatus::Recovering
            } else {
                SessionStatus::Completed
            };
            (
                SessionEnd {
                    terminal: outcome.terminal,
                    error: None,
                },
                release,
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "url plane failed");
            (
                SessionEnd {
                    terminal: TerminalReason::FatalError,
                    error: Some(e.to_string()),
                },
                SessionStatus::Failed,
            )
        }
    };
    if let Err(e) = scheduler.release(&lease, release).await {
        tracing::warn!(error = %e, "coordinator lease not released cleanly");
    }
    end
}

/// A run is done when its static plane has ended (or it has none) and every session is terminal.
async fn finalize_if_done(
    stores: &Stores,
    slots: &mut BTreeMap<CrawlRunId, RunSlot>,
    id: CrawlRunId,
) -> Result<bool, WorkerError> {
    let Some(slot) = slots.get_mut(&id) else {
        return Ok(false);
    };
    let row = stores.runs.get(id).await?;
    if row.status.is_terminal() {
        stores.artifacts.erase_run_credentials(id).await?;
        return Ok(true);
    }
    let mode = slot.crawl_row.config.mode;
    let static_done = slot.replay.is_some() || mode == CrawlMode::Dynamic || slot.url_terminal.is_some();
    if !static_done || slot.plane_task.is_some() {
        return Ok(false);
    }
    let sessions = stores.runs.list_sessions(id).await?;
    if sessions.iter().any(|s| !s.status.is_terminal()) {
        return Ok(false);
    }
    if mode != CrawlMode::Static {
        let leased = stores
            .frontier
            .list(id)
            .await?
            .iter()
            .any(|f| f.status == FrontierStatus::Leased);
        if leased {
            return Ok(false);
        }
    }
    let mut reasons = slot.session_reasons.clone();
    reasons.extend(slot.url_terminal);
    if slot
        .authorization
        .as_ref()
        .is_some_and(|guard| guard.is_stopped())
    {
        reasons.push(TerminalReason::AuthorizationRevoked);
    }
    let mut reason = merge_reasons(&reasons);
    slot.rc.counters.persist(stores.runs.as_ref(), id).await?;
    if slot.rc.crawl.extract.xhr {
        slot.rc.xhr.apply(stores.pages.as_ref(), id).await?;
    }
    if !slot.rc.cancel.is_cancelled() {
        match crate::archive_recorder::finalize(
            stores,
            &row,
            Arc::clone(&slot.rc.clock),
            &slot.rc.cancel,
            reason,
        )
        .await?
        {
            crate::archive_recorder::Finalization::Busy => return Ok(false),
            crate::archive_recorder::Finalization::Failed => reason = TerminalReason::FatalError,
            crate::archive_recorder::Finalization::Ready => {}
        }
    }
    stores
        .finish_run(id, reason, &slot.rc.cpu_pool, slot.rc.worker)
        .await?;
    let _ = stores
        .events
        .append(
            id,
            "completed",
            serde_json::json!({ "status": status_for(reason).as_str(), "terminalReason": reason.as_str(), "counters": slot.rc.counters.snapshot() }),
        )
        .await;
    Ok(true)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::StoreError;
    use crawlx_scheduler::SchedulerError;

    #[test]
    fn only_a_lost_session_lease_is_survivable_at_admission() {
        assert!(admission_lease_lost(&WorkerError::Store(StoreError::LeaseLost)));
        assert!(admission_lease_lost(&WorkerError::Scheduler(
            SchedulerError::Store(StoreError::LeaseLost)
        )));
        assert!(!admission_lease_lost(&WorkerError::Store(StoreError::Backend(
            "down".into()
        ))));
        assert!(!admission_lease_lost(&WorkerError::Config("bad".into())));
    }

    /// The startup probe measures the device matrix on its own browser and publishes it with
    /// the browser capability, so the capabilities endpoint can count the worker as measured.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_startup_probe_publishes_a_coherent_device_matrix_for_the_browser_backend() {
        let Some(executable) = crawlx_browser::launch::find_executable() else {
            eprintln!("SKIP: no Chromium executable found (set CRAWLX_CHROMIUM_PATH)");
            return;
        };
        let mut cfg = WorkerConfig::default();
        cfg.launch.executable = executable;
        cfg.launch.allow_unpinned = true;
        cfg.protocol_registry = Some(Arc::new(crate::protocol::ProtocolRegistry::default()));
        let mut manifest = acquisition_manifest(&cfg, None, &CancellationToken::new())
            .await
            .unwrap();
        if !manifest
            .iter()
            .any(|backend| backend.backend_id == "native_browser" && backend.available)
        {
            eprintln!("warning: probe launch failed; retrying once with --no-sandbox (CI containers only)");
            cfg.launch.unsafe_no_sandbox_for_ci = true;
            manifest = acquisition_manifest(&cfg, None, &CancellationToken::new())
                .await
                .unwrap();
        }
        let browser = manifest
            .iter()
            .find(|backend| backend.backend_id == "native_browser")
            .unwrap();
        assert!(browser.available, "{:?}", browser.limitations);
        let matrix = browser
            .device_matrix
            .as_ref()
            .expect("the probe measured a matrix");
        assert!(matrix.coherent(), "{matrix:#?}");
        assert_eq!(
            matrix.entries.len(),
            crawlx_core::page_op::DevicePreset::ALL.len()
        );
        assert_eq!(
            matrix.build.chromium_version,
            browser.browser.as_ref().unwrap().chromium_version
        );
        assert!(!matrix.stealth_claim);
        assert!(!browser
            .limitations
            .iter()
            .any(|l| l == "device_matrix_unmeasured"));
        // what the registry accepts and the capabilities endpoint counts
        browser.validate_evidence().unwrap();
    }
}
