//! `BrowserPool`: Chromium processes start lazily, each hosts at most
//! `contexts_per_browser` incognito contexts (one per session), and processes are bounded by
//! a semaphore. Under `authorized_security_test` every session gets its own process.

use async_trait::async_trait;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::ProfileSpec;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::{BrowserBackend, BrowserContext, BrowserError, ContextConfig, LaunchProfile};
use parking_lot::Mutex;
use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[path = "pool_extensions.rs"]
mod hooks;

use crawlx_core::extensions::{ExtensionEventV1, ExtensionTerminalV1};
use hooks::BrowserAttempt;
pub use hooks::{PoolExtensions, BROWSER_EVENT_KIND};

/// Pool sizing.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PoolConfig {
    /// Chromium processes per worker (planning default: cores / 2).
    pub max_browsers: usize,
    /// Contexts per process (planning default 4).
    pub contexts_per_browser: usize,
}

impl PoolConfig {
    #[must_use]
    /// With contexts.
    pub fn with_contexts(contexts_per_browser: usize) -> Self {
        let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
        Self {
            max_browsers: (cores / 2).max(1),
            contexts_per_browser: contexts_per_browser.max(1),
        }
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self::with_contexts(4)
    }
}

/// Finite process retirement bounds. Retirement drains live actors before owned shutdown.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct PoolRetirement {
    /// Maximum context creations admitted to one process, including failed creations.
    pub max_contexts: u64,
    /// Maximum process lifetime before it stops accepting contexts.
    pub max_age: std::time::Duration,
    /// Maximum idle time after the last context closes.
    pub max_idle: std::time::Duration,
}

impl Default for PoolRetirement {
    fn default() -> Self {
        Self {
            max_contexts: 1_000,
            max_age: std::time::Duration::from_secs(3_600),
            max_idle: std::time::Duration::from_secs(300),
        }
    }
}

/// Launch settings are process-wide, so processes are keyed by them. A named persistent
/// profile (`dynamic.browserProfile`) is one: its user-data directory belongs to one browser.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Key {
    profile: LaunchProfile,
    egress_port: Option<u16>,
    persistent: Option<ProfileSpec>,
}

struct Slot {
    id: u64,
    key: Key,
    /// A process dedicated to one session; retired when its context is released.
    exclusive: bool,
    backend: Arc<dyn BrowserBackend>,
    contexts: Arc<Semaphore>,
    /// Unconfirmed resource cleanup remains charged against bounded pool capacity.
    quarantined: Vec<OwnedSemaphorePermit>,
    draining: bool,
    capacity: usize,
    admitted: u64,
    started_at: tokio::time::Instant,
    last_used_at: tokio::time::Instant,
}

type Picked = (u64, Arc<dyn BrowserBackend>, Arc<Semaphore>, bool);

/// Source of backends.
#[async_trait]
trait Launcher: Send + Sync {
    async fn launch(&self, key: &Key) -> Result<Arc<dyn BrowserBackend>, BrowserError>;
    /// Does the pool own the processes it launches (and so may shut them down)?
    fn owns_backends(&self) -> bool;
}

struct ChromiumLauncher {
    base: LaunchConfig,
}

#[async_trait]
impl Launcher for ChromiumLauncher {
    async fn launch(&self, key: &Key) -> Result<Arc<dyn BrowserBackend>, BrowserError> {
        let mut cfg = self.base.clone();
        cfg.launch_profile = key.profile;
        cfg.egress_proxy_port = key.egress_port;
        cfg.profile.clone_from(&key.persistent);
        Ok(Arc::new(ChromiumBackend::launch(cfg).await?))
    }

    fn owns_backends(&self) -> bool {
        self.base.cdp_ws_url.is_none()
    }
}

struct FixedLauncher {
    backend: Arc<dyn BrowserBackend>,
}

#[async_trait]
impl Launcher for FixedLauncher {
    async fn launch(&self, _key: &Key) -> Result<Arc<dyn BrowserBackend>, BrowserError> {
        Ok(Arc::clone(&self.backend))
    }

    fn owns_backends(&self) -> bool {
        false
    }
}

struct Inner {
    launcher: Box<dyn Launcher>,
    cfg: PoolConfig,
    retirement: PoolRetirement,
    slots: Mutex<Vec<Slot>>,
    active_sessions: Mutex<std::collections::BTreeMap<crawlx_core::SessionId, u64>>,
    next_id: Mutex<u64>,
    /// Serializes process launches so a burst of sessions starts one browser, not N.
    launch_lock: tokio::sync::Mutex<()>,
    /// In-flight or failed launches whose resource death has not been proved.
    unconfirmed_launches: std::sync::atomic::AtomicUsize,
    launches: Mutex<usize>,
    /// Owned retirement tasks are bounded by process capacity and retain their join handles.
    cleanup: Mutex<tokio::task::JoinSet<()>>,
}

/// Decorates every context the pool hands out (proxy capture); applied after
/// `new_context`, also on recovery and replay acquisitions.
pub type ContextWrapper =
    Arc<dyn Fn(crawlx_core::SessionId, Box<dyn BrowserContext>) -> Box<dyn BrowserContext> + Send + Sync>;

/// Lazily launched, bounded pool of browser contexts.
#[derive(Clone)]
pub struct BrowserPool {
    inner: Arc<Inner>,
    wrap: Option<ContextWrapper>,
    /// Typed lifecycle hooks of the run this handle belongs to; never shared across clones of
    /// other runs, so the process table stays hook-free.
    ext: Option<PoolExtensions>,
}

/// A leased context. Explicit confirmed cleanup returns capacity; dropping quarantines it.
pub struct PooledContext {
    /// Ctx.
    pub ctx: Box<dyn BrowserContext>,
    /// Build.
    pub build: BrowserBuildInfo,
    lease: Lease,
}

impl PooledContext {
    /// Split into the context and the lease that keeps its slot reserved.
    #[must_use]
    pub fn into_parts(self) -> (Box<dyn BrowserContext>, BrowserBuildInfo, Lease) {
        (self.ctx, self.build, self.lease)
    }

    pub(crate) fn with_session_proxy(mut self, proxy: crawlx_fetch::EgressProxyHandle) -> Self {
        self.lease.proxy = Some(proxy);
        self
    }
}

/// Keeps one context slot reserved.
pub struct Lease {
    pool: Arc<Inner>,
    slot: u64,
    session: crawlx_core::SessionId,
    exclusive: bool,
    permit: Option<OwnedSemaphorePermit>,
    proxy: Option<crawlx_fetch::EgressProxyHandle>,
    attempt: Option<BrowserAttempt>,
}

impl Lease {
    /// Release only after context closure. An owned exclusive process must also be reaped.
    /// An attached/injected backend is never killed on behalf of one context.
    ///
    /// # Errors
    /// Returns cleanup/lease/profile generation errors without releasing uncertain capacity.
    pub async fn release(mut self, context_closed: bool) -> Result<(), crate::error::SessionError> {
        let mut attempt = self.attempt.take();
        if context_closed {
            if let Some(attempt) = attempt.as_mut() {
                // Only a confirmed closure is reported. A refusal cannot undo it and stays
                // sticky in the terminal outcome. The hook has no pool reference.
                attempt.observe(ExtensionEventV1::BrowserPageClose);
            }
        }
        let result = self.release_resources(context_closed).await;
        if let Some(mut attempt) = attempt {
            match &result {
                Ok(owned_process_closed) => {
                    if *owned_process_closed {
                        attempt.observe(ExtensionEventV1::BrowserClose);
                    }
                    attempt.finish(ExtensionTerminalV1::Completed).await;
                }
                Err(_) => {
                    let outcome = attempt.failure_outcome();
                    attempt.finish(outcome).await;
                }
            }
        }
        result.map(|_| ())
    }

    /// Returns whether a process this pool owns was shut down with confirmed death.
    async fn release_resources(&mut self, context_closed: bool) -> Result<bool, crate::error::SessionError> {
        let backend = {
            let mut slots = self.pool.slots.lock();
            let Some(slot) = slots.iter_mut().find(|slot| slot.id == self.slot) else {
                return Ok(false);
            };
            let final_context = slot.contexts.available_permits().saturating_add(1) == slot.capacity;
            if self.pool.launcher.owns_backends() && (self.exclusive || (slot.draining && final_context)) {
                slot.draining = true;
                Some(Arc::clone(&slot.backend))
            } else {
                None
            }
        };
        let mut process_closed = false;
        if let Some(backend) = backend {
            // No timeout around this future: cancellation must not drop an owned Child and
            // pretend resource death. The backend itself has bounded graceful/kill waits.
            backend.shutdown_confirmed().await?;
            process_closed = true;
            self.pool.slots.lock().retain(|slot| slot.id != self.slot);
            self.permit.take();
            self.pool
                .active_sessions
                .lock()
                .retain(|_, slot| *slot != self.slot);
        } else if context_closed {
            if self.exclusive {
                self.pool.slots.lock().retain(|slot| slot.id != self.slot);
            }
            if let Some(slot) = self
                .pool
                .slots
                .lock()
                .iter_mut()
                .find(|slot| slot.id == self.slot)
            {
                slot.last_used_at = tokio::time::Instant::now();
            }
            self.permit.take();
            self.pool.active_sessions.lock().remove(&self.session);
        } else {
            return Err(crate::error::SessionError::Other(
                "session_unavailable: browser resource quarantined".into(),
            ));
        }
        if let Some(proxy) = self.proxy.take() {
            proxy.shutdown().await;
        }
        // Failed cleanup reaches Drop and keeps its permit in bounded quarantine.
        Ok(process_closed)
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let backend = {
                let mut slots = self.pool.slots.lock();
                if let Some(slot) = slots.iter_mut().find(|slot| slot.id == self.slot) {
                    slot.quarantined.push(permit);
                    if self.exclusive {
                        slot.draining = true;
                    }
                    if self.exclusive && self.pool.launcher.owns_backends() {
                        Some(Arc::clone(&slot.backend))
                    } else {
                        None
                    }
                } else {
                    // A slot is removed only after confirmed resource death.
                    drop(permit);
                    None
                }
            };
            if let Some(backend) = backend {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    let mut cleanup = self.pool.cleanup.lock();
                    while cleanup.try_join_next().is_some() {}
                    if cleanup.len() < self.pool.cfg.max_browsers.max(1) {
                        let pool = Arc::clone(&self.pool);
                        let id = self.slot;
                        cleanup.spawn_on(
                            async move {
                                if backend.shutdown_confirmed().await.is_ok() {
                                    pool.slots.lock().retain(|slot| slot.id != id);
                                    pool.active_sessions.lock().retain(|_, slot| *slot != id);
                                }
                            },
                            &runtime,
                        );
                    }
                }
            }
        }
    }
}

impl BrowserPool {
    /// Pool that launches Chromium from `launch` on demand.
    #[must_use]
    pub fn new(launch: LaunchConfig, cfg: PoolConfig) -> Self {
        Self::build(Box::new(ChromiumLauncher { base: launch }), cfg)
    }

    /// Pool over an injected backend (tests): one shared "process", `contexts_per_browser` bounded.
    #[must_use]
    pub fn with_backend(backend: Arc<dyn BrowserBackend>) -> Self {
        Self::with_backend_config(backend, PoolConfig::default())
    }

    /// [`Self::with_backend`] with explicit sizing.
    #[must_use]
    pub fn with_backend_config(backend: Arc<dyn BrowserBackend>, cfg: PoolConfig) -> Self {
        Self::build(Box::new(FixedLauncher { backend }), cfg)
    }

    fn build(launcher: Box<dyn Launcher>, cfg: PoolConfig) -> Self {
        let cfg = PoolConfig {
            max_browsers: cfg.max_browsers.max(1),
            contexts_per_browser: cfg.contexts_per_browser.max(1),
        };
        Self {
            inner: Arc::new(Inner {
                launcher,
                cfg,
                retirement: PoolRetirement::default(),
                slots: Mutex::new(Vec::new()),
                active_sessions: Mutex::new(std::collections::BTreeMap::new()),
                next_id: Mutex::new(0),
                launch_lock: tokio::sync::Mutex::new(()),
                unconfirmed_launches: std::sync::atomic::AtomicUsize::new(0),
                launches: Mutex::new(0),
                cleanup: Mutex::new(tokio::task::JoinSet::new()),
            }),
            wrap: None,
            ext: None,
        }
    }

    /// Narrow finite process retirement bounds before sharing or acquiring from this pool.
    ///
    /// # Errors
    /// Rejects zero bounds or a pool already cloned or used.
    #[must_use = "the retirement policy is applied to the returned pool"]
    pub fn with_retirement(mut self, retirement: PoolRetirement) -> Result<Self, BrowserError> {
        if retirement.max_contexts == 0 || retirement.max_age.is_zero() || retirement.max_idle.is_zero() {
            return Err(BrowserError::Unsupported(
                "invalid browser retirement bounds".into(),
            ));
        }
        let inner = Arc::get_mut(&mut self.inner)
            .filter(|inner| inner.slots.lock().is_empty())
            .ok_or_else(|| BrowserError::Unsupported("browser retirement policy already in use".into()))?;
        inner.retirement = retirement;
        Ok(self)
    }

    /// Decorate every context this pool (and its clones) hands out from now on.
    #[must_use]
    pub fn with_context_wrapper(mut self, wrap: ContextWrapper) -> Self {
        self.wrap = Some(wrap);
        self
    }

    /// Bind this run's typed lifecycle hooks to a handle of the pool. The process table is
    /// shared with the original; only acquisitions through the returned handle run hooks.
    #[must_use]
    pub fn with_extensions(mut self, ext: PoolExtensions) -> Self {
        self.ext = Some(ext);
        self
    }

    /// Processes launched so far.
    #[must_use]
    pub fn launches(&self) -> usize {
        *self.inner.launches.lock()
    }

    /// Live processes.
    #[must_use]
    pub fn browsers(&self) -> usize {
        self.inner.slots.lock().len()
    }

    /// Context resources with unconfirmed death, still charged against hard pool capacity.
    #[must_use]
    pub fn quarantined_contexts(&self) -> usize {
        self.inner
            .slots
            .lock()
            .iter()
            .map(|slot| slot.quarantined.len())
            .sum::<usize>()
            .saturating_add(
                self.inner
                    .unconfirmed_launches
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
    }

    /// Slots whose prior resource closure has been confirmed. Dropping a lease alone
    /// never returns capacity; unconfirmed resources stay in bounded quarantine.
    #[must_use]
    pub fn available_contexts(&self) -> usize {
        self.inner
            .slots
            .lock()
            .iter()
            .filter(|slot| !slot.draining)
            .map(|s| s.contexts.available_permits())
            .sum()
    }

    /// Safe free admission budget, including bounded processes not yet launched.
    /// In-flight/failed launches and quarantines remain charged, never reported as free.
    #[must_use]
    pub fn admission_available_contexts(&self) -> usize {
        let slots = self.inner.slots.lock();
        let free = slots
            .iter()
            .filter(|slot| !slot.draining)
            .map(|slot| slot.contexts.available_permits())
            .sum::<usize>();
        let charged = slots.len().saturating_add(
            self.inner
                .unconfirmed_launches
                .load(std::sync::atomic::Ordering::Relaxed),
        );
        let unlaunched = if !self.inner.launcher.owns_backends() && slots.iter().any(|slot| slot.draining) {
            0
        } else {
            self.inner.cfg.max_browsers.saturating_sub(charged)
        };
        free.saturating_add(unlaunched.saturating_mul(self.inner.cfg.contexts_per_browser.max(1)))
    }

    /// Context slots across live processes, free or leased (`1` for an exclusive process,
    /// `contexts_per_browser` otherwise).
    #[must_use]
    pub fn context_capacity(&self) -> usize {
        let slots = self.inner.slots.lock();
        slots
            .iter()
            .map(|s| {
                if s.exclusive {
                    1
                } else {
                    self.inner.cfg.contexts_per_browser
                }
            })
            .sum()
    }

    /// Open one incognito context. `exclusive` gives the session its own process.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    #[must_use = "the context is not acquired unless the future is polled"]
    pub fn acquire(
        &self,
        config: ContextConfig,
        exclusive: bool,
    ) -> impl Future<Output = Result<PooledContext, BrowserError>> + Send + '_ {
        // Callers can try several binding/profile generations. Keep each acquisition's
        // construction temporary out of their poll frames, even for unused branches.
        Box::pin(self.acquire_inner(config, exclusive))
    }

    async fn acquire_inner(
        &self,
        config: ContextConfig,
        exclusive: bool,
    ) -> Result<PooledContext, BrowserError> {
        let mut attempt = match &self.ext {
            Some(ext) => ext.attempt(&config)?,
            None => None,
        };
        let result = self.acquire_attempt(config, exclusive, &mut attempt).await;
        let Some(mut attempt) = attempt else {
            return result;
        };
        match result {
            Ok(mut pooled) => {
                attempt.flush().await;
                pooled.lease.attempt = Some(attempt);
                Ok(pooled)
            }
            Err(error) => {
                let outcome = attempt.failure_outcome();
                attempt.finish(outcome).await;
                Err(error)
            }
        }
    }

    async fn acquire_attempt(
        &self,
        config: ContextConfig,
        exclusive: bool,
        attempt: &mut Option<BrowserAttempt>,
    ) -> Result<PooledContext, BrowserError> {
        if self.inner.active_sessions.lock().contains_key(&config.session_id) {
            return Err(BrowserError::Unsupported(
                "session_unavailable: binding already has an actor".into(),
            ));
        }
        if !config.incognito && !self.inner.launcher.owns_backends() {
            return Err(BrowserError::Unsupported(
                "session_unavailable: attached default jar has no principal binding".into(),
            ));
        }
        let exclusive = exclusive || !config.incognito || config.browser_profile.is_some();
        let key = Key {
            profile: config.launch_profile,
            egress_port: config.egress_proxy_port,
            persistent: config.browser_profile.clone(),
        };
        let (slot_id, backend, permit, is_exclusive) = self.reserve_context(&key, exclusive, attempt).await?;
        {
            let mut sessions = self.inner.active_sessions.lock();
            if sessions.contains_key(&config.session_id) {
                if is_exclusive {
                    if let Some(slot) = self.inner.slots.lock().iter_mut().find(|slot| slot.id == slot_id) {
                        slot.draining = true;
                    }
                }
                return Err(BrowserError::Unsupported(
                    "session_unavailable: binding actor collision".into(),
                ));
            }
            sessions.insert(config.session_id, slot_id);
        }
        let lease = Lease {
            pool: Arc::clone(&self.inner),
            slot: slot_id,
            session: config.session_id,
            exclusive: is_exclusive,
            permit: Some(permit),
            proxy: None,
            attempt: None,
        };
        if let Some(attempt) = attempt.as_mut() {
            if let Err(error) = attempt.dispatch(ExtensionEventV1::BrowserPageCreate) {
                // No page was requested, so the reserved capacity is provably unused.
                if let Err(cleanup) = lease.release(true).await {
                    tracing::warn!(error = %cleanup, "refused context creation left quarantined capacity");
                }
                return Err(error);
            }
        }
        let created = match tokio::time::timeout(
            std::time::Duration::from_secs(30),
            backend.new_context(config.clone()),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(BrowserError::Timeout(30_000)),
        };
        match created {
            Ok(ctx) => {
                let ctx = match &self.wrap {
                    Some(w) => w(config.session_id, ctx),
                    None => ctx,
                };
                Ok(PooledContext {
                    ctx,
                    build: backend.build_info().clone(),
                    lease,
                })
            }
            Err(error) => {
                // A failed create can have allocated a page before its reply was lost.
                // Only exclusive owned shutdown can prove that allocation is gone.
                if let Err(cleanup) = lease.release(false).await {
                    tracing::warn!(error = %cleanup, "failed context creation left quarantined capacity");
                }
                Err(error)
            }
        }
    }

    /// Shut down, gracefully and one after the other, the browsers this pool launched for a
    /// named persistent profile, so what they wrote reaches the profile directory
    /// ([`BrowserBackend::shutdown`]). Other browsers, and backends the pool was handed, are
    /// left alone. Call it once the run's sessions are done.
    pub async fn shutdown_persistent(&self) {
        if !self.inner.launcher.owns_backends() {
            return;
        }
        let retired: Vec<(u64, Arc<dyn BrowserBackend>)> = {
            let mut slots = self.inner.slots.lock();
            slots
                .iter_mut()
                .filter(|slot| slot.key.persistent.is_some())
                .map(|slot| {
                    slot.draining = true;
                    (slot.id, Arc::clone(&slot.backend))
                })
                .collect()
        };
        for (id, backend) in retired {
            if backend.shutdown_confirmed().await.is_ok() {
                self.inner.slots.lock().retain(|slot| slot.id != id);
                self.inner.active_sessions.lock().retain(|_, slot| *slot != id);
            }
        }
    }

    async fn reserve_context(
        &self,
        key: &Key,
        exclusive: bool,
        attempt: &mut Option<BrowserAttempt>,
    ) -> Result<(u64, Arc<dyn BrowserBackend>, OwnedSemaphorePermit, bool), BrowserError> {
        Ok(loop {
            let (slot_id, backend, sem, is_exclusive) = self.pick(key, exclusive, attempt).await?;
            let permit = sem
                .acquire_owned()
                .await
                .map_err(|_| BrowserError::Launch("browser slot closed".to_owned()))?;
            let mut slots = self.inner.slots.lock();
            let Some(slot) = slots.iter_mut().find(|slot| slot.id == slot_id) else {
                continue;
            };
            // Selection and permit acquisition may race another retirement.
            if slot.draining {
                continue;
            }
            slot.admitted = slot.admitted.saturating_add(1);
            if slot.admitted >= self.inner.retirement.max_contexts {
                slot.draining = true;
            }
            break (slot_id, backend, permit, is_exclusive);
        })
    }

    async fn retire_expired(&self) {
        {
            let now = tokio::time::Instant::now();
            let mut slots = self.inner.slots.lock();
            for slot in slots.iter_mut() {
                if now.duration_since(slot.started_at) >= self.inner.retirement.max_age
                    || (slot.contexts.available_permits() == slot.capacity
                        && now.duration_since(slot.last_used_at) >= self.inner.retirement.max_idle)
                {
                    slot.draining = true;
                }
            }
        }
        if self.inner.launcher.owns_backends() {
            let draining: Vec<_> = self
                .inner
                .slots
                .lock()
                .iter()
                .filter(|slot| {
                    slot.draining
                        && slot
                            .contexts
                            .available_permits()
                            .saturating_add(slot.quarantined.len())
                            == slot.capacity
                })
                .map(|slot| (slot.id, Arc::clone(&slot.backend)))
                .collect();
            for (id, backend) in draining {
                if backend.shutdown_confirmed().await.is_ok() {
                    self.inner.slots.lock().retain(|slot| slot.id != id);
                    self.inner.active_sessions.lock().retain(|_, slot| *slot != id);
                }
            }
        }
    }

    /// Forget an exclusive process that no session will ever use (hook refusal after launch).
    /// An attached backend is never killed; an owned one is retired only after confirmed death.
    async fn discard_unused_exclusive(&self, slot_id: u64) {
        let backend = self
            .inner
            .slots
            .lock()
            .iter_mut()
            .find(|slot| slot.id == slot_id)
            .map(|slot| {
                slot.draining = true;
                Arc::clone(&slot.backend)
            });
        let Some(backend) = backend else {
            return;
        };
        if self.inner.launcher.owns_backends() && backend.shutdown_confirmed().await.is_err() {
            // Death is unproved: the slot stays draining and charged until retirement confirms it.
            return;
        }
        self.inner.slots.lock().retain(|slot| slot.id != slot_id);
    }

    async fn pick(
        &self,
        key: &Key,
        exclusive: bool,
        attempt: &mut Option<BrowserAttempt>,
    ) -> Result<Picked, BrowserError> {
        self.retire_expired().await;
        let find = |slots: &[Slot]| -> Option<Picked> {
            slots
                .iter()
                .filter(|s| s.key == *key && !s.exclusive && !exclusive && !s.draining)
                .max_by_key(|s| (s.contexts.available_permits(), std::cmp::Reverse(s.id)))
                .map(|s| (s.id, Arc::clone(&s.backend), Arc::clone(&s.contexts), false))
        };
        {
            let slots = self.inner.slots.lock();
            if let Some(found) = find(&slots) {
                if found.2.available_permits() > 0 {
                    return Ok(found);
                }
            }
        }
        let _guard = self.inner.launch_lock.lock().await;
        // a concurrent acquirer may have launched a process while we waited
        let (existing, count) = {
            let slots = self.inner.slots.lock();
            (find(&slots), slots.len())
        };
        if let Some(found) = &existing {
            if found.2.available_permits() > 0 {
                return Ok(found.clone());
            }
        }
        if !self.inner.launcher.owns_backends() && self.inner.slots.lock().iter().any(|slot| slot.draining) {
            return Err(BrowserError::Unsupported(
                "session_unavailable: attached browser retired".into(),
            ));
        }
        if count.saturating_add(
            self.inner
                .unconfirmed_launches
                .load(std::sync::atomic::Ordering::Relaxed),
        ) >= self.inner.cfg.max_browsers.max(1)
        {
            if let Some(found) = existing {
                if self
                    .inner
                    .slots
                    .lock()
                    .iter()
                    .any(|slot| slot.id == found.0 && slot.quarantined.is_empty())
                {
                    return Ok(found); // wait for confirmed closure, never exceed the hard cap
                }
            }
            return Err(BrowserError::Unsupported(
                "session_unavailable: browser capacity quarantined or incompatible".into(),
            ));
        }
        // Launch hooks describe only a real process start; an attached backend is not launched.
        let launching = self.inner.launcher.owns_backends();
        if launching {
            if let Some(attempt) = attempt.as_mut() {
                attempt.dispatch(ExtensionEventV1::BrowserPreLaunch)?;
            }
        }
        self.inner
            .unconfirmed_launches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let backend = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            self.inner.launcher.launch(key),
        )
        .await
        .map_err(|_| BrowserError::Timeout(30_000))??;
        *self.inner.launches.lock() += 1;
        let id = {
            let mut n = self.inner.next_id.lock();
            *n += 1;
            *n
        };
        let contexts = Arc::new(Semaphore::new(if exclusive {
            1
        } else {
            self.inner.cfg.contexts_per_browser
        }));
        self.inner.slots.lock().push(Slot {
            id,
            key: key.clone(),
            exclusive,
            backend: Arc::clone(&backend),
            contexts: Arc::clone(&contexts),
            quarantined: Vec::new(),
            draining: false,
            capacity: if exclusive {
                1
            } else {
                self.inner.cfg.contexts_per_browser
            },
            admitted: 0,
            started_at: tokio::time::Instant::now(),
            last_used_at: tokio::time::Instant::now(),
        });
        self.inner
            .unconfirmed_launches
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if launching {
            if let Some(attempt) = attempt.as_mut() {
                if let Err(error) = attempt.dispatch(ExtensionEventV1::BrowserPostLaunch) {
                    // The process is real and already registered; a shared one stays usable.
                    if exclusive {
                        self.discard_unused_exclusive(id).await;
                    }
                    return Err(error);
                }
            }
        }
        Ok((id, backend, contexts, exclusive))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_browser::fake::{FakePage, FakeScript};
    use crawlx_browser::FakeBackend;
    use crawlx_core::SessionId;
    use std::time::Duration;

    fn fake() -> Arc<FakeBackend> {
        Arc::new(FakeBackend::new(
            FakeScript::new().page(FakePage::new("https://example.test/")),
        ))
    }

    fn cfg() -> ContextConfig {
        ContextConfig::new(SessionId::new())
    }

    async fn close(pooled: PooledContext) {
        let (context, _, lease) = pooled.into_parts();
        context.close().await.unwrap();
        lease.release(true).await.unwrap();
    }

    struct RetiringBackend {
        backend: Arc<FakeBackend>,
        stopped: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl BrowserBackend for RetiringBackend {
        async fn new_context(&self, config: ContextConfig) -> Result<Box<dyn BrowserContext>, BrowserError> {
            assert!(!self.stopped.load(std::sync::atomic::Ordering::SeqCst));
            self.backend.new_context(config).await
        }

        fn build_info(&self) -> &BrowserBuildInfo {
            self.backend.build_info()
        }

        async fn shutdown_confirmed(&self) -> Result<(), BrowserError> {
            assert_eq!(
                self.backend.open_contexts(),
                0,
                "retirement must drain active actors first"
            );
            self.stopped.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    struct RetiringLauncher(Arc<Mutex<Vec<Arc<RetiringBackend>>>>);

    #[async_trait]
    impl Launcher for RetiringLauncher {
        async fn launch(&self, _: &Key) -> Result<Arc<dyn BrowserBackend>, BrowserError> {
            let backend = Arc::new(RetiringBackend {
                backend: fake(),
                stopped: std::sync::atomic::AtomicBool::new(false),
            });
            self.0.lock().push(Arc::clone(&backend));
            Ok(backend)
        }

        fn owns_backends(&self) -> bool {
            true
        }
    }

    fn retiring_pool(policy: PoolRetirement) -> (BrowserPool, Arc<Mutex<Vec<Arc<RetiringBackend>>>>) {
        let launched = Arc::new(Mutex::new(Vec::new()));
        let pool = BrowserPool::build(
            Box::new(RetiringLauncher(Arc::clone(&launched))),
            PoolConfig {
                max_browsers: 1,
                contexts_per_browser: 2,
            },
        )
        .with_retirement(policy)
        .unwrap();
        (pool, launched)
    }

    #[tokio::test]
    async fn context_count_retirement_drains_all_actors_before_replacement() {
        let (pool, launched) = retiring_pool(PoolRetirement {
            max_contexts: 2,
            ..PoolRetirement::default()
        });
        let first = pool.acquire(cfg(), false).await.unwrap();
        let second = pool.acquire(cfg(), false).await.unwrap();
        assert!(pool.acquire(cfg(), false).await.is_err());
        assert!(!launched.lock()[0]
            .stopped
            .load(std::sync::atomic::Ordering::SeqCst));
        close(first).await;
        assert_eq!(pool.browsers(), 1);
        close(second).await;
        assert_eq!(pool.browsers(), 0);
        assert!(launched.lock()[0]
            .stopped
            .load(std::sync::atomic::Ordering::SeqCst));
        close(pool.acquire(cfg(), false).await.unwrap()).await;
        assert_eq!(launched.lock().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn inactivity_and_age_retirement_do_not_interrupt_live_contexts() {
        let (pool, launched) = retiring_pool(PoolRetirement {
            max_idle: Duration::from_secs(5),
            max_age: Duration::from_secs(10),
            ..PoolRetirement::default()
        });
        close(pool.acquire(cfg(), false).await.unwrap()).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        let active = pool.acquire(cfg(), false).await.unwrap();
        assert_eq!(launched.lock().len(), 2, "idle process must be replaced");
        tokio::time::advance(Duration::from_secs(10)).await;
        assert!(pool.acquire(cfg(), false).await.is_err());
        assert!(!launched.lock()[1]
            .stopped
            .load(std::sync::atomic::Ordering::SeqCst));
        close(active).await;
        assert!(launched.lock()[1]
            .stopped
            .load(std::sync::atomic::Ordering::SeqCst));
        close(pool.acquire(cfg(), false).await.unwrap()).await;
        assert_eq!(launched.lock().len(), 3);
    }

    #[tokio::test]
    async fn attached_retirement_preserves_resource_charge_and_never_kills_the_backend() {
        let pool = BrowserPool::with_backend(fake())
            .with_retirement(PoolRetirement {
                max_contexts: 1,
                ..PoolRetirement::default()
            })
            .unwrap();
        let context = pool.acquire(cfg(), false).await.unwrap();
        close(context).await;
        assert_eq!(pool.admission_available_contexts(), 0);
        assert!(pool.acquire(cfg(), false).await.is_err());
        assert_eq!(pool.launches(), 1);
    }

    #[tokio::test]
    async fn one_context_per_session_from_the_injected_backend() {
        let backend = fake();
        let pool = BrowserPool::with_backend(backend.clone());
        let a = pool.acquire(cfg(), false).await.unwrap();
        let b = pool.acquire(cfg(), false).await.unwrap();
        assert_eq!(backend.contexts_created(), 2);
        assert_eq!(pool.browsers(), 1, "contexts share the process");
        assert_eq!(pool.launches(), 1);
        drop((a, b));
    }

    #[tokio::test]
    async fn contexts_per_browser_is_a_semaphore() {
        let backend = fake();
        let pool = BrowserPool::with_backend_config(
            backend.clone(),
            PoolConfig {
                max_browsers: 1,
                contexts_per_browser: 1,
            },
        );
        let first = pool.acquire(cfg(), false).await.unwrap();
        let waiting = tokio::time::timeout(Duration::from_millis(100), pool.acquire(cfg(), false)).await;
        assert!(waiting.is_err(), "second acquire must wait for the first release");
        close(first).await;
        let second = tokio::time::timeout(Duration::from_secs(2), pool.acquire(cfg(), false))
            .await
            .expect("released slot is reusable")
            .unwrap();
        assert_eq!(backend.contexts_created(), 2);
        close(second).await;
    }

    #[tokio::test]
    async fn exclusive_sessions_get_their_own_process_and_retire_it() {
        let pool = BrowserPool::with_backend_config(
            fake(),
            PoolConfig {
                max_browsers: 2,
                contexts_per_browser: 4,
            },
        );
        let a = pool.acquire(cfg(), true).await.unwrap();
        let b = pool.acquire(cfg(), true).await.unwrap();
        assert_eq!(pool.browsers(), 2);
        close(a).await;
        assert_eq!(pool.browsers(), 1, "exclusive process retires with its session");
        close(b).await;
        assert_eq!(pool.browsers(), 0);
    }

    #[tokio::test]
    async fn profiles_do_not_share_a_process() {
        let pool = BrowserPool::with_backend_config(
            fake(),
            PoolConfig {
                max_browsers: 2,
                contexts_per_browser: 4,
            },
        );
        let mut stealth = cfg();
        stealth.launch_profile = LaunchProfile::Stealth;
        let a = pool.acquire(cfg(), false).await.unwrap();
        let b = pool.acquire(stealth, false).await.unwrap();
        assert_eq!(pool.browsers(), 2);
        drop((a, b));
    }

    #[tokio::test]
    async fn dropping_unconfirmed_external_context_quarantines_and_caps_new_admissions() {
        let pool = BrowserPool::with_backend_config(
            fake(),
            PoolConfig {
                max_browsers: 1,
                contexts_per_browser: 1,
            },
        );
        let context = pool.acquire(cfg(), false).await.unwrap();
        drop(context);
        assert_eq!(pool.available_contexts(), 0);
        assert_eq!(pool.quarantined_contexts(), 1);
        let failure = pool.acquire(cfg(), true).await;
        assert!(matches!(failure, Err(BrowserError::Unsupported(_))));
        assert_eq!(
            pool.browsers(),
            1,
            "no unrelated external process was killed or replaced"
        );
    }

    #[tokio::test]
    async fn strict_session_actor_collision_is_rejected_without_allocating_another_jar() {
        let pool = BrowserPool::with_backend(fake());
        let config = cfg();
        let first = pool.acquire(config.clone(), false).await.unwrap();
        assert!(matches!(
            pool.acquire(config.clone(), false).await,
            Err(BrowserError::Unsupported(_))
        ));
        close(first).await;
        close(pool.acquire(config, false).await.unwrap()).await;
    }

    // ---- typed browser lifecycle hooks -------------------------------------------------

    use crawlx_core::extensions::{
        ExtensionConfigV1, ExtensionPipelineV1, ExtensionSpecV1, ExtensionStageV1,
    };
    use crawlx_core::repo::RunEvent;

    #[derive(Default)]
    struct Recorder(Mutex<Vec<serde_json::Value>>);

    #[async_trait]
    impl crawlx_core::repo::EventRepo for Recorder {
        async fn append(
            &self,
            _run: crawlx_core::CrawlRunId,
            kind: &str,
            payload: serde_json::Value,
        ) -> Result<u64, crawlx_core::StoreError> {
            assert_eq!(kind, BROWSER_EVENT_KIND);
            let mut events = self.0.lock();
            events.push(payload);
            Ok(events.len() as u64)
        }

        async fn list_after(
            &self,
            _run: crawlx_core::CrawlRunId,
            _after: u64,
            _limit: u32,
        ) -> Result<Vec<RunEvent>, crawlx_core::StoreError> {
            Ok(Vec::new())
        }
    }

    impl Recorder {
        fn stages(&self) -> Vec<String> {
            self.0
                .lock()
                .iter()
                .map(|payload| payload["receipt"]["event"]["kind"].as_str().unwrap().to_owned())
                .collect()
        }

        fn terminal(&self) -> Option<serde_json::Value> {
            self.0
                .lock()
                .iter()
                .find(|payload| payload["receipt"]["event"]["kind"] == "terminal")
                .map(|payload| payload["receipt"]["event"]["facts"].clone())
        }
    }

    fn hooked(
        pipeline: &ExtensionPipelineV1,
        pool: BrowserPool,
        cancel: tokio_util::sync::CancellationToken,
    ) -> (BrowserPool, Arc<Recorder>) {
        let events = Arc::new(Recorder::default());
        let ext =
            PoolExtensions::new(pipeline, events.clone(), crawlx_core::CrawlRunId::new(), cancel).unwrap();
        (pool.with_extensions(ext), events)
    }

    fn pipeline(entries: Vec<ExtensionSpecV1>) -> ExtensionPipelineV1 {
        let mut pipeline = ExtensionPipelineV1::default();
        pipeline.extensions = entries;
        pipeline
    }

    fn annotate(stage: ExtensionStageV1) -> ExtensionSpecV1 {
        ExtensionSpecV1::new(
            ExtensionConfigV1::Annotate {
                stage,
                code: "seen".into(),
            },
            0,
        )
    }

    fn owned_pool() -> (BrowserPool, Arc<Mutex<Vec<Arc<RetiringBackend>>>>) {
        let launched = Arc::new(Mutex::new(Vec::new()));
        let pool = BrowserPool::build(
            Box::new(RetiringLauncher(Arc::clone(&launched))),
            PoolConfig {
                max_browsers: 2,
                contexts_per_browser: 2,
            },
        );
        (pool, launched)
    }

    #[tokio::test]
    async fn owned_launch_page_and_close_hooks_run_in_real_effect_order() {
        let (pool, _) = owned_pool();
        let (pool, events) = hooked(
            &pipeline(vec![annotate(ExtensionStageV1::BrowserPreLaunch)]),
            pool,
            Default::default(),
        );
        let pooled = pool.acquire(cfg(), true).await.unwrap();
        assert_eq!(
            events.stages(),
            [
                "configure",
                "browser_pre_launch",
                "browser_post_launch",
                "browser_page_create"
            ]
        );
        close(pooled).await;
        assert_eq!(
            events.stages(),
            [
                "configure",
                "browser_pre_launch",
                "browser_post_launch",
                "browser_page_create",
                "browser_page_close",
                "browser_close",
                "terminal",
                "checkpoint",
                "close"
            ]
        );
        assert_eq!(events.terminal().unwrap()["kind"], "completed");
        assert_eq!(
            pool.browsers(),
            0,
            "owner close happened once, with no pool recursion"
        );
    }

    #[tokio::test]
    async fn attached_or_reused_backend_is_never_reported_as_a_launch_or_owner_close() {
        let (pool, events) = hooked(
            &pipeline(vec![annotate(ExtensionStageV1::BrowserPageCreate)]),
            BrowserPool::with_backend(fake()),
            Default::default(),
        );
        close(pool.acquire(cfg(), false).await.unwrap()).await;
        let stages = events.stages();
        assert!(stages.contains(&"browser_page_create".to_owned()));
        assert!(stages.contains(&"browser_page_close".to_owned()));
        assert!(!stages.iter().any(|stage| matches!(
            stage.as_str(),
            "browser_pre_launch" | "browser_post_launch" | "browser_close"
        )));
    }

    #[tokio::test]
    async fn pre_launch_rejection_stops_the_launch_and_leaks_no_capacity() {
        let (pool, launched) = owned_pool();
        let denial = ExtensionSpecV1::new(
            ExtensionConfigV1::RejectStage {
                stage: ExtensionStageV1::BrowserPreLaunch,
            },
            0,
        );
        let (pool, events) = hooked(&pipeline(vec![denial]), pool, Default::default());
        assert!(pool.acquire(cfg(), false).await.is_err());
        assert!(launched.lock().is_empty(), "a refused hook launches nothing");
        assert_eq!(pool.launches(), 0);
        assert_eq!(pool.browsers(), 0);
        assert_eq!(pool.quarantined_contexts(), 0);
        assert!(!events.stages().contains(&"browser_post_launch".to_owned()));
        assert_eq!(events.terminal().unwrap()["kind"], "skipped");
    }

    #[tokio::test]
    async fn page_create_failure_retires_the_unused_owned_process_and_releases_the_permit() {
        let (pool, launched) = owned_pool();
        let failure = ExtensionSpecV1::new(
            ExtensionConfigV1::FailStage {
                stage: ExtensionStageV1::BrowserPageCreate,
            },
            0,
        );
        let (pool, events) = hooked(&pipeline(vec![failure]), pool, Default::default());
        assert!(pool.acquire(cfg(), true).await.is_err());
        assert_eq!(launched.lock().len(), 1);
        assert!(launched.lock()[0]
            .stopped
            .load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            launched.lock()[0].backend.contexts_created(),
            0,
            "no page was requested"
        );
        assert_eq!(pool.browsers(), 0);
        assert_eq!(pool.quarantined_contexts(), 0);
        assert_eq!(events.terminal().unwrap()["kind"], "failed");
    }

    #[tokio::test]
    async fn cancellation_before_launch_is_a_cancelled_skip_without_effects() {
        let (pool, launched) = owned_pool();
        let cancel = tokio_util::sync::CancellationToken::new();
        let (pool, events) = hooked(
            &pipeline(vec![annotate(ExtensionStageV1::BrowserPreLaunch)]),
            pool,
            cancel.clone(),
        );
        cancel.cancel();
        assert!(pool.acquire(cfg(), false).await.is_err());
        assert!(launched.lock().is_empty());
        assert_eq!(pool.quarantined_contexts(), 0);
        let terminal = events.terminal().unwrap();
        assert_eq!(terminal["kind"], "skipped");
        assert_eq!(terminal["reason"], "cancelled");
    }

    #[tokio::test]
    async fn failing_browser_close_hook_cannot_block_or_recurse_into_pool_close() {
        let (pool, _) = owned_pool();
        let failure = ExtensionSpecV1::new(
            ExtensionConfigV1::FailStage {
                stage: ExtensionStageV1::BrowserClose,
            },
            0,
        );
        let (pool, events) = hooked(&pipeline(vec![failure]), pool, Default::default());
        let pooled = pool.acquire(cfg(), true).await.unwrap();
        let (context, _, lease) = pooled.into_parts();
        context.close().await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), lease.release(true))
            .await
            .expect("hook cannot re-enter the pool")
            .unwrap();
        assert_eq!(
            pool.browsers(),
            0,
            "the real close effect is not undone by a hook"
        );
        assert_eq!(events.terminal().unwrap()["kind"], "failed");
        close(pool.acquire(cfg(), false).await.unwrap()).await;
    }

    #[tokio::test]
    async fn dropped_lease_seals_receipts_as_cancelled_and_keeps_capacity_quarantined() {
        let (pool, events) = hooked(
            &pipeline(vec![annotate(ExtensionStageV1::BrowserPageCreate)]),
            BrowserPool::with_backend(fake()),
            Default::default(),
        );
        drop(pool.acquire(cfg(), false).await.unwrap());
        assert_eq!(pool.quarantined_contexts(), 1);
        for _ in 0..100 {
            if events.terminal().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let terminal = events.terminal().expect("drop must persist the sealed trail");
        assert_eq!(terminal["reason"], "cancelled");
    }
}
