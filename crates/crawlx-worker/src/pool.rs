//! `BrowserPool`: Chromium processes start lazily, each hosts at most
//! `contexts_per_browser` incognito contexts (one per session), and processes are bounded by
//! a semaphore. Under `authorized_security_test` every session gets its own process.

use async_trait::async_trait;
use crawlx_browser::{ChromiumBackend, LaunchConfig};
use crawlx_core::browser::ProfileSpec;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::{BrowserBackend, BrowserContext, BrowserError, ContextConfig, LaunchProfile};
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

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

    pub(crate) fn with_profile(mut self, profile: crate::profile_lifecycle::ProfileRun) -> Self {
        self.lease.profile = Some(profile);
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
    profile: Option<crate::profile_lifecycle::ProfileRun>,
}

impl Lease {
    /// Release only after context closure. An owned exclusive process must also be reaped.
    /// An attached/injected backend is never killed on behalf of one context.
    ///
    /// # Errors
    /// Returns cleanup/lease/profile generation errors without releasing uncertain capacity.
    pub async fn release(mut self, context_closed: bool) -> Result<(), crate::error::SessionError> {
        let backend = {
            let mut slots = self.pool.slots.lock();
            let Some(slot) = slots.iter_mut().find(|slot| slot.id == self.slot) else {
                return Ok(());
            };
            if self.exclusive && self.pool.launcher.owns_backends() {
                slot.draining = true;
                Some(Arc::clone(&slot.backend))
            } else {
                None
            }
        };
        if let Some(backend) = backend {
            // No timeout around this future: cancellation must not drop an owned Child and
            // pretend resource death. The backend itself has bounded graceful/kill waits.
            backend.shutdown_confirmed().await?;
            self.pool.slots.lock().retain(|slot| slot.id != self.slot);
            self.permit.take();
            self.pool
                .active_sessions
                .lock()
                .retain(|_, slot| *slot != self.slot);
            if let Some(profile) = self.profile.take() {
                profile.finish().await?;
            }
        } else if context_closed {
            if self.exclusive {
                self.pool.slots.lock().retain(|slot| slot.id != self.slot);
            }
            self.permit.take();
            self.pool.active_sessions.lock().remove(&self.session);
        } else {
            return Err(crate::error::SessionError::Other(
                "session_unavailable: browser resource quarantined".into(),
            ));
        }
        // Failed cleanup reaches Drop and keeps its permit in bounded quarantine.
        Ok(())
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
        Self {
            inner: Arc::new(Inner {
                launcher,
                cfg,
                slots: Mutex::new(Vec::new()),
                active_sessions: Mutex::new(std::collections::BTreeMap::new()),
                next_id: Mutex::new(0),
                launch_lock: tokio::sync::Mutex::new(()),
                unconfirmed_launches: std::sync::atomic::AtomicUsize::new(0),
                launches: Mutex::new(0),
                cleanup: Mutex::new(tokio::task::JoinSet::new()),
            }),
            wrap: None,
        }
    }

    /// Decorate every context this pool (and its clones) hands out from now on.
    #[must_use]
    pub fn with_context_wrapper(mut self, wrap: ContextWrapper) -> Self {
        self.wrap = Some(wrap);
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
        let unlaunched = self.inner.cfg.max_browsers.max(1).saturating_sub(charged);
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
    pub async fn acquire(
        &self,
        config: ContextConfig,
        exclusive: bool,
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
        let (slot_id, backend, sem, is_exclusive) = self.pick(&key, exclusive).await?;
        let permit = Arc::clone(&sem)
            .acquire_owned()
            .await
            .map_err(|_| BrowserError::Launch("browser slot closed".to_owned()))?;
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
            profile: None,
        };
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

    async fn pick(&self, key: &Key, exclusive: bool) -> Result<Picked, BrowserError> {
        if self.inner.launcher.owns_backends() {
            let draining: Vec<_> = self
                .inner
                .slots
                .lock()
                .iter()
                .filter(|slot| slot.draining && slot.exclusive)
                .map(|slot| (slot.id, Arc::clone(&slot.backend)))
                .collect();
            for (id, backend) in draining {
                if backend.shutdown_confirmed().await.is_ok() {
                    self.inner.slots.lock().retain(|slot| slot.id != id);
                    self.inner.active_sessions.lock().retain(|_, slot| *slot != id);
                }
            }
        }
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
        });
        self.inner
            .unconfirmed_launches
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
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
}
