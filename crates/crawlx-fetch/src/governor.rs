//! Per-origin politeness: a concurrency semaphore plus a
//! minimum spacing between request starts, adapting to `429`/`503` answers,
//! and the katana-style rate limits: a global and a per-host
//! requests-per-second / requests-per-minute bucket ([`GlobalBucket`],
//! [`HostBucket`]) and a global in-flight cap (`maxConcurrency`).
//!
//! HTTP and browser effects share one admission authority. The local default uses
//! `tokio::time::Instant` so tests can control time; workers backed by PostgreSQL
//! also charge a deployment-wide [`crawlx_core::origin::OriginAdmission`] permit.
//! The shared cap isolates FIFO capacity and pacing queues by origin. Browser
//! permits retain their process-local start turn until dispatch is committed,
//! so final preparation cannot consume the 500 ms spacing between effects.
//! Abandoned browser preparation does not advance local spacing clocks.
//! Deployment admission still timestamps reservation: its asynchronous interface
//! cannot commit actual dispatch after final browser gates without another await.
//!
//! The buckets are exact sliding windows over reserved start times: the
//! `n`-th start is never earlier than the `(n - limit)`-th start plus the
//! period, so any half-open window of one period holds at most `limit`
//! starts. Reservations are taken in call order under one lock, so
//! concurrent callers never share a slot and never reorder.

use crawlx_core::config::Politeness;
use crawlx_core::origin::{OriginAdmission, OriginPermit};
use crawlx_core::runtime_admission::PacingDialectV1;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::StoreError;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use rand::Rng as _;
use rand_chacha::ChaCha8Rng;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

/// `scheme://host[:port]`, the unit of politeness and scope.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Origin(String);

impl Origin {
    /// Origin of `url` in ASCII serialization (default ports elided).
    #[must_use]
    pub fn from_url(url: &url::Url) -> Self {
        Self(url.origin().ascii_serialization())
    }

    /// Wrap an already serialized origin string (lowercased).
    #[must_use]
    pub fn new(s: &str) -> Self {
        Self(s.to_ascii_lowercase())
    }

    /// The serialized origin, e.g. `https://example.com`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Host part of the origin (no scheme, no port); the unit of the per-host buckets.
    #[must_use]
    pub fn host(&self) -> &str {
        let rest = self.0.split_once("://").map_or(self.0.as_str(), |(_, r)| r);
        if let Some(end) = rest.strip_prefix('[').and_then(|r| r.find(']')) {
            // IPv6 literal: `[::1]:8080`
            return &rest[..=end + 1];
        }
        rest.rsplit_once(':').map_or(rest, |(h, _)| h)
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&url::Url> for Origin {
    fn from(u: &url::Url) -> Self {
        Self::from_url(u)
    }
}

/// Governor tuning.
#[derive(Clone, Debug)]
pub struct GovernorConfig {
    /// `d0`: minimum spacing between request starts to one origin.
    pub base_delay: Duration,
    /// Cap for the adaptive spacing.
    pub max_delay: Duration,
    /// Concurrent requests per origin.
    pub max_in_flight_per_origin: usize,
    /// After this many consecutive `2xx` the spacing halves (never below `base_delay`).
    pub decay_after: u32,
    /// Source of the ±20% back-off jitter.
    pub seed: CrawlSeed,
    /// Requests per second across every host (`politeness.globalRps`); `None` = unlimited.
    pub global_rps: Option<u32>,
    /// Requests per minute across every host (`politeness.globalRpm`); `None` = unlimited.
    pub global_rpm: Option<u32>,
    /// Requests per second to one host (`politeness.perHostRps`); `None` = unlimited.
    pub per_host_rps: Option<u32>,
    /// Requests per minute to one host (`politeness.perHostRpm`); `None` = unlimited.
    pub per_host_rpm: Option<u32>,
    /// Requests in flight across every origin (`politeness.maxConcurrency`, default 10).
    pub max_concurrency: usize,
    /// Connections to one origin across every run of the process (default
    /// [`GlobalOriginCap::DEFAULT_LIMIT`]). Used only when [`OriginGovernor::new`] builds
    /// its own cap; [`OriginGovernor::with_global_cap`] shares a process-wide one.
    pub global_per_origin_cap: usize,
}

impl Default for GovernorConfig {
    fn default() -> Self {
        Self {
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(60),
            max_in_flight_per_origin: 1,
            decay_after: 10,
            seed: CrawlSeed(0),
            global_rps: None,
            global_rpm: None,
            per_host_rps: None,
            per_host_rpm: None,
            max_concurrency: 10,
            global_per_origin_cap: GlobalOriginCap::DEFAULT_LIMIT,
        }
    }
}

impl GovernorConfig {
    /// Build from the crawl's politeness settings.
    #[must_use]
    pub fn from_politeness(p: &Politeness, seed: CrawlSeed) -> Self {
        Self {
            base_delay: Duration::from_millis(u64::from(p.delay_ms)),
            max_in_flight_per_origin: usize::from(p.max_in_flight_per_origin.max(1)),
            seed,
            global_rps: p.global_rps,
            global_rpm: p.global_rpm,
            per_host_rps: p.per_host_rps,
            per_host_rpm: p.per_host_rpm,
            max_concurrency: usize::from(p.max_concurrency.max(1)),
            ..Self::default()
        }
    }
}

/// Exact sliding window: at most `limit` starts in any half-open window of `period`.
#[derive(Debug)]
struct Window {
    period: Duration,
    limit: usize,
    starts: VecDeque<Instant>,
}

impl Window {
    fn new(period: Duration, limit: u32) -> Self {
        let limit = usize::try_from(limit.max(1)).unwrap_or(usize::MAX);
        Self {
            period,
            limit,
            starts: VecDeque::with_capacity(limit.min(4096)),
        }
    }

    /// Reserve the next start at or after `now`; returns the reserved instant.
    fn reserve(&mut self, now: Instant) -> Instant {
        let earliest = if self.starts.len() >= self.limit {
            self.starts.front().map_or(now, |first| *first + self.period)
        } else {
            now
        };
        let start = earliest.max(now);
        self.starts.push_back(start);
        while self.starts.len() > self.limit {
            self.starts.pop_front();
        }
        start
    }
}

/// Per-second and per-minute windows; either may be absent (unlimited).
#[derive(Debug)]
struct RateWindows {
    rps: Option<Window>,
    rpm: Option<Window>,
}

impl RateWindows {
    fn new(rps: Option<u32>, rpm: Option<u32>) -> Self {
        Self {
            rps: rps.map(|n| Window::new(Duration::from_secs(1), n)),
            rpm: rpm.map(|n| Window::new(Duration::from_secs(60), n)),
        }
    }

    /// Reserve a start in every window; the later one wins.
    fn reserve(&mut self, now: Instant) -> Instant {
        let a = self.rps.as_mut().map_or(now, |w| w.reserve(now));
        let b = self.rpm.as_mut().map_or(now, |w| w.reserve(now));
        a.max(b)
    }
}

/// Global rate limit: `politeness.globalRps` / `politeness.globalRpm` across every host.
#[derive(Debug)]
pub struct GlobalBucket {
    windows: Mutex<RateWindows>,
}

impl GlobalBucket {
    /// A bucket with the given limits; `None` for either means unlimited.
    #[must_use]
    pub fn new(rps: Option<u32>, rpm: Option<u32>) -> Self {
        Self {
            windows: Mutex::new(RateWindows::new(rps, rpm)),
        }
    }

    /// Reserve the next allowed start at or after `now`.
    #[must_use]
    pub fn reserve(&self, now: Instant) -> Instant {
        self.windows.lock().reserve(now)
    }

    /// Wait until a start is allowed.
    pub async fn acquire(&self) {
        let start = self.reserve(Instant::now());
        tokio::time::sleep_until(start).await;
    }
}

/// Per-host rate limit: `politeness.perHostRps` / `politeness.perHostRpm`, one window set
/// per host so a slow host never throttles another.
#[derive(Debug)]
pub struct HostBucket {
    rps: Option<u32>,
    rpm: Option<u32>,
    hosts: Mutex<HashMap<String, RateWindows>>,
}

impl HostBucket {
    /// A bucket with the given per-host limits; `None` for either means unlimited.
    #[must_use]
    pub fn new(rps: Option<u32>, rpm: Option<u32>) -> Self {
        Self {
            rps,
            rpm,
            hosts: Mutex::new(HashMap::new()),
        }
    }

    /// Reserve the next allowed start for `host` at or after `now`.
    #[must_use]
    pub fn reserve(&self, host: &str, now: Instant) -> Instant {
        if self.rps.is_none() && self.rpm.is_none() {
            return now;
        }
        let mut hosts = self.hosts.lock();
        match hosts.get_mut(host) {
            Some(w) => w.reserve(now),
            None => {
                let mut w = RateWindows::new(self.rps, self.rpm);
                let start = w.reserve(now);
                hosts.insert(host.to_owned(), w);
                start
            }
        }
    }

    /// Wait until a start to `host` is allowed.
    pub async fn acquire(&self, host: &str) {
        let start = self.reserve(host, Instant::now());
        tokio::time::sleep_until(start).await;
    }
}

#[derive(Debug)]
struct Pacing {
    next_allowed: Instant,
    delay: Duration,
    /// Lower bound of `delay`: `base_delay`, raised by the origin's `robots.txt` `Crawl-delay`.
    floor: Duration,
    ok_streak: u32,
    /// Last HTTP admission or committed browser dispatch; `None` before the first.
    last_start: Option<Instant>,
}

#[derive(Debug)]
struct OriginState {
    sem: Arc<Semaphore>,
    pacing: Mutex<Pacing>,
}

/// Shared origin capacity and start spacing across runs and tenants.
///
/// Attach a deployment admission store with [`Self::with_admission`] when workers
/// run in separate processes. The local queues remain useful for FIFO fairness
/// and for preventing one worker from flooding the deployment store with waiters.
pub struct GlobalOriginCap {
    limit: usize,
    origins: Mutex<BTreeMap<Origin, Arc<SharedOrigin>>>,
    admission: Option<Arc<dyn OriginAdmission>>,
    local: Option<Arc<GlobalOriginCap>>,
}

#[derive(Debug)]
struct SharedOrigin {
    slots: Arc<Semaphore>,
    starts: Arc<Semaphore>,
    pacing: Mutex<Option<(Instant, Duration)>>,
    cooldown: Mutex<Cooldown>,
}

#[derive(Debug, Default)]
struct Cooldown {
    until: Option<Instant>,
    backoff: Duration,
    decays_at: Option<Instant>,
    /// An unrepresentable Retry-After is a closed origin, never a shortened delay.
    blocked: bool,
}

impl fmt::Debug for GlobalOriginCap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GlobalOriginCap")
            .field("limit", &self.limit)
            .field("deployment", &self.admission.is_some())
            .finish_non_exhaustive()
    }
}

impl GlobalOriginCap {
    /// Planning default: four concurrent connections to one origin per process.
    pub const DEFAULT_LIMIT: usize = 4;

    /// Cap of `limit` connections per origin (at least one).
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.max(1),
            origins: Mutex::new(BTreeMap::new()),
            admission: None,
            local: None,
        }
    }

    /// Shared capacity backed by a deployment-wide admission authority.
    #[must_use]
    pub fn with_admission(limit: usize, admission: Arc<dyn OriginAdmission>) -> Self {
        Self {
            admission: Some(admission),
            ..Self::new(limit)
        }
    }

    /// Scope deployment admission while retaining one worker's shared FIFO queues.
    ///
    /// Reuse `local` across runs so a hot origin cannot fill the deployment
    /// connection pool with one blocked waiter per tenant.
    #[must_use]
    pub fn with_shared_admission(local: Arc<Self>, admission: Arc<dyn OriginAdmission>) -> Self {
        let limit = local.limit();
        Self {
            admission: Some(admission),
            local: Some(local),
            ..Self::new(limit)
        }
    }

    /// The configured limit.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Free slots for `origin` right now (`limit` for an origin never seen).
    #[must_use]
    pub fn available(&self, origin: &Origin) -> usize {
        if let Some(local) = &self.local {
            return local.available(origin);
        }
        self.origins
            .lock()
            .get(origin)
            .map_or(self.limit, |s| s.slots.available_permits())
    }

    fn state(&self, origin: &Origin) -> Arc<SharedOrigin> {
        if let Some(local) = &self.local {
            return local.state(origin);
        }
        let mut map = self.origins.lock();
        Arc::clone(map.entry(origin.clone()).or_insert_with(|| {
            Arc::new(SharedOrigin {
                slots: Arc::new(Semaphore::new(self.limit)),
                starts: Arc::new(Semaphore::new(1)),
                pacing: Mutex::new(None),
                cooldown: Mutex::new(Cooldown::default()),
            })
        }))
    }

    async fn acquire_slot(&self, origin: &Origin) -> OwnedSemaphorePermit {
        match Arc::clone(&self.state(origin).slots).acquire_owned().await {
            Ok(permit) => permit,
            Err(_closed) => std::future::pending().await,
        }
    }

    async fn reserve(
        &self,
        origin: &Origin,
    ) -> Result<(OwnedSemaphorePermit, Option<Box<dyn OriginPermit>>), StoreError> {
        let slot = self.acquire_slot(origin).await;
        let deployment = match &self.admission {
            Some(store) => Some(store.reserve(origin.as_str()).await?),
            None => None,
        };
        Ok((slot, deployment))
    }

    fn cooldown_remaining(&self, origin: &Origin) -> Duration {
        let state = self.state(origin);
        let cooldown = state.cooldown.lock();
        if cooldown.blocked {
            return Duration::MAX;
        }
        cooldown.until.map_or(Duration::ZERO, |until| {
            until.saturating_duration_since(Instant::now())
        })
    }

    fn note_cooldown(&self, origin: &Origin, minimum: Duration, exponential: bool) -> Duration {
        let state = self.state(origin);
        let mut cooldown = state.cooldown.lock();
        if cooldown.blocked {
            return Duration::MAX;
        }
        let now = Instant::now();
        let active = cooldown.until.is_some_and(|until| until > now);
        if exponential && !active {
            if cooldown.decays_at.is_none_or(|decays| now >= decays) {
                cooldown.backoff = Duration::ZERO;
            }
            cooldown.backoff = cooldown
                .backoff
                .saturating_mul(2)
                .max(Duration::from_secs(2))
                .min(Duration::from_secs(60));
        }
        let delay = if exponential && !active {
            minimum.max(cooldown.backoff)
        } else {
            minimum
        };
        let Some(until) = now.checked_add(delay) else {
            cooldown.blocked = true;
            return Duration::MAX;
        };
        let previous = cooldown.until;
        cooldown.until = Some(previous.map_or(until, |old| old.max(until)));
        if exponential && (!active || previous.is_none_or(|old| until > old)) {
            let dispatchable = state
                .pacing
                .lock()
                .and_then(|(last, spacing)| last.checked_add(spacing))
                .map_or(until, |paced| paced.max(until));
            cooldown.decays_at = dispatchable.checked_add(delay.max(cooldown.backoff));
        }
        cooldown
            .until
            .map_or(Duration::ZERO, |until| until.saturating_duration_since(now))
    }

    async fn publish_cooldown(
        &self,
        origin: &Origin,
        minimum: Duration,
        exponential: bool,
    ) -> Result<Duration, StoreError> {
        let remaining = match &self.admission {
            Some(store) => store.cooldown(origin.as_str(), minimum, exponential).await?,
            None => self.cooldown_remaining(origin),
        };
        Ok(self.note_cooldown(origin, remaining, false))
    }

    async fn start(
        &self,
        origin: &Origin,
        spacing: Duration,
        deployment: &mut Option<Box<dyn OriginPermit>>,
        concurrency: &Arc<Semaphore>,
    ) -> Result<(OwnedSemaphorePermit, OwnedSemaphorePermit), StoreError> {
        let state = self.state(origin);
        // A per-origin FIFO start queue, never a global mutex. Browser permits
        // retain the turn until dispatch; cancellation releases it automatically.
        let turn = match Arc::clone(&state.starts).acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => std::future::pending().await,
        };
        loop {
            let now = Instant::now();
            if state.cooldown.lock().blocked {
                return Err(StoreError::Conflict(
                    "origin cooldown exceeds monotonic clock range".into(),
                ));
            }
            let paced = state
                .pacing
                .lock()
                .and_then(|(last, previous)| last.checked_add(spacing.max(previous)));
            let cooled = state.cooldown.lock().until;
            let next = paced.into_iter().chain(cooled).max().unwrap_or(now);
            if next > now {
                tokio::time::sleep_until(next).await;
                continue;
            }
            let global = match Arc::clone(concurrency).acquire_owned().await {
                Ok(permit) => permit,
                Err(_) => std::future::pending().await,
            };
            let local_wait = self.cooldown_remaining(origin);
            let wait = if !local_wait.is_zero() {
                Some(local_wait)
            } else if let Some(permit) = deployment {
                permit.try_start(spacing).await?
            } else {
                None
            };
            if let Some(wait) = wait {
                // A newly reported remote cooldown must not monopolize the only
                // run-global slot while unrelated origins are ready.
                drop(global);
                tokio::time::sleep(wait).await;
                continue;
            }
            // The caller records HTTP admission or retains this turn until browser dispatch.
            return Ok((global, turn));
        }
    }
}

impl Default for GlobalOriginCap {
    fn default() -> Self {
        Self::new(Self::DEFAULT_LIMIT)
    }
}

/// Holding a `Permit` means one in-flight slot of the origin, one of the global
/// concurrency cap and one of the process-wide per-origin cap are taken, and the
/// spacing and rate-bucket waits have elapsed. Dropping it frees all three slots.
/// Browser permits also hold the process-local start turn until
/// [`Self::commit_dispatch`] or drop.
#[derive(Debug)]
pub struct Permit {
    _slot: Option<OwnedSemaphorePermit>,
    _global: Option<OwnedSemaphorePermit>,
    _origin_cap: OwnedSemaphorePermit,
    _deployment: Option<Box<dyn OriginPermit>>,
    browser_dispatch: Option<BrowserDispatch>,
}

#[derive(Debug)]
struct BrowserDispatch {
    state: Arc<OriginState>,
    shared: Arc<SharedOrigin>,
    spacing: Duration,
    _turn: OwnedSemaphorePermit,
}

impl Permit {
    /// Charge browser spacing at the effect dispatch boundary without waiting.
    ///
    /// Call immediately before dispatch, after all final checks. The retained
    /// start turn prevents other process-local permits from passing admission
    /// during preparation, even when origin capacity exceeds one. This does not
    /// retimestamp deployment admission or the reserved rate-bucket windows.
    /// Repeated calls and HTTP permits do nothing.
    ///
    /// # Errors
    /// Returns a conflict when spacing exceeds the monotonic clock range.
    pub fn commit_dispatch(&mut self) -> Result<(), StoreError> {
        if let Some(dispatch) = self.browser_dispatch.take() {
            let now = Instant::now();
            let next = now
                .checked_add(dispatch.spacing)
                .ok_or_else(|| StoreError::Conflict("origin spacing exceeds monotonic clock range".into()))?;
            {
                let mut pacing = dispatch.state.pacing.lock();
                pacing.next_allowed = pacing.next_allowed.max(next);
                pacing.last_start = Some(now);
            }
            *dispatch.shared.pacing.lock() = Some((now, dispatch.spacing));
            // Release the FIFO turn only after both spacing clocks are updated.
        }
        Ok(())
    }
}

/// Per-origin concurrency and spacing control plus the global/per-host rate buckets.
pub struct OriginGovernor {
    cfg: GovernorConfig,
    origins: Mutex<HashMap<Origin, Arc<OriginState>>>,
    rng: Mutex<ChaCha8Rng>,
    global: GlobalBucket,
    hosts: HostBucket,
    concurrency: Arc<Semaphore>,
    origin_cap: Arc<GlobalOriginCap>,
    dialect: Mutex<(PacingDialectV1, u32)>,
}

impl fmt::Debug for OriginGovernor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginGovernor")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl OriginGovernor {
    /// Governor with no origin state yet; pacing, jitter and buckets follow `cfg`. The
    /// cross-run origin cap is private to this governor (`cfg.global_per_origin_cap`);
    /// a worker process shares one through [`Self::with_global_cap`].
    #[must_use]
    pub fn new(cfg: GovernorConfig) -> Self {
        let cap = Arc::new(GlobalOriginCap::new(cfg.global_per_origin_cap));
        Self::with_global_cap(cfg, cap)
    }

    /// Governor sharing `origin_cap` with every other governor built over it.
    #[must_use]
    pub fn with_global_cap(cfg: GovernorConfig, origin_cap: Arc<GlobalOriginCap>) -> Self {
        let rng = cfg.seed.rng("fetch/governor-jitter", &[]);
        let global = GlobalBucket::new(cfg.global_rps, cfg.global_rpm);
        let hosts = HostBucket::new(cfg.per_host_rps, cfg.per_host_rpm);
        let concurrency = Arc::new(Semaphore::new(cfg.max_concurrency.max(1)));
        Self {
            cfg,
            origins: Mutex::new(HashMap::new()),
            rng: Mutex::new(rng),
            global,
            hosts,
            concurrency,
            origin_cap,
            dialect: Mutex::new((PacingDialectV1::Native, 1)),
        }
    }

    /// The process-wide per-origin cap this governor charges.
    #[must_use]
    pub fn global_cap(&self) -> &Arc<GlobalOriginCap> {
        &self.origin_cap
    }

    /// Select the imported feedback recurrence without adding another rate limiter.
    /// Advisory concurrency divides latency only; it never expands any hard cap.
    pub fn set_pacing_dialect(&self, dialect: PacingDialectV1, target_concurrency: u32) {
        *self.dialect.lock() = (dialect, target_concurrency.max(1));
    }

    /// Remaining known origin cooldown; dispatch can defer the row without holding capacity.
    #[must_use]
    pub fn cooldown_remaining(&self, origin: &Origin) -> Duration {
        self.origin_cap.cooldown_remaining(origin)
    }

    /// Check committed deployment feedback before a URL occupies dispatch capacity.
    ///
    /// # Errors
    /// Returns a storage error instead of treating unknown shared eligibility as ready.
    pub async fn shared_cooldown_remaining(&self, origin: &Origin) -> Result<Duration, StoreError> {
        let remote = match &self.origin_cap.admission {
            Some(store) => store.cooldown_remaining(origin.as_str()).await?,
            None => Duration::ZERO,
        };
        if !remote.is_zero() {
            self.origin_cap.note_cooldown(origin, remote, false);
        }
        Ok(self.cooldown_remaining(origin))
    }

    /// Source dialects release runtime slots rather than sleeping through 429 retries.
    #[must_use]
    pub fn defers_source_throttle(&self) -> bool {
        self.dialect.lock().0 != PacingDialectV1::Native
    }

    fn state(&self, origin: &Origin) -> Arc<OriginState> {
        let mut map = self.origins.lock();
        if let Some(s) = map.get(origin) {
            return Arc::clone(s);
        }
        let s = Arc::new(OriginState {
            sem: Arc::new(Semaphore::new(self.cfg.max_in_flight_per_origin.max(1))),
            pacing: Mutex::new(Pacing {
                next_allowed: Instant::now(),
                delay: self.cfg.base_delay,
                floor: self.cfg.base_delay,
                ok_streak: 0,
                last_start: None,
            }),
        });
        map.insert(origin.clone(), Arc::clone(&s));
        s
    }

    /// Reserve run-local and shared origin capacity before taking run-global
    /// capacity, so a saturated origin does not block unrelated origins. Then wait
    /// for the origin and rate-bucket starts and admit an actual shared start.
    /// Dropping this future or the returned permit releases all capacity.
    /// The complete wait is observed in `crawlx.fetch.origin_wait`.
    ///
    /// A permit handed out less than `base_delay` after the origin's previous one, or
    /// while more than `max_in_flight_per_origin` permits are live for the origin, is
    /// counted in `crawlx.fetch.politeness_violations` (the permit is still granted).
    ///
    /// # Errors
    /// Returns a storage error when deployment admission is unavailable.
    pub async fn acquire(&self, origin: &Origin) -> Result<Permit, StoreError> {
        self.acquire_spaced(origin, Duration::ZERO).await
    }

    /// Prepare a browser effect with at least 500 ms of process-local spacing.
    ///
    /// Call [`Permit::commit_dispatch`] immediately before the effect. Until then,
    /// no later same-origin start passes this process's shared admission queue.
    /// Dropping an uncommitted permit leaves local spacing clocks unchanged.
    /// Deployment admission and rate windows still charge reservation time.
    ///
    /// # Errors
    /// Returns a storage error when deployment admission is unavailable.
    pub async fn acquire_browser(&self, origin: &Origin) -> Result<Permit, StoreError> {
        self.acquire_spaced(origin, Duration::from_millis(500)).await
    }

    async fn acquire_spaced(&self, origin: &Origin, minimum: Duration) -> Result<Permit, StoreError> {
        let waited_from = Instant::now();
        let state = self.state(origin);
        let slot = Arc::clone(&state.sem).acquire_owned().await.ok();
        // Do not spend run-global slots while this origin is saturated locally
        // or in another worker. Unrelated origins must remain able to progress.
        let (origin_cap, mut deployment) = self.origin_cap.reserve(origin).await?;
        let start = {
            let now = Instant::now();
            // Held across the bucket reservations so a second same-origin caller sees the
            // bucket-delayed start, never the pre-bucket one (lock order: pacing → bucket).
            let mut p = state.pacing.lock();
            let origin_start = now.max(p.next_allowed);
            let start = origin_start
                .max(self.global.reserve(origin_start))
                .max(self.hosts.reserve(origin.host(), origin_start));
            if minimum.is_zero() {
                p.next_allowed = start.checked_add(p.delay).ok_or_else(|| {
                    StoreError::Conflict("origin spacing exceeds monotonic clock range".into())
                })?;
            }
            start
        };
        tokio::time::sleep_until(start).await;
        let spacing = state.pacing.lock().delay.max(minimum);
        let (global, turn) = self
            .origin_cap
            .start(origin, spacing, &mut deployment, &self.concurrency)
            .await?;
        Metrics::global()
            .histogram(names::FETCH_ORIGIN_WAIT)
            .observe_duration(waited_from.elapsed(), &[]);
        let browser_dispatch = if minimum.is_zero() {
            *self.origin_cap.state(origin).pacing.lock() = Some((Instant::now(), spacing));
            self.record_start(&state);
            drop(turn);
            None
        } else {
            Some(BrowserDispatch {
                state,
                shared: self.origin_cap.state(origin),
                spacing,
                _turn: turn,
            })
        };
        Ok(Permit {
            _slot: slot,
            _global: Some(global),
            _origin_cap: origin_cap,
            _deployment: deployment,
            browser_dispatch,
        })
    }

    /// Note that a permit is handed out now; count a politeness violation when it comes
    /// sooner than the origin's spacing floor after its previous permit or while the origin's
    /// in-flight cap is exceeded.
    fn record_start(&self, state: &OriginState) {
        let cap = self.cfg.max_in_flight_per_origin.max(1);
        let live = cap.saturating_sub(state.sem.available_permits());
        let now = Instant::now();
        let mut p = state.pacing.lock();
        let too_soon = p.last_start.is_some_and(|last| now < last + p.floor);
        p.last_start = Some(now);
        drop(p);
        if too_soon || live > cap {
            Metrics::global()
                .counter(names::FETCH_POLITENESS_VIOLATIONS)
                .inc();
        }
    }

    /// Feed local response feedback into the sole governor.
    /// Production callers use [`Self::on_response_with_latency`] to commit shared cooldowns.
    fn on_response(&self, origin: &Origin, status: u16, retry_after: Option<Duration>) {
        let state = self.state(origin);
        let dialect = self.dialect.lock().0;
        match status {
            429 | 503 => {
                let python = dialect == PacingDialectV1::CrawleePythonThrottleV1 && status == 429;
                let delay = if python {
                    self.origin_cap
                        .note_cooldown(origin, retry_after.unwrap_or_default(), true)
                } else {
                    let jitter: f64 = self.rng.lock().gen_range(0.8..1.2);
                    let (current, floor) = {
                        let p = state.pacing.lock();
                        (p.delay, p.floor)
                    };
                    let doubled = current.saturating_mul(2);
                    let delay = Duration::try_from_secs_f64(doubled.as_secs_f64() * jitter)
                        .unwrap_or(Duration::MAX)
                        .min(self.cfg.max_delay)
                        .max(floor)
                        .max(current)
                        .max(retry_after.unwrap_or_default());
                    self.origin_cap.note_cooldown(origin, delay, false);
                    delay
                };
                let mut p = state.pacing.lock();
                if !python {
                    p.delay = delay.max(p.floor);
                }
                p.ok_streak = 0;
                if let Some(until) = Instant::now().checked_add(delay) {
                    p.next_allowed = p.next_allowed.max(until);
                }
            }
            200 if dialect != PacingDialectV1::ScrapyAutothrottleV1 => {
                let mut p = state.pacing.lock();
                p.ok_streak = p.ok_streak.saturating_add(1);
                if p.ok_streak >= self.cfg.decay_after {
                    p.ok_streak = 0;
                    p.delay = (p.delay / 2).max(p.floor);
                }
            }
            _ => {}
        }
    }

    /// Apply measured header latency and publish 429/503 feedback across workers.
    ///
    /// Scrapy uses `(old + latency / target) / 2`, clamped to configured spacing.
    /// Non-200 responses and explicit `dont_adjust_delay` never accelerate traffic.
    /// Retry-After is a floor, not jittered or capped by the ordinary delay maximum.
    ///
    /// # Errors
    /// Returns a storage error if deployment-wide cooldown cannot be recorded.
    pub async fn on_response_with_latency(
        &self,
        origin: &Origin,
        status: u16,
        retry_after: Option<Duration>,
        latency: Option<Duration>,
        dont_adjust_delay: bool,
    ) -> Result<(), StoreError> {
        self.on_response(origin, status, retry_after);
        let (dialect, target) = *self.dialect.lock();
        if dialect == PacingDialectV1::ScrapyAutothrottleV1 && !dont_adjust_delay {
            if let Some(latency) = latency {
                let state = self.state(origin);
                let mut p = state.pacing.lock();
                let proposal = (p.delay.saturating_add(latency / target) / 2)
                    .max(p.floor)
                    .min(self.cfg.max_delay.max(p.floor));
                if status == 200 || proposal >= p.delay {
                    p.delay = proposal;
                }
            }
        }
        if matches!(status, 429 | 503) || retry_after.is_some() {
            let python = dialect == PacingDialectV1::CrawleePythonThrottleV1 && status == 429;
            let minimum = if python {
                retry_after.unwrap_or_default()
            } else {
                self.current_delay(origin).max(retry_after.unwrap_or_default())
            };
            let remaining = self.origin_cap.publish_cooldown(origin, minimum, python).await?;
            let state = self.state(origin);
            let mut p = state.pacing.lock();
            if let Some(until) = Instant::now().checked_add(remaining) {
                p.next_allowed = p.next_allowed.max(until);
            }
        }
        Ok(())
    }

    /// Current spacing for `origin` (the base delay until adapted).
    #[must_use]
    pub fn current_delay(&self, origin: &Origin) -> Duration {
        self.state(origin).pacing.lock().delay
    }

    /// Apply `origin`'s `robots.txt` `Crawl-delay` (already capped by the robots policy):
    /// its spacing floor becomes `max(base_delay, crawl_delay)`. Back-off, success decay and
    /// latency feedback never take the spacing below that floor, and the next start waits
    /// until the floor has passed since the origin's previous one. The spacing handed to the
    /// process-wide cap and to deployment admission carries the floor too.
    ///
    /// Calling it again with the same value is a no-op. A lower value lowers the floor; an
    /// already adapted spacing then decays toward it as usual.
    pub fn set_crawl_delay(&self, origin: &Origin, crawl_delay: Duration) {
        let state = self.state(origin);
        let mut p = state.pacing.lock();
        let floor = self.cfg.base_delay.max(crawl_delay);
        if floor == p.floor {
            return;
        }
        p.floor = floor;
        p.delay = p.delay.max(floor);
        if let Some(next) = p.last_start.and_then(|last| last.checked_add(floor)) {
            p.next_allowed = p.next_allowed.max(next);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::future::{poll_fn, Future};
    use std::task::Poll;

    fn origin(s: &str) -> Origin {
        Origin::new(s)
    }

    fn cfg() -> GovernorConfig {
        GovernorConfig {
            base_delay: Duration::from_millis(250),
            ..GovernorConfig::default()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn browser_dispatch_reanchors_spacing_after_slow_preparation() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://prepared.test");
        let mut first = g.acquire_browser(&o).await.unwrap();
        tokio::time::advance(Duration::from_millis(600)).await;
        first.commit_dispatch().unwrap();
        let dispatched = Instant::now();
        drop(first);
        let mut second = g.acquire_browser(&o).await.unwrap();
        second.commit_dispatch().unwrap();
        assert_eq!(dispatched.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_browser_preparation_preserves_only_committed_spacing() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://stale-preparation.test");
        let started = Instant::now();
        let mut first = g.acquire_browser(&o).await.unwrap();
        first.commit_dispatch().unwrap();
        drop(first);
        tokio::time::advance(Duration::from_millis(500)).await;
        let stale = g.acquire_browser(&o).await.unwrap();
        drop(stale);
        let mut reconstructed = g.acquire_browser(&o).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_millis(500));
        reconstructed.commit_dispatch().unwrap();
        drop(reconstructed);
        let mut next = g.acquire_browser(&o).await.unwrap();
        assert_eq!(started.elapsed(), Duration::from_millis(1000));
        next.commit_dispatch().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn browser_preparation_holds_shared_start_turn_with_spare_capacity() {
        let shared = Arc::new(GlobalOriginCap::new(2));
        let first = OriginGovernor::with_global_cap(cfg(), Arc::clone(&shared));
        let second = OriginGovernor::with_global_cap(cfg(), shared);
        let o = origin("https://prepared-shared.test");
        let mut prepared = first.acquire_browser(&o).await.unwrap();
        let waiting = second.acquire_browser(&o);
        tokio::pin!(waiting);
        assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
        tokio::time::advance(Duration::from_millis(600)).await;
        assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
        prepared.commit_dispatch().unwrap();
        let dispatched = Instant::now();
        // Retain the first in-flight permit: capacity two must not weaken spacing.
        let mut next = waiting.await.unwrap();
        next.commit_dispatch().unwrap();
        assert_eq!(dispatched.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn browser_preparation_keeps_interleaved_http_behind_dispatch_spacing() {
        let shared = Arc::new(GlobalOriginCap::new(2));
        let browser = OriginGovernor::with_global_cap(cfg(), Arc::clone(&shared));
        let http = OriginGovernor::with_global_cap(cfg(), shared);
        let o = origin("https://prepared-http.test");
        let mut prepared = browser.acquire_browser(&o).await.unwrap();
        let waiting = http.acquire(&o);
        tokio::pin!(waiting);
        assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
        tokio::time::advance(Duration::from_millis(600)).await;
        assert!(poll_fn(|cx| Poll::Ready(waiting.as_mut().poll(cx).is_pending())).await);
        prepared.commit_dispatch().unwrap();
        let dispatched = Instant::now();
        let _http = waiting.await.unwrap();
        assert_eq!(dispatched.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn scrapy_latency_mean_never_accelerates_non_200_or_ignored_samples() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://scrapy.test");
        g.set_pacing_dialect(PacingDialectV1::ScrapyAutothrottleV1, 2);
        g.on_response_with_latency(&o, 200, None, Some(Duration::from_secs(1)), false)
            .await
            .unwrap();
        assert_eq!(g.current_delay(&o), Duration::from_millis(375));
        g.on_response_with_latency(&o, 500, None, Some(Duration::ZERO), false)
            .await
            .unwrap();
        assert_eq!(g.current_delay(&o), Duration::from_millis(375));
        g.on_response_with_latency(&o, 200, None, Some(Duration::ZERO), true)
            .await
            .unwrap();
        assert_eq!(g.current_delay(&o), Duration::from_millis(375));
    }

    #[tokio::test(start_paused = true)]
    async fn python_429_wave_coalesces_and_retry_after_is_never_shortened() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://python.test");
        g.set_pacing_dialect(PacingDialectV1::CrawleePythonThrottleV1, 1);
        for _ in 0..20 {
            g.on_response_with_latency(&o, 429, None, None, false)
                .await
                .unwrap();
        }
        assert_eq!(g.cooldown_remaining(&o), Duration::from_secs(2));
        assert_eq!(
            g.current_delay(&o),
            Duration::from_millis(250),
            "cooldown is not permanent spacing"
        );
        tokio::time::advance(Duration::from_secs(2)).await;
        g.on_response_with_latency(&o, 429, None, None, false)
            .await
            .unwrap();
        assert_eq!(g.cooldown_remaining(&o), Duration::from_secs(4));
        g.on_response_with_latency(&o, 429, Some(Duration::from_secs(120)), None, false)
            .await
            .unwrap();
        g.on_response_with_latency(&o, 200, None, Some(Duration::ZERO), false)
            .await
            .unwrap();
        assert_eq!(g.cooldown_remaining(&o), Duration::from_secs(120));
    }

    #[tokio::test(start_paused = true)]
    async fn python_quiet_window_resets_the_next_wave_to_two_seconds() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://quiet.test");
        g.set_pacing_dialect(PacingDialectV1::CrawleePythonThrottleV1, 1);
        g.on_response_with_latency(&o, 429, None, None, false)
            .await
            .unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        g.on_response_with_latency(&o, 429, None, None, false)
            .await
            .unwrap();
        assert_eq!(g.cooldown_remaining(&o), Duration::from_secs(4));
        tokio::time::advance(Duration::from_secs(8)).await;
        g.on_response_with_latency(&o, 429, None, None, false)
            .await
            .unwrap();
        assert_eq!(g.cooldown_remaining(&o), Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn cooldown_from_one_governor_blocks_another_without_blocking_other_origins() {
        let shared = Arc::new(GlobalOriginCap::new(4));
        let a = OriginGovernor::with_global_cap(cfg(), shared.clone());
        let b = Arc::new(OriginGovernor::with_global_cap(
            GovernorConfig {
                max_concurrency: 1,
                ..cfg()
            },
            shared,
        ));
        let cooling = origin("https://cooling.test");
        a.on_response_with_latency(&cooling, 429, Some(Duration::from_secs(10)), None, false)
            .await
            .unwrap();
        let task_governor = b.clone();
        let waiting = tokio::spawn(async move { task_governor.acquire(&cooling).await.unwrap() });
        tokio::task::yield_now().await;
        let started = Instant::now();
        drop(b.acquire(&origin("https://ready.test")).await.unwrap());
        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(!waiting.is_finished());
        tokio::time::advance(Duration::from_secs(10)).await;
        drop(waiting.await.unwrap());
    }

    #[tokio::test(start_paused = true)]
    async fn spaces_request_starts_by_base_delay() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://a.test");
        let t0 = Instant::now();
        let p1 = g.acquire(&o).await.unwrap();
        assert_eq!(t0.elapsed(), Duration::ZERO);
        drop(p1);
        let p2 = g.acquire(&o).await.unwrap();
        assert_eq!(t0.elapsed(), Duration::from_millis(250));
        drop(p2);
        let _p3 = g.acquire(&o).await.unwrap();
        assert_eq!(t0.elapsed(), Duration::from_millis(500));
    }

    #[tokio::test(start_paused = true)]
    async fn origins_are_independent() {
        let g = OriginGovernor::new(cfg());
        let t0 = Instant::now();
        let _a = g.acquire(&origin("https://a.test")).await.unwrap();
        let _b = g.acquire(&origin("https://b.test")).await.unwrap();
        assert_eq!(t0.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn in_flight_limit_blocks_until_permit_dropped() {
        let g = Arc::new(OriginGovernor::new(GovernorConfig {
            base_delay: Duration::ZERO,
            ..cfg()
        }));
        let o = origin("https://a.test");
        let p1 = g.acquire(&o).await.unwrap();
        let g2 = Arc::clone(&g);
        let o2 = o.clone();
        let waiter = tokio::spawn(async move {
            let _p = g2.acquire(&o2).await.unwrap();
            Instant::now()
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!waiter.is_finished());
        let released_at = Instant::now();
        drop(p1);
        let got = waiter.await.unwrap();
        assert!(got >= released_at);
    }

    #[tokio::test(start_paused = true)]
    async fn doubles_on_429_up_to_cap_and_decays_on_success() {
        let g = OriginGovernor::new(GovernorConfig {
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(1),
            decay_after: 2,
            ..GovernorConfig::default()
        });
        let o = origin("https://a.test");
        assert_eq!(g.current_delay(&o), Duration::from_millis(250));
        g.on_response(&o, 429, None);
        let d1 = g.current_delay(&o);
        assert!(
            d1 >= Duration::from_millis(400) && d1 <= Duration::from_millis(600),
            "{d1:?}"
        );
        for _ in 0..8 {
            g.on_response(&o, 503, None);
        }
        assert_eq!(g.current_delay(&o), Duration::from_secs(1));
        g.on_response(&o, 200, None);
        assert_eq!(g.current_delay(&o), Duration::from_secs(1));
        g.on_response(&o, 200, None);
        assert_eq!(g.current_delay(&o), Duration::from_millis(500));
        for _ in 0..20 {
            g.on_response(&o, 200, None);
        }
        assert_eq!(g.current_delay(&o), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn throttle_response_pushes_next_start_out() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://a.test");
        let t0 = Instant::now();
        drop(g.acquire(&o).await.unwrap());
        g.on_response(&o, 429, Some(Duration::from_secs(10)));
        let _p = g.acquire(&o).await.unwrap();
        let waited = t0.elapsed();
        assert!(waited >= Duration::from_secs(8), "{waited:?}");
        assert!(waited <= Duration::from_secs(12), "{waited:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn crawl_delay_spaces_the_origin_from_its_previous_start() {
        let g = OriginGovernor::new(cfg());
        let o = origin("https://slow.test");
        let t0 = Instant::now();
        // the robots.txt fetch itself, before its Crawl-delay is known
        drop(g.acquire(&o).await.unwrap());
        g.set_crawl_delay(&o, Duration::from_secs(2));
        drop(g.acquire(&o).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::from_secs(2));
        drop(g.acquire(&o).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::from_secs(4));
        // other origins keep the configured base delay
        let other = origin("https://fast.test");
        let t1 = Instant::now();
        drop(g.acquire(&other).await.unwrap());
        drop(g.acquire(&other).await.unwrap());
        assert_eq!(t1.elapsed(), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn crawl_delay_is_a_floor_for_backoff_decay_and_latency_feedback() {
        let g = OriginGovernor::new(GovernorConfig {
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(1),
            decay_after: 2,
            ..GovernorConfig::default()
        });
        let o = origin("https://floor.test");
        // a hint below the configured delay never accelerates
        g.set_crawl_delay(&o, Duration::from_millis(100));
        assert_eq!(g.current_delay(&o), Duration::from_millis(250));
        g.set_crawl_delay(&o, Duration::from_secs(3));
        assert_eq!(g.current_delay(&o), Duration::from_secs(3));
        // back-off above max_delay is not capped below the floor
        g.on_response(&o, 429, None);
        let backed_off = g.current_delay(&o);
        assert!(backed_off >= Duration::from_secs(3), "{backed_off:?}");
        for _ in 0..20 {
            g.on_response(&o, 200, None);
        }
        assert_eq!(g.current_delay(&o), Duration::from_secs(3));
        g.set_pacing_dialect(PacingDialectV1::ScrapyAutothrottleV1, 1);
        g.on_response_with_latency(&o, 200, None, Some(Duration::ZERO), false)
            .await
            .unwrap();
        assert_eq!(g.current_delay(&o), Duration::from_secs(3));
        // a lower hint from a refreshed robots.txt lets the spacing decay to it
        g.set_pacing_dialect(PacingDialectV1::Native, 1);
        g.set_crawl_delay(&o, Duration::ZERO);
        for _ in 0..20 {
            g.on_response(&o, 200, None);
        }
        assert_eq!(g.current_delay(&o), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn crawl_delay_reaches_governors_sharing_the_origin_cap() {
        let shared = Arc::new(GlobalOriginCap::new(4));
        let learned = OriginGovernor::with_global_cap(cfg(), Arc::clone(&shared));
        let other = OriginGovernor::with_global_cap(cfg(), shared);
        let o = origin("https://shared-delay.test");
        learned.set_crawl_delay(&o, Duration::from_secs(2));
        let t0 = Instant::now();
        drop(learned.acquire(&o).await.unwrap());
        drop(other.acquire(&o).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::from_secs(2));
    }

    /// Serializes the tests that assert deltas of the process-global violation counter.
    static VIOLATIONS_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn violations() -> u64 {
        Metrics::global()
            .counter(names::FETCH_POLITENESS_VIOLATIONS)
            .get(&[])
    }

    #[tokio::test(start_paused = true)]
    async fn paced_sequential_acquires_are_not_violations() {
        let _guard = VIOLATIONS_LOCK.lock().await;
        let before = violations();
        let g = OriginGovernor::new(cfg());
        let o = origin("https://paced.test");
        drop(g.acquire(&o).await.unwrap());
        drop(g.acquire(&o).await.unwrap());
        let _p = g.acquire(&o).await.unwrap();
        assert_eq!(violations(), before);
    }

    /// Two callers of one origin queued behind a full global bucket must still be spaced
    /// by `base_delay` from the bucket-delayed start: the origin slot is reserved under
    /// the same lock as the bucket slot, so the second permit is not a violation.
    #[tokio::test(start_paused = true)]
    async fn bucket_pushback_keeps_origin_spacing() {
        let _guard = VIOLATIONS_LOCK.lock().await;
        let before = violations();
        let g = Arc::new(OriginGovernor::new(GovernorConfig {
            base_delay: Duration::from_millis(250),
            max_in_flight_per_origin: 2,
            global_rps: Some(2),
            ..GovernorConfig::default()
        }));
        let t0 = Instant::now();
        // fill this second's global budget from two other origins
        drop(g.acquire(&origin("https://b.test")).await.unwrap());
        drop(g.acquire(&origin("https://c.test")).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::ZERO);
        let o = origin("https://a.test");
        let (g1, g2) = (Arc::clone(&g), Arc::clone(&g));
        let (o1, o2) = (o.clone(), o.clone());
        let first = tokio::spawn(async move {
            let _p = g1.acquire(&o1).await.unwrap();
            Instant::now()
        });
        let second = tokio::spawn(async move {
            let _p = g2.acquire(&o2).await.unwrap();
            Instant::now()
        });
        let (s1, s2) = (first.await.unwrap(), second.await.unwrap());
        assert_eq!(s1, t0 + Duration::from_secs(1));
        assert!(s2 >= s1 + Duration::from_millis(250), "{s1:?} {s2:?}");
        assert_eq!(violations(), before);
    }

    #[test]
    fn origin_from_url_elides_default_port() {
        let u = url::Url::parse("HTTPS://Example.COM:443/x?y=1").unwrap();
        assert_eq!(Origin::from_url(&u).as_str(), "https://example.com");
        let u = url::Url::parse("http://example.com:8080/").unwrap();
        assert_eq!(Origin::from_url(&u).as_str(), "http://example.com:8080");
    }

    #[test]
    fn jitter_is_deterministic_per_seed() {
        let run = |seed| {
            let g = OriginGovernor::new(GovernorConfig {
                seed: CrawlSeed(seed),
                ..GovernorConfig::default()
            });
            let o = origin("https://a.test");
            g.on_response(&o, 429, None);
            g.current_delay(&o)
        };
        assert_eq!(run(1), run(1));
        assert_ne!(run(1), run(2));
    }

    #[test]
    fn origin_host_strips_scheme_and_port() {
        assert_eq!(origin("https://a.test").host(), "a.test");
        assert_eq!(origin("http://a.test:8080").host(), "a.test");
        assert_eq!(origin("http://[::1]:8080").host(), "[::1]");
        assert_eq!(origin("http://[::1]").host(), "[::1]");
    }

    /// Count starts in every half-open one-second window; none may exceed `limit`.
    fn assert_window_limit(starts: &[Duration], period: Duration, limit: usize) {
        for (i, s) in starts.iter().enumerate() {
            let in_window = starts[i..].iter().take_while(|t| **t < *s + period).count();
            assert!(in_window <= limit, "window at {s:?} holds {in_window} > {limit}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn global_rps_bounds_starts_per_second() {
        let g = OriginGovernor::new(GovernorConfig {
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 64,
            global_rps: Some(3),
            ..GovernorConfig::default()
        });
        let t0 = Instant::now();
        let mut starts = Vec::new();
        for i in 0..10 {
            let o = origin(&format!("https://h{}.test", i % 4));
            let _p = g.acquire(&o).await.unwrap();
            starts.push(t0.elapsed());
        }
        assert_eq!(starts[0], Duration::ZERO);
        assert_eq!(starts[2], Duration::ZERO);
        assert_eq!(starts[3], Duration::from_secs(1));
        assert_eq!(starts[9], Duration::from_secs(3));
        assert_window_limit(&starts, Duration::from_secs(1), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn global_rpm_bounds_starts_per_minute() {
        let g = OriginGovernor::new(GovernorConfig {
            base_delay: Duration::ZERO,
            global_rpm: Some(2),
            ..GovernorConfig::default()
        });
        let t0 = Instant::now();
        let o = origin("https://a.test");
        drop(g.acquire(&o).await.unwrap());
        drop(g.acquire(&o).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::ZERO);
        drop(g.acquire(&o).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::from_secs(60));
    }

    #[tokio::test(start_paused = true)]
    async fn per_host_rps_isolates_hosts() {
        let g = OriginGovernor::new(GovernorConfig {
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 64,
            per_host_rps: Some(1),
            ..GovernorConfig::default()
        });
        let t0 = Instant::now();
        let slow = origin("https://slow.test");
        let other = origin("https://other.test");
        // exhaust the slow host's budget for this second
        drop(g.acquire(&slow).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::ZERO);
        // the other host is not throttled by it
        drop(g.acquire(&other).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::ZERO);
        // http and https origins of one host share the host bucket
        drop(g.acquire(&origin("http://other.test:8080")).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::from_secs(1));
        drop(g.acquire(&slow).await.unwrap());
        assert_eq!(t0.elapsed(), Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_callers_never_share_a_bucket_slot() {
        let g = Arc::new(OriginGovernor::new(GovernorConfig {
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 64,
            max_concurrency: 64,
            global_rps: Some(2),
            ..GovernorConfig::default()
        }));
        let t0 = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for i in 0..6 {
            let g = Arc::clone(&g);
            tasks.spawn(async move {
                let _p = g.acquire(&origin(&format!("https://h{i}.test"))).await.unwrap();
                t0.elapsed()
            });
        }
        let mut starts = Vec::new();
        while let Some(r) = tasks.join_next().await {
            starts.push(r.unwrap());
        }
        starts.sort();
        assert_window_limit(&starts, Duration::from_secs(1), 2);
        assert_eq!(starts[5], Duration::from_secs(2));
    }

    #[tokio::test(start_paused = true)]
    async fn max_concurrency_caps_in_flight_across_origins() {
        let g = Arc::new(OriginGovernor::new(GovernorConfig {
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 8,
            max_concurrency: 2,
            ..GovernorConfig::default()
        }));
        let p1 = g.acquire(&origin("https://a.test")).await.unwrap();
        let _p2 = g.acquire(&origin("https://b.test")).await.unwrap();
        let g2 = Arc::clone(&g);
        let waiter = tokio::spawn(async move {
            let _p = g2.acquire(&origin("https://c.test")).await.unwrap();
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!waiter.is_finished());
        drop(p1);
        waiter.await.unwrap();
    }

    /// Two runs ("tenants") with eight in-flight slots each on one origin
    /// share one process-wide cap of four; the fifth caller queues and proceeds after a
    /// release instead of being rejected.
    #[tokio::test(start_paused = true)]
    async fn global_origin_cap_is_shared_across_governors_and_queues() {
        let cap = Arc::new(GlobalOriginCap::default());
        assert_eq!(cap.limit(), 4);
        let mk = || {
            Arc::new(OriginGovernor::with_global_cap(
                GovernorConfig {
                    base_delay: Duration::ZERO,
                    max_in_flight_per_origin: 8,
                    max_concurrency: 64,
                    ..GovernorConfig::default()
                },
                Arc::clone(&cap),
            ))
        };
        let (tenant_a, tenant_b) = (mk(), mk());
        let o = origin("https://shared.test");
        let mut held = Vec::new();
        for i in 0..4 {
            let g = if i % 2 == 0 { &tenant_a } else { &tenant_b };
            held.push(g.acquire(&o).await.unwrap());
        }
        assert_eq!(cap.available(&o), 0);
        let g2 = Arc::clone(&tenant_b);
        let o2 = o.clone();
        let fifth = tokio::spawn(async move {
            let _p = g2.acquire(&o2).await.unwrap();
            Instant::now()
        });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(
            !fifth.is_finished(),
            "the fifth connection must queue, not proceed"
        );
        // another origin is not affected by the shared.test queue
        let _other = tenant_a.acquire(&origin("https://other.test")).await.unwrap();
        let released_at = Instant::now();
        drop(held.remove(0));
        let got = fifth.await.unwrap();
        assert!(got >= released_at);
        // the fifth permit was dropped when its task returned; three are still held
        assert_eq!(cap.available(&o), 1);
        drop(held);
        assert_eq!(cap.available(&o), 4);
    }

    #[test]
    fn from_politeness_copies_rate_fields() {
        let p = Politeness {
            delay_ms: 100,
            max_in_flight_per_origin: 2,
            global_rps: Some(5),
            global_rpm: Some(100),
            per_host_rps: Some(2),
            per_host_rpm: Some(50),
            max_concurrency: 7,
        };
        let c = GovernorConfig::from_politeness(&p, CrawlSeed(1));
        assert_eq!(c.global_rps, Some(5));
        assert_eq!(c.global_rpm, Some(100));
        assert_eq!(c.per_host_rps, Some(2));
        assert_eq!(c.per_host_rpm, Some(50));
        assert_eq!(c.max_concurrency, 7);
        assert_eq!(c.base_delay, Duration::from_millis(100));
    }

    struct FailingAdmission {
        at_start: bool,
    }

    #[derive(Debug)]
    struct FailingPermit;

    #[async_trait::async_trait]
    impl OriginPermit for FailingPermit {
        async fn try_start(&mut self, _spacing: Duration) -> Result<Option<Duration>, StoreError> {
            Err(StoreError::Unavailable("admission unavailable".to_owned()))
        }
        async fn start(&mut self, _spacing: Duration) -> Result<(), StoreError> {
            Err(StoreError::Unavailable("admission unavailable".to_owned()))
        }
    }

    #[async_trait::async_trait]
    impl OriginAdmission for FailingAdmission {
        async fn reserve(&self, _origin: &str) -> Result<Box<dyn OriginPermit>, StoreError> {
            if self.at_start {
                Ok(Box::new(FailingPermit))
            } else {
                Err(StoreError::Unavailable("admission unavailable".to_owned()))
            }
        }
        async fn cooldown_remaining(&self, _origin: &str) -> Result<Duration, StoreError> {
            Err(StoreError::Unavailable("admission unavailable".to_owned()))
        }
        async fn cooldown(
            &self,
            _origin: &str,
            _minimum: Duration,
            _exponential: bool,
        ) -> Result<Duration, StoreError> {
            Err(StoreError::Unavailable("admission unavailable".to_owned()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn admission_failure_is_closed_and_releases_capacity_at_each_boundary() {
        for at_start in [false, true] {
            let cap = Arc::new(GlobalOriginCap::with_admission(
                1,
                Arc::new(FailingAdmission { at_start }),
            ));
            let governor = OriginGovernor::with_global_cap(
                GovernorConfig {
                    base_delay: Duration::ZERO,
                    max_concurrency: 1,
                    ..GovernorConfig::default()
                },
                Arc::clone(&cap),
            );
            let origin = origin("https://unavailable.test");
            for _ in 0..2 {
                let result = tokio::time::timeout(Duration::from_millis(1), governor.acquire(&origin))
                    .await
                    .unwrap();
                assert!(matches!(result, Err(StoreError::Unavailable(_))));
                assert_eq!(cap.available(&origin), 1);
            }
        }
    }
}
