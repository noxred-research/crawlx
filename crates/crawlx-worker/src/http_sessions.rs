//! Named, fenced HTTP sessions with one owned cookie jar and connection pool per generation.
//!
//! Registration is lazy and bounded. A caller must supply the existing live session binding
//! and revalidate its authority before every send. This module grants no lease, performs no
//! identity rotation, and never falls back from an unavailable name to another session.

use crawlx_core::request_controls::{ControlCookie, MAX_VALUE_LEN};
use crawlx_core::secret::SecretOr;
use crawlx_core::session_binding::{
    BindingState, RetirementReason, SessionBindingError, SessionBindingV1, SessionLimits,
};
use crawlx_core::{Clock, CrawlRunId, PrincipalId, TenantId, Timestamp};
use crawlx_fetch::redirect::{is_redirect, location, strip_credentials};
use crawlx_fetch::{FetchConfig, FetchError, FetchHop, FetchOptions, FetchResponse, Fetcher};
use crawlx_fetch::{Origin, OriginGovernor, Resolver};
use crawlx_policy::egress::EgressPolicy;
use http::{header, HeaderMap, HeaderValue};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use url::Url;

/// Name used only when a caller explicitly registers its default binding.
pub const DEFAULT_HTTP_SESSION: &str = "default";

/// Security namespace of a session manager. Names cannot cross this boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct HttpSessionOwner {
    /// Tenant owning all registered cookies and connections.
    pub tenant: TenantId,
    /// Run bounding session lifetime.
    pub run: CrawlRunId,
    /// Principal whose existing leases may be registered.
    pub principal: PrincipalId,
}

impl HttpSessionOwner {
    /// Construct an exact tenant/run/principal namespace.
    #[must_use]
    pub fn new(tenant: TenantId, run: CrawlRunId, principal: PrincipalId) -> Self {
        Self {
            tenant,
            run,
            principal,
        }
    }
}

/// Deployment ceilings, independent of request-supplied options.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct HttpSessionLimits {
    /// Maximum registered names, including retired tombstones.
    pub max_sessions: usize,
    /// Absolute age from registration, never renewed by use.
    pub max_age: Duration,
    /// Existing binding usage and health ceilings.
    pub binding: SessionLimits,
    /// Maximum cookies held by one session.
    pub max_cookies: usize,
    /// Ceiling for aggregate jar bytes and, separately, historical redaction-secret bytes.
    pub max_cookie_bytes: usize,
}

impl Default for HttpSessionLimits {
    fn default() -> Self {
        Self {
            max_sessions: 32,
            max_age: Duration::from_secs(30 * 60),
            binding: SessionLimits::default(),
            max_cookies: 64,
            max_cookie_bytes: 64 * 1024,
        }
    }
}

/// Fail-closed session error. No error permits replacing a jar implicitly.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpSessionError {
    /// A limit, name, rotating route or unshared governor is invalid.
    #[error("invalid HTTP session configuration")]
    Configuration,
    /// No registered name matches the requested binding and generation.
    #[error("session_unavailable")]
    Unavailable,
    /// A registered name or durable session slot already exists.
    #[error("http session name or slot collision")]
    Collision,
    /// Registered names already fill the deployment pool.
    #[error("http session pool is full")]
    PoolFull,
    /// Another request is using this jar; no second writer is admitted.
    #[error("http session is busy")]
    Busy,
    /// The fixed manager TTL elapsed.
    #[error("http session expired")]
    Expired,
    /// Existing strict binding validation failed.
    #[error(transparent)]
    Binding(#[from] SessionBindingError),
    /// Cookie count or byte bounds would be exceeded.
    #[error("http session cookie capacity exceeded")]
    CookieCapacity,
    /// Per-request Cookie overrides bypass owned session state.
    #[error("http session cookie override is not allowed")]
    CookieOverride,
    /// Preflight requires separate explicit session requests.
    #[error("http session preflight must be requested explicitly")]
    Preflight,
    /// A lazy client build previously failed and is not retried silently.
    #[error("http session startup failed")]
    StartupFailed,
    /// Checked transport or caller authority rejected the request.
    #[error(transparent)]
    Fetch(#[from] FetchError),
    /// Existing dynamic-secret registry refused registration.
    #[error("http session secret registration failed")]
    Secrets(#[from] crawlx_core::captcha::CaptchaError),
}

struct ClientRecipe {
    config: FetchConfig,
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolver>,
}

struct SessionEntry {
    binding: SessionBindingV1,
    expires_at: Timestamp,
    recipe: Option<ClientRecipe>,
    fetcher: Option<Arc<Fetcher>>,
    cookies: Vec<StoredCookie>,
    serial: Arc<Semaphore>,
    secret_bytes: usize,
    reservation: Option<SessionBindingV1>,
    persisted: bool,
}
/// Live existing-lease authority borrowed by production session sends.
///
/// Implementations recheck the original durable lease and binding. Verification
/// never grants or replaces a session or extends its admitted lifetime.
#[async_trait::async_trait]
pub trait HttpSessionAuthority: Send + Sync {
    /// Verify the original binding immediately before a checked transport send.
    ///
    /// During transport this is the exact persisted usage reservation. Its final
    /// permitted use may be draining for `UsageLimit`; verification still checks
    /// exact metadata revision, original live fence, authorization and expiry.
    ///
    /// # Errors
    /// Returns lease, authorization, storage or strict-binding failures without fallback.
    async fn verify(&self, binding: &SessionBindingV1) -> Result<(), FetchError>;

    /// Persist usage, health or lifecycle updates using the original fence and revision CAS.
    ///
    /// # Errors
    /// Returns lease, storage or revision conflicts; failed persistence never permits a send.
    async fn record_use(&self, before: &SessionBindingV1, after: &SessionBindingV1)
        -> Result<(), FetchError>;
}

/// Bounded named-session registry subordinate to existing session lease authority.
///
/// Each name owns a distinct lazily built `Fetcher`. Connection pools are never
/// shared between names. Retirement retains a bounded tombstone; registration
/// cannot resurrect that name or durable session slot with an empty jar.
#[non_exhaustive]
pub struct NamedHttpSessions {
    owner: HttpSessionOwner,
    limits: HttpSessionLimits,
    clock: Arc<dyn Clock>,
    governor: Arc<OriginGovernor>,
    secrets: crawlx_core::captcha::CaptchaSecrets,
    entries: Mutex<BTreeMap<String, SessionEntry>>,
}

impl std::fmt::Debug for NamedHttpSessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedHttpSessions")
            .field("owner", &self.owner)
            .field("limits", &self.limits)
            .field("registered", &self.entries.lock().len())
            .finish_non_exhaustive()
    }
}

impl NamedHttpSessions {
    /// Construct a registry using the already granted shared origin governor.
    ///
    /// # Errors
    /// Returns configuration error for zero, unrepresentable or unbounded limits.
    pub fn new(
        owner: HttpSessionOwner,
        limits: HttpSessionLimits,
        clock: Arc<dyn Clock>,
        governor: Arc<OriginGovernor>,
    ) -> Result<Self, HttpSessionError> {
        if limits.max_sessions == 0
            || limits.max_age.is_zero()
            || chrono::Duration::from_std(limits.max_age).is_err()
            || limits.binding.max_usage == 0
            || limits.binding.max_health_errors == 0
            || limits.max_cookies == 0
            || limits.max_cookie_bytes == 0
        {
            return Err(HttpSessionError::Configuration);
        }
        Ok(Self {
            owner,
            limits,
            clock,
            governor,
            secrets: crawlx_core::captcha::CaptchaSecrets::default(),
            entries: Mutex::new(BTreeMap::new()),
        })
    }

    /// Share the run's existing dynamic-secret registry before registering any names.
    ///
    /// # Errors
    /// Returns configuration error if registrations already exist.
    #[must_use = "the returned manager owns the shared secret registry"]
    pub fn with_secret_registry(
        mut self,
        secrets: crawlx_core::captcha::CaptchaSecrets,
    ) -> Result<Self, HttpSessionError> {
        if !self.entries.lock().is_empty() {
            return Err(HttpSessionError::Configuration);
        }
        self.secrets = secrets;
        Ok(self)
    }

    /// Register a granted binding without starting its HTTP client or doing I/O.
    ///
    /// Configured cookies become this generation's initial owned state. Registration
    /// requires the manager's exact governor and refuses per-request egress rotation.
    /// The caller must measure and approve config against binding identity before registration.
    ///
    /// # Errors
    /// Rejects foreign ownership, stale/expired bindings, duplicate names or slots,
    /// full pools, unshared governors, rotating routes and cookie bounds.
    pub fn register(
        &self,
        sid: &str,
        binding: SessionBindingV1,
        config: FetchConfig,
        policy: Arc<EgressPolicy>,
        resolver: Arc<dyn Resolver>,
    ) -> Result<(), HttpSessionError> {
        if sid.is_empty()
            || sid.len() > 128
            || !sid
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || !config
                .shared_governor
                .as_ref()
                .is_some_and(|g| Arc::ptr_eq(g, &self.governor))
            || config.pool.as_ref().is_some_and(|pool| pool.rotates_each())
        {
            return Err(HttpSessionError::Configuration);
        }
        self.check_owner(&binding)?;
        let now = self.clock.now();
        binding.eligible(&binding.identity, binding.lease_fence, now, self.limits.binding)?;
        // Volatile jars cannot be recreated for a generation that already performed work.
        if binding.generation == 0
            || binding.state_version == 0
            || binding.state_version == u64::MAX
            || binding.usage != 0
        {
            return Err(HttpSessionError::Unavailable);
        }
        let expires_at = now
            .checked_add_signed(
                chrono::Duration::from_std(self.limits.max_age)
                    .map_err(|_| HttpSessionError::Configuration)?,
            )
            .ok_or(HttpSessionError::Configuration)?
            .min(binding.expires_at);
        let mut cookies: Vec<_> = config
            .controls
            .cookies()
            .iter()
            .cloned()
            .map(|cookie| StoredCookie {
                cookie,
                host_only: false,
                secure: false,
                expires_at: None,
            })
            .collect();
        check_cookie_capacity(&cookies, self.limits)?;
        cookies.sort_by_key(|cookie| std::cmp::Reverse(cookie.cookie.path.len()));
        let secret_bytes = cookies.iter().fold(0_usize, |bytes, cookie| {
            bytes.saturating_add(cookie.cookie.value.expose().len().saturating_mul(4))
        });
        if secret_bytes > self.limits.max_cookie_bytes {
            return Err(HttpSessionError::CookieCapacity);
        }
        let mut entries = self.entries.lock();
        if entries.contains_key(sid)
            || entries
                .values()
                .any(|entry| entry.binding.identity.session == binding.identity.session)
        {
            return Err(HttpSessionError::Collision);
        }
        if entries.len() >= self.limits.max_sessions {
            return Err(HttpSessionError::PoolFull);
        }
        for cookie in &cookies {
            self.secrets.register(cookie.cookie.value.clone())?;
        }
        entries.insert(
            sid.to_owned(),
            SessionEntry {
                binding,
                expires_at,
                recipe: Some(ClientRecipe {
                    config,
                    policy,
                    resolver,
                }),
                fetcher: None,
                cookies,
                serial: Arc::new(Semaphore::new(1)),
                secret_bytes,
                reservation: None,
                persisted: true,
            },
        );
        Ok(())
    }

    /// Read metadata for a registered name, without starting a client or exposing cookies.
    ///
    /// # Errors
    /// Returns unavailable for missing names or foreign ownership.
    pub fn binding(&self, sid: &str) -> Result<SessionBindingV1, HttpSessionError> {
        let entries = self.entries.lock();
        let entry = entries.get(sid).ok_or(HttpSessionError::Unavailable)?;
        self.check_owner(&entry.binding)?;
        Ok(entry.binding.clone())
    }

    /// Read current counters under an exact identity, generation and fence.
    ///
    /// # Errors
    /// Returns unavailable for a name/identity/generation mismatch or lost fence.
    pub fn snapshot(
        &self,
        sid: &str,
        expected: &SessionBindingV1,
    ) -> Result<SessionBindingV1, HttpSessionError> {
        let entries = self.entries.lock();
        let entry = entries.get(sid).ok_or(HttpSessionError::Unavailable)?;
        self.check_identity(entry, expected)?;
        Ok(entry.binding.clone())
    }

    /// Retire explicitly after caller journal reconciliation and drop owned cookie/client state.
    ///
    /// Persists draining and confirmed owned-client cleanup under the original fence.
    /// In-flight sends prevent retirement; retired names remain collision tombstones.
    ///
    /// # Errors
    /// Rejects stale identity/generation/fence, active requests and revision overflow.
    pub async fn retire(
        &self,
        sid: &str,
        expected: &SessionBindingV1,
        reason: RetirementReason,
        authority: &dyn HttpSessionAuthority,
    ) -> Result<SessionBindingV1, HttpSessionError> {
        let (before, _permit) = {
            let entries = self.entries.lock();
            let entry = entries.get(sid).ok_or(HttpSessionError::Unavailable)?;
            self.check_identity(entry, expected)?;
            let permit = Arc::clone(&entry.serial)
                .try_acquire_owned()
                .map_err(|_| HttpSessionError::Busy)?;
            (entry.binding.clone(), permit)
        };
        let mut draining = before.clone();
        draining.begin_drain(reason)?;
        if draining != before {
            self.stage_binding(sid, &before, &draining)?;
            authority.record_use(&before, &draining).await?;
            self.confirm_binding(sid, &draining)?;
        }
        {
            let mut entries = self.entries.lock();
            let entry = entries.get_mut(sid).ok_or(HttpSessionError::Unavailable)?;
            entry.cookies.clear();
            entry.recipe = None;
            entry.fetcher = None;
            entry.reservation = None;
        }
        let mut retired = draining.clone();
        retired.finish_cleanup(true)?;
        self.stage_binding(sid, &draining, &retired)?;
        authority.record_use(&draining, &retired).await?;
        self.confirm_binding(sid, &retired)?;
        Ok(retired)
    }

    /// Fetch through one exact named generation, with live authority rechecked before every send.
    ///
    /// Redirects use the existing checked Fetcher, governor, retry and shared request
    /// allowance. Cookies are ingested before following each hop. Cross-origin transitions
    /// permanently suppress credentials for that chain. Caller cancellation/deadline should
    /// bound this borrowed future; dropping it charges a use and releases the single writer.
    /// Caller-supplied Cookie headers and implicit HEAD preflights are refused.
    ///
    /// # Errors
    /// Returns binding, TTL, pool, cookie, startup, authority or checked fetch failures.
    /// Concurrent use of the same session returns busy rather than choosing another jar.
    pub async fn fetch_with_authority<F, Fut>(
        &self,
        sid: &str,
        expected: &SessionBindingV1,
        url: &Url,
        options: &FetchOptions,
        check: &F,
        authority: &dyn HttpSessionAuthority,
    ) -> Result<FetchResponse, HttpSessionError>
    where
        F: Fn() -> Fut + Sync,
        Fut: Future<Output = Result<(), FetchError>> + Send,
    {
        self.fetch_inner(sid, expected, url, options, check, authority, true)
            .await
    }

    /// Send one checked attempt using the parent coordinator's retry and redirect budgets.
    ///
    /// # Errors
    /// Returns the same strict session, persistence and transport errors as [`Self::fetch_with_authority`].
    pub async fn fetch_once_with_authority<F, Fut>(
        &self,
        sid: &str,
        expected: &SessionBindingV1,
        url: &Url,
        options: &FetchOptions,
        check: &F,
        authority: &dyn HttpSessionAuthority,
    ) -> Result<FetchResponse, HttpSessionError>
    where
        F: Fn() -> Fut + Sync,
        Fut: Future<Output = Result<(), FetchError>> + Send,
    {
        self.fetch_inner(sid, expected, url, options, check, authority, false)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn fetch_inner<F, Fut>(
        &self,
        sid: &str,
        expected: &SessionBindingV1,
        url: &Url,
        options: &FetchOptions,
        check: &F,
        authority: &dyn HttpSessionAuthority,
        retry: bool,
    ) -> Result<FetchResponse, HttpSessionError>
    where
        F: Fn() -> Fut + Sync,
        Fut: Future<Output = Result<(), FetchError>> + Send,
    {
        if options.headers.contains_key(header::COOKIE) {
            return Err(HttpSessionError::CookieOverride);
        }
        if options.preflight.is_some() {
            return Err(HttpSessionError::Preflight);
        }
        let (fetcher, _use_guard) = self.begin(sid, expected)?;
        let before = self.snapshot(sid, expected)?;
        authority.verify(&before).await?;
        let mut reserved = before.clone();
        reserved.record_use(true, self.clock.now(), self.limits.binding)?;
        // Reservation charges usage, not health: cancellation is not a successful response.
        reserved.health_errors = before.health_errors;
        self.stage_binding(sid, &before, &reserved)?;
        authority.record_use(&before, &reserved).await?;
        self.confirm_binding(sid, &reserved)?;
        let started = Instant::now();
        let result = async {
            let mut current = url.clone();
            let mut hop_options = options.clone();
            hop_options.follow_redirects = false;
            let follow = options.follow_redirects && fetcher.config().follow_redirects;
            let max_redirects = options.max_redirects.unwrap_or(fetcher.config().max_redirects);
            let mut redirects = Vec::new();
            let mut hops = Vec::new();
            let mut attempts = 0_u32;
            let dispatch = || async {
                self.validate(sid, &reserved)
                    .map_err(|_| FetchError::AcquisitionUnavailable)?;
                authority.verify(&reserved).await?;
                check().await?;
                self.validate(sid, &reserved)
                    .map_err(|_| FetchError::AcquisitionUnavailable)
            };
            loop {
                self.validate(sid, &reserved)?;
                hop_options.headers.insert(
                    header::COOKIE,
                    self.cookie_header(sid, &reserved, &current, hop_options.suppress_credentials)?,
                );
                let fetched = if retry {
                    fetcher
                        .fetch_with_authority(&current, &hop_options, &dispatch)
                        .await
                } else {
                    fetcher
                        .fetch_once_with_authority(&current, &hop_options, &dispatch)
                        .await
                };
                self.validate(sid, &reserved)?;
                authority.verify(&reserved).await?;
                let mut response = fetched?;
                attempts = attempts
                    .checked_add(response.attempts)
                    .ok_or(FetchError::AcquisitionAllowance)?;
                self.store_cookies(sid, &reserved, &response.final_url, &response.headers)?;
                if follow && is_redirect(response.status.as_u16()) {
                    if redirects.len() >= max_redirects {
                        return Err(FetchError::TooManyRedirects { limit: max_redirects }.into());
                    }
                    let next = location(&current, &response.headers)?;
                    if Origin::from_url(&next) != Origin::from_url(&current) {
                        strip_credentials(&mut hop_options.headers);
                        hop_options.suppress_credentials = true;
                    }
                    hop_options.validators = None;
                    hop_options.suppress_validators = true;
                    redirects.push(current.to_string());
                    hops.push(FetchHop::observed(current, response.status, response.headers));
                    current = next;
                } else {
                    response.redirects = redirects;
                    response.hops = hops;
                    response.attempts = attempts;
                    response.duration = started.elapsed();
                    return Ok(response);
                }
            }
        }
        .await;
        let health_errors = match &result {
            Ok(response) if matches!(response.status.as_u16(), 401 | 403) => {
                before.health_errors.saturating_add(1)
            }
            Ok(response) if response.status.as_u16() == 429 => before.health_errors,
            Ok(_) => before.health_errors.saturating_sub(1),
            Err(_) => before.health_errors,
        };
        if health_errors != reserved.health_errors {
            let mut after = reserved.clone();
            after.health_errors = health_errors;
            after.state_version = after
                .state_version
                .checked_add(1)
                .ok_or(HttpSessionError::Unavailable)?;
            if health_errors >= self.limits.binding.max_health_errors && after.state == BindingState::Leased {
                after.state = BindingState::Draining;
                after.retirement = Some(RetirementReason::Unhealthy);
            }
            self.stage_binding(sid, &reserved, &after)?;
            authority.record_use(&reserved, &after).await?;
            self.confirm_binding(sid, &after)?;
        }
        result
    }

    fn stage_binding(
        &self,
        sid: &str,
        before: &SessionBindingV1,
        after: &SessionBindingV1,
    ) -> Result<(), HttpSessionError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(sid).ok_or(HttpSessionError::Unavailable)?;
        if entry.binding != *before || !entry.persisted {
            return Err(HttpSessionError::Unavailable);
        }
        if entry.reservation.is_none() {
            entry.reservation = Some(before.clone());
        }
        entry.binding = after.clone();
        // Unknown persistence outcomes remain unavailable, including cancellation during CAS.
        entry.persisted = false;
        Ok(())
    }

    fn confirm_binding(&self, sid: &str, expected: &SessionBindingV1) -> Result<(), HttpSessionError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(sid).ok_or(HttpSessionError::Unavailable)?;
        if entry.binding != *expected {
            return Err(HttpSessionError::Unavailable);
        }
        entry.persisted = true;
        Ok(())
    }

    fn check_owner(&self, binding: &SessionBindingV1) -> Result<(), HttpSessionError> {
        if binding.identity.tenant != self.owner.tenant
            || binding.identity.run != self.owner.run
            || binding.identity.principal != self.owner.principal
        {
            return Err(HttpSessionError::Unavailable);
        }
        Ok(())
    }

    fn check_identity(
        &self,
        entry: &SessionEntry,
        expected: &SessionBindingV1,
    ) -> Result<(), HttpSessionError> {
        self.check_owner(expected)?;
        if entry.binding.identity != expected.identity || entry.binding.generation != expected.generation {
            return Err(HttpSessionError::Unavailable);
        }
        if entry.binding.lease_fence != expected.lease_fence {
            return Err(SessionBindingError::LeaseLost.into());
        }
        Ok(())
    }

    fn check_entry(&self, entry: &SessionEntry, expected: &SessionBindingV1) -> Result<(), HttpSessionError> {
        self.check_identity(entry, expected)?;
        let now = self.clock.now();
        if entry.expires_at <= now {
            return Err(HttpSessionError::Expired);
        }
        if !entry.persisted {
            return Err(HttpSessionError::Unavailable);
        }
        entry.reservation.as_ref().unwrap_or(&entry.binding).eligible(
            &expected.identity,
            expected.lease_fence,
            now,
            self.limits.binding,
        )?;
        Ok(())
    }

    fn validate(&self, sid: &str, expected: &SessionBindingV1) -> Result<(), HttpSessionError> {
        let entries = self.entries.lock();
        self.check_entry(entries.get(sid).ok_or(HttpSessionError::Unavailable)?, expected)
    }

    fn begin<'a>(
        &'a self,
        sid: &'a str,
        expected: &SessionBindingV1,
    ) -> Result<(Arc<Fetcher>, SessionUse<'a>), HttpSessionError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(sid).ok_or(HttpSessionError::Unavailable)?;
        self.check_entry(entry, expected)?;
        let permit = Arc::clone(&entry.serial)
            .try_acquire_owned()
            .map_err(|_| HttpSessionError::Busy)?;
        if entry.fetcher.is_none() {
            let recipe = entry.recipe.take().ok_or(HttpSessionError::StartupFailed)?;
            // Ownership moves once. Even a failed build cannot silently create a fresh jar.
            entry.fetcher = Some(Arc::new(Fetcher::new(
                recipe.config,
                recipe.policy,
                recipe.resolver,
            )?));
        }
        let fetcher = Arc::clone(entry.fetcher.as_ref().ok_or(HttpSessionError::StartupFailed)?);
        Ok((
            fetcher,
            SessionUse {
                manager: self,
                sid,
                _permit: permit,
            },
        ))
    }

    fn cookie_header(
        &self,
        sid: &str,
        expected: &SessionBindingV1,
        url: &Url,
        suppress: bool,
    ) -> Result<HeaderValue, HttpSessionError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(sid).ok_or(HttpSessionError::Unavailable)?;
        self.check_entry(entry, expected)?;
        let now = self.clock.now();
        entry
            .cookies
            .retain(|cookie| cookie.expires_at.is_none_or(|expiry| expiry > now));
        let mut value = String::new();
        if !suppress {
            let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
            for stored in &entry.cookies {
                if stored.matches(&host, url.path(), url.scheme() == "https") {
                    if !value.is_empty() {
                        value.push_str("; ");
                    }
                    value.push_str(&stored.cookie.name);
                    value.push('=');
                    value.push_str(stored.cookie.value.expose());
                }
            }
        }
        let mut header = HeaderValue::from_str(&value).map_err(|_| FetchError::InvalidHeader {
            name: "cookie".to_owned(),
        })?;
        header.set_sensitive(true);
        Ok(header)
    }

    fn store_cookies(
        &self,
        sid: &str,
        expected: &SessionBindingV1,
        url: &Url,
        headers: &HeaderMap,
    ) -> Result<(), HttpSessionError> {
        let mut entries = self.entries.lock();
        let entry = entries.get_mut(sid).ok_or(HttpSessionError::Unavailable)?;
        self.check_entry(entry, expected)?;
        let now = self.clock.now();
        entry
            .cookies
            .retain(|cookie| cookie.expires_at.is_none_or(|expiry| expiry > now));
        for value in headers.get_all(header::SET_COOKIE) {
            if value.as_bytes().len() > MAX_VALUE_LEN {
                return Err(HttpSessionError::CookieCapacity);
            }
            let Some(cookie) = value
                .to_str()
                .ok()
                .and_then(|raw| StoredCookie::parse(raw, url, now))
            else {
                continue;
            };
            let index = entry.cookies.iter().position(|old| {
                old.cookie.name == cookie.cookie.name
                    && old.cookie.domain == cookie.cookie.domain
                    && old.cookie.path == cookie.cookie.path
            });
            // Plain HTTP cannot overwrite or delete an existing secure cookie.
            if url.scheme() != "https"
                && entry.cookies.iter().any(|old| {
                    old.secure
                        && old.cookie.name == cookie.cookie.name
                        && (old.cookie.matches(&cookie.cookie.domain, &cookie.cookie.path)
                            || cookie.cookie.matches(&old.cookie.domain, &old.cookie.path))
                })
            {
                continue;
            }
            if cookie.expires_at.is_some_and(|expiry| expiry <= now) {
                if let Some(index) = index {
                    entry.cookies.remove(index);
                }
                continue;
            }
            let old_bytes = index.map_or(0, |index| entry.cookies[index].bytes());
            let bytes = entry
                .cookies
                .iter()
                .map(StoredCookie::bytes)
                .sum::<usize>()
                .saturating_sub(old_bytes)
                .saturating_add(cookie.bytes());
            if bytes > self.limits.max_cookie_bytes
                || (index.is_none() && entry.cookies.len() >= self.limits.max_cookies)
            {
                return Err(HttpSessionError::CookieCapacity);
            }
            let changed = index.is_none_or(|index| {
                entry.cookies[index].cookie.value.expose() != cookie.cookie.value.expose()
            });
            if changed {
                let secret_bytes = entry
                    .secret_bytes
                    .saturating_add(cookie.cookie.value.expose().len().saturating_mul(4));
                if secret_bytes > self.limits.max_cookie_bytes {
                    return Err(HttpSessionError::CookieCapacity);
                }
                self.secrets.register(cookie.cookie.value.clone())?;
                entry.secret_bytes = secret_bytes;
            }
            if let Some(index) = index {
                entry.cookies[index] = cookie;
            } else {
                let position = entry
                    .cookies
                    .iter()
                    .position(|old| old.cookie.path.len() < cookie.cookie.path.len())
                    .unwrap_or(entry.cookies.len());
                entry.cookies.insert(position, cookie);
            }
        }
        Ok(())
    }
}

struct SessionUse<'a> {
    manager: &'a NamedHttpSessions,
    sid: &'a str,
    _permit: OwnedSemaphorePermit,
}

impl Drop for SessionUse<'_> {
    fn drop(&mut self) {
        let mut entries = self.manager.entries.lock();
        if let Some(entry) = entries.get_mut(self.sid) {
            // The durable usage reservation survives cancellation; only the active exemption ends.
            entry.reservation = None;
        }
    }
}

struct StoredCookie {
    cookie: ControlCookie,
    host_only: bool,
    secure: bool,
    expires_at: Option<Timestamp>,
}

impl StoredCookie {
    fn bytes(&self) -> usize {
        self.cookie
            .name
            .len()
            .saturating_add(self.cookie.value.expose().len())
            .saturating_add(self.cookie.domain.len())
            .saturating_add(self.cookie.path.len())
    }

    fn matches(&self, host: &str, path: &str, secure: bool) -> bool {
        (!self.host_only || self.cookie.domain == host)
            && (!self.secure || secure)
            && self.cookie.matches(host, path)
    }

    fn parse(raw: &str, url: &Url, now: Timestamp) -> Option<Self> {
        let host = url.host_str()?.trim_matches(['[', ']']).to_ascii_lowercase();
        let mut parts = raw.split(';');
        let (name, value) = parts.next()?.trim().split_once('=')?;
        let name = name.trim();
        let value = value
            .trim()
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value.trim());
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || !value.bytes().all(|byte| {
                byte == 0x21
                    || (0x23..=0x2b).contains(&byte)
                    || (0x2d..=0x3a).contains(&byte)
                    || (0x3c..=0x5b).contains(&byte)
                    || (0x5d..=0x7e).contains(&byte)
            })
        {
            return None;
        }
        let mut domain = host.clone();
        let mut path = default_cookie_path(url.path()).to_owned();
        let mut host_only = true;
        let mut secure = false;
        let mut expires_at = None;
        let mut max_age = None;
        for part in parts {
            let (attribute, value) = part.trim().split_once('=').unwrap_or((part.trim(), ""));
            match attribute.trim().to_ascii_lowercase().as_str() {
                "domain" => {
                    let candidate = value.trim().trim_start_matches('.').to_ascii_lowercase();
                    if candidate.is_empty()
                        || candidate.ends_with('.')
                        || host.parse::<std::net::IpAddr>().is_ok()
                        || (host != candidate
                            && !host.strip_suffix(&candidate).is_some_and(|p| p.ends_with('.')))
                        || crawlx_policy::scope::registrable_domain(&candidate).is_none()
                    {
                        return None;
                    }
                    domain = candidate;
                    host_only = false;
                }
                "path" if value.trim().starts_with('/') => path = value.trim().to_owned(),
                "secure" => secure = true,
                "max-age" => {
                    let value = value.trim();
                    if !value.is_empty()
                        && value
                            .trim_start_matches('-')
                            .bytes()
                            .all(|byte| byte.is_ascii_digit())
                    {
                        max_age = Some(value.parse::<i64>().unwrap_or(if value.starts_with('-') {
                            i64::MIN
                        } else {
                            i64::MAX
                        }));
                    }
                }
                "expires" => {
                    expires_at = chrono::DateTime::parse_from_rfc2822(value.trim())
                        .ok()
                        .map(|date| date.with_timezone(&chrono::Utc));
                }
                _ => {}
            }
        }
        if secure && url.scheme() != "https" {
            return None;
        }
        if name.starts_with("__Secure-") && !secure {
            return None;
        }
        if name.starts_with("__Host-") && (!secure || !host_only || path != "/") {
            return None;
        }
        if let Some(seconds) = max_age {
            expires_at = Some(if seconds <= 0 {
                now
            } else {
                chrono::Duration::try_seconds(seconds)
                    .and_then(|duration| now.checked_add_signed(duration))
                    .unwrap_or(Timestamp::MAX_UTC)
            });
        }
        Some(Self {
            cookie: ControlCookie {
                name: name.to_owned(),
                value: SecretOr::secret(value.to_owned()),
                domain,
                path,
            },
            host_only,
            secure,
            expires_at,
        })
    }
}

fn default_cookie_path(path: &str) -> &str {
    match path.rfind('/') {
        Some(index) if index > 0 => &path[..index],
        _ => "/",
    }
}

fn check_cookie_capacity(
    cookies: &[StoredCookie],
    limits: HttpSessionLimits,
) -> Result<(), HttpSessionError> {
    if cookies.len() > limits.max_cookies
        || cookies.iter().map(StoredCookie::bytes).sum::<usize>() > limits.max_cookie_bytes
    {
        return Err(HttpSessionError::CookieCapacity);
    }
    Ok(())
}

#[cfg(test)]
#[path = "http_sessions_tests.rs"]
mod tests;
