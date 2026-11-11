//! Production startup and commit of a retained structured browser profile through fenced custody.
//!
//! A named retained profile is cookie and web-storage state in the `browser_profiles` namespace,
//! encrypted under fresh durable key custody. Startup binds the exact [`ProfileScopeV1`] to the
//! session identity about to be bound (measured build, authorised egress, role), requires an
//! explicit non-zero generation to restore, acquires it through
//! [`CustodyProfiles::acquire`] (which registers every secret in the run-wide registry before it
//! releases a byte), mirrors those secrets into the run-local registry, and only then imports the
//! state into a context that was verified empty. The restore is not reported until the browser has
//! been read back: cookies are compared immediately, web storage once its origin has a document
//! ([`ProfileStart::confirm_web_storage`]). A store hit alone never marks a profile restored.
//!
//! No directory, global profile cipher, plaintext key or empty-storage fallback is involved. Any
//! missing capability fails closed with `profile_unavailable`.

use crate::actor::SessionHandle;
use crate::error::WorkerError;
use crate::run::RunContext;
use async_trait::async_trait;
use crawlx_core::browser::{BrowserContext, NavigationGuard, NavigationVerdict};
use crawlx_core::captcha::CaptchaSecrets;
use crawlx_core::custody::CustodyLease;
use crawlx_core::hash::Digest;
use crawlx_core::session_binding::SessionIdentityV1;
use crawlx_core::{BrowserError, SecretOr, SessionId, Timestamp};
use crawlx_storage::artifact_key_crypto::ArtifactKeys;
use crawlx_storage::custody::profiles::{CustodyProfileInspection, CustodyProfiles};
use crawlx_storage::custody::PgSecretAuthority;
use crawlx_storage::profiles::{ProfileScopeV1, SupportedStorageState};
use crawlx_storage::SessionLease;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const FIXITY_DOMAIN: &str = "crawlx/profile-restore-fixity/v1";
const IDENTITY_DOMAIN: &str = "crawlx/profile-identity/v1";

fn unavailable(message: &str) -> WorkerError {
    WorkerError::Config(format!("profile_unavailable: {message}"))
}

/// The two browser operations a restore needs. Implemented for every [`BrowserContext`]; a test
/// double only has to model these.
#[async_trait]
pub(crate) trait StorageSurface: Send {
    /// Apply a complete supported storage state.
    async fn import(&mut self, blob: &[u8]) -> Result<(), BrowserError>;
    /// Complete unredacted export of cookies and open-document web storage.
    async fn export_complete(&mut self) -> Result<Vec<u8>, BrowserError>;
}

#[async_trait]
impl<T: BrowserContext + ?Sized> StorageSurface for T {
    async fn import(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        self.import_storage(blob).await
    }

    async fn export_complete(&mut self) -> Result<Vec<u8>, BrowserError> {
        self.export_profile_storage().await
    }
}

/// Navigation guard confining a retained-profile context to its scope's origins. Install it in
/// the context configuration before the context is created so no document, request or
/// subresource outside the profile's origins is ever loaded with its credentials.
#[derive(Debug)]
struct OriginGuard {
    origins: BTreeSet<String>,
    inner: Option<Arc<dyn NavigationGuard>>,
}

impl OriginGuard {
    fn admits(&self, url: &url::Url) -> bool {
        self.origins.contains(&url.origin().ascii_serialization())
    }
}

const ORIGIN_BLOCKED: NavigationVerdict = NavigationVerdict::RobotsBlocked {
    reason: "profile_origin_binding",
};

#[async_trait]
impl NavigationGuard for OriginGuard {
    async fn check(&self, url: &url::Url) -> NavigationVerdict {
        if !self.admits(url) {
            return ORIGIN_BLOCKED;
        }
        match &self.inner {
            Some(inner) => inner.check(url).await,
            None => NavigationVerdict::Allow,
        }
    }

    async fn check_request(&self, url: &url::Url) -> NavigationVerdict {
        if !self.admits(url) {
            return ORIGIN_BLOCKED;
        }
        match &self.inner {
            Some(inner) => inner.check_request(url).await,
            None => NavigationVerdict::Allow,
        }
    }

    fn intercepts_subresources(&self) -> bool {
        true
    }

    async fn check_subresource(&self, url: &url::Url) -> NavigationVerdict {
        if !self.admits(url) {
            return ORIGIN_BLOCKED;
        }
        match &self.inner {
            Some(inner) => inner.check_subresource(url).await,
            None => NavigationVerdict::Allow,
        }
    }
}

/// Wrap `inner` so only `origins` are reachable. Use for the context configuration of a retained
/// profile session (`cfg.context.navigation_guard`), before the pooled context is acquired.
#[must_use]
pub(crate) fn origin_guard(
    origins: BTreeSet<String>,
    inner: Option<Arc<dyn NavigationGuard>>,
) -> Arc<dyn NavigationGuard> {
    Arc::new(OriginGuard { origins, inner })
}

type CookieKey = (String, String, String, String);
type WebKey = (String, bool, String);

/// Secret-free fixity view of a storage state: identities mapped to value digests only.
#[derive(Debug, Default)]
struct Snapshot {
    cookies: BTreeMap<CookieKey, Digest>,
    web: BTreeMap<WebKey, Digest>,
}

fn fixity(value: &str) -> Digest {
    Digest::of(FIXITY_DOMAIN, value.as_bytes())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, WorkerError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| unavailable("profile storage state malformed"))
}

fn entries<'a>(value: &'a Value, field: &str) -> Result<&'a [Value], WorkerError> {
    value
        .get(field)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| unavailable("profile storage state malformed"))
}

/// Parse a strict version-one export. `drop_expired` skips persistent cookies already past
/// `now` (Unix seconds), which a browser never retains and so can never be read back.
fn snapshot(bytes: &[u8], now: f64, drop_expired: bool) -> Result<Snapshot, WorkerError> {
    let document: Value =
        serde_json::from_slice(bytes).map_err(|_| unavailable("profile storage state malformed"))?;
    if document.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(unavailable("profile storage state version"));
    }
    let mut state = Snapshot::default();
    for cookie in entries(&document, "cookies")? {
        let persistent = cookie.get("session").and_then(Value::as_bool) == Some(false);
        let expires = cookie.get("expires").and_then(Value::as_f64).unwrap_or(-1.0);
        if drop_expired && persistent && expires > 0.0 && expires <= now {
            continue;
        }
        let partition = cookie
            .get("partitionKey")
            .and_then(|key| key.get("topLevelSite"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let key = (
            text(cookie, "domain")?.trim_start_matches('.').to_owned(),
            text(cookie, "path")?.to_owned(),
            text(cookie, "name")?.to_owned(),
            partition.to_owned(),
        );
        if state
            .cookies
            .insert(key, fixity(text(cookie, "value")?))
            .is_some()
        {
            return Err(unavailable("profile storage state has duplicate cookies"));
        }
    }
    for origin in entries(&document, "origins")? {
        let name = text(origin, "origin")?;
        for (field, session) in [("local", false), ("session", true)] {
            for pair in entries(origin, field)? {
                let pair = pair
                    .as_array()
                    .filter(|pair| pair.len() == 2)
                    .ok_or_else(|| unavailable("profile storage state malformed"))?;
                let (Some(key), Some(value)) = (pair[0].as_str(), pair[1].as_str()) else {
                    return Err(unavailable("profile storage state malformed"));
                };
                if state
                    .web
                    .insert((name.to_owned(), session, key.to_owned()), fixity(value))
                    .is_some()
                {
                    return Err(unavailable("profile storage state has duplicate web storage"));
                }
            }
        }
    }
    Ok(state)
}

/// Every application-controlled name and value of a supported state, into the run-local registry.
fn register_local(secrets: &CaptchaSecrets, bytes: &[u8]) -> Result<(), WorkerError> {
    let document: Value =
        serde_json::from_slice(bytes).map_err(|_| unavailable("profile storage state malformed"))?;
    let register = |value: &str| {
        secrets
            .register(SecretOr::secret(value.to_owned()))
            .map_err(|_| unavailable("run-local secret registry unavailable"))
    };
    for cookie in entries(&document, "cookies")? {
        register(text(cookie, "name")?)?;
        register(text(cookie, "value")?)?;
    }
    for origin in entries(&document, "origins")? {
        for field in ["local", "session"] {
            for pair in entries(origin, field)? {
                for item in pair.as_array().map(Vec::as_slice).unwrap_or_default() {
                    register(
                        item.as_str()
                            .ok_or_else(|| unavailable("profile storage state malformed"))?,
                    )?;
                }
            }
        }
    }
    Ok(())
}

async fn export<S: StorageSurface + ?Sized>(
    surface: &mut S,
) -> Result<zeroize::Zeroizing<Vec<u8>>, WorkerError> {
    surface
        .export_complete()
        .await
        .map(zeroize::Zeroizing::new)
        .map_err(|_| unavailable("browser complete storage export unavailable"))
}

/// A context may receive a profile only when it provably holds no cookie and no web storage.
async fn ensure_fresh<S: StorageSurface + ?Sized>(surface: &mut S) -> Result<(), WorkerError> {
    let current = snapshot(&export(surface).await?, 0.0, false)?;
    if current.cookies.is_empty() && current.web.is_empty() {
        Ok(())
    } else {
        Err(unavailable("browser context is not empty"))
    }
}

/// What a successful restore proved about the browser.
#[derive(Debug)]
struct Restored {
    expires_at: Timestamp,
    expected: Snapshot,
    web_confirmed: bool,
}

/// Register, import and read back one acquired state. Order is fixed: the run-local registry
/// holds every secret before the browser receives any, and the cookies must read back equal.
async fn apply_state<S: StorageSurface + ?Sized>(
    secrets: &CaptchaSecrets,
    bytes: &[u8],
    expires_at: Timestamp,
    now: f64,
    surface: &mut S,
) -> Result<Restored, WorkerError> {
    let expected = snapshot(bytes, now, true)?;
    register_local(secrets, bytes)?;
    surface
        .import(bytes)
        .await
        .map_err(|_| unavailable("browser storage import failed"))?;
    let applied = snapshot(&export(surface).await?, now, false)?;
    if applied.cookies != expected.cookies {
        return Err(unavailable("browser did not apply the restored cookies"));
    }
    let web_confirmed = expected.web.is_empty();
    Ok(Restored {
        expires_at,
        expected,
        web_confirmed,
    })
}

/// A generation held under custody and, once [`ProfileStart::apply`] ran, proven in the browser.
struct Acquired {
    state: SupportedStorageState,
    expires_at: Timestamp,
}

/// Outcome of startup for one session: custody claimed first (the session binding needs it),
/// state applied to the final context afterwards.
#[derive(Debug)]
pub(crate) struct ProfileStart {
    scope: ProfileScopeV1,
    generation: u64,
    acquired: Option<Acquired>,
    restored: Option<Restored>,
}

impl std::fmt::Debug for Acquired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acquired").finish_non_exhaustive()
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "second-resolution comparison; f64 holds every Unix second exactly"
)]
fn unix_seconds(now: Timestamp) -> f64 {
    now.timestamp() as f64
}

impl ProfileStart {
    /// Exact retained-profile namespace this session holds.
    #[cfg(test)]
    pub(crate) fn scope(&self) -> &ProfileScopeV1 {
        &self.scope
    }

    /// Generation held: the restored one, or zero for a new namespace.
    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether an existing generation was acquired and applied to the browser.
    #[cfg(test)]
    pub(crate) fn is_restored(&self) -> bool {
        self.restored.is_some()
    }

    /// Whether an acquired generation still has to be applied to the browser.
    pub(crate) fn apply_pending(&self) -> bool {
        self.acquired.is_some()
    }

    /// Apply the acquired generation to `surface`, a fresh context already confined by
    /// [`origin_guard`]. A new namespace (generation zero) applies nothing but still requires the
    /// context to be empty. Registers every secret in `secrets` before the browser sees any.
    ///
    /// # Errors
    /// Fails closed on a non-empty or non-exportable context, an import failure, or cookies that
    /// do not read back identical.
    pub(crate) async fn apply<S: StorageSurface + ?Sized>(
        &mut self,
        secrets: &CaptchaSecrets,
        now: Timestamp,
        surface: &mut S,
    ) -> Result<(), WorkerError> {
        ensure_fresh(surface).await?;
        let Some(acquired) = self.acquired.take() else {
            return Ok(());
        };
        self.restored = Some(
            apply_state(
                secrets,
                acquired.state.as_bytes(),
                acquired.expires_at,
                unix_seconds(now),
                surface,
            )
            .await?,
        );
        Ok(())
    }

    /// Fixed retention deadline of the restored generation. Acquisition never extends it; the
    /// session binding must not outlive it.
    pub(crate) fn expires_at(&self) -> Option<Timestamp> {
        self.acquired
            .as_ref()
            .map(|acquired| acquired.expires_at)
            .or_else(|| self.restored.as_ref().map(|restored| restored.expires_at))
    }

    /// `identity.profile` for the session binding. Present for an existing generation, which the
    /// binding verifier finds in `browser_profiles` under this session's lease once acquired.
    ///
    /// # Errors
    /// Fails if the identity cannot be encoded.
    pub(crate) fn profile_identity(&self) -> Result<Option<Digest>, WorkerError> {
        (self.acquired.is_some() || self.restored.is_some())
            .then(|| Digest::of_value(IDENTITY_DOMAIN, &(&self.scope, self.generation)))
            .transpose()
            .map_err(|error| WorkerError::Config(error.to_string()))
    }

    /// Whether restored web storage still awaits browser read-back. Import applies it to the
    /// documents of each origin, so it can only be observed after a navigation to that origin.
    pub(crate) fn web_storage_pending(&self) -> bool {
        self.restored
            .as_ref()
            .is_some_and(|restored| !restored.web_confirmed)
    }

    /// Read back restored web storage from a fresh strict export taken after the profile origin
    /// has a document (the first navigation of the session). Cookies were checked at import.
    ///
    /// # Errors
    /// Fails closed when the export is malformed or any restored entry is absent or different.
    pub(crate) fn confirm_web_storage(&mut self, exported: &[u8]) -> Result<(), WorkerError> {
        let Some(restored) = self.restored.as_mut() else {
            return Ok(());
        };
        let current = snapshot(exported, 0.0, false)?;
        if restored
            .expected
            .web
            .iter()
            .any(|(key, digest)| current.web.get(key) != Some(digest))
        {
            return Err(unavailable("browser did not apply the restored web storage"));
        }
        restored.web_confirmed = true;
        Ok(())
    }
}

/// Authorities and facts of one retained-profile session.
pub(crate) struct ProfileCustodyInputs {
    /// The run's shared secret authority.
    pub(crate) authority: Arc<PgSecretAuthority>,
    /// Durable artifact key provider.
    pub(crate) keys: Arc<dyn ArtifactKeys>,
    /// The session's scheduler lease.
    pub(crate) lease: SessionLease,
    /// The session's producer custody lease, carrying the hard-stop token.
    pub(crate) custody: CustodyLease,
    /// Run-local registry mirrored from every acquired secret.
    pub(crate) secrets: CaptchaSecrets,
    /// Validated public profile name.
    pub(crate) name: String,
    /// Canonical origins the profile may reach.
    pub(crate) origins: BTreeSet<String>,
    /// Whether the session commits its changes as the next generation.
    pub(crate) save_changes: bool,
    /// Deadline for a new namespace, within operator TTL and run retention.
    pub(crate) fresh_expiry: Timestamp,
}

/// Retained structured-profile service of one leased session.
pub(crate) struct ProfileCustodyRuntime {
    inputs: ProfileCustodyInputs,
}

impl std::fmt::Debug for ProfileCustodyRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileCustodyRuntime").finish_non_exhaustive()
    }
}

impl ProfileCustodyRuntime {
    /// Bind the given authorities, refusing any that is not durable or not this session's.
    ///
    /// # Errors
    /// `profile_unavailable` when keys are not durable or the custody lease is not exactly the
    /// session lease.
    pub(crate) fn new(inputs: ProfileCustodyInputs) -> Result<Self, WorkerError> {
        if !inputs.keys.is_available() || !inputs.keys.is_durable() {
            return Err(unavailable("durable profile key custody required"));
        }
        let lease = &inputs.lease;
        let custody = &inputs.custody;
        if custody.run != lease.session.run
            || custody.worker != lease.worker
            || custody.fence != lease.fencing_token
            || custody.source != crawlx_core::custody::CustodySource::Session(lease.session.id)
        {
            return Err(unavailable("producer custody lease is not this session's lease"));
        }
        Ok(Self { inputs })
    }

    /// Build from the run, the leased session and the ambient producer lease.
    ///
    /// # Errors
    /// `profile_unavailable` unless the run requests a retained profile, is not ZDR, has operator
    /// permission, PostgreSQL custody with durable keys, and runs under its producer lease.
    pub(crate) async fn from_run(rc: &RunContext, lease: &SessionLease) -> Result<Self, WorkerError> {
        let requested = rc
            .crawl
            .dynamic
            .browser_profile
            .as_ref()
            .ok_or_else(|| unavailable("profile not requested"))?;
        let policy = rc
            .retained_profiles
            .as_ref()
            .ok_or_else(|| unavailable("operator retained-profile policy missing"))?;
        if policy.max_ttl.is_zero() || policy.max_ttl > std::time::Duration::from_secs(86_400) {
            return Err(unavailable("operator profile TTL must be 1..=86400 seconds"));
        }
        if rc.crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr {
            return Err(unavailable("durable profiles forbidden under zdr"));
        }
        let (Some(authority), Some(keys)) = (
            rc.stores.pg_secret_authority.clone(),
            rc.stores.artifact_keys.clone(),
        ) else {
            return Err(unavailable("custody-enabled PostgreSQL required"));
        };
        let custody = crawlx_core::custody::current_producer()
            .ok_or_else(|| unavailable("session producer lease required"))?;
        let run = rc.stores.runs.get_metadata(rc.run).await?;
        let retention_end = run.created_at + chrono::Duration::days(i64::from(rc.crawl.retention.days));
        let ttl = i64::try_from(policy.max_ttl.as_secs()).map_err(|_| unavailable("profile TTL overflow"))?;
        Self::new(ProfileCustodyInputs {
            authority,
            keys,
            lease: lease.clone(),
            custody,
            secrets: rc.captcha_secrets.clone(),
            name: requested.name.clone(),
            origins: BTreeSet::from([rc.seed_origin()]),
            save_changes: requested.save_changes,
            fresh_expiry: (rc.clock.now() + chrono::Duration::seconds(ttl)).min(retention_end),
        })
    }

    /// Origins to confine the context to; pass to [`origin_guard`] when building the context.
    pub(crate) fn origins(&self) -> &BTreeSet<String> {
        &self.inputs.origins
    }

    /// Exact namespace for the session identity about to be bound.
    ///
    /// # Errors
    /// `profile_unavailable` when the identity is not this session's or the scope is invalid.
    pub(crate) fn scope(&self, identity: &SessionIdentityV1) -> Result<ProfileScopeV1, WorkerError> {
        let lease = &self.inputs.lease;
        if identity.tenant != self.inputs.custody.tenant
            || identity.run != lease.session.run
            || identity.session != lease.session.id
            || identity.principal != lease.session.role
        {
            return Err(unavailable("session identity is not this session's"));
        }
        ProfileScopeV1::new(
            identity.tenant,
            identity.principal.clone(),
            self.inputs.name.clone(),
            self.inputs.origins.clone(),
            identity.backend_build,
            identity.egress,
        )
        .map_err(WorkerError::from)
    }

    /// Claim `generation` of the exact namespace under custody. Registers every secret run-wide
    /// before releasing any byte, but applies nothing to a browser: the session binding needs this
    /// claim first, and the final context only exists after binding. Generation zero creates a new
    /// namespace; a non-zero generation that is absent, expired, foreign or incompatible fails.
    ///
    /// # Errors
    /// Fails closed on any custody refusal or an acquired profile that is not the requested one.
    pub(crate) async fn acquire(
        &self,
        identity: &SessionIdentityV1,
        generation: u64,
    ) -> Result<ProfileStart, WorkerError> {
        let scope = self.scope(identity)?;
        let acquired = CustodyProfiles::new(self.inputs.authority.as_ref(), self.inputs.keys.as_ref())
            .acquire(&self.inputs.lease, &self.inputs.custody, &scope, generation, true)
            .await?;
        let Some((inspection, state)) = acquired else {
            if generation != 0 {
                return Err(unavailable("requested profile generation unavailable"));
            }
            return Ok(ProfileStart {
                scope,
                generation: 0,
                acquired: None,
                restored: None,
            });
        };
        if inspection.scope != scope || inspection.generation != generation {
            return Err(unavailable("acquired profile is not the requested one"));
        }
        self.inputs.custody.check_local_cancellation()?;
        Ok(ProfileStart {
            scope,
            generation,
            acquired: Some(Acquired {
                state,
                expires_at: inspection.expires_at,
            }),
            restored: None,
        })
    }

    /// Commit the session's strict complete export as the next generation. `Ok(None)` when the
    /// run does not save changes. The caller must have stopped capture before exporting.
    ///
    /// # Errors
    /// Propagates every custody refusal: stale fence, conflicting generation, expiry, retention.
    pub(crate) async fn finish(
        &self,
        start: &ProfileStart,
        storage: &[u8],
    ) -> Result<Option<CustodyProfileInspection>, WorkerError> {
        if !self.inputs.save_changes {
            return Ok(None);
        }
        if start.apply_pending() {
            return Err(unavailable("acquired profile was never applied to the browser"));
        }
        if start.web_storage_pending() {
            return Err(unavailable(
                "restored web storage was never confirmed in the browser",
            ));
        }
        let expires_at = start.expires_at().unwrap_or(self.inputs.fresh_expiry);
        CustodyProfiles::new(self.inputs.authority.as_ref(), self.inputs.keys.as_ref())
            .commit(
                &self.inputs.lease,
                &self.inputs.custody,
                &start.scope,
                start.generation,
                expires_at,
                true,
                storage,
            )
            .await
            .map(Some)
            .map_err(WorkerError::from)
    }
}

/// One leased session's retained profile: its custody service and what it holds.
pub(crate) struct ProfileSession {
    runtime: ProfileCustodyRuntime,
    start: ProfileStart,
}

impl std::fmt::Debug for ProfileSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileSession").finish_non_exhaustive()
    }
}

impl ProfileSession {
    /// Pair a runtime with the claim it acquired.
    pub(crate) fn new(runtime: ProfileCustodyRuntime, start: ProfileStart) -> Self {
        Self { runtime, start }
    }

    /// Fixed retention deadline of the held generation, if one exists.
    pub(crate) fn expires_at(&self) -> Option<Timestamp> {
        self.start.expires_at()
    }

    /// Apply the claim to the session's final context, then keep the session for confirmation and
    /// commit.
    ///
    /// # Errors
    /// See [`ProfileStart::apply`].
    pub(crate) async fn apply<S: StorageSurface + ?Sized>(
        &mut self,
        now: Timestamp,
        surface: &mut S,
    ) -> Result<(), WorkerError> {
        self.start.apply(&self.runtime.inputs.secrets, now, surface).await
    }
}

/// Retained profiles of the run's sessions by session id. Entries are taken out for every await,
/// so the lock is never held across one.
pub(crate) type ProfileSessions = Arc<parking_lot::Mutex<BTreeMap<SessionId, ProfileSession>>>;

/// Prove restored web storage in the live browser once the seed document of the profile's origin
/// exists. A session without a retained profile, or one without web storage to restore, is a no-op.
///
/// # Errors
/// Fails closed (the session ends, nothing is committed) when the strict export is unavailable or
/// any restored entry is absent or different.
pub(crate) async fn confirm_seed(
    sessions: &ProfileSessions,
    session: SessionId,
    handle: &SessionHandle,
) -> Result<(), WorkerError> {
    let Some(mut held) = sessions.lock().remove(&session) else {
        return Ok(());
    };
    if held.start.web_storage_pending() {
        let exported = handle.export_profile_storage().await?;
        held.start.confirm_web_storage(&exported)?;
    }
    sessions.lock().insert(session, held);
    Ok(())
}

/// Export the live browser's complete state and commit it as the next generation. Call only after
/// the session ended successfully and before the actor shuts down. Raw state never leaves the
/// zeroizing buffer and is never logged. `Ok(None)` without a retained profile or `saveChanges`.
///
/// # Errors
/// Propagates export and custody refusals; the entry is consumed either way.
pub(crate) async fn commit(
    sessions: &ProfileSessions,
    session: SessionId,
    handle: &SessionHandle,
) -> Result<Option<u64>, WorkerError> {
    let Some(held) = sessions.lock().remove(&session) else {
        return Ok(None);
    };
    if !held.runtime.inputs.save_changes {
        return Ok(None);
    }
    let storage = handle.export_profile_storage().await?;
    let committed = held.runtime.finish(&held.start, &storage).await?;
    Ok(committed.map(|inspection| inspection.generation))
}

/// Drop a session's retained profile without committing (failure, cancellation, replay).
pub(crate) fn discard(sessions: &ProfileSessions, session: SessionId) {
    sessions.lock().remove(&session);
}

#[cfg(test)]
#[path = "profile_custody_runtime_tests.rs"]
mod tests;
