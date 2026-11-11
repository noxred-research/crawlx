//! Authenticated local interactive profile control over the existing session actor.
//!
//! This registry is deliberately process-local. An API must share this exact instance
//! with its local worker; a separate API process must report the capability unavailable.
//! Commands never contain executable scripts, raw input values, control-port addresses,
//! or screenshot bytes. The driver must revalidate its live lease and authorization
//! before acknowledging every command and must close the owned actor on cancellation.

use crawlx_core::secret::CredentialRef;
use crawlx_core::session_binding::{BindingState, SessionBindingV1};
use crawlx_core::{Clock, CrawlRunId, SessionId, TenantId, Timestamp};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub use crawlx_browser::screencast::{
    ScreencastError, ScreencastEvent, ScreencastObservation, ScreencastPublisher, ScreencastReceiver,
    ScreencastScope,
};

const MAILBOX: usize = 4;
const MAX_SESSIONS: usize = 128;
const MAX_TTL: u16 = 900;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

/// Exact authenticated local control identity; never a bearer capability by itself.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct InteractiveScope {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Owning crawl.
    pub run: CrawlRunId,
    /// Existing session slot.
    pub session: SessionId,
    /// Exact browser generation.
    pub generation: u64,
    /// Existing scheduler fence, not another ownership authority.
    pub lease_fence: i64,
    /// Authenticated API-key actor, not a caller-supplied owner.
    pub owner: String,
}

impl InteractiveScope {
    /// Bind authenticated ownership to a requested existing generation.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        session: SessionId,
        generation: u64,
        lease_fence: i64,
        owner: String,
    ) -> Self {
        Self {
            tenant,
            run,
            session,
            generation,
            lease_fence,
            owner,
        }
    }

    fn cast_scope(&self) -> ScreencastScope {
        ScreencastScope::new(
            self.tenant,
            self.run,
            self.session,
            self.generation,
            self.lease_fence,
            self.owner.clone(),
        )
    }
}

/// Explicit consent and bounded settings for a fresh local profile workflow.
#[derive(Clone, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct InteractiveStart {
    /// Safe profile name under the existing tenant/principal profile namespace.
    pub profile_name: String,
    /// Compare-and-swap generation; zero means create, never overwrite.
    pub expected_generation: u64,
    /// Lifetime in seconds, no greater than the existing binding deadline.
    pub ttl_seconds: u16,
    /// Explicit permission to retain the encrypted structured profile.
    pub retained_profile_consent: bool,
    /// Explicit permission to open a private, ephemeral capture channel.
    pub capture_consent: bool,
    /// Explicit acknowledgment of secret-screen suppression and privacy policy.
    pub privacy_consent: bool,
}

impl InteractiveStart {
    /// Reject ambiguous names, missing consent and unbounded lifetimes.
    ///
    /// # Errors
    /// Returns [`InteractiveError::Invalid`] for invalid input.
    pub fn validate(&self) -> Result<(), InteractiveError> {
        if self.profile_name.is_empty()
            || self.profile_name.len() > 128
            || !self
                .profile_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            || matches!(self.profile_name.as_str(), "." | "..")
            || self.ttl_seconds == 0
            || self.ttl_seconds > MAX_TTL
            || !self.retained_profile_consent
            || !self.privacy_consent
            || self.expected_generation == u64::MAX
        {
            return Err(InteractiveError::Invalid);
        }
        Ok(())
    }
}

/// Allowlisted operator input; secrets are references resolved inside the worker.
#[derive(Clone, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ProfileInput {
    /// Activate one freshly resolved, kernel-admitted candidate.
    Activate {
        /// Bounded CSS selector; not executable code.
        selector: String,
    },
    /// Fill a freshly resolved candidate after run-wide secret registration.
    TypeSecret {
        /// Bounded CSS selector.
        selector: String,
        /// Reference already approved for the owning run; no inline secret values.
        credential: CredentialRef,
    },
}

impl ProfileInput {
    /// The selector to resolve against a fresh actor observation.
    #[must_use]
    pub fn selector(&self) -> &str {
        match self {
            Self::Activate { selector } | Self::TypeSecret { selector, .. } => selector,
        }
    }

    /// Validate bounded declarative input before enqueuing it.
    ///
    /// # Errors
    /// Returns [`InteractiveError::Invalid`] for unbounded selectors/references.
    pub fn validate(&self) -> Result<(), InteractiveError> {
        let selector = self.selector();
        if selector.is_empty() || selector.len() > 2048 || selector.contains('\0') {
            return Err(InteractiveError::Invalid);
        }
        if let Self::TypeSecret { credential, .. } = self {
            if credential.0.is_empty() || credential.0.len() > 512 || credential.scheme().is_none() {
                return Err(InteractiveError::Invalid);
            }
        }
        Ok(())
    }
}

/// Truthful workflow state; no page text or secret value is exposed.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum InteractiveState {
    /// Registered fresh actor awaits explicit start.
    Available,
    /// Start is undergoing live worker validation.
    Starting,
    /// Operator controls are active; autonomous exploration is disabled.
    Active,
    /// Structured encrypted commit is in progress.
    Finishing,
    /// Encrypted structured state was committed and actor cleanup confirmed.
    Finished,
    /// Cancelled, expired, disconnected or failed; no further effects are allowed.
    Closed,
}

/// Structural status only; never a browser endpoint or profile content.
#[derive(Clone, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct InteractiveStatus {
    /// Current workflow state.
    pub state: InteractiveState,
    /// Fixed deadline, never extended by input or subscription.
    pub expires_at: Timestamp,
    /// New encrypted profile generation after a successful finish.
    pub committed_generation: Option<u64>,
    /// Browser pixels remain suppressed without a proven secret-free classifier.
    pub frames_suppressed: bool,
}

/// Fail-closed control errors. Messages never contain selectors or secret references.
#[derive(Clone, Copy, PartialEq, Eq, thiserror::Error, Debug)]
#[non_exhaustive]
pub enum InteractiveError {
    /// Wrong owner, tenant, run, generation, fence, missing or expired session.
    #[error("interactive session unavailable")]
    Unavailable,
    /// Invalid settings or missing explicit consent.
    #[error("invalid interactive control request")]
    Invalid,
    /// Another command is in flight or the bounded mailbox is full.
    #[error("interactive control is busy")]
    Busy,
    /// Actor rejected the command under its live safety/custody authority.
    #[error("interactive control refused")]
    Refused,
}

/// Reply generated only after the existing actor completes the requested boundary.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum InteractiveReply {
    /// Fresh isolated context and live ownership checks passed.
    Ready,
    /// Typed admitted input completed, or live status validation passed.
    Accepted,
    /// Custody commit and owned resource cleanup both completed.
    Committed {
        /// Actual compare-and-swap profile generation.
        generation: u64,
    },
}

/// Bounded actor-only command. Each receiver must recheck live authority before effects.
#[non_exhaustive]
pub enum InteractiveCommand {
    /// Validate fresh context, custody, origin policy and retained-profile permission.
    Start {
        /// Exact authenticated request scope.
        scope: InteractiveScope,
        /// Explicit operator consents and admitted profile settings.
        request: InteractiveStart,
        /// Complete only after worker preflight succeeds.
        reply: oneshot::Sender<Result<InteractiveReply, InteractiveError>>,
    },
    /// Revalidate live authority without browser effects.
    Inspect {
        /// Exact authenticated request scope.
        scope: InteractiveScope,
        /// Structural result only.
        reply: oneshot::Sender<Result<InteractiveReply, InteractiveError>>,
    },
    /// Resolve fresh candidate, classify, journal, confirm and execute typed input.
    Input {
        /// Exact authenticated request scope.
        scope: InteractiveScope,
        /// Bounded allowlisted input.
        input: ProfileInput,
        /// Complete only after actor execution terminates.
        reply: oneshot::Sender<Result<InteractiveReply, InteractiveError>>,
    },
    /// Export strict structured state, commit through custody and close owned resources.
    Finish {
        /// Exact authenticated request scope.
        scope: InteractiveScope,
        /// Complete only after encrypted commit and resource death are confirmed.
        reply: oneshot::Sender<Result<InteractiveReply, InteractiveError>>,
    },
}

struct ControlState {
    owner: Option<String>,
    state: InteractiveState,
    expires_at: Timestamp,
    expected_generation: Option<u64>,
    committed_generation: Option<u64>,
    capture_consent: bool,
    cast: Option<ScreencastPublisher>,
}

struct Entry {
    binding: SessionBindingV1,
    tx: mpsc::Sender<InteractiveCommand>,
    cancel: CancellationToken,
    state: Mutex<ControlState>,
    busy: AtomicBool,
}

impl Entry {
    fn authorize(&self, scope: &InteractiveScope, now: Timestamp) -> Result<(), InteractiveError> {
        let state = self.state.lock();
        let identity = &self.binding.identity;
        if scope.tenant != identity.tenant
            || scope.run != identity.run
            || scope.session != identity.session
            || scope.generation != self.binding.generation
            || scope.lease_fence != self.binding.lease_fence
            || scope.owner.is_empty()
            || state.owner.as_ref().is_some_and(|owner| *owner != scope.owner)
            || now >= state.expires_at
            || self.cancel.is_cancelled()
            || state.state == InteractiveState::Closed
        {
            return Err(InteractiveError::Unavailable);
        }
        Ok(())
    }

    fn status(&self) -> InteractiveStatus {
        let state = self.state.lock();
        InteractiveStatus {
            state: state.state,
            expires_at: state.expires_at,
            committed_generation: state.committed_generation,
            frames_suppressed: true,
        }
    }
}

struct Operation {
    entry: Arc<Entry>,
    completed: bool,
}

impl Drop for Operation {
    fn drop(&mut self) {
        self.entry.busy.store(false, Ordering::Release);
        if !self.completed {
            self.entry.cancel.cancel();
            self.entry.state.lock().state = InteractiveState::Closed;
        }
    }
}

/// One process-local registry shared by authenticated API and local worker.
/// It cannot be independently constructed in separate processes as a control transport.
pub struct InteractiveProfiles {
    clock: Arc<dyn Clock>,
    origin: url::Url,
    entries: Mutex<BTreeMap<SessionId, Arc<Entry>>>,
}

impl InteractiveProfiles {
    /// Configure the exact local UI origin. Remote origins and ambient proxy headers are refused.
    ///
    /// # Errors
    /// Returns [`InteractiveError::Invalid`] unless origin is an explicit loopback HTTP(S) origin.
    pub fn new(clock: Arc<dyn Clock>, origin: url::Url) -> Result<Self, InteractiveError> {
        let host = origin.host_str().unwrap_or("").trim_matches(['[', ']']);
        let local = host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback());
        if !local
            || !matches!(origin.scheme(), "http" | "https")
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(InteractiveError::Invalid);
        }
        Ok(Self {
            clock,
            origin,
            entries: Mutex::new(BTreeMap::new()),
        })
    }

    /// Exact operator-configured local origin for origin and CSRF checks.
    #[must_use]
    pub fn origin(&self) -> &url::Url {
        &self.origin
    }

    /// Register one fresh actor under its existing binding; no API request can mint a registration.
    /// The driver owns the returned receiver and its cleanup lifetime.
    /// Supply the actor's dedicated per-session token, never the run-wide token.
    /// Revocation cancels this exact token so an already-started actor also stops.
    ///
    /// # Errors
    /// Returns unavailable for stale bindings/duplicates or busy when bounded capacity is exhausted.
    pub fn register(
        self: &Arc<Self>,
        binding: SessionBindingV1,
        cancel: CancellationToken,
    ) -> Result<InteractiveControl, InteractiveError> {
        let now = self.clock.now();
        if binding.state != BindingState::Leased
            || binding.generation == 0
            || binding.lease_fence <= 0
            || binding.expires_at <= now
            || cancel.is_cancelled()
        {
            return Err(InteractiveError::Unavailable);
        }
        let session = binding.identity.session;
        let (tx, rx) = mpsc::channel(MAILBOX);
        let entry = Arc::new(Entry {
            state: Mutex::new(ControlState {
                owner: None,
                state: InteractiveState::Available,
                expires_at: binding.expires_at,
                expected_generation: None,
                committed_generation: None,
                capture_consent: false,
                cast: None,
            }),
            binding,
            tx,
            cancel,
            busy: AtomicBool::new(false),
        });
        let mut entries = self.entries.lock();
        entries.retain(|_, value| {
            let expired = value.cancel.is_cancelled() || value.state.lock().expires_at <= now;
            if expired {
                value.cancel.cancel();
            }
            !expired
        });
        if entries.contains_key(&session) {
            return Err(InteractiveError::Unavailable);
        }
        if entries.len() >= MAX_SESSIONS {
            return Err(InteractiveError::Busy);
        }
        entries.insert(session, Arc::clone(&entry));
        Ok(InteractiveControl {
            entry,
            rx,
            registry: Arc::downgrade(self),
        })
    }

    fn entry(&self, scope: &InteractiveScope) -> Result<Arc<Entry>, InteractiveError> {
        let entry = self
            .entries
            .lock()
            .get(&scope.session)
            .cloned()
            .ok_or(InteractiveError::Unavailable)?;
        entry.authorize(scope, self.clock.now())?;
        Ok(entry)
    }

    async fn dispatch(
        &self,
        entry: Arc<Entry>,
        make: impl FnOnce(
            oneshot::Sender<Result<InteractiveReply, InteractiveError>>,
        ) -> Result<InteractiveCommand, InteractiveError>,
    ) -> Result<InteractiveReply, InteractiveError> {
        if entry
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(InteractiveError::Busy);
        }
        let mut operation = Operation {
            entry: Arc::clone(&entry),
            completed: false,
        };
        let (tx, rx) = oneshot::channel();
        let command = match make(tx) {
            Ok(command) => command,
            Err(error) => {
                operation.completed = true;
                return Err(error);
            }
        };
        if entry.tx.try_send(command).is_err() {
            return Err(InteractiveError::Busy);
        }
        let deadline = entry.state.lock().expires_at;
        let remaining = (deadline - self.clock.now())
            .to_std()
            .map_err(|_| InteractiveError::Unavailable)?
            .min(COMMAND_TIMEOUT);
        let result = tokio::select! {
            biased;
            () = entry.cancel.cancelled() => Err(InteractiveError::Unavailable),
            () = tokio::time::sleep(remaining) => Err(InteractiveError::Unavailable),
            reply = rx => reply.map_err(|_| InteractiveError::Unavailable)?,
        };
        if result.is_ok() {
            operation.completed = true;
        }
        result
    }

    /// Start once under the authenticated owner; activity never extends the admitted deadline.
    ///
    /// # Errors
    /// Returns invalid, unavailable, busy or the actor's live policy refusal.
    pub async fn start(
        &self,
        scope: &InteractiveScope,
        request: InteractiveStart,
    ) -> Result<InteractiveStatus, InteractiveError> {
        request.validate()?;
        let entry = self.entry(scope)?;
        let reply = self
            .dispatch(Arc::clone(&entry), |reply| {
                let mut state = entry.state.lock();
                if state.state != InteractiveState::Available {
                    return Err(InteractiveError::Unavailable);
                }
                state.owner = Some(scope.owner.clone());
                state.state = InteractiveState::Starting;
                state.expires_at = state
                    .expires_at
                    .min(self.clock.now() + chrono::Duration::seconds(i64::from(request.ttl_seconds)));
                state.expected_generation = Some(request.expected_generation);
                state.capture_consent = request.capture_consent;
                let remaining = (state.expires_at - self.clock.now())
                    .to_std()
                    .map_err(|_| InteractiveError::Unavailable)?;
                state.cast = Some(
                    ScreencastPublisher::new(scope.cast_scope(), remaining, entry.cancel.child_token())
                        .map_err(|_| InteractiveError::Invalid)?,
                );
                drop(state);
                Ok(InteractiveCommand::Start {
                    scope: scope.clone(),
                    request,
                    reply,
                })
            })
            .await?;
        if !matches!(reply, InteractiveReply::Ready) {
            entry.cancel.cancel();
            return Err(InteractiveError::Refused);
        }
        entry.authorize(scope, self.clock.now())?;
        entry.state.lock().state = InteractiveState::Active;
        Ok(entry.status())
    }

    /// Read structural status only after the driver rechecks live authority.
    ///
    /// # Errors
    /// Returns unavailable/busy/refused on ownership, expiry, driver or authority failure.
    pub async fn status(&self, scope: &InteractiveScope) -> Result<InteractiveStatus, InteractiveError> {
        let entry = self.entry(scope)?;
        if entry.state.lock().state == InteractiveState::Finished {
            return Ok(entry.status());
        }
        let reply = self
            .dispatch(Arc::clone(&entry), |reply| {
                Ok(InteractiveCommand::Inspect {
                    scope: scope.clone(),
                    reply,
                })
            })
            .await?;
        if !matches!(reply, InteractiveReply::Accepted) {
            entry.cancel.cancel();
            return Err(InteractiveError::Refused);
        }
        entry.authorize(scope, self.clock.now())?;
        Ok(entry.status())
    }

    /// Submit one allowlisted input to the existing driver and safety/journal pipeline.
    ///
    /// # Errors
    /// Returns invalid, unavailable, busy or a live safety refusal; no automatic unsafe action occurs.
    pub async fn input(
        &self,
        scope: &InteractiveScope,
        input: ProfileInput,
    ) -> Result<InteractiveStatus, InteractiveError> {
        input.validate()?;
        let entry = self.entry(scope)?;
        let reply = self
            .dispatch(Arc::clone(&entry), |reply| {
                if entry.state.lock().state != InteractiveState::Active {
                    return Err(InteractiveError::Unavailable);
                }
                Ok(InteractiveCommand::Input {
                    scope: scope.clone(),
                    input,
                    reply,
                })
            })
            .await?;
        if !matches!(reply, InteractiveReply::Accepted) {
            entry.cancel.cancel();
            return Err(InteractiveError::Refused);
        }
        entry.authorize(scope, self.clock.now())?;
        Ok(entry.status())
    }

    /// Finish only when encrypted structured state and owned resource cleanup both succeed.
    ///
    /// # Errors
    /// Returns unavailable/busy/refused on stale generation, live authority, commit or cleanup failure.
    pub async fn finish(&self, scope: &InteractiveScope) -> Result<InteractiveStatus, InteractiveError> {
        let entry = self.entry(scope)?;
        let reply = self
            .dispatch(Arc::clone(&entry), |reply| {
                let mut state = entry.state.lock();
                if state.state != InteractiveState::Active {
                    return Err(InteractiveError::Unavailable);
                }
                state.state = InteractiveState::Finishing;
                drop(state);
                Ok(InteractiveCommand::Finish {
                    scope: scope.clone(),
                    reply,
                })
            })
            .await?;
        let InteractiveReply::Committed { generation } = reply else {
            entry.cancel.cancel();
            return Err(InteractiveError::Refused);
        };
        entry.authorize(scope, self.clock.now())?;
        let mut state = entry.state.lock();
        if state.expected_generation.and_then(|old| old.checked_add(1)) != Some(generation) {
            entry.cancel.cancel();
            return Err(InteractiveError::Refused);
        }
        state.committed_generation = Some(generation);
        state.state = InteractiveState::Finished;
        if let Some(cast) = &state.cast {
            cast.cancel();
        }
        drop(state);
        Ok(entry.status())
    }

    /// Stop input and capture immediately; the actor's cancellation branch owns confirmed cleanup.
    ///
    /// # Errors
    /// Returns unavailable for a foreign, expired or stale generation.
    pub fn cancel(&self, scope: &InteractiveScope) -> Result<InteractiveStatus, InteractiveError> {
        let entry = self.entry(scope)?;
        entry.cancel.cancel();
        entry.state.lock().state = InteractiveState::Closed;
        Ok(entry.status())
    }

    /// Subscribe once to the private ephemeral channel after a live driver authority check.
    ///
    /// # Errors
    /// Returns unavailable/refused for stale scope, missing consent, expired or occupied channel.
    pub async fn subscribe(
        &self,
        scope: &InteractiveScope,
        capture_consent: bool,
        privacy_consent: bool,
    ) -> Result<ScreencastReceiver, InteractiveError> {
        self.status(scope).await?;
        let entry = self.entry(scope)?;
        let state = entry.state.lock();
        if state.state != InteractiveState::Active {
            return Err(InteractiveError::Unavailable);
        }
        if !state.capture_consent {
            return Err(InteractiveError::Refused);
        }
        let cast = state.cast.as_ref().ok_or(InteractiveError::Unavailable)?;
        let receiver = cast
            .subscribe(&scope.cast_scope(), capture_consent, privacy_consent)
            .map_err(|_| InteractiveError::Refused)?;
        cast.observe(ScreencastObservation::Unproven)
            .map_err(|_| InteractiveError::Unavailable)?;
        Ok(receiver)
    }
}

/// Actor-owned cleanup guard. Successful finish retains only a bounded status tombstone.
pub struct InteractiveControl {
    entry: Arc<Entry>,
    rx: mpsc::Receiver<InteractiveCommand>,
    registry: Weak<InteractiveProfiles>,
}

impl InteractiveControl {
    /// Existing generation the local driver must verify before every acknowledgment.
    #[must_use]
    pub fn binding(&self) -> &SessionBindingV1 {
        &self.entry.binding
    }

    /// Cancellation/expiry must stop all browser activity and close owned resources.
    #[must_use]
    pub fn cancellation(&self) -> CancellationToken {
        self.entry.cancel.clone()
    }

    /// Mark the actor's completed encrypted commit and confirmed cleanup before replying.
    /// This keeps only a bounded structural tombstone when the actor mailbox is dropped.
    ///
    /// # Errors
    /// Returns refusal if finish was not requested or the committed generation is stale.
    pub fn committed(&self, generation: u64) -> Result<(), InteractiveError> {
        let mut state = self.entry.state.lock();
        if state.state != InteractiveState::Finishing
            || state.expected_generation.and_then(|old| old.checked_add(1)) != Some(generation)
            || self.entry.cancel.is_cancelled()
        {
            return Err(InteractiveError::Refused);
        }
        state.committed_generation = Some(generation);
        state.state = InteractiveState::Finished;
        if let Some(cast) = &state.cast {
            cast.cancel();
        }
        Ok(())
    }

    /// Receive one command; expiry and cancellation close the mailbox without new effects.
    pub async fn recv(&mut self) -> Option<InteractiveCommand> {
        let registry = self.registry.upgrade()?;
        let deadline = self.entry.state.lock().expires_at;
        let Ok(remaining) = (deadline - registry.clock.now()).to_std() else {
            self.entry.cancel.cancel();
            return None;
        };
        let command = tokio::select! {
            biased;
            () = self.entry.cancel.cancelled() => None,
            () = tokio::time::sleep(remaining) => { self.entry.cancel.cancel(); None },
            command = self.rx.recv() => command,
        };
        if let Some(command) = &command {
            let scope = match command {
                InteractiveCommand::Start { scope, .. }
                | InteractiveCommand::Inspect { scope, .. }
                | InteractiveCommand::Input { scope, .. }
                | InteractiveCommand::Finish { scope, .. } => scope,
            };
            if self.entry.authorize(scope, registry.clock.now()).is_err() {
                self.entry.cancel.cancel();
                return None;
            }
        }
        command
    }

    /// Publish structural suppression only; unproven browser pixels are never captured.
    ///
    /// # Errors
    /// Returns unavailable after cancellation or capture-channel expiry. An absent or
    /// slow subscriber closes only capture delivery, never the profile workflow.
    pub fn suppress_frame(&self, secret_present: bool) -> Result<(), InteractiveError> {
        let state = self.entry.state.lock();
        let cast = state.cast.as_ref().ok_or(InteractiveError::Unavailable)?;
        match cast.observe(if secret_present {
            ScreencastObservation::SecretPresent
        } else {
            ScreencastObservation::Unproven
        }) {
            Ok(()) | Err(ScreencastError::Disconnected | ScreencastError::SlowConsumer) => Ok(()),
            Err(_) => Err(InteractiveError::Unavailable),
        }
    }
}

impl Drop for InteractiveControl {
    fn drop(&mut self) {
        if self.entry.state.lock().state == InteractiveState::Finished {
            return;
        }
        self.entry.cancel.cancel();
        if let Some(registry) = self.registry.upgrade() {
            let mut entries = registry.entries.lock();
            let session = self.entry.binding.identity.session;
            if entries
                .get(&session)
                .is_some_and(|entry| Arc::ptr_eq(entry, &self.entry))
            {
                entries.remove(&session);
            }
        }
    }
}

/// Select an existing, fresh candidate proposal for one operator activation.
/// This is only a proposal: callers must still run the normal kernel, journal and
/// live-confirmation pipeline. A selector cannot synthesize a missing candidate.
/// Credential fills use the actor's separate authenticated credential command.
///
/// # Errors
/// Returns refusal for stale/unmatched targets, credential input, or missing click actions.
pub fn proposal_for_input(
    context: &crawlx_strategies::DecisionContext<'_>,
    input: &ProfileInput,
    target: &crawlx_core::observation::RuntimeLocator,
) -> Result<crawlx_core::ActionProposal, InteractiveError> {
    input.validate()?;
    if !matches!(input, ProfileInput::Activate { .. }) {
        return Err(InteractiveError::Refused);
    }
    if target.epoch != context.bundle.epoch {
        return Err(InteractiveError::Refused);
    }
    let candidate = context
        .candidates
        .iter()
        .position(|candidate| {
            let locator = &candidate.descriptor.locator;
            locator.tab == target.tab
                && locator.frame == target.frame
                && locator.backend_node_id == target.backend_node_id
                && locator.epoch == target.epoch
        })
        .ok_or(InteractiveError::Refused)?;
    let keyed = context
        .keyed_actions()
        .iter()
        .find(|action| {
            action.candidate == candidate && action.key.action_kind == crawlx_core::ActionKind::Click
        })
        .ok_or(InteractiveError::Refused)?;
    context
        .proposal_for(keyed, "interactive_profile", 1, 1.0)
        .ok_or(InteractiveError::Refused)
}

#[cfg(test)]
#[path = "interactive_profiles_tests.rs"]
mod tests;
