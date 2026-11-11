//! The Session Actor: the only code that calls a `BrowserContext`.
//!
//! Commands arrive over a bounded mailbox (32) and are handled one at a time, so exactly one
//! state-mutating action is in flight per session. The per-action protocol is
//! [`SessionActor::execute`]; crash recovery lives in `crate::recovery`.
//!
//! Actor termination closes its context before releasing the pool's single-actor reservation.
//! Panic and cancellation use the same supervised cleanup; uncertain closure stays quarantined.

#[path = "actor_captcha.rs"]
mod captcha;

#[path = "actor_extensions.rs"]
mod lifecycle;

use crate::analysis::StateAnalyzer;
use crate::checkpoint::Checkpointer;
use crate::error::SessionError;
use crate::login::{run_login, LoginFailure, LoginMaterial, LoginReport, MAX_LOGIN_ATTEMPTS};
use crate::pool::{Lease, PooledContext};
use crate::supervisor::Supervisor;
use crate::surface::traffic_export::{Exchange, TrafficExporter};
use async_trait::async_trait;
use crawlx_core::config::Dynamic;
use crawlx_core::counters::{ActionStatus, ReconcileResolution};
use crawlx_core::dom_ops::{CssFilter, LazyScrollSpec, XhrRecord};
use crawlx_core::epoch::EpochPolicy;
use crawlx_core::hash::Digest;
use crawlx_core::observation::{
    ActionReceipt, DomSelector, LiveTargetFacts, NavigationResult, ObservationBundle, ObservationSpec,
    QuiescencePolicy, Revalidation, RuntimeLocator, SettleReport,
};
use crawlx_core::page_op::{PageOp, PageOpResult};
use crawlx_core::proposal::{ExpectedEffect, ProposalClass};
use crawlx_core::repo::{
    ActionJournal, ArtifactStore, CheckpointRepo, EventRepo, NewState, OutcomeRecord, Reconciliation,
    RunRepo, StateRepo,
};
use crawlx_core::safety::SafetyDecision;
use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin, UnattributedReason};
use crawlx_core::{
    ActionId, BlockedNavigation, BrowserAction, BrowserContext, BrowserError, CanonicalUrl, CheckpointId,
    Clock, ContextConfig, CrawlRunId, NetworkEpochId, ObservationEpoch, PrincipalId, SecretOr, SessionId,
    StoreError, Timestamp,
};
use crawlx_elements::{
    CandidateDiscovery, DiscoveryConfig, IdentityResolver, InMemoryIdentityIndex, MatchWeights,
};
use crawlx_forms::Partition;
use crawlx_observe::{spec, Observer, ObserverConfig, QuiescenceWaiter};
use crawlx_safety::{AdmittedAction, SafetyKernel};
use crawlx_scheduler::{CheckpointCadence, CheckpointReason, CheckpointTracker, RetryPolicy};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::spans::{self, child};
use crawlx_telemetry::Metrics;
use crawlx_url::CanonicalizeOptions;
use futures::FutureExt as _;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::Instrument as _;

/// Mailbox bound.
pub const MAILBOX: usize = 32;

/// Lifecycle states.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum SessionState {
    /// Starting.
    Starting,
    /// Authenticating.
    Authenticating,
    /// Ready.
    Ready,
    /// Acting.
    Acting,
    /// Recovering.
    Recovering,
    /// Halted storage.
    HaltedStorage,
    /// Paused.
    Paused,
    /// Closing.
    Closing,
    /// Failed.
    Failed,
    /// The actor task has ended.
    Closed,
}

impl SessionState {
    #[must_use]
    /// As str.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Authenticating => "authenticating",
            Self::Ready => "ready",
            Self::Acting => "acting",
            Self::Recovering => "recovering",
            Self::HaltedStorage => "halted_storage",
            Self::Paused => "paused",
            Self::Closing => "closing",
            Self::Failed => "failed",
            Self::Closed => "closed",
        }
    }
}

/// Why the actor is asked to stop.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ShutdownReason {
    /// The session finished its work.
    Completed,
    /// SIGINT/SIGTERM: drain and checkpoint so another worker can resume.
    Graceful,
    /// Cancelled.
    Cancelled,
    /// Failed.
    Failed,
}

/// Why an admitted action was not performed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum DropReason {
    /// Stale epoch.
    StaleEpoch,
    /// Not actionable.
    NotActionable,
    /// Identity changed.
    IdentityChanged,
    /// Confirm denied.
    ConfirmDenied,
}

impl DropReason {
    #[must_use]
    /// As str.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StaleEpoch => "stale_epoch",
            Self::NotActionable => "not_actionable",
            Self::IdentityChanged => "identity_changed",
            Self::ConfirmDenied => "confirm_denied",
        }
    }
}

/// Result of `Execute`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ActionOutcome {
    /// Action id.
    pub action_id: ActionId,
    /// `Succeeded | Failed` after performing; `Proposed` when `dropped` is set (nothing ran).
    pub status: ActionStatus,
    /// Receipt.
    pub receipt: Option<ActionReceipt>,
    /// Settle.
    pub settle: Option<SettleReport>,
    /// After.
    pub after: Option<Arc<ObservationBundle>>,
    /// The persisted after-state (also written by T2) with its cluster decision.
    pub after_state: Option<NewState>,
    /// Dropped.
    pub dropped: Option<DropReason>,
    /// Live target facts when the kernel refused at confirmation: the evidence (for example
    /// traffic observed from this control) the admitted classification did not have.
    pub live: Option<LiveTargetFacts>,
    /// Error.
    pub error: Option<String>,
    /// Navigations the browser's guard refused while the action ran (`robots.txt`): the page
    /// never loaded them, so the action did not take effect. The action's status is `Failed`
    /// with an `error` starting `robots_blocked:`; the outcome is known, never `unknown`.
    pub robots_blocked: Vec<BlockedNavigation>,
    /// Latency ms.
    pub latency_ms: u64,
}

impl ActionOutcome {
    fn dropped(id: ActionId, reason: DropReason) -> Self {
        Self {
            action_id: id,
            status: ActionStatus::Proposed,
            receipt: None,
            settle: None,
            after: None,
            after_state: None,
            dropped: Some(reason),
            live: None,
            error: None,
            robots_blocked: Vec::new(),
            latency_ms: 0,
        }
    }
}

/// Result of `Restore`.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct RestoreReport {
    /// Checkpoint.
    pub checkpoint: CheckpointId,
    /// Url.
    pub url: String,
    /// Admitted handler restored with the document; absent only for a blank checkpoint.
    pub request_route: Option<String>,
    /// Navigation.
    pub navigation: Option<NavigationResult>,
}

/// The mailbox protocol. `Execute` carries `retry_of` for a reconciled
/// `not_applied` action that is re-intended under its original id; `Login` runs the
/// `builtin:form` plan inside the actor so the credential never leaves it. A recorded flow
/// is driven from outside through `ResolveSelector` / `Revalidate` /
/// `Execute` (kernel-adjudicated, journaled), `TypeCredential` for the credential fills
/// (performed inside the actor like `Login`, never journaled with the value), `StorageDigest`
/// for the success check and `Authenticated` to record the outcome.
#[non_exhaustive]
pub enum SessionCommand {
    /// Observe.
    Observe {
        /// Spec.
        spec: ObservationSpec,
        /// The caller's span; the `observation` span is created under it.
        span: tracing::Span,
        /// Reply.
        reply: oneshot::Sender<Result<Arc<ObservationBundle>, SessionError>>,
    },
    /// Execute.
    Execute {
        /// Action.
        action: Box<AdmittedAction>,
        /// Settle.
        settle: QuiescencePolicy,
        /// Retry of.
        retry_of: Option<ActionId>,
        /// The caller's span; the `action` span is created under it.
        span: tracing::Span,
        /// Reply.
        reply: oneshot::Sender<Result<ActionOutcome, SessionError>>,
    },
    /// Navigate.
    Navigate {
        /// Admitted request intent, including its explicit handler route.
        request: Box<crawlx_core::request::RequestEnvelopeV1>,
        /// Reply.
        reply: oneshot::Sender<Result<NavigationResult, SessionError>>,
    },
    /// Checkpoint.
    Checkpoint {
        /// Reason.
        reason: CheckpointReason,
        /// Reply.
        reply: oneshot::Sender<Result<CheckpointId, SessionError>>,
    },
    /// Restore.
    Restore {
        /// Checkpoint.
        checkpoint: CheckpointId,
        /// Reply.
        reply: oneshot::Sender<Result<RestoreReport, SessionError>>,
    },
    /// Reconcile.
    Reconcile {
        /// Action id.
        action_id: ActionId,
        /// Reply.
        reply: oneshot::Sender<Result<Reconciliation, SessionError>>,
    },
    /// Login.
    Login {
        /// Material.
        material: Box<LoginMaterial>,
        /// The `builtin:form` plan runs because a recorded flow failed (audit only).
        fallback: bool,
        /// Reply.
        reply: oneshot::Sender<Result<LoginReport, SessionError>>,
    },
    /// A login that ran outside `Login` (recorded flow) succeeded: keep `material` for
    /// recovery and leave `Authenticating`.
    Authenticated {
        /// Material.
        material: Box<LoginMaterial>,
        /// Reply.
        reply: oneshot::Sender<Result<(), SessionError>>,
    },
    /// Settle the initial login reservation without extending a binding or its profile TTL.
    NarrowBindingDeadline {
        /// Credited exploration deadline.
        deadline: Timestamp,
        /// Reply.
        reply: oneshot::Sender<Result<(), SessionError>>,
    },
    /// Resolve a recorded-flow selector at the current epoch.
    ResolveSelector {
        /// Selector.
        selector: DomSelector,
        /// Reply.
        reply: oneshot::Sender<Result<Option<RuntimeLocator>, SessionError>>,
    },
    /// Revalidate a locator against its own epoch.
    Revalidate {
        /// Locator.
        locator: RuntimeLocator,
        /// Reply.
        reply: oneshot::Sender<Result<Revalidation, SessionError>>,
    },
    /// Digest of the cookie/storage export (the secret-bearing blob never leaves the actor).
    StorageDigest {
        /// Reply.
        reply: oneshot::Sender<Result<Digest, SessionError>>,
    },
    /// Strict complete structured profile export for encrypted custody (never the redacted
    /// checkpoint export).
    ExportProfileStorage {
        /// Reply; the bytes are zeroized on drop.
        reply: oneshot::Sender<Result<zeroize::Zeroizing<Vec<u8>>, SessionError>>,
    },
    /// Type a credential into `target` (recorded-flow `fill` with a placeholder): revalidated,
    /// performed as native input, settled with the session policy; not journaled, like the
    /// typing `Login` does.
    TypeCredential {
        /// Target.
        target: RuntimeLocator,
        /// Value.
        value: SecretOr<String>,
        /// Reply.
        reply: oneshot::Sender<Result<(), SessionError>>,
    },
    /// A caller-driven page operation (scrape engine): emulation, request
    /// blocking, script evaluation, captures. None of them clicks, types or submits; input
    /// stays an adjudicated `Execute`.
    PageOp {
        /// The operation.
        op: Box<PageOp>,
        /// Reply.
        reply: oneshot::Sender<Result<PageOpResult, SessionError>>,
    },
    /// Read document response metadata only while its settled DOM epoch still owns the page.
    DocumentResponse {
        /// Epoch of the immutable observation being extracted.
        expected: ObservationEpoch,
        /// Reply.
        reply: oneshot::Sender<Result<PageOpResult, SessionError>>,
    },
    /// Evaluate a CSS candidate filter in the page for `targets` (`dynamic.interactionSelector`,
    /// `dynamic.interactionExclude`): one admit/reject verdict per target, in order.
    CssFilter {
        /// The filter.
        filter: CssFilter,
        /// The elements to judge.
        targets: Vec<RuntimeLocator>,
        /// Reply.
        reply: oneshot::Sender<Result<Vec<bool>, SessionError>>,
    },
    /// The XHR and `fetch()` requests the pages issued since the previous drain (`extract.xhr`).
    DrainXhr {
        /// Reply.
        reply: oneshot::Sender<Result<Vec<XhrRecord>, SessionError>>,
    },
    /// Pause.
    Pause,
    /// Resume.
    Resume,
    /// Shutdown.
    Shutdown {
        /// Reason.
        reason: ShutdownReason,
        /// Reply.
        reply: oneshot::Sender<Result<(), SessionError>>,
    },
}

impl SessionCommand {
    fn reject(self, error: SessionError) {
        match self {
            Self::Observe { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Execute { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Navigate { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Checkpoint { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Restore { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Reconcile { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Login { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Authenticated { reply, .. }
            | Self::NarrowBindingDeadline { reply, .. }
            | Self::TypeCredential { reply, .. }
            | Self::Shutdown { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::ResolveSelector { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Revalidate { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::StorageDigest { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::ExportProfileStorage { reply } => {
                let _ = reply.send(Err(error));
            }
            Self::PageOp { reply, .. } | Self::DocumentResponse { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::CssFilter { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::DrainXhr { reply, .. } => {
                let _ = reply.send(Err(error));
            }
            Self::Pause | Self::Resume => {}
        }
    }
}

/// Per-run services shared by the sessions of a worker.
#[derive(Clone)]
pub struct SessionServices {
    /// Tenant owning every checkpoint encrypted by these services.
    pub tenant: crawlx_core::TenantId,
    /// Checkpoint secret encryption and authenticated decryption.
    pub checkpoint_keys: Arc<dyn crawlx_storage::checkpoint_crypto::CheckpointKeys>,
    /// Journal.
    pub journal: Arc<dyn ActionJournal>,
    /// Runs.
    pub runs: Arc<dyn RunRepo>,
    /// Events.
    pub events: Arc<dyn EventRepo>,
    /// States.
    pub states: Arc<dyn StateRepo>,
    /// Checkpoints.
    pub checkpoints: Arc<dyn CheckpointRepo>,
    /// Artifacts.
    pub artifacts: Arc<dyn ArtifactStore>,
    /// Kernel.
    pub kernel: Arc<SafetyKernel>,
    /// Clock.
    pub clock: Arc<dyn Clock>,
    /// Pool.
    pub pool: crate::pool::BrowserPool,
    /// Supervisor.
    pub supervisor: Supervisor,
    /// Durable approval repository bound to the same store as the journal; consumed
    /// approvals reach T1 only through its fenced `intend_approved`.
    pub approvals: Arc<dyn crawlx_storage::approvals::ApprovalRepository>,
}

/// Per-session settings.
#[derive(Clone)]
pub struct SessionConfig {
    /// Run.
    pub run: CrawlRunId,
    /// Session.
    pub session: SessionId,
    /// Principal.
    pub principal: PrincipalId,
    /// Context.
    pub context: ContextConfig,
    /// Dedicated Chromium process (`authorized_security_test`).
    pub exclusive_browser: bool,
    /// Strict (`mutation` slack 0) under `authorized_security_test`.
    pub epoch_policy: EpochPolicy,
    /// `scheme://host[:port]` of the seed; credentials are typed only here.
    pub seed_origin: String,
    /// Where the login form lives (re-login during recovery navigates here).
    pub login_url: Option<CanonicalUrl>,
    /// After spec.
    pub after_spec: ObservationSpec,
    /// Cadence.
    pub cadence: CheckpointCadence,
    /// T2 retries (3 attempts).
    pub journal_retry: RetryPolicy,
    /// Mailbox.
    pub mailbox: usize,
    /// Starts in `Authenticating` until a `Login` succeeds.
    pub awaits_login: bool,
    /// Attempts per recovery rung.
    pub recovery_attempts: u32,
    /// Observer.
    pub observer: ObserverConfig,
    /// Canonicalize.
    pub canonicalize: CanonicalizeOptions,
    /// Identity algorithm used by decisions and reconciliation.
    pub identity_version: crawlx_core::config::IdentityVersion,
    /// Quiescence after the actor's own navigations and login typing
    /// (`dynamic.pageLoadStrategy`).
    pub settle: QuiescencePolicy,
    /// Request URL patterns blocked in the browser from the first navigation on
    /// (`dynamic.blockConsentBanners`); empty blocks nothing.
    pub block_urls: Vec<String>,
    /// Lazy-content scroll run after every new document settles (`dynamic.maxScrollSteps`).
    pub lazy_scroll: Option<LazyScrollSpec>,
    /// Receives an exchange for every request the browser makes (`WorkerConfig::traffic_export`).
    pub traffic_export: Option<Arc<TrafficExporter>>,
    /// Admission authority shared with this run's HTTP requests.
    pub origin_governor: Arc<crawlx_fetch::OriginGovernor>,
    /// Cancels pending origin admission when the run stops.
    pub origin_cancel: tokio_util::sync::CancellationToken,
    /// Interactive-owned, per-session token that interrupts an in-flight effect or settle.
    /// `None` (every ordinary run) keeps the graceful drain behavior. Never the run-wide token.
    pub effect_cancel: Option<tokio_util::sync::CancellationToken>,
    /// Optional evidence of actual performed actions; absent in production.
    pub action_trace: Option<Arc<crate::action_trace::ActionTrace>>,
    /// Shared CPU pool for opt-in native settled-DOM item pipelines.
    /// `None` keeps legacy actors from acquiring parser work or output capabilities.
    pub extension_cpu: Option<crate::runtime::CpuPool>,
    /// Worker-installed local article language capability for settled-DOM extraction.
    pub article_language_detector: Option<crawlx_core::article_language::ArticleLanguageHandle>,
    /// Existing scheduler lease used only for fenced binding metadata updates.
    pub(crate) binding_owner: Option<(crate::durable::DurableStore, crawlx_storage::leases::SessionLease)>,
    /// Shared generation pin; the registry remains its sole transport owner.
    pub(crate) pool_pin: Option<Arc<crawlx_fetch::proxyx::PoolBinding>>,
    /// Local lease authority when no PostgreSQL binding repository is installed.
    pub(crate) local_lease_owner: Option<(
        Arc<dyn crawlx_storage::LeaseRepo>,
        crawlx_storage::leases::SessionLease,
    )>,
    /// Bounded initial-login reservation, settled before exploration starts.
    pub(crate) login_allowance: chrono::Duration,
    /// Absolute admitted execution ceiling, recovered from the durable role allocation.
    /// This may narrow but never extend the browser binding's independent lifetime.
    pub execution_deadline: Option<Timestamp>,
}

impl SessionConfig {
    #[must_use]
    /// New.
    pub fn new(run: CrawlRunId, session: SessionId, principal: PrincipalId, seed_origin: String) -> Self {
        Self {
            run,
            session,
            principal,
            context: ContextConfig::new(session),
            exclusive_browser: false,
            epoch_policy: EpochPolicy::default(),
            seed_origin,
            login_url: None,
            after_spec: spec::after_action(),
            cadence: CheckpointCadence::default(),
            journal_retry: RetryPolicy::journal(),
            mailbox: MAILBOX,
            awaits_login: false,
            recovery_attempts: 2,
            observer: ObserverConfig::default(),
            canonicalize: CanonicalizeOptions::default(),
            identity_version: crawlx_core::config::IdentityVersion::V1,
            settle: QuiescencePolicy::default(),
            block_urls: Vec::new(),
            lazy_scroll: None,
            traffic_export: None,
            origin_governor: Arc::new(crawlx_fetch::OriginGovernor::new(
                crawlx_fetch::GovernorConfig::default(),
            )),
            origin_cancel: tokio_util::sync::CancellationToken::new(),
            effect_cancel: None,
            action_trace: None,
            extension_cpu: None,
            article_language_detector: None,
            binding_owner: None,
            pool_pin: None,
            local_lease_owner: None,
            login_allowance: chrono::Duration::zero(),
            execution_deadline: None,
        }
    }

    /// Take the browser-plane settings of the request's `dynamic` block: the consent-banner
    /// blocklist and the lazy-content scroll.
    pub fn apply_dynamic(&mut self, dynamic: &Dynamic) {
        self.block_urls = if dynamic.block_consent_banners {
            crawlx_browser::consent::patterns().to_vec()
        } else {
            Vec::new()
        };
        self.lazy_scroll =
            (dynamic.max_scroll_steps > 0).then(|| LazyScrollSpec::steps(dynamic.max_scroll_steps));
    }
}

/// Counters a session actor shares with its [`SessionHandle`], read for the session's
/// diagnostics (`dynamic.enableDiagnostics`).
#[derive(Debug, Default)]
pub struct SessionStats {
    recoveries: AtomicU64,
    scroll_steps: AtomicU64,
}

impl SessionStats {
    /// Times the recovery ladder brought the session back after a browser crash.
    #[must_use]
    pub fn recoveries(&self) -> u64 {
        self.recoveries.load(Ordering::Relaxed)
    }

    /// Scroll steps the lazy-content scroll (`dynamic.maxScrollSteps`) performed.
    #[must_use]
    pub fn scroll_steps(&self) -> u64 {
        self.scroll_steps.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Copy)]
enum SessionExpiry {
    Execution,
    Binding,
}

impl SessionExpiry {
    fn error(self) -> SessionError {
        match self {
            Self::Execution => SessionError::ExecutionDeadlineReached,
            Self::Binding => {
                SessionError::Binding(crawlx_core::session_binding::SessionBindingError::Expired)
            }
        }
    }
}

#[derive(Default)]
struct ActorExit {
    expiry: Option<SessionExpiry>,
    failure: Option<Arc<SessionError>>,
    cleanup: Option<Result<(), SessionError>>,
    shutdown_completed: bool,
    retired_binding: Option<crawlx_core::session_binding::SessionBindingV1>,
}

/// Cloneable handle to a running actor.
#[derive(Clone)]
pub struct SessionHandle {
    tx: mpsc::Sender<SessionCommand>,
    state: watch::Receiver<SessionState>,
    session: SessionId,
    stats: Arc<SessionStats>,
    exit: Arc<parking_lot::Mutex<ActorExit>>,
    #[cfg(feature = "runtime-diagnostics")]
    task_monitor: crate::runtime::diagnostics::TaskMonitor,
}

impl SessionHandle {
    /// Cumulative poll counters of this actor's actual supervised task.
    #[cfg(feature = "runtime-diagnostics")]
    #[must_use]
    pub fn task_metrics(&self) -> crate::runtime::diagnostics::TaskMetrics {
        self.task_monitor.cumulative()
    }

    /// The counters the actor keeps for this session.
    #[must_use]
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }
    #[must_use]
    /// Session.
    pub const fn session(&self) -> SessionId {
        self.session
    }

    /// Current lifecycle state.
    #[must_use]
    pub fn state(&self) -> SessionState {
        *self.state.borrow()
    }

    /// Exact retired generation retained only after confirmed resource cleanup.
    /// This snapshot does not grant a lease or authorize replacement.
    #[must_use]
    pub fn retired_binding(&self) -> Option<crawlx_core::session_binding::SessionBindingV1> {
        self.exit.lock().retired_binding.clone()
    }

    /// Free mailbox slots right now (`0` means the next send parks the sender:
    /// backpressure).
    #[must_use]
    pub fn mailbox_capacity(&self) -> usize {
        self.tx.capacity()
    }

    /// The mailbox bound: `SessionConfig::mailbox`, never grown.
    #[must_use]
    pub fn mailbox_bound(&self) -> usize {
        self.tx.max_capacity()
    }

    /// Wait until the state satisfies `pred` (or the actor ends); returns the state seen.
    pub async fn wait_state(&self, pred: impl Fn(SessionState) -> bool) -> SessionState {
        let mut rx = self.state.clone();
        loop {
            let s = *rx.borrow_and_update();
            if pred(s) || s == SessionState::Closed {
                return s;
            }
            if rx.changed().await.is_err() {
                return SessionState::Closed;
            }
        }
    }

    async fn call<T>(
        &self,
        make: impl FnOnce(oneshot::Sender<Result<T, SessionError>>) -> SessionCommand,
    ) -> Result<T, SessionError> {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(make(reply)).await.is_err() {
            self.wait_state(|_| false).await;
            return Err(self.closed_error());
        }
        match rx.await {
            Ok(result) => result,
            Err(_) => {
                // A dropped reply can precede panic cleanup. Recovery must not race it.
                self.wait_state(|_| false).await;
                Err(self.closed_error())
            }
        }
    }

    pub(crate) fn closed_error(&self) -> SessionError {
        let exit = self.exit.lock();
        match &exit.failure {
            Some(error) => SessionError::ActorStopped(Arc::clone(error)),
            None => exit.expiry.map_or(SessionError::ActorGone, SessionExpiry::error),
        }
    }

    /// Observe.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn observe(&self, spec: ObservationSpec) -> Result<Arc<ObservationBundle>, SessionError> {
        let span = tracing::Span::current();
        self.call(|reply| SessionCommand::Observe { spec, span, reply })
            .await
    }

    /// Execute.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn execute(
        &self,
        action: AdmittedAction,
        settle: QuiescencePolicy,
    ) -> Result<ActionOutcome, SessionError> {
        let span = tracing::Span::current();
        self.call(|reply| SessionCommand::Execute {
            action: Box::new(action),
            settle,
            retry_of: None,
            span,
            reply,
        })
        .await
    }

    /// Re-execute a reconciled `not_applied` action under its original id.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn execute_retry(
        &self,
        action: AdmittedAction,
        settle: QuiescencePolicy,
        retry_of: ActionId,
    ) -> Result<ActionOutcome, SessionError> {
        let span = tracing::Span::current();
        self.call(|reply| SessionCommand::Execute {
            action: Box::new(action),
            settle,
            retry_of: Some(retry_of),
            span,
            reply,
        })
        .await
    }

    /// Navigate an admitted GET request without inferring its handler from the URL.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn navigate(
        &self,
        request: crawlx_core::request::RequestEnvelopeV1,
    ) -> Result<NavigationResult, SessionError> {
        self.call(|reply| SessionCommand::Navigate {
            request: Box::new(request),
            reply,
        })
        .await
    }

    pub(crate) async fn narrow_binding_deadline(&self, deadline: Timestamp) -> Result<(), SessionError> {
        self.call(|reply| SessionCommand::NarrowBindingDeadline { deadline, reply })
            .await
    }

    /// Checkpoint.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn checkpoint(&self, reason: CheckpointReason) -> Result<CheckpointId, SessionError> {
        self.call(|reply| SessionCommand::Checkpoint { reason, reply })
            .await
    }

    /// Restore.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn restore(&self, checkpoint: CheckpointId) -> Result<RestoreReport, SessionError> {
        self.call(|reply| SessionCommand::Restore { checkpoint, reply })
            .await
    }

    /// Reconcile.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn reconcile(&self, action_id: ActionId) -> Result<Reconciliation, SessionError> {
        self.call(|reply| SessionCommand::Reconcile { action_id, reply })
            .await
    }

    /// Login.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn login(&self, material: LoginMaterial) -> Result<LoginReport, SessionError> {
        self.login_with(material, false).await
    }

    /// [`Self::login`]; `fallback` marks the audit event as the fallback of a failed
    /// recorded flow.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn login_with(
        &self,
        material: LoginMaterial,
        fallback: bool,
    ) -> Result<LoginReport, SessionError> {
        self.call(|reply| SessionCommand::Login {
            material: Box::new(material),
            fallback,
            reply,
        })
        .await
    }

    /// Record that a login performed outside `Login` (recorded flow) succeeded.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn authenticated(&self, material: LoginMaterial) -> Result<(), SessionError> {
        self.call(|reply| SessionCommand::Authenticated {
            material: Box::new(material),
            reply,
        })
        .await
    }

    /// Resolve a recorded-flow selector at the current epoch.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn resolve_selector(
        &self,
        selector: DomSelector,
    ) -> Result<Option<RuntimeLocator>, SessionError> {
        self.call(|reply| SessionCommand::ResolveSelector { selector, reply })
            .await
    }

    /// Revalidate `locator` against the epoch it was captured in.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn revalidate(&self, locator: RuntimeLocator) -> Result<Revalidation, SessionError> {
        self.call(|reply| SessionCommand::Revalidate { locator, reply })
            .await
    }

    /// Digest of the current cookie/storage export.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn storage_digest(&self) -> Result<Digest, SessionError> {
        self.call(|reply| SessionCommand::StorageDigest { reply }).await
    }

    /// Strict structured profile snapshot for custody. The caller must keep it zeroizing.
    ///
    /// # Errors
    /// Fails closed unless the live binding, lease and browser all produce a complete export.
    pub async fn export_profile_storage(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, SessionError> {
        self.call(|reply| SessionCommand::ExportProfileStorage { reply })
            .await
    }

    /// Type a credential into `target` as native input (see [`SessionCommand::TypeCredential`]).
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn type_credential(
        &self,
        target: RuntimeLocator,
        value: SecretOr<String>,
    ) -> Result<(), SessionError> {
        self.call(|reply| SessionCommand::TypeCredential { target, value, reply })
            .await
    }

    /// Run one [`PageOp`] on the session's context (see [`SessionCommand::PageOp`]).
    ///
    /// # Errors
    /// [`SessionError`] when the session is not ready or the context fails the operation
    /// (`Unsupported` for contexts that cannot run it).
    pub async fn page_op(&self, op: PageOp) -> Result<PageOpResult, SessionError> {
        self.call(|reply| SessionCommand::PageOp {
            op: Box::new(op),
            reply,
        })
        .await
    }

    /// Read response metadata associated with one immutable DOM observation.
    ///
    /// # Errors
    /// Returns [`SessionError::ObservationEpochChanged`] when the page changed before
    /// or during the actor-owned read, or the underlying session/browser error.
    pub async fn document_response(&self, expected: ObservationEpoch) -> Result<PageOpResult, SessionError> {
        self.call(|reply| SessionCommand::DocumentResponse { expected, reply })
            .await
    }

    /// Judge `targets` against a CSS candidate filter in the page: `true` where an element is
    /// admitted (see [`SessionCommand::CssFilter`]).
    ///
    /// # Errors
    /// [`SessionError`] when the session is not ready or the context cannot evaluate filters.
    pub async fn css_filter(
        &self,
        filter: CssFilter,
        targets: Vec<RuntimeLocator>,
    ) -> Result<Vec<bool>, SessionError> {
        self.call(|reply| SessionCommand::CssFilter {
            filter,
            targets,
            reply,
        })
        .await
    }

    /// The XHR and `fetch()` requests the pages issued since the previous call.
    ///
    /// # Errors
    /// [`SessionError`] when the session is not ready.
    pub async fn drain_xhr(&self) -> Result<Vec<XhrRecord>, SessionError> {
        self.call(|reply| SessionCommand::DrainXhr { reply }).await
    }

    /// Pause.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn pause(&self) -> Result<(), SessionError> {
        self.tx
            .send(SessionCommand::Pause)
            .await
            .map_err(|_| SessionError::ActorGone)
    }

    /// Resume.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn resume(&self) -> Result<(), SessionError> {
        self.tx
            .send(SessionCommand::Resume)
            .await
            .map_err(|_| SessionError::ActorGone)
    }

    /// Stop the actor: checkpoint (graceful), confirm cleanup, save the encrypted profile.
    ///
    /// # Errors
    /// Returns actor loss, unconfirmed resource cleanup or a profile generation/save conflict.
    pub async fn shutdown(&self, reason: ShutdownReason) -> Result<(), SessionError> {
        let result = self
            .call(|reply| SessionCommand::Shutdown { reason, reply })
            .await;
        if self.state() == SessionState::Closed {
            let mut exit = self.exit.lock();
            if let Some(error) = &exit.failure {
                return Err(SessionError::ActorStopped(Arc::clone(error)));
            }
            if exit.shutdown_completed {
                return Ok(());
            }
            if matches!(&result, Err(SessionError::ExecutionDeadlineReached)) {
                // Only a proven execution-only retirement can become normal termination,
                // and only after its independently recorded cleanup actually succeeded.
                return match exit.cleanup.as_ref() {
                    Some(Ok(())) => Ok(()),
                    Some(Err(_)) => exit.cleanup.take().unwrap_or(Err(SessionError::ActorGone)),
                    None => Err(SessionError::ActorGone),
                };
            }
        }
        result
    }
}

/// Context stand-in while recovery has no live browser; every call reports a closed target.
pub(crate) struct ClosedContext;

#[async_trait]
impl BrowserContext for ClosedContext {
    async fn navigate(&mut self, _url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        Err(BrowserError::TargetClosed)
    }
    async fn observe(&mut self, _spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        Err(BrowserError::TargetClosed)
    }
    async fn revalidate(
        &mut self,
        _l: &RuntimeLocator,
        _e: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        Err(BrowserError::TargetClosed)
    }
    async fn perform(&mut self, _action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        Err(BrowserError::TargetClosed)
    }
    async fn settle(&mut self, _policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        Err(BrowserError::TargetClosed)
    }
    fn current_epoch(&self) -> ObservationEpoch {
        ObservationEpoch::default()
    }
    fn drain_traffic(&mut self) -> Vec<TrafficEvent> {
        Vec::new()
    }
    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError> {
        Err(BrowserError::TargetClosed)
    }
    async fn import_storage(&mut self, _blob: &[u8]) -> Result<(), BrowserError> {
        Err(BrowserError::TargetClosed)
    }
    async fn close(self: Box<Self>) -> Result<(), BrowserError> {
        Ok(())
    }
}

/// What T2 records about an action that reached the browser.
struct Finish {
    status: ActionStatus,
    receipt: Option<ActionReceipt>,
    settle: Option<SettleReport>,
    after_state: Option<NewState>,
    error: Option<String>,
    /// Navigations the guard refused while the action ran; the action did not apply them.
    robots_blocked: Vec<BlockedNavigation>,
}

/// How many executed actions' expected effects are kept for reconciliation.
const RECENT_EFFECTS: usize = 64;

/// Most traffic events kept between two journaled actions; the oldest are dropped first (the
/// context itself bounds its buffer the same way).
const MAX_PENDING_TRAFFIC: usize = 5_000;

/// The actor. Construct with [`SessionActor::spawn`].
pub struct SessionActor {
    pub(crate) cfg: SessionConfig,
    pub(crate) svc: SessionServices,
    pub(crate) analyzer: Arc<StateAnalyzer>,
    pub(crate) checkpointer: Checkpointer,
    pub(crate) ctx: Box<dyn BrowserContext>,
    pub(crate) pacing: crate::pacing::PacingHandle,
    pub(crate) lease: Option<Lease>,
    pub(crate) observer: Observer,
    pub(crate) tracker: CheckpointTracker,
    pub(crate) state: SessionState,
    state_tx: watch::Sender<SessionState>,
    exit: Arc<parking_lot::Mutex<ActorExit>>,
    pub(crate) last: Option<Arc<ObservationBundle>>,
    /// Handler identity survives redirects and action-driven document changes.
    pub(crate) current_request_route: Option<String>,
    pub(crate) login: Option<LoginMaterial>,
    pub(crate) login_attempts: u8,
    pub(crate) action_seq: u64,
    pub(crate) needs_recovery: bool,
    recent: VecDeque<(ActionId, ExpectedEffect)>,
    /// Actions this actor marked `unknown` and has not reconciled yet (`interactions.unknown_unreconciled`).
    unknown_pending: BTreeSet<ActionId>,
    /// Network epochs this actor has journaled a receipt for (a `network_epochs` row exists).
    /// Late events legitimately carry a previous action's epoch; events of any
    /// other epoch (the seed navigation's) are stored unattributed.
    journaled_epochs: BTreeSet<NetworkEpochId>,
    /// Shared with the session's [`SessionHandle`].
    stats: Arc<SessionStats>,
    /// Traffic drained from the context and not yet journaled by an action's T2 (bounded by
    /// [`MAX_PENDING_TRAFFIC`]); it is drained early only when a traffic exporter needs it.
    pending_traffic: Vec<TrafficEvent>,
}

impl Drop for SessionActor {
    fn drop(&mut self) {
        // Aborting the task drops its future, so async epilogues cannot run. Transfer both
        // resources to tracked cleanup instead of releasing the binding or stealing it.
        if tokio::runtime::Handle::try_current().is_ok() {
            let _ = self.start_context_cleanup(true);
        }
    }
}

impl SessionActor {
    /// Start an actor over `pooled` under the worker's supervisor. Records the browser build on
    /// the session row.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub fn spawn(
        cfg: SessionConfig,
        svc: SessionServices,
        analyzer: Arc<StateAnalyzer>,
        retention_days: u16,
        pooled: PooledContext,
    ) -> impl Future<Output = Result<SessionHandle, SessionError>> + Send {
        Box::pin(Self::spawn_inner(cfg, svc, analyzer, retention_days, pooled))
    }

    async fn spawn_inner(
        cfg: SessionConfig,
        svc: SessionServices,
        analyzer: Arc<StateAnalyzer>,
        retention_days: u16,
        pooled: PooledContext,
    ) -> Result<SessionHandle, SessionError> {
        let (ctx, build, lease) = pooled.into_parts();
        svc.runs.set_session_browser(cfg.session, &build).await?;
        let (ctx, pacing) = crate::pacing::wrap(ctx, &cfg, Arc::clone(&svc.clock));
        let initial = if cfg.awaits_login {
            SessionState::Authenticating
        } else {
            SessionState::Ready
        };
        let (state_tx, state_rx) = watch::channel(initial);
        let (tx, rx) = mpsc::channel(cfg.mailbox.max(1));
        let stats = Arc::new(SessionStats::default());
        let exit = Arc::new(parking_lot::Mutex::new(ActorExit::default()));
        #[cfg(feature = "runtime-diagnostics")]
        let task_monitor = crate::runtime::diagnostics::TaskMonitor::with_slow_poll_threshold(
            std::time::Duration::from_millis(10),
        );
        let handle = SessionHandle {
            tx,
            state: state_rx,
            session: cfg.session,
            stats: Arc::clone(&stats),
            exit: Arc::clone(&exit),
            #[cfg(feature = "runtime-diagnostics")]
            task_monitor: task_monitor.clone(),
        };
        let now = svc.clock.now();
        let mut checkpointer = Checkpointer::new(
            svc.tenant,
            cfg.run,
            cfg.session,
            Arc::clone(&svc.checkpoints),
            Arc::clone(&svc.artifacts),
            Arc::clone(&svc.clock),
            retention_days,
        )
        .with_keys(Arc::clone(&svc.checkpoint_keys));
        if let Some(binding) = &cfg.context.session_binding {
            if binding.identity.run != cfg.run
                || binding.identity.session != cfg.session
                || binding.identity.principal != cfg.principal
            {
                return Err(SessionError::Other(
                    "session_unavailable: actor binding mismatch".into(),
                ));
            }
            checkpointer = checkpointer.with_binding(binding.clone());
        }
        let mut actor = Self {
            observer: Observer::new(cfg.observer.clone()),
            tracker: cfg.cadence.tracker(now),
            checkpointer,
            ctx,
            pacing,
            lease: Some(lease),
            state: initial,
            state_tx,
            exit,
            last: None,
            current_request_route: None,
            login: None,
            login_attempts: 0,
            action_seq: 0,
            needs_recovery: false,
            recent: VecDeque::new(),
            unknown_pending: BTreeSet::new(),
            journaled_epochs: BTreeSet::new(),
            stats,
            pending_traffic: Vec::new(),
            analyzer,
            cfg,
            svc: svc.clone(),
        };
        actor.prepare_context().await;
        let session = actor.cfg.session;
        let task = actor.run(rx);
        #[cfg(feature = "runtime-diagnostics")]
        let task = crate::runtime::diagnostics::TaskMonitor::instrument(&task_monitor, task)
            .instrument(tracing::info_span!("session_actor"));
        svc.supervisor.spawn_for("session-actor", Some(session), task);
        Ok(handle)
    }

    pub(crate) fn set_state(&mut self, state: SessionState) {
        self.state = state;
        self.state_tx.send_replace(state);
    }

    async fn run(mut self, mut rx: mpsc::Receiver<SessionCommand>) {
        let result = AssertUnwindSafe(self.run_commands(&mut rx)).catch_unwind().await;
        if result.is_err() {
            self.record_exit(SessionError::ActorGone);
        }
        rx.close();
        if self.state != SessionState::Closed {
            self.set_state(SessionState::Closing);
            let cleanup = self.close_context().await;
            if let Err(error) = &cleanup {
                tracing::warn!(error = %error, "session resource cleanup failed");
            }
            self.exit.lock().cleanup = Some(cleanup);
            self.set_state(SessionState::Closed);
        }
        if let Err(payload) = result {
            // Keep the supervisor's typed panic report after cleanup has completed.
            std::panic::resume_unwind(payload);
        }
    }

    async fn run_commands(&mut self, rx: &mut mpsc::Receiver<SessionCommand>) {
        // The origin token also stops other roles in this run. Local binding retirement
        // closes only this mailbox/context; it must not cancel that shared run authority.
        loop {
            let next = if let Some(deadline) = self.command_deadline() {
                let remaining = deadline
                    .signed_duration_since(self.svc.clock.now())
                    .to_std()
                    .unwrap_or_default();
                tokio::time::timeout(remaining, rx.recv()).await
            } else {
                Ok(rx.recv().await)
            };
            let cmd = match next {
                Ok(Some(command)) => command,
                Ok(None) => break,
                Err(_) => {
                    // Preserve only a proven clock stop. Independent lease, profile and
                    // repository failures must never become deadline completion.
                    let authority = self
                        .verify_current_binding()
                        .await
                        .and_then(|()| self.accepts_owned_context());
                    if let Err(error) = authority {
                        self.record_exit(error);
                    }
                    self.set_state(SessionState::Failed);
                    rx.close();
                    break;
                }
            };
            if let Err(error) = self.verify_current_binding().await {
                let error = self.record_exit(error);
                self.set_state(SessionState::Failed);
                tracing::warn!(error = %error, "session lease or binding lost; queued commands cancelled");
                if !matches!(&cmd, SessionCommand::Shutdown { .. }) {
                    cmd.reject(error);
                    rx.close();
                    break;
                }
            }
            let stop = self.handle(cmd).await;
            let expired = self.exit.lock().expiry.is_some();
            if !stop && expired {
                self.set_state(SessionState::Failed);
                rx.close();
                break;
            }
            if !stop {
                if let Err(error) = self.charge_binding_use().await {
                    tracing::warn!(error = %error, "session binding retired or fenced");
                    self.record_exit(error);
                    self.set_state(SessionState::Failed);
                    rx.close();
                    break;
                }
            }
            if self.needs_recovery && !stop {
                self.needs_recovery = false;
                match Box::pin(self.recover()).await {
                    Ok(rung) => {
                        self.stats.recoveries.fetch_add(1, Ordering::Relaxed);
                        Metrics::global()
                            .counter(names::SESSION_RECOVERIES)
                            .inc_by(1, &[("rung", rung.as_str())]);
                    }
                    Err(e) => {
                        tracing::error!(session = %self.cfg.session, error = %e, "recovery ladder exhausted");
                        self.record_exit(e);
                        self.set_state(SessionState::Failed);
                        rx.close();
                        break;
                    }
                }
            }
            if stop {
                break;
            }
        }
    }

    fn record_exit(&self, error: SessionError) -> SessionError {
        if matches!(&error, SessionError::ExecutionDeadlineReached) {
            return error;
        }
        let error = match error {
            SessionError::ActorStopped(error) => error,
            other => Arc::new(other),
        };
        let mut exit = self.exit.lock();
        exit.expiry = None;
        let primary = exit.failure.get_or_insert(error);
        SessionError::ActorStopped(Arc::clone(primary))
    }

    async fn charge_binding_use(&mut self) -> Result<(), SessionError> {
        let Some(binding) = self.cfg.context.session_binding.as_mut() else {
            return Ok(());
        };
        let version = binding.state_version;
        if let Err(error) = binding.record_use(
            !self.needs_recovery,
            self.svc.clock.now(),
            crawlx_core::session_binding::SessionLimits::default(),
        ) {
            if error == crawlx_core::session_binding::SessionBindingError::Expired {
                self.verify_current_binding().await?;
            }
            return Err(self.binding_error(error));
        }
        if let Some((pg, lease)) = &self.cfg.binding_owner {
            pg.update_session_binding(lease, version, binding).await?;
        }
        if binding.state != crawlx_core::session_binding::BindingState::Leased {
            return Err(SessionError::Binding(
                crawlx_core::session_binding::SessionBindingError::Draining {
                    reason: binding
                        .retirement
                        .ok_or(crawlx_core::session_binding::SessionBindingError::GenerationConflict)?,
                },
            ));
        }
        Ok(())
    }

    async fn narrow_binding_deadline(&mut self, deadline: Timestamp) -> Result<(), SessionError> {
        let Some(current) = &self.cfg.context.session_binding else {
            return Ok(());
        };
        let mut next = current.clone();
        next.expires_at = next.expires_at.min(deadline);
        next.state_version = next
            .state_version
            .checked_add(1)
            .ok_or_else(|| SessionError::Other("session binding version exhausted".into()))?;
        if let Some((pg, lease)) = &self.cfg.binding_owner {
            pg.update_session_binding(lease, current.state_version, &next)
                .await?;
        }
        self.checkpointer.narrow_binding_deadline(next.expires_at);
        self.pacing.narrow_deadline(next.expires_at);
        self.cfg.execution_deadline = Some(deadline);
        self.cfg.context.session_binding = Some(next);
        Ok(())
    }

    fn verify_pool_pin(&self) -> Result<(), SessionError> {
        if let Some(pool) = &self.cfg.pool_pin {
            let binding = self
                .cfg
                .context
                .session_binding
                .as_ref()
                .ok_or(crawlx_core::session_binding::SessionBindingError::Unavailable)?;
            pool.validate_session(binding)?;
        }
        Ok(())
    }

    pub(crate) async fn verify_current_binding(&mut self) -> Result<(), SessionError> {
        if let Some((pg, lease)) = &self.cfg.binding_owner {
            let binding =
                self.cfg.context.session_binding.as_ref().ok_or_else(|| {
                    SessionError::Other("session_unavailable: missing actor binding".into())
                })?;
            pg.verify_session_binding(lease, binding)
                .await
                .map_err(|error| match error {
                    crawlx_storage::session_binding::SessionBindingVerificationError::Store(error) => {
                        self.exit.lock().expiry = None;
                        SessionError::Store(error)
                    }
                    crawlx_storage::session_binding::SessionBindingVerificationError::Binding(error) => {
                        self.binding_error(error)
                    }
                    _ => SessionError::Other("unsupported binding verification failure".into()),
                })?;
        } else if let Some((leases, lease)) = &self.cfg.local_lease_owner {
            leases.heartbeat(lease).await?;
        }
        self.verify_pool_pin()
    }

    fn command_deadline(&self) -> Option<Timestamp> {
        let binding = self.cfg.context.session_binding.as_ref().map(|b| b.expires_at);
        match (binding, self.cfg.execution_deadline) {
            (Some(binding), Some(execution)) => Some(binding.min(execution)),
            (binding, execution) => binding.or(execution),
        }
    }

    fn binding_error(&self, error: crawlx_core::session_binding::SessionBindingError) -> SessionError {
        if error != crawlx_core::session_binding::SessionBindingError::Expired {
            return SessionError::Binding(error);
        }
        let execution = self.state != SessionState::Authenticating
            && self.cfg.execution_deadline.is_some_and(|deadline| {
                deadline <= self.svc.clock.now()
                    && self
                        .cfg
                        .context
                        .session_binding
                        .as_ref()
                        .is_none_or(|binding| deadline <= binding.expires_at)
            });
        let expiry = if execution {
            SessionExpiry::Execution
        } else {
            SessionExpiry::Binding
        };
        self.exit.lock().expiry = Some(expiry);
        expiry.error()
    }

    pub(crate) async fn close_context(&mut self) -> Result<(), SessionError> {
        match self.start_context_cleanup(false) {
            Some(task) => task
                .await
                .map_err(|_| SessionError::ActorGone)?
                .map_err(|_| SessionError::ActorGone)?,
            None => Ok(()),
        }
    }

    fn start_context_cleanup(
        &mut self,
        final_cleanup: bool,
    ) -> Option<crate::supervisor::SupervisedTask<Result<(), SessionError>>> {
        let lease = self.lease.take()?;
        let context = std::mem::replace(&mut self.ctx, Box::new(ClosedContext));
        let state = self.state_tx.clone();
        let terminal = final_cleanup || self.state != SessionState::Recovering;
        let mut binding = terminal
            .then(|| self.cfg.context.session_binding.clone())
            .flatten();
        let owner = self.cfg.binding_owner.clone();
        let exit = Arc::clone(&self.exit);
        let now = self.svc.clock.now();
        Some(
            self.svc
                .supervisor
                .spawn_for("session-cleanup", Some(self.cfg.session), async move {
                    let draining: Result<(), SessionError> = async {
                        if let Some(binding) = &mut binding {
                            let version = binding.state_version;
                            let reason = if binding.expires_at <= now {
                                crawlx_core::session_binding::RetirementReason::Expired
                            } else {
                                crawlx_core::session_binding::RetirementReason::Replaced
                            };
                            binding.begin_drain(reason)?;
                            if binding.state_version != version {
                                if let Some((pg, lease)) = &owner {
                                    pg.update_session_binding(lease, version, binding).await?;
                                }
                            }
                        }
                        Ok(())
                    }
                    .await;
                    let closed = tokio::time::timeout(Duration::from_secs(5), context.close()).await;
                    let released = lease.release(matches!(closed, Ok(Ok(())))).await;
                    let lifecycle: Result<(), SessionError> = async {
                        draining?;
                        if let Some(binding) = &mut binding {
                            let version = binding.state_version;
                            binding.finish_cleanup(released.is_ok())?;
                            if let Some((pg, lease)) = &owner {
                                pg.update_session_binding(lease, version, binding).await?;
                            }
                        }
                        Ok(())
                    }
                    .await;
                    let result = released.and(lifecycle);
                    if result.is_ok() {
                        exit.lock().retired_binding = binding.filter(|binding| {
                            binding.state == crawlx_core::session_binding::BindingState::Retired
                        });
                    }
                    if final_cleanup {
                        if let Err(error) = &result {
                            tracing::warn!(error = %error, "cancelled actor resource cleanup failed");
                        }
                        state.send_replace(SessionState::Closed);
                    }
                    result
                }),
        )
    }

    // Construct only the selected operation's future in a separate synchronous
    // frame; unused command variants must not reserve their state on every poll.
    fn command_future<F: Future>(make: impl FnOnce() -> F) -> Pin<Box<F>> {
        Box::pin(make())
    }

    /// Returns true when the actor must stop.
    async fn handle(&mut self, cmd: SessionCommand) -> bool {
        match cmd {
            SessionCommand::Observe { spec, span, reply } => {
                let r = Self::command_future(|| self.observe(spec, &span)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Execute {
                action,
                settle,
                retry_of,
                span,
                reply,
            } => {
                let r = Self::command_future(|| self.execute(*action, settle, retry_of, &span)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Navigate { request, reply } => {
                let r = Self::command_future(|| self.navigate(&request)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Checkpoint { reason, reply } => {
                let r = Self::command_future(|| self.checkpoint(reason)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Restore { checkpoint, reply } => {
                let r = Self::command_future(|| self.restore(checkpoint)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Reconcile { action_id, reply } => {
                let r = Self::command_future(|| self.reconcile(action_id)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Login {
                material,
                fallback,
                mut reply,
            } => {
                let cancel = self.cfg.origin_cancel.clone();
                let remaining = self.cfg.context.session_binding.as_ref().map(|binding| {
                    binding
                        .expires_at
                        .signed_duration_since(self.svc.clock.now())
                        .to_std()
                        .unwrap_or_default()
                });
                let expiry = async {
                    match remaining {
                        Some(remaining) => tokio::time::sleep(remaining).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                let (r, interrupted) = tokio::select! {
                    biased;
                    () = reply.closed() => (
                        Err(SessionError::LoginFailed("login command cancelled".into())),
                        true,
                    ),
                    () = cancel.cancelled() => (
                        Err(SessionError::LoginFailed("login session cancelled or lease lost".into())),
                        true,
                    ),
                    () = expiry => (
                        Err(SessionError::LoginFailed("login binding expired".into())),
                        true,
                    ),
                    r = Self::command_future(|| self.do_login(*material, fallback)) => (r, false),
                };
                if interrupted {
                    // Dropping the login future stops subsequent plan steps, not an already
                    // dispatched effect. Never reuse/recover this uncertain context, and do
                    // not cancel the run's shared origin token. `run` owns bounded cleanup.
                    self.login = None;
                    self.needs_recovery = false;
                    self.set_state(SessionState::Failed);
                    let _ = reply.send(r);
                    return true;
                }
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Authenticated { material, reply } => {
                let r = self.authenticated(*material);
                let _ = reply.send(r);
            }
            SessionCommand::NarrowBindingDeadline { deadline, reply } => {
                let r = Self::command_future(|| self.narrow_binding_deadline(deadline)).await;
                let _ = reply.send(r);
            }
            SessionCommand::ResolveSelector { selector, reply } => {
                let r = Self::command_future(|| self.resolve_selector(&selector)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::Revalidate { locator, reply } => {
                let r = Self::command_future(|| self.revalidate(&locator)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::StorageDigest { reply } => {
                let r = Self::command_future(|| self.storage_digest()).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::ExportProfileStorage { reply } => {
                let r = Self::command_future(|| self.export_profile_storage()).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::TypeCredential { target, value, reply } => {
                let r = Self::command_future(|| self.type_credential(target, value)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::PageOp { op, reply } => {
                let r = Self::command_future(|| self.page_op(*op)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::DocumentResponse { expected, reply } => {
                let r = self.document_response(expected).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::CssFilter {
                filter,
                targets,
                reply,
            } => {
                let r = Self::command_future(|| self.css_filter(&filter, &targets)).await;
                let r = self.note(r).await;
                let _ = reply.send(r);
            }
            SessionCommand::DrainXhr { reply } => {
                let r = self.accepts_browser_commands().map(|()| self.ctx.drain_xhr());
                let _ = reply.send(r);
            }
            SessionCommand::Pause => {
                if matches!(self.state, SessionState::Ready | SessionState::Authenticating) {
                    let _ = Self::command_future(|| self.checkpoint(CheckpointReason::Pause)).await;
                    self.set_state(SessionState::Paused);
                }
            }
            SessionCommand::Resume => {
                if self.state == SessionState::Paused {
                    self.set_state(if self.cfg.awaits_login && self.login.is_none() {
                        SessionState::Authenticating
                    } else {
                        SessionState::Ready
                    });
                }
            }
            SessionCommand::Shutdown { reason, reply } => {
                if matches!(reason, ShutdownReason::Graceful | ShutdownReason::Completed)
                    && matches!(
                        self.state,
                        SessionState::Ready | SessionState::Paused | SessionState::Authenticating
                    )
                {
                    Self::command_future(|| self.checkpoint_best_effort(CheckpointReason::Shutdown)).await;
                }
                if self.cfg.traffic_export.is_some() {
                    self.collect_traffic();
                }
                self.set_state(SessionState::Closing);
                let cleanup = Self::command_future(|| self.close_context()).await;
                self.exit.lock().shutdown_completed = cleanup.is_ok();
                self.set_state(SessionState::Closed);
                let _ = reply.send(cleanup);
                return true;
            }
        }
        false
    }

    /// A crash anywhere schedules the recovery ladder after the reply went out.
    async fn note<T>(&mut self, r: Result<T, SessionError>) -> Result<T, SessionError> {
        self.verify_pool_pin()?;
        if matches!(
            &r,
            Err(SessionError::Browser(BrowserError::SessionExpired)
                | SessionError::Binding(crawlx_core::session_binding::SessionBindingError::Expired))
        ) && self.state != SessionState::Authenticating
        {
            // Pacing proves no dispatch occurred, not that other authority stayed valid.
            self.verify_current_binding().await?;
            return Err(self.binding_error(crawlx_core::session_binding::SessionBindingError::Expired));
        }
        if let Err(e) = &r {
            if e.is_target_crash() || matches!(e, SessionError::CrashedDuringAction(_)) {
                self.needs_recovery = true;
            }
        }
        r
    }

    fn accepts_browser_commands(&self) -> Result<(), SessionError> {
        if self.cfg.origin_cancel.is_cancelled()
            || self
                .cfg
                .effect_cancel
                .as_ref()
                .is_some_and(|token| token.is_cancelled())
        {
            return Err(SessionError::Cancelled);
        }
        self.accepts_owned_context()
    }

    fn accepts_owned_context(&self) -> Result<(), SessionError> {
        self.verify_pool_pin()?;
        if let Some(binding) = &self.cfg.context.session_binding {
            binding
                .eligible(
                    &binding.identity,
                    binding.lease_fence,
                    self.svc.clock.now(),
                    crawlx_core::session_binding::SessionLimits::default(),
                )
                .map_err(|error| self.binding_error(error))?;
        }
        if self
            .cfg
            .execution_deadline
            .is_some_and(|deadline| self.svc.clock.now() >= deadline)
        {
            return Err(self.binding_error(crawlx_core::session_binding::SessionBindingError::Expired));
        }
        match self.state {
            SessionState::Failed | SessionState::Closing | SessionState::Closed | SessionState::Starting => {
                Err(SessionError::NotReady {
                    state: self.state.as_str(),
                })
            }
            _ => Ok(()),
        }
    }

    fn last_url(&self) -> String {
        self.last
            .as_ref()
            .map(|b| b.url.url.to_string())
            .unwrap_or_default()
    }

    // ---- observe / navigate -------------------------------------------------------------

    /// Observe under an `observation` span created below `parent` (the caller's span).
    async fn observe(
        &mut self,
        spec: ObservationSpec,
        parent: &tracing::Span,
    ) -> Result<Arc<ObservationBundle>, SessionError> {
        self.accepts_browser_commands()?;
        self.solve_pending_captcha().await?;
        let epoch = self.ctx.current_epoch();
        let span = under(parent, || {
            spans::observation_span(
                &self.cfg.run,
                &self.cfg.session,
                epoch.navigation_seq,
                epoch.document_seq,
                epoch.mutation_seq,
                spec_name(spec),
            )
        });
        let started = Instant::now();
        let observed = self
            .observer
            .observe_shared(&mut *self.ctx, &spec)
            .instrument(span)
            .await;
        Metrics::global()
            .histogram(names::OBSERVATION_DURATION)
            .observe_duration(started.elapsed(), &[]);
        self.verify_pool_pin()?;
        let bundle = observed?;
        self.last = Some(Arc::clone(&bundle));
        Ok(bundle)
    }

    pub(crate) async fn navigate(
        &mut self,
        request: &crawlx_core::request::RequestEnvelopeV1,
    ) -> Result<NavigationResult, SessionError> {
        self.accepts_browser_commands()?;
        request
            .validate()
            .map_err(|_| crawlx_core::extensions::ExtensionError::Rejected)?;
        if request.method != "GET"
            || request.body.is_some()
            || request.header_control.is_some()
            || request.session_generation.is_some()
        {
            return Err(SessionError::Other(
                "unsupported extension browser request".into(),
            ));
        }
        let run = self.svc.runs.get(self.cfg.run).await?;
        run.config.extensions.route(&request.route)?;
        let mut lifecycle = if self.cfg.extension_cpu.is_some() && run.config.extensions.configured() {
            Some(crate::extensions::RequestLifecycle::new(&run.config.extensions)?)
        } else {
            None
        };
        let result = self.navigate_admitted(request, &run, lifecycle.as_mut()).await;
        if let Some(chain) = lifecycle {
            let outcome = lifecycle::terminal_for(&result);
            self.finish_lifecycle("navigation", chain, outcome).await;
        }
        result
    }

    /// Native re-admission of a replacement proposal from a reviewed extension. The proposal
    /// is never trusted: only a canonical, credential-free, in-scope GET URL with an exact
    /// registered handler can reach the browser, whether it stays on the origin or leaves it.
    fn readmit_replacement(
        &self,
        run: &crawlx_core::repo::CrawlRun,
        proposal: &crawlx_core::request::RequestEnvelopeV1,
    ) -> Result<CanonicalUrl, SessionError> {
        if proposal.method != "GET"
            || proposal.body.is_some()
            || proposal.header_control.is_some()
            || proposal.session_generation.is_some()
        {
            return Err(SessionError::Other(
                "unsupported extension browser request".into(),
            ));
        }
        // Credentials in a URL would travel to another origin; none may cross this boundary.
        if !proposal.url.url.username().is_empty() || proposal.url.url.password().is_some() {
            return Err(SessionError::Other("extension browser request denied".into()));
        }
        let proposed = crawlx_url::Canonicalizer::canonicalize_detailed(
            proposal.url.url.as_str(),
            &proposal.url.url,
            &self.cfg.canonicalize,
        )
        .map_err(|_| SessionError::Other("invalid extension browser URL".into()))?;
        let scope = crawlx_policy::ScopePolicy::new(&run.config)
            .map_err(|_| SessionError::Other("invalid extension scope policy".into()))?;
        if proposed.action_bearing
            || proposed.url.url != proposal.url.url
            || !scope.decide(&proposed.url, proposal.depth).is_admitted()
            || run.config.extensions.route(&proposal.route)? == crawlx_core::extensions::HandlerV1::Skip
        {
            return Err(SessionError::Other("extension browser request denied".into()));
        }
        Ok(proposed.url)
    }

    async fn navigate_admitted(
        &mut self,
        request: &crawlx_core::request::RequestEnvelopeV1,
        run: &crawlx_core::repo::CrawlRun,
        mut lifecycle: Option<&mut crate::extensions::RequestLifecycle>,
    ) -> Result<NavigationResult, SessionError> {
        use crawlx_core::extensions::{ExtensionEventV1, ExtensionReasonV1, ExtensionTerminalV1, HandlerV1};
        let url = &request.url;
        let mut route = &request.route;
        let mut replacement = None;
        let mut replacement_route = None;
        if let Some(chain) = lifecycle.as_deref_mut() {
            let prepared = chain.before_acquisition(request, &self.cfg.origin_cancel)?;
            if prepared.route == HandlerV1::Skip {
                let _ = chain.finish(ExtensionTerminalV1::Skipped(ExtensionReasonV1::Rejected));
                return Err(SessionError::Other("extension navigation skipped".into()));
            }
            if let Some(proposal) = prepared.replacement {
                match self.readmit_replacement(run, &proposal) {
                    Ok(readmitted) => {
                        replacement = Some(readmitted);
                        replacement_route = Some(proposal.route);
                    }
                    Err(error) => {
                        // Native denial is sticky; no callback result can turn it into an allow.
                        let _ = chain.finish(ExtensionTerminalV1::Skipped(ExtensionReasonV1::PolicyDenied));
                        return Err(error);
                    }
                }
            }
            self.browser_boundary(chain, ExtensionEventV1::BrowserPreNavigation)?;
        }
        if let Some(replacement_route) = replacement_route.as_ref() {
            route = replacement_route;
        }
        // Both original and changed navigation pass the same actor-owned context,
        // origin admission, robots/navigation guard and checked browser egress.
        // Initial read navigation is not an admitted mutation pipeline. Cancellation
        // drops its waiter; terminal cleanup still proves context/process death.
        let mut r = tokio::select! {
            biased;
            () = self.cfg.origin_cancel.cancelled() => return Err(SessionError::Cancelled),
            result = self.ctx.navigate(replacement.as_ref().unwrap_or(url)) => result?,
        };
        self.verify_pool_pin()?;
        // The checked context admitted this intent. Redirects change location, not handler identity.
        self.current_request_route = Some(route.clone());
        if let Some(chain) = lifecycle {
            // The effect happened: prove the same generation, fence and cancellation authority
            // still own this session before the boundary is recorded.
            self.verify_current_binding().await?;
            self.accepts_browser_commands()?;
            self.browser_boundary(chain, ExtensionEventV1::BrowserPostNavigation)?;
        }
        self.observer.reset();
        // a settle report per navigation (`settle_timeout` flags a page that never went idle)
        let settle = match QuiescenceWaiter::default()
            .settle(&mut *self.ctx, &self.cfg.settle)
            .await
        {
            Ok(s) => Some(s),
            Err(e) if e.is_target_crash() => return Err(e.into()),
            Err(_) => None,
        };
        if self.solve_pending_captcha().await? {
            if let Some(bundle) = &self.last {
                r.final_url = bundle.url.url.to_string();
                r.epoch = bundle.epoch;
                r.network_epoch = bundle.network.epoch_id.unwrap_or(r.network_epoch);
            }
            if let PageOpResult::Response { status, .. } = self.ctx.page_op(PageOp::DocumentResponse).await? {
                r.status = status;
            }
        }
        self.reveal_lazy_content().await?;
        self.verify_pool_pin()?;
        if self.cfg.traffic_export.is_some() {
            self.collect_traffic();
        }
        self.audit(
            "navigation",
            serde_json::json!({
                "url": url.url.as_str(),
                "finalUrl": r.final_url,
                "status": r.status,
                "epoch": r.epoch,
                "networkEpoch": r.network_epoch.0,
                "redirects": r.redirects,
                "blockedByEgress": r.blocked_by_egress,
                "settle": settle,
            }),
        )
        .await;
        Ok(r)
    }

    // ---- checkpoint / restore -----------------------------------------------------------

    async fn checkpoint(&mut self, reason: CheckpointReason) -> Result<CheckpointId, SessionError> {
        if matches!(reason, CheckpointReason::Shutdown) {
            // A graceful drain exports owned state only; it cannot admit target effects.
            // The command loop still checks the live lease and binding.
            self.accepts_owned_context()?;
        } else {
            self.accepts_browser_commands()?;
        }
        self.write_checkpoint(reason).await
    }

    /// Cleanup may export owned local state after cancellation without admitting
    /// new target interactions. The actor loop still validates the live lease first.
    async fn write_checkpoint(&mut self, reason: CheckpointReason) -> Result<CheckpointId, SessionError> {
        let url = self.last_url();
        let epoch = self.ctx.current_epoch();
        let rec = self
            .checkpointer
            .write(
                &mut *self.ctx,
                &url,
                self.current_request_route.as_deref(),
                epoch,
                self.action_seq,
                reason,
            )
            .await?;
        self.tracker.checkpointed(self.svc.clock.now());
        Ok(rec.id)
    }

    /// Checkpoint that must never fail the surrounding operation.
    async fn checkpoint_best_effort(&mut self, reason: CheckpointReason) {
        let result = self.checkpoint(reason).await;
        if let Err(e) = result {
            tracing::warn!(session = %self.cfg.session, error = %e, reason = reason.as_str(), "checkpoint skipped");
        }
    }

    async fn restore(&mut self, id: CheckpointId) -> Result<RestoreReport, SessionError> {
        self.accepts_browser_commands()?;
        let rec = self.checkpointer.get(id).await?;
        self.restore_record(&rec).await
    }

    pub(crate) async fn restore_record(
        &mut self,
        rec: &crawlx_core::repo::CheckpointRecord,
    ) -> Result<RestoreReport, SessionError> {
        let mut payload = self.checkpointer.load(rec).await?;
        let storage = zeroize::Zeroizing::new(payload.storage()?);
        self.ctx.import_storage(&storage).await?;
        let navigation = if payload.url.is_empty() {
            None
        } else {
            let url = url::Url::parse(&payload.url).map_err(|e| SessionError::Other(e.to_string()))?;
            let canon = crawlx_url::Canonicalizer::canonicalize_url(&url, &self.cfg.canonicalize)
                .map_err(|e| SessionError::Other(e.to_string()))?;
            let mut request = crawlx_core::request::RequestEnvelopeV1::get(canon, 0, None);
            request.route = payload
                .request_route
                .clone()
                .ok_or(crawlx_core::extensions::ExtensionError::UnknownRoute)?;
            Some(self.navigate(&request).await?)
        };
        // Replay recovery checkpoints count committed outcomes, not new proposals.
        self.action_seq = rec.action_seq;
        self.observer.reset();
        Ok(RestoreReport {
            checkpoint: rec.id,
            url: std::mem::take(&mut payload.url),
            request_route: self.current_request_route.clone(),
            navigation,
        })
    }

    // ---- login --------------------------------------------------------------------------

    async fn do_login(
        &mut self,
        material: LoginMaterial,
        fallback: bool,
    ) -> Result<LoginReport, SessionError> {
        self.accepts_browser_commands()?;
        if self.login_attempts >= MAX_LOGIN_ATTEMPTS {
            self.set_state(SessionState::Failed);
            return Err(SessionError::LoginFailed(format!(
                "login attempt limit ({MAX_LOGIN_ATTEMPTS}) reached"
            )));
        }
        self.login_attempts += 1;
        let settle = self.cfg.settle;
        match run_login(
            &mut *self.ctx,
            &mut self.observer,
            &material,
            &self.cfg.seed_origin,
            settle,
        )
        .await
        {
            Ok(report) => {
                // A completed browser plan is not authority to authenticate after a fence,
                // cancellation, or binding deadline changed while that plan was running.
                self.verify_current_binding().await?;
                self.accepts_browser_commands()?;
                self.login = Some(material);
                if self.state == SessionState::Authenticating {
                    self.set_state(SessionState::Ready);
                }
                self.last = self.observer.previous().cloned();
                self.audit(
                    "session.login",
                    serde_json::json!({
                        "ok": true,
                        "attempt": self.login_attempts,
                        "plan": crawlx_forms::login::BUILTIN_FORM_PLAN,
                        "fallback": fallback,
                    }),
                )
                .await;
                Ok(report)
            }
            Err(LoginFailure::Browser(e)) => Err(SessionError::Browser(e)),
            Err(e) => {
                self.audit(
                    "session.login",
                    serde_json::json!({
                        "ok": false,
                        "attempt": self.login_attempts,
                        "plan": crawlx_forms::login::BUILTIN_FORM_PLAN,
                        "fallback": fallback,
                        "reason": e.to_string(),
                    }),
                )
                .await;
                self.set_state(SessionState::Failed);
                Err(SessionError::LoginFailed(e.to_string()))
            }
        }
    }

    /// A recorded flow logged the session in: keep the material for recovery's re-login
    /// rung and leave `Authenticating`.
    fn authenticated(&mut self, material: LoginMaterial) -> Result<(), SessionError> {
        self.accepts_browser_commands()?;
        self.login = Some(material);
        if self.state == SessionState::Authenticating {
            self.set_state(SessionState::Ready);
        }
        self.last = self.observer.previous().cloned();
        Ok(())
    }

    async fn resolve_selector(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, SessionError> {
        self.accepts_browser_commands()?;
        Ok(self.ctx.resolve_selector(selector).await?)
    }

    async fn revalidate(&mut self, locator: &RuntimeLocator) -> Result<Revalidation, SessionError> {
        self.accepts_browser_commands()?;
        Ok(self.ctx.revalidate(locator, locator.epoch).await?)
    }

    async fn storage_digest(&mut self) -> Result<Digest, SessionError> {
        self.accepts_browser_commands()?;
        let blob = self.ctx.export_storage().await?;
        Ok(Digest::of("crawlx/worker/storage-state", &blob))
    }

    /// Strict complete structured export for encrypted profile custody only. The bytes are
    /// never logged or persisted here and leave the actor only inside a zeroizing buffer.
    async fn export_profile_storage(&mut self) -> Result<zeroize::Zeroizing<Vec<u8>>, SessionError> {
        self.accepts_browser_commands()?;
        Ok(zeroize::Zeroizing::new(self.ctx.export_profile_storage().await?))
    }

    async fn page_op(&mut self, op: PageOp) -> Result<PageOpResult, SessionError> {
        self.accepts_browser_commands()?;
        Ok(self.ctx.page_op(op).await?)
    }

    async fn document_response(&mut self, expected: ObservationEpoch) -> Result<PageOpResult, SessionError> {
        self.accepts_browser_commands()?;
        let current = self.ctx.current_epoch();
        if current != expected {
            return Err(SessionError::ObservationEpochChanged { expected, current });
        }
        let response = self.ctx.page_op(PageOp::DocumentResponse).await?;
        let current = self.ctx.current_epoch();
        if current != expected {
            return Err(SessionError::ObservationEpochChanged { expected, current });
        }
        Ok(response)
    }

    /// Native typing of a credential (recorded-flow `fill` with a placeholder). Like `Login`,
    /// the value only ever reaches `BrowserAction::Type` as `SecretOr`; the step is audited
    /// without it and never journaled.
    async fn type_credential(
        &mut self,
        target: RuntimeLocator,
        value: SecretOr<String>,
    ) -> Result<(), SessionError> {
        self.accepts_browser_commands()?;
        if self.live_origin().await? != self.cfg.seed_origin {
            return Err(SessionError::LoginFailed(
                "refusing to type a credential off the seed origin".to_owned(),
            ));
        }
        match self.ctx.revalidate(&target, target.epoch).await? {
            Revalidation::Actionable { .. } => {}
            other => {
                return Err(SessionError::LoginFailed(format!(
                    "credential field is not actionable: {}",
                    revalidation_name(&other)
                )))
            }
        }
        // This fill is never journaled, so a cancelled one is uncertain: the keystrokes may
        // already be in the page. The interactive token interrupts the effect and settle, the
        // context is marked failed (never reused or recovered) and cleanup closes it promptly.
        let effect_cancel = self.cfg.effect_cancel.clone();
        let settle = self.cfg.settle;
        let outcome = {
            let work = async {
                self.ctx
                    .perform(BrowserAction::Type {
                        target,
                        value,
                        clear_first: true,
                    })
                    .await?;
                QuiescenceWaiter::default()
                    .settle(&mut *self.ctx, &settle)
                    .await
                    .map(drop)
            };
            tokio::select! {
                biased;
                () = Self::effect_cancelled(effect_cancel.as_ref()) => None,
                result = work => Some(result),
            }
        };
        match outcome {
            None => {
                self.needs_recovery = false;
                self.set_state(SessionState::Failed);
                return Err(SessionError::Cancelled);
            }
            Some(result) => result?,
        }
        let after = self
            .observer
            .observe_shared(&mut *self.ctx, &self.cfg.after_spec)
            .await?;
        self.last = Some(after);
        self.audit(
            "session.login.step",
            serde_json::json!({ "op": "fill", "credential": true }),
        )
        .await;
        Ok(())
    }

    /// `scheme://host[:port]` of the page the context shows now (a cheap observation).
    async fn live_origin(&mut self) -> Result<String, SessionError> {
        let bundle = self
            .observer
            .observe_shared(&mut *self.ctx, &spec::cheap())
            .await?;
        let origin = bundle.url.origin.clone();
        self.last = Some(bundle);
        Ok(origin)
    }

    pub(crate) async fn audit(&mut self, kind: &str, mut payload: serde_json::Value) {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("session_id".to_owned(), serde_json::json!(self.cfg.session.0));
        }
        if let Err(e) = self.svc.events.append(self.cfg.run, kind, payload).await {
            tracing::warn!(error = %e, kind, "event not recorded");
        }
    }

    // ---- the per-action protocol ----------------------------------------

    fn halt_storage(&mut self, e: StoreError) -> SessionError {
        if matches!(e, StoreError::LeaseLost) {
            self.set_state(SessionState::Failed);
        } else {
            Metrics::global().counter(names::JOURNAL_HALTS).inc();
            self.set_state(SessionState::HaltedStorage);
        }
        SessionError::HaltedStorage(e)
    }

    /// Runtime safety guards, checked before the browser is touched. `Some(reason)` when the
    /// admitted action must not run: its verdict is not `allow`
    /// (`safety.invariant_violations{reason="performed_without_allow"}`), or its risk class is
    /// one the run's profile denies under every option (`safety.hard_deny_violations{reason=
    /// <class>}`). Both counters must stay 0: the kernel's `AdmittedAction` cannot be built
    /// any other way.
    fn safety_violation(&self, a: &AdmittedAction) -> Option<&'static str> {
        let m = Metrics::global();
        if a.verdict().decision != SafetyDecision::Allow {
            let reason = "performed_without_allow";
            m.counter(names::SAFETY_INVARIANT_VIOLATIONS)
                .inc_by(1, &[("reason", reason)]);
            return Some(reason);
        }
        let profile = self.svc.kernel.config().profile;
        let risk = a.risk();
        // `has_sinks = true` is the most permissive table row: a class denied there is denied
        // under every request option (crawlx_safety::profiles::decide only narrows it)
        if risk.default_decision(profile, true) == SafetyDecision::Deny {
            let reason = risk.as_str();
            m.counter(names::SAFETY_HARD_DENY_VIOLATIONS)
                .inc_by(1, &[("reason", reason)]);
            return Some(reason);
        }
        None
    }

    /// An admitted action that was not performed: counted per strategy and reason
    /// (`proposals.stale`) and per role and lane (`interactions.dropped_*`).
    fn drop_action(&self, id: ActionId, a: &AdmittedAction, reason: DropReason) -> ActionOutcome {
        let proposal = a.proposal();
        let m = Metrics::global();
        m.counter(names::PROPOSALS_STALE)
            .inc_by(1, &[("strategy", proposal.strategy), ("reason", reason.as_str())]);
        let family = match reason {
            DropReason::StaleEpoch | DropReason::IdentityChanged => names::INTERACTIONS_DROPPED_STALE,
            DropReason::NotActionable | DropReason::ConfirmDenied => names::INTERACTIONS_DROPPED_UNACTIONABLE,
        };
        m.counter(family).inc_by(
            1,
            &[
                ("role", &self.cfg.principal.0),
                ("lane", proposal.action.fidelity().lane().as_str()),
                ("reason", reason.as_str()),
            ],
        );
        ActionOutcome::dropped(id, reason)
    }

    /// While halted: the next command probes storage; a healthy answer returns the actor to
    /// `Ready` through `Recovering`, a lost lease fails it.
    async fn probe_storage(&mut self) -> Result<(), SessionError> {
        match self.svc.runs.get(self.cfg.run).await {
            Ok(_) => {
                self.set_state(SessionState::Recovering);
                self.set_state(SessionState::Ready);
                Ok(())
            }
            Err(e) => Err(self.halt_storage(e)),
        }
    }

    async fn execute(
        &mut self,
        a: AdmittedAction,
        settle: QuiescencePolicy,
        retry_of: Option<ActionId>,
        parent: &tracing::Span,
    ) -> Result<ActionOutcome, SessionError> {
        self.accepts_browser_commands()?;
        match self.state {
            SessionState::Ready | SessionState::Authenticating => {}
            SessionState::HaltedStorage => self.probe_storage().await?,
            other => {
                return Err(SessionError::NotReady {
                    state: other.as_str(),
                })
            }
        }
        let proposal = a.proposal();
        // Proposed under the driver's span so the row carries the run's trace id.
        // A durably approved action keeps its original parked identity: no second proposal or
        // approval row. The trusted actor binds it to this exact tenant/run/session/epoch.
        let id = if let Some(authority) = a.approval_authority().copied() {
            if authority.tenant != self.svc.tenant
                || authority.run != self.cfg.run
                || authority.session != self.cfg.session
                || authority.epoch != proposal.epoch
                || retry_of.is_some_and(|id| id != authority.action)
            {
                return Err(self.halt_storage(StoreError::LeaseLost));
            }
            authority.action
        } else {
            match retry_of {
                Some(id) => id,
                None => self
                    .svc
                    .journal
                    .propose(self.cfg.run, self.cfg.session, proposal, a.verdict())
                    .instrument(parent.clone())
                    .await
                    .map_err(|e| self.halt_storage(e))?,
            }
        };
        let fidelity = proposal.action.fidelity();
        let span = under(parent, || {
            spans::action_span(
                &self.cfg.run,
                &id,
                &proposal.key.id(),
                proposal.key.action_kind.as_str(),
                fidelity.lane().as_str(),
                fidelity.as_str(),
            )
        });
        self.execute_in_span(a, settle, id).instrument(span).await
    }

    /// Steps 1–7 of the protocol, inside the `action` span.
    async fn execute_in_span(
        &mut self,
        a: AdmittedAction,
        settle: QuiescencePolicy,
        id: ActionId,
    ) -> Result<ActionOutcome, SessionError> {
        let proposal = a.proposal();

        // Checkpoints can touch the context. Finish them before reserving capacity and
        // before the final epoch/form/kernel probes; no nested paced effect is allowed.
        if let Some(reason) = self.cfg.cadence.before_action(a.risk()) {
            self.checkpoint(reason).await.map_err(|error| match error {
                SessionError::Store(source) => self.halt_storage(source),
                other => other,
            })?;
        }
        let deadline = self.command_deadline();
        let prepare = async {
            tokio::select! {
                biased;
                () = self.cfg.origin_cancel.cancelled() => Err(SessionError::Cancelled),
                result = self.pacing.prepare(&mut *self.ctx, a.browser_action()) => result.map_err(SessionError::from),
            }
        };
        let prepared = if let Some(deadline) = deadline {
            let remaining = deadline
                .signed_duration_since(self.svc.clock.now())
                .to_std()
                .unwrap_or_default();
            match tokio::time::timeout(remaining, prepare).await {
                Ok(result) => result?,
                Err(_) => {
                    self.verify_current_binding().await?;
                    self.accepts_browser_commands()?;
                    return Err(
                        self.binding_error(crawlx_core::session_binding::SessionBindingError::Expired)
                    );
                }
            }
        } else {
            prepare.await?
        };
        // Admission may wait arbitrarily long on another context. Recheck authority and
        // refresh actual browser state, never stamp a new epoch onto admitted facts.
        self.verify_current_binding().await?;
        self.accepts_browser_commands()?;
        let observed = self.ctx.observe(spec::cheap()).await?;
        if !prepared.matches_source(&observed.url.origin) {
            return Ok(self.drop_action(id, &a, DropReason::StaleEpoch));
        }

        // 1. epoch check
        let cur = self.ctx.current_epoch();
        let compatible = child::epoch_check().in_scope(|| {
            let idempotent = proposal.class() == ProposalClass::Idempotent;
            self.cfg.epoch_policy.compatible(proposal.epoch, cur, idempotent)
        });
        if !compatible {
            return Ok(self.drop_action(id, &a, DropReason::StaleEpoch));
        }

        // 2. revalidate, then the kernel's live confirmation
        let live = match a.locator() {
            Some(locator) => {
                let span = child::revalidation();
                let revalidate_started = Instant::now();
                // Form channels belong to current structure, not the admitted proposal.
                // Observe before the final target probe so its destination remains freshest.
                let observed = self
                    .ctx
                    .observe(ObservationSpec {
                        revalidation_only: true,
                        ..ObservationSpec::default()
                    })
                    .await?;
                let hint = crawlx_strategies::frontier::observed_form_hints(&observed)
                    .remove(&locator.backend_node_id.0);
                let revalidated = self
                    .ctx
                    .revalidate(locator, proposal.epoch)
                    .instrument(span.clone())
                    .await?;
                let outcome = revalidation_name(&revalidated);
                Metrics::global()
                    .histogram(names::REVALIDATE_LATENCY)
                    .observe_duration(revalidate_started.elapsed(), &[("outcome", outcome)]);
                span.record("result", outcome);
                match revalidated {
                    Revalidation::Actionable { mut live } => {
                        if self.ctx.current_epoch() != observed.epoch {
                            return Ok(self.drop_action(id, &a, DropReason::StaleEpoch));
                        }
                        live.observed_form_hint = hint;
                        live
                    }
                    Revalidation::StaleEpoch { .. } => {
                        return Ok(self.drop_action(id, &a, DropReason::StaleEpoch))
                    }
                    Revalidation::IdentityChanged => {
                        return Ok(self.drop_action(id, &a, DropReason::IdentityChanged))
                    }
                    Revalidation::Detached
                    | Revalidation::NotVisible
                    | Revalidation::Disabled
                    | Revalidation::Obscured { .. }
                    | Revalidation::Unstable => {
                        return Ok(self.drop_action(id, &a, DropReason::NotActionable))
                    }
                }
            }
            None => LiveTargetFacts {
                current_url: observed.url.url.to_string(),
                ..LiveTargetFacts::default()
            },
        };
        let confirm = child::safety_confirm();
        let confirmed = confirm.in_scope(|| self.svc.kernel.confirm(&a, &live));
        if let Err(denied) = confirmed {
            confirm.record("safety.verdict", "deny");
            tracing::info!(session = %self.cfg.session, rule = denied.rule(), detail = %denied, "action dropped at confirmation");
            let mut dropped = self.drop_action(id, &a, DropReason::ConfirmDenied);
            dropped.live = Some(live);
            return Ok(dropped);
        }
        confirm.record("safety.verdict", "allow");
        // the last gate before the browser is touched: an admitted action whose
        // verdict is not `allow`, or whose class the profile hard-denies, is a kernel invariant
        // violation (SEV-1) and is refused here regardless of how it was built
        if let Some(reason) = self.safety_violation(&a) {
            tracing::error!(session = %self.cfg.session, reason, "safety invariant violated; action refused");
            return Ok(self.drop_action(id, &a, DropReason::ConfirmDenied));
        }

        self.accepts_browser_commands()?;
        // 3. T1: intent (a failure halts; nothing has touched the browser)
        let t1 = Instant::now();
        let intended = if let Some(authority) = a.approval_authority() {
            let lease = self
                .cfg
                .binding_owner
                .as_ref()
                .map(|(_, lease)| lease)
                .or_else(|| self.cfg.local_lease_owner.as_ref().map(|(_, lease)| lease))
                .ok_or(StoreError::LeaseLost);
            match lease {
                Ok(lease) if lease.fencing_token == authority.fence && cur == authority.epoch => {
                    self.svc
                        .approvals
                        .intend_approved(self.svc.tenant, lease, id, cur, a.verdict())
                        .instrument(child::journal_intent())
                        .await
                }
                _ => Err(StoreError::LeaseLost),
            }
        } else {
            self.svc
                .journal
                .intend(id, self.cfg.session, cur)
                .instrument(child::journal_intent())
                .await
        };
        Metrics::global()
            .histogram(names::JOURNAL_T1_DURATION)
            .observe_duration(t1.elapsed(), &[]);
        intended.map_err(|e| self.halt_storage(e))?;
        self.set_state(SessionState::Acting);
        crate::chaos::hit(crate::chaos::AFTER_INTENT_BEFORE_PERFORM).await;
        let result = self.perform_and_finish(&a, id, settle, prepared).await;
        if self.state == SessionState::Acting {
            self.set_state(SessionState::Ready);
        }
        result
    }

    /// Resolves when the interactive-owned effect token is cancelled; pending when absent.
    async fn effect_cancelled(token: Option<&tokio_util::sync::CancellationToken>) {
        match token {
            Some(token) => token.cancelled().await,
            None => std::future::pending::<()>().await,
        }
    }

    async fn perform_and_finish(
        &mut self,
        a: &AdmittedAction,
        id: ActionId,
        settle: QuiescencePolicy,
        prepared: crate::pacing::PreparedAction,
    ) -> Result<ActionOutcome, SessionError> {
        let started = Instant::now();
        let epoch_before = self.ctx.current_epoch();
        let lane = a.browser_action().fidelity().lane();
        // T1 and fault injection may yield long enough to lose authority. No browser
        // effect has started: close the intent as failed instead of dispatching it.
        let authority = self
            .verify_current_binding()
            .await
            .and_then(|()| self.accepts_browser_commands());
        if let Err(error) = authority {
            self.finish(
                a,
                id,
                Finish {
                    status: ActionStatus::Failed,
                    receipt: None,
                    settle: None,
                    after_state: None,
                    error: Some("dispatch_authority_lost".to_owned()),
                    robots_blocked: Vec::new(),
                },
                started,
            )
            .await?;
            return Err(error);
        }
        self.remember_effect(id, a.proposal().expected.clone());
        // 4. perform
        if let Some(trace) = &self.cfg.action_trace {
            trace.record(
                self.cfg.session,
                id,
                &a.proposal().key,
                a.browser_action(),
                self.last.as_deref(),
            );
        }
        let effect_cancel = self.cfg.effect_cancel.clone();
        let performed = {
            let effect = self
                .ctx
                .perform(a.browser_action().clone())
                .instrument(child::browser_mutation());
            tokio::select! {
                biased;
                () = Self::effect_cancelled(effect_cancel.as_ref()) => None,
                result = effect => Some(result),
            }
        };
        // Cancelled mid-dispatch: the command may already have reached the browser.
        let Some(performed) = performed else {
            self.finish_unknown(id, lane, "cancelled_during_effect").await;
            return Err(SessionError::Cancelled);
        };
        if let Err(error) = self.verify_pool_pin() {
            self.finish_unknown(id, lane, "proxy_session_pin_lost").await;
            return Err(error);
        }
        let receipt = match performed {
            Ok(r) => r,
            Err(e) if e.is_target_crash() => {
                self.finish_unknown(id, lane, &e.to_string()).await;
                return Err(SessionError::CrashedDuringAction(id));
            }
            Err(e) => {
                let robots_blocked = match &e {
                    BrowserError::RobotsBlocked { url, reason } => {
                        vec![BlockedNavigation::new(url.clone(), reason)]
                    }
                    _ => Vec::new(),
                };
                let failed = Finish {
                    status: ActionStatus::Failed,
                    receipt: None,
                    settle: None,
                    after_state: None,
                    error: Some(e.to_string()),
                    robots_blocked,
                };
                let outcome = self.finish(a, id, failed, started).await?;
                return if matches!(
                    &e,
                    BrowserError::Captcha(_) | BrowserError::EgressDenied(_) | BrowserError::SessionExpired
                ) {
                    Err(SessionError::Browser(e))
                } else {
                    Ok(outcome)
                };
            }
        };
        crate::chaos::hit(crate::chaos::AFTER_PERFORM_BEFORE_OUTCOME).await;
        // 5. settle
        let quiescence = child::quiescence();
        // An interactive-owned token interrupts settle at once. The effect was already sent,
        // so the outcome is journaled conservatively as unknown, never as "no effect".
        let effect_cancel = self.cfg.effect_cancel.clone();
        let settle_result = {
            let waiter_state = QuiescenceWaiter::default();
            let waiter = waiter_state.settle(&mut *self.ctx, &settle);
            tokio::select! {
                biased;
                () = Self::effect_cancelled(effect_cancel.as_ref()) => None,
                result = waiter.instrument(quiescence.clone()) => Some(result),
            }
        };
        let Some(settle_result) = settle_result else {
            self.finish_unknown(id, lane, "cancelled_during_settle").await;
            return Err(SessionError::Cancelled);
        };
        if let Err(error) = self.verify_pool_pin() {
            self.finish_unknown(id, lane, "proxy_session_pin_lost").await;
            return Err(error);
        }
        let settled = match settle_result {
            Ok(s) => {
                quiescence.record("settle_timeout", s.settle_timeout);
                Some(s)
            }
            Err(e) if e.is_target_crash() => {
                self.finish_unknown(id, lane, &e.to_string()).await;
                return Err(SessionError::CrashedDuringAction(id));
            }
            Err(e) => {
                tracing::warn!(error = %e, "settle failed after perform");
                None
            }
        };
        // The confirmed action is complete. Later lazy-content work owns fresh admission,
        // never the reserved authority used for this action's final confirmation.
        drop(prepared);
        // a navigation the page triggered that the guard refused (a clicked link, a script, a
        // popup): the browser never sent it and the document stayed where it was, so the action
        // did not take effect. Not an unknown outcome: nothing was in flight.
        let refused = self.ctx.drain_blocked_navigations();
        if let Some(first) = refused.first() {
            let egress_denied = refused.iter().any(|blocked| blocked.reason == "egress_denied");
            let blocked = Finish {
                status: ActionStatus::Failed,
                receipt: Some(receipt),
                settle: settled,
                after_state: None,
                error: Some(format!(
                    "{}: {}",
                    if egress_denied {
                        "egress_denied"
                    } else {
                        "robots_blocked"
                    },
                    first.reason
                )),
                robots_blocked: refused,
            };
            let outcome = self.finish(a, id, blocked, started).await?;
            return if egress_denied {
                Err(SessionError::Browser(BrowserError::EgressDenied(
                    "the egress policy refused the navigation".to_owned(),
                )))
            } else {
                Ok(outcome)
            };
        }
        let epoch_after = self.ctx.current_epoch();
        if epoch_after.navigation_seq != epoch_before.navigation_seq
            || epoch_after.document_seq != epoch_before.document_seq
        {
            // the action loaded a new document: reveal its lazy content before observing it
            if let Err(e) = self.reveal_lazy_content().await {
                self.finish_unknown(id, lane, &e.to_string()).await;
                return Err(SessionError::CrashedDuringAction(id));
            }
        }
        // 6. observe
        let after = match self
            .observer
            .observe_shared(&mut *self.ctx, &self.cfg.after_spec)
            .await
        {
            Ok(b) => Some(b),
            Err(e) if e.is_target_crash() => {
                self.finish_unknown(id, lane, &e.to_string()).await;
                return Err(SessionError::CrashedDuringAction(id));
            }
            Err(e) => {
                tracing::warn!(error = %e, "after-observation failed");
                None
            }
        };
        if let Err(error) = self.verify_pool_pin() {
            self.finish_unknown(id, lane, "proxy_session_pin_lost").await;
            return Err(error);
        }
        let analyzed = match &after {
            Some(b) => {
                let analyzed = self.analyzer.analyze(b).await;
                self.analyzer.record_metrics(&analyzed, &self.cfg.principal.0);
                Some(analyzed)
            }
            None => None,
        };
        if let Some(b) = &after {
            self.last = Some(Arc::clone(b));
        }
        // 7. T2: outcome + transition + traffic
        let done = Finish {
            status: ActionStatus::Succeeded,
            receipt: Some(receipt),
            settle: settled,
            after_state: analyzed.map(|x| x.state),
            error: None,
            robots_blocked: Vec::new(),
        };
        if let Err(error) = self.verify_pool_pin() {
            self.finish_unknown(id, lane, "proxy_session_pin_lost").await;
            return Err(error);
        }
        let mut outcome = self.finish(a, id, done, started).await?;
        outcome.after = after;
        Ok(outcome)
    }

    /// Drain the context's captured traffic for T2.
    /// Events of the action's own epoch or of a previously journaled epoch (`late`
    /// events of the previous action) keep it; events of any other epoch (the seed
    /// navigation's, which no action owns and no `network_epochs` row describes) and
    /// epoch-less events of an action without a receipt are stored unattributed with an
    /// explicit reason instead of a dangling epoch reference.
    fn drain_traffic(&mut self, receipt: Option<&ActionReceipt>) -> Vec<TrafficEvent> {
        let own = receipt.map(|r| r.network_epoch);
        self.collect_traffic();
        let mut events = std::mem::take(&mut self.pending_traffic);
        for t in &mut events {
            if t.unattributed_reason.is_some() {
                continue;
            }
            match (t.epoch_id, own) {
                (Some(e), _) if Some(e) == own || self.journaled_epochs.contains(&e) => {}
                (Some(_), _) => {
                    t.epoch_id = None;
                    t.unattributed_reason = Some(UnattributedReason::BeforeFirstEpoch);
                }
                (None, Some(_)) => {}
                (None, None) => t.unattributed_reason = Some(UnattributedReason::NoReceipt),
            }
        }
        events
    }

    /// Move the context's captured traffic into `pending_traffic` and hand a copy of each
    /// HTTP exchange to the traffic exporter (`WorkerConfig::traffic_export`).
    fn collect_traffic(&mut self) {
        let events = self.ctx.drain_traffic();
        if events.is_empty() {
            return;
        }
        if let Some(exporter) = &self.cfg.traffic_export {
            for ev in &events {
                if let Some(exchange) = browser_exchange(ev) {
                    exporter.record(exchange);
                }
            }
        }
        self.pending_traffic.extend(events);
        if self.pending_traffic.len() > MAX_PENDING_TRAFFIC {
            let excess = self.pending_traffic.len() - MAX_PENDING_TRAFFIC;
            self.pending_traffic.drain(..excess);
        }
    }

    /// Context-wide browser setup after the context was created or replaced: the
    /// consent-banner blocklist (`dynamic.blockConsentBanners`). Failing to block is logged, not
    /// fatal: the crawl is still correct, only noisier.
    pub(crate) async fn prepare_context(&mut self) {
        if self.cfg.block_urls.is_empty() {
            return;
        }
        let patterns = self.cfg.block_urls.clone();
        let count = patterns.len();
        match self.ctx.page_op(PageOp::BlockUrls(patterns)).await {
            Ok(_) => {
                tracing::debug!(session = %self.cfg.session, patterns = count, "consent banner requests are blocked")
            }
            Err(e) => {
                tracing::warn!(session = %self.cfg.session, error = %e, "consent banner blocking not applied")
            }
        }
    }

    /// Scroll the current document so lazily loaded content appears (`dynamic.maxScrollSteps`).
    /// Only a crashed target is an error; a page that cannot be scrolled is logged and skipped.
    async fn reveal_lazy_content(&mut self) -> Result<(), BrowserError> {
        let Some(spec) = self.cfg.lazy_scroll else {
            return Ok(());
        };
        match self.ctx.lazy_scroll(spec).await {
            Ok(report) => {
                self.stats
                    .scroll_steps
                    .fetch_add(u64::from(report.steps), Ordering::Relaxed);
                Ok(())
            }
            Err(e) if e.is_target_crash() => Err(e),
            Err(e) => {
                tracing::warn!(session = %self.cfg.session, error = %e, "lazy-content scroll skipped");
                Ok(())
            }
        }
    }

    async fn css_filter(
        &mut self,
        filter: &CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, SessionError> {
        self.accepts_browser_commands()?;
        Ok(self.ctx.css_filter(filter, targets).await?)
    }

    /// Parse the actor-owned settled DOM; no extension sees a browser handle.
    async fn extension_items(
        &mut self,
        action: ActionId,
    ) -> Result<
        (
            Vec<crawlx_core::dataset::AcceptedBatchV1>,
            Vec<crawlx_core::dataset::DeliveryBatchV1>,
        ),
        StoreError,
    > {
        if self.cfg.extension_cpu.is_none() {
            return Ok((Vec::new(), Vec::new()));
        }
        let run = self.svc.runs.get(self.cfg.run).await?;
        let wants_article = run.config.datasets.article_store()?.is_some();
        let wants_item = run.config.extensions.configured() && run.config.extensions.requires_document();
        if !wants_article && !wants_item {
            return Ok((Vec::new(), Vec::new()));
        }
        // A configured pipeline sees exactly one ordered lifecycle attempt per parsed page.
        let mut lifecycle = if run.config.extensions.configured() {
            Some(
                crate::extensions::RequestLifecycle::new(&run.config.extensions)
                    .map_err(|_| StoreError::Conflict("invalid extension pipeline".into()))?,
            )
        } else {
            None
        };
        let result = self
            .extension_items_attempt(action, &run, lifecycle.as_mut())
            .await;
        if let Some(chain) = lifecycle {
            use crawlx_core::extensions::{ExtensionReasonV1, ExtensionTerminalV1};
            let outcome = match &result {
                Ok(_) => ExtensionTerminalV1::Completed,
                Err(_) if self.cfg.origin_cancel.is_cancelled() => {
                    ExtensionTerminalV1::Skipped(ExtensionReasonV1::Cancelled)
                }
                Err(_) => ExtensionTerminalV1::Failed(ExtensionReasonV1::Processing),
            };
            self.finish_lifecycle("items", chain, outcome).await;
        }
        result
    }

    async fn extension_items_attempt(
        &mut self,
        action: ActionId,
        run: &crawlx_core::repo::CrawlRun,
        mut lifecycle: Option<&mut crate::extensions::RequestLifecycle>,
    ) -> Result<
        (
            Vec<crawlx_core::dataset::AcceptedBatchV1>,
            Vec<crawlx_core::dataset::DeliveryBatchV1>,
        ),
        StoreError,
    > {
        use crawlx_core::extensions::{ExtensionEventV1, HeaderFactsV1};
        let Some(cpu) = self.cfg.extension_cpu.clone() else {
            return Ok((Vec::new(), Vec::new()));
        };
        let wants_article = run.config.datasets.article_store()?.is_some();
        let wants_item = run.config.extensions.configured() && run.config.extensions.requires_document();
        if !wants_article && !wants_item {
            return Ok((Vec::new(), Vec::new()));
        }
        run.config
            .extensions
            .validate()
            .map_err(|_| StoreError::Conflict("invalid extension pipeline".into()))?;
        if self.cfg.origin_cancel.is_cancelled() {
            return Err(StoreError::Conflict("extension cancelled".into()));
        }
        let epoch = self.ctx.current_epoch();
        let (html, base) = match self.ctx.page_op(PageOp::Html).await {
            Ok(PageOpResult::Html { html, url })
                if html.len() <= crawlx_core::extensions::MAX_EXTENSION_BYTES =>
            {
                (
                    html,
                    url::Url::parse(&url)
                        .map_err(|_| StoreError::Conflict("invalid extension DOM base".into()))?,
                )
            }
            _ => return Err(StoreError::Conflict("bounded extension DOM unavailable".into())),
        };
        let (status, headers, content_type) = match self.ctx.page_op(PageOp::DocumentResponse).await {
            Ok(PageOpResult::Response {
                status,
                headers,
                content_type,
            }) => (status, headers, content_type),
            _ => {
                return Err(StoreError::Conflict(
                    "extension target evidence unavailable".into(),
                ))
            }
        };
        if self.ctx.current_epoch() != epoch {
            return Err(StoreError::Conflict("extension DOM epoch changed".into()));
        }
        // Response facts are bounded metadata. A skip here stops parsing before any byte is
        // handed to the CPU pool; the page itself was already admitted by the browser guard.
        if let Ok(facts) = HeaderFactsV1::new(status.unwrap_or(0), content_type.as_deref(), None) {
            if !self.item_boundary(lifecycle.as_deref_mut(), ExtensionEventV1::HeadersReceived(facts))? {
                return Ok((Vec::new(), Vec::new()));
            }
        }
        for event in [
            ExtensionEventV1::Response,
            ExtensionEventV1::Html,
            ExtensionEventV1::Parse,
        ] {
            if !self.item_boundary(lifecycle.as_deref_mut(), event)? {
                return Ok((Vec::new(), Vec::new()));
            }
        }
        let policy = run.config.acquisition.clone().unwrap_or_default();
        let extract = crawlx_extract::ExtractOptions {
            content: run.config.extract.content.clone(),
            language_detector: self.cfg.article_language_detector.clone(),
            status: status.unwrap_or(0),
            headers,
            content_type,
            acquisition_validation: Some(crate::acquisition::context(&policy, status, false)),
            ..crawlx_extract::ExtractOptions::default()
        };
        let pipeline = run.config.extensions.clone();
        let label = self
            .current_request_route
            .clone()
            .ok_or_else(|| StoreError::Conflict("extension request route unavailable".into()))?;
        let controls = self.cfg.context.request_controls.clone();
        let deadline_ms = pipeline
            .extensions
            .iter()
            .map(|e| u64::from(e.limits.deadline_ms))
            .sum::<u64>()
            .max(1000);
        let cancel = self.cfg.origin_cancel.child_token();
        let _cancel_on_drop = cancel.clone().drop_guard();
        let captcha = self.cfg.context.captcha_secrets.clone();
        let invalid = |reason: &str| StoreError::Conflict(format!("extension parser unavailable: {reason}"));
        // Bounded, budget-admitted snapshot held until the projection below is built.
        let literals = captcha
            .literal_snapshot_admitted(crate::url_plane::memory_plane::DYNAMIC_SECRET_SNAPSHOT_BYTES)
            .map_err(|_| invalid("dynamic-secret snapshot"))?;
        let secrets = crate::isolated_parser::IsolatedSecrets::new(
            controls.secret_values(),
            literals.value().iter().map(String::as_str),
        )
        .map_err(|_| invalid("secret projection"))?;
        let parser = crate::isolated_parser::shared().map_err(|_| invalid("isolated parser"))?;
        // The producer's `AdmittedText` stays the true owner of the input reservation: the
        // `Bytes` view only borrows it through `from_owner`, so no copy and no second charge. The
        // zero-byte permit is the carrier the parser grows for its own peak before allocating;
        // the output permit comes back with the document and is held until acceptance finishes.
        let carrier = crawlx_core::parser_memory::global()
            .try_reserve(0)
            .map_err(|_| invalid("admission"))?;
        let input = crawlx_core::parser_memory::Budgeted::new(
            bytes::Bytes::from_owner(lifecycle::AdmittedHtml(html)),
            carrier,
        );
        let request = crate::isolated_parser::PageRequest {
            base,
            options: extract,
            engine: crawlx_extract::isolated::Engine::Pipeline,
            secrets,
        };
        let parse = parser.extract_page(&cpu, input, request, &cancel);
        let page = tokio::select! {
            biased;
            () = self.cfg.origin_cancel.cancelled() => return Err(StoreError::Conflict("extension cancelled".into())),
            result = tokio::time::timeout(Duration::from_millis(deadline_ms), parse) =>
                result.map_err(|_| StoreError::Conflict("extension deadline exceeded".into()))?,
        };
        let page = page.map_err(|error| match error.into_extract_error() {
            crawlx_extract::ExtractError::ParseMemory(refused) if !refused.exceeds_budget() => {
                StoreError::ResourceExhausted {
                    resource: "parse_memory",
                    requested: refused.requested,
                    available: refused.available,
                    source: None,
                }
            }
            crawlx_extract::ExtractError::ParseMemory(_) => {
                StoreError::Conflict("extension DOM exceeds the parse-memory budget".into())
            }
            _ => StoreError::Conflict("extension DOM parse failed".into()),
        })?;
        // The output permit rides with the document until acceptance has finished.
        let (document, _output_permit) = page.document.into_parts();
        if !document.validation.as_ref().is_some_and(|v| v.content_accepted) {
            return Err(StoreError::Conflict(
                "extension content validation rejected".into(),
            ));
        }
        // The document moves through the pool job and back; nothing is cloned or re-admitted.
        let (document, mut candidate) = if wants_item {
            let task = cpu.run(move || {
                let candidate = match document.article.as_ref() {
                    None => Err(StoreError::Conflict(
                        "extension document envelope unavailable".into(),
                    )),
                    Some(article) => {
                        match crate::extensions::transform_document(&pipeline, &label, article, &cancel) {
                            Ok(item) => Ok(item),
                            Err(crawlx_core::extensions::ExtensionError::Rejected) => Ok(None),
                            Err(_) => Err(StoreError::Conflict("extension item failed".into())),
                        }
                    }
                };
                (document, candidate)
            });
            let (document, candidate) = tokio::select! {
                biased;
                () = self.cfg.origin_cancel.cancelled() => return Err(StoreError::Conflict("extension cancelled".into())),
                result = tokio::time::timeout(Duration::from_millis(deadline_ms), task) =>
                    result.map_err(|_| StoreError::Conflict("extension deadline exceeded".into()))?
                        .map_err(|_| StoreError::Conflict("extension CPU task failed".into()))?,
            };
            (document, candidate?)
        } else {
            (document, None)
        };
        if candidate.is_some() && !self.item_boundary(lifecycle, ExtensionEventV1::Item)? {
            candidate = None;
        }
        if self.ctx.current_epoch() != epoch || self.cfg.origin_cancel.is_cancelled() {
            return Err(StoreError::Conflict("extension DOM became stale".into()));
        }
        // Journal allocates a collision-free action namespace. Never truncate
        // the UUID or let an action rendition share a frontier page namespace.
        let page = self.svc.journal.dataset_page(action).await?;
        let acquisition_accepted = document.validation.as_ref().is_some_and(|v| v.content_accepted);
        let acceptance = crate::delivery::prepare_article_acceptance(
            self.svc.artifacts.as_ref(),
            &cpu,
            run,
            page,
            document,
            acquisition_accepted,
        );
        let (_, mut accepted, mut outbox) = tokio::select! {
            biased;
            () = self.cfg.origin_cancel.cancelled() => return Err(StoreError::Conflict("extension cancelled".into())),
            result = acceptance => result?,
        };
        if self.ctx.current_epoch() != epoch || self.cfg.origin_cancel.is_cancelled() {
            return Err(StoreError::Conflict("extension DOM became stale".into()));
        }
        if let Some(candidate) = candidate {
            let (_, batch, feeds) = crate::extensions::store_candidate(
                self.svc.artifacts.as_ref(),
                &cpu,
                run,
                page,
                &candidate,
                "native_article_v1.unicode_rules_v1",
                &self.cfg.context.request_controls,
                &self.cfg.context.captcha_secrets,
            )
            .await?;
            accepted.extend(batch);
            outbox.extend(feeds);
        }
        for batch in &mut accepted {
            for item in &mut batch.items {
                item.item_key = format!("action-{action}");
            }
        }
        Ok((accepted, outbox))
    }

    /// T2 with retries, inside a `journal_outcome` span; every attempt is timed
    /// (`journal.t2.duration`).
    async fn write_outcome(&mut self, id: ActionId, record: OutcomeRecord) -> Result<(), StoreError> {
        self.write_outcome_with_items(id, record, Vec::new(), Vec::new())
            .await
    }

    async fn write_outcome_with_items(
        &mut self,
        id: ActionId,
        record: OutcomeRecord,
        accepted: Vec<crawlx_core::dataset::AcceptedBatchV1>,
        outbox: Vec<crawlx_core::dataset::DeliveryBatchV1>,
    ) -> Result<(), StoreError> {
        let session_fence = self
            .cfg
            .context
            .session_binding
            .as_ref()
            .map_or(0, |b| b.lease_fence);
        let span = child::journal_outcome();
        span.record("status", record.status.as_str());
        let journal = Arc::clone(&self.svc.journal);
        self.cfg
            .journal_retry
            .run(|_| {
                let journal = Arc::clone(&journal);
                let record = record.clone();
                let accepted = accepted.clone();
                let outbox = outbox.clone();
                async move {
                    let t2 = Instant::now();
                    let written = journal
                        .finish_with_accepted(id, record, session_fence, accepted, Vec::new(), outbox)
                        .await;
                    Metrics::global()
                        .histogram(names::JOURNAL_T2_DURATION)
                        .observe_duration(t2.elapsed(), &[]);
                    written
                }
            })
            .instrument(span)
            .await
    }

    async fn finish(
        &mut self,
        a: &AdmittedAction,
        id: ActionId,
        f: Finish,
        started: Instant,
    ) -> Result<ActionOutcome, SessionError> {
        let Finish {
            status,
            receipt,
            settle,
            after_state,
            mut error,
            robots_blocked,
        } = f;
        let correlation = child::traffic_correlation();
        let traffic = correlation.in_scope(|| self.drain_traffic(receipt.as_ref()));
        if let Some(r) = &receipt {
            correlation.record("epoch_id", tracing::field::display(r.network_epoch));
        }
        correlation.record("late_count", traffic.iter().filter(|t| t.late).count());
        drop(correlation);
        let (accepted, outbox) = if status == ActionStatus::Succeeded && error.is_none() {
            match self.extension_items(id).await {
                Ok(items) => items,
                Err(_) => {
                    // A parse failure does not undo a performed effect or turn it
                    // into a retry. T2 keeps the real action outcome and failure code.
                    error = Some("extension_item_failed".into());
                    (Vec::new(), Vec::new())
                }
            }
        } else {
            (Vec::new(), Vec::new())
        };
        let record = OutcomeRecord {
            status,
            receipt: receipt.clone(),
            settle: settle.clone(),
            after_state: after_state.clone(),
            traffic,
            error: error.clone(),
            finished_at: self.svc.clock.now(),
        };
        if let Err(e) = self.write_outcome_with_items(id, record, accepted, outbox).await {
            // the action stays `intended`; the reaper will flip it to `unknown`
            return Err(self.halt_storage(e));
        }
        if let Some(r) = &receipt {
            self.journaled_epochs.insert(r.network_epoch);
        }
        // T2 is durable; a crash here loses nothing but the reply to the driver
        crate::chaos::hit(crate::chaos::AFTER_OUTCOME_BEFORE_NEXT_PROPOSAL).await;
        let lane = receipt
            .as_ref()
            .map_or_else(|| a.browser_action().fidelity().lane(), |r| r.lane);
        let proposal = a.proposal();
        let kind = proposal.key.action_kind.as_str();
        let m = Metrics::global();
        if status == ActionStatus::Succeeded {
            m.counter(names::ACTIONS_EXECUTED)
                .inc_by(1, &[("lane", lane.as_str()), ("kind", kind)]);
            m.counter(names::INTERACTIONS_EXECUTED).inc_by(
                1,
                &[
                    ("role", &self.cfg.principal.0),
                    ("lane", lane.as_str()),
                    ("strategy", proposal.strategy),
                    ("kind", kind),
                ],
            );
            // a value-partition input that ran; other input classes carry no partition
            if let Ok(partition) = proposal.key.input_class.0.parse::<Partition>() {
                m.counter(names::FORM_SUBMISSIONS)
                    .inc_by(1, &[("partition", partition.as_str())]);
            }
        }
        // Guard: synthetic DOM events never earn the trusted lane; must stay 0
        if receipt.as_ref().is_some_and(|r| {
            r.lane == crawlx_core::TrustLane::TrustedUi && r.fidelity == Fidelity::SyntheticDomEvent
        }) {
            tracing::error!(session = %self.cfg.session, kind, "synthetic action recorded on the trusted lane");
            m.counter(names::TRUSTED_LANE_SYNTHETIC_ACTIONS)
                .inc_by(1, &[("kind", kind)]);
        }
        m.histogram(names::ACTION_DURATION).observe_duration(
            started.elapsed(),
            &[
                ("lane", lane.as_str()),
                ("kind", kind),
                ("outcome", status.as_str()),
            ],
        );
        self.action_seq += 1;
        self.tracker.record_action();
        let now = self.svc.clock.now();
        if let Some(reason) = self.tracker.due(now) {
            self.checkpoint_best_effort(reason).await;
        }
        Ok(ActionOutcome {
            action_id: id,
            status,
            receipt,
            settle,
            after: None,
            after_state,
            dropped: None,
            live: None,
            error,
            robots_blocked,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// Crash after T1: T2 with `unknown` (no receipt, no transition) so reconciliation can start.
    async fn finish_unknown(&mut self, id: ActionId, lane: crawlx_core::TrustLane, why: &str) {
        let m = Metrics::global();
        m.counter(names::UNKNOWN_OUTCOME).inc();
        m.counter(names::INTERACTIONS_UNKNOWN_OUTCOME)
            .inc_by(1, &[("role", &self.cfg.principal.0), ("lane", lane.as_str())]);
        if self.unknown_pending.insert(id) {
            m.gauge(names::INTERACTIONS_UNKNOWN_UNRECONCILED).add(1.0, &[]);
        }
        let record = OutcomeRecord {
            status: ActionStatus::Unknown,
            receipt: None,
            settle: None,
            after_state: None,
            traffic: Vec::new(),
            error: Some(why.to_owned()),
            finished_at: self.svc.clock.now(),
        };
        if let Err(e) = self.write_outcome(id, record).await {
            tracing::warn!(error = %e, action = %id, "could not mark action unknown; the reaper will");
        }
    }

    fn remember_effect(&mut self, id: ActionId, effect: ExpectedEffect) {
        if self.recent.len() >= RECENT_EFFECTS {
            self.recent.pop_front();
        }
        self.recent.push_back((id, effect));
    }

    // ---- reconciliation -------------------------------------------------

    async fn reconcile(&mut self, id: ActionId) -> Result<Reconciliation, SessionError> {
        self.accepts_browser_commands()?;
        let rec = self.svc.journal.get(id).await?;
        if rec.session != self.cfg.session || rec.status != ActionStatus::Unknown {
            return Err(SessionError::NotReconcilable(id));
        }
        let bundle = self
            .observe(self.cfg.after_spec, &tracing::Span::current())
            .await?;
        let analyzed = self.analyzer.analyze(&bundle).await;
        self.svc.states.put_state(&analyzed.state).await?;
        let expected = self
            .recent
            .iter()
            .find(|(a, _)| *a == id)
            .map(|(_, e)| e.clone())
            .unwrap_or_default();
        let markers = effect_markers(&bundle, &expected, self.cfg.identity_version);
        // Route-level coverage coarsening is not an observation-cluster assignment.
        // Reconcile against the actual before state, never the reserved coverage cluster.
        let before = if rec.key.is_coarsened() {
            match rec.before_state {
                Some(id) => self
                    .svc
                    .states
                    .list_states(self.cfg.run)
                    .await?
                    .into_iter()
                    .find(|state| state.id == id)
                    .map(|state| state.cluster),
                None => None,
            }
        } else {
            Some(rec.key.state_cluster)
        };
        let same_cluster = before == Some(analyzed.cluster());
        let expectation_known = expected.navigates_to.is_some() || !expected.reveals.is_empty();
        let resolution = decide_resolution(
            same_cluster,
            !markers.is_empty(),
            rec.key.action_kind.is_idempotent(),
            expectation_known,
        );
        let mut reconciliation = Reconciliation {
            resolution,
            evidence: serde_json::json!({
                "before_cluster": before.map(|cluster| cluster.0),
                "after_cluster": analyzed.cluster().0,
                "same_cluster": same_cluster,
                "effect_markers": markers,
                "idempotent": rec.key.action_kind.is_idempotent(),
                "expectation_known": expectation_known,
                "url": bundle.url.url.as_str(),
                "state_id": analyzed.state.id.0,
            }),
            reconciled_at: self.svc.clock.now(),
        };
        let (accepted, outbox) = if resolution == ReconcileResolution::Applied {
            match self.extension_items(id).await {
                Ok(items) => items,
                Err(_) => {
                    // Parsing cannot turn a known applied effect into an unknown
                    // effect or authorize its replay during recovery.
                    reconciliation.evidence["extensionItem"] = serde_json::json!("unavailable");
                    (Vec::new(), Vec::new())
                }
            }
        } else {
            (Vec::new(), Vec::new())
        };
        let session_fence = self
            .cfg
            .context
            .session_binding
            .as_ref()
            .map_or(0, |b| b.lease_fence);
        self.svc
            .journal
            .reconcile_with_accepted(
                id,
                reconciliation.clone(),
                session_fence,
                accepted,
                Vec::new(),
                outbox,
            )
            .await?;
        if self.unknown_pending.remove(&id) {
            Metrics::global()
                .gauge(names::INTERACTIONS_UNKNOWN_UNRECONCILED)
                .add(-1.0, &[]);
        }
        Ok(reconciliation)
    }
}

/// Create the span `make` returns as a child of `parent` (the span the caller handed over the
/// mailbox), so actor spans nest under the driver's `phase` span.
pub(crate) fn under(parent: &tracing::Span, make: impl FnOnce() -> tracing::Span) -> tracing::Span {
    let _entered = parent.enter();
    make()
}

/// The exporter's view of one captured browser request: `None` for WebSocket and server-sent
/// event frames, which are not HTTP exchanges. Headers are the context's redacted ones, the URL
/// is redacted like every captured URL, and bodies are not exported (the context stores them as
/// artifacts, not text).
fn browser_exchange(ev: &TrafficEvent) -> Option<Exchange> {
    if matches!(ev.origin, TrafficOrigin::WebSocket | TrafficOrigin::EventSource) {
        return None;
    }
    let lowered = |headers: &[(String, String)]| -> BTreeMap<String, String> {
        headers
            .iter()
            .map(|(name, value)| (name.to_ascii_lowercase(), value.clone()))
            .collect()
    };
    let exchange = Exchange::new(
        "browser",
        ev.started_at,
        ev.method.clone(),
        ev.url.clone(),
        ev.status.unwrap_or(0),
    )
    .with_request(lowered(&ev.request_headers), None)
    .with_response(lowered(&ev.response_headers), None);
    Some(if ev.status.is_none() {
        exchange.with_error("no response")
    } else {
        exchange
    })
}

/// Name of an [`ObservationSpec`] preset for the `observation` span (`custom` otherwise).
fn spec_name(spec: ObservationSpec) -> &'static str {
    if spec == spec::after_action() {
        "after_action"
    } else if spec == spec::checkpoint() {
        "checkpoint"
    } else if spec == spec::novel_state() {
        "novel_state"
    } else if spec == spec::cheap() {
        "cheap"
    } else {
        "custom"
    }
}

/// Stable name of a [`Revalidation`] outcome for the `revalidation` span.
const fn revalidation_name(r: &Revalidation) -> &'static str {
    match r {
        Revalidation::Actionable { .. } => "actionable",
        Revalidation::Detached => "detached",
        Revalidation::IdentityChanged => "identity_changed",
        Revalidation::NotVisible => "not_visible",
        Revalidation::Disabled => "disabled",
        Revalidation::Obscured { .. } => "obscured",
        Revalidation::Unstable => "unstable",
        Revalidation::StaleEpoch { .. } => "stale_epoch",
    }
}

/// Reconciliation verdict (rule 4).
///
/// `Applied` when an expected effect is visible. Otherwise `NotApplied` only on strong
/// negative evidence: the session is still in the action's before-cluster and either the
/// kind is idempotent (a retry cannot repeat a write) or the action declared an effect that
/// is now known to be absent. Anything else is `Indeterminate`: in particular a non-idempotent
/// kind reconciled by a fresh actor, which does not know what the action was expected to do
/// (the expectation is not journaled), is never retried on "same cluster" alone, since the
/// `POST /counter` drill shows that the click may well have been applied. Only `NotApplied`
/// makes the key eligible again.
#[must_use]
pub fn decide_resolution(
    same_cluster: bool,
    markers_present: bool,
    idempotent: bool,
    expectation_known: bool,
) -> ReconcileResolution {
    if markers_present {
        ReconcileResolution::Applied
    } else if same_cluster && (idempotent || expectation_known) {
        ReconcileResolution::NotApplied
    } else {
        ReconcileResolution::Indeterminate
    }
}

/// Which expected effects are visible in `bundle` (`navigates_to`, `reveals`).
fn effect_markers(
    bundle: &ObservationBundle,
    expected: &ExpectedEffect,
    identity_version: crawlx_core::config::IdentityVersion,
) -> Vec<String> {
    let mut found = Vec::new();
    if let Some(target) = &expected.navigates_to {
        let url = bundle.url.url.as_str();
        if url == target || bundle.url.url.path() == target.as_str() {
            found.push(format!("navigated:{target}"));
        }
    }
    if !expected.reveals.is_empty() {
        let resolver =
            IdentityResolver::with_destination(bundle.url.url.clone(), CanonicalizeOptions::default())
                .with_identity_version(
                    identity_version,
                    crawlx_elements::locale::page_language(bundle.html.as_deref()),
                );
        let index = InMemoryIdentityIndex::new();
        let weights = MatchWeights::default();
        for c in CandidateDiscovery::discover(bundle, &DiscoveryConfig::default()) {
            if let Ok(r) = resolver.resolve(&c.descriptor, &index, &weights) {
                if expected.reveals.contains(&r.hash) {
                    found.push(format!("revealed:{}", r.hash));
                }
            }
        }
    }
    found
}

#[cfg(test)]
mod exit_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn closed_handle(exit: ActorExit) -> SessionHandle {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let (_, state) = watch::channel(SessionState::Closed);
        SessionHandle {
            tx,
            state,
            session: SessionId::new(),
            stats: Arc::new(SessionStats::default()),
            exit: Arc::new(parking_lot::Mutex::new(exit)),
            #[cfg(feature = "runtime-diagnostics")]
            task_monitor: crate::runtime::diagnostics::TaskMonitor::with_slow_poll_threshold(
                Duration::from_millis(10),
            ),
        }
    }

    #[tokio::test]
    async fn confirmed_retired_snapshot_keeps_typed_retirement_cause() {
        use crawlx_core::session_binding::{
            RetirementReason, SessionBindingError, SessionBindingV1, SessionIdentityV1, SessionLimits,
        };
        let session = crawlx_storage::testkit::sessions(crawlx_core::CrawlRunId::new(), 1, 1).remove(0);
        let digest = crawlx_core::hash::Digest::of("fixture", b"retired-snapshot");
        let identity = SessionIdentityV1::new(
            crawlx_core::TenantId::new(),
            &session,
            digest,
            digest,
            digest,
            digest,
            None,
        );
        let expiry = chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap();
        let mut limits = SessionLimits::default();
        limits.max_usage = 1;
        let mut binding = SessionBindingV1::new(identity, 7, expiry);
        binding
            .record_use(true, expiry - chrono::Duration::seconds(1), limits)
            .unwrap();
        binding.finish_cleanup(true).unwrap();
        let failure = Arc::new(SessionError::Binding(SessionBindingError::Draining {
            reason: RetirementReason::UsageLimit,
        }));
        let handle = closed_handle(ActorExit {
            failure: Some(Arc::clone(&failure)),
            cleanup: Some(Ok(())),
            retired_binding: Some(binding.clone()),
            ..ActorExit::default()
        });
        assert_eq!(handle.retired_binding(), Some(binding));
        let Err(SessionError::ActorStopped(actual)) = handle.shutdown(ShutdownReason::Completed).await else {
            panic!("retirement cause was discarded after confirmed cleanup");
        };
        assert!(Arc::ptr_eq(&actual, &failure));
        assert!(closed_handle(ActorExit::default()).retired_binding().is_none());
    }

    #[tokio::test]
    async fn successful_cached_cleanup_never_clears_binding_expiry_or_generic_actor_loss() {
        let gone = closed_handle(ActorExit {
            cleanup: Some(Ok(())),
            ..ActorExit::default()
        });
        assert!(matches!(
            gone.shutdown(ShutdownReason::Completed).await,
            Err(SessionError::ActorGone),
        ));
        let requested = closed_handle(ActorExit {
            shutdown_completed: true,
            ..ActorExit::default()
        });
        requested.shutdown(ShutdownReason::Completed).await.unwrap();
        requested.shutdown(ShutdownReason::Completed).await.unwrap();
        let binding = closed_handle(ActorExit {
            expiry: Some(SessionExpiry::Binding),
            cleanup: Some(Ok(())),
            ..ActorExit::default()
        });
        assert!(matches!(
            binding.shutdown(ShutdownReason::Completed).await,
            Err(SessionError::Binding(
                crawlx_core::session_binding::SessionBindingError::Expired
            )),
        ));
    }

    #[tokio::test]
    async fn execution_only_retirement_requires_confirmed_successful_cleanup() {
        let clean = closed_handle(ActorExit {
            expiry: Some(SessionExpiry::Execution),
            cleanup: Some(Ok(())),
            ..ActorExit::default()
        });
        clean.shutdown(ShutdownReason::Completed).await.unwrap();
        clean.shutdown(ShutdownReason::Completed).await.unwrap();
        let failed = closed_handle(ActorExit {
            expiry: Some(SessionExpiry::Execution),
            cleanup: Some(Err(SessionError::Store(StoreError::Unavailable(
                "cleanup fixture".into(),
            )))),
            ..ActorExit::default()
        });
        assert!(matches!(
            failed.shutdown(ShutdownReason::Completed).await,
            Err(SessionError::Store(StoreError::Unavailable(_))),
        ));
        let unconfirmed = closed_handle(ActorExit {
            expiry: Some(SessionExpiry::Execution),
            ..ActorExit::default()
        });
        assert!(matches!(
            unconfirmed.shutdown(ShutdownReason::Completed).await,
            Err(SessionError::ActorGone),
        ));
    }

    #[tokio::test]
    async fn independent_exit_evidence_survives_cleanup_and_later_clock_completion() {
        for failure in [
            SessionError::Store(StoreError::LeaseLost),
            SessionError::Store(StoreError::Unavailable("repository fixture".into())),
            SessionError::Store(StoreError::Conflict("profile fixture".into())),
            SessionError::ActorGone,
        ] {
            let failure = Arc::new(failure);
            let handle = closed_handle(ActorExit {
                expiry: Some(SessionExpiry::Execution),
                failure: Some(Arc::clone(&failure)),
                cleanup: Some(Ok(())),
                shutdown_completed: true,
                retired_binding: None,
            });
            for result in [
                Err::<(), _>(handle.closed_error()),
                handle.shutdown(ShutdownReason::Completed).await,
            ] {
                let Err(SessionError::ActorStopped(actual)) = result else {
                    panic!("independent exit evidence was discarded");
                };
                assert!(Arc::ptr_eq(&actual, &failure));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn generation_profile_drift_fails_actor_command_with_terminal_pin_error() {
        use crawlx_core::error::{Classify, ErrorClass};
        use crawlx_core::session_binding::{SessionBindingV1, SessionIdentityV1};
        use crawlx_fetch::proxyx::{PoolSelector, PoolTier, ProxyxRoute};

        let fixture =
            crate::run::login_lifecycle_tests::fixture_with_bounds(chrono::Duration::minutes(5), None, None)
                .await;
        fixture.handle.shutdown(ShutdownReason::Completed).await.unwrap();
        let mut config = fixture.rc.session_config(&fixture.lease.session);
        config.awaits_login = false;
        let route = ProxyxRoute::new(
            &"http://pool.fixture:8080".parse().unwrap(),
            None,
            crawlx_core::secret::SecretOr::secret("fixture-org-key".into()),
            PoolSelector::default(),
        )
        .unwrap();
        let digest = crawlx_core::hash::Digest::of("fixture", b"identity");
        let identity = SessionIdentityV1::new(
            fixture.rc.stores.tenant,
            &fixture.lease.session,
            digest,
            digest,
            route.egress_digest(PoolTier::Basic),
            digest,
            None,
        );
        let mut binding = SessionBindingV1::new(
            identity,
            fixture.lease.fencing_token,
            fixture.rc.clock.now() + chrono::Duration::minutes(5),
        );
        config.pool_pin = Some(route.bind(PoolTier::Basic, &binding, None).unwrap());
        binding.identity.profile = Some(digest);
        config.context.session_binding = Some(binding);
        config.local_lease_owner = Some((Arc::clone(&fixture.rc.stores.leases), fixture.lease.clone()));
        let pooled = fixture
            .rc
            .pool
            .acquire(config.context.clone(), false)
            .await
            .unwrap();
        let handle = SessionActor::spawn(
            config,
            fixture.rc.services(),
            Arc::clone(&fixture.analyzer),
            7,
            pooled,
        )
        .await
        .unwrap();
        let error = handle
            .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                fixture.rc.seed_url().unwrap(),
                0,
                None,
            ))
            .await
            .unwrap_err();
        let root = match &error {
            SessionError::ActorStopped(root) => root.as_ref(),
            error => error,
        };
        assert!(matches!(
            root,
            SessionError::ProxyPin(crawlx_fetch::proxyx::ProxyxError::SessionUnavailable)
        ));
        assert_eq!(error.class(), ErrorClass::Terminal);
        let _ = handle.shutdown(ShutdownReason::Completed).await;
    }
}
