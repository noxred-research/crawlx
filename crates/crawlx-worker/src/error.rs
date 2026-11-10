//! Typed errors of the worker.

use crawlx_core::error::{Classify, ErrorClass};
use crawlx_core::{ActionId, BrowserError, CoreError, StoreError};
use crawlx_fetch::FetchError;
use crawlx_observe::ObserveError;
use crawlx_scheduler::SchedulerError;
use thiserror::Error;

/// Failures of one Session Actor operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The actor task ended; the handle is stale.
    #[error("session actor is gone")]
    ActorGone,
    /// A retired actor's independently observed failure, retained across later callers.
    #[error("session actor stopped: {0}")]
    ActorStopped(#[source] std::sync::Arc<SessionError>),
    /// Run cancellation stopped a command before its browser effect was dispatched.
    #[error("session command cancelled before dispatch")]
    Cancelled,
    /// An admitted execution clock elapsed before dispatch; no effect may start.
    #[error("session execution deadline reached before dispatch")]
    ExecutionDeadlineReached,
    /// Binding eligibility failed without granting replacement authority.
    #[error(transparent)]
    Binding(#[from] crawlx_core::session_binding::SessionBindingError),
    /// The command is not accepted in the current lifecycle state.
    #[error("session is {state}; command not accepted")]
    NotReady {
        /// Lifecycle state the session is in.
        state: &'static str,
    },
    /// The browser died after the journal recorded intent; the action is `unknown`.
    #[error("browser crashed during action {0}")]
    CrashedDuringAction(ActionId),
    /// A required checkpoint or journal write failed; mutation waits until storage is healthy.
    #[error("storage halted the session")]
    HaltedStorage(#[source] StoreError),
    /// Every rung of the recovery ladder failed.
    #[error("recovery exhausted: {0}")]
    RecoveryExhausted(String),
    #[error("login failed: {0}")]
    /// Login failed.
    LoginFailed(String),
    #[error("action {0} is not in a reconcilable state")]
    /// Not reconcilable.
    NotReconcilable(ActionId),
    #[error("no checkpoint to restore for this session")]
    /// No checkpoint.
    NoCheckpoint,
    #[error("browser error: {0}")]
    /// Browser.
    Browser(#[from] BrowserError),
    #[error("observation error: {0}")]
    /// Observe.
    Observe(#[from] ObserveError),
    #[error("storage error: {0}")]
    /// Store.
    Store(#[from] StoreError),
    /// Native request lifecycle or handler route refusal.
    #[error("extension error: {0}")]
    Extension(#[from] crawlx_core::extensions::ExtensionError),
    /// Checkpoint encryption or authenticated decryption failed.
    #[error("checkpoint encryption failed: {0}")]
    CheckpointCrypto(#[from] crawlx_storage::checkpoint_crypto::CheckpointCryptoError),
    /// Checkpoint payload serialization failed without exposing its content.
    #[error("checkpoint payload encoding failed")]
    CheckpointEncoding(#[source] serde_json::Error),
    /// The saved payload predates explicit handler identity and cannot be resumed safely.
    #[error("unsupported checkpoint version")]
    CheckpointVersion,
    #[error("{0}")]
    /// Other.
    Other(String),
}

impl SessionError {
    pub(crate) fn is_recovery_exhausted(&self) -> bool {
        match self {
            Self::RecoveryExhausted(_) => true,
            Self::ActorStopped(cause) => cause.is_recovery_exhausted(),
            _ => false,
        }
    }

    /// Did the browser target die?
    #[must_use]
    pub fn is_target_crash(&self) -> bool {
        match self {
            Self::Browser(e) => e.is_target_crash(),
            Self::Observe(e) => e.is_target_crash(),
            _ => false,
        }
    }
}

impl Classify for SessionError {
    fn class(&self) -> ErrorClass {
        match self {
            Self::ActorGone
            | Self::ActorStopped(_)
            | Self::Cancelled
            | Self::ExecutionDeadlineReached
            | Self::Binding(_)
            | Self::RecoveryExhausted(_)
            | Self::LoginFailed(_)
            | Self::Other(_) => ErrorClass::Terminal,
            Self::NotReady { .. } | Self::NoCheckpoint => ErrorClass::Retryable,
            // the browser died after intent: the action is `unknown` until reconciled
            Self::CrashedDuringAction(_) => ErrorClass::OutcomeUnknown,
            Self::HaltedStorage(e) | Self::Store(e) => e.class(),
            Self::NotReconcilable(_) => ErrorClass::Stale,
            Self::CheckpointCrypto(_)
            | Self::CheckpointEncoding(_)
            | Self::CheckpointVersion
            | Self::Extension(_) => ErrorClass::Terminal,
            Self::Browser(e) => e.class(),
            Self::Observe(e) => {
                if e.is_target_crash() {
                    ErrorClass::Retryable
                } else {
                    ErrorClass::Terminal
                }
            }
        }
    }
}

/// Failures of the worker as a whole.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WorkerError {
    #[error("storage error: {0}")]
    /// Store.
    Store(#[from] StoreError),
    /// Operator-approved delivery failed.
    #[error("delivery error: {0}")]
    Delivery(#[from] crate::delivery::DeliveryError),
    #[error("scheduler error: {0}")]
    /// Scheduler.
    Scheduler(#[from] SchedulerError),
    /// The session lease heartbeat or its monitor failed to join.
    #[error("session heartbeat task failed")]
    SessionHeartbeatTask(#[source] tokio::task::JoinError),
    #[error("session error: {0}")]
    /// Session.
    Session(#[from] SessionError),
    #[error("browser error: {0}")]
    /// Browser.
    Browser(#[from] BrowserError),
    #[error("fetch error: {0}")]
    /// Fetch.
    Fetch(#[from] crawlx_fetch::FetchError),
    /// Pure extraction admission failed before any target request.
    #[error("extraction policy: {0}")]
    Extraction(#[from] crawlx_extract::ExtractError),
    /// Approved article-language bundle or runtime failed admission.
    #[error("article language provider: {0}")]
    ArticleLanguage(#[from] crawlx_model::article_language::ArticleLanguageError),
    /// The bounded operator bundle-loading task failed.
    #[error("article language loader task failed")]
    ArticleLanguageTask(#[source] tokio::task::JoinError),
    /// Native PDF structural sanitization failed before binary artifact approval.
    #[error("pdf sanitization failed")]
    PdfSanitization(#[source] crawlx_extract::parse::ParseError),
    /// The bounded native PDF sanitizer task failed.
    #[error("pdf sanitizer task failed")]
    PdfSanitizationTask(#[source] tokio::task::JoinError),
    /// The bounded raw-response diagnostic projection task failed.
    #[error("raw response projection task failed")]
    RawCaptureTask(#[source] tokio::task::JoinError),
    /// Finalized virtual-row serialization exceeded its bounded output allowance.
    #[error("virtual rows finalized output limit exceeded")]
    VirtualRowsOutputLimit(#[source] serde_json::Error),
    /// Versioned acquisition admission failed before any target request.
    #[error("acquisition policy: {0}")]
    AcquisitionPolicy(#[from] crawlx_core::acquisition::AcquisitionPolicyError),
    /// A required execution backend failed its worker-local capability gate.
    #[error("acquisition capability unavailable: {0}")]
    AcquisitionUnavailable(&'static str),
    #[error("policy error: {0}")]
    /// Policy.
    Policy(#[from] crawlx_policy::PolicyError),
    #[error("url error: {0}")]
    /// URL (canonicalization, scope patterns such as `dynamic.alwaysBrowserPaths`).
    Url(#[from] crawlx_url::UrlError),
    #[error("safety kernel error: {0}")]
    /// Kernel.
    Kernel(#[from] crawlx_safety::KernelError),
    /// Strategy configuration or proposal failure, preserving its error class and source.
    #[error("strategy error: {0}")]
    Strategy(#[from] crawlx_strategies::StrategyError),
    /// Explicit discovery provider, source protocol or resource-limit refusal.
    #[error(transparent)]
    Discovery(#[from] crawlx_core::discovery::DiscoveryErrorV1),
    #[error("invalid configuration: {0}")]
    /// Config.
    Config(String),
    /// Operator request identity configuration failure, retaining the redacted source chain.
    #[error(transparent)]
    RequestIdentityKey(#[from] crawlx_core::secret::RequestIdentityKeyError),
    #[error("policy denied: {0}")]
    /// Refused by run policy before anything ran (e.g. browser attach outside
    /// `test_environment` / `authorized_security_test`).
    PolicyDenied(String),
    /// A controlled fixture capability failed its isolation or lifecycle checks.
    #[error("fixture evaluation: {0}")]
    FixtureEvaluation(#[from] crate::fixture_evaluation::FixtureEvaluationError),
    #[error("authorization: {0}")]
    /// The run's authorization record is missing, unreadable, revoked, expired or not yet valid
    /// ([`AuthorizationStop`](crate::authorization::AuthorizationStop)).
    Authorization(#[from] crate::authorization::AuthorizationStop),
    #[error("{0}")]
    /// Core.
    Core(#[from] CoreError),
    #[error("telemetry error: {0}")]
    /// Telemetry.
    Telemetry(#[from] crawlx_telemetry::TelemetryError),
    #[error("i/o error: {0}")]
    /// Io.
    Io(#[from] std::io::Error),
    /// Archive codec or bounded stream failure, preserving its source chain.
    #[error("archive finalization failed: {0}")]
    Archive(#[from] crawlx_storage::archive::ArchiveError),
    /// Archive blocking task failed without publishing a manifest.
    #[error("archive writer task failed")]
    ArchiveTask(#[source] tokio::task::JoinError),
    #[error("{0}")]
    /// Other.
    Other(String),
}

impl Classify for WorkerError {
    fn class(&self) -> ErrorClass {
        match self {
            Self::Store(e) => e.class(),
            Self::Delivery(error) => error.class(),
            Self::Scheduler(SchedulerError::Store(s)) => s.class(),
            Self::Session(e) => e.class(),
            Self::Browser(e) => e.class(),
            Self::Strategy(error) => error.class(),
            // A full parse-memory budget is transient; a charge larger than the whole
            // budget can never fit and must not be retried.
            Self::Extraction(crawlx_extract::ExtractError::ParseMemory(refused))
                if !refused.exceeds_budget() =>
            {
                ErrorClass::Retryable
            }
            Self::Extraction(_)
            | Self::AcquisitionPolicy(_)
            | Self::AcquisitionUnavailable(_)
            | Self::ArticleLanguage(_)
            | Self::ArticleLanguageTask(_)
            | Self::SessionHeartbeatTask(_)
            | Self::PdfSanitization(_)
            | Self::RawCaptureTask(_)
            | Self::VirtualRowsOutputLimit(_)
            | Self::PdfSanitizationTask(_) => ErrorClass::Terminal,
            Self::Fetch(e) => match e {
                FetchError::OriginAdmission(e) => e.class(),
                FetchError::EgressDenied(_) | FetchError::PeerNotPinned { .. } => ErrorClass::PolicyDenied,
                // Parent allowances are terminal. Retrying these errors outside acquisition
                // would reset a deadline or replay an operation after cancellation.
                FetchError::AcquisitionAllowance
                | FetchError::AcquisitionDeadline
                | FetchError::AcquisitionCancelled
                | FetchError::MetaRefresh { .. }
                | FetchError::MetaRefreshTarget { .. }
                | FetchError::AcquisitionUnavailable => ErrorClass::Terminal,
                FetchError::Resolve { .. } | FetchError::Transport(_) => ErrorClass::Retryable,
                // the request may have reached the origin: idempotent GET/HEAD only, so a
                // retry is still safe, but the class records that the outcome is not known
                FetchError::Timeout(_) => ErrorClass::OutcomeUnknown,
                // a refusal the gateway never repairs (bad key, option denied, budget spent) is
                // terminal; a saturated or briefly failing pool may clear
                FetchError::PoolRefused { cause, .. } if cause.is_some_and(|c| !c.is_retryable()) => {
                    ErrorClass::Terminal
                }
                FetchError::PoolRefused { .. } => ErrorClass::Retryable,
                FetchError::InvalidUrl { .. }
                | FetchError::UnsupportedMethod(_)
                | FetchError::InvalidRedirect { .. }
                | FetchError::TooManyRedirects { .. }
                | FetchError::InvalidHeader { .. }
                | FetchError::Pool(_)
                | FetchError::ClientBuild(_) => ErrorClass::Terminal,
                FetchError::Io(e) => e.class(),
            },
            Self::Policy(_)
            | Self::Kernel(_)
            | Self::PolicyDenied(_)
            | Self::Authorization(_)
            | Self::FixtureEvaluation(_)
            | Self::RequestIdentityKey(_) => ErrorClass::PolicyDenied,
            Self::Core(e) => e.class(),
            Self::Io(e) => e.class(),
            Self::Archive(crawlx_storage::archive::ArchiveError::Io(error)) => error.class(),
            Self::Archive(_) | Self::ArchiveTask(_) => ErrorClass::Terminal,
            Self::Config(_) | Self::Url(_) | Self::Telemetry(_) | Self::Other(_) | Self::Discovery(_) => {
                ErrorClass::Terminal
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn actor_retirement_preserves_recovery_exhaustion_without_inventing_it() {
        let exhausted = SessionError::ActorStopped(std::sync::Arc::new(SessionError::RecoveryExhausted(
            "all recovery rungs failed".to_owned(),
        )));
        assert!(exhausted.is_recovery_exhausted());
        for cause in [
            SessionError::ActorGone,
            SessionError::Store(StoreError::LeaseLost),
            SessionError::ExecutionDeadlineReached,
        ] {
            assert!(!SessionError::ActorStopped(std::sync::Arc::new(cause)).is_recovery_exhausted());
        }
    }

    /// Every variant of both worker enums maps; a browser crash after intent is `OutcomeUnknown`.
    #[test]
    fn acquisition_stop_errors_never_restart_parent_allowance() {
        for error in [
            FetchError::AcquisitionAllowance,
            FetchError::AcquisitionDeadline,
            FetchError::AcquisitionCancelled,
            FetchError::AcquisitionUnavailable,
        ] {
            assert_eq!(WorkerError::Fetch(error).class(), ErrorClass::Terminal);
        }
    }

    #[test]
    fn parse_memory_pressure_is_retryable_but_an_oversize_page_is_terminal() {
        let per = crawlx_extract::parse_budget::PARSE_BYTES_PER_INPUT_BYTE;
        let budget = std::sync::Arc::new(crawlx_extract::parse_budget::ParseBudget::new(2 * per));
        let held = budget.try_charge_input(2).unwrap();
        // fits the budget once `held` is released: transient pressure
        let pressure = budget.try_charge_input(1).unwrap_err();
        assert!(!pressure.exceeds_budget());
        let error = WorkerError::Extraction(crawlx_extract::ExtractError::ParseMemory(pressure));
        assert_eq!(error.class(), ErrorClass::Retryable);
        drop(held);
        // larger than the whole budget: can never fit
        let oversize = budget.try_charge_input(3).unwrap_err();
        assert!(oversize.exceeds_budget());
        let error = WorkerError::Extraction(crawlx_extract::ExtractError::ParseMemory(oversize));
        assert_eq!(error.class(), ErrorClass::Terminal);
        let policy = WorkerError::Extraction(crawlx_extract::ExtractError::TooLarge {
            what: "bytes",
            limit: 1,
            actual: 2,
        });
        assert_eq!(policy.class(), ErrorClass::Terminal);
    }

    #[test]
    fn every_session_and_worker_variant_maps_to_a_class() {
        let id = ActionId::new();
        let session = [
            (SessionError::ActorGone, ErrorClass::Terminal),
            (
                SessionError::ActorStopped(std::sync::Arc::new(SessionError::ActorGone)),
                ErrorClass::Terminal,
            ),
            (SessionError::ExecutionDeadlineReached, ErrorClass::Terminal),
            (
                SessionError::Binding(crawlx_core::session_binding::SessionBindingError::Expired),
                ErrorClass::Terminal,
            ),
            (SessionError::NotReady { state: "paused" }, ErrorClass::Retryable),
            (SessionError::CrashedDuringAction(id), ErrorClass::OutcomeUnknown),
            (
                SessionError::HaltedStorage(StoreError::Unavailable("db".into())),
                ErrorClass::Retryable,
            ),
            (SessionError::RecoveryExhausted("r".into()), ErrorClass::Terminal),
            (SessionError::LoginFailed("l".into()), ErrorClass::Terminal),
            (SessionError::NotReconcilable(id), ErrorClass::Stale),
            (SessionError::NoCheckpoint, ErrorClass::Retryable),
            (
                SessionError::CheckpointCrypto(
                    crawlx_storage::checkpoint_crypto::CheckpointCryptoError::Unavailable,
                ),
                ErrorClass::Terminal,
            ),
            (
                SessionError::CheckpointEncoding(serde_json::from_str::<serde_json::Value>("{").unwrap_err()),
                ErrorClass::Terminal,
            ),
            (
                SessionError::Browser(BrowserError::Timeout(5)),
                ErrorClass::OutcomeUnknown,
            ),
            (
                SessionError::Browser(BrowserError::TargetCrashed),
                ErrorClass::Retryable,
            ),
            (SessionError::Store(StoreError::LeaseLost), ErrorClass::Stale),
            (SessionError::Other("o".into()), ErrorClass::Terminal),
        ];
        for (e, want) in &session {
            assert_eq!(e.class(), *want, "{e}");
        }
        let worker = [
            (
                WorkerError::Store(StoreError::Backend("b".into())),
                ErrorClass::Retryable,
            ),
            (
                WorkerError::Scheduler(SchedulerError::Store(StoreError::LeaseLost)),
                ErrorClass::Stale,
            ),
            (
                WorkerError::Session(SessionError::CrashedDuringAction(id)),
                ErrorClass::OutcomeUnknown,
            ),
            (
                WorkerError::Browser(BrowserError::Unsupported("u".into())),
                ErrorClass::PolicyDenied,
            ),
            (
                WorkerError::Fetch(FetchError::UnsupportedMethod("PUT".into())),
                ErrorClass::Terminal,
            ),
            (
                WorkerError::Strategy(crawlx_strategies::StrategyError::UnavailableVersion {
                    strategy: "interaction_bfs",
                    version: 99,
                }),
                ErrorClass::Terminal,
            ),
            (
                WorkerError::Discovery(crawlx_core::discovery::DiscoveryErrorV1::ProviderUnavailable(
                    crawlx_core::discovery::DiscoveryProviderV1::GoogleNews,
                )),
                ErrorClass::Terminal,
            ),
            (WorkerError::Config("c".into()), ErrorClass::Terminal),
            (
                WorkerError::Url(crawlx_url::UrlError::NoHost),
                ErrorClass::Terminal,
            ),
            (
                WorkerError::Core(CoreError::Serialization("s".into())),
                ErrorClass::Terminal,
            ),
            (
                WorkerError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)),
                ErrorClass::Retryable,
            ),
            (WorkerError::Other("o".into()), ErrorClass::Terminal),
            (
                WorkerError::PolicyDenied("attach".into()),
                ErrorClass::PolicyDenied,
            ),
        ];
        for (e, want) in &worker {
            assert_eq!(e.class(), *want, "{e}");
        }
    }
}
