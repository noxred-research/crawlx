//! Per-plane counters and terminal reasons.

use serde::{Deserialize, Serialize};

/// Independent counters; `completed` never means "everything was crawled".
#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Debug)]
pub struct Counters {
    /// URLs (or interactions/states) found, whether or not they were kept; equals the sum of the four disposition counters below.
    pub discovered: u64,
    /// Discovered items accepted into the frontier for processing.
    pub admitted: u64,
    /// Discovered items dropped because the same canonical key was already seen.
    pub deduplicated: u64,
    /// Discovered items rejected by crawl policy (scope, limits, safety).
    pub policy_blocked: u64,
    /// Discovered items rejected because `robots.txt` disallows them.
    pub robots_blocked: u64,
    /// Admitted items whose processing was started; equals the sum of the five outcome counters below.
    pub attempted: u64,
    /// Attempts that completed successfully.
    pub succeeded: u64,
    /// Attempts that ended in an error.
    pub failed: u64,
    /// Attempts given up before completion (e.g. retries or budget exhausted).
    pub abandoned: u64,
    /// Attempts whose target could not be reached (network, DNS, robots outage).
    pub unreachable: u64,
    /// Attempts whose result could not be determined (e.g. crash after the action was issued).
    pub unknown_outcome: u64,
}

impl Counters {
    /// Invariants: `discovered = admitted + deduplicated +
    /// policy_blocked + robots_blocked` and `attempted = succeeded + failed +
    /// abandoned + unreachable + unknown_outcome`.
    #[must_use]
    pub const fn invariants_hold(&self) -> bool {
        self.discovered == self.admitted + self.deduplicated + self.policy_blocked + self.robots_blocked
            && self.attempted
                == self.succeeded + self.failed + self.abandoned + self.unreachable + self.unknown_outcome
    }
}

/// Counters per plane.
#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, Debug)]
pub struct PlaneCounters {
    /// Counters for URL fetches (discovery and fetching of pages).
    pub urls: Counters,
    /// Counters for browser interactions (actions proposed and performed on a page).
    pub interactions: Counters,
    /// Counters for distinct UI states observed.
    pub states: Counters,
}

/// Why a run ended.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TerminalReason {
    /// Every admitted URL/state was processed; nothing left to do.
    FrontierExhausted,
    /// A configured count limit (pages, depth, actions) was hit.
    LimitReached,
    /// The run's wall-clock deadline passed.
    DeadlineReached,
    /// A crawl policy decided to stop the run.
    PolicyStopped,
    /// The run was cancelled by the user.
    Cancelled,
    /// An unrecoverable error aborted the run.
    FatalError,
    /// The session recovery ladder ran out of options (e.g. repeated browser crashes).
    RecoveryExhausted,
    /// The run's authorization record was revoked or expired while the run was in flight;
    /// the run status is `failed`.
    AuthorizationRevoked,
}

impl TerminalReason {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FrontierExhausted => "frontier_exhausted",
            Self::LimitReached => "limit_reached",
            Self::DeadlineReached => "deadline_reached",
            Self::PolicyStopped => "policy_stopped",
            Self::Cancelled => "cancelled",
            Self::FatalError => "fatal_error",
            Self::RecoveryExhausted => "recovery_exhausted",
            Self::AuthorizationRevoked => "authorization_revoked",
        }
    }
}

/// The concrete cause behind a [`TerminalReason`]: the stop criterion that fired or the kind of
/// failure that left a drained run with nothing kept.
///
/// It is recorded in the `terminalDetail` field of the run's terminal event, never in the stored
/// run row, so it adds no storage state; every value implies exactly one reason
/// ([`Self::reason`]).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TerminalDetail {
    /// `limits.urls` fetches were started.
    UrlsLimit,
    /// `limits.items` pages were kept.
    ItemsLimit,
    /// `limits.errors` fetches ended failed or unreachable.
    ErrorsLimit,
    /// `limits.idleSeconds` passed without a newly kept page.
    IdleTimeout,
    /// `limits.durationSeconds` passed.
    Deadline,
    /// The artifact spool reached `limits.diskPressurePermille`; the run drained.
    DiskPressure,
    /// The frontier drained and no page was kept: the fetches failed after their retries ran out.
    RetriesExhausted,
    /// The frontier drained and no page was kept: responses exceeded the body limit.
    ByteLimit,
    /// The frontier drained and no page was kept: the seed URL could not be fetched.
    SeedError,
    /// The frontier drained and no page was kept: responses failed the content validation.
    ContentValidationFailed,
}

impl TerminalDetail {
    /// Stable `snake_case` name, identical to the serde form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UrlsLimit => "urls_limit",
            Self::ItemsLimit => "items_limit",
            Self::ErrorsLimit => "errors_limit",
            Self::IdleTimeout => "idle_timeout",
            Self::Deadline => "deadline",
            Self::DiskPressure => "disk_pressure",
            Self::RetriesExhausted => "retries_exhausted",
            Self::ByteLimit => "byte_limit",
            Self::SeedError => "seed_error",
            Self::ContentValidationFailed => "content_validation_failed",
        }
    }

    /// The reason a run with this detail ends with.
    #[must_use]
    pub const fn reason(self) -> TerminalReason {
        match self {
            Self::UrlsLimit | Self::ItemsLimit => TerminalReason::LimitReached,
            Self::ErrorsLimit | Self::IdleTimeout | Self::DiskPressure => TerminalReason::PolicyStopped,
            Self::Deadline => TerminalReason::DeadlineReached,
            Self::RetriesExhausted | Self::ByteLimit | Self::SeedError | Self::ContentValidationFailed => {
                TerminalReason::FrontierExhausted
            }
        }
    }
}

impl std::str::FromStr for TerminalDetail {
    type Err = crate::error::CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "urls_limit" => Self::UrlsLimit,
            "items_limit" => Self::ItemsLimit,
            "errors_limit" => Self::ErrorsLimit,
            "idle_timeout" => Self::IdleTimeout,
            "deadline" => Self::Deadline,
            "disk_pressure" => Self::DiskPressure,
            "retries_exhausted" => Self::RetriesExhausted,
            "byte_limit" => Self::ByteLimit,
            "seed_error" => Self::SeedError,
            "content_validation_failed" => Self::ContentValidationFailed,
            o => {
                return Err(crate::error::CoreError::UnknownEnum {
                    kind: "TerminalDetail",
                    value: o.to_owned(),
                })
            }
        })
    }
}

/// Stable machine code of a run the worker refused before it started.
///
/// The closed vocabulary lets clients branch on the cause without parsing the human message.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunFailureCode {
    /// A browser-backed run needs a checkpoint key provider and this worker has none.
    CheckpointKeysRequired,
    /// Any other run configuration this worker refused; the message names the setting.
    ConfigRefused,
}

impl RunFailureCode {
    /// Stable `snake_case` name, identical to the serde form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CheckpointKeysRequired => "checkpoint_keys_required",
            Self::ConfigRefused => "config_refused",
        }
    }
}

/// Why a run ended `failed` without running: a typed code and a short operator-facing message.
///
/// It is recorded in the `failure` field of the run's terminal event, never in the stored run
/// row, so it adds no storage state. The message names a setting, never a secret value.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct RunFailure {
    /// Stable machine code.
    pub code: RunFailureCode,
    /// Short human-readable explanation, at most [`Self::MAX_MESSAGE_CHARS`] characters.
    pub message: String,
}

impl RunFailure {
    /// Longest stored message, in characters.
    pub const MAX_MESSAGE_CHARS: usize = 256;

    /// A failure with `message` cut to [`Self::MAX_MESSAGE_CHARS`] characters.
    #[must_use]
    pub fn new(code: RunFailureCode, message: &str) -> Self {
        Self {
            code,
            message: message.chars().take(Self::MAX_MESSAGE_CHARS).collect(),
        }
    }

    /// Kind of the run event that records a refusal before the run ends `failed`.
    pub const EVENT_KIND: &'static str = "run.refused";

    /// The body of the [`Self::EVENT_KIND`] event (and of the terminal event's `failure` field).
    #[must_use]
    pub fn event_payload(&self) -> serde_json::Value {
        serde_json::json!({ "failure": self })
    }

    /// The failure a [`Self::event_payload`] body carries; anything outside the closed code
    /// vocabulary reads as absent, and the message is cut to its bound.
    #[must_use]
    pub fn from_event_payload(payload: &serde_json::Value) -> Option<Self> {
        let failure = serde_json::from_value::<Self>(payload.get("failure")?.clone()).ok()?;
        Some(Self::new(failure.code, &failure.message))
    }
}

/// Run status.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Accepted but not yet started.
    Queued,
    /// Actively crawling.
    Running,
    /// Suspended by the user; can be resumed.
    Paused,
    /// Finished normally (see [`TerminalReason`] for why it stopped).
    Completed,
    /// Ended because of an error.
    Failed,
    /// Stopped by the user before finishing.
    Cancelled,
}

impl RunStatus {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Can the run no longer change status (`Completed`, `Failed` or `Cancelled`)?
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

impl std::str::FromStr for RunStatus {
    type Err = crate::error::CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "queued" => Self::Queued,
            "running" => Self::Running,
            "paused" => Self::Paused,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            o => {
                return Err(crate::error::CoreError::UnknownEnum {
                    kind: "RunStatus",
                    value: o.to_owned(),
                })
            }
        })
    }
}

/// `actions.status` machine.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    /// Planned but not yet journaled as started.
    Proposed,
    /// Journaled as about to execute (written before the browser acts).
    Intended,
    /// Executed and the outcome was observed.
    Succeeded,
    /// Executed and failed.
    Failed,
    /// Execution was interrupted or no receipt was recorded, so the effect is undetermined until reconciled.
    Unknown,
    /// Outcome of an earlier attempt was settled by re-observation (see [`ReconcileResolution`]).
    Reconciled,
}

impl ActionStatus {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Proposed => "proposed",
            Self::Intended => "intended",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Reconciled => "reconciled",
        }
    }

    /// Legal transitions.
    #[must_use]
    pub const fn can_transition_to(self, to: Self) -> bool {
        matches!(
            (self, to),
            (Self::Proposed, Self::Intended)
                | (Self::Intended, Self::Succeeded | Self::Failed | Self::Unknown)
                | (Self::Unknown, Self::Reconciled)
                | (Self::Succeeded | Self::Failed, Self::Reconciled)
                | (Self::Reconciled, Self::Intended)
        )
    }
}

impl std::str::FromStr for ActionStatus {
    type Err = crate::error::CoreError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "proposed" => Self::Proposed,
            "intended" => Self::Intended,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "unknown" => Self::Unknown,
            "reconciled" => Self::Reconciled,
            o => {
                return Err(crate::error::CoreError::UnknownEnum {
                    kind: "ActionStatus",
                    value: o.to_owned(),
                })
            }
        })
    }
}

/// Outcome of reconciling an `unknown` action by re-observation.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ReconcileResolution {
    /// Re-observation shows the action took effect.
    Applied,
    /// Re-observation shows the action did not take effect, so it may be re-run.
    NotApplied,
    /// Re-observation could not tell either way.
    Indeterminate,
}

impl ReconcileResolution {
    /// Stable `snake_case` name, identical to the serde form and the stored value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::NotApplied => "not_applied",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::{RunFailure, RunFailureCode, TerminalDetail, TerminalReason};

    const ALL: [TerminalDetail; 10] = [
        TerminalDetail::UrlsLimit,
        TerminalDetail::ItemsLimit,
        TerminalDetail::ErrorsLimit,
        TerminalDetail::IdleTimeout,
        TerminalDetail::Deadline,
        TerminalDetail::DiskPressure,
        TerminalDetail::RetriesExhausted,
        TerminalDetail::ByteLimit,
        TerminalDetail::SeedError,
        TerminalDetail::ContentValidationFailed,
    ];

    #[test]
    fn every_terminal_detail_round_trips_through_its_name() {
        for detail in ALL {
            assert_eq!(detail.as_str().parse::<TerminalDetail>().unwrap(), detail);
            assert_eq!(
                serde_json::to_value(detail).unwrap(),
                serde_json::Value::String(detail.as_str().to_owned())
            );
        }
        assert!("nope".parse::<TerminalDetail>().is_err());
    }

    #[test]
    fn every_terminal_detail_implies_one_reason_and_the_details_are_distinct() {
        let names: std::collections::BTreeSet<_> = ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(names.len(), ALL.len());
        assert_eq!(TerminalDetail::ItemsLimit.reason(), TerminalReason::LimitReached);
        assert_eq!(
            TerminalDetail::ErrorsLimit.reason(),
            TerminalReason::PolicyStopped
        );
        assert_eq!(TerminalDetail::Deadline.reason(), TerminalReason::DeadlineReached);
        assert_eq!(
            TerminalDetail::SeedError.reason(),
            TerminalReason::FrontierExhausted
        );
    }

    #[test]
    fn run_failure_event_payload_round_trips_and_stays_bounded() {
        let failure = RunFailure::new(RunFailureCode::CheckpointKeysRequired, "needs a key provider");
        let payload = failure.event_payload();
        assert_eq!(payload["failure"]["code"], "checkpoint_keys_required");
        assert_eq!(RunFailure::from_event_payload(&payload), Some(failure));
        let long = RunFailure::new(RunFailureCode::ConfigRefused, &"é".repeat(1_000));
        assert_eq!(long.message.chars().count(), RunFailure::MAX_MESSAGE_CHARS);
        let hostile =
            serde_json::json!({"failure": {"code": "config_refused", "message": "m".repeat(9_999)}});
        let read = RunFailure::from_event_payload(&hostile).unwrap();
        assert_eq!(read.message.chars().count(), RunFailure::MAX_MESSAGE_CHARS);
    }

    #[test]
    fn run_failure_codes_are_a_closed_vocabulary() {
        for code in [
            RunFailureCode::CheckpointKeysRequired,
            RunFailureCode::ConfigRefused,
        ] {
            assert_eq!(serde_json::to_value(code).unwrap(), code.as_str());
        }
        for payload in [
            serde_json::json!({}),
            serde_json::json!({"failure": {"code": "invented", "message": "x"}}),
            serde_json::json!({"failure": {"code": "config_refused"}}),
            serde_json::json!({"failure": "config_refused"}),
        ] {
            assert_eq!(RunFailure::from_event_payload(&payload), None, "{payload}");
        }
    }
}
