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
