//! Trail verifier: the correctness invariants of the
//! stored trail, written as checks over a point-in-time [`TrailSnapshot`].
//!
//! The database trail is the correctness record; a run whose rows cannot
//! support replay and explanation is wrong even if every page was fetched.
//! The invariants: an executed action has a `transitions` row and
//! epoch fields; an `intended` action beyond the lease window must be
//! `unknown` or `reconciled`; `seq` is dense per session; the
//! lane is a function of the fidelity, and transitions/epochs carry the
//! action's lane.
//!
//! [`verify_trail`] builds the snapshot from a [`MemoryStore`] or a database of any engine
//! ([`DurableStore`]) and runs [`verify_snapshot`], which is pure so
//! tests can inject each violation and assert it is reported.
//!
//! Correctness verification recomputes every state's applicable fingerprint. Missing
//! evidence is reported separately from corruption, and [`TrailReport::is_clean`] is
//! false when any state is unverifiable, including legitimate ZDR unavailability.

use crate::BenchError;
use chrono::Duration as ChronoDuration;
use crawlx_core::config::RetentionMode;
use crawlx_core::counters::{ActionStatus, PlaneCounters};
use crawlx_core::hash::Digest;
use crawlx_core::observation::FingerprintInput;
use crawlx_core::repo::{
    ActionJournal, ActionRecord, ArtifactStore, FrontierRepo, FrontierStateCounts, ModelDecisionRepo,
    NewState, RunRepo, StateRepo,
};
use crawlx_core::state::StateSignature;
use crawlx_core::traffic::{TrustLane, UnattributedReason};
use crawlx_core::{
    ActionId, ArtifactRef, CrawlRunId, ModelDecisionId, NetworkEpochId, SafetyDecisionId, SessionId, StateId,
    StoreError, Timestamp,
};
use crawlx_state::Fingerprinter;
use crawlx_storage::memory::{MemoryNetworkEpoch, MemoryTransition};
use crawlx_storage::tenant::Tenancy;
use crawlx_storage::{InspectRepo, LeaseRepo, MemoryStore, Store, TrailReads};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use crawlx_worker::DurableStore;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

/// Grace after the lease TTL within which an `unknown` action must be
/// reconciled (stale-lease SLO: 2 minutes).
pub const RECONCILE_WINDOW: Duration = Duration::from_secs(120);

/// Artifact kind holding the [`FingerprintInput`] of a state.
pub const AX_TREE_ARTIFACT: &str = "ax_tree";

/// One `transitions` row as the verifier sees it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct TrailTransition {
    /// The action that caused the transition.
    pub action: ActionId,
    /// Session of the action.
    pub session: SessionId,
    /// State before the action.
    pub before: StateId,
    /// State after the action, when captured.
    pub after: Option<StateId>,
    /// Network epoch attributed to the action.
    pub network_epoch: Option<NetworkEpochId>,
    /// Lane recorded on the transition.
    pub lane: TrustLane,
}

/// One `network_epochs` row as the verifier sees it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct TrailEpoch {
    /// Epoch id.
    pub id: NetworkEpochId,
    /// Session of the epoch.
    pub session: SessionId,
    /// Action the epoch is attributed to; `None` for navigation-only epochs.
    pub action: Option<ActionId>,
    /// Lane recorded on the epoch.
    pub lane: TrustLane,
}

/// The attribution columns of one `traffic_events` row as the verifier sees it.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct TrailTraffic {
    /// Row order within the run (`event_id` on PostgreSQL, capture order in memory).
    pub event_id: u64,
    /// Action the row was journaled under, when known.
    pub action: Option<ActionId>,
    /// Epoch the row is attributed to.
    pub epoch: Option<NetworkEpochId>,
    /// Explicit reason for a missing epoch.
    pub unattributed_reason: Option<UnattributedReason>,
}

/// Outcome of checking one state's signature against its stored artifact.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[non_exhaustive]
pub enum FingerprintOutcome {
    /// Every derivable field of the recomputed signature equals the stored one.
    Match,
    /// At least one derivable field differs; names of the differing fields.
    Mismatch {
        /// Differing `StateSignature` fields.
        fields: Vec<&'static str>,
    },
    /// The artifact could not be read or decoded as a [`FingerprintInput`].
    Unreadable {
        /// Why.
        reason: String,
    },
    /// The stored signature's algorithm version differs from this build's; not comparable.
    VersionSkew {
        /// Stored `StateSignature.version`.
        stored: u16,
    },
    /// The check does not apply to this state.
    Skipped {
        /// Stable reason for excluding the state.
        reason: &'static str,
    },
    /// The state cannot be verified; this is not evidence of corruption.
    Unverifiable {
        /// Stable reason for unavailable evidence.
        reason: &'static str,
    },
}

/// One state's result in the fingerprint reproducibility check.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
pub struct FingerprintSample {
    /// The state.
    pub state: StateId,
    /// What recomputation found.
    pub outcome: FingerprintOutcome,
}

/// Everything the invariants need, captured at one instant.
#[derive(Clone, Debug)]
pub struct TrailSnapshot {
    /// The run under inspection.
    pub run: CrawlRunId,
    /// The store's notion of "now" (DB clock or injected clock), for lease-window checks.
    pub now: Timestamp,
    /// Session lease TTL in force for the store.
    pub lease_ttl: Duration,
    /// Every `actions` row of the run.
    pub actions: Vec<ActionRecord>,
    /// Every `transitions` row of the run.
    pub transitions: Vec<TrailTransition>,
    /// Every `network_epochs` row of the run.
    pub epochs: Vec<TrailEpoch>,
    /// Ids of every `states` row of the run.
    pub state_ids: BTreeSet<StateId>,
    /// Artifact references from the states' artifact manifests.
    pub state_artifacts: Vec<(StateId, ArtifactRef)>,
    /// Digests present in the artifact index, or `None` when the store has no
    /// index and presence was checked directly against the object store
    /// (then `missing_artifacts` lists the unreachable references).
    pub artifact_digests: Option<BTreeSet<Digest>>,
    /// Artifact references the object store could not serve (memory path).
    pub missing_artifacts: Vec<ArtifactRef>,
    /// The run's progress counters.
    pub counters: PlaneCounters,
    /// The run's frontier rows counted by status: what the URL counters are checked against.
    pub frontier: FrontierStateCounts,
    /// The run's retention mode; `zdr` skips the artifact checks.
    pub retention: RetentionMode,
    /// Attribution columns of every `traffic_events` row of the run.
    pub traffic: Vec<TrailTraffic>,
    /// Ids of every `safety_decisions` row of the run.
    pub safety_decisions: BTreeSet<SafetyDecisionId>,
    /// Ids of every `model_decisions` row of the run.
    pub model_decisions: BTreeSet<ModelDecisionId>,
    /// One fingerprint result per stored state, including explicit unavailable evidence.
    pub fingerprints: Vec<FingerprintSample>,
}

/// A violated invariant. Each variant names the rule and the row.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[serde(tag = "rule", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TrailViolation {
    /// A `succeeded` action has no `transitions` row.
    SucceededWithoutTransition {
        /// The action.
        action: ActionId,
    },
    /// A `traffic_events` row has neither a `network_epoch_id` nor an explicit
    /// `unattributed_reason`.
    TrafficUnattributed {
        /// Row order within the run.
        event_id: u64,
        /// Action the row was journaled under, when known.
        action: Option<ActionId>,
    },
    /// A `traffic_events` row carries both an epoch and an `unattributed_reason`.
    TrafficAttributionAmbiguous {
        /// Row order within the run.
        event_id: u64,
        /// The epoch it is attributed to.
        epoch: NetworkEpochId,
    },
    /// A `traffic_events` row references an epoch that has no `network_epochs` row.
    TrafficWithoutEpochRow {
        /// Row order within the run.
        event_id: u64,
        /// The dangling epoch id.
        epoch: NetworkEpochId,
    },
    /// An executed action has an empty `strategy` or `strategy_version = 0`.
    MissingStrategy {
        /// The action.
        action: ActionId,
        /// Stored strategy name.
        strategy: String,
        /// Stored strategy version.
        version: u32,
    },
    /// An executed action's `safety_decision` has no `safety_decisions` row.
    MissingSafetyDecision {
        /// The action.
        action: ActionId,
        /// The dangling decision id.
        decision: SafetyDecisionId,
    },
    /// An executed action names a `model_decision` that has no `model_decisions` row.
    MissingModelDecision {
        /// The action.
        action: ActionId,
        /// The dangling decision id.
        decision: ModelDecisionId,
    },
    /// Recomputing a state's signature from its stored artifact and masks gives a
    /// different signature.
    SignatureNotReproducible {
        /// The state.
        state: StateId,
        /// Differing `StateSignature` fields.
        fields: Vec<&'static str>,
    },
    /// A state's `ax_tree` artifact exists but is not a readable [`FingerprintInput`].
    FingerprintArtifactUnreadable {
        /// The state.
        state: StateId,
        /// Why.
        reason: String,
    },
    /// A `succeeded` action has no `network_epochs` row attributed to it.
    SucceededWithoutEpoch {
        /// The action.
        action: ActionId,
    },
    /// The transition's lane differs from the action's lane.
    TransitionLaneMismatch {
        /// The action.
        action: ActionId,
        /// Lane on the action row.
        action_lane: TrustLane,
        /// Lane on the transition row.
        transition_lane: TrustLane,
    },
    /// The epoch's lane differs from the action's lane.
    EpochLaneMismatch {
        /// The action.
        action: ActionId,
        /// Lane on the action row.
        action_lane: TrustLane,
        /// Lane on the epoch row.
        epoch_lane: TrustLane,
    },
    /// An `intended` action is older than the lease TTL and was neither
    /// flipped to `unknown` nor reconciled.
    IntendedBeyondLease {
        /// The action.
        action: ActionId,
        /// Seconds since `intended_at`.
        age_secs: i64,
    },
    /// An `unknown` action is older than lease TTL + [`RECONCILE_WINDOW`] and
    /// still not reconciled.
    UnknownUnreconciled {
        /// The action.
        action: ActionId,
        /// Seconds since `finished_at`.
        age_secs: i64,
    },
    /// `actions.seq` is not dense within a session.
    SeqGap {
        /// The session.
        session: SessionId,
        /// The sequence number that is missing.
        missing: u64,
    },
    /// Two actions share a `seq` within a session.
    SeqDuplicate {
        /// The session.
        session: SessionId,
        /// The duplicated sequence number.
        seq: u64,
    },
    /// `lane != fidelity.lane()` on an action (`lane_matches_fidelity`).
    LaneFidelityMismatch {
        /// The action.
        action: ActionId,
        /// Recorded lane.
        lane: TrustLane,
        /// Lane the fidelity implies.
        expected: TrustLane,
    },
    /// A transition or action references a state that does not exist.
    MissingState {
        /// The state id referenced.
        state: StateId,
        /// Which row referenced it: `transition.before`, `transition.after` or `action.before_state`.
        referenced_by: &'static str,
        /// The action whose row holds the reference.
        action: ActionId,
    },
    /// A state's artifact manifest references a digest absent from the artifact index.
    MissingArtifact {
        /// The state.
        state: StateId,
        /// Hex digest of the missing artifact.
        digest: String,
    },
    /// A transition references an action id that has no `actions` row.
    TransitionWithoutAction {
        /// The orphan action id.
        action: ActionId,
    },
    /// An epoch references an action id that has no `actions` row.
    EpochWithoutAction {
        /// The orphan action id.
        action: ActionId,
    },
    /// Two transitions claim the same action.
    DuplicateTransition {
        /// The action.
        action: ActionId,
    },
    /// A final-status action lacks `intended_at` or `finished_at`.
    MissingTimestamp {
        /// The action.
        action: ActionId,
        /// `intended_at` or `finished_at`.
        field: &'static str,
    },
    /// The run's plane counters violate the counter identities.
    CounterInvariant {
        /// `urls`, `interactions` or `states`.
        plane: &'static str,
    },
    /// Executed-action counts do not match the counters (`interactions.succeeded`,
    /// `interactions.unknown_outcome`), or the frontier rows do not match the URL counters
    /// (`urls.succeeded`, `urls.failed`, `urls.unreachable`, `urls.abandoned`,
    /// `urls.deduplicated`).
    CounterMismatch {
        /// The counter name.
        counter: &'static str,
        /// Value stored on the run.
        stored: u64,
        /// Value derived from the `actions` or `url_frontier` rows.
        derived: u64,
    },
}

impl fmt::Display for TrailViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SucceededWithoutTransition { action } => {
                write!(f, "succeeded action {action} has no transitions row")
            }
            Self::TrafficUnattributed { event_id, action } => write!(
                f,
                "traffic event {event_id} (action {}) has no network epoch and no unattributed reason",
                action.map_or_else(|| "none".to_owned(), |a| a.to_string())
            ),
            Self::TrafficAttributionAmbiguous { event_id, epoch } => write!(
                f,
                "traffic event {event_id} is attributed to epoch {epoch} and also carries an unattributed reason"
            ),
            Self::TrafficWithoutEpochRow { event_id, epoch } => {
                write!(f, "traffic event {event_id} references missing epoch {epoch}")
            }
            Self::MissingStrategy {
                action,
                strategy,
                version,
            } => write!(
                f,
                "executed action {action} has no strategy attribution (strategy {strategy:?} version {version})"
            ),
            Self::MissingSafetyDecision { action, decision } => write!(
                f,
                "executed action {action} references safety decision {decision} without a safety_decisions row"
            ),
            Self::MissingModelDecision { action, decision } => write!(
                f,
                "executed action {action} references model decision {decision} without a model_decisions row"
            ),
            Self::SignatureNotReproducible { state, fields } => write!(
                f,
                "state {state} signature not reproducible from its artifact: {} differ",
                fields.join(", ")
            ),
            Self::FingerprintArtifactUnreadable { state, reason } => {
                write!(f, "state {state} ax_tree artifact unreadable: {reason}")
            }
            Self::SucceededWithoutEpoch { action } => {
                write!(f, "succeeded action {action} has no network_epochs row")
            }
            Self::TransitionLaneMismatch {
                action,
                action_lane,
                transition_lane,
            } => write!(
                f,
                "action {action} lane {} but its transition is {}",
                action_lane.as_str(),
                transition_lane.as_str()
            ),
            Self::EpochLaneMismatch {
                action,
                action_lane,
                epoch_lane,
            } => write!(
                f,
                "action {action} lane {} but its epoch is {}",
                action_lane.as_str(),
                epoch_lane.as_str()
            ),
            Self::IntendedBeyondLease { action, age_secs } => {
                write!(
                    f,
                    "action {action} intended {age_secs}s ago, beyond the lease ttl, not unknown/reconciled"
                )
            }
            Self::UnknownUnreconciled { action, age_secs } => {
                write!(
                    f,
                    "action {action} unknown for {age_secs}s, beyond the reconcile window"
                )
            }
            Self::SeqGap { session, missing } => write!(f, "session {session} has no action seq {missing}"),
            Self::SeqDuplicate { session, seq } => {
                write!(f, "session {session} has two actions with seq {seq}")
            }
            Self::LaneFidelityMismatch {
                action,
                lane,
                expected,
            } => write!(
                f,
                "action {action} lane {} does not match fidelity lane {}",
                lane.as_str(),
                expected.as_str()
            ),
            Self::MissingState {
                state,
                referenced_by,
                action,
            } => write!(
                f,
                "{referenced_by} of action {action} references missing state {state}"
            ),
            Self::MissingArtifact { state, digest } => {
                write!(
                    f,
                    "state {state} references artifact digest {digest} absent from the index"
                )
            }
            Self::TransitionWithoutAction { action } => {
                write!(f, "transition references unknown action {action}")
            }
            Self::EpochWithoutAction { action } => write!(f, "epoch references unknown action {action}"),
            Self::DuplicateTransition { action } => write!(f, "action {action} has more than one transition"),
            Self::MissingTimestamp { action, field } => write!(f, "action {action} lacks {field}"),
            Self::CounterInvariant { plane } => write!(f, "{plane} counters violate the plane identities"),
            Self::CounterMismatch {
                counter,
                stored,
                derived,
            } => write!(f, "{counter}: run stores {stored} but actions derive {derived}"),
        }
    }
}

/// Result of a trail verification.
#[derive(Clone, PartialEq, Eq, Debug, Serialize)]
#[non_exhaustive]
pub struct TrailReport {
    /// The run.
    pub run: CrawlRunId,
    /// Rows examined per table.
    pub checked: BTreeMap<&'static str, u64>,
    /// Every violated invariant, in deterministic order.
    pub violations: Vec<TrailViolation>,
    /// Checks that were skipped and why (e.g. artifact checks under `zdr`).
    pub skipped: Vec<String>,
    /// Number of unverifiable states by reason, distinct from proven violations.
    pub unverifiable: BTreeMap<String, u64>,
    /// Number of inapplicable fingerprint checks by reason.
    pub skipped_counts: BTreeMap<String, u64>,
}

impl TrailReport {
    /// `true` when no invariant was violated and no state's evidence is unavailable.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty() && self.unverifiable.is_empty()
    }

    /// Violations grouped by rule name, for summaries.
    #[must_use]
    pub fn by_rule(&self) -> BTreeMap<String, u64> {
        let mut out = BTreeMap::new();
        for v in &self.violations {
            let rule = serde_json::to_value(v)
                .ok()
                .and_then(|j| j.get("rule").and_then(|r| r.as_str()).map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned());
            *out.entry(rule).or_insert(0) += 1;
        }
        out
    }
}

impl fmt::Display for TrailReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "trail {}: {} violation(s)", self.run, self.violations.len())?;
        for (table, n) in &self.checked {
            writeln!(f, "  checked {table}: {n}")?;
        }
        for s in &self.skipped {
            writeln!(f, "  skipped: {s}")?;
        }
        for (reason, count) in &self.unverifiable {
            writeln!(f, "  unverifiable: {count} state(s): {reason}")?;
        }
        for v in &self.violations {
            writeln!(f, "  VIOLATION {v}")?;
        }
        Ok(())
    }
}

fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn count_reason(counts: &mut BTreeMap<String, u64>, reason: &str) {
    if let Some(count) = counts.get_mut(reason) {
        *count = count.saturating_add(1);
    } else {
        counts.insert(reason.to_owned(), 1);
    }
}

fn age_secs(now: Timestamp, at: Timestamp) -> i64 {
    (now - at).num_seconds()
}

fn chrono_dur(d: Duration) -> ChronoDuration {
    ChronoDuration::milliseconds(i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Run every invariant over `s`. Pure: no I/O, no clock.
#[must_use]
pub fn verify_snapshot(s: &TrailSnapshot) -> TrailReport {
    let mut v: Vec<TrailViolation> = Vec::new();
    let mut skipped = Vec::new();
    let mut unverifiable = BTreeMap::new();
    let mut skipped_counts = BTreeMap::new();
    let mut recomputed = 0_u64;
    let mut verified = 0_u64;
    let actions: BTreeMap<ActionId, &ActionRecord> = s.actions.iter().map(|a| (a.id, a)).collect();

    // transitions: one per action, action must exist
    let mut transitions: BTreeMap<ActionId, &TrailTransition> = BTreeMap::new();
    for t in &s.transitions {
        if !actions.contains_key(&t.action) {
            v.push(TrailViolation::TransitionWithoutAction { action: t.action });
        }
        if transitions.insert(t.action, t).is_some() {
            v.push(TrailViolation::DuplicateTransition { action: t.action });
        }
        if !s.state_ids.contains(&t.before) {
            v.push(TrailViolation::MissingState {
                state: t.before,
                referenced_by: "transition.before",
                action: t.action,
            });
        }
        if let Some(after) = t.after {
            if !s.state_ids.contains(&after) {
                v.push(TrailViolation::MissingState {
                    state: after,
                    referenced_by: "transition.after",
                    action: t.action,
                });
            }
        }
    }

    // epochs by action
    let mut epochs: BTreeMap<ActionId, Vec<&TrailEpoch>> = BTreeMap::new();
    for e in &s.epochs {
        if let Some(a) = e.action {
            if !actions.contains_key(&a) {
                v.push(TrailViolation::EpochWithoutAction { action: a });
            }
            epochs.entry(a).or_default().push(e);
        }
    }
    let epoch_ids: BTreeSet<NetworkEpochId> = s.epochs.iter().map(|e| e.id).collect();

    // traffic_events: an epoch, or an explicit reason for none; never neither, never both
    for t in &s.traffic {
        match (t.epoch, t.unattributed_reason) {
            (None, None) => v.push(TrailViolation::TrafficUnattributed {
                event_id: t.event_id,
                action: t.action,
            }),
            (Some(epoch), Some(_)) => v.push(TrailViolation::TrafficAttributionAmbiguous {
                event_id: t.event_id,
                epoch,
            }),
            (Some(epoch), None) if !epoch_ids.contains(&epoch) => {
                v.push(TrailViolation::TrafficWithoutEpochRow {
                    event_id: t.event_id,
                    epoch,
                });
            }
            _ => {}
        }
    }

    let lease = chrono_dur(s.lease_ttl);
    let window = lease + chrono_dur(RECONCILE_WINDOW);
    let mut seqs: BTreeMap<SessionId, Vec<u64>> = BTreeMap::new();
    let mut succeeded = 0_u64;
    let mut unknown_total = 0_u64;

    for a in &s.actions {
        seqs.entry(a.session).or_default().push(a.seq);
        if let (Some(lane), Some(fid)) = (a.lane, a.fidelity) {
            if fid.lane() != lane {
                v.push(TrailViolation::LaneFidelityMismatch {
                    action: a.id,
                    lane,
                    expected: fid.lane(),
                });
            }
        }
        if let Some(before) = a.before_state {
            if !s.state_ids.contains(&before) {
                v.push(TrailViolation::MissingState {
                    state: before,
                    referenced_by: "action.before_state",
                    action: a.id,
                });
            }
        }
        // attribution of every action past `proposed`: who proposed it, who admitted it,
        // which model (if any) influenced it
        if a.status != ActionStatus::Proposed {
            if a.strategy.is_empty() || a.strategy_version == 0 {
                v.push(TrailViolation::MissingStrategy {
                    action: a.id,
                    strategy: a.strategy.clone(),
                    version: a.strategy_version,
                });
            }
            if !s.safety_decisions.contains(&a.safety_decision) {
                v.push(TrailViolation::MissingSafetyDecision {
                    action: a.id,
                    decision: a.safety_decision,
                });
            }
            if let Some(m) = a.model_decision {
                if !s.model_decisions.contains(&m) {
                    v.push(TrailViolation::MissingModelDecision {
                        action: a.id,
                        decision: m,
                    });
                }
            }
        }
        match a.status {
            ActionStatus::Proposed => {}
            ActionStatus::Intended => {
                if a.intended_at.is_none() {
                    v.push(TrailViolation::MissingTimestamp {
                        action: a.id,
                        field: "intended_at",
                    });
                }
                if let Some(at) = a.intended_at {
                    if s.now - at > lease {
                        v.push(TrailViolation::IntendedBeyondLease {
                            action: a.id,
                            age_secs: age_secs(s.now, at),
                        });
                    }
                }
            }
            ActionStatus::Succeeded
            | ActionStatus::Failed
            | ActionStatus::Unknown
            | ActionStatus::Reconciled => {
                if a.intended_at.is_none() {
                    v.push(TrailViolation::MissingTimestamp {
                        action: a.id,
                        field: "intended_at",
                    });
                }
                if a.finished_at.is_none() {
                    v.push(TrailViolation::MissingTimestamp {
                        action: a.id,
                        field: "finished_at",
                    });
                }
                if a.status == ActionStatus::Unknown {
                    unknown_total += 1;
                    if let Some(at) = a.finished_at {
                        if s.now - at > window {
                            v.push(TrailViolation::UnknownUnreconciled {
                                action: a.id,
                                age_secs: age_secs(s.now, at),
                            });
                        }
                    }
                }
                if a.status == ActionStatus::Succeeded {
                    succeeded += 1;
                    let action_lane = a.lane.unwrap_or(TrustLane::Diagnostic);
                    match transitions.get(&a.id) {
                        None => v.push(TrailViolation::SucceededWithoutTransition { action: a.id }),
                        Some(t) if t.lane != action_lane => v.push(TrailViolation::TransitionLaneMismatch {
                            action: a.id,
                            action_lane,
                            transition_lane: t.lane,
                        }),
                        Some(_) => {}
                    }
                    match epochs.get(&a.id) {
                        None => v.push(TrailViolation::SucceededWithoutEpoch { action: a.id }),
                        Some(es) => {
                            for e in es {
                                if e.lane != action_lane {
                                    v.push(TrailViolation::EpochLaneMismatch {
                                        action: a.id,
                                        action_lane,
                                        epoch_lane: e.lane,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    for (session, mut list) in seqs {
        list.sort_unstable();
        let Some(&first) = list.first() else { continue };
        let mut expected = first;
        for seq in list {
            if seq < expected {
                v.push(TrailViolation::SeqDuplicate { session, seq });
                continue;
            }
            while expected < seq {
                v.push(TrailViolation::SeqGap {
                    session,
                    missing: expected,
                });
                expected += 1;
            }
            expected = seq + 1;
        }
    }

    // artifacts
    if s.retention == RetentionMode::Zdr {
        skipped.push(
            "artifact manifest checks: run is zdr (identities and hashes kept, content not)".to_owned(),
        );
    } else {
        match &s.artifact_digests {
            Some(index) => {
                for (state, r) in &s.state_artifacts {
                    if !index.contains(&r.digest) {
                        v.push(TrailViolation::MissingArtifact {
                            state: *state,
                            digest: r.digest.to_string(),
                        });
                    }
                }
            }
            None => {
                for r in &s.missing_artifacts {
                    let state = s.state_artifacts.iter().find(|(_, x)| x == r).map(|(st, _)| *st);
                    if let Some(state) = state {
                        v.push(TrailViolation::MissingArtifact {
                            state,
                            digest: r.digest.to_string(),
                        });
                    }
                }
            }
        }
    }

    // Fingerprint reproducibility covers every stored state, not a sample.
    for f in &s.fingerprints {
        match &f.outcome {
            FingerprintOutcome::Match => {
                recomputed = recomputed.saturating_add(1);
                verified = verified.saturating_add(1);
            }
            FingerprintOutcome::Mismatch { fields } => {
                recomputed = recomputed.saturating_add(1);
                v.push(TrailViolation::SignatureNotReproducible {
                    state: f.state,
                    fields: fields.clone(),
                });
            }
            FingerprintOutcome::Unreadable { reason } => {
                v.push(TrailViolation::FingerprintArtifactUnreadable {
                    state: f.state,
                    reason: reason.clone(),
                });
            }
            FingerprintOutcome::VersionSkew { stored } => {
                let reason = format!(
                    "stored signature version {stored}, this build computes {}",
                    StateSignature::VERSION
                );
                let count = unverifiable.entry(reason).or_insert(0_u64);
                *count = count.saturating_add(1);
            }
            FingerprintOutcome::Skipped { reason } => {
                count_reason(&mut skipped_counts, reason);
            }
            FingerprintOutcome::Unverifiable { reason } => {
                count_reason(&mut unverifiable, reason);
            }
        }
    }
    for (reason, count) in &skipped_counts {
        skipped.push(format!("fingerprints: {count} state(s): {reason}"));
    }

    // counters
    for (plane, c) in [
        ("urls", &s.counters.urls),
        ("interactions", &s.counters.interactions),
        ("states", &s.counters.states),
    ] {
        if !c.invariants_hold() {
            v.push(TrailViolation::CounterInvariant { plane });
        }
    }
    if s.counters.interactions.succeeded != succeeded {
        v.push(TrailViolation::CounterMismatch {
            counter: "interactions.succeeded",
            stored: s.counters.interactions.succeeded,
            derived: succeeded,
        });
    }
    if s.counters.interactions.unknown_outcome < unknown_total {
        v.push(TrailViolation::CounterMismatch {
            counter: "interactions.unknown_outcome",
            stored: s.counters.interactions.unknown_outcome,
            derived: unknown_total,
        });
    }
    // the URL counters against the frontier rows: every finished row is one attempt of its
    // outcome, and the rows that carry a `dedupe:` reason are duplicates the counters hold
    for (counter, stored, derived) in [
        ("urls.succeeded", s.counters.urls.succeeded, s.frontier.succeeded),
        ("urls.failed", s.counters.urls.failed, s.frontier.failed),
        (
            "urls.unreachable",
            s.counters.urls.unreachable,
            s.frontier.unreachable,
        ),
        ("urls.abandoned", s.counters.urls.abandoned, s.frontier.abandoned),
    ] {
        if stored != derived {
            v.push(TrailViolation::CounterMismatch {
                counter,
                stored,
                derived,
            });
        }
    }
    if s.counters.urls.deduplicated < s.frontier.deduplicated() {
        v.push(TrailViolation::CounterMismatch {
            counter: "urls.deduplicated",
            stored: s.counters.urls.deduplicated,
            derived: s.frontier.deduplicated(),
        });
    }

    let mut checked = BTreeMap::new();
    checked.insert("actions", to_u64(s.actions.len()));
    checked.insert("transitions", to_u64(s.transitions.len()));
    checked.insert("network_epochs", to_u64(s.epochs.len()));
    checked.insert("states", to_u64(s.state_ids.len()));
    checked.insert("state_artifacts", to_u64(s.state_artifacts.len()));
    checked.insert("traffic_events", to_u64(s.traffic.len()));
    checked.insert("safety_decisions", to_u64(s.safety_decisions.len()));
    checked.insert("model_decisions", to_u64(s.model_decisions.len()));
    checked.insert("fingerprints_recomputed", recomputed);
    checked.insert("fingerprints_verified", verified);
    checked.insert(
        "fingerprints_skipped",
        skipped_counts.values().copied().fold(0, u64::saturating_add),
    );
    checked.insert(
        "fingerprints_unverifiable",
        unverifiable.values().copied().fold(0, u64::saturating_add),
    );
    // a dangling safety decision is a SEV-1 safety invariant violation.
    let missing_safety = v
        .iter()
        .filter(|v| matches!(v, TrailViolation::MissingSafetyDecision { .. }))
        .count();
    if missing_safety > 0 {
        Metrics::global()
            .counter(names::SAFETY_INVARIANT_VIOLATIONS)
            .inc_by(to_u64(missing_safety), &[("reason", "missing_safety_decision")]);
    }
    TrailReport {
        run: s.run,
        checked,
        violations: v,
        skipped,
        unverifiable,
        skipped_counts,
    }
}

/// Names of the `StateSignature` fields that differ between `stored` and `recomputed`,
/// excluding the signals the artifact does not carry (`visual_phash`,
/// `browser_storage_digest`). Empty means reproducible.
#[must_use]
pub fn signature_diff(stored: &StateSignature, recomputed: &StateSignature) -> Vec<&'static str> {
    let mut out = Vec::new();
    if stored.version != recomputed.version {
        out.push("version");
    }
    if stored.route_key != recomputed.route_key {
        out.push("route_key");
    }
    if stored.semantic_affordance_minhash != recomputed.semantic_affordance_minhash {
        out.push("semantic_affordance_minhash");
    }
    if stored.dom_structure_simhash != recomputed.dom_structure_simhash {
        out.push("dom_structure_simhash");
    }
    if stored.visible_element_identity_digest != recomputed.visible_element_identity_digest {
        out.push("visible_element_identity_digest");
    }
    if stored.frame_tree_digest != recomputed.frame_tree_digest {
        out.push("frame_tree_digest");
    }
    if stored.network_operation_digest != recomputed.network_operation_digest {
        out.push("network_operation_digest");
    }
    out
}

/// Recompute the signature of `state` from `artifact` bytes (a [`FingerprintInput`]) and
/// the state's stored masks, and compare it to the stored signature.
#[must_use]
pub fn check_fingerprint(state: &NewState, artifact: &[u8]) -> FingerprintOutcome {
    if state.signature.version != StateSignature::VERSION {
        return FingerprintOutcome::VersionSkew {
            stored: state.signature.version,
        };
    }
    let input: FingerprintInput = match serde_json::from_slice(artifact) {
        Ok(i) => i,
        Err(e) => {
            return FingerprintOutcome::Unreadable {
                reason: format!("not a FingerprintInput: {e}"),
            };
        }
    };
    let recomputed = Fingerprinter::default().fingerprint(&input.to_bundle(), &state.masks);
    let fields = signature_diff(&state.signature, &recomputed);
    if fields.is_empty() {
        FingerprintOutcome::Match
    } else {
        FingerprintOutcome::Mismatch { fields }
    }
}

/// Check every state in `(observed_at, id)` order, including unavailable evidence.
/// ZDR never reads ephemeral content during durable trail inspection.
async fn verify_fingerprints(
    states: &[NewState],
    artifacts: Option<&dyn ArtifactStore>,
    retention: RetentionMode,
) -> Vec<FingerprintSample> {
    let mut ordered: Vec<&NewState> = states.iter().collect();
    ordered.sort_by(|a, b| a.observed_at.cmp(&b.observed_at).then(a.id.cmp(&b.id)));
    let mut out = Vec::with_capacity(ordered.len());
    for state in ordered {
        let outcome = if state.signature.version != StateSignature::VERSION {
            FingerprintOutcome::VersionSkew {
                stored: state.signature.version,
            }
        } else if retention == RetentionMode::Zdr {
            FingerprintOutcome::Unverifiable {
                reason: "zdr content is ephemeral and unavailable to durable inspection",
            }
        } else if let Some((_, reference)) = state.artifacts.iter().find(|(k, _)| k == AX_TREE_ARTIFACT) {
            if let Some(artifacts) = artifacts {
                match artifacts.get(reference).await {
                    Ok(bytes) => check_fingerprint(state, &bytes),
                    Err(StoreError::NotFound { .. }) => FingerprintOutcome::Unverifiable {
                        reason: "ax_tree artifact is missing or expired",
                    },
                    Err(StoreError::Unavailable(_)) => FingerprintOutcome::Unverifiable {
                        reason: "artifact store is unavailable",
                    },
                    Err(StoreError::AccessDenied(_)) => FingerprintOutcome::Unverifiable {
                        reason: "artifact access is denied",
                    },
                    Err(e) => FingerprintOutcome::Unreadable {
                        reason: format!("artifact store: {e}"),
                    },
                }
            } else {
                FingerprintOutcome::Unverifiable {
                    reason: "artifact store is not configured",
                }
            }
        } else {
            FingerprintOutcome::Skipped {
                reason: "state has no ax_tree artifact (capture disabled or not applicable)",
            }
        };
        out.push(FingerprintSample {
            state: state.id,
            outcome,
        });
    }
    out
}

/// Snapshot of a run held in a [`MemoryStore`]. Artifact presence and fingerprint
/// reproducibility are checked against `artifacts` when given (the memory store has
/// no artifact index).
///
/// # Errors
/// Any repository error while loading the rows.
pub async fn snapshot_memory(
    store: &MemoryStore,
    artifacts: Option<&dyn ArtifactStore>,
    run: CrawlRunId,
) -> Result<TrailSnapshot, BenchError> {
    let crawl = RunRepo::get(store, run).await?;
    let actions = ActionJournal::list(store, run, None).await?;
    let states = StateRepo::list_states(store, run).await?;
    let frontier = FrontierRepo::state_counts(store, run).await?;
    let now = LeaseRepo::now(store).await?;
    let transitions = store
        .transitions(run)
        .into_iter()
        .map(|t: MemoryTransition| TrailTransition {
            action: t.action,
            session: t.session,
            before: t.before,
            after: t.after,
            network_epoch: t.network_epoch,
            lane: t.lane,
        })
        .collect();
    let epochs: Vec<TrailEpoch> = store
        .network_epochs(run)
        .into_iter()
        .map(|e: MemoryNetworkEpoch| TrailEpoch {
            id: e.id,
            session: e.session,
            action: Some(e.action),
            lane: e.lane,
        })
        .collect();
    // the memory mirror keeps the event's own epoch; an event journaled without one
    // under an action with a receipt is attributed to that action's epoch (as T2 does)
    let receipt_epoch: BTreeMap<ActionId, NetworkEpochId> = epochs
        .iter()
        .filter_map(|e| e.action.map(|a| (a, e.id)))
        .collect();
    let traffic = store
        .traffic_of_run(run)
        .into_iter()
        .enumerate()
        .map(|(i, (action, t))| TrailTraffic {
            event_id: to_u64(i) + 1,
            action: Some(action),
            epoch: match (t.epoch_id, t.unattributed_reason) {
                (None, None) => receipt_epoch.get(&action).copied(),
                (epoch, _) => epoch,
            },
            unattributed_reason: t.unattributed_reason,
        })
        .collect();
    let safety_decisions = store.safety_decision_ids(run).into_iter().collect();
    let model_decisions = ModelDecisionRepo::list(store, run)
        .await?
        .into_iter()
        .map(|d| d.id)
        .collect();
    let state_ids = states.iter().map(|s| s.id).collect();
    let state_artifacts: Vec<(StateId, ArtifactRef)> = states
        .iter()
        .flat_map(|s| s.artifacts.iter().map(move |(_, r)| (s.id, r.clone())))
        .collect();
    let mut missing_artifacts = Vec::new();
    if let Some(store) = artifacts.filter(|_| crawl.config.retention.mode != RetentionMode::Zdr) {
        // AX artifacts are read once by the exhaustive fingerprint check below.
        for (_, reference) in states
            .iter()
            .flat_map(|state| &state.artifacts)
            .filter(|(kind, _)| kind != AX_TREE_ARTIFACT)
        {
            if store.get(reference).await.is_err() {
                missing_artifacts.push(reference.clone());
            }
        }
    }
    let fingerprints = verify_fingerprints(&states, artifacts, crawl.config.retention.mode).await;
    Ok(TrailSnapshot {
        run,
        now,
        lease_ttl: store.session_ttl(),
        actions,
        transitions,
        epochs,
        state_ids,
        state_artifacts,
        artifact_digests: None,
        missing_artifacts,
        counters: crawl.counters,
        frontier,
        retention: crawl.config.retention.mode,
        traffic,
        safety_decisions,
        model_decisions,
        fingerprints,
    })
}

/// Snapshot of a run held in a database. Fingerprints are recomputed only when the
/// object store holding the run's artifacts is given.
///
/// # Errors
/// Any repository or query error while loading the rows.
pub async fn snapshot_database(
    store: &DurableStore,
    artifacts: Option<&dyn ArtifactStore>,
    run: CrawlRunId,
) -> Result<TrailSnapshot, BenchError> {
    crawlx_worker::on_store!(store, store => snapshot_on(store, artifacts, run).await)
}

async fn snapshot_on<B: Tenancy>(
    pg: &Store<B>,
    artifacts: Option<&dyn ArtifactStore>,
    run: CrawlRunId,
) -> Result<TrailSnapshot, BenchError> {
    let crawl = RunRepo::get(pg, run).await?;
    let actions = ActionJournal::list(pg, run, None).await?;
    let states = StateRepo::list_states(pg, run).await?;
    let frontier = FrontierRepo::state_counts(pg, run).await?;
    let now = LeaseRepo::now(pg).await?;
    let inspect = InspectRepo::new(pg.clone());
    let reads = TrailReads::new(pg.clone());

    let transitions = inspect
        .transitions(run)
        .await?
        .into_iter()
        .map(|t| TrailTransition {
            action: t.action,
            session: t.session,
            before: t.before_state,
            after: t.after_state,
            network_epoch: t.network_epoch,
            lane: t.lane,
        })
        .collect();
    let epochs = inspect
        .epochs(run)
        .await?
        .into_iter()
        .map(|e| TrailEpoch {
            id: e.epoch,
            session: e.session,
            action: e.action,
            lane: e.lane,
        })
        .collect();
    let traffic = reads
        .traffic_attribution(run)
        .await?
        .into_iter()
        .map(|t| TrailTraffic {
            event_id: t.event_id,
            action: None,
            epoch: t.epoch,
            unattributed_reason: t.unattributed_reason,
        })
        .collect();
    let digests = reads.artifact_digests(run).await?;
    let safety_decisions = reads.safety_decision_ids(run).await?;
    let model_decisions = ModelDecisionRepo::list(pg, run)
        .await?
        .into_iter()
        .map(|d| d.id)
        .collect();

    let lease_ttl = crawlx_storage::DEFAULT_SESSION_TTL;
    let state_ids = states.iter().map(|s| s.id).collect();
    let state_artifacts = states
        .iter()
        .flat_map(|s| s.artifacts.iter().map(move |(_, r)| (s.id, r.clone())))
        .collect();
    let fingerprints = verify_fingerprints(&states, artifacts, crawl.config.retention.mode).await;
    Ok(TrailSnapshot {
        run,
        now,
        lease_ttl,
        actions,
        transitions,
        epochs,
        state_ids,
        state_artifacts,
        artifact_digests: Some(digests),
        missing_artifacts: Vec::new(),
        counters: crawl.counters,
        frontier,
        retention: crawl.config.retention.mode,
        traffic,
        safety_decisions,
        model_decisions,
        fingerprints,
    })
}

/// Where the trail lives.
#[derive(Clone, Copy)]
pub enum TrailStore<'a> {
    /// In-process store, with the object store its states refer to.
    Memory {
        /// The store.
        store: &'a MemoryStore,
        /// Object store for artifact presence and fingerprint checks; `None` reports unverifiable states.
        artifacts: Option<&'a dyn ArtifactStore>,
    },
    /// A database of any engine, with the object store its states refer to.
    Database {
        /// The database.
        store: &'a DurableStore,
        /// Object store for fingerprints; `None` reports unverifiable states (the index is still checked).
        artifacts: Option<&'a dyn ArtifactStore>,
    },
}

/// `crawlx-bench verify-trail <run_id>`: load the trail and run every invariant.
///
/// # Errors
/// Repository or query errors while loading the rows.
pub async fn verify_trail(run: CrawlRunId, store: TrailStore<'_>) -> Result<TrailReport, BenchError> {
    let snapshot = match store {
        TrailStore::Memory { store, artifacts } => snapshot_memory(store, artifacts, run).await?,
        TrailStore::Database { store, artifacts } => snapshot_database(store, artifacts, run).await?,
    };
    Ok(verify_snapshot(&snapshot))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use chrono::{TimeZone as _, Utc};
    use crawlx_core::counters::Counters;
    use crawlx_core::epoch::ObservationEpoch;
    use crawlx_core::traffic::Fidelity;
    use crawlx_core::{ArtifactId, SafetyDecisionId};
    use std::sync::Arc;

    fn seq_u32(seq: u64) -> u32 {
        u32::try_from(seq).unwrap()
    }

    fn ts(secs: i64) -> Timestamp {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn action(session: SessionId, seq: u64, status: ActionStatus, before: StateId) -> ActionRecord {
        let key =
            crawlx_storage::testkit::proposal("member", crawlx_core::StateClusterId::new(), seq_u32(seq)).key;
        let final_status = matches!(
            status,
            ActionStatus::Succeeded | ActionStatus::Failed | ActionStatus::Unknown | ActionStatus::Reconciled
        );
        ActionRecord {
            id: ActionId::new(),
            run: CrawlRunId::new(),
            session,
            seq,
            key,
            status,
            attempt: 0,
            strategy: "test".to_owned(),
            strategy_version: 1,
            epoch: ObservationEpoch::default(),
            lane: Some(TrustLane::TrustedUi),
            fidelity: Some(Fidelity::NativePointer),
            safety_decision: SafetyDecisionId::new(),
            model_decision: None,
            before_state: Some(before),
            reconcile_resolution: None,
            proposed_at: ts(0),
            intended_at: (status != ActionStatus::Proposed).then(|| ts(1)),
            finished_at: final_status.then(|| ts(2)),
            trace_id: None,
        }
    }

    /// A clean two-action trail: one succeeded (with transition + epoch) and one failed.
    fn clean() -> TrailSnapshot {
        let run = CrawlRunId::new();
        let session = SessionId::new();
        let s1 = StateId::new();
        let s2 = StateId::new();
        let mut a1 = action(session, 1, ActionStatus::Succeeded, s1);
        a1.run = run;
        let mut a2 = action(session, 2, ActionStatus::Failed, s2);
        a2.run = run;
        let epoch = NetworkEpochId::new();
        let digest = Digest([7; 32]);
        let a1_id = a1.id;
        let safety_decisions = [a1.safety_decision, a2.safety_decision].into_iter().collect();
        TrailSnapshot {
            run,
            now: ts(10),
            lease_ttl: Duration::from_secs(30),
            transitions: vec![
                TrailTransition {
                    action: a1.id,
                    session,
                    before: s1,
                    after: Some(s2),
                    network_epoch: Some(epoch),
                    lane: TrustLane::TrustedUi,
                },
                TrailTransition {
                    action: a2.id,
                    session,
                    before: s2,
                    after: None,
                    network_epoch: None,
                    lane: TrustLane::TrustedUi,
                },
            ],
            epochs: vec![TrailEpoch {
                id: epoch,
                session,
                action: Some(a1.id),
                lane: TrustLane::TrustedUi,
            }],
            actions: vec![a1, a2],
            state_ids: [s1, s2].into_iter().collect(),
            state_artifacts: vec![(
                s1,
                ArtifactRef {
                    id: ArtifactId::new(),
                    digest,
                },
            )],
            artifact_digests: Some([digest].into_iter().collect()),
            missing_artifacts: Vec::new(),
            counters: PlaneCounters {
                interactions: Counters {
                    discovered: 2,
                    admitted: 2,
                    attempted: 2,
                    succeeded: 1,
                    failed: 1,
                    ..Counters::default()
                },
                ..PlaneCounters::default()
            },
            frontier: FrontierStateCounts::default(),
            retention: RetentionMode::Standard,
            traffic: vec![
                TrailTraffic {
                    event_id: 1,
                    action: Some(a1_id),
                    epoch: Some(epoch),
                    unattributed_reason: None,
                },
                TrailTraffic {
                    event_id: 2,
                    action: None,
                    epoch: None,
                    unattributed_reason: Some(UnattributedReason::NotApplicable),
                },
            ],
            safety_decisions,
            model_decisions: BTreeSet::new(),
            fingerprints: vec![FingerprintSample {
                state: s1,
                outcome: FingerprintOutcome::Match,
            }],
        }
    }

    fn rules(r: &TrailReport) -> Vec<String> {
        r.by_rule().into_keys().collect()
    }

    #[test]
    fn clean_trail_has_no_violations() {
        let r = verify_snapshot(&clean());
        assert!(r.is_clean(), "{r}");
        assert_eq!(r.checked["actions"], 2);
        assert_eq!(r.checked["transitions"], 2);
    }

    #[test]
    fn succeeded_without_transition_or_epoch() {
        let mut s = clean();
        s.transitions.remove(0);
        s.epochs.clear();
        s.traffic.clear();
        let r = verify_snapshot(&s);
        assert_eq!(
            rules(&r),
            ["succeeded_without_epoch", "succeeded_without_transition"]
        );
    }

    #[test]
    fn lane_mismatches_are_reported() {
        let mut s = clean();
        s.transitions[0].lane = TrustLane::Diagnostic;
        s.epochs[0].lane = TrustLane::Diagnostic;
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["epoch_lane_mismatch", "transition_lane_mismatch"]);

        let mut s = clean();
        s.actions[0].fidelity = Some(Fidelity::SyntheticDomEvent);
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["lane_fidelity_mismatch"]);
    }

    #[test]
    fn intended_beyond_lease_and_unknown_unreconciled() {
        let mut s = clean();
        let session = s.actions[0].session;
        let mut a3 = action(
            session,
            3,
            ActionStatus::Intended,
            s.actions[0].before_state.unwrap(),
        );
        a3.intended_at = Some(ts(1));
        s.safety_decisions.insert(a3.safety_decision);
        s.actions.push(a3);
        s.counters.interactions.discovered = 3;
        s.counters.interactions.admitted = 3;
        s.now = ts(1 + 31);
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["intended_beyond_lease"]);
        // within the TTL it is fine
        s.now = ts(1 + 29);
        assert!(verify_snapshot(&s).is_clean());

        let mut s = clean();
        let session = s.actions[0].session;
        let mut a3 = action(
            session,
            3,
            ActionStatus::Unknown,
            s.actions[0].before_state.unwrap(),
        );
        a3.finished_at = Some(ts(2));
        s.safety_decisions.insert(a3.safety_decision);
        s.actions.push(a3);
        s.counters.interactions.discovered = 3;
        s.counters.interactions.admitted = 3;
        s.counters.interactions.attempted = 3;
        s.counters.interactions.unknown_outcome = 1;
        s.now = ts(2 + 30 + 121);
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["unknown_unreconciled"]);
        s.now = ts(2 + 30 + 100);
        assert!(verify_snapshot(&s).is_clean());
    }

    #[test]
    fn seq_gaps_and_duplicates() {
        let mut s = clean();
        s.actions[1].seq = 4;
        let r = verify_snapshot(&s);
        assert_eq!(
            r.violations,
            vec![
                TrailViolation::SeqGap {
                    session: s.actions[0].session,
                    missing: 2
                },
                TrailViolation::SeqGap {
                    session: s.actions[0].session,
                    missing: 3
                }
            ]
        );
        let mut s = clean();
        s.actions[1].seq = 1;
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["seq_duplicate"]);
    }

    #[test]
    fn missing_states_are_reported_per_reference() {
        let mut s = clean();
        let ghost = StateId::new();
        s.transitions[0].after = Some(ghost);
        s.actions[1].before_state = Some(ghost);
        let r = verify_snapshot(&s);
        let refs: Vec<&str> = r
            .violations
            .iter()
            .filter_map(|v| match v {
                TrailViolation::MissingState { referenced_by, .. } => Some(*referenced_by),
                _ => None,
            })
            .collect();
        assert_eq!(refs, ["transition.after", "action.before_state"]);
    }

    #[test]
    fn missing_artifacts_reported_unless_zdr() {
        let mut s = clean();
        s.artifact_digests = Some(BTreeSet::new());
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["missing_artifact"]);
        s.retention = RetentionMode::Zdr;
        let r = verify_snapshot(&s);
        assert!(r.is_clean());
        assert_eq!(r.skipped.len(), 1);

        // memory path: the object store reported the reference unreachable
        let mut s = clean();
        s.artifact_digests = None;
        s.missing_artifacts = vec![s.state_artifacts[0].1.clone()];
        assert_eq!(rules(&verify_snapshot(&s)), ["missing_artifact"]);
    }

    #[test]
    fn orphans_duplicates_and_timestamps() {
        let mut s = clean();
        let orphan = ActionId::new();
        s.transitions.push(TrailTransition {
            action: orphan,
            session: s.actions[0].session,
            before: s.actions[0].before_state.unwrap(),
            after: None,
            network_epoch: None,
            lane: TrustLane::Diagnostic,
        });
        s.epochs.push(TrailEpoch {
            id: NetworkEpochId::new(),
            session: s.actions[0].session,
            action: Some(orphan),
            lane: TrustLane::Diagnostic,
        });
        let dup = s.transitions[0].clone();
        s.transitions.push(dup);
        s.actions[1].finished_at = None;
        let r = verify_snapshot(&s);
        assert_eq!(
            rules(&r),
            [
                "duplicate_transition",
                "epoch_without_action",
                "missing_timestamp",
                "transition_without_action"
            ]
        );
    }

    #[test]
    fn counter_invariants_and_mismatch() {
        let mut s = clean();
        s.counters.interactions.succeeded = 5;
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["counter_invariant", "counter_mismatch"]);
    }

    /// The URL counters are derived state: rows a killed worker finished after its last flush
    /// are `counter_mismatch`, until the worker that takes the run over re-derives them.
    #[test]
    fn url_counters_are_checked_against_the_frontier_rows() {
        let mut s = clean();
        s.frontier = FrontierStateCounts {
            succeeded: 3,
            failed: 1,
            succeeded_duplicate: 1,
            policy_blocked: 1,
            policy_blocked_duplicate: 1,
            ..FrontierStateCounts::default()
        };
        s.counters.urls = Counters {
            discovered: 6,
            admitted: 3,
            deduplicated: 3,
            attempted: 4,
            succeeded: 3,
            failed: 1,
            ..Counters::default()
        };
        assert!(verify_snapshot(&s).is_clean(), "{:?}", verify_snapshot(&s));

        // two rows finished after the last flush
        s.frontier.succeeded = 5;
        s.frontier.failed = 2;
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["counter_mismatch"]);
        assert_eq!(
            r.violations,
            vec![
                TrailViolation::CounterMismatch {
                    counter: "urls.succeeded",
                    stored: 3,
                    derived: 5
                },
                TrailViolation::CounterMismatch {
                    counter: "urls.failed",
                    stored: 1,
                    derived: 2
                },
            ]
        );

        // duplicates are a floor: sightings no row proves are not a mismatch, a row nobody
        // counted is
        let mut s = clean();
        s.frontier.policy_blocked = 1;
        s.frontier.policy_blocked_duplicate = 1;
        s.counters.urls.discovered = 3;
        s.counters.urls.deduplicated = 3;
        assert!(verify_snapshot(&s).is_clean());
        s.frontier.succeeded_duplicate = 4;
        s.frontier.succeeded = 4;
        s.counters.urls.attempted = 4;
        s.counters.urls.succeeded = 4;
        s.counters.urls.discovered = 7;
        s.counters.urls.admitted = 4;
        assert_eq!(
            verify_snapshot(&s).violations,
            vec![TrailViolation::CounterMismatch {
                counter: "urls.deduplicated",
                stored: 3,
                derived: 5
            }]
        );
    }

    #[test]
    fn traffic_rows_need_an_epoch_or_an_explicit_reason() {
        let mut s = clean();
        s.traffic[1].unattributed_reason = None;
        let r = verify_snapshot(&s);
        assert_eq!(
            r.violations,
            vec![TrailViolation::TrafficUnattributed {
                event_id: 2,
                action: None
            }]
        );

        let mut s = clean();
        s.traffic[0].unattributed_reason = Some(UnattributedReason::NoReceipt);
        assert_eq!(rules(&verify_snapshot(&s)), ["traffic_attribution_ambiguous"]);

        let mut s = clean();
        s.traffic[0].epoch = Some(NetworkEpochId::new());
        assert_eq!(rules(&verify_snapshot(&s)), ["traffic_without_epoch_row"]);
    }

    #[test]
    fn executed_actions_carry_strategy_safety_and_model_attribution() {
        let mut s = clean();
        s.actions[0].strategy = String::new();
        s.actions[1].strategy_version = 0;
        let r = verify_snapshot(&s);
        assert_eq!(rules(&r), ["missing_strategy"]);
        assert_eq!(r.violations.len(), 2, "{r}");

        let mut s = clean();
        s.safety_decisions.remove(&s.actions[0].safety_decision);
        let violations = Metrics::global().counter(names::SAFETY_INVARIANT_VIOLATIONS);
        let label = [("reason", "missing_safety_decision")];
        // the counter is process-global; this is the only block in the crate's unit tests that moves it
        let before = violations.get(&label);
        let r = verify_snapshot(&s);
        assert_eq!(
            r.violations,
            vec![TrailViolation::MissingSafetyDecision {
                action: s.actions[0].id,
                decision: s.actions[0].safety_decision
            }]
        );
        assert_eq!(violations.get(&label), before + 1);

        let mut s = clean();
        let m = ModelDecisionId::new();
        s.actions[1].model_decision = Some(m);
        assert_eq!(rules(&verify_snapshot(&s)), ["missing_model_decision"]);
        s.model_decisions.insert(m);
        assert!(verify_snapshot(&s).is_clean());

        // a proposed-only action is not executed: no attribution rule applies
        let mut s = clean();
        let mut a3 = action(
            s.actions[0].session,
            3,
            ActionStatus::Proposed,
            s.actions[0].before_state.unwrap(),
        );
        a3.strategy = String::new();
        s.actions.push(a3);
        s.counters.interactions.discovered = 3;
        s.counters.interactions.admitted = 3;
        assert!(verify_snapshot(&s).is_clean());
    }

    #[test]
    fn fingerprint_outcomes_map_to_violations_or_skips() {
        let mut s = clean();
        s.fingerprints[0].outcome = FingerprintOutcome::Mismatch {
            fields: vec!["dom_structure_simhash"],
        };
        let r = verify_snapshot(&s);
        assert_eq!(
            r.violations,
            vec![TrailViolation::SignatureNotReproducible {
                state: s.fingerprints[0].state,
                fields: vec!["dom_structure_simhash"]
            }]
        );
        s.fingerprints[0].outcome = FingerprintOutcome::Unreadable {
            reason: "boom".to_owned(),
        };
        assert_eq!(rules(&verify_snapshot(&s)), ["fingerprint_artifact_unreadable"]);
        s.fingerprints[0].outcome = FingerprintOutcome::VersionSkew { stored: 0 };
        let r = verify_snapshot(&s);
        assert!(!r.is_clean(), "{r}");
        assert!(r.violations.is_empty(), "{r}");
        assert_eq!(r.unverifiable.values().sum::<u64>(), 1);
        assert_eq!(r.checked["fingerprints_recomputed"], 0);
    }

    /// A bundle with a small AX tree, masks for its clock, and the signature the worker
    /// would store.
    fn fingerprinted_state() -> (NewState, Vec<u8>) {
        use crawlx_core::observation::{AxNode, BoundingBox, ObservationBundle, RuntimeLocator};
        use crawlx_core::{AxNodeId, BackendNodeId, FrameId, TabId};
        let url = crawlx_storage::testkit::canonical_url("https://example.test/app/42");
        let tab = TabId("t".to_owned());
        let mut bundle = ObservationBundle::empty(SessionId::new(), tab.clone(), url.clone());
        let node = |i: i64, role: &str, name: Option<&str>, parent: Option<i64>, children: &[i64]| AxNode {
            locator: RuntimeLocator {
                tab: tab.clone(),
                frame: FrameId("f".to_owned()),
                backend_node_id: BackendNodeId(100 + i),
                object_id: None,
                ax_node_id: Some(AxNodeId(format!("ax{i}"))),
                epoch: ObservationEpoch::default(),
            },
            role: role.to_owned(),
            name: name.map(str::to_owned),
            description: None,
            value: None,
            ignored: false,
            focusable: role == "button",
            disabled: false,
            expanded: None,
            checked: None,
            properties: BTreeMap::new(),
            parent: parent.map(|p| AxNodeId(format!("ax{p}"))),
            children: children.iter().map(|c| AxNodeId(format!("ax{c}"))).collect(),
            bbox: Some(BoundingBox {
                x: 0.0,
                y: 0.0,
                width: 10.0,
                height: 10.0,
            }),
        };
        bundle.ax.nodes = vec![
            node(0, "RootWebArea", Some("App"), None, &[1, 2, 3]),
            node(1, "button", Some("Save"), Some(0), &[]),
            node(2, "link", Some("Help"), Some(0), &[]),
            node(3, "timer", Some("12:00:01"), Some(0), &[]),
        ];
        bundle.network.operations = vec!["GET /api/items".to_owned()];
        let masks = crawlx_state::MaskBuilder::build(&bundle, &[], &crawlx_state::MaskConfig::default());
        let signature = Fingerprinter::default().fingerprint(&bundle, &masks);
        let state = NewState {
            id: StateId::new(),
            session: bundle.session_id,
            epoch: bundle.epoch,
            url,
            signature,
            masks,
            cluster: crawlx_core::StateClusterId::new(),
            cluster_similarity: 1.0,
            cluster_is_new: true,
            artifacts: Vec::new(),
            observed_at: ts(0),
        };
        let artifact = serde_json::to_vec(&FingerprintInput::from_bundle(&bundle)).unwrap();
        (state, artifact)
    }

    #[test]
    fn worker_fingerprint_capture_excludes_ancestor_text_but_preserves_typed_inputs_and_decisions() {
        use crawlx_core::observation::{DomNodeSupplement, FrameInfo};
        use crawlx_core::{FrameId, ParamClass};
        const SECRET: &str = "fingerprint-ancestor-script-canary-872d";
        crawlx_core::secret::register_secret(SECRET);
        let (mut state, artifact) = fingerprinted_state();
        let mut bundle = serde_json::from_slice::<FingerprintInput>(&artifact)
            .unwrap()
            .to_bundle();
        bundle.url = crawlx_url::Canonicalizer::canonicalize_url(
            &url::Url::parse("https://example.test/app?id=42&page=2&sort=asc").unwrap(),
            &crawlx_url::CanonicalizeOptions::default(),
        )
        .unwrap();
        bundle.route = bundle.url.route_key();
        bundle.ax.nodes[1].properties.insert(
            "url".into(),
            format!("https://example.test/app?id=42&sessionid={SECRET}"),
        );
        bundle.frames.push(FrameInfo {
            id: FrameId("main".into()),
            parent: None,
            url: format!("https://example.test/app?sessionid={SECRET}"),
            same_origin: true,
            lineage: Vec::new(),
        });
        bundle.dom_supplement.nodes.insert(
            0,
            DomNodeSupplement {
                text: Some(format!("script source and profile data: {SECRET}")),
                listeners: vec!["click".into()],
                attributes: [("href".into(), format!("/app?id=42&sessionid={SECRET}"))].into(),
                ..DomNodeSupplement::default()
            },
        );
        // Record the original observation's decision before the privacy projection.
        state.url = bundle.url.clone();
        state.signature = Fingerprinter::default().fingerprint(&bundle, &state.masks);
        let retained = crawlx_worker::analysis::ax_json(&bundle).unwrap();
        let input: FingerprintInput = serde_json::from_slice(retained.as_ref()).unwrap();
        assert_eq!(
            input.url, bundle.url,
            "canonical keys and classified resource/view values must not change"
        );
        assert!(input
            .url
            .params
            .iter()
            .any(|param| param.class == ParamClass::ResourceId));
        assert_eq!(input.supplement[&0].text, None);
        assert_eq!(input.supplement[&0].listeners, ["click"]);
        assert!(!std::str::from_utf8(retained.as_ref()).unwrap().contains(SECRET));
        assert_eq!(
            check_fingerprint(&state, retained.as_ref()),
            FingerprintOutcome::Match
        );
        let mut changed = input.to_bundle();
        changed.ax.nodes[1].name = Some("Delete".into());
        assert!(matches!(
            check_fingerprint(
                &state,
                crawlx_worker::analysis::ax_json(&changed).unwrap().as_ref()
            ),
            FingerprintOutcome::Mismatch { .. }
        ));
    }

    #[test]
    fn worker_fingerprint_capture_refuses_secret_signature_inputs_and_invalid_geometry() {
        const SECRET: &str = "fingerprint-visible-name-canary-591c";
        crawlx_core::secret::register_secret(SECRET);
        let (_, artifact) = fingerprinted_state();
        let mut bundle = serde_json::from_slice::<FingerprintInput>(&artifact)
            .unwrap()
            .to_bundle();
        bundle.ax.nodes[1].name = Some(SECRET.into());
        assert!(crawlx_worker::analysis::ax_json(&bundle).is_err());
        bundle.ax.nodes[1].name = Some("https://example.test/app?sessionid=unknown-session".into());
        assert!(crawlx_worker::analysis::ax_json(&bundle).is_err());
        bundle.ax.nodes[1].name = Some("Save".into());
        bundle.ax.nodes[1].bbox.as_mut().unwrap().width = f64::NAN;
        assert!(crawlx_worker::analysis::ax_json(&bundle).is_err());
    }

    #[test]
    fn stored_signature_is_reproducible_from_the_ax_tree_artifact() {
        let (state, artifact) = fingerprinted_state();
        assert_eq!(check_fingerprint(&state, &artifact), FingerprintOutcome::Match);

        // a tampered artifact (one more button) is detected
        let mut input: FingerprintInput = serde_json::from_slice(&artifact).unwrap();
        let mut extra = input.nodes[1].clone();
        extra.name = Some("Delete".to_owned());
        input.nodes.push(extra);
        let outcome = check_fingerprint(&state, &serde_json::to_vec(&input).unwrap());
        match outcome {
            FingerprintOutcome::Mismatch { fields } => {
                assert!(fields.contains(&"semantic_affordance_minhash"), "{fields:?}");
            }
            other => panic!("{other:?}"),
        }

        // Garbage is unreadable; an older algorithm version is explicitly unverifiable.
        assert!(matches!(
            check_fingerprint(&state, b"not json"),
            FingerprintOutcome::Unreadable { .. }
        ));
        let mut old = state.clone();
        old.signature.version = 0;
        assert_eq!(
            check_fingerprint(&old, &artifact),
            FingerprintOutcome::VersionSkew { stored: 0 }
        );
    }

    #[tokio::test]
    async fn artifactless_legacy_states_report_version_skew_even_under_zdr() {
        let (mut state, _) = fingerprinted_state();
        state.signature.version = StateSignature::VERSION - 1;
        assert!(state.artifacts.is_empty());
        for retention in [RetentionMode::Standard, RetentionMode::Zdr] {
            let mut snapshot = clean();
            snapshot.fingerprints = verify_fingerprints(std::slice::from_ref(&state), None, retention).await;
            assert_eq!(
                snapshot.fingerprints[0].outcome,
                FingerprintOutcome::VersionSkew {
                    stored: StateSignature::VERSION - 1
                }
            );
            let report = verify_snapshot(&snapshot);
            assert!(!report.is_clean(), "{report}");
            assert_eq!(report.checked["fingerprints_unverifiable"], 1);
            assert_eq!(report.checked["fingerprints_skipped"], 0);
        }
    }

    #[tokio::test]
    async fn memory_snapshot_checks_all_fingerprints_and_reports_corruption_after_first_sixteen() {
        use crawlx_core::repo::{RunRepo as _, Sensitivity};
        use crawlx_core::{SystemClock, TenantId, WorkerId};
        use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
        let store = Arc::new(MemoryStore::new());
        let artifacts = crawlx_storage::MemoryArtifactStore::in_memory(store.clone(), Arc::new(SystemClock));
        let run = crawl_run(TenantId::new(), create_crawl("https://example.test/", &[], 1));
        store.create(&run, None).await.unwrap();
        let ss = sessions(run.id, 1, 1);
        store.create_sessions(&ss).await.unwrap();
        store
            .claim_session(run.id, WorkerId::new(), false)
            .await
            .unwrap()
            .unwrap();
        let (mut state, artifact) = fingerprinted_state();
        let r = artifacts
            .put(run.id, Sensitivity::Sensitive, "application/json", &artifact)
            .await
            .unwrap();
        state.artifacts.push((AX_TREE_ARTIFACT.to_owned(), r.clone()));
        state.session = ss[0].id;
        StateRepo::put_state(store.as_ref(), &state).await.unwrap();

        let snap = snapshot_memory(&store, Some(&artifacts), run.id).await.unwrap();
        assert_eq!(
            snap.fingerprints,
            vec![FingerprintSample {
                state: state.id,
                outcome: FingerprintOutcome::Match
            }]
        );
        assert!(verify_snapshot(&snap).is_clean(), "{}", verify_snapshot(&snap));
        for i in 1..16 {
            let mut next = state.clone();
            next.id = StateId::new();
            next.observed_at = ts(i);
            StateRepo::put_state(store.as_ref(), &next).await.unwrap();
        }

        // the same state pointing at a different (tampered) artifact fails the rule
        let mut input: FingerprintInput = serde_json::from_slice(&artifact).unwrap();
        input.nodes.retain(|n| n.role != "link");
        let tampered = artifacts
            .put(
                run.id,
                Sensitivity::Sensitive,
                "application/json",
                &serde_json::to_vec(&input).unwrap(),
            )
            .await
            .unwrap();
        let mut state2 = state.clone();
        state2.id = StateId::new();
        state2.observed_at = ts(16);
        state2.artifacts = vec![(AX_TREE_ARTIFACT.to_owned(), tampered)];
        StateRepo::put_state(store.as_ref(), &state2).await.unwrap();
        let r = verify_trail(
            run.id,
            TrailStore::Memory {
                store: &store,
                artifacts: Some(&artifacts),
            },
        )
        .await
        .unwrap();
        assert_eq!(rules(&r), ["signature_not_reproducible"]);
        assert_eq!(r.checked["fingerprints_recomputed"], 17);
        assert_eq!(r.checked["fingerprints_verified"], 16);
        assert!(matches!(
            &r.violations[0],
            TrailViolation::SignatureNotReproducible { state, .. } if *state == state2.id
        ));
    }

    #[tokio::test]
    async fn unavailable_evidence_never_reports_a_clean_verification() {
        let (mut state, _) = fingerprinted_state();
        state.artifacts.push((
            AX_TREE_ARTIFACT.to_owned(),
            ArtifactRef {
                id: ArtifactId::new(),
                digest: Digest([3; 32]),
            },
        ));
        for (retention, reason) in [
            (RetentionMode::Standard, "artifact store is not configured"),
            (
                RetentionMode::Zdr,
                "zdr content is ephemeral and unavailable to durable inspection",
            ),
        ] {
            let mut snapshot = clean();
            snapshot.fingerprints = verify_fingerprints(std::slice::from_ref(&state), None, retention).await;
            let report = verify_snapshot(&snapshot);
            assert!(!report.is_clean(), "{report}");
            assert!(report.violations.is_empty(), "{report}");
            assert_eq!(report.unverifiable[reason], 1);
            assert_eq!(report.checked["fingerprints_recomputed"], 0);
            assert_eq!(report.checked["fingerprints_unverifiable"], 1);
        }
        let artifacts = crawlx_storage::MemoryArtifactStore::in_memory(
            Arc::new(MemoryStore::new()),
            Arc::new(crawlx_core::SystemClock),
        );
        let mut snapshot = clean();
        snapshot.fingerprints = verify_fingerprints(
            std::slice::from_ref(&state),
            Some(&artifacts),
            RetentionMode::Standard,
        )
        .await;
        let report = verify_snapshot(&snapshot);
        assert!(!report.is_clean(), "{report}");
        assert!(report.violations.is_empty(), "{report}");
        assert_eq!(report.unverifiable["ax_tree artifact is missing or expired"], 1);

        state.artifacts.clear();
        let mut snapshot = clean();
        snapshot.fingerprints = verify_fingerprints(&[state], None, RetentionMode::Standard).await;
        let report = verify_snapshot(&snapshot);
        assert!(report.is_clean(), "{report}");
        assert_eq!(report.checked["fingerprints_skipped"], 1);
        assert_eq!(report.skipped_counts.values().sum::<u64>(), 1);
        assert!(!report.skipped[0].is_empty());
    }
}
