//! Durable execution of API replay jobs on their leased run and session.
//!
//! A started event fences each selected source action. A completion becomes durable only
//! after its browser checkpoint. Recovery never dispatches an action whose journal already
//! records intent: terminal outcomes require a matching checkpoint and live state evidence;
//! uncertain outcomes fail closed instead of repeating a possible mutation.
//! A drain may reuse the completed step's checkpoint only when its journal cursor still
//! matches; the session lease is renewed before accepting the hand-over.

use crate::actor::{SessionActor, SessionHandle, ShutdownReason};
use crate::analysis::StateAnalyzer;
use crate::checkpoint::{CheckpointPayload, Checkpointer};
use crate::error::{SessionError, WorkerError};
use crate::replay::{ReplayMode, ReplayPlan, ReplayRunner, ReplayStep, StepResult, StepVerdict};
use crate::run::{RunContext, SessionEnd};
use crawlx_core::counters::{ActionStatus, RunStatus, TerminalReason};
use crawlx_core::epoch::EpochPolicy;
use crawlx_core::observation::BrowserBuildInfo;
use crawlx_core::repo::{ActionRecord, CheckpointRecord, CrawlSession, SessionStatus};
use crawlx_core::state::StateSignature;
use crawlx_core::{ActionId, CheckpointId, CrawlRunId, PrincipalId, SessionId, StateId, TransitionId};
use crawlx_elements::IdentityResolver;
use crawlx_observe::spec;
use crawlx_scheduler::{CheckpointReason, Scheduler, HEARTBEAT_INTERVAL};
use crawlx_state::{score, ClusterConfig, Prototype};
use crawlx_storage::{PgApiRepo, SessionLease, TransitionFilter};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const EVENT_PAGE: u32 = 256;
const CONTROL_POLL: Duration = Duration::from_millis(250);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplaySpec {
    source_run_id: CrawlRunId,
    role: PrincipalId,
    mode: SpecMode,
    transition_ids: Vec<TransitionId>,
    action_ids: Vec<ActionId>,
    after_state_ids: Vec<Option<StateId>>,
    stop_on_divergence: bool,
    allow_build_mismatch: bool,
    identity_version: u16,
    state_algo_version: u16,
    target: ReplayTarget,
    build_mismatch_overridden: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReplayTarget {
    base_url: Option<url::Url>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SpecMode {
    Verify,
    Reproduce,
}

impl From<SpecMode> for ReplayMode {
    fn from(mode: SpecMode) -> Self {
        match mode {
            SpecMode::Verify => Self::Verify,
            SpecMode::Reproduce => Self::Reproduce,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Started {
    session_id: SessionId,
    index: usize,
    source_action_id: ActionId,
    source_transition_id: TransitionId,
    journal_seq: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Completed {
    session_id: SessionId,
    index: usize,
    source_action_id: ActionId,
    source_transition_id: TransitionId,
    journal_seq: u64,
    checkpoint_id: CheckpointId,
    replay_action_ids: Vec<ActionId>,
    #[serde(deserialize_with = "deserialize_persisted_step")]
    result: StepResult,
}

fn deserialize_persisted_step<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<StepResult, D::Error> {
    // Durable input owns its strings. Only closed vocabulary labels become static output.
    #[derive(Deserialize)]
    struct PersistedStep {
        seq: u64,
        action: ActionId,
        kind: crawlx_core::ActionKind,
        #[serde(flatten)]
        verdict: PersistedVerdict,
    }
    #[derive(Deserialize)]
    #[serde(tag = "result", rename_all = "snake_case")]
    enum PersistedVerdict {
        Matched { similarity: f32 },
        Diverged { similarity: f32 },
        Executed,
        ElementNotFound,
        Dropped { reason: PersistedDropReason },
        Failed { error: String },
        FailedAsRecorded { error: String },
        NotReproducible,
        Denied,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum PersistedDropReason {
        StaleEpoch,
        NotActionable,
        IdentityChanged,
        ConfirmDenied,
    }
    let persisted = PersistedStep::deserialize(deserializer)?;
    let verdict = match persisted.verdict {
        PersistedVerdict::Matched { similarity } => StepVerdict::Matched { similarity },
        PersistedVerdict::Diverged { similarity } => StepVerdict::Diverged { similarity },
        PersistedVerdict::Executed => StepVerdict::Executed,
        PersistedVerdict::ElementNotFound => StepVerdict::ElementNotFound,
        PersistedVerdict::Dropped { reason } => StepVerdict::Dropped {
            reason: match reason {
                PersistedDropReason::StaleEpoch => crate::actor::DropReason::StaleEpoch.as_str(),
                PersistedDropReason::NotActionable => crate::actor::DropReason::NotActionable.as_str(),
                PersistedDropReason::IdentityChanged => crate::actor::DropReason::IdentityChanged.as_str(),
                PersistedDropReason::ConfirmDenied => crate::actor::DropReason::ConfirmDenied.as_str(),
            },
        },
        PersistedVerdict::Failed { error } => StepVerdict::Failed { error },
        PersistedVerdict::FailedAsRecorded { error } => StepVerdict::FailedAsRecorded { error },
        PersistedVerdict::NotReproducible => StepVerdict::NotReproducible {
            kind: persisted.kind.as_str(),
        },
        PersistedVerdict::Denied => StepVerdict::Denied,
    };
    Ok(StepResult {
        seq: persisted.seq,
        action: persisted.action,
        kind: persisted.kind.as_str(),
        verdict,
    })
}

#[derive(Clone, Copy)]
enum Interrupted {
    Drain,
    Cancelled,
    Deadline,
}

/// Durable selected-path cursor shared with `ReplayRunner::steps`.
pub(crate) struct ReplayProgress {
    /// Completed source-action prefix, restored from the paged replay event stream.
    pub(crate) results: Vec<StepResult>,
    /// Whether a divergence ends execution rather than allowing the next selected action.
    pub(crate) stop_on_divergence: bool,
    session: SessionId,
    transitions: Vec<TransitionId>,
    started: Option<Started>,
    checkpoint: Option<CheckpointId>,
    journal_seq: u64,
    interrupted: Option<Interrupted>,
    reported: bool,
    browser_ready: bool,
}

fn recovery(message: &str) -> WorkerError {
    SessionError::RecoveryExhausted(message.to_owned()).into()
}

fn decode<T: serde::de::DeserializeOwned>(value: Value) -> Result<T, WorkerError> {
    serde_json::from_value(value)
        .map_err(|error| WorkerError::Config(format!("invalid replay data: {error}")))
}

impl ReplayProgress {
    async fn load(
        rc: &Arc<RunContext>,
        session: SessionId,
        spec: &ReplaySpec,
        plan: &ReplayPlan,
    ) -> Result<Self, WorkerError> {
        let mut progress = Self {
            results: Vec::with_capacity(plan.steps.len()),
            stop_on_divergence: spec.stop_on_divergence,
            session,
            transitions: spec.transition_ids.clone(),
            started: None,
            checkpoint: None,
            journal_seq: 0,
            interrupted: None,
            reported: false,
            browser_ready: false,
        };
        let journal = session_journal(rc, session).await?;
        let mut cursor = 0;
        loop {
            let events = rc.stores.events.list_after(rc.run, cursor, EVENT_PAGE).await?;
            if events.is_empty() {
                break;
            }
            for event in events {
                if event.seq <= cursor {
                    return Err(recovery("replay event cursor did not advance"));
                }
                cursor = event.seq;
                match event.kind.as_str() {
                    "replay.step_started" => {
                        if progress.reported {
                            return Err(recovery("replay step follows its final report"));
                        }
                        let started: Started = decode(event.payload)?;
                        progress.validate_step(
                            started.session_id,
                            started.index,
                            started.source_action_id,
                            started.source_transition_id,
                            plan,
                        )?;
                        if started.journal_seq < progress.journal_seq {
                            return Err(recovery("replay journal cursor moved backwards"));
                        }
                        progress.started = Some(started);
                    }
                    "replay.step_completed" => {
                        let completed: Completed = decode(event.payload)?;
                        progress.validate_step(
                            completed.session_id,
                            completed.index,
                            completed.source_action_id,
                            completed.source_transition_id,
                            plan,
                        )?;
                        let started = progress
                            .started
                            .as_ref()
                            .ok_or_else(|| recovery("replay completion has no durable start"))?;
                        let step = &plan.steps[completed.index];
                        if completed.result.action != step.action.id
                            || completed.result.seq != step.action.seq
                            || completed.result.kind != step.action.key.action_kind.as_str()
                            || completed.journal_seq < started.journal_seq
                            || !completed.replay_action_ids.iter().copied().eq(journal
                                .iter()
                                .filter(|action| {
                                    action.seq > started.journal_seq && action.seq <= completed.journal_seq
                                })
                                .map(|action| action.id))
                        {
                            return Err(recovery("replay completion does not match the selected action"));
                        }
                        progress.journal_seq = completed.journal_seq;
                        progress.checkpoint = Some(completed.checkpoint_id);
                        progress.results.push(completed.result);
                        progress.started = None;
                    }
                    "replay.completed" => {
                        if progress.reported || progress.started.is_some() {
                            return Err(recovery("replay final report has an unfinished step"));
                        }
                        let expected = serde_json::to_value(&progress.results)
                            .map_err(|error| WorkerError::Other(error.to_string()))?;
                        if event.payload.get("steps") != Some(&expected)
                            || event.payload.get("identity_version").and_then(Value::as_u64)
                                != Some(u64::from(plan.identity_version))
                            || event.payload.get("verify").and_then(Value::as_bool)
                                != Some(matches!(spec.mode, SpecMode::Verify))
                        {
                            return Err(recovery("replay final report does not match its durable cursor"));
                        }
                        progress.reported = true;
                    }
                    _ => {}
                }
            }
        }
        Ok(progress)
    }

    fn validate_step(
        &self,
        session: SessionId,
        index: usize,
        action: ActionId,
        transition: TransitionId,
        plan: &ReplayPlan,
    ) -> Result<(), WorkerError> {
        if session != self.session
            || index != self.results.len()
            || self.transitions.get(index) != Some(&transition)
            || plan.steps.get(index).map(|step| step.action.id) != Some(action)
        {
            return Err(recovery("replay events are not a selected-action prefix"));
        }
        Ok(())
    }

    /// Check fresh authorization and run control without opening a new step fence.
    ///
    /// # Errors
    /// Fails if authorization or durable run control cannot be read, or checkpointing fails.
    pub(crate) async fn guard(
        &mut self,
        rc: &Arc<RunContext>,
        handle: &SessionHandle,
    ) -> Result<bool, WorkerError> {
        self.control(rc, Some(handle)).await
    }

    async fn control(
        &mut self,
        rc: &Arc<RunContext>,
        handle: Option<&SessionHandle>,
    ) -> Result<bool, WorkerError> {
        let mut paused = false;
        loop {
            if let Some(guard) = &rc.authorization {
                guard.check_now().await?;
            }
            let run = rc.stores.runs.get(rc.run).await?;
            if let Some(guard) = &rc.authorization {
                if guard.record().tenant != run.tenant {
                    return Err(WorkerError::PolicyDenied(
                        "authorization tenant mismatch".to_owned(),
                    ));
                }
                guard
                    .record()
                    .check_profile(rc.crawl.safety.profile)
                    .map_err(|error| WorkerError::PolicyDenied(error.to_string()))?;
                guard
                    .scope()
                    .check_covers_url(&rc.seed_url()?.url)
                    .map_err(|error| WorkerError::PolicyDenied(error.to_string()))?;
            }
            if run.status == RunStatus::Cancelled {
                self.interrupted = Some(Interrupted::Cancelled);
                return Ok(false);
            }
            if rc.cancel.is_cancelled() {
                if self.browser_ready && self.started.is_none() && self.checkpoint.is_some() {
                    // Cancellation blocks actor commands, including a redundant checkpoint.
                    // Reuse only the exact durable completion boundary, never an older snapshot.
                    let checkpoint = rc
                        .stores
                        .checkpoints
                        .latest(self.session)
                        .await?
                        .ok_or_else(|| recovery("replay drain lost its committed checkpoint"))?;
                    let journal = session_journal(rc, self.session).await?;
                    let completed_count =
                        u64::try_from(journal.iter().filter(|action| finished(action)).count())
                            .map_err(|_| recovery("replay journal action count overflow"))?;
                    validate_checkpoint(&checkpoint, rc.run, self.session, completed_count, &journal)?;
                    if Some(checkpoint.id) != self.checkpoint
                        || checkpoint.expires_at <= rc.clock.now()
                        || journal.iter().map(|action| action.seq).max().unwrap_or(0) != self.journal_seq
                        || journal.iter().any(|action| {
                            matches!(
                                action.status,
                                ActionStatus::Intended | ActionStatus::Unknown | ActionStatus::Reconciled
                            )
                        })
                    {
                        return Err(recovery("replay drain checkpoint cursor is not current"));
                    }
                } else if self.browser_ready {
                    if let Some(handle) = handle {
                        handle
                            .checkpoint(CheckpointReason::Shutdown)
                            .await
                            .map_err(|_| recovery("replay drain could not persist a checkpoint"))?;
                    }
                }
                self.interrupted = Some(Interrupted::Drain);
                return Ok(false);
            }
            match run.status {
                RunStatus::Running => return Ok(true),
                RunStatus::Paused => {
                    if !paused {
                        if self.browser_ready {
                            if let Some(handle) = handle {
                                handle.checkpoint(CheckpointReason::Pause).await?;
                            }
                        }
                        paused = true;
                    }
                    tokio::select! {
                        () = rc.cancel.cancelled() => {},
                        () = tokio::time::sleep(CONTROL_POLL) => {},
                    }
                }
                RunStatus::Queued | RunStatus::Completed | RunStatus::Failed => {
                    return Err(WorkerError::PolicyDenied(
                        "replay run is not executable".to_owned(),
                    ));
                }
                RunStatus::Cancelled => {
                    self.interrupted = Some(Interrupted::Cancelled);
                    return Ok(false);
                }
            }
        }
    }

    /// Fence a selected source action durably before the actor can execute it.
    ///
    /// # Errors
    /// Fails if run control, authorization, or the durable start event cannot be written.
    pub(crate) async fn before_step(
        &mut self,
        rc: &Arc<RunContext>,
        handle: &SessionHandle,
        index: usize,
        step: &ReplayStep,
    ) -> Result<bool, WorkerError> {
        if !self.guard(rc, handle).await? {
            return Ok(false);
        }
        if index != self.results.len() {
            return Err(recovery("replay action cursor is not contiguous"));
        }
        let transition = *self
            .transitions
            .get(index)
            .ok_or_else(|| recovery("replay action has no selected transition"))?;
        let journal = session_journal(rc, self.session).await?;
        let journal_seq = journal.iter().map(|action| action.seq).max().unwrap_or(0);
        rc.stores
            .events
            .append(
                rc.run,
                "replay.step_started",
                json!({
                    "sessionId": self.session,
                    "index": index,
                    "sourceActionId": step.action.id,
                    "sourceTransitionId": transition,
                    "journalSeq": journal_seq,
                }),
            )
            .await?;
        self.started = Some(Started {
            session_id: self.session,
            index,
            source_action_id: step.action.id,
            source_transition_id: transition,
            journal_seq,
        });
        Ok(true)
    }

    /// Checkpoint the actor after its journal outcome, then append the durable result cursor.
    ///
    /// # Errors
    /// Fails if the checkpoint or completion event cannot be persisted.
    pub(crate) async fn completed_step(
        &mut self,
        rc: &Arc<RunContext>,
        handle: &SessionHandle,
        index: usize,
        result: &StepResult,
    ) -> Result<(), WorkerError> {
        let started = self
            .started
            .as_ref()
            .ok_or_else(|| recovery("replay result has no durable start"))?;
        if index != self.results.len() || started.index != index || started.source_action_id != result.action
        {
            return Err(recovery("replay result does not match its durable start"));
        }
        let checkpoint = handle
            .checkpoint(CheckpointReason::CadenceActions)
            .await
            .map_err(|error| match error {
                SessionError::ExecutionDeadlineReached => WorkerError::from(error),
                other => recovery(&format!("replay result checkpoint failed: {other}")),
            })?;
        let journal = session_journal(rc, self.session).await?;
        let journal_seq = journal.iter().map(|action| action.seq).max().unwrap_or(0);
        let replay_action_ids: Vec<_> = journal
            .iter()
            .filter(|action| action.seq > started.journal_seq)
            .map(|action| action.id)
            .collect();
        rc.stores
            .events
            .append(
                rc.run,
                "replay.step_completed",
                json!({
                    "sessionId": self.session,
                    "index": index,
                    "sourceActionId": started.source_action_id,
                    "sourceTransitionId": started.source_transition_id,
                    "journalSeq": journal_seq,
                    "checkpointId": checkpoint,
                    "replayActionIds": replay_action_ids,
                    "result": result,
                }),
            )
            .await?;
        self.results.push(result.clone());
        self.checkpoint = Some(checkpoint);
        self.journal_seq = journal_seq;
        self.started = None;
        Ok(())
    }
}

async fn session_journal(rc: &Arc<RunContext>, session: SessionId) -> Result<Vec<ActionRecord>, WorkerError> {
    let mut actions: Vec<_> = rc
        .stores
        .journal
        .list(rc.run, None)
        .await?
        .into_iter()
        .filter(|action| action.session == session)
        .collect();
    actions.sort_by_key(|action| action.seq);
    Ok(actions)
}

async fn journal_afterstate(
    rc: &Arc<RunContext>,
    action: &ActionRecord,
) -> Result<Option<StateId>, WorkerError> {
    if let Some(memory) = &rc.stores.memory {
        return Ok(memory
            .transitions(rc.run)
            .into_iter()
            .find(|transition| transition.action == action.id && transition.session == action.session)
            .and_then(|transition| transition.after));
    }
    if let Some(pg) = &rc.stores.pg {
        let transitions = PgApiRepo::new(pg.clone())
            .transitions_list(
                rc.run,
                &TransitionFilter {
                    session: Some(action.session),
                    ..TransitionFilter::default()
                },
            )
            .await?;
        return Ok(transitions
            .into_iter()
            .find(|transition| transition.action.id == action.id)
            .and_then(|transition| transition.after));
    }
    Err(recovery("replay store exposes no durable transition evidence"))
}

fn finished(action: &ActionRecord) -> bool {
    matches!(action.status, ActionStatus::Succeeded | ActionStatus::Failed)
}

fn similarity(actual: &StateSignature, recorded: &StateSignature) -> f32 {
    score(
        actual,
        &Prototype {
            signature: recorded.clone(),
            minhash_union: recorded.semantic_affordance_minhash.clone(),
            consequence: None,
        },
    )
}

async fn selected_plan(
    rc: &Arc<RunContext>,
    session: &CrawlSession,
    spec: &ReplaySpec,
) -> Result<(ReplayPlan, Vec<BrowserBuildInfo>), WorkerError> {
    if spec.state_algo_version != StateSignature::VERSION {
        return Err(WorkerError::Config(
            "replay state signature version mismatch".to_owned(),
        ));
    }
    if spec.source_run_id == rc.run
        || spec.role != session.role
        || spec.action_ids.is_empty()
        || spec.action_ids.len() != spec.transition_ids.len()
        || session.run != rc.run
        || spec.action_ids.len() != spec.after_state_ids.len()
        || spec.identity_version != rc.crawl.crawl.identity.version.decision_version()
        || (spec.build_mismatch_overridden && !spec.allow_build_mismatch)
    {
        return Err(WorkerError::Config("invalid selected replay path".to_owned()));
    }
    if spec.action_ids.iter().copied().collect::<BTreeSet<_>>().len() != spec.action_ids.len()
        || spec.transition_ids.iter().copied().collect::<BTreeSet<_>>().len() != spec.transition_ids.len()
    {
        return Err(WorkerError::Config(
            "replay path repeats a recorded action".to_owned(),
        ));
    }
    let replay = rc.stores.runs.get(rc.run).await?;
    if spec
        .target
        .base_url
        .as_ref()
        .is_some_and(|base| base != &replay.config.seed_url)
    {
        return Err(WorkerError::Config(
            "replay target does not match its queued run".to_owned(),
        ));
    }
    let source = rc.stores.runs.get(spec.source_run_id).await?;
    if source.tenant != replay.tenant {
        return Err(WorkerError::Config("replay source tenant mismatch".to_owned()));
    }
    let source_states = rc.stores.states.list_states(spec.source_run_id).await?;
    let mut selected: Option<ReplayPlan> = None;
    let mut builds = Vec::new();
    let mut source_sessions = BTreeSet::new();
    for (index, action) in spec.action_ids.iter().enumerate() {
        let mut loaded = ReplayPlan::load(&rc.stores, spec.source_run_id, *action).await?;
        if loaded.run.tenant != replay.tenant
            || loaded.session.role != spec.role
            || loaded.identity_version != spec.identity_version
        {
            return Err(WorkerError::Config(
                "replay source tenant, role or identity mismatch".to_owned(),
            ));
        }
        let resolver =
            IdentityResolver::new().with_identity_version(loaded.run.config.crawl.identity.version, "");
        if !resolver.accepts_replay_version(spec.identity_version) {
            return Err(WorkerError::Config("replay identity version mismatch".to_owned()));
        }
        let mut step = loaded
            .steps
            .drain(..)
            .find(|step| step.action.id == *action)
            .ok_or_else(|| WorkerError::Config("selected replay action was not performed".to_owned()))?;
        step.recorded_after = match spec.after_state_ids[index] {
            Some(id) => Some(
                source_states
                    .iter()
                    .find(|state| state.id == id && state.session == loaded.session.id)
                    .cloned()
                    .ok_or_else(|| WorkerError::Config("selected replay afterstate is missing".to_owned()))?,
            ),
            None => None,
        };
        if step.action.key.principal != spec.role {
            return Err(WorkerError::Config(
                "selected replay action has incompatible identity".to_owned(),
            ));
        }
        if step.recorded_before.signature.version != spec.state_algo_version
            || step
                .recorded_after
                .as_ref()
                .is_some_and(|state| state.signature.version != spec.state_algo_version)
        {
            return Err(WorkerError::Config(
                "replay state signature version mismatch".to_owned(),
            ));
        }
        if source_sessions.insert(loaded.session.id) {
            match loaded.session.browser.as_ref() {
                Some(build) => builds.push(build.clone()),
                None if spec.allow_build_mismatch => {}
                None => {
                    return Err(WorkerError::Config(
                        "source replay browser build is missing".to_owned(),
                    ))
                }
            }
        }
        match &mut selected {
            Some(plan) => plan.steps.push(step),
            None => {
                loaded.steps.push(step);
                selected = Some(loaded);
            }
        }
    }
    let plan = selected.ok_or_else(|| WorkerError::Config("replay path is empty".to_owned()))?;
    Ok((plan, builds))
}

async fn restore_progress(
    rc: &Arc<RunContext>,
    handle: &SessionHandle,
    analyzer: &StateAnalyzer,
    progress: &mut ReplayProgress,
    plan: &ReplayPlan,
    mode: ReplayMode,
) -> Result<bool, WorkerError> {
    let journal = session_journal(rc, progress.session).await?;
    let latest = rc.stores.checkpoints.latest(progress.session).await?;
    if progress.results.is_empty() && progress.started.is_none() && journal.is_empty() && latest.is_none() {
        return Ok(false);
    }
    if !progress.results.is_empty() && progress.checkpoint.is_none() {
        return Err(recovery("replay completion has no checkpoint cursor"));
    }
    if journal.iter().any(|action| {
        matches!(
            action.status,
            ActionStatus::Intended | ActionStatus::Unknown | ActionStatus::Reconciled
        )
    }) {
        return Err(recovery(
            "replay has an uncertain journal outcome; mutation will not be repeated",
        ));
    }
    let pending: Vec<_> = journal
        .iter()
        .filter(|action| {
            action.seq
                > progress
                    .started
                    .as_ref()
                    .map_or(progress.journal_seq, |started| started.journal_seq)
        })
        .filter(|action| action.status != ActionStatus::Proposed)
        .collect();
    if pending.len() > 1 || (!pending.is_empty() && progress.started.is_none()) {
        return Err(recovery("replay journal has no unique selected-action fence"));
    }
    let completed_count = u64::try_from(journal.iter().filter(|action| finished(action)).count())
        .map_err(|_| recovery("replay journal action count overflow"))?;
    let Some(checkpoint) = latest else {
        if progress.results.is_empty() && pending.is_empty() {
            // A start without any intent has no browser effect and may safely be rebuilt.
            return Ok(false);
        }
        return Err(recovery("replay progress has no safe checkpoint"));
    };
    validate_checkpoint(&checkpoint, rc.run, progress.session, completed_count, &journal)?;
    if !progress.guard(rc, handle).await? {
        return Ok(true);
    }
    let checkpointer = Checkpointer::new(
        rc.stores.tenant,
        rc.run,
        progress.session,
        Arc::clone(&rc.stores.checkpoints),
        Arc::clone(&rc.stores.artifacts),
        Arc::clone(&rc.clock),
        rc.crawl.retention.days,
    )
    .with_keys(Arc::clone(&rc.checkpoint_keys));
    let payload = checkpointer.load(&checkpoint).await?;
    if checkpoint.expires_at <= rc.clock.now()
        || payload.version != CheckpointPayload::VERSION
        || payload.action_seq != checkpoint.action_seq
    {
        return Err(recovery("replay checkpoint metadata is incompatible"));
    }
    if let Some(guard) = &rc.authorization {
        let url = url::Url::parse(&payload.url).map_err(|_| recovery("replay checkpoint URL is invalid"))?;
        guard
            .scope()
            .check_covers_url(&url)
            .map_err(|error| WorkerError::PolicyDenied(error.to_string()))?;
    }
    handle.restore(checkpoint.id).await.map_err(|error| match error {
        SessionError::ExecutionDeadlineReached => WorkerError::from(error),
        _ => recovery("replay checkpoint could not be restored"),
    })?;
    progress.browser_ready = true;
    if let Some(material) = rc.login_material(&plan.session.role.0).await? {
        // Register restored credentials without executing the login form a second time.
        handle.authenticated(material).await?;
    }
    if let Some(committed) = journal.iter().rev().find(|action| finished(action)) {
        let after_id = journal_afterstate(rc, committed)
            .await?
            .ok_or_else(|| recovery("committed replay action has no durable afterstate"))?;
        let states = rc.stores.states.list_states(rc.run).await?;
        let after = states
            .iter()
            .find(|state| state.id == after_id && state.session == progress.session)
            .ok_or_else(|| recovery("committed replay afterstate is missing"))?;
        let bundle = handle.observe(spec::after_action()).await?;
        let actual = analyzer.analyze(&bundle).await;
        if similarity(&actual.state.signature, &after.signature) < ClusterConfig::default().theta_review {
            return Err(recovery(
                "restored replay checkpoint does not match the committed afterstate",
            ));
        }
        if let Some(pending) = pending.first() {
            let started = progress
                .started
                .as_ref()
                .ok_or_else(|| recovery("replay action fence is missing"))?;
            let step = plan
                .steps
                .get(started.index)
                .ok_or_else(|| recovery("replay action cursor is out of range"))?;
            if pending.id != committed.id || pending.strategy != "replay" || pending.key != step.action.key {
                return Err(recovery(
                    "committed replay action does not match its selected source",
                ));
            }
            let verdict = match pending.status {
                ActionStatus::Failed if step.action.status == ActionStatus::Failed => {
                    StepVerdict::FailedAsRecorded {
                        error: "recovered failed journal outcome".to_owned(),
                    }
                }
                ActionStatus::Failed => StepVerdict::Failed {
                    error: "recovered failed journal outcome".to_owned(),
                },
                ActionStatus::Succeeded => match (mode, step.recorded_after.as_ref()) {
                    (ReplayMode::Reproduce, _) => StepVerdict::Executed,
                    (ReplayMode::Verify, Some(recorded)) => {
                        let similarity = similarity(&actual.state.signature, &recorded.signature);
                        if similarity >= ClusterConfig::default().theta_review {
                            StepVerdict::Matched { similarity }
                        } else {
                            StepVerdict::Diverged { similarity }
                        }
                    }
                    (ReplayMode::Verify, None) => StepVerdict::Diverged { similarity: 0.0 },
                },
                _ => return Err(recovery("replay journal outcome cannot be recovered safely")),
            };
            let index = started.index;
            let result = StepResult {
                seq: step.action.seq,
                action: step.action.id,
                kind: step.action.key.action_kind.as_str(),
                verdict,
            };
            progress.completed_step(rc, handle, index, &result).await?;
        }
    }
    Ok(true)
}

fn validate_checkpoint(
    checkpoint: &CheckpointRecord,
    run: CrawlRunId,
    session: SessionId,
    completed_count: u64,
    journal: &[ActionRecord],
) -> Result<(), WorkerError> {
    if checkpoint.run != run
        || checkpoint.session != session
        || checkpoint.action_seq != completed_count
        || journal
            .iter()
            .filter(|action| finished(action))
            .any(|action| action.finished_at.is_none_or(|at| checkpoint.created_at < at))
    {
        return Err(recovery(
            "latest replay checkpoint does not cover committed actions",
        ));
    }
    Ok(())
}

/// Execute only the selected replay path, keeping the original source immutable.
pub(crate) async fn run_session(
    rc: Arc<RunContext>,
    scheduler: Scheduler,
    lease: SessionLease,
    spec: Value,
) -> SessionEnd {
    let producer = rc.stores.session_producer(rc.run, &lease);
    let authority = rc.stores.pg_secret_authority.clone();
    let result = crawlx_core::custody::with_producer(
        producer.clone(),
        crate::custody_renewal::with_custody_renewal(authority, producer, async {
            Ok::<_, WorkerError>(Box::pin(run_session_scoped(rc, scheduler, lease, spec)).await)
        }),
    )
    .await;
    match result {
        Ok(end) => end,
        Err(error) => SessionEnd {
            terminal: TerminalReason::FatalError,
            error: Some(error.to_string()),
        },
    }
}

async fn run_session_scoped(
    rc: Arc<RunContext>,
    scheduler: Scheduler,
    lease: SessionLease,
    spec: Value,
) -> SessionEnd {
    let keepalive_cancel = CancellationToken::new();
    let _keepalive_guard = keepalive_cancel.clone().drop_guard();
    let keepalive = scheduler.keep_alive(lease.clone(), HEARTBEAT_INTERVAL, keepalive_cancel.clone());
    let cancel_on_lease_loss = rc.cancel.clone();
    let keepalive = tokio::spawn(async move {
        let result = keepalive.await;
        if !matches!(result, Ok(Ok(()))) {
            cancel_on_lease_loss.cancel();
        }
        result
    });
    let result = session_body(&rc, &lease, spec).await;
    keepalive_cancel.cancel();
    let _ = keepalive.await;
    let cancelled = rc
        .stores
        .runs
        .get(rc.run)
        .await
        .is_ok_and(|run| run.status == RunStatus::Cancelled);
    let release_status = match &result {
        Err(_) => SessionStatus::Failed,
        Ok(_) if cancelled => SessionStatus::Cancelled,
        Ok(Some(Interrupted::Drain)) => SessionStatus::Recovering,
        Ok(Some(Interrupted::Cancelled)) => SessionStatus::Cancelled,
        Ok(Some(Interrupted::Deadline)) | Ok(None) => SessionStatus::Completed,
    };
    let release = scheduler
        .release(&lease, release_status)
        .await
        .map_err(WorkerError::from);
    let result = crate::replay::finish_replay(result, Ok(()), release);
    match result {
        Ok(_) if cancelled => SessionEnd {
            terminal: TerminalReason::Cancelled,
            error: None,
        },
        Ok(Some(Interrupted::Drain | Interrupted::Cancelled)) => SessionEnd {
            terminal: TerminalReason::Cancelled,
            error: None,
        },
        Ok(Some(Interrupted::Deadline)) => SessionEnd {
            terminal: TerminalReason::DeadlineReached,
            error: None,
        },
        Ok(None) => SessionEnd {
            terminal: TerminalReason::FrontierExhausted,
            error: None,
        },
        Err(error) => {
            let terminal = match &error {
                WorkerError::Session(
                    SessionError::RecoveryExhausted(_) | SessionError::CrashedDuringAction(_),
                ) => TerminalReason::RecoveryExhausted,
                WorkerError::Authorization(_) => TerminalReason::AuthorizationRevoked,
                _ => TerminalReason::FatalError,
            };
            tracing::error!(session = %lease.session.id, error = %error, "replay session failed");
            SessionEnd {
                terminal,
                error: Some(error.to_string()),
            }
        }
    }
}

async fn session_body(
    rc: &Arc<RunContext>,
    lease: &SessionLease,
    value: Value,
) -> Result<Option<Interrupted>, WorkerError> {
    let session = &lease.session;
    if let Some(guard) = &rc.authorization {
        guard.check_now().await?;
    }
    let spec: ReplaySpec = decode(value)?;
    let (plan, source_builds) = selected_plan(rc, session, &spec).await?;
    let mode = ReplayMode::from(spec.mode);
    let mut progress = ReplayProgress::load(rc, session.id, &spec, &plan).await?;
    if !progress.control(rc, None).await? {
        return Ok(progress.interrupted);
    }
    if progress.reported {
        return Ok(None);
    }
    let mut cfg = rc.session_config(session);
    let login = rc.prepare_session_login(session, &mut cfg).await?;
    if rc.crawl.safety.profile == crawlx_core::SafetyProfile::AuthorizedSecurityTest {
        cfg.epoch_policy = EpochPolicy::strict();
    }
    let pooled = rc.acquire_bound_session(lease, &mut cfg).await?;
    let login_bounds = crate::run::LoginBounds::from(&cfg);
    let actual_build = pooled.build.clone();
    let analyzer = Arc::new(StateAnalyzer::new(
        rc.run,
        session.id,
        rc.clusters.clone(),
        Arc::clone(&rc.stores.artifacts),
        Arc::clone(&rc.clock),
        rc.crawl.capture.clone(),
        (&rc.controls, &rc.captcha_secrets),
    ));
    // Checkpoint validation analyzes live state before the next step; it must attach
    // to durable clusters rather than create an unpersisted replacement cluster.
    rc.clusters.sync(rc.stores.states.as_ref(), rc.run).await?;
    let handle = SessionActor::spawn(
        cfg,
        rc.services(),
        Arc::clone(&analyzer),
        rc.crawl.retention.days,
        pooled,
    )
    .await?;
    let result = async {
        // Compare the created actor's actual browser, not the deployment's expected pin.
        if !spec.allow_build_mismatch
            && source_builds.iter().any(|source| {
                source.chromium_version != actual_build.chromium_version
                    || source.cdp_revision != actual_build.cdp_revision
            })
        {
            return Err(WorkerError::Config("replay browser build mismatch".to_owned()));
        }
        if !progress.guard(rc, &handle).await? {
            return Ok(progress.interrupted);
        }
        let restored = restore_progress(rc, &handle, &analyzer, &mut progress, &plan, mode).await?;
        if progress.interrupted.is_some() {
            return Ok(progress.interrupted);
        }
        if !restored {
            if !progress.guard(rc, &handle).await? {
                return Ok(progress.interrupted);
            }
            handle
                .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                    rc.seed_url()?,
                    0,
                    None,
                ))
                .await?;
            if let Some(material) = login {
                if !progress.guard(rc, &handle).await? {
                    return Ok(progress.interrupted);
                }
                rc.login_session_bounded(session, &handle, &analyzer, material, login_bounds)
                    .await?;
            }
            progress.browser_ready = true;
        } else {
            // Restored authentication spends no new login envelope.
            crate::role_budget::RoleBudget::load(rc, session)
                .await?
                .reserve_login(rc, chrono::Duration::zero())
                .await?;
            let role_budget = crate::role_budget::RoleBudget::load(rc, session).await?;
            let deadline = role_budget.deadline().min(rc.budget.lock().deadline());
            handle.narrow_binding_deadline(deadline).await?;
        }
        let report = ReplayRunner::steps(
            rc,
            &session.role,
            &handle,
            &analyzer,
            &plan,
            mode,
            Some(&mut progress),
        )
        .await?;
        if !progress.guard(rc, &handle).await? {
            return Ok(progress.interrupted);
        }
        rc.stores
            .events
            .append(
                rc.run,
                "replay.completed",
                serde_json::to_value(&report).map_err(|error| WorkerError::Other(error.to_string()))?,
            )
            .await?;
        Ok(None)
    }
    .await;
    // A drain can arrive after the per-step guard while the actor awaits
    // admission. Only its typed pre-dispatch cancellation is recoverable;
    // independently observed storage, authorization and browser errors stay fatal.
    let result = match result {
        Err(WorkerError::Session(SessionError::Cancelled)) if rc.cancel.is_cancelled() => {
            progress.guard(rc, &handle).await.map(|_| progress.interrupted)
        }
        Err(WorkerError::Session(SessionError::ExecutionDeadlineReached)) => {
            // The path did not finish. Preserve all existing durable recovery evidence;
            // neither emit replay.completed nor manufacture a matched step/report.
            let authority = match &rc.authorization {
                Some(guard) => guard.check_execution_stop().await,
                None => Ok(()),
            };
            authority.map(|()| Some(Interrupted::Deadline))
        }
        other => other,
    };
    let result = match result {
        Ok(Some(Interrupted::Drain)) => rc
            .stores
            .leases
            .heartbeat(lease)
            .await
            .map(|_| Some(Interrupted::Drain))
            .map_err(WorkerError::from),
        other => other,
    };
    let reason = match &result {
        Ok(Some(Interrupted::Drain)) if progress.browser_ready => ShutdownReason::Graceful,
        Ok(Some(Interrupted::Drain)) => ShutdownReason::Cancelled,
        Ok(Some(Interrupted::Cancelled)) | Err(_) => ShutdownReason::Cancelled,
        Ok(Some(Interrupted::Deadline)) => ShutdownReason::Cancelled,
        Ok(None) => ShutdownReason::Completed,
    };
    let shutdown = handle.shutdown(reason).await.map_err(WorkerError::from);
    crate::replay::finish_replay(result, shutdown, Ok(()))
}

#[cfg(test)]
mod deadline_consumer_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::run::login_lifecycle_tests::fixture_with_bounds;

    fn progress(session: SessionId) -> ReplayProgress {
        ReplayProgress {
            results: Vec::new(),
            stop_on_divergence: true,
            session,
            transitions: Vec::new(),
            started: None,
            checkpoint: None,
            journal_seq: 0,
            interrupted: None,
            reported: false,
            browser_ready: false,
        }
    }

    async fn assert_no_completion(rc: &Arc<RunContext>) {
        let events = rc.stores.events.list_after(rc.run, 0, 256).await.unwrap();
        assert!(!events
            .iter()
            .any(|event| matches!(event.kind.as_str(), "replay.step_completed" | "replay.completed",)));
    }

    #[tokio::test(start_paused = true)]
    async fn completed_step_forwards_execution_expiry_without_fabricating_durable_progress() {
        for failure in 0..3 {
            let f = fixture_with_bounds(
                chrono::Duration::minutes(5),
                Some(chrono::Duration::milliseconds(100)),
                (failure == 1).then_some(chrono::Duration::milliseconds(50)),
            )
            .await;
            let rc = Arc::new(f.rc);
            let action = ActionId::new();
            let transition = TransitionId::new();
            let mut progress = progress(f.lease.session.id);
            rc.stores
                .events
                .append(
                    rc.run,
                    "replay.step_started",
                    json!({
                        "sessionId": progress.session,
                        "index": 0,
                        "sourceActionId": action,
                        "sourceTransitionId": transition,
                        "journalSeq": 0,
                    }),
                )
                .await
                .unwrap();
            progress.started = Some(Started {
                session_id: progress.session,
                index: 0,
                source_action_id: action,
                source_transition_id: transition,
                journal_seq: 0,
            });
            if failure == 2 {
                rc.stores
                    .leases
                    .release(&f.lease, SessionStatus::Failed)
                    .await
                    .unwrap();
            }
            tokio::time::advance(Duration::from_millis(100)).await;
            f.handle
                .wait_state(|state| state == crate::actor::SessionState::Closed)
                .await;
            let error = progress
                .completed_step(
                    &rc,
                    &f.handle,
                    0,
                    &StepResult {
                        seq: 1,
                        action,
                        kind: "click",
                        verdict: StepVerdict::Executed,
                    },
                )
                .await
                .unwrap_err();
            if failure == 0 {
                assert!(matches!(
                    error,
                    WorkerError::Session(SessionError::ExecutionDeadlineReached)
                ));
            } else {
                assert!(matches!(
                    error,
                    WorkerError::Session(SessionError::RecoveryExhausted(_))
                ));
            }
            assert!(progress.results.is_empty());
            assert!(
                progress.started.is_some(),
                "the original unfinished fence must survive"
            );
            assert!(progress.checkpoint.is_none());
            assert!(!progress.reported);
            assert!(rc
                .stores
                .checkpoints
                .latest(progress.session)
                .await
                .unwrap()
                .is_none());
            assert_no_completion(&rc).await;
            let shutdown = f.handle.shutdown(ShutdownReason::Cancelled).await;
            assert_eq!(shutdown.is_ok(), failure == 0);
            rc.supervisor.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn restore_progress_forwards_execution_expiry_only_after_required_checkpoint_evidence() {
        for failure in 0..3 {
            let f = fixture_with_bounds(
                chrono::Duration::minutes(5),
                Some(chrono::Duration::milliseconds(100)),
                None,
            )
            .await;
            let rc = Arc::new(f.rc);
            // Navigation alone does not populate the actor's last observation. A real
            // recovery checkpoint needs its observed URL, not the empty initial cache.
            let observed = f.handle.observe(spec::after_action()).await.unwrap();
            let mut checkpoint = f
                .handle
                .checkpoint(CheckpointReason::CadenceActions)
                .await
                .unwrap();
            let record = rc
                .stores
                .checkpoints
                .latest(f.lease.session.id)
                .await
                .unwrap()
                .unwrap();
            let payload = Checkpointer::new(
                rc.stores.tenant,
                rc.run,
                f.lease.session.id,
                Arc::clone(&rc.stores.checkpoints),
                Arc::clone(&rc.stores.artifacts),
                Arc::clone(&rc.clock),
                rc.crawl.retention.days,
            )
            .with_keys(Arc::clone(&rc.checkpoint_keys))
            .load(&record)
            .await
            .unwrap();
            assert_eq!(
                payload.url,
                observed.url.url.as_str(),
                "checkpoint needs actual observed URL evidence"
            );
            assert!(
                payload.request_route.is_some(),
                "checkpoint needs the admitted handler route"
            );
            if failure == 2 {
                // Expired execution cannot excuse missing durable recovery evidence.
                let mut invalid = rc
                    .stores
                    .checkpoints
                    .latest(f.lease.session.id)
                    .await
                    .unwrap()
                    .unwrap();
                invalid.id = CheckpointId::new();
                invalid.action_seq = invalid.action_seq.checked_add(1).unwrap();
                rc.stores.checkpoints.put(&invalid).await.unwrap();
                checkpoint = invalid.id;
            }
            let plan = ReplayPlan::checkpoint_test_plan(
                rc.stores.runs.get(rc.run).await.unwrap(),
                f.lease.session.clone(),
            );
            let mut progress = progress(f.lease.session.id);
            if failure == 1 {
                rc.stores
                    .leases
                    .release(&f.lease, SessionStatus::Failed)
                    .await
                    .unwrap();
            }
            tokio::time::advance(Duration::from_millis(100)).await;
            f.handle
                .wait_state(|state| state == crate::actor::SessionState::Closed)
                .await;
            let error = restore_progress(
                &rc,
                &f.handle,
                &f.analyzer,
                &mut progress,
                &plan,
                ReplayMode::Verify,
            )
            .await
            .unwrap_err();
            if failure != 0 {
                assert!(
                    matches!(&error, WorkerError::Session(SessionError::RecoveryExhausted(_))),
                    "restore case {failure}: {error:?}: {error}",
                );
            } else {
                assert!(
                    matches!(
                        &error,
                        WorkerError::Session(SessionError::ExecutionDeadlineReached)
                    ),
                    "restore case {failure}: {error:?}: {error}",
                );
            }
            assert!(progress.results.is_empty());
            assert!(progress.checkpoint.is_none());
            assert!(!progress.browser_ready);
            assert!(!progress.reported);
            assert_eq!(
                rc.stores
                    .checkpoints
                    .latest(progress.session)
                    .await
                    .unwrap()
                    .unwrap()
                    .id,
                checkpoint
            );
            assert_no_completion(&rc).await;
            let shutdown = f.handle.shutdown(ShutdownReason::Cancelled).await;
            assert_eq!(shutdown.is_ok(), failure != 1);
            rc.supervisor.shutdown().await;
        }
    }
}
