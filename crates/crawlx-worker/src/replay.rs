//! `ReplayRunner`: re-execute a recorded transition path against the live target through a
//! fresh Session Actor (`crawlx replay <run-id> --to <transition-id>`).
//!
//! The path is the target session's performed actions up to and including the target action,
//! in journal order: the `succeeded` ones and the `failed` ones (a browser error can leave the
//! page changed, e.g. a `Select` that toggled a custom combobox shut before it failed to find
//! its option, so a path without it never reaches the recorded states). Each step is rebuilt
//! from its `ActionContextKey` (element identity + kind + input class): the identity is resolved
//! against the current page, the action is adjudicated by the safety kernel of the recorded
//! profile and executed through the actor, so a replay never bypasses a safety rule. Replays
//! write their evidence to a separate run; the recorded run is never modified.
//! Recorded login actions are restored once through the governed login runner before this
//! path starts; they are not rebuilt as exploration actions from their selector-based keys.
//!
//! * `verify`: after each step the new state's fingerprint is compared with the recorded
//!   after-state (`crawlx_state::score` against the recorded signature, ≥ θ_review).
//! * `reproduce`: execute only and report per-step outcomes.
//!
//! Parameters are re-derived the way the driver derived them, through the strategies' own
//! builder (`crawlx_strategies::rebuild_action`): generated values come from
//! `(seed, key, partition)` at ordinal 0 with the target's input constraints and the date the
//! action was proposed on, a toggle moves to the opposite of the checked state it is found in,
//! a scroll covers 80 % of the viewport, a select picks the option the key's class names, a drag
//! goes to the destination `drag_destination` picks, and an upload attaches the fixture of its
//! partition. Keys that name no page element resolve against what the replay observed: a tab
//! action finds its tab by the URL hash the key carries, a reset `Navigate` goes to the first
//! URL observed for the route the key names, and a `Navigate` to a URL the page hooks reported
//! goes to the URL whose digest the key carries. Only keys whose parameters the journal does
//! not hold (a model-chosen option or chord) stop the replay with
//! [`StepVerdict::NotReproducible`]. Every action settles under the policy the recorded run's
//! driver used (`dynamic.pageLoadStrategy`, `timeStableMs`, `interactionSettleMs`).

use crate::actor::{DropReason, SessionActor};
use crate::analysis::StateAnalyzer;
use crate::authorization::{AuthorizationGuard, AuthorizationSource, AuthorizationStop};
use crate::config::WorkerConfig;
use crate::driver::{discovered_url_element, tab_element, DriverConfig};
use crate::error::WorkerError;
use crate::run::{EgressCapture, RunContext};
use crate::stores::Stores;
use crawlx_core::action::BrowserAction;
use crawlx_core::counters::{ActionStatus, RunStatus};
use crawlx_core::epoch::EpochPolicy;
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::{LiveTargetFacts, ObservationBundle};
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::{ActionRecord, CrawlRun, NewState, SafetyContext};
use crawlx_core::secret::SecretResolver;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{
    ActionId, BrowserBackend, Clock, CrawlRunId, ElementIdentityHash, RouteTemplate, SessionId, SystemClock,
};
use crawlx_elements::{
    Candidate, CandidateDiscovery, DiscoveryConfig, IdentityResolver, InMemoryIdentityIndex, MatchWeights,
};
use crawlx_fetch::EgressOptions;
use crawlx_observe::spec;
use crawlx_safety::Adjudication;
use crawlx_scheduler::RunPlanner;
use crawlx_state::{score, ClusterConfig, Prototype};
use crawlx_storage::MemoryStore;
use crawlx_strategies::{rebuild_action, route_element, target_facts};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// `--mode`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum ReplayMode {
    /// Execute and compare each step's resulting state with the recorded one.
    Verify,
    /// Execute and report outcomes.
    Reproduce,
}

/// One recorded step.
#[derive(Clone, Debug)]
pub struct ReplayStep {
    /// Action.
    pub action: ActionRecord,
    /// Authoritative persisted state immediately before this action.
    /// Required even when a failed observation left no after-state.
    pub recorded_before: NewState,
    /// The state the recorded run observed after this action.
    pub recorded_after: Option<NewState>,
}

/// The recorded path to replay.
#[derive(Clone)]
pub struct ReplayPlan {
    /// Run.
    pub run: CrawlRun,
    /// Session.
    pub session: crawlx_core::repo::CrawlSession,
    /// Identity algorithm stored with the recorded path. Never inferred from hashes.
    pub identity_version: u16,
    /// Steps.
    pub steps: Vec<ReplayStep>,
    /// Live source retained from the repositories that loaded the path, never a record snapshot.
    authorization_source: Option<Arc<dyn AuthorizationSource>>,
    /// Source-run worker decisions in persisted event order, never resampled.
    admission_records: Vec<crawlx_core::runtime_admission::AdmissionRecordV1>,
}

impl std::fmt::Debug for ReplayPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayPlan")
            .field("run", &self.run)
            .field("session", &self.session)
            .field("identity_version", &self.identity_version)
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

impl ReplayPlan {
    /// Empty recorded plan for checkpoint-boundary consumer regressions.
    #[cfg(test)]
    pub(crate) fn checkpoint_test_plan(run: CrawlRun, session: crawlx_core::repo::CrawlSession) -> Self {
        Self {
            run,
            session,
            identity_version: 1,
            steps: Vec::new(),
            authorization_source: None,
            admission_records: Vec::new(),
        }
    }

    /// The performed exploration actions of the target action's session up to and including
    /// `to_action`: every `succeeded` one, and every `failed` one (the browser rejected it,
    /// but it may have left the page changed). Recorded login actions are restored separately
    /// through the configured session authentication plan.
    ///
    /// # Errors
    /// Fails when a dependency fails, or when `to_action` is an authentication action rather
    /// than an exploration replay target.
    pub async fn load(stores: &Stores, run_id: CrawlRunId, to_action: ActionId) -> Result<Self, WorkerError> {
        let run = stores.runs.get_for_execution(run_id).await?;
        let target = stores.journal.get(to_action).await?;
        if target.run != run_id {
            return Err(WorkerError::Config(format!(
                "action {to_action} is not part of run {run_id}"
            )));
        }
        if target.strategy == crate::login::LOGIN_STRATEGY {
            return Err(WorkerError::Config(
                "login actions are restored as session authentication, not replay targets".to_owned(),
            ));
        }
        let session = stores
            .runs
            .list_sessions(run_id)
            .await?
            .into_iter()
            .find(|s| s.id == target.session)
            .ok_or_else(|| WorkerError::Config("the action's session is not part of the run".to_owned()))?;
        let mut actions: Vec<ActionRecord> = stores
            .journal
            .list(run_id, None)
            .await?
            .into_iter()
            .filter(|a| {
                a.session == target.session
                    && a.seq <= target.seq
                    && matches!(a.status, ActionStatus::Succeeded | ActionStatus::Failed)
            })
            .collect();
        actions.sort_by_key(|a| a.seq);
        let mut states: Vec<NewState> = stores
            .states
            .list_states(run_id)
            .await?
            .into_iter()
            .filter(|s| s.session == target.session)
            .collect();
        states.sort_by_key(|s| s.observed_at);
        let mut steps = actions
            .into_iter()
            .map(|a| {
                let recorded_before = a
                    .before_state
                    .and_then(|id| states.iter().find(|state| state.id == id))
                    .ok_or_else(|| WorkerError::Config("replay source before-state is missing".to_owned()))?
                    .clone();
                if recorded_before.signature.version != crawlx_core::state::StateSignature::VERSION {
                    return Err(WorkerError::Config(
                        "replay state signature version mismatch".to_owned(),
                    ));
                }
                let recorded_after = a
                    .intended_at
                    .and_then(|t| states.iter().find(|s| s.observed_at >= t).cloned());
                Ok(ReplayStep {
                    action: a,
                    recorded_before,
                    recorded_after,
                })
            })
            .collect::<Result<Vec<_>, WorkerError>>()?;
        // Validate the complete source trail above before removing authentication actions.
        // Their selector-based keys cannot be rebuilt by the exploration replay resolver;
        // login_session restores the configured login plan through its actor/kernel path.
        steps.retain(|step| step.action.strategy != crate::login::LOGIN_STRATEGY);
        let identity_version = run.config.crawl.identity.version.decision_version();
        let admission_records = crate::runtime_admission::load_recorded(
            stores.events.as_ref(),
            run_id,
            target.finished_at.unwrap_or(target.proposed_at),
        )
        .await?;
        Ok(Self {
            run,
            session,
            identity_version,
            steps,
            authorization_source: stores.authorization.clone(),
            admission_records,
        })
    }
}

/// How one replayed step ended.
#[derive(Clone, PartialEq, Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
#[non_exhaustive]
pub enum StepVerdict {
    /// `verify`: the resulting state matches the recorded one.
    Matched {
        /// Similarity to the recorded state.
        similarity: f32,
    },
    /// `verify`: the resulting state differs from the recorded one.
    Diverged {
        /// Similarity to the recorded state.
        similarity: f32,
    },
    /// `reproduce`: the action executed.
    Executed,
    /// The recorded element is not on the page.
    ElementNotFound,
    /// The action was dropped before execution (stale, not actionable, kernel denial).
    Dropped {
        /// `DropReason::as_str` of the drop.
        reason: &'static str,
    },
    /// The browser rejected the action.
    Failed {
        /// The browser's error message.
        error: String,
    },
    /// The recorded action failed in the browser and the replay's did too: the page is left in
    /// the state the failed attempt left the recorded one in.
    FailedAsRecorded {
        /// The browser's error message.
        error: String,
    },
    /// The journal does not keep what this kind needs.
    NotReproducible {
        /// The action kind the journal cannot reproduce.
        kind: &'static str,
    },
    /// The safety kernel did not admit the action.
    Denied,
}

impl StepVerdict {
    #[must_use]
    /// Ok.
    pub const fn ok(&self) -> bool {
        matches!(
            self,
            Self::Matched { .. } | Self::Executed | Self::FailedAsRecorded { .. }
        )
    }
}

/// Outcome of one step.
#[derive(Clone, PartialEq, Debug, Serialize)]
#[non_exhaustive]
pub struct StepResult {
    /// Seq.
    pub seq: u64,
    /// Action.
    pub action: ActionId,
    /// Kind.
    pub kind: &'static str,
    #[serde(flatten)]
    /// Verdict.
    pub verdict: StepVerdict,
}

/// Outcome of the replay.
#[derive(Clone, PartialEq, Debug, Serialize)]
#[non_exhaustive]
pub struct ReplayReport {
    /// Verify.
    pub verify: bool,
    /// Recorded identity version used to resolve every step.
    pub identity_version: u16,
    /// Steps.
    pub steps: Vec<StepResult>,
    /// Every step succeeded (and matched, in `verify` mode).
    pub ok: bool,
    /// What the replay's egress proxy admitted and refused: the replay runs behind the
    /// recorded run's egress policy, never unguarded. In-process evidence, not part of the
    /// API payload.
    #[serde(skip)]
    pub egress: EgressCapture,
}

/// Runs replays.
pub struct ReplayRunner;

/// What the replay has observed so far: the targets of keys that name no page element.
#[derive(Default)]
struct Seen {
    /// First URL (fragment stripped) observed for each route template: what the recorded run's
    /// frontier kept as the target of a reset `Navigate`.
    routes: BTreeMap<RouteTemplate, url::Url>,
    /// URLs the page hooks reported, canonicalized, by their `discovered_url_element`.
    discovered: BTreeMap<ElementIdentityHash, url::Url>,
}

impl Seen {
    /// Fold one observation in, the way the recorded driver folded it into its frontier and
    /// its set of discovered URLs.
    fn note(
        &mut self,
        bundle: &ObservationBundle,
        canon: &crawlx_url::CanonicalizeOptions,
        page_hooks: bool,
    ) {
        self.routes
            .entry(bundle.route.template.clone())
            .or_insert_with(|| {
                let mut first = bundle.url.url.clone();
                first.set_fragment(None);
                first
            });
        if !page_hooks {
            return;
        }
        for (raw, _) in &bundle.discovered_urls {
            let Ok(joined) = bundle.url.url.join(raw) else {
                continue;
            };
            if !matches!(joined.scheme(), "http" | "https") {
                continue;
            }
            if let Ok(canonical) = crawlx_url::Canonicalizer::canonicalize_url(&joined, canon) {
                self.discovered
                    .insert(discovered_url_element(canonical.url.as_str()), canonical.url);
            }
        }
    }
}

/// The page a step is rebuilt against: what the replay observed just before the step.
struct Page<'a> {
    bundle: &'a ObservationBundle,
    candidates: &'a [Candidate],
    /// Index into `candidates` of the first candidate the step's element identity resolves to.
    found: Option<usize>,
    seen: &'a Seen,
}

/// Rebuild the action of `step` against `page` together with the facts the safety kernel
/// admits it on (the target's, else the page it is on: the driver's rule for keys without a
/// candidate). The `Err` is the step's verdict when it cannot be rebuilt.
fn action_for(
    step: &ReplayStep,
    page: &Page<'_>,
    seed: CrawlSeed,
    configured: &crawlx_forms::ConfiguredValues,
) -> Result<(BrowserAction, LiveTargetFacts), StepVerdict> {
    let key = &step.action.key;
    let bundle = page.bundle;
    let candidate = page.found.and_then(|i| page.candidates.get(i));
    let mut facts = candidate.map_or_else(
        || LiveTargetFacts {
            current_url: bundle.url.url.to_string(),
            ..LiveTargetFacts::default()
        },
        |c| target_facts(c, bundle),
    );
    facts.observed_form_hint = candidate.and_then(|candidate| {
        crawlx_strategies::frontier::observed_form_hints(bundle)
            .remove(&candidate.descriptor.locator.backend_node_id.0)
    });
    let not_reproducible = || StepVerdict::NotReproducible {
        kind: key.action_kind.as_str(),
    };
    let action = match key.action_kind {
        ActionKind::SwitchTab | ActionKind::CloseTab => {
            // The key names the tab by its URL, which two tabs may share (a popup navigated to
            // the page that opened it). The driver never switches to or closes the tab the
            // session started on, and acts on the pending popup it switches to, or on the active
            // popup it closes.
            let closing = key.action_kind == ActionKind::CloseTab;
            let tab = bundle
                .tabs
                .iter()
                .filter(|t| tab_element(&t.url) == key.element)
                .min_by_key(|t| (t.opener.is_none(), !if closing { t.active } else { t.pending }))
                .ok_or(StepVerdict::ElementNotFound)?
                .id
                .clone();
            if closing {
                BrowserAction::CloseTab { tab }
            } else {
                BrowserAction::SwitchTab { tab }
            }
        }
        ActionKind::Navigate => {
            let url = match candidate {
                Some(c) => {
                    let href = c.descriptor.href.as_deref().ok_or_else(not_reproducible)?;
                    bundle.url.url.join(href).map_err(|_| not_reproducible())?
                }
                None => page
                    .seen
                    .routes
                    .iter()
                    .find(|(route, _)| route_element(route) == key.element)
                    .map(|(_, url)| url)
                    .or_else(|| page.seen.discovered.get(&key.element))
                    .cloned()
                    .ok_or(StepVerdict::ElementNotFound)?,
            };
            BrowserAction::Navigate { url }
        }
        ActionKind::SyntheticClick => BrowserAction::SyntheticClick {
            target: candidate
                .ok_or(StepVerdict::ElementNotFound)?
                .descriptor
                .locator
                .clone(),
        },
        _ => {
            let index = page.found.ok_or(StepVerdict::ElementNotFound)?;
            rebuild_action(
                key,
                index,
                page.candidates,
                bundle,
                seed,
                step.action.proposed_at,
                configured,
            )
            .ok_or_else(not_reproducible)?
        }
    };
    Ok((action, facts))
}

/// Most fresh reconstructions of one recorded step after a proven pre-intent stale drop.
const MAX_STALE_REOBSERVATIONS_PER_STEP: u8 = 3;

/// Preserve the execution error after both cleanup operations have been attempted.
pub(crate) fn finish_replay<T>(
    primary: Result<T, WorkerError>,
    shutdown: Result<(), WorkerError>,
    release: Result<(), WorkerError>,
) -> Result<T, WorkerError> {
    let primary_failed = primary.is_err();
    let shutdown_failed = shutdown.is_err();
    let release_failed = release.is_err();
    if (primary_failed && (shutdown_failed || release_failed)) || (shutdown_failed && release_failed) {
        tracing::warn!(
            primary_failed,
            shutdown_failed,
            release_failed,
            "replay has secondary cleanup failures"
        );
    }
    let value = primary?;
    shutdown?;
    release?;
    Ok(value)
}

impl ReplayRunner {
    /// Execute `plan` in `mode` through a fresh session against the live target.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn run(
        cfg: WorkerConfig,
        plan: ReplayPlan,
        mode: ReplayMode,
        backend: Option<Arc<dyn BrowserBackend>>,
        secrets: Option<Arc<dyn SecretResolver>>,
    ) -> Result<ReplayReport, WorkerError> {
        let resolver =
            IdentityResolver::new().with_identity_version(plan.run.config.crawl.identity.version, "");
        if !resolver.accepts_replay_version(plan.identity_version) {
            return Err(WorkerError::Config("replay identity version mismatch".to_owned()));
        }
        if plan.steps.iter().any(|step| {
            Some(step.recorded_before.id) != step.action.before_state
                || step.recorded_before.session != step.action.session
                || step.recorded_before.signature.version != crawlx_core::state::StateSignature::VERSION
                || step.recorded_after.as_ref().is_some_and(|state| {
                    state.signature.version != crawlx_core::state::StateSignature::VERSION
                })
        }) {
            return Err(WorkerError::Config(
                "replay state signature version mismatch".to_owned(),
            ));
        }
        plan.run
            .config
            .check_gates(cfg.gates.status())
            .map_err(|e| WorkerError::Config(e.to_string()))?;
        // The replay logs in, so what it retains can be authenticated: seal it like any worker
        // write and remove the scratch directory when the replay ends.
        let scratch = tempfile::tempdir().map_err(|e| WorkerError::Other(e.to_string()))?;
        let stores = Stores::over_memory_with_local_custody_keys(
            Arc::new(MemoryStore::new()),
            scratch.path(),
            cfg.artifact_keys.clone(),
        )
        .await?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut run = plan.run.clone();
        run.id = CrawlRunId::new();
        run.status = RunStatus::Queued;
        run.terminal_reason = None;
        run.created_at = clock.now();
        run.started_at = None;
        run.finished_at = None;
        stores.runs.create(&run, None).await?;
        // CLI replays re-read the live record instead of trusting source admission.
        let authorization = if let Some(record) = run.config.safety.authorization_record_ref {
            let source = match plan.authorization_source.clone() {
                Some(source) => source,
                None => Stores::open(&cfg)
                    .await?
                    .authorization
                    .ok_or_else(|| WorkerError::Authorization(AuthorizationStop::Missing(record)))?,
            };
            Some(
                AuthorizationGuard::admit(
                    run.id,
                    None,
                    Some(record),
                    source,
                    Arc::new(SystemClock),
                    Arc::clone(&stores.events),
                    cfg.authorization_recheck,
                )
                .await?,
            )
        } else {
            None
        };
        let mut session = RunPlanner::sessions(run.id, &run.config)
            .into_iter()
            .find(|s| s.role == plan.session.role)
            .or_else(|| RunPlanner::sessions(run.id, &run.config).into_iter().next())
            .ok_or_else(|| WorkerError::Config("the recorded run has no role".to_owned()))?;
        session.id = SessionId::new();
        stores
            .runs
            .create_sessions(std::slice::from_ref(&session))
            .await?;
        stores.runs.set_status(run.id, RunStatus::Running, None).await?;
        let scheduler = crawlx_scheduler::Scheduler::new(Arc::clone(&stores.leases));
        let lease = scheduler
            .lease_in_run(run.id, cfg.worker_id, run.config.parallel_roles_allowed())
            .await?
            .ok_or_else(|| {
                WorkerError::Config("session_unavailable: replay role lease unavailable".into())
            })?;
        let keepalive_cancel = tokio_util::sync::CancellationToken::new();
        let _keepalive_guard = keepalive_cancel.clone().drop_guard();
        let keepalive = scheduler.keep_alive(
            lease.clone(),
            std::time::Duration::from_secs(10),
            keepalive_cancel.clone(),
        );
        let run = stores.runs.get_for_execution(run.id).await?;

        // The same fresh record narrows proxy, robots, scope and kernel.
        let resolver = cfg.egress.resolver_for(&run.config)?;
        let proxy = cfg
            .egress
            .serve_proxy(
                &run.config,
                run.id,
                authorization.as_ref().map(|guard| guard.record()),
                resolver,
                EgressOptions::new(),
            )
            .await?;
        // Everything the replay session retains (context pump, actor, analysis) publishes under
        // this session lease's fence.
        let producer = crawlx_core::custody::CustodyLease::new(
            run.tenant,
            run.id,
            lease.session.id,
            lease.worker,
            lease.fencing_token,
        );
        let (rc, handle, report) = crawlx_core::custody::with_producer(
            producer,
            Box::pin(async {
                let rc = Arc::new(
                    RunContext::build(
                        &run,
                        &cfg,
                        stores.clone(),
                        backend,
                        secrets,
                        Default::default(),
                        Some(&proxy),
                        authorization,
                    )
                    .await?,
                );
                let mut scfg = rc.session_config(&session);
                if run.config.safety.profile == crawlx_core::SafetyProfile::AuthorizedSecurityTest {
                    scfg.epoch_policy = EpochPolicy::strict();
                }
                let login = rc.prepare_session_login(&session, &mut scfg).await?;
                let pooled = rc.acquire_bound_session(&lease, &mut scfg).await?;
                let login_bounds = crate::run::LoginBounds::from(&scfg);
                if let Some(recorded) = &plan.session.browser {
                    if recorded.chromium_version != pooled.build.chromium_version
                        || recorded.cdp_revision != pooled.build.cdp_revision
                    {
                        return Err(WorkerError::Config("replay browser build mismatch".to_owned()));
                    }
                } else {
                    return Err(WorkerError::Config(
                        "replay source browser build is unrecorded".to_owned(),
                    ));
                }
                let analyzer = Arc::new(StateAnalyzer::new(
                    rc.run,
                    session.id,
                    rc.clusters.clone(),
                    Arc::clone(&stores.artifacts),
                    Arc::clone(&clock),
                    run.config.capture.clone(),
                    (&rc.controls, &rc.captcha_secrets),
                ));
                let handle = SessionActor::spawn(
                    scfg,
                    rc.services(),
                    Arc::clone(&analyzer),
                    run.config.retention.days,
                    pooled,
                )
                .await?;
                tracing::debug!(run = %run.id, seed = %run.config.seed_url, "replay session ready");
                let report = async {
                    if let Some(guard) = &rc.authorization {
                        guard.check_now().await?;
                        guard
                            .record()
                            .check_profile(rc.crawl.safety.profile)
                            .map_err(|e| WorkerError::PolicyDenied(e.to_string()))?;
                        if guard.record().tenant != run.tenant {
                            return Err(WorkerError::PolicyDenied(
                                "authorization tenant mismatch".to_owned(),
                            ));
                        }
                        guard
                            .scope()
                            .check_covers_url(&rc.seed_url()?.url)
                            .map_err(|e| WorkerError::PolicyDenied(e.to_string()))?;
                    }
                    handle
                        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                            rc.seed_url()?,
                            0,
                            None,
                        ))
                        .await?;
                    if let Some(material) = login {
                        rc.login_session_bounded(&session, &handle, &analyzer, material, login_bounds)
                            .await?;
                    }
                    Self::steps(&rc, &session.role, &handle, &analyzer, &plan, mode, None).await
                }
                .await;
                Ok::<_, WorkerError>((rc, handle, report))
            }),
        )
        .await?;
        let cleanup = handle.shutdown(crate::actor::ShutdownReason::Cancelled).await;
        keepalive_cancel.cancel();
        let _ = keepalive.await;
        let terminal = if report.is_ok() && cleanup.is_ok() {
            crawlx_core::repo::SessionStatus::Completed
        } else {
            crawlx_core::repo::SessionStatus::Failed
        };
        let release = scheduler
            .release(&lease, terminal)
            .await
            .map_err(WorkerError::from);
        rc.supervisor.shutdown().await;
        finish_replay(report, cleanup.map_err(WorkerError::from), release).map(|mut r| {
            r.egress = EgressCapture {
                dialed_hosts: proxy.dialed_hosts(),
                denied_events: proxy.denied_events(),
            };
            r
        })
    }

    pub(crate) async fn steps(
        rc: &Arc<RunContext>,
        principal: &crawlx_core::PrincipalId,
        handle: &crate::actor::SessionHandle,
        analyzer: &StateAnalyzer,
        plan: &ReplayPlan,
        mode: ReplayMode,
        mut progress: Option<&mut crate::replay_queue::ReplayProgress>,
    ) -> Result<ReplayReport, WorkerError> {
        let policy = plan
            .run
            .config
            .orchestration
            .as_ref()
            .map_or_else(Default::default, |config| config.admission.clone());
        let hard_limit = 16_u32.min(u32::from(plan.run.config.politeness.max_concurrency.max(1)));
        let mut recorded = crate::runtime_admission::RecordedAdmissionReplay::new(policy, hard_limit);
        for record in &plan.admission_records {
            if record.source_run != plan.run.id {
                return Err(WorkerError::Config(
                    "recorded admission belongs to another source run".into(),
                ));
            }
            recorded.apply(record)?;
        }
        if progress.as_ref().is_none_or(|state| state.results.is_empty()) {
            // Existing replay executes one actor lane. Pressure decisions belong
            // to source URL dispatch, not permission to cancel an admitted action.
            // Absence explicitly means fixed admission, never synthetic samples.
            rc.stores.events.append(rc.run, "runtime.admission.replay", serde_json::json!({
                "sourceRun": plan.run.id,
                "version": 1,
                "mode": if plan.admission_records.is_empty() { "fixed_missing_recordings" } else { "recorded" },
                "decisions": plan.admission_records.len(),
                "hardLimit": hard_limit,
                "lastDecision": plan.admission_records.last().map(|record| &record.decision),
            })).await?;
        }
        let mut results = progress.as_ref().map_or_else(Vec::new, |p| p.results.clone());
        let stopped = results.last().is_some_and(|result| {
            !result.verdict.ok()
                && !(matches!(result.verdict, StepVerdict::Diverged { .. })
                    && progress.as_ref().is_some_and(|p| !p.stop_on_divergence))
        });
        // every action settles under the policy the recorded run's driver settled it under
        let settle = {
            let mut driver = DriverConfig::default();
            driver.apply_dynamic(&rc.crawl.dynamic);
            driver.action_settle()
        };
        let mut seen = Seen::default();
        let form_values = rc.form_values();
        let resumed = results.len();
        if resumed > 0 {
            // Restore route-reset knowledge from this replay's own observations, not source URLs.
            let mut states = rc.stores.states.list_states(rc.run).await?;
            states.sort_by_key(|state| state.observed_at);
            for state in states {
                seen.routes
                    .entry(state.url.route_template)
                    .or_insert(state.url.url);
            }
        }
        'steps: for (index, step) in plan.steps.iter().enumerate().skip(resumed) {
            if stopped {
                break;
            }
            if let Some(guard) = &rc.authorization {
                guard.check_now().await?;
            }
            if rc.cancel.is_cancelled() {
                break;
            }
            if let Some(p) = progress.as_deref_mut() {
                if !p.before_step(rc, handle, index, step).await? {
                    break;
                }
            }
            let kind = step.action.key.action_kind;
            let recorded_failed = step.action.status == ActionStatus::Failed;
            let mk = |verdict| StepResult {
                seq: step.action.seq,
                action: step.action.id,
                kind: kind.as_str(),
                verdict,
            };
            let mut stale_reobservations = 0_u8;
            let outcome = loop {
                if rc.cancel.is_cancelled() {
                    break 'steps;
                }
                if stale_reobservations > 0 {
                    if let Some(guard) = &rc.authorization {
                        guard.check_now().await?;
                    }
                }
                let bundle = handle.observe(spec::after_action()).await?;
                // T1 binds the latest persisted session state; T2 then links its exact afterstate.
                // Observation alone leaves no transition for crash-safe replay recovery.
                let before = analyzer.analyze(&bundle).await;
                analyzer.record_metrics(&before, &principal.0);
                rc.stores.states.put_state(&before.state).await?;
                seen.note(&bundle, &rc.canon, rc.crawl.dynamic.page_hooks);
                let resolver = IdentityResolver::with_destination(bundle.url.url.clone(), rc.canon.clone())
                    .with_identity_version(
                        plan.run.config.crawl.identity.version,
                        crawlx_elements::locale::page_language(bundle.html.as_deref()),
                    );
                if !resolver.accepts_replay_version(plan.identity_version) {
                    return Err(WorkerError::Config("replay identity version mismatch".to_owned()));
                }
                let identity_index = InMemoryIdentityIndex::new();
                let weights = MatchWeights::default();
                let candidates = CandidateDiscovery::discover(&bundle, &DiscoveryConfig::default());
                let found = candidates.iter().position(|c| {
                    resolver
                        .resolve(&c.descriptor, &identity_index, &weights)
                        .is_ok_and(|r| r.hash == step.action.key.element)
                });
                let page = Page {
                    bundle: &bundle,
                    candidates: &candidates,
                    found,
                    seen: &seen,
                };
                let (action, facts) = match action_for(step, &page, rc.seed, &form_values) {
                    Ok(rebuilt) => rebuilt,
                    Err(verdict) => {
                        let result = mk(verdict);
                        if let Some(p) = progress.as_deref_mut() {
                            p.completed_step(rc, handle, index, &result).await?;
                        }
                        results.push(result);
                        break 'steps;
                    }
                };
                if let Some(guard) = &rc.authorization {
                    let scope = guard.scope();
                    scope
                        .check_covers_url(&bundle.url.url)
                        .map_err(|e| WorkerError::PolicyDenied(e.to_string()))?;
                    if let BrowserAction::Navigate { url } = &action {
                        scope
                            .check_covers_url(url)
                            .map_err(|e| WorkerError::PolicyDenied(e.to_string()))?;
                    }
                }
                let proposal = ActionProposal {
                    key: step.action.key.clone(),
                    action,
                    epoch: bundle.epoch,
                    strategy: "replay",
                    strategy_version: 1,
                    confidence: 1.0,
                    expected: ExpectedEffect::default(),
                    hinted_risk: None,
                    model_decision: None,
                    summary: format!("replay of action {}", step.action.id),
                };
                let mut sc = SafetyContext {
                    profile: rc.crawl.safety.profile,
                    has_test_sinks: rc.kernel.has_verified_test_sinks(),
                    destructive_approval_allowed: false,
                    principal: principal.clone(),
                    seed_origin: rc.seed_origin(),
                    in_scope: true,
                    form_hint: facts.observed_form_hint.clone(),
                    target: facts,
                };
                let admitted = match rc.kernel.adjudicate(proposal.clone(), &sc) {
                    Adjudication::Allow(a) => a,
                    Adjudication::Deny(_) | Adjudication::ApprovalRequired(..) => {
                        let result = mk(StepVerdict::Denied);
                        if let Some(p) = progress.as_deref_mut() {
                            p.completed_step(rc, handle, index, &result).await?;
                        }
                        results.push(result);
                        break 'steps;
                    }
                };
                if let Some(p) = progress.as_deref_mut() {
                    if !p.guard(rc, handle).await? {
                        break 'steps;
                    }
                } else if let Some(guard) = &rc.authorization {
                    guard.check_now().await?;
                }
                let mut outcome = handle.execute(admitted, settle).await?;
                if outcome.dropped == Some(DropReason::ConfirmDenied) {
                    // Descriptor facts carry no hit points or frame, so the live evidence can
                    // classify the target stricter than admission did (a submit control inside a
                    // form); the driver re-admits once on those facts and so does the replay.
                    if let Some(live) = outcome.live.take() {
                        sc.target = live;
                        match rc.kernel.adjudicate(proposal, &sc) {
                            Adjudication::Allow(a) => {
                                if let Some(p) = progress.as_deref_mut() {
                                    if !p.guard(rc, handle).await? {
                                        break 'steps;
                                    }
                                } else if let Some(guard) = &rc.authorization {
                                    guard.check_now().await?;
                                }
                                outcome = handle.execute(a, settle).await?;
                            }
                            Adjudication::Deny(_) | Adjudication::ApprovalRequired(..) => {
                                let result = mk(StepVerdict::Denied);
                                if let Some(p) = progress.as_deref_mut() {
                                    p.completed_step(rc, handle, index, &result).await?;
                                }
                                results.push(result);
                                break 'steps;
                            }
                        }
                    }
                }
                // Stale drops occur before T1 and have no receipt. Rebuild the same
                // recorded step from a real observation; never refresh an old proposal's
                // epoch or retry a failed/unknown browser effect.
                if outcome.dropped == Some(DropReason::StaleEpoch)
                    && outcome.status == ActionStatus::Proposed
                    && outcome.receipt.is_none()
                    && stale_reobservations < MAX_STALE_REOBSERVATIONS_PER_STEP
                {
                    stale_reobservations = stale_reobservations.saturating_add(1);
                    continue;
                }
                break outcome;
            };
            let verdict = if let Some(reason) = outcome.dropped {
                StepVerdict::Dropped {
                    reason: DropReason::as_str(reason),
                }
            } else if outcome.status != ActionStatus::Succeeded {
                let error = outcome.error.unwrap_or_else(|| "action failed".to_owned());
                if recorded_failed {
                    StepVerdict::FailedAsRecorded { error }
                } else {
                    StepVerdict::Failed { error }
                }
            } else {
                match (mode, &step.recorded_after, &outcome.after_state) {
                    (ReplayMode::Verify, Some(recorded), Some(now)) => {
                        let proto = Prototype {
                            signature: recorded.signature.clone(),
                            minhash_union: recorded.signature.semantic_affordance_minhash.clone(),
                            consequence: None,
                        };
                        let similarity = score(&now.signature, &proto);
                        if similarity >= ClusterConfig::default().theta_review {
                            StepVerdict::Matched { similarity }
                        } else {
                            StepVerdict::Diverged { similarity }
                        }
                    }
                    (ReplayMode::Verify, _, _) => StepVerdict::Diverged { similarity: 0.0 },
                    (ReplayMode::Reproduce, _, _) => StepVerdict::Executed,
                }
            };
            let stop = !verdict.ok()
                && !(matches!(verdict, StepVerdict::Diverged { .. })
                    && progress.as_ref().is_some_and(|p| !p.stop_on_divergence));
            let result = mk(verdict);
            if let Some(p) = progress.as_deref_mut() {
                p.completed_step(rc, handle, index, &result).await?;
            }
            results.push(result);
            if stop {
                break;
            }
        }
        let ok = results.len() == plan.steps.len() && results.iter().all(|r| r.verdict.ok());
        Ok(ReplayReport {
            verify: mode == ReplayMode::Verify,
            identity_version: plan.identity_version,
            steps: results,
            ok,
            egress: EgressCapture::default(),
        })
    }
}

#[cfg(test)]
mod lifecycle_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn cleanup_never_masks_the_primary_error_or_converts_cleanup_failure_to_success() {
        let primary = finish_replay::<()>(
            Err(WorkerError::PolicyDenied("fixture denial".into())),
            Err(WorkerError::Session(crate::error::SessionError::ActorGone)),
            Err(WorkerError::Store(crawlx_core::StoreError::LeaseLost)),
        );
        assert!(matches!(primary, Err(WorkerError::PolicyDenied(_))));

        let shutdown = finish_replay(
            Ok(()),
            Err(WorkerError::Session(crate::error::SessionError::ActorGone)),
            Err(WorkerError::Store(crawlx_core::StoreError::LeaseLost)),
        );
        assert!(matches!(
            shutdown,
            Err(WorkerError::Session(crate::error::SessionError::ActorGone))
        ));

        let release = finish_replay(
            Ok(()),
            Ok(()),
            Err(WorkerError::Store(crawlx_core::StoreError::LeaseLost)),
        );
        assert!(matches!(
            release,
            Err(WorkerError::Store(crawlx_core::StoreError::LeaseLost))
        ));
    }
}
