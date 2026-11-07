//! Shared rig: a Session Actor over a `FakeBackend` and the in-memory store.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod authorization;
pub mod site;

use async_trait::async_trait;
use crawlx_browser::fake::FakeScript;
use crawlx_browser::FakeBackend;
use crawlx_core::action::{BrowserAction, Modifiers, PointerButton};
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::identity::{ActionContextKey, ActionKind, InputClass, ResourceContext};
use crawlx_core::observation::{LiveTargetFacts, ObservationBundle};
use crawlx_core::proposal::{ActionProposal, ExpectedEffect};
use crawlx_core::repo::{
    ActionJournal, ActionRecord, CrawlRun, JournalOutcomes, NewState, OutcomeRecord, Reconciliation,
    SafetyContext,
};
use crawlx_core::safety::SafetyVerdict;
use crawlx_core::{
    ActionId, BrowserBackend, CanonicalUrl, Clock, CrawlRunId, CreateCrawl, ObservationEpoch, PrincipalId,
    SafetyProfile, SessionId, StateClusterId, StoreError, SystemClock, Timestamp,
};
use crawlx_elements::{
    CandidateDiscovery, DiscoveryConfig, IdentityResolver, InMemoryIdentityIndex, MatchWeights,
};
use crawlx_safety::{Adjudication, AdmittedAction};
use crawlx_scheduler::RunPlanner;
use crawlx_storage::MemoryStore;
use crawlx_worker::actor::{SessionActor, SessionHandle};
use crawlx_worker::{RunContext, StateAnalyzer, Stores, WorkerConfig};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

pub const SEED: &str = "https://example.test/";

pub struct Rig {
    pub store: Arc<MemoryStore>,
    pub stores: Stores,
    pub backend: Arc<FakeBackend>,
    pub rc: Arc<RunContext>,
    pub handle: SessionHandle,
    pub run: CrawlRunId,
    pub session: SessionId,
    pub principal: PrincipalId,
    pub dir: tempfile::TempDir,
    pub flaky: Option<Arc<FlakyJournal>>,
}

pub fn crawl(profile: SafetyProfile) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(SEED).unwrap());
    c.safety.profile = profile;
    c.seed = Some(7);
    c
}

/// The store-agnostic part of a rig: a run with one anonymous session and an actor over
/// `backend`, already navigated to the seed. `rig_with` builds it over the in-memory store;
/// the PostgreSQL drills build it over `Stores::over_pg`.
pub struct RigCore {
    pub stores: Stores,
    pub backend: Arc<FakeBackend>,
    pub rc: Arc<RunContext>,
    pub handle: SessionHandle,
    pub run: CrawlRunId,
    pub session: SessionId,
    pub principal: PrincipalId,
    pub dir: tempfile::TempDir,
}

pub async fn rig_core(
    stores: Stores,
    dir: tempfile::TempDir,
    backend: Arc<dyn BrowserBackend>,
    fake: Arc<FakeBackend>,
    profile: SafetyProfile,
) -> RigCore {
    let mut crawl = crawl(profile);
    // The fake browser never contacts these origins; use an explicitly authorized
    // robots override rather than attempting network access to example.test.
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    let mut record = authorization::verified_record(&crawl, stores.tenant);
    record.robots_override_acknowledged = true;
    record.url_prefixes.push("https://other.test".to_owned());
    rig_core_authorized(stores, dir, backend, fake, crawl, record, None).await
}

/// Actor fixture using the caller's selected authorization and safety settings.
pub async fn rig_core_authorized(
    stores: Stores,
    dir: tempfile::TempDir,
    backend: Arc<dyn BrowserBackend>,
    fake: Arc<FakeBackend>,
    crawl: CreateCrawl,
    record: crawlx_policy::AuthorizationRecord,
    initial_request: Option<crawlx_core::request::RequestEnvelopeV1>,
) -> RigCore {
    if let Some(pg) = &stores.pg {
        pg.ensure_tenant(stores.tenant, "local").await.unwrap();
        authorization::register_verified(pg, &record).await;
    }
    let mut stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    if !stores.checkpoint_keys.is_available() {
        stores.checkpoint_keys =
            Arc::new(crawlx_storage::checkpoint_crypto::MemoryCheckpointKeys::new().unwrap());
    }
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    let sessions = RunPlanner::sessions(run.id, &crawl);
    stores.runs.create_sessions(&sessions).await.unwrap();
    stores
        .runs
        .set_status(run.id, RunStatus::Running, None)
        .await
        .unwrap();
    let session = sessions[0].clone();
    stores
        .runs
        .set_session_status(session.id, crawlx_core::repo::SessionStatus::Running)
        .await
        .unwrap();
    let run = stores.runs.get(run.id).await.unwrap();
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    };
    let guard = authorization::admit(&stores, &run, &cfg).await;
    let rc = Arc::new(
        RunContext::build(
            &run,
            &cfg,
            stores.clone(),
            Some(backend),
            None,
            CancellationToken::new(),
            None,
            Some(guard),
        )
        .await
        .unwrap(),
    );
    let scfg = rc.session_config(&session);
    let pooled = rc
        .pool
        .acquire(scfg.context.clone(), scfg.exclusive_browser)
        .await
        .unwrap();
    let analyzer = Arc::new(StateAnalyzer::new(
        rc.run,
        session.id,
        rc.clusters.clone(),
        stores.artifacts.clone(),
        rc.clock.clone(),
        crawl.capture.clone(),
        (&rc.controls, &rc.captcha_secrets),
    ));
    let handle = SessionActor::spawn(scfg, rc.services(), analyzer, 7, pooled)
        .await
        .unwrap();
    let request = initial_request
        .unwrap_or_else(|| crawlx_core::request::RequestEnvelopeV1::get(rc.seed_url().unwrap(), 0, None));
    handle.navigate(request).await.unwrap();
    RigCore {
        stores,
        backend: fake,
        rc,
        handle,
        run: run.id,
        session: session.id,
        principal: session.role.clone(),
        dir,
    }
}

/// A second actor over a fresh context of the same run and session (what recovery does),
/// navigated to `url` (the seed when `None`).
pub async fn fresh_actor_in(
    stores: &Stores,
    rc: &Arc<RunContext>,
    run: CrawlRunId,
    url: Option<CanonicalUrl>,
) -> SessionHandle {
    let session = stores.runs.list_sessions(run).await.unwrap()[0].clone();
    let scfg = rc.session_config(&session);
    let pooled = rc
        .pool
        .acquire(scfg.context.clone(), scfg.exclusive_browser)
        .await
        .unwrap();
    let analyzer = Arc::new(StateAnalyzer::new(
        rc.run,
        session.id,
        rc.clusters.clone(),
        stores.artifacts.clone(),
        rc.clock.clone(),
        rc.crawl.capture.clone(),
        (&rc.controls, &rc.captcha_secrets),
    ));
    let handle = SessionActor::spawn(scfg, rc.services(), analyzer, 11, pooled)
        .await
        .unwrap();
    handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            url.unwrap_or_else(|| rc.seed_url().unwrap()),
            0,
            None,
        ))
        .await
        .unwrap();
    handle
}

/// Total `perform` calls across every context `fake` opened.
pub fn performed_total(fake: &FakeBackend) -> usize {
    fake.context_handles().iter().map(|c| c.performed().len()).sum()
}

impl RigCore {
    pub async fn fresh_actor(&self, url: Option<CanonicalUrl>) -> SessionHandle {
        fresh_actor_in(&self.stores, &self.rc, self.run, url).await
    }

    pub fn performed_total(&self) -> usize {
        performed_total(&self.backend)
    }
}

/// A run with one anonymous session, an actor over `backend`, already navigated to the seed.
pub async fn rig_with(
    backend: Arc<dyn BrowserBackend>,
    fake: Arc<FakeBackend>,
    flaky: bool,
    profile: SafetyProfile,
) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let mut stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let flaky = flaky.then(|| FlakyJournal::new(store.clone()));
    if let Some(j) = &flaky {
        stores.journal = j.clone();
    }
    let RigCore {
        stores,
        backend,
        rc,
        handle,
        run,
        session,
        principal,
        dir,
    } = rig_core(stores, dir, backend, fake, profile).await;
    Rig {
        store,
        stores,
        backend,
        rc,
        handle,
        run,
        session,
        principal,
        dir,
        flaky,
    }
}

pub async fn rig(script: FakeScript, profile: SafetyProfile) -> Rig {
    let fake = Arc::new(FakeBackend::new(script));
    rig_with(fake.clone(), fake, false, profile).await
}

impl Rig {
    /// Click proposal for the control named `name` in `bundle`, with kernel facts.
    pub fn proposal(
        &self,
        bundle: &ObservationBundle,
        name: &str,
        cluster: StateClusterId,
    ) -> (ActionProposal, SafetyContext) {
        proposal_for(
            bundle,
            name,
            ActionKind::Click,
            cluster,
            &self.principal,
            &self.rc.seed_origin(),
            self.rc.crawl.safety.profile,
        )
    }

    pub fn admit(&self, p: ActionProposal, c: &SafetyContext) -> AdmittedAction {
        match self.rc.kernel.adjudicate(p, c) {
            Adjudication::Allow(a) => a,
            other => panic!("expected allow, got {:?}", other.verdict()),
        }
    }

    pub async fn actions(&self) -> Vec<ActionRecord> {
        self.store.list(self.run, None).await.unwrap()
    }

    pub async fn fresh_actor(&self, url: Option<CanonicalUrl>) -> SessionHandle {
        fresh_actor_in(&self.stores, &self.rc, self.run, url).await
    }

    pub fn performed_total(&self) -> usize {
        performed_total(&self.backend)
    }
}

pub fn proposal_for(
    bundle: &ObservationBundle,
    name: &str,
    kind: ActionKind,
    cluster: StateClusterId,
    principal: &PrincipalId,
    seed_origin: &str,
    profile: SafetyProfile,
) -> (ActionProposal, SafetyContext) {
    let resolver = IdentityResolver::with_destination(bundle.url.url.clone(), Default::default());
    let index = InMemoryIdentityIndex::new();
    let cand = CandidateDiscovery::discover(bundle, &DiscoveryConfig::default())
        .into_iter()
        .find(|c| c.descriptor.accessible_name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("no control named {name}"));
    let resolved = resolver
        .resolve(&cand.descriptor, &index, &MatchWeights::default())
        .unwrap();
    let d = &cand.descriptor;
    let key = ActionContextKey {
        principal: principal.clone(),
        route_template: bundle.route.template.clone(),
        element: resolved.hash,
        action_kind: kind,
        input_class: InputClass::none(),
        resource_context: ResourceContext::None,
        state_cluster: cluster,
    };
    let proposal = ActionProposal {
        key,
        action: BrowserAction::Click {
            target: d.locator.clone(),
            button: PointerButton::Left,
            modifiers: Modifiers::default(),
        },
        epoch: bundle.epoch,
        strategy: "test",
        strategy_version: 1,
        confidence: 0.9,
        expected: ExpectedEffect::default(),
        hinted_risk: None,
        model_decision: None,
        summary: format!("click {name}"),
    };
    let ctx = SafetyContext {
        profile,
        has_test_sinks: false,
        destructive_approval_allowed: false,
        principal: principal.clone(),
        seed_origin: seed_origin.to_owned(),
        in_scope: true,
        target: LiveTargetFacts {
            role: Some(d.role.clone()),
            name: d.accessible_name.clone(),
            tag: d.tag.clone(),
            href: d.href.clone(),
            bbox: d.bbox.unwrap_or_default(),
            hit_points: Vec::new(),
            frame_url: None,
            current_url: bundle.url.url.to_string(),
            attributes: d.attributes.clone(),
            observed_form_hint: None,
        },
        form_hint: None,
    };
    (proposal, ctx)
}

pub fn canonical(url: &str) -> CanonicalUrl {
    crawlx_url::Canonicalizer::canonicalize_url(&url::Url::parse(url).unwrap(), &Default::default()).unwrap()
}

/// Journal wrapper whose writes can be made to fail.
pub struct FlakyJournal {
    pub inner: Arc<MemoryStore>,
    pub fail_intend: AtomicBool,
    pub fail_finish: AtomicBool,
    pub finish_attempts: AtomicU32,
}

impl FlakyJournal {
    pub fn new(inner: Arc<MemoryStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            fail_intend: AtomicBool::new(false),
            fail_finish: AtomicBool::new(false),
            finish_attempts: AtomicU32::new(0),
        })
    }
}

#[async_trait]
impl ActionJournal for FlakyJournal {
    async fn propose(
        &self,
        run: CrawlRunId,
        session: SessionId,
        p: &ActionProposal,
        v: &SafetyVerdict,
    ) -> Result<ActionId, StoreError> {
        self.inner.propose(run, session, p, v).await
    }
    async fn intend(
        &self,
        id: ActionId,
        session: SessionId,
        epoch: ObservationEpoch,
    ) -> Result<(), StoreError> {
        if self.fail_intend.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable("injected T1 failure".to_owned()));
        }
        self.inner.intend(id, session, epoch).await
    }
    async fn finish(&self, id: ActionId, outcome: OutcomeRecord) -> Result<(), StoreError> {
        self.finish_attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail_finish.load(Ordering::SeqCst) {
            return Err(StoreError::Unavailable("injected T2 failure".to_owned()));
        }
        self.inner.finish(id, outcome).await
    }
    async fn mark_unknown(&self, before: Timestamp) -> Result<Vec<ActionId>, StoreError> {
        self.inner.mark_unknown(before).await
    }
    async fn reconcile(&self, id: ActionId, r: Reconciliation) -> Result<(), StoreError> {
        self.inner.reconcile(id, r).await
    }
    async fn get(&self, id: ActionId) -> Result<ActionRecord, StoreError> {
        ActionJournal::get(self.inner.as_ref(), id).await
    }
    async fn list(
        &self,
        run: CrawlRunId,
        status: Option<crawlx_core::counters::ActionStatus>,
    ) -> Result<Vec<ActionRecord>, StoreError> {
        ActionJournal::list(self.inner.as_ref(), run, status).await
    }
    async fn outcome_counts(&self, run: CrawlRunId) -> Result<JournalOutcomes, StoreError> {
        ActionJournal::outcome_counts(self.inner.as_ref(), run).await
    }
}

pub fn first_state(s: &[NewState]) -> &NewState {
    s.first().expect("a state")
}
