//! Browser mutations share origin admission without network access or Chromium.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use common::{canonical, proposal_for, rig_core, RigCore, SEED};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::action::BrowserAction;
use crawlx_core::counters::ActionStatus;
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::{
    ActionReceipt, BrowserBuildInfo, DomSelector, DomSelectorKind, NavigationResult, ObservationBundle,
    ObservationSpec, QuiescencePolicy, Revalidation, RuntimeLocator, SettleReport,
};
use crawlx_core::page_op::{PageOp, PageOpResult};
use crawlx_core::secret::SecretOr;
use crawlx_core::traffic::TrafficEvent;
use crawlx_core::{
    BrowserBackend, BrowserContext, BrowserError, CanonicalUrl, ContextConfig, ObservationEpoch,
    SafetyProfile,
};
use crawlx_fetch::governor::{GlobalOriginCap, GovernorConfig, Origin, OriginGovernor};
use crawlx_safety::Adjudication;
use crawlx_storage::MemoryStore;
use crawlx_worker::actor::{SessionActor, SessionConfig, SessionHandle, ShutdownReason};
use crawlx_worker::{StateAnalyzer, Stores};
use parking_lot::Mutex;
use std::future::{poll_fn, Future};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;

const SPACING: Duration = Duration::from_millis(500);
const HELD: &str = "https://example.test/held";
const OTHER: &str = "https://other.test/";

#[derive(Clone, Debug)]
struct Start {
    kind: &'static str,
    at: Instant,
}

#[derive(Default)]
struct Recording {
    starts: Mutex<Vec<Start>>,
    navigation_gate: Mutex<Option<Arc<Semaphore>>>,
    revalidation_delay: Mutex<Option<Duration>>,
    cancel_after_revalidation: Mutex<Option<tokio_util::sync::CancellationToken>>,
    mutation_seq: AtomicU64,
}

impl Recording {
    fn record(&self, kind: &'static str) {
        self.starts.lock().push(Start {
            kind,
            at: Instant::now(),
        });
    }
}

struct RecordingBackend {
    fake: Arc<FakeBackend>,
    recording: Arc<Recording>,
}

#[async_trait]
impl BrowserBackend for RecordingBackend {
    async fn new_context(&self, config: ContextConfig) -> Result<Box<dyn BrowserContext>, BrowserError> {
        Ok(Box::new(RecordingContext {
            inner: self.fake.new_context(config).await?,
            recording: Arc::clone(&self.recording),
        }))
    }

    fn build_info(&self) -> &BrowserBuildInfo {
        self.fake.build_info()
    }
}

struct RecordingContext {
    inner: Box<dyn BrowserContext>,
    recording: Arc<Recording>,
}

#[async_trait]
impl BrowserContext for RecordingContext {
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        self.recording.record("navigate");
        let gate = self.recording.navigation_gate.lock().clone();
        if url.url.as_str() == HELD {
            if let Some(gate) = gate {
                let _permit = gate.acquire().await.unwrap();
            }
        }
        self.inner.navigate(url).await
    }

    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        let mut bundle = self.inner.observe(spec).await?;
        bundle.epoch.mutation_seq += self.recording.mutation_seq.load(Ordering::SeqCst);
        for node in &mut bundle.ax.nodes {
            node.locator.epoch = bundle.epoch;
        }
        Ok(bundle)
    }

    async fn revalidate(
        &mut self,
        locator: &RuntimeLocator,
        expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        let delay = self.recording.revalidation_delay.lock().take();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let result = self.inner.revalidate(locator, expected).await;
        if let Some(cancel) = self.recording.cancel_after_revalidation.lock().take() {
            cancel.cancel();
        }
        result
    }

    async fn resolve_selector(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, BrowserError> {
        self.inner.resolve_selector(selector).await
    }

    async fn perform(&mut self, action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        self.recording.record("perform");
        self.inner.perform(action).await
    }

    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        self.inner.settle(policy).await
    }

    fn current_epoch(&self) -> ObservationEpoch {
        let mut epoch = self.inner.current_epoch();
        epoch.mutation_seq += self.recording.mutation_seq.load(Ordering::SeqCst);
        epoch
    }

    fn drain_traffic(&mut self) -> Vec<TrafficEvent> {
        self.inner.drain_traffic()
    }

    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError> {
        self.inner.export_storage().await
    }

    async fn import_storage(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        self.inner.import_storage(blob).await
    }

    async fn page_op(&mut self, op: PageOp) -> Result<PageOpResult, BrowserError> {
        self.recording.record("page_op");
        match op {
            PageOp::EvaluateScript { .. } => Ok(PageOpResult::Json(serde_json::Value::Null)),
            other => self.inner.page_op(other).await,
        }
    }

    async fn close(self: Box<Self>) -> Result<(), BrowserError> {
        self.inner.close().await
    }
}

fn script() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new(SEED)
                .node(FakeAxSpec::link("next", "Next", "/next"))
                .node(FakeAxSpec::textbox("username", "Username"))
                .on_click("next", vec![FakeEffect::Navigate("/next".to_owned())]),
        )
        .page(FakePage::new("https://example.test/next"))
        .page(FakePage::new(HELD))
        .page(FakePage::new(OTHER))
}

fn governor(cap: Arc<GlobalOriginCap>) -> Arc<OriginGovernor> {
    Arc::new(OriginGovernor::with_global_cap(
        GovernorConfig {
            // Browser admission must impose its own floor, even when HTTP has none.
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 4,
            max_concurrency: 4,
            ..GovernorConfig::default()
        },
        cap,
    ))
}

struct ActorRig {
    core: RigCore,
    handle: SessionHandle,
    recording: Arc<Recording>,
    cancel: tokio_util::sync::CancellationToken,
}

async fn actor(governor: Option<Arc<OriginGovernor>>) -> ActorRig {
    actor_with_binding(governor, None).await
}

async fn actor_with_binding(
    governor: Option<Arc<OriginGovernor>>,
    binding_ttl: Option<Duration>,
) -> ActorRig {
    actor_with_bounds(governor, binding_ttl, None).await
}

async fn actor_with_bounds(
    governor: Option<Arc<OriginGovernor>>,
    binding_ttl: Option<Duration>,
    execution_ttl: Option<Duration>,
) -> ActorRig {
    let fake = Arc::new(FakeBackend::new(script()));
    let recording = Arc::new(Recording::default());
    let backend = Arc::new(RecordingBackend {
        fake: Arc::clone(&fake),
        recording: Arc::clone(&recording),
    });
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let core = rig_core(stores, dir, backend, fake, SafetyProfile::ReadOnly).await;
    core.handle.shutdown(ShutdownReason::Completed).await.unwrap();
    let session = core.stores.runs.list_sessions(core.run).await.unwrap()[0].clone();
    let mut config = SessionConfig::new(
        core.run,
        core.session,
        core.principal.clone(),
        core.rc.seed_origin(),
    );
    if let Some(governor) = governor {
        config.origin_governor = governor;
    }
    let clock = Arc::new(BindingClock {
        started: Instant::now(),
    });
    if let Some(ttl) = binding_ttl {
        let digest = crawlx_core::hash::Digest::of("pacing-fixture", b"identity");
        let build =
            crawlx_core::hash::Digest::of_value("crawlx/session-backend-build/v1", core.backend.build_info())
                .unwrap();
        let identity = crawlx_core::session_binding::SessionIdentityV1::new(
            core.stores.tenant,
            &session,
            digest,
            build,
            digest,
            digest,
            None,
        );
        config.context.session_binding = Some(crawlx_core::session_binding::SessionBindingV1::new(
            identity,
            1,
            crawlx_core::Clock::now(clock.as_ref()) + chrono::Duration::from_std(ttl).unwrap(),
        ));
    }
    config.execution_deadline = execution_ttl
        .map(|ttl| crawlx_core::Clock::now(clock.as_ref()) + chrono::Duration::from_std(ttl).unwrap());
    let pooled = core
        .rc
        .pool
        .acquire(config.context.clone(), config.exclusive_browser)
        .await
        .unwrap();
    let analyzer = Arc::new(StateAnalyzer::new(
        core.run,
        session.id,
        core.rc.clusters.clone(),
        core.stores.artifacts.clone(),
        core.rc.clock.clone(),
        core.rc.crawl.capture.clone(),
        (&core.rc.controls, &core.rc.captcha_secrets),
    ));
    let cancel = config.origin_cancel.clone();
    let mut services = core.rc.services();
    if binding_ttl.is_some() || execution_ttl.is_some() {
        services.clock = clock;
    }
    let handle = SessionActor::spawn(config, services, analyzer, 19, pooled)
        .await
        .unwrap();
    recording.starts.lock().clear();
    ActorRig {
        core,
        handle,
        recording,
        cancel,
    }
}

async fn pending<F: Future>(mut future: Pin<&mut F>) {
    poll_fn(|cx| {
        assert!(future.as_mut().poll(cx).is_pending(), "operation started early");
        Poll::Ready(())
    })
    .await;
}

async fn schedule_actor() {
    // Keep a runnable task so Tokio cannot auto-advance the paused clock while
    // actors consume their mailbox and enter the admission wait.
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
}

async fn assert_browser_floor(rig: &ActorRig) {
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ))
        .await
        .unwrap();
    let first = rig.recording.starts.lock()[0].at;
    let operation = rig.handle.page_op(PageOp::EvaluateScript {
        script: "document.title".to_owned(),
    });
    tokio::pin!(operation);
    pending(operation.as_mut()).await;
    schedule_actor().await;
    assert_eq!(rig.recording.starts.lock().len(), 1);
    tokio::time::advance(SPACING - Duration::from_millis(1)).await;
    schedule_actor().await;
    assert_eq!(rig.recording.starts.lock().len(), 1, "499 ms is too soon");
    pending(operation.as_mut()).await;
    tokio::time::advance(Duration::from_millis(1)).await;
    operation.await.unwrap();
    let starts = rig.recording.starts.lock();
    assert_eq!(starts[1].kind, "page_op");
    assert_eq!(starts[1].at.duration_since(first), SPACING);
}

#[tokio::test(start_paused = true)]
async fn default_actor_spaces_navigation_and_page_operations_by_500ms() {
    let rig = actor(None).await;
    assert_browser_floor(&rig).await;
    rig.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn browser_floor_survives_zero_http_delay_and_covers_credentials_and_actions() {
    let rig = actor(Some(governor(Arc::new(GlobalOriginCap::new(4))))).await;
    assert_browser_floor(&rig).await;
    let target = rig
        .handle
        .resolve_selector(DomSelector {
            kind: DomSelectorKind::Css,
            expr: "#username".to_owned(),
        })
        .await
        .unwrap()
        .unwrap();
    rig.handle
        .type_credential(target, SecretOr::Plain("fixture-user".to_owned()))
        .await
        .unwrap();
    let bundle = rig.handle.observe(ObservationSpec::default()).await.unwrap();
    let analyzed = StateAnalyzer::new(
        rig.core.run,
        rig.core.session,
        rig.core.rc.clusters.clone(),
        rig.core.stores.artifacts.clone(),
        rig.core.rc.clock.clone(),
        rig.core.rc.crawl.capture.clone(),
        (&rig.core.rc.controls, &rig.core.rc.captcha_secrets),
    )
    .analyze(&bundle)
    .await;
    let (proposal, context) = proposal_for(
        &bundle,
        "Next",
        ActionKind::Click,
        analyzed.state.cluster,
        &rig.core.principal,
        &rig.core.rc.seed_origin(),
        SafetyProfile::ReadOnly,
    );
    let Adjudication::Allow(admitted) = rig.core.rc.kernel.adjudicate(proposal, &context) else {
        panic!("fixture link must be admitted");
    };
    let outcome = rig
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    {
        let starts = rig.recording.starts.lock();
        assert_eq!(
            starts.iter().map(|start| start.kind).collect::<Vec<_>>(),
            ["navigate", "page_op", "perform", "perform"]
        );
        for pair in starts.windows(2) {
            assert!(pair[1].at.duration_since(pair[0].at) >= SPACING);
        }
    }
    rig.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn two_tenants_share_origin_cap_but_an_independent_origin_proceeds() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let first_governor = governor(Arc::clone(&cap));
    let second_governor = governor(Arc::clone(&cap));
    assert!(!Arc::ptr_eq(&first_governor, &second_governor));
    let first = actor(Some(first_governor)).await;
    let second = actor(Some(second_governor)).await;
    assert_ne!(first.core.stores.tenant, second.core.stores.tenant);
    let gate = Arc::new(Semaphore::new(0));
    *first.recording.navigation_gate.lock() = Some(Arc::clone(&gate));
    let held = first
        .handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(HELD),
            0,
            None,
        ));
    tokio::pin!(held);
    pending(held.as_mut()).await;
    schedule_actor().await;
    assert_eq!(first.recording.starts.lock().len(), 1);
    assert_eq!(cap.available(&Origin::new("https://example.test")), 0);

    // This second tenant can use its other-origin slot while the first holds
    // example.test, but it cannot bypass the shared cap for example.test.
    let now = Instant::now();
    second
        .handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(OTHER),
            0,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(second.recording.starts.lock()[0].at, now);
    let waiting = second
        .handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ));
    tokio::pin!(waiting);
    pending(waiting.as_mut()).await;
    schedule_actor().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    schedule_actor().await;
    assert_eq!(second.recording.starts.lock().len(), 1);
    pending(waiting.as_mut()).await;
    gate.add_permits(1);
    held.await.unwrap();
    waiting.await.unwrap();
    assert_eq!(second.recording.starts.lock().len(), 2);
    assert_eq!(cap.available(&Origin::new("https://example.test")), 1);
    first.handle.shutdown(ShutdownReason::Completed).await.unwrap();
    second.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelling_cap_waiter_releases_worker_slots() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let holder = governor(Arc::clone(&cap));
    let waiter = OriginGovernor::with_global_cap(
        GovernorConfig {
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 1,
            max_concurrency: 1,
            ..GovernorConfig::default()
        },
        Arc::clone(&cap),
    );
    let origin = Origin::new("https://example.test");
    let held = holder.acquire_browser(&origin).await.unwrap();
    {
        let waiting = waiter.acquire_browser(&origin);
        tokio::pin!(waiting);
        pending(waiting.as_mut()).await;
    }
    // The cancelled cap waiter had already taken its worker-global slot.
    // A different origin must still be admitted without a clock advance.
    let before = Instant::now();
    let independent = waiter
        .acquire_browser(&Origin::new("https://other.test"))
        .await
        .unwrap();
    assert_eq!(Instant::now(), before);
    drop(independent);
    drop(held);
    assert_eq!(cap.available(&origin), 1);
    let replacement = waiter.acquire_browser(&origin).await.unwrap();
    assert_eq!(cap.available(&origin), 0);
    drop(replacement);
    assert_eq!(cap.available(&origin), 1);
}

#[tokio::test(start_paused = true)]
async fn cancelling_spacing_waiter_releases_every_held_slot() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let governor = OriginGovernor::with_global_cap(
        GovernorConfig {
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 1,
            max_concurrency: 1,
            ..GovernorConfig::default()
        },
        Arc::clone(&cap),
    );
    let origin = Origin::new("https://example.test");
    let mut dispatched = governor.acquire_browser(&origin).await.unwrap();
    dispatched.commit_dispatch().unwrap();
    drop(dispatched);
    {
        let waiting = governor.acquire_browser(&origin);
        tokio::pin!(waiting);
        pending(waiting.as_mut()).await;
        assert_eq!(cap.available(&origin), 0);
    }
    assert_eq!(cap.available(&origin), 1);
    let before = Instant::now();
    let independent = governor
        .acquire_browser(&Origin::new("https://other.test"))
        .await
        .unwrap();
    assert_eq!(Instant::now(), before);
    drop(independent);
    tokio::time::advance(Duration::from_secs(1)).await;
    let replacement = governor.acquire_browser(&origin).await.unwrap();
    drop(replacement);
    assert_eq!(cap.available(&origin), 1);
}

#[tokio::test(start_paused = true)]
async fn saturated_origin_waiters_do_not_spend_unrelated_run_global_capacity() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let holder = governor(Arc::clone(&cap));
    let waiter = OriginGovernor::with_global_cap(
        GovernorConfig {
            base_delay: Duration::ZERO,
            max_in_flight_per_origin: 4,
            max_concurrency: 1,
            ..GovernorConfig::default()
        },
        Arc::clone(&cap),
    );
    let origin = Origin::new("https://example.test");
    let held = holder.acquire_browser(&origin).await.unwrap();
    {
        let waiting = waiter.acquire_browser(&origin);
        tokio::pin!(waiting);
        pending(waiting.as_mut()).await;
        let before = Instant::now();
        let independent = tokio::time::timeout(
            Duration::from_millis(1),
            waiter.acquire_browser(&Origin::new("https://other.test")),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(Instant::now(), before);
        drop(independent);
    }
    drop(held);
    assert_eq!(cap.available(&origin), 1);
}

#[tokio::test(start_paused = true)]
async fn run_cancellation_stops_browser_admission_without_starting_the_effect() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let origin = Origin::new("https://example.test");
    let holder = governor(Arc::clone(&cap));
    let held = holder.acquire_browser(&origin).await.unwrap();
    let rig = actor(Some(governor(Arc::clone(&cap)))).await;
    let waiting = rig.handle.navigate(crawlx_core::request::RequestEnvelopeV1::get(
        canonical(SEED),
        0,
        None,
    ));
    tokio::pin!(waiting);
    pending(waiting.as_mut()).await;
    schedule_actor().await;
    assert!(rig.recording.starts.lock().is_empty());
    rig.cancel.cancel();
    assert!(matches!(
        waiting.await,
        Err(crawlx_worker::SessionError::Browser(
            BrowserError::OriginAdmission(_)
        ))
    ));
    assert!(rig.recording.starts.lock().is_empty());
    drop(held);
    assert_eq!(cap.available(&origin), 1);
    rig.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

struct BindingClock {
    started: Instant,
}

impl crawlx_core::Clock for BindingClock {
    fn now(&self) -> crawlx_core::Timestamp {
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap()
            + chrono::Duration::from_std(self.started.elapsed()).unwrap()
    }
}

async fn admitted_next(rig: &ActorRig) -> crawlx_safety::AdmittedAction {
    let bundle = rig.handle.observe(ObservationSpec::default()).await.unwrap();
    let analyzed = StateAnalyzer::new(
        rig.core.run,
        rig.core.session,
        rig.core.rc.clusters.clone(),
        rig.core.stores.artifacts.clone(),
        rig.core.rc.clock.clone(),
        rig.core.rc.crawl.capture.clone(),
        (&rig.core.rc.controls, &rig.core.rc.captcha_secrets),
    )
    .analyze(&bundle)
    .await;
    let (proposal, context) = proposal_for(
        &bundle,
        "Next",
        ActionKind::Click,
        analyzed.state.cluster,
        &rig.core.principal,
        &rig.core.rc.seed_origin(),
        SafetyProfile::ReadOnly,
    );
    let Adjudication::Allow(admitted) = rig.core.rc.kernel.adjudicate(proposal, &context) else {
        panic!("fixture link must be admitted");
    };
    admitted
}

async fn assert_only_proposed(rig: &ActorRig) {
    let records = rig.core.stores.journal.list(rig.core.run, None).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, ActionStatus::Proposed, "never intended");
    assert!(!rig
        .recording
        .starts
        .lock()
        .iter()
        .any(|start| start.kind == "perform"));
}

#[tokio::test(start_paused = true)]
async fn actor_rechecks_mutation_after_origin_wait_and_fresh_action_uses_one_permit() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let paced = governor(Arc::clone(&cap));
    let rig = actor(Some(Arc::clone(&paced))).await;
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ))
        .await
        .unwrap();
    let admitted = admitted_next(&rig).await;
    let origin = Origin::new("https://example.test");
    let held = governor(Arc::clone(&cap)).acquire_browser(&origin).await.unwrap();
    let waiting = rig.handle.execute(admitted, QuiescencePolicy::default());
    tokio::pin!(waiting);
    pending(waiting.as_mut()).await;
    schedule_actor().await;
    assert_only_proposed(&rig).await;
    // Model a live MutationObserver counter changing independently of the actor's mailbox.
    rig.recording.mutation_seq.store(9, Ordering::SeqCst);
    drop(held);
    let outcome = waiting.await.unwrap();
    assert_eq!(
        outcome.dropped,
        Some(crawlx_worker::actor::DropReason::StaleEpoch)
    );
    assert_only_proposed(&rig).await;
    assert_eq!(
        cap.available(&origin),
        1,
        "dropped proposal releases its reservation"
    );

    let admitted = admitted_next(&rig).await;
    let before = Instant::now();
    let outcome = rig
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    assert_eq!(
        Instant::now().duration_since(before),
        Duration::ZERO,
        "stale preparation spends no dispatch spacing and confirmation adds no wait"
    );
    assert_eq!(
        rig.recording
            .starts
            .lock()
            .iter()
            .filter(|start| start.kind == "perform")
            .count(),
        1
    );
    assert_eq!(cap.available(&origin), 1, "settle releases capacity one");
    rig.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn delayed_final_probe_does_not_spend_browser_dispatch_spacing() {
    let rig = actor(None).await;
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ))
        .await
        .unwrap();
    let admitted = admitted_next(&rig).await;
    *rig.recording.revalidation_delay.lock() = Some(Duration::from_millis(600));
    let outcome = rig
        .handle
        .execute(admitted, QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(outcome.status, ActionStatus::Succeeded);
    let dispatched = rig
        .recording
        .starts
        .lock()
        .iter()
        .find(|start| start.kind == "perform")
        .unwrap()
        .at;
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ))
        .await
        .unwrap();
    let next = rig.recording.starts.lock().last().unwrap().at;
    assert_eq!(next.duration_since(dispatched), SPACING);
    rig.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancellation_after_final_probe_prevents_prepared_dispatch() {
    let rig = actor(None).await;
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ))
        .await
        .unwrap();
    let admitted = admitted_next(&rig).await;
    *rig.recording.cancel_after_revalidation.lock() = Some(rig.cancel.clone());
    assert!(matches!(
        rig.handle.execute(admitted, QuiescencePolicy::default()).await,
        Err(crawlx_worker::SessionError::Cancelled)
    ));
    assert!(!rig
        .recording
        .starts
        .lock()
        .iter()
        .any(|start| start.kind == "perform"));
    rig.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelling_actor_action_admission_never_journals_intent_or_starts_effect() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let paced = governor(Arc::clone(&cap));
    let rig = actor(Some(Arc::clone(&paced))).await;
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ))
        .await
        .unwrap();
    let admitted = admitted_next(&rig).await;
    let origin = Origin::new("https://example.test");
    let held = governor(Arc::clone(&cap)).acquire_browser(&origin).await.unwrap();
    let waiting = rig.handle.execute(admitted, QuiescencePolicy::default());
    tokio::pin!(waiting);
    pending(waiting.as_mut()).await;
    schedule_actor().await;
    assert_only_proposed(&rig).await;
    rig.cancel.cancel();
    assert!(matches!(
        waiting.await,
        Err(crawlx_worker::SessionError::Cancelled)
    ));
    assert_only_proposed(&rig).await;
    drop(held);
    let replacement = paced.acquire_browser(&origin).await.unwrap();
    drop(replacement);
    assert_eq!(cap.available(&origin), 1);
    rig.handle.shutdown(ShutdownReason::Completed).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn binding_expiry_bounds_actor_admission_without_intent_or_effect() {
    let cap = Arc::new(GlobalOriginCap::new(1));
    let paced = governor(Arc::clone(&cap));
    let rig = actor_with_binding(Some(Arc::clone(&paced)), Some(Duration::from_secs(10))).await;
    rig.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical(SEED),
            0,
            None,
        ))
        .await
        .unwrap();
    let admitted = admitted_next(&rig).await;
    let origin = Origin::new("https://example.test");
    let held = governor(Arc::clone(&cap)).acquire_browser(&origin).await.unwrap();
    let waiting = rig.handle.execute(admitted, QuiescencePolicy::default());
    tokio::pin!(waiting);
    pending(waiting.as_mut()).await;
    schedule_actor().await;
    assert_only_proposed(&rig).await;
    tokio::time::advance(Duration::from_secs(10)).await;
    assert!(matches!(
        waiting.await,
        Err(crawlx_worker::SessionError::Binding(
            crawlx_core::session_binding::SessionBindingError::Expired
        ))
    ));
    assert_only_proposed(&rig).await;
    schedule_actor().await;
    assert!(
        !rig.cancel.is_cancelled(),
        "local retirement must not cancel other roles"
    );
    drop(held);
    let replacement = paced.acquire_browser(&origin).await.unwrap();
    drop(replacement);
    assert_eq!(cap.available(&origin), 1, "expired waiter releases capacity");
}

#[tokio::test(start_paused = true)]
async fn execution_deadline_during_admission_is_typed_without_intent_or_effect() {
    for (binding_seconds, execution_seconds) in [(10, 10), (30, 10), (10, 20)] {
        let execution_first = execution_seconds <= binding_seconds;
        let assert_expiry = |error: crawlx_worker::SessionError| {
            let mut cause = &error;
            while let crawlx_worker::SessionError::ActorStopped(source) = cause {
                cause = source.as_ref();
            }
            match cause {
                crawlx_worker::SessionError::ExecutionDeadlineReached => assert!(execution_first),
                crawlx_worker::SessionError::Binding(
                    crawlx_core::session_binding::SessionBindingError::Expired,
                ) => assert!(
                    !execution_first,
                    "an earlier binding ceiling remains an independent failure"
                ),
                other => panic!("unexpected expiry cause: {other:?}"),
            }
        };
        let cap = Arc::new(GlobalOriginCap::new(1));
        let paced = governor(Arc::clone(&cap));
        let rig = actor_with_bounds(
            Some(Arc::clone(&paced)),
            Some(Duration::from_secs(binding_seconds)),
            Some(Duration::from_secs(execution_seconds)),
        )
        .await;
        rig.handle
            .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                canonical(SEED),
                0,
                None,
            ))
            .await
            .unwrap();
        let admitted = admitted_next(&rig).await;
        let origin = Origin::new("https://example.test");
        let held = governor(Arc::clone(&cap)).acquire_browser(&origin).await.unwrap();
        let waiting = rig.handle.execute(admitted, QuiescencePolicy::default());
        tokio::pin!(waiting);
        pending(waiting.as_mut()).await;
        schedule_actor().await;
        assert_only_proposed(&rig).await;
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_expiry(waiting.await.unwrap_err());
        assert_only_proposed(&rig).await;
        assert!(!rig.cancel.is_cancelled());
        // Idle retirement and a later caller retain the proven cause, not ActorGone.
        schedule_actor().await;
        assert_expiry(rig.handle.observe(ObservationSpec::default()).await.unwrap_err());
        let shutdown = rig.handle.shutdown(ShutdownReason::Completed).await;
        if execution_first {
            shutdown.unwrap();
        } else {
            assert_expiry(shutdown.unwrap_err());
        }
        drop(held);
        assert_eq!(cap.available(&origin), 1);
    }
}
