//! Actor-owned browser lifecycle hooks, native re-admission and approved actor recipes,
//! against the real Session Actor, journal and driver over the scripted browser.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::archive_behaviors::{RecipeStepV1, RecipeV1};
use crawlx_core::counters::{ActionStatus, PlaneCounters, RunStatus};
use crawlx_core::extensions::{ExtensionConfigV1, ExtensionSpecV1, ExtensionStageV1, HandlerV1};
use crawlx_core::repo::{CrawlRun, CrawlSession};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::scrape::ScrapeAction;
use crawlx_core::{CrawlRunId, SafetyProfile, SystemClock};
use crawlx_scheduler::RunPlanner;
use crawlx_storage::MemoryStore;
use crawlx_worker::actor::{SessionActor, SessionHandle};
use crawlx_worker::driver::{DriverConfig, ExplorationDriver};
use crawlx_worker::{RunContext, StateAnalyzer, Stores, WorkerConfig};
use serde_json::Value;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Counts performed actions and, once one was performed, never lets settle finish.
#[derive(Default)]
struct Hang {
    performed: std::sync::atomic::AtomicUsize,
    in_settle: std::sync::atomic::AtomicBool,
}

struct HangContext {
    inner: Box<dyn crawlx_core::BrowserContext>,
    hang: Arc<Hang>,
}

#[async_trait::async_trait]
impl crawlx_core::BrowserContext for HangContext {
    async fn navigate(
        &mut self,
        url: &crawlx_core::CanonicalUrl,
    ) -> Result<crawlx_core::observation::NavigationResult, crawlx_core::BrowserError> {
        self.inner.navigate(url).await
    }
    async fn observe(
        &mut self,
        spec: crawlx_core::observation::ObservationSpec,
    ) -> Result<crawlx_core::observation::ObservationBundle, crawlx_core::BrowserError> {
        self.inner.observe(spec).await
    }
    async fn revalidate(
        &mut self,
        locator: &crawlx_core::observation::RuntimeLocator,
        epoch: crawlx_core::ObservationEpoch,
    ) -> Result<crawlx_core::observation::Revalidation, crawlx_core::BrowserError> {
        self.inner.revalidate(locator, epoch).await
    }
    async fn resolve_selector(
        &mut self,
        selector: &crawlx_core::observation::DomSelector,
    ) -> Result<Option<crawlx_core::observation::RuntimeLocator>, crawlx_core::BrowserError> {
        self.inner.resolve_selector(selector).await
    }
    async fn perform(
        &mut self,
        action: crawlx_core::BrowserAction,
    ) -> Result<crawlx_core::observation::ActionReceipt, crawlx_core::BrowserError> {
        let receipt = self.inner.perform(action).await?;
        self.hang
            .performed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(receipt)
    }
    async fn settle(
        &mut self,
        policy: crawlx_core::observation::QuiescencePolicy,
    ) -> Result<crawlx_core::observation::SettleReport, crawlx_core::BrowserError> {
        if self.hang.performed.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            self.hang
                .in_settle
                .store(true, std::sync::atomic::Ordering::SeqCst);
            std::future::pending::<()>().await;
        }
        self.inner.settle(policy).await
    }
    fn current_epoch(&self) -> crawlx_core::ObservationEpoch {
        self.inner.current_epoch()
    }
    fn drain_traffic(&mut self) -> Vec<crawlx_core::traffic::TrafficEvent> {
        self.inner.drain_traffic()
    }
    async fn export_storage(&mut self) -> Result<Vec<u8>, crawlx_core::BrowserError> {
        self.inner.export_storage().await
    }
    async fn import_storage(&mut self, blob: &[u8]) -> Result<(), crawlx_core::BrowserError> {
        self.inner.import_storage(blob).await
    }
    async fn close(self: Box<Self>) -> Result<(), crawlx_core::BrowserError> {
        self.inner.close().await
    }
    async fn page_op(
        &mut self,
        op: crawlx_core::page_op::PageOp,
    ) -> Result<crawlx_core::page_op::PageOpResult, crawlx_core::BrowserError> {
        self.inner.page_op(op).await
    }
    fn drain_blocked_navigations(&mut self) -> Vec<crawlx_core::BlockedNavigation> {
        self.inner.drain_blocked_navigations()
    }
}

struct Fixture {
    stores: Stores,
    rc: Arc<RunContext>,
    handle: SessionHandle,
    analyzer: Arc<StateAnalyzer>,
    session: CrawlSession,
    run: CrawlRunId,
    fake: Arc<FakeBackend>,
    cancel: CancellationToken,
    effect: CancellationToken,
    _dir: tempfile::TempDir,
}

fn script() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Home")
                .html("<html><body><h1>Home</h1></body></html>")
                .node(FakeAxSpec::button("danger", "Delete account"))
                .node(FakeAxSpec::textbox("q", "Query"))
                .node(FakeAxSpec::button("save", "Save"))
                .on_click("save", vec![FakeEffect::Nothing]),
        )
        .page(FakePage::new("https://example.test/about").title("About"))
        .page(FakePage::new("https://example.test/replacement").title("Replacement"))
}

/// Actor over a fresh run. The seed navigation is NOT issued, so a lifecycle that refuses
/// navigation can be tested from the very first request.
async fn fixture(configure: impl FnOnce(&mut crawlx_core::CreateCrawl), profile: SafetyProfile) -> Fixture {
    fixture_with(configure, profile, None).await
}

async fn fixture_with(
    configure: impl FnOnce(&mut crawlx_core::CreateCrawl),
    profile: SafetyProfile,
    hang: Option<Arc<Hang>>,
) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = common::crawl(profile);
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    configure(&mut crawl);
    let mut record = common::authorization::verified_record(&crawl, stores.tenant);
    record.robots_override_acknowledged = true;
    stores =
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
        created_at: chrono::Utc::now(),
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
    let guard = common::authorization::admit(&stores, &run, &cfg).await;
    let fake = Arc::new(
        FakeBackend::builder()
            .script(script())
            .clock(Arc::new(SystemClock))
            .build(),
    );
    let cancel = CancellationToken::new();
    let rc = Arc::new(
        RunContext::build(
            &run,
            &cfg,
            stores.clone(),
            Some(fake.clone()),
            None,
            cancel.clone(),
            None,
            Some(guard),
        )
        .await
        .unwrap(),
    );
    let mut scfg = rc.session_config(&session);
    // Per-session interactive-style token: interrupts an in-flight effect or settle.
    let effect = cancel.child_token();
    let pool = match &hang {
        Some(hang) => {
            scfg.origin_cancel = effect.clone();
            scfg.effect_cancel = Some(effect.clone());
            let hang = Arc::clone(hang);
            rc.pool.clone().with_context_wrapper(Arc::new(move |_, inner| {
                Box::new(HangContext {
                    inner,
                    hang: Arc::clone(&hang),
                })
            }))
        }
        None => rc.pool.clone(),
    };
    let pooled = pool
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
    let handle = SessionActor::spawn(scfg, rc.services(), Arc::clone(&analyzer), 7, pooled)
        .await
        .unwrap();
    Fixture {
        stores,
        rc,
        handle,
        analyzer,
        session,
        run: run.id,
        fake,
        cancel,
        effect,
        _dir: dir,
    }
}

fn annotate(stage: ExtensionStageV1) -> ExtensionSpecV1 {
    ExtensionSpecV1::new(
        ExtensionConfigV1::Annotate {
            stage,
            code: "seen".into(),
        },
        0,
    )
}

fn seed(f: &Fixture) -> RequestEnvelopeV1 {
    RequestEnvelopeV1::get(f.rc.seed_url().unwrap(), 0, None)
}

async fn receipts(f: &Fixture, scope: &str) -> Vec<Value> {
    f.stores
        .events
        .list_after(f.run, 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|event| event.kind == "extension.browser" && event.payload["scope"] == scope)
        .map(|event| event.payload)
        .collect()
}

fn stages(payloads: &[Value]) -> Vec<String> {
    payloads
        .iter()
        .map(|p| p["receipt"]["event"]["kind"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn navigation_hooks_run_around_the_real_navigation_with_epoch_and_one_terminal() {
    let f = fixture(
        |crawl| {
            crawl.extensions.extensions = vec![
                annotate(ExtensionStageV1::BrowserPreNavigation),
                annotate(ExtensionStageV1::BrowserPostNavigation),
            ];
        },
        SafetyProfile::ReadOnly,
    )
    .await;
    f.handle.navigate(seed(&f)).await.unwrap();
    let trail = receipts(&f, "navigation").await;
    assert_eq!(
        stages(&trail),
        [
            "configure",
            "request_proposed",
            "before_acquisition",
            "browser_pre_navigation",
            "browser_post_navigation",
            "terminal",
            "checkpoint",
            "close"
        ]
    );
    assert_eq!(trail[5]["receipt"]["event"]["facts"]["kind"], "completed");
    assert!(
        trail.iter().all(|p| p["epoch"]["navigation"].is_u64()),
        "epoch stamped"
    );
    assert_eq!(f.fake.context_handles()[0].navigations().len(), 1);
    // Sequence is contiguous and one-based.
    let sequence: Vec<u64> = trail
        .iter()
        .map(|p| p["receipt"]["sequence"].as_u64().unwrap())
        .collect();
    assert_eq!(sequence, (1..=8).collect::<Vec<u64>>());
}

#[tokio::test]
async fn pre_navigation_rejection_never_reaches_the_browser_and_records_one_skip() {
    let f = fixture(
        |crawl| {
            crawl.extensions.extensions = vec![ExtensionSpecV1::new(
                ExtensionConfigV1::RejectStage {
                    stage: ExtensionStageV1::BrowserPreNavigation,
                },
                0,
            )];
        },
        SafetyProfile::ReadOnly,
    )
    .await;
    assert!(f.handle.navigate(seed(&f)).await.is_err());
    assert!(
        f.fake.context_handles()[0].navigations().is_empty(),
        "refused hook, no effect"
    );
    let trail = receipts(&f, "navigation").await;
    let terminals: Vec<_> = trail
        .iter()
        .filter(|p| p["receipt"]["event"]["kind"] == "terminal")
        .collect();
    assert_eq!(terminals.len(), 1);
    assert_eq!(terminals[0]["receipt"]["event"]["facts"]["kind"], "skipped");
    assert!(!stages(&trail).contains(&"browser_post_navigation".to_owned()));
}

#[tokio::test]
async fn failing_post_navigation_hook_is_a_failed_terminal_not_a_silent_success() {
    let f = fixture(
        |crawl| {
            crawl.extensions.extensions = vec![ExtensionSpecV1::new(
                ExtensionConfigV1::FailStage {
                    stage: ExtensionStageV1::BrowserPostNavigation,
                },
                0,
            )];
        },
        SafetyProfile::ReadOnly,
    )
    .await;
    assert!(f.handle.navigate(seed(&f)).await.is_err());
    let trail = receipts(&f, "navigation").await;
    let terminal = trail
        .iter()
        .find(|p| p["receipt"]["event"]["kind"] == "terminal")
        .unwrap();
    assert_eq!(terminal["receipt"]["event"]["facts"]["kind"], "failed");
}

#[tokio::test]
async fn out_of_scope_replacement_is_denied_stickily_and_never_navigated() {
    let f = fixture(
        |crawl| {
            let mut replacement =
                RequestEnvelopeV1::get(common::canonical("https://evil.test/steal"), 0, None);
            replacement.route = "default".into();
            crawl.extensions.extensions = vec![ExtensionSpecV1::new(
                ExtensionConfigV1::ReplaceRequest {
                    request: Box::new(replacement),
                },
                0,
            )];
            crawl
                .extensions
                .routes
                .insert("default".into(), HandlerV1::DocumentItem);
        },
        SafetyProfile::ReadOnly,
    )
    .await;
    let error = f.handle.navigate(seed(&f)).await.unwrap_err();
    assert!(error.to_string().contains("denied"), "{error}");
    let navigations = f.fake.context_handles()[0].navigations();
    assert!(
        navigations.iter().all(|url| !url.contains("evil.test")),
        "{navigations:?}"
    );
    assert!(navigations.is_empty());
    let trail = receipts(&f, "navigation").await;
    let terminal = trail
        .iter()
        .find(|p| p["receipt"]["event"]["kind"] == "terminal")
        .unwrap();
    assert_eq!(terminal["receipt"]["event"]["facts"]["kind"], "skipped");
    assert_eq!(terminal["receipt"]["event"]["facts"]["reason"], "policy_denied");
}

#[tokio::test]
async fn cancelled_run_refuses_navigation_before_any_hook_or_effect() {
    let f = fixture(
        |crawl| crawl.extensions.extensions = vec![annotate(ExtensionStageV1::BrowserPreNavigation)],
        SafetyProfile::ReadOnly,
    )
    .await;
    f.cancel.cancel();
    assert!(f.handle.navigate(seed(&f)).await.is_err());
    assert!(f.fake.context_handles()[0].navigations().is_empty());
    assert!(
        receipts(&f, "navigation").await.is_empty(),
        "no lifecycle began after cancellation"
    );
}

#[tokio::test]
async fn approved_recipe_denial_stops_later_steps_through_the_real_kernel_and_journal() {
    let mut recipe = RecipeV1::new("wave3-actor".into(), 1);
    recipe.steps = vec![
        RecipeStepV1::new(
            0,
            ScrapeAction::Click {
                selector: "#danger".into(),
                all: false,
            },
        ),
        RecipeStepV1::new(
            1,
            ScrapeAction::Fill {
                selector: "#q".into(),
                text: "must-not-run".into(),
            },
        ),
        RecipeStepV1::new(2, ScrapeAction::Press { key: "Enter".into() }),
    ];
    let f = fixture(|_| {}, SafetyProfile::TestEnvironment).await;
    f.handle.navigate(seed(&f)).await.unwrap();
    let cfg = DriverConfig {
        observe_only: true,
        ..DriverConfig::default()
    };
    let mut driver = ExplorationDriver::new(
        cfg,
        Arc::clone(&f.rc),
        f.session.clone(),
        f.handle.clone(),
        Arc::clone(&f.analyzer),
        Vec::new(),
    )
    .with_extension_recipe(Arc::new(recipe));
    driver.run(vec![seed(&f)]).await.unwrap();
    // The destructive click was denied by the existing kernel: nothing reached the page.
    assert!(f.fake.context_handles()[0].performed().is_empty());
    let rows = f.stores.journal.list(f.run, None).await.unwrap();
    assert_eq!(rows.len(), 1, "only the denied proposal is journaled: {rows:?}");
    assert!(rows.iter().all(|row| row.status != ActionStatus::Succeeded));
    let events = f.stores.events.list_after(f.run, 0, 10_000).await.unwrap();
    let provenance = events
        .iter()
        .find(|event| event.kind == "archive.recipe")
        .unwrap();
    assert_eq!(provenance.payload["steps"][0]["disposition"], "failed");
    assert_eq!(provenance.payload["steps"][1]["disposition"], "not_run");
    assert_eq!(provenance.payload["steps"][2]["disposition"], "not_run");
    assert!(events
        .iter()
        .any(|event| event.kind == "extension_recipe_stopped"));
    assert!(!provenance.payload.to_string().contains("must-not-run"));
}

#[tokio::test]
async fn cancel_during_settle_journals_unknown_and_refuses_any_later_effect() {
    use crawlx_core::identity::ActionKind;
    use crawlx_observe::spec;
    let hang = Arc::new(Hang::default());
    let f = fixture_with(|_| {}, SafetyProfile::TestEnvironment, Some(Arc::clone(&hang))).await;
    f.handle.navigate(seed(&f)).await.unwrap();
    let bundle = f.handle.observe(spec::after_action()).await.unwrap();
    let state = f.analyzer.analyze(&bundle).await.state;
    f.stores.states.put_state(&state).await.unwrap();
    let (proposal, safety) = common::proposal_for(
        &bundle,
        "Save",
        ActionKind::Click,
        state.cluster,
        &f.session.role,
        &f.rc.seed_origin(),
        f.rc.crawl.safety.profile,
    );
    let admitted = match f.rc.kernel.adjudicate(proposal, &safety) {
        crawlx_safety::Adjudication::Allow(admitted) => admitted,
        other => panic!("fixture click must be admitted: {other:?}"),
    };
    let handle = f.handle.clone();
    let running = tokio::spawn(async move {
        handle
            .execute(admitted, crawlx_core::observation::QuiescencePolicy::default())
            .await
    });
    // The click has been dispatched and the actor is parked inside settle.
    for _ in 0..500 {
        if hang.in_settle.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        hang.in_settle.load(std::sync::atomic::Ordering::SeqCst),
        "never reached settle"
    );
    f.effect.cancel();
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), running)
        .await
        .expect("cancel must interrupt settle, not wait for quiescence")
        .unwrap();
    assert!(
        result.is_err(),
        "the cancelled action is not reported as a success"
    );
    // The dispatched effect is journaled conservatively, never as "no effect".
    let rows = f.stores.journal.list(f.run, None).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, ActionStatus::Unknown, "{rows:?}");
    // No later browser effect, and shutdown proceeds immediately.
    let performed = hang.performed.load(std::sync::atomic::Ordering::SeqCst);
    assert!(f.handle.navigate(seed(&f)).await.is_err());
    assert!(f.handle.observe(spec::cheap()).await.is_err());
    assert_eq!(
        hang.performed.load(std::sync::atomic::Ordering::SeqCst),
        performed
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        f.handle.shutdown(crawlx_worker::actor::ShutdownReason::Cancelled),
    )
    .await
    .expect("shutdown is not queued behind a quiescence wait")
    .unwrap();
    assert_eq!(f.fake.open_contexts(), 0);
}
