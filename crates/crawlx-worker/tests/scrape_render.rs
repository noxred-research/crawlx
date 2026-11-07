//! The browser leg of the scrape engine (`BrowserRenderer`).
//!
//! The scripted-backend tests run everywhere: a `FakeBackend` behind a context decorator that
//! answers the scrape page operations. The Chromium tests need `CRAWLX_CHROMIUM_PATH` (and
//! `CRAWLX_ALLOW_UNPINNED=1` for a build that is not the pinned one) and skip without it; they
//! load a fixture site on `127.0.0.1` through the run's egress proxy, where every fixture host
//! name resolves through a static table.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
use common::authorization as authorization_fixture;

use async_trait::async_trait;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript, PLACEHOLDER_PNG};
use crawlx_browser::FakeBackend;
use crawlx_core::action::BrowserAction;
use crawlx_core::counters::{ActionStatus, PlaneCounters, RunStatus};
use crawlx_core::identity::ActionKind;
use crawlx_core::observation::{
    ActionReceipt, BrowserBuildInfo, DomSelector, DomSelectorKind, NavigationResult, ObservationBundle,
    ObservationSpec, QuiescencePolicy, Revalidation, RuntimeLocator, SettleReport,
};
use crawlx_core::page_op::{Emulation, PageOp, PageOpResult, SelectorState};
use crawlx_core::repo::{CrawlRun, SessionStatus};
use crawlx_core::scrape::{ScrapeAction, ScrapeOptions, MOBILE_USER_AGENT};
use crawlx_core::traffic::TrafficEvent;
use crawlx_core::{
    BrowserBackend, BrowserContext, BrowserError, CanonicalUrl, Clock, CrawlRunId, CreateCrawl,
    ObservationEpoch, SafetyProfile, SystemClock,
};
use crawlx_fetch::{EgressProxy, EgressProxyHandle, StaticResolver};
use crawlx_storage::MemoryStore;
use crawlx_worker::scrape::render::{
    BrowserRenderer, PageRenderer, RenderError, RenderRequest, Rendered, EXPLICIT_ACTIONS_STRATEGY,
};
use crawlx_worker::{EgressConfig, RunContext, Stores, WorkerConfig};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

fn options(v: Value) -> ScrapeOptions {
    let o: ScrapeOptions = serde_json::from_value(v).unwrap();
    o.validate().unwrap();
    o
}

fn lo() -> IpAddr {
    IpAddr::from([127, 0, 0, 1])
}

/// A run in `stores` with `crawl`.
async fn create_run(stores: &Stores, crawl: &CreateCrawl) -> CrawlRun {
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
    stores
        .runs
        .set_status(run.id, RunStatus::Running, None)
        .await
        .unwrap();
    stores.runs.get(run.id).await.unwrap()
}

fn crawl_for(seed: &str, profile: SafetyProfile) -> CreateCrawl {
    let mut crawl = CreateCrawl::new(Url::parse(seed).unwrap());
    crawl.seed = Some(20_261_027);
    crawl.safety.profile = profile;
    crawl.safety.allow_private_networks = true;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.scope.allow_subdomains = true;
    crawl
}

// ---------------------------------------------------------------------------------------------
// Scripted backend: a FakeBackend whose contexts also answer the scrape page operations
// ---------------------------------------------------------------------------------------------

/// What the decorated contexts do beyond the fake.
#[derive(Default)]
struct Behavior {
    /// Sleep before every navigation.
    nav_delay: Duration,
    /// Fail every navigation with this error.
    nav_error: Option<fn() -> BrowserError>,
    /// CSS selector -> node keys it matches (`ResolveAll`); other selectors match `#<selector>`.
    groups: BTreeMap<String, Vec<String>>,
}

struct Ops {
    behavior: Behavior,
    log: Mutex<Vec<String>>,
    emulations: Mutex<Vec<Emulation>>,
    wait_states: Mutex<Vec<SelectorState>>,
}

impl Ops {
    fn new(behavior: Behavior) -> Arc<Self> {
        Arc::new(Self {
            behavior,
            log: Mutex::new(Vec::new()),
            emulations: Mutex::new(Vec::new()),
            wait_states: Mutex::new(Vec::new()),
        })
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().clone()
    }
}

struct OpsBackend {
    fake: Arc<FakeBackend>,
    ops: Arc<Ops>,
}

#[async_trait]
impl BrowserBackend for OpsBackend {
    async fn new_context(
        &self,
        config: crawlx_core::ContextConfig,
    ) -> Result<Box<dyn BrowserContext>, BrowserError> {
        Ok(Box::new(OpsContext {
            inner: self.fake.new_context(config).await?,
            ops: Arc::clone(&self.ops),
        }))
    }

    fn build_info(&self) -> &BrowserBuildInfo {
        self.fake.build_info()
    }
}

struct OpsContext {
    inner: Box<dyn BrowserContext>,
    ops: Arc<Ops>,
}

impl OpsContext {
    async fn css(&mut self, expr: String) -> Option<RuntimeLocator> {
        self.inner
            .resolve_selector(&DomSelector {
                kind: DomSelectorKind::Css,
                expr,
            })
            .await
            .unwrap()
    }
}

fn png() -> PageOpResult {
    PageOpResult::Bytes {
        bytes: PLACEHOLDER_PNG.to_vec(),
        content_type: "image/png",
    }
}

#[async_trait]
impl BrowserContext for OpsContext {
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        self.ops.log.lock().push(format!("navigate:{}", url.url));
        tokio::time::sleep(self.ops.behavior.nav_delay).await;
        if let Some(fail) = self.ops.behavior.nav_error {
            return Err(fail());
        }
        self.inner.navigate(url).await
    }

    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        self.inner.observe(spec).await
    }

    async fn revalidate(
        &mut self,
        locator: &RuntimeLocator,
        expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        self.inner.revalidate(locator, expected).await
    }

    async fn resolve_selector(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, BrowserError> {
        self.inner.resolve_selector(selector).await
    }

    async fn perform(&mut self, action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        self.inner.perform(action).await
    }

    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        self.inner.settle(policy).await
    }

    fn current_epoch(&self) -> ObservationEpoch {
        self.inner.current_epoch()
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

    async fn close(self: Box<Self>) -> Result<(), BrowserError> {
        self.inner.close().await
    }

    async fn page_op(&mut self, op: PageOp) -> Result<PageOpResult, BrowserError> {
        self.ops.log.lock().push(format!("page_op:{}", op.name()));
        match op {
            PageOp::Emulate(em) => {
                self.ops.emulations.lock().push(em);
                Ok(PageOpResult::Done)
            }
            PageOp::BlockUrls(_) => self.inner.page_op(op).await,
            PageOp::DocumentResponse => Ok(PageOpResult::Response {
                status: Some(200),
                headers: vec![("content-type".to_owned(), "text/html".to_owned())],
                content_type: Some("text/html".to_owned()),
            }),
            PageOp::Html => {
                let bundle = self.inner.observe(ObservationSpec::default()).await?;
                Ok(PageOpResult::Html {
                    html: bundle.html.unwrap_or_default(),
                    url: bundle.url.url.to_string(),
                })
            }
            PageOp::ResolveAll { selector, limit } => {
                let keys = self
                    .ops
                    .behavior
                    .groups
                    .get(&selector)
                    .cloned()
                    .unwrap_or_else(|| vec![selector.trim_start_matches('#').to_owned()]);
                let mut found = Vec::new();
                for key in keys.into_iter().take(limit as usize) {
                    if let Some(loc) = self.css(format!("#{key}")).await {
                        found.push(loc);
                    }
                }
                Ok(PageOpResult::Locators(found))
            }
            PageOp::WaitForSelector { state, .. } => {
                self.ops.wait_states.lock().push(state);
                self.inner.page_op(op).await
            }
            PageOp::EvaluateScript { script } => {
                Ok(PageOpResult::Json(json!({ "scriptLength": script.len() })))
            }
            PageOp::Screenshot(_) => Ok(png()),
            PageOp::PrintToPdf(_) => Ok(PageOpResult::Bytes {
                bytes: b"%PDF-1.4 scripted".to_vec(),
                content_type: "application/pdf",
            }),
            other @ (PageOp::BeginVirtualRows(_)
            | PageOp::ReadVirtualRows
            | PageOp::VirtualRowsTarget
            | PageOp::RestoreVirtualRows) => self.inner.page_op(other).await,
        }
    }
}

/// A run over `backend` with no egress proxy.
struct FakeRig {
    rc: Arc<RunContext>,
    stores: Stores,
    renderer: BrowserRenderer,
    cancel: CancellationToken,
    _dir: tempfile::TempDir,
}

async fn fake_rig(backend: Arc<dyn BrowserBackend>, profile: SafetyProfile) -> FakeRig {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let mut crawl = crawl_for("https://example.test/", profile);
    // Scripted pages have no HTTP robots source. The owned fixture explicitly authorizes
    // the override instead of relying on a browser context without the run's guard.
    crawl.safety.respect_robots_txt = false;
    let mut record = authorization_fixture::verified_record(&crawl, stores.tenant);
    record.robots_override_acknowledged = true;
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let run = create_run(&stores, &crawl).await;
    let cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        ..WorkerConfig::default()
    };
    let authorization = authorization_fixture::admit(&stores, &run, &cfg).await;
    let cancel = CancellationToken::new();
    let rc = Arc::new(
        RunContext::build(
            &run,
            &cfg,
            stores.clone(),
            Some(backend),
            None,
            cancel.clone(),
            None,
            Some(authorization),
        )
        .await
        .unwrap(),
    );
    FakeRig {
        renderer: BrowserRenderer::new(Arc::clone(&rc)).allow_unproxied(),
        rc,
        stores,
        cancel,
        _dir: dir,
    }
}

fn lab_script() -> FakeScript {
    FakeScript::new().page(
        FakePage::new("https://example.test/")
            .title("Lab")
            .html("<html><body><h1>Lab</h1></body></html>")
            .node(FakeAxSpec::button("b1", "Item 1"))
            .node(FakeAxSpec::button("b2", "Item 2"))
            .node(FakeAxSpec::button("b3", "Item 3"))
            .node(FakeAxSpec::textbox("q", "Query"))
            .node(FakeAxSpec::button("danger", "Delete account"))
            .node(FakeAxSpec::button("hidden", "Hidden").hidden())
            .on_click("b1", vec![FakeEffect::Nothing]),
    )
}

async fn scripted(behavior: Behavior, profile: SafetyProfile) -> (FakeRig, Arc<FakeBackend>, Arc<Ops>) {
    let fake = Arc::new(FakeBackend::new(lab_script()));
    let ops = Ops::new(behavior);
    let backend = Arc::new(OpsBackend {
        fake: Arc::clone(&fake),
        ops: Arc::clone(&ops),
    });
    (fake_rig(backend, profile).await, fake, ops)
}

#[tokio::test]
async fn admitted_handler_survives_replacement_redirect_and_settled_dom() {
    use common::canonical;
    use crawlx_core::extensions::{ExtensionConfigV1, ExtensionSpecV1, HandlerV1};
    use crawlx_core::request::RequestEnvelopeV1;

    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(MemoryStore::new());
    let stores = Stores::over_memory(store.clone(), dir.path()).await.unwrap();
    let mut crawl = common::crawl(SafetyProfile::TestEnvironment);
    crawl.safety.respect_robots_txt = false;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.extract.content = Some(crawlx_core::extraction::ExtractionPolicyV1::default());
    crawl.extensions.routes = BTreeMap::from([
        ("default".into(), HandlerV1::Skip),
        ("source_article".into(), HandlerV1::DocumentItem),
        ("admitted_article".into(), HandlerV1::DocumentItem),
    ]);
    crawl.extensions.dataset = Some("items".into());
    crawl.datasets.stores.push(
        serde_json::from_value(serde_json::json!({
            "name": "items", "schemaVersion": "document_item_v1",
            "maxItems": 10, "maxBytes": 1_000_000
        }))
        .unwrap(),
    );
    let mut initial = RequestEnvelopeV1::get(canonical(common::SEED), 0, None);
    initial.route = "source_article".into();
    let mut replacement = RequestEnvelopeV1::get(canonical("https://example.test/replacement"), 0, None);
    replacement.route = "admitted_article".into();
    crawl.extensions.extensions.push(ExtensionSpecV1::new(
        ExtensionConfigV1::ReplaceRequest {
            request: Box::new(replacement.clone()),
        },
        0,
    ));
    let mut record = common::authorization::verified_record(&crawl, stores.tenant);
    record.robots_override_acknowledged = true;
    let final_url = "https://example.test/settled";
    let page = FakePage::new(final_url)
        .title("River report")
        .html(include_str!("../../crawlx-bench/fixtures/ext-article/main.html"))
        .redirect_from([replacement.url.url.as_str()])
        .node(FakeAxSpec::button("save", "Save"))
        .on_click(
            "save",
            vec![FakeEffect::SetStorage(BTreeMap::from([(
                "saved".into(),
                "true".into(),
            )]))],
        );
    let mut script = FakeScript::new().page(page.clone());
    // Acquisition addresses the replacement URL, but the admitted response settles elsewhere.
    // Matching descriptors against the settled base would miss this route and select Skip.
    script.pages.insert(replacement.url.url.to_string(), page);
    let fake = Arc::new(FakeBackend::new(script));
    let backend = Arc::new(OpsBackend {
        fake: fake.clone(),
        ops: Ops::new(Behavior::default()),
    });
    let core =
        common::rig_core_authorized(stores, dir, backend, fake, crawl, record, Some(initial.clone())).await;
    core.handle
        .shutdown(crawlx_worker::actor::ShutdownReason::Completed)
        .await
        .unwrap();
    core.stores
        .runs
        .set_session_status(core.session, SessionStatus::Pending)
        .await
        .unwrap();
    let lease = crawlx_scheduler::Scheduler::new(core.stores.leases.clone())
        .lease_in_run(core.run, core.rc.worker, false)
        .await
        .unwrap()
        .unwrap();
    let digest = crawlx_core::hash::Digest::of("route-fixture-binding", b"fake-browser");
    let identity = crawlx_core::session_binding::SessionIdentityV1::new(
        core.stores.tenant,
        &lease.session,
        digest,
        digest,
        digest,
        digest,
        None,
    );
    let expiry = core.rc.budget.lock().deadline();
    let mut config = core.rc.session_config(&lease.session);
    config.context.session_binding = Some(crawlx_core::session_binding::SessionBindingV1::new(
        identity.clone(),
        lease.fencing_token,
        expiry,
    ));
    let pooled = core
        .rc
        .pool
        .acquire(config.context.clone(), config.exclusive_browser)
        .await
        .unwrap();
    let analyzer = Arc::new(crawlx_worker::StateAnalyzer::new(
        core.run,
        core.session,
        core.rc.clusters.clone(),
        core.stores.artifacts.clone(),
        core.rc.clock.clone(),
        core.rc.crawl.capture.clone(),
        (&core.rc.controls, &core.rc.captcha_secrets),
    ));
    let handle = crawlx_worker::actor::SessionActor::spawn(config, core.rc.services(), analyzer, 7, pooled)
        .await
        .unwrap();
    let r = common::Rig {
        store,
        stores: core.stores,
        backend: core.backend,
        rc: core.rc,
        handle,
        run: core.run,
        session: core.session,
        principal: core.principal,
        dir: core.dir,
        flaky: None,
    };
    let nav = r.handle.navigate(initial).await.unwrap();
    assert_eq!(nav.final_url, final_url);
    assert_eq!(nav.redirects, vec![replacement.url.url.to_string()]);
    let bundle = r
        .handle
        .observe(crawlx_observe::spec::after_action())
        .await
        .unwrap();
    let state = crawlx_worker::StateAnalyzer::new(
        r.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    )
    .analyze(&bundle)
    .await
    .state;
    r.stores.states.put_state(&state).await.unwrap();
    let cluster = state.cluster;
    let (proposal, facts) = r.proposal(&bundle, "Save", cluster);
    let out = r
        .handle
        .execute(r.admit(proposal, &facts), QuiescencePolicy::default())
        .await
        .unwrap();
    assert_eq!(out.status, ActionStatus::Succeeded);
    assert!(out.error.is_none(), "{:?}", out.error);
    let items = r.stores.datasets.items(r.run, "items", 0, 10).await.unwrap();
    assert_eq!(
        items.len(),
        1,
        "the admitted non-default handler must run after redirect"
    );
    assert_eq!(items[0].source_action, Some(out.action_id));

    let checkpoint = r
        .handle
        .checkpoint(crawlx_scheduler::CheckpointReason::CadenceActions)
        .await
        .unwrap();
    r.handle
        .shutdown(crawlx_worker::actor::ShutdownReason::Completed)
        .await
        .unwrap();
    let session = r.stores.runs.list_sessions(r.run).await.unwrap().remove(0);
    let mut config = r.rc.session_config(&session);
    config.context.session_binding = Some(crawlx_core::session_binding::SessionBindingV1::new(
        identity,
        lease.fencing_token,
        expiry,
    ));
    let pooled =
        r.rc.pool
            .acquire(config.context.clone(), config.exclusive_browser)
            .await
            .unwrap();
    let analyzer = Arc::new(crawlx_worker::StateAnalyzer::new(
        r.run,
        r.session,
        r.rc.clusters.clone(),
        r.stores.artifacts.clone(),
        r.rc.clock.clone(),
        r.rc.crawl.capture.clone(),
        (&r.rc.controls, &r.rc.captcha_secrets),
    ));
    let restored_actor =
        crawlx_worker::actor::SessionActor::spawn(config, r.rc.services(), analyzer, 7, pooled)
            .await
            .unwrap();
    // A new actor has no in-memory route to reuse. The encrypted checkpoint owns this label.
    let restored = restored_actor.restore(checkpoint).await.unwrap();
    assert_eq!(restored.request_route.as_deref(), Some("admitted_article"));
    assert_eq!(restored.navigation.unwrap().final_url, final_url);
    restored_actor
        .shutdown(crawlx_worker::actor::ShutdownReason::Completed)
        .await
        .unwrap();
}

async fn render_at(rig: &FakeRig, url: &str, options: &ScrapeOptions) -> Result<Rendered, RenderError> {
    let url = Url::parse(url).unwrap();
    let request = crawlx_core::request::RequestEnvelopeV1::get(
        crawlx_url::Canonicalizer::canonicalize_url(&url, &Default::default()).unwrap(),
        0,
        None,
    );
    rig.renderer
        .render(&RenderRequest {
            request: &request,
            options,
        })
        .await
}

async fn render_lab(rig: &FakeRig, options: &ScrapeOptions) -> Result<Rendered, RenderError> {
    render_at(rig, "https://example.test/", options).await
}

/// Journal rows of the run as `(kind, strategy)`, in proposal order.
async fn journal(stores: &Stores, run: CrawlRunId) -> Vec<(ActionKind, String, ActionStatus)> {
    stores
        .journal
        .list(run, None)
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.key.action_kind, r.strategy, r.status))
        .collect()
}

async fn scrape_events(stores: &Stores, run: CrawlRunId) -> Vec<Value> {
    stores
        .events
        .list_after(run, 0, 1_000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "scrape.action")
        .map(|e| e.payload)
        .collect()
}

fn assert_released(rig: &FakeRig) {
    assert_eq!(
        rig.rc.pool.available_contexts(),
        rig.rc.pool.context_capacity(),
        "every pooled context is back"
    );
}

#[tokio::test]
async fn a_render_without_an_egress_proxy_is_refused_unless_scripted() {
    let (rig, fake, _) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    let strict = BrowserRenderer::new(Arc::clone(&rig.rc));
    let url = Url::parse("https://example.test/").unwrap();
    let request = crawlx_core::request::RequestEnvelopeV1::get(
        crawlx_url::Canonicalizer::canonicalize_url(&url, &Default::default()).unwrap(),
        0,
        None,
    );
    let o = options(json!({}));
    let err = strict
        .render(&RenderRequest {
            request: &request,
            options: &o,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, RenderError::Unavailable(_)), "{err:?}");
    assert_eq!(fake.open_contexts(), 0, "nothing was opened");
    assert!(rig
        .stores
        .runs
        .list_sessions(rig.rc.run)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn emulation_and_blocking_are_applied_before_the_navigation() {
    let (rig, fake, ops) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    let o = options(json!({
        "mobile": true,
        "blockAds": true,
        "location": {"country": "DE", "languages": ["de-DE", "en"]}
    }));
    let rendered = render_lab(&rig, &o).await.unwrap();
    assert_eq!(
        ops.log(),
        [
            "page_op:emulate",
            "page_op:block_urls",
            "navigate:https://example.test/",
            "page_op:document_response",
            "page_op:html"
        ]
    );
    let emulations = ops.emulations.lock().clone();
    assert_eq!(emulations.len(), 1, "one merged emulation");
    let em = &emulations[0];
    assert!(em.mobile);
    assert_eq!(em.viewport, Some((390, 844)));
    assert_eq!(em.user_agent.as_deref(), Some(MOBILE_USER_AGENT));
    assert_eq!(em.accept_language.as_deref(), Some("de-DE,en"));
    assert_eq!(em.locale.as_deref(), Some("de-DE"));
    assert_eq!(em.timezone.as_deref(), Some("Europe/Berlin"));
    let blocked = fake.context_handles().remove(0).blocked_url_patterns();
    let page = Url::parse("https://example.test/").unwrap();
    assert_eq!(blocked, crawlx_extract::blocklist::patterns_for(&page));
    assert!(!blocked.is_empty());
    assert!(rendered.html.contains("<h1>Lab</h1>"));
    assert_eq!(rendered.status, 200);
    assert_eq!(rendered.content_type.as_deref(), Some("text/html"));
    assert_eq!(rendered.final_url.as_str(), "https://example.test/");
    assert_released(&rig);
}

#[tokio::test]
async fn without_mobile_location_or_block_ads_nothing_is_emulated_or_blocked() {
    let (rig, _, ops) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    render_lab(&rig, &options(json!({"blockAds": false})))
        .await
        .unwrap();
    assert_eq!(
        ops.log(),
        [
            "navigate:https://example.test/",
            "page_op:document_response",
            "page_op:html"
        ]
    );
}

#[tokio::test]
async fn a_context_that_cannot_emulate_makes_the_render_unavailable_and_still_releases() {
    let fake = Arc::new(FakeBackend::new(lab_script()));
    let rig = fake_rig(
        Arc::clone(&fake) as Arc<dyn BrowserBackend>,
        SafetyProfile::ReadOnly,
    )
    .await;
    let err = render_lab(&rig, &options(json!({"mobile": true})))
        .await
        .unwrap_err();
    assert!(matches!(err, RenderError::Unavailable(_)), "{err:?}");
    assert_eq!(fake.open_contexts(), 0);
    assert_released(&rig);
    let sessions = rig.stores.runs.list_sessions(rig.rc.run).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, SessionStatus::Failed);
}

#[tokio::test]
async fn navigation_failures_map_to_navigation_and_egress_errors() {
    let nav = Behavior {
        nav_error: Some(|| BrowserError::Navigation("net::ERR_NAME_NOT_RESOLVED".to_owned())),
        ..Behavior::default()
    };
    let (rig, _, _) = scripted(nav, SafetyProfile::ReadOnly).await;
    let err = render_lab(&rig, &options(json!({"blockAds": false})))
        .await
        .unwrap_err();
    assert!(matches!(err, RenderError::Navigation(_)), "{err:?}");
    assert_released(&rig);

    let denied = Behavior {
        nav_error: Some(|| BrowserError::EgressDenied("http://10.0.0.1/".to_owned())),
        ..Behavior::default()
    };
    let (rig, _, _) = scripted(denied, SafetyProfile::ReadOnly).await;
    let err = render_lab(&rig, &options(json!({"blockAds": false})))
        .await
        .unwrap_err();
    assert!(matches!(err, RenderError::EgressDenied(_)), "{err:?}");
    assert_released(&rig);
}

#[tokio::test]
async fn caller_actions_run_in_order_and_are_journaled_under_explicit_actions() {
    let behavior = Behavior {
        groups: BTreeMap::from([(
            ".item".to_owned(),
            vec!["b1".to_owned(), "b2".to_owned(), "b3".to_owned()],
        )]),
        ..Behavior::default()
    };
    let (rig, fake, _) = scripted(behavior, SafetyProfile::TestEnvironment).await;
    let o = options(json!({
        "blockAds": false,
        "actions": [
            {"type": "wait", "selector": "#q"},
            {"type": "click", "selector": "#q"},
            {"type": "write", "text": "s3cret-typed-text"},
            {"type": "press", "key": "Enter"},
            {"type": "click", "selector": ".item", "all": true},
            {"type": "scroll", "direction": "down"},
            {"type": "scroll", "direction": "up", "selector": "#q"},
            {"type": "scrape"},
            {"type": "executeJavascript", "script": "document.title"},
            {"type": "screenshot", "fullPage": true},
            {"type": "pdf", "format": "A4", "landscape": true, "scale": 0.5},
            {"type": "wait", "milliseconds": 5}
        ]
    }));
    let rendered = render_lab(&rig, &o).await.unwrap();

    let rows = journal(&rig.stores, rig.rc.run).await;
    let kinds: Vec<ActionKind> = rows.iter().map(|(k, _, _)| *k).collect();
    assert_eq!(
        kinds,
        [
            ActionKind::Click,
            ActionKind::Keys,
            ActionKind::Keys,
            ActionKind::Click,
            ActionKind::Click,
            ActionKind::Click,
            ActionKind::Scroll,
            ActionKind::Scroll,
        ],
        "one journal row per input action, one click per `all` match"
    );
    assert!(rows
        .iter()
        .all(|(_, s, st)| s == EXPLICIT_ACTIONS_STRATEGY && *st == ActionStatus::Succeeded));
    assert_eq!(fake.context_handles().remove(0).performed(), kinds);

    let events = scrape_events(&rig.stores, rig.rc.run).await;
    let seen: Vec<(u64, &str)> = events
        .iter()
        .map(|e| (e["index"].as_u64().unwrap(), e["type"].as_str().unwrap()))
        .collect();
    assert_eq!(
        seen,
        [
            (0, "wait"),
            (7, "scrape"),
            (8, "executeJavascript"),
            (9, "screenshot"),
            (10, "pdf"),
            (11, "wait")
        ],
        "an event per action the kernel does not gate"
    );
    let script_event = &events[2];
    assert_eq!(script_event["scriptLength"], "document.title".len());
    assert_eq!(script_event["scriptDigest"].as_str().unwrap().len(), 64);

    // the typed text is user data: it reaches no row
    let trail = format!("{:?}", rig.stores.journal.list(rig.rc.run, None).await.unwrap());
    assert!(!trail.contains("s3cret-typed-text"), "{trail}");
    assert!(!events.iter().any(|e| e.to_string().contains("s3cret-typed-text")));

    assert_eq!(rendered.actions.scrapes.len(), 1);
    assert_eq!(rendered.actions.scrapes[0].url, "https://example.test/");
    assert!(rendered.actions.scrapes[0].html.contains("<h1>Lab</h1>"));
    assert_eq!(rendered.actions.javascript_returns.len(), 1);
    assert_eq!(rendered.actions.javascript_returns[0].kind, "object");
    assert_eq!(
        rendered.actions.javascript_returns[0].value,
        json!({"scriptLength": 14})
    );
    assert_eq!(rendered.actions.screenshots.len(), 1);
    assert_eq!(rendered.actions.screenshots[0].content_type, "image/png");
    assert_eq!(rendered.actions.pdfs.len(), 1);
    assert!(rendered.actions.pdfs[0].bytes.starts_with(b"%PDF"));

    let sessions = rig.stores.runs.list_sessions(rig.rc.run).await.unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, SessionStatus::Completed);
    assert_eq!(sessions[0].role.0, "scrape");
    assert!(
        sessions[0].browser.is_some(),
        "the actor recorded the browser build"
    );
    assert_released(&rig);
}

#[tokio::test]
async fn the_screenshot_format_is_captured_after_the_actions() {
    let (rig, _, ops) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    let o = options(json!({
        "blockAds": false,
        "formats": [{"type": "markdown"}, {"type": "screenshot", "fullPage": true, "quality": 70}]
    }));
    let rendered = render_lab(&rig, &o).await.unwrap();
    assert!(rendered.screenshot.is_some());
    assert_eq!(ops.log().last().unwrap(), "page_op:screenshot");
    let without = render_lab(&rig, &options(json!({"blockAds": false})))
        .await
        .unwrap();
    assert!(without.screenshot.is_none());
}

#[tokio::test]
async fn the_kernel_denies_a_destructive_click_and_journals_the_verdict() {
    for profile in [SafetyProfile::ReadOnly, SafetyProfile::TestEnvironment] {
        let (rig, fake, _) = scripted(Behavior::default(), profile).await;
        let o = options(json!({
            "blockAds": false,
            "actions": [{"type": "click", "selector": "#danger"}]
        }));
        let err = render_lab(&rig, &o).await.unwrap_err();
        match err {
            RenderError::Action { index, kind, reason } => {
                assert_eq!(
                    (index, kind, reason.as_str()),
                    (0, "click", "denied"),
                    "{profile:?}"
                );
            }
            other => panic!("{profile:?}: {other:?}"),
        }
        assert!(
            fake.context_handles().remove(0).performed().is_empty(),
            "nothing reached the page"
        );
        let rows = journal(&rig.stores, rig.rc.run).await;
        assert_eq!(rows.len(), 1, "the denied proposal is on the journal: {rows:?}");
        assert_eq!(rows[0].0, ActionKind::Click);
        assert_eq!(rows[0].1, EXPLICIT_ACTIONS_STRATEGY);
        assert_released(&rig);
    }
}

#[tokio::test]
async fn the_read_only_profile_refuses_unclassified_input_the_test_profile_allows() {
    let o = options(json!({
        "blockAds": false,
        "actions": [{"type": "press", "key": "Enter"}]
    }));
    let (rig, _, _) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    let err = render_lab(&rig, &o).await.unwrap_err();
    assert!(
        matches!(&err, RenderError::Action { kind: "press", reason, .. } if reason == "denied"),
        "{err:?}"
    );
    let (rig, _, _) = scripted(Behavior::default(), SafetyProfile::TestEnvironment).await;
    render_lab(&rig, &o).await.unwrap();
}

#[tokio::test]
async fn bad_actions_fail_with_a_fixed_reason_and_the_action_index() {
    let behavior = Behavior::default();
    let (rig, _, _) = scripted(behavior, SafetyProfile::TestEnvironment).await;
    let cases = [
        (
            json!({"type": "click", "selector": "#nope"}),
            "click",
            "selector_not_found",
        ),
        (
            json!({"type": "press", "key": "NoSuchKey"}),
            "press",
            "unknown_key",
        ),
        (
            json!({"type": "wait", "selector": "div[", "state": "hidden"}),
            "wait",
            "invalid_selector",
        ),
        (
            json!({"type": "scroll", "direction": "down", "selector": "#nope"}),
            "scroll",
            "selector_not_found",
        ),
    ];
    for (action, kind, reason) in cases {
        let o = options(json!({"blockAds": false, "actions": [{"type": "wait", "milliseconds": 1}, action]}));
        let err = render_lab(&rig, &o).await.unwrap_err();
        match err {
            RenderError::Action {
                index,
                kind: k,
                reason: r,
            } => assert_eq!((index, k, r.as_str()), (1, kind, reason)),
            other => panic!("{kind}: {other:?}"),
        }
    }
    assert_released(&rig);
}

#[tokio::test]
async fn selector_wait_states_reach_actor_and_use_fake_visibility() {
    let (rig, _, ops) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    let options = options(json!({
        "blockAds": false,
        "actions": [
            {"type": "wait", "selector": "#hidden"},
            {"type": "wait", "selector": "#q", "state": "visible"},
            {"type": "wait", "selector": "#hidden", "state": "hidden"},
            {"type": "wait", "selector": "#missing", "state": "hidden"},
            {"type": "wait", "selector": "#missing", "state": "detached"}
        ]
    }));
    render_lab(&rig, &options).await.unwrap();
    assert_eq!(
        ops.wait_states.lock().as_slice(),
        [
            SelectorState::Attached,
            SelectorState::Visible,
            SelectorState::Hidden,
            SelectorState::Hidden,
            SelectorState::Detached,
        ]
    );
    assert_released(&rig);
}

#[tokio::test]
async fn cancelling_selector_state_wait_releases_context() {
    let (rig, fake, ops) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    let cancel = rig.cancel.clone();
    let seen = Arc::clone(&ops);
    let cancellation = tokio::spawn(async move {
        for _ in 0..1000 {
            if !seen.wait_states.lock().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cancel.cancel();
    });
    let options = options(json!({
        "blockAds": false,
        "actions": [{"type": "wait", "selector": "#hidden", "state": "visible"}]
    }));
    let started = std::time::Instant::now();
    let error = render_lab(&rig, &options).await.unwrap_err();
    cancellation.await.unwrap();
    assert!(matches!(error, RenderError::Cancelled), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(ops.wait_states.lock().first(), Some(&SelectorState::Visible));
    assert_eq!(fake.open_contexts(), 0);
    assert_released(&rig);
}

#[tokio::test]
async fn a_selector_that_never_appears_ends_the_wait_at_the_thirty_second_cap() {
    let behavior = Behavior::default();
    let (rig, _, _) = scripted(behavior, SafetyProfile::ReadOnly).await;
    let o = options(json!({"blockAds": false, "actions": [{"type": "wait", "selector": "#late"}]}));
    let started = std::time::Instant::now();
    let err = render_lab(&rig, &o).await.unwrap_err();
    assert!(
        matches!(&err, RenderError::Action { index: 0, kind: "wait", reason } if reason == "selector_timeout"),
        "{err:?}"
    );
    let waited = started.elapsed();
    assert!(
        waited >= Duration::from_secs(30) && waited < Duration::from_secs(40),
        "{waited:?}"
    );
    assert_released(&rig);
}

#[tokio::test]
async fn a_slow_page_times_out_and_releases_its_context() {
    let behavior = Behavior {
        nav_delay: Duration::from_secs(3),
        ..Behavior::default()
    };
    let (rig, fake, _) = scripted(behavior, SafetyProfile::ReadOnly).await;
    let o = options(json!({"blockAds": false, "timeoutMs": 1000}));
    let started = std::time::Instant::now();
    let err = render_lab(&rig, &o).await.unwrap_err();
    assert!(matches!(err, RenderError::Timeout(1000)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(fake.open_contexts(), 0, "the context was closed");
    assert_released(&rig);
    let sessions = rig.stores.runs.list_sessions(rig.rc.run).await.unwrap();
    assert_eq!(sessions[0].status, SessionStatus::Failed);
}

#[tokio::test]
async fn cancelling_the_run_aborts_the_render_and_releases_its_context() {
    let behavior = Behavior {
        nav_delay: Duration::from_secs(3),
        ..Behavior::default()
    };
    let (rig, fake, _) = scripted(behavior, SafetyProfile::ReadOnly).await;
    let cancel = rig.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
    });
    let started = std::time::Instant::now();
    let err = render_lab(&rig, &options(json!({"blockAds": false})))
        .await
        .unwrap_err();
    assert!(matches!(err, RenderError::Cancelled), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(fake.open_contexts(), 0);
    assert_released(&rig);
    let sessions = rig.stores.runs.list_sessions(rig.rc.run).await.unwrap();
    assert_eq!(sessions[0].status, SessionStatus::Cancelled);
}

#[tokio::test]
async fn pages_of_other_origins_get_a_kernel_for_their_own_origin() {
    // the run's seed is example.test; the page is on another origin: its own links are in scope
    let script = FakeScript::new()
        .page(
            FakePage::new("https://other.test/")
                .html("<html>other</html>")
                .node(FakeAxSpec::link("next", "Next page", "https://other.test/next"))
                .on_click(
                    "next",
                    vec![FakeEffect::Navigate("https://other.test/next".to_owned())],
                ),
        )
        .page(FakePage::new("https://other.test/next").html("<html>next page</html>"));
    let fake = Arc::new(FakeBackend::new(script));
    let backend = Arc::new(OpsBackend {
        fake: Arc::clone(&fake),
        ops: Ops::new(Behavior::default()),
    });
    let rig = fake_rig(backend, SafetyProfile::ReadOnly).await;
    let o = options(json!({"blockAds": false, "actions": [{"type": "click", "selector": "#next"}]}));
    // the click is admitted only because the kernel of this render is built for other.test:
    // under the run's own kernel the page is outside the seed's scope and every action is denied
    let page = render_at(&rig, "https://other.test/", &o).await.unwrap();
    assert_eq!(page.final_url.as_str(), "https://other.test/next");
    assert!(page.html.contains("next page"));
    let rows = journal(&rig.stores, rig.rc.run).await;
    assert_eq!(
        rows,
        [(
            ActionKind::Click,
            EXPLICIT_ACTIONS_STRATEGY.to_owned(),
            ActionStatus::Succeeded
        )]
    );
    assert_released(&rig);
}

// ---------------------------------------------------------------------------------------------
// Chromium
// ---------------------------------------------------------------------------------------------

const LAB: &str = r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Lab</title>
<style>body{margin:0;font:16px sans-serif}.spacer{height:3000px}</style></head><body>
<h1>Lab</h1>
<button class="add" onclick="add(1)">Item 1</button>
<button class="add" onclick="add(2)">Item 2</button>
<button class="add" onclick="add(3)">Item 3</button>
<input id="q" type="text" aria-label="Query">
<div id="echo"></div>
<ul id="log"></ul>
<a id="next" href="/static">Next page</a>
<a id="meta" href="http://meta.site.test:PORT/">Metadata</a>
<button id="danger" onclick="fetch('/delete',{method:'POST'})">Delete account</button>
<img src="http://googleads.g.doubleclick.net/pixel" width="1" height="1" alt="">
<div class="spacer"></div>
<div id="sentinel"></div>
<div id="lazy"></div>
<script>
function add(n){var li=document.createElement('li');li.className='clicked';li.textContent='item '+n;document.getElementById('log').appendChild(li);}
var q=document.getElementById('q');
q.addEventListener('input',function(){document.getElementById('echo').textContent=q.value;});
q.addEventListener('keydown',function(e){if(e.key==='Enter'){var li=document.createElement('li');li.className='enter';li.textContent='ENTER';document.getElementById('log').appendChild(li);}});
new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting&&!window.__lazy){window.__lazy=1;fetch('/lazy').then(function(r){return r.text();}).then(function(t){var d=document.createElement('div');d.className='loaded';d.textContent=t;document.getElementById('lazy').appendChild(d);});}});}).observe(document.getElementById('sentinel'));
</script></body></html>"##;

const WAITER: &str = r##"<!doctype html><html><body><h1>Waiter</h1><div id="late"></div>
<script>setTimeout(function(){document.getElementById('late').textContent='LATE-CONTENT';},2500);</script></body></html>"##;

/// What the fixture server saw.
#[derive(Default)]
struct Seen {
    lazy: AtomicUsize,
    deletes: AtomicUsize,
    /// `(Accept-Language, User-Agent)` of every `/lab` request.
    lab: Mutex<Vec<(Option<String>, Option<String>)>>,
}

struct Fixture {
    seen: Arc<Seen>,
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn page(body: String) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body)
}

async fn fixture() -> Fixture {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Seen::default());
    let lab_page = LAB.replace("PORT", &port.to_string());
    let app = axum::Router::new()
        .route("/robots.txt", get(|| async { "User-agent: *\nAllow: /\n" }))
        .route(
            "/lab",
            get(move |State(s): State<Arc<Seen>>, headers: HeaderMap| {
                let text = |name: header::HeaderName| {
                    headers.get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
                };
                s.lab
                    .lock()
                    .push((text(header::ACCEPT_LANGUAGE), text(header::USER_AGENT)));
                let body = lab_page.clone();
                async move { page(body) }
            }),
        )
        .route("/wait", get(|| async { page(WAITER.to_owned()) }))
        .route(
            "/virtual",
            get(|| async {
                page(include_str!("../../crawlx-browser/tests/fixtures/virtual_rows.html").to_owned())
            }),
        )
        .route(
            "/static",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                        (header::HeaderName::from_static("x-fixture"), "yes"),
                    ],
                    "<!doctype html><html><body><h1>Static</h1></body></html>",
                )
            }),
        )
        .route(
            "/missing",
            get(|| async {
                (
                    StatusCode::NOT_FOUND,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    "<html><body>gone</body></html>",
                )
            }),
        )
        .route(
            "/lazy",
            get(|State(s): State<Arc<Seen>>| async move {
                s.lazy.fetch_add(1, Ordering::SeqCst);
                "LAZY-LOADED"
            }),
        )
        .route(
            "/delete",
            post(|State(s): State<Arc<Seen>>| async move {
                s.deletes.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }),
        )
        .with_state(Arc::clone(&seen));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Fixture { seen, port, task }
}

/// A run over real Chromium reached through the egress proxy.
struct Rig {
    rc: Arc<RunContext>,
    stores: Stores,
    renderer: BrowserRenderer,
    fx: Fixture,
    proxy: EgressProxyHandle,
    _dir: tempfile::TempDir,
}

async fn rig(profile: SafetyProfile) -> Option<Rig> {
    if std::env::var_os("CRAWLX_CHROMIUM_PATH").is_none() {
        eprintln!("skipped: CRAWLX_CHROMIUM_PATH is not set");
        return None;
    }
    let exe = crawlx_browser::launch::find_executable()?;
    let fx = fixture().await;
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let crawl = crawl_for(&format!("http://site.test:{}/lab", fx.port), profile);
    let mut record = authorization_fixture::verified_record(&crawl, stores.tenant);
    for host in ["other.test", "googleads.g.doubleclick.net", "meta.site.test"] {
        let mut target = crawl.seed_url.clone();
        target.set_host(Some(host)).unwrap();
        record.origins.push(target.origin().ascii_serialization());
    }
    let stores =
        stores.with_authorization_source(Arc::new(crawlx_worker::StaticAuthorizationSource::new(record)));
    let run = create_run(&stores, &crawl).await;
    let resolver = Arc::new(
        StaticResolver::new()
            .with("site.test", [lo()])
            .with("other.test", [lo()])
            .with("googleads.g.doubleclick.net", [lo()])
            .with("meta.site.test", [IpAddr::from([169, 254, 169, 254])]),
    );
    let mut cfg = WorkerConfig {
        artifacts_dir: dir.path().to_path_buf(),
        egress: EgressConfig {
            resolver: Some(resolver),
            ..EgressConfig::default()
        },
        ..WorkerConfig::default()
    };
    cfg.launch.executable = exe;
    cfg.launch.allow_unpinned = true;
    if std::env::var("CRAWLX_UNSAFE_NO_SANDBOX_FOR_CI").is_err() && std::env::var_os("CI").is_none() {
        cfg.launch.unsafe_no_sandbox_for_ci = std::env::var("USER").map_or(true, |u| u == "root");
    }
    let policy = Arc::new(cfg.egress.policy_for(&crawl));
    let proxy = EgressProxy::serve(policy, cfg.egress.resolver().unwrap())
        .await
        .unwrap();
    let authorization = authorization_fixture::admit(&stores, &run, &cfg).await;
    let rc = Arc::new(
        RunContext::build(
            &run,
            &cfg,
            stores.clone(),
            None,
            None,
            CancellationToken::new(),
            Some(&proxy),
            Some(authorization),
        )
        .await
        .unwrap(),
    );
    Some(Rig {
        renderer: BrowserRenderer::new(Arc::clone(&rc)),
        rc,
        stores,
        fx,
        proxy,
        _dir: dir,
    })
}

impl Rig {
    fn url(&self, host: &str, path: &str) -> Url {
        Url::parse(&format!("http://{host}:{}{path}", self.fx.port)).unwrap()
    }

    async fn render_url(&self, url: &Url, o: &ScrapeOptions) -> Result<Rendered, RenderError> {
        let request = crawlx_core::request::RequestEnvelopeV1::get(
            crawlx_url::Canonicalizer::canonicalize_url(url, &Default::default()).unwrap(),
            0,
            None,
        );
        self.renderer
            .render(&RenderRequest {
                request: &request,
                options: o,
            })
            .await
    }

    async fn render(&self, path: &str, o: &ScrapeOptions) -> Result<Rendered, RenderError> {
        let url = self.url("site.test", path);
        self.render_url(&url, o).await
    }

    fn assert_released(&self) {
        assert_eq!(self.rc.pool.available_contexts(), self.rc.pool.context_capacity());
    }
}

/// Width and height of a PNG from its IHDR.
fn png_size(bytes: &[u8]) -> (u32, u32) {
    assert!(bytes.starts_with(b"\x89PNG\r\n\x1a\n"), "not a PNG");
    let be = |at: usize| u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
    (be(16), be(20))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_reports_status_headers_and_content_type_of_the_main_document() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let o = options(json!({"blockAds": false}));
    let page = rig.render("/static", &o).await.unwrap();
    assert_eq!(page.status, 200);
    assert_eq!(page.content_type.as_deref(), Some("text/html"));
    assert!(
        page.headers.contains(&("x-fixture".to_owned(), "yes".to_owned())),
        "{:?}",
        page.headers
    );
    assert!(page.html.contains("<h1>Static</h1>"));
    assert_eq!(page.final_url.path(), "/static");
    assert!(page.screenshot.is_none());

    let missing = rig.render("/missing", &o).await.unwrap();
    assert_eq!(missing.status, 404, "an error status is a page, not an error");
    assert!(missing.html.contains("gone"));
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_wait_for_delays_the_capture_of_js_inserted_content() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let early = rig
        .render("/wait", &options(json!({"blockAds": false, "mobile": true})))
        .await
        .unwrap();
    // the timer's source text is in the page either way; its effect is the filled element
    assert!(
        early.html.contains(r#"<div id="late"></div>"#),
        "the page settled before the timer"
    );
    let late = rig
        .render("/wait", &options(json!({"blockAds": false, "waitForMs": 3500})))
        .await
        .unwrap();
    assert!(
        late.html.contains(r#"<div id="late">LATE-CONTENT</div>"#),
        "waitFor held the capture back"
    );
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_runs_every_action_type_in_order() {
    let Some(rig) = rig(SafetyProfile::TestEnvironment).await else {
        return;
    };
    let o = options(json!({
        "blockAds": false,
        "formats": [{"type": "markdown"}, {"type": "screenshot", "quality": 50}],
        "actions": [
            {"type": "click", "selector": "#q"},
            {"type": "write", "text": "hello world"},
            {"type": "press", "key": "Enter"},
            {"type": "click", "selector": ".add", "all": true},
            {"type": "scroll", "direction": "down"},
            {"type": "scroll", "direction": "down"},
            {"type": "scroll", "direction": "down"},
            {"type": "scroll", "direction": "down"},
            {"type": "scroll", "direction": "down"},
            {"type": "wait", "selector": "#lazy .loaded"},
            {"type": "scrape"},
            {"type": "executeJavascript", "script": "document.querySelectorAll('li.clicked').length"},
            {"type": "executeJavascript", "script": "'text'"},
            {"type": "executeJavascript", "script": "({a: 1})"},
            {"type": "executeJavascript", "script": "[1, 2]"},
            {"type": "executeJavascript", "script": "null"},
            {"type": "executeJavascript", "script": "true"},
            {"type": "screenshot"},
            {"type": "screenshot", "fullPage": true},
            {"type": "screenshot", "quality": 60, "viewport": {"width": 500, "height": 400}},
            {"type": "pdf", "format": "A4", "landscape": true, "scale": 0.8}
        ]
    }));
    let page = rig.render("/lab", &o).await.unwrap();

    // click all hit the three buttons, write+press reached the focused input, scroll revealed
    // the lazily loaded block
    let scraped = &page.actions.scrapes;
    assert_eq!(scraped.len(), 1);
    assert_eq!(scraped[0].url, rig.url("site.test", "/lab").to_string());
    let html = &scraped[0].html;
    assert_eq!(html.matches(r#"class="clicked""#).count(), 3, "{html}");
    assert!(html.contains(r#"<div id="echo">hello world</div>"#), "{html}");
    assert!(html.contains(r#"<li class="enter">ENTER</li>"#), "{html}");
    assert!(html.contains("LAZY-LOADED"), "{html}");
    assert_eq!(rig.fx.seen.lazy.load(Ordering::SeqCst), 1);
    assert!(page.html.contains("LAZY-LOADED") && page.html.contains("hello world"));

    let js: Vec<(&str, &Value)> = page
        .actions
        .javascript_returns
        .iter()
        .map(|r| (r.kind.as_str(), &r.value))
        .collect();
    assert_eq!(
        js,
        [
            ("number", &json!(3)),
            ("string", &json!("text")),
            ("object", &json!({"a": 1})),
            ("array", &json!([1, 2])),
            ("null", &Value::Null),
            ("boolean", &json!(true)),
        ]
    );

    // screenshot action 1: viewport PNG; 2: full page PNG, taller; 3: JPEG
    let shots = &page.actions.screenshots;
    assert_eq!(shots.len(), 3);
    assert_eq!(shots[0].content_type, "image/png");
    let (w0, h0) = png_size(&shots[0].bytes);
    assert_eq!((w0, h0), (1280, 800));
    assert_eq!(shots[1].content_type, "image/png");
    let (w1, h1) = png_size(&shots[1].bytes);
    assert_eq!(w1, 1280);
    assert!(h1 > 3000, "full page height {h1}");
    assert_eq!(shots[2].content_type, "image/jpeg");
    assert!(shots[2].bytes.starts_with(&[0xFF, 0xD8, 0xFF]));
    // the `screenshot` format: a JPEG of the viewport after the actions
    let format_shot = page.screenshot.as_ref().unwrap();
    assert_eq!(format_shot.content_type, "image/jpeg");
    assert!(format_shot.bytes.starts_with(&[0xFF, 0xD8, 0xFF]));

    assert_eq!(page.actions.pdfs.len(), 1);
    assert_eq!(page.actions.pdfs[0].content_type, "application/pdf");
    assert!(page.actions.pdfs[0].bytes.starts_with(b"%PDF"));

    // journal: explicit_actions rows for click, keys and scroll only
    let rows = journal(&rig.stores, rig.rc.run).await;
    let kinds: Vec<ActionKind> = rows.iter().map(|(k, _, _)| *k).collect();
    let mut expected = vec![ActionKind::Click, ActionKind::Keys, ActionKind::Keys];
    expected.extend([ActionKind::Click; 3]);
    expected.extend([ActionKind::Scroll; 5]);
    assert_eq!(kinds, expected);
    assert!(rows
        .iter()
        .all(|(_, s, st)| s == EXPLICIT_ACTIONS_STRATEGY && *st == ActionStatus::Succeeded));
    let events = scrape_events(&rig.stores, rig.rc.run).await;
    let types: Vec<&str> = events.iter().map(|e| e["type"].as_str().unwrap()).collect();
    let mut expected_types = vec!["wait", "scrape"];
    expected_types.extend(["executeJavascript"; 6]);
    expected_types.extend(["screenshot"; 3]);
    expected_types.push("pdf");
    assert_eq!(types, expected_types);
    let trail = format!(
        "{:?}{:?}",
        rig.stores.journal.list(rig.rc.run, None).await.unwrap(),
        events
    );
    assert!(
        !trail.contains("hello world"),
        "typed text never reaches the journal"
    );
    assert_eq!(rig.fx.seen.deletes.load(Ordering::SeqCst), 0);
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_mobile_emulation_is_visible_to_the_page_and_the_server() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let o = options(json!({
        "blockAds": false,
        "mobile": true,
        "actions": [{
            "type": "executeJavascript",
            "script": "({ua: navigator.userAgent, width: window.innerWidth, touch: navigator.maxTouchPoints})"
        }]
    }));
    let page = rig.render("/lab", &o).await.unwrap();
    let env = &page.actions.javascript_returns[0].value;
    assert_eq!(env["ua"], MOBILE_USER_AGENT);
    assert_eq!(env["width"], 390);
    assert!(env["touch"].as_u64().unwrap() > 0, "{env}");
    let lab = rig.fx.seen.lab.lock().clone();
    assert_eq!(lab.len(), 1);
    assert_eq!(
        lab[0].1.as_deref(),
        Some(MOBILE_USER_AGENT),
        "the request carries the phone UA"
    );

    let desktop = rig
        .render(
            "/lab",
            &options(json!({"blockAds": false, "actions": [{"type": "executeJavascript", "script": "window.innerWidth"}]})),
        )
        .await
        .unwrap();
    assert_eq!(desktop.actions.javascript_returns[0].value, json!(1280));
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_location_sets_accept_language_locale_and_time_zone() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let o = options(json!({
        "blockAds": false,
        "location": {"country": "JP", "languages": ["ja-JP", "en"]},
        "actions": [{
            "type": "executeJavascript",
            "script": "({lang: navigator.language, langs: navigator.languages, tz: Intl.DateTimeFormat().resolvedOptions().timeZone})"
        }]
    }));
    let page = rig.render("/lab", &o).await.unwrap();
    let env = &page.actions.javascript_returns[0].value;
    assert_eq!(env["lang"], "ja-JP");
    assert_eq!(env["langs"][0], "ja-JP");
    assert_eq!(env["tz"], "Asia/Tokyo");
    let lab = rig.fx.seen.lab.lock().clone();
    assert_eq!(
        lab[0].0.as_deref(),
        Some("ja-JP,en;q=0.9"),
        "the Accept-Language header"
    );

    // a country alone brings its language
    let de = rig
        .render(
            "/lab",
            &options(json!({
                "blockAds": false,
                "location": {"country": "DE"},
                "actions": [{"type": "executeJavascript", "script": "navigator.language"}]
            })),
        )
        .await
        .unwrap();
    assert_eq!(de.actions.javascript_returns[0].value, json!("de-DE"));
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_block_ads_cancels_tracker_requests() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let tracker = Url::parse("http://googleads.g.doubleclick.net/pixel").unwrap();
    assert!(
        crawlx_extract::blocklist::is_blocked_for(&Url::parse("http://site.test/").unwrap(), &tracker),
        "the fixture tracker must be on the blocklist"
    );
    let tracker_dialed = |rig: &Rig| {
        rig.proxy
            .dialed_hosts()
            .iter()
            .any(|(host, _)| host == "googleads.g.doubleclick.net")
    };
    let blocked = rig
        .render("/lab", &options(json!({"blockAds": true, "waitForMs": 800})))
        .await
        .unwrap();
    assert!(blocked.html.contains("<h1>Lab</h1>"));
    assert!(
        !tracker_dialed(&rig),
        "the blocked request never left the browser: {:?}",
        rig.proxy.dialed_hosts()
    );
    let open = rig
        .render("/lab", &options(json!({"blockAds": false, "waitForMs": 800})))
        .await
        .unwrap();
    assert!(open.html.contains("<h1>Lab</h1>"));
    assert!(tracker_dialed(&rig), "without blockAds the tracker is requested");
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_read_only_profile_denies_destructive_and_unclassified_clicks_but_not_links() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let click = |selector: &str| {
        options(json!({"blockAds": false, "actions": [{"type": "click", "selector": selector}]}))
    };
    for selector in ["#danger", ".add"] {
        let err = rig.render("/lab", &click(selector)).await.unwrap_err();
        assert!(
            matches!(&err, RenderError::Action { index: 0, kind: "click", reason } if reason == "denied"),
            "{selector}: {err:?}"
        );
    }
    assert_eq!(rig.fx.seen.deletes.load(Ordering::SeqCst), 0);
    let denied = journal(&rig.stores, rig.rc.run).await;
    assert_eq!(denied.len(), 2);
    assert!(denied
        .iter()
        .all(|(k, s, _)| *k == ActionKind::Click && s == EXPLICIT_ACTIONS_STRATEGY));

    // an in-scope link only reveals: allowed, and the render ends on the page it opened
    let link = rig.render("/lab", &click("#next")).await.unwrap();
    assert_eq!(link.final_url.path(), "/static");
    assert!(link.html.contains("<h1>Static</h1>"));
    // the main document of the *first* navigation is what status and headers describe
    assert_eq!(link.status, 200);
    assert!(!link.headers.iter().any(|(k, _)| k == "x-fixture"));
    let rows = journal(&rig.stores, rig.rc.run).await;
    assert_eq!(rows.last().unwrap().2, ActionStatus::Succeeded);
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_refuses_navigations_the_egress_policy_denies() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let o = options(json!({"blockAds": false}));
    // the page itself resolves to the cloud metadata address
    let err = rig
        .render_url(&rig.url("meta.site.test", "/lab"), &o)
        .await
        .unwrap_err();
    assert!(matches!(err, RenderError::EgressDenied(_)), "{err:?}");

    // a link the kernel admits (same site, subdomain) whose host resolves to a denied address
    let click = options(json!({"blockAds": false, "actions": [{"type": "click", "selector": "#meta"}]}));
    let err = rig.render("/lab", &click).await.unwrap_err();
    assert!(matches!(err, RenderError::EgressDenied(_)), "{err:?}");
    assert!(
        rig.proxy
            .dialed_hosts()
            .iter()
            .all(|(host, _)| host != "meta.site.test"),
        "the denied target must never be dialed: {:?}",
        rig.proxy.dialed_hosts()
    );
    rig.assert_released();
    let sessions = rig.stores.runs.list_sessions(rig.rc.run).await.unwrap();
    assert!(
        sessions.iter().all(|s| s.status == SessionStatus::Failed),
        "{sessions:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_pages_outside_the_seed_origin_are_scraped_under_their_own_kernel() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let o = options(json!({"blockAds": false, "actions": [{"type": "click", "selector": "#next"}]}));
    let page = rig.render_url(&rig.url("other.test", "/lab"), &o).await.unwrap();
    assert_eq!(page.final_url.host_str(), Some("other.test"));
    assert_eq!(page.final_url.path(), "/static");
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_action_errors_carry_fixed_reasons() {
    let Some(rig) = rig(SafetyProfile::TestEnvironment).await else {
        return;
    };
    let cases = [
        (
            json!({"type": "executeJavascript", "script": "throw new Error('boom')"}),
            "script_error",
        ),
        (json!({"type": "pdf", "format": "Z9"}), "invalid"),
        (
            json!({"type": "click", "selector": "#nope"}),
            "selector_not_found",
        ),
        (json!({"type": "press", "key": "NoSuchKey"}), "unknown_key"),
    ];
    for (action, reason) in cases {
        let o = options(json!({"blockAds": false, "actions": [action]}));
        let err = rig.render("/lab", &o).await.unwrap_err();
        assert!(
            matches!(&err, RenderError::Action { index: 0, reason: r, .. } if r == reason),
            "{reason}: {err:?}"
        );
    }
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_times_out_releases_the_context_and_stays_usable() {
    let Some(rig) = rig(SafetyProfile::TestEnvironment).await else {
        return;
    };
    let o = options(json!({
        "blockAds": false,
        "timeoutMs": 1500,
        "actions": [{"type": "wait", "selector": "#never"}]
    }));
    let started = std::time::Instant::now();
    let err = rig.render("/lab", &o).await.unwrap_err();
    assert!(matches!(err, RenderError::Timeout(1500)), "{err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    rig.assert_released();
    // the pool still serves the next render
    let page = rig
        .render("/static", &options(json!({"blockAds": false})))
        .await
        .unwrap();
    assert!(page.html.contains("Static"));
}

fn virtual_options(steps: u8) -> ScrapeOptions {
    options(json!({
        "blockAds": false, "timeoutMs": 30000,
        "actions": [{"type": "collectVirtualRows", "spec": {
            "container": "#virtual", "rows": ".row", "maxSteps": steps, "settleMs": 50,
            "maxRowsPerWindow": 10, "maxRows": 1000, "maxBytes": 65536
        }}, {"type": "executeJavascript", "script":
            "({top:document.querySelector('#virtual').scrollTop,rows:document.querySelectorAll('#virtual .row').length})"}]
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_virtual_rows_native_consumer_captures_final_step_and_journals_scrolls() {
    use crawlx_core::dom_ops::{VirtualRowsRestoration, VirtualRowsStop};
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let rendered = rig.render("/virtual", &virtual_options(2)).await.unwrap();
    let report = &rendered.actions.virtual_rows[0];
    assert_eq!(report.steps, 2);
    assert_eq!(report.windows.len(), 3);
    assert_eq!(report.stop, VirtualRowsStop::StepCap);
    assert_eq!(report.restoration, VirtualRowsRestoration::Restored);
    assert_eq!(report.windows[0].rows[0], "C++");
    assert_eq!(report.windows[0].rows[1], "C#");
    assert!(
        report.windows[2].rows.iter().any(|row| row == "row 19"),
        "final permitted native step must be captured"
    );
    assert_eq!(
        rendered.actions.javascript_returns[0].value,
        json!({"top":50,"rows":10})
    );
    let scrolls = journal(&rig.stores, rig.rc.run).await;
    assert_eq!(scrolls.len(), 2);
    assert!(scrolls
        .iter()
        .all(|(kind, strategy, status)| *kind == ActionKind::Scroll
            && strategy == EXPLICIT_ACTIONS_STRATEGY
            && *status == ActionStatus::Succeeded));
    rig.assert_released();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_virtual_rows_consumer_refuses_missing_ambiguous_and_replaced_containers() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    for selector in ["#missing", "div", "["] {
        let mut request = virtual_options(2);
        let ScrapeAction::CollectVirtualRows { spec } = &mut request.actions[0] else {
            panic!("collection");
        };
        spec.container = selector.into();
        assert!(rig.render("/virtual", &request).await.is_err(), "{selector}");
        rig.assert_released();
    }
    for path in [
        "/virtual?replace=1",
        "/virtual?navigate=1",
        "/virtual?refuseRestore=1",
    ] {
        assert!(rig.render(path, &virtual_options(2)).await.is_err(), "{path}");
        rig.assert_released();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn chromium_virtual_rows_cancellation_closes_active_pin_and_releases_context() {
    let Some(rig) = rig(SafetyProfile::ReadOnly).await else {
        return;
    };
    let stores = rig.stores.clone();
    let run = rig.rc.run;
    let cancel = rig.rc.cancel.clone();
    let cancellation = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if !journal(&stores, run).await.is_empty() {
                    cancel.cancel();
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("collection must reach its journaled native scroll");
    });
    let mut request = virtual_options(100);
    let ScrapeAction::CollectVirtualRows { spec } = &mut request.actions[0] else {
        panic!("collection");
    };
    spec.settle_ms = 1000;
    let result = rig.render("/virtual", &request).await;
    cancellation.await.unwrap();
    assert!(matches!(result, Err(RenderError::Cancelled)), "{result:?}");
    // Context close checks the pinned original offset before releasing its lease.
    rig.assert_released();
}

#[tokio::test]
async fn unsupported_virtual_rows_consumer_fails_without_http_or_script_fallback() {
    let (rig, _, ops) = scripted(Behavior::default(), SafetyProfile::ReadOnly).await;
    let error = render_lab(&rig, &virtual_options(2)).await.unwrap_err();
    assert!(
        matches!(error, RenderError::Browser(_) | RenderError::Unavailable(_)),
        "{error:?}"
    );
    assert!(!ops
        .log
        .lock()
        .iter()
        .any(|entry| entry == "page_op:evaluate_script"));
    assert_released(&rig);
}
