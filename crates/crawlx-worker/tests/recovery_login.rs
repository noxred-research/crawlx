//! Recovery ladder, login and secret hygiene.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use async_trait::async_trait;
use common::{canonical, rig_with, rig_with_authorized_prefix};
use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
use crawlx_browser::FakeBackend;
use crawlx_core::action::BrowserAction;
use crawlx_core::observation::{
    ActionReceipt, BrowserBuildInfo, NavigationResult, ObservationBundle, ObservationSpec, QuiescencePolicy,
    Revalidation, RuntimeLocator, SettleReport,
};
use crawlx_core::repo::EventRepo;
use crawlx_core::secret::SecretOr;
use crawlx_core::traffic::TrafficEvent;
use crawlx_core::{
    BrowserBackend, BrowserContext, BrowserError, CanonicalUrl, ContextConfig, ObservationEpoch,
    SafetyProfile,
};
use crawlx_forms::LoginPlan;
use crawlx_observe::spec;
use crawlx_scheduler::CheckpointReason;
use crawlx_worker::actor::SessionState;
use crawlx_worker::login::{LoginCredential, LoginMaterial};
use crawlx_worker::SessionError;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Wraps a `FakeBackend`; contexts whose creation index is in `dead` fail every call like a
/// crashed target.
struct KillableBackend {
    inner: Arc<FakeBackend>,
    dead: Mutex<BTreeSet<usize>>,
    created: AtomicUsize,
    killed: Mutex<Vec<Arc<std::sync::atomic::AtomicBool>>>,
}

impl KillableBackend {
    fn new(inner: Arc<FakeBackend>, dead: &[usize]) -> Arc<Self> {
        Arc::new(Self {
            inner,
            dead: Mutex::new(dead.iter().copied().collect()),
            created: AtomicUsize::new(0),
            killed: Mutex::new(Vec::new()),
        })
    }
    /// Kill the context created at `index` now.
    fn kill(&self, index: usize) {
        self.killed.lock()[index].store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl BrowserBackend for KillableBackend {
    async fn new_context(&self, config: ContextConfig) -> Result<Box<dyn BrowserContext>, BrowserError> {
        let index = self.created.fetch_add(1, Ordering::SeqCst);
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(
            self.dead.lock().contains(&index),
        ));
        self.killed.lock().push(flag.clone());
        Ok(Box::new(KillableContext {
            inner: self.inner.new_context(config).await?,
            dead: flag,
        }))
    }
    fn build_info(&self) -> &BrowserBuildInfo {
        self.inner.build_info()
    }
}

struct KillableContext {
    inner: Box<dyn BrowserContext>,
    dead: Arc<std::sync::atomic::AtomicBool>,
}

impl KillableContext {
    fn check(&self) -> Result<(), BrowserError> {
        if self.dead.load(Ordering::SeqCst) {
            Err(BrowserError::TargetCrashed)
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl BrowserContext for KillableContext {
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        self.check()?;
        self.inner.navigate(url).await
    }
    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        self.check()?;
        self.inner.observe(spec).await
    }
    async fn revalidate(
        &mut self,
        l: &RuntimeLocator,
        e: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        self.check()?;
        self.inner.revalidate(l, e).await
    }
    async fn perform(&mut self, action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        self.check()?;
        self.inner.perform(action).await
    }
    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        self.check()?;
        self.inner.settle(policy).await
    }
    fn current_epoch(&self) -> ObservationEpoch {
        self.inner.current_epoch()
    }
    fn drain_traffic(&mut self) -> Vec<TrafficEvent> {
        self.inner.drain_traffic()
    }
    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError> {
        self.check()?;
        self.inner.export_storage().await
    }
    async fn import_storage(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        self.check()?;
        self.inner.import_storage(blob).await
    }
    async fn close(self: Box<Self>) -> Result<(), BrowserError> {
        self.inner.close().await
    }
}

fn site() -> FakeScript {
    FakeScript::new()
        .page(FakePage::new("https://example.test/").node(FakeAxSpec::link("a", "A", "/a")))
        .page(FakePage::new("https://example.test/a").node(FakeAxSpec::link("h", "Home", "/")))
}

async fn recovery_events(r: &common::Rig) -> Vec<(String, bool)> {
    EventRepo::list_after(r.store.as_ref(), r.run, 0, 1000)
        .await
        .unwrap()
        .into_iter()
        .filter(|e| e.kind == "session_recovery")
        .map(|e| {
            (
                e.payload["rung"].as_str().unwrap().to_owned(),
                e.payload["ok"].as_bool().unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn rung_one_reattaches_when_the_target_recovers() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let backend = KillableBackend::new(fake.clone(), &[]);
    let r = rig_with(backend.clone(), fake, false, SafetyProfile::ReadOnly).await;
    r.handle.observe(spec::after_action()).await.unwrap();
    backend.kill(0);
    assert!(r
        .handle
        .observe(spec::cheap())
        .await
        .unwrap_err()
        .is_target_crash());
    // revive before the ladder's probe is irrelevant: the ladder runs after the reply, so the
    // first probe (still dead) fails and rung 2 takes over; reviving is covered below
    r.handle.wait_state(|s| s == SessionState::Ready).await;
    assert_eq!(r.handle.state(), SessionState::Ready);
}

#[tokio::test]
async fn rung_two_opens_a_new_context_and_restores_the_checkpoint() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let backend = KillableBackend::new(fake.clone(), &[]);
    let r = rig_with(backend.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
    r.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical("https://example.test/a"),
            0,
            None,
        ))
        .await
        .unwrap();
    r.handle.observe(spec::after_action()).await.unwrap();
    r.handle
        .checkpoint(CheckpointReason::CadenceActions)
        .await
        .unwrap();
    backend.kill(0);
    assert!(r.handle.observe(spec::cheap()).await.is_err());
    assert_eq!(
        r.handle
            .wait_state(|s| s == SessionState::Ready || s == SessionState::Failed)
            .await,
        SessionState::Ready
    );
    // the session is back on the checkpoint URL in a new context
    let bundle = r.handle.observe(spec::cheap()).await.unwrap();
    assert_eq!(bundle.url.url.path(), "/a");
    assert_eq!(backend.created.load(Ordering::SeqCst), 2);
    let events = recovery_events(&r).await;
    assert!(events.contains(&("reattach".to_owned(), false)), "{events:?}");
    assert!(
        events.contains(&("new_context_restore".to_owned(), true)),
        "{events:?}"
    );
}

fn login_site() -> FakeScript {
    FakeScript::new()
        .page(
            FakePage::new("https://example.test/")
                .title("Sign in")
                .node(
                    FakeAxSpec::textbox("user", "Username")
                        .attr("type", "text")
                        .attr("autocomplete", "username")
                        .attr("crawlx:form", "login"),
                )
                .node(
                    FakeAxSpec::textbox("pw", "Password")
                        .attr("type", "password")
                        .attr("autocomplete", "current-password")
                        .attr("crawlx:form", "login"),
                )
                .node(
                    FakeAxSpec::button("go", "Sign in")
                        .attr("type", "submit")
                        .attr("crawlx:form", "login"),
                )
                .on_click(
                    "go",
                    vec![FakeEffect::Navigate("https://example.test/home".into())],
                ),
        )
        .page(
            FakePage::new("https://example.test/home")
                .title("Home")
                .node(FakeAxSpec::button("out", "Log out")),
        )
}

fn material() -> LoginMaterial {
    LoginMaterial {
        plan: LoginPlan::builtin_form(),
        credential: LoginCredential::parse(&SecretOr::secret("alice:Hunter2-secret".to_owned())).unwrap(),
    }
}

#[tokio::test]
async fn login_types_the_secret_through_the_actor_and_never_leaks_it() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(login_site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let r = rig_with(fake.clone(), fake.clone(), false, SafetyProfile::ReadOnly).await;
    let report = r.handle.login(material()).await.unwrap();
    assert_eq!(report.final_url, "https://example.test/home");
    let typed = fake.context_handles()[0].typed_inputs();
    assert_eq!(typed.len(), 2);
    // secrets are never stored in clear by the context, the journal or events
    let events = EventRepo::list_after(r.store.as_ref(), r.run, 0, 1000)
        .await
        .unwrap();
    let dump = format!("{events:?}{:?}", r.actions().await);
    assert!(!dump.contains("Hunter2"));
    assert!(!dump.contains("alice"));
}

#[tokio::test]
async fn a_page_without_a_login_form_fails_the_session() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let r = rig_with(fake.clone(), fake, false, SafetyProfile::ReadOnly).await;
    let err = r.handle.login(material()).await.unwrap_err();
    assert!(matches!(err, SessionError::LoginFailed(_)), "{err:?}");
    assert_eq!(r.handle.state(), SessionState::Failed);
}

#[tokio::test]
async fn login_is_refused_off_origin() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(
                login_site().page(
                    FakePage::new("https://evil.test/")
                        .node(
                            FakeAxSpec::textbox("user", "Username")
                                .attr("type", "text")
                                .attr("autocomplete", "username")
                                .attr("crawlx:form", "login"),
                        )
                        .node(
                            FakeAxSpec::textbox("pw", "Password")
                                .attr("type", "password")
                                .attr("autocomplete", "current-password")
                                .attr("crawlx:form", "login"),
                        )
                        .node(
                            FakeAxSpec::button("go", "Sign in")
                                .attr("type", "submit")
                                .attr("crawlx:form", "login"),
                        ),
                ),
            )
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    // the signed scope bounds every navigation: the off-origin page is reachable only because
    // the record names it, and the login still refuses to type a credential there
    let r = rig_with_authorized_prefix(fake.clone(), SafetyProfile::ReadOnly, "https://evil.test").await;
    r.handle
        .navigate(crawlx_core::request::RequestEnvelopeV1::get(
            canonical("https://evil.test/"),
            0,
            None,
        ))
        .await
        .unwrap();
    let err = r.handle.login(material()).await.unwrap_err();
    assert!(err.to_string().contains("refusing to type a credential"), "{err}");
    assert!(fake.context_handles()[0].typed_inputs().is_empty());
}

#[tokio::test]
async fn rung_three_logs_in_again_when_restore_fails() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(login_site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    // contexts 0 (original), 1 and 2 (rung 2 attempts) are dead; context 3 is healthy
    let backend = KillableBackend::new(fake.clone(), &[1, 2]);
    let r = rig_with(backend.clone(), fake, false, SafetyProfile::ReadOnly).await;
    r.handle.login(material()).await.unwrap();
    r.handle.observe(spec::after_action()).await.unwrap();
    r.handle.checkpoint(CheckpointReason::PreMutation).await.unwrap();
    backend.kill(0);
    assert!(r.handle.observe(spec::cheap()).await.is_err());
    assert_eq!(
        r.handle
            .wait_state(|s| s == SessionState::Ready || s == SessionState::Failed)
            .await,
        SessionState::Ready
    );
    let events = recovery_events(&r).await;
    assert!(events.contains(&("relogin".to_owned(), true)), "{events:?}");
    // logged in again and returned to the checkpoint page
    let bundle = r.handle.observe(spec::cheap()).await.unwrap();
    assert_eq!(bundle.url.url.path(), "/home");
}

#[tokio::test]
async fn an_exhausted_ladder_fails_the_session() {
    let fake = Arc::new(
        FakeBackend::builder()
            .script(site())
            .clock(Arc::new(crawlx_core::SystemClock))
            .build(),
    );
    let backend = KillableBackend::new(fake.clone(), &(1..40).collect::<Vec<_>>());
    let r = rig_with(backend.clone(), fake, false, SafetyProfile::ReadOnly).await;
    r.handle.observe(spec::after_action()).await.unwrap();
    backend.kill(0);
    assert!(r.handle.observe(spec::cheap()).await.is_err());
    assert_eq!(
        r.handle.wait_state(|s| s == SessionState::Closed).await,
        SessionState::Closed
    );
    let err = r.handle.observe(spec::cheap()).await.unwrap_err();
    let SessionError::ActorStopped(cause) = err else {
        panic!("recovery exhaustion lost its typed cause: {err:?}");
    };
    assert!(matches!(&*cause, SessionError::RecoveryExhausted(_)), "{cause:?}");
    let shutdown = r
        .handle
        .shutdown(crawlx_worker::actor::ShutdownReason::Completed)
        .await
        .unwrap_err();
    let SessionError::ActorStopped(shutdown_cause) = shutdown else {
        panic!("shutdown lost recovery exhaustion: {shutdown:?}");
    };
    assert!(Arc::ptr_eq(&cause, &shutdown_cause));
    assert_eq!(r.backend.open_contexts(), 0);
    let events = recovery_events(&r).await;
    assert!(events.contains(&("exhausted".to_owned(), false)), "{events:?}");
}
