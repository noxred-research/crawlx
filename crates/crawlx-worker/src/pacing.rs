//! Shared HTTP/browser admission around every actor context, including login and recovery.

use async_trait::async_trait;
use crawlx_core::action::BrowserAction;
use crawlx_core::dom_ops::{CssFilter, LazyScrollReport, LazyScrollSpec, XhrRecord};
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{
    ActionReceipt, DomSelector, NavigationResult, ObservationBundle, ObservationSpec, QuiescencePolicy,
    Revalidation, RuntimeLocator, SettleReport,
};
use crawlx_core::page_op::{PageOp, PageOpResult};
use crawlx_core::traffic::TrafficEvent;
use crawlx_core::{BlockedNavigation, BrowserContext, BrowserError, CanonicalUrl, StoreError};
use crawlx_fetch::{Origin, OriginGovernor, Permit};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio_util::sync::CancellationToken;

#[must_use]
pub(crate) fn wrap(
    inner: Box<dyn BrowserContext>,
    cfg: &crate::actor::SessionConfig,
    clock: Arc<dyn crawlx_core::Clock>,
) -> (Box<dyn BrowserContext>, PacingHandle) {
    let handle = PacingHandle {
        governor: Arc::clone(&cfg.origin_governor),
        cancel: cfg.origin_cancel.clone(),
        navigation_guard: cfg.context.navigation_guard.clone(),
        clock,
        state: Arc::new(Mutex::new(PacingState {
            deadline: match (
                cfg.context
                    .session_binding
                    .as_ref()
                    .map(|binding| binding.expires_at),
                cfg.execution_deadline,
            ) {
                (Some(binding), Some(execution)) => Some(binding.min(execution)),
                (binding, execution) => binding.or(execution),
            },
            ..PacingState::default()
        })),
    };
    (
        Box::new(PacedContext {
            inner,
            handle: handle.clone(),
        }),
        handle,
    )
}

#[derive(Default)]
struct PacingState {
    deadline: Option<crawlx_core::Timestamp>,
    reserved: bool,
    prepared: Option<Permit>,
    // Keep capacity through quiescence, not just until Page.navigate commits.
    active: Option<Permit>,
}

/// Actor-side admission for the matching context, before its final safety checks.
#[derive(Clone)]
pub(crate) struct PacingHandle {
    governor: Arc<OriginGovernor>,
    cancel: CancellationToken,
    navigation_guard: Option<Arc<dyn crawlx_core::NavigationGuard>>,
    clock: Arc<dyn crawlx_core::Clock>,
    state: Arc<Mutex<PacingState>>,
}

/// An actor action owns its reservation until every finish/error/drop path unwinds.
#[must_use]
pub(crate) struct PreparedAction {
    state: Arc<Mutex<PacingState>>,
    source_origin: Origin,
}

impl PreparedAction {
    pub(crate) fn matches_source(&self, origin: &str) -> bool {
        self.source_origin.as_str() == origin
    }
}

impl Drop for PreparedAction {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.prepared = None;
        state.active = None;
        state.reserved = false;
    }
}

impl PacingHandle {
    fn state(&self) -> MutexGuard<'_, PacingState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn narrow_deadline(&self, deadline: crawlx_core::Timestamp) {
        let mut state = self.state();
        state.deadline = Some(state.deadline.map_or(deadline, |current| current.min(deadline)));
    }

    fn check_deadline(&self) -> Result<(), BrowserError> {
        if self
            .state()
            .deadline
            .is_some_and(|deadline| self.clock.now() >= deadline)
        {
            return Err(BrowserError::SessionExpired);
        }
        Ok(())
    }

    async fn check_navigation(&self, url: &url::Url) -> Result<(), BrowserError> {
        if let Some(guard) = &self.navigation_guard {
            if let Some(reason) = guard.check(url).await.refusal() {
                return Err(BlockedNavigation::new(url.to_string(), reason).into_error());
            }
        }
        Ok(())
    }

    fn end_unprepared(&self) -> Result<(), BrowserError> {
        let mut state = self.state();
        if state.reserved {
            return Err(admission_error("nested effect during prepared actor action"));
        }
        state.active = None;
        Ok(())
    }

    async fn acquire(&self, origin: &Origin) -> Result<Permit, BrowserError> {
        self.check_deadline()?;
        let deadline = self.state().deadline;
        let expiry = async {
            match deadline {
                Some(deadline) => {
                    let remaining = deadline
                        .signed_duration_since(self.clock.now())
                        .to_std()
                        .unwrap_or_default();
                    tokio::time::sleep(remaining).await;
                }
                None => std::future::pending::<()>().await,
            }
        };
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(admission_error("origin admission cancelled")),
            () = expiry => Err(BrowserError::SessionExpired),
            permit = self.governor.acquire_browser(origin) => {
                permit.map_err(BrowserError::OriginAdmission)
            }
        }
    }

    fn dispatch(&self, permit: &mut Permit) -> Result<(), BrowserError> {
        self.check_deadline()?;
        if self.cancel.is_cancelled() {
            return Err(admission_error("origin admission cancelled"));
        }
        permit.commit_dispatch().map_err(BrowserError::OriginAdmission)
    }

    /// Reserve once; final actor probes must run only after this wait completes.
    ///
    /// # Errors
    /// Returns navigation refusal, cancellation, nested admission, or governor failure.
    pub(crate) async fn prepare(
        &self,
        ctx: &mut dyn BrowserContext,
        action: &BrowserAction,
    ) -> Result<PreparedAction, BrowserError> {
        self.end_unprepared()?;
        // Robots may require the same origin's HTTP capacity. Resolve before reserving it.
        if let BrowserAction::Navigate { url } = action {
            self.check_navigation(url).await?;
        }
        let source = ctx.observe(crawlx_observe::spec::cheap()).await?;
        let scope = PreparedAction {
            state: Arc::clone(&self.state),
            source_origin: Origin::from_url(&source.url.url),
        };
        self.state().reserved = true;
        let destination = match action {
            BrowserAction::Navigate { url } => Some(Origin::from_url(url)),
            _ => None,
        };
        let permit = self
            .acquire(destination.as_ref().unwrap_or(&scope.source_origin))
            .await?;
        self.state().prepared = Some(permit);
        Ok(scope)
    }
}

fn admission_error(message: &str) -> BrowserError {
    BrowserError::OriginAdmission(StoreError::Unavailable(message.to_owned()))
}

struct PacedContext {
    inner: Box<dyn BrowserContext>,
    handle: PacingHandle,
}

impl PacedContext {
    async fn admit(&mut self, origin: &Origin) -> Result<Permit, BrowserError> {
        // A new unprepared command closes a previous effect that needed no explicit settle.
        self.handle.end_unprepared()?;
        self.handle.acquire(origin).await
    }

    async fn live_origin(&mut self) -> Result<Origin, BrowserError> {
        let bundle = self.inner.observe(crawlx_observe::spec::cheap()).await?;
        Ok(Origin::from_url(&bundle.url.url))
    }
}

#[async_trait]
impl BrowserContext for PacedContext {
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        // Resolve robots before charging this document. The guard may itself need
        // an HTTP permit for robots.txt, including when origin capacity is one.
        self.handle.end_unprepared()?;
        self.handle.check_navigation(&url.url).await?;
        let mut permit = self.admit(&Origin::from_url(&url.url)).await?;
        self.handle.dispatch(&mut permit)?;
        let result = self.inner.navigate(url).await;
        if result.is_ok() {
            self.handle.state().active = Some(permit);
        }
        result
    }

    async fn captcha_pending(&mut self) -> Result<bool, BrowserError> {
        self.inner.captcha_pending().await
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
        let prepared = {
            let mut state = self.handle.state();
            if state.reserved {
                Some(
                    state
                        .prepared
                        .take()
                        .ok_or_else(|| admission_error("prepared actor permit already consumed"))?,
                )
            } else {
                None
            }
        };
        let mut permit = match prepared {
            Some(permit) => permit,
            None => {
                self.handle.end_unprepared()?;
                let origin = if let BrowserAction::Navigate { url } = &action {
                    self.handle.check_navigation(url).await?;
                    Origin::from_url(url)
                } else {
                    self.live_origin().await?
                };
                self.admit(&origin).await?
            }
        };
        self.handle.dispatch(&mut permit)?;
        let result = self.inner.perform(action).await;
        if result.is_ok() {
            self.handle.state().active = Some(permit);
        }
        result
    }

    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        let _permit = self.handle.state().active.take();
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

    async fn close(mut self: Box<Self>) -> Result<(), BrowserError> {
        {
            let mut state = self.handle.state();
            state.prepared = None;
            state.active = None;
        }
        self.inner.close().await
    }

    async fn page_op(&mut self, op: PageOp) -> Result<PageOpResult, BrowserError> {
        if matches!(op, PageOp::EvaluateScript { .. }) {
            self.handle.end_unprepared()?;
            let origin = self.live_origin().await?;
            let mut permit = self.admit(&origin).await?;
            self.handle.dispatch(&mut permit)?;
            self.inner.page_op(op).await
        } else {
            self.inner.page_op(op).await
        }
    }

    async fn lazy_scroll(&mut self, spec: LazyScrollSpec) -> Result<LazyScrollReport, BrowserError> {
        self.handle.end_unprepared()?;
        let origin = self.live_origin().await?;
        let mut permit = self.admit(&origin).await?;
        self.handle.dispatch(&mut permit)?;
        self.inner.lazy_scroll(spec).await
    }

    async fn css_filter(
        &mut self,
        filter: &CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, BrowserError> {
        self.inner.css_filter(filter, targets).await
    }

    fn drain_xhr(&mut self) -> Vec<XhrRecord> {
        self.inner.drain_xhr()
    }

    fn drain_blocked_navigations(&mut self) -> Vec<BlockedNavigation> {
        self.inner.drain_blocked_navigations()
    }
}
