//! The browser leg of the scrape engine: render one URL in a browser context, run the caller's
//! `actions[]`, and hand back the serialized DOM plus the binary results.
//!
//! [`PageRenderer`] is the seam: the scrape engine (`super::ScrapeEngine`) asks it for a
//! [`Rendered`] page whenever [`crawlx_core::scrape::ScrapeOptions::needs_browser`] holds, and
//! tests inject a scripted renderer. [`BrowserRenderer`] is the production implementation over
//! the worker's [`crate::RunContext`] (browser pool, egress proxy, safety kernel, action journal).
//!
//! One render is one Session Actor over one pooled, incognito browser context, with its own
//! `crawl_sessions` row so that the caller's input actions are adjudicated and journaled like
//! any other ([`actions`]). In order it: applies `mobile` / `location` emulation and `blockAds`
//! ([`locale`]), navigates through the run's egress proxy and settles for `waitFor`, runs the
//! actions, and captures the DOM and the `screenshot` format. The context is released on every
//! path: success, failure, `timeout` and cancellation of the run.

mod actions;
pub mod locale;

use crate::actor::{SessionActor, SessionHandle, ShutdownReason};
use crate::analysis::StateAnalyzer;
use crate::driven::Driver;
use crate::error::SessionError;
use crate::run::{build_kernel, RunContext};
use actions::ActionRunner;
use async_trait::async_trait;
use crawlx_core::observation::{NavigationResult, QuiescencePolicy};
use crawlx_core::page_op::{PageOp, PageOpResult, ShotSpec};
use crawlx_core::repo::{CrawlSession, SessionStatus};
use crawlx_core::scrape::{ActionScrape, FormatSpec, JavascriptReturn, ScrapeOptions};
use crawlx_core::{BrowserError, PrincipalId, SessionId, StoreError};
use crawlx_extract::branding::{ComputedStyles, COLLECT_SCRIPT};
use crawlx_fetch::DENIED_HEADER;
use crawlx_safety::SafetyKernel;
use crawlx_scheduler::{Scheduler, HEARTBEAT_INTERVAL};
use crawlx_storage::SessionLease;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

pub use actions::{EXPLICIT_ACTIONS_STRATEGY, MAX_CLICK_TARGETS, WAIT_SELECTOR_MS};

/// Role of the `crawl_sessions` row a render journals under.
const SESSION_ROLE: &str = "scrape";
/// First `schedule_slot` a render session takes; the exploration planner's slots stay far
/// below it.
const SLOT_BASE: u32 = 1_000_000;
/// Tries at a free `(role, run_index)` / `schedule_slot` pair before a render gives up.
const SLOT_ATTEMPTS: usize = 16;
/// How long a render waits for its Session Actor to close once the render is over. The actor
/// finishes the command in flight first (a navigation stuck in the browser), so a slower close
/// finishes in the background and still releases the pool slot.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// What to render.
#[derive(Clone, Copy, Debug)]
pub struct RenderRequest<'a> {
    /// The admitted request, including the explicit handler route; never inferred from redirects.
    pub request: &'a crawlx_core::request::RequestEnvelopeV1,
    /// The scrape options: `waitFor`, `actions`, `mobile`, `location`, `blockAds`,
    /// `timeout_ms`, and the `screenshot` format.
    pub options: &'a ScrapeOptions,
}

/// An encoded image or document.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Shot {
    /// The bytes.
    pub bytes: Vec<u8>,
    /// Media type: `image/png`, `image/jpeg` or `application/pdf`.
    pub content_type: &'static str,
}

/// Binary and structured results of the caller's `actions[]`, in action order per kind.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct ActionOutputs {
    /// One per `screenshot` action.
    pub screenshots: Vec<Shot>,
    /// One per `scrape` action.
    pub scrapes: Vec<ActionScrape>,
    /// One per `executeJavascript` action.
    pub javascript_returns: Vec<JavascriptReturn>,
    /// One per `pdf` action.
    pub pdfs: Vec<Shot>,
    /// Diagnostic virtualized row renditions, finalized into typed content artifacts.
    pub virtual_rows: Vec<crawlx_core::dom_ops::VirtualRowsReport>,
    /// Original render byte allowance shared by finalized virtual-row renditions.
    /// Producers must carry the actual allowance; absence with rows fails publication.
    pub virtual_rows_max_bytes: Option<usize>,
}

/// Observed browser provenance, separate from compatibility status fields and DOM bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RenderedEvidence {
    /// Existing actor session that owns this navigation and its journal.
    pub session: SessionId,
    /// Actual persistent binding generation observed before actor launch.
    pub session_generation: Option<u64>,
    /// Observed main document status; absent never becomes HTTP 200.
    pub target_status: Option<u16>,
    /// Whether the serialized document reported a parseable final URL.
    pub final_url_observed: bool,
    /// Main-navigation redirects observed by the native browser.
    pub redirects: Vec<String>,
    /// Actual leased browser build, not the requested configuration.
    pub backend: crawlx_core::acquisition::BackendCapabilitiesV1,
    /// Serialized DOM was capped by the parent's remaining decoded-byte allowance.
    pub truncated: bool,
}

/// A rendered page.
#[derive(Clone, PartialEq, Debug)]
pub struct Rendered {
    /// Document URL after the actions ran.
    pub final_url: Url,
    /// HTTP status of the main document navigation.
    pub status: u16,
    /// Response headers of the main document navigation (lower-case names).
    pub headers: Vec<(String, String)>,
    /// `Content-Type` of the main document.
    pub content_type: Option<String>,
    /// Serialized DOM after `waitFor` and every action.
    pub html: String,
    /// The `screenshot` format capture, taken after the actions.
    pub screenshot: Option<Shot>,
    /// Results of the actions.
    pub actions: ActionOutputs,
    /// What `getComputedStyle` reported for the page, collected when the `branding` format is
    /// requested (see [`crawlx_extract::branding::COLLECT_SCRIPT`]). `None` when the format is
    /// not requested or the page would not answer the script: `branding` then reads the markup
    /// and stylesheets alone.
    pub computed_styles: Option<ComputedStyles>,
    /// Native observed evidence; absent means a legacy/test adapter did not supply it.
    pub evidence: Option<RenderedEvidence>,
}

/// Why a page could not be rendered.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RenderError {
    /// The scrape's time budget elapsed.
    #[error("render timed out after {0} ms")]
    Timeout(u64),
    /// The navigation failed (DNS, connection, TLS).
    #[error("navigation failed: {0}")]
    Navigation(String),
    /// The egress policy refused the page or one of the caller's navigations.
    #[error("egress denied: {0}")]
    EgressDenied(String),
    /// An action did not run: its selector matched nothing, the element was not actionable, the
    /// safety kernel denied it, or the script threw.
    #[error("action {index} ({kind}) failed: {reason}")]
    Action {
        /// Position in `actions[]`.
        index: usize,
        /// Firecrawl action type.
        kind: &'static str,
        /// Fixed reason code.
        reason: String,
    },
    /// The browser failed (crash, protocol error).
    #[error("browser error: {0}")]
    Browser(String),
    /// No browser is available to this worker.
    #[error("no browser is available: {0}")]
    Unavailable(String),
    /// The run was cancelled while the page rendered.
    #[error("render cancelled")]
    Cancelled,
}

/// Renders pages in a browser. Object-safe.
#[async_trait]
pub trait PageRenderer: Send + Sync {
    /// Open `req.request.url`, apply emulation and request blocking, wait, run the actions, and capture
    /// the DOM and the requested binaries.
    ///
    /// # Errors
    /// [`RenderError`].
    async fn render(&self, req: &RenderRequest<'_>) -> Result<Rendered, RenderError>;
    /// Render with the parent's deadline, cancellation and navigation-request allowance.
    /// Legacy adapters must explicitly support this contract before native selection.
    ///
    /// # Errors
    /// Returns unavailable when the adapter cannot enforce the parent allowance.
    async fn render_bounded(
        &self,
        _req: &RenderRequest<'_>,
        _allowance: &RenderAllowance,
    ) -> Result<Rendered, RenderError> {
        Err(RenderError::Unavailable(
            "parent acquisition allowance unsupported".to_owned(),
        ))
    }
}

/// Parent-owned browser allowance. No tenant can supply executable browser configuration here.
#[derive(Clone, Debug)]
pub struct RenderAllowance {
    pub(crate) requests: Arc<std::sync::atomic::AtomicU32>,
    pub(crate) deadline: tokio::time::Instant,
    pub(crate) max_decoded_bytes: usize,
    pub(crate) cancel: tokio_util::sync::CancellationToken,
}
impl RenderAllowance {
    /// Create a standalone bounded render allowance; coordinators share its remaining state.
    ///
    /// # Errors
    /// Returns unavailable for zero or above-operator-limit request, duration or body bounds.
    pub fn new(
        max_requests: u32,
        max_elapsed: Duration,
        max_decoded_bytes: usize,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Self, RenderError> {
        if !(1..=512).contains(&max_requests)
            || max_elapsed.is_zero()
            || max_elapsed > Duration::from_secs(300)
            || !(1..=67_108_864).contains(&max_decoded_bytes)
        {
            return Err(RenderError::Unavailable(
                "acquisition allowance outside bounds".to_owned(),
            ));
        }
        Ok(Self {
            requests: Arc::new(std::sync::atomic::AtomicU32::new(max_requests)),
            deadline: tokio::time::Instant::now() + max_elapsed,
            max_decoded_bytes,
            cancel,
        })
    }
}

#[derive(Debug)]
struct BudgetNavigationGuard {
    inner: Option<Arc<dyn crawlx_core::browser::NavigationGuard>>,
    allowance: RenderAllowance,
}
#[async_trait]
impl crawlx_core::browser::NavigationGuard for BudgetNavigationGuard {
    async fn check(&self, url: &Url) -> crawlx_core::browser::NavigationVerdict {
        use crawlx_core::browser::NavigationVerdict;
        if self.allowance.cancel.is_cancelled() || tokio::time::Instant::now() >= self.allowance.deadline {
            return NavigationVerdict::RobotsBlocked {
                reason: "acquisition_stopped",
            };
        }
        if let Some(inner) = &self.inner {
            let verdict = inner.check(url).await;
            if verdict.refusal().is_some() {
                return verdict;
            }
        }
        NavigationVerdict::Allow
    }

    fn intercepts_subresources(&self) -> bool {
        true
    }

    async fn check_request(&self, url: &Url) -> crawlx_core::browser::NavigationVerdict {
        let verdict = self.check(url).await;
        if verdict.refusal().is_some() {
            return verdict;
        }
        self.check_subresource(url).await
    }

    async fn check_subresource(&self, _url: &Url) -> crawlx_core::browser::NavigationVerdict {
        use crawlx_core::browser::NavigationVerdict;
        if self.allowance.cancel.is_cancelled() || tokio::time::Instant::now() >= self.allowance.deadline {
            return NavigationVerdict::RobotsBlocked {
                reason: "acquisition_stopped",
            };
        }
        if self
            .allowance
            .requests
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |left| left.checked_sub(1),
            )
            .is_err()
        {
            return NavigationVerdict::RobotsBlocked {
                reason: "acquisition_allowance",
            };
        }
        NavigationVerdict::Allow
    }
}

/// The production [`PageRenderer`]: pooled Chromium contexts of one run.
pub struct BrowserRenderer {
    rc: Arc<RunContext>,
    unproxied: bool,
}

impl BrowserRenderer {
    /// A renderer over `rc`'s pool, egress proxy, kernel and journal.
    ///
    /// Every render refuses with [`RenderError::Unavailable`] unless `rc.egress_port` names the
    /// run's egress proxy: a browser context without it would navigate unchecked.
    #[must_use]
    pub fn new(rc: Arc<RunContext>) -> Self {
        Self { rc, unproxied: false }
    }

    /// Render without an egress proxy. For scripted browser backends (tests) that open no
    /// sockets; a real browser must never run this way.
    #[must_use]
    pub fn allow_unproxied(mut self) -> Self {
        self.unproxied = true;
        self
    }
}

#[async_trait]
impl PageRenderer for BrowserRenderer {
    async fn render(&self, req: &RenderRequest<'_>) -> Result<Rendered, RenderError> {
        self.render_task(req, None).await
    }

    async fn render_bounded(
        &self,
        req: &RenderRequest<'_>,
        allowance: &RenderAllowance,
    ) -> Result<Rendered, RenderError> {
        self.render_task(req, Some(allowance.clone())).await
    }
}

impl BrowserRenderer {
    /// Keep actor cleanup alive if the outer scrape deadline drops its waiter.
    /// The drop guard cancels the owned task; it closes the session and releases the lease.
    async fn render_task(
        &self,
        req: &RenderRequest<'_>,
        mut allowance: Option<RenderAllowance>,
    ) -> Result<Rendered, RenderError> {
        let cancel = allowance.as_ref().map_or_else(
            || self.rc.cancel.child_token(),
            |budget| budget.cancel.child_token(),
        );
        let _cancel_on_drop = cancel.clone().drop_guard();
        if let Some(budget) = &mut allowance {
            budget.cancel = cancel.clone();
        }
        let renderer = Self {
            rc: Arc::clone(&self.rc),
            unproxied: self.unproxied,
        };
        let request = req.request.clone();
        let options = req.options.clone();
        tokio::spawn(crawlx_core::custody::inherit(async move {
            renderer
                .render_with_allowance(
                    &RenderRequest {
                        request: &request,
                        options: &options,
                    },
                    allowance.as_ref(),
                    cancel,
                )
                .await
        }))
        .await
        .map_err(|error| RenderError::Browser(format!("render task failed: {error}")))?
    }

    async fn render_with_allowance(
        &self,
        req: &RenderRequest<'_>,
        allowance: Option<&RenderAllowance>,
        parent_cancel: tokio_util::sync::CancellationToken,
    ) -> Result<Rendered, RenderError> {
        if self.rc.egress_port.is_none() && !self.unproxied {
            return Err(RenderError::Unavailable(
                "the run has no egress proxy, so a browser page would load unchecked".to_owned(),
            ));
        }
        let budget_ms = u64::from(req.options.timeout_ms);
        let deadline = allowance.map_or_else(
            || tokio::time::Instant::now() + Duration::from_millis(budget_ms),
            |budget| budget.deadline,
        );
        let lease = tokio::select! {
            biased;
            () = parent_cancel.cancelled() => return Err(RenderError::Cancelled),
            () = self.rc.cancel.cancelled() => return Err(RenderError::Cancelled),
            result = tokio::time::timeout_at(deadline, self.open_session()) => result.map_err(|_| RenderError::Timeout(budget_ms))??,
        };
        let scheduler = Scheduler::new(Arc::clone(&self.rc.stores.leases));
        let heartbeat_cancel = tokio_util::sync::CancellationToken::new();
        let mut heartbeat = scheduler.keep_alive(lease.clone(), HEARTBEAT_INTERVAL, heartbeat_cancel.clone());
        let mut actor: Option<SessionHandle> = None;
        let outcome = {
            let work = self.render_in(req, &lease, &mut actor, allowance);
            tokio::select! {
                biased;
                () = self.rc.cancel.cancelled() => Err(RenderError::Cancelled),
                () = parent_cancel.cancelled() => Err(RenderError::Cancelled),
                result = &mut heartbeat => Err(RenderError::Browser(format!("render lease lost: {result:?}"))),
                r = tokio::time::timeout_at(deadline, work) => {
                    r.unwrap_or(Err(RenderError::Timeout(budget_ms)))
                }
            }
        };
        let cleanup = self.close(&lease, actor, &outcome).await;
        heartbeat_cancel.cancel();
        if !heartbeat.is_finished() {
            let _ = heartbeat.await;
        }
        cleanup?;
        outcome
    }
}

impl BrowserRenderer {
    /// The `crawl_sessions` row the render's actions are journaled under: a `running`
    /// `scrape` session at a free slot of the run.
    async fn open_session(&self) -> Result<SessionLease, RenderError> {
        for _ in 0..SLOT_ATTEMPTS {
            let id = SessionId::new();
            let b = id.0.as_bytes();
            // the random tail of the UUID picks the slot; a taken slot is tried again
            let slot = u32::from_be_bytes([b[9], b[10], b[11], b[12]]) & 0x3FFF_FFFF;
            let run_index = u16::from_be_bytes([b[13], b[14]]).max(1);
            let session = CrawlSession {
                id,
                run: self.rc.run,
                role: PrincipalId(SESSION_ROLE.to_owned()),
                run_index,
                schedule_slot: SLOT_BASE + slot,
                status: SessionStatus::Pending,
                browser: None,
                action_seq: 0,
            };
            match self
                .rc
                .stores
                .leases
                .create_render_session(&session, self.rc.worker)
                .await
            {
                Ok(lease) => return Ok(lease),
                Err(StoreError::Conflict(_)) => {}
                Err(e) => return Err(RenderError::Browser(format!("render session: {e}"))),
            }
        }
        Err(RenderError::Browser(
            "render session: no free session slot in the run".to_owned(),
        ))
    }

    /// Stop the actor (which closes and releases its browser context) and finish the session
    /// row. No checkpoint: nobody resumes a scrape.
    async fn close(
        &self,
        lease: &SessionLease,
        actor: Option<SessionHandle>,
        outcome: &Result<Rendered, RenderError>,
    ) -> Result<(), RenderError> {
        let cleanup = if let Some(handle) = actor {
            match tokio::time::timeout(SHUTDOWN_GRACE, handle.shutdown(ShutdownReason::Cancelled)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(RenderError::Browser(format!("render shutdown: {error}"))),
                Err(_) => Err(RenderError::Browser("render shutdown unconfirmed".to_owned())),
            }
        } else {
            Ok(())
        };
        let status = match outcome {
            Ok(_) if cleanup.is_ok() => SessionStatus::Completed,
            Ok(_) => SessionStatus::Failed,
            Err(RenderError::Cancelled) => SessionStatus::Cancelled,
            Err(_) => SessionStatus::Failed,
        };
        Scheduler::new(Arc::clone(&self.rc.stores.leases))
            .release(lease, status)
            .await
            .map_err(|error| RenderError::Browser(format!("render lease release: {error}")))?;
        cleanup
    }

    /// The kernel that gates this page's actions: the run's own, or, for a page outside the
    /// seed's origin (a batch of unrelated URLs), one built for the page's origin so that the
    /// page itself is in scope.
    fn kernel_for(&self, url: &Url) -> Result<Arc<SafetyKernel>, RenderError> {
        if url.origin() == self.rc.crawl.seed_url.origin() {
            return Ok(Arc::clone(&self.rc.kernel));
        }
        let mut crawl = self.rc.crawl.clone();
        crawl.seed_url = url.clone();
        build_kernel(
            &crawl,
            Arc::clone(&self.rc.clock),
            self.rc.authorization.as_ref().map(|guard| guard.record()),
        )
        .map(Arc::new)
        .map_err(|e| RenderError::Browser(format!("safety kernel: {e}")))
    }

    /// Everything after the session row exists, under the render's budget. The actor handle is
    /// parked in `actor` as soon as it exists so the caller can stop it however this ends.
    async fn render_in(
        &self,
        req: &RenderRequest<'_>,
        lease: &SessionLease,
        actor: &mut Option<SessionHandle>,
        allowance: Option<&RenderAllowance>,
    ) -> Result<Rendered, RenderError> {
        let session = &lease.session;
        let options = req.options;
        let rc = &self.rc;
        let kernel = self.kernel_for(&req.request.url.url)?;
        let base = QuiescencePolicy::for_dynamic(&rc.crawl.dynamic);
        let mut cfg = rc.session_config(session);
        if let Some(allowance) = allowance {
            cfg.context.navigation_guard = Some(Arc::new(BudgetNavigationGuard {
                inner: cfg.context.navigation_guard.take(),
                allowance: allowance.clone(),
            }));
        }
        // Each enhanced attempt owns a distinct checked proxy/context. Never mutate the
        // shared basic proxy while other batch/crawl pages are still using it.
        let _enhanced_proxy = if options.proxy == crawlx_core::scrape::ProxyMode::Enhanced {
            let mut crawl = rc.crawl.clone();
            let job = crawl.scrape.get_or_insert_with(|| {
                crawlx_core::scrape::ScrapeJob::new(crawlx_core::scrape::JobKind::Scrape, options.clone())
            });
            job.options.proxy = crawlx_core::scrape::ProxyMode::Enhanced;
            let resolver = rc
                .egress
                .resolver_for(&crawl)
                .map_err(|e| RenderError::Unavailable(e.to_string()))?;
            let proxy = rc
                .egress
                .serve_proxy(
                    &crawl,
                    rc.authorization.as_ref().map(|guard| guard.record()),
                    resolver,
                    crawlx_fetch::EgressOptions::new().with_controls(rc.controls.clone()),
                )
                .await
                .map_err(|e| RenderError::Unavailable(e.to_string()))?;
            cfg.context.egress_proxy_port = Some(proxy.port());
            Some(proxy)
        } else {
            None
        };
        // `waitFor`: an unconditional wait after the page loads, before the idle criteria
        cfg.settle = QuiescencePolicy {
            fixed_wait_ms: base.fixed_wait_ms.saturating_add(u64::from(options.wait_for_ms)),
            ..base
        };
        let pooled = rc
            .acquire_bound_session(lease, &mut cfg)
            .await
            .map_err(|error| RenderError::Unavailable(error.to_string()))?;
        let effective_build = pooled.build.clone();
        let session_generation = cfg
            .context
            .session_binding
            .as_ref()
            .map(|binding| binding.generation);
        let analyzer = Arc::new(StateAnalyzer::new(
            rc.run,
            session.id,
            rc.clusters.clone(),
            Arc::clone(&rc.stores.artifacts),
            Arc::clone(&rc.clock),
            rc.crawl.capture.clone(),
            (&rc.controls, &rc.captcha_secrets),
        ));
        if rc.stores.pg.is_some() {
            rc.clusters
                .sync(rc.stores.states.as_ref(), rc.run)
                .await
                .map_err(|e| RenderError::Browser(format!("state clusters: {e}")))?;
        }
        let mut services = rc.services();
        services.kernel = Arc::clone(&kernel);
        let handle = SessionActor::spawn(
            cfg,
            services,
            Arc::clone(&analyzer),
            rc.crawl.retention.days,
            pooled,
        )
        .await
        .map_err(render_error)?;
        let handle: &SessionHandle = actor.insert(handle);

        // emulation and blocking are context-wide and apply to the navigation below
        if let Some(emulation) = locale::emulation_for(options) {
            handle
                .page_op(PageOp::Emulate(emulation))
                .await
                .map_err(render_error)?;
        }
        if options.block_ads {
            handle
                .page_op(PageOp::BlockUrls(crawlx_extract::blocklist::patterns_for(
                    &req.request.url.url,
                )))
                .await
                .map_err(render_error)?;
        }

        let nav = handle.navigate(req.request.clone()).await.map_err(render_error)?;
        let document = document_response(handle, &nav).await?;
        if let (Some(status), Ok(final_url)) = (document.status, Url::parse(&nav.final_url)) {
            let mut headers = http::HeaderMap::new();
            for (name, value) in &document.headers {
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::try_from(name.as_str()),
                    http::HeaderValue::try_from(value.as_str()),
                ) {
                    headers.append(name, value);
                }
            }
            let retry_after = crawlx_fetch::retry::parse_retry_after(&headers, rc.clock.now());
            rc.origin_governor
                .on_response_with_latency(
                    &crawlx_fetch::Origin::from_url(&final_url),
                    status,
                    retry_after,
                    None,
                    false,
                )
                .await
                .map_err(|error| RenderError::Browser(format!("origin feedback: {error}")))?;
        }

        let driver = Driver {
            handle,
            rc,
            kernel: kernel.as_ref(),
            session,
            analyzer: analyzer.as_ref(),
            settle: base,
        };
        let actions = ActionRunner::new(
            driver,
            allowance.map_or(1_048_576, |budget| budget.max_decoded_bytes),
        )
        .run(&options.actions)
        .await?;
        // read before the DOM is serialized: both describe the page after the actions
        let computed_styles = if options.wants("branding") {
            computed_styles(handle).await
        } else {
            None
        };
        let (mut html, url) = match handle.page_op(PageOp::Html).await.map_err(render_error)? {
            PageOpResult::Html { html, url } => (html, url),
            _ => {
                return Err(RenderError::Browser(
                    "unexpected result of page operation html".to_owned(),
                ))
            }
        };
        let truncated = allowance.is_some_and(|budget| html.len() > budget.max_decoded_bytes);
        if let Some(allowance) = allowance {
            if html.len() > allowance.max_decoded_bytes {
                let mut end = allowance.max_decoded_bytes;
                while !html.is_char_boundary(end) {
                    end = end.saturating_sub(1);
                }
                html.truncate(end);
            }
        }
        let parsed_final_url = Url::parse(&url).ok();
        let final_url_observed = parsed_final_url.is_some();
        let final_url = parsed_final_url.unwrap_or_else(|| req.request.url.url.clone());
        let screenshot = match options.format("screenshot") {
            Some(FormatSpec::Screenshot {
                full_page,
                quality,
                viewport,
            }) => {
                let spec = ShotSpec {
                    full_page: *full_page,
                    quality: *quality,
                    viewport: viewport.map(|v| (v.width, v.height)),
                };
                match handle
                    .page_op(PageOp::Screenshot(spec))
                    .await
                    .map_err(render_error)?
                {
                    PageOpResult::Bytes { bytes, content_type } => Some(Shot { bytes, content_type }),
                    _ => {
                        return Err(RenderError::Browser(
                            "unexpected result of page operation screenshot".to_owned(),
                        ))
                    }
                }
            }
            _ => None,
        };
        Ok(Rendered {
            final_url,
            status: document.status.unwrap_or(0),
            headers: document.headers,
            content_type: document.content_type,
            html,
            screenshot,
            actions,
            computed_styles,
            evidence: Some(RenderedEvidence {
                session: session.id,
                session_generation,
                target_status: document.status,
                final_url_observed,
                redirects: nav.redirects,
                truncated,
                backend: crawlx_core::acquisition::BackendCapabilitiesV1::native_browser(effective_build),
            }),
        })
    }
}

/// What `getComputedStyle` reports for the rendered page. A page that does not answer the
/// script gives no report (the `branding` format then reads the markup and stylesheets alone).
async fn computed_styles(handle: &SessionHandle) -> Option<ComputedStyles> {
    let script = PageOp::EvaluateScript {
        script: COLLECT_SCRIPT.to_owned(),
    };
    match handle.page_op(script).await {
        Ok(PageOpResult::Json(report)) => ComputedStyles::from_value(report),
        Ok(_) => None,
        Err(e) => {
            tracing::debug!(error = %e, "computed styles not collected");
            None
        }
    }
}

/// The main document's response as the browser saw it.
struct Document {
    status: Option<u16>,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
}

/// Status, headers and media type of the document the navigation `nav` loaded.
/// A final-document refusal recorded by the browser or a marked proxy `403` is
/// [`RenderError::EgressDenied`], not a target page. Unrelated blocked subresources
/// do not turn an otherwise valid document into an acquisition failure.
async fn document_response(handle: &SessionHandle, nav: &NavigationResult) -> Result<Document, RenderError> {
    let PageOpResult::Response {
        status,
        headers,
        content_type,
    } = handle
        .page_op(PageOp::DocumentResponse)
        .await
        .map_err(render_error)?
    else {
        return Err(RenderError::Browser(
            "unexpected result of page operation document_response".to_owned(),
        ));
    };
    let status = status.or(nav.status);
    let document_denied = nav
        .blocked_by_egress
        .iter()
        .any(|blocked| blocked == &nav.final_url);
    if document_denied
        || (status == Some(403) && headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(DENIED_HEADER)))
    {
        return Err(RenderError::EgressDenied(
            "the egress policy refused the page".to_owned(),
        ));
    }
    Ok(Document {
        status,
        headers,
        content_type,
    })
}

/// A browser failure as a render failure. `Unsupported` is a context that cannot run what the
/// render asked of it.
fn browser_error(e: BrowserError) -> RenderError {
    match e {
        BrowserError::EgressDenied(m) => RenderError::EgressDenied(m),
        BrowserError::Navigation(m) => RenderError::Navigation(m),
        BrowserError::Unsupported(m) => RenderError::Unavailable(m),
        other => RenderError::Browser(other.to_string()),
    }
}

/// A Session Actor failure as a render failure.
fn render_error(e: SessionError) -> RenderError {
    match e {
        SessionError::Browser(b) => browser_error(b),
        other => RenderError::Browser(other.to_string()),
    }
}
