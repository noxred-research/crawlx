//! Browser backend traits. `crawlx-browser`
//! implements them over CDP and provides a scripted `FakeBackend`; every other
//! crate programs against these traits only.

use crate::action::BrowserAction;
use crate::config::LaunchProfile;
use crate::epoch::ObservationEpoch;
use crate::observation::{
    ActionReceipt, BrowserBuildInfo, DomSelector, NavigationResult, ObservationBundle, ObservationSpec,
    QuiescencePolicy, Revalidation, RuntimeLocator, SettleReport, Viewport,
};
use crate::url::CanonicalUrl;
use async_trait::async_trait;
use std::sync::Arc;
use thiserror::Error;

/// What a [`NavigationGuard`] decides about one document navigation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NavigationVerdict {
    /// The navigation may go ahead.
    Allow,
    /// `robots.txt` forbids fetching the URL, or could not be read and the policy fails closed.
    /// `reason` is the bounded code of the decision (`robots_disallow`, `robots_unavailable`),
    /// the same codes the URL plane stores on a `robots_blocked` frontier row.
    RobotsBlocked {
        /// Bounded reason code.
        reason: &'static str,
    },
    /// The egress policy refused the robots request needed to authorize this navigation.
    EgressDenied,
}

impl NavigationVerdict {
    /// The reason code when the navigation is refused, `None` when it may go ahead. Callers
    /// outside this crate use it instead of matching, so a verdict added later fails closed.
    #[must_use]
    pub const fn refusal(self) -> Option<&'static str> {
        match self {
            Self::Allow => None,
            Self::RobotsBlocked { reason } => Some(reason),
            Self::EgressDenied => Some("egress_denied"),
        }
    }
}

/// A document navigation a context refused because its [`NavigationGuard`] said no.
/// The document request never left the browser.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlockedNavigation {
    /// The URL that was about to load.
    pub url: String,
    /// Bounded reason code, see [`NavigationVerdict::refusal`].
    pub reason: &'static str,
}

impl BlockedNavigation {
    /// A refused navigation to `url`.
    #[must_use]
    pub fn new(url: impl Into<String>, reason: &'static str) -> Self {
        Self {
            url: url.into(),
            reason,
        }
    }

    /// Convert the refusal to its typed browser error without exposing a denied target.
    #[must_use]
    pub fn into_error(self) -> BrowserError {
        if self.reason == "egress_denied" {
            BrowserError::EgressDenied("the egress policy refused the navigation".to_owned())
        } else {
            BrowserError::RobotsBlocked {
                url: self.url,
                reason: self.reason,
            }
        }
    }
}

/// Consulted by a browser context before it loads a document: every top-level navigation it
/// issues itself (`navigate`, a `Navigate` action), every main-frame document request a page
/// triggers (link clicks, form submits, script navigations, redirect hops) and every popup.
/// Subresources (images, scripts, XHR) and the documents of embedded frames are not
/// consulted. A refused navigation never reaches the network.
///
/// Implementations decide only; they hold no browser state. `async_trait` keeps the trait
/// object-safe (the documented exception for dyn-compatible traits of this crate).
#[async_trait]
pub trait NavigationGuard: Send + Sync + std::fmt::Debug {
    /// The verdict for loading `url` as a document.
    async fn check(&self, url: &url::Url) -> NavigationVerdict;
    /// Admit an actual paused document request, including redirects.
    ///
    /// Unlike preflight [`Self::check`], this hook may reserve a network allowance.
    /// Existing policy guards retain identical decisions through the default implementation.
    async fn check_request(&self, url: &url::Url) -> NavigationVerdict {
        self.check(url).await
    }
    /// Whether this guard needs paused subresource requests for shared allowance accounting.
    fn intercepts_subresources(&self) -> bool {
        false
    }

    /// Admit a subresource without applying top-level robots/scope rules to it.
    /// Existing network egress policy still runs independently.
    async fn check_subresource(&self, _url: &url::Url) -> NavigationVerdict {
        NavigationVerdict::Allow
    }
}

/// Per-context configuration.
#[derive(Clone, Debug)]
pub struct ContextConfig {
    /// Session that owns this context; one context per Session Actor.
    pub session_id: crate::ids::SessionId,
    /// Strict principal, generation and lease-fence identity for this context.
    pub session_binding: Option<crate::session_binding::SessionBindingV1>,
    /// Initial viewport size for new tabs.
    pub viewport: Viewport,
    /// Launch profile controlling stealth/automation behaviour of the browser.
    pub launch_profile: LaunchProfile,
    /// Loopback egress proxy port (`crawlx-fetch::EgressProxy`); `None` only in tests.
    pub egress_proxy_port: Option<u16>,
    /// `User-Agent` override sent by every tab; `None` keeps the browser's own value.
    pub user_agent: Option<String>,
    /// BCP 47 locale (e.g. `en-US`) used for the `Accept-Language` header and the browser locale override.
    pub locale: String,
    /// Maximum number of tabs open at once; opening more fails with [`BrowserError::TabLimit`].
    pub max_tabs: u8,
    /// Whether `BrowserAction::SyntheticClick` is permitted (mirrors `dynamic.syntheticClick`).
    pub synthetic_click_allowed: bool,
    /// Capture console messages (always false under `Stealth`).
    pub console_capture: bool,
    /// Create a fresh incognito browser context (default `true`). `false` reuses the
    /// browser's default context and its logged-in session (compatibility flag `-no-incognito`);
    /// only meaningful with an attached browser and policy-gated like it.
    pub incognito: bool,
    /// Install the discovery hooks (`dynamic.pageHooks`): `history`,
    /// `window.open`, `hashchange`, `WebSocket`, `EventSource`, `fetch`, XHR URL capture and
    /// the `addEventListener` recorder. The sink is drained into
    /// `ObservationBundle::discovered_urls` and `dom_supplement.listener_candidates`.
    /// Refused under `Stealth` (the hooks run in the page's main world).
    pub page_hooks: bool,
    /// Behaviour-changing page hooks (`dynamic.pageHookOptions`):
    /// timer acceleration, `form.reset()` and `window.close()` prevention, injected into the
    /// page's main world. Refused under `Stealth`.
    pub page_hook_options: crate::config::PageHookOptions,
    /// Inject the stealth patches (`dynamic.stealthPatches`) into every
    /// document. Only valid under `Stealth`.
    pub stealth_patches: bool,
    /// Run in a named persistent browser profile (`dynamic.browserProfile`). Needs
    /// `incognito = false`: only the browser's default context writes to the profile
    /// directory, so the context opens a fresh tab in it instead of adopting one. Launch
    /// settings are process-wide, so the pool starts a browser per profile.
    pub browser_profile: Option<ProfileSpec>,
    /// Custom headers, cookies, `User-Agent` and TLS verification every tab and frame session
    /// applies (`fetch.extraHeaders`, `fetch.cookies`, `fetch.userAgent`,
    /// `fetch.skipTlsVerification`). Cookies are scoped by their own `domain`. Values are
    pub request_controls: crate::request_controls::RequestControls,
    /// Consulted before every document navigation of the context (see [`NavigationGuard`]);
    /// `None` navigates unchecked. The worker sets it from `safety.respectRobotsTxt`.
    pub navigation_guard: Option<Arc<dyn NavigationGuard>>,
    /// Response-body retention mode; full capture requires a policy-enforcing sink.
    pub response_bodies: crate::config::ResponseBodies,
    /// Receives bounded bodies before they enter any persistent queue.
    pub response_body_sink: Option<Arc<dyn ResponseBodySink>>,
    /// Explicit opt-in solver credentials, resolved immediately before context construction.
    pub captcha: Option<crate::captcha::CaptchaCredentials>,
    /// Stops an in-flight solver request when the owning crawl is cancelled.
    pub captcha_cancel: tokio_util::sync::CancellationToken,
    /// Shared dynamic-secret registry; tokens are registered before page callback delivery.
    pub captcha_secrets: crate::captcha::CaptchaSecrets,
    /// Run-wide registration of a token before it is delivered to a page. When present,
    /// delivery is refused unless `register` succeeds; `captcha_secrets` stays the local mirror.
    pub secret_registrar: Option<Arc<dyn crate::custody::SecretRegistrar>>,
}

impl ContextConfig {
    /// Defaults for `session_id`.
    #[must_use]
    pub fn new(session_id: crate::ids::SessionId) -> Self {
        Self {
            session_id,
            session_binding: None,
            viewport: Viewport::default(),
            launch_profile: LaunchProfile::Standard,
            egress_proxy_port: None,
            user_agent: None,
            locale: "en-US".to_owned(),
            max_tabs: 3,
            synthetic_click_allowed: false,
            console_capture: true,
            incognito: true,
            page_hooks: false,
            page_hook_options: crate::config::PageHookOptions::default(),
            stealth_patches: false,
            browser_profile: None,
            request_controls: crate::request_controls::RequestControls::default(),
            navigation_guard: None,
            response_bodies: crate::config::ResponseBodies::MetadataOnly,
            response_body_sink: None,
            captcha: None,
            captcha_cancel: tokio_util::sync::CancellationToken::new(),
            captcha_secrets: crate::captcha::CaptchaSecrets::default(),
            secret_registrar: None,
        }
    }
}

/// Policy boundary for retained browser response bodies.
#[async_trait]
pub trait ResponseBodySink: Send + Sync + std::fmt::Debug {
    /// Store a bounded body after sensitivity, secret and retention checks.
    /// `None` means policy refused the body; callers retain that refusal as metadata.
    /// `truncated` identifies a capped text prefix, never a complete response.
    ///
    /// # Errors
    /// Returns the storage error without exposing response content.
    async fn store(
        &self,
        content_type: &str,
        bytes: &[u8],
        truncated: bool,
    ) -> Result<Option<crate::ids::ArtifactRef>, crate::error::StoreError>;
}

/// A persistent browser profile as the browser layer sees it: `dir` is a relative path
/// below the launcher's profiles directory (`<namespace>/<name>`, each component
/// `A-Z a-z 0-9 _ -`), `save_changes` selects reuse (`true`) or copy-and-discard (`false`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ProfileSpec {
    /// Relative directory below the profiles directory, `/`-separated.
    pub dir: String,
    /// Keep what the run writes (see `dynamic.browserProfile.saveChanges`).
    pub save_changes: bool,
}

/// Browser-layer errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum BrowserError {
    /// Shared admission failed before the browser effect was sent.
    #[error("origin admission failed: {0}")]
    OriginAdmission(#[source] crate::StoreError),
    /// A finite session ceiling elapsed before dispatch; no browser effect was sent.
    #[error("browser session ceiling expired before dispatch")]
    SessionExpired,
    /// A configured CAPTCHA solve or token delivery failed; never contains keys or tokens.
    #[error(transparent)]
    Captcha(#[from] crate::captcha::CaptchaError),
    /// Chromium could not be started or its DevTools endpoint did not come up; carries the cause.
    #[error("browser launch failed: {0}")]
    Launch(String),
    /// The running Chromium build differs from the one pinned in `chromium-pin.toml`.
    #[error("browser build does not match chromium-pin.toml: expected {expected}, got {actual}")]
    PinMismatch {
        /// Build identifier pinned in `chromium-pin.toml`.
        expected: String,
        /// Build identifier reported by the running browser.
        actual: String,
    },
    /// The CDP connection failed (socket closed, send/receive error); carries the cause.
    #[error("CDP transport error: {0}")]
    Transport(String),
    /// Chromium answered a CDP command with an error response.
    #[error("CDP protocol error: {method}: {message}")]
    Protocol {
        /// CDP method that failed, e.g. `Page.navigate`.
        method: String,
        /// Error message returned by the browser.
        message: String,
    },
    /// The renderer behind the target crashed.
    #[error("target crashed")]
    TargetCrashed,
    /// The target (tab or page) was closed while a command was in flight or before it was issued.
    #[error("target closed")]
    TargetClosed,
    /// A navigation did not complete; carries the browser's failure text (e.g. a net error).
    #[error("navigation failed: {0}")]
    Navigation(String),
    /// The egress policy refused a request; carries the denial reason.
    #[error("egress denied: {0}")]
    EgressDenied(String),
    /// The locator belongs to an older observation epoch; the payload is that stale epoch.
    #[error("locator is stale (epoch {0:?})")]
    StaleLocator(ObservationEpoch),
    /// The action or feature is unavailable in the current profile or context config; carries what was refused.
    #[error("action not supported in this profile: {0}")]
    Unsupported(String),
    /// An operation exceeded its deadline; the payload is the limit in milliseconds.
    #[error("timeout after {0} ms")]
    Timeout(u64),
    /// Opening another tab would exceed `max_tabs`; the payload is that limit.
    #[error("too many tabs (limit {0})")]
    TabLimit(u8),
    /// A script evaluated in the page (or a helper script step) failed; carries the message.
    #[error("script error: {0}")]
    Script(String),
    /// A local filesystem or process I/O operation failed; carries the error text.
    #[error("i/o error: {0}")]
    Io(String),
    /// A [`NavigationGuard`] refused the navigation (`robots.txt`); nothing was sent. Not a
    /// network failure and not an egress denial: callers tell the three apart.
    #[error("navigation to {url} refused by the robots policy ({reason})")]
    RobotsBlocked {
        /// The URL that was refused.
        url: String,
        /// Bounded reason code, see [`NavigationVerdict::RobotsBlocked`].
        reason: &'static str,
    },
}

impl BrowserError {
    /// Did the browser target die (recovery ladder applies)?
    #[must_use]
    pub const fn is_target_crash(&self) -> bool {
        matches!(
            self,
            Self::TargetCrashed | Self::TargetClosed | Self::Transport(_)
        )
    }
}

impl crate::error::Classify for BrowserError {
    /// `Timeout` and `Transport` are `OutcomeUnknown`: when they interrupt `perform`, the
    /// browser may already have applied the action. Callers that know
    /// nothing was sent yet (launch, connect) treat them as retryable through their own
    /// [`BrowserError::Launch`] / [`BrowserError::Navigation`] mapping.
    fn class(&self) -> crate::error::ErrorClass {
        use crate::error::ErrorClass;
        match self {
            Self::OriginAdmission(error) => crate::error::Classify::class(error),
            Self::Launch(_) | Self::Navigation(_) | Self::TargetCrashed | Self::TargetClosed => {
                ErrorClass::Retryable
            }
            Self::Timeout(_) | Self::Transport(_) => ErrorClass::OutcomeUnknown,
            Self::Captcha(crate::captcha::CaptchaError::PolicyDenied) => ErrorClass::PolicyDenied,
            Self::Captcha(_) => ErrorClass::Terminal,
            Self::SessionExpired => ErrorClass::Terminal,
            Self::PinMismatch { .. } | Self::Protocol { .. } | Self::Script(_) | Self::Io(_) => {
                ErrorClass::Terminal
            }
            Self::EgressDenied(_) | Self::RobotsBlocked { .. } | Self::Unsupported(_) | Self::TabLimit(_) => {
                ErrorClass::PolicyDenied
            }
            Self::StaleLocator(_) => ErrorClass::Stale,
        }
    }
}

/// Creates browser contexts.
#[async_trait]
pub trait BrowserBackend: Send + Sync {
    /// Create a fresh, isolated browser context configured by `config`.
    ///
    /// # Errors
    /// Returns [`BrowserError`] if the browser cannot be launched or reached, or the
    /// context cannot be created.
    async fn new_context(&self, config: ContextConfig) -> Result<Box<dyn BrowserContext>, BrowserError>;
    /// Chromium version + CDP revision, persisted per session.
    fn build_info(&self) -> &BrowserBuildInfo;
    /// Does this backend's context consult [`ContextConfig::navigation_guard`] before it loads a
    /// document? A real browser does (the default). A scripted backend that models no network
    /// answers `false` unless it was told to enforce the guard: callers then skip the guard and
    /// the `robots.txt` lookups it would trigger, which a scripted site on a made-up host
    /// cannot answer.
    fn honours_navigation_guard(&self) -> bool {
        true
    }
    /// Stop the browser gracefully and wait for it to exit, so state it keeps on disk (a named
    /// profile's cookies and local storage, `dynamic.browserProfile`) is flushed. Idempotent;
    /// the default has nothing to stop. Contexts of a shut-down backend are unusable.
    async fn shutdown(&self) {}
    /// Stop an owned backend and confirm that its resources have exited.
    ///
    /// # Errors
    /// Returns an unsupported error unless the backend can confirm resource death.
    async fn shutdown_confirmed(&self) -> Result<(), BrowserError> {
        Err(BrowserError::Unsupported(
            "browser resource death cannot be confirmed".to_owned(),
        ))
    }
}

/// One browser context owned by exactly one Session Actor.
#[async_trait]
pub trait BrowserContext: Send {
    /// Navigate the active tab to `url` and wait for the navigation to commit.
    ///
    /// # Errors
    /// Returns [`BrowserError::Navigation`] when the navigation fails, or any other
    /// [`BrowserError`] when the target is gone or the transport breaks.
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError>;
    /// Whether the active document has supported, unsolved CAPTCHA widgets.
    ///
    /// # Errors
    /// Returns a typed CAPTCHA error for an unsupported challenge or detection failure.
    async fn captcha_pending(&mut self) -> Result<bool, BrowserError> {
        Ok(false)
    }
    /// Capture an observation; the bundle carries the epoch every proposal from it inherits.
    ///
    /// # Errors
    /// Returns [`BrowserError`] if the page cannot be inspected (target closed, protocol or transport failure).
    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError>;
    /// Cheap check: is `locator` still attached, visible and actionable at the current epoch?
    ///
    /// # Errors
    /// Returns [`BrowserError`] if the page cannot be queried; a stale or detached
    /// locator is reported through [`Revalidation`], not as an error.
    async fn revalidate(
        &mut self,
        locator: &RuntimeLocator,
        expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError>;
    /// Resolve a recorded-flow selector to the first matching element at the
    /// current epoch, or `None` when nothing matches. The default says nothing matches, for
    /// contexts without a DOM.
    ///
    /// # Errors
    /// Returns [`BrowserError`] if the page cannot be queried (target closed, protocol or
    /// transport failure); an invalid selector expression resolves to `None`.
    async fn resolve_selector(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, BrowserError> {
        let _ = selector;
        Ok(None)
    }
    /// Perform `action` and report what it did.
    ///
    /// # Errors
    /// Returns [`BrowserError::StaleLocator`] if the action's locator is from an older
    /// epoch, [`BrowserError::Unsupported`] if the profile forbids the action, or any
    /// other [`BrowserError`] raised while driving the page.
    async fn perform(&mut self, action: BrowserAction) -> Result<ActionReceipt, BrowserError>;
    /// Wait until the page is quiet according to `policy`, or the policy's budget runs out.
    ///
    /// # Errors
    /// Returns [`BrowserError`] if the target is closed or the transport fails while waiting.
    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError>;
    /// Current epoch without a full observation.
    fn current_epoch(&self) -> ObservationEpoch;
    /// Traffic captured since the last drain (already redacted), with the console
    /// messages when `console_capture` is on.
    fn drain_traffic(&mut self) -> Vec<crate::traffic::TrafficEvent>;
    /// Cookies and storage for a checkpoint (secret-bearing; caller encrypts).
    ///
    /// # Errors
    /// Returns [`BrowserError`] if cookies or storage cannot be read from the browser.
    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError>;
    /// Restore cookies and storage from a blob produced by [`BrowserContext::export_storage`].
    ///
    /// # Errors
    /// Returns [`BrowserError`] if `blob` is malformed or cannot be applied to the browser.
    async fn import_storage(&mut self, blob: &[u8]) -> Result<(), BrowserError>;
    /// Shut the context down and release its browser resources.
    ///
    /// # Errors
    /// Returns [`BrowserError`] if the browser does not shut down cleanly.
    async fn close(self: Box<Self>) -> Result<(), BrowserError>;
    /// Execute one caller-driven [`crate::page_op::PageOp`] (emulation, request blocking,
    /// script evaluation, screenshots, PDF). The default says the context cannot, which is
    /// what scripted contexts and decorators that do not forward answer.
    ///
    /// # Errors
    /// [`BrowserError::Unsupported`] by default; otherwise the transport, protocol or script
    /// errors of the operation.
    async fn page_op(
        &mut self,
        op: crate::page_op::PageOp,
    ) -> Result<crate::page_op::PageOpResult, BrowserError> {
        Err(BrowserError::Unsupported(format!("page operation {}", op.name())))
    }
    /// Scroll the active tab's document down in viewport-sized steps so lazily loaded content
    /// (infinite scroll, `IntersectionObserver` sentinels) appears (`dynamic.maxScrollSteps`,
    /// compatibility flag `-max-scroll-steps`), then return to the top. Not a journaled action: it clicks,
    /// types and submits nothing, and the caller observes the page again afterwards. The default
    /// says the context cannot.
    ///
    /// # Errors
    /// [`BrowserError::Unsupported`] by default; otherwise the transport, protocol or script
    /// errors of the scroll, [`BrowserError::TargetClosed`] / [`BrowserError::TargetCrashed`]
    /// when the tab is gone.
    async fn lazy_scroll(
        &mut self,
        spec: crate::dom_ops::LazyScrollSpec,
    ) -> Result<crate::dom_ops::LazyScrollReport, BrowserError> {
        let _ = spec;
        Err(BrowserError::Unsupported("lazy scroll".to_owned()))
    }
    /// Evaluate `filter` in the page for every element of `targets` and return, in order,
    /// whether the element is admitted (`dynamic.interactionSelector`,
    /// `dynamic.interactionExclude`). A target that is gone from the page is not admitted. The
    /// default says the context cannot.
    ///
    /// # Errors
    /// [`BrowserError::Unsupported`] by default; otherwise the transport or protocol errors of
    /// the evaluation. An invalid selector never fails the call: it matches nothing.
    async fn css_filter(
        &mut self,
        filter: &crate::dom_ops::CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, BrowserError> {
        let _ = (filter, targets);
        Err(BrowserError::Unsupported("css candidate filter".to_owned()))
    }
    /// XHR and `fetch()` requests the pages of this context issued since the last call
    /// (`extract.xhr`), oldest first, each tagged with the page that issued it. Contexts
    /// without network capture have none, which is the default.
    fn drain_xhr(&mut self) -> Vec<crate::dom_ops::XhrRecord> {
        Vec::new()
    }
    /// Document navigations this context's [`NavigationGuard`] refused since the last call,
    /// oldest first, that no call returned as [`BrowserError::RobotsBlocked`]: the ones a page
    /// triggered itself (a clicked link, a script, a popup, a redirect hop). A refused
    /// navigation leaves the current document in place. Contexts without a guard have none,
    /// which is the default.
    fn drain_blocked_navigations(&mut self) -> Vec<BlockedNavigation> {
        Vec::new()
    }
}
