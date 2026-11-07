//! Login: the declarative `builtin:form` plan from `crawlx-forms`,
//! executed against a browser context with a credential resolved immediately before use.
//! The credential only ever travels as `SecretOr<String>` into `BrowserAction::Type`; the
//! typed value is never logged, journaled or stored.
//!
//! Recorded flows are replayed by [`run_recorded_login`] through
//! the Session Actor handle: every non-credential step is a kernel-adjudicated, journaled
//! native action attributed to the `login` strategy; credential fills go through
//! `SessionCommand::TypeCredential` (native input performed inside the actor, outside the
//! kernel, exactly like the typing of `builtin:form`: the kernel classifies typing into a
//! password field as `security_change` by design, so a credential fill can never be
//! admitted). Step semantics follow projectdiscovery/katana
//! `pkg/engine/headless/auth/replay.go` (`RunLoginSteps`, `waitVisible`, `submitForm`) and
//! `session.go` (`SessionStateChanged`) at commit 9662cd7 (MIT): success is a cookie/storage
//! change or a satisfied terminal `waitvisible`; a failed flow falls back to `builtin:form`
//! ([`login_session`]).

use crate::actor::SessionHandle;
use crate::analysis::StateAnalyzer;
use crate::driven::{Attribution, DriveFailure, Driver};
use crate::error::SessionError;
use crate::run::RunContext;
use crawlx_core::action::{BrowserAction, KeyChord, Modifiers, PointerButton};
use crawlx_core::hash::Digest;
use crawlx_core::identity::InputClass;
use crawlx_core::observation::{
    DomSelector, DomSelectorKind, LiveTargetFacts, ObservationBundle, QuiescencePolicy, Revalidation,
    RuntimeLocator,
};
use crawlx_core::repo::CrawlSession;
use crawlx_core::safety::RiskClass;
use crawlx_core::secret::SecretOr;
use crawlx_core::{BrowserContext, BrowserError, CoreError};
use crawlx_elements::{CandidateDiscovery, DiscoveryConfig};
use crawlx_forms::{
    detect_login_form, CredentialPart, FillValue, LoggedInIndicator, LoginExpectation, LoginField, LoginPlan,
    LoginStep, LoginTargets, PressKey, Selector, SelectorKind, SubmitMethod,
};
use crawlx_observe::{spec, Observer, QuiescenceWaiter};
use crawlx_url::Canonicalizer;
use std::time::Duration;
use tokio::time::Instant;

/// At most this many login attempts per role per run.
pub const MAX_LOGIN_ATTEMPTS: u8 = 3;

/// Maximum UTF-8 JSON bytes accepted from a native recorded login artifact.
pub const MAX_RECORDED_ARTIFACT_BYTES: u64 = 1_048_576;

const RECORDED_ARTIFACT_PREFIX: &str = "artifact://";
const MAX_RECORDED_ARTIFACT_DESCRIPTOR_BYTES: usize = 4_096;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedLoginArtifact {
    tenant: crawlx_core::TenantId,
    run: crawlx_core::CrawlRunId,
    sensitivity: crawlx_core::repo::Sensitivity,
    artifact: RecordedLoginArtifactRef,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedLoginArtifactRef {
    id: crawlx_core::ArtifactId,
    digest: Digest,
}

/// Parse an explicit recorded-artifact login reference without granting read authority.
///
/// Returns tenant, source run and artifact labels, or `None` for a non-artifact
/// plan. Callers must authorize the labels and independently verify source custody,
/// sensitivity, retention, size and fixity through the artifact store.
///
/// # Errors
/// Returns fixed, data-free errors for malformed, oversized or non-content descriptors.
pub fn parse_recorded_login_artifact(
    spec: &str,
) -> Result<
    Option<(
        crawlx_core::TenantId,
        crawlx_core::CrawlRunId,
        crawlx_core::ArtifactRef,
    )>,
    SessionError,
> {
    let Some(flow) = spec
        .trim_start()
        .strip_prefix(crawlx_forms::login::RECORDED_PLAN_PREFIX)
    else {
        return Ok(None);
    };
    let Some(descriptor) = flow.trim_start().strip_prefix(RECORDED_ARTIFACT_PREFIX) else {
        return Ok(None);
    };
    if descriptor.len() > MAX_RECORDED_ARTIFACT_DESCRIPTOR_BYTES {
        return Err(SessionError::LoginFailed(
            "recorded flow artifact descriptor exceeds byte limit".into(),
        ));
    }
    let descriptor: RecordedLoginArtifact = serde_json::from_str(descriptor)
        .map_err(|_| SessionError::LoginFailed("recorded flow artifact descriptor is invalid".into()))?;
    if descriptor.sensitivity != crawlx_core::repo::Sensitivity::Content {
        return Err(SessionError::LoginFailed(
            "recorded flow artifact scope or sensitivity is invalid".into(),
        ));
    }
    Ok(Some((
        descriptor.tenant,
        descriptor.run,
        crawlx_core::ArtifactRef {
            id: descriptor.artifact.id,
            digest: descriptor.artifact.digest,
        },
    )))
}

/// Resolve only plan data, before resolving credentials or acquiring a browser.
pub(crate) async fn resolve_login_plan(
    stores: &crate::stores::Stores,
    spec: Option<&str>,
) -> Result<LoginPlan, SessionError> {
    let Some(spec) = spec.map(str::trim_start) else {
        return Ok(LoginPlan::builtin_form());
    };
    if spec.trim_end() == crawlx_forms::login::BUILTIN_FORM_PLAN {
        return Ok(LoginPlan::builtin_form());
    }
    if let Some((tenant, run, artifact)) = parse_recorded_login_artifact(spec)? {
        if tenant != stores.tenant {
            return Err(SessionError::LoginFailed(
                "recorded flow artifact scope or sensitivity is invalid".into(),
            ));
        }
        // The immutable plan explicitly identifies a same-tenant source run.
        // Labels grant no authority: the store independently checks actual source
        // tenant/run, sensitivity, retention, size and fixity before returning bytes.
        let bytes = stores
            .artifacts
            .read_archive_content(stores.tenant, run, &artifact, MAX_RECORDED_ARTIFACT_BYTES)
            .await
            .map_err(|_| SessionError::LoginFailed("recorded flow artifact is not readable".into()))?;
        return parse_recorded_login_flow(&bytes);
    }
    let flow = spec
        .strip_prefix(crawlx_forms::login::RECORDED_PLAN_PREFIX)
        .ok_or_else(|| SessionError::LoginFailed("login plan is not supported".into()))?
        .trim_start();
    if let Some(path) = flow.trim_end().strip_prefix("file://") {
        // Keep the existing local-file contract; the native artifact ceiling does
        // not narrow previously supported inline/file flows.
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|_| SessionError::LoginFailed("recorded flow file is not readable".into()))?;
        return parse_recorded_login_flow(&bytes);
    }
    parse_recorded_login_flow(flow.as_bytes())
}

fn parse_recorded_login_flow(bytes: &[u8]) -> Result<LoginPlan, SessionError> {
    let json = std::str::from_utf8(bytes)
        .map_err(|_| SessionError::LoginFailed("recorded flow is not UTF-8 JSON".into()))?;
    crawlx_forms::RecordedFlow::parse(json)
        .map(LoginPlan::recorded)
        // A parser error can contain recorded text. Never echo flow data into errors.
        .map_err(|_| SessionError::LoginFailed("recorded login flow is invalid".into()))
}

/// Validate exact source bytes before storing a recorded login flow as content.
///
/// Uses the replay parser, but rejects credential literals instead of silently
/// persisting values that Recorder compilation would replace with placeholders.
/// Ordinary non-credential fills remain supported. This function never rewrites
/// bytes or resolves credentials.
///
/// # Errors
/// Returns a fixed, data-free [`SessionError::LoginFailed`] for malformed flows,
/// flows exceeding the artifact-only byte limit, or credential-targeted literal fills.
pub fn validate_recorded_login_flow(bytes: &[u8]) -> Result<(), SessionError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECORDED_ARTIFACT_BYTES {
        return Err(SessionError::LoginFailed(
            "recorded flow artifact exceeds byte limit".into(),
        ));
    }
    let plan = parse_recorded_login_flow(bytes)?;
    // The replay compiler intentionally drops Recorder credential literals.
    // Inspect only original fill values against its compiled selectors so upload
    // validation uses exactly the same selector precedence and classification.
    let source: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| SessionError::LoginFailed("recorded login flow is invalid".into()))?;
    let steps = source
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| SessionError::LoginFailed("recorded login flow is invalid".into()))?;
    let recorder = steps.first().is_some_and(|step| step.get("type").is_some());
    let fills = steps.iter().filter(|step| {
        let name = step
            .get(if recorder { "type" } else { "action" })
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim();
        if recorder {
            name.eq_ignore_ascii_case("change")
        } else {
            ["fill", "input", "type"]
                .iter()
                .any(|action| name.eq_ignore_ascii_case(action))
        }
    });
    let selectors = plan.steps.iter().filter_map(|step| match step {
        LoginStep::FillSelector { selector, .. } => Some(selector),
        _ => None,
    });
    for (selector, source) in selectors.zip(fills) {
        let value = source
            .get("value")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim();
        if (selector.looks_like_username() || selector.looks_like_password())
            && !matches!(
                value,
                crawlx_forms::login::recorded::USERNAME_PLACEHOLDER
                    | crawlx_forms::login::recorded::PASSWORD_PLACEHOLDER
            )
        {
            return Err(SessionError::LoginFailed(
                "recorded flow credential fills require placeholders".into(),
            ));
        }
    }
    Ok(())
}

/// Username and password of one principal.
#[derive(Clone)]
pub struct LoginCredential {
    /// Username.
    pub username: SecretOr<String>,
    /// Password.
    pub password: SecretOr<String>,
}

impl std::fmt::Debug for LoginCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LoginCredential([REDACTED])")
    }
}

impl LoginCredential {
    /// Split a resolved credential: JSON `{"username": .., "password": ..}` or `user:password`.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub fn parse(value: &SecretOr<String>) -> Result<Self, CoreError> {
        let raw = value.expose();
        let invalid =
            || CoreError::CredentialUnavailable("credential must be `user:password` or JSON".to_owned());
        if raw.trim_start().starts_with('{') {
            let v: serde_json::Value = serde_json::from_str(raw).map_err(|_| invalid())?;
            let field = |k: &str| v.get(k).and_then(serde_json::Value::as_str).map(str::to_owned);
            let (Some(u), Some(p)) = (field("username"), field("password")) else {
                return Err(invalid());
            };
            crawlx_telemetry::register_secret(&u);
            crawlx_telemetry::register_secret(&p);
            return Ok(Self {
                username: SecretOr::secret(u),
                password: SecretOr::secret(p),
            });
        }
        let (u, p) = raw.split_once(':').ok_or_else(invalid)?;
        crawlx_telemetry::register_secret(u);
        crawlx_telemetry::register_secret(p);
        Ok(Self {
            username: SecretOr::secret(u.to_owned()),
            password: SecretOr::secret(p.to_owned()),
        })
    }
}

/// A plan with the credential it types; the actor keeps it to re-login during recovery.
#[derive(Clone)]
pub struct LoginMaterial {
    /// Plan.
    pub plan: LoginPlan,
    /// Credential.
    pub credential: LoginCredential,
}

/// Bound initial authentication separately from exploration. Include one built-in
/// fallback and cap the whole envelope even when a supplied plan has many steps.
pub(crate) fn login_allowance(material: &LoginMaterial) -> chrono::Duration {
    let fallback = if material.plan.is_recorded() { 6 } else { 0 };
    let steps = material.plan.steps.len().saturating_add(fallback);
    let millis = u64::try_from(steps)
        .unwrap_or(u64::MAX)
        .saturating_mul(MAX_WAIT_MS)
        .min(crawlx_storage::session_binding::MAX_LOGIN_RESERVATION_MS);
    chrono::Duration::milliseconds(i64::try_from(millis).unwrap_or(i64::MAX))
}

/// Why a login did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoginFailure {
    #[error("no login form was found on the page")]
    /// No login form.
    NoLoginForm,
    #[error("the page is on {actual}, not the declared origin {expected}; refusing to type a credential")]
    /// Origin mismatch.
    OriginMismatch {
        /// Origin the credential is bound to.
        expected: String,
        /// Origin of the page that was loaded.
        actual: String,
    },
    #[error("login step failed: {0}")]
    /// Step.
    Step(String),
    #[error("login did not reach a logged-in state within {0} ms")]
    /// Expectation timeout.
    ExpectationTimeout(u64),
    #[error("recorded step {index} ({op}) failed: {reason}")]
    /// A recorded-flow step did not complete; `op` names the step and `reason` is one of
    /// [`RECORDED_REASONS`] (never a selector or page text).
    Recorded {
        /// Zero-based step index (`steps.len()` for the end-of-flow success check).
        index: usize,
        /// Step op name (`navigate`, `fill`, `click`, ...).
        op: &'static str,
        /// Fixed-vocabulary reason.
        reason: &'static str,
    },
    #[error("browser error: {0}")]
    /// Browser.
    Browser(#[from] BrowserError),
    #[error("session error: {0}")]
    /// The Session Actor refused or failed a command of the recorded flow.
    Session(#[from] SessionError),
}

/// Reasons [`LoginFailure::Recorded`] carries.
pub const RECORDED_REASONS: [&str; 7] = [
    "selector_not_found",
    "not_actionable",
    "denied",
    "dropped",
    "failed",
    "timeout",
    "no_session_change",
];

impl From<crawlx_observe::ObserveError> for LoginFailure {
    fn from(e: crawlx_observe::ObserveError) -> Self {
        match e {
            crawlx_observe::ObserveError::Browser(b) => Self::Browser(b),
        }
    }
}

const LOGOUT_WORDS: [&str; 9] = [
    "log out",
    "logout",
    "sign out",
    "signout",
    "abmelden",
    "déconnexion",
    "deconnexion",
    "cerrar sesión",
    "çıkış",
];

fn has_logout_control(bundle: &ObservationBundle) -> bool {
    crawlx_observe::candidate_nodes(bundle).any(|n| {
        n.name.as_deref().is_some_and(|name| {
            let lower = name.to_lowercase();
            LOGOUT_WORDS.iter().any(|w| lower.contains(w))
        })
    })
}

fn login_targets(bundle: &ObservationBundle) -> Result<LoginTargets, LoginFailure> {
    let candidates = CandidateDiscovery::discover(bundle, &DiscoveryConfig::default());
    let descriptors: Vec<_> = candidates.into_iter().map(|c| c.descriptor).collect();
    detect_login_form(&descriptors).map_err(|_| LoginFailure::NoLoginForm)
}

/// Outcome of a successful login.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct LoginReport {
    /// Final url.
    pub final_url: String,
}

struct Runner<'a> {
    ctx: &'a mut dyn BrowserContext,
    observer: &'a mut Observer,
    seed_origin: &'a str,
    settle: QuiescencePolicy,
    bundle: ObservationBundle,
    targets: Option<LoginTargets>,
    start_nav: u64,
    login_route: String,
}

impl Runner<'_> {
    async fn refresh(&mut self) -> Result<(), LoginFailure> {
        self.bundle = self.observer.observe(self.ctx, &spec::after_action()).await?;
        Ok(())
    }

    fn locator(&self, field: LoginField) -> Result<RuntimeLocator, LoginFailure> {
        let targets = self
            .targets
            .as_ref()
            .ok_or_else(|| LoginFailure::Step("FindField must precede Type".to_owned()))?;
        targets
            .field(field)
            .map(|t| t.locator.clone())
            .ok_or_else(|| LoginFailure::Step(format!("the form has no {field:?} field")))
    }

    async fn actionable(&mut self, locator: &RuntimeLocator) -> Result<(), LoginFailure> {
        match self.ctx.revalidate(locator, locator.epoch).await? {
            Revalidation::Actionable { .. } => Ok(()),
            other => Err(LoginFailure::Step(format!(
                "login control is not actionable: {other:?}"
            ))),
        }
    }

    async fn perform(&mut self, action: BrowserAction) -> Result<(), LoginFailure> {
        self.ctx.perform(action).await?;
        QuiescenceWaiter::default().settle(self.ctx, &self.settle).await?;
        Ok(())
    }

    async fn step(&mut self, step: &LoginStep, cred: &LoginCredential) -> Result<(), LoginFailure> {
        match step {
            LoginStep::FindField { .. } => {
                self.refresh().await?;
                self.targets = Some(login_targets(&self.bundle)?);
                self.start_nav = self.bundle.epoch.navigation_seq;
                self.login_route = self.bundle.url.route_template.0.clone();
                Ok(())
            }
            LoginStep::Type { field, source } => {
                if self.bundle.url.origin != self.seed_origin {
                    return Err(LoginFailure::OriginMismatch {
                        expected: self.seed_origin.to_owned(),
                        actual: self.bundle.url.origin.clone(),
                    });
                }
                let target = self.locator(*field)?;
                self.actionable(&target).await?;
                let value = match source {
                    CredentialPart::Username => cred.username.clone(),
                    CredentialPart::Password => cred.password.clone(),
                };
                self.perform(BrowserAction::Type {
                    target,
                    value,
                    clear_first: true,
                })
                .await
            }
            LoginStep::Submit { method } => {
                let targets = self
                    .targets
                    .clone()
                    .ok_or_else(|| LoginFailure::Step("FindField must precede Submit".to_owned()))?;
                match (method, &targets.submit) {
                    (SubmitMethod::ClickSubmit, Some(submit)) => {
                        let target = submit.locator.clone();
                        self.actionable(&target).await?;
                        self.perform(BrowserAction::Click {
                            target,
                            button: PointerButton::Left,
                            modifiers: Modifiers::default(),
                        })
                        .await
                    }
                    _ => {
                        // no submit control (or Enter requested): focus the password field, press Enter
                        let pw = targets.password.locator.clone();
                        self.actionable(&pw).await?;
                        self.perform(BrowserAction::Click {
                            target: pw,
                            button: PointerButton::Left,
                            modifiers: Modifiers::default(),
                        })
                        .await?;
                        self.perform(BrowserAction::Keys {
                            sequence: vec![KeyChord {
                                key: "Enter".to_owned(),
                                modifiers: Modifiers::default(),
                            }],
                        })
                        .await
                    }
                }
            }
            LoginStep::Expect { any_of, timeout_ms } => {
                let deadline = Instant::now() + Duration::from_millis(*timeout_ms);
                loop {
                    self.refresh().await?;
                    if self.expectation_met(any_of) {
                        return Ok(());
                    }
                    if Instant::now() >= deadline {
                        return Err(LoginFailure::ExpectationTimeout(*timeout_ms));
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
            // Recorded-flow steps are compiled by `crawlx-forms`; their replay
            // through the Session Actor is a separate path and not wired here.
            other => Err(LoginFailure::Step(format!(
                "login step is not supported by the builtin:form runner: {other:?}"
            ))),
        }
    }

    fn expectation_met(&self, any_of: &[LoginExpectation]) -> bool {
        any_of.iter().any(|e| match e {
            LoginExpectation::Navigation => {
                self.bundle.epoch.navigation_seq != self.start_nav
                    && self.bundle.url.route_template.0 != self.login_route
            }
            LoginExpectation::LoggedIn(LoggedInIndicator::PasswordFieldGone) => {
                login_targets(&self.bundle).is_err()
            }
            LoginExpectation::LoggedIn(LoggedInIndicator::LogoutControl) => has_logout_control(&self.bundle),
        })
    }
}

/// Run `material.plan` on `ctx`, which must already show the login page of `seed_origin`.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub async fn run_login(
    ctx: &mut dyn BrowserContext,
    observer: &mut Observer,
    material: &LoginMaterial,
    seed_origin: &str,
    settle: QuiescencePolicy,
) -> Result<LoginReport, LoginFailure> {
    if !material.plan.types_password_only_into_password_field() {
        return Err(LoginFailure::Step(
            "a plan may type the password only into the password field".to_owned(),
        ));
    }
    let bundle = observer.observe(ctx, &spec::after_action()).await?;
    let mut runner = Runner {
        ctx,
        observer,
        seed_origin,
        settle,
        start_nav: bundle.epoch.navigation_seq,
        login_route: bundle.url.route_template.0.clone(),
        bundle,
        targets: None,
    };
    for step in &material.plan.steps {
        runner.step(step, &material.credential).await?;
    }
    Ok(LoginReport {
        final_url: runner.bundle.url.url.to_string(),
    })
}

// ---- recorded flows --------------------------------------------------------

/// Strategy name recorded on every journaled step of a recorded flow.
pub const LOGIN_STRATEGY: &str = "login";
/// Upper bound of a `wait` step (katana accepts any duration; the crawl's deadline must stay
/// reachable).
pub const MAX_WAIT_MS: u64 = 30_000;
/// Polling interval of `waitvisible` (katana: 150 ms).
const WAIT_VISIBLE_POLL_MS: u64 = 150;

/// The forms-side selector as the browser-side one.
#[must_use]
pub fn dom_selector(selector: &Selector) -> DomSelector {
    DomSelector {
        kind: match selector.kind {
            SelectorKind::XPath => DomSelectorKind::XPath,
            SelectorKind::Aria => DomSelectorKind::Aria,
            SelectorKind::Text => DomSelectorKind::Text,
            // `Css`, and any kind added later, which the adapter resolves as CSS
            _ => DomSelectorKind::Css,
        },
        expr: selector.expr.clone(),
    }
}

/// Step op name as recorded in audit events and errors.
#[must_use]
pub const fn step_op(step: &LoginStep) -> &'static str {
    match step {
        LoginStep::NavigateTo { .. } => "navigate",
        LoginStep::FillSelector { .. } => "fill",
        LoginStep::ClickSelector { .. } => "click",
        LoginStep::DoubleClickSelector { .. } => "doubleclick",
        LoginStep::WaitVisible { .. } => "waitvisible",
        LoginStep::Wait { .. } => "wait",
        LoginStep::Press { .. } => "press",
        LoginStep::SubmitSelector { .. } => "submit",
        LoginStep::FindField { .. } => "find_field",
        LoginStep::Type { .. } => "type",
        LoginStep::Submit { .. } => "submit_form",
        LoginStep::Expect { .. } => "expect",
        _ => "unknown",
    }
}

/// Outcome of a successful recorded flow.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct RecordedLoginReport {
    /// URL the flow ended on.
    pub final_url: String,
    /// Steps replayed.
    pub steps: usize,
    /// The cookie/storage export changed between the first and the last step.
    pub session_changed: bool,
    /// The flow ended with a satisfied `waitvisible`.
    pub terminal_visible: bool,
}

/// Replays one recorded plan through the actor (see the module docs).
struct RecordedRunner<'a> {
    handle: &'a SessionHandle,
    rc: &'a RunContext,
    session: &'a CrawlSession,
    analyzer: &'a StateAnalyzer,
    settle: QuiescencePolicy,
}

impl RecordedRunner<'_> {
    fn fail(index: usize, step: &LoginStep, reason: &'static str) -> LoginFailure {
        LoginFailure::Recorded {
            index,
            op: step_op(step),
            reason,
        }
    }

    async fn resolve(
        &self,
        index: usize,
        step: &LoginStep,
        selector: &Selector,
    ) -> Result<RuntimeLocator, LoginFailure> {
        self.handle
            .resolve_selector(dom_selector(selector))
            .await?
            .ok_or_else(|| Self::fail(index, step, "selector_not_found"))
    }

    /// Live facts of an actionable `locator`; `not_actionable` otherwise.
    async fn actionable(
        &self,
        index: usize,
        step: &LoginStep,
        locator: &RuntimeLocator,
    ) -> Result<LiveTargetFacts, LoginFailure> {
        match self.handle.revalidate(locator.clone()).await? {
            Revalidation::Actionable { live } => Ok(live),
            _ => Err(Self::fail(index, step, "not_actionable")),
        }
    }

    /// Adjudicate `action` with the kernel and execute it through the actor's protocol.
    async fn execute(
        &self,
        index: usize,
        step: &LoginStep,
        bundle: &ObservationBundle,
        action: BrowserAction,
        target: Option<(&Selector, LiveTargetFacts)>,
        input_class: InputClass,
    ) -> Result<(), LoginFailure> {
        let op = step_op(step);
        let (element, facts) = match target {
            Some((selector, facts)) => (
                Digest::of("crawlx/worker/login-target", selector.to_string().as_bytes()),
                facts,
            ),
            None => (
                Digest::of("crawlx/worker/login-target", b"keyboard"),
                LiveTargetFacts {
                    current_url: bundle.url.url.to_string(),
                    ..LiveTargetFacts::default()
                },
            ),
        };
        let driver = Driver {
            handle: self.handle,
            rc: self.rc,
            kernel: &self.rc.kernel,
            session: self.session,
            analyzer: self.analyzer,
            settle: self.settle,
        };
        let who = Attribution {
            strategy: LOGIN_STRATEGY,
            strategy_version: 1,
            hinted_risk: Some(RiskClass::PersistentWriteOwn),
            summary: format!("recorded login step {index} ({op})"),
            element,
            input_class,
        };
        driver
            .drive(bundle, action, facts, who)
            .await
            .map_err(|e| match e {
                DriveFailure::Denied => Self::fail(index, step, "denied"),
                DriveFailure::Dropped(_) => Self::fail(index, step, "dropped"),
                DriveFailure::Failed => Self::fail(index, step, "failed"),
                DriveFailure::Session(e) => LoginFailure::Session(e),
            })
    }

    async fn click(&self, index: usize, step: &LoginStep, selector: &Selector) -> Result<(), LoginFailure> {
        let bundle = self.handle.observe(spec::after_action()).await?;
        let target = self.resolve(index, step, selector).await?;
        let facts = self.actionable(index, step, &target).await?;
        self.execute(
            index,
            step,
            &bundle,
            BrowserAction::Click {
                target,
                button: PointerButton::Left,
                modifiers: Modifiers::default(),
            },
            Some((selector, facts)),
            InputClass::none(),
        )
        .await
    }

    async fn press(&self, index: usize, step: &LoginStep, key: &str) -> Result<(), LoginFailure> {
        let bundle = self.handle.observe(spec::after_action()).await?;
        self.execute(
            index,
            step,
            &bundle,
            BrowserAction::Keys {
                sequence: vec![KeyChord {
                    key: key.to_owned(),
                    modifiers: Modifiers::default(),
                }],
            },
            None,
            InputClass::none(),
        )
        .await
    }

    async fn wait_visible(
        &self,
        index: usize,
        step: &LoginStep,
        selector: &Selector,
        timeout_ms: u64,
    ) -> Result<(), LoginFailure> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.min(MAX_WAIT_MS));
        loop {
            if let Some(locator) = self.handle.resolve_selector(dom_selector(selector)).await? {
                if matches!(
                    self.handle.revalidate(locator).await?,
                    Revalidation::Actionable { .. }
                ) {
                    return Ok(());
                }
            }
            if Instant::now() >= deadline {
                return Err(Self::fail(index, step, "timeout"));
            }
            tokio::time::sleep(Duration::from_millis(WAIT_VISIBLE_POLL_MS)).await;
        }
    }

    /// Replay one step; `true` when it was a satisfied `waitvisible`.
    async fn step(
        &self,
        index: usize,
        step: &LoginStep,
        cred: &LoginCredential,
    ) -> Result<bool, LoginFailure> {
        match step {
            LoginStep::NavigateTo { url } => {
                let canon = Canonicalizer::canonicalize_url(url, &self.rc.canon)
                    .map_err(|_| Self::fail(index, step, "failed"))?;
                self.handle
                    .navigate(crawlx_core::request::RequestEnvelopeV1::get(canon, 0, None))
                    .await?;
            }
            LoginStep::FillSelector { selector, value } => match value {
                FillValue::Placeholder(part) => {
                    let secret = match part {
                        CredentialPart::Username => cred.username.clone(),
                        CredentialPart::Password => cred.password.clone(),
                    };
                    let target = self.resolve(index, step, selector).await?;
                    self.handle.type_credential(target, secret).await?;
                }
                FillValue::Literal(text) => {
                    let bundle = self.handle.observe(spec::after_action()).await?;
                    let target = self.resolve(index, step, selector).await?;
                    let facts = self.actionable(index, step, &target).await?;
                    self.execute(
                        index,
                        step,
                        &bundle,
                        BrowserAction::Type {
                            target,
                            value: SecretOr::Plain(text.clone()),
                            clear_first: true,
                        },
                        Some((selector, facts)),
                        InputClass::new("text", "literal"),
                    )
                    .await?;
                }
            },
            LoginStep::ClickSelector { selector } => self.click(index, step, selector).await?,
            LoginStep::DoubleClickSelector { selector } => {
                // `BrowserAction::Click` carries no click count: two adjudicated clicks
                self.click(index, step, selector).await?;
                self.click(index, step, selector).await?;
            }
            LoginStep::WaitVisible { selector, timeout_ms } => {
                self.wait_visible(index, step, selector, *timeout_ms).await?;
                return Ok(true);
            }
            LoginStep::Wait { duration_ms } => {
                tokio::time::sleep(Duration::from_millis((*duration_ms).min(MAX_WAIT_MS))).await;
            }
            LoginStep::Press { key } => {
                let name = match key {
                    PressKey::Enter => "Enter",
                    PressKey::Tab => "Tab",
                    PressKey::Escape => "Escape",
                    _ => "Space",
                };
                self.press(index, step, name).await?;
            }
            LoginStep::SubmitSelector {
                selector: Some(selector),
            } => self.click(index, step, selector).await?,
            // no submit control: Enter on the focused field (katana's `submitForm` fallback)
            LoginStep::SubmitSelector { selector: None } => self.press(index, step, "Enter").await?,
            // `builtin:form` steps never appear in a recorded plan (`RecordedFlow` compiles
            // selector steps only); refuse rather than guess
            _ => return Err(Self::fail(index, step, "failed")),
        }
        Ok(false)
    }
}

/// Replay the recorded plan of `material` through the Session Actor `handle` (see the module
/// docs). Success is a changed cookie/storage export or a satisfied terminal `waitvisible`.
///
/// # Errors
/// [`LoginFailure::Recorded`] names the step and a fixed reason; [`LoginFailure::Session`]
/// when the actor refused or failed a command (the session is then not usable for a
/// fallback either).
pub async fn run_recorded_login(
    handle: &SessionHandle,
    rc: &RunContext,
    session: &CrawlSession,
    analyzer: &StateAnalyzer,
    material: &LoginMaterial,
) -> Result<RecordedLoginReport, LoginFailure> {
    let runner = RecordedRunner {
        handle,
        rc,
        session,
        analyzer,
        settle: QuiescencePolicy::for_dynamic(&rc.crawl.dynamic),
    };
    let steps = &material.plan.steps;
    let before = handle.storage_digest().await?;
    let mut terminal_visible = false;
    for (index, step) in steps.iter().enumerate() {
        terminal_visible = runner.step(index, step, &material.credential).await?;
    }
    let after = handle.storage_digest().await?;
    let session_changed = before != after;
    if !session_changed && !terminal_visible {
        return Err(LoginFailure::Recorded {
            index: steps.len(),
            op: "end",
            reason: "no_session_change",
        });
    }
    let bundle = handle.observe(spec::after_action()).await?;
    Ok(RecordedLoginReport {
        final_url: bundle.url.url.to_string(),
        steps: steps.len(),
        session_changed,
        terminal_visible,
    })
}

/// Log the session in with `material`: `builtin:form` runs inside the actor; a recorded
/// flow is replayed once with [`run_recorded_login`]. Recoverable detection failures may
/// fall back to `builtin:form` with the same credential. Kernel denials and final-confirmation
/// drops stop the login: fallback must not execute an operation the policy just refused.
/// Every outcome is a `session.login` audit event with `plan` and `fallback`.
/// Replay restoration uses this same dispatcher: recorded plans must not be sent directly
/// to [`SessionHandle::login`], which only executes the builtin form plan.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails, or when the
/// fallback login fails too.
pub async fn login_session(
    handle: &SessionHandle,
    rc: &RunContext,
    session: &CrawlSession,
    analyzer: &StateAnalyzer,
    material: LoginMaterial,
) -> Result<LoginReport, SessionError> {
    if !material.plan.is_recorded() {
        return handle.login(material).await;
    }
    let audit = |payload: serde_json::Value| async move {
        let mut payload = payload;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("session_id".to_owned(), serde_json::json!(session.id.0));
        }
        if let Err(e) = rc.stores.events.append(rc.run, "session.login", payload).await {
            tracing::warn!(error = %e, "login event not recorded");
        }
    };
    match run_recorded_login(handle, rc, session, analyzer, &material).await {
        Ok(report) => {
            handle.authenticated(material).await?;
            audit(serde_json::json!({
                "ok": true,
                "plan": "recorded",
                "fallback": false,
                "steps": report.steps,
                "sessionChanged": report.session_changed,
                "terminalVisible": report.terminal_visible,
            }))
            .await;
            Ok(LoginReport {
                final_url: report.final_url,
            })
        }
        Err(LoginFailure::Session(e)) => Err(e),
        Err(LoginFailure::Browser(e)) => Err(SessionError::Browser(e)),
        Err(e) => {
            let (step, op, reason) = match &e {
                LoginFailure::Recorded { index, op, reason } => (Some(*index), *op, (*reason).to_owned()),
                other => (None, "unknown", other.to_string()),
            };
            audit(serde_json::json!({
                "ok": false,
                "plan": "recorded",
                "fallback": false,
                "step": step,
                "op": op,
                "reason": reason,
            }))
            .await;
            if matches!(
                &e,
                LoginFailure::Recorded {
                    reason: "denied" | "dropped",
                    ..
                }
            ) {
                return Err(SessionError::LoginFailed(e.to_string()));
            }
            tracing::info!(session = %session.id, step, op, reason, "recorded login failed; falling back to builtin:form");
            let seed = rc.seed_url().map_err(|e| SessionError::Other(e.to_string()))?;
            handle
                .navigate(crawlx_core::request::RequestEnvelopeV1::get(seed, 0, None))
                .await?;
            let fallback = LoginMaterial {
                plan: LoginPlan::builtin_form(),
                credential: material.credential,
            };
            handle.login_with(fallback, true).await
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn credential_parsing_accepts_both_shapes_and_never_prints() {
        let a = LoginCredential::parse(&SecretOr::secret("alice:s3cret:with:colons".to_owned())).unwrap();
        assert_eq!(a.username.expose(), "alice");
        assert_eq!(a.password.expose(), "s3cret:with:colons");
        let b = LoginCredential::parse(&SecretOr::secret(
            r#"{"username":"bob","password":"pw"}"#.to_owned(),
        ))
        .unwrap();
        assert_eq!(
            (b.username.expose().as_str(), b.password.expose().as_str()),
            ("bob", "pw")
        );
        assert!(!format!("{b:?}").contains("pw"));
        assert!(LoginCredential::parse(&SecretOr::secret("nocolon".to_owned())).is_err());
    }
}
