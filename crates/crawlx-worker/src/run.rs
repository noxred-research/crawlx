//! `run_local`: create a run in the store and execute it in-process (what
//! `crawlx crawl` calls), plus the per-run wiring shared with the lease loop.

use crate::actor::{SessionConfig, SessionServices};
use crate::analysis::{RunClusters, StateAnalyzer};
use crate::authorization::{
    AuthorizationGuard, AuthorizationSource, AuthorizationStop, StaticAuthorizationSource,
};
use crate::capture::{ProxyCapture, FLOW_CHANNEL};
use crate::config::WorkerConfig;
use crate::counters::RunCounters;
use crate::diagnostics::{DiagnosticsSink, SessionDiagnostics};
use crate::driver::{DriverConfig, DriverEnd, ExplorationDriver};
use crate::error::{SessionError, WorkerError};
use crate::katana::form_ai::FormAi;
use crate::katana::resume::ResumeState;
use crate::katana::traffic_export::TrafficExporter;
use crate::login::{LoginCredential, LoginMaterial};
use crate::model::{ModelOverlay, ModelServices, StrategySet};
use crate::pool::{BrowserPool, PoolConfig};
use crate::robots_gate::RobotsGate;
use crate::routes::RouteLearner;
use crate::secrets::ChainResolver;
use crate::stores::Stores;
use crate::supervisor::Supervisor;
use crate::url_plane::{UrlPlaneDeps, UrlPlaneRunner};
use crate::xhr::XhrSink;
use crawlx_core::browser::BrowserError;
use crawlx_core::config::{
    CaptureBackend, CrawlMode, ExternalCommunication, LaunchProfile, SafetyProfile, TargetIsolation,
};
use crawlx_core::counters::{PlaneCounters, RunStatus, TerminalReason};
use crawlx_core::hash::Digest;
use crawlx_core::observation::QuiescencePolicy;
use crawlx_core::repo::{
    ActionRecord, ArtifactStore, CrawlRun, CrawlSession, EventRepo, FrontierStatus, LedgerRow, NewState,
    PageRecord, SessionStatus,
};
use crawlx_core::request_controls::{is_credential_reference, RequestControls};
use crawlx_core::secret::SecretResolver;
use crawlx_core::seed::CrawlSeed;
use crawlx_core::{
    BrowserBackend, CanonicalUrl, Clock, ContextConfig, CrawlRunId, CreateCrawl, SystemClock, WorkerId,
};
use crawlx_extract::secret_validation::SecretValidators;
use crawlx_fetch::{
    DeniedEvent, EgressOptions, EgressProxyHandle, FetchConfig, Fetcher, GovernorConfig, Resolver,
};
#[cfg(test)]
use crawlx_forms::LoginPlan;
use crawlx_policy::Budget;
use crawlx_safety::{KernelConfig, MemoryAuditLog, SafetyKernel, ScopeRules};
use crawlx_scheduler::{RunPlanner, Scheduler, HEARTBEAT_INTERVAL};
use crawlx_storage::SessionLease;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::spans;
use crawlx_telemetry::Metrics;
use crawlx_url::{CanonicalizeOptions, Canonicalizer};
use futures::stream::{FuturesUnordered, StreamExt as _};
use parking_lot::Mutex;
use serde::Serialize;
use std::future::Future;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

/// Everything one run needs, shared by its sessions and its URL plane.
#[derive(Clone)]
pub struct RunContext {
    /// Run.
    pub run: CrawlRunId,
    /// Crawl.
    pub crawl: CreateCrawl,
    /// Seed.
    pub seed: CrawlSeed,
    /// Stores.
    pub stores: Stores,
    /// Clock.
    pub clock: Arc<dyn Clock>,
    /// Pool.
    pub pool: BrowserPool,
    /// Supervisor.
    pub supervisor: Supervisor,
    /// Kernel.
    pub kernel: Arc<SafetyKernel>,
    /// Clusters.
    pub clusters: RunClusters,
    /// Counters.
    pub counters: RunCounters,
    /// `limits.interactions` / `limits.states` and the deadline, shared by every session.
    pub budget: Arc<Mutex<Budget>>,
    /// Secrets.
    pub secrets: Arc<dyn SecretResolver>,
    /// Encryption provider for all checkpoint writes and restores in this run.
    pub checkpoint_keys: Arc<dyn crawlx_storage::checkpoint_crypto::CheckpointKeys>,
    /// Opt-in provider credentials, never persisted with the crawl.
    pub captcha: Option<crawlx_core::captcha::CaptchaCredentials>,
    /// Shared redaction registry for provider keys and delivered widget tokens.
    pub captcha_secrets: crawlx_core::captcha::CaptchaSecrets,
    /// Worker.
    pub worker: WorkerId,
    /// Canon.
    pub canon: CanonicalizeOptions,
    /// Online route-template learner writing into `canon.templater`, shared by
    /// the URL plane and every session of the run.
    pub routes: RouteLearner,
    /// Cancel.
    pub cancel: CancellationToken,
    /// Loopback egress proxy port for the browser plane.
    pub egress_port: Option<u16>,
    /// Deployment egress configuration for isolated enhanced scrape contexts.
    pub egress: crate::config::EgressConfig,
    /// Worker-approved isolated acquisition services, never tenant-provided endpoints.
    pub protocol_registry: Option<Arc<crate::protocol::ProtocolRegistry>>,
    /// Protected operator root for tenant-keyed request/cache correlation.
    pub request_identity_key: Option<crawlx_core::secret::SecretOr<[u8; 32]>>,
    /// Model clients (System 1, planner) shared by the sessions of the run.
    pub models: ModelServices,
    /// Milestone gates the strategy registry checks before building gated strategies.
    pub gates: crawlx_strategies::Gates,
    /// Sessions open incognito contexts (`false` only in attach mode).
    pub incognito: bool,
    /// Operator-approved retained-profile policy; never supplied by a crawl request.
    pub retained_profiles: Option<crate::config::RetainedProfilePolicy>,
    /// The proxy traffic source when `capture.backend = "proxy"`.
    pub capture: Option<Arc<ProxyCapture>>,
    /// The worker's CPU pool, for the URL plane's extraction step.
    pub cpu_pool: crate::runtime::CpuPool,
    /// Trusted worker-local article language capability, shared without body/model copies.
    pub article_language_detector: Option<crawlx_core::article_language::ArticleLanguageHandle>,
    /// `fetch.extraHeaders`, `fetch.cookies`, `fetch.userAgent` and `fetch.skipTlsVerification`
    /// with credential references resolved: applied by the URL plane's fetcher
    /// and by every browser context ([`Self::context_config`]). `Debug` never prints a value.
    pub controls: RequestControls,
    /// Exports every URL-plane exchange (`WorkerConfig::traffic_export`); `None` exports
    /// nothing. Shut down by [`Self::finish_traffic`] when the run ends.
    pub traffic_export: Option<Arc<TrafficExporter>>,
    /// Provider endpoints that validate detected tokens (`extract.validateSecrets`).
    pub secret_validators: Option<Arc<SecretValidators>>,
    /// Decider of the form fields the deterministic filler could not resolve.
    pub form_ai: Option<Arc<dyn FormAi>>,
    /// Optional collector of actual browser action/value evidence.
    pub action_trace: Option<Arc<crate::action_trace::ActionTrace>>,
    /// Where sessions deposit their diagnostics (`dynamic.enableDiagnostics`); drained into
    /// [`RunReport::diagnostics`] when the run ends.
    pub diagnostics: DiagnosticsSink,
    /// Browser-plane XHR/fetch requests, merged into the page metadata (`xhr_requests`) when
    /// `extract.xhr` is set and the run ends.
    pub xhr: XhrSink,
    /// `robots.txt` obedience of the run: the URL plane decides with it and every browser context
    /// consults it as its navigation guard, over one cache, so an origin's `robots.txt` is
    /// fetched once however many planes visit it.
    pub robots: RobotsGate,
    /// Shared run governor for HTTP requests and all browser effects.
    pub origin_governor: Arc<crawlx_fetch::OriginGovernor>,
    /// Approved delivery registry and the same run egress, resolver and pacing authorities.
    pub delivery: Arc<crate::delivery::DeliveryRegistry>,
    /// Existing checked network authorities used by delivery connectors.
    pub delivery_authority: Arc<crate::delivery::DeliveryAuthority>,
    /// The browser plane honours [`Self::robots`]: its backend consults a navigation guard (a
    /// real browser does).
    pub browser_robots: bool,
    /// The run's authorization guard: its record's target bounds every request, its
    /// revocation or expiry ends the run. `None` for a run that references no record.
    pub authorization: Option<Arc<AuthorizationGuard>>,
}

/// Timing copied from the acquired binding, without copying browser controls or secrets.
#[derive(Clone, Copy)]
pub(crate) struct LoginBounds {
    allowance: chrono::Duration,
    binding_deadline: Option<crawlx_core::Timestamp>,
}

impl From<&SessionConfig> for LoginBounds {
    fn from(cfg: &SessionConfig) -> Self {
        Self {
            allowance: cfg.login_allowance,
            binding_deadline: cfg
                .context
                .session_binding
                .as_ref()
                .map(|binding| binding.expires_at),
        }
    }
}

/// Which capture backend recorded the run's `traffic_events`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct CaptureReport {
    /// `capture.backend` of the run.
    pub backend: CaptureBackend,
    /// Protocols the backend disabled in the browser (`[h3]` for the proxy).
    pub protocols_disabled: Vec<crawlx_core::traffic::Protocol>,
    /// Counters of the proxy backend; `None` under CDP.
    #[serde(skip)]
    pub proxy: Option<crawlx_observe::ProxyCaptureStats>,
}

impl Default for CaptureReport {
    fn default() -> Self {
        Self {
            backend: CaptureBackend::Cdp,
            protocols_disabled: Vec::new(),
            proxy: None,
        }
    }
}

/// Contents of one stored page, for writers of `pages/*.md`.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PageContent {
    /// Url.
    pub url: String,
    /// Markdown.
    pub markdown: Option<String>,
    /// Html.
    pub html: Option<String>,
    /// The raw HTTP exchange of the page (status line, headers, blank line, body; credentials
    /// redacted) when `output.captureRaw` was set.
    pub raw: Option<String>,
}

/// What the browser plane's egress proxy saw during the run (mode
/// isolation). Empty for a run that started no proxy (`mode = static`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EgressCapture {
    /// Distinct `(host, port)` targets the policy admitted, sorted.
    pub dialed_hosts: Vec<(String, u16)>,
    /// Refused requests, oldest first.
    pub denied_events: Vec<DeniedEvent>,
}

/// A frontier row that ended `failed` or `unreachable` (katana `-elog` entries).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct UrlFailure {
    /// Canonical URL of the row.
    pub url: String,
    /// Discovery depth of the row.
    pub depth: u16,
    /// Failure code stored on the row (`http_404`, `timeout`, `egress_denied`, ...).
    pub reason: String,
    /// HTTP status when the failure is an HTTP status (`http_<code>`), else `None`.
    pub status: Option<u16>,
}

impl UrlFailure {
    /// A failure of `url` at `depth`; `status` is derived from an `http_<code>` reason.
    #[must_use]
    pub fn new(url: impl Into<String>, depth: u16, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let status = reason.strip_prefix("http_").and_then(|c| c.parse::<u16>().ok());
        Self {
            url: url.into(),
            depth,
            reason,
            status,
        }
    }
}

/// What `run_local` returns.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct RunReport {
    /// Run id.
    pub run_id: CrawlRunId,
    /// Status.
    pub status: RunStatus,
    /// Terminal reason.
    pub terminal_reason: Option<TerminalReason>,
    /// Counters.
    pub counters: PlaneCounters,
    /// Pages.
    pub pages: Vec<PageRecord>,
    /// States.
    pub states: Vec<NewState>,
    /// Actions.
    pub actions: Vec<ActionRecord>,
    /// Persisted enablement edges (`enablement_edges`) the run learned.
    pub edges: Vec<crawlx_core::repo::EdgeRecord>,
    /// Sessions.
    pub sessions: Vec<CrawlSession>,
    /// Coverage ledger rows (`action_contexts`).
    pub ledger: Vec<LedgerRow>,
    /// Coverage claim over `ledger`, classified under the run's `targetIsolation`
    /// (cross-principal keys are `not_observable` under `per_role_replica`).
    pub coverage: crawlx_strategies::CoverageSummary,
    #[serde(skip)]
    /// Page contents.
    pub page_contents: Vec<PageContent>,
    /// Browser processes the run's pool launched; `0` for every `mode = static` run.
    pub browser_launches: usize,
    #[serde(skip)]
    /// Egress capture of the browser plane.
    pub egress: EgressCapture,
    /// Capture backend of the run and its counters.
    pub capture: CaptureReport,
    /// URLs whose fetch failed or whose host was unreachable, sorted by URL.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<UrlFailure>,
    /// Progress to resume from: set when the URL plane stopped (a limit, the deadline, a
    /// cancellation) with URLs left to fetch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<ResumeState>,
    /// One entry per browser-plane session; empty unless `dynamic.enableDiagnostics`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<SessionDiagnostics>,
}

/// Inputs of an in-process run beyond the request.
pub struct LocalRun {
    /// Crawl.
    pub crawl: CreateCrawl,
    /// Cfg.
    pub cfg: WorkerConfig,
    /// Browser backend to use instead of launching Chromium (tests).
    pub backend: Option<Arc<dyn BrowserBackend>>,
    /// Existing stores (tests share a `MemoryStore` with the API).
    pub stores: Option<Stores>,
    /// Secrets.
    pub secrets: Option<Arc<dyn SecretResolver>>,
    /// Cancel.
    pub cancel: CancellationToken,
    /// Strategies.
    pub strategies: Option<Vec<Arc<dyn crawlx_strategies::Strategy>>>,
    /// Reviewer-controlled approval persistence. The kernel still checks bindings and
    /// consumes each granted approval atomically before admitting its action.
    pub approvals: Option<Arc<dyn crawlx_safety::ApprovalStore>>,
    /// Driver.
    pub driver: DriverConfig,
    /// The authorization record the request references; registered in PostgreSQL so the run's
    /// foreign key holds.
    pub authorization: Option<crawlx_policy::AuthorizationRecord>,
    /// Where the run's authorization record is re-read from while the run lives, instead of the
    /// store's own source (the stored record in PostgreSQL; the supplied record, fixed, in
    /// memory). Tests revoke a record mid-run through it.
    pub authorization_source: Option<Arc<dyn AuthorizationSource>>,
    /// Progress of an earlier run to continue (katana `-resume`): its visited URLs are not
    /// fetched again and its pending URLs seed the frontier.
    pub resume: Option<ResumeState>,
    /// Optional graceful shutdown signal, distinct from hard caller cancellation.
    graceful_drain: Option<CancellationToken>,
    // Deliberately absent from WorkerConfig, request JSON and queued run records.
    fixture_evaluation: Option<crate::fixture_evaluation::FixtureEvaluationPermit>,
}

impl LocalRun {
    #[must_use]
    /// New.
    pub fn new(crawl: CreateCrawl, cfg: WorkerConfig) -> Self {
        Self {
            crawl,
            cfg,
            backend: None,
            stores: None,
            secrets: None,
            cancel: CancellationToken::new(),
            strategies: None,
            approvals: None,
            driver: DriverConfig::default(),
            authorization: None,
            authorization_source: None,
            resume: None,
            graceful_drain: None,
            fixture_evaluation: None,
        }
    }

    /// Attach single-use Advisory evaluation authority from an owned local fixture listener.
    /// All production admission, queued jobs and public RunContext builders remain G3-gated.
    #[must_use]
    pub fn with_fixture_evaluation(
        mut self,
        permit: crate::fixture_evaluation::FixtureEvaluationPermit,
    ) -> Self {
        self.fixture_evaluation = Some(permit);
        self
    }

    #[must_use]
    /// With authorization.
    pub fn with_authorization(mut self, record: crawlx_policy::AuthorizationRecord) -> Self {
        self.authorization = Some(record);
        self
    }

    #[must_use]
    /// With an authorization source that overrides the store's.
    pub fn with_authorization_source(mut self, source: Arc<dyn AuthorizationSource>) -> Self {
        self.authorization_source = Some(source);
        self
    }

    #[must_use]
    /// With backend.
    pub fn with_backend(mut self, backend: Arc<dyn BrowserBackend>) -> Self {
        self.backend = Some(backend);
        self
    }

    #[must_use]
    /// With stores.
    pub fn with_stores(mut self, stores: Stores) -> Self {
        self.stores = Some(stores);
        self
    }

    #[must_use]
    /// With secrets.
    pub fn with_secrets(mut self, secrets: Arc<dyn SecretResolver>) -> Self {
        self.secrets = Some(secrets);
        self
    }

    #[must_use]
    /// Set hard caller cancellation, which interrupts even an active graceful drain.
    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }

    /// Stop new work and finish an already-started static response before checkpointing.
    ///
    /// This does not grant permission for another redirect, retry or request. Authorization,
    /// API cancellation, lease loss and [`Self::with_cancel`] still take precedence.
    #[must_use]
    pub fn with_graceful_drain(mut self, drain: CancellationToken) -> Self {
        self.graceful_drain = Some(drain);
        self
    }

    #[must_use]
    /// With strategies.
    pub fn with_strategies(mut self, strategies: Vec<Arc<dyn crawlx_strategies::Strategy>>) -> Self {
        self.strategies = Some(strategies);
        self
    }

    /// Use a reviewer-controlled approval store for this in-process run.
    #[must_use]
    pub fn with_approval_store(mut self, store: Arc<dyn crawlx_safety::ApprovalStore>) -> Self {
        self.approvals = Some(store);
        self
    }

    #[must_use]
    /// With driver.
    pub fn with_driver(mut self, driver: DriverConfig) -> Self {
        self.driver = driver;
        self
    }

    #[must_use]
    /// With resume.
    pub fn with_resume(mut self, resume: ResumeState) -> Self {
        self.resume = Some(resume);
        self
    }
}

/// The run status a terminal reason implies.
#[must_use]
pub const fn status_for(reason: TerminalReason) -> RunStatus {
    match reason {
        TerminalReason::FrontierExhausted
        | TerminalReason::LimitReached
        | TerminalReason::DeadlineReached
        | TerminalReason::PolicyStopped => RunStatus::Completed,
        TerminalReason::Cancelled => RunStatus::Cancelled,
        TerminalReason::FatalError
        | TerminalReason::RecoveryExhausted
        | TerminalReason::AuthorizationRevoked => RunStatus::Failed,
    }
}

/// Merge the terminal reasons of the planes: failure outranks cancellation outranks
/// deadline outranks limit outranks exhaustion.
#[must_use]
pub fn merge_reasons(reasons: &[TerminalReason]) -> TerminalReason {
    const ORDER: [TerminalReason; 8] = [
        TerminalReason::FatalError,
        TerminalReason::RecoveryExhausted,
        TerminalReason::AuthorizationRevoked,
        TerminalReason::Cancelled,
        TerminalReason::DeadlineReached,
        TerminalReason::LimitReached,
        TerminalReason::PolicyStopped,
        TerminalReason::FrontierExhausted,
    ];
    ORDER
        .into_iter()
        .find(|r| reasons.contains(r))
        .unwrap_or(TerminalReason::FrontierExhausted)
}

/// Safety kernel for `crawl`, narrowed by the run's authorization `record` when it has one
/// (`permittedRiskClasses`, `approvalRequired`: [`crate::authorization::narrowing_of`]).
/// Sink endpoints come only from the selected, stored authorization record; its
/// verification and validity window remain authoritative at every adjudication.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub fn build_kernel(
    crawl: &CreateCrawl,
    clock: Arc<dyn Clock>,
    record: Option<&crawlx_policy::AuthorizationRecord>,
) -> Result<SafetyKernel, WorkerError> {
    let seed_origin = crawl.seed_url.origin().ascii_serialization();
    let sinks = record
        .filter(|record| crawl.safety.authorization_record_ref == Some(record.id))
        .map(|record| {
            let spec = |kind: &str| {
                record
                    .test_sinks
                    .get(kind)
                    .map(|address| crawlx_safety::SinkSpec {
                        address: address.clone(),
                        verified_at: record.verified_at.map(|at| at.max(record.valid_from)),
                        expires_at: record
                            .revoked_at
                            .map_or(record.valid_to, |at| at.min(record.valid_to)),
                    })
            };
            crawlx_safety::TestSinks {
                email: spec("email"),
                sms: spec("sms"),
                webhook: spec("webhook"),
            }
        })
        .unwrap_or_default();
    let cfg = KernelConfig {
        profile: crawl.safety.profile,
        launch_profile: crawl.dynamic.launch_profile,
        has_test_sinks: crawl.safety.external_communication == ExternalCommunication::TestSinks
            && sinks.any_verified(clock.now()),
        destructive_approval: crawl.safety.destructive_actions,
        seed_origin,
        policy_version: 1,
    };
    let mut kernel = SafetyKernel::new_with_clock(cfg, clock)?
        .with_audit_sink(Arc::new(MemoryAuditLog::new()))
        .with_test_sinks(sinks)
        .with_scope(ScopeRules {
            allow_subdomains: crawl.scope.allow_subdomains,
            extra_hosts: Vec::new(),
        });
    if let Some(record) = record {
        kernel = kernel.with_record_narrowing(crate::authorization::narrowing_of(record));
    }
    Ok(kernel)
}

/// Canonicalization options of a run: query policy and overrides from the request, a per-run
/// resource-id key derived from the seed, the worker's trailing-slash policy.
#[must_use]
pub fn canonicalize_options(
    crawl: &CreateCrawl,
    seed: CrawlSeed,
    run: CrawlRunId,
    cfg: &WorkerConfig,
) -> CanonicalizeOptions {
    let key = seed.derive("resource-id-key", &[run.0.as_bytes()]);
    let mut opts = CanonicalizeOptions::from_scope(&crawl.scope, key);
    opts.trailing_slash = cfg.trailing_slash;
    opts
}

/// Restore the route rules a resumed run learned (its last `route_templates` event) and the
/// paths it had observed (frontier rows and state URLs), so URLs key the same way as before
/// the restart and learning continues from the same set. A fresh run has neither.
async fn restore_routes(routes: &RouteLearner, stores: &Stores, run: CrawlRunId) -> Result<(), WorkerError> {
    let mut paths: Vec<String> = stores
        .frontier
        .list(run)
        .await?
        .into_iter()
        .map(|f| f.url.url.path().to_owned())
        .collect();
    paths.extend(
        stores
            .states
            .list_states(run)
            .await?
            .into_iter()
            .map(|s| s.url.url.path().to_owned()),
    );
    if paths.is_empty() {
        return Ok(());
    }
    let snapshot = match RouteLearner::persisted(stores.events.as_ref(), run).await? {
        Some(s) => s,
        None => routes.snapshot(),
    };
    routes.restore(&snapshot, &paths);
    tracing::info!(
        version = snapshot.version,
        slots = snapshot.learned.len(),
        paths = paths.len(),
        "route templates restored"
    );
    Ok(())
}

/// Resolve the request controls of a run (`fetch.extraHeaders`, `fetch.cookies`,
/// `fetch.userAgent`, `fetch.skipTlsVerification`): credential references are looked up
/// through `secrets`, each exactly once, and header values are scoped to the seed's
/// registrable domain (an IP or single-label seed host scopes to itself). Every resolved
/// reference is audited by reference hash and purpose, never by value.
///
/// # Errors
/// [`WorkerError::Core`] when a reference cannot be resolved or a resolved value is not a
/// valid header or cookie value.
pub async fn resolve_controls(
    crawl: &CreateCrawl,
    run: CrawlRunId,
    secrets: &dyn SecretResolver,
    events: &dyn EventRepo,
) -> Result<RequestControls, WorkerError> {
    let host = crawl
        .seed_url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    let scope = crawlx_policy::scope::registrable_domain(&host).unwrap_or(host);
    let controls = RequestControls::resolve(&crawl.fetch, &scope, Some(secrets)).await?;
    for value in controls.secret_values() {
        crawlx_telemetry::register_secret(value);
    }
    let referenced = crawl
        .fetch
        .extra_headers
        .iter()
        .map(|(name, value)| ("request_header", name, value))
        .chain(
            crawl
                .fetch
                .cookies
                .iter()
                .map(|c| ("request_cookie", c.name.as_str(), c.value.as_str())),
        )
        .filter(|(_, _, value)| is_credential_reference(value));
    for (purpose, name, value) in referenced {
        let reference = crawlx_core::secret::CredentialRef(value.to_owned());
        let _ = events
            .append(
                run,
                "secret.resolved",
                serde_json::json!({
                    "name": name,
                    "scheme": reference.scheme(),
                    "reference_hash": Digest::of("crawlx/worker/credential-ref", value.as_bytes()).to_hex(),
                    "purpose": purpose,
                }),
            )
            .await;
    }
    Ok(controls)
}

/// The worker's secret resolver: `secrets` when given, else the environment/file/vault chain.
pub(crate) async fn default_secrets(secrets: Option<Arc<dyn SecretResolver>>) -> Arc<dyn SecretResolver> {
    match secrets {
        Some(s) => s,
        None => Arc::new(ChainResolver::from_env(Arc::new(SystemClock)).await),
    }
}

/// Build a run fetcher using the same governor as its browser actors.
/// `controls` (see [`resolve_controls`]) set headers, cookies, `User-Agent`
/// and TLS verification of every request.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub fn build_fetcher(
    crawl: &CreateCrawl,
    seed: CrawlSeed,
    cfg: &WorkerConfig,
    controls: RequestControls,
    record: Option<&crawlx_policy::AuthorizationRecord>,
    origin_governor: Arc<crawlx_fetch::OriginGovernor>,
) -> Result<(Arc<Fetcher>, Arc<dyn Resolver>), WorkerError> {
    build_fetcher_with_capture(crawl, seed, cfg, controls, record, None, origin_governor)
}

/// [`build_fetcher`] reporting every fetch-plane response on `capture` (unified
/// capture, `source = fetch_plane`).
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
#[allow(clippy::too_many_arguments)]
pub fn build_fetcher_with_capture(
    crawl: &CreateCrawl,
    seed: CrawlSeed,
    cfg: &WorkerConfig,
    controls: RequestControls,
    record: Option<&crawlx_policy::AuthorizationRecord>,
    capture: Option<tokio::sync::mpsc::Sender<crawlx_core::traffic::ProxyFlow>>,
    origin_governor: Arc<crawlx_fetch::OriginGovernor>,
) -> Result<(Arc<Fetcher>, Arc<dyn Resolver>), WorkerError> {
    let resolver = cfg.egress.resolver_for(crawl)?;
    let policy = Arc::new(cfg.egress.policy_for_run(crawl, record));
    let fetch_cfg = FetchConfig {
        contact: cfg.egress.contact.clone(),
        governor: GovernorConfig::from_politeness(&crawl.politeness, seed),
        seed,
        shared_governor: Some(origin_governor),
        proxy: cfg.egress.proxy_for(crawl)?.cloned(),
        ..FetchConfig::from_request(&crawl.fetch)
    }
    .with_controls(controls);
    let mut fetcher = Fetcher::new(fetch_cfg, policy, Arc::clone(&resolver))?;
    if let Some(tx) = capture {
        fetcher = fetcher.with_capture(tx);
    }
    if crawl.acquisition.is_none()
        && crawl
            .scrape
            .as_ref()
            .is_some_and(|job| job.options.proxy == crawlx_core::scrape::ProxyMode::Auto)
    {
        if let Some(proxy) = &cfg.egress.proxy_routes.enhanced {
            fetcher = fetcher.with_enhanced_proxy(proxy)?;
        }
    }
    Ok((Arc::new(fetcher), resolver))
}

impl RunContext {
    /// Wire a run that already exists in the store.
    ///
    /// Browser attach mode (`WorkerConfig::cdp_ws_url`) is admitted only for
    /// runs under `test_environment` or `authorized_security_test`; the pool then attaches
    /// every "process" to that one browser (`max_browsers = 1`). `incognito = false` needs
    /// attach mode: only an attached browser has a human's default context to reuse.
    ///
    /// # Errors
    /// [`WorkerError::PolicyDenied`] for attach mode under `read_only`,
    /// [`WorkerError::Config`] for missing model-authority gates or `incognito = false`
    /// without attach mode, and storage, browser or network failures of the wiring.
    #[allow(clippy::too_many_arguments)]
    pub async fn build(
        run: &CrawlRun,
        cfg: &WorkerConfig,
        stores: Stores,
        backend: Option<Arc<dyn BrowserBackend>>,
        secrets: Option<Arc<dyn SecretResolver>>,
        cancel: CancellationToken,
        proxy: Option<&EgressProxyHandle>,
        authorization: Option<Arc<AuthorizationGuard>>,
    ) -> Result<Self, WorkerError> {
        check_role_credentials(&run.config, authorization.as_deref())?;
        cfg.check_gates(&run.config)?;
        cfg.check_article_language(&run.config)?;
        let secrets = default_secrets(secrets).await;
        let controls =
            resolve_controls(&run.config, run.id, secrets.as_ref(), stores.events.as_ref()).await?;
        Self::build_with_controls(
            run,
            cfg,
            stores,
            backend,
            secrets,
            cancel,
            proxy,
            controls,
            authorization,
        )
        .await
    }

    /// [`Self::build`] with the request controls already resolved ([`resolve_controls`]): a
    /// caller that builds the egress proxy or the fetcher first needs them there too, and a
    /// credential reference is resolved exactly once per run.
    ///
    /// # Errors
    /// The errors of [`Self::build`] except the secret resolution.
    #[allow(clippy::too_many_arguments)]
    pub async fn build_with_controls(
        run: &CrawlRun,
        cfg: &WorkerConfig,
        stores: Stores,
        backend: Option<Arc<dyn BrowserBackend>>,
        secrets: Arc<dyn SecretResolver>,
        cancel: CancellationToken,
        proxy: Option<&EgressProxyHandle>,
        controls: RequestControls,
        authorization: Option<Arc<AuthorizationGuard>>,
    ) -> Result<Self, WorkerError> {
        Self::build_with_fixture_evaluation(
            run,
            cfg,
            stores,
            backend,
            secrets,
            cancel,
            proxy,
            controls,
            authorization,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_with_fixture_evaluation(
        run: &CrawlRun,
        cfg: &WorkerConfig,
        mut stores: Stores,
        backend: Option<Arc<dyn BrowserBackend>>,
        secrets: Arc<dyn SecretResolver>,
        cancel: CancellationToken,
        proxy: Option<&EgressProxyHandle>,
        controls: RequestControls,
        authorization: Option<Arc<AuthorizationGuard>>,
        evaluation: Option<&crate::fixture_evaluation::BoundFixtureEvaluation>,
    ) -> Result<Self, WorkerError> {
        cfg.check_article_language(&run.config)?;
        let checkpoint_keys = cfg
            .checkpoint_keys
            .as_ref()
            .unwrap_or(&stores.checkpoint_keys)
            .clone();
        if run.config.mode != CrawlMode::Static && !checkpoint_keys.is_available() {
            return Err(WorkerError::Config(
                "browser checkpoints require CRAWLX_CHECKPOINT_KMS_KEY_ID".into(),
            ));
        }
        if let Some(referenced) = run.config.safety.authorization_record_ref {
            let guard = authorization
                .as_ref()
                .ok_or(AuthorizationStop::Missing(referenced))?;
            if guard.record_id() != referenced {
                return Err(AuthorizationStop::Mismatch {
                    given: guard.record_id(),
                    referenced,
                }
                .into());
            }
        }
        if let Some(guard) = &authorization {
            guard.check_tenant(run.tenant)?;
        }
        check_role_credentials(&run.config, authorization.as_deref())?;
        if let Some(evaluation) = evaluation {
            let guard = authorization.as_ref().ok_or_else(|| {
                WorkerError::PolicyDenied(
                    "fixture evaluation needs freshly admitted authorization".to_owned(),
                )
            })?;
            guard.check_now().await?;
            evaluation.check_run(run, guard.record())?;
            crate::fixture_evaluation::check_worker_config(evaluation.scope(), &run.config, cfg)?;
            if backend.is_some() {
                return Err(WorkerError::PolicyDenied(
                    "fixture evaluation requires the worker's real browser".to_owned(),
                ));
            }
        } else {
            cfg.check_gates(&run.config)?;
        }
        // A shared facade/worker store is not the run's owner; bind this wrapper to
        // the admitted run before constructing actor and checkpoint services.
        stores.tenant = run.tenant;
        let models = ModelServices::from_request_config(
            cfg.model.as_ref(),
            cfg.planner.as_ref(),
            &cfg.gates,
            run.config.dynamic.system1_mode,
            evaluation,
        )?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let crawl = run.config.clone();
        let captcha_secrets = crawlx_core::captcha::CaptchaSecrets::default();
        let captcha = if let Some(config) = &crawl.crawl.captcha {
            config.validate().map_err(BrowserError::from)?;
            let key = secrets
                .resolve(&config.key_ref)
                .await
                .map_err(|_| BrowserError::from(crawlx_core::captcha::CaptchaError::Configuration))?;
            captcha_secrets
                .register(key.clone())
                .map_err(BrowserError::from)?;
            Some(crawlx_core::captcha::CaptchaCredentials::new(config.clone(), key))
        } else {
            None
        };
        // a browser plane that ignores robots.txt needs the authorization record (admission
        // checks the record's content; this refuses a run that arrives here without one)
        if crawl.mode != CrawlMode::Static && crawl.dynamic.enabled && crawl.scrape.is_none() {
            RobotsGate::check_override(&crawl)?;
        }
        // the record (when the run has one) bounds the robots.txt fetches too
        let record = authorization.as_ref().map(|guard| guard.record());
        let origin_cap = stores.origin_cap(
            cfg,
            run.id,
            usize::from(crawl.politeness.max_in_flight_per_origin),
        );
        let origin_governor = Arc::new(crawlx_fetch::OriginGovernor::with_global_cap(
            GovernorConfig::from_politeness(&crawl.politeness, run.seed),
            origin_cap,
        ));
        if let Some(orchestration) = &crawl.orchestration {
            origin_governor.set_pacing_dialect(
                orchestration.pacing_dialect,
                u32::from(crawl.politeness.max_in_flight_per_origin.max(1)),
            );
        }
        let (robots_fetcher, delivery_resolver) = build_fetcher(
            &crawl,
            run.seed,
            cfg,
            controls.clone(),
            record,
            Arc::clone(&origin_governor),
        )?;
        let delivery_authority = Arc::new(crate::delivery::DeliveryAuthority {
            policy: Arc::new(cfg.egress.policy_for_run(&crawl, record)),
            resolver: delivery_resolver,
            governor: Arc::clone(&origin_governor),
            cancel: cancel.clone(),
        });
        cfg.delivery.register_authority(run.id, &delivery_authority);
        let robots = RobotsGate::for_crawl(
            &crate::url_plane::effective_crawl(crawl.clone()),
            robots_fetcher,
            Arc::clone(&clock),
        );
        let kernel = Arc::new(build_kernel(&crawl, Arc::clone(&clock), record)?);
        let mut pool_cfg = PoolConfig::with_contexts(cfg.contexts_per_browser);
        let mut launch = cfg.launch_config();
        // Names are logical encrypted catalog identities, never legacy tenant/name directories.
        if crawl.dynamic.browser_profile.is_some() {
            if cfg.retained_profiles.is_none()
                || stores.pg.is_none()
                || crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr
            {
                return Err(WorkerError::Config("profile_unavailable: retained profiles require operator approval, encryption key and PostgreSQL fence; zdr forbids them".into()));
            }
            if stores.custody.is_some() {
                return Err(WorkerError::Config(
                    "profile_unavailable: retained browser profiles are unavailable while encrypted artifact custody is enabled"
                        .into(),
                ));
            }
            launch.profiles_dir = Some(std::path::PathBuf::from(crate::profile_lifecycle::PROFILE_TMPFS));
        }
        if crawl.dynamic.browser_profile.is_some() && cfg.cdp_ws_url.is_some() {
            return Err(WorkerError::Config(
                "dynamic.browserProfile needs a browser this worker launches, not an attached one (cdp_ws_url)"
                    .to_owned(),
            ));
        }
        if let Some(ws) = &cfg.cdp_ws_url {
            if !matches!(
                crawl.safety.profile,
                SafetyProfile::TestEnvironment | SafetyProfile::AuthorizedSecurityTest
            ) {
                return Err(WorkerError::PolicyDenied(
                    "browser attach requires test_environment or authorized_security_test".to_owned(),
                ));
            }
            launch.cdp_ws_url = Some(ws.clone());
            pool_cfg.max_browsers = 1;
        } else if !cfg.incognito {
            return Err(WorkerError::Config(
                "incognito = false requires browser attach mode (cdp_ws_url)".to_owned(),
            ));
        }
        if crawl.capture.backend == CaptureBackend::Proxy {
            // the proxy cannot see QUIC: force HTTP/1.1 and HTTP/2 (`protocols_disabled = [h3]`)
            launch.extra_args.push("--disable-quic".to_owned());
        }
        // a backend that does not model a guard (scripted test sites) is left unchecked
        let browser_robots = backend.as_ref().is_none_or(|b| b.honours_navigation_guard());
        let pool = match backend {
            Some(b) => BrowserPool::with_backend_config(b, pool_cfg),
            None => BrowserPool::new(launch, pool_cfg),
        };
        // capture contract (`late` = started after settle) on the default backend;
        // `with_proxy_capture` replaces this wrapper for the proxy backend
        let wrap_clock = Arc::clone(&clock);
        let wrap_captcha_secrets = captcha_secrets.clone();
        let pool = pool.with_context_wrapper(Arc::new(move |session, ctx| {
            crate::capture::wrap_cdp(
                session,
                Arc::clone(&wrap_clock),
                ctx,
                wrap_captcha_secrets.clone(),
            )
        }));
        let started = run.started_at.unwrap_or_else(|| clock.now());
        let canon = canonicalize_options(&crawl, run.seed, run.id, cfg);
        let routes = RouteLearner::new(Arc::clone(&canon.templater));
        restore_routes(&routes, &stores, run.id).await?;
        let traffic_export = cfg
            .traffic_export
            .as_ref()
            .map(|c| TrafficExporter::new(c.clone()).map(Arc::new))
            .transpose()
            .map_err(|e| WorkerError::Config(format!("traffic export: {e}")))?;
        let protocol_registry = match &cfg.protocol_registry {
            Some(registry) => Some(Arc::clone(registry)),
            None => crate::protocol::ProtocolRegistry::from_operator_env().await?,
        };
        if crawl
            .protocol
            .routes
            .iter()
            .any(|route| route.backend == crawlx_core::protocol::ProtocolBackendV1::Delegate)
        {
            let registry = protocol_registry.as_ref().ok_or_else(|| {
                WorkerError::Config("protocol capability unavailable: operator registry absent".to_owned())
            })?;
            crate::protocol::ProtocolRuntime::new(
                Arc::clone(registry),
                &cfg.egress,
                &crawl,
                authorization.as_deref().map(|guard| guard.record()),
                Arc::clone(&origin_governor),
            )?
            .admit(
                &crawl.protocol.routes,
                run.id,
                run.tenant,
                &crawl.seed_url,
                crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr,
            )?;
        }
        Ok(Self {
            run: run.id,
            seed: run.seed,
            canon,
            routes,
            budget: Arc::new(Mutex::new(Budget::new(&crawl.limits, started))),
            crawl,
            stores,
            clock,
            pool,
            supervisor: Supervisor::new(),
            kernel,
            clusters: RunClusters::new(),
            counters: RunCounters::from_snapshot(run.counters),
            secrets,
            checkpoint_keys,
            captcha,
            request_identity_key: cfg.request_identity_key.clone(),
            captcha_secrets,
            worker: cfg.worker_id,
            cancel,
            egress_port: proxy.map(EgressProxyHandle::port),
            egress: cfg.egress.clone(),
            protocol_registry,
            models,
            gates: cfg.gates.clone(),
            incognito: cfg.incognito,
            retained_profiles: cfg.retained_profiles.clone(),
            capture: None,
            cpu_pool: cfg.cpu_pool.clone(),
            article_language_detector: cfg.article_language_detector.clone(),
            controls,
            traffic_export,
            secret_validators: cfg.secret_validators.clone(),
            form_ai: cfg.form_ai.clone(),
            action_trace: cfg.action_trace.clone(),
            diagnostics: DiagnosticsSink::default(),
            xhr: XhrSink::default(),
            robots,
            origin_governor,
            delivery: Arc::clone(&cfg.delivery),
            delivery_authority,
            browser_robots,
            authorization,
        })
    }

    /// Record `traffic_events` from the proxy source instead of CDP (`capture.backend =
    /// "proxy"`): every context the pool hands out is decorated with
    /// [`crate::capture::CaptureContext`] in proxy mode. Call before any session starts.
    #[must_use]
    pub fn with_proxy_capture(mut self, capture: Arc<ProxyCapture>) -> Self {
        let clock = Arc::clone(&self.clock);
        let wrap = Arc::clone(&capture);
        let captcha_secrets = self.captcha_secrets.clone();
        self.pool = self.pool.with_context_wrapper(Arc::new(move |session, ctx| {
            crate::capture::wrap_proxy(&wrap, session, Arc::clone(&clock), ctx, captcha_secrets.clone())
        }));
        self.capture = Some(capture);
        self
    }

    /// Attach this run's body retention policy before a fetcher reaches any consumer.
    ///
    /// # Errors
    /// Returns a configuration error if another consumer already owns the fetcher.
    pub(crate) fn capture_fetcher(&self, fetcher: Arc<Fetcher>) -> Result<Arc<Fetcher>, WorkerError> {
        if self.crawl.capture.response_bodies == crawlx_core::config::ResponseBodies::MetadataOnly {
            return Ok(fetcher);
        }
        let body_limit = fetcher.config().max_body_bytes;
        let sink = Arc::new(
            crate::capture::RetainedBodySink::new(
                self.run,
                Arc::clone(&self.stores.artifacts),
                self.controls.clone(),
                self.crawl.retention.mode,
                self.seed.derive("traffic-redaction", &[self.run.0.as_bytes()]),
                self.captcha_secrets.clone(),
            )
            .with_body_limit(body_limit),
        );
        let fetcher = Arc::try_unwrap(fetcher).map_err(|_| {
            WorkerError::Config("fetcher shared before response body policy was attached".to_owned())
        })?;
        Ok(Arc::new(fetcher.with_response_body_sink(
            self.crawl.capture.response_bodies,
            sink,
            self.crawl.seed_url.clone(),
        )))
    }

    /// Replace the run's cluster index (seeded ids for an in-process run, see
    /// [`RunClusters::seeded`]).
    #[must_use]
    pub fn with_clusters(mut self, clusters: RunClusters) -> Self {
        self.clusters = clusters;
        self
    }

    /// Deliver what the traffic exporter still holds and stop it, and close the browsers that
    /// run in a named persistent profile cleanly so the profile is flushed to disk. Called once
    /// when the run ends, on every path (completion, error, cancellation).
    pub async fn finish_traffic(&self) {
        if let Some(exporter) = &self.traffic_export {
            exporter.flush().await;
            exporter.shutdown().await;
        }
        // a named profile is only saved by a browser that exits cleanly
        self.pool.shutdown_persistent().await;
    }

    /// The `-form-config` values the browser plane types into matching text fields
    /// (`extract.formFill`, only while it is enabled), with `rand_*` helpers evaluated for the
    /// run's seed exactly as the URL plane evaluates them. Empty when nothing is configured.
    #[must_use]
    pub fn form_values(&self) -> crawlx_forms::ConfiguredValues {
        let resolved =
            crawlx_extract::form_fill::configured_values(&self.crawl.extract.form_fill, &self.seed);
        crawlx_forms::ConfiguredValues {
            email: resolved.email,
            phone: resolved.phone,
            password: resolved.password,
            placeholder: resolved.placeholder,
        }
    }

    /// `scheme://host[:port]` of the seed.
    #[must_use]
    pub fn seed_origin(&self) -> String {
        self.crawl.seed_url.origin().ascii_serialization()
    }

    /// The seed as a canonical URL.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub fn seed_url(&self) -> Result<CanonicalUrl, WorkerError> {
        Canonicalizer::canonicalize_url(&self.crawl.seed_url, &self.canon)
            .map_err(|e| WorkerError::Config(format!("seed URL: {e}")))
    }

    #[must_use]
    /// Services.
    pub fn services(&self) -> SessionServices {
        SessionServices {
            tenant: self.stores.tenant,
            checkpoint_keys: Arc::clone(&self.checkpoint_keys),
            journal: Arc::clone(&self.stores.journal),
            runs: Arc::clone(&self.stores.runs),
            events: Arc::clone(&self.stores.events),
            states: Arc::clone(&self.stores.states),
            checkpoints: Arc::clone(&self.stores.checkpoints),
            artifacts: Arc::clone(&self.stores.artifacts),
            kernel: Arc::clone(&self.kernel),
            clock: Arc::clone(&self.clock),
            pool: self.pool.clone(),
            supervisor: self.supervisor.clone(),
        }
    }

    /// Acquire one strict role-pinned identity under the scheduler's existing lease.
    /// The actual browser build is measured before the actor receives any command.
    pub(crate) async fn acquire_bound_session(
        &self,
        lease: &SessionLease,
        cfg: &mut SessionConfig,
    ) -> Result<crate::pool::PooledContext, WorkerError> {
        use crawlx_core::session_binding::{SessionBindingV1, SessionIdentityV1};
        if !self.checkpoint_keys.is_available() {
            return Err(WorkerError::Config(
                "browser checkpoints require CRAWLX_CHECKPOINT_KMS_KEY_ID".into(),
            ));
        }
        let retained = self.crawl.dynamic.browser_profile.is_some();
        let profile_key = if retained {
            Some(crate::profile_lifecycle::ProfileRun::encryption(self).await?)
        } else {
            None
        };
        // CAPTCHA tokens register run-wide under this session's fence before page delivery.
        cfg.context.secret_registrar = self.stores.secret_registrar(
            self.stores.session_producer(self.run, lease),
            &self.captcha_secrets,
        );
        let mut acquisition_config = cfg.context.clone();
        if retained {
            if self.retained_profiles.is_none() || self.stores.pg.is_none() {
                return Err(WorkerError::Config(
                    "profile_unavailable: operator policy and existing lease required".into(),
                ));
            }
            acquisition_config.browser_profile = None;
            acquisition_config.incognito = true;
        }
        let pooled = self
            .pool
            .acquire(acquisition_config, retained || cfg.exclusive_browser)
            .await?;
        let metadata = self.stores.runs.get_metadata(self.run).await?;
        let mut identity = SessionIdentityV1::new(
            metadata.tenant,
            &lease.session,
            Digest::of_value(
                "crawlx/session-acquisition/v1",
                &(
                    cfg.context.launch_profile,
                    if retained { false } else { cfg.context.incognito },
                    cfg.context.page_hooks,
                    cfg.context.stealth_patches,
                    cfg.context.max_tabs,
                ),
            )
            .map_err(|error| WorkerError::Config(error.to_string()))?,
            Digest::of_value("crawlx/session-backend-build/v1", &pooled.build)
                .map_err(|error| WorkerError::Config(error.to_string()))?,
            Digest::keyed(
                &self.seed.derive("session-egress", &[]),
                "crawlx/session-egress/v1",
                self.egress
                    .proxy_for(&self.crawl)?
                    .map_or("direct", url::Url::as_str)
                    .as_bytes(),
            ),
            metadata.config_digest,
            self.crawl
                .dynamic
                .browser_profile
                .as_ref()
                .map(|profile| Digest::of("crawlx/session-profile/v1", profile.name.as_bytes())),
        );
        // Login is outside the exploration clock. Reserve only its bounded envelope;
        // session_body narrows this to the measured, durably credited deadline before
        // exploration starts. Operator authorization and retained-profile TTL never move.
        let expiry = self
            .budget
            .lock()
            .deadline()
            .checked_add_signed(cfg.login_allowance)
            .ok_or_else(|| WorkerError::Config("session binding expiry overflow".into()))?;
        let expiry = self
            .authorization
            .as_ref()
            .map_or(expiry, |guard| expiry.min(guard.record().valid_to));
        let (pooled, profile) = if retained {
            let build = pooled.build.clone();
            let (context, _, capacity) = pooled.into_parts();
            let closed = tokio::time::timeout(std::time::Duration::from_secs(5), context.close()).await;
            capacity.release(matches!(closed, Ok(Ok(())))).await?;
            let (cipher, egress) = profile_key
                .ok_or_else(|| WorkerError::Config("profile_unavailable: operator key missing".into()))?;
            let profile =
                crate::profile_lifecycle::ProfileRun::prepare(self, lease, &identity, cfg, cipher, egress)
                    .await?;
            identity = profile.identity().clone();
            let pooled = self.pool.acquire(cfg.context.clone(), true).await?;
            if pooled.build != build {
                let (context, _, capacity) = pooled.into_parts();
                let closed = tokio::time::timeout(std::time::Duration::from_secs(5), context.close()).await;
                capacity.release(matches!(closed, Ok(Ok(())))).await?;
                return Err(WorkerError::Config(
                    "profile_unavailable: browser build changed after profile compatibility check".into(),
                ));
            }
            (pooled, Some(profile))
        } else {
            (pooled, None)
        };
        let expiry = profile
            .as_ref()
            .map_or(expiry, |profile| expiry.min(profile.expires_at()));
        let binding = if let Some(pg) = &self.stores.pg {
            let binding = match pg.bind_session(lease, identity, expiry).await {
                Ok(binding) => binding,
                Err(error) => {
                    let (context, _, capacity) = pooled.into_parts();
                    let closed =
                        tokio::time::timeout(std::time::Duration::from_secs(5), context.close()).await;
                    capacity.release(matches!(closed, Ok(Ok(())))).await?;
                    return Err(error.into());
                }
            };
            cfg.binding_owner = Some((pg.clone(), lease.clone()));
            binding
        } else {
            cfg.local_lease_owner = Some((Arc::clone(&self.stores.leases), lease.clone()));
            SessionBindingV1::new(identity, lease.fencing_token, expiry)
        };
        cfg.context.session_binding = Some(binding);
        Ok(match profile {
            Some(profile) => pooled.with_profile(profile),
            None => pooled,
        })
    }

    /// Browser context settings of a session: launch profile, egress proxy, tab policy,
    /// `dynamic.pageHooks` and `dynamic.pageHookOptions`, `dynamic.stealthPatches`,
    /// the worker's `incognito` setting, the run's named persistent profile
    /// (the default browser context: only it is written to the profile directory) and the
    /// run's request controls (headers, cookies, `User-Agent`, TLS verification).
    #[must_use]
    pub fn context_config(&self, session: crawlx_core::SessionId) -> ContextConfig {
        let mut c = ContextConfig::new(session);
        c.launch_profile = self.crawl.dynamic.launch_profile;
        c.egress_proxy_port = self.egress_port;
        c.max_tabs = self.crawl.dynamic.max_tabs;
        c.synthetic_click_allowed = self.crawl.dynamic.synthetic_click;
        c.console_capture = self.crawl.dynamic.launch_profile != LaunchProfile::Stealth;
        c.page_hooks = self.crawl.dynamic.page_hooks;
        c.page_hook_options = self.crawl.dynamic.page_hook_options;
        c.stealth_patches = self.crawl.dynamic.stealth_patches;
        c.incognito = self.incognito;
        c.request_controls = self.controls.clone();
        c.response_bodies = self.crawl.capture.response_bodies;
        if c.response_bodies != crawlx_core::config::ResponseBodies::MetadataOnly {
            c.response_body_sink = Some(Arc::new(crate::capture::RetainedBodySink::new(
                self.run,
                Arc::clone(&self.stores.artifacts),
                self.controls.clone(),
                self.crawl.retention.mode,
                self.seed.derive("traffic-redaction", &[self.run.0.as_bytes()]),
                self.captcha_secrets.clone(),
            )));
        }
        c.captcha.clone_from(&self.captcha);
        c.captcha_cancel = self.cancel.clone();
        c.captcha_secrets = self.captcha_secrets.clone();
        // A context built under a producer scope (session body, leased URL row) registers its
        // CAPTCHA tokens run-wide under that producer's fence.
        c.secret_registrar = crawlx_core::custody::current_producer()
            .and_then(|producer| self.stores.secret_registrar(producer, &self.captcha_secrets));
        if let Some(gate) = self.browser_guard() {
            // every document the browser loads is checked against `robots.txt` first;
            // a run that ignores it navigates unchecked
            c.navigation_guard = Some(Arc::new(gate.clone()));
        }
        c
    }

    /// The gate the run's browser contexts consult before every document they load, and the
    /// driver before it queues a discovered URL: `None` when the run ignores `robots.txt` or its
    /// backend does not honour a navigation guard ([`BrowserBackend::honours_navigation_guard`]).
    #[must_use]
    pub fn browser_guard(&self) -> Option<&RobotsGate> {
        (self.browser_robots && self.robots.obeys()).then_some(&self.robots)
    }

    /// `SessionConfig` of `session`.
    #[must_use]
    pub fn session_config(&self, session: &CrawlSession) -> SessionConfig {
        let role = self
            .crawl
            .effective_roles()
            .into_iter()
            .find(|r| r.name == session.role.0);
        let mut cfg = SessionConfig::new(self.run, session.id, session.role.clone(), self.seed_origin());
        cfg.context = self.context_config(session.id);
        let strict = self.crawl.safety.profile == SafetyProfile::AuthorizedSecurityTest;
        cfg.exclusive_browser = strict;
        if strict {
            cfg.epoch_policy = crawlx_core::epoch::EpochPolicy::strict();
        }
        cfg.awaits_login = role.as_ref().is_some_and(|r| r.credential_ref.is_some());
        cfg.login_url = self.seed_url().ok();
        cfg.canonicalize = self.canon.clone();
        cfg.identity_version = self.crawl.crawl.identity.version;
        cfg.observer.canonicalize = self.canon.clone();
        cfg.settle = QuiescencePolicy::for_dynamic(&self.crawl.dynamic);
        cfg.apply_dynamic(&self.crawl.dynamic);
        cfg.traffic_export.clone_from(&self.traffic_export);
        cfg.origin_governor = Arc::clone(&self.origin_governor);
        cfg.origin_cancel = self.cancel.clone();
        cfg.action_trace.clone_from(&self.action_trace);
        cfg.extension_cpu = (self.crawl.extensions.configured()
            || self.crawl.datasets.article_dataset.is_some()
            || self
                .crawl
                .datasets
                .stores
                .iter()
                .any(|s| s.schema_version == "document_v1"))
        .then(|| self.cpu_pool.clone());
        cfg.article_language_detector
            .clone_from(&self.article_language_detector);
        cfg
    }

    /// Reserve the role's bounded login envelope before acquiring its browser binding.
    pub(crate) async fn prepare_session_login(
        &self,
        session: &CrawlSession,
        cfg: &mut SessionConfig,
    ) -> Result<Option<LoginMaterial>, WorkerError> {
        let material = self.login_material(&session.role.0).await?;
        cfg.login_allowance = material
            .as_ref()
            .map_or(chrono::Duration::zero(), crate::login::login_allowance);
        let mut role_budget = crate::role_budget::RoleBudget::load(self, session).await?;
        if material.is_some() {
            role_budget.reserve_login(self, cfg.login_allowance).await?;
        }
        cfg.execution_deadline = Some(
            role_budget
                .deadline()
                .min(self.budget.lock().deadline())
                .checked_add_signed(cfg.login_allowance)
                .ok_or_else(|| WorkerError::Config("session execution deadline overflow".into()))?,
        );
        Ok(material)
    }

    /// Authenticate within the reserved envelope and binding ceiling, then credit only
    /// measured login time. Recovery reloads the same durable role allocation.
    pub(crate) async fn login_session_bounded(
        &self,
        session: &CrawlSession,
        handle: &crate::actor::SessionHandle,
        analyzer: &StateAnalyzer,
        material: LoginMaterial,
        bounds: LoginBounds,
    ) -> Result<(), WorkerError> {
        let mut role_budget = crate::role_budget::RoleBudget::load(self, session).await?;
        let started = self.clock.now();
        let allowance = bounds.binding_deadline.map_or(bounds.allowance, |deadline| {
            bounds.allowance.min(deadline.signed_duration_since(started))
        });
        let logged_in = if allowance <= chrono::Duration::zero() {
            Err(SessionError::LoginFailed("login deadline reached".into()))
        } else {
            tokio::time::timeout(
                allowance.to_std().unwrap_or_default(),
                crate::login::login_session(handle, self, session, analyzer, material),
            )
            .await
            .unwrap_or_else(|_| Err(SessionError::LoginFailed("login deadline reached".into())))
        };
        let spent = self.clock.now().signed_duration_since(started);
        let accounting = async {
            role_budget.credit_login(self, spent).await?;
            if spent.num_milliseconds() <= 0 {
                role_budget.reserve_login(self, chrono::Duration::zero()).await?;
            }
            // Loading reconciles the absolute durable clock without double-crediting it.
            let role_budget = crate::role_budget::RoleBudget::load(self, session).await?;
            let deadline = role_budget.deadline().min(self.budget.lock().deadline());
            handle.narrow_binding_deadline(deadline).await?;
            Ok(())
        }
        .await;
        if accounting.is_err() {
            tracing::warn!(
                session = %session.id,
                primary_failed = logged_in.is_err(),
                "login accounting or binding narrowing failed"
            );
        }
        match logged_in {
            Err(error) => Err(error.into()),
            Ok(_) => accounting,
        }
    }

    /// Resolve the role's credential after validating its complete login plan.
    /// `loginPlan` accepts `builtin:form`, `recorded:<json>`, `recorded:file://<path>`,
    /// or `recorded:artifact://<json descriptor>`. The strict, at most 4096-byte
    /// descriptor contains `tenant`, `run`, `sensitivity: "content"` and
    /// `artifact: {id, digest}`. `run` names the source run, which may differ
    /// from this target run. The artifact must belong to this tenant and the
    /// named source run and pass retention, the artifact-only 1 MiB limit and
    /// fixity checks. Inline and file flows retain their existing size semantics.
    /// Every source uses the same recorded-flow parser and actor.
    ///
    /// # Errors
    /// [`SessionError::LoginFailed`] when the credential cannot be resolved or parsed, or the
    /// plan is neither `builtin:form` nor a parseable recorded flow.
    pub async fn login_material(&self, role: &str) -> Result<Option<LoginMaterial>, SessionError> {
        let Some(r) = self.crawl.effective_roles().into_iter().find(|r| r.name == role) else {
            return Ok(None);
        };
        let Some(reference) = r.credential_ref else {
            return Ok(None);
        };
        let plan = crate::login::resolve_login_plan(&self.stores, r.login_plan.as_deref()).await?;
        let secret = self
            .secrets
            .resolve(&reference)
            .await
            .map_err(|e| SessionError::LoginFailed(e.to_string()))?;
        // every resolution is audited by reference hash and purpose, never value.
        let _ = self
            .stores
            .events
            .append(
                self.run,
                "secret.resolved",
                serde_json::json!({
                    "role": role,
                    "scheme": reference.scheme(),
                    "reference_hash": Digest::of("crawlx/worker/credential-ref", reference.0.as_bytes()).to_hex(),
                    "purpose": "login",
                }),
            )
            .await;
        let credential =
            LoginCredential::parse(&secret).map_err(|e| SessionError::LoginFailed(e.to_string()))?;
        Ok(Some(LoginMaterial { plan, credential }))
    }
}

/// Outcome of one session.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct SessionEnd {
    /// Terminal.
    pub terminal: TerminalReason,
    /// Error.
    pub error: Option<String>,
}

/// Run one leased session: actor, login, exploration, release. Never panics the caller.
pub async fn run_session(
    rc: Arc<RunContext>,
    scheduler: Scheduler,
    lease: SessionLease,
    start_requests: impl Future<Output = Result<Vec<crawlx_core::request::RequestEnvelopeV1>, WorkerError>> + Send,
    driver: DriverConfig,
    strategies: Option<Vec<Arc<dyn crawlx_strategies::Strategy>>>,
) -> SessionEnd {
    // Every artifact the session (and the tasks it spawns) retains is published under this
    // session lease's fence.
    let producer = rc.stores.session_producer(rc.run, &lease);
    crawlx_core::custody::with_producer(
        producer,
        Box::pin(run_session_scoped(
            rc,
            scheduler,
            lease,
            start_requests,
            driver,
            strategies,
        )),
    )
    .await
}

async fn run_session_scoped(
    rc: Arc<RunContext>,
    scheduler: Scheduler,
    lease: SessionLease,
    start_requests: impl Future<Output = Result<Vec<crawlx_core::request::RequestEnvelopeV1>, WorkerError>> + Send,
    driver: DriverConfig,
    strategies: Option<Vec<Arc<dyn crawlx_strategies::Strategy>>>,
) -> SessionEnd {
    let session = lease.session.clone();
    let keepalive_cancel = CancellationToken::new();
    let keepalive = scheduler.keep_alive(lease.clone(), HEARTBEAT_INTERVAL, keepalive_cancel.clone());
    let cancel_on_lease_loss = rc.cancel.clone();
    let keepalive = tokio::spawn(async move {
        let result = keepalive
            .await
            .map_err(WorkerError::SessionHeartbeatTask)
            .and_then(|result| result.map_err(WorkerError::from));
        if result.is_err() {
            cancel_on_lease_loss.cancel();
        }
        result
    });
    // Hybrid inputs wait under this same lease heartbeat, before acquiring browser capacity.
    let starts = tokio::select! {
        biased;
        () = rc.cancel.cancelled() => None,
        starts = start_requests => Some(starts),
    };
    let mut result = match starts {
        Some(Ok(requests)) => session_body(&rc, &session, &lease, requests, driver, strategies).await,
        Some(Err(error)) => Err(error),
        None => Ok(SessionEnd {
            terminal: TerminalReason::Cancelled,
            error: None,
        }),
    };
    keepalive_cancel.cancel();
    let heartbeat = keepalive
        .await
        .map_err(WorkerError::SessionHeartbeatTask)
        .and_then(|result| result);
    // The authorization guard also cancels the run token. That fatal stop must not
    // become a resumable worker drain, including while hybrid inputs are pending.
    if matches!(
        &result,
        Ok(SessionEnd {
            terminal: TerminalReason::Cancelled,
            ..
        }) | Err(WorkerError::Session(SessionError::Cancelled))
    ) {
        if let Some(stop) = rc.authorization.as_ref().and_then(|guard| guard.stop()) {
            result = Err(stop.into());
        }
    }
    // A failed heartbeat cancels the run to stop dispatch; cancellation is its
    // consequence, not a graceful handover. Preserve independent primary failures.
    let result = match (result, heartbeat) {
        (Err(WorkerError::Session(SessionError::Cancelled)), Err(error)) => Err(error),
        (result, heartbeat) => crate::replay::finish_replay(result, heartbeat, Ok(())),
    };
    let (end, release) = match result {
        Ok(end) => {
            let status = if rc.cancel.is_cancelled() && end.terminal == TerminalReason::Cancelled {
                SessionStatus::Recovering
            } else {
                SessionStatus::Completed
            };
            (end, status)
        }
        Err(WorkerError::Session(SessionError::Cancelled)) if rc.cancel.is_cancelled() => (
            SessionEnd {
                terminal: TerminalReason::Cancelled,
                error: None,
            },
            SessionStatus::Recovering,
        ),
        Err(e) => {
            tracing::error!(session = %session.id, error = %e, "session failed");
            let terminal = match &e {
                WorkerError::Session(error) if error.is_recovery_exhausted() => {
                    TerminalReason::RecoveryExhausted
                }
                WorkerError::Authorization(_) => TerminalReason::AuthorizationRevoked,
                _ => TerminalReason::FatalError,
            };
            (
                SessionEnd {
                    terminal,
                    error: Some(e.to_string()),
                },
                SessionStatus::Failed,
            )
        }
    };
    if let Err(e) = scheduler.release(&lease, release).await {
        tracing::warn!(session = %session.id, error = %e, "session lease not released cleanly");
    }
    end
}

async fn session_body(
    rc: &Arc<RunContext>,
    session: &CrawlSession,
    lease: &SessionLease,
    mut start_requests: Vec<crawlx_core::request::RequestEnvelopeV1>,
    driver_cfg: DriverConfig,
    strategies: Option<Vec<Arc<dyn crawlx_strategies::Strategy>>>,
) -> Result<SessionEnd, WorkerError> {
    // a session never starts under a record that is revoked or expired
    if let Some(guard) = &rc.authorization {
        guard.check_now().await?;
    }
    let mut role_budget = crate::role_budget::RoleBudget::load(rc, session).await?;
    if let Some(terminal) = role_budget
        .exhausted(rc.clock.now())
        .filter(|_| session.status != SessionStatus::Recovering)
    {
        if terminal == TerminalReason::DeadlineReached {
            if let Some(guard) = &rc.authorization {
                guard.check_execution_stop().await?;
            }
        }
        return Ok(SessionEnd {
            terminal,
            error: None,
        });
    }
    let mut cfg = rc.session_config(session);
    let login = rc.prepare_session_login(session, &mut cfg).await?;
    let pooled = rc.acquire_bound_session(lease, &mut cfg).await?;
    let login_bounds = LoginBounds::from(&cfg);
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
        rc.clusters.sync(rc.stores.states.as_ref(), rc.run).await?;
    }
    let handle = crate::actor::SessionActor::spawn(
        cfg.clone(),
        rc.services(),
        Arc::clone(&analyzer),
        rc.crawl.retention.days,
        pooled,
    )
    .await?;
    let run_span = spans::run_span(
        &rc.run,
        &session.id,
        &session.role.0,
        u32::from(session.run_index),
        rc.seed.0,
    );
    let outcome = async {
        if let Some(terminal) = role_budget
            .exhausted(rc.clock.now())
            .filter(|_| session.status != SessionStatus::Recovering)
        {
            return Ok(DriverEnd {
                terminal,
                actions: 0,
                states: 0,
            });
        }
        let seed = rc.seed_url()?;
        // Reuse the actual admitted seed intent when the URL plane flagged it.
        // Reconstructing a GET here would silently erase an imported handler label.
        let seed_request = start_requests
            .iter()
            .position(|request| request.url.url == seed.url)
            .map(|index| start_requests.remove(index))
            .unwrap_or_else(|| crawlx_core::request::RequestEnvelopeV1::get(seed.clone(), 0, None));
        match handle.navigate(seed_request.clone()).await {
            Ok(_) => {}
            // robots.txt disallows the seed itself: nothing was loaded and nothing is left to explore
            Err(SessionError::Browser(BrowserError::RobotsBlocked { reason, .. })) => {
                crate::driver::record_robots_blocked(rc, Some(session.id), &seed, 0, reason).await;
                return Ok(DriverEnd {
                    terminal: TerminalReason::FrontierExhausted,
                    actions: 0,
                    states: 0,
                });
            }
            Err(e) => return Err(e.into()),
        }
        // `crawl_sessions` has no cheap flag for it: the hooks setting is in the audit stream
        let _ = rc
            .stores
            .events
            .append(
                rc.run,
                "session.started",
                serde_json::json!({
                    "session_id": session.id.0,
                    "page_hooks": rc.crawl.dynamic.page_hooks || rc.crawl.dynamic.page_hook_options.any(),
                    "page_hook_options": rc.crawl.dynamic.page_hook_options.names(),
                    "stealth_patches": rc.crawl.dynamic.stealth_patches,
                    "browser_profile": rc.crawl.dynamic.browser_profile.as_ref().map(|p| p.name.as_str()),
                    "incognito": cfg.context.incognito,
                }),
            )
            .await;
        let mut authenticated = false;
        if let Some(material) = login {
            rc.login_session_bounded(session, &handle, &analyzer, material, login_bounds)
                .await?;
            authenticated = true;
            role_budget = crate::role_budget::RoleBudget::load(rc, session).await?;
        }
        let set = match strategies {
            Some(custom) => {
                let (strategies, arm_assignments) = crate::driver::select_strategy_arms(
                    &rc.crawl.dynamic,
                    &rc.gates,
                    rc.seed,
                    &session.role,
                    session.run_index,
                    custom,
                )?;
                StrategySet {
                    strategies,
                    overlay: ModelOverlay::default(),
                    system1: false,
                    arm_assignments,
                }
            }
            None => crate::driver::build_strategy_set(rc, session, driver_cfg.record_shortlists.is_some())?,
        };
        crate::driver::persist_strategy_arm_assignments(rc, session, &set.arm_assignments).await?;
        let mut driver = ExplorationDriver::new(
            driver_cfg,
            Arc::clone(rc),
            session.clone(),
            handle.clone(),
            Arc::clone(&analyzer),
            set.strategies,
        )
        .with_model_overlay(set.overlay, set.system1)
        .with_authenticated(authenticated)
        .with_role_budget(role_budget);
        let mut requests = vec![seed_request];
        requests.extend(start_requests);
        driver.run(requests).await
    }
    .instrument(run_span)
    .await;
    let outcome = match outcome.map(|end| end.terminal) {
        Ok(TerminalReason::DeadlineReached)
        | Err(WorkerError::Session(SessionError::ExecutionDeadlineReached)) => match &rc.authorization {
            Some(guard) => guard.check_execution_stop().await,
            None => Ok(()),
        }
        .map(|()| TerminalReason::DeadlineReached),
        other => other,
    };
    let reason = if rc.cancel.is_cancelled() {
        crate::actor::ShutdownReason::Graceful
    } else {
        crate::actor::ShutdownReason::Completed
    };
    let shutdown = handle.shutdown(reason).await.map_err(WorkerError::from);
    let end = crate::replay::finish_replay(outcome, shutdown, Ok(()))?;
    Ok(SessionEnd {
        terminal: end,
        error: None,
    })
}

/// Create the run and execute it to completion in this process.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub async fn run_local(crawl: CreateCrawl, cfg: WorkerConfig) -> Result<RunReport, WorkerError> {
    run_local_with(LocalRun::new(crawl, cfg)).await
}

/// [`run_local`] with injectable backend, stores, secrets, cancellation and strategies.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
#[must_use = "the run does not execute unless the future is polled"]
pub fn run_local_with(local: LocalRun) -> impl Future<Output = Result<RunReport, WorkerError>> {
    // One allocation per run prevents the full orchestration state machine from being
    // embedded in every caller's async frame. Nested scrape/dispatch frames otherwise
    // overflow ordinary executor stacks before bounded acquisition can start.
    Box::pin(run_local_inner(local))
}

async fn run_local_inner(local: LocalRun) -> Result<RunReport, WorkerError> {
    let LocalRun {
        mut crawl,
        mut cfg,
        backend,
        stores,
        secrets,
        cancel: hard_cancel,
        strategies,
        approvals,
        driver,
        authorization,
        authorization_source,
        resume,
        graceful_drain,
        fixture_evaluation,
    } = local;
    let cancel = hard_cancel.child_token();
    // JoinSet owns the relay: dropping this run aborts it instead of leaking a signal waiter.
    let mut drain_watch = tokio::task::JoinSet::new();
    if let Some(drain) = &graceful_drain {
        let drain = drain.clone();
        let cancelled = cancel.clone();
        drain_watch.spawn(async move {
            drain.cancelled().await;
            cancelled.cancel();
        });
    }
    if let Err(errs) = crawl.normalize() {
        return Err(WorkerError::Config(
            errs.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        ));
    }
    if let Some(permit) = &fixture_evaluation {
        let record = authorization.as_ref().ok_or_else(|| {
            WorkerError::PolicyDenied("fixture evaluation needs an explicit authorization record".to_owned())
        })?;
        permit.check_request(&crawl, record)?;
        crate::fixture_evaluation::check_worker_config(permit.scope(), &crawl, &cfg)?;
        if backend.is_some() || strategies.is_some() || resume.is_some() || secrets.is_some() {
            return Err(WorkerError::PolicyDenied(
                "fixture evaluation refuses injected backends, strategies, secrets or resume state"
                    .to_owned(),
            ));
        }
    } else {
        cfg.check_gates(&crawl)?;
        cfg.check_article_language(&crawl)?;
    }
    let mut stores = match stores {
        Some(s) => s,
        None => Stores::open(&cfg).await?,
    };
    if let Some(source) = authorization_source {
        stores = stores.with_authorization_source(source);
    }
    if let Some(record) = &authorization {
        stores.tenant = record.tenant;
    }
    if let (Some(pg), Some(record)) = (&stores.pg, &authorization) {
        let body = serde_json::to_value(record).map_err(|e| WorkerError::Other(e.to_string()))?;
        let digest = record.body_digest()?;
        pg.ensure_authorization_record(&crawlx_storage::AuthorizationRow {
            tenant: record.tenant,
            record: record.id,
            version: i32::try_from(record.version).unwrap_or(i32::MAX),
            body: &body,
            body_digest: &digest.0,
            valid_from: record.valid_from,
            valid_to: record.valid_to,
        })
        .await?;
    }
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    let now = clock.now();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: if fixture_evaluation.is_some() {
            RunStatus::Running
        } else {
            RunStatus::Queued
        },
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest()?,
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: now,
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    if let Some(pg) = &stores.pg {
        pg.ensure_tenant(stores.tenant, "local").await?;
    }
    stores.runs.create(&run, None).await?;
    // the record bounds the run (target, window, revocation); a record that is
    // already unusable ends the run before anything is requested
    let authz = match local_authorization(&run, authorization, &stores, &cfg, &clock).await {
        Ok(guard) => guard,
        Err(WorkerError::Authorization(stop)) => return finish_refused(&stores, run.id, &stop).await,
        Err(e) => {
            if fixture_evaluation.is_some() {
                stores.finish_run(run.id, TerminalReason::FatalError).await?;
            }
            return Err(e);
        }
    };
    let binding = fixture_evaluation
        .map(|permit| {
            let guard = authz.as_ref().ok_or_else(|| {
                WorkerError::PolicyDenied("fixture evaluation authorization was not admitted".to_owned())
            })?;
            permit.bind(&run, guard.record()).map_err(WorkerError::from)
        })
        .transpose();
    let fixture_evaluation = match binding {
        Ok(evaluation) => evaluation,
        Err(error) => {
            stores.finish_run(run.id, TerminalReason::FatalError).await?;
            return Err(error);
        }
    };
    if let Some(evaluation) = &fixture_evaluation {
        cfg.egress.fixture_scope = Some(evaluation.scope().clone());
        stores
            .events
            .append(
                run.id,
                "fixture_evaluation",
                serde_json::json!({
                    "authority": "controlled_fixture_evaluation",
                    "fixture": evaluation.fixture(),
                    "origin": evaluation.scope().origin().origin().ascii_serialization(),
                    "mode": crawl.dynamic.system1_mode,
                    "promotion": false,
                }),
            )
            .await?;
    }
    // the token the plane and sessions honour: the caller's cancellation or a lost authorization
    let run_cancel = cancel.child_token();
    if let Some(guard) = &authz {
        guard.cancels(run_cancel.clone());
    }
    let _authorization_watch = authz.as_ref().map(AuthorizationGuard::watch);
    let _fixture_watch = fixture_evaluation
        .as_ref()
        .map(|permit| permit.watch(run_cancel.clone()));
    // a scrape run (Firecrawl scrape, batch, crawl, map) never explores in browser sessions:
    // its pages come from the scrape engine, whose renderer opens its own browser contexts
    let dynamic = crawl.mode != CrawlMode::Static && crawl.dynamic.enabled && crawl.scrape.is_none();
    if dynamic {
        stores
            .runs
            .create_sessions(&RunPlanner::sessions(run.id, &crawl))
            .await?;
    }
    stores.runs.set_status(run.id, RunStatus::Running, None).await?;
    let run = stores.runs.get_for_execution(run.id).await?;

    // in proxy mode the egress proxy and the fetch plane report every flow to
    // one bounded channel; `ProxyTraffic` attributes the flows to epochs.
    let proxy_mode = dynamic && crawl.capture.backend == CaptureBackend::Proxy;
    let (flow_tx, capture) = if proxy_mode {
        let (tx, rx) = tokio::sync::mpsc::channel(FLOW_CHANNEL);
        let key = run.seed.derive("traffic-redaction", &[run.id.0.as_bytes()]);
        let mut source = crawlx_observe::ProxyTraffic::new(rx, crawlx_observe::Redactor::new(key));
        source.set_page_origin(crawl.seed_url.origin().ascii_serialization());
        (Some(tx), Some(ProxyCapture::new(source)))
    } else {
        (None, None)
    };
    let secrets = default_secrets(secrets).await;
    let controls = resolve_controls(&crawl, run.id, secrets.as_ref(), stores.events.as_ref()).await?;
    let origin_governor = Arc::new(crawlx_fetch::OriginGovernor::with_global_cap(
        GovernorConfig::from_politeness(&crawl.politeness, run.seed),
        stores.origin_cap(
            &cfg,
            run.id,
            usize::from(crawl.politeness.max_in_flight_per_origin),
        ),
    ));
    if let Some(orchestration) = &crawl.orchestration {
        origin_governor.set_pacing_dialect(
            orchestration.pacing_dialect,
            u32::from(crawl.politeness.max_in_flight_per_origin.max(1)),
        );
    }
    let (fetcher, resolver) = build_fetcher_with_capture(
        &crawl,
        run.seed,
        &cfg,
        controls.clone(),
        authz.as_ref().map(|g| g.record()),
        flow_tx.clone(),
        Arc::clone(&origin_governor),
    )?;
    let proxy = if dynamic || crate::scrape::needs_browser_renderer(&crawl, &cfg) {
        let mut options = EgressOptions::new().with_controls(controls.clone());
        if let Some(tx) = flow_tx {
            options = options.with_capture(tx);
        }
        Some(
            cfg.egress
                .serve_proxy(
                    &crawl,
                    authz.as_ref().map(|g| g.record()),
                    Arc::clone(&resolver),
                    options,
                )
                .await?,
        )
    } else {
        None
    };
    // this process owns every session of the run, so cluster ids can derive from the seed
    let salt: &[u8] = if stores.pg.is_some() {
        run.id.0.as_bytes()
    } else {
        &[]
    };
    let operator_backend = backend.is_some();
    let mut rc = RunContext::build_with_fixture_evaluation(
        &run,
        &cfg,
        stores.clone(),
        backend,
        secrets,
        run_cancel.clone(),
        proxy.as_ref(),
        controls,
        authz.clone(),
        fixture_evaluation.as_ref(),
    )
    .await?
    .with_clusters(RunClusters::seeded(run.seed, salt));
    rc.origin_governor = origin_governor;
    if let Some(approvals) = approvals {
        let kernel = Arc::try_unwrap(rc.kernel).map_err(|_| {
            WorkerError::Config("approval store must be installed before sharing the kernel".to_owned())
        })?;
        rc.kernel = Arc::new(kernel.with_approval_store(approvals));
    }
    let fetcher = rc.capture_fetcher(fetcher)?;
    if let Some(capture) = &capture {
        rc = rc.with_proxy_capture(Arc::clone(capture));
        let _ = stores
            .events
            .append(
                run.id,
                "capture.backend",
                serde_json::json!({
                    "backend": CaptureBackend::Proxy.as_str(),
                    "protocols_disabled": capture.protocols_disabled(),
                }),
            )
            .await;
    }
    let rc = Arc::new(rc);
    crate::acquisition::admit_runtime(&rc, &cfg, operator_backend, true).await?;

    let mut reasons = Vec::new();
    let mut dynamic_requests: Vec<crawlx_core::request::RequestEnvelopeV1> = Vec::new();
    let mut url_resume: Option<ResumeState> = None;
    let crawl_span = spans::crawl_span(
        &run.id,
        crawl_mode_name(crawl.mode),
        crawl.safety.profile.as_str(),
    );
    if let Some(t) = crawlx_telemetry::trace_id::trace_id_of(&crawl_span) {
        stores.runs.set_trace_id(run.id, t).await?;
    }
    let active = Metrics::global().gauge(names::CRAWLS_ACTIVE);
    active.add(1.0, &[]);
    let result: Result<(), WorkerError> = async {
        if crawl.mode != CrawlMode::Dynamic {
            let mut plane = UrlPlaneRunner::new(
                run.id,
                crawl.clone(),
                cfg.worker_id,
                UrlPlaneDeps {
                    runs: Arc::clone(&stores.runs),
                    frontier: Arc::clone(&stores.frontier),
                    request_commits: Arc::clone(&stores.request_commits),
                    leases: Arc::clone(&stores.leases),
                    pages: Arc::clone(&stores.pages),
                    events: Arc::clone(&stores.events),
                    artifacts: Arc::clone(&stores.artifacts),
                    archives: Arc::clone(&stores.archives),
                    clock: Arc::clone(&clock),
                },
                fetcher,
                rc.counters.clone(),
                rc.canon.clone(),
            )?
            .with_cpu_pool(rc.cpu_pool.clone())
            .with_route_learner(rc.routes.clone())
            .with_katana_services(&rc)
            .with_scrape_services(&rc, &cfg)
            .with_authorization(rc.authorization.clone());
            if let Some(drain) = &graceful_drain {
                plane = plane.with_graceful_drain(drain.clone(), Some(hard_cancel.clone()));
            }
            if let Some(state) = &resume {
                plane.seed_resume(state);
            }
            // Match leased execution: finite input must be sealed before draining.
            // Child discovery keeps using parent-fenced appends after that seal.
            plane.seed_if_empty().await?;
            // Allocate the large URL-lane state machine once per run, not inside
            // the already nested orchestration poll frame.
            let outcome = Box::pin(plane.run(&run_cancel)).await?;
            url_resume = Some(plane.resume_state()).filter(|s| !s.is_finished());
            reasons.push(outcome.terminal);
            dynamic_requests = outcome.dynamic_requests;
        }
        if dynamic && !run_cancel.is_cancelled() {
            reasons.extend(run_sessions(&rc, &cfg, dynamic_requests, driver, strategies).await?);
        }
        while !run_cancel.is_cancelled()
            && rc
                .delivery
                .drain_once(&stores, &run, rc.worker, clock.as_ref(), &rc.delivery_authority)
                .await?
                > 0
        {}
        Ok(())
    }
    .instrument(crawl_span)
    .await;
    rc.finish_traffic().await;
    active.add(-1.0, &[]);
    if let Err(e) = &result {
        tracing::error!(run = %run.id, error = %e, "run failed");
        reasons.push(TerminalReason::FatalError);
    }
    if authz.as_ref().is_some_and(|g| g.is_stopped()) {
        reasons.push(TerminalReason::AuthorizationRevoked);
    }
    if cancel.is_cancelled() {
        reasons.push(TerminalReason::Cancelled);
        // Session planning precedes URL-plane work and browser admission. Cancellation
        // can therefore leave sessions that never acquired a lease, including later
        // rounds after active sessions drained. They have no actor state to recover.
        for session in stores.runs.list_sessions(run.id).await? {
            if session.status == SessionStatus::Pending {
                stores
                    .runs
                    .set_session_status(session.id, SessionStatus::Cancelled)
                    .await?;
            }
        }
    }
    let mut reason = merge_reasons(&reasons);
    rc.counters.persist(stores.runs.as_ref(), run.id).await?;
    if rc.crawl.extract.xhr {
        rc.xhr.apply(stores.pages.as_ref(), run.id).await?;
    }
    if !cancel.is_cancelled() {
        loop {
            match crate::archive_recorder::finalize(&stores, &run, Arc::clone(&clock), &cancel, reason)
                .await?
            {
                crate::archive_recorder::Finalization::Ready => break,
                crate::archive_recorder::Finalization::Failed => {
                    reason = TerminalReason::FatalError;
                    break;
                }
                crate::archive_recorder::Finalization::Busy => tokio::select! {
                    () = cancel.cancelled() => break,
                    () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                },
            }
        }
    }
    stores.finish_run(run.id, reason).await?;
    let mut report = build_report(&stores, run.id).await?;
    report.browser_launches = rc.pool.launches();
    report.resume = url_resume;
    report.diagnostics = rc.diagnostics.take();
    let _ = stores
        .events
        .append(
            run.id,
            "completed",
            serde_json::json!({
                "status": report.status.as_str(),
                "terminalReason": reason.as_str(),
                "counters": report.counters,
            }),
        )
        .await;
    rc.supervisor.shutdown().await;
    if let Some(p) = proxy {
        report.egress = EgressCapture {
            dialed_hosts: p.dialed_hosts(),
            denied_events: p.denied_events(),
        };
        if let Some(capture) = &capture {
            let stats = capture.stats();
            let pending = capture.pending();
            observe_capture(&stats);
            report.capture = CaptureReport {
                backend: CaptureBackend::Proxy,
                protocols_disabled: capture.protocols_disabled(),
                proxy: Some(stats),
            };
            let _ = stores
                .events
                .append(
                    run.id,
                    "capture.proxy.summary",
                    serde_json::json!({
                        "flows": stats.flows,
                        "cdp_matched": stats.cdp_matched,
                        "window_matched": stats.window_matched,
                        "late": stats.late,
                        "unmatched_proxy_flows": stats.unmatched,
                        "traffic_unattributed": stats.unattributed,
                        "pending_at_end": pending,
                        "proxy_capture_dropped": p.capture_dropped(),
                    }),
                )
                .await;
        }
        p.shutdown().await;
    }
    result?;
    Ok(report)
}

/// Enforce the common account-reference policy before resolving any role credentials.
///
/// # Errors
/// Returns a configuration error for undeclared roles or mismatched credential references.
pub(crate) fn check_role_credentials(
    crawl: &CreateCrawl,
    guard: Option<&AuthorizationGuard>,
) -> Result<(), WorkerError> {
    let errors =
        crawlx_policy::AdmissionPolicy::check_role_credentials(crawl, guard.map(AuthorizationGuard::record));
    if errors.is_empty() {
        Ok(())
    } else {
        Err(WorkerError::Config(
            "role credentials require matching testAccounts in the selected authorization record".to_owned(),
        ))
    }
}

/// The authorization guard of an in-process run, or `None` when the run has
/// neither a record in hand nor a record reference to resolve.
///
/// The record is re-read from the store's source: the stored record over PostgreSQL, an injected
/// source ([`LocalRun::with_authorization_source`]) or, for in-memory stores, the supplied record
/// itself (so its window and target are enforced, not its revocation). A referenced record
/// without a record in hand or a source is refused before any browser or request is started.
pub(crate) async fn local_authorization(
    run: &CrawlRun,
    record: Option<crawlx_policy::AuthorizationRecord>,
    stores: &Stores,
    cfg: &WorkerConfig,
    clock: &Arc<dyn Clock>,
) -> Result<Option<Arc<AuthorizationGuard>>, WorkerError> {
    let referenced = run.config.safety.authorization_record_ref;
    if record.is_none() && referenced.is_none() {
        check_role_credentials(&run.config, None)?;
        return Ok(None);
    }
    let source: Arc<dyn AuthorizationSource> =
        match (&record, &stores.authorization) {
            (_, Some(source)) => Arc::clone(source),
            (Some(record), None) => Arc::new(StaticAuthorizationSource::new(record.clone())),
            (None, None) => {
                return Err(AuthorizationStop::Missing(referenced.ok_or_else(|| {
                    WorkerError::Config("an authorization reference is required".to_owned())
                })?)
                .into());
            }
        };
    let guard = AuthorizationGuard::admit(
        run.id,
        record,
        referenced,
        source,
        Arc::clone(clock),
        Arc::clone(&stores.events),
        cfg.authorization_recheck,
    )
    .await?;
    guard.check_tenant(run.tenant)?;
    check_role_credentials(&run.config, Some(&guard))?;
    Ok(Some(guard))
}

/// End a run whose authorization was refused at admission: failed, `authorization_revoked`,
/// nothing requested. The report carries the terminal reason like any other run's.
async fn finish_refused(
    stores: &Stores,
    run: CrawlRunId,
    stop: &AuthorizationStop,
) -> Result<RunReport, WorkerError> {
    let reason = TerminalReason::AuthorizationRevoked;
    stores.finish_run(run, reason).await?;
    let report = build_report(stores, run).await?;
    let _ = stores
        .events
        .append(
            run,
            "completed",
            serde_json::json!({
                "status": report.status.as_str(),
                "terminalReason": reason.as_str(),
                "authorization": stop.reason(),
                "counters": report.counters,
            }),
        )
        .await;
    Ok(report)
}

/// The `mode` field of the `crawl` span.
pub(crate) const fn crawl_mode_name(mode: CrawlMode) -> &'static str {
    match mode {
        CrawlMode::Static => "static",
        CrawlMode::Dynamic => "dynamic",
        CrawlMode::Hybrid => "hybrid",
    }
}

/// Capture metrics of one proxy-captured run: the late-attribution ratio, the events
/// stored without an epoch (`reason = unmatched_proxy_flow` for browser flows no CDP request
/// or unambiguous window claimed, `fetch_plane` for the static plane's own requests) and the
/// unmatched proxy flows themselves. Called once at the end of the run, so the counters
/// grow by the run's totals.
fn observe_capture(stats: &crawlx_observe::ProxyCaptureStats) {
    let m = Metrics::global();
    let ratio = if stats.flows == 0 {
        0.0
    } else {
        to_f64(stats.late) / to_f64(stats.flows)
    };
    m.gauge(names::TRAFFIC_LATE_RATIO).set(ratio, &[]);
    let unattributed = m.counter(names::TRAFFIC_UNATTRIBUTED);
    unattributed.inc_by(stats.unmatched, &[("reason", "unmatched_proxy_flow")]);
    unattributed.inc_by(
        stats.unattributed.saturating_sub(stats.unmatched),
        &[("reason", "fetch_plane")],
    );
    m.counter(names::TRAFFIC_UNMATCHED_PROXY_FLOWS)
        .inc_by(stats.unmatched, &[]);
}

fn to_f64(n: u64) -> f64 {
    u32::try_from(n).map_or(f64::MAX, f64::from)
}

/// Lease and run every session of the run, honoring the round-robin barrier.
/// `crawlx.session.round_wait` is the time from the first refused lease while sessions
/// were still running (a role waiting for its turn) to the next granted lease;
/// `crawlx.roles.abandoned` counts sessions that ended without completing their turn.
async fn run_sessions(
    rc: &Arc<RunContext>,
    cfg: &WorkerConfig,
    start_requests: Vec<crawlx_core::request::RequestEnvelopeV1>,
    driver: DriverConfig,
    strategies: Option<Vec<Arc<dyn crawlx_strategies::Strategy>>>,
) -> Result<Vec<TerminalReason>, WorkerError> {
    let scheduler = Scheduler::new(Arc::clone(&rc.stores.leases));
    let parallel =
        rc.crawl.parallel_roles_allowed() || rc.crawl.target_isolation == TargetIsolation::PerRoleReplica;
    let mut running = FuturesUnordered::new();
    let mut reasons = Vec::new();
    let mut waiting_since: Option<std::time::Instant> = None;
    loop {
        while running.len() < cfg.max_sessions.max(1) && !rc.cancel.is_cancelled() {
            // no session starts under a record that is revoked or expired
            if let Some(guard) = &rc.authorization {
                if guard.check_now().await.is_err() {
                    reasons.push(TerminalReason::AuthorizationRevoked);
                    break;
                }
            }
            let Some(lease) = scheduler.lease_in_run(rc.run, rc.worker, parallel).await? else {
                if waiting_since.is_none() && !running.is_empty() {
                    waiting_since = Some(std::time::Instant::now());
                }
                break;
            };
            let session = lease.session.clone();
            if let Some(since) = waiting_since.take() {
                observe_round_wait(since, &session.role.0);
            }
            let _ = rc
                .stores
                .events
                .append(
                    rc.run,
                    "session",
                    serde_json::json!({
                        "sessionId": session.id.0,
                        "role": session.role.0,
                        "runIndex": session.run_index,
                        "scheduleSlot": session.schedule_slot,
                        "status": "running",
                    }),
                )
                .await;
            let task = rc.supervisor.spawn_for(
                "session",
                Some(session.id),
                run_session(
                    Arc::clone(rc),
                    scheduler.clone(),
                    lease.clone(),
                    std::future::ready(Ok(start_requests.clone())),
                    driver.clone(),
                    strategies.clone(),
                ),
            );
            running.push(async move { (lease, task.await) });
        }
        let Some((lease, joined)) = running.next().await else {
            break;
        };
        match joined {
            Ok(Ok(end)) => {
                observe_session_end(end.terminal);
                reasons.push(end.terminal);
            }
            Ok(Err(failure)) => {
                tracing::error!(session = %lease.session.id, message = %failure.message, "session task panicked");
                let _ = scheduler.fail(&lease).await;
                observe_session_end(TerminalReason::FatalError);
                reasons.push(TerminalReason::FatalError);
            }
            Err(join) => {
                tracing::error!(session = %lease.session.id, error = %join, "session task aborted");
                let _ = scheduler.fail(&lease).await;
                observe_session_end(TerminalReason::FatalError);
                reasons.push(TerminalReason::FatalError);
            }
        }
    }
    Ok(reasons)
}

/// Count a role session that ended with `terminal` without completing its turn in
/// `crawlx.roles.abandoned`; a session that completed its turn (frontier
/// exhausted, a limit, the deadline, a policy stop) is not counted.
pub(crate) fn observe_session_end(terminal: TerminalReason) {
    let reason = match terminal {
        TerminalReason::FatalError
        | TerminalReason::RecoveryExhausted
        | TerminalReason::AuthorizationRevoked
        | TerminalReason::Cancelled => terminal.as_str(),
        TerminalReason::FrontierExhausted
        | TerminalReason::LimitReached
        | TerminalReason::DeadlineReached
        | TerminalReason::PolicyStopped => return,
    };
    Metrics::global()
        .counter(names::ROLES_ABANDONED)
        .inc_by(1, &[("reason", reason)]);
}

/// Record one round-robin wait (`crawlx.session.round_wait`): `since` is when a
/// lease was first refused while sessions were still running; the wait ends when `role`'s
/// session is granted.
pub(crate) fn observe_round_wait(since: std::time::Instant, role: &str) {
    Metrics::global()
        .histogram(names::SESSION_ROUND_WAIT)
        .observe_duration(since.elapsed(), &[("role", role)]);
}

/// Collect the report of a finished run from the store.
///
/// # Errors
/// Fails when a storage, browser or network operation it depends on fails.
pub async fn build_report(stores: &Stores, run: CrawlRunId) -> Result<RunReport, WorkerError> {
    let row = stores.runs.get(run).await?;
    let pages = stores.pages.list(run).await?;
    let mut page_contents = Vec::with_capacity(pages.len());
    for p in &pages {
        let raw = match p
            .metadata
            .get("raw_artifact")
            .and_then(|v| serde_json::from_value::<crawlx_core::ArtifactRef>(v.clone()).ok())
        {
            Some(r) => read_text(stores.artifacts.as_ref(), Some(&r)).await,
            None => None,
        };
        page_contents.push(PageContent {
            url: p.url.url.to_string(),
            markdown: read_text(stores.artifacts.as_ref(), p.markdown.as_ref()).await,
            html: read_text(stores.artifacts.as_ref(), p.html.as_ref()).await,
            raw,
        });
    }
    let mut failures: Vec<UrlFailure> = stores
        .frontier
        .list(run)
        .await?
        .into_iter()
        .filter(|f| matches!(f.status, FrontierStatus::Failed | FrontierStatus::Unreachable))
        .map(|f| {
            UrlFailure::new(
                f.url.url.to_string(),
                f.depth,
                f.denial_reason.unwrap_or_else(|| f.status.as_str().to_owned()),
            )
        })
        .collect();
    failures.sort_by(|a, b| (&a.url, a.depth).cmp(&(&b.url, b.depth)));
    let ledger = stores.ledger.list(run).await?;
    let coverage = crawlx_strategies::InMemoryLedger::from_rows(ledger.iter().cloned())
        .with_isolation(row.config.target_isolation)
        .coverage(None);
    Ok(RunReport {
        run_id: run,
        status: row.status,
        terminal_reason: row.terminal_reason,
        counters: row.counters,
        states: stores.states.list_states(run).await?,
        actions: stores.journal.list(run, None).await?,
        edges: stores.edges.list(run).await?,
        sessions: stores.runs.list_sessions(run).await?,
        ledger,
        coverage,
        pages,
        page_contents,
        browser_launches: 0,
        failures,
        resume: None,
        diagnostics: Vec::new(),
        egress: EgressCapture::default(),
        capture: CaptureReport::default(),
    })
}

async fn read_text(store: &dyn ArtifactStore, r: Option<&crawlx_core::ArtifactRef>) -> Option<String> {
    let bytes = store.get(r?).await.ok()?;
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
pub(crate) mod login_lifecycle_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::actor::{SessionActor, SessionHandle, ShutdownReason};
    use async_trait::async_trait;
    use crawlx_browser::fake::{FakeAxSpec, FakeEffect, FakePage, FakeScript};
    use crawlx_browser::FakeBackend;
    use crawlx_core::config::Role;
    use crawlx_core::secret::{CredentialRef, SecretOr};
    use crawlx_core::{CoreError, Timestamp};
    use crawlx_fetch::StaticResolver;
    use crawlx_policy::testkit::sample_record;
    use crawlx_storage::MemoryStore;

    struct PausedClock {
        at: Timestamp,
        started: Mutex<Option<tokio::time::Instant>>,
    }

    impl Clock for PausedClock {
        fn now(&self) -> Timestamp {
            let elapsed = self
                .started
                .lock()
                .map_or(std::time::Duration::ZERO, |start| start.elapsed());
            self.at + chrono::Duration::from_std(elapsed).unwrap()
        }
    }

    struct Credentials;

    #[async_trait]
    impl SecretResolver for Credentials {
        async fn resolve(&self, _: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
            Ok(SecretOr::secret("fixture-user:fixture-password".to_owned()))
        }
    }

    pub(crate) struct LoginFixture {
        pub(crate) rc: RunContext,
        pub(crate) lease: SessionLease,
        pub(crate) handle: SessionHandle,
        pub(crate) analyzer: Arc<StateAnalyzer>,
        material: LoginMaterial,
        bounds: LoginBounds,
        source: StaticAuthorizationSource,
        pub(crate) backend: Arc<FakeBackend>,
        _dir: tempfile::TempDir,
    }

    async fn fixture(valid_for: chrono::Duration) -> LoginFixture {
        fixture_with_bounds(valid_for, None, None).await
    }

    pub(crate) async fn fixture_with_bounds(
        valid_for: chrono::Duration,
        execution_ttl: Option<chrono::Duration>,
        binding_ttl: Option<chrono::Duration>,
    ) -> LoginFixture {
        let dir = tempfile::tempdir().unwrap();
        let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let now = Timestamp::from_timestamp_millis(SystemClock.now().timestamp_millis()).unwrap();
        let paused_clock = Arc::new(PausedClock {
            at: now,
            started: Mutex::new(None),
        });
        let clock: Arc<dyn Clock> = paused_clock.clone();
        let mut crawl = CreateCrawl::new(url::Url::parse("https://example.test/").unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.safety.profile = SafetyProfile::TestEnvironment;
        crawl.limits.duration_seconds = 1;
        crawl.roles = vec![Role {
            name: "admin".to_owned(),
            credential_ref: Some(CredentialRef("env://LOGIN_FIXTURE".to_owned())),
            login_plan: Some(
                r##"recorded:{"steps":[{"action":"wait","value":"2s"},{"action":"fill","selector":"#user","value":"{{username}}"},{"action":"waitvisible","selector":"#ready","value":"1s"}]}"##
                    .to_owned(),
            ),
            replica_base_url: None,
        }];
        let mut record = sample_record(stores.tenant, now, &["https://example.test"]);
        record.verified_at = Some(now);
        record.valid_to = now + valid_for;
        record.test_accounts = vec![crawlx_policy::TestAccount {
            role: "admin".to_owned(),
            credential_ref: "env://LOGIN_FIXTURE".to_owned(),
        }];
        crawl.safety.authorization_record_ref = Some(record.id);
        let run = CrawlRun {
            id: CrawlRunId::new(),
            tenant: stores.tenant,
            status: RunStatus::Running,
            terminal_reason: None,
            seed: crawl.effective_seed(),
            config_digest: crawl.digest().unwrap(),
            config: crawl.clone(),
            policy_version: 1,
            counters: PlaneCounters::default(),
            created_at: now,
            started_at: Some(now),
            finished_at: None,
            trace_id: None,
        };
        stores.runs.create(&run, None).await.unwrap();
        stores
            .runs
            .create_sessions(&RunPlanner::sessions(run.id, &crawl))
            .await
            .unwrap();
        let cfg = WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            gates: crate::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
            egress: crate::config::EgressConfig {
                resolver: Some(Arc::new(StaticResolver::new())),
                ..crate::config::EgressConfig::default()
            },
            ..WorkerConfig::default()
        };
        let source = StaticAuthorizationSource::new(record.clone());
        let guard = AuthorizationGuard::admit(
            run.id,
            Some(record.clone()),
            Some(record.id),
            Arc::new(source.clone()),
            Arc::clone(&clock),
            Arc::clone(&stores.events),
            cfg.authorization_recheck,
        )
        .await
        .unwrap();
        let backend = Arc::new(
            FakeBackend::builder()
                .script(
                    FakeScript::new()
                        .page(
                            FakePage::new("https://example.test/")
                                .node(
                                    FakeAxSpec::textbox("user", "Username")
                                        .attr("autocomplete", "username")
                                        .attr("crawlx:form", "login"),
                                )
                                .node(
                                    FakeAxSpec::textbox("password", "Password")
                                        .attr("type", "password")
                                        .attr("autocomplete", "current-password")
                                        .attr("crawlx:form", "login"),
                                )
                                .node(
                                    FakeAxSpec::button("submit", "Sign in")
                                        .attr("type", "submit")
                                        .attr("crawlx:form", "login"),
                                )
                                .on_click("submit", vec![FakeEffect::Navigate("/home".to_owned())])
                                .node(FakeAxSpec::button("ready", "Ready")),
                        )
                        .page(FakePage::new("https://example.test/home").title("Home")),
                )
                .clock(Arc::clone(&clock))
                .build(),
        );
        let mut rc = RunContext::build(
            &run,
            &cfg,
            stores,
            Some(backend.clone()),
            Some(Arc::new(Credentials)),
            CancellationToken::new(),
            None,
            Some(guard),
        )
        .await
        .unwrap();
        rc.clock = clock;
        let lease = Scheduler::new(Arc::clone(&rc.stores.leases))
            .lease_in_run(rc.run, rc.worker, false)
            .await
            .unwrap()
            .unwrap();
        let mut scfg = rc.session_config(&lease.session);
        let material = rc
            .prepare_session_login(&lease.session, &mut scfg)
            .await
            .unwrap()
            .unwrap();
        let reserved = rc.stores.events.list_after(rc.run, 0, 100).await.unwrap();
        assert!(reserved.iter().any(|event| {
            event.kind == "session.budget"
                && event.payload["login_allowance_ms"]
                    .as_u64()
                    .is_some_and(|ms| ms > 0)
        }));
        let pooled = rc.acquire_bound_session(&lease, &mut scfg).await.unwrap();
        if let Some(ttl) = execution_ttl {
            // Controlled non-login consumer fixture: execution may stop before the
            // independent binding/checkpoint ceiling, with no fresh durable allocation.
            scfg.awaits_login = false;
            scfg.execution_deadline = Some(now + ttl);
        }
        if let Some(ttl) = binding_ttl {
            let binding = scfg.context.session_binding.as_mut().unwrap();
            binding.expires_at = binding.expires_at.min(now + ttl);
        }
        let bounds = LoginBounds::from(&scfg);
        let analyzer = Arc::new(StateAnalyzer::new(
            rc.run,
            lease.session.id,
            rc.clusters.clone(),
            Arc::clone(&rc.stores.artifacts),
            Arc::clone(&rc.clock),
            rc.crawl.capture.clone(),
            (&rc.controls, &rc.captcha_secrets),
        ));
        let handle = SessionActor::spawn(scfg, rc.services(), Arc::clone(&analyzer), 7, pooled)
            .await
            .unwrap();
        handle
            .navigate(crawlx_core::request::RequestEnvelopeV1::get(
                rc.seed_url().unwrap(),
                0,
                None,
            ))
            .await
            .unwrap();
        *paused_clock.started.lock() = Some(tokio::time::Instant::now());
        LoginFixture {
            rc,
            lease,
            handle,
            analyzer,
            material,
            bounds,
            source,
            backend,
            _dir: dir,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_hybrid_input_wait_distinguishes_revocation_from_worker_drain() {
        for revoked in [false, true] {
            let f = fixture(chrono::Duration::minutes(5)).await;
            f.handle.shutdown(ShutdownReason::Completed).await.unwrap();
            let guard = f.rc.authorization.as_ref().unwrap();
            guard.cancels(f.rc.cancel.clone());
            if revoked {
                assert!(f
                    .source
                    .revoke(guard.record_id(), f.rc.clock.now(), "fixture revocation"));
                assert!(guard.check_execution_stop().await.is_err());
            } else {
                f.rc.cancel.cancel();
            }
            let rc = Arc::new(f.rc);
            let end = run_session(
                Arc::clone(&rc),
                Scheduler::new(Arc::clone(&rc.stores.leases)),
                f.lease,
                std::future::pending(),
                DriverConfig::default(),
                None,
            )
            .await;
            assert_eq!(
                end.terminal,
                if revoked {
                    TerminalReason::AuthorizationRevoked
                } else {
                    TerminalReason::Cancelled
                },
            );
            assert_eq!(end.error.is_some(), revoked);
            let sessions = rc.stores.runs.list_sessions(rc.run).await.unwrap();
            assert_eq!(
                sessions[0].status,
                if revoked {
                    SessionStatus::Failed
                } else {
                    SessionStatus::Recovering
                },
            );
            assert_eq!(f.backend.open_contexts(), 0);
            rc.supervisor.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn role_lease_loss_is_fatal_even_when_worker_drain_follows() {
        for drain_after_loss in [false, true] {
            let mut f = fixture(chrono::Duration::minutes(5)).await;
            f.handle.shutdown(ShutdownReason::Completed).await.unwrap();
            let worker_drain = CancellationToken::new();
            f.rc.cancel = worker_drain.child_token();
            // Transfer the actual lease. The old heartbeat must discover the
            // repository's fence mismatch, not an injected cancellation/error.
            f.rc.stores
                .leases
                .release(&f.lease, SessionStatus::Recovering)
                .await
                .unwrap();
            let replacement_scheduler = Scheduler::new(Arc::clone(&f.rc.stores.leases));
            let replacement = replacement_scheduler
                .lease_in_run(f.rc.run, crawlx_core::WorkerId::new(), false)
                .await
                .unwrap()
                .unwrap();
            assert_ne!(replacement.fencing_token, f.lease.fencing_token);
            let rc = Arc::new(f.rc);
            let running = run_session(
                Arc::clone(&rc),
                Scheduler::new(Arc::clone(&rc.stores.leases)),
                f.lease,
                std::future::pending(),
                DriverConfig::default(),
                None,
            );
            tokio::pin!(running);
            tokio::select! {
                biased;
                () = rc.cancel.cancelled() => {}
                end = &mut running => panic!("session ended before heartbeat stop: {end:?}"),
            }
            if drain_after_loss {
                worker_drain.cancel();
            }
            let end = running.await;
            assert_eq!(end.terminal, TerminalReason::FatalError);
            assert_eq!(
                end.error,
                Some(
                    WorkerError::Scheduler(crawlx_scheduler::SchedulerError::Store(
                        crawlx_core::StoreError::LeaseLost
                    ),)
                    .to_string()
                ),
            );
            assert_eq!(
                rc.stores.runs.list_sessions(rc.run).await.unwrap()[0].status,
                replacement.session.status,
                "stale owner must not complete or hand over the replacement lease",
            );
            replacement_scheduler.heartbeat(&replacement).await.unwrap();
            replacement_scheduler
                .release(&replacement, SessionStatus::Failed)
                .await
                .unwrap();
            assert_eq!(f.backend.open_contexts(), 0);
            rc.supervisor.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn driver_deadline_does_not_hide_an_earlier_idle_binding_or_lease_failure() {
        for lost_lease in [false, true] {
            let f = fixture_with_bounds(
                chrono::Duration::minutes(5),
                Some(chrono::Duration::milliseconds(500)),
                (!lost_lease).then_some(chrono::Duration::milliseconds(100)),
            )
            .await;
            if lost_lease {
                f.rc.stores
                    .leases
                    .release(&f.lease, SessionStatus::Failed)
                    .await
                    .unwrap();
            }
            tokio::time::advance(std::time::Duration::from_secs(1)).await;
            f.handle
                .wait_state(|state| state == crate::actor::SessionState::Closed)
                .await;
            let rc = Arc::new(f.rc);
            let mut driver = ExplorationDriver::new(
                DriverConfig::default(),
                Arc::clone(&rc),
                f.lease.session.clone(),
                f.handle.clone(),
                Arc::clone(&f.analyzer),
                Vec::new(),
            );
            let end = driver
                .run(vec![crawlx_core::request::RequestEnvelopeV1::get(
                    rc.seed_url().unwrap(),
                    0,
                    None,
                )])
                .await
                .unwrap();
            assert_eq!(end.terminal, TerminalReason::DeadlineReached);
            let shutdown = f
                .handle
                .shutdown(ShutdownReason::Completed)
                .await
                .map_err(WorkerError::from);
            let error = crate::replay::finish_replay(Ok(end), shutdown, Ok(())).unwrap_err();
            let WorkerError::Session(SessionError::ActorStopped(cause)) = error else {
                panic!("idle fatal cause was lost: {error}");
            };
            if lost_lease {
                assert!(matches!(
                    cause.as_ref(),
                    SessionError::Store(crawlx_core::StoreError::LeaseLost)
                ));
            } else {
                assert!(matches!(
                    cause.as_ref(),
                    SessionError::Binding(crawlx_core::session_binding::SessionBindingError::Expired),
                ));
            }
            assert_eq!(f.backend.open_contexts(), 0);
            rc.supervisor.shutdown().await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_during_seed_admission_completes_normally_without_dispatch() {
        execution_deadline_case(
            chrono::Duration::minutes(5),
            false,
            TerminalReason::DeadlineReached,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn authorization_expiry_coincident_with_execution_deadline_stays_authorization_failure() {
        execution_deadline_case(
            chrono::Duration::seconds(1),
            false,
            TerminalReason::AuthorizationRevoked,
        )
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn authorization_revocation_coincident_with_execution_deadline_bypasses_cached_authority() {
        execution_deadline_case(
            chrono::Duration::minutes(5),
            true,
            TerminalReason::AuthorizationRevoked,
        )
        .await;
    }

    async fn execution_deadline_case(valid_for: chrono::Duration, revoke: bool, expected: TerminalReason) {
        let mut f = fixture(valid_for).await;
        f.handle.shutdown(ShutdownReason::Completed).await.unwrap();
        // Reuse the admitted durable allocation without logging in or resetting its clock.
        f.rc.crawl.roles[0].credential_ref = None;
        crate::role_budget::RoleBudget::load(&f.rc, &f.lease.session)
            .await
            .unwrap()
            .reserve_login(&f.rc, chrono::Duration::zero())
            .await
            .unwrap();
        let cap = Arc::new(crawlx_fetch::governor::GlobalOriginCap::new(1));
        let governor = Arc::new(crawlx_fetch::OriginGovernor::with_global_cap(
            crawlx_fetch::GovernorConfig::default(),
            cap,
        ));
        f.rc.origin_governor = Arc::clone(&governor);
        let held = governor
            .acquire_browser(&crawlx_fetch::Origin::new("https://example.test"))
            .await
            .unwrap();
        if revoke {
            // A future revocation becomes active exactly at the execution ceiling.
            assert!(f.source.revoke(
                f.rc.authorization.as_ref().unwrap().record_id(),
                f.rc.budget.lock().deadline(),
                "fixture deadline revocation",
            ));
        }
        let navigations = f
            .backend
            .context_handles()
            .iter()
            .map(|context| context.navigations().len())
            .sum::<usize>();
        let rc = Arc::new(f.rc);
        let scheduler = Scheduler::new(Arc::clone(&rc.stores.leases));
        let end = run_session(
            Arc::clone(&rc),
            scheduler,
            f.lease.clone(),
            std::future::ready(Ok(Vec::new())),
            DriverConfig::default(),
            None,
        )
        .await;
        assert_eq!(end.terminal, expected, "{end:?}");
        assert_eq!(end.error.is_none(), expected == TerminalReason::DeadlineReached);
        assert!(rc.stores.journal.list(rc.run, None).await.unwrap().is_empty());
        assert!(f
            .backend
            .context_handles()
            .iter()
            .all(|context| context.performed_keys().is_empty()));
        assert_eq!(
            f.backend
                .context_handles()
                .iter()
                .map(|context| context.navigations().len())
                .sum::<usize>(),
            navigations,
            "admission expiry must not dispatch the pending seed navigation",
        );
        assert_eq!(f.backend.open_contexts(), 0);
        let sessions = rc.stores.runs.list_sessions(rc.run).await.unwrap();
        assert_eq!(
            sessions[0].status,
            if expected == TerminalReason::DeadlineReached {
                SessionStatus::Completed
            } else {
                SessionStatus::Failed
            },
        );
        drop(held);
        rc.supervisor.shutdown().await;
    }

    async fn credited_millis(rc: &RunContext) -> u64 {
        rc.stores
            .events
            .list_after(rc.run, 0, 100)
            .await
            .unwrap()
            .iter()
            .rev()
            .find(|event| event.kind == "session.budget")
            .unwrap()
            .payload["login_credit_ms"]
            .as_u64()
            .unwrap()
    }

    #[tokio::test(start_paused = true)]
    async fn slow_login_credits_measured_time_without_spending_exploration_or_resetting_resume() {
        let f = fixture(chrono::Duration::minutes(5)).await;
        let original_deadline = f.rc.budget.lock().deadline();
        let started = f.rc.clock.now();
        f.rc.login_session_bounded(&f.lease.session, &f.handle, &f.analyzer, f.material, f.bounds)
            .await
            .unwrap();
        let measured = f.rc.clock.now().signed_duration_since(started);
        assert!(measured >= chrono::Duration::seconds(2));
        assert!(f.rc.clock.now() > original_deadline);
        assert_eq!(
            credited_millis(&f.rc).await,
            u64::try_from(measured.num_milliseconds()).unwrap()
        );
        let deadline = f.rc.budget.lock().deadline();
        assert_eq!(deadline, original_deadline + measured);
        assert!(deadline > f.rc.clock.now());
        let recovered = crate::role_budget::RoleBudget::load(&f.rc, &f.lease.session)
            .await
            .unwrap();
        assert_eq!(recovered.exhausted(f.rc.clock.now()), None);
        assert_eq!(f.rc.budget.lock().deadline(), deadline);
        assert!(f.backend.context_handles()[0]
            .performed_keys()
            .iter()
            .any(|key| key == "type:user"));
        f.handle.shutdown(ShutdownReason::Completed).await.unwrap();
        Scheduler::new(Arc::clone(&f.rc.stores.leases))
            .release(&f.lease, SessionStatus::Completed)
            .await
            .unwrap();
        f.rc.supervisor.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn login_timeout_does_not_extend_authorization_ceiling() {
        let f = fixture(chrono::Duration::milliseconds(1500)).await;
        let ceiling = f.rc.authorization.as_ref().unwrap().record().valid_to;
        assert_eq!(f.bounds.binding_deadline, Some(ceiling));
        let error =
            f.rc.login_session_bounded(&f.lease.session, &f.handle, &f.analyzer, f.material, f.bounds)
                .await
                .unwrap_err();
        assert!(matches!(
            error,
            WorkerError::Session(SessionError::LoginFailed(_))
        ));
        assert_eq!(f.rc.clock.now(), ceiling);
        assert_eq!(f.rc.authorization.as_ref().unwrap().record().valid_to, ceiling);
        assert!(credited_millis(&f.rc).await <= 1500);
        assert!(f.backend.context_handles()[0].performed_keys().is_empty());
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            f.handle.state(),
            crate::actor::SessionState::Failed | crate::actor::SessionState::Closed
        ));
        assert!(!f.rc.cancel.is_cancelled());
        assert!(f.backend.context_handles()[0].performed_keys().is_empty());
        let events = f.rc.stores.events.list_after(f.rc.run, 0, 100).await.unwrap();
        assert!(!events
            .iter()
            .any(|event| event.kind == "session.login" && event.payload["ok"] == true));
        let _ = f.handle.shutdown(ShutdownReason::Cancelled).await;
        Scheduler::new(Arc::clone(&f.rc.stores.leases))
            .release(&f.lease, SessionStatus::Failed)
            .await
            .unwrap();
        f.rc.supervisor.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn abandoned_builtin_login_stops_before_later_credential_effects() {
        let mut f = fixture(chrono::Duration::minutes(5)).await;
        f.material.plan = LoginPlan::builtin_form();
        // End the receiver while the first credential is waiting for the native
        // origin-spacing floor, well before the binding's own expiry.
        f.bounds.allowance = chrono::Duration::milliseconds(100);
        let error =
            f.rc.login_session_bounded(&f.lease.session, &f.handle, &f.analyzer, f.material, f.bounds)
                .await
                .unwrap_err();
        assert!(matches!(
            error,
            WorkerError::Session(SessionError::LoginFailed(_))
        ));
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert!(matches!(
            f.handle.state(),
            crate::actor::SessionState::Failed | crate::actor::SessionState::Closed
        ));
        assert!(!f.rc.cancel.is_cancelled());
        assert!(f.backend.context_handles()[0].performed_keys().is_empty());
        let events = f.rc.stores.events.list_after(f.rc.run, 0, 100).await.unwrap();
        assert!(!events
            .iter()
            .any(|event| event.kind == "session.login" && event.payload["ok"] == true));
        let _ = f.handle.shutdown(ShutdownReason::Cancelled).await;
        Scheduler::new(Arc::clone(&f.rc.stores.leases))
            .release(&f.lease, SessionStatus::Failed)
            .await
            .unwrap();
        f.rc.supervisor.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn released_lease_cannot_authenticate_or_replace_its_fence() {
        let f = fixture(chrono::Duration::minutes(5)).await;
        Scheduler::new(Arc::clone(&f.rc.stores.leases))
            .release(&f.lease, SessionStatus::Failed)
            .await
            .unwrap();
        assert!(f
            .rc
            .login_session_bounded(&f.lease.session, &f.handle, &f.analyzer, f.material, f.bounds,)
            .await
            .is_err());
        assert!(f.backend.context_handles()[0].performed_keys().is_empty());
        let _ = f.handle.shutdown(ShutdownReason::Cancelled).await;
        f.rc.supervisor.shutdown().await;
    }
}
