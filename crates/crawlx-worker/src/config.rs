//! Worker configuration.

use crate::error::WorkerError;
use crate::model::{ModelConfig, PlannerConfig};
use crate::runtime::CpuPool;
use crate::scrape::PageRenderer;
use crate::surface::form_ai::FormAi;
use crate::surface::traffic_export::TrafficExportConfig;
use crawlx_browser::LaunchConfig;
use crawlx_core::config::System1Mode;
use crawlx_core::{CrawlRunId, CreateCrawl, SafetyProfile, WorkerId};
use crawlx_extract::secret_validation::SecretValidators;
use crawlx_fetch::proxyx::{PoolBinding, PoolTier, ProxyxRoute};
use crawlx_fetch::{
    EgressOptions, EgressProxy, EgressProxyHandle, GlobalOriginCap, HickoryResolver, Resolver, UpstreamProxy,
};
use crawlx_model::llm::{ExtractionRouter, LlmExtractor};
use crawlx_policy::{AuthorizationRecord, EgressPolicy, SharedEgressLists};
use crawlx_strategies::Gates;
use crawlx_telemetry::TelemetryConfig;
use crawlx_url::TrailingSlash;
use ipnet::IpNet;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Egress settings shared by the fetch plane and the browser's loopback proxy.
///
/// The per-run policy derives from the run's `safety.allowPrivateNetworks` (admission has
/// already required an authorization record for it) plus the networks and ports below.
#[derive(Clone, Default)]
pub struct EgressConfig {
    /// Contact URL or address advertised in the `User-Agent`.
    pub contact: String,
    /// Authorized private networks (`authorizedNetworks` of the record). Empty with
    /// `allowPrivateNetworks` exempts every exemptable private range.
    pub extra_allow: Vec<IpNet>,
    /// Extra deny.
    pub extra_deny: Vec<IpNet>,
    /// Ports allowed besides 80/443 and the ports of the seed and replica URLs.
    pub extra_ports: Vec<u16>,
    /// DNS resolver; `None` uses the system configuration.
    pub resolver: Option<Arc<dyn Resolver>>,
    /// The live deployment lists (`egress.deployment_allowlist`, `egress.operator_blocklist`):
    /// every run's policy carries this handle, so a reload reaches runs in flight.
    pub lists: Option<SharedEgressLists>,
    /// Narrowing-only listener scope installed by an in-process fixture experiment.
    pub fixture_scope: Option<crawlx_policy::fixture_evaluation::FixtureEvaluationScope>,
    /// Deployment-owned basic and enhanced routes; credentials are never logged.
    pub proxy_routes: crawlx_fetch::ProxyRoutes,
}

impl fmt::Debug for EgressConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressConfig")
            .field("contact", &self.contact)
            .field("extra_allow", &self.extra_allow)
            .field("extra_deny", &self.extra_deny)
            .field("extra_ports", &self.extra_ports)
            .field("resolver", &self.resolver.as_ref().map(|_| "custom"))
            .field("lists", &self.lists)
            .field("proxy_routes", &self.proxy_routes)
            .finish()
    }
}

/// The deployment route a run's traffic takes.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum TierRoute<'a> {
    /// No proxy.
    Direct,
    /// A proxy URL: the deployment's tier route or the request's `fetch.proxy`.
    Url(&'a url::Url),
    /// A ProxyX pool route and the tier it serves.
    Pool(&'a ProxyxRoute, PoolTier),
}

impl fmt::Debug for TierRoute<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => f.write_str("Direct"),
            Self::Url(_) => f.write_str("Url([configured])"),
            Self::Pool(route, tier) => write!(f, "Pool({route:?}, {tier:?})"),
        }
    }
}

impl<'a> TierRoute<'a> {
    /// The proxy URL of a plain route.
    #[must_use]
    pub const fn url(&self) -> Option<&'a url::Url> {
        match self {
            Self::Url(url) => Some(url),
            Self::Direct | Self::Pool(..) => None,
        }
    }

    /// The pool route and tier.
    #[must_use]
    pub const fn pool(&self) -> Option<(&'a ProxyxRoute, PoolTier)> {
        match self {
            Self::Pool(route, tier) => Some((route, *tier)),
            Self::Direct | Self::Url(_) => None,
        }
    }

    /// A stable name of the route for identity digests: `direct`, the proxy URL as configured, or
    /// the credential-free pool identity (gateway and selector).
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::Direct => "direct".to_owned(),
            Self::Url(url) => url.as_str().to_owned(),
            Self::Pool(route, _) => route.identity(),
        }
    }

    /// The upstream run `run` binds for this route: the pool binding of a pool route, `None`
    /// otherwise. `report` carries the run's egress policy and resolver when block signals should
    /// be reported (the fetch plane).
    ///
    /// # Errors
    /// [`WorkerError::Fetch`] when the selector does not fit the username budget.
    pub fn bind(
        &self,
        run: CrawlRunId,
        report: Option<(Arc<EgressPolicy>, Arc<dyn Resolver>)>,
    ) -> Result<Option<Arc<PoolBinding>>, WorkerError> {
        let Some((route, tier)) = self.pool() else {
            return Ok(None);
        };
        let binding = route
            .bind(tier, &run.0.simple().to_string(), report)
            .map_err(crawlx_fetch::FetchError::from)?;
        Ok(Some(binding))
    }
}

impl EgressConfig {
    /// Resolve a scrape's deployment tier without exposing proxy credentials.
    ///
    /// A tier is a proxy URL or a ProxyX pool route; a pool route wins when both could apply
    /// (configuration refuses setting both on one tier).
    ///
    /// # Errors
    /// Fails when explicit enhanced mode, or legacy automatic escalation, lacks its route.
    pub fn route_for<'a>(&'a self, crawl: &'a CreateCrawl) -> Result<TierRoute<'a>, WorkerError> {
        use crawlx_core::scrape::ProxyMode;
        let request = || {
            crawl
                .fetch
                .proxy
                .as_ref()
                .map_or(TierRoute::Direct, TierRoute::Url)
        };
        let Some(job) = &crawl.scrape else {
            return Ok(request());
        };
        let enhanced = self.enhanced_route();
        // An explicit native policy replaces facade Auto escalation with its bounded
        // backend plan. Native Auto stays on basic; it never silently rotates identity.
        let requires_enhanced = job.options.proxy == ProxyMode::Enhanced
            || (job.options.proxy == ProxyMode::Auto && crawl.acquisition.is_none());
        if requires_enhanced && enhanced.is_none() {
            return Err(WorkerError::Config(
                "enhanced proxy requested but neither fetch.enhanced_proxy_url nor fetch.proxyx.enhanced is configured"
                    .to_owned(),
            ));
        }
        let routes = &self.proxy_routes;
        Ok(match job.options.proxy {
            ProxyMode::Enhanced => enhanced.unwrap_or(TierRoute::Direct),
            _ => match (&routes.basic_pool, &routes.basic) {
                (Some(route), _) => TierRoute::Pool(route, PoolTier::Basic),
                (None, Some(url)) => TierRoute::Url(url),
                (None, None) => request(),
            },
        })
    }

    /// The enhanced route a scrape escalates to, `None` when none is configured.
    #[must_use]
    pub fn enhanced_route(&self) -> Option<TierRoute<'_>> {
        match (&self.proxy_routes.enhanced_pool, &self.proxy_routes.enhanced) {
            (Some(route), _) => Some(TierRoute::Pool(route, PoolTier::Enhanced)),
            (None, Some(url)) => Some(TierRoute::Url(url)),
            (None, None) => None,
        }
    }

    /// The egress policy of `crawl` when it runs without an authorization record. See
    /// [`Self::policy_for_run`].
    #[must_use]
    pub fn policy_for(&self, crawl: &CreateCrawl) -> EgressPolicy {
        self.policy_for_run(crawl, None)
    }

    /// The egress policy of `crawl` under the authorization `record` the run was admitted with.
    ///
    /// The record bounds every destination: its target (origins, URL prefixes, excluded paths) is
    /// attached as the policy's [`RecordScope`](crawlx_policy::RecordScope), so a redirect hop or a
    /// browser request outside it is refused with [`DenyRule::AuthorizationScope`](crawlx_policy::DenyRule).
    /// With `allowPrivateNetworks` the private ranges the run may reach are the record's
    /// `authorizedNetworks` (the worker's own `extra_allow` only applies to a run without a
    /// record, or to a record that lists none); the deployment lists bound them further.
    #[must_use]
    pub fn policy_for_run(&self, crawl: &CreateCrawl, record: Option<&AuthorizationRecord>) -> EgressPolicy {
        let mut policy =
            EgressPolicy::new(crawl.safety.allow_private_networks).with_seed_port(&crawl.seed_url);
        for role in &crawl.roles {
            if let Some(u) = &role.replica_base_url {
                policy = policy.with_seed_port(u);
            }
        }
        if crawl.safety.allow_private_networks {
            match record.filter(|r| !r.authorized_networks.is_empty()) {
                Some(record) => policy.extra_allow.clone_from(&record.authorized_networks),
                None => policy.extra_allow.clone_from(&self.extra_allow),
            }
        }
        policy.extra_deny.clone_from(&self.extra_deny);
        if let Some(lists) = &self.lists {
            policy = policy.with_lists(lists.clone());
        }
        if let Some(record) = record {
            policy = policy.with_record_scope(record.scope());
        }
        policy.fixture_scope.clone_from(&self.fixture_scope);
        policy.deployment_exempt = crawl.safety.profile == SafetyProfile::TestEnvironment;
        for p in &self.extra_ports {
            if !policy.extra_ports.contains(p) {
                policy.extra_ports.push(*p);
            }
        }
        policy
    }

    /// The configured resolver, or the system resolver.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub fn resolver(&self) -> Result<Arc<dyn Resolver>, WorkerError> {
        match &self.resolver {
            Some(r) => Ok(Arc::clone(r)),
            None => Ok(Arc::new(HickoryResolver::from_system_conf()?)),
        }
    }

    /// The resolver of `crawl`'s fetch plane: the injected one when set, else the servers
    /// the request lists in `fetch.resolvers` (the `-r` compatibility flag), else the system resolver.
    /// Egress checks apply to whatever the chosen resolver answers.
    ///
    /// # Errors
    /// [`WorkerError::Config`] when a listed server is not an `ip` or `ip:port`;
    /// [`WorkerError::Fetch`] when resolver configuration or construction fails.
    pub fn resolver_for(&self, crawl: &CreateCrawl) -> Result<Arc<dyn Resolver>, WorkerError> {
        if self.resolver.is_some() || crawl.fetch.resolvers.is_empty() {
            return self.resolver();
        }
        let servers = crawl
            .fetch
            .resolvers
            .iter()
            .map(|s| parse_resolver(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Arc::new(HickoryResolver::from_servers(&servers)?))
    }

    /// The loopback egress proxy of `crawl`'s browser plane: the run's egress policy (bound to
    /// the authorization `record` when the run has one, [`Self::policy_for_run`]) over
    /// `resolver`, plus whatever `options` carry (flow capture, request controls). With
    /// `fetch.proxy` set (the `-proxy` compatibility flag, `proxy: basic`) every request the policy
    /// admits is chained to that proxy, so rendered pages leave through it like URL-plane
    /// fetches do. A ProxyX pool route chains through the pool gateway with the run's sticky
    /// identity (`run` keys the sticky id), `CONNECT` only.
    ///
    /// # Errors
    /// [`WorkerError::Fetch`] when `fetch.proxy` is not a usable upstream proxy URL, the pool
    /// selector does not fit, or the loopback listener cannot be bound.
    pub async fn serve_proxy(
        &self,
        crawl: &CreateCrawl,
        run: CrawlRunId,
        record: Option<&AuthorizationRecord>,
        resolver: Arc<dyn Resolver>,
        options: EgressOptions,
    ) -> Result<EgressProxyHandle, WorkerError> {
        let route = self.route_for(crawl)?;
        let options = match route {
            TierRoute::Direct => options,
            TierRoute::Url(url) => options.with_upstream(UpstreamProxy::from_url(url)?),
            TierRoute::Pool(..) => match route.bind(run, None)? {
                Some(binding) => options.with_upstream(binding.upstream().clone()),
                None => options,
            },
        };
        Ok(EgressProxy::serve_with(Arc::new(self.policy_for_run(crawl, record)), resolver, options).await?)
    }
}

/// One `fetch.resolvers` entry: `ip` (port 53) or `ip:port` (`[v6]:port` for IPv6).
fn parse_resolver(entry: &str) -> Result<SocketAddr, WorkerError> {
    let entry = entry.trim();
    if let Ok(addr) = entry.parse::<SocketAddr>() {
        return Ok(addr);
    }
    entry
        .parse::<IpAddr>()
        .map(|ip| SocketAddr::new(ip, 53))
        .map_err(|_| {
            WorkerError::Config(format!(
                "fetch.resolvers: {entry:?} is not an IP address or ip:port"
            ))
        })
}

/// Operator-only permission for encrypted retained browser profiles. Never tenant configuration.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RetainedProfilePolicy {
    /// Secret reference resolving to 64 hexadecimal characters (an AES-256 key).
    pub key_ref: crawlx_core::secret::CredentialRef,
    /// Maximum secret lifetime, capped to one day.
    pub max_ttl: Duration,
    /// Explicit approval for browser preferences/extensions inside imported profiles.
    pub executable_preferences: bool,
}

impl RetainedProfilePolicy {
    /// Read operator environment. Enabling retention requires an explicit secret reference.
    ///
    /// # Errors
    /// Rejects missing keys, ambiguous booleans and TTLs outside 1..=86400 seconds.
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, WorkerError> {
        match getenv("CRAWLX_RETAINED_PROFILES_ENABLED").as_deref() {
            None | Some("false" | "0") => return Ok(None),
            Some("true" | "1") => {}
            _ => {
                return Err(WorkerError::Config(
                    "CRAWLX_RETAINED_PROFILES_ENABLED must be true or false".into(),
                ))
            }
        }
        let key_ref = getenv("CRAWLX_PROFILE_KEY_REF")
            .filter(|reference| {
                ["env://", "file://", "vault://", "cloud-sm://"]
                    .iter()
                    .any(|scheme| reference.starts_with(scheme))
            })
            .ok_or_else(|| {
                WorkerError::Config(
                    "retained profiles require CRAWLX_PROFILE_KEY_REF secret reference".into(),
                )
            })?;
        let ttl = getenv("CRAWLX_PROFILE_MAX_TTL_SECONDS")
            .map_or(Ok(3600u64), |value| value.parse::<u64>())
            .map_err(|_| WorkerError::Config("invalid retained profile TTL".into()))?;
        if !(1..=86_400).contains(&ttl) {
            return Err(WorkerError::Config(
                "retained profile TTL must be 1..=86400 seconds".into(),
            ));
        }
        let executable_preferences = match getenv("CRAWLX_PROFILE_EXECUTABLE_PREFERENCES").as_deref() {
            None | Some("false" | "0") => false,
            Some("true" | "1") => true,
            _ => {
                return Err(WorkerError::Config(
                    "invalid profile executable-preferences approval".into(),
                ))
            }
        };
        Ok(Some(Self {
            key_ref: crawlx_core::secret::CredentialRef(key_ref),
            max_ttl: Duration::from_secs(ttl),
            executable_preferences,
        }))
    }
}

/// Everything a worker process (or an in-process local run) needs.
#[derive(Clone)]
pub struct WorkerConfig {
    /// PostgreSQL URL. `None` runs against an in-memory store (CLI local runs, tests).
    pub database_url: Option<String>,
    /// Operator root for tenant-keyed credential/cache identity; never serialized or logged.
    pub request_identity_key: Option<crawlx_core::secret::SecretOr<[u8; 32]>>,
    /// Operator-provisioned durable checkpoint encryption; local memory stores use ephemeral custody.
    pub checkpoint_keys: Option<Arc<dyn crawlx_storage::checkpoint_crypto::CheckpointKeys>>,
    /// Durable key custody for encrypted artifacts (`CRAWLX_ARTIFACT_KMS_KEY_ID` or
    /// `CRAWLX_ARTIFACT_KEY_FILE`). PostgreSQL workers refuse to start without it; local memory
    /// stores use an ephemeral in-memory provider.
    pub artifact_keys: Option<Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys>>,
    /// Endpoint of the persistence-free Redis-compatible store holding each run's volatile
    /// secret registry (`CRAWLX_SECRET_REDIS_URL` / `_FILE`); never serialized or logged.
    pub secret_redis_url: Option<crawlx_core::secret::SecretOr<String>>,
    /// Lifetime of one run's volatile secret authority (`CRAWLX_SECRET_AUTHORITY_TTL_SECS`).
    /// There is no renewal: after expiry durable content writes of the run fail closed.
    pub secret_authority_ttl: Duration,
    /// Root of the filesystem artifact store.
    pub artifacts_dir: PathBuf,
    /// Bounded memory-only upload spool shared by this worker's artifact store.
    pub artifact_spool: crawlx_storage::UploadSpoolConfig,
    /// Immutable operator-approved delivery destinations, never supplied by page content.
    pub delivery: Arc<crate::delivery::DeliveryRegistry>,
    /// Worker id.
    pub worker_id: WorkerId,
    /// Concurrent session leases (planning default 4).
    pub max_sessions: usize,
    /// Browser contexts per Chromium process (planning default 4).
    pub contexts_per_browser: usize,
    /// Launch.
    pub launch: LaunchConfig,
    /// Egress.
    pub egress: EgressConfig,
    /// Telemetry.
    pub telemetry: TelemetryConfig,
    /// Trailing-slash policy of URL canonicalization (default keeps slashes).
    pub trailing_slash: TrailingSlash,
    /// Lease loop: exit after this long without any claimable work (`crawlx worker --recover`).
    pub idle_exit_after: Option<Duration>,
    /// System 1 engine and its authority ceiling. `None` skips non-Active requests;
    /// an Active request requires an authenticated G3 report and an Active engine.
    pub model: Option<ModelConfig>,
    /// Approved offline article-language model, loaded once by the operator on this worker.
    pub article_language_detector: Option<crawlx_core::article_language::ArticleLanguageHandle>,
    /// LLM planner endpoint; `None` runs without a planner (`dynamic.llmPlanner` is then ignored).
    pub planner: Option<PlannerConfig>,
    /// Milestone gates the run may rely on. Default grants none.
    /// Production loads authenticated evidence through [`Gates::load`].
    /// In-process tests must opt into explicit test-only gate status.
    pub gates: Gates,
    /// Attach to a running Chromium at this DevTools websocket instead of launching one
    /// (the `-chrome-ws-url` compatibility flag). Admitted only for runs whose safety profile
    /// is `test_environment` or `authorized_security_test`.
    pub cdp_ws_url: Option<url::Url>,
    /// Open sessions in incognito contexts (default true). `false` reuses the attached
    /// browser's default context, which belongs to a human (`-no-incognito`).
    pub incognito: bool,
    /// Explicit operator permission and encryption-key reference; absent disables retained profiles.
    pub retained_profiles: Option<RetainedProfilePolicy>,
    /// Download the Chromium build `chromium-pin.toml` names when no Chromium is installed
    /// (default false). The archive is unpacked only if its SHA-256 equals
    /// the pinned one. See also [`Self::chromium_cache`].
    pub auto_download_chromium: bool,
    /// Where downloaded Chromium builds live (`--chromium-cache`, default `.cache/chromium`
    /// or `CRAWLX_CHROMIUM_CACHE`).
    pub chromium_cache: PathBuf,
    /// Per-origin capacity shared by HTTP and browser effects across this worker's
    /// runs and tenants (default four). PostgreSQL stores also enforce
    /// this limit deployment-wide; all workers must use the same configured limit.
    /// Excess work queues rather than being rejected.
    pub origin_cap: Arc<GlobalOriginCap>,
    /// CPU pool shared by every run this process executes: CPU-bound steps
    /// such as HTML extraction queue on it, and the queue is `crawlx.cpu_pool.queue_depth`.
    /// The default is sized like [`crate::RuntimeConfig::default`]'s blocking pool; a binary
    /// that builds its runtime from another `RuntimeConfig` passes [`CpuPool::new`] of it.
    pub cpu_pool: CpuPool,
    /// Where to post every URL-plane exchange (the `-traffic-export` compatibility flag, operator level:
    /// never part of a request). `None` exports nothing.
    pub traffic_export: Option<TrafficExportConfig>,
    /// Operator-listed provider endpoints that check a detected token (`extract.validateSecrets`,
    /// the `-kb-validate-secrets` compatibility flag). `None` uses [`SecretValidators::builtin`], whose
    /// list is empty unless the build embeds one: then every finding stays `unknown`.
    pub secret_validators: Option<Arc<SecretValidators>>,
    /// Answers the form fields the deterministic filler could not resolve
    /// (`extract.formFill`). `None` leaves them seed-derived.
    pub form_ai: Option<Arc<dyn FormAi>>,
    /// Optional in-memory actual-action evidence for bounded benchmark runs.
    pub action_trace: Option<Arc<crate::action_trace::ActionTrace>>,
    /// The document LLM behind the compatibility-API scrape formats `json`, `summary`, `question`,
    /// `highlights`, `query` and `changeTracking`'s `json` mode. `None`: a page that asks for
    /// one of them fails with `llm_not_configured`.
    pub llm: Option<Arc<dyn LlmExtractor>>,
    /// Chooses per page whether the `json` format is answered by [`Self::llm`] or by a second
    /// chat-completions compatible endpoint (the `EXTRACTION_PROVIDER_*` settings); every other LLM format
    /// keeps using [`Self::llm`]. `None`: [`Self::llm`] answers `json` too.
    pub extraction_llm: Option<Arc<ExtractionRouter>>,
    /// The LLM that refines the markup-derived `branding` profile (`BRANDING_LLM_*`). `None`: the
    /// profile stays as the markup heuristics produced it. A refinement that fails keeps the
    /// markup profile and adds a warning to the document.
    pub branding_llm: Option<Arc<dyn LlmExtractor>>,
    /// Renders the pages of scrape runs whose options need a browser (`waitFor`, `actions`,
    /// `mobile`, `screenshot`) instead of the production
    /// [`BrowserRenderer`](crate::scrape::BrowserRenderer): a remote browser service, or a
    /// scripted renderer in tests. `None` renders in the worker's own browser pool.
    pub renderer: Option<Arc<dyn PageRenderer>>,
    /// Operator-only approved protocol services; absent registry also checks `CRAWLX_PROTOCOL_REGISTRY` at run admission.
    pub protocol_registry: Option<Arc<crate::protocol::ProtocolRegistry>>,
    /// Largest audio or video file one scrape downloads per `audio` / `video` format, bytes. The
    /// file is held in memory while it is downloaded, transcribed and stored, so this bounds the
    /// memory of one scrape; a larger file adds a `media_too_large:` warning to the page.
    /// Default [`DEFAULT_MEDIA_MAX_BYTES`](crate::scrape::DEFAULT_MEDIA_MAX_BYTES) (256 MiB).
    pub media_max_bytes: usize,
    /// The OCR engine behind the `image` parser and PDF `mode: ocr` / `auto` of the scrape
    /// `parsers` option (the compatibility `parsers`, `IMAGE_OCR_ENABLED` settings). `None`: images yield no text
    /// and scanned PDF pages stay empty, each with an `ocr_unavailable` warning on the document.
    pub ocr: Option<Arc<crawlx_extract::parse::ocr::Ocr>>,
    /// How long a worker trusts the state of an authorization record it has read before it reads
    /// it again (revocation, expiry). The record is
    /// re-read at admission, before each session starts and on the periodic lease check, at most
    /// once per interval; its validity window is enforced at the instant regardless. Default
    /// [`DEFAULT_RECHECK_INTERVAL`](crate::authorization::DEFAULT_RECHECK_INTERVAL) (60 s).
    pub authorization_recheck: Duration,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            database_url: None,
            request_identity_key: None,
            checkpoint_keys: None,
            artifact_keys: None,
            secret_redis_url: None,
            secret_authority_ttl: crawlx_storage::custody::MAX_AUTHORITY_TTL,
            artifacts_dir: PathBuf::from("./crawlx-artifacts"),
            artifact_spool: crawlx_storage::UploadSpoolConfig::default(),
            delivery: Arc::new(crate::delivery::DeliveryRegistry::new()),
            worker_id: WorkerId::new(),
            max_sessions: 4,
            contexts_per_browser: 4,
            launch: LaunchConfig::new(),
            egress: EgressConfig::default(),
            telemetry: TelemetryConfig::default(),
            trailing_slash: TrailingSlash::Keep,
            idle_exit_after: None,
            model: None,
            article_language_detector: None,
            planner: None,
            gates: Gates::none(),
            cdp_ws_url: None,
            incognito: true,
            retained_profiles: None,
            auto_download_chromium: false,
            chromium_cache: crawlx_browser::install::default_cache_root(),
            origin_cap: Arc::new(GlobalOriginCap::default()),
            cpu_pool: CpuPool::default(),
            traffic_export: None,
            secret_validators: None,
            form_ai: None,
            action_trace: None,
            llm: None,
            extraction_llm: None,
            branding_llm: None,
            renderer: None,
            protocol_registry: None,
            media_max_bytes: crate::scrape::DEFAULT_MEDIA_MAX_BYTES,
            ocr: None,
            authorization_recheck: crate::authorization::DEFAULT_RECHECK_INTERVAL,
        }
    }
}

impl WorkerConfig {
    /// Load the protected request identity root using the caller's environment lookup.
    ///
    /// # Errors
    /// Rejects malformed, ambiguous or unreadable inline/file inputs without echoing contents.
    pub fn request_identity_key_from_lookup(
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<crawlx_core::secret::SecretOr<[u8; 32]>>, WorkerError> {
        crawlx_core::secret::request_identity_key_from_lookup(getenv).map_err(WorkerError::from)
    }

    /// Load the operator's cloud KMS checkpoint key without exposing it in crawl configuration.
    ///
    /// # Errors
    /// Rejects empty key identifiers and provider initialization failures. No production key is generated.
    pub async fn load_checkpoint_keys_from_lookup(
        &mut self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), WorkerError> {
        let Some(key_id) = getenv("CRAWLX_CHECKPOINT_KMS_KEY_ID") else {
            return Ok(());
        };
        if key_id.trim().is_empty() {
            return Err(WorkerError::Config(
                "checkpoint KMS key id must not be empty".into(),
            ));
        }
        let keys = crawlx_storage::checkpoint_crypto::KmsCheckpointKeys::from_environment(key_id)
            .await
            .map_err(crate::error::SessionError::from)?;
        self.checkpoint_keys = Some(Arc::new(keys));
        Ok(())
    }

    /// Load the encrypted-artifact key provider, the volatile secret-registry endpoint and the
    /// authority lifetime from the caller's environment lookup.
    ///
    /// Every setting is optional here; [`crate::Stores::open`] refuses a PostgreSQL worker that
    /// lacks the key provider or the registry endpoint.
    ///
    /// # Errors
    /// Rejects setting both key providers, an unreadable or malformed key file or registry
    /// secret file, an empty value and a lifetime outside `1..=86400` seconds. No value is echoed.
    pub async fn load_artifact_custody_from_lookup(
        &mut self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), WorkerError> {
        self.artifact_keys = artifact_keys_from_lookup(getenv).await?;
        self.secret_redis_url = secret_redis_url_from_lookup(getenv)?;
        if let Some(raw) = getenv("CRAWLX_SECRET_AUTHORITY_TTL_SECS") {
            let seconds = raw.trim().parse::<u64>().ok().filter(|seconds| {
                (1..=crawlx_storage::custody::MAX_AUTHORITY_TTL.as_secs()).contains(seconds)
            });
            self.secret_authority_ttl = Duration::from_secs(seconds.ok_or_else(|| {
                WorkerError::Config("CRAWLX_SECRET_AUTHORITY_TTL_SECS must be an integer in 1..=86400".into())
            })?);
        }
        Ok(())
    }
}

/// Catalog custody and key provider of a read-only process.
pub type ReadOnlyCustody = (
    Arc<dyn crawlx_storage::ArtifactCustody>,
    Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys>,
);

/// The key provider the environment selects, resolved up to the one step that needs I/O.
enum ArtifactKeySelection {
    None,
    Kms(String),
    Ready(Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys>),
}

impl ArtifactKeySelection {
    /// Read the environment synchronously: the lookup closure is not required to be `Sync`, so
    /// it must not live inside a future that may be spawned.
    fn from_lookup(getenv: &dyn Fn(&str) -> Option<String>) -> Result<Self, WorkerError> {
        match (
            getenv("CRAWLX_ARTIFACT_KMS_KEY_ID"),
            getenv("CRAWLX_ARTIFACT_KEY_FILE"),
        ) {
            (Some(_), Some(_)) => Err(WorkerError::Config(
                "CRAWLX_ARTIFACT_KMS_KEY_ID and CRAWLX_ARTIFACT_KEY_FILE are mutually exclusive".into(),
            )),
            (Some(key_id), None) => {
                if key_id.trim().is_empty() {
                    return Err(WorkerError::Config(
                        "artifact KMS key id must not be empty".into(),
                    ));
                }
                Ok(Self::Kms(key_id))
            }
            (None, Some(_)) => {
                let keys = crawlx_storage::artifact_key_crypto::FileArtifactKeys::from_lookup(getenv)
                    .map_err(|error| WorkerError::Config(format!("artifact key file: {error}")))?;
                Ok(keys.map_or(Self::None, |keys| Self::Ready(Arc::new(keys))))
            }
            (None, None) => Ok(Self::None),
        }
    }

    async fn open(
        self,
    ) -> Result<Option<Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys>>, WorkerError> {
        match self {
            Self::None => Ok(None),
            Self::Ready(keys) => Ok(Some(keys)),
            Self::Kms(key_id) => {
                let keys = crawlx_storage::artifact_key_crypto::KmsArtifactKeys::from_environment(key_id)
                    .await
                    .map_err(|error| WorkerError::Config(format!("artifact key custody: {error}")))?;
                Ok(Some(Arc::new(keys)))
            }
        }
    }
}

/// Catalog custody for processes that only read sealed artifacts (API, export, replay of saved
/// responses, inspection): decryption goes through the catalog and the key provider of the
/// environment. Without one, sealed artifacts fail with an "unavailable" error and legacy
/// plaintext artifacts stay readable. No secret registry is needed.
///
/// The returned future does not borrow `getenv`, so it can be spawned.
///
/// # Errors
/// Rejects contradictory or malformed key settings, as [`artifact_keys_from_lookup`] does.
pub fn read_only_custody_from_lookup(
    pg: &crawlx_storage::Pg,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> impl std::future::Future<Output = Result<ReadOnlyCustody, WorkerError>> + Send {
    let selection = ArtifactKeySelection::from_lookup(getenv);
    let pg = pg.clone();
    async move {
        let keys: Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys> = match selection?.open().await?
        {
            Some(keys) => keys,
            None => Arc::new(crawlx_storage::artifact_key_crypto::UnavailableArtifactKeys),
        };
        let custody = crawlx_storage::PgArtifactCustody::new(
            crawlx_storage::custody::PgSecretAuthority::finalized_reads(pg),
        );
        let custody: Arc<dyn crawlx_storage::ArtifactCustody> = Arc::new(custody);
        Ok((custody, keys))
    }
}

/// Load the durable encrypted-artifact key provider named by the environment.
///
/// `CRAWLX_ARTIFACT_KMS_KEY_ID` selects cloud KMS (credentials and region come from the SDK's
/// default chains); `CRAWLX_ARTIFACT_KEY_FILE` selects a 64-hex-character root key file.
/// Exactly one may be set. `None` when neither is. The returned future does not borrow
/// `getenv`, so it can be spawned.
///
/// # Errors
/// Rejects both providers at once, an empty key identifier, a malformed or unsafe key file and
/// KMS client initialization failures. No key material or identifier is echoed.
pub fn artifact_keys_from_lookup(
    getenv: &dyn Fn(&str) -> Option<String>,
) -> impl std::future::Future<
    Output = Result<Option<Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys>>, WorkerError>,
> + Send {
    let selection = ArtifactKeySelection::from_lookup(getenv);
    async move { selection?.open().await }
}

/// Largest accepted size of the registry endpoint secret file.
const SECRET_REDIS_FILE_LIMIT: u64 = 4096;

/// Load the volatile secret-registry endpoint from `CRAWLX_SECRET_REDIS_URL` or the contents of
/// the file named by `CRAWLX_SECRET_REDIS_URL_FILE` (at most one of the two).
///
/// # Errors
/// Rejects both settings at once, an empty value and an unreadable or oversized file. The URL
/// carries credentials and is never echoed.
pub fn secret_redis_url_from_lookup(
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<crawlx_core::secret::SecretOr<String>>, WorkerError> {
    use std::io::Read as _;
    let value = match (
        getenv("CRAWLX_SECRET_REDIS_URL"),
        getenv("CRAWLX_SECRET_REDIS_URL_FILE"),
    ) {
        (Some(_), Some(_)) => {
            return Err(WorkerError::Config(
                "CRAWLX_SECRET_REDIS_URL and CRAWLX_SECRET_REDIS_URL_FILE are mutually exclusive".into(),
            ))
        }
        (Some(url), None) => url,
        (None, Some(path)) => {
            let unavailable =
                || WorkerError::Config("the secret registry URL file is unreadable or oversized".into());
            let file = std::fs::File::open(&path).map_err(|_| unavailable())?;
            let mut text = String::new();
            file.take(SECRET_REDIS_FILE_LIMIT + 1)
                .read_to_string(&mut text)
                .map_err(|_| unavailable())?;
            if !u64::try_from(text.len()).is_ok_and(|len| len <= SECRET_REDIS_FILE_LIMIT) {
                return Err(unavailable());
            }
            text
        }
        (None, None) => return Ok(None),
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(WorkerError::Config(
            "the secret registry URL must not be empty".into(),
        ));
    }
    Ok(Some(crawlx_core::secret::SecretOr::secret(value.to_owned())))
}

impl WorkerConfig {
    /// Load the bounded operator registry and resolve credential references before admission.
    ///
    /// # Errors
    /// Rejects unreadable, malformed or unsupported registry files and credential references.
    pub async fn load_delivery_from_lookup(
        &mut self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), WorkerError> {
        let Some(path) = getenv("CRAWLX_DELIVERY_REGISTRY") else {
            return Ok(());
        };
        if path.is_empty() {
            return Err(WorkerError::Config(
                "delivery registry path must not be empty".into(),
            ));
        }
        let resolver = crate::secrets::ChainResolver::from_env(Arc::new(crawlx_core::SystemClock)).await;
        self.delivery = Arc::new(
            crate::delivery::DeliveryRegistry::from_file(std::path::Path::new(&path), &resolver).await?,
        );
        Ok(())
    }
    /// Publish destination IDs and exact pinned language bundle digests without credentials.
    ///
    /// # Errors
    /// Rejects an oversized operator capability manifest.
    pub fn data_capabilities(
        &self,
    ) -> Result<crawlx_core::data_capabilities::WorkerDataCapabilitiesV1, WorkerError> {
        let mut facts = crawlx_core::data_capabilities::WorkerDataCapabilitiesV1::default();
        facts.destinations = self.delivery.capabilities();
        if let Some(handle) = &self.article_language_detector {
            facts.language_bundles.insert(handle.detector().bundle_digest());
        }
        facts.validate()?;
        Ok(facts)
    }
    /// Enforce request gates and required worker capabilities before target I/O.
    pub(crate) fn check_gates(&self, crawl: &CreateCrawl) -> Result<(), WorkerError> {
        crawl
            .check_gates(self.gates.status())
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        self.check_data_capabilities(crawl)?;
        if crawl.dynamic.system1_mode == System1Mode::Active {
            if self.gates.g3_token().is_none() {
                return Err(WorkerError::Config(
                    "system1Mode active requires authenticated G3 evidence".to_owned(),
                ));
            }
            if !self
                .model
                .as_ref()
                .is_some_and(|model| model.mode == System1Mode::Active)
            {
                return Err(WorkerError::Config(
                    "system1Mode active requires a configured Active model engine".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Enforce delivery and language capabilities independently of model gate authority.
    ///
    /// # Errors
    /// Refuses an invalid destination configuration or unavailable required capability.
    pub(crate) fn check_data_capabilities(&self, crawl: &CreateCrawl) -> Result<(), WorkerError> {
        self.delivery.validate_config(crawl)?;
        let required = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(crawl)?;
        if !self.data_capabilities()?.supports(&required) {
            return Err(WorkerError::Config(
                "worker lacks required delivery or language bundle capability".into(),
            ));
        }
        Ok(())
    }

    /// The browser launch configuration plus this worker's pinned Chromium download settings.
    #[must_use]
    pub fn launch_config(&self) -> LaunchConfig {
        let mut launch = self.launch.clone();
        launch.auto_download_chromium = self.auto_download_chromium;
        launch.set_chromium_cache(self.chromium_cache.clone());
        launch
    }
}

impl fmt::Debug for WorkerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkerConfig")
            .field("database_url", &self.database_url.as_ref().map(|_| "[set]"))
            .field("artifacts_dir", &self.artifacts_dir)
            .field("artifact_spool", &self.artifact_spool)
            .field("worker_id", &self.worker_id)
            .field("max_sessions", &self.max_sessions)
            .field("contexts_per_browser", &self.contexts_per_browser)
            .field("launch", &self.launch)
            .field("egress", &self.egress)
            .field("telemetry", &self.telemetry)
            .field("trailing_slash", &self.trailing_slash)
            .field("idle_exit_after", &self.idle_exit_after)
            .field("model", &self.model)
            .field("planner", &self.planner)
            .field("gates", &self.gates)
            .field("cdp_ws_url", &self.cdp_ws_url)
            .field("incognito", &self.incognito)
            .field(
                "retained_profiles",
                &self.retained_profiles.as_ref().map(|_| "[enabled]"),
            )
            .field("auto_download_chromium", &self.auto_download_chromium)
            .field("chromium_cache", &self.chromium_cache)
            .field("origin_cap", &self.origin_cap)
            .field("cpu_pool", &self.cpu_pool)
            .field("traffic_export", &self.traffic_export)
            .field(
                "secret_validators",
                &self.secret_validators.as_ref().map(|_| "[set]"),
            )
            .field("form_ai", &self.form_ai.as_ref().map(|_| "[set]"))
            .field("llm", &self.llm.as_ref().map(|_| "[set]"))
            .field("extraction_llm", &self.extraction_llm)
            .field("branding_llm", &self.branding_llm.as_ref().map(|_| "[set]"))
            .field("renderer", &self.renderer.as_ref().map(|_| "[set]"))
            .field(
                "protocol_registry",
                &self.protocol_registry.as_ref().map(|_| "[approved]"),
            )
            .field("media_max_bytes", &self.media_max_bytes)
            .field("ocr", &self.ocr)
            .field("authorization_recheck", &self.authorization_recheck)
            .finish()
    }
}

impl WorkerConfig {
    /// Load the explicitly installed language bundle on this worker's existing CPU pool.
    /// No file or model is downloaded. The path is operator configuration, never HTTP input.
    ///
    /// # Errors
    /// Refuses missing optional runtime, mismatched resource digests and invalid operator paths.
    pub async fn load_article_language_from_lookup(
        &mut self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), WorkerError> {
        let Some(root) = getenv("CRAWLX_ARTICLE_LANGUAGE_BUNDLE").filter(|value| !value.is_empty()) else {
            return Ok(());
        };
        if self.article_language_detector.is_some() {
            return Err(WorkerError::Config(
                "article language detector configured twice".into(),
            ));
        }
        let detector = self
            .cpu_pool
            .run(move || {
                crawlx_model::article_language::LocalArticleLanguage::open(std::path::Path::new(&root))
            })
            .await
            .map_err(WorkerError::ArticleLanguageTask)??;
        self.article_language_detector = Some(crawlx_core::article_language::ArticleLanguageHandle::new(
            Arc::new(detector),
        ));
        Ok(())
    }

    /// Check the exact worker-local capability before dispatching a model-requiring policy.
    ///
    /// # Errors
    /// Missing or different pinned bundles are explicit admission refusals, not unknown success.
    pub fn check_article_language(&self, crawl: &CreateCrawl) -> Result<(), WorkerError> {
        use crawlx_core::article_language::LanguageModeV1;
        let policy = crawl
            .scrape
            .as_ref()
            .and_then(|job| job.options.content_policy.as_ref())
            .or(crawl.extract.content.as_ref());
        if let Some(policy) = policy.filter(|policy| policy.language_mode != LanguageModeV1::DeclaredOnly) {
            if self
                .article_language_detector
                .as_ref()
                .is_none_or(|handle| Some(handle.detector().bundle_digest()) != policy.language_bundle_digest)
            {
                return Err(WorkerError::AcquisitionUnavailable(
                    "exact article language bundle unavailable",
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_fetch::proxyx::PoolTier;

    #[test]
    fn native_budget_auto_keeps_basic_while_legacy_auto_and_explicit_enhanced_fail_closed() {
        use crawlx_core::scrape::{JobKind, ProxyMode, ScrapeJob, ScrapeOptions};
        let mut crawl = CreateCrawl::new("https://fixture.example.test/".parse().unwrap());
        let options = ScrapeOptions {
            proxy: ProxyMode::Auto,
            ..ScrapeOptions::default()
        };
        crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
        let mut egress = EgressConfig::default();
        assert!(egress.route_for(&crawl).is_err());
        crawl.acquisition = Some(crawlx_core::acquisition::AcquisitionPolicyV1::default());
        assert!(egress.route_for(&crawl).unwrap().url().is_none());
        egress.proxy_routes.basic = Some("http://basic.fixture:8080".parse().unwrap());
        assert_eq!(
            egress.route_for(&crawl).unwrap().url(),
            egress.proxy_routes.basic.as_ref()
        );
        crawl.scrape.as_mut().unwrap().options.proxy = ProxyMode::Enhanced;
        assert!(egress.route_for(&crawl).is_err());
        egress.proxy_routes.enhanced = Some("http://enhanced.fixture:8080".parse().unwrap());
        assert_eq!(
            egress.route_for(&crawl).unwrap().url(),
            egress.proxy_routes.enhanced.as_ref()
        );
        crawl.scrape.as_mut().unwrap().options.proxy = ProxyMode::Auto;
        assert_eq!(
            egress.route_for(&crawl).unwrap().url(),
            egress.proxy_routes.basic.as_ref()
        );
    }

    fn pool_route(selector: &str) -> ProxyxRoute {
        ProxyxRoute::new(
            &"http://pool.fixture:8080".parse().unwrap(),
            None,
            crawlx_core::secret::SecretOr::secret("ak_fixture-key".to_owned()),
            crawlx_fetch::proxyx::PoolSelector::from_spec(selector).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn pool_routes_serve_their_tier_and_replace_the_url_of_the_tier() {
        use crawlx_core::scrape::{JobKind, ProxyMode, ScrapeJob, ScrapeOptions};
        let mut crawl = CreateCrawl::new("https://fixture.example.test/".parse().unwrap());
        crawl.fetch.proxy = Some("http://request.fixture:3128".parse().unwrap());
        let mut options = ScrapeOptions::default();
        crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options.clone()));
        let mut egress = EgressConfig::default();
        egress.proxy_routes.basic_pool = Some(pool_route("cc=fr"));
        egress.proxy_routes.enhanced_pool = Some(pool_route("kind=static"));

        let basic = egress.route_for(&crawl).unwrap();
        assert!(matches!(basic.pool(), Some((_, PoolTier::Basic))));
        assert!(basic.url().is_none());
        assert_eq!(basic.identity(), "proxyx://pool.fixture:8080?cc=fr");

        options.proxy = ProxyMode::Enhanced;
        crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options.clone()));
        let enhanced = egress.route_for(&crawl).unwrap();
        assert!(matches!(enhanced.pool(), Some((_, PoolTier::Enhanced))));
        assert_eq!(enhanced.identity(), "proxyx://pool.fixture:8080?kind=static");

        // Auto starts on the basic pool and may escalate to the enhanced pool
        options.proxy = ProxyMode::Auto;
        crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
        assert!(matches!(
            egress.route_for(&crawl).unwrap().pool(),
            Some((_, PoolTier::Basic))
        ));
        assert!(matches!(
            egress.enhanced_route().unwrap().pool(),
            Some((_, PoolTier::Enhanced))
        ));

        // without a scrape job only the request's own proxy applies, as for plain tier routes
        crawl.scrape = None;
        assert_eq!(
            egress.route_for(&crawl).unwrap().url().map(url::Url::as_str),
            Some("http://request.fixture:3128/")
        );
    }

    #[test]
    fn missing_enhanced_pool_still_fails_closed_and_debug_hides_credentials() {
        use crawlx_core::scrape::{JobKind, ProxyMode, ScrapeJob, ScrapeOptions};
        let mut crawl = CreateCrawl::new("https://fixture.example.test/".parse().unwrap());
        let options = ScrapeOptions {
            proxy: ProxyMode::Enhanced,
            ..ScrapeOptions::default()
        };
        crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, options));
        let mut egress = EgressConfig::default();
        egress.proxy_routes.basic_pool = Some(pool_route(""));
        let error = egress.route_for(&crawl).unwrap_err().to_string();
        assert!(error.contains("fetch.proxyx.enhanced"), "{error}");
        let shown = format!("{egress:?}");
        assert!(!shown.contains("ak_fixture-key"), "{shown}");
        assert!(shown.contains("[configured]"));
    }

    #[test]
    fn policy_carries_seed_port_and_private_flag() {
        let mut crawl = CreateCrawl::new(url::Url::parse("http://127.0.0.1:8123/").unwrap());
        crawl.safety.allow_private_networks = true;
        let cfg = EgressConfig {
            extra_ports: vec![9000],
            ..EgressConfig::default()
        };
        let p = cfg.policy_for(&crawl);
        assert!(p.allow_private);
        assert_eq!(p.extra_ports, vec![8123, 9000]);
        assert!(p.check_ip("127.0.0.1".parse().unwrap()).is_ok());
        let strict = cfg.policy_for(&CreateCrawl::new(
            url::Url::parse("https://example.com/").unwrap(),
        ));
        assert!(strict.check_ip("127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn a_record_bounds_the_policy_to_its_target_and_supplies_the_private_networks() {
        use crawlx_core::{Clock, SystemClock, TenantId};
        use crawlx_policy::DenyRule;
        let mut record = crawlx_policy::testkit::sample_record(
            TenantId::new(),
            SystemClock.now(),
            &["https://a.example.test"],
        );
        record.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        record.excluded_paths = vec!["/billing/*".to_owned()];
        let cfg = EgressConfig {
            extra_allow: vec!["127.0.0.0/8".parse().unwrap()],
            ..EgressConfig::default()
        };
        let mut crawl = CreateCrawl::new(url::Url::parse("https://a.example.test/").unwrap());
        crawl.safety.allow_private_networks = true;

        let bounded = cfg.policy_for_run(&crawl, Some(&record));
        let url = |s: &str| url::Url::parse(s).unwrap();
        assert!(bounded.check_url(&url("https://a.example.test/app")).is_ok());
        for outside in ["https://b.example.test/", "https://a.example.test/billing/x"] {
            let denied = bounded.check_url(&url(outside)).unwrap_err();
            assert_eq!(denied.rule, DenyRule::AuthorizationScope, "{outside}");
        }
        // the record's networks, not the worker's, are what the run may reach
        assert_eq!(bounded.extra_allow, record.authorized_networks);
        assert!(bounded.check_ip("10.20.1.1".parse().unwrap()).is_ok());
        assert!(bounded.check_ip("127.0.0.1".parse().unwrap()).is_err());

        // a run with no record keeps the worker's own list and no target bound
        let unbounded = cfg.policy_for(&crawl);
        assert_eq!(unbounded.extra_allow, cfg.extra_allow);
        assert!(unbounded.check_url(&url("https://b.example.test/")).is_ok());

        // a record that lists no network leaves the worker's list in force
        record.authorized_networks.clear();
        let fallback = cfg.policy_for_run(&crawl, Some(&record));
        assert_eq!(fallback.extra_allow, cfg.extra_allow);
    }

    #[test]
    fn defaults_match_the_plan() {
        let c = WorkerConfig::default();
        assert_eq!((c.max_sessions, c.contexts_per_browser), (4, 4));
        assert!(c.database_url.is_none());
    }
}
