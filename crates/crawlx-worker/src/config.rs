//! Worker configuration.

use crate::error::WorkerError;
use crate::model::{ModelConfig, PlannerConfig};
use crate::runtime::CpuPool;
use crate::scrape::PageRenderer;
use crate::surface::form_ai::FormAi;
use crate::surface::traffic_export::TrafficExportConfig;
use crawlx_browser::LaunchConfig;
use crawlx_core::config::System1Mode;
use crawlx_core::hash::Digest;
use crawlx_core::session_binding::SessionBindingV1;
use crawlx_core::{CrawlRunId, CreateCrawl, SafetyProfile, WorkerId};
use crawlx_extract::secret_validation::SecretValidators;
use crawlx_fetch::proxyx::{PoolBinding, PoolTier, ProxyxRoute};
use crawlx_fetch::{
    EgressOptions, EgressProxy, EgressProxyHandle, GlobalOriginCap, HickoryResolver, Resolver, UpstreamProxy,
};
use crawlx_model::llm::{EmbeddingsClient, ExtractionRouter, LlmExtractor};
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
    /// Operator-owned checked encrypted DNS. Wins over injected and tenant-listed resolvers.
    /// Construct with explicit endpoint pins and endpoint/answer policies; never tenant URLs.
    pub resolver_https: Option<Arc<crawlx_fetch::HttpsResolver>>,
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
            .field("resolver_https", &self.resolver_https)
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

    /// A credential-free diagnostic name. Authorization uses [`Self::egress_digest`].
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::Direct => "direct".to_owned(),
            Self::Url(url) => {
                let mut identity = (*url).clone();
                let _ = identity.set_username("");
                let _ = identity.set_password(None);
                identity.to_string()
            }
            Self::Pool(route, _) => route.identity(),
        }
    }

    /// The exact approved route authority, including tier and credential identity.
    #[must_use]
    pub fn egress_digest(&self) -> Digest {
        match self {
            Self::Direct => Digest::of("crawlx/session-direct-egress/v1", b"direct"),
            Self::Url(url) => Digest::of("crawlx/session-url-egress/v1", url.as_str().as_bytes()),
            Self::Pool(route, tier) => route.egress_digest(*tier),
        }
    }

    /// Bind stateless run traffic. Never use this route for a named HTTP or browser session.
    ///
    /// # Errors
    /// [`WorkerError::Fetch`] when the selector does not fit the username budget.
    pub fn bind_run(
        &self,
        run: CrawlRunId,
        report: Option<(Arc<EgressPolicy>, Arc<dyn Resolver>)>,
    ) -> Result<Option<Arc<PoolBinding>>, WorkerError> {
        let Some((route, tier)) = self.pool() else {
            return Ok(None);
        };
        let binding = route
            .bind_run(tier, run, report)
            .map_err(crawlx_fetch::FetchError::from)?;
        Ok(Some(binding))
    }

    /// Bind an admitted generation without changing its approved route.
    ///
    /// # Errors
    /// Returns a fetch error for identity drift, an inactive binding or an invalid selector.
    pub fn bind(
        &self,
        session: &SessionBindingV1,
        report: Option<(Arc<EgressPolicy>, Arc<dyn Resolver>)>,
    ) -> Result<Option<Arc<PoolBinding>>, WorkerError> {
        if session.identity.egress != self.egress_digest() {
            return Err(
                crawlx_fetch::FetchError::from(crawlx_fetch::proxyx::ProxyxError::EgressMismatch).into(),
            );
        }
        self.pool()
            .map(|(route, tier)| {
                route
                    .bind(tier, session, report)
                    .map_err(crawlx_fetch::FetchError::from)
            })
            .transpose()
            .map_err(WorkerError::from)
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
    ///
    /// # Errors
    /// Returns an error when caller host exclusions cannot be compiled.
    pub fn policy_for(&self, crawl: &CreateCrawl) -> Result<EgressPolicy, WorkerError> {
        self.policy_for_run(crawl, None)
    }

    /// The egress policy of `crawl` under the authorization `record` the run was admitted with.
    ///
    /// The record bounds every destination: its target (origins, URL prefixes, excluded paths) is
    /// attached as the policy's [`RecordScope`](crawlx_policy::RecordScope), so a redirect hop or a
    /// browser request outside it is refused with [`DenyRule::AuthorizationScope`](crawlx_policy::DenyRule).
    /// With `allowPrivateNetworks` the private ranges the run may reach are the record's
    /// `authorizedNetworks`. Empty or absent signed networks grant no private access, and
    /// the worker's `extra_allow` never substitutes for a record's networks. A run with no
    /// record at all (local and fixture runs) is limited to the operator's explicit
    /// `extra_allow` CIDRs. Caller host exclusions remain independent denials, including
    /// `private-ips`, on every DNS answer and peer check.
    ///
    /// # Errors
    /// Returns an error when caller host exclusions cannot be compiled.
    pub fn policy_for_run(
        &self,
        crawl: &CreateCrawl,
        record: Option<&AuthorizationRecord>,
    ) -> Result<EgressPolicy, WorkerError> {
        let exclusions = crawlx_policy::ExcludeHosts::new(&crawl.scope.exclude_hosts)?;
        let mut policy = EgressPolicy::new(false)
            .with_seed_port(&crawl.seed_url)
            .with_host_exclusions(exclusions);
        for role in &crawl.roles {
            if let Some(u) = &role.replica_base_url {
                policy = policy.with_seed_port(u);
            }
        }
        policy.extra_deny.clone_from(&self.extra_deny);
        if let Some(lists) = &self.lists {
            policy = policy.with_lists(lists.clone());
        }
        if let Some(record) = record {
            policy = if crawl.safety.allow_private_networks {
                policy.with_private_host_scope(crawlx_policy::egress::PrivateHostScope::new(record))
            } else {
                policy
                    .with_record_scope(record.scope())
                    .with_authorized_private_networks(Vec::new())
            };
        } else if crawl.safety.allow_private_networks {
            // No signed record exists to widen or contradict (local and fixture runs only;
            // production admission requires a record): the operator's explicit CIDR
            // allowance is the typed authorized list, never a boolean "all private".
            policy = policy.with_authorized_private_networks(self.extra_allow.clone());
        }
        policy.fixture_scope.clone_from(&self.fixture_scope);
        policy.deployment_exempt = crawl.safety.profile == SafetyProfile::TestEnvironment;
        for p in &self.extra_ports {
            if !policy.extra_ports.contains(p) {
                policy.extra_ports.push(*p);
            }
        }
        Ok(policy)
    }

    /// The operator's encrypted resolver, otherwise the injected or system resolver.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub fn resolver(&self) -> Result<Arc<dyn Resolver>, WorkerError> {
        if let Some(resolver) = &self.resolver_https {
            return Ok(Arc::clone(resolver) as Arc<dyn Resolver>);
        }
        match &self.resolver {
            Some(r) => Ok(Arc::clone(r)),
            None => Ok(Arc::new(HickoryResolver::from_system_conf()?)),
        }
    }

    /// The resolver of `crawl`'s fetch plane: operator encrypted DNS first, then the
    /// injected resolver, tenant-listed servers, or system configuration.
    /// Checked target resolution still applies the run's policy to every answer.
    ///
    /// # Errors
    /// [`WorkerError::Config`] when a listed server is not an `ip` or `ip:port`;
    /// [`WorkerError::Fetch`] when resolver configuration or construction fails.
    pub fn resolver_for(&self, crawl: &CreateCrawl) -> Result<Arc<dyn Resolver>, WorkerError> {
        if self.resolver_https.is_some() || self.resolver.is_some() || crawl.fetch.resolvers.is_empty() {
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
            TierRoute::Pool(..) => match route.bind_run(run, None)? {
                Some(binding) => options.with_upstream(binding.upstream().clone()),
                None => options,
            },
        };
        Ok(EgressProxy::serve_with(Arc::new(self.policy_for_run(crawl, record)?), resolver, options).await?)
    }

    /// Select only an operator route already approved by this generation.
    ///
    /// # Errors
    /// Refuses a changed request override, deployment route or unapproved tier.
    pub(crate) fn bound_route<'a>(
        &'a self,
        crawl: &'a CreateCrawl,
        binding: &SessionBindingV1,
    ) -> Result<TierRoute<'a>, WorkerError> {
        let route = self.route_for(crawl)?;
        if route.egress_digest() == binding.identity.egress {
            return Ok(route);
        }
        if let Some(enhanced) = self.enhanced_route() {
            if enhanced.egress_digest() == binding.identity.egress {
                return Ok(enhanced);
            }
        }
        Err(crawlx_fetch::FetchError::from(crawlx_fetch::proxyx::ProxyxError::EgressMismatch).into())
    }

    /// Serve a generation-owned browser proxy using the same pool binding as HTTP.
    ///
    /// # Errors
    /// Returns an error for missing/shared binding drift, unapproved routes or listener failure.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn serve_bound_proxy(
        &self,
        crawl: &CreateCrawl,
        binding: &SessionBindingV1,
        record: Option<&AuthorizationRecord>,
        resolver: Arc<dyn Resolver>,
        options: EgressOptions,
        pool: Option<Arc<PoolBinding>>,
    ) -> Result<EgressProxyHandle, WorkerError> {
        let route = self.bound_route(crawl, binding)?;
        let options = match (route, pool) {
            (TierRoute::Direct, None) => options,
            (TierRoute::Url(url), None) => options.with_upstream(UpstreamProxy::from_url(url)?),
            (TierRoute::Pool(..), Some(pool)) => {
                pool.validate_session(binding)
                    .map_err(crawlx_fetch::FetchError::from)?;
                options.with_upstream(pool.upstream().clone())
            }
            _ => return Err(WorkerError::Config("session proxy binding unavailable".into())),
        };
        Ok(EgressProxy::serve_with(Arc::new(self.policy_for_run(crawl, record)?), resolver, options).await?)
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

/// The embedding model of the scrape `clusters` option: the client and the label recorded on the
/// result (a model name, never a credential).
#[derive(Clone)]
#[non_exhaustive]
pub struct ClusterEmbeddings {
    /// Turns the chunks of a page into vectors.
    pub client: Arc<dyn EmbeddingsClient>,
    /// Model label recorded on the cluster envelope.
    pub model: String,
}

impl ClusterEmbeddings {
    /// Embed with `client`, recording `model` on every result.
    #[must_use]
    pub fn new(client: Arc<dyn EmbeddingsClient>, model: impl Into<String>) -> Self {
        Self {
            client,
            model: model.into(),
        }
    }
}

/// Everything a worker process (or an in-process local run) needs.
#[derive(Clone)]
pub struct WorkerConfig {
    /// Database URL (`postgres:`, `mariadb:`/`mysql:` or `sqlite:`). `None` runs against an
    /// in-memory store (CLI local runs, tests).
    pub database_url: Option<String>,
    /// Pool size and timeouts of the connection to `database_url`.
    pub store: crawlx_storage::StoreConfig,
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
    /// Renewable use window for volatile secret authority (`CRAWLX_SECRET_AUTHORITY_TTL_SECS`).
    pub secret_authority_ttl: Duration,
    /// Absolute operator ceiling; renewal never extends the original physical secret expiry.
    pub secret_authority_hard_max: Duration,
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
    /// Operator-approved bounded source traversal and finalized metadata projection.
    pub source_dispatch: Option<Arc<crate::source_dispatch::SourceDispatcher>>,
    /// LLM planner endpoint; required when `dynamic.llmPlanner` is not `off`.
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
    /// Optional process-local interactive registry shared with the loopback API.
    pub interactive_profiles: Option<Arc<crate::interactive_profiles::InteractiveProfiles>>,
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
    /// The embedding model behind the scrape `clusters` option. `None`: a page that asks for
    /// clusters fails with `llm_not_configured` before it is fetched.
    pub embeddings: Option<ClusterEmbeddings>,
    /// Renders the pages of scrape runs whose options need a browser (`waitFor`, `actions`,
    /// `mobile`, `screenshot`) instead of the production
    /// [`BrowserRenderer`](crate::scrape::BrowserRenderer): a remote browser service, or a
    /// scripted renderer in tests. `None` renders in the worker's own browser pool.
    pub renderer: Option<Arc<dyn PageRenderer>>,
    /// Operator-only approved protocol services; absent registry also checks `CRAWLX_PROTOCOL_REGISTRY` at run admission.
    pub protocol_registry: Option<Arc<crate::protocol::ProtocolRegistry>>,
    /// Operator-owned immutable recipe registry; never read from tenant request JSON.
    pub archive_behaviors: Option<Arc<crate::archive_behaviors::RecipeRegistry>>,
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
            store: crawlx_storage::StoreConfig::default(),
            request_identity_key: None,
            checkpoint_keys: None,
            artifact_keys: None,
            secret_redis_url: None,
            secret_authority_ttl: Duration::from_secs(3600),
            secret_authority_hard_max: Duration::from_secs(259_200),
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
            source_dispatch: None,
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
            interactive_profiles: None,
            llm: None,
            extraction_llm: None,
            branding_llm: None,
            embeddings: None,
            renderer: None,
            protocol_registry: None,
            archive_behaviors: None,
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

    /// Load the operator's checkpoint key provider without exposing it in crawl configuration.
    ///
    /// `CRAWLX_CHECKPOINT_KMS_KEY_ID` selects cloud KMS; `CRAWLX_CHECKPOINT_KEK_FILE` selects a
    /// local key-encryption-key file (`<key-id>:<64 hex>` lines, mode `0600`, first line primary).
    /// Setting neither leaves browser checkpoints unavailable.
    ///
    /// # Errors
    /// Rejects setting both providers, empty values, an unreadable, unsafe or malformed key file
    /// and provider initialization failures. No production key is generated and no value is echoed.
    pub async fn load_checkpoint_keys_from_lookup(
        &mut self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), WorkerError> {
        let kms = getenv("CRAWLX_CHECKPOINT_KMS_KEY_ID");
        let file = getenv("CRAWLX_CHECKPOINT_KEK_FILE");
        match (kms, file) {
            (None, None) => Ok(()),
            (Some(_), Some(_)) => Err(WorkerError::Config(
                "CRAWLX_CHECKPOINT_KMS_KEY_ID and CRAWLX_CHECKPOINT_KEK_FILE are mutually exclusive".into(),
            )),
            (Some(key_id), None) => {
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
            (None, Some(path)) => {
                if path.trim().is_empty() {
                    return Err(WorkerError::Config(
                        "checkpoint key-encryption-key file path must not be empty".into(),
                    ));
                }
                let keys = crawlx_storage::checkpoint_crypto::FileCheckpointKeys::from_file(
                    std::path::Path::new(&path),
                )
                .map_err(|error| WorkerError::Config(format!("CRAWLX_CHECKPOINT_KEK_FILE: {error}")))?;
                self.checkpoint_keys = Some(Arc::new(keys));
                Ok(())
            }
        }
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
        if let Some(raw) = getenv("CRAWLX_SECRET_AUTHORITY_HARD_MAX_SECS") {
            let seconds = raw
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|seconds| (1..=259_200).contains(seconds))
                .ok_or_else(|| {
                    WorkerError::Config(
                        "CRAWLX_SECRET_AUTHORITY_HARD_MAX_SECS must be an integer in 1..=259200".into(),
                    )
                })?;
            self.secret_authority_hard_max = Duration::from_secs(seconds);
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
    store: &crate::durable::DurableStore,
    getenv: &dyn Fn(&str) -> Option<String>,
) -> impl std::future::Future<Output = Result<ReadOnlyCustody, WorkerError>> + Send {
    let selection = ArtifactKeySelection::from_lookup(getenv);
    let authority = crate::durable::DurableAuthority::finalized_reads(store);
    async move {
        let keys: Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys> = match selection?.open().await?
        {
            Some(keys) => keys,
            None => Arc::new(crawlx_storage::artifact_key_crypto::UnavailableArtifactKeys),
        };
        Ok((authority.custody(), keys))
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
        let mut facts = self.delivery.capabilities();
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
            .field("store", &self.store)
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
            .field("cdp_ws_url", &self.cdp_ws_url.as_ref().map(|_| "[set]"))
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
            .field("embeddings", &self.embeddings.as_ref().map(|e| &e.model))
            .field("renderer", &self.renderer.as_ref().map(|_| "[set]"))
            .field(
                "protocol_registry",
                &self.protocol_registry.as_ref().map(|_| "[approved]"),
            )
            .field(
                "archive_behaviors",
                &self.archive_behaviors.as_ref().map(|_| "[approved]"),
            )
            .field("media_max_bytes", &self.media_max_bytes)
            .field("ocr", &self.ocr)
            .field("authorization_recheck", &self.authorization_recheck)
            .finish()
    }
}

impl WorkerConfig {
    /// Compile bounded source traversal and metadata projection from operator-local configuration.
    /// No configuration is loaded from fetched content or tenant request fields.
    ///
    /// # Errors
    /// Refuses duplicate configuration, unreadable files, unsupported versions and invalid limits.
    pub fn load_source_dispatch_from_lookup(
        &mut self,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> Result<(), WorkerError> {
        if self.source_dispatch.is_some() && getenv("CRAWLX_SOURCE_DISPATCH_CONFIG").is_some() {
            return Err(WorkerError::Config("source dispatcher configured twice".into()));
        }
        if self.source_dispatch.is_none() {
            self.source_dispatch =
                crate::source_dispatch::SourceDispatcher::from_env(getenv).map_err(|_| {
                    WorkerError::Config("source dispatcher configuration unavailable or invalid".into())
                })?;
        }
        Ok(())
    }
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

impl WorkerConfig {
    /// Resolve a tenant's recipe reference once, before creating any browser context.
    ///
    /// # Errors
    /// Refuses absent registries, unknown pins, unapproved tenants and conflicting request options.
    pub async fn resolve_archive_behaviors(
        &self,
        crawl: &CreateCrawl,
        tenant: crawlx_core::TenantId,
    ) -> Result<Option<Arc<crawlx_core::archive_behaviors::RecipeV1>>, WorkerError> {
        let Some(options) = crawl.scrape.as_ref().map(|job| &job.options) else {
            return Ok(None);
        };
        let Some(reference) = &options.archive_behavior else {
            return Ok(None);
        };
        options.validate().map_err(WorkerError::Config)?;
        if crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr {
            return Err(WorkerError::Config(
                "approved recipe provenance is unavailable under zero-data retention".to_owned(),
            ));
        }
        if self.renderer.is_some() {
            return Err(WorkerError::Config(
                "approved recipes require the native Session Actor renderer".to_owned(),
            ));
        }
        let registry = self.approved_recipe_registry().await?;
        let recipe = registry.resolve(reference, tenant)?;
        if recipe
            .entry_url
            .as_ref()
            .is_some_and(|url| url != &crawl.seed_url)
            || (recipe.entry_url.is_some() && crawl.scrape.as_ref().is_some_and(|job| !job.urls.is_empty()))
        {
            return Err(WorkerError::Config(
                "recorded recipe requires its exact single initial URL".to_owned(),
            ));
        }
        Ok(Some(recipe))
    }

    async fn approved_recipe_registry(
        &self,
    ) -> Result<Arc<crate::archive_behaviors::RecipeRegistry>, WorkerError> {
        match &self.archive_behaviors {
            Some(registry) => Ok(Arc::clone(registry)),
            None => {
                let path = std::env::var_os("CRAWLX_RECIPE_REGISTRY")
                    .ok_or_else(|| WorkerError::Config("operator recipe registry absent".into()))?;
                crate::archive_behaviors::RecipeRegistry::from_file(std::path::Path::new(&path)).await
            }
        }
    }

    /// Resolve the actor recipe only through the operator's existing tenant-approved registry.
    ///
    /// # Errors
    /// Rejects invalid recipes, ZDR, injected renderers and missing or mismatched approval pins.
    pub async fn resolve_extension_actor_recipe(
        &self,
        crawl: &CreateCrawl,
        tenant: crawlx_core::TenantId,
    ) -> Result<Option<Arc<crawlx_core::archive_behaviors::RecipeV1>>, WorkerError> {
        let Some(spec) = &crawl.extension_recipe else {
            return Ok(None);
        };
        let compiled = crate::extension_recipes::CompiledExtensionRecipe::new(spec.clone())
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        if compiled.actor().steps.is_empty() {
            return Ok(None);
        }
        if crawl.retention.mode == crawlx_core::config::RetentionMode::Zdr || self.renderer.is_some() {
            return Err(WorkerError::Config(
                "actor recipe requires retained native execution".into(),
            ));
        }
        let reference = crawlx_core::archive_behaviors::RecipeReferenceV1::for_recipe(compiled.actor())
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        let registry = self.approved_recipe_registry().await?;
        Ok(Some(registry.resolve(&reference, tenant)?))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_fetch::proxyx::PoolTier;

    #[tokio::test]
    async fn operator_encrypted_dns_wins_over_injected_and_tenant_resolvers() {
        let endpoint = "https://resolver.test/dns-query".parse().unwrap();
        let config = crawlx_fetch::HttpsResolverConfig::new(endpoint, vec!["93.184.216.34".parse().unwrap()]);
        let encrypted = Arc::new(
            crawlx_fetch::HttpsResolver::new(
                config,
                Arc::new(EgressPolicy::default()),
                Arc::new(EgressPolicy::default()),
                tokio_util::sync::CancellationToken::new(),
            )
            .unwrap(),
        );
        let expected: Arc<dyn Resolver> = encrypted.clone();
        let egress = EgressConfig {
            resolver_https: Some(encrypted),
            resolver: Some(Arc::new(crawlx_fetch::StaticResolver::new())),
            ..EgressConfig::default()
        };
        let mut crawl = CreateCrawl::new("https://owned.test/".parse().unwrap());
        // A tenant cannot replace the operator endpoint, even with malformed server input.
        crawl.fetch.resolvers = vec!["not-an-address".to_owned()];
        let selected = egress.resolver_for(&crawl).unwrap();
        assert!(Arc::ptr_eq(&selected, &expected));
        assert!(matches!(
            selected.resolve("127.0.0.1").await,
            Err(crawlx_fetch::FetchError::EgressDenied(_))
        ));
        assert!(Arc::ptr_eq(&egress.resolver().unwrap(), &expected));
    }

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
    fn strict_generation_refuses_tier_switch_even_after_health_replacement() {
        use crawlx_core::scrape::{JobKind, ScrapeJob, ScrapeOptions};
        use crawlx_core::session_binding::{RetirementReason, SessionIdentityV1};
        let mut crawl = CreateCrawl::new("https://fixture.example.test/".parse().unwrap());
        crawl.scrape = Some(ScrapeJob::new(JobKind::Scrape, ScrapeOptions::default()));
        let mut egress = EgressConfig::default();
        egress.proxy_routes.basic_pool = Some(pool_route("cc=fr"));
        egress.proxy_routes.enhanced_pool = Some(pool_route("cc=de"));
        let route = egress.route_for(&crawl).unwrap();
        let digest = Digest::of("fixture", b"identity");
        let identity: SessionIdentityV1 = serde_json::from_value(serde_json::json!({
            "tenant": "00000000-0000-0000-0000-000000000001",
            "run": "00000000-0000-0000-0000-000000000002",
            "principal": crawlx_core::PrincipalId::anonymous(),
            "session": "00000000-0000-0000-0000-000000000003",
            "acquisition": digest,
            "backend_build": digest,
            "egress": route.egress_digest(),
            "identity_policy": digest,
            "profile": null,
        }))
        .unwrap();
        let binding = SessionBindingV1::new(
            identity,
            7,
            chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap(),
        );
        let enhanced = egress.enhanced_route().unwrap();
        assert!(enhanced.bind(&binding, None).is_err());
        let mut changed = binding.identity.clone();
        changed.egress = enhanced.egress_digest();
        assert!(binding
            .replace(changed.clone(), true, binding.expires_at)
            .is_err());
        let mut retired = binding.clone();
        retired.begin_drain(RetirementReason::Unhealthy).unwrap();
        retired.finish_cleanup(true).unwrap();
        // Health replacement preserves approved egress; it cannot authorize a tier switch.
        assert!(retired.replace(changed, true, retired.expires_at).is_err());
        let next = retired
            .replace(retired.identity.clone(), true, retired.expires_at)
            .unwrap();
        assert!(enhanced.bind(&next, None).is_err());
        assert!(egress
            .bound_route(&crawl, &next)
            .unwrap()
            .bind(&next, None)
            .is_ok());
        let pool = route.bind(&binding, None).unwrap().unwrap();
        assert!(pool.validate_session(&next).is_err());
        egress.proxy_routes.basic_pool = Some(pool_route("cc=us"));
        assert!(egress.bound_route(&crawl, &binding).is_err());
    }

    #[test]
    fn diagnostic_proxy_name_hides_credentials_but_authority_digest_keeps_them_distinct() {
        let one: url::Url = "http://reader:first-secret@proxy.fixture:8080".parse().unwrap();
        let two: url::Url = "http://reader:second-secret@proxy.fixture:8080".parse().unwrap();
        let one = TierRoute::Url(&one);
        let two = TierRoute::Url(&two);
        assert_eq!(one.identity(), "http://proxy.fixture:8080/");
        assert_eq!(one.identity(), two.identity());
        assert_ne!(one.egress_digest(), two.egress_digest());
    }

    #[test]
    fn policy_carries_seed_port_without_unsigned_private_authority() {
        let mut crawl = CreateCrawl::new(url::Url::parse("http://127.0.0.1:8123/").unwrap());
        crawl.safety.allow_private_networks = true;
        let cfg = EgressConfig {
            extra_ports: vec![9000],
            ..EgressConfig::default()
        };
        let p = cfg.policy_for(&crawl).unwrap();
        assert!(!p.allow_private);
        assert_eq!(p.extra_ports, vec![8123, 9000]);
        assert!(p.check_ip("127.0.0.1".parse().unwrap()).is_err());
        let strict = cfg
            .policy_for(&CreateCrawl::new(
                url::Url::parse("https://example.com/").unwrap(),
            ))
            .unwrap();
        assert!(strict.check_ip("127.0.0.1".parse().unwrap()).is_err());
    }

    #[test]
    fn a_run_without_a_record_reaches_only_the_operators_explicit_networks() {
        let mut crawl = CreateCrawl::new(url::Url::parse("http://127.0.0.1:8123/").unwrap());
        crawl.safety.allow_private_networks = true;
        let cfg = EgressConfig {
            extra_allow: vec!["127.0.0.1/32".parse().unwrap()],
            ..EgressConfig::default()
        };
        let p = cfg.policy_for(&crawl).unwrap();
        assert!(p.check_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(p.check_ip("127.0.0.2".parse().unwrap()).is_err());
        assert!(p.check_ip("10.0.0.5".parse().unwrap()).is_err());
        assert!(p.check_ip("169.254.169.254".parse().unwrap()).is_err());
        crawl.safety.allow_private_networks = false;
        assert!(cfg
            .policy_for(&crawl)
            .unwrap()
            .check_ip("127.0.0.1".parse().unwrap())
            .is_err());
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

        let bounded = cfg.policy_for_run(&crawl, Some(&record)).unwrap();
        let url = |s: &str| url::Url::parse(s).unwrap();
        assert!(bounded.check_url(&url("https://a.example.test/app")).is_ok());
        for outside in ["https://b.example.test/", "https://a.example.test/billing/x"] {
            let denied = bounded.check_url(&url(outside)).unwrap_err();
            assert_eq!(denied.rule, DenyRule::AuthorizationScope, "{outside}");
        }
        // the record's networks, not the worker's, are what the run may reach
        assert_eq!(
            bounded.authorized_private_networks(),
            Some(record.authorized_networks.as_slice())
        );
        assert!(bounded.check_ip("10.20.1.1".parse().unwrap()).is_ok());
        assert!(bounded.check_ip("127.0.0.1".parse().unwrap()).is_err());

        // Without a record the run is limited to the operator's explicit `extra_allow` CIDRs
        // (see `policy_for_run`): exactly those, never "all private".
        let unbounded = cfg.policy_for(&crawl).unwrap();
        assert!(unbounded.extra_allow.is_empty());
        assert!(unbounded.check_ip("127.0.0.1".parse().unwrap()).is_ok());
        assert!(unbounded.check_ip("10.20.1.1".parse().unwrap()).is_err());
        assert!(unbounded.check_url(&url("https://b.example.test/")).is_ok());
        // A request boolean that is off grants no private access whatever the operator allows.
        let mut public_only = crawl.clone();
        public_only.safety.allow_private_networks = false;
        let denied = cfg.policy_for(&public_only).unwrap();
        assert!(denied.check_ip("127.0.0.1".parse().unwrap()).is_err());

        // An empty signed network list grants no private access.
        record.authorized_networks.clear();
        let fallback = cfg.policy_for_run(&crawl, Some(&record)).unwrap();
        assert!(fallback.extra_allow.is_empty());
        assert!(fallback.check_ip("127.0.0.1".parse().unwrap()).is_err());
        assert!(fallback.check_ip("10.20.1.1".parse().unwrap()).is_err());
        assert!(fallback
            .authorized_private_networks()
            .is_some_and(|networks| networks.is_empty()));

        record.authorized_networks = vec!["10.20.0.0/16".parse().unwrap()];
        crawl.scope.exclude_hosts = vec!["^a\\.example\\.test$".to_owned()];
        let excluded = cfg.policy_for_run(&crawl, Some(&record)).unwrap();
        assert_eq!(
            excluded
                .check_all("a.example.test", &["10.20.1.1".parse().unwrap()])
                .unwrap_err()
                .rule,
            DenyRule::HostExcluded
        );
        crawl.scope.exclude_hosts = vec!["private-ips".to_owned()];
        let private_excluded = cfg.policy_for_run(&crawl, Some(&record)).unwrap();
        assert_eq!(
            private_excluded
                .check_all("a.example.test", &["10.20.1.1".parse().unwrap()])
                .unwrap_err()
                .rule,
            DenyRule::HostExcluded
        );
        crawl.scope.exclude_hosts = vec!["[".to_owned()];
        assert!(cfg.policy_for_run(&crawl, Some(&record)).is_err());
    }

    #[test]
    fn defaults_match_the_plan() {
        let c = WorkerConfig::default();
        assert_eq!((c.max_sessions, c.contexts_per_browser), (4, 4));
        assert!(c.database_url.is_none());
    }

    #[test]
    fn debug_output_hides_the_devtools_url() {
        let mut c = WorkerConfig::default();
        let url = url::Url::parse("ws://127.0.0.1:9222/devtools/browser/lease-token-4242").unwrap();
        c.cdp_ws_url = Some(url.clone());
        c.launch.cdp_ws_url = Some(url);
        let shown = format!("{c:?}");
        assert!(!shown.contains("lease-token-4242"), "{shown}");
        assert!(shown.contains("cdp_ws_url: Some(\"[set]\")"), "{shown}");
    }
}
