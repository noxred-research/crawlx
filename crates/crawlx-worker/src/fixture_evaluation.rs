//! In-process, listener-bound authority for controlled fixture experiments, never promotion.
//!
//! The owner retains the bound socket until every capability is dropped. Stopping the
//! server revokes capabilities immediately; retaining the socket prevents a stale capability
//! from reaching a different service that later reuses its port. Nothing here is serializable.

use crawlx_core::config::{CreateCrawl, LlmPlannerMode, SafetyProfile, System1Mode};
use crawlx_core::hash::Digest;
use crawlx_core::repo::CrawlRun;
use crawlx_core::{AuthorizationRecordId, Clock, CoreError, CrawlRunId, SystemClock, TenantId};
use crawlx_policy::fixture_evaluation::{FixtureEvaluationLease, FixtureEvaluationScope};
use crawlx_policy::{AuthorizationRecord, AuthzFailure, PolicyError};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Failure to create or validate a controlled fixture capability.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FixtureEvaluationError {
    /// Binding or cloning the real local listener failed.
    #[error("fixture listener: {0}")]
    Io(#[from] std::io::Error),
    /// Request digest construction failed.
    #[error("fixture request: {0}")]
    Core(#[from] CoreError),
    /// Authorization body construction failed.
    #[error("fixture authorization: {0}")]
    Policy(#[from] PolicyError),
    /// The authorization is no longer usable.
    #[error("fixture authorization: {0}")]
    Authorization(#[from] AuthzFailure),
    /// A binding or isolation invariant was not met.
    #[error("fixture evaluation refused: {0}")]
    Invalid(&'static str),
}

#[derive(Debug)]
struct ListenerIdentity {
    listener: TcpListener,
    address: SocketAddr,
    live: CancellationToken,
}

/// Owner of a real, nonblocking, ephemeral IPv4 loopback listener.
///
/// Keep this owner beside the fixture server task. Dropping it revokes every issued permit.
#[derive(Debug)]
pub struct FixtureEvaluationHost {
    identity: Arc<ListenerIdentity>,
    scope: FixtureEvaluationScope,
}

impl FixtureEvaluationHost {
    /// Bind the controlled server. No caller-supplied origin or port is accepted.
    ///
    /// # Errors
    /// Returns a typed I/O error if binding or nonblocking setup fails.
    pub fn bind() -> Result<Self, FixtureEvaluationError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let identity = Arc::new(ListenerIdentity {
            listener,
            address,
            live: CancellationToken::new(),
        });
        let scope = FixtureEvaluationScope::new(Arc::clone(&identity) as Arc<dyn FixtureEvaluationLease>)
            .ok_or(FixtureEvaluationError::Invalid("invalid listener origin"))?;
        Ok(Self { identity, scope })
    }

    /// Clone the retained listener for the real fixture HTTP server.
    ///
    /// # Errors
    /// Fails if the owner stopped or the operating system cannot clone its socket.
    pub fn listener(&self) -> Result<TcpListener, FixtureEvaluationError> {
        if self.identity.live.is_cancelled() {
            return Err(FixtureEvaluationError::Invalid("fixture server stopped"));
        }
        Ok(self.identity.listener.try_clone()?)
    }

    /// Immutable actual origin, independent of caller-visible URL strings.
    #[must_use]
    pub fn origin(&self) -> &Url {
        self.scope.origin()
    }

    /// Narrowing-only scope for every browser/fetch resource and server shutdown.
    #[must_use]
    pub fn scope(&self) -> FixtureEvaluationScope {
        self.scope.clone()
    }

    /// Issue a single-use permit for one normalized, bounded experiment request.
    ///
    /// # Errors
    /// Refuses stopped servers, Active, widened destinations, unbounded budgets or invalid authorization.
    pub fn permit(
        &self,
        fixture: &str,
        crawl: &CreateCrawl,
        record: &AuthorizationRecord,
    ) -> Result<FixtureEvaluationPermit, FixtureEvaluationError> {
        let scope = self.scope();
        validate_request(&scope, crawl, record)?;
        if fixture.is_empty()
            || fixture.len() > 64
            || !fixture
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !crawl.seed_url.path().starts_with(&format!("/{fixture}/"))
        {
            return Err(FixtureEvaluationError::Invalid(
                "request is not the named fixture",
            ));
        }
        Ok(FixtureEvaluationPermit {
            scope,
            fixture: fixture.to_owned(),
            request_digest: crawl.digest()?,
            authorization: record.id,
            authorization_digest: record.body_digest()?,
            tenant: record.tenant,
            stopped: self.identity.live.clone(),
        })
    }
}

impl Drop for FixtureEvaluationHost {
    fn drop(&mut self) {
        self.identity.live.cancel();
    }
}

impl FixtureEvaluationLease for ListenerIdentity {
    fn address(&self) -> SocketAddr {
        self.address
    }
    fn is_live(&self) -> bool {
        !self.live.is_cancelled()
    }
    fn revoke(&self) {
        self.live.cancel();
    }
}

/// Single-use authority for a bounded Off/Shadow/Advisory request against the owned fixture.
/// This is neither a gate status nor a G3 token and cannot be attached to a queued job.
#[derive(Debug)]
pub struct FixtureEvaluationPermit {
    scope: FixtureEvaluationScope,
    fixture: String,
    request_digest: Digest,
    authorization: AuthorizationRecordId,
    authorization_digest: Digest,
    tenant: TenantId,
    stopped: CancellationToken,
}

impl FixtureEvaluationPermit {
    /// Check request/budget integrity before any run is created.
    ///
    /// # Errors
    /// Refuses mutations, stale authorization and stopped fixture servers.
    pub fn check_request(
        &self,
        crawl: &CreateCrawl,
        record: &AuthorizationRecord,
    ) -> Result<(), FixtureEvaluationError> {
        validate_request(&self.scope, crawl, record)?;
        if crawl.digest()? != self.request_digest
            || record.id != self.authorization
            || record.tenant != self.tenant
            || record.body_digest()? != self.authorization_digest
        {
            return Err(FixtureEvaluationError::Invalid(
                "request or authorization binding changed",
            ));
        }
        Ok(())
    }

    pub(crate) fn scope(&self) -> &FixtureEvaluationScope {
        &self.scope
    }

    /// Consume the permit after the worker freshly admitted the authorization record.
    ///
    /// # Errors
    /// Refuses another tenant, request, authorization body, or stopped server.
    pub fn bind(
        self,
        run: &CrawlRun,
        fresh_record: &AuthorizationRecord,
    ) -> Result<BoundFixtureEvaluation, FixtureEvaluationError> {
        self.check_request(&run.config, fresh_record)?;
        if run.tenant != self.tenant || run.config_digest != self.request_digest {
            return Err(FixtureEvaluationError::Invalid("run binding changed"));
        }
        Ok(BoundFixtureEvaluation {
            scope: self.scope,
            fixture: self.fixture,
            run: run.id,
            tenant: self.tenant,
            request_digest: self.request_digest,
            authorization: self.authorization,
            authorization_digest: self.authorization_digest,
            stopped: self.stopped,
        })
    }
}

/// Authority already bound to one real run and freshly read authorization body.
#[derive(Debug)]
pub struct BoundFixtureEvaluation {
    scope: FixtureEvaluationScope,
    fixture: String,
    run: CrawlRunId,
    tenant: TenantId,
    request_digest: Digest,
    authorization: AuthorizationRecordId,
    authorization_digest: Digest,
    stopped: CancellationToken,
}

impl BoundFixtureEvaluation {
    /// Narrowing-only live network scope.
    #[must_use]
    pub fn scope(&self) -> &FixtureEvaluationScope {
        &self.scope
    }
    /// Fixture identity to record with the experimental evidence.
    #[must_use]
    pub fn fixture(&self) -> &str {
        &self.fixture
    }
    pub(crate) fn watch(&self, run_cancel: CancellationToken) -> FixtureEvaluationWatch {
        let stopped = self.stopped.clone();
        FixtureEvaluationWatch(tokio::spawn(async move {
            tokio::select! {
                () = stopped.cancelled() => run_cancel.cancel(),
                () = run_cancel.cancelled() => {}
            }
        }))
    }
    /// Recheck the exact run and freshly admitted authorization before building model clients.
    ///
    /// # Errors
    /// Refuses stopped servers, different runs/tenants or changed authorization and budgets.
    pub fn check_run(
        &self,
        run: &CrawlRun,
        record: &AuthorizationRecord,
    ) -> Result<(), FixtureEvaluationError> {
        validate_request(&self.scope, &run.config, record)?;
        if run.id != self.run
            || run.tenant != self.tenant
            || run.config_digest != self.request_digest
            || run.config.digest()? != self.request_digest
            || record.id != self.authorization
            || record.body_digest()? != self.authorization_digest
            || record.tenant != self.tenant
        {
            return Err(FixtureEvaluationError::Invalid(
                "bound run or authorization changed",
            ));
        }
        Ok(())
    }
}

pub(crate) struct FixtureEvaluationWatch(tokio::task::JoinHandle<()>);
impl Drop for FixtureEvaluationWatch {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn check_worker_config(
    scope: &FixtureEvaluationScope,
    crawl: &CreateCrawl,
    cfg: &crate::WorkerConfig,
) -> Result<(), crate::WorkerError> {
    let invalid = |detail: &str| crate::WorkerError::Config(format!("fixture evaluation refused: {detail}"));
    if !scope.is_live()
        || cfg.cdp_ws_url.is_some()
        || cfg.launch.cdp_ws_url.is_some()
        || !cfg.incognito
        || !cfg.launch.extra_args.is_empty()
        || cfg.launch.user_data_dir.is_some()
        || cfg.launch.profile.is_some()
        || cfg.launch.egress_proxy_port.is_some()
        || cfg.auto_download_chromium
        || cfg.launch.auto_download_chromium
        || cfg.egress.proxy_routes.basic.is_some()
        || cfg.egress.proxy_routes.enhanced.is_some()
        || cfg.egress.proxy_routes.basic_pool.is_some()
        || cfg.egress.proxy_routes.enhanced_pool.is_some()
        || cfg
            .egress
            .fixture_scope
            .as_ref()
            .is_some_and(|other| other != scope)
        || cfg.planner.is_some()
        || cfg.form_ai.is_some()
        || cfg.traffic_export.is_some()
    {
        return Err(invalid("runtime settings widen the controlled experiment"));
    }
    if let Some(crate::EngineConfig::DecisionHttp { base_url, .. }) =
        cfg.model.as_ref().map(|model| &model.engine)
    {
        let endpoint = Url::parse(base_url).map_err(|_| invalid("model endpoint is malformed"))?;
        if endpoint.scheme() != "http"
            || endpoint.host_str() != Some("127.0.0.1")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
        {
            return Err(invalid("model endpoint must be a local controlled service"));
        }
    }
    if crawl.dynamic.strategies.iter().any(|name| {
        crawlx_strategies::registry::gate_for(*name) == Some(crawlx_strategies::registry::Gate::G1)
    }) && (!cfg.gates.passed(crawlx_strategies::registry::Gate::G1) || cfg.gates.dir().is_none())
    {
        return Err(invalid(
            "gated deterministic strategies still require authenticated G1",
        ));
    }
    Ok(())
}

fn validate_request(
    scope: &FixtureEvaluationScope,
    crawl: &CreateCrawl,
    record: &AuthorizationRecord,
) -> Result<(), FixtureEvaluationError> {
    record.check_active(SystemClock.now())?;
    record.check_profile(crawl.safety.profile)?;
    record.scope().check_request(&crawl.seed_url)?;
    if !scope.permits_url(&crawl.seed_url)
        || record.origins.len() != 1
        || record.origins[0] != scope.origin().origin().ascii_serialization()
        || !record.url_prefixes.is_empty()
        || crawl.safety.authorization_record_ref != Some(record.id)
        || !matches!(
            crawl.safety.profile,
            SafetyProfile::ReadOnly | SafetyProfile::TestEnvironment
        )
        || crawl.mode == crawlx_core::config::CrawlMode::Static
        || !crawl.dynamic.enabled
        || crawl.dynamic.system1_mode == System1Mode::Active
        || crawl.dynamic.llm_planner != LlmPlannerMode::Off
        || crawl.dynamic.browser_profile.is_some()
        || crawl.crawl.captcha.is_some()
        || crawl.fetch.proxy.is_some()
        || crawl.scrape.is_some()
        || crawl.extract.validate_secrets
        || !crawl.fetch.extra_headers.is_empty()
        || !crawl.fetch.cookies.is_empty()
        || crawl.scope.allow_external_links
        || crawl.scope.allow_subdomains
        || crawl.roles.iter().any(|role| {
            role.credential_ref.is_some()
                || role
                    .replica_base_url
                    .as_ref()
                    .is_some_and(|url| !scope.permits_url(url))
        })
    {
        return Err(FixtureEvaluationError::Invalid(
            "request widens controlled fixture authority",
        ));
    }
    if crawl.limits.duration_seconds == 0
        || crawl.limits.duration_seconds > 3600
        || crawl.limits.interactions > 10_000
        || crawl.limits.urls > 10_000
        || crawl.limits.states > 10_000
    {
        return Err(FixtureEvaluationError::Invalid(
            "experiment exceeds bounded fixture budgets",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::model::{EngineConfig, ModelConfig, ModelServices};
    use crawlx_core::config::{CrawlMode, StrategyName};
    use crawlx_core::counters::{PlaneCounters, RunStatus};

    fn fixture() -> (FixtureEvaluationHost, CreateCrawl, AuthorizationRecord) {
        let host = FixtureEvaluationHost::bind().unwrap();
        let now = SystemClock.now();
        let origin = host.origin().origin().ascii_serialization();
        let mut record = crawlx_policy::testkit::sample_record(TenantId::new(), now, &[&origin]);
        record.verified_at = Some(now);
        record.authorized_networks = vec!["127.0.0.1/32".parse().unwrap()];
        let mut crawl = CreateCrawl::new(host.origin().join("g01/").unwrap());
        crawl.mode = CrawlMode::Dynamic;
        crawl.dynamic.strategies = vec![StrategyName::InteractionBfs, StrategyName::System1];
        crawl.dynamic.system1_mode = System1Mode::Advisory;
        crawl.safety.authorization_record_ref = Some(record.id);
        crawl.safety.allow_private_networks = true;
        crawl.limits.duration_seconds = 60;
        crawl.limits.interactions = 20;
        crawl.limits.urls = 20;
        crawl.limits.states = 20;
        crawl.normalize().unwrap();
        (host, crawl, record)
    }

    fn run(crawl: CreateCrawl, tenant: TenantId) -> CrawlRun {
        CrawlRun {
            id: CrawlRunId::new(),
            tenant,
            status: RunStatus::Running,
            terminal_reason: None,
            seed: crawl.effective_seed(),
            config_digest: crawl.digest().unwrap(),
            config: crawl,
            policy_version: 1,
            counters: PlaneCounters::default(),
            created_at: SystemClock.now(),
            started_at: None,
            finished_at: None,
            trace_id: None,
        }
    }

    #[test]
    fn permit_binds_real_listener_request_budget_tenant_run_and_fresh_authorization() {
        let (host, crawl, record) = fixture();
        let permit = host.permit("g01", &crawl, &record).unwrap();
        let mut changed = crawl.clone();
        changed.limits.interactions += 1;
        assert!(permit.check_request(&changed, &record).is_err());
        let mut fresh = record.clone();
        fresh.title.push_str(" changed");
        assert!(permit.check_request(&crawl, &fresh).is_err());
        let row = run(crawl.clone(), record.tenant);
        let bound = permit.bind(&row, &record).unwrap();
        assert!(bound.check_run(&row, &record).is_ok());
        let mut other = row.clone();
        other.id = CrawlRunId::new();
        assert!(bound.check_run(&other, &record).is_err());
        other = row.clone();
        other.tenant = TenantId::new();
        assert!(bound.check_run(&other, &record).is_err());
        fresh = record.clone();
        fresh.revoked_at = Some(SystemClock.now());
        assert!(bound.check_run(&row, &fresh).is_err());
    }

    #[test]
    fn active_widened_targets_and_unbounded_experiments_cannot_obtain_permits() {
        let (host, crawl, record) = fixture();
        for mutation in ["active", "target", "external", "budget"] {
            let mut changed = crawl.clone();
            match mutation {
                "active" => changed.dynamic.system1_mode = System1Mode::Active,
                "target" => changed.seed_url = Url::parse("https://example.test/g01/").unwrap(),
                "external" => changed.scope.allow_external_links = true,
                _ => changed.limits.duration_seconds = 3601,
            }
            assert!(host.permit("g01", &changed, &record).is_err(), "{mutation}");
        }
        let mut widened = record.clone();
        widened.origins.push("http://127.0.0.1:80".to_owned());
        assert!(host.permit("g01", &crawl, &widened).is_err());
    }

    #[test]
    fn stopped_permit_retains_socket_so_another_service_cannot_recycle_its_port() {
        let (host, crawl, record) = fixture();
        let address = host.identity.address;
        let permit = host.permit("g01", &crawl, &record).unwrap();
        drop(host);
        assert!(!permit.scope().is_live());
        assert!(permit.check_request(&crawl, &record).is_err());
        assert!(
            TcpListener::bind(address).is_err(),
            "stale capability must retain listener identity"
        );
        drop(permit);
        let replacement = TcpListener::bind(address).unwrap();
        assert_eq!(replacement.local_addr().unwrap(), address);
    }

    #[tokio::test]
    async fn stopped_fixture_cancels_its_bounded_worker_run() {
        let (host, crawl, record) = fixture();
        let bound = host
            .permit("g01", &crawl, &record)
            .unwrap()
            .bind(&run(crawl, record.tenant), &record)
            .unwrap();
        let cancel = CancellationToken::new();
        let _watch = bound.watch(cancel.clone());
        host.scope().revoke();
        tokio::time::timeout(std::time::Duration::from_secs(1), cancel.cancelled())
            .await
            .unwrap();
    }

    #[test]
    fn evaluation_advisory_never_grants_g3_or_active_or_boolean_g1() {
        let (host, crawl, record) = fixture();
        let bound = host
            .permit("g01", &crawl, &record)
            .unwrap()
            .bind(&run(crawl.clone(), record.tenant), &record)
            .unwrap();
        let gates = crawlx_strategies::Gates::none();
        let model = ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Advisory,
        };
        assert!(ModelServices::from_config(Some(&model), None, &gates).is_err());
        let services = ModelServices::from_request_config(
            Some(&model),
            None,
            &gates,
            System1Mode::Advisory,
            Some(&bound),
        )
        .unwrap();
        assert_eq!(
            services.system1_mode(System1Mode::Advisory),
            System1Mode::Advisory
        );
        assert!(!gates.status().g3 && gates.g3_token().is_none());
        let active = ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Active,
        };
        assert!(ModelServices::from_request_config(
            Some(&active),
            None,
            &gates,
            System1Mode::Active,
            Some(&bound),
        )
        .is_err());
        let cfg = crate::WorkerConfig {
            gates: crawlx_strategies::Gates::from_status(crawlx_core::gates::GateStatus {
                g1: true,
                g3: false,
            }),
            ..crate::WorkerConfig::default()
        };
        let mut gated = crawl.clone();
        gated.dynamic.strategies.push(StrategyName::StateNovelty);
        assert!(check_worker_config(bound.scope(), &gated, &cfg).is_err());
        let cfg = crate::WorkerConfig {
            cdp_ws_url: Some(Url::parse("ws://127.0.0.1:9222/devtools/browser").unwrap()),
            ..crate::WorkerConfig::default()
        };
        assert!(check_worker_config(bound.scope(), &crawl, &cfg).is_err());
    }

    #[test]
    fn off_baseline_and_shadow_do_not_inherit_the_advisory_ceiling_gate() {
        let model = ModelConfig {
            engine: EngineConfig::Mock,
            mode: System1Mode::Advisory,
        };
        let gates = crawlx_strategies::Gates::none();
        let baseline =
            ModelServices::from_request_config(Some(&model), None, &gates, System1Mode::Off, None).unwrap();
        assert!(baseline.engine_id().is_none());
        let shadow =
            ModelServices::from_request_config(Some(&model), None, &gates, System1Mode::Shadow, None)
                .unwrap();
        assert_eq!(shadow.system1_mode(System1Mode::Shadow), System1Mode::Shadow);
        assert!(
            ModelServices::from_request_config(Some(&model), None, &gates, System1Mode::Advisory, None)
                .is_err()
        );
    }

    #[tokio::test]
    async fn local_experiment_reads_authoritative_revocation_before_browser_or_model_work() {
        let (host, crawl, record) = fixture();
        let permit = host.permit("g01", &crawl, &record).unwrap();
        let mut revoked = record.clone();
        revoked.revoked_at = Some(SystemClock.now());
        let source = Arc::new(crate::StaticAuthorizationSource::new(revoked));
        let dir = tempfile::tempdir().unwrap();
        let stores = crate::Stores::over_memory(Arc::new(crawlx_storage::MemoryStore::new()), dir.path())
            .await
            .unwrap();
        let cfg = crate::WorkerConfig {
            artifacts_dir: dir.path().to_path_buf(),
            model: Some(ModelConfig {
                engine: EngineConfig::Mock,
                mode: System1Mode::Advisory,
            }),
            ..crate::WorkerConfig::default()
        };
        let report = crate::run_local_with(
            crate::LocalRun::new(crawl, cfg)
                .with_authorization(record)
                .with_authorization_source(source)
                .with_stores(stores)
                .with_fixture_evaluation(permit),
        )
        .await
        .unwrap();
        assert_eq!(
            report.terminal_reason,
            Some(crawlx_core::counters::TerminalReason::AuthorizationRevoked)
        );
        assert!(report.actions.is_empty() && report.pages.is_empty());
        assert_eq!(report.browser_launches, 0);
    }
}
