//! Operator registry admission and qualified diagnostic acquisition. Browser writes remain Session Actor owned.

use crate::{config::EgressConfig, error::WorkerError};
use crawlx_core::{
    acquisition::{AcquisitionResultV1, BackendCapabilitiesV1, RepresentationV1, UrlEvidenceV1},
    hash::Digest,
    protocol::{CompiledProtocolRoutes, ProtocolBackendV1, ProtocolRouteV1},
    secret::SecretResolver,
    CrawlRunId, TenantId,
};
use crawlx_fetch::{
    protocol::{
        service::{DelegateScope, ServiceAdapter, ServiceRegistration},
        ProtocolError, ProtocolResource,
    },
    OriginGovernor, Resolver,
};
use crawlx_policy::EgressPolicy;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Worker-private immutable registry. No downloaded code or tenant-supplied endpoints.
#[derive(Debug, Default)]
pub struct ProtocolRegistry {
    services: BTreeMap<String, Arc<ServiceAdapter>>,
    approved_tenants: BTreeSet<String>,
    whois: Option<crawlx_fetch::protocol::whois::WhoisRegistry>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryFile {
    schema_version: u8,
    approved_tenants: BTreeSet<String>,
    services: BTreeMap<String, ServiceRegistration>,
    #[serde(default)]
    whois: Option<crawlx_fetch::protocol::whois::WhoisRegistry>,
}
impl ProtocolRegistry {
    /// Load bounded operator configuration named by `CRAWLX_PROTOCOL_REGISTRY`.
    /// Operator references reuse the existing env/file chain and never enter Debug or durable config.
    ///
    /// # Errors
    /// Refuses unknown schema, oversized registrations, missing credential references and insecure services.
    pub async fn from_operator_env() -> Result<Option<Arc<Self>>, WorkerError> {
        let Some(path) = std::env::var_os("CRAWLX_PROTOCOL_REGISTRY") else {
            return Ok(None);
        };
        let resolver = crate::secrets::ChainResolver::new()
            .with("env", Arc::new(crate::secrets::EnvSecretResolver))
            .with("file", Arc::new(crate::secrets::FileSecretResolver));
        Self::from_file(std::path::Path::new(&path), &resolver)
            .await
            .map(Some)
    }

    /// Load a bounded operator registry with an existing scoped secret resolver.
    ///
    /// # Errors
    /// Refuses malformed registration, missing scoped credentials and insecure or unavailable service capabilities.
    pub async fn from_file(
        path: &std::path::Path,
        resolver: &dyn SecretResolver,
    ) -> Result<Arc<Self>, WorkerError> {
        let mut bytes = Vec::new();
        tokio::fs::File::open(path)
            .await
            .map_err(|_| WorkerError::Config("protocol registry unavailable".to_owned()))?
            .take(65_537)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| WorkerError::Config("protocol registry unreadable".to_owned()))?;
        if bytes.len() > 65_536 {
            return Err(WorkerError::Config("protocol registry byte cap".to_owned()));
        }
        let file: RegistryFile = serde_json::from_slice(&bytes)
            .map_err(|_| WorkerError::Config("invalid protocol registry schema".to_owned()))?;
        if file.schema_version != 1 || file.services.len() > 16 || file.approved_tenants.len() > 256 {
            return Err(WorkerError::Config(
                "protocol registry version or count".to_owned(),
            ));
        }
        if file.whois.as_ref().is_some_and(|registry| {
            registry.endpoints.len() > 32
                || registry.max_referrals > 8
                || registry.endpoints.iter().any(|(id, endpoint)| {
                    id.is_empty()
                        || id.len() > 253
                        || endpoint.host.is_empty()
                        || endpoint.host.len() > 253
                        || endpoint.port == 0
                })
        }) {
            return Err(WorkerError::Config("WHOIS registry bounds".to_owned()));
        }
        let mut registry = Self {
            services: BTreeMap::new(),
            approved_tenants: file.approved_tenants,
            whois: file.whois,
        };
        for (id, registration) in file.services {
            if id.is_empty() || id.len() > 128 {
                return Err(WorkerError::Config("protocol registry id".to_owned()));
            }
            let credential = resolver
                .resolve(&registration.credential_ref)
                .await
                .map_err(|_| {
                    WorkerError::Config("protocol service scoped credential unavailable".to_owned())
                })?;
            let adapter = ServiceAdapter::new(registration, credential)
                .map_err(|e| WorkerError::Config(e.to_string()))?;
            registry.services.insert(id, Arc::new(adapter));
        }
        Ok(Arc::new(registry))
    }
}

/// Run-bound protocol client. Native HTTP/browser stay in their original coordinators.
#[derive(Clone)]
pub struct ProtocolRuntime {
    registry: Arc<ProtocolRegistry>,
    policy: Arc<EgressPolicy>,
    resolver: Arc<dyn Resolver>,
    governor: Arc<OriginGovernor>,
}
impl std::fmt::Debug for ProtocolRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolRuntime").finish_non_exhaustive()
    }
}
impl ProtocolRuntime {
    /// Bind existing checked policy/resolver and global origin governor to approved service registry.
    ///
    /// # Errors
    /// Fails if configured checked resolver is unavailable.
    pub fn new(
        registry: Arc<ProtocolRegistry>,
        egress: &EgressConfig,
        crawl: &crawlx_core::CreateCrawl,
        record: Option<&crawlx_policy::AuthorizationRecord>,
        governor: Arc<OriginGovernor>,
    ) -> Result<Self, WorkerError> {
        Ok(Self {
            registry,
            policy: Arc::new(egress.policy_for_run(crawl, record)),
            resolver: egress.resolver_for(crawl)?,
            governor,
        })
    }

    /// Refuse all explicit unavailable delegates at run admission, before acquisition sockets.
    ///
    /// # Errors
    /// Fails for unknown registration, missing tenant approval or unavailable required capabilities.
    pub fn admit(
        &self,
        routes: &[ProtocolRouteV1],
        run: CrawlRunId,
        tenant: TenantId,
        target: &Url,
        zdr: bool,
    ) -> Result<(), WorkerError> {
        for route in routes
            .iter()
            .filter(|route| route.backend == ProtocolBackendV1::Delegate)
        {
            if route.delegate_id.as_deref() == Some("native_whois") {
                if self.registry.whois.is_none()
                    || route.schemes != ["whois"]
                    || !route.required_capabilities.is_subset(&BTreeSet::from([
                        "checked_egress".to_owned(),
                        "bounded_referrals".to_owned(),
                    ]))
                {
                    return Err(WorkerError::Config(
                        "protocol capability unavailable: native WHOIS registration".to_owned(),
                    ));
                }
                continue;
            }
            let adapter = self
                .adapter(route)
                .map_err(|e| WorkerError::Config(e.to_string()))?;
            let scope = self.scope(run, tenant, "admission", &route.policy_revision, zdr);
            adapter
                .admit_route(route, &scope)
                .map_err(|e| WorkerError::Config(e.to_string()))?;
            // Scheme-specific admission for the seed only. Every dispatch checks its actual target again.
            if route.schemes.is_empty() || route.schemes.iter().any(|s| s == target.scheme()) {
                adapter
                    .admit(route, target, &scope)
                    .map_err(|e| WorkerError::Config(e.to_string()))?;
            }
        }
        Ok(())
    }
    fn adapter(&self, route: &ProtocolRouteV1) -> Result<&Arc<ServiceAdapter>, ProtocolError> {
        route
            .delegate_id
            .as_ref()
            .and_then(|id| self.registry.services.get(id))
            .ok_or(ProtocolError::CapabilityUnavailable(
                "operator delegate registration",
            ))
    }
    fn scope(
        &self,
        run: CrawlRunId,
        tenant: TenantId,
        attempt: &str,
        policy: &str,
        zdr: bool,
    ) -> DelegateScope {
        DelegateScope {
            tenant: tenant.to_string(),
            run: run.to_string(),
            attempt: attempt.to_owned(),
            policy_digest: policy.to_owned(),
            external_processing_approved: self.registry.approved_tenants.contains(&tenant.to_string()),
            zdr,
        }
    }
    /// Perform actual registered-service acquisition, never direct fallback.
    ///
    /// # Errors
    /// Propagates closed service capability, scope, replay, transport and deadline refusals.
    #[allow(clippy::too_many_arguments)]
    pub async fn acquire(
        &self,
        route: &ProtocolRouteV1,
        url: &Url,
        run: CrawlRunId,
        tenant: TenantId,
        attempt: &str,
        zdr: bool,
        requests: &Arc<std::sync::atomic::AtomicU32>,
        cancel: &CancellationToken,
    ) -> Result<ProtocolResource, ProtocolError> {
        use std::sync::atomic::Ordering;
        let scope = self.scope(run, tenant, attempt, &route.policy_revision, zdr);
        let allowance = requests.load(Ordering::Acquire);
        requests
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .map_err(|_| ProtocolError::Limit)?;
        let resource = if route.delegate_id.as_deref() == Some("native_whois") {
            let mut registry = self
                .registry
                .whois
                .clone()
                .ok_or(ProtocolError::CapabilityUnavailable("native WHOIS registry"))?;
            registry.max_referrals = registry
                .max_referrals
                .min(u8::try_from(allowance.saturating_sub(1)).unwrap_or(u8::MAX));
            registry
                .acquire(
                    url,
                    route.max_body_bytes,
                    std::time::Duration::from_millis(u64::from(route.max_elapsed_ms)),
                    cancel,
                    &self.policy,
                    self.resolver.as_ref(),
                    &self.governor,
                )
                .await?
        } else {
            self.adapter(route)?
                .acquire(
                    route,
                    url,
                    &scope,
                    &[],
                    allowance,
                    &self.policy,
                    self.resolver.as_ref(),
                    &self.governor,
                    cancel,
                )
                .await?
        };
        let extra = resource.network_requests.saturating_sub(1);
        requests
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(extra))
            .map_err(|_| ProtocolError::Limit)?;
        Ok(resource)
    }
}

/// Construct truthful body-free diagnostic metadata using authenticated local ownership.
#[must_use]
pub fn resource_metadata(
    resource: &ProtocolResource,
    route: &ProtocolRouteV1,
    requested: &Url,
    run: CrawlRunId,
    tenant: TenantId,
) -> AcquisitionResultV1 {
    let mut backend = BackendCapabilitiesV1::native_http("approved-isolated-service", "1");
    backend.backend_id = route
        .delegate_id
        .clone()
        .unwrap_or_else(|| "unavailable".to_owned());
    backend.build_digest = Digest::from_hex(&resource.build_digest).ok();
    backend.limitations = vec![
        "diagnostic_only".to_owned(),
        "remote_attested_not_native_wire".to_owned(),
        format!("protocol_route:{}", route.id),
        format!("policy_revision:{}", route.policy_revision),
    ];
    if route.delegate_id.as_deref() == Some("native_whois") {
        backend.implementation = "crawlx-fetch/native-whois".to_owned();
        backend.version = env!("CARGO_PKG_VERSION").to_owned();
        backend.limitations[1] = "native_protocol_resource_without_http_status".to_owned();
    }
    let mut result = AcquisitionResultV1::new(
        run,
        tenant,
        requested.clone(),
        Digest::of("crawlx/canonical-url/v1", requested.as_str().as_bytes()),
        backend,
    );
    result.final_url.clone_from(&resource.final_url);
    result.redirects.clone_from(&resource.redirects);
    result.final_url_evidence = if resource.final_url.is_some() {
        UrlEvidenceV1::Declared
    } else {
        UrlEvidenceV1::Unavailable
    };
    result.target_status = resource.target_status;
    result.gateway_status = resource.gateway_status;
    result.content_type.clone_from(&resource.media_type);
    result.transport_succeeded = true;
    result.representation = RepresentationV1::SuppliedHtml;
    result.decoded_bytes = u64::try_from(resource.decoded_bytes).unwrap_or(u64::MAX);
    result.attempts = 1;
    result.network_requests = resource.network_requests;
    result
}

/// Select using scheduler facts only. Page-produced metadata is deliberately not an input.
#[must_use]
pub fn select_route<'a>(routes: &'a CompiledProtocolRoutes, url: &Url) -> Option<&'a ProtocolRouteV1> {
    static SCHEDULER_FACTS: std::sync::LazyLock<BTreeMap<String, String>> = std::sync::LazyLock::new(|| {
        BTreeMap::from([
            ("request_class".to_owned(), "stateless_get".to_owned()),
            ("source_kind".to_owned(), "url_plane".to_owned()),
            ("media_class".to_owned(), "unclassified".to_owned()),
        ])
    });
    routes.select(url, &SCHEDULER_FACTS)
}
