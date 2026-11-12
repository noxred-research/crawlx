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
    acquisition_service::{AcquisitionServiceAdapter, AcquisitionServiceRegistrationV1},
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
    acquisition_services: BTreeMap<String, Arc<AcquisitionServiceAdapter>>,
    approved_tenants: BTreeSet<String>,
    whois: Option<crawlx_fetch::protocol::whois::WhoisRegistry>,
    ftp: Option<crawlx_fetch::protocol::ftp::FtpRegistry>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistryFile {
    schema_version: u8,
    approved_tenants: BTreeSet<String>,
    services: BTreeMap<String, ServiceRegistration>,
    #[serde(default)]
    acquisition_services: BTreeMap<String, AcquisitionServiceRegistrationV1>,
    #[serde(default)]
    whois: Option<crawlx_fetch::protocol::whois::WhoisRegistry>,
    #[serde(default)]
    ftp: Option<crawlx_fetch::protocol::ftp::FtpRegistry>,
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
        // Nonblocking descriptor admission prevents operator path mistakes from hanging on a FIFO.
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| WorkerError::Config("protocol registry unavailable".to_owned()))?;
        let stat = rustix::fs::fstat(&fd)
            .map_err(|_| WorkerError::Config("protocol registry metadata unavailable".to_owned()))?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || !(0..=65_536).contains(&stat.st_size)
        {
            return Err(WorkerError::Config(
                "protocol registry requires a bounded regular file".to_owned(),
            ));
        }
        tokio::fs::File::from_std(std::fs::File::from(fd))
            .take(65_537)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| WorkerError::Config("protocol registry unreadable".to_owned()))?;
        if bytes.len() > 65_536 {
            return Err(WorkerError::Config("protocol registry byte cap".to_owned()));
        }
        let mut file: RegistryFile = serde_json::from_slice(&bytes)
            .map_err(|_| WorkerError::Config("invalid protocol registry schema".to_owned()))?;
        if file.schema_version != 1
            || file.services.len() > 16
            || file.acquisition_services.len() > 16
            || file.approved_tenants.len() > 256
        {
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
        if let Some(ftp) = &mut file.ftp {
            ftp.validate()
                .map_err(|error| WorkerError::Config(error.to_string()))?;
            // Secrets resolve once, by reference, and stay inside the registry.
            ftp.resolve_credentials(resolver)
                .await
                .map_err(|error| WorkerError::Config(error.to_string()))?;
        }
        if file.services.contains_key("native_ftp")
            || file.services.contains_key("native_whois")
            || file.acquisition_services.contains_key("native_ftp")
            || file.acquisition_services.contains_key("native_whois")
            || file
                .acquisition_services
                .keys()
                .any(|id| file.services.contains_key(id))
        {
            return Err(WorkerError::Config("reserved protocol registry id".to_owned()));
        }
        let mut registry = Self {
            services: BTreeMap::new(),
            acquisition_services: BTreeMap::new(),
            approved_tenants: file.approved_tenants,
            whois: file.whois,
            ftp: file.ftp,
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
        for (id, registration) in file.acquisition_services {
            if id.is_empty() || id.len() > 128 {
                return Err(WorkerError::Config("protocol registry id".to_owned()));
            }
            let credential = resolver
                .resolve(&registration.credential_ref)
                .await
                .map_err(|_| {
                    WorkerError::Config("acquisition service scoped credential unavailable".to_owned())
                })?;
            let adapter = AcquisitionServiceAdapter::new(registration, credential)
                .map_err(|e| WorkerError::Config(e.to_string()))?;
            registry.acquisition_services.insert(id, Arc::new(adapter));
        }
        Ok(Arc::new(registry))
    }
}

impl ProtocolRegistry {
    /// Aggregate backend capability published by workers for every registered acquisition service.
    ///
    /// One `acquisition_service` backend id exists, so its build digest commits to every sorted
    /// `(registry id, build digest, guard digest)`; the per-run selector still names one exact id.
    /// `None` when no service is registered.
    ///
    /// # Errors
    /// Fails if the digest input cannot be encoded.
    pub(crate) fn acquisition_capability(&self) -> Result<Option<BackendCapabilitiesV1>, WorkerError> {
        if self.acquisition_services.is_empty() {
            return Ok(None);
        }
        let registered: Vec<(&str, Digest, Digest)> = self
            .acquisition_services
            .iter()
            .map(|(id, adapter)| {
                let registration = adapter.registration();
                (id.as_str(), registration.build_digest, registration.guard_digest)
            })
            .collect();
        let digest = Digest::of_value("crawlx/acquisition-service-registry/v1", &registered)
            .map_err(|e| WorkerError::Config(e.to_string()))?;
        let mut capability = BackendCapabilitiesV1::native_http("crawlx-fetch", env!("CARGO_PKG_VERSION"));
        capability.backend_id = "acquisition_service".to_owned();
        capability.build_digest = Some(digest);
        capability.limitations = vec![
            "service_declared_target_evidence".to_owned(),
            "certificate_evidence_unavailable".to_owned(),
        ];
        Ok(Some(capability))
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
            policy: Arc::new(egress.policy_for_run(crawl, record)?),
            resolver: egress.resolver_for(crawl)?,
            governor,
        })
    }

    /// Refuse an unknown selector, unapproved tenant or non-ZDR service before any socket.
    ///
    /// # Errors
    /// Fails for an unregistered id, a tenant without external-processing approval, or a
    /// zero-retention run on a service that does not declare `zdr_compatible`.
    pub fn admit_acquisition_service(
        &self,
        id: &str,
        tenant: TenantId,
        zdr: bool,
    ) -> Result<(), WorkerError> {
        let adapter =
            self.registry.acquisition_services.get(id).ok_or_else(|| {
                WorkerError::Config("acquisition service registration unavailable".to_owned())
            })?;
        if !self.external_processing_approved(tenant)
            || (zdr && !adapter.registration().capabilities.contains("zdr_compatible"))
        {
            return Err(WorkerError::Config(
                "acquisition service scope refused".to_owned(),
            ));
        }
        Ok(())
    }

    /// Registered adapter with this runtime's already checked egress, resolver and governor.
    pub(crate) fn acquisition_service(
        &self,
        id: &str,
    ) -> Option<(
        &Arc<AcquisitionServiceAdapter>,
        &EgressPolicy,
        &dyn Resolver,
        &OriginGovernor,
    )> {
        self.registry.acquisition_services.get(id).map(|adapter| {
            (
                adapter,
                self.policy.as_ref(),
                self.resolver.as_ref(),
                self.governor.as_ref(),
            )
        })
    }

    /// Whether the operator approved this tenant for external content processing.
    pub(crate) fn external_processing_approved(&self, tenant: TenantId) -> bool {
        self.registry.approved_tenants.contains(&tenant.to_string())
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
            if route.delegate_id.as_deref() == Some("native_ftp") {
                let registry = self.registry.ftp.as_ref().ok_or_else(|| {
                    WorkerError::Config("protocol capability unavailable: native FTP registration".to_owned())
                })?;
                let declares = |id: &str| route.required_capabilities.contains(id);
                if route.schemes != ["ftp"]
                    || !route.required_capabilities.iter().all(|id| {
                        matches!(
                            id.as_str(),
                            "checked_egress"
                                | "bounded_body"
                                | "cancellation"
                                | "ftp_passive_pinned"
                                | "ftp_anonymous_file"
                                | "ftp_credential_login"
                                | "ftp_bounded_recursion"
                        )
                    })
                    // A declared capability must actually be configured, never assumed.
                    || (declares("ftp_credential_login") && !registry.has_credentials())
                    || (declares("ftp_bounded_recursion") && registry.recursion.is_none())
                    || !self.registry.approved_tenants.contains(&tenant.to_string())
                    || !registry.policy_digests.contains(&route.policy_revision)
                {
                    return Err(WorkerError::Config(
                        "protocol capability unavailable: native FTP scope".to_owned(),
                    ));
                }
                if target.scheme() == "ftp" {
                    registry
                        .admit(target, &route.policy_revision)
                        .map_err(|error| WorkerError::Config(error.to_string()))?;
                    // Logging in or walking a directory is an explicit per-route decision; an
                    // anonymous-file route never silently becomes an authenticated one.
                    let credentialed = registry.uses_credentials(target);
                    if (credentialed && !declares("ftp_credential_login"))
                        || (!credentialed && declares("ftp_credential_login"))
                        || (credentialed && declares("ftp_anonymous_file"))
                        || (crawlx_fetch::protocol::ftp::FtpRegistry::is_directory(target)
                            && !declares("ftp_bounded_recursion"))
                    {
                        return Err(WorkerError::Config(
                            "protocol capability unavailable: native FTP scope".to_owned(),
                        ));
                    }
                }
                continue;
            }
            if route.delegate_id.as_deref() == Some("native_whois") {
                if self.registry.whois.is_none()
                    || route.schemes != ["whois"]
                    || !route.required_capabilities.is_subset(&BTreeSet::from([
                        "checked_egress".to_owned(),
                        "bounded_referrals".to_owned(),
                    ]))
                    || !self.registry.approved_tenants.contains(&tenant.to_string())
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
        self.admit(std::slice::from_ref(route), run, tenant, url, zdr)
            .map_err(|_| ProtocolError::CapabilityUnavailable("protocol route scope"))?;
        let allowance = requests.load(Ordering::Acquire);
        requests
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1))
            .map_err(|_| ProtocolError::Limit)?;
        let resource = if route.delegate_id.as_deref() == Some("native_ftp") {
            use crawlx_fetch::protocol::ftp::{FtpNetwork, FtpRequest};
            self.registry
                .ftp
                .as_ref()
                .ok_or(ProtocolError::CapabilityUnavailable("native FTP registry"))?
                .acquire(
                    // The shared request allowance also bounds directory listings.
                    &FtpRequest::new(
                        url,
                        &route.policy_revision,
                        route.max_body_bytes,
                        std::time::Duration::from_millis(u64::from(route.max_elapsed_ms)),
                    )
                    .with_max_requests(allowance),
                    &FtpNetwork::new(&self.policy, self.resolver.as_ref(), &self.governor),
                    cancel,
                )
                .await?
        } else if route.delegate_id.as_deref() == Some("native_whois") {
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
    if route.delegate_id.as_deref() == Some("native_ftp") {
        backend.implementation = "crawlx-fetch/native-ftp".to_owned();
        backend.version = env!("CARGO_PKG_VERSION").to_owned();
        backend.limitations[1] = if resource.build_digest == "native-ftp-credential-v1" {
            "native_credentialed_ftp_without_http_status"
        } else {
            "native_anonymous_ftp_file_without_http_status"
        }
        .to_owned();
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

/// Report validated local registrations without DNS, target fetches or service health claims.
#[must_use]
pub fn capability_report(
    registry: Option<&ProtocolRegistry>,
) -> crawlx_core::protocol::ProtocolCapabilityReportV1 {
    use crawlx_core::protocol::{ProtocolCapabilityEntryV1, ProtocolCapabilityReportV1};
    let mut delegates = Vec::new();
    if let Some(registry) = registry {
        for (id, adapter) in &registry.services {
            let cap = adapter.capabilities();
            delegates.push(ProtocolCapabilityEntryV1::configured(
                id.clone(),
                cap.schemes.clone(),
                cap.capabilities.clone(),
                cap.max_bytes,
                Some(cap.build_digest.clone()),
            ));
        }
        for (id, adapter) in &registry.acquisition_services {
            let registration = adapter.registration();
            delegates.push(ProtocolCapabilityEntryV1::configured(
                id.clone(),
                BTreeSet::from(["https".to_owned()]),
                registration.capabilities.clone(),
                67_108_864,
                Some(registration.build_digest.to_hex()),
            ));
        }
        let mut ftp_capabilities = vec![
            "bounded_body",
            "cancellation",
            "checked_egress",
            "ftp_anonymous_file",
            "ftp_passive_pinned",
        ];
        if let Some(ftp) = &registry.ftp {
            if ftp.has_credentials() {
                ftp_capabilities.push("ftp_credential_login");
            }
            if ftp.recursion.is_some() {
                ftp_capabilities.push("ftp_bounded_recursion");
            }
        }
        for (id, scheme, enabled, capabilities) in [
            ("native_ftp", "ftp", registry.ftp.is_some(), &ftp_capabilities[..]),
            (
                "native_whois",
                "whois",
                registry.whois.is_some(),
                &["bounded_referrals", "checked_egress"][..],
            ),
        ] {
            if enabled {
                delegates.push(ProtocolCapabilityEntryV1::configured(
                    id.to_owned(),
                    BTreeSet::from([scheme.to_owned()]),
                    capabilities.iter().map(|id| (*id).to_owned()).collect(),
                    67_108_864,
                    None,
                ));
            }
        }
    }
    delegates.sort_by(|a, b| a.id.cmp(&b.id));
    ProtocolCapabilityReportV1::configured(registry.is_some(), delegates)
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "protocol_acquisition_tests.rs"]
mod acquisition_tests;

#[cfg(test)]
#[path = "protocol_ftp_tests.rs"]
mod ftp_tests;
