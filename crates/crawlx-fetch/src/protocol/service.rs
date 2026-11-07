//! HTTPS scoped-credential acquisition contract. Operator conformance approval is mandatory.
//! No raw CDP endpoint or provider advertisement can establish checked egress capability.

use super::{ProtocolError, ProtocolResource};
use crate::{
    governor::{Origin, OriginGovernor},
    resolver::Resolver,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use crawlx_core::{
    protocol::{DelegateCapabilitiesV1, ProtocolRouteV1},
    secret::{CredentialRef, SecretOr},
};
use crawlx_policy::egress::EgressPolicy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Strict operator registration, never deserialized from tenant configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceRegistration {
    /// Fixed HTTPS resource URL. Redirects and environment proxies are disabled.
    pub endpoint: Url,
    /// Fixed service audience.
    pub audience: String,
    /// Operator approval digest from local conformance review, not remote self-advertisement.
    pub approval_digest: String,
    /// Scoped service credential reference; only the operator loader resolves it.
    pub credential_ref: CredentialRef,
    /// Approved capability contract.
    pub capabilities: DelegateCapabilitiesV1,
    /// Expected SSH host key by exact SFTP host. Service must verify before authentication.
    pub sftp_host_keys: BTreeMap<String, String>,
    /// Exact allowed registry authorities for WHOIS referrals.
    pub whois_registries: BTreeSet<String>,
    /// Optional operator CA PEM; certificate and hostname checks always remain enabled.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Explicit operator control-plane network approval, independent of target-network permission.
    #[serde(default)]
    pub service_networks: Vec<ipnet::IpNet>,
    /// Approved policy references enforced on every service request path and socket.
    pub policy_digests: BTreeSet<String>,
    /// Approved exact-origin credential references resolved only inside the isolated service.
    #[serde(default)]
    pub target_credential_refs: BTreeMap<String, Vec<CredentialRef>>,
    /// Approved network broker policy sharing deployment-wide origin admission for delegated effects.
    pub origin_admission_ref: String,
}

/// Trusted caller scope. Ownership never comes from response JSON.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegateScope {
    /// Authenticated tenant identity.
    pub tenant: String,
    /// Current run identity.
    pub run: String,
    /// Stable attempt identity; one invocation only.
    pub attempt: String,
    /// Immutable approved policy digest.
    pub policy_digest: String,
    /// External processing explicitly approved for this tenant/run.
    pub external_processing_approved: bool,
    /// Zero data retention required.
    pub zdr: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Request<'a> {
    schema_version: u8,
    audience: &'a str,
    nonce: &'a str,
    idempotency_key: &'a str,
    ticket: String,
    scope: &'a DelegateScope,
    target: &'a Url,
    target_addresses: &'a [IpAddr],
    origin: String,
    deadline_unix_ms: u64,
    max_bytes: u32,
    max_network_requests: u32,
    follow_redirects: bool,
    max_redirects: u8,
    required_capabilities: &'a BTreeSet<String>,
    credential_refs: &'a [CredentialRef],
    sftp_host_key: Option<&'a str>,
    whois_registries: &'a BTreeSet<String>,
    max_referrals: u8,
    max_children: u16,
    origin_admission_ref: &'a str,
    allow_browser_writes: bool,
    // Lease expiry is mandatory; dropping the local request never claims remote cancellation acknowledgement.
    cancel_on_disconnect: bool,
}

/// Server response contract. No artifact handles or provider ownership are accepted.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceResponseV1 {
    /// Only contract one is accepted.
    pub schema_version: u8,
    /// Must equal fixed operator audience.
    pub audience: String,
    /// Must equal this exact one-use request nonce.
    pub nonce: String,
    /// Must equal this request's idempotency key.
    pub idempotency_key: String,
    /// Must equal authenticated tenant.
    pub tenant: String,
    /// Must equal authenticated run.
    pub run: String,
    /// Must equal authenticated attempt.
    pub attempt: String,
    /// Must equal approved immutable build.
    pub build_digest: String,
    /// Actual final target URL, or absent with unavailable evidence.
    pub final_url: Option<Url>,
    /// Actual target status, not the HTTP gateway response.
    pub target_status: Option<u16>,
    /// Representation MIME type.
    pub media_type: Option<String>,
    /// Bounded base64 representation; no remote storage credentials or artifact references.
    pub body_base64: String,
    /// Every observed socket host and peer, including redirect/subresource/control/data sockets.
    pub peers: Vec<PeerEvidence>,
    /// Actual verified SSH key; never guessed from registration.
    pub sftp_host_key: Option<String>,
    /// Completion was within the enforceable lease.
    pub lease_completed: bool,
    /// The complete selected representation was received; prefixes never satisfy acquisition success.
    pub body_complete: bool,
    /// Actual target requests, including redirects and subresources.
    pub network_requests: u32,
    /// Approved policy applied to remove service-resolved credentials and transient secret-registry values.
    pub redaction_policy_digest: String,
    /// Ordered authenticated redirects, absent only when the service observed none.
    #[serde(default)]
    pub redirects: Vec<crawlx_core::acquisition::AcquisitionRedirectV1>,
}
impl std::fmt::Debug for ServiceResponseV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceResponseV1")
            .field("schema_version", &self.schema_version)
            .field("target_status", &self.target_status)
            .field("network_requests", &self.network_requests)
            .finish_non_exhaustive()
    }
}
/// Checked-network attestation from the approved isolated service.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PeerEvidence {
    /// Exact host queried on this socket.
    pub host: String,
    /// Checked address connected by service.
    pub ip: IpAddr,
    /// Actual socket port.
    pub port: u16,
    /// True for passive FTP data socket; active FTP is unsupported.
    pub ftp_data: bool,
}

/// Registered authenticated service. Debug never reveals credential values.
pub struct ServiceAdapter {
    registration: ServiceRegistration,
    credential: SecretOr<String>,
    sequence: AtomicU64,
    consumed_attempts: Mutex<BTreeMap<String, tokio::time::Instant>>,
    slots: tokio::sync::Semaphore,
}
impl std::fmt::Debug for ServiceAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceAdapter")
            .field("build_digest", &self.registration.capabilities.build_digest)
            .finish_non_exhaustive()
    }
}
impl ServiceAdapter {
    /// Construct after operator registration and credential resolution.
    ///
    /// # Errors
    /// Refuses insecure endpoints, absent scoped authentication and unapproved or incomplete network enforcement.
    pub fn new(
        registration: ServiceRegistration,
        credential: SecretOr<String>,
    ) -> Result<Self, ProtocolError> {
        let cap = &registration.capabilities;
        if registration.endpoint.scheme() != "https"
            || registration.endpoint.host_str().is_none()
            || !registration.endpoint.username().is_empty()
            || registration.endpoint.password().is_some()
            || registration.endpoint.query().is_some()
            || registration.endpoint.fragment().is_some()
            || registration.audience.is_empty()
            || registration.audience.len() > 128
            || registration.approval_digest.len() != 64
            || !registration
                .approval_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || credential.expose().is_empty()
            || credential.expose().len() > 8192
            || cap.schema_version != 1
            || !cap.checked_egress
            || !cap.deadline_enforced
            || !cap.identity_isolation
            || !cap.body_streaming
            || !cap.subresource_enforcement
            || !cap.cancellation
            || !cap.capabilities.contains("shared_origin_admission")
            || !cap.capabilities.contains("read_only_effects")
            || !cap.capabilities.contains("secret_free_response")
            || registration.origin_admission_ref.is_empty()
            || registration.origin_admission_ref.len() > 128
            || cap.schemes.len() > 6
            || cap.capabilities.len() > 32
            || cap.capabilities.iter().any(|id| id.is_empty() || id.len() > 128)
            || cap
                .browser_build
                .as_ref()
                .is_some_and(|build| build.is_empty() || build.len() > 128)
            || registration.target_credential_refs.len() > 64
            || registration.target_credential_refs.iter().any(|(origin, refs)| {
                origin.len() > 512
                    || Url::parse(origin)
                        .ok()
                        .and_then(|url| crawlx_core::protocol::protocol_origin(&url))
                        .as_ref()
                        != Some(origin)
                    || refs.len() > 8
                    || refs.iter().any(|r| r.0.len() > 256 || r.scheme().is_none())
            })
            || registration.service_networks.len() > 32
            || registration.sftp_host_keys.len() > 64
            || registration.whois_registries.len() > 32
            || registration.policy_digests.is_empty()
            || registration.policy_digests.len() > 64
            || registration
                .policy_digests
                .iter()
                .any(|s| s.is_empty() || s.len() > 128)
            || cap.max_bytes == 0
            || cap.max_bytes > 67_108_864
            || cap.build_digest.len() != 64
            || !cap.build_digest.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(ProtocolError::CapabilityUnavailable(
                "approved authenticated checked-egress service",
            ));
        }
        Ok(Self {
            registration,
            credential,
            sequence: AtomicU64::new(0),
            consumed_attempts: Mutex::new(BTreeMap::new()),
            slots: tokio::sync::Semaphore::new(2),
        })
    }

    /// Check route-wide capabilities before any scheduler-owned target work.
    ///
    /// # Errors
    /// Refuses unsupported schemes, missing policy approval, absent required capabilities and incompatible retention.
    pub fn admit_route(&self, route: &ProtocolRouteV1, scope: &DelegateScope) -> Result<(), ProtocolError> {
        let cap = &self.registration.capabilities;
        if route.schemes.is_empty()
            || route.schemes.iter().any(|scheme| !cap.schemes.contains(scheme))
            || !route.required_capabilities.is_subset(&cap.capabilities)
            || route.max_body_bytes > cap.max_bytes
            || !scope.external_processing_approved
            || (scope.zdr && !cap.zero_retention)
            || !self.registration.policy_digests.contains(&scope.policy_digest)
        {
            return Err(ProtocolError::CapabilityUnavailable(
                "route capability or approved policy",
            ));
        }
        Ok(())
    }

    /// Refuse unsupported capability before resolving or opening any socket.
    ///
    /// # Errors
    /// Refuses missing target scheme, enforcement capability, SSH key pin, provider approval or retention behavior.
    pub fn admit(
        &self,
        route: &ProtocolRouteV1,
        target: &Url,
        scope: &DelegateScope,
    ) -> Result<(), ProtocolError> {
        self.admit_route(route, scope)?;
        let cap = &self.registration.capabilities;
        if !scope.external_processing_approved
            || (scope.zdr && !cap.zero_retention)
            || !self.registration.policy_digests.contains(&scope.policy_digest)
            || !cap.schemes.contains(target.scheme())
            || !route.required_capabilities.is_subset(&cap.capabilities)
            || route.max_body_bytes == 0
            || route.max_body_bytes > cap.max_bytes
            || route.max_elapsed_ms == 0
            || route.max_elapsed_ms > 90_000
            || target.username() != ""
            || target.password().is_some()
            || target.fragment().is_some()
            || scope.tenant.is_empty()
            || scope.run.is_empty()
            || scope.attempt.is_empty()
            || scope.policy_digest.is_empty()
            || [&scope.tenant, &scope.run, &scope.attempt, &scope.policy_digest]
                .iter()
                .any(|s| s.len() > 128)
        {
            return Err(ProtocolError::CapabilityUnavailable(
                "request scope or required capability",
            ));
        }
        if matches!(target.scheme(), "ftp" | "sftp" | "whois")
            && percent_encoding::percent_decode_str(target.path()).any(|byte| byte.is_ascii_control())
        {
            return Err(ProtocolError::Refused("protocol command control characters"));
        }
        let target_origin =
            crawlx_core::protocol::protocol_origin(target).ok_or(ProtocolError::Refused("target origin"))?;
        match target.scheme() {
            "ftp" if !cap.capabilities.contains("ftp_passive_pinned") => {
                return Err(ProtocolError::CapabilityUnavailable("checked passive FTP"))
            }
            "sftp"
                if !cap.capabilities.contains("sftp_key_pinned")
                    || !self
                        .registration
                        .sftp_host_keys
                        .contains_key(target.host_str().unwrap_or(""))
                    || self
                        .registration
                        .target_credential_refs
                        .get(&target_origin)
                        .is_none_or(Vec::is_empty) =>
            {
                return Err(ProtocolError::CapabilityUnavailable(
                    "pinned SFTP key and credential reference",
                ))
            }
            "whois"
                if !self
                    .registration
                    .whois_registries
                    .contains(target.host_str().unwrap_or("")) =>
            {
                return Err(ProtocolError::CapabilityUnavailable("approved WHOIS registry"))
            }
            "http" | "https" | "ftp" | "sftp" | "whois" => {}
            _ => return Err(ProtocolError::CapabilityUnavailable("service scheme")),
        }
        Ok(())
    }

    /// Invoke once with fixed audience, scoped ticket, pinned service DNS and enforced lease expiry.
    ///
    /// # Errors
    /// Refuses replay, wrong scope/schema/audience, unknown peers, wrong keys and response/elapsed bounds. Never falls back.
    #[allow(clippy::too_many_arguments)]
    pub async fn acquire(
        &self,
        route: &ProtocolRouteV1,
        target: &Url,
        scope: &DelegateScope,
        credential_refs: &[CredentialRef],
        max_network_requests: u32,
        policy: &EgressPolicy,
        resolver: &dyn Resolver,
        governor: &Arc<OriginGovernor>,
        cancel: &CancellationToken,
    ) -> Result<ProtocolResource, ProtocolError> {
        self.admit(route, target, scope)?;
        if max_network_requests == 0 || max_network_requests > 512 {
            return Err(ProtocolError::Limit);
        }
        if credential_refs.len() > 8
            || credential_refs
                .iter()
                .any(|r| r.0.len() > 256 || r.scheme().is_none())
        {
            return Err(ProtocolError::Refused("credential reference bounds"));
        }
        let target_origin =
            crawlx_core::protocol::protocol_origin(target).ok_or(ProtocolError::Refused("target origin"))?;
        let approved_refs = self
            .registration
            .target_credential_refs
            .get(&target_origin)
            .map_or(&[][..], Vec::as_slice);
        if credential_refs
            .iter()
            .any(|reference| !approved_refs.contains(reference))
        {
            return Err(ProtocolError::Refused(
                "credential reference outside approved target scope",
            ));
        }
        let credential_refs = if credential_refs.is_empty() {
            approved_refs
        } else {
            credential_refs
        };
        let attempt_key = format!("{}:{}:{}", scope.tenant, scope.run, scope.attempt);
        {
            let mut consumed = self.consumed_attempts.lock();
            let now = tokio::time::Instant::now();
            consumed.retain(|_, expiry| *expiry > now);
            if consumed.len() >= 4096 || consumed.contains_key(&attempt_key) {
                return Err(ProtocolError::Refused("attempt replay or nonce window full"));
            }
            consumed.insert(
                attempt_key.clone(),
                now + Duration::from_millis(u64::from(route.max_elapsed_ms)) + Duration::from_secs(5),
            );
        }
        let sequence = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| ProtocolError::Limit)?;
        let nonce = blake3::keyed_hash(
            blake3::hash(self.credential.expose().as_bytes()).as_bytes(),
            format!(
                "{attempt_key}:{sequence}:{}:{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| ProtocolError::Refused("clock"))?
                    .as_nanos()
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string();
        let idempotency = blake3::hash(attempt_key.as_bytes()).to_hex().to_string();
        let run = async {
            let _slot = self
                .slots
                .acquire()
                .await
                .map_err(|_| ProtocolError::CapabilityUnavailable("service pool closed"))?;
            if matches!(target.scheme(), "http" | "https") {
                policy
                    .check_url(target)
                    .map_err(|_| ProtocolError::Refused("target URL policy"))?;
            } else if let Some(scope) = &policy.record_scope {
                scope
                    .check_request(target)
                    .map_err(|_| ProtocolError::Refused("target URL authorization"))?;
            }
            let host = target.host_str().ok_or(ProtocolError::Refused("target host"))?;
            policy
                .check_host(host)
                .map_err(|_| ProtocolError::Refused("target host policy"))?;
            let port = target
                .port_or_known_default()
                .or_else(|| match target.scheme() {
                    "sftp" => Some(22),
                    "whois" => Some(43),
                    _ => None,
                })
                .ok_or(ProtocolError::Refused("target port"))?;
            policy
                .check_port(port)
                .map_err(|_| ProtocolError::Refused("target port policy"))?;
            let target_addresses = resolver.resolve(host).await?;
            if target_addresses.is_empty() {
                return Err(ProtocolError::Refused("empty target DNS"));
            }
            policy
                .check_all(host, &target_addresses)
                .map_err(|_| ProtocolError::Refused("target DNS policy"))?;
            let endpoint = &self.registration.endpoint;
            // Operator control-plane authority is separate from tenant target authorization.
            let mut service_policy =
                EgressPolicy::new(!self.registration.service_networks.is_empty()).with_seed_port(endpoint);
            service_policy
                .extra_allow
                .clone_from(&self.registration.service_networks);
            service_policy
                .check_url(endpoint)
                .map_err(|_| ProtocolError::Refused("service URL policy"))?;
            let service_host = endpoint
                .host_str()
                .ok_or(ProtocolError::Refused("service host"))?;
            let service_ips = resolver.resolve(service_host).await?;
            if service_ips.is_empty() {
                return Err(ProtocolError::Refused("empty service DNS"));
            }
            service_policy
                .check_all(service_host, &service_ips)
                .map_err(|_| ProtocolError::Refused("service DNS policy"))?;
            let service_port = endpoint
                .port_or_known_default()
                .ok_or(ProtocolError::Refused("service port"))?;
            let sockets: Vec<SocketAddr> = service_ips
                .iter()
                .map(|ip| SocketAddr::new(*ip, service_port))
                .collect();
            let mut builder = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .connect_timeout(Duration::from_secs(30))
                .timeout(Duration::from_millis(u64::from(route.max_elapsed_ms)))
                .resolve_to_addrs(service_host, &sockets);
            if let Some(pem) = &self.registration.ca_pem {
                if pem.len() > 16384 {
                    return Err(ProtocolError::Limit);
                }
                builder = builder.add_root_certificate(
                    reqwest::Certificate::from_pem(pem.as_bytes()).map_err(ProtocolError::Service)?,
                );
            }
            let client = builder.build().map_err(ProtocolError::Service)?;
            let now = u64::try_from(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| ProtocolError::Refused("clock"))?
                    .as_millis(),
            )
            .map_err(|_| ProtocolError::Limit)?;
            let deadline_unix_ms = now
                .checked_add(u64::from(route.max_elapsed_ms))
                .ok_or(ProtocolError::Limit)?;
            let mut request = Request {
                schema_version: 1,
                audience: &self.registration.audience,
                nonce: &nonce,
                idempotency_key: &idempotency,
                ticket: String::new(),
                scope,
                target,
                target_addresses: &target_addresses,
                origin: target_origin,
                deadline_unix_ms,
                max_bytes: route.max_body_bytes,
                max_network_requests,
                follow_redirects: self.registration.capabilities.redirects,
                max_redirects: 20,
                required_capabilities: &route.required_capabilities,
                credential_refs,
                sftp_host_key: self.registration.sftp_host_keys.get(host).map(String::as_str),
                origin_admission_ref: &self.registration.origin_admission_ref,
                allow_browser_writes: false,
                whois_registries: &self.registration.whois_registries,
                max_referrals: 8,
                max_children: 256,
                cancel_on_disconnect: true,
            };
            let mut ticket_payload = serde_json::to_value(&request).map_err(ProtocolError::Schema)?;
            ticket_payload.sort_all_objects();
            let signed = serde_json::to_vec(&ticket_payload).map_err(ProtocolError::Schema)?;
            request.ticket = blake3::keyed_hash(
                blake3::hash(self.credential.expose().as_bytes()).as_bytes(),
                &signed,
            )
            .to_hex()
            .to_string();
            let _permit = governor
                .acquire(&Origin::new(&request.origin))
                .await
                .map_err(|_| ProtocolError::Refused("origin admission unavailable"))?;
            let mut response = client
                .post(endpoint.clone())
                .bearer_auth(self.credential.expose())
                .json(&request)
                .send()
                .await
                .map_err(ProtocolError::Service)?;
            let peer = response
                .remote_addr()
                .ok_or(ProtocolError::Refused("missing service peer"))?;
            if !sockets.contains(&peer) {
                return Err(ProtocolError::Refused("service peer not pinned"));
            }
            let gateway = response.status().as_u16();
            if gateway != 200 {
                return Err(ProtocolError::Refused("service gateway failure"));
            }
            let wire_cap = usize::try_from(route.max_body_bytes)
                .map_err(|_| ProtocolError::Limit)?
                .saturating_mul(2)
                .saturating_add(65536);
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(ProtocolError::Service)? {
                if bytes.len().saturating_add(chunk.len()) > wire_cap {
                    return Err(ProtocolError::Limit);
                }
                bytes.extend_from_slice(&chunk);
            }
            let result: ServiceResponseV1 = serde_json::from_slice(&bytes).map_err(ProtocolError::Schema)?;
            self.validate_response(
                &result,
                scope,
                &nonce,
                &idempotency,
                target,
                &target_addresses,
                policy,
                resolver,
            )
            .await?;
            if result.network_requests == 0 || result.network_requests > max_network_requests {
                return Err(ProtocolError::Refused("service request allowance"));
            }
            let body = STANDARD
                .decode(&result.body_base64)
                .map_err(|_| ProtocolError::Refused("service body encoding"))?;
            if body.len() > usize::try_from(route.max_body_bytes).map_err(|_| ProtocolError::Limit)? {
                return Err(ProtocolError::Limit);
            }
            let decoded_bytes = body.len();
            let body = match crawlx_telemetry::Redactor::new()
                .scrub_bytes(&body, std::iter::once(self.credential.expose().as_str()))
            {
                std::borrow::Cow::Borrowed(_) => body,
                std::borrow::Cow::Owned(clean) => clean,
            };
            Ok(ProtocolResource {
                final_url: result.final_url,
                target_status: result.target_status,
                gateway_status: Some(gateway),
                media_type: result.media_type,
                body: Bytes::from(body),
                children: Vec::new(),
                build_digest: result.build_digest,
                network_requests: result.network_requests,
                decoded_bytes,
                redirects: result.redirects,
                denied_children: Vec::new(),
            })
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtocolError::Cancelled),
            result = tokio::time::timeout(Duration::from_millis(u64::from(route.max_elapsed_ms)), run) => result.map_err(|_| ProtocolError::Deadline)?,
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn validate_response(
        &self,
        result: &ServiceResponseV1,
        scope: &DelegateScope,
        nonce: &str,
        idempotency: &str,
        target: &Url,
        target_addresses: &[IpAddr],
        policy: &EgressPolicy,
        resolver: &dyn Resolver,
    ) -> Result<(), ProtocolError> {
        if result.schema_version != 1
            || result.audience != self.registration.audience
            || result.nonce != nonce
            || result.idempotency_key != idempotency
            || result.tenant != scope.tenant
            || result.run != scope.run
            || result.attempt != scope.attempt
            || result.build_digest != self.registration.capabilities.build_digest
            || result.redaction_policy_digest != scope.policy_digest
            || !result.lease_completed
            || !result.body_complete
            || result.peers.is_empty()
            || result.peers.len() > 256
            || result.target_status.is_some_and(|s| !(100..=599).contains(&s))
            || (!matches!(target.scheme(), "http" | "https") && result.target_status.is_some())
            || result.redirects.len() > 20
            || (!self.registration.capabilities.redirects
                && (!result.redirects.is_empty()
                    || result
                        .final_url
                        .as_ref()
                        .is_some_and(|final_url| final_url != target)))
            || result.media_type.as_ref().is_some_and(|s| s.len() > 256)
        {
            return Err(ProtocolError::Refused(
                "service response scope, schema or evidence",
            ));
        }
        for hop in &result.redirects {
            if !matches!(hop.url.scheme(), "http" | "https") {
                return Err(ProtocolError::Refused("redirect scheme"));
            }
            policy
                .check_url(&hop.url)
                .map_err(|_| ProtocolError::Refused("redirect authorization"))?;
            if hop.status.is_some_and(|status| !(300..=399).contains(&status))
                || !result
                    .peers
                    .iter()
                    .any(|peer| Some(peer.host.as_str()) == hop.url.host_str())
            {
                return Err(ProtocolError::Refused("redirect evidence"));
            }
        }
        if let Some(final_url) = &result.final_url {
            if final_url.username() != ""
                || final_url.password().is_some()
                || !self
                    .registration
                    .capabilities
                    .schemes
                    .contains(final_url.scheme())
            {
                return Err(ProtocolError::Refused("service final URL"));
            }
            policy
                .check_host(
                    final_url
                        .host_str()
                        .ok_or(ProtocolError::Refused("final URL host"))?,
                )
                .map_err(|_| ProtocolError::Refused("final URL policy"))?;
            if matches!(final_url.scheme(), "http" | "https") {
                policy
                    .check_url(final_url)
                    .map_err(|_| ProtocolError::Refused("final URL authorization"))?;
            } else if let Some(scope) = &policy.record_scope {
                scope
                    .check_request(final_url)
                    .map_err(|_| ProtocolError::Refused("final URL authorization"))?;
            }
            if !result
                .peers
                .iter()
                .any(|peer| Some(peer.host.as_str()) == final_url.host_str())
            {
                return Err(ProtocolError::Refused("final URL lacks peer evidence"));
            }
        }
        if target.scheme() == "sftp"
            && result.sftp_host_key.as_ref()
                != self
                    .registration
                    .sftp_host_keys
                    .get(target.host_str().unwrap_or(""))
        {
            return Err(ProtocolError::Refused("SFTP host key mismatch"));
        }
        for peer in &result.peers {
            if peer.host.len() > 253 {
                return Err(ProtocolError::Refused("peer host length"));
            }
            policy
                .check_host(&peer.host)
                .and_then(|()| policy.check_ip(peer.ip))
                .and_then(|()| policy.check_port(peer.port))
                .map_err(|_| ProtocolError::Refused("service target peer policy"))?;
            if peer.ftp_data && (target.scheme() != "ftp" || !target_addresses.contains(&peer.ip)) {
                return Err(ProtocolError::Refused("FTP passive bounce"));
            }
            let resolved;
            let addresses = if Some(peer.host.as_str()) == target.host_str() {
                target_addresses
            } else {
                resolved = resolver.resolve(&peer.host).await?;
                resolved.as_slice()
            };
            policy
                .check_all(&peer.host, addresses)
                .map_err(|_| ProtocolError::Refused("service peer DNS"))?;
            if !addresses.contains(&peer.ip) {
                return Err(ProtocolError::Refused("service peer not pinned"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
