//! Authenticated, one-request HTML acquisition through an operator-approved service.
//! The control-plane authority is independent from the caller's checked target policy.

use crate::{
    governor::{Origin, OriginGovernor},
    resolver::{CheckedResolution, Resolver},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use bytes::Bytes;
use crawlx_core::{
    acquisition::{AcquisitionResultV1, BackendCapabilitiesV1, UrlEvidenceV1},
    hash::Digest,
    parser_memory::{self, BytePermit},
    secret::{CredentialRef, SecretOr},
    CrawlRunId, SessionId, TenantId,
};
use crawlx_policy::egress::EgressPolicy;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;
use url::Url;

const REQUIRED: [&str; 10] = [
    "checked_egress",
    "all_resource_guard",
    "bounded_body",
    "deadline",
    "cancellation",
    "identity_isolation",
    "read_only_effects",
    "secret_free_response",
    "shared_origin_admission",
    "external_processing",
];
const MAX_BODY: u32 = 67_108_864;
const MAX_ATTEMPTS: usize = 4096;

/// Strict operator configuration, never supplied by a remote service or tenant.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AcquisitionServiceRegistrationV1 {
    /// Fixed HTTPS endpoint without userinfo, query or fragment.
    pub endpoint: Url,
    /// Fixed audience approved by the operator.
    pub audience: String,
    /// Approved immutable service build.
    pub build_digest: Digest,
    /// Approved complete network guard implementation.
    pub guard_digest: Digest,
    /// Exact approved capability set, echoed without additions or omissions.
    pub capabilities: BTreeSet<String>,
    /// Scoped credential reference resolved by the operator, never sent to targets.
    pub credential_ref: CredentialRef,
    /// Optional trust root; hostname and certificate checks remain enabled.
    #[serde(default)]
    pub ca_pem: Option<String>,
    /// Explicit control-plane address approval, separate from target permissions.
    #[serde(default)]
    pub service_networks: Vec<ipnet::IpNet>,
    /// Maximum concurrent service requests, between one and 32.
    pub max_concurrency: u8,
}
impl std::fmt::Debug for AcquisitionServiceRegistrationV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquisitionServiceRegistrationV1")
            .field("build_digest", &self.build_digest)
            .field("guard_digest", &self.guard_digest)
            .finish_non_exhaustive()
    }
}
impl AcquisitionServiceRegistrationV1 {
    /// Construct a registration with one request slot and public-only control-plane egress.
    #[must_use]
    pub fn new(
        endpoint: Url,
        audience: String,
        build_digest: Digest,
        guard_digest: Digest,
        capabilities: BTreeSet<String>,
        credential_ref: CredentialRef,
    ) -> Self {
        Self {
            endpoint,
            audience,
            build_digest,
            guard_digest,
            capabilities,
            credential_ref,
            ca_pem: None,
            service_networks: Vec::new(),
            max_concurrency: 1,
        }
    }
}

/// Trusted caller ownership and privacy requirements. Responses cannot choose these values.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AcquisitionServiceScopeV1 {
    /// Authenticated tenant.
    pub tenant: TenantId,
    /// Current run.
    pub run: CrawlRunId,
    /// Actor session, absent for stateless requests.
    pub session: Option<SessionId>,
    /// Fenced actor generation, present exactly when session is present.
    pub session_generation: Option<u64>,
    /// Authenticated principal digest, not a service identity claim.
    pub principal: Digest,
    /// Stable one-use attempt identifier.
    pub attempt: String,
    /// Trusted immutable policy digest.
    pub policy_digest: Digest,
    /// Existing canonical request digest supplied by the authenticated worker.
    pub request_digest: Digest,
    /// Explicit permission to process content outside this worker.
    pub external_processing_approved: bool,
    /// Require operator-approved zero data retention compatibility.
    pub zdr: bool,
}
impl std::fmt::Debug for AcquisitionServiceScopeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquisitionServiceScopeV1")
            .finish_non_exhaustive()
    }
}
impl AcquisitionServiceScopeV1 {
    /// Construct trusted ownership; session fields may be assigned before acquisition.
    #[must_use]
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        principal: Digest,
        attempt: String,
        policy_digest: Digest,
        request_digest: Digest,
    ) -> Self {
        Self {
            tenant,
            run,
            session: None,
            session_generation: None,
            principal,
            attempt,
            policy_digest,
            request_digest,
            external_processing_approved: false,
            zdr: false,
        }
    }
}

/// Complete, bounded response. The caller owns metadata publication and canonical request identity.
#[non_exhaustive]
pub struct AcquisitionServiceResultV1 {
    /// Credential-masked target representation.
    pub body: Bytes,
    /// Byte reservation retained for the lifetime of the returned representation.
    pub body_permit: Arc<BytePermit>,
    /// Target evidence whose ownership comes only from the trusted scope.
    pub metadata: AcquisitionResultV1,
    /// Safe static classification of a legacy page error; never remote error text.
    pub page_error: Option<String>,
    /// Exactly one target request.
    pub network_requests: u32,
}
impl std::fmt::Debug for AcquisitionServiceResultV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquisitionServiceResultV1")
            .field("body_bytes", &self.body.len())
            .field("network_requests", &self.network_requests)
            .finish_non_exhaustive()
    }
}

struct BodyOwner {
    body: Vec<u8>,
    _permit: Arc<BytePermit>,
}
impl AsRef<[u8]> for BodyOwner {
    fn as_ref(&self) -> &[u8] {
        &self.body
    }
}

/// Safe boundary failures. HTTP errors retain their source after removing the endpoint URL.
/// JSON source omission is deliberate: parser errors can contain arbitrary response strings.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[allow(
    clippy::disallowed_types,
    reason = "service adapter retains sanitized native transport error sources"
)]
pub enum AcquisitionServiceError {
    /// Invalid operator configuration.
    #[error("acquisition service registration refused")]
    Registration,
    /// Policy, ownership or authenticated response mismatch.
    #[error("acquisition service contract refused: {0}")]
    Refused(&'static str),
    /// Attempt was consumed already or the bounded ledger is full.
    #[error("acquisition service attempt unavailable")]
    Replay,
    /// Envelope, decoded body or metadata exceeded a bound.
    #[error("acquisition service limit exceeded")]
    Limit,
    /// Shared byte admission refused an allocation.
    #[error("acquisition service byte pressure")]
    BytePressure,
    /// Bounded secret projection refused output or memory admission.
    #[error("acquisition service secret projection failed")]
    Projection(#[from] crawlx_core::secret::BoundedScrubError),
    /// Checked DNS failed without revealing host or resolver details.
    #[error("acquisition service resolution failed")]
    Resolve,
    /// TLS or HTTP failed; the endpoint URL is removed before retaining the source.
    #[error("acquisition service transport failed")]
    Transport(#[source] reqwest::Error),
    /// Malformed or unknown response schema.
    #[error("acquisition service response schema refused")]
    Schema,
    /// Whole-call lease expired.
    #[error("acquisition service deadline exceeded")]
    Deadline,
    /// Caller cancelled queued or running acquisition.
    #[error("acquisition service cancelled")]
    Cancelled,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Request<'a> {
    schema_version: u8,
    kind: &'static str,
    audience: &'a str,
    nonce: &'a str,
    idempotency_key: &'a str,
    ticket: String,
    scope: &'a AcquisitionServiceScopeV1,
    target: &'a Url,
    target_addresses: &'a [IpAddr],
    max_body_bytes: u32,
    deadline_unix_ms: u64,
    build_digest: Digest,
    guard_digest: Digest,
    required_capabilities: &'a BTreeSet<String>,
    follow_redirects: bool,
    allow_subresources: bool,
    allow_browser_writes: bool,
    cancel_on_disconnect: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Response {
    schema_version: u8,
    kind: String,
    audience: String,
    nonce: String,
    idempotency_key: String,
    tenant: TenantId,
    run: CrawlRunId,
    session: Option<SessionId>,
    session_generation: Option<u64>,
    principal: Digest,
    attempt: String,
    policy_digest: Digest,
    build_digest: Digest,
    guard_digest: Digest,
    #[serde(deserialize_with = "deserialize_capabilities")]
    capabilities: BTreeSet<String>,
    lease_completed: bool,
    body_complete: bool,
    network_requests: u32,
    #[serde(deserialize_with = "deserialize_peers")]
    peers: Vec<Peer>,
    representation: Representation,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Peer {
    host: String,
    ip: IpAddr,
    port: u16,
}

fn deserialize_peers<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Peer>, D::Error> {
    struct Peers;
    impl<'de> serde::de::Visitor<'de> for Peers {
        type Value = Vec<Peer>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most one checked target peer")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut peers = Vec::new();
            if let Some(peer) = seq.next_element::<Peer>()? {
                if peer.host.len() > 253 {
                    return Err(serde::de::Error::custom("peer host bound"));
                }
                peers.push(peer);
            }
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("peer count bound"));
            }
            Ok(peers)
        }
    }
    deserializer.deserialize_seq(Peers)
}

fn deserialize_capabilities<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeSet<String>, D::Error> {
    struct Capabilities;
    impl<'de> serde::de::Visitor<'de> for Capabilities {
        type Value = BTreeSet<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most 32 distinct bounded capability identifiers")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut capabilities = BTreeSet::new();
            while let Some(capability) = seq.next_element::<String>()? {
                if capabilities.len() >= 32
                    || capability.is_empty()
                    || capability.len() > 128
                    || capability.bytes().any(|b| b.is_ascii_control())
                    || !capabilities.insert(capability)
                {
                    return Err(serde::de::Error::custom("capability set bound"));
                }
            }
            Ok(capabilities)
        }
    }
    deserializer.deserialize_seq(Capabilities)
}
#[derive(Deserialize)]
#[serde(tag = "format", rename_all = "snake_case", deny_unknown_fields)]
enum Representation {
    Native {
        #[serde(rename = "bodyBase64")]
        body_base64: String,
        #[serde(rename = "targetStatus")]
        target_status: Option<u16>,
        #[serde(rename = "contentType")]
        content_type: Option<String>,
        #[serde(rename = "finalUrl")]
        final_url: Option<Url>,
    },
    Legacy {
        content: String,
        // wire-compat: exact legacy response keys.
        #[serde(rename = "pageStatusCode")]
        page_status_code: Option<u16>,
        #[serde(rename = "pageError")]
        page_error: Option<String>,
        #[serde(rename = "contentType")]
        content_type: Option<String>,
    },
}

/// Distinct HTML service adapter with scoped authentication and permanent one-use attempt admission.
pub struct AcquisitionServiceAdapter {
    registration: AcquisitionServiceRegistrationV1,
    credential: SecretOr<String>,
    sequence: AtomicU64,
    consumed: Mutex<BTreeSet<Digest>>,
    slots: tokio::sync::Semaphore,
}
impl std::fmt::Debug for AcquisitionServiceAdapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcquisitionServiceAdapter")
            .field("registration", &self.registration)
            .finish_non_exhaustive()
    }
}
impl AcquisitionServiceAdapter {
    /// Borrow approved body-free capability facts without exposing the resolved credential.
    #[must_use]
    pub fn registration(&self) -> &AcquisitionServiceRegistrationV1 {
        &self.registration
    }

    /// Validate operator registration and bind an already resolved scoped service credential.
    ///
    /// # Errors
    /// Refuses incomplete guard capabilities, invalid endpoint, unscoped credentials and unbounded settings.
    #[allow(
        clippy::disallowed_types,
        reason = "approved HTTPS acquisition adapter exclusively owns scoped raw transport"
    )]
    pub fn new(
        registration: AcquisitionServiceRegistrationV1,
        credential: SecretOr<String>,
    ) -> Result<Self, AcquisitionServiceError> {
        let endpoint = &registration.endpoint;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.as_str().len() > 4096
            || registration.audience.is_empty()
            || registration.audience.len() > 128
            || registration.audience.bytes().any(|b| b.is_ascii_control())
            || registration.build_digest == Digest([0; 32])
            || registration.guard_digest == Digest([0; 32])
            || registration.credential_ref.0.len() > 256
            || registration
                .credential_ref
                .0
                .bytes()
                .any(|b| b.is_ascii_control())
            || registration
                .credential_ref
                .0
                .split_once("://")
                .is_none_or(|(scheme, path)| scheme.is_empty() || path.is_empty())
            || credential.expose().len() < 8
            || credential.expose().len() > 8192
            || credential.expose().bytes().any(|b| b.is_ascii_control())
            || !(1..=32).contains(&registration.max_concurrency)
            || registration.capabilities.len() > 32
            || registration
                .capabilities
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.bytes().any(|b| b.is_ascii_control()))
            || REQUIRED.iter().any(|s| !registration.capabilities.contains(*s))
            || registration.service_networks.len() > 32
            || registration.ca_pem.as_ref().is_some_and(|pem| pem.len() > 16384)
        {
            return Err(AcquisitionServiceError::Registration);
        }
        if let Some(pem) = &registration.ca_pem {
            reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|_| AcquisitionServiceError::Registration)?;
        }
        let slots = tokio::sync::Semaphore::new(usize::from(registration.max_concurrency));
        Ok(Self {
            registration,
            credential,
            sequence: AtomicU64::new(0),
            consumed: Mutex::new(BTreeSet::new()),
            slots,
        })
    }

    /// Acquire exactly one HTML representation under checked target and independent control-plane policy.
    ///
    /// # Errors
    /// Refuses privacy violations, replay, failed DNS/pinning, response scope mismatch and all body bounds.
    /// Cancellation and deadline cover slot admission, DNS, governor, send and response streaming.
    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::disallowed_types,
        reason = "approved HTTPS acquisition adapter pins peers and bounds every raw response"
    )]
    pub async fn acquire(
        &self,
        scope: &AcquisitionServiceScopeV1,
        target: &Url,
        max_body_bytes: u32,
        max_elapsed: Duration,
        policy: &EgressPolicy,
        resolver: &dyn Resolver,
        governor: &OriginGovernor,
        cancel: &CancellationToken,
    ) -> Result<AcquisitionServiceResultV1, AcquisitionServiceError> {
        let started = Instant::now();
        let operation = async {
            if !scope.external_processing_approved
                || (scope.zdr && !self.registration.capabilities.contains("zdr_compatible"))
            {
                return Err(AcquisitionServiceError::Refused(
                    "external processing or retention",
                ));
            }
            if scope.attempt.is_empty()
                || scope.attempt.len() > 128
                || scope.attempt.bytes().any(|b| b.is_ascii_control())
                || scope.session.is_some() != scope.session_generation.is_some()
                || scope.principal == Digest([0; 32])
                || scope.policy_digest == Digest([0; 32])
                || scope.request_digest == Digest([0; 32])
                || target.as_str().len() > 8192
                || !target.username().is_empty()
                || target.password().is_some()
                || target.fragment().is_some()
            {
                return Err(AcquisitionServiceError::Refused("scope or target bounds"));
            }
            if max_body_bytes == 0
                || max_body_bytes > MAX_BODY
                || max_elapsed.is_zero()
                || max_elapsed > Duration::from_secs(3600)
            {
                return Err(AcquisitionServiceError::Limit);
            }
            let attempt = serde_json::to_vec(&(
                scope.tenant,
                scope.run,
                scope.session,
                scope.session_generation,
                scope.principal,
                &scope.attempt,
            ))
            .map_err(|_| AcquisitionServiceError::Schema)?;
            let idempotency = Digest::keyed(
                blake3::hash(self.credential.expose().as_bytes()).as_bytes(),
                "html-acquisition-attempt-v1",
                &attempt,
            );
            {
                let mut consumed = self.consumed.lock();
                if consumed.len() >= MAX_ATTEMPTS || !consumed.insert(idempotency) {
                    return Err(AcquisitionServiceError::Replay);
                }
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AcquisitionServiceError::Deadline)?;
            let remaining = max_elapsed
                .checked_sub(started.elapsed())
                .ok_or(AcquisitionServiceError::Deadline)?;
            let deadline_unix_ms = u64::try_from(
                now.as_millis()
                    .checked_add(remaining.as_millis())
                    .ok_or(AcquisitionServiceError::Limit)?,
            )
            .map_err(|_| AcquisitionServiceError::Limit)?;
            let sequence = self
                .sequence
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .map_err(|_| AcquisitionServiceError::Limit)?;
            let nonce = Digest::keyed(
                blake3::hash(self.credential.expose().as_bytes()).as_bytes(),
                "html-acquisition-nonce-v1",
                &serde_json::to_vec(&(std::process::id(), now.as_nanos(), sequence, idempotency))
                    .map_err(|_| AcquisitionServiceError::Schema)?,
            )
            .to_hex();
            let idempotency_key = idempotency.to_hex();
            let _slot = self
                .slots
                .acquire()
                .await
                .map_err(|_| AcquisitionServiceError::Refused("service pool closed"))?;
            policy
                .check_url(target)
                .map_err(|_| AcquisitionServiceError::Refused("target policy"))?;
            let host = target
                .host_str()
                .ok_or(AcquisitionServiceError::Refused("target host"))?;
            let port = target
                .port_or_known_default()
                .ok_or(AcquisitionServiceError::Refused("target port"))?;
            let checked = CheckedResolution::resolve(resolver, policy, target)
                .await
                .map_err(|error| match error {
                    crate::FetchError::Resolve { .. } => AcquisitionServiceError::Resolve,
                    _ => AcquisitionServiceError::Refused("target checked resolution"),
                })?;
            let addresses = checked.addresses();
            if addresses.len() > 64 {
                return Err(AcquisitionServiceError::Refused("target DNS bounds"));
            }
            let endpoint = &self.registration.endpoint;
            let mut service_policy = EgressPolicy::new(false).with_seed_port(endpoint);
            service_policy
                .extra_allow
                .clone_from(&self.registration.service_networks);
            service_policy
                .check_url(endpoint)
                .map_err(|_| AcquisitionServiceError::Refused("service endpoint policy"))?;
            let service_host = endpoint.host_str().ok_or(AcquisitionServiceError::Registration)?;
            let service_ips = resolver
                .resolve(service_host)
                .await
                .map_err(|_| AcquisitionServiceError::Resolve)?;
            if service_ips.is_empty() || service_ips.len() > 64 {
                return Err(AcquisitionServiceError::Refused("service DNS bounds"));
            }
            service_policy
                .check_all(service_host, &service_ips)
                .map_err(|_| AcquisitionServiceError::Refused("service DNS policy"))?;
            let service_port = endpoint
                .port_or_known_default()
                .ok_or(AcquisitionServiceError::Registration)?;
            let sockets: Vec<_> = service_ips
                .iter()
                .map(|ip| SocketAddr::new(*ip, service_port))
                .collect();
            let mut builder = reqwest::Client::builder()
                .https_only(true)
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .http1_only()
                .pool_max_idle_per_host(0)
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .resolve_to_addrs(service_host, &sockets);
            if let Some(pem) = &self.registration.ca_pem {
                builder = builder.add_root_certificate(
                    reqwest::Certificate::from_pem(pem.as_bytes())
                        .map_err(|_| AcquisitionServiceError::Registration)?,
                );
            }
            let client = builder
                .build()
                .map_err(|error| AcquisitionServiceError::Transport(error.without_url()))?;
            let mut request = Request {
                schema_version: 1,
                kind: "html_acquisition",
                audience: &self.registration.audience,
                nonce: &nonce,
                idempotency_key: &idempotency_key,
                ticket: String::new(),
                scope,
                target,
                target_addresses: addresses,
                max_body_bytes,
                deadline_unix_ms,
                build_digest: self.registration.build_digest,
                guard_digest: self.registration.guard_digest,
                required_capabilities: &self.registration.capabilities,
                follow_redirects: false,
                allow_subresources: false,
                allow_browser_writes: false,
                cancel_on_disconnect: true,
            };
            let mut canonical =
                serde_json::to_value(&request).map_err(|_| AcquisitionServiceError::Schema)?;
            canonical.sort_all_objects();
            request.ticket = Digest::keyed(
                blake3::hash(self.credential.expose().as_bytes()).as_bytes(),
                "html-acquisition-ticket-v1",
                &serde_json::to_vec(&canonical).map_err(|_| AcquisitionServiceError::Schema)?,
            )
            .to_hex();
            let _permit = governor
                .acquire_resolved(&Origin::new(&target.origin().ascii_serialization()), &checked)
                .await
                .map_err(|_| AcquisitionServiceError::Refused("origin admission unavailable"))?;
            if started.elapsed() >= max_elapsed {
                return Err(AcquisitionServiceError::Deadline);
            }
            let cap = usize::try_from(max_body_bytes).map_err(|_| AcquisitionServiceError::Limit)?;
            let wire_cap = cap
                .checked_mul(2)
                .and_then(|n| n.checked_add(65536))
                .ok_or(AcquisitionServiceError::Limit)?;
            // Covers the streamed bytes plus owned strings created during strict JSON parsing.
            let _envelope_permit = parser_memory::global()
                .try_reserve(wire_cap.checked_mul(2).ok_or(AcquisitionServiceError::Limit)?)
                .map_err(|_| AcquisitionServiceError::BytePressure)?;
            let mut response = client
                .post(endpoint.clone())
                .bearer_auth(self.credential.expose())
                .json(&request)
                .send()
                .await
                .map_err(|error| AcquisitionServiceError::Transport(error.without_url()))?;
            if response.remote_addr().is_none_or(|peer| !sockets.contains(&peer)) {
                return Err(AcquisitionServiceError::Refused("service peer not pinned"));
            }
            let gateway_status = response.status().as_u16();
            if gateway_status != 200 {
                return Err(AcquisitionServiceError::Refused("service gateway failure"));
            }
            let wire_cap_u64 = u64::try_from(wire_cap).map_err(|_| AcquisitionServiceError::Limit)?;
            if response.content_length().is_some_and(|n| n > wire_cap_u64) {
                return Err(AcquisitionServiceError::Limit);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| AcquisitionServiceError::Transport(error.without_url()))?
            {
                if bytes.len().checked_add(chunk.len()).is_none_or(|n| n > wire_cap) {
                    return Err(AcquisitionServiceError::Limit);
                }
                bytes
                    .try_reserve_exact(chunk.len())
                    .map_err(|_| AcquisitionServiceError::BytePressure)?;
                bytes.extend_from_slice(&chunk);
            }
            let result: Response =
                serde_json::from_slice(&bytes).map_err(|_| AcquisitionServiceError::Schema)?;
            self.validate(&result, scope, &nonce, &idempotency_key, host, port, addresses)?;
            // Decoding and redaction can temporarily coexist. Admission precedes either allocation.
            let body_permit = Arc::new(
                parser_memory::global()
                    .try_reserve(cap)
                    .map_err(|_| AcquisitionServiceError::BytePressure)?,
            );
            let mut decode_permit = parser_memory::global()
                .try_reserve(0)
                .map_err(|_| AcquisitionServiceError::BytePressure)?;
            let (body, target_status, content_type, final_url, page_error) = match result.representation {
                Representation::Native {
                    body_base64,
                    target_status,
                    content_type,
                    final_url,
                } => {
                    if final_url.as_ref().is_some_and(|url| url != target) {
                        return Err(AcquisitionServiceError::Refused("final URL differs from target"));
                    }
                    let padding = body_base64
                        .as_bytes()
                        .iter()
                        .rev()
                        .take_while(|b| **b == b'=')
                        .count();
                    if padding > 2 || !body_base64.len().is_multiple_of(4) {
                        return Err(AcquisitionServiceError::Schema);
                    }
                    let decoded_len = body_base64
                        .len()
                        .checked_div(4)
                        .and_then(|n| n.checked_mul(3))
                        .and_then(|n| n.checked_sub(padding))
                        .ok_or(AcquisitionServiceError::Limit)?;
                    if decoded_len > cap {
                        return Err(AcquisitionServiceError::Limit);
                    }
                    let mut body = vec![0; decoded_len];
                    let written = STANDARD
                        .decode_slice(body_base64.as_bytes(), &mut body)
                        .map_err(|_| AcquisitionServiceError::Schema)?;
                    body.truncate(written);
                    (body, target_status, content_type, final_url, None)
                }
                Representation::Legacy {
                    content,
                    page_status_code,
                    page_error,
                    content_type,
                } => {
                    if content.len() > cap || page_error.as_ref().is_some_and(|s| s.len() > 1024) {
                        return Err(AcquisitionServiceError::Limit);
                    }
                    (
                        content.into_bytes(),
                        page_status_code,
                        content_type,
                        None,
                        page_error
                            .filter(|s| !s.is_empty())
                            .map(|_| "remote_page_error".to_owned()),
                    )
                }
            };
            if target_status.is_some_and(|status| !(100..=599).contains(&status))
                || content_type.as_ref().is_some_and(|s| {
                    s.len() > 256 || !s.is_ascii() || s.bytes().any(|b| b.is_ascii_control())
                })
            {
                return Err(AcquisitionServiceError::Refused("target metadata bounds"));
            }
            if let Some(status) = target_status {
                // Target status drives the same shared cooldown owner. Service/control-plane
                // elapsed time is not invented as target latency or Retry-After evidence.
                governor
                    .on_response_with_latency(
                        &Origin::new(&target.origin().ascii_serialization()),
                        status,
                        None,
                        None,
                        true,
                    )
                    .await
                    .map_err(|_| AcquisitionServiceError::Refused("origin feedback unavailable"))?;
            }
            let decoded_bytes = u64::try_from(body.len()).map_err(|_| AcquisitionServiceError::Limit)?;
            let redactor = crawlx_telemetry::Redactor::new();
            let body = match redactor.scrub_bytes_bounded(
                &body,
                std::iter::once(self.credential.expose().as_str()),
                &mut decode_permit,
                cap,
            )? {
                None => body,
                Some(clean) => {
                    drop(body);
                    clean
                }
            };
            if body.len() > cap {
                return Err(AcquisitionServiceError::Limit);
            }
            drop(decode_permit);
            let mut backend = BackendCapabilitiesV1::native_http("crawlx-fetch", env!("CARGO_PKG_VERSION"));
            backend.backend_id = "acquisition_service".to_owned();
            backend.build_digest = Some(self.registration.build_digest);
            backend.limitations = vec![
                "service_declared_target_evidence".to_owned(),
                "certificate_evidence_unavailable".to_owned(),
            ];
            let safe_url = |url: &Url| -> Result<Url, AcquisitionServiceError> {
                let clean = redactor.scrub_bytes(
                    url.as_str().as_bytes(),
                    std::iter::once(self.credential.expose().as_str()),
                );
                Url::parse(std::str::from_utf8(&clean).map_err(|_| AcquisitionServiceError::Schema)?)
                    .map_err(|_| AcquisitionServiceError::Schema)
            };
            let mut metadata = AcquisitionResultV1::new(
                scope.run,
                scope.tenant,
                safe_url(target)?,
                scope.request_digest,
                backend,
            );
            metadata.session = scope.session;
            metadata.session_generation = scope.session_generation;
            metadata.dns_report = checked.dns_report().cloned();
            metadata.final_url = final_url.as_ref().map(safe_url).transpose()?;
            metadata.final_url_evidence = if final_url.is_some() {
                UrlEvidenceV1::Declared
            } else {
                UrlEvidenceV1::Unavailable
            };
            metadata.target_status = target_status;
            metadata.gateway_status = Some(gateway_status);
            metadata.content_type =
                content_type.map(|s| redactor.scrub(&s).replace(self.credential.expose(), "[REDACTED]"));
            metadata.transport_succeeded = target_status.is_some();
            metadata.decoded_bytes = decoded_bytes;
            metadata.attempts = 1;
            metadata.network_requests = 1;
            metadata.network_requests_observed = Some(1);
            metadata.elapsed_ms =
                u64::try_from(started.elapsed().as_millis()).map_err(|_| AcquisitionServiceError::Limit)?;
            metadata.bound().map_err(|_| AcquisitionServiceError::Limit)?;
            if started.elapsed() >= max_elapsed {
                return Err(AcquisitionServiceError::Deadline);
            }
            let body = Bytes::from_owner(BodyOwner {
                body,
                _permit: Arc::clone(&body_permit),
            });
            Ok(AcquisitionServiceResultV1 {
                body,
                body_permit,
                metadata,
                page_error,
                network_requests: 1,
            })
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(AcquisitionServiceError::Cancelled),
            result = tokio::time::timeout(max_elapsed, operation) => result.map_err(|_| AcquisitionServiceError::Deadline)?,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate(
        &self,
        result: &Response,
        scope: &AcquisitionServiceScopeV1,
        nonce: &str,
        idempotency: &str,
        host: &str,
        port: u16,
        addresses: &[IpAddr],
    ) -> Result<(), AcquisitionServiceError> {
        if result.schema_version != 1
            || result.kind != "html_acquisition"
            || result.audience != self.registration.audience
            || result.nonce != nonce
            || result.idempotency_key != idempotency
            || result.tenant != scope.tenant
            || result.run != scope.run
            || result.session != scope.session
            || result.session_generation != scope.session_generation
            || result.principal != scope.principal
            || result.attempt != scope.attempt
            || result.policy_digest != scope.policy_digest
            || result.build_digest != self.registration.build_digest
            || result.guard_digest != self.registration.guard_digest
            || result.capabilities != self.registration.capabilities
            || !result.lease_completed
            || !result.body_complete
            || result.network_requests != 1
            || result.peers.len() != 1
        {
            return Err(AcquisitionServiceError::Refused(
                "authenticated response mismatch",
            ));
        }
        if result
            .peers
            .iter()
            .any(|peer| peer.host != host || peer.port != port || !addresses.contains(&peer.ip))
        {
            return Err(AcquisitionServiceError::Refused("unapproved target peer"));
        }
        Ok(())
    }
}
