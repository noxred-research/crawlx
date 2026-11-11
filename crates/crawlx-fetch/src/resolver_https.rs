//! Bounded DNS-over-HTTPS with operator-owned endpoint pins and no system DNS fallback.
//!
//! Endpoint and answer policies are independent. Callers must still use checked target
//! resolution: the operator's answer policy never replaces a run's narrower egress policy.

use crate::error::FetchError;
use crate::resolver::{parse_ip_literal, Resolver};
use async_trait::async_trait;
use crawlx_policy::EgressPolicy;
use hickory_resolver::proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_resolver::proto::serialize::binary::{BinDecodable, BinDecoder};
use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;

/// Operator-only endpoint, bootstrap pins and finite resource limits.
#[derive(Clone)]
#[non_exhaustive]
pub struct HttpsResolverConfig {
    /// HTTPS endpoint accepting RFC 8484 wire-format POST requests.
    pub endpoint: Url,
    /// Approved endpoint addresses. Empty pins fail closed; no bootstrap lookup occurs.
    pub bootstrap_pins: Vec<IpAddr>,
    /// Total lookup deadline, including both address families and all aliases.
    pub deadline: Duration,
    /// Maximum DNS response body size, at most 65,535 bytes.
    pub max_response_bytes: usize,
    /// Maximum records across all sections of one DNS response, at most 1,024.
    pub max_records: usize,
    /// Maximum alias transitions per address family, at most 16.
    pub max_cname_depth: usize,
}

impl std::fmt::Debug for HttpsResolverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Invalid, not-yet-validated operator input may still contain credentials.
        f.debug_struct("HttpsResolverConfig")
            .field("endpoint", &"[configured]")
            .field("bootstrap_pins", &self.bootstrap_pins)
            .field("deadline", &self.deadline)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_records", &self.max_records)
            .field("max_cname_depth", &self.max_cname_depth)
            .finish()
    }
}

impl HttpsResolverConfig {
    /// Use conservative finite limits; endpoint pins must come from operator configuration.
    #[must_use]
    pub fn new(endpoint: Url, bootstrap_pins: Vec<IpAddr>) -> Self {
        Self {
            endpoint,
            bootstrap_pins,
            deadline: Duration::from_secs(5),
            max_response_bytes: 16_384,
            max_records: 128,
            max_cname_depth: 8,
        }
    }

    /// Validate deployment configuration without building a client or making network requests.
    ///
    /// # Errors
    /// Returns an error for non-HTTPS endpoints, missing or denied pins, or unbounded limits.
    pub fn validate(&self, endpoint_policy: &EgressPolicy) -> Result<(), FetchError> {
        if self.endpoint.scheme() != "https" {
            return Err(refused("", "encrypted DNS requires HTTPS"));
        }
        self.validate_endpoint(endpoint_policy)
    }

    fn validate_endpoint(&self, endpoint_policy: &EgressPolicy) -> Result<(), FetchError> {
        let host = self
            .endpoint
            .host_str()
            .ok_or_else(|| refused("", "missing DNS endpoint host"))?;
        if self.endpoint.fragment().is_some()
            || self.endpoint.query().is_some()
            || self.bootstrap_pins.is_empty()
            || self.bootstrap_pins.len() > 16
            || self.deadline.is_zero()
            || self.deadline > Duration::from_secs(60)
            || !(12..=65_535).contains(&self.max_response_bytes)
            || !(1..=1024).contains(&self.max_records)
            || !(1..=16).contains(&self.max_cname_depth)
        {
            return Err(refused("", "invalid encrypted DNS endpoint or limits"));
        }
        endpoint_policy.check_url(&self.endpoint)?;
        endpoint_policy.check_all(host, &self.bootstrap_pins)?;
        if let Some(ip) = parse_ip_literal(host) {
            if self.bootstrap_pins.iter().any(|pin| *pin != ip) {
                return Err(refused("", "literal DNS endpoint differs from bootstrap pins"));
            }
        }
        Ok(())
    }
}

/// Checked encrypted DNS transport. No redirects, ambient proxy, or DNS recursion.
#[non_exhaustive]
pub struct HttpsResolver {
    config: HttpsResolverConfig,
    client: reqwest::Client,
    endpoint_policy: Arc<EgressPolicy>,
    answer_policy: Arc<EgressPolicy>,
    cancel: CancellationToken,
}

impl std::fmt::Debug for HttpsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpsResolver")
            .field("pin_count", &self.config.bootstrap_pins.len())
            .field("deadline", &self.config.deadline)
            .finish_non_exhaustive()
    }
}

/// Transport DNS is deliberately incapable of resolving any name except the pinned endpoint.
struct EndpointPins {
    host: String,
    addresses: Arc<[SocketAddr]>,
}

impl reqwest::dns::Resolve for EndpointPins {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let matches = name.as_str().eq_ignore_ascii_case(&self.host);
        let addresses = Arc::clone(&self.addresses);
        Box::pin(async move {
            if !matches {
                return Err(std::io::Error::other("unapproved DNS transport host").into());
            }
            // The iterator owns shared pins, so resolution does not copy the address list.
            Ok(Box::new((0..addresses.len()).map(move |index| addresses[index])) as reqwest::dns::Addrs)
        })
    }
}

fn refused(host: &str, reason: &'static str) -> FetchError {
    FetchError::Resolve {
        host: host.to_owned(),
        reason: reason.to_owned(),
    }
}

impl HttpsResolver {
    /// Build a verified HTTPS transport using only explicit approved bootstrap pins.
    ///
    /// Neither policy nor endpoint may originate from tenant request fields. TLS always
    /// verifies the endpoint name and certificate chain using the standard trusted roots.
    ///
    /// # Errors
    /// Returns configuration, endpoint egress or HTTP client construction errors.
    pub fn new(
        config: HttpsResolverConfig,
        endpoint_policy: Arc<EgressPolicy>,
        answer_policy: Arc<EgressPolicy>,
        cancel: CancellationToken,
    ) -> Result<Self, FetchError> {
        config.validate(&endpoint_policy)?;
        Self::build_validated(config, endpoint_policy, answer_policy, cancel)
    }

    fn build_validated(
        mut config: HttpsResolverConfig,
        endpoint_policy: Arc<EgressPolicy>,
        answer_policy: Arc<EgressPolicy>,
        cancel: CancellationToken,
    ) -> Result<Self, FetchError> {
        let host = config.endpoint.host_str().unwrap_or_default().to_owned();
        config.bootstrap_pins.sort_unstable();
        config.bootstrap_pins.dedup();
        let port = config
            .endpoint
            .port_or_known_default()
            .ok_or_else(|| refused("", "invalid DNS endpoint port"))?;
        let addresses = config
            .bootstrap_pins
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect();
        let client = reqwest::Client::builder()
            .dns_resolver(Arc::new(EndpointPins { host, addresses }))
            .no_proxy()
            .https_only(config.endpoint.scheme() == "https")
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .http1_only()
            .pool_max_idle_per_host(0)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .connect_timeout(config.deadline)
            .timeout(config.deadline)
            .build()
            .map_err(|source| FetchError::ClientBuild(source.without_url().into()))?;
        Ok(Self {
            config,
            client,
            endpoint_policy,
            answer_policy,
            cancel,
        })
    }

    /// Resolve with an additional caller cancellation token; dropping the future also cancels I/O.
    ///
    /// # Errors
    /// Returns egress, DNS protocol, transport, deadline or cancellation errors. No failure
    /// falls back to system DNS or accepts only the safe subset of a mixed answer.
    pub async fn resolve_cancellable(
        &self,
        host: &str,
        cancel: &CancellationToken,
    ) -> Result<(Vec<IpAddr>, Option<Duration>), FetchError> {
        tokio::select! {
            biased;
            () = self.cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
            () = cancel.cancelled() => Err(FetchError::AcquisitionCancelled),
            result = tokio::time::timeout(self.config.deadline, self.lookup(host)) => {
                result.map_err(|_| FetchError::AcquisitionDeadline)?
            }
        }
    }

    async fn lookup(&self, host: &str) -> Result<(Vec<IpAddr>, Option<Duration>), FetchError> {
        self.answer_policy.check_host(host)?;
        if let Some(ip) = parse_ip_literal(host) {
            self.answer_policy.check_all(host, &[ip])?;
            return Ok((vec![ip], None));
        }
        let mut name = Name::from_ascii(host).map_err(|source| {
            FetchError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, source))
        })?;
        name.set_fqdn(true);
        let started = tokio::time::Instant::now();
        let mut addresses = Vec::new();
        let mut ttl = u32::MAX;
        // Both families are mandatory: a broken or unsafe second answer cannot be hidden
        // behind the first family's successful result.
        for kind in [RecordType::A, RecordType::AAAA] {
            self.lookup_family(host, name.clone(), kind, &mut addresses, &mut ttl)
                .await?;
        }
        if addresses.is_empty() {
            return Err(refused(host, "no addresses"));
        }
        self.answer_policy.check_all(host, &addresses)?;
        addresses.sort_unstable();
        addresses.dedup();
        let remaining = Duration::from_secs(u64::from(ttl)).saturating_sub(started.elapsed());
        Ok((addresses, Some(remaining)))
    }

    async fn lookup_family(
        &self,
        host: &str,
        mut name: Name,
        kind: RecordType,
        addresses: &mut Vec<IpAddr>,
        ttl: &mut u32,
    ) -> Result<(), FetchError> {
        let mut visited = BTreeSet::new();
        visited.insert(name.clone());
        let mut depth = 0;
        loop {
            let query = Query::query(name.clone(), kind);
            let message = self.exchange(host, &query).await?;
            let queried = name.clone();
            loop {
                let mut alias = None;
                let mut found = false;
                for record in message.answers.iter().filter(|record| record.name == name) {
                    match &record.data {
                        RData::CNAME(target) => {
                            if alias.is_some_and(|previous| previous != &target.0) {
                                return Err(refused(host, "conflicting DNS aliases"));
                            }
                            alias = Some(&target.0);
                            *ttl = (*ttl).min(record.ttl);
                        }
                        RData::A(ip) if kind == RecordType::A => {
                            addresses.push(IpAddr::V4(ip.0));
                            *ttl = (*ttl).min(record.ttl);
                            found = true;
                        }
                        RData::AAAA(ip) if kind == RecordType::AAAA => {
                            addresses.push(IpAddr::V6(ip.0));
                            *ttl = (*ttl).min(record.ttl);
                            found = true;
                        }
                        RData::A(_) | RData::AAAA(_) => {
                            return Err(refused(host, "DNS answer type differs from question"));
                        }
                        _ => {}
                    }
                }
                let Some(target) = alias else {
                    if found || name == queried {
                        return Ok(());
                    }
                    break; // An alias-only reply needs another checked endpoint exchange.
                };
                if found || depth >= self.config.max_cname_depth || !visited.insert(target.clone()) {
                    return Err(refused(host, "invalid DNS alias chain"));
                }
                self.answer_policy.check_host(&target.to_ascii())?;
                name = target.clone();
                depth += 1;
            }
        }
    }

    async fn exchange(&self, host: &str, query: &Query) -> Result<Message, FetchError> {
        self.endpoint_policy.check_url(&self.config.endpoint)?;
        self.endpoint_policy.check_all(
            self.config.endpoint.host_str().unwrap_or_default(),
            &self.config.bootstrap_pins,
        )?;
        // RFC 8484 recommends zero IDs: HTTP binds each response to its own request.
        let mut request = Message::new(0, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(query.clone());
        let wire = request
            .to_vec()
            .map_err(|source| FetchError::Io(std::io::Error::other(source)))?;
        let mut response = self
            .client
            .post(self.config.endpoint.clone())
            .header(reqwest::header::ACCEPT, "application/dns-message")
            .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .body(wire)
            .send()
            .await
            .map_err(|source| FetchError::Transport(source.without_url().into()))?;
        let peer = response
            .remote_addr()
            .ok_or_else(|| refused(host, "DNS endpoint peer unavailable"))?;
        let endpoint_host = self.config.endpoint.host_str().unwrap_or_default();
        if !self.config.bootstrap_pins.contains(&peer.ip())
            || Some(peer.port()) != self.config.endpoint.port_or_known_default()
        {
            return Err(FetchError::PeerNotPinned {
                host: endpoint_host.to_owned(),
                peer: peer.ip(),
            });
        }
        self.endpoint_policy.check_all(endpoint_host, &[peer.ip()])?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(refused(host, "DNS endpoint refused request or redirected"));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if !content_type.is_some_and(|value| value.eq_ignore_ascii_case("application/dns-message"))
            || response.headers().contains_key(reqwest::header::CONTENT_ENCODING)
        {
            return Err(refused(host, "invalid DNS endpoint media type or encoding"));
        }
        if response
            .content_length()
            .is_some_and(|length| length > u64::try_from(self.config.max_response_bytes).unwrap_or(u64::MAX))
        {
            return Err(refused(host, "DNS response exceeds byte limit"));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|source| FetchError::Transport(source.without_url().into()))?
        {
            if chunk.len() > self.config.max_response_bytes.saturating_sub(bytes.len()) {
                return Err(refused(host, "DNS response exceeds byte limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        self.decode(host, query, &bytes)
    }

    fn decode(&self, host: &str, query: &Query, bytes: &[u8]) -> Result<Message, FetchError> {
        let invalid = |source| FetchError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, source));
        // Decode the standard header before allocating records, including EDNS/signatures
        // in the cap. The protocol crate validates compression, names and record lengths.
        let header = Header::read(&mut BinDecoder::new(bytes)).map_err(invalid)?;
        let count = usize::from(header.counts.answers)
            .saturating_add(usize::from(header.counts.authorities))
            .saturating_add(usize::from(header.counts.additionals));
        if header.counts.queries != 1 || count > self.config.max_records {
            return Err(refused(host, "DNS question or record count exceeds limit"));
        }
        let mut decoder = BinDecoder::new(bytes);
        let message = Message::read(&mut decoder).map_err(invalid)?;
        if decoder.index() != bytes.len()
            || message.metadata.id != 0
            || message.metadata.message_type != MessageType::Response
            || message.metadata.op_code != OpCode::Query
            || message.metadata.truncation
            || message.metadata.response_code != ResponseCode::NoError
            || message.queries.as_slice() != std::slice::from_ref(query)
        {
            return Err(refused(host, "mismatched, truncated or refused DNS response"));
        }
        for record in message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
        {
            if record.dns_class != DNSClass::IN {
                return Err(refused(host, "invalid DNS record class"));
            }
            // Reject every unsafe address, even unrelated glue. Never filter a mixed
            // response into an apparently safe answer.
            match &record.data {
                RData::A(ip) => self.answer_policy.check_ip(IpAddr::V4(ip.0))?,
                RData::AAAA(ip) => self.answer_policy.check_ip(IpAddr::V6(ip.0))?,
                _ => {}
            }
        }
        Ok(message)
    }
}

#[async_trait]
impl Resolver for HttpsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, FetchError> {
        self.resolve_with_ttl(host).await.map(|(addresses, _)| addresses)
    }

    async fn resolve_with_ttl(&self, host: &str) -> Result<(Vec<IpAddr>, Option<Duration>), FetchError> {
        self.resolve_cancellable(host, &CancellationToken::new()).await
    }
}

#[cfg(test)]
#[path = "resolver_https_tests.rs"]
mod tests;
