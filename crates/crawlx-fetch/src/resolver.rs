//! Name resolution behind a trait so tests and the egress proxy can inject
//! answers. `HickoryResolver` is the production
//! implementation; `StaticResolver` maps names to fixed addresses.

use crate::error::FetchError;
use async_trait::async_trait;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Addresses checked together against the target URL's egress policy.
///
/// Only checked resolution can construct this evidence. Request headers and
/// proxy addresses cannot select the physical-target capacity key.
#[derive(Debug)]
#[non_exhaustive]
pub struct CheckedResolution {
    origin: crate::governor::Origin,
    host: String,
    addresses: Vec<IpAddr>,
    valid_for: Option<Duration>,
}

impl CheckedResolution {
    /// Resolve a target and check its URL, name and every returned address.
    ///
    /// # Errors
    /// Returns URL, resolution or egress errors before minting admission evidence.
    pub async fn resolve(
        resolver: &dyn Resolver,
        policy: &crawlx_policy::EgressPolicy,
        url: &url::Url,
    ) -> Result<Self, FetchError> {
        policy.check_url(url)?;
        let (host, literal) = match url.host() {
            Some(url::Host::Domain(host)) => (host.to_ascii_lowercase(), None),
            Some(url::Host::Ipv4(ip)) => (ip.to_string(), Some(IpAddr::V4(ip))),
            Some(url::Host::Ipv6(ip)) => (ip.to_string(), Some(IpAddr::V6(ip))),
            None => {
                return Err(FetchError::InvalidUrl {
                    url: url.to_string(),
                    reason: "missing host",
                });
            }
        };
        Self::resolve_host(
            resolver,
            policy,
            crate::governor::Origin::from_url(url),
            host,
            literal,
        )
        .await
    }

    /// Check a proxy request authority without treating its Host header as evidence.
    pub(crate) async fn resolve_host(
        resolver: &dyn Resolver,
        policy: &crawlx_policy::EgressPolicy,
        origin: crate::governor::Origin,
        host: String,
        literal: Option<IpAddr>,
    ) -> Result<Self, FetchError> {
        policy.check_host(&host)?;
        let (mut addresses, valid_for) = match literal {
            Some(ip) => (vec![ip], None),
            None => resolver.resolve_with_ttl(&host).await?,
        };
        if addresses.is_empty() {
            return Err(FetchError::Resolve {
                host,
                reason: "no addresses".to_owned(),
            });
        }
        policy.check_all(&host, &addresses)?;
        // Canonical order also prevents lock-order cycles across overlapping DNS answers.
        addresses.sort_unstable_by_key(|ip| (ip.to_canonical(), *ip));
        addresses.dedup();
        tracing::debug!(
            address_count = addresses.len(),
            dns_ttl_known = valid_for.is_some(),
            dns_ttl_millis = valid_for.map(|ttl| u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX)),
            literal = literal.is_some(),
            "checked target resolution"
        );
        Ok(Self {
            origin,
            host,
            addresses,
            valid_for,
        })
    }

    /// Target origin bound to these addresses, not a caller-supplied Host header.
    #[must_use]
    pub fn origin(&self) -> &crate::governor::Origin {
        &self.origin
    }

    /// Checked target host, without brackets around IP literals.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Sorted, deduplicated addresses; every address passed egress policy.
    #[must_use]
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Remaining resolver cache lifetime at resolution, or unknown for literals/custom resolvers.
    ///
    /// Zero means the answer cannot be reused as a DNS cache entry. It does not
    /// invalidate the current checked, pinned connection attempt.
    #[must_use]
    pub const fn valid_for(&self) -> Option<Duration> {
        self.valid_for
    }
}

/// Resolves a host name to all of its A and AAAA addresses.
///
/// Implementations return every address; the caller checks all of them
/// against the egress policy. IP literals resolve to themselves.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Resolve `host` (name, IPv4 literal or bracketed IPv6 literal) to its addresses.
    ///
    /// # Errors
    /// [`FetchError::Resolve`] when the name does not resolve or yields no address.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, FetchError>;

    /// Resolve addresses and report their remaining cache lifetime when known.
    ///
    /// The default preserves custom resolvers without inventing a TTL or adding
    /// a second cache. Production DNS uses the resolver's actual expiry.
    ///
    /// # Errors
    /// Returns the same resolution errors as [`Self::resolve`].
    async fn resolve_with_ttl(&self, host: &str) -> Result<(Vec<IpAddr>, Option<Duration>), FetchError> {
        self.resolve(host).await.map(|addresses| (addresses, None))
    }
}

/// Parse `host` as an IP literal, accepting the bracketed IPv6 form.
pub(crate) fn parse_ip_literal(host: &str) -> Option<IpAddr> {
    let h = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    h.parse().ok()
}

/// `hickory-resolver` backed resolver (system configuration by default).
pub struct HickoryResolver {
    inner: TokioResolver,
}

impl HickoryResolver {
    /// Use the system resolver configuration (`/etc/resolv.conf`).
    ///
    /// # Errors
    /// [`FetchError::Resolve`] when the system configuration cannot be read or the resolver
    /// cannot be initialized.
    pub fn from_system_conf() -> Result<Self, FetchError> {
        let inner = hickory_resolver::system_conf::read_system_conf()
            .and_then(|(mut config, opts)| {
                // Hickory 0.24's system config did not trust negative replies.
                // Preserve failover without overriding explicit with_config callers.
                for server in &mut config.name_servers {
                    server.trust_negative_responses = false;
                }
                TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
                    .with_options(opts)
                    .build()
            })
            .map_err(|e| FetchError::Resolve {
                host: String::new(),
                reason: format!("system resolver configuration: {e}"),
            })?;
        Ok(Self { inner })
    }

    /// Use an explicit resolver configuration.
    ///
    /// # Errors
    /// [`FetchError::Resolve`] when the resolver cannot be initialized.
    pub fn with_config(config: ResolverConfig, opts: ResolverOpts) -> Result<Self, FetchError> {
        let inner = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .map_err(|e| FetchError::Resolve {
                host: String::new(),
                reason: format!("resolver configuration: {e}"),
            })?;
        Ok(Self { inner })
    }

    /// Query exactly `servers` (UDP first, TCP for truncated answers) instead of the system
    /// configuration (the `-r` compatibility flag): no search domains and no hosts file, so a name resolves
    /// the way the listed servers answer it.
    ///
    /// # Errors
    /// [`FetchError::Resolve`] when the resolver cannot be initialized.
    pub fn from_servers(servers: &[SocketAddr]) -> Result<Self, FetchError> {
        let group = servers
            .iter()
            .map(|server| {
                let mut config = NameServerConfig::udp_and_tcp(server.ip());
                config.trust_negative_responses = false;
                for connection in &mut config.connections {
                    connection.port = server.port();
                }
                config
            })
            .collect();
        let mut opts = ResolverOpts::default();
        opts.use_hosts_file = ResolveHosts::Never;
        Self::with_config(ResolverConfig::from_parts(None, Vec::new(), group), opts)
    }

    /// The TXT records of `name`: one string per record, a record's character-strings joined
    /// and decoded as lossy UTF-8. A name without a TXT record (NXDOMAIN or an empty answer)
    /// yields an empty list.
    ///
    /// # Errors
    /// [`FetchError::Resolve`] when the lookup fails for any other reason (timeout, SERVFAIL,
    /// refused): the caller cannot tell whether the record exists.
    pub async fn txt_lookup(&self, name: &str) -> Result<Vec<String>, FetchError> {
        match self.inner.txt_lookup(name).await {
            Ok(lookup) => Ok(lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::TXT(txt) => Some(txt),
                    _ => None,
                })
                .map(|txt| {
                    let bytes: Vec<u8> = txt
                        .txt_data
                        .iter()
                        .flat_map(|part| part.iter().copied())
                        .collect();
                    String::from_utf8_lossy(&bytes).into_owned()
                })
                .collect()),
            // Only NXDOMAIN and an empty NOERROR answer mean "no such record".
            // SERVFAIL, REFUSED and other lookup failures must still reach the caller.
            Err(e)
                if matches!(
                    &e,
                    NetError::Dns(DnsError::NoRecordsFound(records))
                        if matches!(records.response_code, ResponseCode::NXDomain | ResponseCode::NoError)
                ) =>
            {
                Ok(Vec::new())
            }
            Err(e) => Err(FetchError::Resolve {
                host: name.to_owned(),
                reason: e.to_string(),
            }),
        }
    }
}

impl std::fmt::Debug for HickoryResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HickoryResolver").finish_non_exhaustive()
    }
}

#[async_trait]
impl Resolver for HickoryResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, FetchError> {
        self.resolve_with_ttl(host).await.map(|(addresses, _)| addresses)
    }

    async fn resolve_with_ttl(&self, host: &str) -> Result<(Vec<IpAddr>, Option<Duration>), FetchError> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok((vec![ip], None));
        }
        let lookup = self
            .inner
            .lookup_ip(host)
            .await
            .map_err(|e| FetchError::Resolve {
                host: host.to_owned(),
                reason: e.to_string(),
            })?;
        let mut out: Vec<IpAddr> = Vec::new();
        for ip in lookup.iter() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        if out.is_empty() {
            return Err(FetchError::Resolve {
                host: host.to_owned(),
                reason: "no addresses".to_owned(),
            });
        }
        let valid_for = lookup.valid_until().saturating_duration_since(Instant::now());
        Ok((out, Some(valid_for)))
    }
}

/// Fixed name-to-address table. Unknown names fail like NXDOMAIN. Answers
/// can be replaced between calls to simulate DNS rebinding.
#[derive(Debug, Default)]
pub struct StaticResolver {
    table: Mutex<HashMap<String, Vec<IpAddr>>>,
}

impl StaticResolver {
    /// Empty table: every name fails to resolve until [`StaticResolver::set`] is called.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder form of [`StaticResolver::set`].
    #[must_use]
    pub fn with(self, host: &str, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.set(host, addrs);
        self
    }

    /// Replace the answer for `host` (case-insensitive).
    pub fn set(&self, host: &str, addrs: impl IntoIterator<Item = IpAddr>) {
        self.table
            .lock()
            .insert(host.to_ascii_lowercase(), addrs.into_iter().collect());
    }
}

#[async_trait]
impl Resolver for StaticResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, FetchError> {
        if let Some(ip) = parse_ip_literal(host) {
            return Ok(vec![ip]);
        }
        match self.table.lock().get(&host.to_ascii_lowercase()) {
            Some(v) if !v.is_empty() => Ok(v.clone()),
            _ => Err(FetchError::Resolve {
                host: host.to_owned(),
                reason: "no such host".to_owned(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use hickory_resolver::config::{LookupIpStrategy, ServerOrderingStrategy};
    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::rdata::{A, SOA, TXT};
    use hickory_resolver::proto::rr::{Record, RecordType};
    use std::net::Ipv6Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::sync::oneshot;
    use tokio::task::JoinSet;
    use tokio::time::{sleep, timeout};

    /// A loopback-only DNS server; dropping it aborts its receive task.
    struct DnsStub {
        addr: SocketAddr,
        _tasks: JoinSet<()>,
    }

    impl DnsStub {
        async fn start(mut answer: impl FnMut(&mut Message) + Send + 'static) -> Self {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let addr = socket.local_addr().unwrap();
            let mut tasks = JoinSet::new();
            tasks.spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                    let mut reply = Message::from_vec(&buf[..n]).unwrap().into_response();
                    reply.metadata.recursion_available = true;
                    answer(&mut reply);
                    socket.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
                }
            });
            Self { addr, _tasks: tasks }
        }

        fn with_options(&self, opts: ResolverOpts) -> HickoryResolver {
            let mut server = NameServerConfig::udp(self.addr.ip());
            server.connections[0].port = self.addr.port();
            HickoryResolver::with_config(ResolverConfig::from_parts(None, Vec::new(), vec![server]), opts)
                .unwrap()
        }
    }

    #[tokio::test]
    async fn custom_server_returns_a_aaaa_and_only_authoritative_txt_absence() {
        let dns = DnsStub::start(|reply| {
            let query = &reply.queries[0];
            let name = query.name.clone();
            match name.to_utf8().as_str() {
                "missing.test." => reply.metadata.response_code = ResponseCode::NXDomain,
                "empty.test." => {}
                "servfail.test." => reply.metadata.response_code = ResponseCode::ServFail,
                "refused.test." => reply.metadata.response_code = ResponseCode::Refused,
                "answer.test." => {
                    let data = match query.query_type {
                        RecordType::A => RData::A(A::new(192, 0, 2, 1)),
                        RecordType::AAAA => RData::AAAA(Ipv6Addr::LOCALHOST.into()),
                        RecordType::TXT => RData::TXT(TXT::from_bytes(vec![b"first", b"-second"])),
                        other => panic!("unexpected query type: {other}"),
                    };
                    reply.add_answer(Record::from_rdata(name, 60, data));
                }
                other => panic!("unexpected DNS name: {other}"),
            }
        })
        .await;
        let resolver = HickoryResolver::from_servers(&[dns.addr]).unwrap();
        assert_eq!(resolver.inner.options().use_hosts_file, ResolveHosts::Never);
        let addrs = resolver.resolve("answer.test.").await.unwrap();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&IpAddr::from([192, 0, 2, 1])));
        assert!(addrs.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert_eq!(
            resolver.txt_lookup("answer.test.").await.unwrap(),
            ["first-second"]
        );
        for name in ["missing.test.", "empty.test."] {
            assert!(resolver.txt_lookup(name).await.unwrap().is_empty());
            assert!(matches!(
                resolver.resolve(name).await,
                Err(FetchError::Resolve { .. })
            ));
        }
        for name in ["servfail.test.", "refused.test."] {
            assert!(matches!(
                resolver.txt_lookup(name).await,
                Err(FetchError::Resolve { .. })
            ));
            assert!(matches!(
                resolver.resolve(name).await,
                Err(FetchError::Resolve { .. })
            ));
        }
    }

    #[tokio::test]
    async fn explicit_options_preserve_positive_ttl_and_zero_ttl_rebinding() {
        for ttl in [0, 60] {
            let queries = Arc::new(AtomicUsize::new(0));
            let seen = Arc::clone(&queries);
            let dns = DnsStub::start(move |reply| {
                let n = u8::try_from(seen.fetch_add(1, Ordering::SeqCst) + 1).unwrap();
                let name = reply.queries[0].name.clone();
                assert_eq!(reply.queries[0].query_type, RecordType::A);
                reply.add_answer(Record::from_rdata(name, ttl, RData::A(A::new(192, 0, 2, n))));
            })
            .await;
            let mut opts = ResolverOpts::default();
            opts.ip_strategy = LookupIpStrategy::Ipv4Only;
            opts.use_hosts_file = ResolveHosts::Never;
            let resolver = dns.with_options(opts);
            let (addresses, valid_for) = resolver.resolve_with_ttl("ttl.test.").await.unwrap();
            assert_eq!(addresses, [IpAddr::from([192, 0, 2, 1])]);
            let valid_for = valid_for.unwrap();
            if ttl == 0 {
                assert_eq!(valid_for, Duration::ZERO);
            } else {
                assert!(valid_for > Duration::ZERO);
                assert!(valid_for <= Duration::from_secs(u64::from(ttl)));
            }
            let expected = if ttl == 0 { 2 } else { 1 };
            assert_eq!(
                resolver.resolve("ttl.test.").await.unwrap(),
                [IpAddr::from([192, 0, 2, expected])]
            );
            assert_eq!(queries.load(Ordering::SeqCst), usize::from(expected));
        }
    }

    #[tokio::test]
    async fn checked_resolution_rejects_mixed_and_rebound_private_answers() {
        let public = IpAddr::from([93, 184, 216, 34]);
        let private = IpAddr::from([127, 0, 0, 1]);
        let resolver = StaticResolver::new().with("target.test", [public]);
        let policy = crawlx_policy::EgressPolicy::new(false);
        let url = url::Url::parse("https://target.test/").unwrap();
        let checked = CheckedResolution::resolve(&resolver, &policy, &url)
            .await
            .unwrap();
        assert_eq!(checked.addresses(), &[public]);
        assert_eq!(checked.valid_for(), None);
        resolver.set("target.test", [public, private]);
        assert!(matches!(
            CheckedResolution::resolve(&resolver, &policy, &url).await,
            Err(FetchError::EgressDenied(_))
        ));
        resolver.set("target.test", [private]);
        assert!(matches!(
            CheckedResolution::resolve(&resolver, &policy, &url).await,
            Err(FetchError::EgressDenied(_))
        ));
    }

    fn loopback_options() -> ResolverOpts {
        let mut opts = ResolverOpts::default();
        opts.ip_strategy = LookupIpStrategy::Ipv4Only;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.server_ordering_strategy = ServerOrderingStrategy::UserProvidedOrder;
        opts.num_concurrent_reqs = 2;
        opts.attempts = 1;
        opts.timeout = Duration::from_secs(1);
        opts
    }

    async fn parallel_answer_survives(
        code: ResponseCode,
        trust_negative_responses: bool,
        default_servers: bool,
    ) {
        let negative = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let healthy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addrs = [negative.local_addr().unwrap(), healthy.local_addr().unwrap()];
        let servers = addrs
            .iter()
            .map(|addr| {
                let mut config = NameServerConfig::udp(addr.ip());
                config.connections[0].port = addr.port();
                config.trust_negative_responses = trust_negative_responses;
                config
            })
            .collect();
        let resolver = if default_servers {
            HickoryResolver::from_servers(&addrs).unwrap()
        } else {
            HickoryResolver::with_config(
                ResolverConfig::from_parts(None, Vec::new(), servers),
                loopback_options(),
            )
            .unwrap()
        };
        let (negative_sent, sent) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut buf = [0; 4096];
            let (n, peer) = negative.recv_from(&mut buf).await.unwrap();
            let mut reply = Message::from_vec(&buf[..n]).unwrap().into_response();
            reply.metadata.response_code = code;
            reply.metadata.recursion_available = true;
            negative.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
            negative_sent.send(()).unwrap();
        });
        tasks.spawn(async move {
            let mut buf = [0; 4096];
            let (n, peer) = healthy.recv_from(&mut buf).await.unwrap();
            released.await.unwrap();
            let mut reply = Message::from_vec(&buf[..n]).unwrap().into_response();
            reply.metadata.recursion_available = true;
            let name = reply.queries[0].name.clone();
            reply.add_answer(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));
            healthy.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
        });
        let lookup = resolver.inner.ipv4_lookup("parallel.test.");
        tokio::pin!(lookup);
        tokio::select! {
            result = &mut lookup => panic!("lookup ended before negative response was observed: {result:?}"),
            result = sent => result.unwrap(),
        }
        // Keep the healthy response gated while the first packet is processed. This
        // detects early cancellation instead of relying on server scheduling order.
        tokio::select! {
            result = &mut lookup => panic!("negative {code} cancelled healthy parallel answer: {result:?}"),
            () = sleep(Duration::from_millis(50)) => {}
        }
        release.send(()).unwrap();
        let answer = timeout(Duration::from_secs(2), lookup).await.unwrap().unwrap();
        assert_eq!(answer.answers()[0].data, RData::A(A::new(192, 0, 2, 1)));
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn parallel_healthy_answer_survives_servfail() {
        parallel_answer_survives(ResponseCode::ServFail, true, false).await;
    }

    #[tokio::test]
    async fn parallel_healthy_answer_survives_refused() {
        parallel_answer_survives(ResponseCode::Refused, true, false).await;
    }

    #[tokio::test]
    async fn parallel_healthy_answer_survives_nodata() {
        for trust in [false, true] {
            parallel_answer_survives(ResponseCode::NoError, trust, false).await;
        }
    }

    #[tokio::test]
    async fn parallel_healthy_answer_survives_untrusted_nxdomain() {
        parallel_answer_survives(ResponseCode::NXDomain, false, false).await;
    }

    #[tokio::test]
    async fn default_servers_preserve_untrusted_negative_failover() {
        parallel_answer_survives(ResponseCode::NXDomain, false, true).await;
    }

    #[tokio::test]
    async fn explicit_trusted_authoritative_nxdomain_stops_failover() {
        let negative = DnsStub::start(|reply| {
            reply.metadata.response_code = ResponseCode::NXDomain;
            reply.metadata.authoritative = true;
            let name = reply.queries[0].name.clone();
            reply.authorities.push(Record::from_rdata(
                name.clone(),
                60,
                RData::SOA(SOA::new(name.clone(), name, 1, 60, 60, 60, 60)),
            ));
        })
        .await;
        let healthy_queries = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&healthy_queries);
        let healthy = DnsStub::start(move |reply| {
            seen.fetch_add(1, Ordering::SeqCst);
            let name = reply.queries[0].name.clone();
            reply.add_answer(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));
        })
        .await;
        let servers = [negative.addr, healthy.addr]
            .into_iter()
            .map(|addr| {
                let mut server = NameServerConfig::udp(addr.ip());
                server.connections[0].port = addr.port();
                server.trust_negative_responses = true;
                server
            })
            .collect();
        let mut opts = loopback_options();
        opts.num_concurrent_reqs = 1;
        let resolver =
            HickoryResolver::with_config(ResolverConfig::from_parts(None, Vec::new(), servers), opts)
                .unwrap();
        assert!(resolver.txt_lookup("trusted.test.").await.unwrap().is_empty());
        assert_eq!(healthy_queries.load(Ordering::SeqCst), 0);
    }

    async fn udp_failure_tcp_fallback(try_tcp_on_error: bool, udp_timeout: bool) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        // Silent bound UDP forces a timeout. Reusing its occupied address as
        // the client's bind address forces a deterministic I/O error instead.
        let _udp = UdpSocket::bind(addr).await.unwrap();
        let tcp_queries = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&tcp_queries);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let (mut stream, _) = tcp.accept().await.unwrap();
            seen.fetch_add(1, Ordering::SeqCst);
            let n = stream.read_u16().await.unwrap();
            let mut buf = vec![0; usize::from(n)];
            stream.read_exact(&mut buf).await.unwrap();
            let mut reply = Message::from_vec(&buf).unwrap().into_response();
            reply.metadata.recursion_available = true;
            let name = reply.queries[0].name.clone();
            reply.add_answer(Record::from_rdata(name, 60, RData::A(A::new(192, 0, 2, 1))));
            let bytes = reply.to_vec().unwrap();
            stream
                .write_u16(u16::try_from(bytes.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&bytes).await.unwrap();
        });
        let mut server = NameServerConfig::udp_and_tcp(addr.ip());
        for connection in &mut server.connections {
            connection.port = addr.port();
        }
        if !udp_timeout {
            server.connections[0].bind_addr = Some(addr);
        }
        let mut opts = loopback_options();
        opts.timeout = Duration::from_millis(100);
        opts.try_tcp_on_error = try_tcp_on_error;
        let resolver =
            HickoryResolver::with_config(ResolverConfig::from_parts(None, Vec::new(), vec![server]), opts)
                .unwrap();
        let result = timeout(Duration::from_secs(2), resolver.resolve("fallback.test."))
            .await
            .unwrap();
        if try_tcp_on_error {
            assert_eq!(result.unwrap(), [IpAddr::from([192, 0, 2, 1])]);
            assert_eq!(tcp_queries.load(Ordering::SeqCst), 1);
            tasks.join_next().await.unwrap().unwrap();
        } else {
            let Err(FetchError::Resolve { .. }) = result else {
                panic!("UDP failure unexpectedly resolved: {result:?}");
            };
            assert_eq!(tcp_queries.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn try_tcp_on_error_retries_udp_timeout() {
        udp_failure_tcp_fallback(true, true).await;
    }

    #[tokio::test]
    async fn try_tcp_on_error_retries_udp_io_failure() {
        udp_failure_tcp_fallback(true, false).await;
    }

    #[tokio::test]
    async fn disabled_tcp_fallback_preserves_udp_timeout() {
        udp_failure_tcp_fallback(false, true).await;
    }

    #[tokio::test]
    async fn disabled_tcp_fallback_preserves_udp_io_failure() {
        udp_failure_tcp_fallback(false, false).await;
    }

    #[tokio::test]
    async fn tcp_fallback_does_not_retry_valid_negative_dns_responses() {
        for code in [
            ResponseCode::NXDomain,
            ResponseCode::NoError,
            ResponseCode::ServFail,
            ResponseCode::Refused,
        ] {
            let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            tcp.set_nonblocking(true).unwrap();
            let addr = tcp.local_addr().unwrap();
            let udp = UdpSocket::bind(addr).await.unwrap();
            let mut tasks = JoinSet::new();
            tasks.spawn(async move {
                let mut buf = [0; 4096];
                while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
                    let mut reply = Message::from_vec(&buf[..n]).unwrap().into_response();
                    reply.metadata.recursion_available = true;
                    reply.metadata.response_code = code;
                    udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
                }
            });
            let mut server = NameServerConfig::udp_and_tcp(addr.ip());
            server.trust_negative_responses = true;
            for connection in &mut server.connections {
                connection.port = addr.port();
            }
            let mut opts = loopback_options();
            opts.try_tcp_on_error = true;
            opts.timeout = Duration::from_millis(100);
            let resolver = HickoryResolver::with_config(
                ResolverConfig::from_parts(None, Vec::new(), vec![server]),
                opts,
            )
            .unwrap();
            let result = timeout(Duration::from_secs(2), resolver.txt_lookup("negative.test."))
                .await
                .unwrap();
            match code {
                ResponseCode::NXDomain | ResponseCode::NoError => {
                    assert!(result.unwrap().is_empty());
                }
                _ => assert!(matches!(result, Err(FetchError::Resolve { .. }))),
            }
            assert!(
                matches!(
                    tcp.accept(),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
                ),
                "{code} must not open a TCP connection"
            );
            tasks.shutdown().await;
        }
    }

    #[tokio::test]
    async fn static_resolver_answers_and_rebinds() {
        let r = StaticResolver::new().with("A.test", [IpAddr::from([93, 184, 216, 34])]);
        assert_eq!(
            r.resolve("a.test").await.unwrap(),
            vec![IpAddr::from([93, 184, 216, 34])]
        );
        r.set("a.test", [IpAddr::from([10, 0, 0, 1])]);
        assert_eq!(
            r.resolve("a.test").await.unwrap(),
            vec![IpAddr::from([10, 0, 0, 1])]
        );
        assert!(matches!(
            r.resolve("b.test").await,
            Err(FetchError::Resolve { .. })
        ));
    }

    #[tokio::test]
    async fn literals_resolve_to_themselves() {
        let r = StaticResolver::new();
        assert_eq!(
            r.resolve("127.0.0.1").await.unwrap(),
            vec![IpAddr::from([127, 0, 0, 1])]
        );
        assert_eq!(
            r.resolve("[::1]").await.unwrap(),
            vec![IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1])]
        );
    }

    #[tokio::test]
    async fn hickory_resolves_literal_without_network() {
        let r = HickoryResolver::with_config(
            ResolverConfig::from_parts(None, Vec::new(), Vec::new()),
            ResolverOpts::default(),
        )
        .unwrap();
        assert_eq!(
            r.resolve("1.2.3.4").await.unwrap(),
            vec![IpAddr::from([1, 2, 3, 4])]
        );
        assert_eq!(
            r.resolve("[::1]").await.unwrap(),
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)]
        );
    }
}
