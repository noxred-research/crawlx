//! WHOIS queries use explicit operator registry endpoints and bounded allowlisted referrals.

use super::{ProtocolError, ProtocolResource};
use crate::{
    governor::{Origin, OriginGovernor},
    resolver::Resolver,
};
use bytes::Bytes;
use crawlx_policy::egress::EgressPolicy;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Approved registry host and finite port; endpoints never come from page content.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WhoisEndpoint {
    /// DNS name subject to checked resolution.
    pub host: String,
    /// Explicit WHOIS service port.
    pub port: u16,
}
/// Operator registry. A referral can only name another key already in this map.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WhoisRegistry {
    /// Registry authority keys and approved sockets.
    pub endpoints: BTreeMap<String, WhoisEndpoint>,
    /// At most eight referral transitions.
    pub max_referrals: u8,
}
impl WhoisRegistry {
    /// Acquire bounded text using the shared origin governor and checked DNS/peer boundary.
    ///
    /// # Errors
    /// Refuses unknown registries, control characters, private DNS, unknown referrals, loops and exhausted bounds.
    #[allow(clippy::too_many_arguments)]
    pub async fn acquire(
        &self,
        url: &Url,
        max_bytes: u32,
        deadline: Duration,
        cancel: &CancellationToken,
        policy: &EgressPolicy,
        resolver: &dyn Resolver,
        governor: &Arc<OriginGovernor>,
    ) -> Result<ProtocolResource, ProtocolError> {
        if url.scheme() != "whois"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
            || self.max_referrals > 8
            || max_bytes == 0
            || max_bytes > 67_108_864
            || deadline.is_zero()
            || deadline > Duration::from_secs(90)
        {
            return Err(ProtocolError::Refused("WHOIS request bounds"));
        }
        let query = percent_encoding::percent_decode_str(url.path().trim_start_matches('/'))
            .decode_utf8()
            .map_err(|_| ProtocolError::Refused("WHOIS query encoding"))?;
        if query.is_empty()
            || query.len() > 253
            || !query
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'))
        {
            return Err(ProtocolError::Refused("WHOIS query"));
        }
        let run = async {
            if let Some(scope) = &policy.record_scope {
                scope
                    .check_request(url)
                    .map_err(|_| ProtocolError::Refused("WHOIS authorization"))?;
            }
            let mut registry = url
                .host_str()
                .ok_or(ProtocolError::Refused("WHOIS registry required"))?
                .to_owned();
            let mut visited = BTreeSet::new();
            let mut body = Vec::new();
            for hop in 0..=self.max_referrals {
                if !visited.insert(registry.clone()) {
                    return Err(ProtocolError::Refused("WHOIS referral loop"));
                }
                let endpoint = self
                    .endpoints
                    .get(&registry)
                    .ok_or(ProtocolError::CapabilityUnavailable(
                        "WHOIS registry not approved",
                    ))?;
                policy
                    .check_host(&endpoint.host)
                    .map_err(|_| ProtocolError::Refused("WHOIS registry host"))?;
                policy
                    .check_port(endpoint.port)
                    .map_err(|_| ProtocolError::Refused("WHOIS registry port"))?;
                let addresses = resolver.resolve(&endpoint.host).await?;
                if addresses.is_empty() {
                    return Err(ProtocolError::Refused("WHOIS empty DNS"));
                }
                policy
                    .check_all(&endpoint.host, &addresses)
                    .map_err(|_| ProtocolError::Refused("WHOIS registry DNS"))?;
                let authority = if endpoint.port == 43 {
                    format!("whois://{}", endpoint.host)
                } else {
                    format!("whois://{}:{}", endpoint.host, endpoint.port)
                };
                let origin = Origin::new(&authority);
                let _permit = governor
                    .acquire(&origin)
                    .await
                    .map_err(|_| ProtocolError::Refused("origin admission unavailable"))?;
                let socket = SocketAddr::new(addresses[0], endpoint.port);
                let mut stream = tokio::net::TcpStream::connect(socket).await?;
                if stream.peer_addr()? != socket {
                    return Err(ProtocolError::Refused("WHOIS peer"));
                }
                stream.write_all(query.as_bytes()).await?;
                stream.write_all(b"\r\n").await?;
                let start = body.len();
                let mut chunk = [0_u8; 4096];
                loop {
                    let n = stream.read(&mut chunk).await?;
                    if n == 0 {
                        break;
                    }
                    if body.len().saturating_add(n)
                        > usize::try_from(max_bytes).map_err(|_| ProtocolError::Limit)?
                    {
                        return Err(ProtocolError::Limit);
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                let text = std::str::from_utf8(&body[start..])
                    .map_err(|_| ProtocolError::Refused("WHOIS response encoding"))?;
                let referral = text.lines().find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    (key.eq_ignore_ascii_case("refer") || key.eq_ignore_ascii_case("whois server"))
                        .then(|| value.trim().to_ascii_lowercase())
                });
                match referral {
                    None => {
                        return Ok(ProtocolResource {
                            final_url: Some(url.clone()),
                            target_status: None,
                            gateway_status: None,
                            media_type: Some("text/plain".to_owned()),
                            decoded_bytes: body.len(),
                            body: Bytes::from(body),
                            children: Vec::new(),
                            build_digest: "native-whois-v1".to_owned(),
                            network_requests: u32::from(hop) + 1,
                            redirects: Vec::new(),
                            denied_children: Vec::new(),
                        })
                    }
                    Some(next) if hop < self.max_referrals && self.endpoints.contains_key(&next) => {
                        registry = next
                    }
                    Some(_) => {
                        return Err(ProtocolError::Refused(
                            "WHOIS referral not approved or limit exceeded",
                        ))
                    }
                }
            }
            Err(ProtocolError::Limit)
        };
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(ProtocolError::Cancelled),
            result = tokio::time::timeout(deadline, run) => result.map_err(|_| ProtocolError::Deadline)?,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::{governor::GovernorConfig, resolver::StaticResolver};

    async fn fixture(response: &'static [u8]) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut query = Vec::new();
            loop {
                let byte = socket.read_u8().await.unwrap();
                query.push(byte);
                if byte == b'\n' {
                    break;
                }
                assert!(query.len() < 256);
            }
            assert_eq!(query, b"example.test\r\n");
            socket.write_all(response).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        (port, task)
    }
    #[tokio::test]
    async fn local_whois_keeps_non_http_status_absent() {
        let (port, task) = fixture(b"Domain: example.test\r\n").await;
        let registry = WhoisRegistry {
            endpoints: BTreeMap::from([(
                "registry.test".into(),
                WhoisEndpoint {
                    host: "registry.test".into(),
                    port,
                },
            )]),
            max_referrals: 1,
        };
        let resolver = StaticResolver::new().with("registry.test", ["127.0.0.1".parse().unwrap()]);
        let mut policy = EgressPolicy::new(true);
        policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
        policy.extra_ports.push(port);
        let result = registry
            .acquire(
                &Url::parse("whois://registry.test/example.test").unwrap(),
                4096,
                Duration::from_secs(1),
                &CancellationToken::new(),
                &policy,
                &resolver,
                &Arc::new(OriginGovernor::new(GovernorConfig::default())),
            )
            .await
            .unwrap();
        assert_eq!(result.target_status, None);
        assert_eq!(result.network_requests, 1);
        task.await.unwrap();
    }
    #[tokio::test]
    async fn approved_referral_private_dns_fails_before_referral_socket() {
        let (port, task) = fixture(b"refer: private.test\r\n").await;
        let registry = WhoisRegistry {
            endpoints: BTreeMap::from([
                (
                    "registry.test".into(),
                    WhoisEndpoint {
                        host: "registry.test".into(),
                        port,
                    },
                ),
                (
                    "private.test".into(),
                    WhoisEndpoint {
                        host: "private.test".into(),
                        port: 43,
                    },
                ),
            ]),
            max_referrals: 1,
        };
        let resolver = StaticResolver::new()
            .with("registry.test", ["127.0.0.1".parse().unwrap()])
            .with("private.test", ["169.254.169.254".parse().unwrap()]);
        let mut policy = EgressPolicy::new(true);
        policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
        policy.extra_ports.extend([port, 43]);
        let result = registry
            .acquire(
                &Url::parse("whois://registry.test/example.test").unwrap(),
                4096,
                Duration::from_secs(1),
                &CancellationToken::new(),
                &policy,
                &resolver,
                &Arc::new(OriginGovernor::new(GovernorConfig::default())),
            )
            .await;
        assert!(matches!(
            result,
            Err(ProtocolError::Refused("WHOIS registry DNS"))
        ));
        task.await.unwrap();
    }
    #[tokio::test]
    async fn referrals_and_response_bytes_never_exceed_registry_authority() {
        for (response, max_referrals, max_bytes, expected) in [
            (
                b"refer: registry.test\r\n".as_slice(),
                1,
                4096,
                "WHOIS referral loop",
            ),
            (
                b"refer: registry.test\r\n".as_slice(),
                0,
                4096,
                "WHOIS referral not approved or limit exceeded",
            ),
            (
                b"refer: unknown.test\r\n".as_slice(),
                1,
                4096,
                "WHOIS referral not approved or limit exceeded",
            ),
            (b"Domain: example.test\r\n".as_slice(), 1, 4, "limit"),
        ] {
            let (port, task) = fixture(response).await;
            let registry = WhoisRegistry {
                endpoints: BTreeMap::from([(
                    "registry.test".to_owned(),
                    WhoisEndpoint {
                        host: "registry.test".to_owned(),
                        port,
                    },
                )]),
                max_referrals,
            };
            let mut policy = EgressPolicy::new(true);
            policy.extra_allow.push("127.0.0.1/32".parse().unwrap());
            policy.extra_ports.push(port);
            let result = registry
                .acquire(
                    &Url::parse("whois://registry.test/example.test").unwrap(),
                    max_bytes,
                    Duration::from_secs(1),
                    &CancellationToken::new(),
                    &policy,
                    &StaticResolver::new().with("registry.test", ["127.0.0.1".parse().unwrap()]),
                    &Arc::new(OriginGovernor::new(GovernorConfig::default())),
                )
                .await;
            if expected == "limit" {
                assert!(matches!(result, Err(ProtocolError::Limit)));
            } else {
                assert!(matches!(result, Err(ProtocolError::Refused(reason)) if reason == expected));
            }
            task.await.unwrap();
        }
    }
}
