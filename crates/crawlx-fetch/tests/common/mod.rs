//! Shared helpers for the wiremock-based integration tests.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_fetch::{FetchConfig, Fetcher, GovernorConfig, RetryPolicy, StaticResolver};
use crawlx_policy::egress::EgressPolicy;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use url::Url;
use wiremock::MockServer;

pub const LOOPBACK: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

/// Fast config: tiny spacing and backoff so retry tests finish quickly.
pub fn fast_config() -> FetchConfig {
    FetchConfig {
        contact: "ops@example.test".to_owned(),
        governor: GovernorConfig {
            base_delay: Duration::from_millis(5),
            ..GovernorConfig::default()
        },
        retry: RetryPolicy {
            max_retries: 3,
            base_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(200),
            max_retry_after: Duration::from_secs(5),
        },
        request_timeout: Duration::from_secs(10),
        ..FetchConfig::default()
    }
}

/// Policy that lets only `127.0.0.1` through the private-range deny and
/// accepts the mock server's port.
pub fn loopback_only_policy(server: &MockServer) -> EgressPolicy {
    let mut p = EgressPolicy::new(false);
    p.extra_allow.push("127.0.0.1/32".parse().unwrap());
    p.extra_ports.push(server.address().port());
    p
}

pub fn allow_private_policy(server: &MockServer) -> EgressPolicy {
    let mut p = EgressPolicy::new(true);
    p.extra_ports.push(server.address().port());
    p
}

pub fn fetcher(cfg: FetchConfig, policy: EgressPolicy, resolver: Arc<StaticResolver>) -> Fetcher {
    Fetcher::new(cfg, Arc::new(policy), resolver).unwrap()
}

pub fn url(host: &str, server: &MockServer, path: &str) -> Url {
    Url::parse(&format!("http://{host}:{}{path}", server.address().port())).unwrap()
}
