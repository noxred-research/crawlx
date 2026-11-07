//! Narrowing-only live fixture egress scope. This module creates no model authority and opens no sockets.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use url::Url;

/// Runtime-owned listener lifetime. A scope retains this lease to prevent port recycling.
/// Implementations live in runtime crates; policy only consults their immutable identity and liveness.
pub trait FixtureEvaluationLease: Send + Sync + std::fmt::Debug {
    /// Actual retained listener address, not a caller-visible URL string.
    fn address(&self) -> SocketAddr;
    /// Whether the fixture server still owns its live capability.
    fn is_live(&self) -> bool;
    /// Revoke scope when its owner or HTTP task stops. Revocation never grants authority.
    fn revoke(&self);
}

#[derive(Debug)]
struct Scope {
    lease: Arc<dyn FixtureEvaluationLease>,
    origin: Url,
    address: SocketAddr,
}

/// Exact-listener restriction for every resource. Possessing this scope only narrows egress.
#[derive(Clone, Debug)]
pub struct FixtureEvaluationScope {
    inner: Arc<Scope>,
}

impl PartialEq for FixtureEvaluationScope {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}
impl Eq for FixtureEvaluationScope {}

impl FixtureEvaluationScope {
    /// Create a restriction from an existing runtime lease. No socket is opened.
    /// Returns `None` unless the lease names literal IPv4 localhost and a nonzero port.
    #[must_use]
    pub fn new(lease: Arc<dyn FixtureEvaluationLease>) -> Option<Self> {
        let address = lease.address();
        if address.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) || address.port() == 0 {
            return None;
        }
        let origin = Url::parse(&format!("http://{address}/")).ok()?;
        Some(Self {
            inner: Arc::new(Scope {
                lease,
                origin,
                address,
            }),
        })
    }
    /// Whether the original controlled server remains live.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.inner.lease.is_live()
    }
    /// Revoke authority when the server stops or its task exits unexpectedly.
    pub fn revoke(&self) {
        self.inner.lease.revoke();
    }
    /// Immutable actual HTTP origin of the retained listener.
    #[must_use]
    pub fn origin(&self) -> &Url {
        &self.inner.origin
    }
    /// Check redirects, frames, XHR and every other resource URL.
    #[must_use]
    pub fn permits_url(&self, url: &Url) -> bool {
        self.is_live()
            && url.origin() == self.inner.origin.origin()
            && url.username().is_empty()
            && url.password().is_none()
    }
    /// A custom resolver cannot widen the bound socket.
    #[must_use]
    pub fn permits_ip(&self, ip: IpAddr) -> bool {
        self.is_live() && ip == self.inner.address.ip()
    }
    /// Another local service is not the controlled fixture.
    #[must_use]
    pub fn permits_port(&self, port: u16) -> bool {
        self.is_live() && port == self.inner.address.port()
    }
}
