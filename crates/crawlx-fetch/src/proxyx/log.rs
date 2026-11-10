//! What the gateway said about the tunnels of one binding.
//!
//! The pool session id and the exit IP are only delivered in the headers of the `CONNECT`
//! answer, which the HTTP client libraries do not expose. The upstream connector reads them
//! while it opens the tunnel and records them here, keyed by the target authority. The log is
//! bounded: old entries are evicted, so a long crawl holds a constant amount of memory.
//!
//! Correlation is by target: the most recent tunnel to `host:port` stands for the next
//! response from that authority. With a sticky identity (every tunnel of a crawl carries the
//! same `sid`) this is exact; with `rot-each` and concurrent requests to one origin a signal
//! may name a sibling tunnel's session, which the gateway still validates by session and
//! exit IP and ignores when they do not match.

use super::cause::PoolCause;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Tunnels remembered per binding.
const MAX_TUNNELS: usize = 256;
/// Refusals remembered per binding.
const MAX_REFUSALS: usize = 32;
/// The session id is 32 lowercase hexadecimal characters.
const SESSION_LEN: usize = 32;

/// One tunnel the gateway opened.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PoolTunnel {
    /// `X-ProxyX-Pool-Session` of the `CONNECT` answer.
    pub session: String,
    /// `X-ProxyX-Exit-IP` of the `CONNECT` answer.
    pub exit_ip: IpAddr,
    /// Target host, lower-cased, without brackets.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// When the answer arrived.
    pub opened_at: Instant,
}

/// One tunnel the gateway refused.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PoolRefusal {
    /// The status line code.
    pub status: u16,
    /// The reason phrase as sent.
    pub reason: String,
    /// The named cause; `None` for a phrase the gateway does not send.
    pub cause: Option<PoolCause>,
    /// Target host, lower-cased, without brackets.
    pub host: String,
    /// Target port.
    pub port: u16,
    /// When the answer arrived.
    pub at: Instant,
}

#[derive(Default)]
struct Inner {
    tunnels: VecDeque<PoolTunnel>,
    refusals: VecDeque<PoolRefusal>,
}

/// Bounded record of the tunnels and refusals of a binding.
#[derive(Default)]
pub struct TunnelLog {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for TunnelLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("TunnelLog")
            .field("tunnels", &inner.tunnels.len())
            .field("refusals", &inner.refusals.len())
            .finish()
    }
}

impl TunnelLog {
    /// Record a `2xx` answer. A reply without a valid session id and exit IP is not recorded:
    /// without both a block signal cannot be correlated.
    pub(crate) fn opened(&self, host: &str, port: u16, session: Option<&str>, exit_ip: Option<&str>) {
        let (Some(session), Some(exit_ip)) = (session, exit_ip) else {
            return;
        };
        let session = session.trim();
        if session.len() != SESSION_LEN || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
            return;
        }
        let Ok(exit_ip) = exit_ip.trim().parse::<IpAddr>() else {
            return;
        };
        let mut inner = self.inner.lock();
        if inner.tunnels.len() >= MAX_TUNNELS {
            inner.tunnels.pop_front();
        }
        inner.tunnels.push_back(PoolTunnel {
            session: session.to_ascii_lowercase(),
            exit_ip,
            host: host.to_owned(),
            port,
            opened_at: Instant::now(),
        });
    }

    /// Record a refusal.
    pub(crate) fn refused(&self, host: &str, port: u16, status: u16, reason: &str) -> Option<PoolCause> {
        let cause = PoolCause::from_code(reason.trim());
        Metrics::global()
            .counter(names::PROXYX_TUNNEL_REFUSALS)
            .inc_by(1, &[("reason", cause.map_or("unrecognized", PoolCause::code))]);
        let mut inner = self.inner.lock();
        if inner.refusals.len() >= MAX_REFUSALS {
            inner.refusals.pop_front();
        }
        inner.refusals.push_back(PoolRefusal {
            status,
            reason: reason.trim().chars().take(64).collect(),
            cause,
            host: host.to_owned(),
            port,
            at: Instant::now(),
        });
        cause
    }

    /// The most recent tunnel opened to `host:port`.
    #[must_use]
    pub fn latest(&self, host: &str, port: u16) -> Option<PoolTunnel> {
        self.inner
            .lock()
            .tunnels
            .iter()
            .rev()
            .find(|t| t.port == port && t.host == host)
            .cloned()
    }

    /// The most recent refusal of `host:port` no older than `within`.
    #[must_use]
    pub fn recent_refusal(&self, host: &str, port: u16, within: Duration) -> Option<PoolRefusal> {
        self.inner
            .lock()
            .refusals
            .iter()
            .rev()
            .find(|r| r.port == port && r.host == host && r.at.elapsed() <= within)
            .cloned()
    }

    /// Tunnels currently remembered, oldest first.
    #[must_use]
    pub fn tunnels(&self) -> Vec<PoolTunnel> {
        self.inner.lock().tunnels.iter().cloned().collect()
    }

    /// Refusals currently remembered, oldest first.
    #[must_use]
    pub fn refusals(&self) -> Vec<PoolRefusal> {
        self.inner.lock().refusals.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn a_tunnel_needs_a_valid_session_and_exit_ip() {
        let log = TunnelLog::default();
        log.opened("a.test", 443, Some(SESSION), Some("203.0.113.9"));
        log.opened("b.test", 443, Some("short"), Some("203.0.113.9"));
        log.opened("c.test", 443, Some(SESSION), Some("not-an-ip"));
        log.opened("d.test", 443, None, Some("203.0.113.9"));
        log.opened("e.test", 443, Some(SESSION), None);
        log.opened("f.test", 443, Some(&"g".repeat(32)), Some("203.0.113.9"));
        let tunnels = log.tunnels();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].host, "a.test");
        assert_eq!(tunnels[0].exit_ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn latest_is_per_target_and_most_recent_wins() {
        let log = TunnelLog::default();
        let other = "f".repeat(32);
        log.opened("a.test", 443, Some(SESSION), Some("203.0.113.9"));
        log.opened("a.test", 443, Some(&other), Some("2001:db8::1"));
        log.opened("a.test", 80, Some(SESSION), Some("203.0.113.10"));
        assert_eq!(log.latest("a.test", 443).unwrap().session, other);
        assert_eq!(
            log.latest("a.test", 80).unwrap().exit_ip.to_string(),
            "203.0.113.10"
        );
        assert!(log.latest("b.test", 443).is_none());
    }

    #[test]
    fn the_log_is_bounded() {
        let log = TunnelLog::default();
        for i in 0..(MAX_TUNNELS + 50) {
            log.opened(&format!("h{i}.test"), 443, Some(SESSION), Some("203.0.113.9"));
        }
        assert_eq!(log.tunnels().len(), MAX_TUNNELS);
        assert!(log.latest("h0.test", 443).is_none());
        assert!(log.latest(&format!("h{}.test", MAX_TUNNELS + 49), 443).is_some());
        for _ in 0..(MAX_REFUSALS + 5) {
            log.refused("a.test", 443, 503, "cache_empty");
        }
        assert_eq!(log.refusals().len(), MAX_REFUSALS);
    }

    #[test]
    fn refusals_carry_the_cause_and_expire() {
        let log = TunnelLog::default();
        assert_eq!(
            log.refused("a.test", 443, 403, "option_denied"),
            Some(PoolCause::OptionDenied)
        );
        assert_eq!(log.refused("a.test", 80, 502, "who knows"), None);
        let r = log.recent_refusal("a.test", 443, Duration::from_secs(5)).unwrap();
        assert_eq!((r.status, r.cause), (403, Some(PoolCause::OptionDenied)));
        assert!(log
            .recent_refusal("b.test", 443, Duration::from_secs(5))
            .is_none());
        assert_eq!(
            log.recent_refusal("a.test", 80, Duration::from_secs(5))
                .unwrap()
                .cause,
            None
        );
    }
}
