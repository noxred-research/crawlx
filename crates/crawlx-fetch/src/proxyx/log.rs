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
use super::{PoolPinAuthority, ProxyxError};
use crawlx_core::hash::Digest;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
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
    pin: Option<(String, IpAddr)>,
    pin_lost: bool,
    authority_error: Option<Arc<crawlx_core::StoreError>>,
    authority: Option<Arc<dyn PoolPinAuthority>>,
}

/// Bounded record of the tunnels and refusals of a binding.
#[derive(Default)]
pub struct TunnelLog {
    inner: Mutex<Inner>,
    pin_key: Option<[u8; 32]>,
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
    /// A log that refuses any change to the gateway session or measured exit.
    pub(crate) fn pinned(key: [u8; 32]) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            pin_key: Some(key),
        }
    }

    pub(crate) fn set_pin_authority(&self, authority: Arc<dyn PoolPinAuthority>) -> Result<(), ProxyxError> {
        let mut inner = self.inner.lock();
        if self.pin_key.is_none() || inner.authority.is_some() || inner.pin.is_some() || inner.pin_lost {
            return Err(ProxyxError::SessionUnavailable);
        }
        inner.authority = Some(authority);
        Ok(())
    }

    /// Check whether this generation can still open a tunnel.
    ///
    /// # Errors
    /// Returns pin lost after any identity loss; recovery requires explicit replacement.
    pub fn ensure_pin(&self) -> Result<(), ProxyxError> {
        let inner = self.inner.lock();
        if let Some(source) = &inner.authority_error {
            return Err(ProxyxError::PinAuthority(Arc::clone(source)));
        }
        if inner.pin_lost {
            return Err(ProxyxError::PinLost);
        }
        Ok(())
    }

    /// Record a `2xx` answer before allowing target request bytes through the tunnel.
    ///
    /// # Errors
    /// Strict logs fail permanently on missing metadata or a changed session/exit pair.
    /// Non-strict diagnostic logs ignore malformed metadata.
    pub(crate) async fn opened(
        &self,
        host: &str,
        port: u16,
        session: Option<&str>,
        exit_ip: Option<&str>,
    ) -> Result<(), ProxyxError> {
        let measured = session.zip(exit_ip).and_then(|(session, exit_ip)| {
            let session = session.trim();
            if session.len() != SESSION_LEN || !session.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            Some((
                session.to_ascii_lowercase(),
                exit_ip.trim().parse::<IpAddr>().ok()?,
            ))
        });
        let authority = {
            let mut inner = self.inner.lock();
            if self.pin_key.is_some()
                && (inner.pin_lost
                    || measured.is_none()
                    || inner
                        .pin
                        .as_ref()
                        .is_some_and(|pin| Some(pin) != measured.as_ref()))
            {
                inner.pin_lost = true;
                drop(inner);
                self.lose_pin(host, port);
                return Err(ProxyxError::PinLost);
            }
            if self.pin_key.is_some() && inner.pin.is_none() {
                inner.pin.clone_from(&measured);
            }
            inner.authority.clone()
        };
        let Some((session, exit_ip)) = measured else {
            return Ok(());
        };
        if let (Some(authority), Some(key)) = (authority, self.pin_key) {
            let mut observed = [0_u8; SESSION_LEN + 1 + 16];
            observed[..SESSION_LEN].copy_from_slice(session.as_bytes());
            let length = match exit_ip {
                IpAddr::V4(ip) => {
                    observed[SESSION_LEN] = 4;
                    observed[SESSION_LEN + 1..SESSION_LEN + 5].copy_from_slice(&ip.octets());
                    SESSION_LEN + 5
                }
                IpAddr::V6(ip) => {
                    observed[SESSION_LEN] = 6;
                    observed[SESSION_LEN + 1..].copy_from_slice(&ip.octets());
                    observed.len()
                }
            };
            let pin = Digest::keyed(&key, "crawlx/proxy-observed-pin/v1", &observed[..length]);
            if let Err(error) = authority.verify_or_bind(pin).await {
                {
                    let mut inner = self.inner.lock();
                    inner.pin_lost = true;
                    if let ProxyxError::PinAuthority(source) = &error {
                        inner.authority_error = Some(Arc::clone(source));
                    }
                }
                self.lose_pin(host, port);
                return Err(error);
            }
        }
        let mut inner = self.inner.lock();
        if inner.pin_lost {
            drop(inner);
            self.lose_pin(host, port);
            return Err(ProxyxError::PinLost);
        }
        if inner.tunnels.len() >= MAX_TUNNELS {
            inner.tunnels.pop_front();
        }
        inner.tunnels.push_back(PoolTunnel {
            session,
            exit_ip,
            host: host.to_owned(),
            port,
            opened_at: Instant::now(),
        });
        Ok(())
    }

    /// Make transport loss terminal without exposing network or credential error text.
    pub(crate) fn lose_pin(&self, host: &str, port: u16) {
        if self.pin_key.is_some() {
            self.refused(host, port, 502, PoolCause::SessionPinLost.code());
        }
    }

    /// Record a refusal.
    pub(crate) fn refused(&self, host: &str, port: u16, status: u16, reason: &str) -> Option<PoolCause> {
        let mut cause = PoolCause::from_code(reason.trim());
        if self.pin_key.is_some() && cause.is_none_or(PoolCause::is_retryable) {
            cause = Some(PoolCause::SessionPinLost);
        }
        Metrics::global()
            .counter(names::PROXYX_TUNNEL_REFUSALS)
            .inc_by(1, &[("reason", cause.map_or("unrecognized", PoolCause::code))]);
        let mut inner = self.inner.lock();
        if self.pin_key.is_some() {
            inner.pin_lost = true;
        }
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

    #[tokio::test]
    async fn a_tunnel_needs_a_valid_session_and_exit_ip() {
        let log = TunnelLog::default();
        log.opened("a.test", 443, Some(SESSION), Some("203.0.113.9"))
            .await
            .unwrap();
        log.opened("b.test", 443, Some("short"), Some("203.0.113.9"))
            .await
            .unwrap();
        log.opened("c.test", 443, Some(SESSION), Some("not-an-ip"))
            .await
            .unwrap();
        log.opened("d.test", 443, None, Some("203.0.113.9"))
            .await
            .unwrap();
        log.opened("e.test", 443, Some(SESSION), None).await.unwrap();
        log.opened("f.test", 443, Some(&"g".repeat(32)), Some("203.0.113.9"))
            .await
            .unwrap();
        let tunnels = log.tunnels();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].host, "a.test");
        assert_eq!(tunnels[0].exit_ip, "203.0.113.9".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn latest_is_per_target_and_most_recent_wins() {
        let log = TunnelLog::default();
        let other = "f".repeat(32);
        log.opened("a.test", 443, Some(SESSION), Some("203.0.113.9"))
            .await
            .unwrap();
        log.opened("a.test", 443, Some(&other), Some("2001:db8::1"))
            .await
            .unwrap();
        log.opened("a.test", 80, Some(SESSION), Some("203.0.113.10"))
            .await
            .unwrap();
        assert_eq!(log.latest("a.test", 443).unwrap().session, other);
        assert_eq!(
            log.latest("a.test", 80).unwrap().exit_ip.to_string(),
            "203.0.113.10"
        );
        assert!(log.latest("b.test", 443).is_none());
    }

    #[tokio::test]
    async fn the_log_is_bounded() {
        let log = TunnelLog::default();
        for i in 0..(MAX_TUNNELS + 50) {
            log.opened(&format!("h{i}.test"), 443, Some(SESSION), Some("203.0.113.9"))
                .await
                .unwrap();
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

    #[tokio::test]
    async fn generation_pin_spans_origins_and_survives_log_eviction() {
        let log = TunnelLog::pinned([7; 32]);
        for i in 0..=MAX_TUNNELS {
            log.opened(&format!("h{i}.test"), 443, Some(SESSION), Some("203.0.113.9"))
                .await
                .unwrap();
        }
        assert!(log.latest("h0.test", 443).is_none());
        assert!(matches!(
            log.opened("other.test", 80, Some(SESSION), Some("203.0.113.10"))
                .await,
            Err(ProxyxError::PinLost)
        ));
        assert!(matches!(log.ensure_pin(), Err(ProxyxError::PinLost)));
        assert!(matches!(
            log.opened("h0.test", 443, Some(SESSION), Some("203.0.113.9"))
                .await,
            Err(ProxyxError::PinLost)
        ));
        assert!(log.latest("other.test", 80).is_none());
    }

    #[tokio::test]
    async fn changed_session_missing_metadata_and_outage_require_replacement() {
        for (session, exit) in [
            (Some("ffffffffffffffffffffffffffffffff"), Some("203.0.113.9")),
            (None, Some("203.0.113.9")),
            (Some(SESSION), None),
        ] {
            let log = TunnelLog::pinned([7; 32]);
            log.opened("a.test", 443, Some(SESSION), Some("203.0.113.9"))
                .await
                .unwrap();
            assert!(matches!(
                log.opened("b.test", 443, session, exit).await,
                Err(ProxyxError::PinLost)
            ));
        }
        let log = TunnelLog::pinned([7; 32]);
        assert_eq!(
            log.refused("a.test", 443, 502, "provider_unavailable"),
            Some(PoolCause::SessionPinLost)
        );
        assert!(matches!(log.ensure_pin(), Err(ProxyxError::PinLost)));
        let replacement = TunnelLog::pinned([7; 32]);
        replacement
            .opened("a.test", 443, Some(SESSION), Some("203.0.113.10"))
            .await
            .unwrap();
    }

    #[derive(Default)]
    struct StoredPin(Mutex<Option<Digest>>);

    #[async_trait::async_trait]
    impl PoolPinAuthority for StoredPin {
        async fn verify_or_bind(&self, pin: Digest) -> Result<(), ProxyxError> {
            let mut stored = self.0.lock();
            if stored.is_some_and(|stored| stored != pin) {
                return Err(ProxyxError::PinLost);
            }
            *stored = Some(pin);
            Ok(())
        }
    }

    #[tokio::test]
    async fn durable_observation_survives_log_recreation_and_never_accepts_silent_exit_replacement() {
        let authority = Arc::new(StoredPin::default());
        let first = TunnelLog::pinned([7; 32]);
        first.set_pin_authority(authority.clone()).unwrap();
        first
            .opened("a.test", 443, Some(SESSION), Some("203.0.113.9"))
            .await
            .unwrap();
        assert!(first.set_pin_authority(authority.clone()).is_err());
        drop(first);
        let restarted = TunnelLog::pinned([7; 32]);
        restarted.set_pin_authority(authority.clone()).unwrap();
        restarted
            .opened("b.test", 80, Some(SESSION), Some("203.0.113.9"))
            .await
            .unwrap();
        drop(restarted);
        let changed = TunnelLog::pinned([7; 32]);
        changed.set_pin_authority(authority.clone()).unwrap();
        assert!(matches!(
            changed
                .opened("c.test", 443, Some(SESSION), Some("203.0.113.10"))
                .await,
            Err(ProxyxError::PinLost)
        ));
        assert!(changed.tunnels().is_empty());
        let other_org = TunnelLog::pinned([8; 32]);
        other_org.set_pin_authority(authority).unwrap();
        assert!(matches!(
            other_org
                .opened("a.test", 443, Some(SESSION), Some("203.0.113.9"))
                .await,
            Err(ProxyxError::PinLost)
        ));
    }

    struct UnavailablePinAuthority;

    #[async_trait::async_trait]
    impl PoolPinAuthority for UnavailablePinAuthority {
        async fn verify_or_bind(&self, _pin: Digest) -> Result<(), ProxyxError> {
            Err(ProxyxError::PinAuthority(Arc::new(
                crawlx_core::StoreError::Unavailable("private repository diagnostic".into()),
            )))
        }
    }

    #[tokio::test]
    async fn durable_authority_failure_preserves_source_and_never_opens_a_target_tunnel() {
        let log = TunnelLog::pinned([7; 32]);
        log.set_pin_authority(Arc::new(UnavailablePinAuthority)).unwrap();
        let error = log
            .opened("a.test", 443, Some(SESSION), Some("203.0.113.9"))
            .await
            .unwrap_err();
        assert!(matches!(error, ProxyxError::PinAuthority(_)));
        assert!(std::error::Error::source(&error).is_some());
        assert!(!error.to_string().contains("private repository diagnostic"));
        assert!(log.tunnels().is_empty());
        assert!(matches!(log.ensure_pin(), Err(ProxyxError::PinAuthority(_))));
    }

    #[derive(Default)]
    struct WaitingAuthority {
        entered: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    #[async_trait::async_trait]
    impl PoolPinAuthority for WaitingAuthority {
        async fn verify_or_bind(&self, _pin: Digest) -> Result<(), ProxyxError> {
            self.entered.notify_one();
            self.release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn concurrent_drift_never_reopens_a_tunnel_after_authority_verification_started() {
        let authority = Arc::new(WaitingAuthority::default());
        let log = Arc::new(TunnelLog::pinned([7; 32]));
        log.set_pin_authority(authority.clone()).unwrap();
        let opening = {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                log.opened("a.test", 443, Some(SESSION), Some("203.0.113.9"))
                    .await
            })
        };
        authority.entered.notified().await;
        assert!(matches!(
            log.opened("b.test", 443, Some(SESSION), Some("203.0.113.10"))
                .await,
            Err(ProxyxError::PinLost)
        ));
        authority.release.notify_one();
        assert!(matches!(opening.await.unwrap(), Err(ProxyxError::PinLost)));
        assert!(log.tunnels().is_empty());
    }
}
