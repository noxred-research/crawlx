//! Refusal causes of the ProxyX pool gateway.
//!
//! The gateway answers a refused `CONNECT` with `HTTP/1.1 <status> <cause_code>`; the reason
//! phrase is the stable cause code. A refusal is never repaired by the gateway, so the client
//! decides from the cause whether another attempt can help.

/// What a caller may do after a refusal.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Retryability {
    /// The request or the credentials are wrong, or an operator or budget stopped the org.
    /// Another attempt with the same inputs fails the same way.
    Terminal,
    /// The pool is saturated or short of units; try again after a delay.
    Backoff,
    /// A transient provider or lease failure; an immediate retry is reasonable.
    Retry,
}

/// Why the gateway refused to open a tunnel.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum PoolCause {
    /// `407 auth_required`: the org key is missing or unknown.
    AuthRequired,
    /// `407 source_limited`: too many failed authentications from this source address.
    SourceLimited,
    /// `403 org_disabled`: the org key is disabled.
    OrgDisabled,
    /// `403 org_blocked`: an operator block stops this org.
    OrgBlocked,
    /// `403 option_denied`: a username option is malformed or widens the policy.
    OptionDenied,
    /// `403 port_not_allowed`: the provider does not allow the target port.
    PortNotAllowed,
    /// `403 destination_denied`: the target is a private, loopback, link-local, metadata or
    /// cluster address.
    DestinationDenied,
    /// `503 org_capacity`: the org reached its tunnel cap.
    OrgCapacity,
    /// `503 org_budget`: the org used its daily traffic budget.
    OrgBudget,
    /// `503 cache_empty`: no unit could be leased.
    CacheEmpty,
    /// `503 no_healthy_ip`: a static partition has no healthy IP.
    NoHealthyIp,
    /// `503 cache_unavailable`: the gateway's lease store is down.
    CacheUnavailable,
    /// `504 lease_timeout`: waiting for a unit ran out.
    LeaseTimeout,
    /// `504 provider_timeout`: the provider did not answer in time.
    ProviderTimeout,
    /// `502 provider_unavailable`: the provider refused the connection or is in an open breaker.
    ProviderUnavailable,
    /// `502 provider_auth`: the provider rejected the rendered credential.
    ProviderAuth,
    /// `502 upstream_error`: the provider answered the `CONNECT` with an unexpected status.
    UpstreamError,
    /// Local terminal failure: the gateway lost this generation's pinned session or exit.
    SessionPinLost,
}

impl PoolCause {
    /// Every cause, for tests and metric pre-registration.
    pub const ALL: [Self; 18] = [
        Self::AuthRequired,
        Self::SourceLimited,
        Self::OrgDisabled,
        Self::OrgBlocked,
        Self::OptionDenied,
        Self::PortNotAllowed,
        Self::DestinationDenied,
        Self::OrgCapacity,
        Self::OrgBudget,
        Self::CacheEmpty,
        Self::NoHealthyIp,
        Self::CacheUnavailable,
        Self::LeaseTimeout,
        Self::ProviderTimeout,
        Self::ProviderUnavailable,
        Self::ProviderAuth,
        Self::UpstreamError,
        Self::SessionPinLost,
    ];

    /// The cause named by a reason phrase; `None` for a phrase the gateway does not send.
    #[must_use]
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|cause| cause.code() == code)
    }

    /// The reason phrase the gateway sends, also the metric label.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::AuthRequired => "auth_required",
            Self::SourceLimited => "source_limited",
            Self::OrgDisabled => "org_disabled",
            Self::OrgBlocked => "org_blocked",
            Self::OptionDenied => "option_denied",
            Self::PortNotAllowed => "port_not_allowed",
            Self::DestinationDenied => "destination_denied",
            Self::OrgCapacity => "org_capacity",
            Self::OrgBudget => "org_budget",
            Self::CacheEmpty => "cache_empty",
            Self::NoHealthyIp => "no_healthy_ip",
            Self::CacheUnavailable => "cache_unavailable",
            Self::LeaseTimeout => "lease_timeout",
            Self::ProviderTimeout => "provider_timeout",
            Self::ProviderUnavailable => "provider_unavailable",
            Self::ProviderAuth => "provider_auth",
            Self::UpstreamError => "upstream_error",
            Self::SessionPinLost => "session_pin_lost",
        }
    }

    /// The status line code the gateway pairs with this cause.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::AuthRequired | Self::SourceLimited => 407,
            Self::OrgDisabled
            | Self::OrgBlocked
            | Self::OptionDenied
            | Self::PortNotAllowed
            | Self::DestinationDenied => 403,
            Self::OrgCapacity
            | Self::OrgBudget
            | Self::CacheEmpty
            | Self::NoHealthyIp
            | Self::CacheUnavailable => 503,
            Self::LeaseTimeout | Self::ProviderTimeout => 504,
            Self::ProviderUnavailable | Self::ProviderAuth | Self::UpstreamError | Self::SessionPinLost => {
                502
            }
        }
    }

    /// Whether and how fast another attempt can succeed.
    ///
    /// Gateway guidance applies only to an unbound diagnostic route. A strict generation
    /// converts transient refusal into [`Self::SessionPinLost`], because choosing a fresh exit
    /// requires explicit session replacement.
    #[must_use]
    pub const fn retryability(self) -> Retryability {
        match self {
            Self::AuthRequired
            | Self::OrgDisabled
            | Self::OrgBlocked
            | Self::OptionDenied
            | Self::PortNotAllowed
            | Self::DestinationDenied
            | Self::ProviderAuth
            | Self::OrgBudget
            | Self::SessionPinLost => Retryability::Terminal,
            Self::SourceLimited
            | Self::OrgCapacity
            | Self::CacheEmpty
            | Self::NoHealthyIp
            | Self::CacheUnavailable => Retryability::Backoff,
            Self::LeaseTimeout | Self::ProviderTimeout | Self::ProviderUnavailable | Self::UpstreamError => {
                Retryability::Retry
            }
        }
    }

    /// Can another attempt help at all?
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        !matches!(self.retryability(), Retryability::Terminal)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn every_code_round_trips_and_statuses_match_the_gateway_table() {
        let table = [
            ("auth_required", 407),
            ("source_limited", 407),
            ("org_disabled", 403),
            ("org_blocked", 403),
            ("option_denied", 403),
            ("port_not_allowed", 403),
            ("destination_denied", 403),
            ("org_capacity", 503),
            ("org_budget", 503),
            ("cache_empty", 503),
            ("no_healthy_ip", 503),
            ("cache_unavailable", 503),
            ("lease_timeout", 504),
            ("provider_timeout", 504),
            ("provider_unavailable", 502),
            ("provider_auth", 502),
            ("upstream_error", 502),
            ("session_pin_lost", 502),
        ];
        assert_eq!(table.len(), PoolCause::ALL.len());
        for (code, status) in table {
            let cause = PoolCause::from_code(code).unwrap();
            assert_eq!(cause.code(), code);
            assert_eq!(cause.status(), status, "{code}");
        }
        assert_eq!(PoolCause::from_code("Connection established"), None);
        assert_eq!(PoolCause::from_code(""), None);
        assert_eq!(PoolCause::from_code("AUTH_REQUIRED"), None);
    }

    #[test]
    fn retry_guidance_separates_terminal_backoff_and_retry() {
        use Retryability::{Backoff, Retry, Terminal};
        let expected = [
            (PoolCause::AuthRequired, Terminal),
            (PoolCause::OrgDisabled, Terminal),
            (PoolCause::OrgBlocked, Terminal),
            (PoolCause::OptionDenied, Terminal),
            (PoolCause::PortNotAllowed, Terminal),
            (PoolCause::DestinationDenied, Terminal),
            (PoolCause::OrgBudget, Terminal),
            (PoolCause::ProviderAuth, Terminal),
            (PoolCause::SessionPinLost, Terminal),
            (PoolCause::SourceLimited, Backoff),
            (PoolCause::OrgCapacity, Backoff),
            (PoolCause::CacheEmpty, Backoff),
            (PoolCause::NoHealthyIp, Backoff),
            (PoolCause::CacheUnavailable, Backoff),
            (PoolCause::LeaseTimeout, Retry),
            (PoolCause::ProviderTimeout, Retry),
            (PoolCause::ProviderUnavailable, Retry),
            (PoolCause::UpstreamError, Retry),
        ];
        assert_eq!(expected.len(), PoolCause::ALL.len());
        for (cause, retryability) in expected {
            assert_eq!(cause.retryability(), retryability, "{}", cause.code());
            assert_eq!(cause.is_retryable(), retryability != Terminal);
        }
    }
}
