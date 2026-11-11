//! Typed errors of the fetch plane.

use crate::codec::BodyLimitKind;
use crate::preflight::PreflightRefusal;
use crawlx_policy::egress::EgressDenied;
use thiserror::Error;

/// Source error from the selected HTTP/TLS transport.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpError {
    /// Default rustls-backed reqwest transport.
    #[error(transparent)]
    Rustls(#[from] reqwest::Error),
    /// Opt-in synthetic ClientHello transport.
    #[error(transparent)]
    Randomized(#[from] wreq::Error),
}

/// Everything `Fetcher::fetch`, the resolvers and the egress proxy can fail with.
#[derive(Debug, Error)]
pub enum FetchError {
    /// The shared origin admission store failed before any request was sent.
    #[error("origin admission failed: {0}")]
    OriginAdmission(#[from] crawlx_core::StoreError),
    /// Parent acquisition allowance was exhausted before dispatch.
    #[error("acquisition allowance exhausted")]
    AcquisitionAllowance,
    /// Parent monotonic acquisition deadline elapsed.
    #[error("acquisition deadline elapsed")]
    AcquisitionDeadline,
    /// Parent cancelled the running acquisition.
    #[error("acquisition cancelled")]
    AcquisitionCancelled,
    /// Required registered backend or policy is unavailable.
    #[error("acquisition capability unavailable")]
    AcquisitionUnavailable,
    /// A selected meta continuation failed; original success is never substituted.
    #[error("meta refresh continuation failed ({})", .source.code())]
    MetaRefresh {
        /// Bounded observed initial and target facts.
        evidence: Box<crawlx_core::acquisition::MetaRefreshEvidenceV1>,
        /// Typed admission, budget, target-status or transport cause.
        #[source]
        source: Box<FetchError>,
    },
    /// A selected continuation returned a non-successful response.
    #[error("meta refresh target returned status {status}")]
    MetaRefreshTarget {
        /// Observed target status.
        status: u16,
    },
    /// The egress policy refused the URL, the host name or a resolved address.
    /// Never retried.
    #[error("egress denied: {0}")]
    EgressDenied(#[from] EgressDenied),
    /// The request URL cannot be fetched by this plane (scheme, userinfo, host).
    #[error("invalid url {url}: {reason}")]
    InvalidUrl {
        /// The offending URL as given.
        url: String,
        /// Which URL rule was violated.
        reason: &'static str,
    },
    /// Only `GET` and `HEAD` are supported by the fetch plane.
    #[error("unsupported method {0}")]
    UnsupportedMethod(String),
    /// Name resolution failed or returned no address.
    #[error("dns resolution failed for {host}: {reason}")]
    Resolve {
        /// Host name that failed to resolve.
        host: String,
        /// Resolver failure detail.
        reason: String,
    },
    /// A `3xx` answer carried no usable `Location`.
    #[error("invalid redirect from {from}: {reason}")]
    InvalidRedirect {
        /// URL that answered with the redirect.
        from: String,
        /// Why the `Location` could not be followed.
        reason: String,
    },
    /// More redirect hops than allowed.
    #[error("too many redirects (limit {limit})")]
    TooManyRedirects {
        /// The hop limit that was exceeded.
        limit: usize,
    },
    /// The connection was established to an address outside the checked set.
    #[error("connected peer {peer} is not in the pinned address set for {host}")]
    PeerNotPinned {
        /// Host the request was made for.
        host: String,
        /// Address the connection actually reached.
        peer: std::net::IpAddr,
    },
    /// The request timed out (connect, headers or body).
    #[error("request timed out: {}", error_chain(.0))]
    Timeout(#[source] HttpError),
    /// Any other transport failure (connect refused, TLS, protocol, body read).
    #[error("transport error: {}", error_chain(.0))]
    Transport(#[source] HttpError),
    /// The HTTP client could not be constructed.
    #[error("http client could not be built: {}", error_chain(.0))]
    ClientBuild(#[source] HttpError),
    /// A configured request header or cookie (`fetch.extraHeaders`, `fetch.cookies`) is not
    /// a valid HTTP header; carries the header name, never the value.
    #[error("request control {name} is not a valid HTTP header")]
    InvalidHeader {
        /// Name of the offending header or cookie.
        name: String,
    },
    /// The ProxyX pool route or selection is unusable. Never retried; carries no credential.
    #[error("proxy pool configuration: {0}")]
    Pool(#[from] crate::proxyx::ProxyxError),
    /// The ProxyX pool gateway refused to open the tunnel. [`PoolCause::is_retryable`] says
    /// whether another attempt can help.
    ///
    /// [`PoolCause::is_retryable`]: crate::proxyx::PoolCause::is_retryable
    #[error("proxy pool refused the tunnel: {status} {}", .cause.map_or("unrecognized", crate::proxyx::PoolCause::code))]
    PoolRefused {
        /// The named cause; `None` for a reason phrase the gateway does not send.
        cause: Option<crate::proxyx::PoolCause>,
        /// The status line code.
        status: u16,
    },
    /// Local socket or listener failure (egress proxy).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// The response body is not a valid stream of its content coding, or stacks more codings
    /// than are decoded. Never retried: the same bytes would fail again.
    #[error("response body is not valid {encoding}: {reason}")]
    BodyDecode {
        /// Content coding (`gzip`, `deflate`, `br`, `stacked`).
        encoding: &'static str,
        /// Decoder message.
        reason: String,
    },
    /// A body limit refused the response: an oversize declared length under
    /// [`crate::OversizePolicy::Reject`], or a decompression bomb (expansion ratio).
    #[error("response body exceeds the {} limit of {limit}", .kind.as_str())]
    BodyLimit {
        /// Which limit.
        kind: BodyLimitKind,
        /// Its value (bytes, or decoded bytes per wire byte for the ratio).
        limit: u64,
    },
    /// The request's declaration denies this HTTP status.
    #[error("response status {status} is denied by the request declaration")]
    StatusDenied {
        /// The refused status.
        status: u16,
    },
    /// The `HEAD` preflight refused the `GET`; no `GET` was sent.
    #[error("head preflight refused the request: {refusal}")]
    PreflightRefused {
        /// Why.
        refusal: PreflightRefusal,
    },
    /// A request declaration (MIME, encoding, status sets) is malformed; no request was sent.
    #[error("request declaration field {field} is invalid")]
    InvalidDeclaration {
        /// The offending field.
        field: &'static str,
    },
}

impl FetchError {
    /// Stable machine-readable code for logs and metrics.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OriginAdmission(_) => "origin_admission",
            Self::AcquisitionAllowance => "acquisition_allowance",
            Self::AcquisitionDeadline => "acquisition_deadline",
            Self::AcquisitionCancelled => "acquisition_cancelled",
            Self::AcquisitionUnavailable => "acquisition_unavailable",
            Self::MetaRefresh { .. } => "meta_refresh_failed",
            Self::MetaRefreshTarget { .. } => "meta_refresh_target",
            Self::EgressDenied(_) => "egress_denied",
            Self::InvalidUrl { .. } => "invalid_url",
            Self::UnsupportedMethod(_) => "unsupported_method",
            Self::Resolve { .. } => "dns",
            Self::InvalidRedirect { .. } => "invalid_redirect",
            Self::TooManyRedirects { .. } => "too_many_redirects",
            Self::PeerNotPinned { .. } => "peer_not_pinned",
            Self::Timeout(_) => "timeout",
            Self::Transport(_) => "transport",
            Self::ClientBuild(_) => "client_build",
            Self::InvalidHeader { .. } => "invalid_header",
            Self::Pool(_) => "pool_config",
            Self::PoolRefused { .. } => "pool_refused",
            Self::Io(_) => "io",
            Self::BodyDecode { .. } => "body_decode",
            Self::BodyLimit { .. } => "body_limit",
            Self::StatusDenied { .. } => "status_denied",
            Self::PreflightRefused { .. } => "preflight_refused",
            Self::InvalidDeclaration { .. } => "invalid_declaration",
        }
    }

    pub(crate) fn from_reqwest(e: reqwest::Error) -> Self {
        if e.is_timeout() {
            Self::Timeout(e.into())
        } else {
            Self::Transport(e.into())
        }
    }

    pub(crate) fn from_wreq(e: wreq::Error) -> Self {
        if e.is_timeout() {
            Self::Timeout(e.into())
        } else {
            Self::Transport(e.into())
        }
    }
}

/// Render an error with its `source()` chain; reqwest hides the cause.
pub(crate) fn error_chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}
