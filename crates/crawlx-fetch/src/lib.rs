//! crawlx-fetch: the HTTP fetch plane and the loopback egress proxy.
//!
//! * [`Fetcher`]: resolve, check every address against `EgressPolicy`, pin,
//!   per-origin politeness, bounded retries, manual redirects with a re-check
//!   per hop, conditional requests and a streaming body cap.
//! * [`OriginGovernor`]: per-origin concurrency and adaptive spacing.
//! * [`EgressProxy`]: loopback HTTP/CONNECT proxy for the browser plane, optionally chained to
//!   the operator's upstream proxy ([`UpstreamProxy`]).
//! * [`proxyx`]: native client of the ProxyX pool gateway, an optional upstream for the proxy tiers.
//! * [`Resolver`]: DNS behind a trait (`HickoryResolver`, `StaticResolver`).

pub mod body_limits;
pub mod certificate;
pub mod charset;
pub mod client;
pub mod codec;
pub mod conditional;
pub mod declaration;
pub mod egress;
pub mod error;
pub mod evidence;
pub mod governor;
pub mod lists;
pub mod preflight;
pub mod protocol;
pub mod proxyx;
pub mod redirect;
pub mod resolver;
pub mod retry;
mod tls;
pub mod upstream;

pub use body_limits::DEFAULT_MAX_BODY_BYTES;
pub use certificate::{CertificateEvidence, CertificateUnavailable, PeerCertificate};
pub use charset::{CharsetEvidence, CharsetSource, DecodeError};
pub use client::{FetchConfig, FetchHop, FetchOptions, FetchResponse, Fetcher, OversizePolicy};
pub use codec::{BodyLimitKind, BodyLimits};
pub use conditional::{interpret as interpret_revalidation, CachedValidators, Revalidation, Validators};
pub use declaration::{HttpErrorStatuses, ResponseDeclaration, StatusVerdict};
pub use egress::{
    capture_headers, DeniedEvent, EgressOptions, EgressProxy, EgressProxyHandle, DENIED_HEADER,
};
pub use error::FetchError;
pub use evidence::{BodyEvidence, FetchEvidence};
pub use governor::{GlobalOriginCap, GovernorConfig, Origin, OriginGovernor, Permit};
pub use lists::{EgressListSource, ListKind, ListReloader, ListsError, Reload, DEFAULT_RELOAD_INTERVAL};
pub use preflight::{HeadPreflight, PreflightRefusal};
pub use redirect::DEFAULT_MAX_REDIRECTS;
pub use resolver::{HickoryResolver, Resolver, StaticResolver};
pub use retry::RetryPolicy;
pub use upstream::{ProxyRoutes, UpstreamProxy, UpstreamScheme};
