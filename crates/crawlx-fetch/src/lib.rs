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
pub mod client;
pub mod conditional;
pub mod egress;
pub mod error;
pub mod governor;
pub mod lists;
pub mod protocol;
pub mod proxyx;
pub mod redirect;
pub mod resolver;
pub mod retry;
mod tls;
pub mod upstream;

pub use body_limits::DEFAULT_MAX_BODY_BYTES;
pub use client::{FetchConfig, FetchHop, FetchOptions, FetchResponse, Fetcher};
pub use conditional::Validators;
pub use egress::{
    capture_headers, DeniedEvent, EgressOptions, EgressProxy, EgressProxyHandle, DENIED_HEADER,
};
pub use error::FetchError;
pub use governor::{GlobalOriginCap, GovernorConfig, Origin, OriginGovernor, Permit};
pub use lists::{EgressListSource, ListKind, ListReloader, ListsError, Reload, DEFAULT_RELOAD_INTERVAL};
pub use redirect::DEFAULT_MAX_REDIRECTS;
pub use resolver::{HickoryResolver, Resolver, StaticResolver};
pub use retry::RetryPolicy;
pub use upstream::{ProxyRoutes, UpstreamProxy, UpstreamScheme};
