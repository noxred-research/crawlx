//! crawlx-observe: observation bundles, network epochs, quiescence.
//!
//! Drives `crawlx_core::BrowserContext` (never a concrete backend) and turns
//! its raw output into the `ObservationBundle` every other layer consumes.
//! Everything except [`observer`] and [`quiescence`] is pure and takes
//! timestamps as arguments.

pub mod bundle;
pub mod capture;
pub mod epoch;
pub mod error;
pub mod mutation;
pub mod network;
pub mod observer;
pub mod quiescence;
pub mod spec;
pub mod traffic;

#[cfg(test)]
mod testutil;

pub use bundle::{candidate_nodes, node_key, AxIndex};
pub use capture::{CdpTraffic, ProxyCaptureStats, ProxyTraffic, TrafficSource};
pub use epoch::{EpochEvent, EpochTracker};
pub use error::{CaptureError, ObserveError};
pub use mutation::{VolatileDetector, VolatileHint, VolatileReason};
pub use network::{Confidence, EventTag, NetworkEpochTracker, RequestEvent, ResponseEvent};
pub use observer::{Observer, ObserverConfig};
pub use quiescence::QuiescenceWaiter;
pub use traffic::{Redactor, RemovedSecret};
