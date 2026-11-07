//! CrawlerGym: fixture server, ground-truth manifests and the server-side ledger.

pub mod fixtures;
pub mod ledger;
pub mod manifest;
pub mod server;

pub use ledger::{Ledger, LedgerEntry, LedgerEvent};
pub use manifest::{ControlTruth, ExpectedClass, ExpectedMetrics, FixtureManifest};
pub use server::{GymHandle, GymServer};
