//! crawlx-state: volatile-region masks, multi-signal state fingerprints,
//! two-stage cluster matching and split-on-contradiction.
//!
//! Everything here is pure and deterministic: no wall-clock reads (callers
//! pass `Timestamp`s), no hash-map iteration in hashing paths, and the
//! MinHash permutation constants are fixed in code rather than derived from
//! the crawl seed so signatures compare across runs.

// No hash-ordered containers on decision or hashing paths (`clippy.toml`).
#![deny(clippy::disallowed_types)]

pub mod cluster;
pub mod diff;
pub mod error;
pub mod lsh;
pub mod mask;
pub mod minhash;
mod roles;
pub mod signature;
pub mod simhash;
pub mod split;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod testutil;
mod text;
mod tree;

pub use cluster::{
    score, Attachment, Cluster, ClusterConfig, ClusterIndex, Member, Prototype, W_FRAME, W_IDENTITY,
    W_MINHASH, W_ROUTE, W_SIMHASH,
};
pub use diff::{NameChange, StateDiff, StateDiffReport};
pub use error::StateError;
pub use lsh::LshIndex;
pub use mask::{MaskBuilder, MaskConfig, MaskSelector, VolatileHint, MASK_VERSION};
pub use signature::{ExtraSignals, FingerprintConfig, Fingerprinter, StateProfile};
pub use simhash::hamming;
pub use split::{
    Contradiction, MembershipChange, OutcomeClass, SplitConfig, SplitPlan, SplitResult, Splitter,
};
pub use text::normalize_name;
