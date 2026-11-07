//! crawlx-elements: candidate discovery, semantic identity, interactability
//! and action vocabulary.
//!
//! The crate is pure: it consumes an immutable `ObservationBundle` and returns
//! values. It never reads wall time and never iterates a `HashMap` on a path
//! that feeds a hash or an ordering.
//!
//! Pipeline: [`CandidateDiscovery::discover`] climbs the evidence ladder and
//! assembles one [`crawlx_core::observation::ObservedDescriptor`] per candidate
//! ([`descriptor`]); [`IdentityBuilder`] turns a descriptor into the durable
//! [`crawlx_core::ElementIdentityV1`]; [`IdentityResolver`] matches it against
//! known identities with the weighted model;
//! [`Interactability`] and [`ActionVocabulary`] describe what can be done to it.

pub mod descriptor;
pub mod hit_test;
pub mod identity;
pub mod index;
pub mod ladder;
pub mod locale;
pub mod matching;
pub mod normalize;
#[cfg(test)]
pub(crate) mod testutil;
pub mod unsupported_surface;
pub mod vocabulary;

pub use descriptor::DescriptorBuilder;
pub use hit_test::{Assessment, HitTestPlan, Interactability};
pub use identity::{rates, ElementIdentityV2, IdentityBuilder};
pub use index::BundleIndex;
pub use ladder::{Candidate, CandidateDiscovery, CandidateEvidence, Discovery, DiscoveryConfig, Rung};
pub use matching::{
    DestinationContext, DurableValue, EvidenceSummary, IdentityIndex, IdentityResolver,
    InMemoryIdentityIndex, KnownIdentity, MatchDecision, MatchWeights, ResolvedElement,
    DEFAULT_MATCH_WEIGHTS,
};
pub use unsupported_surface::{SurfaceKind, UnsupportedSurface};
pub use vocabulary::ActionVocabulary;

/// Errors of this crate. Everything else is infallible by construction.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ElementsError {
    /// Canonical encoding of an identity failed (cannot happen for in-memory writers).
    #[error("identity hash failed")]
    Hash(#[source] Box<dyn std::error::Error + Send + Sync>),
}
