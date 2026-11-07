//! State fingerprints. Computation lives in `crawlx-state`.

use crate::hash::Digest;
use serde::{Deserialize, Serialize};

/// Multi-signal fingerprint of one observation (`StateSignature`).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct StateSignature {
    /// Fingerprint algorithm version ([`StateSignature::VERSION`] when computed); signatures of different versions are not comparable.
    pub version: u16,
    /// Digest of the route schema and classified navigation/filter/action view values.
    /// Resource identifiers and session/tracking values never partition state clusters.
    pub route_key: Digest,
    /// MinHash signature (k = 128) over semantic affordances.
    pub semantic_affordance_minhash: Vec<u64>,
    /// 64-bit SimHash over DOM structure shingles.
    pub dom_structure_simhash: u64,
    /// Digest over the sorted, de-duplicated identities of visible interactive elements.
    pub visible_element_identity_digest: Digest,
    /// Digest over the frame tree (one key per frame URL, in observation order).
    pub frame_tree_digest: Digest,
    /// Digest over the sorted network operations (e.g. `POST /api/cart`) seen during the observation.
    pub network_operation_digest: Digest,
    /// 64-bit perceptual hash of the screenshot; `None` when no visual capture was taken.
    pub visual_phash: Option<u64>,
    /// Digest of storage and cookie names (never values); `None` unless the storage privacy gate is enabled.
    pub browser_storage_digest: Option<Digest>,
}

impl StateSignature {
    /// Current state-signature algorithm version, written into [`StateSignature::version`].
    /// Version 2 adds classified functional query views to the hard route partition.
    pub const VERSION: u16 = 2;

    /// Exact-equality digest for dedupe of identical observations.
    ///
    /// # Errors
    /// Returns the CBOR serialization error if the signature cannot be encoded.
    pub fn exact_digest(&self) -> Result<Digest, ciborium::ser::Error<std::io::Error>> {
        Digest::of_value("crawlx/state-signature/v1", self)
    }
}

/// Regions excluded from hashing, stored with the state so a fingerprint is
/// reproducible from its artifact.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug, Default)]
pub struct MaskSet {
    /// Mask algorithm version that produced this set.
    pub version: u16,
    /// Stable node keys (role + path digest) masked as volatile.
    pub masked_node_keys: Vec<Digest>,
    /// Why each region was masked, one entry per masked region; may contain repeats.
    pub reasons: Vec<MaskReason>,
}

/// Why a region was masked.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum MaskReason {
    /// Live region or ARIA live role whose content updates on its own.
    LiveRegion,
    /// Clock, timer or counter whose text changes with time.
    ClockOrCounter,
    /// List item past the first page of a feed; feed length varies between observations.
    FeedBeyondFirstPage,
    /// Node that changed between two observations with no action in between (probe re-observation).
    ChangedWithoutAction,
    /// Masked by explicit mask configuration (role or accessible-name match).
    Configured,
}

/// Cluster membership decision.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct ClusterDecision {
    /// Cluster the state was assigned to.
    pub cluster: crate::ids::StateClusterId,
    /// Similarity score in `[0.0, 1.0]` between the state and the cluster prototype.
    pub similarity: f32,
    /// Version of the clustering decision (cluster version at assignment); starts at 1 for a new cluster.
    pub decision_version: u32,
    /// `true` when the state founded a new cluster instead of joining an existing one.
    pub created_new: bool,
}
