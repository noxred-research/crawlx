//! Two-stage state clustering.
//!
//! Stage 1 is a cheap in-memory candidate lookup (MinHash LSH ∩ same route ∩
//! SimHash Hamming prefilter). Stage 2 is a weighted comparison against each
//! candidate prototype with a hard route gate, followed by a semantic
//! affordance compatibility veto, so a false merge that would hide a
//! consequence-bearing control is impossible by construction. Ambiguity
//! prefers a split. Raw observations are never touched.

use crate::error::StateError;
use crate::lsh::LshIndex;
use crate::minhash::{jaccard_estimate, union_into};
use crate::signature::StateProfile;
use crate::simhash::{hamming, similarity};
use crate::split::{SplitPlan, SplitResult, Splitter};
use crawlx_core::state::{ClusterDecision, StateSignature};
use crawlx_core::{StateClusterId, StateId, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Weight of the MinHash Jaccard estimate (affordance-set overlap) in [`score`]. All `W_*` weights sum to 1.0.
pub const W_MINHASH: f32 = 0.45;
/// Weight of the SimHash similarity of the DOM structure stream in [`score`].
pub const W_SIMHASH: f32 = 0.20;
/// Weight granted in [`score`] when the visible-element identity digests are equal.
pub const W_IDENTITY: f32 = 0.15;
/// Weight granted in [`score`] for a matching route; a route mismatch short-circuits the score to 0.
pub const W_ROUTE: f32 = 0.15;
/// Weight granted in [`score`] when the frame-tree digests are equal.
pub const W_FRAME: f32 = 0.05;

/// Thresholds and candidate limits.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClusterConfig {
    /// Attach at or above this weighted score.
    pub theta_attach: f32,
    /// Between this and `theta_attach`: attach but flag for review.
    pub theta_review: f32,
    /// Candidates kept after stage 1, best estimated Jaccard first.
    pub max_candidates: usize,
    /// Stage-1 SimHash Hamming prefilter.
    pub max_hamming: u32,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            theta_attach: 0.90,
            theta_review: 0.80,
            max_candidates: 16,
            max_hamming: 6,
        }
    }
}

/// What a cluster is compared against: the first member's signature plus the
/// running MinHash union of all members.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Prototype {
    /// Signature of the cluster's first member; the route, SimHash and digests are compared against it.
    pub signature: StateSignature,
    /// Slot-wise minimum of every member's MinHash (the MinHash of the member union); same length as the signature's MinHash.
    pub minhash_union: Vec<u64>,
    /// Sorted consequence-bearing affordance set shared by all members; `None`
    /// for clusters restored from storage without member profiles.
    pub consequence: Option<Vec<u64>>,
}

impl Prototype {
    /// Prototype of a single-member cluster: the profile's signature, its MinHash as the union and its consequence set.
    #[must_use]
    pub fn from_profile(p: &StateProfile) -> Self {
        Self {
            signature: p.signature.clone(),
            minhash_union: p.signature.semantic_affordance_minhash.clone(),
            consequence: Some(p.consequence.clone()),
        }
    }
}

/// One state's membership in a cluster version.
#[derive(Clone, PartialEq, Debug)]
pub struct Member {
    /// The clustered state.
    pub state: StateId,
    /// Fingerprint profile the state was clustered with; shared, never mutated.
    pub profile: Arc<StateProfile>,
    /// Weighted [`score`] against the prototype at decision time, in `[0, 1]` (1.0 for the seed member).
    pub similarity: f32,
}

/// A versioned cluster. `version` increments on split; a superseded cluster
/// stays queryable (`superseded_by` non-empty) so decisions are auditable.
#[derive(Clone, PartialEq, Debug)]
pub struct Cluster {
    /// Cluster identity; a split mints fresh ids rather than reusing it.
    pub id: StateClusterId,
    /// Starts at 1 and increments with every split generation.
    pub version: u32,
    /// What new states are compared against.
    pub prototype: Prototype,
    /// Members known in memory; empty for a cluster restored from storage.
    pub members: Vec<Member>,
    /// Member count, including members restored from storage without profiles.
    pub size: u32,
    /// The closest cluster that refused this one at creation, or the split source for a split product.
    pub near_of: Option<StateClusterId>,
    /// Clusters that replaced this one in a split; empty while the cluster is active.
    pub superseded_by: Vec<StateClusterId>,
}

impl Cluster {
    /// `true` while no split has superseded this cluster.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.superseded_by.is_empty()
    }
}

/// Outcome of [`ClusterIndex::attach`].
#[derive(Clone, Copy, PartialEq, Debug)]
#[non_exhaustive]
pub struct Attachment {
    /// Cluster the state joined or created, with the score and the cluster version it was decided under.
    pub decision: ClusterDecision,
    /// Attached in the `[theta_review, theta_attach)` band: a human/replay should confirm.
    pub review: bool,
    /// For a new cluster: the closest existing cluster it was refused by.
    pub near_of: Option<StateClusterId>,
    /// The best-scoring candidate was rejected by the affordance compatibility veto.
    pub vetoed: bool,
}

/// Weighted similarity in `[0, 1]`. Different algorithm versions or routes score 0.
#[must_use]
pub fn score(sig: &StateSignature, proto: &Prototype) -> f32 {
    let p = &proto.signature;
    if sig.version != p.version || sig.route_key != p.route_key {
        return 0.0;
    }
    let j = estimate_j(sig, proto);
    let mut s = W_MINHASH * j + W_ROUTE;
    s += W_SIMHASH * similarity(sig.dom_structure_simhash, p.dom_structure_simhash);
    if sig.visible_element_identity_digest == p.visible_element_identity_digest {
        s += W_IDENTITY;
    }
    if sig.frame_tree_digest == p.frame_tree_digest {
        s += W_FRAME;
    }
    s.clamp(0.0, 1.0)
}

/// Jaccard estimate against the first member or the member union, whichever is closer.
fn estimate_j(sig: &StateSignature, proto: &Prototype) -> f32 {
    let mh = &sig.semantic_affordance_minhash;
    jaccard_estimate(mh, &proto.signature.semantic_affordance_minhash)
        .max(jaccard_estimate(mh, &proto.minhash_union))
}

/// Semantic-affordance compatibility: the consequence-bearing affordance set
/// must be identical. Without a stored set (restored cluster) only an equal
/// visible-identity digest is accepted, which is strictly more conservative.
fn compatible(profile: &StateProfile, proto: &Prototype) -> bool {
    match &proto.consequence {
        Some(c) => *c == profile.consequence,
        None => {
            profile.signature.visible_element_identity_digest
                == proto.signature.visible_element_identity_digest
        }
    }
}

type IdSource = Box<dyn FnMut() -> StateClusterId + Send>;

/// In-memory cluster index of one crawl run.
pub struct ClusterIndex {
    clusters: BTreeMap<StateClusterId, Cluster>,
    lsh: LshIndex<StateClusterId>,
    /// Behind a `Mutex` so the index is `Sync` (a boxed `FnMut` is not); access is always `&mut self`.
    id_source: std::sync::Mutex<IdSource>,
}

impl fmt::Debug for ClusterIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterIndex")
            .field("clusters", &self.clusters.len())
            .finish_non_exhaustive()
    }
}

impl Default for ClusterIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ClusterIndex {
    /// Index minting fresh `StateClusterId::new()` ids.
    #[must_use]
    pub fn new() -> Self {
        Self::with_id_source(StateClusterId::new)
    }

    /// Index minting ids from `source` (deterministic replay and tests).
    #[must_use]
    pub fn with_id_source(source: impl FnMut() -> StateClusterId + Send + 'static) -> Self {
        Self {
            clusters: BTreeMap::new(),
            lsh: LshIndex::new(),
            id_source: std::sync::Mutex::new(Box::new(source)),
        }
    }

    fn id_source_mut(&mut self) -> &mut IdSource {
        self.id_source
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Number of active (non-superseded) clusters.
    #[must_use]
    pub fn active_len(&self) -> usize {
        self.clusters.values().filter(|c| c.is_active()).count()
    }

    /// The cluster with `id`, active or superseded.
    #[must_use]
    pub fn get(&self, id: StateClusterId) -> Option<&Cluster> {
        self.clusters.get(&id)
    }

    /// All clusters (including superseded) in id order.
    pub fn iter(&self) -> impl Iterator<Item = &Cluster> {
        self.clusters.values()
    }

    /// Re-register a cluster persisted by an earlier run (`StateRepo::list_clusters`).
    /// Its member profiles are unknown, so the attach compatibility test falls
    /// back to the visible-identity digest.
    pub fn restore(&mut self, id: StateClusterId, version: u32, signature: StateSignature, size: u32) {
        let prototype = Prototype {
            minhash_union: signature.semantic_affordance_minhash.clone(),
            signature,
            consequence: None,
        };
        self.lsh
            .insert(id, &prototype.signature.semantic_affordance_minhash);
        self.clusters.insert(
            id,
            Cluster {
                id,
                version,
                prototype,
                members: Vec::new(),
                size,
                near_of: None,
                superseded_by: Vec::new(),
            },
        );
    }

    /// Stage 1 with default limits: `(cluster, estimated Jaccard)`, best first.
    #[must_use]
    pub fn candidates(&self, sig: &StateSignature) -> Vec<(StateClusterId, f32)> {
        self.candidates_with(sig, &ClusterConfig::default())
    }

    /// Stage 1: LSH hits on the MinHash, same route, SimHash Hamming within
    /// `cfg.max_hamming`, at most `cfg.max_candidates` ordered by estimated
    /// Jaccard (ties by id).
    #[must_use]
    pub fn candidates_with(&self, sig: &StateSignature, cfg: &ClusterConfig) -> Vec<(StateClusterId, f32)> {
        let mut out: Vec<(StateClusterId, f32)> = self
            .lsh
            .query(&sig.semantic_affordance_minhash)
            .into_iter()
            .filter_map(|id| {
                let c = self.clusters.get(&id)?;
                if !c.is_active()
                    || c.prototype.signature.version != sig.version
                    || c.prototype.signature.route_key != sig.route_key
                {
                    return None;
                }
                let h = hamming(
                    sig.dom_structure_simhash,
                    c.prototype.signature.dom_structure_simhash,
                );
                (h <= cfg.max_hamming).then(|| (id, estimate_j(sig, &c.prototype)))
            })
            .collect();
        out.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        out.truncate(cfg.max_candidates);
        out
    }

    /// Stage 2 + 3: attach `state` to the best compatible candidate or create a
    /// new cluster. Attach at `score ≥ theta_attach`; `[theta_review,
    /// theta_attach)` attaches with `review = true`; anything lower (or a
    /// compatibility veto) creates a new cluster.
    pub fn attach(&mut self, state: StateId, profile: &StateProfile, cfg: &ClusterConfig) -> Attachment {
        let mut scored: Vec<(StateClusterId, f32, bool)> = self
            .candidates_with(&profile.signature, cfg)
            .into_iter()
            .filter_map(|(id, _)| {
                let c = self.clusters.get(&id)?;
                Some((
                    id,
                    score(&profile.signature, &c.prototype),
                    compatible(profile, &c.prototype),
                ))
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));

        let best_overall = scored.first().copied();
        let best_ok = scored.iter().find(|(_, _, ok)| *ok).copied();

        if let Some((id, s, _)) = best_ok {
            if s >= cfg.theta_review {
                let review = s < cfg.theta_attach;
                let version = self.add_member(id, state, profile, s);
                return Attachment {
                    decision: ClusterDecision {
                        cluster: id,
                        similarity: s,
                        decision_version: version,
                        created_new: false,
                    },
                    review,
                    near_of: None,
                    vetoed: false,
                };
            }
        }

        let vetoed = best_overall.is_some_and(|(_, s, ok)| !ok && s >= cfg.theta_review);
        let near_of = best_overall
            .filter(|(_, s, _)| *s >= cfg.theta_review)
            .map(|(id, _, _)| id);
        let similarity = best_overall.map_or(0.0, |(_, s, _)| s);
        let id = (self.id_source_mut())();
        self.create(id, state, profile, near_of);
        Attachment {
            decision: ClusterDecision {
                cluster: id,
                similarity,
                decision_version: 1,
                created_new: true,
            },
            review: false,
            near_of,
            vetoed,
        }
    }

    fn create(
        &mut self,
        id: StateClusterId,
        state: StateId,
        profile: &StateProfile,
        near_of: Option<StateClusterId>,
    ) {
        let prototype = Prototype::from_profile(profile);
        self.lsh.insert(id, &prototype.minhash_union);
        self.clusters.insert(
            id,
            Cluster {
                id,
                version: 1,
                prototype,
                members: vec![Member {
                    state,
                    profile: Arc::new(profile.clone()),
                    similarity: 1.0,
                }],
                size: 1,
                near_of,
                superseded_by: Vec::new(),
            },
        );
    }

    /// Returns the cluster version the membership was decided under.
    fn add_member(
        &mut self,
        id: StateClusterId,
        state: StateId,
        profile: &StateProfile,
        similarity: f32,
    ) -> u32 {
        let Some(c) = self.clusters.get_mut(&id) else {
            return 1;
        };
        union_into(
            &mut c.prototype.minhash_union,
            &profile.signature.semantic_affordance_minhash,
        );
        if c.prototype.consequence.is_none() {
            c.prototype.consequence = Some(profile.consequence.clone());
        }
        c.members.push(Member {
            state,
            profile: Arc::new(profile.clone()),
            similarity,
        });
        c.size = c.size.saturating_add(1);
        self.lsh.insert(id, &c.prototype.minhash_union);
        c.version
    }

    /// Apply a [`SplitPlan`]: the source cluster is marked superseded and
    /// removed from candidate lookup, two new cluster versions take over its
    /// members. Raw states are untouched.
    ///
    /// # Errors
    /// [`StateError::UnknownCluster`] when the plan's source is not indexed,
    /// [`StateError::AlreadySuperseded`] when it was already split, and
    /// [`StateError::StaleSplitPlan`] when the cluster's version moved past the plan's.
    pub fn split(&mut self, plan: &SplitPlan, decided_at: Timestamp) -> Result<SplitResult, StateError> {
        let source = self
            .clusters
            .get(&plan.source)
            .ok_or(StateError::UnknownCluster(plan.source))?;
        if !source.is_active() {
            return Err(StateError::AlreadySuperseded(plan.source));
        }
        if source.version != plan.source_version {
            return Err(StateError::StaleSplitPlan {
                cluster: plan.source,
                plan_version: plan.source_version,
                current_version: source.version,
            });
        }
        let result = Splitter::apply(plan, self.id_source_mut(), decided_at);
        self.lsh.remove(plan.source);
        if let Some(src) = self.clusters.get_mut(&plan.source) {
            src.superseded_by = result.clusters.iter().map(|c| c.id).collect();
        }
        for c in &result.clusters {
            self.lsh.insert(c.id, &c.prototype.minhash_union);
            self.clusters.insert(c.id, c.clone());
        }
        Ok(result)
    }
}
