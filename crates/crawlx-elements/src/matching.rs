//! Weighted identity matching.
//!
//! Frame lineage and role are hard gates (candidates come from an index keyed
//! by exactly those). Within the bucket an observed descriptor first tries an
//! exact identity match (same `ElementIdentityV1` ⇒ same hash ⇒ reuse), then
//! scores each known identity:
//!
//! | term | default weight |
//! |---|---:|
//! | durable attributes (`id`, `name`, `data-testid`, …, href template); exact agreement counts 1, agreement of the digit-free templates only 0.6 | 0.35 |
//! | stable ancestor role path | 0.20 |
//! | container signature | 0.15 |
//! | control type | 0.15 |
//! | accessible-name similarity (Jaro-Winkler + token overlap) | 0.10 |
//! | geometry (box IoU) | 0.05 |
//!
//! `score ≥ 0.80` reuses the known identity; `0.60 ≤ score < 0.80` mints a new
//! identity and records the best candidate as its alias; below that the
//! identity is simply new. Ambiguity prefers a split: a false split costs
//! redundant exploration, a false merge hides functionality.
//!
//! When neither side carries durable attributes the durable weight moves to
//! the name term, so two attribute-less controls cannot merge on structure
//! alone.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};

use crawlx_core::identity::{ElementIdentityHash, ElementIdentityV1};
use crawlx_core::observation::{BoundingBox, ObservedDescriptor, RuntimeLocator};
use crawlx_url::CanonicalizeOptions;
use unicode_normalization::UnicodeNormalization;

use crate::identity::IdentityBuilder;
use crate::normalize::{collapse_ws, normalize_attr_value};
use crate::ElementsError;

/// Attributes that survive re-renders better than anything else on the node.
const DURABLE_ATTRIBUTES: [&str; 8] = [
    "id",
    "name",
    "data-testid",
    "data-test-id",
    "data-test",
    "data-cy",
    "for",
    "aria-controls",
];

/// Key under which the identity's destination key is stored as durable evidence.
const HREF_TEMPLATE_KEY: &str = "href-template";

/// Slack for `f32` rounding when comparing a score against a threshold.
const EPS: f32 = 1e-4;

/// Matching weights and decision thresholds (planning defaults).
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct MatchWeights {
    /// Weight of agreement on durable attributes (`id`, `name`, `data-testid`, …, href template).
    pub durable: f32,
    /// Weight of the stable ancestor role path similarity.
    pub ancestor_path: f32,
    /// Weight of the container signature similarity.
    pub container: f32,
    /// Weight of an equal control type.
    pub control_type: f32,
    /// Weight of accessible-name similarity (also receives the durable weight
    /// when neither side carries durable attributes).
    pub name: f32,
    /// Weight of bounding-box overlap (IoU).
    pub geometry: f32,
    /// Scores at or above this reuse the known identity.
    pub accept: f32,
    /// Scores in `[ambiguous_floor, accept)` mint a new identity with an alias.
    pub ambiguous_floor: f32,
}

/// The weight table of the weighted matcher as the code ships it:
/// `durable` 0.35, `ancestor_path` 0.20, `container` 0.15, `control_type` 0.15,
/// `name` 0.10, `geometry` 0.05 (the six terms sum to 1), `accept` 0.80 and
/// `ambiguous_floor` 0.60. [`MatchWeights::default`] returns exactly this table;
/// a weight change must update this constant and the regression corpus
/// report (`tests/weight_regression.rs`).
pub const DEFAULT_MATCH_WEIGHTS: MatchWeights = MatchWeights {
    durable: 0.35,
    ancestor_path: 0.20,
    container: 0.15,
    control_type: 0.15,
    name: 0.10,
    geometry: 0.05,
    accept: 0.80,
    ambiguous_floor: 0.60,
};

impl Default for MatchWeights {
    fn default() -> Self {
        DEFAULT_MATCH_WEIGHTS
    }
}

/// One durable attribute value as observed: the exact (NFKC, lowercased, whitespace-collapsed)
/// value and its digit-free template (`normalize_attr_value`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DurableValue {
    /// Exact value; equal values are full agreement.
    pub exact: String,
    /// Digit-free template; equal templates with different exact values are the weaker
    /// agreement of a framework-numbered id (`input-17` → `input-23`) — or of two siblings
    /// of one template (`tab-1`, `tab-2`), which the name term must then tell apart.
    pub template: String,
}

impl DurableValue {
    fn new(raw: &str) -> Self {
        Self {
            exact: collapse_ws(&raw.nfkc().collect::<String>().to_lowercase()),
            template: normalize_attr_value(raw),
        }
    }

    /// `1.0` exact, [`TEMPLATE_AGREEMENT`] template-only, `0.0` otherwise.
    fn agreement(&self, other: &Self) -> f32 {
        if self.exact == other.exact {
            1.0
        } else if self.template == other.template {
            TEMPLATE_AGREEMENT
        } else {
            0.0
        }
    }
}

/// Credit for a durable key whose digit-free templates agree while the exact values differ.
/// Calibrated so that a re-numbered id with an unchanged name still reuses
/// (`0.35·0.6 + 0.20 + 0.15 + 0.15 + 0.10 = 0.81 ≥ accept`) while two template siblings with
/// different names stop in the ambiguity band (`0.71 + 0.10·name < 0.80` unless the names are
/// near-identical); see `tests/weight_regression.rs`.
const TEMPLATE_AGREEMENT: f32 = 0.6;

/// Evidence retained next to a known identity; what matching needs beyond the
/// identity fields themselves.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct EvidenceSummary {
    /// Durable attribute values plus the `href-template`.
    pub durable: BTreeMap<String, DurableValue>,
    /// Normalized accessible name of the latest observation.
    pub normalized_name: String,
    /// Box of the latest observation.
    pub bbox: Option<BoundingBox>,
    /// Observations merged into this identity.
    pub observations: u32,
}

impl EvidenceSummary {
    /// Summary of one observation of `identity`.
    #[must_use]
    pub fn from_descriptor(desc: &ObservedDescriptor, identity: &ElementIdentityV1) -> Self {
        let mut durable = BTreeMap::new();
        for key in DURABLE_ATTRIBUTES {
            if let Some(v) = desc.attributes.get(key) {
                let value = DurableValue::new(v);
                if !value.template.is_empty() {
                    durable.insert(key.to_owned(), value);
                }
            }
        }
        if let Some(d) = &identity.destination_key {
            durable.insert(
                HREF_TEMPLATE_KEY.to_owned(),
                DurableValue {
                    exact: d.clone(),
                    template: d.clone(),
                },
            );
        }
        Self {
            durable,
            normalized_name: identity.normalized_accessible_name.clone(),
            bbox: desc.bbox,
            observations: 1,
        }
    }

    fn merge(&mut self, newer: &Self) {
        for (k, v) in &newer.durable {
            if !self.durable.contains_key(k) {
                self.durable.insert(k.clone(), v.clone());
            }
        }
        self.normalized_name.clone_from(&newer.normalized_name);
        if newer.bbox.is_some() {
            self.bbox = newer.bbox;
        }
        self.observations = self.observations.saturating_add(newer.observations);
    }
}

/// An identity already known to the crawl.
#[derive(Clone, PartialEq, Debug)]
pub struct KnownIdentity {
    /// Hash of `identity`; the key of this record in an [`IdentityIndex`].
    pub hash: ElementIdentityHash,
    /// Identity algorithm version; matching never crosses this boundary.
    pub version: u16,
    /// The durable identity itself.
    pub identity: ElementIdentityV1,
    /// Evidence accumulated over all observations merged into this identity.
    pub evidence_summary: EvidenceSummary,
}

/// Source of known identities, bucketed by the two hard gates.
pub trait IdentityIndex {
    /// Known identities with exactly `frame_lineage` and `role` (lowercase).
    fn candidates(&self, frame_lineage: &[String], role: &str) -> Vec<KnownIdentity>;
}

/// `BTreeMap`-backed index for tests, replay and single-process crawls.
///
/// Buckets nest by frame lineage, then role, so lookups borrow `&[String]` and
/// `&str` without allocating a composite key.
#[derive(Clone, Debug, Default)]
pub struct InMemoryIdentityIndex {
    buckets: BTreeMap<Vec<String>, BTreeMap<String, Bucket>>,
    aliases: BTreeMap<ElementIdentityHash, ElementIdentityHash>,
}

/// Known identities sharing one frame lineage and role, by hash.
type Bucket = BTreeMap<ElementIdentityHash, KnownIdentity>;

/// Merge `known` into `bucket`: evidence is merged into an existing record
/// with the same hash, otherwise the record is inserted.
fn merge_or_insert(bucket: &mut Bucket, known: KnownIdentity) {
    match bucket.entry(known.hash) {
        Entry::Occupied(mut existing) => existing.get_mut().evidence_summary.merge(&known.evidence_summary),
        Entry::Vacant(slot) => {
            slot.insert(known);
        }
    }
}

impl InMemoryIdentityIndex {
    /// Empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of known identities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets
            .values()
            .flat_map(BTreeMap::values)
            .map(BTreeMap::len)
            .sum()
    }

    /// No identity is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Insert (or merge evidence into) a known identity.
    pub fn insert(&mut self, known: KnownIdentity) {
        let lineage = &known.identity.frame_lineage;
        let role = &known.identity.role;
        if let Some(bucket) = self
            .buckets
            .get_mut(lineage.as_slice())
            .and_then(|roles| roles.get_mut(role.as_str()))
        {
            merge_or_insert(bucket, known);
            return;
        }
        let bucket = self
            .buckets
            .entry(lineage.clone())
            .or_default()
            .entry(role.clone())
            .or_default();
        bucket.insert(known.hash, known);
    }

    /// Record the outcome of a resolution: merge evidence on reuse, insert and
    /// remember the alias candidate on a mint.
    pub fn record(&mut self, resolved: &ResolvedElement) {
        if let MatchDecision::MintedNew { alias: Some(a), .. } = &resolved.decision {
            self.aliases.insert(resolved.hash, *a);
        }
        self.insert(resolved.known());
    }

    /// Alias candidate recorded for a minted identity (ambiguity band).
    #[must_use]
    pub fn alias_of(&self, hash: &ElementIdentityHash) -> Option<ElementIdentityHash> {
        self.aliases.get(hash).copied()
    }

    /// Known identity by hash.
    #[must_use]
    pub fn get(&self, hash: &ElementIdentityHash) -> Option<&KnownIdentity> {
        self.buckets
            .values()
            .flat_map(BTreeMap::values)
            .find_map(|b| b.get(hash))
    }
}

impl IdentityIndex for InMemoryIdentityIndex {
    fn candidates(&self, frame_lineage: &[String], role: &str) -> Vec<KnownIdentity> {
        self.buckets
            .get(frame_lineage)
            .and_then(|roles| roles.get(role))
            .map(|b| b.values().cloned().collect())
            .unwrap_or_default()
    }
}

/// How a descriptor resolved.
#[derive(Clone, Copy, PartialEq, Debug)]
#[non_exhaustive]
pub enum MatchDecision {
    /// The known identity was reused (`1.0` for an exact identity match).
    Reused {
        /// Similarity to the reused identity, in `0..=1`.
        score: f32,
    },
    /// A new identity was minted; `alias` is set when the best candidate fell
    /// in the ambiguity band `[ambiguous_floor, accept)`.
    MintedNew {
        /// Highest score over the known candidates (`0.0` when there were none).
        best_score: f32,
        /// Best candidate when its score fell in the ambiguity band.
        alias: Option<ElementIdentityHash>,
    },
}

/// Result of resolving one descriptor.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct ResolvedElement {
    /// Hash of `identity` (of the reused record when the match was reused).
    pub hash: ElementIdentityHash,
    /// Identity algorithm version used for hashing and matching.
    pub version: u16,
    /// Identity of the element after resolution.
    pub identity: ElementIdentityV1,
    /// Whether an identity was reused or minted.
    pub decision: MatchDecision,
    /// Epoch-bound runtime handle of the observed node.
    pub locator: RuntimeLocator,
    /// Evidence of this observation, ready for [`InMemoryIdentityIndex::record`].
    pub evidence: EvidenceSummary,
}

impl ResolvedElement {
    /// The known-identity record this resolution contributes.
    #[must_use]
    pub fn known(&self) -> KnownIdentity {
        KnownIdentity {
            hash: self.hash,
            version: self.version,
            identity: self.identity.clone(),
            evidence_summary: self.evidence.clone(),
        }
    }
}

/// Page context needed to key link destinations.
#[derive(Clone, Debug)]
pub struct DestinationContext {
    /// URL of the observed page; relative `href`s resolve against it.
    pub base: url::Url,
    /// Canonicalization options applied to `href`s.
    pub options: CanonicalizeOptions,
}

/// Resolves descriptors to identities.
#[derive(Clone, Debug, Default)]
pub struct IdentityResolver {
    destination: Option<DestinationContext>,
    version: crawlx_core::config::IdentityVersion,
    language: String,
}

impl IdentityResolver {
    /// Resolver without a canonicalizer: links carry no `destination_key`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolver that derives link destination keys with `options` against `base`.
    #[must_use]
    pub fn with_destination(base: url::Url, options: CanonicalizeOptions) -> Self {
        Self {
            destination: Some(DestinationContext { base, options }),
            ..Self::default()
        }
    }

    /// Select the identity algorithm and the page's `lang`.
    /// Dual mode resolves with V1; callers separately record the V2 alias.
    #[must_use]
    pub fn with_identity_version(
        mut self,
        version: crawlx_core::config::IdentityVersion,
        language: &str,
    ) -> Self {
        self.version = version;
        self.language = language.to_owned();
        self
    }

    /// Identity version accepted when resolving a recorded replay path.
    #[must_use]
    pub fn accepts_replay_version(&self, stored: u16) -> bool {
        self.version.decision_version() == stored
    }

    /// Resolve `desc` against `index`.
    ///
    /// # Errors
    /// [`ElementsError::Hash`] when the observed identity cannot be hashed.
    pub fn resolve(
        &self,
        desc: &ObservedDescriptor,
        index: &dyn IdentityIndex,
        weights: &MatchWeights,
    ) -> Result<ResolvedElement, ElementsError> {
        let dest = self
            .destination
            .as_ref()
            .and_then(|c| IdentityBuilder::destination_key(desc, &c.base, &c.options));
        self.resolve_versioned(desc, dest, index, weights)
    }

    /// Resolve with an explicit destination key (the caller canonicalized).
    ///
    /// # Errors
    /// [`ElementsError::Hash`] when the observed identity cannot be hashed.
    pub fn resolve_with_key(
        desc: &ObservedDescriptor,
        destination_key: Option<String>,
        index: &dyn IdentityIndex,
        weights: &MatchWeights,
    ) -> Result<ResolvedElement, ElementsError> {
        Self::default().resolve_versioned(desc, destination_key, index, weights)
    }

    fn resolve_versioned(
        &self,
        desc: &ObservedDescriptor,
        destination_key: Option<String>,
        index: &dyn IdentityIndex,
        weights: &MatchWeights,
    ) -> Result<ResolvedElement, ElementsError> {
        let version = self.version.decision_version();
        let (identity, hash) = if version == 2 {
            let identity = IdentityBuilder::build_v2(desc, destination_key, &self.language);
            let hash = identity.hash()?;
            (identity.components, hash)
        } else {
            let identity = IdentityBuilder::build(desc, destination_key);
            let hash = IdentityBuilder::hash(&identity)?;
            (identity, hash)
        };
        let evidence = EvidenceSummary::from_descriptor(desc, &identity);
        let mut known = index.candidates(&identity.frame_lineage, &identity.role);
        known.retain(|candidate| candidate.version == version);
        known.sort_by_key(|k| k.hash);

        let (hash, identity, decision) = if let Some(i) = known.iter().position(|k| k.hash == hash) {
            let exact = known.swap_remove(i);
            (exact.hash, exact.identity, MatchDecision::Reused { score: 1.0 })
        } else {
            let mut best: Option<(f32, usize)> = None;
            for (i, k) in known.iter().enumerate() {
                let s = weights.score(&identity, &evidence, k);
                if best.is_none_or(|(b, _)| s > b) {
                    best = Some((s, i));
                }
            }
            match best {
                Some((s, i)) if s + EPS >= weights.accept => {
                    let reused = known.swap_remove(i);
                    (reused.hash, reused.identity, MatchDecision::Reused { score: s })
                }
                Some((s, i)) if s + EPS >= weights.ambiguous_floor => (
                    hash,
                    identity,
                    MatchDecision::MintedNew {
                        best_score: s,
                        alias: Some(known[i].hash),
                    },
                ),
                other => (
                    hash,
                    identity,
                    MatchDecision::MintedNew {
                        best_score: other.map_or(0.0, |(s, _)| s),
                        alias: None,
                    },
                ),
            }
        };
        Ok(ResolvedElement {
            hash,
            version,
            identity,
            decision,
            locator: desc.locator.clone(),
            evidence,
        })
    }
}

impl MatchWeights {
    /// Weighted similarity (0..=1) of an observed identity and evidence to a known identity.
    #[must_use]
    pub fn score(
        &self,
        identity: &ElementIdentityV1,
        evidence: &EvidenceSummary,
        known: &KnownIdentity,
    ) -> f32 {
        let durable = durable_similarity(&evidence.durable, &known.evidence_summary.durable);
        let mut name_weight = self.name;
        let mut total = 0.0;
        match durable {
            Some(d) => total += self.durable * d,
            None => name_weight += self.durable,
        }
        total += self.ancestor_path
            * path_similarity(
                &identity.stable_ancestor_role_path,
                &known.identity.stable_ancestor_role_path,
            );
        total += self.container
            * container_similarity(
                identity.container_signature.as_deref(),
                known.identity.container_signature.as_deref(),
            );
        total +=
            self.control_type * f32::from(u8::from(identity.control_type == known.identity.control_type));
        total +=
            name_weight * name_similarity(&evidence.normalized_name, &known.evidence_summary.normalized_name);
        total +=
            self.geometry * geometry_similarity(evidence.bbox.as_ref(), known.evidence_summary.bbox.as_ref());
        total.clamp(0.0, 1.0)
    }
}

/// Mean agreement over the durable keys of both sides (a key missing on one side counts
/// `0`); `None` when neither side has any.
fn durable_similarity(a: &BTreeMap<String, DurableValue>, b: &BTreeMap<String, DurableValue>) -> Option<f32> {
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    if keys.is_empty() {
        return None;
    }
    let agree: f32 = keys
        .iter()
        .filter_map(|k| Some(a.get(*k)?.agreement(b.get(*k)?)))
        .sum();
    Some(agree / keys.len() as f32)
}

/// `2·LCS / (|a| + |b|)`; two empty paths are identical.
fn path_similarity(a: &[String], b: &[String]) -> f32 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let mut prev = vec![0usize; b.len() + 1];
    let mut cur = vec![0usize; b.len() + 1];
    for x in a {
        for (j, y) in b.iter().enumerate() {
            cur[j + 1] = if x == y {
                prev[j] + 1
            } else {
                prev[j + 1].max(cur[j])
            };
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    2.0 * prev[b.len()] as f32 / (a.len() + b.len()) as f32
}

/// Same signature ⇒ 1; same container kind where at most one side is named ⇒ 0.4; one
/// side missing or a different kind ⇒ 0; same kind with **two different names**
/// (`region:featured` vs `region:clearance`) ⇒ −1: the container is contradicting evidence,
/// so identically named controls in different named landmarks fall into the ambiguity band
/// (alias, never a silent merge).
fn container_similarity(a: Option<&str>, b: Option<&str>) -> f32 {
    match (a, b) {
        (None, None) => 1.0,
        (Some(x), Some(y)) if x == y => 1.0,
        (Some(x), Some(y)) => {
            let (kx, named_x) = x.split_once(':').map_or((x, false), |(k, _)| (k, true));
            let (ky, named_y) = y.split_once(':').map_or((y, false), |(k, _)| (k, true));
            if kx != ky {
                0.0
            } else if named_x && named_y {
                // Same kind, both named, names differ (equal signatures matched above).
                -1.0
            } else {
                0.4
            }
        }
        _ => 0.0,
    }
}

/// Mean of Jaro-Winkler and token Jaccard; two empty names are identical.
#[allow(
    clippy::cast_possible_truncation,
    reason = "similarity scores lie in 0..=1; f64 → f32 rounding is the intent"
)]
fn name_similarity(a: &str, b: &str) -> f32 {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => return 1.0,
        (true, false) | (false, true) => return 0.0,
        (false, false) => {}
    }
    let jw = strsim::jaro_winkler(a, b) as f32;
    let ta: BTreeSet<&str> = a.split_whitespace().collect();
    let tb: BTreeSet<&str> = b.split_whitespace().collect();
    let inter = ta.intersection(&tb).count();
    let union = ta.union(&tb).count();
    let jaccard = if union == 0 {
        0.0
    } else {
        inter as f32 / union as f32
    };
    (jw + jaccard) / 2.0
}

/// Box IoU; unknown geometry is neutral (0.5).
#[allow(
    clippy::cast_possible_truncation,
    reason = "IoU lies in 0..=1; f64 → f32 rounding is the intent"
)]
fn geometry_similarity(a: Option<&BoundingBox>, b: Option<&BoundingBox>) -> f32 {
    let (Some(a), Some(b)) = (a, b) else { return 0.5 };
    let ix = (a.x + a.width).min(b.x + b.width) - a.x.max(b.x);
    let iy = (a.y + a.height).min(b.y + b.height) - a.y.max(b.y);
    if ix <= 0.0 || iy <= 0.0 {
        return 0.0;
    }
    let inter = ix * iy;
    let union = a.area() + b.area() - inter;
    if union <= 0.0 {
        0.0
    } else {
        (inter / union) as f32
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::ladder::{CandidateDiscovery, DiscoveryConfig};
    use crate::testutil::{attrs, bbox, card_page, descriptor, page_url};

    fn base() -> ObservedDescriptor {
        let mut d = descriptor("button", "Save draft");
        d.tag = Some("button".into());
        d.attributes = attrs(&[("type", "button"), ("id", "save-btn")]);
        d.ancestor_roles = ["RootWebArea", "main", "form"]
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        d.container_text = Some("form|Compose".into());
        d.bbox = Some(bbox(10.0, 10.0, 100.0, 30.0));
        d
    }

    fn seeded(d: &ObservedDescriptor) -> InMemoryIdentityIndex {
        let mut idx = InMemoryIdentityIndex::new();
        let r = IdentityResolver::new()
            .resolve(d, &idx, &MatchWeights::default())
            .unwrap();
        assert!(matches!(r.decision, MatchDecision::MintedNew { alias: None, .. }));
        idx.record(&r);
        idx
    }

    fn resolve(d: &ObservedDescriptor, idx: &InMemoryIdentityIndex) -> ResolvedElement {
        IdentityResolver::new()
            .resolve(d, idx, &MatchWeights::default())
            .unwrap()
    }

    #[test]
    fn default_weights_are_the_documented_table_and_sum_to_one() {
        let w = MatchWeights::default();
        assert_eq!(w, DEFAULT_MATCH_WEIGHTS);
        let sum = w.durable + w.ancestor_path + w.container + w.control_type + w.name + w.geometry;
        assert!((sum - 1.0).abs() < 1e-6, "term weights sum to {sum}");
        assert_eq!((w.accept, w.ambiguous_floor), (0.80, 0.60));
    }

    #[test]
    fn reuses_at_or_above_accept() {
        let known = base();
        let idx = seeded(&known);
        // same durable id, drifted name: still the same control
        let mut d = base();
        d.accessible_name = Some("Save draft now".into());
        let r = resolve(&d, &idx);
        let known_hash = IdentityBuilder::hash(&IdentityBuilder::build(&known, None)).unwrap();
        match r.decision {
            MatchDecision::Reused { score } => assert!((0.80..1.0).contains(&score), "{score}"),
            other => panic!("expected reuse, got {other:?}"),
        }
        assert_eq!(
            r.hash, known_hash,
            "reuse returns the known identity, not the drifted one"
        );
        assert_eq!(r.identity.normalized_accessible_name, "save draft");
    }

    #[test]
    fn exact_identity_is_reused_with_score_one() {
        let d = base();
        let idx = seeded(&d);
        let mut again = base();
        again.attributes.insert("id".into(), "totally-different".into());
        let r = resolve(&again, &idx);
        assert_eq!(r.decision, MatchDecision::Reused { score: 1.0 });
    }

    #[test]
    fn mints_with_alias_in_the_ambiguity_band() {
        let known = base();
        let idx = seeded(&known);
        let known_hash = IdentityBuilder::hash(&IdentityBuilder::build(&known, None)).unwrap();
        let mut d = base();
        d.attributes.insert("id".into(), "x-btn".into()); // durable evidence contradicts
        d.accessible_name = Some("Save the draft".into());
        let r = resolve(&d, &idx);
        match r.decision {
            MatchDecision::MintedNew { best_score, alias } => {
                assert!((0.60..0.80).contains(&best_score), "{best_score}");
                assert_eq!(alias, Some(known_hash));
            }
            other => panic!("expected mint with alias, got {other:?}"),
        }
        assert_ne!(r.hash, known_hash);
    }

    #[test]
    fn new_below_the_floor_has_no_alias() {
        let known = base();
        let idx = seeded(&known);
        let mut d = descriptor("button", "Completely unrelated");
        d.tag = Some("button".into());
        d.attributes = attrs(&[("type", "submit"), ("id", "other")]);
        d.ancestor_roles = vec!["navigation".into()];
        d.container_text = None;
        d.bbox = Some(bbox(500.0, 500.0, 10.0, 10.0));
        let r = resolve(&d, &idx);
        match r.decision {
            MatchDecision::MintedNew { best_score, alias } => {
                assert!(best_score < 0.60, "{best_score}");
                assert_eq!(alias, None);
            }
            other => panic!("expected new identity, got {other:?}"),
        }
    }

    #[test]
    fn hard_gates_role_and_frame_lineage() {
        let idx = seeded(&base());
        let mut other_role = base();
        other_role.role = "link".into();
        assert!(matches!(
            resolve(&other_role, &idx).decision,
            MatchDecision::MintedNew {
                best_score,
                alias: None
            } if best_score == 0.0
        ));
        let mut other_frame = base();
        other_frame.frame_lineage = vec!["iframe-1".into()];
        assert!(matches!(
            resolve(&other_frame, &idx).decision,
            MatchDecision::MintedNew { alias: None, .. }
        ));
    }

    #[test]
    fn attribute_less_siblings_do_not_merge_on_structure() {
        let mut save = base();
        save.attributes.remove("id");
        save.accessible_name = Some("Save".into());
        let idx = seeded(&save);
        let mut delete = save.clone();
        delete.accessible_name = Some("Delete".into());
        let r = resolve(&delete, &idx);
        assert!(
            matches!(r.decision, MatchDecision::MintedNew { .. }),
            "Save and Delete must stay distinct: {:?}",
            r.decision
        );
    }

    #[test]
    fn same_name_in_different_named_landmarks_is_aliased_not_merged() {
        let mut featured = base();
        featured.attributes.remove("id");
        featured.accessible_name = Some("Add to cart".into());
        featured.container_text = Some("region|Featured".into());
        let idx = seeded(&featured);
        let known_hash = IdentityBuilder::hash(&IdentityBuilder::build(&featured, None)).unwrap();
        let mut clearance = featured.clone();
        clearance.container_text = Some("region|Clearance".into());
        let r = resolve(&clearance, &idx);
        match r.decision {
            MatchDecision::MintedNew { best_score, alias } => {
                assert!((0.60..0.80).contains(&best_score), "{best_score}");
                assert_eq!(alias, Some(known_hash));
            }
            other => panic!("expected an aliased mint, got {other:?}"),
        }
        // An unnamed container of the same kind is still weak positive evidence.
        assert!((container_similarity(Some("region"), Some("region:featured")) - 0.4).abs() < f32::EPSILON);
        assert!((container_similarity(Some("region:a"), Some("region:b")) + 1.0).abs() < f32::EPSILON);
        assert!(container_similarity(Some("region:a"), Some("form:a")).abs() < f32::EPSILON);
    }

    #[test]
    fn repeated_cards_share_identity_with_distinct_ordinals() {
        let page = card_page(&["Blue Widget", "Red Widget", "Green Widget"], 1, 3);
        let cands = CandidateDiscovery::discover(&page.bundle, &DiscoveryConfig::default());
        let mut idx = InMemoryIdentityIndex::new();
        let mut resolved = Vec::new();
        for c in &cands {
            let r = resolve(&c.descriptor, &idx);
            idx.record(&r);
            resolved.push(r);
        }
        assert!(matches!(
            resolved[0].decision,
            MatchDecision::MintedNew { alias: None, .. }
        ));
        for r in &resolved[1..] {
            assert_eq!(r.decision, MatchDecision::Reused { score: 1.0 });
            assert_eq!(r.hash, resolved[0].hash);
        }
        let ordinals: Vec<u32> = cands.iter().map(|c| c.descriptor.instance_ordinal).collect();
        assert_eq!(ordinals, vec![0, 1, 2]);
        assert_eq!(idx.len(), 1);
        assert_eq!(
            idx.get(&resolved[0].hash).unwrap().evidence_summary.observations,
            3
        );
        // locators stay per-instance
        assert_ne!(resolved[0].locator, resolved[1].locator);
    }

    #[test]
    fn record_remembers_aliases() {
        let known = base();
        let mut idx = seeded(&known);
        let mut d = base();
        d.attributes.insert("id".into(), "x-btn".into());
        d.accessible_name = Some("Save the draft".into());
        let r = resolve(&d, &idx);
        idx.record(&r);
        let MatchDecision::MintedNew { alias: Some(a), .. } = r.decision else {
            panic!("expected alias")
        };
        assert_eq!(idx.alias_of(&r.hash), Some(a));
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn resolver_with_destination_keys_links() {
        let mut a = descriptor("link", "View invoice");
        a.tag = Some("a".into());
        a.href = Some("/invoice/41".into());
        let mut b = a.clone();
        b.href = Some("/invoice/42".into());
        let mut c = a.clone();
        c.href = Some("/receipt/41".into());
        let resolver = IdentityResolver::with_destination(page_url(), CanonicalizeOptions::default());
        let mut idx = InMemoryIdentityIndex::new();
        let ra = resolver.resolve(&a, &idx, &MatchWeights::default()).unwrap();
        idx.record(&ra);
        assert_eq!(
            ra.identity.destination_key.as_deref(),
            Some("https://shop.example/invoice/:id")
        );
        let rb = resolver.resolve(&b, &idx, &MatchWeights::default()).unwrap();
        assert_eq!(rb.decision, MatchDecision::Reused { score: 1.0 });
        let rc = resolver.resolve(&c, &idx, &MatchWeights::default()).unwrap();
        assert!(matches!(rc.decision, MatchDecision::MintedNew { .. }));
        assert_ne!(rc.hash, ra.hash);
        // without a canonicalizer links carry no destination
        let plain = IdentityResolver::new()
            .resolve(&a, &InMemoryIdentityIndex::new(), &MatchWeights::default())
            .unwrap();
        assert_eq!(plain.identity.destination_key, None);
    }

    #[test]
    fn similarity_helpers() {
        assert_eq!(path_similarity(&[], &[]), 1.0);
        let a: Vec<String> = ["main", "list"].iter().map(|s| (*s).to_owned()).collect();
        let b: Vec<String> = ["main", "table"].iter().map(|s| (*s).to_owned()).collect();
        assert!((path_similarity(&a, &b) - 0.5).abs() < 1e-6);
        assert_eq!(path_similarity(&a, &[]), 0.0);
        assert_eq!(container_similarity(Some("dialog:a"), Some("dialog:b")), -1.0);
        assert_eq!(container_similarity(Some("dialog"), Some("dialog:b")), 0.4);
        assert_eq!(container_similarity(None, Some("heading")), 0.0);
        assert_eq!(name_similarity("", ""), 1.0);
        assert_eq!(name_similarity("a", ""), 0.0);
        assert!(name_similarity("save draft", "save drafts") > name_similarity("save draft", "delete"));
        assert_eq!(geometry_similarity(None, None), 0.5);
        let b1 = bbox(0.0, 0.0, 10.0, 10.0);
        assert_eq!(geometry_similarity(Some(&b1), Some(&b1)), 1.0);
        assert_eq!(
            geometry_similarity(Some(&b1), Some(&bbox(20.0, 20.0, 5.0, 5.0))),
            0.0
        );
    }
}
