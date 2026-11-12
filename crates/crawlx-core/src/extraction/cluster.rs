//! Deterministic embedding-cluster extraction over source ranges of the final text.
//!
//! The caller supplies one vector per source range (the model call lives in `crawlx-model`; this
//! module is pure arithmetic). Ranges are grouped with spherical k-means: vectors are
//! normalized, the first centroid is chosen from a seeded stream, the others by farthest-first
//! traversal, and Lloyd iterations assign each range to the most similar centroid. Every tie
//! breaks toward the lowest index and the input is first put in a canonical order (range start,
//! then end), so the result depends on the seed and the ranges, never on input order or hash
//! iteration order. Output is source-only: byte ranges into the exact final text plus a
//! cohesion score, no copied page text.
//!
//! A hard vector cap bounds memory and the embedding bill before any vector exists; one range
//! over the cap fails with [`ClusterErrorV1::TooManyVectors`] and nothing is truncated.

use super::SourceRangeV1;
use crate::hash::Digest;
use crate::seed::CrawlSeed;
use rand::Rng as _;
use serde::{Deserialize, Serialize};

const IMPLEMENTATION: &str = "native_spherical_kmeans_v1";
/// Most source ranges (vectors) one clustering run accepts.
pub const MAX_CLUSTER_VECTORS: usize = 512;
/// Most clusters one run produces.
pub const MAX_CLUSTERS: usize = 64;
/// Most Lloyd iterations one run performs.
pub const MAX_CLUSTER_ITERATIONS: u32 = 100;
/// Widest vector accepted.
pub const MAX_CLUSTER_DIMENSIONS: usize = 4096;
/// Longest model label recorded on the envelope, in bytes.
pub const MAX_CLUSTER_MODEL_LABEL: usize = 128;
const SEED_PURPOSE: &str = "extract.cluster.init.v1";

/// Versioned clustering policy. Every limit is inclusive; one over fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ClusterPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Requested cluster count, `1..=`[`MAX_CLUSTERS`]; fewer when there are fewer ranges.
    pub clusters: usize,
    /// Source-range (vector) ceiling, `1..=`[`MAX_CLUSTER_VECTORS`], checked before embedding.
    pub max_vectors: usize,
    /// Lloyd iteration ceiling, `1..=`[`MAX_CLUSTER_ITERATIONS`].
    pub max_iterations: u32,
}
impl Default for ClusterPolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            clusters: 3,
            max_vectors: 256,
            max_iterations: 25,
        }
    }
}
impl ClusterPolicyV1 {
    /// Check version and every hard ceiling.
    ///
    /// # Errors
    /// [`ClusterErrorV1::InvalidPolicy`] for an unknown version or a limit outside its range.
    pub fn validate(&self) -> Result<(), ClusterErrorV1> {
        if self.version != 1
            || !(1..=MAX_CLUSTERS).contains(&self.clusters)
            || !(1..=MAX_CLUSTER_VECTORS).contains(&self.max_vectors)
            || !(1..=MAX_CLUSTER_ITERATIONS).contains(&self.max_iterations)
        {
            return Err(ClusterErrorV1::InvalidPolicy);
        }
        Ok(())
    }

    /// Refuse `count` ranges above [`Self::max_vectors`] before any embedding work starts.
    ///
    /// # Errors
    /// [`ClusterErrorV1::InvalidPolicy`] or [`ClusterErrorV1::TooManyVectors`].
    pub fn check_count(&self, count: usize) -> Result<(), ClusterErrorV1> {
        self.validate()?;
        if count > self.max_vectors {
            return Err(ClusterErrorV1::TooManyVectors {
                count,
                max: self.max_vectors,
            });
        }
        Ok(())
    }
}

/// One cluster: its member ranges in text order and how tightly they sit around the centroid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ClusterV1 {
    /// Member source ranges in text order; every input range is a member of exactly one cluster.
    pub members: Vec<SourceRangeV1>,
    /// Mean cosine similarity of the members to the centroid in thousandths, `0..=1000`
    /// (negative similarity counts as zero).
    pub cohesion_millis: u16,
}

/// Source-only clusters bound to the exact final text and the effective policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ClusterEnvelopeV1 {
    /// Exactly one.
    pub version: u16,
    /// Pinned clustering implementation.
    pub implementation: String,
    /// Complete effective policy.
    pub policy: ClusterPolicyV1,
    /// Label of the embedding model that produced the vectors (not a credential).
    pub model: String,
    /// Dimension of every vector.
    pub dimensions: usize,
    /// Lloyd iterations performed.
    pub iterations: u32,
    /// The assignment reached a fixed point before the iteration ceiling.
    pub converged: bool,
    /// Domain-separated digest of the exact final text bytes.
    pub final_text_digest: Digest,
    /// Clusters ordered by their first member's position in the text.
    pub clusters: Vec<ClusterV1>,
}

/// Typed failures never return a partial clustering.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClusterErrorV1 {
    /// Policy version or a hard bound is invalid.
    #[error("invalid cluster policy")]
    InvalidPolicy,
    /// More source ranges than the policy allows; nothing was embedded or truncated.
    #[error("cluster input of {count} ranges exceeds the cap of {max}")]
    TooManyVectors {
        /// Ranges supplied.
        count: usize,
        /// Policy ceiling.
        max: usize,
    },
    /// The ranges and vectors do not describe one consistent input.
    #[error("invalid cluster input: {0}")]
    InvalidInput(&'static str),
    /// Checked arithmetic could not represent an index or count.
    #[error("cluster arithmetic overflow")]
    Arithmetic,
    /// Persisted clusters no longer match the exact final text or policy.
    #[error("cluster envelope does not match the finalized text and policy")]
    InvalidEnvelope,
}

fn text_digest(text: &str) -> Digest {
    Digest::of("crawlx.extract.cluster.final_text.v1", text.as_bytes())
}

impl ClusterEnvelopeV1 {
    /// Check that `ranges` are non-empty, in-bounds, UTF-8-aligned and pairwise distinct, so a
    /// caller can refuse bad input before it pays for any embedding.
    ///
    /// # Errors
    /// [`ClusterErrorV1::InvalidInput`] naming the first problem.
    pub fn check_ranges(text: &str, ranges: &[SourceRangeV1]) -> Result<(), ClusterErrorV1> {
        canonical_order(text, ranges).map(|_| ())
    }

    /// Cluster `ranges` of `text` by their `vectors` (one per range, same order).
    ///
    /// The result is the same for the same seed, ranges and vectors whatever order the pairs are
    /// supplied in.
    ///
    /// # Errors
    /// A typed failure for an invalid policy, a count above the cap, mismatched, empty,
    /// duplicated, out-of-bounds or non-boundary ranges, ragged or non-finite vectors, or an
    /// over-long model label.
    pub fn build(
        text: &str,
        ranges: &[SourceRangeV1],
        vectors: &[Vec<f32>],
        model: &str,
        policy: ClusterPolicyV1,
        seed: CrawlSeed,
    ) -> Result<Self, ClusterErrorV1> {
        policy.check_count(ranges.len())?;
        if ranges.len() != vectors.len() {
            return Err(ClusterErrorV1::InvalidInput("range and vector counts differ"));
        }
        if ranges.is_empty() {
            return Err(ClusterErrorV1::InvalidInput("no ranges"));
        }
        if model.len() > MAX_CLUSTER_MODEL_LABEL {
            return Err(ClusterErrorV1::InvalidInput("model label too long"));
        }
        let dimensions = vectors.first().map_or(0, Vec::len);
        if dimensions == 0 || dimensions > MAX_CLUSTER_DIMENSIONS {
            return Err(ClusterErrorV1::InvalidInput("vector dimension out of range"));
        }
        let order = canonical_order(text, ranges)?;
        let mut unit: Vec<Vec<f64>> = Vec::with_capacity(order.len());
        for &index in &order {
            let vector = vectors
                .get(index)
                .ok_or(ClusterErrorV1::InvalidInput("vector index"))?;
            unit.push(normalized(vector, dimensions)?);
        }
        let ordered: Vec<SourceRangeV1> = order.iter().filter_map(|&i| ranges.get(i).copied()).collect();
        let k = policy.clusters.min(unit.len());
        let mut centroids = initial_centroids(&unit, k, text, seed)?;
        let mut assignment = vec![0_usize; unit.len()];
        let mut iterations = 0_u32;
        let mut converged = false;
        while iterations < policy.max_iterations {
            iterations = iterations.checked_add(1).ok_or(ClusterErrorV1::Arithmetic)?;
            let next: Vec<usize> = unit.iter().map(|v| nearest(&centroids, v)).collect();
            let stable = next == assignment && iterations > 1;
            assignment = next;
            if stable {
                converged = true;
                break;
            }
            recompute(&mut centroids, &unit, &assignment, dimensions);
        }
        let clusters = collect(&ordered, &unit, &centroids, &assignment, k)?;
        Ok(Self {
            version: 1,
            implementation: IMPLEMENTATION.into(),
            policy,
            model: model.into(),
            dimensions,
            iterations,
            converged,
            final_text_digest: text_digest(text),
            clusters,
        })
    }

    /// Check implementation, policy, digest and that every member is an in-bounds, UTF-8-aligned,
    /// non-empty range belonging to exactly one cluster, with clusters ordered by first member.
    ///
    /// # Errors
    /// [`ClusterErrorV1::InvalidEnvelope`] for any mismatch, [`ClusterErrorV1::InvalidPolicy`]
    /// for an invalid policy.
    pub fn validate(&self, text: &str, policy: &ClusterPolicyV1) -> Result<(), ClusterErrorV1> {
        policy.validate()?;
        if self.version != 1
            || self.implementation != IMPLEMENTATION
            || self.policy != *policy
            || self.final_text_digest != text_digest(text)
            || self.clusters.is_empty()
            || self.clusters.len() > policy.clusters
        {
            return Err(ClusterErrorV1::InvalidEnvelope);
        }
        let mut seen: Vec<SourceRangeV1> = Vec::new();
        let mut previous_first: Option<usize> = None;
        for cluster in &self.clusters {
            let first = cluster.members.first().ok_or(ClusterErrorV1::InvalidEnvelope)?;
            if previous_first.is_some_and(|p| p >= first.start) || cluster.cohesion_millis > 1000 {
                return Err(ClusterErrorV1::InvalidEnvelope);
            }
            previous_first = Some(first.start);
            if cluster
                .members
                .windows(2)
                .any(|pair| pair[0].start >= pair[1].start)
            {
                return Err(ClusterErrorV1::InvalidEnvelope);
            }
            for member in &cluster.members {
                if member.start >= member.end
                    || !text.is_char_boundary(member.start)
                    || !text.is_char_boundary(member.end)
                    || member.end > text.len()
                {
                    return Err(ClusterErrorV1::InvalidEnvelope);
                }
                seen.push(*member);
            }
        }
        if seen.len() > policy.max_vectors {
            return Err(ClusterErrorV1::InvalidEnvelope);
        }
        seen.sort_by_key(|r| (r.start, r.end));
        if seen.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ClusterErrorV1::InvalidEnvelope);
        }
        Ok(())
    }
}

/// Indices of `ranges` sorted by `(start, end)`, after refusing empty, out-of-bounds,
/// non-boundary and duplicate ranges.
fn canonical_order(text: &str, ranges: &[SourceRangeV1]) -> Result<Vec<usize>, ClusterErrorV1> {
    for range in ranges {
        if range.start >= range.end
            || range.end > text.len()
            || !text.is_char_boundary(range.start)
            || !text.is_char_boundary(range.end)
        {
            return Err(ClusterErrorV1::InvalidInput(
                "range out of bounds or not on a UTF-8 boundary",
            ));
        }
    }
    let mut order: Vec<usize> = (0..ranges.len()).collect();
    order.sort_by_key(|&i| {
        ranges
            .get(i)
            .map_or((usize::MAX, usize::MAX), |r| (r.start, r.end))
    });
    let duplicate = order
        .windows(2)
        .any(|pair| ranges.get(pair[0]) == ranges.get(pair[1]));
    if duplicate {
        return Err(ClusterErrorV1::InvalidInput("duplicate range"));
    }
    Ok(order)
}

/// Unit-length copy of `vector`; the zero vector stays zero.
fn normalized(vector: &[f32], dimensions: usize) -> Result<Vec<f64>, ClusterErrorV1> {
    if vector.len() != dimensions {
        return Err(ClusterErrorV1::InvalidInput("vectors differ in dimension"));
    }
    let mut out = Vec::with_capacity(dimensions);
    let mut norm = 0.0_f64;
    for &value in vector {
        if !value.is_finite() {
            return Err(ClusterErrorV1::InvalidInput("non-finite vector component"));
        }
        let wide = f64::from(value);
        norm += wide * wide;
        out.push(wide);
    }
    let norm = norm.sqrt();
    if norm > 0.0 {
        for component in &mut out {
            *component /= norm;
        }
    }
    Ok(out)
}

fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// Seeded first centroid, then farthest-first (largest minimum cosine distance, lowest index).
fn initial_centroids(
    unit: &[Vec<f64>],
    k: usize,
    text: &str,
    seed: CrawlSeed,
) -> Result<Vec<Vec<f64>>, ClusterErrorV1> {
    let digest = text_digest(text);
    let mut rng = seed.rng(SEED_PURPOSE, &[&digest.0]);
    let count = u64::try_from(unit.len()).map_err(|_| ClusterErrorV1::Arithmetic)?;
    let first = usize::try_from(rng.next_u64() % count).map_err(|_| ClusterErrorV1::Arithmetic)?;
    let mut chosen = vec![first];
    let mut nearest_similarity: Vec<f64> = unit
        .iter()
        .map(|v| unit.get(first).map_or(0.0, |c| dot(v, c)))
        .collect();
    while chosen.len() < k {
        let mut best: Option<(usize, f64)> = None;
        for (index, similarity) in nearest_similarity.iter().enumerate() {
            if chosen.contains(&index) {
                continue;
            }
            if best.is_none_or(|(_, s)| *similarity < s) {
                best = Some((index, *similarity));
            }
        }
        let Some((next, _)) = best else { break };
        chosen.push(next);
        if let Some(centroid) = unit.get(next) {
            for (similarity, v) in nearest_similarity.iter_mut().zip(unit) {
                *similarity = similarity.max(dot(v, centroid));
            }
        }
    }
    Ok(chosen
        .iter()
        .filter_map(|&index| unit.get(index).cloned())
        .collect())
}

/// Index of the most similar centroid; ties go to the lowest index.
fn nearest(centroids: &[Vec<f64>], vector: &[f64]) -> usize {
    let mut best = (0_usize, f64::NEG_INFINITY);
    for (index, centroid) in centroids.iter().enumerate() {
        let similarity = dot(vector, centroid);
        if similarity > best.1 {
            best = (index, similarity);
        }
    }
    best.0
}

/// Mean of each cluster's members, re-normalized; an empty cluster keeps its centroid.
fn recompute(centroids: &mut [Vec<f64>], unit: &[Vec<f64>], assignment: &[usize], dimensions: usize) {
    for (cluster, centroid) in centroids.iter_mut().enumerate() {
        let mut sum = vec![0.0_f64; dimensions];
        let mut members = 0_usize;
        for (vector, &assigned) in unit.iter().zip(assignment) {
            if assigned == cluster {
                members += 1;
                for (total, component) in sum.iter_mut().zip(vector) {
                    *total += component;
                }
            }
        }
        if members == 0 {
            continue;
        }
        let norm = sum.iter().map(|x| x * x).sum::<f64>().sqrt();
        if norm > 0.0 {
            for component in &mut sum {
                *component /= norm;
            }
            *centroid = sum;
        }
    }
}

/// Group the canonical members, drop empty clusters, order clusters by first member.
fn collect(
    ordered: &[SourceRangeV1],
    unit: &[Vec<f64>],
    centroids: &[Vec<f64>],
    assignment: &[usize],
    k: usize,
) -> Result<Vec<ClusterV1>, ClusterErrorV1> {
    let mut clusters = Vec::new();
    for cluster in 0..k {
        let mut members = Vec::new();
        let mut similarity = 0.0_f64;
        for ((range, vector), &assigned) in ordered.iter().zip(unit).zip(assignment) {
            if assigned == cluster {
                members.push(*range);
                similarity += centroids.get(cluster).map_or(0.0, |c| dot(vector, c)).max(0.0);
            }
        }
        if members.is_empty() {
            continue;
        }
        let count = f64::from(u32::try_from(members.len()).map_err(|_| ClusterErrorV1::Arithmetic)?);
        let scaled = (similarity / count).clamp(0.0, 1.0) * 1000.0;
        // `scaled` lies in `0.0..=1000.0`, so the rounded value always fits `u16`.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let millis = scaled.round() as u16;
        clusters.push(ClusterV1 {
            members,
            cohesion_millis: millis,
        });
    }
    clusters.sort_by_key(|c| c.members.first().map_or(usize::MAX, |r| r.start));
    if clusters.is_empty() {
        return Err(ClusterErrorV1::Arithmetic);
    }
    Ok(clusters)
}
