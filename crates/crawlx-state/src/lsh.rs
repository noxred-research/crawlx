//! Banded locality-sensitive hashing over MinHash signatures
//! (32 bands × 4 rows; `P(candidate | J) = 1 − (1 − J⁴)³²`).

use crate::text::{mix64, Hasher64};
use std::collections::BTreeMap;
// Lookup-only maps: never iterated, and `query` sorts its output, so hash order cannot leak.
#[allow(
    clippy::disallowed_types,
    reason = "lookup-only; never iterated, query output is sorted"
)]
use std::collections::HashMap;
use std::hash::Hash;

/// Bands in the index.
pub const BANDS: usize = 32;
/// Rows (signature slots) per band.
pub const ROWS: usize = 4;

const _: () = assert!(BANDS <= u8::MAX as usize, "band index is stored as u8");

/// Candidate index keyed by an arbitrary item id.
#[derive(Debug, Clone)]
pub struct LshIndex<K: Copy + Eq + Hash + Ord> {
    #[allow(
        clippy::disallowed_types,
        reason = "lookup-only; never iterated, query output is sorted"
    )]
    buckets: Vec<HashMap<u64, Vec<K>>>,
    keys_of: BTreeMap<K, Vec<(u8, u64)>>,
}

impl<K: Copy + Eq + Hash + Ord> Default for LshIndex<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// The band keys of a signature; empty when the signature is too short.
#[must_use]
pub fn band_keys(signature: &[u64]) -> Vec<u64> {
    if signature.len() < BANDS * ROWS {
        return Vec::new();
    }
    (0..BANDS)
        .map(|b| {
            let mut h = Hasher64::new();
            for v in &signature[b * ROWS..(b + 1) * ROWS] {
                h.write(&v.to_le_bytes());
            }
            // band index participates so equal rows in different bands do not collide
            mix64(h.finish() ^ ((b as u64) << 56))
        })
        .collect()
}

impl<K: Copy + Eq + Hash + Ord> LshIndex<K> {
    /// Empty index with one bucket map per band.
    #[must_use]
    #[allow(
        clippy::disallowed_types,
        reason = "lookup-only; never iterated, query output is sorted"
    )]
    pub fn new() -> Self {
        Self {
            buckets: (0..BANDS).map(|_| HashMap::new()).collect(),
            keys_of: BTreeMap::new(),
        }
    }

    /// Number of distinct items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys_of.len()
    }

    /// `true` when no item is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys_of.is_empty()
    }

    /// Add `signature` for `item`. Inserting again (e.g. after the item's
    /// signature grew) accumulates band keys; stale keys only cost extra
    /// candidates, never recall.
    pub fn insert(&mut self, item: K, signature: &[u64]) {
        let keys = band_keys(signature);
        let owned = self.keys_of.entry(item).or_default();
        // `BANDS` fits `u8`; zipping with a `u8` range avoids a narrowing cast
        for (band, key) in (0..).zip(keys) {
            let tag: (u8, u64) = (band, key);
            if owned.contains(&tag) {
                continue;
            }
            owned.push(tag);
            self.buckets[usize::from(band)].entry(key).or_default().push(item);
        }
    }

    /// Remove every entry of `item`.
    pub fn remove(&mut self, item: K) {
        let Some(owned) = self.keys_of.remove(&item) else {
            return;
        };
        for (band, key) in owned {
            let bucket = &mut self.buckets[usize::from(band)];
            if let Some(items) = bucket.get_mut(&key) {
                items.retain(|i| *i != item);
                if items.is_empty() {
                    bucket.remove(&key);
                }
            }
        }
    }

    /// Distinct items sharing at least one band with `signature`, sorted.
    #[must_use]
    pub fn query(&self, signature: &[u64]) -> Vec<K> {
        let mut out: Vec<K> = Vec::new();
        for (band, key) in band_keys(signature).into_iter().enumerate() {
            if let Some(items) = self.buckets[band].get(&key) {
                out.extend(items.iter().copied());
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::minhash::MinHasher;

    fn elems(range: std::ops::Range<u64>) -> impl Iterator<Item = u64> {
        range.map(|i| mix64(i.wrapping_mul(0x1234_5678_9abc_def1)))
    }

    #[test]
    fn insert_query_remove() {
        let h = MinHasher::standard();
        let mut idx = LshIndex::new();
        let s = h.signature(elems(0..40));
        idx.insert(7u32, &s);
        idx.insert(9u32, &h.signature(elems(500..540)));
        assert_eq!(idx.query(&s), vec![7]);
        assert_eq!(idx.len(), 2);
        idx.remove(7);
        assert!(idx.query(&s).is_empty());
        assert_eq!(idx.len(), 1);
        idx.remove(7); // idempotent
    }

    /// 200 synthetic signatures: set `i` shares `overlap` of `base` elements
    /// with the query set, giving a controlled Jaccard. High-Jaccard items
    /// must be recalled; the recall curve follows `1 - (1 - J^4)^32`.
    #[test]
    fn candidate_recall_follows_theory() {
        let h = MinHasher::standard();
        let universe = 100u64;
        let query_set: Vec<u64> = elems(0..universe).collect();
        let query = h.signature(query_set.iter().copied());

        let mut idx = LshIndex::new();
        let mut jaccards = Vec::new();
        for i in 0u32..200 {
            // keep `keep` of the query elements, add `extra` fresh ones; J = keep / (100 + extra)
            let keep = 60 + u64::from(i % 41); // 60..=100
            let extra = u64::from(i % 7) * 3;
            let fresh_base = 10_000 + u64::from(i) * 1_000;
            let set: Vec<u64> = query_set[..usize::try_from(keep).unwrap()]
                .iter()
                .copied()
                .chain(elems(fresh_base..fresh_base + extra))
                .collect();
            let j = keep as f64 / (universe + extra) as f64;
            idx.insert(i, &h.signature(set));
            jaccards.push(j);
        }
        let hits = idx.query(&query);
        let mut expected = 0.0f64;
        let mut got_high = 0usize;
        let mut total_high = 0usize;
        for (i, j) in jaccards.iter().enumerate() {
            let p = 1.0 - (1.0 - j.powi(4)).powi(32);
            expected += p;
            if *j >= 0.7 {
                total_high += 1;
                if hits.contains(&u32::try_from(i).unwrap()) {
                    got_high += 1;
                }
            }
        }
        assert!(total_high > 50, "fixture must contain many high-J items");
        assert!(
            got_high as f64 >= 0.98 * total_high as f64,
            "recall at J>=0.7: {got_high}/{total_high}"
        );
        // overall hit count within a loose band of the theoretical expectation
        let observed = hits.len() as f64;
        assert!(
            (observed - expected).abs() < 0.15 * 200.0,
            "observed {observed}, expected {expected:.1}"
        );
    }

    #[test]
    fn short_signature_has_no_bands() {
        assert!(band_keys(&[1, 2, 3]).is_empty());
        let mut idx = LshIndex::new();
        idx.insert(1u8, &[1, 2]);
        assert!(idx.query(&[1, 2]).is_empty());
    }
}
