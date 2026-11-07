//! MinHash with k = 128 permutations `h_i(x) = a_i·x + b_i (mod 2^64)`.
//!
//! The constants are derived from a fixed seed (never the crawl seed) so
//! signatures are comparable across runs, builds and machines. Each slot
//! stores the high 32 bits of the minimum (512 B of information per
//! signature), zero-extended into the `u64` the shared `StateSignature`
//! field uses.

use crate::text::mix64;
use std::sync::LazyLock;

/// Number of hash functions.
pub const K: usize = 128;

/// Fixed seed for the permutation constants. Changing it invalidates every
/// stored signature.
const PERMUTATION_SEED: u64 = 0x6372_6177_6c78_6d68; // "crawlxmh"

/// The slot value of an empty set.
pub const EMPTY_SLOT: u64 = u32::MAX as u64;

/// A bank of `K` affine permutations.
#[derive(Debug)]
pub struct MinHasher {
    a: [u64; K],
    b: [u64; K],
}

impl MinHasher {
    fn build() -> Self {
        let mut a = [0u64; K];
        let mut b = [0u64; K];
        let mut state = PERMUTATION_SEED;
        for i in 0..K {
            state = mix64(state);
            a[i] = state | 1; // odd multiplier => bijection mod 2^64
            state = mix64(state);
            b[i] = state;
        }
        Self { a, b }
    }

    /// The process-wide hasher with the fixed constants.
    #[must_use]
    pub fn standard() -> &'static Self {
        static HASHER: LazyLock<MinHasher> = LazyLock::new(MinHasher::build);
        &HASHER
    }

    /// MinHash signature of a set of 64-bit element hashes. Duplicates are
    /// harmless. The empty set yields [`EMPTY_SLOT`] in every slot.
    #[must_use]
    pub fn signature(&self, elements: impl IntoIterator<Item = u64>) -> Vec<u64> {
        let mut mins = [u64::MAX; K];
        for x in elements {
            for (i, m) in mins.iter_mut().enumerate() {
                let v = self.a[i].wrapping_mul(x).wrapping_add(self.b[i]);
                if v < *m {
                    *m = v;
                }
            }
        }
        mins.iter().map(|m| m >> 32).collect()
    }
}

/// Fraction of equal slots: the unbiased Jaccard estimate. Signatures of
/// different length (or empty) estimate 0.
#[must_use]
pub fn jaccard_estimate(a: &[u64], b: &[u64]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let equal = a.iter().zip(b).filter(|(x, y)| x == y).count();
    equal as f32 / a.len() as f32
}

/// MinHash of the union of two sets is the slot-wise minimum.
pub fn union_into(acc: &mut [u64], other: &[u64]) {
    for (a, b) in acc.iter_mut().zip(other) {
        if *b < *a {
            *a = *b;
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn set(range: std::ops::Range<u64>) -> Vec<u64> {
        range.map(|i| mix64(i ^ 0xabcdef)).collect()
    }

    #[test]
    fn identical_sets_match_exactly() {
        let h = MinHasher::standard();
        let a = h.signature(set(0..50));
        let b = h.signature(set(0..50).into_iter().rev());
        assert_eq!(a, b);
        assert_eq!(a.len(), K);
        assert!((jaccard_estimate(&a, &b) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn estimate_tracks_true_jaccard() {
        let h = MinHasher::standard();
        // |A ∩ B| = 60, |A ∪ B| = 100 -> J = 0.6
        let a = h.signature(set(0..80));
        let b = h.signature(set(20..100));
        let est = jaccard_estimate(&a, &b);
        assert!((est - 0.6).abs() < 0.15, "estimate {est}");
        let disjoint = h.signature(set(1000..1080));
        assert!(jaccard_estimate(&a, &disjoint) < 0.1);
    }

    #[test]
    fn union_is_slotwise_min_of_union_set() {
        let h = MinHasher::standard();
        let mut u = h.signature(set(0..30));
        union_into(&mut u, &h.signature(set(20..60)));
        assert_eq!(u, h.signature(set(0..60)));
    }

    #[test]
    fn empty_set_is_all_max() {
        let h = MinHasher::standard();
        let e = h.signature(std::iter::empty());
        assert!(e.iter().all(|s| *s == EMPTY_SLOT));
        assert!((jaccard_estimate(&e, &e) - 1.0).abs() < f32::EPSILON);
    }
}
