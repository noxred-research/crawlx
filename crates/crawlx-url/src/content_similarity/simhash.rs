//! 64-bit Charikar simhash over weighted string features.
//!
//! Ported from projectdiscovery/katana `pkg/similarity/simhash.go` at commit
//! 9662cd7 (MIT). Features are hashed with FNV-1a 64 so fingerprints are
//! stable across processes and platforms (`crawlx-state` has its own simhash
//! for browser states; layering keeps the two separate).

use std::collections::BTreeMap;

/// FNV-1a 64-bit hash of `s`.
#[must_use]
pub fn fnv1a_64(s: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    s.bytes()
        .fold(OFFSET, |h, b| (h ^ u64::from(b)).wrapping_mul(PRIME))
}

/// Simhash of `features`, each weighted by its multiplicity; `0` for none.
#[must_use]
pub fn simhash64<S: AsRef<str>>(features: &[S]) -> u64 {
    if features.is_empty() {
        return 0;
    }
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for f in features {
        *counts.entry(f.as_ref()).or_default() += 1;
    }
    let mut weights = [0i64; 64];
    for (feature, weight) in counts {
        let h = fnv1a_64(feature);
        for (bit, w) in weights.iter_mut().enumerate() {
            if (h >> bit) & 1 == 1 {
                *w += weight;
            } else {
                *w -= weight;
            }
        }
    }
    weights
        .iter()
        .enumerate()
        .filter(|(_, w)| **w > 0)
        .fold(0u64, |fp, (bit, _)| fp | (1u64 << bit))
}

/// Number of differing bits.
#[must_use]
pub const fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::super::normalize::{html_page, normalize, shingles, tokenize};
    use super::*;

    #[test]
    fn fnv1a_known_vectors() {
        assert_eq!(fnv1a_64(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a_64("a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a_64("foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn similar_text_close_unrelated_far() {
        let base = tokenize("the quick brown fox jumps over the lazy dog again today while another fox waits beside the river bank under morning sunlight near the wooden bridge");
        let edited = tokenize("the quick black fox jumps over the lazy dog again today while another fox waits beside the river bank under morning sunlight near the wooden bridge");
        let unrelated = tokenize("kubernetes cluster orchestration scheduler pod node affinity ingress service mesh control plane etcd api server controller manager kubelet runtime");
        let a = simhash64(&shingles(&base, 3));
        let b = simhash64(&shingles(&edited, 3));
        let c = simhash64(&shingles(&unrelated, 3));
        assert!(hamming_distance(a, b) < hamming_distance(a, c));
        assert!(hamming_distance(a, c) > 10);
        assert_eq!(hamming_distance(a, a), 0);
        assert_eq!(simhash64::<&str>(&[]), 0);
    }

    #[test]
    fn near_identical_pages_within_default_band() {
        let product = |id: u32| {
            html_page(
                "Home Shop Cart Account Help",
                &format!("Product {id} crimson Exclusive cotton shirt available in multiple sizes with free shipping worldwide today only"),
            )
        };
        let a = normalize(&product(1)).unwrap();
        let b = normalize(&product(2)).unwrap();
        assert!(hamming_distance(simhash64(&a.shingles), simhash64(&b.shingles)) <= 3);
    }
}
