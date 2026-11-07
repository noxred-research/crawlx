//! 64-bit SimHash and Hamming distance.

use crate::text::mix64;

/// SimHash over already-hashed features (each feature votes with weight 1).
/// An empty feature stream hashes to 0.
#[must_use]
pub fn simhash(features: impl IntoIterator<Item = u64>) -> u64 {
    let mut votes = [0i32; 64];
    for f in features {
        for (bit, v) in votes.iter_mut().enumerate() {
            if (f >> bit) & 1 == 1 {
                *v += 1;
            } else {
                *v -= 1;
            }
        }
    }
    let mut out = 0u64;
    for (bit, v) in votes.iter().enumerate() {
        if *v > 0 {
            out |= 1 << bit;
        }
    }
    out
}

/// Shingles of `width` consecutive tokens, each combined into one feature.
/// A stream shorter than `width` yields one feature over the whole stream so
/// tiny pages still produce a non-zero fingerprint.
#[must_use]
pub fn shingles(tokens: &[u64], width: usize) -> Vec<u64> {
    if tokens.is_empty() || width == 0 {
        return Vec::new();
    }
    let combine = |window: &[u64]| {
        let mut h = 0x5151_5151_5151_5151u64;
        for t in window {
            h = mix64(h ^ *t);
        }
        h
    };
    if tokens.len() < width {
        return vec![combine(tokens)];
    }
    tokens.windows(width).map(combine).collect()
}

/// Hamming distance between two SimHashes.
#[inline]
#[must_use]
pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// `1 - hamming/64` in `[0, 1]`.
#[inline]
#[must_use]
pub fn similarity(a: u64, b: u64) -> f32 {
    1.0 - hamming(a, b) as f32 / 64.0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn stream(n: u64) -> Vec<u64> {
        (0..n).map(|i| mix64(i % 37 + (i / 11) * 1000)).collect()
    }

    #[test]
    fn identical_streams_have_zero_distance() {
        let s = shingles(&stream(300), 3);
        assert_eq!(hamming(simhash(s.iter().copied()), simhash(s.iter().copied())), 0);
    }

    #[test]
    fn small_edit_gives_small_distance() {
        let base: Vec<u64> = (0..400).map(|i| mix64(i + 1)).collect();
        let a = simhash(shingles(&base, 3));
        let mut inserted = base.clone();
        inserted.insert(200, mix64(0xdead_beef));
        let b = simhash(shingles(&inserted, 3));
        assert!(hamming(a, b) <= 6, "insert distance {}", hamming(a, b));
        let mut replaced = base.clone();
        replaced[50] = mix64(0xfeed);
        let c = simhash(shingles(&replaced, 3));
        assert!(hamming(a, c) <= 6, "replace distance {}", hamming(a, c));
        let unrelated: Vec<u64> = (0..400).map(|i| mix64(i + 9_999_999)).collect();
        let d = simhash(shingles(&unrelated, 3));
        assert!(hamming(a, d) > 12, "unrelated distance {}", hamming(a, d));
    }

    #[test]
    fn short_streams_and_empty() {
        assert_eq!(simhash(shingles(&[], 3)), 0);
        assert_eq!(shingles(&[1, 2], 3).len(), 1);
        assert!((similarity(0, u64::MAX)).abs() < f32::EPSILON);
        assert!((similarity(7, 7) - 1.0).abs() < f32::EPSILON);
    }
}
