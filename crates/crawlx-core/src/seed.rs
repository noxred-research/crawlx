//! Seeded randomness. All tie-breaks and generated
//! values derive from `crawl_seed`; `rand::rng` (formerly `rand::thread_rng`) is lint-denied.

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};

/// The run seed recorded on `crawl_runs.seed`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
#[serde(transparent)]
pub struct CrawlSeed(pub u64);

impl CrawlSeed {
    /// Derive a 32-byte seed for `purpose` and arbitrary context bytes.
    #[must_use]
    pub fn derive(&self, purpose: &str, context: &[&[u8]]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"crawlx/seed/v1");
        h.update(&[0]);
        h.update(&self.0.to_le_bytes());
        h.update(purpose.as_bytes());
        for c in context {
            h.update(&[0]);
            h.update(&(c.len() as u64).to_le_bytes());
            h.update(c);
        }
        *h.finalize().as_bytes()
    }

    /// A deterministic RNG for `purpose` + context.
    #[must_use]
    pub fn rng(&self, purpose: &str, context: &[&[u8]]) -> ChaCha8Rng {
        ChaCha8Rng::from_seed(self.derive(purpose, context))
    }

    /// One uniform draw in `0..1000` for `purpose` + context: the first eight bytes of the
    /// derived seed reduced modulo 1000 (the bias of that reduction is below 2^-50). A pure
    /// function of the run seed and its inputs, so a replay recomputes the same value.
    #[must_use]
    pub fn draw_per_mille(&self, purpose: &str, context: &[&[u8]]) -> u16 {
        let derived = self.derive(purpose, context);
        let mut head = [0u8; 8];
        head.copy_from_slice(&derived[..8]);
        u16::try_from(u64::from_le_bytes(head) % 1000).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use rand::Rng as _;

    #[test]
    fn same_inputs_same_stream() {
        let a = CrawlSeed(7).rng("tie", &[b"s1", &1u64.to_le_bytes()]).next_u64();
        let b = CrawlSeed(7).rng("tie", &[b"s1", &1u64.to_le_bytes()]).next_u64();
        let c = CrawlSeed(8).rng("tie", &[b"s1", &1u64.to_le_bytes()]).next_u64();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn per_mille_draw_is_stable_bounded_and_seed_dependent() {
        let draws: Vec<u16> = (0u64..200)
            .map(|n| CrawlSeed(7).draw_per_mille("predictor", &[&n.to_le_bytes()]))
            .collect();
        let again: Vec<u16> = (0u64..200)
            .map(|n| CrawlSeed(7).draw_per_mille("predictor", &[&n.to_le_bytes()]))
            .collect();
        let other: Vec<u16> = (0u64..200)
            .map(|n| CrawlSeed(8).draw_per_mille("predictor", &[&n.to_le_bytes()]))
            .collect();
        assert_eq!(draws, again);
        assert_ne!(draws, other);
        assert!(draws.iter().all(|d| *d < 1000));
        assert!(draws.iter().any(|d| *d < 100) && draws.iter().any(|d| *d >= 900));
    }
}
