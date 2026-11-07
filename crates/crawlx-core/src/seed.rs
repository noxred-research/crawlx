//! Seeded randomness. All tie-breaks and generated
//! values derive from `crawl_seed`; `rand::thread_rng` is lint-denied.

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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use rand::RngCore as _;

    #[test]
    fn same_inputs_same_stream() {
        let a = CrawlSeed(7).rng("tie", &[b"s1", &1u64.to_le_bytes()]).next_u64();
        let b = CrawlSeed(7).rng("tie", &[b"s1", &1u64.to_le_bytes()]).next_u64();
        let c = CrawlSeed(8).rng("tie", &[b"s1", &1u64.to_le_bytes()]).next_u64();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
