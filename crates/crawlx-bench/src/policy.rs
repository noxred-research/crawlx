//! The layered-queue frontier policy shared by the driver and the replay harness:
//! `Score(e) = W(e) + 0.3·Z(e) + E(e)`, with ties broken by a seeded hash.
//!
//! The state is a pure function of the history of `(chosen candidate, novel reveals)`, so a
//! recorded trace can be replayed deterministically.

use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::seed::CrawlSeed;
use std::collections::{BTreeMap, BTreeSet};

/// `Z` weight (paper reference value).
pub const Z_WEIGHT: f64 = 0.3;
/// `E` bonus per reveal episode (paper reference value).
pub const REVEAL_BONUS: f64 = 0.8;
/// Cap on counted reveal episodes.
pub const REVEAL_CAP: u32 = 5;

/// Which terms of the queue score are active.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct PolicyFlags {
    /// Scored queue (`W`); otherwise the frontier is document order.
    pub queue: bool,
    /// Add the structural-repetition term `0.3·Z` (executions of the candidate's family) to the score.
    pub z: bool,
    /// Subtract the reveal bonus `E` (`0.8` per reveal episode, capped at 5 episodes) from the score.
    pub e: bool,
    /// Subtract the number of pending enablement targets (revealed by the candidate, since vanished and never exercised) from the score.
    pub graph: bool,
}

/// A selectable candidate.
#[derive(Clone, Debug)]
pub struct Cand<L> {
    /// Element identity hash; the unit the layer count, reveals and tie-break are keyed by.
    pub hash: ElementIdentityHash,
    /// Ground-truth control id, when labelled.
    pub label: Option<String>,
    /// Stable-path signature: `role | ancestor role path` (the `Z` family).
    pub family: String,
    /// Backend handle needed to act on the candidate (absent in replays).
    pub locator: L,
    /// Position in discovery order.
    pub order: usize,
}

/// `(score, seeded tie-break, document order)`; lower sorts first.
type ScoreKey = (f64, u64, usize);

/// Interaction history the score is computed from.
#[derive(Clone, Debug, Default)]
pub struct PolicyState {
    layer: BTreeMap<ElementIdentityHash, u32>,
    family: BTreeMap<String, u32>,
    reveals: BTreeMap<ElementIdentityHash, u32>,
    enables: BTreeMap<ElementIdentityHash, BTreeSet<ElementIdentityHash>>,
    unavailable: BTreeSet<ElementIdentityHash>,
}

impl PolicyState {
    /// Mark an identity as not actionable right now (hidden, covered, disabled).
    pub fn mark_unavailable(&mut self, h: ElementIdentityHash) {
        self.unavailable.insert(h);
    }

    /// Record one executed candidate and the identities it newly revealed (a novel-reveal episode
    /// when `novel` is non-empty).
    pub fn record(&mut self, chosen: ElementIdentityHash, family: &str, novel: &[ElementIdentityHash]) {
        *self.layer.entry(chosen).or_insert(0) += 1;
        *self.family.entry(family.to_owned()).or_insert(0) += 1;
        if !novel.is_empty() {
            *self.reveals.entry(chosen).or_insert(0) += 1;
            self.enables
                .entry(chosen)
                .or_default()
                .extend(novel.iter().copied());
        }
    }

    /// Times `h` was executed (`W`).
    #[must_use]
    pub fn layer(&self, h: &ElementIdentityHash) -> u32 {
        self.layer.get(h).copied().unwrap_or(0)
    }

    /// The score of `c` and the seeded tie-break value.
    fn score<L>(
        &self,
        flags: PolicyFlags,
        c: &Cand<L>,
        visible: &BTreeSet<ElementIdentityHash>,
        seed: CrawlSeed,
    ) -> (f64, u64) {
        if !flags.queue {
            return (0.0, 0);
        }
        let mut score = f64::from(self.layer(&c.hash));
        if flags.z {
            score += Z_WEIGHT * f64::from(self.family.get(&c.family).copied().unwrap_or(0));
        }
        if flags.e {
            score -=
                REVEAL_BONUS * f64::from(self.reveals.get(&c.hash).copied().unwrap_or(0).min(REVEAL_CAP));
        }
        if flags.graph {
            // Recorded reachability: prefer triggers whose revealed targets vanished and were never exercised.
            let pending = self.enables.get(&c.hash).map_or(0, |ts| {
                ts.iter()
                    .filter(|t| !visible.contains(*t) && self.layer(t) == 0)
                    .count()
            });
            score -= pending as f64;
        }
        let d = seed.derive("bench/policy/tie", &[&c.hash.0 .0]);
        (
            score,
            u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]),
        )
    }

    /// Candidates ranked best first (candidates at or beyond `max_layer` or unavailable are dropped).
    #[must_use]
    pub fn rank<'a, L>(
        &self,
        flags: PolicyFlags,
        cands: &'a [Cand<L>],
        seed: CrawlSeed,
        max_layer: u32,
    ) -> Vec<&'a Cand<L>> {
        let visible: BTreeSet<ElementIdentityHash> = cands.iter().map(|c| c.hash).collect();
        let mut scored: Vec<(ScoreKey, &Cand<L>)> = cands
            .iter()
            .filter(|c| self.layer(&c.hash) < max_layer && !self.unavailable.contains(&c.hash))
            .map(|c| {
                let (s, t) = self.score(flags, c, &visible, seed);
                ((s, t, c.order), c)
            })
            .collect();
        scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        scored.into_iter().map(|(_, c)| c).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;

    fn h(s: &str) -> ElementIdentityHash {
        ElementIdentityHash(Digest::of("t", s.as_bytes()))
    }

    fn cand(s: &str, family: &str, order: usize) -> Cand<()> {
        Cand {
            hash: h(s),
            label: Some(s.to_owned()),
            family: family.to_owned(),
            locator: (),
            order,
        }
    }

    fn queue() -> PolicyFlags {
        PolicyFlags {
            queue: true,
            ..PolicyFlags::default()
        }
    }

    #[test]
    fn document_order_without_a_queue() {
        let cands = [cand("c", "f", 2), cand("a", "f", 0), cand("b", "f", 1)];
        let ranked = PolicyState::default().rank(PolicyFlags::default(), &cands, CrawlSeed(1), 1);
        let order: Vec<_> = ranked.iter().map(|c| c.label.clone().unwrap()).collect();
        assert_eq!(order, ["a", "b", "c"]);
    }

    #[test]
    fn w_layer_prefers_never_executed_and_caps_layers() {
        let cands = [cand("a", "f", 0), cand("b", "f", 1)];
        let mut st = PolicyState::default();
        st.record(h("a"), "f", &[]);
        let ranked = st.rank(queue(), &cands, CrawlSeed(1), 2);
        assert_eq!(ranked[0].label.as_deref(), Some("b"));
        assert_eq!(ranked.len(), 2);
        assert_eq!(
            st.rank(queue(), &cands, CrawlSeed(1), 1).len(),
            1,
            "layer cap drops executed identities"
        );
    }

    #[test]
    fn z_penalizes_repeated_families_and_e_rewards_reveals() {
        let cands = [cand("a", "menu", 0), cand("b", "menu", 1), cand("c", "other", 2)];
        let mut st = PolicyState::default();
        st.record(h("x"), "menu", &[]);
        st.record(h("y"), "menu", &[]);
        let z = PolicyFlags {
            queue: true,
            z: true,
            ..PolicyFlags::default()
        };
        // menu family count 2 -> +0.6; "other" has 0
        assert_eq!(st.rank(z, &cands, CrawlSeed(3), 5)[0].label.as_deref(), Some("c"));
        // two reveal episodes: -1.6 outweighs the family penalty (+1.2 after four executions)
        st.record(h("a"), "menu", &[h("new")]);
        st.record(h("a"), "menu", &[h("new2")]);
        st.layer.remove(&h("a")); // isolate the E term from W
        let ze = PolicyFlags {
            queue: true,
            z: true,
            e: true,
            graph: false,
        };
        assert_eq!(
            st.rank(ze, &cands, CrawlSeed(3), 5)[0].label.as_deref(),
            Some("a")
        );
    }

    #[test]
    fn graph_prefers_triggers_of_vanished_unexercised_targets() {
        let mut st = PolicyState::default();
        st.record(h("menu"), "f", &[h("item")]);
        st.layer.remove(&h("menu"));
        let cands = [cand("other", "f", 0), cand("menu", "f", 1)];
        let g = PolicyFlags {
            queue: true,
            graph: true,
            ..PolicyFlags::default()
        };
        assert_eq!(
            st.rank(g, &cands, CrawlSeed(1), 5)[0].label.as_deref(),
            Some("menu")
        );
        // once the item is visible again the bonus disappears
        let cands2 = [cand("other", "f", 0), cand("menu", "f", 1), cand("item", "f", 2)];
        assert_ne!(
            st.rank(g, &cands2, CrawlSeed(1), 5)[0].label.as_deref(),
            Some("menu")
        );
    }

    #[test]
    fn ties_are_broken_by_seed_deterministically() {
        let cands: Vec<_> = (0..8).map(|i| cand(&format!("c{i}"), "f", i)).collect();
        let a = PolicyState::default().rank(queue(), &cands, CrawlSeed(11), 1);
        let b = PolicyState::default().rank(queue(), &cands, CrawlSeed(11), 1);
        let c = PolicyState::default().rank(queue(), &cands, CrawlSeed(12), 1);
        let ids = |v: &[&Cand<()>]| v.iter().map(|x| x.order).collect::<Vec<_>>();
        assert_eq!(ids(&a), ids(&b));
        assert_ne!(ids(&a), ids(&c));
    }
}
