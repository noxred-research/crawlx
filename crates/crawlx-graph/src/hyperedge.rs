//! Conjunctive preconditions.
//!
//! Some targets need several earlier actions together (a ticked checkbox *and*
//! a created entity). Each session window is recorded as an [`Episode`]: the
//! set of trusted, succeeded actions that occurred and whether the target
//! appeared. A set of at least two distinct actions becomes a [`Hyperedge`]
//! when the conjunction is present in ≥ 80 % of the episodes where the target
//! appeared and ≤ 20 % of those where it did not, across ≥ 5 episodes, and no
//! single action already discriminates (that would be a plain edge).

use crawlx_core::identity::ElementIdentityHash;
use crawlx_core::ActionContextId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// `target` appears only after all `sources` occurred in the same session window.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
pub struct Hyperedge {
    /// Actions that must all have occurred (at least two).
    pub sources: BTreeSet<ActionContextId>,
    /// Control whose appearance the conjunction enables.
    pub target: ElementIdentityHash,
}

/// One session window observed for a target.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Episode {
    /// Distinct actions that occurred in the window.
    pub actions: BTreeSet<ActionContextId>,
    /// Whether the target was revealed in the window.
    pub appeared: bool,
}

/// Mining thresholds.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
pub struct MiningParams {
    /// Minimum episodes (appeared + not appeared) before mining.
    pub min_episodes: usize,
    /// Minimum episodes in which the target appeared.
    pub min_successes: usize,
    /// Conjunction presence required among success episodes.
    pub presence: f64,
    /// Conjunction presence allowed among failure episodes.
    pub absence: f64,
    /// Oldest episodes are dropped beyond this many per target.
    pub max_episodes: usize,
}

impl Default for MiningParams {
    fn default() -> Self {
        Self {
            min_episodes: 5,
            min_successes: 2,
            presence: 0.8,
            absence: 0.2,
            max_episodes: 256,
        }
    }
}

/// Episode log plus the hyperedges mined from it.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
#[serde(from = "MinerRepr", into = "MinerRepr")]
pub struct HyperedgeMiner {
    params: MiningParams,
    episodes: BTreeMap<ElementIdentityHash, VecDeque<Episode>>,
    found: BTreeMap<ElementIdentityHash, Vec<Hyperedge>>,
}

/// Flat serde form (JSON map keys must be strings).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
struct MinerRepr {
    params: MiningParams,
    episodes: Vec<(ElementIdentityHash, Vec<Episode>)>,
    found: Vec<Hyperedge>,
}

impl From<HyperedgeMiner> for MinerRepr {
    fn from(m: HyperedgeMiner) -> Self {
        Self {
            params: m.params,
            episodes: m
                .episodes
                .into_iter()
                .map(|(t, e)| (t, e.into_iter().collect()))
                .collect(),
            found: m.found.into_values().flatten().collect(),
        }
    }
}

impl From<MinerRepr> for HyperedgeMiner {
    fn from(r: MinerRepr) -> Self {
        let mut found: BTreeMap<ElementIdentityHash, Vec<Hyperedge>> = BTreeMap::new();
        for h in r.found {
            found.entry(h.target).or_default().push(h);
        }
        Self {
            params: r.params,
            episodes: r
                .episodes
                .into_iter()
                .map(|(t, e)| (t, e.into_iter().collect()))
                .collect(),
            found,
        }
    }
}

impl HyperedgeMiner {
    /// Empty miner with the given thresholds.
    #[must_use]
    pub fn new(params: MiningParams) -> Self {
        Self {
            params,
            ..Self::default()
        }
    }

    /// Record one session window for `target`.
    pub fn record_episode(
        &mut self,
        target: ElementIdentityHash,
        actions: BTreeSet<ActionContextId>,
        appeared: bool,
    ) {
        let q = self.episodes.entry(target).or_default();
        q.push_back(Episode { actions, appeared });
        while q.len() > self.params.max_episodes {
            q.pop_front();
        }
    }

    /// Number of episodes recorded for `target`.
    #[must_use]
    pub fn episode_count(&self, target: &ElementIdentityHash) -> usize {
        self.episodes.get(target).map_or(0, VecDeque::len)
    }

    /// Mine `target` from its episodes and replace its stored hyperedges.
    /// Returns the hyperedges now stored for it (empty when none qualify).
    pub fn mine(&mut self, target: ElementIdentityHash) -> Vec<Hyperedge> {
        let mined = self
            .mine_set(&target)
            .map(|sources| Hyperedge { sources, target });
        match mined {
            Some(h) => {
                self.found.insert(target, vec![h.clone()]);
                vec![h]
            }
            None => {
                self.found.remove(&target);
                Vec::new()
            }
        }
    }

    /// Mine every target that has episodes; returns all stored hyperedges.
    pub fn mine_all(&mut self) -> Vec<Hyperedge> {
        let targets: Vec<ElementIdentityHash> = self.episodes.keys().copied().collect();
        for t in targets {
            self.mine(t);
        }
        self.all().cloned().collect()
    }

    /// Hyperedges stored for `target`.
    #[must_use]
    pub fn for_target(&self, target: &ElementIdentityHash) -> &[Hyperedge] {
        self.found.get(target).map_or(&[], Vec::as_slice)
    }

    /// All stored hyperedges in deterministic order.
    pub fn all(&self) -> impl Iterator<Item = &Hyperedge> {
        self.found.values().flatten()
    }

    fn mine_set(&self, target: &ElementIdentityHash) -> Option<BTreeSet<ActionContextId>> {
        let p = &self.params;
        let eps = self.episodes.get(target)?;
        let succ: Vec<&Episode> = eps.iter().filter(|e| e.appeared).collect();
        let fail: Vec<&Episode> = eps.iter().filter(|e| !e.appeared).collect();
        if eps.len() < p.min_episodes || succ.len() < p.min_successes || fail.is_empty() {
            return None;
        }
        let frac = |set: &BTreeSet<ActionContextId>, group: &[&Episode]| -> f64 {
            let n = group.iter().filter(|e| set.is_subset(&e.actions)).count();
            n as f64 / group.len() as f64
        };
        let present = |set: &BTreeSet<ActionContextId>| frac(set, &succ) + 1e-9 >= p.presence;
        let absent = |set: &BTreeSet<ActionContextId>| frac(set, &fail) <= p.absence + 1e-9;

        // Candidates: individually present in enough success episodes.
        let mut candidates: BTreeSet<ActionContextId> = BTreeSet::new();
        for e in &succ {
            candidates.extend(e.actions.iter().copied());
        }
        candidates.retain(|a| present(&BTreeSet::from([*a])));
        if candidates.len() < 2 {
            return None;
        }
        // A single discriminating action is a plain edge, not a hyperedge.
        if candidates.iter().any(|a| absent(&BTreeSet::from([*a]))) {
            return None;
        }
        // Greedy: add the candidate that lowers failure presence most while
        // success presence stays above the threshold (ties: smallest id).
        let mut chosen: BTreeSet<ActionContextId> = BTreeSet::new();
        loop {
            let mut best: Option<(f64, ActionContextId)> = None;
            for a in candidates.iter().filter(|a| !chosen.contains(*a)) {
                let mut trial = chosen.clone();
                trial.insert(*a);
                if !present(&trial) {
                    continue;
                }
                let f = frac(&trial, &fail);
                if best.is_none_or(|(bf, _)| f < bf) {
                    best = Some((f, *a));
                }
            }
            let (_, a) = best?;
            chosen.insert(a);
            if absent(&chosen) {
                break;
            }
        }
        // Drop redundant members, smallest id first.
        for a in chosen.clone() {
            if chosen.len() <= 2 {
                break;
            }
            let mut trial = chosen.clone();
            trial.remove(&a);
            if present(&trial) && absent(&trial) {
                chosen = trial;
            }
        }
        (chosen.len() >= 2).then_some(chosen)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;

    fn act(n: u8) -> ActionContextId {
        ActionContextId([n; 16])
    }
    fn tgt() -> ElementIdentityHash {
        ElementIdentityHash(Digest::of("t", b"x"))
    }
    fn ep(actions: &[u8]) -> BTreeSet<ActionContextId> {
        actions.iter().map(|a| act(*a)).collect()
    }

    #[test]
    fn mines_conjunction_where_each_action_alone_is_insufficient() {
        let mut m = HyperedgeMiner::default();
        // A and B together reveal; A alone or B alone (and C noise) do not.
        for _ in 0..4 {
            m.record_episode(tgt(), ep(&[1, 2, 9]), true);
        }
        m.record_episode(tgt(), ep(&[1, 9]), false);
        m.record_episode(tgt(), ep(&[2, 9]), false);
        m.record_episode(tgt(), ep(&[1]), false);
        m.record_episode(tgt(), ep(&[2]), false);
        m.record_episode(tgt(), ep(&[9]), false);
        let got = m.mine(tgt());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].sources, ep(&[1, 2]));
        assert_eq!(m.for_target(&tgt()), got.as_slice());
    }

    #[test]
    fn single_discriminating_action_is_not_a_hyperedge() {
        let mut m = HyperedgeMiner::default();
        for _ in 0..4 {
            m.record_episode(tgt(), ep(&[1, 2]), true);
        }
        for _ in 0..3 {
            m.record_episode(tgt(), ep(&[2]), false);
        }
        assert!(m.mine(tgt()).is_empty());
    }

    #[test]
    fn needs_five_episodes() {
        let mut m = HyperedgeMiner::default();
        for _ in 0..2 {
            m.record_episode(tgt(), ep(&[1, 2]), true);
        }
        m.record_episode(tgt(), ep(&[1]), false);
        m.record_episode(tgt(), ep(&[2]), false);
        assert!(m.mine(tgt()).is_empty());
        m.record_episode(tgt(), ep(&[]), false);
        assert_eq!(m.mine(tgt()).len(), 1);
    }

    #[test]
    fn presence_threshold_tolerates_one_miss_in_five() {
        let mut m = HyperedgeMiner::default();
        for _ in 0..4 {
            m.record_episode(tgt(), ep(&[1, 2]), true);
        }
        m.record_episode(tgt(), ep(&[1]), true); // 4/5 = 80 % keep conjunction
        m.record_episode(tgt(), ep(&[1]), false);
        m.record_episode(tgt(), ep(&[2]), false);
        assert_eq!(m.mine(tgt()).len(), 1);
    }

    #[test]
    fn contradicting_episodes_retire_the_hyperedge() {
        let mut m = HyperedgeMiner::default();
        for _ in 0..4 {
            m.record_episode(tgt(), ep(&[1, 2]), true);
        }
        for a in [&[1u8][..], &[2], &[]] {
            m.record_episode(tgt(), ep(a), false);
        }
        assert_eq!(m.mine(tgt()).len(), 1);
        for _ in 0..6 {
            m.record_episode(tgt(), ep(&[1, 2]), false);
        }
        assert!(m.mine(tgt()).is_empty());
        assert_eq!(m.all().count(), 0);
    }

    #[test]
    fn serde_round_trip() {
        let mut m = HyperedgeMiner::default();
        for _ in 0..4 {
            m.record_episode(tgt(), ep(&[1, 2]), true);
        }
        for a in [&[1u8][..], &[2], &[]] {
            m.record_episode(tgt(), ep(a), false);
        }
        m.mine(tgt());
        let json = serde_json::to_string(&m).unwrap();
        let back: HyperedgeMiner = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }
}
