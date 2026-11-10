//! Content similarity index with a per-cluster budget.
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md. Cluster
//! ids are stable (`mode:n`) and survive eviction of their representative, so
//! a budget never attaches to the wrong cluster.

use std::collections::BTreeMap;

use crawlx_core::config::SimilarityMode;

use super::lexical::Corpus;
use super::normalize::{normalize, Document};
use super::simhash::{hamming_distance, simhash64};

/// Default Hamming band for `simhash`.
pub const DEFAULT_DISTANCE: u32 = 3;
/// Default cosine/BM25 threshold.
pub const DEFAULT_THRESHOLD: f64 = 0.85;
/// Default pages fully processed per cluster.
pub const DEFAULT_BUDGET: u32 = 1;
/// Default representatives retained before the oldest is evicted.
pub const DEFAULT_MAX_CLUSTERS: usize = 1000;

/// Index configuration; zero or out-of-range values fall back to the defaults.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Config {
    /// Backend; `Off` builds an index that accepts everything.
    pub mode: SimilarityMode,
    /// Maximum Hamming distance for `simhash` (0..=64).
    pub distance: u32,
    /// Minimum score for `tfidf`/`bm25` (0.0..=1.0).
    pub threshold: f64,
    /// Pages accepted per cluster (≥ 1).
    pub budget: u32,
    /// Representatives retained (≥ 1).
    pub max_clusters: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: SimilarityMode::Simhash,
            distance: DEFAULT_DISTANCE,
            threshold: DEFAULT_THRESHOLD,
            budget: DEFAULT_BUDGET,
            max_clusters: DEFAULT_MAX_CLUSTERS,
        }
    }
}

impl Config {
    /// Configuration from the request's `scope.contentSimilarity`.
    #[must_use]
    pub fn from_request(cs: &crawlx_core::config::ContentSimilarity) -> Self {
        Self {
            mode: cs.mode,
            distance: u32::from(cs.distance),
            threshold: cs.threshold,
            budget: cs.budget,
            max_clusters: DEFAULT_MAX_CLUSTERS,
        }
    }

    fn sanitized(mut self) -> Self {
        if self.distance > 64 {
            self.distance = DEFAULT_DISTANCE;
        }
        if !(self.threshold > 0.0 && self.threshold <= 1.0) {
            self.threshold = DEFAULT_THRESHOLD;
        }
        if self.budget == 0 {
            self.budget = DEFAULT_BUDGET;
        }
        if self.max_clusters == 0 {
            self.max_clusters = DEFAULT_MAX_CLUSTERS;
        }
        self
    }
}

/// Cumulative [`Index::accept`] counters.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Stats {
    /// Bodies offered.
    pub processed: u64,
    /// Bodies accepted (new cluster, within budget, or low signal).
    pub accepted: u64,
    /// Bodies filtered as similar beyond the cluster budget.
    pub filtered: u64,
}

/// Outcome of [`Index::accept`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Accept {
    /// Stable cluster id (`mode:n`); `None` for low-signal bodies or an `Off` index.
    pub cluster_id: Option<String>,
    /// `true` when the page should be skipped as a near-duplicate beyond budget.
    pub filtered: bool,
    /// Backend that produced the decision.
    pub mode: SimilarityMode,
}

#[derive(Clone, Copy, Debug)]
struct SimRep {
    id: u64,
    fp: u64,
}

/// Near-duplicate page filter.
#[derive(Clone, Debug)]
pub struct Index {
    cfg: Config,
    corpus: Corpus,
    sigs: Vec<SimRep>,
    next_id: u64,
    /// cluster id → accepted count
    clusters: BTreeMap<String, u32>,
    stats: Stats,
}

impl Index {
    /// Build an index; invalid fields fall back to defaults.
    #[must_use]
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg: cfg.sanitized(),
            corpus: Corpus::new(),
            sigs: Vec::new(),
            next_id: 0,
            clusters: BTreeMap::new(),
            stats: Stats::default(),
        }
    }

    /// Effective configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.cfg
    }

    /// Backend.
    #[must_use]
    pub const fn mode(&self) -> SimilarityMode {
        self.cfg.mode
    }

    /// Counter snapshot.
    #[must_use]
    pub const fn stats(&self) -> Stats {
        self.stats
    }

    /// Clusters currently tracked.
    #[must_use]
    pub fn cluster_count(&self) -> usize {
        self.clusters.len()
    }

    fn key(mode: SimilarityMode, id: u64) -> String {
        format!("{}:{id}", mode.as_str())
    }

    /// Decide whether `body` should be fully processed. Low-signal bodies and
    /// every body under `Off` are accepted without touching the index.
    pub fn accept(&mut self, body: &[u8]) -> Accept {
        self.stats.processed += 1;
        let mode = self.cfg.mode;
        if mode == SimilarityMode::Off {
            self.stats.accepted += 1;
            return Accept {
                cluster_id: None,
                filtered: false,
                mode,
            };
        }
        let Some(doc) = normalize(body) else {
            self.stats.accepted += 1;
            return Accept {
                cluster_id: None,
                filtered: false,
                mode,
            };
        };
        if let Some(cluster) = self.matching_cluster(&doc) {
            let count = self.clusters.entry(cluster.clone()).or_insert(0);
            if *count >= self.cfg.budget {
                self.stats.filtered += 1;
                return Accept {
                    cluster_id: Some(cluster),
                    filtered: true,
                    mode,
                };
            }
            *count += 1;
            self.stats.accepted += 1;
            return Accept {
                cluster_id: Some(cluster),
                filtered: false,
                mode,
            };
        }
        let cluster = self.remember(&doc);
        self.clusters.insert(cluster.clone(), 1);
        self.stats.accepted += 1;
        Accept {
            cluster_id: Some(cluster),
            filtered: false,
            mode,
        }
    }

    fn matching_cluster(&self, doc: &Document) -> Option<String> {
        match self.cfg.mode {
            SimilarityMode::Off => None,
            SimilarityMode::Simhash => {
                let fp = simhash64(&doc.shingles);
                let best = self
                    .sigs
                    .iter()
                    .map(|s| (hamming_distance(fp, s.fp), s.id))
                    .fold(None, |best: Option<(u32, u64)>, cand| match best {
                        Some(prev) if cand.0 >= prev.0 => Some(prev),
                        _ => Some(cand),
                    })?;
                (best.0 <= self.cfg.distance).then(|| Self::key(SimilarityMode::Simhash, best.1))
            }
            SimilarityMode::Tfidf => {
                let b = self.corpus.max_cosine(&doc.tokens)?;
                (b.score >= self.cfg.threshold).then(|| Self::key(SimilarityMode::Tfidf, b.id))
            }
            SimilarityMode::Bm25 => {
                let b = self.corpus.max_bm25(&doc.tokens)?;
                (b.score >= self.cfg.threshold).then(|| Self::key(SimilarityMode::Bm25, b.id))
            }
        }
    }

    /// Store a new representative; returns its stable cluster id.
    fn remember(&mut self, doc: &Document) -> String {
        let mode = self.cfg.mode;
        match mode {
            SimilarityMode::Simhash => {
                while self.sigs.len() >= self.cfg.max_clusters {
                    let old = self.sigs.remove(0);
                    self.clusters.remove(&Self::key(mode, old.id));
                }
                let id = self.next_id;
                self.next_id += 1;
                self.sigs.push(SimRep {
                    id,
                    fp: simhash64(&doc.shingles),
                });
                Self::key(mode, id)
            }
            SimilarityMode::Tfidf | SimilarityMode::Bm25 => {
                while self.corpus.len() >= self.cfg.max_clusters {
                    match self.corpus.evict_oldest() {
                        Some(id) => {
                            self.clusters.remove(&Self::key(mode, id));
                        }
                        None => break,
                    }
                }
                Self::key(mode, self.corpus.add(&doc.tokens))
            }
            SimilarityMode::Off => Self::key(mode, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::super::normalize::html_page;
    use super::*;

    const MODES: [SimilarityMode; 3] = [
        SimilarityMode::Simhash,
        SimilarityMode::Tfidf,
        SimilarityMode::Bm25,
    ];

    fn product(id: u32, blurb: &str) -> Vec<u8> {
        html_page(
            "Home Shop Cart Account Help",
            &format!("Product {id} {blurb} Exclusive cotton shirt available in multiple sizes with free shipping worldwide today only"),
        )
    }

    fn blog(title: &str, body: &str) -> Vec<u8> {
        html_page("Home Shop Cart Account Help", &format!("{title} {body}"))
    }

    fn cfg(mode: SimilarityMode, budget: u32) -> Config {
        Config {
            mode,
            distance: 3,
            threshold: 0.85,
            budget,
            max_clusters: DEFAULT_MAX_CLUSTERS,
        }
    }

    fn ok(idx: &mut Index, body: &[u8]) -> bool {
        !idx.accept(body).filtered
    }

    #[test]
    fn simhash_cluster_budget() {
        let mut idx = Index::new(cfg(SimilarityMode::Simhash, 1));
        let p1 = product(1, "red");
        let p2 = product(2, "red");
        let p3 = blog(
            "Deep Dive Into Distributed Consensus Algorithms",
            "Raft Paxos Viewstamped Replication quorum election log replication safety liveness detailed analysis for engineers building reliable systems",
        );
        let first = idx.accept(&p1);
        assert!(!first.filtered);
        assert_eq!(first.cluster_id.as_deref(), Some("simhash:0"));
        assert_eq!(first.mode, SimilarityMode::Simhash);
        let second = idx.accept(&p2);
        assert!(
            second.filtered,
            "near-duplicate product is filtered with budget 1"
        );
        assert_eq!(second.cluster_id.as_deref(), Some("simhash:0"));
        assert!(ok(&mut idx, &p3), "unrelated blog is accepted");
        assert_eq!(
            idx.stats(),
            Stats {
                processed: 3,
                accepted: 2,
                filtered: 1
            }
        );
        assert_eq!(idx.cluster_count(), 2);
    }

    #[test]
    fn simhash_budget_two() {
        let mut idx = Index::new(cfg(SimilarityMode::Simhash, 2));
        assert!(ok(&mut idx, &product(1, "blue")));
        assert!(
            ok(&mut idx, &product(2, "blue")),
            "second near-dupe allowed with budget 2"
        );
        assert!(!ok(&mut idx, &product(3, "blue")), "third near-dupe filtered");
    }

    #[test]
    fn tfidf_near_copy_filtered_unrelated_accepted() {
        let mut idx = Index::new(cfg(SimilarityMode::Tfidf, 1));
        let a = blog(
            "Introducing GraphQL Federation at Scale",
            "This article explains schema stitching gateway composition subgraph ownership and query planning challenges when operating federated graphs across many teams",
        );
        let b = blog(
            "Introducing GraphQL Federation at Scale",
            "This article explains schema stitching gateway composition subgraph ownership and query planning challenges when operating federated graphs across many teams with minor notes",
        );
        let c = blog(
            "Sourdough Baking Hydration Percentages",
            "Learn how flour water salt and starter ratios affect crumb structure oven spring and fermentation timing for artisan loaves baked on a stone",
        );
        assert!(ok(&mut idx, &a));
        assert!(!ok(&mut idx, &b), "near-copy exceeds the TF-IDF threshold");
        assert!(ok(&mut idx, &c), "topically different page passes");
    }

    #[test]
    fn bm25_near_copy_filtered_unrelated_accepted() {
        let mut idx = Index::new(cfg(SimilarityMode::Bm25, 1));
        let a = blog(
            "Kubernetes Network Policies Deep Dive",
            "Calico Cilium eBPF egress ingress selectors namespaces and troubleshooting connection refused errors in multi-tenant clusters explained step by step",
        );
        let b = blog(
            "Kubernetes Network Policies Deep Dive",
            "Calico Cilium eBPF egress ingress selectors namespaces and troubleshooting connection refused errors in multi-tenant clusters explained step by step again",
        );
        let c = blog(
            "Classical Guitar Fingerstyle Patterns",
            "Travis picking arpeggios rest stroke free stroke practice routines metronome technique and repertoire suggestions for intermediate players",
        );
        assert!(ok(&mut idx, &a));
        assert!(!ok(&mut idx, &b));
        assert!(ok(&mut idx, &c));
    }

    #[test]
    fn low_signal_always_accepted_in_every_mode() {
        for mode in MODES {
            let mut idx = Index::new(cfg(mode, 1));
            let a = idx.accept(b"ok");
            let b = idx.accept(b"ok");
            assert!(!a.filtered && !b.filtered, "{mode:?}");
            assert!(a.cluster_id.is_none() && b.cluster_id.is_none());
            assert_eq!(idx.stats().accepted, 2);
        }
    }

    #[test]
    fn off_mode_accepts_everything() {
        let mut idx = Index::new(Config {
            mode: SimilarityMode::Off,
            ..Config::default()
        });
        for _ in 0..3 {
            let a = idx.accept(&product(1, "red"));
            assert!(!a.filtered && a.cluster_id.is_none());
        }
        assert_eq!(idx.stats().filtered, 0);
        assert_eq!(idx.cluster_count(), 0);
    }

    #[test]
    fn shared_chrome_does_not_collapse_distinct_mains() {
        for mode in MODES {
            let mut idx = Index::new(cfg(mode, 1));
            let a = html_page(
                "Home About Contact Shared Nav Items",
                "Astronomy telescope aperture focal length mount equatorial tracking deep sky objects nebulae galaxies observing checklist",
            );
            let b = html_page(
                "Home About Contact Shared Nav Items",
                "Mediterranean cooking olive oil garlic lemon herbs grilled vegetables seafood pasta recipes weeknight dinners",
            );
            assert!(ok(&mut idx, &a), "{mode:?}");
            assert!(
                ok(&mut idx, &b),
                "{mode:?}: distinct main content must not collapse"
            );
        }
    }

    #[test]
    fn stable_cluster_ids_survive_eviction() {
        for mode in MODES {
            let mut idx = Index::new(Config {
                max_clusters: 2,
                ..cfg(mode, 1)
            });
            let pages = [
                blog(
                    "Topic Alpha One",
                    "alpha content about networking switches routers firewalls packet capture tooling",
                ),
                blog(
                    "Topic Beta Two",
                    "beta content about photography lenses apertures shutters composition lighting",
                ),
                blog(
                    "Topic Gamma Three",
                    "gamma content about baking sourdough hydration fermentation oven spring crumb",
                ),
            ];
            assert!(ok(&mut idx, &pages[0]), "{mode:?}");
            assert!(ok(&mut idx, &pages[1]), "{mode:?}");
            assert!(ok(&mut idx, &pages[2]), "{mode:?}: evicts page 0");
            let near_evicted = blog(
                "Topic Alpha One",
                "alpha content about networking switches routers firewalls packet capture tooling notes",
            );
            assert!(
                ok(&mut idx, &near_evicted),
                "{mode:?}: evicted cluster keeps no stale budget"
            );
            assert!(
                !ok(&mut idx, &pages[2]),
                "{mode:?}: resident cluster budget still applies"
            );
        }
    }

    #[test]
    fn invalid_config_falls_back_to_defaults() {
        let idx = Index::new(Config {
            mode: SimilarityMode::Tfidf,
            distance: 99,
            threshold: 7.0,
            budget: 0,
            max_clusters: 0,
        });
        let c = idx.config();
        assert_eq!(c.distance, DEFAULT_DISTANCE);
        assert!((c.threshold - DEFAULT_THRESHOLD).abs() < f64::EPSILON);
        assert_eq!(c.budget, DEFAULT_BUDGET);
        assert_eq!(c.max_clusters, DEFAULT_MAX_CLUSTERS);
        assert_eq!(idx.mode(), SimilarityMode::Tfidf);
    }
}
