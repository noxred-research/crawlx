//! TF-IDF cosine and normalized BM25 over a bounded corpus of token vectors.
//!
//! Ported from an MIT-licensed upstream; see THIRD_PARTY_NOTICES.md. Term maps
//! are ordered so scores are reproducible to the bit.

use std::collections::{BTreeMap, VecDeque};

const BM25_K1: f64 = 1.2;
const BM25_B: f64 = 0.75;

type TermCounts = BTreeMap<String, u32>;

fn count_terms<S: AsRef<str>>(tokens: &[S]) -> (TermCounts, u32) {
    let mut counts = TermCounts::new();
    for t in tokens {
        *counts.entry(t.as_ref().to_owned()).or_default() += 1;
    }
    let len = counts.values().sum();
    (counts, len)
}

#[derive(Clone, Debug)]
struct Doc {
    id: u64,
    counts: TermCounts,
    length: u32,
}

/// Best match of a query against the corpus.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Best {
    /// Score in `0.0..=1.0`.
    pub score: f64,
    /// Stable id of the matched document.
    pub id: u64,
}

/// Bounded FIFO corpus with document frequencies kept exact under eviction.
#[derive(Clone, Debug, Default)]
pub struct Corpus {
    docs: VecDeque<Doc>,
    doc_freq: BTreeMap<String, u32>,
    total_len: u64,
    next_id: u64,
}

impl Corpus {
    /// Empty corpus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Documents held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// No documents?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Document frequency of `term`.
    #[must_use]
    pub fn doc_freq(&self, term: &str) -> u32 {
        self.doc_freq.get(term).copied().unwrap_or(0)
    }

    fn avg_doc_len(&self) -> f64 {
        if self.docs.is_empty() {
            0.0
        } else {
            // lossless for any realistic corpus size (≤ 2^53 tokens)
            #[allow(clippy::cast_precision_loss, reason = "averaging token counts")]
            let avg = self.total_len as f64 / self.docs.len() as f64;
            avg
        }
    }

    /// Store a document; returns its stable id.
    pub fn add<S: AsRef<str>>(&mut self, tokens: &[S]) -> u64 {
        let (counts, length) = count_terms(tokens);
        let id = self.next_id;
        self.next_id += 1;
        self.total_len += u64::from(length);
        for term in counts.keys() {
            *self.doc_freq.entry(term.clone()).or_default() += 1;
        }
        self.docs.push_back(Doc { id, counts, length });
        id
    }

    /// Remove the oldest document, repairing document frequencies; returns its id.
    pub fn evict_oldest(&mut self) -> Option<u64> {
        let old = self.docs.pop_front()?;
        self.total_len -= u64::from(old.length);
        for term in old.counts.keys() {
            if let Some(df) = self.doc_freq.get_mut(term) {
                *df = df.saturating_sub(1);
                if *df == 0 {
                    self.doc_freq.remove(term);
                }
            }
        }
        Some(old.id)
    }

    fn idf(&self, term: &str) -> f64 {
        let df = f64::from(self.doc_freq(term));
        #[allow(clippy::cast_precision_loss, reason = "corpus sizes are small")]
        let n = (self.docs.len() + 1) as f64; // +1 for the query document
        (n / (1.0 + df)).ln() + 1.0
    }

    /// Best TF-IDF cosine score; `None` when the corpus or the query is empty.
    #[must_use]
    pub fn max_cosine<S: AsRef<str>>(&self, tokens: &[S]) -> Option<Best> {
        if self.docs.is_empty() || tokens.is_empty() {
            return None;
        }
        let (query, query_len) = count_terms(tokens);
        if query_len == 0 {
            return None;
        }
        self.docs
            .iter()
            .map(|d| Best {
                score: self.cosine_tfidf(&query, query_len, &d.counts, d.length),
                id: d.id,
            })
            .fold(None, |best: Option<Best>, b| match best {
                Some(prev) if b.score <= prev.score => Some(prev),
                _ => Some(b),
            })
    }

    fn cosine_tfidf(&self, a: &TermCounts, a_len: u32, b: &TermCounts, b_len: u32) -> f64 {
        if a_len == 0 || b_len == 0 {
            return 0.0;
        }
        let (mut dot, mut norm_a, mut norm_b) = (0.0, 0.0, 0.0);
        let terms = a.keys().chain(b.keys().filter(|t| !a.contains_key(*t)));
        for term in terms {
            let idf = self.idf(term);
            let va = f64::from(a.get(term).copied().unwrap_or(0)) / f64::from(a_len) * idf;
            let vb = f64::from(b.get(term).copied().unwrap_or(0)) / f64::from(b_len) * idf;
            dot += va * vb;
            norm_a += va * va;
            norm_b += vb * vb;
        }
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        dot / (norm_a.sqrt() * norm_b.sqrt())
    }

    /// Best normalized BM25 score (self-score = 1); `None` when empty.
    #[must_use]
    pub fn max_bm25<S: AsRef<str>>(&self, tokens: &[S]) -> Option<Best> {
        if self.docs.is_empty() || tokens.is_empty() {
            return None;
        }
        let (query, query_len) = count_terms(tokens);
        if query_len == 0 {
            return None;
        }
        let avg = self.avg_doc_len();
        let own = self.bm25(&query, &query, query_len, avg);
        if own <= 0.0 {
            return None;
        }
        self.docs
            .iter()
            .map(|d| Best {
                score: (self.bm25(&query, &d.counts, d.length, avg) / own).min(1.0),
                id: d.id,
            })
            .fold(None, |best: Option<Best>, b| match best {
                Some(prev) if b.score <= prev.score => Some(prev),
                _ => Some(b),
            })
    }

    fn bm25(&self, query: &TermCounts, doc: &TermCounts, doc_len: u32, avg_doc_len: f64) -> f64 {
        if doc_len == 0 || avg_doc_len == 0.0 {
            return 0.0;
        }
        let mut score = 0.0;
        for (term, qf) in query {
            let tf = f64::from(doc.get(term).copied().unwrap_or(0));
            if tf == 0.0 {
                continue;
            }
            let idf = self.idf(term);
            let denom = tf + BM25_K1 * (1.0 - BM25_B + BM25_B * f64::from(doc_len) / avg_doc_len);
            score += idf * (tf * (BM25_K1 + 1.0) / denom) * f64::from(*qf);
        }
        score
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::super::normalize::tokenize;
    use super::*;

    #[test]
    fn cosine_identical_high_unrelated_low() {
        let mut c = Corpus::new();
        c.add(&tokenize(
            "graphql federation schema stitching gateway subgraph query planning ownership",
        ));
        let high = c
            .max_cosine(&tokenize(
                "graphql federation schema stitching gateway subgraph query planning ownership notes",
            ))
            .unwrap();
        let low = c
            .max_cosine(&tokenize(
                "sourdough baking hydration flour water salt starter crumb oven spring",
            ))
            .unwrap();
        assert!(high.score >= 0.85, "{}", high.score);
        assert!(low.score < 0.5, "{}", low.score);
    }

    #[test]
    fn bm25_identical_high_unrelated_low() {
        let mut c = Corpus::new();
        c.add(&tokenize(
            "kubernetes network policies calico cilium ebpf egress ingress selectors namespaces",
        ));
        let high = c
            .max_bm25(&tokenize(
                "kubernetes network policies calico cilium ebpf egress ingress selectors namespaces again",
            ))
            .unwrap();
        let low = c
            .max_bm25(&tokenize(
                "classical guitar fingerstyle travis picking arpeggios metronome repertoire",
            ))
            .unwrap();
        assert!(high.score >= 0.85, "{}", high.score);
        assert!(low.score < 0.5, "{}", low.score);
        assert!(c.max_bm25::<&str>(&[]).is_none());
        assert!(Corpus::new().max_cosine(&["a"]).is_none());
    }

    #[test]
    fn evict_repairs_doc_freq_and_keeps_ids() {
        let mut c = Corpus::new();
        let id0 = c.add(&["alpha", "beta", "gamma", "delta", "epsilon"]);
        let id1 = c.add(&["alpha", "zeta", "eta", "theta", "iota"]);
        assert_eq!((id0, id1), (0, 1));
        assert_eq!(c.doc_freq("alpha"), 2);
        assert_eq!(c.evict_oldest(), Some(id0));
        assert_eq!(c.doc_freq("alpha"), 1);
        assert_eq!(c.doc_freq("beta"), 0);
        assert_eq!(c.len(), 1);
        let best = c.max_cosine(&["alpha", "zeta", "eta", "theta", "iota"]).unwrap();
        assert_eq!(best.id, id1);
        assert!(best.score > 0.9);
        assert_eq!(c.evict_oldest(), Some(id1));
        assert_eq!(c.evict_oldest(), None);
        assert!(c.is_empty());
    }
}
