//! Deterministic BM25 relevance scoring (`bm25_v1`).
//!
//! Everything is integer arithmetic: the inverse document frequency uses a fixed-point
//! `log2` (16 fractional bits) instead of a platform `ln`, so scores are bit-identical on every
//! target. Tokenization is the offline dictionary word segmentation used by the article
//! pipeline (Unicode word boundaries, lower-cased), minus a small fixed stop list, so the
//! same text and query always yield the same terms.
//!
//! The version string [`BM25_VERSION`] names this exact tokenizer, stop list and arithmetic;
//! any change to them must bump it.

use std::collections::{BTreeMap, BTreeSet};

use icu_segmenter::{WordSegmenter, WordSegmenterBorrowed};

/// Version of the tokenizer, stop list and fixed-point arithmetic.
pub const BM25_VERSION: &str = "bm25_v1";

/// Fractional bits of every fixed-point quantity.
const FRAC_BITS: u32 = 16;
const ONE: u128 = 1 << FRAC_BITS;
/// Longest token kept, in bytes.
const MAX_TOKEN_BYTES: usize = 128;
/// Most tokens produced from one text.
const MAX_TOKENS: usize = 100_000;

/// Words that carry no relevance signal in `bm25_v1`.
const STOP_WORDS: [&str; 24] = [
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "in", "is", "it", "of", "on",
    "or", "that", "the", "to", "was", "were", "will", "with",
];

/// Word tokenizer of `bm25_v1`. Build once per filter run.
pub struct Tokenizer {
    segmenter: WordSegmenterBorrowed<'static>,
}

impl Default for Tokenizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Tokenizer {
    /// Create the tokenizer (loads the compiled segmentation data once).
    #[must_use]
    pub fn new() -> Self {
        Self {
            segmenter: WordSegmenter::new_dictionary(Default::default()),
        }
    }

    /// Lower-cased word tokens of `text` in order, stop words removed.
    /// Tokens longer than 128 bytes are skipped; at most 100 000 tokens are returned.
    #[must_use]
    pub fn tokens(&self, text: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut previous = 0;
        for end in self.segmenter.segment_str(text) {
            let start = previous;
            previous = end;
            let piece = &text[start..end];
            if start == end || !piece.chars().any(char::is_alphanumeric) || piece.len() > MAX_TOKEN_BYTES {
                continue;
            }
            let token = piece.to_lowercase();
            if STOP_WORDS.contains(&token.as_str()) {
                continue;
            }
            if out.len() == MAX_TOKENS {
                break;
            }
            out.push(token);
        }
        out
    }

    /// Distinct query terms in sorted order.
    #[must_use]
    pub fn query_terms(&self, query: &str) -> Vec<String> {
        self.tokens(query)
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// `log2(x)` with 16 fractional bits. `x` must be positive.
fn log2_q16(x: u64) -> u128 {
    let x = x.max(1);
    let int = 63 - x.leading_zeros();
    // Mantissa in [1, 2) with 32 fractional bits.
    let mut m: u128 = if int >= 32 {
        u128::from(x >> (int - 32))
    } else {
        u128::from(x) << (32 - int)
    };
    let mut frac: u128 = 0;
    for bit in (0..FRAC_BITS).rev() {
        m = (m * m) >> 32;
        if m >= (1u128 << 33) {
            m >>= 1;
            frac |= 1 << bit;
        }
    }
    (u128::from(int) << FRAC_BITS) | frac
}

/// BM25 parameters in thousandths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Term-frequency saturation `k1 * 1000`.
    pub k1_milli: u32,
    /// Length normalization `b * 1000`, at most 1000.
    pub b_milli: u32,
}

/// Term statistics of a set of chunks.
pub struct Corpus {
    docs: Vec<(BTreeMap<String, u32>, u64)>,
    df: BTreeMap<String, u64>,
    total_len: u64,
}

impl Corpus {
    /// Build the statistics from tokenized chunks, in order.
    #[must_use]
    pub fn new(chunks: &[Vec<String>]) -> Self {
        let mut df: BTreeMap<String, u64> = BTreeMap::new();
        let mut docs = Vec::with_capacity(chunks.len());
        let mut total_len = 0u64;
        for tokens in chunks {
            let mut tf: BTreeMap<String, u32> = BTreeMap::new();
            for token in tokens {
                let count = tf.entry(token.clone()).or_insert(0);
                *count = count.saturating_add(1);
            }
            for term in tf.keys() {
                *df.entry(term.clone()).or_insert(0) += 1;
            }
            let len = u64::try_from(tokens.len()).unwrap_or(u64::MAX);
            total_len = total_len.saturating_add(len);
            docs.push((tf, len));
        }
        Self { docs, df, total_len }
    }

    /// Number of chunks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.docs.len()
    }

    /// True when the corpus has no chunks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.docs.is_empty()
    }

    /// Score of chunk `doc` against the sorted distinct `query` terms, in thousandths.
    /// Out-of-range chunks and an empty corpus score zero.
    #[must_use]
    pub fn score_milli(&self, doc: usize, query: &[String], params: Params) -> u64 {
        let Some((tf, len)) = self.docs.get(doc) else {
            return 0;
        };
        if self.total_len == 0 || *len == 0 {
            return 0;
        }
        let n_docs = u64::try_from(self.docs.len()).unwrap_or(u64::MAX);
        let k1 = u128::from(params.k1_milli);
        let b = u128::from(params.b_milli.min(1000));
        // (1 - b) + b * len / avg_len, with avg_len = total_len / n_docs.
        let norm = ((1000 - b) * ONE
            + b * u128::from(*len) * u128::from(n_docs) * ONE / u128::from(self.total_len))
            / 1000;
        let mut score: u128 = 0;
        for term in query {
            let Some(&freq) = tf.get(term) else {
                continue;
            };
            let n = self.df.get(term).copied().unwrap_or(0);
            let idf = log2_q16(n_docs.saturating_mul(2).saturating_add(2))
                .saturating_sub(log2_q16(n.saturating_mul(2).saturating_add(1)));
            let freq = u128::from(freq);
            let numerator = freq * (k1 + 1000) * ONE / 1000;
            let denominator = freq * ONE + k1 * norm / 1000;
            if denominator == 0 {
                continue;
            }
            let tf_part = numerator * ONE / denominator;
            score += idf * tf_part / ONE;
        }
        u64::try_from(score * 1000 / ONE).unwrap_or(u64::MAX)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn log2_is_exact_on_powers_and_monotone() {
        assert_eq!(log2_q16(1), 0);
        assert_eq!(log2_q16(2), ONE);
        assert_eq!(log2_q16(1024), 10 * ONE);
        assert_eq!(log2_q16(u64::MAX >> 1) >> FRAC_BITS, 62);
        let mut last = 0;
        for x in 1..4000u64 {
            let v = log2_q16(x);
            assert!(v >= last);
            last = v;
        }
        // log2(3) = 1.58496...
        let v = log2_q16(3);
        assert!((103_870..=103_875).contains(&v), "{v}");
    }

    #[test]
    fn tokenizer_lowercases_drops_stop_words_and_dedupes_query() {
        let t = Tokenizer::new();
        assert_eq!(
            t.tokens("The Quick, brown fox is at the zoo"),
            ["quick", "brown", "fox", "zoo"]
        );
        assert_eq!(t.query_terms("Fox fox QUICK"), ["fox", "quick"]);
        assert!(t.tokens("... --- !!!").is_empty());
    }

    #[test]
    fn rarer_matching_terms_score_higher() {
        let t = Tokenizer::new();
        let chunks: Vec<Vec<String>> = [
            "alpha beta gamma",
            "alpha delta epsilon",
            "alpha zeta eta",
            "theta iota rare",
        ]
        .iter()
        .map(|c| t.tokens(c))
        .collect();
        let corpus = Corpus::new(&chunks);
        let params = Params {
            k1_milli: 1200,
            b_milli: 750,
        };
        let common = corpus.score_milli(0, &["alpha".to_owned()], params);
        let rare = corpus.score_milli(3, &["rare".to_owned()], params);
        let none = corpus.score_milli(1, &["rare".to_owned()], params);
        assert!(rare > common, "{rare} {common}");
        assert_eq!(none, 0);
        // Deterministic.
        assert_eq!(rare, corpus.score_milli(3, &["rare".to_owned()], params));
    }
}
