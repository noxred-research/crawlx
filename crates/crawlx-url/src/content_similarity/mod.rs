//! Page-content near-duplicate filtering for the URL plane.
//!
//! Ported from projectdiscovery/katana `pkg/similarity/{normalize,simhash,
//! lexical,index}.go` at commit 9662cd7 (MIT). Bodies are normalized to the
//! text of their main content ([`normalize`]), then matched against earlier
//! representatives by one of three backends: `simhash` (Hamming band),
//! `tfidf` or `bm25` (score threshold). Each cluster has a budget of fully
//! processed pages; further members are reported as filtered. Everything is
//! deterministic and in-memory.

pub mod index;
pub mod lexical;
pub mod normalize;
pub mod simhash;

pub use index::{Accept, Config, Index, Stats};
pub use normalize::{normalize, Document, MIN_TOKENS, SHINGLE_SIZE};
pub use simhash::{hamming_distance, simhash64};
