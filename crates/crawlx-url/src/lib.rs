//! crawlx-url: canonicalization, query-parameter classification, sitemaps,
//! link discovery, URL-shape fingerprints, extension and content-similarity
//! filters, and the in-memory URL frontier.
//!
//! Everything here is pure and deterministic: no I/O, no wall time, no
//! unseeded randomness.

pub mod canonical;
pub mod content_similarity;
pub mod destination_key;
pub mod error;
pub mod extensions;
pub mod feed;
pub mod fingerprint;
pub mod frontier;
pub mod links;
pub mod params;
pub mod path_climb;
pub mod route_template;
pub mod scope;
pub mod sitemap;

pub use canonical::{
    origin_of, CanonicalizeOptions, Canonicalized, Canonicalizer, TrailingSlash, KEY_DOMAIN,
    RESOURCE_ID_DOMAIN,
};
pub use content_similarity::{Accept as SimilarityAccept, Index as SimilarityIndex};
pub use destination_key::destination_key;
pub use error::UrlError;
pub use extensions::{ExtensionFilter, DEFAULT_EXTENSION_FILTER};
pub use fingerprint::{fingerprint_url, Fingerprint, PathTrie};
pub use frontier::{BlockKind, DedupeReason, Frontier, FrontierEntry, LinkSource, PushOutcome};
pub use links::{extract_links, LinkKind, RawLink};
pub use params::{bucket_value, looks_like_id, shannon_entropy, ParamClassifier, ParamObservation};
pub use path_climb::parent_paths;
pub use route_template::RouteTemplater;
pub use scope::{host_relation, HostRelation, PathFilter, ScopeDecision, ScopeFilter};
pub use sitemap::{
    PendingSitemap, SitemapDoc, SitemapKind, SitemapParser, SitemapRef, SitemapTraversal, SitemapUrl,
    MAX_DEPTH, MAX_URLS,
};
