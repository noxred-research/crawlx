//! In-memory frontier.
//!
//! Breadth-first order (ascending): `(depth, source rank, inverse sitemap
//! priority, discovery order)`, so BFS by depth, seeds before sitemap entries
//! before links, higher sitemap `<priority>` first, and discovery order as the
//! deterministic final tie-break. Depth-first order pops the most recently
//! discovered, deepest entry first. Entries are deduplicated by the canonical
//! `key`; a key stays "seen" after it is popped. Every entry carries its
//! URL-shape [`Fingerprint`]; with the similar-URL filter on, a fingerprint
//! admits at most `budget` entries. An optional [`ExtensionFilter`] and a
//! per-host page limit are enforced at push time. Counters follow the
//! `discovered = admitted + deduplicated + policy_blocked + robots_blocked`
//! invariant of `crawlx_core::counters::Counters`; every `deduplicated`
//! increment is attributed to a [`DedupeReason`].

use std::collections::hash_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crawlx_core::config::CrawlStrategy;
use crawlx_core::counters::Counters;
use crawlx_core::hash::Digest;
use crawlx_core::url::CanonicalUrl;

use crate::extensions::ExtensionFilter;
use crate::fingerprint::{fingerprint_url, Fingerprint, PathTrie};

/// How a URL was discovered; lower rank is dequeued first at equal depth.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum LinkSource {
    /// A seed URL supplied by the user.
    Seed,
    /// Listed in a sitemap.
    Sitemap,
    /// Followed from a navigation link (pagination, next page).
    Navigation,
    /// Found in a fetched page body.
    Body,
    /// Observed by the browser plane (DOM links, network requests).
    Browser,
}

impl LinkSource {
    const fn rank(self) -> u8 {
        match self {
            Self::Seed => 0,
            Self::Sitemap => 1,
            Self::Navigation => 2,
            Self::Body => 3,
            Self::Browser => 4,
        }
    }
}

/// Why a discovered URL was refused before reaching the frontier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockKind {
    /// Refused by the scope or admission policy.
    Policy,
    /// Refused by the origin's robots.txt.
    Robots,
}

/// Why an item was counted as `deduplicated` (`urls.dedupe_reason`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum DedupeReason {
    /// Same canonical key as an earlier entry.
    Canonical,
    /// Same URL-shape fingerprint beyond `scope.filterSimilarBudget`.
    Fingerprint,
    /// Same body digest as an earlier page (BLAKE3).
    ContentExact,
    /// Near-duplicate body beyond the content-similarity cluster budget.
    ContentSimilar,
    /// Extension refused by the extension filter.
    Extension,
}

impl DedupeReason {
    /// Stable code for counters and the frontier row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Canonical => "canonical",
            Self::Fingerprint => "fingerprint",
            Self::ContentExact => "content_exact",
            Self::ContentSimilar => "content_similar",
            Self::Extension => "extension",
        }
    }

    /// Every reason, in declaration order.
    pub const ALL: [Self; 5] = [
        Self::Canonical,
        Self::Fingerprint,
        Self::ContentExact,
        Self::ContentSimilar,
        Self::Extension,
    ];
}

/// Result of [`Frontier::push`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PushOutcome {
    /// The URL entered the queue.
    Admitted,
    /// The key was already queued or already seen (`deduplicated`, `canonical`).
    Duplicate,
    /// Deeper than the configured maximum; counted as `policy_blocked`.
    DepthExceeded,
    /// Its fingerprint already consumed the similar-URL budget (`deduplicated`, `fingerprint`).
    FilteredSimilar,
    /// Its extension is refused by the extension filter (`deduplicated`, `extension`).
    ExtensionFiltered,
    /// The host already admitted `maxPagesPerHost` pages; counted as `policy_blocked`.
    HostPageLimit,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct SortKey {
    depth: u32,
    rank: u8,
    inverse_priority: u16,
    seq: u64,
}

/// A queued URL.
#[derive(Clone, Debug)]
pub struct FrontierEntry {
    /// Canonical URL of the entry.
    pub url: CanonicalUrl,
    /// Link-hops from the seed; the seed is depth 0.
    pub depth: u32,
    /// How the URL was discovered.
    pub source: LinkSource,
    /// Sitemap `<priority>` (`0.0..=1.0`) when the URL came from a sitemap.
    pub sitemap_priority: Option<f32>,
    /// Discovery order (0-based).
    pub seq: u64,
    /// URL-shape fingerprint recorded for the `url_frontier` row.
    pub fingerprint: Fingerprint,
}

#[derive(Debug)]
struct SimilarFilter {
    trie: PathTrie,
    budget: u32,
    /// fingerprint → admitted entries
    counts: BTreeMap<Fingerprint, u32>,
}

/// In-memory URL frontier.
#[derive(Debug, Default)]
pub struct Frontier {
    queue: BTreeMap<SortKey, FrontierEntry>,
    by_origin: HashMap<String, BTreeSet<SortKey>>,
    seen: HashSet<Digest>,
    /// Body digests seen, with the key of the entry that had the body first.
    content_seen: HashMap<Digest, Digest>,
    counters: Counters,
    dedupe: BTreeMap<DedupeReason, u64>,
    next_seq: u64,
    max_depth: Option<u32>,
    strategy: CrawlStrategy,
    max_pages_per_host: Option<u32>,
    host_pages: BTreeMap<String, u32>,
    similar: Option<SimilarFilter>,
    extensions: Option<ExtensionFilter>,
    /// `true` once [`Frontier::with_content_dedupe`] turned exact-content dedupe off.
    content_dedupe_off: bool,
}

impl Frontier {
    /// Empty breadth-first frontier without bounds or filters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Refuse entries deeper than `max_depth` (counted as `policy_blocked`).
    #[must_use]
    pub fn with_max_depth(mut self, max_depth: u32) -> Self {
        self.max_depth = Some(max_depth);
        self
    }

    /// Pop order (`scope.strategy`).
    #[must_use]
    pub fn with_strategy(mut self, strategy: CrawlStrategy) -> Self {
        self.strategy = strategy;
        self
    }

    /// Admit at most `max` pages per host (`scope.maxPagesPerHost`; minimum 1).
    #[must_use]
    pub fn with_max_pages_per_host(mut self, max: u32) -> Self {
        self.max_pages_per_host = Some(max.max(1));
        self
    }

    /// Enable the similar-URL filter: a per-host [`PathTrie`] promoting a
    /// position after `threshold` distinct values, and at most `budget`
    /// admitted entries per fingerprint (`scope.filterSimilar*`).
    #[must_use]
    pub fn with_similar_filter(mut self, threshold: u32, budget: u32) -> Self {
        self.similar = Some(SimilarFilter {
            trie: PathTrie::new(threshold),
            budget: budget.max(1),
            counts: BTreeMap::new(),
        });
        self
    }

    /// Refuse URLs whose extension the filter denies (`deduplicated`, `extension`).
    #[must_use]
    pub fn with_extension_filter(mut self, filter: ExtensionFilter) -> Self {
        self.extensions = Some(filter);
        self
    }

    /// Exact-content dedupe on or off (`scope.disableUniqueFilter`, katana `-duf`; default on).
    /// Off, [`Self::note_content`] reports every body as new and keeps no digests, so pages
    /// with byte-identical bodies are all kept. The URL-level dedupe (canonical key,
    /// fingerprint budget) and the content-similarity index are unaffected.
    #[must_use]
    pub fn with_content_dedupe(mut self, enabled: bool) -> Self {
        self.content_dedupe_off = !enabled;
        self
    }

    /// Configured pop order.
    #[must_use]
    pub const fn strategy(&self) -> CrawlStrategy {
        self.strategy
    }

    fn dedupe(&mut self, reason: DedupeReason) {
        self.counters.deduplicated += 1;
        *self.dedupe.entry(reason).or_default() += 1;
    }

    /// Offer a discovered URL. `sitemap_priority` is the sitemap
    /// `<priority>` (`0.0..=1.0`; default `0.5`). Checks, in order: depth,
    /// canonical key, extension filter, host page limit, fingerprint budget.
    pub fn push(
        &mut self,
        url: CanonicalUrl,
        depth: u32,
        source: LinkSource,
        sitemap_priority: Option<f32>,
    ) -> PushOutcome {
        self.counters.discovered += 1;
        if self.max_depth.is_some_and(|m| depth > m) {
            self.counters.policy_blocked += 1;
            return PushOutcome::DepthExceeded;
        }
        if self.seen.contains(&url.key) {
            self.dedupe(DedupeReason::Canonical);
            return PushOutcome::Duplicate;
        }
        if self.extensions.as_ref().is_some_and(|f| !f.allows(&url.url)) {
            self.dedupe(DedupeReason::Extension);
            return PushOutcome::ExtensionFiltered;
        }
        let host = url.url.host_str().unwrap_or("").to_ascii_lowercase();
        let host_pages = self.host_pages.get(&host).copied().unwrap_or(0);
        if self.max_pages_per_host.is_some_and(|m| host_pages >= m) {
            self.counters.policy_blocked += 1;
            return PushOutcome::HostPageLimit;
        }
        let fingerprint = match &mut self.similar {
            Some(f) => {
                let fp = fingerprint_url(&url.url, Some(&mut f.trie));
                let n = f.counts.entry(fp.clone()).or_default();
                if *n >= f.budget {
                    None
                } else {
                    *n += 1;
                    Some(fp)
                }
            }
            None => Some(fingerprint_url(&url.url, None)),
        };
        let Some(fingerprint) = fingerprint else {
            self.dedupe(DedupeReason::Fingerprint);
            return PushOutcome::FilteredSimilar;
        };
        self.seen.insert(url.key);
        self.host_pages.insert(host, host_pages + 1);
        self.counters.admitted += 1;
        let seq = self.next_seq;
        self.next_seq += 1;
        let p = sitemap_priority.unwrap_or(0.5).clamp(0.0, 1.0);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "p is clamped to 0.0..=1.0, so the rounded product is within 0..=1000; NaN saturates to 0"
        )]
        let scaled_priority = (p * 1000.0).round() as u16;
        let key = match self.strategy {
            CrawlStrategy::BreadthFirst => SortKey {
                depth,
                rank: source.rank(),
                inverse_priority: 1000 - scaled_priority,
                seq,
            },
            // deepest first, then most recently discovered first
            CrawlStrategy::DepthFirst => SortKey {
                depth: u32::MAX - depth,
                rank: 0,
                inverse_priority: 0,
                seq: u64::MAX - seq,
            },
            // lowest `depth - surface score` first, breadth-first tie-breaks (katana `priority`)
            CrawlStrategy::Priority => SortKey {
                depth: crawlx_core::priority::priority_depth(&url.url, depth, true),
                rank: source.rank(),
                inverse_priority: 1000 - scaled_priority,
                seq,
            },
        };
        self.by_origin.entry(url.origin.clone()).or_default().insert(key);
        self.queue.insert(
            key,
            FrontierEntry {
                url,
                depth,
                source,
                sitemap_priority,
                seq,
                fingerprint,
            },
        );
        PushOutcome::Admitted
    }

    /// Record a discovered URL that scope/robots/safety refused. It never
    /// enters the queue and is not marked seen.
    pub fn note_blocked(&mut self, kind: BlockKind) {
        self.counters.discovered += 1;
        match kind {
            BlockKind::Policy => self.counters.policy_blocked += 1,
            BlockKind::Robots => self.counters.robots_blocked += 1,
        }
    }

    /// Record a discovered URL refused for `reason` before it was offered
    /// (e.g. the worker's own extension or content checks). It never enters
    /// the queue and is not marked seen.
    pub fn note_deduplicated(&mut self, reason: DedupeReason) {
        self.counters.discovered += 1;
        self.dedupe(reason);
    }

    /// Exact content dedupe for an admitted entry `key` whose fetched body
    /// hashes to `body_digest`. Returns `true` when the body is new. A
    /// repeated body re-attributes the entry from `admitted` to
    /// `deduplicated` (`content_exact`) so `discovered` stays invariant.
    /// An entry fetched again (its lease expired and it was returned, a retry)
    /// is no duplicate of itself: its own body is new again.
    /// Always `true` when [`Self::with_content_dedupe`] turned the dedupe off.
    pub fn note_content(&mut self, key: &Digest, body_digest: Digest) -> bool {
        if self.content_dedupe_off {
            return true;
        }
        match self.content_seen.entry(body_digest) {
            Entry::Vacant(first) => {
                first.insert(*key);
                return true;
            }
            Entry::Occupied(first) if first.get() == key => return true,
            Entry::Occupied(_) => {}
        }
        if !self.seen.contains(key) {
            // not an admitted entry: nothing to re-attribute
            return false;
        }
        self.reattribute(DedupeReason::ContentExact);
        false
    }

    /// Re-attribute the admitted entry `key` to `deduplicated`
    /// (`content_similar`) after the content-similarity index filtered its
    /// body. Returns `false` when `key` was never admitted.
    pub fn note_content_similar(&mut self, key: &Digest) -> bool {
        if !self.seen.contains(key) {
            return false;
        }
        self.reattribute(DedupeReason::ContentSimilar);
        true
    }

    fn reattribute(&mut self, reason: DedupeReason) {
        self.counters.admitted = self.counters.admitted.saturating_sub(1);
        self.dedupe(reason);
    }

    /// Pop the globally best entry.
    pub fn pop(&mut self) -> Option<FrontierEntry> {
        let key = *self.queue.keys().next()?;
        self.take(key)
    }

    /// Pop the best entry for `origin` (politeness is per origin).
    pub fn next_for_origin(&mut self, origin: &str) -> Option<FrontierEntry> {
        let key = *self.by_origin.get(origin)?.iter().next()?;
        self.take(key)
    }

    /// Pop the best entry whose origin satisfies `ready` (e.g. the origin
    /// governor says it may be fetched now); others stay queued.
    pub fn pop_where(&mut self, mut ready: impl FnMut(&str) -> bool) -> Option<FrontierEntry> {
        let key = self
            .queue
            .iter()
            .find(|(_, e)| ready(&e.url.origin))
            .map(|(k, _)| *k)?;
        self.take(key)
    }

    fn take(&mut self, key: SortKey) -> Option<FrontierEntry> {
        let entry = self.queue.remove(&key)?;
        if let Some(set) = self.by_origin.get_mut(&entry.url.origin) {
            set.remove(&key);
            if set.is_empty() {
                self.by_origin.remove(&entry.url.origin);
            }
        }
        Some(entry)
    }

    /// Queued entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Nothing queued?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Queued entries for one origin.
    #[must_use]
    pub fn queued_for_origin(&self, origin: &str) -> usize {
        self.by_origin.get(origin).map_or(0, BTreeSet::len)
    }

    /// Origins with queued work, sorted.
    #[must_use]
    pub fn origins(&self) -> Vec<&str> {
        let mut v: Vec<&str> = self.by_origin.keys().map(String::as_str).collect();
        v.sort_unstable();
        v
    }

    /// Has this canonical key been admitted before (queued or popped)?
    #[must_use]
    pub fn has_seen(&self, key: &Digest) -> bool {
        self.seen.contains(key)
    }

    /// Pages admitted so far for `host` (lowercase).
    #[must_use]
    pub fn host_pages(&self, host: &str) -> u32 {
        self.host_pages.get(host).copied().unwrap_or(0)
    }

    /// Snapshot of the URL-plane counters maintained here.
    #[must_use]
    pub const fn counters(&self) -> Counters {
        self.counters
    }

    /// `deduplicated` broken down by reason (zero for unseen reasons).
    #[must_use]
    pub fn dedupe_count(&self, reason: DedupeReason) -> u64 {
        self.dedupe.get(&reason).copied().unwrap_or(0)
    }

    /// All non-zero dedupe reasons with their counts, in [`DedupeReason`] order.
    #[must_use]
    pub fn dedupe_counts(&self) -> &BTreeMap<DedupeReason, u64> {
        &self.dedupe
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::{CanonicalizeOptions, Canonicalizer};
    use url::Url;

    fn c(s: &str) -> CanonicalUrl {
        let base = Url::parse("https://a.example/").unwrap();
        Canonicalizer::canonicalize(s, &base, &CanonicalizeOptions::default()).unwrap()
    }

    #[test]
    fn orders_by_depth_source_priority_then_discovery() {
        let mut f = Frontier::new();
        f.push(c("https://a.example/d1-body"), 1, LinkSource::Body, None);
        f.push(c("https://a.example/d1-nav"), 1, LinkSource::Navigation, None);
        f.push(c("https://a.example/d0"), 0, LinkSource::Seed, None);
        f.push(c("https://a.example/sm-low"), 1, LinkSource::Sitemap, Some(0.1));
        f.push(c("https://a.example/sm-high"), 1, LinkSource::Sitemap, Some(0.9));
        f.push(c("https://a.example/sm-high2"), 1, LinkSource::Sitemap, Some(0.9));
        let order: Vec<String> = std::iter::from_fn(|| f.pop())
            .map(|e| e.url.url.path().to_owned())
            .collect();
        assert_eq!(
            order,
            ["/d0", "/sm-high", "/sm-high2", "/sm-low", "/d1-nav", "/d1-body"]
        );
    }

    #[test]
    fn dedupes_by_key_even_after_pop_and_counts() {
        let mut f = Frontier::new().with_max_depth(2);
        assert_eq!(
            f.push(c("https://a.example/x?utm_source=1"), 0, LinkSource::Seed, None),
            PushOutcome::Admitted
        );
        assert_eq!(
            f.push(c("https://A.example:443/x#frag"), 1, LinkSource::Body, None),
            PushOutcome::Duplicate
        );
        assert!(f.pop().is_some());
        assert_eq!(
            f.push(c("https://a.example/x"), 1, LinkSource::Body, None),
            PushOutcome::Duplicate
        );
        assert_eq!(
            f.push(c("https://a.example/deep"), 3, LinkSource::Body, None),
            PushOutcome::DepthExceeded
        );
        f.note_blocked(BlockKind::Robots);
        f.note_blocked(BlockKind::Policy);
        let k = f.counters();
        assert_eq!(
            (
                k.discovered,
                k.admitted,
                k.deduplicated,
                k.policy_blocked,
                k.robots_blocked
            ),
            (6, 1, 2, 2, 1)
        );
        assert!(k.invariants_hold());
    }

    #[test]
    fn origin_aware_pop() {
        let mut f = Frontier::new();
        f.push(c("https://a.example/1"), 0, LinkSource::Seed, None);
        f.push(c("https://b.example/1"), 1, LinkSource::Body, None);
        f.push(c("https://b.example/2"), 1, LinkSource::Body, None);
        assert_eq!(f.origins(), ["https://a.example", "https://b.example"]);
        assert_eq!(f.queued_for_origin("https://b.example"), 2);
        let e = f.next_for_origin("https://b.example").unwrap();
        assert_eq!(e.url.url.path(), "/1");
        assert!(f.next_for_origin("https://c.example").is_none());
        let e = f.pop_where(|o| o == "https://b.example").unwrap();
        assert_eq!(e.url.url.path(), "/2");
        assert!(f.pop_where(|o| o == "https://b.example").is_none());
        assert_eq!(f.len(), 1);
        assert_eq!(f.pop().unwrap().url.url.path(), "/1");
        assert!(f.is_empty());
    }

    #[test]
    fn depth_first_pops_most_recent_deepest_first() {
        let mut f = Frontier::new().with_strategy(CrawlStrategy::DepthFirst);
        assert_eq!(f.strategy(), CrawlStrategy::DepthFirst);
        f.push(c("https://a.example/d0"), 0, LinkSource::Seed, None);
        f.push(c("https://a.example/d1-a"), 1, LinkSource::Body, None);
        f.push(c("https://a.example/d1-b"), 1, LinkSource::Body, None);
        f.push(c("https://a.example/d2-a"), 2, LinkSource::Body, None);
        f.push(c("https://a.example/d1-c"), 1, LinkSource::Seed, Some(1.0));
        let order: Vec<String> = std::iter::from_fn(|| f.pop())
            .map(|e| e.url.url.path().to_owned())
            .collect();
        assert_eq!(order, ["/d2-a", "/d1-c", "/d1-b", "/d1-a", "/d0"]);
        // breadth-first keeps the documented order for the same input
        let mut b = Frontier::new();
        b.push(c("https://a.example/d0"), 0, LinkSource::Seed, None);
        b.push(c("https://a.example/d1-a"), 1, LinkSource::Body, None);
        b.push(c("https://a.example/d2-a"), 2, LinkSource::Body, None);
        b.push(c("https://a.example/d1-c"), 1, LinkSource::Seed, Some(1.0));
        let order: Vec<String> = std::iter::from_fn(|| b.pop())
            .map(|e| e.url.url.path().to_owned())
            .collect();
        assert_eq!(order, ["/d0", "/d1-c", "/d1-a", "/d2-a"]);
    }

    #[test]
    fn host_page_limit_counts_as_policy_blocked() {
        let mut f = Frontier::new().with_max_pages_per_host(2);
        assert_eq!(
            f.push(c("https://a.example/1"), 0, LinkSource::Seed, None),
            PushOutcome::Admitted
        );
        assert_eq!(
            f.push(c("https://A.example/2"), 1, LinkSource::Body, None),
            PushOutcome::Admitted
        );
        assert_eq!(
            f.push(c("https://a.example/3"), 1, LinkSource::Body, None),
            PushOutcome::HostPageLimit
        );
        assert_eq!(
            f.push(c("https://b.example/1"), 1, LinkSource::Body, None),
            PushOutcome::Admitted
        );
        assert_eq!(f.host_pages("a.example"), 2);
        assert_eq!(f.host_pages("b.example"), 1);
        // a refused URL is not marked seen: it can be offered again once allowed
        assert!(!f.has_seen(&c("https://a.example/3").key));
        let k = f.counters();
        assert_eq!((k.discovered, k.admitted, k.policy_blocked), (4, 3, 1));
        assert!(k.invariants_hold());
    }

    #[test]
    fn fingerprint_budget_and_dedupe_reasons() {
        let mut f = Frontier::new()
            .with_similar_filter(10, 1)
            .with_extension_filter(ExtensionFilter::defaults());
        assert_eq!(
            f.push(c("https://a.example/users/123"), 0, LinkSource::Seed, None),
            PushOutcome::Admitted
        );
        assert_eq!(
            f.push(c("https://a.example/users/456"), 1, LinkSource::Body, None),
            PushOutcome::FilteredSimilar
        );
        assert_eq!(
            f.push(c("https://a.example/users/123"), 1, LinkSource::Body, None),
            PushOutcome::Duplicate
        );
        assert_eq!(
            f.push(c("https://a.example/logo.png"), 1, LinkSource::Body, None),
            PushOutcome::ExtensionFiltered
        );
        assert_eq!(
            f.push(c("https://a.example/users/123/posts"), 1, LinkSource::Body, None),
            PushOutcome::Admitted
        );
        let e = f.pop().unwrap();
        assert_eq!(e.fingerprint.0, "https://a.example/users/{num}");
        // exact content dedupe re-attributes an admitted entry
        let page = f.pop().unwrap();
        let body = Digest::of("test/body", b"same body");
        assert!(f.note_content(&e.url.key, body));
        assert!(!f.note_content(&page.url.key, body));
        // similarity filter outcome re-attributes too; unknown keys are ignored
        assert!(!f.note_content_similar(&c("https://a.example/never").key));
        f.note_deduplicated(DedupeReason::ContentSimilar);
        let k = f.counters();
        assert_eq!((k.discovered, k.admitted, k.deduplicated), (6, 1, 5));
        assert!(k.invariants_hold());
        assert_eq!(f.dedupe_count(DedupeReason::Canonical), 1);
        assert_eq!(f.dedupe_count(DedupeReason::Fingerprint), 1);
        assert_eq!(f.dedupe_count(DedupeReason::Extension), 1);
        assert_eq!(f.dedupe_count(DedupeReason::ContentExact), 1);
        assert_eq!(f.dedupe_count(DedupeReason::ContentSimilar), 1);
        assert_eq!(
            f.dedupe_counts().keys().copied().collect::<Vec<_>>(),
            DedupeReason::ALL
        );
        assert_eq!(DedupeReason::ContentSimilar.as_str(), "content_similar");
        // without the filter the fingerprint is still recorded (regex-only)
        let mut plain = Frontier::new();
        plain.push(c("https://a.example/blog/2024-01-15"), 0, LinkSource::Seed, None);
        assert_eq!(
            plain.pop().unwrap().fingerprint.0,
            "https://a.example/blog/{date}"
        );
    }

    #[test]
    fn an_entry_fetched_again_is_no_duplicate_of_itself() {
        let mut f = Frontier::new();
        let a = c("https://a.example/a");
        let b = c("https://a.example/b");
        f.push(a.clone(), 0, LinkSource::Seed, None);
        f.push(b.clone(), 1, LinkSource::Body, None);
        let body = Digest::of("test/body", b"same body");
        assert!(f.note_content(&a.key, body));
        // as after a lost lease: the same URL is fetched again and its own body is new again
        assert!(f.note_content(&a.key, body));
        assert_eq!(f.dedupe_count(DedupeReason::ContentExact), 0);
        assert_eq!(f.counters().admitted, 2);
        // another URL with that body is still a duplicate
        assert!(!f.note_content(&b.key, body));
        assert_eq!(f.dedupe_count(DedupeReason::ContentExact), 1);
        assert_eq!(f.counters().admitted, 1);
    }
}
