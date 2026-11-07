//! URL-shape fingerprints.
//!
//! Ported from projectdiscovery/katana `pkg/utils/urlfingerprint.go` and
//! `pkg/utils/pathtrie.go` at commit 9662cd7 (MIT).
//!
//! Layer 1 replaces variable path segments by anchored placeholders
//! (`{uuid}`, `{sha256}`, `{sha1}`, `{md5}`, `{oid}`, `{hex}`, `{date}`,
//! `{ts}`, `{num}`); layer 2 is a per-host adaptive [`PathTrie`] that promotes
//! a position to `{param}` once more than `threshold` distinct literal values
//! were seen there. Query values are dropped and keys sorted. Everything is
//! deterministic: no regex engine (hand-written matchers), ordered maps only.

use std::collections::BTreeMap;
use std::fmt;

use url::Url;

use crate::params::is_uuid;

/// Distinct children a trie position accumulates before promotion (`scope.filterSimilarThreshold`).
pub const DEFAULT_PROMOTION_THRESHOLD: u32 = 10;
/// Hosts tracked by a [`PathTrie`] before the least recently used one is evicted.
pub const DEFAULT_MAX_HOSTS: usize = 1000;
/// Placeholder for a trie-promoted position.
pub const PARAM_PLACEHOLDER: &str = "{param}";

/// A URL-shape fingerprint: scheme, host, templated path and sorted query keys.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Fingerprint(pub String);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn all_hex(b: &[u8]) -> bool {
    b.iter().all(u8::is_ascii_hexdigit)
}

fn all_digits(b: &[u8]) -> bool {
    b.iter().all(u8::is_ascii_digit)
}

/// Pure-numeric strings that happen to be ≥ 8 digits fall through to the
/// timestamp/numeric patterns instead of matching as hex.
fn contains_hex_letter(b: &[u8]) -> bool {
    b.iter().any(|c| matches!(c, b'a'..=b'f' | b'A'..=b'F'))
}

fn is_date(b: &[u8]) -> bool {
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && all_digits(&b[..4])
        && all_digits(&b[5..7])
        && all_digits(&b[8..])
}

/// Placeholder for `segment` when it matches one of the anchored patterns,
/// tested from most to least specific exactly as katana does.
#[must_use]
pub fn segment_placeholder(segment: &str) -> Option<&'static str> {
    let b = segment.as_bytes();
    if b.is_empty() {
        return None;
    }
    if is_uuid(b) {
        return Some("{uuid}");
    }
    if all_hex(b) && contains_hex_letter(b) {
        return match b.len() {
            64 => Some("{sha256}"),
            40 => Some("{sha1}"),
            32 => Some("{md5}"),
            24 => Some("{oid}"),
            n if n >= 8 => Some("{hex}"),
            _ => None,
        };
    }
    if is_date(b) {
        return Some("{date}");
    }
    if all_digits(b) {
        return Some(if matches!(b.len(), 10 | 13) {
            "{ts}"
        } else {
            "{num}"
        });
    }
    None
}

#[derive(Clone, Debug, Default)]
struct TrieNode {
    children: BTreeMap<String, TrieNode>,
    param_child: Option<Box<TrieNode>>,
    promoted: bool,
}

#[derive(Clone, Debug)]
struct HostTrie {
    root: TrieNode,
    last_used: u64,
}

/// Per-host adaptive trie; a position whose node accumulates more than
/// `threshold` distinct children is promoted and every later value at that
/// position collapses to [`PARAM_PLACEHOLDER`]. Host tries are bounded by an
/// LRU of `max_hosts` entries.
#[derive(Clone, Debug)]
pub struct PathTrie {
    hosts: BTreeMap<String, HostTrie>,
    /// `last_used` → host, for O(log n) eviction.
    by_use: BTreeMap<u64, String>,
    threshold: usize,
    max_hosts: usize,
    tick: u64,
}

impl Default for PathTrie {
    fn default() -> Self {
        Self::new(DEFAULT_PROMOTION_THRESHOLD)
    }
}

impl PathTrie {
    /// Trie promoting a position after more than `threshold` distinct values
    /// (`0` selects [`DEFAULT_PROMOTION_THRESHOLD`]); bounded to [`DEFAULT_MAX_HOSTS`].
    #[must_use]
    pub fn new(threshold: u32) -> Self {
        let threshold = if threshold == 0 {
            DEFAULT_PROMOTION_THRESHOLD
        } else {
            threshold
        };
        Self {
            hosts: BTreeMap::new(),
            by_use: BTreeMap::new(),
            threshold: threshold as usize,
            max_hosts: DEFAULT_MAX_HOSTS,
            tick: 0,
        }
    }

    /// Bound the number of tracked hosts (minimum 1).
    #[must_use]
    pub fn with_max_hosts(mut self, max_hosts: usize) -> Self {
        self.max_hosts = max_hosts.max(1);
        self
    }

    /// Promotion threshold.
    #[must_use]
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Hosts currently tracked.
    #[must_use]
    pub fn host_count(&self) -> usize {
        self.hosts.len()
    }

    /// Is `host` tracked?
    #[must_use]
    pub fn contains_host(&self, host: &str) -> bool {
        self.hosts.contains_key(host)
    }

    /// Mark `host` as most recently used, creating (and evicting) as needed.
    /// `None` only if the map lost the entry it just inserted (impossible).
    fn touch(&mut self, host: &str) -> Option<&mut TrieNode> {
        self.tick += 1;
        let tick = self.tick;
        if let Some(entry) = self.hosts.get_mut(host) {
            self.by_use.remove(&entry.last_used);
            entry.last_used = tick;
        } else {
            while self.hosts.len() >= self.max_hosts {
                let Some((_, victim)) = self.by_use.pop_first() else {
                    break;
                };
                self.hosts.remove(&victim);
            }
            self.hosts.insert(
                host.to_owned(),
                HostTrie {
                    root: TrieNode::default(),
                    last_used: tick,
                },
            );
        }
        self.by_use.insert(tick, host.to_owned());
        self.hosts.get_mut(host).map(|h| &mut h.root)
    }

    /// Walk the trie for `host`, registering literal segments and replacing
    /// promoted positions by [`PARAM_PLACEHOLDER`].
    pub fn fingerprint(&mut self, host: &str, segments: &mut [String]) {
        if segments.is_empty() {
            return;
        }
        let threshold = self.threshold;
        let Some(mut current) = self.touch(host) else {
            return;
        };
        for seg in segments.iter_mut() {
            if current.promoted {
                *seg = PARAM_PLACEHOLDER.to_owned();
                current = current.param_child.get_or_insert_with(Box::default);
                continue;
            }
            if !current.children.contains_key(seg.as_str()) {
                if current.children.len() >= threshold {
                    // this distinct child would exceed the threshold: promote
                    current.promoted = true;
                    current.children = BTreeMap::new();
                    *seg = PARAM_PLACEHOLDER.to_owned();
                    current = current.param_child.get_or_insert_with(Box::default);
                    continue;
                }
                current.children.insert(seg.clone(), TrieNode::default());
            }
            let Some(child) = current.children.get_mut(seg.as_str()) else {
                return;
            };
            current = child;
        }
    }
}

/// Fingerprint `url`: layer-1 placeholders on each path segment, layer 2 via
/// `trie` when given, query values dropped and keys sorted, fragment ignored.
#[must_use]
pub fn fingerprint_url(url: &Url, trie: Option<&mut PathTrie>) -> Fingerprint {
    let path = url.path();
    let mut out = String::with_capacity(url.as_str().len());
    out.push_str(url.scheme());
    out.push_str("://");
    if let Some(host) = url.host_str() {
        out.push_str(host);
    }
    if let Some(port) = url.port() {
        out.push(':');
        out.push_str(&port.to_string());
    }
    let trimmed = path.trim_matches('/');
    if trimmed.is_empty() {
        out.push_str(path);
    } else {
        let mut segments: Vec<String> = trimmed
            .split('/')
            .map(|seg| segment_placeholder(seg).map_or_else(|| seg.to_owned(), str::to_owned))
            .collect();
        if let Some(trie) = trie {
            trie.fingerprint(url.host_str().unwrap_or(""), &mut segments);
        }
        out.push('/');
        out.push_str(&segments.join("/"));
        if path.ends_with('/') {
            out.push('/');
        }
    }
    if url.query().is_some() {
        let mut keys: Vec<String> = url.query_pairs().map(|(k, _)| k.into_owned()).collect();
        keys.sort_unstable();
        keys.dedup();
        if !keys.is_empty() {
            out.push('?');
            out.push_str(&keys.join("&"));
        }
    }
    Fingerprint(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn fp(s: &str) -> String {
        fingerprint_url(&Url::parse(s).unwrap(), None).0
    }

    fn fp_t(s: &str, t: &mut PathTrie) -> String {
        fingerprint_url(&Url::parse(s).unwrap(), Some(t)).0
    }

    #[test]
    fn segment_pattern_table() {
        let cases: &[(&str, Option<&str>)] = &[
            ("550e8400-e29b-41d4-a716-446655440000", Some("{uuid}")),
            ("550E8400-E29B-41D4-A716-446655440000", Some("{uuid}")),
            ("12345678-1234-1234-1234-123456789012", Some("{uuid}")),
            (
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                Some("{sha256}"),
            ),
            (
                "1234567890123456789012345678901234567890123456789012345678901234",
                Some("{num}"),
            ),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", Some("{sha1}")),
            ("1234567890123456789012345678901234567890", Some("{num}")),
            ("d41d8cd98f00b204e9800998ecf8427e", Some("{md5}")),
            ("12345678901234567890123456789012", Some("{num}")),
            ("507f1f77bcf86cd799439011", Some("{oid}")),
            ("123456789012345678901234", Some("{num}")),
            ("abcdef01", Some("{hex}")),
            ("1234abcd5678", Some("{hex}")),
            ("DEADBEEF", Some("{hex}")),
            ("12345678", Some("{num}")),
            ("123456789", Some("{num}")),
            ("2024-01-15", Some("{date}")),
            ("1999-01-01", Some("{date}")),
            ("20240115", Some("{num}")),
            ("1704067200", Some("{ts}")),
            ("1704067200000", Some("{ts}")),
            ("17040672001", Some("{num}")),
            ("17040672000001", Some("{num}")),
            ("123", Some("{num}")),
            ("0", Some("{num}")),
            ("users", None),
            ("v1", None),
            ("my-awesome-post", None),
            ("image123.jpg", None),
            ("abcdef", None),
            ("feedback", None),
            ("deadbeef-cafe", None),
            ("", None),
        ];
        for (seg, want) in cases {
            assert_eq!(segment_placeholder(seg), *want, "{seg}");
        }
    }

    #[test]
    fn regex_only_fingerprints() {
        let cases = [
            (
                "https://example.com/api/v1/users/123/posts/456",
                "https://example.com/api/v1/users/{num}/posts/{num}",
            ),
            (
                "https://example.com/product/550e8400-e29b-41d4-a716-446655440000",
                "https://example.com/product/{uuid}",
            ),
            (
                "https://example.com/archive/2024-01-15/article",
                "https://example.com/archive/{date}/article",
            ),
            (
                "https://example.com/search?z=1&a=2&m=3",
                "https://example.com/search?a&m&z",
            ),
            ("https://example.com/about/team", "https://example.com/about/team"),
            ("https://example.com/", "https://example.com/"),
            (
                "https://example.com/users/42/posts/da39a3ee5e6b4b0d3255bfef95601890afd80709",
                "https://example.com/users/{num}/posts/{sha1}",
            ),
            (
                "https://example.com/api/v1/users/123/",
                "https://example.com/api/v1/users/{num}/",
            ),
            (
                "https://example.com/events/1704067200",
                "https://example.com/events/{ts}",
            ),
            ("http://example.com/items/99", "http://example.com/items/{num}"),
            (
                "https://example.com:8443/api/users/42",
                "https://example.com:8443/api/users/{num}",
            ),
            (
                "https://example.com/page/123#section",
                "https://example.com/page/{num}",
            ),
            (
                "https://example.com/users/42/posts?sort=date&page=1",
                "https://example.com/users/{num}/posts?page&sort",
            ),
            (
                "https://cdn.example.com/assets/d41d8cd98f00b204e9800998ecf8427e/image.png",
                "https://cdn.example.com/assets/{md5}/image.png",
            ),
            (
                "https://example.com/docs/507f1f77bcf86cd799439011",
                "https://example.com/docs/{oid}",
            ),
            (
                "https://example.com/verify/abcdef0123456789",
                "https://example.com/verify/{hex}",
            ),
            ("https://example.com/42", "https://example.com/{num}"),
            ("https://example.com/?q=test", "https://example.com/?q"),
            (
                "https://example.com/assets/image123.jpg",
                "https://example.com/assets/image123.jpg",
            ),
            (
                "https://example.com/a/1/b/2/c/3/d/4",
                "https://example.com/a/{num}/b/{num}/c/{num}/d/{num}",
            ),
        ];
        for (url, want) in cases {
            assert_eq!(fp(url), want, "{url}");
        }
    }

    #[test]
    fn similar_urls_collapse_and_distinct_stay_distinct() {
        assert_eq!(
            fp("https://example.com/users/123"),
            fp("https://example.com/users/456")
        );
        assert_eq!(
            fp("https://example.com/search?q=foo&page=1"),
            fp("https://example.com/search?page=5&q=bar")
        );
        assert_ne!(
            fp("https://example.com/users/123/profile"),
            fp("https://example.com/users/123/settings")
        );
        assert_ne!(
            fp("https://example.com/api/v1/users"),
            fp("https://example.com/api/v2/users")
        );
        assert_ne!(
            fp("https://example.com/search?q=test"),
            fp("https://example.com/search?q=test&page=1")
        );
        // stable across repeated calls and independent of query order
        let once = fp("https://example.com/users/123/posts/456?z=1&a=2");
        assert_eq!(fp("https://example.com/users/123/posts/456?a=2&z=1"), once);
        assert_eq!(once, "https://example.com/users/{num}/posts/{num}?a&z");
    }

    #[test]
    fn trie_promotes_after_threshold_and_isolates_hosts() {
        let mut t = PathTrie::new(0);
        for i in 0..DEFAULT_PROMOTION_THRESHOLD {
            let u = format!("https://example.com/blog/post-{i}");
            assert_eq!(fp_t(&u, &mut t), u, "before promotion");
        }
        // exactly threshold distinct children: still literal
        assert_eq!(
            fp_t("https://example.com/blog/post-0", &mut t),
            "https://example.com/blog/post-0"
        );
        // one more distinct child promotes the position
        assert_eq!(
            fp_t("https://example.com/blog/the-trigger", &mut t),
            "https://example.com/blog/{param}"
        );
        assert_eq!(
            fp_t("https://example.com/blog/never-seen", &mut t),
            "https://example.com/blog/{param}"
        );
        assert_eq!(
            fp_t("https://example.com/blog/post-0", &mut t),
            "https://example.com/blog/{param}"
        );
        // other hosts are unaffected
        assert_eq!(
            fp_t("https://b.com/blog/alice", &mut t),
            "https://b.com/blog/alice"
        );
        // regex-normalized segments never inflate the trie
        for i in 0..100 {
            fp_t(&format!("https://example.com/items/{i}/details"), &mut t);
        }
        assert_eq!(
            fp_t("https://example.com/items/brand-new-slug/details", &mut t),
            "https://example.com/items/brand-new-slug/details"
        );
        // deep promotion keeps static neighbours and tracks later positions independently
        for i in 0..=DEFAULT_PROMOTION_THRESHOLD {
            fp_t(&format!("https://example.com/api/users/user-{i}/posts"), &mut t);
        }
        assert_eq!(
            fp_t("https://example.com/api/users/new/posts", &mut t),
            "https://example.com/api/users/{param}/posts"
        );
        assert_eq!(
            fp_t("https://example.com/api/users/x/settings", &mut t),
            "https://example.com/api/users/{param}/settings"
        );
        // custom threshold 3 promotes on the 4th distinct child
        let mut t3 = PathTrie::new(3);
        for s in ["a", "b", "c"] {
            fp_t(&format!("https://h.test/items/{s}"), &mut t3);
        }
        assert_eq!(fp_t("https://h.test/items/a", &mut t3), "https://h.test/items/a");
        assert_eq!(
            fp_t("https://h.test/items/d", &mut t3),
            "https://h.test/items/{param}"
        );
        // an empty trie behaves like no trie
        let mut e = PathTrie::new(0);
        for u in [
            "https://example.com/users/123",
            "https://example.com/about",
            "https://example.com/search?q=test&page=1",
        ] {
            assert_eq!(fp_t(u, &mut e), fp(u));
        }
    }

    #[test]
    fn trie_evicts_least_recently_used_host() {
        let mut t = PathTrie::new(0).with_max_hosts(2);
        for i in 0..=DEFAULT_PROMOTION_THRESHOLD {
            fp_t(&format!("https://a.test/p/{i}-x"), &mut t);
        }
        fp_t("https://b.test/p/x", &mut t);
        assert_eq!(t.host_count(), 2);
        // touching a keeps it fresh; c evicts b
        fp_t("https://a.test/p/y", &mut t);
        fp_t("https://c.test/p/x", &mut t);
        assert!(t.contains_host("a.test") && t.contains_host("c.test") && !t.contains_host("b.test"));
        assert_eq!(fp_t("https://a.test/p/zzz", &mut t), "https://a.test/p/{param}");
        // a is still promoted; b starts fresh after eviction (and evicts c, the LRU)
        fp_t("https://b.test/p/x", &mut t);
        assert_eq!(fp_t("https://b.test/p/y", &mut t), "https://b.test/p/y");
        assert!(!t.contains_host("c.test"));
        // the default bound holds up under many hosts
        let mut big = PathTrie::new(0);
        for i in 0..(DEFAULT_MAX_HOSTS + 50) {
            fp_t(&format!("https://h{i}.test/path/segment"), &mut big);
        }
        assert_eq!(big.host_count(), DEFAULT_MAX_HOSTS);
    }
}
