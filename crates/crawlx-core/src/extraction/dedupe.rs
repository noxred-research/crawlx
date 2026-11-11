//! Bounded, caller-scoped dedupe contracts for extracted content.
//!
//! Three separate stages share these types: extracted-block dedupe (a repeated paragraph is
//! dropped from the selected output), post-parse content dedupe (the same normalized title and
//! body at two URLs is rejected from ingestion with `duplicate_main`), and the digest report that
//! keeps raw, page, main and comment hashes distinct. The cache stores fixed-size hashes and
//! counts, never paragraph text, has no clock and no process-global state: recency is a logical
//! counter that advances once per admission, so replaying the same admission order evicts the
//! same entries.

use crate::{hash::Digest, CoreError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Hard ceiling for [`DedupeCache::new`]; one entry is a fixed-size hash record.
pub const MAX_DEDUPE_CACHE_ENTRIES: usize = 262_144;
/// Normalization identifier recorded with every digest set.
pub const DEDUPE_NORMALIZATION_V1: &str = "dedupe_text_v1";
/// Digest domain prefix recorded with every digest set.
pub const DEDUPE_DIGEST_DOMAIN_V1: &str = "crawlx.extract.dedupe.v1";
const MAX_LABEL_BYTES: usize = 128;
const MAX_MIN_BLOCK_CHARS: usize = 4096;

fn label_ok(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= MAX_LABEL_BYTES && !value.chars().any(char::is_control)
}

/// Opt-in dedupe policy. `None` on the extraction policy preserves legacy behavior and the
/// serialized policy identity; `Some` records the digest report and enables the chosen stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DedupePolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Remove repeated normalized blocks from the selected main output. Without this flag a
    /// repeated block (a quoted legal notice, a refrain) is retained.
    pub blocks: bool,
    /// Reject a document whose normalized title and body were already admitted in the same
    /// cache scope (`duplicate_main`). Acquisitions and origins stay distinct.
    pub content: bool,
    /// Blocks with fewer normalized scalars than this are never deduplicated (at most 4096).
    pub min_block_chars: usize,
}
impl Default for DedupePolicyV1 {
    fn default() -> Self {
        Self {
            version: 1,
            blocks: false,
            content: false,
            min_block_chars: 16,
        }
    }
}
impl DedupePolicyV1 {
    /// Validate version and bounds.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` for an unknown version or an out-of-range block minimum.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.version == 1 && self.min_block_chars <= MAX_MIN_BLOCK_CHARS {
            Ok(())
        } else {
            Err(CoreError::Invalid {
                field: "extract.content.dedupe",
                reason: "unsupported version or min_block_chars above 4096".into(),
            })
        }
    }
}

/// Caller-supplied cache partition: tenant, run/source namespace and role/session label.
/// Every label is non-blank, at most 128 bytes and free of control characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DedupeScopeV1 {
    tenant: String,
    namespace: String,
    role: String,
}
impl DedupeScopeV1 {
    /// Construct a validated scope.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` when a label is blank, longer than 128 bytes or contains a
    /// control character.
    pub fn new(tenant: &str, namespace: &str, role: &str) -> Result<Self, CoreError> {
        for (field, value) in [
            ("dedupe.tenant", tenant),
            ("dedupe.namespace", namespace),
            ("dedupe.role", role),
        ] {
            if !label_ok(value) {
                return Err(CoreError::Invalid {
                    field,
                    reason: "label must be non-blank, at most 128 bytes, without control characters".into(),
                });
            }
        }
        Ok(Self {
            tenant: tenant.to_owned(),
            namespace: namespace.to_owned(),
            role: role.to_owned(),
        })
    }
    /// Tenant label.
    #[must_use]
    pub fn tenant(&self) -> &str {
        &self.tenant
    }
    /// Run or source namespace label.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    /// Role or session representation label.
    #[must_use]
    pub fn role(&self) -> &str {
        &self.role
    }
    /// Bind the scope to the extractor, policy and normalization versions. Entries admitted
    /// under one key are invisible under any other.
    #[must_use]
    pub fn key(&self, extractor: &str, policy: Digest, normalization: &str) -> DedupeKeyV1 {
        DedupeKeyV1 {
            scope: self.clone(),
            extractor: extractor.to_owned(),
            policy,
            normalization: normalization.to_owned(),
        }
    }
}

/// Full cache partition key: scope plus extractor, policy and normalization versions.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DedupeKeyV1 {
    scope: DedupeScopeV1,
    extractor: String,
    policy: Digest,
    normalization: String,
}
impl DedupeKeyV1 {
    /// Caller scope of this key.
    #[must_use]
    pub fn scope(&self) -> &DedupeScopeV1 {
        &self.scope
    }
}

/// What a cached hash identifies. Kinds never match each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum DedupeKindV1 {
    /// Normalized extracted block.
    Block,
    /// Normalized title and body of a whole document.
    Content,
}

/// Result of [`DedupeCache::admit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum DedupeAdmissionV1 {
    /// First sighting in this partition; the hash is now cached.
    New,
    /// The hash was admitted before.
    Seen {
        /// Earlier sightings, not counting this one.
        sightings: u32,
        /// Whether the first sighting carried the same origin digest as this one.
        same_origin: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EntryKey {
    scope: u64,
    kind: DedupeKindV1,
    hash: [u8; 32],
}
#[derive(Debug, Clone, Copy)]
struct Entry {
    tick: u64,
    sightings: u32,
    origin: Digest,
}

/// Bounded least-recently-admitted hash cache. Admission order is the call order: callers that
/// extract concurrently and need a reproducible result admit in their ordered-commit sequence.
#[derive(Debug, Clone)]
pub struct DedupeCache {
    capacity: usize,
    tick: u64,
    next_scope: u64,
    scopes: BTreeMap<DedupeKeyV1, u64>,
    scope_entries: BTreeMap<u64, usize>,
    entries: BTreeMap<EntryKey, Entry>,
    order: BTreeMap<u64, EntryKey>,
}
impl DedupeCache {
    /// Create a cache holding at most `capacity` hashes across all partitions.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` unless `1 <= capacity <= MAX_DEDUPE_CACHE_ENTRIES`.
    pub fn new(capacity: usize) -> Result<Self, CoreError> {
        if capacity == 0 || capacity > MAX_DEDUPE_CACHE_ENTRIES {
            return Err(CoreError::Invalid {
                field: "dedupe.cache_capacity",
                reason: format!("capacity must be in 1..={MAX_DEDUPE_CACHE_ENTRIES}"),
            });
        }
        Ok(Self {
            capacity,
            tick: 0,
            next_scope: 0,
            scopes: BTreeMap::new(),
            scope_entries: BTreeMap::new(),
            entries: BTreeMap::new(),
            order: BTreeMap::new(),
        })
    }
    /// Maximum number of cached hashes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
    /// Current number of cached hashes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// True when nothing is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Number of partitions that currently own at least one entry.
    #[must_use]
    pub fn partitions(&self) -> usize {
        self.scopes.len()
    }
    /// Record one hash in `key`'s partition. A repeat refreshes recency; a new hash may evict the
    /// least recently admitted entry of any partition.
    pub fn admit(
        &mut self,
        key: &DedupeKeyV1,
        kind: DedupeKindV1,
        hash: [u8; 32],
        origin: Digest,
    ) -> DedupeAdmissionV1 {
        self.tick = self.tick.saturating_add(1);
        let tick = self.tick;
        let scope = if let Some(id) = self.scopes.get(key) {
            *id
        } else {
            let id = self.next_scope;
            self.next_scope = self.next_scope.saturating_add(1);
            self.scopes.insert(key.clone(), id);
            id
        };
        let entry_key = EntryKey { scope, kind, hash };
        if let Some(entry) = self.entries.get_mut(&entry_key) {
            let previous = entry.sightings;
            let same_origin = entry.origin == origin;
            self.order.remove(&entry.tick);
            entry.tick = tick;
            entry.sightings = previous.saturating_add(1);
            self.order.insert(tick, entry_key);
            return DedupeAdmissionV1::Seen {
                sightings: previous,
                same_origin,
            };
        }
        self.entries.insert(
            entry_key,
            Entry {
                tick,
                sightings: 1,
                origin,
            },
        );
        self.order.insert(tick, entry_key);
        let owned = self.scope_entries.entry(scope).or_insert(0);
        *owned = owned.saturating_add(1);
        while self.entries.len() > self.capacity {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
            if let Some(owned) = self.scope_entries.get_mut(&oldest.scope) {
                *owned = owned.saturating_sub(1);
                if *owned == 0 {
                    self.scope_entries.remove(&oldest.scope);
                    self.scopes.retain(|_, id| *id != oldest.scope);
                }
            }
        }
        DedupeAdmissionV1::New
    }
}

/// Distinct digests of one acquisition, with the normalization and domain that produced them.
/// Raw covers response bytes, page the whole filtered page text, main the selected article text
/// and comment the separately selected comment text. Same main text under different page chrome
/// has the same `main` and different `raw` and `page` digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ContentDigestsV1 {
    /// Exactly one.
    pub version: u16,
    /// Text normalization identifier applied before page, main and comment hashing.
    pub normalization: String,
    /// Digest domain prefix of the page, main and comment digests.
    pub domain: String,
    /// Digest of the raw input bytes.
    pub raw: Digest,
    /// Digest of the normalized text of the whole filtered page.
    pub page: Digest,
    /// Digest of the normalized selected main text.
    pub main: Digest,
    /// Digest of the normalized comment text, absent when there are no comments.
    pub comment: Option<Digest>,
    /// 64-bit similarity fingerprint of the main text from the shared URL-plane engine,
    /// sixteen lowercase hexadecimal digits. Near duplicates differ in few bits.
    pub main_simhash: String,
}
impl ContentDigestsV1 {
    /// Construct a version-one digest set under [`DEDUPE_NORMALIZATION_V1`].
    #[must_use]
    pub fn new(raw: Digest, page: Digest, main: Digest, comment: Option<Digest>, main_simhash: u64) -> Self {
        Self {
            version: 1,
            normalization: DEDUPE_NORMALIZATION_V1.into(),
            domain: DEDUPE_DIGEST_DOMAIN_V1.into(),
            raw,
            page,
            main,
            comment,
            main_simhash: format!("{main_simhash:016x}"),
        }
    }
}

/// Dedupe evidence attached to the document envelope when a dedupe policy is present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DedupeReportV1 {
    /// Exactly one.
    pub version: u16,
    /// Distinct raw, page, main and comment digests.
    pub digests: ContentDigestsV1,
    /// Whether a caller-scoped cache was consulted (otherwise only this document was compared).
    pub cache_scoped: bool,
    /// Normalized blocks that were eligible for comparison.
    pub blocks_seen: usize,
    /// Blocks removed from the selected output as repeats.
    pub blocks_removed: usize,
    /// Lowercase hexadecimal SHA-256 of the normalized title and body, when content dedupe ran.
    pub content_sha256: Option<String>,
    /// The content hash was already admitted in this cache scope.
    pub content_duplicate: bool,
    /// For a content duplicate: whether the earlier sighting had the same origin. Origins are
    /// compared exactly; `http`, `https` and `www` variants never merge.
    pub duplicate_same_origin: Option<bool>,
    /// Exact scheme, host and port of this acquisition's final URL.
    pub origin: String,
}
impl DedupeReportV1 {
    /// Construct a version-one report with no content-dedupe outcome; the caller sets the
    /// `content_*` fields when the content stage ran.
    #[must_use]
    pub fn new(
        digests: ContentDigestsV1,
        cache_scoped: bool,
        blocks_seen: usize,
        blocks_removed: usize,
        origin: String,
    ) -> Self {
        Self {
            version: 1,
            digests,
            cache_scoped,
            blocks_seen,
            blocks_removed,
            content_sha256: None,
            content_duplicate: false,
            duplicate_same_origin: None,
            origin,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn key(tenant: &str, namespace: &str, role: &str) -> DedupeKeyV1 {
        DedupeScopeV1::new(tenant, namespace, role).unwrap().key(
            "extractor_v1",
            Digest::of("t", b"policy"),
            DEDUPE_NORMALIZATION_V1,
        )
    }
    fn hash(n: u8) -> [u8; 32] {
        [n; 32]
    }
    fn origin(label: &str) -> Digest {
        Digest::of("t.origin", label.as_bytes())
    }

    #[test]
    fn partitions_isolate_tenant_namespace_role_and_versions() {
        let mut cache = DedupeCache::new(64).unwrap();
        let base = key("t1", "run-a", "anonymous");
        assert_eq!(
            cache.admit(&base, DedupeKindV1::Block, hash(1), origin("o")),
            DedupeAdmissionV1::New
        );
        assert_eq!(
            cache.admit(&base, DedupeKindV1::Block, hash(1), origin("o")),
            DedupeAdmissionV1::Seen {
                sightings: 1,
                same_origin: true
            }
        );
        for other in [
            key("t2", "run-a", "anonymous"),
            key("t1", "run-b", "anonymous"),
            key("t1", "run-a", "member"),
            DedupeScopeV1::new("t1", "run-a", "anonymous").unwrap().key(
                "extractor_v2",
                Digest::of("t", b"policy"),
                DEDUPE_NORMALIZATION_V1,
            ),
            DedupeScopeV1::new("t1", "run-a", "anonymous").unwrap().key(
                "extractor_v1",
                Digest::of("t", b"other"),
                DEDUPE_NORMALIZATION_V1,
            ),
            DedupeScopeV1::new("t1", "run-a", "anonymous").unwrap().key(
                "extractor_v1",
                Digest::of("t", b"policy"),
                "dedupe_text_v2",
            ),
        ] {
            assert_eq!(
                cache.admit(&other, DedupeKindV1::Block, hash(1), origin("o")),
                DedupeAdmissionV1::New
            );
        }
        // block and content hashes never match each other
        assert_eq!(
            cache.admit(&base, DedupeKindV1::Content, hash(1), origin("o")),
            DedupeAdmissionV1::New
        );
    }

    #[test]
    fn eviction_is_least_recently_admitted_and_replays_identically() {
        let run = || {
            let mut cache = DedupeCache::new(3).unwrap();
            let k = key("t", "n", "r");
            let mut trace = Vec::new();
            for n in [1u8, 2, 3, 1, 4, 2, 3, 5, 1] {
                trace.push(cache.admit(&k, DedupeKindV1::Block, hash(n), origin("o")));
                assert!(cache.len() <= 3);
            }
            trace
        };
        let first = run();
        assert_eq!(first, run());
        // 1 refreshed before 4 arrives, so 2 is the evicted entry and is new again afterwards
        assert_eq!(first[4], DedupeAdmissionV1::New);
        assert_eq!(first[5], DedupeAdmissionV1::New);
    }

    #[test]
    fn emptied_partitions_are_released() {
        let mut cache = DedupeCache::new(1).unwrap();
        let _ = cache.admit(&key("t", "a", "r"), DedupeKindV1::Block, hash(1), origin("o"));
        let _ = cache.admit(&key("t", "b", "r"), DedupeKindV1::Block, hash(1), origin("o"));
        assert_eq!((cache.len(), cache.partitions()), (1, 1));
    }

    #[test]
    fn origin_difference_is_reported_without_merging() {
        let mut cache = DedupeCache::new(8).unwrap();
        let k = key("t", "n", "r");
        let _ = cache.admit(&k, DedupeKindV1::Content, hash(7), origin("http://example.test"));
        assert_eq!(
            cache.admit(
                &k,
                DedupeKindV1::Content,
                hash(7),
                origin("https://www.example.test")
            ),
            DedupeAdmissionV1::Seen {
                sightings: 1,
                same_origin: false
            }
        );
    }

    #[test]
    fn bounds_are_enforced() {
        assert!(DedupeCache::new(0).is_err());
        assert!(DedupeCache::new(MAX_DEDUPE_CACHE_ENTRIES + 1).is_err());
        assert!(DedupeScopeV1::new("", "n", "r").is_err());
        assert!(DedupeScopeV1::new("t", &"x".repeat(129), "r").is_err());
        assert!(DedupeScopeV1::new("t", "n", "r\n").is_err());
        let mut policy = DedupePolicyV1::default();
        assert!(policy.validate().is_ok());
        policy.min_block_chars = 4097;
        assert!(policy.validate().is_err());
        policy = DedupePolicyV1::default();
        policy.version = 2;
        assert!(policy.validate().is_err());
    }
}
