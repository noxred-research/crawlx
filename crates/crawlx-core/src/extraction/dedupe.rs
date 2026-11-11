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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DedupeKindV1 {
    /// Normalized extracted block.
    Block,
    /// Normalized title and body of a whole document.
    Content,
}

/// Result of checking or recording a hash in [`DedupeCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
#[must_use]
pub enum DedupeAdmissionV1 {
    /// No committed sighting; recording caches the hash, while checking leaves it absent.
    New,
    /// The hash was admitted before.
    Seen {
        /// Earlier sightings, not counting this one.
        sightings: u32,
        /// Whether the first sighting carried the same origin digest as this one.
        same_origin: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EntryKey {
    scope: u64,
    kind: DedupeKindV1,
    hash: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Entry {
    tick: u64,
    sightings: u32,
    origin: Digest,
}

/// Version of the bounded, hash-only checkpoint representation.
pub const DEDUPE_SNAPSHOT_VERSION: u32 = 1;

/// Why a dedupe checkpoint cannot be restored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DedupeSnapshotError {
    /// The snapshot format is not supported.
    #[error("dedupe snapshot version {found} is not supported")]
    Version {
        /// Version recorded in the checkpoint.
        found: u32,
    },
    /// Capacity or serialized collection bounds are invalid.
    #[error("dedupe snapshot exceeds cache bounds")]
    Bounds,
    /// Tenant, source namespace or key labels do not match the checkpoint binding.
    #[error("dedupe snapshot scope binding does not match")]
    Binding,
    /// Entry identifiers, counts or logical recency are inconsistent.
    #[error("dedupe snapshot records are inconsistent")]
    Inconsistent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotScope {
    key: DedupeKeyV1,
    id: u64,
    entries: usize,
}

/// Hash-only continuation state, subject to the enclosing checkpoint's custody and expiry.
///
/// Private fields prevent constructing unchecked snapshots except by deserialization. Restore
/// validates every record before exposing a cache. Entry ticks encode the complete eviction order;
/// no article, paragraph, URL or wall-clock value is stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DedupeSnapshotV1 {
    version: u32,
    tenant: String,
    namespace: String,
    capacity: usize,
    tick: u64,
    next_scope: u64,
    #[serde(deserialize_with = "bounded_records")]
    scopes: Vec<SnapshotScope>,
    #[serde(deserialize_with = "bounded_records")]
    entries: Vec<(EntryKey, Entry)>,
}

impl DedupeSnapshotV1 {
    /// Validate bounds, key bindings, counts and eviction order without changing namespaces.
    ///
    /// # Errors
    /// Returns a typed refusal for an unknown version, invalid bounds or inconsistent records.
    pub fn validate(&self) -> Result<(), DedupeSnapshotError> {
        DedupeCache::restore(self, self.capacity, &self.tenant, &self.namespace).map(|_| ())
    }
}

fn bounded_records<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Records<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Records<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded array of dedupe hash records")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut records = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_DEDUPE_CACHE_ENTRIES));
            while let Some(record) = seq.next_element()? {
                if records.len() == MAX_DEDUPE_CACHE_ENTRIES {
                    return Err(serde::de::Error::custom("dedupe snapshot exceeds record bounds"));
                }
                records.push(record);
            }
            Ok(records)
        }
    }
    deserializer.deserialize_seq(Records(std::marker::PhantomData))
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
    /// Capture exact logical recency and hash counts for an enclosing authorized checkpoint.
    ///
    /// The caller supplies the checkpoint's tenant and source-run namespace. Restoration refuses
    /// any partition outside this binding; this method grants no cross-run authorization.
    #[must_use]
    pub fn snapshot(&self, tenant: &str, namespace: &str) -> DedupeSnapshotV1 {
        DedupeSnapshotV1 {
            version: DEDUPE_SNAPSHOT_VERSION,
            tenant: tenant.to_owned(),
            namespace: namespace.to_owned(),
            capacity: self.capacity,
            tick: self.tick,
            next_scope: self.next_scope,
            scopes: self
                .scopes
                .iter()
                .map(|(key, id)| SnapshotScope {
                    key: key.clone(),
                    id: *id,
                    entries: self.scope_entries.get(id).copied().unwrap_or(0),
                })
                .collect(),
            entries: self.entries.iter().map(|(key, entry)| (*key, *entry)).collect(),
        }
    }

    /// Restore an authorized checkpoint, rebinding its source run to `namespace`.
    ///
    /// Tenant identity never changes. Role/session, extractor, policy and normalization bindings,
    /// entry identifiers, counts and logical recency remain exact.
    ///
    /// # Errors
    /// Refuses unsupported versions, a different capacity or tenant, invalid labels, oversized
    /// collections, orphaned/duplicate entries or partitions, and inconsistent recency or counts.
    pub fn restore(
        snapshot: &DedupeSnapshotV1,
        capacity: usize,
        tenant: &str,
        namespace: &str,
    ) -> Result<Self, DedupeSnapshotError> {
        use DedupeSnapshotError::{Binding, Bounds, Inconsistent, Version};
        if snapshot.version != DEDUPE_SNAPSHOT_VERSION {
            return Err(Version {
                found: snapshot.version,
            });
        }
        if capacity == 0
            || capacity > MAX_DEDUPE_CACHE_ENTRIES
            || snapshot.capacity != capacity
            || snapshot.entries.len() > capacity
            || snapshot.scopes.len() > snapshot.entries.len()
        {
            return Err(Bounds);
        }
        if snapshot.tenant != tenant
            || !label_ok(tenant)
            || !label_ok(namespace)
            || !label_ok(&snapshot.namespace)
        {
            return Err(Binding);
        }
        if snapshot.next_scope > snapshot.tick || snapshot.tick == u64::MAX || snapshot.next_scope == u64::MAX
        {
            return Err(Inconsistent);
        }
        let mut restored = Self {
            capacity,
            tick: snapshot.tick,
            next_scope: snapshot.next_scope,
            scopes: BTreeMap::new(),
            scope_entries: BTreeMap::new(),
            entries: BTreeMap::new(),
            order: BTreeMap::new(),
        };
        for scope in &snapshot.scopes {
            let mut key = scope.key.clone();
            if key.scope.tenant != tenant
                || key.scope.namespace != snapshot.namespace
                || !label_ok(&key.scope.role)
                || !label_ok(&key.extractor)
                || !label_ok(&key.normalization)
            {
                return Err(Binding);
            }
            key.scope.namespace = namespace.to_owned();
            if scope.id >= snapshot.next_scope
                || scope.entries == 0
                || scope.entries > capacity
                || restored.scopes.insert(key, scope.id).is_some()
                || restored.scope_entries.insert(scope.id, 0).is_some()
            {
                return Err(Inconsistent);
            }
        }
        let mut sightings = 0u64;
        for (key, entry) in &snapshot.entries {
            let owned = restored.scope_entries.get_mut(&key.scope).ok_or(Inconsistent)?;
            if entry.tick == 0
                || entry.tick > snapshot.tick
                || entry.sightings == 0
                || u64::from(entry.sightings) > entry.tick
                || restored.entries.insert(*key, *entry).is_some()
                || restored.order.insert(entry.tick, *key).is_some()
            {
                return Err(Inconsistent);
            }
            *owned = owned.checked_add(1).ok_or(Bounds)?;
            sightings = sightings
                .checked_add(u64::from(entry.sightings))
                .ok_or(Inconsistent)?;
        }
        if restored
            .order
            .last_key_value()
            .map(|(tick, _)| *tick)
            .unwrap_or(0)
            != snapshot.tick
            || sightings > snapshot.tick
            || snapshot
                .scopes
                .iter()
                .any(|scope| restored.scope_entries.get(&scope.id).copied() != Some(scope.entries))
        {
            return Err(Inconsistent);
        }
        Ok(restored)
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
    /// Inspect a committed hash without changing sightings, recency, partitions or eviction order.
    /// `New` means absent; no admission occurs until [`Self::record`] or [`Self::admit`].
    pub fn check(
        &self,
        key: &DedupeKeyV1,
        kind: DedupeKindV1,
        hash: [u8; 32],
        origin: Digest,
    ) -> DedupeAdmissionV1 {
        let Some(scope) = self.scopes.get(key).copied() else {
            return DedupeAdmissionV1::New;
        };
        match self.entries.get(&EntryKey { scope, kind, hash }) {
            Some(entry) => DedupeAdmissionV1::Seen {
                sightings: entry.sightings,
                same_origin: entry.origin == origin,
            },
            None => DedupeAdmissionV1::New,
        }
    }

    /// Record one committed observation using the same ordered admission rules as [`Self::admit`].
    pub fn record(
        &mut self,
        key: &DedupeKeyV1,
        kind: DedupeKindV1,
        hash: [u8; 32],
        origin: Digest,
    ) -> DedupeAdmissionV1 {
        self.admit(key, kind, hash, origin)
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
    fn checking_preserves_exact_snapshot_for_present_absent_and_foreign_hashes() {
        let mut cache = DedupeCache::new(2).unwrap();
        let k = key("tenant", "run", "anonymous");
        let o = origin("first");
        let _ = cache.record(&k, DedupeKindV1::Content, hash(1), o);
        let before = cache.snapshot("tenant", "run");
        for _ in 0..3 {
            assert_eq!(
                cache.check(&k, DedupeKindV1::Content, hash(1), o),
                DedupeAdmissionV1::Seen {
                    sightings: 1,
                    same_origin: true
                }
            );
            assert_eq!(
                cache.check(&k, DedupeKindV1::Content, hash(1), origin("other")),
                DedupeAdmissionV1::Seen {
                    sightings: 1,
                    same_origin: false
                }
            );
            assert_eq!(
                cache.check(&k, DedupeKindV1::Block, hash(1), o),
                DedupeAdmissionV1::New
            );
            assert_eq!(
                cache.check(&k, DedupeKindV1::Content, hash(2), o),
                DedupeAdmissionV1::New
            );
            assert_eq!(
                cache.check(&key("tenant", "run", "member"), DedupeKindV1::Content, hash(1), o),
                DedupeAdmissionV1::New
            );
        }
        assert_eq!(before, cache.snapshot("tenant", "run"));
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
    fn snapshot_roundtrip_preserves_partitions_counts_origins_and_exact_eviction_order() {
        let mut original = DedupeCache::new(3).unwrap();
        let keys = [
            key("tenant", "old-run", "anonymous"),
            key("tenant", "old-run", "member"),
        ];
        for (partition, n) in [(0, 1), (1, 2), (0, 3), (0, 1)] {
            let _ = original.admit(&keys[partition], DedupeKindV1::Content, hash(n), origin("first"));
        }
        let saved = original.snapshot("tenant", "old-run");
        let json = serde_json::to_string(&saved).unwrap();
        assert!(!json.contains("first"));
        let decoded: DedupeSnapshotV1 = serde_json::from_str(&json).unwrap();
        let mut restored = DedupeCache::restore(&decoded, 3, "tenant", "old-run").unwrap();
        assert_eq!(saved, restored.snapshot("tenant", "old-run"));
        for (partition, n) in [(0, 1), (0, 4), (1, 2), (0, 3), (1, 5)] {
            let expected = original.admit(&keys[partition], DedupeKindV1::Content, hash(n), origin("next"));
            let actual = restored.admit(&keys[partition], DedupeKindV1::Content, hash(n), origin("next"));
            assert_eq!(actual, expected);
            assert_eq!(
                original.snapshot("tenant", "old-run"),
                restored.snapshot("tenant", "old-run")
            );
        }
        let mut remapped = DedupeCache::restore(&saved, 3, "tenant", "new-run").unwrap();
        assert_eq!(
            remapped.admit(
                &key("tenant", "new-run", "anonymous"),
                DedupeKindV1::Content,
                hash(1),
                origin("other"),
            ),
            DedupeAdmissionV1::Seen {
                sightings: 2,
                same_origin: false
            }
        );
        assert_eq!(
            remapped.admit(&keys[0], DedupeKindV1::Content, hash(1), origin("first"),),
            DedupeAdmissionV1::New
        );
    }

    #[test]
    fn snapshot_refuses_versions_bounds_corruption_and_foreign_scope_bindings() {
        use DedupeSnapshotError::{Binding, Bounds, Inconsistent, Version};
        let mut cache = DedupeCache::new(2).unwrap();
        let _ = cache.admit(
            &key("tenant", "run", "role"),
            DedupeKindV1::Block,
            hash(1),
            origin("a"),
        );
        let _ = cache.admit(
            &key("tenant", "run", "role"),
            DedupeKindV1::Content,
            hash(2),
            origin("b"),
        );
        let saved = cache.snapshot("tenant", "run");
        let assert_refused = |snapshot: &DedupeSnapshotV1, expected| {
            assert_eq!(
                DedupeCache::restore(snapshot, 2, "tenant", "next").unwrap_err(),
                expected
            );
        };
        let mut bad = saved.clone();
        bad.version = 2;
        assert_refused(&bad, Version { found: 2 });
        let mut bad = saved.clone();
        bad.capacity = MAX_DEDUPE_CACHE_ENTRIES + 1;
        assert_refused(&bad, Bounds);
        let mut bad = saved.clone();
        bad.entries.push(saved.entries[0]);
        assert_refused(&bad, Bounds);
        assert_eq!(
            DedupeCache::restore(&saved, 1, "tenant", "next").unwrap_err(),
            Bounds
        );
        assert_eq!(
            DedupeCache::restore(&saved, 2, "other", "next").unwrap_err(),
            Binding
        );
        for corrupt in 0..8 {
            let mut bad = saved.clone();
            match corrupt {
                0 => bad.entries[0].0.scope = 99,
                1 => bad.entries[0].1.tick = bad.entries[1].1.tick,
                2 => bad.entries[0].1.sightings = 0,
                3 => bad.scopes[0].entries = 1,
                4 => bad.next_scope = 0,
                5 => bad.tick = bad.tick.saturating_add(1),
                6 => bad.entries[0] = bad.entries[1],
                _ => bad.entries[0].1.sightings = u32::MAX,
            }
            assert_refused(&bad, Inconsistent);
        }
        let mut bad = saved.clone();
        bad.scopes[0].key.scope.tenant = "other".to_owned();
        assert_refused(&bad, Binding);
        let mut bad = saved.clone();
        bad.scopes[0].key.scope.namespace = "other-run".to_owned();
        assert_refused(&bad, Binding);
        let mut bad = saved.clone();
        bad.scopes[0].key.normalization.clear();
        assert_refused(&bad, Binding);
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
