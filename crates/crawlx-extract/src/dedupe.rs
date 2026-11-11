//! Dedupe stages over extracted content: block dedupe, distinct digests and content dedupe.
//!
//! Three independent stages, all opt-in through `ExtractionPolicyV1::dedupe`:
//!
//! * **Block dedupe** runs on the selected block tree before any rendering. A block whose
//!   normalized text was already admitted (earlier in the document, or earlier in the same
//!   cache scope) is removed from every output, so a repeated sidebar paragraph disappears.
//!   Without the policy flag a repeated block is retained.
//! * **Digests** record separate raw, page, main and comment hashes with the normalization and
//!   domain that produced them, plus a similarity fingerprint from the shared URL-plane engine.
//! * **Content dedupe** is a quality stage after every other gate: the SHA-256 of the
//!   normalized title and body is checked against committed observations in the cache scope.
//!   A match marks the document `duplicate_main`. Both acquisitions and origins stay distinct.
//!
//! Parsing never mutates the shared cache, including recency and sighting counts. Successful
//! extraction returns a runtime-only [`DedupeCommit`]; callers record it only after page commit.
//! Dropping it leaves retries unchanged. Record tokens in ordered-commit sequence for replay.
//! The cache and tokens store hashes and counts only, never paragraph text.
//!
//! # Process transport
//!
//! A helper process parses on a bounded copy of the caller's cache and never owns the original:
//!
//! 1. The parent calls [`DedupeHandle::export_snapshot`] (one short lock, no await) and sends
//!    the [`DedupeSnapshotTransportV1`] with the request.
//! 2. The helper calls [`DedupeSnapshotTransportV1::restore`] and extracts with the returned
//!    handle, then [`DedupeCommitEnvelopeV1::take_from`] on the resulting document. The export
//!    spends the shared admission right, so no clone of the child token can record locally.
//! 3. The parent calls [`DedupeHandle::attach_commit`] on its ORIGINAL handle. The envelope is
//!    accepted only when its key, origin, raw-source digest and observation shape equal what
//!    the parent derives itself from its own scope, policy, page URL and raw bytes. The wire
//!    never selects the cache or the authority. The cache changes only when the page commit
//!    calls [`DedupeCommit::record`]; a dropped reply or refused envelope changes nothing.
//!
//! A cache that also holds partitions of another tenant or namespace cannot be exported: the
//! snapshot format binds one tenant and namespace, so the export is refused rather than
//! narrowed. Every refusal is a fixed [`DedupeTransportError`] that carries no content.

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crawlx_core::extraction::{
    ContentDigestsV1, DedupeAdmissionV1, DedupeCache, DedupeKeyV1, DedupeKindV1, DedupePolicyV1,
    DedupeReportV1, DedupeScopeV1, DedupeSnapshotError, DedupeSnapshotV1, ExtractionPolicyV1,
    QualityOutcomeV1, QualityStatusV1, ARTICLE_EXTRACTOR_ID_V1, DEDUPE_DIGEST_DOMAIN_V1,
    DEDUPE_NORMALIZATION_V1,
};
use crawlx_core::hash::Digest;
use crawlx_url::content_similarity::normalize::{shingles, tokenize};
use crawlx_url::content_similarity::{simhash64, SHINGLE_SIZE};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use url::Url;

use crate::dom::{Elem, Node};
use crate::{article, text, Document, ExtractError, ExtractOptions};

const BLOCK_DOMAIN: &str = "crawlx.extract.dedupe.v1.block";
const PAGE_DOMAIN: &str = "crawlx.extract.dedupe.v1.page";
const MAIN_DOMAIN: &str = "crawlx.extract.dedupe.v1.main";
const COMMENT_DOMAIN: &str = "crawlx.extract.dedupe.v1.comment";
const ORIGIN_DOMAIN: &str = "crawlx.extract.dedupe.v1.origin";

/// Caller-scoped cache handle carried on [`ExtractOptions`]. Cloning shares the cache; two
/// handles are equal when they share one cache under one scope. There is no process-global
/// cache: a caller that passes no handle gets in-document block dedupe only and no content
/// duplicates.
#[derive(Clone)]
pub struct DedupeHandle {
    scope: DedupeScopeV1,
    cache: Arc<Mutex<DedupeCache>>,
}
impl DedupeHandle {
    /// Bind a shared cache to one tenant, namespace and role scope.
    #[must_use]
    pub fn new(scope: DedupeScopeV1, cache: Arc<Mutex<DedupeCache>>) -> Self {
        Self { scope, cache }
    }
    /// Scope this handle admits under.
    #[must_use]
    pub fn scope(&self) -> &DedupeScopeV1 {
        &self.scope
    }

    /// Check retained content digests under this caller's scope and stage content admission.
    ///
    /// No plaintext is reconstructed. Blocks cannot be replayed from the digest report, so this
    /// stages only the content observation. Invalid or differently bound reports stage nothing.
    /// This method never changes the cache; record the returned document token after page commit.
    ///
    /// # Errors
    /// Returns an error when the effective policy cannot be serialized.
    pub fn stage_cached_content(
        &self,
        document: &mut Document,
        policy: &ExtractionPolicyV1,
    ) -> Result<(), ExtractError> {
        document.dedupe_commit = None;
        if !policy.dedupe.is_some_and(|dedupe| dedupe.content) {
            return Ok(());
        }
        let digest = policy_digest(policy)?;
        let Some(envelope) = document.article.as_mut() else {
            return Ok(());
        };
        if envelope.version != 1
            || envelope.extractor != ARTICLE_EXTRACTOR_ID_V1
            || envelope.policy_digest != digest
            || envelope.quality.status != QualityStatusV1::Accepted
        {
            return Ok(());
        }
        let Some(report) = envelope.dedupe.as_mut() else {
            return Ok(());
        };
        if report.version != 1
            || report.digests.version != 1
            || report.digests.normalization != DEDUPE_NORMALIZATION_V1
            || report.digests.domain != DEDUPE_DIGEST_DOMAIN_V1
            || report.digests.raw != document.raw_html_digest
        {
            return Ok(());
        }
        if report.content_duplicate || report.duplicate_same_origin.is_some() {
            return Ok(());
        }
        let Some(hash) = report.content_sha256.as_deref().and_then(parse_hash) else {
            return Ok(());
        };
        let Ok(url) = Url::parse(&report.origin) else {
            return Ok(());
        };
        if !matches!(url.scheme(), "http" | "https") || crawlx_url::origin_of(&url) != report.origin {
            return Ok(());
        }
        let origin = Digest::of(ORIGIN_DOMAIN, report.origin.as_bytes());
        let key = self
            .scope
            .key(ARTICLE_EXTRACTOR_ID_V1, digest, DEDUPE_NORMALIZATION_V1);
        let admission = self.cache.lock().unwrap_or_else(PoisonError::into_inner).check(
            &key,
            DedupeKindV1::Content,
            hash,
            origin,
        );
        if let DedupeAdmissionV1::Seen { same_origin, .. } = admission {
            report.content_duplicate = true;
            report.duplicate_same_origin = Some(same_origin);
            crate::article_quality::mark_duplicate_main(&mut envelope.quality);
        }
        document.dedupe_commit = Some(DedupeCommit::new(
            self.clone(),
            key,
            origin,
            vec![Observation {
                kind: DedupeKindV1::Content,
                hash,
            }],
        ));
        Ok(())
    }
}
impl fmt::Debug for DedupeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DedupeHandle")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}
impl PartialEq for DedupeHandle {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope && Arc::ptr_eq(&self.cache, &other.cache)
    }
}
impl Eq for DedupeHandle {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observation {
    kind: DedupeKindV1,
    hash: [u8; 32],
}

struct Pending {
    handle: DedupeHandle,
    key: DedupeKeyV1,
    origin: Digest,
    observations: Box<[Observation]>,
    recorded: AtomicBool,
}

/// Hash-only local cache observations awaiting a successful page commit.
///
/// Dropping a token does nothing. Clones share one admission right: recording any clone records
/// the ordered observations once. Equality compares bindings and observations, never cache state.
#[derive(Clone)]
#[non_exhaustive]
#[must_use]
pub struct DedupeCommit {
    pending: Arc<Pending>,
}

impl DedupeCommit {
    fn new(handle: DedupeHandle, key: DedupeKeyV1, origin: Digest, observations: Vec<Observation>) -> Self {
        Self {
            pending: Arc::new(Pending {
                handle,
                key,
                origin,
                observations: observations.into_boxed_slice(),
                recorded: AtomicBool::new(false),
            }),
        }
    }

    /// Consume this admission right after page commit, recording at most once across clones.
    pub fn record(self) {
        if self.pending.recorded.swap(true, Ordering::Relaxed) {
            return;
        }
        let mut cache = self
            .pending
            .handle
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        for observation in &self.pending.observations {
            let _ = cache.record(
                &self.pending.key,
                observation.kind,
                observation.hash,
                self.pending.origin,
            );
        }
    }
}

impl fmt::Debug for DedupeCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DedupeCommit")
            .field("observations", &self.pending.observations.len())
            .finish_non_exhaustive()
    }
}

impl PartialEq for DedupeCommit {
    fn eq(&self, other: &Self) -> bool {
        self.pending.handle == other.pending.handle
            && self.pending.key == other.pending.key
            && self.pending.origin == other.pending.origin
            && self.pending.observations == other.pending.observations
    }
}
impl Eq for DedupeCommit {}

/// Transport version of [`DedupeSnapshotTransportV1`] and [`DedupeCommitEnvelopeV1`].
pub const DEDUPE_TRANSPORT_VERSION: u16 = 1;
/// Most observations one commit envelope may carry.
pub const MAX_DEDUPE_TRANSPORT_OBSERVATIONS: usize = 65_536;
/// Largest serialized (JSON) commit envelope.
pub const MAX_DEDUPE_COMMIT_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;
/// Largest serialized (JSON) cache snapshot; covers a full `MAX_DEDUPE_CACHE_ENTRIES` cache.
pub const MAX_DEDUPE_SNAPSHOT_BYTES: usize = 96 * 1024 * 1024;

/// Why a dedupe snapshot or commit envelope was refused. Messages are fixed and never contain
/// hashes, labels, URLs or text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DedupeTransportError {
    /// The transport version is not supported.
    #[error("dedupe transport version is not supported")]
    Version,
    /// A count, capacity or serialized size is outside the transport bounds.
    #[error("dedupe transport exceeds bounds")]
    Bounds,
    /// The scope, key, origin or raw-source identity does not match the expected binding.
    #[error("dedupe transport binding does not match")]
    Binding,
    /// The effective policy does not enable the requested dedupe stages.
    #[error("dedupe transport policy does not match")]
    Policy,
    /// The observation list is empty, misordered or uses a disabled stage.
    #[error("dedupe transport observations are invalid")]
    Observations,
    /// The cache snapshot is inconsistent or holds partitions outside its tenant and namespace.
    #[error("dedupe transport snapshot is invalid")]
    Snapshot,
    /// The commit right was already consumed.
    #[error("dedupe transport commit was already recorded")]
    Recorded,
    /// The transport payload could not be encoded or decoded.
    #[error("dedupe transport encoding failed")]
    Encoding,
}

struct BoundedCount {
    len: usize,
    max: usize,
}
impl io::Write for BoundedCount {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.len = self.len.saturating_add(buf.len());
        if self.len > self.max {
            return Err(io::Error::other("bound"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Refuse `value` as soon as its serialized JSON size exceeds `max`. Allocates nothing.
fn json_len_within<T: Serialize>(value: &T, max: usize) -> Result<(), DedupeTransportError> {
    let mut count = BoundedCount { len: 0, max };
    serde_json::to_writer(&mut count, value).map_err(|_| DedupeTransportError::Bounds)
}

fn encode<T: Serialize>(value: &T, max: usize) -> Result<Vec<u8>, DedupeTransportError> {
    json_len_within(value, max)?;
    serde_json::to_vec(value).map_err(|_| DedupeTransportError::Encoding)
}

fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8], max: usize) -> Result<T, DedupeTransportError> {
    if bytes.len() > max {
        return Err(DedupeTransportError::Bounds);
    }
    serde_json::from_slice(bytes).map_err(|_| DedupeTransportError::Encoding)
}

/// Hash-only copy of a caller's cache, sent to a helper process with its scope.
///
/// Fields are private: an instance comes from [`DedupeHandle::export_snapshot`] or from a
/// decode, and [`Self::restore`] validates every record before exposing a cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DedupeSnapshotTransportV1 {
    version: u16,
    scope: DedupeScopeV1,
    capacity: usize,
    snapshot: DedupeSnapshotV1,
}

impl DedupeSnapshotTransportV1 {
    /// Scope the restored handle will admit under.
    #[must_use]
    pub fn scope(&self) -> &DedupeScopeV1 {
        &self.scope
    }

    /// Cache capacity the restored copy keeps.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Serialize as JSON within [`MAX_DEDUPE_SNAPSHOT_BYTES`].
    ///
    /// # Errors
    /// Returns `Bounds` for an oversized snapshot and `Encoding` when serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, DedupeTransportError> {
        encode(self, MAX_DEDUPE_SNAPSHOT_BYTES)
    }

    /// Decode and validate JSON bytes; oversized input is refused before parsing.
    ///
    /// # Errors
    /// Returns `Bounds`, `Encoding` or any refusal of [`Self::validate`].
    pub fn from_json(bytes: &[u8]) -> Result<Self, DedupeTransportError> {
        let transport: Self = decode(bytes, MAX_DEDUPE_SNAPSHOT_BYTES)?;
        transport.validate()?;
        Ok(transport)
    }

    /// Validate version, scope labels, bounds, records and eviction order without building a
    /// handle.
    ///
    /// # Errors
    /// Returns `Version`, `Bounds`, `Binding` or `Snapshot`.
    pub fn validate(&self) -> Result<(), DedupeTransportError> {
        self.cache().map(|_| ())
    }

    /// Build the helper's private bounded cache and a handle with the same scope.
    ///
    /// The returned handle owns a copy; nothing it records reaches the exporting cache.
    ///
    /// # Errors
    /// Returns `Version`, `Bounds`, `Binding` or `Snapshot`.
    pub fn restore(&self) -> Result<DedupeHandle, DedupeTransportError> {
        let cache = self.cache()?;
        Ok(DedupeHandle::new(self.scope.clone(), Arc::new(Mutex::new(cache))))
    }

    fn cache(&self) -> Result<DedupeCache, DedupeTransportError> {
        if self.version != DEDUPE_TRANSPORT_VERSION {
            return Err(DedupeTransportError::Version);
        }
        // Deserialization bypasses scope label validation; rebuild and compare.
        let scope = DedupeScopeV1::new(self.scope.tenant(), self.scope.namespace(), self.scope.role())
            .map_err(|_| DedupeTransportError::Binding)?;
        if scope != self.scope {
            return Err(DedupeTransportError::Binding);
        }
        DedupeCache::restore(
            &self.snapshot,
            self.capacity,
            self.scope.tenant(),
            self.scope.namespace(),
        )
        .map_err(|error| match error {
            DedupeSnapshotError::Version { .. } => DedupeTransportError::Version,
            DedupeSnapshotError::Bounds => DedupeTransportError::Bounds,
            DedupeSnapshotError::Binding => DedupeTransportError::Binding,
            _ => DedupeTransportError::Snapshot,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireObservation {
    kind: DedupeKindV1,
    /// Opaque 32-byte hash; the digest type only supplies the hex encoding.
    hash: Digest,
}

/// Hash-only commit observations produced by a helper, carried beside its isolated document.
///
/// The envelope grants nothing by itself. [`DedupeHandle::attach_commit`] rebuilds the commit
/// from the parent's own binding and uses the envelope only for its ordered observations, after
/// proving that every identity field equals the parent's expectation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DedupeCommitEnvelopeV1 {
    version: u16,
    key: DedupeKeyV1,
    origin: Digest,
    raw: Digest,
    observations: Vec<WireObservation>,
}

impl DedupeCommitEnvelopeV1 {
    /// Remove the document's runtime commit and export it with the document's raw-source digest.
    /// `None` when the document staged no observations. The removed token is spent afterward.
    ///
    /// # Errors
    /// Returns `Bounds` for too many observations or an oversized envelope, and `Recorded` when
    /// the token was already consumed.
    pub fn take_from(document: &mut Document) -> Result<Option<Self>, DedupeTransportError> {
        let raw = document.raw_html_digest;
        document
            .dedupe_commit
            .take()
            .map(|commit| commit.export(raw))
            .transpose()
    }

    /// Serialize as JSON within [`MAX_DEDUPE_COMMIT_ENVELOPE_BYTES`].
    ///
    /// # Errors
    /// Returns `Bounds` or `Encoding`.
    pub fn to_json(&self) -> Result<Vec<u8>, DedupeTransportError> {
        encode(self, MAX_DEDUPE_COMMIT_ENVELOPE_BYTES)
    }

    /// Decode JSON bytes; oversized input is refused before parsing. Identity is checked only by
    /// [`DedupeHandle::attach_commit`].
    ///
    /// # Errors
    /// Returns `Bounds` or `Encoding`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DedupeTransportError> {
        decode(bytes, MAX_DEDUPE_COMMIT_ENVELOPE_BYTES)
    }

    /// Number of ordered observations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.observations.len()
    }

    /// True when the envelope carries no observation (never accepted by the parent).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}

impl DedupeCommit {
    /// Spend this token into a transport envelope. No clone can record into the local cache
    /// afterwards: a helper's commit is applied only by the parent.
    fn export(self, raw: Digest) -> Result<DedupeCommitEnvelopeV1, DedupeTransportError> {
        if self.pending.recorded.swap(true, Ordering::Relaxed) {
            return Err(DedupeTransportError::Recorded);
        }
        if self.pending.observations.len() > MAX_DEDUPE_TRANSPORT_OBSERVATIONS {
            return Err(DedupeTransportError::Bounds);
        }
        let envelope = DedupeCommitEnvelopeV1 {
            version: DEDUPE_TRANSPORT_VERSION,
            key: self.pending.key.clone(),
            origin: self.pending.origin,
            raw,
            observations: self
                .pending
                .observations
                .iter()
                .map(|observation| WireObservation {
                    kind: observation.kind,
                    hash: Digest(observation.hash),
                })
                .collect(),
        };
        json_len_within(&envelope, MAX_DEDUPE_COMMIT_ENVELOPE_BYTES)?;
        Ok(envelope)
    }
}

impl DedupeHandle {
    /// Copy this handle's cache for a helper process. Holds the cache lock only while the
    /// snapshot is built; the caller sends the result without holding any lock.
    ///
    /// # Errors
    /// Returns `Snapshot` when the cache holds partitions outside this handle's tenant and
    /// namespace (a copy could not be restored), and `Bounds` for an oversized cache.
    pub fn export_snapshot(&self) -> Result<DedupeSnapshotTransportV1, DedupeTransportError> {
        let (capacity, snapshot) = {
            let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
            (
                cache.capacity(),
                cache.snapshot(self.scope.tenant(), self.scope.namespace()),
            )
        };
        let transport = DedupeSnapshotTransportV1 {
            version: DEDUPE_TRANSPORT_VERSION,
            scope: self.scope.clone(),
            capacity,
            snapshot,
        };
        transport.validate().map_err(|error| match error {
            DedupeTransportError::Binding => DedupeTransportError::Snapshot,
            other => other,
        })?;
        Ok(transport)
    }

    /// Bind a helper's commit envelope to this ORIGINAL handle and install it on `document`.
    ///
    /// `policy`, `page` (the URL given to the extractor) and `raw` (the parent's own raw-source
    /// digest) are the parent's expectation; the envelope must equal every derived identity and
    /// `document.raw_html_digest` must equal `raw`. Any refusal leaves `document.dedupe_commit`
    /// empty and the cache untouched. `None` installs nothing. The cache changes only when the
    /// installed token is recorded after page commit.
    ///
    /// # Errors
    /// Returns `Binding`, `Policy`, `Version`, `Bounds` or `Observations`.
    pub fn attach_commit(
        &self,
        document: &mut Document,
        envelope: Option<&DedupeCommitEnvelopeV1>,
        policy: &ExtractionPolicyV1,
        page: &Url,
        raw: Digest,
    ) -> Result<(), DedupeTransportError> {
        document.dedupe_commit = None;
        if document.raw_html_digest != raw {
            return Err(DedupeTransportError::Binding);
        }
        if let Some(envelope) = envelope {
            document.dedupe_commit = Some(self.rebind_commit(envelope, policy, page, raw)?);
        }
        Ok(())
    }

    /// Validate `envelope` against this handle and the parent's expectation and return a
    /// commit bound to this handle. Nothing is recorded.
    ///
    /// # Errors
    /// Returns `Version`, `Bounds`, `Policy`, `Binding` or `Observations`.
    pub fn rebind_commit(
        &self,
        envelope: &DedupeCommitEnvelopeV1,
        policy: &ExtractionPolicyV1,
        page: &Url,
        raw: Digest,
    ) -> Result<DedupeCommit, DedupeTransportError> {
        if envelope.version != DEDUPE_TRANSPORT_VERSION {
            return Err(DedupeTransportError::Version);
        }
        if envelope.observations.len() > MAX_DEDUPE_TRANSPORT_OBSERVATIONS {
            return Err(DedupeTransportError::Bounds);
        }
        json_len_within(envelope, MAX_DEDUPE_COMMIT_ENVELOPE_BYTES)?;
        let dedupe = policy.dedupe.ok_or(DedupeTransportError::Policy)?;
        let digest = policy_digest(policy).map_err(|_| DedupeTransportError::Policy)?;
        let key = self
            .scope
            .key(ARTICLE_EXTRACTOR_ID_V1, digest, DEDUPE_NORMALIZATION_V1);
        let origin = Digest::of(ORIGIN_DOMAIN, crawlx_url::origin_of(page).as_bytes());
        if envelope.key != key || envelope.origin != origin || envelope.raw != raw {
            return Err(DedupeTransportError::Binding);
        }
        // Native order: block observations in scan order, then at most one content observation.
        let (blocks, content) = match envelope.observations.split_last() {
            None => return Err(DedupeTransportError::Observations),
            Some((last, rest)) if last.kind == DedupeKindV1::Content => (rest, true),
            Some(_) => (envelope.observations.as_slice(), false),
        };
        if (!blocks.is_empty() && !dedupe.blocks)
            || (content && !dedupe.content)
            || blocks.iter().any(|item| item.kind != DedupeKindV1::Block)
        {
            return Err(DedupeTransportError::Observations);
        }
        let observations = envelope
            .observations
            .iter()
            .map(|item| Observation {
                kind: item.kind,
                hash: item.hash.0,
            })
            .collect();
        Ok(DedupeCommit::new(self.clone(), key, origin, observations))
    }
}

fn parse_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut hash = [0; 32];
    let (pairs, _) = value.as_bytes().as_chunks::<2>();
    for (out, &[high, low]) in hash.iter_mut().zip(pairs) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *out = digit(high)? * 16 + digit(low)?;
    }
    Some(hash)
}

/// Dedupe text normalization `dedupe_text_v1`: Unicode lowercase alphanumeric words joined by
/// one space; punctuation, symbols and whitespace runs disappear.
pub(crate) fn normalize(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for word in value
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
    {
        if !out.is_empty() {
            out.push(' ');
        }
        out.extend(word.chars().flat_map(char::to_lowercase));
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// Counts reported by the block stage.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BlockStats {
    pub seen: usize,
    pub removed: usize,
}

/// Content-stage result.
#[derive(Debug, Clone, Default)]
pub(crate) struct ContentStage {
    pub sha256: Option<String>,
    pub duplicate: bool,
    pub same_origin: Option<bool>,
}

/// Per-extraction dedupe state, built once from the options.
pub(crate) struct Context<'a> {
    policy: DedupePolicyV1,
    key: Option<DedupeKeyV1>,
    handle: Option<&'a DedupeHandle>,
    observations: Vec<Observation>,
    origin_text: String,
    origin: Digest,
}

impl<'a> Context<'a> {
    /// `None` when the content policy carries no dedupe policy.
    pub(crate) fn new(opts: &'a ExtractOptions, page: &Url) -> Result<Option<Self>, ExtractError> {
        let Some(policy) = opts.content.as_ref() else {
            return Ok(None);
        };
        let Some(dedupe) = policy.dedupe else {
            return Ok(None);
        };
        let origin_text = crawlx_url::origin_of(page);
        let origin = Digest::of(ORIGIN_DOMAIN, origin_text.as_bytes());
        let (key, handle) = match &opts.dedupe_cache {
            Some(handle) => (
                Some(handle.scope.key(
                    ARTICLE_EXTRACTOR_ID_V1,
                    policy_digest(policy)?,
                    DEDUPE_NORMALIZATION_V1,
                )),
                Some(handle),
            ),
            None => (None, None),
        };
        Ok(Some(Self {
            policy: dedupe,
            key,
            handle,
            observations: Vec::new(),
            origin_text,
            origin,
        }))
    }

    fn lock(&self) -> Option<MutexGuard<'a, DedupeCache>> {
        self.handle
            .map(|handle| handle.cache.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether block removal is enabled.
    pub(crate) fn blocks_enabled(&self) -> bool {
        self.policy.blocks
    }

    /// Remove repeated blocks from the selected tree. `ids` stays aligned with `nodes`.
    pub(crate) fn prune_blocks(&mut self, nodes: &mut Vec<Node>, ids: &mut Vec<usize>) -> BlockStats {
        let guard = self
            .handle
            .map(|handle| handle.cache.lock().unwrap_or_else(PoisonError::into_inner));
        let mut pass = Pass {
            min_chars: self.policy.min_block_chars,
            origin: self.origin,
            cache: guard.as_deref(),
            key: self.key.as_ref(),
            observations: &mut self.observations,
            local: BTreeSet::new(),
            stats: BlockStats::default(),
        };
        let keep: Vec<bool> = nodes.iter_mut().map(|node| pass.keep(node)).collect();
        let aligned = ids.len() == nodes.len();
        let mut flags = keep.iter().copied();
        nodes.retain(|_| flags.next().unwrap_or(true));
        if aligned {
            let mut flags = keep.iter().copied();
            ids.retain(|_| flags.next().unwrap_or(true));
        }
        pass.stats
    }

    /// Distinct raw, page, main and comment digests under the recorded normalization.
    pub(crate) fn digests(&self, raw: Digest, page: &str, main: &str, comments: &str) -> ContentDigestsV1 {
        let main = normalize(main);
        let comments = normalize(comments);
        let tokens = tokenize(&main);
        let fingerprint = simhash64(&shingles(&tokens, SHINGLE_SIZE));
        ContentDigestsV1::new(
            raw,
            Digest::of(PAGE_DOMAIN, normalize(page).as_bytes()),
            Digest::of(MAIN_DOMAIN, main.as_bytes()),
            (!comments.is_empty()).then(|| Digest::of(COMMENT_DOMAIN, comments.as_bytes())),
            fingerprint,
        )
    }

    /// Content dedupe quality stage. Computes the title+body SHA-256 when the stage is enabled
    /// and checks it only when every other gate accepted the document. Observations remain staged
    /// until page commit, so a rejected or rolled-back document cannot shadow a later good one.
    pub(crate) fn content_stage(
        &mut self,
        title: Option<&str>,
        main: &str,
        quality: &mut QualityOutcomeV1,
    ) -> ContentStage {
        if !self.policy.content {
            return ContentStage::default();
        }
        let body = normalize(main);
        if body.is_empty() {
            return ContentStage::default();
        }
        let mut hasher = sha2::Sha256::new();
        hasher.update(normalize(title.unwrap_or_default()).as_bytes());
        hasher.update(b"\n");
        hasher.update(body.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let mut stage = ContentStage {
            sha256: Some(hex(&hash)),
            ..ContentStage::default()
        };
        if quality.status != QualityStatusV1::Accepted {
            return stage;
        }
        let (Some(guard), Some(key)) = (self.lock(), self.key.as_ref()) else {
            return stage;
        };
        let admission = guard.check(key, DedupeKindV1::Content, hash, self.origin);
        drop(guard);
        self.observations.push(Observation {
            kind: DedupeKindV1::Content,
            hash,
        });
        if let DedupeAdmissionV1::Seen { same_origin, .. } = admission {
            stage.duplicate = true;
            stage.same_origin = Some(same_origin);
            crate::article_quality::mark_duplicate_main(quality);
        }
        stage
    }

    /// Assemble the envelope projection.
    pub(crate) fn report(
        &self,
        digests: ContentDigestsV1,
        blocks: BlockStats,
        stage: ContentStage,
    ) -> DedupeReportV1 {
        let mut report = DedupeReportV1::new(
            digests,
            self.handle.is_some(),
            blocks.seen,
            blocks.removed,
            self.origin_text.clone(),
        );
        report.content_sha256 = stage.sha256;
        report.content_duplicate = stage.duplicate;
        report.duplicate_same_origin = stage.same_origin;
        report
    }

    /// Transfer staged hashes only after every fallible extraction stage succeeds.
    pub(crate) fn into_commit(self) -> Option<DedupeCommit> {
        if self.observations.is_empty() {
            return None;
        }
        Some(DedupeCommit::new(
            self.handle?.clone(),
            self.key?,
            self.origin,
            self.observations,
        ))
    }
}

/// Same digest the envelope records, so cache partitions follow the effective policy.
fn policy_digest(policy: &ExtractionPolicyV1) -> Result<Digest, ExtractError> {
    let bytes =
        serde_json::to_vec(policy).map_err(|e| crawlx_core::CoreError::Serialization(e.to_string()))?;
    Ok(Digest::of("crawlx.extract.policy.v1", &bytes))
}

struct Pass<'g> {
    min_chars: usize,
    origin: Digest,
    cache: Option<&'g DedupeCache>,
    key: Option<&'g DedupeKeyV1>,
    observations: &'g mut Vec<Observation>,
    /// Every parse tracks its own blocks, independently of committed cache capacity.
    local: BTreeSet<[u8; 32]>,
    stats: BlockStats,
}
impl Pass<'_> {
    fn keep(&mut self, node: &mut Node) -> bool {
        let Node::Elem(element) = node else {
            return true;
        };
        if article::terminal(element) {
            self.admit(element)
        } else {
            self.prune(element);
            true
        }
    }
    fn prune(&mut self, element: &mut Elem) {
        element.children.retain_mut(|child| self.keep(child));
    }
    fn admit(&mut self, element: &Elem) -> bool {
        let normalized = normalize(&text::element_text(element));
        if normalized.is_empty() || normalized.chars().count() < self.min_chars {
            return true;
        }
        self.stats.seen = self.stats.seen.saturating_add(1);
        let hash = Digest::of(BLOCK_DOMAIN, normalized.as_bytes()).0;
        let first_in_document = self.local.insert(hash);
        let fresh = match (self.cache, self.key) {
            (Some(cache), Some(key)) => {
                self.observations.push(Observation {
                    kind: DedupeKindV1::Block,
                    hash,
                });
                first_in_document
                    && matches!(
                        cache.check(key, DedupeKindV1::Block, hash, self.origin),
                        DedupeAdmissionV1::New
                    )
            }
            _ => first_in_document,
        };
        if !fresh {
            self.stats.removed = self.stats.removed.saturating_add(1);
        }
        fresh
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn staged_block_observations_replay_duplicates_in_exact_scan_order_before_content() {
        let first = "The bridge authority announced the revised crossing timetable for winter travel.";
        let second = "Passengers can inspect every departure time before booking the next river crossing.";
        let html = format!("<body><p>{first}</p><p>{second}</p><p>{first}</p></body>");
        let cache = Arc::new(Mutex::new(DedupeCache::new(2).unwrap()));
        let handle = DedupeHandle::new(
            DedupeScopeV1::new("tenant", "run", "anonymous").unwrap(),
            Arc::clone(&cache),
        );
        let mut policy = ExtractionPolicyV1::default();
        let mut dedupe = DedupePolicyV1::default();
        dedupe.blocks = true;
        dedupe.content = true;
        policy.dedupe = Some(dedupe);
        let mut document = crate::Extractor::extract(
            &html,
            &Url::parse("https://example.test/a").unwrap(),
            &ExtractOptions {
                content: Some(policy.clone()),
                only_main_content: false,
                dedupe_cache: Some(handle.clone()),
                ..ExtractOptions::default()
            },
        )
        .unwrap();
        let report = document.article.as_ref().unwrap().dedupe.as_ref().unwrap();
        assert_eq!(report.blocks_seen, 3);
        assert_eq!(report.blocks_removed, 1);
        let hash = parse_hash(report.content_sha256.as_deref().unwrap()).unwrap();
        let origin = Digest::of(ORIGIN_DOMAIN, report.origin.as_bytes());
        let key = handle.scope.key(
            ARTICLE_EXTRACTOR_ID_V1,
            policy_digest(&policy).unwrap(),
            DEDUPE_NORMALIZATION_V1,
        );
        let mut expected = DedupeCache::new(2).unwrap();
        for paragraph in [first, second, first] {
            let _ = expected.record(
                &key,
                DedupeKindV1::Block,
                Digest::of(BLOCK_DOMAIN, normalize(paragraph).as_bytes()).0,
                origin,
            );
        }
        let _ = expected.record(&key, DedupeKindV1::Content, hash, origin);
        assert!(cache.lock().unwrap().is_empty());
        document.dedupe_commit.take().unwrap().record();
        assert_eq!(
            expected.snapshot("tenant", "run"),
            cache.lock().unwrap().snapshot("tenant", "run")
        );
    }

    const A: &str = "The harbour authority announced new crossing times for the winter season on Monday.";
    const B: &str =
        "Passengers on the northern route will see the earliest departure moved by twenty minutes.";
    const C: &str =
        "Ticket prices stay unchanged and the harbour authority will publish the full timetable online.";
    const D: &str = "Cyclists may board the early service only when the lower deck has free capacity.";

    fn page(paragraphs: &[&str]) -> String {
        let body: String = paragraphs.iter().map(|p| format!("<p>{p}</p>")).collect();
        format!(
            "<html><head><title>Ferry timetable changes</title></head><body><article><h1>Ferry timetable changes</h1>{body}</article></body></html>"
        )
    }

    fn policy(blocks: bool, content: bool) -> ExtractionPolicyV1 {
        let mut policy = ExtractionPolicyV1::default();
        let mut dedupe = DedupePolicyV1::default();
        dedupe.blocks = blocks;
        dedupe.content = content;
        policy.dedupe = Some(dedupe);
        policy
    }

    fn url(path: &str) -> Url {
        Url::parse(&format!("https://example.test/{path}")).unwrap()
    }

    fn raw(html: &str) -> Digest {
        Digest::of(crate::RAW_HTML_DOMAIN, html.as_bytes())
    }

    fn handle(namespace: &str, capacity: usize) -> DedupeHandle {
        DedupeHandle::new(
            DedupeScopeV1::new("tenant", namespace, "anonymous").unwrap(),
            Arc::new(Mutex::new(DedupeCache::new(capacity).unwrap())),
        )
    }

    fn extract(html: &str, path: &str, policy: &ExtractionPolicyV1, handle: &DedupeHandle) -> Document {
        crate::Extractor::extract(
            html,
            &url(path),
            &ExtractOptions {
                content: Some(policy.clone()),
                only_main_content: false,
                dedupe_cache: Some(handle.clone()),
                ..ExtractOptions::default()
            },
        )
        .unwrap()
    }

    fn snapshot_of(handle: &DedupeHandle) -> DedupeSnapshotV1 {
        handle
            .cache
            .lock()
            .unwrap()
            .snapshot(handle.scope().tenant(), handle.scope().namespace())
    }

    fn commit(document: &mut Document) {
        document.dedupe_commit.take().unwrap().record();
    }

    /// Child extraction over a JSON-round-tripped snapshot; returns the child document and its
    /// JSON-round-tripped envelope. The original handle is only read.
    fn child_extract(
        original: &DedupeHandle,
        html: &str,
        path: &str,
        policy: &ExtractionPolicyV1,
    ) -> (Document, Option<DedupeCommitEnvelopeV1>) {
        let snapshot = original.export_snapshot().unwrap();
        let snapshot = DedupeSnapshotTransportV1::from_json(&snapshot.to_json().unwrap()).unwrap();
        let child = snapshot.restore().unwrap();
        assert_eq!(child.scope(), original.scope());
        assert!(!Arc::ptr_eq(&child.cache, &original.cache));
        let mut document = extract(html, path, policy, &child);
        let local = document.dedupe_commit.clone();
        let envelope = DedupeCommitEnvelopeV1::take_from(&mut document).unwrap();
        assert!(document.dedupe_commit.is_none());
        if let Some(local) = local {
            // A clone of the child token is spent: the child cache never records.
            local.record();
            assert_eq!(snapshot_of(&child), snapshot.snapshot);
        }
        let envelope = envelope.map(|e| DedupeCommitEnvelopeV1::from_json(&e.to_json().unwrap()).unwrap());
        (document, envelope)
    }

    fn parity(policy: &ExtractionPolicyV1, capacity: usize, first: &str, second: &str) -> Document {
        let native = handle("run", capacity);
        let bridged = handle("run", capacity);
        for handle in [&native, &bridged] {
            let mut document = extract(first, "one", policy, handle);
            commit(&mut document);
        }
        assert_eq!(snapshot_of(&native), snapshot_of(&bridged));

        let mut expected = extract(second, "two", policy, &native);
        let before = snapshot_of(&bridged);
        let (mut document, envelope) = child_extract(&bridged, second, "two", policy);
        assert!(envelope.is_some());
        bridged
            .attach_commit(&mut document, envelope.as_ref(), policy, &url("two"), raw(second))
            .unwrap();
        assert_eq!(snapshot_of(&bridged), before, "attach must not mutate the cache");
        assert_eq!(
            serde_json::to_value(&expected).unwrap(),
            serde_json::to_value(&document).unwrap()
        );
        commit(&mut expected);
        commit(&mut document);
        assert_eq!(snapshot_of(&native), snapshot_of(&bridged));
        document
    }

    #[test]
    fn bridged_blocks_match_native_pruning_quality_and_eviction() {
        let first = page(&[A, B, A]);
        let second = page(&[B, C, D, C]);
        let document = parity(&policy(true, true), 3, &first, &second);
        let report = document.article.as_ref().unwrap().dedupe.as_ref().unwrap();
        assert!(report.cache_scoped);
        assert!(report.blocks_removed >= 2);
        assert!(!document.text.contains(B));
    }

    #[test]
    fn bridged_content_duplicate_matches_native_and_keeps_acquisition() {
        let html = page(&[A, B]);
        let document = parity(&policy(false, true), 16, &html, &html);
        let article = document.article.as_ref().unwrap();
        assert!(article.dedupe.as_ref().unwrap().content_duplicate);
        assert_eq!(
            article.quality.reasons,
            vec![crawlx_core::extraction::QualityReasonV1::DuplicateMain]
        );
        assert_eq!(document.base_url.as_str(), "https://example.test/two");
    }

    #[test]
    fn attach_refuses_foreign_policy_scope_origin_raw_and_shape() {
        let html = page(&[A, B]);
        let good = policy(true, true);
        let original = handle("run", 16);
        let (document, envelope) = child_extract(&original, &html, "one", &good);
        let envelope = envelope.unwrap();
        let before = snapshot_of(&original);
        let scratch = handle("scratch", 16);
        let attempt = |target: &DedupeHandle,
                       envelope: &DedupeCommitEnvelopeV1,
                       expected: &ExtractionPolicyV1,
                       origin: &Url,
                       raw_digest: Digest| {
            let mut copy = extract(&html, "one", &good, &scratch);
            copy.dedupe_commit = None;
            let result = target.attach_commit(&mut copy, Some(envelope), expected, origin, raw_digest);
            assert!(copy.dedupe_commit.is_none() || result.is_ok());
            result
        };
        let ok_raw = raw(&html);
        assert_eq!(document.raw_html_digest, ok_raw);
        assert_eq!(
            attempt(&handle("other", 16), &envelope, &good, &url("one"), ok_raw),
            Err(DedupeTransportError::Binding)
        );
        assert_eq!(
            attempt(&original, &envelope, &policy(false, true), &url("one"), ok_raw),
            Err(DedupeTransportError::Binding)
        );
        assert_eq!(
            attempt(
                &original,
                &envelope,
                &ExtractionPolicyV1::default(),
                &url("one"),
                ok_raw
            ),
            Err(DedupeTransportError::Policy)
        );
        assert_eq!(
            attempt(
                &original,
                &envelope,
                &good,
                &Url::parse("https://other.test/one").unwrap(),
                ok_raw
            ),
            Err(DedupeTransportError::Binding)
        );
        assert_eq!(
            attempt(&original, &envelope, &good, &url("one"), raw("different")),
            Err(DedupeTransportError::Binding)
        );

        // Same identity, but a disabled stage or a shape the extractor never emits.
        let blocks_only = policy(true, false);
        let (_, blocks_envelope) = child_extract(&original, &html, "one", &blocks_only);
        let mut content_forged = blocks_envelope.clone().unwrap();
        content_forged.observations.push(WireObservation {
            kind: DedupeKindV1::Content,
            hash: Digest([7; 32]),
        });
        assert_eq!(
            original
                .rebind_commit(&content_forged, &blocks_only, &url("one"), ok_raw)
                .unwrap_err(),
            DedupeTransportError::Observations
        );
        let mut misordered = envelope.clone();
        misordered.observations.insert(
            0,
            WireObservation {
                kind: DedupeKindV1::Content,
                hash: Digest([8; 32]),
            },
        );
        assert_eq!(
            original
                .rebind_commit(&misordered, &good, &url("one"), ok_raw)
                .unwrap_err(),
            DedupeTransportError::Observations
        );
        let mut empty = envelope.clone();
        empty.observations.clear();
        assert!(empty.is_empty());
        assert_eq!(
            original
                .rebind_commit(&empty, &good, &url("one"), ok_raw)
                .unwrap_err(),
            DedupeTransportError::Observations
        );
        let mut future = envelope;
        future.version = 2;
        assert_eq!(
            original
                .rebind_commit(&future, &good, &url("one"), ok_raw)
                .unwrap_err(),
            DedupeTransportError::Version
        );
        assert_eq!(snapshot_of(&original), before);
    }

    #[test]
    fn bounds_and_snapshot_binding_are_refused_with_fixed_messages() {
        let original = handle("run", 16);
        let good = policy(true, true);
        let html = page(&[A, B]);
        let mut seed = extract(&html, "seed", &good, &original);
        commit(&mut seed);

        let mut too_many = DedupeCommitEnvelopeV1 {
            version: DEDUPE_TRANSPORT_VERSION,
            key: original.scope().key(
                ARTICLE_EXTRACTOR_ID_V1,
                policy_digest(&good).unwrap(),
                DEDUPE_NORMALIZATION_V1,
            ),
            origin: Digest::of(ORIGIN_DOMAIN, b"https://example.test"),
            raw: raw(&html),
            observations: Vec::new(),
        };
        too_many.observations.resize(
            MAX_DEDUPE_TRANSPORT_OBSERVATIONS + 1,
            WireObservation {
                kind: DedupeKindV1::Block,
                hash: Digest([1; 32]),
            },
        );
        assert_eq!(
            original
                .rebind_commit(&too_many, &good, &url("x"), raw(&html))
                .unwrap_err(),
            DedupeTransportError::Bounds
        );
        assert_eq!(
            DedupeCommitEnvelopeV1::from_json(&vec![b' '; MAX_DEDUPE_COMMIT_ENVELOPE_BYTES + 1]).unwrap_err(),
            DedupeTransportError::Bounds
        );
        assert_eq!(
            DedupeSnapshotTransportV1::from_json(&vec![b' '; MAX_DEDUPE_SNAPSHOT_BYTES + 1]).unwrap_err(),
            DedupeTransportError::Bounds
        );
        assert_eq!(
            DedupeCommitEnvelopeV1::from_json(b"{}").unwrap_err(),
            DedupeTransportError::Encoding
        );

        let wire = original.export_snapshot().unwrap().to_json().unwrap();
        let edit = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value: serde_json::Value = serde_json::from_slice(&wire).unwrap();
            change(&mut value);
            DedupeSnapshotTransportV1::from_json(&serde_json::to_vec(&value).unwrap())
        };
        assert!(edit(&|_| {}).is_ok());
        assert_eq!(
            edit(&|v| v["version"] = 2.into()).unwrap_err(),
            DedupeTransportError::Version
        );
        assert_eq!(
            edit(&|v| v["capacity"] = 0.into()).unwrap_err(),
            DedupeTransportError::Bounds
        );
        assert_eq!(
            edit(&|v| v["capacity"] = (MAX_DEDUPE_CACHE_ENTRIES_FOR_TEST + 1).into()).unwrap_err(),
            DedupeTransportError::Bounds
        );
        // scope tenant disagrees with the checkpoint tenant
        assert_eq!(
            edit(&|v| v["scope"]["tenant"] = "intruder".into()).unwrap_err(),
            DedupeTransportError::Binding
        );
        assert_eq!(
            edit(&|v| v["scope"]["role"] = "".into()).unwrap_err(),
            DedupeTransportError::Binding
        );
        assert_eq!(
            edit(&|v| v["snapshot"]["tick"] = 1.into()).unwrap_err(),
            DedupeTransportError::Snapshot
        );
        for error in [
            DedupeTransportError::Version,
            DedupeTransportError::Bounds,
            DedupeTransportError::Binding,
            DedupeTransportError::Policy,
            DedupeTransportError::Observations,
            DedupeTransportError::Snapshot,
            DedupeTransportError::Recorded,
            DedupeTransportError::Encoding,
        ] {
            let message = error.to_string();
            assert!(message.starts_with("dedupe transport") && !message.contains("tenant"));
        }
    }

    const MAX_DEDUPE_CACHE_ENTRIES_FOR_TEST: usize = crawlx_core::extraction::MAX_DEDUPE_CACHE_ENTRIES;

    #[test]
    fn export_refuses_cache_holding_another_namespace() {
        let first = handle("run", 16);
        let foreign = DedupeHandle::new(
            DedupeScopeV1::new("tenant", "elsewhere", "anonymous").unwrap(),
            Arc::clone(&first.cache),
        );
        let good = policy(true, true);
        let mut document = extract(&page(&[A, B]), "one", &good, &foreign);
        commit(&mut document);
        assert_eq!(
            first.export_snapshot().unwrap_err(),
            DedupeTransportError::Snapshot
        );
        assert!(foreign.export_snapshot().is_ok());
    }

    #[test]
    fn dropped_reply_leaves_original_unchanged_and_duplicate_record_applies_once() {
        let good = policy(true, true);
        let html = page(&[A, B, C]);
        let original = handle("run", 16);
        let (mut document, envelope) = child_extract(&original, &html, "one", &good);
        let before = snapshot_of(&original);
        // reply lost: the envelope and child document are dropped without attaching
        drop(envelope);
        drop(document.dedupe_commit.take());
        assert_eq!(snapshot_of(&original), before);

        let (mut document, envelope) = child_extract(&original, &html, "one", &good);
        original
            .attach_commit(&mut document, envelope.as_ref(), &good, &url("one"), raw(&html))
            .unwrap();
        let token = document.dedupe_commit.take().unwrap();
        let clone = token.clone();
        assert_eq!(snapshot_of(&original), before);
        token.record();
        let once = snapshot_of(&original);
        assert_ne!(once, before);
        clone.record();
        assert_eq!(snapshot_of(&original), once);

        // a refused attach leaves no token behind
        let (mut refused, envelope) = child_extract(&original, &html, "two", &good);
        assert_eq!(
            original
                .attach_commit(&mut refused, envelope.as_ref(), &good, &url("two"), raw("other"))
                .unwrap_err(),
            DedupeTransportError::Binding
        );
        assert!(refused.dedupe_commit.is_none());
        assert_eq!(snapshot_of(&original), once);
    }

    #[test]
    fn exporting_a_spent_commit_is_refused_and_none_attaches_nothing() {
        let good = policy(true, true);
        let html = page(&[A, B]);
        let original = handle("run", 16);
        let mut document = extract(&html, "one", &good, &original);
        let token = document.dedupe_commit.clone().unwrap();
        token.clone().record();
        assert_eq!(
            token.export(raw(&html)).unwrap_err(),
            DedupeTransportError::Recorded
        );
        let mut plain = extract(&html, "one", &policy(false, false), &original);
        original
            .attach_commit(&mut plain, None, &policy(false, false), &url("one"), raw(&html))
            .unwrap();
        assert!(plain.dedupe_commit.is_none());
        document.dedupe_commit = None;
    }
}
