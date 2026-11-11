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

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crawlx_core::extraction::{
    ContentDigestsV1, DedupeAdmissionV1, DedupeCache, DedupeKeyV1, DedupeKindV1, DedupePolicyV1,
    DedupeReportV1, DedupeScopeV1, ExtractionPolicyV1, QualityOutcomeV1, QualityStatusV1,
    ARTICLE_EXTRACTOR_ID_V1, DEDUPE_DIGEST_DOMAIN_V1, DEDUPE_NORMALIZATION_V1,
};
use crawlx_core::hash::Digest;
use crawlx_url::content_similarity::normalize::{shingles, tokenize};
use crawlx_url::content_similarity::{simhash64, SHINGLE_SIZE};
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

fn parse_hash(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut hash = [0; 32];
    for (out, pair) in hash.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
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
}
