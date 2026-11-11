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
//!   normalized title and body is admitted into the cache scope, and a second admission marks
//!   the document `duplicate_main`. Both acquisitions and both origins stay distinct.
//!
//! Admission order is the order of extraction calls against one [`DedupeHandle`]; callers that
//! extract concurrently and need reproducible results call in their ordered-commit sequence.
//! The cache stores hashes and counts only, never paragraph text. A re-extraction of the same
//! page in the same scope is a repeat by design; give a retry its own namespace.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crawlx_core::extraction::{
    ContentDigestsV1, DedupeAdmissionV1, DedupeCache, DedupeKeyV1, DedupeKindV1, DedupePolicyV1,
    DedupeReportV1, DedupeScopeV1, ExtractionPolicyV1, QualityOutcomeV1, QualityStatusV1,
    ARTICLE_EXTRACTOR_ID_V1, DEDUPE_NORMALIZATION_V1,
};
use crawlx_core::hash::Digest;
use crawlx_url::content_similarity::normalize::{shingles, tokenize};
use crawlx_url::content_similarity::{simhash64, SHINGLE_SIZE};
use sha2::Digest as _;
use url::Url;

use crate::dom::{Elem, Node};
use crate::{article, text, ExtractError, ExtractOptions};

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
    cache: Option<&'a Mutex<DedupeCache>>,
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
        let (key, cache) = match &opts.dedupe_cache {
            Some(handle) => (
                Some(handle.scope.key(
                    ARTICLE_EXTRACTOR_ID_V1,
                    policy_digest(policy)?,
                    DEDUPE_NORMALIZATION_V1,
                )),
                Some(&*handle.cache),
            ),
            None => (None, None),
        };
        Ok(Some(Self {
            policy: dedupe,
            key,
            cache,
            origin_text,
            origin,
        }))
    }

    fn lock(&self) -> Option<MutexGuard<'a, DedupeCache>> {
        self.cache
            .map(|cache| cache.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Whether block removal is enabled.
    pub(crate) fn blocks_enabled(&self) -> bool {
        self.policy.blocks
    }

    /// Remove repeated blocks from the selected tree. `ids` stays aligned with `nodes`.
    pub(crate) fn prune_blocks(&self, nodes: &mut Vec<Node>, ids: &mut Vec<usize>) -> BlockStats {
        let mut guard = self.lock();
        let mut pass = Pass {
            min_chars: self.policy.min_block_chars,
            origin: self.origin,
            cache: guard.as_deref_mut(),
            key: self.key.as_ref(),
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
    /// and admits it only when every other gate accepted the document, so a rejected or partial
    /// document never shadows a later good one. A repeat appends `duplicate_main` and rejects.
    pub(crate) fn content_stage(
        &self,
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
        let (Some(mut guard), Some(key)) = (self.lock(), self.key.as_ref()) else {
            return stage;
        };
        if let DedupeAdmissionV1::Seen { same_origin, .. } =
            guard.admit(key, DedupeKindV1::Content, hash, self.origin)
        {
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
            self.cache.is_some(),
            blocks.seen,
            blocks.removed,
            self.origin_text.clone(),
        );
        report.content_sha256 = stage.sha256;
        report.content_duplicate = stage.duplicate;
        report.duplicate_same_origin = stage.same_origin;
        report
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
    cache: Option<&'g mut DedupeCache>,
    key: Option<&'g DedupeKeyV1>,
    /// In-document set when no cache handle was supplied; the block scan ceiling bounds it.
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
        let fresh = match (self.cache.as_deref_mut(), self.key) {
            (Some(cache), Some(key)) => {
                matches!(
                    cache.admit(key, DedupeKindV1::Block, hash, self.origin),
                    DedupeAdmissionV1::New
                )
            }
            _ => self.local.insert(hash),
        };
        if !fresh {
            self.stats.removed = self.stats.removed.saturating_add(1);
        }
        fresh
    }
}
