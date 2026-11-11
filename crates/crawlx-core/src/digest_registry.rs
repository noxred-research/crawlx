//! Hash-only, run-scoped content claims committed with request results.
//!
//! A local extraction cache is only a fast path. Durable writers arbitrate both content and
//! main hashes inside the page transaction; a failed transaction never consumes a claim.

use crate::extraction::{
    DocumentEnvelopeV1, QualityStatusV1, ARTICLE_EXTRACTOR_ID_V1, DEDUPE_DIGEST_DOMAIN_V1,
    DEDUPE_NORMALIZATION_V1,
};
use crate::{hash::Digest, CrawlRunId, StoreError, TenantId, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Hash stage; stages never collide even when their bytes match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DigestStageV1 {
    /// SHA-256 of normalized title and body.
    Content,
    /// Domain-separated digest of selected normalized main text.
    Main,
}
impl DigestStageV1 {
    /// Stable storage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Main => "main",
        }
    }
}

/// Fixed-size, content-free claim. Both stages are mandatory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
#[must_use]
pub struct ContentDedupeClaimV1 {
    /// Exactly one.
    pub version: u16,
    /// Tenant owning the admitted run.
    pub tenant: TenantId,
    /// Effective extraction policy, also bound into `scope`; used to verify native projections.
    pub policy_digest: Digest,
    /// Run owning the result transaction.
    pub run: CrawlRunId,
    /// Hash binding role/session representation, extractor, policy and normalization.
    pub scope: Digest,
    /// Normalized title/body SHA-256 bytes, not a rehash of its hexadecimal encoding.
    pub content: Digest,
    /// `dedupe.digests.main`, distinct from `DocumentEnvelopeV1.main_digest`.
    pub main: Digest,
}
impl ContentDedupeClaimV1 {
    /// Bind an accepted, privacy-projected document to its durable scope.
    /// `representation` must bind the caller's role/session representation, not a worker ID.
    /// Call only when the effective policy opted into content dedupe.
    ///
    /// # Errors
    /// Returns a conflict for absent content-stage evidence, unsupported versions or malformed hashes.
    pub fn from_document(
        tenant: TenantId,
        run: CrawlRunId,
        representation: Digest,
        document: &DocumentEnvelopeV1,
    ) -> Result<Self, StoreError> {
        let report = document.dedupe.as_ref().ok_or_else(invalid)?;
        let content = report.content_sha256.as_deref().ok_or_else(invalid)?;
        if document.version != 1
            || document.extractor != ARTICLE_EXTRACTOR_ID_V1
            || document.quality.status != QualityStatusV1::Accepted
            || document.privacy_projection_version != Some(1)
            || report.version != 1
            || report.digests.version != 1
            || report.digests.normalization != DEDUPE_NORMALIZATION_V1
            || report.digests.domain != DEDUPE_DIGEST_DOMAIN_V1
            || content.len() != 64
            || !content
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || report.digests.main_simhash.len() != 16
            || !report
                .digests
                .main_simhash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || report.blocks_removed > report.blocks_seen
        {
            return Err(invalid());
        }
        let scope = Digest::of_value(
            "crawlx/content-registry-scope/v1",
            &(
                tenant,
                run,
                representation,
                &document.extractor,
                document.policy_digest,
                &report.digests.normalization,
                &report.digests.domain,
            ),
        )
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
        Ok(Self {
            version: 1,
            tenant,
            policy_digest: document.policy_digest,
            run,
            scope,
            content: Digest::from_hex(content).map_err(|_| invalid())?,
            main: report.digests.main,
        })
    }

    /// Validate the claim against the transaction's authoritative tenant and run.
    ///
    /// # Errors
    /// Returns a conflict for an unsupported version or mismatched tenant/run.
    pub fn validate(&self, tenant: TenantId, run: CrawlRunId) -> Result<(), StoreError> {
        if self.version != 1 || self.tenant != tenant || self.run != run {
            return Err(invalid());
        }
        Ok(())
    }

    /// Fixed pair of stage/hash keys in stable lock order.
    #[must_use]
    pub const fn stages(&self) -> [(DigestStageV1, Digest); 2] {
        [
            (DigestStageV1::Content, self.content),
            (DigestStageV1::Main, self.main),
        ]
    }
}
fn invalid() -> StoreError {
    StoreError::Conflict("invalid content dedupe claim".into())
}

/// Durable disposition after transactional arbitration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DigestDispositionV1 {
    /// First successful page commit owns both hashes.
    Canonical,
    /// An earlier successful commit already owns content or main.
    DuplicateMain,
}

/// Hash-only result receipt. Its timestamp comes from storage at publication, never acquisition time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
#[must_use]
pub struct DigestOutcomeV1 {
    /// Exactly one.
    pub version: u16,
    /// Transactional content disposition.
    pub disposition: DigestDispositionV1,
    /// Full hash-only scope binding.
    pub scope: Digest,
    /// First committed frontier row for the winning stage.
    pub first_frontier_id: i64,
    /// Storage record time of that canonical commit.
    pub committed_at: Timestamp,
}
impl DigestOutcomeV1 {
    /// Construct a storage-issued receipt.
    pub const fn new(
        disposition: DigestDispositionV1,
        scope: Digest,
        first_frontier_id: i64,
        committed_at: Timestamp,
    ) -> Self {
        Self {
            version: 1,
            disposition,
            scope,
            first_frontier_id,
            committed_at,
        }
    }
    /// Whether ingestion and delivery must be rejected.
    #[must_use]
    pub const fn is_duplicate(&self) -> bool {
        matches!(self.disposition, DigestDispositionV1::DuplicateMain)
    }
}

/// Read-only durable result evidence. Claims are deliberately available only through page commit.
#[async_trait]
pub trait DigestRegistryRepo: Send + Sync {
    /// Read this exact frontier's receipt; opt-out results have no receipt.
    ///
    /// # Errors
    /// Returns access, retention, missing-run or storage errors.
    async fn digest_outcome(
        &self,
        run: CrawlRunId,
        frontier_id: i64,
    ) -> Result<Option<DigestOutcomeV1>, StoreError>;
}
