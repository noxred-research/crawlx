//! Hash-only first-commit arbitration. No independent claim API can outlive a failed page commit.

use crate::codec::get;
use crate::error::db;
use crate::Pg;
use crawlx_core::digest_registry::{
    ContentDedupeClaimV1, DigestDispositionV1, DigestOutcomeV1, DigestRegistryRepo, DigestStageV1,
};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::RequestCommitV1;
use crawlx_core::repo::{FrontierStatus, RunRepo};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};
use std::collections::BTreeMap;
type RegistryKey = (TenantId, CrawlRunId, Digest, DigestStageV1, Digest);

#[derive(Clone, Default)]
pub(crate) struct RegistryState {
    pub(crate) gate: std::sync::Arc<tokio::sync::Mutex<()>>,
    entries: BTreeMap<RegistryKey, (i64, Timestamp)>,
    receipts: BTreeMap<(CrawlRunId, i64), DigestOutcomeV1>,
}
impl RegistryState {
    pub(crate) fn prepare(
        &self,
        claim: &ContentDedupeClaimV1,
        frontier: i64,
        now: Timestamp,
    ) -> DigestOutcomeV1 {
        for (stage, digest) in claim.stages() {
            if let Some((first, committed)) =
                self.entries
                    .get(&(claim.tenant, claim.run, claim.scope, stage, digest))
            {
                return DigestOutcomeV1::new(
                    DigestDispositionV1::DuplicateMain,
                    claim.scope,
                    *first,
                    *committed,
                );
            }
        }
        DigestOutcomeV1::new(DigestDispositionV1::Canonical, claim.scope, frontier, now)
    }
    pub(crate) fn apply(&mut self, claim: &ContentDedupeClaimV1, frontier: i64, outcome: DigestOutcomeV1) {
        if !outcome.is_duplicate() {
            for (stage, digest) in claim.stages() {
                self.entries.insert(
                    (claim.tenant, claim.run, claim.scope, stage, digest),
                    (frontier, outcome.committed_at),
                );
            }
        }
        self.receipts.insert((claim.run, frontier), outcome);
    }
    pub(crate) fn outcome(&self, run: CrawlRunId, frontier: i64) -> Option<DigestOutcomeV1> {
        self.receipts.get(&(run, frontier)).cloned()
    }
    pub(crate) fn purge_run(&mut self, run: CrawlRunId) {
        self.entries.retain(|(_, owner, _, _, _), _| *owner != run);
        self.receipts.retain(|(owner, _), _| *owner != run);
    }
}

pub(crate) fn validate_commit(commit: &RequestCommitV1, tenant: TenantId) -> Result<(), StoreError> {
    let Some(claim) = &commit.content_dedupe else {
        return Ok(());
    };
    claim.validate(tenant, commit.run)?;
    if commit.request_id <= 0
        || commit.status != FrontierStatus::Succeeded
        || commit.head_response.is_some()
        || commit.page.as_ref().is_none_or(|page| !page.metadata.is_object())
    {
        return Err(StoreError::Conflict(
            "content dedupe requires successful owned page".into(),
        ));
    }
    Ok(())
}

/// Change the real ingestion result, not only a diagnostic duplicate marker.
pub(crate) fn apply_outcome(commit: &mut RequestCommitV1, outcome: &DigestOutcomeV1) {
    if outcome.is_duplicate() {
        commit.accepted.clear();
        commit.state_deltas.clear();
        commit.outbox.clear();
        commit.reason = Some("duplicate_main".into());
        // This reference hashes the worker's pre-arbitration document, not the rejected result.
        commit.document_ref = None;
    }
    if let Some(page) = &mut commit.page {
        page.metadata["contentDedupe"] = serde_json::json!(outcome);
        if outcome.is_duplicate() {
            if let Some(extraction) = page
                .metadata
                .get_mut("extraction")
                .and_then(serde_json::Value::as_object_mut)
            {
                if let Some(quality) = extraction.get_mut("quality") {
                    let initial = quality.clone();
                    if let Some(object) = quality.as_object_mut() {
                        object.insert("status".into(), serde_json::json!("rejected"));
                        object.insert("reasons".into(), serde_json::json!(["duplicate_main"]));
                    }
                    extraction.entry("parseQuality").or_insert(initial);
                }
                // Keep pure parse evidence separate; never advertise its accepted artifact as
                // a re-rendered rejected document. Physical artifact custody remains unchanged.
                extraction.remove("content");
            }
            page.metadata["itemPipeline"] =
                serde_json::json!({"accepted":0,"rejected":1,"reason":"duplicate_main"});
            if let Some(extension) = page
                .metadata
                .get_mut("extensions")
                .and_then(serde_json::Value::as_object_mut)
            {
                extension.remove("content");
                extension.insert("outcome".into(), serde_json::json!("rejected"));
            }
            if let Some(scrape) = page
                .metadata
                .get_mut("scrape")
                .and_then(serde_json::Value::as_object_mut)
            {
                scrape.insert("notCacheable".into(), serde_json::json!(true));
                if let Some(claim) = &commit.content_dedupe {
                    reject_scrape_article(scrape, claim);
                }
            }
        }
    }
}

// `scrape.meta.article` is reserved by the native scrape assembler, not page metadata.
// Still require the full typed schema and exact claim hashes/policy before changing it.
fn reject_scrape_article(
    scrape: &mut serde_json::Map<String, serde_json::Value>,
    claim: &ContentDedupeClaimV1,
) {
    use crawlx_core::extraction::{
        DocumentEnvelopeV1, QualityStatusV1, ARTICLE_EXTRACTOR_ID_V1, DEDUPE_DIGEST_DOMAIN_V1,
        DEDUPE_NORMALIZATION_V1,
    };
    use serde::Deserialize as _;
    let Some(meta) = scrape.get_mut("meta").and_then(serde_json::Value::as_object_mut) else {
        return;
    };
    let Some(value) = meta.get("article") else {
        return;
    };
    let Ok(article) = DocumentEnvelopeV1::deserialize(value) else {
        return;
    };
    let Some(report) = &article.dedupe else {
        return;
    };
    if article.version != 1
        || article.extractor != ARTICLE_EXTRACTOR_ID_V1
        || article.privacy_projection_version != Some(1)
        || article.policy_digest != claim.policy_digest
        || report.version != 1
        || report.digests.version != 1
        || report.digests.main != claim.main
        || report.digests.normalization != DEDUPE_NORMALIZATION_V1
        || report.digests.domain != DEDUPE_DIGEST_DOMAIN_V1
        || report
            .content_sha256
            .as_deref()
            .and_then(|hash| Digest::from_hex(hash).ok())
            != Some(claim.content)
    {
        return;
    }
    let was_accepted = article.quality.status == QualityStatusV1::Accepted;
    let Some(article) = meta.get_mut("article").and_then(serde_json::Value::as_object_mut) else {
        return;
    };
    let initial = was_accepted.then(|| article.get("quality").cloned()).flatten();
    if let Some(quality) = article
        .get_mut("quality")
        .and_then(serde_json::Value::as_object_mut)
    {
        quality.insert("status".into(), serde_json::json!("rejected"));
        quality.insert("reasons".into(), serde_json::json!(["duplicate_main"]));
    }
    if let Some(dedupe) = article
        .get_mut("dedupe")
        .and_then(serde_json::Value::as_object_mut)
    {
        dedupe.insert("contentDuplicate".into(), serde_json::json!(true));
        // Durable registry stores no origin; do not invent a same-origin comparison.
        dedupe.insert("duplicateSameOrigin".into(), serde_json::Value::Null);
    }
    if let Some(initial) = initial {
        meta.insert("articleParseQuality".into(), initial);
    }
    meta.remove("articleDocumentRef");
    meta.remove("articleCacheSourceRun");
    meta.remove("extensionItem");
}

pub(crate) async fn claim_pg(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    claim: &ContentDedupeClaimV1,
    frontier: i64,
) -> Result<DigestOutcomeV1, StoreError> {
    // The owning run is already locked by the request transaction. It serializes both stages
    // without cross-stage partial winners, and every failed later operation rolls these rows back.
    let available: bool = sqlx::query_scalar(
        "SELECT purge_requested_at IS NULL FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2",
    )
    .bind(claim.tenant.0)
    .bind(claim.run.0)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !available {
        return Err(StoreError::RetentionDenied(
            "content digest source is being purged".into(),
        ));
    }
    for (stage, digest) in claim.stages() {
        let prior = sqlx::query("SELECT first_frontier_id,committed_at FROM content_digest_registry WHERE tenant_id=$1 AND run_id=$2 AND scope_digest=$3 AND stage=$4 AND digest=$5")
            .bind(claim.tenant.0).bind(claim.run.0).bind(claim.scope.0.as_slice())
            .bind(stage.as_str()).bind(digest.0.as_slice()).fetch_optional(&mut **tx).await.map_err(db)?;
        if let Some(prior) = prior {
            return Ok(DigestOutcomeV1::new(
                DigestDispositionV1::DuplicateMain,
                claim.scope,
                get(&prior, "first_frontier_id")?,
                get(&prior, "committed_at")?,
            ));
        }
    }
    let now: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
    for (stage, digest) in claim.stages() {
        sqlx::query("INSERT INTO content_digest_registry (tenant_id,run_id,scope_digest,stage,digest,first_frontier_id,committed_at) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(claim.tenant.0).bind(claim.run.0).bind(claim.scope.0.as_slice())
            .bind(stage.as_str()).bind(digest.0.as_slice()).bind(frontier).bind(now)
            .execute(&mut **tx).await.map_err(db)?;
    }
    Ok(DigestOutcomeV1::new(
        DigestDispositionV1::Canonical,
        claim.scope,
        frontier,
        now,
    ))
}

#[async_trait::async_trait]
impl DigestRegistryRepo for Pg {
    async fn digest_outcome(
        &self,
        run: CrawlRunId,
        frontier_id: i64,
    ) -> Result<Option<DigestOutcomeV1>, StoreError> {
        let source = self.get(run).await?;
        check_source(&source, chrono::Utc::now())?;
        let row = sqlx::query("SELECT f.content_dedupe_outcome,r.purge_requested_at IS NULL AS available FROM url_frontier f JOIN crawl_runs r ON r.tenant_id=f.tenant_id AND r.run_id=f.run_id WHERE f.tenant_id=$1 AND f.run_id=$2 AND f.frontier_id=$3")
            .bind(source.tenant.0).bind(run.0).bind(frontier_id).fetch_optional(&self.pool).await.map_err(db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        if !get::<bool>(&row, "available")? {
            return Err(StoreError::RetentionDenied(
                "content digest source is being purged".into(),
            ));
        }
        let payload: Option<serde_json::Value> = get(&row, "content_dedupe_outcome")?;
        payload
            .map(serde_json::from_value)
            .transpose()
            .map_err(Into::into)
    }
}

pub(crate) fn check_source(run: &crawlx_core::repo::CrawlRun, now: Timestamp) -> Result<(), StoreError> {
    if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
        return Err(StoreError::AccessDenied("content digest tenant mismatch".into()));
    }
    if run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr
        && run.config.retention.days != 0
        && run.created_at + chrono::Duration::days(i64::from(run.config.retention.days)) <= now
    {
        return Err(StoreError::RetentionDenied(
            "content digest source expired".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "digest_registry_tests.rs"]
mod tests;
