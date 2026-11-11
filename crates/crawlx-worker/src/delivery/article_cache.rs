//! Retained finalized article views. Cache reuse never reparses raw HTML or invents text.
//!
//! Cache serialization, canonical approval, decoding and lineage validation run on the worker's
//! existing bounded CPU pool. Source buffers cross that boundary by ownership, never cloning.
use super::{article_deadline, LimitedOutput};
use crate::runtime::CpuPool;
use crawlx_core::{
    dataset::MAX_VALUE_BYTES,
    extraction::{DocumentEnvelopeV1, ExtractionPolicyV1, QualityStatusV1},
    hash::Digest,
    repo::{ArtifactStore, CrawlRun},
    scrape::BlobRef,
    secret::ArtifactSink,
    selectors::ItemOutcomeV1,
    StoreError, Timestamp,
};
use crawlx_extract::Document;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct View<'a> {
    version: u16,
    source: String,
    expires_at: Timestamp,
    acquisition_accepted: bool,
    text: &'a str,
    comments: &'a str,
    markdown: &'a str,
    html: &'a str,
    article: &'a DocumentEnvelopeV1,
    item: Option<&'a ItemOutcomeV1>,
    raw_html_digest: Digest,
    word_count: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Saved {
    version: u16,
    source: String,
    expires_at: Timestamp,
    acquisition_accepted: bool,
    text: String,
    comments: String,
    markdown: String,
    html: String,
    article: DocumentEnvelopeV1,
    item: Option<ItemOutcomeV1>,
    raw_html_digest: Digest,
    word_count: usize,
}

pub(crate) async fn store_article_cache(
    artifacts: &dyn ArtifactStore,
    cpu: &CpuPool,
    run: &CrawlRun,
    page: i64,
    document: Box<Document>,
    acquisition_accepted: bool,
) -> Result<(Box<Document>, Option<BlobRef>), StoreError> {
    if run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr
        || !document.article.as_ref().is_some_and(|article| {
            acquisition_accepted
                && article.quality.status == QualityStatusV1::Accepted
                && article.privacy_projection_version == Some(1)
        })
    {
        return Ok((document, None));
    }
    let deadline = article_deadline(run, None)
        .ok_or_else(|| StoreError::RetentionDenied("article cache deadline unavailable".into()))?;
    let source = format!("{}:document:{page}", run.id);
    let maximum = usize::try_from(MAX_VALUE_BYTES)
        .map_err(|_| StoreError::Conflict("article cache byte limit overflow".into()))?;
    let reservation = cpu.try_reserve_article_output(maximum)?;
    // Move, never clone, the source-owning document through the existing bounded pool.
    // Serialization and immutable approval are CPU work too; the sink only performs I/O.
    let (document, approved, reservation) = cpu
        .run(move || {
            let article = document
                .article
                .as_ref()
                .ok_or_else(|| StoreError::RetentionDenied("article cache envelope unavailable".into()))?;
            let view = View {
                version: 1,
                source,
                expires_at: deadline,
                acquisition_accepted,
                text: &document.text,
                comments: &document.comments,
                markdown: &document.markdown,
                html: &document.html,
                article,
                item: document.item.as_ref(),
                raw_html_digest: document.raw_html_digest,
                word_count: document.word_count,
            };
            let mut output = LimitedOutput::new(maximum);
            serde_json::to_writer(&mut output, &view)
                .map_err(|_| output.serialization_error("article cache serialization failed"))?;
            let approved = crawlx_core::secret::Redactor::new().verify_canonical_owned(output.bytes)?;
            Ok::<_, StoreError>((document, approved, reservation))
        })
        .await
        .map_err(|_| StoreError::Backend("article cache CPU task failed".into()))??;
    // Tuple order keeps the original approved allocation alive under credit through storage.
    let output = (approved, reservation);
    let size = u64::try_from(output.0.as_ref().len())
        .map_err(|_| StoreError::Conflict("article cache length overflow".into()))?;
    let artifact = ArtifactSink::over(artifacts)
        .put_dataset_until(
            run.id,
            page,
            "article_cache",
            "application/json",
            &output.0,
            deadline,
        )
        .await?;
    drop(output);
    Ok((
        document,
        Some(BlobRef {
            artifact,
            content_type: "application/json".into(),
            size,
        }),
    ))
}

pub(crate) async fn load_article_cache(
    artifacts: &dyn ArtifactStore,
    cpu: &CpuPool,
    source_run: &CrawlRun,
    reference: &BlobRef,
    now: Timestamp,
    policy: Option<&ExtractionPolicyV1>,
) -> Result<(Document, Timestamp, String), StoreError> {
    let denied = || StoreError::RetentionDenied("retained canonical article unavailable".into());
    if source_run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr
        || reference.size > MAX_VALUE_BYTES
        || reference.content_type != "application/json"
    {
        return Err(denied());
    }
    let bytes = artifacts
        .read_archive_content(
            source_run.tenant,
            source_run.id,
            &reference.artifact,
            reference.size,
        )
        .await?;
    if u64::try_from(bytes.len()).ok() != Some(reference.size) {
        return Err(denied());
    }
    let horizon = article_deadline(source_run, None).ok_or_else(denied)?;
    let prefix = format!("{}:document:", source_run.id);
    let policy = policy.cloned();
    let (document, deadline, source) = cpu
        .run(move || restore_article_cache(bytes, horizon, prefix, now, policy))
        .await
        .map_err(|_| StoreError::Backend("article cache CPU task failed".into()))??;
    Ok((*document, deadline, source))
}

/// Decode and verify the exact retained bytes only while holding a bounded CPU permit.
fn restore_article_cache(
    bytes: Vec<u8>,
    horizon: Timestamp,
    prefix: String,
    now: Timestamp,
    policy: Option<ExtractionPolicyV1>,
) -> Result<(Box<Document>, Timestamp, String), StoreError> {
    let denied = || StoreError::RetentionDenied("retained canonical article unavailable".into());
    // Deserialization alone cannot prove that a retained backend preserved privacy.
    crawlx_core::secret::Redactor::new().check_canonical(&bytes)?;
    let saved: Saved = serde_json::from_slice(&bytes).map_err(|_| denied())?;
    if saved.version != 1
        || !saved.acquisition_accepted
        || saved.expires_at <= now
        || saved.expires_at > horizon
        || !saved
            .source
            .strip_prefix(&prefix)
            .is_some_and(|page| page.parse::<i64>().is_ok_and(|page| page > 0))
        || saved.article.privacy_projection_version != Some(1)
        || saved.article.quality.status != QualityStatusV1::Accepted
        || saved.article.main_digest
            != Digest::of("crawlx.extract.main.unicode_rules_v1", saved.text.as_bytes())
    {
        return Err(denied());
    }
    validate_effective_policy(&saved.article, policy.as_ref()).map_err(|_| denied())?;
    for block in &saved.article.blocks {
        let text = if block.comment {
            &saved.comments
        } else {
            &saved.text
        };
        if block
            .source
            .as_ref()
            .is_some_and(|range| range.start > range.end || text.get(range.start..range.end).is_none())
        {
            return Err(denied());
        }
    }
    // Only serializer-consumed finalized fields are restored. Legacy discovery/forms/raw
    // metadata stay absent; the inert base is not claimed as source provenance.
    let document = Box::new(Document {
        title: None,
        description: None,
        language: None,
        canonical_url: None,
        base_url: url::Url::parse("about:blank").map_err(|_| denied())?,
        markdown: saved.markdown,
        text: saved.text,
        html: saved.html,
        raw_html_digest: saved.raw_html_digest,
        metadata: Default::default(),
        links: Vec::new(),
        assets: Vec::new(),
        word_count: saved.word_count,
        forms: Vec::new(),
        page_type: None,
        technologies: Vec::new(),
        custom_fields: Default::default(),
        item: saved.item,
        discovered_endpoints: Vec::new(),
        article: Some(saved.article),
        comments: saved.comments,
        validation: None,
        image_urls: None,
        attributes: None,
        outputs: None,
        decode: None,
        markup: None,
    });
    Ok((document, saved.expires_at, saved.source))
}

/// Canonical approval already verified exact source ranges against the saved chunk policy.
/// Bind that proven policy to this request without rescanning the full text a second time.
fn validate_effective_policy(
    article: &DocumentEnvelopeV1,
    policy: Option<&ExtractionPolicyV1>,
) -> Result<(), StoreError> {
    let denied = || StoreError::RetentionDenied("retained article policy or chunks invalid".into());
    let policy = policy.ok_or_else(denied)?;
    policy.validate().map_err(|_| denied())?;
    let bytes = serde_json::to_vec(policy).map_err(|_| denied())?;
    if article.policy_digest != Digest::of("crawlx.extract.policy.v1", &bytes) {
        return Err(denied());
    }
    match (&article.chunks, &policy.chunks) {
        (None, None) => Ok(()),
        (Some(chunks), Some(effective)) if chunks.policy == *effective => Ok(()),
        _ => Err(denied()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::{
        extraction::{WordChunkPolicyV1, WordChunkStrategyV1},
        repo::RunRepo,
        time::ManualClock,
        Clock, TenantId,
    };
    use crawlx_storage::{artifacts::FsArtifactStore, testkit, MemoryStore};
    use std::sync::Arc;

    #[tokio::test]
    async fn redacted_word_chunks_cache_roundtrip_rejects_corruption_and_effective_policy_mismatch() {
        let clock = Arc::new(ManualClock::new(
            "2026-11-05T00:00:00Z".parse::<Timestamp>().unwrap(),
        ));
        let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
        let directory = tempfile::tempdir().unwrap();
        let artifacts = FsArtifactStore::open(directory.path(), repo.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(repo.clone());
        let cpu = CpuPool::default();
        let mut policy = ExtractionPolicyV1::default();
        let mut chunks = WordChunkPolicyV1::default();
        chunks.strategy = WordChunkStrategyV1::Sliding { window: 4, step: 3 };
        policy.chunks = Some(chunks);
        let mut config = testkit::create_crawl("https://fixture.test/", &[], 1);
        config.retention.mode = crawlx_core::config::RetentionMode::Standard;
        config.retention.days = 1;
        config.extract.content = Some(policy.clone());
        let mut run = testkit::crawl_run(TenantId::new(), config);
        run.created_at = clock.now();
        repo.create(&run, None).await.unwrap();
        let document = crawlx_extract::Extractor::extract_bytes_with_projection(
            b"<article><p>The public report hides private<span>Canary718</span> and retains enough actual words for a meaningful final article after privacy approval.</p></article>",
            &url::Url::parse("https://fixture.test/article").unwrap(),
            &crawlx_extract::ExtractOptions { content: Some(policy.clone()), ..Default::default() },
            &|text| text.contains("privateCanary718").then(|| text.replace("privateCanary718", "[REDACTED]")),
        ).unwrap();
        assert!(!document.text.contains("privateCanary718"));
        let source_allocation = document.text.as_ptr().addr();
        let (document, reference) = store_article_cache(&artifacts, &cpu, &run, 10, Box::new(document), true)
            .await
            .unwrap();
        assert_eq!(document.text.as_ptr().addr(), source_allocation);
        let reference = reference.unwrap();
        let (restored, deadline, _) =
            load_article_cache(&artifacts, &cpu, &run, &reference, clock.now(), Some(&policy))
                .await
                .unwrap();
        assert_eq!(restored.text, document.text);
        assert_eq!(restored.article, document.article);
        restored
            .article
            .as_ref()
            .unwrap()
            .chunks
            .as_ref()
            .unwrap()
            .validate(&restored.text, &chunks)
            .unwrap();
        let mut changed = policy.clone();
        changed.chunks.as_mut().unwrap().max_ranges -= 1;
        assert!(
            load_article_cache(&artifacts, &cpu, &run, &reference, clock.now(), Some(&changed))
                .await
                .is_err()
        );
        assert!(
            load_article_cache(&artifacts, &cpu, &run, &reference, clock.now(), None)
                .await
                .is_err()
        );

        let bytes = artifacts
            .read_archive_content(run.tenant, run.id, &reference.artifact, reference.size)
            .await
            .unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        for mutation in 0..8 {
            let mut corrupt = saved.clone();
            match mutation {
                0 => corrupt["text"] = serde_json::json!("changed final source"),
                1 => corrupt["article"]["chunks"]["ranges"][0]["start"] = serde_json::json!(usize::MAX),
                2 => {
                    corrupt["article"]["chunks"]["finalTextDigest"] =
                        serde_json::json!(Digest::of("wrong", b"x"))
                }
                3 => corrupt["article"]["chunks"]["policy"]["strategy"]["step"] = serde_json::json!(2),
                4 => corrupt["article"]["chunks"]["ranges"]
                    .as_array_mut()
                    .unwrap()
                    .reverse(),
                5 => {
                    corrupt["article"].as_object_mut().unwrap().remove("chunks");
                }
                6 => {
                    corrupt["article"]["metadata"]["authors"]["value"] =
                        serde_json::json!(["Bearer cache-metadata-canary"]);
                }
                7 => {
                    corrupt["article"]["metadata"]["keywords"] = serde_json::json!([{
                        "token": "unbound-cache-keyword",
                        "score": 1,
                        "source": { "start": 0, "end": 3 }
                    }]);
                }
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&corrupt).unwrap();
            // Simulate a corrupted retained backend without claiming sink approval.
            let artifact = artifacts
                .put_dataset_until(run.id, 11, "article_cache", "application/json", &bytes, deadline)
                .await
                .unwrap();
            let corrupt_ref = BlobRef {
                artifact,
                content_type: "application/json".into(),
                size: u64::try_from(bytes.len()).unwrap(),
            };
            assert!(
                load_article_cache(&artifacts, &cpu, &run, &corrupt_ref, clock.now(), Some(&policy),)
                    .await
                    .is_err()
            );
        }
    }
}
