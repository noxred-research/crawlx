//! Focused hash-only registry state tests; no backend or wall-clock dependencies.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;

fn claim() -> ContentDedupeClaimV1 {
    serde_json::from_value(serde_json::json!({
        "version":1,"tenant":TenantId(uuid::Uuid::from_u128(1)),
        "run":CrawlRunId(uuid::Uuid::from_u128(2)),
        "scope":Digest::of("registry-test",b"scope"),
        "policyDigest":Digest::of("registry-test",b"policy"),
        "content":Digest::of("registry-test",b"content"),
        "main":Digest::of("registry-test",b"main")
    }))
    .unwrap()
}

#[test]
fn registry_plans_do_not_consume_hashes_and_keys_isolate_every_dimension() {
    let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    let mut state = RegistryState::default();
    let original = claim();
    let abandoned = state.prepare(&original, 1, now);
    assert!(!abandoned.is_duplicate());
    let winner = state.prepare(&original, 2, now);
    assert!(!winner.is_duplicate());
    state.apply(&original, 2, winner);
    let duplicate = state.prepare(&original, 3, now);
    assert!(duplicate.is_duplicate());
    assert_eq!(duplicate.first_frontier_id, 2);
    assert_eq!(duplicate.committed_at, now);
    assert!(state.outcome(original.run, 1).is_none());
    assert!(state.outcome(original.run, 3).is_none());
    state.apply(&original, 3, duplicate);
    assert!(state.outcome(original.run, 3).unwrap().is_duplicate());

    let mut other = original.clone();
    other.tenant = TenantId(uuid::Uuid::from_u128(3));
    assert!(!state.prepare(&other, 4, now).is_duplicate());
    other = original.clone();
    other.run = CrawlRunId(uuid::Uuid::from_u128(4));
    assert!(!state.prepare(&other, 4, now).is_duplicate());
    other = original.clone();
    other.scope = Digest::of("registry-test", b"other-role-session-policy");
    assert!(!state.prepare(&other, 4, now).is_duplicate());
    other = original.clone();
    other.content = original.main;
    other.main = original.content;
    assert!(
        !state.prepare(&other, 4, now).is_duplicate(),
        "stages cannot cross-match"
    );
    other = original.clone();
    other.main = Digest::of("registry-test", b"changed-main");
    assert!(
        state.prepare(&other, 4, now).is_duplicate(),
        "content stage alone rejects"
    );
    other = original.clone();
    other.content = Digest::of("registry-test", b"changed-title");
    assert!(
        state.prepare(&other, 4, now).is_duplicate(),
        "main stage alone rejects"
    );
    state.purge_run(original.run);
    assert!(state.outcome(original.run, 2).is_none());
    assert!(!state.prepare(&original, 5, now).is_duplicate());
}

#[test]
fn duplicate_rejects_bound_native_scrape_without_rewriting_page_authored_article() {
    use crawlx_core::extraction::{
        ArticleMetadataV1, ContentDigestsV1, DedupeReportV1, DocumentEnvelopeV1, QualityOutcomeV1,
        QualityStatusV1,
    };
    let claim = claim();
    let mut article = DocumentEnvelopeV1::new(
        claim.policy_digest,
        claim.main,
        "article".into(),
        0,
        Vec::new(),
        ArticleMetadataV1::default(),
        QualityOutcomeV1::new(QualityStatusV1::Accepted, Vec::new(), 100, 1, 1),
    );
    article.privacy_projection_version = Some(1);
    let mut report = DedupeReportV1::new(
        ContentDigestsV1::new(claim.content, claim.content, claim.main, None, 1),
        true,
        1,
        0,
        "https://example.test".into(),
    );
    report.content_sha256 = Some(claim.content.to_hex());
    article.dedupe = Some(report);
    let source = serde_json::json!({"artifact":"unchanged-source-evidence"});
    let mut scrape = serde_json::json!({"meta":{
        "article":article,"articleDocumentRef":{"acceptedDocument":true},
        "articleCacheSourceRun":claim.run,"articleTextRef":source,"articleCommentsRef":source,
        "extensionItem":{"accepted":true},"arbitrary":{"article":{"quality":"accepted"}}
    }})
    .as_object()
    .unwrap()
    .clone();
    reject_scrape_article(&mut scrape, &claim);
    reject_scrape_article(&mut scrape, &claim);
    let meta = &scrape["meta"];
    assert_eq!(meta["article"]["quality"]["status"], "rejected");
    assert_eq!(
        meta["article"]["quality"]["reasons"],
        serde_json::json!(["duplicate_main"])
    );
    assert_eq!(meta["article"]["dedupe"]["contentDuplicate"], true);
    assert_eq!(meta["articleParseQuality"]["status"], "accepted");
    assert_eq!(meta["articleTextRef"], source);
    assert_eq!(meta["articleCommentsRef"], source);
    assert!(meta.get("articleDocumentRef").is_none());
    assert!(meta.get("articleCacheSourceRun").is_none());
    assert!(meta.get("extensionItem").is_none());
    assert_eq!(meta["arbitrary"]["article"]["quality"], "accepted");
    let authored = serde_json::json!({"article":{"quality":{"status":"accepted"}}});
    let mut unrelated = serde_json::json!({"meta":authored}).as_object().unwrap().clone();
    reject_scrape_article(&mut unrelated, &claim);
    assert_eq!(unrelated["meta"], authored);
    let mut foreign = article;
    foreign.policy_digest = Digest::of("registry-test", b"other-policy");
    let mut unrelated = serde_json::json!({"meta":{"article":foreign,"articleDocumentRef":"not-owned"}})
        .as_object()
        .unwrap()
        .clone();
    reject_scrape_article(&mut unrelated, &claim);
    assert_eq!(unrelated["meta"]["article"]["quality"]["status"], "accepted");
    assert_eq!(unrelated["meta"]["articleDocumentRef"], "not-owned");
}
