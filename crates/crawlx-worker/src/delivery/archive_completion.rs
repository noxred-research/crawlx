//! Archive completion callback: one outbox row that names only a committed export.
//!
//! A feed whose `source` is [`ARCHIVE_COMPLETION_SOURCE`] carries no dataset items. Its single
//! terminal delivery is the completion notice of the run's archive export: identity, package
//! hash and exact size, taken from the published catalog row itself. The row rides the
//! existing terminal-feed outbox, so it inherits its guarantees: it is staged atomically with
//! the run's terminal transition, keyed by the stable `terminal.empty.<feed>` identity (a
//! retried or recovered finalization never creates a second row), leased with a fence, and
//! delivered at least once to the operator-registered destination.
//!
//! The notice is built only from a published export ([`ArchiveCompletionV1::committed`]). A run
//! whose archive was not committed (disabled, failed, still recording, erased or expired)
//! produces a notice that says so and carries no export identity, hash or size.

use crate::stores::Stores;
use crawlx_core::archive_catalog::{ArchiveCompletionV1, ArchiveExportState, ArchiveReadV1};
use crawlx_core::dataset::{EmptyFeedPolicyV1, FeedCompressionV1, FeedDeclarationV1};
use crawlx_core::repo::CrawlRun;
use crawlx_core::{Clock, StoreError};

/// Reserved dataset name of the feed that delivers archive completion.
pub const ARCHIVE_COMPLETION_SOURCE: &str = "archive_export";

/// Refuse a completion feed that cannot deliver a faithful notice.
///
/// # Errors
/// Names the unsupported combination.
pub(crate) fn validate_feed(feed: &FeedDeclarationV1, archive_enabled: bool) -> Result<(), &'static str> {
    if feed.source != ARCHIVE_COMPLETION_SOURCE {
        return Ok(());
    }
    if !archive_enabled {
        return Err("archive_completion_feed_requires_archive_output");
    }
    if feed.serializer != "json"
        || feed.compression != FeedCompressionV1::None
        || feed.empty_policy != EmptyFeedPolicyV1::Emit
    {
        return Err("archive_completion_feed_requires_uncompressed_json_with_emit");
    }
    Ok(())
}

fn not_committed(reason: &str) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "schemaVersion": 1,
        "state": "not_committed",
        "reason": reason,
    }))
    .unwrap_or_default();
    bytes.push(b'\n');
    bytes
}

/// The terminal body of an archive completion feed, or `None` for any other feed.
///
/// # Errors
/// Returns catalog or serialization failures; a missing or unpublished export is not an error
/// but a `not_committed` notice.
pub(crate) async fn archive_completion_notice(
    stores: &Stores,
    run: &CrawlRun,
    feed: &FeedDeclarationV1,
    clock: &dyn Clock,
) -> Result<Option<Vec<u8>>, StoreError> {
    if feed.source != ARCHIVE_COMPLETION_SOURCE {
        return Ok(None);
    }
    if run.config.output.archive.is_none() {
        return Ok(Some(not_committed("archive_disabled")));
    }
    let export = match stores.archives.get(run.tenant, run.id.0, clock.now()).await? {
        ArchiveReadV1::Available(export) => export,
        ArchiveReadV1::Expired => return Ok(Some(not_committed("expired"))),
        _ => return Ok(Some(not_committed("missing"))),
    };
    match ArchiveCompletionV1::committed(&export) {
        Ok(completion) => {
            let mut bytes = completion.to_bytes()?;
            bytes.push(b'\n');
            Ok(Some(bytes))
        }
        Err(_) => Ok(Some(not_committed(match export.state {
            ArchiveExportState::Recording => "recording",
            ArchiveExportState::Failed => "failed",
            ArchiveExportState::Deleted => "deleted",
            _ => "unavailable",
        }))),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::archive_recorder::{finalize, Finalization};
    use crawlx_core::counters::TerminalReason;
    use crawlx_core::hash::Digest;
    use crawlx_core::orchestration::{RequestBatchV1, RequestCommitV1};
    use crawlx_core::repo::{FrontierStatus, PageRecord, Sensitivity};
    use crawlx_core::request::RequestEnvelopeV1;
    use crawlx_core::secret::{ArtifactSink, Redactor};
    use crawlx_core::time::ManualClock;
    use crawlx_core::traffic::TrustLane;
    use crawlx_core::WorkerId;
    use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
    use crawlx_storage::MemoryStore;
    use std::sync::Arc;
    use tokio_util::sync::CancellationToken;

    fn feed(source: &str, serializer: &str, empty: &str) -> FeedDeclarationV1 {
        serde_json::from_value(serde_json::json!({
            "id":"done","source":source,"serializer":serializer,"serializerVersion":1,
            "destination":"done","maxBatchItems":1,"maxBatchBytes":4096,"emptyPolicy":empty
        }))
        .unwrap()
    }

    #[test]
    fn only_an_uncompressed_json_emit_feed_over_an_enabled_archive_is_accepted() {
        assert_eq!(validate_feed(&feed("items", "csv", "skip"), false), Ok(()));
        assert_eq!(
            validate_feed(&feed(ARCHIVE_COMPLETION_SOURCE, "json", "emit"), true),
            Ok(())
        );
        assert!(validate_feed(&feed(ARCHIVE_COMPLETION_SOURCE, "json", "emit"), false).is_err());
        assert!(validate_feed(&feed(ARCHIVE_COMPLETION_SOURCE, "csv", "emit"), true).is_err());
        assert!(validate_feed(&feed(ARCHIVE_COMPLETION_SOURCE, "json", "skip"), true).is_err());
        let mut gz = feed(ARCHIVE_COMPLETION_SOURCE, "json", "emit");
        gz.compression = FeedCompressionV1::Gzip;
        assert!(validate_feed(&gz, true).is_err());
    }

    async fn run_with_page(
        stores: &Stores,
        clock: &ManualClock,
        archive: bool,
    ) -> crawlx_core::repo::CrawlRun {
        let mut config = create_crawl("https://callback.example.test/a", &[], 1);
        config.retention.days = 1;
        if archive {
            config.output.archive = Some(crawlx_core::archive::ArchiveConfigV1::default());
        }
        let mut run = crawl_run(stores.tenant, config);
        run.created_at = clock.now();
        stores.runs.create(&run, None).await.unwrap();
        let url = canonical_url("https://callback.example.test/a");
        stores
            .frontier
            .append_batch(RequestBatchV1::new(
                run.tenant,
                run.id,
                "anonymous".into(),
                Digest::of("test/archive-callback", b"batch"),
                vec![RequestEnvelopeV1::get(url.clone(), 0, None)],
            ))
            .await
            .unwrap();
        let (entry, fence) = stores
            .frontier
            .lease_batch_fenced(run.id, WorkerId::new(), 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let body = b"callback retained body";
        let source = ArtifactSink::over(stores.artifacts.as_ref())
            .put_page(
                run.id,
                entry.id,
                Sensitivity::Content,
                "text/markdown",
                &Redactor::new().redact_artifact(body).unwrap(),
            )
            .await
            .unwrap();
        let page = PageRecord {
            run: run.id,
            frontier_id: entry.id,
            url,
            status: 200,
            content_type: Some("text/markdown".into()),
            content_digest: Digest::of("test/body", body),
            title: None,
            markdown: Some(source),
            html: None,
            metadata: serde_json::json!({}),
            links: Vec::new(),
            fetched_at: clock.now(),
            lane: TrustLane::Diagnostic,
        };
        let mut commit =
            RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
        commit.page = Some(page);
        stores.request_commits.commit_fenced(commit).await.unwrap();
        run
    }

    fn parse(bytes: &[u8]) -> serde_json::Value {
        assert!(bytes.ends_with(b"\n"));
        serde_json::from_slice(bytes).unwrap()
    }

    #[tokio::test]
    async fn notice_names_only_a_committed_export_and_is_identical_on_every_retry() {
        let root = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(
            chrono::DateTime::parse_from_rfc3339("2026-11-08T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        ));
        let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
        let mut stores = Stores::over_memory(memory.clone(), root.path()).await.unwrap();
        stores.artifacts = Arc::new(
            crawlx_storage::FsArtifactStore::open(root.path(), memory.clone(), clock.clone())
                .await
                .unwrap()
                .with_index(memory.clone()),
        );
        let notice_feed = feed(ARCHIVE_COMPLETION_SOURCE, "json", "emit");
        // Any other feed is not an archive completion feed.
        let other = feed("items", "json", "emit");
        let run = run_with_page(&stores, &clock, true).await;
        assert!(archive_completion_notice(&stores, &run, &other, clock.as_ref())
            .await
            .unwrap()
            .is_none());

        // Nothing exported yet: the notice says so and carries no identity, hash or size.
        let none = parse(
            &archive_completion_notice(&stores, &run, &notice_feed, clock.as_ref())
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(none["state"], "not_committed");
        assert_eq!(none["reason"], "missing");
        for forbidden in ["export", "package", "packageBytes"] {
            assert!(none.get(forbidden).is_none(), "{forbidden}");
        }

        // A recording (claimed, unpublished) export is not committed either.
        let pending = crawlx_core::archive_catalog::ArchiveExportV1::pending(
            run.tenant,
            run.id,
            run.config.output.archive.clone().unwrap(),
            run.created_at,
            Some(run.created_at + chrono::Duration::days(1)),
            TerminalReason::FrontierExhausted,
        );
        stores.archives.begin(&pending).await.unwrap();
        let recording = parse(
            &archive_completion_notice(&stores, &run, &notice_feed, clock.as_ref())
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(
            (recording["state"].clone(), recording["reason"].clone()),
            ("not_committed".into(), "recording".into())
        );
        assert!(recording.get("package").is_none());

        // After publication the notice is the catalog's own hash and size.
        let outcome = finalize(
            &stores,
            &run,
            clock.clone(),
            &CancellationToken::new(),
            TerminalReason::FrontierExhausted,
        )
        .await
        .unwrap();
        if outcome != Finalization::Ready {
            let row = stores
                .archives
                .get(run.tenant, run.id.0, clock.now())
                .await
                .unwrap();
            panic!("finalization {outcome:?}: {row:?}");
        }
        let Ok(ArchiveReadV1::Available(export)) =
            stores.archives.get(run.tenant, run.id.0, clock.now()).await
        else {
            panic!("export missing");
        };
        let first = archive_completion_notice(&stores, &run, &notice_feed, clock.as_ref())
            .await
            .unwrap()
            .unwrap();
        let notice = parse(&first);
        let package = export.artifact.clone().unwrap();
        assert_eq!(notice["state"], "committed");
        assert_eq!(notice["export"], export.id.to_string());
        assert_eq!(notice["package"]["digest"], package.digest.to_hex());
        assert_eq!(
            notice["packageBytes"],
            export.manifest.as_ref().unwrap().package_bytes
        );
        assert!(notice["packageBytes"].as_u64().unwrap() > 0);
        // The recorded size is the real stored object's size.
        let bytes = stores
            .artifacts
            .read_archive_content(run.tenant, run.id, &package, export.config.max_bytes)
            .await
            .unwrap();
        assert_eq!(
            u64::try_from(bytes.len()).unwrap(),
            notice["packageBytes"].as_u64().unwrap()
        );
        // Retry: same bytes, same idempotency key.
        let again = archive_completion_notice(&stores, &run, &notice_feed, clock.as_ref())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first, again);
        let key = |export: &crawlx_core::archive_catalog::ArchiveExportV1| {
            ArchiveCompletionV1::committed(export).unwrap().idempotency_key()
        };
        assert_eq!(key(&export), key(&export));
        assert!(key(&export).contains(&package.digest.to_hex()));

        // An erased export is not announced.
        stores.archives.erase(run.tenant, run.id.0).await.unwrap();
        let erased = parse(
            &archive_completion_notice(&stores, &run, &notice_feed, clock.as_ref())
                .await
                .unwrap()
                .unwrap(),
        );
        assert_eq!(erased["state"], "not_committed");
        assert!(erased.get("package").is_none());
    }

    #[tokio::test]
    async fn run_without_archive_output_announces_nothing_committed() {
        let root = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(chrono::Utc::now()));
        let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
        let mut stores = Stores::over_memory(memory.clone(), root.path()).await.unwrap();
        stores.artifacts = Arc::new(
            crawlx_storage::FsArtifactStore::open(root.path(), memory.clone(), clock.clone())
                .await
                .unwrap()
                .with_index(memory.clone()),
        );
        let run = run_with_page(&stores, &clock, false).await;
        let notice = parse(
            &archive_completion_notice(
                &stores,
                &run,
                &feed(ARCHIVE_COMPLETION_SOURCE, "json", "emit"),
                clock.as_ref(),
            )
            .await
            .unwrap()
            .unwrap(),
        );
        assert_eq!(notice["reason"], "archive_disabled");
    }
}
