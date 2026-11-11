//! Retained approved bodies and renditions preserve captures with bounded local revisit closure.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::archive::ArchiveDedupe;

async fn prepared(
    stores: &Stores,
    clock: &ManualClock,
    scope: ArchiveDedupe,
    urls: &[&str],
    body: &[u8],
) -> (CrawlRun, Vec<PageRecord>) {
    prepared_representation(
        stores,
        clock,
        scope,
        urls,
        body,
        ArchiveRepresentation::ProtocolResource,
    )
    .await
}

async fn prepared_representation(
    stores: &Stores,
    clock: &ManualClock,
    scope: ArchiveDedupe,
    urls: &[&str],
    body: &[u8],
    representation: ArchiveRepresentation,
) -> (CrawlRun, Vec<PageRecord>) {
    let mime = match representation {
        ArchiveRepresentation::RenderedDom => "text/html",
        ArchiveRepresentation::ExtractedText => "text/markdown",
        _ => "text/plain",
    };
    let mut config = create_crawl(urls[0], &[], 4);
    config.retention.days = 1;
    config.capture.response_bodies = crawlx_core::config::ResponseBodies::Full;
    let mut archive = crawlx_core::archive::ArchiveConfigV1::default();
    archive.dedupe = scope;
    archive.max_records = 4;
    archive.rollover_bytes = Some(1024);
    config.output.archive = Some(archive);
    let mut run = crawl_run(stores.tenant, config);
    run.created_at = clock.now();
    stores.runs.create(&run, None).await.unwrap();
    stores
        .frontier
        .append_batch(RequestBatchV1::new(
            run.tenant,
            run.id,
            "anonymous".into(),
            Digest::of("test/archive-payload-batch", body),
            urls.iter()
                .map(|url| RequestEnvelopeV1::get(canonical_url(url), 0, None))
                .collect(),
        ))
        .await
        .unwrap();
    let mut pages = Vec::new();
    for _ in urls {
        let (entry, fence) = stores
            .frontier
            .lease_batch_fenced(run.id, WorkerId::new(), 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let request = stores.frontier.get_request(run.id, entry.id).await.unwrap();
        let artifact = ArtifactSink::over(stores.artifacts.as_ref())
            .put_page(
                run.id,
                entry.id,
                Sensitivity::Content,
                mime,
                &ArtifactRedactor::new().redact_artifact(body).unwrap(),
            )
            .await
            .unwrap();
        let page = PageRecord {
            run: run.id,
            frontier_id: entry.id,
            url: request.envelope.url,
            status: 200,
            content_type: Some(mime.into()),
            content_digest: Digest::of("test/body", body),
            title: None,
            markdown: (representation == ArchiveRepresentation::ExtractedText).then(|| artifact.clone()),
            html: (representation == ArchiveRepresentation::RenderedDom).then(|| artifact.clone()),
            metadata: serde_json::json!({"acquisition":{
                "wireBody":(representation == ArchiveRepresentation::ProtocolResource).then_some(&artifact),
                "backend":(representation == ArchiveRepresentation::ProtocolResource).then(|| serde_json::json!({"backendId":"native_http"})),
                "truncated":false,"decodedBytes":body.len()
            },"response_headers":{}}),
            links: Vec::new(),
            fetched_at: clock.now(),
            lane: TrustLane::Diagnostic,
        };
        let mut commit =
            RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
        commit.page = Some(page.clone());
        stores.request_commits.commit_fenced(commit).await.unwrap();
        pages.push(page);
    }
    (run, pages)
}

async fn published(stores: &Stores, run: &CrawlRun, clock: Arc<ManualClock>) -> Box<ArchiveExportV1> {
    assert_eq!(
        finalize(
            stores,
            run,
            clock.clone(),
            &CancellationToken::new(),
            TerminalReason::FrontierExhausted
        )
        .await
        .unwrap(),
        Finalization::Ready
    );
    let ArchiveReadV1::Available(export) = stores
        .archives
        .get(run.tenant, run.id.0, clock.now())
        .await
        .unwrap()
    else {
        panic!("published payload export missing");
    };
    assert_eq!(export.state, ArchiveExportState::Published);
    export
}

async fn inspect_payloads(
    stores: &Stores,
    export: &ArchiveExportV1,
    root: &Path,
    body: &[u8],
    captures: usize,
    dependencies: u64,
) {
    let path = root.join(format!("{}.wacz", export.id));
    stores
        .artifacts
        .copy_archive_with_custody(
            export.tenant,
            export.run,
            export.artifact.as_ref().unwrap(),
            &export.custody,
            &path,
            1_048_576,
        )
        .await
        .unwrap();
    let inspected = wacz::inspect(File::open(&path).unwrap(), Limits::default()).unwrap();
    let records: Vec<_> = inspected
        .records
        .iter()
        .flat_map(|(file, records)| records.iter().map(move |record| (file, record)))
        .collect();
    assert_eq!(records.len(), captures + usize::try_from(dependencies).unwrap());
    assert_eq!(
        records
            .iter()
            .filter(|(_, record)| record.record_type == "resource")
            .count(),
        1
    );
    for (filename, record) in records {
        assert_eq!(
            wacz::payload(File::open(&path).unwrap(), filename, record, Limits::default()).unwrap(),
            body
        );
    }
    assert_eq!(
        export.manifest.as_ref().unwrap().records,
        u64::try_from(captures).unwrap()
    );
    assert_eq!(
        export.manifest.as_ref().unwrap().materialized_dependencies,
        dependencies
    );
}

async fn exercise_renditions(stores: &Stores, clock: Arc<ManualClock>, root: &Path) {
    let body = b"same approved retained rendition";
    for representation in [
        ArchiveRepresentation::RenderedDom,
        ArchiveRepresentation::ExtractedText,
    ] {
        let (run, pages) = prepared_representation(
            stores,
            &clock,
            ArchiveDedupe::Tenant,
            &[
                "https://rendition.example.test/first",
                "https://rendition.example.test/second",
            ],
            body,
            representation,
        )
        .await;
        let export = published(stores, &run, clock.clone()).await;
        let records = stores
            .archives
            .records(run.tenant, run.id.0, None, 64, clock.now())
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_ne!(records[0].record_id, records[1].record_id);
        assert_ne!(records[0].target, records[1].target);
        assert!(records[0].dependency.is_none());
        assert_eq!(records[1].dependency.as_ref().unwrap().export, run.id.0);
        assert_eq!(
            records[1].dependency.as_ref().unwrap().ordinal,
            records[0].ordinal
        );
        assert!(records
            .iter()
            .all(|record| record.facts.representation == representation
                && record.facts.body_state == "unknown"
                && record
                    .facts
                    .transformations
                    .iter()
                    .any(|step| step == "retained_rendition_not_original_wire")));
        inspect_payloads(stores, &export, root, body, 2, 0).await;
        let page = &pages[0];
        let request = stores
            .frontier
            .get_request(run.id, page.frontier_id)
            .await
            .unwrap();
        let record = &records[0];
        let key = record.payload_key.as_ref().unwrap();
        let mut changed_request = request.clone();
        changed_request.envelope.session_generation = Some(1);
        assert_ne!(
            payload::key(&run, &changed_request, page, &record.facts, &record.mime)
                .unwrap()
                .as_ref(),
            Some(key)
        );
        changed_request = request.clone();
        changed_request.principal = "separate-principal".into();
        assert_ne!(
            payload::key(&run, &changed_request, page, &record.facts, &record.mime)
                .unwrap()
                .as_ref(),
            Some(key)
        );
        let mut changed_facts = record.facts.clone();
        changed_facts.redaction_revision = "different-redaction".into();
        assert_ne!(
            payload::key(&run, &request, page, &changed_facts, &record.mime)
                .unwrap()
                .as_ref(),
            Some(key)
        );
        changed_facts = record.facts.clone();
        changed_facts.capture_source = "retained_journal_unknown".into();
        assert!(payload::key(&run, &request, page, &changed_facts, &record.mime)
            .unwrap()
            .is_none());
        changed_facts = record.facts.clone();
        changed_facts.body_state = "prefix".into();
        assert!(payload::key(&run, &request, page, &changed_facts, &record.mime)
            .unwrap()
            .is_none());
        // Even an exact copied key cannot authorize published rendition reuse across runs.
        let (next, _) = prepared_representation(
            stores,
            &clock,
            ArchiveDedupe::Tenant,
            &[
                "https://rendition.example.test/third",
                "https://rendition.example.test/fourth",
            ],
            body,
            representation,
        )
        .await;
        assert_ne!(
            payload::key(&next, &request, page, &record.facts, &record.mime)
                .unwrap()
                .as_ref(),
            Some(key)
        );
        let pending = ArchiveExportV1::pending(
            next.tenant,
            next.id,
            next.config.output.archive.as_ref().unwrap().clone(),
            next.created_at,
            Some(next.created_at + chrono::Duration::days(1)),
            TerminalReason::FrontierExhausted,
        );
        stores.archives.begin(&pending).await.unwrap();
        assert!(stores
            .archives
            .payload_source(next.tenant, next.id.0, key, &record.payload_digest, clock.now())
            .await
            .unwrap()
            .is_none());
        let next_export = published(stores, &next, clock.clone()).await;
        let next_records = stores
            .archives
            .records(next.tenant, next.id.0, None, 64, clock.now())
            .await
            .unwrap();
        assert!(next_records[0].dependency.is_none());
        assert_eq!(next_records[1].dependency.as_ref().unwrap().export, next.id.0);
        inspect_payloads(stores, &next_export, root, body, 2, 0).await;
    }
}

async fn exercise(stores: &Stores, clock: Arc<ManualClock>, root: &Path) {
    let body = b"same approved native body";
    exercise_renditions(stores, clock.clone(), root).await;
    let (collection, _) = prepared(
        stores,
        &clock,
        ArchiveDedupe::Collection,
        &[
            "https://payload.example.test/first",
            "https://payload.example.test/second",
        ],
        body,
    )
    .await;
    let export = published(stores, &collection, clock.clone()).await;
    let records = stores
        .archives
        .records(collection.tenant, collection.id.0, None, 64, clock.now())
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_ne!(records[0].record_id, records[1].record_id);
    assert_ne!(records[0].target, records[1].target);
    assert!(records[0].dependency.is_none());
    assert_eq!(records[1].dependency.as_ref().unwrap().export, collection.id.0);
    assert_eq!(
        records[1].dependency.as_ref().unwrap().ordinal,
        records[0].ordinal
    );
    inspect_payloads(stores, &export, root, body, 2, 0).await;

    let tenant_body = b"independent tenant scope payload";
    let (source, _) = prepared(
        stores,
        &clock,
        ArchiveDedupe::Tenant,
        &["https://payload.example.test/source"],
        tenant_body,
    )
    .await;
    published(stores, &source, clock.clone()).await;
    let (dependent, _) = prepared(
        stores,
        &clock,
        ArchiveDedupe::Tenant,
        &[
            "https://payload.example.test/new-first",
            "https://payload.example.test/new-second",
        ],
        tenant_body,
    )
    .await;
    let export = published(stores, &dependent, clock.clone()).await;
    let records = stores
        .archives
        .records(dependent.tenant, dependent.id.0, None, 64, clock.now())
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| record
        .dependency
        .as_ref()
        .is_some_and(|dependency| dependency.export == source.id.0)));
    inspect_payloads(stores, &export, root, tenant_body, 2, 1).await;
    let key = records[0].payload_key.as_ref().unwrap();
    let mut changed = key.clone();
    changed.principal = "different-principal".into();
    // A new recording intent is required for a lookup; publication is not writable authority.
    let (probe, _) = prepared(
        stores,
        &clock,
        ArchiveDedupe::Tenant,
        &["https://payload.example.test/probe"],
        tenant_body,
    )
    .await;
    let pending = ArchiveExportV1::pending(
        probe.tenant,
        probe.id,
        probe.config.output.archive.as_ref().unwrap().clone(),
        probe.created_at,
        Some(probe.created_at + chrono::Duration::days(1)),
        TerminalReason::FrontierExhausted,
    );
    stores.archives.begin(&pending).await.unwrap();
    assert!(stores
        .archives
        .payload_source(
            probe.tenant,
            probe.id.0,
            &changed,
            &records[0].payload_digest,
            clock.now()
        )
        .await
        .unwrap()
        .is_none());
    changed = key.clone();
    changed.redaction_revision = "different-policy".into();
    assert!(stores
        .archives
        .payload_source(
            probe.tenant,
            probe.id.0,
            &changed,
            &records[0].payload_digest,
            clock.now()
        )
        .await
        .unwrap()
        .is_none());
    changed = key.clone();
    changed.representation = ArchiveRepresentation::RenderedDom;
    assert!(stores
        .archives
        .payload_source(
            probe.tenant,
            probe.id.0,
            &changed,
            &records[0].payload_digest,
            clock.now()
        )
        .await
        .unwrap()
        .is_none());
    assert!(stores
        .archives
        .payload_source(
            TenantId::new(),
            probe.id.0,
            key,
            &records[0].payload_digest,
            clock.now()
        )
        .await
        .unwrap()
        .is_none());
    failed_source_is_never_selected(stores, &probe, &clock).await;
    clock.advance_ms(86_400_001);
    assert!(stores
        .archives
        .payload_source(
            probe.tenant,
            probe.id.0,
            key,
            &records[0].payload_digest,
            clock.now()
        )
        .await
        .unwrap()
        .is_none());
    let (fresh, _) = prepared(
        stores,
        &clock,
        ArchiveDedupe::Tenant,
        &["https://payload.example.test/after-expiry"],
        tenant_body,
    )
    .await;
    let fresh_pending = ArchiveExportV1::pending(
        fresh.tenant,
        fresh.id,
        fresh.config.output.archive.as_ref().unwrap().clone(),
        fresh.created_at,
        Some(fresh.created_at + chrono::Duration::days(1)),
        TerminalReason::FrontierExhausted,
    );
    stores.archives.begin(&fresh_pending).await.unwrap();
    assert!(stores
        .archives
        .payload_source(
            fresh.tenant,
            fresh.id.0,
            key,
            &records[0].payload_digest,
            clock.now()
        )
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn memory_cross_url_payload_revisits_preserve_captures_and_close_local_packages() {
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-06T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    ));
    let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
    let mut stores = Stores::over_memory(memory.clone(), root.path()).await.unwrap();
    stores.artifacts = Arc::new(
        FsArtifactStore::open(root.path(), memory.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(memory),
    );
    exercise(&stores, clock, root.path()).await;
}

#[tokio::test]
async fn postgres_cross_url_payload_revisits_match_memory_custody() {
    let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap(),
    ));
    let pg = Pg::connect(
        &url,
        StoreConfig {
            schema: Some(format!("archive_payloads_{}", uuid::Uuid::now_v7().simple())),
            ..StoreConfig::default()
        },
    )
    .await
    .unwrap();
    pg.migrate().await.unwrap();
    let tenant = TenantId::new();
    pg.ensure_tenant(tenant, "archive-payloads").await.unwrap();
    let artifacts = Arc::new(
        FsArtifactStore::open(root.path(), Arc::new(pg.clone()), clock.clone())
            .await
            .unwrap()
            .with_index(Arc::new(pg.clone())),
    );
    let stores = Stores::over_durable(
        crate::durable::DurableStore::Postgres(pg.clone()),
        artifacts,
        tenant,
    );
    exercise(&stores, clock, root.path()).await;
    pg.drop_schema().await.unwrap();
}

async fn failed_source_is_never_selected(stores: &Stores, probe: &CrawlRun, clock: &ManualClock) {
    let (run, pages) = prepared(
        stores,
        clock,
        ArchiveDedupe::Tenant,
        &["https://payload.example.test/unpublished"],
        b"failed publication only payload",
    )
    .await;
    let pending = ArchiveExportV1::pending(
        run.tenant,
        run.id,
        run.config.output.archive.as_ref().unwrap().clone(),
        run.created_at,
        Some(run.created_at + chrono::Duration::days(1)),
        TerminalReason::FrontierExhausted,
    );
    stores.archives.begin(&pending).await.unwrap();
    let export = stores
        .archives
        .claim(run.tenant, run.id.0, clock.now())
        .await
        .unwrap()
        .unwrap();
    let page = &pages[0];
    let source: crawlx_core::ArtifactRef =
        serde_json::from_value(page.metadata["acquisition"]["wireBody"].clone()).unwrap();
    let request = stores
        .frontier
        .get_request(run.id, page.frontier_id)
        .await
        .unwrap();
    let mut facts = ArchiveCaptureFactsV1::retained(
        "unpublished:response",
        page.fetched_at,
        ArchiveRepresentation::ProtocolResource,
        "retained_native_decoded_response_body",
    );
    facts.body_state = "complete".into();
    let mut recorder = resource::Recorder {
        stores,
        run: &run,
        export: &export,
        clock,
        cancel: &CancellationToken::new(),
        committed_bytes: 0,
    };
    assert!(matches!(
        recorder
            .record(resource::ResourceInput {
                ordinal: 8,
                source: Some(&source),
                capture: None,
                target: page.url.url.as_str(),
                mime: "text/plain",
                facts,
                history_source: Some((&request, page)),
            })
            .await
            .unwrap(),
        resource::RecordOutcome::Committed
    ));
    let record = stores
        .archives
        .records(run.tenant, run.id.0, None, 1, clock.now())
        .await
        .unwrap()
        .pop()
        .unwrap();
    let key = record.payload_key.as_ref().unwrap();
    let mut changed_page = page.clone();
    changed_page.metadata["response_headers"]["vary"] = "*".into();
    assert!(
        payload::key(&run, &request, &changed_page, &record.facts, &record.mime)
            .unwrap()
            .is_none()
    );
    changed_page.metadata["response_headers"]["vary"] = serde_json::json!(["accept"]);
    assert!(
        payload::key(&run, &request, &changed_page, &record.facts, &record.mime)
            .unwrap()
            .is_none()
    );
    changed_page.metadata["response_headers"]["vary"] = "accept".into();
    assert_ne!(
        payload::key(&run, &request, &changed_page, &record.facts, &record.mime)
            .unwrap()
            .as_ref(),
        Some(key)
    );
    assert!(stores
        .archives
        .payload_source(probe.tenant, probe.id.0, key, &record.payload_digest, clock.now())
        .await
        .unwrap()
        .is_none());
    stores
        .archives
        .fail(
            run.tenant,
            run.id.0,
            export.fence,
            crawlx_core::archive_catalog::ArchiveFailureV1::InvalidCapture,
            clock.now(),
        )
        .await
        .unwrap();
    assert!(stores
        .archives
        .payload_source(probe.tenant, probe.id.0, key, &record.payload_digest, clock.now())
        .await
        .unwrap()
        .is_none());
    let writer = stores
        .archives
        .claim(probe.tenant, probe.id.0, clock.now())
        .await
        .unwrap()
        .unwrap();
    let mut uncommitted = record.clone();
    uncommitted.export = probe.id.0;
    uncommitted.artifact.id = crawlx_core::ArtifactId::new();
    assert!(stores
        .archives
        .commit_record(probe.tenant, writer.fence, &uncommitted, None, clock.now())
        .await
        .is_err());
    assert!(stores
        .archives
        .payload_source(probe.tenant, probe.id.0, key, &record.payload_digest, clock.now())
        .await
        .unwrap()
        .is_none());
}

mod races;
