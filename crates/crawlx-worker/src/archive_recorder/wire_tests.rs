//! Wire evidence records: observed protocol, true status, TLS facts, redacted request headers.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crawlx_core::archive_catalog::ArchiveTrafficV1;
use crawlx_core::counters::TerminalReason;
use crawlx_core::orchestration::{RequestBatchV1, RequestCommitV1};
use crawlx_core::repo::{FrontierStatus, PageRecord, Sensitivity};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_core::secret::{ArtifactSink, Redactor as ArtifactRedactor};
use crawlx_core::time::ManualClock;
use crawlx_core::traffic::{Protocol, TrustLane};
use crawlx_core::WorkerId;
use crawlx_storage::testkit::{canonical_url, crawl_run, create_crawl};
use crawlx_storage::MemoryStore;
use std::io::Read as _;
use std::path::Path;

const FIXTURE_SHA256: &str = "1bb0682e7256efceefe2d64c65a6af436cfcc6431d967774f1048d71e043d947";

async fn memory(root: &Path) -> (Stores, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::parse_from_rfc3339("2026-11-08T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    ));
    let memory = Arc::new(MemoryStore::with_clock(clock.clone()));
    let mut stores = Stores::over_memory(memory.clone(), root).await.unwrap();
    // Archive custody reads the artifact index, so the store must be indexed like a live one.
    stores.artifacts = Arc::new(
        crawlx_storage::FsArtifactStore::open(root, memory.clone(), clock.clone())
            .await
            .unwrap()
            .with_index(memory.clone()),
    );
    (stores, clock)
}

/// WARC header text and block of one committed shard.
async fn member(stores: &Stores, run: &CrawlRun, record: &ArchiveRecordV1) -> (String, Vec<u8>) {
    let bytes = stores
        .artifacts
        .read_archive_content(run.tenant, run.id, &record.artifact, 1_048_576)
        .await
        .unwrap();
    let mut plain = Vec::new();
    flate2::read::MultiGzDecoder::new(&bytes[..])
        .read_to_end(&mut plain)
        .unwrap();
    let split = plain.windows(4).position(|window| window == b"\r\n\r\n").unwrap();
    let headers = String::from_utf8(plain[..split].to_vec()).unwrap();
    let block = plain[split + 4..plain.len() - 4].to_vec();
    (headers, block)
}

fn evidence_header(decoded: bool) -> String {
    serde_json::json!({
        "schemaVersion": 1,
        "certificate": {"state": "unavailable", "reason": "not_tls"},
        "body": {"contentEncoding": [], "decoded": decoded, "wireBytes": 1, "decodedBytes": 1,
                  "truncated": false},
    })
    .to_string()
}

struct NativePage<'a> {
    url: &'a str,
    body: &'a [u8],
    /// Everything of the receipt except `wireBody`, `truncated` and `decodedBytes`.
    acquisition: serde_json::Value,
    headers: Option<serde_json::Value>,
    truncated: bool,
}

async fn native_run(
    stores: &Stores,
    clock: &ManualClock,
    pages: &[NativePage<'_>],
) -> (CrawlRun, Vec<PageRecord>) {
    let mut config = create_crawl(pages[0].url, &[], 8);
    config.retention.days = 1;
    config.capture.response_bodies = crawlx_core::config::ResponseBodies::Full;
    config.output.archive = Some(crawlx_core::archive::ArchiveConfigV1::default());
    let mut run = crawl_run(stores.tenant, config);
    run.created_at = clock.now();
    stores.runs.create(&run, None).await.unwrap();
    stores
        .frontier
        .append_batch(RequestBatchV1::new(
            run.tenant,
            run.id,
            "anonymous".into(),
            Digest::of("test/archive-wire", b"batch"),
            pages
                .iter()
                .map(|page| RequestEnvelopeV1::get(canonical_url(page.url), 0, None))
                .collect(),
        ))
        .await
        .unwrap();
    let mut committed = Vec::new();
    for page in pages {
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
                "text/html",
                &ArtifactRedactor::new().redact_artifact(page.body).unwrap(),
            )
            .await
            .unwrap();
        let mut acquisition = page.acquisition.clone();
        acquisition["wireBody"] = serde_json::to_value(&artifact).unwrap();
        acquisition["truncated"] = page.truncated.into();
        acquisition["decodedBytes"] = page.body.len().into();
        acquisition["backend"] = serde_json::json!({"backendId": "native_http"});
        let mut metadata = serde_json::json!({ "acquisition": acquisition });
        if let Some(headers) = &page.headers {
            metadata["response_headers"] = headers.clone();
        }
        let record = PageRecord {
            run: run.id,
            frontier_id: entry.id,
            url: request.envelope.url,
            status: 200,
            content_type: Some("text/html".into()),
            content_digest: Digest::of("test/body", page.body),
            title: None,
            markdown: None,
            html: None,
            metadata,
            links: Vec::new(),
            fetched_at: clock.now(),
            lane: TrustLane::Diagnostic,
        };
        let mut commit =
            RequestCommitV1::terminal(run.id, entry.id, fence, 1, FrontierStatus::Succeeded, None);
        commit.page = Some(record.clone());
        stores.request_commits.commit_fenced(commit).await.unwrap();
        committed.push(record);
    }
    (run, committed)
}

async fn publish(stores: &Stores, run: &CrawlRun, clock: &Arc<ManualClock>) -> ArchiveExportV1 {
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
        Finalization::Ready,
        "{:?}",
        stores
            .archives
            .get(run.tenant, run.id.0, clock.now())
            .await
            .unwrap()
    );
    let ArchiveReadV1::Available(export) = stores
        .archives
        .get(run.tenant, run.id.0, clock.now())
        .await
        .unwrap()
    else {
        panic!("published export missing");
    };
    assert_eq!(export.state, ArchiveExportState::Published);
    *export
}

async fn records(stores: &Stores, run: &CrawlRun, clock: &ManualClock) -> BTreeMapRecords {
    stores
        .archives
        .records(run.tenant, run.id.0, None, 64, clock.now())
        .await
        .unwrap()
        .into_iter()
        .map(|record| (record.ordinal, record))
        .collect()
}

type BTreeMapRecords = std::collections::BTreeMap<u64, ArchiveRecordV1>;

fn certificate() -> serde_json::Value {
    serde_json::json!({
        "sha256": FIXTURE_SHA256,
        "notBefore": "2026-10-27T18:43:27Z",
        "notAfter": "2126-10-03T18:43:27Z",
        "selfIssued": true,
        "derLen": 700
    })
}

#[tokio::test]
async fn native_h2_response_is_a_normalized_message_with_true_status_protocol_and_tls_facts() {
    let root = tempfile::tempdir().unwrap();
    let (stores, clock) = memory(root.path()).await;
    let body = b"<html><body>wire body</body></html>";
    let (run, pages) = native_run(
        &stores,
        &clock,
        &[NativePage {
            url: "https://wire.example.test/page?a=1",
            body,
            acquisition: serde_json::json!({
                "targetStatus": 200,
                "connection": {
                    "negotiatedProtocol": "h2",
                    "tlsVerification": "explicit_insecure",
                    "certificateObserved": true,
                    "certificate": certificate(),
                },
            }),
            headers: Some(serde_json::json!({
                "content-type": "text/html; charset=utf-8",
                // The fetch plane removed this coding; the stored body is the decoded one.
                "content-encoding": "gzip",
                "content-length": "9",
                "etag": "\"v1\"",
                "server": "fixture",
                // A credential-named header that reached the receipt must never reach the archive.
                "x-api-key": "wire-secret-key-12345678",
                "x-crawlx-stream-evidence": evidence_header(true),
            })),
            truncated: false,
        }],
    )
    .await;
    let export = publish(&stores, &run, &clock).await;
    let by_ordinal = records(&stores, &run, &clock).await;
    let base = u64::try_from(pages[0].frontier_id).unwrap() * 8;

    // The retained body keeps its resource record and now names the observed wire facts.
    let resource = &by_ordinal[&base];
    assert_eq!(resource.facts.source_protocol.as_deref(), Some("h2"));
    assert_eq!(resource.facts.source_status, Some(200));
    let tls = resource.facts.tls.as_ref().unwrap();
    assert_eq!(tls.verification.as_deref(), Some("explicit_insecure"));
    assert_eq!(tls.certificate.as_ref().unwrap().sha256, FIXTURE_SHA256);
    assert!(tls.certificate.as_ref().unwrap().self_issued);

    // Beside it, a separate normalized response message.
    let response = &by_ordinal[&(base + 3)];
    assert_eq!(
        response.facts.representation,
        crawlx_core::archive::ArchiveRepresentation::NormalizedHttp
    );
    assert_eq!(response.facts.source_protocol.as_deref(), Some("h2"));
    assert_eq!(response.facts.source_status, Some(200));
    assert_eq!(response.facts.body_state, "complete");
    assert!(response
        .facts
        .transformations
        .contains(&"normalized_http_message_not_original_wire".to_owned()));
    assert_eq!(
        response
            .facts
            .tls
            .as_ref()
            .unwrap()
            .certificate
            .as_ref()
            .unwrap()
            .sha256,
        FIXTURE_SHA256
    );
    let (warc_headers, block) = member(&stores, &run, response).await;
    assert!(warc_headers.contains("warc-type: response"), "{warc_headers}");
    assert!(warc_headers.contains("warc-protocol: h2"), "{warc_headers}");
    assert!(
        warc_headers.contains("content-type: application/http; msgtype=response"),
        "{warc_headers}"
    );
    let text = String::from_utf8(block).unwrap();
    let (head, payload) = text.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert!(
        head.contains("\r\ncontent-type: text/html; charset=utf-8"),
        "{head}"
    );
    assert!(head.contains("\r\netag: \"v1\""), "{head}");
    assert!(head.contains("\r\nserver: fixture"), "{head}");
    // Framing is rebuilt from the stored decoded body; the removed coding is gone.
    assert!(
        head.contains(&format!("\r\ncontent-length: {}", body.len())),
        "{head}"
    );
    assert!(!head.contains("content-length: 9"), "{head}");
    assert!(!head.to_ascii_lowercase().contains("content-encoding"), "{head}");
    // Internal evidence and credentials are never archived.
    assert!(!head.contains("x-crawlx"), "{head}");
    assert!(!head.contains("wire-secret-key"), "{head}");
    assert!(!head.to_ascii_lowercase().contains("x-api-key"), "{head}");
    assert_eq!(payload.as_bytes(), body);
    // The package index states the real status, not the page row's apparent success.
    let package = root.path().join("package.wacz");
    stores
        .artifacts
        .copy_archive_content(
            run.tenant,
            run.id,
            export.artifact.as_ref().unwrap(),
            &package,
            export.config.max_bytes,
        )
        .await
        .unwrap();
    let inspection = wacz::inspect(std::fs::File::open(&package).unwrap(), Limits::default()).unwrap();
    let statuses: Vec<_> = inspection
        .records
        .values()
        .flatten()
        .map(|record| (record.record_type.clone(), record.status))
        .collect();
    assert!(
        statuses.contains(&("response".to_owned(), Some(200))),
        "{statuses:?}"
    );
    assert!(statuses.contains(&("resource".to_owned(), None)), "{statuses:?}");
    // Wire records are not page entry points: one page, one entry.
    assert_eq!(
        inspection
            .resources
            .iter()
            .filter(|resource| resource.path == "pages/pages.jsonl")
            .count(),
        1
    );
    assert_eq!(
        export.manifest.as_ref().unwrap().package_bytes,
        std::fs::metadata(&package).unwrap().len()
    );
}

#[tokio::test]
async fn responses_that_cannot_be_presented_truthfully_are_omitted_by_reason() {
    let root = tempfile::tempdir().unwrap();
    let (stores, clock) = memory(root.path()).await;
    let html = serde_json::json!({"content-type": "text/html"});
    let acquisition =
        |connection: serde_json::Value| serde_json::json!({"targetStatus": 200, "connection": connection});
    let (run, pages) = native_run(
        &stores,
        &clock,
        &[
            // The sender's coding was not removed: the stored bytes are not the message body.
            NativePage {
                url: "https://wire.example.test/encoded",
                body: b"<p>encoded</p>",
                acquisition: acquisition(serde_json::json!({})),
                headers: Some(serde_json::json!({
                    "content-type": "text/html",
                    "content-encoding": "gzip",
                    "x-crawlx-stream-evidence": evidence_header(false)
                })),
                truncated: false,
            },
            // A media type the text-only package policy cannot carry.
            NativePage {
                url: "https://wire.example.test/binary-type",
                body: b"plain text under a binary label",
                acquisition: acquisition(serde_json::json!({})),
                headers: Some(serde_json::json!({"content-type": "application/octet-stream"})),
                truncated: false,
            },
            // The receipt never recorded status or headers: nothing is invented, nothing omitted.
            NativePage {
                url: "https://wire.example.test/unrecorded",
                body: b"<p>unrecorded</p>",
                acquisition: serde_json::json!({}),
                headers: None,
                truncated: false,
            },
            // A prefix is not a complete message.
            NativePage {
                url: "https://wire.example.test/prefix",
                body: b"<p>prefix</p>",
                acquisition: acquisition(serde_json::json!({})),
                headers: Some(html.clone()),
                truncated: true,
            },
            // No observed protocol: the fact stays absent in the facts and the WARC header.
            NativePage {
                url: "https://wire.example.test/no-protocol",
                body: b"<p>plain</p>",
                acquisition: acquisition(serde_json::json!({"tlsVerification": "verify_peer_and_hostname"})),
                headers: Some(html),
                truncated: false,
            },
        ],
    )
    .await;
    let export = publish(&stores, &run, &clock).await;
    let by_ordinal = records(&stores, &run, &clock).await;
    let slot = |index: usize, slot: u64| u64::try_from(pages[index].frontier_id).unwrap() * 8 + slot;
    for index in 0..4 {
        assert!(
            !by_ordinal.contains_key(&slot(index, 3)),
            "page {index} must not have a normalized message"
        );
    }
    let reasons: Vec<_> = export
        .manifest
        .as_ref()
        .unwrap()
        .omissions
        .iter()
        .filter(|omission| omission.source_event.ends_with(":http_response"))
        .map(|omission| (omission.source_event.clone(), omission.reason.clone()))
        .collect();
    let expect = |index: usize, reason: &str| {
        (
            format!("page:{}:http_response", pages[index].frontier_id),
            reason.to_owned(),
        )
    };
    assert_eq!(
        reasons,
        [
            expect(0, "normalized_http_content_coding_not_decoded"),
            expect(1, "normalized_http_media_type_not_text"),
            expect(3, "normalized_http_requires_complete_decoded_body"),
        ]
    );
    // The page without a protocol still gets its message, and names no protocol anywhere.
    let response = &by_ordinal[&slot(4, 3)];
    assert_eq!(response.facts.source_protocol, None);
    assert_eq!(
        response.facts.tls.as_ref().unwrap().verification.as_deref(),
        Some("verify_peer_and_hostname")
    );
    assert_eq!(response.facts.tls.as_ref().unwrap().certificate, None);
    let (warc_headers, _) = member(&stores, &run, response).await;
    assert!(!warc_headers.contains("warc-protocol"), "{warc_headers}");
    assert_eq!(by_ordinal[&slot(4, 0)].facts.source_protocol, None);
}

#[tokio::test]
async fn journal_event_yields_separate_redacted_header_protocol_body_and_screenshot_records() {
    use crawlx_core::browser_capture::{
        CaptureArtifact, CaptureCompleteness, CaptureDescriptor, CaptureKind,
    };
    use image::ImageEncoder as _;
    let root = tempfile::tempdir().unwrap();
    let (stores, clock) = memory(root.path()).await;
    let mut config = create_crawl("https://journal.example.test/", &[], 1);
    config.retention.days = 1;
    config.capture.browser.phase_resources = true;
    config.output.archive = Some(crawlx_core::archive::ArchiveConfigV1::default());
    let mut run = crawl_run(stores.tenant, config);
    run.created_at = clock.now();
    stores.runs.create(&run, None).await.unwrap();
    let put = |kind: Sensitivity, mime: &'static str, bytes: Vec<u8>| {
        let stores = &stores;
        let run = &run;
        async move {
            let approved = if kind == Sensitivity::Sensitive {
                ArtifactRedactor::new().verify_binary(&bytes).unwrap()
            } else {
                ArtifactRedactor::new().redact_artifact(&bytes).unwrap()
            };
            ArtifactSink::over(stores.artifacts.as_ref())
                .put(run.id, kind, mime, &approved)
                .await
                .unwrap()
        }
    };
    let request_body = put(Sensitivity::Content, "text/plain", br#"{"q":"one"}"#.to_vec()).await;
    let response_body = put(Sensitivity::Content, "text/plain", b"answer one".to_vec()).await;
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png)
        .write_image(
            &[0, 10, 20, 255, 30, 40, 50, 255],
            2,
            1,
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();
    let screenshot = put(Sensitivity::Sensitive, "image/png", png.clone()).await;
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
        .claim(run.tenant, pending.id, clock.now())
        .await
        .unwrap()
        .unwrap();
    let cancel = CancellationToken::new();
    let mut recorder = resource::Recorder {
        stores: &stores,
        run: &run,
        export: &export,
        clock: clock.as_ref(),
        cancel: &cancel,
        committed_bytes: 0,
    };
    let mut manifest = ArchiveManifestV1::available(run.tenant, run.id, run.created_at);
    let mut committed = 0u64;
    let target = "https://journal.example.test/search?q=one";
    let at = clock.now();
    let events = [
        // Headers and protocol recorded: header record and protocol record exist.
        ArchiveTrafficV1::new(
            7,
            Some(target.into()),
            at,
            Some(request_body.clone()),
            Some(response_body.clone()),
        )
        .with_wire(
            Some("POST".into()),
            Some(
                [
                    ("host", "journal.example.test"),
                    ("authorization", "Bearer journal-secret-token-1234567890"),
                    ("cookie", "sid=journalsession1234567890"),
                    ("content-type", "application/json"),
                    ("x-trace", "t1"),
                    ("content-length", "11"),
                    (":authority", "journal.example.test"),
                    ("transfer-encoding", "chunked"),
                    ("bad_name", "1"),
                ]
                .map(|(name, value)| (name.to_owned(), value.to_owned()))
                .to_vec(),
            ),
            Some(Protocol::H2),
        ),
        // Headers recorded, protocol never observed: the protocol record stays absent.
        ArchiveTrafficV1::new(9, Some(target.into()), at, None, None).with_wire(
            Some("GET".into()),
            Some(vec![("accept".into(), "*/*".into())]),
            None,
        ),
        // Headers never persisted: omitted by reason, not reconstructed.
        ArchiveTrafficV1::new(11, Some(target.into()), at, None, None).with_wire(
            Some("GET".into()),
            None,
            None,
        ),
    ];
    for traffic in &events {
        for (slot, kind, source) in [
            (0u64, "request", traffic.request_body.as_ref()),
            (1u64, "response", traffic.response_body.as_ref()),
        ] {
            let facts = ArchiveCaptureFactsV1::retained(
                format!("traffic:{}:{kind}", traffic.event_id),
                traffic.captured_at,
                ArchiveRepresentation::ProtocolResource,
                "retained_journal_body",
            )
            .with_source_wire(traffic.protocol, None, None);
            if source.is_some() {
                let outcome = recorder
                    .record(resource::ResourceInput {
                        ordinal: traffic.event_id * 8 + 4 + slot,
                        source,
                        capture: None,
                        target,
                        mime: "text/plain",
                        facts,
                        history_source: None,
                    })
                    .await
                    .unwrap();
                assert!(matches!(outcome, resource::RecordOutcome::Committed));
                committed += 1;
            }
        }
        wire::record_traffic(&mut recorder, &mut manifest, &mut committed, traffic, target)
            .await
            .unwrap();
    }
    // A retained PNG screenshot of the same crawl rides the same package as its own record.
    let mut capture = CaptureArtifact::new(
        CaptureDescriptor::new(CaptureKind::Screenshot, "image/png", target),
        screenshot.clone(),
        u64::try_from(png.len()).unwrap(),
        CaptureCompleteness::Complete,
    );
    capture.width = Some(2);
    capture.height = Some(1);
    let mut facts = ArchiveCaptureFactsV1::retained(
        "screenshot:initial",
        at,
        ArchiveRepresentation::Screenshot,
        "browser_evidence_initial",
    );
    facts.redaction_revision = "browser-evidence-v1".into();
    facts.body_state = "complete".into();
    assert!(matches!(
        recorder
            .record(resource::ResourceInput {
                ordinal: 1 << 62,
                source: Some(&screenshot),
                capture: Some(&capture),
                target,
                mime: "image/png",
                facts,
                history_source: None,
            })
            .await
            .unwrap(),
        resource::RecordOutcome::Committed
    ));
    let by_ordinal = records(&stores, &run, &clock).await;

    // Event 7: request body, response body, request headers, protocol: four separate records.
    let (body, answer, headers, protocol) = (
        &by_ordinal[&60],
        &by_ordinal[&61],
        &by_ordinal[&62],
        &by_ordinal[&63],
    );
    assert_eq!(body.facts.source_protocol.as_deref(), Some("h2"));
    assert_eq!(answer.facts.source_protocol.as_deref(), Some("h2"));
    let (_, request_payload) = member(&stores, &run, body).await;
    assert_eq!(request_payload, br#"{"q":"one"}"#);
    let (_, response_payload) = member(&stores, &run, answer).await;
    assert_eq!(response_payload, b"answer one");

    let (warc_headers, block) = member(&stores, &run, headers).await;
    assert!(warc_headers.contains("warc-type: request"), "{warc_headers}");
    assert!(warc_headers.contains("warc-protocol: h2"), "{warc_headers}");
    let message = String::from_utf8(block).unwrap();
    assert_eq!(
        message,
        "POST /search?q=one HTTP/1.1\r\nhost: journal.example.test\r\n\
         content-type: application/json\r\nx-trace: t1\r\n\r\n"
    );
    for leaked in [
        "journal-secret-token",
        "journalsession",
        "content-length",
        "transfer-encoding",
        ":authority",
        "bad_name",
    ] {
        assert!(!message.contains(leaked), "{leaked}: {message}");
    }
    assert_eq!(headers.facts.source_protocol.as_deref(), Some("h2"));
    assert_eq!(
        headers.facts.representation,
        ArchiveRepresentation::NormalizedHttp
    );

    let (warc_headers, block) = member(&stores, &run, protocol).await;
    assert!(warc_headers.contains("warc-type: resource"), "{warc_headers}");
    assert!(String::from_utf8(block).unwrap().starts_with("protocol: h2\r\n"));
    assert_eq!(protocol.facts.source_protocol.as_deref(), Some("h2"));

    // Event 9: no protocol was observed, so none is written anywhere.
    let headers = &by_ordinal[&(9 * 8 + 4 + 2)];
    assert_eq!(headers.facts.source_protocol, None);
    let (warc_headers, block) = member(&stores, &run, headers).await;
    assert!(!warc_headers.contains("warc-protocol"), "{warc_headers}");
    assert_eq!(
        String::from_utf8(block).unwrap(),
        "GET /search?q=one HTTP/1.1\r\naccept: */*\r\n\r\n"
    );
    assert!(!by_ordinal.contains_key(&(9 * 8 + 4 + 3)));

    // Event 11: headers were never persisted: an omission, no record.
    assert!(!by_ordinal.contains_key(&(11 * 8 + 4 + 2)));
    assert!(manifest.omissions.iter().any(|omission| {
        omission.source_event == "traffic:11:request_headers"
            && omission.reason == "request_headers_not_recorded"
    }));

    // The screenshot stays its own sensitive record; nothing above was folded into it.
    let screenshot_record = &by_ordinal[&(1 << 62)];
    assert_eq!(
        screenshot_record.facts.representation,
        ArchiveRepresentation::Screenshot
    );
    assert_eq!(screenshot_record.custody.sensitivity, Sensitivity::Sensitive);
    // Header and protocol records are ordinary content: they never need the screenshot's source.
    assert_eq!(headers.custody.sensitivity, Sensitivity::Content);
    assert_eq!(committed, 2 + 2 + 1);
}
