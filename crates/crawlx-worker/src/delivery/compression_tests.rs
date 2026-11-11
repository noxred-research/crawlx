//! Codec, quota, privacy and actual prepared-feed regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::delivery::tests::{document, run};
use crate::delivery::{
    prepare_article_feeds_inner, prepare_item_feeds, DeliveryAuthority, DeliveryDestination, DeliveryError,
    DeliveryRegistry, HttpDeliveryProtocol, HttpDestination, LocalDestination, S3Destination,
    StdoutDestination,
};
use crate::runtime::CpuPool;
use bytes::Bytes;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::{DatasetConfigV1, DeliveryBatchV1};
use crawlx_core::repo::{ArtifactStore, CrawlRun, RunRepo};
use crawlx_core::secret::ArtifactSink;
use crawlx_core::time::ManualClock;
use crawlx_core::Clock;
use crawlx_storage::artifacts::{ArtifactBlobs, FsArtifactStore, MemBlobs};
use crawlx_storage::MemoryStore;
use reqwest::header::HeaderMap;
use serde_json::{json, Value};
use std::io::Read;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

const CODECS: [FeedCompressionV1; 4] = [
    FeedCompressionV1::None,
    FeedCompressionV1::Gzip,
    FeedCompressionV1::Bzip2,
    FeedCompressionV1::Xz,
];

fn decode(codec: FeedCompressionV1, encoded: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    let reader: Box<dyn Read + '_> = match codec {
        FeedCompressionV1::None => Box::new(encoded),
        FeedCompressionV1::Gzip => Box::new(flate2::read::GzDecoder::new(encoded)),
        FeedCompressionV1::Bzip2 => Box::new(bzip2::read::BzDecoder::new(encoded)),
        FeedCompressionV1::Xz => Box::new(lzma_rust2::XzReader::new(encoded, false)),
        _ => panic!("unknown test codec"),
    };
    reader
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut decoded)
        .unwrap();
    assert!(decoded.len() <= 16 * 1024 * 1024);
    decoded
}

fn encode(codec: FeedCompressionV1, source: &[u8], maximum: usize) -> Result<Redacted<Vec<u8>>, StoreError> {
    encode_approved(Redactor::new().verify_canonical(source)?, codec, maximum)
}

#[test]
fn every_codec_roundtrips_empty_short_and_multichunk_plaintext_deterministically() {
    for source in [
        Vec::new(),
        b"safe feed\n".to_vec(),
        b"bounded streaming feed\n".repeat(8192),
    ] {
        for codec in CODECS {
            let first = encode(codec, &source, 1024 * 1024).unwrap();
            let second = encode(codec, &source, 1024 * 1024).unwrap();
            assert_eq!(first.as_ref(), second.as_ref());
            assert_eq!(decode(codec, first.as_ref()), source);
            if codec == FeedCompressionV1::Gzip {
                assert_eq!(&first.as_ref()[4..8], &[0, 0, 0, 0]);
                assert_eq!(first.as_ref()[9], 255);
            }
        }
    }
}

#[test]
fn none_preserves_owned_buffer_and_all_codecs_enforce_plaintext_and_encoded_limits() {
    let approved = Redactor::new().verify_canonical(b"unchanged").unwrap();
    let allocation = approved.as_ref().as_ptr();
    let result = encode_approved(approved, FeedCompressionV1::None, 9).unwrap();
    assert_eq!(allocation, result.as_ref().as_ptr());
    for codec in CODECS {
        assert!(encode(codec, b"plaintext exceeds cap", 8).is_err());
        if codec != FeedCompressionV1::None {
            assert!(
                encode(codec, b"a", 16).is_err(),
                "framing also consumes output quota"
            );
        }
    }
}

#[test]
fn compression_state_and_binary_approval_copy_require_prior_memory_admission() {
    for codec in CODECS
        .into_iter()
        .filter(|codec| *codec != FeedCompressionV1::None)
    {
        let requested = reservation_bytes(codec, 1024).unwrap();
        assert!(requested > 2048);
        let available = u32::try_from(requested - 1).unwrap();
        let cpu = CpuPool::with_article_output_limit(NonZeroUsize::MIN, NonZeroU32::new(available).unwrap());
        assert!(matches!(
            cpu.try_reserve_article_output(requested),
            Err(StoreError::ResourceExhausted { .. })
        ));
        assert_eq!(
            cpu.article_output_available(),
            usize::try_from(available).unwrap()
        );
    }
    assert!(reservation_bytes(FeedCompressionV1::Xz, usize::MAX).is_err());
    let xz = lzma_rust2::XzOptions::with_preset(0);
    let state = usize::try_from(xz.lzma_options.get_memory_usage())
        .unwrap()
        .checked_mul(1024)
        .unwrap();
    assert!(state < reservation_bytes(FeedCompressionV1::Xz, 0).unwrap());
}

#[test]
fn serde_defaults_to_none_and_rejects_unknown_codecs_or_executable_postprocessors() {
    let feed = json!({"id":"feed","source":"items","serializer":"json","serializerVersion":1,
        "destination":"fixture","maxBatchItems":1,"maxBatchBytes":1048576});
    let base = json!({"stores":[{"name":"items","schemaVersion":"document_item_v1",
        "maxItems":10,"maxBytes":1048576}],"feeds":[feed]});
    let default: DatasetConfigV1 = serde_json::from_value(base.clone()).unwrap();
    default.validate().unwrap();
    assert_eq!(default.feeds[0].compression, FeedCompressionV1::None);
    for codec in ["none", "gzip", "bzip2", "xz"] {
        let mut config = base.clone();
        config["feeds"][0]["compression"] = json!(codec);
        let declaration: DatasetConfigV1 = serde_json::from_value(config).unwrap();
        declaration.validate().unwrap();
    }
    for codec in ["custom", "lzma", "bz2", "plugin.module"] {
        let mut config = base.clone();
        config["feeds"][0]["compression"] = json!(codec);
        assert!(serde_json::from_value::<DatasetConfigV1>(config).is_err());
    }
    for field in ["postprocessor", "postprocessors", "plugins"] {
        let mut config = base.clone();
        config["feeds"][0][field] = json!(["custom.module"]);
        assert!(serde_json::from_value::<DatasetConfigV1>(config).is_err());
    }
    assert_eq!(
        media_type(FeedCompressionV1::None, "application/json").unwrap(),
        "application/json"
    );
    assert_eq!(
        media_type(FeedCompressionV1::Gzip, "application/json").unwrap(),
        "application/gzip"
    );
    assert_eq!(
        media_type(FeedCompressionV1::Bzip2, "application/json").unwrap(),
        "application/x-bzip2"
    );
    assert_eq!(
        media_type(FeedCompressionV1::Xz, "application/json").unwrap(),
        "application/x-xz"
    );
}

#[tokio::test]
async fn actual_article_manifests_reference_compressed_approved_serializer_bytes() {
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
    ));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(directory.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let mut run = run(RetentionMode::Standard, clock.now(), &["json"]);
    let declaration = run.config.datasets.feeds[0].clone();
    run.config.datasets.feeds = CODECS
        .iter()
        .enumerate()
        .map(|(index, codec)| {
            let mut feed = declaration.clone();
            feed.id = format!("codec_{index}");
            feed.compression = *codec;
            feed
        })
        .collect();
    run.config.datasets.validate().unwrap();
    repo.create(&run, None).await.unwrap();
    let cpu = CpuPool::default();
    let (_, batches) = prepare_article_feeds_inner(
        &artifacts,
        &cpu,
        &run,
        1,
        "articles",
        Box::new(document(200).await),
        true,
        None,
        "https://fixture.test/article",
    )
    .await
    .unwrap();
    assert_eq!(batches.len(), CODECS.len());
    let plain = artifacts.get(batches[0].content.artifact()).await.unwrap();
    assert!(serde_json::from_slice::<Value>(&plain).unwrap().is_array());
    for (batch, codec) in batches.iter().zip(CODECS) {
        let encoded = artifacts.get(batch.content.artifact()).await.unwrap();
        assert_eq!(batch.size_bytes, u64::try_from(encoded.len()).unwrap());
        assert_eq!(decode(codec, &encoded), plain.as_slice());
        assert!(batch.expires_at <= run.created_at + chrono::Duration::days(1));
    }
}

#[tokio::test]
async fn actual_generic_json_jsonl_csv_xml_feeds_frame_before_compression() {
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
    ));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(directory.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let mut run = run(RetentionMode::Standard, clock.now(), &[]);
    let mut feeds = Vec::new();
    for serializer in ["json", "jsonl", "csv", "xml"] {
        for (index, codec) in CODECS.iter().enumerate() {
            feeds.push(
                json!({"id":format!("{serializer}_{index}"),"source":"items","serializer":serializer,
                "compression":codec,"serializerVersion":1,"destination":"fixture",
                "maxBatchItems":1,"maxBatchBytes":1048576}),
            );
        }
    }
    run.config.datasets = serde_json::from_value(json!({"stores":[{"name":"items",
        "schemaVersion":"document_item_v1","maxItems":10,"maxBytes":16777216}],"feeds":feeds}))
    .unwrap();
    run.config.datasets.validate().unwrap();
    repo.create(&run, None).await.unwrap();
    let original = b"{\"title\":\"A safe item\",\"count\":7}\n";
    let approved = Redactor::new().verify_canonical(original).unwrap();
    let reference = ArtifactSink::over(&artifacts)
        .put_dataset(run.id, 1, "original_item", "application/json", &approved)
        .await
        .unwrap();
    let cpu = CpuPool::default();
    let batches = prepare_item_feeds(&artifacts, &cpu, &run, 1, "items", &reference, approved)
        .await
        .unwrap();
    assert_eq!(batches.len(), 16);
    let value: Value = serde_json::from_slice(original).unwrap();
    for batch in batches {
        let declaration = run
            .config
            .datasets
            .feeds
            .iter()
            .find(|feed| feed.id == batch.feed)
            .unwrap();
        let encoded = artifacts.get(batch.content.artifact()).await.unwrap();
        assert_eq!(batch.size_bytes, u64::try_from(encoded.len()).unwrap());
        if declaration.compression == FeedCompressionV1::None
            && matches!(declaration.serializer.as_str(), "json" | "jsonl")
        {
            assert_eq!(batch.content.artifact(), &reference);
            continue;
        }
        let format = match declaration.serializer.as_str() {
            "json" => crawlx_extract::serialize::ItemFormat::Json,
            "jsonl" => crawlx_extract::serialize::ItemFormat::Jsonl,
            "csv" => crawlx_extract::serialize::ItemFormat::Csv,
            _ => crawlx_extract::serialize::ItemFormat::Xml,
        };
        let mut expected = Vec::new();
        crawlx_extract::serialize::write_item(&mut expected, &value, format).unwrap();
        let decoded = decode(declaration.compression, &encoded);
        assert_eq!(decoded, expected);
        if declaration.serializer == "jsonl" {
            assert_eq!(decoded.last(), Some(&b'\n'));
        }
        assert_eq!(batch.expires_at, run.created_at + chrono::Duration::days(1));
    }
}

#[tokio::test]
async fn actual_article_compression_refuses_unapproved_plaintext_before_artifact_write() {
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
    ));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(directory.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let mut run = run(RetentionMode::Standard, clock.now(), &["json"]);
    let secret = "feedCompressionPlaintextCanary581";
    assert!(crawlx_core::secret::register_secret(secret));
    repo.create(&run, None).await.unwrap();
    let cpu = CpuPool::default();
    for codec in CODECS {
        run.config.datasets.feeds[0].compression = codec;
        let mut source = document(200).await;
        source.article.as_mut().unwrap().metadata.title.value = Some(secret.into());
        let result = prepare_article_feeds_inner(
            &artifacts,
            &cpu,
            &run,
            1,
            "articles",
            Box::new(source),
            true,
            None,
            "https://fixture.test/article",
        )
        .await;
        assert!(matches!(result, Err(StoreError::RetentionDenied(_))));
    }
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn actual_generic_preparation_refuses_encoded_framing_over_batch_cap() {
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
    ));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(directory.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let mut run = run(RetentionMode::Standard, clock.now(), &[]);
    run.config.datasets = serde_json::from_value(json!({"stores":[{"name":"items",
        "schemaVersion":"document_item_v1","maxItems":10,"maxBytes":1048576}],
        "feeds":[{"id":"tiny","source":"items","serializer":"json","serializerVersion":1,
        "destination":"fixture","maxBatchItems":1,"maxBatchBytes":2}]}))
    .unwrap();
    repo.create(&run, None).await.unwrap();
    let approved = Redactor::new().verify_canonical(b"{}").unwrap();
    let reference = ArtifactSink::over(&artifacts)
        .put_dataset(run.id, 1, "original_item", "application/json", &approved)
        .await
        .unwrap();
    let cpu = CpuPool::default();
    for codec in CODECS
        .into_iter()
        .filter(|codec| *codec != FeedCompressionV1::None)
    {
        run.config.datasets.feeds[0].compression = codec;
        assert!(prepare_item_feeds(
            &artifacts,
            &cpu,
            &run,
            1,
            "items",
            &reference,
            Redactor::new().verify_canonical_owned(b"{}".to_vec()).unwrap()
        )
        .await
        .is_err());
    }
}

#[tokio::test]
async fn structured_sink_compression_is_refused_at_admission_before_loopback_requests() {
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&collector)
        .await;
    let endpoint: url::Url = collector.uri().parse().unwrap();
    let now = chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap();
    let mut run = run(RetentionMode::Standard, now, &["json"]);
    for protocol in [
        HttpDeliveryProtocol::SearchUpdate,
        HttpDeliveryProtocol::SearchIndex,
        HttpDeliveryProtocol::StreamRestV2,
        HttpDeliveryProtocol::QueueHttpV1,
    ] {
        let sink = HttpDestination::approved(
            endpoint.clone(),
            &[*collector.address()],
            HeaderMap::new(),
            protocol,
            false,
        )
        .unwrap();
        assert!(!sink.permits_feed_compression());
        let mut registry = DeliveryRegistry::new();
        registry.register("fixture".into(), Arc::new(sink)).unwrap();
        run.config.datasets.feeds[0].compression = FeedCompressionV1::None;
        registry.validate(&run).unwrap();
        for codec in CODECS
            .into_iter()
            .filter(|codec| *codec != FeedCompressionV1::None)
        {
            run.config.datasets.feeds[0].compression = codec;
            assert!(matches!(
                registry.validate(&run),
                Err(DeliveryError::Unavailable(
                    "feed_compression_unsupported_for_sink"
                ))
            ));
        }
    }
    assert!(collector.received_requests().await.unwrap().is_empty());
}

struct RawFeedFixture {
    _directory: tempfile::TempDir,
    artifacts: FsArtifactStore,
    run: CrawlRun,
    batches: Vec<DeliveryBatchV1>,
    authority: DeliveryAuthority,
}

async fn raw_feed_fixture(endpoint: url::Url) -> RawFeedFixture {
    let clock = Arc::new(ManualClock::new(
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
    ));
    let repo = Arc::new(MemoryStore::with_clock(clock.clone()));
    let directory = tempfile::tempdir().unwrap();
    let artifacts = FsArtifactStore::open(directory.path(), repo.clone(), clock.clone())
        .await
        .unwrap();
    let mut run = run(RetentionMode::Standard, clock.now(), &["json"]);
    let declaration = run.config.datasets.feeds[0].clone();
    run.config.datasets.feeds = CODECS
        .iter()
        .enumerate()
        .map(|(index, codec)| {
            let mut feed = declaration.clone();
            feed.id = format!("raw_codec_{index}");
            feed.compression = *codec;
            feed
        })
        .collect();
    run.config.seed_url = endpoint.clone();
    run.config.safety.allow_private_networks = true;
    let address: std::net::IpAddr = endpoint.host_str().unwrap().parse().unwrap();
    let mut config = crate::WorkerConfig::default();
    config
        .egress
        .extra_allow
        .push(format!("{address}/32").parse().unwrap());
    let authority = DeliveryAuthority {
        policy: Arc::new(config.egress.policy_for_run(&run.config, None)),
        resolver: Arc::new(crawlx_fetch::StaticResolver::new().with(endpoint.host_str().unwrap(), [address])),
        governor: Arc::new(crawlx_fetch::OriginGovernor::new(
            crawlx_fetch::GovernorConfig::from_politeness(&run.config.politeness, run.seed),
        )),
        cancel: CancellationToken::new(),
    };
    repo.create(&run, None).await.unwrap();
    let (_, batches) = prepare_article_feeds_inner(
        &artifacts,
        &CpuPool::default(),
        &run,
        1,
        "articles",
        Box::new(document(200).await),
        true,
        None,
        "https://fixture.test/article",
    )
    .await
    .unwrap();
    RawFeedFixture {
        _directory: directory,
        artifacts,
        run,
        batches,
        authority,
    }
}

#[tokio::test]
async fn raw_http_local_and_object_sinks_preserve_each_encoded_feed_artifact() {
    let collector = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(4)
        .mount(&collector)
        .await;
    let fixture = raw_feed_fixture(collector.uri().parse().unwrap()).await;
    let http = Arc::new(
        HttpDestination::approved(
            collector.uri().parse().unwrap(),
            &[*collector.address()],
            HeaderMap::new(),
            HttpDeliveryProtocol::Http,
            false,
        )
        .unwrap(),
    );
    let local_root = tempfile::tempdir().unwrap();
    let local = Arc::new(LocalDestination::open(local_root.path()).await.unwrap());
    let blobs = Arc::new(MemBlobs::default());
    let object = Arc::new(S3Destination::new(blobs.clone(), "feeds".into()).unwrap());
    for sink in [
        http.clone() as Arc<dyn DeliveryDestination>,
        local.clone() as Arc<dyn DeliveryDestination>,
        object.clone() as Arc<dyn DeliveryDestination>,
        Arc::new(StdoutDestination::new(false)) as Arc<dyn DeliveryDestination>,
    ] {
        let mut registry = DeliveryRegistry::new();
        registry.register("fixture".into(), sink).unwrap();
        registry.validate(&fixture.run).unwrap();
    }
    let plaintext = fixture
        .artifacts
        .get(fixture.batches[0].content.artifact())
        .await
        .unwrap();
    for (batch, codec) in fixture.batches.iter().zip(CODECS) {
        let encoded = fixture.artifacts.get(batch.content.artifact()).await.unwrap();
        let bytes = Bytes::from(encoded.clone());
        http.send(&fixture.authority, &fixture.run, batch, bytes.clone())
            .await
            .unwrap();
        local
            .send(&fixture.authority, &fixture.run, batch, bytes.clone())
            .await
            .unwrap();
        object
            .send(&fixture.authority, &fixture.run, batch, bytes)
            .await
            .unwrap();
        let local_name = format!(
            "{}.{}.{}",
            fixture.run.id,
            batch.idempotency_key,
            batch.content.artifact().digest.to_hex()
        );
        let local_bytes = tokio::fs::read(local_root.path().join(local_name)).await.unwrap();
        assert_eq!(local_bytes, encoded);
        assert_eq!(decode(codec, &local_bytes), plaintext);
        let object_key = format!(
            "feeds/{}/{}/{}/{}",
            fixture.run.tenant,
            fixture.run.id,
            batch.idempotency_key,
            batch.content.artifact().digest.to_hex()
        );
        let object_bytes = blobs.get(&object_key).await.unwrap().unwrap();
        assert_eq!(object_bytes, encoded);
        assert_eq!(decode(codec, &object_bytes), plaintext);
    }
    let requests = collector.received_requests().await.unwrap();
    assert_eq!(requests.len(), CODECS.len());
    for ((request, batch), codec) in requests.iter().zip(&fixture.batches).zip(CODECS) {
        let encoded = fixture.artifacts.get(batch.content.artifact()).await.unwrap();
        assert_eq!(request.body, encoded);
        assert_eq!(decode(codec, &request.body), plaintext);
        assert!(!request.headers.contains_key("content-encoding"));
    }
}

#[tokio::test]
async fn stdout_sink_writes_compressed_artifacts_without_transformation() {
    const CHILD: &str = "CRAWLX_TEST_COMPRESSED_STDOUT_CHILD";
    const FRAME: &[u8] = b"\ncompressed_feed_frame_v1\n";
    if std::env::var_os(CHILD).is_some() {
        let fixture = raw_feed_fixture("http://127.0.0.1/".parse().unwrap()).await;
        let sink = StdoutDestination::new(false);
        for batch in &fixture.batches {
            let encoded = fixture.artifacts.get(batch.content.artifact()).await.unwrap();
            {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(FRAME).unwrap();
                stdout
                    .write_all(&u32::try_from(encoded.len()).unwrap().to_le_bytes())
                    .unwrap();
                stdout.flush().unwrap();
            }
            sink.send(&fixture.authority, &fixture.run, batch, Bytes::from(encoded))
                .await
                .unwrap();
        }
        return;
    }
    // Isolate actual stdout from the test harness and parallel tests without replacing the sink.
    let output = tokio::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "delivery::compression::tests::stdout_sink_writes_compressed_artifacts_without_transformation",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "stdout child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut remaining = output.stdout.as_slice();
    let mut plaintext = None;
    for codec in CODECS {
        let start = remaining
            .windows(FRAME.len())
            .position(|window| window == FRAME)
            .unwrap();
        remaining = &remaining[start + FRAME.len()..];
        let length = usize::try_from(u32::from_le_bytes(remaining[..4].try_into().unwrap())).unwrap();
        remaining = &remaining[4..];
        let decoded = decode(codec, &remaining[..length]);
        if let Some(expected) = &plaintext {
            assert_eq!(&decoded, expected);
        } else {
            assert!(serde_json::from_slice::<Value>(&decoded).unwrap().is_array());
            plaintext = Some(decoded);
        }
        remaining = &remaining[length..];
    }
}
