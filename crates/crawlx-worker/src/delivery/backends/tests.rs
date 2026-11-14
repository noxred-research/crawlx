//! The infrastructure sinks against real services. Each test reads its endpoint from
//! `CRAWLX_TEST_*` (see `ci/backend-services.sh`) and returns early without it. Names are unique
//! per run, so tests share an instance with anything else on it, and every test removes what it
//! created.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::amqp::{connection_uri, AmqpDestination, AmqpSettings};
use super::clickhouse::ClickHouseDestination;
use super::http::InfraHttp;
use super::kafka::{KafkaDestination, KafkaSettings};
use super::search::{SearchDestination, SearchEngine};
use crate::delivery::tests::run;
use crate::delivery::{DeliveryAuthority, DeliveryDestination, DeliveryError};
use bytes::Bytes;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::{DatasetContentV1, DeliveryBatchV1};
use crawlx_core::hash::Digest;
use crawlx_core::repo::CrawlRun;
use crawlx_core::{ArtifactId, ArtifactRef};
use reqwest::header::HeaderMap;
use reqwest::Method;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use url::Url;

fn unique() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
}

fn authority(run: &CrawlRun) -> DeliveryAuthority {
    let config = crate::WorkerConfig::default();
    DeliveryAuthority {
        policy: Arc::new(config.egress.policy_for_run(&run.config, None).unwrap()),
        resolver: Arc::new(crawlx_fetch::StaticResolver::new()),
        governor: Arc::new(crawlx_fetch::OriginGovernor::new(
            crawlx_fetch::GovernorConfig::from_politeness(&run.config.politeness, run.seed),
        )),
        cancel: CancellationToken::new(),
    }
}

fn batch(key: &str, bytes: &[u8]) -> DeliveryBatchV1 {
    DeliveryBatchV1::for_request(
        "feed".to_owned(),
        key.to_owned(),
        DatasetContentV1::Durable {
            artifact: ArtifactRef {
                id: ArtifactId::new(),
                digest: Digest::of("test", bytes),
            },
        },
        bytes.len() as u64,
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
}

fn standard_run() -> CrawlRun {
    run(RetentionMode::Standard, chrono::Utc::now(), &["json"])
}

fn projection(id: &str, deleted: bool, title: &str) -> Bytes {
    let mut value = json!({
        "version": 1, "documentId": id, "parentId": null, "deleted": deleted,
        "extractorVersion": "test-1", "fields": {},
    });
    if !deleted {
        value["fields"] = json!({"title": title, "kind": "page"});
    }
    Bytes::from(serde_json::to_vec(&value).unwrap())
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

// ---- search ------------------------------------------------------------------------------------

async fn search_cycle(url: &str, engine: SearchEngine, other_engine: SearchEngine) {
    let endpoint: Url = url.parse().unwrap();
    let id = unique();
    let (prefix_a, prefix_b) = (format!("crawlxa{id}-"), format!("crawlxb{id}-"));
    let a = SearchDestination::new(endpoint.clone(), HeaderMap::new(), engine, &prefix_a, "pages").unwrap();
    let b = SearchDestination::new(endpoint.clone(), HeaderMap::new(), engine, &prefix_b, "pages").unwrap();
    let run = standard_run();
    let authority = authority(&run);
    let batch = batch("k1", b"x");
    a.send(&authority, &run, &batch, projection("doc-1", false, "first"))
        .await
        .unwrap();
    b.send(&authority, &run, &batch, projection("doc-2", false, "second"))
        .await
        .unwrap();
    // the same id again is an overwrite, not a second document
    a.send(
        &authority,
        &run,
        &batch,
        projection("doc-1", false, "first again"),
    )
    .await
    .unwrap();
    let admin = InfraHttp::new(endpoint.clone(), HeaderMap::new()).unwrap();
    let get = |path: String| {
        let admin = &admin;
        async move {
            admin
                .send(Method::GET, &path, &[], None, Bytes::new())
                .await
                .unwrap()
        }
    };
    for prefix in [&prefix_a, &prefix_b] {
        admin
            .send(
                Method::POST,
                &format!("/{prefix}pages/_refresh"),
                &[],
                None,
                Bytes::new(),
            )
            .await
            .unwrap();
    }
    let count = |prefix: &str| {
        let path = format!("/{prefix}pages/_count");
        let get = &get;
        async move { get(path).await.json().unwrap()["count"].as_u64().unwrap() }
    };
    assert_eq!(count(&prefix_a).await, 1, "an overwrite keeps one document");
    assert_eq!(count(&prefix_b).await, 1);
    let doc = get(format!("/{prefix_a}pages/_doc/doc-1")).await.json().unwrap();
    assert_eq!(doc["_source"]["title"], "first again");
    assert_eq!(
        get(format!("/{prefix_a}pages/_doc/doc-2")).await.status,
        404,
        "B's document is not in A's index"
    );
    // exactly our prefix's indices exist under it, and the template covers exactly that prefix
    let indices = admin
        .send(
            Method::GET,
            &format!("/_cat/indices/{prefix_a}*"),
            &[("format", "json")],
            None,
            Bytes::new(),
        )
        .await
        .unwrap()
        .json()
        .unwrap();
    let names: Vec<&str> = indices
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["index"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec![format!("{prefix_a}pages")]);
    let template = get(format!("/_index_template/{prefix_a}crawlx"))
        .await
        .json()
        .unwrap();
    assert_eq!(
        template
            .pointer("/index_templates/0/index_template/index_patterns/0")
            .and_then(Value::as_str),
        Some(format!("{prefix_a}*").as_str())
    );
    assert_eq!(
        template.pointer("/index_templates/0/index_template/_meta/crawlx_template_version"),
        Some(&json!(1))
    );
    // a tombstone deletes one document and nothing else
    a.send(&authority, &run, &batch, projection("doc-1", true, ""))
        .await
        .unwrap();
    admin
        .send(
            Method::POST,
            &format!("/{prefix_a}pages/_refresh"),
            &[],
            None,
            Bytes::new(),
        )
        .await
        .unwrap();
    assert_eq!(count(&prefix_a).await, 0);
    assert_eq!(count(&prefix_b).await, 1, "B is untouched");
    // deleting a document that is not there is acknowledged
    a.send(&authority, &run, &batch, projection("never-existed", true, ""))
        .await
        .unwrap();
    // an endpoint of the other engine kind is refused before anything is written
    let mismatched =
        SearchDestination::new(endpoint, HeaderMap::new(), other_engine, &prefix_a, "pages").unwrap();
    let error = mismatched
        .send(&authority, &run, &batch, projection("x", false, "x"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, DeliveryError::Unavailable("search_engine_mismatch")),
        "{error:?}"
    );
    // zero-data-retention content never reaches a search index
    let zdr = run_zdr();
    let error = a
        .send(&authority, &zdr, &batch, projection("z", false, "z"))
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        DeliveryError::Unavailable("search_persistence_forbidden_in_zdr")
    ));
    // a payload that is not a search projection is rejected
    let error = a
        .send(&authority, &run, &batch, Bytes::from_static(b"{\"nope\":1}"))
        .await
        .unwrap_err();
    assert!(
        matches!(error, DeliveryError::Rejected("search_projection_required")),
        "{error:?}"
    );
    for prefix in [&prefix_a, &prefix_b] {
        admin
            .send(
                Method::DELETE,
                &format!("/{prefix}pages"),
                &[],
                None,
                Bytes::new(),
            )
            .await
            .unwrap();
        admin
            .send(
                Method::DELETE,
                &format!("/_index_template/{prefix}crawlx"),
                &[],
                None,
                Bytes::new(),
            )
            .await
            .unwrap();
    }
}

fn run_zdr() -> CrawlRun {
    run(RetentionMode::Zdr, chrono::Utc::now(), &["json"])
}

#[tokio::test]
async fn opensearch_indexes_under_its_prefix_and_shares_the_instance() {
    let Some(url) = env("CRAWLX_TEST_OPENSEARCH_URL") else {
        eprintln!("skipped: CRAWLX_TEST_OPENSEARCH_URL is not set");
        return;
    };
    search_cycle(&url, SearchEngine::OpenSearch, SearchEngine::Elasticsearch).await;
}

#[tokio::test]
async fn elasticsearch_indexes_under_its_prefix_and_shares_the_instance() {
    let Some(url) = env("CRAWLX_TEST_ELASTICSEARCH_URL") else {
        eprintln!("skipped: CRAWLX_TEST_ELASTICSEARCH_URL is not set");
        return;
    };
    search_cycle(&url, SearchEngine::Elasticsearch, SearchEngine::OpenSearch).await;
}

#[tokio::test]
async fn an_unreachable_search_endpoint_asks_for_a_retry() {
    let sink = SearchDestination::new(
        "http://127.0.0.1:1".parse().unwrap(),
        HeaderMap::new(),
        SearchEngine::OpenSearch,
        "crawlx-",
        "pages",
    )
    .unwrap();
    let run = standard_run();
    let error = sink
        .send(
            &authority(&run),
            &run,
            &batch("k", b"x"),
            projection("d", false, "t"),
        )
        .await
        .unwrap_err();
    assert!(matches!(error, DeliveryError::Http(_)), "{error:?}");
}

// ---- ClickHouse --------------------------------------------------------------------------------

#[tokio::test]
async fn clickhouse_migrates_deduplicates_and_keeps_databases_apart() {
    let Some(url) = env("CRAWLX_TEST_CLICKHOUSE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_CLICKHOUSE_URL is not set");
        return;
    };
    let endpoint: Url = url.parse().unwrap();
    let id = unique();
    let (db_a, db_b) = (format!("crawlx_a_{id}"), format!("crawlx_b_{id}"));
    let a = ClickHouseDestination::new(endpoint.clone(), HeaderMap::new(), &db_a, "pages").unwrap();
    let b = ClickHouseDestination::new(endpoint.clone(), HeaderMap::new(), &db_b, "pages").unwrap();
    let run = standard_run();
    let authority = authority(&run);
    let payload = b"{\"title\":\"hello\"}\n{\"title\":\"caf\xc3\xa9\"}\n";
    a.send(
        &authority,
        &run,
        &batch("key-1", payload),
        Bytes::from_static(payload),
    )
    .await
    .unwrap();
    // a retried batch (same key) is dropped by the deduplication window; a new key is stored
    a.send(
        &authority,
        &run,
        &batch("key-1", payload),
        Bytes::from_static(payload),
    )
    .await
    .unwrap();
    a.send(
        &authority,
        &run,
        &batch("key-2", payload),
        Bytes::from_static(payload),
    )
    .await
    .unwrap();
    b.send(
        &authority,
        &run,
        &batch("key-1", payload),
        Bytes::from_static(payload),
    )
    .await
    .unwrap();
    let admin = InfraHttp::new(endpoint, HeaderMap::new()).unwrap();
    let query = |sql: String| {
        let admin = &admin;
        async move {
            let reply = admin
                .send(Method::POST, "/", &[], Some("text/plain"), Bytes::from(sql))
                .await
                .unwrap();
            assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
            String::from_utf8_lossy(&reply.body).trim().to_owned()
        }
    };
    assert_eq!(
        query(format!("SELECT count() FROM {db_a}.pages FORMAT TabSeparated")).await,
        "2"
    );
    assert_eq!(
        query(format!("SELECT count() FROM {db_b}.pages FORMAT TabSeparated")).await,
        "1"
    );
    assert_eq!(
        query(format!(
            "SELECT payload FROM {db_a}.pages WHERE batch_key = 'key-1' FORMAT TabSeparated"
        ))
        .await
        .replace("\\n", "\n")
        .trim_end(),
        String::from_utf8(payload.to_vec()).unwrap().trim_end()
    );
    assert_eq!(
        query(format!("SELECT run_id, feed, length(content_digest) FROM {db_a}.pages WHERE batch_key = 'key-2' FORMAT TabSeparated")).await,
        format!("{}\tfeed\t64", run.id.0)
    );
    // migrations ran once per database and are recorded in that database
    assert_eq!(
        query(format!(
            "SELECT table_name, version, name FROM {db_a}.crawlx_migrations FORMAT TabSeparated"
        ))
        .await,
        "pages\t1\tcreate_feed_table"
    );
    // a fresh sink on an existing database does not migrate again
    let second = ClickHouseDestination::new(
        env("CRAWLX_TEST_CLICKHOUSE_URL").unwrap().parse().unwrap(),
        HeaderMap::new(),
        &db_a,
        "pages",
    )
    .unwrap();
    second
        .send(
            &authority,
            &run,
            &batch("key-3", payload),
            Bytes::from_static(payload),
        )
        .await
        .unwrap();
    assert_eq!(
        query(format!(
            "SELECT count() FROM {db_a}.crawlx_migrations FORMAT TabSeparated"
        ))
        .await,
        "1"
    );
    // binary payloads and zero-data-retention runs are refused
    let error = a
        .send(
            &authority,
            &run,
            &batch("bin", b"x"),
            Bytes::from_static(&[0xff, 0xfe]),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(error, DeliveryError::Rejected("clickhouse_payload_not_utf8")),
        "{error:?}"
    );
    let error = a
        .send(
            &authority,
            &run_zdr(),
            &batch("z", b"x"),
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        DeliveryError::Unavailable("clickhouse_persistence_forbidden_in_zdr")
    ));
    for db in [&db_a, &db_b] {
        query(format!("DROP DATABASE IF EXISTS {db}")).await;
    }
}

#[tokio::test]
async fn clickhouse_keeps_the_batches_of_runs_and_deployments_sharing_a_table() {
    let Some(url) = env("CRAWLX_TEST_CLICKHOUSE_URL") else {
        eprintln!("skipped: CRAWLX_TEST_CLICKHOUSE_URL is not set");
        return;
    };
    let endpoint: Url = url.parse().unwrap();
    let db = format!("crawlx_s_{}", unique());
    // two deployments (two sink instances, as two processes would be) feed ONE table
    let one = ClickHouseDestination::new(endpoint.clone(), HeaderMap::new(), &db, "pages").unwrap();
    let two = ClickHouseDestination::new(endpoint.clone(), HeaderMap::new(), &db, "pages").unwrap();
    // each deployment runs twice; request ids restart at 1 in every deployment, so the batch keys
    // repeat across all four runs
    let runs = [standard_run(), standard_run(), standard_run(), standard_run()];
    let authority = authority(&runs[0]);
    let payload = b"{\"title\":\"hello\"}\n";
    for (index, run) in runs.iter().enumerate() {
        let sink = if index < 2 { &one } else { &two };
        for key in ["request.1.f", "request.2.f", "request.3.f"] {
            sink.send(&authority, run, &batch(key, payload), Bytes::from_static(payload))
                .await
                .unwrap();
        }
    }
    // a retry of one batch from its own deployment and run is still dropped by the window
    one.send(
        &authority,
        &runs[0],
        &batch("request.2.f", payload),
        Bytes::from_static(payload),
    )
    .await
    .unwrap();
    let admin = InfraHttp::new(endpoint, HeaderMap::new()).unwrap();
    let query = |sql: String| {
        let admin = &admin;
        async move {
            let reply = admin
                .send(Method::POST, "/", &[], Some("text/plain"), Bytes::from(sql))
                .await
                .unwrap();
            assert_eq!(reply.status, 200, "{}", String::from_utf8_lossy(&reply.body));
            String::from_utf8_lossy(&reply.body).trim().to_owned()
        }
    };
    assert_eq!(
        query(format!("SELECT count() FROM {db}.pages FORMAT TabSeparated")).await,
        "12",
        "every batch of every run arrives, the retried one only once"
    );
    assert_eq!(
        query(format!(
            "SELECT uniqExact(run_id) FROM {db}.pages FORMAT TabSeparated"
        ))
        .await,
        "4"
    );
    query(format!("DROP DATABASE IF EXISTS {db}")).await;
}

// ---- Kafka -------------------------------------------------------------------------------------

#[tokio::test]
async fn kafka_produces_to_prefixed_topics_and_keeps_deployments_apart() {
    use rskafka::client::partition::{OffsetAt, UnknownTopicHandling};
    use rskafka::client::ClientBuilder;
    let Some(brokers) = env("CRAWLX_TEST_KAFKA_BROKERS") else {
        eprintln!("skipped: CRAWLX_TEST_KAFKA_BROKERS is not set");
        return;
    };
    let brokers: Vec<String> = brokers.split(',').map(str::to_owned).collect();
    let id = unique();
    let (topic_a, topic_b) = (format!("crawlxa{id}.pages"), format!("crawlxb{id}.pages"));
    let settings = |topic: &str| KafkaSettings {
        brokers: brokers.clone(),
        topic: topic.to_owned(),
        tls: false,
        sasl: None,
        partitions: 2,
        replication_factor: 1,
    };
    let a = KafkaDestination::new(settings(&topic_a)).unwrap();
    let b = KafkaDestination::new(settings(&topic_b)).unwrap();
    let run = standard_run();
    let authority = authority(&run);
    a.send(
        &authority,
        &run,
        &batch("batch-a", b"payload-a"),
        Bytes::from_static(b"payload-a"),
    )
    .await
    .unwrap();
    b.send(
        &authority,
        &run,
        &batch("batch-b", b"payload-b"),
        Bytes::from_static(b"payload-b"),
    )
    .await
    .unwrap();
    let client = ClientBuilder::new(brokers.clone()).build().await.unwrap();
    let topics = client.list_topics().await.unwrap();
    let ours = topics.iter().find(|t| t.name == topic_a).expect("topic A exists");
    assert_eq!(
        ours.partitions.len(),
        2,
        "the sink created the topic with its partitions"
    );
    let mut seen = Vec::new();
    for partition in ours.partitions.iter().copied() {
        let pc = client
            .partition_client(topic_a.clone(), partition, UnknownTopicHandling::Error)
            .await
            .unwrap();
        let end = pc.get_offset(OffsetAt::Latest).await.unwrap();
        if end > 0 {
            let (records, _) = pc.fetch_records(0, 1..1_000_000, 2_000).await.unwrap();
            seen.extend(records.into_iter().map(|r| r.record));
        }
    }
    assert_eq!(seen.len(), 1, "exactly the one record of A");
    let record = &seen[0];
    assert_eq!(
        record.key.as_deref(),
        Some(super::scoped_batch_id(&run, &batch("batch-a", b"payload-a")).as_bytes())
    );
    assert_eq!(record.headers["crawlx-batch"], b"batch-a");
    assert_eq!(record.value.as_deref(), Some(&b"payload-a"[..]));
    assert_eq!(record.headers["crawlx-feed"], b"feed");
    assert_eq!(record.headers["crawlx-run"], run.id.0.to_string().into_bytes());
    // B's record never appears in A's topic, and a retry of the same batch is a second record
    a.send(
        &authority,
        &run,
        &batch("batch-a", b"payload-a"),
        Bytes::from_static(b"payload-a"),
    )
    .await
    .unwrap();
    assert!(a.duplicate_possible(), "the sink says a retry can duplicate");
    let mut total = 0;
    for partition in ours.partitions.iter().copied() {
        let pc = client
            .partition_client(topic_a.clone(), partition, UnknownTopicHandling::Error)
            .await
            .unwrap();
        total += pc.get_offset(OffsetAt::Latest).await.unwrap();
    }
    assert_eq!(total, 2);
    // an unreachable broker asks for a retry instead of failing the batch for good
    let down = KafkaDestination::new(KafkaSettings {
        brokers: vec!["127.0.0.1:1".to_owned()],
        ..settings(&topic_a)
    })
    .unwrap();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        down.send(&authority, &run, &batch("x", b"x"), Bytes::from_static(b"x")),
    )
    .await
    .expect("the failure is bounded")
    .unwrap_err();
    assert!(matches!(error, DeliveryError::ProviderBackoff(_)), "{error:?}");
    let error = a
        .send(
            &authority,
            &run_zdr(),
            &batch("z", b"x"),
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        DeliveryError::Unavailable("kafka_persistence_forbidden_in_zdr")
    ));
}

// ---- RabbitMQ ----------------------------------------------------------------------------------

#[tokio::test]
async fn rabbitmq_publishes_with_confirms_to_prefixed_queues() {
    use lapin::options::{BasicGetOptions, ExchangeDeleteOptions, QueueDeleteOptions};
    use lapin::{Connection, ConnectionProperties};
    let (Some(url), Some(user), Some(password)) = (
        env("CRAWLX_TEST_AMQP_URL"),
        env("CRAWLX_TEST_AMQP_USER"),
        env("CRAWLX_TEST_AMQP_PASSWORD"),
    ) else {
        eprintln!("skipped: CRAWLX_TEST_AMQP_URL is not set");
        return;
    };
    let endpoint: Url = url.parse().unwrap();
    let login = (user, password);
    let id = unique();
    let (name_a, name_b) = (format!("crawlxa{id}.pages"), format!("crawlxb{id}.pages"));
    let sink = |name: &str| {
        AmqpDestination::new(AmqpSettings {
            uri: connection_uri(&endpoint, Some(&login)).unwrap(),
            exchange: name.to_owned(),
            queue: name.to_owned(),
        })
        .unwrap()
    };
    let (a, b) = (sink(&name_a), sink(&name_b));
    let run = standard_run();
    let authority = authority(&run);
    a.send(
        &authority,
        &run,
        &batch("key-a", b"payload-a"),
        Bytes::from_static(b"payload-a"),
    )
    .await
    .unwrap();
    a.send(
        &authority,
        &run,
        &batch("key-a2", b"payload-a2"),
        Bytes::from_static(b"payload-a2"),
    )
    .await
    .unwrap();
    b.send(
        &authority,
        &run,
        &batch("key-b", b"payload-b"),
        Bytes::from_static(b"payload-b"),
    )
    .await
    .unwrap();
    let connection = Connection::connect(
        &connection_uri(&endpoint, Some(&login)).unwrap(),
        ConnectionProperties::default(),
    )
    .await
    .unwrap();
    let channel = connection.create_channel().await.unwrap();
    let first = channel
        .basic_get(name_a.clone().into(), BasicGetOptions::default())
        .await
        .unwrap()
        .expect("a message");
    assert_eq!(first.data, b"payload-a");
    assert_eq!(
        first.properties.message_id().as_ref().map(|m| m.as_str()),
        Some(super::scoped_batch_id(&run, &batch("key-a", b"payload-a")).as_str())
    );
    let headers = first.properties.headers().as_ref().expect("headers");
    assert_eq!(
        headers.inner().get("crawlx-batch"),
        Some(&lapin::types::AMQPValue::LongString("key-a".into()))
    );
    assert_eq!(first.properties.delivery_mode(), &Some(2), "persistent");
    first
        .ack(lapin::options::BasicAckOptions::default())
        .await
        .unwrap();
    let second = channel
        .basic_get(name_a.clone().into(), BasicGetOptions::default())
        .await
        .unwrap()
        .expect("a second message");
    assert_eq!(second.data, b"payload-a2");
    second
        .ack(lapin::options::BasicAckOptions::default())
        .await
        .unwrap();
    assert!(
        channel
            .basic_get(name_a.clone().into(), BasicGetOptions::default())
            .await
            .unwrap()
            .is_none(),
        "A's queue holds only A's messages"
    );
    let other = channel
        .basic_get(name_b.clone().into(), BasicGetOptions::default())
        .await
        .unwrap()
        .expect("B's own message");
    assert_eq!(other.data, b"payload-b");
    other
        .ack(lapin::options::BasicAckOptions::default())
        .await
        .unwrap();
    // a dropped connection is re-established by the next send
    channel.close(200, "done".into()).await.unwrap();
    connection.close(200, "done".into()).await.unwrap();
    // an unreachable broker asks for a retry; a ZDR run is refused
    let down = AmqpDestination::new(AmqpSettings {
        uri: "amqp://127.0.0.1:1/%2f".to_owned(),
        exchange: name_a.clone(),
        queue: name_a.clone(),
    })
    .unwrap();
    let error = down
        .send(&authority, &run, &batch("x", b"x"), Bytes::from_static(b"x"))
        .await
        .unwrap_err();
    assert!(matches!(error, DeliveryError::ProviderBackoff(_)), "{error:?}");
    let error = a
        .send(
            &authority,
            &run_zdr(),
            &batch("z", b"x"),
            Bytes::from_static(b"x"),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        DeliveryError::Unavailable("amqp_persistence_forbidden_in_zdr")
    ));
    // clean up
    let cleanup = Connection::connect(
        &connection_uri(&endpoint, Some(&login)).unwrap(),
        ConnectionProperties::default(),
    )
    .await
    .unwrap();
    let channel = cleanup.create_channel().await.unwrap();
    for name in [&name_a, &name_b] {
        channel
            .queue_delete(name.clone().into(), QueueDeleteOptions::default())
            .await
            .unwrap();
        channel
            .exchange_delete(name.clone().into(), ExchangeDeleteOptions::default())
            .await
            .unwrap();
    }
}

// ---- Registry file -----------------------------------------------------------------------------

struct FixedSecrets;

#[async_trait::async_trait]
impl crawlx_core::secret::SecretResolver for FixedSecrets {
    async fn resolve(
        &self,
        _reference: &crawlx_core::secret::CredentialRef,
    ) -> Result<crawlx_core::secret::SecretOr<String>, crawlx_core::error::CoreError> {
        Ok(crawlx_core::secret::SecretOr::secret("s3cret".to_owned()))
    }
}

async fn load(destinations: Value) -> Result<crate::delivery::DeliveryRegistry, DeliveryError> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("registry.json");
    std::fs::write(
        &path,
        json!({"version": 1, "destinations": destinations}).to_string(),
    )
    .unwrap();
    crate::delivery::DeliveryRegistry::from_file(&path, &FixedSecrets).await
}

#[tokio::test]
async fn registry_accepts_each_new_kind_and_refuses_fields_a_kind_does_not_use() {
    let valid = json!([
        {"id": "s", "kind": "opensearch", "endpoint": "http://127.0.0.1:9200", "index": "pages", "indexPrefix": "crawlx-"},
        {"id": "e", "kind": "elasticsearch", "endpoint": "http://127.0.0.1:9201", "index": "pages"},
        {"id": "c", "kind": "clickhouse", "endpoint": "http://127.0.0.1:8123", "table": "pages", "database": "crawlx"},
        {"id": "k", "kind": "kafka", "brokers": ["127.0.0.1:9092"], "topic": "pages", "partitions": 2,
         "credentials": {"username": "env://U", "password": "env://P"}},
        {"id": "a", "kind": "amqp", "endpoint": "amqp://127.0.0.1:5672/%2f", "topic": "pages",
         "credentials": {"username": "env://U", "password": "env://P"}},
    ]);
    assert!(
        load(valid).await.is_ok(),
        "all five kinds construct without connecting"
    );
    let refused = [
        json!([{"id": "s", "kind": "opensearch", "endpoint": "http://h:9200", "index": "i", "database": "x"}]),
        json!([{"id": "s", "kind": "opensearch", "endpoint": "http://h:9200", "index": "i", "addresses": ["10.0.0.1"]}]),
        json!([{"id": "s", "kind": "opensearch", "endpoint": "http://h:9200", "index": "i", "allowsZdr": true}]),
        json!([{"id": "s", "kind": "opensearch", "endpoint": "http://h:9200", "index": "Bad Index"}]),
        json!([{"id": "s", "kind": "opensearch", "endpoint": "http://h:9200"}]),
        json!([{"id": "c", "kind": "clickhouse", "endpoint": "http://h:8123", "table": "t; DROP TABLE x"}]),
        json!([{"id": "k", "kind": "kafka", "brokers": ["h:9092"], "topic": "t", "endpoint": "http://h"}]),
        json!([{"id": "k", "kind": "kafka", "brokers": ["nohostport"], "topic": "t"}]),
        json!([{"id": "k", "kind": "kafka", "brokers": ["h:9092"], "topic": "t", "headers": {"a": "env://X"}}]),
        json!([{"id": "a", "kind": "amqp", "endpoint": "amqp://user:pw@h:5672/%2f", "topic": "t"}]),
        json!([{"id": "a", "kind": "amqp", "endpoint": "amqp://h:5672", "topic": "t"}]),
        json!([{"id": "a", "kind": "amqp", "endpoint": "amqp://h:5672/%2f", "topic": "t", "brokers": ["h:1"]}]),
        json!([{"id": "x", "kind": "stdout", "indexPrefix": "crawlx-"}]),
    ];
    for destinations in refused {
        assert!(load(destinations.clone()).await.is_err(), "{destinations}");
    }
}
