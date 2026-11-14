//! Native Kafka producer sink (no REST proxy in between).
//!
//! Topics live under a deployment prefix (default `crawlx.`). A topic is created on first use
//! when missing. Each batch is one record keyed by its scoped batch identity (a hash of tenant id,
//! run id and batch key, so runs and deployments sharing a topic never share a key; the raw batch
//! key is in the `crawlx-batch` header) and sent to the partition that key hashes to; the send returns only after the broker acknowledged it (`acks=all`). The
//! client has no idempotent-producer mode, so a retry after an unacknowledged send can store the
//! batch twice: the sink reports `duplicate_possible` and consumers deduplicate on the record key.

use super::scoped_batch_id;
use crate::delivery::{DeliveryAuthority, DeliveryDestination, DeliveryError};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::DeliveryBatchV1;
use crawlx_core::repo::CrawlRun;
use rskafka::client::error::{Error as KafkaError, ProtocolError};
use rskafka::client::partition::{Compression, UnknownTopicHandling};
use rskafka::client::{ClientBuilder, Credentials, SaslConfig};
use rskafka::record::Record;
use rskafka::BackoffConfig;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::OnceCell;

/// Default topic prefix of a CrawlX deployment.
pub(crate) const DEFAULT_TOPIC_PREFIX: &str = "crawlx.";
/// Cooldown after a transport or broker failure.
const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(30);
/// Largest record value sent.
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// Topic name part: letters, digits and `. _ -`, at most 200 bytes in total once prefixed.
pub(crate) fn valid_topic_part(text: &str) -> bool {
    (1..=200).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && text != "."
        && text != ".."
}

/// Broker `host:port`.
pub(crate) fn valid_broker(text: &str) -> bool {
    text.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'[' | b']' | b':'))
            && port.parse::<u16>().is_ok_and(|p| p > 0)
    })
}

/// Connection settings of a Kafka destination.
pub(crate) struct KafkaSettings {
    pub(crate) brokers: Vec<String>,
    pub(crate) topic: String,
    pub(crate) tls: bool,
    pub(crate) sasl: Option<(String, String)>,
    pub(crate) partitions: i32,
    pub(crate) replication_factor: i16,
}

/// A delivery destination producing one record per batch to `<prefix><topic>`.
pub(crate) struct KafkaDestination {
    settings: KafkaSettings,
    client: OnceCell<Arc<rskafka::client::Client>>,
    partitions: OnceCell<Vec<i32>>,
}

impl std::fmt::Debug for KafkaDestination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaDestination")
            .field("topic", &self.settings.topic)
            .finish_non_exhaustive()
    }
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>, DeliveryError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| DeliveryError::Unavailable("kafka_tls_unavailable"))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Transport and broker failures retry later; they carry no endpoint or payload.
fn backoff(_error: KafkaError) -> DeliveryError {
    DeliveryError::ProviderBackoff(RETRY_AFTER)
}

impl KafkaDestination {
    pub(crate) fn new(settings: KafkaSettings) -> Result<Self, DeliveryError> {
        if settings.brokers.is_empty()
            || settings.brokers.len() > 16
            || !settings.brokers.iter().all(|b| valid_broker(b))
            || !valid_topic_part(&settings.topic)
            || !(1..=1024).contains(&settings.partitions)
            || !(1..=8).contains(&settings.replication_factor)
        {
            return Err(DeliveryError::Unavailable("invalid_kafka_settings"));
        }
        Ok(Self {
            settings,
            client: OnceCell::new(),
            partitions: OnceCell::new(),
        })
    }

    async fn client(&self) -> Result<&Arc<rskafka::client::Client>, DeliveryError> {
        self.client
            .get_or_try_init(|| async {
                // The client retries forever by default; bound each operation so an unreachable
                // broker surfaces as a retry-later error instead of a hung send.
                let mut builder =
                    ClientBuilder::new(self.settings.brokers.clone()).backoff_config(BackoffConfig {
                        init_backoff: std::time::Duration::from_millis(100),
                        max_backoff: std::time::Duration::from_secs(2),
                        base: 2.0,
                        deadline: Some(std::time::Duration::from_secs(15)),
                    });
                if self.settings.tls {
                    builder = builder.tls_config(tls_config()?);
                }
                if let Some((user, password)) = &self.settings.sasl {
                    builder = builder.sasl_config(SaslConfig::Plain(Credentials::new(
                        user.clone(),
                        password.clone(),
                    )));
                }
                builder.build().await.map(Arc::new).map_err(backoff)
            })
            .await
    }

    /// The partitions of the topic, creating it when it does not exist.
    async fn partitions(&self) -> Result<&Vec<i32>, DeliveryError> {
        self.partitions
            .get_or_try_init(|| async {
                let client = self.client().await?;
                let topic = &self.settings.topic;
                let find = || async {
                    Ok::<_, DeliveryError>(
                        client
                            .list_topics()
                            .await
                            .map_err(backoff)?
                            .into_iter()
                            .find(|t| &t.name == topic)
                            .map(|t| t.partitions.into_iter().collect::<Vec<i32>>()),
                    )
                };
                if let Some(partitions) = find().await? {
                    return Ok(partitions);
                }
                let controller = client.controller_client().map_err(backoff)?;
                match controller
                    .create_topic(
                        topic.clone(),
                        self.settings.partitions,
                        self.settings.replication_factor,
                        5_000,
                    )
                    .await
                {
                    Ok(()) => {}
                    Err(KafkaError::ServerError {
                        protocol_error: ProtocolError::TopicAlreadyExists,
                        ..
                    }) => {}
                    Err(error) => return Err(backoff(error)),
                }
                find()
                    .await?
                    .ok_or(DeliveryError::Unavailable("kafka_topic_unavailable"))
            })
            .await
    }
}

#[async_trait]
impl DeliveryDestination for KafkaDestination {
    fn duplicate_possible(&self) -> bool {
        true
    }

    fn permits_zdr(&self) -> bool {
        false
    }

    async fn send(
        &self,
        _authority: &DeliveryAuthority,
        run: &CrawlRun,
        batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        if run.config.retention.mode == RetentionMode::Zdr {
            return Err(DeliveryError::Unavailable("kafka_persistence_forbidden_in_zdr"));
        }
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(DeliveryError::Rejected("provider_wire_byte_limit"));
        }
        let partitions = self.partitions().await?;
        let client = self.client().await?;
        let record_key = scoped_batch_id(run, batch);
        let hash = blake3::hash(record_key.as_bytes());
        let slot = usize::try_from(u32::from_le_bytes([
            hash.as_bytes()[0],
            hash.as_bytes()[1],
            hash.as_bytes()[2],
            hash.as_bytes()[3],
        ]))
        .unwrap_or(0)
            % partitions.len().max(1);
        let partition = *partitions
            .get(slot)
            .ok_or(DeliveryError::Unavailable("kafka_topic_unavailable"))?;
        let partition_client = client
            .partition_client(
                self.settings.topic.clone(),
                partition,
                UnknownTopicHandling::Error,
            )
            .await
            .map_err(backoff)?;
        let mut headers = BTreeMap::new();
        headers.insert("crawlx-feed".to_owned(), batch.feed.clone().into_bytes());
        headers.insert(
            "crawlx-batch".to_owned(),
            batch.idempotency_key.clone().into_bytes(),
        );
        headers.insert("crawlx-run".to_owned(), run.id.0.to_string().into_bytes());
        headers.insert(
            "crawlx-content-digest".to_owned(),
            batch.content.artifact().digest.to_hex().into_bytes(),
        );
        let record = Record {
            key: Some(record_key.into_bytes()),
            value: Some(bytes.to_vec()),
            headers,
            timestamp: Utc::now(),
        };
        let offsets = partition_client
            .produce(vec![record], Compression::NoCompression)
            .await
            .map_err(backoff)?;
        if offsets.len() == 1 && offsets.iter().all(|offset| *offset >= 0) {
            Ok(())
        } else {
            Err(DeliveryError::Rejected("provider_ack_rejected"))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn brokers_and_topics_are_validated() {
        for good in ["localhost:9092", "broker-1.internal:19092", "10.0.0.5:9092"] {
            assert!(valid_broker(good), "{good}");
        }
        for bad in ["localhost", ":9092", "host:0", "host:99999", "ho st:1", "host:x"] {
            assert!(!valid_broker(bad), "{bad}");
        }
        assert!(valid_topic_part("crawlx.pages-v1"));
        for bad in ["", ".", "..", "a/b", "a b", "a*"] {
            assert!(!valid_topic_part(bad), "{bad}");
        }
        let settings = |topic: &str| KafkaSettings {
            brokers: vec!["localhost:9092".to_owned()],
            topic: topic.to_owned(),
            tls: false,
            sasl: None,
            partitions: 1,
            replication_factor: 1,
        };
        assert!(KafkaDestination::new(settings("crawlx.pages")).is_ok());
        assert!(KafkaDestination::new(settings("bad topic")).is_err());
    }
}
