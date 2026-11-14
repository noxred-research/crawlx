//! Native sinks for the infrastructure families a deployment can share between products:
//! search (OpenSearch, Elasticsearch), analytics (ClickHouse) and event streams (Kafka, RabbitMQ).
//!
//! Each is a [`DeliveryDestination`](super::DeliveryDestination) selected by id from the operator
//! registry file; a crawl names only the id. Every sink keeps to its own namespace on a shared
//! instance (index prefix, database, topic prefix, exchange/queue prefix) and creates what it
//! needs on first use through versioned, idempotent steps. Endpoints are trusted infrastructure
//! chosen by the operator, like the database and the object store, not crawl targets: the crawl
//! egress policy does not apply, and nothing a page contains can change where data goes.

mod amqp;
mod clickhouse;
mod http;
mod kafka;
mod search;
#[cfg(test)]
mod tests;

use crawlx_core::dataset::DeliveryBatchV1;
use crawlx_core::repo::CrawlRun;

/// Identity of one batch that is unique across runs and deployments: a hash of the tenant id, the
/// run id and the batch key, as 64 lowercase hex digits.
///
/// Batch keys are only unique inside one run (`request.<page>.<feed>`, and request ids restart in
/// every database), so a sink that deduplicates or keys on the raw batch key would drop or merge
/// the batches of another run or another deployment writing to the same table, topic or queue.
/// Tenant and run ids are random time-ordered UUIDs, so they separate deployments without any
/// configured deployment id, and they are persisted with the run, so a retry of one batch, also
/// after a restart, yields the same identity. Each part is length-prefixed so that no two
/// distinct triples hash the same bytes.
pub(super) fn scoped_batch_id(run: &CrawlRun, batch: &DeliveryBatchV1) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("crawlx.delivery.scoped-batch-id.v1");
    for part in [
        run.tenant.0.as_bytes().as_slice(),
        run.id.0.as_bytes().as_slice(),
        batch.idempotency_key.as_bytes(),
    ] {
        hasher.update(&(part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_hex().to_string()
}

pub(super) use amqp::DEFAULT_PREFIX as DEFAULT_AMQP_PREFIX;
pub(super) use amqp::{connection_uri, valid_name_part as valid_amqp_name, AmqpDestination, AmqpSettings};
pub(super) use clickhouse::{ClickHouseDestination, DEFAULT_DATABASE};
pub(super) use kafka::{KafkaDestination, KafkaSettings, DEFAULT_TOPIC_PREFIX};
pub(super) use search::{SearchDestination, SearchEngine, DEFAULT_INDEX_PREFIX};

#[cfg(test)]
mod scope_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::scoped_batch_id;
    use crate::delivery::tests::run;
    use crawlx_core::config::RetentionMode;
    use crawlx_core::dataset::{DatasetContentV1, DeliveryBatchV1};
    use crawlx_core::hash::Digest;
    use crawlx_core::{ArtifactId, ArtifactRef};

    fn batch(key: &str) -> DeliveryBatchV1 {
        DeliveryBatchV1::for_request(
            "feed".to_owned(),
            key.to_owned(),
            DatasetContentV1::Durable {
                artifact: ArtifactRef {
                    id: ArtifactId::new(),
                    digest: Digest::of("test", b"x"),
                },
            },
            1,
            chrono::Utc::now() + chrono::Duration::hours(1),
        )
    }

    #[test]
    fn identity_separates_runs_tenants_and_keys_but_not_retries() {
        let first = run(RetentionMode::Standard, chrono::Utc::now(), &["json"]);
        let second = run(RetentionMode::Standard, chrono::Utc::now(), &["json"]);
        let id = scoped_batch_id(&first, &batch("request.1.f"));
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        // a retry of the same batch, with a different content artifact, keeps the identity
        assert_eq!(id, scoped_batch_id(&first, &batch("request.1.f")));
        assert_ne!(id, scoped_batch_id(&first, &batch("request.2.f")));
        assert_ne!(first.id, second.id);
        assert_ne!(id, scoped_batch_id(&second, &batch("request.1.f")));
        let mut other_tenant = first.clone();
        other_tenant.tenant = crawlx_core::TenantId::new();
        assert_ne!(id, scoped_batch_id(&other_tenant, &batch("request.1.f")));
        let mut other_run = first.clone();
        other_run.id = crawlx_core::CrawlRunId::new();
        assert_ne!(id, scoped_batch_id(&other_run, &batch("request.1.f")));
    }
}
