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

pub(super) use amqp::DEFAULT_PREFIX as DEFAULT_AMQP_PREFIX;
pub(super) use amqp::{connection_uri, valid_name_part as valid_amqp_name, AmqpDestination, AmqpSettings};
pub(super) use clickhouse::{ClickHouseDestination, DEFAULT_DATABASE};
pub(super) use kafka::{KafkaDestination, KafkaSettings, DEFAULT_TOPIC_PREFIX};
pub(super) use search::{SearchDestination, SearchEngine, DEFAULT_INDEX_PREFIX};
