//! ClickHouse sink over the HTTP interface.
//!
//! One database per deployment (default `crawlx`), tables created by versioned migrations that
//! are recorded in `<database>.crawlx_migrations`. Each delivered batch is one `JSONEachRow`
//! insert whose `insert_deduplication_token` is the batch idempotency key, so a retried batch is
//! dropped by the table's deduplication window instead of storing twice.

use super::http::{InfraHttp, RETRY_AFTER};
use crate::delivery::{DeliveryAuthority, DeliveryDestination, DeliveryError};
use async_trait::async_trait;
use bytes::Bytes;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::{DeliveryBatchV1, MAX_VALUE_BYTES};
use crawlx_core::repo::CrawlRun;
use reqwest::header::HeaderMap;
use reqwest::Method;
use serde_json::json;
use tokio::sync::OnceCell;
use url::Url;

/// Default database of a CrawlX deployment.
pub(crate) const DEFAULT_DATABASE: &str = "crawlx";
/// Inserts of the same token inside this many recent blocks are deduplicated.
const DEDUPLICATION_WINDOW: u32 = 10_000;

/// SQL identifier safe to interpolate: ASCII letters, digits and `_`, not starting with a digit.
pub(crate) fn valid_identifier(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && bytes.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// The migrations of the feed table, in order: `(version, name, statement)`. Statements use
/// `{db}` and `{table}` for validated identifiers.
const MIGRATIONS: [(u32, &str, &str); 1] = [(
    1,
    "create_feed_table",
    "CREATE TABLE IF NOT EXISTS {db}.{table} (\
        tenant_id String, run_id String, feed String, batch_key String, content_digest String, \
        ingested_at DateTime64(3) DEFAULT now64(3), payload String CODEC(ZSTD(3))) \
     ENGINE = MergeTree PARTITION BY toYYYYMM(ingested_at) \
     ORDER BY (tenant_id, run_id, ingested_at, batch_key) \
     SETTINGS non_replicated_deduplication_window = {window}",
)];

/// A delivery destination appending one row per batch to `<database>.<table>`.
#[derive(Debug)]
pub(crate) struct ClickHouseDestination {
    http: InfraHttp,
    database: String,
    table: String,
    ready: OnceCell<()>,
}

impl ClickHouseDestination {
    pub(crate) fn new(
        endpoint: Url,
        headers: HeaderMap,
        database: &str,
        table: &str,
    ) -> Result<Self, DeliveryError> {
        if !valid_identifier(database) || !valid_identifier(table) || table == "crawlx_migrations" {
            return Err(DeliveryError::Unavailable("invalid_clickhouse_identifier"));
        }
        Ok(Self {
            http: InfraHttp::new(endpoint, headers)?,
            database: database.to_owned(),
            table: table.to_owned(),
            ready: OnceCell::new(),
        })
    }

    async fn execute(&self, sql: &str) -> Result<Bytes, DeliveryError> {
        let reply = self
            .http
            .send(
                Method::POST,
                "/",
                &[],
                Some("text/plain"),
                Bytes::copy_from_slice(sql.as_bytes()),
            )
            .await?
            .require_success()?;
        Ok(reply.body)
    }

    /// Create the database, the migration ledger and every migration of the table not yet applied.
    async fn ensure_ready(&self) -> Result<(), DeliveryError> {
        self.ready
            .get_or_try_init(|| async {
                let db = &self.database;
                self.execute(&format!("CREATE DATABASE IF NOT EXISTS {db}")).await?;
                self.execute(&format!(
                    "CREATE TABLE IF NOT EXISTS {db}.crawlx_migrations (table_name String, version UInt32, \
                     name String, applied_at DateTime64(3) DEFAULT now64(3)) ENGINE = MergeTree ORDER BY (table_name, version)"
                ))
                .await?;
                for (version, name, statement) in MIGRATIONS {
                    let applied = self
                        .execute(&format!(
                            "SELECT count() FROM {db}.crawlx_migrations WHERE table_name = '{}' AND version = {version} FORMAT TabSeparated",
                            self.table
                        ))
                        .await?;
                    if String::from_utf8_lossy(&applied).trim() != "0" {
                        continue;
                    }
                    let sql = statement
                        .replace("{db}", db)
                        .replace("{table}", &self.table)
                        .replace("{window}", &DEDUPLICATION_WINDOW.to_string());
                    self.execute(&sql).await?;
                    self.execute(&format!(
                        "INSERT INTO {db}.crawlx_migrations (table_name, version, name) VALUES ('{}', {version}, '{name}')",
                        self.table
                    ))
                    .await?;
                }
                Ok::<(), DeliveryError>(())
            })
            .await
            .map(|_| ())
    }
}

#[async_trait]
impl DeliveryDestination for ClickHouseDestination {
    fn duplicate_possible(&self) -> bool {
        // a retry inside the deduplication window is dropped by the table; beyond it, it is not
        true
    }

    fn permits_zdr(&self) -> bool {
        false
    }

    fn working_bytes(&self, input: u64) -> Option<u64> {
        input.checked_mul(3)?.checked_add(256 * 1024)
    }

    async fn send(
        &self,
        _authority: &DeliveryAuthority,
        run: &CrawlRun,
        batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        if run.config.retention.mode == RetentionMode::Zdr {
            return Err(DeliveryError::Unavailable(
                "clickhouse_persistence_forbidden_in_zdr",
            ));
        }
        self.ensure_ready().await?;
        let payload = String::from_utf8(bytes.to_vec())
            .map_err(|_| DeliveryError::Rejected("clickhouse_payload_not_utf8"))?;
        let mut row = serde_json::to_vec(&json!({
            "tenant_id": run.tenant.0.to_string(),
            "run_id": run.id.0.to_string(),
            "feed": batch.feed,
            "batch_key": batch.idempotency_key,
            "content_digest": batch.content.artifact().digest.to_hex(),
            "payload": payload,
        }))
        .map_err(|_| DeliveryError::Rejected("clickhouse_serialization_failed"))?;
        row.push(b'\n');
        if u64::try_from(row.len()).map_or(true, |size| size > MAX_VALUE_BYTES.saturating_mul(2)) {
            return Err(DeliveryError::Rejected("provider_wire_byte_limit"));
        }
        let statement = format!(
            "INSERT INTO {}.{} (tenant_id, run_id, feed, batch_key, content_digest, payload) FORMAT JSONEachRow",
            self.database, self.table
        );
        let reply = self
            .http
            .send(
                Method::POST,
                "/",
                &[
                    ("query", statement.as_str()),
                    ("insert_deduplication_token", batch.idempotency_key.as_str()),
                ],
                Some("application/x-ndjson"),
                Bytes::from(row),
            )
            .await?;
        if reply.status == 429 || reply.status == 503 {
            return Err(DeliveryError::ProviderBackoff(RETRY_AFTER));
        }
        reply.require_success()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn identifiers_are_safe_to_interpolate() {
        for good in ["crawlx", "_a", "Pages_2"] {
            assert!(valid_identifier(good), "{good}");
        }
        for bad in ["", "1a", "a-b", "a.b", "a b", "a;drop", "a`b", &"x".repeat(64)] {
            assert!(!valid_identifier(bad), "{bad}");
        }
        let url: Url = "http://127.0.0.1:8123".parse().unwrap();
        assert!(ClickHouseDestination::new(url.clone(), HeaderMap::new(), "crawlx; DROP", "t").is_err());
        assert!(
            ClickHouseDestination::new(url.clone(), HeaderMap::new(), "crawlx", "crawlx_migrations").is_err()
        );
        assert!(ClickHouseDestination::new(url, HeaderMap::new(), "crawlx", "pages").is_ok());
    }
}
