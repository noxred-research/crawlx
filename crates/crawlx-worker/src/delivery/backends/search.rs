//! OpenSearch and Elasticsearch sink over the shared REST subset.
//!
//! Only calls both engines answer alike are used: `GET /` (engine and version), composable index
//! templates (`/_index_template/{name}`) and `POST /_bulk`. The engine is detected on first use and
//! must match the configured kind. Every index of this deployment starts with the configured
//! prefix (default `crawlx-`), one versioned template covers exactly that prefix, and nothing here
//! ever deletes an index: a tombstone deletes one document, in an index under the prefix.

use super::http::{InfraHttp, RETRY_AFTER};
use crate::delivery::{search_acknowledged, DeliveryAuthority, DeliveryDestination, DeliveryError};
use async_trait::async_trait;
use bytes::Bytes;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::{DeliveryBatchV1, MAX_VALUE_BYTES};
use crawlx_core::repo::CrawlRun;
use reqwest::header::HeaderMap;
use reqwest::Method;
use serde_json::{json, Value};
use tokio::sync::OnceCell;
use url::Url;

/// Version of the index template this build installs. A template with a lower version is
/// replaced; a higher one (a newer CrawlX) is left alone.
pub(crate) const TEMPLATE_VERSION: u64 = 1;
/// Default index prefix of a CrawlX deployment.
pub(crate) const DEFAULT_INDEX_PREFIX: &str = "crawlx-";
/// Oldest Elasticsearch with composable index templates.
const ES_MIN: (u64, u64) = (7, 8);
/// Oldest OpenSearch with composable index templates.
const OS_MIN: (u64, u64) = (1, 0);

/// Which engine the endpoint must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SearchEngine {
    OpenSearch,
    Elasticsearch,
}

/// Valid prefix or index name part: lowercase, digits and `. _ -`, not starting with `- _ +`.
pub(crate) fn valid_index_part(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=100).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// The engine kind and version of a `GET /` answer.
pub(crate) fn detect(root: &Value) -> Option<(SearchEngine, (u64, u64))> {
    let version = root.get("version")?;
    let number = version.get("number")?.as_str()?;
    let mut parts = number
        .split('.')
        .map(|p| p.split(['-', '+']).next().unwrap_or("").parse::<u64>());
    let major = parts.next()?.ok()?;
    let minor = parts.next()?.ok()?;
    let engine = if version.get("distribution").and_then(Value::as_str) == Some("opensearch") {
        SearchEngine::OpenSearch
    } else {
        SearchEngine::Elasticsearch
    };
    Some((engine, (major, minor)))
}

/// A delivery destination indexing one search projection per batch into
/// `<index_prefix><index>`.
#[derive(Debug)]
pub(crate) struct SearchDestination {
    http: InfraHttp,
    expected: SearchEngine,
    prefix: String,
    index: String,
    ready: OnceCell<()>,
}

impl SearchDestination {
    pub(crate) fn new(
        endpoint: Url,
        headers: HeaderMap,
        expected: SearchEngine,
        index_prefix: &str,
        index: &str,
    ) -> Result<Self, DeliveryError> {
        if !valid_index_part(index_prefix)
            || !valid_index_part(index)
            || index_prefix.len() + index.len() > 200
        {
            return Err(DeliveryError::Unavailable("invalid_search_index_name"));
        }
        Ok(Self {
            http: InfraHttp::new(endpoint, headers)?,
            expected,
            prefix: index_prefix.to_owned(),
            index: index.to_owned(),
            ready: OnceCell::new(),
        })
    }

    fn template_name(&self) -> String {
        format!("{}crawlx", self.prefix)
    }

    /// Detect the engine and install the versioned template once per process.
    async fn ensure_ready(&self) -> Result<(), DeliveryError> {
        self.ready
            .get_or_try_init(|| async {
                let root = self
                    .http
                    .send(Method::GET, "/", &[], None, Bytes::new())
                    .await?
                    .require_success()?
                    .json()?;
                let (engine, version) =
                    detect(&root).ok_or(DeliveryError::Rejected("search_engine_unrecognized"))?;
                if engine != self.expected {
                    return Err(DeliveryError::Unavailable("search_engine_mismatch"));
                }
                let minimum = match engine {
                    SearchEngine::OpenSearch => OS_MIN,
                    SearchEngine::Elasticsearch => ES_MIN,
                };
                if version < minimum {
                    return Err(DeliveryError::Unavailable("search_engine_version_unsupported"));
                }
                self.migrate().await
            })
            .await?;
        Ok(())
    }

    /// The only migration: one composable template over `<prefix>*`.
    async fn migrate(&self) -> Result<(), DeliveryError> {
        let path = format!("/_index_template/{}", self.template_name());
        let existing = self
            .http
            .send(Method::GET, &path, &[], None, Bytes::new())
            .await?;
        let installed = if existing.status == 404 {
            0
        } else {
            existing
                .require_success()?
                .json()?
                .pointer("/index_templates/0/index_template/_meta/crawlx_template_version")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        };
        if installed >= TEMPLATE_VERSION {
            return Ok(());
        }
        let body = json!({
            "index_patterns": [format!("{}*", self.prefix)],
            "priority": 200,
            "version": TEMPLATE_VERSION,
            "_meta": {"crawlx_template_version": TEMPLATE_VERSION},
            "template": {
                "settings": {"index": {"number_of_shards": 1}},
                "mappings": {"dynamic": true},
            },
        });
        let body =
            serde_json::to_vec(&body).map_err(|_| DeliveryError::Rejected("search_serialization_failed"))?;
        self.http
            .send(
                Method::PUT,
                &path,
                &[],
                Some("application/json"),
                Bytes::from(body),
            )
            .await?
            .require_success()?;
        Ok(())
    }
}

#[async_trait]
impl DeliveryDestination for SearchDestination {
    fn duplicate_possible(&self) -> bool {
        // stable document ids make a retry an overwrite
        false
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
        _batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        if run.config.retention.mode == RetentionMode::Zdr {
            return Err(DeliveryError::Unavailable("search_persistence_forbidden_in_zdr"));
        }
        self.ensure_ready().await?;
        let projection: crawlx_core::extraction::SearchProjectionV1 = serde_json::from_slice(&bytes)
            .map_err(|_| DeliveryError::Rejected("search_projection_required"))?;
        projection.validate()?;
        let index = format!("{}{}", self.prefix, self.index);
        let operation = if projection.deleted {
            json!({"delete": {"_index": index, "_id": projection.document_id}})
        } else {
            json!({"index": {"_index": index, "_id": projection.document_id}})
        };
        let mut body = Vec::new();
        serde_json::to_writer(&mut body, &operation)
            .map_err(|_| DeliveryError::Rejected("search_serialization_failed"))?;
        body.push(b'\n');
        if !projection.deleted {
            serde_json::to_writer(&mut body, &projection.fields)
                .map_err(|_| DeliveryError::Rejected("search_serialization_failed"))?;
            body.push(b'\n');
        }
        if u64::try_from(body.len()).map_or(true, |size| size > MAX_VALUE_BYTES) {
            return Err(DeliveryError::Rejected("provider_wire_byte_limit"));
        }
        let reply = self
            .http
            .send(
                Method::POST,
                "/_bulk",
                &[],
                Some("application/x-ndjson"),
                Bytes::from(body),
            )
            .await?;
        if reply.status == 429 || reply.status == 503 {
            return Err(DeliveryError::ProviderBackoff(RETRY_AFTER));
        }
        let value = reply.require_success()?.json()?;
        if search_acknowledged(&value, &projection.document_id, projection.deleted) {
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
    fn engines_and_versions_are_detected_from_the_root_document() {
        let os = json!({"version": {"number": "2.19.1", "distribution": "opensearch"}});
        assert_eq!(detect(&os), Some((SearchEngine::OpenSearch, (2, 19))));
        let es = json!({"version": {"number": "8.15.3", "build_flavor": "default"}, "tagline": "You Know, for Search"});
        assert_eq!(detect(&es), Some((SearchEngine::Elasticsearch, (8, 15))));
        let snapshot = json!({"version": {"number": "9.0.0-SNAPSHOT"}});
        assert_eq!(detect(&snapshot), Some((SearchEngine::Elasticsearch, (9, 0))));
        assert_eq!(detect(&json!({"nope": 1})), None);
    }

    #[test]
    fn index_names_are_lowercase_and_bounded() {
        for good in ["crawlx-", "crawlx-pages", "a.b_c-d", "9lives"] {
            assert!(valid_index_part(good), "{good}");
        }
        for bad in [
            "",
            "-x",
            "_x",
            "X",
            "a b",
            "a/b",
            "a*",
            "a,b",
            "a#b",
            &"a".repeat(101),
        ] {
            assert!(!valid_index_part(bad), "{bad}");
        }
        let url: Url = "http://127.0.0.1:9200".parse().unwrap();
        assert!(SearchDestination::new(
            url.clone(),
            HeaderMap::new(),
            SearchEngine::OpenSearch,
            "Crawlx-",
            "pages"
        )
        .is_err());
        assert!(SearchDestination::new(
            url,
            HeaderMap::new(),
            SearchEngine::OpenSearch,
            "crawlx-",
            "pages"
        )
        .is_ok());
    }
}
