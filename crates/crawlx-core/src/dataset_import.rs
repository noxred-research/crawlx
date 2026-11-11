//! Safe, bounded JSON dataset exports, never live storage adapters or directory loaders.
//!
//! Import uses the existing typed artifact sink and fenced request result transaction.
//! Source backend metadata describes provenance only; it never selects native authority.

use super::{AcceptedBatchV1, AcceptedItemV1, DatasetConfigV1, MAX_BATCH_ITEMS};
use crate::orchestration::{RequestCommitRepo, RequestCommitV1};
use crate::repo::{ArtifactStore, FrontierStatus};
use crate::secret::{ArtifactSink, Redactor};
use crate::{StoreError, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Maximum complete JSON export size, including metadata and whitespace.
pub const MAX_IMPORT_BYTES: usize = 1024 * 1024;
/// Maximum canonical JSON bytes in one imported object.
pub const MAX_IMPORT_ITEM_BYTES: usize = 64 * 1024;
/// Schema of imported JSON objects; no document/extractor schema is inferred from arbitrary JSON.
pub const IMPORT_SCHEMA_VERSION: &str = "json_object_v1";

/// Source backend provenance, not an installed native storage implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceBackendV1 {
    /// Process-local source memory.
    Memory,
    /// Exported files; never a shared multiprocess queue.
    Filesystem,
    /// Export from PostgreSQL.
    PostgreSql,
    /// Experimental SQLite source.
    Sqlite,
    /// Experimental MariaDB source.
    MariaDb,
    /// Experimental Redis source.
    Redis,
}

/// Exact identities versus a source that may have omitted unseen records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SourceDedupeV1 {
    /// Source retained exact identities.
    Exact,
    /// Approximate membership can omit records; no coverage claim is supported.
    Approximate,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Export {
    version: u16,
    source: Source,
    policy: Policy,
    dataset: String,
    schema_version: String,
    batch: String,
    items: Vec<Item>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Source {
    backend: SourceBackendV1,
    version: String,
    experimental: bool,
    dedupe: SourceDedupeV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Policy {
    purge_on_start: bool,
    shared_filesystem_queue: bool,
    // A requested backend swap is reported, never applied.
    authoritative_backend: SourceBackendV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Item {
    key: String,
    value: serde_json::Value,
}

/// Parsed export with private unapproved content. Debug never reveals item bytes.
#[must_use]
pub struct DatasetImportV1(Export);

impl std::fmt::Debug for DatasetImportV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DatasetImportV1([REDACTED])")
    }
}

/// Structural inspection result; item values, paths and connection strings are absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ImportReportV1 {
    /// Source backend provenance only.
    pub source_backend: SourceBackendV1,
    /// Explicit exporter-supplied source version.
    pub source_version: String,
    /// Whether the exporter marked the backend experimental.
    pub experimental: bool,
    /// Whether source deduplication may have omitted records.
    pub possible_omissions: bool,
    /// Always false: importing an export never proves frontier coverage.
    pub complete_coverage: bool,
    /// Bounded number of objects, without content.
    pub item_count: usize,
    /// Policy conflicts that must be fixed explicitly before import.
    pub incompatibilities: Vec<ImportIncompatibilityV1>,
}

/// Explicit unsupported source semantics; no destructive fallback is performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ImportIncompatibilityV1 {
    /// Restart must never implicitly purge shared pending state or named stores.
    DestructivePurgeOnStart,
    /// Filesystem storage cannot become a multiprocess queue.
    SharedFilesystemQueue,
    /// PostgreSQL remains the only durable authority.
    AlternateAuthority,
}

/// Privacy-safe import failure. Parser diagnostics intentionally omit untrusted field text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ImportError {
    /// Input or object bounds were exceeded.
    #[error("dataset import exceeds bounded input limits")]
    Limit,
    /// Malformed JSON or an unsupported strict export shape.
    #[error("invalid dataset import JSON")]
    InvalidJson,
    /// Invalid version, identifier, duplicate key, or non-object value.
    #[error("invalid dataset import contract")]
    InvalidContract,
    /// Source policies cannot be honored safely.
    #[error("dataset import has unsupported storage policies")]
    IncompatiblePolicy,
    /// Existing sink or request authority refused the operation.
    #[error("dataset import storage operation failed")]
    Store(#[from] StoreError),
}

impl DatasetImportV1 {
    /// Parse one strict, bounded JSON export without opening any referenced objects.
    ///
    /// # Errors
    /// Rejects oversized input, unknown fields, invalid versions/keys, duplicate keys,
    /// non-object items, and experimental backends not explicitly marked experimental.
    pub fn parse(bytes: &[u8]) -> Result<Self, ImportError> {
        if bytes.len() > MAX_IMPORT_BYTES {
            return Err(ImportError::Limit);
        }
        // The existing JSON privacy gate also rejects duplicate object members.
        // Never retain serde diagnostics: rejected keys can themselves contain secrets.
        let approved = Redactor::new().redact_artifact(bytes)?;
        if approved.as_ref().len() > MAX_IMPORT_BYTES {
            return Err(ImportError::Limit);
        }
        let export: Export =
            serde_json::from_slice(approved.as_ref()).map_err(|_| ImportError::InvalidJson)?;
        if export.items.len() > MAX_BATCH_ITEMS {
            return Err(ImportError::Limit);
        }
        if export.version != 1
            || export.schema_version != IMPORT_SCHEMA_VERSION
            || export.items.is_empty()
            || (matches!(
                export.source.backend,
                SourceBackendV1::Sqlite | SourceBackendV1::MariaDb | SourceBackendV1::Redis
            ) && !export.source.experimental)
        {
            return Err(ImportError::InvalidContract);
        }
        for identifier in [
            &export.dataset,
            &export.schema_version,
            &export.batch,
            &export.source.version,
        ] {
            super::validate_identifier(identifier).map_err(|_| ImportError::InvalidContract)?;
        }
        let mut keys = BTreeSet::new();
        for item in &export.items {
            super::validate_identifier(&item.key).map_err(|_| ImportError::InvalidContract)?;
            if !keys.insert(&item.key) || !item.value.is_object() {
                return Err(ImportError::InvalidContract);
            }
            let size = crate::extensions::json_size(&item.value).map_err(|_| ImportError::Limit)?;
            if size > MAX_IMPORT_ITEM_BYTES {
                return Err(ImportError::Limit);
            }
        }
        Ok(Self(export))
    }

    /// Report all unsupported policies without returning any imported content.
    #[must_use]
    pub fn inspect(&self) -> ImportReportV1 {
        let export = &self.0;
        let mut incompatibilities = Vec::new();
        if export.policy.purge_on_start {
            incompatibilities.push(ImportIncompatibilityV1::DestructivePurgeOnStart);
        }
        if export.policy.shared_filesystem_queue {
            incompatibilities.push(ImportIncompatibilityV1::SharedFilesystemQueue);
        }
        if export.policy.authoritative_backend != SourceBackendV1::PostgreSql {
            incompatibilities.push(ImportIncompatibilityV1::AlternateAuthority);
        }
        ImportReportV1 {
            source_backend: export.source.backend,
            source_version: export.source.version.clone(),
            experimental: export.source.experimental,
            possible_omissions: export.source.dedupe == SourceDedupeV1::Approximate,
            complete_coverage: false,
            item_count: export.items.len(),
            incompatibilities,
        }
    }
}

/// Approve and store exported objects, then append only through the authoritative live fence.
///
/// Caller supplies the admitted request's terminal result and immutable content deadline.
/// No request is fabricated, no queue is purged, and no metadata is published before commit.
/// Failed commits can leave only artifacts subject to existing orphan collection and expiry.
/// Source batch/key plus the real source request make replay identity stable.
///
/// # Errors
/// Returns policy/schema/bounds failures before writing, or existing privacy, retention,
/// quota, lease, CAS and storage errors. No alternative backend or raw sink fallback exists.
pub async fn commit_import(
    import: DatasetImportV1,
    config: &DatasetConfigV1,
    mut commit: RequestCommitV1,
    deadline: Timestamp,
    artifacts: &dyn ArtifactStore,
    authority: &dyn RequestCommitRepo,
) -> Result<(), ImportError> {
    if !import.inspect().incompatibilities.is_empty() {
        return Err(ImportError::IncompatiblePolicy);
    }
    config.validate()?;
    let export = import.0;
    let declaration = config
        .stores
        .iter()
        .find(|s| s.name == export.dataset)
        .ok_or(ImportError::InvalidContract)?;
    if declaration.schema_version != export.schema_version
        || commit.request_id <= 0
        || commit.fence <= 0
        || commit.status != FrontierStatus::Succeeded
        || !commit.accepted.is_empty()
    {
        return Err(ImportError::InvalidContract);
    }
    let mut items = Vec::with_capacity(export.items.len());
    for item in export.items {
        let bytes = serde_json::to_vec(&item.value).map_err(|_| ImportError::InvalidJson)?;
        let approved = Redactor::new().redact_artifact(&bytes)?;
        if approved.as_ref().len() > MAX_IMPORT_ITEM_BYTES {
            return Err(ImportError::Limit);
        }
        let size = u64::try_from(approved.as_ref().len()).map_err(|_| ImportError::Limit)?;
        // Batch and key are separately bounded identifiers. A digest avoids truncation/collisions.
        let mut hasher = blake3::Hasher::new();
        for part in [export.batch.as_bytes(), item.key.as_bytes()] {
            hasher.update(
                &u64::try_from(part.len())
                    .map_err(|_| ImportError::Limit)?
                    .to_le_bytes(),
            );
            hasher.update(part);
        }
        let key = hasher.finalize().to_hex().to_string();
        let rendition = format!("dataset_import_{key}");
        let artifact = ArtifactSink::over(artifacts)
            .put_dataset_until(
                commit.run,
                commit.request_id,
                &rendition,
                "application/json",
                &approved,
                deadline,
            )
            .await?;
        let content = artifacts
            .dataset_content(commit.run, commit.request_id, &artifact, size)
            .await?;
        if content.expires_at().is_some_and(|expiry| expiry > deadline) {
            return Err(ImportError::Store(StoreError::RetentionDenied(
                "import content deadline mismatch".into(),
            )));
        }
        let mut accepted = AcceptedItemV1::new(
            key,
            "safe_json_import_v1".into(),
            export.schema_version.clone(),
            "safe_json_export_v1".into(),
            content,
            size,
        );
        accepted.expires_at = Some(
            accepted
                .expires_at
                .map_or(deadline, |expiry| expiry.min(deadline)),
        );
        items.push(accepted);
    }
    commit.accepted.push(AcceptedBatchV1::new(export.dataset, items));
    authority.commit_fenced(commit).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "source": {"backend":"filesystem", "version":"1.0", "experimental":false, "dedupe":"exact"},
            "policy": {"purgeOnStart":false, "sharedFilesystemQueue":false, "authoritativeBackend":"postgre_sql"},
            "dataset":"records", "schemaVersion":"json_object_v1", "batch":"export-1",
            "items":[{"key":"one", "value":{"text":"private-content-canary"}}]
        })
    }

    #[test]
    fn accepts_json_only_and_hides_content() {
        let parsed = DatasetImportV1::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        assert!(parsed.inspect().incompatibilities.is_empty());
        assert!(!parsed.inspect().complete_coverage);
        assert!(!format!("{parsed:?}").contains("private-content-canary"));
        assert!(!serde_json::to_string(&parsed.inspect())
            .unwrap()
            .contains("private-content-canary"));
    }

    #[test]
    fn reports_all_destructive_and_backend_conflicts() {
        let mut value = fixture();
        value["policy"] = serde_json::json!({"purgeOnStart":true,"sharedFilesystemQueue":true,"authoritativeBackend":"redis"});
        let report = DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .inspect();
        assert_eq!(
            report.incompatibilities,
            vec![
                ImportIncompatibilityV1::DestructivePurgeOnStart,
                ImportIncompatibilityV1::SharedFilesystemQueue,
                ImportIncompatibilityV1::AlternateAuthority,
            ]
        );
    }

    #[test]
    fn reports_experimental_approximate_source_without_coverage_claim() {
        let mut value = fixture();
        value["source"] =
            serde_json::json!({"backend":"redis","version":"8.0","experimental":true,"dedupe":"approximate"});
        let report = DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .inspect();
        assert!(report.experimental && report.possible_omissions);
        assert!(!report.complete_coverage);
        value["source"]["experimental"] = false.into();
        assert!(DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn rejects_object_graphs_scripts_duplicates_and_bad_shapes() {
        for field in ["path", "module", "factory", "connectionString", "artifact"] {
            let mut value = fixture();
            value[field] = "do-not-load-this".into();
            assert!(DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let mut value = fixture();
        let item = value["items"][0].clone();
        value["items"].as_array_mut().unwrap().push(item);
        assert!(DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(DatasetImportV1::parse(b"run_code()").is_err());
        value = fixture();
        value["items"][0]["value"] = "not-an-object".into();
        assert!(DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn bounds_complete_input_item_size_and_count() {
        assert!(matches!(
            DatasetImportV1::parse(&vec![b' '; MAX_IMPORT_BYTES + 1]),
            Err(ImportError::Limit)
        ));
        let mut value = fixture();
        value["items"][0]["value"]["text"] = "x".repeat(MAX_IMPORT_ITEM_BYTES).into();
        assert!(matches!(
            DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()),
            Err(ImportError::Limit)
        ));
        value = fixture();
        value["items"] = (0..=MAX_BATCH_ITEMS)
            .map(|i| serde_json::json!({"key":format!("item-{i}"),"value":{}}))
            .collect();
        assert!(matches!(
            DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()),
            Err(ImportError::Limit)
        ));
    }

    #[derive(Default)]
    struct TestAuthority {
        writes: std::sync::Mutex<Vec<Vec<u8>>>,
        commits: std::sync::Mutex<Vec<RequestCommitV1>>,
        reject_commit: bool,
    }

    #[async_trait::async_trait]
    impl ArtifactStore for TestAuthority {
        async fn put(
            &self,
            _: crate::CrawlRunId,
            _: crate::repo::Sensitivity,
            _: &str,
            _: &[u8],
        ) -> Result<crate::ArtifactRef, StoreError> {
            panic!("untyped storage must never be called")
        }

        async fn get(&self, _: &crate::ArtifactRef) -> Result<Vec<u8>, StoreError> {
            panic!("import must never dereference source artifacts")
        }

        async fn put_dataset_until(
            &self,
            _: crate::CrawlRunId,
            page: i64,
            _: &str,
            mime: &str,
            bytes: &[u8],
            _: Timestamp,
        ) -> Result<crate::ArtifactRef, StoreError> {
            assert_eq!(page, 7);
            assert_eq!(mime, "application/json");
            self.writes.lock().unwrap().push(bytes.to_vec());
            Ok(crate::ArtifactRef {
                id: crate::ArtifactId(uuid::Uuid::from_u128(2)),
                digest: crate::hash::Digest::of("import-test", bytes),
            })
        }

        async fn dataset_content(
            &self,
            _: crate::CrawlRunId,
            page: i64,
            artifact: &crate::ArtifactRef,
            _: u64,
        ) -> Result<super::super::DatasetContentV1, StoreError> {
            Ok(super::super::DatasetContentV1::Volatile {
                page,
                artifact: artifact.clone(),
                expires_at: deadline(),
            })
        }
    }

    #[async_trait::async_trait]
    impl crate::digest_registry::DigestRegistryRepo for TestAuthority {
        async fn digest_outcome(
            &self,
            _: crate::CrawlRunId,
            _: i64,
        ) -> Result<Option<crate::digest_registry::DigestOutcomeV1>, StoreError> {
            Err(StoreError::Unavailable(
                "test authority has no digest registry".into(),
            ))
        }
    }

    #[async_trait::async_trait]
    impl RequestCommitRepo for TestAuthority {
        async fn begin_feed_finalization(
            &self,
            _: crate::CrawlRunId,
            _: Option<crate::counters::TerminalReason>,
        ) -> Result<Option<crate::counters::TerminalReason>, StoreError> {
            panic!("dataset import must not begin feed finalization")
        }

        async fn stage_feed_batches(
            &self,
            _: crate::CrawlRunId,
            _: &[super::super::DeliveryBatchV1],
        ) -> Result<(), StoreError> {
            panic!("dataset import must not stage terminal feeds")
        }

        async fn staged_feed_batch(
            &self,
            _: crate::CrawlRunId,
            _: &str,
            _: &str,
        ) -> Result<Option<super::super::DeliveryBatchV1>, StoreError> {
            panic!("dataset import must not read staged terminal feeds")
        }

        async fn finalize_run_feeds(
            &self,
            _: crate::CrawlRunId,
            _: crate::counters::RunStatus,
            _: crate::counters::TerminalReason,
            _: &[super::super::DeliveryBatchV1],
        ) -> Result<(), StoreError> {
            panic!("dataset import must not finalize runs")
        }

        async fn lease_observed_fenced(
            &self,
            _: &crate::custody::CustodyLease,
            _: crate::ObservationEpoch,
            _: i64,
        ) -> Result<Option<(crate::repo::FrontierEntry, i64)>, StoreError> {
            panic!("dataset import must not lease observed receipts")
        }

        async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError> {
            if self.reject_commit {
                return Err(StoreError::Conflict("test stale fence".into()));
            }
            self.commits.lock().unwrap().push(commit);
            Ok(())
        }
    }

    fn deadline() -> Timestamp {
        chrono::DateTime::from_timestamp(1_900_000_000, 0).unwrap()
    }

    fn config() -> DatasetConfigV1 {
        serde_json::from_value(serde_json::json!({
            "stores":[{"name":"records","schemaVersion":"json_object_v1","maxItems":100,"maxBytes":1000000}]
        }))
        .unwrap()
    }

    fn commit() -> RequestCommitV1 {
        RequestCommitV1::terminal(
            crate::CrawlRunId(uuid::Uuid::from_u128(1)),
            7,
            11,
            3,
            FrontierStatus::Succeeded,
            None,
        )
    }

    #[tokio::test]
    async fn uses_typed_volatile_sink_and_real_fenced_commit_with_stable_identity() {
        let authority = TestAuthority::default();
        let mut value = fixture();
        value["items"][0]["value"]["password"] = "credential-import-canary".into();
        for _ in 0..2 {
            let import = DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
            commit_import(import, &config(), commit(), deadline(), &authority, &authority)
                .await
                .unwrap();
        }
        let writes = authority.writes.lock().unwrap();
        assert_eq!(writes.len(), 2);
        assert!(!writes
            .iter()
            .any(|bytes| String::from_utf8_lossy(bytes).contains("credential-import-canary")));
        let commits = authority.commits.lock().unwrap();
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].request_id, 7);
        assert_eq!(commits[0].fence, 11);
        assert_eq!(commits[0].expected_state_version, 3);
        let first = &commits[0].accepted[0].items[0];
        assert_eq!(first.item_key, commits[1].accepted[0].items[0].item_key);
        assert_eq!(first.expires_at, Some(deadline()));
        assert!(matches!(
            first.content,
            super::super::DatasetContentV1::Volatile { page: 7, .. }
        ));
    }

    #[tokio::test]
    async fn rejects_policy_before_writes_and_preserves_authority_failure() {
        let authority = TestAuthority {
            reject_commit: true,
            ..TestAuthority::default()
        };
        let mut value = fixture();
        value["policy"]["purgeOnStart"] = true.into();
        let import = DatasetImportV1::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(matches!(
            commit_import(import, &config(), commit(), deadline(), &authority, &authority).await,
            Err(ImportError::IncompatiblePolicy)
        ));
        assert!(authority.writes.lock().unwrap().is_empty());
        let import = DatasetImportV1::parse(&serde_json::to_vec(&fixture()).unwrap()).unwrap();
        assert!(matches!(
            commit_import(import, &config(), commit(), deadline(), &authority, &authority).await,
            Err(ImportError::Store(StoreError::Conflict(_)))
        ));
        assert!(authority.commits.lock().unwrap().is_empty());
    }

    #[test]
    fn rejects_duplicate_json_members() {
        assert!(DatasetImportV1::parse(br#"{"version":1,"version":2}"#).is_err());
    }
}
