//! Bounded accepted-item repositories, versioned state and leased delivery manifests.
//!
//! Content is written through the existing artifact sink before committing these references.
//! Request completion composes accepted items, state CAS and outbox insertion in one transaction.

use crate::repo::Sensitivity;
use crate::{ArtifactRef, CrawlRunId, StoreError, Timestamp, WorkerId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Maximum metadata records in one repository operation.
pub const MAX_BATCH_ITEMS: usize = 1000;
/// Maximum bytes in one value or delivery batch.
pub const MAX_VALUE_BYTES: u64 = 16 * 1024 * 1024;

/// Check a non-secret operator-declared identifier without echoing rejected input.
///
/// # Errors
/// Returns a conflict for empty, oversized, or non-identifier text.
pub fn validate_identifier(value: &str) -> Result<(), StoreError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(StoreError::Conflict("invalid dataset identifier".into()));
    }
    Ok(())
}

fn version_one() -> u16 {
    1
}

/// Immutable run-scoped dataset and feed declarations. Destination credentials are never inline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DatasetConfigV1 {
    /// Contract version, exactly one.
    #[serde(default = "version_one")]
    pub version: u16,
    /// Append-only datasets.
    #[serde(default)]
    pub stores: Vec<DatasetDeclarationV1>,
    /// Approved serializer/destination bindings.
    #[serde(default)]
    pub feeds: Vec<FeedDeclarationV1>,
    /// Versioned key-value namespaces.
    #[serde(default)]
    pub kv_stores: Vec<KvDeclarationV1>,
    /// Explicit article namespace. A single declared `document_v1` store is unambiguous by default.
    #[serde(default)]
    pub article_dataset: Option<String>,
}

impl Default for DatasetConfigV1 {
    fn default() -> Self {
        Self {
            version: 1,
            stores: Vec::new(),
            feeds: Vec::new(),
            kv_stores: Vec::new(),
            article_dataset: None,
        }
    }
}

impl DatasetConfigV1 {
    /// Validate bounded declarations and source references before accepting a run.
    ///
    /// # Errors
    /// Returns a conflict for unsupported versions, duplicate names or unbounded limits.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != 1 || self.stores.len() > 64 || self.feeds.len() > 64 || self.kv_stores.len() > 64 {
            return Err(StoreError::Conflict(
                "unsupported or oversized dataset configuration".into(),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for store in &self.stores {
            validate_identifier(&store.name)?;
            validate_identifier(&store.schema_version)?;
            if !names.insert(&store.name)
                || store.max_items == 0
                || store.max_items > i64::MAX.unsigned_abs()
                || store.max_bytes == 0
                || store.max_bytes > i64::MAX.unsigned_abs()
            {
                return Err(StoreError::Conflict(
                    "invalid dataset quota or duplicate name".into(),
                ));
            }
        }
        names.clear();
        for store in &self.kv_stores {
            validate_identifier(&store.name)?;
            if !names.insert(&store.name)
                || store.max_keys == 0
                || store.max_keys > 1_000_000
                || store.max_value_bytes == 0
                || store.max_value_bytes > MAX_VALUE_BYTES
                || store.max_bytes == 0
                || store.max_bytes > i64::MAX.unsigned_abs()
            {
                return Err(StoreError::Conflict("invalid kv quota or duplicate name".into()));
            }
        }
        names.clear();
        for feed in &self.feeds {
            validate_identifier(&feed.id)?;
            validate_identifier(&feed.destination)?;
            validate_identifier(&feed.serializer)?;
            if !names.insert(&feed.id)
                || !self.stores.iter().any(|s| s.name == feed.source)
                || feed.max_batch_items == 0
                || usize::from(feed.max_batch_items) > MAX_BATCH_ITEMS
                || feed.max_batch_bytes == 0
                || feed.max_batch_bytes > MAX_VALUE_BYTES
                || feed.serializer_version != 1
            {
                return Err(StoreError::Conflict(
                    "invalid feed source, version or bounds".into(),
                ));
            }
            let source = self
                .stores
                .iter()
                .find(|store| store.name == feed.source)
                .ok_or_else(|| StoreError::Conflict("undeclared feed source".into()))?;
            let compatible = match source.schema_version.as_str() {
                "document_item_v1" => matches!(feed.serializer.as_str(), "json" | "jsonl" | "csv" | "xml"),
                "document_v1" => matches!(
                    feed.serializer.as_str(),
                    "json" | "jsonl" | "csv" | "xml" | "tei" | "text" | "markdown" | "html" | "search_json"
                ),
                "search_projection_v1" => matches!(feed.serializer.as_str(), "json" | "jsonl"),
                _ => false,
            };
            if !compatible {
                return Err(StoreError::Conflict(
                    "feed serializer is incompatible with source schema".into(),
                ));
            }
        }
        self.article_store()?;
        Ok(())
    }

    /// Select only an explicit or unambiguous article namespace, never an arbitrary first store.
    ///
    /// # Errors
    /// Returns a conflict for a missing/wrong-schema explicit name or ambiguous article declarations.
    pub fn article_store(&self) -> Result<Option<&DatasetDeclarationV1>, StoreError> {
        if let Some(name) = &self.article_dataset {
            return self
                .stores
                .iter()
                .find(|store| store.name == *name && store.schema_version == "document_v1")
                .map(Some)
                .ok_or_else(|| {
                    StoreError::Conflict("article dataset is missing or has wrong schema".into())
                });
        }
        let mut stores = self
            .stores
            .iter()
            .filter(|store| store.schema_version == "document_v1");
        let selected = stores.next();
        if stores.next().is_some() {
            return Err(StoreError::Conflict(
                "multiple article datasets require explicit articleDataset".into(),
            ));
        }
        Ok(selected)
    }
}

/// Run-local accepted-item namespace. Cross-run authority is deliberately not implicit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DatasetDeclarationV1 {
    /// Non-secret namespace.
    pub name: String,
    /// Approved schema identifier and version.
    pub schema_version: String,
    /// Maximum committed items.
    pub max_items: u64,
    /// Maximum committed content bytes.
    pub max_bytes: u64,
}

/// Versioned key-value namespace with immutable deployment-bounded quotas.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct KvDeclarationV1 {
    /// Non-secret namespace.
    pub name: String,
    /// Maximum live keys, including retained tombstones for CAS history.
    pub max_keys: u32,
    /// Maximum bytes in one value.
    pub max_value_bytes: u64,
    /// Maximum bytes in live values.
    pub max_bytes: u64,
}

/// Immutable serializer and operator-approved destination binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct FeedDeclarationV1 {
    /// Non-secret feed identifier.
    pub id: String,
    /// Declared dataset name.
    pub source: String,
    /// Registered serializer identifier.
    pub serializer: String,
    /// Serializer implementation contract version.
    pub serializer_version: u16,
    /// Operator registry identifier, never a target-supplied URL or path.
    pub destination: String,
    /// Maximum records in one immutable delivery.
    pub max_batch_items: u16,
    /// Maximum bytes in one immutable delivery.
    pub max_batch_bytes: u64,
}

/// Retention-aware content reference. A volatile handle cannot become a durable artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum DatasetContentV1 {
    /// Approved retained artifact, already written by the typed artifact sink.
    Durable {
        /// Artifact capability.
        artifact: ArtifactRef,
    },
    /// Shared volatile rendition with the original immutable page deadline.
    Volatile {
        /// Original page namespace, used for acknowledgement erasure.
        page: i64,
        /// Artifact capability held only in volatile metadata for ZDR.
        artifact: ArtifactRef,
        /// Original deadline; no retry may extend it.
        expires_at: Timestamp,
    },
}

impl DatasetContentV1 {
    /// Borrow the reference without copying content.
    #[must_use]
    pub const fn artifact(&self) -> &ArtifactRef {
        match self {
            Self::Durable { artifact } | Self::Volatile { artifact, .. } => artifact,
        }
    }
    /// Original volatile deadline, when applicable.
    #[must_use]
    pub const fn expires_at(&self) -> Option<Timestamp> {
        match self {
            Self::Durable { .. } => None,
            Self::Volatile { expires_at, .. } => Some(*expires_at),
        }
    }
}

/// Accepted item metadata; bytes never enter the relational transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AcceptedItemV1 {
    /// Non-secret stable key within the source request and transform version.
    pub item_key: String,
    /// Transform implementation identifier/version.
    pub transform_version: String,
    /// Schema identifier/version.
    pub schema_version: String,
    /// Extractor identifier/version.
    pub extractor_version: String,
    /// Source document identifier; absent when unavailable.
    pub source_document: Option<crate::hash::Digest>,
    /// Already stored, policy-authorized content.
    pub content: DatasetContentV1,
    /// Exact approved content length.
    pub size_bytes: u64,
    /// Artifact sensitivity; operational secrets are not dataset values.
    pub sensitivity: Sensitivity,
    /// Deadline bounded by run and original content expiry.
    pub expires_at: Option<Timestamp>,
}

impl AcceptedItemV1 {
    /// Build accepted metadata from an already authorized content handle.
    #[must_use]
    pub fn new(
        item_key: String,
        transform_version: String,
        schema_version: String,
        extractor_version: String,
        content: DatasetContentV1,
        size_bytes: u64,
    ) -> Self {
        let expires_at = content.expires_at();
        Self {
            item_key,
            transform_version,
            schema_version,
            extractor_version,
            source_document: None,
            content,
            size_bytes,
            sensitivity: Sensitivity::Content,
            expires_at,
        }
    }
}

/// Append batch coupled to the live request fence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct AcceptedBatchV1 {
    /// Declared dataset namespace.
    pub dataset: String,
    /// Bounded immutable candidates.
    pub items: Vec<AcceptedItemV1>,
}

impl AcceptedBatchV1 {
    /// Couple bounded candidates to a declared dataset namespace.
    #[must_use]
    pub fn new(dataset: String, items: Vec<AcceptedItemV1>) -> Self {
        Self { dataset, items }
    }
}

/// Committed keyset item with stable monotone ordinal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DatasetItemV1 {
    /// Committed ordinal; also the stable item ID within this namespace.
    pub ordinal: u64,
    /// Source frontier request.
    pub source_request: i64,
    /// Browser action source; request ID is zero only for this explicitly typed source.
    pub source_action: Option<crate::ActionId>,
    /// Accepted metadata and content capability.
    pub item: AcceptedItemV1,
}

impl DatasetItemV1 {
    /// Construct metadata after allocating a committed ordinal.
    #[must_use]
    pub const fn new(ordinal: u64, source_request: i64, item: AcceptedItemV1) -> Self {
        Self {
            ordinal,
            source_request,
            source_action: None,
            item,
        }
    }
}

/// Versioned key-value update. `None` content writes a tombstone without resetting its version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct KvCasV1 {
    /// Declared namespace.
    pub store: String,
    /// Validated non-secret key.
    pub key: String,
    /// Zero means absent; all later updates require the exact observed version.
    pub expected_version: u64,
    /// Already stored value, or deletion.
    pub content: Option<DatasetContentV1>,
    /// MIME type of the value.
    pub content_type: String,
    /// Value bytes; zero for deletion.
    pub size_bytes: u64,
    /// Immutable deadline for this key generation.
    pub expires_at: Option<Timestamp>,
}

/// Versioned value metadata, including deletion state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct KvValueV1 {
    /// Current monotone version.
    pub version: u64,
    /// Last applied delta; expected version is the previous version.
    pub value: KvCasV1,
}

impl KvValueV1 {
    /// Pair a checked monotone version with its applied delta.
    #[must_use]
    pub const fn new(version: u64, value: KvCasV1) -> Self {
        Self { version, value }
    }
}

/// Source range proposed before commit or fixed after its atomic ordinal allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum DeliveryRangeV1 {
    /// Resolve this request's newly accepted item range inside the same transaction.
    AcceptedRequest,
    /// Already committed immutable keyset interval.
    Committed {
        /// First included ordinal.
        first: u64,
        /// Last included ordinal.
        last: u64,
    },
}

/// Immutable delivery batch, inserted only with its accepted source commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DeliveryBatchV1 {
    /// Declared feed identifier.
    pub feed: String,
    /// Stable non-secret batch idempotency key, independent of attempts.
    pub idempotency_key: String,
    /// Immutable serialized artifact prepared through the typed sink.
    pub content: DatasetContentV1,
    /// Exact byte length.
    pub size_bytes: u64,
    /// Atomic source allocation; durable manifests always contain a committed range.
    pub range: DeliveryRangeV1,
    /// Delivery deadline, never later than volatile content expiry.
    pub expires_at: Timestamp,
}

impl DeliveryBatchV1 {
    /// Prepare an immutable feed artifact for this request's accepted records.
    #[must_use]
    pub fn for_request(
        feed: String,
        idempotency_key: String,
        content: DatasetContentV1,
        size_bytes: u64,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            feed,
            idempotency_key,
            content,
            size_bytes,
            range: DeliveryRangeV1::AcceptedRequest,
            expires_at,
        }
    }
}

/// Honest durable delivery state; transport success is separate from accepted-item commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeliveryStateV1 {
    /// Eligible after not-before.
    Pending,
    /// Held by one worker until its deadline.
    Leased,
    /// Positively acknowledged by the configured destination.
    Delivered,
    /// Original content or delivery deadline ended.
    ContentExpired,
}

/// Durable receipt and current fenced lease. ZDR manifests themselves remain volatile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct DurableDeliveryOutboxV1 {
    /// Opaque relational identifier.
    pub id: i64,
    /// Owning run.
    pub run: CrawlRunId,
    /// Immutable batch descriptor.
    pub batch: DeliveryBatchV1,
    /// Current lease fence.
    pub fence: i64,
    /// Charged claim attempts.
    pub attempts: u32,
    /// Current durable state.
    pub state: DeliveryStateV1,
}

impl DurableDeliveryOutboxV1 {
    /// Construct a pending immutable intent.
    #[must_use]
    pub const fn pending(id: i64, run: CrawlRunId, batch: DeliveryBatchV1) -> Self {
        Self {
            id,
            run,
            batch,
            fence: 0,
            attempts: 0,
            state: DeliveryStateV1::Pending,
        }
    }
}

/// Append-oriented reads. Writes belong to `RequestCommitRepo`, not a second transaction.
#[async_trait]
pub trait DatasetRepo: Send + Sync {
    /// Read a bounded keyset page strictly after `after`; expired values are unavailable.
    ///
    /// # Errors
    /// Returns invalid-bound, unknown-namespace, retention or backend errors.
    async fn items(
        &self,
        run: CrawlRunId,
        dataset: &str,
        after: u64,
        limit: u16,
    ) -> Result<Vec<DatasetItemV1>, StoreError>;
}

/// Run-scoped typed state; no global mutable service locator.
#[async_trait]
pub trait KvRepo: Send + Sync {
    /// Read current value metadata, including tombstones.
    ///
    /// # Errors
    /// Returns retention errors for expired content and backend errors.
    async fn value(&self, run: CrawlRunId, store: &str, key: &str) -> Result<Option<KvValueV1>, StoreError>;
    /// Apply one exact-version change atomically.
    ///
    /// # Errors
    /// Returns conflict for CAS collisions, quota, or undeclared namespace.
    async fn compare_and_set(&self, run: CrawlRunId, delta: KvCasV1) -> Result<KvValueV1, StoreError>;
    /// List bounded metadata strictly after a validated key.
    ///
    /// # Errors
    /// Returns invalid-bound, namespace, retention or backend errors.
    async fn keys(
        &self,
        run: CrawlRunId,
        store: &str,
        after: &str,
        limit: u16,
    ) -> Result<Vec<KvValueV1>, StoreError>;
    /// Irrevocably drop a declared namespace for this run, including every key.
    /// A dropped namespace cannot be recreated, so old versions never become create-version zero.
    ///
    /// # Errors
    /// Returns unknown namespace, tenant authority or backend errors.
    async fn drop_store(&self, run: CrawlRunId, store: &str) -> Result<(), StoreError>;
}

/// Durable leased delivery intents, sharing existing database/clock authorities.
#[async_trait]
pub trait DeliveryOutboxRepo: Send + Sync {
    /// List runs with due deliveries or receipt cleanup, including terminal runs.
    ///
    /// # Errors
    /// Returns invalid-bound or repository authority errors.
    async fn ready_runs(&self, after: Option<CrawlRunId>, limit: u16) -> Result<Vec<CrawlRunId>, StoreError>;
    /// Retire expired intents and retry physical volatile erasure without loading expired config.
    ///
    /// # Errors
    /// Returns scope or storage/erasure failures; durable receipts remain retryable.
    async fn maintain(&self, run: CrawlRunId) -> Result<(), StoreError>;
    /// Retire an expired batch under its current fence without sending its content.
    ///
    /// # Errors
    /// Returns lease-lost if the batch is not expired or the fence changed.
    async fn expire(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError>;
    /// Claim bounded eligible deliveries with a new fence per claim.
    ///
    /// # Errors
    /// Returns validation, expiry or backend errors.
    async fn claim(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        limit: u16,
        lease_seconds: u16,
    ) -> Result<Vec<DurableDeliveryOutboxV1>, StoreError>;
    /// Acknowledge only a live fence; successful ZDR acknowledgement erases shared content.
    ///
    /// # Errors
    /// Returns lease-lost or backend/erasure errors.
    async fn acknowledge(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError>;
    /// Release only a live fence to a bounded later retry time, without changing batch identity.
    ///
    /// # Errors
    /// Returns lease-lost, invalid-time or backend errors.
    async fn retry(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        not_before: Timestamp,
    ) -> Result<(), StoreError>;
}
