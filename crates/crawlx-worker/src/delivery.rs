//! Operator-approved feed delivery. Page content can name neither a destination nor credentials.
//!
//! Accepted-item/outbox insertion is atomic; network transmission is at-least-once. Immutable
//! object keys and logical search IDs make retries idempotent where the destination supports it.
//! Stdout, FTP gateways and generic HTTP endpoints may duplicate after an acknowledged-send crash.

use crate::runtime::CpuPool;
use crate::stores::Stores;
use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use crawlx_core::config::RetentionMode;
use crawlx_core::dataset::{DeliveryBatchV1, DurableDeliveryOutboxV1, MAX_VALUE_BYTES};
use crawlx_core::repo::{ArtifactStore, CrawlRun};
use crawlx_core::secret::{ArtifactSink, Redacted, Redactor};
use crawlx_core::{Clock, StoreError, WorkerId};
use crawlx_extract::serialize::{write_article, ArticleFormat, ArticleStream};
use crawlx_storage::ArtifactBlobs;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use url::Url;
mod compression;
mod config;
mod feed_policy;
pub(crate) use feed_policy::{finalize_feeds, take_fragments as take_feed_fragments};
mod recovery;
pub(crate) use recovery::recover_once;
mod article_cache;
pub(crate) use article_cache::{load_article_cache, store_article_cache};
#[cfg(test)]
#[path = "delivery/tests.rs"]
mod tests;

/// Existing run egress and pacing authorities, borrowed rather than duplicated.
#[derive(Clone)]
pub struct DeliveryAuthority {
    /// Current run's hard egress policy.
    pub policy: Arc<crawlx_policy::egress::EgressPolicy>,
    /// Existing checked resolver.
    pub resolver: Arc<dyn crawlx_fetch::Resolver>,
    /// Same governor used by target/helper/browser traffic.
    pub governor: Arc<crawlx_fetch::OriginGovernor>,
    /// Existing run cancellation tree.
    pub cancel: CancellationToken,
}

/// Delivery failures omit endpoints, credentials, payloads and provider error bodies.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeliveryError {
    /// Existing repository/artifact policy refused work.
    #[error("delivery storage failed")]
    Store(#[from] StoreError),
    /// Provider transport failed; source remains available without displaying its URL.
    #[error("delivery HTTP request failed")]
    Http(#[from] reqwest::Error),
    /// Approved local output failed.
    #[error("delivery local output failed")]
    Io(#[from] std::io::Error),
    /// Existing checked resolver/governor operation failed.
    #[error("delivery checked egress failed")]
    Fetch(#[from] crawlx_fetch::FetchError),
    /// Operator credential reference resolution failed.
    #[error("delivery provider credential resolution failed")]
    Credential(#[source] crawlx_core::CoreError),
    /// A declared capability or response contract is unavailable.
    #[error("delivery capability unavailable: {0}")]
    Unavailable(&'static str),
    /// Destination did not positively acknowledge all records.
    #[error("delivery destination rejected batch: {0}")]
    Rejected(&'static str),
    /// Provider requested a bounded cooldown; no response body or endpoint is retained.
    #[error("delivery provider cooldown")]
    ProviderBackoff(Duration),
}

impl crawlx_core::Classify for DeliveryError {
    fn class(&self) -> crawlx_core::ErrorClass {
        use crawlx_core::ErrorClass;
        match self {
            Self::Store(error) => error.class(),
            Self::Fetch(error) => match error {
                crawlx_fetch::FetchError::EgressDenied(_)
                | crawlx_fetch::FetchError::PeerNotPinned { .. } => ErrorClass::PolicyDenied,
                crawlx_fetch::FetchError::Resolve { .. }
                | crawlx_fetch::FetchError::OriginAdmission(_)
                | crawlx_fetch::FetchError::Io(_) => ErrorClass::Retryable,
                crawlx_fetch::FetchError::Timeout(_) | crawlx_fetch::FetchError::Transport(_) => {
                    ErrorClass::OutcomeUnknown
                }
                _ => ErrorClass::Terminal,
            },
            Self::Credential(error) => error.class(),
            Self::Http(_) | Self::Io(_) => ErrorClass::OutcomeUnknown,
            Self::ProviderBackoff(_) => ErrorClass::Retryable,
            Self::Unavailable(_) | Self::Rejected(_) => ErrorClass::Terminal,
        }
    }
}

/// One compiled operator-approved destination. Implementations cannot discover new destinations.
#[async_trait]
pub trait DeliveryDestination: Send + Sync {
    /// Whether acknowledged retries can duplicate externally visible records.
    fn duplicate_possible(&self) -> bool;
    /// Whether content may leave volatile retention (false for local/object persistence).
    fn permits_zdr(&self) -> bool;
    /// Whether this sink preserves pre-compressed feed artifacts as opaque bytes.
    /// Structured or external implementations must explicitly opt in; transport encoding differs.
    fn permits_feed_compression(&self) -> bool {
        false
    }
    /// Account for bounded encoding/acknowledgement buffers in the existing shared spool quota.
    fn working_bytes(&self, input: u64) -> Option<u64> {
        Some(input)
    }
    /// Deliver one immutable, bounded artifact under its stable idempotency key.
    ///
    /// # Errors
    /// Returns transport, policy or missing acknowledgement failures without payload diagnostics.
    async fn send(
        &self,
        authority: &DeliveryAuthority,
        run: &CrawlRun,
        batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError>;
}

/// Immutable operator registry, shared by all runs. Tenant/page config contains IDs only.
#[derive(Clone, Default)]
pub struct DeliveryRegistry {
    destinations: BTreeMap<String, Arc<dyn DeliveryDestination>>,
    authorities:
        Arc<parking_lot::Mutex<BTreeMap<crawlx_core::CrawlRunId, std::sync::Weak<DeliveryAuthority>>>>,
}
impl std::fmt::Debug for DeliveryRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryRegistry")
            .field("destinations", &self.destinations.keys().collect::<Vec<_>>())
            .finish()
    }
}
impl DeliveryRegistry {
    pub(crate) fn register_authority(
        &self,
        run: crawlx_core::CrawlRunId,
        authority: &Arc<DeliveryAuthority>,
    ) {
        let mut authorities = self.authorities.lock();
        authorities.retain(|_, authority| authority.strong_count() > 0);
        authorities.insert(run, Arc::downgrade(authority));
    }
    pub(crate) fn active_authority(&self, run: crawlx_core::CrawlRunId) -> Option<Arc<DeliveryAuthority>> {
        self.authorities
            .lock()
            .get(&run)
            .and_then(std::sync::Weak::upgrade)
    }
    /// Empty registry: declaring a feed without a registered destination fails admission.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a reviewed destination during operator startup, never from target data.
    ///
    /// # Errors
    /// Returns a conflict for invalid IDs or duplicate registrations.
    pub fn register(
        &mut self,
        id: String,
        destination: Arc<dyn DeliveryDestination>,
    ) -> Result<(), StoreError> {
        crawlx_core::dataset::validate_identifier(&id)?;
        if self.destinations.contains_key(&id) {
            return Err(StoreError::Conflict("duplicate delivery destination".into()));
        }
        self.destinations.insert(id, destination);
        Ok(())
    }
    /// Check feed serializers and destination privacy before acquisition starts.
    ///
    /// # Errors
    /// Returns unavailable or retention errors for undeclared capabilities.
    pub fn validate(&self, run: &CrawlRun) -> Result<(), DeliveryError> {
        self.validate_config(&run.config)
    }
    /// Check declared feeds against the operator registry before target I/O.
    ///
    /// # Errors
    /// Returns unsupported serializer, destination or retention errors.
    pub fn validate_config(&self, config: &crawlx_core::config::CreateCrawl) -> Result<(), DeliveryError> {
        config.datasets.validate()?;
        for feed in &config.datasets.feeds {
            article_format(&feed.serializer)?;
            let destination = self
                .destinations
                .get(&feed.destination)
                .ok_or(DeliveryError::Unavailable("approved_destination_not_registered"))?;
            if feed.compression != crawlx_core::dataset::FeedCompressionV1::None
                && !destination.permits_feed_compression()
            {
                return Err(DeliveryError::Unavailable(
                    "feed_compression_unsupported_for_sink",
                ));
            }
            if config.retention.mode == RetentionMode::Zdr && !destination.permits_zdr() {
                return Err(DeliveryError::Unavailable("destination_forbids_zdr_persistence"));
            }
        }
        Ok(())
    }
    /// Return bounded destination IDs and their explicit volatile-retention allowance.
    #[must_use]
    pub fn capabilities(&self) -> BTreeMap<String, bool> {
        self.destinations
            .iter()
            .map(|(id, destination)| (id.clone(), destination.permits_zdr()))
            .collect()
    }
    /// Claim and deliver at most one record under existing repository leases.
    ///
    /// # Errors
    /// Returns storage, transport or acknowledgement errors. Failed sends retain immutable intent.
    pub async fn drain_once(
        &self,
        stores: &Stores,
        run: &CrawlRun,
        worker: WorkerId,
        clock: &dyn Clock,
        authority: &DeliveryAuthority,
    ) -> Result<usize, DeliveryError> {
        self.validate(run)?;
        let claims = stores.delivery.claim(run.id, worker, 1, 60).await?;
        let mut delivered = 0usize;
        for claim in claims {
            let feed = run
                .config
                .datasets
                .feeds
                .iter()
                .find(|feed| feed.id == claim.batch.feed)
                .ok_or(DeliveryError::Unavailable("committed_feed_missing"))?;
            let destination = self
                .destinations
                .get(&feed.destination)
                .ok_or(DeliveryError::Unavailable("approved_destination_not_registered"))?;
            let spool = stores
                .delivery_spool
                .as_ref()
                .ok_or(DeliveryError::Unavailable("shared_artifact_spool_required"))?;
            let working = destination
                .working_bytes(claim.batch.size_bytes)
                .ok_or(DeliveryError::Unavailable("delivery_working_byte_overflow"))?;
            let _reservation = spool.reserve_delivery(working)?;
            if claim.batch.expires_at <= clock.now() {
                stores.delivery.expire(run.id, claim.id, claim.fence).await?;
                continue;
            }
            let bytes = match &claim.batch.content {
                crawlx_core::dataset::DatasetContentV1::Durable { artifact } => {
                    stores
                        .artifacts
                        .read_archive_content(run.tenant, run.id, artifact, claim.batch.size_bytes)
                        .await?
                }
                crawlx_core::dataset::DatasetContentV1::Volatile { page, artifact, .. } => {
                    stores
                        .artifacts
                        .dataset_content(run.id, *page, artifact, claim.batch.size_bytes)
                        .await?;
                    stores.artifacts.get(artifact).await?
                }
                _ => return Err(DeliveryError::Unavailable("unsupported_delivery_content_handle")),
            };
            if u64::try_from(bytes.len()).ok() != Some(claim.batch.size_bytes) {
                return Err(DeliveryError::Rejected("immutable_batch_size_mismatch"));
            }
            let remaining = (claim.batch.expires_at - clock.now())
                .to_std()
                .map_err(|_| DeliveryError::Unavailable("delivery_content_expired"))?
                .min(Duration::from_secs(30));
            let send = tokio::select! {
                () = authority.cancel.cancelled() => return Err(DeliveryError::Unavailable("delivery_cancelled")),
                result = tokio::time::timeout(remaining, destination.send(authority,run,&claim.batch,Bytes::from(bytes))) =>
                    result.unwrap_or_else(|_| Err(DeliveryError::Unavailable("delivery_deadline_exceeded"))),
            };
            match send {
                Ok(()) => {
                    stores.delivery.acknowledge(run.id, claim.id, claim.fence).await?;
                    delivered = delivered.saturating_add(1);
                }
                Err(error) => {
                    let delay = match &error {
                        DeliveryError::ProviderBackoff(delay) => *delay,
                        _ => Duration::from_secs(30),
                    };
                    let delay = chrono::Duration::from_std(
                        delay
                            .max(Duration::from_secs(30))
                            .min(Duration::from_secs(86_400)),
                    )
                    .map_err(|_| DeliveryError::Unavailable("retry_timestamp_overflow"))?;
                    let retry = clock
                        .now()
                        .checked_add_signed(delay)
                        .ok_or(DeliveryError::Unavailable("retry_timestamp_overflow"))?
                        .min(claim.batch.expires_at);
                    if claim.batch.expires_at > clock.now() {
                        stores
                            .delivery
                            .retry(run.id, claim.id, claim.fence, retry)
                            .await?;
                    } else {
                        stores.delivery.expire(run.id, claim.id, claim.fence).await?;
                    }
                    return Err(error);
                }
            }
        }
        Ok(delivered)
    }
    /// Operator-visible delivery semantics; this is not an exactly-once transmission claim.
    #[must_use]
    pub fn duplicate_possible(&self, id: &str) -> Option<bool> {
        self.destinations
            .get(id)
            .map(|destination| destination.duplicate_possible())
    }
}

fn article_format(id: &str) -> Result<ArticleFormat, DeliveryError> {
    match id {
        "json" | "search_json" => Ok(ArticleFormat::Json),
        "jsonl" => Ok(ArticleFormat::Jsonl),
        "csv" => Ok(ArticleFormat::Csv),
        "xml" => Ok(ArticleFormat::Xml),
        "tei" => Ok(ArticleFormat::Tei),
        "text" => Ok(ArticleFormat::Text),
        "markdown" => Ok(ArticleFormat::Markdown),
        "html" => Ok(ArticleFormat::Html),
        _ => Err(DeliveryError::Unavailable("serializer_not_registered")),
    }
}

/// Shared capped serialization buffer; refuses a write before growing past its byte limit.
pub(crate) struct LimitedOutput {
    /// Serialized bytes already admitted by the cap.
    pub(crate) bytes: Vec<u8>,
    /// Hard output length, independent of the allocation's capacity.
    pub(crate) maximum: usize,
    allocation_error: Option<(usize, std::collections::TryReserveError)>,
}
impl LimitedOutput {
    /// Start without allocating; each write reserves capped geometric growth fallibly.
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            allocation_error: None,
        }
    }

    /// Take an original allocation failure without coercing unrelated serializer errors.
    pub(crate) fn take_allocation_error(&mut self) -> Option<StoreError> {
        self.allocation_error
            .take()
            .map(|(requested, source)| StoreError::ResourceExhausted {
                resource: "article_output_buffer",
                requested,
                available: self.bytes.capacity(),
                source: Some(source),
            })
    }

    /// Recover an allocation failure instead of losing it in a serializer's I/O error.
    pub(crate) fn serialization_error(&mut self, message: &'static str) -> StoreError {
        self.take_allocation_error()
            .unwrap_or_else(|| StoreError::Serialization(message.into()))
    }
}
impl Write for LimitedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.allocation_error.is_some() {
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        let size = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|size| *size <= self.maximum)
            .ok_or_else(|| std::io::Error::other("feed output byte limit"))?;
        if size > self.bytes.capacity() {
            let capacity = self
                .bytes
                .capacity()
                .saturating_mul(2)
                .max(256 * 1024)
                .max(size)
                .min(self.maximum);
            if let Err(source) = self.bytes.try_reserve_exact(capacity - self.bytes.len()) {
                self.allocation_error = Some((capacity, source));
                return Err(std::io::ErrorKind::OutOfMemory.into());
            }
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ArticleSearchView<'a> {
    version: u16,
    document_id: String,
    parent_id: Option<&'a str>,
    deleted: bool,
    extractor_version: &'a str,
    fields: BTreeMap<&'a str, &'a str>,
}

#[allow(clippy::too_many_arguments)]
async fn prepare_article_feeds_inner(
    artifacts: &dyn ArtifactStore,
    cpu: &CpuPool,
    run: &CrawlRun,
    page: i64,
    dataset: &str,
    mut document: Box<crawlx_extract::Document>,
    acquisition_accepted: bool,
    source_deadline: Option<crawlx_core::Timestamp>,
    source: &str,
) -> Result<(Box<crawlx_extract::Document>, Vec<DeliveryBatchV1>), StoreError> {
    let mut batches = Vec::new();
    for feed in run
        .config
        .datasets
        .feeds
        .iter()
        .filter(|feed| feed.source == dataset)
    {
        if !feed_policy::article_matches(feed, &document) {
            continue;
        }
        let format = article_format(&feed.serializer)
            .map_err(|_| StoreError::Conflict("unsupported article feed serializer".into()))?;
        let maximum = usize::try_from(feed.max_batch_bytes.min(MAX_VALUE_BYTES))
            .map_err(|_| StoreError::Conflict("feed byte limit overflow".into()))?;
        let search_json = feed.serializer == "search_json";
        let codec = feed_policy::codec(feed);
        let reservation = cpu.try_reserve_article_output(compression::reservation_bytes(codec, maximum)?)?;
        let source = source.to_owned();
        let feed_options = feed.clone();
        let parameter_cpu = cpu.clone();
        // Produce one bounded output at a time. The pool owns all source buffers
        // until serialization and canonical lineage/privacy approval finish.
        let (returned, approved, reservation) = cpu
            .run(move || {
                let article = document
                    .article
                    .as_ref()
                    .filter(|article| {
                        acquisition_accepted
                            && article.quality.status == crawlx_core::extraction::QualityStatusV1::Accepted
                            && article.privacy_projection_version == Some(1)
                    })
                    .ok_or_else(|| {
                        StoreError::RetentionDenied("only validated accepted articles can enter feeds".into())
                    })?;
                let mut output = LimitedOutput::new(maximum);
                if search_json {
                    let mut fields = BTreeMap::new();
                    if let Some(title) = &article.metadata.title.value {
                        fields.insert("title", title.as_str());
                    }
                    fields.insert("text", document.text.as_str());
                    fields.insert("comments", document.comments.as_str());
                    let projection = ArticleSearchView {
                        version: 1,
                        document_id: source,
                        parent_id: None,
                        deleted: false,
                        extractor_version: "native_article_v1",
                        fields,
                    };
                    serde_json::to_writer(&mut output, &projection)
                        .map_err(|_| output.serialization_error("search projection serialization failed"))?;
                } else if feed_policy::article_parameters(
                    &mut output,
                    &document,
                    &source,
                    &feed_options,
                    &parameter_cpu,
                )? {
                    // Explicit columns use only the approved article CSV field projection.
                } else {
                    let serialized = (|| {
                        let mut stream = ArticleStream::begin(&mut output, format)
                            .map_err(|_| "article feed framing failed")?;
                        stream
                            .push(&source, &document)
                            .map_err(|_| "article feed serialization failed")?;
                        stream.finish().map_err(|_| "article feed framing failed")
                    })();
                    serialized.map_err(|message| output.serialization_error(message))?;
                }
                let output = feed_policy::pretty_json(output, &feed_options, maximum, &parameter_cpu)?;
                let approved = Redactor::new().verify_canonical_owned(output.bytes)?;
                let approved = compression::encode_approved(approved, codec, maximum)?;
                Ok::<_, StoreError>((document, approved, reservation))
            })
            .await
            .map_err(|_| StoreError::Backend("article feed CPU task failed".into()))??;
        // Tuple fields drop in order: approved bytes before their reservation, even on cancellation.
        let output = (approved, reservation);
        document = returned;
        let size = u64::try_from(output.0.as_ref().len())
            .map_err(|_| StoreError::Conflict("feed length overflow".into()))?;
        let mime = match format {
            ArticleFormat::Json => "application/json",
            ArticleFormat::Jsonl => "application/x-ndjson",
            ArticleFormat::Csv => "text/csv",
            ArticleFormat::Xml | ArticleFormat::Tei => "application/xml",
            ArticleFormat::Html => "text/html",
            _ => "text/plain",
        };
        let mime = compression::media_type(codec, mime)?;
        let artifact = put_approved(
            artifacts,
            run,
            page,
            &format!("feed.{}", crawlx_core::dataset::feed_key_component(&feed.id)),
            mime,
            &output.0,
            source_deadline,
        )
        .await?;
        let content = artifacts.dataset_content(run.id, page, &artifact, size).await?;
        drop(output);
        let deadline = content
            .expires_at()
            .or(article_deadline(run, source_deadline))
            .ok_or_else(|| StoreError::RetentionDenied("feed deadline unavailable".into()))?;
        let key = format!(
            "request.{page}.{}",
            crawlx_core::dataset::feed_key_component(&feed.id)
        );
        batches.push(DeliveryBatchV1::for_request(
            feed.id.clone(),
            key,
            content,
            size,
            deadline,
        ));
    }
    Ok((document, batches))
}

/// Prepare accepted article and feed intents on the bounded CPU pool, returning the unchanged source.
///
/// # Errors
/// Returns declaration, missing privacy projection, serializer, retention or quota errors.
pub async fn prepare_article_acceptance(
    artifacts: &dyn ArtifactStore,
    cpu: &CpuPool,
    run: &CrawlRun,
    page: i64,
    document: Box<crawlx_extract::Document>,
    acquisition_accepted: bool,
) -> Result<
    (
        Box<crawlx_extract::Document>,
        Vec<crawlx_core::dataset::AcceptedBatchV1>,
        Vec<DeliveryBatchV1>,
    ),
    StoreError,
> {
    prepare_article_acceptance_retained(
        artifacts,
        cpu,
        run,
        page,
        document,
        acquisition_accepted,
        None,
        &format!("{}:document:{page}", run.id),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_article_acceptance_retained(
    artifacts: &dyn ArtifactStore,
    cpu: &CpuPool,
    run: &CrawlRun,
    page: i64,
    document: Box<crawlx_extract::Document>,
    acquisition_accepted: bool,
    source_deadline: Option<crawlx_core::Timestamp>,
    source: &str,
) -> Result<
    (
        Box<crawlx_extract::Document>,
        Vec<crawlx_core::dataset::AcceptedBatchV1>,
        Vec<DeliveryBatchV1>,
    ),
    StoreError,
> {
    use crawlx_core::dataset::{AcceptedBatchV1, AcceptedItemV1};
    let Some(store) = run.config.datasets.article_store()? else {
        return Ok((document, Vec::new(), Vec::new()));
    };
    let Some(article) = document.article.as_ref().filter(|article| {
        acquisition_accepted && article.quality.status == crawlx_core::extraction::QualityStatusV1::Accepted
    }) else {
        return Ok((document, Vec::new(), Vec::new()));
    };
    if article.privacy_projection_version != Some(1) {
        return Err(StoreError::RetentionDenied(
            "article privacy projection is required before ingestion".into(),
        ));
    }
    let source_document = article.main_digest;
    let maximum = usize::try_from(MAX_VALUE_BYTES)
        .map_err(|_| StoreError::Conflict("article dataset byte limit overflow".into()))?;
    let reservation = cpu.try_reserve_article_output(maximum)?;
    let (document, approved, reservation) = cpu
        .run(move || {
            let mut output = LimitedOutput::new(maximum);
            write_article(&mut output, &document, ArticleFormat::Json)
                .map_err(|_| output.serialization_error("article dataset serialization failed"))?;
            let approved = Redactor::new().verify_canonical_owned(output.bytes)?;
            Ok::<_, StoreError>((document, approved, reservation))
        })
        .await
        .map_err(|_| StoreError::Backend("article dataset CPU task failed".into()))??;
    // Keep the original approved allocation and its credit together through storage.
    let output = (approved, reservation);
    let size = u64::try_from(output.0.as_ref().len())
        .map_err(|_| StoreError::Conflict("article dataset length overflow".into()))?;
    let reference = put_approved(
        artifacts,
        run,
        page,
        &format!("article.{}", store.name),
        "application/json",
        &output.0,
        source_deadline,
    )
    .await?;
    let content = artifacts.dataset_content(run.id, page, &reference, size).await?;
    // Release dataset bytes and credit before reserving any subsequent feed output.
    drop(output);
    let mut item = AcceptedItemV1::new(
        "document".into(),
        "article_v1".into(),
        store.schema_version.clone(),
        "native_article_v1".into(),
        content,
        size,
    );
    item.source_document = Some(source_document);
    item.expires_at = item
        .content
        .expires_at()
        .or(article_deadline(run, source_deadline));
    let (document, outbox) = prepare_article_feeds_inner(
        artifacts,
        cpu,
        run,
        page,
        &store.name,
        document,
        true,
        item.expires_at,
        source,
    )
    .await?;
    let outbox = feed_policy::take_fragments(run, &mut item, outbox);
    Ok((
        document,
        vec![AcceptedBatchV1::new(store.name.clone(), vec![item])],
        outbox,
    ))
}

/// Serialize generic approved object items using real JSON/JSONL/CSV/XML wire contracts.
///
/// # Errors
/// Returns input-schema, serializer, byte quota or original-expiry errors.
pub async fn prepare_item_feeds(
    artifacts: &dyn ArtifactStore,
    cpu: &CpuPool,
    run: &CrawlRun,
    page: i64,
    dataset: &str,
    artifact: &crawlx_core::ArtifactRef,
    approved_json: Redacted<Vec<u8>>,
) -> Result<Vec<DeliveryBatchV1>, StoreError> {
    feed_policy::prepare_generic(artifacts, cpu, run, page, dataset, artifact, approved_json).await
}

/// Approved stdout data channel. A crash after writing but before receipt commit can duplicate output.
#[derive(Debug)]
pub struct StdoutDestination {
    permits: Arc<tokio::sync::Semaphore>,
    allows_zdr: bool,
}
impl StdoutDestination {
    /// Approve stdout only when the operator controls the data channel's retention.
    #[must_use]
    pub fn new(allows_zdr: bool) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(1)),
            allows_zdr,
        }
    }
}
#[async_trait]
impl DeliveryDestination for StdoutDestination {
    fn duplicate_possible(&self) -> bool {
        true
    }
    fn permits_zdr(&self) -> bool {
        self.allows_zdr
    }
    fn permits_feed_compression(&self) -> bool {
        true
    }
    async fn send(
        &self,
        _authority: &DeliveryAuthority,
        _run: &CrawlRun,
        _batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        let permit = self
            .permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| DeliveryError::Unavailable("stdout_destination_closed"))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut output = std::io::stdout().lock();
            output.write_all(&bytes)?;
            output.flush()
        })
        .await
        .map_err(|_| DeliveryError::Unavailable("stdout_task_failed"))??;
        Ok(())
    }
}

/// Operator-owned existing directory. Final names are immutable and contain no target-supplied path.
#[derive(Debug)]
pub struct LocalDestination {
    root: PathBuf,
}
impl LocalDestination {
    /// Canonicalize an operator-owned directory before it enters the registry.
    ///
    /// # Errors
    /// Returns I/O or unavailable errors for absent/non-directory roots.
    pub async fn open(root: &Path) -> Result<Self, DeliveryError> {
        let root = tokio::fs::canonicalize(root).await?;
        if !tokio::fs::metadata(&root).await?.is_dir() {
            return Err(DeliveryError::Unavailable("local_root_not_directory"));
        }
        Ok(Self { root })
    }
}
#[async_trait]
impl DeliveryDestination for LocalDestination {
    fn duplicate_possible(&self) -> bool {
        false
    }
    fn permits_zdr(&self) -> bool {
        false
    }
    fn permits_feed_compression(&self) -> bool {
        true
    }
    async fn send(
        &self,
        _authority: &DeliveryAuthority,
        run: &CrawlRun,
        batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        if run.config.retention.mode == RetentionMode::Zdr {
            return Err(DeliveryError::Unavailable("local_persistence_forbidden_in_zdr"));
        }
        let name = format!(
            "{}.{}.{}",
            run.id,
            batch.idempotency_key,
            batch.content.artifact().digest.to_hex()
        );
        crawlx_core::dataset::validate_identifier(&batch.idempotency_key)?;
        let final_path = self.root.join(name);
        if tokio::fs::try_exists(&final_path).await? {
            return verify_local(&final_path, &bytes).await;
        }
        let temporary = tempfile::NamedTempFile::new_in(&self.root)?;
        use tokio::io::AsyncWriteExt;
        let mut output = tokio::fs::File::from_std(temporary.reopen()?);
        output.write_all(&bytes).await?;
        output.sync_all().await?;
        match tokio::fs::hard_link(temporary.path(), &final_path).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_local(&final_path, &bytes).await?
            }
            Err(error) => return Err(error.into()),
        }
        drop(output);
        temporary.close()?;
        tokio::fs::File::open(&self.root).await?.sync_all().await?;
        Ok(())
    }
}

async fn verify_local(path: &Path, expected: &[u8]) -> Result<(), DeliveryError> {
    use tokio::io::AsyncReadExt;
    let metadata = tokio::fs::symlink_metadata(path).await?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() != u64::try_from(expected.len()).unwrap_or(u64::MAX)
    {
        return Err(DeliveryError::Rejected("local_immutable_object_conflict"));
    }
    let mut input = tokio::fs::File::open(path).await?;
    let mut buffer = [0u8; 64 * 1024];
    for chunk in expected.chunks(buffer.len()) {
        input.read_exact(&mut buffer[..chunk.len()]).await?;
        if &buffer[..chunk.len()] != chunk {
            return Err(DeliveryError::Rejected("local_immutable_object_conflict"));
        }
    }
    Ok(())
}

/// Existing S3-compatible blob sink, using an immutable run/batch/content key.
pub struct S3Destination {
    blobs: Arc<dyn ArtifactBlobs>,
    prefix: String,
}
impl S3Destination {
    /// Bind an already approved S3 sink and a non-secret fixed prefix at operator startup.
    ///
    /// # Errors
    /// Returns a conflict for invalid prefixes.
    pub fn new(blobs: Arc<dyn ArtifactBlobs>, prefix: String) -> Result<Self, StoreError> {
        crawlx_core::dataset::validate_identifier(&prefix)?;
        Ok(Self { blobs, prefix })
    }
}
#[async_trait]
impl DeliveryDestination for S3Destination {
    fn duplicate_possible(&self) -> bool {
        false
    }
    fn permits_zdr(&self) -> bool {
        false
    }
    fn permits_feed_compression(&self) -> bool {
        true
    }
    async fn send(
        &self,
        _authority: &DeliveryAuthority,
        run: &CrawlRun,
        batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        if run.config.retention.mode == RetentionMode::Zdr {
            return Err(DeliveryError::Unavailable("s3_persistence_forbidden_in_zdr"));
        }
        let key = format!(
            "{}/{}/{}/{}/{}",
            self.prefix,
            run.tenant,
            run.id,
            batch.idempotency_key,
            batch.content.artifact().digest.to_hex()
        );
        self.blobs.put_shared(&key, bytes).await?;
        Ok(())
    }
}

/// Explicit provider wire contract; legacy/deprecated services are not silently selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HttpDeliveryProtocol {
    /// Generic approved POST. Duplicate output remains possible unless provider honors the key.
    Http,
    /// Search-engine JSON update API; stable document IDs are required by the producer schema.
    SearchUpdate,
    /// Search-index NDJSON bulk API; every record result must acknowledge success.
    SearchIndex,
    /// Confluent-compatible stream REST v2 binary producer API, not a native broker protocol.
    StreamRestV2,
    /// Message-queue HTTP publish API with routed acknowledgement.
    QueueHttpV1,
    /// Object-store JSON media upload endpoint with fixed object identity and generation precondition.
    ObjectJsonUpload,
    /// Approved isolated FTP/FTPS service, acknowledging committed remote publication.
    FtpServiceV1,
}

/// Pinned operator endpoint. Redirects/sniffing are disabled and credentials never cross hosts.
pub struct HttpDestination {
    endpoint: Url,
    approved_addresses: Vec<SocketAddr>,
    headers: HeaderMap,
    protocol: HttpDeliveryProtocol,
    allows_zdr: bool,
}
impl HttpDestination {
    /// Build a TLS endpoint pinned to operator-authorized addresses, or an explicit loopback fixture.
    ///
    /// `headers` must come from resolved operator credential references, not the crawl manifest.
    /// ZDR approval is explicit and requires the provider's retention contract.
    ///
    /// # Errors
    /// Returns invalid endpoint, capability or HTTP client construction errors.
    pub fn approved(
        endpoint: Url,
        addresses: &[SocketAddr],
        headers: HeaderMap,
        protocol: HttpDeliveryProtocol,
        allows_zdr: bool,
    ) -> Result<Self, DeliveryError> {
        if endpoint.username() != ""
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || endpoint.query().is_some()
            || addresses.is_empty()
            || addresses.len() > 16
        {
            return Err(DeliveryError::Unavailable("invalid_approved_endpoint"));
        }
        let host = endpoint
            .host_str()
            .ok_or(DeliveryError::Unavailable("endpoint_host_missing"))?;
        let loopback = addresses.iter().all(|address| address.ip().is_loopback());
        if endpoint.scheme() != "https" && !(endpoint.scheme() == "http" && loopback) {
            return Err(DeliveryError::Unavailable("provider_tls_required"));
        }
        if headers.contains_key(reqwest::header::HOST) {
            return Err(DeliveryError::Unavailable("provider_host_override_forbidden"));
        }
        let _ = host;
        Ok(Self {
            endpoint,
            approved_addresses: addresses.to_vec(),
            headers,
            protocol,
            allows_zdr,
        })
    }
}
#[async_trait]
impl DeliveryDestination for HttpDestination {
    fn duplicate_possible(&self) -> bool {
        !matches!(
            self.protocol,
            HttpDeliveryProtocol::SearchUpdate
                | HttpDeliveryProtocol::SearchIndex
                | HttpDeliveryProtocol::ObjectJsonUpload
        )
    }
    fn permits_zdr(&self) -> bool {
        self.allows_zdr
    }
    fn permits_feed_compression(&self) -> bool {
        matches!(
            self.protocol,
            HttpDeliveryProtocol::Http
                | HttpDeliveryProtocol::ObjectJsonUpload
                | HttpDeliveryProtocol::FtpServiceV1
        )
    }
    fn working_bytes(&self, input: u64) -> Option<u64> {
        let factor = match self.protocol {
            HttpDeliveryProtocol::Http | HttpDeliveryProtocol::ObjectJsonUpload => 1,
            HttpDeliveryProtocol::SearchUpdate | HttpDeliveryProtocol::SearchIndex => 3,
            _ => 4,
        };
        input.checked_mul(factor)?.checked_add(256 * 1024)
    }
    async fn send(
        &self,
        authority: &DeliveryAuthority,
        run: &CrawlRun,
        batch: &DeliveryBatchV1,
        bytes: Bytes,
    ) -> Result<(), DeliveryError> {
        if run.config.retention.mode == RetentionMode::Zdr && !self.allows_zdr {
            return Err(DeliveryError::Unavailable("provider_zdr_not_approved"));
        }
        let mut endpoint = self.endpoint.clone();
        let mut headers = self.headers.clone();
        let mut search_receipt = None;
        headers.insert(
            "idempotency-key",
            HeaderValue::from_str(&batch.idempotency_key)
                .map_err(|_| DeliveryError::Rejected("invalid_idempotency_key"))?,
        );
        let body = match self.protocol {
            HttpDeliveryProtocol::StreamRestV2 => {
                headers.insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/vnd.kafka.binary.v2+json"), // wire-compat: stream REST media type
                );
                Bytes::from(serde_json::to_vec(&json!({"records":[{"key":base64::engine::general_purpose::STANDARD.encode(batch.idempotency_key.as_bytes()),"value":base64::engine::general_purpose::STANDARD.encode(&bytes)}]}))
                    .map_err(|_| DeliveryError::Rejected("stream_serialization_failed"))?)
            }
            HttpDeliveryProtocol::QueueHttpV1 => {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                Bytes::from(serde_json::to_vec(&json!({"properties":{"message_id":batch.idempotency_key,"delivery_mode":2},"routing_key":"","payload":base64::engine::general_purpose::STANDARD.encode(&bytes),"payload_encoding":"base64"}))
                    .map_err(|_| DeliveryError::Rejected("queue_serialization_failed"))?)
            }
            HttpDeliveryProtocol::FtpServiceV1 => {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
                headers.insert("x-crawlx-protocol-version", HeaderValue::from_static("1"));
                bytes
            }
            HttpDeliveryProtocol::ObjectJsonUpload => {
                endpoint
                    .query_pairs_mut()
                    .append_pair("uploadType", "media")
                    .append_pair(
                        "name",
                        &format!(
                            "{}/{}/{}",
                            run.id,
                            batch.idempotency_key,
                            batch.content.artifact().digest.to_hex()
                        ),
                    )
                    .append_pair("ifGenerationMatch", "0");
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
                bytes
            }
            HttpDeliveryProtocol::SearchIndex | HttpDeliveryProtocol::SearchUpdate => {
                let projection: crawlx_core::extraction::SearchProjectionV1 = serde_json::from_slice(&bytes)
                    .map_err(|_| DeliveryError::Rejected("search_projection_required"))?;
                projection.validate()?;
                search_receipt = Some((projection.document_id.clone(), projection.deleted));
                if self.protocol == HttpDeliveryProtocol::SearchUpdate {
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    let value = if projection.deleted {
                        json!({"delete":{"id":projection.document_id}})
                    } else {
                        let mut fields = projection.fields;
                        fields.insert("id".into(), json!(projection.document_id));
                        json!({"add":{"doc":fields,"overwrite":true}})
                    };
                    Bytes::from(
                        serde_json::to_vec(&value)
                            .map_err(|_| DeliveryError::Rejected("search_serialization_failed"))?,
                    )
                } else {
                    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/x-ndjson"));
                    let mut output = Vec::new();
                    let operation = if projection.deleted {
                        json!({"delete":{"_id":projection.document_id}})
                    } else {
                        json!({"index":{"_id":projection.document_id}})
                    };
                    serde_json::to_writer(&mut output, &operation)
                        .map_err(|_| DeliveryError::Rejected("search_serialization_failed"))?;
                    output.push(b'\n');
                    if !projection.deleted {
                        serde_json::to_writer(&mut output, &projection.fields)
                            .map_err(|_| DeliveryError::Rejected("search_serialization_failed"))?;
                        output.push(b'\n');
                    }
                    Bytes::from(output)
                }
            }
            HttpDeliveryProtocol::Http => bytes,
        };
        if u64::try_from(body.len()).map_or(true, |size| size > MAX_VALUE_BYTES) {
            return Err(DeliveryError::Rejected("provider_wire_byte_limit"));
        }
        authority
            .policy
            .check_url(&endpoint)
            .map_err(|_| DeliveryError::Unavailable("provider_egress_policy_denied"))?;
        let host = endpoint
            .host_str()
            .ok_or(DeliveryError::Unavailable("endpoint_host_missing"))?;
        let port = endpoint
            .port_or_known_default()
            .ok_or(DeliveryError::Unavailable("endpoint_port_missing"))?;
        authority
            .policy
            .check_port(port)
            .map_err(|_| DeliveryError::Unavailable("provider_egress_port_denied"))?;
        let addresses = authority.resolver.resolve(host).await?;
        authority
            .policy
            .check_all(host, &addresses)
            .map_err(|_| DeliveryError::Unavailable("provider_egress_address_denied"))?;
        if addresses.is_empty()
            || addresses.len() > 16
            || addresses
                .iter()
                .any(|ip| !self.approved_addresses.contains(&SocketAddr::new(*ip, port)))
        {
            return Err(DeliveryError::Unavailable("provider_address_not_approved"));
        }
        let sockets: Vec<_> = addresses.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
        // Fresh checked pins cannot reuse a stale pooled peer after DNS changes.
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .resolve_to_addrs(host, &sockets)
            .build()?;
        let origin = crawlx_fetch::Origin::from_url(&endpoint);
        let _permit = authority.governor.acquire(&origin).await?;
        let started = tokio::time::Instant::now();
        let mut response = client
            .post(endpoint.clone())
            .headers(headers)
            .body(body)
            .send()
            .await?;
        if response.remote_addr().is_none_or(|peer| !sockets.contains(&peer)) {
            return Err(DeliveryError::Rejected("provider_peer_not_pinned"));
        }
        let retry_after = crawlx_fetch::retry::parse_retry_after(response.headers(), chrono::Utc::now());
        authority
            .governor
            .on_response_with_latency(
                &origin,
                response.status().as_u16(),
                retry_after,
                Some(started.elapsed()),
                false,
            )
            .await?;
        if response.status().as_u16() == 429 || response.status().as_u16() == 503 {
            return Err(DeliveryError::ProviderBackoff(
                retry_after.unwrap_or(Duration::from_secs(30)),
            ));
        }
        if !response.status().is_success() {
            return Err(DeliveryError::Rejected("provider_http_status"));
        }
        let mut ack = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if ack
                .len()
                .checked_add(chunk.len())
                .is_none_or(|size| size > 256 * 1024)
            {
                return Err(DeliveryError::Rejected("provider_ack_too_large"));
            }
            ack.extend_from_slice(&chunk);
        }
        if self.protocol == HttpDeliveryProtocol::Http
            || self.protocol == HttpDeliveryProtocol::ObjectJsonUpload
        {
            return Ok(());
        }
        let value: Value =
            serde_json::from_slice(&ack).map_err(|_| DeliveryError::Rejected("provider_ack_invalid_json"))?;
        let accepted = match self.protocol {
            HttpDeliveryProtocol::SearchUpdate => {
                value.pointer("/responseHeader/status").and_then(Value::as_u64) == Some(0)
            }
            HttpDeliveryProtocol::SearchIndex => search_receipt
                .as_ref()
                .is_some_and(|(id, deleted)| search_acknowledged(&value, id, *deleted)),
            HttpDeliveryProtocol::StreamRestV2 => {
                value
                    .get("offsets")
                    .and_then(Value::as_array)
                    .is_some_and(|offsets| {
                        offsets.len() == 1
                            && offsets.iter().all(|offset| {
                                offset.get("error_code").is_none_or(Value::is_null)
                                    && offset
                                        .get("offset")
                                        .and_then(Value::as_i64)
                                        .is_some_and(|offset| offset >= 0)
                            })
                    })
            }
            HttpDeliveryProtocol::QueueHttpV1 => value.get("routed").and_then(Value::as_bool) == Some(true),
            HttpDeliveryProtocol::FtpServiceV1 => {
                value.get("version").and_then(Value::as_u64) == Some(1)
                    && value.get("committed").and_then(Value::as_bool) == Some(true)
                    && value.get("idempotencyKey").and_then(Value::as_str)
                        == Some(batch.idempotency_key.as_str())
            }
            _ => false,
        };
        if !accepted {
            return Err(DeliveryError::Rejected("provider_ack_rejected"));
        }
        Ok(())
    }
}

/// Inspect a claimed manifest without exposing payloads in diagnostics.
#[must_use]
pub fn delivery_receipt_id(receipt: &DurableDeliveryOutboxV1) -> (i64, i64) {
    (receipt.id, receipt.fence)
}

fn article_deadline(
    run: &CrawlRun,
    source: Option<crawlx_core::Timestamp>,
) -> Option<crawlx_core::Timestamp> {
    if run.config.retention.mode == RetentionMode::Zdr {
        return source;
    }
    let horizon = run
        .created_at
        .checked_add_signed(chrono::Duration::days(i64::from(run.config.retention.days)));
    match (source, horizon) {
        (Some(source), Some(horizon)) => Some(source.min(horizon)),
        (source, horizon) => source.or(horizon),
    }
}

#[allow(clippy::too_many_arguments)]
async fn put_approved(
    artifacts: &dyn ArtifactStore,
    run: &CrawlRun,
    page: i64,
    rendition: &str,
    mime: &str,
    approved: &Redacted<Vec<u8>>,
    source: Option<crawlx_core::Timestamp>,
) -> Result<crawlx_core::ArtifactRef, StoreError> {
    if let Some(deadline) = article_deadline(run, source) {
        ArtifactSink::over(artifacts)
            .put_dataset_until(run.id, page, rendition, mime, approved, deadline)
            .await
    } else {
        ArtifactSink::over(artifacts)
            .put_dataset(run.id, page, rendition, mime, approved)
            .await
    }
}

fn search_acknowledged(value: &Value, id: &str, deleted: bool) -> bool {
    let operation = if deleted { "delete" } else { "index" };
    let Some(items) = value
        .get("items")
        .and_then(Value::as_array)
        .filter(|items| items.len() == 1)
    else {
        return false;
    };
    let Some(operations) = items[0].as_object().filter(|operations| operations.len() == 1) else {
        return false;
    };
    let Some(result) = operations.get(operation) else {
        return false;
    };
    if result.get("_id").and_then(Value::as_str) != Some(id)
        || result.get("error").is_some_and(|value| !value.is_null())
    {
        return false;
    }
    match result.get("status").and_then(Value::as_u64) {
        Some(200..=299) => value.get("errors").and_then(Value::as_bool) == Some(false),
        Some(404) if deleted => result.get("result").and_then(Value::as_str) == Some("not_found"),
        _ => false,
    }
}
