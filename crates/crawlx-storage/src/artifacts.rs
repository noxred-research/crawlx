//! Content-addressed artifact store.
//!
//! The key layout is `{class}/{tenant}/{run}/{blake3}`: the top-level prefix is
//! the sensitivity class so lifecycle rules differ per class, and identical
//! content within a run shares one object. Every `put` additionally writes a
//! small index record at `_index/{artifact_id}.json` (one record per use, the
//! counterpart of an `artifacts` row) so `get(&ArtifactRef)` can find the
//! object without a database. When an [`ArtifactIndex`] is attached (see
//! [`crate::Pg`]) the same record is mirrored into the `artifacts` table. Reads and
//! reaping honor the attached index's authoritative retention and deletion state.
//!
//! Object-store backends implement [`ArtifactBlobs`]: a directory backend, an
//! in-memory backend and the S3-compatible backend in [`crate::s3`]. The store
//! writes the object before its index record and before the `artifacts` row
//! (object first, row second); a crash in between leaves an orphan
//! object that [`ArtifactReaper::collect_orphans`] removes after a grace period.

use crate::retention::{artifact_expiry, zdr_write_gate};
use crate::spool::UploadSpool;
use crate::zdr::DeliveryBuffer;
use async_trait::async_trait;
use bytes::Bytes;
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ArtifactStore, RunRepo, Sensitivity};
use crawlx_core::{ArtifactId, ArtifactRef, Clock, CrawlRunId, StoreError, TenantId, Timestamp};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

mod sealed;

use crate::artifact_custody::{ciphertext_bound, ArtifactCustody, CustodyWrites};
use crate::artifact_key_crypto::ArtifactKeys;
use crate::custody::{encrypted_object_key, CiphertextIdentity, CIPHERTEXT_DIGEST_DOMAIN};

const INDEX_PREFIX: &str = "_index/";
pub(crate) const DIGEST_DOMAIN: &str = "crawlx/artifact/v1";
/// Longest lifetime of a presigned `content` URL.
pub const PRESIGN_MAX_TTL: Duration = Duration::from_secs(60);

/// Bounded filesystem reads preserve storage semantics and underlying I/O/parse causes.
/// Callers must not expose raw index parse details to untrusted clients or logs.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BoundedArtifactError {
    /// Existing artifact scope, retention, sensitivity or fixity refusal.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// An opened descriptor failed without losing its OS error cause.
    #[error("bounded filesystem artifact I/O failed")]
    Io(#[from] std::io::Error),
    /// A bounded index was not a valid artifact row.
    #[error("bounded filesystem artifact index is invalid")]
    Index(#[from] serde_json::Error),
    /// The reader refused an oversized index or object.
    #[error("bounded filesystem artifact limit exceeded: {0}")]
    Limit(&'static str),
    /// The bounded blocking task did not complete.
    #[error("bounded filesystem artifact read task failed")]
    Task(#[from] tokio::task::JoinError),
}

/// One stored use of an object (an `artifacts` row).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct ArtifactRow {
    /// Unique id of this use (the `artifacts.artifact_id` column).
    pub id: ArtifactId,
    /// Tenant owning the run that wrote the object.
    pub tenant: TenantId,
    /// Run that wrote this use.
    pub run: CrawlRunId,
    /// One of the `artifacts.kind` check values (`markdown`, `html`, `screenshot`, ...).
    pub kind: String,
    /// Object-store bucket holding the blob.
    pub bucket: String,
    /// Key of the blob inside `bucket` (see [`object_key`]).
    pub object_key: String,
    /// Blob size in bytes.
    pub size_bytes: u64,
    /// Domain-separated blake3 digest of the blob.
    pub digest: Digest,
    /// MIME type supplied by the writer.
    pub content_type: String,
    /// Sensitivity class the blob was written under.
    pub sensitivity: Sensitivity,
    /// Write time.
    pub created_at: Timestamp,
    /// Expiry per [`artifact_expiry`]; `None` lives until the run is purged.
    pub expires_at: Option<Timestamp>,
}

/// Raw object storage the artifact store sits on.
#[async_trait]
pub trait ArtifactBlobs: Send + Sync {
    /// Bucket name recorded in `artifacts.bucket`.
    fn bucket(&self) -> &str;
    /// Write `bytes` under `key`, replacing any existing object.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the key or cannot persist the object.
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError>;
    /// Write shared bytes without copying the payload for each retry.
    ///
    /// Backends that own request bodies override this to retain the shared allocation.
    ///
    /// # Errors
    /// Returns the same errors as [`Self::put`].
    async fn put_shared(&self, key: &str, bytes: Bytes) -> Result<(), StoreError> {
        self.put(key, &bytes).await
    }
    /// Open a bounded-memory object reader. Unsupported stores refuse explicitly.
    ///
    /// # Errors
    /// Returns missing-object, backend, or unavailable streaming capability errors.
    async fn reader(&self, key: &str) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        let _ = key;
        Err(StoreError::Unavailable(
            "streaming object reads unavailable".into(),
        ))
    }
    /// Stream a file without collecting its bytes. The destination becomes visible atomically.
    ///
    /// # Errors
    /// Returns a backend error or an unavailable streaming capability error.
    async fn put_file(&self, key: &str, file: &Path, size: u64) -> Result<(), StoreError> {
        let _ = (key, file, size);
        Err(StoreError::Unavailable(
            "streaming object writes unavailable".into(),
        ))
    }
    /// Read the object at `key`; `Ok(None)` if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the key or cannot read the object.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Whether an object exists at `key`.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the key or cannot be queried.
    async fn exists(&self, key: &str) -> Result<bool, StoreError>;
    /// Delete; missing keys are not an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend rejects the key or cannot delete the object.
    async fn delete(&self, key: &str) -> Result<(), StoreError>;
    /// All objects whose key starts with `prefix`, sorted by key.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot enumerate its objects.
    async fn list(&self, prefix: &str) -> Result<Vec<BlobEntry>, StoreError>;
    /// A URL that serves `key` without credentials for at most `ttl`; `Ok(None)` when the
    /// backend has no such mechanism (the default).
    ///
    /// # Errors
    ///
    /// Returns an error if the backend fails to sign the request.
    async fn presign(&self, key: &str, ttl: Duration) -> Result<Option<url::Url>, StoreError> {
        let _ = (key, ttl);
        Ok(None)
    }
}

/// One stored object as returned by [`ArtifactBlobs::list`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlobEntry {
    /// Object key.
    pub key: String,
    /// When the object was last written.
    pub modified: Timestamp,
}

/// Artifact rows the database still references (input to [`ArtifactReaper::collect_orphans`]).
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct LiveArtifacts {
    /// `artifacts.artifact_id` of every row with `deleted_at IS NULL`.
    pub ids: BTreeSet<ArtifactId>,
    /// `artifacts.object_key` of those rows.
    pub object_keys: BTreeSet<String>,
}

/// Authoritative retention state of an artifact use in the attached index.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct ArtifactRetention {
    /// Retention deadline; `None` means no additional deadline.
    pub expires_at: Option<Timestamp>,
    /// Physical deletion acknowledgement, also revoking access immediately.
    pub deleted_at: Option<Timestamp>,
}

impl ArtifactRetention {
    /// Construct authoritative retention state from persisted deadlines.
    #[must_use]
    pub fn new(expires_at: Option<Timestamp>, deleted_at: Option<Timestamp>) -> Self {
        Self {
            expires_at,
            deleted_at,
        }
    }
}

/// Mirror of artifact rows and authoritative retention in a database table.
#[async_trait]
pub trait ArtifactIndex: Send + Sync {
    /// Record `row` in the mirrored table.
    ///
    /// # Errors
    ///
    /// Returns an error if the row cannot be encoded or the database rejects the insert.
    async fn record(&self, row: &ArtifactRow) -> Result<(), StoreError>;
    /// Read authoritative retention state; `None` means the use does not exist.
    ///
    /// # Errors
    /// Returns an error if authoritative metadata cannot be read. Callers must not
    /// fall back to the object index when this fails.
    async fn retention(&self, id: ArtifactId) -> Result<Option<ArtifactRetention>, StoreError>;
    /// Mark rows deleted (the objects are already gone).
    ///
    /// # Errors
    ///
    /// Returns an error if the database rejects the update.
    async fn mark_deleted(&self, ids: &[ArtifactId]) -> Result<(), StoreError>;
}

/// Deletes blobs of expired uses (used by the retention sweeper).
#[async_trait]
pub trait ArtifactReaper: Send + Sync {
    /// Delete every use expiring at or before `now`; objects without remaining uses are removed.
    /// Returns the number of uses deleted.
    ///
    /// # Errors
    ///
    /// Returns an error if the index records or blobs cannot be read or deleted.
    async fn reap_expired(&self, now: Timestamp) -> Result<u64, StoreError>;
    /// Delete every use belonging to `run` (run purge).
    ///
    /// # Errors
    ///
    /// Returns an error if the index records or blobs cannot be read or deleted.
    async fn purge_run(&self, run: CrawlRunId) -> Result<u64, StoreError>;
    /// Delete one artifact use, preserving other uses of the same content-addressed object.
    ///
    /// # Errors
    /// Returns tenant scope, index or backend erasure errors.
    async fn erase_artifact(&self, artifact: &ArtifactRef) -> Result<u64, StoreError>;
    /// Remove objects written before `older_than` that no row in `live` references, and
    /// index records written before `older_than` whose id is not in `live` (a crash
    /// between the object `PUT` and the row insert leaves an orphan). Returns the number of
    /// objects removed; an object referenced by `live` is never removed.
    ///
    /// # Errors
    ///
    /// Returns an error if the backend cannot be listed or an object cannot be deleted.
    async fn collect_orphans(&self, live: &LiveArtifacts, older_than: Timestamp) -> Result<u64, StoreError>;
}

/// Run one [`ArtifactBlobs`] call and account for it under
/// `crawlx.objectstore.requests{op,outcome}` and `crawlx.objectstore.duration{op}`.
/// A `get` miss is `ok`; only an `Err` counts as `error`.
pub(crate) async fn observed<T>(
    op: &'static str,
    call: impl Future<Output = Result<T, StoreError>>,
) -> Result<T, StoreError> {
    let started = Instant::now();
    let result = call.await;
    let metrics = Metrics::global();
    metrics
        .histogram(names::OBJECTSTORE_DURATION)
        .observe_duration(started.elapsed(), &[("op", op)]);
    let outcome = if result.is_ok() { "ok" } else { "error" };
    metrics
        .counter(names::OBJECTSTORE_REQUESTS)
        .inc_by(1, &[("op", op), ("outcome", outcome)]);
    result
}

/// Artifact store over any [`ArtifactBlobs`] backend.
pub struct ObjectArtifactStore<B: ArtifactBlobs> {
    blobs: B,
    runs: Arc<dyn RunRepo>,
    clock: Arc<dyn Clock>,
    index: Option<Arc<dyn ArtifactIndex>>,
    zdr: Option<Arc<DeliveryBuffer>>,
    spool: Arc<UploadSpool>,
    read_scope: Option<(TenantId, CrawlRunId)>,
    custody: Option<sealed::StoreCustody>,
}

/// Artifacts under a directory.
pub type FsArtifactStore = ObjectArtifactStore<FsBlobs>;
/// Artifacts in process memory (tests).
pub type MemoryArtifactStore = ObjectArtifactStore<MemBlobs>;

impl ObjectArtifactStore<FsBlobs> {
    /// Open (creating if needed) a store rooted at `root`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the root directory cannot be created.
    pub async fn open(
        root: impl Into<PathBuf>,
        runs: Arc<dyn RunRepo>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        let root = root.into();
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|e| StoreError::Unavailable(format!("create {}: {e}", root.display())))?;
        Ok(Self::new(FsBlobs { root }, runs, clock))
    }

    /// Read one artifact through an explicit tenant/run scope, expected sensitivity
    /// and byte ceiling. Index reads are capped at 64 KiB; object reads at `max_bytes`.
    /// Linux descriptors refuse symlinks, traversal, special files and blocking FIFOs.
    ///
    /// # Errors
    /// Preserves missing/foreign/expired/digest errors, and rejects missing scope,
    /// unexpected sensitivity, noncanonical keys, size mismatches and unsafe paths.
    /// Other platforms return an explicit unavailable capability, never a weak fallback.
    pub async fn get_bounded(
        &self,
        artifact: &ArtifactRef,
        expected: Sensitivity,
        max_bytes: u64,
    ) -> Result<Vec<u8>, BoundedArtifactError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (artifact, expected, max_bytes);
            return Err(
                StoreError::Unavailable("bounded filesystem reads require Linux openat2".into()).into(),
            );
        }
        #[cfg(target_os = "linux")]
        {
            let scope = self.read_scope.ok_or_else(|| {
                StoreError::AccessDenied(
                    "bounded filesystem reads require an explicit tenant and run scope".into(),
                )
            })?;
            if expected == Sensitivity::CredentialBearing {
                let owner = self.runs.get_metadata(scope.1).await?;
                if owner.tenant != scope.0 || owner.status.is_terminal() {
                    return Err(
                        StoreError::RetentionDenied("credential run has ended or is foreign".into()).into(),
                    );
                }
            }
            if let Some(index) = &self.index {
                let retention = index
                    .retention(artifact.id)
                    .await?
                    .ok_or_else(|| StoreError::NotFound {
                        entity: "artifact",
                        id: artifact.id.to_string(),
                    })?;
                if retention.deleted_at.is_some()
                    || retention
                        .expires_at
                        .is_some_and(|expiry| expiry <= self.clock.now())
                {
                    return Err(StoreError::RetentionDenied("artifact expired or deleted".into()).into());
                }
            }
            let sealed = self.sealed_custody_for(scope.0, scope.1, artifact.id).await?;
            let ciphertext = sealed.as_ref().map(|sealed| sealed.custody.ciphertext);
            let root = self.blobs.root.clone();
            let artifact = artifact.clone();
            let now = self.clock.now();
            let (row, bytes) = tokio::task::spawn_blocking(move || {
                bounded_fs_artifact(&root, scope, &artifact, expected, max_bytes, now, ciphertext)
            })
            .await??;
            match sealed {
                Some(sealed) => Ok(self.sealed_open_bytes(&sealed, &row, bytes).await?),
                None => Ok(bytes),
            }
        }
    }

    /// Read the fixed local replay bootstrap descriptor from an operator-owned root.
    /// This grants no tenant/model authority; its references still require scoped reads.
    ///
    /// # Errors
    /// Refuses symlinks, special files, a descriptor above 64 KiB, or unavailable
    /// Linux descriptor confinement. Missing files retain their I/O error kind.
    pub async fn read_bundle_descriptor(root: &Path) -> Result<Vec<u8>, BoundedArtifactError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = root;
            return Err(
                StoreError::Unavailable("bounded filesystem reads require Linux openat2".into()).into(),
            );
        }
        #[cfg(target_os = "linux")]
        {
            let root = root.to_owned();
            tokio::task::spawn_blocking(move || {
                let mut file = crate::archive::collection::open_confined_regular(&root, "bundle.json")?;
                bounded_fs_bytes(&mut file, 65_536, "replay bundle descriptor bytes")
            })
            .await?
        }
    }
}

#[cfg(target_os = "linux")]
fn bounded_fs_artifact(
    root: &Path,
    scope: (TenantId, CrawlRunId),
    artifact: &ArtifactRef,
    expected: Sensitivity,
    max_bytes: u64,
    now: Timestamp,
    ciphertext: Option<CiphertextIdentity>,
) -> Result<(ArtifactRow, Vec<u8>), BoundedArtifactError> {
    let missing = || StoreError::NotFound {
        entity: "artifact",
        id: artifact.id.to_string(),
    };
    let root = crate::archive::collection::open_confined_root(root)?;
    let open = |key: &str| {
        crate::archive::collection::open_confined_regular_at(&root, key).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                BoundedArtifactError::Store(missing())
            } else {
                BoundedArtifactError::Io(error)
            }
        })
    };
    let mut index = open(&index_key(artifact.id))?;
    let index = bounded_fs_bytes(&mut index, 65_536, "artifact index bytes")?;
    let row: ArtifactRow = serde_json::from_slice(&index)?;
    if row.id != artifact.id
        || row.tenant != scope.0
        || row.run != scope.1
        || row.digest != artifact.digest
        || row.expires_at.is_some_and(|expiry| expiry <= now)
    {
        return Err(missing().into());
    }
    if row.sensitivity != expected {
        return Err(
            StoreError::AccessDenied("artifact sensitivity does not match bounded read".into()).into(),
        );
    }
    if let Some(identity) = ciphertext {
        if row.object_key != encrypted_object_key(scope.0, scope.1, row.id, identity.digest) {
            return Err(
                StoreError::Backend("sealed artifact object key does not match its custody".into()).into(),
            );
        }
        if row.size_bytes > max_bytes || identity.size_bytes > ciphertext_bound(row.size_bytes)? {
            return Err(BoundedArtifactError::Limit("sealed artifact object bytes"));
        }
        let mut file = open(&row.object_key)?;
        let bytes = bounded_fs_bytes(&mut file, identity.size_bytes, "sealed artifact object bytes")?;
        if u64::try_from(bytes.len()).ok() != Some(identity.size_bytes)
            || Digest::of(CIPHERTEXT_DIGEST_DOMAIN, &bytes) != identity.digest
        {
            return Err(StoreError::Backend(format!(
                "sealed artifact {} failed ciphertext verification",
                artifact.id
            ))
            .into());
        }
        return Ok((row, bytes));
    }
    if row.object_key != object_key(row.sensitivity, scope.0, scope.1, &row.digest) {
        return Err(
            StoreError::Backend("artifact object key does not match its scoped namespace".into()).into(),
        );
    }
    if row.size_bytes > max_bytes {
        return Err(BoundedArtifactError::Limit("artifact object bytes"));
    }
    let mut file = open(&row.object_key)?;
    let bytes = bounded_fs_bytes(&mut file, max_bytes, "artifact object bytes")?;
    if u64::try_from(bytes.len()).ok() != Some(row.size_bytes) {
        return Err(StoreError::Backend("artifact object length does not match its index".into()).into());
    }
    if Digest::of(DIGEST_DOMAIN, &bytes) != row.digest {
        return Err(
            StoreError::Backend(format!("artifact {} failed digest verification", artifact.id)).into(),
        );
    }
    Ok((row, bytes))
}

#[cfg(target_os = "linux")]
fn bounded_fs_bytes(
    file: &mut std::fs::File,
    maximum: u64,
    bound: &'static str,
) -> Result<Vec<u8>, BoundedArtifactError> {
    use std::io::Read as _;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "artifact is not a regular file").into(),
        );
    }
    if metadata.len() > maximum {
        return Err(BoundedArtifactError::Limit(bound));
    }
    let capacity = usize::try_from(metadata.len()).map_err(|_| BoundedArtifactError::Limit(bound))?;
    let mut bytes = Vec::with_capacity(capacity);
    let ceiling = maximum.checked_add(1).ok_or(BoundedArtifactError::Limit(bound))?;
    file.take(ceiling).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| BoundedArtifactError::Limit(bound))? > maximum {
        return Err(BoundedArtifactError::Limit(bound));
    }
    Ok(bytes)
}

impl ObjectArtifactStore<MemBlobs> {
    /// Store backed by [`MemBlobs`]; nothing is persisted.
    #[must_use]
    pub fn in_memory(runs: Arc<dyn RunRepo>, clock: Arc<dyn Clock>) -> Self {
        Self::new(MemBlobs::default(), runs, clock)
    }
}

impl<B: ArtifactBlobs> ObjectArtifactStore<B> {
    /// Store over `blobs` with no [`ArtifactIndex`] attached.
    #[must_use]
    pub fn new(blobs: B, runs: Arc<dyn RunRepo>, clock: Arc<dyn Clock>) -> Self {
        Self {
            blobs,
            runs,
            clock,
            index: None,
            zdr: None,
            spool: Arc::new(UploadSpool::default()),
            read_scope: None,
            custody: None,
        }
    }

    /// Mirror every use into `index` (e.g. the `artifacts` table).
    #[must_use]
    pub fn with_index(mut self, index: Arc<dyn ArtifactIndex>) -> Self {
        self.index = Some(index);
        self
    }

    /// Attach encrypted-artifact custody.
    ///
    /// Reads of artifacts the custody knows decrypt and verify through the catalog;
    /// legacy plaintext artifacts keep reading unchanged. With
    /// [`CustodyWrites::Required`], Content/Sensitive writes of a non-terminal run stage
    /// ciphertext only and publish through `custody` under the current producer lease
    /// ([`crawlx_core::custody::with_producer`]); without one the write fails with
    /// [`StoreError::Unavailable`]. [`CustodyWrites::ReadOnly`] keeps writes plaintext.
    #[must_use]
    pub fn with_custody(
        mut self,
        custody: Arc<dyn ArtifactCustody>,
        keys: Arc<dyn ArtifactKeys>,
        writes: CustodyWrites,
    ) -> Self {
        self.custody = Some(sealed::StoreCustody {
            custody,
            keys,
            writes,
        });
        self
    }

    /// Restrict artifact reads and presigned URLs to one tenant and run.
    ///
    /// Out-of-scope references are reported as missing without reading their content.
    #[must_use]
    pub fn with_read_scope(mut self, tenant: TenantId, run: CrawlRunId) -> Self {
        self.read_scope = Some((tenant, run));
        self
    }

    /// Share a bounded upload spool across stores in this process.
    #[must_use]
    pub fn with_upload_spool(mut self, spool: Arc<UploadSpool>) -> Self {
        self.spool = spool;
        self
    }

    /// Keep `content` of zero-data-retention runs in `buffer` instead of
    /// refusing it: [`ArtifactStore::put_page`] routes it there and [`ArtifactStore::get`]
    /// resolves references the buffer handed out. Without a buffer ZDR content is refused.
    #[must_use]
    pub fn with_zdr_buffer(mut self, buffer: Arc<DeliveryBuffer>) -> Self {
        self.zdr = Some(buffer);
        self
    }

    /// The attached delivery buffer, if any.
    #[must_use]
    pub fn zdr_buffer(&self) -> Option<&Arc<DeliveryBuffer>> {
        self.zdr.as_ref()
    }

    /// The backend (tests inspect it).
    #[must_use]
    pub fn blobs(&self) -> &B {
        &self.blobs
    }

    /// `put` with an explicit `artifacts.kind`; the trait method infers it from the content type.
    ///
    /// # Errors
    ///
    /// Returns an error if the run cannot be loaded, [`StoreError::RetentionDenied`] if the
    /// run's retention mode forbids `class`, [`StoreError::Serialization`] if the index record
    /// cannot be encoded, or any backend or index error from storing the blob and its record.
    pub async fn put_kind(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        kind: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        self.put_kind_until(run, class, kind, content_type, bytes, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn put_kind_until(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        kind: &str,
        content_type: &str,
        bytes: &[u8],
        deadline: Option<Timestamp>,
    ) -> Result<ArtifactRef, StoreError> {
        let run_row = self.runs.get_metadata(run).await?;
        zdr_write_gate(run_row.retention.mode, class)?;
        if class == Sensitivity::CredentialBearing && run_row.status.is_terminal() {
            return Err(StoreError::RetentionDenied("credential run has ended".into()));
        }
        let now = self.clock.now();
        if deadline.is_some_and(|deadline| deadline <= now) {
            return Err(StoreError::RetentionDenied("artifact source expired".into()));
        }
        if let Some(attached) = self.sealing(class, &run_row)? {
            let expires_at = artifact_expiry(
                class,
                content_type,
                run_row.retention.mode,
                u32::from(run_row.retention.days),
                now,
            )
            .map(|expiry| deadline.map_or(expiry, |deadline| deadline.min(expiry)))
            .or(deadline);
            return self
                .put_sealed_bytes(
                    attached,
                    &run_row,
                    class,
                    kind,
                    content_type,
                    bytes,
                    now,
                    expires_at,
                )
                .await;
        }
        let digest = Digest::of(DIGEST_DOMAIN, bytes);
        let object_key = object_key(class, run_row.tenant, run, &digest);
        self.spool.ensure(&self.blobs, &object_key, bytes).await?;
        crate::chaos::pause("artifact.after_object_put").await;
        let row = ArtifactRow {
            id: ArtifactId::new(),
            tenant: run_row.tenant,
            run,
            kind: kind.to_owned(),
            bucket: self.blobs.bucket().to_owned(),
            object_key,
            size_bytes: bytes.len() as u64,
            digest,
            content_type: content_type.to_owned(),
            sensitivity: class,
            created_at: now,
            expires_at: artifact_expiry(
                class,
                content_type,
                run_row.retention.mode,
                u32::from(run_row.retention.days),
                now,
            )
            .map(|expiry| deadline.map_or(expiry, |deadline| deadline.min(expiry)))
            .or(deadline),
        };
        let record = serde_json::to_vec(&row).map_err(|e| StoreError::Serialization(e.to_string()))?;
        self.spool.put(&self.blobs, &index_key(row.id), &record).await?;
        if let Some(index) = &self.index {
            index.record(&row).await?;
        }
        if class == Sensitivity::CredentialBearing && self.runs.get_metadata(run).await?.status.is_terminal()
        {
            self.delete_rows(&[row]).await?;
            return Err(StoreError::RetentionDenied("credential run has ended".into()));
        }
        Ok(ArtifactRef { id: row.id, digest })
    }
    /// Open a content stream after tenant, run, expiry and byte-bound checks.
    /// Fixity is checked before the terminal stream item; consumers must reject stream errors.
    ///
    /// # Errors
    /// Refuses foreign, expired, non-content, oversized or corrupt artifacts.
    pub async fn stream_content(
        &self,
        artifact: &ArtifactRef,
        max_bytes: u64,
    ) -> Result<futures::stream::BoxStream<'static, Result<Bytes, StoreError>>, StoreError> {
        let row = self.row(artifact.id).await?.ok_or_else(|| StoreError::NotFound {
            entity: "artifact",
            id: artifact.id.to_string(),
        })?;
        let run = self.runs.get_metadata(row.run).await?;
        let source_expiry = (run.retention.days != 0)
            .then(|| run.created_at + chrono::Duration::days(i64::from(run.retention.days)));
        if row.id != artifact.id
            || row.digest != artifact.digest
            || row.sensitivity != Sensitivity::Content
            || row.size_bytes > max_bytes
            || row.tenant != run.tenant
            || run.retention.mode == RetentionMode::Zdr
            || crate::tenant::current().is_some_and(|tenant| tenant != row.tenant)
            || self
                .read_scope
                .is_some_and(|(tenant, run)| tenant != row.tenant || run != row.run)
            || row.expires_at.is_some_and(|expiry| expiry <= self.clock.now())
            || source_expiry.is_some_and(|expiry| expiry <= self.clock.now())
        {
            return Err(StoreError::RetentionDenied(
                "content stream scope, retention or bound failed".into(),
            ));
        }
        let sealed = self.sealed_custody(&row).await?;
        if let Some(sealed) = &sealed {
            return self.sealed_content_stream(&row, sealed, max_bytes).await;
        }
        if row.object_key != object_key(row.sensitivity, row.tenant, row.run, &row.digest) {
            return Err(StoreError::RetentionDenied(
                "content stream scope, retention or bound failed".into(),
            ));
        }
        let mut reader = self.blobs.reader(&row.object_key).await?;
        Ok(Box::pin(async_stream::try_stream! {
            let mut hash = blake3::Hasher::new();
            hash.update(DIGEST_DOMAIN.as_bytes()); hash.update(&[0]);
            let mut count = 0u64;
            let mut buffer = [0u8; 32 * 1024];
            loop {
                let n = reader.read(&mut buffer).await.map_err(|e| io(&e, "stream content"))?;
                if n == 0 { break; }
                count = count.checked_add(u64::try_from(n).map_err(|_| StoreError::Conflict("content chunk size".into()))?)
                    .ok_or_else(|| StoreError::Conflict("content size overflow".into()))?;
                if count > max_bytes || count > row.size_bytes { Err(StoreError::RetentionDenied("content stream exceeded approved size".into()))?; }
                hash.update(&buffer[..n]);
                yield Bytes::copy_from_slice(&buffer[..n]);
            }
            if count != row.size_bytes || Digest(*hash.finalize().as_bytes()) != row.digest {
                Err(StoreError::RetentionDenied("content stream fixity failed".into()))?;
            }
        }))
    }

    /// Read one bounded retained representation, validating size before allocation.
    ///
    /// # Errors
    /// Returns stream ownership, expiry, size or fixity errors.
    pub async fn read_content_limited(
        &self,
        artifact: &ArtifactRef,
        max_bytes: u64,
    ) -> Result<Vec<u8>, StoreError> {
        use futures::TryStreamExt as _;
        let mut stream = self.stream_content(artifact, max_bytes).await?;
        let row = self.row(artifact.id).await?.ok_or_else(|| StoreError::NotFound {
            entity: "artifact",
            id: artifact.id.to_string(),
        })?;
        if row.size_bytes > max_bytes {
            return Err(StoreError::RetentionDenied(
                "content body exceeds byte bound".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(
            usize::try_from(row.size_bytes)
                .map_err(|_| StoreError::RetentionDenied("content body exceeds allocation range".into()))?,
        );
        while let Some(chunk) = stream.try_next().await? {
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Erase one artifact use and delete its object when no other use references it.
    ///
    /// # Errors
    /// Refuses a foreign artifact and returns index or backend erasure errors.
    pub async fn erase_artifact(&self, artifact: &ArtifactRef) -> Result<u64, StoreError> {
        let Some(row) = self.row(artifact.id).await? else {
            return Ok(0);
        };
        if row.digest != artifact.digest
            || crate::tenant::current().is_some_and(|tenant| tenant != row.tenant)
        {
            return Err(StoreError::AccessDenied("artifact erasure scope mismatch".into()));
        }
        self.delete_rows(&[row]).await
    }

    /// The stored use `id`, if it exists and has not been purged.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Serialization`] if the stored record is malformed, or a backend
    /// error if it cannot be read.
    pub async fn row(&self, id: ArtifactId) -> Result<Option<ArtifactRow>, StoreError> {
        let Some(bytes) = observed("get", self.blobs.get(&index_key(id))).await? else {
            return Ok(None);
        };
        let mut row: ArtifactRow =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Serialization(e.to_string()))?;
        if let Some(index) = &self.index {
            let Some(retention) = index.retention(id).await? else {
                return Ok(None);
            };
            if retention.deleted_at.is_some() {
                return Ok(None);
            }
            row.expires_at = earliest_expiry(row.expires_at, retention.expires_at);
        }
        row.expires_at = earliest_expiry(row.expires_at, self.credential_expiry(&row).await?);
        Ok(Some(row))
    }

    async fn rows(&self) -> Result<Vec<ArtifactRow>, StoreError> {
        let mut out = Vec::new();
        for entry in observed("list", self.blobs.list(INDEX_PREFIX)).await? {
            if let Some(bytes) = observed("get", self.blobs.get(&entry.key)).await? {
                let mut row: ArtifactRow =
                    serde_json::from_slice(&bytes).map_err(|e| StoreError::Serialization(e.to_string()))?;
                if crate::tenant::current().is_some_and(|tenant| row.tenant != tenant) {
                    continue;
                }
                if let Some(index) = &self.index {
                    if let Some(retention) = index.retention(row.id).await? {
                        row.expires_at = earliest_expiry(
                            row.expires_at,
                            earliest_expiry(retention.expires_at, retention.deleted_at),
                        );
                    }
                }
                row.expires_at = earliest_expiry(row.expires_at, self.credential_expiry(&row).await?);
                out.push(row);
            }
        }
        Ok(out)
    }

    async fn credential_expiry(&self, row: &ArtifactRow) -> Result<Option<Timestamp>, StoreError> {
        if row.sensitivity != Sensitivity::CredentialBearing {
            return Ok(None);
        }
        let run = match self.runs.get_metadata(row.run).await {
            Ok(run) => run,
            Err(StoreError::NotFound { .. }) => return Ok(Some(Timestamp::MIN_UTC)),
            Err(error) => return Err(error),
        };
        if run.tenant != row.tenant {
            return Err(StoreError::AccessDenied(
                "credential artifact tenant mismatch".into(),
            ));
        }
        Ok(run.status.is_terminal().then(|| {
            // Clock skew or a missing finish timestamp cannot postpone erasure.
            run.finished_at
                .filter(|finished| *finished <= self.clock.now())
                .unwrap_or(Timestamp::MIN_UTC)
        }))
    }

    async fn delete_rows(&self, doomed: &[ArtifactRow]) -> Result<u64, StoreError> {
        if doomed.is_empty() {
            return Ok(0);
        }
        let doomed_ids: BTreeSet<ArtifactId> = doomed.iter().map(|r| r.id).collect();
        let doomed_keys: BTreeSet<&str> = doomed.iter().map(|r| r.object_key.as_str()).collect();
        let still_used: BTreeSet<String> = self
            .rows()
            .await?
            .into_iter()
            .filter(|r| !doomed_ids.contains(&r.id))
            .map(|r| r.object_key)
            .collect();
        for key in doomed_keys {
            if !still_used.contains(key) {
                observed("delete", self.blobs.delete(key)).await?;
            }
        }
        for row in doomed {
            observed("delete", self.blobs.delete(&index_key(row.id))).await?;
        }
        if let Some(index) = &self.index {
            index
                .mark_deleted(&doomed.iter().map(|r| r.id).collect::<Vec<_>>())
                .await?;
        }
        Ok(doomed.len() as u64)
    }
}

fn earliest_expiry(left: Option<Timestamp>, right: Option<Timestamp>) -> Option<Timestamp> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

/// `{class}/{tenant}/{run}/{blake3}` (assignment key layout).
#[must_use]
pub fn object_key(class: Sensitivity, tenant: TenantId, run: CrawlRunId, digest: &Digest) -> String {
    format!("{}/{}/{}/{}", class.as_str(), tenant, run, digest.to_hex())
}

fn index_key(id: ArtifactId) -> String {
    format!("{INDEX_PREFIX}{id}.json")
}

/// The artifact id of an index-record key; `None` for object keys.
fn index_id(key: &str) -> Option<ArtifactId> {
    let id = key.strip_prefix(INDEX_PREFIX)?.strip_suffix(".json")?;
    id.parse::<uuid::Uuid>().ok().map(ArtifactId)
}

/// Artifact `kind` implied by class and content type when the caller does not name one.
#[must_use]
pub fn infer_kind(class: Sensitivity, content_type: &str) -> &'static str {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    match (class, ct) {
        (Sensitivity::CredentialBearing, _) => "storage_state",
        (_, "text/markdown") => "markdown",
        (_, "text/html") => "html",
        (_, "text/plain") => "robots",
        (_, c) if c.starts_with("image/") => "screenshot",
        (Sensitivity::Sensitive, "application/json") => "manifest",
        (Sensitivity::Content, _) => "html",
        _ => "evidence",
    }
}

#[async_trait]
impl<B: ArtifactBlobs> ArtifactStore for ObjectArtifactStore<B> {
    fn spool_pressure_permille(&self) -> Option<u16> {
        Some(self.spool.pressure_permille())
    }
    async fn read_archive_content(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        max_bytes: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let row = self.row(artifact.id).await?.ok_or_else(|| StoreError::NotFound {
            entity: "artifact",
            id: artifact.id.to_string(),
        })?;
        if row.tenant != tenant || row.run != run {
            return Err(StoreError::AccessDenied("archive content scope mismatch".into()));
        }
        self.read_content_limited(artifact, max_bytes).await
    }
    async fn put_archive_file(
        &self,
        run: CrawlRunId,
        content_type: &str,
        file: &Path,
        max_bytes: u64,
    ) -> Result<ArtifactRef, StoreError> {
        let source = self.runs.get_metadata(run).await?;
        // Gate before opening even a temporary content file.
        if source.retention.mode == RetentionMode::Zdr {
            return Err(StoreError::RetentionDenied(
                "durable archive forbidden for zdr".into(),
            ));
        }
        let now = self.clock.now();
        let expires_at = artifact_expiry(
            Sensitivity::Content,
            content_type,
            source.retention.mode,
            u32::from(source.retention.days),
            source.created_at,
        );
        if expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(StoreError::RetentionDenied("archive source expired".into()));
        }
        if let Some(attached) = self.sealing(Sensitivity::Content, &source)? {
            return self
                .put_sealed_file(attached, &source, content_type, file, max_bytes, now, expires_at)
                .await;
        }
        let mut input = tokio::fs::File::open(file)
            .await
            .map_err(|e| io(&e, "open archive"))?;
        let mut hash = blake3::Hasher::new();
        hash.update(DIGEST_DOMAIN.as_bytes());
        hash.update(&[0]);
        let mut size = 0u64;
        let mut buffer = [0u8; 32 * 1024];
        loop {
            let n = input
                .read(&mut buffer)
                .await
                .map_err(|e| io(&e, "read archive"))?;
            if n == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(n).map_err(|_| StoreError::Conflict("archive chunk size".into()))?)
                .ok_or_else(|| StoreError::Conflict("archive size overflow".into()))?;
            if size > max_bytes {
                return Err(StoreError::RetentionDenied("archive byte budget exceeded".into()));
            }
            hash.update(&buffer[..n]);
        }
        let digest = Digest(*hash.finalize().as_bytes());
        let key = object_key(Sensitivity::Content, source.tenant, run, &digest);
        self.spool.ensure_file(&self.blobs, &key, file, size).await?;
        crate::chaos::pause("archive.after_object_put").await;
        let row = ArtifactRow {
            id: ArtifactId::new(),
            tenant: source.tenant,
            run,
            kind: "evidence".into(),
            bucket: self.blobs.bucket().into(),
            object_key: key,
            size_bytes: size,
            digest,
            content_type: content_type.into(),
            sensitivity: Sensitivity::Content,
            created_at: now,
            expires_at,
        };
        let bytes = serde_json::to_vec(&row).map_err(|e| StoreError::Serialization(e.to_string()))?;
        self.spool.put(&self.blobs, &index_key(row.id), &bytes).await?;
        if let Some(index) = &self.index {
            index.record(&row).await?;
        }
        Ok(ArtifactRef { id: row.id, digest })
    }

    async fn copy_archive_content(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        file: &Path,
        max_bytes: u64,
    ) -> Result<u64, StoreError> {
        let source = self.runs.get_metadata(run).await?;
        if source.tenant != tenant || source.retention.mode == RetentionMode::Zdr {
            return Err(StoreError::RetentionDenied(
                "archive source is not retained tenant content".into(),
            ));
        }
        let row = self.row(artifact.id).await?.ok_or_else(|| StoreError::NotFound {
            entity: "artifact",
            id: artifact.id.to_string(),
        })?;
        if row.tenant != tenant
            || row.run != run
            || row.sensitivity != Sensitivity::Content
            || row.digest != artifact.digest
            || row.size_bytes > max_bytes
            || row.expires_at.is_some_and(|expiry| expiry <= self.clock.now())
        {
            return Err(StoreError::RetentionDenied(
                "archive artifact ownership, expiry or bound failed".into(),
            ));
        }
        let sealed = self.sealed_custody(&row).await?;
        if let Some(sealed) = &sealed {
            return self.copy_sealed_to_file(&row, sealed, file, max_bytes).await;
        }
        if row.object_key != object_key(row.sensitivity, tenant, run, &row.digest) {
            return Err(StoreError::RetentionDenied(
                "archive artifact ownership, expiry or bound failed".into(),
            ));
        }
        let mut input = self.blobs.reader(&row.object_key).await?;
        let mut output = tokio::fs::File::create(file)
            .await
            .map_err(|e| io(&e, "create archive spool"))?;
        let mut hash = blake3::Hasher::new();
        hash.update(DIGEST_DOMAIN.as_bytes());
        hash.update(&[0]);
        let mut size = 0u64;
        let mut buffer = [0u8; 32 * 1024];
        loop {
            let n = input
                .read(&mut buffer)
                .await
                .map_err(|e| io(&e, "read archive source"))?;
            if n == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(n).map_err(|_| StoreError::Conflict("archive chunk size".into()))?)
                .ok_or_else(|| StoreError::Conflict("archive size overflow".into()))?;
            if size > max_bytes || size > row.size_bytes {
                return Err(StoreError::RetentionDenied(
                    "archive source exceeds approved size".into(),
                ));
            }
            hash.update(&buffer[..n]);
            output
                .write_all(&buffer[..n])
                .await
                .map_err(|e| io(&e, "write archive spool"))?;
        }
        if size != row.size_bytes || Digest(*hash.finalize().as_bytes()) != row.digest {
            return Err(StoreError::RetentionDenied("archive source fixity failed".into()));
        }
        output.flush().await.map_err(|e| io(&e, "flush archive spool"))?;
        Ok(size)
    }
    async fn put(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        self.put_kind(run, class, infer_kind(class, content_type), content_type, bytes)
            .await
    }

    async fn put_until(
        &self,
        run: CrawlRunId,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
        deadline: Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        self.put_kind_until(
            run,
            class,
            infer_kind(class, content_type),
            content_type,
            bytes,
            Some(deadline),
        )
        .await
    }

    async fn erase_run_credentials(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        if !self.runs.get_metadata(run).await?.status.is_terminal() {
            return Err(StoreError::Conflict("credential run is not terminal".into()));
        }
        let doomed: Vec<_> = self
            .rows()
            .await?
            .into_iter()
            .filter(|row| row.run == run && row.sensitivity == Sensitivity::CredentialBearing)
            .collect();
        self.delete_rows(&doomed).await
    }

    async fn put_page(
        &self,
        run: CrawlRunId,
        page: i64,
        class: Sensitivity,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        if let (Some(buffer), Sensitivity::Content) = (&self.zdr, class) {
            let run_row = self.runs.get_metadata(run).await?;
            if run_row.retention.mode == RetentionMode::Zdr {
                return buffer
                    .insert(
                        run_row.tenant,
                        run,
                        page,
                        infer_kind(class, content_type),
                        content_type,
                        bytes,
                    )
                    .await;
            }
        }
        self.put(run, class, content_type, bytes).await
    }

    async fn put_dataset(
        &self,
        run: CrawlRunId,
        page: i64,
        rendition: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        crawlx_core::dataset::validate_identifier(rendition)?;
        let owner = self.runs.get_metadata(run).await?;
        if owner.retention.mode == RetentionMode::Zdr {
            let buffer = self
                .zdr
                .as_ref()
                .ok_or_else(|| StoreError::RetentionDenied("dataset volatile sink unavailable".into()))?;
            return buffer
                .insert(
                    owner.tenant,
                    run,
                    page,
                    &format!("dataset.{rendition}"),
                    content_type,
                    bytes,
                )
                .await;
        }
        self.put_kind(
            run,
            Sensitivity::Content,
            infer_kind(Sensitivity::Content, content_type),
            content_type,
            bytes,
        )
        .await
    }
    async fn put_dataset_until(
        &self,
        run: CrawlRunId,
        page: i64,
        rendition: &str,
        content_type: &str,
        bytes: &[u8],
        deadline: Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        crawlx_core::dataset::validate_identifier(rendition)?;
        let owner = self.runs.get_metadata(run).await?;
        if owner.retention.mode == RetentionMode::Zdr {
            let buffer = self
                .zdr
                .as_ref()
                .ok_or_else(|| StoreError::RetentionDenied("dataset volatile sink unavailable".into()))?;
            return buffer
                .insert_until(
                    owner.tenant,
                    run,
                    page,
                    &format!("dataset.{rendition}"),
                    content_type,
                    bytes,
                    deadline,
                )
                .await;
        }
        self.put_kind_until(
            run,
            Sensitivity::Content,
            infer_kind(Sensitivity::Content, content_type),
            content_type,
            bytes,
            Some(deadline),
        )
        .await
    }

    async fn dataset_content(
        &self,
        run: CrawlRunId,
        page: i64,
        artifact: &ArtifactRef,
        size_bytes: u64,
    ) -> Result<crawlx_core::dataset::DatasetContentV1, StoreError> {
        let owner = self.runs.get_metadata(run).await?;
        if owner.retention.mode == RetentionMode::Zdr {
            let buffer = self
                .zdr
                .as_ref()
                .ok_or_else(|| StoreError::RetentionDenied("dataset volatile sink unavailable".into()))?;
            let (expires_at, actual_size) = buffer
                .content_metadata(owner.tenant, run, page, artifact)
                .await?
                .ok_or_else(|| StoreError::RetentionDenied("dataset content_expired".into()))?;
            if actual_size != size_bytes {
                return Err(StoreError::RetentionDenied(
                    "dataset volatile length mismatch".into(),
                ));
            }
            return Ok(crawlx_core::dataset::DatasetContentV1::Volatile {
                page,
                artifact: artifact.clone(),
                expires_at,
            });
        }
        let row = self
            .row(artifact.id)
            .await?
            .filter(|row| {
                row.run == run
                    && row.tenant == owner.tenant
                    && row.digest == artifact.digest
                    && row.size_bytes == size_bytes
                    && matches!(row.sensitivity, Sensitivity::Content | Sensitivity::Metadata)
                    && row.expires_at.is_none_or(|end| end > self.clock.now())
            })
            .ok_or_else(|| StoreError::RetentionDenied("dataset artifact metadata unavailable".into()))?;
        let _ = row;
        Ok(crawlx_core::dataset::DatasetContentV1::Durable {
            artifact: artifact.clone(),
        })
    }

    async fn get(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
        if let Some(buffer) = self.zdr.as_ref().filter(|buffer| buffer.is_enabled()) {
            let blob = match self.read_scope {
                Some((tenant, run)) => buffer.read_for_run(tenant, run, artifact).await?,
                None => buffer.read(artifact).await?,
            };
            if let Some(blob) = blob {
                return Ok(blob.bytes);
            }
        }
        let missing = || StoreError::NotFound {
            entity: "artifact",
            id: artifact.id.to_string(),
        };
        let row = self.row(artifact.id).await?.ok_or_else(missing)?;
        if row.id != artifact.id
            || self
                .read_scope
                .is_some_and(|(tenant, run)| row.tenant != tenant || row.run != run)
            || row.digest != artifact.digest
            || row.expires_at.is_some_and(|e| e <= self.clock.now())
        {
            return Err(missing());
        }
        if let Some(sealed) = self.sealed_custody(&row).await? {
            return self.sealed_content(&row, &sealed).await;
        }
        let bytes = observed("get", self.blobs.get(&row.object_key))
            .await?
            .ok_or_else(missing)?;
        if Digest::of(DIGEST_DOMAIN, &bytes) != row.digest {
            return Err(StoreError::Backend(format!(
                "artifact {} failed digest verification",
                artifact.id
            )));
        }
        Ok(bytes)
    }

    async fn presign(&self, artifact: &ArtifactRef, ttl: Duration) -> Result<Option<url::Url>, StoreError> {
        let missing = || StoreError::NotFound {
            entity: "artifact",
            id: artifact.id.to_string(),
        };
        let row = self.row(artifact.id).await?.ok_or_else(missing)?;
        if row.id != artifact.id
            || self
                .read_scope
                .is_some_and(|(tenant, run)| row.tenant != tenant || row.run != run)
            || row.digest != artifact.digest
            || row.expires_at.is_some_and(|e| e <= self.clock.now())
        {
            return Err(missing());
        }
        if self.sealed_custody(&row).await?.is_some() {
            return Err(StoreError::AccessDenied(
                "sealed artifact cannot be presigned".into(),
            ));
        }
        if row.sensitivity != Sensitivity::Content {
            return Err(StoreError::AccessDenied(format!(
                "{} artifacts are served through the api, never by presigned url",
                row.sensitivity.as_str()
            )));
        }
        self.blobs
            .presign(&row.object_key, ttl.min(PRESIGN_MAX_TTL))
            .await
    }
}

#[async_trait]
impl<B: ArtifactBlobs> ArtifactReaper for ObjectArtifactStore<B> {
    async fn erase_artifact(&self, artifact: &ArtifactRef) -> Result<u64, StoreError> {
        ObjectArtifactStore::erase_artifact(self, artifact).await
    }
    async fn reap_expired(&self, now: Timestamp) -> Result<u64, StoreError> {
        let buffered = match &self.zdr {
            Some(buffer) if buffer.is_enabled() => buffer.sweep(now).await?,
            _ => 0,
        };
        let doomed: Vec<ArtifactRow> = self
            .rows()
            .await?
            .into_iter()
            .filter(|r| r.expires_at.is_some_and(|e| e <= now))
            .collect();
        Ok(self.delete_rows(&doomed).await?.saturating_add(buffered))
    }

    async fn purge_run(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let buffered = match &self.zdr {
            Some(buffer) if buffer.is_enabled() => buffer.purge_run_id(run).await?,
            _ => 0,
        };
        let doomed: Vec<ArtifactRow> = self.rows().await?.into_iter().filter(|r| r.run == run).collect();
        Ok(self.delete_rows(&doomed).await?.saturating_add(buffered))
    }

    async fn collect_orphans(&self, live: &LiveArtifacts, older_than: Timestamp) -> Result<u64, StoreError> {
        let mut removed = 0u64;
        for entry in observed("list", self.blobs.list("")).await? {
            // Audit exports and ZDR delivery files have independent lifecycle owners.
            if entry.modified >= older_than
                || entry.key.starts_with(crate::audit::EXPORT_PREFIX)
                || entry.key.starts_with("zdr/")
            {
                continue;
            }
            match index_id(&entry.key) {
                Some(id) => {
                    if !live.ids.contains(&id) {
                        observed("delete", self.blobs.delete(&entry.key)).await?;
                    }
                }
                None => {
                    if !live.object_keys.contains(&entry.key) {
                        observed("delete", self.blobs.delete(&entry.key)).await?;
                        removed += 1;
                    }
                }
            }
        }
        Ok(removed)
    }
}

/// Directory backend. Keys are slash-separated relative paths; writes go through a
/// temporary file and an atomic rename.
pub struct FsBlobs {
    root: PathBuf,
}

impl FsBlobs {
    /// Backend rooted at `root`, creating the directory if needed.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Unavailable`] if the root directory cannot be created.
    pub async fn open(root: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let root = root.into();
        tokio::fs::create_dir_all(&root)
            .await
            .map_err(|e| StoreError::Unavailable(format!("create {}: {e}", root.display())))?;
        Ok(Self { root })
    }

    fn path(&self, key: &str) -> Result<PathBuf, StoreError> {
        if key.is_empty()
            || key
                .split('/')
                .any(|seg| seg.is_empty() || seg == "." || seg == "..")
            || key.contains('\\')
        {
            return Err(StoreError::Conflict(format!("invalid object key {key:?}")));
        }
        Ok(self.root.join(key))
    }
}

fn io(e: &std::io::Error, what: &str) -> StoreError {
    StoreError::Unavailable(format!("{what}: {e}"))
}

#[async_trait]
impl ArtifactBlobs for FsBlobs {
    fn bucket(&self) -> &str {
        "fs"
    }
    async fn reader(&self, key: &str) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        Ok(Box::new(
            tokio::fs::File::open(self.path(key)?)
                .await
                .map_err(|e| io(&e, "open object"))?,
        ))
    }
    async fn put_file(&self, key: &str, file: &Path, size: u64) -> Result<(), StoreError> {
        let destination = self.path(key)?;
        let parent = destination
            .parent()
            .ok_or_else(|| StoreError::Conflict("object parent missing".into()))?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| io(&e, "create object parent"))?;
        let parent = parent.to_path_buf();
        let temporary = tokio::task::spawn_blocking(move || tempfile::NamedTempFile::new_in(parent))
            .await
            .map_err(|e| StoreError::Unavailable(format!("object spool task: {e}")))?
            .map_err(|e| io(&e, "create object spool"))?
            .into_temp_path();
        let input = tokio::fs::File::open(file)
            .await
            .map_err(|e| io(&e, "open object source"))?;
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&temporary)
            .await
            .map_err(|e| io(&e, "open object spool"))?;
        let copied = tokio::io::copy(&mut input.take(size.saturating_add(1)), &mut output)
            .await
            .map_err(|e| io(&e, "copy object"))?;
        if copied != size {
            return Err(StoreError::Conflict(
                "archive source changed during upload".into(),
            ));
        }
        output.sync_all().await.map_err(|e| io(&e, "sync object"))?;
        tokio::fs::rename(&temporary, destination)
            .await
            .map_err(|e| io(&e, "publish object"))?;
        Ok(())
    }

    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let path = self.path(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| io(&e, "create dir"))?;
        }
        let tmp = path.with_extension(format!("tmp-{}", uuid::Uuid::now_v7()));
        tokio::fs::write(&tmp, bytes).await.map_err(|e| io(&e, "write"))?;
        tokio::fs::rename(&tmp, &path).await.map_err(|e| io(&e, "rename"))
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        match tokio::fs::read(self.path(key)?).await {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(&e, "read")),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        tokio::fs::try_exists(self.path(key)?)
            .await
            .map_err(|e| io(&e, "stat"))
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        match tokio::fs::remove_file(self.path(key)?).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io(&e, "delete")),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<BlobEntry>, StoreError> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut rd = match tokio::fs::read_dir(&dir).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io(&e, "read_dir")),
            };
            while let Some(entry) = rd.next_entry().await.map_err(|e| io(&e, "read_dir"))? {
                let path = entry.path();
                if entry.file_type().await.map_err(|e| io(&e, "file_type"))?.is_dir() {
                    stack.push(path);
                } else if let Some(key) = relative_key(&self.root, &path) {
                    if key.starts_with(prefix) && !key.contains(".tmp-") {
                        let modified = entry
                            .metadata()
                            .await
                            .and_then(|m| m.modified())
                            .map_err(|e| io(&e, "mtime"))?;
                        out.push(BlobEntry {
                            key,
                            modified: Timestamp::from(modified),
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }
}

fn relative_key(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let parts: Vec<&str> = rel.components().filter_map(|c| c.as_os_str().to_str()).collect();
    Some(parts.join("/"))
}

/// In-memory backend. Write times come from the wall clock so
/// [`ArtifactReaper::collect_orphans`] behaves as with a real backend.
#[derive(Default)]
pub struct MemBlobs {
    map: Mutex<BTreeMap<String, (Vec<u8>, Timestamp)>>,
}

impl MemBlobs {
    /// Number of stored objects including index records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.lock().len()
    }

    /// Whether the backend holds no objects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.lock().is_empty()
    }

    /// Keys excluding index records.
    #[must_use]
    pub fn object_keys(&self) -> Vec<String> {
        self.map
            .lock()
            .keys()
            .filter(|k| !k.starts_with(INDEX_PREFIX))
            .cloned()
            .collect()
    }
}

#[async_trait]
impl ArtifactBlobs for MemBlobs {
    fn bucket(&self) -> &str {
        "mem"
    }
    async fn reader(&self, key: &str) -> Result<Box<dyn tokio::io::AsyncRead + Send + Unpin>, StoreError> {
        let bytes = self
            .map
            .lock()
            .get(key)
            .map(|(bytes, _)| bytes.clone())
            .ok_or_else(|| StoreError::NotFound {
                entity: "object",
                id: "memory object".into(),
            })?;
        Ok(Box::new(std::io::Cursor::new(bytes)))
    }
    async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.map
            .lock()
            .insert(key.to_owned(), (bytes.to_vec(), chrono::Utc::now()));
        Ok(())
    }
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.map.lock().get(key).map(|(b, _)| b.clone()))
    }
    async fn exists(&self, key: &str) -> Result<bool, StoreError> {
        Ok(self.map.lock().contains_key(key))
    }
    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.map.lock().remove(key);
        Ok(())
    }
    async fn list(&self, prefix: &str) -> Result<Vec<BlobEntry>, StoreError> {
        Ok(self
            .map
            .lock()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, (_, modified))| BlobEntry {
                key: k.clone(),
                modified: *modified,
            })
            .collect())
    }
}

#[async_trait]
impl ArtifactIndex for crate::Pg {
    async fn record(&self, row: &ArtifactRow) -> Result<(), StoreError> {
        sqlx::query(
            "INSERT INTO artifacts (artifact_id, tenant_id, run_id, kind, bucket, object_key, size_bytes, content_digest, content_type, sensitivity, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::text::sensitivity_class, $11, $12)",
        )
        .bind(row.id.0)
        .bind(row.tenant.0)
        .bind(row.run.0)
        .bind(&row.kind)
        .bind(&row.bucket)
        .bind(&row.object_key)
        .bind(i64::try_from(row.size_bytes).map_err(|_| StoreError::Serialization("artifact too large".to_owned()))?)
        .bind(row.digest.0.to_vec())
        .bind(&row.content_type)
        .bind(row.sensitivity.as_str())
        .bind(row.created_at)
        .bind(row.expires_at)
        .execute(&self.pool)
        .await
        .map_err(crate::error::db)?;
        Ok(())
    }

    async fn retention(&self, id: ArtifactId) -> Result<Option<ArtifactRetention>, StoreError> {
        let row = sqlx::query("SELECT expires_at, deleted_at FROM artifacts WHERE artifact_id = $1")
            .bind(id.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(crate::error::db)?;
        row.map(|row| {
            Ok(ArtifactRetention {
                expires_at: crate::codec::get(&row, "expires_at")?,
                deleted_at: crate::codec::get(&row, "deleted_at")?,
            })
        })
        .transpose()
    }

    async fn mark_deleted(&self, ids: &[ArtifactId]) -> Result<(), StoreError> {
        let raw: Vec<uuid::Uuid> = ids.iter().map(|i| i.0).collect();
        sqlx::query(
            "UPDATE artifacts SET deleted_at = now() WHERE artifact_id = ANY($1) AND deleted_at IS NULL",
        )
        .bind(raw)
        .execute(&self.pool)
        .await
        .map_err(crate::error::db)?;
        Ok(())
    }
}
