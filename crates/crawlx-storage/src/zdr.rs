//! Bounded, tenant-scoped zero-data-retention delivery.
//!
//! [`DeliveryBuffer::new`] is explicit process-memory mode. [`DeliveryBuffer::open_fs`]
//! shares delivery content through a filesystem's `zdr/` namespace; filesystem work
//! runs on Tokio's blocking pool under a crash-released OS lock. Production selects
//! dedicated nonpersistent Redis or explicitly configured shared tmpfs/ramfs through
//! [`DeliveryBuffer::open_runtime`]. Without either configuration, delivery is disabled.
//! No backend writes the normal artifact index or durable content namespace.
//!
//! A page expires from its **first** insertion, after at most one hour. Reads and
//! additional renditions never renew its deadline or eviction age. Acknowledgment,
//! run purge, capacity eviction, and expiry remove the complete page atomically from
//! readers' perspective. All participating processes must use the same limits.
//!
//! Call [`DeliveryBuffer::sweep`] periodically, including when no runs are active.
//! Opening shared storage also sweeps. Filesystem deployments need an independent
//! lifecycle sweeper during downtime of API/workers: it must acquire `zdr/.lock`,
//! remove orphan temporaries, and delete expired pages. Committed page mtime stays at
//! first insertion; an mtime-only one-hour cleanup is a secondary backstop, not a
//! replacement for that sweeper. Never remove or replace the lock file while any
//! process can access this namespace. Redis uses first-insert native TTL instead.
//! Time for application expiry comes exclusively from the injected [`Clock`].

use crawlx_core::hash::Digest;
use crawlx_core::{ArtifactId, ArtifactRef, Clock, CrawlRunId, StoreError, TenantId, Timestamp};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

mod fs;
mod redis;

/// Planning default: pages held at once.
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;
/// Planning default: bytes held at once (256 MiB).
pub const DEFAULT_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Maximum lifetime of a page, measured from its first insertion (1 h).
pub const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60);

/// Capacity and lifetime of a [`DeliveryBuffer`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct BufferLimits {
    /// Pages held at once; inserting past it evicts the oldest page.
    pub max_entries: usize,
    /// Content bytes held at once, across all tenants and processes sharing the buffer.
    pub max_bytes: usize,
    /// Lifetime from first insertion, clamped to [`DEFAULT_TTL`].
    pub ttl: Duration,
}

impl Default for BufferLimits {
    fn default() -> Self {
        Self {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_bytes: DEFAULT_MAX_BYTES,
            ttl: DEFAULT_TTL,
        }
    }
}

/// One buffered rendition of a page (`markdown`, `html`, ...).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferedBlob {
    /// Reference handed to the page row; `read` resolves it back to these bytes.
    pub artifact: ArtifactRef,
    /// MIME type supplied by the writer.
    pub content_type: String,
    /// The content.
    pub bytes: Vec<u8>,
}

/// Everything buffered for one page of a tenant's run.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferedPage {
    /// Tenant that owns the page.
    pub tenant: TenantId,
    /// Run the page belongs to.
    pub run: CrawlRunId,
    /// `PageRecord::frontier_id` of the page.
    pub page: i64,
    /// Renditions keyed by artifact kind (`markdown`, `html`, `robots`, ...).
    pub blobs: BTreeMap<String, BufferedBlob>,
    /// When the page was first inserted; never refreshed by another rendition.
    pub inserted_at: Timestamp,
    /// When [`DeliveryBuffer::sweep`] removes the page.
    pub expires_at: Timestamp,
}

impl BufferedPage {
    /// Total blob bytes, saturating if an in-memory caller constructs an oversized page.
    #[must_use]
    pub fn size(&self) -> usize {
        self.blobs
            .values()
            .fold(0usize, |n, blob| n.saturating_add(blob.bytes.len()))
    }
}

impl std::fmt::Debug for BufferedBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedBlob")
            .field("artifact", &self.artifact)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for BufferedPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferedPage")
            .field("tenant", &self.tenant)
            .field("run", &self.run)
            .field("page", &self.page)
            .field("renditions", &self.blobs.len())
            .field("bytes", &self.size())
            .field("inserted_at", &self.inserted_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

type PageKey = (TenantId, CrawlRunId, i64);

/// The bounded header allows filesystem scans without decoding every content blob.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PageMeta {
    tenant: TenantId,
    run: CrawlRunId,
    page: i64,
    inserted_at: Timestamp,
    expires_at: Timestamp,
    sequence: u64,
    bytes: usize,
    artifacts: BTreeMap<ArtifactId, String>,
    #[serde(default)]
    content_metadata: BTreeMap<ArtifactId, (Digest, usize)>,
}

impl PageMeta {
    fn key(&self) -> PageKey {
        (self.tenant, self.run, self.page)
    }

    fn from_page(page: &BufferedPage, sequence: u64) -> Self {
        Self {
            tenant: page.tenant,
            run: page.run,
            page: page.page,
            inserted_at: page.inserted_at,
            expires_at: page.expires_at,
            sequence,
            bytes: page.size(),
            artifacts: page
                .blobs
                .iter()
                .map(|(kind, blob)| (blob.artifact.id, kind.clone()))
                .collect(),
            content_metadata: page
                .blobs
                .values()
                .map(|blob| (blob.artifact.id, (blob.artifact.digest, blob.bytes.len())))
                .collect(),
        }
    }
}

/// Synchronous operations run inside one memory mutex or one filesystem lock.
trait Pages {
    fn metadata(&self) -> &BTreeMap<PageKey, PageMeta>;
    fn load(&self, key: &PageKey) -> Result<Option<BufferedPage>, StoreError>;
    fn load_blob(&self, key: &PageKey, kind: &str) -> Result<Option<BufferedBlob>, StoreError> {
        Ok(self.load(key)?.and_then(|mut page| page.blobs.remove(kind)))
    }
    fn locate_artifact(&self, id: ArtifactId) -> Option<(PageKey, &str)> {
        self.metadata()
            .iter()
            .find_map(|(key, meta)| meta.artifacts.get(&id).map(|kind| (*key, kind.as_str())))
    }
    fn take_for_update(&mut self, key: &PageKey) -> Result<Option<BufferedPage>, StoreError> {
        self.load(key)
    }
    fn put(&mut self, meta: PageMeta, page: BufferedPage) -> Result<(), StoreError>;
    fn remove(&mut self, key: &PageKey) -> Result<bool, StoreError>;
}

#[derive(Default)]
struct MemoryPages {
    metadata: BTreeMap<PageKey, PageMeta>,
    pages: BTreeMap<PageKey, BufferedPage>,
    artifacts: BTreeMap<ArtifactId, (PageKey, String)>,
}

impl MemoryPages {
    fn take(&mut self, key: &PageKey) -> Option<BufferedPage> {
        if let Some(meta) = self.metadata.remove(key) {
            for id in meta.artifacts.keys() {
                self.artifacts.remove(id);
            }
        }
        self.pages.remove(key)
    }
}

impl Pages for MemoryPages {
    fn metadata(&self) -> &BTreeMap<PageKey, PageMeta> {
        &self.metadata
    }

    fn load(&self, key: &PageKey) -> Result<Option<BufferedPage>, StoreError> {
        Ok(self.pages.get(key).cloned())
    }

    fn load_blob(&self, key: &PageKey, kind: &str) -> Result<Option<BufferedBlob>, StoreError> {
        Ok(self.pages.get(key).and_then(|page| page.blobs.get(kind)).cloned())
    }

    fn locate_artifact(&self, id: ArtifactId) -> Option<(PageKey, &str)> {
        self.artifacts.get(&id).map(|(key, kind)| (*key, kind.as_str()))
    }

    fn take_for_update(&mut self, key: &PageKey) -> Result<Option<BufferedPage>, StoreError> {
        Ok(self.take(key))
    }

    fn put(&mut self, meta: PageMeta, page: BufferedPage) -> Result<(), StoreError> {
        drop(self.take(&meta.key()));
        for (id, kind) in &meta.artifacts {
            self.artifacts.insert(*id, (meta.key(), kind.clone()));
        }
        self.metadata.insert(meta.key(), meta);
        self.pages.insert((page.tenant, page.run, page.page), page);
        Ok(())
    }

    fn remove(&mut self, key: &PageKey) -> Result<bool, StoreError> {
        Ok(self.take(key).is_some())
    }
}

enum Backend {
    Memory(Arc<Mutex<MemoryPages>>),
    Filesystem(Arc<std::path::PathBuf>),
    Redis(Arc<redis::RedisPages>),
    Disabled,
}

/// Bounded delivery content in explicit memory, shared-filesystem, or volatile Redis mode.
pub struct DeliveryBuffer {
    backend: Backend,
    clock: Arc<dyn Clock>,
    limits: BufferLimits,
}

impl std::fmt::Debug for DeliveryBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryBuffer")
            .field(
                "backend",
                &match &self.backend {
                    Backend::Memory(_) => "memory",
                    Backend::Filesystem(_) => "filesystem",
                    Backend::Redis(_) => "redis",
                    Backend::Disabled => "disabled",
                },
            )
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl DeliveryBuffer {
    /// Create an explicitly process-local memory buffer; TTL is clamped to one hour.
    #[must_use]
    pub fn new(clock: Arc<dyn Clock>, mut limits: BufferLimits) -> Self {
        limits.ttl = limits.ttl.min(DEFAULT_TTL);
        Self {
            backend: Backend::Memory(Arc::new(Mutex::new(MemoryPages::default()))),
            clock,
            limits,
        }
    }

    /// Create a process-local buffer with 10 000 pages, 256 MiB, and one-hour TTL.
    #[must_use]
    pub fn with_defaults(clock: Arc<dyn Clock>) -> Self {
        Self::new(clock, BufferLimits::default())
    }

    /// Open shared delivery storage beneath `artifact_root/zdr/`, then sweep expired pages.
    ///
    /// Cooperating processes serialize scans, replacement, eviction, and deletion through
    /// `zdr/.lock`. The OS releases that lock on process death. Startup also removes
    /// abandoned replacement temporaries and enforces the configured capacity limits.
    ///
    /// # Errors
    /// Returns filesystem, lock, malformed-page, serialization, or blocking-task errors.
    /// Symlinks within the delivery namespace are rejected rather than followed.
    pub async fn open_fs(
        artifact_root: impl AsRef<Path>,
        clock: Arc<dyn Clock>,
        mut limits: BufferLimits,
    ) -> Result<Self, StoreError> {
        limits.ttl = limits.ttl.min(DEFAULT_TTL);
        let root = artifact_root.as_ref().join("zdr");
        let init_root = root.clone();
        tokio::task::spawn_blocking(move || fs::initialize(&init_root))
            .await
            .map_err(join_error)??;
        let buffer = Self {
            backend: Backend::Filesystem(Arc::new(root)),
            clock,
            limits,
        };
        let now = buffer.clock.now();
        buffer
            .with_pages(move |pages| {
                sweep_pages(pages, now)?;
                enforce_capacity(pages, limits, None, 0)?;
                Ok(())
            })
            .await?;
        Ok(buffer)
    }

    /// Open a dedicated, nonpersistent Redis delivery backend shared across nodes.
    ///
    /// The server must disable RDB/AOF, have no replicas, and use `noeviction`.
    /// These settings are rechecked before every operation. Deployment ACLs must deny
    /// persistence/reconfiguration and replication commands while permitting CONFIG GET.
    /// Page hashes receive native first-insert TTL; reads/renditions never renew it.
    ///
    /// # Errors
    /// Returns connection/configuration errors, unsafe server configuration, invalid
    /// limits, malformed content, or atomic-script errors. Errors never include `url`.
    pub async fn open_redis(
        url: &str,
        clock: Arc<dyn Clock>,
        limits: BufferLimits,
    ) -> Result<Self, StoreError> {
        let prefix = crate::redis_namespace::key_prefix_from_env()?;
        Self::open_redis_prefixed(url, clock, limits, &prefix).await
    }

    /// As [`Self::open_redis`] under an explicit key prefix (see
    /// [`crate::redis_namespace::normalize_key_prefix`]): deployments sharing one instance use
    /// different prefixes and never read, expire or delete each other's keys.
    ///
    /// # Errors
    /// As [`Self::open_redis`], and [`StoreError::Conflict`] for an invalid prefix.
    pub async fn open_redis_prefixed(
        url: &str,
        clock: Arc<dyn Clock>,
        mut limits: BufferLimits,
        key_prefix: &str,
    ) -> Result<Self, StoreError> {
        let key_prefix = crate::redis_namespace::normalize_key_prefix(key_prefix)?;
        limits.ttl = limits.ttl.min(DEFAULT_TTL);
        let backend = redis::RedisPages::open(url, limits, clock.now(), &key_prefix).await?;
        Ok(Self {
            backend: Backend::Redis(Arc::new(backend)),
            clock,
            limits,
        })
    }

    /// Open explicitly configured production delivery, or a disabled buffer.
    ///
    /// `CRAWLX_ZDR_REDIS_URL` (or its `_FILE` secret-file form) selects dedicated
    /// nonpersistent Redis. Otherwise, explicitly setting `CRAWLX_ZDR_DIR` selects its
    /// `zdr/` child, which must be a shared Linux `tmpfs`/`ramfs` mount. Filesystem
    /// participants must share a UID and an independent lifecycle sweeper.
    /// Missing configuration never silently enables process-local or durable storage.
    ///
    /// # Errors
    /// Returns secret-file, connection, unsafe server/mount configuration, permission,
    /// unsupported-platform, or startup-sweep errors.
    pub async fn open_runtime(clock: Arc<dyn Clock>, mut limits: BufferLimits) -> Result<Self, StoreError> {
        limits.ttl = limits.ttl.min(DEFAULT_TTL);
        let url = if let Some(url) = std::env::var_os("CRAWLX_ZDR_REDIS_URL") {
            Some(
                url.into_string()
                    .map_err(|_| StoreError::RetentionDenied("zdr redis URL must be valid UTF-8".into()))?,
            )
        } else if let Some(path) = std::env::var_os("CRAWLX_ZDR_REDIS_URL_FILE") {
            Some(
                tokio::fs::read_to_string(path)
                    .await
                    .map_err(|_| StoreError::Backend("zdr redis secret file cannot be read".into()))?,
            )
        } else {
            None
        };
        if let Some(url) = url {
            return Self::open_redis(url.trim(), clock, limits).await;
        }
        let Some(base) = std::env::var_os("CRAWLX_ZDR_DIR").map(std::path::PathBuf::from) else {
            return Ok(Self {
                backend: Backend::Disabled,
                clock,
                limits,
            });
        };
        let check_base = base.clone();
        tokio::task::spawn_blocking(move || fs::validate_runtime_root(&check_base))
            .await
            .map_err(join_error)??;
        Self::open_fs(base, clock, limits).await
    }

    /// Whether a delivery backend was explicitly enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        !matches!(self.backend, Backend::Disabled)
    }

    /// Configured limits, including the clamped TTL.
    #[must_use]
    pub const fn limits(&self) -> BufferLimits {
        self.limits
    }

    async fn with_pages<R, F>(&self, operation: F) -> Result<R, StoreError>
    where
        R: Send + 'static,
        F: FnOnce(&mut dyn Pages) -> Result<R, StoreError> + Send + 'static,
    {
        match &self.backend {
            Backend::Memory(inner) => {
                let inner = Arc::clone(inner);
                tokio::task::spawn_blocking(move || operation(&mut *inner.lock()))
                    .await
                    .map_err(join_error)?
            }
            Backend::Filesystem(root) => {
                let root = Arc::clone(root);
                let limits = self.limits;
                tokio::task::spawn_blocking(move || {
                    let mut pages = fs::FilesystemPages::open(&root, limits)?;
                    operation(&mut pages)
                })
                .await
                .map_err(join_error)?
            }
            Backend::Disabled => Err(disabled_error()),
            Backend::Redis(_) => Err(StoreError::Backend(
                "zdr redis operation used local storage path".into(),
            )),
        }
    }

    /// Number of held pages, including expired pages not yet swept.
    ///
    /// # Errors
    /// Returns shared-storage or blocking-task errors.
    pub async fn len(&self) -> Result<usize, StoreError> {
        if let Backend::Redis(redis) = &self.backend {
            return Ok(redis.stats(self.clock.now()).await?.0);
        }
        self.with_pages(|pages| Ok(pages.metadata().len())).await
    }

    /// Whether no page is held, including expired pages not yet swept.
    ///
    /// # Errors
    /// Returns shared-storage or blocking-task errors.
    pub async fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len().await? == 0)
    }

    /// Held blob bytes, including expired pages not yet swept.
    ///
    /// # Errors
    /// Returns shared-storage, accounting-overflow, or blocking-task errors.
    pub async fn bytes(&self) -> Result<usize, StoreError> {
        if let Backend::Redis(redis) = &self.backend {
            return Ok(redis.stats(self.clock.now()).await?.1);
        }
        self.with_pages(|pages| total_bytes(pages.metadata().values()))
            .await
    }

    /// Insert or replace one rendition without renewing the page's first-insert deadline.
    ///
    /// Expired pages are swept before capacity eviction. Eviction always removes the
    /// oldest first-inserted page, across all tenants. A page whose combined renditions
    /// exceed the byte limit is removed entirely. A rendition that cannot fit alone is
    /// refused without changing existing pages.
    ///
    /// # Errors
    /// Returns [`StoreError::RetentionDenied`] for capacity or timestamp overflow, plus
    /// shared-storage, serialization, accounting, and blocking-task errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        kind: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> Result<ArtifactRef, StoreError> {
        self.insert_bounded(tenant, run, page, kind, content_type, bytes, None)
            .await
    }

    /// Store derived metadata/content with a deadline no later than its original source.
    ///
    /// # Errors
    /// Returns retention errors for elapsed deadlines or an attempted deadline extension,
    /// plus shared-storage, quota and serialization errors.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_until(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        kind: &str,
        content_type: &str,
        bytes: &[u8],
        deadline: Timestamp,
    ) -> Result<ArtifactRef, StoreError> {
        self.insert_bounded(tenant, run, page, kind, content_type, bytes, Some(deadline))
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_bounded(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        kind: &str,
        content_type: &str,
        bytes: &[u8],
        deadline: Option<Timestamp>,
    ) -> Result<ArtifactRef, StoreError> {
        if !self.is_enabled() {
            return Err(disabled_error());
        }
        let limits = self.limits;
        if bytes.len() > limits.max_bytes || limits.max_entries == 0 {
            return Err(StoreError::RetentionDenied(
                "zdr delivery rendition exceeds buffer capacity".into(),
            ));
        }
        let now = self.clock.now();
        let expires_at = now
            .checked_add_signed(
                chrono::Duration::from_std(limits.ttl)
                    .map_err(|e| StoreError::RetentionDenied(e.to_string()))?,
            )
            .ok_or_else(|| StoreError::RetentionDenied("zdr delivery expiry overflows timestamp".into()))?;
        let expires_at = deadline.map_or(expires_at, |deadline| deadline.min(expires_at));
        if expires_at <= now {
            return Err(StoreError::RetentionDenied("zdr original content_expired".into()));
        }
        let kind = kind.to_owned();
        let content_type = content_type.to_owned();
        let bytes = bytes.to_vec();
        if let Backend::Redis(redis) = &self.backend {
            return redis
                .insert(tenant, run, page, kind, content_type, bytes, now, expires_at)
                .await;
        }
        self.with_pages(move |pages| {
            sweep_pages(pages, now)?;
            let key = (tenant, run, page);
            if pages
                .metadata()
                .get(&key)
                .is_some_and(|meta| deadline.is_some_and(|end| meta.expires_at > end))
            {
                return Err(StoreError::RetentionDenied(
                    "zdr derived rendition cannot extend original expiry".into(),
                ));
            }
            let sequence = match pages.metadata().get(&key) {
                Some(meta) => meta.sequence,
                None => pages
                    .metadata()
                    .values()
                    .map(|m| m.sequence)
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or_else(|| StoreError::Backend("zdr insertion sequence exhausted".into()))?,
            };
            let artifact = ArtifactRef {
                id: ArtifactId::new(),
                digest: Digest::of(crate::artifacts::DIGEST_DOMAIN, &bytes),
            };
            let blob = BufferedBlob {
                artifact: artifact.clone(),
                content_type,
                bytes,
            };
            let mut entry = pages.take_for_update(&key)?.unwrap_or(BufferedPage {
                tenant,
                run,
                page,
                blobs: BTreeMap::new(),
                inserted_at: now,
                expires_at,
            });
            entry.blobs.insert(kind, blob);
            let meta = PageMeta::from_page(&entry, sequence);
            if meta.bytes > limits.max_bytes {
                pages.remove(&key)?;
                return Err(StoreError::RetentionDenied(
                    "zdr delivery page exceeds buffer capacity".into(),
                ));
            }
            enforce_capacity(pages, limits, Some(key), meta.bytes)?;
            pages.put(meta, entry)?;
            Ok(artifact)
        })
        .await
    }

    /// Get one unexpired page within its tenant and run.
    ///
    /// # Errors
    /// Returns shared-storage, malformed-page, serialization, or blocking-task errors.
    pub async fn get(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
    ) -> Result<Option<BufferedPage>, StoreError> {
        let now = self.clock.now();
        if let Backend::Redis(redis) = &self.backend {
            return redis.get(tenant, run, page, now).await;
        }
        self.with_pages(move |pages| {
            let key = (tenant, run, page);
            if pages
                .metadata()
                .get(&key)
                .is_some_and(|meta| meta.expires_at > now)
            {
                pages.load(&key)
            } else {
                Ok(None)
            }
        })
        .await
    }

    /// List live pages within one tenant and run, sorted by page id.
    ///
    /// # Errors
    /// Returns shared-storage, malformed-page, serialization, or blocking-task errors.
    pub async fn list(&self, tenant: TenantId, run: CrawlRunId) -> Result<Vec<BufferedPage>, StoreError> {
        let now = self.clock.now();
        if let Backend::Redis(redis) = &self.backend {
            return redis.list(tenant, run, now).await;
        }
        self.with_pages(move |pages| {
            pages
                .metadata()
                .range((tenant, run, i64::MIN)..=(tenant, run, i64::MAX))
                .filter(|(_, meta)| meta.expires_at > now)
                .map(|(key, _)| {
                    pages
                        .load(key)?
                        .ok_or_else(|| StoreError::Backend("zdr page disappeared under lock".into()))
                })
                .collect()
        })
        .await
    }

    /// Find a live rendition by id, scoped to the authorized tenant and run.
    ///
    /// # Errors
    /// Returns shared-storage, malformed-page, serialization, or blocking-task errors.
    pub async fn find(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<Option<BufferedBlob>, StoreError> {
        let now = self.clock.now();
        if let Backend::Redis(redis) = &self.backend {
            return redis.find(Some((tenant, run)), id, now).await;
        }
        self.with_pages(move |pages| find_blob(pages, Some((tenant, run)), id, now))
            .await
    }

    /// Resolve a reference only within the authorized tenant and run, checking its digest.
    ///
    /// # Errors
    /// Returns shared-storage, malformed-page, serialization, or blocking-task errors.
    pub async fn read_for_run(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
    ) -> Result<Option<BufferedBlob>, StoreError> {
        Ok(self
            .find(tenant, run, artifact.id)
            .await?
            .filter(|blob| blob.artifact.digest == artifact.digest))
    }

    /// Scoped bounded read; checks shared metadata before allocating response content.
    ///
    /// # Errors
    /// Returns retention denial when the rendition (or filesystem page) exceeds the bound.
    pub async fn read_for_run_limited(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: &ArtifactRef,
        max_bytes: usize,
    ) -> Result<Option<BufferedBlob>, StoreError> {
        let now = self.clock.now();
        let artifact = artifact.clone();
        if let Backend::Redis(redis) = &self.backend {
            return Ok(redis
                .find_limited(Some((tenant, run)), artifact.id, now, max_bytes)
                .await?
                .filter(|blob| blob.artifact.digest == artifact.digest));
        }
        self.with_pages(move |pages| {
            let Some((key, kind)) = pages.locate_artifact(artifact.id) else {
                return Ok(None);
            };
            let kind = kind.to_owned();
            if key.0 != tenant || key.1 != run {
                return Ok(None);
            }
            let Some(meta) = pages.metadata().get(&key) else {
                return Ok(None);
            };
            if meta.expires_at <= now {
                return Ok(None);
            }
            if meta.bytes > max_bytes {
                return Err(StoreError::RetentionDenied(
                    "volatile content exceeds bounded read allowance".into(),
                ));
            }
            Ok(pages
                .load_blob(&key, &kind)?
                .filter(|blob| blob.artifact.digest == artifact.digest))
        })
        .await
    }

    /// Check reference identity, length and original deadline without reading its content.
    ///
    /// # Errors
    /// Returns shared-storage or malformed metadata errors. Legacy headers may require one read.
    pub async fn content_metadata(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        artifact: &ArtifactRef,
    ) -> Result<Option<(Timestamp, u64)>, StoreError> {
        let now = self.clock.now();
        let artifact = artifact.clone();
        if let Backend::Redis(redis) = &self.backend {
            return redis.content_metadata(tenant, run, page, &artifact, now).await;
        }
        self.with_pages(move |pages| {
            let Some(meta) = pages
                .metadata()
                .get(&(tenant, run, page))
                .filter(|meta| meta.expires_at > now)
            else {
                return Ok(None);
            };
            if let Some((digest, size)) = meta.content_metadata.get(&artifact.id) {
                return Ok((*digest == artifact.digest).then_some((
                    meta.expires_at,
                    u64::try_from(*size)
                        .map_err(|_| StoreError::Serialization("volatile length overflow".into()))?,
                )));
            }
            let Some(kind) = meta.artifacts.get(&artifact.id) else {
                return Ok(None);
            };
            Ok(pages
                .load_blob(&(tenant, run, page), kind)?
                .filter(|blob| blob.artifact == artifact)
                .map(|blob| {
                    (
                        meta.expires_at,
                        u64::try_from(blob.bytes.len()).unwrap_or(u64::MAX),
                    )
                }))
        })
        .await
    }
    /// Read a rendition's original page deadline without reading or copying its bytes.
    ///
    /// # Errors
    /// Returns shared-storage or blocking-task errors.
    pub async fn content_deadline(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        page: i64,
        artifact: ArtifactId,
    ) -> Result<Option<Timestamp>, StoreError> {
        let now = self.clock.now();
        if let Backend::Redis(redis) = &self.backend {
            return redis.content_deadline(tenant, run, page, artifact, now).await;
        }
        self.with_pages(move |pages| {
            Ok(pages
                .metadata()
                .get(&(tenant, run, page))
                .filter(|meta| meta.expires_at > now && meta.artifacts.contains_key(&artifact))
                .map(|meta| meta.expires_at))
        })
        .await
    }

    /// Internal capability read: the complete unguessable reference authorizes lookup.
    ///
    /// HTTP consumers must use [`Self::read_for_run`] or [`Self::find`] after tenant/run
    /// authorization instead. This method serves the internal artifact-store contract.
    ///
    /// # Errors
    /// Returns shared-storage, malformed-page, serialization, or blocking-task errors.
    pub async fn read(&self, artifact: &ArtifactRef) -> Result<Option<BufferedBlob>, StoreError> {
        let now = self.clock.now();
        let artifact = artifact.clone();
        if let Backend::Redis(redis) = &self.backend {
            return Ok(redis
                .find(None, artifact.id, now)
                .await?
                .filter(|blob| blob.artifact.digest == artifact.digest));
        }
        self.with_pages(move |pages| {
            Ok(find_blob(pages, None, artifact.id, now)?
                .filter(|blob| blob.artifact.digest == artifact.digest))
        })
        .await
    }

    /// Remove a complete page after successful delivery; return whether it was held.
    ///
    /// # Errors
    /// Returns shared-storage or blocking-task errors.
    pub async fn ack(&self, tenant: TenantId, run: CrawlRunId, page: i64) -> Result<bool, StoreError> {
        if let Backend::Redis(redis) = &self.backend {
            return redis.ack(tenant, run, page, self.clock.now()).await;
        }
        self.with_pages(move |pages| pages.remove(&(tenant, run, page)))
            .await
    }

    /// Remove every held page belonging to one tenant and run.
    ///
    /// # Errors
    /// Returns shared-storage or blocking-task errors.
    pub async fn purge_run(&self, tenant: TenantId, run: CrawlRunId) -> Result<u64, StoreError> {
        if let Backend::Redis(redis) = &self.backend {
            return redis.purge(Some(tenant), run, self.clock.now()).await;
        }
        self.with_pages(move |pages| {
            let keys: Vec<_> = pages
                .metadata()
                .range((tenant, run, i64::MIN)..=(tenant, run, i64::MAX))
                .map(|(key, _)| *key)
                .collect();
            remove_pages(pages, keys)
        })
        .await
    }

    /// Internal erasure capability after the run's tenant row has already been removed.
    /// Public API handlers must use the tenant-scoped [`Self::purge_run`] instead.
    ///
    /// # Errors
    /// Returns shared-storage or blocking-task errors.
    pub(crate) async fn purge_run_id(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        if let Backend::Redis(redis) = &self.backend {
            return redis.purge(None, run, self.clock.now()).await;
        }
        self.with_pages(move |pages| {
            let keys = pages
                .metadata()
                .keys()
                .filter(|key| key.1 == run)
                .copied()
                .collect();
            remove_pages(pages, keys)
        })
        .await
    }

    /// Remove every page whose first-insert deadline ended at or before `now`.
    ///
    /// # Errors
    /// Returns shared-storage or blocking-task errors; failed deletions are not counted.
    pub async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError> {
        if let Backend::Redis(redis) = &self.backend {
            return redis.sweep(now).await;
        }
        self.with_pages(move |pages| sweep_pages(pages, now)).await
    }
}

fn disabled_error() -> StoreError {
    StoreError::RetentionDenied("zdr delivery backend is not configured".into())
}

fn join_error(error: tokio::task::JoinError) -> StoreError {
    StoreError::Backend(format!("zdr blocking operation failed: {error}"))
}

fn total_bytes<'a>(mut metadata: impl Iterator<Item = &'a PageMeta>) -> Result<usize, StoreError> {
    metadata.try_fold(0usize, |n, meta| {
        n.checked_add(meta.bytes)
            .ok_or_else(|| StoreError::Backend("zdr byte accounting overflow".into()))
    })
}

fn enforce_capacity(
    pages: &mut dyn Pages,
    limits: BufferLimits,
    replacing: Option<PageKey>,
    incoming: usize,
) -> Result<(), StoreError> {
    let mut entries = pages
        .metadata()
        .keys()
        .filter(|key| Some(**key) != replacing)
        .count()
        .saturating_add(usize::from(replacing.is_some()));
    let mut bytes = total_bytes(
        pages
            .metadata()
            .iter()
            .filter(|(key, _)| Some(**key) != replacing)
            .map(|(_, meta)| meta),
    )?;
    let fits = |entries: usize, bytes: usize| {
        entries <= limits.max_entries && bytes.checked_add(incoming).is_some_and(|n| n <= limits.max_bytes)
    };
    if fits(entries, bytes) {
        return Ok(());
    }
    let mut victims: Vec<_> = pages
        .metadata()
        .iter()
        .filter(|(key, _)| Some(**key) != replacing)
        .map(|(key, meta)| (meta.sequence, *key, meta.bytes))
        .collect();
    victims.sort_unstable_by_key(|(sequence, key, _)| (*sequence, *key));
    for (_, key, size) in victims {
        pages.remove(&key)?;
        entries = entries.saturating_sub(1);
        bytes = bytes.saturating_sub(size);
        if fits(entries, bytes) {
            return Ok(());
        }
    }
    Err(StoreError::RetentionDenied(
        "zdr delivery buffer has no remaining capacity".into(),
    ))
}

fn sweep_pages(pages: &mut dyn Pages, now: Timestamp) -> Result<u64, StoreError> {
    let keys: Vec<_> = pages
        .metadata()
        .iter()
        .filter(|(_, meta)| meta.expires_at <= now)
        .map(|(key, _)| *key)
        .collect();
    remove_pages(pages, keys)
}

fn remove_pages(pages: &mut dyn Pages, keys: Vec<PageKey>) -> Result<u64, StoreError> {
    let mut count = 0u64;
    for key in keys {
        if pages.remove(&key)? {
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

fn find_blob(
    pages: &dyn Pages,
    scope: Option<(TenantId, CrawlRunId)>,
    id: ArtifactId,
    now: Timestamp,
) -> Result<Option<BufferedBlob>, StoreError> {
    let Some((key, kind)) = pages.locate_artifact(id) else {
        return Ok(None);
    };
    let meta = pages
        .metadata()
        .get(&key)
        .ok_or_else(|| StoreError::Backend("zdr artifact index has no page metadata".into()))?;
    if meta.expires_at <= now || scope.is_some_and(|s| (meta.tenant, meta.run) != s) {
        return Ok(None);
    }
    let blob = pages
        .load_blob(&key, kind)?
        .ok_or_else(|| StoreError::Serialization("zdr artifact index has no rendition".into()))?;
    Ok(Some(blob))
}

#[cfg(test)]
mod tests;
