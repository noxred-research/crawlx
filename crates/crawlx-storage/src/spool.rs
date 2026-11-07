//! Bounded, process-local upload spool (RB-06).
//!
//! Pending uploads stay in memory, never in a plaintext filesystem WAL. Admission
//! counts both queued and active entries before copying payloads. One uploader
//! drains the queue; each caller waits for its upload before committing references.
//! Retry attempts reuse one `Bytes` allocation. Dropping a caller cancels its work
//! and releases its reservation; there are no detached tasks. Shutdown cancels all
//! pending work. A crash loses pending bytes, not committed artifact references:
//! this spool is not durable and cannot replace the journal/checkpoint WAL.

use crate::artifacts::{observed, ArtifactBlobs};
use bytes::Bytes;
use crawlx_core::StoreError;
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use std::future::Future;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

/// Limits for the privacy-safe, memory-only upload spool.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct UploadSpoolConfig {
    /// Maximum payload bytes across queued and active entries.
    pub max_bytes: u64,
    /// Maximum queued and active entries, including empty objects.
    pub max_entries: usize,
    /// Maximum attempts per upload, including the first attempt.
    pub max_attempts: u32,
    /// Delay between retryable failures.
    pub retry_delay: Duration,
    /// Deadline for each individual backend request.
    pub request_timeout: Duration,
}

impl Default for UploadSpoolConfig {
    fn default() -> Self {
        Self {
            max_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 1024,
            max_attempts: 3,
            retry_delay: Duration::from_secs(1),
            request_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Default)]
struct Usage {
    bytes: u64,
    entries: usize,
}

/// Bounded caller-driven queue; no task or payload outlives its upload future.
#[derive(Debug)]
#[non_exhaustive]
pub struct UploadSpool {
    config: UploadSpoolConfig,
    usage: Mutex<Usage>,
    uploader: Semaphore,
    stop: CancellationToken,
}

impl Default for UploadSpool {
    fn default() -> Self {
        Self::from_config(UploadSpoolConfig::default())
    }
}

impl UploadSpool {
    /// Construct a spool with explicit limits.
    ///
    /// # Errors
    /// Returns [`StoreError::Conflict`] for zero capacity, attempts or request timeout.
    pub fn new(config: UploadSpoolConfig) -> Result<Self, StoreError> {
        if config.max_bytes == 0
            || config.max_entries == 0
            || config.max_attempts == 0
            || config.request_timeout.is_zero()
        {
            return Err(StoreError::Conflict(
                "upload spool limits must be positive".into(),
            ));
        }
        Ok(Self::from_config(config))
    }

    fn from_config(config: UploadSpoolConfig) -> Self {
        Metrics::global()
            .gauge(names::OBJECTSTORE_SPOOL_BYTES)
            .add(0.0, &[]);
        Self {
            config,
            usage: Mutex::new(Usage::default()),
            uploader: Semaphore::new(1),
            stop: CancellationToken::new(),
        }
    }

    /// Bytes reserved by queued and active uploads.
    #[must_use]
    pub fn queued_bytes(&self) -> u64 {
        self.usage.lock().bytes
    }

    /// Entries reserved by queued and active uploads.
    #[must_use]
    pub fn queued_entries(&self) -> usize {
        self.usage.lock().entries
    }

    /// Greater of actual byte and entry occupancy, bounded to 0..=1000.
    #[must_use]
    pub fn pressure_permille(&self) -> u16 {
        let usage = self.usage.lock();
        let bytes = u128::from(usage.bytes).saturating_mul(1000) / u128::from(self.config.max_bytes.max(1));
        let entries = u128::try_from(usage.entries)
            .unwrap_or(u128::MAX)
            .saturating_mul(1000)
            / u128::try_from(self.config.max_entries.max(1)).unwrap_or(u128::MAX);
        u16::try_from(bytes.max(entries).min(1000)).unwrap_or(1000)
    }

    /// Cancel queued uploads and interrupt active requests and retry delays.
    /// Completed objects remain available; unfinished uploads cannot publish references.
    pub fn cancel(&self) {
        self.stop.cancel();
    }

    /// Reserve the existing upload quota before reading a committed delivery batch.
    ///
    /// # Errors
    /// Returns a quota, cancellation or numeric-bound error without copying any content.
    pub fn reserve_delivery(&self, bytes: u64) -> Result<Reservation<'_>, StoreError> {
        let bytes =
            usize::try_from(bytes).map_err(|_| StoreError::Conflict("delivery spool byte limit".into()))?;
        self.reserve(bytes)
    }

    fn reserve(&self, len: usize) -> Result<Reservation<'_>, StoreError> {
        let bytes = u64::try_from(len)
            .map_err(|_| StoreError::Conflict("upload exceeds spool byte capacity".into()))?;
        let mut usage = self.usage.lock();
        if self.stop.is_cancelled() {
            return Err(cancelled());
        }
        if usage.entries >= self.config.max_entries
            || bytes > self.config.max_bytes.saturating_sub(usage.bytes)
        {
            return Err(StoreError::Unavailable("upload spool full".into()));
        }
        usage.bytes += bytes;
        usage.entries += 1;
        Metrics::global()
            .gauge(names::OBJECTSTORE_SPOOL_BYTES)
            .add(bytes as f64, &[]);
        Ok(Reservation { spool: self, bytes })
    }

    /// Ensure a content-addressed object exists, retrying transient backend failures.
    ///
    /// # Errors
    /// Returns an explicit full/cancelled error, or the final backend/timeout error.
    pub async fn ensure<B: ArtifactBlobs>(
        &self,
        backend: &B,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.upload(backend, key, bytes, true).await
    }
    /// Upload one bounded disk spool through existing admission, cancellation and timeout.
    /// The file remains caller-owned and no collection-sized payload enters memory.
    ///
    /// # Errors
    /// Returns quota, cancellation, timeout or backend errors.
    pub async fn ensure_file<B: ArtifactBlobs>(
        &self,
        backend: &B,
        key: &str,
        file: &std::path::Path,
        size: u64,
    ) -> Result<(), StoreError> {
        let size = usize::try_from(size).map_err(|_| StoreError::Conflict("archive spool size".into()))?;
        let _reservation = self.reserve(size)?;
        let _permit = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(cancelled()),
            permit = self.uploader.acquire() => permit.map_err(|_| cancelled())?,
        };
        self.request(
            "put",
            backend.put_file(
                key,
                file,
                u64::try_from(size).map_err(|_| StoreError::Conflict("archive spool size".into()))?,
            ),
        )
        .await
    }

    /// Upload an index record, waiting for completion before returning.
    ///
    /// # Errors
    /// Returns an explicit full/cancelled error, or the final backend/timeout error.
    pub async fn put<B: ArtifactBlobs>(
        &self,
        backend: &B,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        self.upload(backend, key, bytes, false).await
    }

    async fn upload<B: ArtifactBlobs>(
        &self,
        backend: &B,
        key: &str,
        bytes: &[u8],
        if_missing: bool,
    ) -> Result<(), StoreError> {
        let _reservation = self.reserve(bytes.len())?;
        let _permit = tokio::select! {
            biased;
            () = self.stop.cancelled() => return Err(cancelled()),
            permit = self.uploader.acquire() => permit.map_err(|_| cancelled())?,
        };
        // The caller retains the source slice while queued. Allocate only when
        // the backend actually needs the object, then reuse it on every retry.
        let mut shared = None;
        for attempt in 0..self.config.max_attempts {
            let result = async {
                if if_missing && self.request("exists", backend.exists(key)).await? {
                    return Ok(());
                }
                let payload = shared.get_or_insert_with(|| Bytes::copy_from_slice(bytes));
                self.request("put", backend.put_shared(key, payload.clone()))
                    .await
            }
            .await;
            match result {
                Ok(()) => return Ok(()),
                Err(error) => {
                    if !error.is_retryable()
                        || attempt == self.config.max_attempts - 1
                        || self.stop.is_cancelled()
                    {
                        return Err(error);
                    }
                    tokio::select! {
                        biased;
                        () = self.stop.cancelled() => return Err(cancelled()),
                        () = tokio::time::sleep(self.config.retry_delay) => {}
                    }
                }
            }
        }
        Err(StoreError::Unavailable("upload spool exhausted attempts".into()))
    }

    async fn request<T>(
        &self,
        op: &'static str,
        call: impl Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        observed(op, async {
            tokio::select! {
                biased;
                () = self.stop.cancelled() => Err(cancelled()),
                result = tokio::time::timeout(self.config.request_timeout, call) => {
                    result.unwrap_or_else(|_| Err(StoreError::Unavailable("upload request timed out".into())))
                }
            }
        })
        .await
    }
}

fn cancelled() -> StoreError {
    StoreError::Unavailable("upload spool cancelled".into())
}

/// A live reservation against the shared artifact spool; drop releases capacity.
#[must_use]
pub struct Reservation<'a> {
    spool: &'a UploadSpool,
    bytes: u64,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut usage = self.spool.usage.lock();
        usage.bytes -= self.bytes;
        usage.entries -= 1;
        Metrics::global()
            .gauge(names::OBJECTSTORE_SPOOL_BYTES)
            .add(-(self.bytes as f64), &[]);
    }
}
