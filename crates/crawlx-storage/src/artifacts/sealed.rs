//! Encrypted write and read paths of [`ObjectArtifactStore`].
//!
//! Writes stage ciphertext only and return a reference after the run-wide secret
//! epoch recheck and atomic catalog publication confirmed. Reads decrypt through the
//! catalog's custody row. Legacy plaintext artifacts take the existing paths.

use super::{index_key, io, observed, ArtifactBlobs, ArtifactRow, ObjectArtifactStore, DIGEST_DOMAIN};
use crate::artifact_crypto::ArtifactContext;
use crate::artifact_custody::{
    ciphertext_bound, collect_sealed, crypto_error, domain_hasher, is_stale_epoch, key_error,
    open_sealed_bytes, scan_error, sealed_stream, ArtifactCustody, CustodyWrites,
};
use crate::artifact_key_crypto::ArtifactKeys;
use crate::custody::{
    encrypted_object_key, ArtifactKeyCustody, ArtifactKeyEnvelope, CiphertextIdentity,
    CIPHERTEXT_DIGEST_DOMAIN,
};
use bytes::Bytes;
use crawlx_core::captcha::CaptchaSecrets;
use crawlx_core::custody::{
    current_frozen_archive, current_producer, CustodyLease, CustodySource, FrozenArchiveGrant, SecretEpoch,
};
use crawlx_core::hash::Digest;
use crawlx_core::repo::{RunMetadata, Sensitivity};
use crawlx_core::secret::{SecretByteScanner, SecretScanError, SecretScanLimits, SecretScanMode};
use crawlx_core::{ArtifactId, ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};

/// Attempts at one publication across epoch races and unknown outcomes.
const MAX_PUBLISH_ATTEMPTS: usize = 8;
/// Attempts at deleting a rejected staged object before reporting it unresolved.
const DELETE_ATTEMPTS: usize = 3;

/// Custody attached to a store.
pub(super) struct StoreCustody {
    pub(super) custody: Arc<dyn ArtifactCustody>,
    pub(super) keys: Arc<dyn ArtifactKeys>,
    pub(super) writes: CustodyWrites,
}

/// Wrapped-key custody of one encrypted artifact together with its key provider.
pub(super) struct Sealed {
    pub(super) keys: Arc<dyn ArtifactKeys>,
    pub(super) custody: ArtifactKeyCustody,
}

/// What a staged ciphertext was made from; used to rescan after an epoch change.
enum Plaintext<'a> {
    Bytes(&'a [u8]),
    File {
        path: &'a Path,
        size: u64,
        digest: Digest,
    },
}

/// Plaintext file reader that hashes and secret-scans exactly the bytes it hands out.
struct ScannedFile {
    inner: tokio::fs::File,
    hasher: blake3::Hasher,
    scanner: Option<SecretByteScanner>,
    failure: Option<SecretScanError>,
}

impl AsyncRead for ScannedFile {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let fresh = &buf.filled()[before..];
            self.hasher.update(fresh);
            if let Some(scanner) = self.scanner.as_mut() {
                if let Err(error) = scanner.push(fresh) {
                    self.failure = Some(error);
                    return Poll::Ready(Err(std::io::Error::other("secret inspection refused the source")));
                }
            }
        }
        poll
    }
}

fn producer_for(tenant: TenantId, run: CrawlRunId) -> Result<CustodyLease, StoreError> {
    let lease = current_producer()
        .ok_or_else(|| StoreError::Unavailable("artifact custody producer lease required".into()))?;
    if lease.tenant != tenant || lease.run != run {
        return Err(StoreError::AccessDenied(
            "artifact custody producer lease belongs to another run".into(),
        ));
    }
    Ok(lease)
}

/// Terminal-run archive output authority.
///
/// A terminal run has closed secret registration, so no live snapshot exists to rescan against.
/// Every output of its claimed export must carry a [`FrozenArchiveGrant`] bound to exactly this
/// producer; the plaintext path no longer exists. Live runs return `None` and are unchanged.
/// The returned expiry is clamped to the grant, never extended.
fn frozen_output(
    lease: &CustodyLease,
    run: &RunMetadata,
    class: Sensitivity,
    kind: &str,
    content_type: &str,
    expires_at: Option<Timestamp>,
) -> Result<Option<(FrozenArchiveGrant, Option<Timestamp>)>, StoreError> {
    // A feed finalizer seals under the live run-wide registry: its run is ending, never closed.
    if !run.status.is_terminal() || matches!(lease.source, CustodySource::FeedFinalization(_)) {
        return Ok(None);
    }
    if !matches!(lease.source, CustodySource::ArchiveExport(_)) {
        return Err(StoreError::RetentionDenied(
            "run ended; artifact not retained".into(),
        ));
    }
    let grant = current_frozen_archive().ok_or_else(|| {
        StoreError::RetentionDenied("terminal archive output requires a frozen archive grant".into())
    })?;
    grant.check_lease(lease)?;
    let expires_at = match (expires_at, grant.custody.expires_at) {
        (Some(output), Some(ceiling)) => Some(output.min(ceiling)),
        (output, ceiling) => output.or(ceiling),
    };
    grant.check_output(class, expires_at, kind, content_type)?;
    Ok(Some((grant, expires_at)))
}

async fn hash_file(path: &Path, domain: &str) -> Result<(Digest, u64), StoreError> {
    let mut input = tokio::fs::File::open(path)
        .await
        .map_err(|e| io(&e, "open staged ciphertext"))?;
    let mut hasher = domain_hasher(domain);
    let mut count = 0u64;
    let mut buffer = vec![0u8; 32 * 1024];
    loop {
        let n = input
            .read(&mut buffer)
            .await
            .map_err(|e| io(&e, "read staged ciphertext"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        count = count.saturating_add(n as u64);
    }
    Ok((Digest(*hasher.finalize().as_bytes()), count))
}

/// Refuse `plaintext` if it contains any value of `secrets`.
async fn rescan(plaintext: &Plaintext<'_>, secrets: &CaptchaSecrets) -> Result<(), StoreError> {
    match plaintext {
        Plaintext::Bytes(bytes) => {
            let found = secrets
                .contains_bytes(bytes)
                .map_err(|_| StoreError::Unavailable("secret registry unavailable".into()))?;
            if found {
                return Err(scan_error(SecretScanError::Secret));
            }
            Ok(())
        }
        Plaintext::File { path, size, digest } => {
            let mut scanner = secrets
                .scoped_byte_scanner(SecretScanMode::Auto, SecretScanLimits::new(*size))
                .map_err(scan_error)?;
            let mut input = tokio::fs::File::open(path)
                .await
                .map_err(|e| io(&e, "open archive"))?;
            let mut hasher = domain_hasher(DIGEST_DOMAIN);
            let mut count = 0u64;
            let mut buffer = vec![0u8; 32 * 1024];
            loop {
                let n = input
                    .read(&mut buffer)
                    .await
                    .map_err(|e| io(&e, "read archive"))?;
                if n == 0 {
                    break;
                }
                hasher.update(&buffer[..n]);
                count = count.saturating_add(n as u64);
                scanner.push(&buffer[..n]).map_err(scan_error)?;
            }
            scanner.finish().map_err(scan_error)?;
            if count != *size || Digest(*hasher.finalize().as_bytes()) != *digest {
                return Err(StoreError::Conflict(
                    "archive source changed during upload".into(),
                ));
            }
            Ok(())
        }
    }
}

impl<B: ArtifactBlobs> ObjectArtifactStore<B> {
    /// The attached custody when this write must be encrypted.
    ///
    /// A terminal run has closed secret registration, so a Session or Url producer still
    /// writing for it is refused: a plaintext write would bypass the run-wide secret check.
    /// Archive-export producers of a terminal run are sealed under a frozen archive grant, never
    /// plaintext. Writes without any producer (operator inputs) keep the legacy plaintext path.
    pub(super) fn sealing(
        &self,
        class: Sensitivity,
        run: &RunMetadata,
    ) -> Result<Option<&StoreCustody>, StoreError> {
        let producer = current_producer().map(|lease| lease.source);
        let terminal_archive =
            run.status.is_terminal() && matches!(producer, Some(CustodySource::ArchiveExport(_)));
        let Some(custody) = self.custody.as_ref().filter(|custody| {
            custody.writes == CustodyWrites::Required
                && matches!(class, Sensitivity::Content | Sensitivity::Sensitive)
        }) else {
            if terminal_archive && matches!(class, Sensitivity::Content | Sensitivity::Sensitive) {
                return Err(StoreError::RetentionDenied(
                    "terminal archive output requires sealed custody".into(),
                ));
            }
            return Ok(None);
        };
        if !run.status.is_terminal() {
            return Ok(Some(custody));
        }
        match producer {
            Some(CustodySource::Session(_) | CustodySource::Url(_)) => Err(StoreError::RetentionDenied(
                "run ended; artifact not retained".into(),
            )),
            // The grant itself is demanded by the sealed write, never a plaintext fallback.
            Some(CustodySource::ArchiveExport(_)) => Ok(Some(custody)),
            // Recovery finalizes feeds of a run that already ended; the claim keeps the
            // run-wide secret check, so it never falls back to plaintext.
            Some(CustodySource::FeedFinalization(_)) => Ok(Some(custody)),
            _ => Ok(None),
        }
    }

    /// Encrypted custody of `id`; `None` for a legacy plaintext artifact.
    pub(super) async fn sealed_custody_for(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<Option<Sealed>, StoreError> {
        let Some(attached) = &self.custody else {
            return Ok(None);
        };
        Ok(attached
            .custody
            .custody(tenant, run, id)
            .await?
            .map(|custody| Sealed {
                keys: Arc::clone(&attached.keys),
                custody,
            }))
    }

    /// Encrypted custody of `row`, requiring its catalog key to name the encrypted object.
    pub(super) async fn sealed_custody(&self, row: &ArtifactRow) -> Result<Option<Sealed>, StoreError> {
        let Some(sealed) = self.sealed_custody_for(row.tenant, row.run, row.id).await? else {
            return Ok(None);
        };
        if row.object_key
            != encrypted_object_key(row.tenant, row.run, row.id, sealed.custody.ciphertext.digest)
        {
            return Err(StoreError::Conflict(
                "sealed artifact catalog key does not match its custody".into(),
            ));
        }
        Ok(Some(sealed))
    }

    /// Verified plaintext chunks of a sealed artifact; the final chunk follows all checks.
    pub(super) async fn sealed_content_stream(
        &self,
        row: &ArtifactRow,
        sealed: &Sealed,
        max_bytes: u64,
    ) -> Result<futures::stream::BoxStream<'static, Result<Bytes, StoreError>>, StoreError> {
        let reader = self.blobs.reader(&row.object_key).await?;
        sealed_stream(sealed.keys.as_ref(), reader, row, &sealed.custody, max_bytes).await
    }

    /// Whole verified plaintext of a sealed artifact, bounded by its catalog size.
    pub(super) async fn sealed_content(
        &self,
        row: &ArtifactRow,
        sealed: &Sealed,
    ) -> Result<Vec<u8>, StoreError> {
        let stream = self.sealed_content_stream(row, sealed, row.size_bytes).await?;
        collect_sealed(stream, row.size_bytes).await
    }

    /// Decrypt ciphertext already read by a bounded filesystem read.
    pub(super) async fn sealed_open_bytes(
        &self,
        sealed: &Sealed,
        row: &ArtifactRow,
        stored: Vec<u8>,
    ) -> Result<Vec<u8>, StoreError> {
        let mut plain = open_sealed_bytes(sealed.keys.as_ref(), stored, row, &sealed.custody).await?;
        Ok(std::mem::take(&mut *plain))
    }

    /// Copy a verified sealed artifact into `file`; the file holds only authenticated bytes.
    pub(super) async fn copy_sealed_to_file(
        &self,
        row: &ArtifactRow,
        sealed: &Sealed,
        file: &Path,
        max_bytes: u64,
    ) -> Result<u64, StoreError> {
        use futures::TryStreamExt as _;
        use tokio::io::AsyncWriteExt as _;
        let mut stream = self.sealed_content_stream(row, sealed, max_bytes).await?;
        let mut output = tokio::fs::File::create(file)
            .await
            .map_err(|e| io(&e, "create archive spool"))?;
        let mut size = 0u64;
        let copied = async {
            while let Some(chunk) = stream.try_next().await? {
                size = size.saturating_add(chunk.len() as u64);
                output
                    .write_all(&chunk)
                    .await
                    .map_err(|e| io(&e, "write archive spool"))?;
            }
            output.flush().await.map_err(|e| io(&e, "flush archive spool"))
        }
        .await;
        if let Err(error) = copied {
            // Unverified plaintext must not remain readable on disk.
            drop(output);
            let _ = tokio::fs::remove_file(file).await;
            return Err(error);
        }
        Ok(size)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn put_sealed_bytes(
        &self,
        attached: &StoreCustody,
        run_row: &RunMetadata,
        class: Sensitivity,
        kind: &str,
        content_type: &str,
        bytes: &[u8],
        now: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Result<ArtifactRef, StoreError> {
        let lease = producer_for(run_row.tenant, run_row.id)?;
        let frozen = frozen_output(&lease, run_row, class, kind, content_type, expires_at)?;
        let expires_at = frozen.as_ref().map_or(expires_at, |(_, clamped)| *clamped);
        let plaintext = Plaintext::Bytes(bytes);
        // A terminal run has no live registry: its sources were validated when they were sealed.
        let version = if let Some((grant, _)) = &frozen {
            grant.epoch
        } else {
            let snapshot = attached.custody.snapshot(&lease).await?;
            rescan(&plaintext, &snapshot.secrets).await?;
            snapshot.version
        };
        let size =
            u64::try_from(bytes.len()).map_err(|_| StoreError::Conflict("artifact size overflow".into()))?;
        let id = ArtifactId::new();
        let context = ArtifactContext::new(run_row.tenant, run_row.id, id);
        let prepared = attached
            .keys
            .prepare(&context, size, size)
            .await
            .map_err(key_error)?;
        let mut ciphertext = Vec::new();
        let wanted = usize::try_from(ciphertext_bound(size)?)
            .map_err(|_| StoreError::Conflict("artifact size overflow".into()))?;
        ciphertext
            .try_reserve_exact(wanted)
            .map_err(|source| StoreError::ResourceExhausted {
                resource: "sealed artifact",
                requested: wanted,
                available: 0,
                source: Some(source),
            })?;
        let sealed = prepared
            .encryption
            .seal(bytes, &mut ciphertext)
            .await
            .map_err(crypto_error)?;
        if u64::try_from(ciphertext.len()).ok() != Some(sealed.ciphertext_len) {
            return Err(StoreError::Conflict("sealed artifact length mismatch".into()));
        }
        let identity = CiphertextIdentity::new(
            Digest::of(CIPHERTEXT_DIGEST_DOMAIN, &ciphertext),
            u64::try_from(ciphertext.len())
                .map_err(|_| StoreError::Conflict("artifact size overflow".into()))?,
        )?;
        let object_key = encrypted_object_key(run_row.tenant, run_row.id, id, identity.digest);
        self.spool.ensure(&self.blobs, &object_key, &ciphertext).await?;
        drop(ciphertext);
        crate::chaos::pause("artifact.after_object_put").await;
        let row = ArtifactRow {
            id,
            tenant: run_row.tenant,
            run: run_row.id,
            kind: kind.to_owned(),
            bucket: self.blobs.bucket().to_owned(),
            object_key,
            size_bytes: size,
            digest: Digest::of(DIGEST_DOMAIN, bytes),
            content_type: content_type.to_owned(),
            sensitivity: class,
            created_at: now,
            expires_at,
        };
        self.publish_confirmed(
            attached,
            &lease,
            version,
            frozen.as_ref().map(|(grant, _)| grant),
            &row,
            &identity,
            &prepared.envelope,
            &plaintext,
        )
        .await?;
        self.record_published(attached, &row).await?;
        Ok(ArtifactRef {
            id,
            digest: row.digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn put_sealed_file(
        &self,
        attached: &StoreCustody,
        run_row: &RunMetadata,
        class: Sensitivity,
        content_type: &str,
        file: &Path,
        max_bytes: u64,
        now: Timestamp,
        expires_at: Option<Timestamp>,
    ) -> Result<ArtifactRef, StoreError> {
        let lease = producer_for(run_row.tenant, run_row.id)?;
        let frozen = frozen_output(&lease, run_row, class, "evidence", content_type, expires_at)?;
        let expires_at = frozen.as_ref().map_or(expires_at, |(_, clamped)| *clamped);
        // A terminal run has no live registry; its sources were validated when they were sealed.
        let snapshot = if frozen.is_some() {
            None
        } else {
            Some(attached.custody.snapshot(&lease).await?)
        };
        let version = match (&frozen, &snapshot) {
            (Some((grant, _)), _) => grant.epoch,
            (None, Some(snapshot)) => snapshot.version,
            (None, None) => {
                return Err(StoreError::Unavailable(
                    "secret authority snapshot unavailable".into(),
                ));
            }
        };
        let input = tokio::fs::File::open(file)
            .await
            .map_err(|e| io(&e, "open archive"))?;
        let size = input.metadata().await.map_err(|e| io(&e, "stat archive"))?.len();
        if size > max_bytes {
            return Err(StoreError::RetentionDenied("archive byte budget exceeded".into()));
        }
        let id = ArtifactId::new();
        let context = ArtifactContext::new(run_row.tenant, run_row.id, id);
        let prepared = attached
            .keys
            .prepare(&context, size, max_bytes)
            .await
            .map_err(key_error)?;
        // Ciphertext is staged under the process temporary directory, never next to plaintext.
        let temporary = tokio::task::spawn_blocking(tempfile::NamedTempFile::new)
            .await
            .map_err(|e| StoreError::Unavailable(format!("archive spool task: {e}")))?
            .map_err(|e| io(&e, "create sealed archive spool"))?
            .into_temp_path();
        let mut output = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&temporary)
            .await
            .map_err(|e| io(&e, "open sealed archive spool"))?;
        let scanner = match &snapshot {
            Some(snapshot) => Some(
                snapshot
                    .secrets
                    .scoped_byte_scanner(SecretScanMode::Auto, SecretScanLimits::new(size))
                    .map_err(scan_error)?,
            ),
            None => None,
        };
        let mut source = ScannedFile {
            inner: input,
            hasher: domain_hasher(DIGEST_DOMAIN),
            scanner,
            failure: None,
        };
        let sealed = prepared.encryption.seal(&mut source, &mut output).await;
        if let Some(failure) = source.failure.take() {
            return Err(scan_error(failure));
        }
        let sealed = sealed.map_err(crypto_error)?;
        if let Some(scanner) = source.scanner.take() {
            scanner.finish().map_err(scan_error)?;
        }
        output
            .sync_all()
            .await
            .map_err(|e| io(&e, "sync sealed archive spool"))?;
        drop(output);
        let digest = Digest(*source.hasher.finalize().as_bytes());
        let (ciphertext_digest, ciphertext_size) = hash_file(&temporary, CIPHERTEXT_DIGEST_DOMAIN).await?;
        if ciphertext_size != sealed.ciphertext_len {
            return Err(StoreError::Conflict("sealed archive length mismatch".into()));
        }
        let identity = CiphertextIdentity::new(ciphertext_digest, ciphertext_size)?;
        let object_key = encrypted_object_key(run_row.tenant, run_row.id, id, identity.digest);
        self.spool
            .ensure_file(&self.blobs, &object_key, &temporary, identity.size_bytes)
            .await?;
        crate::chaos::pause("archive.after_object_put").await;
        let row = ArtifactRow {
            id,
            tenant: run_row.tenant,
            run: run_row.id,
            kind: "evidence".into(),
            bucket: self.blobs.bucket().into(),
            object_key,
            size_bytes: size,
            digest,
            content_type: content_type.into(),
            sensitivity: class,
            created_at: now,
            expires_at,
        };
        let plaintext = Plaintext::File {
            path: file,
            size,
            digest,
        };
        self.publish_confirmed(
            attached,
            &lease,
            version,
            frozen.as_ref().map(|(grant, _)| grant),
            &row,
            &identity,
            &prepared.envelope,
            &plaintext,
        )
        .await?;
        self.record_published(attached, &row).await?;
        Ok(ArtifactRef { id, digest })
    }

    /// Publish until confirmed; never return success without a confirmed publication.
    ///
    /// A lost epoch race changed nothing: refresh the snapshot, rescan the same plaintext
    /// and retry the identical row, ciphertext identity and envelope. A secret found
    /// deletes the staged object. An unknown outcome retries the identical publication
    /// and, if it stays unknown, keeps the staged object because it may be published.
    #[allow(clippy::too_many_arguments)]
    async fn publish_confirmed(
        &self,
        attached: &StoreCustody,
        lease: &CustodyLease,
        mut version: SecretEpoch,
        frozen: Option<&FrozenArchiveGrant>,
        row: &ArtifactRow,
        identity: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
        plaintext: &Plaintext<'_>,
    ) -> Result<(), StoreError> {
        let mut stale = 0usize;
        let mut unknown = 0usize;
        loop {
            if row.expires_at.is_some_and(|expiry| expiry <= self.clock.now()) {
                self.reject_staged(attached, row, unknown > 0).await?;
                return Err(StoreError::RetentionDenied(
                    "archive source expired before publication".into(),
                ));
            }
            let published = match frozen {
                Some(grant) => {
                    attached
                        .custody
                        .publish_frozen_archive(grant, lease, row, identity, envelope)
                        .await
                }
                None => {
                    attached
                        .custody
                        .publish(lease, version, row, identity, envelope)
                        .await
                }
            };
            match published {
                Ok(()) => return Ok(()),
                // A closed terminal epoch cannot be raced: there is nothing to refresh or rescan.
                Err(error) if frozen.is_some() && is_stale_epoch(&error) => {
                    self.reject_staged(attached, row, unknown > 0).await?;
                    return Err(error);
                }
                Err(error) if is_stale_epoch(&error) => {
                    stale += 1;
                    if stale > MAX_PUBLISH_ATTEMPTS {
                        self.reject_staged(attached, row, unknown > 0).await?;
                        return Err(StoreError::Unavailable(
                            "artifact publication kept losing secret epoch races".into(),
                        ));
                    }
                    let refreshed = match attached.custody.snapshot(lease).await {
                        Ok(snapshot) => snapshot,
                        Err(error) => {
                            self.reject_staged(attached, row, unknown > 0).await?;
                            return Err(error);
                        }
                    };
                    if let Err(refusal) = rescan(plaintext, &refreshed.secrets).await {
                        self.reject_staged(attached, row, unknown > 0).await?;
                        return Err(refusal);
                    }
                    version = refreshed.version;
                }
                Err(error) if error.is_retryable() => {
                    unknown += 1;
                    if unknown > MAX_PUBLISH_ATTEMPTS {
                        return Err(StoreError::Unavailable(
                            "artifact publication outcome unknown; staged object retained".into(),
                        ));
                    }
                    tokio::time::sleep(Duration::from_millis(20 * u64::try_from(unknown).unwrap_or(1))).await;
                }
                Err(error) => {
                    self.reject_staged(attached, row, unknown > 0).await?;
                    return Err(error);
                }
            }
        }
    }

    /// Remove a rejected publication's staged object.
    ///
    /// After any attempt with an unknown outcome the publication may have committed, so the
    /// row is withdrawn first (idempotent), then the object deleted. If the withdrawal cannot be
    /// confirmed the object is kept: it may still back a live row.
    async fn reject_staged(
        &self,
        attached: &StoreCustody,
        row: &ArtifactRow,
        possibly_published: bool,
    ) -> Result<(), StoreError> {
        if possibly_published {
            if attached
                .custody
                .withdraw(row.tenant, row.run, row.id)
                .await
                .is_err()
            {
                return Err(StoreError::Unavailable(
                    "published artifact withdrawal unresolved".into(),
                ));
            }
            if let Some(index) = &self.index {
                if index.mark_deleted(&[row.id]).await.is_err() {
                    return Err(StoreError::Unavailable(
                        "published artifact withdrawal unresolved".into(),
                    ));
                }
            }
        }
        self.discard_staged(&row.object_key).await
    }

    /// Delete a rejected, unpublished staged object; success means it is confirmed gone.
    async fn discard_staged(&self, key: &str) -> Result<(), StoreError> {
        let mut last = None;
        for attempt in 0..DELETE_ATTEMPTS {
            match observed("delete", self.blobs.delete(key)).await {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last = Some(error);
                    tokio::time::sleep(Duration::from_millis(
                        20 * u64::try_from(attempt + 1).unwrap_or(1),
                    ))
                    .await;
                }
            }
        }
        tracing::warn!(error = ?last, "rejected staged encrypted object could not be deleted");
        Err(StoreError::Unavailable(
            "staged encrypted object unresolved: delete after rejected publication failed".into(),
        ))
    }

    /// Make a published row findable by the object index and the attached catalog index.
    async fn record_published(&self, attached: &StoreCustody, row: &ArtifactRow) -> Result<(), StoreError> {
        let outcome = async {
            let record = serde_json::to_vec(row).map_err(|e| StoreError::Serialization(e.to_string()))?;
            self.spool.put(&self.blobs, &index_key(row.id), &record).await?;
            if !attached.custody.publishes_catalog_row() {
                if let Some(index) = &self.index {
                    index.record(row).await?;
                }
            }
            Ok(())
        }
        .await;
        if outcome.is_err() {
            // Published but unreadable: withdraw it rather than leave an unreachable row.
            if let Some(index) = &self.index {
                let _ = index.mark_deleted(&[row.id]).await;
            }
            let _ = self.blobs.delete(&index_key(row.id)).await;
            let _ = self.blobs.delete(&row.object_key).await;
        }
        outcome
    }
}
