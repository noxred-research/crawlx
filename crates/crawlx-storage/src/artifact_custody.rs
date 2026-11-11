//! Run-wide custody of encrypted artifacts: secret registration and epoch-checked
//! atomic publication of ciphertext catalog rows.
//!
//! A worker stages an artifact as ciphertext only. The plaintext object is never
//! written. Publication atomically rechecks the run-wide secret epoch that the
//! plaintext was scanned against. A secret registered while the upload was in
//! flight therefore changes the epoch, the publication is refused and the staged
//! ciphertext is deleted. [`PgArtifactCustody`] serializes this across workers
//! through PostgreSQL and the shared Redis registry; [`LocalArtifactCustody`]
//! gives the same epoch semantics inside one process for memory/CLI mode.
//!
//! Reading decrypts through [`ArtifactCustody::custody`]: the catalog row names the
//! encrypted object, the wrapped key and the exact ciphertext identity. Every read
//! verifies the stored bytes against that identity, authenticates every frame and
//! verifies the plaintext identity before the final chunk is released.

use crate::artifact_crypto::{ArtifactContext, ArtifactCryptoError, ArtifactDecryption};
use crate::artifact_key_crypto::{ArtifactKeyError, ArtifactKeys};
use crate::artifacts::{ArtifactRow, DIGEST_DOMAIN};
use crate::custody::{
    encrypted_object_key, ArtifactKeyCustody, ArtifactKeyEnvelope, CiphertextIdentity, PgSecretAuthority,
    CIPHERTEXT_DIGEST_DOMAIN, PUBLISH_STALE, REGISTER_STALE, SNAPSHOT_PENDING,
};
use async_trait::async_trait;
use bytes::Bytes;
use crawlx_core::archive_catalog::ArchiveCustodyV1;
use crawlx_core::captcha::CaptchaSecrets;
use crawlx_core::custody::{
    CustodyLease, FrozenArchiveGrant, FrozenArchiveSource, RunSecretAuthority as _, RunSecretSnapshot,
    SecretEpoch, SecretRegistrar,
};
use crawlx_core::hash::Digest;
use crawlx_core::secret::SecretScanError;
use crawlx_core::{ArtifactId, CrawlRunId, SecretOr, StoreError, TenantId};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, ReadBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Longest registered value, as enforced by the shared authority.
const MAX_SECRET_BYTES: usize = 16 * 1024;
/// Most registered values per run, as enforced by the shared authority.
const MAX_VALUES: usize = 256;
/// Most registered bytes per run, as enforced by the shared authority.
const MAX_TOTAL_BYTES: usize = 1024 * 1024;
/// Rounds of "refresh snapshot, register under a new operation" after a lost epoch race.
const REGISTER_ROUNDS: usize = 8;
/// Retries of the same operation after an unknown outcome.
const UNKNOWN_RETRIES: usize = 4;
/// Polls of a snapshot that is blocked by another worker's pending registration.
const PENDING_POLLS: usize = 6;

/// When a store with attached custody encrypts what it writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CustodyWrites {
    /// Worker producers: Content/Sensitive writes for a non-terminal run need
    /// [`crawlx_core::custody::current_producer`]; absent → `StoreError::Unavailable`.
    Required,
    /// API/CLI operator inputs (evidence, login flows, archive replay saves): legacy
    /// plaintext writes. Custody is used for reads only.
    ReadOnly,
}

/// Run-wide secret registry and atomic ciphertext publication.
#[async_trait]
pub trait ArtifactCustody: Send + Sync {
    /// Current run-wide snapshot under `lease`; initializes the run authority once if absent.
    ///
    /// # Errors
    /// Rejects stale leases, unavailable authorities and registrations that stay pending.
    async fn snapshot(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError>;

    /// Register `value` run-wide before it reaches a browser or content source.
    ///
    /// Expected-epoch and exact-operation recovery are handled inside: an unknown
    /// outcome retries the same operation; a lost epoch race retries under a new one.
    ///
    /// # Errors
    /// Any error means the value must not be delivered.
    async fn register(
        &self,
        lease: &CustodyLease,
        value: &SecretOr<String>,
    ) -> Result<RunSecretSnapshot, StoreError>;

    /// Atomically publish the catalog row and wrapped key iff `expected` is still current.
    ///
    /// # Errors
    /// A stale epoch returns `StoreError::Conflict` ([`is_stale_epoch`] is true); the
    /// caller refreshes its snapshot, rescans and retries with the identical arguments.
    async fn publish(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        row: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError>;

    /// Encrypted custody of an existing artifact; `Ok(None)` means a legacy plaintext artifact.
    ///
    /// # Errors
    /// Rejects foreign scope and custody rows that are inconsistent with their catalog row.
    async fn custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<Option<ArtifactKeyCustody>, StoreError>;

    /// Withdraw a published artifact after its publication outcome was unknown and the
    /// write was then rejected. Idempotent: an unpublished or already withdrawn artifact
    /// succeeds. After success the artifact has no readable catalog row or custody.
    ///
    /// # Errors
    /// Any error means withdrawal is unconfirmed and the staged object must be kept.
    async fn withdraw(&self, tenant: TenantId, run: CrawlRunId, id: ArtifactId) -> Result<(), StoreError>;

    /// Bind the terminal run's closed secret epoch to an archive export's source proofs.
    ///
    /// Registers nothing and reads no raw secret. `custody` is narrowed by every source.
    ///
    /// # Errors
    /// Rejects non-terminal runs, non-export leases, stale fences, missing or unmatched
    /// source custody and weakened class or deadline.
    async fn issue_frozen_archive(
        &self,
        lease: &CustodyLease,
        custody: &ArchiveCustodyV1,
        sources: &[FrozenArchiveSource],
    ) -> Result<FrozenArchiveGrant, StoreError> {
        let _ = (lease, custody, sources);
        Err(StoreError::Unavailable(
            "frozen archive custody unavailable".into(),
        ))
    }

    /// Atomically publish one archive output under a [`FrozenArchiveGrant`].
    ///
    /// # Errors
    /// Rejects any producer, run, fence, epoch, class, deadline, type or source drift.
    async fn publish_frozen_archive(
        &self,
        grant: &FrozenArchiveGrant,
        lease: &CustodyLease,
        row: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        let _ = (grant, lease, row, ciphertext, envelope);
        Err(StoreError::Unavailable(
            "frozen archive custody unavailable".into(),
        ))
    }

    /// Whether [`Self::publish`] itself writes the `artifacts` catalog row. When it does
    /// not, the store records the row through its attached index after publication.
    fn publishes_catalog_row(&self) -> bool {
        true
    }
}

/// Whether `error` is a publication or registration that lost an epoch race (or hit a
/// pending registration). The refused operation changed no state and is safe to redo.
#[must_use]
pub fn is_stale_epoch(error: &StoreError) -> bool {
    matches!(error, StoreError::Conflict(detail) if detail == PUBLISH_STALE || detail == REGISTER_STALE)
}

fn is_pending(error: &StoreError) -> bool {
    matches!(error, StoreError::Conflict(detail) if detail == SNAPSHOT_PENDING)
}

/// Whether `error` leaves it unknown if the remote operation took effect.
fn is_unknown_outcome(error: &StoreError) -> bool {
    error.is_retryable()
        || matches!(error, StoreError::Conflict(detail) if detail == crate::custody::OUTCOME_UNKNOWN)
}

fn backoff(round: usize) -> tokio::time::Sleep {
    let millis = 20u64.saturating_mul(u64::try_from(round).unwrap_or(u64::MAX).saturating_add(1));
    tokio::time::sleep(Duration::from_millis(millis.min(500)))
}

/// Custody over PostgreSQL fencing and the shared volatile Redis registry.
///
/// Clones share PostgreSQL and Redis, never local secrets. Two instances (two
/// workers) observe each other's registrations through the shared authority.
#[derive(Clone)]
pub struct PgArtifactCustody {
    authority: PgSecretAuthority,
}

impl fmt::Debug for PgArtifactCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgArtifactCustody").finish_non_exhaustive()
    }
}

impl PgArtifactCustody {
    /// Custody over an opened authority. [`PgSecretAuthority::finalized_reads`] suffices
    /// for read-only consumers such as the API: snapshot, register and publish then
    /// report `Unavailable`, while [`ArtifactCustody::custody`] works.
    #[must_use]
    pub fn new(authority: PgSecretAuthority) -> Self {
        Self { authority }
    }

    async fn current(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        let mut last = None;
        for poll in 0..PENDING_POLLS {
            match self.authority.snapshot_or_initialize(lease).await {
                Err(error) if is_pending(&error) => {
                    last = Some(error);
                    backoff(poll).await;
                }
                other => return other,
            }
        }
        Err(last.unwrap_or_else(|| StoreError::Unavailable("secret authority snapshot unavailable".into())))
    }
}

#[async_trait]
impl ArtifactCustody for PgArtifactCustody {
    async fn snapshot(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        self.current(lease).await
    }

    async fn register(
        &self,
        lease: &CustodyLease,
        value: &SecretOr<String>,
    ) -> Result<RunSecretSnapshot, StoreError> {
        for round in 0..REGISTER_ROUNDS {
            let snapshot = self.current(lease).await?;
            let operation = Uuid::now_v7();
            let mut unknown = 0;
            loop {
                match self
                    .authority
                    .register(lease, snapshot.version, operation, value)
                    .await
                {
                    Ok(snapshot) => return Ok(snapshot),
                    // Refused before any state changed: refresh the epoch, new operation.
                    Err(error) if is_stale_epoch(&error) => {
                        backoff(round).await;
                        break;
                    }
                    // Recover exactly this operation; never start another while it is pending.
                    Err(error) if is_unknown_outcome(&error) => {
                        unknown += 1;
                        if unknown > UNKNOWN_RETRIES {
                            return Err(StoreError::Unavailable(
                                "secret registration outcome unknown; recover the same operation".into(),
                            ));
                        }
                        backoff(unknown).await;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Err(StoreError::Unavailable(
            "secret registration kept losing epoch races".into(),
        ))
    }

    async fn publish(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        row: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        self.authority
            .publish(lease, expected, row, ciphertext, envelope)
            .await
    }

    async fn custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<Option<ArtifactKeyCustody>, StoreError> {
        self.authority.try_read_custody(tenant, run, id).await
    }

    async fn issue_frozen_archive(
        &self,
        lease: &CustodyLease,
        custody: &ArchiveCustodyV1,
        sources: &[FrozenArchiveSource],
    ) -> Result<FrozenArchiveGrant, StoreError> {
        self.authority.issue_frozen_archive(lease, custody, sources).await
    }

    async fn publish_frozen_archive(
        &self,
        grant: &FrozenArchiveGrant,
        lease: &CustodyLease,
        row: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        self.authority
            .publish_frozen_archive(grant, lease, row, ciphertext, envelope)
            .await
    }

    async fn withdraw(&self, tenant: TenantId, run: CrawlRunId, id: ArtifactId) -> Result<(), StoreError> {
        self.authority.withdraw_published(tenant, run, id).await
    }
}

struct LocalRun {
    incarnation: Uuid,
    epoch: i64,
    values: Vec<SecretOr<String>>,
    bytes: usize,
}

#[derive(Default)]
struct LocalState {
    runs: BTreeMap<(Uuid, Uuid), LocalRun>,
    published: BTreeMap<(Uuid, Uuid, Uuid), (ArtifactKeyCustody, ArtifactRow)>,
}

/// Single-process custody for memory/CLI mode.
///
/// Keeps one registry per run with a monotonic epoch and the same epoch-checked
/// publication as [`PgArtifactCustody`] within one process. Nothing is durable:
/// [`ArtifactKeys::is_durable`] providers do not make these rows survive a restart.
/// The lock guards plain data and is never held across an await point.
#[derive(Default)]
pub struct LocalArtifactCustody {
    state: Mutex<LocalState>,
}

impl fmt::Debug for LocalArtifactCustody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalArtifactCustody").finish_non_exhaustive()
    }
}

impl LocalArtifactCustody {
    /// Empty in-process custody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn snapshot_of(lease: &CustodyLease, run: &LocalRun) -> Result<RunSecretSnapshot, StoreError> {
        let secrets = CaptchaSecrets::default();
        for value in &run.values {
            secrets
                .register(value.clone())
                .map_err(|_| StoreError::Unavailable("local secret registry unavailable".into()))?;
        }
        Ok(RunSecretSnapshot::new(
            SecretEpoch::new(lease.tenant, lease.run, run.incarnation, run.epoch),
            secrets,
        ))
    }

    fn check(lease: &CustodyLease) -> Result<(), StoreError> {
        lease.check_local_cancellation()?;
        if lease.fence <= 0 {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }
}

#[async_trait]
impl ArtifactCustody for LocalArtifactCustody {
    async fn snapshot(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        Self::check(lease)?;
        let mut state = self.state.lock();
        let run = state
            .runs
            .entry((lease.tenant.0, lease.run.0))
            .or_insert_with(|| LocalRun {
                incarnation: Uuid::now_v7(),
                epoch: 1,
                values: Vec::new(),
                bytes: 0,
            });
        Self::snapshot_of(lease, run)
    }

    async fn register(
        &self,
        lease: &CustodyLease,
        value: &SecretOr<String>,
    ) -> Result<RunSecretSnapshot, StoreError> {
        Self::check(lease)?;
        let text = value.expose();
        if text.is_empty() || text.len() > MAX_SECRET_BYTES {
            return Err(StoreError::Conflict(
                "secret registration operation or value out of bounds".into(),
            ));
        }
        let mut state = self.state.lock();
        let run = state
            .runs
            .entry((lease.tenant.0, lease.run.0))
            .or_insert_with(|| LocalRun {
                incarnation: Uuid::now_v7(),
                epoch: 1,
                values: Vec::new(),
                bytes: 0,
            });
        if !run.values.iter().any(|known| known.expose() == text) {
            let bytes = run.bytes.saturating_add(text.len());
            if run.values.len() >= MAX_VALUES || bytes > MAX_TOTAL_BYTES {
                return Err(StoreError::Conflict(
                    "secret authority secret bound exceeded".into(),
                ));
            }
            run.values.push(SecretOr::secret(text.to_owned()));
            run.bytes = bytes;
        }
        run.epoch = run
            .epoch
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("secret authority epoch out of bounds".into()))?;
        Self::snapshot_of(lease, run)
    }

    async fn publish(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        row: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        Self::check(lease)?;
        if row.tenant != lease.tenant || row.run != lease.run {
            return Err(StoreError::Conflict("artifact publication scope mismatch".into()));
        }
        let identity = CiphertextIdentity::new(ciphertext.digest, ciphertext.size_bytes)?;
        if row.object_key != encrypted_object_key(row.tenant, row.run, row.id, identity.digest) {
            return Err(StoreError::Conflict(
                "artifact ciphertext key must bind unique artifact identity".into(),
            ));
        }
        let mut state = self.state.lock();
        let run = state
            .runs
            .get(&(lease.tenant.0, lease.run.0))
            .ok_or_else(|| StoreError::Conflict("secret authority missing or expired".into()))?;
        if expected.tenant != lease.tenant
            || expected.run != lease.run
            || expected.incarnation != run.incarnation
            || expected.epoch != run.epoch
        {
            return Err(StoreError::Conflict(PUBLISH_STALE.into()));
        }
        let key = (lease.tenant.0, lease.run.0, row.id.0);
        let custody = ArtifactKeyCustody {
            envelope: envelope.clone(),
            ciphertext: identity,
        };
        if let Some((existing, existing_row)) = state.published.get(&key) {
            if existing != &custody || existing_row != row {
                return Err(StoreError::Conflict(
                    "artifact publication retry changed immutable custody".into(),
                ));
            }
            return Ok(());
        }
        state.published.insert(key, (custody, row.clone()));
        Ok(())
    }

    async fn custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<Option<ArtifactKeyCustody>, StoreError> {
        if crate::tenant::current().is_some_and(|current| current != tenant) {
            return Err(StoreError::AccessDenied(
                "artifact custody tenant mismatch".into(),
            ));
        }
        Ok(self
            .state
            .lock()
            .published
            .get(&(tenant.0, run.0, id.0))
            .map(|(custody, _)| custody.clone()))
    }

    async fn withdraw(&self, tenant: TenantId, run: CrawlRunId, id: ArtifactId) -> Result<(), StoreError> {
        self.state.lock().published.remove(&(tenant.0, run.0, id.0));
        Ok(())
    }

    async fn issue_frozen_archive(
        &self,
        lease: &CustodyLease,
        custody: &ArchiveCustodyV1,
        sources: &[FrozenArchiveSource],
    ) -> Result<FrozenArchiveGrant, StoreError> {
        Self::check(lease)?;
        let (incarnation, epoch) = {
            let state = self.state.lock();
            let run = state
                .runs
                .get(&(lease.tenant.0, lease.run.0))
                .ok_or_else(|| StoreError::Conflict("secret authority missing or expired".into()))?;
            (run.incarnation, run.epoch)
        };
        let mut narrowed = *custody;
        for source in sources {
            if source.custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive {
                narrowed.sensitivity = crawlx_core::repo::Sensitivity::Sensitive;
            }
            narrowed.expires_at = match (narrowed.expires_at, source.custody.expires_at) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            };
        }
        FrozenArchiveGrant::new(
            lease,
            SecretEpoch::new(lease.tenant, lease.run, incarnation, epoch),
            narrowed,
            sources.to_vec(),
        )
    }

    async fn publish_frozen_archive(
        &self,
        grant: &FrozenArchiveGrant,
        lease: &CustodyLease,
        row: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        Self::check(lease)?;
        grant.check_lease(lease)?;
        if row.tenant != lease.tenant || row.run != lease.run {
            return Err(StoreError::Conflict("artifact publication scope mismatch".into()));
        }
        grant.check_output(row.sensitivity, row.expires_at, &row.kind, &row.content_type)?;
        let identity = CiphertextIdentity::new(ciphertext.digest, ciphertext.size_bytes)?;
        if row.object_key != encrypted_object_key(row.tenant, row.run, row.id, identity.digest) {
            return Err(StoreError::Conflict(
                "artifact ciphertext key must bind unique artifact identity".into(),
            ));
        }
        let mut state = self.state.lock();
        let run = state
            .runs
            .get(&(lease.tenant.0, lease.run.0))
            .ok_or_else(|| StoreError::Conflict("secret authority missing or expired".into()))?;
        if grant.epoch.incarnation != run.incarnation || grant.epoch.epoch != run.epoch {
            return Err(StoreError::Conflict(PUBLISH_STALE.into()));
        }
        let key = (lease.tenant.0, lease.run.0, row.id.0);
        let custody = ArtifactKeyCustody {
            envelope: envelope.clone(),
            ciphertext: identity,
        };
        if let Some((existing, existing_row)) = state.published.get(&key) {
            if existing != &custody || existing_row != row {
                return Err(StoreError::Conflict(
                    "artifact publication retry changed immutable custody".into(),
                ));
            }
            return Ok(());
        }
        state.published.insert(key, (custody, row.clone()));
        Ok(())
    }

    fn publishes_catalog_row(&self) -> bool {
        false
    }
}

/// Worker binding of a custody registrar to one session lease.
///
/// Registers each value run-wide through the shared authority and mirrors it into the
/// worker's local [`CaptchaSecrets`] so local scans and redaction see it immediately.
#[derive(Clone)]
pub struct LeasedSecretRegistrar {
    custody: Arc<dyn ArtifactCustody>,
    lease: CustodyLease,
    local: CaptchaSecrets,
}

impl fmt::Debug for LeasedSecretRegistrar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeasedSecretRegistrar")
            .field("tenant", &self.lease.tenant)
            .field("run", &self.lease.run)
            .finish_non_exhaustive()
    }
}

impl LeasedSecretRegistrar {
    /// Bind `custody` to the producer `lease`; `local` is the worker's own registry mirror.
    #[must_use]
    pub fn new(custody: Arc<dyn ArtifactCustody>, lease: CustodyLease, local: CaptchaSecrets) -> Self {
        Self {
            custody,
            lease,
            local,
        }
    }
}

#[async_trait]
impl SecretRegistrar for LeasedSecretRegistrar {
    async fn register(&self, value: &SecretOr<String>) -> Result<(), StoreError> {
        // Local first: a value whose run-wide outcome is unknown must still be scanned for here.
        self.local
            .register(value.clone())
            .map_err(|_| StoreError::Unavailable("local secret registry unavailable".into()))?;
        self.custody.register(&self.lease, value).await.map(|_| ())
    }
}

/// Map a key-provider failure; remote details never reach the message.
pub(crate) fn key_error(error: ArtifactKeyError) -> StoreError {
    match error {
        ArtifactKeyError::Unavailable => StoreError::Unavailable("artifact key custody unavailable".into()),
        ArtifactKeyError::Kms(_) | ArtifactKeyError::Task(_) => {
            StoreError::Unavailable("artifact key custody operation failed".into())
        }
        ArtifactKeyError::Crypto(error) => crypto_error(error),
        _ => StoreError::Backend("artifact key custody rejected the envelope".into()),
    }
}

/// Map an encryption/decryption failure. Authentication failures are never retryable.
pub(crate) fn crypto_error(error: ArtifactCryptoError) -> StoreError {
    match error {
        ArtifactCryptoError::Io(_) => StoreError::Unavailable("artifact encryption io failed".into()),
        ArtifactCryptoError::LimitExceeded => {
            StoreError::RetentionDenied("artifact exceeds approved size".into())
        }
        ArtifactCryptoError::Authentication
        | ArtifactCryptoError::InvalidEnvelope
        | ArtifactCryptoError::LengthMismatch
        | ArtifactCryptoError::Aborted => {
            StoreError::Conflict("encrypted artifact failed verification".into())
        }
        _ => StoreError::Conflict("encrypted artifact operation failed".into()),
    }
}

/// Map a scoped secret inspection failure; any non-success refuses publication.
pub(crate) fn scan_error(error: SecretScanError) -> StoreError {
    match error {
        SecretScanError::Secret => {
            StoreError::RetentionDenied("artifact contains a registered secret".into())
        }
        _ => StoreError::RetentionDenied("artifact secret inspection refused".into()),
    }
}

/// A fresh blake3 state positioned exactly as [`Digest::of`] frames its domain.
pub(crate) fn domain_hasher(domain: &str) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0]);
    hasher
}

#[derive(Default)]
struct Audit {
    hasher: Option<blake3::Hasher>,
    count: u64,
}

/// Reader that fingerprints the stored ciphertext while it is decrypted.
struct AuditedReader {
    inner: Box<dyn AsyncRead + Send + Unpin>,
    audit: Arc<Mutex<Audit>>,
}

impl AsyncRead for AuditedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let fresh = &buf.filled()[before..];
            let mut audit = self.audit.lock();
            if let Some(hasher) = audit.hasher.as_mut() {
                hasher.update(fresh);
            }
            audit.count = audit.count.saturating_add(fresh.len() as u64);
        }
        poll
    }
}

/// Decrypt and verify one sealed artifact as a stream of plaintext chunks.
///
/// The stored bytes must match `custody.ciphertext` and the plaintext must match the
/// catalog `row`. The final chunk is held back until both fingerprints verified, and
/// every frame is authenticated before release. Earlier chunks stay provisional until
/// the stream ends `Ok`: consumers must discard everything on an error.
///
/// # Errors
/// Refuses unavailable keys, malformed or tampered ciphertext, size above `max_bytes`
/// or the catalog size, and any fingerprint mismatch.
pub(crate) async fn sealed_stream(
    keys: &dyn ArtifactKeys,
    reader: Box<dyn AsyncRead + Send + Unpin>,
    row: &ArtifactRow,
    custody: &ArtifactKeyCustody,
    max_bytes: u64,
) -> Result<futures::stream::BoxStream<'static, Result<Bytes, StoreError>>, StoreError> {
    let context = ArtifactContext::new(row.tenant, row.run, row.id);
    let key = keys.open(&context, &custody.envelope).await.map_err(key_error)?;
    let audit = Arc::new(Mutex::new(Audit {
        hasher: Some(domain_hasher(CIPHERTEXT_DIGEST_DOMAIN)),
        count: 0,
    }));
    let limit = row.size_bytes.min(max_bytes);
    let mut decryption = ArtifactDecryption::new(
        AuditedReader {
            inner: reader,
            audit: Arc::clone(&audit),
        },
        context,
        key,
        limit,
    )
    .await
    .map_err(crypto_error)?;
    let id = row.id;
    let size = row.size_bytes;
    let digest = row.digest;
    let ciphertext = custody.ciphertext;
    Ok(Box::pin(async_stream::try_stream! {
        let mut plain = domain_hasher(DIGEST_DOMAIN);
        let mut count = 0u64;
        let mut held: Option<Bytes> = None;
        while let Some(chunk) = decryption.next_chunk().await.map_err(crypto_error)? {
            count = count
                .checked_add(chunk.len() as u64)
                .filter(|count| *count <= limit)
                .ok_or_else(|| StoreError::RetentionDenied("sealed content exceeded approved size".into()))?;
            plain.update(&chunk);
            let next = Bytes::copy_from_slice(&chunk);
            drop(chunk);
            if let Some(previous) = held.replace(next) {
                yield previous;
            }
        }
        let stored = {
            let mut audit = audit.lock();
            let hasher = audit.hasher.take();
            (audit.count, hasher.map(|hasher| Digest(*hasher.finalize().as_bytes())))
        };
        if stored.0 != ciphertext.size_bytes || stored.1 != Some(ciphertext.digest) {
            Err(StoreError::Conflict(format!("sealed artifact {id} failed ciphertext verification")))?;
        }
        if count != size || Digest(*plain.finalize().as_bytes()) != digest {
            Err(StoreError::Conflict(format!("sealed artifact {id} failed plaintext verification")))?;
        }
        if let Some(last) = held {
            yield last;
        }
    }))
}

/// Collect a verified sealed stream, refusing to allocate beyond the catalog size.
pub(crate) async fn collect_sealed(
    stream: futures::stream::BoxStream<'static, Result<Bytes, StoreError>>,
    size: u64,
) -> Result<Vec<u8>, StoreError> {
    use futures::TryStreamExt as _;
    let wanted = usize::try_from(size).map_err(|_| StoreError::ResourceExhausted {
        resource: "artifact content",
        requested: usize::MAX,
        available: 0,
        source: None,
    })?;
    let mut out = Vec::new();
    out.try_reserve_exact(wanted)
        .map_err(|source| StoreError::ResourceExhausted {
            resource: "artifact content",
            requested: wanted,
            available: out.capacity(),
            source: Some(source),
        })?;
    let mut stream = stream;
    while let Some(chunk) = stream.try_next().await? {
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Verify a fully buffered sealed object (bounded filesystem reads and admin audits).
///
/// # Errors
/// Same as [`sealed_stream`]; callers bound `stored` with [`ciphertext_bound`] before reading it.
pub(crate) async fn open_sealed_bytes(
    keys: &dyn ArtifactKeys,
    stored: Vec<u8>,
    row: &ArtifactRow,
    custody: &ArtifactKeyCustody,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let reader: Box<dyn AsyncRead + Send + Unpin> = Box::new(std::io::Cursor::new(stored));
    let stream = sealed_stream(keys, reader, row, custody, row.size_bytes).await?;
    collect_sealed(stream, row.size_bytes).await.map(Zeroizing::new)
}

/// Upper bound of the ciphertext length for `plaintext` bytes, including framing.
pub(crate) fn ciphertext_bound(plaintext: u64) -> Result<u64, StoreError> {
    crate::artifact_crypto::checked_lengths(plaintext, plaintext).map_err(crypto_error)
}
