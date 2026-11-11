//! Run-wide secret snapshots for encrypted artifact publication.
//!
//! Implementations must share volatile secret material across workers. A local
//! `CaptchaSecrets` value is only a snapshot, never publication authority.

use crate::archive_catalog::ArchiveCustodyV1;
use crate::captcha::CaptchaSecrets;
use crate::hash::Digest;
use crate::{ArtifactId, CrawlRunId, SecretOr, SessionId, StoreError, TenantId, WorkerId};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::future::Future;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Existing producer ownership required for every custody mutation and publication.
///
/// Bootstrap leases also retain the admitted context's actual cancellation token.
/// This local veto supplements, never replaces, PostgreSQL ownership checks.
/// Cancellation cannot retract an already-enqueued remote command or COMMIT.
/// Such outcomes remain unknown; pending barriers must not be cleared as success.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CustodyLease {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Owning run.
    pub run: CrawlRunId,
    /// Existing session, URL, or authenticated API producer lease.
    pub source: CustodySource,
    /// Worker or unique API producer owner.
    pub worker: WorkerId,
    /// Existing monotonically increasing fencing token.
    pub fence: i64,
    local_cancellation: Option<CancellationToken>,
}

impl CustodyLease {
    /// Bind custody to an existing session fence, not a separate expiring lock.
    #[must_use]
    pub const fn new(
        tenant: TenantId,
        run: CrawlRunId,
        session: SessionId,
        worker: WorkerId,
        fence: i64,
    ) -> Self {
        Self {
            tenant,
            run,
            source: CustodySource::Session(session),
            worker,
            fence,
            local_cancellation: None,
        }
    }

    /// Retain the producer's actual hard-stop token across storage lock waits.
    /// Graceful worker drain must use a separate token, so acquired effects can publish.
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.local_cancellation = Some(cancellation);
        self
    }

    /// Bind a static/URL producer to its real existing frontier lease.
    #[must_use]
    pub const fn for_url(
        tenant: TenantId,
        run: CrawlRunId,
        frontier_id: i64,
        worker: WorkerId,
        fence: i64,
    ) -> Self {
        Self {
            tenant,
            run,
            source: CustodySource::Url(frontier_id),
            worker,
            fence,
            local_cancellation: None,
        }
    }

    /// Describe a separately authenticated, persisted producer lease. Storage
    /// validates the exact owner, fence, live API key and run on every mutation.
    #[must_use]
    pub const fn for_authenticated_producer(
        tenant: TenantId,
        run: CrawlRunId,
        producer: Uuid,
        worker: WorkerId,
        fence: i64,
    ) -> Self {
        Self {
            tenant,
            run,
            source: CustodySource::AuthenticatedProducer(producer),
            worker,
            fence,
            local_cancellation: None,
        }
    }

    /// Bind archive packaging to its claimed export row (`archive_exports.fence`).
    ///
    /// Storage validates on every mutation that the export is still `recording` for this
    /// run at exactly `fence` with an unexpired lease. `worker` is informational: the
    /// archive catalog fences by export and fence, not by worker.
    #[must_use]
    pub const fn for_archive_export(
        tenant: TenantId,
        run: CrawlRunId,
        export: Uuid,
        worker: WorkerId,
        fence: i64,
    ) -> Self {
        Self {
            tenant,
            run,
            source: CustodySource::ArchiveExport(export),
            worker,
            fence,
            local_cancellation: None,
        }
    }

    /// Bind credential-bearing bootstrap I/O to its dedicated persisted run lease.
    ///
    /// `cancellation` must be cloned from the actual admitted worker context,
    /// not a fresh token. Constructing this descriptor does not establish ownership.
    #[must_use]
    pub fn for_bootstrap(
        tenant: TenantId,
        run: CrawlRunId,
        producer: Uuid,
        worker: WorkerId,
        fence: i64,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            tenant,
            run,
            source: CustodySource::Bootstrap(producer),
            worker,
            fence,
            local_cancellation: Some(cancellation),
        }
    }

    /// Reject a locally cancelled bootstrap capability or a missing token binding.
    ///
    /// Storage must also validate the shared database fence. Check again after
    /// lock waits and before side effects; this is not atomic remote revocation.
    ///
    /// # Errors
    /// Returns [`StoreError::LeaseLost`] after cancellation or without a required binding.
    pub fn check_local_cancellation(&self) -> Result<(), StoreError> {
        if self
            .local_cancellation
            .as_ref()
            .is_some_and(CancellationToken::is_cancelled)
            || (matches!(self.source, CustodySource::Bootstrap(_)) && self.local_cancellation.is_none())
        {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }

    /// Wait for the captured local cancellation, without granting shared ownership.
    ///
    /// Non-bootstrap leases without a token never resolve this wait. Dropping a
    /// raced remote operation does not prove that the server did not execute it.
    pub async fn cancelled(&self) {
        if let Some(cancellation) = &self.local_cancellation {
            cancellation.cancelled().await;
        } else {
            std::future::pending::<()>().await;
        }
    }
}

/// Database row that already fences a custody producer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CustodySource {
    /// Browser session lease.
    Session(SessionId),
    /// Static or URL acquisition lease.
    Url(i64),
    /// Short-lived lease minted through a trusted API authorization boundary.
    AuthenticatedProducer(Uuid),
    /// Claimed archive export that is still recording at its current fence.
    ArchiveExport(Uuid),
    /// Dedicated run-bootstrap ownership, independent of sessions/frontier rows.
    Bootstrap(Uuid),
}

/// Exact volatile incarnation and committed secret epoch of a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SecretEpoch {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Owning run.
    pub run: CrawlRunId,
    /// Random incarnation; lost volatile state must never be recreated under it.
    pub incarnation: Uuid,
    /// Monotonically increasing committed registry epoch.
    pub epoch: i64,
}

impl SecretEpoch {
    /// Describe an authority response. This token alone does not prove bytes were scanned.
    #[must_use]
    pub const fn new(tenant: TenantId, run: CrawlRunId, incarnation: Uuid, epoch: i64) -> Self {
        Self {
            tenant,
            run,
            incarnation,
            epoch,
        }
    }
}

/// Bounded in-memory projection of a shared registry at one committed epoch.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct RunSecretSnapshot {
    /// Publication must atomically recheck this exact epoch.
    pub version: SecretEpoch,
    /// Local redaction view; never use this as an independent authority.
    pub secrets: CaptchaSecrets,
}

impl RunSecretSnapshot {
    /// Construct a snapshot from a shared authority response.
    #[must_use]
    pub fn new(version: SecretEpoch, secrets: CaptchaSecrets) -> Self {
        Self { version, secrets }
    }
}

/// Content types a frozen archive grant may seal: archive shards, packages and adjacent indexes.
pub const FROZEN_ARCHIVE_CONTENT_TYPES: [&str; 3] =
    ["application/warc", "application/wacz+zip", "application/cdxj"];
/// Most retained sources one grant can name.
pub const MAX_FROZEN_ARCHIVE_SOURCES: usize = 20_000;

/// One already-sealed retained source whose approved authority a frozen archive output inherits.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrozenArchiveSource {
    /// Exact source artifact and its plaintext fixity digest.
    pub artifact: crate::ArtifactRef,
    /// Class and earliest deadline approved for this source ([`ArchiveCustodyV1`]).
    pub custody: ArchiveCustodyV1,
}

impl FrozenArchiveSource {
    /// Describe one source proof; storage verifies it against the catalog on issuance.
    #[must_use]
    pub const fn new(artifact: crate::ArtifactRef, custody: ArchiveCustodyV1) -> Self {
        Self { artifact, custody }
    }
}

/// Authority to seal the output of one archive export for a terminal run whose secret
/// registration is permanently closed.
///
/// This is not a [`CustodyLease`] and not a [`RunSecretSnapshot`]: it carries no secret
/// material, registers nothing and authorizes no other producer or run. It binds the exact
/// claimed export fence, the run's closed secret epoch and incarnation, the aggregate
/// retained class and deadline, and the exact source artifacts. Constructing a value grants
/// nothing: storage persists the binding at issuance, revalidates it with the live export
/// fence on every publication, and the durable row keeps working after the raw registry expires.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FrozenArchiveGrant {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Terminal source run.
    pub run: CrawlRunId,
    /// Claimed archive export.
    pub export: Uuid,
    /// Exact claimed export fence.
    pub fence: i64,
    /// Closed secret epoch and incarnation the output is sealed under.
    pub epoch: SecretEpoch,
    /// Aggregate class and deadline of the output; never weaker than any source.
    pub custody: ArchiveCustodyV1,
    sources: Vec<FrozenArchiveSource>,
    binding: Digest,
}

fn grant_custody_covers(grant: &ArchiveCustodyV1, source: &ArchiveCustodyV1) -> bool {
    use crate::repo::Sensitivity;
    (source.sensitivity != Sensitivity::Sensitive || grant.sensitivity == Sensitivity::Sensitive)
        && match (grant.expires_at, source.expires_at) {
            (_, None) => true,
            (Some(grant), Some(source)) => grant <= source,
            (None, Some(_)) => false,
        }
}

fn push_expiry(bytes: &mut Vec<u8>, expires_at: Option<crate::Timestamp>) {
    match expires_at {
        Some(at) => {
            bytes.push(1);
            bytes.extend_from_slice(&at.timestamp_micros().to_be_bytes());
        }
        None => bytes.push(0),
    }
}

fn push_class(bytes: &mut Vec<u8>, custody: &ArchiveCustodyV1) {
    bytes.push(match custody.sensitivity {
        crate::repo::Sensitivity::Sensitive => 2,
        _ => 1,
    });
    push_expiry(bytes, custody.expires_at);
}

impl FrozenArchiveGrant {
    /// Bind source proofs to an archive-export lease and a closed secret epoch.
    ///
    /// Sources are sorted and deduplicated by artifact. The grant custody must be at least
    /// as restrictive as every source: Sensitive stays Sensitive and the deadline never
    /// extends a source deadline.
    ///
    /// # Errors
    /// Rejects non-export leases, scope or epoch mismatches, empty or oversized source
    /// lists, conflicting duplicate sources and grant custody weaker than a source.
    pub fn new(
        lease: &CustodyLease,
        epoch: SecretEpoch,
        custody: ArchiveCustodyV1,
        mut sources: Vec<FrozenArchiveSource>,
    ) -> Result<Self, StoreError> {
        use crate::repo::Sensitivity;
        let CustodySource::ArchiveExport(export) = lease.source else {
            return Err(StoreError::AccessDenied(
                "frozen archive grant requires an archive export producer".into(),
            ));
        };
        let conflict = |detail: &str| StoreError::Conflict(detail.into());
        if lease.fence <= 0
            || epoch.tenant != lease.tenant
            || epoch.run != lease.run
            || epoch.epoch < 1
            || epoch.incarnation.is_nil()
        {
            return Err(conflict("frozen archive grant scope or epoch mismatch"));
        }
        if sources.is_empty() || sources.len() > MAX_FROZEN_ARCHIVE_SOURCES {
            return Err(conflict("frozen archive grant source count out of bounds"));
        }
        if !matches!(custody.sensitivity, Sensitivity::Content | Sensitivity::Sensitive)
            || (custody.sensitivity == Sensitivity::Sensitive && custody.expires_at.is_none())
        {
            return Err(StoreError::RetentionDenied(
                "frozen archive custody is invalid".into(),
            ));
        }
        sources.sort_by_key(|source| source.artifact.id.0);
        sources.dedup_by(|next, kept| next == kept);
        if sources
            .windows(2)
            .any(|pair| pair[0].artifact.id == pair[1].artifact.id)
        {
            return Err(conflict(
                "frozen archive grant names one source twice with different proofs",
            ));
        }
        for source in &sources {
            if !matches!(
                source.custody.sensitivity,
                Sensitivity::Content | Sensitivity::Sensitive
            ) || (source.custody.sensitivity == Sensitivity::Sensitive
                && source.custody.expires_at.is_none())
                || !grant_custody_covers(&custody, &source.custody)
            {
                return Err(StoreError::RetentionDenied(
                    "frozen archive custody is weaker than a source".into(),
                ));
            }
        }
        let mut bytes = Vec::with_capacity(128 + sources.len() * 64);
        bytes.extend_from_slice(lease.tenant.0.as_bytes());
        bytes.extend_from_slice(lease.run.0.as_bytes());
        bytes.extend_from_slice(export.as_bytes());
        bytes.extend_from_slice(&lease.fence.to_be_bytes());
        bytes.extend_from_slice(epoch.incarnation.as_bytes());
        bytes.extend_from_slice(&epoch.epoch.to_be_bytes());
        push_class(&mut bytes, &custody);
        bytes.extend_from_slice(&u64::try_from(sources.len()).unwrap_or(u64::MAX).to_be_bytes());
        for source in &sources {
            bytes.extend_from_slice(source.artifact.id.0.as_bytes());
            bytes.extend_from_slice(&source.artifact.digest.0);
            push_class(&mut bytes, &source.custody);
        }
        Ok(Self {
            tenant: lease.tenant,
            run: lease.run,
            export,
            fence: lease.fence,
            epoch,
            custody,
            sources,
            binding: Digest::of("crawlx/frozen-archive-grant/v1", &bytes),
        })
    }

    /// Sorted, deduplicated source proofs.
    #[must_use]
    pub fn sources(&self) -> &[FrozenArchiveSource] {
        &self.sources
    }

    /// Domain-separated digest of every bound field, the durable identity of this grant.
    #[must_use]
    pub const fn binding(&self) -> Digest {
        self.binding
    }

    /// Whether `lease` is exactly the export producer this grant was issued to.
    ///
    /// # Errors
    /// Returns [`StoreError::AccessDenied`] for any other producer, run or fence.
    pub fn check_lease(&self, lease: &CustodyLease) -> Result<(), StoreError> {
        if lease.tenant != self.tenant
            || lease.run != self.run
            || lease.fence != self.fence
            || lease.source != CustodySource::ArchiveExport(self.export)
        {
            return Err(StoreError::AccessDenied(
                "frozen archive grant belongs to another export".into(),
            ));
        }
        Ok(())
    }

    /// Validate one output's exact class, deadline, kind and media type against the grant.
    ///
    /// # Errors
    /// Returns a retention refusal when the output is not Sensitive/Content exactly like the
    /// grant, outlives it, is not archive evidence, or has a type outside
    /// [`FROZEN_ARCHIVE_CONTENT_TYPES`].
    pub fn check_output(
        &self,
        class: crate::repo::Sensitivity,
        expires_at: Option<crate::Timestamp>,
        kind: &str,
        content_type: &str,
    ) -> Result<(), StoreError> {
        let bounded = match (self.custody.expires_at, expires_at) {
            (None, _) => true,
            (Some(grant), Some(output)) => output <= grant,
            (Some(_), None) => false,
        };
        if class != self.custody.sensitivity
            || !bounded
            || kind != "evidence"
            || !FROZEN_ARCHIVE_CONTENT_TYPES.contains(&content_type)
        {
            return Err(StoreError::RetentionDenied(
                "frozen archive output exceeds its grant".into(),
            ));
        }
        Ok(())
    }
}

tokio::task_local! {
    static FROZEN_ARCHIVE: FrozenArchiveGrant;
}

/// Run `fut` with `grant` as the only authority to seal terminal archive output.
///
/// Not inherited by [`inherit`] or `tokio::spawn`; the sealed store still demands the
/// matching export [`CustodyLease`] from [`with_producer`].
pub async fn with_frozen_archive<F: Future>(grant: FrozenArchiveGrant, fut: F) -> F::Output {
    FROZEN_ARCHIVE.scope(grant, fut).await
}

/// The frozen archive grant of the current task, if any.
#[must_use]
pub fn current_frozen_archive() -> Option<FrozenArchiveGrant> {
    FROZEN_ARCHIVE.try_with(Clone::clone).ok()
}

/// Secret-validation state for one existing retained artifact.
///
/// This does not grant caller access. Authentication, sensitivity authorization,
/// ciphertext fixity, complete AEAD validation and output bounds remain mandatory.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ArtifactReadState {
    /// Current snapshot for internal validation only. This is not live disclosure
    /// authority: a transport-owned lifecycle boundary is still required.
    Live(RunSecretSnapshot),
    /// The terminal run permanently closed secret registration, and this exact
    /// immutable ciphertext was validated at its final complete secret epoch.
    /// Only this durable state permits reads after volatile authority expiry.
    Finalized(SecretEpoch),
}

/// Distributed volatile registry serialized against durable catalog publication.
///
/// Unknown write outcomes must block publication until the same operation recovers.
/// Implementations must not fall back to process memory or recreate lost snapshots.
#[async_trait]
pub trait RunSecretAuthority: Send + Sync {
    /// Initialize once under a real existing producer fence. A lost committed
    /// volatile incarnation must never be recreated as an empty success.
    ///
    /// # Errors
    /// Rejects stale producers, unavailable backends, pending recovery and expiry.
    async fn initialize(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError>;

    /// Read the complete committed run-wide registry under an existing live fence.
    ///
    /// # Errors
    /// Rejects lost volatile state, pending writes, expired authority and stale leases.
    async fn snapshot(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError>;

    /// Renew the durable use window without extending volatile retention.
    ///
    /// Reuse the exact operation, epoch and deadline after unknown outcomes.
    /// Every access must check durable authority. Original retention ceilings
    /// never move, and expired use windows cannot be resurrected. Applied
    /// historical receipts may recover without replaying a TTL mutation.
    ///
    /// # Errors
    /// Rejects stale fences, changed retries, expired or missing state, deadlines
    /// beyond original policy ceilings and unavailable authorization.
    async fn renew_authority(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        operation: Uuid,
        deadline: crate::Timestamp,
    ) -> Result<RunSecretSnapshot, StoreError>;

    /// Obtain the original retained-source privacy projector while its registry survives.
    ///
    /// The caller must authenticate and authorize the original retained source.
    /// This read-only projection grants no publication, browser or renewal authority.
    /// Terminal runs may project their permanently closed epoch until the frozen
    /// volatile ceiling. Lost raw values are never reconstructed from commitments.
    ///
    /// # Errors
    /// Rejects ZDR, foreign epochs, pending operations, expired retention, missing
    /// volatile values and expired use windows on active runs.
    async fn retained_snapshot(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        expected: SecretEpoch,
    ) -> Result<RunSecretSnapshot, StoreError>;

    /// Resolve current secret-validation state for one existing artifact.
    ///
    /// # Errors
    /// Rejects wrong tenant/run/artifact, missing custody and unavailable live state.
    /// This inspection value does not authorize external disclosure. Complete
    /// transport/producer lifetime fencing remains an explicit integration blocker.
    async fn read_state(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: ArtifactId,
    ) -> Result<ArtifactReadState, StoreError>;

    /// Register before delivering a secret to any browser callback or content source.
    /// Reuse `operation` and `expected` when recovering an unknown result.
    ///
    /// # Errors
    /// Rejects stale epochs/fences, changed retries, bounds and backend uncertainty.
    /// An error never authorizes callback delivery or artifact publication.
    async fn register(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        operation: Uuid,
        value: &SecretOr<String>,
    ) -> Result<RunSecretSnapshot, StoreError>;
}

/// One bounded durable use window under an immutable volatile-retention ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct CustodyRenewalWindow {
    /// Complete committed registry epoch observed with this window.
    pub version: SecretEpoch,
    /// Current durable use deadline; expiry cannot be recovered by a new renewal.
    pub expires_at: crate::Timestamp,
    /// Original retention permission; Redis expiry never moves beyond this.
    pub retention_ceiling: crate::Timestamp,
    /// Maximum extension window measured from the next renewal's durable clock.
    pub use_window: std::time::Duration,
    /// Durable clock sample taken while the authority and producer were locked.
    pub observed_at: crate::Timestamp,
}

impl CustodyRenewalWindow {
    /// Describe a durable window; construction itself grants no authority.
    pub const fn new(
        version: SecretEpoch,
        expires_at: crate::Timestamp,
        retention_ceiling: crate::Timestamp,
        use_window: std::time::Duration,
        observed_at: crate::Timestamp,
    ) -> Self {
        Self {
            version,
            expires_at,
            retention_ceiling,
            use_window,
            observed_at,
        }
    }
}

tokio::task_local! {
    static PRODUCER: CustodyLease;
}

/// Run `fut` with `lease` as the current artifact producer.
///
/// Task-locals do not cross `tokio::spawn`: wrap every spawned write path with
/// [`inherit`] before spawning.
pub async fn with_producer<F: Future>(lease: CustodyLease, fut: F) -> F::Output {
    PRODUCER.scope(lease, fut).await
}

/// The producer lease of the current task, if any.
#[must_use]
pub fn current_producer() -> Option<CustodyLease> {
    PRODUCER.try_with(Clone::clone).ok()
}

/// Capture the caller's producer (if any) for a future that will be spawned.
///
/// The lease is read when this function is called, not when the future first polls,
/// so the result may safely move to another task.
pub fn inherit<F: Future>(fut: F) -> impl Future<Output = F::Output> {
    let lease = current_producer();
    async move {
        match lease {
            Some(lease) => with_producer(lease, fut).await,
            None => fut.await,
        }
    }
}

/// Run-wide registration of a secret before it reaches a browser or content source.
///
/// Implementations must make the value visible to every worker's publication check.
/// Implementors must not print the registered value in their `Debug` output.
#[async_trait]
pub trait SecretRegistrar: Send + Sync + std::fmt::Debug {
    /// Register `value` run-wide. Errors never authorize delivery.
    ///
    /// # Errors
    /// Rejects stale producers, unavailable authorities, bounds and unknown outcomes.
    async fn register(&self, value: &SecretOr<String>) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn lease(fence: i64) -> CustodyLease {
        CustodyLease::new(
            TenantId::new(),
            CrawlRunId::new(),
            SessionId::new(),
            WorkerId::new(),
            fence,
        )
    }

    #[tokio::test]
    async fn producer_is_scoped_inherited_explicitly_and_never_leaks() {
        assert!(current_producer().is_none());
        let outer = lease(7);
        let seen = with_producer(outer.clone(), async {
            assert_eq!(current_producer().unwrap().fence, 7);
            // A plain spawn does not carry the task-local.
            let bare = tokio::spawn(async { current_producer().is_none() })
                .await
                .unwrap();
            // `inherit` captures it at call time for the spawned future.
            let inherited = tokio::spawn(inherit(async { current_producer().map(|lease| lease.fence) }))
                .await
                .unwrap();
            // A nested scope shadows and restores.
            let inner = with_producer(lease(9), async { current_producer().unwrap().fence }).await;
            (bare, inherited, inner, current_producer().unwrap().fence)
        })
        .await;
        assert_eq!(seen, (true, Some(7), 9, 7));
        assert!(current_producer().is_none());
        // Without a producer, `inherit` is a transparent wrapper.
        assert!(inherit(async { current_producer().is_none() }).await);
    }

    fn export_lease(fence: i64) -> (CustodyLease, Uuid) {
        let export = Uuid::now_v7();
        let lease = CustodyLease::for_archive_export(
            TenantId::new(),
            CrawlRunId::new(),
            export,
            WorkerId::new(),
            fence,
        );
        (lease, export)
    }

    fn proof(custody: ArchiveCustodyV1) -> FrozenArchiveSource {
        FrozenArchiveSource::new(
            crate::ArtifactRef {
                id: ArtifactId::new(),
                digest: Digest::of("test", b"source"),
            },
            custody,
        )
    }

    fn closed(lease: &CustodyLease) -> SecretEpoch {
        SecretEpoch::new(lease.tenant, lease.run, Uuid::now_v7(), 4)
    }

    #[test]
    fn frozen_grant_binds_export_epoch_and_sources_and_refuses_weaker_authority() {
        let (lease, export) = export_lease(3);
        let epoch = closed(&lease);
        let deadline = crate::Timestamp::from_timestamp(2_000_000_000, 0).unwrap();
        let sensitive = proof(ArchiveCustodyV1::sensitive(deadline));
        let content = proof(ArchiveCustodyV1::content(None));
        let grant = FrozenArchiveGrant::new(
            &lease,
            epoch,
            ArchiveCustodyV1::sensitive(deadline),
            vec![sensitive.clone(), content.clone(), content.clone()],
        )
        .unwrap();
        assert_eq!((grant.export, grant.fence, grant.epoch), (export, 3, epoch));
        assert_eq!(grant.sources().len(), 2, "identical proofs deduplicate");
        assert!(grant
            .sources()
            .windows(2)
            .all(|pair| pair[0].artifact.id.0 < pair[1].artifact.id.0));
        grant.check_lease(&lease).unwrap();
        // Order of proofs never changes the durable identity.
        let reordered = FrozenArchiveGrant::new(
            &lease,
            epoch,
            ArchiveCustodyV1::sensitive(deadline),
            vec![content.clone(), sensitive.clone()],
        )
        .unwrap();
        assert_eq!(grant.binding(), reordered.binding());
        // Every bound field changes the identity.
        let other_epoch = SecretEpoch::new(lease.tenant, lease.run, epoch.incarnation, 5);
        let mut changed = vec![
            FrozenArchiveGrant::new(
                &lease,
                other_epoch,
                ArchiveCustodyV1::sensitive(deadline),
                vec![sensitive.clone(), content.clone()],
            ),
            FrozenArchiveGrant::new(
                &lease,
                epoch,
                ArchiveCustodyV1::sensitive(deadline),
                vec![sensitive.clone()],
            ),
        ];
        let mut fenced = lease.clone();
        fenced.fence = 4;
        changed.push(FrozenArchiveGrant::new(
            &fenced,
            epoch,
            ArchiveCustodyV1::sensitive(deadline),
            vec![sensitive.clone(), content.clone()],
        ));
        for other in changed {
            assert_ne!(other.unwrap().binding(), grant.binding());
        }

        // A grant never authorizes another producer, run or fence.
        let (other_export, _) = export_lease(3);
        assert!(grant.check_lease(&other_export).is_err());
        let mut stale = lease.clone();
        stale.fence = 2;
        assert!(grant.check_lease(&stale).is_err());
        let session = CustodyLease::new(lease.tenant, lease.run, SessionId::new(), WorkerId::new(), 3);
        assert!(grant.check_lease(&session).is_err());
        assert!(FrozenArchiveGrant::new(
            &session,
            epoch,
            ArchiveCustodyV1::content(None),
            vec![content.clone()]
        )
        .is_err());

        // Custody weaker than a source, empty sources, a foreign or unclosed epoch: no grant.
        assert!(FrozenArchiveGrant::new(
            &lease,
            epoch,
            ArchiveCustodyV1::content(None),
            vec![sensitive.clone()]
        )
        .is_err());
        assert!(FrozenArchiveGrant::new(
            &lease,
            epoch,
            ArchiveCustodyV1::sensitive(deadline + chrono::Duration::hours(1)),
            vec![sensitive.clone()],
        )
        .is_err());
        assert!(FrozenArchiveGrant::new(&lease, epoch, ArchiveCustodyV1::content(None), vec![]).is_err());
        assert!(FrozenArchiveGrant::new(
            &lease,
            SecretEpoch::new(TenantId::new(), lease.run, epoch.incarnation, 4),
            ArchiveCustodyV1::content(None),
            vec![content.clone()],
        )
        .is_err());
        assert!(FrozenArchiveGrant::new(
            &lease,
            SecretEpoch::new(lease.tenant, lease.run, epoch.incarnation, 0),
            ArchiveCustodyV1::content(None),
            vec![content.clone()],
        )
        .is_err());
        assert!(FrozenArchiveGrant::new(
            &lease,
            SecretEpoch::new(lease.tenant, lease.run, Uuid::nil(), 4),
            ArchiveCustodyV1::content(None),
            vec![content.clone()],
        )
        .is_err());
        let mut twice = content.clone();
        twice.custody = ArchiveCustodyV1::sensitive(deadline);
        assert!(FrozenArchiveGrant::new(
            &lease,
            epoch,
            ArchiveCustodyV1::sensitive(deadline),
            vec![content, twice]
        )
        .is_err());
    }

    #[test]
    fn frozen_grant_outputs_stay_inside_class_deadline_kind_and_media_type() {
        use crate::repo::Sensitivity;
        let (lease, _) = export_lease(3);
        let deadline = crate::Timestamp::from_timestamp(2_000_000_000, 0).unwrap();
        let grant = FrozenArchiveGrant::new(
            &lease,
            closed(&lease),
            ArchiveCustodyV1::sensitive(deadline),
            vec![proof(ArchiveCustodyV1::sensitive(deadline))],
        )
        .unwrap();
        for content_type in FROZEN_ARCHIVE_CONTENT_TYPES {
            grant
                .check_output(Sensitivity::Sensitive, Some(deadline), "evidence", content_type)
                .unwrap();
        }
        let earlier = deadline - chrono::Duration::seconds(1);
        grant
            .check_output(
                Sensitivity::Sensitive,
                Some(earlier),
                "evidence",
                "application/warc",
            )
            .unwrap();
        for (class, expiry, kind, content_type) in [
            (
                Sensitivity::Content,
                Some(deadline),
                "evidence",
                "application/warc",
            ),
            (Sensitivity::Sensitive, None, "evidence", "application/warc"),
            (
                Sensitivity::Sensitive,
                Some(deadline + chrono::Duration::seconds(1)),
                "evidence",
                "application/warc",
            ),
            (
                Sensitivity::Sensitive,
                Some(deadline),
                "markdown",
                "application/warc",
            ),
            (Sensitivity::Sensitive, Some(deadline), "evidence", "text/html"),
            (
                Sensitivity::CredentialBearing,
                Some(deadline),
                "evidence",
                "application/warc",
            ),
        ] {
            assert!(
                matches!(
                    grant.check_output(class, expiry, kind, content_type),
                    Err(StoreError::RetentionDenied(_))
                ),
                "{class:?} {kind} {content_type}"
            );
        }
    }

    #[tokio::test]
    async fn frozen_grant_is_task_scoped_and_not_inherited() {
        let (lease, _) = export_lease(3);
        let grant = FrozenArchiveGrant::new(
            &lease,
            closed(&lease),
            ArchiveCustodyV1::content(None),
            vec![proof(ArchiveCustodyV1::content(None))],
        )
        .unwrap();
        assert!(current_frozen_archive().is_none());
        let seen = with_frozen_archive(grant.clone(), async {
            let spawned = tokio::spawn(inherit(async { current_frozen_archive().is_none() }))
                .await
                .unwrap();
            (current_frozen_archive().map(|grant| grant.binding()), spawned)
        })
        .await;
        assert_eq!(seen, (Some(grant.binding()), true));
        assert!(current_frozen_archive().is_none());
    }
}
