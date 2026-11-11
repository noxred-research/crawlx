//! Run-wide secret snapshots for encrypted artifact publication.
//!
//! Implementations must share volatile secret material across workers. A local
//! `CaptchaSecrets` value is only a snapshot, never publication authority.

use crate::captcha::CaptchaSecrets;
use crate::{ArtifactId, CrawlRunId, SecretOr, SessionId, StoreError, TenantId, WorkerId};
use async_trait::async_trait;
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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

    /// Recover an exact previously applied renewal receipt without extending expiry.
    ///
    /// PostgreSQL/Redis implementations reject new or unapplied renewals: Redis
    /// cannot atomically revalidate PostgreSQL ownership and local cancellation.
    /// Read-only recovery of an applied historical receipt may return the current
    /// epoch after later registration; it must never replay an expiry extension.
    ///
    /// # Errors
    /// Rejects new/unapplied renewals, stale fences, changed retries, lost state,
    /// unavailable authorization and unresolved registration.
    async fn renew_authority(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        operation: Uuid,
        deadline: crate::Timestamp,
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
}
