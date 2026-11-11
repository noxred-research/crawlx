//! Dedicated, PostgreSQL-fenced ownership of joined run-bootstrap work.
//!
//! Lifecycle: authorize the admitted worker context, claim, resume from the
//! durable non-secret cursor, renew well before expiry, checkpoint only joined
//! successful work, then explicitly complete after every bootstrap task joins.
//! Claim returns durable completion separately from acquisition and contention.
//! Existing seed/frontier rows never establish completion. Expiry or release
//! permits takeover with a fresh sequence fence and the same durable cursor;
//! neither operation proves that an old task or plaintext queue stopped.
//! Numeric progress denotes stable completed phases, not a cursor into mutable
//! sitemap contents. Source-level resume must also bind its existing source
//! digest and position. `Busy` and `Completed` grant no credential-delivery lease.
//!
//! Errors, cancellation and unknown remote writes never imply success. A failed
//! commit leaves the caller without authority; re-read through claim, which may
//! report busy or completed. Never mark partial/unknown work completed. Producers
//! must stop using a fence immediately after any lease/authorization error.
//! Release does not join work, erase OPEN exposures or authorize plaintext.
//!
//! Every issued custody lease retains the captured context's cancellation token.
//! Lock waits recheck this local veto before mutation. Cancellation does not
//! retract queued PostgreSQL/Redis commands or prove task/transport quiescence.
//! A pending registration remains a barrier after cancellation or an unknown
//! remote result; neither a local error nor release clears that barrier.
//!
//! The trusted worker-context adapter deliberately remains unwired until full
//! secret enumeration and live-output ownership boundaries are integrated.
//! This module provides neither a plaintext fallback nor production closure.

use super::{database_now, denied, frag, locally_live, no_exposures, random_uuid, run_lock};
use crate::backend::strategy::{Conn, FenceSeq};
use crate::backend::{BackendKind, PgBackend, WriteTx};
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::custody::{CustodyLease, CustodySource};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp, WorkerId};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Suggested lease duration; renew substantially before its absolute expiry.
pub const BOOTSTRAP_PRODUCER_TTL: Duration = Duration::from_secs(60);
/// Hard maximum for each bootstrap acquisition or renewal.
pub const MAX_BOOTSTRAP_PRODUCER_TTL: Duration = Duration::from_secs(5 * 60);

/// Trusted boundary capturing an actual admitted worker `RunContext`.
///
/// Implementations must match `tenant` to `RunContext.stores.tenant`, `run` to
/// `RunContext.run`, reject its cancelled token, and read current run metadata.
/// If the run references an authorization record, require the matching captured
/// `AuthorizationGuard`, call `check_tenant` and `check_now`, and fail closed on
/// unavailable authorization. A missing guard is valid only for a context whose
/// run references no authorization record (including public/read-only runs).
/// Return the real `RunContext.worker` and a clone of `RunContext.cancel`, never
/// a fresh token, session, API principal, surrogate, heartbeat identity or
/// unverified caller argument. Worker registration alone is not producer
/// ownership. Storage also locks and checks current run, authorization and
/// non-draining worker rows on every operation.
#[async_trait]
pub trait BootstrapProducerAuthorizer: Send + Sync {
    /// Authorize the captured context and return its actual worker and token.
    ///
    /// # Errors
    /// Rejects mismatched, cancelled, unauthorized or unavailable contexts.
    async fn authorize(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
    ) -> Result<BootstrapAuthorization, StoreError>;
}

/// Trusted admission result, including the actual context's cancellation token.
#[derive(Clone, Debug)]
#[must_use]
#[non_exhaustive]
pub struct BootstrapAuthorization {
    worker: WorkerId,
    cancellation: CancellationToken,
}

impl BootstrapAuthorization {
    /// Bind the actual admitted worker and a clone of its existing context token.
    ///
    /// Only a trusted [`BootstrapProducerAuthorizer`] may supply this result.
    /// This value alone grants no ownership: PostgreSQL must issue a fresh fence.
    pub fn new(worker: WorkerId, cancellation: CancellationToken) -> Self {
        Self { worker, cancellation }
    }

    fn check(&self) -> Result<(), StoreError> {
        if self.cancellation.is_cancelled() {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }
}

/// Owned bootstrap fence plus the last durably observed progress and expiry.
#[derive(Clone, Debug)]
#[must_use]
#[non_exhaustive]
pub struct BootstrapLease {
    custody: CustodyLease,
    expires_at: Timestamp,
    progress: i64,
}

impl BootstrapLease {
    /// Custody authority for bootstrap secret registration and encrypted writes.
    #[must_use]
    pub const fn custody(&self) -> &CustodyLease {
        &self.custody
    }

    /// Absolute database-clock expiry, not proof that an old producer stopped.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Last durably observed non-secret, monotonically increasing resume cursor.
    #[must_use]
    pub const fn progress(&self) -> i64 {
        self.progress
    }
}

/// Distinguishes durable completion from live ownership and contention.
#[derive(Clone, Debug)]
#[must_use]
#[non_exhaustive]
pub enum BootstrapClaim {
    /// New ownership; resume from this lease's durable cursor.
    Acquired(BootstrapLease),
    /// Another acquisition still owns the run, including this worker's old claim.
    Busy {
        /// Absolute expiry of the current owner; never evidence of quiescence.
        expires_at: Timestamp,
    },
    /// Explicitly committed completion; never inferred from seed/frontier state.
    Completed {
        /// Final durable resume cursor.
        progress: i64,
        /// Database time of successful fenced completion.
        completed_at: Timestamp,
    },
}

/// Database bootstrap ownership, independent of volatile secret storage.
#[derive(Clone)]
pub struct BootstrapAuthority<B: Sql> {
    store: Store<B>,
    authorizer: Arc<dyn BootstrapProducerAuthorizer>,
    ttl: chrono::Duration,
}

/// Bootstrap ownership over PostgreSQL.
pub type PgBootstrapAuthority = BootstrapAuthority<PgBackend>;

impl<B: Sql> BootstrapAuthority<B> {
    /// Bind a trusted worker-context authorizer and positive bounded lease TTL.
    ///
    /// # Errors
    /// Rejects sub-millisecond, zero or greater-than-five-minute TTLs.
    pub fn new(
        store: Store<B>,
        authorizer: Arc<dyn BootstrapProducerAuthorizer>,
        ttl: Duration,
    ) -> Result<Self, StoreError> {
        if ttl < Duration::from_millis(1) || ttl > MAX_BOOTSTRAP_PRODUCER_TTL {
            return Err(denied(
                "bootstrap lease TTL must be between one millisecond and five minutes",
            ));
        }
        let ttl = chrono::Duration::from_std(ttl).map_err(|_| denied("bootstrap lease TTL out of range"))?;
        Ok(Self {
            store,
            authorizer,
            ttl,
        })
    }

    async fn transaction(&self) -> Result<WriteTx<B::Db>, StoreError> {
        let mut tx = self.store.begin_write().await?;
        frag::bound_waits::<B>(tx.conn()).await?;
        Ok(tx)
    }

    // Lock order matches custody: authority, run, source/worker, authorization.
    // Every authorization decision uses fresh database time after lock waits.
    async fn eligible(
        &self,
        conn: &mut Conn<B>,
        tenant: TenantId,
        run: CrawlRunId,
        authorization: &BootstrapAuthorization,
    ) -> Result<(Timestamp, Timestamp), StoreError> {
        authorization.check()?;
        let result = tokio::select! {
            biased;
            () = authorization.cancellation.cancelled() => Err(StoreError::LeaseLost),
            result = self.eligible_locked(conn, tenant, run, authorization.worker) => result,
        };
        authorization.check()?;
        result
    }

    async fn eligible_locked(
        &self,
        conn: &mut Conn<B>,
        tenant: TenantId,
        run: CrawlRunId,
        worker: WorkerId,
    ) -> Result<(Timestamp, Timestamp), StoreError> {
        run_lock::<B>(conn, tenant, run, true).await?;
        let found = stmt!(
            B,
            format!(
                "SELECT run_id FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2{}",
                frag::share::<B>()
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .fetch_optional(conn)
        .await?;
        if found.is_none() {
            return Err(StoreError::LeaseLost);
        }
        let registered = stmt!(
            B,
            format!(
                "SELECT worker_id FROM workers WHERE worker_id=$1 AND NOT draining{}",
                frag::share::<B>()
            )
        )
        .uuid(worker.0)
        .fetch_optional(conn)
        .await?;
        if registered.is_none() {
            return Err(StoreError::LeaseLost);
        }
        stmt!(
            B,
            format!(
                "SELECT a.record_id FROM authorization_records a JOIN crawl_runs r ON r.authorization_record_id=a.record_id WHERE r.run_id=$1{}",
                frag::share_of::<B>("a")
            )
        )
        .uuid(run.0)
        .fetch_optional(conn)
        .await?;
        let now = database_now::<B>(conn).await?;
        let limit = stmt!(
            B,
            format!(
                "SELECT {} AS v FROM crawl_runs r \
             LEFT JOIN authorization_records a ON a.record_id=r.authorization_record_id \
             WHERE r.tenant_id=$1 AND r.run_id=$2 AND r.status IN ('queued','running') \
             AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
             AND (r.expires_at IS NULL OR r.expires_at>$3) \
             AND (r.deadline_at IS NULL OR r.deadline_at>$3) \
             AND (r.authorization_record_id IS NULL OR \
               (a.record_id IS NOT NULL AND a.tenant_id=r.tenant_id AND a.revoked_at IS NULL \
                AND a.valid_from<=$3 AND a.valid_to>$3 \
                AND (r.authorization_body_digest IS NULL OR r.authorization_body_digest=a.body_digest)))",
                frag::least::<B>(&["r.expires_at", "r.deadline_at", "a.valid_to"])
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .ts(now)
        .fetch_optional(conn)
        .await?;
        let limit = limit.ok_or(StoreError::LeaseLost)?.opt_ts("v")?;
        let expiry = now
            .checked_add_signed(self.ttl)
            .ok_or_else(|| denied("bootstrap lease expiry out of range"))?;
        Ok((now, limit.map_or(expiry, |limit| expiry.min(limit))))
    }

    /// Claim the run exclusively, retaining durable progress after takeover.
    ///
    /// A live row returns `Busy` even for the same worker. A retry after an
    /// unknown acquisition must not assume ownership. An expired/released row
    /// receives a strictly newer fence from the owned sequence.
    ///
    /// # Errors
    /// Rejects unavailable authorization, unregistered/draining workers, stopped
    /// runs, expired/revoked authorization, tenant mismatches and backend errors.
    pub async fn claim(&self, tenant: TenantId, run: CrawlRunId) -> Result<BootstrapClaim, StoreError> {
        let authorization = self.authorizer.authorize(tenant, run).await?;
        authorization.check()?;
        let worker = authorization.worker;
        let mut tx = self.transaction().await?;
        let (now, expiry) = self.eligible(tx.conn(), tenant, run, &authorization).await?;
        let existing = stmt!(
            B,
            format!(
                "SELECT producer_id,state,expires_at,progress,completed_at FROM run_bootstrap_producers WHERE tenant_id=$1 AND run_id=$2{}",
                frag::update::<B>()
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .fetch_optional(tx.conn())
        .await?;
        authorization.check()?;
        let producer = if let Some(row) = existing {
            let id = row.uuid("producer_id")?;
            let state = row.text("state")?;
            let expires_at = row.ts("expires_at")?;
            let progress = row.i64("progress")?;
            let completed_at = row.opt_ts("completed_at")?;
            if state == "completed" {
                let completed_at =
                    completed_at.ok_or_else(|| denied("bootstrap completion timestamp missing"))?;
                tx.commit().await?;
                authorization.check()?;
                return Ok(BootstrapClaim::Completed {
                    progress,
                    completed_at,
                });
            }
            if state == "running" && expires_at > now {
                tx.commit().await?;
                authorization.check()?;
                return Ok(BootstrapClaim::Busy { expires_at });
            }
            id
        } else {
            random_uuid()?
        };
        let (fence, progress) =
            acquire_row::<B>(tx.conn(), producer, tenant, run, worker, now, expiry).await?;
        authorization.check()?;
        tx.commit().await?;
        authorization.check()?;
        Ok(BootstrapClaim::Acquired(BootstrapLease {
            custody: CustodyLease::for_bootstrap(
                tenant,
                run,
                producer,
                worker,
                fence,
                authorization.cancellation,
            ),
            expires_at: expiry,
            progress,
        }))
    }

    async fn owned(
        &self,
        conn: &mut Conn<B>,
        lease: &BootstrapLease,
    ) -> Result<(Uuid, Timestamp, Timestamp, i64), StoreError> {
        let custody = lease.custody();
        custody.check_local_cancellation()?;
        let authorization = self.authorizer.authorize(custody.tenant, custody.run).await?;
        authorization.check()?;
        let worker = authorization.worker;
        if worker != custody.worker || custody.fence <= 0 {
            return Err(StoreError::LeaseLost);
        }
        let CustodySource::Bootstrap(producer) = custody.source else {
            return Err(StoreError::LeaseLost);
        };
        let (now, expiry) = self
            .eligible(conn, custody.tenant, custody.run, &authorization)
            .await?;
        let owned = locally_live(custody, async {
            stmt!(
                B,
                format!(
                    "SELECT expires_at,progress FROM run_bootstrap_producers WHERE producer_id=$1 AND tenant_id=$2 AND run_id=$3 AND owner=$4 AND fence=$5 AND state='running'{}",
                    frag::update::<B>()
                )
            )
            .uuid(producer)
            .uuid(custody.tenant.0)
            .uuid(custody.run.0)
            .uuid(worker.0)
            .i64(custody.fence)
            .fetch_optional(&mut *conn)
            .await
        })
        .await?;
        let owned = owned.ok_or(StoreError::LeaseLost)?;
        let (old_expiry, progress) = (owned.ts("expires_at")?, owned.i64("progress")?);
        if old_expiry <= database_now::<B>(conn).await? {
            return Err(StoreError::LeaseLost);
        }
        authorization.check()?;
        custody.check_local_cancellation()?;
        Ok((producer, now, expiry, progress))
    }

    /// Renew live ownership; an expired fence can never renew or revive.
    ///
    /// # Errors
    /// Rejects stale/expired fences, failed current authorization and backend errors.
    pub async fn renew(&self, lease: &BootstrapLease) -> Result<BootstrapLease, StoreError> {
        let mut tx = self.transaction().await?;
        let (producer, now, expiry, progress) = self.owned(tx.conn(), lease).await?;
        let clock = frag::clock::<B>();
        let renewed = frag::update_returning::<B>(
            tx.conn(),
            stmt!(B, format!("UPDATE run_bootstrap_producers SET leased_at=$2,expires_at=$3 WHERE producer_id=$1 AND expires_at>{clock}{}", frag::returning::<B>("producer_id")))
                .uuid(producer).ts(now).ts(expiry),
            stmt!(B, "SELECT producer_id FROM run_bootstrap_producers WHERE producer_id=$1").uuid(producer),
        )
        .await?;
        renewed.ok_or(StoreError::LeaseLost)?;
        lease.custody.check_local_cancellation()?;
        tx.commit().await?;
        lease.custody.check_local_cancellation()?;
        Ok(BootstrapLease {
            custody: lease.custody.clone(),
            expires_at: expiry,
            progress,
        })
    }

    /// Persist a non-secret cursor only after the corresponding work joins.
    ///
    /// Does not renew expiry. A takeover resumes this cursor but must independently
    /// handle idempotency of external writes; unknown writes are not checkpoints.
    ///
    /// # Errors
    /// Rejects negative/regressing cursors, stale fences, authorization or backend errors.
    pub async fn checkpoint(
        &self,
        lease: &BootstrapLease,
        progress: i64,
    ) -> Result<BootstrapLease, StoreError> {
        let mut tx = self.transaction().await?;
        let (producer, _, _, previous) = self.owned(tx.conn(), lease).await?;
        if progress < previous || progress < 0 {
            return Err(denied("bootstrap progress cannot regress"));
        }
        let clock = frag::clock::<B>();
        let updated = frag::update_returning::<B>(
            tx.conn(),
            stmt!(B, format!("UPDATE run_bootstrap_producers SET progress=$2 WHERE producer_id=$1 AND expires_at>{clock}{}", frag::returning::<B>("expires_at")))
                .uuid(producer).i64(progress),
            stmt!(B, "SELECT expires_at FROM run_bootstrap_producers WHERE producer_id=$1").uuid(producer),
        )
        .await?;
        let expires_at = updated.ok_or(StoreError::LeaseLost)?.ts("expires_at")?;
        lease.custody.check_local_cancellation()?;
        tx.commit().await?;
        lease.custody.check_local_cancellation()?;
        Ok(BootstrapLease {
            custody: lease.custody.clone(),
            expires_at,
            progress,
        })
    }

    /// Commit permanent completion only after all successful bootstrap work joins.
    ///
    /// `progress` must match the durable checkpoint exactly. Partial work,
    /// cancellation and unknown writes must never call this method. Completion
    /// cannot clear OPEN exposures and is not a production plaintext-closure claim.
    ///
    /// # Errors
    /// Rejects mismatched progress, stale ownership, OPEN exposures, failed current
    /// authorization and backend errors. Unknown commit outcomes require claim.
    pub async fn complete(&self, lease: &BootstrapLease, progress: i64) -> Result<(), StoreError> {
        let mut tx = self.transaction().await?;
        let (producer, _, _, durable) = self.owned(tx.conn(), lease).await?;
        if progress != durable {
            return Err(denied("bootstrap completion requires the durable checkpoint"));
        }
        no_exposures::<B>(tx.conn(), lease.custody.tenant, lease.custody.run).await?;
        lease.custody.check_local_cancellation()?;
        let clock = frag::clock::<B>();
        let completed = stmt!(B, format!("UPDATE run_bootstrap_producers SET state='completed',completed_at={clock},expires_at={clock} WHERE producer_id=$1 AND expires_at>{clock}"))
            .uuid(producer).execute(tx.conn()).await?;
        if completed == 0 {
            return Err(StoreError::LeaseLost);
        }
        lease.custody.check_local_cancellation()?;
        tx.commit().await?;
        lease.custody.check_local_cancellation()
    }

    /// Relinquish a still-live fence without marking its work completed.
    ///
    /// Join/cancel owned work before release. This API does not infer producer
    /// death, clear OPEN exposures, erase progress or alter secret authority.
    ///
    /// # Errors
    /// Rejects stale/expired ownership, failed authorization and backend errors.
    pub async fn release(&self, lease: &BootstrapLease) -> Result<(), StoreError> {
        let mut tx = self.transaction().await?;
        let (producer, _, _, _) = self.owned(tx.conn(), lease).await?;
        let clock = frag::clock::<B>();
        let released = stmt!(B, format!("UPDATE run_bootstrap_producers SET state='released',expires_at={clock} WHERE producer_id=$1 AND expires_at>{clock}"))
            .uuid(producer).execute(tx.conn()).await?;
        if released == 0 {
            return Err(StoreError::LeaseLost);
        }
        lease.custody.check_local_cancellation()?;
        tx.commit().await?;
        lease.custody.check_local_cancellation()
    }
}

/// Insert or take over the producer row with a fresh fence, returning `(fence, progress)`.
async fn acquire_row<B: Sql>(
    conn: &mut Conn<B>,
    producer: Uuid,
    tenant: TenantId,
    run: CrawlRunId,
    worker: WorkerId,
    now: Timestamp,
    expiry: Timestamp,
) -> Result<(i64, i64), StoreError> {
    let row = match B::KIND {
        BackendKind::Postgres => stmt!(B, "INSERT INTO run_bootstrap_producers(producer_id,tenant_id,run_id,owner,state,leased_at,expires_at) \
             VALUES($1,$2,$3,$4,'running',$5,$6) \
             ON CONFLICT(tenant_id,run_id) DO UPDATE SET owner=EXCLUDED.owner, \
               fence=nextval('run_bootstrap_producer_fence'),state='running',leased_at=EXCLUDED.leased_at,expires_at=EXCLUDED.expires_at \
             RETURNING fence,progress")
            .uuid(producer).uuid(tenant.0).uuid(run.0).uuid(worker.0).ts(now).ts(expiry)
            .fetch_one(conn).await?,
        BackendKind::MariaDb => stmt!(B, "INSERT INTO run_bootstrap_producers(producer_id,tenant_id,run_id,owner,state,leased_at,expires_at) \
             VALUES($1,$2,$3,$4,'running',$5,$6) \
             ON DUPLICATE KEY UPDATE owner=VALUES(owner), \
               fence=NEXTVAL(run_bootstrap_producer_fence),state='running',leased_at=VALUES(leased_at),expires_at=VALUES(expires_at) \
             RETURNING fence,progress")
            .uuid(producer).uuid(tenant.0).uuid(run.0).uuid(worker.0).ts(now).ts(expiry)
            .fetch_one(conn).await?,
        BackendKind::Sqlite => {
            let fence = B::next_fence(conn, FenceSeq::BootstrapProducer).await?;
            stmt!(B, "INSERT INTO run_bootstrap_producers(producer_id,tenant_id,run_id,owner,fence,state,leased_at,expires_at) \
                 VALUES($1,$2,$3,$4,$7,'running',$5,$6) \
                 ON CONFLICT(tenant_id,run_id) DO UPDATE SET owner=EXCLUDED.owner, \
                   fence=EXCLUDED.fence,state='running',leased_at=EXCLUDED.leased_at,expires_at=EXCLUDED.expires_at \
                 RETURNING fence,progress")
                .uuid(producer).uuid(tenant.0).uuid(run.0).uuid(worker.0).ts(now).ts(expiry).i64(fence)
                .fetch_one(conn).await?
        }
    };
    Ok((row.i64("fence")?, row.i64("progress")?))
}
