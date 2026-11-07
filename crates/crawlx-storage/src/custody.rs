//! PostgreSQL-fenced publication with a shared, volatile Redis secret registry.
//!
//! A durable pending operation is committed before Redis receives secret bytes.
//! Unknown outcomes remain pending: no publication or handoff may infer success.
//! Retry the same operation and value to recover. Redis loss is not recoverable
//! by rebuilding an empty registry. An unfinalized run then becomes unavailable;
//! its retained encrypted artifacts must not silently become readable without
//! their complete secret authority. Every secret category must register here
//! before entering browser/content state. Local registries alone are insufficient.
//!
//! PostgreSQL owns tenant/run fencing, pending operations, salted commitments,
//! ciphertext catalog identity, KMS-wrapped keys and permanent finalization.
//! Redis alone owns raw values and the random commitment salt. Initial lifetime
//! is bounded. New expiry extensions are unavailable: Redis cannot atomically
//! revalidate PostgreSQL ownership or local cancellation. Only exact historical,
//! already-applied renewal receipts can recover read-only, without extending TTL.
//! Lost state is never reconstructed. Finalize a terminal run at its complete
//! epoch before its original lifetime expires. The permanent seal permits retained
//! artifact reads to outlive the volatile registry.
//!
//! API consumers must authenticate/authorize each artifact and validate complete
//! ciphertext/AEAD/plaintext fixity. A current snapshot or recheck does not fence
//! live plaintext disclosure. There is deliberately no public exposure issuance
//! or cleanup API until a transport-owned producer/queue lifetime capability
//! exists. An arbitrary successful task is not quiescence proof. Existing OPEN
//! ledger entries conservatively block new registration/finalization; no TTL
//! clears them. Live-output integration remains an explicit blocker, not solved
//! by replacing required live behavior with finalized-only reads.
//!
//! Deployment must dedicate a Redis instance, disable RDB/AOF and replicas, set
//! positive maxmemory with noeviction, deny SAVE/BGSAVE/CONFIG SET/REPLICAOF,
//! MONITOR and replica connections, disable swap and core dumps, and isolate the
//! transport. Runtime checks cannot enforce host memory or administrator behavior.
//! PostgreSQL and Redis clocks must stay within one second without backward
//! steps. Runtime samples reject wider skew; native Redis expiry is two seconds
//! earlier than the PostgreSQL deadline. Unsynchronized clocks are unsupported.
//! No implicit process-local backend exists.
//!
//! Bootstrap leases carry a local cancellation veto. Storage checks it around
//! lock waits, remote operations and commits, in addition to the shared fence.
//! This is cooperative revocation, not an atomic fence inside Redis/PostgreSQL:
//! already-enqueued commands or COMMIT may execute after cancellation. Errors
//! never authorize credential delivery; durable pending intents remain barriers.

use crate::codec::get;
use crate::error::db;
use crate::{ArtifactRow, Pg};
use async_trait::async_trait;
use crawlx_core::captcha::CaptchaSecrets;
use crawlx_core::custody::{
    ArtifactReadState, CustodyLease, CustodySource, RunSecretAuthority, RunSecretSnapshot, SecretEpoch,
};
use crawlx_core::hash::Digest;
use crawlx_core::{ArtifactId, CrawlRunId, SecretOr, StoreError, TenantId, Timestamp, WorkerId};
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::collections::BTreeMap;
use std::future::Future;
use std::time::Duration;
use uuid::Uuid;
use zeroize::Zeroizing;

pub mod bootstrap;
mod renewal;
pub use bootstrap::{
    BootstrapAuthorization, BootstrapClaim, BootstrapLease, BootstrapProducerAuthorizer,
    PgBootstrapAuthority, BOOTSTRAP_PRODUCER_TTL, MAX_BOOTSTRAP_PRODUCER_TTL,
};
const SCRIPT: &str = include_str!("custody_redis.lua");
const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_VALUES: usize = 256;
const MAX_TOTAL_BYTES: usize = 1024 * 1024;
const MAX_CLOCK_SKEW_MS: i64 = 1000;
const EXPIRY_MARGIN_MS: i64 = 2000;
const MAX_EPOCH: i64 = 9_007_199_254_740_000;
/// Maximum initial lifetime and supported historical renewal-receipt window.
pub const MAX_AUTHORITY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Conflict detail: no live authority exists for the run (never initialized or expired).
pub(crate) const AUTHORITY_MISSING: &str = "secret authority missing or expired";
/// Conflict detail: Redis outcome unknown; the same operation must be recovered.
pub(crate) const OUTCOME_UNKNOWN: &str = "secret authority Redis outcome unknown; recover same operation";
/// Conflict detail: publication lost an epoch race or a registration is pending.
pub(crate) const PUBLISH_STALE: &str = "artifact publication secret epoch changed or pending";
/// Conflict detail: a snapshot was refused because a registration is pending.
pub(crate) const SNAPSHOT_PENDING: &str = "secret authority registration pending";
/// Conflict detail: registration lost an epoch race or another registration is pending.
pub(crate) const REGISTER_STALE: &str = "secret registration pending or epoch changed";
/// Digest domain for complete stored ciphertext, including authenticated framing.
pub const CIPHERTEXT_DIGEST_DOMAIN: &str = "crawlx/artifact-ciphertext/v1";

/// Authenticated identity of the encrypted object, separate from plaintext API identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
#[non_exhaustive]
pub struct CiphertextIdentity {
    /// Domain-separated digest of the stored ciphertext bytes.
    pub digest: Digest,
    /// Stored ciphertext length, including authenticated framing.
    pub size_bytes: u64,
}

impl CiphertextIdentity {
    /// Construct bounded, nonempty encrypted-object identity.
    ///
    /// # Errors
    /// Rejects empty or PostgreSQL-unrepresentable ciphertext lengths.
    pub fn new(digest: Digest, size_bytes: u64) -> Result<Self, StoreError> {
        if size_bytes == 0 || i64::try_from(size_bytes).is_err() {
            return Err(denied("invalid artifact ciphertext length"));
        }
        Ok(Self { digest, size_bytes })
    }
}

/// Durable key custody and encrypted-object fixity returned in one authoritative read.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ArtifactKeyCustody {
    /// KMS envelope bound to tenant/run/artifact.
    pub envelope: ArtifactKeyEnvelope,
    /// Encrypted-object identity; never replaces plaintext ArtifactRow identity.
    pub ciphertext: CiphertextIdentity,
}

/// Unique AEAD-owned encrypted object namespace. Fresh sealing attempts cannot
/// overwrite an already-published blob; identical ciphertext retries are idempotent.
#[must_use]
pub fn encrypted_object_key(
    tenant: TenantId,
    run: CrawlRunId,
    artifact: ArtifactId,
    ciphertext: Digest,
) -> String {
    use std::fmt::Write as _;
    // Fixed UUIDs plus lowercase digest: one allocation, no temporary hex string.
    let mut key = String::with_capacity(185);
    let _ = write!(key, "encrypted/{tenant}/{run}/{artifact}/");
    for byte in ciphertext.0 {
        let _ = write!(key, "{byte:02x}");
    }
    key
}

const CUSTODY_ROW_QUERY: &str = "SELECT c.* FROM artifact_key_custody c JOIN artifacts a USING(artifact_id) \
     JOIN crawl_runs r ON r.run_id=c.run_id AND r.tenant_id=c.tenant_id \
     WHERE c.tenant_id=$1 AND c.run_id=$2 AND c.artifact_id=$3 \
       AND a.tenant_id=c.tenant_id AND a.run_id=c.run_id \
       AND a.content_digest=c.plaintext_digest AND a.size_bytes=c.plaintext_size \
       AND c.artifact_payload->>'digest'=encode(a.content_digest,'hex') \
       AND (c.artifact_payload->>'size_bytes')::bigint=a.size_bytes \
       AND a.object_key=c.object_key AND a.object_key=c.artifact_payload->>'object_key' \
       AND a.bucket=c.artifact_payload->>'bucket' AND a.kind=c.artifact_payload->>'kind' \
       AND a.content_type=c.artifact_payload->>'content_type' \
       AND a.sensitivity::text=c.artifact_payload->>'sensitivity' \
       AND a.created_at=c.created_at \
       AND a.deleted_at IS NULL AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) \
       AND r.purge_requested_at IS NULL AND (r.expires_at IS NULL OR r.expires_at>clock_timestamp())";

async fn custody_row<'e, E: sqlx::Executor<'e, Database = Postgres>>(
    executor: E,
    tenant: TenantId,
    run: CrawlRunId,
    artifact: ArtifactId,
) -> Result<sqlx::postgres::PgRow, StoreError> {
    scope(tenant)?;
    sqlx::query(CUSTODY_ROW_QUERY)
        .bind(tenant.0)
        .bind(run.0)
        .bind(artifact.0)
        .fetch_optional(executor)
        .await
        .map_err(db)?
        .ok_or_else(|| denied("artifact key custody unavailable"))
}

/// Durable KMS ciphertext for one artifact key; never contains a plaintext key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ArtifactKeyEnvelope {
    /// Exact KMS key identifier used for wrapping.
    pub kms_key_id: String,
    /// KMS ciphertext blob, not raw artifact key bytes.
    pub wrapped_key: Vec<u8>,
    /// Exact ownership context passed to KMS Encrypt and Decrypt.
    pub encryption_context: BTreeMap<String, String>,
    /// Ciphertext framing version.
    pub format_version: u32,
}

impl ArtifactKeyEnvelope {
    /// Construct a version-one envelope with the required ownership context.
    ///
    /// # Errors
    /// Rejects empty/oversized key identifiers and wrapped-key blobs.
    pub fn new(
        tenant: TenantId,
        run: CrawlRunId,
        artifact: ArtifactId,
        kms_key_id: String,
        wrapped_key: Vec<u8>,
    ) -> Result<Self, StoreError> {
        let envelope = Self {
            kms_key_id,
            wrapped_key,
            encryption_context: Self::context(tenant, run, artifact),
            format_version: 1,
        };
        envelope.validate(tenant, run, artifact)?;
        Ok(envelope)
    }

    /// Ownership context callers must pass unchanged to KMS wrapping/unwrapping.
    #[must_use]
    pub fn context(tenant: TenantId, run: CrawlRunId, artifact: ArtifactId) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("domain".into(), "crawlx/artifact-key/v1".into()),
            ("tenant".into(), tenant.to_string()),
            ("run".into(), run.to_string()),
            ("artifact".into(), artifact.to_string()),
        ])
    }

    fn validate(&self, tenant: TenantId, run: CrawlRunId, artifact: ArtifactId) -> Result<(), StoreError> {
        if self.kms_key_id.is_empty()
            || self.kms_key_id.len() > 2048
            || self.wrapped_key.is_empty()
            || self.wrapped_key.len() > 64 * 1024
            || self.format_version != 1
            || self.encryption_context != Self::context(tenant, run, artifact)
        {
            return Err(denied("invalid artifact key custody envelope"));
        }
        Ok(())
    }
}

/// Real distributed authority. Clones share PostgreSQL and Redis, not local secrets.
#[derive(Clone)]
pub struct PgSecretAuthority {
    pg: Pg,
    connection: Option<redis::aio::MultiplexedConnection>,
    ttl: Duration,
}

/// Trusted service boundary implemented by the API's authenticated Principal
/// adapter. Implementations must check actual authentication, tenant/run access
/// and the route's producer permission; a tenant id alone is not authorization.
#[async_trait]
pub trait ArtifactProducerAuthorizer: Send + Sync {
    /// Return the authenticated API key id only after all route checks pass.
    ///
    /// # Errors
    /// Rejects unauthenticated, out-of-scope or unauthorized producers.
    async fn authorize(&self, tenant: TenantId, run: CrawlRunId) -> Result<Uuid, StoreError>;
}

struct AuthorityRow {
    tenant: TenantId,
    run: CrawlRunId,
    incarnation: Uuid,
    epoch: i64,
    pending: Option<Uuid>,
    last: Option<Uuid>,
    commitment: Option<Vec<u8>>,
    pending_commitment: Option<Vec<u8>>,
    pending_value_commitment: Option<Vec<u8>>,
    last_value_commitment: Option<Vec<u8>>,
    expires_at: Timestamp,
    sealed_at: Option<Timestamp>,
}

impl AuthorityRow {
    fn parse(tenant: TenantId, run: CrawlRunId, row: &sqlx::postgres::PgRow) -> Result<Self, StoreError> {
        Ok(Self {
            tenant,
            run,
            incarnation: get(row, "incarnation")?,
            epoch: get(row, "epoch")?,
            pending: get(row, "pending_operation")?,
            last: get(row, "last_operation")?,
            commitment: get(row, "commitment")?,
            pending_commitment: get(row, "pending_commitment")?,
            pending_value_commitment: get(row, "pending_value_commitment")?,
            last_value_commitment: get(row, "last_value_commitment")?,
            expires_at: get(row, "expires_at")?,
            sealed_at: get(row, "sealed_at")?,
        })
    }
}

struct VolatileSnapshot {
    snapshot: RunSecretSnapshot,
    commitment: [u8; 32],
    proposed: [u8; 32],
    binding_salt: Zeroizing<String>,
}

impl VolatileSnapshot {
    fn check(&self, expected: Option<&[u8]>) -> Result<(), StoreError> {
        if expected != Some(self.commitment.as_slice()) {
            return Err(denied("secret authority snapshot commitment mismatch"));
        }
        Ok(())
    }

    fn value_commitment(
        &self,
        operation: Uuid,
        expected_epoch: i64,
        value: &str,
    ) -> Result<[u8; 32], StoreError> {
        let key = Zeroizing::new(blake3::derive_key(
            "crawlx/registration-value-key/v1",
            self.binding_salt.as_bytes(),
        ));
        let mut hash = blake3::Hasher::new_keyed(&key);
        hash.update(self.snapshot.version.tenant.0.as_bytes());
        hash.update(self.snapshot.version.run.0.as_bytes());
        hash.update(self.snapshot.version.incarnation.as_bytes());
        hash.update(operation.as_bytes());
        hash.update(&expected_epoch.to_be_bytes());
        hash.update(
            &u64::try_from(value.len())
                .map_err(|_| denied("secret value length overflow"))?
                .to_be_bytes(),
        );
        hash.update(value.as_bytes());
        Ok(*hash.finalize().as_bytes())
    }
}

fn denied(message: &'static str) -> StoreError {
    StoreError::Conflict(message.into())
}

fn random_uuid() -> Result<Uuid, StoreError> {
    // Authority salts and incarnations need full OS entropy, not timestamp IDs.
    let mut bytes = [0; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| denied("secret authority cryptographic entropy unavailable"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(Uuid::from_bytes(bytes))
}

fn scope(tenant: TenantId) -> Result<(), StoreError> {
    if crate::tenant::current().is_some_and(|current| current != tenant) {
        return Err(StoreError::AccessDenied(
            "secret authority tenant mismatch".into(),
        ));
    }
    Ok(())
}

fn check_version(lease: &CustodyLease, expected: SecretEpoch, row: &AuthorityRow) -> Result<(), StoreError> {
    if expected.tenant != lease.tenant
        || expected.run != lease.run
        || expected.incarnation != row.incarnation
        || expected.epoch < 1
        || expected.epoch >= MAX_EPOCH
    {
        return Err(denied("secret authority scope or incarnation mismatch"));
    }
    Ok(())
}

async fn run_lock(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
    exclusive: bool,
) -> Result<(), StoreError> {
    scope(tenant)?;
    let sql = if exclusive {
        "SELECT pg_advisory_xact_lock(hashtextextended('crawlx/secret-authority/v1:' || $1::uuid::text || ':' || $2::uuid::text,0))"
    } else {
        "SELECT pg_advisory_xact_lock_shared(hashtextextended('crawlx/secret-authority/v1:' || $1::uuid::text || ':' || $2::uuid::text,0))"
    };
    sqlx::query(sql)
        .bind(tenant.0)
        .bind(run.0)
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    Ok(())
}

// Cancellation is a local veto, never remote rollback. A dropped command may
// already be queued; mutating remote callers must preserve their pending barrier.
async fn locally_live<T>(
    lease: &CustodyLease,
    operation: impl Future<Output = Result<T, StoreError>>,
) -> Result<T, StoreError> {
    lease.check_local_cancellation()?;
    let result = tokio::select! {
        biased;
        () = lease.cancelled() => Err(StoreError::LeaseLost),
        result = operation => result,
    };
    lease.check_local_cancellation()?;
    result
}

async fn live(tx: &mut Transaction<'_, Postgres>, lease: &CustodyLease) -> Result<(), StoreError> {
    locally_live(lease, live_locked(tx, lease)).await
}

async fn live_locked(tx: &mut Transaction<'_, Postgres>, lease: &CustodyLease) -> Result<(), StoreError> {
    run_lock(tx, lease.tenant, lease.run, false).await?;
    if lease.fence <= 0 {
        return Err(StoreError::LeaseLost);
    }
    let owner: Option<Uuid> =
        sqlx::query_scalar("SELECT run_id FROM crawl_runs WHERE run_id=$1 AND tenant_id=$2 FOR SHARE")
            .bind(lease.run.0)
            .bind(lease.tenant.0)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?;
    if owner.is_none() {
        return Err(StoreError::LeaseLost);
    }
    let query = match lease.source {
        CustodySource::Session(id) => sqlx::query_scalar::<_, Option<Timestamp>>(
            "SELECT lease_expires_at FROM crawl_sessions WHERE session_id=$1 AND run_id=$2 AND lease_owner=$3 AND fencing_token=$4 AND status IN ('running','recovering') FOR SHARE",
        ).bind(id.0),
        CustodySource::Url(id) => sqlx::query_scalar::<_, Option<Timestamp>>(
            "SELECT lease_expires_at FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND lease_owner=$3 AND fencing_token=$4 AND status='leased' FOR SHARE",
        ).bind(id),
        CustodySource::AuthenticatedProducer(id) => sqlx::query_scalar::<_, Option<Timestamp>>(
            "SELECT LEAST(p.expires_at,k.expires_at) FROM run_custody_producers p JOIN api_keys k ON k.key_id=p.api_key_id AND k.tenant_id=p.tenant_id WHERE p.producer_id=$1 AND p.run_id=$2 AND p.owner=$3 AND p.fence=$4 AND k.revoked_at IS NULL FOR SHARE OF p,k",
        ).bind(id),
        // archive_exports has no owner column: the catalog fences writers by export and fence
        // alone (`archive_catalog::writer`), so the worker bind ($3) is only typed, not compared.
        // The export row's tenant is bound to the run by its foreign key, and `live_locked`
        // has already verified that run belongs to `lease.tenant`.
        CustodySource::ArchiveExport(id) => sqlx::query_scalar::<_, Option<Timestamp>>(
            "SELECT lease_until FROM archive_exports WHERE export_id=$1 AND run_id=$2 AND $3::uuid IS NOT NULL AND fence=$4 AND state='recording' AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE",
        ).bind(id),
        CustodySource::Bootstrap(id) => sqlx::query_scalar::<_, Option<Timestamp>>(
            "SELECT p.expires_at FROM run_bootstrap_producers p JOIN workers w ON w.worker_id=p.owner WHERE p.producer_id=$1 AND p.run_id=$2 AND p.owner=$3 AND p.fence=$4 AND p.state='running' AND NOT w.draining FOR SHARE OF p,w",
        ).bind(id),
        _ => return Err(StoreError::Unavailable("unsupported custody producer authority".into())),
    };
    let expiry = query
        .bind(lease.run.0)
        .bind(lease.worker.0)
        .bind(lease.fence)
        .fetch_optional(&mut **tx)
        .await
        .map_err(db)?
        .flatten()
        .ok_or(StoreError::LeaseLost)?;
    let _: Option<Uuid> = sqlx::query_scalar(
        "SELECT a.record_id FROM authorization_records a JOIN crawl_runs r ON a.record_id=r.authorization_record_id WHERE r.run_id=$1 FOR SHARE OF a",
    ).bind(lease.run.0).fetch_optional(&mut **tx).await.map_err(db)?;
    let now = database_now(tx).await?;
    if expiry <= now {
        return Err(StoreError::LeaseLost);
    }
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM crawl_runs r WHERE r.run_id=$1 AND r.tenant_id=$2 \
         AND r.status IN ('queued','running') AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
         AND (r.expires_at IS NULL OR r.expires_at>$3) \
         AND (r.deadline_at IS NULL OR r.deadline_at>$3) \
         AND (r.authorization_record_id IS NULL OR EXISTS(SELECT 1 FROM authorization_records a \
             WHERE a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id \
               AND a.revoked_at IS NULL AND a.valid_from<=$3 AND a.valid_to>$3 \
               AND (r.authorization_body_digest IS NULL OR r.authorization_body_digest=a.body_digest))))",
    ).bind(lease.run.0).bind(lease.tenant.0).bind(now).fetch_one(&mut **tx).await.map_err(db)?;
    if !valid {
        return Err(StoreError::LeaseLost);
    }
    Ok(())
}

async fn locked(
    tx: &mut Transaction<'_, Postgres>,
    lease: &CustodyLease,
) -> Result<AuthorityRow, StoreError> {
    live(tx, lease).await?;
    let row = tokio::select! {
        biased;
        () = lease.cancelled() => return Err(StoreError::LeaseLost),
        result = sqlx::query("SELECT incarnation,epoch,COALESCE(pending_operation,pending_renewal_operation) AS pending_operation,last_operation,commitment,pending_commitment,pending_value_commitment,last_value_commitment,GREATEST(expires_at,pending_renewal_deadline) AS expires_at,sealed_at FROM run_secret_authority WHERE tenant_id=$1 AND run_id=$2 AND GREATEST(expires_at,pending_renewal_deadline)>clock_timestamp() AND sealed_at IS NULL FOR UPDATE")
            .bind(lease.tenant.0).bind(lease.run.0).fetch_optional(&mut **tx) => result.map_err(db)?,
    }.ok_or_else(|| denied(AUTHORITY_MISSING))?;
    lease.check_local_cancellation()?;
    AuthorityRow::parse(lease.tenant, lease.run, &row)
}

async fn read_locked(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(AuthorityRow, String), StoreError> {
    scope(tenant)?;
    run_lock(tx, tenant, run, false).await?;
    let status: Option<String> = sqlx::query_scalar(
        "SELECT status::text FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2 \
         AND purge_requested_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE",
    )
    .bind(tenant.0)
    .bind(run.0)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?;
    let status = status.ok_or_else(|| denied("artifact run authority unavailable"))?;
    let row = sqlx::query("SELECT incarnation,epoch,COALESCE(pending_operation,pending_renewal_operation) AS pending_operation,last_operation,commitment,pending_commitment,pending_value_commitment,last_value_commitment,GREATEST(expires_at,pending_renewal_deadline) AS expires_at,sealed_at FROM run_secret_authority WHERE tenant_id=$1 AND run_id=$2 FOR UPDATE")
        .bind(tenant.0).bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?
        .ok_or_else(|| denied("artifact secret authority missing"))?;
    Ok((AuthorityRow::parse(tenant, run, &row)?, status))
}

async fn no_exposures(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(), StoreError> {
    let open: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM run_artifact_exposures WHERE tenant_id=$1 AND run_id=$2 AND closed_at IS NULL)")
        .bind(tenant.0).bind(run.0).fetch_one(&mut **tx).await.map_err(db)?;
    if open {
        return Err(denied(
            "artifact exposure remains open; producer quiescence required",
        ));
    }
    Ok(())
}

impl PgSecretAuthority {
    /// Open a dedicated nonpersistent Redis authority. There is no local fallback.
    ///
    /// # Errors
    /// Rejects invalid TTL, inaccessible Redis or nonvolatile/replicated configuration.
    pub async fn open(pg: Pg, url: &str, ttl: Duration) -> Result<Self, StoreError> {
        if ttl.as_millis() <= 2000 || ttl > MAX_AUTHORITY_TTL {
            return Err(denied(
                "secret authority TTL must exceed two seconds and be at most 24 hours",
            ));
        }
        let client =
            redis::Client::open(url).map_err(|_| denied("invalid secret authority Redis configuration"))?;
        let config = redis::AsyncConnectionConfig::new()
            .set_connection_timeout(Duration::from_secs(10))
            .set_response_timeout(Duration::from_secs(30));
        let connection = client
            .get_multiplexed_async_connection_with_config(&config)
            .await
            .map_err(|_| denied("secret authority Redis connection unavailable"))?;
        let authority = Self {
            pg,
            connection: Some(connection),
            ttl,
        };
        authority.validate_volatile().await?;
        authority.validate_clock().await?;
        Ok(authority)
    }

    /// Open only durable, finalized reads without Redis. Live runs, secret
    /// registration, initialization and publication remain explicitly unavailable.
    #[must_use]
    pub fn finalized_reads(pg: Pg) -> Self {
        Self {
            pg,
            connection: None,
            ttl: Duration::ZERO,
        }
    }

    fn connection(&self) -> Result<redis::aio::MultiplexedConnection, StoreError> {
        self.connection.clone().ok_or_else(|| {
            StoreError::Unavailable("live secret authority unavailable in finalized-read mode".into())
        })
    }

    async fn transaction(&self) -> Result<Transaction<'static, Postgres>, StoreError> {
        let mut tx = self.pg.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT set_config('lock_timeout','10s',true),set_config('statement_timeout','30s',true),set_config('idle_in_transaction_session_timeout','90s',true)")
            .execute(&mut *tx).await.map_err(db)?;
        Ok(tx)
    }

    async fn validate_volatile(&self) -> Result<(), StoreError> {
        let mut connection = self.connection()?;
        let (config, replication, persistence, _expiry_probe): (
            BTreeMap<String, String>,
            String,
            String,
            i64,
        ) = redis::pipe()
            .cmd("CONFIG")
            .arg("GET")
            .arg(&["appendonly", "save", "maxmemory-policy", "maxmemory"])
            .cmd("INFO")
            .arg("replication")
            .cmd("INFO")
            .arg("persistence")
            // Redis 7+ absolute-expiry introspection is required for recovery.
            .cmd("PEXPIRETIME")
            .arg("crawlx:secrets:capability-probe:missing")
            .query_async(&mut connection)
            .await
            .map_err(|_| denied("secret authority Redis volatility unavailable"))?;
        fn info<'a>(body: &'a str, key: &str) -> Option<&'a str> {
            body.lines().find_map(|line| {
                line.trim_end_matches('\r')
                    .split_once(':')
                    .filter(|(name, _)| *name == key)
                    .map(|(_, value)| value)
            })
        }
        if config.get("appendonly").map(String::as_str) != Some("no")
            || config.get("save").map(String::as_str) != Some("")
            || config.get("maxmemory-policy").map(String::as_str) != Some("noeviction")
            || config
                .get("maxmemory")
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|value| value == 0)
            || info(&replication, "role") != Some("master")
            || info(&replication, "connected_slaves") != Some("0")
            || info(&persistence, "aof_enabled") != Some("0")
            || info(&persistence, "rdb_bgsave_in_progress") != Some("0")
        {
            return Err(denied(
                "secret authority requires disabled RDB/AOF, no replicas and noeviction",
            ));
        }
        Ok(())
    }

    async fn validate_clock(&self) -> Result<(), StoreError> {
        let before: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut connection = self.connection()?;
        let (seconds, micros): (i64, i64) = redis::cmd("TIME")
            .query_async(&mut connection)
            .await
            .map_err(|_| denied("secret authority Redis clock unavailable"))?;
        let after: Timestamp = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&self.pg.pool)
            .await
            .map_err(db)?;
        let redis_ms = seconds
            .checked_mul(1000)
            .and_then(|value| value.checked_add(micros / 1000))
            .ok_or_else(|| denied("secret authority Redis clock overflow"))?;
        let low = after
            .timestamp_millis()
            .checked_sub(MAX_CLOCK_SKEW_MS)
            .ok_or_else(|| denied("secret authority clock overflow"))?;
        let high = before
            .timestamp_millis()
            .checked_add(MAX_CLOCK_SKEW_MS)
            .ok_or_else(|| denied("secret authority clock overflow"))?;
        if after < before || redis_ms < low || redis_ms > high {
            return Err(denied("secret authority clocks exceed supported one-second skew"));
        }
        Ok(())
    }

    async fn invoke(
        &self,
        row: &AuthorityRow,
        action: &str,
        expected: i64,
        operation: Uuid,
        value: &str,
        ttl_ms: i64,
    ) -> Result<VolatileSnapshot, StoreError> {
        self.validate_volatile().await?;
        let mut connection = self.connection()?;
        let response: Vec<String> = redis::Script::new(SCRIPT)
            .key(format!("crawlx:secrets:{{{}:{}}}", row.tenant, row.run))
            .arg(action)
            .arg(row.incarnation.to_string())
            .arg(expected)
            .arg(operation.to_string())
            // A prospective value is hashed locally during snapshot preparation;
            // only registration sends it to Redis, after the pending barrier.
            .arg(if matches!(action, "register" | "prepare" | "renew_recover") {
                value
            } else {
                ""
            })
            .arg(ttl_ms)
            .arg(if action == "init" {
                random_uuid()?.to_string()
            } else {
                String::new()
            })
            .invoke_async(&mut connection)
            .await
            // Neither a transport error nor cancellation proves a remote write failed.
            // Never include Redis response details, which can contain secret material.
            .map_err(|_| denied(OUTCOME_UNKNOWN))?;
        let mut response = Zeroizing::new(response);
        if response.first().map(String::as_str) != Some("ok")
            || response.len() < 3
            || response.len() > MAX_VALUES + 3
        {
            return Err(denied(
                "secret authority volatile state missing, changed or corrupt",
            ));
        }
        let epoch = response[1]
            .parse::<i64>()
            .map_err(|_| denied("secret authority epoch corrupt"))?;
        if !(1..=MAX_EPOCH).contains(&epoch) {
            return Err(denied("secret authority epoch out of bounds"));
        }
        if response[2].len() != 36 {
            return Err(denied("secret authority volatile salt corrupt"));
        }
        let mut hasher = blake3::Hasher::new_derive_key("crawlx/run-secret-snapshot/v1");
        hasher.update(response[2].as_bytes());
        let mut total = 0usize;
        for known in response.iter().skip(3) {
            total = total
                .checked_add(known.len())
                .ok_or_else(|| denied("secret authority byte bound exceeded"))?;
            if known.is_empty() || known.len() > MAX_SECRET_BYTES || total > MAX_TOTAL_BYTES {
                return Err(denied("secret authority secret bound exceeded"));
            }
            hasher.update(
                &u64::try_from(known.len())
                    .map_err(|_| denied("secret authority size overflow"))?
                    .to_be_bytes(),
            );
            hasher.update(known.as_bytes());
        }
        let commitment = *hasher.finalize().as_bytes();
        if matches!(action, "snapshot" | "prepare")
            && !value.is_empty()
            && !response.iter().skip(3).any(|known| known == value)
        {
            if response.len() >= MAX_VALUES + 3
                || total
                    .checked_add(value.len())
                    .is_none_or(|size| size > MAX_TOTAL_BYTES)
            {
                return Err(denied("secret authority secret bound exceeded"));
            }
            hasher.update(
                &u64::try_from(value.len())
                    .map_err(|_| denied("secret authority size overflow"))?
                    .to_be_bytes(),
            );
            hasher.update(value.as_bytes());
        }
        let proposed = *hasher.finalize().as_bytes();
        let binding_salt = Zeroizing::new(std::mem::take(&mut response[2]));
        let secrets = CaptchaSecrets::default();
        for value in response.drain(3..) {
            secrets
                .register(SecretOr::secret(value))
                .map_err(|_| denied("secret authority snapshot unavailable"))?;
        }
        Ok(VolatileSnapshot {
            snapshot: RunSecretSnapshot::new(
                SecretEpoch::new(row.tenant, row.run, row.incarnation, epoch),
                secrets,
            ),
            commitment,
            proposed,
            binding_salt,
        })
    }

    /// Create once or recover incomplete initialization under an existing session fence.
    /// All existing request credentials must be registered before content acquisition.
    ///
    /// # Errors
    /// Rejects stale fences, expired/lost registries and unresolved registrations.
    async fn initialize_run(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        scope(lease.tenant)?;
        lease.check_local_cancellation()?;
        self.validate_volatile().await?;
        self.validate_clock().await?;
        let mut tx = self.transaction().await?;
        tokio::select! {
            biased;
            () = lease.cancelled() => return Err(StoreError::LeaseLost),
            result = run_lock(&mut tx, lease.tenant, lease.run, true) => result?,
        }
        live(&mut tx, lease).await?;
        let incarnation = random_uuid()?;
        let ttl_ms =
            i64::try_from(self.ttl.as_millis()).map_err(|_| denied("secret authority TTL overflow"))?;
        sqlx::query("INSERT INTO run_secret_authority(tenant_id,run_id,incarnation,epoch,pending_operation,expires_at) SELECT $1,$2,$3,0,$3,LEAST(clock_timestamp()+($4::bigint * interval '1 millisecond'),r.expires_at,r.deadline_at,a.valid_to) FROM crawl_runs r LEFT JOIN authorization_records a ON a.record_id=r.authorization_record_id WHERE r.tenant_id=$1 AND r.run_id=$2 ON CONFLICT(tenant_id,run_id) DO NOTHING")
            .bind(lease.tenant.0).bind(lease.run.0).bind(incarnation).bind(ttl_ms).execute(&mut *tx).await.map_err(db)?;
        let row = locked(&mut tx, lease).await?;
        tx.commit().await.map_err(db)?;
        lease.check_local_cancellation()?;
        if row.epoch > 0 {
            return self.snapshot(lease).await;
        }
        if row.pending != Some(row.incarnation) {
            return Err(denied("secret authority initialization corrupt"));
        }
        // Absolute expiry cannot be extended by a delayed command. The early
        // margin covers the explicitly supported maximum clock skew.
        let deadline = row
            .expires_at
            .timestamp_millis()
            .checked_sub(EXPIRY_MARGIN_MS)
            .ok_or_else(|| denied("secret authority expiry overflow"))?;
        let snapshot =
            locally_live(lease, self.invoke(&row, "init", 0, row.incarnation, "", deadline)).await?;
        self.finish(lease, &row, row.incarnation, 1, snapshot.commitment, None)
            .await?;
        lease.check_local_cancellation()?;
        Ok(snapshot.snapshot)
    }

    async fn finish(
        &self,
        lease: &CustodyLease,
        original: &AuthorityRow,
        operation: Uuid,
        epoch: i64,
        commitment: [u8; 32],
        value_commitment: Option<[u8; 32]>,
    ) -> Result<(), StoreError> {
        let mut tx = self.transaction().await?;
        let row = locked(&mut tx, lease).await?;
        if row.incarnation != original.incarnation {
            return Err(denied("secret authority incarnation changed"));
        }
        if row.pending == Some(operation) && row.epoch.checked_add(1) == Some(epoch) {
            if row.epoch != 0
                && (row.pending_commitment.as_deref() != Some(commitment.as_slice())
                    || row.pending_value_commitment.as_deref()
                        != value_commitment.as_ref().map(|value| value.as_slice())
                    || value_commitment.is_none())
            {
                return Err(denied(
                    "secret authority pending set or exact value commitment mismatch",
                ));
            }
            sqlx::query("UPDATE run_secret_authority SET epoch=$3,pending_operation=NULL,last_operation=$4,commitment=$5,pending_commitment=NULL,pending_value_commitment=NULL,last_value_commitment=$6 WHERE tenant_id=$1 AND run_id=$2")
                .bind(lease.tenant.0).bind(lease.run.0).bind(epoch).bind(operation).bind(commitment.as_slice())
                .bind(value_commitment.as_ref().map(|value| value.as_slice())).execute(&mut *tx).await.map_err(db)?;
        } else if row.pending.is_some()
            || row.epoch != epoch
            || row.last != Some(operation)
            || row.commitment.as_deref() != Some(commitment.as_slice())
            || row.last_value_commitment.as_deref() != value_commitment.as_ref().map(|value| value.as_slice())
        {
            return Err(denied("secret authority recovery operation changed"));
        }
        live(&mut tx, lease).await?;
        if row.expires_at <= database_now(&mut tx).await? {
            return Err(denied("secret authority expired during registration"));
        }
        lease.check_local_cancellation()?;
        tx.commit().await.map_err(db)?;
        lease.check_local_cancellation()?;
        Ok(())
    }

    /// Atomically publish ciphertext catalog identity, epoch and durable KMS custody.
    /// The caller must scan/decrypt the complete object against `expected` first.
    /// Object upload must finish before this call; unknown outcomes never authorize
    /// plaintext reads or a new publication under a different artifact identity.
    ///
    /// # Errors
    /// Rejects stale epochs/fences, pending registration, lost Redis, secret-bearing
    /// metadata, invalid envelopes and conflicting artifact identities.
    pub async fn publish(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        artifact: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        scope(lease.tenant)?;
        lease.check_local_cancellation()?;
        if artifact.tenant != lease.tenant || artifact.run != lease.run {
            return Err(denied("artifact publication scope mismatch"));
        }
        if artifact.kind.is_empty()
            || artifact.kind.len() > 128
            || artifact.bucket.len() > 1024
            || artifact.object_key.len() > 4096
            || artifact.content_type.len() > 1024
        {
            return Err(denied("artifact publication metadata bound exceeded"));
        }
        let _validated_ciphertext = CiphertextIdentity::new(ciphertext.digest, ciphertext.size_bytes)?;
        if artifact.object_key
            != encrypted_object_key(artifact.tenant, artifact.run, artifact.id, ciphertext.digest)
        {
            return Err(denied(
                "artifact ciphertext key must bind unique artifact identity",
            ));
        }
        envelope.validate(lease.tenant, lease.run, artifact.id)?;
        let row_json =
            serde_json::to_value(artifact).map_err(|_| denied("artifact publication metadata invalid"))?;
        let envelope_json =
            serde_json::to_value(envelope).map_err(|_| denied("artifact key custody metadata invalid"))?;
        let mut tx = self.transaction().await?;
        let row = locked(&mut tx, lease).await?;
        check_version(lease, expected, &row)?;
        let retained: bool = sqlx::query_scalar(
            "SELECT retention_mode<>'zdr' FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2",
        )
        .bind(lease.tenant.0)
        .bind(lease.run.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if !retained {
            return Err(StoreError::RetentionDenied(
                "zdr cannot publish retained artifact custody".into(),
            ));
        }
        if row.pending.is_some() || row.epoch != expected.epoch {
            return Err(denied(PUBLISH_STALE));
        }
        let snapshot = locally_live(
            lease,
            self.invoke(&row, "snapshot", row.epoch, Uuid::nil(), "", 0),
        )
        .await?;
        snapshot.check(row.commitment.as_deref())?;
        drop(
            crawlx_core::secret::Redactor::new()
                .verify_binary(&envelope.wrapped_key)
                .map_err(|_| denied("artifact wrapped key contains unapproved secret bytes"))?,
        );
        if snapshot
            .snapshot
            .secrets
            .contains_bytes(&envelope.wrapped_key)
            .map_err(|_| denied("artifact wrapped-key secret check unavailable"))?
        {
            return Err(denied("artifact wrapped key contains scoped secret"));
        }
        for metadata in [&row_json, &envelope_json] {
            let bytes =
                serde_json::to_vec(metadata).map_err(|_| denied("artifact publication metadata invalid"))?;
            if snapshot
                .snapshot
                .secrets
                .contains_bytes(&bytes)
                .map_err(|_| denied("artifact publication secret check unavailable"))?
            {
                return Err(denied("artifact publication metadata contains scoped secret"));
            }
        }
        // Idempotent retry after an unknown COMMIT must match every immutable field.
        let existing = sqlx::query("SELECT artifact_payload,envelope,incarnation,secret_epoch,ciphertext_digest,ciphertext_size,object_key FROM artifact_key_custody WHERE tenant_id=$1 AND run_id=$2 AND artifact_id=$3")
            .bind(lease.tenant.0).bind(lease.run.0).bind(artifact.id.0).fetch_optional(&mut *tx).await.map_err(db)?;
        lease.check_local_cancellation()?;
        if let Some(existing) = existing {
            if get::<serde_json::Value>(&existing, "artifact_payload")? != row_json
                || get::<serde_json::Value>(&existing, "envelope")? != envelope_json
                || get::<Uuid>(&existing, "incarnation")? != expected.incarnation
                || get::<i64>(&existing, "secret_epoch")? > expected.epoch
                || get::<Vec<u8>>(&existing, "ciphertext_digest")?.as_slice()
                    != ciphertext.digest.0.as_slice()
                || u64::try_from(get::<i64>(&existing, "ciphertext_size")?)
                    .map_err(|_| denied("negative ciphertext length"))?
                    != ciphertext.size_bytes
                || get::<String>(&existing, "object_key")? != artifact.object_key
            {
                return Err(denied("artifact publication retry changed immutable custody"));
            }
            // Calling publish at a later epoch asserts a complete rescan of the
            // same immutable ciphertext against that newer complete snapshot.
            sqlx::query("UPDATE artifact_key_custody SET secret_epoch=$4 WHERE tenant_id=$1 AND run_id=$2 AND artifact_id=$3")
                .bind(lease.tenant.0).bind(lease.run.0).bind(artifact.id.0).bind(expected.epoch)
                .execute(&mut *tx).await.map_err(db)?;
        } else {
            sqlx::query("INSERT INTO artifacts(artifact_id,tenant_id,run_id,kind,bucket,object_key,size_bytes,content_digest,content_type,sensitivity,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::sensitivity_class,$11,$12)")
                .bind(artifact.id.0).bind(artifact.tenant.0).bind(artifact.run.0).bind(&artifact.kind).bind(&artifact.bucket)
                .bind(&artifact.object_key).bind(i64::try_from(artifact.size_bytes).map_err(|_| denied("artifact plaintext size overflow"))?)
                .bind(artifact.digest.0.as_slice()).bind(&artifact.content_type).bind(artifact.sensitivity.as_str())
                .bind(artifact.created_at).bind(artifact.expires_at).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("INSERT INTO artifact_key_custody(artifact_id,tenant_id,run_id,incarnation,secret_epoch,object_key,plaintext_digest,plaintext_size,ciphertext_digest,ciphertext_size,envelope,artifact_payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
                .bind(artifact.id.0).bind(lease.tenant.0).bind(lease.run.0).bind(expected.incarnation).bind(expected.epoch)
                .bind(&artifact.object_key).bind(artifact.digest.0.as_slice())
                .bind(i64::try_from(artifact.size_bytes).map_err(|_| denied("artifact plaintext size overflow"))?)
                .bind(ciphertext.digest.0.as_slice()).bind(i64::try_from(ciphertext.size_bytes).map_err(|_| denied("artifact ciphertext size overflow"))?)
                .bind(envelope_json).bind(row_json).bind(artifact.created_at).execute(&mut *tx).await.map_err(db)?;
        }
        live(&mut tx, lease).await?;
        if row.expires_at <= database_now(&mut tx).await? {
            return Err(denied("secret authority expired during publication"));
        }
        lease.check_local_cancellation()?;
        tx.commit().await.map_err(db)?;
        lease.check_local_cancellation()?;
        Ok(())
    }

    /// Read durable wrapped-key custody, bound to the exact ciphertext catalog row.
    /// This is cryptographic key access, not plaintext disclosure approval. Callers
    /// must also authorize the user and obtain [`RunSecretAuthority::read_state`].
    /// Only finalized runs can outlive the volatile secret authority safely.
    ///
    /// # Errors
    /// Rejects cross-tenant, deleted/expired, missing or inconsistent custody.
    pub async fn read_custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<ArtifactKeyCustody, StoreError> {
        let row = custody_row(&self.pg.pool, tenant, run, id).await?;
        let envelope: ArtifactKeyEnvelope = serde_json::from_value(get(&row, "envelope")?)
            .map_err(|_| denied("artifact key custody corrupt"))?;
        envelope.validate(tenant, run, id)?;
        let digest: Vec<u8> = get(&row, "ciphertext_digest")?;
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| denied("artifact ciphertext digest corrupt"))?;
        let size = u64::try_from(get::<i64>(&row, "ciphertext_size")?)
            .map_err(|_| denied("artifact ciphertext length corrupt"))?;
        Ok(ArtifactKeyCustody {
            envelope,
            ciphertext: CiphertextIdentity::new(Digest(digest), size)?,
        })
    }

    /// Tombstone a published artifact's catalog row (`deleted_at`), the same semantics as the
    /// store's other deletes: the custody row stays but is no longer readable
    /// ([`CUSTODY_ROW_QUERY`] requires a live catalog row). Idempotent.
    ///
    /// # Errors
    /// Returns tenant scope or database errors; any error leaves withdrawal unconfirmed.
    pub(crate) async fn withdraw_published(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        sqlx::query(
            "UPDATE artifacts SET deleted_at=clock_timestamp() WHERE artifact_id=$1 AND tenant_id=$2 AND run_id=$3 AND deleted_at IS NULL",
        )
        .bind(id.0)
        .bind(tenant.0)
        .bind(run.0)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(())
    }

    /// Like [`Self::read_custody`], but `Ok(None)` when the artifact has no encrypted
    /// custody row (a legacy plaintext artifact). An existing custody row that is
    /// inconsistent with its catalog row is an error, never a plaintext fallback.
    ///
    /// # Errors
    /// Rejects cross-tenant scope, deleted/expired artifacts with custody and corrupt rows.
    pub(crate) async fn try_read_custody(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        id: ArtifactId,
    ) -> Result<Option<ArtifactKeyCustody>, StoreError> {
        scope(tenant)?;
        let sealed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM artifact_key_custody WHERE tenant_id=$1 AND run_id=$2 AND artifact_id=$3)",
        )
        .bind(tenant.0)
        .bind(run.0)
        .bind(id.0)
        .fetch_one(&self.pg.pool)
        .await
        .map_err(db)?;
        if !sealed {
            return Ok(None);
        }
        self.read_custody(tenant, run, id).await.map(Some)
    }

    /// Current committed snapshot, initializing the run authority under the lease when
    /// none exists yet or a half-finished initialization remains. Idempotent across workers.
    ///
    /// # Errors
    /// Same as [`RunSecretAuthority::snapshot`] and the initialization path.
    pub(crate) async fn snapshot_or_initialize(
        &self,
        lease: &CustodyLease,
    ) -> Result<RunSecretSnapshot, StoreError> {
        match RunSecretAuthority::snapshot(self, lease).await {
            Err(StoreError::Conflict(detail))
                if detail == AUTHORITY_MISSING || detail == SNAPSHOT_PENDING =>
            {
                self.initialize_run(lease).await
            }
            other => other,
        }
    }

    /// Permanently close a terminal run's complete secret epoch before volatile expiry.
    ///
    /// Every live artifact must already have been completely validated/published
    /// at the current epoch. Missing or older custody refuses finalization. A
    /// caller may rescan immutable ciphertext and republish it at a newer epoch
    /// while its session remains live, then stop the run and finalize.
    ///
    /// # Errors
    /// Rejects nonterminal runs, pending writes, lost/expired Redis, stale epochs
    /// and any artifact without matching current-epoch encrypted custody.
    pub async fn finalize(&self, expected: SecretEpoch) -> Result<(), StoreError> {
        scope(expected.tenant)?;
        let mut tx = self.transaction().await?;
        run_lock(&mut tx, expected.tenant, expected.run, true).await?;
        let (row, status) = read_locked(&mut tx, expected.tenant, expected.run).await?;
        no_exposures(&mut tx, expected.tenant, expected.run).await?;
        let retained: bool = sqlx::query_scalar(
            "SELECT retention_mode<>'zdr' FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2",
        )
        .bind(expected.tenant.0)
        .bind(expected.run.0)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if !retained {
            return Err(StoreError::RetentionDenied(
                "zdr cannot finalize retained artifact custody".into(),
            ));
        }
        if !matches!(status.as_str(), "completed" | "failed" | "cancelled")
            || row.incarnation != expected.incarnation
            || row.epoch != expected.epoch
            || row.pending.is_some()
            || row.epoch < 1
        {
            return Err(denied(
                "artifact finalization requires an exact terminal secret epoch",
            ));
        }
        if row.sealed_at.is_some() {
            return Ok(());
        }
        if row.expires_at <= database_now(&mut tx).await? {
            return Err(denied("secret authority expired before finalization"));
        }
        let snapshot = self
            .invoke(&row, "snapshot", row.epoch, Uuid::nil(), "", 0)
            .await?;
        snapshot.check(row.commitment.as_deref())?;
        let incomplete: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM artifacts a LEFT JOIN artifact_key_custody c USING(artifact_id) \
             WHERE a.tenant_id=$1 AND a.run_id=$2 AND a.deleted_at IS NULL \
             AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) \
             AND (c.artifact_id IS NULL OR c.tenant_id<>a.tenant_id OR c.run_id<>a.run_id \
               OR c.incarnation<>$3 OR c.secret_epoch<>$4 OR c.plaintext_digest<>a.content_digest \
               OR c.plaintext_size<>a.size_bytes OR c.object_key<>a.object_key \
               OR c.artifact_payload->>'digest' IS DISTINCT FROM encode(a.content_digest,'hex') \
               OR (c.artifact_payload->>'size_bytes')::bigint IS DISTINCT FROM a.size_bytes \
               OR c.created_at IS DISTINCT FROM a.created_at \
               OR c.artifact_payload->>'object_key' IS DISTINCT FROM a.object_key \
               OR c.artifact_payload->>'bucket' IS DISTINCT FROM a.bucket \
               OR c.artifact_payload->>'kind' IS DISTINCT FROM a.kind \
               OR c.artifact_payload->>'content_type' IS DISTINCT FROM a.content_type \
               OR c.artifact_payload->>'sensitivity' IS DISTINCT FROM a.sensitivity::text))",
        )
        .bind(row.tenant.0)
        .bind(row.run.0)
        .bind(row.incarnation)
        .bind(row.epoch)
        .fetch_one(&mut *tx)
        .await
        .map_err(db)?;
        if incomplete {
            return Err(denied(
                "artifact finalization requires all live ciphertext at final epoch",
            ));
        }
        if row.expires_at <= database_now(&mut tx).await? {
            return Err(denied("secret authority expired during finalization"));
        }
        sqlx::query(
            "UPDATE run_secret_authority SET sealed_at=clock_timestamp() WHERE tenant_id=$1 AND run_id=$2",
        )
        .bind(row.tenant.0)
        .bind(row.run.0)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn read_state_on(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: ArtifactId,
    ) -> Result<ArtifactReadState, StoreError> {
        let (row, status) = read_locked(tx, tenant, run).await?;
        if row.pending.is_some() || row.epoch < 1 {
            return Err(denied("artifact read secret registration pending"));
        }
        let artifact_row = custody_row(&mut **tx, tenant, run, artifact).await?;
        if get::<Uuid>(&artifact_row, "incarnation")? != row.incarnation {
            return Err(denied("artifact incarnation mismatch"));
        }
        let artifact_epoch: i64 = get(&artifact_row, "secret_epoch")?;
        let state = if row.sealed_at.is_some() {
            if artifact_epoch != row.epoch || !matches!(status.as_str(), "completed" | "failed" | "cancelled")
            {
                return Err(denied("artifact finalized custody mismatch"));
            }
            ArtifactReadState::Finalized(SecretEpoch::new(tenant, run, row.incarnation, row.epoch))
        } else {
            if row.expires_at <= database_now(tx).await? {
                return Err(denied("artifact live secret authority expired"));
            }
            let snapshot = self
                .invoke(&row, "snapshot", row.epoch, Uuid::nil(), "", 0)
                .await?;
            snapshot.check(row.commitment.as_deref())?;
            if row.expires_at <= database_now(tx).await? {
                return Err(denied("artifact live secret authority expired"));
            }
            ArtifactReadState::Live(snapshot.snapshot)
        };
        let retained: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM artifacts a JOIN crawl_runs r USING(run_id) \
             WHERE a.artifact_id=$1 AND a.run_id=$2 AND a.tenant_id=$3 AND r.tenant_id=$3 \
             AND a.deleted_at IS NULL AND r.purge_requested_at IS NULL \
             AND (a.expires_at IS NULL OR a.expires_at>clock_timestamp()) \
             AND (r.expires_at IS NULL OR r.expires_at>clock_timestamp()))",
        )
        .bind(artifact.0)
        .bind(run.0)
        .bind(tenant.0)
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
        if !retained {
            return Err(denied("artifact retention ended during read authorization"));
        }
        Ok(state)
    }

    /// Mint a short-lived nonbrowser producer through a trusted authenticated API
    /// adapter. No tenant-only acquisition or plaintext fallback exists.
    ///
    /// # Errors
    /// Rejects failed route authorization, inactive/wrong-tenant API keys, inactive
    /// runs, sealed authority, invalid TTL (1 ms..5 min), and 32 live producers.
    pub async fn acquire_authenticated_producer(
        &self,
        authorization: &dyn ArtifactProducerAuthorizer,
        tenant: TenantId,
        run: CrawlRunId,
        ttl: Duration,
    ) -> Result<CustodyLease, StoreError> {
        scope(tenant)?;
        let ttl_ms = i64::try_from(ttl.as_millis()).map_err(|_| denied("producer TTL overflow"))?;
        if !(1..=300_000).contains(&ttl_ms) {
            return Err(denied(
                "producer TTL must be between one millisecond and five minutes",
            ));
        }
        let key = authorization.authorize(tenant, run).await?;
        let mut tx = self.transaction().await?;
        run_lock(&mut tx, tenant, run, false).await?;
        let active: Option<Uuid> = sqlx::query_scalar("SELECT run_id FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2 AND status IN ('queued','running') AND cancel_requested_at IS NULL AND purge_requested_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR UPDATE")
            .bind(tenant.0).bind(run.0).fetch_optional(&mut *tx).await.map_err(db)?;
        if active.is_none() {
            return Err(StoreError::LeaseLost);
        }
        let valid_key: Option<Uuid> = sqlx::query_scalar("SELECT key_id FROM api_keys WHERE tenant_id=$1 AND key_id=$2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>clock_timestamp()) FOR SHARE")
            .bind(tenant.0).bind(key).fetch_optional(&mut *tx).await.map_err(db)?;
        if valid_key.is_none() {
            return Err(StoreError::AccessDenied(
                "authenticated producer key unavailable".into(),
            ));
        }
        let sealed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM run_secret_authority WHERE tenant_id=$1 AND run_id=$2 AND sealed_at IS NOT NULL)")
            .bind(tenant.0).bind(run.0).fetch_one(&mut *tx).await.map_err(db)?;
        if sealed {
            return Err(denied("authenticated producer authority sealed"));
        }
        sqlx::query("DELETE FROM run_custody_producers p WHERE tenant_id=$1 AND run_id=$2 AND (p.expires_at<=clock_timestamp() OR EXISTS(SELECT 1 FROM api_keys k WHERE k.key_id=p.api_key_id AND (k.revoked_at IS NOT NULL OR k.expires_at<=clock_timestamp())))")
            .bind(tenant.0).bind(run.0).execute(&mut *tx).await.map_err(db)?;
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM run_custody_producers WHERE tenant_id=$1 AND run_id=$2")
                .bind(tenant.0)
                .bind(run.0)
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        if count >= 32 {
            return Err(denied("authenticated producer capacity exceeded"));
        }
        let producer = random_uuid()?;
        let owner = WorkerId(random_uuid()?);
        let fence: i64 = sqlx::query_scalar("INSERT INTO run_custody_producers(tenant_id,run_id,producer_id,owner,api_key_id,expires_at) SELECT $1,$2,$3,$4,$5,LEAST(clock_timestamp()+($6::bigint*interval '1 millisecond'),k.expires_at,r.expires_at) FROM api_keys k JOIN crawl_runs r ON r.run_id=$2 AND r.tenant_id=$1 WHERE k.key_id=$5 AND k.tenant_id=$1 RETURNING fence")
            .bind(tenant.0).bind(run.0).bind(producer).bind(owner.0).bind(key).bind(ttl_ms)
            .fetch_one(&mut *tx).await.map_err(db)?;
        let lease = CustodyLease::for_authenticated_producer(tenant, run, producer, owner, fence);
        live(&mut tx, &lease).await?;
        tx.commit().await.map_err(db)?;
        Ok(lease)
    }

    /// Release exactly the authenticated producer owner/fence after its writes
    /// finish. Expired/revoked leases may clean up metadata; no new work is granted.
    ///
    /// # Errors
    /// Rejects non-API sources, tenant mismatch, changed owner/fence and database
    /// uncertainty. A missing row is an idempotent prior release.
    pub async fn release_authenticated_producer(&self, lease: &CustodyLease) -> Result<(), StoreError> {
        scope(lease.tenant)?;
        lease.check_local_cancellation()?;
        let CustodySource::AuthenticatedProducer(producer) = lease.source else {
            return Err(denied("producer release requires authenticated API source"));
        };
        let mut tx = self.transaction().await?;
        run_lock(&mut tx, lease.tenant, lease.run, false).await?;
        let row = sqlx::query("SELECT owner,fence FROM run_custody_producers WHERE tenant_id=$1 AND run_id=$2 AND producer_id=$3 FOR UPDATE")
            .bind(lease.tenant.0).bind(lease.run.0).bind(producer).fetch_optional(&mut *tx).await.map_err(db)?;
        lease.check_local_cancellation()?;
        if let Some(row) = row {
            if get::<Uuid>(&row, "owner")? != lease.worker.0 || get::<i64>(&row, "fence")? != lease.fence {
                return Err(StoreError::LeaseLost);
            }
            sqlx::query("DELETE FROM run_custody_producers WHERE tenant_id=$1 AND run_id=$2 AND producer_id=$3 AND owner=$4 AND fence=$5")
                .bind(lease.tenant.0).bind(lease.run.0).bind(producer).bind(lease.worker.0).bind(lease.fence)
                .execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        lease.check_local_cancellation()?;
        Ok(())
    }
}

async fn database_now(tx: &mut Transaction<'_, Postgres>) -> Result<Timestamp, StoreError> {
    sqlx::query_scalar("SELECT clock_timestamp()")
        .fetch_one(&mut **tx)
        .await
        .map_err(db)
}

#[async_trait]
impl RunSecretAuthority for PgSecretAuthority {
    async fn initialize(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        self.initialize_run(lease).await
    }

    async fn renew_authority(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        operation: Uuid,
        deadline: Timestamp,
    ) -> Result<RunSecretSnapshot, StoreError> {
        PgSecretAuthority::renew_authority(self, lease, expected, operation, deadline).await
    }

    async fn snapshot(&self, lease: &CustodyLease) -> Result<RunSecretSnapshot, StoreError> {
        scope(lease.tenant)?;
        lease.check_local_cancellation()?;
        let mut tx = self.transaction().await?;
        let row = locked(&mut tx, lease).await?;
        if row.pending.is_some() || row.epoch == 0 {
            return Err(denied(SNAPSHOT_PENDING));
        }
        let snapshot = locally_live(
            lease,
            self.invoke(&row, "snapshot", row.epoch, Uuid::nil(), "", 0),
        )
        .await?;
        snapshot.check(row.commitment.as_deref())?;
        live(&mut tx, lease).await?;
        if row.expires_at <= database_now(&mut tx).await? {
            return Err(denied("secret authority expired during snapshot"));
        }
        lease.check_local_cancellation()?;
        tx.commit().await.map_err(db)?;
        lease.check_local_cancellation()?;
        Ok(snapshot.snapshot)
    }

    async fn read_state(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        artifact: ArtifactId,
    ) -> Result<ArtifactReadState, StoreError> {
        scope(tenant)?;
        let mut tx = self.transaction().await?;
        let state = self.read_state_on(&mut tx, tenant, run, artifact).await?;
        tx.commit().await.map_err(db)?;
        Ok(state)
    }

    async fn register(
        &self,
        lease: &CustodyLease,
        expected: SecretEpoch,
        operation: Uuid,
        value: &SecretOr<String>,
    ) -> Result<RunSecretSnapshot, StoreError> {
        scope(lease.tenant)?;
        lease.check_local_cancellation()?;
        self.validate_clock().await?;
        if operation.is_nil()
            || operation == expected.incarnation
            || value.expose().is_empty()
            || value.expose().len() > MAX_SECRET_BYTES
        {
            return Err(denied("secret registration operation or value out of bounds"));
        }
        let mut tx = self.transaction().await?;
        let mut row = locked(&mut tx, lease).await?;
        check_version(lease, expected, &row)?;
        no_exposures(&mut tx, lease.tenant, lease.run).await?;
        let recovering = row.pending == Some(operation) && row.epoch == expected.epoch;
        let committed = row.pending.is_none()
            && row.last == Some(operation)
            && expected.epoch.checked_add(1) == Some(row.epoch);
        if row.last == Some(operation) && !committed {
            return Err(denied(
                "secret registration operation reused at a different epoch",
            ));
        }
        if !recovering && !committed {
            if row.pending.is_some() || row.epoch != expected.epoch {
                return Err(denied(REGISTER_STALE));
            }
            let prior = locally_live(
                lease,
                self.invoke(&row, "snapshot", row.epoch, Uuid::nil(), value.expose(), 0),
            )
            .await?;
            prior.check(row.commitment.as_deref())?;
            let exact_value = prior.value_commitment(operation, expected.epoch, value.expose())?;
            lease.check_local_cancellation()?;
            sqlx::query("UPDATE run_secret_authority SET pending_operation=$3,pending_commitment=$4,pending_value_commitment=$5 WHERE tenant_id=$1 AND run_id=$2")
                .bind(lease.tenant.0).bind(lease.run.0).bind(operation).bind(prior.proposed.as_slice()).bind(exact_value.as_slice())
                .execute(&mut *tx).await.map_err(db)?;
            row.pending_commitment = Some(prior.proposed.to_vec());
            row.pending_value_commitment = Some(exact_value.to_vec());
        }
        if recovering || committed {
            // Compare the proposed complete registry BEFORE Redis can mutate.
            // A changed retry must not poison an otherwise recoverable operation.
            let prepared = locally_live(
                lease,
                self.invoke(&row, "prepare", expected.epoch, operation, value.expose(), 0),
            )
            .await?;
            let exact_value = prepared.value_commitment(operation, expected.epoch, value.expose())?;
            let expected_value = if committed {
                row.last_value_commitment.as_deref()
            } else {
                row.pending_value_commitment.as_deref()
            };
            if expected_value != Some(exact_value.as_slice()) {
                return Err(denied("secret registration exact recovery value changed"));
            }
            let expected_commitment = if committed {
                row.commitment.as_deref()
            } else {
                row.pending_commitment.as_deref()
            };
            let candidate = if prepared.snapshot.version.epoch == expected.epoch {
                prepared.proposed.as_slice()
            } else {
                prepared.commitment.as_slice()
            };
            if expected_commitment != Some(candidate) {
                return Err(denied("secret registration recovery value changed"));
            }
        }
        // This barrier MUST commit before secret bytes leave this process. If its
        // COMMIT outcome is unknown, do not touch Redis or deliver the secret.
        live(&mut tx, lease).await?;
        if row.expires_at <= database_now(&mut tx).await? {
            return Err(denied("secret authority expired before registration"));
        }
        lease.check_local_cancellation()?;
        tx.commit().await.map_err(db)?;
        lease.check_local_cancellation()?;
        let snapshot = locally_live(
            lease,
            self.invoke(&row, "register", expected.epoch, operation, value.expose(), 0),
        )
        .await?;
        snapshot.check(if committed {
            row.commitment.as_deref()
        } else {
            row.pending_commitment.as_deref()
        })?;
        let exact_value = snapshot.value_commitment(operation, expected.epoch, value.expose())?;
        let expected_value = if committed {
            row.last_value_commitment.as_deref()
        } else {
            row.pending_value_commitment.as_deref()
        };
        if expected_value != Some(exact_value.as_slice()) {
            return Err(denied("secret registration exact value commitment mismatch"));
        }
        self.finish(
            lease,
            &row,
            operation,
            snapshot.snapshot.version.epoch,
            snapshot.commitment,
            Some(exact_value),
        )
        .await?;
        lease.check_local_cancellation()?;
        Ok(snapshot.snapshot)
    }
}
