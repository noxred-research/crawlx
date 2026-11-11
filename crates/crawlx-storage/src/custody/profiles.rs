//! Fenced retained cookie and web-storage custody in the browser_profiles namespace.
//!
//! Each generation uses fresh ArtifactKeys custody. No directory, reusable global
//! profile cipher, plaintext key, partial export or unregistered restore is accepted.

use super::{
    check_version, database_now, denied, get, live, locally_live, locked, no_exposures, random_uuid,
    ArtifactKeyEnvelope, PgSecretAuthority, PUBLISH_STALE,
};
use crate::artifact_crypto::{ArtifactContext, ArtifactDecryption};
use crate::artifact_custody::{crypto_error, key_error};
use crate::artifact_key_crypto::ArtifactKeys;
use crate::codec::{from_json, to_json};
use crate::error::db;
use crate::leases::SessionLease;
use crate::profiles::{ProfileScopeV1, MAX_PROFILE_BYTES};
use crate::session_binding::lock_lease;
use crawlx_core::custody::{CustodyLease, CustodySource, RunSecretAuthority, SecretEpoch};
use crawlx_core::hash::Digest;
use crawlx_core::{ArtifactId, CrawlRunId, SecretOr, StoreError, Timestamp};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use crate::profiles::SupportedStorageState;

const CIPHER_DOMAIN: &str = "crawlx/profile-custody-ciphertext/v1";

/// Secret-free metadata for one exact supported storage-state generation.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct CustodyProfileInspection {
    /// Exact tenant, principal, origin, browser-build and egress scope.
    pub scope: ProfileScopeV1,
    /// Generation explicitly committed or acquired.
    pub generation: u64,
    /// Digest of the complete authenticated ciphertext, never of raw credentials.
    pub digest: Digest,
    /// Fixed approved retention deadline; acquisition never extends it.
    pub expires_at: Timestamp,
}

/// Retained storage-state service sharing the run's real secret authority.
#[non_exhaustive]
pub struct CustodyProfiles<'a> {
    authority: &'a PgSecretAuthority,
    keys: &'a dyn ArtifactKeys,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadHeader {
    version: u32,
    scope: ProfileScopeV1,
    generation: u64,
    expires_at: Timestamp,
    incarnation: Uuid,
    epoch: i64,
}

fn generation(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| denied("profile generation exhausted"))
}

fn identity(lease: &SessionLease, custody: &CustodyLease, scope: &ProfileScopeV1) -> Result<(), StoreError> {
    scope.validate()?;
    custody.check_local_cancellation()?;
    if custody.tenant != scope.tenant
        || custody.run != lease.session.run
        || custody.worker != lease.worker
        || custody.fence != lease.fencing_token
        || custody.source != CustodySource::Session(lease.session.id)
        || scope.principal != lease.session.role
    {
        return Err(denied("profile tenant, principal or producer fence mismatch"));
    }
    Ok(())
}

async fn retention(
    tx: &mut Transaction<'_, Postgres>,
    lease: &CustodyLease,
    expires_at: Timestamp,
) -> Result<(), StoreError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2 \
         AND retention_mode<>'zdr' AND expires_at IS NOT NULL AND expires_at>=$3 \
         AND $3>clock_timestamp())",
    )
    .bind(lease.tenant.0)
    .bind(lease.run.0)
    .bind(expires_at)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !valid {
        return Err(StoreError::RetentionDenied(
            "profile retention denied or expired".into(),
        ));
    }
    Ok(())
}

async fn finish(
    tx: &mut Transaction<'_, Postgres>,
    custody: &CustodyLease,
    profile_expiry: Timestamp,
    authority_expiry: Timestamp,
) -> Result<(), StoreError> {
    live(tx, custody).await?;
    retention(tx, custody, profile_expiry).await?;
    let now = database_now(tx).await?;
    if authority_expiry
        .timestamp_millis()
        .saturating_sub(super::EXPIRY_MARGIN_MS)
        <= now.timestamp_millis()
    {
        return Err(denied("profile secret authority expired before completion"));
    }
    Ok(())
}

async fn compatible_holder(
    tx: &mut Transaction<'_, Postgres>,
    lease: &SessionLease,
    scope: &ProfileScopeV1,
    row: &sqlx::postgres::PgRow,
    committing: bool,
) -> Result<(), StoreError> {
    let stored_scope: ProfileScopeV1 = from_json(get(row, "scope")?)?;
    if stored_scope != *scope {
        return Err(denied("profile origin, browser build or egress scope mismatch"));
    }
    let session: Uuid = get(row, "session_id")?;
    let fence: i64 = get(row, "lease_fence")?;
    if session != lease.session.id.0 || fence != lease.fencing_token {
        let busy: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM crawl_sessions WHERE session_id=$1 \
             AND fencing_token=$2 AND lease_expires_at>clock_timestamp())",
        )
        .bind(session)
        .bind(fence)
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
        if busy {
            return Err(denied("profile lease conflict"));
        }
    }
    if committing || session != lease.session.id.0 {
        let unresolved: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM actions a JOIN crawl_runs r USING(run_id) \
             WHERE r.tenant_id=$1 AND a.session_id IN ($2,$3) AND a.status IN ('intended','unknown'))",
        )
        .bind(scope.tenant.0)
        .bind(session)
        .bind(lease.session.id.0)
        .fetch_one(&mut **tx)
        .await
        .map_err(db)?;
        if unresolved {
            return Err(denied("profile transfer blocked by unresolved write"));
        }
    }
    Ok(())
}

async fn source_retained(
    tx: &mut Transaction<'_, Postgres>,
    scope: &ProfileScopeV1,
    owner: CrawlRunId,
    expiry: Timestamp,
) -> Result<(), StoreError> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM crawl_runs r WHERE r.tenant_id=$1 AND r.run_id=$2 \
         AND r.retention_mode<>'zdr' AND r.status NOT IN ('failed','cancelled') \
         AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
         AND r.expires_at IS NOT NULL AND r.expires_at>=$3 AND $3>clock_timestamp() \
         AND (r.authorization_record_id IS NULL OR EXISTS(SELECT 1 FROM authorization_records a \
           WHERE a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id \
           AND a.revoked_at IS NULL AND a.valid_from<=clock_timestamp() AND a.valid_to>clock_timestamp() \
           AND (r.authorization_body_digest IS NULL OR a.body_digest=r.authorization_body_digest))))",
    )
    .bind(scope.tenant.0)
    .bind(owner.0)
    .bind(expiry)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !valid {
        return Err(denied("retained profile source unavailable or expired"));
    }
    Ok(())
}

impl<'a> CustodyProfiles<'a> {
    /// Use the existing distributed authority and explicitly configured durable keys.
    #[must_use]
    pub fn new(authority: &'a PgSecretAuthority, keys: &'a dyn ArtifactKeys) -> Self {
        Self { authority, keys }
    }

    fn durable_keys(&self) -> Result<(), StoreError> {
        if !self.keys.is_available() || !self.keys.is_durable() {
            return Err(StoreError::Unavailable(
                "durable profile key custody unavailable".into(),
            ));
        }
        Ok(())
    }

    async fn register(
        &self,
        custody: &CustodyLease,
        state: &SupportedStorageState,
    ) -> Result<SecretEpoch, StoreError> {
        let mut snapshot = self.authority.snapshot(custody).await?;
        for value in state.opaque_values() {
            snapshot = self
                .authority
                .register(
                    custody,
                    snapshot.version,
                    random_uuid()?,
                    &SecretOr::secret(value.to_owned()),
                )
                .await?;
        }
        custody.check_local_cancellation()?;
        Ok(snapshot.version)
    }

    async fn epoch(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        custody: &CustodyLease,
        expected: SecretEpoch,
    ) -> Result<Timestamp, StoreError> {
        let row = locked(tx, custody).await?;
        check_version(custody, expected, &row)?;
        if row.pending.is_some() || row.epoch != expected.epoch {
            return Err(denied(PUBLISH_STALE));
        }
        no_exposures(tx, custody.tenant, custody.run).await?;
        let snapshot = locally_live(
            custody,
            self.authority
                .invoke(&row, "snapshot", row.epoch, Uuid::nil(), "", 0),
        )
        .await?;
        snapshot.check(row.commitment.as_deref())?;
        Ok(row.expires_at)
    }

    /// Register and commit a complete strict browser storage export with a fresh wrapped key.
    /// Expected generation zero creates; every later commit requires exact old generation.
    /// The caller must disable capture before obtaining this unredacted export.
    ///
    /// # Errors
    /// Rejects incomplete schemas, missing approval, ZDR, stale fences/epochs, conflicting
    /// holders or generations, expiry, incompatible scopes and unavailable key/registry custody.
    #[allow(
        clippy::too_many_arguments,
        reason = "security approvals, lease and generation stay explicit"
    )]
    pub async fn commit(
        &self,
        lease: &SessionLease,
        custody: &CustodyLease,
        scope: &ProfileScopeV1,
        expected_generation: u64,
        expires_at: Timestamp,
        retained_profile_approved: bool,
        storage: &[u8],
    ) -> Result<CustodyProfileInspection, StoreError> {
        identity(lease, custody, scope)?;
        self.durable_keys()?;
        if !retained_profile_approved {
            return Err(StoreError::RetentionDenied(
                "retained profile approval required".into(),
            ));
        }
        let next = expected_generation
            .checked_add(1)
            .ok_or_else(|| denied("profile generation exhausted"))?;
        let next_sql = generation(next)?;
        let prior_sql = generation(expected_generation)?;
        let state = SupportedStorageState::parse(storage, scope)?;
        // Reject policy before any registration or external key-provider request.
        let mut preflight = self.authority.transaction().await?;
        live(&mut preflight, custody).await?;
        lock_lease(&mut preflight, lease, scope.tenant).await?;
        retention(&mut preflight, custody, expires_at).await?;
        let unresolved: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM actions WHERE run_id=$1 AND session_id=$2 AND status IN ('intended','unknown'))",
        ).bind(custody.run.0).bind(lease.session.id.0)
            .fetch_one(&mut *preflight).await.map_err(db)?;
        if unresolved {
            return Err(denied("profile commit blocked by unresolved write"));
        }
        preflight.commit().await.map_err(db)?;
        let expected = self.register(custody, &state).await?;
        let header = PayloadHeader {
            version: 1,
            scope: scope.clone(),
            generation: next,
            expires_at,
            incarnation: expected.incarnation,
            epoch: expected.epoch,
        };
        let mut payload = Zeroizing::new(
            serde_json::to_vec(&header).map_err(|_| denied("profile metadata serialization failed"))?,
        );
        payload.reserve(state.as_bytes().len().saturating_add(1));
        payload.push(b'\n');
        payload.extend_from_slice(state.as_bytes());
        let size = u64::try_from(payload.len()).map_err(|_| denied("profile size overflow"))?;
        let bound = u64::try_from(MAX_PROFILE_BYTES).map_err(|_| denied("profile size overflow"))?;
        let artifact = ArtifactId(random_uuid()?);
        let context = ArtifactContext::new(scope.tenant, custody.run, artifact);
        let prepared = locally_live(custody, async {
            self.keys.prepare(&context, size, bound).await.map_err(key_error)
        })
        .await?;
        prepared.envelope.validate(scope.tenant, custody.run, artifact)?;
        let ciphertext_size = crate::artifact_crypto::checked_lengths(size, bound).map_err(crypto_error)?;
        let capacity = usize::try_from(ciphertext_size).map_err(|_| denied("profile size overflow"))?;
        let mut ciphertext = Vec::with_capacity(capacity);
        let sealed = locally_live(custody, async {
            prepared
                .encryption
                .seal(payload.as_slice(), &mut ciphertext)
                .await
                .map_err(crypto_error)
        })
        .await?;
        drop(sealed); // The raw single-use key never enters durable metadata.
        let digest = Digest::of(CIPHER_DOMAIN, &ciphertext);
        let mut tx = self.authority.transaction().await?;
        let authority_expiry = self.epoch(&mut tx, custody, expected).await?;
        lock_lease(&mut tx, lease, scope.tenant).await?;
        retention(&mut tx, custody, expires_at).await?;
        let existing = sqlx::query(
            "SELECT * FROM browser_profiles WHERE tenant_id=$1 AND principal=$2 AND name=$3 FOR UPDATE",
        )
        .bind(scope.tenant.0)
        .bind(&scope.principal.0)
        .bind(&scope.name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if let Some(row) = existing {
            if get::<i64>(&row, "generation")? != prior_sql {
                return Err(denied("profile generation conflict"));
            }
            compatible_holder(&mut tx, lease, scope, &row, true).await?;
            let format: i32 = get(&row, "custody_format")?;
            if format != 1 {
                return Err(denied("legacy directory profiles unavailable in custody mode"));
            }
        } else {
            if expected_generation != 0 {
                return Err(denied("profile generation conflict"));
            }
            let unresolved: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM actions WHERE run_id=$1 AND session_id=$2 AND status IN ('intended','unknown'))",
            ).bind(custody.run.0).bind(lease.session.id.0)
                .fetch_one(&mut *tx).await.map_err(db)?;
            if unresolved {
                return Err(denied("profile commit blocked by unresolved write"));
            }
        }
        let result = sqlx::query(
            "INSERT INTO browser_profiles(tenant_id,principal,name,generation,scope,encrypted_bundle,digest,expires_at,owner_run,session_id,lease_fence,custody_format,custody_artifact,custody_envelope,custody_incarnation,custody_epoch) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,1,$12,$13,$14,$15) \
             ON CONFLICT(tenant_id,principal,name) DO UPDATE SET generation=EXCLUDED.generation,scope=EXCLUDED.scope, \
             encrypted_bundle=EXCLUDED.encrypted_bundle,digest=EXCLUDED.digest,expires_at=EXCLUDED.expires_at, \
             owner_run=EXCLUDED.owner_run,session_id=EXCLUDED.session_id,lease_fence=EXCLUDED.lease_fence, \
             custody_format=1,custody_artifact=EXCLUDED.custody_artifact,custody_envelope=EXCLUDED.custody_envelope, \
             custody_incarnation=EXCLUDED.custody_incarnation,custody_epoch=EXCLUDED.custody_epoch \
             WHERE browser_profiles.generation=$16 AND browser_profiles.custody_format=1",
        ).bind(scope.tenant.0).bind(&scope.principal.0).bind(&scope.name).bind(next_sql)
            .bind(to_json(scope)?).bind(&ciphertext).bind(digest.0.as_slice()).bind(expires_at)
            .bind(custody.run.0).bind(lease.session.id.0).bind(lease.fencing_token)
            .bind(artifact.0).bind(to_json(&prepared.envelope)?).bind(expected.incarnation).bind(expected.epoch)
            .bind(prior_sql).execute(&mut *tx).await.map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(denied("profile generation conflict"));
        }
        crate::profiles::audit_profile(&mut tx, lease, scope, "profile.custody.commit", next).await?;
        finish(&mut tx, custody, expires_at, authority_expiry).await?;
        tx.commit().await.map_err(db)?;
        custody.check_local_cancellation()?;
        Ok(CustodyProfileInspection {
            scope: scope.clone(),
            generation: next,
            digest,
            expires_at,
        })
    }

    /// Claim, authenticate and register a retained storage-state generation before import.
    ///
    /// Use only inside a fresh empty tmpfs browser context with the exact origin guard.
    /// No bytes leave this method on partial/unknown registration or a post-registration race.
    /// The source ciphertext keeps its original key context; acquisition never extends expiry.
    /// Only generation zero may return `None` for an absent, fresh namespace.
    /// A requested nonzero generation never silently falls back to empty storage.
    ///
    /// # Errors
    /// Rejects approval/policy failures, old directory bundles, schema/fixity/key failures,
    /// stale leases, incompatible scope/generation, concurrent holders and registry loss.
    pub async fn acquire(
        &self,
        lease: &SessionLease,
        custody: &CustodyLease,
        scope: &ProfileScopeV1,
        generation: u64,
        retained_profile_approved: bool,
    ) -> Result<Option<(CustodyProfileInspection, SupportedStorageState)>, StoreError> {
        identity(lease, custody, scope)?;
        self.durable_keys()?;
        if !retained_profile_approved {
            return Err(StoreError::RetentionDenied(
                "retained profile approval required".into(),
            ));
        }
        let requested = self::generation(generation)?;
        let mut tx = self.authority.transaction().await?;
        live(&mut tx, custody).await?;
        lock_lease(&mut tx, lease, scope.tenant).await?;
        let row = sqlx::query(
            "SELECT * FROM browser_profiles WHERE tenant_id=$1 AND principal=$2 AND name=$3 FOR UPDATE",
        )
        .bind(scope.tenant.0)
        .bind(&scope.principal.0)
        .bind(&scope.name)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let Some(row) = row else {
            // Even an empty namespace cannot bypass the destination retention policy.
            let retained: bool = sqlx::query_scalar("SELECT retention_mode<>'zdr' AND expires_at IS NOT NULL AND expires_at>clock_timestamp() FROM crawl_runs WHERE run_id=$1 AND tenant_id=$2")
                .bind(custody.run.0).bind(scope.tenant.0).fetch_one(&mut *tx).await.map_err(db)?;
            if !retained {
                return Err(StoreError::RetentionDenied(
                    "retained profiles forbidden under zdr".into(),
                ));
            }
            if generation != 0 {
                return Err(denied("requested profile generation unavailable"));
            }
            tx.commit().await.map_err(db)?;
            custody.check_local_cancellation()?;
            return Ok(None);
        };
        if get::<i32>(&row, "custody_format")? != 1 {
            return Err(denied("arbitrary directory profiles unavailable in custody mode"));
        }
        if get::<i64>(&row, "generation")? != requested || generation == 0 {
            return Err(denied("profile generation conflict"));
        }
        compatible_holder(&mut tx, lease, scope, &row, false).await?;
        let expires_at: Timestamp = get(&row, "expires_at")?;
        retention(&mut tx, custody, expires_at).await?;
        let owner = CrawlRunId(get(&row, "owner_run")?);
        source_retained(&mut tx, scope, owner, expires_at).await?;
        let artifact = ArtifactId(get(&row, "custody_artifact")?);
        let envelope: ArtifactKeyEnvelope = from_json(get(&row, "custody_envelope")?)?;
        envelope.validate(scope.tenant, owner, artifact)?;
        let incarnation: Uuid = get(&row, "custody_incarnation")?;
        let epoch: i64 = get(&row, "custody_epoch")?;
        let ciphertext: Vec<u8> = get(&row, "encrypted_bundle")?;
        let stored_digest: Vec<u8> = get(&row, "digest")?;
        let digest = Digest::of(CIPHER_DOMAIN, &ciphertext);
        if stored_digest.as_slice() != digest.0 || ciphertext.len() > crate::profiles::MAX_BUNDLE_BYTES {
            return Err(denied("profile ciphertext fixity mismatch"));
        }
        sqlx::query("UPDATE browser_profiles SET session_id=$4,lease_fence=$5 WHERE tenant_id=$1 AND principal=$2 AND name=$3")
            .bind(scope.tenant.0).bind(&scope.principal.0).bind(&scope.name)
            .bind(lease.session.id.0).bind(lease.fencing_token).execute(&mut *tx).await.map_err(db)?;
        live(&mut tx, custody).await?;
        tx.commit().await.map_err(db)?;
        let context = ArtifactContext::new(scope.tenant, owner, artifact);
        let key = locally_live(custody, async {
            self.keys.open(&context, &envelope).await.map_err(key_error)
        })
        .await?;
        let bound = u64::try_from(MAX_PROFILE_BYTES).map_err(|_| denied("profile size overflow"))?;
        let mut reader = ArtifactDecryption::new(ciphertext.as_slice(), context, key, bound)
            .await
            .map_err(crypto_error)?;
        let mut plaintext = Zeroizing::new(Vec::with_capacity(ciphertext.len().min(MAX_PROFILE_BYTES)));
        while let Some(chunk) =
            locally_live(custody, async { reader.next_chunk().await.map_err(crypto_error) }).await?
        {
            plaintext.extend_from_slice(&chunk);
        }
        if reader.authenticated_len() != u64::try_from(plaintext.len()).ok() {
            return Err(denied("profile ciphertext incomplete"));
        }
        let separator = plaintext
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or_else(|| denied("profile metadata framing invalid"))?;
        let header: PayloadHeader = serde_json::from_slice(&plaintext[..separator])
            .map_err(|_| denied("profile metadata invalid"))?;
        if header.version != 1
            || header.scope != *scope
            || header.generation != generation
            || header.expires_at != expires_at
            || header.incarnation != incarnation
            || header.epoch != epoch
        {
            return Err(denied("profile authenticated scope or generation mismatch"));
        }
        let state = SupportedStorageState::parse(&plaintext[separator + 1..], scope)?;
        let expected = self.register(custody, &state).await?;
        // Registration uses independent transactions. Recheck claim and complete authority
        // afterward; a same-session writer can otherwise replace the claimed generation.
        let mut tx = self.authority.transaction().await?;
        let authority_expiry = self.epoch(&mut tx, custody, expected).await?;
        lock_lease(&mut tx, lease, scope.tenant).await?;
        retention(&mut tx, custody, expires_at).await?;
        source_retained(&mut tx, scope, owner, expires_at).await?;
        let unchanged: bool = sqlx::query_scalar(
            "SELECT true FROM browser_profiles WHERE tenant_id=$1 AND principal=$2 AND name=$3 \
             AND generation=$4 AND digest=$5 AND session_id=$6 AND lease_fence=$7 AND custody_format=1 \
             AND custody_artifact=$8 AND custody_incarnation=$9 AND custody_epoch=$10 AND expires_at=$11 \
             AND scope=$12 AND owner_run=$13 FOR UPDATE",
        )
        .bind(scope.tenant.0)
        .bind(&scope.principal.0)
        .bind(&scope.name)
        .bind(requested)
        .bind(digest.0.as_slice())
        .bind(lease.session.id.0)
        .bind(lease.fencing_token)
        .bind(artifact.0)
        .bind(incarnation)
        .bind(epoch)
        .bind(expires_at)
        .bind(to_json(scope)?)
        .bind(owner.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .unwrap_or(false);
        if !unchanged || expires_at <= database_now(&mut tx).await? {
            return Err(denied("profile changed or expired during secret registration"));
        }
        crate::profiles::audit_profile(&mut tx, lease, scope, "profile.custody.acquire", generation).await?;
        finish(&mut tx, custody, expires_at, authority_expiry).await?;
        tx.commit().await.map_err(db)?;
        custody.check_local_cancellation()?;
        Ok(Some((
            CustodyProfileInspection {
                scope: scope.clone(),
                generation,
                digest,
                expires_at,
            },
            state,
        )))
    }
}

#[cfg(test)]
#[path = "profiles_tests.rs"]
mod tests;
