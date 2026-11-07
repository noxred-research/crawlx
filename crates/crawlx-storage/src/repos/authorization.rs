//! `authorization_records`: creating an immutable, verified record, its lifecycle
//! (re-verification, revocation) and binding a run to the body it was admitted under.
//!
//! The body column holds the record JSON without lifecycle state; `verified_at`, `revoked_at`,
//! `revoked_reason` and `verification` live in columns and are merged back into the JSON on every
//! read ([`stored_from_row`]) so `serde_json::from_value::<AuthorizationRecord>` yields the record
//! as it stands now. Migration 0019 installs the trigger that rejects an `UPDATE` of the body.

use super::api::PgApiRepo;
use crate::codec::{digest, get};
use crate::error::{db, not_found};
use crate::Pg;
use crawlx_core::hash::Digest;
use crawlx_core::{AuthorizationRecordId, CrawlRunId, StoreError, TenantId, Timestamp};
use serde_json::Value;
use sqlx::postgres::PgRow;
use std::borrow::Cow;
use uuid::Uuid;

/// Keys of the record JSON that are lifecycle state: kept in columns, never in `body`.
pub(crate) const LIFECYCLE_KEYS: [&str; 3] = ["verifiedAt", "revokedAt", "revokedReason"];

/// Columns of `authorization_records` that [`stored_from_row`] reads.
pub(crate) const COLUMNS: &str = "body, body_digest, version, valid_from, valid_to, tenant_id, verified_at, \
    verification, revoked_at, revoked_reason";

/// `body` without the lifecycle keys; borrowed when it carries none.
pub(crate) fn without_lifecycle(body: &Value) -> Cow<'_, Value> {
    match body.as_object() {
        Some(map) if LIFECYCLE_KEYS.iter().any(|k| map.contains_key(*k)) => {
            let mut map = map.clone();
            for key in LIFECYCLE_KEYS {
                map.remove(key);
            }
            Cow::Owned(Value::Object(map))
        }
        _ => Cow::Borrowed(body),
    }
}

fn serialization(msg: impl Into<String>) -> StoreError {
    StoreError::Serialization(msg.into())
}

/// A record to store (see [`PgApiRepo::authorization_create`]).
#[derive(Clone, Copy, Debug)]
pub struct NewAuthorization<'a> {
    /// Owning tenant.
    pub tenant: TenantId,
    /// Record id (the primary key).
    pub id: AuthorizationRecordId,
    /// Record version.
    pub version: i32,
    /// The record JSON without `verifiedAt`, `revokedAt` and `revokedReason`.
    pub body: &'a Value,
    /// `AuthorizationRecord::body_digest` of the record, computed by `crawlx-policy`.
    pub body_digest: &'a [u8],
    /// Start of the validity window.
    pub valid_from: Timestamp,
    /// End of the validity window.
    pub valid_to: Timestamp,
    /// The API key creating the record (`authorization_records.created_by`).
    pub created_by: Uuid,
    /// When the ownership proof was checked.
    pub verified_at: Timestamp,
    /// How it was checked (`{kind, checkedAt, hosts|keyId}`).
    pub verification: &'a Value,
}

/// Outcome of [`PgApiRepo::authorization_create`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum AuthorizationInsert {
    /// The record was stored.
    Created,
    /// The tenant already stored this exact body under this id; nothing changed.
    Replayed,
    /// The id is taken by another body or another tenant's record; nothing changed.
    Taken,
}

/// A stored record with its lifecycle state merged in.
#[derive(Clone, PartialEq, Debug)]
pub struct StoredAuthorization {
    /// The record JSON `crawlx-policy` deserializes: `body` with `id`, `tenant`, `version`,
    /// `validFrom` and `validTo` filled in from their columns when the body lacks them, and
    /// `verifiedAt`, `revokedAt` and `revokedReason` from their columns when set.
    pub body: Value,
    /// The digest stored at creation (`AuthorizationRecord::body_digest`).
    pub body_digest: Digest,
    /// How the ownership proof was checked; `None` for a record that was never verified.
    pub verification: Option<Value>,
}

/// Outcome of [`PgApiRepo::authorization_revoke`].
#[derive(Clone, PartialEq, Debug)]
pub struct Revoked {
    /// The record after the call; its revocation is the first one when the record was already revoked.
    pub stored: StoredAuthorization,
    /// `true` when this call revoked the record, `false` when it already was revoked.
    pub first: bool,
}

/// Build a [`StoredAuthorization`] from a row selected with [`COLUMNS`].
pub(crate) fn stored_from_row(
    r: &PgRow,
    id: AuthorizationRecordId,
) -> Result<StoredAuthorization, StoreError> {
    let Value::Object(mut body) = get::<Value>(r, "body")? else {
        return Err(serialization("authorization record body is not a JSON object"));
    };
    let json = |v: &Timestamp| serde_json::to_value(v).map_err(|e| serialization(e.to_string()));
    let tenant: Uuid = get(r, "tenant_id")?;
    let version: i32 = get(r, "version")?;
    let valid_from: Timestamp = get(r, "valid_from")?;
    let valid_to: Timestamp = get(r, "valid_to")?;
    for key in LIFECYCLE_KEYS {
        body.remove(key);
    }
    body.entry("id")
        .or_insert_with(|| Value::String(id.0.to_string()));
    body.entry("tenant")
        .or_insert_with(|| Value::String(tenant.to_string()));
    body.entry("version").or_insert_with(|| Value::from(version));
    body.entry("validFrom").or_insert(json(&valid_from)?);
    body.entry("validTo").or_insert(json(&valid_to)?);
    if let Some(at) = get::<Option<Timestamp>>(r, "verified_at")? {
        body.insert("verifiedAt".to_owned(), json(&at)?);
    }
    if let Some(at) = get::<Option<Timestamp>>(r, "revoked_at")? {
        body.insert("revokedAt".to_owned(), json(&at)?);
    }
    if let Some(reason) = get::<Option<String>>(r, "revoked_reason")? {
        body.insert("revokedReason".to_owned(), Value::String(reason));
    }
    Ok(StoredAuthorization {
        body: Value::Object(body),
        body_digest: digest(&get::<Vec<u8>>(r, "body_digest")?)?,
        verification: get(r, "verification")?,
    })
}

impl PgApiRepo {
    /// Store `record` as a new immutable authorization record, already verified. Idempotent on
    /// `(id, body_digest)`: the same tenant storing the same body again changes nothing and
    /// answers [`AuthorizationInsert::Replayed`]; any other use of the id answers
    /// [`AuthorizationInsert::Taken`].
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the insert fails (for example `created_by` is not an API key).
    pub async fn authorization_create(
        &self,
        record: &NewAuthorization<'_>,
    ) -> Result<AuthorizationInsert, StoreError> {
        let _timer = self.pg.query_timer("api.authorization_create");
        let n = sqlx::query(
            "INSERT INTO authorization_records (record_id, tenant_id, version, body, body_digest, valid_from, valid_to, \
             created_by, verified_at, verification) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (record_id) DO NOTHING",
        )
        .bind(record.id.0)
        .bind(record.tenant.0)
        .bind(record.version)
        .bind(record.body)
        .bind(record.body_digest)
        .bind(record.valid_from)
        .bind(record.valid_to)
        .bind(record.created_by)
        .bind(record.verified_at)
        .bind(record.verification)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?
        .rows_affected();
        if n == 1 {
            return Ok(AuthorizationInsert::Created);
        }
        let existing: Option<(Uuid, Vec<u8>)> =
            sqlx::query_as("SELECT tenant_id, body_digest FROM authorization_records WHERE record_id = $1")
                .bind(record.id.0)
                .fetch_optional(&self.pg.pool)
                .await
                .map_err(db)?;
        Ok(match existing {
            Some((tenant, stored)) if tenant == record.tenant.0 && stored == record.body_digest => {
                AuthorizationInsert::Replayed
            }
            _ => AuthorizationInsert::Taken,
        })
    }

    /// The record `id` of `tenant` with its lifecycle state merged in; `None` when absent or
    /// owned by another tenant.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] when the stored body is not a JSON object and other
    /// [`StoreError`]s if the query fails.
    pub async fn authorization_stored(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> Result<Option<StoredAuthorization>, StoreError> {
        let _timer = self.pg.query_timer("api.authorization_stored");
        let sql =
            format!("SELECT {COLUMNS} FROM authorization_records WHERE record_id = $1 AND tenant_id = $2");
        let row = sqlx::query(&sql)
            .bind(id.0)
            .bind(tenant.0)
            .fetch_optional(&self.pg.pool)
            .await
            .map_err(db)?;
        row.as_ref().map(|r| stored_from_row(r, id)).transpose()
    }

    /// The record JSON of [`Self::authorization_stored`]; `None` when absent.
    ///
    /// # Errors
    /// As [`Self::authorization_stored`].
    pub async fn authorization_get(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
    ) -> Result<Option<Value>, StoreError> {
        Ok(self
            .authorization_stored(tenant, id)
            .await?
            .map(|stored| stored.body))
    }

    /// Revoke the record `id` of `tenant` at `now`, recording `by` and `reason`. Idempotent: a
    /// record that is already revoked keeps its first revocation and the answer says so
    /// ([`Revoked::first`]). `None` when the record is absent or owned by another tenant.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the update or the read-back fails.
    pub async fn authorization_revoke(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        by: Uuid,
        reason: Option<&str>,
        now: Timestamp,
    ) -> Result<Option<Revoked>, StoreError> {
        let _timer = self.pg.query_timer("api.authorization_revoke");
        let n = sqlx::query(
            "UPDATE authorization_records SET revoked_at = $3, revoked_reason = $4, revoked_by = $5 \
             WHERE record_id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
        )
        .bind(id.0)
        .bind(tenant.0)
        .bind(now)
        .bind(reason)
        .bind(by)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?
        .rows_affected();
        Ok(self
            .authorization_stored(tenant, id)
            .await?
            .map(|stored| Revoked {
                stored,
                first: n == 1,
            }))
    }

    /// Record a fresh ownership check of the record `id` of `tenant`: `verified_at` and
    /// `verification`; the body is untouched. `None` when the record is absent or owned by
    /// another tenant.
    ///
    /// # Errors
    /// Returns a [`StoreError`] if the update or the read-back fails.
    pub async fn authorization_mark_verified(
        &self,
        tenant: TenantId,
        id: AuthorizationRecordId,
        verification: &Value,
        now: Timestamp,
    ) -> Result<Option<StoredAuthorization>, StoreError> {
        let _timer = self.pg.query_timer("api.authorization_mark_verified");
        let n = sqlx::query(
            "UPDATE authorization_records SET verified_at = $3, verification = $4 \
             WHERE record_id = $1 AND tenant_id = $2",
        )
        .bind(id.0)
        .bind(tenant.0)
        .bind(now)
        .bind(verification)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?
        .rows_affected();
        if n == 0 {
            return Ok(None);
        }
        self.authorization_stored(tenant, id).await
    }

    /// Bind `run` to the body digest of the record it was admitted under
    /// (`crawl_runs.authorization_body_digest`).
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when `run` does not exist and other [`StoreError`]s if
    /// the update fails.
    pub async fn authorization_bind_run(
        &self,
        run: CrawlRunId,
        body_digest: Digest,
    ) -> Result<(), StoreError> {
        let _timer = self.pg.query_timer("api.authorization_bind_run");
        let n = sqlx::query("UPDATE crawl_runs SET authorization_body_digest = $2 WHERE run_id = $1")
            .bind(run.0)
            .bind(body_digest.0.as_slice())
            .execute(&self.pg.pool)
            .await
            .map_err(db)?
            .rows_affected();
        if n == 0 {
            return Err(not_found("crawl_run", run));
        }
        Ok(())
    }

    /// The record body digest `run` was bound to; `None` when it references no record.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when `run` does not exist and other [`StoreError`]s if
    /// the query fails.
    pub async fn authorization_run_digest(&self, run: CrawlRunId) -> Result<Option<Digest>, StoreError> {
        let _timer = self.pg.query_timer("api.authorization_run_digest");
        let row: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT authorization_body_digest FROM crawl_runs WHERE run_id = $1")
                .bind(run.0)
                .fetch_optional(&self.pg.pool)
                .await
                .map_err(db)?;
        match row {
            None => Err(not_found("crawl_run", run)),
            Some(stored) => stored.map(|b| digest(&b)).transpose(),
        }
    }
}

impl Pg {
    /// The stored body of an authorization record (`authorization_records.body`), if it exists,
    /// with its lifecycle state merged in exactly as [`PgApiRepo::authorization_get`] does
    /// (`revokedAt`, `revokedReason`, `verifiedAt`, and `id`, `tenant`, `version`, `validFrom`,
    /// `validTo` when the body lacks them), so `serde_json::from_value::<AuthorizationRecord>`
    /// works and a revoked row shows `revokedAt`. Not tenant-scoped: the worker's authority is
    /// the run's lease.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] when the stored body is not a JSON object and other
    /// [`StoreError`]s if the query fails.
    pub async fn authorization_record_body(
        &self,
        record: AuthorizationRecordId,
    ) -> Result<Option<Value>, StoreError> {
        let sql = format!("SELECT {COLUMNS} FROM authorization_records WHERE record_id = $1");
        let row = sqlx::query(&sql)
            .bind(record.0)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
        Ok(row
            .as_ref()
            .map(|r| stored_from_row(r, record))
            .transpose()?
            .map(|stored| stored.body))
    }
}
