//! `authorization_records`: creating an immutable, verified record, its lifecycle
//! (re-verification, revocation) and binding a run to the body it was admitted under.
//!
//! The body column holds the record JSON without lifecycle state; `verified_at`, `revoked_at`,
//! `revoked_reason` and `verification` live in columns and are merged back into the JSON on every
//! read ([`stored_from_row`]) so `serde_json::from_value::<AuthorizationRecord>` yields the record
//! as it stands now. Migration 0019 installs the trigger that rejects an `UPDATE` of the body.

#![deny(clippy::disallowed_methods)]

use super::api::{insert_if_absent, ApiRepo};
use crate::codec::digest;
use crate::error::not_found;
use crate::sql::{SqlRow, Stmt};
use crate::store::{AuthorizationRow, Store};
use crate::tenant::Tenancy;
use crawlx_core::hash::Digest;
use crawlx_core::{AuthorizationRecordId, CrawlRunId, StoreError, TenantId, Timestamp};
use serde_json::Value;
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

/// A record to store (see [`ApiRepo::authorization_create`]).
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

/// Outcome of [`ApiRepo::authorization_create`].
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

/// Outcome of [`ApiRepo::authorization_revoke`].
#[derive(Clone, PartialEq, Debug)]
pub struct Revoked {
    /// The record after the call; its revocation is the first one when the record was already revoked.
    pub stored: StoredAuthorization,
    /// `true` when this call revoked the record, `false` when it already was revoked.
    pub first: bool,
}

/// Build a [`StoredAuthorization`] from a row selected with [`COLUMNS`].
pub(crate) fn stored_from_row<R: SqlRow>(
    r: &R,
    id: AuthorizationRecordId,
) -> Result<StoredAuthorization, StoreError> {
    let Value::Object(mut body) = r.json("body")? else {
        return Err(serialization("authorization record body is not a JSON object"));
    };
    let json = |v: &Timestamp| serde_json::to_value(v).map_err(|e| serialization(e.to_string()));
    let tenant = r.uuid("tenant_id")?;
    let version = r.i32("version")?;
    let valid_from = r.ts("valid_from")?;
    let valid_to = r.ts("valid_to")?;
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
    if let Some(at) = r.opt_ts("verified_at")? {
        body.insert("verifiedAt".to_owned(), json(&at)?);
    }
    if let Some(at) = r.opt_ts("revoked_at")? {
        body.insert("revokedAt".to_owned(), json(&at)?);
    }
    if let Some(reason) = r.opt_text("revoked_reason")? {
        body.insert("revokedReason".to_owned(), Value::String(reason));
    }
    Ok(StoredAuthorization {
        body: Value::Object(body),
        body_digest: digest(&r.bytes("body_digest")?)?,
        verification: r.opt_json("verification")?,
    })
}

impl<B: Tenancy> ApiRepo<B> {
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
        let _timer = self.store.query_timer("api.authorization_create");
        let scope = self.store.scope()?;
        scope.authorize(record.tenant)?;
        let insert = insert_if_absent::<B>(
            "authorization_records",
            &[
                ("record_id", "$1"),
                ("tenant_id", "$2"),
                ("version", "$3"),
                ("body", "$4"),
                ("body_digest", "$5"),
                ("valid_from", "$6"),
                ("valid_to", "$7"),
                ("created_by", "$8"),
                ("verified_at", "$9"),
                ("verification", "$10"),
            ],
            &["record_id"],
        );
        let mut tx = self.store.begin_write().await?;
        let n = scope
            .query(
                "authorization_records",
                Stmt::<B>::dynamic(&insert)
                    .uuid(record.id.0)
                    .uuid(record.tenant.0)
                    .i32(record.version)
                    .json(record.body)
                    .bytes(record.body_digest)
                    .ts(record.valid_from)
                    .ts(record.valid_to)
                    .uuid(record.created_by)
                    .ts(record.verified_at)
                    .json(record.verification),
            )?
            .execute(tx.conn())
            .await?;
        if n == 1 {
            tx.commit().await?;
            return Ok(AuthorizationInsert::Created);
        }
        let sql = format!(
            "SELECT tenant_id, body_digest FROM authorization_records WHERE record_id = $1{}",
            scope.and("authorization_records", "", 2)?
        );
        let existing = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(record.id.0))
            .fetch_optional(tx.conn())
            .await?;
        tx.commit().await?;
        let existing = existing
            .map(|r| Ok::<_, StoreError>((r.uuid("tenant_id")?, r.bytes("body_digest")?)))
            .transpose()?;
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
        let _timer = self.store.query_timer("api.authorization_stored");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let sql =
            format!("SELECT {COLUMNS} FROM authorization_records WHERE record_id = $1 AND tenant_id = $2");
        let row = scope
            .query(
                "authorization_records",
                Stmt::<B>::dynamic(&sql).uuid(id.0).uuid(tenant.0),
            )?
            .fetch_optional_pool(&self.store.pool)
            .await?;
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
        let _timer = self.store.query_timer("api.authorization_revoke");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let mut tx = self.store.begin_write().await?;
        let n = scope
            .query(
                "authorization_records",
                Stmt::<B>::dynamic(
                    "UPDATE authorization_records SET revoked_at = $3, revoked_reason = $4, revoked_by = $5 \
                     WHERE record_id = $1 AND tenant_id = $2 AND revoked_at IS NULL",
                )
                .uuid(id.0)
                .uuid(tenant.0)
                .ts(now)
                .opt_text(reason)
                .uuid(by),
            )?
            .execute(tx.conn())
            .await?;
        if n == 1 {
            // what the PostgreSQL trigger does on revocation: the other engines settle in Rust,
            // in the same transaction
            crate::repos::effects::settle_authorization_revoked::<B>(tx.conn(), id.0).await?;
        }
        tx.commit().await?;
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
        let _timer = self.store.query_timer("api.authorization_mark_verified");
        let scope = self.store.scope()?;
        if !scope.sees(tenant) {
            return Ok(None);
        }
        let n = scope
            .query(
                "authorization_records",
                Stmt::<B>::dynamic(
                    "UPDATE authorization_records SET verified_at = $3, verification = $4 \
                     WHERE record_id = $1 AND tenant_id = $2",
                )
                .uuid(id.0)
                .uuid(tenant.0)
                .ts(now)
                .json(verification),
            )?
            .execute_write(&self.store.pool)
            .await?;
        if n == 0 {
            return Ok(None);
        }
        self.authorization_stored(tenant, id).await
    }

    /// Bind `run` to the body digest of the record it was admitted under
    /// (`crawl_runs.authorization_body_digest`).
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when `run` does not exist (or belongs to another
    /// tenant) and other [`StoreError`]s if the update fails.
    pub async fn authorization_bind_run(
        &self,
        run: CrawlRunId,
        body_digest: Digest,
    ) -> Result<(), StoreError> {
        let _timer = self.store.query_timer("api.authorization_bind_run");
        let scope = self.store.scope()?;
        let sql = format!(
            "UPDATE crawl_runs SET authorization_body_digest = $2 WHERE run_id = $1{}",
            scope.and("crawl_runs", "", 3)?
        );
        let n = scope
            .bind(
                Stmt::<B>::dynamic(&sql)
                    .uuid(run.0)
                    .bytes(body_digest.0.as_slice()),
            )
            .execute_write(&self.store.pool)
            .await?;
        if n == 0 {
            return Err(not_found("crawl_run", run));
        }
        Ok(())
    }

    /// The record body digest `run` was bound to; `None` when it references no record.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when `run` does not exist (or belongs to another
    /// tenant) and other [`StoreError`]s if the query fails.
    pub async fn authorization_run_digest(&self, run: CrawlRunId) -> Result<Option<Digest>, StoreError> {
        let _timer = self.store.query_timer("api.authorization_run_digest");
        let scope = self.store.scope()?;
        let sql = format!(
            "SELECT authorization_body_digest FROM crawl_runs WHERE run_id = $1{}",
            scope.and("crawl_runs", "", 2)?
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(run.0))
            .fetch_optional_pool(&self.store.pool)
            .await?;
        match row {
            None => Err(not_found("crawl_run", run)),
            Some(r) => r
                .opt_bytes("authorization_body_digest")?
                .map(|b| digest(&b))
                .transpose(),
        }
    }
}

impl<B: Tenancy> Store<B> {
    /// The stored body of an authorization record (`authorization_records.body`), if it exists,
    /// with its lifecycle state merged in exactly as [`ApiRepo::authorization_get`] does
    /// (`revokedAt`, `revokedReason`, `verifiedAt`, and `id`, `tenant`, `version`, `validFrom`,
    /// `validTo` when the body lacks them), so `serde_json::from_value::<AuthorizationRecord>`
    /// works and a revoked row shows `revokedAt`. Operator authority is not tenant-scoped (the
    /// worker's authority is the run's lease); a handle with a tenant scope only reads its
    /// tenant's records.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] when the stored body is not a JSON object and other
    /// [`StoreError`]s if the query fails.
    pub async fn authorization_record_body(
        &self,
        record: AuthorizationRecordId,
    ) -> Result<Option<Value>, StoreError> {
        let scope = self.scope()?;
        let sql = format!(
            "SELECT {COLUMNS} FROM authorization_records WHERE record_id = $1{}",
            scope.and("authorization_records", "", 2)?
        );
        let row = scope
            .bind(Stmt::<B>::dynamic(&sql).uuid(record.0))
            .fetch_optional_pool(&self.pool)
            .await?;
        Ok(row
            .as_ref()
            .map(|r| stored_from_row(r, record))
            .transpose()?
            .map(|stored| stored.body))
    }
}

impl<B: Tenancy> Store<B> {
    /// Insert a tenant if absent (runs reference `tenants`).
    ///
    /// # Errors
    /// Returns [`StoreError`] if the insert fails.
    pub async fn ensure_tenant(&self, tenant: TenantId, name: &str) -> Result<(), StoreError> {
        self.scope()?.authorize(tenant)?;
        let mut tx = self.begin_write().await?;
        super::api::ensure_tenant_on::<B>(tx.conn(), tenant, name).await?;
        tx.commit().await
    }

    /// Register an authorization record (`authorization_records`) so a run can reference it.
    /// The record's creator is a placeholder `api_keys` row of the tenant (`cli_<tenant>`).
    /// Idempotent. The body and digest are computed by `crawlx-policy`; the stored body never
    /// carries lifecycle state (`verifiedAt`, `revokedAt`, `revokedReason`), which lives in
    /// columns. The record stays unverified (`verified_at` NULL): only the API route checks
    /// an ownership proof.
    ///
    /// # Errors
    /// Returns [`StoreError`] if registering the tenant, the placeholder `api_keys` row
    /// or the record fails.
    pub async fn ensure_authorization_record(&self, row: &AuthorizationRow<'_>) -> Result<(), StoreError> {
        let scope = self.scope()?;
        scope.authorize(row.tenant)?;
        let mut tx = self.begin_write().await?;
        super::api::ensure_tenant_on::<B>(tx.conn(), row.tenant, "local").await?;
        let placeholder_key = if B::KIND == crate::backend::BackendKind::Postgres {
            "INSERT INTO api_keys (key_id, tenant_id, prefix, key_hash, scopes) VALUES ($1, $1, $2, '\\x'::bytea, '{}') \
             ON CONFLICT DO NOTHING"
                .to_owned()
        } else {
            super::api::insert_if_absent::<B>(
                "api_keys",
                &[
                    ("key_id", "$1"),
                    ("tenant_id", "$1"),
                    ("prefix", "$2"),
                    ("key_hash", "$3"),
                    ("scopes", "$4"),
                ],
                &["key_id"],
            )
        };
        let prefix = format!("cli_{}", row.tenant.0.simple());
        let mut key = Stmt::<B>::dynamic(&placeholder_key)
            .uuid(row.tenant.0)
            .text(&prefix);
        let empty: Vec<String> = Vec::new();
        if B::KIND != crate::backend::BackendKind::Postgres {
            key = key.bytes(&[]).text_list(&empty);
        }
        scope.query("api_keys", key)?.execute(tx.conn()).await?;
        let body = without_lifecycle(row.body);
        let insert = super::api::insert_if_absent::<B>(
            "authorization_records",
            &[
                ("record_id", "$1"),
                ("tenant_id", "$2"),
                ("version", "$3"),
                ("body", "$4"),
                ("body_digest", "$5"),
                ("valid_from", "$6"),
                ("valid_to", "$7"),
                ("created_by", "$2"),
            ],
            &["record_id"],
        );
        scope
            .query(
                "authorization_records",
                Stmt::<B>::dynamic(&insert)
                    .uuid(row.record.0)
                    .uuid(row.tenant.0)
                    .i32(row.version)
                    .json(body.as_ref())
                    .bytes(row.body_digest)
                    .ts(row.valid_from)
                    .ts(row.valid_to),
            )?
            .execute(tx.conn())
            .await?;
        tx.commit().await
    }
}
