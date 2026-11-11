//! Independent committed-action observer and narrowly scoped pause client.
//!
//! This module has no browser or actor dependency. Reads use one read-only repeatable-read
//! snapshot. The separate pause capability rechecks each violation before changing a run,
//! and appends the existing paused event and BLAKE3 audit-chain entry atomically.

use crate::backend::{BackendKind, BackendRefusal, DatabaseUrl};
use crate::codec::get;
use crate::error::db;
use crawlx_core::hash::Digest;
use crawlx_core::{ActionId, CrawlRunId, StoreError, TenantId};
use serde::Serialize;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::collections::BTreeSet;

/// One committed action that violates an independently checked safety invariant.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[must_use]
pub struct SafetyViolation {
    /// Tenant owning the affected run.
    pub tenant: TenantId,
    /// Run to contain; never a tenant-wide selector.
    pub run: CrawlRunId,
    /// Action whose persisted evidence failed the invariant.
    pub action: ActionId,
    /// Stable, non-sensitive invariant identifier.
    pub reason: String,
}

/// Result of one consistent observation and its separately authorized containment.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
#[must_use]
pub struct SafetyAuditReport {
    /// Committed actions at or beyond intent examined in the snapshot.
    pub checked: u64,
    /// Violations observed, ordered by run and action.
    pub violations: Vec<SafetyViolation>,
    /// Runs actually paused; terminal or already-paused runs remain unchanged.
    pub paused: Vec<CrawlRunId>,
}

/// Independent observer holding two disjoint, limited database capabilities.
#[derive(Clone, Debug)]
pub struct SafetyAuditor {
    reader: PgPool,
    pauser: PgPool,
}

impl SafetyAuditor {
    /// Connect without running migrations or borrowing a privileged worker/API pool.
    ///
    /// # Errors
    /// Returns the `sqlite_safety_auditor` refusal for SQLite URLs (it has no second database
    /// identity) and the `backend_unimplemented` refusal for MariaDB, which has no
    /// independent auditor yet. On PostgreSQL returns an error on connection failure, missing
    /// auditor migration, identical database identities, elevated privileges, or membership
    /// in both auditor capability roles.
    pub async fn connect(read_url: &str, pause_url: &str) -> Result<Self, StoreError> {
        for url in [read_url, pause_url] {
            match DatabaseUrl::parse(url)?.kind() {
                BackendKind::Postgres => {}
                BackendKind::Sqlite => return Err(BackendRefusal::sqlite_safety_auditor().into()),
                kind => {
                    return Err(BackendRefusal::unimplemented(kind, "the independent safety auditor").into())
                }
            }
        }
        let reader = PgPoolOptions::new()
            .max_connections(1)
            .connect(read_url)
            .await
            .map_err(db)?;
        let pauser = PgPoolOptions::new()
            .max_connections(1)
            .connect(pause_url)
            .await
            .map_err(db)?;
        let read_identity =
            validate_identity(&reader, "crawlx_safety_reader", "crawlx_safety_pauser").await?;
        let pause_identity =
            validate_identity(&pauser, "crawlx_safety_pauser", "crawlx_safety_reader").await?;
        if read_identity == pause_identity {
            return Err(StoreError::Conflict(
                "safety auditor requires distinct database identities".to_owned(),
            ));
        }
        let location = "SELECT jsonb_build_array(current_database(), current_schema(), inet_server_addr(), inet_server_port())";
        let pause_database: serde_json::Value = sqlx::query_scalar(location)
            .fetch_one(&pauser)
            .await
            .map_err(db)?;
        let read_database: serde_json::Value = sqlx::query_scalar(location)
            .fetch_one(&reader)
            .await
            .map_err(db)?;
        if pause_database != read_database {
            return Err(StoreError::Conflict(
                "safety auditor identities must connect to the same database and schema".to_owned(),
            ));
        }
        Ok(Self { reader, pauser })
    }

    /// Observe committed intended/executed actions, then pause only still-confirmed violations.
    ///
    /// Pending proposals are excluded. Unknown outcomes are checked against their historical
    /// intent evidence, not treated as unauthorized because their outcome is uncertain.
    /// Authorization revocation or approval expiry after intent does not rewrite history.
    ///
    /// # Errors
    /// Returns an error if observation, containment, or the atomic audit append fails.
    pub async fn audit(&self) -> Result<SafetyAuditReport, StoreError> {
        let mut tx = self.reader.begin().await.map_err(db)?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let checked: i64 = sqlx::query_scalar("SELECT count(*) FROM safety_auditor_actions")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let rows = sqlx::query("SELECT tenant_id, run_id, action_id, reason FROM safety_auditor_actions WHERE reason IS NOT NULL ORDER BY run_id, action_id")
            .fetch_all(&mut *tx).await.map_err(db)?;
        let violations = rows
            .iter()
            .map(|r| {
                Ok(SafetyViolation {
                    tenant: TenantId(get(r, "tenant_id")?),
                    run: CrawlRunId(get(r, "run_id")?),
                    action: ActionId(get(r, "action_id")?),
                    reason: get(r, "reason")?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        tx.commit().await.map_err(db)?;
        let mut paused = BTreeSet::new();
        for violation in &violations {
            if !paused.contains(&violation.run) && self.pause(violation).await? {
                paused.insert(violation.run);
            }
        }
        Ok(SafetyAuditReport {
            checked: u64::try_from(checked).map_err(|e| StoreError::Serialization(e.to_string()))?,
            violations,
            paused: paused.into_iter().collect(),
        })
    }

    async fn pause(&self, violation: &SafetyViolation) -> Result<bool, StoreError> {
        let mut tx = self.pauser.begin().await.map_err(db)?;
        let previous: Vec<u8> = sqlx::query_scalar("SELECT safety_auditor_chain_head()")
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        let subject = serde_json::json!({ "action": violation.action, "reason": violation.reason });
        let entry = serde_json::json!({
            "tenant": violation.tenant, "run": violation.run, "actor": "safety_auditor",
            "event": "safety.invariant_violation", "subject": subject,
        });
        let text = entry.to_string();
        let mut bytes = Vec::with_capacity(previous.len() + text.len());
        bytes.extend_from_slice(&previous);
        bytes.extend_from_slice(text.as_bytes());
        let hash = Digest::of("crawlx/audit-chain/v1", &bytes);
        let paused = sqlx::query_scalar("SELECT safety_auditor_pause($1,$2,$3,$4)")
            .bind(violation.action.0)
            .bind(&violation.reason)
            .bind(previous)
            .bind(hash.0.as_slice())
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(paused)
    }
}

async fn validate_identity(pool: &PgPool, required: &str, forbidden: &str) -> Result<String, StoreError> {
    let row = sqlx::query(
        "SELECT current_user::text AS identity, \
           NOT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication) \
           AND current_user = session_user \
           AND pg_has_role(current_user,$1::name,'MEMBER') AND NOT pg_has_role(current_user,$2::name,'MEMBER') \
           AND NOT EXISTS (SELECT 1 FROM pg_roles elevated WHERE \
             (elevated.rolsuper OR elevated.rolbypassrls OR elevated.rolcreaterole OR elevated.rolcreatedb OR elevated.rolreplication) \
             AND pg_has_role(current_user,elevated.oid,'MEMBER')) \
           AND (($1 = 'crawlx_safety_reader') = has_table_privilege(current_user,'safety_auditor_actions','SELECT')) \
           AND (($1 = 'crawlx_safety_pauser') = has_function_privilege(current_user,'safety_auditor_pause(uuid,text,bytea,bytea)','EXECUTE')) \
           AND NOT has_schema_privilege(current_user,current_schema(),'CREATE') \
           AND NOT EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace \
             WHERE n.nspname=current_schema() AND c.relkind IN ('r','p','v','m','f') \
               AND (c.relowner=r.oid OR has_table_privilege(current_user,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') \
                 OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE,REFERENCES') \
                 OR (has_any_column_privilege(current_user,c.oid,'SELECT') \
                   AND (c.relname <> 'safety_auditor_actions' OR $1 <> 'crawlx_safety_reader')))) AS limited \
         FROM pg_roles r WHERE r.rolname=current_user",
    ).bind(required).bind(forbidden).fetch_one(pool).await.map_err(db)?;
    if !get::<bool>(&row, "limited")? {
        return Err(StoreError::Conflict(
            "safety auditor database identity has elevated or overlapping privileges".to_owned(),
        ));
    }
    get(&row, "identity")
}
