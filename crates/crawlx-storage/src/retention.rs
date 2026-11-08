//! Retention and ZDR.
//!
//! * [`zdr_write_gate`] – the durable store refuses `content`, `sensitive` and
//!   `credential_bearing` objects for runs in `zdr` mode.
//! * [`artifact_expiry`] – per-class expiry horizon.
//! * [`RetentionSweeper`] – deletes expired artifacts and pages and purges runs
//!   whose `expires_at` has passed or that have `purge_requested_at` set, leaf
//!   tables first in batches of 10 000 rows, writing one hash-chained
//!   `audit_events` row per purged run.
//! * [`ensure_traffic_partitions`] – monthly `traffic_events` partitions created ahead of time.

use crate::artifacts::{ArtifactReaper, LiveArtifacts};
use crate::codec::get;
use crate::error::db;
use crate::pg::Pg;
use chrono::{Datelike, Duration, NaiveDate, TimeZone, Utc};
use crawlx_core::archive_catalog::ArchiveRepo;
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::Sensitivity;
use crawlx_core::{ArtifactId, CrawlRunId, StoreError, TenantId, Timestamp};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use parking_lot::Mutex;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Rows deleted per statement when purging.
const PURGE_BATCH: i64 = 10_000;

/// ZDR write gate: under `zdr` only metadata rows may be persisted. Every refusal is a
/// caller that tried to persist ZDR content and counts under `crawlx.zdr.violations`.
///
/// # Errors
///
/// Returns [`StoreError::RetentionDenied`] if `mode` is `zdr` and `class` is anything but
/// `metadata`.
pub fn zdr_write_gate(mode: RetentionMode, class: Sensitivity) -> Result<(), StoreError> {
    if mode == RetentionMode::Zdr && class != Sensitivity::Metadata {
        Metrics::global().counter(names::ZDR_VIOLATIONS).inc();
        return Err(StoreError::RetentionDenied(format!(
            "zero-data-retention run may not write {} artifacts to the durable store",
            class.as_str()
        )));
    }
    Ok(())
}

/// Expiry of an artifact written at `now` for a run with `days` retention.
///
/// `metadata` lives until purge; `content` for `days`; `sensitive` for `days`, capped at
/// 3 days for screenshots (`image/*`) and bodies; `credential_bearing`
/// for at most one day (a "run end + 1 h" rule needs the run lifecycle, which the
/// run purge covers).
#[must_use]
pub fn artifact_expiry(
    class: Sensitivity,
    content_type: &str,
    mode: RetentionMode,
    days: u32,
    now: Timestamp,
) -> Option<Timestamp> {
    let horizon = |d: u32| now + Duration::days(i64::from(d));
    match (class, mode) {
        (Sensitivity::Metadata, _) => None,
        (_, RetentionMode::Zdr) => Some(now + Duration::hours(1)),
        (Sensitivity::Content, _) => Some(horizon(days)),
        (Sensitivity::Sensitive, _) if content_type.starts_with("image/") => Some(horizon(days.min(3))),
        (Sensitivity::Sensitive, _) => Some(horizon(days)),
        (Sensitivity::CredentialBearing, _) => Some(horizon(days.min(1))),
    }
}

/// What a sweep removed.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct SweepReport {
    /// Artifact uses removed through the attached [`ArtifactReaper`].
    pub artifacts_deleted: u64,
    /// Orphan objects removed by [`RetentionSweeper::collect_orphans`] (only with an orphan grace set).
    pub orphans_collected: u64,
    /// Expired `pages` rows deleted.
    pub pages_deleted: u64,
    /// Runs purged in full.
    pub runs_purged: u64,
    /// Rows deleted across all tables by the run purges.
    pub rows_deleted: u64,
    /// Expired, unreferenced authorization records removed after the audit horizon.
    pub authorizations_deleted: u64,
}

/// Deletes expired data. Cheap to construct; call [`RetentionSweeper::sweep`] periodically.
pub struct RetentionSweeper {
    pg: Pg,
    artifacts: Option<Arc<dyn ArtifactReaper>>,
    orphan_grace: Option<Duration>,
    /// Non-metadata artifacts of ZDR runs already counted under `crawlx.zdr.violations`
    /// (RB-08); a row that survives several sweeps is one violation, not one per sweep.
    zdr_seen: Mutex<BTreeSet<ArtifactId>>,
}

impl RetentionSweeper {
    /// Sweeper over `pg` with no artifact store attached.
    #[must_use]
    pub fn new(pg: Pg) -> Self {
        Self {
            pg,
            artifacts: None,
            orphan_grace: None,
            zdr_seen: Mutex::new(BTreeSet::new()),
        }
    }

    /// Also delete the objects behind expired artifact rows.
    #[must_use]
    pub fn with_artifacts(mut self, artifacts: Arc<dyn ArtifactReaper>) -> Self {
        self.artifacts = Some(artifacts);
        self
    }

    /// Also run [`RetentionSweeper::collect_orphans`] with `grace` on every sweep. Listing a
    /// whole bucket is not free, so this is opt-in; a grace of a day is a reasonable default.
    #[must_use]
    pub const fn with_orphan_grace(mut self, grace: Duration) -> Self {
        self.orphan_grace = Some(grace);
        self
    }

    /// Remove objects (and index records) written before `now - grace` that no live
    /// `artifacts` row references (orphan collection). Objects referenced by a row
    /// with `deleted_at IS NULL` are never removed. Returns the number of objects removed;
    /// `0` when no artifact store is attached.
    ///
    /// # Errors
    ///
    /// Returns an error if the live rows cannot be read or the store cannot list or delete.
    pub async fn collect_orphans(&self, now: Timestamp, grace: Duration) -> Result<u64, StoreError> {
        let Some(store) = &self.artifacts else {
            return Ok(0);
        };
        let rows = sqlx::query("SELECT artifact_id, object_key FROM artifacts WHERE deleted_at IS NULL")
            .fetch_all(&self.pg.pool)
            .await
            .map_err(db)?;
        let mut live = LiveArtifacts::default();
        for r in &rows {
            live.ids.insert(crawlx_core::ArtifactId(get(r, "artifact_id")?));
            live.object_keys.insert(get(r, "object_key")?);
        }
        let older_than = now
            .checked_sub_signed(grace)
            .ok_or_else(|| StoreError::Backend("orphan grace is out of range".to_owned()))?;
        store.collect_orphans(&live, older_than).await
    }

    /// One pass at `now`: expired artifacts, orphan objects (when an orphan grace is set),
    /// expired pages, then whole-run purges.
    ///
    /// Publishes `crawlx.retention.overdue_artifacts{kind}` (artifacts past `expires_at`
    /// and still present after the pass, per run retention mode), counts
    /// `crawlx.retention.sweep.failures` when the pass fails and `crawlx.zdr.violations`
    /// for every non-metadata artifact row of a ZDR run (RB-08) seen for the first time.
    ///
    /// # Errors
    ///
    /// Returns an error if the artifact reaper or any database statement fails. A failed sweep
    /// is safe to repeat.
    pub async fn sweep(&self, now: Timestamp) -> Result<SweepReport, StoreError> {
        let metrics = Metrics::global();
        let result = self.sweep_inner(now).await;
        if result.is_err() {
            metrics.counter(names::RETENTION_SWEEP_FAILURES).inc();
        }
        // best effort either way: a failed sweep leaves the overdue rows in place and the gauge must say so
        if let Ok(overdue) = self.overdue_artifacts(now).await {
            let gauge = metrics.gauge(names::RETENTION_OVERDUE_ARTIFACTS);
            for kind in ["standard", "extended", "zdr"] {
                let n = overdue.get(kind).copied().unwrap_or(0);
                // u64 → f64 is lossy above 2^53; a gauge of that size is not a real count
                #[allow(clippy::cast_precision_loss)]
                gauge.set(n as f64, &[("kind", kind)]);
            }
        }
        if let Ok(ids) = self.zdr_violations().await {
            let fresh = {
                let mut seen = self.zdr_seen.lock();
                ids.into_iter().filter(|id| seen.insert(*id)).count()
            };
            metrics
                .counter(names::ZDR_VIOLATIONS)
                .inc_by(u64::try_from(fresh).unwrap_or(u64::MAX), &[]);
        }
        result
    }

    /// Non-metadata artifact rows of ZDR runs that are still present (RB-08: none may exist).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn zdr_violations(&self) -> Result<Vec<ArtifactId>, StoreError> {
        let ids: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT a.artifact_id FROM artifacts a JOIN crawl_runs r ON r.run_id = a.run_id \
             WHERE r.retention_mode = 'zdr' AND a.sensitivity <> 'metadata' AND a.deleted_at IS NULL \
             ORDER BY a.artifact_id",
        )
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        Ok(ids.into_iter().map(ArtifactId).collect())
    }

    /// Artifacts past `expires_at` that are still present, grouped by the owning run's
    /// `retention_mode` (`standard`, `extended`, `zdr`).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn overdue_artifacts(&self, now: Timestamp) -> Result<BTreeMap<String, u64>, StoreError> {
        let rows = sqlx::query(
            "SELECT r.retention_mode::text AS kind, count(*) AS n FROM artifacts a \
             JOIN crawl_runs r ON r.run_id = a.run_id \
             WHERE a.deleted_at IS NULL AND a.expires_at IS NOT NULL AND a.expires_at <= $1 GROUP BY 1",
        )
        .bind(now)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        let mut out = BTreeMap::new();
        for r in &rows {
            let kind: String = get(r, "kind")?;
            let n: i64 = get(r, "n")?;
            out.insert(kind, u64::try_from(n).unwrap_or(0));
        }
        Ok(out)
    }

    async fn sweep_inner(&self, now: Timestamp) -> Result<SweepReport, StoreError> {
        self.pg.reap_profiles().await?;
        self.pg.reap_profile_directories().await?;
        let mut report = SweepReport::default();
        // Revoke dependency closure before deleting source content. Each object removal is
        // acknowledged separately, so cancellation leaves a resumable erasure cursor.
        let expired = sqlx::query(
            "SELECT e.tenant_id,e.export_id FROM archive_exports e \
             WHERE (e.expires_at<=$1 AND e.state<>'deleted') OR (e.state='deleted' AND ( \
               e.payload->'artifact'<>'null'::jsonb OR e.payload->'index'<>'null'::jsonb OR \
               EXISTS(SELECT 1 FROM archive_records r WHERE r.tenant_id=e.tenant_id AND r.export_id=e.export_id))) \
             ORDER BY e.expires_at,e.export_id LIMIT 64",
        ).bind(now).fetch_all(&self.pg.pool).await.map_err(db)?;
        for row in &expired {
            let tenant = TenantId(get(row, "tenant_id")?);
            let export = get(row, "export_id")?;
            report.artifacts_deleted = report
                .artifacts_deleted
                .saturating_add(self.purge_archives(tenant, export).await?);
        }
        // A source that expires while finalizing cannot resume from deleted content.
        // Close its durable lifecycle rather than strand a nonterminal run forever.
        sqlx::query(
            "UPDATE crawl_runs r SET status='failed',terminal_reason='fatal_error',finished_at=$1 \
             WHERE r.expires_at<=$1 AND r.status NOT IN ('completed','failed','cancelled') \
             AND EXISTS(SELECT 1 FROM archive_exports e WHERE e.tenant_id=r.tenant_id AND e.run_id=r.run_id)",
        )
        .bind(now)
        .execute(&self.pg.pool)
        .await
        .map_err(db)?;
        if let Some(store) = &self.artifacts {
            report.artifacts_deleted = report
                .artifacts_deleted
                .saturating_add(store.reap_expired(now).await?);
        }
        if let Some(grace) = self.orphan_grace {
            report.orphans_collected = self.collect_orphans(now, grace).await?;
        }
        report.pages_deleted = delete_batched(&self.pg, "pages", "expires_at <= $1", Some(now)).await?;
        report.rows_deleted = report.rows_deleted.saturating_add(
            delete_batched(
                &self.pg,
                "page_captures",
                "expires_at <= $1 OR run_id IN (SELECT run_id FROM crawl_runs WHERE expires_at <= $1 OR retention_mode='zdr')",
                Some(now),
            )
            .await?,
        );
        report.rows_deleted = report.rows_deleted.saturating_add(
            delete_batched(&self.pg, "adaptive_selectors", "expires_at <= $1", Some(now)).await?,
        );
        let runs = sqlx::query(
            "SELECT run_id FROM crawl_runs WHERE status::text IN ('completed','failed','cancelled') \
             AND ((expires_at IS NOT NULL AND expires_at <= $1) OR purge_requested_at IS NOT NULL) ORDER BY run_id",
        )
        .bind(now)
        .fetch_all(&self.pg.pool)
        .await
        .map_err(db)?;
        for r in &runs {
            let run = CrawlRunId(get(r, "run_id")?);
            report.rows_deleted += self.purge_run(run).await?;
            report.runs_purged += 1;
        }
        report.authorizations_deleted = self.sweep_authorizations(now).await?;
        Ok(report)
    }

    /// Remove at most 100 expired authorization records per pass.
    ///
    /// The explicit policy retains bodies for 1,096 days (at least three years) after the latest
    /// lifecycle event or validity end. Every retained run protects its record regardless of status. Audit
    /// rows are never deleted or rewritten; a digest-only purge event is appended atomically.
    ///
    /// # Errors
    /// Returns an error if selection, deletion or the audit-chain append fails.
    pub async fn sweep_authorizations(&self, now: Timestamp) -> Result<u64, StoreError> {
        let cutoff = now.checked_sub_signed(Duration::days(1_096)).ok_or_else(|| {
            StoreError::Backend("authorization retention horizon is out of range".to_owned())
        })?;
        let mut tx = self.pg.pool.begin().await.map_err(db)?;
        let rows = sqlx::query(
            "SELECT a.record_id, a.tenant_id, a.body_digest FROM authorization_records a \
             WHERE GREATEST(a.valid_to, a.created_at, a.verified_at, a.revoked_at) <= $1 \
             AND NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.authorization_record_id = a.record_id) \
             AND NOT EXISTS (SELECT 1 FROM safety_decisions d WHERE d.authorization_record_id = a.record_id) \
             ORDER BY a.valid_to, a.record_id LIMIT 100 FOR UPDATE OF a SKIP LOCKED",
        )
        .bind(cutoff)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        for row in &rows {
            let id: uuid::Uuid = get(row, "record_id")?;
            let tenant: uuid::Uuid = get(row, "tenant_id")?;
            let digest: Vec<u8> = get(row, "body_digest")?;
            sqlx::query("DELETE FROM authorization_records WHERE record_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            append_audit_on(
                &mut tx, Some(tenant), None, "retention_sweeper", "authorization.purged",
                serde_json::json!({ "record_id": id, "bodyDigest": Digest(digest.try_into().map_err(|_| StoreError::Serialization("invalid authorization body digest length".to_owned()))?) }),
            ).await?;
        }
        tx.commit().await.map_err(db)?;
        u64::try_from(rows.len()).map_err(|error| StoreError::Backend(error.to_string()))
    }

    /// Delete only the objects of `run` through the attached [`ArtifactReaper`] (RB-08 step 3:
    /// content first, rows afterwards). Returns the uses removed; `0` without a store.
    ///
    /// # Errors
    ///
    /// Returns an error if the artifact reaper fails.
    pub async fn purge_run_objects(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let tenant: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT tenant_id FROM crawl_runs WHERE run_id=$1")
                .bind(run.0)
                .fetch_optional(&self.pg.pool)
                .await
                .map_err(db)?;
        let mut removed = match tenant {
            Some(tenant) => self.purge_archives(TenantId(tenant), run.0).await?,
            None => 0,
        };
        if let Some(store) = &self.artifacts {
            removed = removed.saturating_add(store.purge_run(run).await?);
        }
        Ok(removed)
    }

    async fn purge_archives(&self, tenant: TenantId, export: uuid::Uuid) -> Result<u64, StoreError> {
        self.pg.erase(tenant, export).await?;
        let mut removed = 0u64;
        loop {
            let artifacts = self.pg.erased_artifacts(tenant, 64).await?;
            if artifacts.is_empty() {
                return Ok(removed);
            }
            let store = self.artifacts.as_ref().ok_or_else(|| {
                StoreError::Backend("archive erasure requires the configured artifact reaper".to_owned())
            })?;
            for artifact in artifacts {
                removed = removed.saturating_add(store.erase_artifact(&artifact).await?);
                self.pg.acknowledge_erased(tenant, &artifact).await?;
            }
        }
    }

    /// Delete everything belonging to `run`, leaf tables first, then record the purge in
    /// the audit chain. Resumable: a failed purge can simply be run again.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::NotFound`] if `run` does not exist, or an error if the artifact
    /// reaper, a delete batch or the audit append fails.
    pub async fn purge_run(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let tenant: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT tenant_id FROM crawl_runs WHERE run_id = $1")
                .bind(run.0)
                .fetch_optional(&self.pg.pool)
                .await
                .map_err(db)?;
        let tenant = tenant.ok_or_else(|| crate::error::not_found("crawl_run", run))?;
        self.purge_archives(TenantId(tenant), run.0).await?;
        if let Some(store) = &self.artifacts {
            store.purge_run(run).await?;
        }
        let pool = &self.pg.pool;
        let mut total = 0u64;
        for table in [
            "webhook_deliveries",
            "crawl_events",
            "approvals",
            "workflow_runs",
            "checkpoints",
            "transitions",
        ] {
            total += delete_run_rows(&self.pg, table, run).await?;
        }
        loop {
            let n = sqlx::query(
                "DELETE FROM traffic_events WHERE (event_id, occurred_at) IN \
                 (SELECT event_id, occurred_at FROM traffic_events WHERE run_id = $1 LIMIT $2)",
            )
            .bind(run.0)
            .bind(PURGE_BATCH)
            .execute(pool)
            .await
            .map_err(db)?
            .rows_affected();
            total += n;
            if n == 0 {
                break;
            }
        }
        for table in [
            "network_epochs",
            "enablement_edges",
            "actions",
            "action_contexts",
            "safety_decisions",
            "model_decisions",
        ] {
            total += delete_run_rows(&self.pg, table, run).await?;
        }
        total += sqlx::query("DELETE FROM state_cluster_membership WHERE state_id IN (SELECT state_id FROM states WHERE run_id = $1)")
            .bind(run.0)
            .execute(pool)
            .await
            .map_err(db)?
            .rows_affected();
        total += sqlx::query("DELETE FROM state_clusters WHERE run_id = $1")
            .bind(run.0)
            .execute(pool)
            .await
            .map_err(db)?
            .rows_affected();
        for table in ["identity_aliases", "elements", "states", "pages", "page_captures"] {
            total += delete_run_rows(&self.pg, table, run).await?;
        }
        sqlx::query("UPDATE url_frontier SET parent_id = NULL WHERE run_id = $1")
            .bind(run.0)
            .execute(pool)
            .await
            .map_err(db)?;
        for table in ["url_frontier", "origin_leases", "artifacts", "crawl_sessions"] {
            total += delete_run_rows(&self.pg, table, run).await?;
        }
        sqlx::query("DELETE FROM idempotency_keys WHERE run_id = $1")
            .bind(run.0)
            .execute(pool)
            .await
            .map_err(db)?;
        total += sqlx::query("DELETE FROM crawl_runs WHERE run_id = $1")
            .bind(run.0)
            .execute(pool)
            .await
            .map_err(db)?
            .rows_affected();
        append_audit(
            &self.pg,
            Some(tenant),
            Some(run.0),
            "retention_sweeper",
            "run.purged",
            serde_json::json!({ "run_id": run.0, "rows_deleted": total }),
        )
        .await?;
        Ok(total)
    }
}

/// `table` is `'static` so only compile-time literals can name the target of the
/// interpolated `DELETE`.
async fn delete_run_rows(pg: &Pg, table: &'static str, run: CrawlRunId) -> Result<u64, StoreError> {
    let mut total = 0;
    loop {
        let sql = format!("DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE run_id = $1 LIMIT {PURGE_BATCH})");
        let n = sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(run.0)
            .execute(&pg.pool)
            .await
            .map_err(db)?
            .rows_affected();
        total += n;
        if n == 0 {
            return Ok(total);
        }
    }
}

async fn delete_batched(
    pg: &Pg,
    table: &'static str,
    predicate: &'static str,
    at: Option<Timestamp>,
) -> Result<u64, StoreError> {
    let mut total = 0;
    loop {
        let sql = format!("DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE {predicate} LIMIT {PURGE_BATCH})");
        let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
        if let Some(at) = at {
            q = q.bind(at);
        }
        let n = q.execute(&pg.pool).await.map_err(db)?.rows_affected();
        total += n;
        if n == 0 {
            return Ok(total);
        }
    }
}

/// Append one hash-chained row to `audit_events`: `entry_hash` covers the
/// previous hash and the canonical entry. Serialized by an advisory lock.
///
/// # Errors
///
/// Returns an error if the transaction, the advisory lock, the chain-head read or the insert
/// fails.
pub async fn append_audit(
    pg: &Pg,
    tenant: Option<uuid::Uuid>,
    run: Option<uuid::Uuid>,
    actor: &str,
    event: &str,
    subject: serde_json::Value,
) -> Result<(), StoreError> {
    let confidential = if let Some(run) = run {
        sqlx::query_scalar::<_, bool>("SELECT retention_mode = 'zdr' FROM crawl_runs WHERE run_id = $1")
            .bind(run)
            .fetch_optional(&pg.pool)
            .await
            .map_err(db)?
            .unwrap_or(true)
    } else {
        false
    };
    // Hash before chaining: rewriting an audit subject after entry_hash would invalidate
    // historical evidence. A deleted run also has no durable content-retention authority.
    let subject = if confidential {
        serde_json::json!({ "digest": Digest::of("crawlx/zdr-audit-subject/v1", subject.to_string().as_bytes()).to_hex() })
    } else {
        subject
    };
    let mut tx = pg.pool.begin().await.map_err(db)?;
    append_audit_on(&mut tx, tenant, run, actor, event, subject).await?;
    tx.commit().await.map_err(db)
}

pub(crate) async fn append_audit_on(
    connection: &mut PgConnection,
    tenant: Option<uuid::Uuid>,
    run: Option<uuid::Uuid>,
    actor: &str,
    event: &str,
    subject: serde_json::Value,
) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('crawlx_audit_chain'))")
        .execute(&mut *connection)
        .await
        .map_err(db)?;
    let prev: Option<Vec<u8>> = sqlx::query_scalar("SELECT crawlx_audit_head()")
        .fetch_one(&mut *connection)
        .await
        .map_err(db)?;
    let prev = prev.unwrap_or_else(|| vec![0u8; 32]);
    let entry = serde_json::json!({ "tenant": tenant, "run": run, "actor": actor, "event": event, "subject": subject });
    let entry_text = entry.to_string();
    let bytes = [prev.as_slice(), entry_text.as_bytes()].concat();
    let hash = Digest::of("crawlx/audit-chain/v1", &bytes);
    sqlx::query("INSERT INTO audit_events (tenant_id, run_id, actor, event, subject, prev_hash, entry_hash) VALUES ($1, $2, $3, $4, $5, $6, $7)")
        .bind(tenant)
        .bind(run)
        .bind(actor)
        .bind(event)
        .bind(subject)
        .bind(prev)
        .bind(hash.0.to_vec())
        .execute(&mut *connection)
        .await
        .map_err(db)?;
    Ok(())
}

fn first_of_month(ts: Timestamp, add_months: u32) -> Option<NaiveDate> {
    let month0 = i32::try_from(ts.month0()).ok()?;
    let months = i32::try_from(add_months).ok()?;
    let total = ts
        .year()
        .checked_mul(12)?
        .checked_add(month0)?
        .checked_add(months)?;
    NaiveDate::from_ymd_opt(
        total.div_euclid(12),
        u32::try_from(total.rem_euclid(12)).ok()? + 1,
        1,
    )
}

/// Create the monthly `traffic_events` partitions for the month of `from` and the
/// `months_ahead` following months. Rows that already landed in the default partition
/// for a month are moved into its new partition. Returns the partition names created.
///
/// # Errors
///
/// Returns [`StoreError::Backend`] if a month is outside the representable date range, or an
/// error if a partition lookup, move or creation fails.
pub async fn ensure_traffic_partitions(
    pg: &Pg,
    from: Timestamp,
    months_ahead: u32,
) -> Result<Vec<String>, StoreError> {
    let mut created = Vec::new();
    for offset in 0..=months_ahead {
        let (Some(start), Some(end)) = (
            first_of_month(from, offset),
            offset.checked_add(1).and_then(|next| first_of_month(from, next)),
        ) else {
            return Err(StoreError::Backend("partition month out of range".to_owned()));
        };
        let name = format!("traffic_events_{}{:02}", start.year(), start.month());
        let mut tx = pg.pool.begin().await.map_err(db)?;
        let exists: Option<String> = sqlx::query_scalar("SELECT to_regclass($1)::text")
            .bind(&name)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if exists.is_some() {
            continue;
        }
        move_and_create_partition(&mut tx, &name, start, end).await?;
        tx.commit().await.map_err(db)?;
        created.push(name);
    }
    Ok(created)
}

async fn move_and_create_partition(
    conn: &mut PgConnection,
    name: &str,
    start: NaiveDate,
    end: NaiveDate,
) -> Result<(), StoreError> {
    // Interpolated: `name` (built by `ensure_traffic_partitions` from integer year/month only)
    // and `lo`/`hi` (chrono-formatted dates). No request or tenant data reaches these statements.
    let (lo, hi) = (start.format("%Y-%m-%d"), end.format("%Y-%m-%d"));
    let stmts = [
        format!(
            "CREATE TEMP TABLE _tev_moved ON COMMIT DROP AS WITH d AS (DELETE FROM traffic_events_default \
             WHERE occurred_at >= '{lo}' AND occurred_at < '{hi}' RETURNING *) SELECT * FROM d"
        ),
        format!("CREATE TABLE {name} PARTITION OF traffic_events FOR VALUES FROM ('{lo}') TO ('{hi}')"),
        // migration 0012: a partition accessed directly is filtered like its parent
        format!("ALTER TABLE {name} ENABLE ROW LEVEL SECURITY"),
        format!(
            "CREATE POLICY tenant_isolation ON {name} USING (EXISTS (SELECT 1 FROM crawl_runs r WHERE r.run_id = {name}.run_id))"
        ),
        "INSERT INTO traffic_events OVERRIDING SYSTEM VALUE SELECT * FROM _tev_moved".to_owned(),
    ];
    for sql in stmts {
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .execute(&mut *conn)
            .await
            .map_err(db)?;
    }
    Ok(())
}

/// First instant of the month after `ts` (exposed for tests and the retention worker).
#[must_use]
pub fn next_month_start(ts: Timestamp) -> Option<Timestamp> {
    let d = first_of_month(ts, 1)?;
    Utc.from_utc_datetime(&d.and_hms_opt(0, 0, 0)?).into()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn ts(y: i32, m: u32, d: u32) -> Timestamp {
        Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
    }

    #[test]
    fn zdr_gate_refuses_everything_but_metadata() {
        assert!(zdr_write_gate(RetentionMode::Zdr, Sensitivity::Metadata).is_ok());
        for c in [
            Sensitivity::Content,
            Sensitivity::Sensitive,
            Sensitivity::CredentialBearing,
        ] {
            assert!(
                matches!(
                    zdr_write_gate(RetentionMode::Zdr, c),
                    Err(StoreError::RetentionDenied(_))
                ),
                "{c:?}"
            );
            assert!(zdr_write_gate(RetentionMode::Standard, c).is_ok());
            assert!(zdr_write_gate(RetentionMode::Extended, c).is_ok());
        }
    }

    #[test]
    fn expiry_follows_class() {
        let now = ts(2026, 10, 16);
        assert_eq!(
            artifact_expiry(
                Sensitivity::Metadata,
                "application/json",
                RetentionMode::Standard,
                7,
                now
            ),
            None
        );
        assert_eq!(
            artifact_expiry(Sensitivity::Content, "text/html", RetentionMode::Standard, 7, now),
            Some(now + Duration::days(7))
        );
        assert_eq!(
            artifact_expiry(
                Sensitivity::Sensitive,
                "image/webp",
                RetentionMode::Standard,
                7,
                now
            ),
            Some(now + Duration::days(3))
        );
        assert_eq!(
            artifact_expiry(
                Sensitivity::Sensitive,
                "application/json",
                RetentionMode::Standard,
                7,
                now
            ),
            Some(now + Duration::days(7))
        );
        assert_eq!(
            artifact_expiry(
                Sensitivity::CredentialBearing,
                "application/octet-stream",
                RetentionMode::Standard,
                7,
                now
            ),
            Some(now + Duration::days(1))
        );
    }

    #[test]
    fn month_arithmetic_wraps_years() {
        assert_eq!(
            first_of_month(ts(2026, 12, 31), 1),
            NaiveDate::from_ymd_opt(2027, 1, 1)
        );
        assert_eq!(
            first_of_month(ts(2026, 11, 5), 14),
            NaiveDate::from_ymd_opt(2028, 1, 1)
        );
        assert_eq!(
            next_month_start(ts(2026, 10, 16)).unwrap(),
            Utc.with_ymd_and_hms(2026, 11, 1, 0, 0, 0).unwrap()
        );
    }
}
