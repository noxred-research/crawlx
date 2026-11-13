//! Retention and ZDR.
//!
//! * [`zdr_write_gate`] – the durable store refuses `content`, `sensitive` and
//!   `credential_bearing` objects for runs in `zdr` mode.
//! * [`artifact_expiry`] – per-class expiry horizon.
//! * [`RetentionSweeper`] – deletes expired artifacts and pages and purges runs
//!   whose `expires_at` has passed or that have `purge_requested_at` set, leaf
//!   tables first in batches of 10 000 rows, writing one hash-chained
//!   `audit_events` row per purged run.
//! * [`run_sweep_loop`] / [`RetentionSweeper::run_loop`] – the scheduled sweeper: one pass per
//!   interval, cancellable, never overlapping.
//! * [`ensure_traffic_partitions`] – monthly `traffic_events` partitions created ahead of time.

use crate::artifacts::{ArtifactReaper, LiveArtifacts};
use crate::backend::strategy::{AuditEntry, Conn};
use crate::backend::{Backend, BackendKind, Dialect, PgBackend, RowLock};
use crate::error::db;
use crate::repos::effects::settle_run;
use crate::sql::{stmt, Sql, SqlRow, Stmt};
use crate::store::{Pg, Store};
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
use std::future::Future;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio_util::sync::CancellationToken;

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
pub struct RetentionSweeper<B: Sql = PgBackend> {
    store: Store<B>,
    artifacts: Option<Arc<dyn ArtifactReaper>>,
    orphan_grace: Option<Duration>,
    /// Non-metadata artifacts of ZDR runs already counted under `crawlx.zdr.violations`
    /// (RB-08); a row that survives several sweeps is one violation, not one per sweep.
    zdr_seen: Mutex<BTreeSet<ArtifactId>>,
}

impl<B: Sql> RetentionSweeper<B> {
    /// Sweeper over `store` with no artifact store attached.
    #[must_use]
    pub fn new(store: Store<B>) -> Self {
        Self {
            store,
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
        let rows = stmt!(
            B,
            "SELECT artifact_id, object_key FROM artifacts WHERE deleted_at IS NULL"
        )
        .fetch_all_pool(&self.store.pool)
        .await?;
        let mut live = LiveArtifacts::default();
        for r in &rows {
            live.ids.insert(crawlx_core::ArtifactId(r.uuid("artifact_id")?));
            live.object_keys.insert(r.text("object_key")?);
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
        let rows = stmt!(
            B,
            "SELECT a.artifact_id FROM artifacts a JOIN crawl_runs r ON r.run_id = a.run_id \
             WHERE r.retention_mode = 'zdr' AND a.sensitivity <> 'metadata' AND a.deleted_at IS NULL \
             ORDER BY a.artifact_id"
        )
        .fetch_all_pool(&self.store.pool)
        .await?;
        rows.iter()
            .map(|r| r.uuid("artifact_id").map(ArtifactId))
            .collect()
    }

    /// Artifacts past `expires_at` that are still present, grouped by the owning run's
    /// `retention_mode` (`standard`, `extended`, `zdr`).
    ///
    /// # Errors
    ///
    /// Returns an error if the query fails.
    pub async fn overdue_artifacts(&self, now: Timestamp) -> Result<BTreeMap<String, u64>, StoreError> {
        let rows = stmt!(
            B,
            "SELECT r.retention_mode::text AS kind, count(*) AS n FROM artifacts a \
             JOIN crawl_runs r ON r.run_id = a.run_id \
             WHERE a.deleted_at IS NULL AND a.expires_at IS NOT NULL AND a.expires_at <= $1 GROUP BY 1"
        )
        .ts(now)
        .fetch_all_pool(&self.store.pool)
        .await?;
        let mut out = BTreeMap::new();
        for r in &rows {
            let kind = r.text("kind")?;
            let n = r.i64("n")?;
            out.insert(kind, u64::try_from(n).unwrap_or(0));
        }
        Ok(out)
    }

    async fn sweep_inner(&self, now: Timestamp) -> Result<SweepReport, StoreError> {
        self.store.reap_profiles().await?;
        self.store.reap_profile_directories().await?;
        // Metadata expiry shares the existing sweeper cadence, not another background loop.
        let _report_rows = self.store.purge_expired_report_history().await?;
        let _graph_rows = self.store.purge_expired_url_graph().await?;
        let mut report = SweepReport::default();
        // Revoke dependency closure before deleting source content. Each object removal is
        // acknowledged separately, so cancellation leaves a resumable erasure cursor.
        // Changed source authority revokes derived objects even before the old export deadline.
        let expired = expired_exports::<B>(&self.store, now).await?;
        for (tenant, export) in expired {
            report.artifacts_deleted = report
                .artifacts_deleted
                .saturating_add(self.purge_archives(tenant, export).await?);
        }
        // A source that expires while finalizing cannot resume from deleted content.
        // Close its durable lifecycle rather than strand a nonterminal run forever.
        self.fail_expired_exporting_runs(now).await?;
        if let Some(store) = &self.artifacts {
            report.artifacts_deleted = report
                .artifacts_deleted
                .saturating_add(store.reap_expired(now).await?);
        }
        if let Some(grace) = self.orphan_grace {
            report.orphans_collected = self.collect_orphans(now, grace).await?;
        }
        report.pages_deleted =
            delete_batched::<B>(&self.store, "pages", "expires_at <= $1", Some(now)).await?;
        report.rows_deleted = report.rows_deleted.saturating_add(
            delete_batched::<B>(
                &self.store,
                "page_captures",
                "expires_at <= $1 OR run_id IN (SELECT run_id FROM crawl_runs WHERE expires_at <= $1 OR retention_mode='zdr')",
                Some(now),
            )
            .await?,
        );
        report.rows_deleted = report.rows_deleted.saturating_add(
            delete_batched::<B>(&self.store, "adaptive_selectors", "expires_at <= $1", Some(now)).await?,
        );
        let runs = stmt!(
            B,
            "SELECT run_id FROM crawl_runs WHERE status::text IN ('completed','failed','cancelled') \
             AND ((expires_at IS NOT NULL AND expires_at <= $1) OR purge_requested_at IS NOT NULL) ORDER BY run_id"
        )
        .ts(now)
        .fetch_all_pool(&self.store.pool)
        .await?;
        for r in &runs {
            let run = CrawlRunId(r.uuid("run_id")?);
            report.rows_deleted += self.purge_run(run).await?;
            report.runs_purged += 1;
        }
        report.authorizations_deleted = self.sweep_authorizations(now).await?;
        Ok(report)
    }

    /// Mark runs whose source expired while finalizing as failed, together with the credential
    /// revocation their terminal status implies.
    async fn fail_expired_exporting_runs(&self, now: Timestamp) -> Result<(), StoreError> {
        let alias = alias_kw::<B>();
        let condition = "r.expires_at<=$1 AND r.status NOT IN ('completed','failed','cancelled') \
             AND EXISTS(SELECT 1 FROM archive_exports e WHERE e.tenant_id=r.tenant_id AND e.run_id=r.run_id)";
        let update = format!(
            "UPDATE crawl_runs{alias}r SET status='failed',terminal_reason='fatal_error',finished_at=$1 WHERE {condition}"
        );
        if !crate::repos::effects::in_rust::<B>() {
            // PostgreSQL revokes the credentials in the same statement through its triggers
            Stmt::<B>::dynamic(&update)
                .ts(now)
                .execute_write(&self.store.pool)
                .await?;
            return Ok(());
        }
        let mut tx = self.store.begin_write().await?;
        let runs = Stmt::<B>::dynamic(&format!("SELECT r.run_id FROM crawl_runs r WHERE {condition}"))
            .ts(now)
            .fetch_all(tx.conn())
            .await?;
        Stmt::<B>::dynamic(&update).ts(now).execute(tx.conn()).await?;
        for run in &runs {
            settle_run::<B>(tx.conn(), CrawlRunId(run.uuid("run_id")?)).await?;
        }
        tx.commit().await
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
        let mut tx = self.store.begin_write().await?;
        let latest = <B::Dialect as Dialect>::greatest_ignoring_null(&[
            "a.valid_to",
            "a.created_at",
            "a.verified_at",
            "a.revoked_at",
        ]);
        let lock = if B::KIND == BackendKind::Postgres {
            " FOR UPDATE OF a SKIP LOCKED"
        } else {
            <B::Dialect as Dialect>::row_lock(RowLock::UpdateSkipLocked)
        };
        let rows = stmt!(
            B,
            format!(
                "SELECT a.record_id, a.tenant_id, a.body_digest FROM authorization_records a \
                 WHERE {latest} <= $1 \
                 AND NOT EXISTS (SELECT 1 FROM crawl_runs r WHERE r.authorization_record_id = a.record_id) \
                 AND NOT EXISTS (SELECT 1 FROM safety_decisions d WHERE d.authorization_record_id = a.record_id) \
                 ORDER BY a.valid_to, a.record_id LIMIT 100{lock}"
            )
        )
        .ts(cutoff)
        .fetch_all(tx.conn())
        .await?;
        for row in &rows {
            let id = row.uuid("record_id")?;
            let tenant = row.uuid("tenant_id")?;
            let digest = row.bytes("body_digest")?;
            stmt!(B, "DELETE FROM authorization_records WHERE record_id = $1")
                .uuid(id)
                .execute(tx.conn())
                .await?;
            append_audit_in::<B>(
                tx.conn(), Some(tenant), None, "retention_sweeper", "authorization.purged",
                serde_json::json!({ "record_id": id, "bodyDigest": Digest(digest.try_into().map_err(|_| StoreError::Serialization("invalid authorization body digest length".to_owned()))?) }),
            ).await?;
        }
        tx.commit().await?;
        u64::try_from(rows.len()).map_err(|error| StoreError::Backend(error.to_string()))
    }

    /// Close HEAD publication before physically erasing a run's objects.
    ///
    /// This update waits for fenced request transactions holding the run row.
    /// Its committed terminal status then prevents later HEAD publication.
    /// No pooled connection remains held during artifact erasure.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] for a missing run, or a database error.
    pub async fn begin_run_erasure(&self, run: CrawlRunId) -> Result<TenantId, StoreError> {
        let clock = <B::Dialect as Dialect>::clock_timestamp();
        let update = format!(
            "UPDATE crawl_runs SET status=CASE \
             WHEN status IN ('completed','failed','cancelled') THEN status ELSE 'cancelled' END, \
             terminal_reason=COALESCE(terminal_reason,'cancelled'), \
             finished_at=COALESCE(finished_at,{clock}) \
             WHERE run_id=$1"
        );
        let mut tx = self.store.begin_write().await?;
        let tenant = if <B::Dialect as Dialect>::UPDATE_RETURNING {
            stmt!(B, format!("{update} RETURNING tenant_id"))
                .uuid(run.0)
                .fetch_optional(tx.conn())
                .await?
                .map(|row| row.uuid("tenant_id"))
                .transpose()?
        } else if stmt!(B, update).uuid(run.0).execute(tx.conn()).await? == 0 {
            None
        } else {
            stmt!(B, "SELECT tenant_id FROM crawl_runs WHERE run_id = $1")
                .uuid(run.0)
                .fetch_optional(tx.conn())
                .await?
                .map(|row| row.uuid("tenant_id"))
                .transpose()?
        };
        if tenant.is_some() {
            settle_run::<B>(tx.conn(), run).await?;
        }
        tx.commit().await?;
        tenant
            .map(TenantId)
            .ok_or_else(|| crate::error::not_found("crawl_run", run))
    }

    /// Delete only the objects of `run` through the attached [`ArtifactReaper`] (RB-08 step 3:
    /// content first, rows afterwards). Returns the uses removed; `0` without a store.
    ///
    /// # Errors
    ///
    /// Returns an error if the artifact reaper fails.
    pub async fn purge_run_objects(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let (mut removed, tenant) = match self.begin_run_erasure(run).await {
            Ok(tenant) => (self.purge_archives(tenant, run.0).await?, Some(tenant)),
            Err(StoreError::NotFound { .. }) => (0, None),
            Err(error) => return Err(error),
        };
        if let (Some(buffer), Some(tenant)) = (&self.store.delivery, tenant) {
            removed = removed.saturating_add(buffer.purge_run(tenant, run).await?);
        }
        if let Some(store) = &self.artifacts {
            removed = removed.saturating_add(store.purge_run(run).await?);
        }
        Ok(removed)
    }

    async fn purge_archives(&self, tenant: TenantId, export: uuid::Uuid) -> Result<u64, StoreError> {
        ArchiveRepo::erase(&self.store, tenant, export).await?;
        let mut removed = 0u64;
        loop {
            let artifacts = ArchiveRepo::erased_artifacts(&self.store, tenant, 64).await?;
            if artifacts.is_empty() {
                return Ok(removed);
            }
            let store = self.artifacts.as_ref().ok_or_else(|| {
                StoreError::Backend("archive erasure requires the configured artifact reaper".to_owned())
            })?;
            for artifact in artifacts {
                removed = removed.saturating_add(store.erase_artifact(&artifact).await?);
                ArchiveRepo::acknowledge_erased(&self.store, tenant, &artifact).await?;
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
        let tenant = self.begin_run_erasure(run).await?.0;
        self.purge_archives(TenantId(tenant), run.0).await?;
        if let Some(buffer) = &self.store.delivery {
            buffer.purge_run(TenantId(tenant), run).await?;
        }
        if let Some(store) = &self.artifacts {
            store.purge_run(run).await?;
        }
        let pool = &self.store.pool;
        let mut total = 0u64;
        for table in [
            "webhook_deliveries",
            "crawl_events",
            "approvals",
            "workflow_runs",
            "checkpoints",
            "transitions",
            "traffic_events",
            "network_epochs",
            "enablement_edges",
            "actions",
            "action_contexts",
            "safety_decisions",
            "model_decisions",
        ] {
            total += delete_run_rows::<B>(&self.store, table, run).await?;
        }
        total += stmt!(
            B,
            "DELETE FROM state_cluster_membership WHERE state_id IN (SELECT state_id FROM states WHERE run_id = $1)"
        )
        .uuid(run.0)
        .execute_write(pool)
        .await?;
        total += stmt!(B, "DELETE FROM state_clusters WHERE run_id = $1")
            .uuid(run.0)
            .execute_write(pool)
            .await?;
        for table in ["identity_aliases", "elements", "states", "pages", "page_captures"] {
            total += delete_run_rows::<B>(&self.store, table, run).await?;
        }
        stmt!(B, "UPDATE url_frontier SET parent_id = NULL WHERE run_id = $1")
            .uuid(run.0)
            .execute_write(pool)
            .await?;
        for table in ["url_frontier", "origin_leases", "artifacts", "crawl_sessions"] {
            total += delete_run_rows::<B>(&self.store, table, run).await?;
        }
        stmt!(B, "DELETE FROM idempotency_keys WHERE run_id = $1")
            .uuid(run.0)
            .execute_write(pool)
            .await?;
        // records the AI endpoints keep per run (extractions, triage, findings, summaries)
        let key_col = if B::KIND == BackendKind::MariaDb {
            "`key`"
        } else {
            "key"
        };
        for kind in crate::intel::RUN_SETTING_KINDS {
            total += Stmt::<B>::dynamic(&format!(
                "DELETE FROM tenant_settings WHERE tenant_id = $1 AND {key_col} = $2"
            ))
            .uuid(tenant)
            .text(&crate::intel::run_setting_key(kind, run))
            .execute_write(pool)
            .await?;
        }
        total += stmt!(B, "DELETE FROM crawl_runs WHERE run_id = $1")
            .uuid(run.0)
            .execute_write(pool)
            .await?;
        append_audit(
            &self.store,
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

/// ` ` before a table alias on PostgreSQL (as the statements always spelled it), ` AS ` on
/// the engines whose `UPDATE` requires the keyword.
const fn alias_kw<B: Backend>() -> &'static str {
    if matches!(B::KIND, BackendKind::Postgres) {
        " "
    } else {
        " AS "
    }
}

/// Exports whose objects must be erased: past their deadline, whose source custody changed,
/// or already deleted with leftovers. At most 64, oldest first.
async fn expired_exports<B: Sql>(
    store: &Store<B>,
    now: Timestamp,
) -> Result<Vec<(TenantId, uuid::Uuid)>, StoreError> {
    let rows = if B::KIND == BackendKind::Postgres {
        stmt!(
            B,
            "SELECT e.tenant_id,e.export_id FROM archive_exports e \
             WHERE (e.state<>'deleted' AND (e.expires_at<=$1 OR EXISTS( \
               SELECT 1 FROM archive_records s WHERE s.tenant_id=e.tenant_id AND s.export_id=e.export_id \
               AND s.payload->'custody'->>'sensitivity'='sensitive' AND NOT EXISTS( \
                 SELECT 1 FROM artifacts a WHERE a.artifact_id=(s.payload->'sourceArtifact'->>'id')::uuid \
                 AND a.tenant_id=e.tenant_id AND a.run_id=e.run_id AND a.sensitivity='sensitive' \
                 AND a.content_type=s.payload->>'mime' \
                 AND a.content_digest=decode(s.payload->'sourceArtifact'->>'digest','hex') \
                 AND a.expires_at=(s.payload->'custody'->>'expiresAt')::timestamptz \
                 AND a.expires_at>$1 AND a.deleted_at IS NULL)))) OR (e.state='deleted' AND ( \
               e.payload->'artifact'<>'null'::jsonb OR e.payload->'index'<>'null'::jsonb OR \
               EXISTS(SELECT 1 FROM archive_records r WHERE r.tenant_id=e.tenant_id AND r.export_id=e.export_id))) \
             ORDER BY e.expires_at,e.export_id LIMIT 64"
        )
    } else {
        // The probes into `payload` are columns of the new engines' schemas.
        stmt!(
            B,
            "SELECT e.tenant_id,e.export_id FROM archive_exports e \
             WHERE (e.state<>'deleted' AND (e.expires_at<=$1 OR EXISTS( \
               SELECT 1 FROM archive_records s WHERE s.tenant_id=e.tenant_id AND s.export_id=e.export_id \
               AND s.custody_sensitivity='sensitive' AND NOT EXISTS( \
                 SELECT 1 FROM artifacts a WHERE a.artifact_id=s.source_artifact_id \
                 AND a.tenant_id=e.tenant_id AND a.run_id=e.run_id AND a.sensitivity='sensitive' \
                 AND a.content_type=s.source_mime AND a.content_digest=s.source_digest \
                 AND a.expires_at=s.custody_expires_at \
                 AND a.expires_at>$1 AND a.deleted_at IS NULL)))) OR (e.state='deleted' AND ( \
               e.package_artifact_id IS NOT NULL OR e.index_artifact_id IS NOT NULL OR \
               EXISTS(SELECT 1 FROM archive_records r WHERE r.tenant_id=e.tenant_id AND r.export_id=e.export_id))) \
             ORDER BY (e.expires_at IS NULL),e.expires_at,e.export_id LIMIT 64"
        )
    }
    .ts(now)
    .fetch_all_pool(&store.pool)
    .await?;
    rows.iter()
        .map(|row| Ok((TenantId(row.uuid("tenant_id")?), row.uuid("export_id")?)))
        .collect()
}

/// Shortest period between two passes of [`run_sweep_loop`]; a smaller request is raised to it.
pub const MIN_SWEEP_INTERVAL: StdDuration = StdDuration::from_secs(1);
/// Longest one pass of [`run_sweep_loop`] may run before it is abandoned and counted as a failure.
/// A pass is resumable, so the next one picks up where the abandoned one stopped.
pub const MAX_SWEEP_PASS: StdDuration = StdDuration::from_secs(3_600);

/// Schedule of [`run_sweep_loop`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
#[must_use]
pub struct SweepLoopConfig {
    /// Period between pass starts; passes never overlap and a slow pass delays the next one
    /// instead of causing a burst of catch-up passes.
    pub interval: StdDuration,
    /// Stop after this many finished passes (successful or failed); `None` runs until cancelled.
    pub max_passes: Option<u64>,
}

impl SweepLoopConfig {
    /// Run every `interval` (at least [`MIN_SWEEP_INTERVAL`]) until cancelled.
    pub fn every(interval: StdDuration) -> Self {
        Self {
            interval: interval.max(MIN_SWEEP_INTERVAL),
            max_passes: None,
        }
    }

    /// Also stop after `passes` finished passes.
    pub const fn with_max_passes(mut self, passes: u64) -> Self {
        self.max_passes = Some(passes);
        self
    }
}

/// What a finished [`run_sweep_loop`] did.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[non_exhaustive]
pub struct SweepLoopSummary {
    /// Passes that ran to an end, successful or failed.
    pub passes: u64,
    /// Passes that failed or exceeded [`MAX_SWEEP_PASS`].
    pub failures: u64,
}

/// Run `pass` once immediately and then every `config.interval` until `cancel` fires or
/// `config.max_passes` is reached.
///
/// Cancellation is checked between passes and while one runs: an in-flight pass is dropped at
/// its next await point. That is safe because a sweep is resumable (each object removal is
/// acknowledged on its own and database statements are batched), so the next process or pass
/// repeats what was cut short. A failed pass never ends the loop: the failure is logged
/// (error text only, never row content) and counted in the summary, and the next pass retries.
/// `observe` sees every finished pass (`Ok` report, or the failure) in order.
pub async fn run_sweep_loop<F, Fut, O>(
    config: SweepLoopConfig,
    cancel: &CancellationToken,
    mut pass: F,
    mut observe: O,
) -> SweepLoopSummary
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<SweepReport, StoreError>>,
    O: FnMut(u64, &Result<SweepReport, StoreError>),
{
    let mut summary = SweepLoopSummary::default();
    let mut ticker = tokio::time::interval(config.interval.max(MIN_SWEEP_INTERVAL));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }
        let outcome = tokio::select! {
            biased;
            () = cancel.cancelled() => break,
            r = tokio::time::timeout(MAX_SWEEP_PASS, pass()) => r,
        };
        summary.passes = summary.passes.saturating_add(1);
        let result = outcome.unwrap_or_else(|_| {
            Err(StoreError::Backend(
                "retention sweep pass exceeded its time limit".to_owned(),
            ))
        });
        match &result {
            Ok(report) => tracing::info!(
                pass = summary.passes,
                artifacts_deleted = report.artifacts_deleted,
                orphans_collected = report.orphans_collected,
                pages_deleted = report.pages_deleted,
                runs_purged = report.runs_purged,
                rows_deleted = report.rows_deleted,
                authorizations_deleted = report.authorizations_deleted,
                "retention sweep finished"
            ),
            Err(error) => {
                summary.failures = summary.failures.saturating_add(1);
                tracing::warn!(pass = summary.passes, %error, "retention sweep failed; the next pass retries");
            }
        }
        observe(summary.passes, &result);
        if config.max_passes.is_some_and(|max| summary.passes >= max) {
            break;
        }
    }
    summary
}

impl<B: Sql> RetentionSweeper<B> {
    /// [`run_sweep_loop`] over this sweeper, each pass stamped with the database clock.
    pub async fn run_loop<O>(
        &self,
        config: SweepLoopConfig,
        cancel: &CancellationToken,
        observe: O,
    ) -> SweepLoopSummary
    where
        O: FnMut(u64, &Result<SweepReport, StoreError>),
    {
        run_sweep_loop(
            config,
            cancel,
            || async {
                let now = db_now::<B>(&self.store).await?;
                self.sweep(now).await
            },
            observe,
        )
        .await
    }
}

/// The engine's own clock, as `SELECT now`.
async fn db_now<B: Sql>(store: &Store<B>) -> Result<Timestamp, StoreError> {
    stmt!(B, format!("SELECT {} AS v", <B::Dialect as Dialect>::now()))
        .fetch_one_pool(&store.pool)
        .await?
        .ts("v")
}

/// One bounded `DELETE` of at most [`PURGE_BATCH`] rows of `table` matching `predicate`.
///
/// PostgreSQL addresses the rows by `ctid`, SQLite by `rowid`; MariaDB limits the `DELETE`
/// itself. `table` and `predicate` are compile-time literals.
fn batch_delete_sql<B: Backend>(table: &'static str, predicate: &str) -> String {
    match B::KIND {
        BackendKind::Postgres => format!(
            "DELETE FROM {table} WHERE ctid IN (SELECT ctid FROM {table} WHERE {predicate} LIMIT {PURGE_BATCH})"
        ),
        BackendKind::MariaDb => format!("DELETE FROM {table} WHERE {predicate} LIMIT {PURGE_BATCH}"),
        _ => format!(
            "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {predicate} LIMIT {PURGE_BATCH})"
        ),
    }
}

/// `table` is `'static` so only compile-time literals can name the target of the
/// interpolated `DELETE`.
async fn delete_run_rows<B: Sql>(
    store: &Store<B>,
    table: &'static str,
    run: CrawlRunId,
) -> Result<u64, StoreError> {
    let mut total = 0;
    loop {
        let n = if table == "traffic_events" && B::KIND == BackendKind::Postgres {
            // a partitioned table: `ctid` is unique per partition only
            Stmt::<B>::dynamic(
                "DELETE FROM traffic_events WHERE (event_id, occurred_at) IN \
                 (SELECT event_id, occurred_at FROM traffic_events WHERE run_id = $1 LIMIT $2)",
            )
            .uuid(run.0)
            .i64(PURGE_BATCH)
            .execute_write(&store.pool)
            .await?
        } else {
            Stmt::<B>::dynamic(&batch_delete_sql::<B>(table, "run_id = $1"))
                .uuid(run.0)
                .execute_write(&store.pool)
                .await?
        };
        total += n;
        if n == 0 {
            return Ok(total);
        }
    }
}

async fn delete_batched<B: Sql>(
    store: &Store<B>,
    table: &'static str,
    predicate: &'static str,
    at: Option<Timestamp>,
) -> Result<u64, StoreError> {
    let mut total = 0;
    loop {
        let mut statement = Stmt::<B>::dynamic(&batch_delete_sql::<B>(table, predicate));
        if let Some(at) = at {
            statement = statement.ts(at);
        }
        let n = statement.execute_write(&store.pool).await?;
        total += n;
        if n == 0 {
            return Ok(total);
        }
    }
}

/// Append one hash-chained row to `audit_events`: `entry_hash` covers the
/// previous hash and the canonical entry. Serialized by the engine's chain lock (an advisory
/// lock on PostgreSQL, the head row elsewhere).
///
/// # Errors
///
/// Returns an error if the transaction, the chain lock, the chain-head read or the insert
/// fails.
pub async fn append_audit<B: Sql>(
    store: &Store<B>,
    tenant: Option<uuid::Uuid>,
    run: Option<uuid::Uuid>,
    actor: &str,
    event: &str,
    subject: serde_json::Value,
) -> Result<(), StoreError> {
    let confidential = if let Some(run) = run {
        stmt!(
            B,
            "SELECT retention_mode::text AS mode FROM crawl_runs WHERE run_id = $1"
        )
        .uuid(run)
        .fetch_optional_pool(&store.pool)
        .await?
        .map(|row| row.text("mode"))
        .transpose()?
        .is_none_or(|mode| mode == "zdr")
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
    let mut tx = store.begin_write().await?;
    append_audit_in::<B>(tx.conn(), tenant, run, actor, event, subject).await?;
    tx.commit().await
}

/// [`append_audit`] inside the caller's write transaction on `connection`.
///
/// # Errors
///
/// Returns an error if the chain lock, the chain-head read or the insert fails.
pub(crate) async fn append_audit_in<B: Sql>(
    connection: &mut Conn<B>,
    tenant: Option<uuid::Uuid>,
    run: Option<uuid::Uuid>,
    actor: &str,
    event: &str,
    subject: serde_json::Value,
) -> Result<(), StoreError> {
    B::append_audit_chain(
        connection,
        AuditEntry {
            tenant,
            run,
            actor,
            event,
            subject: &subject,
        },
    )
    .await
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
