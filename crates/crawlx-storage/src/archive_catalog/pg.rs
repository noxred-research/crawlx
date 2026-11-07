//! PostgreSQL archive transactions under existing tenant-local pool authority.

use super::{decode, history_key, invalid, json, live, publish_bounds, record_bounds, scope, writer};
use crate::error::db;
use crate::Pg;
use async_trait::async_trait;
use crawlx_core::archive::ArchiveManifestV1;
use crawlx_core::archive_catalog::{
    ArchiveExportState, ArchiveExportV1, ArchiveHistoryKeyV1, ArchiveHistoryV1, ArchiveReadV1,
    ArchiveRecordV1, ArchiveRepo,
};
use crawlx_core::{ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

fn number(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| invalid("archive integer exceeds database range"))
}
async fn locked(
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    export: Uuid,
) -> Result<ArchiveExportV1, StoreError> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT payload FROM archive_exports WHERE tenant_id=$1 AND export_id=$2 FOR UPDATE",
    )
    .bind(tenant.0)
    .bind(export)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db)?;
    decode(value.ok_or_else(|| StoreError::NotFound {
        entity: "archive",
        id: export.to_string(),
    })?)
}
async fn save(tx: &mut Transaction<'_, Postgres>, export: &ArchiveExportV1) -> Result<(), StoreError> {
    let state = match export.state {
        ArchiveExportState::Recording => "recording",
        ArchiveExportState::Published => "published",
        ArchiveExportState::Failed => "failed",
        ArchiveExportState::Deleted => "deleted",
        _ => return Err(invalid("unsupported archive state")),
    };
    sqlx::query("UPDATE archive_exports SET state=$3,fence=$4,lease_until=$5,payload=$6 WHERE tenant_id=$1 AND export_id=$2")
        .bind(export.tenant.0).bind(export.id).bind(state).bind(export.fence).bind(export.lease_until)
        .bind(json(export)?).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn artifact_exists(
    tx: &mut Transaction<'_, Postgres>,
    export: &ArchiveExportV1,
    artifact: &ArtifactRef,
    minimum: u64,
    content_type: &str,
    now: Timestamp,
) -> Result<(), StoreError> {
    let present: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE artifact_id=$1 AND run_id=$2 \
        AND tenant_id=$3 AND content_digest=$4 AND sensitivity='content' AND size_bytes >= $5 \
        AND (expires_at IS NULL OR expires_at>$6) AND deleted_at IS NULL AND content_type=$7)",
    )
    .bind(artifact.id.0)
    .bind(export.run.0)
    .bind(export.tenant.0)
    .bind(artifact.digest.0.to_vec())
    .bind(number(minimum)?)
    .bind(now)
    .bind(content_type)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !present {
        return Err(invalid("archive artifact is not committed and retained"));
    }
    Ok(())
}

#[async_trait]
impl ArchiveRepo for Pg {
    async fn begin(&self, export: &ArchiveExportV1) -> Result<(), StoreError> {
        scope(export.tenant)?;
        export.config.validate().map_err(invalid)?;
        super::pending_bounds(export)?;
        if export.id != export.run.0 {
            return Err(invalid("archive identity mismatch"));
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let source = sqlx::query("SELECT created_at,expires_at,retention_mode::text AS mode, config->'output'->'archive' AS archive, \
            (expires_at IS NOT NULL AND expires_at<=clock_timestamp()) AS expired FROM crawl_runs \
            WHERE tenant_id=$1 AND run_id=$2 FOR SHARE")
            .bind(export.tenant.0).bind(export.run.0).fetch_optional(&mut *tx).await.map_err(db)?
            .ok_or_else(|| invalid("archive source missing"))?;
        let admitted: Option<crawlx_core::archive::ArchiveConfigV1> = source
            .try_get::<Option<serde_json::Value>, _>("archive")
            .map_err(db)?
            .filter(|value| !value.is_null())
            .map(decode)
            .transpose()?;
        if admitted.as_ref() != Some(&export.config) || source.try_get::<bool, _>("expired").map_err(db)? {
            return Err(StoreError::RetentionDenied(
                "archive configuration absent, changed or expired".into(),
            ));
        }
        if source.try_get::<String, _>("mode").map_err(db)? == "zdr"
            || source.try_get::<Timestamp, _>("created_at").map_err(db)? != export.created_at
            || source.try_get::<Option<Timestamp>, _>("expires_at").map_err(db)? != export.expires_at
        {
            return Err(StoreError::RetentionDenied(
                "durable archive source policy mismatch".into(),
            ));
        }
        sqlx::query("INSERT INTO archive_exports(tenant_id,run_id,export_id,state,fence,lease_until,expires_at,payload) \
            VALUES($1,$2,$3,'recording',0,$4,$5,$6) ON CONFLICT(tenant_id,export_id) DO NOTHING")
            .bind(export.tenant.0).bind(export.run.0).bind(export.id).bind(export.created_at)
            .bind(export.expires_at).bind(json(export)?).execute(&mut *tx).await.map_err(db)?;
        let existing = locked(&mut tx, export.tenant, export.id).await?;
        if json(&existing.config)? != json(&export.config)? {
            return Err(invalid("archive configuration changed during recovery"));
        }
        tx.commit().await.map_err(db)
    }

    async fn claim(
        &self,
        tenant: TenantId,
        export: Uuid,
        now: Timestamp,
    ) -> Result<Option<ArchiveExportV1>, StoreError> {
        scope(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let mut row = locked(&mut tx, tenant, export).await?;
        if !live(&row, now) || row.state != ArchiveExportState::Recording || row.lease_until > now {
            return Ok(None);
        }
        row.fence = row
            .fence
            .checked_add(1)
            .ok_or_else(|| invalid("archive fence exhausted"))?;
        row.lease_until = now + chrono::Duration::seconds(120);
        save(&mut tx, &row).await?;
        tx.commit().await.map_err(db)?;
        Ok(Some(row))
    }

    async fn get(&self, tenant: TenantId, export: Uuid, now: Timestamp) -> Result<ArchiveReadV1, StoreError> {
        scope(tenant)?;
        let value: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT payload FROM archive_exports WHERE tenant_id=$1 AND export_id=$2")
                .bind(tenant.0)
                .bind(export)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        let Some(value) = value else {
            return Ok(ArchiveReadV1::Missing);
        };
        let row: ArchiveExportV1 = decode(value)?;
        Ok(if row.state == ArchiveExportState::Deleted {
            ArchiveReadV1::Missing
        } else if !live(&row, now) {
            ArchiveReadV1::Expired
        } else {
            ArchiveReadV1::Available(Box::new(row))
        })
    }

    async fn list(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        now: Timestamp,
    ) -> Result<Vec<ArchiveExportV1>, StoreError> {
        scope(tenant)?;
        let values: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM archive_exports WHERE tenant_id=$1 AND run_id=$2 \
            AND state<>'deleted' AND (expires_at IS NULL OR expires_at>$3) ORDER BY export_id LIMIT 100",
        )
        .bind(tenant.0)
        .bind(run.0)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        values.into_iter().map(decode).collect()
    }

    async fn commit_record(
        &self,
        tenant: TenantId,
        fence: i64,
        record: &ArchiveRecordV1,
        history: Option<&ArchiveHistoryV1>,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        let mut export = locked(&mut tx, tenant, record.export).await?;
        writer(&export, fence, now)?;
        let existing: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT payload FROM archive_records WHERE tenant_id=$1 AND export_id=$2 AND ordinal=$3",
        )
        .bind(tenant.0)
        .bind(record.export)
        .bind(number(record.ordinal)?)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        if let Some(existing) = existing {
            let prior: ArchiveRecordV1 = decode(existing)?;
            if prior.record_id != record.record_id
                || prior.payload_digest != record.payload_digest
                || prior.length != record.length
                || prior.target != record.target
            {
                return Err(invalid("archive ordinal conflicts with committed shard"));
            }
            return Ok(());
        }
        record_bounds(&export, record)?;
        artifact_exists(
            &mut tx,
            &export,
            &record.artifact,
            record
                .offset
                .checked_add(record.length)
                .ok_or_else(|| invalid("archive member range overflow"))?,
            "application/warc",
            now,
        )
        .await?;
        if let Some(history) = history {
            history_key(&history.key)?;
            if history.source.export != record.export
                || history.source.ordinal != record.ordinal
                || history.key.target != record.target
            {
                return Err(invalid("archive history mismatches record"));
            }
        }
        if let Some(source) = &record.dependency {
            // Serialize against deletion and publication, so no source can disappear between
            // validation and dependency insertion. Only standalone baselines are eligible.
            let baseline = locked(&mut tx, tenant, source.export).await?;
            let prior: Option<serde_json::Value> = sqlx::query_scalar(
                "SELECT payload FROM archive_records WHERE tenant_id=$1 AND export_id=$2 AND ordinal=$3",
            )
            .bind(tenant.0)
            .bind(source.export)
            .bind(number(source.ordinal)?)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
            let prior: ArchiveRecordV1 =
                decode(prior.ok_or_else(|| invalid("archive dependency record missing"))?)?;
            let prior_history: Option<serde_json::Value> = sqlx::query_scalar("SELECT payload FROM archive_history WHERE tenant_id=$1 AND export_id=$2 AND ordinal=$3 LIMIT 1")
                .bind(tenant.0).bind(source.export).bind(number(source.ordinal)?).fetch_optional(&mut *tx).await.map_err(db)?;
            let prior_history: Option<ArchiveHistoryV1> = prior_history.map(decode).transpose()?;
            if source.export == record.export
                || !live(&baseline, now)
                || baseline.state != ArchiveExportState::Published
                || super::expires_before(baseline.expires_at, export.expires_at)
                || prior.dependency.is_some()
                || prior.payload_digest != record.payload_digest
                || history.is_none_or(|current| {
                    prior_history
                        .as_ref()
                        .is_none_or(|prior| prior.key != current.key)
                })
            {
                return Err(invalid("archive dependency is incompatible or not durable"));
            }
        }
        sqlx::query("INSERT INTO archive_records(tenant_id,export_id,ordinal,artifact_id,member_offset,member_length,payload) VALUES($1,$2,$3,$4,$5,$6,$7)")
            .bind(tenant.0).bind(record.export).bind(number(record.ordinal)?).bind(record.artifact.id.0)
            .bind(number(record.offset)?).bind(number(record.length)?).bind(json(record)?)
            .execute(&mut *tx).await.map_err(db)?;
        if let Some(source) = &record.dependency {
            sqlx::query("INSERT INTO archive_dependencies(tenant_id,export_id,ordinal,source_export,source_ordinal) VALUES($1,$2,$3,$4,$5)")
                .bind(tenant.0).bind(record.export).bind(number(record.ordinal)?).bind(source.export).bind(number(source.ordinal)?)
                .execute(&mut *tx).await.map_err(db)?;
        }
        if let Some(history) = history {
            sqlx::query("INSERT INTO archive_history(tenant_id,identity_key,export_id,ordinal,captured_at,payload) VALUES($1,$2,$3,$4,$5,$6)")
                .bind(tenant.0).bind(history_key(&history.key)?.0.to_vec()).bind(record.export).bind(number(record.ordinal)?)
                .bind(history.captured_at).bind(json(history)?).execute(&mut *tx).await.map_err(db)?;
        }
        export.records += 1;
        export.bytes += record.length;
        export.lease_until = now + chrono::Duration::seconds(120);
        save(&mut tx, &export).await?;
        tx.commit().await.map_err(db)
    }

    async fn records(
        &self,
        tenant: TenantId,
        export: Uuid,
        after: Option<u64>,
        limit: u32,
        now: Timestamp,
    ) -> Result<Vec<ArchiveRecordV1>, StoreError> {
        scope(tenant)?;
        if !(1..=64).contains(&limit) {
            return Err(invalid("archive record page limit must be 1..64"));
        }
        let values: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT r.payload FROM archive_records r JOIN archive_exports e USING(tenant_id,export_id) \
            WHERE r.tenant_id=$1 AND r.export_id=$2 AND r.ordinal>$3 AND e.state<>'deleted' \
            AND (e.expires_at IS NULL OR e.expires_at>$4) ORDER BY r.ordinal LIMIT $5",
        )
        .bind(tenant.0)
        .bind(export)
        .bind(after.map(number).transpose()?.unwrap_or(-1))
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        values.into_iter().map(decode).collect()
    }

    async fn publish(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        artifact: &ArtifactRef,
        index: Option<&ArtifactRef>,
        manifest: &ArchiveManifestV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let mut row = locked(&mut tx, tenant, export).await?;
        writer(&row, fence, now)?;
        publish_bounds(&row, manifest)?;
        let expected = if row.config.format == crawlx_core::archive::ArchiveFormat::Warc {
            "application/warc"
        } else {
            "application/wacz+zip"
        };
        artifact_exists(&mut tx, &row, artifact, 1, expected, now).await?;
        if let Some(index) = index {
            artifact_exists(&mut tx, &row, index, 1, "application/cdxj", now).await?;
        }
        if (row.config.format == crawlx_core::archive::ArchiveFormat::Warc) != index.is_some() {
            return Err(invalid("archive index does not match export format"));
        }
        row.index = index.cloned();
        row.artifact = Some(artifact.clone());
        row.manifest = Some(manifest.clone());
        row.state = ArchiveExportState::Published;
        save(&mut tx, &row).await?;
        tx.commit().await.map_err(db)
    }

    async fn history(
        &self,
        tenant: TenantId,
        key: &ArchiveHistoryKeyV1,
        now: Timestamp,
    ) -> Result<Option<ArchiveHistoryV1>, StoreError> {
        scope(tenant)?;
        let value: Option<serde_json::Value> = sqlx::query_scalar("SELECT h.payload FROM archive_history h JOIN archive_exports e USING(tenant_id,export_id) \
            JOIN archive_records r USING(tenant_id,export_id,ordinal) WHERE h.tenant_id=$1 AND h.identity_key=$2 AND e.state='published' \
            AND (e.expires_at IS NULL OR e.expires_at>$3) \
            AND (h.payload->>'etag' IS NOT NULL OR h.payload->>'lastModified' IS NOT NULL) \
            ORDER BY h.captured_at DESC,h.export_id DESC,h.ordinal DESC LIMIT 1")
            .bind(tenant.0).bind(history_key(key)?.0.to_vec()).bind(now).fetch_optional(&self.pool).await.map_err(db)?;
        let history: Option<ArchiveHistoryV1> = value.map(decode).transpose()?;
        Ok(history.filter(|row| row.key == *key))
    }

    async fn erase(&self, tenant: TenantId, export: Uuid) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        // The tenant-scoped advisory lock serializes dependency creation and cascading purge.
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("WITH RECURSIVE doomed(id) AS (SELECT $2::uuid UNION \
            SELECT d.export_id FROM archive_dependencies d JOIN doomed s ON d.source_export=s.id WHERE d.tenant_id=$1) \
            UPDATE archive_exports e SET state='deleted',fence=e.fence+1, \
            payload=jsonb_set(jsonb_set(e.payload,'{state}','\"deleted\"'),'{manifest}','null') \
            WHERE e.tenant_id=$1 AND e.export_id IN(SELECT id FROM doomed)")
            .bind(tenant.0).bind(export).execute(&mut *tx).await.map_err(db)?;
        sqlx::query("DELETE FROM archive_history h USING archive_exports e WHERE h.tenant_id=$1 AND e.tenant_id=h.tenant_id \
            AND e.export_id=h.export_id AND e.state='deleted'").bind(tenant.0).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)
    }
    async fn renew(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let mut row = locked(&mut tx, tenant, export).await?;
        writer(&row, fence, now)?;
        row.lease_until = now + chrono::Duration::seconds(120);
        save(&mut tx, &row).await?;
        tx.commit().await.map_err(db)
    }
    async fn artifact_visible(
        &self,
        tenant: TenantId,
        artifact: &ArtifactRef,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        scope(tenant)?;
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM archive_exports e WHERE e.tenant_id=$1 AND e.state='published' \
            AND (e.expires_at IS NULL OR e.expires_at>$3) AND (e.payload->'artifact'->>'id'=$2 OR e.payload->'index'->>'id'=$2 \
            OR EXISTS(SELECT 1 FROM archive_records r WHERE r.tenant_id=e.tenant_id AND r.export_id=e.export_id AND r.artifact_id::text=$2)))")
            .bind(tenant.0).bind(artifact.id.to_string()).bind(now).fetch_one(&self.pool).await.map_err(db)
    }
    async fn erased_artifacts(&self, tenant: TenantId, limit: u32) -> Result<Vec<ArtifactRef>, StoreError> {
        scope(tenant)?;
        if !(1..=64).contains(&limit) {
            return Err(invalid("archive erase batch limit must be 1..64"));
        }
        let values: Vec<serde_json::Value> = sqlx::query_scalar("SELECT artifact FROM ( \
            SELECT e.payload->'artifact' AS artifact FROM archive_exports e WHERE e.tenant_id=$1 AND e.state='deleted' \
            UNION ALL SELECT e.payload->'index' FROM archive_exports e WHERE e.tenant_id=$1 AND e.state='deleted' \
            UNION ALL SELECT r.payload->'artifact' FROM archive_records r JOIN archive_exports e USING(tenant_id,export_id) \
            WHERE e.tenant_id=$1 AND e.state='deleted') refs WHERE artifact IS NOT NULL AND artifact<>'null'::jsonb LIMIT $2")
            .bind(tenant.0).bind(i64::from(limit)).fetch_all(&self.pool).await.map_err(db)?;
        values.into_iter().map(decode).collect()
    }
    async fn acknowledge_erased(&self, tenant: TenantId, artifact: &ArtifactRef) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query(
            "UPDATE archive_exports SET payload=jsonb_set(payload,'{artifact}','null') \
            WHERE tenant_id=$1 AND state='deleted' AND payload->'artifact'->>'id'=$2",
        )
        .bind(tenant.0)
        .bind(artifact.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query(
            "UPDATE archive_exports SET payload=jsonb_set(payload,'{index}','null') \
            WHERE tenant_id=$1 AND state='deleted' AND payload->'index'->>'id'=$2",
        )
        .bind(tenant.0)
        .bind(artifact.id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM archive_records r USING archive_exports e WHERE r.tenant_id=$1 AND r.artifact_id=$2 \
            AND e.tenant_id=r.tenant_id AND e.export_id=r.export_id AND e.state='deleted'")
            .bind(tenant.0).bind(artifact.id.0).execute(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)
    }
    async fn recoverable(&self, now: Timestamp, limit: u32) -> Result<Vec<ArchiveExportV1>, StoreError> {
        if crate::tenant::current().is_some() {
            return Err(StoreError::AccessDenied(
                "archive recovery requires worker authority".into(),
            ));
        }
        if !(1..=64).contains(&limit) {
            return Err(invalid("archive recovery batch limit must be 1..64"));
        }
        let values: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT e.payload FROM archive_exports e JOIN crawl_runs r USING(tenant_id,run_id) \
            WHERE e.state<>'deleted' AND r.status NOT IN ('completed','failed','cancelled') \
            AND (e.expires_at IS NULL OR e.expires_at>$1) AND (e.state='published' OR e.lease_until<=$1) \
            ORDER BY e.export_id LIMIT $2",
        )
        .bind(now)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        values.into_iter().map(decode).collect()
    }
    async fn fail(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        failure: crawlx_core::archive_catalog::ArchiveFailureV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let mut row = locked(&mut tx, tenant, export).await?;
        writer(&row, fence, now)?;
        row.state = ArchiveExportState::Failed;
        row.failure = Some(failure);
        save(&mut tx, &row).await?;
        tx.commit().await.map_err(db)
    }
    async fn traffic_keyset(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        after: u64,
        limit: u32,
    ) -> Result<Vec<crawlx_core::archive_catalog::ArchiveTrafficV1>, StoreError> {
        scope(tenant)?;
        crate::archive::recorded::traffic_keyset(self, tenant, run, after, limit)
            .await?
            .into_iter()
            .map(|row| {
                Ok(crawlx_core::archive_catalog::ArchiveTrafficV1::new(
                    u64::try_from(row.event_id).map_err(|_| invalid("negative archive traffic event"))?,
                    row.url,
                    row.captured_at,
                    row.request_body,
                    row.response_body,
                ))
            })
            .collect()
    }
}
