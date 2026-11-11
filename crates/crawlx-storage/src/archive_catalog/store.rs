//! Archive catalog transactions, written once for every engine.
//!
//! Every statement carries its tenant, so the catalog is tenant-isolated on engines without
//! row-level security as well. Fields of the JSON payloads that statements probe are columns
//! the write path fills from the typed value (`archive_records.custody_sensitivity` and
//! friends, `archive_history.has_validator`) or generated from it
//! (`archive_exports.package_artifact_id`, `index_artifact_id`, `custody_sensitivity`);
//! payload patches are made in Rust inside the write transaction.

use super::{
    decode, export_json, history_key, invalid, json, live, publish_bounds, record_bounds, scope, writer,
};
use crate::backend::strategy::Conn;
use crate::backend::{Dialect, LockMode, RowLock};
use crate::sql::{in_ids, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::archive::{ArchiveDedupe, ArchiveManifestV1};
use crawlx_core::archive_catalog::{
    ArchiveCustodyV1, ArchiveExportState, ArchiveExportV1, ArchiveHistoryKeyV1, ArchiveHistoryV1,
    ArchiveReadV1, ArchiveRecordV1, ArchiveRepo,
};
use crawlx_core::repo::Sensitivity;
use crawlx_core::{ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use std::collections::BTreeSet;
use uuid::Uuid;

/// Ids per `IN` list of the dependency walk.
const WALK_CHUNK: usize = 500;

fn number(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| invalid("archive integer exceeds database range"))
}

/// The row-lock clause of the engine, with its leading space.
fn lock<B: Sql>(mode: RowLock) -> &'static str {
    <B::Dialect as Dialect>::row_lock(mode)
}

fn missing(export: Uuid) -> StoreError {
    StoreError::NotFound {
        entity: "archive",
        id: export.to_string(),
    }
}

fn state_label(state: ArchiveExportState) -> Result<&'static str, StoreError> {
    match state {
        ArchiveExportState::Recording => Ok("recording"),
        ArchiveExportState::Published => Ok("published"),
        ArchiveExportState::Failed => Ok("failed"),
        ArchiveExportState::Deleted => Ok("deleted"),
        _ => Err(invalid("unsupported archive state")),
    }
}

/// The payload of an export row, locked for the rest of the transaction.
async fn export_payload<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    export: Uuid,
) -> Result<Option<serde_json::Value>, StoreError> {
    stmt!(
        B,
        format!(
            "SELECT payload FROM archive_exports WHERE tenant_id=$1 AND export_id=$2{}",
            lock::<B>(RowLock::Update)
        )
    )
    .uuid(tenant.0)
    .uuid(export)
    .fetch_optional(conn)
    .await?
    .map(|row| row.json("payload"))
    .transpose()
}

async fn locked<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    export: Uuid,
) -> Result<ArchiveExportV1, StoreError> {
    decode(
        export_payload::<B>(conn, tenant, export)
            .await?
            .ok_or_else(|| missing(export))?,
    )
}

async fn save<B: Sql>(conn: &mut Conn<B>, export: &ArchiveExportV1) -> Result<(), StoreError> {
    let payload = export_json(export)?;
    stmt!(
        B,
        "UPDATE archive_exports SET state=$3,fence=$4,lease_until=$5,payload=$6,expires_at=$7 \
         WHERE tenant_id=$1 AND export_id=$2"
    )
    .uuid(export.tenant.0)
    .uuid(export.id)
    .text(state_label(export.state)?)
    .i64(export.fence)
    .ts(export.lease_until)
    .json(&payload)
    .opt_ts(export.expires_at)
    .execute(conn)
    .await?;
    Ok(())
}

async fn artifact_exists<B: Sql>(
    conn: &mut Conn<B>,
    export: &ArchiveExportV1,
    artifact: &ArtifactRef,
    minimum: u64,
    content_type: &str,
    now: Timestamp,
    custody: ArchiveCustodyV1,
) -> Result<(), StoreError> {
    custody.validate(now)?;
    let present = stmt!(
        B,
        format!(
            "SELECT artifact_id FROM artifacts WHERE artifact_id=$1 AND run_id=$2 \
             AND tenant_id=$3 AND content_digest=$4 AND sensitivity=$8::text::sensitivity_class AND size_bytes >= $5 \
             AND (expires_at IS NULL OR expires_at>$6) AND deleted_at IS NULL AND content_type=$7 \
             AND ($9::timestamptz IS NULL OR expires_at<=$9){}",
            lock::<B>(RowLock::Share)
        )
    )
    .uuid(artifact.id.0)
    .uuid(export.run.0)
    .uuid(export.tenant.0)
    .bytes(&artifact.digest.0)
    .i64(number(minimum)?)
    .ts(now)
    .text(content_type)
    .text(custody.sensitivity.as_str())
    .opt_ts(
        (custody.sensitivity == Sensitivity::Sensitive)
            .then_some(custody.expires_at)
            .flatten(),
    )
    .fetch_optional(conn)
    .await?;
    if present.is_none() {
        return Err(invalid("archive artifact is not committed and retained"));
    }
    Ok(())
}

async fn content_package<B: Sql>(
    conn: &mut Conn<B>,
    source: &ArchiveExportV1,
    dependent: &ArchiveExportV1,
    now: Timestamp,
) -> Result<(), StoreError> {
    if source.tenant != dependent.tenant
        || !live(source, now)
        || source.state != ArchiveExportState::Published
        || source.custody.sensitivity != Sensitivity::Content
        || super::expires_before(source.expires_at, dependent.expires_at)
    {
        return Err(invalid("archive dependency package authority is incompatible"));
    }
    let artifact = source
        .artifact
        .as_ref()
        .ok_or_else(|| invalid("archive dependency package missing"))?;
    let mime = if source.config.format == crawlx_core::archive::ArchiveFormat::Warc {
        "application/warc"
    } else {
        "application/wacz+zip"
    };
    let present = stmt!(
        B,
        format!(
            "SELECT artifact_id FROM artifacts WHERE artifact_id=$1 AND tenant_id=$2 AND run_id=$3 \
             AND content_digest=$4 AND sensitivity='content' AND content_type=$5 AND size_bytes>0 \
             AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at>$6) \
             AND (expires_at IS NULL OR ($7::timestamptz IS NOT NULL AND expires_at>=$7)){}",
            lock::<B>(RowLock::Share)
        )
    )
    .uuid(artifact.id.0)
    .uuid(source.tenant.0)
    .uuid(source.run.0)
    .bytes(&artifact.digest.0)
    .text(mime)
    .ts(now)
    .opt_ts(dependent.expires_at)
    .fetch_optional(conn)
    .await?;
    if present.is_none() {
        return Err(invalid("archive dependency package authority changed"));
    }
    Ok(())
}

async fn source_exists<B: Sql>(
    conn: &mut Conn<B>,
    export: &ArchiveExportV1,
    record: &ArchiveRecordV1,
    now: Timestamp,
) -> Result<(), StoreError> {
    if record.custody.sensitivity != Sensitivity::Sensitive {
        return Ok(());
    }
    record.custody.validate(now)?;
    let source = record
        .source_artifact
        .as_ref()
        .ok_or_else(|| invalid("sensitive archive source missing"))?;
    let present = stmt!(
        B,
        format!(
            "SELECT artifact_id FROM artifacts WHERE tenant_id=$1 AND run_id=$2 AND artifact_id=$3 \
             AND content_digest=$4 AND sensitivity='sensitive' AND expires_at=$5 AND expires_at>$6 \
             AND deleted_at IS NULL AND content_type=$7{}",
            lock::<B>(RowLock::Share)
        )
    )
    .uuid(export.tenant.0)
    .uuid(export.run.0)
    .uuid(source.id.0)
    .bytes(&source.digest.0)
    .opt_ts(record.custody.expires_at)
    .ts(now)
    .text(&record.mime)
    .fetch_optional(conn)
    .await?;
    if present.is_none() {
        return Err(invalid("sensitive archive source revoked or changed"));
    }
    Ok(())
}

async fn sources_live<B: Sql>(
    conn: &mut Conn<B>,
    export: &ArchiveExportV1,
    now: Timestamp,
) -> Result<(), StoreError> {
    let expected = stmt!(
        B,
        "SELECT count(*) AS n FROM archive_records WHERE tenant_id=$1 AND export_id=$2 \
         AND custody_sensitivity='sensitive'"
    )
    .uuid(export.tenant.0)
    .uuid(export.id)
    .fetch_one(conn)
    .await?
    .i64("n")?;
    // Lock artifact rows separately: MariaDB cannot express `FOR SHARE OF a`.
    stmt!(
        B,
        format!(
            "SELECT a.artifact_id FROM artifacts a WHERE a.tenant_id=$1 AND a.run_id=$3 \
             AND EXISTS(SELECT 1 FROM archive_records r WHERE r.tenant_id=$1 AND r.export_id=$2 \
                 AND r.custody_sensitivity='sensitive' AND r.source_artifact_id=a.artifact_id){}",
            lock::<B>(RowLock::Share)
        )
    )
    .uuid(export.tenant.0)
    .uuid(export.id)
    .uuid(export.run.0)
    .fetch_all(conn)
    .await?;
    let retained = stmt!(
        B,
        "SELECT r.ordinal FROM archive_records r JOIN artifacts a ON a.artifact_id=r.source_artifact_id \
         WHERE r.tenant_id=$1 AND r.export_id=$2 AND r.custody_sensitivity='sensitive' \
         AND a.tenant_id=$1 AND a.run_id=$3 AND a.sensitivity='sensitive' AND a.content_type=r.source_mime \
         AND a.content_digest=r.source_digest AND a.expires_at=r.custody_expires_at \
         AND a.expires_at>$4 AND a.deleted_at IS NULL"
    )
    .uuid(export.tenant.0)
    .uuid(export.id)
    .uuid(export.run.0)
    .ts(now)
    .fetch_all(conn)
    .await?;
    if i64::try_from(retained.len()).ok() != Some(expected) {
        return Err(invalid("sensitive archive source revoked or changed"));
    }
    Ok(())
}

async fn record_payload<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    export: Uuid,
    ordinal: u64,
) -> Result<Option<serde_json::Value>, StoreError> {
    stmt!(
        B,
        "SELECT payload FROM archive_records WHERE tenant_id=$1 AND export_id=$2 AND ordinal=$3"
    )
    .uuid(tenant.0)
    .uuid(export)
    .i64(number(ordinal)?)
    .fetch_optional(conn)
    .await?
    .map(|row| row.json("payload"))
    .transpose()
}

async fn history_payload<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    export: Uuid,
    ordinal: u64,
) -> Result<Option<ArchiveHistoryV1>, StoreError> {
    stmt!(
        B,
        "SELECT payload FROM archive_history WHERE tenant_id=$1 AND export_id=$2 AND ordinal=$3 LIMIT 1"
    )
    .uuid(tenant.0)
    .uuid(export)
    .i64(number(ordinal)?)
    .fetch_optional(conn)
    .await?
    .map(|row| row.json("payload").and_then(decode))
    .transpose()
}

/// Every export that transitively depends on `export`, and `export` itself, in id order.
async fn doomed_set<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    export: Uuid,
) -> Result<BTreeSet<Uuid>, StoreError> {
    let mut doomed = BTreeSet::from([export]);
    let mut frontier = vec![export];
    while !frontier.is_empty() {
        let mut next = Vec::new();
        for chunk in frontier.chunks(WALK_CHUNK) {
            let rows = Stmt::<B>::dynamic(&format!(
                "SELECT DISTINCT export_id FROM archive_dependencies WHERE tenant_id=$1 AND source_export {}",
                in_ids::<B>(2, chunk.len())
            ))
            .uuid(tenant.0)
            .uuid_list(chunk)
            .fetch_all(conn)
            .await?;
            for row in rows {
                let id = row.uuid("export_id")?;
                if doomed.insert(id) {
                    next.push(id);
                }
            }
        }
        frontier = next;
    }
    Ok(doomed)
}

/// Scan bounded pages until the exact approved key matches; mismatched keys cannot hide
/// a later candidate merely by filling the first page.
async fn first_match<'a, B: Sql>(
    pool: &B::Pool,
    key: &crawlx_core::archive_catalog::ArchivePayloadKeyV1,
    mut query: impl FnMut(i64) -> Stmt<'a, B> + Send,
) -> Result<Option<ArchiveRecordV1>, StoreError> {
    let mut offset = 0_i64;
    loop {
        let rows = query(offset).fetch_all_pool(pool).await?;
        let exhausted = rows.len() < 128;
        for row in rows {
            let record: ArchiveRecordV1 = decode(row.json("payload")?)?;
            if record.payload_key.as_ref() == Some(key) && record.dependency.is_none() {
                return Ok(Some(record));
            }
        }
        if exhausted {
            return Ok(None);
        }
        offset = offset
            .checked_add(128)
            .ok_or_else(|| invalid("archive payload source scan exceeds database range"))?;
    }
}

#[async_trait]
impl<B: Sql> ArchiveRepo for Store<B> {
    async fn begin(&self, export: &ArchiveExportV1) -> Result<(), StoreError> {
        scope(export.tenant)?;
        export.config.validate().map_err(invalid)?;
        super::pending_bounds(export)?;
        if export.id != export.run.0 {
            return Err(invalid("archive identity mismatch"));
        }
        let mut tx = self.begin_write().await?;
        let archive_config = <B::Dialect as Dialect>::json_extract(
            &<B::Dialect as Dialect>::json_extract("config", "output"),
            "archive",
        );
        let source = stmt!(
            B,
            format!(
                "SELECT created_at,expires_at,retention_mode::text AS mode, {archive_config} AS archive, \
                 (expires_at IS NOT NULL AND expires_at<={}) AS expired FROM crawl_runs \
                 WHERE tenant_id=$1 AND run_id=$2{}",
                <B::Dialect as Dialect>::clock_timestamp(),
                lock::<B>(RowLock::Share)
            )
        )
        .uuid(export.tenant.0)
        .uuid(export.run.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or_else(|| invalid("archive source missing"))?;
        let admitted: Option<crawlx_core::archive::ArchiveConfigV1> = source
            .opt_json("archive")?
            .filter(|value| !value.is_null())
            .map(decode)
            .transpose()?;
        if admitted.as_ref() != Some(&export.config) || source.flag("expired")? {
            return Err(StoreError::RetentionDenied(
                "archive configuration absent, changed or expired".into(),
            ));
        }
        if source.text("mode")? == "zdr"
            || source.ts("created_at")? != export.created_at
            || source.opt_ts("expires_at")? != export.expires_at
        {
            return Err(StoreError::RetentionDenied(
                "durable archive source policy mismatch".into(),
            ));
        }
        let payload = export_json(export)?;
        stmt!(
            B,
            format!(
                "INSERT INTO archive_exports(tenant_id,run_id,export_id,state,fence,lease_until,expires_at,payload) \
                 VALUES($1,$2,$3,'recording',0,$4,$5,$6) {}",
                <B::Dialect as Dialect>::upsert_do_nothing(&["tenant_id", "export_id"])
            )
        )
        .uuid(export.tenant.0)
        .uuid(export.run.0)
        .uuid(export.id)
        .ts(export.created_at)
        .opt_ts(export.expires_at)
        .json(&payload)
        .execute(tx.conn())
        .await?;
        let existing = locked::<B>(tx.conn(), export.tenant, export.id).await?;
        if existing.state == ArchiveExportState::Deleted {
            return Err(StoreError::RetentionDenied(
                "archive export permanently erased".into(),
            ));
        }
        if json(&existing.config)? != json(&export.config)? {
            return Err(invalid("archive configuration changed during recovery"));
        }
        tx.commit().await
    }

    async fn narrow_custody(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        custody: &ArchiveCustodyV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.begin_write().await?;
        let mut row = locked::<B>(tx.conn(), tenant, export).await?;
        writer(&row, fence, now)?;
        row.custody = super::narrowed(&row, *custody, now)?;
        row.expires_at = row.custody.expires_at;
        save::<B>(tx.conn(), &row).await?;
        tx.commit().await
    }

    async fn claim(
        &self,
        tenant: TenantId,
        export: Uuid,
        now: Timestamp,
    ) -> Result<Option<ArchiveExportV1>, StoreError> {
        scope(tenant)?;
        let mut tx = self.begin_write().await?;
        let mut row = locked::<B>(tx.conn(), tenant, export).await?;
        if !live(&row, now) || row.state != ArchiveExportState::Recording || row.lease_until > now {
            return Ok(None);
        }
        row.fence = row
            .fence
            .checked_add(1)
            .ok_or_else(|| invalid("archive fence exhausted"))?;
        row.lease_until = now + chrono::Duration::seconds(120);
        save::<B>(tx.conn(), &row).await?;
        tx.commit().await?;
        Ok(Some(row))
    }

    async fn get(&self, tenant: TenantId, export: Uuid, now: Timestamp) -> Result<ArchiveReadV1, StoreError> {
        scope(tenant)?;
        let row = stmt!(
            B,
            "SELECT payload FROM archive_exports WHERE tenant_id=$1 AND export_id=$2"
        )
        .uuid(tenant.0)
        .uuid(export)
        .fetch_optional_pool(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(ArchiveReadV1::Missing);
        };
        let row: ArchiveExportV1 = decode(row.json("payload")?)?;
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
        stmt!(
            B,
            "SELECT payload FROM archive_exports WHERE tenant_id=$1 AND run_id=$2 \
             AND state<>'deleted' AND (expires_at IS NULL OR expires_at>$3) ORDER BY export_id LIMIT 100"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .ts(now)
        .fetch_all_pool(&self.pool)
        .await?
        .iter()
        .map(|row| decode(row.json("payload")?))
        .collect()
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
        let mut tx = self.begin_write().await?;
        B::xact_lock(tx.conn(), &tenant.to_string(), LockMode::Exclusive).await?;
        let mut export = locked::<B>(tx.conn(), tenant, record.export).await?;
        writer(&export, fence, now)?;
        source_exists::<B>(tx.conn(), &export, record, now).await?;
        if let Some(existing) = record_payload::<B>(tx.conn(), tenant, record.export, record.ordinal).await? {
            let prior: ArchiveRecordV1 = decode(existing)?;
            let prior_history =
                history_payload::<B>(tx.conn(), tenant, record.export, record.ordinal).await?;
            if prior != *record || prior_history.as_ref() != history {
                return Err(invalid("archive ordinal conflicts with committed shard"));
            }
            return Ok(());
        }
        record_bounds(&export, record)?;
        artifact_exists::<B>(
            tx.conn(),
            &export,
            &record.artifact,
            record
                .offset
                .checked_add(record.length)
                .ok_or_else(|| invalid("archive member range overflow"))?,
            "application/warc",
            now,
            record.custody,
        )
        .await?;
        if let Some(history) = history {
            if record.custody.sensitivity != Sensitivity::Content {
                return Err(invalid(
                    "sensitive archive records cannot become validator history",
                ));
            }
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
            let baseline = locked::<B>(tx.conn(), tenant, source.export).await?;
            if source.export != record.export {
                content_package::<B>(tx.conn(), &baseline, &export, now).await?;
            }
            let prior = record_payload::<B>(tx.conn(), tenant, source.export, source.ordinal).await?;
            let prior: ArchiveRecordV1 =
                decode(prior.ok_or_else(|| invalid("archive dependency record missing"))?)?;
            let prior_history =
                history_payload::<B>(tx.conn(), tenant, source.export, source.ordinal).await?;
            let payload_compatible = record.payload_key.as_ref().is_some_and(|key| {
                super::payload::eligible(&export, &baseline, &prior, key, &record.payload_digest, now)
                    && (source.export != record.export || source.ordinal < record.ordinal)
            });
            let validator_compatible = record.payload_key.is_none()
                && source.export != record.export
                && live(&baseline, now)
                && baseline.state == ArchiveExportState::Published
                && !super::expires_before(baseline.expires_at, export.expires_at)
                && prior.dependency.is_none()
                && prior.payload_digest == record.payload_digest
                && history.is_some_and(|current| {
                    prior_history
                        .as_ref()
                        .is_some_and(|prior| prior.key == current.key)
                });
            if !payload_compatible && !validator_compatible {
                return Err(invalid("archive dependency is incompatible or not durable"));
            }
        }
        let payload = json(record)?;
        stmt!(
            B,
            "INSERT INTO archive_records(tenant_id,export_id,ordinal,artifact_id,member_offset,member_length,payload,\
             custody_sensitivity,source_artifact_id,source_mime,source_digest,custody_expires_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"
        )
        .uuid(tenant.0)
        .uuid(record.export)
        .i64(number(record.ordinal)?)
        .uuid(record.artifact.id.0)
        .i64(number(record.offset)?)
        .i64(number(record.length)?)
        .json(&payload)
        .text(record.custody.sensitivity.as_str())
        .opt_uuid(record.source_artifact.as_ref().map(|source| source.id.0))
        .text(&record.mime)
        .opt_bytes(record.source_artifact.as_ref().map(|source| source.digest.0.as_slice()))
        .opt_ts(record.custody.expires_at)
        .execute(tx.conn())
        .await?;
        if let Some(source) = &record.dependency {
            stmt!(
                B,
                "INSERT INTO archive_dependencies(tenant_id,export_id,ordinal,source_export,source_ordinal) \
                 VALUES($1,$2,$3,$4,$5)"
            )
            .uuid(tenant.0)
            .uuid(record.export)
            .i64(number(record.ordinal)?)
            .uuid(source.export)
            .i64(number(source.ordinal)?)
            .execute(tx.conn())
            .await?;
        }
        if let Some(history) = history {
            let payload = json(history)?;
            stmt!(
                B,
                "INSERT INTO archive_history(tenant_id,identity_key,export_id,ordinal,captured_at,payload,has_validator) \
                 VALUES($1,$2,$3,$4,$5,$6,$7)"
            )
            .uuid(tenant.0)
            .bytes(&history_key(&history.key)?.0)
            .uuid(record.export)
            .i64(number(record.ordinal)?)
            .ts(history.captured_at)
            .json(&payload)
            .bool(history.etag.is_some() || history.last_modified.is_some())
            .execute(tx.conn())
            .await?;
        }
        if let Some(key) = record
            .payload_key
            .as_ref()
            .filter(|_| record.dependency.is_none() && export.custody.sensitivity == Sensitivity::Content)
        {
            stmt!(
                B,
                "INSERT INTO archive_payload_sources(tenant_id,export_id,ordinal,payload_digest,identity_key,published,expires_at) \
                 VALUES($1,$2,$3,$4,$5,false,$6)"
            )
            .uuid(tenant.0)
            .uuid(record.export)
            .i64(number(record.ordinal)?)
            .text(&record.payload_digest)
            .bytes(key.variant.0.as_slice())
            .opt_ts(super::payload::deadline(&export, record))
            .execute(tx.conn())
            .await?;
        }
        export.records += 1;
        export.bytes += record.length;
        export.lease_until = now + chrono::Duration::seconds(120);
        save::<B>(tx.conn(), &export).await?;
        tx.commit().await
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
        stmt!(
            B,
            "SELECT r.payload FROM archive_records r JOIN archive_exports e \
             ON e.tenant_id=r.tenant_id AND e.export_id=r.export_id \
             WHERE r.tenant_id=$1 AND r.export_id=$2 AND r.ordinal>$3 AND e.state<>'deleted' \
             AND (e.expires_at IS NULL OR e.expires_at>$4) ORDER BY r.ordinal LIMIT $5"
        )
        .uuid(tenant.0)
        .uuid(export)
        .i64(after.map(number).transpose()?.unwrap_or(-1))
        .ts(now)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?
        .iter()
        .map(|row| decode(row.json("payload")?))
        .collect()
    }

    async fn payload_source(
        &self,
        tenant: TenantId,
        export: Uuid,
        key: &crawlx_core::archive_catalog::ArchivePayloadKeyV1,
        payload_digest: &str,
        now: Timestamp,
    ) -> Result<Option<ArchiveRecordV1>, StoreError> {
        scope(tenant)?;
        let current = stmt!(
            B,
            "SELECT payload,expires_at FROM archive_exports \
             WHERE tenant_id=$1 AND export_id=$2 AND state='recording' \
             AND (expires_at IS NULL OR expires_at>$3)"
        )
        .uuid(tenant.0)
        .uuid(export)
        .ts(now)
        .fetch_optional_pool(&self.pool)
        .await?;
        let Some(current) = current else {
            return Ok(None);
        };
        let expires_at = current.opt_ts("expires_at")?;
        let current: ArchiveExportV1 = decode(current.json("payload")?)?;
        let mode = current.config.dedupe;
        if !matches!(mode, ArchiveDedupe::Collection | ArchiveDedupe::Tenant) {
            return Ok(None);
        }
        let mut record: Option<ArchiveRecordV1> = None;
        if current.custody.sensitivity == Sensitivity::Content {
            record = first_match::<B>(&self.pool, key, |offset| {
                stmt!(
                    B,
                    "SELECT r.payload FROM archive_payload_sources p JOIN archive_records r \
                     ON r.tenant_id=p.tenant_id AND r.export_id=p.export_id AND r.ordinal=p.ordinal \
                     WHERE p.tenant_id=$1 AND p.export_id=$2 AND p.payload_digest=$3 AND p.identity_key=$4 \
                     ORDER BY p.ordinal LIMIT 128 OFFSET $5"
                )
                .uuid(tenant.0)
                .uuid(export)
                .text(payload_digest)
                .bytes(key.variant.0.as_slice())
                .i64(offset)
            })
            .await?;
        }
        if record.is_none()
            && mode == ArchiveDedupe::Tenant
            && key.representation == crawlx_core::archive::ArchiveRepresentation::ProtocolResource
        {
            if let Some(expiry) = expires_at {
                record = first_match::<B>(&self.pool, key, |offset| {
                    stmt!(
                        B,
                        "SELECT r.payload FROM archive_payload_sources p JOIN archive_records r \
                         ON r.tenant_id=p.tenant_id AND r.export_id=p.export_id AND r.ordinal=p.ordinal \
                         WHERE p.tenant_id=$1 AND p.payload_digest=$2 AND p.identity_key=$3 AND p.published=true \
                         AND p.expires_at>=$4 ORDER BY p.expires_at,p.export_id,p.ordinal LIMIT 128 OFFSET $5"
                    )
                    .uuid(tenant.0)
                    .text(payload_digest)
                    .bytes(key.variant.0.as_slice())
                    .ts(expiry)
                    .i64(offset)
                })
                .await?;
            }
            if record.is_none() {
                record = first_match::<B>(&self.pool, key, |offset| {
                    stmt!(
                        B,
                        "SELECT r.payload FROM archive_payload_sources p JOIN archive_records r \
                         ON r.tenant_id=p.tenant_id AND r.export_id=p.export_id AND r.ordinal=p.ordinal \
                         WHERE p.tenant_id=$1 AND p.payload_digest=$2 AND p.identity_key=$3 AND p.published=true \
                         AND p.expires_at IS NULL ORDER BY p.export_id,p.ordinal LIMIT 128 OFFSET $4"
                    )
                    .uuid(tenant.0)
                    .text(payload_digest)
                    .bytes(key.variant.0.as_slice())
                    .i64(offset)
                })
                .await?;
            }
        }
        if record.as_ref().is_some_and(|record| {
            !super::payload::key_matches(record, key)
                || record.payload_key.as_ref() != Some(key)
                || record.payload_digest != payload_digest
                || record.dependency.is_some()
                || record.custody.expires_at.is_some_and(|expiry| expiry <= now)
                || super::expires_before(record.custody.expires_at, expires_at)
        }) {
            return Err(invalid("archive payload source index mismatch"));
        }
        Ok(record)
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
        let mut tx = self.begin_write().await?;
        B::xact_lock(tx.conn(), &tenant.to_string(), LockMode::Exclusive).await?;
        let mut row = locked::<B>(tx.conn(), tenant, export).await?;
        writer(&row, fence, now)?;
        publish_bounds(&row, manifest)?;
        sources_live::<B>(tx.conn(), &row, now).await?;
        let sources = stmt!(
            B,
            "SELECT DISTINCT source_export FROM archive_dependencies \
             WHERE tenant_id=$1 AND export_id=$2 AND source_export<>$2 ORDER BY source_export"
        )
        .uuid(tenant.0)
        .uuid(export)
        .fetch_all(tx.conn())
        .await?;
        for source in sources {
            let baseline = locked::<B>(tx.conn(), tenant, source.uuid("source_export")?).await?;
            content_package::<B>(tx.conn(), &baseline, &row, now).await?;
        }
        let expected = if row.config.format == crawlx_core::archive::ArchiveFormat::Warc {
            "application/warc"
        } else {
            "application/wacz+zip"
        };
        artifact_exists::<B>(tx.conn(), &row, artifact, 1, expected, now, row.custody).await?;
        if let Some(index) = index {
            artifact_exists::<B>(tx.conn(), &row, index, 1, "application/cdxj", now, row.custody).await?;
        }
        if (row.config.format == crawlx_core::archive::ArchiveFormat::Warc) != index.is_some() {
            return Err(invalid("archive index does not match export format"));
        }
        row.index = index.cloned();
        row.artifact = Some(artifact.clone());
        row.manifest = Some(manifest.clone());
        row.state = ArchiveExportState::Published;
        save::<B>(tx.conn(), &row).await?;
        tx.commit().await
    }

    async fn history(
        &self,
        tenant: TenantId,
        key: &ArchiveHistoryKeyV1,
        now: Timestamp,
    ) -> Result<Option<ArchiveHistoryV1>, StoreError> {
        scope(tenant)?;
        let row = stmt!(
            B,
            "SELECT h.payload FROM archive_history h JOIN archive_exports e \
             ON e.tenant_id=h.tenant_id AND e.export_id=h.export_id \
             WHERE h.tenant_id=$1 AND h.identity_key=$2 AND e.state='published' \
             AND (e.expires_at IS NULL OR e.expires_at>$3) \
             AND e.custody_sensitivity='content' AND h.has_validator=true \
             ORDER BY h.captured_at DESC,h.export_id DESC,h.ordinal DESC LIMIT 1"
        )
        .uuid(tenant.0)
        .bytes(&history_key(key)?.0)
        .ts(now)
        .fetch_optional_pool(&self.pool)
        .await?;
        let history: Option<ArchiveHistoryV1> =
            row.map(|row| row.json("payload").and_then(decode)).transpose()?;
        Ok(history.filter(|row| row.key == *key))
    }

    async fn erase(&self, tenant: TenantId, export: Uuid) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.begin_write().await?;
        // The tenant-scoped lock serializes dependency creation and cascading purge.
        B::xact_lock(tx.conn(), &tenant.to_string(), LockMode::Exclusive).await?;
        for id in doomed_set::<B>(tx.conn(), tenant, export).await? {
            let Some(mut payload) = export_payload::<B>(tx.conn(), tenant, id).await? else {
                continue;
            };
            if let Some(object) = payload.as_object_mut() {
                object.insert("state".into(), "deleted".into());
                object.insert("manifest".into(), serde_json::Value::Null);
            }
            stmt!(
                B,
                "UPDATE archive_exports SET state='deleted',fence=fence+1,payload=$3 \
                 WHERE tenant_id=$1 AND export_id=$2"
            )
            .uuid(tenant.0)
            .uuid(id)
            .json(&payload)
            .execute(tx.conn())
            .await?;
        }
        stmt!(
            B,
            "DELETE FROM archive_history WHERE tenant_id=$1 AND export_id IN \
             (SELECT export_id FROM archive_exports WHERE tenant_id=$1 AND state='deleted')"
        )
        .uuid(tenant.0)
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }

    async fn renew(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.begin_write().await?;
        let mut row = locked::<B>(tx.conn(), tenant, export).await?;
        writer(&row, fence, now)?;
        row.lease_until = now + chrono::Duration::seconds(120);
        save::<B>(tx.conn(), &row).await?;
        tx.commit().await
    }

    async fn artifact_visible(
        &self,
        tenant: TenantId,
        artifact: &ArtifactRef,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        scope(tenant)?;
        stmt!(
            B,
            "SELECT EXISTS(SELECT 1 FROM archive_exports e WHERE e.tenant_id=$1 AND e.state='published' \
             AND (e.expires_at IS NULL OR e.expires_at>$3) \
             AND NOT EXISTS(SELECT 1 FROM archive_records s WHERE s.tenant_id=e.tenant_id AND s.export_id=e.export_id \
                 AND s.custody_sensitivity='sensitive' AND NOT EXISTS(SELECT 1 FROM artifacts a \
                     WHERE a.artifact_id=s.source_artifact_id AND a.tenant_id=e.tenant_id AND a.run_id=e.run_id \
                     AND a.sensitivity='sensitive' AND a.content_type=s.source_mime AND a.content_digest=s.source_digest \
                     AND a.expires_at=s.custody_expires_at AND a.expires_at>$3 AND a.deleted_at IS NULL)) \
             AND (e.package_artifact_id=$2 OR e.index_artifact_id=$2 \
                 OR EXISTS(SELECT 1 FROM archive_records r WHERE r.tenant_id=e.tenant_id AND r.export_id=e.export_id \
                     AND r.artifact_id=$2))) AS visible"
        )
        .uuid(tenant.0)
        .uuid(artifact.id.0)
        .ts(now)
        .fetch_one_pool(&self.pool)
        .await?
        .flag("visible")
    }

    async fn erased_artifacts(&self, tenant: TenantId, limit: u32) -> Result<Vec<ArtifactRef>, StoreError> {
        scope(tenant)?;
        if !(1..=64).contains(&limit) {
            return Err(invalid("archive erase batch limit must be 1..64"));
        }
        let limit = usize::try_from(limit).map_err(|_| invalid("archive erase batch limit must be 1..64"))?;
        let mut found = Vec::new();
        let exports = stmt!(
            B,
            "SELECT payload FROM archive_exports WHERE tenant_id=$1 AND state='deleted' \
             AND (package_artifact_id IS NOT NULL OR index_artifact_id IS NOT NULL) \
             ORDER BY export_id LIMIT $2"
        )
        .uuid(tenant.0)
        .i64(i64::try_from(limit).map_err(|_| invalid("archive erase batch limit must be 1..64"))?)
        .fetch_all_pool(&self.pool)
        .await?;
        for row in &exports {
            let export: ArchiveExportV1 = decode(row.json("payload")?)?;
            found.extend(export.artifact.into_iter().chain(export.index));
        }
        found.truncate(limit);
        if found.len() < limit {
            let remaining = i64::try_from(limit - found.len())
                .map_err(|_| invalid("archive erase batch limit must be 1..64"))?;
            let records = stmt!(
                B,
                "SELECT r.payload FROM archive_records r JOIN archive_exports e \
                 ON e.tenant_id=r.tenant_id AND e.export_id=r.export_id \
                 WHERE e.tenant_id=$1 AND e.state='deleted' ORDER BY r.export_id,r.ordinal LIMIT $2"
            )
            .uuid(tenant.0)
            .i64(remaining)
            .fetch_all_pool(&self.pool)
            .await?;
            for row in &records {
                let record: ArchiveRecordV1 = decode(row.json("payload")?)?;
                found.push(record.artifact);
            }
        }
        Ok(found)
    }

    async fn acknowledge_erased(&self, tenant: TenantId, artifact: &ArtifactRef) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut tx = self.begin_write().await?;
        let rows = stmt!(
            B,
            format!(
                "SELECT export_id,payload,package_artifact_id,index_artifact_id FROM archive_exports \
                 WHERE tenant_id=$1 AND state='deleted' \
                 AND (package_artifact_id=$2 OR index_artifact_id=$2){}",
                lock::<B>(RowLock::Update)
            )
        )
        .uuid(tenant.0)
        .uuid(artifact.id.0)
        .fetch_all(tx.conn())
        .await?;
        for row in rows {
            let id = row.uuid("export_id")?;
            let mut payload = row.json("payload")?;
            let package_matches = row.opt_uuid("package_artifact_id")? == Some(artifact.id.0);
            let index_matches = row.opt_uuid("index_artifact_id")? == Some(artifact.id.0);
            if let Some(object) = payload.as_object_mut() {
                if package_matches {
                    object.insert("artifact".into(), serde_json::Value::Null);
                }
                if index_matches {
                    object.insert("index".into(), serde_json::Value::Null);
                }
            }
            stmt!(
                B,
                "UPDATE archive_exports SET payload=$3 WHERE tenant_id=$1 AND export_id=$2"
            )
            .uuid(tenant.0)
            .uuid(id)
            .json(&payload)
            .execute(tx.conn())
            .await?;
        }
        stmt!(
            B,
            "DELETE FROM archive_records WHERE tenant_id=$1 AND artifact_id=$2 AND export_id IN \
             (SELECT export_id FROM archive_exports WHERE tenant_id=$1 AND state='deleted')"
        )
        .uuid(tenant.0)
        .uuid(artifact.id.0)
        .execute(tx.conn())
        .await?;
        tx.commit().await
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
        stmt!(
            B,
            "SELECT e.payload FROM archive_exports e JOIN crawl_runs r \
             ON r.tenant_id=e.tenant_id AND r.run_id=e.run_id \
             WHERE e.state<>'deleted' AND r.status NOT IN ('completed','failed','cancelled') \
             AND (e.expires_at IS NULL OR e.expires_at>$1) AND (e.state='published' OR e.lease_until<=$1) \
             ORDER BY e.export_id LIMIT $2"
        )
        .ts(now)
        .i64(i64::from(limit))
        .fetch_all_pool(&self.pool)
        .await?
        .iter()
        .map(|row| decode(row.json("payload")?))
        .collect()
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
        let mut tx = self.begin_write().await?;
        let mut row = locked::<B>(tx.conn(), tenant, export).await?;
        writer(&row, fence, now)?;
        row.state = ArchiveExportState::Failed;
        row.failure = Some(failure);
        save::<B>(tx.conn(), &row).await?;
        tx.commit().await
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
