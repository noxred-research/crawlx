//! Accepted-item, versioned KV and delivery receipt transactions (migration 0029).
//!
//! PostgreSQL helpers run inside the caller's request-completion transaction. Memory helpers
//! stage metadata only; content bytes remain in the existing artifact/volatile store.

use crate::codec::{from_json, get};
use crate::error::{db, not_found};
use crate::Pg;
use async_trait::async_trait;
use crawlx_core::config::{CreateCrawl, RetentionMode};
use crawlx_core::dataset::*;
use crawlx_core::repo::{CrawlRun, Sensitivity};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp, WorkerId};
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{Postgres, Transaction};
#[path = "dataset_state.rs"]
mod state;
pub(crate) use state::{apply_prepared, prepare_memory, prepare_memory_action, DatasetState};

fn conflict(message: &'static str) -> StoreError {
    StoreError::Conflict(message.into())
}
fn expired() -> StoreError {
    StoreError::RetentionDenied("dataset content_expired".into())
}
fn signed(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| conflict("dataset integer overflow"))
}
fn unsigned(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| conflict("negative dataset integer"))
}

pub(crate) fn action_page(ordinal: i64) -> Result<i64, StoreError> {
    if ordinal <= 0 || ordinal >= (1i64 << 56) {
        return Err(StoreError::RetentionDenied(
            "action dataset namespace exhausted".into(),
        ));
    }
    (i64::MIN / 2)
        .checked_add(ordinal)
        .ok_or_else(|| StoreError::RetentionDenied("action dataset namespace overflow".into()))
}
pub(crate) fn bounds(limit: u16) -> Result<(), StoreError> {
    if limit == 0 || usize::from(limit) > MAX_BATCH_ITEMS {
        return Err(conflict("invalid dataset page bounds"));
    }
    Ok(())
}
fn content_valid(
    content: &DatasetContentV1,
    zdr: bool,
    expires: Option<Timestamp>,
    now: Timestamp,
) -> Result<(), StoreError> {
    if expires.is_some_and(|end| end <= now) {
        return Err(expired());
    }
    match content {
        DatasetContentV1::Durable { .. } if !zdr => Ok(()),
        DatasetContentV1::Volatile { expires_at, .. }
            if zdr && *expires_at > now && expires.is_some_and(|end| end <= *expires_at) =>
        {
            Ok(())
        }
        _ => Err(StoreError::RetentionDenied(
            "dataset content retention class mismatch".into(),
        )),
    }
}
fn item_valid(item: &AcceptedItemV1, zdr: bool, now: Timestamp) -> Result<(), StoreError> {
    validate_identifier(&item.item_key)?;
    validate_identifier(&item.transform_version)?;
    validate_identifier(&item.schema_version)?;
    validate_identifier(&item.extractor_version)?;
    if item.size_bytes > MAX_VALUE_BYTES
        || matches!(
            item.sensitivity,
            Sensitivity::CredentialBearing | Sensitivity::Sensitive
        )
    {
        return Err(StoreError::RetentionDenied(
            "dataset item exceeds content policy".into(),
        ));
    }
    content_valid(&item.content, zdr, item.expires_at, now)
}
fn delta_valid(
    delta: &KvCasV1,
    config: &DatasetConfigV1,
    zdr: bool,
    now: Timestamp,
) -> Result<(), StoreError> {
    validate_identifier(&delta.store)?;
    validate_identifier(&delta.key)?;
    let declaration = config
        .kv_stores
        .iter()
        .find(|store| store.name == delta.store)
        .ok_or_else(|| conflict("undeclared kv namespace"))?;
    if delta.content_type.is_empty()
        || delta.content_type.len() > 128
        || delta.content_type.bytes().any(|b| b.is_ascii_control())
        || delta.size_bytes > declaration.max_value_bytes
        || delta.expected_version >= i64::MAX.unsigned_abs()
    {
        return Err(conflict("invalid kv value bounds"));
    }
    if let Some(content) = &delta.content {
        content_valid(content, zdr, delta.expires_at, now)?;
    } else if delta.size_bytes != 0 {
        return Err(conflict("kv tombstone has content size"));
    }
    if delta.expires_at.is_some_and(|end| end <= now) || (zdr && delta.expires_at.is_none()) {
        return Err(expired());
    }
    Ok(())
}
fn delivery_valid(
    batch: &DeliveryBatchV1,
    config: &DatasetConfigV1,
    zdr: bool,
    now: Timestamp,
) -> Result<(), StoreError> {
    validate_identifier(&batch.feed)?;
    validate_identifier(&batch.idempotency_key)?;
    let feed = config
        .feeds
        .iter()
        .find(|feed| feed.id == batch.feed)
        .ok_or_else(|| conflict("undeclared delivery feed"))?;
    let (first, last) = match batch.range {
        DeliveryRangeV1::Committed { first, last } => (first, last),
        _ => return Err(conflict("delivery range has not been allocated")),
    };
    let count = last
        .checked_sub(first)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| conflict("invalid delivery ordinal range"))?;
    if first == 0 || count > u64::from(feed.max_batch_items) || batch.size_bytes > feed.max_batch_bytes {
        return Err(conflict("delivery batch exceeds feed bounds"));
    }
    content_valid(&batch.content, zdr, Some(batch.expires_at), now)
}

async fn config_tx(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    run: CrawlRunId,
) -> Result<(TenantId, CreateCrawl, Timestamp), StoreError> {
    let row = sqlx::query("SELECT tenant_id, config, retention_mode::text AS retention_mode, now() AS clock FROM crawl_runs WHERE run_id=$1 FOR UPDATE")
        .bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?.ok_or_else(|| not_found("crawl_run", run))?;
    let tenant = TenantId(get(&row, "tenant_id")?);
    check_tenant(tenant)?;
    let config = if get::<String>(&row, "retention_mode")? == "zdr" {
        pg.ephemeral_get(tenant, run, i64::MIN, "run_config").await?
    } else {
        from_json(get(&row, "config")?)?
    };
    Ok((tenant, config, get(&row, "clock")?))
}

// Dedicated negative namespace, disjoint from frontier rows and reserved operational slots.
fn manifest_page(tag: u8, id: i64) -> Result<i64, StoreError> {
    if !(1..=3).contains(&tag) || id <= 0 || id >= (1i64 << 56) {
        return Err(conflict("dataset volatile namespace exhausted"));
    }
    i64::MIN
        .checked_add(i64::from(tag) << 56)
        .and_then(|base| base.checked_add(id))
        .ok_or_else(|| conflict("dataset volatile namespace overflow"))
}

// Keep transaction, tenant/run scope, and content retention checks explicit at each call site.
#[allow(clippy::too_many_arguments)]
async fn verify_content(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
    content: &DatasetContentV1,
    size: u64,
    deadline: Option<Timestamp>,
    now: Timestamp,
) -> Result<(), StoreError> {
    match content {
        DatasetContentV1::Durable { artifact } => {
            let row = sqlx::query("SELECT size_bytes, content_digest, sensitivity::text AS sensitivity, expires_at FROM artifacts WHERE artifact_id=$1 AND tenant_id=$2 AND run_id=$3 AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > now())")
                .bind(artifact.id.0).bind(tenant.0).bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?
                .ok_or_else(|| StoreError::RetentionDenied("dataset artifact unavailable".into()))?;
            if unsigned(get(&row, "size_bytes")?)? != size
                || get::<Vec<u8>>(&row, "content_digest")? != artifact.digest.0
                || get::<Option<Timestamp>>(&row, "expires_at")?
                    .is_some_and(|end| deadline.is_none_or(|deadline| deadline > end))
                || matches!(
                    get::<String>(&row, "sensitivity")?.as_str(),
                    "sensitive" | "credential_bearing"
                )
            {
                return Err(StoreError::RetentionDenied(
                    "dataset artifact policy mismatch".into(),
                ));
            }
        }
        DatasetContentV1::Volatile {
            page,
            artifact,
            expires_at,
        } => {
            let buffer = pg.delivery.as_ref().ok_or_else(expired)?;
            let (original_expiry, actual_size) = buffer
                .content_metadata(tenant, run, *page, artifact)
                .await?
                .ok_or_else(expired)?;
            if original_expiry != *expires_at || *expires_at <= now || actual_size != size {
                return Err(expired());
            }
        }
        _ => {
            return Err(StoreError::RetentionDenied(
                "unsupported dataset content handle".into(),
            ))
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_payload<T: Serialize + Sync>(
    pg: &Pg,
    tenant: TenantId,
    run: CrawlRunId,
    page: i64,
    kind: &str,
    value: &T,
    zdr: bool,
    expires_at: Option<Timestamp>,
) -> Result<Option<serde_json::Value>, StoreError> {
    if zdr {
        let deadline = expires_at.ok_or_else(expired)?;
        let bytes =
            serde_json::to_vec(value).map_err(|error| StoreError::Serialization(error.to_string()))?;
        pg.delivery
            .as_ref()
            .ok_or_else(expired)?
            .insert_until(tenant, run, page, kind, "application/json", &bytes, deadline)
            .await?;
        Ok(None)
    } else {
        serde_json::to_value(value)
            .map(Some)
            .map_err(|error| StoreError::Serialization(error.to_string()))
    }
}
async fn read_payload<T: DeserializeOwned>(
    pg: &Pg,
    tenant: TenantId,
    run: CrawlRunId,
    row: &sqlx::postgres::PgRow,
    kind: &str,
) -> Result<T, StoreError> {
    match get::<Option<serde_json::Value>>(row, "payload")? {
        Some(value) => from_json(value),
        None => {
            pg.ephemeral_get(tenant, run, get(row, "volatile_page")?, kind)
                .await
        }
    }
}

/// Apply accepted items, state CAS and immutable outbox in the existing request transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_pg(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    run: CrawlRunId,
    request: i64,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
) -> Result<(), StoreError> {
    apply_pg_source(pg, tx, run, request, None, accepted, deltas, outbox).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_pg_action(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    run: CrawlRunId,
    action: crawlx_core::ActionId,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
) -> Result<(), StoreError> {
    apply_pg_source(pg, tx, run, 0, Some(action), accepted, deltas, outbox).await
}

#[allow(clippy::too_many_arguments)]
async fn apply_pg_source(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    run: CrawlRunId,
    request: i64,
    action: Option<crawlx_core::ActionId>,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
) -> Result<(), StoreError> {
    if accepted.is_empty() && deltas.is_empty() && outbox.is_empty() {
        return Ok(());
    }
    let count = accepted.iter().try_fold(0usize, |count, batch| {
        count
            .checked_add(batch.items.len())
            .ok_or_else(|| conflict("accepted item batch overflow"))
    })?;
    if accepted.len() > 64 || count > MAX_BATCH_ITEMS {
        return Err(conflict("accepted item batch limit"));
    }
    let (tenant, config, now) = config_tx(pg, tx, run).await?;
    config.datasets.validate()?;
    let zdr = config.retention.mode == RetentionMode::Zdr;
    if deltas.len() > MAX_BATCH_ITEMS || outbox.len() > MAX_BATCH_ITEMS {
        return Err(conflict("dataset transaction batch limit"));
    }
    for batch in accepted {
        validate_identifier(&batch.dataset)?;
        if batch.items.len() > MAX_BATCH_ITEMS {
            return Err(conflict("accepted item batch limit"));
        }
        let declaration = config
            .datasets
            .stores
            .iter()
            .find(|store| store.name == batch.dataset)
            .ok_or_else(|| conflict("undeclared dataset namespace"))?;
        sqlx::query("INSERT INTO datasets(tenant_id,run_id,name) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(tenant.0)
            .bind(run.0)
            .bind(&batch.dataset)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        let row = sqlx::query("SELECT dataset_id,next_ordinal,item_count,size_bytes FROM datasets WHERE tenant_id=$1 AND run_id=$2 AND name=$3 FOR UPDATE")
            .bind(tenant.0).bind(run.0).bind(&batch.dataset).fetch_one(&mut **tx).await.map_err(db)?;
        let dataset: i64 = get(&row, "dataset_id")?;
        let mut ordinal: i64 = get(&row, "next_ordinal")?;
        let mut count = unsigned(get(&row, "item_count")?)?;
        let mut bytes = unsigned(get(&row, "size_bytes")?)?;
        for item in &batch.items {
            item_valid(item, zdr, now)?;
            if item.schema_version != declaration.schema_version {
                return Err(conflict("dataset schema mismatch"));
            }
            verify_content(
                pg,
                tx,
                tenant,
                run,
                &item.content,
                item.size_bytes,
                item.expires_at,
                now,
            )
            .await?;
            let identity = crawlx_core::hash::Digest::of_value(
                "crawlx/accepted-item-key/v1",
                &(&item.item_key, &item.transform_version),
            )
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
            let existing = sqlx::query("SELECT payload,volatile_page FROM dataset_items WHERE tenant_id=$1 AND dataset_id=$2 AND source_request_id IS NOT DISTINCT FROM $3 AND identity_key=$4 AND source_action_id IS NOT DISTINCT FROM $5")
                .bind(tenant.0).bind(dataset).bind(action.is_none().then_some(request)).bind(identity.0.to_vec()).bind(action.map(|id| id.0))
                .fetch_optional(&mut **tx).await.map_err(db)?;
            if let Some(existing) = existing {
                let old: DatasetItemV1 = read_payload(pg, tenant, run, &existing, "dataset_item").await?;
                if old.item != *item {
                    return Err(conflict("accepted item identity changed"));
                }
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| conflict("dataset count overflow"))?;
            bytes = bytes
                .checked_add(item.size_bytes)
                .ok_or_else(|| conflict("dataset bytes overflow"))?;
            if count > declaration.max_items || bytes > declaration.max_bytes {
                return Err(conflict("dataset quota exhausted"));
            }
            let mut record = DatasetItemV1::new(unsigned(ordinal)?, request, item.clone());
            record.source_action = action;
            let row = sqlx::query("INSERT INTO dataset_items(tenant_id,run_id,dataset_id,ordinal,source_request_id,identity_key,payload,volatile_page,size_bytes,expires_at,source_action_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING item_id")
                .bind(tenant.0).bind(run.0).bind(dataset).bind(ordinal).bind(action.is_none().then_some(request)).bind(identity.0.to_vec())
                .bind(if zdr { None } else { Some(serde_json::to_value(&record).map_err(|error| StoreError::Serialization(error.to_string()))?) })
                .bind(zdr.then_some(0i64)).bind(signed(item.size_bytes)?).bind(item.expires_at).bind(action.map(|id| id.0))
                .fetch_one(&mut **tx).await.map_err(db)?;
            if zdr {
                let page = manifest_page(1, get(&row, "item_id")?)?;
                write_payload(
                    pg,
                    tenant,
                    run,
                    page,
                    "dataset_item",
                    &record,
                    true,
                    item.expires_at,
                )
                .await?;
                sqlx::query("UPDATE dataset_items SET volatile_page=$1 WHERE item_id=$2 AND tenant_id=$3")
                    .bind(page)
                    .bind(get::<i64>(&row, "item_id")?)
                    .bind(tenant.0)
                    .execute(&mut **tx)
                    .await
                    .map_err(db)?;
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| conflict("dataset ordinal overflow"))?;
        }
        sqlx::query("UPDATE datasets SET next_ordinal=$1,item_count=$2,size_bytes=$3 WHERE dataset_id=$4 AND tenant_id=$5")
            .bind(ordinal).bind(signed(count)?).bind(signed(bytes)?).bind(dataset).bind(tenant.0).execute(&mut **tx).await.map_err(db)?;
    }
    for delta in deltas {
        cas_pg(pg, tx, tenant, run, &config, delta, now).await?;
    }
    for batch in outbox {
        let mut resolved = batch.clone();
        verify_content(
            pg,
            tx,
            tenant,
            run,
            &batch.content,
            batch.size_bytes,
            Some(batch.expires_at),
            now,
        )
        .await?;
        let feed = config
            .datasets
            .feeds
            .iter()
            .find(|feed| feed.id == batch.feed)
            .ok_or_else(|| conflict("undeclared delivery feed"))?;
        if matches!(resolved.range, DeliveryRangeV1::AcceptedRequest) {
            let row = sqlx::query("SELECT min(i.ordinal) AS first,max(i.ordinal) AS last FROM dataset_items i JOIN datasets d ON d.dataset_id=i.dataset_id AND d.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.run_id=$2 AND d.name=$3 AND i.source_request_id IS NOT DISTINCT FROM $4 AND i.source_action_id IS NOT DISTINCT FROM $5")
                .bind(tenant.0).bind(run.0).bind(&feed.source).bind(action.is_none().then_some(request)).bind(action.map(|id| id.0))
                .fetch_one(&mut **tx).await.map_err(db)?;
            let first = get::<Option<i64>>(&row, "first")?
                .ok_or_else(|| conflict("delivery source not committed"))?;
            let last =
                get::<Option<i64>>(&row, "last")?.ok_or_else(|| conflict("delivery source not committed"))?;
            resolved.range = DeliveryRangeV1::Committed {
                first: unsigned(first)?,
                last: unsigned(last)?,
            };
        }
        let batch = &resolved;
        delivery_valid(batch, &config.datasets, zdr, now)?;
        let (first, last) = match batch.range {
            DeliveryRangeV1::Committed { first, last } => (first, last),
            _ => return Err(conflict("delivery range has not been allocated")),
        };
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM dataset_items i JOIN datasets d ON d.dataset_id=i.dataset_id AND d.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.run_id=$2 AND d.name=$3 AND i.ordinal BETWEEN $4 AND $5 AND (i.expires_at IS NULL OR i.expires_at>now())")
            .bind(tenant.0).bind(run.0).bind(&feed.source).bind(signed(first)?).bind(signed(last)?)
            .fetch_one(&mut **tx).await.map_err(db)?;
        let wanted = last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| conflict("delivery range overflow"))?;
        if unsigned(count)? != wanted {
            return Err(conflict("delivery references uncommitted items"));
        }
        let old = sqlx::query("SELECT payload,volatile_page FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND feed=$3 AND idempotency_key=$4")
            .bind(tenant.0).bind(run.0).bind(&batch.feed).bind(&batch.idempotency_key).fetch_optional(&mut **tx).await.map_err(db)?;
        if let Some(old) = old {
            let previous: DeliveryBatchV1 = read_payload(pg, tenant, run, &old, "dataset_delivery").await?;
            if previous != *batch {
                return Err(conflict("delivery identity changed"));
            }
            continue;
        }
        let id: i64 = sqlx::query_scalar("INSERT INTO dataset_delivery_outbox(tenant_id,run_id,source_request_id,feed,idempotency_key,payload,volatile_page,expires_at,source_action_id,content_page) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING delivery_id")
            .bind(tenant.0).bind(run.0).bind(action.is_none().then_some(request)).bind(&batch.feed).bind(&batch.idempotency_key)
            .bind(if zdr { None } else { Some(serde_json::to_value(batch).map_err(|error| StoreError::Serialization(error.to_string()))?) })
            .bind(zdr.then_some(0i64)).bind(batch.expires_at).bind(action.map(|id| id.0))
            .bind(match &batch.content { DatasetContentV1::Volatile {page,..} => Some(*page),DatasetContentV1::Durable {..} => None,
                _ => return Err(conflict("unsupported dataset content handle")) })
            .fetch_one(&mut **tx).await.map_err(db)?;
        if zdr {
            let page = manifest_page(2, id)?;
            write_payload(
                pg,
                tenant,
                run,
                page,
                "dataset_delivery",
                batch,
                true,
                Some(batch.expires_at),
            )
            .await?;
            sqlx::query(
                "UPDATE dataset_delivery_outbox SET volatile_page=$1 WHERE delivery_id=$2 AND tenant_id=$3",
            )
            .bind(page)
            .bind(id)
            .bind(tenant.0)
            .execute(&mut **tx)
            .await
            .map_err(db)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cas_pg(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
    config: &CreateCrawl,
    delta: &KvCasV1,
    now: Timestamp,
) -> Result<KvValueV1, StoreError> {
    let zdr = config.retention.mode == RetentionMode::Zdr;
    delta_valid(delta, &config.datasets, zdr, now)?;
    kv_scope(pg, tx, tenant, run, &config.datasets, &delta.store).await?;
    if let Some(content) = &delta.content {
        verify_content(
            pg,
            tx,
            tenant,
            run,
            content,
            delta.size_bytes,
            delta.expires_at,
            now,
        )
        .await?;
    }
    let old = sqlx::query("SELECT version,expires_at,payload,volatile_page FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND key=$4 FOR UPDATE")
        .bind(tenant.0).bind(run.0).bind(&delta.store).bind(&delta.key).fetch_optional(&mut **tx).await.map_err(db)?;
    let old_version = old
        .as_ref()
        .map(|row| get::<i64>(row, "version"))
        .transpose()?
        .map(unsigned)
        .transpose()?
        .unwrap_or(0);
    if old_version != delta.expected_version {
        return Err(conflict("kv compare-and-set collision"));
    }
    if let Some(old) = &old {
        let expires: Option<Timestamp> = get(old, "expires_at")?;
        if expires.is_some_and(|end| end <= now) {
            return Err(expired());
        }
        if expires != delta.expires_at {
            return Err(conflict("kv expiry is immutable"));
        }
    }
    let store = config
        .datasets
        .kv_stores
        .iter()
        .find(|store| store.name == delta.store)
        .ok_or_else(|| conflict("undeclared kv namespace"))?;
    let usage = sqlx::query("SELECT count(*) AS keys,COALESCE(sum(size_bytes),0)::bigint AS bytes FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND key<>$4")
        .bind(tenant.0).bind(run.0).bind(&delta.store).bind(&delta.key).fetch_one(&mut **tx).await.map_err(db)?;
    if unsigned(get(&usage, "keys")?)?
        .checked_add(1)
        .is_none_or(|n| n > u64::from(store.max_keys))
        || unsigned(get(&usage, "bytes")?)?
            .checked_add(delta.size_bytes)
            .is_none_or(|n| n > store.max_bytes)
    {
        return Err(conflict("kv quota exhausted"));
    }
    let version = delta
        .expected_version
        .checked_add(1)
        .ok_or_else(|| conflict("kv version overflow"))?;
    let value = KvValueV1::new(version, delta.clone());
    // Never overwrite committed volatile metadata before this transaction commits.
    // Orphan generations expire independently; the relational deadline remains immutable.
    let page = if zdr {
        let next: i64 =
            sqlx::query_scalar("SELECT nextval(pg_get_serial_sequence('dataset_items','item_id'))")
                .fetch_one(&mut **tx)
                .await
                .map_err(db)?;
        Some(manifest_page(3, next)?)
    } else {
        None
    };
    let payload = write_payload(
        pg,
        tenant,
        run,
        page.unwrap_or(0),
        "dataset_kv",
        &value,
        zdr,
        delta.expires_at,
    )
    .await?;
    sqlx::query("INSERT INTO dataset_kv(tenant_id,run_id,store,key,version,payload,volatile_page,size_bytes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(tenant_id,run_id,store,key) DO UPDATE SET version=EXCLUDED.version,payload=EXCLUDED.payload,volatile_page=EXCLUDED.volatile_page,size_bytes=EXCLUDED.size_bytes,expires_at=EXCLUDED.expires_at")
        .bind(tenant.0).bind(run.0).bind(&delta.store).bind(&delta.key).bind(signed(version)?).bind(payload).bind(page)
        .bind(signed(delta.size_bytes)?).bind(delta.expires_at).execute(&mut **tx).await.map_err(db)?;
    Ok(value)
}

#[async_trait]
impl DatasetRepo for Pg {
    async fn items(
        &self,
        run: CrawlRunId,
        dataset: &str,
        after: u64,
        limit: u16,
    ) -> Result<Vec<DatasetItemV1>, StoreError> {
        bounds(limit)?;
        validate_identifier(dataset)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, config, now) = config_tx(self, &mut tx, run).await?;
        if !config.datasets.stores.iter().any(|store| store.name == dataset) {
            return Err(conflict("undeclared dataset namespace"));
        }
        let rows = sqlx::query("SELECT i.payload,i.volatile_page,i.expires_at FROM dataset_items i JOIN datasets d ON d.dataset_id=i.dataset_id AND d.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.run_id=$2 AND d.name=$3 AND i.ordinal>$4 ORDER BY i.ordinal LIMIT $5")
            .bind(tenant.0).bind(run.0).bind(dataset).bind(signed(after)?).bind(i64::from(limit)).fetch_all(&mut *tx).await.map_err(db)?;
        let mut output = Vec::with_capacity(rows.len());
        for row in rows {
            if get::<Option<Timestamp>>(&row, "expires_at")?.is_some_and(|end| end <= now) {
                return Err(expired());
            }
            let item: DatasetItemV1 = read_payload(self, tenant, run, &row, "dataset_item").await?;
            verify_content(
                self,
                &mut tx,
                tenant,
                run,
                &item.item.content,
                item.item.size_bytes,
                item.item.expires_at,
                now,
            )
            .await?;
            output.push(item);
        }
        tx.commit().await.map_err(db)?;
        Ok(output)
    }
}

#[async_trait]
impl KvRepo for Pg {
    async fn value(&self, run: CrawlRunId, store: &str, key: &str) -> Result<Option<KvValueV1>, StoreError> {
        validate_identifier(store)?;
        validate_identifier(key)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, config, now) = config_tx(self, &mut tx, run).await?;
        kv_scope(self, &mut tx, tenant, run, &config.datasets, store).await?;
        let row = sqlx::query("SELECT payload,volatile_page,expires_at FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND key=$4")
            .bind(tenant.0).bind(run.0).bind(store).bind(key).fetch_optional(&mut *tx).await.map_err(db)?;
        let Some(row) = row else {
            tx.commit().await.map_err(db)?;
            return Ok(None);
        };
        if get::<Option<Timestamp>>(&row, "expires_at")?.is_some_and(|end| end <= now) {
            return Err(expired());
        }
        let value: KvValueV1 = read_payload(self, tenant, run, &row, "dataset_kv").await?;
        if let Some(content) = &value.value.content {
            verify_content(
                self,
                &mut tx,
                tenant,
                run,
                content,
                value.value.size_bytes,
                value.value.expires_at,
                now,
            )
            .await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(Some(value))
    }
    async fn compare_and_set(&self, run: CrawlRunId, delta: KvCasV1) -> Result<KvValueV1, StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, config, now) = config_tx(self, &mut tx, run).await?;
        let value = cas_pg(self, &mut tx, tenant, run, &config, &delta, now).await?;
        tx.commit().await.map_err(db)?;
        Ok(value)
    }
    async fn keys(
        &self,
        run: CrawlRunId,
        store: &str,
        after: &str,
        limit: u16,
    ) -> Result<Vec<KvValueV1>, StoreError> {
        bounds(limit)?;
        validate_identifier(store)?;
        if !after.is_empty() {
            validate_identifier(after)?;
        }
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, config, now) = config_tx(self, &mut tx, run).await?;
        kv_scope(self, &mut tx, tenant, run, &config.datasets, store).await?;
        let rows = sqlx::query("SELECT payload,volatile_page FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND key>$4 AND (expires_at IS NULL OR expires_at>now()) ORDER BY key LIMIT $5")
            .bind(tenant.0).bind(run.0).bind(store).bind(after).bind(i64::from(limit)).fetch_all(&mut *tx).await.map_err(db)?;
        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            let value: KvValueV1 = read_payload(self, tenant, run, &row, "dataset_kv").await?;
            if let Some(content) = &value.value.content {
                verify_content(
                    self,
                    &mut tx,
                    tenant,
                    run,
                    content,
                    value.value.size_bytes,
                    value.value.expires_at,
                    now,
                )
                .await?;
            }
            values.push(value);
        }
        tx.commit().await.map_err(db)?;
        Ok(values)
    }
    async fn drop_store(&self, run: CrawlRunId, store: &str) -> Result<(), StoreError> {
        validate_identifier(store)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let (tenant, config, _) = config_tx(self, &mut tx, run).await?;
        if !config
            .datasets
            .kv_stores
            .iter()
            .any(|declaration| declaration.name == store)
        {
            return Err(conflict("undeclared kv namespace"));
        }
        sqlx::query(
            "INSERT INTO dataset_kv_drops(tenant_id,run_id,store) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(tenant.0)
        .bind(run.0)
        .bind(store)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        sqlx::query("DELETE FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3")
            .bind(tenant.0)
            .bind(run.0)
            .bind(store)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)
    }
}

async fn kv_scope(
    _pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
    config: &DatasetConfigV1,
    store: &str,
) -> Result<(), StoreError> {
    if !config
        .kv_stores
        .iter()
        .any(|declaration| declaration.name == store)
    {
        return Err(conflict("undeclared kv namespace"));
    }
    let dropped: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM dataset_kv_drops WHERE tenant_id=$1 AND run_id=$2 AND store=$3)",
    )
    .bind(tenant.0)
    .bind(run.0)
    .bind(store)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if dropped {
        return Err(conflict("kv namespace dropped"));
    }
    Ok(())
}

#[async_trait]
impl DeliveryOutboxRepo for Pg {
    async fn ready_runs(&self, after: Option<CrawlRunId>, limit: u16) -> Result<Vec<CrawlRunId>, StoreError> {
        bounds(limit)?;
        let rows:Vec<uuid::Uuid> = sqlx::query_scalar("SELECT run_id FROM dataset_delivery_outbox WHERE ($2::uuid IS NULL OR run_id>$2) AND ($3::uuid IS NULL OR tenant_id=$3) AND ((state IN ('pending','leased') AND (expires_at<=now() OR (not_before<=now() AND (lease_expires_at IS NULL OR lease_expires_at<=now())))) OR (state IN ('delivered','content_expired') AND erased_at IS NULL AND volatile_page IS NOT NULL)) GROUP BY run_id ORDER BY run_id LIMIT $1")
            .bind(i64::from(limit)).bind(after.map(|run|run.0)).bind(crate::tenant::current().map(|tenant|tenant.0)).fetch_all(&self.pool).await.map_err(db)?;
        Ok(rows.into_iter().map(CrawlRunId).collect())
    }
    async fn maintain(&self, run: CrawlRunId) -> Result<(), StoreError> {
        let (tenant, _) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        sqlx::query("WITH expired AS (SELECT delivery_id FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND state IN ('pending','leased') AND expires_at<=now() ORDER BY delivery_id LIMIT 1000 FOR UPDATE SKIP LOCKED) UPDATE dataset_delivery_outbox o SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL FROM expired WHERE o.delivery_id=expired.delivery_id")
            .bind(tenant.0).bind(run.0).execute(&self.pool).await.map_err(db)?;
        cleanup_delivered(self, tenant, run).await
    }
    async fn expire(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        let (tenant, _) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        let row = sqlx::query("UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND fence=$4 AND state IN ('pending','leased','content_expired') AND expires_at<=now() RETURNING content_page,volatile_page")
            .bind(tenant.0).bind(run.0).bind(id).bind(fence).fetch_optional(&self.pool).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        if let Some(buffer) = &self.delivery {
            for column in ["content_page", "volatile_page"] {
                if let Some(page) = get::<Option<i64>>(&row, column)? {
                    buffer.ack(tenant, run, page).await?;
                }
            }
        }
        Ok(())
    }
    async fn claim(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        limit: u16,
        lease_seconds: u16,
    ) -> Result<Vec<DurableDeliveryOutboxV1>, StoreError> {
        bounds(limit)?;
        if lease_seconds == 0 || lease_seconds > 300 {
            return Err(conflict("invalid delivery lease duration"));
        }
        let (tenant, _) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        cleanup_delivered(self, tenant, run).await?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND state IN ('pending','leased') AND expires_at<=now()")
            .bind(tenant.0).bind(run.0).execute(&mut *tx).await.map_err(db)?;
        let rows = sqlx::query("WITH picked AS (SELECT delivery_id FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND expires_at>now() AND not_before<=now() AND (state='pending' OR (state='leased' AND lease_expires_at<=now())) ORDER BY delivery_id FOR UPDATE SKIP LOCKED LIMIT $3) UPDATE dataset_delivery_outbox o SET state='leased',attempts=o.attempts+1,fence=o.fence+1,lease_owner=$4,lease_expires_at=now()+make_interval(secs=>$5) FROM picked WHERE o.delivery_id=picked.delivery_id RETURNING o.delivery_id,o.payload,o.volatile_page,o.fence,o.attempts")
            .bind(tenant.0).bind(run.0).bind(i64::from(limit)).bind(worker.0).bind(f64::from(lease_seconds))
            .fetch_all(&mut *tx).await.map_err(db)?;
        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
            let batch: Result<DeliveryBatchV1, StoreError> =
                read_payload(self, tenant, run, &row, "dataset_delivery").await;
            match batch {
                Ok(batch) => {
                    let mut receipt = DurableDeliveryOutboxV1::pending(get(&row, "delivery_id")?, run, batch);
                    receipt.fence = get(&row, "fence")?;
                    receipt.attempts = u32::try_from(get::<i32>(&row, "attempts")?)
                        .map_err(|_| conflict("delivery attempts overflow"))?;
                    receipt.state = DeliveryStateV1::Leased;
                    claims.push(receipt);
                }
                Err(StoreError::RetentionDenied(_)) => {
                    sqlx::query("UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND delivery_id=$2")
                        .bind(tenant.0).bind(get::<i64>(&row,"delivery_id")?).execute(&mut *tx).await.map_err(db)?;
                }
                Err(error) => return Err(error),
            }
        }
        tx.commit().await.map_err(db)?;
        cleanup_delivered(self, tenant, run).await?;
        claims.sort_by_key(|claim| claim.id);
        Ok(claims)
    }
    async fn acknowledge(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        let (tenant, zdr) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        sqlx::query("SELECT delivery_id FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND fence=$4 AND (state='delivered' OR (state='leased' AND lease_expires_at>now() AND expires_at>now())) FOR UPDATE")
            .bind(tenant.0).bind(run.0).bind(id).bind(fence).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(StoreError::LeaseLost)?;
        sqlx::query("UPDATE dataset_delivery_outbox SET state='delivered',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND delivery_id=$2 AND fence=$3")
            .bind(tenant.0).bind(id).bind(fence).execute(&mut *tx).await.map_err(db)?;
        // Commit the receipt before erasing content. A crash can only leave retriable cleanup.
        tx.commit().await.map_err(db)?;
        if zdr {
            cleanup_delivered(self, tenant, run).await?;
        }
        Ok(())
    }
    async fn retry(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        not_before: Timestamp,
    ) -> Result<(), StoreError> {
        let (tenant, _) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        let updated = sqlx::query("UPDATE dataset_delivery_outbox SET state='pending',not_before=$5,lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND state='leased' AND fence=$4 AND lease_expires_at>now() AND expires_at>now() AND $5>=now() AND $5<=expires_at AND $5<=now()+interval '1 day'")
            .bind(tenant.0).bind(run.0).bind(id).bind(fence).bind(not_before).execute(&self.pool).await.map_err(db)?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }
}

async fn cleanup_delivered(pg: &Pg, tenant: TenantId, run: CrawlRunId) -> Result<(), StoreError> {
    let rows = sqlx::query("SELECT delivery_id,volatile_page,content_page FROM dataset_delivery_outbox o WHERE tenant_id=$1 AND run_id=$2 AND state IN ('delivered','content_expired') AND erased_at IS NULL AND volatile_page IS NOT NULL ORDER BY delivery_id LIMIT 1000")
        .bind(tenant.0).bind(run.0).fetch_all(&pg.pool).await.map_err(db)?;
    if rows.is_empty() {
        return Ok(());
    }
    let buffer = pg.delivery.as_ref().ok_or_else(expired)?;
    for row in rows {
        if let Some(page) = get::<Option<i64>>(&row, "content_page")? {
            let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND content_page=$3 AND state IN ('pending','leased') AND expires_at>now())")
                .bind(tenant.0).bind(run.0).bind(page).fetch_one(&pg.pool).await.map_err(db)?;
            if live {
                continue;
            }
            buffer.ack(tenant, run, page).await?;
        }
        buffer.ack(tenant, run, get(&row, "volatile_page")?).await?;
        sqlx::query("UPDATE dataset_delivery_outbox SET erased_at=now() WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND state IN ('delivered','content_expired')")
            .bind(tenant.0).bind(run.0).bind(get::<i64>(&row,"delivery_id")?).execute(&pg.pool).await.map_err(db)?;
    }
    Ok(())
}

fn check_tenant(tenant: TenantId) -> Result<(), StoreError> {
    if crate::tenant::current().is_some_and(|scope| scope != tenant) {
        return Err(StoreError::AccessDenied("dataset tenant mismatch".into()));
    }
    Ok(())
}

#[cfg(test)]
mod namespace_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn tagged_manifest_pages_cannot_overlap_operational_frontier_action_or_other_manifest_pages() {
        let maximum = (1i64 << 56) - 1;
        assert!(manifest_page(1, 1).unwrap() > i64::MIN + 2);
        for tag in 1..3 {
            assert!(manifest_page(tag, maximum).unwrap() < manifest_page(tag + 1, 1).unwrap());
        }
        assert!(manifest_page(3, maximum).unwrap() < action_page(1).unwrap());
        assert!(action_page(maximum).unwrap() < 0);
        for tag in 1..=3 {
            assert!(manifest_page(tag, 0).is_err());
            assert!(manifest_page(tag, 1i64 << 56).is_err());
            assert!(manifest_page(tag, -1).is_err());
        }
        assert!(manifest_page(4, 1).is_err());
        assert!(action_page(1i64 << 56).is_err());
    }
}
