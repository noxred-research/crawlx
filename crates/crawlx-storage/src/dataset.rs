//! Accepted-item, versioned KV and delivery receipt transactions (migration 0029).
//!
//! The SQL helpers run inside the caller's request-completion transaction on any engine. The
//! repositories are generic over the storage backend (`impl<B: Sql> .. for Store<B>`).
//! Memory helpers stage metadata only; content bytes remain in the existing artifact/volatile
//! store.

use crate::backend::strategy::{Conn, FenceSeq, OutboxClaim};
use crate::backend::{Backend, BackendKind, Dialect, RowLock};
use crate::codec::from_json;
use crate::error::not_found;
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::config::{CreateCrawl, RetentionMode};
use crawlx_core::dataset::*;
use crawlx_core::repo::{CrawlRun, Sensitivity};
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp, WorkerId};
use serde::{de::DeserializeOwned, Serialize};
#[path = "dataset_state.rs"]
mod state;
pub(crate) use state::{
    apply_prepared, prepare_memory, prepare_memory_action, DatasetState, MemoryFinalizer,
};
#[path = "dataset_memo.rs"]
pub(crate) mod memo;

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
    if item.feed_fragments.len() > 64 {
        return Err(conflict("feed fragment count limit"));
    }
    let mut feeds = std::collections::BTreeSet::new();
    for fragment in &item.feed_fragments {
        validate_identifier(&fragment.feed)?;
        validate_identifier(&fragment.idempotency_key)?;
        if !feeds.insert(&fragment.feed)
            || fragment.range != DeliveryRangeV1::AcceptedRequest
            || fragment.size_bytes > MAX_VALUE_BYTES
            || item.expires_at.is_none_or(|end| fragment.expires_at > end)
        {
            return Err(conflict("invalid accepted feed fragment"));
        }
        content_valid(&fragment.content, zdr, Some(fragment.expires_at), now)?;
    }
    content_valid(&item.content, zdr, item.expires_at, now)
}

fn item_bytes(item: &AcceptedItemV1) -> Result<u64, StoreError> {
    item.feed_fragments
        .iter()
        .try_fold(item.size_bytes, |total, fragment| {
            total
                .checked_add(fragment.size_bytes)
                .ok_or_else(|| conflict("feed fragment byte overflow"))
        })
}

fn fragments_valid(item: &AcceptedItemV1, config: &DatasetConfigV1, source: &str) -> Result<(), StoreError> {
    for fragment in &item.feed_fragments {
        let feed = config
            .feeds
            .iter()
            .find(|feed| feed.id == fragment.feed)
            .ok_or_else(|| conflict("undeclared fragment feed"))?;
        if feed.source != source
            || feed.batching != FeedBatchingV1::Terminal
            || fragment.size_bytes > feed.max_batch_bytes
        {
            return Err(conflict("feed fragment declaration mismatch"));
        }
    }
    Ok(())
}
// RFC 9110 media-type syntax, not a header-value or media-range check. The existing
// metadata policy forbids controls, including HTAB, even inside quoted parameters.
fn valid_content_type(value: &str) -> bool {
    if value.len() > 128 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    fn token_len(bytes: &[u8]) -> usize {
        bytes
            .iter()
            .position(|byte| {
                !(byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    ))
            })
            .unwrap_or(bytes.len())
    }
    let mut remaining = value.as_bytes();
    let end = token_len(remaining);
    if end == 0 || remaining.get(end) != Some(&b'/') || remaining[..end].contains(&b'*') {
        return false;
    }
    remaining = &remaining[end + 1..];
    let end = token_len(remaining);
    if end == 0 || remaining[..end].contains(&b'*') {
        return false;
    }
    remaining = &remaining[end..];
    loop {
        remaining = remaining.trim_ascii_start();
        if remaining.is_empty() {
            return true;
        }
        let Some(parameters) = remaining.strip_prefix(b";") else {
            return false;
        };
        remaining = parameters.trim_ascii_start();
        let end = token_len(remaining);
        if end == 0 || remaining.get(end) != Some(&b'=') {
            return false;
        }
        remaining = &remaining[end + 1..];
        if remaining.first() == Some(&b'"') {
            let mut cursor = 1;
            loop {
                match remaining.get(cursor) {
                    Some(b'"') => {
                        remaining = &remaining[cursor + 1..];
                        break;
                    }
                    Some(b'\\') if remaining.get(cursor + 1).is_some() => cursor += 2,
                    Some(b'\\') | None => return false,
                    Some(_) => cursor += 1,
                }
            }
        } else {
            let end = token_len(remaining);
            if end == 0 {
                return false;
            }
            remaining = &remaining[end..];
        }
    }
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
    if !valid_content_type(&delta.content_type)
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
    let count = match batch.range {
        DeliveryRangeV1::Empty if feed.empty_policy == EmptyFeedPolicyV1::Emit => 0,
        DeliveryRangeV1::Committed { first, last } if first > 0 => last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| conflict("invalid delivery ordinal range"))?,
        _ => return Err(conflict("delivery range has not been allocated")),
    };
    if count > u64::from(feed.max_batch_items) || batch.size_bytes > feed.max_batch_bytes {
        return Err(conflict("delivery batch exceeds feed bounds"));
    }
    content_valid(&batch.content, zdr, Some(batch.expires_at), now)
}

/// Database time in the caller's transaction (`now()` on PostgreSQL).
fn sql_now<B: Backend>() -> &'static str {
    <B::Dialect as Dialect>::now()
}

/// The row locking clause of the engine, with a leading space (empty on SQLite).
fn lock<B: Backend>(lock: RowLock) -> &'static str {
    <B::Dialect as Dialect>::row_lock(lock)
}

/// The run's tenant, configuration and database time, with the run row locked.
///
/// The run is read by `run_id` only; the tenant comes from the row and is then checked
/// against the current tenant scope.
pub(crate) async fn config_tx<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    run: CrawlRunId,
) -> Result<(TenantId, CreateCrawl, Timestamp), StoreError> {
    store.scope()?;
    let row = stmt!(
        B,
        format!(
            "SELECT tenant_id, config, retention_mode::text AS retention_mode, {} AS clock FROM crawl_runs WHERE run_id=$1{}",
            sql_now::<B>(),
            lock::<B>(RowLock::Update)
        )
    )
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| not_found("crawl_run", run))?;
    let tenant = TenantId(row.uuid("tenant_id")?);
    check_tenant(tenant)?;
    let config = if row.text("retention_mode")? == "zdr" {
        store.ephemeral_get(tenant, run, i64::MIN, "run_config").await?
    } else {
        from_json(row.json("config")?)?
    };
    Ok((tenant, config, row.ts("clock")?))
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
async fn verify_content<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
    content: &DatasetContentV1,
    size: u64,
    deadline: Option<Timestamp>,
    now: Timestamp,
) -> Result<(), StoreError> {
    match content {
        DatasetContentV1::Durable { artifact } => {
            let row = stmt!(
                B,
                format!(
                    "SELECT size_bytes, content_digest, sensitivity::text AS sensitivity, expires_at FROM artifacts WHERE artifact_id=$1 AND tenant_id=$2 AND run_id=$3 AND deleted_at IS NULL AND (expires_at IS NULL OR expires_at > {})",
                    sql_now::<B>()
                )
            )
            .uuid(artifact.id.0)
            .uuid(tenant.0)
            .uuid(run.0)
            .fetch_optional(conn)
            .await?
            .ok_or_else(|| StoreError::RetentionDenied("dataset artifact unavailable".into()))?;
            if unsigned(row.i64("size_bytes")?)? != size
                || row.bytes("content_digest")? != artifact.digest.0
                || row
                    .opt_ts("expires_at")?
                    .is_some_and(|end| deadline.is_none_or(|deadline| deadline > end))
                || matches!(
                    row.text("sensitivity")?.as_str(),
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
            let buffer = store.delivery.as_ref().ok_or_else(expired)?;
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
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn write_payload<B: Backend, T: Serialize + Sync>(
    store: &Store<B>,
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
        store
            .delivery
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

/// The `payload` and `volatile_page` columns of a row: the value itself, or for a
/// zero-retention run the volatile page it was parked on.
pub(crate) struct Stored {
    json: Option<serde_json::Value>,
    page: Option<i64>,
}

impl Stored {
    /// Read the two columns of `row` (owned values, so no row is held across an await).
    pub(crate) fn of<R: SqlRow>(row: &R) -> Result<Self, StoreError> {
        Ok(Self {
            json: row.opt_json("payload")?,
            page: row.opt_i64("volatile_page")?,
        })
    }

    /// The stored value of kind `kind`.
    pub(crate) async fn read<B: Backend, T: DeserializeOwned>(
        self,
        store: &Store<B>,
        tenant: TenantId,
        run: CrawlRunId,
        kind: &str,
    ) -> Result<T, StoreError> {
        match (self.json, self.page) {
            (Some(value), _) => from_json(value),
            (None, Some(page)) => store.ephemeral_get(tenant, run, page, kind).await,
            (None, None) => Err(conflict("dataset row has neither payload nor volatile page")),
        }
    }
}

/// The value of a row that carries `payload` or, for a zero-retention run, `volatile_page`.
pub(crate) async fn read_payload<B: Backend, R: SqlRow, T: DeserializeOwned>(
    store: &Store<B>,
    tenant: TenantId,
    run: CrawlRunId,
    row: &R,
    kind: &str,
) -> Result<T, StoreError> {
    Stored::of(row)?.read(store, tenant, run, kind).await
}

pub(crate) async fn verify_delivery<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
    config: &CreateCrawl,
    batch: &DeliveryBatchV1,
    now: Timestamp,
) -> Result<(), StoreError> {
    delivery_valid(
        batch,
        &config.datasets,
        config.retention.mode == RetentionMode::Zdr,
        now,
    )?;
    verify_content(
        store,
        conn,
        tenant,
        run,
        &batch.content,
        batch.size_bytes,
        Some(batch.expires_at),
        now,
    )
    .await?;
    if let DeliveryRangeV1::Committed { first, last } = batch.range {
        let feed = config
            .datasets
            .feeds
            .iter()
            .find(|feed| feed.id == batch.feed)
            .ok_or_else(|| conflict("undeclared delivery feed"))?;
        let count = stmt!(
            B,
            format!(
                "SELECT count(*) AS n FROM dataset_items i JOIN datasets d ON d.dataset_id=i.dataset_id AND d.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.run_id=$2 AND d.name=$3 AND i.ordinal BETWEEN $4 AND $5 AND (i.expires_at IS NULL OR i.expires_at>{})",
                sql_now::<B>()
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(&feed.source)
        .i64(signed(first)?)
        .i64(signed(last)?)
        .fetch_one(conn)
        .await?
        .i64("n")?;
        let wanted = last
            .checked_sub(first)
            .and_then(|n| n.checked_add(1))
            .ok_or_else(|| conflict("delivery range overflow"))?;
        if unsigned(count)? != wanted {
            return Err(conflict("delivery references uncommitted items"));
        }
    }
    Ok(())
}

/// Apply accepted items, state CAS and immutable outbox in the existing request transaction.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    run: CrawlRunId,
    request: i64,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
) -> Result<(), StoreError> {
    // The common empty commit never enters the large transaction body's stack frame.
    if accepted.is_empty() && deltas.is_empty() && outbox.is_empty() {
        return Ok(());
    }
    Box::pin(apply_source::<B>(
        store, conn, run, request, None, accepted, deltas, outbox,
    ))
    .await
}

/// [`apply`] for an action-scoped source.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_action<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    run: CrawlRunId,
    action: crawlx_core::ActionId,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
) -> Result<(), StoreError> {
    if accepted.is_empty() && deltas.is_empty() && outbox.is_empty() {
        return Ok(());
    }
    Box::pin(apply_source::<B>(
        store,
        conn,
        run,
        0,
        Some(action),
        accepted,
        deltas,
        outbox,
    ))
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn apply_source<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
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
    let (tenant, config, now) = config_tx(store, conn, run).await?;
    config.datasets.validate()?;
    if !accepted.is_empty() {
        let sealed = stmt!(
            B,
            "SELECT feed_finalizing OR status IN ('completed','failed','cancelled') AS sealed FROM crawl_runs WHERE run_id=$1"
        )
        .uuid(run.0)
        .fetch_one(conn)
        .await?
        .flag("sealed")?;
        if sealed {
            return Err(conflict("feed source is sealed for finalization"));
        }
    }
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
            .find(|declared| declared.name == batch.dataset)
            .ok_or_else(|| conflict("undeclared dataset namespace"))?;
        stmt!(
            B,
            format!(
                "INSERT INTO datasets(tenant_id,run_id,name) VALUES($1,$2,$3) {}",
                <B::Dialect as Dialect>::upsert_do_nothing(&["tenant_id", "run_id", "name"])
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(&batch.dataset)
        .execute(conn)
        .await?;
        let row = stmt!(
            B,
            format!(
                "SELECT dataset_id,next_ordinal,item_count,size_bytes FROM datasets WHERE tenant_id=$1 AND run_id=$2 AND name=$3{}",
                lock::<B>(RowLock::Update)
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(&batch.dataset)
        .fetch_one(conn)
        .await?;
        let dataset = row.i64("dataset_id")?;
        let mut ordinal = row.i64("next_ordinal")?;
        let mut count = unsigned(row.i64("item_count")?)?;
        let mut bytes = unsigned(row.i64("size_bytes")?)?;
        for item in &batch.items {
            item_valid(item, zdr, now)?;
            fragments_valid(item, &config.datasets, &batch.dataset)?;
            for fragment in &item.feed_fragments {
                verify_content(
                    store,
                    conn,
                    tenant,
                    run,
                    &fragment.content,
                    fragment.size_bytes,
                    Some(fragment.expires_at),
                    now,
                )
                .await?;
            }
            if item.schema_version != declaration.schema_version {
                return Err(conflict("dataset schema mismatch"));
            }
            verify_content(
                store,
                conn,
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
            let request_source = action.is_none().then_some(request);
            let action_source = action.map(|id| id.0);
            let existing = stmt!(
                B,
                format!(
                    "SELECT payload,volatile_page FROM dataset_items WHERE tenant_id=$1 AND dataset_id=$2 AND {} AND identity_key=$4 AND {}",
                    <B::Dialect as Dialect>::null_safe_eq("source_request_id", "$3"),
                    <B::Dialect as Dialect>::null_safe_eq("source_action_id", "$5")
                )
            )
            .uuid(tenant.0)
            .i64(dataset)
            .opt_i64(request_source)
            .bytes(&identity.0)
            .opt_uuid(action_source)
            .fetch_optional(conn)
            .await?;
            if let Some(existing) = existing {
                let old: DatasetItemV1 = Stored::of(&existing)?
                    .read(store, tenant, run, "dataset_item")
                    .await?;
                if old.item != *item {
                    return Err(conflict("accepted item identity changed"));
                }
                continue;
            }
            count = count
                .checked_add(1)
                .ok_or_else(|| conflict("dataset count overflow"))?;
            bytes = bytes
                .checked_add(item_bytes(item)?)
                .ok_or_else(|| conflict("dataset bytes overflow"))?;
            if count > declaration.max_items || bytes > declaration.max_bytes {
                return Err(conflict("dataset quota exhausted"));
            }
            let mut record = DatasetItemV1::new(unsigned(ordinal)?, request, item.clone());
            record.source_action = action;
            let payload = if zdr {
                None
            } else {
                Some(
                    serde_json::to_value(&record)
                        .map_err(|error| StoreError::Serialization(error.to_string()))?,
                )
            };
            let inserted = stmt!(
                B,
                "INSERT INTO dataset_items(tenant_id,run_id,dataset_id,ordinal,source_request_id,identity_key,payload,volatile_page,size_bytes,expires_at,source_action_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING item_id"
            )
            .uuid(tenant.0)
            .uuid(run.0)
            .i64(dataset)
            .i64(ordinal)
            .opt_i64(request_source)
            .bytes(&identity.0)
            .opt_json(payload.as_ref())
            .opt_i64(zdr.then_some(0i64))
            .i64(signed(item.size_bytes)?)
            .opt_ts(item.expires_at)
            .opt_uuid(action_source)
            .fetch_one(conn)
            .await?;
            if zdr {
                let item_id = inserted.i64("item_id")?;
                let page = manifest_page(1, item_id)?;
                write_payload(
                    store,
                    tenant,
                    run,
                    page,
                    "dataset_item",
                    &record,
                    true,
                    item.expires_at,
                )
                .await?;
                stmt!(
                    B,
                    "UPDATE dataset_items SET volatile_page=$1 WHERE item_id=$2 AND tenant_id=$3"
                )
                .i64(page)
                .i64(item_id)
                .uuid(tenant.0)
                .execute(conn)
                .await?;
            }
            ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| conflict("dataset ordinal overflow"))?;
        }
        stmt!(
            B,
            "UPDATE datasets SET next_ordinal=$1,item_count=$2,size_bytes=$3 WHERE dataset_id=$4 AND tenant_id=$5"
        )
        .i64(ordinal)
        .i64(signed(count)?)
        .i64(signed(bytes)?)
        .i64(dataset)
        .uuid(tenant.0)
        .execute(conn)
        .await?;
    }
    for delta in deltas {
        cas(store, conn, tenant, run, &config, delta, now).await?;
    }
    for batch in outbox {
        let mut resolved = batch.clone();
        let feed = config
            .datasets
            .feeds
            .iter()
            .find(|feed| feed.id == batch.feed)
            .ok_or_else(|| conflict("undeclared delivery feed"))?;
        if matches!(resolved.range, DeliveryRangeV1::AcceptedRequest) {
            let row = stmt!(
                B,
                format!(
                    "SELECT min(i.ordinal) AS first_ordinal,max(i.ordinal) AS last_ordinal FROM dataset_items i JOIN datasets d ON d.dataset_id=i.dataset_id AND d.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.run_id=$2 AND d.name=$3 AND {} AND {}",
                    <B::Dialect as Dialect>::null_safe_eq("i.source_request_id", "$4"),
                    <B::Dialect as Dialect>::null_safe_eq("i.source_action_id", "$5")
                )
            )
            .uuid(tenant.0)
            .uuid(run.0)
            .text(&feed.source)
            .opt_i64(action.is_none().then_some(request))
            .opt_uuid(action.map(|id| id.0))
            .fetch_one(conn)
            .await?;
            let first = row
                .opt_i64("first_ordinal")?
                .ok_or_else(|| conflict("delivery source not committed"))?;
            let last = row
                .opt_i64("last_ordinal")?
                .ok_or_else(|| conflict("delivery source not committed"))?;
            resolved.range = DeliveryRangeV1::Committed {
                first: unsigned(first)?,
                last: unsigned(last)?,
            };
        }
        let batch = &resolved;
        if matches!(batch.range, DeliveryRangeV1::Empty) && (request != 0 || action.is_some()) {
            return Err(conflict("empty feed requires terminal transaction"));
        }
        verify_delivery(store, conn, tenant, run, &config, batch, now).await?;
        let old = stmt!(
            B,
            "SELECT payload,volatile_page FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND feed=$3 AND idempotency_key=$4"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(&batch.feed)
        .text(&batch.idempotency_key)
        .fetch_optional(conn)
        .await?;
        if let Some(old) = old {
            let previous: DeliveryBatchV1 = Stored::of(&old)?
                .read(store, tenant, run, "dataset_delivery")
                .await?;
            if previous != *batch {
                return Err(conflict("delivery identity changed"));
            }
            continue;
        }
        let payload = if zdr {
            None
        } else {
            Some(serde_json::to_value(batch).map_err(|error| StoreError::Serialization(error.to_string()))?)
        };
        let content_page = match &batch.content {
            DatasetContentV1::Volatile { page, .. } => Some(*page),
            DatasetContentV1::Durable { .. } => None,
            _ => return Err(conflict("unsupported dataset content handle")),
        };
        let id = stmt!(
            B,
            "INSERT INTO dataset_delivery_outbox(tenant_id,run_id,source_request_id,feed,idempotency_key,payload,volatile_page,expires_at,source_action_id,content_page,terminal_source) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING delivery_id"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .opt_i64((action.is_none() && request != 0).then_some(request))
        .text(&batch.feed)
        .text(&batch.idempotency_key)
        .opt_json(payload.as_ref())
        .opt_i64(zdr.then_some(0i64))
        .ts(batch.expires_at)
        .opt_uuid(action.map(|id| id.0))
        .opt_i64(content_page)
        .bool(request == 0 && action.is_none())
        .fetch_one(conn)
        .await?
        .i64("delivery_id")?;
        if zdr {
            let page = manifest_page(2, id)?;
            write_payload(
                store,
                tenant,
                run,
                page,
                "dataset_delivery",
                batch,
                true,
                Some(batch.expires_at),
            )
            .await?;
            stmt!(
                B,
                "UPDATE dataset_delivery_outbox SET volatile_page=$1 WHERE delivery_id=$2 AND tenant_id=$3"
            )
            .i64(page)
            .i64(id)
            .uuid(tenant.0)
            .execute(conn)
            .await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cas<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
    config: &CreateCrawl,
    delta: &KvCasV1,
    now: Timestamp,
) -> Result<KvValueV1, StoreError> {
    let zdr = config.retention.mode == RetentionMode::Zdr;
    delta_valid(delta, &config.datasets, zdr, now)?;
    kv_scope::<B>(conn, tenant, run, &config.datasets, &delta.store).await?;
    if let Some(content) = &delta.content {
        verify_content(
            store,
            conn,
            tenant,
            run,
            content,
            delta.size_bytes,
            delta.expires_at,
            now,
        )
        .await?;
    }
    let key = <B::Dialect as Dialect>::reserved_ident("key");
    let old = stmt!(
        B,
        format!(
            "SELECT version,expires_at,payload,volatile_page FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND {key}=$4{}",
            lock::<B>(RowLock::Update)
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .text(&delta.store)
    .text(&delta.key)
    .fetch_optional(conn)
    .await?;
    let old_version = old
        .as_ref()
        .map(|row| row.i64("version"))
        .transpose()?
        .map(unsigned)
        .transpose()?
        .unwrap_or(0);
    if old_version != delta.expected_version {
        return Err(conflict("kv compare-and-set collision"));
    }
    if let Some(old) = &old {
        let expires: Option<Timestamp> = old.opt_ts("expires_at")?;
        if expires.is_some_and(|end| end <= now) {
            return Err(expired());
        }
        if expires != delta.expires_at {
            return Err(conflict("kv expiry is immutable"));
        }
    }
    let declaration = config
        .datasets
        .kv_stores
        .iter()
        .find(|declared| declared.name == delta.store)
        .ok_or_else(|| conflict("undeclared kv namespace"))?;
    let usage = stmt!(
        B,
        format!(
            "SELECT count(*) AS key_count, {} AS total_bytes FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND {key}<>$4",
            sum_as_integer::<B>("size_bytes")
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .text(&delta.store)
    .text(&delta.key)
    .fetch_one(conn)
    .await?;
    if unsigned(usage.i64("key_count")?)?
        .checked_add(1)
        .is_none_or(|n| n > u64::from(declaration.max_keys))
        || unsigned(usage.i64("total_bytes")?)?
            .checked_add(delta.size_bytes)
            .is_none_or(|n| n > declaration.max_bytes)
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
    // Every write takes a page of its own from the fence counter: strictly increasing and
    // never repeated, on every engine, which keeps the tagged page namespace unique.
    let page = if zdr {
        let next = B::next_fence(conn, FenceSeq::Lease).await?;
        Some(manifest_page(3, next)?)
    } else {
        None
    };
    let payload = write_payload(
        store,
        tenant,
        run,
        page.unwrap_or(0),
        "dataset_kv",
        &value,
        zdr,
        delta.expires_at,
    )
    .await?;
    stmt!(
        B,
        format!(
            "INSERT INTO dataset_kv(tenant_id,run_id,store,{key},version,payload,volatile_page,size_bytes,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) {}",
            <B::Dialect as Dialect>::upsert_update(
                &["tenant_id", "run_id", "store", &key],
                &["version", "payload", "volatile_page", "size_bytes", "expires_at"],
                None
            )
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .text(&delta.store)
    .text(&delta.key)
    .i64(signed(version)?)
    .opt_json(payload.as_ref())
    .opt_i64(page)
    .i64(signed(delta.size_bytes)?)
    .opt_ts(delta.expires_at)
    .execute(conn)
    .await?;
    Ok(value)
}

/// `COALESCE(sum(col), 0)` as an integer the row decoder reads: MariaDB sums to `DECIMAL`,
/// so it is cast there; the other engines return an integer already.
fn sum_as_integer<B: Backend>(col: &str) -> String {
    match B::KIND {
        BackendKind::MariaDb => format!("CAST(COALESCE(sum({col}), 0) AS SIGNED)"),
        _ => format!("COALESCE(sum({col}), 0)::bigint"),
    }
}

#[async_trait]
impl<B: Sql> DatasetRepo for Store<B> {
    async fn items(
        &self,
        run: CrawlRunId,
        dataset: &str,
        after: u64,
        limit: u16,
    ) -> Result<Vec<DatasetItemV1>, StoreError> {
        bounds(limit)?;
        validate_identifier(dataset)?;
        let mut tx = self.begin_write().await?;
        let (tenant, config, now) = config_tx(self, tx.conn(), run).await?;
        if !config.datasets.stores.iter().any(|store| store.name == dataset) {
            return Err(conflict("undeclared dataset namespace"));
        }
        let rows = stmt!(
            B,
            "SELECT i.payload,i.volatile_page,i.expires_at FROM dataset_items i JOIN datasets d ON d.dataset_id=i.dataset_id AND d.tenant_id=i.tenant_id WHERE i.tenant_id=$1 AND i.run_id=$2 AND d.name=$3 AND i.ordinal>$4 ORDER BY i.ordinal LIMIT $5"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(dataset)
        .i64(signed(after)?)
        .i64(i64::from(limit))
        .fetch_all(tx.conn())
        .await?;
        let mut output = Vec::with_capacity(rows.len());
        for row in rows {
            if row.opt_ts("expires_at")?.is_some_and(|end| end <= now) {
                return Err(expired());
            }
            let item: DatasetItemV1 = Stored::of(&row)?.read(self, tenant, run, "dataset_item").await?;
            verify_content(
                self,
                tx.conn(),
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
        tx.commit().await?;
        Ok(output)
    }
}

#[async_trait]
impl<B: Sql> KvRepo for Store<B> {
    async fn value(&self, run: CrawlRunId, store: &str, key: &str) -> Result<Option<KvValueV1>, StoreError> {
        validate_identifier(store)?;
        validate_identifier(key)?;
        let mut tx = self.begin_write().await?;
        let (tenant, config, now) = config_tx(self, tx.conn(), run).await?;
        kv_scope::<B>(tx.conn(), tenant, run, &config.datasets, store).await?;
        let column = <B::Dialect as Dialect>::reserved_ident("key");
        let row = stmt!(
            B,
            format!(
                "SELECT payload,volatile_page,expires_at FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND {column}=$4"
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(store)
        .text(key)
        .fetch_optional(tx.conn())
        .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        if row.opt_ts("expires_at")?.is_some_and(|end| end <= now) {
            return Err(expired());
        }
        let value: KvValueV1 = Stored::of(&row)?.read(self, tenant, run, "dataset_kv").await?;
        if let Some(content) = &value.value.content {
            verify_content(
                self,
                tx.conn(),
                tenant,
                run,
                content,
                value.value.size_bytes,
                value.value.expires_at,
                now,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(Some(value))
    }
    async fn compare_and_set(&self, run: CrawlRunId, delta: KvCasV1) -> Result<KvValueV1, StoreError> {
        let mut tx = self.begin_write().await?;
        let (tenant, config, now) = config_tx(self, tx.conn(), run).await?;
        let value = cas(self, tx.conn(), tenant, run, &config, &delta, now).await?;
        tx.commit().await?;
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
        let mut tx = self.begin_write().await?;
        let (tenant, config, now) = config_tx(self, tx.conn(), run).await?;
        kv_scope::<B>(tx.conn(), tenant, run, &config.datasets, store).await?;
        let column = <B::Dialect as Dialect>::reserved_ident("key");
        let rows = stmt!(
            B,
            format!(
                "SELECT payload,volatile_page FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3 AND {column}>$4 AND (expires_at IS NULL OR expires_at>{}) ORDER BY {column} LIMIT $5",
                sql_now::<B>()
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(store)
        .text(after)
        .i64(i64::from(limit))
        .fetch_all(tx.conn())
        .await?;
        let mut values = Vec::with_capacity(rows.len());
        for row in rows {
            let value: KvValueV1 = Stored::of(&row)?.read(self, tenant, run, "dataset_kv").await?;
            if let Some(content) = &value.value.content {
                verify_content(
                    self,
                    tx.conn(),
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
        tx.commit().await?;
        Ok(values)
    }
    async fn drop_store(&self, run: CrawlRunId, store: &str) -> Result<(), StoreError> {
        validate_identifier(store)?;
        let mut tx = self.begin_write().await?;
        let (tenant, config, _) = config_tx(self, tx.conn(), run).await?;
        if !config
            .datasets
            .kv_stores
            .iter()
            .any(|declaration| declaration.name == store)
        {
            return Err(conflict("undeclared kv namespace"));
        }
        stmt!(
            B,
            format!(
                "INSERT INTO dataset_kv_drops(tenant_id,run_id,store) VALUES($1,$2,$3) {}",
                <B::Dialect as Dialect>::upsert_do_nothing(&["tenant_id", "run_id", "store"])
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(store)
        .execute(tx.conn())
        .await?;
        stmt!(
            B,
            "DELETE FROM dataset_kv WHERE tenant_id=$1 AND run_id=$2 AND store=$3"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .text(store)
        .execute(tx.conn())
        .await?;
        tx.commit().await
    }
}

async fn kv_scope<B: Sql>(
    conn: &mut Conn<B>,
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
    let dropped = stmt!(
        B,
        "SELECT EXISTS(SELECT 1 FROM dataset_kv_drops WHERE tenant_id=$1 AND run_id=$2 AND store=$3) AS dropped"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .text(store)
    .fetch_one(conn)
    .await?
    .flag("dropped")?;
    if dropped {
        return Err(conflict("kv namespace dropped"));
    }
    Ok(())
}

/// A claimed outbox row, read out of the driver row before anything is awaited.
struct Claimed {
    id: i64,
    fence: i64,
    attempts: u32,
    stored: Stored,
}

impl Claimed {
    fn of<R: SqlRow>(row: &R) -> Result<Self, StoreError> {
        Ok(Self {
            id: row.i64("delivery_id")?,
            fence: row.i64("fence")?,
            attempts: u32::try_from(row.i32("attempts")?)
                .map_err(|_| conflict("delivery attempts overflow"))?,
            stored: Stored::of(row)?,
        })
    }
}

#[async_trait]
impl<B: Sql> DeliveryOutboxRepo for Store<B> {
    async fn ready_runs(&self, after: Option<CrawlRunId>, limit: u16) -> Result<Vec<CrawlRunId>, StoreError> {
        bounds(limit)?;
        self.scope()?;
        let rows = stmt!(
            B,
            format!(
                "SELECT run_id FROM (SELECT run_id FROM dataset_delivery_outbox o WHERE ($2::uuid IS NULL OR run_id>$2) AND ($3::uuid IS NULL OR tenant_id=$3) AND ((state IN ('pending','leased') AND (expires_at<={now} OR ((NOT terminal_source OR EXISTS(SELECT 1 FROM crawl_runs r WHERE r.run_id=o.run_id AND r.feed_finalized)) AND not_before<={now} AND (lease_expires_at IS NULL OR lease_expires_at<={now})))) OR (state IN ('delivered','content_expired') AND erased_at IS NULL AND volatile_page IS NOT NULL)) UNION SELECT run_id FROM crawl_runs WHERE NOT feed_finalized AND (feed_finalizing OR (feed_required AND status IN ('completed','failed','cancelled'))) AND ($2::uuid IS NULL OR run_id>$2) AND ($3::uuid IS NULL OR tenant_id=$3)) pending GROUP BY run_id ORDER BY run_id LIMIT $1",
                now = sql_now::<B>()
            )
        )
        .i64(i64::from(limit))
        .opt_uuid(after.map(|run| run.0))
        .opt_uuid(crate::tenant::current().map(|tenant| tenant.0))
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter()
            .map(|row| row.uuid("run_id").map(CrawlRunId))
            .collect()
    }
    async fn maintain(&self, run: CrawlRunId) -> Result<(), StoreError> {
        self.scope()?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        let retired = self
            .retire_expired_feed_finalization_owned(run, tenant, zdr)
            .await?;
        B::expire_outbox(&self.pool, tenant.0, run.0).await?;
        cleanup_delivered(self, tenant, run).await?;
        if retired {
            Err(StoreError::RetentionDenied("feed content_expired".into()))
        } else {
            Ok(())
        }
    }
    async fn expire(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        self.scope()?;
        let (tenant, _) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        // Read the pages first: engines without `UPDATE .. RETURNING` cannot hand them back.
        let mut tx = self.begin_write().await?;
        let row = stmt!(
            B,
            format!(
                "SELECT content_page,volatile_page FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND fence=$4 AND state IN ('pending','leased','content_expired') AND expires_at<={}{}",
                sql_now::<B>(),
                lock::<B>(RowLock::Update)
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .i64(id)
        .i64(fence)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        let pages = [row.opt_i64("content_page")?, row.opt_i64("volatile_page")?];
        stmt!(
            B,
            "UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND fence=$4"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .i64(id)
        .i64(fence)
        .execute(tx.conn())
        .await?;
        tx.commit().await?;
        if let Some(buffer) = &self.delivery {
            for page in pages.into_iter().flatten() {
                buffer.ack(tenant, run, page).await?;
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
        self.scope()?;
        let (tenant, _) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        cleanup_delivered(self, tenant, run).await?;
        let mut tx = self.begin_write().await?;
        stmt!(
            B,
            format!(
                "UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND state IN ('pending','leased') AND expires_at<={}",
                sql_now::<B>()
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .execute(tx.conn())
        .await?;
        let claimed = B::claim_outbox(
            tx.conn(),
            OutboxClaim {
                tenant: tenant.0,
                run: run.0,
                worker: worker.0,
                limit: i64::from(limit),
                lease_secs: f64::from(lease_seconds),
            },
        )
        .await?
        .into_iter()
        .map(|row| Claimed::of(&row))
        .collect::<Result<Vec<_>, _>>()?;
        let mut claims = Vec::with_capacity(claimed.len());
        for row in claimed {
            let batch: Result<DeliveryBatchV1, StoreError> =
                row.stored.read(self, tenant, run, "dataset_delivery").await;
            match batch {
                Ok(batch) => {
                    let mut receipt = DurableDeliveryOutboxV1::pending(row.id, run, batch);
                    receipt.fence = row.fence;
                    receipt.attempts = row.attempts;
                    receipt.state = DeliveryStateV1::Leased;
                    claims.push(receipt);
                }
                Err(StoreError::RetentionDenied(_)) => {
                    stmt!(
                        B,
                        "UPDATE dataset_delivery_outbox SET state='content_expired',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND delivery_id=$2"
                    )
                    .uuid(tenant.0)
                    .i64(row.id)
                    .execute(tx.conn())
                    .await?;
                }
                Err(error) => return Err(error),
            }
        }
        tx.commit().await?;
        cleanup_delivered(self, tenant, run).await?;
        claims.sort_by_key(|claim| claim.id);
        Ok(claims)
    }
    async fn acknowledge(&self, run: CrawlRunId, id: i64, fence: i64) -> Result<(), StoreError> {
        self.scope()?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        let mut tx = self.begin_write().await?;
        crate::report_history::lock_pipeline_ack_run::<B>(tx.conn(), tenant, run).await?;
        let row = stmt!(
            B,
            format!(
                "SELECT state FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND fence=$4 AND (state='delivered' OR (state='leased' AND lease_expires_at>{now} AND expires_at>{now})){}",
                lock::<B>(RowLock::Update),
                now = sql_now::<B>()
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .i64(id)
        .i64(fence)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        stmt!(
            B,
            "UPDATE dataset_delivery_outbox SET state='delivered',lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND delivery_id=$2 AND fence=$3"
        )
        .uuid(tenant.0)
        .i64(id)
        .i64(fence)
        .execute(tx.conn())
        .await?;
        if row.text("state")? != "delivered" {
            crate::report_history::acknowledge_pipeline::<B>(tx.conn(), tenant, run, id).await?;
        }
        // Commit the receipt before erasing content. A crash can only leave retriable cleanup.
        tx.commit().await?;
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
        self.scope()?;
        let (tenant, _) = self.privacy_scope(run).await?;
        check_tenant(tenant)?;
        let updated = stmt!(
            B,
            format!(
                "UPDATE dataset_delivery_outbox SET state='pending',not_before=$5,lease_owner=NULL,lease_expires_at=NULL WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND state='leased' AND fence=$4 AND lease_expires_at>{now} AND expires_at>{now} AND $5>={now} AND $5<=expires_at AND $5<=({later})",
                now = sql_now::<B>(),
                later = <B::Dialect as Dialect>::add_seconds(sql_now::<B>(), "86400")
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .i64(id)
        .i64(fence)
        .ts(not_before)
        .execute_write(&self.pool)
        .await?;
        if updated != 1 {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }
}

async fn cleanup_delivered<B: Sql>(
    store: &Store<B>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<(), StoreError> {
    let rows = stmt!(
        B,
        "SELECT delivery_id,volatile_page,content_page FROM dataset_delivery_outbox o WHERE tenant_id=$1 AND run_id=$2 AND state IN ('delivered','content_expired') AND erased_at IS NULL AND volatile_page IS NOT NULL ORDER BY delivery_id LIMIT 1000"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_all_pool(&store.pool)
    .await?;
    if rows.is_empty() {
        return Ok(());
    }
    let buffer = store.delivery.as_ref().ok_or_else(expired)?;
    for row in rows {
        if let Some(page) = row.opt_i64("content_page")? {
            let live = stmt!(
                B,
                format!(
                    "SELECT EXISTS(SELECT 1 FROM dataset_delivery_outbox WHERE tenant_id=$1 AND run_id=$2 AND content_page=$3 AND state IN ('pending','leased') AND expires_at>{}) AS live",
                    sql_now::<B>()
                )
            )
            .uuid(tenant.0)
            .uuid(run.0)
            .i64(page)
            .fetch_one_pool(&store.pool)
            .await?
            .flag("live")?;
            if live {
                continue;
            }
            buffer.ack(tenant, run, page).await?;
        }
        buffer.ack(tenant, run, row.i64("volatile_page")?).await?;
        stmt!(
            B,
            format!(
                "UPDATE dataset_delivery_outbox SET erased_at={} WHERE tenant_id=$1 AND run_id=$2 AND delivery_id=$3 AND state IN ('delivered','content_expired')",
                sql_now::<B>()
            )
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .i64(row.i64("delivery_id")?)
        .execute_write(&store.pool)
        .await?;
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
