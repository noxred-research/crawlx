//! Hash-only source memo metadata; ZDR uses shared volatile custody without SQL memo writes.
use super::*;
use crawlx_core::dataset::memo::*;
use crawlx_core::hash::Digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// Fixed run-local namespace, disjoint from real frontier and existing operational slots.
const VOLATILE_PAGE: i64 = i64::MIN + 50;
const VOLATILE_KIND: &str = "source_memo_v1";

#[derive(Default, Serialize, Deserialize)]
pub(crate) struct MemoState {
    pub(crate) seen: BTreeMap<Digest, Timestamp>,
    pub(crate) categories: BTreeMap<Digest, CategoryCacheEntryV1>,
}
impl MemoState {
    pub(crate) fn record(&mut self, keys: &[Digest], maximum: usize, now: Timestamp) {
        for key in keys {
            self.seen.entry(*key).or_insert(now);
        }
        while self.seen.len() > maximum {
            let oldest = self
                .seen
                .iter()
                .min_by_key(|(key, time)| (**time, **key))
                .map(|(key, _)| *key);
            if let Some(key) = oldest {
                self.seen.remove(&key);
            }
        }
    }
    pub(crate) fn cache(&mut self, key: Digest, mut entry: CategoryCacheEntryV1, now: Timestamp) {
        self.categories.retain(|_, value| value.expires_at > now);
        if let Some(old) = self.categories.get(&key) {
            entry.expires_at = entry.expires_at.min(old.expires_at);
        }
        self.categories.insert(key, entry);
        while self.categories.len() > MAX_CATEGORY_CACHE_ENTRIES {
            let oldest = self
                .categories
                .iter()
                .min_by_key(|(key, value)| (value.expires_at, **key))
                .map(|(key, _)| *key);
            if let Some(key) = oldest {
                self.categories.remove(&key);
            }
        }
    }
}

pub(crate) fn lookup(scope: &MemoScopeV1, value: Digest, category: bool) -> Result<Digest, StoreError> {
    Digest::of_value(
        if category {
            "crawlx/source-category-key/v1"
        } else {
            "crawlx/source-seen-key/v1"
        },
        &(scope, value),
    )
    .map_err(|_| conflict("source memo key serialization failed"))
}
pub(crate) fn capacity(articles: &[Digest], maximum: u32) -> Result<usize, StoreError> {
    if articles.len() > MAX_BATCH_ITEMS || !(1..=MAX_MEMO_ENTRIES).contains(&maximum) {
        return Err(conflict("invalid source memo capacity or batch"));
    }
    usize::try_from(maximum).map_err(|_| conflict("source memo capacity overflow"))
}
pub(crate) fn horizon(run: &CrawlRun, now: Timestamp) -> Result<Timestamp, StoreError> {
    let duration = if run.config.retention.mode == RetentionMode::Zdr {
        chrono::Duration::hours(1)
    } else {
        chrono::Duration::days(i64::from(run.config.retention.days))
    };
    let deadline = run.created_at.checked_add_signed(duration).ok_or_else(expired)?;
    if deadline <= now {
        return Err(expired());
    }
    Ok(deadline)
}
pub(crate) fn category_valid(
    entry: &CategoryCacheEntryV1,
    zdr: bool,
    end: Timestamp,
    now: Timestamp,
) -> Result<(), StoreError> {
    if entry.size_bytes > MAX_CATEGORY_CACHE_BYTES || entry.expires_at <= now || entry.expires_at > end {
        return Err(expired());
    }
    content_valid(&entry.content, zdr, Some(entry.expires_at), now)
}

struct ScopeRow {
    tenant: TenantId,
    zdr: bool,
    deadline: Timestamp,
    generation: i64,
}
async fn scope_tx<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<ScopeRow, StoreError> {
    check_tenant(tenant)?;
    let row = stmt!(
        B,
        format!(
            "SELECT tenant_id, retention_mode::text AS retention_mode, retention_days, created_at, expires_at, purge_requested_at FROM crawl_runs WHERE run_id=$1{}",
            lock::<B>(RowLock::Update)
        )
    )
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| not_found("crawl_run", run))?;
    if TenantId(row.uuid("tenant_id")?) != tenant {
        return Err(StoreError::AccessDenied("source memo tenant mismatch".into()));
    }
    if row.opt_ts("purge_requested_at")?.is_some() {
        return Err(expired());
    }
    let zdr = row.text("retention_mode")? == "zdr";
    let created = row.ts("created_at")?;
    let duration = if zdr {
        chrono::Duration::hours(1)
    } else {
        chrono::Duration::days(i64::from(row.i32("retention_days")?))
    };
    let deadline = created.checked_add_signed(duration).ok_or_else(expired)?;
    let deadline = row
        .opt_ts("expires_at")?
        .map_or(deadline, |value| value.min(deadline));
    stmt!(
        B,
        format!(
            "INSERT INTO source_memo_control(tenant_id,run_id,generation) VALUES($1,$2,0) {}",
            <B::Dialect as Dialect>::upsert_do_nothing(&["tenant_id", "run_id"])
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .execute(conn)
    .await?;
    let generation = stmt!(
        B,
        "SELECT generation FROM source_memo_control WHERE tenant_id=$1 AND run_id=$2"
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_one(conn)
    .await?
    .i64("generation")?;
    Ok(ScopeRow {
        tenant,
        zdr,
        deadline,
        generation,
    })
}
async fn volatile_get<B: Backend>(
    store: &Store<B>,
    owner: &ScopeRow,
    run: CrawlRunId,
) -> Result<MemoState, StoreError> {
    let buffer = store.delivery.as_ref().ok_or_else(expired)?;
    let Some(page) = buffer.get(owner.tenant, run, VOLATILE_PAGE).await? else {
        return Ok(MemoState::default());
    };
    let kind = format!("{VOLATILE_KIND}.{}", owner.generation);
    let Some(blob) = page.blobs.get(&kind) else {
        return Ok(MemoState::default());
    };
    serde_json::from_slice(&blob.bytes).map_err(|_| conflict("invalid volatile source memo"))
}
async fn volatile_put<B: Backend>(
    store: &Store<B>,
    owner: &ScopeRow,
    run: CrawlRunId,
    state: &MemoState,
) -> Result<(), StoreError> {
    let buffer = store.delivery.as_ref().ok_or_else(expired)?;
    let bytes = serde_json::to_vec(state).map_err(|_| conflict("source memo serialization failed"))?;
    let kind = format!("{VOLATILE_KIND}.{}", owner.generation);
    buffer
        .insert_until(
            owner.tenant,
            run,
            VOLATILE_PAGE,
            &kind,
            "application/json",
            &bytes,
            owner.deadline,
        )
        .await?;
    Ok(())
}

/// Delete every row of `table` of the run past the newest `keep` (ordered by `order`,
/// newest first, then by key). The ordering clause is a literal of this module.
async fn evict<B: Sql>(
    conn: &mut Conn<B>,
    table: &str,
    order: &str,
    scope: &MemoScopeV1,
    keep: i64,
) -> Result<(), StoreError> {
    // A derived table keeps the statement valid on every engine: MariaDB rejects `LIMIT`
    // inside an `IN` subquery and `OFFSET` without `LIMIT`.
    crate::sql::Stmt::<B>::dynamic(&format!(
        "DELETE FROM {table} WHERE tenant_id=$1 AND run_id=$2 AND lookup_key IN (SELECT lookup_key FROM (SELECT lookup_key FROM {table} WHERE tenant_id=$1 AND run_id=$2 ORDER BY {order} DESC,lookup_key DESC LIMIT 9223372036854775807 OFFSET $3) evicted)"
    ))
    .uuid(scope.tenant.0)
    .uuid(scope.run.0)
    .i64(keep)
    .execute(conn)
    .await?;
    Ok(())
}

#[async_trait]
impl<B: Sql> SourceMemoRepo for Store<B> {
    async fn seen(&self, scope: &MemoScopeV1, article: Digest, now: Timestamp) -> Result<bool, StoreError> {
        let key = lookup(scope, article, false)?;
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let owner = scope_tx::<B>(tx.conn(), scope.tenant, scope.run).await?;
        if owner.deadline <= now {
            return Ok(false);
        }
        let found = if owner.zdr {
            volatile_get(self, &owner, scope.run)
                .await?
                .seen
                .contains_key(&key)
        } else {
            stmt!(
                B,
                "SELECT EXISTS(SELECT 1 FROM source_memo_seen WHERE tenant_id=$1 AND run_id=$2 AND lookup_key=$3) AS seen"
            )
            .uuid(scope.tenant.0)
            .uuid(scope.run.0)
            .text(&key.to_hex())
            .fetch_one(tx.conn())
            .await?
            .flag("seen")?
        };
        tx.commit().await?;
        Ok(found)
    }
    async fn record_seen(
        &self,
        scope: &MemoScopeV1,
        articles: &[Digest],
        max_entries: u32,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let maximum = capacity(articles, max_entries)?;
        let keys = articles
            .iter()
            .map(|key| lookup(scope, *key, false))
            .collect::<Result<Vec<_>, _>>()?;
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let owner = scope_tx::<B>(tx.conn(), scope.tenant, scope.run).await?;
        if owner.deadline <= now {
            return Err(expired());
        }
        if owner.zdr {
            let mut state = volatile_get(self, &owner, scope.run).await?;
            state.record(&keys, maximum, now);
            volatile_put(self, &owner, scope.run, &state).await?;
        } else {
            for key in keys {
                stmt!(
                    B,
                    format!(
                        "INSERT INTO source_memo_seen(tenant_id,run_id,lookup_key,recorded_at) VALUES($1,$2,$3,$4) {}",
                        <B::Dialect as Dialect>::upsert_do_nothing(&["tenant_id", "run_id", "lookup_key"])
                    )
                )
                .uuid(scope.tenant.0)
                .uuid(scope.run.0)
                .text(&key.to_hex())
                .ts(now)
                .execute(tx.conn())
                .await?;
            }
            evict::<B>(
                tx.conn(),
                "source_memo_seen",
                "recorded_at",
                scope,
                i64::from(max_entries),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn category(
        &self,
        scope: &MemoScopeV1,
        representation: Digest,
        now: Timestamp,
    ) -> Result<Option<CategoryCacheEntryV1>, StoreError> {
        let key = lookup(scope, representation, true)?;
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let owner = scope_tx::<B>(tx.conn(), scope.tenant, scope.run).await?;
        if owner.deadline <= now {
            return Ok(None);
        }
        let found = if owner.zdr {
            volatile_get(self, &owner, scope.run)
                .await?
                .categories
                .remove(&key)
        } else {
            stmt!(
                B,
                "SELECT payload FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 AND lookup_key=$3 AND expires_at>$4"
            )
            .uuid(scope.tenant.0)
            .uuid(scope.run.0)
            .text(&key.to_hex())
            .ts(now)
            .fetch_optional(tx.conn())
            .await?
            .map(|row| from_json(row.json("payload")?))
            .transpose()?
        };
        tx.commit().await?;
        Ok(found.filter(|entry| entry.expires_at > now && entry.expires_at <= owner.deadline))
    }
    async fn cache_category(
        &self,
        scope: &MemoScopeV1,
        representation: Digest,
        mut entry: CategoryCacheEntryV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let key = lookup(scope, representation, true)?;
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let owner = scope_tx::<B>(tx.conn(), scope.tenant, scope.run).await?;
        category_valid(&entry, owner.zdr, owner.deadline, now)?;
        verify_content(
            self,
            tx.conn(),
            scope.tenant,
            scope.run,
            &entry.content,
            entry.size_bytes,
            Some(entry.expires_at),
            now,
        )
        .await?;
        if owner.zdr {
            let mut state = volatile_get(self, &owner, scope.run).await?;
            state.cache(key, entry, now);
            volatile_put(self, &owner, scope.run, &state).await?;
        } else {
            let lookup_key = key.to_hex();
            stmt!(
                B,
                "DELETE FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 AND expires_at<=$3"
            )
            .uuid(scope.tenant.0)
            .uuid(scope.run.0)
            .ts(now)
            .execute(tx.conn())
            .await?;
            if let Some(old) = stmt!(
                B,
                "SELECT expires_at FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 AND lookup_key=$3"
            )
            .uuid(scope.tenant.0)
            .uuid(scope.run.0)
            .text(&lookup_key)
            .fetch_optional(tx.conn())
            .await?
            {
                entry.expires_at = entry.expires_at.min(old.ts("expires_at")?);
            }
            let payload =
                serde_json::to_value(&entry).map_err(|_| conflict("source category serialization failed"))?;
            stmt!(
                B,
                format!(
                    "INSERT INTO source_category_cache(tenant_id,run_id,lookup_key,payload,expires_at) VALUES($1,$2,$3,$4,$5) {}",
                    <B::Dialect as Dialect>::upsert_update(
                        &["tenant_id", "run_id", "lookup_key"],
                        &["payload", "expires_at"],
                        None
                    )
                )
            )
            .uuid(scope.tenant.0)
            .uuid(scope.run.0)
            .text(&lookup_key)
            .json(&payload)
            .ts(entry.expires_at)
            .execute(tx.conn())
            .await?;
            evict::<B>(
                tx.conn(),
                "source_category_cache",
                "expires_at",
                scope,
                i64::try_from(MAX_CATEGORY_CACHE_ENTRIES)
                    .map_err(|_| conflict("category capacity overflow"))?,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    async fn reset(&self, tenant: TenantId, run: CrawlRunId) -> Result<(), StoreError> {
        self.scope()?;
        let mut tx = self.begin_write().await?;
        let owner = scope_tx::<B>(tx.conn(), tenant, run).await?;
        let generation = owner
            .generation
            .checked_add(1)
            .ok_or_else(|| conflict("source memo reset generation exhausted"))?;
        stmt!(
            B,
            "UPDATE source_memo_control SET generation=$3 WHERE tenant_id=$1 AND run_id=$2"
        )
        .uuid(tenant.0)
        .uuid(run.0)
        .i64(generation)
        .execute(tx.conn())
        .await?;
        // The generation is operational metadata only. A delayed volatile write to the old
        // rendition cannot become visible after this transaction commits, even if cancelled.
        if !owner.zdr {
            stmt!(B, "DELETE FROM source_memo_seen WHERE tenant_id=$1 AND run_id=$2")
                .uuid(tenant.0)
                .uuid(run.0)
                .execute(tx.conn())
                .await?;
            stmt!(
                B,
                "DELETE FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2"
            )
            .uuid(tenant.0)
            .uuid(run.0)
            .execute(tx.conn())
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
