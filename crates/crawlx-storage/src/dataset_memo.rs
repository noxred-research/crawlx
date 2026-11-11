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
async fn scope_tx(
    pg: &Pg,
    tx: &mut Transaction<'_, Postgres>,
    tenant: TenantId,
    run: CrawlRunId,
) -> Result<ScopeRow, StoreError> {
    check_tenant(tenant)?;
    let row = sqlx::query("SELECT tenant_id, retention_mode::text AS mode, retention_days, created_at, expires_at, purge_requested_at FROM crawl_runs WHERE run_id=$1 FOR UPDATE")
        .bind(run.0).fetch_optional(&mut **tx).await.map_err(db)?.ok_or_else(|| not_found("crawl_run", run))?;
    if TenantId(get(&row, "tenant_id")?) != tenant {
        return Err(StoreError::AccessDenied("source memo tenant mismatch".into()));
    }
    if get::<Option<Timestamp>>(&row, "purge_requested_at")?.is_some() {
        return Err(expired());
    }
    let zdr = get::<String>(&row, "mode")? == "zdr";
    let created: Timestamp = get(&row, "created_at")?;
    let duration = if zdr {
        chrono::Duration::hours(1)
    } else {
        chrono::Duration::days(i64::from(get::<i32>(&row, "retention_days")?))
    };
    let deadline = created.checked_add_signed(duration).ok_or_else(expired)?;
    let deadline =
        get::<Option<Timestamp>>(&row, "expires_at")?.map_or(deadline, |value| value.min(deadline));
    sqlx::query(
        "INSERT INTO source_memo_control(tenant_id,run_id,generation) VALUES($1,$2,0) ON CONFLICT DO NOTHING",
    )
    .bind(tenant.0)
    .bind(run.0)
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    let generation = sqlx::query_scalar::<_, i64>(
        "SELECT generation FROM source_memo_control WHERE tenant_id=$1 AND run_id=$2",
    )
    .bind(tenant.0)
    .bind(run.0)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    let _ = pg;
    Ok(ScopeRow {
        tenant,
        zdr,
        deadline,
        generation,
    })
}
async fn volatile_get(pg: &Pg, owner: &ScopeRow, run: CrawlRunId) -> Result<MemoState, StoreError> {
    let buffer = pg.delivery.as_ref().ok_or_else(expired)?;
    let Some(page) = buffer.get(owner.tenant, run, VOLATILE_PAGE).await? else {
        return Ok(MemoState::default());
    };
    let kind = format!("{VOLATILE_KIND}.{}", owner.generation);
    let Some(blob) = page.blobs.get(&kind) else {
        return Ok(MemoState::default());
    };
    serde_json::from_slice(&blob.bytes).map_err(|_| conflict("invalid volatile source memo"))
}
async fn volatile_put(
    pg: &Pg,
    owner: &ScopeRow,
    run: CrawlRunId,
    state: &MemoState,
) -> Result<(), StoreError> {
    let buffer = pg.delivery.as_ref().ok_or_else(expired)?;
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

#[async_trait]
impl SourceMemoRepo for Pg {
    async fn seen(&self, scope: &MemoScopeV1, article: Digest, now: Timestamp) -> Result<bool, StoreError> {
        let key = lookup(scope, article, false)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let owner = scope_tx(self, &mut tx, scope.tenant, scope.run).await?;
        if owner.deadline <= now {
            return Ok(false);
        }
        let found = if owner.zdr {
            volatile_get(self, &owner, scope.run)
                .await?
                .seen
                .contains_key(&key)
        } else {
            sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM source_memo_seen WHERE tenant_id=$1 AND run_id=$2 AND lookup_key=$3)")
                .bind(scope.tenant.0).bind(scope.run.0).bind(key.to_hex()).fetch_one(&mut *tx).await.map_err(db)?
        };
        tx.commit().await.map_err(db)?;
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
        let mut tx = self.pool.begin().await.map_err(db)?;
        let owner = scope_tx(self, &mut tx, scope.tenant, scope.run).await?;
        if owner.deadline <= now {
            return Err(expired());
        }
        if owner.zdr {
            let mut state = volatile_get(self, &owner, scope.run).await?;
            state.record(&keys, maximum, now);
            volatile_put(self, &owner, scope.run, &state).await?;
        } else {
            for key in keys {
                sqlx::query("INSERT INTO source_memo_seen(tenant_id,run_id,lookup_key,recorded_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
                    .bind(scope.tenant.0).bind(scope.run.0).bind(key.to_hex()).bind(now).execute(&mut *tx).await.map_err(db)?;
            }
            sqlx::query("DELETE FROM source_memo_seen WHERE tenant_id=$1 AND run_id=$2 AND lookup_key IN (SELECT lookup_key FROM source_memo_seen WHERE tenant_id=$1 AND run_id=$2 ORDER BY recorded_at DESC,lookup_key DESC OFFSET $3)")
                .bind(scope.tenant.0).bind(scope.run.0).bind(i64::from(max_entries)).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }
    async fn category(
        &self,
        scope: &MemoScopeV1,
        representation: Digest,
        now: Timestamp,
    ) -> Result<Option<CategoryCacheEntryV1>, StoreError> {
        let key = lookup(scope, representation, true)?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        let owner = scope_tx(self, &mut tx, scope.tenant, scope.run).await?;
        if owner.deadline <= now {
            return Ok(None);
        }
        let found = if owner.zdr {
            volatile_get(self, &owner, scope.run)
                .await?
                .categories
                .remove(&key)
        } else {
            sqlx::query("SELECT payload FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 AND lookup_key=$3 AND expires_at>$4")
                .bind(scope.tenant.0).bind(scope.run.0).bind(key.to_hex()).bind(now).fetch_optional(&mut *tx).await.map_err(db)?
                .map(|row| from_json(get(&row,"payload")?)).transpose()?
        };
        tx.commit().await.map_err(db)?;
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
        let mut tx = self.pool.begin().await.map_err(db)?;
        let owner = scope_tx(self, &mut tx, scope.tenant, scope.run).await?;
        category_valid(&entry, owner.zdr, owner.deadline, now)?;
        verify_content(
            self,
            &mut tx,
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
            sqlx::query(
                "DELETE FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 AND expires_at<=$3",
            )
            .bind(scope.tenant.0)
            .bind(scope.run.0)
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            if let Some(old) = sqlx::query_scalar::<_, Timestamp>("SELECT expires_at FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 AND lookup_key=$3")
                .bind(scope.tenant.0).bind(scope.run.0).bind(key.to_hex()).fetch_optional(&mut *tx).await.map_err(db)? {
                entry.expires_at = entry.expires_at.min(old);
            }
            sqlx::query("INSERT INTO source_category_cache(tenant_id,run_id,lookup_key,payload,expires_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,run_id,lookup_key) DO UPDATE SET payload=EXCLUDED.payload,expires_at=EXCLUDED.expires_at")
                .bind(scope.tenant.0).bind(scope.run.0).bind(key.to_hex()).bind(serde_json::to_value(&entry).map_err(|_| conflict("source category serialization failed"))?).bind(entry.expires_at).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("DELETE FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 AND lookup_key IN (SELECT lookup_key FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2 ORDER BY expires_at DESC,lookup_key DESC OFFSET $3)")
                .bind(scope.tenant.0).bind(scope.run.0).bind(i64::try_from(MAX_CATEGORY_CACHE_ENTRIES).map_err(|_| conflict("category capacity overflow"))?).execute(&mut *tx).await.map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }
    async fn reset(&self, tenant: TenantId, run: CrawlRunId) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(db)?;
        let owner = scope_tx(self, &mut tx, tenant, run).await?;
        let generation = owner
            .generation
            .checked_add(1)
            .ok_or_else(|| conflict("source memo reset generation exhausted"))?;
        sqlx::query("UPDATE source_memo_control SET generation=$3 WHERE tenant_id=$1 AND run_id=$2")
            .bind(tenant.0)
            .bind(run.0)
            .bind(generation)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        // The generation is operational metadata only. A delayed volatile write to the old
        // rendition cannot become visible after this transaction commits, even if cancelled.
        if !owner.zdr {
            sqlx::query("DELETE FROM source_memo_seen WHERE tenant_id=$1 AND run_id=$2")
                .bind(tenant.0)
                .bind(run.0)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            sqlx::query("DELETE FROM source_category_cache WHERE tenant_id=$1 AND run_id=$2")
                .bind(tenant.0)
                .bind(run.0)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }
}
