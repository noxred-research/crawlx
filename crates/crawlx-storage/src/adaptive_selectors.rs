//! Tenant/principal/origin/source/schema-scoped descriptor storage with fixed retention.
//! ZDR rows contain only lookup metadata; descriptor bytes use the shared volatile buffer.

use super::MemoryStore;
use crate::codec::{from_json, get, to_json};
use crate::error::db;
use crate::Pg;
use async_trait::async_trait;
use chrono::Duration;
use crawlx_core::cache::{AdaptiveSelectorRecordV1, AdaptiveSelectorRepo};
use crawlx_core::config::RetentionMode;
use crawlx_core::hash::Digest;
use crawlx_core::repo::RunRepo;
use crawlx_core::selectors::SelectorScopeV1;
use crawlx_core::{CrawlRunId, StoreError, TenantId, Timestamp};

#[derive(Clone)]
pub(super) struct StoredDescriptor {
    pub(super) run: CrawlRunId,
    expires_at: Timestamp,
    record: Option<AdaptiveSelectorRecordV1>,
    volatile_page: Option<i64>,
}

fn identity(scope: &SelectorScopeV1, selector_id: &str) -> Result<(TenantId, String), StoreError> {
    scope
        .validate()
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    if selector_id.is_empty() || selector_id.len() > 128 {
        return Err(StoreError::Serialization("invalid selector identifier".into()));
    }
    let tenant = scope
        .tenant
        .parse::<uuid::Uuid>()
        .map_err(|_| StoreError::AccessDenied("invalid selector tenant".into()))?;
    let encoded =
        serde_json::to_vec(&(scope, selector_id)).map_err(|e| StoreError::Serialization(e.to_string()))?;
    Ok((
        TenantId(tenant),
        Digest::of("crawlx/adaptive-selector-scope/v1", &encoded).to_string(),
    ))
}
fn page_key(key: &str) -> i64 {
    let digest = Digest::of("crawlx/adaptive-selector-volatile-page/v1", key.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.0[..8]);
    // Separate negative delivery-page namespace from real positive frontier identifiers.
    i64::from_be_bytes(bytes)
        .saturating_abs()
        .saturating_neg()
        .min(-1)
}
fn expiry(
    record: &AdaptiveSelectorRecordV1,
    created: Timestamp,
    mode: RetentionMode,
    days: u16,
    now: Timestamp,
) -> Result<Timestamp, StoreError> {
    record
        .spec
        .validate()
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    let horizon = created
        + if mode == RetentionMode::Zdr {
            Duration::hours(1)
        } else {
            Duration::days(i64::from(days))
        };
    if record.expires_at <= now || record.expires_at > horizon || (mode != RetentionMode::Zdr && days == 0) {
        return Err(StoreError::RetentionDenied(
            "selector expiry exceeds source run retention".into(),
        ));
    }
    Ok(record.expires_at)
}
async fn volatile_put(
    buffer: Option<&crate::DeliveryBuffer>,
    tenant: TenantId,
    key: &str,
    record: &AdaptiveSelectorRecordV1,
) -> Result<i64, StoreError> {
    let buffer = buffer.ok_or_else(|| {
        StoreError::RetentionDenied("shared volatile descriptor delivery unavailable".into())
    })?;
    let bytes = serde_json::to_vec(record).map_err(|e| StoreError::Serialization(e.to_string()))?;
    let page = page_key(key);
    buffer
        .insert(
            tenant,
            record.run,
            page,
            "adaptive_selector",
            "application/json",
            &bytes,
        )
        .await?;
    Ok(page)
}
async fn materialize(
    buffer: Option<&crate::DeliveryBuffer>,
    tenant: TenantId,
    stored: StoredDescriptor,
    now: Timestamp,
) -> Result<Option<AdaptiveSelectorRecordV1>, StoreError> {
    if stored.expires_at <= now {
        return Ok(None);
    }
    if let Some(mut record) = stored.record {
        record.expires_at = stored.expires_at;
        return Ok(Some(record));
    }
    let Some(buffer) = buffer else {
        return Ok(None);
    };
    let Some(page) = stored.volatile_page else {
        return Ok(None);
    };
    let Some(page) = buffer.get(tenant, stored.run, page).await? else {
        return Ok(None);
    };
    let Some(blob) = page.blobs.get("adaptive_selector") else {
        return Ok(None);
    };
    let mut record: AdaptiveSelectorRecordV1 =
        serde_json::from_slice(&blob.bytes).map_err(|e| StoreError::Serialization(e.to_string()))?;
    record.expires_at = stored.expires_at.min(page.expires_at);
    Ok((record.expires_at > now).then_some(record))
}

#[async_trait]
impl AdaptiveSelectorRepo for MemoryStore {
    async fn put(&self, record: &AdaptiveSelectorRecordV1) -> Result<(), StoreError> {
        let (tenant, key) = identity(&record.spec.scope, &record.spec.selector_id)?;
        let run = RunRepo::get(self, record.run).await?;
        if run.tenant != tenant {
            return Err(StoreError::AccessDenied(
                "selector source run belongs to another tenant".into(),
            ));
        }
        let expires_at = expiry(
            record,
            run.created_at,
            run.config.retention.mode,
            run.config.retention.days,
            self.clock.now(),
        )?;
        let buffer = self.dataset_delivery.lock().clone();
        let volatile_page = if run.config.retention.mode == RetentionMode::Zdr {
            Some(volatile_put(buffer.as_deref(), tenant, &key, record).await?)
        } else {
            None
        };
        let mut inner = self.inner.lock();
        if !inner.runs.contains_key(&record.run) {
            return Err(StoreError::NotFound {
                entity: "crawl_run",
                id: record.run.to_string(),
            });
        }
        let expiry = inner
            .adaptive_selectors
            .get(&key)
            .filter(|old| old.run == record.run)
            .map_or(expires_at, |old| old.expires_at.min(expires_at));
        inner.adaptive_selectors.insert(
            key,
            StoredDescriptor {
                run: record.run,
                expires_at: expiry,
                record: volatile_page.is_none().then(|| record.clone()),
                volatile_page,
            },
        );
        Ok(())
    }
    async fn get(
        &self,
        scope: &SelectorScopeV1,
        selector_id: &str,
        now: Timestamp,
    ) -> Result<Option<AdaptiveSelectorRecordV1>, StoreError> {
        let (tenant, key) = identity(scope, selector_id)?;
        let stored = self.inner.lock().adaptive_selectors.get(&key).cloned();
        let Some(mut stored) = stored else {
            return Ok(None);
        };
        let run = match RunRepo::get(self, stored.run).await {
            Ok(run) => run,
            Err(StoreError::NotFound { .. }) => return Ok(None),
            Err(error) => return Err(error),
        };
        if run.tenant != tenant {
            return Ok(None);
        }
        let horizon = run.created_at
            + if run.config.retention.mode == RetentionMode::Zdr {
                Duration::hours(1)
            } else {
                Duration::days(i64::from(run.config.retention.days))
            };
        stored.expires_at = stored.expires_at.min(horizon);
        let buffer = self.dataset_delivery.lock().clone();
        let found = materialize(buffer.as_deref(), tenant, stored, now).await?;
        Ok(found.filter(|r| &r.spec.scope == scope && r.spec.selector_id == selector_id))
    }
    async fn delete_run(&self, run: CrawlRunId) -> Result<(), StoreError> {
        self.inner
            .lock()
            .adaptive_selectors
            .retain(|_, record| record.run != run);
        Ok(())
    }
    async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError> {
        let mut inner = self.inner.lock();
        let before = inner.adaptive_selectors.len();
        inner
            .adaptive_selectors
            .retain(|_, record| record.expires_at > now);
        Ok(u64::try_from(before.saturating_sub(inner.adaptive_selectors.len())).unwrap_or(u64::MAX))
    }
}

#[async_trait]
impl AdaptiveSelectorRepo for Pg {
    async fn put(&self, record: &AdaptiveSelectorRecordV1) -> Result<(), StoreError> {
        let (tenant, key) = identity(&record.spec.scope, &record.spec.selector_id)?;
        let run = RunRepo::get(self, record.run).await?;
        if run.tenant != tenant {
            return Err(StoreError::AccessDenied(
                "selector source run belongs to another tenant".into(),
            ));
        }
        let now = chrono::Utc::now();
        let expires_at = expiry(
            record,
            run.created_at,
            run.config.retention.mode,
            run.config.retention.days,
            now,
        )?;
        let volatile_page = if run.config.retention.mode == RetentionMode::Zdr {
            Some(volatile_put(self.delivery.as_deref(), tenant, &key, record).await?)
        } else {
            None
        };
        let payload = if volatile_page.is_none() {
            Some(to_json(record)?)
        } else {
            None
        };
        let saved = sqlx::query("INSERT INTO adaptive_selectors(tenant_id,scope_key,run_id,payload,volatile_page,expires_at) \
            SELECT $1,$2,$3,$4,$5,$6 FROM crawl_runs WHERE tenant_id=$1 AND run_id=$3 AND purge_requested_at IS NULL \
            ON CONFLICT(tenant_id,scope_key) DO UPDATE SET run_id=EXCLUDED.run_id,payload=EXCLUDED.payload, \
            volatile_page=EXCLUDED.volatile_page,expires_at=CASE WHEN adaptive_selectors.run_id=EXCLUDED.run_id \
            THEN LEAST(adaptive_selectors.expires_at,EXCLUDED.expires_at) ELSE EXCLUDED.expires_at END")
            .bind(tenant.0).bind(key).bind(record.run.0).bind(payload).bind(volatile_page).bind(expires_at)
            .execute(&self.pool).await.map_err(db)?;
        if saved.rows_affected() == 0 {
            return Err(StoreError::RetentionDenied(
                "selector source run is unavailable or purging".into(),
            ));
        }
        Ok(())
    }
    async fn get(
        &self,
        scope: &SelectorScopeV1,
        selector_id: &str,
        now: Timestamp,
    ) -> Result<Option<AdaptiveSelectorRecordV1>, StoreError> {
        let (tenant, key) = identity(scope, selector_id)?;
        let row = sqlx::query(
            "SELECT a.* FROM adaptive_selectors a JOIN crawl_runs r USING(tenant_id,run_id) \
            WHERE a.tenant_id=$1 AND a.scope_key=$2 AND a.expires_at>$3 AND r.purge_requested_at IS NULL \
            AND (r.expires_at IS NULL OR r.expires_at>$3)",
        )
        .bind(tenant.0)
        .bind(key)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let payload: Option<serde_json::Value> = get(&row, "payload")?;
        let stored = StoredDescriptor {
            run: CrawlRunId(get(&row, "run_id")?),
            expires_at: get(&row, "expires_at")?,
            record: payload.map(from_json).transpose()?,
            volatile_page: get(&row, "volatile_page")?,
        };
        let found = materialize(self.delivery.as_deref(), tenant, stored, now).await?;
        Ok(found.filter(|r| &r.spec.scope == scope && r.spec.selector_id == selector_id))
    }
    async fn delete_run(&self, run: CrawlRunId) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM adaptive_selectors WHERE run_id=$1")
            .bind(run.0)
            .execute(&self.pool)
            .await
            .map_err(db)?;
        Ok(())
    }
    async fn sweep(&self, now: Timestamp) -> Result<u64, StoreError> {
        Ok(sqlx::query("DELETE FROM adaptive_selectors WHERE expires_at<=$1")
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(db)?
            .rows_affected())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::testkit::{crawl_run, create_crawl};
    use crawlx_core::selectors::{AdaptiveSelectorSpecV1, StructuralDescriptorV1};
    use crawlx_core::time::ManualClock;
    use crawlx_core::Clock;
    use std::sync::Arc;

    fn spec(tenant: TenantId) -> AdaptiveSelectorSpecV1 {
        AdaptiveSelectorSpecV1::new(
            "body".into(),
            SelectorScopeV1::new(
                tenant.to_string(),
                "principal-a".into(),
                "https://example.test".into(),
                "news".into(),
                "article/v1".into(),
            ),
            StructuralDescriptorV1::new(
                "p".into(),
                Some("article".into()),
                Some("main".into()),
                vec!["descriptor-canary".into()],
                0,
            ),
        )
    }
    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new("2026-11-04T12:00:00Z".parse().unwrap()))
    }
    #[tokio::test]
    async fn memory_scope_fixed_expiry_and_purge_are_enforced() {
        let clock = clock();
        let store = MemoryStore::with_clock(clock.clone());
        let tenant = TenantId::new();
        let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        run.created_at = clock.now();
        store.create(&run, None).await.unwrap();
        let record = AdaptiveSelectorRecordV1::new(run.id, spec(tenant), clock.now() + Duration::minutes(10));
        AdaptiveSelectorRepo::put(&store, &record).await.unwrap();
        assert_eq!(
            AdaptiveSelectorRepo::get(&store, &record.spec.scope, "body", clock.now())
                .await
                .unwrap(),
            Some(record.clone())
        );
        let mut foreign = record.spec.scope.clone();
        foreign.principal = "principal-b".into();
        assert!(AdaptiveSelectorRepo::get(&store, &foreign, "body", clock.now())
            .await
            .unwrap()
            .is_none());
        foreign = record.spec.scope.clone();
        foreign.tenant = TenantId::new().to_string();
        assert!(AdaptiveSelectorRepo::get(&store, &foreign, "body", clock.now())
            .await
            .unwrap()
            .is_none());
        let mut replacement = record.clone();
        replacement.expires_at += Duration::minutes(5);
        AdaptiveSelectorRepo::put(&store, &replacement).await.unwrap();
        assert_eq!(
            AdaptiveSelectorRepo::get(&store, &record.spec.scope, "body", clock.now())
                .await
                .unwrap()
                .unwrap()
                .expires_at,
            record.expires_at
        );
        let mut invalid = record.clone();
        invalid.expires_at = run.created_at + Duration::days(8);
        assert!(matches!(
            AdaptiveSelectorRepo::put(&store, &invalid).await,
            Err(StoreError::RetentionDenied(_))
        ));
        clock.advance_ms(600_001);
        assert!(
            AdaptiveSelectorRepo::get(&store, &record.spec.scope, "body", clock.now())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(AdaptiveSelectorRepo::sweep(&store, clock.now()).await.unwrap(), 1);
        replacement.expires_at = clock.now() + Duration::minutes(2);
        AdaptiveSelectorRepo::put(&store, &replacement).await.unwrap();
        store.purge_run(run.id).await.unwrap();
        assert!(store.inner.lock().adaptive_selectors.is_empty());
    }
    #[tokio::test]
    async fn zdr_descriptor_payload_uses_shared_buffer_without_renewing_original_ttl() {
        let clock = clock();
        let store = MemoryStore::with_clock(clock.clone());
        let limits = crate::BufferLimits {
            ttl: std::time::Duration::from_secs(5),
            ..crate::BufferLimits::default()
        };
        let delivery = Arc::new(crate::DeliveryBuffer::new(clock.clone(), limits));
        store.set_dataset_delivery(delivery.clone());
        let tenant = TenantId::new();
        let mut run = crawl_run(tenant, create_crawl("https://example.test/", &[], 1));
        run.created_at = clock.now();
        run.config.retention.mode = RetentionMode::Zdr;
        run.config.retention.days = 0;
        store.create(&run, None).await.unwrap();
        let record = AdaptiveSelectorRecordV1::new(run.id, spec(tenant), clock.now() + Duration::minutes(30));
        AdaptiveSelectorRepo::put(&store, &record).await.unwrap();
        assert!(store
            .inner
            .lock()
            .adaptive_selectors
            .values()
            .all(|row| row.record.is_none()));
        assert!(delivery.bytes().await.unwrap() > 0);
        clock.advance_ms(4000);
        AdaptiveSelectorRepo::put(&store, &record).await.unwrap();
        clock.advance_ms(2000);
        assert!(
            AdaptiveSelectorRepo::get(&store, &record.spec.scope, "body", clock.now())
                .await
                .unwrap()
                .is_none()
        );
        delivery.sweep(clock.now()).await.unwrap();
        assert_eq!(delivery.bytes().await.unwrap(), 0);
    }
}
