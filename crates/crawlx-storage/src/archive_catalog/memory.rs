//! In-process mirror of the durable archive transaction boundary.

use super::{history_key, invalid, live, publish_bounds, record_bounds, scope, writer};
use crate::MemoryStore;
use async_trait::async_trait;
use crawlx_core::archive::ArchiveManifestV1;
use crawlx_core::archive_catalog::{
    ArchiveExportState, ArchiveExportV1, ArchiveHistoryKeyV1, ArchiveHistoryV1, ArchiveReadV1,
    ArchiveRecordV1, ArchiveRepo,
};
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::RunRepo;
use crawlx_core::{ArtifactRef, CrawlRunId, StoreError, TenantId, Timestamp};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Default)]
pub(crate) struct ArchiveState {
    exports: BTreeMap<(TenantId, Uuid), ArchiveExportV1>,
    records: BTreeMap<(TenantId, Uuid, u64), ArchiveRecordV1>,
    history: BTreeMap<(TenantId, Uuid, u64), ArchiveHistoryV1>,
    artifacts: BTreeMap<crawlx_core::ArtifactId, crate::ArtifactRow>,
}

impl ArchiveState {
    pub(crate) fn artifact_row(&self, id: &crawlx_core::ArtifactId) -> Option<&crate::ArtifactRow> {
        self.artifacts.get(id)
    }
    pub(crate) fn purge_run(&mut self, run: CrawlRunId) {
        let sources: Vec<_> = self
            .exports
            .values()
            .filter(|row| row.run == run)
            .map(|row| (row.tenant, row.id))
            .collect();
        for (tenant, export) in sources {
            self.erase(tenant, export);
        }
    }

    fn artifact(
        &self,
        export: &ArchiveExportV1,
        artifact: &ArtifactRef,
        minimum: u64,
        content_type: &str,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        let row = self
            .artifacts
            .get(&artifact.id)
            .ok_or_else(|| invalid("archive artifact is not committed"))?;
        if row.tenant != export.tenant
            || row.run != export.run
            || row.digest != artifact.digest
            || row.sensitivity != crawlx_core::repo::Sensitivity::Content
            || row.size_bytes < minimum
            || row.content_type != content_type
            || row.expires_at.is_some_and(|expiry| expiry <= now)
        {
            return Err(invalid("archive artifact custody, format or expiry mismatch"));
        }
        Ok(())
    }

    fn erase(&mut self, tenant: TenantId, export: Uuid) {
        let mut doomed = BTreeSet::from([export]);
        loop {
            let mut changed = false;
            for ((owner, id, _), record) in &self.records {
                if *owner == tenant
                    && record
                        .dependency
                        .as_ref()
                        .is_some_and(|source| doomed.contains(&source.export))
                {
                    changed |= doomed.insert(*id);
                }
            }
            if !changed {
                break;
            }
        }
        for id in &doomed {
            if let Some(row) = self.exports.get_mut(&(tenant, *id)) {
                row.state = ArchiveExportState::Deleted;
                row.fence = row.fence.saturating_add(1);
                row.manifest = None;
            }
        }
        self.history
            .retain(|(owner, id, _), _| *owner != tenant || !doomed.contains(id));
    }
}

#[async_trait]
impl crate::ArtifactIndex for MemoryStore {
    async fn record(&self, row: &crate::ArtifactRow) -> Result<(), StoreError> {
        scope(row.tenant)?;
        if RunRepo::get(self, row.run).await?.tenant != row.tenant {
            return Err(StoreError::AccessDenied("artifact index tenant mismatch".into()));
        }
        self.archives.lock().artifacts.insert(row.id, row.clone());
        Ok(())
    }

    async fn retention(
        &self,
        id: crawlx_core::ArtifactId,
    ) -> Result<Option<crate::artifacts::ArtifactRetention>, StoreError> {
        let state = self.archives.lock();
        let Some(row) = state.artifacts.get(&id) else {
            return Ok(None);
        };
        scope(row.tenant)?;
        Ok(Some(crate::artifacts::ArtifactRetention::new(
            row.expires_at,
            None,
        )))
    }

    async fn mark_deleted(&self, ids: &[crawlx_core::ArtifactId]) -> Result<(), StoreError> {
        let mut state = self.archives.lock();
        for id in ids {
            if state
                .artifacts
                .get(id)
                .is_some_and(|row| crate::tenant::current().is_some_and(|tenant| row.tenant != tenant))
            {
                return Err(StoreError::AccessDenied(
                    "artifact index erasure tenant mismatch".into(),
                ));
            }
            state.artifacts.remove(id);
        }
        Ok(())
    }
}

#[async_trait]
impl ArchiveRepo for MemoryStore {
    async fn begin(&self, export: &ArchiveExportV1) -> Result<(), StoreError> {
        scope(export.tenant)?;
        export.config.validate().map_err(invalid)?;
        super::pending_bounds(export)?;
        let run = RunRepo::get(self, export.run).await?;
        if run.tenant != export.tenant || run.config.retention.mode == RetentionMode::Zdr {
            return Err(StoreError::RetentionDenied(
                "durable archive requires retained tenant-owned run".into(),
            ));
        }
        let expiry = (run.config.retention.days != 0)
            .then(|| run.created_at + chrono::Duration::days(i64::from(run.config.retention.days)));
        if run.config.output.archive.as_ref() != Some(&export.config)
            || expiry.is_some_and(|expiry| expiry <= self.worker_registry_now())
        {
            return Err(StoreError::RetentionDenied(
                "archive configuration absent, changed or expired".into(),
            ));
        }
        if export.id != export.run.0 || export.created_at != run.created_at || export.expires_at != expiry {
            return Err(invalid("archive source retention mismatch"));
        }
        let mut state = self.archives.lock();
        if let Some(existing) = state.exports.get(&(export.tenant, export.id)) {
            if super::json(&existing.config)? != super::json(&export.config)? {
                return Err(invalid("archive configuration changed during recovery"));
            }
            return Ok(());
        }
        state.exports.insert((export.tenant, export.id), export.clone());
        Ok(())
    }

    async fn claim(
        &self,
        tenant: TenantId,
        export: Uuid,
        now: Timestamp,
    ) -> Result<Option<ArchiveExportV1>, StoreError> {
        scope(tenant)?;
        let mut state = self.archives.lock();
        let Some(row) = state.exports.get_mut(&(tenant, export)) else {
            return Ok(None);
        };
        if !live(row, now) || row.state != ArchiveExportState::Recording || row.lease_until > now {
            return Ok(None);
        }
        row.fence = row
            .fence
            .checked_add(1)
            .ok_or_else(|| invalid("archive fence exhausted"))?;
        row.lease_until = now + chrono::Duration::seconds(120);
        Ok(Some(row.clone()))
    }

    async fn get(&self, tenant: TenantId, export: Uuid, now: Timestamp) -> Result<ArchiveReadV1, StoreError> {
        scope(tenant)?;
        let state = self.archives.lock();
        Ok(match state.exports.get(&(tenant, export)) {
            None => ArchiveReadV1::Missing,
            Some(row) if row.state == ArchiveExportState::Deleted => ArchiveReadV1::Missing,
            Some(row) if !live(row, now) => ArchiveReadV1::Expired,
            Some(row) => ArchiveReadV1::Available(Box::new(row.clone())),
        })
    }

    async fn list(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        now: Timestamp,
    ) -> Result<Vec<ArchiveExportV1>, StoreError> {
        scope(tenant)?;
        Ok(self
            .archives
            .lock()
            .exports
            .values()
            .filter(|row| row.tenant == tenant && row.run == run && live(row, now))
            .take(100)
            .cloned()
            .collect())
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
        let mut state = self.archives.lock();
        let export = state
            .exports
            .get(&(tenant, record.export))
            .ok_or_else(|| invalid("archive export missing"))?;
        writer(export, fence, now)?;
        if let Some(existing) = state.records.get(&(tenant, record.export, record.ordinal)) {
            if existing.record_id != record.record_id
                || existing.payload_digest != record.payload_digest
                || existing.target != record.target
                || existing.length != record.length
            {
                return Err(invalid("archive ordinal conflicts with committed shard"));
            }
            return Ok(());
        }
        record_bounds(export, record)?;
        state.artifact(
            export,
            &record.artifact,
            record
                .offset
                .checked_add(record.length)
                .ok_or_else(|| invalid("archive record range overflow"))?,
            "application/warc",
            now,
        )?;
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
            let baseline = state
                .exports
                .get(&(tenant, source.export))
                .ok_or_else(|| invalid("archive dependency missing"))?;
            let baseline_record = state
                .records
                .get(&(tenant, source.export, source.ordinal))
                .ok_or_else(|| invalid("archive dependency record missing"))?;
            let baseline_history = state.history.get(&(tenant, source.export, source.ordinal));
            if source.export == record.export
                || !live(baseline, now)
                || baseline.state != ArchiveExportState::Published
                || super::expires_before(baseline.expires_at, export.expires_at)
                || baseline_record.dependency.is_some()
                || baseline_record.payload_digest != record.payload_digest
                || history.is_none_or(|current| baseline_history.is_none_or(|prior| prior.key != current.key))
            {
                return Err(invalid("archive dependency is incompatible or not durable"));
            }
        }
        let row = state
            .exports
            .get_mut(&(tenant, record.export))
            .ok_or(StoreError::LeaseLost)?;
        row.records += 1;
        row.bytes += record.length;
        row.lease_until = now + chrono::Duration::seconds(120);
        state
            .records
            .insert((tenant, record.export, record.ordinal), record.clone());
        if let Some(history) = history {
            state
                .history
                .insert((tenant, record.export, record.ordinal), history.clone());
        }
        Ok(())
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
        let state = self.archives.lock();
        if !state
            .exports
            .get(&(tenant, export))
            .is_some_and(|row| live(row, now))
        {
            return Ok(Vec::new());
        }
        Ok(state
            .records
            .range((tenant, export, after.map_or(0, |n| n.saturating_add(1)))..=(tenant, export, u64::MAX))
            .take(usize::try_from(limit).map_err(|_| invalid("archive page limit"))?)
            .map(|(_, row)| row.clone())
            .collect())
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
        let mut state = self.archives.lock();
        let row = state
            .exports
            .get(&(tenant, export))
            .ok_or(StoreError::LeaseLost)?;
        writer(row, fence, now)?;
        publish_bounds(row, manifest)?;
        let expected = if row.config.format == crawlx_core::archive::ArchiveFormat::Warc {
            "application/warc"
        } else {
            "application/wacz+zip"
        };
        state.artifact(row, artifact, 1, expected, now)?;
        if let Some(index) = index {
            state.artifact(row, index, 1, "application/cdxj", now)?;
        }
        if (row.config.format == crawlx_core::archive::ArchiveFormat::Warc) != index.is_some() {
            return Err(invalid("archive index does not match export format"));
        }
        let row = state
            .exports
            .get_mut(&(tenant, export))
            .ok_or(StoreError::LeaseLost)?;
        row.artifact = Some(artifact.clone());
        row.index = index.cloned();
        row.manifest = Some(manifest.clone());
        row.state = ArchiveExportState::Published;
        Ok(())
    }

    async fn history(
        &self,
        tenant: TenantId,
        key: &ArchiveHistoryKeyV1,
        now: Timestamp,
    ) -> Result<Option<ArchiveHistoryV1>, StoreError> {
        scope(tenant)?;
        history_key(key)?;
        let state = self.archives.lock();
        Ok(state
            .history
            .iter()
            .filter(|((owner, export, ordinal), history)| {
                *owner == tenant
                    && history.key == *key
                    && (history.etag.is_some() || history.last_modified.is_some())
                    && state
                        .exports
                        .get(&(*owner, *export))
                        .is_some_and(|row| live(row, now) && row.state == ArchiveExportState::Published)
                    && state.records.contains_key(&(*owner, *export, *ordinal))
            })
            .max_by_key(|(_, history)| history.captured_at)
            .map(|(_, history)| history.clone()))
    }

    async fn erase(&self, tenant: TenantId, export: Uuid) -> Result<(), StoreError> {
        scope(tenant)?;
        self.archives.lock().erase(tenant, export);
        Ok(())
    }
    async fn renew(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut state = self.archives.lock();
        let row = state
            .exports
            .get_mut(&(tenant, export))
            .ok_or(StoreError::LeaseLost)?;
        writer(row, fence, now)?;
        row.lease_until = now + chrono::Duration::seconds(120);
        Ok(())
    }
    async fn artifact_visible(
        &self,
        tenant: TenantId,
        artifact: &ArtifactRef,
        now: Timestamp,
    ) -> Result<bool, StoreError> {
        scope(tenant)?;
        let state = self.archives.lock();
        Ok(state.exports.values().any(|row| {
            row.tenant == tenant
                && live(row, now)
                && row.state == ArchiveExportState::Published
                && (row.artifact.as_ref() == Some(artifact)
                    || row.index.as_ref() == Some(artifact)
                    || state
                        .records
                        .values()
                        .any(|record| record.export == row.id && record.artifact == *artifact))
        }))
    }
    async fn erased_artifacts(&self, tenant: TenantId, limit: u32) -> Result<Vec<ArtifactRef>, StoreError> {
        scope(tenant)?;
        if !(1..=64).contains(&limit) {
            return Err(invalid("archive erase batch limit must be 1..64"));
        }
        let state = self.archives.lock();
        let mut refs = Vec::new();
        for row in state
            .exports
            .values()
            .filter(|row| row.tenant == tenant && row.state == ArchiveExportState::Deleted)
        {
            if let Some(artifact) = &row.artifact {
                refs.push(artifact.clone());
            }
            if refs.len() >= usize::try_from(limit).unwrap_or(64) {
                break;
            }
            if let Some(artifact) = &row.index {
                refs.push(artifact.clone());
            }
            if refs.len() >= usize::try_from(limit).unwrap_or(64) {
                break;
            }
            for ((owner, export, _), record) in &state.records {
                if *owner == tenant && *export == row.id {
                    refs.push(record.artifact.clone());
                }
                if refs.len() >= usize::try_from(limit).unwrap_or(64) {
                    break;
                }
            }
            if refs.len() >= usize::try_from(limit).unwrap_or(64) {
                break;
            }
        }
        Ok(refs)
    }
    async fn acknowledge_erased(&self, tenant: TenantId, artifact: &ArtifactRef) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut state = self.archives.lock();
        let deleted: BTreeSet<_> = state
            .exports
            .values()
            .filter(|row| row.tenant == tenant && row.state == ArchiveExportState::Deleted)
            .map(|row| row.id)
            .collect();
        for row in state
            .exports
            .values_mut()
            .filter(|row| row.tenant == tenant && deleted.contains(&row.id))
        {
            if row.artifact.as_ref() == Some(artifact) {
                row.artifact = None;
            }
            if row.index.as_ref() == Some(artifact) {
                row.index = None;
            }
        }
        state.records.retain(|(owner, export, _), row| {
            *owner != tenant || !deleted.contains(export) || row.artifact != *artifact
        });
        Ok(())
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
        let mut after = None;
        let mut selected = Vec::new();
        loop {
            // Release archive metadata before reading run state. Dataset commits acquire
            // run state first and may consult artifact custody under the archive lock.
            let candidates: Vec<_> = self
                .archives
                .lock()
                .exports
                .range((
                    after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                    std::ops::Bound::Unbounded,
                ))
                .filter(|(_, row)| {
                    live(row, now)
                        && (row.state == ArchiveExportState::Published
                            || row.state == ArchiveExportState::Failed
                            || row.lease_until <= now)
                })
                .take(64)
                .map(|(_, row)| row.clone())
                .collect();
            if candidates.is_empty() {
                return Ok(selected);
            }
            for row in candidates {
                after = Some((row.tenant, row.id));
                if self.archive_run_active(row.run) {
                    selected.push(row);
                    if selected.len() >= usize::try_from(limit).unwrap_or(64) {
                        return Ok(selected);
                    }
                }
            }
        }
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
        let mut state = self.archives.lock();
        let row = state
            .exports
            .get_mut(&(tenant, export))
            .ok_or(StoreError::LeaseLost)?;
        writer(row, fence, now)?;
        row.state = ArchiveExportState::Failed;
        row.failure = Some(failure);
        Ok(())
    }
    async fn traffic_keyset(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
        after: u64,
        limit: u32,
    ) -> Result<Vec<crawlx_core::archive_catalog::ArchiveTrafficV1>, StoreError> {
        scope(tenant)?;
        self.archive_traffic_keyset(tenant, run, after, limit)
    }
}
