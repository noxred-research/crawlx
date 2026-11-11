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
    local_payloads: BTreeMap<(TenantId, Uuid), super::payload::Rows>,
    published_payloads: BTreeMap<TenantId, super::payload::Rows>,
    published_artifacts: BTreeMap<crawlx_core::ArtifactId, (TenantId, Uuid)>,
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

    fn index_payload(&mut self, tenant: TenantId, export: Uuid, ordinal: u64) {
        let Some(owner) = self.exports.get(&(tenant, export)) else {
            return;
        };
        let Some(record) = self.records.get(&(tenant, export, ordinal)) else {
            return;
        };
        if record.payload_key.is_none()
            || record.dependency.is_some()
            || owner.custody.sensitivity != crawlx_core::repo::Sensitivity::Content
        {
            return;
        }
        super::payload::insert(
            self.local_payloads.entry((tenant, export)).or_default(),
            owner,
            record,
        );
    }

    fn publish_payloads(&mut self, tenant: TenantId, export: Uuid) {
        self.local_payloads.remove(&(tenant, export));
        let Some(owner) = self.exports.get(&(tenant, export)) else {
            return;
        };
        for artifact in [owner.artifact.as_ref(), owner.index.as_ref()]
            .into_iter()
            .flatten()
        {
            self.published_artifacts.insert(artifact.id, (tenant, export));
        }
        if owner.config.dedupe != crawlx_core::archive::ArchiveDedupe::Tenant
            || owner.custody.sensitivity != crawlx_core::repo::Sensitivity::Content
        {
            return;
        }
        for (_, record) in self
            .records
            .range((tenant, export, 0)..=(tenant, export, u64::MAX))
        {
            if record.payload_key.is_some() && record.dependency.is_none() {
                super::payload::insert(self.published_payloads.entry(tenant).or_default(), owner, record);
            }
        }
    }

    fn unindex_payloads(&mut self, tenant: TenantId, export: Uuid) {
        self.local_payloads.remove(&(tenant, export));
        let Some(owner) = self.exports.get(&(tenant, export)) else {
            return;
        };
        for artifact in [owner.artifact.as_ref(), owner.index.as_ref()]
            .into_iter()
            .flatten()
        {
            self.published_artifacts.remove(&artifact.id);
        }
        let Some(rows) = self.published_payloads.get_mut(&tenant) else {
            return;
        };
        for (_, record) in self
            .records
            .range((tenant, export, 0)..=(tenant, export, u64::MAX))
        {
            super::payload::remove(rows, owner, record);
        }
        if rows.is_empty() {
            self.published_payloads.remove(&tenant);
        }
    }

    fn artifact(
        &self,
        export: &ArchiveExportV1,
        artifact: &ArtifactRef,
        minimum: u64,
        content_type: &str,
        now: Timestamp,
        custody: crawlx_core::archive_catalog::ArchiveCustodyV1,
    ) -> Result<(), StoreError> {
        let row = self
            .artifacts
            .get(&artifact.id)
            .ok_or_else(|| invalid("archive artifact is not committed"))?;
        if row.tenant != export.tenant
            || row.run != export.run
            || row.digest != artifact.digest
            || !super::artifact_custody(row.sensitivity, row.expires_at, custody, now)
            || row.size_bytes < minimum
            || row.content_type != content_type
            || row.expires_at.is_some_and(|expiry| expiry <= now)
        {
            return Err(invalid("archive artifact custody, format or expiry mismatch"));
        }
        Ok(())
    }

    fn content_package(
        &self,
        source: &ArchiveExportV1,
        dependent: &ArchiveExportV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        if source.tenant != dependent.tenant
            || source.state != ArchiveExportState::Published
            || !live(source, now)
            || source.custody.sensitivity != crawlx_core::repo::Sensitivity::Content
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
        self.artifact(source, artifact, 1, mime, now, source.custody)?;
        if self
            .artifacts
            .get(&artifact.id)
            .is_none_or(|row| super::expires_before(row.expires_at, dependent.expires_at))
        {
            return Err(invalid("archive dependency package deadline is incompatible"));
        }
        Ok(())
    }

    fn payload_sources_live(&self, export: &ArchiveExportV1, now: Timestamp) -> Result<(), StoreError> {
        for (_, record) in self
            .records
            .range((export.tenant, export.id, 0)..=(export.tenant, export.id, u64::MAX))
        {
            if let Some(dependency) = record
                .dependency
                .as_ref()
                .filter(|source| source.export != export.id)
            {
                let source = self
                    .exports
                    .get(&(export.tenant, dependency.export))
                    .ok_or_else(|| invalid("archive dependency package missing"))?;
                self.content_package(source, export, now)?;
            }
        }
        Ok(())
    }

    fn source(
        &self,
        export: &ArchiveExportV1,
        record: &ArchiveRecordV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        if record.custody.sensitivity != crawlx_core::repo::Sensitivity::Sensitive {
            return Ok(());
        }
        let source = record
            .source_artifact
            .as_ref()
            .ok_or_else(|| invalid("sensitive archive source missing"))?;
        let row = self
            .artifacts
            .get(&source.id)
            .ok_or_else(|| invalid("sensitive archive source revoked"))?;
        if row.tenant != export.tenant
            || row.run != export.run
            || row.digest != source.digest
            || row.sensitivity != record.custody.sensitivity
            || row.expires_at != record.custody.expires_at
            || row.content_type != record.mime
            || row.expires_at.is_none_or(|expiry| expiry <= now)
        {
            return Err(invalid("sensitive archive source authority changed"));
        }
        Ok(())
    }

    fn sources_live(&self, export: &ArchiveExportV1, now: Timestamp) -> bool {
        self.records
            .range((export.tenant, export.id, 0)..=(export.tenant, export.id, u64::MAX))
            .all(|(_, record)| self.source(export, record, now).is_ok())
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
            self.unindex_payloads(tenant, *id);
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
        if RunRepo::get_metadata(self, row.run).await?.tenant != row.tenant {
            return Err(StoreError::AccessDenied("artifact index tenant mismatch".into()));
        }
        let mut state = self.archives.lock();
        if state.artifacts.get(&row.id).is_some_and(|previous| {
            previous.tenant != row.tenant
                || previous.run != row.run
                || previous.digest != row.digest
                || previous.sensitivity != row.sensitivity
                || previous.expires_at != row.expires_at
                || previous.content_type != row.content_type
                || previous.size_bytes != row.size_bytes
        }) {
            if let Some((tenant, export)) = state.published_artifacts.get(&row.id).copied() {
                state.erase(tenant, export);
            }
        }
        state.artifacts.insert(row.id, row.clone());
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
            if let Some((tenant, export)) = state.published_artifacts.get(id).copied() {
                state.erase(tenant, export);
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
            if existing.state == ArchiveExportState::Deleted {
                return Err(StoreError::RetentionDenied(
                    "archive export permanently erased".into(),
                ));
            }
            if super::json(&existing.config)? != super::json(&export.config)? {
                return Err(invalid("archive configuration changed during recovery"));
            }
            return Ok(());
        }
        state.exports.insert((export.tenant, export.id), export.clone());
        Ok(())
    }

    async fn narrow_custody(
        &self,
        tenant: TenantId,
        export: Uuid,
        fence: i64,
        custody: &crawlx_core::archive_catalog::ArchiveCustodyV1,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        scope(tenant)?;
        let mut state = self.archives.lock();
        let row = state
            .exports
            .get_mut(&(tenant, export))
            .ok_or(StoreError::LeaseLost)?;
        writer(row, fence, now)?;
        row.custody = super::narrowed(row, *custody, now)?;
        row.expires_at = row.custody.expires_at;
        if row.custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive {
            state.unindex_payloads(tenant, export);
        }
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
        state.source(export, record, now)?;
        if let Some(existing) = state.records.get(&(tenant, record.export, record.ordinal)) {
            if existing != record || state.history.get(&(tenant, record.export, record.ordinal)) != history {
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
            record.custody,
        )?;
        if let Some(history) = history {
            if record.custody.sensitivity != crawlx_core::repo::Sensitivity::Content {
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
            let baseline = state
                .exports
                .get(&(tenant, source.export))
                .ok_or_else(|| invalid("archive dependency missing"))?;
            let baseline_record = state
                .records
                .get(&(tenant, source.export, source.ordinal))
                .ok_or_else(|| invalid("archive dependency record missing"))?;
            let baseline_history = state.history.get(&(tenant, source.export, source.ordinal));
            if source.export != record.export {
                state.content_package(baseline, export, now)?;
            }
            let payload_compatible = record.payload_key.as_ref().is_some_and(|key| {
                super::payload::eligible(
                    export,
                    baseline,
                    baseline_record,
                    key,
                    &record.payload_digest,
                    now,
                ) && (source.export != record.export || source.ordinal < record.ordinal)
            });
            let validator_compatible = record.payload_key.is_none()
                && source.export != record.export
                && live(baseline, now)
                && baseline.state == ArchiveExportState::Published
                && !super::expires_before(baseline.expires_at, export.expires_at)
                && baseline_record.dependency.is_none()
                && baseline_record.payload_digest == record.payload_digest
                && history
                    .is_some_and(|current| baseline_history.is_some_and(|prior| prior.key == current.key));
            if !payload_compatible && !validator_compatible {
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
        state.index_payload(tenant, record.export, record.ordinal);
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

    async fn payload_source(
        &self,
        tenant: TenantId,
        export: Uuid,
        key: &crawlx_core::archive_catalog::ArchivePayloadKeyV1,
        payload_digest: &str,
        now: Timestamp,
    ) -> Result<Option<ArchiveRecordV1>, StoreError> {
        scope(tenant)?;
        let state = self.archives.lock();
        let Some(current) = state.exports.get(&(tenant, export)) else {
            return Ok(None);
        };
        if let Some((source, ordinal)) = state
            .local_payloads
            .get(&(tenant, export))
            .and_then(|rows| super::payload::candidate(rows, current, key, payload_digest, now))
        {
            if let Some(record) = state
                .records
                .get(&(tenant, source, ordinal))
                .filter(|record| super::payload::eligible(current, current, record, key, payload_digest, now))
            {
                return Ok(Some(record.clone()));
            }
        }
        if current.config.dedupe != crawlx_core::archive::ArchiveDedupe::Tenant {
            return Ok(None);
        }
        let candidate = state
            .published_payloads
            .get(&tenant)
            .and_then(|rows| super::payload::candidate(rows, current, key, payload_digest, now));
        Ok(candidate.and_then(|(source, ordinal)| {
            let owner = state.exports.get(&(tenant, source))?;
            let record = state.records.get(&(tenant, source, ordinal))?;
            super::payload::eligible(current, owner, record, key, payload_digest, now).then(|| record.clone())
        }))
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
        state.payload_sources_live(row, now)?;
        if !state.sources_live(row, now) {
            return Err(invalid("sensitive archive source revoked or changed"));
        }
        let expected = if row.config.format == crawlx_core::archive::ArchiveFormat::Warc {
            "application/warc"
        } else {
            "application/wacz+zip"
        };
        state.artifact(row, artifact, 1, expected, now, row.custody)?;
        if let Some(index) = index {
            state.artifact(row, index, 1, "application/cdxj", now, row.custody)?;
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
        state.publish_payloads(tenant, export);
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
                    && state.exports.get(&(*owner, *export)).is_some_and(|row| {
                        live(row, now)
                            && row.state == ArchiveExportState::Published
                            && row.custody.sensitivity == crawlx_core::repo::Sensitivity::Content
                    })
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
                && state.sources_live(row, now)
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
        state.unindex_payloads(tenant, export);
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
