//! Durable archive catalog, memory parity and fenced PostgreSQL persistence.

mod memory;
mod payload;
mod pg;

use crawlx_core::archive::ArchiveManifestV1;
use crawlx_core::archive_catalog::{
    ArchiveCustodyV1, ArchiveExportState, ArchiveExportV1, ArchiveHistoryKeyV1, ArchiveRecordV1,
};
use crawlx_core::{StoreError, TenantId, Timestamp};

pub(crate) use memory::ArchiveState;

fn scope(tenant: TenantId) -> Result<(), StoreError> {
    if crate::tenant::current().is_some_and(|current| current != tenant) {
        return Err(StoreError::AccessDenied("archive tenant mismatch".into()));
    }
    Ok(())
}
fn invalid(reason: &str) -> StoreError {
    StoreError::Conflict(reason.into())
}
fn pending_bounds(export: &ArchiveExportV1) -> Result<(), StoreError> {
    if export.custody != ArchiveCustodyV1::content(export.expires_at) {
        return Err(invalid("archive intent source authority mismatch"));
    }
    if export.state != ArchiveExportState::Recording
        || export.fence != 0
        || export.records != 0
        || export.bytes != 0
        || export.artifact.is_some()
        || export.index.is_some()
        || export.manifest.is_some()
        || export.failure.is_some()
    {
        return Err(invalid("archive intent must start empty and unpublished"));
    }
    Ok(())
}
fn live(export: &ArchiveExportV1, now: Timestamp) -> bool {
    export.state != ArchiveExportState::Deleted
        && export.expires_at.is_none_or(|expiry| expiry > now)
        && export.custody.validate(now).is_ok()
        && !expires_before(export.custody.expires_at, export.expires_at)
}
fn writer(export: &ArchiveExportV1, fence: i64, now: Timestamp) -> Result<(), StoreError> {
    if !live(export, now)
        || export.state != ArchiveExportState::Recording
        || export.fence != fence
        || export.lease_until <= now
    {
        return Err(StoreError::LeaseLost);
    }
    Ok(())
}
fn expires_before(source: Option<Timestamp>, dependent: Option<Timestamp>) -> bool {
    match (source, dependent) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(source), Some(dependent)) => source < dependent,
    }
}
fn narrowed(
    export: &ArchiveExportV1,
    custody: ArchiveCustodyV1,
    now: Timestamp,
) -> Result<ArchiveCustodyV1, StoreError> {
    export
        .custody
        .narrow(ArchiveCustodyV1::content(export.expires_at), now)?
        .narrow(custody, now)
}

fn artifact_custody(
    class: crawlx_core::repo::Sensitivity,
    expires_at: Option<Timestamp>,
    custody: ArchiveCustodyV1,
    now: Timestamp,
) -> bool {
    custody.validate(now).is_ok()
        && class == custody.sensitivity
        && expires_at.is_none_or(|expiry| expiry > now)
        && (class == crawlx_core::repo::Sensitivity::Content
            || !expires_before(custody.expires_at, expires_at))
}

fn record_bounds(export: &ArchiveExportV1, record: &ArchiveRecordV1) -> Result<(), StoreError> {
    if narrowed(export, record.custody, export.created_at)?
        != export
            .custody
            .narrow(ArchiveCustodyV1::content(export.expires_at), export.created_at)?
    {
        return Err(invalid("archive source authority was not narrowed before commit"));
    }
    if record.export != export.id
        || record.length == 0
        || i64::try_from(record.ordinal).is_err()
        || record.offset.checked_add(record.length).is_none()
        || record.payload_digest.len() != 71
        || !record.payload_digest.starts_with("sha256:")
        || record.target.len() > 8192
        || record.record_id.len() > 256
        || record.facts.redaction_revision.is_empty()
    {
        return Err(invalid("invalid archive record descriptor"));
    }
    if record
        .payload_key
        .as_ref()
        .is_some_and(|key| !payload::key_matches(record, key))
    {
        return Err(invalid("archive payload key mismatches approved representation"));
    }
    if export.records >= u64::from(export.config.max_records)
        || export
            .bytes
            .checked_add(record.length)
            .is_none_or(|bytes| bytes > export.config.max_bytes)
    {
        return Err(invalid("archive record or byte budget exhausted"));
    }
    Ok(())
}
fn publish_bounds(export: &ArchiveExportV1, manifest: &ArchiveManifestV1) -> Result<(), StoreError> {
    if manifest.custody != export.custody
        && (export.custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive
            || manifest.custody != ArchiveCustodyV1::default())
    {
        return Err(invalid("archive manifest byte authority mismatch"));
    }
    if manifest.schema_version != 1
        || manifest.tenant != export.tenant
        || manifest.run != export.run
        || manifest.records != export.records
        || manifest.records == 0
        || manifest.materialized_dependencies > manifest.records
        || manifest.complete
    {
        return Err(invalid(
            "archive manifest mismatches committed incomplete capture",
        ));
    }
    Ok(())
}
fn history_key(key: &ArchiveHistoryKeyV1) -> Result<crawlx_core::hash::Digest, StoreError> {
    if key.target.len() > 8192
        || key.method.is_empty()
        || key.method.len() > 32
        || key.principal.is_empty()
        || key.principal.len() > 256
        || key.variant.is_empty()
        || key.variant.len() > 256
        || key.policy.is_empty()
        || key.policy.len() > 128
    {
        return Err(invalid(
            "archive history requires exact bounded principal and variant",
        ));
    }
    let bytes = serde_json::to_vec(key).map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(crawlx_core::hash::Digest::of("crawlx/archive-history/v1", &bytes))
}
fn json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, StoreError> {
    serde_json::to_value(value).map_err(|error| StoreError::Serialization(error.to_string()))
}
fn decode<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T, StoreError> {
    serde_json::from_value(value).map_err(|error| StoreError::Serialization(error.to_string()))
}
