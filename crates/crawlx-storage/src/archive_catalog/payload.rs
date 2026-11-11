//! Exact payload-reuse custody checks shared by both catalog implementations.

use super::{expires_before, live};
use crawlx_core::archive::{ArchiveDedupe, ArchiveRepresentation};
use crawlx_core::archive_catalog::{
    ArchiveExportState, ArchiveExportV1, ArchivePayloadKeyV1, ArchiveRecordV1,
};
use crawlx_core::Timestamp;

pub(super) fn key_matches(record: &ArchiveRecordV1, key: &ArchivePayloadKeyV1) -> bool {
    !key.principal.is_empty()
        && record.custody.sensitivity == crawlx_core::repo::Sensitivity::Content
        && key.principal.len() <= 256
        && key.representation == record.facts.representation
        && key.redaction_revision == record.facts.redaction_revision
        && key.mime == record.mime
        && matches!(
            (
                record.facts.representation,
                record.facts.capture_source.as_str(),
                record.facts.body_state.as_str()
            ),
            (
                ArchiveRepresentation::ProtocolResource,
                "retained_native_decoded_response_body",
                "complete"
            ) | (
                ArchiveRepresentation::RenderedDom,
                "retained_page_html",
                "unknown"
            ) | (
                ArchiveRepresentation::ExtractedText,
                "retained_page_markdown",
                "unknown"
            )
        )
}

pub(super) fn eligible(
    export: &ArchiveExportV1,
    source: &ArchiveExportV1,
    record: &ArchiveRecordV1,
    key: &ArchivePayloadKeyV1,
    digest: &str,
    now: Timestamp,
) -> bool {
    export.config.dedupe != ArchiveDedupe::None
        && export.state == ArchiveExportState::Recording
        && export.tenant == source.tenant
        && source.custody.sensitivity == crawlx_core::repo::Sensitivity::Content
        && live(export, now)
        && live(source, now)
        && !expires_before(source.expires_at, export.expires_at)
        && record.custody.expires_at.is_none_or(|expiry| expiry > now)
        && !expires_before(record.custody.expires_at, export.expires_at)
        && record.export == source.id
        && record.dependency.is_none()
        && record.payload_digest == digest
        && record.payload_key.as_ref() == Some(key)
        && key_matches(record, key)
        && if source.id == export.id {
            source.state == ArchiveExportState::Recording
        } else {
            export.config.dedupe == ArchiveDedupe::Tenant
                && key.representation == ArchiveRepresentation::ProtocolResource
                && source.config.dedupe == ArchiveDedupe::Tenant
                && source.state == ArchiveExportState::Published
        }
}

/// Ordered source rows for one tenant or one recording export.
pub(super) type Rows = std::collections::BTreeMap<
    String,
    std::collections::BTreeMap<
        crawlx_core::hash::Digest,
        std::collections::BTreeSet<(Timestamp, bool, uuid::Uuid, u64)>,
    >,
>;

pub(super) fn deadline(export: &ArchiveExportV1, record: &ArchiveRecordV1) -> Option<Timestamp> {
    match (export.expires_at, record.custody.expires_at) {
        (Some(export), Some(record)) => Some(export.min(record)),
        (export, record) => export.or(record),
    }
}

fn position(export: &ArchiveExportV1, record: &ArchiveRecordV1) -> (Timestamp, bool, uuid::Uuid, u64) {
    let expiry = deadline(export, record);
    (
        expiry.unwrap_or(Timestamp::MAX_UTC),
        expiry.is_none(),
        record.export,
        record.ordinal,
    )
}

pub(super) fn insert(rows: &mut Rows, export: &ArchiveExportV1, record: &ArchiveRecordV1) {
    let Some(key) = &record.payload_key else {
        return;
    };
    if record.dependency.is_some()
        || !key_matches(record, key)
        || export.custody.sensitivity != crawlx_core::repo::Sensitivity::Content
        || (export.state == ArchiveExportState::Published
            && key.representation != ArchiveRepresentation::ProtocolResource)
    {
        return;
    }
    rows.entry(record.payload_digest.clone())
        .or_default()
        .entry(key.variant)
        .or_default()
        .insert(position(export, record));
}

pub(super) fn remove(rows: &mut Rows, export: &ArchiveExportV1, record: &ArchiveRecordV1) {
    let Some(key) = &record.payload_key else {
        return;
    };
    let Some(scopes) = rows.get_mut(&record.payload_digest) else {
        return;
    };
    if let Some(candidates) = scopes.get_mut(&key.variant) {
        candidates.remove(&position(export, record));
        if candidates.is_empty() {
            scopes.remove(&key.variant);
        }
    }
    if scopes.is_empty() {
        rows.remove(&record.payload_digest);
    }
}

pub(super) fn candidate(
    rows: &Rows,
    export: &ArchiveExportV1,
    key: &ArchivePayloadKeyV1,
    digest: &str,
    now: Timestamp,
) -> Option<(uuid::Uuid, u64)> {
    let active = now.checked_add_signed(chrono::Duration::nanoseconds(1))?;
    let floor = export.expires_at.unwrap_or(Timestamp::MAX_UTC).max(active);
    let (_, _, source, ordinal) = rows
        .get(digest)?
        .get(&key.variant)?
        .range((floor, export.expires_at.is_none(), uuid::Uuid::nil(), 0)..)
        .next()?;
    Some((*source, *ordinal))
}
