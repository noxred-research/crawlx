//! Content-only payload reuse; browser renditions stay run-bound and history stays target-bound.

use crate::WorkerError;
use crawlx_core::archive::{ArchiveCaptureFactsV1, ArchiveDedupe, ArchiveRepresentation};
use crawlx_core::archive_catalog::ArchivePayloadKeyV1;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::QueuedRequestV1;
use crawlx_core::repo::{CrawlRun, PageRecord};

pub(super) fn key(
    run: &CrawlRun,
    request: &QueuedRequestV1,
    page: &PageRecord,
    facts: &ArchiveCaptureFactsV1,
    mime: &str,
) -> Result<Option<ArchivePayloadKeyV1>, WorkerError> {
    let native = facts.representation == ArchiveRepresentation::ProtocolResource
        && facts.capture_source == "retained_native_decoded_response_body"
        && facts.body_state == "complete";
    let rendition = matches!(
        (facts.representation, facts.capture_source.as_str()),
        (ArchiveRepresentation::RenderedDom, "retained_page_html")
            | (ArchiveRepresentation::ExtractedText, "retained_page_markdown")
    ) && facts.body_state == "unknown";
    if run
        .config
        .output
        .archive
        .as_ref()
        .is_none_or(|config| config.dedupe == ArchiveDedupe::None)
        || request.envelope.method != "GET"
        || request.envelope.body.is_some()
        || !(200..300).contains(&page.status)
        || page.status == 206
        || (!native && !rendition)
    {
        return Ok(None);
    }
    let headers = page
        .metadata
        .get("response_headers")
        .and_then(serde_json::Value::as_object);
    if native && headers.is_none() {
        return Ok(None);
    }
    let header = |name: &str| {
        headers
            .and_then(|headers| headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)))
            .map(|(_, value)| value)
    };
    if header("content-range").is_some() {
        return Ok(None);
    }
    let vary = match header("vary") {
        None => Vec::new(),
        Some(value) => match value.as_str().and_then(super::history::vary_names) {
            Some(names) => names,
            None => return Ok(None),
        },
    };
    let base = super::history::key(run, request, page.url.url.as_str())?;
    // Full immutable request controls cover configured and scheduler-owned header values.
    // Vary additionally binds origin; unknown/wildcard contexts are never reused.
    let variant = serde_json::to_vec(&serde_json::json!({
        "requestVariant":base.variant,"policy":base.policy,"method":base.method,
        "principal":request.principal,"representation":facts.representation,
        "redactionRevision":facts.redaction_revision,"mime":mime,
        "authorizationRecord":run.config.safety.authorization_record_ref,
        "retention":run.config.retention,
        "vary":vary,"varyOrigin":(!vary.is_empty()).then(|| page.url.url.origin().ascii_serialization()),
        "sourceProtocol":facts.source_protocol,"captureSource":facts.capture_source,
        "transformations":facts.transformations,"bodyState":facts.body_state,
        // Stored renditions make no claim about original wire completeness or cross-run sessions.
        "browserContext":rendition.then(|| serde_json::json!({
            "run":run.id,"origin":page.url.url.origin().ascii_serialization(),
            "dynamic":run.config.dynamic,"capture":run.config.capture,"extract":run.config.extract,
            "backend":page.metadata.pointer("/acquisition/backend"),
        })),
    }))
    .map_err(super::json)?;
    Ok(Some(ArchivePayloadKeyV1::new(
        request.principal.clone(),
        Digest::of("crawlx/archive-payload-scope/v1", &variant),
        facts,
        mime.into(),
    )))
}

pub(super) async fn dependency(
    stores: &crate::Stores,
    export: &crawlx_core::archive_catalog::ArchiveExportV1,
    record: &crawlx_core::archive_catalog::ArchiveRecordV1,
    now: crawlx_core::Timestamp,
) -> Result<
    Option<(
        crawlx_core::CrawlRunId,
        crawlx_core::archive_catalog::ArchiveRecordV1,
    )>,
    WorkerError,
> {
    use crawlx_core::archive_catalog::{ArchiveExportState, ArchiveReadV1};
    let Some(dependency) = record
        .dependency
        .as_ref()
        .filter(|source| source.export != export.id)
    else {
        return Ok(None);
    };
    let ArchiveReadV1::Available(source) = stores.archives.get(export.tenant, dependency.export, now).await?
    else {
        return Err(super::codec(crawlx_storage::archive::ArchiveError::Invalid(
            "archive dependency unavailable",
        )));
    };
    if source.state != ArchiveExportState::Published {
        return Err(super::codec(crawlx_storage::archive::ArchiveError::Invalid(
            "archive dependency unpublished",
        )));
    }
    let baseline = stores
        .archives
        .records(
            export.tenant,
            source.id,
            dependency.ordinal.checked_sub(1),
            1,
            now,
        )
        .await?
        .pop()
        .filter(|baseline| baseline.ordinal == dependency.ordinal);
    let Some(baseline) = baseline else {
        return Err(super::codec(crawlx_storage::archive::ArchiveError::Invalid(
            "archive dependency record unavailable",
        )));
    };
    if baseline.dependency.is_some()
        || baseline.payload_digest != record.payload_digest
        || (record.payload_key.is_some() && baseline.payload_key != record.payload_key)
        || baseline.custody.sensitivity != crawlx_core::repo::Sensitivity::Content
    {
        return Err(super::codec(crawlx_storage::archive::ArchiveError::Invalid(
            "archive dependency scope mismatch",
        )));
    }
    Ok(Some((source.run, baseline)))
}
