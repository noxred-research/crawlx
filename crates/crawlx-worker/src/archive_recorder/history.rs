//! Conditional history only for an owned complete decoded native response, never a DOM rendition.

use super::{approved_target, codec, joined, json};
use crate::WorkerError;
use crawlx_core::archive::ArchiveRepresentation;
use crawlx_core::archive_catalog::{
    ArchiveDependencyV1, ArchiveExportState, ArchiveHistoryKeyV1, ArchiveHistoryV1, ArchiveReadV1,
    ArchiveRecordV1, ArchiveRepo,
};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::QueuedRequestV1;
use crawlx_core::repo::{ArtifactStore, CrawlRun, PageRecord};
use crawlx_core::Timestamp;
use crawlx_fetch::conditional::Validators;
use crawlx_storage::archive::{warc, Limits};
use crawlx_telemetry::redact::Redactor;
use std::io::Cursor;

/// Exact retained validator baseline for the native acquisition coordinator.
pub(crate) struct ArchiveBaseline {
    /// Actual captured validator pair; never inferred from a payload digest.
    pub(crate) validators: Validators,
    /// Approved decoded response bytes, independently of a 304's target status.
    pub(crate) body: Vec<u8>,
    /// Persisted source record for provenance and conditional-revisit dependencies.
    pub(crate) record: ArchiveRecordV1,
    /// Exact captured Vary names, checked again against the 304 response.
    pub(crate) vary: Vec<String>,
}

impl ArchiveBaseline {
    pub(crate) fn matches_response(&self, headers: &http::HeaderMap) -> bool {
        let get = |name| headers.get(name).and_then(|value| value.to_str().ok());
        if get(http::header::ETAG).is_some_and(|etag| self.validators.etag.as_deref() != Some(etag))
            || (self.validators.etag.is_none()
                && get(http::header::LAST_MODIFIED)
                    .is_some_and(|value| self.validators.last_modified.as_deref() != Some(value)))
        {
            return false;
        }
        get(http::header::VARY).is_none_or(|value| vary_names(value).is_some_and(|names| names == self.vary))
    }
}

fn vary_names(value: &str) -> Option<Vec<String>> {
    if value.len() > 2048 {
        return None;
    }
    let mut names = Vec::new();
    for name in value.split(',').map(str::trim) {
        if name.is_empty()
            || name == "*"
            || name.len() > 128
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || names.len() >= 16
        {
            return None;
        }
        names.push(name.to_ascii_lowercase());
    }
    names.sort_unstable();
    names.dedup();
    Some(names)
}

fn key(run: &CrawlRun, request: &QueuedRequestV1, target: &str) -> Result<ArchiveHistoryKeyV1, WorkerError> {
    // Include the entire immutable fetch dialect and scheduler identity, rather than guessing
    // which headers a server varied on. Authentication/session contexts are run-bound.
    let private_context = request.principal != "anonymous"
        || request.envelope.header_control.is_some()
        || request.envelope.session_generation.is_some()
        || !run.config.fetch.cookies.is_empty()
        || !run.config.fetch.extra_headers.is_empty();
    let variant = serde_json::to_vec(&serde_json::json!({
        "run":private_context.then_some(run.id),
        "headerControl":request.envelope.header_control,"sessionGeneration":request.envelope.session_generation,
        "fetch":run.config.fetch,"nativeVersion":env!("CARGO_PKG_VERSION")
    })).map_err(json)?;
    let policy = format!(
        "archive-text-v1:{}:{}",
        run.policy_version, run.config.retention.days
    );
    Ok(ArchiveHistoryKeyV1::new(
        target.into(),
        request.envelope.method.clone(),
        request.principal.clone(),
        Digest::of("crawlx/archive-variant/v1", &variant).to_hex(),
        policy,
    ))
}

pub(super) fn captured_history(
    run: &CrawlRun,
    request: &QueuedRequestV1,
    page: &PageRecord,
    record: &ArchiveRecordV1,
) -> Result<Option<ArchiveHistoryV1>, WorkerError> {
    if request.envelope.method != "GET"
        || request.envelope.body.is_some()
        || !(200..300).contains(&page.status)
        || record.facts.body_state != "complete"
        || record.facts.representation != ArchiveRepresentation::ProtocolResource
        || record.facts.capture_source != "retained_native_decoded_response_body"
    {
        return Ok(None);
    }
    let Some(headers) = page
        .metadata
        .get("response_headers")
        .and_then(serde_json::Value::as_object)
    else {
        return Ok(None);
    };
    let header = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .and_then(|(_, value)| value.as_str())
    };
    let vary = match header("vary") {
        None => Vec::new(),
        Some(value) => match vary_names(value) {
            Some(names) => names,
            None => return Ok(None),
        },
    };
    let approved = |name: &str| {
        header(name)
            .filter(|value| {
                value.len() <= 1024
                    && !value.contains(['\r', '\n'])
                    && Redactor::new().is_clean_text(value)
                    && !value.contains("[redacted]")
                    && !value.contains("[REDACTED]")
            })
            .map(str::to_owned)
    };
    let etag = approved("etag");
    let last_modified = approved("last-modified");
    if etag.is_none() && last_modified.is_none() {
        return Ok(None);
    }
    let mut history = ArchiveHistoryV1::new(
        key(run, request, &record.target)?,
        ArchiveDependencyV1::new(record.export, record.ordinal),
        etag,
        last_modified,
        page.fetched_at,
    );
    history.vary = vary;
    Ok(Some(history))
}

/// Resolve a complete validator-compatible archived response without any live re-request.
/// Returns no baseline for non-GET, missing principal/session variants, DOM-only captures,
/// expiry, failed/deleted publication or absent validators.
///
/// # Errors
/// Returns storage, approved-body bound, framing or digest errors; never downgrades integrity failures.
pub(crate) async fn conditional_baseline(
    archives: &dyn ArchiveRepo,
    artifacts: &dyn ArtifactStore,
    run: &CrawlRun,
    request: &QueuedRequestV1,
    now: Timestamp,
    max_bytes: u64,
) -> Result<Option<ArchiveBaseline>, WorkerError> {
    if run.config.retention.mode == crawlx_core::config::RetentionMode::Zdr
        || request.envelope.method != "GET"
        || request.envelope.body.is_some()
        || request.identity.revisit_generation == 0
    {
        return Ok(None);
    }
    let target = approved_target(request.envelope.url.url.as_str())?;
    let Some(history) = archives
        .history(run.tenant, &key(run, request, &target)?, now)
        .await?
    else {
        return Ok(None);
    };
    let source = match archives.get(run.tenant, history.source.export, now).await? {
        ArchiveReadV1::Available(source) if source.state == ArchiveExportState::Published => source,
        _ => return Ok(None),
    };
    let mut rows = archives
        .records(
            run.tenant,
            source.id,
            history.source.ordinal.checked_sub(1),
            1,
            now,
        )
        .await?;
    let Some(record) = rows.pop().filter(|row| row.ordinal == history.source.ordinal) else {
        return Ok(None);
    };
    if record.dependency.is_some()
        || record.target != target
        || record.facts.body_state != "complete"
        || record.facts.representation != ArchiveRepresentation::ProtocolResource
        || record.facts.capture_source != "retained_native_decoded_response_body"
    {
        return Ok(None);
    }
    let mut limits = Limits::default();
    limits.record_bytes = source.config.max_record_bytes.min(max_bytes);
    limits.total_bytes = limits.record_bytes.saturating_add(131_072);
    let bytes = artifacts
        .read_archive_content(run.tenant, source.run, &record.artifact, limits.total_bytes)
        .await?;
    let expected = record.clone();
    let body = tokio::task::spawn_blocking(move || {
        let (summary, body) = warc::read_member(Cursor::new(bytes), limits)?;
        if summary.id != expected.record_id
            || summary.payload_digest != expected.payload_digest
            || summary.length != expected.length
            || summary.target.as_deref() != Some(expected.target.as_str())
            || !std::str::from_utf8(&body).is_ok_and(|text| Redactor::new().is_clean_text(text))
        {
            return Err(crawlx_storage::archive::ArchiveError::Invalid(
                "conditional baseline catalog or privacy mismatch",
            ));
        }
        Ok::<_, crawlx_storage::archive::ArchiveError>(body)
    })
    .await
    .map_err(joined)?
    .map_err(codec)?;
    Ok(Some(ArchiveBaseline {
        validators: Validators {
            etag: history.etag,
            last_modified: history.last_modified,
        },
        body,
        record,
        vary: history.vary,
    }))
}
