//! Rebuilt HTTP messages and protocol facts for archived wire evidence.
//!
//! The persisted source rarely holds original wire bytes: an HTTP/2 response was never an
//! HTTP/1.1 message. The records written here are therefore always labelled as normalized
//! messages (`ArchiveRepresentation::NormalizedHttp`) that name the protocol actually
//! observed. Anything the source did not record (status, headers, protocol, method) stays
//! absent: the record is omitted with a reason instead of being filled in.
//!
//! Credentials never enter a message: headers with a sensitive name are dropped, framing headers are rebuilt or dropped, and the finished message must pass
//! the same fail-closed privacy gate as every other archived byte.

use super::resource::{RecordOutcome, Recorder};
use super::{codec, identifier, joined, json, limits, stopped};
use crate::WorkerError;
use crawlx_core::archive::{ArchiveCaptureFactsV1, ArchiveTlsFactsV1};
use crawlx_core::archive_catalog::{ArchiveCustodyV1, ArchiveReadV1, ArchiveRecordV1};
use crawlx_core::custody::FrozenArchiveSource;
use crawlx_core::traffic::Protocol;
use crawlx_core::ArtifactRef;
use crawlx_storage::archive::{staging::StagedFile, warc, ArchiveError};
use crawlx_storage::custody::frozen_archive::with_terminal_grant;
use crawlx_telemetry::redact::Redactor;
use std::collections::BTreeMap;
use std::io::Cursor;

/// Reserved evidence header the fetch plane attaches to every live response.
const EVIDENCE_HEADER: &str = "x-crawlx-stream-evidence";

/// Header names that describe framing or the hop, never the representation. Framing is rebuilt
/// from the stored body; hop-by-hop fields have no meaning in an archived message.
fn dropped(name: &str) -> bool {
    matches!(
        name,
        "content-length"
            | "transfer-encoding"
            | "connection"
            | "keep-alive"
            | "upgrade"
            | "te"
            | "trailer"
            | "proxy-connection"
            | "proxy-authenticate"
    ) || name.starts_with(':')
        || name.starts_with("x-crawlx-")
}

fn token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// Whether a media type may appear in an archived message (the same text-only policy the
/// package reader applies on import).
fn textual(media_type: &str) -> bool {
    warc::is_text_media_type(media_type)
}

fn media_type(value: &str) -> &str {
    value.split(';').next().unwrap_or("").trim()
}

/// Normalized, credential-free header lines: `(name, value)` in input order.
///
/// Invalid names (pseudo headers, non-token names), empty values and control characters are
/// skipped, as are headers with a sensitive name.
fn clean_headers<'a>(
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    keep_content_type: bool,
) -> Vec<(String, String)> {
    let redactor = Redactor::new();
    headers
        .into_iter()
        .filter_map(|(name, value)| {
            let lower = name.to_ascii_lowercase();
            let value = value.trim();
            if dropped(&lower) || !token(&lower) || value.is_empty() || value.chars().any(char::is_control) {
                return None;
            }
            if lower == "content-type" && !keep_content_type && !textual(media_type(value)) {
                return None;
            }
            // A credential-named field is dropped outright: even a placeholder value trips the
            // archive's own secret rules (`name: value` pairs), and the name alone is not evidence.
            if redactor.is_sensitive_name(&lower) {
                return None;
            }
            Some((lower, value.to_owned()))
        })
        .collect()
}

fn finish(mut head: String, headers: &[(String, String)]) -> Result<Vec<u8>, &'static str> {
    for (name, value) in headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    // Fail closed: a message that still trips a secret rule, by the writer's gate or the
    // package reader's, is never archived.
    let redactor = Redactor::new();
    if redactor.is_clean_text(&head)
        && redactor.scrub(&head) == head
        && redactor.scrub_session_queries(&head) == head
    {
        Ok(head.into_bytes())
    } else {
        Err("wire_message_privacy_gate_failed")
    }
}

/// A normalized HTTP request message with no body (the body is its own record).
///
/// # Errors
/// Names the reason the message cannot be written truthfully.
pub(super) fn request_message(
    method: Option<&str>,
    target: &str,
    headers: &[(String, String)],
) -> Result<Vec<u8>, &'static str> {
    let method = method.ok_or("request_method_not_recorded")?;
    if method.is_empty()
        || !method
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte == b'-')
    {
        return Err("request_method_not_recorded");
    }
    let url = url::Url::parse(target).map_err(|_| "request_target_unavailable")?;
    let mut path = url.path().to_owned();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    let headers = clean_headers(
        headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
        false,
    );
    finish(format!("{method} {path} HTTP/1.1\r\n"), &headers)
}

/// The `application/warc-fields` block of a protocol-version record.
pub(super) fn protocol_fields(protocol: Protocol, source_event: &str) -> Vec<u8> {
    format!(
        "protocol: {}\r\nsource-event: {source_event}\r\nrepresentation: normalized_http\r\n",
        protocol.as_str()
    )
    .into_bytes()
}

/// What the page's persisted acquisition receipt says about the response it archived.
#[derive(Clone, Debug)]
pub(super) struct ResponseWire {
    status: u16,
    protocol: Option<Protocol>,
    headers: Vec<(String, String)>,
}

impl ResponseWire {
    /// Read the receipt of a native acquisition. `Ok(None)` when the receipt never recorded a
    /// status or response headers: there is then no message to present at all.
    ///
    /// # Errors
    /// Names the unsafe fact; a recorded response that cannot be presented truthfully is
    /// omitted by reason.
    pub(super) fn from_page(metadata: &serde_json::Value) -> Result<Option<Self>, &'static str> {
        let Some(status) = metadata
            .pointer("/acquisition/targetStatus")
            .and_then(serde_json::Value::as_u64)
            .and_then(|status| u16::try_from(status).ok())
            .filter(|status| (100..=599).contains(status))
        else {
            return Ok(None);
        };
        let Some(recorded) = metadata
            .get("response_headers")
            .and_then(serde_json::Value::as_object)
        else {
            return Ok(None);
        };
        let evidence: Option<serde_json::Value> = recorded
            .get(EVIDENCE_HEADER)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| serde_json::from_str(text).ok());
        let decoded = evidence
            .as_ref()
            .and_then(|evidence| evidence.pointer("/body/decoded"))
            .and_then(serde_json::Value::as_bool);
        let mut pairs = Vec::with_capacity(recorded.len());
        for (name, value) in recorded {
            let Some(value) = value.as_str() else {
                continue;
            };
            if name.eq_ignore_ascii_case("content-encoding") {
                // The stored body is the decoded representation. A coding is only dropped when
                // the fetch plane says it removed it; an unverified coding refuses the message.
                let identity = value.trim().is_empty() || value.trim().eq_ignore_ascii_case("identity");
                match (identity, decoded) {
                    (true, _) | (false, Some(true)) => continue,
                    (false, _) => return Err("normalized_http_content_coding_not_decoded"),
                }
            }
            pairs.push((name.as_str(), value));
        }
        let headers = clean_headers(pairs, true);
        Ok(Some(Self {
            status,
            protocol: metadata
                .pointer("/acquisition/connection/negotiatedProtocol")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok()),
            headers,
        }))
    }

    /// Observed application protocol, when the receipt has one.
    pub(super) fn protocol(&self) -> Option<Protocol> {
        self.protocol
    }

    /// Status line and headers with a rebuilt `Content-Length` for a decoded body of
    /// `body_len` bytes.
    fn head(&self, body_len: u64) -> Result<Vec<u8>, &'static str> {
        let media = self
            .headers
            .iter()
            .find(|(name, _)| name == "content-type")
            .map(|(_, value)| media_type(value))
            .ok_or("normalized_http_media_type_not_text")?;
        if !textual(media) {
            return Err("normalized_http_media_type_not_text");
        }
        let mut headers = self.headers.clone();
        headers.push(("content-length".into(), body_len.to_string()));
        let status =
            http::StatusCode::from_u16(self.status).map_err(|_| "normalized_http_status_not_recorded")?;
        let line = match status.canonical_reason() {
            Some(reason) => format!("HTTP/1.1 {} {reason}\r\n", self.status),
            None => format!("HTTP/1.1 {}\r\n", self.status),
        };
        finish(line, &headers)
    }
}

/// Wire facts of the page's own acquisition for the retained body record: observed protocol,
/// true status and the TLS facts of the request's own connection. Absent stays absent.
pub(super) fn source_wire(
    metadata: &serde_json::Value,
) -> (Option<Protocol>, Option<u16>, Option<ArchiveTlsFactsV1>) {
    let protocol = metadata
        .pointer("/acquisition/connection/negotiatedProtocol")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    let status = metadata
        .pointer("/acquisition/targetStatus")
        .and_then(serde_json::Value::as_u64)
        .and_then(|status| u16::try_from(status).ok());
    let verification = metadata
        .pointer("/acquisition/connection/tlsVerification")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let certificate = metadata
        .pointer("/acquisition/connection/certificate")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok());
    let tls = (verification.is_some() || certificate.is_some())
        .then(|| ArchiveTlsFactsV1::new(verification, certificate));
    (protocol, status, tls)
}

/// Content of one wire record.
pub(super) enum WireContent<'a> {
    /// A retained decoded body behind a rebuilt response head. `expected_len` is the decoded
    /// size the receipt recorded; a different stored size refuses the message.
    Response {
        source: &'a ArtifactRef,
        wire: &'a ResponseWire,
        expected_len: Option<u64>,
    },
    /// A fully rebuilt message with no retained source. `payload_offset` is the HTTP payload
    /// start. A terminal run needs `authority`, a retained artifact of the same event, to
    /// bind the frozen grant; without one the record is omitted.
    Rebuilt {
        block: Vec<u8>,
        payload_offset: u64,
        authority: Option<&'a ArtifactRef>,
    },
}

/// One request/response/metadata WARC record to commit.
pub(super) struct WireInput<'a> {
    pub ordinal: u64,
    pub warc_type: &'static str,
    pub target: &'a str,
    pub media_type: &'static str,
    pub protocol: Option<Protocol>,
    pub facts: ArchiveCaptureFactsV1,
    pub content: WireContent<'a>,
}

impl Recorder<'_> {
    /// Commit one wire record: shard first, catalog row second, exactly like resources.
    pub(super) async fn record_wire(&mut self, input: WireInput<'_>) -> Result<RecordOutcome, WorkerError> {
        if self.cancel.is_cancelled() {
            return Err(stopped());
        }
        let existing = self
            .stores
            .archives
            .records(
                self.run.tenant,
                self.export.id,
                input.ordinal.checked_sub(1),
                1,
                self.clock.now(),
            )
            .await?;
        if existing.first().is_some_and(|row| row.ordinal == input.ordinal) {
            return Ok(RecordOutcome::Existing);
        }
        let terminal = super::run_is_terminal(self.stores, self.run.id).await?;
        let (block, payload_offset, custody, sources) = match input.content {
            WireContent::Response {
                source,
                wire,
                expected_len,
            } => {
                let custody = match self
                    .stores
                    .artifacts
                    .archive_custody(
                        self.run.tenant,
                        self.run.id,
                        source,
                        self.export.config.max_record_bytes,
                    )
                    .await
                {
                    Ok(custody) => custody,
                    Err(
                        crawlx_core::StoreError::NotFound { .. }
                        | crawlx_core::StoreError::RetentionDenied(_),
                    ) => {
                        return Ok(RecordOutcome::Omitted(
                            "retained_body_missing_expired_or_disallowed",
                        ))
                    }
                    Err(error) => return Err(error.into()),
                };
                if custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive {
                    return Ok(RecordOutcome::Omitted(
                        "sensitive_capture_not_approved_for_archive",
                    ));
                }
                self.stores
                    .archives
                    .narrow_custody(
                        self.run.tenant,
                        self.export.id,
                        self.export.fence,
                        &custody,
                        self.clock.now(),
                    )
                    .await?;
                let body = match self
                    .stores
                    .artifacts
                    .read_archive_content(
                        self.run.tenant,
                        self.run.id,
                        source,
                        self.export.config.max_record_bytes,
                    )
                    .await
                {
                    Ok(body) => body,
                    Err(
                        crawlx_core::StoreError::NotFound { .. }
                        | crawlx_core::StoreError::RetentionDenied(_),
                    ) => {
                        return Ok(RecordOutcome::Omitted(
                            "retained_body_missing_expired_or_disallowed",
                        ))
                    }
                    Err(error) => return Err(error.into()),
                };
                let length =
                    u64::try_from(body.len()).map_err(|_| WorkerError::Config("body length".into()))?;
                if expected_len != Some(length) {
                    return Ok(RecordOutcome::Omitted("normalized_http_body_length_unverified"));
                }
                if !std::str::from_utf8(&body).is_ok_and(|text| Redactor::new().is_clean_text(text)) {
                    return Ok(RecordOutcome::Omitted(
                        "body_privacy_or_binary_capability_unavailable",
                    ));
                }
                let head = match wire.head(length) {
                    Ok(head) => head,
                    Err(reason) => return Ok(RecordOutcome::Omitted(reason)),
                };
                let offset =
                    u64::try_from(head.len()).map_err(|_| WorkerError::Config("head length".into()))?;
                let mut block = head;
                block.extend_from_slice(&body);
                (
                    block,
                    offset,
                    custody,
                    vec![FrozenArchiveSource::new(source.clone(), custody)],
                )
            }
            WireContent::Rebuilt {
                block,
                payload_offset,
                authority,
            } => {
                let ArchiveReadV1::Available(current) = self
                    .stores
                    .archives
                    .get(self.run.tenant, self.export.id, self.clock.now())
                    .await?
                else {
                    return Err(WorkerError::Config(
                        "archive custody disappeared during finalization".into(),
                    ));
                };
                // A rebuilt message holds only redacted facts of the persisted event: it is
                // ordinary content and never outlives the export's own source deadline.
                let custody = ArchiveCustodyV1::content(current.custody.expires_at.or(current.expires_at));
                let sources = match (terminal, authority) {
                    (false, _) => Vec::new(),
                    (true, Some(authority)) => {
                        let source_custody = match self
                            .stores
                            .artifacts
                            .archive_custody(
                                self.run.tenant,
                                self.run.id,
                                authority,
                                self.export.config.max_record_bytes,
                            )
                            .await
                        {
                            Ok(custody) => custody,
                            Err(
                                crawlx_core::StoreError::NotFound { .. }
                                | crawlx_core::StoreError::RetentionDenied(_),
                            ) => {
                                return Ok(RecordOutcome::Omitted(
                                    "retained_body_missing_expired_or_disallowed",
                                ))
                            }
                            Err(error) => return Err(error.into()),
                        };
                        if source_custody.sensitivity == crawlx_core::repo::Sensitivity::Sensitive {
                            return Ok(RecordOutcome::Omitted(
                                "sensitive_capture_not_approved_for_archive",
                            ));
                        }
                        vec![FrozenArchiveSource::new(authority.clone(), source_custody)]
                    }
                    (true, None) => {
                        return Ok(RecordOutcome::Omitted(
                            "terminal_run_wire_record_requires_retained_authority",
                        ))
                    }
                };
                (block, payload_offset, custody, sources)
            }
        };
        let mut fields = BTreeMap::from([
            ("WARC-Type".to_owned(), input.warc_type.to_owned()),
            ("WARC-Record-ID".into(), identifier(self.export, input.ordinal)),
            ("WARC-Date".into(), warc::date(input.facts.captured_at)),
            ("WARC-Target-URI".into(), input.target.into()),
            ("Content-Type".into(), input.media_type.into()),
            (
                "Crawlx-Capture-Facts".into(),
                serde_json::to_string(&input.facts).map_err(json)?,
            ),
        ]);
        if let Some(protocol) = input.protocol {
            fields.insert("WARC-Protocol".into(), protocol.as_str().into());
        }
        let header = warc::RecordHeader {
            payload_offset,
            fields,
        };
        let mut codec_limits = limits(self.export);
        codec_limits.total_bytes = self.export.config.max_record_bytes.saturating_add(131_072);
        let stop = self.cancel.clone();
        let (summary, shard) = tokio::task::spawn_blocking(move || {
            if stop.is_cancelled() {
                return Err(ArchiveError::Invalid("archive cancelled"));
            }
            let length = u64::try_from(block.len()).map_err(|_| ArchiveError::Limit("record bytes"))?;
            let mut output = StagedFile::new()?;
            let summary = warc::write_record(
                output.file_mut(),
                &header,
                &mut Cursor::new(block),
                length,
                codec_limits,
            )?;
            output.file().sync_all()?;
            Ok::<_, ArchiveError>((summary, output))
        })
        .await
        .map_err(joined)?
        .map_err(codec)?;
        let reserve = (self.export.config.max_bytes / 8).min(4_194_304);
        if self
            .committed_bytes
            .checked_add(summary.length)
            .is_none_or(|bytes| bytes > self.export.config.max_bytes.saturating_sub(reserve))
        {
            return Ok(RecordOutcome::Omitted("remaining_encoded_archive_byte_budget"));
        }
        let artifact = tokio::select! {
            biased;
            () = self.cancel.cancelled() => return Err(stopped()),
            result = with_terminal_grant(
                self.stores.custody.as_deref(),
                terminal,
                self.export,
                &custody,
                sources,
                self.stores.artifacts.put_archive_file_with_custody(self.run.id, "application/warc", shard.path(),
                    self.export.config.max_record_bytes.saturating_add(131_072), &custody),
            ) => result??,
        };
        let mut record = ArchiveRecordV1::resource(
            self.export.id,
            input.ordinal,
            summary.id,
            artifact,
            summary.offset,
            summary.length,
            summary.payload_digest,
            input.target.into(),
            input.facts,
            input.media_type.into(),
        );
        record.custody = custody;
        self.stores
            .archives
            .commit_record(
                self.run.tenant,
                self.export.fence,
                &record,
                None,
                self.clock.now(),
            )
            .await?;
        self.committed_bytes = self
            .committed_bytes
            .checked_add(record.length)
            .ok_or_else(|| WorkerError::Config("archive byte counter overflow".into()))?;
        Ok(RecordOutcome::Committed)
    }
}

fn traffic_ordinal(event_id: u64, slot: u64) -> Result<u64, WorkerError> {
    event_id
        .checked_mul(8)
        .and_then(|id| id.checked_add(4))
        .and_then(|id| id.checked_add(slot))
        .filter(|id| i64::try_from(*id).is_ok())
        .ok_or_else(|| WorkerError::Config("archive traffic ordinal overflow".into()))
}

fn wire_facts(
    event: String,
    captured_at: crawlx_core::Timestamp,
    representation: crawlx_core::archive::ArchiveRepresentation,
    source: &str,
    body_state: &str,
    transformations: &[&str],
) -> ArchiveCaptureFactsV1 {
    let mut facts = ArchiveCaptureFactsV1::retained(event, captured_at, representation, source);
    facts.body_state = body_state.into();
    facts.redaction_revision = "archive-wire-v1".into();
    facts.transformations = transformations.iter().map(|value| (*value).to_owned()).collect();
    facts
}

fn tally(
    outcome: RecordOutcome,
    event: String,
    manifest: &mut crawlx_core::archive::ArchiveManifestV1,
    committed_records: &mut u64,
) {
    match outcome {
        RecordOutcome::Existing | RecordOutcome::Committed => {
            *committed_records = committed_records.saturating_add(1);
        }
        RecordOutcome::Omitted(reason) => manifest
            .omissions
            .push(crawlx_core::archive::ArchiveOmissionV1::new(event, reason)),
    }
}

/// Request-header and protocol-version records of one journal event, each separate from the
/// body records, with the credentials of the headers redacted. An event that recorded no
/// headers or no protocol yields an omission or no record, never an invented one.
pub(super) async fn record_traffic(
    recorder: &mut Recorder<'_>,
    manifest: &mut crawlx_core::archive::ArchiveManifestV1,
    committed_records: &mut u64,
    traffic: &crawlx_core::archive_catalog::ArchiveTrafficV1,
    target: &str,
) -> Result<(), WorkerError> {
    use crawlx_core::archive::ArchiveRepresentation;
    let max = u64::from(recorder.export.config.max_records);
    let authority = traffic.response_body.as_ref().or(traffic.request_body.as_ref());
    if *committed_records < max {
        let event = format!("traffic:{}:request_headers", traffic.event_id);
        let message = match traffic.request_headers.as_deref() {
            None => Err("request_headers_not_recorded"),
            Some(headers) => request_message(traffic.method.as_deref(), target, headers),
        };
        match message {
            Err(reason) => manifest
                .omissions
                .push(crawlx_core::archive::ArchiveOmissionV1::new(event, reason)),
            Ok(block) => {
                let payload_offset =
                    u64::try_from(block.len()).map_err(|_| WorkerError::Config("request length".into()))?;
                let facts = wire_facts(
                    event.clone(),
                    traffic.captured_at,
                    ArchiveRepresentation::NormalizedHttp,
                    "retained_journal_request_headers",
                    "headers_only",
                    &[
                        "normalized_http_message_not_original_wire",
                        "framing_headers_omitted",
                        "secret_and_session_redaction",
                    ],
                )
                .with_source_wire(traffic.protocol, None, None);
                let outcome = recorder
                    .record_wire(WireInput {
                        ordinal: traffic_ordinal(traffic.event_id, 2)?,
                        warc_type: "request",
                        target,
                        media_type: "application/http; msgtype=request",
                        protocol: traffic.protocol,
                        facts,
                        content: WireContent::Rebuilt {
                            block,
                            payload_offset,
                            authority,
                        },
                    })
                    .await?;
                tally(outcome, event, manifest, committed_records);
            }
        }
    }
    if let Some(protocol) = traffic.protocol {
        if *committed_records < max {
            let event = format!("traffic:{}:protocol", traffic.event_id);
            let facts = wire_facts(
                event.clone(),
                traffic.captured_at,
                ArchiveRepresentation::ProtocolResource,
                "retained_journal_protocol",
                "complete",
                &["observed_protocol_fact"],
            )
            .with_source_wire(Some(protocol), None, None);
            let outcome = recorder
                .record_wire(WireInput {
                    ordinal: traffic_ordinal(traffic.event_id, 3)?,
                    warc_type: "resource",
                    target,
                    media_type: "application/warc-fields",
                    protocol: Some(protocol),
                    facts,
                    content: WireContent::Rebuilt {
                        block: protocol_fields(protocol, &format!("traffic:{}", traffic.event_id)),
                        payload_offset: 0,
                        authority,
                    },
                })
                .await?;
            tally(outcome, event, manifest, committed_records);
        }
    }
    Ok(())
}

/// The normalized response message of a natively fetched page: true status, observed
/// protocol and TLS facts, headers and the retained decoded body. Browser-rendered pages have
/// no such message, and a page whose receipt lacks a required fact is omitted by reason.
pub(super) async fn record_page_response(
    recorder: &mut Recorder<'_>,
    manifest: &mut crawlx_core::archive::ArchiveManifestV1,
    committed_records: &mut u64,
    page: &crawlx_core::repo::PageRecord,
    source: Option<&ArtifactRef>,
    target: &str,
) -> Result<(), WorkerError> {
    let native = page
        .metadata
        .pointer("/acquisition/backend/backendId")
        .and_then(serde_json::Value::as_str)
        == Some("native_http");
    let Some(source) = source.filter(|_| native) else {
        return Ok(());
    };
    if *committed_records >= u64::from(recorder.export.config.max_records) {
        return Ok(());
    }
    let event = format!("page:{}:http_response", page.frontier_id);
    let complete = recorder.run.config.capture.response_bodies == crawlx_core::config::ResponseBodies::Full
        && page
            .metadata
            .pointer("/acquisition/truncated")
            .and_then(serde_json::Value::as_bool)
            == Some(false);
    let wire = match ResponseWire::from_page(&page.metadata) {
        // The receipt never recorded a status or headers: there is no message to present.
        Ok(None) => return Ok(()),
        Ok(Some(wire)) if complete => wire,
        Ok(Some(_)) => {
            manifest
                .omissions
                .push(crawlx_core::archive::ArchiveOmissionV1::new(
                    event,
                    "normalized_http_requires_complete_decoded_body",
                ));
            return Ok(());
        }
        Err(reason) => {
            manifest
                .omissions
                .push(crawlx_core::archive::ArchiveOmissionV1::new(event, reason));
            return Ok(());
        }
    };
    let ordinal = u64::try_from(page.frontier_id)
        .ok()
        .and_then(|id| id.checked_mul(8))
        .and_then(|id| id.checked_add(3))
        .filter(|id| i64::try_from(*id).is_ok())
        .ok_or_else(|| WorkerError::Config("archive event ordinal overflow".into()))?;
    let (protocol, status, tls) = source_wire(&page.metadata);
    let facts = wire_facts(
        event.clone(),
        page.fetched_at,
        crawlx_core::archive::ArchiveRepresentation::NormalizedHttp,
        "retained_native_normalized_response",
        "complete",
        &[
            "normalized_http_message_not_original_wire",
            "decoded_body_not_original_wire",
            "framing_headers_rebuilt",
            "secret_and_session_redaction",
        ],
    )
    .with_source_wire(protocol, status, tls);
    let expected_len = page
        .metadata
        .pointer("/acquisition/decodedBytes")
        .and_then(serde_json::Value::as_u64);
    let outcome = recorder
        .record_wire(WireInput {
            ordinal,
            warc_type: "response",
            target,
            media_type: "application/http; msgtype=response",
            protocol: wire.protocol(),
            facts,
            content: WireContent::Response {
                source,
                wire: &wire,
                expected_len,
            },
        })
        .await?;
    tally(outcome, event, manifest, committed_records);
    Ok(())
}
