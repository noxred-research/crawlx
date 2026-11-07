//! WARC 1.1 exact framing and record-at-a-time gzip. Based only on the IIPC normative format.

use super::{ArchiveError, Limits};
use chrono::{DateTime, SecondsFormat, Utc};
use flate2::{bufread::GzDecoder, Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};

/// A classified record; unknown types remain data, never executable behavior.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordSummary {
    /// WARC-Record-ID, including angle brackets.
    pub id: String,
    /// Lowercase record type. Unrecognized values are retained here.
    pub record_type: String,
    /// Whether the type is defined by WARC 1.1.
    pub known_type: bool,
    /// Truthful WARC-Date.
    pub date: DateTime<Utc>,
    /// Target URI when present.
    pub target: Option<String>,
    /// Stored payload MIME type.
    pub mime: String,
    /// Actual recorded response status, absent for resources and unknown records.
    pub status: Option<u16>,
    /// SHA-256 digest of the stored payload.
    pub payload_digest: String,
    /// First byte of this record's gzip member (or uncompressed record).
    pub offset: u64,
    /// Actual encoded member/record length.
    pub length: u64,
    /// Offset of payload inside the uncompressed record block.
    pub payload_offset: u64,
    /// Length of the uncompressed block.
    pub block_length: u64,
    /// Exact expanded record bytes, including WARC headers and terminator.
    pub uncompressed_length: u64,
    /// Relationship targets to resolve after the complete input is read.
    pub dependencies: Vec<String>,
    /// Whether text-only import may retain this record without weakening the privacy gate.
    /// False for binary blocks, detected secret shapes, session parameters or credential fields.
    pub retention_approved: bool,
    /// Segment ordinal, when this is part of a bounded logical record.
    pub segment_number: Option<u32>,
    /// Final logical block length declared by the last continuation.
    pub segment_total_length: Option<u64>,
    /// HTTP transfer framing. Payload retrieval removes chunk framing, never content encoding.
    pub transfer_chunked: bool,
    /// Header/target privacy approval, independent of possibly split payload bytes.
    pub headers_retention_approved: bool,
    /// Optional revisit target constraint from the original record.
    pub refers_to_target: Option<String>,
    /// Optional revisit capture-date constraint from the original record.
    pub refers_to_date: Option<DateTime<Utc>>,
    /// Captured partial-message declaration; materialization never fills missing bytes.
    pub truncated: bool,
    /// Revisit profile URI; only the two WARC 1.1 baseline-reuse profiles are interpreted.
    pub revisit_profile: Option<String>,
}

/// Headers supplied separately from streaming block ownership.
#[derive(Clone, Debug)]
pub struct RecordHeader {
    /// Case-insensitive WARC named fields. The writer generates Content-Length and digests.
    pub fields: BTreeMap<String, String>,
    /// Offset of the actual payload within the block (HTTP headers are excluded).
    pub payload_offset: u64,
}

/// Write one independently decompressible member without buffering the block.
///
/// # Errors
/// Rejects invalid headers, oversized/short inputs, digest/framing problems, or I/O errors.
pub fn write_record<W: Write + Seek, R: Read + Seek>(
    output: &mut W,
    header: &RecordHeader,
    block: &mut R,
    length: u64,
    limits: Limits,
) -> Result<RecordSummary, ArchiveError> {
    if length > limits.record_bytes || header.payload_offset > length {
        return Err(ArchiveError::Limit("record bytes"));
    }
    let start = block.stream_position()?;
    let mut block_hash = Sha256::new();
    let mut payload_hash = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    let mut consumed = 0u64;
    while consumed < length {
        let want = usize::try_from((length - consumed).min(buffer.len() as u64))
            .map_err(|_| ArchiveError::Limit("record bytes"))?;
        let n = block.read(&mut buffer[..want])?;
        if n == 0 {
            return Err(ArchiveError::Invalid("short record block"));
        }
        block_hash.update(&buffer[..n]);
        let skip = usize::try_from(header.payload_offset.saturating_sub(consumed).min(n as u64))
            .map_err(|_| ArchiveError::Limit("payload offset"))?;
        payload_hash.update(&buffer[skip..n]);
        consumed += n as u64;
    }
    let block_digest = format!("sha256:{}", hex::encode(block_hash.finalize()));
    let payload_digest = format!("sha256:{}", hex::encode(payload_hash.finalize()));
    let mut fields = BTreeMap::new();
    for (name, value) in &header.fields {
        let name = name.to_ascii_lowercase();
        if !valid_name(&name) || !valid_value(value) || fields.insert(name, value.clone()).is_some() {
            return Err(ArchiveError::Invalid("invalid or duplicate WARC header"));
        }
    }
    fields.insert("content-length".into(), length.to_string());
    fields.insert("warc-block-digest".into(), block_digest);
    let kind = required(&fields, "warc-type")?;
    if matches!(kind, "warcinfo" | "metadata") {
        fields.remove("warc-payload-digest");
    } else if kind != "revisit" && !fields.contains_key("warc-segment-number") {
        fields.insert("warc-payload-digest".into(), payload_digest);
    }
    let mut summary = summarize(&fields, length, header.payload_offset)?;
    if matches!(summary.record_type.as_str(), "request" | "response" | "revisit") && length > 0 {
        block.seek(SeekFrom::Start(start))?;
        let mut prefix = Vec::new();
        (&mut *block)
            .take(limits.header_bytes + 1)
            .read_to_end(&mut prefix)?;
        let block_size = usize::try_from(length).map_err(|_| ArchiveError::Limit("record bytes"))?;
        let (offset, status, mime, chunked) = parse_http(
            &prefix,
            &summary.record_type,
            limits.header_bytes,
            block_size,
            summary.segment_number.is_some() || fields.contains_key("warc-truncated"),
        )?;
        if chunked {
            return Err(ArchiveError::Invalid(
                "streaming writer requires normalized non-chunked HTTP input",
            ));
        }
        if offset as u64 != header.payload_offset {
            return Err(ArchiveError::Invalid("HTTP payload offset mismatch"));
        }
        summary.status = status;
        if let Some(mime) = mime {
            summary.mime = mime;
        }
    }
    let mut head = Vec::new();
    head.extend_from_slice(b"WARC/1.1\r\n");
    for (name, value) in &fields {
        write!(&mut head, "{name}: {value}\r\n")?;
    }
    head.extend_from_slice(b"\r\n");
    if head.len() as u64 > limits.header_bytes {
        return Err(ArchiveError::Limit("header bytes"));
    }
    summary.uncompressed_length = length
        .checked_add(head.len() as u64)
        .and_then(|n| n.checked_add(4))
        .ok_or(ArchiveError::Limit("expanded record bytes"))?;
    block.seek(SeekFrom::Start(start))?;
    let offset = output.stream_position()?;
    let mut member = GzBuilder::new()
        .mtime(0)
        .write(&mut *output, Compression::default());
    member.write_all(&head)?;
    let copied = std::io::copy(&mut block.take(length), &mut member)?;
    if copied != length {
        return Err(ArchiveError::Invalid("short record block"));
    }
    member.write_all(b"\r\n\r\n")?;
    member.finish()?;
    summary.offset = offset;
    summary.length = output
        .stream_position()?
        .checked_sub(offset)
        .ok_or(ArchiveError::Limit("offset"))?;
    if output.stream_position()? > limits.total_bytes {
        return Err(ArchiveError::Limit("archive bytes"));
    }
    Ok(summary)
}

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn valid_value(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| !c.is_control())
}
fn required<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, ArchiveError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or(ArchiveError::Invalid("missing required WARC field"))
}
fn valid_id(value: &str) -> bool {
    value
        .strip_prefix('<')
        .and_then(|v| v.strip_suffix('>'))
        .is_some_and(|v| url::Url::parse(v).is_ok())
}
fn summarize(
    fields: &BTreeMap<String, String>,
    length: u64,
    payload_offset: u64,
) -> Result<RecordSummary, ArchiveError> {
    let id = required(fields, "warc-record-id")?;
    if !valid_id(id) {
        return Err(ArchiveError::Invalid("invalid WARC record identifier"));
    }
    let date = DateTime::parse_from_rfc3339(required(fields, "warc-date")?)
        .map_err(|_| ArchiveError::Invalid("invalid WARC date"))?
        .with_timezone(&Utc);
    let kind = required(fields, "warc-type")?;
    if !valid_name(kind) {
        return Err(ArchiveError::Invalid("invalid WARC type"));
    }
    let known = matches!(
        kind,
        "warcinfo"
            | "request"
            | "response"
            | "resource"
            | "metadata"
            | "revisit"
            | "conversion"
            | "continuation"
    );
    let target = fields.get("warc-target-uri").cloned();
    if matches!(
        kind,
        "request" | "response" | "resource" | "revisit" | "conversion" | "continuation"
    ) && target.is_none()
    {
        return Err(ArchiveError::Invalid("missing WARC target URI"));
    }
    if target.as_ref().is_some_and(|v| url::Url::parse(v).is_err()) {
        return Err(ArchiveError::Invalid("invalid WARC target URI"));
    }
    if kind == "warcinfo" && target.is_some() {
        return Err(ArchiveError::Invalid("warcinfo cannot have a target URI"));
    }
    if matches!(kind, "warcinfo" | "metadata") && fields.contains_key("warc-payload-digest") {
        return Err(ArchiveError::Invalid("record type has no defined payload"));
    }
    if known
        && fields.contains_key("warc-refers-to")
        && !matches!(kind, "metadata" | "conversion" | "revisit")
    {
        return Err(ArchiveError::Invalid("record type cannot carry WARC-Refers-To"));
    }
    if fields.contains_key("warc-segment-origin-id") && kind != "continuation" {
        return Err(ArchiveError::Invalid(
            "segment origin is only valid on continuation records",
        ));
    }
    if fields.contains_key("warc-segment-total-length") && kind != "continuation" {
        return Err(ArchiveError::Invalid(
            "segment total length is only valid on final continuation",
        ));
    }
    let mut dependencies = Vec::new();
    for key in ["warc-refers-to", "warc-segment-origin-id"] {
        if let Some(value) = fields.get(key) {
            if !valid_id(value) {
                return Err(ArchiveError::Invalid("invalid WARC relationship"));
            }
            dependencies.push(value.clone());
        }
    }
    if kind == "revisit" {
        if !fields.contains_key("warc-segment-number") && payload_offset != length {
            return Err(ArchiveError::Invalid("revisit block carries stored payload"));
        }
        let profile = required(fields, "warc-profile")?;
        url::Url::parse(profile).map_err(|_| ArchiveError::Invalid("invalid revisit profile URI"))?;
        if profile == "http://netpreserve.org/warc/1.1/revisit/identical-payload-digest" {
            required(fields, "warc-payload-digest")?;
        }
        if dependencies.is_empty()
            && !(fields.contains_key("warc-refers-to-target-uri")
                && fields.contains_key("warc-refers-to-date"))
        {
            return Err(ArchiveError::Invalid("revisit baseline unavailable"));
        }
    }
    if kind == "conversion" && dependencies.is_empty() {
        return Err(ArchiveError::Invalid("conversion source unavailable"));
    }
    if kind == "continuation" {
        let segment = required(fields, "warc-segment-number")?
            .parse::<u32>()
            .map_err(|_| ArchiveError::Invalid("invalid segment number"))?;
        if segment < 2 || dependencies.is_empty() {
            return Err(ArchiveError::Invalid("invalid continuation dependency"));
        }
    }
    let segment_number = fields
        .get("warc-segment-number")
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| ArchiveError::Invalid("invalid segment number"))
        })
        .transpose()?;
    let segment_total_length = fields
        .get("warc-segment-total-length")
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| ArchiveError::Invalid("invalid segment total length"))
        })
        .transpose()?;
    if kind != "continuation" && segment_number.is_some_and(|number| number != 1) {
        return Err(ArchiveError::Invalid("first segment must be number one"));
    }
    let refers_to_target = fields.get("warc-refers-to-target-uri").cloned();
    if refers_to_target
        .as_ref()
        .is_some_and(|uri| url::Url::parse(uri).is_err())
    {
        return Err(ArchiveError::Invalid("invalid revisit target URI"));
    }
    let refers_to_date = fields
        .get("warc-refers-to-date")
        .map(|date| {
            DateTime::parse_from_rfc3339(date)
                .map(|date| date.with_timezone(&Utc))
                .map_err(|_| ArchiveError::Invalid("invalid revisit date"))
        })
        .transpose()?;
    Ok(RecordSummary {
        id: id.into(),
        record_type: kind.into(),
        known_type: known,
        date,
        target,
        mime: fields
            .get("content-type")
            .and_then(|value| value.split(';').next())
            .unwrap_or("application/octet-stream")
            .trim()
            .into(),
        status: None,
        payload_digest: fields.get("warc-payload-digest").cloned().unwrap_or_default(),
        offset: 0,
        length: 0,
        payload_offset,
        block_length: length,
        dependencies,
        retention_approved: false,
        segment_number,
        segment_total_length,
        transfer_chunked: false,
        uncompressed_length: 0,
        headers_retention_approved: false,
        refers_to_target,
        refers_to_date,
        truncated: fields.contains_key("warc-truncated"),
        revisit_profile: fields.get("warc-profile").cloned(),
    })
}

fn line<R: BufRead>(input: &mut R, budget: &mut u64) -> Result<Vec<u8>, ArchiveError> {
    let mut result = Vec::new();
    loop {
        let available = input.fill_buf()?;
        if available.is_empty() {
            return Err(ArchiveError::Invalid("unterminated WARC header"));
        }
        let n = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        if n as u64 > *budget {
            return Err(ArchiveError::Limit("header bytes"));
        }
        *budget -= n as u64;
        result.extend_from_slice(&available[..n]);
        input.consume(n);
        if result.ends_with(b"\n") {
            break;
        }
    }
    if !result.ends_with(b"\r\n") {
        return Err(ArchiveError::Invalid("WARC requires CRLF framing"));
    }
    result.truncate(result.len() - 2);
    Ok(result)
}

/// Decode one record from a bounded uncompressed reader. Payload ownership remains local.
///
/// # Errors
/// Rejects malformed framing, headers, HTTP messages and digest mismatches.
pub fn read_record<R: BufRead>(
    input: &mut R,
    limits: Limits,
) -> Result<(RecordSummary, Vec<u8>), ArchiveError> {
    let mut budget = limits.header_bytes;
    if line(input, &mut budget)? != b"WARC/1.1" {
        return Err(ArchiveError::Invalid("unsupported WARC version"));
    }
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut previous: Option<String> = None;
    loop {
        let row = line(input, &mut budget)?;
        if row.is_empty() {
            break;
        }
        let row = std::str::from_utf8(&row).map_err(|_| ArchiveError::Invalid("non-UTF8 WARC header"))?;
        if row.starts_with([' ', '\t']) {
            let name = previous
                .as_ref()
                .ok_or(ArchiveError::Invalid("orphan WARC header continuation"))?;
            let value = fields
                .get_mut(name)
                .ok_or(ArchiveError::Invalid("missing continued header"))?;
            value.push(' ');
            value.push_str(row.trim());
            continue;
        }
        let (name, value) = row
            .split_once(':')
            .ok_or(ArchiveError::Invalid("malformed WARC header"))?;
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        if name == "warc-concurrent-to" && fields.contains_key(&name) {
            if !valid_id(value) {
                return Err(ArchiveError::Invalid("invalid concurrent record identifier"));
            }
            // WARC 1.1 explicitly permits repeated concurrent-to fields.
            continue;
        }
        if !valid_name(&name) || !valid_value(value) || fields.insert(name.clone(), value.into()).is_some() {
            return Err(ArchiveError::Invalid("invalid or duplicate WARC header"));
        }
        previous = Some(name);
    }
    let declared_length = required(&fields, "content-length")?;
    if !declared_length.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ArchiveError::Invalid("invalid Content-Length"));
    }
    let length = declared_length
        .parse::<u64>()
        .map_err(|_| ArchiveError::Invalid("invalid Content-Length"))?;
    if length > limits.record_bytes {
        return Err(ArchiveError::Limit("record bytes"));
    }
    let mut block = vec![0; usize::try_from(length).map_err(|_| ArchiveError::Limit("record bytes"))?];
    input.read_exact(&mut block)?;
    let mut trailer = [0u8; 4];
    input.read_exact(&mut trailer)?;
    if trailer != *b"\r\n\r\n" {
        return Err(ArchiveError::Invalid("invalid WARC record terminator"));
    }
    if let Some(digest) = fields.get("warc-block-digest") {
        verify_digest(digest, &block)?;
    }
    let kind = required(&fields, "warc-type")?;
    let segmented = fields.contains_key("warc-segment-number");
    let (payload_offset, status, mime, chunked) =
        if matches!(kind, "request" | "response" | "revisit") && !block.is_empty() {
            if segmented && !block.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                (0usize, None, None, false)
            } else {
                parse_http(
                    &block,
                    kind,
                    limits.header_bytes,
                    block.len(),
                    segmented || fields.contains_key("warc-truncated"),
                )?
            }
        } else {
            (0usize, None, None, false)
        };
    let decoded;
    let payload = if chunked && !segmented && kind != "revisit" {
        decoded = decode_chunks(&block[payload_offset..], limits.record_bytes)?;
        decoded.as_slice()
    } else {
        &block[payload_offset..]
    };
    // Revisit and segmented digests describe a separate or logical payload, not this block.
    if kind != "revisit" && !segmented {
        if let Some(digest) = fields.get("warc-payload-digest") {
            verify_digest(digest, payload)?;
        }
    }
    let mut summary = summarize(&fields, length, payload_offset as u64)?;
    summary.uncompressed_length = length
        .checked_add(limits.header_bytes - budget)
        .and_then(|n| n.checked_add(4))
        .ok_or(ArchiveError::Limit("expanded record bytes"))?;
    summary.status = status;
    summary.transfer_chunked = chunked;
    if let Some(mime) = mime {
        summary.mime = mime;
    }
    if kind != "revisit" && !segmented && !matches!(kind, "warcinfo" | "metadata") {
        summary.payload_digest = digest(payload);
    }
    let redactor = crawlx_telemetry::redact::Redactor::new();
    summary.headers_retention_approved = fields.iter().all(|(name, value)| {
        if matches!(name.as_str(), "warc-block-digest" | "warc-payload-digest") {
            return true;
        }
        !redactor.is_sensitive_name(name)
            && redactor.scrub(value) == *value
            && redactor.scrub_session_queries(value) == *value
    });
    summary.headers_retention_approved &= summary
        .target
        .as_ref()
        .is_none_or(|target| retention_safe_url(target));
    summary.headers_retention_approved &= summary
        .refers_to_target
        .as_ref()
        .is_none_or(|target| retention_safe_url(target));
    summary.retention_approved =
        summary.headers_retention_approved && retention_safe_text(&block, &summary.mime);
    if chunked && !segmented && kind != "revisit" {
        summary.retention_approved &= retention_safe_text(payload, &summary.mime);
    }
    Ok((summary, block))
}
/// Whether a target URI passes the text-only archive policy, including decoded query fields.
#[must_use]
pub fn retention_safe_url(target: &str) -> bool {
    let Ok(url) = url::Url::parse(target) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    let redactor = crawlx_telemetry::redact::Redactor::with_extra_deny_names([
        "session",
        "login",
        "auth",
        "csrf",
        "accesskey",
    ]);
    redactor.is_clean_text(target)
        && url.query_pairs().all(|(name, value)| {
            !redactor.is_sensitive_name(&name)
                && redactor.is_clean_text(&name)
                && redactor.is_clean_text(&value)
        })
}

pub(super) fn retention_safe_text(bytes: &[u8], mime: &str) -> bool {
    let textual = mime.starts_with("text/")
        || matches!(
            mime,
            "application/json"
                | "application/xml"
                | "application/xhtml+xml"
                | "application/warc-fields"
                | "application/javascript"
                | "application/http"
                | "message/http"
        );
    let redactor = crawlx_telemetry::redact::Redactor::new();
    textual
        && std::str::from_utf8(bytes)
            .is_ok_and(|text| redactor.scrub(text) == text && redactor.scrub_session_queries(text) == text)
}

pub(super) fn logical_http(
    kind: &str,
    block: &[u8],
    limits: Limits,
    partial: bool,
) -> Result<(usize, Option<u16>, Option<String>, bool), ArchiveError> {
    if matches!(kind, "request" | "response" | "revisit") && !block.is_empty() {
        parse_http(block, kind, limits.header_bytes, block.len(), partial)
    } else {
        Ok((0, None, None, false))
    }
}

pub(super) fn same_digest(left: &str, right: &str) -> bool {
    let left = left
        .strip_prefix("sha256:")
        .or_else(|| left.strip_prefix("sha-256:"));
    let right = right
        .strip_prefix("sha256:")
        .or_else(|| right.strip_prefix("sha-256:"));
    matches!((left, right), (Some(left), Some(right)) if left.eq_ignore_ascii_case(right))
}

fn parse_http(
    block: &[u8],
    kind: &str,
    header_limit: u64,
    block_length: usize,
    allow_partial: bool,
) -> Result<(usize, Option<u16>, Option<String>, bool), ArchiveError> {
    let end = block
        .windows(4)
        .position(|v| v == b"\r\n\r\n")
        .ok_or(ArchiveError::Invalid("missing HTTP header terminator"))?;
    if end as u64 > header_limit {
        return Err(ArchiveError::Limit("HTTP header bytes"));
    }
    let head =
        std::str::from_utf8(&block[..end]).map_err(|_| ArchiveError::Invalid("invalid HTTP headers"))?;
    let mut lines = head.split("\r\n");
    let first = lines
        .next()
        .ok_or(ArchiveError::Invalid("missing HTTP start line"))?;
    let mut words = first.split(' ');
    let status = if kind == "request" {
        let method = words.next().ok_or(ArchiveError::Invalid("missing HTTP method"))?;
        if method.is_empty()
            || !method.bytes().all(|b| b.is_ascii_uppercase() || b == b'-')
            || words.next().is_none_or(str::is_empty)
            || !words.next().is_some_and(|v| matches!(v, "HTTP/1.0" | "HTTP/1.1"))
            || words.next().is_some()
        {
            return Err(ArchiveError::Invalid("invalid HTTP request line"));
        }
        None
    } else {
        if !words.next().is_some_and(|v| matches!(v, "HTTP/1.0" | "HTTP/1.1")) {
            return Err(ArchiveError::Invalid("invalid HTTP response version"));
        }
        let status = words
            .next()
            .ok_or(ArchiveError::Invalid("missing HTTP status"))?
            .parse::<u16>()
            .map_err(|_| ArchiveError::Invalid("invalid HTTP status"))?;
        if !(100..=599).contains(&status) {
            return Err(ArchiveError::Invalid("invalid HTTP status"));
        }
        Some(status)
    };
    let mut mime = None;
    let mut content_length = None;
    let mut transfer_encoding = false;
    for row in lines {
        let (name, value) = row
            .split_once(':')
            .ok_or(ArchiveError::Invalid("malformed HTTP header"))?;
        if !valid_name(name) || !valid_value(value.trim()) {
            return Err(ArchiveError::Invalid("invalid HTTP header"));
        }
        if name.eq_ignore_ascii_case("content-type") {
            mime = Some(value.split(';').next().unwrap_or("").trim().into());
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.trim().eq_ignore_ascii_case("chunked") {
                return Err(ArchiveError::Invalid("unsupported HTTP transfer coding"));
            }
            transfer_encoding = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            let n = value
                .trim()
                .parse::<u64>()
                .map_err(|_| ArchiveError::Invalid("invalid HTTP Content-Length"))?;
            if content_length.replace(n).is_some() {
                return Err(ArchiveError::Invalid("duplicate HTTP Content-Length"));
            }
        }
    }
    let offset = end + 4;
    if transfer_encoding && content_length.is_some() {
        return Err(ArchiveError::Invalid("ambiguous HTTP framing"));
    }
    if !allow_partial
        && kind != "revisit"
        && content_length.is_some_and(|n| n != block_length.saturating_sub(offset) as u64)
        && !matches!(status, Some(204 | 304))
    {
        return Err(ArchiveError::Invalid("HTTP body length mismatch"));
    }
    Ok((offset, status, mime, transfer_encoding))
}

pub(super) fn decode_chunks(mut input: &[u8], limit: u64) -> Result<Vec<u8>, ArchiveError> {
    let mut result = Vec::new();
    loop {
        let end = input
            .windows(2)
            .position(|bytes| bytes == b"\r\n")
            .ok_or(ArchiveError::Invalid("invalid chunk header"))?;
        if end > 8192 {
            return Err(ArchiveError::Limit("chunk header bytes"));
        }
        let line =
            std::str::from_utf8(&input[..end]).map_err(|_| ArchiveError::Invalid("invalid chunk size"))?;
        let size = u64::from_str_radix(line.split(';').next().unwrap_or(""), 16)
            .map_err(|_| ArchiveError::Invalid("invalid chunk size"))?;
        input = &input[end + 2..];
        if size == 0 {
            if input == b"\r\n" {
                return Ok(result);
            }
            if input.len() > 65_536 || !input.ends_with(b"\r\n\r\n") {
                return Err(ArchiveError::Invalid("invalid chunk trailers"));
            }
            for trailer in input[..input.len() - 4].split(|byte| *byte == b'\n') {
                if !trailer.contains(&b':') {
                    return Err(ArchiveError::Invalid("invalid chunk trailer field"));
                }
            }
            return Ok(result);
        }
        let size = usize::try_from(size).map_err(|_| ArchiveError::Limit("chunk bytes"))?;
        let end = size.checked_add(2).ok_or(ArchiveError::Limit("chunk bytes"))?;
        if end > input.len() || &input[size..end] != b"\r\n" {
            return Err(ArchiveError::Invalid("short or malformed chunk"));
        }
        if result.len().saturating_add(size) as u64 > limit {
            return Err(ArchiveError::Limit("chunk payload bytes"));
        }
        result.extend_from_slice(&input[..size]);
        input = &input[end..];
    }
}

/// SHA-256 fixity using the WACZ/WARC algorithm label.
#[must_use]
pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn verify_digest(expected: &str, bytes: &[u8]) -> Result<(), ArchiveError> {
    let expected = expected
        .strip_prefix("sha256:")
        .or_else(|| expected.strip_prefix("sha-256:"))
        .ok_or(ArchiveError::Invalid("unsupported digest algorithm"))?;
    if !expected.eq_ignore_ascii_case(&hex::encode(Sha256::digest(bytes))) {
        return Err(ArchiveError::Invalid("digest mismatch"));
    }
    Ok(())
}

/// Validate a WARC stream and retain only bounded record descriptors.
///
/// # Errors
/// Rejects malformed members, expansion/count limits, duplicate IDs or unresolved dependencies.
pub fn inspect<R: Read + Seek>(
    mut input: R,
    compressed: bool,
    limits: Limits,
) -> Result<Vec<RecordSummary>, ArchiveError> {
    let records = scan(&mut input, compressed, limits)?;
    let mut catalog = super::resolver::Catalog::new(
        records
            .iter()
            .cloned()
            .map(|record| super::resolver::RecordLocation {
                source: 0,
                filename: String::new(),
                record,
            }),
        limits,
    )?;
    catalog.validate(&mut |location| block_at(&mut input, &location.record, compressed, limits))?;
    let mut normalized = records;
    for record in &mut normalized {
        *record = catalog.location(&record.id)?.record.clone();
    }
    Ok(normalized)
}

pub(super) fn scan<R: Read + Seek>(
    input: R,
    compressed: bool,
    limits: Limits,
) -> Result<Vec<RecordSummary>, ArchiveError> {
    let mut input = BufReader::new(input);
    let mut records = Vec::new();
    let mut expanded = 0u64;
    while !input.fill_buf()?.is_empty() {
        if records.len() as u64 >= u64::from(limits.records) {
            return Err(ArchiveError::Limit("record count"));
        }
        let offset = input.stream_position()?;
        let (mut summary, _block) = if compressed {
            let decoder = GzDecoder::new(&mut input);
            let max = limits
                .record_bytes
                .checked_add(limits.header_bytes)
                .and_then(|v| v.checked_add(4))
                .ok_or(ArchiveError::Limit("expanded record bytes"))?;
            let mut decoded = BufReader::new(decoder.take(max + 1));
            let parsed = read_record(&mut decoded, limits)?;
            // Reading to EOF checks CRC and ISIZE and forbids multiple WARC records in a member.
            let mut extra = [0u8; 1];
            if decoded.read(&mut extra)? != 0 {
                return Err(ArchiveError::Invalid("extra data in gzip member"));
            }
            parsed
        } else {
            read_record(&mut input, limits)?
        };
        let end = input.stream_position()?;
        if end > limits.total_bytes {
            return Err(ArchiveError::Limit("input bytes"));
        }
        summary.offset = offset;
        summary.length = end
            .checked_sub(offset)
            .ok_or(ArchiveError::Limit("member offset"))?;
        expanded = expanded
            .checked_add(summary.uncompressed_length)
            .ok_or(ArchiveError::Limit("expanded bytes"))?;
        if expanded > limits.expanded_bytes {
            return Err(ArchiveError::Limit("expanded bytes"));
        }
        records.push(summary);
    }
    if records.is_empty() {
        return Err(ArchiveError::Invalid("empty WARC"));
    }
    Ok(records)
}

/// Read the actual payload at a validated member range, without live content execution.
///
/// # Errors
/// Rejects ranges that do not identify exactly one complete member/record.
pub fn payload_at<R: Read + Seek>(
    input: &mut R,
    record: &RecordSummary,
    compressed: bool,
    limits: Limits,
) -> Result<Vec<u8>, ArchiveError> {
    if record.segment_number.is_none() && !matches!(record.record_type.as_str(), "revisit" | "continuation") {
        let block = block_at(input, record, compressed, limits)?;
        return payload_from_block(block, record, limits);
    }
    input.rewind()?;
    let records = scan(&mut *input, compressed, limits)?;
    let mut catalog = super::resolver::Catalog::new(
        records.into_iter().map(|record| super::resolver::RecordLocation {
            source: 0,
            filename: String::new(),
            record,
        }),
        limits,
    )?;
    catalog.validate(&mut |location| block_at(input, &location.record, compressed, limits))?;
    let actual = &catalog.location(&record.id)?.record;
    if actual.offset != record.offset || actual.length != record.length {
        return Err(ArchiveError::Invalid("indexed member range mismatch"));
    }
    Ok(catalog
        .materialize(&record.id, &mut |location| {
            block_at(input, &location.record, compressed, limits)
        })?
        .bytes)
}

pub(super) fn block_at<R: Read + Seek>(
    input: &mut R,
    record: &RecordSummary,
    compressed: bool,
    limits: Limits,
) -> Result<Vec<u8>, ArchiveError> {
    input.seek(SeekFrom::Start(record.offset))?;
    let mut range = BufReader::new(input.take(record.length));
    let (actual, block) = if compressed {
        let mut decoder = BufReader::new(GzDecoder::new(&mut range));
        let parsed = read_record(&mut decoder, limits)?;
        let mut extra = [0u8; 1];
        if decoder.read(&mut extra)? != 0 {
            return Err(ArchiveError::Invalid("extra member data"));
        }
        parsed
    } else {
        read_record(&mut range, limits)?
    };
    if !range.fill_buf()?.is_empty() || range.get_ref().limit() != 0 {
        return Err(ArchiveError::Invalid(
            "member range does not match encoded length",
        ));
    }
    if actual.id != record.id
        || actual.block_length != record.block_length
        || actual.record_type != record.record_type
    {
        return Err(ArchiveError::Invalid("indexed member mismatch"));
    }
    Ok(block)
}

fn payload_from_block(
    mut block: Vec<u8>,
    record: &RecordSummary,
    limits: Limits,
) -> Result<Vec<u8>, ArchiveError> {
    if matches!(record.record_type.as_str(), "warcinfo" | "metadata") {
        return Err(ArchiveError::CapabilityUnavailable(
            "record_has_no_defined_payload",
        ));
    }
    let (offset, _, _, chunked) = logical_http(&record.record_type, &block, limits, record.truncated)?;
    let bytes = if chunked {
        decode_chunks(&block[offset..], limits.record_bytes)?
    } else {
        if offset > 0 {
            drop(block.drain(..offset));
        }
        block
    };
    if !record.payload_digest.is_empty() {
        verify_digest(&record.payload_digest, &bytes)?;
    }
    Ok(bytes)
}

/// Decode exactly one independent gzip WARC member once, returning its actual entity payload.
///
/// # Errors
/// Rejects malformed/trailing data, CRC/digest/size failures and records needing a dependency catalog.
pub fn read_member<R: Read + Seek>(
    mut input: R,
    limits: Limits,
) -> Result<(RecordSummary, Vec<u8>), ArchiveError> {
    let length = input.seek(SeekFrom::End(0))?;
    if length > limits.total_bytes {
        return Err(ArchiveError::Limit("member input bytes"));
    }
    input.rewind()?;
    let mut input = BufReader::new(input);
    let (mut record, block) = {
        let mut decoder = BufReader::new(GzDecoder::new(&mut input));
        let parsed = read_record(&mut decoder, limits)?;
        let mut extra = [0u8; 1];
        if decoder.read(&mut extra)? != 0 {
            return Err(ArchiveError::Invalid("multiple records in one gzip member"));
        }
        parsed
    };
    if !input.fill_buf()?.is_empty() {
        return Err(ArchiveError::Invalid("trailing data after gzip member"));
    }
    if record.segment_number.is_some() || !record.dependencies.is_empty() || record.record_type == "revisit" {
        return Err(ArchiveError::CapabilityUnavailable(
            "member_requires_local_dependency_catalog",
        ));
    }
    if record.uncompressed_length > limits.expanded_bytes {
        return Err(ArchiveError::Limit("member expanded bytes"));
    }
    record.offset = 0;
    record.length = length;
    let bytes = payload_from_block(block, &record, limits)?;
    Ok((record, bytes))
}

/// RFC3339 UTC date suitable for WARC-Date.
#[must_use]
pub fn date(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}
