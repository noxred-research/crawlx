//! CDXJ 0.1.0 searchable URL keys, bounded external sorting and actual member-range validation.

use super::{validate_path, warc::RecordSummary, ArchiveError, Limits};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use tempfile::TempDir;

/// The required CDXJ JSON object. Resource records use status `-`, never synthetic HTTP 200.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    /// Archived, privacy-approved URL; distinct from the lookup normalization.
    pub url: String,
    /// Stored payload SHA-256 digest.
    pub digest: String,
    /// Payload MIME type.
    pub mime: String,
    /// WARC filename relative to archive/ in WACZ.
    pub filename: String,
    /// Actual first byte of the record's member.
    pub offset: u64,
    /// Actual encoded member length.
    pub length: u64,
    /// HTTP response status, or `-` for a non-HTTP resource.
    pub status: serde_json::Value,
}

/// Produce the specification's lookup-only SURT. Never use this key for crawl identity or scope.
///
/// # Errors
/// Rejects malformed URLs, userinfo, control characters or missing hosts.
pub fn searchable_url(url: &str) -> Result<String, ArchiveError> {
    if url.chars().any(char::is_control) {
        return Err(ArchiveError::Invalid("invalid indexed URL"));
    }
    let parsed = url::Url::parse(url).map_err(|_| ArchiveError::Invalid("invalid indexed URL"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ArchiveError::Invalid("URL credentials forbidden"));
    }
    let host = parsed
        .host_str()
        .ok_or(ArchiveError::Invalid("indexed URL requires a host"))?;
    let mut key = host
        .split('.')
        .rev()
        .collect::<Vec<_>>()
        .join(",")
        .to_ascii_lowercase();
    if let Some(port) = parsed.port() {
        key.push(':');
        key.push_str(&port.to_string());
    }
    key.push(')');
    key.push_str(&parsed.path().to_lowercase());
    if let Some(query) = parsed.query() {
        key.push('?');
        key.push_str(&query.to_lowercase());
    }
    Ok(key)
}

impl Entry {
    /// Index an already committed member descriptor.
    ///
    /// # Errors
    /// Rejects absent target URLs or unsafe filenames.
    pub fn from_record(record: &RecordSummary, filename: &str) -> Result<Self, ArchiveError> {
        validate_path(filename)?;
        Ok(Self {
            url: record
                .target
                .clone()
                .ok_or(ArchiveError::Invalid("indexed record has no URL"))?,
            digest: record.payload_digest.clone(),
            mime: record.mime.clone(),
            filename: filename.into(),
            offset: record.offset,
            length: record.length,
            status: record
                .status
                .map_or_else(|| serde_json::Value::String("-".into()), serde_json::Value::from),
        })
    }

    /// Encode a full sortable CDXJ line, preserving the original URL in JSON.
    ///
    /// # Errors
    /// Rejects invalid lookup URLs or serialization failures.
    pub fn line(&self, record: &RecordSummary) -> Result<String, ArchiveError> {
        Ok(format!(
            "{} {} {}\n",
            searchable_url(&self.url)?,
            record.date.format("%Y%m%d%H%M%S%3f"),
            serde_json::to_string(self)?
        ))
    }
}

/// Bounded external sort. Only a fixed-size run and one line per spill file remain in memory.
pub struct Sorter {
    dir: TempDir,
    rows: Vec<String>,
    bytes: usize,
    runs: usize,
}
impl Sorter {
    /// Create private staging after the caller's retention gate.
    ///
    /// # Errors
    /// Returns an I/O error when temporary storage is unavailable.
    pub fn new() -> Result<Self, ArchiveError> {
        Ok(Self {
            dir: tempfile::tempdir()?,
            rows: Vec::new(),
            bytes: 0,
            runs: 0,
        })
    }
    /// Add a bounded line; spill at 1 MiB.
    ///
    /// # Errors
    /// Rejects oversized lines or excessive spill count; preserves I/O errors.
    pub fn push(&mut self, row: String) -> Result<(), ArchiveError> {
        if row.len() > 65_536 {
            return Err(ArchiveError::Limit("CDXJ line"));
        }
        self.bytes = self
            .bytes
            .checked_add(row.len())
            .ok_or(ArchiveError::Limit("CDXJ sort bytes"))?;
        self.rows.push(row);
        if self.bytes >= 1_048_576 {
            self.spill()?;
        }
        Ok(())
    }
    fn spill(&mut self) -> Result<(), ArchiveError> {
        if self.rows.is_empty() {
            return Ok(());
        }
        if self.runs >= 1024 {
            return Err(ArchiveError::Limit("CDXJ sort runs"));
        }
        self.rows.sort_unstable();
        let mut file = BufWriter::new(File::create(self.dir.path().join(self.runs.to_string()))?);
        for row in self.rows.drain(..) {
            file.write_all(row.as_bytes())?;
        }
        file.flush()?;
        self.runs += 1;
        self.bytes = 0;
        Ok(())
    }
    /// Merge sorted runs into the finalized index.
    ///
    /// # Errors
    /// Returns I/O errors from spill or output storage.
    pub fn finish(mut self, output: &mut impl Write) -> Result<(), ArchiveError> {
        self.spill()?;
        let mut readers = (0..self.runs)
            .map(|i| File::open(self.dir.path().join(i.to_string())).map(BufReader::new))
            .collect::<Result<Vec<_>, _>>()?;
        let mut heap: BinaryHeap<Reverse<(String, usize)>> = BinaryHeap::new();
        for (index, reader) in readers.iter_mut().enumerate() {
            let mut row = String::new();
            if reader.read_line(&mut row)? != 0 {
                heap.push(Reverse((row, index)));
            }
        }
        while let Some(Reverse((row, index))) = heap.pop() {
            output.write_all(row.as_bytes())?;
            let mut next = String::new();
            if readers[index].read_line(&mut next)? != 0 {
                heap.push(Reverse((next, index)));
            }
        }
        Ok(())
    }
}

/// Validate every index range against parsed members, not just against the file size.
///
/// # Errors
/// Rejects unsorted/oversized lines, missing members, mismatched metadata or bad lookup keys.
pub fn validate<R: BufRead>(
    mut input: R,
    members: &BTreeMap<(String, u64), RecordSummary>,
    limits: Limits,
) -> Result<u64, ArchiveError> {
    let mut previous = String::new();
    let mut count = 0u64;
    let mut total = 0u64;
    loop {
        let mut bytes = Vec::new();
        loop {
            let available = input.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let n = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |v| v + 1);
            if bytes.len().saturating_add(n) as u64 > limits.header_bytes {
                return Err(ArchiveError::Limit("CDXJ line"));
            }
            bytes.extend_from_slice(&available[..n]);
            input.consume(n);
            if bytes.ends_with(b"\n") {
                break;
            }
        }
        if bytes.is_empty() {
            break;
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or(ArchiveError::Limit("CDXJ bytes"))?;
        if total > limits.total_bytes {
            return Err(ArchiveError::Limit("CDXJ bytes"));
        }
        if !bytes.ends_with(b"\n") {
            return Err(ArchiveError::Invalid("unterminated CDXJ line"));
        }
        let row = String::from_utf8(bytes).map_err(|_| ArchiveError::Invalid("invalid CDXJ UTF8"))?;
        if row < previous {
            return Err(ArchiveError::Invalid("unsorted CDXJ"));
        }
        let mut parts = row.trim_end_matches('\n').splitn(3, ' ');
        let key = parts.next().ok_or(ArchiveError::Invalid("missing CDXJ key"))?;
        let timestamp = parts
            .next()
            .ok_or(ArchiveError::Invalid("missing CDXJ timestamp"))?;
        let entry: Entry =
            serde_json::from_str(parts.next().ok_or(ArchiveError::Invalid("missing CDXJ JSON"))?)?;
        validate_path(&entry.filename)?;
        if key != searchable_url(&entry.url)?
            || !matches!(timestamp.len(), 14 | 17)
            || !timestamp.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(ArchiveError::Invalid("invalid CDXJ lookup prefix"));
        }
        let member = members
            .get(&(entry.filename.clone(), entry.offset))
            .ok_or(ArchiveError::Invalid("CDXJ member unavailable"))?;
        let actual_timestamp = if timestamp.len() == 14 {
            member.date.format("%Y%m%d%H%M%S").to_string()
        } else {
            member.date.format("%Y%m%d%H%M%S%3f").to_string()
        };
        let status_matches = match member.status {
            Some(status) => {
                entry.status.as_u64() == Some(u64::from(status))
                    || entry.status.as_str().and_then(|value| value.parse::<u16>().ok()) == Some(status)
            }
            None => entry.status.as_str() == Some("-"),
        };
        if entry.length != member.length
            || entry.digest != member.payload_digest
            || Some(&entry.url) != member.target.as_ref()
            || entry.mime != member.mime
            || !status_matches
            || timestamp != actual_timestamp
        {
            return Err(ArchiveError::Invalid("CDXJ metadata or range mismatch"));
        }
        previous = row;
        count += 1;
        if count > u64::from(limits.records) {
            return Err(ArchiveError::Limit("CDXJ count"));
        }
    }
    Ok(count)
}
