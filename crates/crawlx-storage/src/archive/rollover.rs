//! Record-boundary WARC rollover shared by offline exports and live finalization.

use super::{staging::StagedFile, warc, ArchiveError, Limits};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

/// Disk-backed writer with a hard optional encoded cap and aggregate WARC accounting.
/// Records are staged before destination selection; payloads never accumulate in memory.
#[non_exhaustive]
pub struct Writer {
    output: StagedFile,
    name: String,
    files: Vec<(String, StagedFile)>,
    rollover_bytes: Option<u64>,
    total_bytes: u64,
    records: u32,
    limits: Limits,
}

impl Writer {
    /// Open a new anonymous WARC collection.
    ///
    /// # Errors
    /// Returns an error for invalid caps or staging I/O failures.
    pub fn new(rollover_bytes: Option<u64>, limits: Limits) -> Result<Self, ArchiveError> {
        if rollover_bytes.is_some_and(|bytes| bytes == 0 || bytes > limits.total_bytes) {
            return Err(ArchiveError::Invalid("rollover cap"));
        }
        let name = "data.warc.gz".to_owned();
        let staged = StagedFile::new()?;
        Ok(Self {
            output: staged,
            name,
            files: Vec::new(),
            rollover_bytes,
            total_bytes: 0,
            records: 0,
            limits,
        })
    }

    /// Encode one record into a disk spool, then append it to its selected WARC file.
    ///
    /// # Errors
    /// Returns codec, I/O, aggregate-limit, or typed single-record rollover errors.
    pub fn write_record<R: Read + Seek>(
        &mut self,
        header: &warc::RecordHeader,
        block: &mut R,
        length: u64,
    ) -> Result<(warc::RecordSummary, String), ArchiveError> {
        if self.rollover_bytes.is_none() {
            if self.records >= self.limits.records {
                return Err(ArchiveError::Limit("WARC record count"));
            }
            // Preserve the default direct writer; only rollover needs a record spool.
            let summary = warc::write_record(self.output.file_mut(), header, block, length, self.limits)?;
            self.total_bytes = self
                .total_bytes
                .checked_add(summary.length)
                .filter(|bytes| *bytes <= self.limits.total_bytes)
                .ok_or(ArchiveError::Limit("aggregate WARC bytes"))?;
            self.records += 1;
            let filename = self.name.clone();
            return Ok((summary, filename));
        }
        let mut staged = StagedFile::new()?;
        // Input and headers retain their per-record bounds. Apply encoded bounds after
        // compression so an oversized member reports the typed rollover error first.
        let mut staging_limits = self.limits;
        staging_limits.total_bytes = u64::MAX;
        let mut summary = warc::write_record(staged.file_mut(), header, block, length, staging_limits)?;
        let filename = self.append(staged.file_mut(), &mut summary)?;
        Ok((summary, filename))
    }

    /// Append one already inspected, disk-backed gzip member and set its file-relative offset.
    ///
    /// # Errors
    /// Rejects mismatched staging lengths, oversized members, aggregate bounds, and I/O errors.
    pub fn append(
        &mut self,
        staged: &mut File,
        summary: &mut warc::RecordSummary,
    ) -> Result<String, ArchiveError> {
        let length = staged.metadata()?.len();
        if self.records >= self.limits.records {
            return Err(ArchiveError::Limit("WARC record count"));
        }
        if summary.offset != 0 || summary.length != length {
            return Err(ArchiveError::Invalid("staged record range mismatch"));
        }
        if let Some(cap) = self.rollover_bytes {
            if length > cap {
                return Err(ArchiveError::RecordExceedsRollover {
                    encoded_bytes: length,
                    rollover_bytes: cap,
                });
            }
        }
        let total = self
            .total_bytes
            .checked_add(length)
            .filter(|bytes| *bytes <= self.limits.total_bytes)
            .ok_or(ArchiveError::Limit("aggregate WARC bytes"))?;
        let mut offset = self.output.file_mut().stream_position()?;
        if self
            .rollover_bytes
            .is_some_and(|cap| offset > cap.saturating_sub(length))
        {
            if self.files.len().saturating_add(1) >= self.limits.resources {
                return Err(ArchiveError::Limit("WARC resource count"));
            }
            self.output.file().sync_all()?;
            // Keep the historical first name; subsequent names follow physical record order.
            let name = format!("data-{:05}.warc.gz", self.files.len().saturating_add(1));
            let previous = std::mem::replace(&mut self.output, StagedFile::new()?);
            let previous_name = std::mem::replace(&mut self.name, name);
            self.files.push((previous_name, previous));
            offset = 0;
        }
        staged.seek(SeekFrom::Start(0))?;
        let copied = std::io::copy(&mut staged.take(length), self.output.file_mut())?;
        if copied != length {
            return Err(ArchiveError::Invalid("short staged record"));
        }
        summary.offset = offset;
        self.total_bytes = total;
        self.records += 1;
        Ok(self.name.clone())
    }

    /// Sync all WARC files and return ordered resource names and their held anonymous sources.
    ///
    /// # Errors
    /// Returns an error if syncing the final file fails.
    pub fn finish(mut self) -> Result<Vec<(String, StagedFile)>, ArchiveError> {
        self.output.file().sync_all()?;
        self.files.push((self.name, self.output));
        Ok(self
            .files
            .into_iter()
            .map(|(name, path)| (format!("archive/{name}"), path))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn exact_cap_rolls_before_append_and_aggregate_limit_spans_files() {
        let mut staged = StagedFile::new().unwrap();
        let header = warc::RecordHeader {
            fields: BTreeMap::from([
                (
                    "WARC-Record-ID".into(),
                    "<urn:uuid:00000000-0000-8000-8000-000000000001>".into(),
                ),
                ("WARC-Type".into(), "resource".into()),
                ("WARC-Date".into(), "2026-11-06T00:00:00Z".into()),
                ("WARC-Target-URI".into(), "https://example.test/".into()),
                ("Content-Type".into(), "text/plain".into()),
            ]),
            payload_offset: 0,
        };
        let summary = warc::write_record(
            staged.file_mut(),
            &header,
            &mut std::io::Cursor::new(b"retained text"),
            13,
            Limits::default(),
        )
        .unwrap();
        let cap = summary.length;
        let mut writer = Writer::new(Some(cap), Limits::default()).unwrap();
        assert_eq!(
            writer.append(staged.file_mut(), &mut summary.clone()).unwrap(),
            "data.warc.gz"
        );
        let mut second = summary.clone();
        assert_eq!(
            writer.append(staged.file_mut(), &mut second).unwrap(),
            "data-00001.warc.gz"
        );
        assert_eq!(second.offset, 0);
        let files = writer.finish().unwrap();
        assert_eq!(files.len(), 2);
        assert!(files
            .iter()
            .all(|(_, source)| source.file().metadata().unwrap().len() == cap));

        let limits = Limits {
            total_bytes: cap * 2 - 1,
            ..Limits::default()
        };
        let mut writer = Writer::new(Some(cap), limits).unwrap();
        writer.append(staged.file_mut(), &mut summary.clone()).unwrap();
        assert!(matches!(
            writer.append(staged.file_mut(), &mut summary.clone()),
            Err(ArchiveError::Limit("aggregate WARC bytes"))
        ));
        assert_eq!(writer.finish().unwrap().len(), 1);

        let mut writer = Writer::new(Some(cap - 1), Limits::default()).unwrap();
        assert!(matches!(writer.append(staged.file_mut(), &mut summary.clone()),
            Err(ArchiveError::RecordExceedsRollover { encoded_bytes, rollover_bytes })
            if encoded_bytes == cap && rollover_bytes == cap - 1));
        let files = writer.finish().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].1.file().metadata().unwrap().len(), 0);

        let limits = Limits {
            records: 1,
            ..Limits::default()
        };
        let mut writer = Writer::new(Some(cap), limits).unwrap();
        writer.append(staged.file_mut(), &mut summary.clone()).unwrap();
        assert!(matches!(
            writer.append(staged.file_mut(), &mut summary.clone()),
            Err(ArchiveError::Limit("WARC record count"))
        ));
        assert_eq!(writer.finish().unwrap().len(), 1);

        let limits = Limits {
            resources: 1,
            ..Limits::default()
        };
        let mut writer = Writer::new(Some(cap), limits).unwrap();
        writer.append(staged.file_mut(), &mut summary.clone()).unwrap();
        assert!(matches!(
            writer.append(staged.file_mut(), &mut summary.clone()),
            Err(ArchiveError::Limit("WARC resource count"))
        ));
        assert_eq!(writer.finish().unwrap().len(), 1);
    }
}
