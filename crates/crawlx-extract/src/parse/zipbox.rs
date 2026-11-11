//! Bounded access to zip containers (OOXML, ODF, EPUB).
//!
//! Every read charges the decompressed bytes against one shared budget
//! ([`ParseLimits::max_uncompressed_bytes`]), so a zip bomb fails with
//! [`ParseError::TooLarge`] after at most `budget + 1` bytes were inflated, whatever sizes the
//! central directory claims. The number of entries and the sum of the *declared* sizes are
//! checked up front, before any entry is touched.

use std::io::{Cursor, Read};

use zip::result::ZipError;
use zip::ZipArchive;

use super::{ParseError, ParseLimits};

/// A zip archive plus its decompression budget.
pub(crate) struct ZipBox<'a> {
    zip: ZipArchive<Cursor<&'a [u8]>>,
    format: &'static str,
    limit: usize,
    budget: usize,
}

fn map_zip(format: &'static str, e: ZipError) -> ParseError {
    match e {
        ZipError::InvalidPassword => ParseError::Encrypted { format },
        ZipError::UnsupportedArchive(m) if m == ZipError::PASSWORD_REQUIRED => {
            ParseError::Encrypted { format }
        }
        other => ParseError::corrupt_from(format, "the zip container cannot be read", other),
    }
}

impl<'a> ZipBox<'a> {
    /// Open `bytes` as a zip archive.
    ///
    /// # Errors
    /// [`ParseError::Corrupt`] when it is not a zip archive, [`ParseError::TooLarge`] for too many
    /// entries or a declared uncompressed size above the limit.
    pub(crate) fn open(
        bytes: &'a [u8],
        format: &'static str,
        limits: &ParseLimits,
    ) -> Result<Self, ParseError> {
        let mut zip = ZipArchive::new(Cursor::new(bytes)).map_err(|e| map_zip(format, e))?;
        if zip.len() > limits.max_entries {
            return Err(ParseError::TooLarge {
                what: "archive entries",
                limit: limits.max_entries,
                actual: zip.len(),
            });
        }
        let mut declared: u64 = 0;
        for i in 0..zip.len() {
            let f = zip.by_index_raw(i).map_err(|e| map_zip(format, e))?;
            declared = declared.saturating_add(f.size());
        }
        let limit_u64 = u64::try_from(limits.max_uncompressed_bytes).unwrap_or(u64::MAX);
        if declared > limit_u64 {
            return Err(ParseError::TooLarge {
                what: "uncompressed bytes",
                limit: limits.max_uncompressed_bytes,
                actual: usize::try_from(declared).unwrap_or(usize::MAX),
            });
        }
        Ok(Self {
            zip,
            format,
            limit: limits.max_uncompressed_bytes,
            budget: limits.max_uncompressed_bytes,
        })
    }

    /// Number of physical entries, including directories and duplicate names.
    pub(crate) fn len(&self) -> usize {
        self.zip.len()
    }

    /// Physical entry sizes. Ordinals, rather than names, preserve duplicate-entry identity.
    pub(crate) fn entry_info(&mut self, index: usize) -> Result<(u64, u64, bool), ParseError> {
        let file = self
            .zip
            .by_index_raw(index)
            .map_err(|error| map_zip(self.format, error))?;
        Ok((file.size(), file.compressed_size(), file.is_dir()))
    }

    /// Supported media type inferred from extension; no archive name leaves the parser.
    pub(crate) fn entry_mime(&mut self, index: usize) -> Result<Option<&'static str>, ParseError> {
        let file = self
            .zip
            .by_index_raw(index)
            .map_err(|error| map_zip(self.format, error))?;
        let name = file.name().map_err(|error| map_zip(self.format, error))?;
        Ok(name.rsplit_once('.').and_then(|(_, extension)| {
            if extension.eq_ignore_ascii_case("rss") {
                Some("application/rss+xml")
            } else if extension.eq_ignore_ascii_case("atom") {
                Some("application/atom+xml")
            } else {
                super::ParseFormat::from_extension(extension).map(|format| format.content_type())
            }
        }))
    }

    /// Read one physical entry under this container's shared byte budget.
    /// `check` runs before each finite decompression chunk, including the first.
    pub(crate) fn read_index(
        &mut self,
        index: usize,
        mut check: impl FnMut() -> Result<(), ParseError>,
    ) -> Result<Vec<u8>, ParseError> {
        check()?;
        let mut file = self
            .zip
            .by_index(index)
            .map_err(|error| map_zip(self.format, error))?;
        let mut output = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            check()?;
            let available = self.budget.saturating_add(1).min(chunk.len());
            let read = file.read(&mut chunk[..available]).map_err(|error| {
                ParseError::corrupt_from(self.format, "a zip entry cannot be inflated", error)
            })?;
            if read == 0 {
                return Ok(output);
            }
            if read > self.budget {
                return Err(ParseError::TooLarge {
                    what: "uncompressed bytes",
                    limit: self.limit,
                    actual: self.limit.saturating_add(1),
                });
            }
            output.try_reserve(read).map_err(|error| {
                ParseError::corrupt_from(self.format, "entry buffer allocation failed", error)
            })?;
            output.extend_from_slice(&chunk[..read]);
            self.budget -= read;
        }
    }

    /// Whether an entry named exactly `name` exists.
    pub(crate) fn has(&self, name: &str) -> bool {
        self.zip.file_names().any(|n| n.is_ok_and(|n| n == name))
    }

    /// Read the entry `name`; `Ok(None)` when it does not exist.
    ///
    /// # Errors
    /// [`ParseError::TooLarge`] when the budget is exhausted, [`ParseError::Corrupt`] for a
    /// damaged entry.
    pub(crate) fn read(&mut self, name: &str) -> Result<Option<Vec<u8>>, ParseError> {
        let format = self.format;
        let file = match self.zip.by_name(name) {
            Ok(f) => f,
            Err(ZipError::FileNotFound) => return Ok(None),
            Err(e) => return Err(map_zip(format, e)),
        };
        let cap = u64::try_from(self.budget).unwrap_or(u64::MAX).saturating_add(1);
        let mut buf = Vec::new();
        file.take(cap)
            .read_to_end(&mut buf)
            .map_err(|e| ParseError::corrupt_from(format, "a zip entry cannot be inflated", e))?;
        if buf.len() > self.budget {
            return Err(ParseError::TooLarge {
                what: "uncompressed bytes",
                limit: self.limit,
                actual: self.limit.saturating_add(1),
            });
        }
        self.budget -= buf.len();
        Ok(Some(buf))
    }

    /// Like [`ZipBox::read`] for an entry that must exist.
    ///
    /// # Errors
    /// As [`ZipBox::read`], plus [`ParseError::Corrupt`] when the entry is missing.
    pub(crate) fn require(&mut self, name: &str) -> Result<Vec<u8>, ParseError> {
        self.read(name)?
            .ok_or_else(|| ParseError::corrupt(self.format, format!("missing part {name}")))
    }

    /// Inflate every entry into a sink under the budget. Used before handing the archive to a
    /// parser that reads entries without limits.
    ///
    /// # Errors
    /// [`ParseError::TooLarge`] when the real decompressed size exceeds the limit.
    pub(crate) fn verify_all(&mut self) -> Result<(), ParseError> {
        let format = self.format;
        let mut remaining = self.limit;
        for i in 0..self.zip.len() {
            let file = self.zip.by_index(i).map_err(|e| map_zip(format, e))?;
            let cap = u64::try_from(remaining).unwrap_or(u64::MAX).saturating_add(1);
            let n = std::io::copy(&mut file.take(cap), &mut std::io::sink())
                .map_err(|e| ParseError::corrupt_from(format, "a zip entry cannot be inflated", e))?;
            let n = usize::try_from(n).unwrap_or(usize::MAX);
            if n > remaining {
                return Err(ParseError::TooLarge {
                    what: "uncompressed bytes",
                    limit: self.limit,
                    actual: self.limit.saturating_add(1),
                });
            }
            remaining -= n;
        }
        Ok(())
    }
}
