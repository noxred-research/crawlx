//! Bounded, resumable streaming of feed rows: XML item rows and CSV records.
//!
//! [`FeedRowStream`] reads any [`std::io::Read`] through one fixed chunk buffer and yields one
//! typed [`StreamRow`] at a time, so peak memory depends on [`StreamLimits`], never on the
//! source size. Every row carries a [`StreamCursor`] (byte offset, row index and a digest of the
//! consumed prefix) that serializes to a short token; [`FeedRowStream::resume`] over the same
//! source yields exactly the rows after that cursor, or fails with
//! [`FeedStreamError::CursorMismatch`] when the consumed prefix changed.
//!
//! A malformed row (bad quoting, wrong column count, missing required field, undefined entity,
//! oversize row) becomes a [`RowOutcome::Malformed`] and the stream continues. Structural
//! failures (broken XML, `DOCTYPE`, an oversize single event, I/O errors) end the stream with one
//! `Err` item.
//!
//! No I/O beyond reading the supplied source is performed. There is no entity table and no
//! DTD processing: a `DOCTYPE` ends the stream and any entity other than the five predefined ones
//! and numeric character references marks the row malformed, so document content can never cause
//! a read or a network call.

mod csv;
mod reader;
mod template;
mod xml;

use crawlx_core::hash::Digest;
use csv::CsvRows;
use reader::HashedReader;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::str::FromStr;
pub use template::{CsvHeader, CsvTemplate, FeedTemplate, XmlField, XmlName, XmlTemplate};
use xml::XmlRows;

/// Digest of `bytes` as a consumed stream prefix; equals the digest in a cursor whose byte offset
/// is `bytes.len()` when `bytes` are the first bytes of the source.
#[must_use]
pub fn prefix_digest(bytes: &[u8]) -> Digest {
    reader::prefix_digest(bytes)
}

/// Resource bounds of one stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamLimits {
    /// Maximum bytes one row (or one XML event) may occupy; larger rows are malformed.
    pub max_row_bytes: usize,
    /// Maximum XML element nesting.
    pub max_nesting: usize,
    /// Size of the single read chunk buffer.
    pub read_chunk: usize,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_row_bytes: 64 * 1024,
            max_nesting: 64,
            read_chunk: 8 * 1024,
        }
    }
}

/// Durable resume position: everything before it was consumed and verified by digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamCursor {
    /// Source bytes consumed up to the end of the last row.
    pub byte_offset: u64,
    /// Rows (well-formed and malformed) completed before this position.
    pub row_index: u64,
    /// Digest of the consumed source bytes (see [`prefix_digest`]).
    pub source_digest: Digest,
}

impl StreamCursor {
    /// Position before any row.
    #[must_use]
    pub fn start() -> Self {
        Self {
            byte_offset: 0,
            row_index: 0,
            source_digest: reader::empty_digest(),
        }
    }
}

impl fmt::Display for StreamCursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fs1:{}:{}:{}",
            self.byte_offset,
            self.row_index,
            self.source_digest.to_hex()
        )
    }
}

impl FromStr for StreamCursor {
    type Err = FeedStreamError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bad = |reason: &str| FeedStreamError::Cursor(reason.to_owned());
        let mut parts = text.split(':');
        if parts.next() != Some("fs1") {
            return Err(bad("unknown cursor version"));
        }
        let mut number = |label: &str| {
            parts
                .next()
                .and_then(|part| part.parse::<u64>().ok())
                .ok_or_else(|| bad(label))
        };
        let byte_offset = number("invalid byte offset")?;
        let row_index = number("invalid row index")?;
        let source_digest = parts
            .next()
            .and_then(|part| Digest::from_hex(part).ok())
            .ok_or_else(|| bad("invalid source digest"))?;
        if parts.next().is_some() {
            return Err(bad("trailing cursor data"));
        }
        Ok(Self {
            byte_offset,
            row_index,
            source_digest,
        })
    }
}

/// Reason one row is unusable; the stream continues after it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RowFault {
    /// A required field is absent or empty.
    #[error("required field `{0}` is missing or empty")]
    MissingField(String),
    /// A CSV record has another column count than the header.
    #[error("expected {expected} columns, found {found}")]
    FieldCount {
        /// Columns the header defines.
        expected: usize,
        /// Columns the record has.
        found: usize,
    },
    /// A CSV quote appears where it is not allowed.
    #[error("misplaced quote")]
    InvalidQuote,
    /// A quoted CSV field is not closed before the end of the source.
    #[error("unterminated quoted field")]
    UnterminatedQuote,
    /// A CSV field is not valid UTF-8 (invalid UTF-8 inside XML ends the stream instead).
    #[error("row is not valid utf-8")]
    InvalidUtf8,
    /// An entity reference is neither predefined nor a numeric character reference.
    #[error("undefined or malformed entity reference")]
    InvalidReference,
    /// An attribute is malformed or uses an undeclared namespace prefix.
    #[error("malformed attribute")]
    InvalidAttribute,
    /// The row is larger than the configured limit.
    #[error("row exceeds {limit} bytes")]
    RowTooLarge {
        /// Configured `max_row_bytes`.
        limit: usize,
    },
}

/// Result of one row: mapped fields (sorted by name) or the reason it is malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowOutcome {
    /// Well-formed row.
    Row(BTreeMap<String, String>),
    /// Malformed row; the stream continues.
    Malformed(RowFault),
}

/// One streamed row with the cursor that resumes after it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamRow {
    /// Zero-based position among all rows of the source.
    pub index: u64,
    /// Row or malformed-row outcome.
    pub outcome: RowOutcome,
    /// Cursor positioned right after this row.
    pub cursor: StreamCursor,
}

/// Failure that ends a stream.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FeedStreamError {
    /// The row template is invalid.
    #[error("invalid stream template: {0}")]
    Template(String),
    /// A cursor token could not be parsed.
    #[error("invalid stream cursor: {0}")]
    Cursor(String),
    /// The source does not reproduce the cursor's offset and prefix digest.
    #[error("source does not match the resume cursor")]
    CursorMismatch,
    /// The XML source declares a document type.
    #[error("doctype declarations are forbidden")]
    Doctype,
    /// The XML declaration names an encoding other than UTF-8.
    #[error("only utf-8 xml is supported")]
    Encoding,
    /// A resource bound was exceeded.
    #[error("stream limit exceeded: {0}")]
    Limit(&'static str),
    /// The XML is not well-formed.
    #[error("malformed xml stream")]
    Xml(#[source] quick_xml::Error),
    /// The XML structure is unusable.
    #[error("malformed xml structure: {0}")]
    Structure(&'static str),
    /// The CSV header row is missing or unusable.
    #[error("invalid csv header: {0}")]
    Header(String),
    /// Reading the source failed.
    #[error("reading the stream source failed")]
    Io(#[source] std::io::Error),
}

/// Counters of one stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct StreamStats {
    /// Rows read from the source, including rows skipped while resuming.
    pub rows: u64,
    /// Malformed rows among them.
    pub malformed: u64,
    /// Source bytes consumed.
    pub bytes: u64,
    /// Largest number of bytes the stream held at once (chunk buffer, parser buffer, open row).
    pub peak_buffered_bytes: usize,
}

enum Source<R> {
    Xml(Box<XmlRows<R>>),
    Csv(Box<CsvRows<R>>),
}

/// Iterator over the rows of one source; ends after the first `Err`.
pub struct FeedRowStream<R> {
    source: Source<R>,
    next_index: u64,
    resume: Option<StreamCursor>,
    done: bool,
    malformed: u64,
}

impl<R: Read> FeedRowStream<R> {
    /// Stream `source` from its beginning.
    ///
    /// # Errors
    /// Rejects invalid templates and zero limits.
    pub fn new(source: R, template: &FeedTemplate, limits: StreamLimits) -> Result<Self, FeedStreamError> {
        if limits.max_row_bytes == 0 || limits.max_nesting == 0 {
            return Err(FeedStreamError::Template(
                "stream limits must be positive".to_owned(),
            ));
        }
        let reader = HashedReader::new(source, limits.read_chunk);
        let source = match template {
            FeedTemplate::Xml(template) => {
                template.validate()?;
                Source::Xml(Box::new(XmlRows::new(
                    reader,
                    template,
                    limits.max_row_bytes,
                    limits.max_nesting,
                )?))
            }
            FeedTemplate::Csv(template) => {
                template.validate()?;
                Source::Csv(Box::new(CsvRows::new(reader, template, limits.max_row_bytes)))
            }
        };
        Ok(Self {
            source,
            next_index: 0,
            resume: None,
            done: false,
            malformed: 0,
        })
    }

    /// Stream `source` (the same bytes from the beginning) and yield only rows after `cursor`.
    ///
    /// The prefix is parsed again without retaining rows, so memory stays bounded; the cursor's
    /// offset and digest are verified at its row boundary.
    ///
    /// # Errors
    /// Same as [`Self::new`], plus [`FeedStreamError::CursorMismatch`] on a start cursor that is
    /// not [`StreamCursor::start`].
    pub fn resume(
        source: R,
        template: &FeedTemplate,
        limits: StreamLimits,
        cursor: &StreamCursor,
    ) -> Result<Self, FeedStreamError> {
        let mut stream = Self::new(source, template, limits)?;
        if cursor.row_index == 0 {
            if *cursor != StreamCursor::start() {
                return Err(FeedStreamError::CursorMismatch);
            }
        } else {
            stream.resume = Some(*cursor);
        }
        Ok(stream)
    }

    /// Counters so far.
    #[must_use]
    pub fn stats(&self) -> StreamStats {
        let (bytes, peak_buffered_bytes) = match &self.source {
            Source::Xml(rows) => (rows.reader.get_ref().consumed(), rows.peak()),
            Source::Csv(rows) => (rows.reader.consumed(), rows.peak),
        };
        StreamStats {
            rows: self.next_index,
            malformed: self.malformed,
            bytes,
            peak_buffered_bytes,
        }
    }

    fn cursor_now(&self) -> StreamCursor {
        let (byte_offset, source_digest) = match &self.source {
            Source::Xml(rows) => {
                let reader = rows.reader.get_ref();
                (reader.consumed(), reader.digest())
            }
            Source::Csv(rows) => (rows.reader.consumed(), rows.reader.digest()),
        };
        StreamCursor {
            byte_offset,
            row_index: self.next_index,
            source_digest,
        }
    }

    fn next_outcome(&mut self) -> Result<Option<RowOutcome>, FeedStreamError> {
        match &mut self.source {
            Source::Xml(rows) => rows.next_outcome(),
            Source::Csv(rows) => rows.next_outcome(),
        }
    }
}

impl<R: Read> Iterator for FeedRowStream<R> {
    type Item = Result<StreamRow, FeedStreamError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                return None;
            }
            match self.next_outcome() {
                Ok(Some(outcome)) => {
                    let index = self.next_index;
                    self.next_index += 1;
                    if matches!(outcome, RowOutcome::Malformed(_)) {
                        self.malformed += 1;
                    }
                    if let Some(target) = self.resume {
                        if self.next_index < target.row_index {
                            continue;
                        }
                        if self.next_index == target.row_index {
                            if self.cursor_now() != target {
                                self.done = true;
                                return Some(Err(FeedStreamError::CursorMismatch));
                            }
                            self.resume = None;
                            continue;
                        }
                    }
                    return Some(Ok(StreamRow {
                        index,
                        outcome,
                        cursor: self.cursor_now(),
                    }));
                }
                Ok(None) => {
                    self.done = true;
                    return self.resume.map(|_| Err(FeedStreamError::CursorMismatch));
                }
                Err(error) => {
                    self.done = true;
                    return Some(Err(error));
                }
            }
        }
    }
}
