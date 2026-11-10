//! Bounded streaming CSV record reader producing typed row outcomes.

use super::reader::HashedReader;
use super::template::{CsvHeader, CsvTemplate};
use super::{FeedStreamError, RowFault, RowOutcome};
use std::collections::BTreeMap;
use std::io::{BufRead, Read};

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Unquoted,
    Quoted,
    QuoteSeen,
}

/// Incremental RFC 4180 record builder with a hard byte cap.
struct RecordBuilder {
    delimiter: u8,
    quote: u8,
    limit: usize,
    state: State,
    cur: Vec<u8>,
    fields: Vec<String>,
    fault: Option<RowFault>,
    stored: usize,
    pending_cr: bool,
}

impl RecordBuilder {
    fn new(delimiter: u8, quote: u8, limit: usize) -> Self {
        Self {
            delimiter,
            quote,
            limit,
            state: State::Start,
            cur: Vec::new(),
            fields: Vec::new(),
            fault: None,
            stored: 0,
            pending_cr: false,
        }
    }

    fn fault(&mut self, fault: RowFault) {
        self.fault.get_or_insert(fault);
    }

    fn push(&mut self, byte: u8) {
        if self.stored >= self.limit {
            self.fault(RowFault::RowTooLarge { limit: self.limit });
            return;
        }
        self.stored += 1;
        self.cur.push(byte);
    }

    fn end_field(&mut self) {
        let bytes = std::mem::take(&mut self.cur);
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => {
                self.fault(RowFault::InvalidUtf8);
                String::new()
            }
        };
        if self.fields.len() >= self.limit {
            self.fault(RowFault::RowTooLarge { limit: self.limit });
        } else {
            self.fields.push(text);
        }
        self.state = State::Start;
    }

    /// Returns true when a record is complete; blank lines reset and return false.
    fn end_record(&mut self) -> bool {
        if self.state == State::Start && self.fields.is_empty() {
            return false;
        }
        self.end_field();
        true
    }

    fn dispatch(&mut self, byte: u8) -> bool {
        let (delimiter, quote) = (self.delimiter, self.quote);
        match self.state {
            State::Quoted => {
                if byte == quote {
                    self.state = State::QuoteSeen;
                } else {
                    self.push(byte);
                }
            }
            State::QuoteSeen => {
                if byte == quote {
                    self.push(quote);
                    self.state = State::Quoted;
                } else if byte == delimiter {
                    self.end_field();
                } else if byte == b'\n' {
                    return self.end_record();
                } else {
                    self.fault(RowFault::InvalidQuote);
                    self.state = State::Unquoted;
                }
            }
            State::Start | State::Unquoted => {
                if byte == delimiter {
                    self.end_field();
                } else if byte == b'\n' {
                    return self.end_record();
                } else if byte == quote {
                    if self.state == State::Start {
                        self.state = State::Quoted;
                    } else {
                        self.fault(RowFault::InvalidQuote);
                    }
                } else {
                    self.state = State::Unquoted;
                    self.push(byte);
                }
            }
        }
        false
    }

    fn feed(&mut self, byte: u8) -> bool {
        if std::mem::take(&mut self.pending_cr) {
            if byte == b'\n' {
                return self.dispatch(b'\n');
            }
            self.dispatch(b'\r');
        }
        if byte == b'\r' && self.state != State::Quoted {
            self.pending_cr = true;
            return false;
        }
        self.dispatch(byte)
    }

    /// Flush at end of input; `None` when nothing was pending.
    fn finish(mut self) -> Option<Self> {
        if self.pending_cr {
            self.pending_cr = false;
            self.dispatch(b'\r');
        }
        if self.state == State::Start && self.fields.is_empty() {
            return None;
        }
        if self.state == State::Quoted {
            self.fault(RowFault::UnterminatedQuote);
        }
        self.end_field();
        Some(self)
    }

    fn retained(&self) -> usize {
        self.stored
    }
}

struct Record {
    fields: Vec<String>,
    fault: Option<RowFault>,
}

pub(super) struct CsvRows<R> {
    pub(super) reader: HashedReader<R>,
    delimiter: u8,
    quote: u8,
    header: CsvHeader,
    required: Vec<String>,
    limit: usize,
    columns: Option<Vec<Option<String>>>,
    first_record: bool,
    pub(super) peak: usize,
}

impl<R: Read> CsvRows<R> {
    pub(super) fn new(reader: HashedReader<R>, template: &CsvTemplate, limit: usize) -> Self {
        Self {
            reader,
            delimiter: template.delimiter,
            quote: template.quote,
            header: template.header.clone(),
            required: template.required.clone(),
            limit,
            columns: None,
            first_record: true,
            peak: 0,
        }
    }

    fn read_record(&mut self) -> Result<Option<Record>, FeedStreamError> {
        let mut builder = RecordBuilder::new(self.delimiter, self.quote, self.limit);
        loop {
            let chunk = self.reader.fill_buf().map_err(FeedStreamError::Io)?;
            if chunk.is_empty() {
                let Some(done) = builder.finish() else {
                    return Ok(None);
                };
                return Ok(Some(self.record(done)));
            }
            let mut used = chunk.len();
            let mut complete = false;
            for (index, &byte) in chunk.iter().enumerate() {
                if builder.feed(byte) {
                    used = index + 1;
                    complete = true;
                    break;
                }
            }
            self.reader.consume(used);
            if complete {
                return Ok(Some(self.record(builder)));
            }
        }
    }

    fn record(&mut self, builder: RecordBuilder) -> Record {
        self.peak = self.peak.max(self.reader.chunk_len() + builder.retained());
        let mut fields = builder.fields;
        if self.first_record {
            self.first_record = false;
            if let Some(first) = fields.first_mut() {
                if let Some(stripped) = first.strip_prefix('\u{feff}') {
                    *first = stripped.to_owned();
                }
            }
        }
        Record {
            fields,
            fault: builder.fault,
        }
    }

    fn resolve_columns(&mut self) -> Result<(), FeedStreamError> {
        if self.columns.is_some() {
            return Ok(());
        }
        let columns: Vec<Option<String>> = match &self.header {
            CsvHeader::Positional(names) => names.iter().cloned().map(Some).collect(),
            CsvHeader::FirstRow { rename } => {
                let rename = rename.clone();
                let record = self
                    .read_record()?
                    .ok_or_else(|| FeedStreamError::Header("csv source has no header row".to_owned()))?;
                if record.fault.is_some() {
                    return Err(FeedStreamError::Header("csv header row is malformed".to_owned()));
                }
                let mapped: Vec<Option<String>> = if rename.is_empty() {
                    record.fields.iter().cloned().map(Some).collect()
                } else {
                    for header in rename.keys() {
                        if !record.fields.contains(header) {
                            return Err(FeedStreamError::Header(format!(
                                "csv header `{header}` not found"
                            )));
                        }
                    }
                    record
                        .fields
                        .iter()
                        .map(|header| rename.get(header).cloned())
                        .collect()
                };
                let mut seen = std::collections::BTreeSet::new();
                for name in mapped.iter().flatten() {
                    if name.is_empty() || !seen.insert(name.as_str()) {
                        return Err(FeedStreamError::Header(
                            "csv header has an empty or duplicate column name".to_owned(),
                        ));
                    }
                }
                if let Some(missing) = self.required.iter().find(|name| !seen.contains(name.as_str())) {
                    return Err(FeedStreamError::Header(format!(
                        "required csv field `{missing}` is not in the header"
                    )));
                }
                mapped
            }
        };
        self.columns = Some(columns);
        Ok(())
    }

    pub(super) fn next_outcome(&mut self) -> Result<Option<RowOutcome>, FeedStreamError> {
        self.resolve_columns()?;
        let Some(record) = self.read_record()? else {
            return Ok(None);
        };
        let Some(columns) = self.columns.as_ref() else {
            return Ok(None);
        };
        if let Some(fault) = record.fault {
            return Ok(Some(RowOutcome::Malformed(fault)));
        }
        if record.fields.len() != columns.len() {
            return Ok(Some(RowOutcome::Malformed(RowFault::FieldCount {
                expected: columns.len(),
                found: record.fields.len(),
            })));
        }
        let mut row = BTreeMap::new();
        for (name, value) in columns.iter().zip(record.fields) {
            if let Some(name) = name {
                row.insert(name.clone(), value);
            }
        }
        if let Some(missing) = self
            .required
            .iter()
            .find(|name| row.get(name.as_str()).is_none_or(String::is_empty))
        {
            return Ok(Some(RowOutcome::Malformed(RowFault::MissingField(
                missing.clone(),
            ))));
        }
        Ok(Some(RowOutcome::Row(row)))
    }
}
