//! Spreadsheet helpers shared by the xlsx, xlsb, xls (calamine) and ods readers: sparse cell
//! collection under the row/column limits and the conversion of a sheet to blocks.

use std::collections::BTreeMap;

use calamine::{Data, DataRef};

use super::blocks::{Block, Span};
use super::ParseLimits;

/// Widest sheet that is rendered; further columns are dropped with a warning.
pub(crate) const MAX_COLUMNS: u32 = 1024;

/// A sheet reduced to its non-empty rows.
#[derive(Debug, Default)]
pub(crate) struct Sheet {
    /// Sheet name.
    pub name: String,
    rows: BTreeMap<u32, BTreeMap<u32, String>>,
    /// Rows were dropped by the row limit.
    pub rows_truncated: bool,
    /// Columns were dropped by the column limit.
    pub columns_truncated: bool,
}

impl Sheet {
    /// An empty sheet.
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }

    /// Store `text` at (`row`, `col`), 0-based. Empty text and cells outside the limits are
    /// dropped (the latter set the truncation flags). Returns `false` once the row limit is hit
    /// so a row-major reader can stop.
    pub(crate) fn put(&mut self, row: u32, col: u32, text: String, limits: &ParseLimits) -> bool {
        if text.trim().is_empty() {
            return true;
        }
        if !self.rows.contains_key(&row) && self.rows.len() >= limits.max_rows {
            self.rows_truncated = true;
            return false;
        }
        if col >= MAX_COLUMNS {
            self.columns_truncated = true;
            return true;
        }
        self.rows.entry(row).or_default().insert(col, text);
        true
    }

    /// The sheet as a table block (header row first), `None` when it holds no text.
    pub(crate) fn table(&self) -> Option<Block> {
        let first_col = self
            .rows
            .values()
            .filter_map(|r| r.keys().next().copied())
            .min()?;
        let last_col = self
            .rows
            .values()
            .filter_map(|r| r.keys().next_back().copied())
            .max()?;
        let width = usize::try_from(last_col - first_col + 1).unwrap_or(usize::MAX);
        let rows = self
            .rows
            .values()
            .map(|cells| {
                let mut row = vec![Vec::new(); width];
                for (c, t) in cells {
                    let idx = usize::try_from(*c - first_col).unwrap_or(0);
                    row[idx] = vec![Span::plain(t.replace(['\n', '\r'], " "))];
                }
                row
            })
            .collect();
        Some(Block::Table(rows))
    }
}

/// Append `sheets` to `blocks` as `## name` headings followed by tables, and the findings to
/// `warnings`.
pub(crate) fn render(sheets: &[Sheet], blocks: &mut Vec<Block>, warnings: &mut Vec<String>) {
    for sh in sheets {
        blocks.push(Block::Heading {
            level: 2,
            spans: vec![Span::plain(sh.name.clone())],
        });
        if let Some(t) = sh.table() {
            blocks.push(t);
        }
        if sh.rows_truncated {
            warnings.push(format!(
                "sheet {:?}: rows beyond the row limit were dropped",
                sh.name
            ));
        }
        if sh.columns_truncated {
            warnings.push(format!(
                "sheet {:?}: columns beyond column {MAX_COLUMNS} were dropped",
                sh.name
            ));
        }
    }
}

fn float_text(f: f64) -> String {
    if f.is_finite() && f.fract() == 0.0 && f.abs() < 1e15 {
        // Integral and below 1e15: the conversion is exact.
        format!("{f:.0}")
    } else {
        f.to_string()
    }
}

fn date_text(dt: &calamine::ExcelDateTime) -> String {
    if dt.is_duration() {
        let total = (dt.as_f64() * 86_400.0).round();
        if total.is_finite() && total.abs() < 1e12 {
            // |total| < 1e12: fits i64 exactly.
            #[allow(clippy::cast_possible_truncation)]
            let secs = total as i64;
            let sign = if secs < 0 { "-" } else { "" };
            let s = secs.unsigned_abs();
            return format!("{sign}{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60);
        }
        return dt.as_f64().to_string();
    }
    match dt.as_datetime() {
        Some(d) => {
            let s = d.to_string();
            s.strip_suffix(" 00:00:00").map_or(s.clone(), str::to_owned)
        }
        None => dt.as_f64().to_string(),
    }
}

/// Display text of a streamed (xlsx/xlsb) cell value.
pub(crate) fn cell_ref_text(d: &DataRef<'_>) -> String {
    match d {
        DataRef::Empty => String::new(),
        DataRef::String(s) => s.clone(),
        DataRef::SharedString(s) => (*s).to_owned(),
        DataRef::Int(i) => i.to_string(),
        DataRef::Float(f) => float_text(*f),
        DataRef::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_owned(),
        DataRef::DateTime(dt) => date_text(dt),
        DataRef::DateTimeIso(s) | DataRef::DurationIso(s) => s.clone(),
        DataRef::Error(e) => e.to_string(),
    }
}

/// Display text of an owned (xls) cell value.
pub(crate) fn cell_text(d: &Data) -> String {
    match d {
        Data::Empty => String::new(),
        Data::String(s) => s.clone(),
        Data::Int(i) => i.to_string(),
        Data::Float(f) => float_text(*f),
        Data::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_owned(),
        Data::DateTime(dt) => date_text(dt),
        Data::DateTimeIso(s) | Data::DurationIso(s) => s.clone(),
        Data::Error(e) => e.to_string(),
    }
}
