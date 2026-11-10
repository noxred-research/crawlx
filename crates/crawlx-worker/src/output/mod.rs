//! Compatibility-style output of stored pages, shared by
//! `crawlx export`, `crawlx crawl` and the API's `/pages?field=` and `/export` routes.
//!
//! * [`fields`] – the field model (`url`, `qurl`, `key`, ... and custom regex fields).
//! * [`template`] – `{{field}}` templates rendered as a cross product of field values.
//! * [`filters`] – match/filter regexes and extension allow/deny lists.
//! * [`dsl`] – the `-mdc/-fdc` condition language over the JSONL record.
//! * [`store_fields`] – per-host wordlists.
//! * [`jsonl`] – one request/response record per page.
//! * [`stored`] – `-sr/-srd` raw request/response files and their `index.txt`.
//! * [`text_file`] – the `-o FILE` writer and the `-ncb` naming rule.
//! * [`errlog`] – the `-elog` error log.
//! * [`Exporter`] – ties them together: text (one line per field/template value) or JSONL.

pub mod dsl;
pub mod errlog;
pub mod fields;
pub mod filters;
pub mod jsonl;
pub mod store_fields;
pub mod stored;
pub mod template;
pub mod text_file;

pub use dsl::{Dsl, DslError};
pub use errlog::write_error_log;
pub use fields::{extract, extract_page, Field, FieldError};
pub use filters::{expand_patterns, FilterError, OutputFilters};
pub use jsonl::{field_names, write_line, Record, Request, Response};
pub use store_fields::StoreFields;
pub use stored::StoredResponses;
pub use template::{Template, TemplateError};
pub use text_file::TextFile;

use crate::run::UrlFailure;
use crawlx_core::repo::PageRecord;
use serde_json::Value;
use std::io::Write;
use thiserror::Error;
use url::Url;

const DEFAULT_STORED_FIELDS: &[Field] = &[Field::Url];

/// The library documentation (`README.md`) is compiled as doc-tests so its examples cannot rot.
#[cfg(doctest)]
#[doc = include_str!("../../README.md")]
pub struct ReadmeDoctests;

/// What can go wrong while exporting.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OutputError {
    /// A malformed output template.
    #[error("output template")]
    Template(#[from] TemplateError),
    /// A rejected filter configuration.
    #[error("output filters")]
    Filter(#[from] FilterError),
    /// A malformed `-mdc` / `-fdc` condition.
    #[error("output condition")]
    Condition(#[from] DslError),
    /// An invalid field name.
    #[error("output field")]
    Field(#[from] FieldError),
    /// JSON serialization failed.
    #[error("serializing output record")]
    Json(#[from] serde_json::Error),
    /// Writing output or wordlists failed.
    #[error("writing output")]
    Io(#[from] std::io::Error),
}

/// Output format.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExportFormat {
    /// One line per field or template value.
    #[default]
    Text,
    /// One [`Record`] per page.
    Jsonl,
}

/// What an export produced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExportStats {
    /// Pages (or failed URLs) visited.
    pub pages: u64,
    /// Lines written.
    pub lines: u64,
    /// Lines or records dropped by the filters.
    pub filtered: u64,
    /// Raw request/response files written by `-sr`.
    pub stored: u64,
}

/// The heavy parts of a page the export may attach: the response body and the raw
/// request/response text. Neither lives in [`PageRecord`]; the caller loads them on demand
/// (see [`Exporter::export_pages_with`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PageText {
    /// The response body.
    pub body: Option<String>,
    /// The raw response text (status line, headers, blank line, body; `PageContent::raw`).
    pub raw: Option<String>,
}

impl PageText {
    /// Text with a body.
    #[must_use]
    pub fn with_body(mut self, body: impl Into<String>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Text with a raw response.
    #[must_use]
    pub fn with_raw(mut self, raw: impl Into<String>) -> Self {
        self.raw = Some(raw.into());
        self
    }
}

/// Export configuration. Text output renders `template` when set, else `fields`, else `url`.
///
/// Build it with struct update syntax (`Exporter { format, ..Exporter::default() }`); fields
/// are added over time.
#[derive(Clone, Debug, Default)]
pub struct Exporter {
    /// Output format.
    pub format: ExportFormat,
    /// Fields for text output (`-f url,path`): every value of every field on its own line, in
    /// field order. `url` when empty.
    pub fields: Vec<Field>,
    /// Template for text output (`--output-template`); wins over `fields`.
    pub template: Option<Template>,
    /// Match/filter regexes and extension lists.
    pub filters: OutputFilters,
    /// `-mdc`: keep results for which the condition holds (or a match regex hits).
    pub match_condition: Option<Dsl>,
    /// `-fdc`: drop results for which the condition holds (or a filter regex hits).
    pub filter_condition: Option<Dsl>,
    /// `-fpt`: page types (`login`, `error`, `captcha`, ...; case-insensitive) dropped from
    /// the output. The page was still crawled and stored; only this export leaves it out.
    pub filter_page_types: Vec<String>,
    /// Per-host wordlists (`--store-fields DIR`), fed with the text values of every page
    /// that passes the filters (also in JSONL mode).
    pub store_fields: Option<StoreFields>,
    /// Explicit wordlist fields, independent of text fields and template references.
    /// `None` preserves the text/template selection; `Some([])` stores no fields.
    /// Explicit selections use page-level URL/extension/type/condition filtering, independent
    /// of whether any display/template values exist. Display-line filters remain unchanged.
    pub stored_field_selection: Option<Vec<Field>>,
    /// `-sr/-srd`: store the raw request and response of every emitted page and set
    /// `response.stored_response_path`.
    pub stored_responses: Option<StoredResponses>,
    /// JSONL fields to drop (`-eof`, names from [`field_names`]).
    pub exclude_fields: Vec<String>,
    /// Include the response body in JSONL records. The reference includes it by default; here it is
    /// opt-in because the body is not part of the page row.
    pub include_body: bool,
    /// `-or`: leave `request.raw` and `response.raw` out of JSONL records.
    pub omit_raw: bool,
    /// `-ob`: leave the body out of JSONL records, even with `include_body`.
    pub omit_body: bool,
    /// `-kb`: add `response.knowledgebase` (`PageType`, `Forms`, `secrets`, `endpoints`).
    pub knowledge_base: bool,
}

impl Exporter {
    /// Is the body part of the emitted record?
    fn emit_body(&self) -> bool {
        self.include_body && !self.omit_body
    }

    fn has_conditions(&self) -> bool {
        self.match_condition.is_some() || self.filter_condition.is_some()
    }

    /// Must the body be loaded: it is emitted, stored, or read by a condition.
    fn needs_body(&self) -> bool {
        self.emit_body()
            || self.stored_responses.is_some()
            || self.match_condition.as_ref().is_some_and(Dsl::reads_body)
            || self.filter_condition.as_ref().is_some_and(Dsl::reads_body)
    }

    /// Must the raw response text be loaded: it is stored or emitted in JSONL.
    fn needs_raw(&self) -> bool {
        self.stored_responses.is_some() || (self.format == ExportFormat::Jsonl && !self.omit_raw)
    }

    /// Text lines for `url` (template > fields > `url`), before filtering.
    fn lines_for_url(&self, url: &Url, metadata: &Value) -> Vec<String> {
        match (&self.template, self.fields.as_slice()) {
            (Some(t), _) => t.render(url, metadata),
            (None, []) => fields::extract(&Field::Url, url, metadata),
            (None, fields) => fields
                .iter()
                .flat_map(|f| fields::extract(f, url, metadata))
                .collect(),
        }
    }

    /// Text lines of `page` (template > fields > `url`), before filtering.
    #[must_use]
    pub fn lines_for(&self, page: &PageRecord) -> Vec<String> {
        self.lines_for_url(&page.url.url, &page.metadata)
    }

    /// Does `page`'s type (`metadata.page_type`) put it on the `-fpt` drop list?
    fn page_type_dropped(&self, page: &PageRecord) -> bool {
        if self.filter_page_types.is_empty() {
            return false;
        }
        page.metadata
            .get("page_type")
            .and_then(Value::as_str)
            .is_some_and(|t| {
                self.filter_page_types
                    .iter()
                    .any(|f| f.trim().eq_ignore_ascii_case(t))
            })
    }

    /// The `-mdc` / `-fdc` verdicts over `record` (`None` = not configured).
    fn evaluate(&self, record: &Record) -> (Option<bool>, Option<bool>) {
        if !self.has_conditions() {
            return (None, None);
        }
        let json = serde_json::to_value(record).ok();
        let run = |d: &Dsl| json.as_ref().is_some_and(|j| d.eval_value(j));
        (
            self.match_condition.as_ref().map(run),
            self.filter_condition.as_ref().map(run),
        )
    }

    /// The full record of `page` before filtering and shaping.
    fn assemble(&self, page: &PageRecord, text: PageText) -> Record {
        let body = if self.needs_body() { text.body } else { None };
        let mut record = Record::from_page(page, body);
        if let Some(response) = record.response.as_mut() {
            response.raw = text.raw;
        }
        if self.knowledge_base {
            record.attach_knowledgebase(page);
        }
        record
    }

    /// Does the page pass the page-type drop list, the extension/regex filters and the
    /// conditions?
    fn admit(&self, page: &PageRecord, record: &Record) -> bool {
        if self.page_type_dropped(page) {
            return false;
        }
        let (matched, filtered) = self.evaluate(record);
        let url = &page.url.url;
        self.filters.accept_with(url, url.as_str(), matched, filtered)
    }

    /// Apply `-or`, `-ob` and `-eof`.
    fn shape(&self, record: &mut Record) {
        if let Some(response) = record.response.as_mut() {
            if !self.emit_body() {
                response.body = None;
            }
            if self.omit_raw {
                response.raw = None;
            }
        }
        if self.omit_raw {
            if let Some(request) = record.request.as_mut() {
                request.raw = None;
            }
        }
        record.exclude_fields(&self.exclude_fields);
    }

    /// Write the raw request/response of `record` (`-sr`) and set
    /// `response.stored_response_path`. Returns whether a file was written.
    fn store_response(&self, url: &Url, record: &mut Record) -> Result<bool, OutputError> {
        let Some(stored) = &self.stored_responses else {
            return Ok(false);
        };
        let Some(response) = record.response.as_mut() else {
            return Ok(false);
        };
        let default_request = Request::default();
        let request = record.request.as_ref().unwrap_or(&default_request);
        let request_raw = request
            .raw
            .clone()
            .unwrap_or_else(|| stored::synthesize_request(url, request));
        let response_raw = response
            .raw
            .clone()
            .unwrap_or_else(|| stored::synthesize_response(response));
        let path = stored.store(url, response.status_code, &request_raw, &response_raw)?;
        response.stored_response_path = Some(path.to_string_lossy().into_owned());
        Ok(true)
    }

    /// Text lines of `page` that pass the filters, and the number dropped. Conditions are
    /// evaluated over the record without a body.
    #[must_use]
    pub fn text_lines(&self, page: &PageRecord) -> (Vec<String>, u64) {
        self.text_lines_checked(page, None)
    }

    fn text_lines_checked(&self, page: &PageRecord, record: Option<&Record>) -> (Vec<String>, u64) {
        if self.page_type_dropped(page) {
            return (Vec::new(), 1);
        }
        let (matched, filtered) = match record {
            Some(r) => self.evaluate(r),
            None if self.has_conditions() => self.evaluate(&self.assemble(page, PageText::default())),
            None => (None, None),
        };
        let url = &page.url.url;
        let mut dropped = 0u64;
        let kept = self
            .lines_for(page)
            .into_iter()
            .filter(|line| {
                let ok = self.filters.accept_with(url, line, matched, filtered);
                if !ok {
                    dropped = dropped.saturating_add(1);
                }
                ok
            })
            .collect();
        (kept, dropped)
    }

    /// The JSONL record of `page` with `exclude_fields` applied, or `None` when the filters
    /// drop the page. `body` is attached only when `include_body` is set (and not
    /// `omit_body`). Raw responses and `-sr` storage need [`Exporter::record_with`] /
    /// [`Exporter::export_pages_with`].
    #[must_use]
    pub fn record(&self, page: &PageRecord, body: Option<String>) -> Option<Record> {
        self.record_with(page, PageText { body, raw: None })
    }

    /// [`Exporter::record`] with the raw response text too. Does not write `-sr` files.
    #[must_use]
    pub fn record_with(&self, page: &PageRecord, text: PageText) -> Option<Record> {
        let mut record = self.assemble(page, text);
        if !self.admit(page, &record) {
            return None;
        }
        self.shape(&mut record);
        Some(record)
    }

    /// The JSONL record of a URL that could not be fetched (`error` set), or `None` when the
    /// filters drop it. `-or`/`-ob`/`-eof` apply.
    #[must_use]
    pub fn failure_record(&self, url: &Url, status: Option<u16>, reason: &str) -> Option<Record> {
        let mut record = Record::from_failure(url.as_str(), status, reason);
        let (matched, filtered) = self.evaluate(&record);
        if !self.filters.accept_with(url, url.as_str(), matched, filtered) {
            return None;
        }
        self.shape(&mut record);
        Some(record)
    }

    /// Wordlist fields: the explicit selection, else template references, text fields or `url`.
    fn stored_fields(&self) -> std::borrow::Cow<'_, [Field]> {
        if let Some(fields) = &self.stored_field_selection {
            return std::borrow::Cow::Borrowed(fields);
        }
        match (&self.template, self.fields.as_slice()) {
            (Some(t), _) => t.fields().into_iter().cloned().collect::<Vec<_>>().into(),
            (None, []) => std::borrow::Cow::Borrowed(DEFAULT_STORED_FIELDS),
            (None, fields) => std::borrow::Cow::Borrowed(fields),
        }
    }

    /// Export `pages` to `out`. `bodies` supplies the raw body of a page; it is called only
    /// when the export needs bodies (`include_body` without `omit_body`, `-sr`, or a condition
    /// reading `body`).
    ///
    /// # Errors
    /// [`OutputError::Io`] on write, wordlist or `-sr` failure, [`OutputError::Json`] when a
    /// record cannot be serialized.
    pub fn export_pages<'a>(
        &self,
        pages: impl IntoIterator<Item = &'a PageRecord>,
        bodies: impl Fn(&PageRecord) -> Option<String>,
        out: &mut dyn Write,
    ) -> Result<ExportStats, OutputError> {
        let needs_body = self.needs_body();
        self.export_pages_with(
            pages,
            |page| PageText {
                body: if needs_body { bodies(page) } else { None },
                raw: None,
            },
            out,
        )
    }

    /// Export `pages` to `out`. `text` loads a page's body and raw response; it is called
    /// once per page, and only when the export needs either (see [`Exporter::export_pages`];
    /// raw is needed for `-sr` and for JSONL unless `omit_raw`).
    ///
    /// JSONL: one record per page that passes the page-type list, the extension/regex filters
    /// and the conditions, in input order; `-sr` files are written before `-or/-ob/-eof` strip
    /// the record. Text: the lines of the fields/template that pass the same filters.
    ///
    /// # Errors
    /// [`OutputError::Io`] on write, wordlist or `-sr` failure, [`OutputError::Json`] when a
    /// record cannot be serialized.
    pub fn export_pages_with<'a>(
        &self,
        pages: impl IntoIterator<Item = &'a PageRecord>,
        text: impl Fn(&PageRecord) -> PageText,
        out: &mut dyn Write,
    ) -> Result<ExportStats, OutputError> {
        let mut stats = ExportStats::default();
        let stored_fields = self.store_fields.as_ref().map(|_| self.stored_fields());
        let explicit_wordlists = stored_fields.is_some() && self.stored_field_selection.is_some();
        let wants_text = self.needs_body() || self.needs_raw();
        for page in pages {
            stats.pages = stats.pages.saturating_add(1);
            let loaded = if wants_text {
                text(page)
            } else {
                PageText::default()
            };
            match self.format {
                ExportFormat::Text => {
                    let record =
                        (self.has_conditions() || self.stored_responses.is_some() || explicit_wordlists)
                            .then(|| self.assemble(page, loaded));
                    let (kept, dropped) = self.text_lines_checked(page, record.as_ref());
                    stats.filtered = stats.filtered.saturating_add(dropped);
                    if let Some(fields) = stored_fields.as_ref().filter(|_| {
                        explicit_wordlists && record.as_ref().is_some_and(|record| self.admit(page, record))
                    }) {
                        self.store_field_values(page, fields)?;
                    }
                    if kept.is_empty() {
                        continue;
                    }
                    if let Some(mut record) = record {
                        if self.store_response(&page.url.url, &mut record)? {
                            stats.stored = stats.stored.saturating_add(1);
                        }
                    }
                    if let Some(fields) = stored_fields.as_ref().filter(|_| !explicit_wordlists) {
                        self.store_field_values(page, fields)?;
                    }
                    for line in &kept {
                        out.write_all(line.as_bytes())?;
                        out.write_all(b"\n")?;
                        stats.lines = stats.lines.saturating_add(1);
                    }
                }
                ExportFormat::Jsonl => {
                    let mut record = self.assemble(page, loaded);
                    if !self.admit(page, &record) {
                        stats.filtered = stats.filtered.saturating_add(1);
                        continue;
                    }
                    if self.store_response(&page.url.url, &mut record)? {
                        stats.stored = stats.stored.saturating_add(1);
                    }
                    self.shape(&mut record);
                    if let Some(fields) = &stored_fields {
                        self.store_field_values(page, fields)?;
                    }
                    jsonl::write_line(&record, out)?;
                    stats.lines = stats.lines.saturating_add(1);
                }
            }
        }
        out.flush()?;
        Ok(stats)
    }

    /// Export the URLs of a run that failed (`RunReport::failures`) the way the reference emits
    /// failed requests: JSONL records with `error` set, or the URL's field lines in text
    /// mode. The same extension/regex filters and conditions apply (a condition can read
    /// `error`, `status_code`, `url`); `-or/-ob/-eof` shape the records. There is no
    /// timestamp: a failed row has no fetch time.
    ///
    /// # Errors
    /// [`OutputError::Io`] on write failure, [`OutputError::Json`] when a record cannot be
    /// serialized.
    pub fn export_failures(
        &self,
        failures: &[UrlFailure],
        out: &mut dyn Write,
    ) -> Result<ExportStats, OutputError> {
        let mut stats = ExportStats::default();
        for failure in failures {
            stats.pages = stats.pages.saturating_add(1);
            let Ok(url) = Url::parse(&failure.url) else {
                stats.filtered = stats.filtered.saturating_add(1);
                continue;
            };
            match self.format {
                ExportFormat::Text => {
                    let record = self
                        .has_conditions()
                        .then(|| Record::from_failure(url.as_str(), failure.status, &failure.reason));
                    let (matched, filtered) = record.as_ref().map_or((None, None), |r| self.evaluate(r));
                    for line in self.lines_for_url(&url, &Value::Null) {
                        if self.filters.accept_with(&url, &line, matched, filtered) {
                            out.write_all(line.as_bytes())?;
                            out.write_all(b"\n")?;
                            stats.lines = stats.lines.saturating_add(1);
                        } else {
                            stats.filtered = stats.filtered.saturating_add(1);
                        }
                    }
                }
                ExportFormat::Jsonl => {
                    let Some(record) = self.failure_record(&url, failure.status, &failure.reason) else {
                        stats.filtered = stats.filtered.saturating_add(1);
                        continue;
                    };
                    jsonl::write_line(&record, out)?;
                    stats.lines = stats.lines.saturating_add(1);
                }
            }
        }
        out.flush()?;
        Ok(stats)
    }

    fn store_field_values(&self, page: &PageRecord, stored: &[Field]) -> Result<(), OutputError> {
        let Some(sf) = &self.store_fields else {
            return Ok(());
        };
        for field in stored {
            let values = fields::extract_page(field, page);
            if !values.is_empty() {
                sf.write(&page.url.url, field, &values)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::jsonl::tests::page;
    use super::*;
    use serde_json::{json, Value};

    fn pages() -> Vec<PageRecord> {
        vec![
            page("https://e.com/", json!({})),
            page(
                "https://e.com/a/b.js?x=1&y=2",
                json!({"custom_fields": {"email": ["m@e.com"]}}),
            ),
            page("https://e.com/a/c.png", json!({})),
        ]
    }

    fn run(exp: &Exporter, bodies: impl Fn(&PageRecord) -> Option<String>) -> (ExportStats, String) {
        let mut out = Vec::new();
        let stats = exp.export_pages(&pages(), bodies, &mut out).unwrap();
        (stats, String::from_utf8(out).unwrap())
    }

    #[test]
    fn default_text_export_lists_urls() {
        let (stats, out) = run(&Exporter::default(), |_| None);
        assert_eq!(
            out,
            "https://e.com/\nhttps://e.com/a/b.js?x=1&y=2\nhttps://e.com/a/c.png\n"
        );
        assert_eq!(
            stats,
            ExportStats {
                pages: 3,
                lines: 3,
                filtered: 0,
                stored: 0
            }
        );
    }

    #[test]
    fn template_wins_over_fields_and_filters_apply_per_line() {
        let exp = Exporter {
            fields: vec![Field::Url],
            template: Some(Template::parse("{{key}}@{{fqdn}}").unwrap()),
            filters: OutputFilters::new(&[], &["^y".to_owned()], &[], &[]).unwrap(),
            ..Exporter::default()
        };
        let (stats, out) = run(&exp, |_| None);
        assert_eq!(out, "x@e.com\n");
        assert_eq!(stats.filtered, 1);
        assert_eq!(stats.lines, 1);
    }

    #[test]
    fn multiple_fields_emit_every_value_in_field_order() {
        let exp = Exporter {
            fields: Field::parse_list("fqdn,key,email").unwrap(),
            ..Exporter::default()
        };
        let (stats, out) = run(&exp, |_| None);
        assert_eq!(out, "e.com\ne.com\nx\ny\nm@e.com\ne.com\n");
        assert_eq!(stats.lines, 6);
    }

    #[test]
    fn field_export_with_extension_filter_and_wordlists() {
        let dir = tempfile::tempdir().unwrap();
        let exp = Exporter {
            fields: vec![Field::Qurl],
            filters: OutputFilters::new(&[], &[], &[], &["png".to_owned()]).unwrap(),
            store_fields: Some(StoreFields::new(dir.path())),
            ..Exporter::default()
        };
        let (_, out) = run(&exp, |_| None);
        assert_eq!(out, "https://e.com/a/b.js?x=1&y=2\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("https_e.com_qurl.txt")).unwrap(),
            "https://e.com/a/b.js?x=1&y=2\n"
        );
    }

    #[test]
    fn jsonl_export_includes_bodies_only_on_request_and_excludes_fields() {
        let exp = Exporter {
            format: ExportFormat::Jsonl,
            filters: OutputFilters::new(&["b\\.js".to_owned()], &[], &[], &[]).unwrap(),
            exclude_fields: vec!["timestamp".to_owned()],
            include_body: true,
            ..Exporter::default()
        };
        let (stats, out) = run(&exp, |p| Some(format!("body of {}", p.url.url)));
        assert_eq!(
            stats,
            ExportStats {
                pages: 3,
                lines: 1,
                filtered: 2,
                stored: 0
            }
        );
        let v: Value = serde_json::from_str(out.trim_end()).unwrap();
        assert!(v.get("timestamp").is_none());
        assert_eq!(v["request"]["endpoint"], "https://e.com/a/b.js?x=1&y=2");
        assert_eq!(v["response"]["body"], "body of https://e.com/a/b.js?x=1&y=2");
        assert_eq!(v["response"]["custom_fields"]["email"][0], "m@e.com");
        assert_eq!(v["request"]["custom_fields"]["email"][0], "m@e.com");

        let exp = Exporter {
            format: ExportFormat::Jsonl,
            ..Exporter::default()
        };
        let (stats, out) = run(&exp, |_| panic!("bodies must not be loaded"));
        assert_eq!(stats.lines, 3);
        assert_eq!(out.lines().count(), 3);
        assert!(!out.contains("\"body\""));
    }

    fn typed_pages() -> Vec<PageRecord> {
        vec![
            page("https://e.com/login", json!({"page_type": "login"})),
            page("https://e.com/oops", json!({"page_type": "Error"})),
            page("https://e.com/home", json!({"page_type": "article"})),
            page("https://e.com/plain", json!({})),
        ]
    }

    fn export(exp: &Exporter, pages: &[PageRecord]) -> (ExportStats, String) {
        let mut out = Vec::new();
        let stats = exp.export_pages(pages, |_| None, &mut out).unwrap();
        (stats, String::from_utf8(out).unwrap())
    }

    #[test]
    fn filter_page_types_drop_matching_pages_case_insensitively() {
        for format in [ExportFormat::Text, ExportFormat::Jsonl] {
            let exp = Exporter {
                format,
                filter_page_types: vec!["error".to_owned(), "LOGIN".to_owned()],
                ..Exporter::default()
            };
            let (stats, out) = export(&exp, &typed_pages());
            assert_eq!(stats.pages, 4);
            assert_eq!(stats.lines, 2, "{format:?}");
            assert_eq!(stats.filtered, 2, "{format:?}");
            assert!(out.contains("https://e.com/home"));
            assert!(
                out.contains("https://e.com/plain"),
                "a page without a type is kept"
            );
            assert!(!out.contains("/login") && !out.contains("/oops"), "{out}");
        }
    }

    #[test]
    fn conditions_select_records() {
        let mut pages = typed_pages();
        pages[1].status = 404;
        let exp = Exporter {
            format: ExportFormat::Jsonl,
            match_condition: Some(Dsl::parse("status_code == 404 || page_type == \"login\"").unwrap()),
            ..Exporter::default()
        };
        let (stats, out) = export(&exp, &pages);
        assert_eq!(stats.lines, 2);
        assert!(out.contains("/login") && out.contains("/oops"));

        let exp = Exporter {
            format: ExportFormat::Jsonl,
            filter_condition: Some(Dsl::parse("status_code == 404").unwrap()),
            ..Exporter::default()
        };
        let (stats, out) = export(&exp, &pages);
        assert_eq!(stats.lines, 3);
        assert!(!out.contains("/oops"));

        // text mode applies the same conditions
        let exp = Exporter {
            match_condition: Some(Dsl::parse("contains(url, \"home\")").unwrap()),
            ..Exporter::default()
        };
        let (stats, out) = export(&exp, &pages);
        assert_eq!(out, "https://e.com/home\n");
        assert_eq!(stats.filtered, 3);
    }

    #[test]
    fn a_match_condition_joins_match_regexes_with_or() {
        let exp = Exporter {
            filters: OutputFilters::new(&["login".to_owned()], &[], &[], &[]).unwrap(),
            match_condition: Some(Dsl::parse("page_type == \"article\"").unwrap()),
            ..Exporter::default()
        };
        let (_, out) = export(&exp, &typed_pages());
        assert_eq!(out, "https://e.com/login\nhttps://e.com/home\n");
    }

    #[test]
    fn conditions_can_read_the_body_which_is_loaded_for_them_only() {
        let exp = Exporter {
            format: ExportFormat::Jsonl,
            match_condition: Some(Dsl::parse("contains(body, \"secret\")").unwrap()),
            ..Exporter::default()
        };
        let mut out = Vec::new();
        let stats = exp
            .export_pages(
                &typed_pages(),
                |p| {
                    Some(
                        if p.url.url.path() == "/home" {
                            "a secret"
                        } else {
                            "none"
                        }
                        .to_owned(),
                    )
                },
                &mut out,
            )
            .unwrap();
        assert_eq!(stats.lines, 1);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["request"]["endpoint"], "https://e.com/home");
        assert!(
            v["response"].get("body").is_none(),
            "the body is not emitted without include_body"
        );
    }

    #[test]
    fn omit_flags_and_exclude_shape_the_record() {
        let p = page("https://e.com/p", jsonl_meta());
        let exp = Exporter {
            format: ExportFormat::Jsonl,
            include_body: true,
            ..Exporter::default()
        };
        let text = PageText::default()
            .with_body("<b>")
            .with_raw("HTTP/1.1 200 OK\r\n\r\n<b>");
        let v = serde_json::to_value(exp.record_with(&p, text.clone()).unwrap()).unwrap();
        assert_eq!(v["response"]["body"], "<b>");
        assert_eq!(v["response"]["raw"], "HTTP/1.1 200 OK\r\n\r\n<b>");
        assert_eq!(v["request"]["raw"], "GET /p HTTP/1.1\r\n\r\n");

        let exp = Exporter {
            omit_raw: true,
            omit_body: true,
            ..exp
        };
        let v = serde_json::to_value(exp.record_with(&p, text).unwrap()).unwrap();
        assert!(v["response"].get("body").is_none(), "-ob wins over include_body");
        assert!(v["response"].get("raw").is_none());
        assert!(v["request"].get("raw").is_none());
        assert_eq!(v["response"]["status_code"], 200);
    }

    fn jsonl_meta() -> Value {
        json!({"request": {"raw": "GET /p HTTP/1.1\r\n\r\n"}})
    }

    #[test]
    fn knowledge_base_is_attached_only_when_asked() {
        let p = page(
            "https://e.com/p",
            json!({"page_type": "login", "forms": [jsonl::tests::login_form()]}),
        );
        let plain = Exporter::default().record(&p, None).unwrap();
        assert!(plain.response.unwrap().knowledgebase.is_none());
        let kb = Exporter {
            knowledge_base: true,
            ..Exporter::default()
        }
        .record(&p, None)
        .unwrap();
        let v = serde_json::to_value(kb).unwrap();
        assert_eq!(v["response"]["knowledgebase"]["PageType"], "login");
        assert_eq!(v["response"]["knowledgebase"]["Forms"][0]["type"], "login");
    }

    #[test]
    fn failures_are_exported_with_their_error() {
        let failures = vec![
            UrlFailure::new("https://e.com/gone", 1, "http_404"),
            UrlFailure::new("https://e.com/down", 2, "timeout"),
            UrlFailure::new("not a url", 0, "invalid"),
        ];
        let exp = Exporter {
            format: ExportFormat::Jsonl,
            filter_condition: Some(Dsl::parse("error == \"timeout\"").unwrap()),
            ..Exporter::default()
        };
        let mut out = Vec::new();
        let stats = exp.export_failures(&failures, &mut out).unwrap();
        assert_eq!(stats.pages, 3);
        assert_eq!(stats.lines, 1);
        assert_eq!(stats.filtered, 2);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["error"], "http_404");
        assert_eq!(v["response"]["status_code"], 404);

        let exp = Exporter {
            fields: vec![Field::Fqdn, Field::Path],
            ..Exporter::default()
        };
        let mut out = Vec::new();
        exp.export_failures(&failures[..2], &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "e.com\n/gone\ne.com\n/down\n");
    }

    #[test]
    fn stored_responses_are_written_and_linked_from_the_record() {
        let dir = tempfile::tempdir().unwrap();
        let stored = StoredResponses::new(dir.path().join("sr"), false).unwrap();
        let exp = Exporter {
            format: ExportFormat::Jsonl,
            stored_responses: Some(stored.clone()),
            omit_body: true,
            ..Exporter::default()
        };
        let p = page("https://e.com/p", jsonl_meta());
        let mut out = Vec::new();
        let stats = exp
            .export_pages_with(
                [&p],
                |_| {
                    PageText::default()
                        .with_body("hello")
                        .with_raw("HTTP/1.1 200 OK\r\n\r\nhello")
                },
                &mut out,
            )
            .unwrap();
        assert_eq!(stats.stored, 1);
        let v: Value = serde_json::from_slice(&out).unwrap();
        let path = v["response"]["stored_response_path"].as_str().unwrap();
        assert!(std::path::Path::new(path).is_absolute());
        let file = std::fs::read_to_string(path).unwrap();
        assert!(
            file.starts_with("https://e.com/p\n\n\nGET /p HTTP/1.1\r\n\r\n\n\nHTTP/1.1 200 OK"),
            "{file}"
        );
        assert!(file.contains("hello"));
        assert!(
            v["response"].get("body").is_none(),
            "-ob strips the body after storing"
        );
        assert_eq!(
            std::fs::read_to_string(stored.index_path())
                .unwrap()
                .lines()
                .count(),
            1
        );
    }
}
