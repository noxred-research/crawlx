//! Event formatter that renders only redacted data.
//!
//! The formatter owns the whole rendering path (JSON and human-readable), so
//! nothing the stock `tracing_subscriber` formatters would print can bypass
//! the [`Redactor`]. Event fields are redacted while they are visited; span
//! fields come from the [`RedactedSpanFields`] extension that
//! [`crate::redact::RedactionLayer`] stored. Implements the "Logs and traces"
//! row of the redaction policy (`docs/design/data-and-secrets.md`).

use crate::redact::{FieldCollector, RedactedSpanFields, Redactor};
use serde_json::{Map, Value};
use std::fmt;
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::LookupSpan;

/// Output encoding of log lines.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum LogFormat {
    /// One JSON object per line (production default).
    #[default]
    Json,
    /// Multi-line human-readable output for terminals.
    Pretty,
}

/// `FormatEvent` implementation shared by both [`LogFormat`]s.
#[derive(Clone, Debug)]
pub struct RedactingFormat {
    format: LogFormat,
    redactor: Redactor,
}

impl RedactingFormat {
    /// Event formatter that renders `format` and masks field values through `redactor`.
    #[must_use]
    pub const fn new(format: LogFormat, redactor: Redactor) -> Self {
        Self { format, redactor }
    }
}

/// Field formatter that discards everything: the stock `fmt` layer would
/// otherwise store unredacted span text next to the redacted fields.
#[derive(Clone, Copy, Debug, Default)]
pub struct DiscardFields;

impl<'writer> FormatFields<'writer> for DiscardFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        _writer: Writer<'writer>,
        _fields: R,
    ) -> fmt::Result {
        Ok(())
    }
}

fn timestamp() -> String {
    let mut s = String::new();
    // Writing into a `String` cannot fail; fall back to an empty timestamp.
    if SystemTime.format_time(&mut Writer::new(&mut s)).is_err() {
        s.clear();
    }
    s
}

impl<S, N> FormatEvent<S, N> for RedactingFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let meta = event.metadata();
        let mut collector = FieldCollector::new(&self.redactor);
        event.record(&mut collector);
        let fields = collector.fields;

        let mut spans: Vec<(String, Vec<(String, Value)>)> = Vec::new();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let span_fields = span
                    .extensions()
                    .get::<RedactedSpanFields>()
                    .map(|f| f.0.clone())
                    .unwrap_or_default();
                spans.push((span.name().to_owned(), span_fields));
            }
        }

        match self.format {
            LogFormat::Json => {
                let mut fields_obj = Map::new();
                for (k, v) in fields {
                    fields_obj.insert(k, v);
                }
                let spans_json: Vec<Value> = spans
                    .into_iter()
                    .map(|(name, fs)| {
                        let mut m = Map::new();
                        m.insert("name".to_owned(), Value::String(name));
                        for (k, v) in fs {
                            m.entry(k).or_insert(v);
                        }
                        Value::Object(m)
                    })
                    .collect();
                let mut root = Map::new();
                root.insert("timestamp".to_owned(), Value::String(timestamp()));
                root.insert(
                    "level".to_owned(),
                    Value::String(meta.level().as_str().to_owned()),
                );
                root.insert("target".to_owned(), Value::String(meta.target().to_owned()));
                root.insert("fields".to_owned(), Value::Object(fields_obj));
                root.insert("spans".to_owned(), Value::Array(spans_json));
                let line = serde_json::to_string(&Value::Object(root)).map_err(|_| fmt::Error)?;
                writeln!(writer, "{line}")
            }
            LogFormat::Pretty => {
                write!(writer, "{} {:>5} {}:", timestamp(), meta.level(), meta.target())?;
                if let Some((_, msg)) = fields.iter().find(|(k, _)| k == "message") {
                    write!(writer, " {}", display_value(msg))?;
                }
                writeln!(writer)?;
                for (k, v) in fields.iter().filter(|(k, _)| k != "message") {
                    writeln!(writer, "    {k}: {}", display_value(v))?;
                }
                for (name, fs) in &spans {
                    write!(writer, "    in {name}")?;
                    if !fs.is_empty() {
                        write!(writer, "{{")?;
                        for (i, (k, v)) in fs.iter().enumerate() {
                            if i > 0 {
                                write!(writer, " ")?;
                            }
                            write!(writer, "{k}={}", display_value(v))?;
                        }
                        write!(writer, "}}")?;
                    }
                    writeln!(writer)?;
                }
                Ok(())
            }
        }
    }
}

fn display_value(v: &Value) -> String {
    match v {
        // Escape line breaks so a value cannot forge extra log lines.
        Value::String(s) => s.replace('\r', "\\r").replace('\n', "\\n"),
        other => other.to_string(),
    }
}
