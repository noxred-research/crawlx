//! Redaction rules and the span-field redaction layer.
//!
//! Implements the "Logs and traces" sink: field names on a deny-list
//! are replaced wholesale, string values are scrubbed for secret shapes (JWT,
//! `Bearer`/`Basic` credentials, 32+ hex strings, `sk-` keys, `name=value`
//! pairs whose name is on the deny-list) and for secrets registered at run time
//! with [`register_secret`]. Everything that fails to be scrubbed fails
//! closed: if a pattern ever failed to compile, the whole value is masked.
//!
//! [`RedactionLayer`] records the *already redacted* span fields as a span
//! extension; [`crate::format::RedactingFormat`] reads them back when it
//! renders an event, so no unredacted field value ever reaches a writer.

pub use crawlx_core::secret::{register_secret, Redactor, DENY_NAMES, MIN_REGISTERED_SECRET_LEN, REDACTED};
use serde_json::Value;
use std::fmt;
use tracing::field::{Field, Visit};
use tracing::span;
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// Collects event or span fields into redacted JSON values, preserving order.
pub struct FieldCollector<'r> {
    redactor: &'r Redactor,
    /// `(field name, redacted value)` in recording order.
    pub fields: Vec<(String, Value)>,
}

impl<'r> FieldCollector<'r> {
    /// Empty collector that redacts every recorded value through `redactor`.
    #[must_use]
    pub const fn new(redactor: &'r Redactor) -> Self {
        Self {
            redactor,
            fields: Vec::new(),
        }
    }

    fn push(&mut self, field: &Field, value: Value) {
        let name = field.name();
        let value = self.redactor.redact_field(name, value);
        if let Some(slot) = self.fields.iter_mut().find(|(n, _)| n == name) {
            slot.1 = value;
        } else {
            self.fields.push((name.to_owned(), value));
        }
    }
}

impl Visit for FieldCollector<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, Value::String(format!("{value:?}")));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, Value::String(value.to_owned()));
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.push(field, Value::String(value.to_string()));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, Value::from(value));
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.push(field, Value::String(value.to_string()));
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.push(field, Value::String(value.to_string()));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(
            field,
            serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number),
        );
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, Value::Bool(value));
    }
}

/// Redacted span fields, stored as a span extension by [`RedactionLayer`].
#[derive(Debug, Default, Clone)]
pub struct RedactedSpanFields(pub Vec<(String, Value)>);

/// Layer that stores redacted span fields for the event formatter.
///
/// Must be installed together with [`crate::format::RedactingFormat`]; without
/// it span fields are omitted from output (fail closed).
#[derive(Clone, Debug, Default)]
pub struct RedactionLayer {
    redactor: Redactor,
}

impl RedactionLayer {
    /// Layer that redacts span and event fields with `redactor` before they are stored.
    #[must_use]
    pub const fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }
}

impl<S> Layer<S> for RedactionLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut collector = FieldCollector::new(&self.redactor);
        attrs.record(&mut collector);
        span.extensions_mut().insert(RedactedSpanFields(collector.fields));
    }

    fn on_record(&self, id: &span::Id, values: &span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut collector = FieldCollector::new(&self.redactor);
        values.record(&mut collector);
        let mut ext = span.extensions_mut();
        if let Some(existing) = ext.get_mut::<RedactedSpanFields>() {
            for (name, value) in collector.fields {
                if let Some(slot) = existing.0.iter_mut().find(|(n, _)| *n == name) {
                    slot.1 = value;
                } else {
                    existing.0.push((name, value));
                }
            }
        } else {
            ext.insert(RedactedSpanFields(collector.fields));
        }
    }
}
