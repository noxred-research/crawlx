//! XML string-value redaction across comments, CDATA and adjacent text nodes.

use std::ops::Range;

use quick_xml::events::{BytesStart, BytesText, Event};

use super::{nesting, removed_ranges, xml_error, BoundedWriter, Budget};
use crate::parse::ParseError;

struct Text {
    event: usize,
    span: Range<usize>,
    value: String,
    sensitive: bool,
}

pub(super) fn sanitize_xml(
    bytes: &[u8],
    limit: usize,
    redact: &impl Fn(&str) -> Result<String, ParseError>,
) -> Result<Vec<u8>, ParseError> {
    let mut budget = Budget {
        remaining: limit,
        limit,
    };
    budget.charge(bytes.len())?;
    let mut reader = quick_xml::Reader::from_reader(bytes);
    let policy = crawlx_core::secret::Redactor::new();
    let mut sensitive = Vec::new();
    let mut events = Vec::new();
    let mut texts = Vec::new();
    let mut logical = String::new();
    loop {
        let event = reader.read_event().map_err(xml_error)?;
        if matches!(event, Event::Eof) {
            break;
        }
        budget.charge(
            event
                .len()
                .saturating_mul(2)
                .saturating_add(std::mem::size_of::<Event<'_>>().saturating_mul(2)),
        )?;
        let is_start = matches!(&event, Event::Start(_));
        let event = match event {
            Event::Start(start) | Event::Empty(start) => {
                let name = start.name().as_ref().to_owned();
                let mut clean = BytesStart::new(&name);
                for attribute in start.attributes() {
                    let attribute = attribute.map_err(xml_error)?;
                    let key = attribute.key.as_ref();
                    // Do not normalize literal attribute whitespace during redaction.
                    let value = quick_xml::escape::unescape_with(
                        &attribute.value,
                        quick_xml::escape::resolve_xml_entity,
                    )
                    .map_err(xml_error)?;
                    let value = if policy.is_sensitive_name(key) {
                        crawlx_core::secret::REDACTED.to_owned()
                    } else {
                        redact(&value)?
                    };
                    clean.push_attribute((key, value.as_str()));
                }
                if is_start {
                    sensitive.push(policy.is_sensitive_name(&name));
                    nesting(sensitive.len())?;
                    Event::Start(clean.into_owned())
                } else {
                    Event::Empty(clean.into_owned())
                }
            }
            Event::End(end) => {
                if sensitive.pop().is_none() {
                    return Err(ParseError::corrupt("pdf", "unmatched metadata XML end"));
                }
                Event::End(end.into_owned())
            }
            Event::Text(text) => {
                let decoded: &str = &text;
                text_event(
                    decoded,
                    &sensitive,
                    &mut logical,
                    &mut texts,
                    events.len(),
                    &mut budget,
                )?
            }
            Event::GeneralRef(reference) => {
                let mut encoded = [0; 4];
                let decoded = if let Some(ch) = reference.resolve_char_ref().map_err(xml_error)? {
                    ch.encode_utf8(&mut encoded)
                } else {
                    quick_xml::escape::resolve_xml_entity(&reference).ok_or_else(|| {
                        ParseError::corrupt("pdf", "custom metadata XML entities are forbidden")
                    })?
                };
                text_event(
                    decoded,
                    &sensitive,
                    &mut logical,
                    &mut texts,
                    events.len(),
                    &mut budget,
                )?
            }
            Event::CData(text) => {
                let decoded: &str = &text;
                text_event(
                    decoded,
                    &sensitive,
                    &mut logical,
                    &mut texts,
                    events.len(),
                    &mut budget,
                )?
            }
            Event::Comment(comment) => {
                let text: &str = &comment;
                let clean = redact(text)?;
                Event::Comment(BytesText::from_escaped(clean).into_owned())
            }
            Event::DocType(_) => return Err(ParseError::corrupt("pdf", "metadata DTD is unsupported")),
            other => {
                let text: &str = &other;
                if redact(text)? != text {
                    return Err(ParseError::corrupt(
                        "pdf",
                        "metadata event requires unsupported redaction",
                    ));
                }
                other.into_owned()
            }
        };
        budget.charge(event.len())?;
        events.push(event);
    }
    if !sensitive.is_empty() {
        return Err(ParseError::corrupt("pdf", "unterminated metadata XML element"));
    }
    // XML comments do not interrupt an element's string value; CDATA is plain text too.
    // Match on the logical text first, then project removals back onto owned events.
    let clean = redact(&logical)?;
    budget.charge(clean.len())?;
    let removed = removed_ranges(&logical, &clean);
    for text in texts {
        let clean = if text.sensitive {
            crawlx_core::secret::REDACTED.to_owned()
        } else {
            let mut clean = String::new();
            let mut cursor = text.span.start;
            let first = removed.partition_point(|range| range.end <= text.span.start);
            for range in &removed[first..] {
                if range.start >= text.span.end {
                    break;
                }
                let start = range.start.max(text.span.start);
                clean.push_str(&text.value[cursor - text.span.start..start - text.span.start]);
                if range.start >= text.span.start {
                    clean.push_str(crawlx_core::secret::REDACTED);
                }
                cursor = range.end.min(text.span.end);
            }
            clean.push_str(&text.value[cursor - text.span.start..]);
            clean
        };
        budget.charge(clean.len().saturating_mul(2))?;
        events[text.event] = Event::Text(BytesText::new(&clean).into_owned());
    }
    let mut writer = quick_xml::Writer::new(BoundedWriter {
        bytes: Vec::new(),
        limit,
    });
    for event in events {
        writer.write_event(event).map_err(xml_error)?;
    }
    Ok(writer.into_inner().bytes)
}

fn text_event(
    decoded: &str,
    sensitive: &[bool],
    logical: &mut String,
    texts: &mut Vec<Text>,
    event: usize,
    budget: &mut Budget,
) -> Result<Event<'static>, ParseError> {
    let is_sensitive = sensitive.iter().any(|value| *value);
    budget.charge(
        decoded
            .len()
            .saturating_mul(6)
            .saturating_add(std::mem::size_of::<Text>().saturating_mul(2)),
    )?;
    let start = logical.len();
    logical.push_str(decoded);
    texts.push(Text {
        event,
        span: start..logical.len(),
        value: decoded.to_owned(),
        sensitive: is_sensitive,
    });
    let output = if is_sensitive {
        crawlx_core::secret::REDACTED
    } else {
        decoded
    };
    Ok(Event::Text(BytesText::new(output).into_owned()))
}
