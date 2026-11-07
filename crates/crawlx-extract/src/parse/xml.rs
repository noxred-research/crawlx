//! Thin wrapper over `quick-xml` for the OOXML, ODF and EPUB readers: empty elements are expanded
//! to a start/end pair, text is unescaped, names are reduced to their local part and malformed XML
//! becomes a typed [`ParseError`]. DTDs, custom entities and duplicate attributes are rejected.
//! Adjacent text and references form one logical run, so consumers store hyperlink targets once
//! per run rather than once per reference. CDATA and all markup remain run boundaries.

use std::borrow::Cow;

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

use super::ParseError;

/// One XML event.
pub(crate) enum Ev<'a> {
    /// An opening tag.
    Start(&'a BytesStart<'a>),
    /// A closing tag; the local name.
    End(&'a [u8]),
    /// Character data (unescaped) or CDATA.
    Text(&'a str),
}

/// Local part of a (possibly prefixed) element or attribute name.
pub(crate) fn local(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|b| *b == b':') {
        Some(i) => &name[i + 1..],
        None => name,
    }
}

/// Local name of an element.
pub(crate) fn tag<'a>(e: &'a BytesStart<'_>) -> &'a [u8] {
    local(e.name().into_inner())
}

/// The value of the attribute whose local name is `key` (prefix ignored).
pub(crate) fn attr(e: &BytesStart<'_>, key: &str) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        (local(a.key.into_inner()) == key.as_bytes())
            .then(|| attribute_text(&a).ok().map(|value| value.into_owned()))
            .flatten()
    })
}

/// The value of the attribute named exactly `key` (prefix included, e.g. `r:id`).
pub(crate) fn attr_q(e: &BytesStart<'_>, key: &str) -> Option<String> {
    e.attributes().flatten().find_map(|a| {
        (a.key.into_inner() == key.as_bytes())
            .then(|| attribute_text(&a).ok().map(|value| value.into_owned()))
            .flatten()
    })
}

// Preserve the pre-0.41 literal attribute whitespace; normalized_value would change it.
fn attribute_text<'a>(
    attribute: &'a quick_xml::events::attributes::Attribute<'_>,
) -> Result<std::borrow::Cow<'a, str>, quick_xml::Error> {
    let raw = std::str::from_utf8(&attribute.value).map_err(quick_xml::encoding::EncodingError::from)?;
    Ok(quick_xml::escape::unescape_with(
        raw,
        quick_xml::escape::resolve_xml_entity,
    )?)
}

/// Walk the events of `xml`. `f` returns `Ok(false)` to stop early.
/// Text runs are validated before dispatch; stopping there does not parse the following markup.
///
/// # Errors
/// [`ParseError::Corrupt`] for malformed XML and whatever `f` returns.
pub(crate) fn walk(
    xml: &[u8],
    format: &'static str,
    mut f: impl FnMut(Ev<'_>) -> Result<bool, ParseError>,
) -> Result<(), ParseError> {
    let xml = xml.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(xml);
    let mut reader = Reader::from_reader(xml);
    let cfg = reader.config_mut();
    cfg.expand_empty_elements = true;
    cfg.check_end_names = false;
    let mut text: Option<Cow<'_, str>> = None;
    loop {
        let ev = reader
            .read_event()
            .map_err(|e| ParseError::corrupt_from(format, "malformed XML", e))?;
        let keep_going = match &ev {
            Event::Start(e) => {
                // Validate every attribute before callers select individual values.
                for attribute in e.attributes() {
                    let attribute = attribute
                        .map_err(|e| ParseError::corrupt_from(format, "malformed XML attribute", e))?;
                    attribute_text(&attribute).map_err(|e| {
                        ParseError::corrupt_from(format, "invalid XML attribute reference", e)
                    })?;
                }
                f(Ev::Start(e))?
            }
            Event::End(e) => f(Ev::End(local(e.name().into_inner())))?,
            Event::Text(t) => {
                let decoded = match t.decode() {
                    Ok(value) => value,
                    Err(_) => Cow::Owned(String::from_utf8_lossy(t).into_owned()),
                };
                if let Some(run) = text.as_mut() {
                    run.to_mut().push_str(&decoded);
                } else {
                    text = Some(decoded);
                }
                true
            }
            Event::GeneralRef(reference) => {
                if let Some(ch) = reference
                    .resolve_char_ref()
                    .map_err(|e| ParseError::corrupt_from(format, "invalid XML character reference", e))?
                {
                    text.get_or_insert(Cow::Borrowed("")).to_mut().push(ch);
                } else {
                    let name = reference
                        .decode()
                        .map_err(|e| ParseError::corrupt_from(format, "invalid XML entity name", e))?;
                    let value = quick_xml::escape::resolve_xml_entity(&name)
                        .ok_or_else(|| ParseError::corrupt(format, "custom XML entities are forbidden"))?;
                    if let Some(run) = text.as_mut() {
                        run.to_mut().push_str(value);
                    } else {
                        text = Some(Cow::Borrowed(value));
                    }
                }
                true
            }
            Event::CData(c) => f(Ev::Text(&String::from_utf8_lossy(c)))?,
            Event::DocType(_) => {
                return Err(ParseError::corrupt(
                    format,
                    "DTD and entity declarations are forbidden",
                ));
            }
            Event::Eof => return Ok(()),
            _ => true,
        };
        if !keep_going {
            return Ok(());
        }
        // The slice reader leaves '<' unconsumed after Text and GeneralRef events. Flush before
        // reading that markup, preserving early-stop behavior even if the next tag is malformed.
        if matches!(reader.get_ref().first(), None | Some(b'<')) {
            if let Some(run) = text.take() {
                let keep_going = f(Ev::Text(&run))?;
                if !keep_going {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn predefined_and_numeric_references_preserve_text_and_attributes() {
        let mut text = String::new();
        let mut href = None;
        walk(
            br#"<p href="https://example.test/?a=1&amp;b=&#50;">A &amp; B &lt;x&gt; &quot;&apos; &#x1F642; &#50;</p>"#,
            "docx",
            |event| {
                match event {
                    Ev::Start(element) => href = attr(element, "href"),
                    Ev::Text(value) => text.push_str(value),
                    Ev::End(_) => {}
                }
                Ok(true)
            },
        ).unwrap();
        assert_eq!(text, "A & B <x> \"' 🙂 2");
        assert_eq!(href.as_deref(), Some("https://example.test/?a=1&b=2"));
    }

    #[test]
    fn literal_attribute_whitespace_is_not_normalized_by_the_upgrade() {
        let mut value = None;
        walk(b"<p value='one&#10;two\nthree\tfour'/>", "odt", |event| {
            if let Ev::Start(element) = event {
                value = attr(element, "value");
            }
            Ok(true)
        })
        .unwrap();
        assert_eq!(value.as_deref(), Some("one\ntwo\nthree\tfour"));
    }

    #[test]
    fn ordinary_utf8_text_borrows_the_input() {
        let xml = b"<p>ordinary text</p>";
        let mut seen = false;
        walk(xml, "docx", |event| {
            if let Ev::Text(value) = event {
                assert_eq!(value, "ordinary text");
                assert_eq!(value.as_ptr(), xml[3..].as_ptr());
                seen = true;
            }
            Ok(true)
        })
        .unwrap();
        assert!(seen);
    }

    #[test]
    fn text_runs_preserve_markup_comment_and_cdata_boundaries() {
        let mut runs = Vec::new();
        walk(
            b"<p>A&amp;B&#38;C<!-- boundary -->D&amp;E<![CDATA[F&amp;G]]>H&#x26;I<q/>J&amp;K</p>",
            "docx",
            |event| {
                if let Ev::Text(value) = event {
                    runs.push(value.to_owned());
                }
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(runs, ["A&B&C", "D&E", "F&amp;G", "H&I", "J&K"]);
    }

    #[test]
    fn early_stop_after_complete_text_run_does_not_validate_later_markup() {
        for suffix in [
            "<broken",
            "<p key='&custom;'/>",
            "<!DOCTYPE p>",
            "<![CDATA[unterminated",
        ] {
            let xml = format!("<p>one&amp;two&#38;three{suffix}");
            let mut seen = false;
            walk(xml.as_bytes(), "docx", |event| {
                if let Ev::Text(value) = event {
                    assert_eq!(value, "one&two&three");
                    seen = true;
                    return Ok(false);
                }
                Ok(true)
            })
            .unwrap();
            assert!(seen);
        }
    }

    #[test]
    fn coalesced_text_keeps_lossy_utf8_and_validates_the_whole_run() {
        let mut text = String::new();
        walk(b"<p>\xff&amp;\xfe&#38;\xfd</p>", "docx", |event| {
            if let Ev::Text(value) = event {
                text.push_str(value);
            }
            Ok(true)
        })
        .unwrap();
        assert_eq!(text, "\u{fffd}&\u{fffd}&\u{fffd}");
        for invalid in ["&custom;", "&#x110000;", "&#0;", "&unterminated"] {
            let xml = format!("<p>prefix&amp;{invalid}</p>");
            assert!(walk(xml.as_bytes(), "docx", |event| {
                Ok(!matches!(event, Ev::Text(_)))
            })
            .is_err());
        }
    }

    #[test]
    fn rejects_custom_entities_dtds_and_duplicate_attributes() {
        for bytes in [
            br#"<!DOCTYPE p [<!ENTITY x "value">]><p>&x;</p>"#.as_slice(),
            br#"<p>&custom;</p>"#.as_slice(),
            br#"<p>&#x110000;</p>"#.as_slice(),
            br#"<p key="one" key="two"/>"#.as_slice(),
            br#"<p key="&custom;"/>"#.as_slice(),
        ] {
            assert!(walk(bytes, "docx", |_| Ok(true)).is_err());
        }
    }
}
