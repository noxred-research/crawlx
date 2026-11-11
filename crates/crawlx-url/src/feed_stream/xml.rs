//! Bounded streaming XML item reader. Parses owned bytes only: there is no entity table, no
//! DTD processing and no resolver of any kind, so nothing can trigger an external fetch.

use super::reader::HashedReader;
use super::template::{XmlName, XmlTemplate};
use super::{FeedStreamError, RowFault, RowOutcome};
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{NamespaceResolver, ResolveResult};
use quick_xml::reader::NsReader;
use std::collections::BTreeMap;
use std::io::Read;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Id of an element or attribute name that the template does not mention.
const OTHER: u16 = u16::MAX;

struct Plan {
    names: Vec<XmlName>,
    item: u16,
    fields: Vec<PlanField>,
}

struct PlanField {
    name: String,
    path: Vec<u16>,
    attribute: Option<u16>,
    required: bool,
}

impl Plan {
    fn compile(template: &XmlTemplate) -> Result<Self, FeedStreamError> {
        let mut names: Vec<XmlName> = Vec::new();
        let mut intern = |name: &XmlName| -> Result<u16, FeedStreamError> {
            let index = match names.iter().position(|known| known == name) {
                Some(index) => index,
                None => {
                    names.push(name.clone());
                    names.len() - 1
                }
            };
            u16::try_from(index)
                .ok()
                .filter(|index| *index != OTHER)
                .ok_or_else(|| FeedStreamError::Template("too many distinct xml names".to_owned()))
        };
        let item = intern(&template.item)?;
        let mut fields = Vec::with_capacity(template.fields.len());
        for field in &template.fields {
            let path = field
                .path
                .iter()
                .map(&mut intern)
                .collect::<Result<Vec<_>, _>>()?;
            let attribute = field.attribute.as_ref().map(&mut intern).transpose()?;
            fields.push(PlanField {
                name: field.name.clone(),
                path,
                attribute,
                required: field.required,
            });
        }
        Ok(Self { names, item, fields })
    }

    fn lookup(&self, namespace: Option<&str>, local: &str) -> u16 {
        self.names
            .iter()
            .position(|name| name.local == local && name.namespace.as_deref() == namespace)
            .and_then(|index| u16::try_from(index).ok())
            .unwrap_or(OTHER)
    }
}

struct Capture {
    field: usize,
    depth: usize,
    text: String,
}

struct Row {
    item_level: usize,
    start: u64,
    values: Vec<Option<String>>,
    captures: Vec<Capture>,
    stored: usize,
    fault: Option<RowFault>,
}

/// Parser state that does not borrow the event buffer.
struct State {
    plan: Plan,
    limit: usize,
    max_nesting: usize,
    stack: Vec<u16>,
    row: Option<Row>,
    peak: usize,
}

fn attribute_value(raw: &str) -> Result<String, RowFault> {
    quick_xml::escape::unescape_with(raw, quick_xml::escape::resolve_xml_entity)
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| RowFault::InvalidReference)
}

impl State {
    fn sample_peak(&mut self, overhead: usize) {
        let stored = self.row.as_ref().map_or(0, |row| row.stored);
        self.peak = self.peak.max(overhead + stored);
    }

    /// Start a row at an item element, then record the fields the element contributes:
    /// attribute values now, text captures that complete at the matching end tag.
    fn start_element(
        &mut self,
        id: u16,
        element: &BytesStart<'_>,
        resolver: &NamespaceResolver,
        before: u64,
    ) {
        self.stack.push(id);
        if self.row.is_none() {
            if id != self.plan.item {
                return;
            }
            self.row = Some(Row {
                item_level: self.stack.len() - 1,
                start: before,
                values: vec![None; self.plan.fields.len()],
                captures: Vec::new(),
                stored: 0,
                fault: None,
            });
        }
        let depth = self.stack.len();
        let Some(row) = self.row.as_mut() else {
            return;
        };
        let relative = &self.stack[row.item_level + 1..];
        for (index, field) in self.plan.fields.iter().enumerate() {
            if row.fault.is_some() || field.path != relative || row.values[index].is_some() {
                continue;
            }
            let Some(wanted) = field.attribute else {
                row.captures.push(Capture {
                    field: index,
                    depth,
                    text: String::new(),
                });
                continue;
            };
            for attribute in element.attributes() {
                let Ok(attribute) = attribute else {
                    row.fault = Some(RowFault::InvalidAttribute);
                    break;
                };
                let (resolved, local) = resolver.resolve_attribute(attribute.key);
                let namespace = match resolved {
                    ResolveResult::Bound(namespace) => Some(namespace.0),
                    ResolveResult::Unbound => None,
                    ResolveResult::Unknown(_) => {
                        row.fault = Some(RowFault::InvalidAttribute);
                        break;
                    }
                };
                if self.plan.lookup(namespace, local.as_ref()) != wanted {
                    continue;
                }
                match attribute_value(&attribute.value) {
                    Ok(value) => {
                        row.stored = row.stored.saturating_add(value.len());
                        row.values[index] = Some(value.trim().to_owned());
                    }
                    Err(fault) => row.fault = Some(fault),
                }
                break;
            }
        }
    }

    fn append_text(&mut self, text: &str) {
        let limit = self.limit;
        let depth = self.stack.len();
        let Some(row) = self.row.as_mut() else {
            return;
        };
        if row.fault.is_some() {
            return;
        }
        if let Some(capture) = row.captures.last_mut().filter(|capture| capture.depth == depth) {
            row.stored = row.stored.saturating_add(text.len());
            if row.stored > limit {
                row.fault = Some(RowFault::RowTooLarge { limit });
                return;
            }
            capture.text.push_str(text);
        }
    }

    fn append_fault(&mut self, fault: RowFault) {
        let depth = self.stack.len();
        if let Some(row) = self.row.as_mut() {
            if row.fault.is_none() && row.captures.last().is_some_and(|capture| capture.depth == depth) {
                row.fault = Some(fault);
            }
        }
    }

    /// Close the current element; returns the row outcome when it was the item element.
    fn end_element(&mut self) -> Result<Option<RowOutcome>, FeedStreamError> {
        let depth = self.stack.len();
        if depth == 0 {
            return Err(FeedStreamError::Structure("unbalanced end tag"));
        }
        if let Some(row) = self.row.as_mut() {
            if row.captures.last().is_some_and(|capture| capture.depth == depth) {
                if let Some(capture) = row.captures.pop() {
                    if row.fault.is_none() {
                        row.values[capture.field] = Some(capture.text.trim().to_owned());
                    }
                }
            }
        }
        let closes_row = self.row.as_ref().is_some_and(|row| row.item_level + 1 == depth);
        self.stack.pop();
        Ok(closes_row.then(|| self.finish_row()))
    }

    fn finish_row(&mut self) -> RowOutcome {
        let Some(row) = self.row.take() else {
            return RowOutcome::Malformed(RowFault::InvalidAttribute);
        };
        if let Some(fault) = row.fault {
            return RowOutcome::Malformed(fault);
        }
        let mut out = BTreeMap::new();
        for (field, value) in self.plan.fields.iter().zip(row.values) {
            match value {
                Some(value) if !value.is_empty() => {
                    out.insert(field.name.clone(), value);
                }
                _ if field.required => {
                    return RowOutcome::Malformed(RowFault::MissingField(field.name.clone()));
                }
                Some(value) => {
                    out.insert(field.name.clone(), value);
                }
                None => {}
            }
        }
        RowOutcome::Row(out)
    }
}

pub(super) struct XmlRows<R> {
    pub(super) reader: NsReader<HashedReader<R>>,
    buf: Vec<u8>,
    st: State,
    finished: bool,
    over: Arc<AtomicBool>,
}

impl<R: Read> XmlRows<R> {
    pub(super) fn new(
        reader: HashedReader<R>,
        template: &XmlTemplate,
        limit: usize,
        max_nesting: usize,
    ) -> Result<Self, FeedStreamError> {
        let over = reader.over_budget_flag();
        let mut reader = NsReader::from_reader(reader);
        reader.config_mut().expand_empty_elements = true;
        Ok(Self {
            reader,
            buf: Vec::new(),
            st: State {
                plan: Plan::compile(template)?,
                limit,
                max_nesting,
                stack: Vec::new(),
                row: None,
                peak: 0,
            },
            finished: false,
            over,
        })
    }

    pub(super) fn peak(&self) -> usize {
        self.st.peak
    }

    pub(super) fn next_outcome(&mut self) -> Result<Option<RowOutcome>, FeedStreamError> {
        if self.finished {
            return Ok(None);
        }
        let result = self.drive();
        let overhead = self.reader.get_mut().chunk_len() + self.buf.capacity();
        self.st.sample_peak(overhead);
        if !matches!(result, Ok(Some(_))) {
            self.finished = true;
        }
        result
    }

    fn drive(&mut self) -> Result<Option<RowOutcome>, FeedStreamError> {
        let limit64 = u64::try_from(self.st.limit).unwrap_or(u64::MAX);
        loop {
            let overhead = self.reader.get_mut().chunk_len() + self.buf.capacity();
            self.st.sample_peak(overhead);
            self.buf.clear();
            let before = {
                let inner = self.reader.get_mut();
                inner.reset_budget(self.st.limit);
                inner.consumed()
            };
            let (resolved, event) = match self.reader.read_resolved_event_into(&mut self.buf) {
                Ok(_) if self.over.load(Ordering::Relaxed) => {
                    return Err(FeedStreamError::Limit("xml_event_bytes"));
                }
                Ok(read) => read,
                Err(error) => {
                    return Err(if self.over.load(Ordering::Relaxed) {
                        FeedStreamError::Limit("xml_event_bytes")
                    } else {
                        FeedStreamError::Xml(error)
                    });
                }
            };
            let start_id = match &event {
                Event::Start(element) => {
                    let namespace = match resolved {
                        ResolveResult::Bound(namespace) => Some(namespace.0),
                        ResolveResult::Unbound => None,
                        ResolveResult::Unknown(_) => {
                            return Err(FeedStreamError::Structure("unbound namespace prefix"));
                        }
                    };
                    Some(self.st.plan.lookup(namespace, element.local_name().as_ref()))
                }
                _ => None,
            };
            if let Some(row) = self.st.row.as_mut() {
                if row.fault.is_none() && before.saturating_sub(row.start) > limit64 {
                    row.fault = Some(RowFault::RowTooLarge { limit: self.st.limit });
                    row.values.iter_mut().for_each(|value| *value = None);
                    row.captures.clear();
                }
            }
            match event {
                Event::DocType(_) => return Err(FeedStreamError::Doctype),
                Event::Decl(decl) => {
                    if let Some(Ok(encoding)) = decl.encoding() {
                        if !encoding.eq_ignore_ascii_case("utf-8") {
                            return Err(FeedStreamError::Encoding);
                        }
                    }
                }
                Event::Start(element) => {
                    if self.st.stack.len() >= self.st.max_nesting {
                        return Err(FeedStreamError::Limit("xml_nesting"));
                    }
                    let id = start_id.unwrap_or(OTHER);
                    self.st
                        .start_element(id, &element, self.reader.resolver(), before);
                }
                Event::Text(part) => self.st.append_text(&part),
                Event::CData(part) => self.st.append_text(&part),
                Event::GeneralRef(reference) => match reference.resolve_char_ref() {
                    Ok(Some(ch)) => self.st.append_text(ch.encode_utf8(&mut [0; 4])),
                    Ok(None) => match quick_xml::escape::resolve_xml_entity(&reference) {
                        Some(text) => self.st.append_text(text),
                        None => self.st.append_fault(RowFault::InvalidReference),
                    },
                    Err(_) => self.st.append_fault(RowFault::InvalidReference),
                },
                Event::End(_) => {
                    if let Some(outcome) = self.st.end_element()? {
                        return Ok(Some(outcome));
                    }
                }
                Event::Eof => {
                    if !self.st.stack.is_empty() || self.st.row.is_some() {
                        return Err(FeedStreamError::Structure("incomplete document"));
                    }
                    return Ok(None);
                }
                _ => {}
            }
        }
    }
}
