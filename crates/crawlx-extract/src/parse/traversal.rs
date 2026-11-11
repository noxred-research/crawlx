//! Offline bounded ZIP, feed and embedded-document traversal.
//!
//! Physical archive ordinals and authored feed ordinals define child identity. Nothing here
//! acquires links, resolves DNS, runs scripts, submits forms, or downloads external entities.
//! Native parser results are not claims of upstream parser/algorithm equivalence.

use crawlx_core::hash::Digest;
use url::Url;

use super::{
    xml::{self, Ev},
    zipbox::ZipBox,
    ParseError, ParseLimits,
};
use crate::{
    pipeline::{ParserPipeline, PipelineError, PipelineInput, PipelineOutput},
    source_projection::stable_child_id,
};

/// Aggregate limits shared by every descendant, not reset for each nested container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct TraversalLimits {
    /// Accepted root and individual child bytes.
    pub max_input_bytes: usize,
    /// Total expanded child bytes across all levels.
    pub max_expanded_bytes: usize,
    /// Most emitted descendants, including container records.
    pub max_children: usize,
    /// Most nested child hops; root depth is zero.
    pub max_depth: u32,
    /// Maximum declared expanded/compressed ratio, per ZIP entry.
    pub max_ratio: u64,
    /// Finite XML events plus physical archive entries.
    pub max_operations: usize,
    /// Aggregate parsed text/HTML/Markdown bytes.
    pub max_output_bytes: usize,
}

impl Default for TraversalLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 16 * 1024 * 1024,
            max_expanded_bytes: 64 * 1024 * 1024,
            max_children: 1024,
            max_depth: 8,
            max_ratio: 100,
            max_operations: 1_000_000,
            max_output_bytes: 32 * 1024 * 1024,
        }
    }
}

/// One source unit's truthful parse result.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChildContent {
    /// Native parser output.
    Parsed(Box<PipelineOutput>),
    /// Traversed container; children follow in deterministic preorder.
    Container,
    /// An unsupported child is recorded, never silently interpreted as text.
    Unsupported,
}

/// A parent/child record. IDs contain no archive paths or feed content.
#[derive(Debug)]
#[non_exhaustive]
pub struct ChildRecord {
    /// Stable opaque identity.
    pub id: Digest,
    /// Immediate parent; absent on root.
    pub parent: Option<Digest>,
    /// Physical ZIP ordinal or authored feed ordinal. Root is zero.
    pub ordinal: u64,
    /// Root-relative depth.
    pub depth: u32,
    /// Local parse result.
    pub content: ChildContent,
    /// Bounded feed references. Proposals only; worker must re-admit every target.
    pub references: Vec<Url>,
}

/// Hard traversal failures. No partially parsed tree is returned on failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TraversalError {
    /// Finite limit or arithmetic overflow.
    #[error("embedded traversal limit exceeded")]
    Limit,
    /// Cooperative cancellation or caller deadline expired.
    #[error("embedded traversal cancelled")]
    Cancelled,
    /// Native parser rejected malformed content.
    #[error("embedded document parse failed")]
    Pipeline(#[source] PipelineError),
    /// Malformed container/feed.
    #[error("embedded container parse failed")]
    Container(#[source] ParseError),
}

struct Walk<'a> {
    pipeline: &'a ParserPipeline,
    limits: TraversalLimits,
    cancelled: &'a dyn Fn() -> bool,
    expanded: usize,
    operations: usize,
    output_bytes: usize,
    records: Vec<ChildRecord>,
}

impl Walk<'_> {
    fn check(&mut self) -> Result<(), TraversalError> {
        if (self.cancelled)() {
            return Err(TraversalError::Cancelled);
        }
        self.operations = self.operations.checked_add(1).ok_or(TraversalError::Limit)?;
        if self.operations > self.limits.max_operations {
            return Err(TraversalError::Limit);
        }
        Ok(())
    }

    fn charge(&mut self, bytes: usize) -> Result<(), TraversalError> {
        self.expanded = self.expanded.checked_add(bytes).ok_or(TraversalError::Limit)?;
        if bytes > self.limits.max_input_bytes || self.expanded > self.limits.max_expanded_bytes {
            return Err(TraversalError::Limit);
        }
        Ok(())
    }

    fn emit(&mut self, record: ChildRecord) -> Result<(), TraversalError> {
        if self.records.len() > self.limits.max_children {
            return Err(TraversalError::Limit);
        }
        self.records.push(record);
        Ok(())
    }

    fn visit(
        &mut self,
        bytes: &[u8],
        mime: Option<&str>,
        id: Digest,
        parent: Option<Digest>,
        ordinal: u64,
        depth: u32,
    ) -> Result<(), TraversalError> {
        self.check()?;
        if depth > self.limits.max_depth || bytes.len() > self.limits.max_input_bytes {
            return Err(TraversalError::Limit);
        }
        let is_zip = bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06");
        let is_feed = mime.is_some_and(|mime| {
            matches!(
                mime.split(';').next().unwrap_or("").trim(),
                "application/rss+xml" | "application/atom+xml"
            )
        });
        if is_zip {
            let limits = ParseLimits {
                max_input_bytes: self.limits.max_input_bytes,
                max_uncompressed_bytes: self.limits.max_expanded_bytes.saturating_sub(self.expanded),
                max_entries: self
                    .limits
                    .max_children
                    .saturating_sub(self.records.len().saturating_sub(1)),
                ..ParseLimits::default()
            };
            let mut zip = ZipBox::open(bytes, "zip", &limits).map_err(TraversalError::Container)?;
            // Apply shared expansion/ratio limits before native container sniffing.
            for index in 0..zip.len() {
                self.check()?;
                let (expanded, compressed, _) = zip.entry_info(index).map_err(TraversalError::Container)?;
                if expanded
                    > compressed
                        .max(1)
                        .checked_mul(self.limits.max_ratio)
                        .ok_or(TraversalError::Limit)?
                {
                    return Err(TraversalError::Limit);
                }
            }
            // Supported Office/EPUB packages remain native documents, not arbitrary ZIP trees.
            match self.pipeline.run(PipelineInput::new(bytes)) {
                Ok(output) => return self.parsed(output, id, parent, ordinal, depth),
                Err(PipelineError::Detect(ParseError::UnsupportedFormat { .. })) => {}
                Err(error) => return Err(TraversalError::Pipeline(error)),
            }
            self.emit(ChildRecord {
                id,
                parent,
                ordinal,
                depth,
                content: ChildContent::Container,
                references: Vec::new(),
            })?;
            for index in 0..zip.len() {
                self.check()?;
                let (_, _, directory) = zip.entry_info(index).map_err(TraversalError::Container)?;
                if directory {
                    continue;
                }
                let mime = zip.entry_mime(index).map_err(TraversalError::Container)?;
                let cancelled = self.cancelled;
                let child = zip
                    .read_index(index, || {
                        if cancelled() {
                            Err(ParseError::corrupt("zip", "traversal cancelled"))
                        } else {
                            Ok(())
                        }
                    })
                    .map_err(|error| {
                        if cancelled() {
                            TraversalError::Cancelled
                        } else {
                            TraversalError::Container(error)
                        }
                    })?;
                self.charge(child.len())?;
                let ordinal = u64::try_from(index).map_err(|_| TraversalError::Limit)?;
                self.visit(
                    &child,
                    mime,
                    stable_child_id(id, ordinal),
                    Some(id),
                    ordinal,
                    depth.checked_add(1).ok_or(TraversalError::Limit)?,
                )?;
            }
            return Ok(());
        }
        if is_feed {
            self.emit(ChildRecord {
                id,
                parent,
                ordinal,
                depth,
                content: ChildContent::Container,
                references: Vec::new(),
            })?;
            return self.feed(bytes, id, depth);
        }
        let mut input = PipelineInput::new(bytes);
        if let Some(mime) = mime {
            input = input.with_content_type(mime);
        }
        match self.pipeline.run(input) {
            Ok(output) => self.parsed(output, id, parent, ordinal, depth),
            Err(PipelineError::Detect(ParseError::UnsupportedFormat { .. })) => self.emit(ChildRecord {
                id,
                parent,
                ordinal,
                depth,
                content: ChildContent::Unsupported,
                references: Vec::new(),
            }),
            Err(error) => Err(TraversalError::Pipeline(error)),
        }
    }

    fn parsed(
        &mut self,
        output: PipelineOutput,
        id: Digest,
        parent: Option<Digest>,
        ordinal: u64,
        depth: u32,
    ) -> Result<(), TraversalError> {
        self.check()?;
        self.output_bytes = self
            .output_bytes
            .checked_add(output.text().len())
            .and_then(|size| size.checked_add(output.html().len()))
            .and_then(|size| size.checked_add(output.markdown().len()))
            .ok_or(TraversalError::Limit)?;
        if self.output_bytes > self.limits.max_output_bytes {
            return Err(TraversalError::Limit);
        }
        self.emit(ChildRecord {
            id,
            parent,
            ordinal,
            depth,
            content: ChildContent::Parsed(Box::new(output)),
            references: Vec::new(),
        })
    }

    fn feed(&mut self, bytes: &[u8], parent: Digest, depth: u32) -> Result<(), TraversalError> {
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut entry_depth = None;
        let mut text = String::new();
        let mut references = Vec::new();
        let mut ordinal = 0_u64;
        let mut callback_error = None;
        let mut root_seen = false;
        let result = xml::walk(bytes, "feed", |event| {
            let result = (|| -> Result<(), TraversalError> {
                self.check()?;
                match event {
                    Ev::Start(element) => {
                        let name = xml::tag(element);
                        if stack.is_empty() {
                            if root_seen || !matches!(name, b"rss" | b"feed" | b"RDF") {
                                return Err(TraversalError::Container(ParseError::corrupt(
                                    "feed",
                                    "unsupported feed root",
                                )));
                            }
                            root_seen = true;
                        }
                        if stack.len() >= usize::try_from(self.limits.max_depth).unwrap_or(usize::MAX) {
                            return Err(TraversalError::Limit);
                        }
                        if entry_depth.is_none() && matches!(name, b"entry" | b"item") {
                            entry_depth = Some(stack.len());
                        }
                        if entry_depth.is_some() && name == b"link" {
                            if let Some(href) = xml::attr(element, "href") {
                                if let Ok(url) = Url::parse(&href) {
                                    if matches!(url.scheme(), "http" | "https")
                                        && url.username().is_empty()
                                        && url.password().is_none()
                                    {
                                        if references.len() >= self.limits.max_children {
                                            return Err(TraversalError::Limit);
                                        }
                                        references.push(url);
                                    }
                                }
                            }
                        }
                        stack.push(name.to_vec());
                    }
                    Ev::Text(value) if entry_depth.is_some() => {
                        if stack.last().is_some_and(|name| {
                            matches!(
                                name.as_slice(),
                                b"title" | b"description" | b"summary" | b"content"
                            )
                        }) {
                            let extra = value.len().checked_add(1).ok_or(TraversalError::Limit)?;
                            if text
                                .len()
                                .checked_add(extra)
                                .is_none_or(|length| length > self.limits.max_input_bytes)
                            {
                                return Err(TraversalError::Limit);
                            }
                            text.push_str(value);
                            text.push('\n');
                        } else if stack.last().is_some_and(|name| name.as_slice() == b"link") {
                            if let Ok(url) = Url::parse(value.trim()) {
                                if matches!(url.scheme(), "http" | "https")
                                    && url.username().is_empty()
                                    && url.password().is_none()
                                {
                                    if references.len() >= self.limits.max_children {
                                        return Err(TraversalError::Limit);
                                    }
                                    references.push(url);
                                }
                            }
                        }
                    }
                    Ev::End(name) => {
                        if stack.last().map(Vec::as_slice) != Some(name) {
                            return Err(TraversalError::Container(ParseError::corrupt(
                                "feed",
                                "unbalanced XML",
                            )));
                        }
                        stack.pop();
                        if entry_depth == Some(stack.len()) {
                            let child_depth = depth.checked_add(1).ok_or(TraversalError::Limit)?;
                            if child_depth > self.limits.max_depth {
                                return Err(TraversalError::Limit);
                            }
                            self.charge(text.len())?;
                            let id = stable_child_id(parent, ordinal);
                            let output = self
                                .pipeline
                                .run(PipelineInput::new(text.as_bytes()).with_content_type("text/plain"))
                                .map_err(TraversalError::Pipeline)?;
                            self.parsed(output, id, Some(parent), ordinal, child_depth)?;
                            for reference in &references {
                                self.output_bytes = self
                                    .output_bytes
                                    .checked_add(reference.as_str().len())
                                    .ok_or(TraversalError::Limit)?;
                                if self.output_bytes > self.limits.max_output_bytes {
                                    return Err(TraversalError::Limit);
                                }
                            }
                            if let Some(record) = self.records.last_mut() {
                                record.references = std::mem::take(&mut references);
                            }
                            ordinal = ordinal.checked_add(1).ok_or(TraversalError::Limit)?;
                            text.clear();
                            entry_depth = None;
                        }
                    }
                    Ev::Text(_) => {}
                }
                Ok(())
            })();
            if let Err(error) = result {
                callback_error = Some(error);
                return Ok(false);
            }
            Ok(true)
        });
        if let Some(error) = callback_error {
            return Err(error);
        }
        result.map_err(TraversalError::Container)?;
        if !root_seen || !stack.is_empty() {
            return Err(TraversalError::Container(ParseError::corrupt(
                "feed",
                "unclosed or missing XML root",
            )));
        }
        Ok(())
    }
}

/// Traverse retained/in-memory bytes only. `cancelled` may include an injected deadline check.
/// Use an upload pipeline for containers without page URLs. Root identity must be tenant-scoped.
///
/// # Errors
/// Refuses invalid limits, bombs, malformed documents, depth/work/output excess and cancellation.
pub fn traverse(
    pipeline: &ParserPipeline,
    bytes: &[u8],
    content_type: Option<&str>,
    root_id: Digest,
    limits: TraversalLimits,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ChildRecord>, TraversalError> {
    if limits.max_input_bytes == 0
        || limits.max_expanded_bytes == 0
        || limits.max_children > 100_000
        || limits.max_depth > 64
        || limits.max_ratio == 0
        || limits.max_operations == 0
        || limits.max_output_bytes == 0
    {
        return Err(TraversalError::Limit);
    }
    let mut walk = Walk {
        pipeline,
        limits,
        cancelled,
        expanded: 0,
        operations: 0,
        output_bytes: 0,
        records: Vec::new(),
    };
    walk.visit(bytes, content_type, root_id, None, 0, 0)?;
    Ok(walk.records)
}

/// Bounded feed result. A soft entry cap is explicit and cannot establish freshness.
#[derive(Debug)]
#[non_exhaustive]
pub struct FeedReport {
    /// Root followed by retained authored children.
    pub records: Vec<ChildRecord>,
    /// Authored feed modification compared with the caller's retained baseline.
    pub freshness: crate::source_policy::SourceFreshness,
    /// Entries excluded by the explicit output cap.
    pub omitted_entries: usize,
}

/// Parse a complete feed and compare its authored RFC3339/RFC2822 update timestamp.
/// `max_entries` is a soft output cap below the independent hard traversal bounds.
///
/// # Errors
/// Rejects malformed feeds, hard bounds and cancellation. External entities are never loaded.
#[allow(clippy::too_many_arguments)]
pub fn feed_with_freshness(
    pipeline: &ParserPipeline,
    bytes: &[u8],
    content_type: &str,
    root_id: Digest,
    mut limits: TraversalLimits,
    max_entries: usize,
    baseline_modified_ms: Option<i64>,
    cancelled: &dyn Fn() -> bool,
) -> Result<FeedReport, TraversalError> {
    if bytes.len() > limits.max_input_bytes {
        return Err(TraversalError::Limit);
    }
    if !matches!(
        content_type.split(';').next().unwrap_or("").trim(),
        "application/rss+xml" | "application/atom+xml"
    ) {
        return Err(TraversalError::Container(ParseError::corrupt(
            "feed",
            "unsupported feed media type",
        )));
    }
    let mut timestamp = None;
    let mut in_update = false;
    let mut operations = 0_usize;
    let mut stopped = false;
    xml::walk(bytes, "feed", |event| {
        operations = operations.saturating_add(1);
        if cancelled() || operations >= limits.max_operations {
            stopped = true;
            return Ok(false);
        }
        match event {
            Ev::Start(element) => {
                in_update = matches!(xml::tag(element), b"updated" | b"lastBuildDate" | b"pubDate")
            }
            Ev::End(_) => in_update = false,
            Ev::Text(text) if in_update => {
                let parsed = chrono::DateTime::parse_from_rfc3339(text.trim())
                    .or_else(|_| chrono::DateTime::parse_from_rfc2822(text.trim()))
                    .ok()
                    .map(|date| date.timestamp_millis());
                if let Some(parsed) = parsed {
                    timestamp = Some(timestamp.map_or(parsed, |old: i64| old.max(parsed)));
                }
            }
            Ev::Text(_) => {}
        }
        Ok(true)
    })
    .map_err(TraversalError::Container)?;
    if stopped {
        return Err(if cancelled() {
            TraversalError::Cancelled
        } else {
            TraversalError::Limit
        });
    }
    limits.max_operations = limits
        .max_operations
        .checked_sub(operations)
        .ok_or(TraversalError::Limit)?;
    let mut records = traverse(pipeline, bytes, Some(content_type), root_id, limits, cancelled)?;
    let entries = records.len().saturating_sub(1);
    let omitted_entries = entries.saturating_sub(max_entries);
    records.truncate(max_entries.saturating_add(1));
    let freshness = crate::source_policy::freshness(timestamp, baseline_modified_ms, omitted_entries > 0);
    Ok(FeedReport {
        records,
        freshness,
        omitted_entries,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::extraction::ParserPipelineV1;

    #[test]
    fn authored_feed_children_have_stable_ids_and_no_network() {
        let pipeline = ParserPipeline::new(ParserPipelineV1::for_uploads()).unwrap();
        let bytes = b"<rss><channel><item><title>First</title><link>https://example.test/a</link></item><item><title>Second</title></item></channel></rss>";
        let id = Digest::of("test", b"feed");
        let records = traverse(
            &pipeline,
            bytes,
            Some("application/rss+xml"),
            id,
            TraversalLimits::default(),
            &|| false,
        )
        .unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[1].id, stable_child_id(id, 0));
        assert_eq!(records[2].id, stable_child_id(id, 1));
        assert_eq!(records[1].references[0].as_str(), "https://example.test/a");
        assert_eq!(records[1].parent, Some(id));
    }

    #[test]
    fn cancellation_depth_entities_and_malformed_pdf_refuse() {
        let pipeline = ParserPipeline::new(ParserPipelineV1::for_uploads()).unwrap();
        let id = Digest::of("test", b"root");
        assert!(matches!(
            traverse(
                &pipeline,
                b"text",
                Some("text/plain"),
                id,
                TraversalLimits::default(),
                &|| true
            ),
            Err(TraversalError::Cancelled)
        ));
        assert!(traverse(
            &pipeline,
            b"<!DOCTYPE rss [<!ENTITY x SYSTEM 'https://forbidden.test'>]><rss>&x;</rss>",
            Some("application/rss+xml"),
            id,
            TraversalLimits::default(),
            &|| false
        )
        .is_err());
        assert!(traverse(
            &pipeline,
            b"%PDF-broken",
            Some("application/pdf"),
            id,
            TraversalLimits::default(),
            &|| false
        )
        .is_err());
    }
}
