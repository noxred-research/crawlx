//! The single parser pipeline entry point.
//!
//! [`ParserPipeline::run`] executes one [`ParserPipelineV1`]: it detects the input format,
//! looks up the explicit route for that format and either calls the page extractor
//! ([`Extractor`]) or the document parser ([`parse_document_with`]), then
//! projects both onto one result type, [`PipelineOutput`]. Static fetches, scrape-engine
//! parses, settled dynamic DOMs, replayed bodies and uploaded files all enter here, so they
//! share one set of limits and one output record version.
//!
//! Stage order is fixed by the contract ([`PipelineStageV1::ALL`]) and every run returns one
//! [`StageReportV1`] per stage in that order. Detection, decoding, limits and projection are
//! pipeline work; parse, select, metadata and quality run inside the extractor or parser the
//! route selects and are reported from their results.
//!
//! Limits only narrow the limits of the underlying parsers. Hard limits (input, nodes, depth,
//! operations, children, output) refuse the input with [`PipelineError::Limit`]; they never
//! return a silently shortened record. Page, slide and sheet counts keep the document
//! parser's soft truncation with a warning.
//!
//! Page decode options apply to the original bytes before depth checks. Without decode options,
//! the legacy BOM-aware UTF-8/UTF-16 path remains in use. Extraction reuses the decoded text,
//! retains its diagnostics, and hashes the original input rather than the converted text.
//!
//! No network, clock, filesystem or randomness is used.

use std::borrow::Cow;

use crawlx_core::{
    extraction::{ParserPipelineV1, PipelineRouteV1, PipelineStageV1, StageReportV1, StageStatusV1},
    hash::Digest,
    CoreError,
};
use encoding_rs::Encoding;
use url::Url;

use crate::{
    document::Document,
    parse::{detect_format, parse_document_with, ParseError, ParseFormat, ParseOptions, ParsedDocument},
    parse_budget, ExtractError, ExtractOptions, Extractor,
};

/// Transient privacy/content projection: `None` keeps a string, `Some` replaces it.
type Projection<'a> = dyn Fn(&str) -> Option<String> + 'a;

/// Why a pipeline run refused or failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PipelineError {
    /// The pipeline value failed validation; nothing was read.
    #[error("invalid parser pipeline")]
    Invalid(#[from] CoreError),
    /// The detected format has no route in the pipeline.
    #[error("format `{format}` has no pipeline route")]
    Unrouted {
        /// Canonical detected format name.
        format: &'static str,
    },
    /// A pipeline limit refused the input. Nothing was truncated.
    #[error("pipeline limit exceeded: {what} {actual} exceeds {limit}")]
    Limit {
        /// Which limit: `input bytes`, `nodes`, `depth`, `operations`, `children`,
        /// `output bytes` or a parser-specific container limit.
        what: &'static str,
        /// Effective limit.
        limit: u64,
        /// Observed value (a lower bound when the check stopped early).
        actual: u64,
    },
    /// The page route needs the URL the document was fetched from.
    #[error("the page route requires a page URL")]
    MissingPageUrl,
    /// A projection was supplied on the page route without a native content policy; the page
    /// extractor applies projections only under a content policy, so running would leave
    /// content unprojected.
    #[error("a page projection requires a native content policy")]
    ProjectionNeedsContentPolicy,
    /// Format detection failed (unsupported, encrypted or corrupt container).
    #[error("format detection failed")]
    Detect(#[source] ParseError),
    /// The page extractor failed for a reason other than a limit.
    #[error("page extraction failed")]
    Extract(#[source] ExtractError),
    /// The document parser failed for a reason other than a limit.
    #[error("document parsing failed")]
    Parse(#[source] ParseError),
}

fn widen(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn narrow(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

fn extract_error(error: ExtractError) -> PipelineError {
    match error {
        ExtractError::TooLarge { what, limit, actual } => PipelineError::Limit {
            what,
            limit: widen(limit),
            actual: widen(actual),
        },
        other => PipelineError::Extract(other),
    }
}

fn parse_error(error: ParseError, detect: bool) -> PipelineError {
    match error {
        ParseError::TooLarge { what, limit, actual } => PipelineError::Limit {
            what,
            limit: widen(limit),
            actual: widen(actual),
        },
        other if detect => PipelineError::Detect(other),
        other => PipelineError::Parse(other),
    }
}

/// One validated pipeline, ready to run any number of inputs.
#[derive(Debug, Clone)]
pub struct ParserPipeline {
    spec: ParserPipelineV1,
    digest: Digest,
    record_version: String,
}

/// Borrowed input of one run. Construct with [`PipelineInput::new`] and the `with_*` setters.
#[derive(Clone, Copy)]
pub struct PipelineInput<'a> {
    bytes: &'a [u8],
    filename: Option<&'a str>,
    content_type: Option<&'a str>,
    page_url: Option<&'a Url>,
    page_options: Option<&'a ExtractOptions>,
    document_options: Option<&'a ParseOptions>,
    projection: Option<&'a Projection<'a>>,
}

impl<'a> PipelineInput<'a> {
    /// Input bytes, already transport-decoded (content-encoding removed). No other facts yet.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            filename: None,
            content_type: None,
            page_url: None,
            page_options: None,
            document_options: None,
            projection: None,
        }
    }

    /// File name or URL path, a format hint after the bytes themselves.
    #[must_use]
    pub const fn with_filename(mut self, filename: &'a str) -> Self {
        self.filename = Some(filename);
        self
    }

    /// Declared `Content-Type`, a format hint after the bytes and file name.
    #[must_use]
    pub const fn with_content_type(mut self, content_type: &'a str) -> Self {
        self.content_type = Some(content_type);
        self
    }

    /// URL the document came from; required by the page route.
    #[must_use]
    pub const fn with_page_url(mut self, url: &'a Url) -> Self {
        self.page_url = Some(url);
        self
    }

    /// Page extractor options for the page route; defaults apply when absent.
    #[must_use]
    pub const fn with_page_options(mut self, options: &'a ExtractOptions) -> Self {
        self.page_options = Some(options);
        self
    }

    /// Document parser options for the document route; defaults apply when absent.
    #[must_use]
    pub const fn with_document_options(mut self, options: &'a ParseOptions) -> Self {
        self.document_options = Some(options);
        self
    }

    /// Worker-injected pure content projection (privacy redaction). It runs before derived
    /// outputs are finalized on the page route and over every text field of a parsed document.
    #[must_use]
    pub const fn with_projection(mut self, projection: &'a Projection<'a>) -> Self {
        self.projection = Some(projection);
        self
    }
}

/// Parsed content of one run, by route.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum PipelineContent {
    /// Output of the page extractor.
    Page(Box<Document>),
    /// Output of the document parser.
    Document(Box<ParsedDocument>),
}

/// The one result type of the pipeline.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PipelineOutput {
    /// `ParserPipelineV1::record_version` of the pipeline that produced this output.
    pub record_version: String,
    /// Digest of that pipeline.
    pub pipeline_digest: Digest,
    /// Detected format.
    pub format: ParseFormat,
    /// Route the format took.
    pub route: PipelineRouteV1,
    /// Parsed content.
    pub content: PipelineContent,
    /// One record per stage, in stage order.
    pub stages: Vec<StageReportV1>,
    /// Non-fatal findings of the pipeline and the parser.
    pub warnings: Vec<String>,
}

impl PipelineOutput {
    /// Title, if the document has one.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        match &self.content {
            PipelineContent::Page(d) => d.title.as_deref(),
            PipelineContent::Document(d) => d.title.as_deref(),
        }
    }

    /// Plain text of the selected content.
    #[must_use]
    pub fn text(&self) -> &str {
        match &self.content {
            PipelineContent::Page(d) => &d.text,
            PipelineContent::Document(d) => &d.text,
        }
    }

    /// Markdown of the selected content.
    #[must_use]
    pub fn markdown(&self) -> &str {
        match &self.content {
            PipelineContent::Page(d) => &d.markdown,
            PipelineContent::Document(d) => &d.markdown,
        }
    }

    /// Cleaned HTML of the selected content.
    #[must_use]
    pub fn html(&self) -> &str {
        match &self.content {
            PipelineContent::Page(d) => &d.html,
            PipelineContent::Document(d) => &d.html,
        }
    }

    /// Hyperlinks in document order.
    #[must_use]
    pub fn link_urls(&self) -> Vec<&str> {
        match &self.content {
            PipelineContent::Page(d) => d.links.iter().map(|l| l.url.as_str()).collect(),
            PipelineContent::Document(d) => d.links.iter().map(String::as_str).collect(),
        }
    }

    /// Record of `stage`.
    #[must_use]
    pub fn stage(&self, stage: PipelineStageV1) -> Option<&StageReportV1> {
        self.stages.iter().find(|r| r.stage == stage)
    }

    /// Children counted against the pipeline child limit.
    fn children(&self) -> usize {
        match &self.content {
            PipelineContent::Page(d) => d.links.len().saturating_add(d.assets.len()),
            PipelineContent::Document(d) => d
                .links
                .len()
                .saturating_add(d.images.len())
                .saturating_add(d.pages.len()),
        }
    }

    fn output_bytes(&self) -> usize {
        self.text()
            .len()
            .saturating_add(self.markdown().len())
            .saturating_add(self.html().len())
    }
}

impl ParserPipeline {
    /// Validate `spec` and fix its digest.
    ///
    /// # Errors
    /// [`PipelineError::Invalid`] when the pipeline contract is not valid version one.
    pub fn new(spec: ParserPipelineV1) -> Result<Self, PipelineError> {
        let digest = spec.digest()?;
        let record_version = spec.record_version()?;
        Ok(Self {
            spec,
            digest,
            record_version,
        })
    }

    /// The contract this pipeline executes.
    #[must_use]
    pub const fn spec(&self) -> &ParserPipelineV1 {
        &self.spec
    }

    /// Digest of the contract.
    #[must_use]
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Output record version, which embeds the pipeline digest.
    #[must_use]
    pub fn record_version(&self) -> &str {
        &self.record_version
    }

    /// Run `input` through every stage.
    ///
    /// Synchronous and CPU-bound: call from a blocking thread, never from an async task.
    ///
    /// # Errors
    /// [`PipelineError::Limit`] when any pipeline limit refuses the input,
    /// [`PipelineError::Unrouted`] when the detected format has no route,
    /// [`PipelineError::MissingPageUrl`] for a page route without a URL,
    /// [`PipelineError::ProjectionNeedsContentPolicy`] for a page projection without a native
    /// content policy, and the typed detection, extraction or parsing errors otherwise.
    pub fn run(&self, input: PipelineInput<'_>) -> Result<PipelineOutput, PipelineError> {
        let limits = &self.spec.limits;
        let input_len = widen(input.bytes.len());
        if input_len > limits.max_input_bytes {
            return Err(PipelineError::Limit {
                what: "input bytes",
                limit: limits.max_input_bytes,
                actual: input_len,
            });
        }
        let parse_options = self.document_options(input.document_options);

        // detect
        let format = detect_format(
            input.bytes,
            input.filename,
            input.content_type,
            &parse_options.limits,
        )
        .map_err(|e| parse_error(e, true))?;
        let route = self.spec.route(format.name()).ok_or(PipelineError::Unrouted {
            format: format.name(),
        })?;
        let mut stages = Vec::with_capacity(PipelineStageV1::ALL.len());
        stages.push(StageReportV1::new(
            PipelineStageV1::Detect,
            StageStatusV1::Completed,
            input_len,
            1,
        ));

        let (content, warnings) = match route {
            PipelineRouteV1::Html => self.run_page(&input, &mut stages)?,
            PipelineRouteV1::Document => self.run_document(&input, &parse_options, &mut stages)?,
            _ => {
                return Err(PipelineError::Unrouted {
                    format: format.name(),
                })
            }
        };
        let mut output = PipelineOutput {
            record_version: self.record_version.clone(),
            pipeline_digest: self.digest,
            format,
            route,
            content,
            stages,
            warnings,
        };

        // project
        let children = widen(output.children());
        if children > limits.max_children {
            return Err(PipelineError::Limit {
                what: "children",
                limit: limits.max_children,
                actual: children,
            });
        }
        let bytes = widen(output.output_bytes());
        if bytes > limits.max_output_bytes {
            return Err(PipelineError::Limit {
                what: "output bytes",
                limit: limits.max_output_bytes,
                actual: bytes,
            });
        }
        output.stages.push(StageReportV1::new(
            PipelineStageV1::Project,
            StageStatusV1::Completed,
            bytes,
            bytes,
        ));
        Ok(output)
    }

    /// Document parser options narrowed by the pipeline limits.
    fn document_options(&self, supplied: Option<&ParseOptions>) -> ParseOptions {
        let limits = &self.spec.limits;
        let mut options = supplied.cloned().unwrap_or_default();
        options.limits.max_input_bytes = options.limits.max_input_bytes.min(narrow(limits.max_input_bytes));
        options.limits.max_entries = options.limits.max_entries.min(narrow(limits.max_nodes));
        options.limits.max_pages = options.limits.max_pages.min(narrow(limits.max_children));
        options.limits.max_sheets = options.limits.max_sheets.min(narrow(limits.max_children));
        options
    }

    fn run_page(
        &self,
        input: &PipelineInput<'_>,
        stages: &mut Vec<StageReportV1>,
    ) -> Result<(PipelineContent, Vec<String>), PipelineError> {
        let limits = &self.spec.limits;
        let page_url = input.page_url.ok_or(PipelineError::MissingPageUrl)?;
        if input.projection.is_some() && input.page_options.is_none_or(|o| o.content.is_none()) {
            return Err(PipelineError::ProjectionNeedsContentPolicy);
        }
        let mut options = input.page_options.cloned().unwrap_or_default();
        options.max_input_bytes = options.max_input_bytes.min(narrow(limits.max_input_bytes));
        options.max_nodes = options.max_nodes.min(narrow(limits.max_nodes));
        if let Some(policy) = &options.content {
            let requested = widen(policy.max_operations);
            if requested > limits.max_operations {
                return Err(PipelineError::Limit {
                    what: "operations",
                    limit: limits.max_operations,
                    actual: requested,
                });
            }
        }

        // Decode once, retaining the original bytes for extraction evidence and its raw digest.
        let max_bytes = if options.content.is_some() {
            options
                .max_input_bytes
                .min(crate::document::DEFAULT_MAX_INPUT_BYTES)
        } else {
            options.max_input_bytes
        };
        if input.bytes.len() > max_bytes {
            return Err(extract_error(ExtractError::TooLarge {
                what: "bytes",
                limit: max_bytes,
                actual: input.bytes.len(),
            }));
        }
        let mut charge =
            parse_budget::charge(input.bytes.len()).map_err(|error| extract_error(error.into()))?;
        let (decoded, decode_report, lossy, converted) = if options.decode.is_some() {
            let (decoded, report) = crate::decode_bytes(input.bytes, &options).map_err(extract_error)?;
            let lossy = report.as_ref().is_some_and(|report| report.issue_count > 0);
            let converted = report
                .as_ref()
                .is_some_and(|report| report.bom_len > 0 || report.encoding != "UTF-8");
            (decoded, report, lossy, converted)
        } else {
            let (decoded, lossy, converted) = decode_markup(input.bytes);
            (decoded, None, lossy, converted)
        };
        charge
            .cover(decoded.len())
            .map_err(|error| extract_error(error.into()))?;
        let mut warnings = Vec::new();
        if lossy {
            warnings.push(
                "input is not valid text in its detected encoding; invalid sequences were replaced"
                    .to_owned(),
            );
        }
        let decoded_len = widen(decoded.len());
        stages.push(StageReportV1::new(
            PipelineStageV1::DecodeInput,
            if lossy || converted {
                StageStatusV1::Completed
            } else {
                StageStatusV1::PassThrough
            },
            widen(input.bytes.len()),
            decoded_len,
        ));

        // parse (depth is checked on the parsed tree; the extractor enforces the 512 ceiling)
        if limits.max_depth < u32::try_from(crate::dom::MAX_DEPTH).unwrap_or(u32::MAX) {
            check_depth(&decoded, limits.max_depth)?;
        }
        let document = Extractor::extract_inner(
            &decoded,
            input.bytes,
            Digest::of(crate::RAW_HTML_DOMAIN, input.bytes),
            page_url,
            &options,
            input.projection,
            Some((charge, decode_report)),
        )
        .map_err(extract_error)?;
        stages.push(StageReportV1::new(
            PipelineStageV1::Parse,
            StageStatusV1::Completed,
            decoded_len,
            1,
        ));
        stages.push(StageReportV1::new(
            PipelineStageV1::Select,
            StageStatusV1::Completed,
            decoded_len,
            widen(document.text.len()),
        ));
        let present = [
            document.title.is_some(),
            document.description.is_some(),
            document.language.is_some(),
            document.canonical_url.is_some(),
        ]
        .into_iter()
        .filter(|present| *present)
        .count();
        stages.push(StageReportV1::new(
            PipelineStageV1::Metadata,
            StageStatusV1::Completed,
            4,
            widen(present),
        ));
        stages.push(match &document.article {
            Some(envelope) => StageReportV1::new(
                PipelineStageV1::Quality,
                StageStatusV1::Completed,
                widen(envelope.quality.operations),
                widen(envelope.quality.main_chars),
            ),
            None => StageReportV1::new(PipelineStageV1::Quality, StageStatusV1::NotApplicable, 0, 0),
        });
        let text_len = widen(document.text.len());
        stages.push(StageReportV1::new(
            PipelineStageV1::Transform,
            if input.projection.is_some() {
                StageStatusV1::Completed
            } else {
                StageStatusV1::PassThrough
            },
            text_len,
            text_len,
        ));
        Ok((PipelineContent::Page(Box::new(document)), warnings))
    }

    fn run_document(
        &self,
        input: &PipelineInput<'_>,
        options: &ParseOptions,
        stages: &mut Vec<StageReportV1>,
    ) -> Result<(PipelineContent, Vec<String>), PipelineError> {
        let input_len = widen(input.bytes.len());
        // Container decompression and entry limits are enforced inside the parse stage.
        stages.push(StageReportV1::new(
            PipelineStageV1::DecodeInput,
            StageStatusV1::PassThrough,
            input_len,
            input_len,
        ));
        let mut parsed = parse_document_with(input.bytes, input.filename, input.content_type, options)
            .map_err(|e| parse_error(e, false))?;
        let units = parsed.num_pages.map_or(1, |n| u64::from(n.max(1)));
        stages.push(StageReportV1::new(
            PipelineStageV1::Parse,
            StageStatusV1::Completed,
            input_len,
            units,
        ));
        let text_len = widen(parsed.text.len());
        stages.push(StageReportV1::new(
            PipelineStageV1::Select,
            StageStatusV1::PassThrough,
            text_len,
            text_len,
        ));
        let fields = widen(parsed.metadata.len());
        stages.push(StageReportV1::new(
            PipelineStageV1::Metadata,
            StageStatusV1::Completed,
            fields,
            fields,
        ));
        stages.push(StageReportV1::new(
            PipelineStageV1::Quality,
            StageStatusV1::NotApplicable,
            0,
            0,
        ));
        if let Some(project) = input.projection {
            project_document(&mut parsed, project);
        }
        stages.push(StageReportV1::new(
            PipelineStageV1::Transform,
            if input.projection.is_some() {
                StageStatusV1::Completed
            } else {
                StageStatusV1::PassThrough
            },
            text_len,
            widen(parsed.text.len()),
        ));
        let warnings = std::mem::take(&mut parsed.warnings);
        Ok((PipelineContent::Document(Box::new(parsed)), warnings))
    }
}

/// Apply `project` to every text field of a parsed document, including the generated source.
fn project_document(parsed: &mut ParsedDocument, project: &Projection<'_>) {
    let apply = |value: &mut String| {
        if let Some(replacement) = project(value) {
            *value = replacement;
        }
    };
    if let Some(title) = &mut parsed.title {
        apply(title);
    }
    apply(&mut parsed.text);
    apply(&mut parsed.markdown);
    apply(&mut parsed.html);
    apply(&mut parsed.raw_html);
    for page in &mut parsed.pages {
        apply(&mut page.markdown);
    }
    for value in parsed.metadata.values_mut() {
        if let serde_json::Value::String(text) = value {
            apply(text);
        }
    }
}

/// Decode markup bytes: a byte-order mark selects UTF-8/UTF-16, otherwise UTF-8. Returns the
/// text, whether invalid sequences were replaced, and whether a conversion changed the bytes.
fn decode_markup(bytes: &[u8]) -> (Cow<'_, str>, bool, bool) {
    if let Some((encoding, bom_len)) = Encoding::for_bom(bytes) {
        let (text, had_errors) = encoding.decode_without_bom_handling(&bytes[bom_len..]);
        return (text, had_errors, true);
    }
    match std::str::from_utf8(bytes) {
        Ok(text) => (Cow::Borrowed(text), false, false),
        Err(_) => (String::from_utf8_lossy(bytes), true, true),
    }
}

/// Refuse markup nested deeper than `max_depth`. Same convention as the extractor's own
/// ceiling: the document node is depth zero.
fn check_depth(markup: &str, max_depth: u32) -> Result<(), PipelineError> {
    let _charge =
        parse_budget::charge(markup.len()).map_err(|e| PipelineError::Extract(ExtractError::from(e)))?;
    let parsed = scraper::Html::parse_document(markup);
    let mut stack = vec![(parsed.tree.root(), 0u32)];
    while let Some((node, depth)) = stack.pop() {
        if depth > max_depth {
            return Err(PipelineError::Limit {
                what: "depth",
                limit: u64::from(max_depth),
                actual: u64::from(depth),
            });
        }
        let child_depth = depth.saturating_add(1);
        stack.extend(node.children().map(|child| (child, child_depth)));
    }
    Ok(())
}
