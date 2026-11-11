//! Version-one parser pipeline contract.
//!
//! One `ParserPipelineV1` describes every route from caller-supplied bytes to extracted
//! content: the fixed ordered stage list, the explicit per-format routing table and the
//! resource limits each stage runs under. The contract is a pure value; the executor lives in
//! `crawlx-extract`, so static, scrape, dynamic, replay and upload callers share one entry
//! point and one set of limits. Transport decoding (content-encoding, charset negotiation)
//! happens before the pipeline; input-container decompression is bounded by the parse limits
//! this contract narrows.
//!
//! The pipeline digest identifies stage order, routing and limits. It is part of the output
//! record version ([`ParserPipelineV1::record_version`]), so a change of any limit or route
//! yields a different record version instead of silently changing stored output.

use crate::{hash::Digest, CoreError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain tag of [`ParserPipelineV1::digest`].
const DIGEST_DOMAIN: &str = "crawlx.parser-pipeline.v1";
/// Prefix of [`ParserPipelineV1::record_version`].
const RECORD_VERSION_PREFIX: &str = "parser_pipeline_v1";
/// Most format routes one pipeline can carry.
pub const MAX_PIPELINE_ROUTES: usize = 32;

/// Ordered stages of one pipeline run.
///
/// Stage order is part of the contract: [`ParserPipelineV1::validate`] accepts exactly
/// [`PipelineStageV1::ALL`] in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PipelineStageV1 {
    /// Identify the input format from bytes, file name and declared content type.
    Detect,
    /// Prepare bytes for the parser: UTF-8 normalization for markup, container admission for
    /// binary documents.
    DecodeInput,
    /// Build the document model, under node/entry limits.
    Parse,
    /// Select the content blocks that form the output.
    Select,
    /// Collect document metadata.
    Metadata,
    /// Apply the content quality gates, when a native content policy is configured.
    Quality,
    /// Apply the worker-injected privacy/content projection, when one is supplied.
    Transform,
    /// Build the output record and enforce child and output limits.
    Project,
}

impl PipelineStageV1 {
    /// The only valid stage list of version one, in execution order.
    pub const ALL: [Self; 8] = [
        Self::Detect,
        Self::DecodeInput,
        Self::Parse,
        Self::Select,
        Self::Metadata,
        Self::Quality,
        Self::Transform,
        Self::Project,
    ];

    /// Stable lowercase name used in traces and metrics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Detect => "detect",
            Self::DecodeInput => "decode_input",
            Self::Parse => "parse",
            Self::Select => "select",
            Self::Metadata => "metadata",
            Self::Quality => "quality",
            Self::Transform => "transform",
            Self::Project => "project",
        }
    }
}

/// Which parser a detected format is routed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PipelineRouteV1 {
    /// The page extractor: article selection, quality gates, links, forms and metadata over a
    /// page URL. Only the `html` format may use this route.
    Html,
    /// The document parser: PDF, Office, EPUB, text, CSV and (for uploads) HTML without a page
    /// URL.
    Document,
}

/// Format names a route may be declared for, in the document parser's canonical spelling.
pub const PIPELINE_FORMATS: [&str; 23] = [
    "html", "pdf", "docx", "doc", "odt", "ods", "odp", "rtf", "xlsx", "xls", "xlsb", "pptx", "ppt", "epub",
    "csv", "txt", "md", "png", "jpeg", "gif", "webp", "bmp", "tiff",
];

/// Formats routed by [`ParserPipelineV1::default`]: every text-bearing document format. Image
/// formats need an OCR engine and are routed only when a caller adds them explicitly.
const DEFAULT_ROUTED: [&str; 17] = [
    "html", "pdf", "docx", "doc", "odt", "ods", "odp", "rtf", "xlsx", "xls", "xlsb", "pptx", "ppt", "epub",
    "csv", "txt", "md",
];

/// Resource limits of one pipeline run. Every limit narrows, never widens, the limits of the
/// underlying parsers: the effective limit is the smaller of the two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PipelineLimitsV1 {
    /// Largest content policy operation budget accepted (paragraph/element/selector
    /// operations). A configured native content policy asking for more is refused, not clamped.
    /// Not used by the document parser, which counts entries through `max_nodes`.
    pub max_operations: u64,
    /// Largest accepted input, checked before any parsing.
    pub max_input_bytes: u64,
    /// Largest parsed node count (markup) or container entry/object count (documents).
    pub max_nodes: u64,
    /// Deepest accepted markup nesting; at most 512, the tree-builder ceiling. Documents have
    /// no nesting model and are bounded by `max_nodes` instead.
    pub max_depth: u32,
    /// Most children: links plus images of a page, or links plus images plus pages of a
    /// document. Page and sheet counts also cap the document parser, which truncates with a
    /// warning; the link and image counts refuse.
    pub max_children: u64,
    /// Largest total of text, Markdown and cleaned-HTML output bytes.
    pub max_output_bytes: u64,
}

impl Default for PipelineLimitsV1 {
    fn default() -> Self {
        Self {
            max_operations: 4_000_000,
            max_input_bytes: 50 * 1024 * 1024,
            max_nodes: 1_000_000,
            max_depth: 512,
            max_children: 100_000,
            max_output_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Ceilings no pipeline may exceed.
const CEIL_OPERATIONS: u64 = 4_000_000;
const CEIL_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const CEIL_NODES: u64 = 10_000_000;
const CEIL_DEPTH: u32 = 512;
const CEIL_CHILDREN: u64 = 1_000_000;
const CEIL_OUTPUT_BYTES: u64 = 128 * 1024 * 1024;

/// The one parser pipeline: ordered stages, explicit format routing and limits.
///
/// Omission of a route refuses the format; there is no implicit fallback parser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ParserPipelineV1 {
    /// Schema version, exactly one.
    pub version: u16,
    /// Stage list; version one accepts exactly [`PipelineStageV1::ALL`].
    pub stages: Vec<PipelineStageV1>,
    /// Route per detected format name (see [`PIPELINE_FORMATS`]). A detected format without a
    /// route is refused.
    pub routes: BTreeMap<String, PipelineRouteV1>,
    /// Resource limits.
    pub limits: PipelineLimitsV1,
}

impl Default for ParserPipelineV1 {
    fn default() -> Self {
        let routes = DEFAULT_ROUTED
            .iter()
            .map(|format| {
                let route = if *format == "html" {
                    PipelineRouteV1::Html
                } else {
                    PipelineRouteV1::Document
                };
                ((*format).to_owned(), route)
            })
            .collect();
        Self {
            version: 1,
            stages: PipelineStageV1::ALL.to_vec(),
            routes,
            limits: PipelineLimitsV1::default(),
        }
    }
}

impl ParserPipelineV1 {
    /// Pipeline for callers that hold only bytes without a page URL (uploads): HTML is parsed
    /// by the document parser, so no page URL is needed.
    #[must_use]
    pub fn for_uploads() -> Self {
        let mut pipeline = Self::default();
        pipeline
            .routes
            .insert("html".to_owned(), PipelineRouteV1::Document);
        pipeline
    }

    /// Route declared for `format`, if any.
    #[must_use]
    pub fn route(&self, format: &str) -> Option<PipelineRouteV1> {
        self.routes.get(format).copied()
    }

    /// Check version, stage order, routes and limits before any input is read.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` for an unknown version, a stage list other than
    /// [`PipelineStageV1::ALL`], an empty/oversized/unknown route table, the page route on a
    /// non-HTML format, or a limit that is zero or above its ceiling.
    pub fn validate(&self) -> Result<(), CoreError> {
        let invalid = |field: &'static str, reason: &str| CoreError::Invalid {
            field,
            reason: reason.to_owned(),
        };
        if self.version != 1 {
            return Err(invalid("extract.pipeline.version", "exactly one"));
        }
        if self.stages != PipelineStageV1::ALL {
            return Err(invalid(
                "extract.pipeline.stages",
                "version one runs exactly detect, decode_input, parse, select, metadata, quality, transform, project in that order",
            ));
        }
        if self.routes.is_empty() || self.routes.len() > MAX_PIPELINE_ROUTES {
            return Err(invalid("extract.pipeline.routes", "between one and 32 routes"));
        }
        for (format, route) in &self.routes {
            if !PIPELINE_FORMATS.contains(&format.as_str()) {
                return Err(invalid("extract.pipeline.routes", "unknown format name"));
            }
            if *route == PipelineRouteV1::Html && format != "html" {
                return Err(invalid(
                    "extract.pipeline.routes",
                    "the page route applies only to the html format",
                ));
            }
        }
        let l = &self.limits;
        let in_range = |value: u64, ceiling: u64| (1..=ceiling).contains(&value);
        if !(in_range(l.max_operations, CEIL_OPERATIONS)
            && in_range(l.max_input_bytes, CEIL_INPUT_BYTES)
            && in_range(l.max_nodes, CEIL_NODES)
            && (1..=CEIL_DEPTH).contains(&l.max_depth)
            && in_range(l.max_children, CEIL_CHILDREN)
            && in_range(l.max_output_bytes, CEIL_OUTPUT_BYTES))
        {
            return Err(invalid(
                "extract.pipeline.limits",
                "every limit must be at least one and at most its ceiling",
            ));
        }
        Ok(())
    }

    /// Digest of the canonical pipeline value: stage order, routes and limits.
    ///
    /// # Errors
    /// Returns `CoreError::Invalid` when the pipeline fails validation, so a digest always
    /// names a runnable pipeline.
    pub fn digest(&self) -> Result<Digest, CoreError> {
        self.validate()?;
        Digest::of_value(DIGEST_DOMAIN, self).map_err(|_| CoreError::Invalid {
            field: "extract.pipeline",
            reason: "pipeline is not encodable".to_owned(),
        })
    }

    /// Output record version: the pipeline contract name plus the first 16 hex digits of the
    /// pipeline digest. Stored extraction output carries this string, so records produced
    /// under different limits or routing never compare equal.
    ///
    /// # Errors
    /// Same as [`ParserPipelineV1::digest`].
    pub fn record_version(&self) -> Result<String, CoreError> {
        let hex = self.digest()?.to_hex();
        let short = hex.get(..16).unwrap_or(&hex);
        Ok(format!("{RECORD_VERSION_PREFIX}/{short}"))
    }
}

/// How one stage ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StageStatusV1 {
    /// The stage did work for this input.
    Completed,
    /// The stage ran but changed nothing (no projection supplied, whole document selected).
    PassThrough,
    /// The stage does not exist for this route (for example quality gates on a PDF).
    NotApplicable,
}

/// Bounded per-stage accounting of one run, in stage order.
///
/// Counts carry no content. Units per stage: detect `bytes -> formats`, decode_input
/// `bytes -> bytes`, parse `bytes -> parsed documents or pages`, select `bytes -> selected
/// text bytes`, metadata `fields seen -> fields kept`, quality `charged operations -> accepted
/// main characters`, transform `text bytes -> text bytes`, project `candidate output bytes ->
/// retained output bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct StageReportV1 {
    /// Stage this record describes.
    pub stage: PipelineStageV1,
    /// Outcome.
    pub status: StageStatusV1,
    /// Items entering the stage.
    pub input: u64,
    /// Items leaving the stage.
    pub output: u64,
}

impl StageReportV1 {
    /// Construct one stage record.
    #[must_use]
    pub const fn new(stage: PipelineStageV1, status: StageStatusV1, input: u64, output: u64) -> Self {
        Self {
            stage,
            status,
            input,
            output,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn default_pipeline_is_valid_and_routes_html_to_the_page_extractor() {
        let pipeline = ParserPipelineV1::default();
        pipeline.validate().unwrap();
        assert_eq!(pipeline.route("html"), Some(PipelineRouteV1::Html));
        assert_eq!(pipeline.route("pdf"), Some(PipelineRouteV1::Document));
        assert_eq!(pipeline.route("png"), None);
        assert_eq!(pipeline.stages, PipelineStageV1::ALL);
        let uploads = ParserPipelineV1::for_uploads();
        uploads.validate().unwrap();
        assert_eq!(uploads.route("html"), Some(PipelineRouteV1::Document));
    }

    #[test]
    fn stage_order_is_the_derived_order() {
        let mut sorted = PipelineStageV1::ALL;
        sorted.sort();
        assert_eq!(sorted, PipelineStageV1::ALL);
        let names: Vec<_> = PipelineStageV1::ALL.iter().map(|s| s.name()).collect();
        assert_eq!(
            names,
            [
                "detect",
                "decode_input",
                "parse",
                "select",
                "metadata",
                "quality",
                "transform",
                "project"
            ]
        );
    }

    #[test]
    fn reordered_missing_or_extra_stages_are_rejected() {
        let mut reordered = ParserPipelineV1::default();
        reordered.stages.swap(2, 3);
        assert!(reordered.validate().is_err());
        let mut missing = ParserPipelineV1::default();
        missing.stages.pop();
        assert!(missing.validate().is_err());
        let mut extra = ParserPipelineV1::default();
        extra.stages.push(PipelineStageV1::Project);
        assert!(extra.validate().is_err());
    }

    #[test]
    fn routes_and_limits_are_bounded() {
        let mut p = ParserPipelineV1::default();
        p.routes.insert("pdf".into(), PipelineRouteV1::Html);
        assert!(p.validate().is_err());
        let mut p = ParserPipelineV1::default();
        p.routes.insert("exe".into(), PipelineRouteV1::Document);
        assert!(p.validate().is_err());
        let mut p = ParserPipelineV1::default();
        p.routes.clear();
        assert!(p.validate().is_err());
        for edit in [
            |l: &mut PipelineLimitsV1| l.max_operations = 0,
            |l: &mut PipelineLimitsV1| l.max_input_bytes = 0,
            |l: &mut PipelineLimitsV1| l.max_nodes = u64::MAX,
            |l: &mut PipelineLimitsV1| l.max_depth = 513,
            |l: &mut PipelineLimitsV1| l.max_children = 0,
            |l: &mut PipelineLimitsV1| l.max_output_bytes = CEIL_OUTPUT_BYTES + 1,
        ] {
            let mut p = ParserPipelineV1::default();
            edit(&mut p.limits);
            assert!(p.validate().is_err());
        }
    }

    #[test]
    fn digest_changes_with_any_limit_or_route_and_names_the_record_version() {
        let base = ParserPipelineV1::default();
        let digest = base.digest().unwrap();
        assert_eq!(digest, ParserPipelineV1::default().digest().unwrap());
        let mut limits = base.clone();
        limits.limits.max_children = 99;
        assert_ne!(limits.digest().unwrap(), digest);
        assert_ne!(ParserPipelineV1::for_uploads().digest().unwrap(), digest);
        let version = base.record_version().unwrap();
        assert!(version.starts_with("parser_pipeline_v1/"));
        assert_eq!(version.len(), "parser_pipeline_v1/".len() + 16);
        assert_ne!(limits.record_version().unwrap(), version);
        let mut invalid = base;
        invalid.version = 2;
        assert!(invalid.digest().is_err());
    }

    #[test]
    fn omitted_fields_default_and_unknown_fields_fail() {
        let p: ParserPipelineV1 = serde_json::from_str("{}").unwrap();
        assert_eq!(p, ParserPipelineV1::default());
        assert!(serde_json::from_str::<ParserPipelineV1>(r#"{"extra":1}"#).is_err());
        assert!(serde_json::from_str::<ParserPipelineV1>(r#"{"limits":{"maxNodes":0,"x":1}}"#).is_err());
    }

    #[test]
    fn known_format_list_has_no_duplicates() {
        let mut names = PIPELINE_FORMATS.to_vec();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), PIPELINE_FORMATS.len());
        assert!(DEFAULT_ROUTED.iter().all(|f| PIPELINE_FORMATS.contains(f)));
    }
}
